//! BLE GATT chunking. Each write/notify is `[hdr][body...]`; hdr bit7 = more chunks follow,
//! bits 0..=6 = sequence number (0 first, mod 128). The first chunk body starts with the frame's
//! total length as u16 LE. `mtu` is the ATT_MTU; max chunk size is `mtu - 3`.
//!
//! **Framing v2 (channels)**: `[hdr][chan u32 LE][body…]`, the first chunk additionally carries
//! `total_len u16 LE` after `chan`. `hdr`: bit7 = more, bit6 = 1 (v2 marker), bits0-5 = seq mod 64.
//! `chan` (non-zero) is a per-client routing tag so several processes can share one BLE link.
//! `chan == 0` means "v1". Caveat: a v1 frame longer than 64 chunks has chunk headers with bit6 set;
//! [`chunk_channel`] cannot tell those from v2, but [`ChannelReassembler`] disambiguates by context.

use crate::{frame::MAX_FRAME, Error, Result};

pub const MORE: u8 = 0x80;
/// v2 framing marker (header bit6).
pub const V2: u8 = 0x40;

/// Split `frame` into GATT chunks for the given ATT MTU (>= 23).
///
/// Panics if `mtu < 23` or `frame.len() > 65535`.
pub fn chunk(frame: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    assert!(mtu >= 23, "ATT MTU must be >= 23");
    assert!(frame.len() <= MAX_FRAME, "frame too large");
    let max = mtu - 3;
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut seq = 0u8;
    loop {
        let mut c = Vec::with_capacity(max);
        c.push(0); // header placeholder
        if seq == 0 && out.is_empty() {
            c.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        }
        let room = max - c.len();
        let n = room.min(frame.len() - pos);
        c.extend_from_slice(&frame[pos..pos + n]);
        pos += n;
        let more = pos < frame.len();
        c[0] = (seq & 0x7f) | if more { MORE } else { 0 };
        out.push(c);
        if !more {
            break;
        }
        seq = (seq + 1) & 0x7f;
    }
    out
}

/// Reassembly state for one partial frame. `mask` selects the seq bits (0x7f for v1, 0x3f for v2).
#[derive(Default, Debug)]
struct Frag {
    buf: Vec<u8>,
    total: usize,
    next_seq: u8,
    active: bool,
    count: usize,
}

impl Frag {
    fn reset(&mut self) {
        self.buf.clear();
        self.total = 0;
        self.next_seq = 0;
        self.active = false;
        self.count = 0;
    }

    fn push(&mut self, hdr: u8, mut body: &[u8], mask: u8) -> Result<Option<Vec<u8>>> {
        let r = self.push_inner(hdr, &mut body, mask);
        if r.is_err() {
            self.reset();
        }
        r
    }

    fn push_inner(&mut self, hdr: u8, body: &mut &[u8], mask: u8) -> Result<Option<Vec<u8>>> {
        let seq = hdr & mask;
        let more = hdr & MORE != 0;
        let period = mask as usize + 1;
        // seq 0 restarts reassembly, except when it is the wrap-around of a long frame
        // (a multiple of `period` chunks already received).
        let wrapped = seq == 0 && self.active && self.count > 0 && self.count.is_multiple_of(period);
        if seq == 0 && !wrapped {
            self.reset();
            if body.len() < 2 {
                return Err(Error::Chunk("first chunk too short"));
            }
            self.total = u16::from_le_bytes([body[0], body[1]]) as usize;
            *body = &body[2..];
            self.buf.reserve(self.total);
            self.active = true;
        } else if !self.active {
            return Err(Error::Chunk("chunk without start"));
        } else if seq != self.next_seq {
            return Err(Error::Chunk("sequence gap"));
        }
        self.next_seq = (seq + 1) & mask;
        self.count += 1;
        if self.buf.len() + body.len() > self.total {
            return Err(Error::Chunk("overflow"));
        }
        self.buf.extend_from_slice(body);
        let complete = self.buf.len() == self.total;
        match (more, complete) {
            (false, true) => {
                let f = core::mem::take(&mut self.buf);
                self.reset();
                Ok(Some(f))
            }
            (true, false) => Ok(None),
            (false, false) => Err(Error::Chunk("truncated frame")),
            (true, true) => Err(Error::Chunk("trailing chunks")),
        }
    }
}

/// Reassembles chunks into frames. [`Reassembler::new`] is the v1 reassembler (a chunk with seq 0
/// always restarts reassembly); [`Reassembler::new_channel`] accepts only v2 chunks of one channel.
#[derive(Default, Debug)]
pub struct Reassembler {
    frag: Frag,
    chan: Option<u32>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Host-side v2 reassembler for channel `chan`. Chunks of other channels and v1 chunks are
    /// ignored (`Ok(None)`) without touching the partial frame.
    pub fn new_channel(chan: u32) -> Self {
        Self {
            frag: Frag::default(),
            chan: Some(chan),
        }
    }

    pub fn reset(&mut self) {
        self.frag.reset();
    }

    /// Feed one chunk; returns `Some(frame)` when complete. On error the state is reset.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.chan {
            None => {
                let (&hdr, body) = chunk.split_first().ok_or(Error::Chunk("empty chunk"))?;
                self.frag.push(hdr, body, 0x7f)
            }
            Some(own) => {
                if chunk.is_empty() {
                    return Err(Error::Chunk("empty chunk"));
                }
                match parse_v2(chunk) {
                    Some((c, hdr, body)) if c == own => self.frag.push(hdr, body, 0x3f),
                    _ => Ok(None),
                }
            }
        }
    }
}

/// Split a chunk into `(chan, hdr, body)` if it is a well-formed v2 chunk (marker set, len >= 5,
/// non-zero channel).
fn parse_v2(chunk: &[u8]) -> Option<(u32, u8, &[u8])> {
    if chunk.len() < 5 || chunk[0] & V2 == 0 {
        return None;
    }
    let chan = u32::from_le_bytes([chunk[1], chunk[2], chunk[3], chunk[4]]);
    if chan == 0 {
        return None;
    }
    Some((chan, chunk[0], &chunk[5..]))
}

/// Channel of a chunk: `Some(chan)` for v2, `Some(0)` for v1, `None` if empty or malformed.
pub fn chunk_channel(chunk: &[u8]) -> Option<u32> {
    let &hdr = chunk.first()?;
    if hdr & V2 == 0 {
        Some(0)
    } else {
        parse_v2(chunk).map(|(c, _, _)| c)
    }
}

/// Non-zero random channel id (CSPRNG).
pub fn random_channel() -> u32 {
    loop {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).expect("system RNG unavailable");
        let c = u32::from_le_bytes(b);
        if c != 0 {
            return c;
        }
    }
}

/// Split `frame` into v2 GATT chunks tagged with `chan` for the given ATT MTU (>= 23).
///
/// Panics if `mtu < 23`, `frame.len() > 65535` or `chan == 0` (reserved for v1).
pub fn chunk_v2(frame: &[u8], mtu: usize, chan: u32) -> Vec<Vec<u8>> {
    assert!(mtu >= 23, "ATT MTU must be >= 23");
    assert!(frame.len() <= MAX_FRAME, "frame too large");
    assert!(chan != 0, "channel 0 is reserved for v1");
    let max = mtu - 3;
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0usize;
    let mut seq = 0u8;
    loop {
        let mut c = Vec::with_capacity(max);
        c.push(0);
        c.extend_from_slice(&chan.to_le_bytes());
        if out.is_empty() {
            c.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        }
        let n = (max - c.len()).min(frame.len() - pos);
        c.extend_from_slice(&frame[pos..pos + n]);
        pos += n;
        let more = pos < frame.len();
        c[0] = (seq & 0x3f) | V2 | if more { MORE } else { 0 };
        out.push(c);
        if !more {
            break;
        }
        seq = (seq + 1) & 0x3f;
    }
    out
}

/// Chunk a reply in the client's format: v1 when `chan == 0`, v2 otherwise.
pub fn chunk_for(frame: &[u8], mtu: usize, chan: u32) -> Vec<Vec<u8>> {
    if chan == 0 {
        chunk(frame, mtu)
    } else {
        chunk_v2(frame, mtu, chan)
    }
}

/// Device-side demultiplexer: one partial frame per channel (v1 = channel 0). Beyond
/// `max_channels` the least recently used channel is evicted.
#[derive(Debug)]
pub struct ChannelReassembler {
    max: usize,
    tick: u64,
    slots: Vec<(u32, u64, Frag)>,
}

impl ChannelReassembler {
    pub fn new(max_channels: usize) -> Self {
        Self {
            max: max_channels.max(1),
            tick: 0,
            slots: Vec::new(),
        }
    }

    /// Feed one chunk from any channel. Returns `(chan, frame)` when a frame completes
    /// (`chan == 0` for v1). On error that channel's partial state is dropped.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<(u32, Vec<u8>)>> {
        let &hdr = chunk.first().ok_or(Error::Chunk("empty chunk"))?;
        // A bit6-set header is v2, unless channel 0 is mid-way through a long v1 frame and this is
        // exactly its next chunk (v1 seq 64..=127).
        let v1_cont = hdr & V2 != 0
            && self
                .slots
                .iter()
                .any(|(c, _, f)| *c == 0 && f.active && f.next_seq == hdr & 0x7f);
        let (chan, mask, body) = if hdr & V2 == 0 || v1_cont {
            (0, 0x7f, &chunk[1..])
        } else {
            let (c, _, b) = parse_v2(chunk).ok_or(Error::Chunk("malformed v2 chunk"))?;
            (c, 0x3f, b)
        };
        self.tick += 1;
        let idx = match self.slots.iter().position(|(c, _, _)| *c == chan) {
            Some(i) => i,
            None => {
                if hdr & mask != 0 {
                    return Err(Error::Chunk("chunk without start"));
                }
                if self.slots.len() >= self.max {
                    let lru = (0..self.slots.len())
                        .min_by_key(|&i| self.slots[i].1)
                        .unwrap();
                    self.slots.swap_remove(lru);
                }
                self.slots.push((chan, 0, Frag::default()));
                self.slots.len() - 1
            }
        };
        self.slots[idx].1 = self.tick;
        match self.slots[idx].2.push(hdr, body, mask) {
            Ok(Some(f)) => Ok(Some((chan, f))),
            Ok(None) => Ok(None),
            Err(e) => {
                self.slots.swap_remove(idx);
                Err(e)
            }
        }
    }

    /// Forget a channel (e.g. on disconnect).
    pub fn remove(&mut self, chan: u32) {
        self.slots.retain(|(c, _, _)| *c != chan);
    }

    /// Currently tracked channels, ascending.
    pub fn channels(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.slots.iter().map(|(c, _, _)| *c).collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn roundtrip(mtu in 23usize..=517, len in 0usize..=65535, seed in any::<u8>()) {
            let frame: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect();
            let chunks = chunk(&frame, mtu);
            let mut r = Reassembler::new();
            let mut got = None;
            for (i, c) in chunks.iter().enumerate() {
                prop_assert!(c.len() <= mtu - 3);
                let o = r.push(c).unwrap();
                if i + 1 == chunks.len() { got = o; } else { prop_assert!(o.is_none()); }
            }
            prop_assert_eq!(got.unwrap(), frame);
        }
    }

    #[test]
    fn empty_and_reset_and_gap() {
        let c = chunk(&[], 23);
        assert_eq!(c, vec![vec![0, 0, 0]]);
        let f: Vec<u8> = (0..100).collect();
        let cs = chunk(&f, 23);
        let mut r = Reassembler::new();
        r.push(&cs[0]).unwrap();
        // restart with seq 0 discards partial state
        assert_eq!(r.push(&cs[0]).unwrap(), None);
        assert!(r.push(&cs[2]).is_err());
        for c in &cs[..cs.len() - 1] {
            r.push(c).unwrap();
        }
        // after error state reset: orphan chunk rejected
        assert!(Reassembler::new().push(&cs[1]).is_err());
    }

    fn frame_of(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn v2_roundtrip(mtu in 23usize..=517, len in 0usize..=65535, seed in any::<u8>(), chan in 1u32..) {
            let frame = frame_of(len, seed);
            let chunks = chunk_v2(&frame, mtu, chan);
            let mut r = Reassembler::new_channel(chan);
            let mut cr = ChannelReassembler::new(4);
            let mut got = None;
            for (i, c) in chunks.iter().enumerate() {
                prop_assert!(c.len() <= mtu - 3);
                prop_assert_eq!(chunk_channel(c), Some(chan));
                let o = r.push(c).unwrap();
                let o2 = cr.push(c).unwrap();
                if i + 1 == chunks.len() { got = o; prop_assert_eq!(o2, Some((chan, frame.clone()))); }
                else { prop_assert!(o.is_none()); prop_assert!(o2.is_none()); }
            }
            prop_assert_eq!(got.unwrap(), frame);
        }

        #[test]
        fn interleaved_channels(
            mtu in 23usize..=200,
            lens in proptest::collection::vec(proptest::collection::vec(0usize..3000, 1..4), 2..=4),
            order in proptest::collection::vec(any::<u16>(), 0..64),
        ) {
            // channel k sends several frames back-to-back; chunks of different channels are mixed
            // in pseudo-random order (per-channel order preserved).
            let n = lens.len();
            let mut queues: Vec<std::collections::VecDeque<Vec<u8>>> = Vec::new();
            let mut expect: Vec<Vec<Vec<u8>>> = Vec::new();
            for (k, fl) in lens.iter().enumerate() {
                let chan = 100 + k as u32;
                let mut q = std::collections::VecDeque::new();
                let mut e = Vec::new();
                for (j, &l) in fl.iter().enumerate() {
                    let f = frame_of(l, (k * 7 + j) as u8);
                    q.extend(chunk_v2(&f, mtu, chan));
                    e.push(f);
                }
                queues.push(q);
                expect.push(e);
            }
            let mut cr = ChannelReassembler::new(n);
            let mut hosts: Vec<Reassembler> = (0..n).map(|k| Reassembler::new_channel(100 + k as u32)).collect();
            let mut got: Vec<Vec<Vec<u8>>> = vec![Vec::new(); n];
            let mut got_h: Vec<Vec<Vec<u8>>> = vec![Vec::new(); n];
            let mut step = 0usize;
            while queues.iter().any(|q| !q.is_empty()) {
                let pick = order.get(step).copied().unwrap_or(step as u16) as usize;
                step += 1;
                // random pick, falling back to round-robin over non-empty queues
                let mut k = pick % n;
                while queues[k].is_empty() { k = (k + 1) % n; }
                let c = queues[k].pop_front().unwrap();
                for (h, hr) in hosts.iter_mut().enumerate() {
                    if let Some(f) = hr.push(&c).unwrap() { got_h[h].push(f); }
                }
                if let Some((chan, f)) = cr.push(&c).unwrap() {
                    got[(chan - 100) as usize].push(f);
                }
            }
            prop_assert_eq!(got, expect.clone());
            prop_assert_eq!(got_h, expect);
        }
    }

    #[test]
    fn v2_layout_and_chan0_rejected() {
        let c = chunk_v2(&[1, 2, 3], 23, 0x0403_0201);
        assert_eq!(c, vec![vec![0x40, 1, 2, 3, 4, 3, 0, 1, 2, 3]]);
        let c = chunk_v2(&frame_of(100, 0), 23, 7);
        assert_eq!(c[0][0], 0xC0);
        assert_eq!(c.last().unwrap()[0] & 0x80, 0);
        assert!(std::panic::catch_unwind(|| chunk_v2(&[1], 23, 0)).is_err());
    }

    #[test]
    fn channel_detection() {
        assert_eq!(chunk_channel(&[]), None);
        assert_eq!(chunk_channel(&[0x00, 0, 0]), Some(0));
        assert_eq!(chunk_channel(&[0x40, 1, 0]), None);
        assert_eq!(chunk_channel(&[0x40, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(chunk_channel(&chunk_v2(&[9], 23, 77)[0]), Some(77));
        assert_ne!(random_channel(), 0);
    }

    #[test]
    fn host_filters_foreign_traffic() {
        let a = frame_of(300, 1);
        let b = frame_of(300, 2);
        let ca = chunk_v2(&a, 50, 11);
        let cb = chunk_v2(&b, 50, 22);
        let v1 = chunk(&b, 50);
        let mut r = Reassembler::new_channel(11);
        let mut got = None;
        for i in 0..ca.len().max(cb.len()) {
            if let Some(c) = cb.get(i) {
                assert_eq!(r.push(c).unwrap(), None);
            }
            if let Some(c) = v1.get(i) {
                assert_eq!(r.push(c).unwrap(), None);
            }
            if let Some(c) = ca.get(i) {
                if let Some(f) = r.push(c).unwrap() {
                    got = Some(f);
                }
            }
        }
        assert_eq!(got.unwrap(), a);
        // v1 reassembler is untouched by the new API
        let mut v = Reassembler::new();
        let mut out = None;
        for c in &v1 {
            out = v.push(c).unwrap();
        }
        assert_eq!(out.unwrap(), b);
    }

    #[test]
    fn mixed_v1_v2_and_chunk_for() {
        let a = frame_of(500, 3);
        let b = frame_of(500, 4);
        let ca = chunk_for(&a, 40, 0);
        let cb = chunk_for(&b, 40, 9);
        assert_eq!(ca, chunk(&a, 40));
        assert_eq!(cb, chunk_v2(&b, 40, 9));
        let mut cr = ChannelReassembler::new(4);
        let mut got = Vec::new();
        for i in 0..ca.len().max(cb.len()) {
            for c in [ca.get(i), cb.get(i)].into_iter().flatten() {
                if let Some(x) = cr.push(c).unwrap() {
                    got.push(x);
                }
            }
        }
        got.sort_by_key(|x| x.0);
        assert_eq!(got, vec![(0, a), (9, b)]);
        assert_eq!(cr.channels(), vec![0, 9]);
        cr.remove(9);
        assert_eq!(cr.channels(), vec![0]);
    }

    #[test]
    fn long_v1_frame_in_channel_reassembler() {
        // > 64 chunks: v1 headers get bit6 set from seq 64 on.
        let f = frame_of(2000, 5);
        let mut cr = ChannelReassembler::new(2);
        let mut out = None;
        for c in chunk(&f, 23) {
            out = cr.push(&c).unwrap();
        }
        assert_eq!(out.unwrap(), (0, f));
    }

    #[test]
    fn lru_eviction() {
        let f = frame_of(100, 0);
        let c1 = chunk_v2(&f, 23, 1);
        let c2 = chunk_v2(&f, 23, 2);
        let c3 = chunk_v2(&f, 23, 3);
        let mut cr = ChannelReassembler::new(2);
        cr.push(&c1[0]).unwrap();
        cr.push(&c2[0]).unwrap();
        cr.push(&c1[1]).unwrap(); // chan 1 is now more recent than 2
        cr.push(&c3[0]).unwrap(); // evicts 2
        assert_eq!(cr.channels(), vec![1, 3]);
        assert!(cr.push(&c2[1]).is_err()); // 2 lost its state
        assert_eq!(cr.channels(), vec![1, 3]); // orphan chunk did not evict anyone
    }
}
