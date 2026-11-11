//! CTAPHID framing (64-byte reports), sans-IO.
//!
//! Handled internally by [`CtapHid`] (replies are queued, drain with [`CtapHid::take_outbox`]):
//! INIT, PING, MSG (-> ERR_INVALID_CMD), unknown commands and all protocol errors.
//! Returned to the caller as a [`CompletedRequest`]: CBOR, WINK, CANCEL.
//! The caller answers CBOR/WINK with [`CtapHid::response_reports`].

pub const REPORT_SIZE: usize = 64;
pub const MAX_MESSAGE: usize = 7609;
pub const BROADCAST_CID: u32 = 0xffff_ffff;

pub const CMD_PING: u8 = 0x01;
pub const CMD_MSG: u8 = 0x03;
pub const CMD_LOCK: u8 = 0x04;
pub const CMD_INIT: u8 = 0x06;
pub const CMD_WINK: u8 = 0x08;
pub const CMD_CBOR: u8 = 0x10;
pub const CMD_CANCEL: u8 = 0x11;
pub const CMD_KEEPALIVE: u8 = 0x3B;
pub const CMD_ERROR: u8 = 0x3F;

pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_INVALID_CID: u8 = 0x0B;
pub const ERR_OTHER: u8 = 0x7F;

pub const CAP_WINK: u8 = 0x01;
pub const CAP_CBOR: u8 = 0x04;
pub const CAP_NMSG: u8 = 0x08;

pub const KEEPALIVE_PROCESSING: u8 = 1;
pub const KEEPALIVE_UP_NEEDED: u8 = 2;

const INIT_DATA: usize = REPORT_SIZE - 7;
const CONT_DATA: usize = REPORT_SIZE - 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedRequest {
    pub cid: u32,
    /// Command without the 0x80 bit.
    pub cmd: u8,
    pub payload: Vec<u8>,
}

struct Assembly {
    cid: u32,
    cmd: u8,
    total: usize,
    buf: Vec<u8>,
    next_seq: u8,
}

pub struct CtapHid {
    next_cid: u32,
    assembly: Option<Assembly>,
    /// Channel with a request currently being processed by the application.
    processing: Option<u32>,
    outbox: Vec<[u8; 64]>,
}

impl Default for CtapHid {
    fn default() -> Self {
        Self::new()
    }
}

impl CtapHid {
    pub fn new() -> Self {
        Self { next_cid: 1, assembly: None, processing: None, outbox: Vec::new() }
    }

    /// Reports queued for immediate sending (INIT/PING replies, errors).
    pub fn take_outbox(&mut self) -> Vec<[u8; 64]> {
        core::mem::take(&mut self.outbox)
    }

    /// Drop a half-assembled message (call when the transport's ~500 ms timeout expires).
    /// Queues ERR_MSG_TIMEOUT on that channel.
    pub fn timeout_assembly(&mut self) {
        if let Some(a) = self.assembly.take() {
            self.queue_error(a.cid, ERR_MSG_TIMEOUT);
        }
    }

    pub fn is_busy(&self) -> bool {
        self.assembly.is_some() || self.processing.is_some()
    }

    fn queue_error(&mut self, cid: u32, code: u8) {
        let r = build_reports(cid, CMD_ERROR, &[code]);
        self.outbox.extend(r);
    }

    fn alloc_cid(&mut self) -> u32 {
        loop {
            let c = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1);
            if c != 0 && c != BROADCAST_CID {
                return c;
            }
        }
    }

    pub fn push_report(&mut self, r: &[u8; 64]) -> Option<CompletedRequest> {
        let cid = u32::from_be_bytes([r[0], r[1], r[2], r[3]]);
        if cid == 0 {
            self.queue_error(cid, ERR_INVALID_CID);
            return None;
        }
        if r[4] & 0x80 != 0 {
            self.init_packet(cid, r)
        } else {
            self.cont_packet(cid, r)
        }
    }

    fn init_packet(&mut self, cid: u32, r: &[u8; 64]) -> Option<CompletedRequest> {
        let cmd = r[4] & 0x7f;
        let len = u16::from_be_bytes([r[5], r[6]]) as usize;

        // INIT is always allowed and resynchronises its channel.
        if cmd == CMD_INIT {
            if self.assembly.as_ref().map(|a| a.cid) == Some(cid) {
                self.assembly = None;
            }
            if let Some(a) = &self.assembly {
                let _ = a;
                self.queue_error(cid, ERR_CHANNEL_BUSY);
                return None;
            }
            if len != 8 {
                self.queue_error(cid, ERR_INVALID_LEN);
                return None;
            }
            let new_cid = if cid == BROADCAST_CID { self.alloc_cid() } else { cid };
            let mut p = Vec::with_capacity(17);
            p.extend_from_slice(&r[7..15]);
            p.extend_from_slice(&new_cid.to_be_bytes());
            p.extend_from_slice(&[2, 1, 0, 0, CAP_WINK | CAP_CBOR | CAP_NMSG]);
            let reps = build_reports(cid, CMD_INIT, &p);
            self.outbox.extend(reps);
            return None;
        }
        if cid == BROADCAST_CID {
            self.queue_error(cid, ERR_INVALID_CID);
            return None;
        }
        if self.processing.is_some() || self.assembly.is_some() {
            // New init packet while busy: other channel -> busy; same channel mid-message -> seq error.
            if self.assembly.as_ref().map(|a| a.cid) == Some(cid) {
                self.assembly = None;
                self.queue_error(cid, ERR_INVALID_SEQ);
            } else if cmd == CMD_CANCEL && self.processing == Some(cid) {
                return Some(CompletedRequest { cid, cmd, payload: Vec::new() });
            } else {
                self.queue_error(cid, ERR_CHANNEL_BUSY);
            }
            return None;
        }
        if len > MAX_MESSAGE {
            self.queue_error(cid, ERR_INVALID_LEN);
            return None;
        }
        let take = len.min(INIT_DATA);
        let mut buf = Vec::with_capacity(len);
        buf.extend_from_slice(&r[7..7 + take]);
        if len <= INIT_DATA {
            return self.complete(cid, cmd, buf);
        }
        self.assembly = Some(Assembly { cid, cmd, total: len, buf, next_seq: 0 });
        None
    }

    fn cont_packet(&mut self, cid: u32, r: &[u8; 64]) -> Option<CompletedRequest> {
        let a = match &mut self.assembly {
            Some(a) if a.cid == cid => a,
            Some(_) => {
                self.queue_error(cid, ERR_CHANNEL_BUSY);
                return None;
            }
            None => return None, // spurious continuation: ignore per spec
        };
        if r[4] != a.next_seq {
            self.assembly = None;
            self.queue_error(cid, ERR_INVALID_SEQ);
            return None;
        }
        a.next_seq = a.next_seq.wrapping_add(1);
        let take = (a.total - a.buf.len()).min(CONT_DATA);
        a.buf.extend_from_slice(&r[5..5 + take]);
        if a.buf.len() == a.total {
            let a = self.assembly.take().unwrap();
            return self.complete(a.cid, a.cmd, a.buf);
        }
        None
    }

    fn complete(&mut self, cid: u32, cmd: u8, payload: Vec<u8>) -> Option<CompletedRequest> {
        match cmd {
            CMD_PING => {
                let r = build_reports(cid, CMD_PING, &payload);
                self.outbox.extend(r);
                None
            }
            CMD_MSG => {
                self.queue_error(cid, ERR_INVALID_CMD);
                None
            }
            CMD_CBOR => {
                self.processing = Some(cid);
                Some(CompletedRequest { cid, cmd, payload })
            }
            CMD_WINK | CMD_CANCEL => Some(CompletedRequest { cid, cmd, payload }),
            _ => {
                self.queue_error(cid, ERR_INVALID_CMD);
                None
            }
        }
    }

    /// Build the reports for a response; also marks the channel as no longer busy.
    pub fn response_reports(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; 64]> {
        if self.processing == Some(cid) {
            self.processing = None;
        }
        build_reports(cid, cmd, payload)
    }
}

/// Fragment a message into reports (stateless).
pub fn build_reports(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; 64]> {
    let mut out = Vec::new();
    let mut r = [0u8; 64];
    r[..4].copy_from_slice(&cid.to_be_bytes());
    r[4] = cmd | 0x80;
    r[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let n = payload.len().min(INIT_DATA);
    r[7..7 + n].copy_from_slice(&payload[..n]);
    out.push(r);
    let mut seq = 0u8;
    for chunk in payload[n..].chunks(CONT_DATA) {
        let mut r = [0u8; 64];
        r[..4].copy_from_slice(&cid.to_be_bytes());
        r[4] = seq;
        seq = seq.wrapping_add(1);
        r[5..5 + chunk.len()].copy_from_slice(chunk);
        out.push(r);
    }
    out
}

/// A KEEPALIVE report (status: [`KEEPALIVE_PROCESSING`] / [`KEEPALIVE_UP_NEEDED`]).
pub fn keepalive_report(cid: u32, status: u8) -> [u8; 64] {
    build_reports(cid, CMD_KEEPALIVE, &[status])[0]
}

/// An ERROR report.
pub fn error_report(cid: u32, code: u8) -> [u8; 64] {
    build_reports(cid, CMD_ERROR, &[code])[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init(h: &mut CtapHid, nonce: [u8; 8]) -> u32 {
        let reps = build_reports(BROADCAST_CID, CMD_INIT, &nonce);
        assert!(h.push_report(&reps[0]).is_none());
        let out = h.take_outbox();
        assert_eq!(out.len(), 1);
        let r = out[0];
        assert_eq!(r[4], 0x80 | CMD_INIT);
        assert_eq!(&r[7..15], &nonce);
        assert_eq!(r[19], 2);
        assert_eq!(r[23] & CAP_CBOR, CAP_CBOR);
        u32::from_be_bytes([r[15], r[16], r[17], r[18]])
    }

    #[test]
    fn init_allocates_distinct_channels() {
        let mut h = CtapHid::new();
        let a = init(&mut h, [1; 8]);
        let b = init(&mut h, [2; 8]);
        assert_ne!(a, b);
    }

    #[test]
    fn fragmented_cbor_roundtrip() {
        let mut h = CtapHid::new();
        let cid = init(&mut h, [9; 8]);
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let reps = build_reports(cid, CMD_CBOR, &payload);
        assert_eq!(reps.len(), 1 + (1000 - 57 + 58) / 59);
        let mut done = None;
        for r in &reps {
            assert!(done.is_none());
            done = h.push_report(r);
        }
        let req = done.unwrap();
        assert_eq!((req.cid, req.cmd), (cid, CMD_CBOR));
        assert_eq!(req.payload, payload);
        assert!(h.is_busy());
        // other channel is busy meanwhile
        let other = build_reports(0x1234, CMD_PING, &[1]);
        assert!(h.push_report(&other[0]).is_none());
        assert_eq!(h.take_outbox()[0][7], ERR_CHANNEL_BUSY);
        // response fragmentation reassembles
        let resp: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
        let out = h.response_reports(cid, CMD_CBOR, &resp);
        assert!(out.len() > 1);
        let mut h2 = CtapHid::new();
        let mut got = None;
        for r in &out {
            got = h2.push_report(r).or(got);
        }
        // CBOR cmd is returned to caller by reassembler
        assert_eq!(got.unwrap().payload, resp);
        assert!(!h.is_busy());
    }

    #[test]
    fn bad_sequence_and_len() {
        let mut h = CtapHid::new();
        let cid = init(&mut h, [0; 8]);
        let reps = build_reports(cid, CMD_CBOR, &[0u8; 200]);
        h.push_report(&reps[0]);
        h.push_report(&reps[2]);
        assert_eq!(h.take_outbox()[0][7], ERR_INVALID_SEQ);
        let mut big = [0u8; 64];
        big[..4].copy_from_slice(&cid.to_be_bytes());
        big[4] = 0x80 | CMD_CBOR;
        big[5..7].copy_from_slice(&((MAX_MESSAGE + 1) as u16).to_be_bytes());
        h.push_report(&big);
        assert_eq!(h.take_outbox()[0][7], ERR_INVALID_LEN);
    }

    #[test]
    fn ping_msg_and_unknown() {
        let mut h = CtapHid::new();
        let cid = init(&mut h, [0; 8]);
        let data: Vec<u8> = (0..100).collect();
        for r in build_reports(cid, CMD_PING, &data) {
            h.push_report(&r);
        }
        let out = h.take_outbox();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][4], 0x80 | CMD_PING);
        h.push_report(&build_reports(cid, CMD_MSG, &[0, 3, 0, 0])[0]);
        assert_eq!(h.take_outbox()[0][7], ERR_INVALID_CMD);
        h.push_report(&build_reports(BROADCAST_CID, CMD_CBOR, &[4])[0]);
        assert_eq!(h.take_outbox()[0][7], ERR_INVALID_CID);
    }

    #[test]
    fn keepalive_format() {
        let r = keepalive_report(5, KEEPALIVE_UP_NEEDED);
        assert_eq!(&r[..8], &[0, 0, 0, 5, 0xBB, 0, 1, 2]);
    }
}
