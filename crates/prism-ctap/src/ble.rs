//! FIDO CTAP-over-BLE framing (FIDO GATT service 0xFFFD).
//!
//! Frames: initial = CMD(1) HLEN(1) LLEN(1) data; continuation = SEQ(1) data.
//! Fragment size is bounded by `fidoControlPointLength` (>= 20).

pub const CMD_PING: u8 = 0x81;
pub const CMD_KEEPALIVE: u8 = 0x82;
pub const CMD_MSG: u8 = 0x83;
pub const CMD_CANCEL: u8 = 0xBE;
pub const CMD_ERROR: u8 = 0xBF;

pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_REQ_TIMEOUT: u8 = 0x05;
pub const ERR_OTHER: u8 = 0x7F;

pub const KEEPALIVE_PROCESSING: u8 = 1;
pub const KEEPALIVE_UP_NEEDED: u8 = 2;

/// Split a message into BLE frames no larger than `max_len` (the control point length, >= 20).
pub fn fragment(cmd: u8, payload: &[u8], max_len: usize) -> Vec<Vec<u8>> {
    let max_len = max_len.max(20);
    let first = payload.len().min(max_len - 3);
    let mut out = Vec::new();
    let mut f = vec![cmd, (payload.len() >> 8) as u8, payload.len() as u8];
    f.extend_from_slice(&payload[..first]);
    out.push(f);
    for (i, c) in payload[first..].chunks(max_len - 1).enumerate() {
        let mut f = vec![(i & 0x7f) as u8];
        f.extend_from_slice(c);
        out.push(f);
    }
    out
}

pub fn keepalive_frame(status: u8) -> Vec<u8> {
    fragment(CMD_KEEPALIVE, &[status], 20).remove(0)
}

pub fn error_frame(code: u8) -> Vec<u8> {
    fragment(CMD_ERROR, &[code], 20).remove(0)
}

#[derive(Debug, PartialEq, Eq)]
pub enum BleError {
    /// Protocol error; the contained code should be sent via [`error_frame`].
    Protocol(u8),
}

/// Reassembles frames written to the FIDO Control Point.
#[derive(Default)]
pub struct BleAssembler {
    cmd: u8,
    total: usize,
    buf: Vec<u8>,
    next_seq: u8,
    active: bool,
}

impl BleAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Abort a partial message (e.g. on connection loss or timeout).
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Feed one frame. Returns `Some((cmd, payload))` when a message is complete.
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<(u8, Vec<u8>)>, BleError> {
        if frame.is_empty() {
            return Err(BleError::Protocol(ERR_INVALID_LEN));
        }
        if frame[0] & 0x80 != 0 {
            // A new initial frame while one is in progress is a sequencing error.
            if self.active {
                self.reset();
                return Err(BleError::Protocol(ERR_INVALID_SEQ));
            }
            if frame.len() < 3 {
                return Err(BleError::Protocol(ERR_INVALID_LEN));
            }
            let total = ((frame[1] as usize) << 8) | frame[2] as usize;
            let data = &frame[3..];
            if data.len() >= total {
                return Ok(Some((frame[0], data[..total].to_vec())));
            }
            self.cmd = frame[0];
            self.total = total;
            self.buf = data.to_vec();
            self.next_seq = 0;
            self.active = true;
            Ok(None)
        } else {
            if !self.active {
                return Err(BleError::Protocol(ERR_INVALID_SEQ));
            }
            if frame[0] != self.next_seq {
                self.reset();
                return Err(BleError::Protocol(ERR_INVALID_SEQ));
            }
            self.next_seq = (self.next_seq + 1) & 0x7f;
            let need = self.total - self.buf.len();
            let data = &frame[1..];
            if data.len() > need {
                self.reset();
                return Err(BleError::Protocol(ERR_INVALID_LEN));
            }
            self.buf.extend_from_slice(data);
            if self.buf.len() == self.total {
                let cmd = self.cmd;
                let buf = core::mem::take(&mut self.buf);
                self.reset();
                return Ok(Some((cmd, buf)));
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for (len, mtu) in [(0usize, 20usize), (10, 20), (17, 20), (18, 20), (500, 20), (3000, 185)] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let frames = fragment(CMD_MSG, &payload, mtu);
            assert!(frames.iter().all(|f| f.len() <= mtu));
            let mut a = BleAssembler::new();
            let mut out = None;
            for f in &frames {
                out = a.push(f).unwrap().or(out);
            }
            assert_eq!(out, Some((CMD_MSG, payload)));
        }
    }

    #[test]
    fn errors() {
        let frames = fragment(CMD_MSG, &[1u8; 100], 20);
        let mut a = BleAssembler::new();
        a.push(&frames[0]).unwrap();
        assert_eq!(a.push(&frames[2]), Err(BleError::Protocol(ERR_INVALID_SEQ)));
        assert_eq!(a.push(&[0, 1]), Err(BleError::Protocol(ERR_INVALID_SEQ)));
        assert_eq!(keepalive_frame(2), vec![CMD_KEEPALIVE, 0, 1, 2]);
    }
}
