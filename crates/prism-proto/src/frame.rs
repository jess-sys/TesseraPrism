//! Frames: `[kind: u8][payload...]`, at most [`MAX_FRAME`] bytes in total.

use crate::{messages::ProtoError, Error, Result};

pub const HANDSHAKE: u8 = 0x01;
pub const TRANSPORT: u8 = 0x02;
pub const PLAIN_ERROR: u8 = 0x03;
pub const MAX_FRAME: usize = 65535;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Handshake,
    Transport,
    PlainError,
}

impl FrameKind {
    pub fn byte(self) -> u8 {
        match self {
            FrameKind::Handshake => HANDSHAKE,
            FrameKind::Transport => TRANSPORT,
            FrameKind::PlainError => PLAIN_ERROR,
        }
    }
}

/// Build a frame from kind + payload.
pub fn build(kind: FrameKind, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() + 1 > MAX_FRAME {
        return Err(Error::FrameTooLarge);
    }
    let mut v = Vec::with_capacity(payload.len() + 1);
    v.push(kind.byte());
    v.extend_from_slice(payload);
    Ok(v)
}

/// Split a frame into kind + payload.
pub fn parse(frame: &[u8]) -> Result<(FrameKind, &[u8])> {
    if frame.len() > MAX_FRAME {
        return Err(Error::FrameTooLarge);
    }
    let (&k, rest) = frame.split_first().ok_or(Error::EmptyFrame)?;
    let kind = match k {
        HANDSHAKE => FrameKind::Handshake,
        TRANSPORT => FrameKind::Transport,
        PLAIN_ERROR => FrameKind::PlainError,
        o => return Err(Error::UnknownFrameKind(o)),
    };
    Ok((kind, rest))
}

/// Build a `PLAIN_ERROR` frame (only valid before the session is established).
pub fn plain_error(e: &ProtoError) -> Result<Vec<u8>> {
    build(FrameKind::PlainError, &postcard::to_stdvec(e)?)
}
