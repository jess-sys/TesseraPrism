//! Prism wire protocol (ARCHITECTURE §5): messages, framing, BLE chunking, CDC COBS framing and a
//! sans-IO Noise_XX session. No I/O, no async; builds for host, ESP-IDF and wasm32.
//!
//! Noise message size limit is 65535 bytes (16 of them AEAD tag, +1 frame-kind byte), so a single
//! encrypted request/response may carry at most [`session::MAX_PLAINTEXT`] (65 518) bytes of
//! postcard. Anything larger (Export/Import data) MUST be chunked at the application level
//! (`ExportChunk`/`ImportChunk` carry <= 8 KiB; keep payloads under ~65 000 bytes).

pub mod ble;
pub mod cdc;
pub mod frame;
pub mod messages;
pub mod session;

pub use messages::{Envelope, ErrorCode, ProtoError, Request, Response};
pub use session::{generate_static_keypair, DeviceEvent, DeviceSession, HostSession, SessionEvent};

/// Crate error type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("frame too large")]
    FrameTooLarge,
    #[error("empty frame")]
    EmptyFrame,
    #[error("unknown frame kind {0:#04x}")]
    UnknownFrameKind(u8),
    #[error("ble chunk error: {0}")]
    Chunk(&'static str),
    #[error("cobs decode error")]
    Cobs,
    #[error("noise error: {0}")]
    Noise(String),
    #[error("session in wrong state: {0}")]
    State(&'static str),
    #[error("codec error: {0}")]
    Codec(String),
    #[error("plain error from peer: {0:?}")]
    Plain(ProtoError),
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Error::Noise(e.to_string())
    }
}
impl From<postcard::Error> for Error {
    fn from(e: postcard::Error) -> Self {
        Error::Codec(e.to_string())
    }
}
