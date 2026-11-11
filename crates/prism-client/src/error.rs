use prism_proto::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Proto(#[from] prism_proto::Error),
    #[error("device returned error: {0:?}")]
    Device(ErrorCode),
    #[error("device not paired with this host (put the device in pairing mode and run `prism pair`)")]
    NotPaired,
    #[error("timed out waiting for the device")]
    Timeout,
    #[error("connection closed")]
    Closed,
    #[error("device public key does not match the pinned key (expected {expected}, got {got}); refusing to connect")]
    DeviceKeyMismatch { expected: String, got: String },
    #[error("no device found: {0}")]
    NoDevice(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("unexpected response: {0}")]
    Unexpected(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("core error: {0}")]
    Core(#[from] prism_core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn from_code(c: ErrorCode) -> Self {
        match c {
            ErrorCode::NotPaired => Error::NotPaired,
            c => Error::Device(c),
        }
    }
}
