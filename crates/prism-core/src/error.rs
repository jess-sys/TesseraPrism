use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Wrong PIN / passphrase (slot AEAD failed to open).
    #[error("wrong PIN or passphrase")]
    BadCredential,
    /// Ciphertext failed authentication or is corrupt.
    #[error("vault or export data is corrupt or was tampered with")]
    Corrupt,
    #[error("bad file format: {0}")]
    Format(&'static str),
    #[error("unsupported version {0}")]
    UnsupportedVersion(u16),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("key derivation error: {0}")]
    Kdf(String),
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    Duplicate,
    #[error("no such key slot")]
    NoSlot,
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),
    #[error("invalid base32")]
    Base32,
    #[error("invalid otpauth URI: {0}")]
    Otpauth(String),
}

impl From<postcard::Error> for Error {
    fn from(e: postcard::Error) -> Self {
        Error::Serde(e.to_string())
    }
}
