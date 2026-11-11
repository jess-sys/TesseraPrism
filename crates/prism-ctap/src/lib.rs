//! Transport-agnostic FIDO2 / CTAP 2.1 authenticator for Prism (see docs/ARCHITECTURE.md §6).
//!
//! Private keys are never stored: they are re-derived from the master seed via
//! [`Platform::seed_key`]. Credential ID = `nonce(16) ‖ HMAC-SHA256(wrap_key, rpIdHash ‖ nonce)[..16]`.
//!
//! Implemented: GetInfo, MakeCredential, GetAssertion, GetNextAssertion, Reset, Selection.
//! NOT implemented: CredentialManagement, clientPin/pinUvAuth, extensions (ignored), U2F/MSG.

pub mod auth;
pub mod ble;
pub mod cbor;
pub mod ctaphid;

pub use auth::Authenticator;
pub use prism_core::model::{CoseAlg, Passkey as PasskeyCredential};

/// "PRISM-KEY-v1-001"
pub const AAGUID: [u8; 16] = *b"PRISM-KEY-v1-001";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceKind {
    Register,
    Authenticate,
    Reset,
    Selection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceRequest {
    pub kind: PresenceKind,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceResult {
    Approved,
    Denied,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepaliveStatus {
    Processing,
    UpNeeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    Full,
    Io,
}

pub trait Platform {
    fn rng(&mut self, buf: &mut [u8]);
    /// HKDF from the master seed; `None` if the device is locked.
    fn seed_key(&self, info: &[u8]) -> Option<[u8; 32]>;
    /// Blocking: shows the approval screen and waits for a tap.
    fn user_presence(&mut self, req: &PresenceRequest) -> PresenceResult;
    fn find_resident(&self, rp_id: &str) -> Vec<PasskeyCredential>;
    fn store_resident(&mut self, cred: PasskeyCredential) -> Result<(), StorageError>;
    fn delete_resident(&mut self, cred_id: &[u8]) -> Result<(), StorageError>;
    /// Delete all resident credentials.
    fn reset(&mut self) -> Result<(), StorageError>;
    /// Transport should emit a keepalive while waiting.
    fn keepalive(&mut self, status: KeepaliveStatus);
}
