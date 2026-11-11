//! Prism core: data model, vault crypto, key slots, BIP39 seed, derivation, TOTP, export.
//! See docs/ARCHITECTURE.md §3–4.

pub mod bip39;
pub mod error;
pub mod export;
pub mod model;
pub mod password_gen;
pub mod slots;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};
pub use slots::{KdfParams, KekHardener, KeySlot, NoHardening, SlotKind, VaultHeader};
pub use vault::{UnlockedVault, VaultFile};
