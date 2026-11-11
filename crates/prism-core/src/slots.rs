//! Key slots and vault header (ARCHITECTURE §3.1).

use crate::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAGIC: [u8; 4] = *b"PRSM";
pub const VERSION: u16 = 1;

/// Hook for hardware-bound KEK hardening (prod profile: HMAC with eFuse key).
pub trait KekHardener {
    fn harden(&self, k: [u8; 32]) -> [u8; 32];
}

/// No hardware hardening (dev profile).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHardening;
impl KekHardener for NoHardening {
    fn harden(&self, k: [u8; 32]) -> [u8; 32] {
        k
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotKind {
    Pin,
    Recovery,
}

impl SlotKind {
    fn tag(self) -> u8 {
        match self {
            SlotKind::Pin => 0,
            SlotKind::Recovery => 1,
        }
    }
}

/// Argon2id parameters (stored per slot / export for forward compatibility).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub const PIN: KdfParams = KdfParams { m_kib: 4096, t: 3, p: 1 };
    pub const RECOVERY: KdfParams = KdfParams { m_kib: 8192, t: 4, p: 1 };
    pub const EXPORT: KdfParams = KdfParams { m_kib: 8192, t: 4, p: 1 };
    /// Minimal parameters for fast tests. NEVER use in production.
    pub const TEST: KdfParams = KdfParams { m_kib: 8, t: 1, p: 1 };
}

/// Argon2id(secret, salt) -> 32 bytes.
pub fn argon2_derive(secret: &[u8], salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(secret, salt, &mut *out)
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySlot {
    pub kind: SlotKind,
    pub params: KdfParams,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    /// XChaCha20-Poly1305(KEK, seed) incl. 16-byte tag (48 bytes).
    pub wrapped: Vec<u8>,
}

fn slot_aad(kind: SlotKind) -> Vec<u8> {
    let mut a = b"prism-slot".to_vec();
    a.push(kind.tag());
    a
}

fn kek(
    kind: SlotKind,
    secret: &[u8],
    salt: &[u8],
    params: &KdfParams,
    hardener: &dyn KekHardener,
) -> Result<Zeroizing<[u8; 32]>> {
    let k = argon2_derive(secret, salt, params)?;
    Ok(match kind {
        SlotKind::Pin => Zeroizing::new(hardener.harden(*k)),
        SlotKind::Recovery => k,
    })
}

impl KeySlot {
    /// Wrap `seed` under a KEK derived from `secret`. `hardener` is only applied to PIN slots.
    pub fn wrap(
        kind: SlotKind,
        secret: &[u8],
        params: KdfParams,
        seed: &[u8; 32],
        hardener: &dyn KekHardener,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Self> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);
        let k = kek(kind, secret, &salt, &params, hardener)?;
        let c = XChaCha20Poly1305::new((&*k).into());
        let wrapped = c
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: seed, aad: &slot_aad(kind) })
            .map_err(|_| Error::Corrupt)?;
        Ok(KeySlot { kind, params, salt, nonce, wrapped })
    }

    /// Recover the seed. `Err(BadCredential)` on wrong secret.
    pub fn unwrap_seed(&self, secret: &[u8], hardener: &dyn KekHardener) -> Result<Zeroizing<[u8; 32]>> {
        let k = kek(self.kind, secret, &self.salt, &self.params, hardener)?;
        let c = XChaCha20Poly1305::new((&*k).into());
        let pt = c
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload { msg: &self.wrapped, aad: &slot_aad(self.kind) },
            )
            .map_err(|_| Error::BadCredential)?;
        let pt = Zeroizing::new(pt);
        if pt.len() != 32 {
            return Err(Error::Corrupt);
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&pt);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub generation: u64,
    pub slots: Vec<KeySlot>,
}

impl VaultHeader {
    pub fn new(slots: Vec<KeySlot>) -> Self {
        VaultHeader { magic: MAGIC, version: VERSION, generation: 0, slots }
    }
    pub fn slot(&self, kind: SlotKind) -> Option<&KeySlot> {
        self.slots.iter().find(|s| s.kind == kind)
    }
    pub fn has_recovery(&self) -> bool {
        self.slot(SlotKind::Recovery).is_some()
    }
    /// Insert or replace the slot of the same kind.
    pub fn set_slot(&mut self, slot: KeySlot) {
        self.slots.retain(|s| s.kind != slot.kind);
        self.slots.push(slot);
    }
    pub fn remove_slot(&mut self, kind: SlotKind) -> bool {
        let n = self.slots.len();
        self.slots.retain(|s| s.kind != kind);
        n != self.slots.len()
    }
}
