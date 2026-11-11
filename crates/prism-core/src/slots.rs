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
    /// 4 MiB (fits the device's PSRAM next to everything else) with more passes to compensate.
    pub const RECOVERY: KdfParams = KdfParams { m_kib: 4096, t: 8, p: 1 };
    pub const EXPORT: KdfParams = KdfParams { m_kib: 4096, t: 8, p: 1 };
    /// Minimal parameters for fast tests. NEVER use in production.
    pub const TEST: KdfParams = KdfParams { m_kib: 8, t: 1, p: 1 };
}

/// Largest Argon2 memory (KiB) this process accepts. Parameters come from stored slots and from
/// imported files, so a crafted file could otherwise request more memory than an embedded device
/// has (allocation failure aborts). Platforms set it once at startup; default: unlimited.
static MAX_KDF_MEMORY_KIB: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

pub fn set_max_kdf_memory_kib(kib: u32) {
    MAX_KDF_MEMORY_KIB.store(kib, core::sync::atomic::Ordering::Relaxed);
}

/// Optional pre-allocated Argon2 working memory (1 KiB blocks). Embedded targets reserve it once at
/// boot, before the heap fragments, so key derivation never needs a large allocation at runtime
/// (which can fail and abort) and always runs in the same memory. Wiped after every use.
static KDF_SCRATCH: std::sync::Mutex<Option<Vec<argon2::Block>>> = std::sync::Mutex::new(None);

/// Reserve `blocks` KiB of Argon2 working memory for all later derivations.
pub fn set_kdf_scratch_blocks(blocks: usize) {
    *KDF_SCRATCH.lock().unwrap_or_else(|e| e.into_inner()) = Some(vec![argon2::Block::default(); blocks]);
}

/// Compute every derivation twice and only accept agreeing results (embedded targets whose memory
/// can return bad data under Argon2's load: a corrupted KEK would count a correct PIN as wrong, or
/// wrap a slot that never opens again). Default off.
static KDF_VERIFY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn set_kdf_verify(on: bool) {
    KDF_VERIFY.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Argon2id(secret, salt) -> 32 bytes.
pub fn argon2_derive(secret: &[u8], salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    if !KDF_VERIFY.load(core::sync::atomic::Ordering::Relaxed) {
        return argon2_once(secret, salt, params);
    }
    const MAX_RUNS: usize = 8;
    let mut prev = argon2_once(secret, salt, params)?;
    for _ in 1..MAX_RUNS {
        let cur = argon2_once(secret, salt, params)?;
        if *cur == *prev {
            return Ok(cur);
        }
        prev = cur;
    }
    Err(Error::Kdf("unstable hardware: repeated Argon2 runs disagree".into()))
}

fn argon2_once(secret: &[u8], salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let max = MAX_KDF_MEMORY_KIB.load(core::sync::atomic::Ordering::Relaxed);
    if params.m_kib > max {
        return Err(Error::Kdf(format!("Argon2 memory {} KiB exceeds this device's limit of {max} KiB", params.m_kib)));
    }
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let need = p.block_count();
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    let mut scratch = KDF_SCRATCH.lock().unwrap_or_else(|e| e.into_inner());
    match scratch.as_mut() {
        Some(buf) if buf.len() >= need => {
            let r = a.hash_password_into_with_memory(secret, salt, &mut *out, &mut buf[..need]);
            for b in buf[..need].iter_mut() {
                zeroize::Zeroize::zeroize(b);
            }
            r.map_err(|e| Error::Kdf(e.to_string()))?;
        }
        _ => {
            drop(scratch);
            a.hash_password_into(secret, salt, &mut *out).map_err(|e| Error::Kdf(e.to_string()))?;
        }
    }
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
