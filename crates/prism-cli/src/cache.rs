//! Encrypted local password cache (`password-cache.bin`).
//!
//! Layout: `"PRC1" | generated_at u64 LE | expires_at u64 LE | count u32 LE | nonce[24] | ciphertext`.
//! The 24-byte header after the magic is plaintext so `status` works without the keyring, but it is
//! part of the AEAD associated data together with the device public key, so tampering with it (or
//! moving the file to another device's config) makes decryption fail. The cipher is
//! XChaCha20-Poly1305 under a random 256-bit key held in the OS keychain (never on disk).

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{aead::Aead, aead::Payload, KeyInit, XChaCha20Poly1305, XNonce};
use prism_core::model::PasswordSnapshot;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

pub const SERVICE: &str = "ch.neutheria.prism";
const MAGIC: &[u8; 4] = b"PRC1";
const HEADER_LEN: usize = 4 + 8 + 8 + 4;
const NONCE_LEN: usize = 24;
const AAD_PREFIX: &[u8] = b"prism-password-cache-v1";

pub type Key = Zeroizing<[u8; 32]>;

/// Where the cache key lives. The real implementation is the OS keychain; tests inject memory.
pub trait KeyStore: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<Key>>;
    fn set(&self, account: &str, key: &[u8; 32]) -> Result<()>;
    fn delete(&self, account: &str) -> Result<()>;
}

pub struct KeyringStore;

impl KeyringStore {
    fn entry(account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, account).map_err(|e| anyhow!("{e}"))
    }
}

impl KeyStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<Key>> {
        match Self::entry(account)?.get_secret() {
            Ok(b) => {
                let b = Zeroizing::new(b);
                let k: [u8; 32] = b.as_slice().try_into().map_err(|_| anyhow!("keychain entry has the wrong length"))?;
                Ok(Some(Zeroizing::new(k)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("{e}")),
        }
    }
    fn set(&self, account: &str, key: &[u8; 32]) -> Result<()> {
        Self::entry(account)?.set_secret(key).map_err(|e| anyhow!("{e}"))
    }
    fn delete(&self, account: &str) -> Result<()> {
        match Self::entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("{e}")),
        }
    }
}

/// In-memory key store (tests).
#[derive(Default)]
pub struct MemoryKeyStore {
    keys: Mutex<HashMap<String, [u8; 32]>>,
    /// Simulate a missing keychain.
    pub unavailable: bool,
}

impl MemoryKeyStore {
    pub fn unavailable() -> Self {
        Self { keys: Mutex::default(), unavailable: true }
    }
    pub fn len(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl KeyStore for MemoryKeyStore {
    fn get(&self, account: &str) -> Result<Option<Key>> {
        if self.unavailable {
            bail!("no keychain");
        }
        Ok(self.keys.lock().unwrap().get(account).map(|k| Zeroizing::new(*k)))
    }
    fn set(&self, account: &str, key: &[u8; 32]) -> Result<()> {
        if self.unavailable {
            bail!("no keychain");
        }
        self.keys.lock().unwrap().insert(account.to_string(), *key);
        Ok(())
    }
    fn delete(&self, account: &str) -> Result<()> {
        self.keys.lock().unwrap().remove(account);
        Ok(())
    }
}

/// Plaintext header of the cache file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub generated_at: u64,
    pub expires_at: u64,
    pub count: u32,
}

pub enum Loaded {
    Missing,
    /// Past `expires_at`; the file and key were deleted.
    Expired,
    Ok(PasswordSnapshot, Header),
}

pub struct PasswordCache<'a> {
    pub path: PathBuf,
    pub keys: &'a dyn KeyStore,
    pub device: [u8; 32],
}

pub fn cache_path(dir: &Path) -> PathBuf {
    dir.join("password-cache.bin")
}

impl<'a> PasswordCache<'a> {
    pub fn new(dir: &Path, keys: &'a dyn KeyStore, device: [u8; 32]) -> Self {
        Self { path: cache_path(dir), keys, device }
    }

    pub fn account(&self) -> String {
        format!("password-cache-{}", hex::encode(&self.device[..8]))
    }

    fn aad(&self, header: &[u8]) -> Vec<u8> {
        let mut a = AAD_PREFIX.to_vec();
        a.extend_from_slice(&self.device);
        a.extend_from_slice(header);
        a
    }

    /// Encrypt and write `snap`, replacing any previous cache. Refuses if the keychain is unusable.
    pub fn store(&self, snap: &PasswordSnapshot) -> Result<Header> {
        let key = match self.keys.get(&self.account()) {
            Ok(Some(k)) => k,
            Ok(None) | Err(_) => {
                let mut k = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(&mut k[..]);
                self.keys.set(&self.account(), &k).map_err(|e| {
                    anyhow!(
                        "refusing to cache passwords: the OS keychain is unavailable ({e}). \
                         The cache key is never stored in a plain file."
                    )
                })?;
                k
            }
        };
        let header = Header { generated_at: snap.generated_at, expires_at: snap.expires_at, count: snap.entries.len() as u32 };
        let mut hb = Vec::with_capacity(HEADER_LEN);
        hb.extend_from_slice(MAGIC);
        hb.extend_from_slice(&header.generated_at.to_le_bytes());
        hb.extend_from_slice(&header.expires_at.to_le_bytes());
        hb.extend_from_slice(&header.count.to_le_bytes());
        let plain = Zeroizing::new(serde_json::to_vec(snap)?);
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ct = XChaCha20Poly1305::new((&*key).into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &self.aad(&hb) })
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut out = hb;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        write_private(&self.path, &out)?;
        Ok(header)
    }

    /// Read just the plaintext header (no keyring access, no authentication).
    pub fn header(&self) -> Result<Option<Header>> {
        let b = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("reading password cache"),
        };
        Ok(Some(parse_header(&b)?))
    }

    /// Load and decrypt. Expired caches (by header, and again by decrypted content) are deleted.
    pub fn load(&self, now: u64) -> Result<Loaded> {
        let b = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::Missing),
            Err(e) => return Err(e).context("reading password cache"),
        };
        let h = parse_header(&b)?;
        if now >= h.expires_at {
            self.clear()?;
            return Ok(Loaded::Expired);
        }
        if b.len() < HEADER_LEN + NONCE_LEN + 16 {
            bail!("password cache is truncated; run `prism cache clear`");
        }
        let key = self
            .keys
            .get(&self.account())
            .context("keychain unavailable; cannot decrypt the password cache")?
            .ok_or_else(|| anyhow!("cache key missing from the keychain; run `prism cache sync`"))?;
        let (hb, rest) = b.split_at(HEADER_LEN);
        let (nonce, ct) = rest.split_at(NONCE_LEN);
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new((&*key).into())
                .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &self.aad(hb) })
                .map_err(|_| anyhow!("password cache failed authentication (wrong device, wrong key or tampered); run `prism cache clear` and `prism cache sync`"))?,
        );
        let snap: PasswordSnapshot = serde_json::from_slice(&plain).context("decoding password cache")?;
        if now >= snap.expires_at {
            self.clear()?;
            return Ok(Loaded::Expired);
        }
        Ok(Loaded::Ok(snap, h))
    }

    /// Delete the file and the keychain entry (best effort on the keychain). Returns whether a file existed.
    pub fn clear(&self) -> Result<bool> {
        let existed = match std::fs::remove_file(&self.path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e).context("deleting password cache"),
        };
        let _ = self.keys.delete(&self.account());
        Ok(existed)
    }
}

fn parse_header(b: &[u8]) -> Result<Header> {
    if b.len() < HEADER_LEN || &b[..4] != MAGIC {
        bail!("not a password cache file; run `prism cache clear`");
    }
    Ok(Header {
        generated_at: u64::from_le_bytes(b[4..12].try_into().unwrap()),
        expires_at: u64::from_le_bytes(b[12..20].try_into().unwrap()),
        count: u32::from_le_bytes(b[20..24].try_into().unwrap()),
    })
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Parse `off`, `1h`, `1d`, `7d`, `30d`, `N[smhd]` or a bare number of seconds.
pub fn parse_duration(s: &str) -> Result<u32> {
    let t = s.trim().to_lowercase();
    if t == "off" || t == "0" {
        return Ok(0);
    }
    let (num, mult) = match t.chars().last() {
        Some('s') => (&t[..t.len() - 1], 1u64),
        Some('m') => (&t[..t.len() - 1], 60),
        Some('h') => (&t[..t.len() - 1], 3600),
        Some('d') => (&t[..t.len() - 1], 86400),
        Some(c) if c.is_ascii_digit() => (&t[..], 1),
        _ => bail!("expected off, or a duration like 1h, 7d, 30d, 90m, 3600s"),
    };
    let n: u64 = num.parse().map_err(|_| anyhow!("expected off, or a duration like 1h, 7d, 30d, 90m, 3600s"))?;
    u32::try_from(n.checked_mul(mult).ok_or_else(|| anyhow!("duration too large"))?).map_err(|_| anyhow!("duration too large"))
}

/// "3 d 4 h" style, coarse.
pub fn fmt_duration(secs: u64) -> String {
    match secs {
        0 => "0 s".into(),
        s if s < 60 => format!("{s} s"),
        s if s < 3600 => format!("{} min", s / 60),
        s if s < 86400 => format!("{} h {} min", s / 3600, (s % 3600) / 60),
        s => format!("{} d {} h", s / 86400, (s % 86400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_core::model::{CachedPassword, EntryId};

    fn snap(gen: u64, exp: u64) -> PasswordSnapshot {
        PasswordSnapshot {
            generated_at: gen,
            expires_at: exp,
            entries: vec![CachedPassword {
                id: EntryId([7; 16]),
                title: "Bank".into(),
                username: "bob".into(),
                password: "hunter2".into(),
                url: None,
                modified: 1,
            }],
        }
    }

    #[test]
    fn round_trip_and_mode() {
        let d = tempfile::tempdir().unwrap();
        let ks = MemoryKeyStore::default();
        let c = PasswordCache::new(d.path(), &ks, [1; 32]);
        c.store(&snap(100, 1000)).unwrap();
        let raw = std::fs::read(&c.path).unwrap();
        assert!(!raw.windows(7).any(|w| w == b"hunter2"), "plaintext leaked");
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&c.path).unwrap().permissions()) & 0o777, 0o600);
        assert_eq!(c.header().unwrap().unwrap(), Header { generated_at: 100, expires_at: 1000, count: 1 });
        match c.load(500).unwrap() {
            Loaded::Ok(s, _) => assert_eq!(s.entries[0].password, "hunter2"),
            _ => panic!(),
        }
    }

    #[test]
    fn expiry_deletes_file_and_key() {
        let d = tempfile::tempdir().unwrap();
        let ks = MemoryKeyStore::default();
        let c = PasswordCache::new(d.path(), &ks, [1; 32]);
        c.store(&snap(100, 1000)).unwrap();
        assert_eq!(ks.len(), 1);
        assert!(matches!(c.load(1000).unwrap(), Loaded::Expired));
        assert!(!c.path.exists());
        assert!(ks.is_empty());
        assert!(matches!(c.load(1).unwrap(), Loaded::Missing));
    }

    #[test]
    fn aad_binds_device_and_header() {
        let d = tempfile::tempdir().unwrap();
        let ks = MemoryKeyStore::default();
        let c = PasswordCache::new(d.path(), &ks, [1; 32]);
        c.store(&snap(100, 1000)).unwrap();
        // Same key, different device in the AAD -> rejected.
        let key = ks.get(&c.account()).unwrap().unwrap();
        let ks2 = MemoryKeyStore::default();
        let other = PasswordCache::new(d.path(), &ks2, [2; 32]);
        ks2.set(&other.account(), &key).unwrap();
        assert!(other.load(500).is_err());
        // Header tamper (extend expiry) -> rejected.
        let mut raw = std::fs::read(&c.path).unwrap();
        raw[12..20].copy_from_slice(&9999u64.to_le_bytes());
        std::fs::write(&c.path, raw).unwrap();
        assert!(c.load(500).is_err());
    }

    #[test]
    fn keyring_unavailable_refuses() {
        let d = tempfile::tempdir().unwrap();
        let ks = MemoryKeyStore::unavailable();
        let c = PasswordCache::new(d.path(), &ks, [1; 32]);
        let e = c.store(&snap(1, 2)).unwrap_err().to_string();
        assert!(e.contains("refusing"), "{e}");
        assert!(!c.path.exists());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("off").unwrap(), 0);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert_eq!(parse_duration("7d").unwrap(), 604800);
        assert_eq!(parse_duration("30d").unwrap(), 2592000);
        assert_eq!(parse_duration("90m").unwrap(), 5400);
        assert_eq!(parse_duration("45s").unwrap(), 45);
        assert_eq!(parse_duration("120").unwrap(), 120);
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("99999999d").is_err());
    }
}
