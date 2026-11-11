//! `.prism` export file (ARCHITECTURE §3.3) and merge semantics.

use crate::model::*;
use crate::slots::{argon2_derive, KdfParams};
use crate::vault::derive_key_from_seed;
use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const EXPORT_MAGIC: &[u8; 8] = b"PRSMEXP1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportHeader {
    pub params: KdfParams,
    pub salt: [u8; 16],
    pub created: u64,
}

#[derive(Serialize, Deserialize)]
struct ExportPayload {
    seed: [u8; 32],
    vault: Vault,
}

impl Drop for ExportPayload {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.seed);
    }
}

/// Encrypt `seed` + `vault` under a key from `passphrase`.
pub fn export(
    seed: &[u8; 32],
    vault: &Vault,
    passphrase: &str,
    params: KdfParams,
    created: u64,
    rng: &mut dyn CryptoRngCore,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let header = ExportHeader { params, salt, created };
    let mut out = EXPORT_MAGIC.to_vec();
    out.extend(postcard::to_stdvec(&header)?);
    let key = argon2_derive(passphrase.as_bytes(), &salt, &params)?;
    let payload = ExportPayload { seed: *seed, vault: vault.clone() };
    let pt = Zeroizing::new(postcard::to_stdvec(&payload)?);
    let c = XChaCha20Poly1305::new((&*key).into());
    let ct = c
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &pt, aad: &out })
        .map_err(|_| Error::Corrupt)?;
    out.extend_from_slice(&nonce);
    out.extend(ct);
    Ok(out)
}

/// Decrypt an export. Wrong passphrase and tampering both yield `BadCredential`.
pub fn import(bytes: &[u8], passphrase: &str) -> Result<(Zeroizing<[u8; 32]>, Vault)> {
    let rest = bytes.strip_prefix(EXPORT_MAGIC.as_slice()).ok_or(Error::Format("bad export magic"))?;
    let (header, tail): (ExportHeader, &[u8]) =
        postcard::take_from_bytes(rest).map_err(|_| Error::Format("bad export header"))?;
    if tail.len() < 24 + 16 {
        return Err(Error::Format("truncated"));
    }
    let aad = &bytes[..bytes.len() - tail.len()];
    let key = argon2_derive(passphrase.as_bytes(), &header.salt, &header.params)?;
    let c = XChaCha20Poly1305::new((&*key).into());
    let pt = c
        .decrypt(XNonce::from_slice(&tail[..24]), Payload { msg: &tail[24..], aad })
        .map_err(|_| Error::BadCredential)?;
    let pt = Zeroizing::new(pt);
    let p: ExportPayload = postcard::from_bytes(&pt)?;
    let seed = Zeroizing::new(p.seed);
    let vault = p.vault.clone();
    Ok((seed, vault))
}

/// Merge `incoming` into `local` (ImportMode::Merge): by id, newest `modified` wins (ties keep
/// local). If seeds differ, incoming seed-derived SSH keys become `Imported` so they keep working.
pub fn merge(local: &mut Vault, local_seed: &[u8; 32], incoming: Vault, incoming_seed: &[u8; 32]) {
    let same_seed = local_seed == incoming_seed;
    for mut e in incoming.entries {
        if !same_seed {
            if let EntryData::SshKey(k) = &mut e.data {
                if let SshKeySource::Derived { index } = k.source {
                    let s = derive_key_from_seed(incoming_seed, format!("ssh-ed25519/{index}").as_bytes());
                    debug_assert_eq!(SigningKey::from_bytes(&s).verifying_key().to_bytes(), k.public_key);
                    k.source = SshKeySource::Imported { secret: *s };
                }
            }
        }
        match local.entries.iter_mut().find(|l| l.id == e.id) {
            Some(l) => {
                if e.modified > l.modified {
                    *l = e;
                }
            }
            None => local.entries.push(e),
        }
    }
    if same_seed {
        local.next_ssh_index = local.next_ssh_index.max(incoming.next_ssh_index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn ent(id: u8, title: &str, modified: u64, data: EntryData) -> Entry {
        Entry { id: EntryId([id; 16]), title: title.into(), tags: vec![], created: 0, modified, policy: ApprovalPolicy::Always, data }
    }
    fn pw() -> EntryData {
        EntryData::Password(Password { username: "u".into(), password: "p".into(), url: None, notes: "".into(), totp: None })
    }

    #[test]
    fn roundtrip_and_failures() {
        let v = Vault { entries: vec![ent(1, "a", 5, pw())], next_ssh_index: 3 };
        let seed = [7u8; 32];
        let f = export(&seed, &v, "hunter2hunter2", KdfParams::TEST, 42, &mut OsRng).unwrap();
        let (s, v2) = import(&f, "hunter2hunter2").unwrap();
        assert_eq!(*s, seed);
        assert_eq!(v2, v);
        assert_eq!(import(&f, "nope").unwrap_err(), Error::BadCredential);
        let mut t = f.clone();
        t[9] ^= 1; // header tamper
        assert!(import(&t, "hunter2hunter2").is_err());
        assert!(import(b"garbage", "x").is_err());
    }

    #[test]
    fn merge_semantics() {
        let ls = [1u8; 32];
        let is = [2u8; 32];
        let ssh = |idx| {
            let s = derive_key_from_seed(&is, format!("ssh-ed25519/{idx}").as_bytes());
            EntryData::SshKey(SshKey {
                comment: "".into(),
                source: SshKeySource::Derived { index: idx },
                public_key: SigningKey::from_bytes(&s).verifying_key().to_bytes(),
            })
        };
        let mut local = Vault { entries: vec![ent(1, "old", 1, pw()), ent(2, "keep", 9, pw())], next_ssh_index: 0 };
        let inc = Vault {
            entries: vec![ent(1, "new", 2, pw()), ent(2, "stale", 3, pw()), ent(3, "ssh", 1, ssh(0))],
            next_ssh_index: 1,
        };
        merge(&mut local, &ls, inc, &is);
        assert_eq!(local.entries.len(), 3);
        assert_eq!(local.entries[0].title, "new");
        assert_eq!(local.entries[1].title, "keep");
        match &local.entries[2].data {
            EntryData::SshKey(k) => assert!(matches!(k.source, SshKeySource::Imported { .. })),
            _ => panic!(),
        }
        assert_eq!(local.next_ssh_index, 0);
    }
}
