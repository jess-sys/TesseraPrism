//! Encrypted vault file and the unlocked-vault session object (ARCHITECTURE §3.2).

use crate::bip39::Mnemonic;
use crate::model::*;
use crate::slots::*;
use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const HKDF_SALT: &[u8] = b"prism/v1";

/// `HKDF-SHA256(ikm=seed, salt="prism/v1", info)` -> 32 bytes.
pub fn derive_key_from_seed(seed: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *out).expect("32 bytes is a valid HKDF length");
    out
}

/// Parsed vault blob: header + nonce + ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultFile {
    pub header: VaultHeader,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl VaultFile {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = postcard::to_stdvec(&self.header)?;
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (header, rest): (VaultHeader, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| Error::Format("bad header"))?;
        if header.magic != MAGIC {
            return Err(Error::Format("bad magic"));
        }
        if header.version != VERSION {
            return Err(Error::UnsupportedVersion(header.version));
        }
        if rest.len() < 24 + 16 {
            return Err(Error::Format("truncated"));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&rest[..24]);
        Ok(VaultFile { header, nonce, ciphertext: rest[24..].to_vec() })
    }

    /// Header only, readable while locked (generation, which slots exist).
    pub fn peek_header(bytes: &[u8]) -> Result<VaultHeader> {
        Ok(Self::decode(bytes)?.header)
    }
}

/// SSH wire helpers.
pub fn ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

pub fn ssh_public_blob(pk: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(51);
    ssh_string(&mut b, b"ssh-ed25519");
    ssh_string(&mut b, pk);
    b
}

pub fn ssh_openssh_line(pk: &[u8; 32], comment: &str) -> String {
    let mut s = format!("ssh-ed25519 {}", B64.encode(ssh_public_blob(pk)));
    if !comment.is_empty() {
        s.push(' ');
        s.push_str(comment);
    }
    s
}

/// 16 random bytes.
pub fn new_entry_id(rng: &mut dyn CryptoRngCore) -> EntryId {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    EntryId(id)
}

/// An unlocked vault: seed + DEK + decrypted contents. Secrets zeroized on drop.
pub struct UnlockedVault {
    seed: Zeroizing<[u8; 32]>,
    dek: Zeroizing<[u8; 32]>,
    header: VaultHeader,
    /// Decrypted contents. Mutating directly is allowed; call `seal()` to persist.
    pub vault: Vault,
    pin_params: KdfParams,
    recovery_params: KdfParams,
}

impl core::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UnlockedVault(<redacted>)")
    }
}

impl UnlockedVault {
    /// New vault with fresh random seed and a PIN slot (production Argon2 params).
    pub fn create(
        pin: &str,
        hardener: &dyn KekHardener,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<(Self, Mnemonic)> {
        Self::create_with_params(pin, hardener, KdfParams::PIN, KdfParams::RECOVERY, rng)
    }

    /// Like `create` with explicit Argon2 parameters (tests use `KdfParams::TEST`).
    pub fn create_with_params(
        pin: &str,
        hardener: &dyn KekHardener,
        pin_params: KdfParams,
        recovery_params: KdfParams,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<(Self, Mnemonic)> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed);
        let m = Mnemonic::from_entropy(&seed);
        let v = Self::from_seed(seed, Vault::default(), pin, hardener, pin_params, recovery_params, rng)?;
        Ok((v, m))
    }

    /// Build a vault around an existing seed (restore from mnemonic / export).
    pub fn from_seed(
        seed: Zeroizing<[u8; 32]>,
        vault: Vault,
        pin: &str,
        hardener: &dyn KekHardener,
        pin_params: KdfParams,
        recovery_params: KdfParams,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Self> {
        check_pin(pin)?;
        let slot = KeySlot::wrap(SlotKind::Pin, pin.as_bytes(), pin_params, &seed, hardener, rng)?;
        let dek = derive_key_from_seed(&seed, b"vault-dek");
        Ok(UnlockedVault {
            seed,
            dek,
            header: VaultHeader::new(vec![slot]),
            vault,
            pin_params,
            recovery_params,
        })
    }

    fn open(file: &VaultFile, seed: Zeroizing<[u8; 32]>) -> Result<Self> {
        let dek = derive_key_from_seed(&seed, b"vault-dek");
        let aad = postcard::to_stdvec(&file.header)?;
        let c = XChaCha20Poly1305::new((&*dek).into());
        let pt = c
            .decrypt(XNonce::from_slice(&file.nonce), Payload { msg: &file.ciphertext, aad: &aad })
            .map_err(|_| Error::Corrupt)?;
        let pt = Zeroizing::new(pt);
        let vault: Vault = postcard::from_bytes(&pt)?;
        let pin_params = file.header.slot(SlotKind::Pin).map(|s| s.params).unwrap_or(KdfParams::PIN);
        let recovery_params =
            file.header.slot(SlotKind::Recovery).map(|s| s.params).unwrap_or(KdfParams::RECOVERY);
        Ok(UnlockedVault { seed, dek, header: file.header.clone(), vault, pin_params, recovery_params })
    }

    pub fn unlock_with_pin(bytes: &[u8], pin: &str, hardener: &dyn KekHardener) -> Result<Self> {
        let file = VaultFile::decode(bytes)?;
        let slot = file.header.slot(SlotKind::Pin).ok_or(Error::NoSlot)?;
        let seed = slot.unwrap_seed(pin.as_bytes(), hardener)?;
        Self::open(&file, seed)
    }

    pub fn unlock_with_passphrase(bytes: &[u8], passphrase: &str) -> Result<Self> {
        let file = VaultFile::decode(bytes)?;
        let slot = file.header.slot(SlotKind::Recovery).ok_or(Error::NoSlot)?;
        let seed = slot.unwrap_seed(passphrase.as_bytes(), &NoHardening)?;
        Self::open(&file, seed)
    }

    /// Unlock directly with the master seed (e.g. from the 24 words), bypassing slots.
    pub fn unlock_with_seed(bytes: &[u8], seed: Zeroizing<[u8; 32]>) -> Result<Self> {
        let file = VaultFile::decode(bytes)?;
        Self::open(&file, seed)
    }

    /// Set or replace the recovery-passphrase slot.
    pub fn set_recovery_passphrase(
        &mut self,
        passphrase: &str,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<()> {
        if passphrase.chars().count() < 8 {
            return Err(Error::Invalid("recovery passphrase must be at least 8 characters"));
        }
        let slot = KeySlot::wrap(
            SlotKind::Recovery,
            passphrase.as_bytes(),
            self.recovery_params,
            &self.seed,
            &NoHardening,
            rng,
        )?;
        self.header.set_slot(slot);
        Ok(())
    }

    pub fn remove_recovery_passphrase(&mut self) -> bool {
        self.header.remove_slot(SlotKind::Recovery)
    }

    pub fn change_pin(
        &mut self,
        new_pin: &str,
        hardener: &dyn KekHardener,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<()> {
        check_pin(new_pin)?;
        let slot =
            KeySlot::wrap(SlotKind::Pin, new_pin.as_bytes(), self.pin_params, &self.seed, hardener, rng)?;
        self.header.set_slot(slot);
        Ok(())
    }

    /// Replace seed and contents (ImportMode::Replace). Re-wraps the PIN slot; the recovery slot
    /// is dropped (the old passphrase wrapped the old seed) and must be set again.
    pub fn replace_contents(
        &mut self,
        seed: Zeroizing<[u8; 32]>,
        vault: Vault,
        pin: &str,
        hardener: &dyn KekHardener,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<()> {
        check_pin(pin)?;
        let slot = KeySlot::wrap(SlotKind::Pin, pin.as_bytes(), self.pin_params, &seed, hardener, rng)?;
        self.dek = derive_key_from_seed(&seed, b"vault-dek");
        self.seed = seed;
        self.vault = vault;
        self.header.slots = vec![slot];
        Ok(())
    }

    pub fn has_recovery(&self) -> bool {
        self.header.has_recovery()
    }
    pub fn generation(&self) -> u64 {
        self.header.generation
    }
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }
    /// The master seed (for export). Handle with care.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
    pub fn mnemonic(&self) -> Mnemonic {
        Mnemonic::from_entropy(&self.seed)
    }

    /// Serialize + encrypt; bumps `generation`. Needs RNG for the nonce.
    pub fn seal(&mut self, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>> {
        self.header.generation += 1;
        let aad = postcard::to_stdvec(&self.header)?;
        let pt = Zeroizing::new(postcard::to_stdvec(&self.vault)?);
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let c = XChaCha20Poly1305::new((&*self.dek).into());
        let ciphertext = c
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &pt, aad: &aad })
            .map_err(|_| Error::Corrupt)?;
        VaultFile { header: self.header.clone(), nonce, ciphertext }.encode()
    }

    // ---- derivation ----

    /// HKDF-SHA256(seed, salt="prism/v1", info). Used by prism-ctap's `Platform::seed_key`.
    pub fn derive_key(&self, info: &[u8]) -> [u8; 32] {
        *derive_key_from_seed(&self.seed, info)
    }

    // ---- entries ----

    pub fn add_entry(&mut self, entry: Entry) -> Result<EntryId> {
        if self.vault.entries.iter().any(|e| e.id == entry.id) {
            return Err(Error::Duplicate);
        }
        let id = entry.id;
        self.vault.entries.push(entry);
        Ok(id)
    }

    pub fn update_entry(&mut self, entry: Entry) -> Result<()> {
        let slot = self.vault.entries.iter_mut().find(|e| e.id == entry.id).ok_or(Error::NotFound)?;
        *slot = entry;
        Ok(())
    }

    pub fn delete_entry(&mut self, id: &EntryId) -> Result<Entry> {
        let i = self.vault.entries.iter().position(|e| &e.id == id).ok_or(Error::NotFound)?;
        Ok(self.vault.entries.remove(i))
    }

    pub fn get_entry(&self, id: &EntryId) -> Option<&Entry> {
        self.vault.entries.iter().find(|e| &e.id == id)
    }

    pub fn list_summaries(&self, kind: Option<EntryKind>) -> Vec<EntrySummary> {
        self.vault
            .entries
            .iter()
            .filter(|e| kind.is_none_or(|k| e.kind() == k))
            .map(Entry::summary)
            .collect()
    }

    /// Every password entry, for a companion's local cache.
    pub fn password_snapshot(&self, now: u64, ttl_secs: u32) -> PasswordSnapshot {
        PasswordSnapshot {
            generated_at: now,
            expires_at: now + ttl_secs as u64,
            entries: self
                .vault
                .entries
                .iter()
                .filter_map(|e| match &e.data {
                    EntryData::Password(p) => Some(CachedPassword {
                        id: e.id,
                        title: e.title.clone(),
                        username: p.username.clone(),
                        password: p.password.clone(),
                        url: p.url.clone(),
                        modified: e.modified,
                    }),
                    _ => None,
                })
                .collect(),
        }
    }

    pub fn passkey_identities(&self) -> Vec<PasskeyIdentity> {
        self.vault
            .entries
            .iter()
            .filter_map(|e| match &e.data {
                EntryData::Passkey(p) => Some(PasskeyIdentity {
                    id: e.id,
                    rp_id: p.rp_id.clone(),
                    user_name: p.user_name.clone(),
                    user_handle: p.user_handle.clone(),
                    credential_id: p.credential_id.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    pub fn find_by_kind(&self, kind: EntryKind) -> Vec<&Entry> {
        self.vault.entries.iter().filter(|e| e.kind() == kind).collect()
    }

    pub fn mark_recovery_code_used(&mut self, id: &EntryId, index: u16) -> Result<()> {
        let e = self.vault.entries.iter_mut().find(|e| &e.id == id).ok_or(Error::NotFound)?;
        match &mut e.data {
            EntryData::RecoveryCodes(r) => {
                r.codes.get_mut(index as usize).ok_or(Error::NotFound)?.used = true;
                Ok(())
            }
            _ => Err(Error::Invalid("not a recovery-codes entry")),
        }
    }

    // ---- SSH ----

    fn ssh_signing_key(&self, key: &SshKey) -> SigningKey {
        match &key.source {
            SshKeySource::Derived { index } => {
                let s = derive_key_from_seed(&self.seed, format!("ssh-ed25519/{index}").as_bytes());
                SigningKey::from_bytes(&s)
            }
            SshKeySource::Imported { secret } => SigningKey::from_bytes(secret),
        }
    }

    /// Generate a new seed-derived Ed25519 key entry (next free index).
    pub fn generate_ssh_key(
        &mut self,
        name: &str,
        comment: &str,
        policy: ApprovalPolicy,
        now: u64,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<SshPublicKey> {
        let index = self.vault.next_ssh_index;
        let s = derive_key_from_seed(&self.seed, format!("ssh-ed25519/{index}").as_bytes());
        let pk = SigningKey::from_bytes(&s).verifying_key().to_bytes();
        self.vault.next_ssh_index = index + 1;
        let entry = Entry {
            id: new_entry_id(rng),
            title: name.to_string(),
            tags: vec![],
            created: now,
            modified: now,
            policy,
            data: EntryData::SshKey(SshKey {
                comment: comment.to_string(),
                source: SshKeySource::Derived { index },
                public_key: pk,
            }),
        };
        let out = ssh_public_of(&entry).expect("ssh entry");
        self.add_entry(entry)?;
        Ok(out)
    }

    /// Re-create derived SSH key entries 0..count after a seed-only restore.
    pub fn restore_derived_ssh_keys(&mut self, count: u32, now: u64, rng: &mut dyn CryptoRngCore) -> Result<()> {
        for _ in self.vault.next_ssh_index..count {
            let i = self.vault.next_ssh_index;
            self.generate_ssh_key(&format!("ssh-{i}"), "", ApprovalPolicy::Always, now, rng)?;
        }
        Ok(())
    }

    pub fn ssh_public_keys(&self) -> Vec<SshPublicKey> {
        self.vault.entries.iter().filter_map(ssh_public_of).collect()
    }

    /// Entry owning the SSH key with this wire blob (for policy lookup before signing).
    pub fn find_ssh_entry(&self, public_blob: &[u8]) -> Option<&Entry> {
        self.vault.entries.iter().find(|e| match &e.data {
            EntryData::SshKey(k) => ssh_public_blob(&k.public_key) == public_blob,
            _ => false,
        })
    }

    /// Sign `data`; returns SSH signature wire blob: string "ssh-ed25519" + string sig.
    pub fn ssh_sign(&self, public_blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let e = self.find_ssh_entry(public_blob).ok_or(Error::NotFound)?;
        let EntryData::SshKey(k) = &e.data else { return Err(Error::NotFound) };
        let sk = self.ssh_signing_key(k);
        let sig = sk.sign(data).to_bytes();
        let mut out = Vec::with_capacity(83);
        ssh_string(&mut out, b"ssh-ed25519");
        ssh_string(&mut out, &sig);
        Ok(out)
    }
}

fn ssh_public_of(e: &Entry) -> Option<SshPublicKey> {
    match &e.data {
        EntryData::SshKey(k) => Some(SshPublicKey {
            id: e.id,
            name: e.title.clone(),
            comment: k.comment.clone(),
            blob: ssh_public_blob(&k.public_key),
            openssh: ssh_openssh_line(&k.public_key, &k.comment),
        }),
        _ => None,
    }
}

fn check_pin(pin: &str) -> Result<()> {
    let n = pin.chars().count();
    if !(6..=12).contains(&n) || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::Invalid("PIN must be 6-12 digits"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use rand::rngs::OsRng;

    fn mk() -> UnlockedVault {
        UnlockedVault::create_with_params("123456", &NoHardening, KdfParams::TEST, KdfParams::TEST, &mut OsRng)
            .unwrap()
            .0
    }

    fn pw(title: &str) -> Entry {
        Entry {
            id: new_entry_id(&mut OsRng),
            title: title.into(),
            tags: vec![],
            created: 1,
            modified: 1,
            policy: ApprovalPolicy::Always,
            data: EntryData::Password(Password {
                username: "u".into(),
                password: "p".into(),
                url: None,
                notes: String::new(),
                totp: None,
            }),
        }
    }

    #[test]
    fn roundtrip_pin_and_passphrase() {
        let (mut v, m) = UnlockedVault::create_with_params(
            "123456", &NoHardening, KdfParams::TEST, KdfParams::TEST, &mut OsRng,
        )
        .unwrap();
        assert_eq!(*m.entropy(), *v.seed());
        let e = pw("site");
        v.add_entry(e.clone()).unwrap();
        v.set_recovery_passphrase("correct horse battery", &mut OsRng).unwrap();
        let blob = v.seal(&mut OsRng).unwrap();
        assert_eq!(VaultFile::peek_header(&blob).unwrap().generation, 1);

        let u = UnlockedVault::unlock_with_pin(&blob, "123456", &NoHardening).unwrap();
        assert_eq!(u.get_entry(&e.id), Some(&e));
        let u2 = UnlockedVault::unlock_with_passphrase(&blob, "correct horse battery").unwrap();
        assert_eq!(u2.seed(), v.seed());
        assert_eq!(
            UnlockedVault::unlock_with_pin(&blob, "654321", &NoHardening).unwrap_err(),
            Error::BadCredential
        );
        assert_eq!(
            UnlockedVault::unlock_with_passphrase(&blob, "wrong wrong wrong").unwrap_err(),
            Error::BadCredential
        );
        let u3 = UnlockedVault::unlock_with_seed(&blob, Zeroizing::new(*m.entropy())).unwrap();
        assert_eq!(u3.vault, u.vault);
    }

    #[test]
    fn tamper_detected_and_generation_bumps() {
        let mut v = mk();
        let b1 = v.seal(&mut OsRng).unwrap();
        let b2 = v.seal(&mut OsRng).unwrap();
        assert_eq!(VaultFile::peek_header(&b2).unwrap().generation, 2);
        let mut bad = b1.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(UnlockedVault::unlock_with_pin(&bad, "123456", &NoHardening).unwrap_err(), Error::Corrupt);
        // header tamper (generation) breaks AAD
        let mut f = VaultFile::decode(&b1).unwrap();
        f.header.generation = 99;
        assert!(UnlockedVault::unlock_with_pin(&f.encode().unwrap(), "123456", &NoHardening).is_err());
        assert!(VaultFile::decode(b"nope").is_err());
    }

    #[test]
    fn change_pin_and_hardener() {
        struct Xor;
        impl KekHardener for Xor {
            fn harden(&self, mut k: [u8; 32]) -> [u8; 32] {
                k.iter_mut().for_each(|b| *b ^= 0x5a);
                k
            }
        }
        let mut v = mk();
        v.change_pin("987654", &Xor, &mut OsRng).unwrap();
        let blob = v.seal(&mut OsRng).unwrap();
        assert!(UnlockedVault::unlock_with_pin(&blob, "987654", &NoHardening).is_err());
        assert!(UnlockedVault::unlock_with_pin(&blob, "123456", &Xor).is_err());
        UnlockedVault::unlock_with_pin(&blob, "987654", &Xor).unwrap();
        assert!(v.change_pin("12", &Xor, &mut OsRng).is_err());
    }

    #[test]
    fn crud_and_recovery_codes() {
        let mut v = mk();
        let mut e = pw("a");
        let id = v.add_entry(e.clone()).unwrap();
        assert_eq!(v.add_entry(e.clone()).unwrap_err(), Error::Duplicate);
        e.title = "b".into();
        v.update_entry(e).unwrap();
        assert_eq!(v.list_summaries(None)[0].title, "b");
        assert!(v.list_summaries(Some(EntryKind::Totp)).is_empty());
        let rc = Entry {
            id: new_entry_id(&mut OsRng),
            title: "rc".into(),
            tags: vec![],
            created: 0,
            modified: 0,
            policy: ApprovalPolicy::Always,
            data: EntryData::RecoveryCodes(RecoveryCodes {
                service: "s".into(),
                codes: vec![RecoveryCode { code: "x".into(), used: false }],
                notes: String::new(),
            }),
        };
        let rid = v.add_entry(rc).unwrap();
        v.mark_recovery_code_used(&rid, 0).unwrap();
        assert_eq!(v.list_summaries(Some(EntryKind::RecoveryCodes))[0].subtitle, "0/1 left");
        assert!(v.mark_recovery_code_used(&rid, 5).is_err());
        assert_eq!(v.find_by_kind(EntryKind::Password).len(), 1);
        v.delete_entry(&id).unwrap();
        assert_eq!(v.delete_entry(&id).unwrap_err(), Error::NotFound);
    }

    #[test]
    fn ssh_derive_sign_verify() {
        let mut v = mk();
        let k0 = v.generate_ssh_key("gh", "me@x", ApprovalPolicy::Session, 5, &mut OsRng).unwrap();
        let k1 = v.generate_ssh_key("gl", "", ApprovalPolicy::Always, 5, &mut OsRng).unwrap();
        assert_ne!(k0.blob, k1.blob);
        assert!(k0.openssh.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"));
        assert!(k0.openssh.ends_with(" me@x"));
        assert_eq!(v.vault.next_ssh_index, 2);
        assert_eq!(v.ssh_public_keys().len(), 2);

        let sig = v.ssh_sign(&k0.blob, b"hello").unwrap();
        assert_eq!(&sig[..4], &[0, 0, 0, 11]);
        assert_eq!(&sig[4..15], b"ssh-ed25519");
        assert_eq!(&sig[15..19], &[0, 0, 0, 64]);
        let vk = VerifyingKey::from_bytes(&k0.blob[19..51].try_into().unwrap()).unwrap();
        vk.verify(b"hello", &Signature::from_bytes(sig[19..83].try_into().unwrap())).unwrap();
        assert_eq!(v.ssh_sign(b"nope", b"x").unwrap_err(), Error::NotFound);

        // re-derivation after seed-only restore gives same key
        let mut w = UnlockedVault::from_seed(
            Zeroizing::new(*v.seed()), Vault::default(), "123456", &NoHardening,
            KdfParams::TEST, KdfParams::TEST, &mut OsRng,
        ).unwrap();
        w.restore_derived_ssh_keys(2, 0, &mut OsRng).unwrap();
        assert_eq!(w.ssh_public_keys()[0].blob, k0.blob);
    }

    #[test]
    fn derive_key_is_domain_separated() {
        let v = mk();
        assert_ne!(v.derive_key(b"a"), v.derive_key(b"b"));
        assert_eq!(v.derive_key(b"a"), v.derive_key(b"a"));
    }
}
