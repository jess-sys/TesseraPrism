//! Hardware-bound PIN hardening (docs/SECURITY.md "How KekHardener uses the eFuse key").
//!
//! The PIN slot's key-encryption key becomes `HMAC-SHA256(efuse_key, Argon2id(pin))`, computed by the
//! ESP32-S3 HMAC peripheral with a 256-bit key held in an eFuse key block whose purpose is
//! `HMAC_UP`. That key is generated on the device (hardware RNG, radio on), burned once, and is
//! read-protected: software — including this firmware — can never read it back, so a flash dump is
//! useless for offline PIN guessing: every guess must run on this chip, where the 10-try wipe applies.
//!
//! The recovery-passphrase slot and the 24-word seed deliberately do NOT use it, so a replacement
//! device can still restore a backup.
//!
//! Burning the key is irreversible (one eFuse key block is consumed). It happens only once, when the
//! first PIN slot is created or migrated.

use esp_idf_svc::sys;
use prism_core::KekHardener;
use zeroize::Zeroize;

extern "C" {
    /// ESP-IDF `esp_hmac.h` (not in esp-idf-sys' generated bindings). `key_id`: 0..=5 = KEY0..KEY5.
    fn esp_hmac_calculate(key_id: u32, message: *const core::ffi::c_void, message_len: usize, hmac: *mut u8) -> sys::esp_err_t;
}

/// PIN hardener backed by the eFuse HMAC key in `block`.
pub struct EfuseHmac {
    key_id: u32,
}

impl EfuseHmac {
    /// The already-provisioned key, if any.
    pub fn existing() -> Option<Self> {
        let mut block: sys::esp_efuse_block_t = 0;
        let found = unsafe { sys::esp_efuse_find_purpose(sys::esp_efuse_purpose_t_ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &mut block) };
        if !found {
            return None;
        }
        Some(Self { key_id: block - sys::esp_efuse_block_t_EFUSE_BLK_KEY0 })
    }

    /// Return the existing key, or generate one with the hardware RNG and burn it into the first
    /// unused eFuse key block (IRREVERSIBLE), then check the HMAC peripheral can use it.
    pub fn existing_or_provision() -> anyhow::Result<Self> {
        if let Some(k) = Self::existing() {
            return Ok(k);
        }
        let block = unsafe { sys::esp_efuse_find_unused_key_block() };
        anyhow::ensure!(
            block != sys::esp_efuse_block_t_EFUSE_BLK_KEY_MAX,
            "no free eFuse key block for the PIN-hardening key"
        );
        let mut key = [0u8; 32];
        // The radio is up by the time a vault is created/unlocked, so esp_fill_random is a TRNG.
        unsafe { sys::esp_fill_random(key.as_mut_ptr().cast(), key.len()) };
        log::warn!("burning the PIN-hardening HMAC key into eFuse block {block} (irreversible)");
        let rc = unsafe {
            sys::esp_efuse_write_key(
                block,
                sys::esp_efuse_purpose_t_ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
                key.as_ptr().cast(),
                key.len(),
            )
        };
        key.zeroize();
        sys::esp!(rc).map_err(|e| anyhow::anyhow!("eFuse key write failed: {e}"))?;
        let k = Self { key_id: block - sys::esp_efuse_block_t_EFUSE_BLK_KEY0 };
        // The key must be unreadable by software (esp_efuse_write_key sets this for HMAC purposes).
        let read_protected = unsafe { sys::esp_efuse_get_key_dis_read(block) };
        anyhow::ensure!(read_protected, "eFuse HMAC key block {block} is not read-protected");
        k.check()?;
        Ok(k)
    }

    /// Prove the peripheral computes with the key (deterministic, non-trivial output).
    pub fn check(&self) -> anyhow::Result<()> {
        let a = self.hmac(&[0x5a; 32])?;
        let b = self.hmac(&[0x5a; 32])?;
        anyhow::ensure!(a == b && a != [0u8; 32], "HMAC peripheral self-test failed");
        Ok(())
    }

    fn hmac(&self, msg: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
        let mut out = [0u8; 32];
        let rc = unsafe { esp_hmac_calculate(self.key_id, msg.as_ptr().cast(), msg.len(), out.as_mut_ptr()) };
        sys::esp!(rc).map_err(|e| anyhow::anyhow!("HMAC peripheral failed: {e}"))?;
        Ok(out)
    }
}

impl KekHardener for EfuseHmac {
    fn harden(&self, k: [u8; 32]) -> [u8; 32] {
        let mut k = k;
        let out = self.hmac(&k).unwrap_or_else(|e| {
            // Never fall back to the unhardened key: an unusable KEK just fails the unlock.
            log::error!("{e:#}");
            [0u8; 32]
        });
        k.zeroize();
        out
    }
}
