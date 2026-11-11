//! Persistent storage (ARCHITECTURE 7.5).
//!
//! * [`VaultStore`]: raw `vault` partition, two 512 KiB A/B slots. Slot layout
//!   `[u32 len LE][u64 generation LE][u32 crc32 LE][bytes]`. A write erases and programs the slot
//!   that does NOT hold the newest valid generation; the loader picks the highest valid generation
//!   (CRC checked), so a power cut mid-write leaves the previous vault intact.
//! * [`Store`]: NVS namespace `prism` (device Noise key, paired hosts, PIN fail counter, settings,
//!   last-used time, battery at shutdown).
//!
//! DEV profile: nothing here is encrypted at the flash level (see docs/SECURITY.md).
use std::ffi::CStr;

use anyhow::{anyhow, bail, ensure, Context, Result};
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_sys as sys;
use prism_core::model::{PairedHost, Settings};
use zeroize::Zeroizing;

pub const MAX_PAIRED_HOSTS: usize = 16;
/// Wipe the vault after this many consecutive wrong PINs.
pub const MAX_PIN_FAILS: u8 = 10;

const SLOT_SIZE: usize = 512 * 1024;
const HDR: usize = 16;
/// Largest vault file that fits a slot.
pub const MAX_VAULT_BYTES: usize = SLOT_SIZE - HDR;
const SECTOR: usize = 4096;
const PARTITION_LABEL: &CStr = c"vault";

fn crc32(data: &[u8]) -> u32 {
    // Bitwise CRC-32/IEEE (poly 0xEDB88320). Vault writes are rare, speed is irrelevant.
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

pub struct VaultStore {
    part: *const sys::esp_partition_t,
}

// The partition descriptor is a static table entry owned by ESP-IDF.
unsafe impl Send for VaultStore {}

struct SlotInfo {
    generation: u64,
    len: usize,
}

impl VaultStore {
    pub fn open() -> Result<Self> {
        let part = unsafe {
            sys::esp_partition_find_first(
                sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
                sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                PARTITION_LABEL.as_ptr(),
            )
        };
        ensure!(!part.is_null(), "partition 'vault' not found");
        let size = unsafe { (*part).size } as usize;
        ensure!(size >= 2 * SLOT_SIZE, "vault partition too small ({size} B)");
        Ok(Self { part })
    }

    fn read_raw(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        sys::esp!(unsafe {
            sys::esp_partition_read(self.part, offset, buf.as_mut_ptr() as *mut _, buf.len())
        })
        .context("vault read")?;
        Ok(())
    }

    /// Validate a slot header + CRC. None if empty/corrupt.
    fn inspect(&self, slot: usize) -> Option<(SlotInfo, Zeroizing<Vec<u8>>)> {
        let base = slot * SLOT_SIZE;
        let mut h = [0u8; HDR];
        self.read_raw(base, &mut h).ok()?;
        let len = u32::from_le_bytes(h[0..4].try_into().unwrap()) as usize;
        let generation = u64::from_le_bytes(h[4..12].try_into().unwrap());
        let crc = u32::from_le_bytes(h[12..16].try_into().unwrap());
        if len == 0 || len > MAX_VAULT_BYTES {
            return None;
        }
        let mut data = Zeroizing::new(vec![0u8; len]);
        self.read_raw(base + HDR, &mut data).ok()?;
        if crc32(&data) != crc {
            return None;
        }
        Some((SlotInfo { generation, len }, data))
    }

    fn best_slot(&self) -> Option<(usize, SlotInfo)> {
        let a = self.inspect(0).map(|(i, _)| i);
        let b = self.inspect(1).map(|(i, _)| i);
        match (a, b) {
            (Some(a), Some(b)) => Some(if b.generation > a.generation { (1, b) } else { (0, a) }),
            (Some(a), None) => Some((0, a)),
            (None, Some(b)) => Some((1, b)),
            (None, None) => None,
        }
    }

    /// Newest valid vault file bytes, or None if the device has no vault.
    pub fn load(&self) -> Option<Zeroizing<Vec<u8>>> {
        let (slot, _) = self.best_slot()?;
        self.inspect(slot).map(|(_, d)| d)
    }

    pub fn exists(&self) -> bool {
        self.best_slot().is_some()
    }

    /// Write `bytes` (a sealed VaultFile) with the given generation into the inactive slot.
    pub fn store(&mut self, bytes: &[u8], generation: u64) -> Result<()> {
        ensure!(!bytes.is_empty() && bytes.len() <= MAX_VAULT_BYTES, "vault does not fit a slot");
        let target = match self.best_slot() {
            Some((cur, info)) => {
                ensure!(generation > info.generation, "stale vault generation");
                1 - cur
            }
            None => 0,
        };
        let base = target * SLOT_SIZE;
        let padded = (HDR + bytes.len()).div_ceil(SECTOR) * SECTOR;
        sys::esp!(unsafe { sys::esp_partition_erase_range(self.part, base, padded) }).context("vault erase")?;

        // Body first (padded to 16 B), header last: the slot only becomes valid once the CRC'd
        // header lands, and the CRC covers the body anyway.
        let mut body = Zeroizing::new(bytes.to_vec());
        while body.len() % 16 != 0 {
            body.push(0xFF);
        }
        sys::esp!(unsafe {
            sys::esp_partition_write(self.part, base + HDR, body.as_ptr() as *const _, body.len())
        })
        .context("vault write body")?;
        let mut h = [0u8; HDR];
        h[0..4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        h[4..12].copy_from_slice(&generation.to_le_bytes());
        h[12..16].copy_from_slice(&crc32(bytes).to_le_bytes());
        sys::esp!(unsafe { sys::esp_partition_write(self.part, base, h.as_ptr() as *const _, HDR) })
            .context("vault write header")?;

        // Read back to verify.
        let ok = self.inspect(target).map(|(i, d)| i.generation == generation && d.as_slice() == bytes);
        ensure!(ok == Some(true), "vault write verification failed");
        Ok(())
    }

    /// Erase both slots completely (wipe).
    pub fn wipe(&mut self) -> Result<()> {
        sys::esp!(unsafe { sys::esp_partition_erase_range(self.part, 0, 2 * SLOT_SIZE) }).context("vault wipe")?;
        Ok(())
    }
}

/// NVS wrapper, namespace `prism`.
pub struct Store {
    nvs: EspNvs<NvsDefault>,
}

const K_DEV_KEY: &str = "dev_key"; // 64 B: private || public
const K_HOSTS: &str = "hosts";
const K_PIN_FAIL: &str = "pin_fail";
const K_SETTINGS: &str = "settings";
const K_LAST_USED: &str = "last_used";
const K_BAT_SHUT: &str = "bat_shut";
/// Shutdown breadcrumb (diagnostics): last stage reached by the power-off sequence.
const K_SHUT_STAGE: &str = "shut_stage";
/// The vault PIN slot is wrapped with the eFuse HMAC-hardened KEK (see hardening.rs).
const K_PIN_HW: &str = "pin_hw";

impl Store {
    pub fn open(partition: EspDefaultNvsPartition) -> Result<Self> {
        let nvs = EspNvs::new(partition, "prism", true).map_err(|e| anyhow!("nvs open: {e}"))?;
        Ok(Self { nvs })
    }

    fn get_blob(&self, key: &str) -> Option<Vec<u8>> {
        let len = self.nvs.blob_len(key).ok()??;
        let mut buf = vec![0u8; len];
        self.nvs.get_blob(key, &mut buf).ok()??;
        Some(buf)
    }

    fn set_blob(&mut self, key: &str, data: &[u8]) -> Result<()> {
        self.nvs.set_blob(key, data).map_err(|e| anyhow!("nvs set {key}: {e}"))?;
        Ok(())
    }

    /// Device Noise static keypair `(private, public)`; generated on first use. Call only after the
    /// radio is up so `esp_random` is a true entropy source.
    pub fn device_keypair(&mut self) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
        if let Some(b) = self.get_blob(K_DEV_KEY) {
            let b = Zeroizing::new(b);
            if b.len() == 64 {
                let mut sk = Zeroizing::new([0u8; 32]);
                sk.copy_from_slice(&b[..32]);
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&b[32..]);
                return Ok((sk, pk));
            }
            log::warn!("device key blob has bad length, regenerating");
        }
        let (sk, pk) = prism_proto::generate_static_keypair();
        let sk = Zeroizing::new(sk);
        let mut blob = Zeroizing::new([0u8; 64]);
        blob[..32].copy_from_slice(&*sk);
        blob[32..].copy_from_slice(&pk);
        self.set_blob(K_DEV_KEY, &*blob)?;
        log::info!("generated device static key");
        Ok((sk, pk))
    }

    pub fn hosts(&self) -> Vec<PairedHost> {
        self.get_blob(K_HOSTS)
            .and_then(|b| postcard::from_bytes::<Vec<PairedHost>>(&b).ok())
            .unwrap_or_default()
    }

    pub fn set_hosts(&mut self, hosts: &[PairedHost]) -> Result<()> {
        if hosts.len() > MAX_PAIRED_HOSTS {
            bail!("too many paired hosts");
        }
        let b = postcard::to_stdvec(&hosts.to_vec())?;
        self.set_blob(K_HOSTS, &b)
    }

    pub fn pin_fails(&self) -> u8 {
        self.nvs.get_u8(K_PIN_FAIL).ok().flatten().unwrap_or(0)
    }

    pub fn set_pin_fails(&mut self, n: u8) -> Result<()> {
        self.nvs.set_u8(K_PIN_FAIL, n).map_err(|e| anyhow!("nvs set pin_fail: {e}"))?;
        Ok(())
    }

    pub fn settings(&self) -> Settings {
        self.get_blob(K_SETTINGS)
            .and_then(|b| postcard::from_bytes::<Settings>(&b).ok())
            .unwrap_or_default()
    }

    pub fn set_settings(&mut self, s: &Settings) -> Result<()> {
        let b = postcard::to_stdvec(s)?;
        self.set_blob(K_SETTINGS, &b)
    }

    pub fn last_used(&self) -> Option<u64> {
        self.nvs.get_u64(K_LAST_USED).ok().flatten()
    }

    pub fn set_last_used(&mut self, unix: u64) -> Result<()> {
        self.nvs.set_u64(K_LAST_USED, unix).map_err(|e| anyhow!("nvs set last_used: {e}"))?;
        Ok(())
    }

    pub fn battery_at_shutdown(&self) -> Option<u8> {
        self.nvs.get_u8(K_BAT_SHUT).ok().flatten()
    }

    pub fn set_battery_at_shutdown(&mut self, pct: u8) -> Result<()> {
        self.nvs.set_u8(K_BAT_SHUT, pct).map_err(|e| anyhow!("nvs set bat_shut: {e}"))?;
        Ok(())
    }

    pub fn pin_hardened(&self) -> bool {
        self.nvs.get_u8(K_PIN_HW).ok().flatten() == Some(1)
    }

    pub fn set_pin_hardened(&mut self, on: bool) -> Result<()> {
        self.nvs.set_u8(K_PIN_HW, on as u8).map_err(|e| anyhow!("nvs set pin_hw: {e}"))?;
        Ok(())
    }

    /// Last shutdown stage written before power was cut (0 = none / cleared).
    pub fn shutdown_stage(&self) -> u8 {
        self.nvs.get_u8(K_SHUT_STAGE).ok().flatten().unwrap_or(0)
    }

    pub fn set_shutdown_stage(&mut self, stage: u8) -> Result<()> {
        self.nvs.set_u8(K_SHUT_STAGE, stage).map_err(|e| anyhow!("nvs set shut_stage: {e}"))?;
        Ok(())
    }

    /// Reset everything except the device identity key.
    pub fn wipe(&mut self) -> Result<()> {
        for k in [K_HOSTS, K_PIN_FAIL, K_SETTINGS, K_LAST_USED, K_BAT_SHUT, K_PIN_HW] {
            let _ = self.nvs.remove(k);
        }
        Ok(())
    }
}
