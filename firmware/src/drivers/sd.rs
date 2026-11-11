//! microSD over SPI (CS 47, SCK 39, MOSI 38, MISO 40). Stub: used later for encrypted exports.
//! TODO(integration): `esp_vfs_fat_sdspi_mount` on SPI3, mount at `/sd`, host = SDSPI_HOST_DEFAULT,
//! slot CS = board::SD_CS, `format_if_mount_failed = false`. Never store unencrypted vault data here.
use anyhow::{bail, Result};

pub struct SdCard;

impl SdCard {
    pub fn mount() -> Result<Self> {
        bail!("microSD support not implemented yet")
    }
}
