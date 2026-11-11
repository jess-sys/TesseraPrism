//! Config (`~/.config/prism/config.toml`) and host key storage.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportPref {
    #[default]
    Auto,
    Usb,
    Ble,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub transport: TransportPref,
    /// Explicit serial port path (otherwise discovered by VID/PID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usb_path: Option<String>,
    /// Last connected BLE peripheral id (fast reconnect).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ble_id: Option<String>,
    /// ATT MTU override for chunking (btleplug cannot report it). Default 185.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ble_mtu: Option<usize>,
    /// Device Noise static public key (hex), pinned at pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_pubkey: Option<String>,
}

impl Config {
    pub fn pinned_device(&self) -> Option<[u8; 32]> {
        let v = hex::decode(self.device_pubkey.as_ref()?).ok()?;
        v.try_into().ok()
    }
    pub fn pin_device(&mut self, key: &[u8; 32]) {
        self.device_pubkey = Some(hex::encode(key));
    }
}

/// Where config and key live. Override the dir with `PRISM_CONFIG_DIR`.
#[derive(Clone, Debug)]
pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    pub fn default_dir() -> Paths {
        if let Some(d) = std::env::var_os("PRISM_CONFIG_DIR") {
            return Paths { dir: d.into() };
        }
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        Paths { dir: base.join("prism") }
    }
    pub fn at(dir: impl Into<PathBuf>) -> Paths {
        Paths { dir: dir.into() }
    }
    pub fn config_file(&self) -> PathBuf {
        self.dir.join("config.toml")
    }
    pub fn host_key_file(&self) -> PathBuf {
        self.dir.join("host_key")
    }

    pub fn load_config(&self) -> Result<Config> {
        match std::fs::read_to_string(self.config_file()) {
            Ok(s) => toml::from_str(&s).map_err(|e| Error::Config(format!("{}: {e}", self.config_file().display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save_config(&self, c: &Config) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let s = toml::to_string_pretty(c).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(self.config_file(), s)?;
        Ok(())
    }

    /// Load the host's static X25519 private key, generating it on first use.
    pub fn load_or_create_host_key(&self) -> Result<[u8; 32]> {
        #[cfg(feature = "keyring")]
        {
            if let Ok(k) = self.keyring_key() {
                return Ok(k);
            }
        }
        let f = self.host_key_file();
        match std::fs::read_to_string(&f) {
            Ok(s) => {
                let v = hex::decode(s.trim()).map_err(|e| Error::Config(format!("{}: {e}", f.display())))?;
                return v.try_into().map_err(|_| Error::Config(format!("{}: wrong key length", f.display())));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let (private, _) = prism_proto::generate_static_keypair();
        #[cfg(feature = "keyring")]
        {
            if let Ok(e) = keyring::Entry::new("prism", "host_key") {
                if e.set_password(&hex::encode(private)).is_ok() {
                    return Ok(private);
                }
            }
        }
        std::fs::create_dir_all(&self.dir)?;
        write_private(&f, hex::encode(private).as_bytes())?;
        Ok(private)
    }

    #[cfg(feature = "keyring")]
    fn keyring_key(&self) -> std::result::Result<[u8; 32], ()> {
        let e = keyring::Entry::new("prism", "host_key").map_err(|_| ())?;
        let s = e.get_password().map_err(|_| ())?;
        hex::decode(s).map_err(|_| ())?.try_into().map_err(|_| ())
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        f.write_all(data)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(data)?;
        Ok(())
    }
}
