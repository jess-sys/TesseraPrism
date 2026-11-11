//! Transport selection: USB if a Prism is attached, else BLE.

use crate::{ble::BleTransport, usb, Config, Error, Result, Transport, UsbTransport};
use std::time::Duration;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TransportChoice {
    /// USB when present, otherwise BLE.
    #[default]
    Auto,
    /// USB; optional explicit serial path.
    Usb(Option<String>),
    Ble,
}

/// Open a transport. Updates `cfg.last_ble_id` when a BLE device was used (caller persists).
pub async fn open_transport(cfg: &mut Config, choice: &TransportChoice) -> Result<Box<dyn Transport>> {
    match choice {
        TransportChoice::Usb(path) => {
            let p = path.clone().or_else(|| cfg.usb_path.clone());
            Ok(Box::new(match p {
                Some(p) => UsbTransport::open(&p)?,
                None => UsbTransport::discover()?,
            }))
        }
        TransportChoice::Ble => open_ble(cfg).await,
        TransportChoice::Auto => {
            if let Some(p) = cfg.usb_path.clone() {
                if let Ok(t) = UsbTransport::open(&p) {
                    return Ok(Box::new(t));
                }
            }
            if !usb::find_ports().is_empty() {
                if let Ok(t) = UsbTransport::discover() {
                    return Ok(Box::new(t));
                }
            }
            open_ble(cfg).await.map_err(|e| match e {
                Error::NoDevice(_) => Error::NoDevice("no Prism device found over USB or BLE".into()),
                e => e,
            })
        }
    }
}

async fn open_ble(cfg: &mut Config) -> Result<Box<dyn Transport>> {
    let t = BleTransport::connect(cfg.last_ble_id.as_deref(), cfg.ble_mtu, Duration::from_secs(10)).await?;
    cfg.last_ble_id = Some(t.device_id().to_string());
    Ok(Box::new(t))
}
