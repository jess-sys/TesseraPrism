//! Transport layer contract (BLE + USB) between `transport/*` and `core/*`.
//!
//! OWNERSHIP: `transport/` is implemented by the transport agent; `core/` + `main.rs` by the core agent.
//! This file's public types are the contract; change them only by agreement.
//!
//! The transport layer owns ALL framing: Prism BLE chunking (prism_proto::ble), USB CDC COBS
//! (prism_proto::cdc), CTAPHID (prism_ctap::ctaphid) and CTAP-BLE (prism_ctap::ble) — including
//! CTAPHID INIT/PING/WINK handling and sending KEEPALIVE every 100 ms while a CTAP request is
//! outstanding. Core only sees complete messages.

use std::sync::mpsc::{Receiver, Sender};

use prism_core::model::KeyboardLayout;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Link {
    /// One BLE connection (NimBLE connection handle). Each connection gets its own Noise
    /// session, so several hosts (e.g. the Prism app and its AutoFill extension) can be
    /// connected at once without clobbering each other's session.
    /// `chan` is the client-chosen BLE framing-v2 channel (0 = v1 client / FIDO service).
    Ble { conn: u16, chan: u32 },
    Usb,
}

/// Opaque handle that identifies a CTAP request's origin so the response goes back to it
/// (CTAPHID channel id for USB; connection handle for BLE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtapOrigin {
    pub link: Link,
    pub channel: u32,
}

/// Transport → core.
#[derive(Debug)]
pub enum TransportEvent {
    /// A complete Prism protocol frame (kind byte + payload), see prism_proto::frame.
    PrismFrame { link: Link, frame: Vec<u8> },
    /// A Prism link session ended (BLE disconnect / USB CDC closed). Core drops the Noise session for it.
    PrismClosed { link: Link },
    /// A complete CTAP2 request (command byte + CBOR). Core must answer with `TransportCommand::CtapResponse`.
    CtapRequest { origin: CtapOrigin, request: Vec<u8> },
    /// Host cancelled the outstanding CTAP request (CTAPHID_CANCEL / BLE CANCEL).
    CtapCancel { origin: CtapOrigin },
    /// CTAPHID_WINK: show something on screen / beep.
    Wink,
    /// BLE bonding (FIDO service requires LESC passkey): display this 6-digit passkey on eInk.
    BlePasskeyDisplay { passkey: u32 },
    BlePairingFinished { success: bool },
    /// Physical link state changes (for status bar & power policy).
    BleConnected(bool),
    UsbConfigured(bool),
}

/// Core → transport.
#[derive(Debug)]
pub enum TransportCommand {
    PrismFrame { link: Link, frame: Vec<u8> },
    CtapResponse { origin: CtapOrigin, response: Vec<u8> },
    /// Type text through the USB HID keyboard using the given layout. Transport replies with
    /// `TransportEvent`-less completion; failures are logged (no USB host → dropped).
    TypeText { text: Zeroizing<String>, layout: KeyboardLayout },
    /// Start/stop BLE advertising (power policy: stop before power-off / deep sleep).
    SetAdvertising(bool),
    /// Allow new BLE bonds (Settings → Pair new host). Existing bonds always allowed.
    SetBondingAllowed(bool),
    /// Update the BLE Battery Service level (0..=100). Added by the transport agent.
    SetBattery(u8),
    /// Locked standby: slow advertising interval (~1-1.5 s) so the radio mostly sleeps.
    SetLowPower(bool),
    /// Disconnect everything and shut the radio down (before power-off).
    Shutdown,
}

pub struct TransportHandles {
    pub events: Receiver<TransportEvent>,
    pub commands: Sender<TransportCommand>,
}

pub struct TransportConfig {
    /// e.g. "Prism-1A2B"
    pub ble_name: String,
    pub fw_version: String,
    pub enable_ble: bool,
    pub enable_usb: bool,
}

mod ble;
#[cfg(not(feature = "jtag-console"))]
mod hid_keyboard;
mod layouts;
#[cfg(not(feature = "jtag-console"))]
mod usb;

use std::sync::mpsc;

/// Start the transport layer: brings up BLE and/or USB per `config`, spawns the worker threads and
/// returns the event/command channels. Never blocks after start-up.
pub fn start(config: TransportConfig) -> anyhow::Result<TransportHandles> {
    let (ev_tx, ev_rx) = mpsc::channel::<TransportEvent>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<TransportCommand>();

    let ble = if config.enable_ble {
        Some(ble::Ble::start(&config, ev_tx.clone())?)
    } else {
        None
    };

    #[cfg(not(feature = "jtag-console"))]
    let (usb, kbd) = if config.enable_usb {
        let usb = usb::Usb::start(ev_tx.clone())?;
        (Some(usb), Some(hid_keyboard::spawn()?))
    } else {
        (None, None)
    };
    #[cfg(feature = "jtag-console")]
    if config.enable_usb {
        log::warn!("transport: USB disabled (jtag-console feature keeps USB for logs)");
    }

    crate::threads::spawn_psram("transport-cmd", 6144, move || {
        while let Ok(cmd) = cmd_rx.recv() {
            match cmd {
                TransportCommand::PrismFrame { link: Link::Ble { conn, chan }, frame } => match &ble {
                    Some(b) => b.prism_frame(conn, chan, frame),
                    None => log::warn!("transport: BLE disabled, frame dropped"),
                },
                TransportCommand::CtapResponse { origin, response } if matches!(origin.link, Link::Ble { .. }) => match &ble {
                    Some(b) => b.ctap_response(origin.channel, response),
                    None => log::warn!("transport: BLE disabled, CTAP response dropped"),
                },
                TransportCommand::SetAdvertising(on) => {
                    if let Some(b) = &ble {
                        b.set_advertising(on);
                    }
                }
                TransportCommand::SetBondingAllowed(on) => {
                    if let Some(b) = &ble {
                        b.set_bonding_allowed(on);
                    }
                }
                TransportCommand::SetLowPower(on) => {
                    if let Some(b) = &ble {
                        b.set_low_power(on);
                    }
                }
                TransportCommand::SetBattery(level) => {
                    if let Some(b) = &ble {
                        b.set_battery(level);
                    }
                }
                TransportCommand::Shutdown => {
                    if let Some(b) = &ble {
                        b.shutdown();
                    }
                }
                #[cfg(not(feature = "jtag-console"))]
                TransportCommand::PrismFrame { link: Link::Usb, frame } => match &usb {
                    Some(u) => u.prism_frame(frame),
                    None => log::warn!("transport: USB disabled, frame dropped"),
                },
                #[cfg(not(feature = "jtag-console"))]
                TransportCommand::CtapResponse { origin, response } => match &usb {
                    Some(u) => u.ctap_response(origin.channel, response),
                    None => log::warn!("transport: USB disabled, CTAP response dropped"),
                },
                #[cfg(not(feature = "jtag-console"))]
                TransportCommand::TypeText { text, layout } => match &kbd {
                    Some(k) => {
                        let _ = k.send(hid_keyboard::TypeJob { text, layout });
                    }
                    None => log::warn!("transport: USB disabled, TypeText dropped"),
                },
                #[cfg(feature = "jtag-console")]
                other => log::warn!("transport: USB unavailable (jtag-console), dropped {:?}", std::mem::discriminant(&other)),
            }
        }
    })?;

    Ok(TransportHandles { events: ev_rx, commands: cmd_tx })
}
