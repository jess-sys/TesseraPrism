//! Host-side client for Prism (ARCHITECTURE §9.1): transports (USB CDC, BLE, in-memory), the
//! Noise session, config/host-key storage and a typed async [`Client`].

pub mod ble;
pub mod client;
pub mod config;
pub mod connect;
pub mod error;
#[cfg(any(test, feature = "fake-device"))]
pub mod fake;
pub mod transport;
pub mod usb;

pub use client::{Client, ClientOptions, EstablishOutcome, REQUEST_TIMEOUT};
pub use config::{Config, Paths, TransportPref};
pub use connect::{open_transport, TransportChoice};
pub use error::{Error, Result};
pub use transport::{MemoryTransport, Transport};
pub use ble::BleTransport;
pub use usb::UsbTransport;
