//! USB CDC-ACM transport: COBS framing over a serial port.

use crate::{Error, Result, Transport};
use async_trait::async_trait;
use prism_proto::cdc;
use std::collections::VecDeque;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_serial::{SerialPortBuilderExt, SerialPortType, SerialStream};

pub const USB_VID: u16 = 0x303A;
pub const USB_PID: u16 = 0x8360;

pub struct UsbTransport {
    port: SerialStream,
    decoder: cdc::Decoder,
    queue: VecDeque<Vec<u8>>,
}

/// Serial port paths of attached Prism devices (VID/PID 303A:8360).
pub fn find_ports() -> Vec<String> {
    let mut v: Vec<String> = tokio_serial::available_ports()
        .unwrap_or_default()
        .into_iter()
        .filter(|p| matches!(&p.port_type, SerialPortType::UsbPort(u) if u.vid == USB_VID && u.pid == USB_PID))
        .map(|p| p.port_name)
        .collect();
    // macOS exposes both /dev/cu.* and /dev/tty.*; prefer cu.
    if v.iter().any(|p| p.contains("/cu.")) {
        v.retain(|p| !p.contains("/tty."));
    }
    v
}

impl UsbTransport {
    pub fn open(path: &str) -> Result<Self> {
        let port = tokio_serial::new(path, 115_200)
            .open_native_async()
            .map_err(|e| Error::Transport(format!("open {path}: {e}")))?;
        Ok(Self { port, decoder: cdc::Decoder::new(), queue: VecDeque::new() })
    }

    /// Open the first Prism device found by VID/PID.
    pub fn discover() -> Result<Self> {
        let ports = find_ports();
        let p = ports.first().ok_or_else(|| Error::NoDevice("no Prism USB device (303A:8360) found".into()))?;
        Self::open(p)
    }
}

#[async_trait]
impl Transport for UsbTransport {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.port.write_all(&cdc::encode(frame)).await?;
        self.port.flush().await?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        let mut buf = [0u8; 1024];
        loop {
            if let Some(f) = self.queue.pop_front() {
                return Ok(f);
            }
            let n = self.port.read(&mut buf).await?;
            if n == 0 {
                return Err(Error::Closed);
            }
            for r in self.decoder.push(&buf[..n]) {
                match r {
                    Ok(f) => self.queue.push_back(f),
                    Err(_) => {} // corrupt frame: drop, resync on next 0x00
                }
            }
        }
    }
}
