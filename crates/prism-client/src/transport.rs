use crate::{Error, Result};
use async_trait::async_trait;
use tokio::sync::mpsc;

/// A bidirectional carrier of whole Prism frames (`[kind][payload]`).
#[async_trait]
pub trait Transport: Send {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()>;
    /// Wait for the next complete frame. Must be cancel-safe (used under `timeout`).
    async fn recv_frame(&mut self) -> Result<Vec<u8>>;
}

#[async_trait]
impl Transport for Box<dyn Transport> {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        (**self).send_frame(frame).await
    }
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        (**self).recv_frame().await
    }
}

/// In-process transport; create with [`MemoryTransport::pair`].
pub struct MemoryTransport {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl MemoryTransport {
    pub fn pair() -> (MemoryTransport, MemoryTransport) {
        let (atx, brx) = mpsc::unbounded_channel();
        let (btx, arx) = mpsc::unbounded_channel();
        (MemoryTransport { tx: atx, rx: arx }, MemoryTransport { tx: btx, rx: brx })
    }
}

#[async_trait]
impl Transport for MemoryTransport {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.tx.send(frame.to_vec()).map_err(|_| Error::Closed)
    }
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        self.rx.recv().await.ok_or(Error::Closed)
    }
}
