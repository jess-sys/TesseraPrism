//! BLE transport (btleplug): Prism GATT service, chunked frames (ARCHITECTURE §5.1).
//!
//! NOTE: btleplug does not expose the negotiated ATT MTU, so the chunk size is derived from
//! [`DEFAULT_MTU`] (185) unless overridden (`Config::ble_mtu`).

use crate::{Error, Result, Transport};
use async_trait::async_trait;
use btleplug::api::{Central, CentralEvent, CharPropFlags, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures::StreamExt;
use prism_proto::ble::{chunk_v2, random_channel, Reassembler};
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

pub const SERVICE_UUID: Uuid = Uuid::from_u128(0x9e5d0001_3c4a_4b8e_9f1a_5072736d0000);
pub const RX_UUID: Uuid = Uuid::from_u128(0x9e5d0002_3c4a_4b8e_9f1a_5072736d0000);
pub const TX_UUID: Uuid = Uuid::from_u128(0x9e5d0003_3c4a_4b8e_9f1a_5072736d0000);
pub const DEFAULT_MTU: usize = 185;

pub struct BleTransport {
    peripheral: Peripheral,
    rx_char: btleplug::api::Characteristic,
    notif: mpsc::UnboundedReceiver<Vec<u8>>,
    framing: Framing,
    id: String,
}

/// BLE framing v2 state for one connection: a random channel id (so several host processes can
/// share one BLE link; the device keeps one session per channel) plus a channel-filtering
/// reassembler that ignores other clients' notifications.
struct Framing {
    chan: u32,
    mtu: usize,
    reassembler: Reassembler,
}

impl Framing {
    fn new(mtu: usize) -> Self {
        let chan = random_channel();
        Self { chan, mtu: mtu.max(23), reassembler: Reassembler::new_channel(chan) }
    }
    fn chunks(&self, frame: &[u8]) -> Vec<Vec<u8>> {
        chunk_v2(frame, self.mtu, self.chan)
    }
    fn push(&mut self, c: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.reassembler.push(c)?)
    }
}

async fn adapter() -> Result<Adapter> {
    let m = Manager::new().await.map_err(be)?;
    m.adapters().await.map_err(be)?.into_iter().next().ok_or_else(|| Error::NoDevice("no Bluetooth adapter".into()))
}

fn be(e: btleplug::Error) -> Error {
    Error::Transport(format!("ble: {e}"))
}

impl BleTransport {
    /// Scan for the Prism service. If `prefer_id` is set (last used device) and seen, it wins.
    pub async fn connect(prefer_id: Option<&str>, mtu: Option<usize>, scan_timeout: Duration) -> Result<Self> {
        let adapter = adapter().await?;
        let mut events = adapter.events().await.map_err(be)?;
        adapter.start_scan(ScanFilter { services: vec![SERVICE_UUID] }).await.map_err(be)?;
        let deadline = tokio::time::Instant::now() + scan_timeout;
        let mut found: Option<Peripheral> = None;
        // Already known peripherals (cached by the OS).
        let consider = |p: Peripheral, found: &mut Option<Peripheral>| -> bool {
            let pid = p.id().to_string();
            if prefer_id == Some(pid.as_str()) {
                *found = Some(p);
                true
            } else {
                if found.is_none() {
                    *found = Some(p);
                }
                prefer_id.is_none()
            }
        };
        'outer: loop {
            for p in adapter.peripherals().await.map_err(be)? {
                if let Ok(Some(props)) = p.properties().await {
                    if props.services.contains(&SERVICE_UUID) && consider(p, &mut found) {
                        break 'outer;
                    }
                }
            }
            match tokio::time::timeout_at(deadline, events.next()).await {
                Ok(Some(CentralEvent::DeviceDiscovered(_) | CentralEvent::ServicesAdvertisement { .. })) => {}
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let _ = adapter.stop_scan().await;
        let peripheral = found.ok_or_else(|| Error::NoDevice("no Prism BLE device found".into()))?;
        Self::attach(peripheral, mtu).await
    }

    async fn attach(peripheral: Peripheral, mtu: Option<usize>) -> Result<Self> {
        let id = peripheral.id().to_string();
        if !peripheral.is_connected().await.map_err(be)? {
            peripheral.connect().await.map_err(be)?;
        }
        peripheral.discover_services().await.map_err(be)?;
        let chars = peripheral.characteristics();
        let rx_char = chars
            .iter()
            .find(|c| c.uuid == RX_UUID && c.service_uuid == SERVICE_UUID)
            .cloned()
            .ok_or_else(|| Error::Transport("Prism RX characteristic not found".into()))?;
        let tx_char = chars
            .iter()
            .find(|c| c.uuid == TX_UUID && c.service_uuid == SERVICE_UUID && c.properties.contains(CharPropFlags::NOTIFY))
            .cloned()
            .ok_or_else(|| Error::Transport("Prism TX characteristic not found".into()))?;
        peripheral.subscribe(&tx_char).await.map_err(be)?;
        let mut stream = peripheral.notifications().await.map_err(be)?;
        let (tx, notif) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(n) = stream.next().await {
                if n.uuid == TX_UUID && tx.send(n.value).is_err() {
                    break;
                }
            }
        });
        Ok(Self { peripheral, rx_char, notif, framing: Framing::new(mtu.unwrap_or(DEFAULT_MTU)), id })
    }

    /// Stable id of the connected peripheral (store as `last_ble_id`).
    pub fn device_id(&self) -> &str {
        &self.id
    }
}

#[async_trait]
impl Transport for BleTransport {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        for c in self.framing.chunks(frame) {
            self.peripheral.write(&self.rx_char, &c, WriteType::WithoutResponse).await.map_err(be)?;
        }
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        loop {
            let c = self.notif.recv().await.ok_or(Error::Closed)?;
            if let Some(f) = self.framing.push(&c)? {
                return Ok(f);
            }
        }
    }
}

impl Drop for BleTransport {
    fn drop(&mut self) {
        let p = self.peripheral.clone();
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(async move {
                let _ = p.disconnect().await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeDevice;
    use crate::{Client, ClientOptions, EstablishOutcome};
    use prism_proto::ble::{chunk_for, ChannelReassembler};
    use prism_proto::generate_static_keypair;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    type Subs = Arc<Mutex<Vec<mpsc::UnboundedSender<Vec<u8>>>>>;

    /// Host side of the fake shared link: writes go to the device, every notification is
    /// delivered to every subscribed client (like CoreBluetooth on one Mac).
    struct LinkTransport {
        framing: Framing,
        rx_write: mpsc::UnboundedSender<Vec<u8>>,
        notif: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    #[async_trait]
    impl Transport for LinkTransport {
        async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
            for c in self.framing.chunks(frame) {
                self.rx_write.send(c).map_err(|_| Error::Closed)?;
                tokio::task::yield_now().await; // let the other client interleave
            }
            Ok(())
        }
        async fn recv_frame(&mut self) -> Result<Vec<u8>> {
            loop {
                let c = self.notif.recv().await.ok_or(Error::Closed)?;
                if let Some(f) = self.framing.push(&c)? {
                    return Ok(f);
                }
            }
        }
    }

    fn new_client_link(rx_write: &mpsc::UnboundedSender<Vec<u8>>, subs: &Subs, mtu: usize) -> LinkTransport {
        let (tx, notif) = mpsc::unbounded_channel();
        subs.lock().unwrap().push(tx);
        LinkTransport { framing: Framing::new(mtu), rx_write: rx_write.clone(), notif }
    }

    /// Fake device: one ChannelReassembler + one FakeDevice session per channel; replies are
    /// chunked with `chunk_for` and broadcast to all subscribers.
    fn spawn_device(dev: FakeDevice, mtu: usize) -> (mpsc::UnboundedSender<Vec<u8>>, Subs) {
        let (rx_write, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let subs: Subs = Default::default();
        let subs2 = subs.clone();
        tokio::spawn(async move {
            let mut re = ChannelReassembler::new(8);
            let mut sessions: HashMap<u32, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
            while let Some(c) = rx.recv().await {
                let Ok(Some((chan, frame))) = re.push(&c) else { continue };
                let to_sess = sessions.entry(chan).or_insert_with(|| {
                    // One device session per channel; its replies are chunked in the client's
                    // format and broadcast to every subscriber.
                    let (tx, mut from_link) = mpsc::unbounded_channel::<Vec<u8>>();
                    let mut t = dev.connect();
                    let subs = subs2.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                f = from_link.recv() => match f {
                                    Some(f) => { if t.send_frame(&f).await.is_err() { return } }
                                    None => return,
                                },
                                r = t.recv_frame() => {
                                    let Ok(r) = r else { return };
                                    for ch in chunk_for(&r, mtu, chan) {
                                        for s in subs.lock().unwrap().iter() {
                                            let _ = s.send(ch.clone());
                                        }
                                        tokio::task::yield_now().await;
                                    }
                                }
                            }
                        }
                    });
                    tx
                });
                let _ = to_sess.send(frame);
            }
        });
        (rx_write, subs)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_clients_share_one_link() {
        let dev = FakeDevice::new();
        let (rx_write, subs) = spawn_device(dev.clone(), 23);
        let ta = new_client_link(&rx_write, &subs, 23);
        let tb = new_client_link(&rx_write, &subs, 23);
        assert_ne!(ta.framing.chan, tb.framing.chan);
        let (ka, pa) = generate_static_keypair();
        let (kb, pb) = generate_static_keypair();
        dev.add_paired_host(pa, "a");
        dev.add_paired_host(pb, "b");
        let run = |t: LinkTransport, k: [u8; 32]| async move {
            let mut c = Client::connect(Box::new(t), ClientOptions::new(k)).await.unwrap();
            assert!(matches!(c.establish(None).await.unwrap(), EstablishOutcome::Ready(_)));
            for _ in 0..5 {
                assert_eq!(c.info().await.unwrap().fw_version, "fake-0.1");
                assert!(c.list(None).await.unwrap().is_empty());
            }
        };
        let (a, b) = tokio::join!(tokio::spawn(run(ta, ka)), tokio::spawn(run(tb, kb)));
        a.unwrap();
        b.unwrap();
    }
}
