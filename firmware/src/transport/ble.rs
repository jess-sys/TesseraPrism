//! BLE transport (NimBLE via `esp32-nimble`): Prism GATT service, FIDO service (0xFFFD),
//! Battery (0x180F) and Device Information (0x180A).
//!
//! Threading: GATT callbacks run on the NimBLE host task and only do cheap work (reassembly, event
//! emission). Everything that sends (notifications, keepalives, disconnects) goes through the
//! `ble-tx` worker thread via the `Out` channel.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use esp32_nimble::{
    enums::{AuthReq, PairKeyDist, SecurityIOCap},
    utilities::{mutex::Mutex as NimMutex, BleUuid},
    BLEAdvertisementData, BLECharacteristic, BLEDevice, NimbleProperties,
};
use esp_idf_svc::sys;
use prism_ctap::ble as ctap_ble;
use prism_proto::ble as prism_ble;

use super::{CtapOrigin, Link, TransportConfig, TransportEvent};

const PRISM_SERVICE: &str = "9e5d0001-3c4a-4b8e-9f1a-5072736d0000";
const PRISM_RX: &str = "9e5d0002-3c4a-4b8e-9f1a-5072736d0000";
const PRISM_TX: &str = "9e5d0003-3c4a-4b8e-9f1a-5072736d0000";

// FIDO CTAP 2.1 section 8.3.1 (BLE): the 128-bit base is F1D0xxxx-DEAA-ECEE-B42F-C9BA7ED623BB.
const FIDO_SERVICE: u16 = 0xFFFD;
const FIDO_CONTROL_POINT: &str = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb";
const FIDO_STATUS: &str = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb";
const FIDO_CONTROL_POINT_LENGTH: &str = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb";
const FIDO_SERVICE_REVISION_BITFIELD: &str = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb";
/// Bit 5 = FIDO2 (CTAP2) supported.
const FIDO2_REVISION: u8 = 0x20;

/// Max simultaneous Prism channels per BLE connection (LRU-evicted beyond this).
const MAX_CHANNELS: usize = 4;

const KEEPALIVE_PERIOD: Duration = Duration::from_millis(100);

type Chr = Arc<NimMutex<BLECharacteristic>>;

fn uuid128(s: &str) -> BleUuid {
    BleUuid::from_uuid128_string(s).expect("valid uuid")
}

struct Conn {
    prism: prism_ble::ChannelReassembler,
    fido: ctap_ble::BleAssembler,
    /// A CTAP request was handed to core and no response was sent yet.
    outstanding: bool,
}

enum Out {
    Prism { handle: u16, chan: u32, frame: Vec<u8> },
    /// Already fragmented FIDO frames for the status characteristic.
    Fido { handle: u16, frames: Vec<Vec<u8>> },
    /// A pairing attempt arrived while bonding is not allowed: drop unencrypted links.
    RejectPairing,
    /// Re-evaluate advertising state.
    Advertising,
    /// Re-apply advertising parameters (interval) and restart advertising.
    Reconfigure,
    Shutdown(Sender<()>),
}

struct Shared {
    /// Locked standby: slow advertising.
    low_power: AtomicBool,
    events: Sender<TransportEvent>,
    out: Sender<Out>,
    conns: Mutex<HashMap<u16, Conn>>,
    bonding_allowed: AtomicBool,
    adv_wanted: AtomicBool,
    pairing_active: AtomicBool,
    shut_down: AtomicBool,
}

impl Shared {
    fn emit(&self, ev: TransportEvent) {
        let _ = self.events.send(ev);
    }
}

pub struct Ble {
    shared: Arc<Shared>,
    battery: Chr,
}

fn max_conns() -> usize {
    sys::CONFIG_BT_NIMBLE_MAX_CONNECTIONS as usize
}

fn att_mtu(handle: u16) -> usize {
    (unsafe { sys::ble_att_mtu(handle) } as usize).max(23)
}

fn fido_max_len(handle: u16) -> usize {
    (att_mtu(handle) - 3).clamp(20, 512)
}

/// Start/stop advertising according to `adv_wanted` and free connection slots.
fn apply_advertising(shared: &Shared) {
    let adv = BLEDevice::take().get_advertising();
    let mut adv = adv.lock();
    let n = shared.conns.lock().unwrap().len();
    let want = shared.adv_wanted.load(Ordering::SeqCst)
        && !shared.shut_down.load(Ordering::SeqCst)
        && n < max_conns();
    if want && !adv.is_advertising() {
        if let Err(e) = adv.start() {
            log::warn!("ble: advertising start failed: {e:?}");
        }
    } else if !want && adv.is_advertising() {
        if let Err(e) = adv.stop() {
            log::warn!("ble: advertising stop failed: {e:?}");
        }
    }
}

impl Ble {
    pub fn start(config: &TransportConfig, events: Sender<TransportEvent>) -> anyhow::Result<Ble> {
        let (out_tx, out_rx) = mpsc::channel::<Out>();
        let shared = Arc::new(Shared {
            low_power: AtomicBool::new(false),
            events,
            out: out_tx,
            conns: Mutex::new(HashMap::new()),
            bonding_allowed: AtomicBool::new(false),
            adv_wanted: AtomicBool::new(true),
            pairing_active: AtomicBool::new(false),
            shut_down: AtomicBool::new(false),
        });

        let device = BLEDevice::take();
        BLEDevice::set_device_name(&config.ble_name).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        device
            .set_preferred_mtu(247)
            .map_err(|e| anyhow::anyhow!("set mtu: {e:?}"))?;

        // LE Secure Connections + MITM + bonding; we can only display a passkey.
        device
            .security()
            .set_auth(AuthReq::Bond | AuthReq::Mitm | AuthReq::Sc)
            .set_io_cap(SecurityIOCap::DisplayOnly)
            .set_security_init_key(PairKeyDist::ENC | PairKeyDist::ID)
            .set_security_resp_key(PairKeyDist::ENC | PairKeyDist::ID)
            .resolve_rpa();

        let server = device.get_server();
        server.advertise_on_disconnect(false);

        {
            let sh = shared.clone();
            server.on_connect(move |_server, desc| {
                let h = desc.conn_handle();
                log::info!("ble: connected handle={h}");
                sh.conns.lock().unwrap().insert(
                    h,
                    Conn {
                        prism: prism_ble::ChannelReassembler::new(MAX_CHANNELS),
                        fido: ctap_ble::BleAssembler::new(),
                        outstanding: false,
                    },
                );
                sh.emit(TransportEvent::BleConnected(true));
                let _ = sh.out.send(Out::Advertising);
            });
        }
        {
            let sh = shared.clone();
            server.on_disconnect(move |desc, reason| {
                let h = desc.conn_handle();
                log::info!("ble: disconnected handle={h} reason={reason:?}");
                let (was, remaining) = {
                    let mut c = sh.conns.lock().unwrap();
                    (c.remove(&h), c.len())
                };
                if let Some(conn) = &was {
                    if conn.outstanding {
                        sh.emit(TransportEvent::CtapCancel {
                            origin: CtapOrigin { link: Link::Ble { conn: h, chan: 0 }, channel: h as u32 },
                        });
                    }
                }
                if let Some(conn) = &was {
                    for chan in conn.prism.channels() {
                        sh.emit(TransportEvent::PrismClosed { link: Link::Ble { conn: h, chan } });
                    }
                }
                sh.emit(TransportEvent::BleConnected(remaining > 0));
                let _ = sh.out.send(Out::Advertising);
            });
        }
        {
            let sh = shared.clone();
            server.on_passkey_request(move || {
                if !sh.bonding_allowed.load(Ordering::SeqCst) {
                    log::warn!("ble: pairing requested while bonding is not allowed; rejecting");
                    let _ = sh.out.send(Out::RejectPairing);
                    return 0;
                }
                let passkey = unsafe { sys::esp_random() } % 1_000_000;
                sh.pairing_active.store(true, Ordering::SeqCst);
                sh.emit(TransportEvent::BlePasskeyDisplay { passkey });
                passkey
            });
        }
        {
            let sh = shared.clone();
            server.on_authentication_complete(move |_server, desc, result| {
                log::info!("ble: auth complete handle={} ok={} bonded={}", desc.conn_handle(), result.is_ok(), desc.bonded());
                // Only report real pairings (a passkey was shown), not re-encryption with an existing bond.
                if sh.pairing_active.swap(false, Ordering::SeqCst) {
                    sh.emit(TransportEvent::BlePairingFinished { success: result.is_ok() });
                }
            });
        }

        // ---- Prism service ---------------------------------------------------------------------
        let prism_svc = server.create_service(uuid128(PRISM_SERVICE));
        let prism_rx = prism_svc
            .lock()
            .create_characteristic(uuid128(PRISM_RX), NimbleProperties::WRITE | NimbleProperties::WRITE_NO_RSP);
        let prism_tx = prism_svc
            .lock()
            .create_characteristic(uuid128(PRISM_TX), NimbleProperties::NOTIFY);
        {
            let sh = shared.clone();
            prism_rx.lock().on_write(move |args| {
                let h = args.desc().conn_handle();
                let data = args.recv_data();
                let (before, result, after) = {
                    let mut conns = sh.conns.lock().unwrap();
                    match conns.get_mut(&h) {
                        Some(c) => {
                            let before = c.prism.channels();
                            let r = c.prism.push(data);
                            (before, r, c.prism.channels())
                        }
                        None => return,
                    }
                };
                // Channels that disappeared (LRU eviction or reassembly error) lose their session.
                for chan in before.iter().filter(|c| !after.contains(c)) {
                    sh.emit(TransportEvent::PrismClosed { link: Link::Ble { conn: h, chan: *chan } });
                }
                match result {
                    Ok(Some((chan, frame))) => {
                        sh.emit(TransportEvent::PrismFrame { link: Link::Ble { conn: h, chan }, frame })
                    }
                    Ok(None) => {}
                    Err(e) => log::warn!("ble: prism reassembly error: {e:?}"),
                }
            });
        }

        // ---- FIDO service ----------------------------------------------------------------------
        let fido_svc = server.create_service(BleUuid::from_uuid16(FIDO_SERVICE));
        let fido_cp = fido_svc.lock().create_characteristic(
            uuid128(FIDO_CONTROL_POINT),
            NimbleProperties::WRITE | NimbleProperties::WRITE_ENC | NimbleProperties::WRITE_AUTHEN,
        );
        let fido_status = fido_svc
            .lock()
            .create_characteristic(uuid128(FIDO_STATUS), NimbleProperties::NOTIFY);
        let fido_len = fido_svc.lock().create_characteristic(
            uuid128(FIDO_CONTROL_POINT_LENGTH),
            NimbleProperties::READ | NimbleProperties::READ_ENC | NimbleProperties::READ_AUTHEN,
        );
        let fido_rev = fido_svc.lock().create_characteristic(
            uuid128(FIDO_SERVICE_REVISION_BITFIELD),
            NimbleProperties::READ
                | NimbleProperties::READ_ENC
                | NimbleProperties::WRITE
                | NimbleProperties::WRITE_ENC,
        );
        fido_len.lock().set_value(&512u16.to_be_bytes());
        fido_len.lock().on_read(|chr, desc| {
            let len = fido_max_len(desc.conn_handle()) as u16;
            chr.set_value(&len.to_be_bytes());
        });
        fido_rev.lock().set_value(&[FIDO2_REVISION]);
        fido_rev.lock().on_write(|args| {
            // We only speak FIDO2; accept the selection of that revision, reject everything else.
            let d = args.recv_data();
            if d.len() != 1 || d[0] & !FIDO2_REVISION != 0 {
                args.reject();
            }
        });
        {
            let sh = shared.clone();
            fido_cp.lock().on_write(move |args| {
                let h = args.desc().conn_handle();
                let data = args.recv_data();
                let result = {
                    let mut conns = sh.conns.lock().unwrap();
                    match conns.get_mut(&h) {
                        Some(c) => c.fido.push(data),
                        None => return,
                    }
                };
                let origin = CtapOrigin { link: Link::Ble { conn: h, chan: 0 }, channel: h as u32 };
                match result {
                    Ok(None) => {}
                    Ok(Some((ctap_ble::CMD_MSG, payload))) => {
                        if let Some(c) = sh.conns.lock().unwrap().get_mut(&h) {
                            c.outstanding = true;
                        }
                        sh.emit(TransportEvent::CtapRequest { origin, request: payload });
                    }
                    Ok(Some((ctap_ble::CMD_PING, payload))) => {
                        let frames = ctap_ble::fragment(ctap_ble::CMD_PING, &payload, fido_max_len(h));
                        let _ = sh.out.send(Out::Fido { handle: h, frames });
                    }
                    Ok(Some((ctap_ble::CMD_CANCEL, _))) => {
                        sh.emit(TransportEvent::CtapCancel { origin });
                    }
                    Ok(Some((cmd, _))) => {
                        log::warn!("ble: unsupported FIDO command {cmd:#x}");
                        let _ = sh.out.send(Out::Fido { handle: h, frames: vec![ctap_ble::error_frame(ctap_ble::ERR_INVALID_CMD)] });
                    }
                    Err(ctap_ble::BleError::Protocol(code)) => {
                        let _ = sh.out.send(Out::Fido { handle: h, frames: vec![ctap_ble::error_frame(code)] });
                    }
                }
            });
        }

        // ---- Battery service -------------------------------------------------------------------
        let batt_svc = server.create_service(BleUuid::from_uuid16(0x180F));
        let battery = batt_svc
            .lock()
            .create_characteristic(BleUuid::from_uuid16(0x2A19), NimbleProperties::READ | NimbleProperties::NOTIFY);
        battery.lock().set_value(&[100]);

        // ---- Device information ----------------------------------------------------------------
        let dis = server.create_service(BleUuid::from_uuid16(0x180A));
        for (uuid, value) in [
            (0x2A29u16, "Prism"),
            (0x2A24, "Prism Key"),
            (0x2A26, config.fw_version.as_str()),
            (0x2A27, "M5Stack Paper S3"),
        ] {
            dis.lock()
                .create_characteristic(BleUuid::from_uuid16(uuid), NimbleProperties::READ)
                .lock()
                .set_value(value.as_bytes());
        }

        server.start().map_err(|e| anyhow::anyhow!("gatt server start: {e:?}"))?;

        // ---- Advertising -----------------------------------------------------------------------
        {
            let adv = device.get_advertising();
            let mut adv = adv.lock();
            adv.set_data(
                BLEAdvertisementData::new()
                    .name(&config.ble_name)
                    .add_service_uuid(uuid128(PRISM_SERVICE))
                    .add_service_uuid(BleUuid::from_uuid16(FIDO_SERVICE)),
            )
            .map_err(|e| anyhow::anyhow!("adv data: {e:?}"))?;
        }

        // ---- TX worker -------------------------------------------------------------------------
        {
            let sh = shared.clone();
            // PSRAM stack: never touches flash.
            crate::threads::spawn_psram("ble-tx", 8192, move || worker(sh, out_rx, prism_tx, fido_status))?;
        }
        let _ = shared.out.send(Out::Advertising);
        log::info!("ble: started as {:?}", config.ble_name);
        Ok(Ble { shared, battery })
    }

    /// Send a Prism frame to one BLE connection.
    pub fn prism_frame(&self, handle: u16, chan: u32, frame: Vec<u8>) {
        if frame.len() > prism_proto::frame::MAX_FRAME {
            log::warn!("ble: dropping oversized prism frame ({} B)", frame.len());
            return;
        }
        let _ = self.shared.out.send(Out::Prism { handle, chan, frame });
    }

    pub fn ctap_response(&self, handle: u32, response: Vec<u8>) {
        let h = handle as u16;
        match self.shared.conns.lock().unwrap().get_mut(&h) {
            Some(c) => c.outstanding = false,
            None => {
                log::warn!("ble: CTAP response for a closed connection dropped");
                return;
            }
        }
        let frames = ctap_ble::fragment(ctap_ble::CMD_MSG, &response, fido_max_len(h));
        let _ = self.shared.out.send(Out::Fido { handle: h, frames });
    }

    pub fn set_advertising(&self, on: bool) {
        self.shared.adv_wanted.store(on, Ordering::SeqCst);
        let _ = self.shared.out.send(Out::Advertising);
    }

    pub fn set_low_power(&self, on: bool) {
        if self.shared.low_power.swap(on, Ordering::SeqCst) != on {
            let _ = self.shared.out.send(Out::Reconfigure);
        }
    }

    pub fn set_bonding_allowed(&self, on: bool) {
        self.shared.bonding_allowed.store(on, Ordering::SeqCst);
    }

    pub fn set_battery(&self, level: u8) {
        let mut c = self.battery.lock();
        c.set_value(&[level.min(100)]);
        c.notify();
    }

    /// Stop advertising, disconnect all peers and deinit the NimBLE stack.
    pub fn shutdown(&self) {
        let (tx, rx) = mpsc::channel();
        if self.shared.out.send(Out::Shutdown(tx)).is_ok() {
            let _ = rx.recv_timeout(Duration::from_secs(3));
        }
    }
}

/// Value handle of the Prism TX characteristic, looked up once the GATT server is running.
fn prism_tx_value_handle() -> u16 {
    static HANDLE: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let h = HANDLE.load(Ordering::Relaxed);
    if h != 0 {
        return h;
    }
    let svc: sys::ble_uuid_any_t = uuid128(PRISM_SERVICE).into();
    let chr: sys::ble_uuid_any_t = uuid128(PRISM_TX).into();
    let mut val = 0u16;
    let rc = unsafe { sys::ble_gatts_find_chr(&svc.u, &chr.u, std::ptr::null_mut(), &mut val) };
    if rc == 0 {
        HANDLE.store(val, Ordering::Relaxed);
    }
    val
}

/// Notify a Prism frame chunk to `handle`. The library only notifies connections in its own
/// subscription list, which can miss a client: on macOS several processes share one link, and
/// when one leaves, the CCCD is cleared, while the next one's "enable" may not be written again
/// on that still-open link. CoreBluetooth only delivers notifications to processes that asked
/// for them, so sending to the requesting connection regardless is safe.
fn notify_prism(chr: &Chr, handle: u16, data: &[u8]) -> bool {
    // Normal path first; EINVAL means "not in the library's subscription list".
    for _ in 0..200 {
        match chr.lock().notify_with(data, handle) {
            Ok(()) => return true,
            Err(e) if e.code() == sys::BLE_HS_ENOMEM || e.code() == sys::BLE_HS_EBUSY => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) if e.code() == sys::BLE_HS_EINVAL => break,
            Err(e) => {
                log::warn!("ble: notify to {handle} failed: {e:?}");
                return false;
            }
        }
    }
    log::info!("ble: conn {handle} not subscribed per stack bookkeeping; notifying directly");
    let val = prism_tx_value_handle();
    if val == 0 {
        log::warn!("ble: prism TX handle unknown, frame dropped");
        return false;
    }
    for _ in 0..200 {
        let om = unsafe { sys::ble_hs_mbuf_from_flat(data.as_ptr().cast(), data.len() as u16) };
        if om.is_null() {
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        let rc = unsafe { sys::ble_gatts_notify_custom(handle, val, om) } as u32;
        match rc {
            0 => return true,
            sys::BLE_HS_ENOMEM | sys::BLE_HS_EBUSY => thread::sleep(Duration::from_millis(5)),
            _ => {
                log::warn!("ble: raw notify to {handle} failed: rc={rc}");
                return false;
            }
        }
    }
    log::warn!("ble: raw notify to {handle} timed out");
    false
}

fn notify(chr: &Chr, handle: u16, data: &[u8]) -> bool {
    for _ in 0..200 {
        let r = chr.lock().notify_with(data, handle);
        match r {
            Ok(()) => return true,
            Err(e) if e.code() == sys::BLE_HS_ENOMEM || e.code() == sys::BLE_HS_EBUSY => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                log::warn!("ble: notify to {handle} failed: {e:?}");
                return false;
            }
        }
    }
    log::warn!("ble: notify to {handle} timed out");
    false
}

fn worker(sh: Arc<Shared>, rx: mpsc::Receiver<Out>, prism_tx: Chr, fido_status: Chr) {
    let mut next_keepalive = Instant::now() + KEEPALIVE_PERIOD;
    loop {
        let timeout = next_keepalive.saturating_duration_since(Instant::now());
        match rx.recv_timeout(timeout) {
            Ok(Out::Prism { handle: h, chan, frame }) => {
                if !sh.conns.lock().unwrap().contains_key(&h) {
                    log::warn!("ble: prism frame for closed connection {h} dropped");
                } else {
                    for c in prism_ble::chunk_for(&frame, att_mtu(h), chan) {
                        if !notify_prism(&prism_tx, h, &c) {
                            break;
                        }
                    }
                }
            }
            Ok(Out::Fido { handle, frames }) => {
                for f in frames {
                    if !notify(&fido_status, handle, &f) {
                        break;
                    }
                }
            }
            Ok(Out::RejectPairing) => {
                let server = BLEDevice::take().get_server();
                let victims: Vec<u16> = server
                    .connections()
                    .filter(|d| !d.encrypted())
                    .map(|d| d.conn_handle())
                    .collect();
                for h in victims {
                    let _ = server.disconnect(h);
                }
            }
            Ok(Out::Advertising) => apply_advertising(&sh),
            Ok(Out::Reconfigure) => {
                let low = sh.low_power.load(Ordering::SeqCst);
                {
                    let adv = BLEDevice::take().get_advertising();
                    let mut adv = adv.lock();
                    if adv.is_advertising() {
                        let _ = adv.stop();
                    }
                    // Units of 0.625 ms: standby 1.0-1.5 s, normal 100-200 ms.
                    let (min, max) = if low { (1600, 2400) } else { (160, 320) };
                    adv.min_interval(min).max_interval(max);
                }
                log::info!("ble: advertising {}", if low { "low power (1-1.5 s)" } else { "normal" });
                apply_advertising(&sh);
            }
            Ok(Out::Shutdown(done)) => {
                sh.shut_down.store(true, Ordering::SeqCst);
                apply_advertising(&sh);
                let server = BLEDevice::take().get_server();
                let handles: Vec<u16> = server.connections().map(|d| d.conn_handle()).collect();
                for h in handles {
                    let _ = server.disconnect(h);
                }
                for _ in 0..20 {
                    if server.connected_count() == 0 {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                if let Err(e) = BLEDevice::deinit_full() {
                    log::warn!("ble: deinit failed: {e:?}");
                }
                log::info!("ble: shut down");
                let _ = done.send(());
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        if Instant::now() >= next_keepalive {
            next_keepalive = Instant::now() + KEEPALIVE_PERIOD;
            let pending: Vec<u16> = sh
                .conns
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, c)| c.outstanding)
                .map(|(h, _)| *h)
                .collect();
            for h in pending {
                notify(&fido_status, h, &ctap_ble::keepalive_frame(ctap_ble::KEEPALIVE_PROCESSING));
            }
        }
    }
}
