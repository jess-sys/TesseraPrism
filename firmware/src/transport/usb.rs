//! USB composite transport (TinyUSB via the `prism_usb` C shim): CDC-ACM (Prism protocol, COBS),
//! HID FIDO (CTAPHID) and HID boot keyboard (see `hid_keyboard.rs`).
//!
//! TinyUSB callbacks run on the TinyUSB task and only push messages into a channel; all framing
//! is done on the `usb` worker thread.

use std::{
    ffi::{c_char, CString},
    sync::{mpsc, OnceLock},
    thread,
    time::{Duration, Instant},
};

use prism_ctap::ctaphid::{self, CtapHid};
use prism_proto::cdc;

use super::{CtapOrigin, Link, TransportEvent};

#[repr(C)]
struct Callbacks {
    on_mount: extern "C" fn(bool),
    on_cdc_rx: extern "C" fn(*const u8, usize),
    on_fido_out: extern "C" fn(*const u8),
    on_cdc_dtr: extern "C" fn(bool),
}

extern "C" {
    fn prism_usb_install(serial: *const c_char, cbs: *const Callbacks) -> i32;
    fn prism_usb_mounted() -> bool;
    fn prism_usb_cdc_write(data: *const u8, len: usize) -> bool;
    fn prism_usb_hid_send(instance: u8, report: *const u8, len: u8) -> bool;
}

const HID_FIDO: u8 = 0;
const HID_KBD: u8 = 1;
const KEEPALIVE_PERIOD: Duration = Duration::from_millis(100);
/// Half-assembled CTAPHID message timeout (CTAPHID spec: 500 ms).
const ASSEMBLY_TIMEOUT: Duration = Duration::from_millis(500);

pub fn mounted() -> bool {
    unsafe { prism_usb_mounted() }
}

/// Send one HID report (blocks briefly until the endpoint is ready). False when it was dropped.
pub fn kbd_report(report: &[u8; 8]) -> bool {
    unsafe { prism_usb_hid_send(HID_KBD, report.as_ptr(), 8) }
}

fn fido_report(r: &[u8; 64]) -> bool {
    unsafe { prism_usb_hid_send(HID_FIDO, r.as_ptr(), 64) }
}

enum In {
    Mount(bool),
    CdcRx(Vec<u8>),
    CdcDtr(bool),
    FidoOut(Box<[u8; 64]>),
    PrismFrame(Vec<u8>),
    CtapResponse { cid: u32, response: Vec<u8> },
}

static INBOX: OnceLock<mpsc::Sender<In>> = OnceLock::new();

fn post(m: In) {
    if let Some(tx) = INBOX.get() {
        let _ = tx.send(m);
    }
}

extern "C" fn cb_mount(m: bool) {
    post(In::Mount(m));
}
extern "C" fn cb_cdc_rx(data: *const u8, len: usize) {
    post(In::CdcRx(unsafe { std::slice::from_raw_parts(data, len) }.to_vec()));
}
extern "C" fn cb_fido_out(data: *const u8) {
    let mut b = Box::new([0u8; 64]);
    b.copy_from_slice(unsafe { std::slice::from_raw_parts(data, 64) });
    post(In::FidoOut(b));
}
extern "C" fn cb_cdc_dtr(dtr: bool) {
    post(In::CdcDtr(dtr));
}

pub struct Usb {
    tx: mpsc::Sender<In>,
}

impl Usb {
    pub fn start(events: mpsc::Sender<TransportEvent>) -> anyhow::Result<Usb> {
        let (tx, rx) = mpsc::channel();
        INBOX.set(tx.clone()).map_err(|_| anyhow::anyhow!("usb already started"))?;

        let mut mac = [0u8; 6];
        unsafe {
            esp_idf_svc::sys::esp_read_mac(mac.as_mut_ptr(), esp_idf_svc::sys::esp_mac_type_t_ESP_MAC_WIFI_STA);
        }
        let serial = format!(
            "PRISM-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        // TinyUSB keeps the pointer for the lifetime of the device.
        let serial: &'static CString = Box::leak(Box::new(CString::new(serial)?));
        static CBS: Callbacks = Callbacks {
            on_mount: cb_mount,
            on_cdc_rx: cb_cdc_rx,
            on_fido_out: cb_fido_out,
            on_cdc_dtr: cb_cdc_dtr,
        };
        let rc = unsafe { prism_usb_install(serial.as_ptr(), &CBS) };
        anyhow::ensure!(rc == 0, "prism_usb_install failed: {rc}");

        thread::Builder::new()
            .name("usb".into())
            .stack_size(8192)
            .spawn(move || worker(rx, events))?;
        log::info!("usb: TinyUSB composite installed (serial {})", serial.to_string_lossy());
        Ok(Usb { tx })
    }

    pub fn prism_frame(&self, frame: Vec<u8>) {
        let _ = self.tx.send(In::PrismFrame(frame));
    }

    pub fn ctap_response(&self, cid: u32, response: Vec<u8>) {
        let _ = self.tx.send(In::CtapResponse { cid, response });
    }
}

fn worker(rx: mpsc::Receiver<In>, events: mpsc::Sender<TransportEvent>) {
    let mut dec = cdc::Decoder::new();
    let mut hid = CtapHid::new();
    let mut configured = false;
    let mut outstanding: Option<u32> = None;
    let mut last_fido_rx = Instant::now();
    let mut next_tick = Instant::now() + KEEPALIVE_PERIOD;

    let send_reports = |reports: Vec<[u8; 64]>| {
        for r in reports {
            if !fido_report(&r) {
                log::warn!("usb: FIDO report dropped (host not ready)");
                break;
            }
        }
    };

    loop {
        let wait = next_tick.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(In::Mount(m)) => {
                if m != configured {
                    configured = m;
                    log::info!("usb: configured={m}");
                    let _ = events.send(TransportEvent::UsbConfigured(m));
                    if !m {
                        dec = cdc::Decoder::new();
                        let _ = events.send(TransportEvent::PrismClosed { link: Link::Usb });
                    }
                }
            }
            Ok(In::CdcDtr(dtr)) => {
                dec = cdc::Decoder::new();
                if !dtr {
                    let _ = events.send(TransportEvent::PrismClosed { link: Link::Usb });
                }
            }
            Ok(In::CdcRx(bytes)) => {
                for f in dec.push(&bytes) {
                    match f {
                        Ok(frame) => {
                            let _ = events.send(TransportEvent::PrismFrame { link: Link::Usb, frame });
                        }
                        Err(e) => log::warn!("usb: bad CDC frame: {e:?}"),
                    }
                }
            }
            Ok(In::PrismFrame(frame)) => {
                let enc = cdc::encode(&frame);
                if !unsafe { prism_usb_cdc_write(enc.as_ptr(), enc.len()) } {
                    log::warn!("usb: CDC write failed ({} B dropped)", enc.len());
                }
            }
            Ok(In::FidoOut(r)) => {
                last_fido_rx = Instant::now();
                let done = hid.push_report(&r);
                send_reports(hid.take_outbox());
                if let Some(req) = done {
                    let origin = CtapOrigin { link: Link::Usb, channel: req.cid };
                    match req.cmd {
                        ctaphid::CMD_CBOR => {
                            outstanding = Some(req.cid);
                            let _ = events.send(TransportEvent::CtapRequest { origin, request: req.payload });
                        }
                        ctaphid::CMD_CANCEL => {
                            let _ = events.send(TransportEvent::CtapCancel { origin });
                        }
                        ctaphid::CMD_WINK => {
                            let _ = events.send(TransportEvent::Wink);
                            send_reports(hid.response_reports(req.cid, ctaphid::CMD_WINK, &[]));
                        }
                        other => log::warn!("usb: unexpected completed CTAPHID cmd {other:#x}"),
                    }
                    send_reports(hid.take_outbox());
                }
            }
            Ok(In::CtapResponse { cid, response }) => {
                if outstanding == Some(cid) {
                    outstanding = None;
                }
                send_reports(hid.response_reports(cid, ctaphid::CMD_CBOR, &response));
                send_reports(hid.take_outbox());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }

        if Instant::now() >= next_tick {
            next_tick = Instant::now() + KEEPALIVE_PERIOD;
            if let Some(cid) = outstanding {
                if configured {
                    let _ = fido_report(&ctaphid::keepalive_report(cid, ctaphid::KEEPALIVE_PROCESSING));
                }
            } else if hid.is_busy() && last_fido_rx.elapsed() > ASSEMBLY_TIMEOUT {
                hid.timeout_assembly();
                send_reports(hid.take_outbox());
            }
        }
    }
}
