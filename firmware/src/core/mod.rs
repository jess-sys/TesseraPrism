//! The `core` actor (ARCHITECTURE 7.4): owns the unlocked vault, the Noise sessions, the approval
//! broker and the persistent state. Everything else talks to it through [`msg::CoreMsg`].
//!
//! Sub-modules: `requests` (Prism protocol requests and their lock/approval gating), `local`
//! (actions from the on-device UI, lock/unlock/setup/wipe), `approval` (broker types), `ctap`
//! (Authenticator worker thread + Platform impl), `clock`, `msg`.
pub mod approval;
pub mod clock;
pub mod ctap;
mod local;
pub mod msg;
pub(crate) mod requests;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use prism_core::model::{PairedHost, Settings};
use prism_core::UnlockedVault;
use prism_proto::{DeviceEvent, DeviceSession, Envelope, ErrorCode, ProtoError, Response};
use prism_ui::{Counts, UiEvent};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::storage::{Store, VaultStore};
use crate::transport::{CtapOrigin, Link, TransportCommand, TransportEvent};
use approval::Broker;
use clock::Clock;
use msg::{CoreMsg, CtapJob, CtapReply, Mode, PowerMsg, SharedStatus, UiMsg};

/// CTAP2_ERR_KEEPALIVE_CANCEL
const CTAP_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
pub const FW_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Pairing mode (Settings -> Pair new host) expires after this long.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);
/// Replace-import waits this long for the PIN.
const PIN_PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest accepted `.prism` import.
pub const MAX_IMPORT_BYTES: usize = 640 * 1024;

/// `rand_core` adapter over the hardware RNG (true entropy while the radio is on).
pub struct EspRng;

impl RngCore for EspRng {
    fn next_u32(&mut self) -> u32 {
        unsafe { esp_idf_sys::esp_random() }
    }
    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | self.next_u32() as u64
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe { esp_idf_sys::esp_fill_random(dest.as_mut_ptr() as *mut _, dest.len()) };
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for EspRng {}

enum Auth {
    /// Noise handshake in progress.
    Handshaking,
    Ready { key: [u8; 32] },
    /// Unknown host in pairing mode: SAS shown, waiting for the user.
    PairPending { key: [u8; 32], confirmed: Option<bool>, first_req: Option<u32> },
    /// Unknown host, not in pairing mode: answer `NotPaired` once, then drop.
    Rejected,
}

struct Session {
    ds: DeviceSession,
    auth: Auth,
    label: String,
    /// Last frame received on this session (LRU eviction).
    last: Instant,
}

/// Max simultaneous Prism sessions (all links); beyond this the least recently used is dropped.
const MAX_SESSIONS: usize = 8;

struct ImportBuf {
    expected: usize,
    data: Vec<u8>,
}

/// Replace-import waiting for the user to type the PIN (needed to re-wrap the PIN slot).
struct PendingReplace {
    seed: Zeroizing<[u8; 32]>,
    vault: prism_core::model::Vault,
    link: Link,
    req_id: u32,
    deadline: Instant,
}

pub struct CoreChannels {
    pub rx: Receiver<CoreMsg>,
    pub self_tx: Sender<CoreMsg>,
    pub transport: Sender<TransportCommand>,
    pub ui: Sender<UiMsg>,
    pub power: Sender<PowerMsg>,
}

pub struct Core {
    rx: Receiver<CoreMsg>,
    transport: Sender<TransportCommand>,
    ui: Sender<UiMsg>,
    power: Sender<PowerMsg>,
    ctap: Sender<CtapJob>,
    store: Arc<Mutex<Store>>,
    vault_store: VaultStore,
    clock: Arc<Clock>,
    status: Arc<SharedStatus>,

    dev_priv: Zeroizing<[u8; 32]>,
    dev_pub: [u8; 32],
    initialized: bool,
    vault: Option<UnlockedVault>,
    /// Vault created by the setup wizard, persisted only after the seed words were verified.
    setup: Option<UnlockedVault>,
    settings: Settings,
    hosts: Vec<PairedHost>,
    sessions: HashMap<Link, Session>,
    pairing_deadline: Option<Instant>,
    broker: Broker,
    session_approved: HashSet<approval::SessionKey>,
    import: Option<ImportBuf>,
    export: Option<Zeroizing<Vec<u8>>>,
    /// Client that started the in-flight export/import: only it may fetch/send chunks, and only
    /// its close (not any other channel's) discards the buffers.
    transfer_owner: Option<Link>,
    /// The "still waiting" reminder sound was played for the active approval.
    approval_reminded: bool,
    /// The vault being set up uses the eFuse-hardened PIN slot.
    setup_hardened: bool,
    pending_replace: Option<PendingReplace>,
    /// Consecutive wrong recovery passphrases over the wire; throttles guessing.
    pp_fails: u8,
    pp_locked_until: Option<Instant>,
    rng: EspRng,
    mode: Mode,
    /// CTAP requests handed to the worker and not yet answered.
    ctap_inflight: Vec<CtapOrigin>,
    /// In-flight CTAP requests the host cancelled: answer KEEPALIVE_CANCEL when they finish.
    ctap_cancelled: Vec<CtapOrigin>,
}

/// Start the core actor thread.
/// Play the reminder sound this long before an approval auto-denies.
const APPROVAL_REMINDER_BEFORE: Duration = Duration::from_secs(10);

pub fn start(
    ch: CoreChannels,
    store: Arc<Mutex<Store>>,
    vault_store: VaultStore,
    clock: Arc<Clock>,
    status: Arc<SharedStatus>,
) -> anyhow::Result<()> {
    let ctap = ctap::spawn(ch.self_tx.clone())?;
    // Device key generation needs the radio up for real entropy: call after `transport::start`.
    let (dev_priv, dev_pub) = store.lock().unwrap().device_keypair()?;
    let (settings, hosts) = {
        let s = store.lock().unwrap();
        (s.settings(), s.hosts())
    };
    let initialized = vault_store.exists();
    let core = Core {
        rx: ch.rx,
        transport: ch.transport,
        ui: ch.ui,
        power: ch.power,
        ctap,
        store,
        vault_store,
        clock,
        status,
        dev_priv,
        dev_pub,
        initialized,
        vault: None,
        setup: None,
        settings,
        hosts,
        sessions: HashMap::new(),
        pairing_deadline: None,
        broker: Broker::default(),
        session_approved: HashSet::new(),
        import: None,
        export: None,
        transfer_owner: None,
        approval_reminded: false,
        setup_hardened: false,
        pending_replace: None,
        pp_fails: 0,
        pp_locked_until: None,
        rng: EspRng,
        mode: Mode::Pin,
        ctap_inflight: Vec::new(),
        ctap_cancelled: Vec::new(),
    };
    std::thread::Builder::new().name("core".into()).stack_size(32 * 1024).spawn(move || core.run())?;
    Ok(())
}

impl Core {
    // ---- plumbing ------------------------------------------------------------------------

    fn store(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap()
    }

    pub(crate) fn ui(&self, ev: UiEvent) {
        let _ = self.ui.send(UiMsg::Event(ev));
    }

    fn power(&self, m: PowerMsg) {
        let _ = self.power.send(m);
    }

    fn tx(&self, c: TransportCommand) {
        let _ = self.transport.send(c);
    }

    pub(crate) fn set_mode(&mut self, m: Mode) {
        self.mode = m;
        self.power(PowerMsg::Mode(m));
    }

    fn activity(&self) {
        self.power(PowerMsg::Activity);
    }

    fn sound(&self, s: crate::sound::Sound) {
        crate::sound::play(s);
    }

    fn now(&self) -> u64 {
        self.clock.now()
    }

    fn counts(&self) -> Counts {
        use prism_core::model::EntryKind::*;
        let mut c = Counts::default();
        if let Some(v) = &self.vault {
            for e in &v.vault.entries {
                match e.kind() {
                    Password => c.passwords += 1,
                    Totp => c.totp += 1,
                    Passkey => c.passkeys += 1,
                    SshKey => c.ssh += 1,
                    RecoveryCodes => c.recovery += 1,
                }
            }
        }
        c
    }

    fn battery(&self) -> (u8, bool) {
        (self.status.battery_pct.load(Ordering::Relaxed), self.status.charging.load(Ordering::Relaxed))
    }

    // ---- main loop -----------------------------------------------------------------------

    fn run(mut self) {
        self.boot();
        loop {
            // Locked standby: wake rarely (light sleep); everything relevant arrives as a message.
            let mut wait = if self.vault.is_none() && self.mode == Mode::LockScreen {
                Duration::from_secs(10)
            } else {
                Duration::from_secs(1)
            };
            let now = Instant::now();
            let reminder = (!self.approval_reminded)
                .then(|| self.broker.deadline().map(|d| d - APPROVAL_REMINDER_BEFORE))
                .flatten();
            for d in [self.broker.deadline(), reminder, self.pairing_deadline, self.pending_replace.as_ref().map(|p| p.deadline)]
                .into_iter()
                .flatten()
            {
                wait = wait.min(d.saturating_duration_since(now));
            }
            match self.rx.recv_timeout(wait.max(Duration::from_millis(5))) {
                Ok(m) => self.handle(m),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    log::error!("core: all senders gone, exiting");
                    return;
                }
            }
            self.housekeeping();
            if !self.approval_reminded {
                if let Some(d) = self.broker.deadline() {
                    if Instant::now() + APPROVAL_REMINDER_BEFORE >= d {
                        self.approval_reminded = true;
                        self.sound(crate::sound::Sound::Reminder);
                    }
                }
            }
        }
    }

    fn boot(&mut self) {
        let fails = self.store().pin_fails();
        let (pct, charging) = self.battery();
        let ent = self.rng.next_u64();
        self.ui(UiEvent::Entropy(ent));
        self.ui(UiEvent::Options(prism_ui::UiOptions { shuffle_pin: true }));
        self.ui(UiEvent::SettingsLoaded(self.settings.clone()));
        self.ui(UiEvent::PairedHosts(self.hosts.clone()));
        self.ui(UiEvent::Battery { pct, charging });
        self.ui(UiEvent::Connectivity {
            ble: self.status.ble.load(Ordering::Relaxed),
            usb: self.status.usb_cfg.load(Ordering::Relaxed),
        });
        self.power(PowerMsg::Settings(self.settings.clone()));
        crate::sound::set_enabled(self.settings.buzzer);
        self.sound(crate::sound::Sound::PowerOn);
        if self.initialized && fails >= 3 {
            self.ui(UiEvent::ShowPin { attempts_left: Some(crate::storage::MAX_PIN_FAILS.saturating_sub(fails)) });
        } else {
            self.ui(UiEvent::BootComplete { initialized: self.initialized });
        }
        self.set_mode(if self.initialized { Mode::Pin } else { Mode::Setup });
        log::info!("core up: initialized={} hosts={}", self.initialized, self.hosts.len());
    }

    fn handle(&mut self, m: CoreMsg) {
        match m {
            CoreMsg::Transport(ev) => self.on_transport(ev),
            CoreMsg::Ui(a) => self.on_ui_action(a),
            CoreMsg::WakeToPin => {
                if self.initialized && self.vault.is_none() {
                    let fails = self.store().pin_fails();
                    self.ui(UiEvent::ShowPin {
                        attempts_left: (fails >= 3).then(|| crate::storage::MAX_PIN_FAILS.saturating_sub(fails)),
                    });
                    self.set_mode(Mode::Pin);
                    self.activity();
                }
            }
            CoreMsg::AutoLock | CoreMsg::ButtonLock => {
                if self.initialized {
                    self.lock();
                }
            }
            CoreMsg::PowerOffRequest => {
                if self.initialized {
                    self.lock();
                }
                self.power(PowerMsg::ForceOff);
            }
            CoreMsg::Platform(op) => self.on_platform(op),
            CoreMsg::CtapResult { reply, response } => match reply {
                CtapReply::Transport(origin) => {
                    self.ctap_inflight.retain(|o| *o != origin);
                    let response = if let Some(i) = self.ctap_cancelled.iter().position(|o| *o == origin) {
                        self.ctap_cancelled.remove(i);
                        vec![CTAP_ERR_KEEPALIVE_CANCEL]
                    } else {
                        response
                    };
                    self.tx(TransportCommand::CtapResponse { origin, response })
                }
                CtapReply::Prism { link, id } => self.reply(link, id, Response::Ctap(response)),
            },
        }
    }

    fn housekeeping(&mut self) {
        let now = Instant::now();
        if self.broker.deadline().is_some_and(|d| now >= d) {
            self.approval_resolve(approval::Outcome::Timeout);
        }
        if self.pairing_deadline.is_some_and(|d| now >= d) {
            self.end_pairing(false);
        }
        if self.pending_replace.as_ref().is_some_and(|p| now >= p.deadline) {
            if let Some(p) = self.pending_replace.take() {
                self.reply(p.link, p.req_id, Response::Error(ErrorCode::Timeout));
                let c = self.counts();
                self.ui(UiEvent::Unlocked(c));
                self.set_mode(Mode::Unlocked);
            }
        }
    }

    // ---- transport events ----------------------------------------------------------------

    fn on_transport(&mut self, ev: TransportEvent) {
        match ev {
            TransportEvent::PrismFrame { link, frame } => self.on_frame(link, frame),
            TransportEvent::PrismClosed { link } => self.on_closed(link),
            TransportEvent::CtapRequest { origin, request } => self.on_ctap(origin, request),
            TransportEvent::CtapCancel { origin } => self.on_ctap_cancel(origin),
            TransportEvent::Wink => self.sound(crate::sound::Sound::Wink),
            TransportEvent::BlePasskeyDisplay { passkey } => {
                self.activity();
                self.ui(UiEvent::PairingSas { host: "Bluetooth".into(), sas: format!("{:06}", passkey % 1_000_000) });
            }
            TransportEvent::BlePairingFinished { success } => {
                self.ui(UiEvent::PairingFinished { ok: success });
            }
            TransportEvent::BleConnected(c) => {
                self.status.ble.store(c, Ordering::Relaxed);
                self.link_changed();
                if c && self.initialized && self.vault.is_none() {
                    // LightSleep mode: a connecting host wants in. Show the PIN pad if we were dark.
                    self.wake_if_lock_screen();
                }
            }
            TransportEvent::UsbConfigured(c) => {
                self.status.usb_cfg.store(c, Ordering::Relaxed);
                self.link_changed();
            }
        }
    }

    fn link_changed(&mut self) {
        self.ui(UiEvent::Connectivity {
            ble: self.status.ble.load(Ordering::Relaxed),
            usb: self.status.usb_cfg.load(Ordering::Relaxed),
        });
    }

    fn on_ctap(&mut self, origin: CtapOrigin, request: Vec<u8>) {
        self.activity();
        // GetInfo (0x04) is harmless and works locked; everything else needs an unlocked vault.
        if self.vault.is_none() && request.first() != Some(&prism_ctap::auth::CMD_GET_INFO) {
            self.tx(TransportCommand::CtapResponse { origin, response: vec![prism_ctap::auth::status::NOT_ALLOWED] });
            self.wake_if_lock_screen();
            return;
        }
        let job = CtapJob { reply: CtapReply::Transport(origin), request };
        self.ctap_inflight.push(origin);
        if self.ctap.send(job).is_err() {
            self.ctap_inflight.retain(|o| *o != origin);
            self.tx(TransportCommand::CtapResponse { origin, response: vec![prism_ctap::auth::status::OTHER] });
        }
    }

    fn on_ctap_cancel(&mut self, origin: CtapOrigin) {
        if !self.ctap_inflight.contains(&origin) {
            // Nothing outstanding: still answer so the transport channel is released.
            self.tx(TransportCommand::CtapResponse { origin, response: vec![CTAP_ERR_KEEPALIVE_CANCEL] });
            return;
        }
        if !self.ctap_cancelled.contains(&origin) {
            self.ctap_cancelled.push(origin);
        }
        if let Some((p, _)) = &self.broker.active {
            if matches!(p.done, approval::Done::Ctap { link, .. } if link == origin.link) {
                self.approval_resolve(approval::Outcome::Cancelled);
            }
        }
    }

    fn wake_if_lock_screen(&mut self) {
        if self.mode != Mode::LockScreen {
            return;
        }
        let fails = self.store().pin_fails();
        self.ui(UiEvent::ShowPin {
            attempts_left: (fails >= 3).then(|| crate::storage::MAX_PIN_FAILS.saturating_sub(fails)),
        });
        self.set_mode(Mode::Pin);
    }

    // ---- Noise sessions & pairing ------------------------------------------------------------

    fn on_frame(&mut self, link: Link, frame: Vec<u8>) {
        // A new handshake (msg1) on a link that already has a session: start over for the new
        // client. On macOS the Prism app and its AutoFill extension share ONE BLE link to the
        // device (CoreBluetooth multiplexes processes), so the device cannot tell them apart;
        // the newest client wins and the other reconnects when it next needs the device.
        if frame.first() == Some(&prism_proto::frame::HANDSHAKE) {
            if let Some(old) = self.sessions.get(&link) {
                // msg1 of Noise XX = the 32-byte ephemeral key only (msg3 is longer and belongs to
                // the in-progress handshake, so it must not reset it).
                let is_msg1 = frame.len() == 1 + 32;
                if old.ds.is_established() || is_msg1 {
                    log::info!("{link:?}: new handshake replaces the existing session");
                    self.on_closed(link);
                }
            }
        }
        if !self.sessions.contains_key(&link) {
            if self.sessions.len() >= MAX_SESSIONS {
                if let Some(lru) = self.sessions.iter().min_by_key(|(_, s)| s.last).map(|(l, _)| *l) {
                    log::info!("{lru:?}: session limit reached, evicting least recently used");
                    self.on_closed(lru);
                }
            }
            match DeviceSession::new(&self.dev_priv) {
                Ok(ds) => {
                    self.sessions.insert(link, Session { ds, auth: Auth::Handshaking, label: String::new(), last: Instant::now() });
                }
                Err(e) => {
                    log::error!("noise init failed: {e}");
                    return;
                }
            }
        }
        let ev = match self.sessions.get_mut(&link) {
            Some(s) => {
                s.last = Instant::now();
                s.ds.on_frame(&frame)
            }
            None => return,
        };
        match ev {
            Ok(DeviceEvent::SendFrame(f)) => self.tx(TransportCommand::PrismFrame { link, frame: f }),
            Ok(DeviceEvent::Established { remote_static }) => self.on_established(link, remote_static),
            Ok(DeviceEvent::Request(env)) => self.on_session_request(link, env),
            Ok(DeviceEvent::Unknown { id }) => {
                log::warn!("{link:?}: request {id} not supported by this firmware");
                self.reply(link, id, Response::Error(ErrorCode::Unsupported));
            }
            Err(e) => {
                log::warn!("{link:?}: bad frame: {e}");
                if let Some(s) = self.sessions.remove(&link) {
                    let pe = ProtoError { code: ErrorCode::InvalidRequest, message: "bad frame".into() };
                    if let Ok(f) = s.ds.plain_error(&pe) {
                        self.tx(TransportCommand::PrismFrame { link, frame: f });
                    }
                }
            }
        }
    }

    fn on_established(&mut self, link: Link, key: [u8; 32]) {
        let now = self.now();
        let link_name = link_name(link);
        let known = self.hosts.iter_mut().find(|h| h.public_key == key).map(|h| {
            h.last_seen = now;
            h.label.clone()
        });
        let pairing = self.pairing_deadline.is_some();
        let Some(s) = self.sessions.get_mut(&link) else { return };
        match known {
            Some(label) => {
                s.label = format!("{label} ({link_name})");
                s.auth = Auth::Ready { key };
                log::info!("{link:?}: host '{label}' connected");
            }
            None if pairing => {
                let sas = s.ds.sas().unwrap_or_else(|| "??????".into());
                s.label = format!("{} ({link_name})", host_label(&key));
                s.auth = Auth::PairPending { key, confirmed: None, first_req: None };
                let host = s.label.clone();
                self.activity();
                self.sound(crate::sound::Sound::Attention);
                self.ui(UiEvent::PairingSas { host, sas });
            }
            None => {
                log::info!("{link:?}: unknown host rejected (not in pairing mode)");
                s.auth = Auth::Rejected;
            }
        }
    }

    fn on_closed(&mut self, link: Link) {
        if let Some(s) = self.sessions.remove(&link) {
            if matches!(s.auth, Auth::PairPending { confirmed: None, .. }) {
                self.end_pairing(false);
            }
        }
        // Drop approvals that were waiting on this link.
        if matches!(&self.broker.active, Some((p, _)) if p.done.link() == link) {
            self.approval_resolve(approval::Outcome::Cancelled);
        }
        self.broker.queue.retain(|p| p.done.link() != link);
        if self.transfer_owner == Some(link) {
            self.export = None;
            self.import = None;
            self.transfer_owner = None;
        }
    }

    pub(crate) fn reply(&mut self, link: Link, id: u32, body: Response) {
        if matches!(body, Response::Error(ErrorCode::Locked)) && self.mode == Mode::LockScreen {
            // A paired app needs the vault while we are in standby: wake to the PIN pad.
            self.sound(crate::sound::Sound::Attention);
            self.wake_if_lock_screen();
        }
        let Some(s) = self.sessions.get_mut(&link) else {
            log::debug!("reply for closed {link:?} session dropped");
            return;
        };
        let env = Envelope { id, body };
        let frame = match s.ds.encrypt_response(&env) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("encrypt response failed: {e}");
                match s.ds.encrypt_response(&Envelope { id, body: Response::Error(ErrorCode::Internal) }) {
                    Ok(f) => f,
                    Err(_) => return,
                }
            }
        };
        let _ = self.transport.send(TransportCommand::PrismFrame { link, frame });
    }

    fn on_session_request(&mut self, link: Link, env: Envelope<prism_proto::Request>) {
        self.activity();
        let id = env.id;
        let Some(s) = self.sessions.get_mut(&link) else { return };
        match &mut s.auth {
            Auth::Ready { .. } => self.dispatch(link, id, env.body),
            Auth::Handshaking => self.reply(link, id, Response::Error(ErrorCode::InvalidRequest)),
            Auth::Rejected => {
                self.reply(link, id, Response::Error(ErrorCode::NotPaired));
                self.sessions.remove(&link);
            }
            Auth::PairPending { confirmed, first_req, .. } => match *confirmed {
                Some(true) => {
                    *first_req = Some(id);
                    self.finish_pairing(link);
                }
                Some(false) => {
                    self.reply(link, id, Response::Error(ErrorCode::NotPaired));
                    self.sessions.remove(&link);
                }
                None if first_req.is_none() => *first_req = Some(id),
                None => self.reply(link, id, Response::Error(ErrorCode::Busy)),
            },
        }
    }

    pub(crate) fn start_pairing(&mut self) {
        self.pairing_deadline = Some(Instant::now() + PAIRING_TIMEOUT);
        self.tx(TransportCommand::SetBondingAllowed(true));
        log::info!("pairing mode on");
    }

    /// Leave pairing mode. `ok` only controls what the UI is told when a handshake was pending.
    pub(crate) fn end_pairing(&mut self, ok: bool) {
        if self.pairing_deadline.take().is_none() {
            return;
        }
        self.tx(TransportCommand::SetBondingAllowed(false));
        if !ok {
            self.sound(crate::sound::Sound::Denied);
        }
        self.ui(UiEvent::PairingFinished { ok });
        // Reject any host still waiting.
        let waiting: Vec<(Link, u32)> = self
            .sessions
            .iter()
            .filter_map(|(l, s)| match s.auth {
                Auth::PairPending { first_req: Some(id), .. } => Some((*l, id)),
                _ => None,
            })
            .collect();
        for (l, id) in waiting {
            self.reply(l, id, Response::Error(ErrorCode::NotPaired));
            self.sessions.remove(&l);
        }
        for s in self.sessions.values_mut() {
            if matches!(s.auth, Auth::PairPending { .. }) {
                s.auth = Auth::Rejected;
            }
        }
    }

    /// UI: user compared the SAS.
    pub(crate) fn confirm_pairing(&mut self, ok: bool) {
        if !ok {
            self.end_pairing(false);
            return;
        }
        let pending = self.sessions.iter_mut().find_map(|(l, s)| match &mut s.auth {
            Auth::PairPending { confirmed, first_req, .. } => {
                *confirmed = Some(true);
                Some((*l, *first_req))
            }
            _ => None,
        });
        match pending {
            Some((link, Some(_))) => self.finish_pairing(link),
            Some((_, None)) => {} // host has not sent its first request yet; finish on arrival
            None => self.end_pairing(false),
        }
    }

    fn finish_pairing(&mut self, link: Link) {
        let Some(s) = self.sessions.get_mut(&link) else { return };
        let Auth::PairPending { key, first_req, .. } = s.auth else { return };
        let Some(req_id) = first_req else { return };
        if self.hosts.len() >= crate::storage::MAX_PAIRED_HOSTS {
            self.reply(link, req_id, Response::Error(ErrorCode::StorageFull));
            self.sessions.remove(&link);
            self.end_pairing(false);
            return;
        }
        let now = self.now();
        let label = host_label(&key);
        let host = PairedHost { public_key: key, label: label.clone(), paired_at: now, last_seen: now };
        self.hosts.retain(|h| h.public_key != key);
        self.hosts.push(host);
        if let Err(e) = self.store().set_hosts(&self.hosts) {
            log::error!("saving paired hosts failed: {e:#}");
        }
        if let Some(s) = self.sessions.get_mut(&link) {
            s.auth = Auth::Ready { key };
            s.label = format!("{label} ({})", link_name(link));
        }
        self.reply(link, req_id, Response::Paired { label });
        self.end_pairing(true);
        self.ui(UiEvent::PairedHosts(self.hosts.clone()));
        self.sound(crate::sound::Sound::Success);
    }
}

pub(crate) fn link_name(l: Link) -> &'static str {
    match l {
        Link::Ble { .. } => "BLE",
        Link::Usb => "USB",
    }
}

fn host_label(key: &[u8; 32]) -> String {
    format!("Host {:02x}{:02x}", key[0], key[1])
}
