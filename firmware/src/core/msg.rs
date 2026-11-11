//! Message types exchanged between the core actor, UI task, power manager and CTAP worker.
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::mpsc::SyncSender;

use prism_core::model::Settings;
use prism_ctap::{PasskeyCredential, PresenceRequest, PresenceResult, StorageError};
use prism_ui::{UiAction, UiEvent};

use crate::transport::{CtapOrigin, Link, TransportEvent};

/// Everything the core actor reacts to.
pub enum CoreMsg {
    Transport(TransportEvent),
    /// Action from the on-device UI.
    Ui(UiAction),
    /// Touch / button on the lock screen: show the PIN pad.
    WakeToPin,
    /// Power manager: idle timeout elapsed.
    AutoLock,
    /// BOOT button short press while unlocked/PIN screen.
    ButtonLock,
    /// BOOT button long press: lock, then power off.
    PowerOffRequest,
    /// Synchronous platform call from the CTAP worker.
    Platform(PlatformOp),
    /// CTAP worker finished a request.
    CtapResult { reply: CtapReply, response: Vec<u8> },
}

#[derive(Clone, Copy, Debug)]
pub enum CtapReply {
    /// Answer via `TransportCommand::CtapResponse`.
    Transport(CtapOrigin),
    /// Answer via `Response::Ctap` on a Prism session.
    Prism { link: Link, id: u32 },
}

impl CtapReply {
    pub fn link(&self) -> Link {
        match self {
            CtapReply::Transport(o) => o.link,
            CtapReply::Prism { link, .. } => *link,
        }
    }
}

pub struct CtapJob {
    pub reply: CtapReply,
    pub request: Vec<u8>,
}

pub enum PlatformOp {
    SeedKey { info: Vec<u8>, reply: SyncSender<Option<[u8; 32]>> },
    FindResident { rp_id: String, reply: SyncSender<Vec<PasskeyCredential>> },
    Store { cred: PasskeyCredential, reply: SyncSender<Result<(), StorageError>> },
    Delete { cred_id: Vec<u8>, reply: SyncSender<Result<(), StorageError>> },
    Reset { reply: SyncSender<Result<(), StorageError>> },
    Presence { req: PresenceRequest, link: Link, reply: SyncSender<PresenceResult> },
}

/// Messages for the UI task (which owns the panel and touch controller).
pub enum UiMsg {
    Event(UiEvent),
    /// From the touch thread: raw controller coordinates (mapped to logical by the UI task).
    Touch { down: bool, x: u16, y: u16 },
    /// Power the panel rails down (image stays) and acknowledge.
    PanelOff(SyncSender<()>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// No vault yet / setup wizard: never auto-lock or power off.
    Setup,
    /// Lock screen is (being) shown.
    LockScreen,
    /// PIN pad shown (locked).
    Pin,
    Unlocked,
}

pub enum PowerMsg {
    Activity,
    Mode(Mode),
    /// UI finished the full refresh of the lock screen.
    LockScreenDrawn,
    /// Power off as soon as the lock screen is on the panel.
    ForceOff,
    Settings(Settings),
}

/// Lock-free state shared between threads (written by power manager / core, read anywhere).
pub struct SharedStatus {
    pub battery_pct: AtomicU8,
    pub charging: AtomicBool,
    pub usb_power: AtomicBool,
    pub ble: AtomicBool,
    pub usb_cfg: AtomicBool,
}

impl SharedStatus {
    pub fn new() -> Self {
        Self {
            battery_pct: AtomicU8::new(100),
            charging: AtomicBool::new(false),
            usb_power: AtomicBool::new(false),
            ble: AtomicBool::new(false),
            usb_cfg: AtomicBool::new(false),
        }
    }
}
