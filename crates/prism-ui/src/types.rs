//! Public event/action types of the UI state machine.

use embedded_graphics::primitives::Rectangle;
use prism_core::model::{EntryId, EntryKind, EntrySummary, PairedHost, RecoveryCode, SecretField, SecretValue, Settings};
use zeroize::Zeroizing;

/// Touch in LOGICAL coordinates (use `Rotation::touch_to_logical` on raw panel coordinates).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchEvent {
    Down { x: i32, y: i32 },
    Up { x: i32, y: i32 },
}

/// How the firmware should refresh the panel after `handle`/`draw`. Rectangles are in PANEL
/// (physical 960x540) coordinates, ready for `EinkDisplay::refresh`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshMode {
    /// Full GC16 refresh (clears ghosting). Used on screen changes and every 8th partial.
    Full,
    /// Fast partial refresh of a region (key press feedback).
    Partial(Rectangle),
    /// GL16 whole-screen text refresh (clock/code updates without flashing).
    Text,
    /// Fastest partial refresh (DU) of a region whose changed pixels are pure black/white
    /// only (PIN dots). Never escalated to a full refresh while typing.
    Fast(Rectangle),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalKind {
    Password,
    Totp,
    PasskeyRegister,
    PasskeyAuth,
    SshSign,
    RecoveryCodes,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub id: u32,
    pub kind: ApprovalKind,
    /// Paired host label asking, e.g. "alice-laptop (BLE)".
    pub requester: String,
    /// Entry title.
    pub title: String,
    /// Extra context: SSH host, relying party id, URL...
    pub context: String,
    /// Seconds until auto-deny.
    pub timeout_secs: u32,
}

/// Number of entries per category (Home tiles).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub passwords: u32,
    pub totp: u32,
    pub passkeys: u32,
    pub ssh: u32,
    pub recovery: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetailField {
    pub label: String,
    pub value: String,
}

/// Non-secret data for a Detail screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetailInfo {
    pub summary: EntrySummary,
    pub fields: Vec<DetailField>,
    /// Secret that the "Reveal" button asks for (None = no reveal button).
    pub reveal: Option<SecretField>,
    /// Show "Type via USB" (needs USB host attached).
    pub can_type: bool,
}

pub struct TotpView {
    pub id: EntryId,
    pub issuer: String,
    pub account: String,
    pub code: Zeroizing<String>,
    pub next: Option<Zeroizing<String>>,
    pub remaining_secs: u32,
    pub period: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UiOptions {
    /// Shuffle the PIN pad digits on every entry (shoulder-surfing / smudge protection).
    pub shuffle_pin: bool,
}

pub enum UiEvent {
    Touch(TouchEvent),
    /// ~1 Hz clock tick with the current UNIX time (UTC). Drives clock, countdowns, TOTP refresh.
    Tick { unix: u64 },
    /// Mix real entropy in (PIN shuffle, setup quiz). Send once at boot, optionally periodically.
    Entropy(u64),
    Battery { pct: u8, charging: bool },
    Connectivity { ble: bool, usb: bool },
    SettingsLoaded(Settings),
    PairedHosts(Vec<PairedHost>),
    Options(UiOptions),

    /// Boot finished: leave the splash. `initialized == false` starts the setup wizard.
    BootComplete { initialized: bool },
    /// Show the PIN pad (e.g. wake button pressed on the lock screen, or BLE connect in LightSleep).
    ShowPin { attempts_left: Option<u8> },
    PinRejected { attempts_left: u8 },
    /// Device is now locked: zeroize everything, show the Lock screen.
    Locked { battery_pct: u8, last_used: Option<u64> },
    /// PIN accepted / setup finished: go to Home.
    Unlocked(Counts),
    Counts(Counts),

    /// Answer to `UiAction::OpenList`.
    EntryList { kind: EntryKind, entries: Vec<EntrySummary> },
    /// Answer to `UiAction::OpenEntry`.
    EntryDetail(DetailInfo),
    /// Answer to `RevealSecret`. Cleared when leaving the detail screen.
    SecretRevealed { id: EntryId, field: SecretField, value: SecretValue },
    /// Answer to `RevealSecret(.., RecoveryCodes)`: codes with used flags.
    RecoveryCodes { id: EntryId, codes: Vec<RecoveryCode> },
    /// Answer to `RequestTotp`.
    Totp(TotpView),

    Approval(ApprovalRequest),
    /// The requester went away / host cancelled.
    ApprovalCancelled(u32),
    /// Pairing SAS to compare on both sides.
    PairingSas { host: String, sas: String },
    PairingFinished { ok: bool },

    /// 24 BIP39 words for the setup wizard (answer to `SetupPin`).
    SetupSeed { words: Zeroizing<Vec<String>> },
    /// Show a toast/modal message.
    Message { text: String, error: bool },
}

pub enum UiAction {
    /// Input rejected locally (e.g. OK with a too-short PIN): give feedback (error beep).
    InvalidInput,
    /// Any user interaction (reset idle timer).
    Activity,
    SubmitPin(Zeroizing<String>),
    /// Setup wizard: PIN chosen and confirmed twice. Firmware answers with `UiEvent::SetupSeed`.
    SetupPin(Zeroizing<String>),
    /// Setup wizard: user verified the seed words. Firmware persists and answers `Unlocked`.
    SetupConfirmedSeed,
    Approve(u32),
    Deny(u32),
    /// Home tile / category tapped: answer with `EntryList`.
    OpenList(EntryKind),
    /// Row tapped (non-TOTP): answer with `EntryDetail`.
    OpenEntry(EntryId),
    RevealSecret(EntryId, SecretField),
    TypeEntry(EntryId, SecretField),
    /// Type the current TOTP code over USB.
    TypeTotp(EntryId),
    /// Ask for a TOTP code (on entering and at each period boundary): answer with `Totp`.
    RequestTotp(EntryId),
    Lock,
    PowerOff,
    StartPairing,
    /// true = SAS matches, false = cancel pairing.
    ConfirmPairing(bool),
    ChangeSettings(Settings),
    RemovePairedHost([u8; 32]),
    /// Fully confirmed (two steps) wipe request.
    Wipe,
}
