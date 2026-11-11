//! The UI state machine.

use crate::gfx::*;
use crate::layout::*;
use crate::types::*;
use embedded_graphics::{prelude::*, primitives::Rectangle};
use prism_core::model::*;
use zeroize::Zeroizing;

pub const MIN_PIN: usize = 4;
pub const MIN_SETUP_PIN: usize = 6;
pub const MAX_PIN: usize = 12;

#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub battery: u8,
    pub charging: bool,
    pub ble: bool,
    pub usb: bool,
    pub locked: bool,
    pub unix: u64,
    pub tz_secs: i32,
}

pub struct PinState {
    pub entry: Zeroizing<String>,
    pub attempts_left: Option<u8>,
    pub digits: [u8; 10],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStep {
    ChoosePin,
    ConfirmPin,
    WaitSeed,
    Seed(usize),
    Verify(usize),
    Saving,
}

pub struct Quiz {
    pub word_index: usize,
    pub choices: [usize; 4],
    pub correct: usize,
}

pub struct Setup {
    pub step: SetupStep,
    pub first: Zeroizing<String>,
    pub entry: Zeroizing<String>,
    pub words: Zeroizing<Vec<String>>,
    pub quiz: Vec<Quiz>,
    pub digits: [u8; 10],
}

pub enum Revealed {
    Secret(SecretValue),
    Codes(Vec<RecoveryCode>),
}

pub struct Detail {
    pub info: DetailInfo,
    pub revealed: Option<Revealed>,
}

pub struct TotpState {
    pub id: EntryId,
    pub issuer: String,
    pub account: String,
    pub data: Option<TotpData>,
}

pub struct TotpData {
    pub code: Zeroizing<String>,
    pub next: Option<Zeroizing<String>>,
    pub period: u32,
    pub expires: u64,
}

pub struct ApprovalState {
    pub req: ApprovalRequest,
    pub deadline: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmKind {
    RemoveHost(usize),
    Wipe1,
    Wipe2,
}

pub enum Screen {
    Splash,
    Lock { battery: u8, last_used: Option<u64> },
    Pin(PinState),
    Setup(Setup),
    Home,
    List { kind: EntryKind, entries: Vec<EntrySummary>, page: usize },
    Detail(Detail),
    Totp(TotpState),
    Approval(ApprovalState),
    PairWait,
    PairSas { host: String, sas: String },
    Settings { page: usize },
    Confirm(ConfirmKind),
    Message { text: String, error: bool },
}

#[derive(Clone, Copy, Debug)]
enum Hint {
    /// Changed pixels are black/white only (DU-safe).
    Fast(Rectangle),
    Partial(Rectangle),
    Text,
    Full,
}

pub struct Ui {
    pub options: UiOptions,
    pub(crate) settings: Settings,
    pub(crate) hosts: Vec<PairedHost>,
    pub(crate) counts: Counts,
    pub(crate) status: Status,
    pub(crate) screen: Screen,
    /// Screens underneath the current one (back navigation, overlays).
    pub(crate) stack: Vec<Screen>,
    pub(crate) pressed: Option<Id>,
    pub(crate) now: u64,
    rng: u64,
    hint: Option<Hint>,
    partial_count: u8,
    /// Screen changes refreshed with GL16 since the last full GC16 refresh.
    screen_changes: u8,
    /// A secret (password, codes, TOTP, seed words) was on screen: the next screen change must be
    /// a full GC16 refresh so no ghost of it stays on the panel.
    secret_shown: bool,
}

fn default_digits() -> [u8; 10] {
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
}

impl Default for Ui {
    fn default() -> Self {
        Self::new()
    }
}

impl Ui {
    pub fn new() -> Self {
        Ui {
            options: UiOptions::default(),
            settings: Settings::default(),
            hosts: Vec::new(),
            counts: Counts::default(),
            status: Status { battery: 100, charging: false, ble: false, usb: false, locked: false, unix: 0, tz_secs: 0 },
            screen: Screen::Splash,
            stack: Vec::new(),
            pressed: None,
            now: 0,
            rng: 0x9E37_79B9_7F4A_7C15,
            hint: Some(Hint::Full),
            partial_count: 0,
            screen_changes: 0,
            secret_shown: false,
        }
    }

    /// Time zone offset (seconds east of UTC) used for the clock.
    pub fn set_tz_offset(&mut self, secs: i32) {
        self.status.tz_secs = secs;
    }

    pub fn rotation(&self) -> Rotation {
        match self.settings.orientation {
            Orientation::Portrait => Rotation::Portrait,
            Orientation::Landscape => Rotation::Landscape,
        }
    }

    /// Logical drawing size (540x960 portrait / 960x540 landscape).
    pub fn size(&self) -> Size {
        self.rotation().logical_size()
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Screen name, handy for logs and tests.
    pub fn screen_name(&self) -> &'static str {
        match &self.screen {
            Screen::Splash => "splash",
            Screen::Lock { .. } => "lock",
            Screen::Pin(_) => "pin",
            Screen::Setup(_) => "setup",
            Screen::Home => "home",
            Screen::List { .. } => "list",
            Screen::Detail(_) => "detail",
            Screen::Totp(_) => "totp",
            Screen::Approval(_) => "approval",
            Screen::PairWait => "pair_wait",
            Screen::PairSas { .. } => "pair_sas",
            Screen::Settings { .. } => "settings",
            Screen::Confirm(_) => "confirm",
            Screen::Message { .. } => "message",
        }
    }

    pub fn setup_step(&self) -> Option<SetupStep> {
        match &self.screen {
            Screen::Setup(s) => Some(s.step),
            _ => None,
        }
    }

    /// Screen is dirty and needs a refresh.
    pub fn needs_refresh(&self) -> bool {
        self.hint.is_some()
    }

    /// Peek at the pending refresh without consuming it (panel coordinates).
    pub fn peek_refresh_hint(&self) -> Option<RefreshMode> {
        self.hint.map(|h| match h {
            Hint::Full => RefreshMode::Full,
            Hint::Text => RefreshMode::Text,
            Hint::Partial(r) => RefreshMode::Partial(self.rotation().rect_to_panel(r)),
            Hint::Fast(r) => RefreshMode::Fast(self.rotation().rect_to_panel(r)),
        })
    }

    /// Consume the pending refresh request. Applies the policy "every 8th partial becomes full".
    /// With nothing pending returns `Partial` of an empty rectangle.
    pub fn refresh_hint(&mut self) -> RefreshMode {
        let h = self.peek_refresh_hint();
        self.hint = None;
        match h {
            None => RefreshMode::Partial(Rectangle::zero()),
            Some(RefreshMode::Full) => {
                self.partial_count = 0;
                RefreshMode::Full
            }
            Some(RefreshMode::Text) => RefreshMode::Text,
            // Not counted towards the "every 8th partial is full" policy: a full refresh flash in
            // the middle of PIN entry would cost ~1 s; the next screen change is full anyway.
            Some(RefreshMode::Fast(r)) => RefreshMode::Fast(r),
            // PIN pads: no full-refresh flash in the middle of typing (see `Fast` above).
            Some(RefreshMode::Partial(r)) if self.on_pin_pad() => RefreshMode::Partial(r),
            Some(RefreshMode::Partial(r)) => {
                self.partial_count += 1;
                if self.partial_count >= 8 {
                    self.partial_count = 0;
                    RefreshMode::Full
                } else {
                    RefreshMode::Partial(r)
                }
            }
        }
    }

    /// Screen change / large redraw. Uses the non-flashing GL16 refresh, except every
    /// `FULL_EVERY`th change (ghosting), right after a secret was displayed (no secret ghosts), and
    /// for the lock/splash screens (shown unpowered for a long time) which get a full GC16.
    fn full(&mut self) {
        const FULL_EVERY: u8 = 6;
        self.screen_changes = self.screen_changes.saturating_add(1);
        let secret = std::mem::take(&mut self.secret_shown);
        if secret || self.screen_changes >= FULL_EVERY || matches!(self.screen, Screen::Lock { .. } | Screen::Splash) {
            self.force_full();
        } else if !matches!(self.hint, Some(Hint::Full)) {
            self.hint = Some(Hint::Text);
        }
    }
    /// Unconditional full GC16 refresh (clears ghosting).
    fn force_full(&mut self) {
        self.screen_changes = 0;
        self.partial_count = 0;
        self.hint = Some(Hint::Full);
    }
    /// Mark that a secret is (about to be) visible.
    fn secret_visible(&mut self) {
        self.secret_shown = true;
    }
    fn text_refresh(&mut self) {
        if !matches!(self.hint, Some(Hint::Full)) {
            self.hint = Some(Hint::Text);
        }
    }
    fn partial(&mut self, r: Rectangle) {
        self.hint = match self.hint {
            None => Some(Hint::Partial(r)),
            Some(Hint::Partial(o)) | Some(Hint::Fast(o)) => Some(Hint::Partial(union(o, r))),
            Some(h) => Some(h),
        };
    }
    /// Like `partial`, for regions whose changes are black/white only.
    fn fast(&mut self, r: Rectangle) {
        self.hint = match self.hint {
            None => Some(Hint::Fast(r)),
            Some(Hint::Fast(o)) => Some(Hint::Fast(union(o, r))),
            Some(Hint::Partial(o)) => Some(Hint::Partial(union(o, r))),
            Some(h) => Some(h),
        };
    }
    fn status_rect(&self) -> Rectangle {
        rect(0, 0, self.size().width, STATUS_H as u32 + 2)
    }

    fn stir(&mut self, v: u64) {
        self.rng ^= v.wrapping_mul(0x2545_F491_4F6C_DD1D);
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        if self.rng == 0 {
            self.rng = 0x9E37_79B9_7F4A_7C15;
        }
    }
    fn rand(&mut self, n: usize) -> usize {
        self.stir(0);
        ((self.rng >> 11) % n as u64) as usize
    }
    fn shuffled_digits(&mut self) -> [u8; 10] {
        let mut d = default_digits();
        if self.options.shuffle_pin {
            for i in (1..10).rev() {
                let j = self.rand(i + 1);
                d.swap(i, j);
            }
        }
        d
    }

    // ---- navigation -------------------------------------------------------

    fn goto(&mut self, s: Screen) {
        self.screen = s;
        self.pressed = None;
        self.full();
    }
    fn push(&mut self, s: Screen) {
        if let Screen::Detail(d) = &mut self.screen {
            d.revealed = None; // never keep secrets in the background
        }
        let old = core::mem::replace(&mut self.screen, s);
        self.stack.push(old);
        self.pressed = None;
        self.full();
    }
    fn pop(&mut self) {
        match self.stack.pop() {
            Some(s) => self.screen = s,
            None => self.screen = Screen::Home,
        }
        self.pressed = None;
        self.full();
    }

    fn clear_all(&mut self) {
        self.stack.clear();
        self.pressed = None;
    }

    // ---- events -------------------------------------------------------------

    pub fn handle(&mut self, ev: UiEvent) -> Vec<UiAction> {
        let mut out = Vec::new();
        match ev {
            UiEvent::Touch(t) => self.touch(t, &mut out),
            UiEvent::Tick { unix } => self.tick(unix, &mut out),
            UiEvent::Entropy(v) => self.stir(v),
            UiEvent::Battery { pct, charging } => {
                if self.status.battery != pct || self.status.charging != charging {
                    self.status.battery = pct;
                    self.status.charging = charging;
                    self.status_dirty();
                }
            }
            UiEvent::Connectivity { ble, usb } => {
                if self.status.ble != ble || self.status.usb != usb {
                    self.status.ble = ble;
                    self.status.usb = usb;
                    self.status_dirty();
                }
            }
            UiEvent::SettingsLoaded(s) => {
                let rot_changed = s.orientation != self.settings.orientation;
                self.settings = s;
                if rot_changed {
                    self.full();
                }
            }
            UiEvent::PairedHosts(h) => {
                self.hosts = h;
                if matches!(self.screen, Screen::Settings { .. }) {
                    self.full();
                }
            }
            UiEvent::Options(o) => self.options = o,
            UiEvent::BootComplete { initialized } => {
                self.clear_all();
                if initialized {
                    let digits = self.shuffled_digits();
                    self.goto(Screen::Pin(PinState { entry: Zeroizing::new(String::new()), attempts_left: None, digits }));
                } else {
                    self.start_setup();
                }
            }
            UiEvent::ShowPin { attempts_left } => {
                self.clear_all();
                self.status.locked = true;
                let digits = self.shuffled_digits();
                self.goto(Screen::Pin(PinState { entry: Zeroizing::new(String::new()), attempts_left, digits }));
            }
            UiEvent::PinRejected { attempts_left } => {
                let digits = self.shuffled_digits();
                self.goto(Screen::Pin(PinState { entry: Zeroizing::new(String::new()), attempts_left: Some(attempts_left), digits }));
            }
            UiEvent::Locked { battery_pct, last_used } => {
                self.clear_all();
                self.status.locked = true;
                self.goto(Screen::Lock { battery: battery_pct, last_used });
            }
            UiEvent::Unlocked(c) => {
                self.clear_all();
                self.counts = c;
                self.status.locked = false;
                self.goto(Screen::Home);
            }
            UiEvent::Counts(c) => {
                self.counts = c;
                if matches!(self.screen, Screen::Home) {
                    self.full();
                }
            }
            UiEvent::EntryList { kind, entries } => {
                let per = self.rows_per_page();
                if let Screen::List { kind: k, entries: e, page } = &mut self.screen {
                    if *k == kind {
                        *e = entries;
                        *page = (*page).min(e.len().saturating_sub(1) / per);
                        self.full();
                        return out;
                    }
                }
                self.push(Screen::List { kind, entries, page: 0 });
            }
            UiEvent::EntryDetail(info) => {
                self.push(Screen::Detail(Detail { info, revealed: None }));
            }
            UiEvent::SecretRevealed { id, field: _, value } => {
                if let Screen::Detail(d) = &mut self.screen {
                    if d.info.summary.id == id {
                        d.revealed = Some(match &value {
                            SecretValue::List(l) => {
                                Revealed::Codes(l.iter().map(|c| RecoveryCode { code: c.clone(), used: false }).collect())
                            }
                            _ => Revealed::Secret(value),
                        });
                        self.full();
                        self.secret_visible();
                    }
                }
            }
            UiEvent::RecoveryCodes { id, codes } => {
                if let Screen::Detail(d) = &mut self.screen {
                    if d.info.summary.id == id {
                        d.revealed = Some(Revealed::Codes(codes));
                        self.full();
                        self.secret_visible();
                    }
                }
            }
            UiEvent::Totp(v) => {
                let data = TotpData {
                    code: v.code,
                    next: v.next,
                    period: v.period.max(1),
                    expires: self.now + v.remaining_secs as u64,
                };
                if let Screen::Totp(t) = &mut self.screen {
                    if t.id == v.id {
                        t.issuer = v.issuer;
                        t.account = v.account;
                        t.data = Some(data);
                        self.text_refresh();
                        self.secret_visible();
                        return out;
                    }
                }
                self.push(Screen::Totp(TotpState { id: v.id, issuer: v.issuer, account: v.account, data: Some(data) }));
                self.secret_visible();
            }
            UiEvent::Approval(req) => {
                let deadline = self.now + req.timeout_secs as u64;
                self.push(Screen::Approval(ApprovalState { req, deadline }));
            }
            UiEvent::ApprovalCancelled(id) => {
                if matches!(&self.screen, Screen::Approval(a) if a.req.id == id) {
                    self.pop();
                }
            }
            UiEvent::PairingSas { host, sas } => {
                if matches!(self.screen, Screen::PairWait) {
                    self.screen = Screen::PairSas { host, sas };
                    self.full();
                } else {
                    self.push(Screen::PairSas { host, sas });
                }
            }
            UiEvent::PairingFinished { ok } => {
                if matches!(self.screen, Screen::PairWait | Screen::PairSas { .. }) {
                    self.pop();
                    let text = if ok { "Host paired." } else { "Pairing failed." };
                    self.push(Screen::Message { text: text.into(), error: !ok });
                }
            }
            UiEvent::SetupSeed { words } => {
                if let Screen::Setup(s) = &mut self.screen {
                    s.words = words;
                    s.step = SetupStep::Seed(0);
                    s.quiz.clear();
                    self.full();
                    self.secret_visible();
                }
            }
            UiEvent::Message { text, error } => {
                self.push(Screen::Message { text, error });
            }
        }
        out
    }

    fn status_dirty(&mut self) {
        if matches!(self.screen, Screen::Splash | Screen::Lock { .. }) {
            self.full();
        } else {
            let r = self.status_rect();
            self.partial(r);
        }
    }

    fn tick(&mut self, unix: u64, out: &mut Vec<UiAction>) {
        let old_min = (self.status.unix + self.status.tz_secs as u64) / 60;
        self.now = unix;
        self.status.unix = unix;
        self.stir(unix);
        if (unix + self.status.tz_secs as u64) / 60 != old_min {
            self.status_dirty();
        }
        // Approval countdown / auto-deny
        let mut expired = None;
        let mut countdown_dirty = false;
        if let Screen::Approval(a) = &self.screen {
            let rem = a.deadline.saturating_sub(unix);
            if rem == 0 {
                expired = Some(a.req.id);
            } else if rem % 5 == 0 || rem <= 5 {
                countdown_dirty = true;
            }
        }
        if let Some(id) = expired {
            out.push(UiAction::Deny(id));
            self.pop();
        } else if countdown_dirty {
            let r = approval_countdown_rect(self.size());
            self.partial(r);
        }
        // TOTP boundaries
        let mut req = None;
        let mut bar_dirty = false;
        if let Screen::Totp(t) = &self.screen {
            if let Some(d) = &t.data {
                if unix >= d.expires {
                    req = Some(t.id);
                } else {
                    let before = totp_segments(d.period, d.expires.saturating_sub(unix.saturating_sub(1)));
                    let after = totp_segments(d.period, d.expires - unix);
                    bar_dirty = before != after;
                }
            }
        }
        if let Some(id) = req {
            out.push(UiAction::RequestTotp(id));
        }
        if bar_dirty {
            let r = totp_bar_rect(self.size());
            self.partial(r);
        }
    }

    // ---- touch --------------------------------------------------------------

    fn buttons(&self) -> Vec<Btn> {
        let mut v = Vec::new();
        collect_buttons(&self.items(), &mut v);
        v
    }

    fn hit(&self, x: i32, y: i32) -> Option<(Id, Rectangle)> {
        let p = Point::new(x, y);
        self.buttons().into_iter().find(|b| b.enabled && b.rect.contains(p)).map(|b| (b.id, b.rect))
    }

    fn touch(&mut self, t: TouchEvent, out: &mut Vec<UiAction>) {
        out.push(UiAction::Activity);
        match t {
            TouchEvent::Down { x, y } => {
                self.stir((x as u64) << 16 | y as u64);
                if let Some((id, _r)) = self.hit(x, y) {
                    // Act on touch-down, without a press highlight: on e-ink the highlight costs a
                    // whole extra refresh, and the action's own redraw is the feedback. PIN pads
                    // then refresh only their dots (DU); destructive actions have confirm screens.
                    self.pressed = None;
                    self.activate(id, out);
                } else {
                    self.pressed = None;
                }
            }
            TouchEvent::Up { x, y } => {
                let was = self.pressed.take();
                let hit = self.hit(x, y);
                if let Some(w) = was {
                    // release feedback region
                    if let Some(b) = self.buttons().into_iter().find(|b| b.id == w) {
                        self.partial(b.rect);
                    }
                }
                if let (Some(w), Some((id, _))) = (was, hit) {
                    if w == id {
                        self.activate(id, out);
                    }
                }
            }
        }
    }

    pub(crate) fn rows_per_page(&self) -> usize {
        list_rows(self.size())
    }

    fn activate(&mut self, id: Id, out: &mut Vec<UiAction>) {
        let size = self.size();
        // Screen-specific first.
        match &mut self.screen {
            Screen::Pin(p) => {
                let (min, _) = (MIN_PIN, 0);
                match id {
                    Id::Digit(d) => {
                        if p.entry.len() < MAX_PIN {
                            p.entry.push((b'0' + d) as char);
                        }
                        self.pin_dirty();
                    }
                    Id::Del => {
                        p.entry.pop();
                        self.pin_dirty();
                    }
                    Id::Ok
                        if p.entry.len() >= min => {
                            let pin = Zeroizing::new(p.entry.to_string());
                            p.entry.clear();
                            out.push(UiAction::SubmitPin(pin));
                            self.pin_dirty();
                        }
                    _ => {}
                }
                return;
            }
            Screen::Setup(_) => return self.activate_setup(id, out),
            Screen::Home => {
                match id {
                    Id::Tile(i) => match i {
                        0 => out.push(UiAction::OpenList(EntryKind::Password)),
                        1 => out.push(UiAction::OpenList(EntryKind::Totp)),
                        2 => out.push(UiAction::OpenList(EntryKind::Passkey)),
                        3 => out.push(UiAction::OpenList(EntryKind::SshKey)),
                        4 => out.push(UiAction::OpenList(EntryKind::RecoveryCodes)),
                        _ => self.push(Screen::Settings { page: 0 }),
                    },
                    // Lock is a full shutdown (keys wiped, power cut).
                    Id::LockNow => out.push(UiAction::PowerOff),
                    _ => {}
                }
                return;
            }
            Screen::List { kind: _, entries, page } => {
                let per = list_rows(size);
                let pages = entries.len().div_ceil(per).max(1);
                match id {
                    Id::Back => self.pop(),
                    Id::PrevPage => {
                        if *page > 0 {
                            *page -= 1;
                            self.full();
                        }
                    }
                    Id::NextPage => {
                        if *page + 1 < pages {
                            *page += 1;
                            self.full();
                        }
                    }
                    Id::Row(i) => {
                        if let Some(e) = entries.get(*page * per + i).cloned() {
                            if e.kind == EntryKind::Totp {
                                out.push(UiAction::RequestTotp(e.id));
                                self.push(Screen::Totp(TotpState { id: e.id, issuer: e.title, account: e.subtitle, data: None }));
                            } else {
                                out.push(UiAction::OpenEntry(e.id));
                            }
                        }
                    }
                    _ => {}
                }
                return;
            }
            Screen::Detail(d) => {
                let sid = d.info.summary.id;
                match id {
                    Id::Back => self.pop(),
                    Id::Reveal => {
                        if let Some(f) = d.info.reveal {
                            out.push(UiAction::RevealSecret(sid, f));
                        }
                    }
                    Id::Hide => {
                        d.revealed = None;
                        self.full();
                    }
                    Id::TypeUsb => {
                        let f = d.info.reveal.unwrap_or(SecretField::Password);
                        out.push(UiAction::TypeEntry(sid, f));
                    }
                    Id::ShowTotp => {
                        let (issuer, account) = (d.info.summary.title.clone(), d.info.summary.subtitle.clone());
                        out.push(UiAction::RequestTotp(sid));
                        self.push(Screen::Totp(TotpState { id: sid, issuer, account, data: None }));
                    }
                    _ => {}
                }
                return;
            }
            Screen::Totp(t) => {
                match id {
                    Id::Back => self.pop(),
                    Id::TypeTotp => out.push(UiAction::TypeTotp(t.id)),
                    _ => {}
                }
                return;
            }
            Screen::Approval(a) => {
                let rid = a.req.id;
                match id {
                    Id::Approve => {
                        out.push(UiAction::Approve(rid));
                        self.pop();
                    }
                    Id::Deny => {
                        out.push(UiAction::Deny(rid));
                        self.pop();
                    }
                    _ => {}
                }
                return;
            }
            Screen::PairWait => {
                if id == Id::Cancel {
                    out.push(UiAction::ConfirmPairing(false));
                    self.pop();
                }
                return;
            }
            Screen::PairSas { .. } => {
                match id {
                    Id::Confirm => {
                        out.push(UiAction::ConfirmPairing(true));
                        self.screen = Screen::PairWait;
                        self.full();
                    }
                    Id::Cancel => {
                        out.push(UiAction::ConfirmPairing(false));
                        self.pop();
                    }
                    _ => {}
                }
                return;
            }
            Screen::Confirm(k) => {
                let k = *k;
                match (k, id) {
                    (_, Id::Cancel) => self.pop(),
                    (ConfirmKind::RemoveHost(i), Id::Confirm) => {
                        if let Some(h) = self.hosts.get(i) {
                            out.push(UiAction::RemovePairedHost(h.public_key));
                            self.hosts.remove(i);
                        }
                        self.pop();
                    }
                    (ConfirmKind::Wipe1, Id::Confirm) => {
                        self.screen = Screen::Confirm(ConfirmKind::Wipe2);
                        self.full();
                    }
                    (ConfirmKind::Wipe2, Id::Confirm) => {
                        out.push(UiAction::Wipe);
                        self.pop();
                    }
                    _ => {}
                }
                return;
            }
            Screen::Message { .. } => {
                if id == Id::MsgOk {
                    self.pop();
                }
                return;
            }
            Screen::Settings { .. } => {}
            Screen::Splash | Screen::Lock { .. } => return,
        }
        // Settings
        let Screen::Settings { page } = &mut self.screen else { return };
        let mut s = self.settings.clone();
        let mut changed = true;
        match id {
            Id::Back => {
                self.pop();
                return;
            }
            Id::PrevPage => {
                if *page > 0 {
                    *page -= 1;
                    self.full();
                }
                return;
            }
            Id::NextPage => {
                *page += 1;
                self.full();
                return;
            }
            Id::AutoLock(v) => s.auto_lock_secs = v,
            Id::Sleep(m) => s.sleep_mode = m,
            Id::Kbd(k) => s.keyboard_layout = k,
            Id::Orient(o) => s.orientation = o,
            Id::Buzzer(b) => s.buzzer = b,
            Id::RemoveHost(i) => {
                self.push(Screen::Confirm(ConfirmKind::RemoveHost(i)));
                return;
            }
            Id::PairNew => {
                out.push(UiAction::StartPairing);
                self.push(Screen::PairWait);
                return;
            }
            Id::WipeStart => {
                self.push(Screen::Confirm(ConfirmKind::Wipe1));
                return;
            }
            _ => changed = false,
        }
        if changed {
            let rot_changed = s.orientation != self.settings.orientation;
            self.settings = s.clone();
            out.push(UiAction::ChangeSettings(s));
            if rot_changed {
                if let Screen::Settings { page } = &mut self.screen {
                    *page = 0;
                }
                self.full();
            } else {
                let r = content_rect(self.size());
                self.partial(r);
            }
        }
    }

    fn on_pin_pad(&self) -> bool {
        match &self.screen {
            Screen::Pin(_) => true,
            Screen::Setup(s) => matches!(s.step, SetupStep::ChoosePin | SetupStep::ConfirmPin),
            _ => false,
        }
    }

    fn pin_entry_len(&self) -> usize {
        match &self.screen {
            Screen::Pin(p) => p.entry.len(),
            Screen::Setup(s) => s.entry.len(),
            _ => 0,
        }
    }

    fn pin_dirty(&mut self) {
        let sz = self.size();
        // Dots are pure black/white: DU-safe fast refresh.
        self.fast(pin_feedback_rect(sz));
        // OK flips between disabled (grey) and enabled around the minimum length: greyscale
        // refresh of just that key when it may have changed.
        let min = match &self.screen {
            Screen::Setup(_) => MIN_SETUP_PIN,
            _ => MIN_PIN,
        };
        let len = self.pin_entry_len();
        if len == min || len + 1 == min {
            if let Some(b) = self.buttons().into_iter().find(|b| b.id == Id::Ok) {
                self.partial(b.rect);
            }
        }
    }

    // ---- setup wizard ----------------------------------------------------

    fn start_setup(&mut self) {
        let digits = self.shuffled_digits();
        self.goto(Screen::Setup(Setup {
            step: SetupStep::ChoosePin,
            first: Zeroizing::new(String::new()),
            entry: Zeroizing::new(String::new()),
            words: Zeroizing::new(Vec::new()),
            quiz: Vec::new(),
            digits,
        }));
    }

    fn make_quiz(&mut self, words: usize) -> Vec<Quiz> {
        let mut idxs: Vec<usize> = Vec::new();
        while idxs.len() < 3 {
            let i = self.rand(words);
            if !idxs.contains(&i) {
                idxs.push(i);
            }
        }
        idxs.sort();
        let mut quiz = Vec::new();
        for wi in idxs {
            let mut ch = vec![wi];
            while ch.len() < 4 {
                let i = self.rand(words);
                if !ch.contains(&i) {
                    ch.push(i);
                }
            }
            for i in (1..4).rev() {
                let j = self.rand(i + 1);
                ch.swap(i, j);
            }
            let correct = ch.iter().position(|&c| c == wi).unwrap();
            quiz.push(Quiz { word_index: wi, choices: [ch[0], ch[1], ch[2], ch[3]], correct });
        }
        quiz
    }

    fn activate_setup(&mut self, id: Id, out: &mut Vec<UiAction>) {
        let Screen::Setup(s) = &mut self.screen else { return };
        match s.step {
            SetupStep::ChoosePin | SetupStep::ConfirmPin => {
                match id {
                    Id::Digit(d) => {
                        if s.entry.len() < MAX_PIN {
                            s.entry.push((b'0' + d) as char);
                        }
                        self.pin_dirty();
                    }
                    Id::Del => {
                        s.entry.pop();
                        self.pin_dirty();
                    }
                    Id::Ok if s.entry.len() >= MIN_SETUP_PIN => {
                        if s.step == SetupStep::ChoosePin {
                            s.first = Zeroizing::new(s.entry.to_string());
                            s.entry.clear();
                            s.step = SetupStep::ConfirmPin;
                            self.full();
                        } else if *s.entry == *s.first {
                            let pin = Zeroizing::new(s.entry.to_string());
                            s.entry.clear();
                            s.first.clear();
                            s.step = SetupStep::WaitSeed;
                            out.push(UiAction::SetupPin(pin));
                            self.full();
                        } else {
                            s.entry.clear();
                            s.first.clear();
                            s.step = SetupStep::ChoosePin;
                            self.full();
                            self.push(Screen::Message { text: "PINs did not match. Start again.".into(), error: true });
                        }
                    }
                    _ => {}
                }
            }
            SetupStep::Seed(p) => match id {
                Id::PrevPage if p > 0 => {
                    s.step = SetupStep::Seed(p - 1);
                    self.full();
                }
                Id::NextPage if p + 1 < 3 => {
                    s.step = SetupStep::Seed(p + 1);
                    self.full();
                }
                Id::SeedDone => {
                    let n = s.words.len().max(1);
                    let quiz = self.make_quiz(n);
                    if let Screen::Setup(s) = &mut self.screen {
                        s.quiz = quiz;
                        s.step = SetupStep::Verify(0);
                    }
                    self.full();
                }
                _ => {}
            },
            SetupStep::Verify(q) => {
                if let Id::Choice(c) = id {
                    if s.quiz.get(q).map(|x| x.correct) == Some(c) {
                        if q + 1 < s.quiz.len() {
                            s.step = SetupStep::Verify(q + 1);
                            self.full();
                        } else {
                            s.step = SetupStep::Saving;
                            s.words = Zeroizing::new(Vec::new());
                            s.quiz.clear();
                            out.push(UiAction::SetupConfirmedSeed);
                            self.full();
                        }
                    } else {
                        s.step = SetupStep::Seed(0);
                        s.quiz.clear();
                        self.full();
                        self.push(Screen::Message { text: "Wrong word. Review your seed words and try again.".into(), error: true });
                    }
                }
            }
            SetupStep::WaitSeed | SetupStep::Saving => {}
        }
    }

    /// All active touch targets as (name, logical rectangle); names look like "Digit(5)", "Approve".
    /// Useful for tests and on-device debugging.
    pub fn targets(&self) -> Vec<(String, Rectangle)> {
        self.buttons().into_iter().filter(|b| b.enabled).map(|b| (format!("{:?}", b.id), b.rect)).collect()
    }

    /// Test/debug helper: (index of the asked word, labels of the 4 choices) while verifying the seed.
    pub fn quiz_debug(&self) -> Option<(usize, Vec<String>)> {
        if let Screen::Setup(s) = &self.screen {
            if let SetupStep::Verify(q) = s.step {
                let qz = s.quiz.get(q)?;
                return Some((qz.word_index, qz.choices.iter().map(|&i| s.words[i].clone()).collect()));
            }
        }
        None
    }

    // ---- drawing -----------------------------------------------------------

    pub fn draw<D: DrawTarget<Color = Gray4>>(&self, d: &mut D) {
        crate::render::draw_ui(self, d);
    }
}

pub(crate) use embedded_graphics::pixelcolor::Gray4;
