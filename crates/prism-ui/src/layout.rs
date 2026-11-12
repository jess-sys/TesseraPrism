//! Screen layouts: every screen is turned into a flat list of `Item`s which are both drawn
//! and hit-tested (buttons), so drawing and touch handling can never disagree.

use crate::gfx::*;
use crate::types::*;
use crate::ui::*;
use embedded_graphics::{prelude::*, primitives::Rectangle};
use prism_core::model::*;

pub const STATUS_H: i32 = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Id {
    Back,
    Digit(u8),
    Del,
    Ok,
    Tile(usize),
    Row(usize),
    PrevPage,
    NextPage,
    Reveal,
    Hide,
    TypeUsb,
    ShowTotp,
    TypeTotp,
    Approve,
    Deny,
    Confirm,
    Cancel,
    Choice(usize),
    SeedDone,
    AutoLock(u32),
    Sleep(SleepMode),
    Kbd(KeyboardLayout),
    Orient(Orientation),
    Buzzer(bool),
    RemoveHost(usize),
    PairNew,
    WipeStart,
    LockNow,
    MsgOk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Primary,
    Outline,
    Row,
    Tile,
    Seg(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Left,
    Right,
    Chevron,
    Key,
    Clock,
    Passkey,
    Ssh,
    Codes,
    Gear,
    Lock,
    Shield,
    Power,
    /// Arrow pointing right (towards the power button on the lock screen).
    Arrow,
}

#[derive(Clone, Debug)]
pub struct Btn {
    pub rect: Rectangle,
    pub id: Id,
    pub label: String,
    pub style: Style,
    pub font: F,
    pub enabled: bool,
    pub icon: Option<Icon>,
    pub inner: Vec<Item>,
}

impl Btn {
    pub fn new(rect: Rectangle, id: Id, label: &str, style: Style) -> Self {
        Btn { rect, id, label: label.to_string(), style, font: F::Bold, enabled: true, icon: None, inner: Vec::new() }
    }
    pub fn font(mut self, f: F) -> Self {
        self.font = f;
        self
    }
    pub fn icon(mut self, i: Icon) -> Self {
        self.icon = Some(i);
        self
    }
    pub fn enabled(mut self, e: bool) -> Self {
        self.enabled = e;
        self
    }
}

#[derive(Clone, Debug)]
pub enum Item {
    Btn(Btn),
    Text { s: String, x: i32, cy: i32, font: F, align: Align, color: Gray4 },
    Fill { rect: Rectangle, color: Gray4 },
    Frame { rect: Rectangle, fill: Option<Gray4>, border: u32 },
    Icon { kind: Icon, rect: Rectangle },
    Dots { cx: i32, cy: i32, total: usize, filled: usize },
    Bar { rect: Rectangle, segs: u32, filled: u32 },
    Digits { s: String, cx: i32, cy: i32, font: F, split: usize },
    /// "NEUTHERIA SYSTEMS" wordmark, centred on (cx, cy). `large`: 480 px wide, else 360 px.
    /// `inverted`: white on black.
    Brand { cx: i32, cy: i32, large: bool, inverted: bool },
    /// Icon with explicit colours (e.g. white on a black band).
    IconC { kind: Icon, rect: Rectangle, fg: Gray4, bg: Gray4 },
    /// Battery gauge (46x22) with its left edge at x, vertically centred on cy.
    Battery { x: i32, cy: i32, pct: u8, fg: Gray4, bg: Gray4 },
    Status(Status),
}

pub fn collect_buttons(items: &[Item], out: &mut Vec<Btn>) {
    for it in items {
        if let Item::Btn(b) = it {
            out.push(b.clone());
        }
    }
}

// ---- geometry shared with the state machine --------------------------------

fn land(sz: Size) -> bool {
    sz.width > sz.height
}
pub fn content_top(sz: Size) -> i32 {
    if land(sz) {
        126
    } else {
        146
    }
}
pub fn content_rect(sz: Size) -> Rectangle {
    rect(0, STATUS_H, sz.width, sz.height - STATUS_H as u32)
}
pub fn list_rows(sz: Size) -> usize {
    if land(sz) {
        4
    } else {
        8
    }
}
fn list_row_h(sz: Size) -> i32 {
    if land(sz) {
        78
    } else {
        82
    }
}
fn pager_rect(sz: Size) -> Rectangle {
    if land(sz) {
        rect(24, sz.height as i32 - 84, sz.width - 48, 72)
    } else {
        rect(24, sz.height as i32 - 124, sz.width - 48, 88)
    }
}
pub fn pin_feedback_rect(sz: Size) -> Rectangle {
    if land(sz) {
        rect(0, STATUS_H, sz.width, sz.height - STATUS_H as u32)
    } else {
        rect(0, 150, sz.width, 160)
    }
}
pub fn totp_segments(period: u32, remaining: u64) -> u32 {
    ((remaining * 10).div_ceil(period.max(1) as u64)).min(10) as u32
}
pub fn totp_bar_rect(sz: Size) -> Rectangle {
    if land(sz) {
        rect(60, 340, 840, 36)
    } else {
        rect(40, 480, sz.width - 80, 36)
    }
}

pub fn kind_label(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Password => "Passwords",
        EntryKind::Totp => "Authenticator",
        EntryKind::Passkey => "Passkeys",
        EntryKind::SshKey => "SSH keys",
        EntryKind::RecoveryCodes => "Recovery codes",
    }
}

fn txt(s: impl Into<String>, x: i32, cy: i32, font: F, align: Align, color: Gray4) -> Item {
    Item::Text { s: s.into(), x, cy, font, align, color }
}

fn rule(x0: i32, x1: i32, y: i32, color: Gray4) -> Item {
    Item::Fill { rect: rect(x0, y, (x1 - x0).max(0) as u32, 2), color }
}

/// Split n buttons across `width` starting at x with gap.
fn hsplit(x: i32, width: i32, n: usize, gap: i32) -> Vec<(i32, i32)> {
    let w = (width - gap * (n as i32 - 1)) / n as i32;
    (0..n).map(|i| (x + i as i32 * (w + gap), w)).collect()
}

fn header(sz: Size, title: &str, back: bool) -> Vec<Item> {
    let w = sz.width as i32;
    let mut v = Vec::new();
    let top = if land(sz) { 54 } else { 58 };
    let h = if land(sz) { 56 } else { 70 };
    let mut tx = 24;
    if back {
        v.push(Item::Btn(Btn::new(rect(16, top, 150, h as u32), Id::Back, "Back", Style::Outline).icon(Icon::Left)));
        tx = 186;
    }
    v.push(txt(fit(F::Title, title, w - tx - 20), tx, top + h / 2, F::Title, Align::Left, INK));
    v.push(rule(16, w - 16, top + h + 8, INK));
    v
}

fn fmt_hhmm(unix: u64, tz: i32) -> String {
    if unix == 0 {
        return "--:--".into();
    }
    let t = (unix as i64 + tz as i64).rem_euclid(86400);
    format!("{:02}:{:02}", t / 3600, (t % 3600) / 60)
}

pub fn fmt_datetime(unix: u64, tz: i32) -> String {
    let t = unix as i64 + tz as i64;
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // civil from days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!("{} {} {}, {:02}:{:02}", d, MON[(m - 1) as usize], y, secs / 3600, (secs % 3600) / 60)
}

pub fn status_time(s: &Status) -> String {
    fmt_hhmm(s.unix, s.tz_secs)
}

fn button_stack(sz: Size, bottom: i32, specs: Vec<(Id, &str, Style, bool)>, h: i32) -> Vec<Item> {
    // bottom-aligned buttons: stacked in portrait, one row in landscape
    let w = sz.width as i32;
    let n = specs.len();
    let mut v = Vec::new();
    if n == 0 {
        return v;
    }
    if land(sz) {
        let cols = hsplit(24, w - 48, n, 12);
        for ((id, label, style, en), (x, bw)) in specs.into_iter().zip(cols) {
            v.push(Item::Btn(Btn::new(rect(x, bottom - h, bw as u32, h as u32), id, label, style).enabled(en)));
        }
    } else {
        let total = n as i32 * h + (n as i32 - 1) * 12;
        let mut y = bottom - total;
        for (id, label, style, en) in specs {
            v.push(Item::Btn(Btn::new(rect(24, y, (w - 48) as u32, h as u32), id, label, style).enabled(en)));
            y += h + 12;
        }
    }
    v
}

fn dots_for_pin(sz: Size, len: usize) -> Item {
    let (cx, cy) = if land(sz) { (240, 280) } else { (sz.width as i32 / 2, 215) };
    Item::Dots { cx, cy, total: len.max(6), filled: len }
}

fn keypad(sz: Size, digits: &[u8; 10], _len: usize, _min: usize) -> Vec<Item> {
    let (ax, ay, aw, ah) = if land(sz) { (500, 56, 436, 468) } else { (24, 340, 492, 584) };
    let gap = 12;
    let cw = (aw - 2 * gap) / 3;
    let ch = (ah - 3 * gap) / 4;
    let mut v = Vec::new();
    for r in 0..4 {
        for c in 0..3 {
            let r_ = rect(ax + c * (cw + gap), ay + r * (ch + gap), cw as u32, ch as u32);
            let btn = match (r, c) {
                (3, 0) => Btn::new(r_, Id::Del, "Del", Style::Outline).font(F::Bold),
                // Always enabled: flipping it at the minimum length forced a greyscale refresh mid-typing.
                (3, 2) => Btn::new(r_, Id::Ok, "OK", Style::Primary).font(F::Title),
                (3, 1) => Btn::new(r_, Id::Digit(digits[9]), &digits[9].to_string(), Style::Outline).font(F::Big),
                _ => {
                    let d = digits[(r * 3 + c) as usize];
                    Btn::new(r_, Id::Digit(d), &d.to_string(), Style::Outline).font(F::Big)
                }
            };
            v.push(Item::Btn(btn));
        }
    }
    v
}

fn pin_items(sz: Size, title: &str, sub: &str, len: usize, min: usize, attempts: Option<u8>, digits: &[u8; 10]) -> Vec<Item> {
    let (cx, ty, sy, wy) = if land(sz) { (240, 140, 195, 360) } else { (sz.width as i32 / 2, 110, 158, 272) };
    let mut v = vec![txt(title, cx, ty, F::Big, Align::Center, INK)];
    if !sub.is_empty() {
        v.push(txt(sub, cx, sy, F::Body, Align::Center, DIM));
    }
    v.push(dots_for_pin(sz, len));
    if let Some(a) = attempts {
        let msg = if a == 1 { "Warning: 1 attempt left".to_string() } else { format!("Warning: {a} attempts left") };
        let bw = if land(sz) { 420 } else { 460 };
        v.push(Item::Frame { rect: rect(cx - bw / 2, wy - 26, bw as u32, 52), fill: Some(FILL), border: 3 });
        v.push(txt(msg, cx, wy, F::Bold, Align::Center, INK));
    }
    v.extend(keypad(sz, digits, len, min));
    v
}

impl Ui {
    pub(crate) fn items(&self) -> Vec<Item> {
        self.screen_items(&self.screen)
    }

    /// Items of the screen below an overlay (message), used to draw the backdrop.
    pub(crate) fn backdrop_items(&self) -> Vec<Item> {
        match (&self.screen, self.stack.last()) {
            (Screen::Message { .. }, Some(s)) => self.screen_items(s),
            _ => Vec::new(),
        }
    }

    pub(crate) fn screen_items(&self, screen: &Screen) -> Vec<Item> {
        let sz = self.size();
        let (w, h) = (sz.width as i32, sz.height as i32);
        let l = land(sz);
        let mut v: Vec<Item> = Vec::new();
        let status = !matches!(screen, Screen::Splash | Screen::Lock { .. });
        if status {
            v.push(Item::Status(self.status));
        }
        match screen {
            Screen::Splash => {
                let (cx, cy) = (w / 2, if l { 190 } else { 380 });
                v.push(Item::Brand { cx, cy, large: true, inverted: false });
                v.push(txt("Tessera Prism", cx, cy + 80, F::Big, Align::Center, INK));
                v.push(txt("Hardware password manager", cx, cy + 140, F::Body, Align::Center, DIM));
                v.push(txt(format!("Battery {}%", self.status.battery), cx, h - 50, F::Small, Align::Center, DIM));
            }
            Screen::Lock { battery, last_used } => {
                let when = last_used.map(|t| fmt_datetime(t, self.status.tz_secs));
                let owner = self.settings.owner_info.as_deref();
                lock_split(sz, *battery, when.as_deref(), owner, &mut v);
            }
            Screen::Pin(p) if p.verifying => {
                let (cx, cy) = (w / 2, if l { h / 2 - 40 } else { h / 2 - 80 });
                v.push(Item::Icon { kind: Icon::Lock, rect: rect(cx - 48, cy - 150, 96, 96) });
                v.push(txt("Decrypting...", cx, cy + 10, F::Big, Align::Center, INK));
                v.push(txt("This takes a few seconds.", cx, cy + 70, F::Body, Align::Center, DIM));
            }
            Screen::Pin(p) => {
                v.extend(pin_items(sz, "Enter PIN", "", p.entry.len(), MIN_PIN, p.attempts_left, &p.digits));
            }
            Screen::Setup(s) => self.setup_items(sz, s, &mut v),
            Screen::Home => {
                let tiles: [(&str, Option<u32>, Icon); 6] = [
                    ("Passwords", Some(self.counts.passwords), Icon::Key),
                    ("Authenticator", Some(self.counts.totp), Icon::Clock),
                    ("Passkeys", Some(self.counts.passkeys), Icon::Passkey),
                    ("SSH keys", Some(self.counts.ssh), Icon::Ssh),
                    ("Recovery", Some(self.counts.recovery), Icon::Codes),
                    ("Settings", None, Icon::Gear),
                ];
                let (cols, tw, th, gap, y0) = if l { (3, 296, 188, 12, 62) } else { (2, 238, 236, 16, 66) };
                let x0 = (w - (cols * tw + (cols - 1) * gap)) / 2;
                for (i, (label, count, icon)) in tiles.iter().enumerate() {
                    let (c, r) = (i as i32 % cols, i as i32 / cols);
                    let (x, y) = (x0 + c * (tw + gap), y0 + r * (th + gap));
                    let mut b = Btn::new(rect(x, y, tw as u32, th as u32), Id::Tile(i), "", Style::Tile);
                    if l {
                        b.inner.push(Item::Icon { kind: *icon, rect: rect(x + 14, y + th / 2 - 32, 64, 64) });
                        b.inner.push(txt(*label, x + 92, y + 62, F::Bold, Align::Left, INK));
                        match count {
                            Some(n) => b.inner.push(txt(n.to_string(), x + 92, y + 120, F::Big, Align::Left, INK)),
                            None => b.inner.push(txt("Preferences", x + 92, y + 120, F::Small, Align::Left, DIM)),
                        }
                    } else {
                        b.inner.push(Item::Icon { kind: *icon, rect: rect(x + tw / 2 - 36, y + 26, 72, 72) });
                        b.inner.push(txt(*label, x + tw / 2, y + 130, F::Bold, Align::Center, INK));
                        match count {
                            Some(n) => b.inner.push(txt(n.to_string(), x + tw / 2, y + 184, F::Big, Align::Center, INK)),
                            None => b.inner.push(txt("Preferences", x + tw / 2, y + 190, F::Small, Align::Center, DIM)),
                        }
                    }
                    v.push(Item::Btn(b));
                }
                let by = if l { h - 74 } else { h - 118 };
                let bh = if l { 62 } else { 92 };
                // Single action: lock = wipe keys from RAM + full shutdown.
                v.push(Item::Btn(Btn::new(rect(x0, by, (w - 2 * x0) as u32, bh), Id::LockNow, "Lock", Style::Primary).icon(Icon::Lock)));
            }
            Screen::List { kind, entries, page } => {
                v.extend(header(sz, kind_label(*kind), true));
                let per = list_rows(sz);
                let pages = entries.len().div_ceil(per).max(1);
                let rh = list_row_h(sz);
                let y0 = content_top(sz);
                if entries.is_empty() {
                    v.push(txt("No entries", w / 2, y0 + 120, F::Title, Align::Center, DIM));
                }
                for i in 0..per {
                    let Some(e) = entries.get(page * per + i) else { break };
                    let y = y0 + i as i32 * rh;
                    let mut b = Btn::new(rect(16, y, (w - 32) as u32, rh as u32), Id::Row(i), "", Style::Row);
                    b.inner.push(txt(fit(F::Bold, &e.title, w - 120), 28, y + rh / 2 - 15, F::Bold, Align::Left, INK));
                    b.inner.push(txt(fit(F::Small, &e.subtitle, w - 120), 28, y + rh / 2 + 17, F::Small, Align::Left, DIM));
                    b.inner.push(Item::Icon { kind: Icon::Chevron, rect: rect(w - 66, y + rh / 2 - 14, 28, 28) });
                    v.push(Item::Btn(b));
                }
                v.extend(self.pager(sz, *page, pages));
            }
            Screen::Detail(d) => self.detail_items(sz, d, &mut v),
            Screen::Totp(t) => {
                v.extend(header(sz, &t.issuer, true));
                let cx = w / 2;
                let (ay, dy, by) = if l { (150, 245, 340) } else { (186, 340, 480) };
                v.push(txt(fit(F::Body, &t.account, w - 60), cx, ay, F::Body, Align::Center, DIM));
                match &t.data {
                    Some(d) => {
                        let split = d.code.len() / 2;
                        v.push(Item::Digits { s: d.code.to_string(), cx, cy: dy, font: F::Digits, split });
                        let rem = d.expires.saturating_sub(self.now);
                        let segs = totp_segments(d.period, rem);
                        v.push(Item::Bar { rect: totp_bar_rect(sz), segs: 10, filled: segs });
                        v.push(txt(format!("Code changes every {} s", d.period), cx, by + 56, F::Small, Align::Center, DIM));
                        if let Some(n) = &d.next {
                            let sp = n.len() / 2;
                            let ns = format!("{} {}", &n[..sp], &n[sp..]);
                            v.push(txt(format!("Next: {ns}"), cx, by + 100, F::Body, Align::Center, DIM));
                        }
                    }
                    None => v.push(txt("Loading...", cx, dy, F::Title, Align::Center, DIM)),
                }
                v.extend(button_stack(sz, h - 24, vec![(Id::TypeTotp, "Type via USB", Style::Outline, t.data.is_some() && self.status.usb)], 88));
            }
            Screen::Approval(a) => self.approval_items(sz, a, &mut v),
            Screen::PairWait => {
                v.extend(header(sz, "Pair new host", false));
                v.push(txt("Waiting for host...", w / 2, if l { 200 } else { 300 }, F::Title, Align::Center, INK));
                for (i, ln) in wrap(F::Body, "On your computer or phone, open Prism and choose Pair device.", w - 80, 4).iter().enumerate() {
                    v.push(txt(ln.clone(), w / 2, if l { 260 } else { 370 } + i as i32 * 36, F::Body, Align::Center, DIM));
                }
                v.extend(button_stack(sz, h - 24, vec![(Id::Cancel, "Cancel", Style::Outline, true)], 96));
            }
            Screen::PairSas { host, sas } => {
                v.extend(header(sz, "Pair new host", false));
                let cx = w / 2;
                let (hy, iy, dy) = if l { (150, 195, 300) } else { (200, 262, 440) };
                v.push(txt(fit(F::Bold, host, w - 60), cx, hy, F::Bold, Align::Center, INK));
                for (i, ln) in wrap(F::Body, "Check that this code is identical on the other device.", w - 80, 3).iter().enumerate() {
                    v.push(txt(ln.clone(), cx, iy + i as i32 * 34, F::Body, Align::Center, DIM));
                }
                v.push(Item::Digits { s: sas.clone(), cx, cy: dy, font: F::Digits, split: sas.len() / 2 });
                v.extend(button_stack(
                    sz,
                    h - 24,
                    vec![(Id::Confirm, "Codes match", Style::Primary, true), (Id::Cancel, "Cancel", Style::Outline, true)],
                    if l { 96 } else { 104 },
                ));
            }
            Screen::Settings { page } => self.settings_items(sz, *page, &mut v),
            Screen::Confirm(k) => {
                let (title, lines, yes, wipe2): (String, Vec<String>, &str, bool) = match k {
                    ConfirmKind::RemoveHost(i) => {
                        let name = self.hosts.get(*i).map(|h| h.label.clone()).unwrap_or_default();
                        (format!("Remove {name}?"), vec!["This host will need to be paired again.".into()], "Remove", false)
                    }
                    ConfirmKind::Wipe1 => ("Wipe device?".into(), vec!["All passwords, keys and settings will be erased.".into()], "Continue", false),
                    ConfirmKind::Wipe2 => (
                        "Are you sure?".into(),
                        vec!["This cannot be undone. Without your 24 seed words your data is gone forever.".into()],
                        "ERASE EVERYTHING",
                        true,
                    ),
                };
                v.extend(header(sz, "Confirm", false));
                let cx = w / 2;
                let ty = if l { 190 } else { 280 };
                for (i, t) in wrap(F::Title, &title, w - 60, 2).iter().enumerate() {
                    v.push(txt(t.clone(), cx, ty + i as i32 * 44, F::Title, Align::Center, INK));
                }
                for ln in lines {
                    for (i, t) in wrap(F::Body, &ln, w - 80, 5).iter().enumerate() {
                        v.push(txt(t.clone(), cx, ty + 100 + i as i32 * 36, F::Body, Align::Center, DIM));
                    }
                }
                let specs = if wipe2 {
                    vec![(Id::Confirm, yes, Style::Outline, true), (Id::Cancel, "Cancel", Style::Primary, true)]
                } else {
                    vec![(Id::Confirm, yes, Style::Primary, true), (Id::Cancel, "Cancel", Style::Outline, true)]
                };
                v.extend(button_stack(sz, h - 24, specs, if l { 96 } else { 104 }));
            }
            Screen::Message { text, error } => {
                let (cw, chh) = if l { (560, 300) } else { (460, 330) };
                let (x, y) = ((w - cw) / 2, (h - chh) / 2);
                v.push(Item::Frame { rect: rect(x, y, cw as u32, chh as u32), fill: Some(PAPER), border: 5 });
                v.push(txt(if *error { "Error" } else { "Notice" }, x + cw / 2, y + 50, F::Title, Align::Center, INK));
                for (i, t) in wrap(F::Body, text, cw - 60, 4).iter().enumerate() {
                    v.push(txt(t.clone(), x + cw / 2, y + 116 + i as i32 * 36, F::Body, Align::Center, INK));
                }
                v.push(Item::Btn(Btn::new(rect(x + 30, y + chh - 96, (cw - 60) as u32, 72), Id::MsgOk, "OK", Style::Primary)));
            }
        }
        v
    }

    fn pager(&self, sz: Size, page: usize, pages: usize) -> Vec<Item> {
        let r = pager_rect(sz);
        let (x, y, w, h) = (r.top_left.x, r.top_left.y, r.size.width as i32, r.size.height);
        vec![
            Item::Btn(Btn::new(rect(x, y, 140, h), Id::PrevPage, "", Style::Outline).icon(Icon::Left).enabled(page > 0)),
            txt(format!("Page {} / {}", page + 1, pages), x + w / 2, y + h as i32 / 2, F::Bold, Align::Center, INK),
            Item::Btn(Btn::new(rect(x + w - 140, y, 140, h), Id::NextPage, "", Style::Outline).icon(Icon::Right).enabled(page + 1 < pages)),
        ]
    }

    fn setup_items(&self, sz: Size, s: &Setup, v: &mut Vec<Item>) {
        let (w, h) = (sz.width as i32, sz.height as i32);
        let l = land(sz);
        match s.step {
            SetupStep::ChoosePin => v.extend(pin_items(sz, "Choose a PIN", "Step 1 of 3  -  6 to 12 digits", s.entry.len(), MIN_SETUP_PIN, None, &s.digits)),
            SetupStep::ConfirmPin => v.extend(pin_items(sz, "Confirm PIN", "Enter the same PIN again", s.entry.len(), MIN_SETUP_PIN, None, &s.digits)),
            SetupStep::WaitSeed | SetupStep::Saving => {
                let t = if s.step == SetupStep::WaitSeed { "Generating seed..." } else { "Saving..." };
                v.push(txt(t, w / 2, h / 2, F::Title, Align::Center, INK));
            }
            SetupStep::Seed(p) => {
                let (bx, by, bh) = (24, 58, if l { 64 } else { 92 });
                v.push(Item::Frame { rect: rect(bx, by, (w - 48) as u32, bh as u32), fill: Some(FILL), border: 3 });
                if l {
                    v.push(txt("Write these 24 words on paper, in order. Never photograph or store digitally.", w / 2, by + 32, F::Bold, Align::Center, INK));
                } else {
                    v.push(txt("Write these 24 words on paper.", w / 2, by + 30, F::Body, Align::Center, INK));
                    v.push(txt("Never photograph or store them digitally.", w / 2, by + 64, F::Small, Align::Center, INK));
                }
                let y0 = if l { 142 } else { 176 };
                let (rh, cols) = if l { (66, 2) } else { (78, 1) };
                let colw = (w - 48) / cols;
                for i in 0..8usize {
                    let (c, r) = if l { (i as i32 / 4, i as i32 % 4) } else { (0, i as i32) };
                    let x = 24 + c * colw;
                    let cy = y0 + r * rh + rh / 2;
                    let n = p * 8 + i;
                    v.push(txt(format!("{}.", n + 1), x + 70, cy, F::Body, Align::Right, DIM));
                    let word = s.words.get(n).cloned().unwrap_or_default();
                    v.push(txt(word, x + 92, cy, F::Title, Align::Left, INK));
                    v.push(rule(x, x + colw - 16, cy + rh / 2, RULE));
                }
                let (by2, bh2) = if l { (h - 80, 68) } else { (h - 116, 92) };
                let last = p == 2;
                v.push(Item::Btn(Btn::new(rect(24, by2, 130, bh2 as u32), Id::PrevPage, "", Style::Outline).icon(Icon::Left).enabled(p > 0)));
                let (nl, nid) = if last { ("I wrote them down", Id::SeedDone) } else { ("Next", Id::NextPage) };
                let mut nb = Btn::new(rect(168, by2, (w - 192) as u32, bh2 as u32), nid, nl, Style::Primary);
                if !last {
                    nb = nb.icon(Icon::Right);
                }
                v.push(Item::Btn(nb));
                v.push(txt(format!("Words {}-{}  ({}/3)", p * 8 + 1, p * 8 + 8, p + 1), w / 2, by2 - 22, F::Small, Align::Center, DIM));
            }
            SetupStep::Verify(q) => {
                v.extend(header(sz, "Verify seed", false));
                let Some(quiz) = s.quiz.get(q) else { return };
                let cx = w / 2;
                v.push(txt(format!("Check {} of {}", q + 1, s.quiz.len()), cx, if l { 150 } else { 190 }, F::Body, Align::Center, DIM));
                v.push(txt(format!("Which is word #{}?", quiz.word_index + 1), cx, if l { 196 } else { 262 }, F::Title, Align::Center, INK));
                let (ax, ay, aw, ah, cols) = if l { (24, 236, w - 48, 280, 2) } else { (24, 330, w - 48, 560, 1) };
                let gap = 14;
                let rows = 4 / cols;
                let bw = (aw - gap * (cols - 1)) / cols;
                let bh = (ah - gap * (rows - 1)) / rows;
                for (i, &wi) in quiz.choices.iter().enumerate() {
                    let (c, r) = (i as i32 % cols, i as i32 / cols);
                    let label = s.words.get(wi).cloned().unwrap_or_default();
                    v.push(Item::Btn(
                        Btn::new(rect(ax + c * (bw + gap), ay + r * (bh + gap), bw as u32, bh as u32), Id::Choice(i), &label, Style::Outline).font(F::Title),
                    ));
                }
            }
        }
    }

    fn detail_items(&self, sz: Size, d: &Detail, v: &mut Vec<Item>) {
        let (w, h) = (sz.width as i32, sz.height as i32);
        let l = land(sz);
        let info = &d.info;
        v.extend(header(sz, &info.summary.title, true));
        let mut specs = Vec::new();
        if let Some(_f) = info.reveal {
            if d.revealed.is_some() {
                specs.push((Id::Hide, "Hide", Style::Primary, true));
            } else {
                specs.push((Id::Reveal, "Reveal", Style::Primary, true));
            }
        }
        if info.can_type {
            specs.push((Id::TypeUsb, "Type via USB", Style::Outline, true));
        }
        if info.summary.has_totp && info.summary.kind == EntryKind::Password {
            specs.push((Id::ShowTotp, "Show TOTP code", Style::Outline, true));
        }
        let bh = if l { 72 } else { 88 };
        let n = specs.len() as i32;
        let btn_area = if n == 0 {
            0
        } else if l {
            bh + 24
        } else {
            n * (bh + 12) + 12
        };
        let btn_top = h - 24 - btn_area + if n == 0 { 0 } else { 12 };
        let rh = if l { 64 } else { 78 };
        let mut y = content_top(sz);
        let max_fields = if d.revealed.is_some() { if l { 1 } else { 3 } } else { usize::MAX };
        for f in info.fields.iter().take(max_fields) {
            if y + rh > btn_top {
                break;
            }
            v.push(txt(f.label.clone(), 28, y + 16, F::Small, Align::Left, DIM));
            v.push(txt(fit(F::Body, &f.value, w - 56), 28, y + 46, F::Body, Align::Left, INK));
            v.push(rule(16, w - 16, y + rh - 2, RULE));
            y += rh;
        }
        if let Some(rv) = &d.revealed {
            let r = rect(16, y + 10, (w - 32) as u32, (btn_top - y - 20).max(60) as u32);
            v.push(Item::Frame { rect: r, fill: None, border: 4 });
            let (rx, ry, rw, rhh) = (r.top_left.x + 18, r.top_left.y + 14, r.size.width as i32 - 36, r.size.height as i32 - 28);
            match rv {
                Revealed::Secret(sv) => {
                    let text = match sv {
                        prism_core::model::SecretValue::Text(t) => t.clone(),
                        prism_core::model::SecretValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
                        prism_core::model::SecretValue::List(l) => l.join(" "),
                    };
                    let max_lines = (rhh / 46).max(1) as usize;
                    for (i, ln) in wrap(F::Mono, &text, rw, max_lines).iter().enumerate() {
                        v.push(txt(ln.clone(), rx, ry + 23 + i as i32 * 46, F::Mono, Align::Left, INK));
                    }
                }
                Revealed::Codes(codes) => {
                    let cols = 2;
                    let rows = ((rhh / 50).max(1)) as usize;
                    let colw = rw / cols;
                    for (i, c) in codes.iter().enumerate().take(rows * cols as usize) {
                        let (cc, rr) = ((i / rows) as i32, (i % rows) as i32);
                        let x = rx + cc * colw;
                        let cy = ry + 24 + rr * 50;
                        let col = if c.used { DIM } else { INK };
                        v.push(txt(c.code.clone(), x, cy, F::Mono, Align::Left, col));
                        if c.used {
                            let tw = text_width(F::Mono, &c.code);
                            v.push(Item::Fill { rect: rect(x - 4, cy, (tw + 8) as u32, 3), color: INK });
                        }
                    }
                }
            }
        }
        v.extend(button_stack(sz, h - 24, specs, bh));
    }

    fn approval_items(&self, sz: Size, a: &ApprovalState, v: &mut Vec<Item>) {
        let (w, h) = (sz.width as i32, sz.height as i32);
        let l = land(sz);
        let req = &a.req;
        let (kind_text, icon) = match req.kind {
            ApprovalKind::Password => ("Password request", Icon::Key),
            ApprovalKind::Totp => ("Code request", Icon::Clock),
            ApprovalKind::PasskeyRegister => ("Create passkey", Icon::Passkey),
            ApprovalKind::PasskeyAuth => ("Passkey sign-in", Icon::Passkey),
            ApprovalKind::SshSign => ("SSH signature", Icon::Ssh),
            ApprovalKind::RecoveryCodes => ("Recovery codes", Icon::Codes),
            ApprovalKind::Other => ("Approval request", Icon::Shield),
        };
        let cx = if l { 250 } else { w / 2 };
        let iw = if l { 440 } else { w - 48 };
        let (icy, ky, fy, ry, ey, et, cy0) = if l {
            (110, 190, 245, 275, 325, 360, 410)
        } else {
            (150, 250, 316, 350, 414, 452, 506)
        };
        v.push(Item::Icon { kind: icon, rect: rect(cx - 40, icy - 40, 80, 80) });
        v.push(txt(kind_text, cx, ky, F::Title, Align::Center, INK));
        v.push(txt("From", cx, fy, F::Small, Align::Center, DIM));
        v.push(txt(fit(F::Bold, &req.requester, iw), cx, ry, F::Bold, Align::Center, INK));
        v.push(txt("Entry", cx, ey, F::Small, Align::Center, DIM));
        v.push(txt(fit(F::Title, &req.title, iw), cx, et, F::Title, Align::Center, INK));
        let lines = wrap(F::Body, &req.context, iw, 3);
        for (i, ln) in lines.iter().enumerate() {
            v.push(txt(ln.clone(), cx, cy0 + 20 + i as i32 * 34, F::Body, Align::Center, DIM));
        }
        if l {
            v.push(Item::Btn(Btn::new(rect(500, 70, 436, 190), Id::Approve, "Approve", Style::Primary).font(F::Big)));
            v.push(Item::Btn(Btn::new(rect(500, 276, 436, 110), Id::Deny, "Deny", Style::Outline).font(F::Title)));
        } else {
            v.extend(button_stack(
                sz,
                h - 24,
                vec![(Id::Approve, "Approve", Style::Primary, true), (Id::Deny, "Deny", Style::Outline, true)],
                120,
            ).into_iter().map(|it| match it {
                Item::Btn(b) if b.id == Id::Approve => Item::Btn(Btn { rect: rect(24, h - 24 - 130 - 12 - 120, (w - 48) as u32, 130), font: F::Big, ..b }),
                other => other,
            }));
        }
    }

    fn settings_blocks(&self, sz: Size) -> Vec<(i32, Vec<Item>)> {
        // Each block is positioned relative to y = 0 (shifted later).
        let w = sz.width as i32;
        let s = &self.settings;
        let mut blocks: Vec<(i32, Vec<Item>)> = Vec::new();
        let seg = |label: &str, opts: Vec<(Id, &str, bool)>| -> (i32, Vec<Item>) {
            let mut items = vec![txt(label, 24, 18, F::Small, Align::Left, DIM)];
            let cols = hsplit(16, w - 32, opts.len(), 8);
            for ((id, l, sel), (x, bw)) in opts.into_iter().zip(cols) {
                items.push(Item::Btn(Btn::new(rect(x, 40, bw as u32, 72), id, l, Style::Seg(sel))));
            }
            (124, items)
        };
        blocks.push(seg(
            "Auto-lock after",
            [(60, "1 min"), (180, "3 min"), (300, "5 min"), (600, "10 min")]
                .iter()
                .map(|(v, l)| (Id::AutoLock(*v), *l, s.auto_lock_secs == *v))
                .collect(),
        ));
        blocks.push(seg(
            "When locked",
            vec![(Id::Sleep(SleepMode::PowerOff), "Power off", s.sleep_mode == SleepMode::PowerOff), (Id::Sleep(SleepMode::LightSleep), "Stay reachable", s.sleep_mode == SleepMode::LightSleep)],
        ));
        blocks.push(seg(
            "Keyboard layout",
            vec![(Id::Kbd(KeyboardLayout::Us), "US", s.keyboard_layout == KeyboardLayout::Us), (Id::Kbd(KeyboardLayout::FrAzerty), "FR AZERTY", s.keyboard_layout == KeyboardLayout::FrAzerty)],
        ));
        blocks.push(seg(
            "Orientation",
            vec![(Id::Orient(Orientation::Portrait), "Portrait", s.orientation == Orientation::Portrait), (Id::Orient(Orientation::Landscape), "Landscape", s.orientation == Orientation::Landscape)],
        ));
        blocks.push(seg("Buzzer", vec![(Id::Buzzer(true), "On", s.buzzer), (Id::Buzzer(false), "Off", !s.buzzer)]));
        let hosts_header: Vec<Item> = vec![txt(format!("Paired hosts ({})", self.hosts.len()), 24, 26, F::Bold, Align::Left, INK), rule(16, w - 16, 48, INK)];
        let first_host_block = blocks.len();
        if self.hosts.is_empty() {
            blocks.push((60, vec![txt("No paired hosts", 24, 30, F::Body, Align::Left, DIM)]));
        }
        for (i, hst) in self.hosts.iter().enumerate() {
            let mut items = vec![
                txt(fit(F::Bold, &hst.label, w - 200), 24, 26, F::Bold, Align::Left, INK),
                txt(
                    if hst.last_seen > 0 { format!("Last seen {}", fmt_datetime(hst.last_seen, self.status.tz_secs)) } else { "Never seen".into() },
                    24,
                    58,
                    F::Small,
                    Align::Left,
                    DIM,
                ),
            ];
            items.push(Item::Btn(Btn::new(rect(w - 156, 8, 140, 68), Id::RemoveHost(i), "Remove", Style::Outline).font(F::Body)));
            blocks.push((84, items));
        }
        let mut hdr = hosts_header;
        let (bh0, items0) = blocks.remove(first_host_block);
        hdr.extend(items0.into_iter().map(|i| shift(i, 50)));
        blocks.insert(first_host_block, (bh0 + 50, hdr));
        blocks.push((92, vec![Item::Btn(Btn::new(rect(16, 6, (w - 32) as u32, 80), Id::PairNew, "Pair new host", Style::Outline))]));
        blocks.push((92, vec![Item::Btn(Btn::new(rect(16, 6, (w - 32) as u32, 80), Id::WipeStart, "Wipe device", Style::Outline))]));
        blocks
    }

    /// Greedy page assignment of settings blocks.
    fn settings_paged(&self, sz: Size) -> Vec<Vec<(i32, Vec<Item>)>> {
        let avail = pager_rect(sz).top_left.y - 8 - content_top(sz);
        let mut pages: Vec<Vec<(i32, Vec<Item>)>> = vec![Vec::new()];
        let mut used = 0;
        for b in self.settings_blocks(sz) {
            if used + b.0 > avail && !pages.last().unwrap().is_empty() {
                pages.push(Vec::new());
                used = 0;
            }
            used += b.0;
            pages.last_mut().unwrap().push(b);
        }
        pages
    }

    fn settings_items(&self, sz: Size, page: usize, v: &mut Vec<Item>) {
        v.extend(header(sz, "Settings", true));
        let pages = self.settings_paged(sz);
        let np = pages.len();
        let page = page.min(np - 1);
        let mut y = content_top(sz);
        for (bh, items) in pages.into_iter().nth(page).unwrap() {
            for it in items {
                v.push(shift(it, y));
            }
            y += bh;
        }
        v.extend(self.pager(sz, page, np));
    }
}

fn shift(it: Item, dy: i32) -> Item {
    let mv = |r: Rectangle| Rectangle::new(r.top_left + Point::new(0, dy), r.size);
    match it {
        Item::Btn(mut b) => {
            b.rect = mv(b.rect);
            b.inner = b.inner.into_iter().map(|i| shift(i, dy)).collect();
            Item::Btn(b)
        }
        Item::Text { s, x, cy, font, align, color } => Item::Text { s, x, cy: cy + dy, font, align, color },
        Item::Fill { rect, color } => Item::Fill { rect: mv(rect), color },
        Item::Frame { rect, fill, border } => Item::Frame { rect: mv(rect), fill, border },
        other => other,
    }
}

// ---- lock screen -------------------------------------------------------------------------------

/// Battery gauge + percentage, then clock icon + date/time, centred on cx as one row.
fn lock_status_row(cx: i32, cy: i32, pct: u8, when: Option<&str>, fg: Gray4, bg: Gray4, v: &mut Vec<Item>) {
    let pct_s = format!("{pct}%");
    let pw = crate::gfx::text_width(F::Body, &pct_s);
    let mut total = 46 + 10 + pw;
    let ww = when.map(|w| crate::gfx::text_width(F::Body, w)).unwrap_or(0);
    if when.is_some() {
        total += 36 + 30 + 10 + ww;
    }
    let mut x = cx - total / 2;
    v.push(Item::Battery { x, cy, pct, fg, bg });
    x += 46 + 10;
    v.push(Item::Text { s: pct_s, x, cy, font: F::Body, align: Align::Left, color: fg });
    x += pw + 36;
    if let Some(w) = when {
        v.push(Item::IconC { kind: Icon::Clock, rect: rect(x, cy - 15, 30, 30), fg, bg });
        x += 30 + 10;
        v.push(Item::Text { s: w.to_string(), x, cy, font: F::Body, align: Align::Left, color: fg });
    }
}

/// Power symbol + arrow in the bottom-right corner, pointing at the power button.
fn lock_power_hint(sz: Size, fg: Gray4, bg: Gray4, v: &mut Vec<Item>) {
    let (w, h) = (sz.width as i32, sz.height as i32);
    v.push(Item::IconC { kind: Icon::Power, rect: rect(w - 118, h - 76, 44, 44), fg, bg });
    v.push(Item::IconC { kind: Icon::Arrow, rect: rect(w - 64, h - 72, 44, 36), fg, bg });
}

fn lock_owner(cx: i32, cy: i32, owner: Option<&str>, color: Gray4, v: &mut Vec<Item>) {
    if let Some(o) = owner {
        for (i, ln) in wrap(F::Small, o, 440, 2).iter().enumerate() {
            v.push(Item::Text { s: ln.clone(), x: cx, cy: cy + i as i32 * 26, font: F::Small, align: Align::Center, color });
        }
    }
}

/// Lock screen: top half black (lock + title), bottom half white (brand, status, power hint).
fn lock_split(sz: Size, pct: u8, when: Option<&str>, owner: Option<&str>, v: &mut Vec<Item>) {
    let (w, h) = (sz.width as i32, sz.height as i32);
    let cx = w / 2;
    let split = h * 54 / 100;
    v.push(Item::Fill { rect: rect(0, 0, w as u32, split as u32), color: INK });
    let ic = 130.min(h / 6);
    v.push(Item::IconC { kind: Icon::Lock, rect: rect(cx - ic / 2, split / 2 - ic + 10, ic as u32, ic as u32), fg: PAPER, bg: INK });
    v.push(Item::Text { s: "LOCKED".into(), x: cx, cy: split / 2 + 70, font: F::Big, align: Align::Center, color: PAPER });
    v.push(Item::Text { s: "Tessera Prism".into(), x: cx, cy: split - 50, font: F::Title, align: Align::Center, color: PAPER });
    v.push(Item::Brand { cx, cy: split + 70, large: true, inverted: false });
    lock_status_row(cx, split + 170, pct, when, INK, PAPER, v);
    lock_owner(cx, split + 230, owner, DIM, v);
    lock_power_hint(sz, INK, PAPER, v);
}
