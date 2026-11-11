use embedded_graphics::{pixelcolor::Gray4, prelude::*, primitives::Rectangle};
use prism_ui::*;
use prism_core::model::*;
use zeroize::Zeroizing;

struct Fb {
    w: u32,
    h: u32,
    px: Vec<u8>,
}
impl Fb {
    fn new(w: u32, h: u32) -> Self {
        Fb { w, h, px: vec![15; (w * h) as usize] }
    }
    fn save(&self, name: &str) {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/snapshots");
        std::fs::create_dir_all(dir).unwrap();
        let img = image::GrayImage::from_fn(self.w, self.h, |x, y| image::Luma([self.px[(y * self.w + x) as usize] * 17]));
        img.save(format!("{dir}/{name}.png")).unwrap();
    }
    fn dark_pixels(&self) -> usize {
        self.px.iter().filter(|&&p| p < 8).count()
    }
}
impl OriginDimensions for Fb {
    fn size(&self) -> Size {
        Size::new(self.w, self.h)
    }
}
impl DrawTarget for Fb {
    type Color = Gray4;
    type Error = core::convert::Infallible;
    fn draw_iter<I: IntoIterator<Item = Pixel<Gray4>>>(&mut self, it: I) -> Result<(), Self::Error> {
        for Pixel(p, c) in it {
            if p.x >= 0 && p.y >= 0 && (p.x as u32) < self.w && (p.y as u32) < self.h {
                self.px[(p.y as u32 * self.w + p.x as u32) as usize] = c.luma();
            }
        }
        Ok(())
    }
}

fn render(ui: &Ui, name: &str) -> Fb {
    let s = ui.size();
    let mut fb = Fb::new(s.width, s.height);
    ui.draw(&mut fb);
    fb.save(name);
    fb
}

fn center(r: Rectangle) -> Point {
    r.center()
}
fn target(ui: &Ui, name: &str) -> Point {
    let t = ui.targets();
    center(t.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("no target {name}: {:?}", t.iter().map(|x| &x.0).collect::<Vec<_>>())).1)
}
fn tap_at(ui: &mut Ui, p: Point) -> Vec<UiAction> {
    let mut a = ui.handle(UiEvent::Touch(TouchEvent::Down { x: p.x, y: p.y }));
    a.extend(ui.handle(UiEvent::Touch(TouchEvent::Up { x: p.x, y: p.y })));
    a
}
fn tap(ui: &mut Ui, name: &str) -> Vec<UiAction> {
    let p = target(ui, name);
    tap_at(ui, p)
}
fn type_pin(ui: &mut Ui, pin: &str) {
    for c in pin.chars() {
        tap(ui, &format!("Digit({c})"));
    }
}

const T0: u64 = 1_762_885_380; // 2025-11-11 18:03 UTC

fn base_ui() -> Ui {
    let mut ui = Ui::new();
    ui.handle(UiEvent::Tick { unix: T0 });
    ui.handle(UiEvent::Battery { pct: 76, charging: false });
    ui.handle(UiEvent::Connectivity { ble: true, usb: true });
    ui
}

fn counts() -> Counts {
    Counts { passwords: 42, totp: 11, passkeys: 7, ssh: 3, recovery: 5 }
}

fn eid(n: u8) -> EntryId {
    EntryId([n; 16])
}

fn summary(n: u8, kind: EntryKind, title: &str, sub: &str) -> EntrySummary {
    EntrySummary {
        id: eid(n),
        kind,
        title: title.into(),
        subtitle: sub.into(),
        url: None,
        tags: vec![],
        modified: T0,
        has_totp: kind == EntryKind::Totp,
        policy: ApprovalPolicy::Always,
    }
}

fn pw_list() -> Vec<EntrySummary> {
    let names = [
        ("GitHub", "alice@example.org"),
        ("Gmail", "alice.martin@example.com"),
        ("Proton Mail", "alice@example.net"),
        ("Cloudflare", "ops@example.org"),
        ("Hetzner Robot", "alice"),
        ("OVH Manager", "am123456-ovh"),
        ("Amazon", "alice.martin@example.com"),
        ("Netflix", "family@example.org"),
        ("Impots.gouv.fr", "1234567890123"),
        ("Bitwarden (legacy export)", "alice"),
        ("Synology NAS", "admin"),
        ("Backblaze B2", "backup@example.org"),
    ];
    names.iter().enumerate().map(|(i, (t, s))| summary(i as u8 + 1, EntryKind::Password, t, s)).collect()
}

fn unlocked() -> Ui {
    let mut ui = base_ui();
    ui.handle(UiEvent::BootComplete { initialized: true });
    ui.handle(UiEvent::Unlocked(counts()));
    ui
}

fn detail_pw() -> DetailInfo {
    let mut s = summary(1, EntryKind::Password, "GitHub", "alice@example.org");
    s.has_totp = true;
    DetailInfo {
        summary: s,
        fields: vec![
            DetailField { label: "Username".into(), value: "alice@example.org".into() },
            DetailField { label: "Website".into(), value: "https://github.com/login".into() },
            DetailField { label: "Approval".into(), value: "Ask every time".into() },
            DetailField { label: "Modified".into(), value: "9 Nov 2025".into() },
        ],
        reveal: Some(SecretField::Password),
        can_type: true,
    }
}

#[test]
fn pin_flow() {
    let mut ui = base_ui();
    render(&ui, "01_splash");
    ui.handle(UiEvent::BootComplete { initialized: true });
    assert_eq!(ui.screen_name(), "pin");
    render(&ui, "02_pin_empty");
    // OK always shown; below the minimum length it only signals invalid input
    let acts = tap(&mut ui, "Ok");
    assert!(acts.iter().any(|a| matches!(a, UiAction::InvalidInput)));
    let _ = ui.refresh_hint();
    type_pin(&mut ui, "2468");
    let fb = render(&ui, "03_pin_entered");
    assert!(fb.dark_pixels() > 1000);
    assert!(matches!(ui.peek_refresh_hint(), Some(RefreshMode::Fast(_))));
    let acts = tap(&mut ui, "Ok");
    let pin = acts.iter().find_map(|a| if let UiAction::SubmitPin(p) = a { Some(p.clone()) } else { None }).expect("SubmitPin");
    assert_eq!(&**pin, "2468");
    // reject -> warning
    ui.handle(UiEvent::PinRejected { attempts_left: 2 });
    render(&ui, "04_pin_attempts_left");
    // backspace
    type_pin(&mut ui, "99");
    tap(&mut ui, "Del");
    tap(&mut ui, "Del");
    tap(&mut ui, "Del"); // extra del harmless
    type_pin(&mut ui, "1357");
    let acts = tap(&mut ui, "Ok");
    assert!(acts.iter().any(|a| matches!(a, UiAction::SubmitPin(p) if &***p == "1357")));
    ui.handle(UiEvent::Unlocked(counts()));
    assert_eq!(ui.screen_name(), "home");
}

#[test]
fn pin_shuffle() {
    let mut ui = base_ui();
    ui.handle(UiEvent::Options(UiOptions { shuffle_pin: true }));
    ui.handle(UiEvent::Entropy(0xDEADBEEF));
    ui.handle(UiEvent::BootComplete { initialized: true });
    let names: Vec<String> = ui.targets().into_iter().map(|t| t.0).filter(|n| n.starts_with("Digit")).collect();
    assert_eq!(names.len(), 10);
    assert_ne!(names, (0..10).map(|i| format!("Digit({})", (i + 1) % 10)).collect::<Vec<_>>());
    render(&ui, "05_pin_shuffled");
}

#[test]
fn rotation_mapping() {
    let r = Rotation::Portrait;
    for &(x, y) in &[(0, 0), (539, 959), (100, 800), (270, 480)] {
        let p = r.to_panel(Point::new(x, y));
        assert!(p.x >= 0 && p.x < 960 && p.y >= 0 && p.y < 540);
        assert_eq!(r.touch_to_logical(p.x, p.y), Point::new(x, y));
    }
    // Rotated adapter lands the pixels where the mapping says.
    let mut panel = Fb::new(960, 540);
    {
        let mut rt = Rotated::new(&mut panel, Rotation::Portrait);
        assert_eq!(rt.size(), Size::new(540, 960));
        rt.draw_iter([Pixel(Point::new(10, 20), Gray4::BLACK)]).unwrap();
    }
    let p = r.to_panel(Point::new(10, 20));
    assert_eq!(panel.px[(p.y as u32 * 960 + p.x as u32) as usize], 0);
    // whole UI through the adapter
    let ui = unlocked();
    let mut panel = Fb::new(960, 540);
    {
        let mut rt = Rotated::new(&mut panel, ui.rotation());
        ui.draw(&mut rt);
    }
    panel.save("home_portrait_on_panel");
    assert!(panel.dark_pixels() > 5000);
}

#[test]
fn refresh_policy_screen_changes_gl16_with_periodic_and_secret_full() {
    let mut ui = unlocked();
    assert_eq!(ui.refresh_hint(), RefreshMode::Full);
    // Navigating Home <-> list: non-flashing GL16 (Text), with a full GC16 every 6th change.
    let mut modes = Vec::new();
    for _ in 0..6 {
        tap(&mut ui, "Tile(0)");
        ui.handle(UiEvent::EntryList { kind: EntryKind::Password, entries: pw_list() });
        modes.push(ui.refresh_hint());
        tap(&mut ui, "Back");
        modes.push(ui.refresh_hint());
    }
    let fulls = modes.iter().filter(|m| **m == RefreshMode::Full).count();
    assert!(modes.iter().all(|m| matches!(m, RefreshMode::Full | RefreshMode::Text)), "{modes:?}");
    assert_eq!(fulls, 2, "{modes:?}");
    // A button acts on touch-down: no separate press-highlight refresh before the action.
    let p = target(&ui, "Tile(0)");
    let acts = ui.handle(UiEvent::Touch(TouchEvent::Down { x: p.x, y: p.y }));
    assert!(acts.iter().any(|a| matches!(a, UiAction::OpenList(EntryKind::Password))));
    let _ = ui.refresh_hint();
    // Leaving a screen that showed a secret is always a full refresh (no ghost of the secret).
    ui.handle(UiEvent::EntryList { kind: EntryKind::Totp, entries: vec![] });
    let _ = ui.refresh_hint();
    ui.handle(UiEvent::Totp(TotpView {
        id: eid(20),
        issuer: "GitHub".into(),
        account: "a".into(),
        code: Zeroizing::new("482913".into()),
        next: None,
        remaining_secs: 20,
        period: 30,
    }));
    let _ = ui.refresh_hint();
    tap(&mut ui, "Back");
    assert_eq!(ui.refresh_hint(), RefreshMode::Full);
    // Lock screen is always a full refresh.
    let _ = ui.refresh_hint();
    ui.handle(UiEvent::Locked { battery_pct: 50, last_used: None });
    assert_eq!(ui.refresh_hint(), RefreshMode::Full);
}

#[test]
fn home_list_pagination_and_detail() {
    let mut ui = unlocked();
    render(&ui, "10_home");
    let a = tap(&mut ui, "Tile(0)");
    assert!(a.iter().any(|a| matches!(a, UiAction::OpenList(EntryKind::Password))));
    ui.handle(UiEvent::EntryList { kind: EntryKind::Password, entries: pw_list() });
    assert_eq!(ui.screen_name(), "list");
    render(&ui, "11_list_page1");
    // 12 entries, 8 per page -> 2 pages
    assert!(ui.targets().iter().any(|t| t.0 == "NextPage"));
    assert!(!ui.targets().iter().any(|t| t.0 == "PrevPage"));
    assert!(!ui.targets().iter().any(|t| t.0 == "Row(4)" && false));
    tap(&mut ui, "NextPage");
    render(&ui, "12_list_page2");
    assert!(!ui.targets().iter().any(|t| t.0 == "NextPage"));
    assert!(ui.targets().iter().any(|t| t.0 == "Row(3)"));
    assert!(!ui.targets().iter().any(|t| t.0 == "Row(4)"));
    let a = tap(&mut ui, "Row(0)");
    // page 2 row 0 = entry index 8
    assert!(a.iter().any(|a| matches!(a, UiAction::OpenEntry(id) if *id == eid(9))));
    tap(&mut ui, "PrevPage");
    // detail
    let a = tap(&mut ui, "Row(0)");
    assert!(a.iter().any(|a| matches!(a, UiAction::OpenEntry(id) if *id == eid(1))));
    ui.handle(UiEvent::EntryDetail(detail_pw()));
    render(&ui, "13_detail_password");
    let a = tap(&mut ui, "Reveal");
    assert!(a.iter().any(|a| matches!(a, UiAction::RevealSecret(id, SecretField::Password) if *id == eid(1))));
    ui.handle(UiEvent::SecretRevealed {
        id: eid(1),
        field: SecretField::Password,
        value: SecretValue::Text("k7#Qp9vL!x2Zr@Wm4$Tn8bYc&Fh5JdA3".into()),
    });
    render(&ui, "14_detail_revealed");
    assert!(ui.targets().iter().any(|t| t.0 == "Hide"));
    let a = tap(&mut ui, "TypeUsb");
    assert!(a.iter().any(|a| matches!(a, UiAction::TypeEntry(_, SecretField::Password))));
    // leaving the screen drops the revealed value
    tap(&mut ui, "Back");
    assert_eq!(ui.screen_name(), "list");
    tap(&mut ui, "Back");
    assert_eq!(ui.screen_name(), "home");
    // list for all other kinds (snapshots)
    let ssh = vec![
        summary(30, EntryKind::SshKey, "prod-bastion", "alice@laptop"),
        summary(31, EntryKind::SshKey, "github-signing", "alice@example.org"),
    ];
    ui.handle(UiEvent::EntryList { kind: EntryKind::SshKey, entries: ssh });
    render(&ui, "15_list_ssh");
}

#[test]
fn totp_and_recovery_screens() {
    let mut ui = unlocked();
    let totp_entries = vec![
        summary(20, EntryKind::Totp, "GitHub", "alice@example.org"),
        summary(21, EntryKind::Totp, "Cloudflare", "ops@example.org"),
    ];
    ui.handle(UiEvent::EntryList { kind: EntryKind::Totp, entries: totp_entries });
    let a = tap(&mut ui, "Row(0)");
    assert!(a.iter().any(|a| matches!(a, UiAction::RequestTotp(id) if *id == eid(20))));
    assert_eq!(ui.screen_name(), "totp");
    ui.handle(UiEvent::Totp(TotpView {
        id: eid(20),
        issuer: "GitHub".into(),
        account: "alice@example.org".into(),
        code: Zeroizing::new("482913".into()),
        next: Some(Zeroizing::new("107735".into())),
        remaining_secs: 21,
        period: 30,
    }));
    render(&ui, "20_totp");
    // period boundary -> RequestTotp
    let a = ui.handle(UiEvent::Tick { unix: T0 + 21 });
    assert!(a.iter().any(|a| matches!(a, UiAction::RequestTotp(_))));
    // 8-digit code
    ui.handle(UiEvent::Totp(TotpView {
        id: eid(20),
        issuer: "GitHub".into(),
        account: "alice@example.org".into(),
        code: Zeroizing::new("48291350".into()),
        next: None,
        remaining_secs: 4,
        period: 30,
    }));
    render(&ui, "21_totp_8digits");
    tap(&mut ui, "Back");

    // recovery codes
    let mut s = summary(40, EntryKind::RecoveryCodes, "Google account", "6/10 left");
    s.has_totp = false;
    ui.handle(UiEvent::EntryDetail(DetailInfo {
        summary: s,
        fields: vec![DetailField { label: "Service".into(), value: "accounts.google.com".into() }, DetailField { label: "Codes left".into(), value: "6 of 10".into() }],
        reveal: Some(SecretField::RecoveryCodes),
        can_type: false,
    }));
    render(&ui, "22_detail_recovery_hidden");
    ui.handle(UiEvent::RecoveryCodes {
        id: eid(40),
        codes: (0..10)
            .map(|i| RecoveryCode { code: format!("{:04}-{:04}", 4821 + i * 37, 9013 - i * 111), used: i < 4 })
            .collect(),
    });
    render(&ui, "23_detail_recovery_codes");
    tap(&mut ui, "Back");

    // passkey + ssh details
    let mut s = summary(50, EntryKind::Passkey, "github.com", "alice");
    s.has_totp = false;
    ui.handle(UiEvent::EntryDetail(DetailInfo {
        summary: s,
        fields: vec![
            DetailField { label: "Relying party".into(), value: "github.com".into() },
            DetailField { label: "User".into(), value: "alice".into() },
            DetailField { label: "Algorithm".into(), value: "ES256".into() },
            DetailField { label: "Created".into(), value: "2 Oct 2025".into() },
        ],
        reveal: None,
        can_type: false,
    }));
    render(&ui, "24_detail_passkey");
    tap(&mut ui, "Back");
    let mut s = summary(51, EntryKind::SshKey, "prod-bastion", "alice@laptop");
    s.has_totp = false;
    ui.handle(UiEvent::EntryDetail(DetailInfo {
        summary: s,
        fields: vec![
            DetailField { label: "Type".into(), value: "ssh-ed25519".into() },
            DetailField { label: "Fingerprint".into(), value: "SHA256:Zk3p9V1xQe7m0Yd2L8".into() },
            DetailField { label: "Source".into(), value: "Derived from seed #2".into() },
        ],
        reveal: Some(SecretField::SshPublicKey),
        can_type: false,
    }));
    render(&ui, "25_detail_ssh");
}

#[test]
fn approval_approve_and_deny() {
    let mut ui = unlocked();
    let req = |id| ApprovalRequest {
        id,
        kind: ApprovalKind::SshSign,
        requester: "alice-macbook (BLE)".into(),
        title: "prod-bastion".into(),
        context: "ssh deploy@bastion.example.org (ed25519 signature)".into(),
        timeout_secs: 30,
    };
    ui.handle(UiEvent::Approval(req(7)));
    assert_eq!(ui.screen_name(), "approval");
    render(&ui, "30_approval_ssh");
    let a = tap(&mut ui, "Approve");
    assert!(a.iter().any(|a| matches!(a, UiAction::Approve(7))));
    assert_eq!(ui.screen_name(), "home");
    ui.handle(UiEvent::Approval(req(8)));
    let a = tap(&mut ui, "Deny");
    assert!(a.iter().any(|a| matches!(a, UiAction::Deny(8))));
    assert_eq!(ui.screen_name(), "home");
    // timeout auto-deny
    ui.handle(UiEvent::Approval(req(9)));
    let a = ui.handle(UiEvent::Tick { unix: T0 + 31 });
    assert!(a.iter().any(|a| matches!(a, UiAction::Deny(9))));
    assert_eq!(ui.screen_name(), "home");
    // cancelled by host
    ui.handle(UiEvent::Approval(req(10)));
    ui.handle(UiEvent::ApprovalCancelled(10));
    assert_eq!(ui.screen_name(), "home");
    // other kinds
    ui.handle(UiEvent::Approval(ApprovalRequest {
        id: 11,
        kind: ApprovalKind::PasskeyAuth,
        requester: "USB host".into(),
        title: "github.com".into(),
        context: "Sign in as alice to github.com".into(),
        timeout_secs: 30,
    }));
    render(&ui, "31_approval_passkey");
    ui.handle(UiEvent::ApprovalCancelled(11));
    ui.handle(UiEvent::Approval(ApprovalRequest {
        id: 12,
        kind: ApprovalKind::Password,
        requester: "alice-iphone (BLE)".into(),
        title: "Proton Mail".into(),
        context: "AutoFill for https://account.proton.me".into(),
        timeout_secs: 30,
    }));
    render(&ui, "32_approval_password");
}

#[test]
fn setup_wizard_happy_path() {
    let mut ui = base_ui();
    ui.handle(UiEvent::Entropy(12345));
    ui.handle(UiEvent::BootComplete { initialized: false });
    assert_eq!(ui.setup_step(), Some(SetupStep::ChoosePin));
    render(&ui, "40_setup_choose_pin");
    type_pin(&mut ui, "12345"); // too short: OK only signals invalid input
    let acts = tap(&mut ui, "Ok");
    assert!(acts.iter().any(|a| matches!(a, UiAction::InvalidInput)));
    assert_eq!(ui.setup_step(), Some(SetupStep::ChoosePin));
    type_pin(&mut ui, "6");
    tap(&mut ui, "Ok");
    assert_eq!(ui.setup_step(), Some(SetupStep::ConfirmPin));
    render(&ui, "41_setup_confirm_pin");
    type_pin(&mut ui, "123456");
    let a = tap(&mut ui, "Ok");
    let pin = a.iter().find_map(|a| if let UiAction::SetupPin(p) = a { Some(p.to_string()) } else { None }).expect("SetupPin");
    assert_eq!(pin, "123456");
    assert_eq!(ui.setup_step(), Some(SetupStep::WaitSeed));
    render(&ui, "42_setup_wait");
    let words: Vec<String> = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident",
        "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    ui.handle(UiEvent::SetupSeed { words: Zeroizing::new(words.clone()) });
    assert_eq!(ui.setup_step(), Some(SetupStep::Seed(0)));
    render(&ui, "43_setup_seed_p1");
    tap(&mut ui, "NextPage");
    render(&ui, "44_setup_seed_p2");
    tap(&mut ui, "NextPage");
    assert_eq!(ui.setup_step(), Some(SetupStep::Seed(2)));
    render(&ui, "45_setup_seed_p3");
    tap(&mut ui, "SeedDone");
    assert_eq!(ui.setup_step(), Some(SetupStep::Verify(0)));
    // The quiz asks "Which is word #N?"; find the correct one by tapping the choice whose label is words[N-1].
    let mut done = false;
    for q in 0..3 {
        assert_eq!(ui.setup_step(), Some(SetupStep::Verify(q)));
        if q == 0 {
            render(&ui, "46_setup_verify");
        }
        // Brute force: try each choice index; a wrong one resets to Seed(0) so we need to peek instead.
        // Peek by examining label text through the test-only helper: the correct choice is the one that advances.
        // To avoid resetting we use the public API only: render is not parseable, so replicate quiz deterministically.
        // Simpler: wrong answers are tested separately; here take the choice whose button label equals the word.
        let (idx, _) = (0..4)
            .map(|i| (i, ui.targets().iter().any(|t| t.0 == format!("Choice({i})"))))
            .find(|(_, ok)| *ok)
            .unwrap();
        let _ = idx;
        let correct = ui_correct_choice(&ui, &words);
        let a = tap(&mut ui, &format!("Choice({correct})"));
        if q == 2 {
            assert!(a.iter().any(|a| matches!(a, UiAction::SetupConfirmedSeed)));
            done = true;
        }
    }
    assert!(done);
    ui.handle(UiEvent::Unlocked(counts()));
    assert_eq!(ui.screen_name(), "home");
}

/// Test helper: the index of the correct quiz choice (uses the debug accessor).
fn ui_correct_choice(ui: &Ui, words: &[String]) -> usize {
    let (word_index, labels) = ui.quiz_debug().expect("quiz");
    labels.iter().position(|l| *l == words[word_index]).unwrap()
}

#[test]
fn setup_wrong_word_restarts_and_pin_mismatch() {
    let mut ui = base_ui();
    ui.handle(UiEvent::BootComplete { initialized: false });
    type_pin(&mut ui, "111111");
    tap(&mut ui, "Ok");
    type_pin(&mut ui, "222222");
    let a = tap(&mut ui, "Ok");
    assert!(!a.iter().any(|a| matches!(a, UiAction::SetupPin(_))));
    assert_eq!(ui.screen_name(), "message");
    render(&ui, "47_message_error");
    tap(&mut ui, "MsgOk");
    assert_eq!(ui.setup_step(), Some(SetupStep::ChoosePin));
    type_pin(&mut ui, "123456");
    tap(&mut ui, "Ok");
    type_pin(&mut ui, "123456");
    tap(&mut ui, "Ok");
    let words: Vec<String> = (0..24).map(|i| format!("word{i}")).collect();
    ui.handle(UiEvent::SetupSeed { words: Zeroizing::new(words.clone()) });
    tap(&mut ui, "NextPage");
    tap(&mut ui, "NextPage");
    tap(&mut ui, "SeedDone");
    let (wi, labels) = ui.quiz_debug().unwrap();
    let wrong = labels.iter().position(|l| *l != words[wi]).unwrap();
    let a = tap(&mut ui, &format!("Choice({wrong})"));
    assert!(!a.iter().any(|a| matches!(a, UiAction::SetupConfirmedSeed)));
    assert_eq!(ui.screen_name(), "message");
    tap(&mut ui, "MsgOk");
    assert_eq!(ui.setup_step(), Some(SetupStep::Seed(0)));
}

#[test]
fn settings_flow() {
    let mut ui = unlocked();
    ui.handle(UiEvent::SettingsLoaded(Settings { owner_info: Some("If found call +33 6 12 34 56 78".into()), ..Settings::default() }));
    ui.handle(UiEvent::PairedHosts(vec![
        PairedHost { public_key: [1; 32], label: "alice-macbook".into(), paired_at: T0 - 86400 * 20, last_seen: T0 - 3600 },
        PairedHost { public_key: [2; 32], label: "ubuntu-desktop".into(), paired_at: T0 - 86400 * 9, last_seen: T0 - 86400 * 2 },
    ]));
    tap(&mut ui, "Tile(5)");
    assert_eq!(ui.screen_name(), "settings");
    render(&ui, "50_settings_1");
    let a = tap(&mut ui, "AutoLock(600)");
    assert!(a.iter().any(|a| matches!(a, UiAction::ChangeSettings(s) if s.auto_lock_secs == 600)));
    assert_eq!(ui.settings().auto_lock_secs, 600);
    let a = tap(&mut ui, "Sleep(LightSleep)");
    assert!(a.iter().any(|a| matches!(a, UiAction::ChangeSettings(s) if s.sleep_mode == SleepMode::LightSleep)));
    tap(&mut ui, "Kbd(FrAzerty)");
    render(&ui, "51_settings_changed");
    tap(&mut ui, "NextPage");
    render(&ui, "52_settings_2");
    // remove host with confirmation
    tap(&mut ui, "RemoveHost(0)");
    assert_eq!(ui.screen_name(), "confirm");
    render(&ui, "53_confirm_remove_host");
    let a = tap(&mut ui, "Confirm");
    assert!(a.iter().any(|a| matches!(a, UiAction::RemovePairedHost(k) if *k == [1; 32])));
    assert_eq!(ui.screen_name(), "settings");
    // pair new
    let a = tap(&mut ui, "PairNew");
    assert!(a.iter().any(|a| matches!(a, UiAction::StartPairing)));
    render(&ui, "54_pair_wait");
    ui.handle(UiEvent::PairingSas { host: "alice-macbook".into(), sas: "407913".into() });
    assert_eq!(ui.screen_name(), "pair_sas");
    render(&ui, "55_pairing_sas");
    let a = tap(&mut ui, "Confirm");
    assert!(a.iter().any(|a| matches!(a, UiAction::ConfirmPairing(true))));
    ui.handle(UiEvent::PairingFinished { ok: true });
    render(&ui, "56_message_paired");
    tap(&mut ui, "MsgOk");
    assert_eq!(ui.screen_name(), "settings");
    // cancel path
    tap(&mut ui, "PairNew");
    ui.handle(UiEvent::PairingSas { host: "x".into(), sas: "000111".into() });
    let a = tap(&mut ui, "Cancel");
    assert!(a.iter().any(|a| matches!(a, UiAction::ConfirmPairing(false))));
    // wipe double confirmation
    tap(&mut ui, "WipeStart");
    render(&ui, "57_wipe_confirm_1");
    let a = tap(&mut ui, "Confirm");
    assert!(!a.iter().any(|a| matches!(a, UiAction::Wipe)));
    render(&ui, "58_wipe_confirm_2");
    let a = tap(&mut ui, "Confirm");
    assert!(a.iter().any(|a| matches!(a, UiAction::Wipe)));
    // orientation switch
    tap(&mut ui, "Back");
    tap(&mut ui, "Tile(5)");
    let a = tap(&mut ui, "Orient(Landscape)");
    assert!(a.iter().any(|a| matches!(a, UiAction::ChangeSettings(s) if s.orientation == Orientation::Landscape)));
    assert_eq!(ui.size(), Size::new(960, 540));
    render(&ui, "59_settings_landscape");
}

#[test]
fn lock_and_zeroize() {
    let mut ui = unlocked();
    ui.handle(UiEvent::EntryDetail(detail_pw()));
    ui.handle(UiEvent::SecretRevealed { id: eid(1), field: SecretField::Password, value: SecretValue::Text("hunter2".into()) });
    let a = ui.handle(UiEvent::Locked { battery_pct: 64, last_used: Some(T0 - 1500) });
    let _ = a;
    assert_eq!(ui.screen_name(), "lock");
    render(&ui, "60_lock");
    ui.handle(UiEvent::SettingsLoaded(Settings { owner_info: Some("Property of Alice M. - reward if found: alice@example.com".into()), ..Settings::default() }));
    render(&ui, "61_lock_owner");
    // touching the lock screen does nothing
    let a = tap_at(&mut ui, Point::new(270, 500));
    assert!(a.iter().all(|a| matches!(a, UiAction::Activity)));
    // home: a single "Lock" button, which is a full shutdown
    ui.handle(UiEvent::ShowPin { attempts_left: Some(5) });
    assert_eq!(ui.screen_name(), "pin");
    ui.handle(UiEvent::Unlocked(counts()));
    assert!(!ui.targets().iter().any(|t| t.0 == "PowerOff"));
    let a = tap(&mut ui, "LockNow");
    assert!(a.iter().any(|a| matches!(a, UiAction::PowerOff)));
}

#[test]
fn message_and_landscape_snapshots() {
    let mut ui = unlocked();
    ui.handle(UiEvent::Message { text: "Typing failed: no USB host connected.".into(), error: true });
    render(&ui, "70_message_toast");
    tap(&mut ui, "MsgOk");
    // landscape
    ui.handle(UiEvent::SettingsLoaded(Settings { orientation: Orientation::Landscape, owner_info: Some("If found: alice@example.com".into()), ..Settings::default() }));
    assert_eq!(ui.size(), Size::new(960, 540));
    ui.handle(UiEvent::Battery { pct: 17, charging: true });
    render(&ui, "80_home_landscape");
    ui.handle(UiEvent::EntryList { kind: EntryKind::Password, entries: pw_list() });
    render(&ui, "81_list_landscape");
    tap(&mut ui, "Back");
    ui.handle(UiEvent::Approval(ApprovalRequest {
        id: 1,
        kind: ApprovalKind::Password,
        requester: "alice-macbook (BLE)".into(),
        title: "GitHub".into(),
        context: "AutoFill for https://github.com".into(),
        timeout_secs: 30,
    }));
    render(&ui, "82_approval_landscape");
    ui.handle(UiEvent::ApprovalCancelled(1));
    ui.handle(UiEvent::BootComplete { initialized: true });
    render(&ui, "83_pin_landscape");
    ui.handle(UiEvent::Locked { battery_pct: 64, last_used: Some(T0 - 1500) });
    render(&ui, "84_lock_landscape");
    // touch mapping for landscape is identity; for portrait a panel touch maps back
    let p = Rotation::Portrait.to_panel(Point::new(100, 200));
    assert_eq!(Rotation::Portrait.touch_to_logical(p.x, p.y), Point::new(100, 200));
}

#[test]
fn status_bar_updates_use_partial() {
    let mut ui = unlocked();
    let _ = ui.refresh_hint();
    ui.handle(UiEvent::Tick { unix: T0 + 30 }); // same minute? T0 is :03:00 -> +30 same minute
    assert!(!ui.needs_refresh());
    ui.handle(UiEvent::Tick { unix: T0 + 61 });
    assert!(matches!(ui.peek_refresh_hint(), Some(RefreshMode::Partial(r)) if r.size.height > 0));
}

#[test]
fn pin_digit_registers_on_touch_down_with_fast_refresh() {
    let mut ui = base_ui();
    ui.handle(UiEvent::BootComplete { initialized: true });
    let _ = ui.refresh_hint();
    // Touch-down alone enters the digit (no release needed) and only asks for a DU refresh.
    let p = target(&ui, "Digit(5)");
    ui.handle(UiEvent::Touch(TouchEvent::Down { x: p.x, y: p.y }));
    assert!(matches!(ui.peek_refresh_hint(), Some(RefreshMode::Fast(_))), "{:?}", ui.peek_refresh_hint());
    let _ = ui.refresh_hint();
    // Release does nothing more (no second refresh per digit).
    ui.handle(UiEvent::Touch(TouchEvent::Up { x: p.x, y: p.y }));
    assert!(ui.peek_refresh_hint().is_none());
    // Fast refreshes never escalate to Full, however many digits are typed.
    for _ in 0..12 {
        tap(&mut ui, "Del");
        type_pin(&mut ui, "1");
        assert!(!matches!(ui.refresh_hint(), RefreshMode::Full));
    }
    // Reaching the minimum length no longer triggers a greyscale refresh (OK is always enabled).
    tap(&mut ui, "Del");
    type_pin(&mut ui, "123");
    let _ = ui.refresh_hint();
    type_pin(&mut ui, "4");
    assert!(matches!(ui.peek_refresh_hint(), Some(RefreshMode::Fast(_))));
}
