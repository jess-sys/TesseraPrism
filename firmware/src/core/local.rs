//! Actions that originate on the device itself (touch UI): PIN entry, setup wizard, browsing,
//! reveal/type, settings, wipe; plus lock/unlock transitions. The user is physically present and
//! the vault is open, so these need no extra approval tap.
use std::sync::atomic::Ordering;

use prism_core::model::{Entry, EntryData, EntryKind, SecretField, SecretValue, Settings};
use prism_core::{totp, Error as CoreError, KekHardener, NoHardening, UnlockedVault};

use crate::hardening::EfuseHmac;

/// Used when the PIN slot is recorded as hardened but the eFuse key cannot be used: never falls
/// back to the unhardened KEK (the unlock simply fails).
struct Unavailable;
impl KekHardener for Unavailable {
    fn harden(&self, _k: [u8; 32]) -> [u8; 32] {
        [0u8; 32]
    }
}
use prism_ui::{DetailField, DetailInfo, TotpView, UiAction, UiEvent};
use zeroize::Zeroizing;

use super::approval::Outcome;
use super::msg::{Mode, PowerMsg};
use super::requests::{secret_value, totp_ref};
use super::Core;
use crate::storage::MAX_PIN_FAILS;
use crate::transport::TransportCommand;

impl Core {
    pub(super) fn on_ui_action(&mut self, a: UiAction) {
        match a {
            UiAction::Activity | UiAction::InvalidInput => {} // handled by the UI task
            UiAction::SubmitPin(pin) => self.submit_pin(pin),
            UiAction::SetupPin(pin) => self.setup_pin(pin),
            UiAction::SetupConfirmedSeed => self.setup_confirmed(),
            UiAction::Approve(id) => self.ui_answer(id, Outcome::Approved),
            UiAction::Deny(id) => self.ui_answer(id, Outcome::Denied),
            UiAction::OpenList(kind) => {
                if let Some(v) = &self.vault {
                    let entries = v.list_summaries(Some(kind));
                    self.ui(UiEvent::EntryList { kind, entries });
                }
            }
            UiAction::OpenEntry(id) => {
                if let Some(e) = self.vault.as_ref().and_then(|v| v.get_entry(&id)) {
                    let info = self.detail_info(e);
                    self.ui(UiEvent::EntryDetail(info));
                }
            }
            UiAction::RevealSecret(id, field) => self.reveal(id, field),
            UiAction::TypeEntry(id, field) => {
                let text = self.vault.as_ref().and_then(|v| v.get_entry(&id)).and_then(|e| secret_value(e, field));
                if let Some(SecretValue::Text(ref t)) = text {
                    self.type_text(Zeroizing::new(t.clone()));
                }
            }
            UiAction::TypeTotp(id) => {
                let code = self.vault.as_ref().and_then(|v| v.get_entry(&id)).and_then(totp_ref).map(|t| totp::code(t, self.now()));
                if let Some(c) = code {
                    self.type_text(Zeroizing::new(c));
                }
            }
            UiAction::RequestTotp(id) => self.request_totp(id),
            UiAction::Lock => {
                if self.initialized {
                    self.lock();
                }
            }
            UiAction::PowerOff => {
                if self.initialized {
                    self.lock();
                }
                self.power(PowerMsg::ForceOff);
            }
            UiAction::StartPairing => self.start_pairing(),
            UiAction::ConfirmPairing(ok) => self.confirm_pairing(ok),
            UiAction::ChangeSettings(s) => self.apply_settings(s, false),
            UiAction::RemovePairedHost(key) => {
                self.hosts.retain(|h| h.public_key != key);
                if let Err(e) = self.store().set_hosts(&self.hosts) {
                    log::error!("saving hosts: {e:#}");
                }
                self.ui(UiEvent::PairedHosts(self.hosts.clone()));
            }
            UiAction::Wipe => self.wipe(),
        }
    }

    fn ui_answer(&mut self, id: u32, outcome: Outcome) {
        if matches!(&self.broker.active, Some((p, _)) if p.ui.id == id) {
            self.approval_resolve(outcome);
        }
    }

    fn type_text(&mut self, text: Zeroizing<String>) {
        if !self.status.usb_cfg.load(Ordering::Relaxed) {
            self.ui(UiEvent::Message { text: "No USB host connected.".into(), error: true });
            return;
        }
        let layout = self.settings.keyboard_layout;
        self.tx(TransportCommand::TypeText { text, layout });
    }

    fn reveal(&mut self, id: prism_core::model::EntryId, field: SecretField) {
        let Some(e) = self.vault.as_ref().and_then(|v| v.get_entry(&id)) else { return };
        if let (EntryData::RecoveryCodes(r), SecretField::RecoveryCodes) = (&e.data, field) {
            let codes = r.codes.clone();
            self.ui(UiEvent::RecoveryCodes { id, codes });
            return;
        }
        if let Some(value) = secret_value(e, field) {
            self.ui(UiEvent::SecretRevealed { id, field, value });
        }
    }

    fn request_totp(&mut self, id: prism_core::model::EntryId) {
        if !self.clock.is_valid() {
            self.ui(UiEvent::Message { text: "Clock not set. Connect a host once to sync the time.".into(), error: true });
            return;
        }
        let now = self.now();
        let Some(e) = self.vault.as_ref().and_then(|v| v.get_entry(&id)) else { return };
        let Some(t) = totp_ref(e) else { return };
        let until = totp::valid_until(t, now);
        let view = TotpView {
            id,
            issuer: t.issuer.clone(),
            account: t.account.clone(),
            code: Zeroizing::new(totp::code(t, now)),
            next: Some(Zeroizing::new(totp::code(t, until))),
            remaining_secs: until.saturating_sub(now) as u32,
            period: t.period.max(1),
        };
        self.ui(UiEvent::Totp(view));
    }

    fn detail_info(&self, e: &Entry) -> DetailInfo {
        let f = |l: &str, v: String| DetailField { label: l.into(), value: v };
        let mut fields = Vec::new();
        let mut reveal = None;
        match &e.data {
            EntryData::Password(p) => {
                fields.push(f("Username", p.username.clone()));
                if let Some(u) = &p.url {
                    fields.push(f("URL", u.clone()));
                }
                if p.totp.is_some() {
                    fields.push(f("TOTP", "configured".into()));
                }
                reveal = Some(SecretField::Password);
            }
            EntryData::Totp(t) => {
                fields.push(f("Issuer", t.issuer.clone()));
                fields.push(f("Account", t.account.clone()));
            }
            EntryData::Passkey(p) => {
                fields.push(f("Site", p.rp_id.clone()));
                fields.push(f("User", p.user_name.clone()));
            }
            EntryData::SshKey(k) => {
                fields.push(f("Type", "Ed25519".into()));
                fields.push(f("Comment", k.comment.clone()));
                fields.push(f("Public key", prism_core::vault::ssh_openssh_line(&k.public_key, "")));
            }
            EntryData::RecoveryCodes(r) => {
                fields.push(f("Service", r.service.clone()));
                let left = r.codes.iter().filter(|c| !c.used).count();
                fields.push(f("Codes left", format!("{left}/{}", r.codes.len())));
                reveal = Some(SecretField::RecoveryCodes);
            }
        }
        fields.push(f("Approval", format!("{:?}", e.policy)));
        if !e.tags.is_empty() {
            fields.push(f("Tags", e.tags.join(", ")));
        }
        DetailInfo {
            summary: e.summary(),
            fields,
            reveal,
            can_type: self.status.usb_cfg.load(Ordering::Relaxed) && matches!(e.data, EntryData::Password(_)),
        }
    }

    pub(super) fn apply_settings(&mut self, s: Settings, from_host: bool) {
        crate::sound::set_enabled(s.buzzer);
        self.settings = s.clone();
        if let Err(e) = self.store().set_settings(&s) {
            log::error!("saving settings: {e:#}");
        }
        self.power(PowerMsg::Settings(s.clone()));
        if from_host {
            self.ui(UiEvent::SettingsLoaded(s));
        }
    }

    // ---- lock / unlock -----------------------------------------------------------------------

    pub(super) fn finish_unlock(&mut self, uv: UnlockedVault) {
        self.vault = Some(uv);
        self.session_approved.clear();
        self.pp_fails = 0;
        let c = self.counts();
        self.ui(UiEvent::Unlocked(c));
        self.set_mode(Mode::Unlocked);
        self.activity();
        self.sound(crate::sound::Sound::Unlocked);
        log::info!("vault unlocked ({} entries)", self.vault.as_ref().map(|v| v.vault.entries.len()).unwrap_or(0));
    }

    /// Zeroize everything secret and show the lock screen. Safe to call when already locked.
    pub(super) fn lock(&mut self) {
        if self.vault.is_some() {
            self.sound(crate::sound::Sound::Lock);
        }
        self.vault = None; // UnlockedVault zeroizes seed + DEK on drop
        self.setup = None;
        self.import = None;
        self.export = None;
        self.pending_replace = None;
        self.session_approved.clear();
        self.approval_cancel_all();
        let now = self.now();
        let last_used = self.clock.is_valid().then_some(now);
        {
            let mut s = self.store();
            if let Some(t) = last_used {
                let _ = s.set_last_used(t);
            }
            let _ = s.set_hosts(&self.hosts);
        }
        let (pct, _) = self.battery();
        let last_used = last_used.or_else(|| self.store().last_used());
        self.ui(UiEvent::Locked { battery_pct: pct, last_used });
        self.set_mode(Mode::LockScreen);
        log::info!("locked");
    }

    pub(super) fn submit_pin(&mut self, pin: Zeroizing<String>) {
        if self.pending_replace.is_some() {
            self.complete_replace(&pin);
            return;
        }
        if self.vault.is_some() || !self.initialized {
            return;
        }
        let Some(bytes) = self.vault_store.load() else {
            self.ui(UiEvent::Message { text: "Vault unreadable.".into(), error: true });
            return;
        };
        // Count the attempt BEFORE checking, so cutting power mid-check cannot dodge the counter.
        let fails = self.store().pin_fails();
        let used = fails.saturating_add(1);
        if let Err(e) = self.store().set_pin_fails(used) {
            log::error!("pin counter write failed: {e:#}");
        }
        let hardened = self.store().pin_hardened();
        let result = if hardened {
            UnlockedVault::unlock_with_pin(&bytes, &pin, &*self.pin_hardener())
        } else {
            // Legacy (pre-eFuse) slot; if that fails, the slot may already be hardened (crash between
            // re-wrapping and recording the flag).
            match UnlockedVault::unlock_with_pin(&bytes, &pin, &NoHardening) {
                Err(CoreError::BadCredential) => match EfuseHmac::existing() {
                    Some(h) => UnlockedVault::unlock_with_pin(&bytes, &pin, &h).inspect(|_| {
                        let _ = self.store().set_pin_hardened(true);
                    }),
                    None => Err(CoreError::BadCredential),
                },
                r => r,
            }
        };
        match result {
            Ok(uv) => {
                let _ = self.store().set_pin_fails(0);
                self.finish_unlock(uv);
                if !self.store().pin_hardened() {
                    self.harden_pin_slot(&pin);
                }
            }
            Err(CoreError::BadCredential) => {
                if used >= MAX_PIN_FAILS {
                    log::warn!("too many wrong PINs: wiping");
                    self.wipe();
                } else {
                    self.sound(crate::sound::Sound::Error);
                    self.ui(UiEvent::PinRejected { attempts_left: MAX_PIN_FAILS - used });
                }
            }
            Err(CoreError::Kdf(e)) => {
                // Not a wrong PIN: the key derivation could not produce a stable result.
                log::error!("unlock: {e}");
                let _ = self.store().set_pin_fails(fails);
                self.ui(UiEvent::Message { text: "Hardware glitch while checking the PIN (not counted as a wrong PIN). Please try again.".into(), error: true });
            }
            Err(e) => {
                log::error!("unlock failed: {e}");
                let _ = self.store().set_pin_fails(fails);
                self.ui(UiEvent::Message { text: "Vault is corrupt or unsupported.".into(), error: true });
            }
        }
    }

    /// KEK hardener for the PIN slot as currently stored.
    pub(super) fn pin_hardener(&self) -> Box<dyn KekHardener> {
        if !self.store().pin_hardened() {
            return Box::new(NoHardening);
        }
        match EfuseHmac::existing() {
            Some(h) => Box::new(h),
            None => {
                log::error!("PIN slot is eFuse-hardened but no HMAC key block was found");
                Box::new(Unavailable)
            }
        }
    }

    /// One-time migration: provision the eFuse HMAC key if needed and re-wrap the PIN slot with the
    /// hardened KEK. Order matters: persist the re-wrapped vault, THEN record the flag (unlock
    /// tolerates a crash in between). Failures leave the legacy slot working.
    fn harden_pin_slot(&mut self, pin: &str) {
        let h = match EfuseHmac::existing_or_provision().and_then(|h| h.check().map(|_| h)) {
            Ok(h) => h,
            Err(e) => {
                log::error!("eFuse PIN hardening unavailable: {e:#}");
                self.ui(UiEvent::Message { text: format!("Hardware PIN protection could not be enabled: {e:#}"), error: true });
                return;
            }
        };
        let Some(v) = self.vault.as_mut() else { return };
        if let Err(e) = v.change_pin(pin, &h, &mut self.rng) {
            log::error!("re-wrapping the PIN slot failed: {e}");
            return;
        }
        match self.persist() {
            Ok(()) => {
                let _ = self.store().set_pin_hardened(true);
                log::info!("PIN slot is now bound to the eFuse HMAC key");
                self.ui(UiEvent::Message {
                    text: "Your PIN is now bound to this device's secure hardware: a copy of the flash can no longer be used to guess it.".into(),
                    error: false,
                });
            }
            Err(e) => {
                log::error!("saving the hardened PIN slot failed: {e:?}");
                self.ui(UiEvent::Message { text: "Hardware PIN protection could not be saved; will retry next unlock.".into(), error: true });
            }
        }
    }

    // ---- setup wizard --------------------------------------------------------------------------

    fn setup_pin(&mut self, pin: Zeroizing<String>) {
        if self.initialized {
            return;
        }
        let hw = match EfuseHmac::existing_or_provision().and_then(|h| h.check().map(|_| h)) {
            Ok(h) => Some(h),
            Err(e) => {
                log::error!("eFuse PIN hardening unavailable, creating an unhardened PIN slot: {e:#}");
                None
            }
        };
        self.setup_hardened = hw.is_some();
        let hardener: &dyn KekHardener = match &hw {
            Some(h) => h,
            None => &NoHardening,
        };
        match UnlockedVault::create(&pin, hardener, &mut self.rng) {
            Ok((uv, mnemonic)) => {
                let words: Vec<String> = mnemonic.words().into_iter().map(String::from).collect();
                self.setup = Some(uv);
                self.ui(UiEvent::SetupSeed { words: Zeroizing::new(words) });
            }
            Err(e) => {
                log::error!("vault create failed: {e}");
                self.ui(UiEvent::Message { text: "Could not create the vault (PIN must be 6-12 digits).".into(), error: true });
            }
        }
    }

    fn setup_confirmed(&mut self) {
        let Some(mut uv) = self.setup.take() else { return };
        let bytes = match uv.seal(&mut self.rng) {
            Ok(b) => b,
            Err(e) => {
                log::error!("seal failed: {e}");
                return;
            }
        };
        if let Err(e) = self.vault_store.store(&bytes, uv.generation()) {
            log::error!("storing new vault failed: {e:#}");
            self.ui(UiEvent::Message { text: "Saving the vault failed.".into(), error: true });
            return;
        }
        self.initialized = true;
        let _ = self.store().set_pin_hardened(self.setup_hardened);
        let _ = self.store().set_pin_fails(0);
        let s = self.settings.clone();
        let _ = self.store().set_settings(&s);
        self.finish_unlock(uv);
    }

    /// Erase vault + settings + paired hosts (keeps the device identity key) and restart setup.
    pub(super) fn wipe(&mut self) {
        self.vault = None;
        self.setup = None;
        self.import = None;
        self.export = None;
        self.pending_replace = None;
        self.session_approved.clear();
        self.approval_cancel_all();
        if let Err(e) = self.vault_store.wipe() {
            log::error!("vault wipe failed: {e:#}");
        }
        let _ = self.store().wipe();
        self.initialized = false;
        self.hosts.clear();
        self.settings = Settings::default();
        self.sessions.clear();
        self.ui(UiEvent::SettingsLoaded(self.settings.clone()));
        self.ui(UiEvent::PairedHosts(Vec::new()));
        self.power(PowerMsg::Settings(self.settings.clone()));
        self.ui(UiEvent::BootComplete { initialized: false });
        self.set_mode(Mode::Setup);
        log::warn!("device wiped");
    }
}

#[allow(dead_code)]
fn _kinds(_: EntryKind) {}
