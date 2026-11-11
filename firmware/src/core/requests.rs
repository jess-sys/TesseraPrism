//! Prism protocol requests: lock/approval gating (`gate`), execution (`exec`), the approval
//! broker and the CTAP platform callbacks.
//!
//! | Request                                  | Locked        | Tap                                   |
//! |------------------------------------------|---------------|---------------------------------------|
//! | GetInfo, SetTime, GetSettings, Lock      | works         | no                                    |
//! | Unlock{passphrase}                       | (is the unlock)| no (passphrase is the proof)         |
//! | ListEntries, SshListKeys, ListPairedHosts, Export/Import chunks | Locked | no |
//! | SetSettings, RemovePairedHost | Locked | always |
//! | GetSecret / GetTotp / GetEntry / SshSign / MarkRecoveryCodeUsed | Locked | per entry policy (Always / Session once / Never) |
//! | AddEntry, UpdateEntry, DeleteEntry, GenerateSshKey, SetRecoveryPassphrase, TypeEntry, Export, ImportCommit | Locked | always |
//! | Ctap                                     | Locked        | Authenticator asks for presence       |
use std::time::{Duration, Instant};

use prism_core::export::{self, import};
use prism_core::model::{
    ApprovalPolicy, Entry, EntryData, EntryId, ImportMode, Passkey, SecretField, SecretValue, SshKeySource,
};
use prism_core::slots::KdfParams;
use prism_core::{totp, Error as CoreError, NoHardening, UnlockedVault};
use prism_ctap::{PresenceKind, PresenceResult, StorageError};
use prism_proto::{ErrorCode, Request, Response};
use prism_ui::{ApprovalKind, ApprovalRequest, UiEvent};
use zeroize::Zeroizing;

use super::approval::{Done, Outcome, Pending, APPROVAL_TIMEOUT};
use super::msg::{CtapJob, CtapReply, Mode, PlatformOp, PowerMsg};
use super::{link_name, Core, ImportBuf, PendingReplace, MAX_IMPORT_BYTES, PIN_PROMPT_TIMEOUT};
use crate::storage::MAX_VAULT_BYTES;
use crate::transport::{Link, TransportCommand};

pub(super) struct Spec {
    pub kind: ApprovalKind,
    pub title: String,
    pub context: String,
    pub session_mark: Option<EntryId>,
}

/// Strip control characters and cap the length of host-supplied text shown on the approval screen.
fn clean(s: &str, max: usize) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_control()).take(max).collect();
    if s.chars().count() > max {
        out.push('~');
    }
    out
}

fn field_name(f: SecretField) -> &'static str {
    match f {
        SecretField::Password => "password",
        SecretField::Username => "username",
        SecretField::Notes => "notes",
        SecretField::TotpSecret => "TOTP secret",
        SecretField::RecoveryCodes => "recovery codes",
        SecretField::SshPublicKey => "public key",
    }
}

/// Value of one field of an entry, if the entry has it.
pub(super) fn secret_value(e: &Entry, field: SecretField) -> Option<SecretValue> {
    match (&e.data, field) {
        (EntryData::Password(p), SecretField::Password) => Some(SecretValue::Text(p.password.clone())),
        (EntryData::Password(p), SecretField::Username) => Some(SecretValue::Text(p.username.clone())),
        (EntryData::Password(p), SecretField::Notes) => Some(SecretValue::Text(p.notes.clone())),
        (EntryData::Password(p), SecretField::TotpSecret) => p.totp.as_ref().map(|t| SecretValue::Bytes(t.secret.clone())),
        (EntryData::Totp(t), SecretField::TotpSecret) => Some(SecretValue::Bytes(t.secret.clone())),
        (EntryData::Totp(t), SecretField::Username) => Some(SecretValue::Text(t.account.clone())),
        (EntryData::RecoveryCodes(r), SecretField::RecoveryCodes) => {
            Some(SecretValue::List(r.codes.iter().filter(|c| !c.used).map(|c| c.code.clone()).collect()))
        }
        (EntryData::RecoveryCodes(r), SecretField::Notes) => Some(SecretValue::Text(r.notes.clone())),
        (EntryData::SshKey(k), SecretField::SshPublicKey) => {
            Some(SecretValue::Text(prism_core::vault::ssh_openssh_line(&k.public_key, &k.comment)))
        }
        (EntryData::Passkey(p), SecretField::Username) => Some(SecretValue::Text(p.user_name.clone())),
        _ => None,
    }
}

fn approval_kind_for(e: &Entry, field: Option<SecretField>) -> ApprovalKind {
    match (&e.data, field) {
        (_, Some(SecretField::TotpSecret)) => ApprovalKind::Totp,
        (EntryData::Totp(_), _) => ApprovalKind::Totp,
        (EntryData::RecoveryCodes(_), _) => ApprovalKind::RecoveryCodes,
        (EntryData::SshKey(_), _) => ApprovalKind::SshSign,
        (EntryData::Password(_), _) => ApprovalKind::Password,
        _ => ApprovalKind::Other,
    }
}

impl Core {
    // ---- gating --------------------------------------------------------------------------

    fn policy_gate(&self, e: &Entry, field: Option<SecretField>, context: String) -> Option<Spec> {
        let need = match e.policy {
            ApprovalPolicy::Always => true,
            ApprovalPolicy::Session => !self.session_approved.contains(&e.id),
            ApprovalPolicy::Never => false,
        };
        need.then(|| Spec {
            kind: approval_kind_for(e, field),
            title: clean(&e.title, 48),
            context,
            session_mark: (e.policy == ApprovalPolicy::Session).then_some(e.id),
        })
    }

    fn always(title: &str, context: &str) -> Spec {
        Spec { kind: ApprovalKind::Other, title: clean(title, 48), context: context.into(), session_mark: None }
    }

    /// Decide whether `req` may run and whether it needs a tap.
    fn gate(&self, req: &Request) -> Result<Option<Spec>, ErrorCode> {
        use Request::*;
        match req {
            GetInfo | SetTime { .. } | Lock | Unlock { .. } | GetSettings => return Ok(None),
            _ => {}
        }
        let Some(v) = &self.vault else { return Err(ErrorCode::Locked) };
        let lookup = |id: &EntryId| v.get_entry(id).ok_or(ErrorCode::NotFound);
        Ok(match req {
            // A paired host must not silently weaken auto-lock / sleep policy or evict other hosts.
            SetSettings { .. } => Some(Self::always("Device settings", "Change settings")),
            RemovePairedHost { public_key } => {
                let label = self.hosts.iter().find(|h| &h.public_key == public_key)
                    .map(|h| h.label.clone()).unwrap_or_else(|| "unknown host".into());
                Some(Self::always(&label, "Remove paired host"))
            }
            ListEntries { .. } | SshListKeys | ListPairedHosts
            | ExportChunk { .. } | ImportBegin { .. } | ImportChunk { .. } | Ctap { .. } => None,
            GetSecret { id, field, context } => {
                let e = lookup(id)?;
                let ctx = context.as_deref().map(|c| clean(c, 80)).unwrap_or_else(|| field_name(*field).to_string());
                self.policy_gate(e, Some(*field), ctx)
            }
            GetTotp { id } => {
                let e = lookup(id)?;
                self.policy_gate(e, Some(SecretField::TotpSecret), "one-time code".into())
            }
            GetEntry { id } => {
                let e = lookup(id)?;
                self.policy_gate(e, None, "full entry (edit)".into())
            }
            MarkRecoveryCodeUsed { id, .. } => {
                let e = lookup(id)?;
                self.policy_gate(e, Some(SecretField::RecoveryCodes), "mark code used".into())
            }
            SshSign { public_key, host_hint, .. } => {
                let e = v.find_ssh_entry(public_key).ok_or(ErrorCode::NotFound)?;
                let host = host_hint.as_deref().map(|h| clean(h, 60)).unwrap_or_else(|| "unknown host".into());
                self.policy_gate(e, None, format!("sign for {host}"))
            }
            AddEntry { entry } => Some(Self::always(&entry.title, "Add entry")),
            UpdateEntry { entry } => {
                let cur = lookup(&entry.id)?;
                Some(Self::always(&cur.title, "Update entry"))
            }
            DeleteEntry { id } => {
                let e = lookup(id)?;
                Some(Self::always(&e.title, "DELETE entry"))
            }
            GenerateSshKey { name, .. } => Some(Self::always(name, "Generate SSH key")),
            TypeEntry { id, field, .. } => {
                let e = lookup(id)?;
                Some(Self::always(&e.title, &format!("Type {} over USB", field_name(*field))))
            }
            SetRecoveryPassphrase { .. } => Some(Self::always("Recovery passphrase", "Set / replace")),
            Export { .. } => Some(Self::always("Export vault", "Encrypted backup file")),
            ImportCommit { mode, .. } => {
                if self.import.is_none() {
                    return Err(ErrorCode::InvalidRequest);
                }
                let what = match mode {
                    ImportMode::Replace => "REPLACE whole vault",
                    ImportMode::Merge => "Merge into vault",
                };
                Some(Self::always("Import backup", what))
            }
            GetInfo | SetTime { .. } | Lock | Unlock { .. } | GetSettings => None,
        })
    }

    pub(super) fn dispatch(&mut self, link: Link, id: u32, req: Request) {
        match self.gate(&req) {
            Err(code) => self.reply(link, id, Response::Error(code)),
            Ok(None) => self.execute(link, id, req),
            Ok(Some(spec)) => {
                let requester = self.sessions.get(&link).map(|s| s.label.clone()).unwrap_or_default();
                let ui = ApprovalRequest {
                    id: 0,
                    kind: spec.kind,
                    requester,
                    title: spec.title,
                    context: spec.context,
                    timeout_secs: APPROVAL_TIMEOUT.as_secs() as u32,
                };
                let done = Done::Prism { link, req_id: id, req, session_mark: spec.session_mark };
                if let Err(done) = self.approval_submit(ui, done) {
                    if let Done::Prism { link, req_id, .. } = done {
                        self.reply(link, req_id, Response::Error(ErrorCode::Busy));
                    }
                }
            }
        }
    }

    /// Run a request that passed the gate (possibly after a tap).
    fn execute(&mut self, link: Link, id: u32, req: Request) {
        if let Some(resp) = self.exec(link, id, req) {
            self.reply(link, id, resp);
        }
    }

    // ---- approval broker -------------------------------------------------------------------

    /// Queue or show an approval. Returns the `Done` back if the queue is full (caller answers Busy).
    pub(super) fn approval_submit(&mut self, mut ui: ApprovalRequest, done: Done) -> Result<(), Done> {
        if self.broker.active.is_some() && self.broker.queue_full() {
            return Err(done);
        }
        ui.id = self.broker.alloc_id();
        let p = Pending { ui, done };
        if self.broker.active.is_none() {
            self.approval_show(p);
        } else {
            self.broker.queue.push_back(p);
        }
        Ok(())
    }

    fn approval_show(&mut self, p: Pending) {
        self.activity();
        self.approval_reminded = false;
        self.sound(crate::sound::Sound::Attention);
        self.ui(UiEvent::Approval(p.ui.clone()));
        self.broker.active = Some((p, Instant::now()));
    }

    /// The user (or time, or a lock) answered the active approval.
    pub(super) fn approval_resolve(&mut self, outcome: Outcome) {
        let Some((p, started)) = self.broker.active.take() else { return };
        let outcome = if outcome == Outcome::Denied && started.elapsed() + Duration::from_millis(1500) >= APPROVAL_TIMEOUT {
            Outcome::Timeout // the UI auto-denies at its own deadline
        } else {
            outcome
        };
        if matches!(outcome, Outcome::Timeout | Outcome::Cancelled) {
            self.ui(UiEvent::ApprovalCancelled(p.ui.id));
        }
        match outcome {
            Outcome::Approved => self.sound(crate::sound::Sound::Approved),
            Outcome::Denied | Outcome::Timeout => self.sound(crate::sound::Sound::Denied),
            Outcome::Cancelled => {}
        }
        match p.done {
            Done::Prism { link, req_id, req, session_mark } => match outcome {
                Outcome::Approved => {
                    if let Some(id) = session_mark {
                        self.session_approved.insert(id);
                    }
                    self.activity();
                    self.execute(link, req_id, req);
                }
                Outcome::Denied => self.reply(link, req_id, Response::Error(ErrorCode::Denied)),
                Outcome::Timeout => self.reply(link, req_id, Response::Error(ErrorCode::Timeout)),
                Outcome::Cancelled => {
                    let code = if self.vault.is_none() { ErrorCode::Locked } else { ErrorCode::Denied };
                    self.reply(link, req_id, Response::Error(code));
                }
            },
            Done::Ctap { reply, .. } => {
                let r = match outcome {
                    Outcome::Approved => PresenceResult::Approved,
                    Outcome::Timeout => PresenceResult::Timeout,
                    _ => PresenceResult::Denied,
                };
                let _ = reply.send(r);
            }
        }
        if let Some(next) = self.broker.queue.pop_front() {
            self.approval_show(next);
        }
    }

    /// Answer every outstanding approval (device locked / wiped).
    pub(super) fn approval_cancel_all(&mut self) {
        while self.broker.active.is_some() {
            self.approval_resolve(Outcome::Cancelled);
        }
    }

    // ---- execution ---------------------------------------------------------------------------

    fn persist(&mut self) -> Result<(), ErrorCode> {
        let Some(v) = self.vault.as_mut() else { return Err(ErrorCode::Locked) };
        let bytes = v.seal(&mut self.rng).map_err(|e| {
            log::error!("seal failed: {e}");
            ErrorCode::Internal
        })?;
        if bytes.len() > MAX_VAULT_BYTES {
            return Err(ErrorCode::StorageFull);
        }
        let generation = v.generation();
        self.vault_store.store(&bytes, generation).map_err(|e| {
            log::error!("vault store failed: {e:#}");
            ErrorCode::Internal
        })?;
        let c = self.counts();
        self.ui(UiEvent::Counts(c));
        Ok(())
    }

    fn ok_or_err(r: Result<(), ErrorCode>) -> Response {
        match r {
            Ok(()) => Response::Ok,
            Err(c) => Response::Error(c),
        }
    }

    fn stamp(&self) -> u64 {
        self.now()
    }

    /// `None` = the response is sent later (CTAP relay, replace-import PIN prompt).
    fn exec(&mut self, link: Link, id: u32, req: Request) -> Option<Response> {
        use Request::*;
        use Response as R;
        let err = |c: ErrorCode| Some(R::Error(c));
        Some(match req {
            GetInfo => R::Info(self.device_info()),
            SetTime { unix } => {
                if unix < 1_704_067_200 {
                    return err(ErrorCode::InvalidRequest);
                }
                self.clock.set(unix);
                R::Ok
            }
            Lock => {
                self.lock();
                R::Ok
            }
            Unlock { passphrase } => return Some(self.unlock_with_passphrase(passphrase)),
            GetSettings => R::Settings(self.settings.clone()),
            SetSettings { settings } => {
                if settings.auto_lock_secs > 24 * 3600 {
                    return err(ErrorCode::InvalidRequest);
                }
                self.apply_settings(settings, true);
                R::Ok
            }
            _ => {
                if self.vault.is_none() {
                    return err(ErrorCode::Locked);
                }
                return self.exec_unlocked(link, id, req);
            }
        })
    }

    fn exec_unlocked(&mut self, link: Link, id: u32, req: Request) -> Option<Response> {
        use Request::*;
        use Response as R;
        let err = |c: ErrorCode| Some(R::Error(c));
        let now = self.stamp();
        let time_ok = self.clock.is_valid();
        Some(match req {
            ListEntries { kind } => R::Entries(self.vault.as_ref()?.list_summaries(kind)),
            GetSecret { id, field, .. } => match self.vault.as_ref()?.get_entry(&id).and_then(|e| secret_value(e, field)) {
                Some(v) => R::Secret(v),
                None => R::Error(ErrorCode::InvalidRequest),
            },
            GetTotp { id } => {
                if !time_ok {
                    return err(ErrorCode::Unsupported); // no valid clock: a code would be wrong
                }
                match self.vault.as_ref()?.get_entry(&id).and_then(totp_of) {
                    Some(t) => R::Totp { code: totp::code(t, now), valid_until: totp::valid_until(t, now) },
                    None => R::Error(ErrorCode::InvalidRequest),
                }
            }
            GetEntry { id } => match self.vault.as_ref()?.get_entry(&id) {
                Some(e) => R::Entry(e.clone()),
                None => R::Error(ErrorCode::NotFound),
            },
            AddEntry { mut entry } => {
                if time_ok {
                    entry.created = now;
                    entry.modified = now;
                }
                let eid = entry.id;
                match self.vault.as_mut()?.add_entry(entry) {
                    Ok(_) => match self.persist() {
                        Ok(()) => R::EntryId(eid),
                        Err(c) => {
                            let _ = self.vault.as_mut()?.delete_entry(&eid);
                            R::Error(c)
                        }
                    },
                    Err(CoreError::Duplicate) => R::Error(ErrorCode::InvalidRequest),
                    Err(_) => R::Error(ErrorCode::Internal),
                }
            }
            UpdateEntry { mut entry } => {
                if time_ok {
                    entry.modified = now;
                }
                match self.vault.as_mut()?.update_entry(entry) {
                    Ok(()) => Self::ok_or_err(self.persist()),
                    Err(_) => R::Error(ErrorCode::NotFound),
                }
            }
            DeleteEntry { id } => match self.vault.as_mut()?.delete_entry(&id) {
                Ok(_) => {
                    self.session_approved.remove(&id);
                    Self::ok_or_err(self.persist())
                }
                Err(_) => R::Error(ErrorCode::NotFound),
            },
            MarkRecoveryCodeUsed { id, index } => match self.vault.as_mut()?.mark_recovery_code_used(&id, index) {
                Ok(()) => Self::ok_or_err(self.persist()),
                Err(CoreError::NotFound) => R::Error(ErrorCode::NotFound),
                Err(_) => R::Error(ErrorCode::InvalidRequest),
            },
            GenerateSshKey { name, comment, policy } => {
                let v = self.vault.as_mut()?;
                match v.generate_ssh_key(&name, &comment, policy, now, &mut self.rng) {
                    Ok(k) => match self.persist() {
                        Ok(()) => R::SshKeys(vec![k]),
                        Err(c) => R::Error(c),
                    },
                    Err(_) => R::Error(ErrorCode::Internal),
                }
            }
            SshListKeys => R::SshKeys(self.vault.as_ref()?.ssh_public_keys()),
            SshSign { public_key, data, .. } => match self.vault.as_ref()?.ssh_sign(&public_key, &data) {
                Ok(sig) => R::SshSignature(sig),
                Err(CoreError::NotFound) => R::Error(ErrorCode::NotFound),
                Err(_) => R::Error(ErrorCode::Internal),
            },
            Ctap { cbor, .. } => {
                if self.vault.is_none() {
                    return err(ErrorCode::Locked);
                }
                let job = CtapJob { reply: CtapReply::Prism { link, id }, request: cbor };
                if self.ctap.send(job).is_err() {
                    return err(ErrorCode::Internal);
                }
                return None;
            }
            TypeEntry { id, field, layout } => {
                let text = match self.vault.as_ref()?.get_entry(&id).and_then(|e| secret_value(e, field)) {
                    Some(SecretValue::Text(ref t)) => Zeroizing::new(t.clone()),
                    Some(_) => return err(ErrorCode::InvalidRequest),
                    None => return err(ErrorCode::NotFound),
                };
                if !self.status.usb_cfg.load(std::sync::atomic::Ordering::Relaxed) {
                    return err(ErrorCode::Unsupported); // no USB host to type into
                }
                self.tx(TransportCommand::TypeText { text, layout });
                R::Ok
            }
            Export { passphrase } => {
                let resp = self.do_export(passphrase);
                if self.export.is_some() {
                    self.transfer_owner = Some(link);
                }
                return Some(resp);
            }
            ExportChunk { .. } | ImportChunk { .. } if self.transfer_owner != Some(link) => {
                R::Error(ErrorCode::InvalidRequest)
            }
            ExportChunk { offset } => match &self.export {
                Some(buf) if (offset as usize) < buf.len() => {
                    let start = offset as usize;
                    let end = (start + 8192).min(buf.len());
                    R::Chunk { offset, data: buf[start..end].to_vec() }
                }
                _ => R::Error(ErrorCode::InvalidRequest),
            },
            ImportBegin { total_len } => {
                let n = total_len as usize;
                if n == 0 || n > MAX_IMPORT_BYTES {
                    return err(ErrorCode::StorageFull);
                }
                self.import = Some(ImportBuf { expected: n, data: Vec::with_capacity(n) });
                self.transfer_owner = Some(link);
                R::Ok
            }
            ImportChunk { offset, data } => match &mut self.import {
                Some(b) if offset as usize == b.data.len() && b.data.len() + data.len() <= b.expected => {
                    b.data.extend_from_slice(&data);
                    R::Ok
                }
                _ => R::Error(ErrorCode::InvalidRequest),
            },
            ImportCommit { passphrase, mode } => return self.do_import(link, id, passphrase, mode),
            ListPairedHosts => R::PairedHosts(self.hosts.clone()),
            RemovePairedHost { public_key } => {
                let n = self.hosts.len();
                self.hosts.retain(|h| h.public_key != public_key);
                if self.hosts.len() == n {
                    return err(ErrorCode::NotFound);
                }
                if let Err(e) = self.store().set_hosts(&self.hosts) {
                    log::error!("saving hosts: {e:#}");
                    return err(ErrorCode::Internal);
                }
                self.ui(UiEvent::PairedHosts(self.hosts.clone()));
                R::Ok
            }
            SetRecoveryPassphrase { passphrase } => {
                let v = self.vault.as_mut()?;
                match v.set_recovery_passphrase(&passphrase, &mut self.rng) {
                    Ok(()) => Self::ok_or_err(self.persist()),
                    Err(CoreError::Invalid(_)) => R::Error(ErrorCode::InvalidRequest),
                    Err(_) => R::Error(ErrorCode::Internal),
                }
            }
            // Handled before `exec_unlocked`.
            GetInfo | SetTime { .. } | Lock | Unlock { .. } | GetSettings | SetSettings { .. } => R::Error(ErrorCode::Internal),
        })
    }

    pub(super) fn device_info(&self) -> prism_core::model::DeviceInfo {
        let (pct, charging) = self.battery();
        prism_core::model::DeviceInfo {
            fw_version: super::FW_VERSION.into(),
            device_pubkey: self.dev_pub,
            locked: self.vault.is_none(),
            initialized: self.initialized,
            battery_pct: pct,
            charging,
            entry_count: self.vault.as_ref().map(|v| v.vault.entries.len() as u32).unwrap_or(0),
            time_valid: self.clock.is_valid(),
        }
    }

    fn unlock_with_passphrase(&mut self, passphrase: String) -> Response {
        let passphrase = Zeroizing::new(passphrase);
        if let Some(t) = self.pp_locked_until {
            if Instant::now() < t {
                return Response::Error(ErrorCode::Busy);
            }
            self.pp_locked_until = None;
        }
        let Some(bytes) = self.vault_store.load() else { return Response::Error(ErrorCode::NotFound) };
        match UnlockedVault::unlock_with_passphrase(&bytes, &passphrase) {
            Ok(uv) => {
                self.pp_fails = 0;
                if self.vault.is_none() {
                    let _ = self.store().set_pin_fails(0);
                    self.finish_unlock(uv);
                }
                Response::Ok
            }
            Err(CoreError::BadCredential) => {
                self.pp_fails = self.pp_fails.saturating_add(1);
                if self.pp_fails >= 5 {
                    // Throttle online guessing of the recovery passphrase (not a wipe trigger).
                    self.pp_locked_until = Some(Instant::now() + Duration::from_secs(60));
                    self.pp_fails = 0;
                }
                Response::Error(ErrorCode::BadPassphrase)
            }
            Err(CoreError::NoSlot) => Response::Error(ErrorCode::Unsupported),
            Err(e) => {
                log::error!("passphrase unlock: {e}");
                Response::Error(ErrorCode::Internal)
            }
        }
    }

    fn do_export(&mut self, passphrase: String) -> Response {
        let passphrase = Zeroizing::new(passphrase);
        let Some(bytes) = self.vault_store.load() else { return Response::Error(ErrorCode::NotFound) };
        // Proves the caller knows the recovery passphrase (and that the slot exists).
        match UnlockedVault::unlock_with_passphrase(&bytes, &passphrase) {
            Ok(check) => drop(check),
            Err(CoreError::BadCredential) => return Response::Error(ErrorCode::BadPassphrase),
            Err(CoreError::NoSlot) => return Response::Error(ErrorCode::Unsupported),
            Err(_) => return Response::Error(ErrorCode::Internal),
        }
        let now = self.stamp();
        let Some(v) = self.vault.as_ref() else { return Response::Error(ErrorCode::Locked) };
        match export::export(v.seed(), &v.vault, &passphrase, KdfParams::EXPORT, now, &mut self.rng) {
            Ok(file) => {
                let total_len = file.len() as u32;
                self.export = Some(file);
                Response::ExportReady { total_len }
            }
            Err(e) => {
                log::error!("export failed: {e}");
                Response::Error(ErrorCode::Internal)
            }
        }
    }

    fn do_import(&mut self, link: Link, id: u32, passphrase: String, mode: ImportMode) -> Option<Response> {
        let passphrase = Zeroizing::new(passphrase);
        let buf = self.import.take()?;
        if buf.data.len() != buf.expected {
            self.import = Some(buf);
            return Some(Response::Error(ErrorCode::InvalidRequest));
        }
        let (seed, incoming) = match import(&buf.data, &passphrase) {
            Ok(x) => x,
            Err(CoreError::BadCredential) => return Some(Response::Error(ErrorCode::BadPassphrase)),
            Err(e) => {
                log::warn!("import rejected: {e}");
                return Some(Response::Error(ErrorCode::InvalidRequest));
            }
        };
        match mode {
            ImportMode::Merge => {
                let v = self.vault.as_mut()?;
                let local_seed = Zeroizing::new(*v.seed());
                export::merge(&mut v.vault, &local_seed, incoming, &seed);
                Some(Self::ok_or_err(self.persist()))
            }
            ImportMode::Replace => {
                // Re-wrapping the PIN slot under the imported seed needs the PIN: ask on the device.
                self.pending_replace = Some(PendingReplace {
                    seed,
                    vault: incoming,
                    link,
                    req_id: id,
                    deadline: Instant::now() + PIN_PROMPT_TIMEOUT,
                });
                self.ui(UiEvent::ShowPin { attempts_left: None });
                self.set_mode(Mode::Pin);
                None
            }
        }
    }

    // ---- CTAP platform callbacks ------------------------------------------------------------------

    pub(super) fn on_platform(&mut self, op: PlatformOp) {
        match op {
            PlatformOp::SeedKey { info, reply } => {
                let _ = reply.send(self.vault.as_ref().map(|v| v.derive_key(&info)));
            }
            PlatformOp::FindResident { rp_id, reply } => {
                let creds = self
                    .vault
                    .as_ref()
                    .map(|v| {
                        v.vault
                            .entries
                            .iter()
                            .filter_map(|e| match &e.data {
                                EntryData::Passkey(p) if p.rp_id == rp_id => Some(p.clone()),
                                _ => None,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let _ = reply.send(creds);
            }
            PlatformOp::Store { cred, reply } => {
                let _ = reply.send(self.store_resident(cred));
            }
            PlatformOp::Delete { cred_id, reply } => {
                let r = match self.vault.as_mut() {
                    None => Err(StorageError::Io),
                    Some(v) => {
                        v.vault.entries.retain(|e| !matches!(&e.data, EntryData::Passkey(p) if p.credential_id == cred_id));
                        self.persist().map_err(storage_err)
                    }
                };
                let _ = reply.send(r);
            }
            PlatformOp::Reset { reply } => {
                let r = match self.vault.as_mut() {
                    None => Err(StorageError::Io),
                    Some(v) => {
                        v.vault.entries.retain(|e| !matches!(e.data, EntryData::Passkey(_)));
                        self.persist().map_err(storage_err)
                    }
                };
                let _ = reply.send(r);
            }
            PlatformOp::Presence { req, link, reply } => {
                if self.vault.is_none() {
                    let _ = reply.send(PresenceResult::Denied);
                    return;
                }
                let (kind, verb) = match req.kind {
                    PresenceKind::Register => (ApprovalKind::PasskeyRegister, "register passkey"),
                    PresenceKind::Authenticate => (ApprovalKind::PasskeyAuth, "sign in"),
                    PresenceKind::Reset => (ApprovalKind::Other, "RESET all passkeys"),
                    PresenceKind::Selection => (ApprovalKind::Other, "security key selection"),
                };
                let title = if !req.rp_name.is_empty() { &req.rp_name } else { &req.rp_id };
                let user = if !req.user_display_name.is_empty() { &req.user_display_name } else { &req.user_name };
                let context = if user.is_empty() { verb.to_string() } else { format!("{verb}: {user}") };
                let ui = ApprovalRequest {
                    id: 0,
                    kind,
                    requester: format!("Passkey ({})", link_name(link)),
                    title: clean(title, 48),
                    context: clean(&context, 80),
                    timeout_secs: APPROVAL_TIMEOUT.as_secs() as u32,
                };
                if let Err(Done::Ctap { reply, .. }) = self.approval_submit(ui, Done::Ctap { link, reply }) {
                    let _ = reply.send(PresenceResult::Denied);
                }
            }
        }
    }

    fn store_resident(&mut self, mut cred: Passkey) -> Result<(), StorageError> {
        let now = self.stamp();
        let time_ok = self.clock.is_valid();
        let v = self.vault.as_mut().ok_or(StorageError::Io)?;
        if time_ok {
            cred.created = now;
        }
        // A second registration for the same account replaces the first (CTAP2 6.1.2).
        v.vault.entries.retain(|e| {
            !matches!(&e.data, EntryData::Passkey(p) if p.rp_id == cred.rp_id && p.user_handle == cred.user_handle)
        });
        let title = if cred.rp_name.is_empty() { cred.rp_id.clone() } else { cred.rp_name.clone() };
        let entry = Entry {
            id: prism_core::vault::new_entry_id(&mut self.rng),
            title,
            tags: vec![],
            created: cred.created,
            modified: cred.created,
            policy: ApprovalPolicy::Always,
            data: EntryData::Passkey(cred),
        };
        let eid = entry.id;
        v.add_entry(entry).map_err(|_| StorageError::Io)?;
        match self.persist() {
            Ok(()) => Ok(()),
            Err(c) => {
                if let Some(v) = self.vault.as_mut() {
                    let _ = v.delete_entry(&eid);
                }
                Err(storage_err(c))
            }
        }
    }

    /// Replace-import PIN step (called from `submit_pin` when a replace is pending).
    pub(super) fn complete_replace(&mut self, pin: &str) {
        let Some(bytes) = self.vault_store.load() else { return };
        let fails = self.store().pin_fails();
        let used = fails.saturating_add(1);
        let _ = self.store().set_pin_fails(used);
        match UnlockedVault::unlock_with_pin(&bytes, pin, &NoHardening) {
            Ok(check) => {
                drop(check);
                let _ = self.store().set_pin_fails(0);
                let Some(p) = self.pending_replace.take() else { return };
                let resp = match self.vault.as_mut() {
                    None => Response::Error(ErrorCode::Locked),
                    Some(v) => match v.replace_contents(p.seed, p.vault, pin, &NoHardening, &mut self.rng) {
                        Ok(()) => {
                            self.session_approved.clear();
                            Self::ok_or_err(self.persist())
                        }
                        Err(e) => {
                            log::error!("replace failed: {e}");
                            Response::Error(ErrorCode::Internal)
                        }
                    },
                };
                self.reply(p.link, p.req_id, resp);
                let c = self.counts();
                self.ui(UiEvent::Unlocked(c));
                self.set_mode(Mode::Unlocked);
            }
            Err(CoreError::BadCredential) => {
                if used >= crate::storage::MAX_PIN_FAILS {
                    self.wipe();
                } else {
                    self.sound(crate::sound::Sound::Error);
                    self.ui(UiEvent::PinRejected { attempts_left: crate::storage::MAX_PIN_FAILS - used });
                }
            }
            Err(e) => {
                log::error!("pin check: {e}");
                let _ = self.store().set_pin_fails(fails);
            }
        }
    }
}

fn storage_err(c: ErrorCode) -> StorageError {
    if c == ErrorCode::StorageFull {
        StorageError::Full
    } else {
        StorageError::Io
    }
}

fn totp_of(e: &Entry) -> Option<&prism_core::model::Totp> {
    match &e.data {
        EntryData::Totp(t) => Some(t),
        EntryData::Password(p) => p.totp.as_ref(),
        _ => None,
    }
}

pub(super) fn totp_ref(e: &Entry) -> Option<&prism_core::model::Totp> {
    totp_of(e)
}

#[allow(dead_code)]
fn _unused(_: SshKeySource, _: PowerMsg) {}
