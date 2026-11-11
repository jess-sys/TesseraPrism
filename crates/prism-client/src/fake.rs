//! In-memory Prism device for tests: a real [`DeviceSession`] plus a real [`UnlockedVault`].
//! Approvals are auto-approved unless [`FakeDevice::set_deny`] is set.

use crate::{MemoryTransport, Transport};
use prism_core::{
    export,
    model::*,
    slots::{KdfParams, NoHardening},
    totp, UnlockedVault,
};
use prism_proto::{
    generate_static_keypair, DeviceEvent, DeviceSession, Envelope, ErrorCode, ProtoError, Request, Response,
};
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};

pub const FAKE_PIN: &str = "123456";
pub const FAKE_PASSPHRASE: &str = "fake recovery passphrase";

struct State {
    dev_priv: [u8; 32],
    dev_pub: [u8; 32],
    vault: UnlockedVault,
    locked: bool,
    pairing_mode: bool,
    paired: Vec<PairedHost>,
    settings: Settings,
    time: Option<u64>,
    passphrase: String,
    import_buf: Option<(usize, Vec<u8>)>,
    export_buf: Option<Vec<u8>>,
    deny: bool,
    approvals: u32,
    sign_hints: Vec<Option<String>>,
    sas_log: Vec<String>,
}

#[derive(Clone)]
pub struct FakeDevice {
    st: Arc<Mutex<State>>,
}

impl Default for FakeDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeDevice {
    /// Fresh, unlocked device in pairing mode.
    pub fn new() -> Self {
        let (dev_priv, dev_pub) = generate_static_keypair();
        let (vault, _) =
            UnlockedVault::create_with_params(FAKE_PIN, &NoHardening, KdfParams::TEST, KdfParams::TEST, &mut OsRng)
                .expect("vault");
        FakeDevice {
            st: Arc::new(Mutex::new(State {
                dev_priv,
                dev_pub,
                vault,
                locked: false,
                pairing_mode: true,
                paired: vec![],
                settings: Settings::default(),
                time: None,
                passphrase: FAKE_PASSPHRASE.into(),
                import_buf: None,
                export_buf: None,
                deny: false,
                approvals: 0,
                sign_hints: vec![],
                sas_log: vec![],
            })),
        }
    }

    pub fn device_pubkey(&self) -> [u8; 32] {
        self.st.lock().unwrap().dev_pub
    }
    pub fn set_pairing_mode(&self, on: bool) {
        self.st.lock().unwrap().pairing_mode = on;
    }
    pub fn set_locked(&self, locked: bool) {
        self.st.lock().unwrap().locked = locked;
    }
    pub fn set_deny(&self, deny: bool) {
        self.st.lock().unwrap().deny = deny;
    }
    pub fn add_paired_host(&self, public_key: [u8; 32], label: &str) {
        self.st.lock().unwrap().paired.push(PairedHost { public_key, label: label.into(), paired_at: 0, last_seen: 0 });
    }
    pub fn paired_hosts(&self) -> Vec<PairedHost> {
        self.st.lock().unwrap().paired.clone()
    }
    pub fn entries(&self) -> Vec<Entry> {
        self.st.lock().unwrap().vault.vault.entries.clone()
    }
    pub fn add_entry(&self, e: Entry) {
        self.st.lock().unwrap().vault.add_entry(e).expect("add");
    }
    pub fn approvals(&self) -> u32 {
        self.st.lock().unwrap().approvals
    }
    /// `host_hint` values received with SshSign requests.
    pub fn sign_hints(&self) -> Vec<Option<String>> {
        self.st.lock().unwrap().sign_hints.clone()
    }
    pub fn time(&self) -> Option<u64> {
        self.st.lock().unwrap().time
    }
    pub fn settings(&self) -> Settings {
        self.st.lock().unwrap().settings.clone()
    }
    /// SAS strings computed device-side for each pairing handshake.
    pub fn sas_log(&self) -> Vec<String> {
        self.st.lock().unwrap().sas_log.clone()
    }

    /// New connection: returns the host-side transport; the device side runs in a task.
    pub fn connect(&self) -> MemoryTransport {
        let (host, dev) = MemoryTransport::pair();
        let st = self.st.clone();
        tokio::spawn(async move { run(st, dev).await });
        host
    }
}

async fn run(st: Arc<Mutex<State>>, mut t: MemoryTransport) {
    let key = st.lock().unwrap().dev_priv;
    let Ok(mut sess) = DeviceSession::new(&key) else { return };
    let mut host_key = [0u8; 32];
    // 0 = unauthorized, 1 = pending pairing, 2 = authorized
    let mut auth = 0u8;
    while let Ok(frame) = t.recv_frame().await {
        match sess.on_frame(&frame) {
            Ok(DeviceEvent::SendFrame(f)) => {
                if t.send_frame(&f).await.is_err() {
                    return;
                }
            }
            Ok(DeviceEvent::Established { remote_static }) => {
                host_key = remote_static;
                let mut g = st.lock().unwrap();
                let s = &mut *g;
                let tm = s.time.unwrap_or(0);
                if let Some(h) = s.paired.iter_mut().find(|h| h.public_key == remote_static) {
                    h.last_seen = tm;
                    auth = 2;
                } else if s.pairing_mode {
                    auth = 1;
                    if let Some(sas) = sess.sas() {
                        s.sas_log.push(sas);
                    }
                }
            }
            Ok(DeviceEvent::Request(env)) => {
                let body = match auth {
                    0 => Response::Error(ErrorCode::NotPaired),
                    1 => {
                        let mut s = st.lock().unwrap();
                        s.pairing_mode = false;
                        s.paired.push(PairedHost { public_key: host_key, label: "fake-host".into(), paired_at: 0, last_seen: 0 });
                        auth = 2;
                        Response::Paired { label: "fake-host".into() }
                    }
                    _ => handle(&mut st.lock().unwrap(), host_key, env.body),
                };
                let denied = matches!(body, Response::Error(ErrorCode::NotPaired));
                let Ok(out) = sess.encrypt_response(&Envelope { id: env.id, body }) else { return };
                if t.send_frame(&out).await.is_err() || denied {
                    return;
                }
            }
            Err(e) => {
                if let Ok(f) = sess.plain_error(&ProtoError { code: ErrorCode::InvalidRequest, message: e.to_string() }) {
                    let _ = t.send_frame(&f).await;
                }
                return;
            }
        }
    }
}

fn now(s: &State) -> u64 {
    s.time.unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    })
}

fn approve(s: &mut State) -> Result<(), Response> {
    if s.deny {
        return Err(Response::Error(ErrorCode::Denied));
    }
    s.approvals += 1;
    Ok(())
}

fn totp_of(e: &Entry) -> Option<&Totp> {
    match &e.data {
        EntryData::Totp(t) => Some(t),
        EntryData::Password(Password { totp: Some(t), .. }) => Some(t),
        _ => None,
    }
}

fn handle(s: &mut State, _host: [u8; 32], req: Request) -> Response {
    use Response as R;
    let err = |c| R::Error(c);
    // Allowed while locked.
    match &req {
        Request::GetInfo => {
            return R::Info(DeviceInfo {
                fw_version: "fake-0.1".into(),
                device_pubkey: s.dev_pub,
                locked: s.locked,
                initialized: true,
                battery_pct: 87,
                charging: false,
                entry_count: s.vault.vault.entries.len() as u32,
                time_valid: s.time.is_some(),
            })
        }
        Request::SetTime { unix } => {
            s.time = Some(*unix);
            return R::Ok;
        }
        Request::Unlock { passphrase } => {
            if *passphrase == s.passphrase {
                s.locked = false;
                return R::Ok;
            }
            return err(ErrorCode::BadPassphrase);
        }
        Request::Lock => {
            s.locked = true;
            return R::Ok;
        }
        Request::ListPairedHosts => return R::PairedHosts(s.paired.clone()),
        Request::RemovePairedHost { public_key } => {
            let n = s.paired.len();
            s.paired.retain(|h| &h.public_key != public_key);
            return if s.paired.len() < n { R::Ok } else { err(ErrorCode::NotFound) };
        }
        _ => {}
    }
    if s.locked {
        return err(ErrorCode::Locked);
    }
    let t = now(s);
    match req {
        Request::ListEntries { kind } => R::Entries(s.vault.list_summaries(kind)),
        Request::GetSecret { id, field, .. } => {
            let Some(e) = s.vault.get_entry(&id).cloned() else { return err(ErrorCode::NotFound) };
            if let Err(r) = approve(s) {
                return r;
            }
            let v = match (&e.data, field) {
                (EntryData::Password(p), SecretField::Password) => SecretValue::Text(p.password.clone()),
                (EntryData::Password(p), SecretField::Username) => SecretValue::Text(p.username.clone()),
                (EntryData::Password(p), SecretField::Notes) => SecretValue::Text(p.notes.clone()),
                (EntryData::RecoveryCodes(r), SecretField::Notes) => SecretValue::Text(r.notes.clone()),
                (EntryData::RecoveryCodes(r), SecretField::RecoveryCodes) => {
                    SecretValue::List(r.codes.iter().filter(|c| !c.used).map(|c| c.code.clone()).collect())
                }
                (EntryData::SshKey(k), SecretField::SshPublicKey) => {
                    SecretValue::Text(prism_core::vault::ssh_openssh_line(&k.public_key, &k.comment))
                }
                (_, SecretField::TotpSecret) => match totp_of(&e) {
                    Some(tp) => SecretValue::Text(totp::base32_encode(&tp.secret)),
                    None => return err(ErrorCode::InvalidRequest),
                },
                _ => return err(ErrorCode::InvalidRequest),
            };
            R::Secret(v)
        }
        Request::GetTotp { id } => {
            let Some(e) = s.vault.get_entry(&id).cloned() else { return err(ErrorCode::NotFound) };
            let Some(tp) = totp_of(&e) else { return err(ErrorCode::InvalidRequest) };
            if let Err(r) = approve(s) {
                return r;
            }
            R::Totp { code: totp::code(tp, t), valid_until: totp::valid_until(tp, t) }
        }
        Request::AddEntry { entry } => {
            if let Err(r) = approve(s) {
                return r;
            }
            match s.vault.add_entry(entry) {
                Ok(id) => R::EntryId(id),
                Err(_) => err(ErrorCode::InvalidRequest),
            }
        }
        Request::UpdateEntry { entry } => match s.vault.update_entry(entry) {
            Ok(()) => R::Ok,
            Err(_) => err(ErrorCode::NotFound),
        },
        Request::DeleteEntry { id } => {
            if let Err(r) = approve(s) {
                return r;
            }
            match s.vault.delete_entry(&id) {
                Ok(_) => R::Ok,
                Err(_) => err(ErrorCode::NotFound),
            }
        }
        Request::MarkRecoveryCodeUsed { id, index } => match s.vault.mark_recovery_code_used(&id, index) {
            Ok(()) => R::Ok,
            Err(_) => err(ErrorCode::NotFound),
        },
        Request::GenerateSshKey { name, comment, policy } => {
            if let Err(r) = approve(s) {
                return r;
            }
            match s.vault.generate_ssh_key(&name, &comment, policy, t, &mut OsRng) {
                Ok(k) => R::SshKeys(vec![k]),
                Err(_) => err(ErrorCode::Internal),
            }
        }
        Request::SshListKeys => R::SshKeys(s.vault.ssh_public_keys()),
        Request::SshSign { public_key, data, host_hint, .. } => {
            if s.vault.find_ssh_entry(&public_key).is_none() {
                return err(ErrorCode::NotFound);
            }
            if let Err(r) = approve(s) {
                return r;
            }
            s.sign_hints.push(host_hint);
            match s.vault.ssh_sign(&public_key, &data) {
                Ok(sig) => R::SshSignature(sig),
                Err(_) => err(ErrorCode::Internal),
            }
        }
        Request::Ctap { .. } => err(ErrorCode::Unsupported),
        Request::TypeEntry { id, .. } => {
            if s.vault.get_entry(&id).is_none() {
                return err(ErrorCode::NotFound);
            }
            R::Ok
        }
        Request::Export { passphrase } => {
            if passphrase != s.passphrase {
                return err(ErrorCode::BadPassphrase);
            }
            if let Err(r) = approve(s) {
                return r;
            }
            let seed = *s.vault.seed();
            match export::export(&seed, &s.vault.vault, &s.passphrase, KdfParams::TEST, t, &mut OsRng) {
                Ok(b) => {
                    let n = b.len() as u32;
                    s.export_buf = Some(b);
                    R::ExportReady { total_len: n }
                }
                Err(_) => err(ErrorCode::Internal),
            }
        }
        Request::ExportChunk { offset } => {
            let Some(b) = &s.export_buf else { return err(ErrorCode::InvalidRequest) };
            let o = offset as usize;
            if o >= b.len() {
                return err(ErrorCode::InvalidRequest);
            }
            R::Chunk { offset, data: b[o..(o + 8192).min(b.len())].to_vec() }
        }
        Request::ImportBegin { total_len } => {
            s.import_buf = Some((total_len as usize, Vec::new()));
            R::Ok
        }
        Request::ImportChunk { offset, data } => match &mut s.import_buf {
            Some((total, buf)) if offset as usize == buf.len() && buf.len() + data.len() <= *total && data.len() <= 8192 => {
                buf.extend_from_slice(&data);
                R::Ok
            }
            _ => err(ErrorCode::InvalidRequest),
        },
        Request::ImportCommit { passphrase, mode } => {
            let Some((total, buf)) = s.import_buf.take() else { return err(ErrorCode::InvalidRequest) };
            if buf.len() != total {
                return err(ErrorCode::InvalidRequest);
            }
            if let Err(r) = approve(s) {
                return r;
            }
            let (seed, incoming) = match export::import(&buf, &passphrase) {
                Ok(x) => x,
                Err(prism_core::Error::BadCredential) => return err(ErrorCode::BadPassphrase),
                Err(_) => return err(ErrorCode::InvalidRequest),
            };
            match mode {
                ImportMode::Merge => {
                    let local_seed = *s.vault.seed();
                    export::merge(&mut s.vault.vault, &local_seed, incoming, &seed);
                    R::Ok
                }
                ImportMode::Replace => match s.vault.replace_contents(seed, incoming, FAKE_PIN, &NoHardening, &mut OsRng) {
                    Ok(()) => R::Ok,
                    Err(_) => err(ErrorCode::Internal),
                },
            }
        }
        Request::SetRecoveryPassphrase { passphrase } => {
            if passphrase.chars().count() < 8 {
                return err(ErrorCode::InvalidRequest);
            }
            if let Err(r) = approve(s) {
                return r;
            }
            s.passphrase = passphrase;
            R::Ok
        }
        Request::GetEntry { id } => {
            let Some(e) = s.vault.get_entry(&id).cloned() else { return err(ErrorCode::NotFound) };
            if let Err(r) = approve(s) {
                return r;
            }
            R::Entry(e)
        }
        Request::GetSettings => R::Settings(s.settings.clone()),
        Request::SetSettings { settings } => {
            s.settings = settings;
            R::Ok
        }
        Request::GetInfo
        | Request::SetTime { .. }
        | Request::Unlock { .. }
        | Request::Lock
        | Request::ListPairedHosts
        | Request::RemovePairedHost { .. } => unreachable!(),
    }
}
