//! [`Client`]: Noise session + request/response matching over any [`Transport`].

use crate::{Error, Result, Transport};
use prism_core::model::*;
use prism_proto::{Envelope, HostSession, Request, Response, SessionEvent};
use std::time::Duration;

/// Per-request timeout (user may need to tap on the device).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Export/import chunk size.
pub const CHUNK: usize = 8 * 1024;

#[derive(Clone, Debug)]
pub struct ClientOptions {
    /// Host static X25519 private key.
    pub host_key: [u8; 32],
    /// If set, the device's static key must equal this (pinned at pairing).
    pub pinned_device: Option<[u8; 32]>,
    pub timeout: Duration,
}

impl ClientOptions {
    pub fn new(host_key: [u8; 32]) -> Self {
        Self { host_key, pinned_device: None, timeout: REQUEST_TIMEOUT }
    }
    pub fn pinned(mut self, k: Option<[u8; 32]>) -> Self {
        self.pinned_device = k;
        self
    }
}

#[derive(Debug)]
pub enum EstablishOutcome {
    /// Host already paired.
    Ready(DeviceInfo),
    /// Pairing completed during this connection.
    Paired { label: String, info: DeviceInfo },
}

impl EstablishOutcome {
    pub fn info(&self) -> &DeviceInfo {
        match self {
            Self::Ready(i) | Self::Paired { info: i, .. } => i,
        }
    }
}

pub struct Client {
    transport: Box<dyn Transport>,
    session: HostSession,
    next_id: u32,
    timeout: Duration,
    sas: String,
    device_key: [u8; 32],
}

impl Client {
    /// Perform the Noise handshake over `transport`. Verifies the pinned device key if set.
    pub async fn connect(mut transport: Box<dyn Transport>, opts: ClientOptions) -> Result<Client> {
        let mut session = HostSession::new(&opts.host_key)?;
        let to = opts.timeout;
        let m1 = session.start()?;
        transport.send_frame(&m1).await?;
        let m2 = tokio::time::timeout(to, transport.recv_frame()).await.map_err(|_| Error::Timeout)??;
        match session.on_frame(&m2)? {
            SessionEvent::SendFrame(m3) => transport.send_frame(&m3).await?,
            SessionEvent::PlainError(e) => return Err(Error::from_code(e.code)),
            other => return Err(Error::Unexpected(format!("handshake: {other:?}"))),
        }
        let device_key = session.remote_static().ok_or_else(|| Error::Unexpected("no device key".into()))?;
        if let Some(p) = opts.pinned_device {
            if p != device_key {
                return Err(Error::DeviceKeyMismatch { expected: hex::encode(p), got: hex::encode(device_key) });
            }
        }
        let sas = session.sas().unwrap_or_default();
        Ok(Client { transport, session, next_id: 1, timeout: to, sas, device_key })
    }

    /// 6-digit short authentication string for this session.
    pub fn sas(&self) -> &str {
        &self.sas
    }
    /// Device static public key learned in the handshake.
    pub fn device_pubkey(&self) -> [u8; 32] {
        self.device_key
    }

    /// First request after the handshake. If the device is in pairing mode, `on_sas` is called
    /// with the SAS and this blocks (up to the timeout) until the user confirms on the device.
    pub async fn establish(&mut self, on_sas: Option<&mut (dyn FnMut(&str) + Send)>) -> Result<EstablishOutcome> {
        if let Some(cb) = on_sas {
            cb(&self.sas.clone());
        }
        match self.call(Request::GetInfo).await? {
            Response::Info(i) => Ok(EstablishOutcome::Ready(i)),
            Response::Paired { label } => {
                let info = self.info().await?;
                Ok(EstablishOutcome::Paired { label, info })
            }
            r => Err(unexpected(r)),
        }
    }

    /// Send a request and wait for the matching response. `Response::Error` becomes `Err`.
    pub async fn call(&mut self, req: Request) -> Result<Response> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let frame = self.session.encrypt_request(&Envelope { id, body: req })?;
        self.transport.send_frame(&frame).await?;
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let f = tokio::time::timeout_at(deadline, self.transport.recv_frame())
                .await
                .map_err(|_| Error::Timeout)??;
            match self.session.on_frame(&f)? {
                SessionEvent::Response(env) if env.id == id => {
                    return match env.body {
                        Response::Error(c) => Err(Error::from_code(c)),
                        r => Ok(r),
                    }
                }
                SessionEvent::Response(_) => continue, // stale (e.g. after a timeout)
                SessionEvent::PlainError(e) => return Err(Error::from_code(e.code)),
                _ => continue,
            }
        }
    }

    async fn call_ok(&mut self, req: Request) -> Result<()> {
        match self.call(req).await? {
            Response::Ok => Ok(()),
            r => Err(unexpected(r)),
        }
    }

    // ---- typed API (ARCHITECTURE §5.3) ----

    pub async fn info(&mut self) -> Result<DeviceInfo> {
        match self.call(Request::GetInfo).await? {
            Response::Info(i) => Ok(i),
            r => Err(unexpected(r)),
        }
    }
    pub async fn set_time(&mut self, unix: u64) -> Result<()> {
        self.call_ok(Request::SetTime { unix }).await
    }
    /// SetTime with the host clock.
    pub async fn sync_time(&mut self) -> Result<()> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        self.set_time(now).await
    }
    pub async fn unlock(&mut self, passphrase: &str) -> Result<()> {
        self.call_ok(Request::Unlock { passphrase: passphrase.into() }).await
    }
    pub async fn lock(&mut self) -> Result<()> {
        self.call_ok(Request::Lock).await
    }
    pub async fn list(&mut self, kind: Option<EntryKind>) -> Result<Vec<EntrySummary>> {
        match self.call(Request::ListEntries { kind }).await? {
            Response::Entries(e) => Ok(e),
            r => Err(unexpected(r)),
        }
    }
    pub async fn get_secret(&mut self, id: EntryId, field: SecretField, context: Option<String>) -> Result<SecretValue> {
        match self.call(Request::GetSecret { id, field, context }).await? {
            Response::Secret(s) => Ok(s),
            r => Err(unexpected(r)),
        }
    }
    /// Returns `(code, valid_until)`.
    pub async fn get_totp(&mut self, id: EntryId) -> Result<(String, u64)> {
        match self.call(Request::GetTotp { id }).await? {
            Response::Totp { code, valid_until } => Ok((code, valid_until)),
            r => Err(unexpected(r)),
        }
    }
    pub async fn add_entry(&mut self, entry: Entry) -> Result<EntryId> {
        match self.call(Request::AddEntry { entry }).await? {
            Response::EntryId(i) => Ok(i),
            r => Err(unexpected(r)),
        }
    }
    pub async fn update_entry(&mut self, entry: Entry) -> Result<()> {
        self.call_ok(Request::UpdateEntry { entry }).await
    }
    pub async fn delete_entry(&mut self, id: EntryId) -> Result<()> {
        self.call_ok(Request::DeleteEntry { id }).await
    }
    pub async fn mark_recovery_code_used(&mut self, id: EntryId, index: u16) -> Result<()> {
        self.call_ok(Request::MarkRecoveryCodeUsed { id, index }).await
    }
    /// Generate a seed-derived SSH key on the device. Returns the new public key.
    pub async fn generate_ssh_key(&mut self, name: &str, comment: &str, policy: ApprovalPolicy) -> Result<SshPublicKey> {
        match self.call(Request::GenerateSshKey { name: name.into(), comment: comment.into(), policy }).await? {
            Response::SshKeys(mut k) if !k.is_empty() => Ok(k.remove(0)),
            r => Err(unexpected(r)),
        }
    }
    pub async fn ssh_list_keys(&mut self) -> Result<Vec<SshPublicKey>> {
        match self.call(Request::SshListKeys).await? {
            Response::SshKeys(k) => Ok(k),
            r => Err(unexpected(r)),
        }
    }
    /// Returns the SSH signature wire blob (`string "ssh-ed25519"`, `string sig`).
    pub async fn ssh_sign(&mut self, public_key: &[u8], data: &[u8], flags: u32, host_hint: Option<String>) -> Result<Vec<u8>> {
        let req = Request::SshSign { public_key: public_key.to_vec(), data: data.to_vec(), flags, host_hint };
        match self.call(req).await? {
            Response::SshSignature(s) => Ok(s),
            r => Err(unexpected(r)),
        }
    }
    pub async fn ctap(&mut self, cbor: Vec<u8>, origin_hint: Option<String>) -> Result<Vec<u8>> {
        match self.call(Request::Ctap { cbor, origin_hint }).await? {
            Response::Ctap(b) => Ok(b),
            r => Err(unexpected(r)),
        }
    }
    pub async fn type_entry(&mut self, id: EntryId, field: SecretField, layout: KeyboardLayout) -> Result<()> {
        self.call_ok(Request::TypeEntry { id, field, layout }).await
    }
    /// Download the encrypted `.prism` export (chunked). `passphrase` must match the device's
    /// recovery passphrase; the export is encrypted with it.
    pub async fn export(&mut self, passphrase: &str) -> Result<Vec<u8>> {
        let total = match self.call(Request::Export { passphrase: passphrase.into() }).await? {
            Response::ExportReady { total_len } => total_len as usize,
            r => return Err(unexpected(r)),
        };
        let mut out = Vec::with_capacity(total);
        while out.len() < total {
            match self.call(Request::ExportChunk { offset: out.len() as u32 }).await? {
                Response::Chunk { offset, data } if offset as usize == out.len() && !data.is_empty() => {
                    out.extend_from_slice(&data)
                }
                r => return Err(unexpected(r)),
            }
        }
        out.truncate(total);
        Ok(out)
    }
    /// Upload an export file in 8 KiB chunks and commit.
    pub async fn import(&mut self, data: &[u8], passphrase: &str, mode: ImportMode) -> Result<()> {
        self.call_ok(Request::ImportBegin { total_len: data.len() as u32 }).await?;
        let mut off = 0usize;
        while off < data.len() {
            let end = (off + CHUNK).min(data.len());
            self.call_ok(Request::ImportChunk { offset: off as u32, data: data[off..end].to_vec() }).await?;
            off = end;
        }
        self.call_ok(Request::ImportCommit { passphrase: passphrase.into(), mode }).await
    }
    /// Set/replace the recovery passphrase slot (device asks for a tap).
    pub async fn set_recovery_passphrase(&mut self, passphrase: &str) -> Result<()> {
        self.call_ok(Request::SetRecoveryPassphrase { passphrase: passphrase.into() }).await
    }
    /// Full entry including secrets (approval per policy).
    pub async fn get_entry(&mut self, id: EntryId) -> Result<Entry> {
        match self.call(Request::GetEntry { id }).await? {
            Response::Entry(e) => Ok(e),
            r => Err(unexpected(r)),
        }
    }
    pub async fn list_paired_hosts(&mut self) -> Result<Vec<PairedHost>> {
        match self.call(Request::ListPairedHosts).await? {
            Response::PairedHosts(h) => Ok(h),
            r => Err(unexpected(r)),
        }
    }
    pub async fn remove_paired_host(&mut self, public_key: [u8; 32]) -> Result<()> {
        self.call_ok(Request::RemovePairedHost { public_key }).await
    }
    pub async fn get_settings(&mut self) -> Result<Settings> {
        match self.call(Request::GetSettings).await? {
            Response::Settings(s) => Ok(s),
            r => Err(unexpected(r)),
        }
    }
    pub async fn set_settings(&mut self, settings: Settings) -> Result<()> {
        self.call_ok(Request::SetSettings { settings }).await
    }
}

fn unexpected(r: Response) -> Error {
    // Only the variant name: responses may carry secrets.
    let d = format!("{r:?}");
    let name: String = d.chars().take_while(|c| c.is_alphanumeric()).collect();
    Error::Unexpected(name)
}
