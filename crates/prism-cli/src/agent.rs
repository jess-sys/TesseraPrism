//! ssh-agent protocol server backed by a Prism device (Ed25519 only).
//!
//! Hand-written codec for: REQUEST_IDENTITIES (11) -> IDENTITIES_ANSWER (12), SIGN_REQUEST (13) ->
//! SIGN_RESPONSE (14), FAILURE (5), SUCCESS (6), EXTENSION (27) incl. `session-bind@openssh.com`.

use crate::{known_hosts, Env};
use futures::future::BoxFuture;
use prism_client::{Client, Error as ClientError};
use prism_core::model::SshPublicKey;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

pub const FAILURE: u8 = 5;
pub const SUCCESS: u8 = 6;
pub const REQUEST_IDENTITIES: u8 = 11;
pub const IDENTITIES_ANSWER: u8 = 12;
pub const SIGN_REQUEST: u8 = 13;
pub const SIGN_RESPONSE: u8 = 14;
pub const EXTENSION: u8 = 27;
const MAX_MSG: usize = 256 * 1024;

pub fn default_socket_path() -> PathBuf {
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(d).join("prism-agent.sock");
    }
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".prism").join("agent.sock")
}

// ---------------------------------------------------------------- codec

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&v, r) = self.b.split_first()?;
        self.b = r;
        Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        let (v, r) = self.b.split_at_checked(4)?;
        self.b = r;
        Some(u32::from_be_bytes(v.try_into().ok()?))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let (v, r) = self.b.split_at_checked(n)?;
        self.b = r;
        Some(v)
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Parsed `session-bind@openssh.com` payload.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionBind {
    pub hostkey: Vec<u8>,
    pub session_id: Vec<u8>,
    pub is_forwarding: bool,
}

pub fn parse_session_bind(payload: &[u8]) -> Option<SessionBind> {
    let mut r = Reader { b: payload };
    let hostkey = r.string()?.to_vec();
    let session_id = r.string()?.to_vec();
    let _sig = r.string()?;
    let is_forwarding = r.u8()? != 0;
    Some(SessionBind { hostkey, session_id, is_forwarding })
}

// ---------------------------------------------------------------- agent

#[derive(Default)]
struct DevState {
    client: Option<Client>,
    /// Prism public keys, also persisted (public data only) so ssh's key listing never has to
    /// wait for the device: servers that don't accept a Prism key move on to other keys at once.
    identities: Vec<SshPublicKey>,
    loaded_cache: bool,
    /// Last successful use of `client`.
    last_ok: Option<std::time::Instant>,
}

/// Reconnect from scratch if the connection sat unused for longer than this: after the device
/// slept, rebooted or was re-flashed, a BLE link can go silent without ever reporting an error.
const IDLE_RECONNECT: Duration = Duration::from_secs(120);
/// Drop the device connection after this long without use. On macOS every Prism process shares
/// one BLE link and only one of them reliably receives the device's notifications, so an idle
/// agent holding the link breaks the app's AutoFill extension.
const IDLE_DISCONNECT: Duration = Duration::from_secs(8);
/// Per-request deadlines. Non-interactive requests answer in well under a second; a signature
/// may wait for the user's tap (the device auto-denies after 30 s).
const QUICK_TIMEOUT: Duration = Duration::from_secs(8);
const SIGN_TIMEOUT: Duration = Duration::from_secs(40);
/// One connection attempt (BLE scan + handshake).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// How long a signature waits for the device to come online / be unlocked.
const WAIT_FOR_DEVICE: Duration = Duration::from_secs(120);
const RETRY_EVERY: Duration = Duration::from_secs(2);
/// A held connection unused for longer than this is checked (GetInfo) before a sign request,
/// so a device that went away shows "looking for your Prism" instead of a stale "approve".
const LIVENESS_AFTER: Duration = Duration::from_secs(10);
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(3);

/// Why a device operation could not run.
enum OpErr {
    /// Device off, out of range or the link died.
    Unavailable(anyhow::Error),
    /// Device reachable but locked.
    Locked,
    /// Any other failure (denied on the device, approval timed out, protocol error...).
    Other(anyhow::Error),
}

impl OpErr {
    fn into_anyhow(self) -> anyhow::Error {
        match self {
            OpErr::Unavailable(e) | OpErr::Other(e) => e,
            OpErr::Locked => anyhow::anyhow!("device is locked"),
        }
    }
}

pub struct Agent {
    env: Arc<Env>,
    dev: Mutex<DevState>,
    /// Override for tests: directory used instead of `~/.ssh` for known_hosts lookups.
    pub ssh_dir: Option<PathBuf>,
    /// Show on-screen feedback (HUD / popup / notifications). Off in tests.
    ui: bool,
}

fn is_connection_error(e: &ClientError) -> bool {
    // A timeout means the link went silent (e.g. the device rebooted): treat it as dead.
    matches!(
        e,
        ClientError::Io(_) | ClientError::Closed | ClientError::Transport(_) | ClientError::Proto(_) | ClientError::Timeout
    )
}

impl Agent {
    pub fn new(env: Arc<Env>) -> Arc<Agent> {
        Arc::new(Agent { env, dev: Mutex::new(DevState::default()), ssh_dir: None, ui: true })
    }
    pub fn with_ssh_dir(env: Arc<Env>, ssh_dir: PathBuf) -> Arc<Agent> {
        Arc::new(Agent { env, dev: Mutex::new(DevState::default()), ssh_dir: Some(ssh_dir), ui: false })
    }

    /// Run `f` against the device connection, (re)connecting lazily and retrying once on
    /// connection-level failures.
    async fn op<T>(
        &self,
        deadline: Duration,
        f: impl for<'a> Fn(&'a mut Client) -> BoxFuture<'a, Result<T, ClientError>>,
    ) -> Result<T, OpErr> {
        self.op_with(deadline, || {}, f).await
    }

    /// Like `op`, calling `ready` each time a connection is available, just before `f` runs.
    async fn op_with<T>(
        &self,
        deadline: Duration,
        ready: impl Fn(),
        f: impl for<'a> Fn(&'a mut Client) -> BoxFuture<'a, Result<T, ClientError>>,
    ) -> Result<T, OpErr> {
        let mut st = self.dev.lock().await;
        if st.last_ok.is_some_and(|t| t.elapsed() > IDLE_RECONNECT) {
            st.client = None;
        }
        for attempt in 0..2 {
            if st.client.is_none() {
                let c = match tokio::time::timeout(CONNECT_TIMEOUT, self.env.connect()).await {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => return Err(OpErr::Unavailable(e)),
                    Err(_) => return Err(OpErr::Unavailable(anyhow::anyhow!("connecting to the device timed out"))),
                };
                st.client = Some(c);
            } else if st.last_ok.is_none_or(|t| t.elapsed() > LIVENESS_AFTER) {
                let c = st.client.as_mut().unwrap();
                let alive = matches!(tokio::time::timeout(LIVENESS_TIMEOUT, c.info()).await, Ok(Ok(_)));
                if !alive {
                    st.client = None;
                    if attempt == 1 {
                        return Err(OpErr::Unavailable(anyhow::anyhow!("the device stopped responding")));
                    }
                    continue;
                }
                st.last_ok = Some(std::time::Instant::now());
            }
            ready();
            let res = match tokio::time::timeout(deadline, f(st.client.as_mut().unwrap())).await {
                Ok(r) => r,
                Err(_) => Err(ClientError::Timeout),
            };
            match res {
                Ok(v) => {
                    st.last_ok = Some(std::time::Instant::now());
                    return Ok(v);
                }
                Err(ClientError::Device(prism_proto::ErrorCode::Locked)) => return Err(OpErr::Locked),
                Err(e) if is_connection_error(&e) => {
                    st.client = None;
                    if attempt == 1 {
                        return Err(OpErr::Unavailable(e.into()));
                    }
                }
                Err(e) => return Err(OpErr::Other(e.into())),
            }
        }
        unreachable!()
    }

    fn cache_path(&self) -> PathBuf {
        self.env.paths.dir.join("agent-identities.json")
    }

    async fn cached_identities(&self) -> Vec<SshPublicKey> {
        let mut st = self.dev.lock().await;
        if !st.loaded_cache {
            st.loaded_cache = true;
            if let Ok(b) = std::fs::read(self.cache_path()) {
                if let Ok(v) = serde_json::from_slice::<Vec<SshPublicKey>>(&b) {
                    st.identities = v;
                }
            }
        }
        st.identities.clone()
    }

    async fn store_identities(&self, keys: &[SshPublicKey]) {
        self.dev.lock().await.identities = keys.to_vec();
        if let Ok(b) = serde_json::to_vec_pretty(keys) {
            let _ = std::fs::write(self.cache_path(), b);
        }
    }

    /// Keys for ssh's listing. Never waits for an absent device: refresh only over a live
    /// connection (or when nothing is cached yet), otherwise answer from the cache.
    async fn identities(&self) -> anyhow::Result<Vec<SshPublicKey>> {
        let cached = self.cached_identities().await;
        let connected = self.dev.lock().await.client.is_some();
        if connected || cached.is_empty() {
            match self.op(QUICK_TIMEOUT, |c| Box::pin(c.ssh_list_keys())).await {
                Ok(keys) => {
                    self.store_identities(&keys).await;
                    return Ok(keys);
                }
                Err(e) if cached.is_empty() => return Err(e.into_anyhow()),
                Err(_) => {}
            }
        }
        Ok(cached)
    }

    /// Sign, waiting (up to `WAIT_FOR_DEVICE`) for the device to be reachable and unlocked, with
    /// on-screen feedback (see `hud`); its Cancel button gives up.
    async fn sign(&self, blob: &[u8], data: &[u8], flags: u32, hint: Option<String>) -> anyhow::Result<Vec<u8>> {
        // Only keys we know about (cache first; refresh if reachable and unknown).
        let mut known = self.cached_identities().await.iter().any(|k| k.blob == blob);
        if !known {
            known = self.identities().await?.iter().any(|k| k.blob == blob);
        }
        anyhow::ensure!(known, "unknown key");
        let hud = hud::Hud::begin(self.ui, hint.clone());
        let res = self.sign_loop(&hud, blob, data, flags, hint).await;
        match &res {
            Ok(_) => hud.finish(hud::State::Success, ""),
            Err(e) if format!("{e:#}").contains("cancelled by the user") => hud.finish(hud::State::Idle, ""),
            Err(e) => hud.finish(hud::State::Failure, &hud::short_reason(&format!("{e:#}"))),
        }
        res
    }

    async fn sign_loop(
        &self,
        hud: &hud::Hud,
        blob: &[u8],
        data: &[u8],
        flags: u32,
        hint: Option<String>,
    ) -> anyhow::Result<Vec<u8>> {
        let started = std::time::Instant::now();
        // Show feedback right away, whether or not the device turns out to be reachable; it
        // switches to "approve" once the request is actually on the device.
        hud.set(hud::State::Searching, "");
        loop {
            // Ed25519 only: rsa-sha2 flags are ignored.
            let (b, d) = (blob.to_vec(), data.to_vec());
            let res = self
                .op_with(
                    SIGN_TIMEOUT,
                    || hud.set(hud::State::Approve, ""),
                    |c| {
                        let (b, d, h) = (b.clone(), d.clone(), hint.clone());
                        Box::pin(async move { c.ssh_sign(&b, &d, flags, h).await })
                    },
                )
                .await;
            let locked = match res {
                Ok(sig) => return Ok(sig),
                Err(OpErr::Other(e)) => return Err(e),
                Err(OpErr::Locked) => true,
                Err(OpErr::Unavailable(_)) => false,
            };
            if started.elapsed() >= WAIT_FOR_DEVICE {
                anyhow::bail!("gave up waiting for the device");
            }
            hud.set(if locked { hud::State::Unlock } else { hud::State::Searching }, "");
            let deadline = std::time::Instant::now() + RETRY_EVERY;
            while std::time::Instant::now() < deadline {
                if hud.cancelled() {
                    anyhow::bail!("cancelled by the user");
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    /// Handle one agent message; returns the reply body (type byte + payload).
    async fn handle(&self, msg: &[u8], conn: &mut ConnState) -> Vec<u8> {
        let mut r = Reader { b: msg };
        let Some(ty) = r.u8() else { return vec![FAILURE] };
        match ty {
            REQUEST_IDENTITIES => match self.identities().await {
                Ok(keys) => {
                    let mut out = vec![IDENTITIES_ANSWER];
                    out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
                    for k in &keys {
                        put_string(&mut out, &k.blob);
                        put_string(&mut out, k.openssh.splitn(3, ' ').nth(2).unwrap_or(&k.name).as_bytes());
                    }
                    out
                }
                Err(e) => {
                    eprintln!("prism-agent: list keys failed: {e:#}");
                    vec![FAILURE]
                }
            },
            SIGN_REQUEST => {
                let (Some(blob), Some(data), Some(flags)) = (r.string(), r.string(), r.u32()) else {
                    return vec![FAILURE];
                };
                match self.sign(blob, data, flags, conn.host_hint.clone()).await {
                    Ok(sig) => {
                        let mut out = vec![SIGN_RESPONSE];
                        put_string(&mut out, &sig);
                        out
                    }
                    Err(e) => {
                        eprintln!("prism-agent: sign failed: {e:#}");
                        vec![FAILURE]
                    }
                }
            }
            EXTENSION => {
                let Some(name) = r.string() else { return vec![FAILURE] };
                if name == b"session-bind@openssh.com" {
                    match parse_session_bind(r.b) {
                        Some(sb) => {
                            let hint = match &self.ssh_dir {
                                Some(d) => known_hosts::resolve_with(d, &sb.hostkey),
                                None => known_hosts::lookup_in_home(&sb.hostkey),
                            };
                            conn.host_hint = hint;
                            conn.bound = Some(sb);
                            vec![SUCCESS]
                        }
                        None => vec![FAILURE],
                    }
                } else {
                    vec![FAILURE]
                }
            }
            _ => vec![FAILURE],
        }
    }

    async fn serve_conn(self: Arc<Self>, mut s: UnixStream) -> std::io::Result<()> {
        let mut conn = ConnState::default();
        loop {
            let mut len = [0u8; 4];
            match s.read_exact(&mut len).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            let n = u32::from_be_bytes(len) as usize;
            if n == 0 || n > MAX_MSG {
                return Ok(());
            }
            let mut buf = vec![0u8; n];
            s.read_exact(&mut buf).await?;
            let reply = self.handle(&buf, &mut conn).await;
            s.write_all(&(reply.len() as u32).to_be_bytes()).await?;
            s.write_all(&reply).await?;
        }
    }

    /// Release the device connection once it has been idle for `IDLE_DISCONNECT`.
    async fn release_if_idle(&self) {
        // try_lock: a busy connection (sign in progress) is by definition not idle.
        if let Ok(mut st) = self.dev.try_lock() {
            let idle = st.last_ok.is_none_or(|t| t.elapsed() > IDLE_DISCONNECT);
            if st.client.is_some() && idle {
                st.client = None; // Drop disconnects the transport.
            }
        }
    }

    /// Accept connections forever.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) -> std::io::Result<()> {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                me.release_if_idle().await;
            }
        });
        loop {
            let (s, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.serve_conn(s).await {
                    eprintln!("prism-agent: connection error: {e}");
                }
            });
        }
    }
}

/// Per-connection state (one per ssh client process).
#[derive(Default)]
pub struct ConnState {
    pub host_hint: Option<String>,
    pub bound: Option<SessionBind>,
}

/// Bind the agent socket (removing a stale one) with 0600 permissions.
pub fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            anyhow::bail!("an agent is already listening on {}", path.display());
        }
        std::fs::remove_file(path)?;
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_bind_parse() {
        let mut p = vec![];
        put_string(&mut p, b"hostkey");
        put_string(&mut p, b"sid");
        put_string(&mut p, b"sig");
        p.push(1);
        let sb = parse_session_bind(&p).unwrap();
        assert_eq!(sb, SessionBind { hostkey: b"hostkey".to_vec(), session_id: b"sid".to_vec(), is_forwarding: true });
        assert!(parse_session_bind(&p[..5]).is_none());
    }
}

/// On-screen feedback for SSH sign requests.
///
/// macOS: the Prism app shows a floating HUD. We write the state to `agent-status.json` in the
/// shared folder `~/.prism/hud` (the sandboxed app is entitled to it); the app acknowledges
/// by writing the sequence number to `agent-ack` (informational), and Cancel is `agent-cancel` containing the
/// sequence number. Without the app there is no on-screen feedback on macOS; on
/// notification. Linux: `notify-send`, if present. Everything here is best effort and silent.
mod hud {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum State {
        Searching,
        Unlock,
        Approve,
        Success,
        Failure,
        /// Nothing to show (hide the HUD).
        Idle,
    }

    impl State {
        fn name(self) -> &'static str {
            match self {
                State::Searching => "searching",
                State::Unlock => "unlock",
                State::Approve => "approve",
                State::Success => "success",
                State::Failure => "failure",
                State::Idle => "idle",
            }
        }
    }

    pub struct Hud {
        dir: Option<PathBuf>,
        enabled: bool,
        seq: u64,
        host: Option<String>,
    }

    /// Directory shared with the Prism app: `~/.prism/hud` (the sandboxed macOS app has a
    /// home-relative entitlement for exactly this folder; a group container would make macOS
    /// prompt about "data from other apps"). macOS only, and only if the app is installed.
    fn app_dir() -> Option<PathBuf> {
        if let Some(d) = std::env::var_os("PRISM_HUD_DIR") {
            return Some(d.into());
        }
        if !cfg!(target_os = "macos") {
            return None;
        }
        let home = dirs::home_dir()?;
        let installed = [PathBuf::from("/Applications/Prism.app"), home.join("Applications/Prism.app")]
            .iter()
            .any(|p| p.is_dir());
        if !installed {
            return None;
        }
        let d = home.join(".prism/hud");
        std::fs::create_dir_all(&d).ok()?;
        Some(d)
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }

    /// First line of an error, trimmed to something that fits in the HUD.
    pub fn short_reason(e: &str) -> String {
        let line = e.lines().next().unwrap_or("").trim();
        let mut out: String = line.chars().take(80).collect();
        if line.chars().count() > 80 {
            out.push('…');
        }
        out
    }

    impl Hud {
        pub fn begin(enabled: bool, host: Option<String>) -> Hud {
            let dir = if enabled { app_dir().filter(|d| d.is_dir()) } else { None };
            Hud::with_dir(enabled, dir, host)
        }

        fn with_dir(enabled: bool, dir: Option<PathBuf>, host: Option<String>) -> Hud {
            let hud = Hud { dir, enabled, seq: now_ms(), host };
            #[cfg(target_os = "macos")]
            if hud.dir.is_some() && std::env::var_os("PRISM_HUD_DIR").is_none() {
                // Start the app in the background (no activation) if it isn't running.
                let _ = Command::new("open")
                    // Not hidden (-j): a hidden app's HUD panel would stay invisible. The app
                    // closes its main window itself when started with --background.
                    .args(["-g", "-b", "ch.neutheria.prism", "--args", "--background"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map(|mut c| std::thread::spawn(move || c.wait()));
            }
            hud
        }

        fn path(&self, name: &str) -> Option<PathBuf> {
            self.dir.as_ref().map(|d| d.join(name))
        }

        fn title_and_icon(&self, st: State, message: &str) -> (String, String, &'static str) {
            let host = self.host.as_deref();
            match st {
                State::Searching => ("Looking for your Prism".into(), "Make sure it is on and nearby".into(), "network-wireless"),
                State::Unlock => ("Unlock your Prism".into(), "Enter your PIN on the device".into(), "dialog-password"),
                State::Approve => (
                    "Approve on your Prism".into(),
                    format!("SSH sign-in to {}", host.unwrap_or("a server")),
                    "dialog-question",
                ),
                State::Success => (format!("Signed in to {}", host.unwrap_or("server")), String::new(), "emblem-ok"),
                State::Failure => ("SSH sign-in failed".into(), message.to_string(), "dialog-error"),
                State::Idle => (String::new(), String::new(), ""),
            }
        }

        /// Publish the current state. Never fails.
        pub fn set(&self, st: State, message: &str) {
            if !self.enabled {
                return;
            }
            if let Some(dir) = &self.dir {
                let (title, subtitle, _) = self.title_and_icon(st, message);
                write_status(dir, self.seq, st, self.host.as_deref(), &title, &subtitle);
            } else if cfg!(target_os = "linux") && st != State::Idle {
                let (title, subtitle, icon) = self.title_and_icon(st, message);
                notify_send(&title, &subtitle, icon);
            }
        }

        /// Final state (success / failure / idle after a cancel).
        pub fn finish(&self, st: State, message: &str) {
            self.set(st, message);
        }


        /// Cancel pressed in the HUD for this request.
        pub fn cancelled(&self) -> bool {
            let Some(p) = self.path("agent-cancel") else { return false };
            let hit = read_cancel(&p) == Some(self.seq);
            if hit {
                let _ = std::fs::remove_file(&p);
            }
            hit
        }
    }

    pub(super) fn read_cancel(p: &Path) -> Option<u64> {
        std::fs::read_to_string(p).ok()?.trim().parse().ok()
    }

    /// Atomically replace `agent-status.json`.
    pub(super) fn write_status(dir: &Path, seq: u64, st: State, host: Option<&str>, title: &str, subtitle: &str) {
        let v = serde_json::json!({
            "seq": seq,
            "state": st.name(),
            "host": host,
            "title": title,
            "message": subtitle,
            "ts": now_ms() / 1000,
        });
        let tmp = dir.join(".agent-status.tmp");
        let ok = serde_json::to_vec(&v).ok().and_then(|b| std::fs::write(&tmp, b).ok()).is_some();
        if ok {
            let _ = std::fs::rename(&tmp, dir.join("agent-status.json"));
        }
    }

    fn notify_send(title: &str, body: &str, icon: &str) {
        let _ = Command::new("notify-send")
            .args(["-a", "Tessera Prism", "-i", icon, "-t", "4000", "-h", "string:x-canonical-private-synchronous:prism-ssh", title, body])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|mut c| std::thread::spawn(move || c.wait()));
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn status_and_cancel_roundtrip() {
            let dir = tempfile::tempdir().unwrap();
            let hud = Hud::with_dir(true, Some(dir.path().to_path_buf()), Some("github.com".into()));
            hud.set(State::Approve, "");
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(dir.path().join("agent-status.json")).unwrap()).unwrap();
            assert_eq!(v["state"], "approve");
            assert_eq!(v["host"], "github.com");
            assert_eq!(v["seq"].as_u64().unwrap(), hud.seq);
            assert!(!dir.path().join(".agent-status.tmp").exists());

            assert!(!hud.cancelled());
            std::fs::write(dir.path().join("agent-cancel"), "1").unwrap();
            assert!(!hud.cancelled(), "other request's cancel is ignored");
            std::fs::write(dir.path().join("agent-cancel"), format!("{}\n", hud.seq)).unwrap();
            assert!(hud.cancelled());
            assert!(!hud.cancelled(), "cancel is consumed");

        }

        #[test]
        fn reasons_are_short() {
            assert_eq!(short_reason("denied\nmore"), "denied");
            assert!(short_reason(&"x".repeat(200)).chars().count() <= 81);
        }
    }
}
