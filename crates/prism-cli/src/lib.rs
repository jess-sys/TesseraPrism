//! `prism` CLI library: command definitions and implementations, plus the SSH agent.
//! The binary (`main.rs`) only wires up the real transport; tests drive [`run`] with a fake device.

pub mod agent;
pub mod install;
pub mod known_hosts;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use clap::{Args, Parser, Subcommand, ValueEnum};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Table};
use prism_client::{Client, ClientOptions, Config, EstablishOutcome, Paths, Transport, TransportChoice};
use prism_core::{
    model::*,
    password_gen::{generate_password, PasswordOptions},
    totp,
    vault::new_entry_id,
};
use rand::rngs::OsRng;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------- environment

/// Opens a raw transport to the device (real: USB/BLE; tests: FakeDevice).
#[async_trait]
pub trait Connector: Send + Sync {
    async fn open(&self, cfg: &mut Config) -> prism_client::Result<Box<dyn Transport>>;
}

/// Reads secrets. `env_key` names an environment variable that may supply the value (scripting).
pub trait Prompter: Send + Sync {
    fn secret(&self, prompt: &str, env_key: &str) -> Result<String>;
}

pub struct TtyPrompter;
impl Prompter for TtyPrompter {
    fn secret(&self, prompt: &str, env_key: &str) -> Result<String> {
        if let Ok(v) = std::env::var(env_key) {
            return Ok(v);
        }
        Ok(rpassword::prompt_password(prompt)?)
    }
}

pub struct RealConnector(pub TransportChoice);
#[async_trait]
impl Connector for RealConnector {
    async fn open(&self, cfg: &mut Config) -> prism_client::Result<Box<dyn Transport>> {
        prism_client::open_transport(cfg, &self.0).await
    }
}

pub struct Env {
    pub connector: Box<dyn Connector>,
    pub paths: Paths,
    pub prompter: Box<dyn Prompter>,
    pub out: Mutex<Box<dyn Write + Send>>,
    /// Send SetTime after connecting (default true).
    pub time_sync: bool,
}

impl Env {
    pub fn new(connector: Box<dyn Connector>, paths: Paths) -> Env {
        Env {
            connector,
            paths,
            prompter: Box::new(TtyPrompter),
            out: Mutex::new(Box::new(std::io::stdout())),
            time_sync: true,
        }
    }

    pub fn say(&self, s: impl AsRef<str>) {
        let mut o = self.out.lock().unwrap();
        let _ = writeln!(o, "{}", s.as_ref());
        let _ = o.flush();
    }

    /// Open the transport, handshake (verifying the pinned device key), and sync time.
    pub async fn connect(&self) -> Result<Client> {
        let (mut client, mut cfg) = self.handshake().await?;
        let out = client.establish(None).await?;
        self.after_connect(&mut client, &mut cfg, &out).await?;
        Ok(client)
    }

    async fn handshake(&self) -> Result<(Client, Config)> {
        let mut cfg = self.paths.load_config()?;
        let key = self.paths.load_or_create_host_key()?;
        let transport = self.connector.open(&mut cfg).await.context("connecting to device")?;
        let client = Client::connect(transport, ClientOptions::new(key).pinned(cfg.pinned_device())).await?;
        Ok((client, cfg))
    }

    async fn after_connect(&self, client: &mut Client, cfg: &mut Config, _out: &EstablishOutcome) -> Result<()> {
        // Trust on first use if nothing is pinned yet (device already knew this host).
        if cfg.pinned_device().is_none() {
            cfg.pin_device(&client.device_pubkey());
        }
        self.paths.save_config(cfg)?;
        if self.time_sync {
            client.sync_time().await.context("time sync")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- CLI definition

#[derive(Parser, Debug)]
#[command(name = "prism", version, about = "Prism hardware password manager companion")]
pub struct Cli {
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    pub json: bool,
    /// Transport to use (default: config, else auto = USB if present, else BLE).
    #[arg(long, global = true, value_enum)]
    pub transport: Option<TransportArg>,
    /// Serial port path for USB (default: discover by VID/PID 303A:8360).
    #[arg(long, global = true)]
    pub port: Option<String>,
    /// Do not send SetTime after connecting.
    #[arg(long, global = true)]
    pub no_time_sync: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TransportArg {
    Auto,
    Usb,
    Ble,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KindArg {
    Password,
    Totp,
    Passkey,
    Ssh,
    Recovery,
}
impl From<KindArg> for EntryKind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::Password => EntryKind::Password,
            KindArg::Totp => EntryKind::Totp,
            KindArg::Passkey => EntryKind::Passkey,
            KindArg::Ssh => EntryKind::SshKey,
            KindArg::Recovery => EntryKind::RecoveryCodes,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum FieldArg {
    Password,
    Username,
    Notes,
    TotpSecret,
    RecoveryCodes,
    SshPublicKey,
}
impl From<FieldArg> for SecretField {
    fn from(f: FieldArg) -> Self {
        match f {
            FieldArg::Password => SecretField::Password,
            FieldArg::Username => SecretField::Username,
            FieldArg::Notes => SecretField::Notes,
            FieldArg::TotpSecret => SecretField::TotpSecret,
            FieldArg::RecoveryCodes => SecretField::RecoveryCodes,
            FieldArg::SshPublicKey => SecretField::SshPublicKey,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum PolicyArg {
    #[default]
    Always,
    Session,
    Never,
}
impl From<PolicyArg> for ApprovalPolicy {
    fn from(p: PolicyArg) -> Self {
        match p {
            PolicyArg::Always => ApprovalPolicy::Always,
            PolicyArg::Session => ApprovalPolicy::Session,
            PolicyArg::Never => ApprovalPolicy::Never,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Pair this host with the device (device must be in Settings > Pair new host).
    Pair,
    /// Show device information.
    Info,
    /// Set the device clock from the host clock.
    TimeSync,
    /// List entries.
    Ls {
        #[arg(long, value_enum)]
        kind: Option<KindArg>,
    },
    /// Show / reveal an entry field.
    Show {
        /// Entry id (hex prefix) or title.
        entry: String,
        #[arg(long, value_enum)]
        field: Option<FieldArg>,
        /// Copy to the clipboard (cleared after 30 s) instead of printing.
        #[arg(long)]
        copy: bool,
    },
    /// Add an entry.
    #[command(subcommand)]
    Add(AddCmd),
    /// Generate a new Ed25519 SSH key on the device.
    SshGen {
        name: String,
        #[arg(long, default_value = "")]
        comment: String,
        #[arg(long, value_enum, default_value_t = PolicyArg::Always)]
        policy: PolicyArg,
    },
    /// Print the OpenSSH public key of an SSH key entry.
    SshPubkey { name: String },
    /// Show the current TOTP code.
    Totp {
        name: String,
        #[arg(long)]
        copy: bool,
    },
    /// Delete an entry (requires a tap on the device).
    Rm { entry: String },
    /// Download an encrypted export (.prism).
    Export { file: PathBuf },
    /// Set or replace the device's recovery passphrase (used to encrypt exports).
    #[command(subcommand)]
    RecoveryPassphrase(PassCmd),
    /// Upload an export file to the device (replaces the vault unless --merge).
    Import {
        file: PathBuf,
        #[arg(long)]
        merge: bool,
    },
    /// Device settings.
    #[command(subcommand)]
    Settings(SettingsCmd),
    /// Paired hosts.
    #[command(subcommand)]
    Hosts(HostsCmd),
    /// Run the SSH agent (or install/uninstall it as a service).
    Agent(AgentArgs),
}

#[derive(Subcommand, Debug)]
pub enum AddCmd {
    /// Add a password (prompted unless --generate).
    Password {
        title: String,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value = "")]
        notes: String,
        /// Generate a random password instead of prompting.
        #[arg(long)]
        generate: bool,
        #[arg(long, default_value_t = 24)]
        length: usize,
        /// Print the generated password.
        #[arg(long)]
        print: bool,
        #[arg(long, value_enum, default_value_t = PolicyArg::Always)]
        policy: PolicyArg,
    },
    /// Add a TOTP from an otpauth:// URI or a base32 secret.
    Totp {
        /// otpauth://totp/... URI
        uri: Option<String>,
        #[arg(long)]
        secret: Option<String>,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        account: Option<String>,
        #[arg(long, value_enum, default_value_t = PolicyArg::Always)]
        policy: PolicyArg,
    },
    /// Add recovery codes (one per line from a file, or stdin).
    Recovery {
        title: String,
        /// File with codes; default stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = PolicyArg::Always)]
        policy: PolicyArg,
    },
    /// Import an OpenSSH Ed25519 private key.
    SshImport {
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_enum, default_value_t = PolicyArg::Always)]
        policy: PolicyArg,
    },
}

#[derive(Subcommand, Debug)]
pub enum SettingsCmd {
    /// Print settings.
    Get,
    /// Change one setting: auto-lock-secs, sleep-mode (power-off|light-sleep), keyboard-layout (us|fr-azerty),
    /// orientation (portrait|landscape), buzzer (true|false), owner-info (text, empty clears).
    Set { key: String, value: String },
}

#[derive(Subcommand, Debug)]
pub enum PassCmd {
    /// Set or replace the recovery passphrase (prompted twice).
    Set,
}

#[derive(Subcommand, Debug)]
pub enum HostsCmd {
    /// List paired hosts.
    Ls,
    /// Remove a paired host by list index or public key hex prefix.
    Rm { host: String },
}

#[derive(Args, Debug)]
pub struct AgentArgs {
    /// Unix socket path (default $XDG_RUNTIME_DIR/prism-agent.sock or ~/.prism/agent.sock).
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,
    #[command(subcommand)]
    pub action: Option<AgentAction>,
}

#[derive(Subcommand, Debug)]
pub enum AgentAction {
    /// Write a launchd (macOS) / systemd --user (Linux) service definition.
    Install {
        /// Also load/enable it now.
        #[arg(long)]
        load: bool,
    },
    /// Remove the service definition.
    Uninstall {
        #[arg(long)]
        load: bool,
    },
}

// ---------------------------------------------------------------- helpers

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn short_id(id: &EntryId) -> String {
    id.to_hex()[..8].to_string()
}

fn summary_json(s: &EntrySummary) -> serde_json::Value {
    json!({
        "id": s.id.to_hex(), "kind": s.kind, "title": s.title, "subtitle": s.subtitle, "url": s.url,
        "tags": s.tags, "modified": s.modified, "has_totp": s.has_totp, "policy": s.policy,
    })
}

/// Resolve `<id|title>`: hex id prefix, exact title (case-insensitive), then unique substring.
pub fn resolve<'a>(list: &'a [EntrySummary], key: &str) -> Result<&'a EntrySummary> {
    let k = key.to_lowercase();
    let is_hex = k.len() >= 4 && k.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex {
        let m: Vec<_> = list.iter().filter(|s| s.id.to_hex().starts_with(&k)).collect();
        if m.len() == 1 {
            return Ok(m[0]);
        }
    }
    let exact: Vec<_> = list.iter().filter(|s| s.title.to_lowercase() == k).collect();
    if exact.len() == 1 {
        return Ok(exact[0]);
    }
    if exact.len() > 1 {
        bail!("'{key}' is ambiguous ({} entries with that title); use the id", exact.len());
    }
    let sub: Vec<_> = list.iter().filter(|s| s.title.to_lowercase().contains(&k)).collect();
    match sub.len() {
        0 => bail!("no entry matching '{key}'"),
        1 => Ok(sub[0]),
        n => bail!("'{key}' matches {n} entries; be more specific or use the id"),
    }
}

fn new_entry(title: &str, policy: ApprovalPolicy, data: EntryData) -> Entry {
    let now = now_unix();
    Entry {
        id: new_entry_id(&mut OsRng),
        title: title.to_string(),
        tags: vec![],
        created: now,
        modified: now,
        policy,
        data,
    }
}

fn secret_to_string(v: &SecretValue) -> String {
    match v {
        SecretValue::Text(t) => t.clone(),
        SecretValue::Bytes(b) => hex::encode(b),
        SecretValue::List(l) => l.join("\n"),
    }
}

fn default_field(kind: EntryKind) -> SecretField {
    match kind {
        EntryKind::Password | EntryKind::Passkey => SecretField::Password,
        EntryKind::Totp => SecretField::TotpSecret,
        EntryKind::SshKey => SecretField::SshPublicKey,
        EntryKind::RecoveryCodes => SecretField::RecoveryCodes,
    }
}

/// Put `text` on the clipboard and clear it after 30 s (if unchanged). Blocks for 30 s.
fn copy_with_clear(text: String) -> Result<()> {
    let mut cb = arboard::Clipboard::new().map_err(|e| anyhow!("clipboard unavailable: {e}"))?;
    cb.set_text(text.clone()).map_err(|e| anyhow!("clipboard: {e}"))?;
    std::thread::sleep(std::time::Duration::from_secs(30));
    if cb.get_text().map(|c| c == text).unwrap_or(false) {
        let _ = cb.clear();
    }
    Ok(())
}

async fn output_secret(env: &Env, json: bool, label: &str, value: String, copy: bool) -> Result<()> {
    if copy {
        eprintln!("{label} copied to clipboard; clearing in 30 s (keep this process running)");
        tokio::task::spawn_blocking(move || copy_with_clear(value)).await??;
    } else if json {
        env.say(json!({ "field": label, "value": value }).to_string());
    } else {
        env.say(value);
    }
    Ok(())
}

fn table(header: &[&str]) -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(header.to_vec());
    t
}

fn read_codes(text: &str) -> Vec<RecoveryCode> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| RecoveryCode { code: l.to_string(), used: false })
        .collect()
}

/// Parse an OpenSSH private key (decrypting if needed) into an Ed25519 `(seed, public, comment)`.
pub fn parse_ssh_private(pem: &str, passphrase: impl FnOnce() -> Result<String>) -> Result<([u8; 32], [u8; 32], String)> {
    let mut key = ssh_key::PrivateKey::from_openssh(pem).map_err(|e| anyhow!("not a valid OpenSSH private key: {e}"))?;
    if key.is_encrypted() {
        let pw = passphrase()?;
        key = key.decrypt(pw.as_bytes()).map_err(|e| anyhow!("could not decrypt key (wrong passphrase?): {e}"))?;
    }
    let comment = key.comment().to_string();
    match key.key_data() {
        ssh_key::private::KeypairData::Ed25519(kp) => Ok((kp.private.to_bytes(), kp.public.0, comment)),
        other => bail!("only Ed25519 keys are supported (this key is {})", other.algorithm().map(|a| a.to_string()).unwrap_or_default()),
    }
}

fn parse_bool(v: &str) -> Result<bool> {
    match v.to_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Ok(true),
        "false" | "off" | "no" | "0" => Ok(false),
        _ => bail!("expected true/false"),
    }
}

pub fn apply_setting(s: &mut Settings, key: &str, value: &str) -> Result<()> {
    match key {
        "auto-lock-secs" => s.auto_lock_secs = value.parse().context("expected a number of seconds")?,
        "sleep-mode" => {
            s.sleep_mode = match value {
                "power-off" => SleepMode::PowerOff,
                "light-sleep" => SleepMode::LightSleep,
                _ => bail!("expected power-off or light-sleep"),
            }
        }
        "keyboard-layout" => {
            s.keyboard_layout = match value {
                "us" => KeyboardLayout::Us,
                "fr-azerty" | "fr" => KeyboardLayout::FrAzerty,
                _ => bail!("expected us or fr-azerty"),
            }
        }
        "orientation" => {
            s.orientation = match value {
                "portrait" => Orientation::Portrait,
                "landscape" => Orientation::Landscape,
                _ => bail!("expected portrait or landscape"),
            }
        }
        "buzzer" => s.buzzer = parse_bool(value)?,
        "owner-info" => s.owner_info = if value.is_empty() { None } else { Some(value.to_string()) },
        _ => bail!("unknown setting '{key}'"),
    }
    Ok(())
}

fn settings_json(s: &Settings) -> serde_json::Value {
    json!({
        "auto-lock-secs": s.auto_lock_secs, "sleep-mode": format!("{:?}", s.sleep_mode),
        "keyboard-layout": format!("{:?}", s.keyboard_layout), "orientation": format!("{:?}", s.orientation),
        "buzzer": s.buzzer, "owner-info": s.owner_info,
    })
}

// ---------------------------------------------------------------- run

pub async fn run(cli: Cli, env: &Arc<Env>) -> Result<()> {
    let json = cli.json;
    match cli.cmd {
        Cmd::Pair => {
            let (mut client, mut cfg) = env.handshake().await?;
            if cfg.pinned_device().is_some_and(|k| k != client.device_pubkey()) {
                unreachable!("pin enforced by connect");
            }
            let mut sas = None;
            env.say("Put the device in Settings > Pair new host, then confirm the code on the device.");
            let mut show = |s: &str| {
                env.say(format!("Verification code: {s}  (must match the device screen)"));
                sas = Some(s.to_string());
            };
            let out = client.establish(Some(&mut show)).await?;
            cfg.pin_device(&client.device_pubkey());
            env.after_connect(&mut client, &mut cfg, &out).await?;
            match &out {
                EstablishOutcome::Paired { label, .. } => env.say(format!("Paired as '{label}'.")),
                EstablishOutcome::Ready(_) => env.say("This host was already paired."),
            }
            env.say(format!("Device key pinned: {}", hex::encode(client.device_pubkey())));
        }
        Cmd::Info => {
            let mut c = env.connect().await?;
            let i = c.info().await?;
            if json {
                env.say(json!({
                    "fw_version": i.fw_version, "device_pubkey": hex::encode(i.device_pubkey), "locked": i.locked,
                    "initialized": i.initialized, "battery_pct": i.battery_pct, "charging": i.charging,
                    "entry_count": i.entry_count, "time_valid": i.time_valid,
                })
                .to_string());
            } else {
                let mut t = table(&["Field", "Value"]);
                t.add_row(["Firmware", &i.fw_version]);
                t.add_row(["Device key", &hex::encode(i.device_pubkey)]);
                t.add_row(["Locked", &i.locked.to_string()]);
                t.add_row(["Initialized", &i.initialized.to_string()]);
                t.add_row(["Battery", &format!("{}%{}", i.battery_pct, if i.charging { " (charging)" } else { "" })]);
                t.add_row(["Entries", &i.entry_count.to_string()]);
                t.add_row(["Time valid", &i.time_valid.to_string()]);
                env.say(t.to_string());
            }
        }
        Cmd::TimeSync => {
            let mut c = env.connect().await?;
            c.sync_time().await?; // explicit (connect also syncs unless --no-time-sync)
            env.say("Device time set.");
        }
        Cmd::Ls { kind } => {
            let mut c = env.connect().await?;
            let list = c.list(kind.map(Into::into)).await?;
            if json {
                env.say(serde_json::Value::Array(list.iter().map(summary_json).collect()).to_string());
            } else {
                let mut t = table(&["ID", "Kind", "Title", "Detail", "Approval"]);
                for s in &list {
                    t.add_row([
                        short_id(&s.id),
                        format!("{:?}", s.kind),
                        s.title.clone(),
                        s.subtitle.clone(),
                        format!("{:?}", s.policy),
                    ]);
                }
                env.say(t.to_string());
            }
        }
        Cmd::Show { entry, field, copy } => {
            let mut c = env.connect().await?;
            let list = c.list(None).await?;
            let s = resolve(&list, &entry)?;
            if json && s.kind == EntryKind::RecoveryCodes && matches!(field, None | Some(FieldArg::RecoveryCodes)) {
                // GetEntry carries the per-code `used` state.
                if let EntryData::RecoveryCodes(rc) = c.get_entry(s.id).await?.data.clone() {
                    let codes: Vec<_> = rc.codes.iter().map(|x| json!({"code": x.code, "used": x.used})).collect();
                    env.say(json!({ "field": "RecoveryCodes", "value": rc.codes.iter().filter(|x| !x.used).map(|x| x.code.clone()).collect::<Vec<_>>(), "codes": codes }).to_string());
                    return Ok(());
                }
            }
            let f = field.map(Into::into).unwrap_or_else(|| default_field(s.kind));
            let v = c.get_secret(s.id, f, None).await?;
            output_secret(env, json, &format!("{f:?}"), secret_to_string(&v), copy).await?;
        }
        Cmd::Add(a) => {
            let entry = match a {
                AddCmd::Password { title, username, url, notes, generate, length, print, policy } => {
                    let pw = if generate {
                        let opts = PasswordOptions { length, ..Default::default() };
                        let p = generate_password(&opts, &mut OsRng)?;
                        if print {
                            env.say(p.as_str());
                        }
                        p.to_string()
                    } else {
                        let a = env.prompter.secret("Password: ", "PRISM_PASSWORD")?;
                        if std::env::var("PRISM_PASSWORD").is_err() {
                            let b = env.prompter.secret("Repeat password: ", "PRISM_PASSWORD")?;
                            if a != b {
                                bail!("passwords do not match");
                            }
                        }
                        a
                    };
                    new_entry(
                        &title,
                        policy.into(),
                        EntryData::Password(Password { username, password: pw, url, notes, totp: None }),
                    )
                }
                AddCmd::Totp { uri, secret, title, issuer, account, policy } => {
                    let mut t = match (uri, secret) {
                        (Some(u), None) => totp::parse_otpauth(&u)?,
                        (None, Some(s)) => Totp {
                            issuer: String::new(),
                            account: String::new(),
                            secret: totp::base32_decode(&s)?,
                            algorithm: TotpAlgorithm::Sha1,
                            digits: 6,
                            period: 30,
                        },
                        (None, None) => {
                            let s = env.prompter.secret("Base32 secret or otpauth URI: ", "PRISM_TOTP")?;
                            if s.starts_with("otpauth://") {
                                totp::parse_otpauth(&s)?
                            } else {
                                Totp {
                                    issuer: String::new(),
                                    account: String::new(),
                                    secret: totp::base32_decode(&s)?,
                                    algorithm: TotpAlgorithm::Sha1,
                                    digits: 6,
                                    period: 30,
                                }
                            }
                        }
                        (Some(_), Some(_)) => bail!("give either a URI or --secret, not both"),
                    };
                    if let Some(i) = issuer {
                        t.issuer = i;
                    }
                    if let Some(a) = account {
                        t.account = a;
                    }
                    let title = title.unwrap_or_else(|| match (t.issuer.is_empty(), t.account.is_empty()) {
                        (false, false) => format!("{}: {}", t.issuer, t.account),
                        (false, true) => t.issuer.clone(),
                        (true, false) => t.account.clone(),
                        _ => "TOTP".to_string(),
                    });
                    new_entry(&title, policy.into(), EntryData::Totp(t))
                }
                AddCmd::Recovery { title, file, policy } => {
                    let text = match file {
                        Some(p) => std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?,
                        None => {
                            let mut s = String::new();
                            std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                            s
                        }
                    };
                    let codes = read_codes(&text);
                    if codes.is_empty() {
                        bail!("no recovery codes found in input");
                    }
                    new_entry(
                        &title,
                        policy.into(),
                        EntryData::RecoveryCodes(RecoveryCodes { service: title.clone(), codes, notes: String::new() }),
                    )
                }
                AddCmd::SshImport { file, name, policy } => {
                    let pem = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
                    let (seed, public, comment) =
                        parse_ssh_private(&pem, || env.prompter.secret("Key passphrase: ", "PRISM_SSH_PASSPHRASE"))?;
                    let title = name.unwrap_or_else(|| {
                        file.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "ssh key".into())
                    });
                    new_entry(
                        &title,
                        policy.into(),
                        EntryData::SshKey(SshKey {
                            comment,
                            source: SshKeySource::Imported { secret: seed },
                            public_key: public,
                        }),
                    )
                }
            };
            let title = entry.title.clone();
            let mut c = env.connect().await?;
            let id = c.add_entry(entry).await?;
            if json {
                env.say(json!({ "id": id.to_hex(), "title": title }).to_string());
            } else {
                env.say(format!("Added '{title}' ({})", short_id(&id)));
            }
        }
        Cmd::SshGen { name, comment, policy } => {
            let mut c = env.connect().await?;
            let k = c.generate_ssh_key(&name, &comment, policy.into()).await?;
            if json {
                env.say(json!({ "id": k.id.to_hex(), "name": k.name, "public_key": k.openssh }).to_string());
            } else {
                env.say(k.openssh);
            }
        }
        Cmd::SshPubkey { name } => {
            let mut c = env.connect().await?;
            let keys = c.ssh_list_keys().await?;
            let n = name.to_lowercase();
            let k = keys
                .iter()
                .find(|k| k.name.to_lowercase() == n || k.id.to_hex().starts_with(&n))
                .ok_or_else(|| anyhow!("no SSH key named '{name}'"))?;
            if json {
                env.say(json!({ "id": k.id.to_hex(), "name": k.name, "public_key": k.openssh }).to_string());
            } else {
                env.say(&k.openssh);
            }
        }
        Cmd::Totp { name, copy } => {
            let mut c = env.connect().await?;
            let list: Vec<_> = c.list(None).await?.into_iter().filter(|s| s.has_totp).collect();
            let s = resolve(&list, &name)?;
            let (code, until) = c.get_totp(s.id).await?;
            let left = until.saturating_sub(now_unix());
            if json {
                env.say(json!({ "code": code, "valid_until": until }).to_string());
            } else if copy {
                eprintln!("(valid for {left} s)");
                output_secret(env, false, "totp", code, true).await?;
            } else {
                env.say(format!("{code}  (valid for {left} s)"));
            }
        }
        Cmd::Rm { entry } => {
            let mut c = env.connect().await?;
            let list = c.list(None).await?;
            let s = resolve(&list, &entry)?;
            let (id, title) = (s.id, s.title.clone());
            c.delete_entry(id).await?;
            env.say(format!("Deleted '{title}'."));
        }
        Cmd::Export { file } => {
            let pass = env.prompter.secret("Recovery passphrase: ", "PRISM_PASSPHRASE")?;
            let mut c = env.connect().await?;
            let data = c.export(&pass).await?;
            write_private_file(&file, &data)?;
            env.say(format!("Wrote {} bytes to {} (encrypted with the device recovery passphrase).", data.len(), file.display()));
        }
        Cmd::RecoveryPassphrase(PassCmd::Set) => {
            let a = env.prompter.secret("New recovery passphrase (min 8 chars): ", "PRISM_NEW_PASSPHRASE")?;
            if std::env::var("PRISM_NEW_PASSPHRASE").is_err() {
                let b = env.prompter.secret("Repeat: ", "PRISM_NEW_PASSPHRASE")?;
                if a != b {
                    bail!("passphrases do not match");
                }
            }
            let mut c = env.connect().await?;
            c.set_recovery_passphrase(&a).await?;
            env.say("Recovery passphrase set.");
        }
        Cmd::Import { file, merge } => {
            let data = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let pass = env.prompter.secret("Recovery passphrase: ", "PRISM_PASSPHRASE")?;
            let mut c = env.connect().await?;
            let mode = if merge { ImportMode::Merge } else { ImportMode::Replace };
            c.import(&data, &pass, mode).await?;
            env.say(if merge { "Merged." } else { "Imported (vault replaced)." });
        }
        Cmd::Settings(sc) => {
            let mut c = env.connect().await?;
            let mut s = c.get_settings().await?;
            if let SettingsCmd::Set { key, value } = &sc {
                apply_setting(&mut s, key, value)?;
                c.set_settings(s.clone()).await?;
            }
            if json {
                env.say(settings_json(&s).to_string());
            } else {
                let mut t = table(&["Setting", "Value"]);
                for (k, v) in settings_json(&s).as_object().unwrap() {
                    t.add_row([k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())]);
                }
                env.say(t.to_string());
            }
        }
        Cmd::Hosts(h) => {
            let mut c = env.connect().await?;
            let hosts = c.list_paired_hosts().await?;
            match h {
                HostsCmd::Ls => {
                    if json {
                        env.say(
                            serde_json::Value::Array(
                                hosts
                                    .iter()
                                    .map(|h| json!({"public_key": hex::encode(h.public_key), "label": h.label, "paired_at": h.paired_at, "last_seen": h.last_seen}))
                                    .collect(),
                            )
                            .to_string(),
                        );
                    } else {
                        let mut t = table(&["#", "Label", "Public key", "Paired", "Last seen"]);
                        for (i, h) in hosts.iter().enumerate() {
                            t.add_row([
                                i.to_string(),
                                h.label.clone(),
                                hex::encode(&h.public_key[..8]) + "…",
                                h.paired_at.to_string(),
                                h.last_seen.to_string(),
                            ]);
                        }
                        env.say(t.to_string());
                    }
                }
                HostsCmd::Rm { host } => {
                    let target = if let Ok(i) = host.parse::<usize>().map_err(|_| ()).and_then(|i| hosts.get(i).ok_or(())) {
                        i
                    } else {
                        let m: Vec<_> = hosts.iter().filter(|h| hex::encode(h.public_key).starts_with(&host.to_lowercase())).collect();
                        match m.len() {
                            1 => m[0],
                            0 => bail!("no paired host matching '{host}'"),
                            _ => bail!("'{host}' matches several hosts"),
                        }
                    };
                    c.remove_paired_host(target.public_key).await?;
                    env.say(format!("Removed '{}'.", target.label));
                }
            }
        }
        Cmd::Agent(a) => {
            let socket = a.socket.clone().unwrap_or_else(agent::default_socket_path);
            match a.action {
                Some(AgentAction::Install { load }) => env.say(install::install(&socket, load)?.trim_end()),
                Some(AgentAction::Uninstall { load }) => env.say(install::uninstall(load)?.trim_end()),
                None => {
                    let listener = agent::bind(&socket)?;
                    env.say(format!("export SSH_AUTH_SOCK={}", socket.display()));
                    let ag = agent::Agent::new(env.clone());
                    tokio::select! {
                        r = ag.serve(listener) => r?,
                        _ = tokio::signal::ctrl_c() => {}
                    }
                    let _ = std::fs::remove_file(&socket);
                }
            }
        }
    }
    Ok(())
}

fn write_private_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)?;
    Ok(())
}
