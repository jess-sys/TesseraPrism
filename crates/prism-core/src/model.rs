//! Shared data model. This is the contract between firmware, protocol and companions.
//! Secret-bearing fields use `Zeroizing`/`ZeroizeOnDrop`; summaries never contain secrets.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 16-byte random entry identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntryId(pub [u8; 16]);

impl EntryId {
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex = core::str::from_utf8(chunk).ok()?;
            out[i] = u8::from_str_radix(hex, 16).ok()?;
        }
        Some(Self(out))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryKind {
    Password,
    Totp,
    Passkey,
    SshKey,
    RecoveryCodes,
}

/// When the device must ask for a physical tap before using an entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalPolicy {
    /// Tap required on every use.
    #[default]
    Always,
    /// Tap once; further uses are silent until the device locks.
    Session,
    /// Never ask (still requires the device to be unlocked).
    Never,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: EntryId,
    pub title: String,
    pub tags: Vec<String>,
    pub created: u64,
    pub modified: u64,
    pub policy: ApprovalPolicy,
    pub data: EntryData,
}

impl Entry {
    pub fn kind(&self) -> EntryKind {
        match &self.data {
            EntryData::Password(_) => EntryKind::Password,
            EntryData::Totp(_) => EntryKind::Totp,
            EntryData::Passkey(_) => EntryKind::Passkey,
            EntryData::SshKey(_) => EntryKind::SshKey,
            EntryData::RecoveryCodes(_) => EntryKind::RecoveryCodes,
        }
    }

    /// Non-secret view, safe to send to any paired host and to show in lists.
    pub fn summary(&self) -> EntrySummary {
        let subtitle = match &self.data {
            EntryData::Password(p) => p.username.clone(),
            EntryData::Totp(t) => t.account.clone(),
            EntryData::Passkey(p) => p.user_name.clone(),
            EntryData::SshKey(s) => s.comment.clone(),
            EntryData::RecoveryCodes(r) => {
                let left = r.codes.iter().filter(|c| !c.used).count();
                format!("{left}/{} left", r.codes.len())
            }
        };
        let url = match &self.data {
            EntryData::Password(p) => p.url.clone(),
            EntryData::Passkey(p) => Some(p.rp_id.clone()),
            _ => None,
        };
        EntrySummary {
            id: self.id,
            kind: self.kind(),
            title: self.title.clone(),
            subtitle,
            url,
            tags: self.tags.clone(),
            modified: self.modified,
            has_totp: matches!(&self.data, EntryData::Password(p) if p.totp.is_some())
                || matches!(&self.data, EntryData::Totp(_)),
            policy: self.policy,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryData {
    Password(Password),
    Totp(Totp),
    Passkey(Passkey),
    SshKey(SshKey),
    RecoveryCodes(RecoveryCodes),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Password {
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: String,
    /// Optional TOTP attached to a login.
    pub totp: Option<Totp>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Totp {
    pub issuer: String,
    pub account: String,
    /// Raw (base32-decoded) secret bytes.
    pub secret: Vec<u8>,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum CoseAlg {
    /// -7
    Es256,
    /// -8
    EdDsa,
}

/// A resident (discoverable) FIDO2 credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Passkey {
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub credential_id: Vec<u8>,
    pub alg: CoseAlg,
    /// Private key is re-derived from the master seed with this nonce (see ARCHITECTURE §3/§6).
    pub key_nonce: [u8; 16],
    pub created: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub enum SshKeySource {
    /// Derived from the master seed: HKDF info "ssh-ed25519/{index}".
    Derived { index: u32 },
    /// Imported Ed25519 secret seed (32 bytes). Included in exports.
    Imported { secret: [u8; 32] },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SshKey {
    pub comment: String,
    pub source: SshKeySource,
    /// Raw Ed25519 public key (32 bytes), cached for listing while unlocked.
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode {
    pub code: String,
    pub used: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCodes {
    pub service: String,
    pub codes: Vec<RecoveryCode>,
    pub notes: String,
}

/// Non-secret projection of an entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrySummary {
    pub id: EntryId,
    pub kind: EntryKind,
    pub title: String,
    pub subtitle: String,
    pub url: Option<String>,
    pub tags: Vec<String>,
    pub modified: u64,
    pub has_totp: bool,
    pub policy: ApprovalPolicy,
}

/// The decrypted vault (lives in PSRAM only while unlocked).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub entries: Vec<Entry>,
    /// Next index for seed-derived SSH keys.
    pub next_ssh_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretField {
    Password,
    Username,
    Notes,
    TotpSecret,
    RecoveryCodes,
    /// OpenSSH public key line (not secret but grouped here for convenience).
    SshPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub enum SecretValue {
    Text(String),
    Bytes(Vec<u8>),
    List(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshPublicKey {
    pub id: EntryId,
    pub name: String,
    pub comment: String,
    /// SSH wire-format public key blob ("ssh-ed25519" string + key).
    pub blob: Vec<u8>,
    /// "ssh-ed25519 AAAA... comment"
    pub openssh: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyboardLayout {
    #[default]
    Us,
    FrAzerty,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SleepMode {
    /// Lock, draw lock screen, cut power. Boot with the power button.
    #[default]
    PowerOff,
    /// Lock, stay BLE-connectable with automatic light sleep.
    LightSleep,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Orientation {
    #[default]
    Portrait,
    Landscape,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub auto_lock_secs: u32,
    pub sleep_mode: SleepMode,
    pub keyboard_layout: KeyboardLayout,
    pub orientation: Orientation,
    pub buzzer: bool,
    /// Shown on the lock screen if set.
    pub owner_info: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_secs: 180,
            sleep_mode: SleepMode::PowerOff,
            keyboard_layout: KeyboardLayout::Us,
            orientation: Orientation::Portrait,
            buzzer: true,
            owner_info: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportMode {
    /// Replace the whole vault and seed with the export's.
    Replace,
    /// Merge entries (by id, newest `modified` wins); keeps the device seed. Seed-derived keys
    /// from a different seed are converted to `Imported`.
    Merge,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedHost {
    pub public_key: [u8; 32],
    pub label: String,
    pub paired_at: u64,
    pub last_seen: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub fw_version: String,
    pub device_pubkey: [u8; 32],
    pub locked: bool,
    pub initialized: bool,
    pub battery_pct: u8,
    pub charging: bool,
    pub entry_count: u32,
    pub time_valid: bool,
}
