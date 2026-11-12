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
    /// Follow the device-wide default for the operation (`Settings::approvals`). Appended last
    /// so stored vaults keep their encoding.
    Default,
}

/// Operation categories with a configurable approval default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApprovalOp {
    /// Reveal / fetch a password, username or notes.
    Password,
    Totp,
    SshSign,
    /// Passkey sign-in (registration always asks). `Never` is treated as `Session`: the
    /// authenticator must not claim user presence without any tap.
    Passkey,
    RecoveryCodes,
    /// Type an entry over USB keyboard emulation.
    TypeOverUsb,
    /// Add or edit entries, generate SSH keys.
    Modify,
    Delete,
}

/// Device-wide approval defaults, one per `ApprovalOp`. Entries whose policy is
/// `ApprovalPolicy::Default` follow these; others override them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDefaults {
    pub password: ApprovalPolicy,
    pub totp: ApprovalPolicy,
    pub ssh_sign: ApprovalPolicy,
    pub passkey: ApprovalPolicy,
    pub recovery_codes: ApprovalPolicy,
    pub type_over_usb: ApprovalPolicy,
    pub modify: ApprovalPolicy,
    pub delete: ApprovalPolicy,
}

impl Default for ApprovalDefaults {
    fn default() -> Self {
        use ApprovalPolicy::Always;
        Self {
            password: Always,
            totp: Always,
            ssh_sign: Always,
            passkey: Always,
            recovery_codes: Always,
            type_over_usb: Always,
            modify: Always,
            delete: Always,
        }
    }
}

impl ApprovalDefaults {
    /// The default for `op`, normalised (`Default` = `Always`; passkeys never `Never`).
    pub fn get(&self, op: ApprovalOp) -> ApprovalPolicy {
        let p = match op {
            ApprovalOp::Password => self.password,
            ApprovalOp::Totp => self.totp,
            ApprovalOp::SshSign => self.ssh_sign,
            ApprovalOp::Passkey => self.passkey,
            ApprovalOp::RecoveryCodes => self.recovery_codes,
            ApprovalOp::TypeOverUsb => self.type_over_usb,
            ApprovalOp::Modify => self.modify,
            ApprovalOp::Delete => self.delete,
        };
        match (op, p) {
            (_, ApprovalPolicy::Default) => ApprovalPolicy::Always,
            (ApprovalOp::Passkey, ApprovalPolicy::Never) => ApprovalPolicy::Session,
            (_, p) => p,
        }
    }

    /// Policy that applies to an entry with `entry_policy` for `op`.
    pub fn effective(&self, entry_policy: ApprovalPolicy, op: ApprovalOp) -> ApprovalPolicy {
        match (op, entry_policy) {
            (_, ApprovalPolicy::Default) => self.get(op),
            (ApprovalOp::Passkey, ApprovalPolicy::Never) => ApprovalPolicy::Session,
            (_, p) => p,
        }
    }
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

/// Public identifiers of a passkey, so a companion can register it with the OS credential
/// store (e.g. Apple's `ASCredentialIdentityStore`). No key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyIdentity {
    pub id: EntryId,
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    pub credential_id: Vec<u8>,
}

/// One password as sent to a companion's local cache (`Request::PasswordSnapshot`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CachedPassword {
    #[zeroize(skip)]
    pub id: EntryId,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub modified: u64,
}

/// Passwords for a companion's encrypted local cache. Companions must delete it at `expires_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordSnapshot {
    pub generated_at: u64,
    pub expires_at: u64,
    pub entries: Vec<CachedPassword>,
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
    PowerOff,
    /// Lock, stay BLE-reachable in low-power standby (light sleep, slow advertising); a paired
    /// app's request wakes the PIN pad. Powers off after 24 h on battery.
    #[default]
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
    /// Approval defaults per operation type.
    pub approvals: ApprovalDefaults,
    /// How long a companion's password cache stays valid; 0 = caching disabled.
    pub password_cache_secs: u32,
}

/// `Settings` before approval defaults and the password cache (for reading stored settings).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsV1 {
    pub auto_lock_secs: u32,
    pub sleep_mode: SleepMode,
    pub keyboard_layout: KeyboardLayout,
    pub orientation: Orientation,
    pub buzzer: bool,
    pub owner_info: Option<String>,
}

impl From<SettingsV1> for Settings {
    fn from(v: SettingsV1) -> Self {
        Self {
            auto_lock_secs: v.auto_lock_secs,
            sleep_mode: v.sleep_mode,
            keyboard_layout: v.keyboard_layout,
            orientation: v.orientation,
            buzzer: v.buzzer,
            owner_info: v.owner_info,
            ..Self::default()
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_secs: 180,
            sleep_mode: SleepMode::LightSleep,
            keyboard_layout: KeyboardLayout::Us,
            orientation: Orientation::Portrait,
            buzzer: true,
            owner_info: None,
            approvals: ApprovalDefaults::default(),
            password_cache_secs: 0,
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

#[cfg(test)]
mod approval_tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let mut d = ApprovalDefaults::default();
        assert_eq!(d.effective(ApprovalPolicy::Default, ApprovalOp::Password), ApprovalPolicy::Always);
        d.password = ApprovalPolicy::Never;
        assert_eq!(d.effective(ApprovalPolicy::Default, ApprovalOp::Password), ApprovalPolicy::Never);
        assert_eq!(d.effective(ApprovalPolicy::Session, ApprovalOp::Password), ApprovalPolicy::Session, "entry overrides");
        // Passkeys never skip presence entirely.
        d.passkey = ApprovalPolicy::Never;
        assert_eq!(d.get(ApprovalOp::Passkey), ApprovalPolicy::Session);
        assert_eq!(d.effective(ApprovalPolicy::Never, ApprovalOp::Passkey), ApprovalPolicy::Session);
        d.modify = ApprovalPolicy::Default;
        assert_eq!(d.get(ApprovalOp::Modify), ApprovalPolicy::Always);
    }

    #[test]
    fn old_settings_encoding_still_reads() {
        let v1 = SettingsV1 {
            auto_lock_secs: 60,
            sleep_mode: SleepMode::PowerOff,
            keyboard_layout: KeyboardLayout::FrAzerty,
            orientation: Orientation::Portrait,
            buzzer: false,
            owner_info: Some("alice@example.org".into()),
        };
        let b = postcard::to_stdvec(&v1).unwrap();
        assert!(postcard::from_bytes::<Settings>(&b).is_err());
        let s: Settings = postcard::from_bytes::<SettingsV1>(&b).unwrap().into();
        assert_eq!(s.auto_lock_secs, 60);
        assert_eq!(s.owner_info.as_deref(), Some("alice@example.org"));
        assert_eq!(s.approvals, ApprovalDefaults::default());
        assert_eq!(s.password_cache_secs, 0);
    }

    #[test]
    fn approval_policy_encoding_is_append_only() {
        // Stored vaults encode the policy by variant index.
        for (p, i) in [(ApprovalPolicy::Always, 0u8), (ApprovalPolicy::Session, 1), (ApprovalPolicy::Never, 2), (ApprovalPolicy::Default, 3)] {
            assert_eq!(postcard::to_stdvec(&p).unwrap(), vec![i]);
        }
    }
}
