//! Request/Response messages (ARCHITECTURE §5.3).
//!
//! On the wire (inside Noise transport) these are `postcard`. Companions in JS/Swift use the
//! equivalent serde-JSON form, which is serde's default *externally tagged* representation:
//!
//! * `Envelope`: `{"id": 7, "body": <Request|Response>}`
//! * unit variant: a bare string, e.g. `"GetInfo"`, `"Lock"`, `"Ok"`
//! * struct variant: `{"SetTime": {"unix": 1700000000}}`
//! * newtype variant: `{"Info": {...DeviceInfo...}}`, `{"Error": "Locked"}`, `{"Ctap": [1,2,3]}`
//! * `Option::None` = `null`; `Vec<u8>` / `[u8; N]` (incl. `EntryId`, public keys) = arrays of numbers
//! * model enums are strings (`"Password"`, `"Always"`, `"Us"`) or `{"Variant": {...}}`
//!
//! Examples:
//! ```json
//! {"id":1,"body":"GetInfo"}
//! {"id":2,"body":{"ListEntries":{"kind":"Password"}}}
//! {"id":3,"body":{"GetSecret":{"id":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],"field":"Password","context":null}}}
//! {"id":3,"body":{"Totp":{"code":"123456","valid_until":1700000030}}}
//! {"id":4,"body":{"Error":"NotPaired"}}
//! ```
//! `u64` values are plain JSON numbers (fine below 2^53).

use prism_core::model::{
    ApprovalPolicy, DeviceInfo, Entry, EntryId, EntryKind, EntrySummary, ImportMode,
    KeyboardLayout, PairedHost, PasskeyIdentity, SecretField, SecretValue, Settings, SshPublicKey,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub id: u32,
    pub body: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    GetInfo,
    SetTime {
        unix: u64,
    },
    Unlock {
        passphrase: String,
    },
    Lock,
    ListEntries {
        kind: Option<EntryKind>,
    },
    GetSecret {
        id: EntryId,
        field: SecretField,
        context: Option<String>,
    },
    GetTotp {
        id: EntryId,
    },
    AddEntry {
        entry: Entry,
    },
    UpdateEntry {
        entry: Entry,
    },
    DeleteEntry {
        id: EntryId,
    },
    MarkRecoveryCodeUsed {
        id: EntryId,
        index: u16,
    },
    /// → `SshKeys(vec![new_key])`
    GenerateSshKey {
        name: String,
        comment: String,
        policy: ApprovalPolicy,
    },
    SshListKeys,
    SshSign {
        public_key: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
        host_hint: Option<String>,
    },
    Ctap {
        cbor: Vec<u8>,
        origin_hint: Option<String>,
    },
    TypeEntry {
        id: EntryId,
        field: SecretField,
        layout: KeyboardLayout,
    },
    /// Device checks the passphrase against its recovery slot, then encrypts the export with it.
    Export {
        passphrase: String,
    },
    ExportChunk {
        offset: u32,
    },
    ImportBegin {
        total_len: u32,
    },
    ImportChunk {
        offset: u32,
        data: Vec<u8>,
    },
    ImportCommit {
        passphrase: String,
        mode: ImportMode,
    },
    ListPairedHosts,
    RemovePairedHost {
        public_key: [u8; 32],
    },
    GetSettings,
    SetSettings {
        settings: Settings,
    },
    /// Sets/replaces the recovery-passphrase key slot (device asks for a tap). → `Ok`
    SetRecoveryPassphrase {
        passphrase: String,
    },
    /// Full entry including secrets, e.g. for editing (approval per policy). → `Entry`
    GetEntry {
        id: EntryId,
    },
    /// Public identifiers of all passkeys (no approval needed). → `Passkeys`
    ListPasskeys,
    /// Change a paired host's display label (device asks for a tap). → `Ok`
    RenamePairedHost {
        public_key: [u8; 32],
        label: String,
    },
    /// Change one entry's approval policy (device asks for a tap). → `Ok`
    SetEntryPolicy {
        id: EntryId,
        policy: ApprovalPolicy,
    },
    /// All passwords for the host's encrypted local cache (device always asks for a tap;
    /// `Unsupported` when `Settings::password_cache_secs` is 0). → `ExportReady`, then read
    /// with `ExportChunk`; the bytes are a postcard `PasswordSnapshot`.
    PasswordSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Info(DeviceInfo),
    Ok,
    Paired { label: String },
    Entries(Vec<EntrySummary>),
    Secret(SecretValue),
    Totp { code: String, valid_until: u64 },
    EntryId(EntryId),
    SshKeys(Vec<SshPublicKey>),
    SshSignature(Vec<u8>),
    Ctap(Vec<u8>),
    ExportReady { total_len: u32 },
    Chunk { offset: u32, data: Vec<u8> },
    PairedHosts(Vec<PairedHost>),
    Settings(Settings),
    Error(ErrorCode),
    Entry(Entry),
    Passkeys(Vec<PasskeyIdentity>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    Locked,
    Denied,
    Timeout,
    NotFound,
    NotPaired,
    InvalidRequest,
    BadPassphrase,
    StorageFull,
    Unsupported,
    Busy,
    Internal,
}

/// Payload of a `PLAIN_ERROR` frame (pre-session only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoError {
    pub code: ErrorCode,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_core::model::*;
    use serde_json::json;

    fn id() -> EntryId {
        EntryId([9; 16])
    }
    fn entry() -> Entry {
        Entry {
            id: id(),
            title: "t".into(),
            tags: vec!["a".into()],
            created: 1,
            modified: 2,
            policy: ApprovalPolicy::Session,
            data: EntryData::Password(Password {
                username: "u".into(),
                password: "p".into(),
                url: Some("https://x".into()),
                notes: String::new(),
                totp: None,
            }),
        }
    }
    fn summary() -> EntrySummary {
        entry().summary()
    }
    fn info() -> DeviceInfo {
        DeviceInfo {
            fw_version: "0.1".into(),
            device_pubkey: [3; 32],
            locked: true,
            initialized: true,
            battery_pct: 80,
            charging: false,
            entry_count: 4,
            time_valid: true,
        }
    }

    pub fn all_requests() -> Vec<Request> {
        vec![
            Request::GetInfo,
            Request::SetTime {
                unix: 1_700_000_000,
            },
            Request::Unlock {
                passphrase: "pw".into(),
            },
            Request::Lock,
            Request::ListEntries { kind: None },
            Request::ListEntries {
                kind: Some(EntryKind::Totp),
            },
            Request::GetSecret {
                id: id(),
                field: SecretField::Password,
                context: Some("x".into()),
            },
            Request::GetTotp { id: id() },
            Request::AddEntry { entry: entry() },
            Request::UpdateEntry { entry: entry() },
            Request::DeleteEntry { id: id() },
            Request::MarkRecoveryCodeUsed { id: id(), index: 3 },
            Request::GenerateSshKey {
                name: "n".into(),
                comment: "c".into(),
                policy: ApprovalPolicy::Always,
            },
            Request::SshListKeys,
            Request::SshSign {
                public_key: vec![1, 2],
                data: vec![3; 10],
                flags: 2,
                host_hint: None,
            },
            Request::Ctap {
                cbor: vec![4, 0xa0],
                origin_hint: Some("o".into()),
            },
            Request::TypeEntry {
                id: id(),
                field: SecretField::Username,
                layout: KeyboardLayout::FrAzerty,
            },
            Request::Export {
                passphrase: "pp".into(),
            },
            Request::ExportChunk { offset: 8192 },
            Request::ImportBegin { total_len: 100 },
            Request::ImportChunk {
                offset: 0,
                data: vec![0; 5],
            },
            Request::ImportCommit {
                passphrase: "p".into(),
                mode: ImportMode::Merge,
            },
            Request::ListPairedHosts,
            Request::RemovePairedHost {
                public_key: [5; 32],
            },
            Request::GetSettings,
            Request::SetSettings {
                settings: Settings::default(),
            },
            Request::SetRecoveryPassphrase {
                passphrase: "correct horse".into(),
            },
            Request::GetEntry { id: id() },
        ]
    }

    pub fn all_responses() -> Vec<Response> {
        vec![
            Response::Info(info()),
            Response::Ok,
            Response::Paired { label: "l".into() },
            Response::Entries(vec![summary()]),
            Response::Secret(SecretValue::Text("s".into())),
            Response::Secret(SecretValue::List(vec!["a".into()])),
            Response::Totp {
                code: "123456".into(),
                valid_until: 30,
            },
            Response::EntryId(id()),
            Response::SshKeys(vec![SshPublicKey {
                id: id(),
                name: "n".into(),
                comment: "c".into(),
                blob: vec![1],
                openssh: "ssh-ed25519 AA".into(),
            }]),
            Response::SshSignature(vec![1, 2, 3]),
            Response::Ctap(vec![0]),
            Response::ExportReady { total_len: 99 },
            Response::Chunk {
                offset: 0,
                data: vec![7; 8192],
            },
            Response::PairedHosts(vec![PairedHost {
                public_key: [1; 32],
                label: "h".into(),
                paired_at: 1,
                last_seen: 2,
            }]),
            Response::Settings(Settings::default()),
            Response::Error(ErrorCode::NotPaired),
            Response::Entry(entry()),
        ]
    }

    #[test]
    fn postcard_and_json_roundtrip_all() {
        for (i, r) in all_requests().into_iter().enumerate() {
            let e = Envelope {
                id: i as u32,
                body: r,
            };
            let b = postcard::to_stdvec(&e).unwrap();
            assert_eq!(postcard::from_bytes::<Envelope<Request>>(&b).unwrap(), e);
            let j = serde_json::to_string(&e).unwrap();
            assert_eq!(serde_json::from_str::<Envelope<Request>>(&j).unwrap(), e);
        }
        for (i, r) in all_responses().into_iter().enumerate() {
            let e = Envelope {
                id: i as u32,
                body: r,
            };
            let b = postcard::to_stdvec(&e).unwrap();
            assert_eq!(postcard::from_bytes::<Envelope<Response>>(&b).unwrap(), e);
            let j = serde_json::to_string(&e).unwrap();
            assert_eq!(serde_json::from_str::<Envelope<Response>>(&j).unwrap(), e);
        }
        let pe = ProtoError {
            code: ErrorCode::Busy,
            message: "m".into(),
        };
        let b = postcard::to_stdvec(&pe).unwrap();
        assert_eq!(postcard::from_bytes::<ProtoError>(&b).unwrap(), pe);
    }

    #[test]
    fn json_shapes() {
        let v = |r: Request| serde_json::to_value(Envelope { id: 1, body: r }).unwrap();
        assert_eq!(v(Request::GetInfo), json!({"id":1,"body":"GetInfo"}));
        assert_eq!(
            v(Request::SetTime { unix: 5 }),
            json!({"id":1,"body":{"SetTime":{"unix":5}}})
        );
        assert_eq!(
            v(Request::ListEntries {
                kind: Some(EntryKind::Password)
            }),
            json!({"id":1,"body":{"ListEntries":{"kind":"Password"}}})
        );
        assert_eq!(
            v(Request::GetSecret {
                id: EntryId([0; 16]),
                field: SecretField::Password,
                context: None
            }),
            json!({"id":1,"body":{"GetSecret":{"id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"field":"Password","context":null}}})
        );
        let r = |r: Response| serde_json::to_value(Envelope { id: 2, body: r }).unwrap();
        assert_eq!(r(Response::Ok), json!({"id":2,"body":"Ok"}));
        assert_eq!(
            r(Response::Error(ErrorCode::Locked)),
            json!({"id":2,"body":{"Error":"Locked"}})
        );
        assert_eq!(
            r(Response::Totp {
                code: "123456".into(),
                valid_until: 30
            }),
            json!({"id":2,"body":{"Totp":{"code":"123456","valid_until":30}}})
        );
        assert_eq!(
            r(Response::Ctap(vec![1, 2])),
            json!({"id":2,"body":{"Ctap":[1,2]}})
        );
    }
}
