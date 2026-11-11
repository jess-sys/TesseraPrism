//! CTAP2 command handling.

use crate::cbor::{self, Value};
use crate::*;
use ed25519_dalek::Signer as _;
use hmac::{Hmac, Mac};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_RESET: u8 = 0x07;
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;
pub const CMD_CREDENTIAL_MGMT: u8 = 0x0A;
pub const CMD_SELECTION: u8 = 0x0B;

pub mod status {
    pub const OK: u8 = 0x00;
    pub const INVALID_COMMAND: u8 = 0x01;
    pub const INVALID_PARAMETER: u8 = 0x02;
    pub const INVALID_LENGTH: u8 = 0x03;
    pub const CBOR_UNEXPECTED_TYPE: u8 = 0x11;
    pub const INVALID_CBOR: u8 = 0x12;
    pub const MISSING_PARAMETER: u8 = 0x14;
    pub const CREDENTIAL_EXCLUDED: u8 = 0x19;
    pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
    pub const OPERATION_DENIED: u8 = 0x27;
    pub const KEY_STORE_FULL: u8 = 0x28;
    pub const NO_OPERATION_PENDING: u8 = 0x2A;
    pub const UNSUPPORTED_OPTION: u8 = 0x2B;
    pub const INVALID_OPTION: u8 = 0x2C;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2F;
    pub const NO_CREDENTIALS: u8 = 0x2E;
    pub const NOT_ALLOWED: u8 = 0x30;
    pub const PIN_NOT_SET: u8 = 0x35;
    pub const OTHER: u8 = 0x7F;
}
use status as st;

type Res<T> = Result<T, u8>;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
/// Backup Eligible + Backup State. Prism credentials are backed up: every private key is
/// re-derived from the master seed (24-word BIP39 backup) and the resident metadata is part of the
/// encrypted export. Apple platforms also *require* BE|BS from credential-provider passkeys
/// ("AuthData is missing a required flag", AuthorizationError 14). BE must be constant for a
/// credential's lifetime, so it is set on every registration and assertion.
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;

/// An assertion candidate.
#[derive(Clone)]
struct Cand {
    cred_id: Vec<u8>,
    alg: CoseAlg,
    nonce: [u8; 16],
    /// Resident record (for the user entity).
    resident: Option<PasskeyCredential>,
}

struct Pending {
    rp_id_hash: [u8; 32],
    client_data_hash: Vec<u8>,
    flags: u8,
    rest: Vec<Cand>, // next one is last (popped)
    include_user: bool,
}

pub struct Authenticator<P: Platform> {
    platform: P,
    pending: Option<Pending>,
}

fn sha256(d: &[u8]) -> [u8; 32] {
    Sha256::digest(d).into()
}

fn mac16(key: &[u8; 32], rp_hash: &[u8; 32], nonce: &[u8; 16], alg: CoseAlg) -> [u8; 16] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(rp_hash);
    m.update(nonce);
    // ES256 follows the contract exactly; EdDSA is domain-separated so the algorithm
    // can be recovered for non-resident credentials.
    if alg == CoseAlg::EdDsa {
        m.update(b"eddsa");
    }
    let t = m.finalize().into_bytes();
    let mut o = [0u8; 16];
    o.copy_from_slice(&t[..16]);
    o
}

fn make_cred_id(key: &[u8; 32], rp_hash: &[u8; 32], nonce: &[u8; 16], alg: CoseAlg) -> Vec<u8> {
    let mut v = nonce.to_vec();
    v.extend_from_slice(&mac16(key, rp_hash, nonce, alg));
    v
}

/// Recognise one of our own credential IDs. Returns (nonce, alg).
fn recognise(key: &[u8; 32], rp_hash: &[u8; 32], id: &[u8]) -> Option<([u8; 16], CoseAlg)> {
    if id.len() != 32 {
        return None;
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&id[..16]);
    for alg in [CoseAlg::Es256, CoseAlg::EdDsa] {
        if bool::from(mac16(key, rp_hash, &nonce, alg).ct_eq(&id[16..])) {
            return Some((nonce, alg));
        }
    }
    None
}

enum Key {
    P256(SigningKey),
    Ed(ed25519_dalek::SigningKey),
}

impl Key {
    fn derive<P: Platform>(p: &P, alg: CoseAlg, nonce: &[u8; 16]) -> Option<Key> {
        match alg {
            CoseAlg::Es256 => {
                let mut info = b"fido/es256/".to_vec();
                info.extend_from_slice(nonce);
                let mut counter = 0u8;
                loop {
                    let mut i = info.clone();
                    if counter > 0 {
                        i.push(counter);
                    }
                    let k = p.seed_key(&i)?;
                    if let Ok(sk) = SigningKey::from_bytes((&k).into()) {
                        return Some(Key::P256(sk));
                    }
                    counter = counter.checked_add(1)?;
                }
            }
            CoseAlg::EdDsa => {
                let mut info = b"fido/eddsa/".to_vec();
                info.extend_from_slice(nonce);
                let k = p.seed_key(&info)?;
                Some(Key::Ed(ed25519_dalek::SigningKey::from_bytes(&k)))
            }
        }
    }

    fn cose_public(&self) -> Value {
        match self {
            Key::P256(sk) => {
                let ep = sk.verifying_key().to_encoded_point(false);
                Value::Map(vec![
                    (Value::Int(1), Value::Int(2)),
                    (Value::Int(3), Value::Int(-7)),
                    (Value::Int(-1), Value::Int(1)),
                    (Value::Int(-2), Value::bytes(ep.x().unwrap())),
                    (Value::Int(-3), Value::bytes(ep.y().unwrap())),
                ])
            }
            Key::Ed(sk) => Value::Map(vec![
                (Value::Int(1), Value::Int(1)),
                (Value::Int(3), Value::Int(-8)),
                (Value::Int(-1), Value::Int(6)),
                (Value::Int(-2), Value::bytes(sk.verifying_key().as_bytes())),
            ]),
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Key::P256(sk) => {
                let s: p256::ecdsa::Signature = sk.sign(msg);
                s.to_der().as_bytes().to_vec()
            }
            Key::Ed(sk) => sk.sign(msg).to_bytes().to_vec(),
        }
    }
}

fn ok(v: Option<Value>) -> Vec<u8> {
    let mut out = vec![st::OK];
    if let Some(v) = v {
        cbor::encode_into(&v, &mut out);
    }
    out
}

fn cred_desc(id: &[u8]) -> Value {
    Value::Map(vec![
        (Value::text("id"), Value::bytes(id)),
        (Value::text("type"), Value::text("public-key")),
    ])
}

impl<P: Platform> Authenticator<P> {
    pub fn new(platform: P) -> Self {
        Self { platform, pending: None }
    }
    pub fn platform(&self) -> &P {
        &self.platform
    }
    pub fn platform_mut(&mut self) -> &mut P {
        &mut self.platform
    }

    /// `request` = command byte + CBOR; returns status byte + CBOR.
    pub fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        let Some((&cmd, body)) = request.split_first() else {
            return vec![st::INVALID_LENGTH];
        };
        if cmd != CMD_GET_NEXT_ASSERTION {
            self.pending = None;
        }
        let r = match cmd {
            CMD_GET_INFO => Ok(ok(Some(self.get_info()))),
            CMD_MAKE_CREDENTIAL => self.make_credential(body),
            CMD_GET_ASSERTION => self.get_assertion(body),
            CMD_GET_NEXT_ASSERTION => self.get_next_assertion(),
            CMD_RESET => self.reset(),
            CMD_SELECTION => self.presence(PresenceKind::Selection, "", "", "", "").map(|_| ok(None)),
            // CMD_CREDENTIAL_MGMT: not implemented.
            _ => Err(st::INVALID_COMMAND),
        };
        r.unwrap_or_else(|e| vec![e])
    }

    fn get_info(&self) -> Value {
        let alg = |a: i64| {
            Value::Map(vec![
                (Value::text("alg"), Value::Int(a)),
                (Value::text("type"), Value::text("public-key")),
            ])
        };
        let b = |k: &str, v: bool| (Value::text(k), Value::Bool(v));
        Value::Map(vec![
            (Value::Int(1), Value::Array(vec![Value::text("FIDO_2_0"), Value::text("FIDO_2_1")])),
            (Value::Int(3), Value::bytes(&AAGUID)),
            (
                Value::Int(4),
                Value::Map(vec![b("rk", true), b("up", true), b("uv", true), b("plat", false)]),
            ),
            (Value::Int(5), Value::Int(ctaphid::MAX_MESSAGE as i64)),
            (Value::Int(7), Value::Int(16)),
            (Value::Int(8), Value::Int(32)),
            (Value::Int(9), Value::Array(vec![Value::text("usb"), Value::text("ble")])),
            (Value::Int(10), Value::Array(vec![alg(-7), alg(-8)])),
        ])
    }

    fn presence(&mut self, kind: PresenceKind, rp_id: &str, rp_name: &str, un: &str, udn: &str) -> Res<()> {
        self.platform.keepalive(KeepaliveStatus::UpNeeded);
        let req = PresenceRequest {
            kind,
            rp_id: rp_id.into(),
            rp_name: rp_name.into(),
            user_name: un.into(),
            user_display_name: udn.into(),
        };
        match self.platform.user_presence(&req) {
            PresenceResult::Approved => Ok(()),
            PresenceResult::Denied => Err(st::OPERATION_DENIED),
            PresenceResult::Timeout => Err(st::USER_ACTION_TIMEOUT),
        }
    }

    fn wrap_key(&self) -> Res<[u8; 32]> {
        self.platform.seed_key(b"fido-cred-wrap").ok_or(st::OPERATION_DENIED)
    }

    fn reset(&mut self) -> Res<Vec<u8>> {
        self.presence(PresenceKind::Reset, "", "", "", "")?;
        self.platform.reset().map_err(|_| st::OTHER)?;
        Ok(ok(None))
    }

    fn make_credential(&mut self, body: &[u8]) -> Res<Vec<u8>> {
        let req = cbor::decode(body).map_err(|_| st::INVALID_CBOR)?;
        if !req.is_map() {
            return Err(st::CBOR_UNEXPECTED_TYPE);
        }
        let cdh = req.get(1).ok_or(st::MISSING_PARAMETER)?.as_bytes().ok_or(st::CBOR_UNEXPECTED_TYPE)?;
        let rp = req.get(2).ok_or(st::MISSING_PARAMETER)?;
        let user = req.get(3).ok_or(st::MISSING_PARAMETER)?;
        let params = req.get(4).ok_or(st::MISSING_PARAMETER)?.as_array().ok_or(st::CBOR_UNEXPECTED_TYPE)?;
        if cdh.len() != 32 {
            return Err(st::INVALID_PARAMETER);
        }
        let rp_id = rp.get_text("id").and_then(|v| v.as_text()).ok_or(st::MISSING_PARAMETER)?.to_string();
        let rp_name = rp.get_text("name").and_then(|v| v.as_text()).unwrap_or("").to_string();
        let user_id = user.get_text("id").and_then(|v| v.as_bytes()).ok_or(st::MISSING_PARAMETER)?.to_vec();
        if user_id.is_empty() || user_id.len() > 64 {
            return Err(st::INVALID_PARAMETER);
        }
        let user_name = user.get_text("name").and_then(|v| v.as_text()).unwrap_or("").to_string();
        let user_dn = user.get_text("displayName").and_then(|v| v.as_text()).unwrap_or("").to_string();

        // First supported algorithm in the RP's preference order.
        let mut alg = None;
        for p in params {
            let a = p.get_text("alg").and_then(|v| v.as_int());
            let t = p.get_text("type").and_then(|v| v.as_text());
            if t != Some("public-key") {
                continue;
            }
            match a {
                Some(-7) => { alg = Some(CoseAlg::Es256); break; }
                Some(-8) => { alg = Some(CoseAlg::EdDsa); break; }
                _ => {}
            }
        }
        let alg = alg.ok_or(st::UNSUPPORTED_ALGORITHM)?;

        let opt = |name: &str| req.get(7).and_then(|o| o.get_text(name)).and_then(|v| v.as_bool());
        let rk = opt("rk").unwrap_or(false);
        if opt("up") == Some(false) {
            return Err(st::INVALID_OPTION);
        }
        if req.get(8).is_some() || req.get(9).is_some() {
            // No clientPin; a (possibly empty) pinUvAuthParam is the "touch" probe.
            self.presence(PresenceKind::Register, &rp_id, &rp_name, &user_name, &user_dn)?;
            return Err(st::PIN_NOT_SET);
        }

        let wrap = self.wrap_key()?;
        let rp_hash = sha256(rp_id.as_bytes());
        self.platform.keepalive(KeepaliveStatus::Processing);

        // excludeList
        if let Some(ex) = req.get(5).and_then(|v| v.as_array()) {
            let resident = self.platform.find_resident(&rp_id);
            for d in ex {
                let Some(id) = d.get_text("id").and_then(|v| v.as_bytes()) else { continue };
                let known = recognise(&wrap, &rp_hash, id).is_some()
                    || resident.iter().any(|r| r.credential_id == id);
                if known {
                    self.presence(PresenceKind::Register, &rp_id, &rp_name, &user_name, &user_dn)?;
                    return Err(st::CREDENTIAL_EXCLUDED);
                }
            }
        }

        self.presence(PresenceKind::Register, &rp_id, &rp_name, &user_name, &user_dn)?;

        let mut nonce = [0u8; 16];
        self.platform.rng(&mut nonce);
        let key = Key::derive(&self.platform, alg, &nonce).ok_or(st::OPERATION_DENIED)?;
        let cred_id = make_cred_id(&wrap, &rp_hash, &nonce, alg);

        if rk {
            // Replace an existing credential for the same (rp, user).
            for old in self.platform.find_resident(&rp_id) {
                if old.user_handle == user_id {
                    let _ = self.platform.delete_resident(&old.credential_id);
                }
            }
            let pk = PasskeyCredential {
                rp_id: rp_id.clone(),
                rp_name,
                user_handle: user_id,
                user_name,
                user_display_name: user_dn,
                credential_id: cred_id.clone(),
                alg,
                key_nonce: nonce,
                created: 0,
            };
            self.platform.store_resident(pk).map_err(|e| match e {
                StorageError::Full => st::KEY_STORE_FULL,
                StorageError::Io => st::OTHER,
            })?;
        }

        let mut ad = rp_hash.to_vec();
        ad.push(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
        ad.extend_from_slice(&[0, 0, 0, 0]);
        ad.extend_from_slice(&AAGUID);
        ad.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        ad.extend_from_slice(&cred_id);
        cbor::encode_into(&key.cose_public(), &mut ad);

        Ok(ok(Some(Value::Map(vec![
            (Value::Int(1), Value::text("none")),
            (Value::Int(2), Value::Bytes(ad)),
            (Value::Int(3), Value::Map(vec![])),
        ]))))
    }

    fn get_assertion(&mut self, body: &[u8]) -> Res<Vec<u8>> {
        let req = cbor::decode(body).map_err(|_| st::INVALID_CBOR)?;
        if !req.is_map() {
            return Err(st::CBOR_UNEXPECTED_TYPE);
        }
        let rp_id = req.get(1).ok_or(st::MISSING_PARAMETER)?.as_text().ok_or(st::CBOR_UNEXPECTED_TYPE)?.to_string();
        let cdh = req.get(2).ok_or(st::MISSING_PARAMETER)?.as_bytes().ok_or(st::CBOR_UNEXPECTED_TYPE)?.to_vec();
        if cdh.len() != 32 {
            return Err(st::INVALID_PARAMETER);
        }
        let opt = |name: &str| req.get(5).and_then(|o| o.get_text(name)).and_then(|v| v.as_bool());
        let up = opt("up").unwrap_or(true);
        if opt("rk") == Some(true) {
            return Err(st::UNSUPPORTED_OPTION);
        }
        if req.get(6).is_some() || req.get(7).is_some() {
            self.presence(PresenceKind::Authenticate, &rp_id, "", "", "")?;
            return Err(st::PIN_NOT_SET);
        }
        let wrap = self.wrap_key()?;
        let rp_hash = sha256(rp_id.as_bytes());
        self.platform.keepalive(KeepaliveStatus::Processing);

        let resident = self.platform.find_resident(&rp_id);
        let allow = req.get(3).and_then(|v| v.as_array()).filter(|a| !a.is_empty());
        let mut cands: Vec<Cand> = Vec::new();
        let discoverable = allow.is_none();
        if let Some(allow) = allow {
            for d in allow {
                let Some(id) = d.get_text("id").and_then(|v| v.as_bytes()) else { continue };
                if let Some((nonce, alg)) = recognise(&wrap, &rp_hash, id) {
                    let res = resident.iter().find(|r| r.credential_id == id).cloned();
                    cands.push(Cand { cred_id: id.to_vec(), alg, nonce, resident: res });
                } else if let Some(r) = resident.iter().find(|r| r.credential_id == id) {
                    cands.push(Cand { cred_id: id.to_vec(), alg: r.alg, nonce: r.key_nonce, resident: Some(r.clone()) });
                }
            }
        } else {
            let mut rs = resident;
            rs.sort_by(|a, b| b.created.cmp(&a.created)); // most recent first
            for r in rs {
                cands.push(Cand { cred_id: r.credential_id.clone(), alg: r.alg, nonce: r.key_nonce, resident: Some(r) });
            }
        }
        if cands.is_empty() {
            return Err(st::NO_CREDENTIALS);
        }

        if up {
            let (un, dn) = cands
                .first()
                .and_then(|c| c.resident.as_ref())
                .map(|r| (r.user_name.clone(), r.user_display_name.clone()))
                .unwrap_or_default();
            self.presence(PresenceKind::Authenticate, &rp_id, "", &un, &dn)?;
        }
        let flags = FLAG_UV | FLAG_BE | FLAG_BS | if up { FLAG_UP } else { 0 };
        let total = cands.len();
        let first = cands.remove(0);
        let resp = self.assert_one(&first, &rp_hash, &cdh, flags, discoverable, if total > 1 { Some(total) } else { None })?;
        if !cands.is_empty() {
            cands.reverse();
            self.pending = Some(Pending {
                rp_id_hash: rp_hash,
                client_data_hash: cdh,
                flags,
                rest: cands,
                include_user: discoverable,
            });
        }
        Ok(resp)
    }

    fn get_next_assertion(&mut self) -> Res<Vec<u8>> {
        let mut p = self.pending.take().ok_or(st::NO_OPERATION_PENDING)?;
        let c = p.rest.pop().ok_or(st::NO_OPERATION_PENDING)?;
        let resp = self.assert_one(&c, &p.rp_id_hash, &p.client_data_hash, p.flags, p.include_user, None)?;
        if !p.rest.is_empty() {
            self.pending = Some(p);
        }
        Ok(resp)
    }

    fn assert_one(
        &self,
        c: &Cand,
        rp_hash: &[u8; 32],
        cdh: &[u8],
        flags: u8,
        include_user: bool,
        number: Option<usize>,
    ) -> Res<Vec<u8>> {
        let key = Key::derive(&self.platform, c.alg, &c.nonce).ok_or(st::OPERATION_DENIED)?;
        let mut ad = rp_hash.to_vec();
        ad.push(flags);
        ad.extend_from_slice(&[0, 0, 0, 0]);
        let mut msg = ad.clone();
        msg.extend_from_slice(cdh);
        let sig = key.sign(&msg);
        let mut m = vec![
            (Value::Int(1), cred_desc(&c.cred_id)),
            (Value::Int(2), Value::Bytes(ad)),
            (Value::Int(3), Value::Bytes(sig)),
        ];
        if let Some(r) = &c.resident {
            let mut u = vec![(Value::text("id"), Value::bytes(&r.user_handle))];
            if include_user {
                u.push((Value::text("name"), Value::text(&r.user_name)));
                u.push((Value::text("displayName"), Value::text(&r.user_display_name)));
            }
            m.push((Value::Int(4), Value::Map(u)));
        }
        if let Some(n) = number {
            m.push((Value::Int(5), Value::Int(n as i64)));
        }
        Ok(ok(Some(Value::Map(m))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    struct Mock {
        locked: bool,
        presence: PresenceResult,
        ctr: u8,
        store: Vec<PasskeyCredential>,
        clock: u64,
    }
    impl Mock {
        fn new() -> Self {
            Mock { locked: false, presence: PresenceResult::Approved, ctr: 0, store: vec![], clock: 0 }
        }
    }
    impl Platform for Mock {
        fn rng(&mut self, buf: &mut [u8]) {
            for b in buf {
                self.ctr = self.ctr.wrapping_add(1);
                *b = self.ctr;
            }
        }
        fn seed_key(&self, info: &[u8]) -> Option<[u8; 32]> {
            if self.locked {
                return None;
            }
            let mut h = Sha256::new();
            h.update(b"test-master-seed");
            h.update(info);
            Some(h.finalize().into())
        }
        fn user_presence(&mut self, _: &PresenceRequest) -> PresenceResult {
            self.presence
        }
        fn find_resident(&self, rp: &str) -> Vec<PasskeyCredential> {
            self.store.iter().filter(|p| p.rp_id == rp).cloned().collect()
        }
        fn store_resident(&mut self, mut c: PasskeyCredential) -> Result<(), StorageError> {
            self.clock += 1;
            c.created = self.clock;
            self.store.push(c);
            Ok(())
        }
        fn delete_resident(&mut self, id: &[u8]) -> Result<(), StorageError> {
            self.store.retain(|p| p.credential_id != id);
            Ok(())
        }
        fn reset(&mut self) -> Result<(), StorageError> {
            self.store.clear();
            Ok(())
        }
        fn keepalive(&mut self, _: KeepaliveStatus) {}
    }

    fn txt(s: &str) -> Value { Value::text(s) }
    fn mc_req(rp: &str, uid: &[u8], rk: bool, algs: &[i64], exclude: &[Vec<u8>]) -> Vec<u8> {
        let mut m = vec![
            (Value::Int(1), Value::Bytes(vec![0xAA; 32])),
            (Value::Int(2), Value::Map(vec![(txt("id"), txt(rp)), (txt("name"), txt("RP"))])),
            (Value::Int(3), Value::Map(vec![(txt("id"), Value::bytes(uid)), (txt("name"), txt("alice")), (txt("displayName"), txt("Alice"))])),
            (Value::Int(4), Value::Array(algs.iter().map(|a| Value::Map(vec![(txt("alg"), Value::Int(*a)), (txt("type"), txt("public-key"))])).collect())),
            (Value::Int(7), Value::Map(vec![(txt("rk"), Value::Bool(rk))])),
        ];
        if !exclude.is_empty() {
            m.push((Value::Int(5), Value::Array(exclude.iter().map(|i| cred_desc(i)).collect())));
        }
        let mut r = vec![CMD_MAKE_CREDENTIAL];
        cbor::encode_into(&Value::Map(m), &mut r);
        r
    }
    fn ga_req(rp: &str, allow: &[Vec<u8>]) -> Vec<u8> {
        let mut m = vec![(Value::Int(1), txt(rp)), (Value::Int(2), Value::Bytes(vec![0xBB; 32]))];
        if !allow.is_empty() {
            m.push((Value::Int(3), Value::Array(allow.iter().map(|i| cred_desc(i)).collect())));
        }
        let mut r = vec![CMD_GET_ASSERTION];
        cbor::encode_into(&Value::Map(m), &mut r);
        r
    }
    fn resp(r: &[u8]) -> Value {
        assert_eq!(r[0], 0, "status {:#x}", r[0]);
        cbor::decode(&r[1..]).unwrap()
    }
    /// Returns (credential id, COSE key).
    fn parse_ad(r: &[u8]) -> (Vec<u8>, Value) {
        let v = resp(r);
        assert_eq!(v.get(1).unwrap().as_text(), Some("none"));
        let ad = v.get(2).unwrap().as_bytes().unwrap();
        assert_eq!(ad[32], FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
        assert_eq!(&ad[33..37], &[0; 4]);
        assert_eq!(&ad[37..53], &AAGUID);
        let l = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        (ad[55..55 + l].to_vec(), cbor::decode(&ad[55 + l..]).unwrap())
    }
    fn verify(cose: &Value, rp: &str, assertion: &Value, cdh: u8) {
        let ad = assertion.get(2).unwrap().as_bytes().unwrap();
        assert_eq!(&ad[..32], &sha256(rp.as_bytes()));
        assert_eq!(ad[32] & 0x05, 0x05);
        let mut msg = ad.to_vec();
        msg.extend_from_slice(&[cdh; 32]);
        let sig = assertion.get(3).unwrap().as_bytes().unwrap();
        match cose.get(3).unwrap().as_int().unwrap() {
            -7 => {
                let mut pt = vec![4u8];
                pt.extend_from_slice(cose.get(-2).unwrap().as_bytes().unwrap());
                pt.extend_from_slice(cose.get(-3).unwrap().as_bytes().unwrap());
                let vk = VerifyingKey::from_sec1_bytes(&pt).unwrap();
                vk.verify(&msg, &Signature::from_der(sig).unwrap()).unwrap();
            }
            -8 => {
                let pk: [u8; 32] = cose.get(-2).unwrap().as_bytes().unwrap().try_into().unwrap();
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
                let s = ed25519_dalek::Signature::from_slice(sig).unwrap();
                ed25519_dalek::Verifier::verify(&vk, &msg, &s).unwrap();
            }
            _ => panic!(),
        }
    }

    #[test]
    fn get_info_decodes() {
        let mut a = Authenticator::new(Mock::new());
        let v = resp(&a.handle(&[CMD_GET_INFO]));
        assert_eq!(v.get(3).unwrap().as_bytes().unwrap(), &AAGUID);
        assert_eq!(v.get(4).unwrap().get_text("rk").unwrap().as_bool(), Some(true));
        assert!(v.get(1).unwrap().as_array().unwrap().contains(&txt("FIDO_2_1")));
    }

    #[test]
    fn rk_roundtrip_es256_and_eddsa() {
        for alg in [-7i64, -8] {
            let mut a = Authenticator::new(Mock::new());
            let (id, cose) = parse_ad(&a.handle(&mc_req("example.com", b"uid1", true, &[alg], &[])));
            assert_eq!(cose.get(3).unwrap().as_int(), Some(alg));
            assert_eq!(a.platform().store.len(), 1);
            assert_eq!(a.platform().store[0].credential_id, id);
            // discoverable flow
            let v = resp(&a.handle(&ga_req("example.com", &[])));
            assert_eq!(v.get(1).unwrap().get_text("id").unwrap().as_bytes().unwrap(), &id[..]);
            let u = v.get(4).unwrap();
            assert_eq!(u.get_text("id").unwrap().as_bytes().unwrap(), b"uid1");
            assert_eq!(u.get_text("name").unwrap().as_text(), Some("alice"));
            assert!(v.get(5).is_none());
            verify(&cose, "example.com", &v, 0xBB);
        }
    }

    #[test]
    fn algorithm_preference_and_unsupported() {
        let mut a = Authenticator::new(Mock::new());
        let (_, c) = parse_ad(&a.handle(&mc_req("a.com", b"u", false, &[-257, -8, -7], &[])));
        assert_eq!(c.get(3).unwrap().as_int(), Some(-8));
        assert_eq!(a.handle(&mc_req("a.com", b"u", false, &[-257], &[])), [st::UNSUPPORTED_ALGORITHM]);
    }

    #[test]
    fn non_resident_via_allow_list() {
        for alg in [-7i64, -8] {
            let mut a = Authenticator::new(Mock::new());
            let (id, cose) = parse_ad(&a.handle(&mc_req("example.com", b"u", false, &[alg], &[])));
            assert!(a.platform().store.is_empty());
            assert_eq!(id.len(), 32);
            // no allowList and nothing resident
            assert_eq!(a.handle(&ga_req("example.com", &[])), [st::NO_CREDENTIALS]);
            // garbage id
            assert_eq!(a.handle(&ga_req("example.com", &[vec![7; 32]])), [st::NO_CREDENTIALS]);
            // wrong RP
            assert_eq!(a.handle(&ga_req("evil.com", &[id.clone()])), [st::NO_CREDENTIALS]);
            let v = resp(&a.handle(&ga_req("example.com", &[vec![7; 32], id])));
            assert!(v.get(4).is_none());
            verify(&cose, "example.com", &v, 0xBB);
        }
    }

    #[test]
    fn exclude_list() {
        let mut a = Authenticator::new(Mock::new());
        let (id, _) = parse_ad(&a.handle(&mc_req("example.com", b"u", false, &[-7], &[])));
        assert_eq!(a.handle(&mc_req("example.com", b"u", false, &[-7], &[id.clone()])), [st::CREDENTIAL_EXCLUDED]);
        // different RP is not excluded
        assert_eq!(a.handle(&mc_req("other.com", b"u", false, &[-7], &[id]))[0], 0);
    }

    #[test]
    fn get_next_assertion_two_creds() {
        let mut a = Authenticator::new(Mock::new());
        let (id1, c1) = parse_ad(&a.handle(&mc_req("example.com", b"u1", true, &[-7], &[])));
        let (id2, c2) = parse_ad(&a.handle(&mc_req("example.com", b"u2", true, &[-8], &[])));
        let v1 = resp(&a.handle(&ga_req("example.com", &[])));
        assert_eq!(v1.get(5).unwrap().as_int(), Some(2));
        // most recent first
        assert_eq!(v1.get(1).unwrap().get_text("id").unwrap().as_bytes().unwrap(), &id2[..]);
        verify(&c2, "example.com", &v1, 0xBB);
        let v2 = resp(&a.handle(&[CMD_GET_NEXT_ASSERTION]));
        assert_eq!(v2.get(1).unwrap().get_text("id").unwrap().as_bytes().unwrap(), &id1[..]);
        assert_eq!(v2.get(4).unwrap().get_text("id").unwrap().as_bytes().unwrap(), b"u1");
        verify(&c1, "example.com", &v2, 0xBB);
        assert_eq!(a.handle(&[CMD_GET_NEXT_ASSERTION]), [st::NO_OPERATION_PENDING]);
    }

    #[test]
    fn same_user_replaces_resident() {
        let mut a = Authenticator::new(Mock::new());
        a.handle(&mc_req("example.com", b"u1", true, &[-7], &[]));
        a.handle(&mc_req("example.com", b"u1", true, &[-7], &[]));
        assert_eq!(a.platform().store.len(), 1);
    }

    #[test]
    fn locked_and_presence_errors() {
        let mut m = Mock::new();
        m.locked = true;
        let mut a = Authenticator::new(m);
        assert_eq!(a.handle(&mc_req("example.com", b"u", true, &[-7], &[])), [st::OPERATION_DENIED]);
        assert_eq!(a.handle(&ga_req("example.com", &[])), [st::OPERATION_DENIED]);
        a.platform_mut().locked = false;
        a.platform_mut().presence = PresenceResult::Denied;
        assert_eq!(a.handle(&mc_req("example.com", b"u", true, &[-7], &[])), [st::OPERATION_DENIED]);
        a.platform_mut().presence = PresenceResult::Timeout;
        assert_eq!(a.handle(&mc_req("example.com", b"u", true, &[-7], &[])), [st::USER_ACTION_TIMEOUT]);
        assert!(a.platform().store.is_empty());
    }

    #[test]
    fn reset_selection_and_misc() {
        let mut a = Authenticator::new(Mock::new());
        a.handle(&mc_req("example.com", b"u", true, &[-7], &[]));
        assert_eq!(a.handle(&[CMD_SELECTION]), [0]);
        assert_eq!(a.handle(&[CMD_RESET]), [0]);
        assert!(a.platform().store.is_empty());
        assert_eq!(a.handle(&[0x55]), [st::INVALID_COMMAND]);
        assert_eq!(a.handle(&[]), [st::INVALID_LENGTH]);
        assert_eq!(a.handle(&[CMD_MAKE_CREDENTIAL, 0xff]), [st::INVALID_CBOR]);
        assert_eq!(a.handle(&[CMD_MAKE_CREDENTIAL, 0xa0]), [st::MISSING_PARAMETER]);
    }

    #[test]
    fn end_to_end_over_ctaphid() {
        use ctaphid::*;
        let mut a = Authenticator::new(Mock::new());
        let mut h = CtapHid::new();
        h.push_report(&build_reports(BROADCAST_CID, CMD_INIT, &[3; 8])[0]);
        let r = h.take_outbox()[0];
        let cid = u32::from_be_bytes([r[15], r[16], r[17], r[18]]);
        let mut req = None;
        for r in build_reports(cid, CMD_CBOR, &mc_req("example.com", b"uid", true, &[-7], &[])) {
            req = h.push_report(&r).or(req);
        }
        let req = req.unwrap();
        let out = a.handle(&req.payload);
        let reps = h.response_reports(req.cid, req.cmd, &out);
        assert!(reps.len() > 1);
        assert_eq!(parse_ad(&out).0.len(), 32);
    }
}
