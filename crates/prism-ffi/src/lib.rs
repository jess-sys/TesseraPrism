//! UniFFI (Swift) bridge for the Prism host protocol (ARCHITECTURE §9.3).
//!
//! Same API as `prism-wasm`: Request/Response/SessionEvent cross as JSON strings, bytes as `Data`/`[UInt8]`.
//! Shared, target-independent logic lives in [`logic`] (kept byte-identical with prism-wasm's copy).

mod logic;

use std::sync::{Arc, Mutex, MutexGuard};

uniffi::setup_scaffolding!();

/// Flat error: Swift receives only the case and its message.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum PrismError {
    /// Malformed argument: key length, JSON, MTU, frame size, TOTP parameters or URI.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Handshake or transport-state failure (e.g. request before the session is established).
    #[error("session error: {0}")]
    Session(String),
    /// BLE chunk or USB CDC framing failure.
    #[error("framing error: {0}")]
    Framing(String),
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicked holder cannot leave the protocol state half-updated in a way we rely on here,
    // and panicking across the FFI boundary is worse than continuing.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Generated X25519 identity.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HostKey {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

#[uniffi::export]
pub fn generate_host_key() -> HostKey {
    let k = logic::generate_host_key();
    HostKey {
        private: k.private.to_vec(),
        public: k.public.to_vec(),
    }
}

/// Host (initiator) Noise session. Methods are serialized by an internal mutex.
#[derive(uniffi::Object)]
pub struct Session {
    inner: Mutex<logic::Host>,
}

#[uniffi::export]
impl Session {
    /// `host_private_key`: 32 bytes from `generateHostKey().private`.
    #[uniffi::constructor]
    pub fn new(host_private_key: Vec<u8>) -> Result<Arc<Self>, PrismError> {
        let inner = logic::Host::new(&host_private_key).map_err(PrismError::InvalidInput)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(inner),
        }))
    }

    /// Handshake message 1 as a frame.
    pub fn start(&self) -> Result<Vec<u8>, PrismError> {
        lock(&self.inner).start().map_err(PrismError::Session)
    }

    /// Feed one received frame. Returns a JSON `SessionEvent` string.
    pub fn on_frame(&self, frame: Vec<u8>) -> Result<String, PrismError> {
        lock(&self.inner)
            .on_frame(&frame)
            .map_err(PrismError::Session)
    }

    pub fn is_established(&self) -> bool {
        lock(&self.inner).is_established()
    }

    /// 6-digit SAS once established, else nil.
    pub fn sas(&self) -> Option<String> {
        lock(&self.inner).sas()
    }

    /// Device static public key (32 bytes) once established, else nil.
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        lock(&self.inner).remote_static().map(|k| k.to_vec())
    }

    /// `json_envelope` is e.g. `{"id":1,"body":"GetInfo"}`. Returns a TRANSPORT frame.
    pub fn encrypt_request(&self, json_envelope: String) -> Result<Vec<u8>, PrismError> {
        lock(&self.inner)
            .encrypt_request(&json_envelope)
            .map_err(PrismError::Session)
    }
}

/// Split a frame into BLE GATT chunks for an ATT MTU (>= 23).
#[uniffi::export]
pub fn ble_chunk(frame: Vec<u8>, mtu: u32) -> Result<Vec<Vec<u8>>, PrismError> {
    logic::ble_chunk(&frame, mtu).map_err(PrismError::InvalidInput)
}

/// Like `bleChunk` but v2 framing: every chunk carries the non-zero channel id `chan`.
#[uniffi::export]
pub fn ble_chunk_v2(frame: Vec<u8>, mtu: u32, chan: u32) -> Result<Vec<Vec<u8>>, PrismError> {
    logic::ble_chunk_v2(&frame, mtu, chan).map_err(PrismError::InvalidInput)
}

/// Random non-zero BLE channel id (CSPRNG).
#[uniffi::export]
pub fn random_channel() -> u32 {
    logic::random_channel()
}

/// Reassembles notified BLE chunks into frames.
#[derive(uniffi::Object)]
pub struct BleReassembler {
    inner: Mutex<logic::Reassembler>,
}

#[uniffi::export]
impl BleReassembler {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(logic::Reassembler::new()),
        })
    }

    /// v2 reassembler bound to channel `chan` (non-zero); other channels' chunks are ignored.
    #[uniffi::constructor]
    pub fn with_channel(chan: u32) -> Result<Arc<Self>, PrismError> {
        Ok(Arc::new(Self {
            inner: Mutex::new(
                logic::Reassembler::with_channel(chan).map_err(PrismError::InvalidInput)?,
            ),
        }))
    }

    /// Returns the completed frame, or nil if more chunks are needed.
    pub fn push(&self, chunk: Vec<u8>) -> Result<Option<Vec<u8>>, PrismError> {
        lock(&self.inner).push(&chunk).map_err(PrismError::Framing)
    }
}

/// COBS-encode a frame for USB CDC (includes the trailing 0x00).
#[uniffi::export]
pub fn cdc_encode(frame: Vec<u8>) -> Vec<u8> {
    logic::cdc_encode(&frame)
}

/// Streaming USB CDC decoder.
#[derive(uniffi::Object)]
pub struct CdcDecoder {
    inner: Mutex<logic::CdcDecoder>,
}

#[uniffi::export]
impl CdcDecoder {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(logic::CdcDecoder::new()),
        })
    }

    /// Returns all complete frames. Throws if any frame is malformed.
    pub fn push(&self, bytes: Vec<u8>) -> Result<Vec<Vec<u8>>, PrismError> {
        lock(&self.inner).push(&bytes).map_err(PrismError::Framing)
    }
}

/// Parse an `otpauth://totp/...` URI. Returns the `Totp` as JSON (secret = byte array).
#[uniffi::export]
pub fn parse_otpauth(uri: String) -> Result<String, PrismError> {
    logic::parse_otpauth(&uri).map_err(PrismError::InvalidInput)
}

/// Code valid at `unix` (seconds).
#[uniffi::export]
pub fn totp_now(json_totp: String, unix: u64) -> Result<String, PrismError> {
    logic::totp_now(&json_totp, unix).map_err(PrismError::InvalidInput)
}

/// Decode the bytes read via `PasswordSnapshot` + `ExportChunk` (postcard) into JSON:
/// `{"generated_at":..,"expires_at":..,"entries":[{"id":[16 bytes],"title","username","password","url","modified"}]}`.
#[uniffi::export]
pub fn decode_password_snapshot(bytes: Vec<u8>) -> Result<String, PrismError> {
    let bytes = zeroize::Zeroizing::new(bytes);
    let snap: prism_core::model::PasswordSnapshot =
        postcard::from_bytes(&bytes).map_err(|e| PrismError::InvalidInput(format!("password snapshot: {e}")))?;
    serde_json::to_string(&snap).map_err(|e| PrismError::InvalidInput(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_proto::session::{DeviceEvent, DeviceSession};
    use prism_proto::{generate_static_keypair, Envelope, ErrorCode, Request, Response};
    use serde_json::{json, Value};

    #[test]
    fn password_snapshot_decodes_to_json() {
        use prism_core::model::{CachedPassword, EntryId, PasswordSnapshot};
        let snap = PasswordSnapshot {
            generated_at: 10,
            expires_at: 20,
            entries: vec![CachedPassword {
                id: EntryId([1; 16]),
                title: "example.org".into(),
                username: "alice".into(),
                password: "pw".into(),
                url: Some("https://example.org".into()),
                modified: 5,
            }],
        };
        let v: Value = serde_json::from_str(&decode_password_snapshot(postcard::to_stdvec(&snap).unwrap()).unwrap()).unwrap();
        assert_eq!(v["expires_at"], 20);
        assert_eq!(v["entries"][0]["password"], "pw");
        assert_eq!(v["entries"][0]["id"], json!(vec![1u8; 16]));
        assert!(decode_password_snapshot(vec![0xff, 0xff]).is_err());
    }

    #[test]
    fn handshake_sas_and_request_roundtrip_via_json_api() {
        let hk = generate_host_key();
        let (dpriv, dpub) = generate_static_keypair();
        let host = Session::new(hk.private.clone()).unwrap();
        let mut dev = DeviceSession::new(&dpriv).unwrap();

        // msg1 -> device msg2 -> host msg3 (JSON SendFrame) -> device Established
        let m1 = host.start().unwrap();
        let DeviceEvent::SendFrame(m2) = dev.on_frame(&m1).unwrap() else {
            panic!("expected msg2")
        };
        let ev: Value = serde_json::from_str(&host.on_frame(m2).unwrap()).unwrap();
        let m3: Vec<u8> = serde_json::from_value(ev["SendFrame"].clone()).unwrap();
        assert!(host.is_established());
        let DeviceEvent::Established { remote_static } = dev.on_frame(&m3).unwrap() else {
            panic!("expected established")
        };
        assert_eq!(remote_static, hk.public.as_slice());

        assert_eq!(host.remote_static(), Some(dpub.to_vec()));
        assert_eq!(host.sas(), dev.sas());
        assert_eq!(host.sas().unwrap().len(), 6);

        // Request round trip.
        let f = host
            .encrypt_request(r#"{"id":5,"body":{"SetTime":{"unix":42}}}"#.into())
            .unwrap();
        let DeviceEvent::Request(req) = dev.on_frame(&f).unwrap() else {
            panic!("expected request")
        };
        assert_eq!(
            req,
            Envelope {
                id: 5,
                body: Request::SetTime { unix: 42 }
            }
        );
        let out = dev
            .encrypt_response(&Envelope {
                id: 5,
                body: Response::Error(ErrorCode::Locked),
            })
            .unwrap();
        let v: Value = serde_json::from_str(&host.on_frame(out).unwrap()).unwrap();
        assert_eq!(v, json!({"Response":{"id":5,"body":{"Error":"Locked"}}}));
    }

    #[test]
    fn errors_map_to_flat_variants() {
        assert!(matches!(
            Session::new(vec![0; 5]),
            Err(PrismError::InvalidInput(_))
        ));
        let s = Session::new(vec![1; 32]).unwrap();
        assert!(matches!(
            s.encrypt_request("{}".into()),
            Err(PrismError::Session(_))
        ));
        assert!(matches!(
            ble_chunk(vec![1], 10),
            Err(PrismError::InvalidInput(_))
        ));
        assert!(matches!(
            BleReassembler::new().push(vec![]),
            Err(PrismError::Framing(_))
        ));
        assert!(matches!(
            totp_now("nope".into(), 0),
            Err(PrismError::InvalidInput(_))
        ));
    }

    #[test]
    fn ble_v2_channel() {
        let chan = random_channel();
        let r = BleReassembler::with_channel(chan).unwrap();
        let frame = vec![5u8; 600];
        let mut got = None;
        for c in ble_chunk_v2(frame.clone(), 185, chan).unwrap() {
            got = r.push(c).unwrap();
        }
        assert_eq!(got.unwrap(), frame);
        assert!(ble_chunk_v2(frame, 185, 0).is_err());
        assert!(BleReassembler::with_channel(0).is_err());
    }

    #[test]
    fn ble_cdc_totp_helpers() {
        let frame: Vec<u8> = (0..400u32).map(|i| i as u8).collect();
        let r = BleReassembler::new();
        let mut got = None;
        for c in ble_chunk(frame.clone(), 185).unwrap() {
            got = r.push(c).unwrap();
        }
        assert_eq!(got.unwrap(), frame);

        let d = CdcDecoder::new();
        let frames = d.push(cdc_encode(vec![0, 1, 2])).unwrap();
        assert_eq!(frames, vec![vec![0, 1, 2]]);

        let uri = "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        let j = parse_otpauth(uri.into()).unwrap();
        assert_eq!(totp_now(j, 59).unwrap(), "94287082");
    }
}
