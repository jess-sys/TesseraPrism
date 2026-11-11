//! Target-independent bridge logic (no wasm-bindgen types), so it can be unit-tested natively.
//! `lib.rs` only converts between these and JS values.

use prism_core::totp;
use prism_proto::{
    ble, cdc, generate_static_keypair,
    messages::{Envelope, ProtoError, Request, Response},
    session::{HostSession, SessionEvent},
};
use serde::Serialize;

pub const MAX_FRAME: usize = prism_proto::frame::MAX_FRAME;

pub struct HostKey {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

pub fn generate_host_key() -> HostKey {
    let (private, public) = generate_static_keypair();
    HostKey { private, public }
}

fn key32(v: &[u8]) -> Result<[u8; 32], String> {
    v.try_into()
        .map_err(|_| format!("host private key must be 32 bytes, got {}", v.len()))
}

/// JSON mirror of [`SessionEvent`] (which is not `Serialize`). Externally tagged, like serde's default:
/// `{"SendFrame":[..]}` | `"Established"` | `{"Response":{"id":..,"body":..}}` | `{"PlainError":{..}}`.
#[derive(Serialize)]
pub enum EventJson {
    SendFrame(Vec<u8>),
    Established,
    Response(Envelope<Response>),
    PlainError(ProtoError),
}

impl From<SessionEvent> for EventJson {
    fn from(ev: SessionEvent) -> Self {
        match ev {
            SessionEvent::SendFrame(f) => EventJson::SendFrame(f),
            SessionEvent::Established => EventJson::Established,
            SessionEvent::Response(r) => EventJson::Response(r),
            SessionEvent::PlainError(e) => EventJson::PlainError(e),
        }
    }
}

/// Host (initiator) session driven through byte frames and JSON envelopes.
pub struct Host {
    inner: HostSession,
}

impl Host {
    pub fn new(private: &[u8]) -> Result<Self, String> {
        let k = key32(private)?;
        let inner = HostSession::new(&k).map_err(|e| e.to_string())?;
        Ok(Self { inner })
    }

    pub fn start(&mut self) -> Result<Vec<u8>, String> {
        self.inner.start().map_err(|e| e.to_string())
    }

    pub fn on_frame(&mut self, frame: &[u8]) -> Result<String, String> {
        let ev = self.inner.on_frame(frame).map_err(|e| e.to_string())?;
        serde_json::to_string(&EventJson::from(ev)).map_err(|e| e.to_string())
    }

    pub fn is_established(&self) -> bool {
        self.inner.is_established()
    }

    pub fn sas(&self) -> Option<String> {
        self.inner.sas()
    }

    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.inner.remote_static()
    }

    pub fn encrypt_request(&mut self, json: &str) -> Result<Vec<u8>, String> {
        let env: Envelope<Request> =
            serde_json::from_str(json).map_err(|e| format!("bad request JSON: {e}"))?;
        self.inner.encrypt_request(&env).map_err(|e| e.to_string())
    }
}

/// GATT chunking with validation (the prism-proto version panics on bad input).
pub fn ble_chunk(frame: &[u8], mtu: u32) -> Result<Vec<Vec<u8>>, String> {
    if mtu < 23 {
        return Err(format!("ATT MTU must be >= 23, got {mtu}"));
    }
    if frame.len() > MAX_FRAME {
        return Err(format!("frame too large: {} > {MAX_FRAME}", frame.len()));
    }
    Ok(ble::chunk(frame, mtu as usize))
}

/// v2 (channel-tagged) chunking. `chan` must be non-zero.
pub fn ble_chunk_v2(frame: &[u8], mtu: u32, chan: u32) -> Result<Vec<Vec<u8>>, String> {
    if chan == 0 {
        return Err("channel 0 is reserved for v1 framing".into());
    }
    if mtu < 23 {
        return Err(format!("ATT MTU must be >= 23, got {mtu}"));
    }
    if frame.len() > MAX_FRAME {
        return Err(format!("frame too large: {} > {MAX_FRAME}", frame.len()));
    }
    Ok(ble::chunk_v2(frame, mtu as usize, chan))
}

/// Non-zero random BLE channel id.
pub fn random_channel() -> u32 {
    ble::random_channel()
}

pub struct Reassembler {
    inner: ble::Reassembler,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            inner: ble::Reassembler::new(),
        }
    }

    /// v2 reassembler for one channel (ignores other channels' chunks). `chan` must be non-zero.
    pub fn with_channel(chan: u32) -> Result<Self, String> {
        if chan == 0 {
            return Err("channel 0 is reserved for v1 framing".into());
        }
        Ok(Self {
            inner: ble::Reassembler::new_channel(chan),
        })
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.inner.push(chunk).map_err(|e| e.to_string())
    }
}

pub fn cdc_encode(frame: &[u8]) -> Vec<u8> {
    cdc::encode(frame)
}

pub struct CdcDecoder {
    inner: cdc::Decoder,
}

impl CdcDecoder {
    pub fn new() -> Self {
        Self {
            inner: cdc::Decoder::new(),
        }
    }

    /// Returns all complete frames. If any frame in this batch is malformed, the whole call fails
    /// (the decoder has already consumed the bytes, so the caller should reset the link).
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.inner
            .push(bytes)
            .into_iter()
            .map(|r| r.map_err(|e| e.to_string()))
            .collect()
    }
}

pub fn parse_otpauth(uri: &str) -> Result<String, String> {
    let t = totp::parse_otpauth(uri).map_err(|e| e.to_string())?;
    serde_json::to_string(&t).map_err(|e| e.to_string())
}

pub fn totp_now(json: &str, unix: u64) -> Result<String, String> {
    let t: prism_core::model::Totp =
        serde_json::from_str(json).map_err(|e| format!("bad Totp JSON: {e}"))?;
    Ok(totp::code(&t, unix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_proto::session::{DeviceEvent, DeviceSession};
    use serde_json::{json, Value};

    /// Host (JSON API) <-> prism_proto DeviceSession, fully in memory.
    fn handshake() -> (Host, DeviceSession, [u8; 32], [u8; 32]) {
        let hk = generate_host_key();
        let (dpriv, dpub) = generate_static_keypair();
        let mut host = Host::new(&hk.private).unwrap();
        let mut dev = DeviceSession::new(&dpriv).unwrap();

        let m1 = host.start().unwrap();
        let DeviceEvent::SendFrame(m2) = dev.on_frame(&m1).unwrap() else {
            panic!("expected msg2")
        };
        let ev: Value = serde_json::from_str(&host.on_frame(&m2).unwrap()).unwrap();
        let m3: Vec<u8> = serde_json::from_value(ev["SendFrame"].clone()).unwrap();
        assert!(host.is_established());
        let DeviceEvent::Established { remote_static } = dev.on_frame(&m3).unwrap() else {
            panic!("expected established")
        };
        assert_eq!(remote_static, hk.public);
        (host, dev, hk.public, dpub)
    }

    #[test]
    fn handshake_sas_and_request_roundtrip() {
        let (mut host, mut dev, _hpub, dpub) = handshake();
        assert_eq!(host.remote_static(), Some(dpub));
        assert_eq!(host.sas(), dev.sas());
        assert_eq!(host.sas().unwrap().len(), 6);

        let frame = host
            .encrypt_request(r#"{"id":1,"body":"GetInfo"}"#)
            .unwrap();
        let DeviceEvent::Request(req) = dev.on_frame(&frame).unwrap() else {
            panic!("expected request")
        };
        assert_eq!(
            req,
            Envelope {
                id: 1,
                body: Request::GetInfo
            }
        );

        let resp = Envelope {
            id: 1,
            body: Response::Error(prism_proto::ErrorCode::Locked),
        };
        let out = dev.encrypt_response(&resp).unwrap();
        let v: Value = serde_json::from_str(&host.on_frame(&out).unwrap()).unwrap();
        assert_eq!(v, json!({"Response":{"id":1,"body":{"Error":"Locked"}}}));
    }

    #[test]
    fn json_request_with_payload_roundtrip() {
        let (mut host, mut dev, ..) = handshake();
        let f = host
            .encrypt_request(r#"{"id":7,"body":{"SetTime":{"unix":1700000000}}}"#)
            .unwrap();
        let DeviceEvent::Request(req) = dev.on_frame(&f).unwrap() else {
            panic!()
        };
        assert_eq!(
            req.body,
            Request::SetTime {
                unix: 1_700_000_000
            }
        );
    }

    #[test]
    fn event_json_shapes() {
        let s = serde_json::to_value(EventJson::SendFrame(vec![1, 2])).unwrap();
        assert_eq!(s, json!({"SendFrame":[1,2]}));
        assert_eq!(
            serde_json::to_value(EventJson::Established).unwrap(),
            json!("Established")
        );
        let p = ProtoError {
            code: prism_proto::ErrorCode::NotPaired,
            message: "m".into(),
        };
        assert_eq!(
            serde_json::to_value(EventJson::PlainError(p)).unwrap(),
            json!({"PlainError":{"code":"NotPaired","message":"m"}})
        );
    }

    #[test]
    fn bad_inputs_are_errors_not_panics() {
        assert!(Host::new(&[0u8; 31]).is_err());
        let mut h = Host::new(&[7u8; 32]).unwrap();
        assert!(h.encrypt_request(r#"{"id":1,"body":"GetInfo"}"#).is_err()); // not established
        assert!(h.on_frame(&[]).is_err());
        assert!(ble_chunk(&[1, 2, 3], 22).is_err());
        assert!(ble_chunk(&vec![0; MAX_FRAME + 1], 185).is_err());
        assert!(totp_now("{not json", 0).is_err());
    }

    #[test]
    fn ble_roundtrip() {
        let frame: Vec<u8> = (0..700u32).map(|i| i as u8).collect();
        let chunks = ble_chunk(&frame, 185).unwrap();
        let mut r = Reassembler::new();
        let mut got = None;
        for c in &chunks {
            got = r.push(c).unwrap();
        }
        assert_eq!(got.unwrap(), frame);
    }

    #[test]
    fn ble_v2_roundtrip_and_filtering() {
        let chan = random_channel();
        assert_ne!(chan, 0);
        let frame: Vec<u8> = (0..700u32).map(|i| i as u8).collect();
        let other = ble_chunk_v2(&[9; 400], 185, chan.wrapping_add(1).max(1)).unwrap();
        let mut r = Reassembler::with_channel(chan).unwrap();
        let mut got = None;
        for (i, c) in ble_chunk_v2(&frame, 185, chan).unwrap().iter().enumerate() {
            if let Some(o) = other.get(i) {
                assert_eq!(r.push(o).unwrap(), None);
            }
            got = r.push(c).unwrap();
        }
        assert_eq!(got.unwrap(), frame);
        assert!(ble_chunk_v2(&frame, 185, 0).is_err());
        assert!(ble_chunk_v2(&frame, 22, 1).is_err());
        assert!(Reassembler::with_channel(0).is_err());
    }

    #[test]
    fn cdc_roundtrip_with_split_stream() {
        let a = vec![0u8, 1, 0, 2];
        let b = vec![9u8; 300];
        let mut stream = cdc_encode(&a);
        stream.extend(cdc_encode(&b));
        let mut d = CdcDecoder::new();
        let mut out = Vec::new();
        for piece in stream.chunks(7) {
            out.extend(d.push(piece).unwrap());
        }
        assert_eq!(out, vec![a, b]);
    }

    #[test]
    fn otpauth_and_totp_rfc6238() {
        // RFC 6238 appendix B, SHA1, secret "12345678901234567890", T=59 -> 94287082 (8 digits).
        let uri =
            "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30";
        let json = parse_otpauth(uri).unwrap();
        assert_eq!(totp_now(&json, 59).unwrap(), "94287082");
        assert_eq!(totp_now(&json, 1111111109).unwrap(), "07081804");
    }
}
