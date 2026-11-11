//! WebAssembly bridge for the Prism host protocol (ARCHITECTURE §9.3).
//!
//! Byte values cross as `Uint8Array`, Request/Response/SessionEvent/Totp cross as JSON strings.
//! Logic lives in [`logic`] (native-testable); this file only maps it to JS types.

mod logic;

use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

const NULL: JsValue = JsValue::NULL;

fn to_err(e: String) -> JsError {
    JsError::new(&e)
}

fn bytes(v: &[u8]) -> JsValue {
    Uint8Array::from(v).into()
}

fn opt_bytes(v: Option<Vec<u8>>) -> JsValue {
    v.map(|b| bytes(&b)).unwrap_or(NULL)
}

/// Generate an X25519 host identity. Returns `{private: Uint8Array(32), public: Uint8Array(32)}`.
#[wasm_bindgen(js_name = generateHostKey, unchecked_return_type = "{ private: Uint8Array; public: Uint8Array }")]
pub fn generate_host_key() -> Result<JsValue, JsError> {
    let k = logic::generate_host_key();
    let obj = Object::new();
    let set = |name: &str, v: JsValue| {
        Reflect::set(&obj, &JsValue::from_str(name), &v).map_err(|_| JsError::new("reflect failed"))
    };
    set("private", bytes(&k.private))?;
    set("public", bytes(&k.public))?;
    Ok(obj.into())
}

/// Host (initiator) Noise session.
#[wasm_bindgen]
pub struct Session {
    inner: logic::Host,
}

#[wasm_bindgen]
impl Session {
    /// `hostPrivateKey`: 32 bytes from `generateHostKey().private`.
    #[wasm_bindgen(constructor)]
    pub fn new(host_private_key: &[u8]) -> Result<Session, JsError> {
        Ok(Session {
            inner: logic::Host::new(host_private_key).map_err(to_err)?,
        })
    }

    /// Handshake message 1 as a frame.
    pub fn start(&mut self) -> Result<Uint8Array, JsError> {
        Ok(bytes(&self.inner.start().map_err(to_err)?).into())
    }

    /// Feed one received frame. Returns a JSON `SessionEvent` string.
    #[wasm_bindgen(js_name = onFrame)]
    pub fn on_frame(&mut self, frame: &[u8]) -> Result<String, JsError> {
        self.inner.on_frame(frame).map_err(to_err)
    }

    #[wasm_bindgen(js_name = isEstablished)]
    pub fn is_established(&self) -> bool {
        self.inner.is_established()
    }

    /// 6-digit SAS once established, else `null`.
    #[wasm_bindgen(unchecked_return_type = "string | null")]
    pub fn sas(&self) -> JsValue {
        self.inner
            .sas()
            .map(|s| JsValue::from_str(&s))
            .unwrap_or(NULL)
    }

    /// Device static public key (32 bytes) once established, else `null`.
    #[wasm_bindgen(js_name = remoteStatic, unchecked_return_type = "Uint8Array | null")]
    pub fn remote_static(&self) -> JsValue {
        opt_bytes(self.inner.remote_static().map(|k| k.to_vec()))
    }

    /// `jsonEnvelope` is e.g. `{"id":1,"body":"GetInfo"}`. Returns a TRANSPORT frame.
    #[wasm_bindgen(js_name = encryptRequest)]
    pub fn encrypt_request(&mut self, json_envelope: &str) -> Result<Uint8Array, JsError> {
        Ok(bytes(&self.inner.encrypt_request(json_envelope).map_err(to_err)?).into())
    }
}

/// Split a frame into BLE GATT chunks for an ATT MTU (>= 23). Returns `Uint8Array[]`.
#[wasm_bindgen(js_name = bleChunk, unchecked_return_type = "Uint8Array[]")]
pub fn ble_chunk(frame: &[u8], mtu: u32) -> Result<Array, JsError> {
    let chunks = logic::ble_chunk(frame, mtu).map_err(to_err)?;
    Ok(chunks.iter().map(|c| bytes(c)).collect())
}

/// Like `bleChunk` but v2 framing: every chunk carries the non-zero channel id `chan`.
#[wasm_bindgen(js_name = bleChunkV2, unchecked_return_type = "Uint8Array[]")]
pub fn ble_chunk_v2(frame: &[u8], mtu: u32, chan: u32) -> Result<Array, JsError> {
    let chunks = logic::ble_chunk_v2(frame, mtu, chan).map_err(to_err)?;
    Ok(chunks.iter().map(|c| bytes(c)).collect())
}

/// Random non-zero BLE channel id (CSPRNG).
#[wasm_bindgen(js_name = randomChannel)]
pub fn random_channel() -> u32 {
    logic::random_channel()
}

/// Reassembles notified BLE chunks into frames.
#[wasm_bindgen(js_name = BleReassembler)]
pub struct BleReassembler {
    inner: logic::Reassembler,
}

#[wasm_bindgen(js_class = BleReassembler)]
impl BleReassembler {
    #[wasm_bindgen(constructor)]
    pub fn new() -> BleReassembler {
        BleReassembler {
            inner: logic::Reassembler::new(),
        }
    }

    /// v2 reassembler bound to channel `chan` (non-zero); other channels' chunks are ignored.
    #[wasm_bindgen(js_name = newChannel)]
    pub fn new_channel(chan: u32) -> Result<BleReassembler, JsError> {
        Ok(BleReassembler {
            inner: logic::Reassembler::with_channel(chan).map_err(to_err)?,
        })
    }

    /// Returns the completed frame, or `null` if more chunks are needed.
    #[wasm_bindgen(unchecked_return_type = "Uint8Array | null")]
    pub fn push(&mut self, chunk: &[u8]) -> Result<JsValue, JsError> {
        Ok(opt_bytes(self.inner.push(chunk).map_err(to_err)?))
    }
}

impl Default for BleReassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// COBS-encode a frame for USB CDC (includes the trailing 0x00).
#[wasm_bindgen(js_name = cdcEncode)]
pub fn cdc_encode(frame: &[u8]) -> Uint8Array {
    bytes(&logic::cdc_encode(frame)).into()
}

/// Streaming USB CDC decoder.
#[wasm_bindgen(js_name = CdcDecoder)]
pub struct CdcDecoder {
    inner: logic::CdcDecoder,
}

#[wasm_bindgen(js_class = CdcDecoder)]
impl CdcDecoder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CdcDecoder {
        CdcDecoder {
            inner: logic::CdcDecoder::new(),
        }
    }

    /// Returns all complete frames as `Uint8Array[]`. Throws if any frame is malformed.
    #[wasm_bindgen(unchecked_return_type = "Uint8Array[]")]
    pub fn push(&mut self, data: &[u8]) -> Result<Array, JsError> {
        let frames = self.inner.push(data).map_err(to_err)?;
        Ok(frames.iter().map(|f| bytes(f)).collect())
    }
}

impl Default for CdcDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an `otpauth://totp/...` URI. Returns the `Totp` as JSON (secret = byte array).
#[wasm_bindgen(js_name = parseOtpauth)]
pub fn parse_otpauth(uri: &str) -> Result<String, JsError> {
    logic::parse_otpauth(uri).map_err(to_err)
}

/// Code valid at `unix` (seconds). `unix` must be a non-negative integer below 2^53.
#[wasm_bindgen(js_name = totpNow)]
pub fn totp_now(json_totp: &str, unix: f64) -> Result<String, JsError> {
    if !(unix.is_finite() && unix >= 0.0 && unix.fract() == 0.0 && unix < 9_007_199_254_740_992.0) {
        return Err(JsError::new(
            "unix must be a non-negative integer below 2^53",
        ));
    }
    logic::totp_now(json_totp, unix as u64).map_err(to_err)
}
