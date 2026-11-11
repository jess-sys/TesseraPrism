//! Sans-IO Noise_XX_25519_ChaChaPoly_BLAKE2s sessions (prologue `prism/v1`, host = initiator).
//!
//! Flow (all values are full frames, see [`crate::frame`]):
//! 1. host `start()` -> HANDSHAKE frame (msg1)
//! 2. device `on_frame(msg1)` -> `SendFrame(msg2)`
//! 3. host `on_frame(msg2)` -> `SendFrame(msg3)`; host `is_established()` is now true
//! 4. device `on_frame(msg3)` -> `Established{remote_static}`; `sas()` available on both sides.
//!
//! The device decides pairing by checking `remote_static` against its paired list.
//!
//! **Size limit:** a Noise message is <= 65535 bytes, so one encrypted message holds at most
//! [`MAX_PLAINTEXT`] bytes of postcard. Larger payloads must be chunked at app level
//! (Export/Import chunks <= 8 KiB; keep anything else < 65 000 bytes).

use crate::{
    frame::{self, FrameKind, MAX_FRAME},
    messages::{Envelope, ProtoError, Request, Response},
    Error, Result,
};
use blake2::{Blake2s256, Digest};

pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const PROLOGUE: &[u8] = b"prism/v1";
/// Max plaintext per transport message: 65535 (frame) - 1 (kind) - 16 (AEAD tag).
pub const MAX_PLAINTEXT: usize = MAX_FRAME - 1 - 16;

fn params() -> snow::params::NoiseParams {
    NOISE_PARAMS.parse().expect("static noise params")
}

/// Generate an X25519 static keypair `(private, public)`.
pub fn generate_static_keypair() -> ([u8; 32], [u8; 32]) {
    let kp = snow::Builder::new(params())
        .generate_keypair()
        .expect("keygen");
    let mut s = [0u8; 32];
    let mut p = [0u8; 32];
    s.copy_from_slice(&kp.private);
    p.copy_from_slice(&kp.public);
    (s, p)
}

fn sas_from_hash(h: &[u8]) -> String {
    let mut hasher = Blake2s256::new();
    hasher.update(b"prism-sas");
    hasher.update(h);
    let d = hasher.finalize();
    let n = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{n:06}")
}

fn key32(v: &[u8]) -> Result<[u8; 32]> {
    v.try_into()
        .map_err(|_| Error::Noise("bad remote static length".into()))
}

enum State {
    Idle(Box<snow::HandshakeState>),
    Waiting(Box<snow::HandshakeState>),
    Transport(Box<snow::TransportState>),
    Failed,
}

/// Shared engine for both roles.
struct Core {
    state: State,
    hash: Option<Vec<u8>>,
    remote: Option<[u8; 32]>,
}

impl Core {
    fn new(initiator: bool, key: &[u8; 32]) -> Result<Self> {
        let b = snow::Builder::new(params())
            .prologue(PROLOGUE)
            .local_private_key(key);
        let hs = if initiator {
            b.build_initiator()?
        } else {
            b.build_responder()?
        };
        Ok(Core {
            state: State::Idle(Box::new(hs)),
            hash: None,
            remote: None,
        })
    }

    fn write_hs(hs: &mut snow::HandshakeState) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_FRAME];
        let n = hs.write_message(&[], &mut buf)?;
        buf.truncate(n);
        frame::build(FrameKind::Handshake, &buf)
    }

    fn read_hs(hs: &mut snow::HandshakeState, payload: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; MAX_FRAME];
        hs.read_message(payload, &mut buf)?;
        Ok(())
    }

    /// If the handshake finished, convert to transport and record hash/remote.
    fn finish_if_done(&mut self, hs: Box<snow::HandshakeState>) -> Result<bool> {
        if hs.is_handshake_finished() {
            self.hash = Some(hs.get_handshake_hash().to_vec());
            self.remote = hs.get_remote_static().map(key32).transpose()?;
            self.state = State::Transport(Box::new(hs.into_transport_mode()?));
            Ok(true)
        } else {
            self.state = State::Waiting(hs);
            Ok(false)
        }
    }

    fn established(&self) -> bool {
        matches!(self.state, State::Transport(_))
    }

    fn sas(&self) -> Option<String> {
        self.hash.as_deref().map(sas_from_hash)
    }

    fn encrypt<T: serde::Serialize>(&mut self, msg: &T) -> Result<Vec<u8>> {
        let State::Transport(t) = &mut self.state else {
            return Err(Error::State("not established"));
        };
        let plain = postcard::to_stdvec(msg)?;
        if plain.len() > MAX_PLAINTEXT {
            return Err(Error::FrameTooLarge);
        }
        let mut out = vec![0u8; plain.len() + 16];
        let n = t.write_message(&plain, &mut out)?;
        out.truncate(n);
        frame::build(FrameKind::Transport, &out)
    }

    fn decrypt<T: serde::de::DeserializeOwned>(&mut self, payload: &[u8]) -> Result<T> {
        let State::Transport(t) = &mut self.state else {
            return Err(Error::State("not established"));
        };
        let mut out = vec![0u8; payload.len()];
        let n = t.read_message(payload, &mut out)?;
        Ok(postcard::from_bytes(&out[..n])?)
    }
}

fn take_plain_error(payload: &[u8]) -> Result<ProtoError> {
    Ok(postcard::from_bytes(payload)?)
}

// ---------------------------------------------------------------- host

/// Events produced by [`HostSession::on_frame`].
#[derive(Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// Send this frame to the device. After the third handshake message is produced the
    /// session is already established (`is_established()` is true).
    SendFrame(Vec<u8>),
    /// (Reserved) handshake complete.
    Established,
    Response(Envelope<Response>),
    PlainError(ProtoError),
}

/// Initiator side (companion).
pub struct HostSession {
    core: Core,
}

impl HostSession {
    pub fn new(host_static_private: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            core: Core::new(true, host_static_private)?,
        })
    }

    /// Produce handshake message 1 (frame kind 0x01).
    pub fn start(&mut self) -> Result<Vec<u8>> {
        let State::Idle(mut hs) = core::mem::replace(&mut self.core.state, State::Failed) else {
            return Err(Error::State("already started"));
        };
        let f = Core::write_hs(&mut hs)?;
        self.core.state = State::Waiting(hs);
        Ok(f)
    }

    pub fn on_frame(&mut self, frame_bytes: &[u8]) -> Result<SessionEvent> {
        let (kind, payload) = frame::parse(frame_bytes)?;
        match kind {
            FrameKind::PlainError => Ok(SessionEvent::PlainError(take_plain_error(payload)?)),
            FrameKind::Handshake => {
                let State::Waiting(mut hs) =
                    core::mem::replace(&mut self.core.state, State::Failed)
                else {
                    return Err(Error::State("unexpected handshake frame"));
                };
                Core::read_hs(&mut hs, payload)?;
                let out = Core::write_hs(&mut hs)?;
                self.core.finish_if_done(hs)?;
                Ok(SessionEvent::SendFrame(out))
            }
            FrameKind::Transport => Ok(SessionEvent::Response(self.core.decrypt(payload)?)),
        }
    }

    pub fn is_established(&self) -> bool {
        self.core.established()
    }
    /// 6-digit short authentication string (available once established).
    pub fn sas(&self) -> Option<String> {
        self.core.sas()
    }
    /// Device static public key (available once established).
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.core.remote
    }
    /// Encrypt a request envelope into a TRANSPORT frame.
    pub fn encrypt_request(&mut self, req: &Envelope<Request>) -> Result<Vec<u8>> {
        self.core.encrypt(req)
    }
}

// ---------------------------------------------------------------- device

#[derive(Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    SendFrame(Vec<u8>),
    Established { remote_static: [u8; 32] },
    Request(Envelope<Request>),
}

/// Responder side (firmware).
pub struct DeviceSession {
    core: Core,
}

impl DeviceSession {
    pub fn new(device_static_private: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            core: Core::new(false, device_static_private)?,
        })
    }

    pub fn on_frame(&mut self, frame_bytes: &[u8]) -> Result<DeviceEvent> {
        let (kind, payload) = frame::parse(frame_bytes)?;
        match kind {
            FrameKind::PlainError => Err(Error::Plain(take_plain_error(payload)?)),
            FrameKind::Handshake => {
                let mut hs = match core::mem::replace(&mut self.core.state, State::Failed) {
                    State::Idle(h) | State::Waiting(h) => h,
                    _ => return Err(Error::State("unexpected handshake frame")),
                };
                Core::read_hs(&mut hs, payload)?;
                if hs.is_handshake_finished() {
                    self.core.finish_if_done(hs)?;
                    let remote_static = self.core.remote.ok_or(Error::State("no remote static"))?;
                    Ok(DeviceEvent::Established { remote_static })
                } else {
                    let out = Core::write_hs(&mut hs)?;
                    self.core.finish_if_done(hs)?;
                    Ok(DeviceEvent::SendFrame(out))
                }
            }
            FrameKind::Transport => Ok(DeviceEvent::Request(self.core.decrypt(payload)?)),
        }
    }

    pub fn is_established(&self) -> bool {
        self.core.established()
    }
    pub fn sas(&self) -> Option<String> {
        self.core.sas()
    }
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.core.remote
    }
    /// Encrypt a response envelope into a TRANSPORT frame.
    pub fn encrypt_response(&mut self, resp: &Envelope<Response>) -> Result<Vec<u8>> {
        self.core.encrypt(resp)
    }
    /// Build a PLAIN_ERROR frame (pre-session errors only).
    pub fn plain_error(&self, e: &ProtoError) -> Result<Vec<u8>> {
        frame::plain_error(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::ErrorCode;

    fn pair() -> (HostSession, DeviceSession, [u8; 32], [u8; 32]) {
        let (hs, hp) = generate_static_keypair();
        let (ds, dp) = generate_static_keypair();
        let mut h = HostSession::new(&hs).unwrap();
        let mut d = DeviceSession::new(&ds).unwrap();
        let m1 = h.start().unwrap();
        assert_eq!(m1[0], frame::HANDSHAKE);
        let DeviceEvent::SendFrame(m2) = d.on_frame(&m1).unwrap() else {
            panic!()
        };
        let SessionEvent::SendFrame(m3) = h.on_frame(&m2).unwrap() else {
            panic!()
        };
        assert!(h.is_established());
        assert!(!d.is_established());
        let DeviceEvent::Established { remote_static } = d.on_frame(&m3).unwrap() else {
            panic!()
        };
        assert_eq!(remote_static, hp);
        (h, d, hp, dp)
    }

    #[test]
    fn handshake_sas_and_transport() {
        let (mut h, mut d, hp, dp) = pair();
        assert_eq!(h.remote_static(), Some(dp));
        assert_eq!(d.remote_static(), Some(hp));
        let s = h.sas().unwrap();
        assert_eq!(s.len(), 6);
        assert_eq!(Some(s), d.sas());

        for i in 0..3 {
            let req = Envelope {
                id: i,
                body: Request::SetTime { unix: 42 },
            };
            let f = h.encrypt_request(&req).unwrap();
            assert_eq!(f[0], frame::TRANSPORT);
            let DeviceEvent::Request(got) = d.on_frame(&f).unwrap() else {
                panic!()
            };
            assert_eq!(got, req);
            let resp = Envelope {
                id: i,
                body: Response::Ok,
            };
            let f = d.encrypt_response(&resp).unwrap();
            let SessionEvent::Response(got) = h.on_frame(&f).unwrap() else {
                panic!()
            };
            assert_eq!(got, resp);
        }
    }

    #[test]
    fn tampering_rejected() {
        let (mut h, mut d, ..) = pair();
        let mut f = h
            .encrypt_request(&Envelope {
                id: 1,
                body: Request::GetInfo,
            })
            .unwrap();
        let last = f.len() - 1;
        f[last] ^= 1;
        assert!(d.on_frame(&f).is_err());
    }

    #[test]
    fn size_limits() {
        let (mut h, mut d, ..) = pair();
        let big = Envelope {
            id: 1,
            body: Request::ImportChunk {
                offset: 0,
                data: vec![1; 70_000],
            },
        };
        assert_eq!(h.encrypt_request(&big), Err(Error::FrameTooLarge));
        let ok = Envelope {
            id: 1,
            body: Request::ImportChunk {
                offset: 0,
                data: vec![1; 65_000],
            },
        };
        let f = h.encrypt_request(&ok).unwrap();
        assert!(f.len() <= MAX_FRAME);
        assert!(matches!(d.on_frame(&f).unwrap(), DeviceEvent::Request(_)));
    }

    #[test]
    fn plain_error_and_state() {
        let (hs, _) = generate_static_keypair();
        let mut h = HostSession::new(&hs).unwrap();
        assert!(h
            .encrypt_request(&Envelope {
                id: 0,
                body: Request::Lock
            })
            .is_err());
        let pe = ProtoError {
            code: ErrorCode::NotPaired,
            message: "no".into(),
        };
        let f = frame::plain_error(&pe).unwrap();
        assert_eq!(h.on_frame(&f).unwrap(), SessionEvent::PlainError(pe));
    }

    #[test]
    fn full_stack_over_ble_and_cdc() {
        let (mut h, mut d, ..) = pair();
        let f = h
            .encrypt_request(&Envelope {
                id: 9,
                body: Request::Export {
                    passphrase: "p".into(),
                },
            })
            .unwrap();
        let mut r = crate::ble::Reassembler::new();
        let mut got = None;
        for c in crate::ble::chunk(&f, 185) {
            got = r.push(&c).unwrap();
        }
        let mut dec = crate::cdc::Decoder::new();
        let v = dec.push(&crate::cdc::encode(&got.unwrap()));
        let DeviceEvent::Request(e) = d.on_frame(v[0].as_ref().unwrap()).unwrap() else {
            panic!()
        };
        assert_eq!(e.id, 9);
    }
}
