//! CTAP worker: runs `prism_ctap::Authenticator` on its own thread so the core actor never
//! blocks while a tap is awaited. The `Platform` impl talks to the core actor over channels
//! (vault access and the approval broker both live there).
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender};
use std::time::Duration;

use prism_ctap::{
    Authenticator, KeepaliveStatus, PasskeyCredential, Platform, PresenceRequest, PresenceResult, StorageError,
};

use super::msg::{CoreMsg, CtapJob, PlatformOp};
use crate::transport::Link;

/// How long the worker waits for the core before giving up on a platform call.
const CALL_TIMEOUT: Duration = Duration::from_secs(45);

pub struct CorePlatform {
    core: Sender<CoreMsg>,
    link: Link,
}

impl CorePlatform {
    fn call<T>(&self, mk: impl FnOnce(std::sync::mpsc::SyncSender<T>) -> PlatformOp) -> Option<T> {
        let (tx, rx) = sync_channel(1);
        self.core.send(CoreMsg::Platform(mk(tx))).ok()?;
        rx.recv_timeout(CALL_TIMEOUT).ok()
    }
}

impl Platform for CorePlatform {
    fn rng(&mut self, buf: &mut [u8]) {
        unsafe { esp_idf_sys::esp_fill_random(buf.as_mut_ptr() as *mut _, buf.len()) };
    }

    fn seed_key(&self, info: &[u8]) -> Option<[u8; 32]> {
        self.call(|reply| PlatformOp::SeedKey { info: info.to_vec(), reply }).flatten()
    }

    fn user_presence(&mut self, req: &PresenceRequest) -> PresenceResult {
        let link = self.link;
        self.call(|reply| PlatformOp::Presence { req: req.clone(), link, reply }).unwrap_or(PresenceResult::Timeout)
    }

    fn find_resident(&self, rp_id: &str) -> Vec<PasskeyCredential> {
        self.call(|reply| PlatformOp::FindResident { rp_id: rp_id.to_string(), reply }).unwrap_or_default()
    }

    fn store_resident(&mut self, cred: PasskeyCredential) -> Result<(), StorageError> {
        self.call(|reply| PlatformOp::Store { cred, reply }).unwrap_or(Err(StorageError::Io))
    }

    fn delete_resident(&mut self, cred_id: &[u8]) -> Result<(), StorageError> {
        self.call(|reply| PlatformOp::Delete { cred_id: cred_id.to_vec(), reply }).unwrap_or(Err(StorageError::Io))
    }

    fn reset(&mut self) -> Result<(), StorageError> {
        self.call(|reply| PlatformOp::Reset { reply }).unwrap_or(Err(StorageError::Io))
    }

    fn keepalive(&mut self, _status: KeepaliveStatus) {
        // The transport layer sends CTAPHID/BLE keepalives on its own timer.
    }
}

/// Spawn the worker; returns the job queue.
pub fn spawn(core: Sender<CoreMsg>) -> anyhow::Result<Sender<CtapJob>> {
    let (tx, rx) = channel::<CtapJob>();
    // PSRAM stack: pure crypto/CBOR; resident-credential storage goes through the core actor.
    crate::threads::spawn_psram("ctap", 40 * 1024, move || worker(core, rx))?;
    Ok(tx)
}

fn worker(core: Sender<CoreMsg>, rx: Receiver<CtapJob>) {
    let mut auth = Authenticator::new(CorePlatform { core: core.clone(), link: Link::Usb });
    while let Ok(job) = rx.recv() {
        auth.platform_mut().link = job.reply.link();
        let response = auth.handle(&job.request);
        if core.send(CoreMsg::CtapResult { reply: job.reply, response }).is_err() {
            break;
        }
    }
}
