//! Buzzer sound design. E-ink feedback is slow (hundreds of ms per refresh), so short sounds give
//! immediate confirmation of touches and make approval requests noticeable.
//!
//! Patterns are played on a dedicated low-priority thread so they never block the core, UI or
//! power threads. `play()` is callable from anywhere; it is a no-op when the buzzer is disabled in
//! Settings. When the small queue is full, new sounds (typically clicks) are dropped.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::OnceLock;

use crate::drivers::power::Buzzer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sound {
    /// Touch on the screen: instant feedback while the panel redraws.
    Click,
    /// Something needs a tap: approval request, pairing code displayed.
    Attention,
    /// Approval still pending, 10 s before auto-deny.
    Reminder,
    /// Approval granted.
    Approved,
    /// Approval denied, timed out, or pairing refused.
    Denied,
    /// Vault unlocked.
    Unlocked,
    /// Wrong PIN or other user-visible error.
    Error,
    /// Pairing completed, setup finished.
    Success,
    /// Device locked / powering off.
    Lock,
    /// FIDO "wink" (the browser asks the authenticator to identify itself).
    Wink,
}

/// (frequency Hz, duration ms); frequency 0 = rest. The Paper S3 piezo is loudest ~2-3 kHz.
fn pattern(s: Sound) -> &'static [(u32, u32)] {
    match s {
        Sound::Click => &[(3200, 6)],
        Sound::Attention => &[(1900, 70), (0, 40), (2600, 110)],
        Sound::Reminder => &[(2600, 60), (0, 60), (2600, 60)],
        Sound::Approved => &[(2900, 70)],
        Sound::Denied => &[(1700, 90), (0, 30), (1100, 160)],
        Sound::Unlocked => &[(1800, 45), (0, 20), (2300, 45), (0, 20), (2900, 70)],
        Sound::Error => &[(700, 260)],
        Sound::Success => &[(2000, 60), (0, 25), (2600, 60), (0, 25), (3200, 120)],
        Sound::Lock => &[(2200, 50), (0, 25), (1500, 110)],
        Sound::Wink => &[(2800, 40), (0, 50), (2800, 40), (0, 50), (2800, 40)],
    }
}

static ENABLED: AtomicBool = AtomicBool::new(true);
static PLAYER: OnceLock<SyncSender<Sound>> = OnceLock::new();

/// Start the player thread. Call once at boot.
pub fn init() -> anyhow::Result<()> {
    // Small queue: sounds are short; anything beyond that is stale feedback.
    let (tx, rx) = sync_channel::<Sound>(4);
    crate::threads::spawn_psram("sound", 4 * 1024, move || {
        while let Ok(s) = rx.recv() {
            for &(freq, ms) in pattern(s) {
                if freq == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
                } else if let Err(e) = Buzzer::beep(freq, ms) {
                    log::warn!("buzzer: {e:#}");
                    break;
                }
            }
        }
    })?;
    let _ = PLAYER.set(tx);
    Ok(())
}

/// Follow Settings.buzzer.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Queue a sound (non-blocking).
pub fn play(s: Sound) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let Some(tx) = PLAYER.get() else { return };
    match tx.try_send(s) {
        Ok(()) | Err(TrySendError::Disconnected(_)) => {}
        Err(TrySendError::Full(_)) => {
            if s != Sound::Click {
                log::debug!("sound queue full, dropped {s:?}");
            }
        }
    }
}
