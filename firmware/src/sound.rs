//! Buzzer sound design. E-ink feedback is slow (hundreds of ms per refresh), so short sounds give
//! immediate confirmation of touches and make approval requests noticeable.
//!
//! Sound language: industrial / military equipment. Hard-edged square tones at fixed pitches
//! (no musical intervals, no fades), built from a few elements:
//! - PIP: short 3 kHz tone, the basic acknowledgement unit;
//! - stepped "stair" tones: up = system online / accepted, down = shutting down / expired;
//! - a self-test style pip pair at power-on;
//! - two-tone warble (klaxon) for alarms;
//! - long low tones for refusals and errors.
//!
//! Patterns play on a dedicated low-priority thread so they never block the core, UI or power
//! threads. `play()` is callable from anywhere; it is a no-op when the buzzer is disabled in
//! Settings. When the small queue is full, new sounds (typically clicks) are dropped.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::drivers::power::{Buzzer, BUZZER_MAX_DUTY};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sound {
    /// Touch on the screen: instant, quiet feedback while the panel redraws.
    Click,
    /// Something needs a tap: approval request, pairing code, standby woken by an app.
    Attention,
    /// Approval still pending, shortly before auto-deny.
    Reminder,
    /// Approval granted.
    Approved,
    /// Approval explicitly denied, or pairing refused.
    Denied,
    /// Approval expired without an answer.
    Timeout,
    /// Vault unlocked.
    Unlocked,
    /// Wrong PIN or other user-visible error.
    Error,
    /// Wrong PIN with only a few attempts left before the vault is wiped.
    LastChances,
    /// Input not accepted yet (e.g. OK with too few PIN digits): gentle, not an error.
    Invalid,
    /// Code submitted, device working (PIN check / key derivation running).
    Processing,
    /// Pairing completed, setup finished.
    Success,
    /// Device locked / powering off.
    Lock,
    /// Device powered on (PIN pad ready).
    PowerOn,
    /// Vault wiped (too many wrong PINs or explicit wipe).
    Wiped,
    /// FIDO "wink" (the browser asks the authenticator to identify itself).
    Wink,
}

#[derive(Clone, Copy)]
struct Note {
    /// Start and end frequency (Hz); equal = steady pitch, different = linear sweep. 0 = rest.
    from: u32,
    to: u32,
    /// Warble partner (Hz): alternates with `from` every `period` ms. 0 = none.
    alt: u32,
    period: u32,
    ms: u32,
    /// Loudness, 0..=100 (% of the piezo's maximum). Hard on/off, no envelope.
    vol: u32,
}

const fn tone(f: u32, ms: u32) -> Note {
    Note { from: f, to: f, alt: 0, period: 0, ms, vol: 100 }
}
const fn quiet(f: u32, ms: u32, vol: u32) -> Note {
    Note { from: f, to: f, alt: 0, period: 0, ms, vol }
}
const fn warble(a: u32, b: u32, period: u32, ms: u32) -> Note {
    Note { from: a, to: a, alt: b, period, ms, vol: 100 }
}
const fn gap(ms: u32) -> Note {
    Note { from: 0, to: 0, alt: 0, period: 0, ms, vol: 0 }
}

// Fixed equipment pitches (not musical): the piezo resonates loudest around 2.7-3.2 kHz.
const PIP: u32 = 3000;
const HI: u32 = 3600;
const MID: u32 = 2200;
const LO: u32 = 1300;
const BUZZ: u32 = 750;

fn pattern(s: Sound) -> &'static [Note] {
    match s {
        // Dry relay-like tick.
        Sound::Click => const { &[quiet(HI, 4, 55)] },
        // Incoming: three fast pips.
        Sound::Attention => const { &[tone(PIP, 45), gap(45), tone(PIP, 45), gap(45), tone(PIP, 45)] },
        // Still waiting: two pips.
        Sound::Reminder => const { &[tone(PIP, 45), gap(45), tone(PIP, 45)] },
        // Acknowledged: short-long, same pitch.
        Sound::Approved => const { &[tone(PIP, 35), gap(35), tone(PIP, 110)] },
        // Refused: one long low tone.
        Sound::Denied => const { &[tone(LO, 320)] },
        // Expired: stepped down, unanswered.
        Sound::Timeout => const { &[tone(MID, 70), gap(20), tone(LO, 70), gap(20), tone(BUZZ, 160)] },
        // System online: stepped up.
        Sound::Unlocked => const { &[tone(LO, 50), gap(15), tone(MID, 50), gap(15), tone(PIP, 50), gap(15), tone(HI, 90)] },
        // Wrong code: two harsh low buzzes.
        Sound::Error => const { &[tone(BUZZ, 160), gap(70), tone(BUZZ, 160)] },
        // Wrong code near the wipe limit: low/mid warble alarm.
        Sound::LastChances => const { &[warble(BUZZ, LO, 60, 600)] },
        // Not accepted yet: one short low blip.
        Sound::Invalid => const { &[tone(LO, 45)] },
        // Code received, processing: fast data burst.
        Sound::Processing => const { &[tone(HI, 15), gap(15), tone(HI, 15), gap(15), tone(HI, 15), gap(15), tone(HI, 15)] },
        // Link established / setup complete: stepped up, then confirmation pips.
        Sound::Success => const { &[tone(MID, 60), gap(15), tone(PIP, 60), gap(60), tone(HI, 40), gap(40), tone(HI, 40)] },
        // Shutting down: stepped down to a low tone.
        Sound::Lock => const { &[tone(HI, 50), gap(15), tone(PIP, 50), gap(15), tone(MID, 50), gap(15), tone(LO, 140)] },
        // Power-on self-test passed: one firm pip, then a short "ready" pip.
        Sound::PowerOn => const { &[tone(PIP, 110), gap(80), tone(HI, 45)] },
        // Vault destroyed: klaxon.
        Sound::Wiped => const { &[warble(LO, PIP, 90, 1400)] },
        // Identify: rapid triple chirp.
        Sound::Wink => const { &[tone(HI, 30), gap(30), tone(HI, 30), gap(30), tone(HI, 30)] },
    }
}

/// Render one note: hard on/off, pitch updated every `STEP` ms for sweeps and warbles.
fn render(n: &Note) -> anyhow::Result<()> {
    const STEP: u32 = 2;
    let start = Instant::now();
    if n.from == 0 || n.vol == 0 {
        Buzzer::off()?;
        std::thread::sleep(Duration::from_millis(n.ms as u64));
        return Ok(());
    }
    let duty = BUZZER_MAX_DUTY * n.vol.min(100) / 100;
    let steady = n.from == n.to && n.alt == 0;
    let mut t = 0;
    while t < n.ms {
        let f = if n.alt != 0 && n.period > 0 {
            if (t / n.period) % 2 == 0 { n.from } else { n.alt }
        } else if n.from != n.to {
            let (a, b) = (n.from as i64, n.to as i64);
            (a + (b - a) * t as i64 / n.ms.max(1) as i64) as u32
        } else {
            n.from
        };
        Buzzer::set(f, duty)?;
        if steady {
            // Nothing changes during a steady tone: one sleep for the whole note.
            if let Some(wait) = Duration::from_millis(n.ms as u64).checked_sub(start.elapsed()) {
                std::thread::sleep(wait);
            }
            break;
        }
        let next = Duration::from_millis((t + STEP).min(n.ms) as u64);
        if let Some(wait) = next.checked_sub(start.elapsed()) {
            std::thread::sleep(wait);
        }
        t += STEP;
    }
    // Hard stop between elements (patterns rely on gaps being silent).
    Buzzer::off()
}

static ENABLED: AtomicBool = AtomicBool::new(true);
static PLAYER: OnceLock<SyncSender<Sound>> = OnceLock::new();

/// Start the player thread. Call once at boot.
pub fn init() -> anyhow::Result<()> {
    // Small queue: sounds are short; anything beyond that is stale feedback.
    let (tx, rx) = sync_channel::<Sound>(4);
    crate::threads::spawn_psram("sound", 6 * 1024, move || {
        while let Ok(s) = rx.recv() {
            for n in pattern(s) {
                if let Err(e) = render(n) {
                    log::warn!("buzzer: {e:#}");
                    break;
                }
            }
            let _ = Buzzer::off();
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
