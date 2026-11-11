//! Touch thread: polls the GT911 independently of the UI thread, so taps made while the panel
//! is refreshing (hundreds of ms, blocking the UI thread) are queued instead of lost.
//!
//! Emits `UiMsg::Touch { down, x, y }` in raw controller coordinates: `down: true` on first
//! contact, `down: false` (with the last position) on release.
//!
//! Debouncing (PIN digits register on touch-down, so a spurious release+press = a duplicate
//! digit = "wrong PIN"):
//! * "no new report" (GT911 ready bit clear) never counts as a release — only a report with zero
//!   points does, (`RELEASE_REPORTS`), or no report at all for
//!   `STALE_RELEASE` (finger lifted without a final report);
//! * a press within `BOUNCE` of the previous release is contact flicker: it is swallowed together
//!   with its release.

use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use crate::core::msg::UiMsg;
use crate::drivers::touch::Gt911;

/// Poll period. One poll = a 1-byte I2C status read when nothing is touched.
const POLL: Duration = Duration::from_millis(20);
/// Zero-point reports before a release is reported. The GT911 sends exactly one such report on
/// lift and then goes quiet, so this must be 1 (contact flicker is handled by `BOUNCE`).
const RELEASE_REPORTS: u32 = 1;
/// Release if a touch produced no report at all for this long.
const STALE_RELEASE: Duration = Duration::from_millis(400);
/// Presses closer than this to the previous release are treated as bounce.
const BOUNCE: Duration = Duration::from_millis(70);

pub fn spawn(mut touch: Gt911, ui: Sender<UiMsg>) -> anyhow::Result<()> {
    // PSRAM stack is fine: I2C only, never touches flash.
    crate::threads::spawn_psram("touch", 6 * 1024, move || {
        let mut last: Option<(u16, u16)> = None; // finger currently down (last position)
        let mut forwarded = false; // the current press was sent to the UI
        let mut empty = 0u32;
        let mut last_report = Instant::now();
        let mut released_at = Instant::now() - BOUNCE * 2;
        loop {
            std::thread::sleep(POLL);
            let report = match touch.read_points() {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("touch read: {e:#}");
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
            };
            let pts = match report {
                Some(p) => {
                    last_report = Instant::now();
                    p
                }
                None => {
                    // No new data: keep the current state, unless the touch went silent.
                    if last.is_some() && last_report.elapsed() >= STALE_RELEASE {
                        Vec::new()
                    } else {
                        continue;
                    }
                }
            };
            match (pts.first(), last) {
                (Some(p), None) => {
                    last = Some((p.x, p.y));
                    empty = 0;
                    forwarded = released_at.elapsed() >= BOUNCE;
                    if !forwarded {
                        log::debug!("touch: bounce suppressed");
                    } else if ui.send(UiMsg::Touch { down: true, x: p.x, y: p.y }).is_err() {
                        return;
                    }
                }
                (Some(p), Some(_)) => {
                    last = Some((p.x, p.y));
                    empty = 0;
                }
                (None, Some((x, y))) => {
                    empty += 1;
                    if empty >= RELEASE_REPORTS || last_report.elapsed() >= STALE_RELEASE {
                        last = None;
                        released_at = Instant::now();
                        if std::mem::take(&mut forwarded)
                            && ui.send(UiMsg::Touch { down: false, x, y }).is_err()
                        {
                            return;
                        }
                    }
                }
                (None, None) => {}
            }
        }
    })
}
