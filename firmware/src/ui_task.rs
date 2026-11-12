//! UI task: owns the e-ink panel, the GT911 and the `prism_ui::Ui` state machine.
//!
//! * Touch: events come from the touch thread (`touch_task`) as `UiMsg::Touch` in raw controller
//!   coordinates (portrait 540x960 frame, verified on hardware), mapped to logical here. All
//!   queued messages are handled before each redraw, so taps made during a refresh coalesce
//!   into one refresh instead of being lost.
//! * 1 Hz `Tick`, drawing through `Rotated` onto the (landscape) `Epd`, refresh per `refresh_hint`.
//! * `UiAction`s go to the core actor (`Activity` goes straight to the power manager).
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use embedded_graphics::prelude::Point;
use prism_ui::{RefreshMode as UiRefresh, Rotated, Rotation, TouchEvent, Ui, UiAction, UiEvent};

use crate::core::clock::Clock;
use crate::core::msg::{CoreMsg, PowerMsg, UiMsg};
use crate::drivers::epd::{EinkDisplay, Epd, RefreshMode, Rotation as EpdRotation};

/// Show the splash only if the first real screen is not ready by then.
const BOOT_SPLASH_AFTER: Duration = Duration::from_secs(3);

pub fn spawn(
    epd: Epd,
    rx: Receiver<UiMsg>,
    core: Sender<CoreMsg>,
    power: Sender<PowerMsg>,
    clock: Arc<Clock>,
) -> anyhow::Result<()> {
    // PSRAM stack: the UI never writes flash (settings are persisted by the core).
    crate::threads::spawn_psram("ui", 40 * 1024, move || {
        UiTask { epd, rx, core, power, clock, ui: Ui::new(), touch_down: false }.run()
    })
}

struct UiTask {
    epd: Epd,
    rx: Receiver<UiMsg>,
    core: Sender<CoreMsg>,
    power: Sender<PowerMsg>,
    clock: Arc<Clock>,
    ui: Ui,
    /// A Down was forwarded to the Ui and its Up is still pending.
    touch_down: bool,
}


impl UiTask {
    fn run(mut self) {
        self.epd.set_rotation(EpdRotation::Landscape); // `Rotated` does the portrait mapping
        // Erase whatever the panel kept from before power-off (lock screen, ghosting) before
        // the first frame.
        self.epd.boot_clear();
        // No splash: the panel is now clean white, so the first real screen (PIN pad / setup) is
        // drawn straight away with a non-flashing refresh as soon as the core reports in. The splash
        // is only shown if that takes longer than BOOT_SPLASH_AFTER.
        let _ = self.ui.refresh_hint(); // drop the initial "full" hint for the splash
        let boot_started = Instant::now();
        let mut first_drawn = false;
        let mut next_tick = Instant::now() + Duration::from_secs(1);
        let mut lock_drawn_pending = false;
        loop {
            let on_lock = self.ui.screen_name() == "lock";
            crate::touch_task::set_active(!on_lock);
            // Lock screen: static, so no 1 Hz tick (keeps the CPU in light sleep in standby).
            let wait = if on_lock { Duration::from_secs(60) } else { next_tick.saturating_duration_since(Instant::now()) };
            match self.rx.recv_timeout(wait) {
                Ok(m) => {
                    lock_drawn_pending |= self.on_msg(m);
                    while let Ok(m) = self.rx.try_recv() {
                        lock_drawn_pending |= self.on_msg(m);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }

            if !on_lock && Instant::now() >= next_tick {
                next_tick += Duration::from_secs(1);
                if next_tick < Instant::now() {
                    next_tick = Instant::now() + Duration::from_secs(1);
                }
                let acts = self.ui.handle(UiEvent::Tick { unix: self.clock.now() });
                self.forward(acts);
            }

            if !first_drawn && !self.ui.needs_refresh() && boot_started.elapsed() >= BOOT_SPLASH_AFTER {
                first_drawn = true;
                self.draw_and_refresh_mode(RefreshMode::Text); // fallback splash
            }
            if self.ui.needs_refresh() {
                first_drawn = true;
                self.draw_and_refresh();
                if lock_drawn_pending && self.ui.screen_name() == "lock" {
                    lock_drawn_pending = false;
                    let _ = self.power.send(PowerMsg::LockScreenDrawn);
                }
            }
        }
    }

    /// Returns true if this message was the lock screen event.
    fn on_msg(&mut self, m: UiMsg) -> bool {
        match m {
            UiMsg::Event(ev) => {
                let is_lock = matches!(ev, UiEvent::Locked { .. });
                let acts = self.ui.handle(ev);
                self.forward(acts);
                is_lock
            }
            UiMsg::Touch { down, x, y } => {
                self.on_touch(down, x, y);
                false
            }
            UiMsg::PanelOff(ack) => {
                self.epd.power_off_panel();
                let _ = ack.send(());
                false
            }
        }
    }

    fn forward(&self, acts: Vec<UiAction>) {
        for a in acts {
            match a {
                UiAction::Activity => {
                    let _ = self.power.send(PowerMsg::Activity);
                }
                UiAction::InvalidInput => crate::sound::play(crate::sound::Sound::Invalid),
                UiAction::SubmitPin(pin) => {
                    crate::sound::play(crate::sound::Sound::Processing);
                    let _ = self.core.send(CoreMsg::Ui(UiAction::SubmitPin(pin)));
                }
                a => {
                    let _ = self.core.send(CoreMsg::Ui(a));
                }
            }
        }
    }

    fn logical(&self, x: u16, y: u16) -> (i32, i32) {
        // Controller frame (portrait 540x960) -> panel frame -> logical frame for the orientation.
        let panel = Rotation::Portrait.to_panel(Point::new(x as i32, y as i32));
        let p = self.ui.rotation().touch_to_logical(panel.x, panel.y);
        (p.x, p.y)
    }

    fn on_touch(&mut self, down: bool, x: u16, y: u16) {
        let (lx, ly) = self.logical(x, y);
        if down {
            if self.ui.screen_name() != "lock" && !self.ui.input_blocked() {
                crate::sound::play(crate::sound::Sound::Click);
            }
            log::debug!("touch down: raw=({x}, {y}) logical=({lx}, {ly}) screen={}", self.ui.screen_name());
            if self.ui.screen_name() == "lock" {
                // Locked means off: touches never wake the device (only the power button does).
                return;
            }
            self.touch_down = true;
            let acts = self.ui.handle(UiEvent::Touch(TouchEvent::Down { x: lx, y: ly }));
            self.forward(acts);
        } else if std::mem::take(&mut self.touch_down) {
            let acts = self.ui.handle(UiEvent::Touch(TouchEvent::Up { x: lx, y: ly }));
            self.forward(acts);
        }
    }

    /// Draw the current screen and refresh the whole panel with `mode`, ignoring the Ui's hint.
    fn draw_and_refresh_mode(&mut self, mode: RefreshMode) {
        {
            let mut r = Rotated::new(&mut self.epd, self.ui.rotation());
            self.ui.draw(&mut r);
        }
        let _ = self.ui.refresh_hint();
        self.epd.refresh(mode, None);
    }

    fn draw_and_refresh(&mut self) {
        {
            let mut r = Rotated::new(&mut self.epd, self.ui.rotation());
            self.ui.draw(&mut r);
        }
        let (mode, area) = match self.ui.refresh_hint() {
            UiRefresh::Full => (RefreshMode::Full, None),
            UiRefresh::Text => (RefreshMode::Text, None),
            UiRefresh::Partial(r) if r.size.width == 0 || r.size.height == 0 => return,
            UiRefresh::Partial(r) => (RefreshMode::Partial, Some(r)), // panel coords == Epd landscape coords
            UiRefresh::Fast(r) if r.size.width == 0 || r.size.height == 0 => return,
            UiRefresh::Fast(r) => (RefreshMode::Fast, Some(r)),
        };
        self.epd.refresh(mode, area);
    }
}
