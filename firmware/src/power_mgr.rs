//! Power manager (ARCHITECTURE 7.3): idle tracking, auto-lock, post-lock sleep policy, battery
//! polling and the power-off sequence.
//!
//! * Idle (no `PowerMsg::Activity` for `auto_lock_secs`) while on the PIN pad or unlocked ->
//!   `CoreMsg::AutoLock`. The core locks, the UI draws the lock screen with a full refresh and
//!   reports `LockScreenDrawn`; only then do we act on `Settings.sleep_mode`:
//!     PowerOff   -> transport Shutdown, panel rails off, `Power::power_off()` (GPIO44 pulses; with
//!                   USB attached the board stays powered, so it deep-sleeps with NO wake source: only a
//!                   power cycle — unplug/replug or the side power button — brings it back).
//!     LightSleep -> keep BLE advertising and rely on automatic light sleep (DFS 80..240 MHz).
//!                   On battery with no BLE connection for 10 min -> PowerOff anyway.
//! * Automatic light sleep is disabled while USB power is present (the USB peripheral cannot
//!   survive light sleep); DFS stays on.
//! * The Paper S3 has no MCU-readable button (GPIO0 is the status LED). The side button is a
//!   hardware power switch: it is the only way to turn the device on. Touch never wakes it.
use std::sync::atomic::Ordering;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use esp_idf_sys as sys;
use prism_core::model::{Settings, SleepMode};
use prism_ui::UiEvent;

use crate::board;
use crate::core::msg::{CoreMsg, Mode, PowerMsg, SharedStatus, UiMsg};
use crate::drivers::power::{lipo_percent, Power};
use crate::storage::Store;
use crate::transport::TransportCommand;

/// Shutdown breadcrumb stages (see `Store::shutdown_stage`).
pub const SHUT_STARTED: u8 = 1;
pub const SHUT_RADIO_OFF: u8 = 2;
pub const SHUT_PANEL_OFF: u8 = 3;
pub const SHUT_PULSES_SENT: u8 = 4;
pub const SHUT_DEEP_SLEEP: u8 = 5;

const BATTERY_POLL: Duration = Duration::from_secs(30);
const NO_BLE_POWER_OFF: Duration = Duration::from_secs(10 * 60);

pub struct PowerMgr {
    power: Power,
    rx: Receiver<PowerMsg>,
    core: Sender<CoreMsg>,
    ui: Sender<UiMsg>,
    transport: Sender<TransportCommand>,
    store: Arc<Mutex<Store>>,
    status: Arc<SharedStatus>,
    settings: Settings,
    mode: Mode,
    last_activity: Instant,
    force_off: bool,
    lock_drawn: bool,
    light_sleeping: bool,
    no_ble_since: Option<Instant>,
    last_battery: Instant,
    pm_light: Option<bool>,
}

impl PowerMgr {
    /// Reads the battery once so the first UI/DeviceInfo values are real.
    pub fn new(
        power: Power,
        rx: Receiver<PowerMsg>,
        core: Sender<CoreMsg>,
        ui: Sender<UiMsg>,
        transport: Sender<TransportCommand>,
        store: Arc<Mutex<Store>>,
        status: Arc<SharedStatus>,
    ) -> Self {
        let mut m = Self {
            power,
            rx,
            core,
            ui,
            transport,
            store,
            status,
            settings: Settings::default(),
            mode: Mode::Setup,
            last_activity: Instant::now(),
            force_off: false,
            lock_drawn: false,
            light_sleeping: false,
            no_ble_since: None,
            last_battery: Instant::now(),
            pm_light: None,
        };
        m.poll_battery(false);
        m
    }

    pub fn spawn(self) -> anyhow::Result<()> {
        std::thread::Builder::new().name("power".into()).stack_size(8 * 1024).spawn(move || self.run())?;
        Ok(())
    }

    fn run(mut self) {
        unsafe {
            // Touch INT may wake *automatic light sleep* while the device is in use (CPU idle
            // between frames). It never turns the device on or leaves the lock screen.
            let _ = sys::gpio_wakeup_enable(board::TOUCH_INT, sys::gpio_int_type_t_GPIO_INTR_LOW_LEVEL);
            let _ = sys::esp_sleep_enable_gpio_wakeup();
        }
        self.update_pm();
        loop {
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => self.on_msg(m),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            while let Ok(m) = self.rx.try_recv() {
                self.on_msg(m);
            }
            if self.last_battery.elapsed() >= BATTERY_POLL {
                self.poll_battery(true);
                crate::threads::log_heap("periodic");
                crate::threads::log_stacks();
            }
            self.update_pm();
            self.policy();
        }
    }

    fn on_msg(&mut self, m: PowerMsg) {
        match m {
            PowerMsg::Activity => self.last_activity = Instant::now(),
            PowerMsg::Mode(m) => {
                self.mode = m;
                self.lock_drawn = false;
                self.last_activity = Instant::now();
                if m != Mode::LockScreen {
                    self.light_sleeping = false;
                    self.force_off = false;
                }
            }
            PowerMsg::LockScreenDrawn => {
                if self.mode == Mode::LockScreen {
                    self.lock_drawn = true;
                    self.after_lock();
                }
            }
            PowerMsg::ForceOff => {
                self.force_off = true;
                if self.mode == Mode::Setup || (self.mode == Mode::LockScreen && self.lock_drawn) {
                    self.shutdown();
                }
            }
            PowerMsg::Settings(s) => self.settings = s,
        }
    }

    fn after_lock(&mut self) {
        let pct = self.status.battery_pct.load(Ordering::Relaxed);
        let _ = self.store.lock().unwrap().set_battery_at_shutdown(pct);
        if self.force_off || self.settings.sleep_mode == SleepMode::PowerOff {
            self.shutdown();
        }
        log::info!("locked: staying reachable over BLE (light sleep)");
        self.light_sleeping = true;
        self.no_ble_since = (!self.status.ble.load(Ordering::Relaxed)).then(Instant::now);
    }

    fn policy(&mut self) {
        // Auto-lock.
        let secs = self.settings.auto_lock_secs;
        if matches!(self.mode, Mode::Pin | Mode::Unlocked)
            && secs > 0
            && self.last_activity.elapsed() >= Duration::from_secs(secs as u64)
        {
            self.last_activity = Instant::now();
            let _ = self.core.send(CoreMsg::AutoLock);
        }
        // Locked + LightSleep: give up on battery after 10 min without a BLE link.
        if self.light_sleeping {
            if self.status.ble.load(Ordering::Relaxed) {
                self.no_ble_since = None;
            } else {
                let since = *self.no_ble_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= NO_BLE_POWER_OFF && !self.power.usb_present() {
                    log::info!("no BLE connection for 10 min on battery: powering off");
                    self.shutdown();
                }
            }
        }
    }

    fn update_pm(&mut self) {
        // USB_DET (GPIO5) reads low on real hardware even with USB attached (2026-11-11), so
        // also treat "charging" and "USB host configured us" as USB present. Light sleep would
        // drop the USB link (and the USB-Serial-JTAG log console in the jtag-console build).
        let usb = self.power.usb_present()
            || self.power.is_charging()
            || self.status.usb_cfg.load(Ordering::Relaxed)
            || cfg!(feature = "jtag-console");
        self.status.usb_power.store(usb, Ordering::Relaxed);
        let light = !usb;
        if self.pm_light != Some(light) {
            log::info!(
                "PM inputs: USB_DET={} CHG_STAT(low=charging)={} usb_configured={}",
                self.power.usb_present() as u8,
                (!self.power.is_charging()) as u8,
                self.status.usb_cfg.load(Ordering::Relaxed) as u8
            );
            match Power::configure_pm(80, light) {
                Ok(()) => {
                    log::info!("PM: DFS 80-240 MHz, auto light sleep {}", if light { "on" } else { "off (USB)" });
                    self.pm_light = Some(light);
                }
                Err(e) => {
                    log::warn!("PM configure failed: {e:#}");
                    self.pm_light = Some(light); // do not retry every 50 ms
                }
            }
        }
    }

    fn poll_battery(&mut self, notify: bool) {
        self.last_battery = Instant::now();
        let mv = match self.power.battery_mv() {
            Ok(v) => v,
            Err(e) => {
                log::warn!("battery read failed: {e:#}");
                return;
            }
        };
        let pct = lipo_percent(mv);
        let charging = self.power.is_charging();
        self.status.battery_pct.store(pct, Ordering::Relaxed);
        self.status.charging.store(charging, Ordering::Relaxed);
        self.status.usb_power.store(self.power.usb_present(), Ordering::Relaxed);
        if notify {
            let _ = self.ui.send(UiMsg::Event(UiEvent::Battery { pct, charging }));
        }
        let _ = self.transport.send(TransportCommand::SetBattery(pct));
    }

    /// Radio down, panel rails down, then cut power (or deep sleep on USB). Never returns.
    /// Breadcrumb for diagnosing shutdowns that end in a reboot (shown at the next boot).
    fn crumb(&self, stage: u8) {
        let _ = self.store.lock().unwrap().set_shutdown_stage(stage);
    }

    fn shutdown(&mut self) -> ! {
        log::info!("shutting down");
        self.crumb(SHUT_STARTED);
        let pct = self.status.battery_pct.load(Ordering::Relaxed);
        let _ = self.store.lock().unwrap().set_battery_at_shutdown(pct);
        let _ = self.transport.send(TransportCommand::Shutdown);
        std::thread::sleep(Duration::from_millis(400));
        self.crumb(SHUT_RADIO_OFF);
        let (tx, rx) = sync_channel(1);
        if self.ui.send(UiMsg::PanelOff(tx)).is_ok() {
            let _ = rx.recv_timeout(Duration::from_secs(5));
        }
        self.crumb(SHUT_PANEL_OFF);
        if cfg!(feature = "jtag-console") && !cfg!(feature = "jtag-real-off") {
            self.power.power_off(); // diagnostic build: stays on
        }
        self.power.send_off_pulses();
        self.power.release_power_line();
        self.crumb(SHUT_PULSES_SENT);
        // The power circuit may cut with a delay: give it time before falling back to sleep.
        std::thread::sleep(Duration::from_millis(1000));
        // Still running: power was not cut (USB attached, or the pulses had no effect).
        self.crumb(SHUT_DEEP_SLEEP);
        self.power.sleep_until_power_cycle()
    }
}
