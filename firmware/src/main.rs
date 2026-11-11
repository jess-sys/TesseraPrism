//! Prism firmware entry point (M5Stack Paper S3).
//!
//! Boot (ARCHITECTURE 7.3): PSRAM check -> NVS + vault storage -> drivers -> UI thread (splash) ->
//! transport (BLE/USB) -> core actor -> power manager. The core then sends `BootComplete`
//! (setup wizard if there is no vault, otherwise the PIN pad).
//!
//! Threads: `ui` (panel + touch), `core` (vault, sessions, approvals), `ctap` (authenticator),
//! `power` (idle/lock/sleep/battery/button), `tp-fwd` (transport events -> core), plus the
//! transport's own threads.
#![allow(dead_code)]
mod board;
mod core;
mod drivers;
mod hardening;
mod power_mgr;
mod sound;
mod storage;
mod threads;
mod touch_task;
mod transport;
mod ui_task;

use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use esp_idf_hal::{
    i2c::{I2cConfig, I2cDriver},
    peripherals::Peripherals,
    units::Hertz,
};
use esp_idf_svc::{nvs::EspDefaultNvsPartition, sys};

use crate::core::clock::Clock;
use crate::core::msg::{CoreMsg, SharedStatus};
use drivers::{epd::Epd, power::Power, rtc::Bm8563, touch::Gt911};

fn check_psram() -> Result<()> {
    let total = unsafe { sys::heap_caps_get_total_size(sys::MALLOC_CAP_SPIRAM) };
    let free = unsafe { sys::heap_caps_get_free_size(sys::MALLOC_CAP_SPIRAM) };
    log::info!("PSRAM: total {total} B, free {free} B");
    anyhow::ensure!(total >= 7 * 1024 * 1024, "PSRAM missing or too small ({total} B)");
    Ok(())
}

/// "Prism-XXXX" from the last two bytes of the Bluetooth MAC.
fn ble_name() -> String {
    let mut mac = [0u8; 6];
    let rc = unsafe { sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_BT) };
    if rc != 0 {
        log::warn!("esp_read_mac failed ({rc})");
    }
    format!("Prism-{:02X}{:02X}", mac[4], mac[5])
}

/// Set once the UI thread is up, so a later boot failure can be shown on the eInk
/// (there is no log output in the normal TinyUSB build).
static BOOT_UI: std::sync::OnceLock<std::sync::mpsc::Sender<core::msg::UiMsg>> = std::sync::OnceLock::new();

fn main() {
    sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    log::info!("Prism firmware {} booting", core::FW_VERSION);
    unsafe {
        log::info!("reset reason: {}", reset_reason_name(sys::esp_reset_reason()));
        // Deep sleep latches the panel rails (EPD_OE/EPD_PWR) low via GPIO hold; release them or
        // epdiy cannot power the panel after a wake / soft reset.
        sys::gpio_deep_sleep_hold_dis();
        for pin in [board::EPD_OE, board::EPD_PWR] {
            sys::gpio_hold_dis(pin);
        }
    }
    if let Err(e) = run() {
        log::error!("boot failed: {e:#}");
        threads::log_heap("boot failed");
        if let Some(ui) = BOOT_UI.get() {
            let _ = ui.send(core::msg::UiMsg::Event(prism_ui::UiEvent::Message {
                text: format!("Boot failed: {e:#}"),
                error: true,
            }));
        }
        // Keep the already-started threads (UI, transport) alive so the message stays visible.
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}

fn reset_reason_name(r: sys::esp_reset_reason_t) -> &'static str {
    match r {
        sys::esp_reset_reason_t_ESP_RST_POWERON => "power-on",
        sys::esp_reset_reason_t_ESP_RST_EXT => "external pin",
        sys::esp_reset_reason_t_ESP_RST_SW => "software restart",
        sys::esp_reset_reason_t_ESP_RST_PANIC => "PANIC",
        sys::esp_reset_reason_t_ESP_RST_INT_WDT => "INTERRUPT WATCHDOG",
        sys::esp_reset_reason_t_ESP_RST_TASK_WDT => "TASK WATCHDOG",
        sys::esp_reset_reason_t_ESP_RST_WDT => "other watchdog",
        sys::esp_reset_reason_t_ESP_RST_DEEPSLEEP => "deep-sleep wake",
        sys::esp_reset_reason_t_ESP_RST_BROWNOUT => "BROWNOUT",
        sys::esp_reset_reason_t_ESP_RST_SDIO => "SDIO",
        sys::esp_reset_reason_t_ESP_RST_USB => "USB",
        sys::esp_reset_reason_t_ESP_RST_JTAG => "JTAG",
        _ => "unknown",
    }
}

fn run() -> Result<()> {
    check_psram()?;
    // Argon2 parameters come from stored slots and imported files: refuse anything that would not
    // fit in PSRAM (an allocation failure would abort the firmware).
    prism_core::slots::set_max_kdf_memory_kib(4096);
    // Reserve Argon2's 4 MiB working memory now, before the framebuffers/BLE fragment PSRAM.
    prism_core::slots::set_kdf_scratch_blocks(4096);
    // This board's PSRAM occasionally returns bad data under Argon2's random-access load (verified on
    // hardware: identical inputs, differing outputs). Accept a derivation only when two runs agree.
    prism_core::slots::set_kdf_verify(true);
    threads::log_heap("kdf scratch reserved");

    // ---- persistent storage ----
    let nvs_part = EspDefaultNvsPartition::take().context("NVS partition")?;
    let store = Arc::new(Mutex::new(storage::Store::open(nvs_part)?));
    let vault_store = storage::VaultStore::open()?;

    // ---- drivers ----
    let p = Peripherals::take()?;
    let i2c = I2cDriver::new(
        p.i2c1,
        p.pins.gpio41,
        p.pins.gpio42,
        &I2cConfig::new().baudrate(Hertz(board::I2C_FREQ_HZ)),
    )?;
    let i2c: board::SharedI2c = Arc::new(Mutex::new(i2c));
    let power = Power::new()?;
    log::info!("wake cause: {:?}", power.wake_cause());
    let rtc = match Bm8563::new(i2c.clone()) {
        Ok(mut r) => {
            // The BM8563 INT line can switch the Paper S3's power on. An alarm/timer left armed
            // (e.g. by the factory firmware; the RTC is battery-backed) keeps INT asserted, so every
            // power cut re-powers the board at once ("Lock reboots on battery"). Prism never uses
            // RTC wake-ups: disarm and clear them on every boot.
            match r.take_irq_flags() {
                Ok((timer, alarm)) if timer || alarm => {
                    log::warn!("RTC IRQ flags were set (timer={timer} alarm={alarm}): clearing")
                }
                Ok(_) => {}
                Err(e) => log::warn!("RTC flag read failed: {e:#}"),
            }
            if let Err(e) = r.disable_irqs() {
                log::warn!("RTC IRQ disable failed: {e:#}");
            }
            Some(r)
        }
        Err(e) => {
            log::warn!("RTC init failed: {e:#}");
            None
        }
    };
    let clock = Arc::new(Clock::new(rtc));
    let touch = match Gt911::new(i2c.clone()) {
        Ok(t) => Some(t),
        Err(e) => {
            log::warn!("touch init failed: {e:#}");
            None
        }
    };
    if let Err(e) = sound::init() {
        log::warn!("sound init failed: {e:#}");
    }
    let epd = Epd::new()?;
    threads::log_heap("drivers up");
    let status = Arc::new(SharedStatus::new());

    // ---- channels ----
    let (core_tx, core_rx) = channel::<CoreMsg>();
    let (ui_tx, ui_rx) = channel();
    let (power_tx, power_rx) = channel();

    // UI first: it draws the splash while the rest comes up.
    ui_task::spawn(epd, ui_rx, core_tx.clone(), power_tx.clone(), clock.clone())?;
    if let Some(t) = touch {
        touch_task::spawn(t, ui_tx.clone())?;
    }
    let _ = BOOT_UI.set(ui_tx.clone());
    {
        // Diagnostics: if the previous run died during the power-off sequence, show where.
        let stage = store.lock().unwrap().shutdown_stage();
        let rr = unsafe { sys::esp_reset_reason() };
        // A power-on reset after a recorded shutdown is the normal "off, then power button" path:
        // only report crashes / watchdogs / brownouts / unexpected resets during power-off.
        let abnormal = rr != sys::esp_reset_reason_t_ESP_RST_POWERON;
        if stage != 0 && !abnormal {
            let _ = store.lock().unwrap().set_shutdown_stage(0);
        }
        if stage != 0 && abnormal {
            let reason = reset_reason_name(rr);
            let what = match stage {
                1 => "started",
                2 => "radio off",
                3 => "panel off",
                4 => "off pulses sent, still powered",
                5 => "entering deep sleep",
                _ => "?",
            };
            let text = format!("Last power-off reached: {what} (stage {stage}). Reset reason: {reason}.");
            log::warn!("{text}");
            // Delayed so it shows on top of the PIN pad instead of being replaced by it.
            let tx = ui_tx.clone();
            let _ = threads::spawn_psram("diag", 4 * 1024, move || {
                std::thread::sleep(std::time::Duration::from_secs(4));
                let _ = tx.send(core::msg::UiMsg::Event(prism_ui::UiEvent::Message { text, error: false }));
            });
            let _ = store.lock().unwrap().set_shutdown_stage(0);
        }
    }

    // ---- transport ----
    let th = transport::start(transport::TransportConfig {
        ble_name: ble_name(),
        fw_version: core::FW_VERSION.into(),
        enable_ble: true,
        enable_usb: true,
    })
    .context("transport start")?;
    threads::log_heap("transport up");
    {
        let tx = core_tx.clone();
        let events = th.events;
        threads::spawn_psram("tp-fwd", 4096, move || {
            while let Ok(ev) = events.recv() {
                if tx.send(CoreMsg::Transport(ev)).is_err() {
                    break;
                }
            }
        })?;
    }

    // ---- power manager (reads the battery once before the core boots) ----
    let pm = power_mgr::PowerMgr::new(
        power,
        power_rx,
        core_tx.clone(),
        ui_tx.clone(),
        th.commands.clone(),
        store.clone(),
        status.clone(),
    );

    // ---- core actor ----
    core::start(
        core::CoreChannels {
            rx: core_rx,
            self_tx: core_tx,
            transport: th.commands,
            ui: ui_tx,
            power: power_tx,
        },
        store,
        vault_store,
        clock,
        status,
    )?;
    pm.spawn()?;

    threads::log_heap("boot complete");
    log::info!("boot complete");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
