//! Wall clock: the BM8563 RTC is the source of truth across power cycles; the ESP-IDF system
//! clock (settimeofday) serves `now()` so no I2C traffic is needed per query.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::drivers::rtc::Bm8563;
use esp_idf_sys as sys;

/// 2024-01-01: anything earlier is considered "not set".
const MIN_VALID: u64 = 1_704_067_200;

pub struct Clock {
    rtc: Mutex<Option<Bm8563>>,
    valid: AtomicBool,
}

impl Clock {
    pub fn new(rtc: Option<Bm8563>) -> Self {
        let c = Self { rtc: Mutex::new(rtc), valid: AtomicBool::new(false) };
        c.load_from_rtc();
        c
    }

    fn load_from_rtc(&self) {
        let mut g = self.rtc.lock().unwrap();
        let Some(rtc) = g.as_mut() else { return };
        match (rtc.voltage_low(), rtc.get_unix_time()) {
            (Ok(false), Ok(t)) if t as u64 >= MIN_VALID => {
                set_system_time(t as u64);
                self.valid.store(true, Ordering::Relaxed);
                log::info!("RTC time valid: {t}");
            }
            other => log::warn!("RTC time not valid yet ({other:?})"),
        }
    }

    /// Current unix time (UTC). 0-ish before the first `set` if the RTC lost power.
    pub fn now(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    pub fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Relaxed)
    }

    pub fn set(&self, unix: u64) {
        set_system_time(unix);
        if let Some(rtc) = self.rtc.lock().unwrap().as_mut() {
            if let Err(e) = rtc.set_unix_time(unix as i64) {
                log::warn!("RTC write failed: {e:#}");
            }
        }
        self.valid.store(unix >= MIN_VALID, Ordering::Relaxed);
    }
}

fn set_system_time(unix: u64) {
    let tv = sys::timeval { tv_sec: unix as _, tv_usec: 0 };
    unsafe { sys::settimeofday(&tv, core::ptr::null()) };
}
