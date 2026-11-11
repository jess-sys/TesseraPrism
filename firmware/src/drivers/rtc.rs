//! BM8563 (PCF8563-compatible) RTC at 0x51 on the shared internal I2C bus.
//!
//! Registers: 0x00/0x01 control 1/2 (TIE=bit0, AIE=bit1, TF=bit2, AF=bit3), 0x02..0x08 time
//! (BCD: sec[6:0] with VL=bit7, min, hour, day, weekday, month[4:0] with century=bit7, year),
//! 0x09..0x0C alarm (min, hour, day, weekday; bit7 = disabled), 0x0D CLKOUT, 0x0E timer control
//! (TE=bit7, TD[1:0] source clock), 0x0F timer count.
//!
//! NOTE: the BM8563 INT output is not routed to an MCU GPIO on the Paper S3 (see `board::RTC_ADDR`).
//! Alarm/timer flags can therefore be polled, and a pending alarm powers the device on only if the
//! power-latch circuit uses INT (unverified without hardware).
use anyhow::{Context, Result};
use esp_idf_hal::delay::TickType;

use crate::board::{self, SharedI2c};

fn timeout() -> u32 {
    TickType::new_millis(50).ticks()
}

fn bcd2bin(v: u8) -> u8 {
    (v >> 4) * 10 + (v & 0x0F)
}
fn bin2bcd(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

pub struct Bm8563 {
    i2c: SharedI2c,
}

impl Bm8563 {
    pub fn new(i2c: SharedI2c) -> Result<Self> {
        let mut dev = Self { i2c };
        // Normal mode, clear any pending flags and interrupt enables.
        dev.write(0x00, &[0x00, 0x00]).context("BM8563 not responding")?;
        Ok(dev)
    }

    fn read(&mut self, reg: u8, buf: &mut [u8]) -> Result<()> {
        let mut bus = self.i2c.lock().unwrap();
        bus.write_read(board::RTC_ADDR, &[reg], buf, timeout())?;
        Ok(())
    }

    fn write(&mut self, reg: u8, data: &[u8]) -> Result<()> {
        let mut bus = self.i2c.lock().unwrap();
        let mut msg = Vec::with_capacity(1 + data.len());
        msg.push(reg);
        msg.extend_from_slice(data);
        bus.write(board::RTC_ADDR, &msg, timeout())?;
        Ok(())
    }

    /// True if the oscillator stopped (battery loss): time is invalid until set.
    pub fn voltage_low(&mut self) -> Result<bool> {
        let mut b = [0u8; 1];
        self.read(0x02, &mut b)?;
        Ok(b[0] & 0x80 != 0)
    }

    /// Current time as unix seconds (UTC). Treats the RTC as UTC.
    pub fn get_unix_time(&mut self) -> Result<i64> {
        let mut r = [0u8; 7];
        self.read(0x02, &mut r)?;
        let sec = bcd2bin(r[0] & 0x7F) as i64;
        let min = bcd2bin(r[1] & 0x7F) as i64;
        let hour = bcd2bin(r[2] & 0x3F) as i64;
        let day = bcd2bin(r[3] & 0x3F) as i64;
        let month = bcd2bin(r[5] & 0x1F) as i64;
        let century = r[5] & 0x80 != 0; // PCF8563: C=1 => 19xx, C=0 => 20xx
        let year = if century { 1900 } else { 2000 } + bcd2bin(r[6]) as i64;
        Ok(days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec)
    }

    pub fn set_unix_time(&mut self, t: i64) -> Result<()> {
        let days = t.div_euclid(86400);
        let rem = t.rem_euclid(86400);
        let (y, m, d) = civil_from_days(days);
        let wd = (days + 4).rem_euclid(7) as u8; // 1970-01-01 was a Thursday (4)
        let century = if y >= 2000 { 0 } else { 0x80 };
        let regs = [
            bin2bcd((rem % 60) as u8),
            bin2bcd(((rem / 60) % 60) as u8),
            bin2bcd((rem / 3600) as u8),
            bin2bcd(d as u8),
            wd,
            bin2bcd(m as u8) | century,
            bin2bcd((y.rem_euclid(100)) as u8),
        ];
        self.write(0x02, &regs)
    }

    /// Arm the countdown timer to fire after `secs` (1..=255 s at 1 Hz, or minutes up to 255
    /// when `secs > 255`, rounded up). Sets TIE so INT asserts when it expires.
    pub fn set_timer(&mut self, secs: u32) -> Result<()> {
        let (count, clk) = if secs <= 255 {
            (secs.max(1) as u8, 0b10u8) // 1 Hz
        } else {
            (secs.div_ceil(60).min(255) as u8, 0b11u8) // 1/60 Hz
        };
        self.write(0x0E, &[0x00])?; // stop
        self.write(0x0F, &[count])?;
        self.write(0x0E, &[0x80 | clk])?;
        let mut c2 = [0u8; 1];
        self.read(0x01, &mut c2)?;
        self.write(0x01, &[(c2[0] & !0x04) | 0x01])?; // clear TF, enable TIE
        Ok(())
    }

    /// Arm a daily-style alarm at hour:minute (UTC). Sets AIE.
    pub fn set_alarm(&mut self, hour: u8, minute: u8) -> Result<()> {
        self.write(0x09, &[bin2bcd(minute), bin2bcd(hour), 0x80, 0x80])?;
        let mut c2 = [0u8; 1];
        self.read(0x01, &mut c2)?;
        self.write(0x01, &[(c2[0] & !0x08) | 0x02])?; // clear AF, enable AIE
        Ok(())
    }

    /// Returns (timer_fired, alarm_fired) and clears both flags.
    pub fn take_irq_flags(&mut self) -> Result<(bool, bool)> {
        let mut c2 = [0u8; 1];
        self.read(0x01, &mut c2)?;
        self.write(0x01, &[c2[0] & !0x0C])?;
        Ok((c2[0] & 0x04 != 0, c2[0] & 0x08 != 0))
    }

    /// Disable timer and alarm interrupts.
    pub fn disable_irqs(&mut self) -> Result<()> {
        self.write(0x0E, &[0x00])?;
        self.write(0x01, &[0x00])?;
        self.write(0x09, &[0x80, 0x80, 0x80, 0x80])
    }
}

// Howard Hinnant's civil date algorithms.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
