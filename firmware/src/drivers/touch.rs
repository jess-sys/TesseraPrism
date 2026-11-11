//! GT911 capacitive touch controller over the shared internal I2C bus.
//!
//! Registers (Goodix GT911 programming guide): 0x8140 product ID ("911"), 0x814E status
//! (bit7 = buffer ready, bits0..3 = point count), 0x814F.. point records (8 bytes each:
//! track id, x lo, x hi, y lo, y hi, size lo, size hi, reserved). The status byte MUST be
//! written back to 0 after each read or the controller stops reporting. INT is pulled low
//! (falling edge) when new data is ready.
use anyhow::{bail, Context, Result};
use esp_idf_hal::delay::TickType;
use esp_idf_sys as sys;

use crate::board::{self, SharedI2c};

const REG_PRODUCT_ID: u16 = 0x8140;
const REG_STATUS: u16 = 0x814E;
/// First point record = track id at 0x814F, then x lo/hi, y lo/hi, size lo/hi, reserved
/// (8 bytes per point). Reading from 0x8150 shifts every field by one byte (seen on hardware:
/// x=0xD301 for a real y of 0x02D3).
const REG_POINTS: u16 = 0x814F;
pub const MAX_POINTS: usize = 5;

/// One touch point in raw panel coordinates (portrait 540x960, as reported by the controller;
/// M5GFX applies `rotation_offset = 1` on top for its own rotations. No transform is done here).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TouchPoint {
    pub id: u8,
    pub x: u16,
    pub y: u16,
    pub size: u16,
}

pub struct Gt911 {
    i2c: SharedI2c,
    addr: u8,
}

fn timeout() -> u32 {
    TickType::new_millis(50).ticks()
}

impl Gt911 {
    /// Probe 0x5D then 0x14 and configure the INT pin as input.
    pub fn new(i2c: SharedI2c) -> Result<Self> {
        unsafe {
            let cfg = sys::gpio_config_t {
                pin_bit_mask: 1u64 << board::TOUCH_INT,
                mode: sys::gpio_mode_t_GPIO_MODE_INPUT,
                pull_up_en: sys::gpio_pullup_t_GPIO_PULLUP_ENABLE,
                pull_down_en: sys::gpio_pulldown_t_GPIO_PULLDOWN_DISABLE,
                // No ISR: GT911 INT may only pulse briefly, so the UI also polls the status
                // register every 150 ms (see ui_task::TOUCH_FALLBACK_POLL).
                intr_type: sys::gpio_int_type_t_GPIO_INTR_DISABLE,
            };
            sys::esp!(sys::gpio_config(&cfg))?;
        }
        for addr in [board::TOUCH_ADDR_PRIMARY, board::TOUCH_ADDR_ALT] {
            let mut dev = Self { i2c: i2c.clone(), addr };
            let mut id = [0u8; 4];
            if dev.read_reg(REG_PRODUCT_ID, &mut id).is_ok() && &id[..3] == b"911" {
                log::info!("GT911 found at {addr:#x}, product id {:?}", core::str::from_utf8(&id));
                return Ok(dev);
            }
        }
        bail!("GT911 not found on the internal I2C bus")
    }

    fn read_reg(&mut self, reg: u16, buf: &mut [u8]) -> Result<()> {
        let mut bus = self.i2c.lock().unwrap();
        bus.write_read(self.addr, &reg.to_be_bytes(), buf, timeout())
            .context("GT911 read")?;
        Ok(())
    }

    fn write_reg(&mut self, reg: u16, data: &[u8]) -> Result<()> {
        let mut bus = self.i2c.lock().unwrap();
        let mut msg = Vec::with_capacity(2 + data.len());
        msg.extend_from_slice(&reg.to_be_bytes());
        msg.extend_from_slice(data);
        bus.write(self.addr, &msg, timeout()).context("GT911 write")?;
        Ok(())
    }

    /// True while INT is asserted (low) — new data may be available.
    pub fn data_pending(&self) -> bool {
        unsafe { sys::gpio_get_level(board::TOUCH_INT) == 0 }
    }

    /// Read the current touch points (empty if none / not ready). Clears the controller's
    /// ready flag.
    /// `Ok(None)`: no new report since the last read (NOT "no finger" — the GT911 only sets the
    /// ready bit when a scan produced new data). `Ok(Some(vec![]))`: a report with no touch point,
    /// i.e. the finger was lifted.
    pub fn read_points(&mut self) -> Result<Option<Vec<TouchPoint>>> {
        let mut st = [0u8; 1];
        self.read_reg(REG_STATUS, &mut st)?;
        if st[0] & 0x80 == 0 {
            return Ok(None);
        }
        let n = ((st[0] & 0x0F) as usize).min(MAX_POINTS);
        let mut pts = Vec::with_capacity(n);
        if n > 0 {
            let mut raw = [0u8; 8 * MAX_POINTS];
            self.read_reg(REG_POINTS, &mut raw[..8 * n])?;
            for i in 0..n {
                let r = &raw[i * 8..i * 8 + 8];
                pts.push(TouchPoint {
                    id: r[0],
                    x: u16::from_le_bytes([r[1], r[2]]),
                    y: u16::from_le_bytes([r[3], r[4]]),
                    size: u16::from_le_bytes([r[5], r[6]]),
                });
            }
        }
        self.write_reg(REG_STATUS, &[0])?;
        Ok(Some(pts))
    }
}
