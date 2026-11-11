//! M5Stack Paper S3 board definition. ALL pin numbers live here.
//!
//! Verified against the vendor's shipping firmware stack (no hardware in the loop yet):
//!  * M5GFX board data  `src/board_detect/m5/generated/esp32s3_board_data.hpp` (namespaces
//!    `wiring::papers3`, `specs::papers3`) and `esp32s3_construct.inl` (`construct_papers3`):
//!    https://github.com/m5stack/M5GFX/blob/master/src/board_detect/m5/generated/esp32s3_board_data.hpp
//!  * M5GFX EPD bus power sequence `src/lgfx/v1/platforms/esp32/Bus_EPD.inl`:
//!    https://github.com/m5stack/M5GFX/blob/master/src/lgfx/v1/platforms/esp32/Bus_EPD.inl
//!  * M5Unified `src/M5Unified.inl` (pin tables: internal I2C, SD SPI, power-hold, buzzer) and
//!    `src/utility/Power_Class.inl` (battery ADC, CHG_STAT, power-off pulse, wake pin):
//!    https://github.com/m5stack/M5Unified/blob/master/src/utility/Power_Class.inl
//!  * M5Stack docs pin map (EPD data lines, SD, USB_DET): https://docs.m5stack.com/en/core/PaperS3
//!
//! Discrepancy: the docs page labels EPD "PWR" as G45; M5GFX has OE = G45 and PWR = G46. The panel
//! power-on sequence drives both (OE first, then PWR), so we follow M5GFX.

/// Native panel size (landscape). The UI is portrait 540x960.
pub const PANEL_W: u32 = 960;
pub const PANEL_H: u32 = 540;
pub const UI_W: u32 = 540;
pub const UI_H: u32 = 960;

// ---- E-ink ED047TC1: 8-bit parallel bus on the LCD_CAM peripheral (16 MHz in M5GFX) -------------
/// Data lines D0..D7.
pub const EPD_DATA: [i32; 8] = [6, 14, 7, 12, 9, 11, 8, 10];
pub const EPD_CL: i32 = 16; // pixel clock (XCL/CKH)
pub const EPD_LE: i32 = 15; // latch enable (XLE)
pub const EPD_SPH: i32 = 13; // horizontal start pulse (XSTL)
pub const EPD_SPV: i32 = 17; // vertical start pulse
pub const EPD_CKV: i32 = 18; // vertical clock
pub const EPD_OE: i32 = 45; // output enable
pub const EPD_PWR: i32 = 46; // panel supply enable
// (mirrored in components/prism_epd/prism_epd_board.c)

// ---- Internal I2C bus (I2C port 1, 400 kHz): GT911 + BM8563 (+ BMI270 IMU @0x68, unused) --------
pub const I2C_SDA: i32 = 41;
pub const I2C_SCL: i32 = 42;
pub const I2C_FREQ_HZ: u32 = 400_000;

/// GT911 touch. Address is 0x5D or 0x14 depending on the INT level at reset; M5GFX probes both.
pub const TOUCH_INT: i32 = 48; // NOT an RTC IO: cannot wake from deep sleep, only light sleep
pub const TOUCH_ADDR_PRIMARY: u8 = 0x5D;
pub const TOUCH_ADDR_ALT: u8 = 0x14;
/// GT911 raw ranges (M5GFX specs::papers3::touch): x 0..=539, y 0..=959 (portrait), rotation offset 1.
pub const TOUCH_X_MAX: u16 = 539;
pub const TOUCH_Y_MAX: u16 = 959;

/// BM8563 RTC. Its INT line is NOT routed to any MCU GPIO in M5Unified (no `_rtcIntPin` for
/// PaperS3); it feeds the power-latch circuit, i.e. an alarm can power the device on after a
/// power-off pulse. Unverified without hardware.
pub const RTC_ADDR: u8 = 0x51;

// ---- Power -------------------------------------------------------------------------------------
/// Battery divider output, ADC1 channel 2 (GPIO3); real voltage = measured * 2.0 (`_adc_ratio`).
pub const BAT_ADC_GPIO: i32 = 3;
pub const BAT_ADC_RATIO: f32 = 2.0;
/// Charger STAT, active low (`gpio_in == false` => charging).
pub const CHG_STAT: i32 = 4;
/// USB VBUS detect (docs pin map "USB_DET"); high = USB present. Not read by M5Unified.
pub const USB_DET: i32 = 5;
/// Power latch / off request. Held LOW in normal operation; M5Unified powers off by pulsing
/// low/high 5x with 50 ms steps (`Power_Class::_powerOff`). The pulse cannot cut power while USB
/// is connected, so fall back to sleep.
pub const POWER_HOLD: i32 = 44; // shared with UART0 RX (console RX unused)

// ---- Misc --------------------------------------------------------------------------------------
pub const BUZZER: i32 = 21; // passive piezo, drive with PWM (M5Unified: speaker pin_data_out, buzzer=true)
/// GPIO0 drives the status LED on the Paper S3 (M5Unified Power_Class: `cfg.pin_bl = GPIO_NUM_0`).
/// It is NOT a button: the board has no MCU-readable button; the side button is a hardware power
/// switch (power-on only). Never read it or use it as a wake source.
pub const STATUS_LED: i32 = 0;
pub const GROVE_G1: i32 = 1; // Grove port (HY2.0-4P) G1/G2
pub const GROVE_G2: i32 = 2;

/// microSD over SPI (M5Unified `sd` pin table for PaperS3).
pub const SD_SCK: i32 = 39;
pub const SD_MOSI: i32 = 38;
pub const SD_MISO: i32 = 40;
pub const SD_CS: i32 = 47;

/// Battery mV at 0% / 100% used by M5Unified (3300 .. 4150); we use a LiPo curve, see `power.rs`.
pub const BAT_EMPTY_MV: u32 = 3300;
pub const BAT_FULL_MV: u32 = 4150;

use std::sync::{Arc, Mutex};

use esp_idf_hal::i2c::I2cDriver;

/// The single internal I2C bus, shared by touch and RTC.
pub type SharedI2c = Arc<Mutex<I2cDriver<'static>>>;
