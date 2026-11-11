//! Power: battery, charge/USB detect, power-off, sleep modes, PM config, buzzer.
//!
//! Hardware facts (see `board.rs` for sources):
//!  * Battery is read by ADC1 on GPIO3 through a 1:2 divider.
//!  * CHG_STAT (GPIO4) is low while charging; USB_DET (GPIO5) is high with VBUS present.
//!  * There is no PMIC. Power-off is a pulse train on GPIO44 (low/high x5, 50 ms steps) into the
//!    board's power-latch circuit. While USB is attached the board stays powered, so after the
//!    pulses we fall back to deep sleep.
//!  * Touch INT (GPIO48) is not an RTC IO: it can wake **light** sleep only. Deep sleep can be
//!    woken by the BOOT button (GPIO0, ext0) and the RTC timer.
use core::time::Duration;

use anyhow::{Result};
use esp_idf_sys as sys;

use crate::board;

// LiPo open-circuit voltage (mV) -> percent, piecewise linear.
const LIPO_CURVE: [(u32, u8); 12] = [
    (3270, 0),
    (3610, 5),
    (3690, 10),
    (3730, 20),
    (3770, 30),
    (3790, 40),
    (3820, 50),
    (3870, 60),
    (3950, 70),
    (4020, 80),
    (4110, 90),
    (4200, 100),
];

/// Convert battery millivolts to 0..=100 %.
pub fn lipo_percent(mv: u32) -> u8 {
    if mv <= LIPO_CURVE[0].0 {
        return 0;
    }
    for w in LIPO_CURVE.windows(2) {
        let ((v0, p0), (v1, p1)) = (w[0], w[1]);
        if mv <= v1 {
            let span = (v1 - v0).max(1);
            return (p0 as u32 + (mv - v0) * (p1 - p0) as u32 / span) as u8;
        }
    }
    100
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeCause {
    PowerOn,
    Timer,
    BootButton,
    Touch,
    Other,
}

pub struct Power {
    adc: sys::adc_oneshot_unit_handle_t,
    cali: Option<sys::adc_cali_handle_t>,
}

// Handles are only used through &self/&mut self from one owner.
unsafe impl Send for Power {}

fn input(gpio: i32, pullup: bool) -> Result<()> {
    let cfg = sys::gpio_config_t {
        pin_bit_mask: 1u64 << gpio,
        mode: sys::gpio_mode_t_GPIO_MODE_INPUT,
        pull_up_en: if pullup {
            sys::gpio_pullup_t_GPIO_PULLUP_ENABLE
        } else {
            sys::gpio_pullup_t_GPIO_PULLUP_DISABLE
        },
        pull_down_en: sys::gpio_pulldown_t_GPIO_PULLDOWN_DISABLE,
        intr_type: sys::gpio_int_type_t_GPIO_INTR_DISABLE,
    };
    sys::esp!(unsafe { sys::gpio_config(&cfg) })?;
    Ok(())
}

fn output(gpio: i32, level: u32) -> Result<()> {
    unsafe {
        sys::esp!(sys::gpio_reset_pin(gpio))?;
        sys::esp!(sys::gpio_set_direction(gpio, sys::gpio_mode_t_GPIO_MODE_OUTPUT))?;
        sys::esp!(sys::gpio_set_level(gpio, level))?;
    }
    Ok(())
}

impl Power {
    /// Release the power-hold line and set up the battery ADC and status inputs.
    pub fn new() -> Result<Self> {
        // Normal operation: hold line low (M5GFX `gpio_power_low`); power-off drives pulses.
        gpio44_hold()?;
        input(board::CHG_STAT, true)?;
        input(board::USB_DET, false)?;

        let mut adc: sys::adc_oneshot_unit_handle_t = core::ptr::null_mut();
        let init = sys::adc_oneshot_unit_init_cfg_t {
            unit_id: sys::adc_unit_t_ADC_UNIT_1,
            ulp_mode: sys::adc_ulp_mode_t_ADC_ULP_MODE_DISABLE,
            ..Default::default()
        };
        sys::esp!(unsafe { sys::adc_oneshot_new_unit(&init, &mut adc) })?;
        let chan = sys::adc_oneshot_chan_cfg_t {
            atten: sys::adc_atten_t_ADC_ATTEN_DB_12,
            bitwidth: sys::adc_bitwidth_t_ADC_BITWIDTH_DEFAULT,
        };
        sys::esp!(unsafe {
            sys::adc_oneshot_config_channel(adc, sys::adc_channel_t_ADC_CHANNEL_2, &chan)
        })?; // GPIO3 = ADC1 channel 2 on ESP32-S3

        let mut cali: sys::adc_cali_handle_t = core::ptr::null_mut();
        let cfg = sys::adc_cali_curve_fitting_config_t {
            unit_id: sys::adc_unit_t_ADC_UNIT_1,
            chan: sys::adc_channel_t_ADC_CHANNEL_2,
            atten: sys::adc_atten_t_ADC_ATTEN_DB_12,
            bitwidth: sys::adc_bitwidth_t_ADC_BITWIDTH_DEFAULT,
        };
        let cali = if unsafe { sys::adc_cali_create_scheme_curve_fitting(&cfg, &mut cali) } == 0 {
            Some(cali)
        } else {
            log::warn!("ADC calibration unavailable, using uncalibrated scaling");
            None
        };
        Ok(Self { adc, cali })
    }

    /// Battery voltage in millivolts (median of 15 samples, divider ratio applied).
    pub fn battery_mv(&mut self) -> Result<u32> {
        let mut s = [0i32; 15];
        for v in s.iter_mut() {
            let mut raw = 0i32;
            sys::esp!(unsafe {
                sys::adc_oneshot_read(self.adc, sys::adc_channel_t_ADC_CHANNEL_2, &mut raw)
            })?;
            *v = match self.cali {
                Some(c) => {
                    let mut mv = 0i32;
                    sys::esp!(unsafe { sys::adc_cali_raw_to_voltage(c, raw, &mut mv) })?;
                    mv
                }
                None => raw * 3100 / 4095, // rough DB_12 full-scale
            };
        }
        s.sort_unstable();
        Ok((s[s.len() / 2] as f32 * board::BAT_ADC_RATIO) as u32)
    }

    pub fn battery_percent(&mut self) -> Result<u8> {
        Ok(lipo_percent(self.battery_mv()?))
    }

    /// Charger STAT pin is active low.
    pub fn is_charging(&self) -> bool {
        unsafe { sys::gpio_get_level(board::CHG_STAT) == 0 }
    }

    pub fn usb_present(&self) -> bool {
        unsafe { sys::gpio_get_level(board::USB_DET) != 0 }
    }

    pub fn wake_cause(&self) -> WakeCause {
        match unsafe { sys::esp_sleep_get_wakeup_cause() } {
            sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TIMER => WakeCause::Timer,
            sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT0
            | sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT1 => WakeCause::BootButton,
            sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_GPIO => WakeCause::Touch,
            sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UNDEFINED => WakeCause::PowerOn,
            _ => WakeCause::Other,
        }
    }

    /// Cut power. The caller must have already drawn the final screen and powered the panel down.
    /// Pulses the power-latch line; if the board stays alive (USB attached) fall back to deep
    /// sleep woken by the BOOT button. Never returns.
    /// GPIO44 power-off pulse train (M5Unified `_powerOff`). Returns if power was not cut
    /// (e.g. USB attached).
    /// Release GPIO44 (high impedance, no pulls), as it is under M5Unified once the chip sleeps.
    /// Keeping it driven/held through deep sleep made the board power-cycle (diagnostics:
    /// "entering deep sleep" followed by a power-on reset).
    pub fn release_power_line(&mut self) {
        unsafe { sys::gpio_hold_dis(board::POWER_HOLD) };
        let _ = input(board::POWER_HOLD, false);
    }

    pub fn send_off_pulses(&mut self) {
        let _ = output(board::POWER_HOLD, 0);
        for _ in 0..5 {
            unsafe {
                sys::gpio_set_level(board::POWER_HOLD, 0);
                sys::vTaskDelay(ms_to_ticks(50));
                sys::gpio_set_level(board::POWER_HOLD, 1);
                sys::vTaskDelay(ms_to_ticks(50));
            }
        }
    }

    pub fn power_off(&mut self) -> ! {
        if cfg!(feature = "jtag-console") && !cfg!(feature = "jtag-real-off") {
            // Diagnostic build: keep the chip (and the USB log console) alive.
            log::warn!("[jtag-console] power_off requested: NOT powering off (diagnostic build)");
            loop {
                unsafe { sys::vTaskDelay(ms_to_ticks(1000)) };
            }
        }
        let _ = output(board::POWER_HOLD, 0);
        for _ in 0..5 {
            unsafe {
                sys::gpio_set_level(board::POWER_HOLD, 0);
                sys::vTaskDelay(ms_to_ticks(50));
                sys::gpio_set_level(board::POWER_HOLD, 1);
                sys::vTaskDelay(ms_to_ticks(50));
            }
        }
        log::warn!("still powered after off pulses (USB attached?): entering deep sleep");
        // USB keeps the board powered: sleep with NO wake source, so only a power cycle (unplug /
        // replug, or the side power button) brings it back — never a touch or a GPIO glitch.
        self.sleep_until_power_cycle()
    }

    /// Deep sleep with no wake source at all: the chip stays off until the board is power cycled.
    /// Panel rails are held low while sleeping.
    pub fn sleep_until_power_cycle(&mut self) -> ! {
        unsafe {
            for pin in [board::EPD_OE, board::EPD_PWR] {
                sys::gpio_set_level(pin, 0);
                sys::gpio_hold_en(pin);
            }
            sys::gpio_deep_sleep_hold_en();
            // In deep sleep the USB PHY falls back to the built-in USB-Serial-JTAG; the host then
            // enumerates it and toggles DTR/RTS, which resets the chip (USB_UART_CHIP_RESET) — the
            // "Lock reboots to the PIN pad" bug. Ignore USB-triggered resets and disconnect the USB
            // pads so the host sees nothing. RTC registers are cleared by the next power cycle.
            let reg = sys::RTC_CNTL_USB_CONF_REG as *mut u32;
            let mut v = core::ptr::read_volatile(reg);
            v |= 1 << sys::RTC_CNTL_USB_RESET_DISABLE_S;
            v |= 1 << sys::RTC_CNTL_USB_PAD_ENABLE_OVERRIDE_S;
            v &= !(1 << sys::RTC_CNTL_USB_PAD_ENABLE_S);
            core::ptr::write_volatile(reg, v);
            sys::esp_sleep_disable_wakeup_source(sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ALL);
            sys::esp_deep_sleep_start();
        }
    }

    /// Manual light sleep (RAM kept), woken by touch INT (low level) and/or a timeout.
    pub fn light_sleep(&mut self, timeout: Option<Duration>, touch: bool) -> Result<()> {
        unsafe {
            if let Some(t) = timeout {
                sys::esp!(sys::esp_sleep_enable_timer_wakeup(t.as_micros() as u64))?;
            }
            if touch {
                sys::esp!(sys::gpio_wakeup_enable(
                    board::TOUCH_INT,
                    sys::gpio_int_type_t_GPIO_INTR_LOW_LEVEL
                ))?;
                sys::esp!(sys::esp_sleep_enable_gpio_wakeup())?;
            }
            sys::esp!(sys::esp_light_sleep_start())?;
        }
        Ok(())
    }

    /// Enable DFS + automatic light sleep (needs CONFIG_PM_ENABLE and tickless idle, both set in
    /// sdkconfig.defaults). Idle FreeRTOS time then sleeps the CPU, keeping BLE connections alive.
    pub fn configure_auto_light_sleep(enable: bool) -> Result<()> {
        Self::configure_pm(40, enable)
    }

    /// DFS between `min_mhz` and 240 MHz, optionally with automatic light sleep.
    pub fn configure_pm(min_mhz: i32, light_sleep: bool) -> Result<()> {
        let enable = light_sleep;
        let cfg = sys::esp_pm_config_t {
            max_freq_mhz: 240,
            min_freq_mhz: min_mhz,
            light_sleep_enable: enable,
        };
        sys::esp!(unsafe { sys::esp_pm_configure(&cfg as *const _ as *const core::ffi::c_void) })?;
        Ok(())
    }
}

/// Configure GPIO44 as the power-hold output, driven low.
fn gpio44_hold() -> Result<()> {
    output(board::POWER_HOLD, 0)
}

fn ms_to_ticks(ms: u32) -> u32 {
    ms * sys::configTICK_RATE_HZ / 1000
}

/// Piezo buzzer on GPIO21 driven by LEDC (low-speed timer 3 / channel 7, 10-bit).
pub struct Buzzer;

impl Buzzer {
    /// Blocking beep.
    pub fn beep(freq_hz: u32, duration_ms: u32) -> Result<()> {
        unsafe {
            let mut timer: sys::ledc_timer_config_t = core::mem::zeroed();
            timer.speed_mode = sys::ledc_mode_t_LEDC_LOW_SPEED_MODE;
            timer.duty_resolution = sys::ledc_timer_bit_t_LEDC_TIMER_10_BIT;
            timer.timer_num = sys::ledc_timer_t_LEDC_TIMER_3;
            timer.freq_hz = freq_hz;
            timer.clk_cfg = sys::soc_periph_ledc_clk_src_legacy_t_LEDC_AUTO_CLK;
            sys::esp!(sys::ledc_timer_config(&timer))?;
            let mut ch: sys::ledc_channel_config_t = core::mem::zeroed();
            ch.gpio_num = board::BUZZER;
            ch.speed_mode = sys::ledc_mode_t_LEDC_LOW_SPEED_MODE;
            ch.channel = sys::ledc_channel_t_LEDC_CHANNEL_7;
            ch.timer_sel = sys::ledc_timer_t_LEDC_TIMER_3;
            ch.duty = 512; // 50 %
            sys::esp!(sys::ledc_channel_config(&ch))?;
            sys::vTaskDelay(ms_to_ticks(duration_ms).max(1));
            sys::esp!(sys::ledc_stop(
                sys::ledc_mode_t_LEDC_LOW_SPEED_MODE,
                sys::ledc_channel_t_LEDC_CHANNEL_7,
                0
            ))?;
        }
        Ok(())
    }
}
