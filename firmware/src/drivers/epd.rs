//! ED047TC1 e-ink driver for the Paper S3.
//!
//! Approach chosen: the **epdiy** C library (registry component `vroland/epdiy` 2.1.3, LCD_CAM/i80
//! backend for ESP32-S3) plus a small local component `components/prism_epd` that provides the
//! Paper S3 `EpdBoardDefinition` (pins + OE/PWR sequencing ported from M5GFX `Bus_EPD`) and a flat C
//! API. epdiy gives us the waveform tables, temperature-ranged phases, line queue and differential
//! updates, which is a large amount of tuned code we would otherwise rewrite.
//!
//! Framebuffer: epdiy's 4 bpp buffer (2 px/byte, high nibble = left pixel, 0 = black, 15 = white),
//! 960x540 native, allocated in PSRAM. The `DrawTarget` presents a portrait 540x960 surface and
//! rotates into the native buffer (see `Rotation`).
use core::convert::Infallible;

use embedded_graphics::{
    pixelcolor::{Gray4, GrayColor},
    prelude::*,
    primitives::Rectangle,
};
use esp_idf_sys as sys;

use crate::board::{PANEL_H, PANEL_W};

/// Refresh strategy. (`prism-ui` does not define one yet; if it adds `RefreshMode`, re-export that
/// type here instead.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshMode {
    /// GC16: full-grey, flashing, clears ghosting. Use on screen changes / before power-off.
    Full,
    /// GL16 partial: greyscale-safe region update (dims, fills, key highlights).
    Partial,
    /// DU: fastest, black/white-only region update (PIN dots). Not escalated to Full.
    Fast,
    /// GL16: non-flashing grey refresh, for text.
    Text,
}

/// Logical orientation relative to the native 960x540 panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rotation {
    /// 960x540, identity.
    Landscape,
    /// 540x960 (default). logical (x, y) -> native (y, 539 - x). Which of the two portrait
    /// directions matches the case orientation (USB port down) must be checked on hardware.
    Portrait,
}

pub trait EinkDisplay: DrawTarget<Color = Gray4> {
    /// Push the framebuffer to the panel. `area` is in logical coordinates (None = whole screen).
    fn refresh(&mut self, mode: RefreshMode, area: Option<Rectangle>);
    /// Cut panel power (image stays).
    fn power_off_panel(&mut self);
}

pub struct Epd {
    fb: *mut u8,
    rotation: Rotation,
    temperature_c: i32,
    partials_since_full: u32,
    pm: RenderPmLock,
}

/// Power-management locks held while epdiy renders: it computes every panel line in real time,
/// and with DFS (80..240 MHz) / automatic light sleep active it falls behind near the end of
/// each frame, which shows up as striped/smeared pixels in the last panel rows (seen on hardware).
struct RenderPmLock {
    cpu_max: sys::esp_pm_lock_handle_t,
    no_sleep: sys::esp_pm_lock_handle_t,
}

impl RenderPmLock {
    fn new() -> Self {
        let mut cpu_max: sys::esp_pm_lock_handle_t = core::ptr::null_mut();
        let mut no_sleep: sys::esp_pm_lock_handle_t = core::ptr::null_mut();
        unsafe {
            // Fails with ESP_ERR_NOT_SUPPORTED if PM is disabled; the handles then stay null.
            sys::esp_pm_lock_create(sys::esp_pm_lock_type_t_ESP_PM_CPU_FREQ_MAX, 0, c"epd_cpu".as_ptr(), &mut cpu_max);
            sys::esp_pm_lock_create(sys::esp_pm_lock_type_t_ESP_PM_NO_LIGHT_SLEEP, 0, c"epd_awake".as_ptr(), &mut no_sleep);
        }
        Self { cpu_max, no_sleep }
    }

    /// Run `f` with the CPU at max frequency and light sleep blocked.
    fn hold<R>(&self, f: impl FnOnce() -> R) -> R {
        unsafe {
            if !self.cpu_max.is_null() {
                sys::esp_pm_lock_acquire(self.cpu_max);
            }
            if !self.no_sleep.is_null() {
                sys::esp_pm_lock_acquire(self.no_sleep);
            }
        }
        let r = f();
        unsafe {
            if !self.no_sleep.is_null() {
                sys::esp_pm_lock_release(self.no_sleep);
            }
            if !self.cpu_max.is_null() {
                sys::esp_pm_lock_release(self.cpu_max);
            }
        }
        r
    }
}

// The framebuffer is owned by epdiy for the program lifetime; Epd is the single accessor.
unsafe impl Send for Epd {}

/// Policy from ARCHITECTURE 7.2: force a full refresh after this many partial ones.
pub const MAX_PARTIALS_BEFORE_FULL: u32 = 8;

/// Number of epdiy clear sequences (3 dark/white cycles each) run at boot.
pub const BOOT_CLEAR_PASSES: i32 = 1;

const STRIDE: usize = (PANEL_W / 2) as usize;

impl Epd {
    /// Initialise epdiy (allocates framebuffers in PSRAM, so PSRAM must be up). Call once.
    pub fn new() -> anyhow::Result<Self> {
        let rc = unsafe { sys::prism_epd_init() };
        anyhow::ensure!(rc == 0, "prism_epd_init failed: {rc}");
        let fb = unsafe { sys::prism_epd_framebuffer() };
        anyhow::ensure!(!fb.is_null(), "epdiy framebuffer allocation failed");
        let mut epd = Self {
            fb,
            rotation: Rotation::Portrait,
            temperature_c: 25,
            partials_since_full: 0,
            pm: RenderPmLock::new(),
        };
        epd.fill_white();
        Ok(epd)
    }

    pub fn set_rotation(&mut self, r: Rotation) {
        self.rotation = r;
    }

    pub fn rotation(&self) -> Rotation {
        self.rotation
    }

    /// Ambient temperature used to select waveform phases (no sensor on the board; default 25 C).
    pub fn set_temperature(&mut self, celsius: i32) {
        self.temperature_c = celsius;
    }

    pub fn fill_white(&mut self) {
        self.buf().fill(0xFF);
    }

    /// Flash to white to remove ghosting; leaves the buffer white.
    pub fn clear_panel(&mut self) {
        self.pm.hold(|| unsafe { sys::prism_epd_clear() });
        self.fill_white();
        self.partials_since_full = 0;
    }

    /// Full wipe at boot: the panel retains the previous image (e.g. the lock screen) across
    /// power-off, possibly for days. Drives every pixel through `BOOT_CLEAR_PASSES` dark/white
    /// clear sequences and resets epdiy's buffers to white so no previous content survives.
    pub fn boot_clear(&mut self) {
        self.pm.hold(|| unsafe { sys::prism_epd_boot_clear(BOOT_CLEAR_PASSES) });
        self.fill_white();
        self.partials_since_full = 0;
    }

    fn buf(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.fb, STRIDE * PANEL_H as usize) }
    }

    fn set_native(&mut self, px: u32, py: u32, luma: u8) {
        let idx = py as usize * STRIDE + (px as usize >> 1);
        let b = &mut self.buf()[idx];
        if px & 1 == 0 {
            *b = (*b & 0x0F) | (luma << 4);
        } else {
            *b = (*b & 0xF0) | luma;
        }
    }

    /// Logical rectangle -> native rectangle (x even-aligned), clipped to the panel.
    fn to_native(&self, r: Rectangle) -> Option<Rectangle> {
        let size = r.size;
        let (x, y) = (r.top_left.x, r.top_left.y);
        let (w, h) = (size.width as i32, size.height as i32);
        let (nx, ny, nw, nh) = match self.rotation {
            Rotation::Landscape => (x, y, w, h),
            Rotation::Portrait => (y, PANEL_H as i32 - (x + w), h, w),
        };
        let x0 = (nx.max(0)) & !1;
        let y0 = ny.max(0);
        let x1 = (((nx + nw).min(PANEL_W as i32)) + 1) & !1;
        let y1 = (ny + nh).min(PANEL_H as i32);
        if x1 <= x0 || y1 <= y0 {
            return None;
        }
        Some(Rectangle::new(
            Point::new(x0, y0),
            Size::new((x1 - x0) as u32, (y1 - y0) as u32),
        ))
    }
}

impl OriginDimensions for Epd {
    fn size(&self) -> Size {
        match self.rotation {
            Rotation::Landscape => Size::new(PANEL_W, PANEL_H),
            Rotation::Portrait => Size::new(PANEL_H, PANEL_W),
        }
    }
}

impl DrawTarget for Epd {
    type Color = Gray4;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        let size = self.size();
        for Pixel(p, c) in pixels {
            if p.x < 0 || p.y < 0 || p.x >= size.width as i32 || p.y >= size.height as i32 {
                continue;
            }
            let (px, py) = match self.rotation {
                Rotation::Landscape => (p.x as u32, p.y as u32),
                Rotation::Portrait => (p.y as u32, PANEL_H - 1 - p.x as u32),
            };
            self.set_native(px, py, c.luma());
        }
        Ok(())
    }
}

impl EinkDisplay for Epd {
    fn refresh(&mut self, mode: RefreshMode, area: Option<Rectangle>) {
        let mut mode = mode;
        if mode == RefreshMode::Partial {
            self.partials_since_full += 1;
            if self.partials_since_full > MAX_PARTIALS_BEFORE_FULL {
                mode = RefreshMode::Full;
            }
        }
        // A full-screen GC16 resets the counter; also never restrict a Full refresh to an area.
        let area = if mode == RefreshMode::Full { None } else { area.and_then(|a| self.to_native(a)) };
        if mode == RefreshMode::Full {
            self.partials_since_full = 0;
        }
        let m = match mode {
            RefreshMode::Full => sys::PRISM_EPD_MODE_GC16,
            // Not DU: DU only drives pure black/white, so grey UI elements (dim text, fills)
            // updated with it come out garbled. GL16 handles greys, at ~2x DU's time.
            RefreshMode::Partial => sys::PRISM_EPD_MODE_GL16,
            RefreshMode::Fast => sys::PRISM_EPD_MODE_DU,
            RefreshMode::Text => sys::PRISM_EPD_MODE_GL16,
        } as i32;
        let (x, y, w, h) = match area {
            Some(r) => (r.top_left.x, r.top_left.y, r.size.width as i32, r.size.height as i32),
            None => (0, 0, 0, 0),
        };
        let t = self.temperature_c;
        let err = self.pm.hold(|| unsafe { sys::prism_epd_refresh(m, x, y, w, h, t) });
        if err != 0 {
            log::warn!("epd refresh returned error mask {err:#x}");
        }
    }

    fn power_off_panel(&mut self) {
        unsafe { sys::prism_epd_power_off() };
    }
}
