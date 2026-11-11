// Flat C API over epdiy for the M5Stack Paper S3 (ED047TC1, 960x540, 4bpp).
// Deliberately self-contained (no epdiy headers) so bindgen can consume it.
#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRISM_EPD_WIDTH 960   // native (landscape) panel width in pixels
#define PRISM_EPD_HEIGHT 540  // native (landscape) panel height in pixels
#define PRISM_EPD_FB_STRIDE (PRISM_EPD_WIDTH / 2)  // bytes per row, 2 px/byte, high nibble = left px

// Update modes (map to epdiy MODE_GC16 / MODE_DU / MODE_GL16).
#define PRISM_EPD_MODE_GC16 0
#define PRISM_EPD_MODE_DU 1
#define PRISM_EPD_MODE_GL16 2

// Initialise epdiy with the Paper S3 board definition. Returns 0 on success.
int prism_epd_init(void);

// 4bpp framebuffer in PSRAM (owned by epdiy), PRISM_EPD_FB_STRIDE * PRISM_EPD_HEIGHT bytes.
// 0x0 = black, 0xF = white. Native landscape orientation. NULL before init.
uint8_t* prism_epd_framebuffer(void);

// Power the panel, update the given native-orientation area (w/h <= 0: whole screen), power it down.
// Blocking. Returns 0 on success, otherwise an epdiy EpdDrawError bit mask.
int prism_epd_refresh(int mode, int x, int y, int w, int h, int temperature_c);

// Flash the panel to clean white (removes ghosting) and leave the framebuffer white.
void prism_epd_clear(void);

// Cut panel power rails (idempotent). The image is retained by the e-paper.
/// Boot-time wipe: resets epdiy's buffers to white and runs `passes` full clear
/// sequences (3 dark/white cycles each) regardless of what the panel currently shows.
void prism_epd_boot_clear(int passes);

void prism_epd_power_off(void);

#ifdef __cplusplus
}
#endif
