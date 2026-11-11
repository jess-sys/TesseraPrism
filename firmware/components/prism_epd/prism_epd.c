#include "prism_epd.h"

#include <stddef.h>
#include <string.h>

#include "epdiy.h"

extern const EpdBoardDefinition prism_board_papers3;
extern const EpdDisplay_t ED047TC1;

static EpdiyHighlevelState hl;
static bool inited = false;
static bool powered = false;

int prism_epd_init(void) {
    if (inited) return 0;
    epd_init(&prism_board_papers3, &ED047TC1, EPD_LUT_64K);
    // Native landscape: rotation is handled in Rust (Epd DrawTarget).
    epd_set_rotation(EPD_ROT_LANDSCAPE);
    hl = epd_hl_init(EPD_BUILTIN_WAVEFORM);
    inited = true;
    return 0;
}

uint8_t* prism_epd_framebuffer(void) {
    return inited ? epd_hl_get_framebuffer(&hl) : NULL;
}

int prism_epd_refresh(int mode, int x, int y, int w, int h, int temperature_c) {
    if (!inited) return -1;
    enum EpdDrawMode m = MODE_GC16;
    if (mode == PRISM_EPD_MODE_DU) m = MODE_DU;
    else if (mode == PRISM_EPD_MODE_GL16) m = MODE_GL16;

    epd_poweron();
    powered = true;
    enum EpdDrawError err;
    if (w <= 0 || h <= 0) {
        err = epd_hl_update_screen(&hl, m, temperature_c);
    } else {
        EpdRect area = {.x = x, .y = y, .width = w, .height = h};
        err = epd_hl_update_area(&hl, m, temperature_c, area);
    }
    epd_poweroff();
    powered = false;
    return (int)err;
}

void prism_epd_clear(void) {
    if (!inited) return;
    epd_poweron();
    epd_fullclear(&hl, 25);
    epd_poweroff();
    powered = false;
}

void prism_epd_boot_clear(int passes) {
    if (!inited) return;
    if (passes < 1) passes = 1;
    epd_poweron();
    // The panel still shows whatever was on it at power-off (lock screen), but epdiy's
    // high-level state assumes white: reset both front/back buffers to white so later
    // differential updates match reality, then drive every pixel dark<->white
    // unconditionally (independent of the buffers) to erase the old image and ghosting.
    epd_hl_set_all_white(&hl);
    for (int i = 0; i < passes; i++) {
        epd_clear(); // 3 dark/white cycles over the full screen
    }
    epd_poweroff();
    powered = false;
}

void prism_epd_power_off(void) {
    if (!inited) return;
    if (powered) {
        epd_poweroff();
        powered = false;
    }
}
