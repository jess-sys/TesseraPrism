// epdiy board definition for the M5Stack Paper S3.
//
// Pins and power sequencing come from M5GFX (the vendor's shipping display stack):
//   src/board_detect/m5/generated/esp32s3_board_data.hpp  (namespace wiring::papers3, specs::papers3)
//   src/lgfx/v1/platforms/esp32/Bus_EPD.inl               (Bus_EPD::powerControl / init)
//   https://github.com/m5stack/M5GFX
// The panel is driven through the ESP32-S3 LCD peripheral in 8-bit i80 mode (epdiy "lcd" backend),
// with the three panel power-sequencing lines (OE, PWR) as plain GPIOs. There is no TPS65185, no
// I2C expander and no VCOM control on this board (fixed VCOM).
#include <stdint.h>
#include <stdbool.h>

#include <driver/gpio.h>
#include <esp_rom_sys.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "epd_board.h"
#include "epdiy.h"
#include "output_lcd/lcd_driver.h"

#define PAPERS3_D0 GPIO_NUM_6
#define PAPERS3_D1 GPIO_NUM_14
#define PAPERS3_D2 GPIO_NUM_7
#define PAPERS3_D3 GPIO_NUM_12
#define PAPERS3_D4 GPIO_NUM_9
#define PAPERS3_D5 GPIO_NUM_11
#define PAPERS3_D6 GPIO_NUM_8
#define PAPERS3_D7 GPIO_NUM_10
#define PAPERS3_CL GPIO_NUM_16   // XCL / CKH: pixel clock
#define PAPERS3_LE GPIO_NUM_15   // XLE: latch enable
#define PAPERS3_SPH GPIO_NUM_13  // XSTL: horizontal start pulse
#define PAPERS3_SPV GPIO_NUM_17  // vertical start pulse
#define PAPERS3_CKV GPIO_NUM_18  // vertical clock
#define PAPERS3_OE GPIO_NUM_45   // output enable
#define PAPERS3_PWR GPIO_NUM_46  // panel supply enable (M5 docs label G45 "PWR"; M5GFX: OE=45, PWR=46)

static lcd_bus_config_t lcd_config = {
    .clock = PAPERS3_CL,
    .ckv = PAPERS3_CKV,
    .leh = PAPERS3_LE,
    .start_pulse = PAPERS3_SPH,
    .stv = PAPERS3_SPV,
    .data = {PAPERS3_D0, PAPERS3_D1, PAPERS3_D2, PAPERS3_D3, PAPERS3_D4, PAPERS3_D5, PAPERS3_D6,
             PAPERS3_D7},
};

static void out_pin(gpio_num_t pin, int level) {
    gpio_reset_pin(pin);
    gpio_set_direction(pin, GPIO_MODE_OUTPUT);
    gpio_set_level(pin, level);
}

static void board_init(uint32_t epd_row_width, const EpdInitConfig* init_config) {
    (void)epd_row_width;
    (void)init_config;
    out_pin(PAPERS3_OE, 0);
    out_pin(PAPERS3_PWR, 0);

    const EpdDisplay_t* display = epd_get_display();
    LcdEpdConfig_t config = {
        // M5GFX runs this bus at 16 MHz (specs::papers3::bus_speed); stay with the vendor value.
        .pixel_clock = 16 * 1000 * 1000,
        .ckv_high_time = 60,
        .line_front_porch = 4,
        .le_high_time = 4,
        .bus_width = display->bus_width,
        .bus = lcd_config,
    };
    epd_lcd_init(&config, display->width, display->height);
}

static void board_deinit(void) {
    epd_lcd_deinit();
    gpio_set_level(PAPERS3_PWR, 0);
    gpio_set_level(PAPERS3_OE, 0);
}

static void board_set_ctrl(epd_ctrl_state_t* state, const epd_ctrl_state_t* const mask) {
    // STV/STH/LE/CKV are owned by the LCD backend; only OE is a plain GPIO here.
    if (mask->ep_output_enable) {
        gpio_set_level(PAPERS3_OE, state->ep_output_enable ? 1 : 0);
    }
}

// Sequence taken from Bus_EPD::powerControl(true): OE, 100us, PWR, 100us, SPV high.
static void board_poweron(epd_ctrl_state_t* state) {
    state->ep_output_enable = true;
    state->ep_stv = true;
    state->ep_sth = true;
    gpio_set_level(PAPERS3_OE, 1);
    esp_rom_delay_us(100);
    gpio_set_level(PAPERS3_PWR, 1);
    esp_rom_delay_us(100);
    gpio_set_level(PAPERS3_SPV, 1);
    vTaskDelay(pdMS_TO_TICKS(2));
}

// Bus_EPD::powerControl(false): 1 ms, PWR low, 10us, OE low, 100us, SPV low.
static void board_poweroff(epd_ctrl_state_t* state) {
    vTaskDelay(pdMS_TO_TICKS(2));
    gpio_set_level(PAPERS3_PWR, 0);
    esp_rom_delay_us(10);
    gpio_set_level(PAPERS3_OE, 0);
    esp_rom_delay_us(100);
    gpio_set_level(PAPERS3_SPV, 0);
    state->ep_output_enable = false;
    state->ep_stv = false;
    state->ep_sth = false;
}

static float board_temperature(void) {
    return 25.0f;  // no sensor wired to the panel; callers pass a temperature explicitly
}

const EpdBoardDefinition prism_board_papers3 = {
    .init = board_init,
    .deinit = board_deinit,
    .set_ctrl = board_set_ctrl,
    .poweron = board_poweron,
    .poweroff = board_poweroff,
    .get_temperature = board_temperature,
    .set_vcom = NULL,
    .gpio_set_direction = NULL,
    .gpio_read = NULL,
    .gpio_write = NULL,
};
