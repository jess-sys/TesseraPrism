// TinyUSB composite for Prism: CDC-ACM (Prism protocol) + HID FIDO (0xF1D0) + HID boot keyboard.
#include "sdkconfig.h"
#include "prism_usb.h"

#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"
#include "class/hid/hid.h"

static const char *TAG = "prism_usb";
static prism_usb_callbacks_t s_cbs;
static const char *s_strings[7];

enum { ITF_CDC = 0, ITF_CDC_DATA, ITF_HID_FIDO, ITF_HID_KBD, ITF_COUNT };
#define EP_CDC_NOTIF 0x81
#define EP_CDC_OUT 0x02
#define EP_CDC_IN 0x82
#define EP_FIDO_OUT 0x03
#define EP_FIDO_IN 0x83
#define EP_KBD_IN 0x84

static const uint8_t hid_fido_report_desc[] = {
    0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01,        // Usage (CTAPHID)
    0xA1, 0x01,        // Collection (Application)
    0x09, 0x20,        //   Usage (Data In)
    0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
    0x09, 0x21,        //   Usage (Data Out)
    0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
    0xC0};
static const uint8_t hid_kbd_report_desc[] = {TUD_HID_REPORT_DESC_KEYBOARD()};

static const uint8_t s_cfg_desc[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + TUD_HID_INOUT_DESC_LEN + TUD_HID_DESC_LEN, TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_CDC_DESCRIPTOR(ITF_CDC, 4, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
    TUD_HID_INOUT_DESCRIPTOR(ITF_HID_FIDO, 5, HID_ITF_PROTOCOL_NONE, sizeof(hid_fido_report_desc), EP_FIDO_OUT, EP_FIDO_IN, 64, 5),
    TUD_HID_DESCRIPTOR(ITF_HID_KBD, 6, HID_ITF_PROTOCOL_KEYBOARD, sizeof(hid_kbd_report_desc), EP_KBD_IN, 8, 10),
};

static const tusb_desc_device_t s_dev_desc = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x303A,
    .idProduct = 0x8360,
    .bcdDevice = 0x0100,
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1,
};

// ---- TinyUSB callbacks -------------------------------------------------------------------------

void tud_mount_cb(void) {
    if (s_cbs.on_mount) s_cbs.on_mount(true);
}
void tud_umount_cb(void) {
    if (s_cbs.on_mount) s_cbs.on_mount(false);
}
void tud_suspend_cb(bool remote_wakeup_en) {
    (void)remote_wakeup_en;
    if (s_cbs.on_mount) s_cbs.on_mount(false);
}
void tud_resume_cb(void) {
    if (s_cbs.on_mount && tud_mounted()) s_cbs.on_mount(true);
}

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    return instance == PRISM_USB_HID_FIDO ? hid_fido_report_desc : hid_kbd_report_desc;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t *buffer, uint16_t reqlen) {
    (void)instance; (void)report_id; (void)report_type; (void)buffer; (void)reqlen;
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize) {
    (void)report_id; (void)report_type;
    if (instance == PRISM_USB_HID_FIDO && bufsize == 64 && s_cbs.on_fido_out) s_cbs.on_fido_out(buffer);
    // Keyboard LED output reports are ignored.
}

static void cdc_rx_cb(int itf, cdcacm_event_t *event) {
    (void)event;
    static uint8_t buf[CONFIG_TINYUSB_CDC_RX_BUFSIZE];
    size_t n = 0;
    while (tinyusb_cdcacm_read((tinyusb_cdcacm_itf_t)itf, buf, sizeof(buf), &n) == ESP_OK && n > 0) {
        if (s_cbs.on_cdc_rx) s_cbs.on_cdc_rx(buf, n);
        n = 0;
    }
}

static void cdc_line_cb(int itf, cdcacm_event_t *event) {
    (void)itf;
    if (s_cbs.on_cdc_dtr) s_cbs.on_cdc_dtr(event->line_state_changed_data.dtr);
}

// ---- API -----------------------------------------------------------------------------------------

int prism_usb_install(const char *serial, const prism_usb_callbacks_t *cbs) {
    s_cbs = *cbs;
    static const char lang[] = {0x09, 0x04};  // LANGID: English (US)
    s_strings[0] = lang;
    s_strings[1] = "Prism";
    s_strings[2] = "Prism Key";
    s_strings[3] = serial;
    s_strings[4] = "Prism Protocol";
    s_strings[5] = "Prism FIDO";
    s_strings[6] = "Prism Keyboard";

    const tinyusb_config_t cfg = {
        .device_descriptor = &s_dev_desc,
        .string_descriptor = s_strings,
        .string_descriptor_count = 7,
        .external_phy = false,
        .configuration_descriptor = s_cfg_desc,
        .self_powered = false,
    };
    esp_err_t err = tinyusb_driver_install(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tinyusb_driver_install: %s", esp_err_to_name(err));
        return err;
    }
    const tinyusb_config_cdcacm_t acm = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .callback_rx = cdc_rx_cb,
        .callback_line_state_changed = cdc_line_cb,
    };
    err = tusb_cdc_acm_init(&acm);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tusb_cdc_acm_init: %s", esp_err_to_name(err));
        return err;
    }
    return 0;
}

bool prism_usb_mounted(void) { return tud_mounted(); }

bool prism_usb_cdc_write(const uint8_t *data, size_t len) {
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(1000);
    while (len > 0) {
        if (!tud_mounted()) return false;
        size_t n = tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, data, len);
        data += n;
        len -= n;
        if (tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, pdMS_TO_TICKS(100)) != ESP_OK && n == 0) {
            if (xTaskGetTickCount() > deadline) return false;
        }
        if (len > 0 && xTaskGetTickCount() > deadline) return false;
    }
    return true;
}

bool prism_usb_hid_send(uint8_t instance, const uint8_t *report, uint8_t len) {
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(500);
    while (!tud_hid_n_ready(instance)) {
        if (!tud_mounted() || xTaskGetTickCount() > deadline) return false;
        vTaskDelay(1);
    }
    return tud_hid_n_report(instance, 0, report, len);
}
