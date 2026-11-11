#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HID instance numbers (order in the configuration descriptor). */
#define PRISM_USB_HID_FIDO 0
#define PRISM_USB_HID_KBD 1

typedef struct {
    void (*on_mount)(bool mounted);                         /* tinyusb task */
    void (*on_cdc_rx)(const uint8_t *data, size_t len);     /* tinyusb task */
    void (*on_fido_out)(const uint8_t *report64);           /* tinyusb task */
    void (*on_cdc_dtr)(bool dtr);                           /* tinyusb task: host opened/closed the port */
} prism_usb_callbacks_t;

/* Install TinyUSB with the Prism composite descriptors. `serial` must stay valid. 0 = ok. */
int prism_usb_install(const char *serial, const prism_usb_callbacks_t *cbs);
bool prism_usb_mounted(void);
/* Blocking (bounded) writes; false if not mounted or timed out. */
bool prism_usb_cdc_write(const uint8_t *data, size_t len);
bool prism_usb_hid_send(uint8_t instance, const uint8_t *report, uint8_t len);

#ifdef __cplusplus
}
#endif
