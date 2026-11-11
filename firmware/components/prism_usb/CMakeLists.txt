idf_component_register(
    SRCS "prism_usb.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_timer
    PRIV_REQUIRES espressif__esp_tinyusb
)
