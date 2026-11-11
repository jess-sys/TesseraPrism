# Prism firmware (M5Stack Paper S3)

Standalone cargo project (excluded from the host workspace), `std` on ESP-IDF, target
`xtensa-esp32s3-espidf`, toolchain `esp`. Architecture: `../docs/ARCHITECTURE.md` section 7.

Layout: `src/board.rs` (all pins), `src/drivers/` (epd, touch, rtc, power, sd), `src/core/` (core actor: vault, sessions, approvals, CTAP worker), `src/ui_task.rs`, `src/power_mgr.rs`,
`src/storage.rs` (NVS + A/B vault partition), `src/transport/` (BLE/USB), `components/prism_epd/` (epdiy board definition + C shim).

## Setup

```sh
cargo install espup espflash ldproxy
espup install            # Xtensa Rust toolchain "esp" + clang + gcc, writes ~/export-esp.sh
brew install cmake ninja python3
. ~/export-esp.sh        # in every shell that builds
```

The first build downloads ESP-IDF v5.5.x and its tools into `.embuild/` (several GB, several
minutes) and the registry components `vroland/epdiy` and `espressif/esp_tinyusb`.

## Build

```sh
cd firmware
cargo build --release
```

`sdkconfig.defaults` is applied on a clean `.embuild`/`sdkconfig`; after editing it run
`rm -f sdkconfig && cargo clean -p esp-idf-sys` to regenerate.

## Flash and monitor

```sh
cargo run --release          # espflash flash --monitor --partition-table partitions.csv
# or: espflash flash --partition-table partitions.csv target/xtensa-esp32s3-espidf/release/prism-firmware
espflash monitor
```

With TinyUSB owning the native USB port the chip does not enumerate as a ROM/JTAG serial device.
To flash, **hold BOOT (GPIO0) while powering on** (or while plugging USB), which enters the ROM
download mode; release after espflash connects. Note that Paper S3 only powers down with the
battery path, so with USB attached the "power off" falls back to deep sleep (wake: BOOT).

Flash image without a device (also a good CI check):

```sh
espflash save-image --chip esp32s3 --flash-size 16mb --partition-table partitions.csv \
  target/xtensa-esp32s3-espidf/release/prism-firmware prism.bin
# add --merge --bootloader target/xtensa-esp32s3-espidf/release/bootloader.bin for a single 16 MB image
```

Note: espflash 4.x (esp-idf-part 0.6) panics (`Option::unwrap` in `SubType::data`) on custom numeric
data subtypes such as `0x40`. `partitions.csv` therefore uses the standard subtype `undefined` for the
`vault` partition; the firmware finds it by label.

## `jtag-console` feature

Keeps the USB-Serial-JTAG for log output and flashing without the BOOT dance, and disables
TinyUSB. It needs the matching sdkconfig overlay because sdkconfig cannot depend on cargo features:

```sh
rm -f sdkconfig
ESP_IDF_SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.jtag" cargo build --release --features jtag-console
```

Without it, logs go to UART0 TX (GPIO43, pad only; GPIO44 is the power-hold line).

## Not yet validated on hardware

Display orientation/mapping (`Rotation::Portrait`), epdiy timing at 16 MHz, GT911 address and
coordinate orientation, deep-sleep wake on the BOOT button, the power-off pulse train, the
RTC INT wiring, and the buzzer pin. See the header comments in `src/board.rs`.

## Flashing the ESP-IDF bootloader

`espflash` writes its own bundled bootloader unless told otherwise, which ignores the bootloader
settings in `sdkconfig.defaults` (skip image validation on power-on, quiet logs → faster boot).
Flash the one ESP-IDF built:

```sh
BL=$(find target/xtensa-esp32s3-espidf/release/build -path '*out/build/bootloader/bootloader.bin' | head -1)
espflash flash --chip esp32s3 --flash-size 16mb --partition-table partitions.csv \
  --bootloader "$BL" target/xtensa-esp32s3-espidf/release/prism-firmware
```
