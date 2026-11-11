# Plan: hardware security (ESP32-S3)

Status (2026-11-11): **Stage 1 implemented** — eFuse-bound PIN. Stages 2–3 planned.

## Stage 1 — eFuse HMAC-hardened PIN (done)

The PIN slot KEK = `HMAC(eFuse key, Argon2id(PIN))`; key generated and burned on the device, read-protected,
never leaves the chip. Existing vaults migrate on the next unlock. Details: [../SECURITY.md](../SECURITY.md).
Effect: a flash dump no longer allows offline PIN brute force; guesses must run on the chip, where the 10-try
wipe applies. Not yet protected: reading the (encrypted) vault and NVS from flash, firmware replacement.

## Stage 2 — signed OTA updates (prerequisite for Stage 3)

Once flash encryption (release) and secure boot are enabled and download mode is disabled, the USB/serial
flashing path is gone. Updates must arrive over the companion protocol:

1. Partition table: two OTA app slots (`ota_0`, `ota_1`) + `otadata` (requires one re-partition over USB
   while that is still possible; the `vault` partition must be preserved).
2. Protocol: `OtaBegin { size, sha256 }`, `OtaChunk { offset, data }`, `OtaCommit` — tap on the device to
   approve, shows version; written with `esp_ota_*` (which encrypts transparently once flash encryption is on).
3. Rollback: `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`; the new image marks itself valid after a healthy boot.
4. Anti-rollback: secure version counter in eFuse (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`).
5. Companions: `prism update firmware.bin` (CLI first, then web/Apple).

Exit criterion: an update is installed over BLE/USB-CDC on the real device and a bad image rolls back.

## Stage 3 — lockdown (irreversible)

Only after Stage 2 works on the device, on a board you can afford to brick first:

1. Secure Boot v2 (RSA-3072 or ECDSA-P256 signing key generated offline, backed up; images and the
   bootloader signed in the build).
2. Flash encryption, **release** mode (key generated on chip; NVS encryption via the HMAC-derived NVS key).
3. Burn `DIS_USB_JTAG`, `DIS_PAD_JTAG`, `DIS_DOWNLOAD_MODE` (or `ENABLE_SECURITY_DOWNLOAD`), `DIS_DIRECT_BOOT`.
4. Verify with `espefuse.py summary`; test that an unsigned image refuses to boot and PIN unlock still works.

Procedure and warnings: [../SECURITY.md](../SECURITY.md) §3.
