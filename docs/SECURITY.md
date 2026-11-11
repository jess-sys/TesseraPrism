# Prism — Security Model

## 1. What is protected, and how

* The 32-byte master seed (BIP39 24 words) never touches flash in clear. It is wrapped in the
  `VaultHeader` under up to two key slots (PIN: Argon2id m=4 MiB t=3; recovery passphrase: Argon2id
  m=8 MiB t=4), XChaCha20-Poly1305. The vault (entries) is encrypted under a DEK derived from the seed
  (HKDF-SHA256, salt `prism/v1`, info `vault-dek`), with the header as AAD.
* Seed-derived keys (SSH, passkey private keys, export subkeys) are re-derived on demand and never stored.
* The unlocked vault lives only in RAM (PSRAM) and is zeroized on lock.
* The PIN failure counter lives in NVS, outside the vault. After 10 consecutive failures the vault is wiped.
* Every secret use is gated by a per-entry approval policy (`Always` / `Session` / `Never`) requiring a
  physical tap on the device.

## 2. Threat model

| Threat | Dev profile | Prod profile |
|---|---|---|
| **Lost / stolen device, powered off** | Attacker needs the PIN. Flash can be dumped, so the PIN can be brute-forced offline: a 6-digit PIN is only 10^6 guesses, and Argon2id at 4 MiB / t=3 makes that cheap on a GPU/cluster. The 10-try wipe is NOT enforced against an attacker working on a flash image. **Effectively weak.** Use a long PIN (12 digits) and/or a recovery-grade secret. | Flash is encrypted (key in eFuse, unreadable). The KEK additionally mixes in an eFuse HMAC key that cannot leave the chip, so offline brute force is impossible; guesses must run on the device, where the 10-try counter and wipe apply. |
| **Lost device, powered on / unlocked** | Auto-lock (default 180 s) zeroizes keys. Within the window the attacker has full access. | Same. |
| **Malicious paired host** | A paired host can list non-secret summaries and request secrets, signatures and codes. Entries with policy `Always` still need a tap, so a compromised host cannot silently exfiltrate them; `Session`/`Never` entries can be used without a tap once approved/unlocked. Treat paired hosts as semi-trusted; remove unused ones. SSH private keys are never sent; only signatures. | Same. |
| **Malicious unpaired BLE peer** | Noise_XX handshake; unknown static keys are rejected (`NotPaired`) unless the user put the device in Pairing mode and confirms the 6-digit SAS on both screens. An attacker within radio range can attempt handshakes (DoS) but gets no data. Pairing mode should be entered only deliberately. | Same. |
| **Flash dump (physical)** | Everything in flash is readable: the encrypted vault, NVS (device Noise key, paired hosts, PIN counter, settings). Vault confidentiality rests on the PIN only (see above). The counter can be reset. Firmware can be replaced with a malicious build that logs the PIN. | Flash encryption + secure boot v2 prevent reading and replacing firmware. |
| **Malicious firmware / evil-maid** | Not protected: no secure boot. | Secure boot v2 blocks unsigned images; JTAG and ROM download disabled. |
| **Shoulder surfing / eInk remanence** | The display keeps the last image with power off. The lock screen never shows secrets; reveal screens should be cleared with a full refresh before sleeping. | Same. |
| **Side channels / fault injection** | Out of scope (no hardening against power analysis or glitching). | ESP32-S3 eFuse protections reduce but do not eliminate this. |
| **Forgotten PIN** | Recover with the recovery passphrase (via companion) or the 24 words / `.prism` export. | Same. |

### What the dev profile does NOT protect
* Offline brute force of the PIN from a flash dump (see above).
* The PIN-attempt counter and wipe (software-only, resettable by anyone who can write flash).
* Firmware integrity: anyone with USB access can reflash and use the device as a PIN-logging trap.
* Secrets in NVS and unencrypted flash partitions; JTAG/download mode is open.
* Anything once the device is unlocked and in an attacker's hands.

The recovery passphrase, the 24 words and `.prism` exports are only as strong as their entropy: use
a generated passphrase (>= 6 diceware words). Store the 24 words offline on paper.

## 3. `prod` profile procedure

> **WARNING: every eFuse step below is IRREVERSIBLE. A mistake can brick the device permanently.
> Practice on a sacrificial board first. Keep the signing key and the HMAC key backed up offline;
> losing them means you can never update firmware or unlock the stored data again. Use
> `espefuse.py --do-not-confirm` never; read each prompt. Do not do this on your only device.**

Prerequisites: ESP-IDF >= 5.3, `espsecure.py`, `espefuse.py`, a build with `sdkconfig` for the `prod` profile.

1. **Build and test the firmware in dev profile first.** Confirm everything works, including the
   `KekHardener` fallback to `NoHardening` on a fresh vault.
2. **Generate keys offline** (air-gapped machine preferred):
   ```
   espsecure.py generate_signing_key --version 2 --scheme rsa3072 secure_boot_signing_key.pem
   espsecure.py generate_flash_encryption_key flash_encryption_key.bin   # only if pre-generating the key
   head -c 32 /dev/urandom > hmac_key.bin                                # PIN-hardening HMAC key
   ```
   Back all three up to offline storage. `hmac_key.bin` MUST be kept: it is the only way to rebuild a
   device after a flash-encryption failure (the vault can still be restored from the 24 words / export,
   which do not depend on it).
3. **Burn the HMAC key** into a key block with purpose `HMAC_UP` (usable by the HMAC peripheral in
   "upstream" mode, and not readable by software):
   ```
   espefuse.py -p PORT burn_key BLOCK_KEY0 hmac_key.bin HMAC_UP
   ```
   The key is write- and read-protected automatically for HMAC purposes. Choose a block not used by flash encryption /
   secure boot (they use the `XTS_AES_*` and `SECURE_BOOT_DIGEST*` purposes).
4. **Enable flash encryption in Release mode** (sdkconfig: `CONFIG_SECURE_FLASH_ENC_ENABLED=y`,
   `CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y`). On first boot the bootloader generates the XTS-AES-128/256 key
   in eFuse and encrypts flash. Release mode permanently disables UART/ROM re-flash of plaintext. Partitions
   needed later (NVS, the `vault` raw partition) are encrypted transparently if marked `encrypted` in
   `partitions.csv` (the raw `vault` partition should be marked `encrypted`).
5. **Enable Secure Boot v2** (`CONFIG_SECURE_BOOT=y`, `CONFIG_SECURE_BOOT_V2_ENABLED=y`, signing key from
   step 2, "sign on build" or sign offline with `espsecure.py sign_data --version 2`). Burn the key digest
   (`espefuse.py burn_key_digest`) before the final lock; the bootloader does it automatically when you
   flash the signed bootloader. Revoke unused digest slots only if you understand the consequences.
6. **Disable debug paths** (eFuses):
   ```
   espefuse.py -p PORT burn_efuse DIS_USB_JTAG
   espefuse.py -p PORT burn_efuse DIS_PAD_JTAG
   espefuse.py -p PORT burn_efuse DIS_DOWNLOAD_MODE        # or ENABLE_SECURITY_DOWNLOAD for a restricted mode
   espefuse.py -p PORT burn_efuse DIS_DIRECT_BOOT
   ```
   Note: the Paper S3 uses native USB for HID/CDC; `DIS_USB_JTAG` / USB-Serial-JTAG disable does not remove
   TinyUSB. With download mode disabled, firmware updates must come through the app (OTA) signed with the Secure Boot key.
7. **Verify** with `espefuse.py summary`: flash encryption in release mode, secure boot enabled, `HMAC_UP`
   block read/write protected, JTAG and download disabled. Then test: unsigned image refuses to boot, PIN unlock works.

### How `KekHardener` uses the eFuse key
For the PIN slot, `KEK = HMAC-SHA256(efuse_hmac_key, Argon2id(pin, salt, params))`. The firmware implements
`prism_core::KekHardener` with the ESP32-S3 HMAC peripheral (`esp_hmac_calculate(HMAC_KEY0 + n, msg, 32, out)`
in ESP-IDF, with the key block holding the `HMAC_UP` key), passing the 32-byte Argon2 output as the
message. The raw key never leaves hardware, so an attacker holding a flash image (even decrypted) cannot test PIN
guesses off-chip: each guess requires the chip. The recovery slot deliberately does NOT use the hardener, so the
recovery passphrase / 24 words restore a vault on a replacement device. Consequently, in the prod profile the
recovery passphrase must be strong (it is the offline-attackable path): use 6+ random words.

A vault created with `NoHardening` (dev) is not readable once the prod hardener is active. Migrate by exporting
(`.prism`) in dev, provisioning prod, and importing, or by running `change_pin` with the real hardener after
unlocking with the recovery slot.
