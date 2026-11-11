# Prism — Architecture & Implementation Contract

Prism is an offline-first hardware password manager running on the **M5Stack Paper S3**
(ESP32-S3R8, 8 MB PSRAM, 16 MB flash, 4.7" 960×540 16-gray eInk, GT911 touch, BM8563 RTC,
1800 mAh battery, USB-C on native USB OTG, microSD).

It holds: **passwords, TOTP, passkeys (FIDO2), SSH keys (Ed25519, agent on Linux/macOS),
recovery codes.** Reachable via **BLE** (primary) and **USB** (backup + FIDO HID + keyboard typing).

This document is the **contract** between all crates/apps. If you are an agent implementing one
part, do not change the interfaces defined here without stating it explicitly in your report.

---

## 1. Decisions (from the owner)

| Topic | Decision |
|---|---|
| Unlock | PIN on touchscreen (daily) **and** recovery passphrase via companion. Two key slots. |
| HW security | Dev profile now (app-level crypto only). `prod` profile documented: flash encryption + secure boot v2 + eFuse HMAC key mixed into PIN KDF. |
| FW stack | Rust **std** on ESP-IDF (`esp-idf-svc`, `esp-idf-hal`, `esp-idf-sys`), ESP-IDF v5.3+. |
| Passkeys | USB HID CTAP2 (primary) + BLE CTAP2 (FIDO GATT 0xFFFD) + Apple credential provider relay via Prism protocol. |
| SSH | Ed25519 only. On-device generated (seed-derived) **or** imported. Never leaves device. |
| Approval | Per-use tap on device; per-entry policy `Always` / `Session` / `Never`. |
| Backup | Encrypted export file (recovery passphrase) **and** BIP39 24-word seed shown on eInk at setup. |
| Companions | Rust CLI + SSH agent daemon; Web app (Web Bluetooth + Web Serial); iOS + macOS SwiftUI app with AutoFill credential provider. |
| Power | Configurable: on idle → lock → `PowerOff` (default) or `LightSleep` (stays BLE-reachable). |
| Off screen | Lock screen: logo, battery % at shutdown, last-used time, "press button to unlock". Never secrets. |
| HID typing | USB keyboard only (layouts: US, FR-AZERTY at minimum). |
| Name | Prism. BLE name `Prism-XXXX` (last 2 bytes of MAC hex). USB product "Prism Key", VID/PID `0x303A:0x8360` (Espressif test PID range — replace for production). |

---

## 2. Repository layout

```
Prism/
├── Cargo.toml                 # host workspace (all crates/*). firmware/ is EXCLUDED (own target/toolchain)
├── docs/ARCHITECTURE.md       # this file
├── docs/SECURITY.md           # threat model, prod profile (eFuse) procedure
├── crates/
│   ├── prism-core/            # data model, vault crypto, key slots, BIP39, derivation, TOTP, export format
│   ├── prism-proto/           # wire messages, framing (BLE chunking, COBS), Noise session, pairing SAS
│   ├── prism-ctap/            # FIDO2 CTAP2.1 authenticator logic + CTAPHID + CTAP-BLE framing (transport-agnostic)
│   ├── prism-ui/              # eInk UI: screens over embedded-graphics (Gray4), touch model; host-testable, renders PNG in tests
│   ├── prism-client/          # host-side: transports (btleplug BLE, serialport USB CDC), session, high-level API
│   ├── prism-cli/             # `prism` binary: CLI + `prism agent` SSH agent daemon
│   ├── prism-wasm/            # wasm-bindgen wrapper (JSON API) for the web app
│   └── prism-ffi/             # UniFFI wrapper (JSON API) for Swift apps
├── firmware/                  # ESP32-S3 firmware, target xtensa-esp32s3-espidf, toolchain "esp"
└── apps/
    ├── web/                   # Vite + TypeScript, uses prism-wasm
    └── apple/                 # XcodeGen project.yml, SwiftUI iOS+macOS, Credential Provider extension
```

All crates are `std` (firmware is std via ESP-IDF). **Crypto must be pure Rust** (no `ring`,
no `aws-lc`, no OpenSSL) because they must build for `xtensa-esp32s3-espidf` and `wasm32`.
Use RustCrypto: `chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`, `p256`, `argon2`, `hkdf`,
`hmac`, `sha1`, `sha2`, `blake2`, `zeroize`, `rand_core`/`getrandom`. Serialization: `serde` +
`postcard` (wire/storage), `serde_json` (JS/Swift bridges), `minicbor` or `ciborium` (CTAP).

Rust edition 2021, MSRV = whatever the `esp` toolchain ships (≥ 1.82). Avoid nightly features.

---

## 3. Cryptography & key hierarchy (prism-core)

```
BIP39 24 words  ──►  entropy (32 B) = MASTER SEED  (never stored in clear)
                         │  HKDF-SHA256(ikm=seed, salt="prism/v1", info=…)
                         ├─ "vault-dek"              → DEK (32 B), XChaCha20-Poly1305 vault key
                         ├─ "ssh-ed25519/{index}"     → Ed25519 secret seed for derived SSH key #index
                         ├─ "fido-cred-wrap"          → key used to derive passkey private keys
                         │      passkey priv = HKDF(seed, info="fido/{alg}/" ‖ cred_nonce(16 B)) → P-256 scalar (retry on invalid) / Ed25519
                         └─ "export"                 → export file MAC/enc subkey (combined with passphrase, see §3.3)
```

### 3.1 Key slots (LUKS-style)
The 32-byte seed is stored wrapped, in the `VaultHeader`, under up to two slots:

* **PIN slot**: `KEK = Argon2id(pin, salt, m=4096 KiB, t=3, p=1)`; in `prod` profile
  `KEK = HMAC-SHA256(efuse_hmac_key, Argon2id(...))` (via ESP32-S3 HMAC peripheral — the firmware
  passes a `KekHardener` callback; prism-core exposes `trait KekHardener { fn harden(&self, k:[u8;32])->[u8;32]; }`
  with a `NoHardening` impl). PIN length 6–12 digits.
* **Recovery slot**: `KEK = Argon2id(passphrase, salt, m=8192 KiB, t=4, p=1)`.
* Wrap = XChaCha20-Poly1305(KEK, nonce 24 B, seed), AAD = `"prism-slot" ‖ slot_kind`.
* Argon2 params are stored in each slot (forward-compatible).
* PIN failure counter lives **outside** the encrypted vault (firmware NVS). After 10 consecutive
  failures → wipe vault. Show remaining attempts after 3 failures.

### 3.2 Vault blob
`VaultFile = postcard(VaultHeader) ‖ nonce(24) ‖ XChaCha20-Poly1305(DEK, postcard(Vault), AAD=postcard(VaultHeader))`

`VaultHeader { magic: [u8;4]="PRSM", version: u16=1, generation: u64, slots: Vec<KeySlot> }`.
Whole vault is decrypted into PSRAM while unlocked (expected < 256 KiB) and `zeroize`d on lock.
All secret-bearing types implement `Zeroize`/`ZeroizeOnDrop`.

### 3.3 Export file (`.prism`)
`ExportFile = "PRSMEXP1" ‖ postcard(ExportHeader{argon2 params, salt, created}) ‖ nonce ‖ XChaCha20-Poly1305(K, postcard(ExportPayload))`
with `K = Argon2id(recovery_passphrase, salt, m=8192 KiB, t=4)`. `ExportPayload { seed: [u8;32], vault: Vault }`.
Restoring needs only the passphrase. Restore from **seed only** (24 words) recreates derived SSH keys
(indices 0..=next_index, scanning) and an empty vault; passwords/TOTP/passkey metadata need the export.

### 3.4 TOTP
RFC 6238 / RFC 4226. SHA1/SHA256/SHA512, 6–8 digits, period default 30. Base32 secret parsing
(no padding, case-insensitive, spaces ignored). `otpauth://` URI parse + build. Test vectors from RFC 6238 appendix B are mandatory.

---

## 4. Data model (prism-core::model) — **already written, see `crates/prism-core/src/model.rs`**

Do not duplicate these types elsewhere; depend on `prism-core`.

---

## 5. Wire protocol (prism-proto)

### 5.1 Transports
* **BLE GATT** (Prism service):
  * Service UUID `9e5d0001-3c4a-4b8e-9f1a-5072736d0000`
  * RX characteristic (host → device, Write Without Response + Write) `9e5d0002-3c4a-4b8e-9f1a-5072736d0000`
  * TX characteristic (device → host, Notify) `9e5d0003-3c4a-4b8e-9f1a-5072736d0000`
  * BLE-level security: LE Secure Connections "Just Works" is enough for the Prism service
    (security comes from Noise). FIDO service (0xFFFD) requires LESC bonding with passkey
    displayed on eInk (IO caps DisplayOnly), per FIDO CTAP-BLE spec.
  * **Chunking**: each GATT write/notify = `[hdr: u8][body…]`. `hdr` bit7 = 1 if *more chunks follow*,
    bits 0-6 = sequence number (0 for first chunk, increment mod 128). First chunk body begins with
    `u16 LE total_len` of the frame. Max chunk = `ATT_MTU − 3`. Reassembler resets on seq 0.
  * **BLE framing v2 (channels)**: on macOS/iOS all host processes share one BLE link, so each client
    picks a random non-zero `u32` channel id and tags every chunk: first chunk
    `[hdr][chan u32 LE][total_len u16 LE][body…]`, later chunks `[hdr][chan u32 LE][body…]`;
    `hdr` bit7 = more, bit6 = 1 (v2 marker), bits 0-5 = seq mod 64. Max chunk is still `ATT_MTU − 3`.
    v1 chunks (bit6 = 0) stay valid and map to channel 0. The device demultiplexes with
    `ble::ChannelReassembler` (LRU-evicting) and replies via `ble::chunk_for(frame, mtu, chan)`; hosts use
    `ble::chunk_v2` + `Reassembler::new_channel(chan)`, which ignores other channels' chunks.
    See `docs/plans/ble-client-channels.md`.
* **USB CDC-ACM** (part of USB composite): frames are **COBS-encoded** and terminated by `0x00`.
* Both carry the same **frame**: `[kind: u8][payload…]`, max frame 65535 bytes.
  * `0x01 HANDSHAKE` — Noise handshake message
  * `0x02 TRANSPORT` — Noise transport message containing `postcard(Request)` or `postcard(Response)`
  * `0x03 PLAIN_ERROR` — `postcard(ProtoError)` (only before the session is established)

### 5.2 Session: Noise
`Noise_XX_25519_ChaChaPoly_BLAKE2s`, prologue `b"prism/v1"`, **host is initiator**. Use the `snow`
crate (default resolver, pure Rust) — verify it builds for `wasm32-unknown-unknown` (getrandom `js`)
and xtensa espidf (getrandom uses esp_fill_random via std). If `snow` is a problem, implement XX
directly with RustCrypto primitives behind the same API.

* Device static X25519 key: generated at first boot, stored in NVS (not inside vault — needed while locked).
* Host static X25519 key: generated by companion, stored in host keychain/file.
* **Pairing**: after handshake, device checks host static key against its paired-host list
  (max 16, stored in NVS with a user-given label). Unknown host:
  * if device is in *Pairing mode* (Settings → Pair new host): device displays
    `SAS = u32::from_le_bytes(BLAKE2s-256("prism-sas" ‖ handshake_hash)[0..4]) % 1_000_000` as 6 digits; host shows the same;
    user taps *Confirm* on device → `Response::Paired{ label }`.
  * else → `Response::Error(ErrorCode::NotPaired)` and close.
* Sans-IO API in prism-proto:

```rust
pub struct HostSession { /* initiator */ }
impl HostSession {
  pub fn new(host_static_private: &[u8;32]) -> Result<Self>;
  pub fn start(&mut self) -> Result<Vec<u8>>;                 // returns full frame (kind 0x01) to send
  pub fn on_frame(&mut self, frame: &[u8]) -> Result<SessionEvent>;  // feed received frames
  pub fn is_established(&self) -> bool;
  pub fn sas(&self) -> Option<String>;                          // "123456"
  pub fn remote_static(&self) -> Option<[u8;32]>;
  pub fn encrypt_request(&mut self, req: &Request) -> Result<Vec<u8>>;  // full frame (kind 0x02)
}
pub enum SessionEvent { SendFrame(Vec<u8>), Established, Response(Response), PlainError(ProtoError) }
pub struct DeviceSession { /* responder; mirror API: on_frame → DeviceEvent::{SendFrame, Established{remote_static}, Request(Request)}; encrypt_response(&Response) */ }
pub fn generate_static_keypair() -> ([u8;32] /*priv*/, [u8;32] /*pub*/);
pub mod ble  { pub fn chunk(frame:&[u8], mtu: usize) -> Vec<Vec<u8>>; pub struct Reassembler; impl Reassembler { pub fn push(&mut self, chunk:&[u8]) -> Result<Option<Vec<u8>>>; } }
pub mod cdc  { pub fn encode(frame:&[u8]) -> Vec<u8>; pub struct Decoder; impl Decoder { pub fn push(&mut self, bytes:&[u8]) -> Vec<Result<Vec<u8>>>; } }
```

**As implemented (authoritative over the sketch above):** `encrypt_request(&Envelope<Request>)`,
`encrypt_response(&Envelope<Response>)`; `SessionEvent::Response(Envelope<Response>)`,
`DeviceEvent::Request(Envelope<Request>)`. Host handshake: `start()` → msg1; `on_frame(msg2)` returns
`SendFrame(msg3)` and `is_established()` is then true (`SessionEvent::Established` is never emitted).
Device emits `DeviceEvent::Established{remote_static}` on msg3. `ProtoError{code: ErrorCode, message: String}`.
`ble::chunk(frame, att_mtu)` takes the ATT MTU (≥ 23). Max encrypted plaintext 65518 bytes (`MAX_PLAINTEXT`).
JSON: `{"id":3,"body":{"GetSecret":{"id":[...16],"field":"Password","context":null}}}`, `{"id":1,"body":"GetInfo"}`.

### 5.3 Messages
Every `Request` carries a `u32 id` echoed by the `Response` (`Envelope<T>{ id: u32, body: T }`).

```rust
pub enum Request {
  GetInfo,                                   // works locked
  SetTime { unix: u64 },                     // works locked; host syncs RTC on every connect
  Unlock { passphrase: String },             // recovery-passphrase unlock (companion path)
  Lock,
  ListEntries { kind: Option<EntryKind> },   // → Entries(Vec<EntrySummary>) — never secrets
  GetSecret { id: EntryId, field: SecretField, context: Option<String> },  // approval per policy
  GetTotp { id: EntryId },                   // → Totp{code, valid_until}; approval per policy
  AddEntry { entry: Entry },                 // shows confirmation on device
  UpdateEntry { entry: Entry },
  DeleteEntry { id: EntryId },               // always requires tap
  MarkRecoveryCodeUsed { id: EntryId, index: u16 },
  GenerateSshKey { name: String, comment: String, policy: ApprovalPolicy },  // derived from seed
  SshListKeys,                               // → SshKeys(Vec<SshPublicKey>) ; allowed when unlocked w/o tap
  SshSign { public_key: Vec<u8> /*SSH wire blob*/, data: Vec<u8>, flags: u32, host_hint: Option<String> },
  Ctap { cbor: Vec<u8>, origin_hint: Option<String> }, // CTAP2 request (cmd byte + CBOR) relayed by Apple credential provider
  TypeEntry { id: EntryId, field: SecretField, layout: KeyboardLayout },   // USB HID typing
  Export,                                    // → ExportReady{ total_len }, then ExportChunk
  ExportChunk { offset: u32 },               // → Chunk{ offset, data (≤ 8 KiB) }
  ImportBegin { total_len: u32 },
  ImportChunk { offset: u32, data: Vec<u8> },
  ImportCommit { passphrase: String, mode: ImportMode },
  ListPairedHosts, RemovePairedHost { public_key: [u8;32] },
  GetSettings, SetSettings { settings: Settings },
}
pub enum Response {
  Info(DeviceInfo), Ok, Paired { label: String }, Entries(Vec<EntrySummary>), Secret(SecretValue),
  Totp { code: String, valid_until: u64 }, EntryId(EntryId), SshKeys(Vec<SshPublicKey>),
  SshSignature(Vec<u8> /* SSH signature wire blob */), Ctap(Vec<u8>),
  ExportReady { total_len: u32 }, Chunk { offset: u32, data: Vec<u8> },
  PairedHosts(Vec<PairedHost>), Settings(Settings), Error(ErrorCode),
}
pub enum ErrorCode { Locked, Denied, Timeout, NotFound, NotPaired, InvalidRequest, BadPassphrase,
                     StorageFull, Unsupported, Busy, Internal }
```
**Additions (rev 2, authoritative):** `Export { passphrase }` (device verifies it against the recovery slot,
then encrypts the export with it; `BadPassphrase` / `Unsupported` if no recovery slot),
`SetRecoveryPassphrase { passphrase }` → `Ok` (tap), `GetEntry { id }` → `Response::Entry(Entry)` (approval per policy),
`GenerateSshKey` → `SshKeys(vec![new_key])`.

`DeviceInfo{ fw_version, device_pubkey: [u8;32], locked: bool, battery_pct: u8, charging: bool, entry_count: u32, time_valid: bool }`.
`Settings`, `SecretField`, `SecretValue`, `KeyboardLayout`, `ImportMode`, `PairedHost` are defined in prism-core::model.

Long operations (waiting for a tap) — device sends nothing until answered; host timeout = 60 s.
Approval timeout on device = 30 s → `Error(Timeout)`.

---

## 6. FIDO2 (prism-ctap)

Transport-agnostic CTAP 2.1 subset:
* Commands: `authenticatorMakeCredential (0x01)`, `GetAssertion (0x02)`, `GetNextAssertion (0x08)`,
  `GetInfo (0x04)`, `Reset (0x07)`, `Selection (0x0B)`, `CredentialManagement (0x0A)` (enumerate/delete; optional, phase 2).
* Algorithms: ES256 (-7) required, EdDSA (-8).
* Options in GetInfo: `rk: true, up: true, uv: true` (built-in UV = device is PIN-unlocked on its own
  touchscreen + tap), no `clientPin`. AAGUID: `50 52 49 53 4d 2d 4b 45 59 2d 76 31 2d 30 30 31` ("PRISM-KEY-v1-001").
* signCount always 0 (avoids flash wear). Attestation format `"none"` (or self `packed`).
* Credential ID = `nonce(16) ‖ HMAC-SHA256(seed-derived key, rpIdHash ‖ nonce)[0..16]` → allows recognising
  our own non-resident credentials; resident ones are stored as `Entry::Passkey`.
* Framing modules: `ctaphid` (64-byte HID reports: INIT 0x06, PING 0x01, MSG 0x03, CBOR 0x10, CANCEL 0x11,
  KEEPALIVE 0x3B, WINK 0x08, ERROR 0x3F; channel allocation; continuation packets) and `ble`
  (FIDO GATT framing: CMD 0x83 MSG, 0x81 PING, 0x82 KEEPALIVE, 0xBE CANCEL, 0xBF ERROR; fidoControlPointLength).
* Platform abstraction:
```rust
pub trait Platform {
  fn rng(&mut self, buf: &mut [u8]);
  fn seed_key(&self, info: &[u8]) -> Option<[u8;32]>;   // HKDF from master seed; None if locked
  fn user_presence(&mut self, req: &PresenceRequest) -> PresenceResult; // blocking: shows approval screen
  fn find_resident(&self, rp_id: &str) -> Vec<PasskeyCredential>;
  fn store_resident(&mut self, cred: PasskeyCredential) -> Result<(), StorageError>;
  fn delete_resident(&mut self, cred_id: &[u8]) -> Result<(), StorageError>;
  fn reset(&mut self) -> Result<(), StorageError>;
  fn keepalive(&mut self, status: KeepaliveStatus);       // transport sends keepalive while waiting
}
pub struct Authenticator<P: Platform>; impl<P: Platform> Authenticator<P> { pub fn new(p:P)->Self; pub fn handle(&mut self, request: &[u8]) -> Vec<u8>; }
```
`PasskeyCredential` = `prism_core::model::Passkey`.

---

## 7. Firmware (firmware/)

### 7.1 Hardware (M5Stack Paper S3 — verified against M5GFX / M5Unified sources, not yet on hardware)
| Function | Pins / bus (source: M5GFX `esp32s3_board_data.hpp`, M5Unified `Power_Class.inl`, M5 docs) |
|---|---|
| eInk ED047TC1 (8-bit parallel, LCD_CAM i80, 16 MHz) | D0–D7 = GPIO 6,14,7,12,9,11,8,10; CL(XCL) 16, LE(XLE) 15, SPH(XSTL) 13, SPV 17, CKV 18, OE 45, PWR 46 (M5 docs call G45 "PWR"; M5GFX: OE=45, PWR=46). No TPS65185/VCOM control. |
| Internal I2C (port 1, 400 kHz) | SDA 41, SCL 42 |
| Touch GT911 (0x5D, or 0x14) | I2C above, INT 48 (not an RTC IO: wakes light sleep only, not deep sleep), no RST pin on MCU |
| RTC BM8563 (0x51) | same I2C bus; INT is NOT routed to an MCU GPIO (feeds power circuit; unverified) |
| IMU BMI270 (0x68) | same I2C bus (unused) |
| Battery ADC | GPIO 3 (ADC1_CH2), divider ×2 |
| Charge status | GPIO 4 (CHG_STAT, low = charging) |
| USB VBUS detect | GPIO 5 (USB_DET, high = present) |
| Power hold / off | GPIO 44 (shared with UART0 RX): off = pulse low/high ×5 at 50 ms; board stays on if USB attached |
| Buzzer | GPIO 21 (passive piezo, PWM) |
| microSD (SPI) | CS 47, SCK 39, MOSI 38, MISO 40 |
| BOOT button / status LED | GPIO 0 (M5Unified drives the LED on GPIO 0; BOOT is also GPIO 0) |
| Grove port | G1 = GPIO 1, G2 = GPIO 2 |

All pins live in **one file**: `firmware/src/board.rs`.

### 7.2 Display
Preferred: use **epdiy** (C, supports ED047TC1) as an ESP-IDF component through
`[package.metadata.esp-idf-sys] extra_components` / component manager, with a custom board
definition for Paper S3, and a thin Rust FFI wrapper. Alternative: M5GFX's Paper S3 panel code as reference.
Rust side exposes:
```rust
pub trait EinkDisplay: embedded_graphics::DrawTarget<Color = Gray4> {
  fn refresh(&mut self, mode: RefreshMode, area: Option<Rectangle>);  // Full (GC16, clears ghosting), Partial (DU/fast 1-bit), Text (GL16)
  fn power_off_panel(&mut self);
}
```
Framebuffer 4 bpp in PSRAM. Policy: partial (fast) refresh for touch feedback/key presses; full
refresh on screen change every 8 partials and always before power-off.
Default orientation: **portrait 540×960**.

### 7.3 State machine
```
PowerOn → Boot splash (logo + battery) → [no vault] Setup wizard | [vault] PIN screen
PIN ok → Home  ⇄ lists/detail/approval/pairing/settings
Idle timeout (Settings.auto_lock_secs, default 180) or Lock request → zeroize → draw LockScreen (full refresh) →
   Settings.sleep_mode == PowerOff  → cut power (eInk keeps image)
   Settings.sleep_mode == LightSleep → BLE advertising, ESP-IDF PM auto light-sleep; on BLE connect show PIN screen
On battery, locked and no BLE connection for 10 min in LightSleep mode → PowerOff anyway.
```
Setup wizard: choose PIN (twice) → generate seed → show 24 words (3 pages, 8 words each, large font) →
verify 3 random words → optional recovery passphrase is set later from companion → Home.

### 7.4 Concurrency
FreeRTOS threads (std::thread): `ui` (owns display+touch), `ble`, `usb`; one `core` actor owning
the unlocked vault, receiving `CoreCommand` over `std::sync::mpsc` and asking the UI for approvals
(UI → approval result channel). Approval requests are serialized (one at a time).

### 7.5 Storage
* NVS namespace `prism`: device Noise static key, paired hosts, PIN fail counter, settings, last-used time, battery-at-shutdown.
* Raw data partition `vault` (2 × 512 KiB A/B slots): `[u32 len][u64 generation][u32 crc32][VaultFile bytes]`;
  write the inactive slot, pick the highest valid generation on load.
* `partitions.csv` in firmware/.

### 7.6 USB composite (TinyUSB via `espressif/esp_tinyusb` component)
CDC-ACM (Prism protocol) + HID FIDO (usage page 0xF1D0, usage 0x01, 64-byte reports) + HID Keyboard.
Feature flag `jtag-console` keeps the USB-Serial-JTAG for logs during development (disables TinyUSB).

### 7.7 BLE
NimBLE through the `esp32-nimble` crate (or esp-idf-svc BLE if better). Services: Prism (§5.1),
FIDO (0xFFFD: fidoControlPoint `F1D0FFF1-…`, fidoStatus `F1D0FFF2-…`, fidoControlPointLength `F1D0FFF3-…`,
fidoServiceRevisionBitfield `F1D0FFF4-…`), Battery Service 0x180F, Device Information 0x180A.

### 7.8 Build
`firmware/rust-toolchain.toml` → channel `esp`. `.cargo/config.toml` target `xtensa-esp32s3-espidf`,
linker `ldproxy`, runner `espflash flash --monitor`. `sdkconfig.defaults`: PSRAM octal, 240 MHz, BT NimBLE,
PM + tickless idle, TinyUSB, 16 MB flash, custom partitions. Depends on `prism-core`, `prism-proto`,
`prism-ctap`, `prism-ui` via path.

---

## 8. eInk UI (prism-ui)

Host-testable crate, depends only on `embedded-graphics` (+ fonts: `u8g2-fonts` or `embedded-graphics` mono, + `qrcodegen` optional) and `prism-core` model.
```rust
pub struct Ui { /* screen stack, state */ }
pub enum UiEvent { Touch(TouchEvent), Tick { unix: u64 }, Approval(ApprovalRequest), Battery(u8, bool), Locked, ... }
pub enum UiAction { None, Redraw(RefreshMode), SubmitPin(Zeroizing<String>), Approve(u32), Deny(u32), Lock, PowerOff, StartPairing, ConfirmPairing, TypeEntry(EntryId, SecretField), RevealSecret(EntryId, SecretField), FinishSetup{pin, }, ... }
impl Ui { pub fn handle(&mut self, ev: UiEvent) -> Vec<UiAction>; pub fn draw<D: DrawTarget<Color=Gray4>>(&self, d: &mut D); }
```
Screens: Splash, Lock (off screen), PinPad (big 3×4 keys, masked dots, attempts left), SetupWizard
(PIN, seed words, verify), Home (category tiles with counts: Passwords, TOTP, Passkeys, SSH, Recovery, Settings),
List (paginated — eInk: no scroll, big ◀ ▶ buttons, 8 rows/page), Detail (fields; Reveal shows secret
in large monospace; Type via USB), TOTP (huge digits, coarse progress bar, refresh at period boundary),
Approval (title, requester, entry, context/host, big Approve/Deny, countdown), PairingSas (6 big digits),
Settings (auto-lock, sleep mode, keyboard layout, paired hosts, pair new host, wipe), Status bar
(battery, BLE/USB icons, lock, time). High contrast, large touch targets (≥ 80 px), no animations.
Tests render every screen to PNG under `crates/prism-ui/snapshots/` (via `image` crate, dev-dependency).

---

## 9. Host side

### 9.1 prism-client
`Transport` trait (`send_frame`, `recv_frame` async with tokio). Impl: `BleTransport` (btleplug,
scan for Prism service UUID), `UsbTransport` (serialport, find CDC by VID/PID). `Client` = transport + `HostSession`,
with typed async methods mirroring `Request`. Host key stored in `~/.config/prism/host_key` (0600) or OS keychain (`keyring` crate) when available.

### 9.2 prism-cli (`prism`)
Subcommands: `pair`, `info`, `time-sync`, `ls [--kind]`, `show <id|name> [--field]`, `add password|totp|recovery|ssh-import <file>`,
`ssh-gen <name>`, `totp <name>`, `rm`, `export <file>`, `import <file>`, `settings`, `agent [--socket PATH]`,
`agent install` (writes launchd plist on macOS / systemd user unit on Linux).
`prism agent`: ssh-agent protocol on a Unix socket (use `ssh-agent-lib` or hand-written codec).
Handles `REQUEST_IDENTITIES` (cached from `SshListKeys`), `SIGN_REQUEST` (→ `SshSign`), and the
`session-bind@openssh.com` extension: resolve the bound host key against `~/.ssh/known_hosts` to produce `host_hint`
(e.g. "github.com"). SSH key import: parse OpenSSH private key on host (`ssh-key` crate, decrypt if needed), send raw Ed25519 seed in `AddEntry`.

### 9.3 prism-wasm / prism-ffi (JSON bridges)
Both expose the same minimal API; `Request`/`Response` cross the boundary as **serde_json** strings
(serde externally-tagged enums; byte arrays as arrays of numbers):
```
generateHostKey() -> {private: bytes, public: bytes}
new Session(hostPrivateKey)
session.start() -> frameBytes
session.onFrame(frameBytes) -> JSON SessionEvent
session.sas() -> string | null
session.encryptRequest(jsonRequest) -> frameBytes
bleChunk(frame, mtu) -> bytes[] ; new BleReassembler().push(chunk) -> frame | null
cdcEncode(frame) -> bytes ; new CdcDecoder().push(bytes) -> frames[]
parseOtpauth(uri) -> JSON Totp ; totpNow(jsonTotp, unix) -> string   (for previews)
```

### 9.4 Web app (apps/web)
Vite + TypeScript (no heavy framework; lit or vanilla web components). Web Bluetooth (Prism service) and
Web Serial (USB CDC). Pages: Connect/Pair (shows SAS), Entries (list/filter by kind), Add/Edit forms
(password generator, TOTP via otpauth URI or QR image upload → `jsQR`), SSH keys (generate, import, copy public key),
Export/Import, Device settings, Paired hosts. Host key in IndexedDB.

### 9.5 Apple (apps/apple)
XcodeGen `project.yml`; targets: `Prism` (iOS 17+), `PrismMac` (macOS 14+, menu-bar), `PrismCredentialProvider`
(iOS/macOS AutoFill extension: passwords, passkeys via `ASPasskeyCredentialRequest` — translate to CTAP2 and use `Request::Ctap`,
one-time codes on iOS 18+). CoreBluetooth transport in Swift; protocol/session via `PrismFFI.xcframework` built by
`crates/prism-ffi/build-xcframework.sh`. Host key in Keychain (shared access group between app and extension).

---

## 10. Testing expectations
* `cargo test --workspace` must pass on macOS host.
* prism-core: RFC 6238 vectors, BIP39 vectors, vault round-trip, wrong PIN, slot add/remove, export round-trip.
* prism-proto: full Host↔Device handshake in-memory, SAS equality, chunk/reassemble fuzz-ish tests (proptest), COBS round-trip.
* prism-ctap: MakeCredential→GetAssertion round trip with a mock Platform, signature verification with `p256`, CTAPHID fragmentation.
* prism-ui: render all screens to PNG snapshots.
* firmware: `cargo build --release` succeeds with the esp toolchain.
