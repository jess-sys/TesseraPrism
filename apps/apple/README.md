# Prism for Apple platforms

SwiftUI app (iOS 17+ / macOS 14+, with a menu-bar extra on macOS) and an AutoFill credential provider
extension (passwords, passkeys, one-time codes) for the Prism hardware password manager.

```
PrismKit/            SwiftPM: models (serde-compatible Codable), PrismCore protocol + StubCore, BLE chunking,
                     CBOR + CTAP2 helpers, CoreBluetooth transport, async PrismClient, Keychain host key store
Shared/              PrismFFICore adapter (#if canImport(PrismFFI)), PrismConnection helper (app + extension)
Prism/               SwiftUI app (iOS + macOS)
CredentialProvider/  ASCredentialProviderViewController extension (iOS + macOS)
project.yml          XcodeGen spec; generate.sh wraps it
```

## Setup

1. Install Xcode 16+ (App Store) and select it: `sudo xcode-select -s /Applications/Xcode.app`.
2. `brew install xcodegen`
3. (Optional but required for a real, encrypted session) build the Rust bridge:
   `crates/prism-ffi/build-xcframework.sh` -> `crates/prism-ffi/out/PrismFFI.xcframework`.
   Without it the apps build against `StubCore` (no Noise, no encryption; UI/testing only).
4. `cp Local.xcconfig.example Local.xcconfig` and set `PRISM_TEAM_ID` to your Apple Developer Team ID (needed for the
   app group, keychain group and the AutoFill entitlement). `Local.xcconfig` is git-ignored; `generate.sh` creates it
   from the example (with a warning) if missing. Optionally change the bundle ID prefix `ch.neutheria` (in
   `project.yml`, `HostKeyStore.swift`, and the entitlements/UTType ids) to one you own.
   Then `./generate.sh` (links the xcframework if present) and `open Prism.xcodeproj`.
5. Run Prism-iOS on a device (CoreBluetooth does not work in the simulator) or Prism-macOS.
   Enable the extension: iOS Settings > General > AutoFill & Passwords > Prism; macOS System Settings > Passwords > Options.

Tests: `cd PrismKit && swift test` (and `cd PrismFFIKit && swift test`).
Command-line builds (no signing):
`xcodebuild -project Prism.xcodeproj -scheme Prism-iOS -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build`
(also `Prism-macOS` with `-destination platform=macOS`, `CredentialProvider-iOS`, `CredentialProvider-macOS`).

## Pairing

On the device: Settings > Pair new host. In the app tap "Pair with Prism": the 6-digit SAS is displayed; compare it
with the device and tap Confirm on the device. The host static key lives in the Keychain (access group
`group.ch.neutheria.prism` on iOS / `<TeamID>.ch.neutheria.prism` on macOS, shared with the extension).

## FFI linking

`PrismFFIKit/` is a small local SwiftPM package: binary target `PrismFFIBinary` =
`../../crates/prism-ffi/out/PrismFFI.xcframework`, plus Swift target `PrismFFI` whose only source is a symlink to the
UniFFI-generated `../../crates/prism-ffi/out/PrismFFI.swift`. `generate.sh` adds the package to the app and extension
targets when both files exist (rebuild with `crates/prism-ffi/build-xcframework.sh`); `Shared/PrismFFICore.swift`
then adapts it to `PrismCore` (`#if canImport(PrismFFI)`), otherwise StubCore is used. `bleChunk` takes the ATT MTU, so the
adapter passes `maximumWriteValueLength + 3`. The simulator slice is arm64 only (x86_64 simulator excluded).
FFI tests: `cd PrismFFIKit && swift test`.

## Known risk: BLE inside an AutoFill extension

Extensions are short-lived, memory-limited and may be suspended or killed while waiting for the user; a cold BLE
scan + Noise handshake + user tap on the device (up to 30 s) can exceed the window, and background BLE is not available.
Mitigations implemented/planned:

* The last peripheral identifier is cached in the shared app group (`PairedDeviceStore`) and the transport uses
  `retrievePeripherals(withIdentifiers:)` + direct `connect` instead of scanning (fast reconnect, falls back to scan).
* One connection per request, closed right after completion; no work before the sheet is shown.
* `provideCredentialWithoutUserInteraction` always fails with `userInteractionRequired` (the device needs a tap anyway),
  so the system shows the sheet immediately.
* The host key and "paired" flag are shared, so the extension never repeats pairing.
* If the extension proves too unreliable, a fallback is to have the main app hold the BLE session and relay requests
  through an app-group XPC/Darwin-notification bridge (not implemented).

Other limitations: passkey credential identities are not registered in `ASCredentialIdentityStore` (the protocol's
`EntrySummary` has no credential id), so passkeys are offered via the provider picker rather than QuickType.
