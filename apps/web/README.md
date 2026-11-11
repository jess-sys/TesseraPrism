# Prism web companion

Vite + TypeScript (strict, no UI framework) companion app for the Prism hardware password
manager. It talks to the device over **Web Bluetooth** (primary) or **Web Serial / USB CDC**
(fallback). All protocol framing, Noise encryption and JSON encoding happen in `prism-wasm`
(`crates/prism-wasm`, see `docs/ARCHITECTURE.md` §5 and §9.3-9.4).

Browser requirement: **Chrome or Edge** (desktop, or Android for Bluetooth), served from
`https://` or `http://localhost`.

## Run

```sh
cd apps/web
npm install
npm run dev        # http://127.0.0.1:5173
npm run build      # typecheck + production build into dist/
npm test           # vitest unit tests
```

### Building the wasm core

The app loads `src/wasm/pkg/prism_wasm.js` if it exists. Build it from the repo root:

```sh
wasm-pack build crates/prism-wasm --target web --out-dir ../../apps/web/src/wasm/pkg
```

If the pkg is missing, the app falls back to a **labelled mock core**: an in-memory fake device
with no real crypto or pairing. The banner at the top says so. Force the mock with `?mock` in the
URL (for example `http://127.0.0.1:5173/?mock#/connect`). The mock also powers the "Start demo
device" button on the Connect page.

## Layout

```
src/
  core/types.ts      PrismCore interface, model + Request/Response types (mirror model.rs, §5.3)
  core/index.ts      loadCore(): real prism-wasm (import.meta.glob) or mock fallback
  core/mock.ts       mock core, fake device, COBS and BLE chunking (real algorithms)
  transport/         Transport interface, BleTransport, SerialTransport
  client.ts          PrismClient: handshake, SAS/pairing, request ids, 60 s timeout, typed API
  keys/openssh.ts    minimal OpenSSH parser (unencrypted Ed25519 only)
  storage/hostkey.ts host key in IndexedDB
  util/              password generator, clipboard with 30 s auto-clear
  pages/             connect, pair, entries, entry-detail, entry-forms, transfer, settings
  ui/dom.ts          small DOM helpers (no innerHTML with data)
  styles/main.css    light/dark via prefers-color-scheme
tests/               vitest: OpenSSH parser, request JSON encoding, framing, mock e2e
```

## Pairing

1. On the device: Settings, then Pair new host.
2. In the app: Pair this browser, then choose Bluetooth or USB.
3. Both screens show the same 6-digit SAS. Confirm on the device.

The app sends `GetInfo` after the handshake. In pairing mode the device answers with
`Paired { label }` once confirmed. Outside pairing mode, a host the device does not know gets
`NotPaired`, and the app sends you to the pairing page.

## Protocol notes (rev 2)

* `Export { passphrase }`: the device verifies the passphrase against the recovery slot and
  encrypts the export with it. Device settings sets the recovery passphrase with
  `SetRecoveryPassphrase` (tap, minimum 8 characters). Export returns `Unsupported` until one is set.
* `GetEntry { id }` returns the full entry (approval per policy). The edit forms use it, so an edit
  needs one tap. Recovery-code used state comes from the same response.
* `GenerateSshKey` returns `SshKeys([key])`, which the SSH page shows directly.
* BLE chunking passes the ATT MTU (default 185, configurable in `BleTransport`) to `bleChunk`,
  which subtracts 3 internally as the wasm doc specifies.

## Known gaps

* **Passkeys** are listed and can be deleted, but not created or edited from the web app.
* **SSH import** parses the key in TypeScript. The imported seed is zeroed after the `AddEntry`
  call, but it does pass through JS memory. Encrypted keys are rejected with an `ssh-keygen -p` hint.
* **Clipboard auto-clear** is best effort. The app clears the clipboard after 30 s only if it was
  the last writer, and the timer is lost if the tab closes.
* **TOTP countdown** fetches a new code on expiry. With approval policy `Always`, each new code
  needs a tap, so the UI waits for a click instead of fetching automatically.
* **Web Bluetooth and Web Serial** are not exercised against real hardware here. The framing
  paths they use are covered by tests against the mock core.
