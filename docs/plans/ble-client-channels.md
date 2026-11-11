# Plan: per-client channels on the Prism BLE transport

Status: proposed (2026-11-11). Interim mitigation shipped: firmware lets a new Noise msg1 replace the
link's session ("newest wins"); the macOS app re-handshakes after idle and releases the BLE link after
8 s of inactivity.

## Problem

The device keeps one Noise session per transport link (`Link::Ble(conn_handle)` / `Link::Usb`).
On macOS (and iOS), CoreBluetooth multiplexes **every process** of the host onto one physical LE link:
the Prism app, its AutoFill extension, a second app instance and the `prism` CLI/agent all share
the same connection handle, the same RX writes and the same TX notifications. Consequences seen on
hardware:

* a second client's handshake clobbers the first client's session (formerly "bad frame", now
  "newest wins" which makes the older client time out until it re-handshakes);
* chunked writes from two processes interleave on RX, corrupting the device-side reassembly;
* every subscribed process receives every TX notification, including frames for other clients.

## Design

Add a **channel id** chosen by each client, carried in every BLE chunk, so the device can keep one
session (and one reassembler) per `(conn_handle, channel)` and address replies to a channel.

### Framing v2 (BLE only; USB CDC is single-client and unchanged)

```
first chunk:  [hdr u8][chan u32 LE][total_len u16 LE][body…]
next chunks:  [hdr u8][chan u32 LE][body…]
hdr: bit7 = more-follows, bit6 = 1 (v2 marker), bits0-5 = seq (mod 64)
```

* `chan`: random non-zero u32 picked by the client per process/session (CSPRNG). Not secret; it is
  a routing tag — authentication still comes from Noise.
* Max chunk body shrinks by 4 bytes (`ATT_MTU - 3 - 1 - 4`, first chunk `- 2` more).
* v1 chunks (bit6 = 0) keep working during migration and map to `chan = 0`.

### Device

* `TransportEvent::PrismFrame { link, frame }` → `link: Link::Ble { conn, chan }`; reassemblers keyed
  by `(conn, chan)`; `TransportCommand::PrismFrame` carries the same link and the TX chunks echo `chan`.
* Core sessions keyed by the full link: independent sessions per client; drop the "newest wins" rule
  for v2 channels (keep it for `chan = 0`).
* Limits: max 4 channels per connection, 8 total; LRU-evict idle channels (no frame for 5 min) and
  drop all channels of a connection on disconnect. Pending approvals are bound to their channel.
* Pairing is unchanged (per host static key); several channels may belong to the same host.

### Hosts

* `prism-proto::ble`: `chunk_v2(frame, att_mtu, chan)`, `Reassembler` filters chunks whose `chan`
  differs from its own (other processes' traffic is ignored instead of corrupting reassembly).
* `prism-client` (CLI/agent), `prism-wasm`/web, `prism-ffi`/Swift: generate a channel per session and
  use v2 framing. Swift: one channel per `PrismClient`; the AutoFill extension gets its own.
* `GetInfo` reports `ble_framing: [1, 2]` so hosts can fall back to v1 against old firmware.

### Testing

* prism-proto: proptests for v2 chunk/reassemble with interleaved chunks from 2–4 channels and
  foreign-channel filtering.
* Firmware (host-testable core logic): two channels on one link complete independent handshakes and
  requests; eviction; approval bound to channel.
* Hardware: Prism app + AutoFill extension + `prism agent` concurrently on one Mac; webauthn.io
  registration while the app is open.

### Rollout

1. ~~prism-proto v2 framing + tests (backward-compatible decode of v1).~~ **Done** (2026-11-11: `ble::chunk_v2`, `chunk_channel`, `random_channel`, `Reassembler::new_channel`, `ChannelReassembler`, `chunk_for`; bridged in prism-wasm/prism-ffi).
2. ~~Firmware: per-channel reassembly/sessions.~~ **Done** (2026-11-11: `Link::Ble{conn,chan}`, `ChannelReassembler(4)` per connection, PrismClosed on eviction/disconnect, 8-session LRU cap; no `GetInfo` advertisement: device accepts v1+v2, hosts just use v2).
3. Hosts switch to v2 when the device advertises it.
4. Remove the interim "newest wins" behaviour for v2 channels; keep the app's idle release as a
   power-saving measure.

Estimated effort: ~1 day across crates, mostly mechanical; the risk is in firmware memory (4–8 extra
Noise states ≈ a few KB each in PSRAM — fine).
