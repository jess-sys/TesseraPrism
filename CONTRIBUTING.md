# Contributing

Thanks for your interest in Tessera Prism!

- Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first — it is the contract between the
  firmware, the protocol crates and the companion apps. Protocol changes must update it.
- Host crates: `cargo test --workspace` must pass and `cargo clippy --workspace` must not gain new warnings.
- Firmware: `cd firmware && cargo build --release` (Xtensa `esp` toolchain via `espup`), see
  [firmware/README.md](firmware/README.md). Hardware-facing changes should say how they were tested
  on a real M5Stack Paper S3.
- Web: `npm test && npm run build` in `apps/web`. Apple: `swift test` in `apps/apple/PrismKit`.
- Keep secrets out of logs, fixtures and screenshots (use `example.com` / `example.org` data).

Contributions are dual-licensed under MIT OR Apache-2.0, like the rest of the project.
