# Security policy

Tessera Prism is a password manager: security reports are very welcome.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private
[security advisory](https://github.com/jess-sys/TesseraPrism/security/advisories/new) form for this repository instead.
Include the affected component (firmware, protocol, CLI/agent, web, Apple apps), the version or
commit, and steps to reproduce. We aim to acknowledge reports within a week.

## Scope and threat model

The design, threat model and the irreversible production hardening procedure (flash encryption,
secure boot, eFuse-bound PIN key) are documented in [docs/SECURITY.md](docs/SECURITY.md).

The project is **pre-1.0 and has not been audited**. Development builds ship without flash
encryption or secure boot: do not rely on them to protect real secrets.
