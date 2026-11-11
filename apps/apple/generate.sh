#!/usr/bin/env bash
# Generates Prism.xcodeproj. Enables the PrismFFI.xcframework dependency only if it was built.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -f Local.xcconfig ]; then
  cp Local.xcconfig.example Local.xcconfig
  echo "WARNING: created Local.xcconfig from Local.xcconfig.example with a placeholder team ID." >&2
  echo "         Edit apps/apple/Local.xcconfig and set PRISM_TEAM_ID to your Apple Developer Team ID, then re-run ./generate.sh." >&2
fi
OUT=../../crates/prism-ffi/out
if [ -d "$OUT/PrismFFI.xcframework" ] && [ -f "$OUT/PrismFFI.swift" ]; then
  echo "Linking $OUT/PrismFFI.xcframework via PrismFFIKit"
  sed 's/#FFI //' project.yml > project.generated.yml
else
  echo "PrismFFI.xcframework/PrismFFI.swift not found (run crates/prism-ffi/build-xcframework.sh) - building with the insecure StubCore"
  cp project.yml project.generated.yml
fi
xcodegen generate --spec project.generated.yml --project .
rm -f project.generated.yml
