#!/usr/bin/env bash
# Build PrismFFI.xcframework (static libs + UniFFI headers) and the Swift bindings (PrismFFI.swift).
#
# Output:
#   crates/prism-ffi/out/PrismFFI.xcframework
#   crates/prism-ffi/out/PrismFFI.swift
#
# Slices: iOS device (aarch64-apple-ios), iOS simulator (aarch64-apple-ios-sim),
# macOS (aarch64-apple-darwin, plus x86_64-apple-darwin lipo'd in when that target is installed).
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$CRATE_DIR/../.." && pwd)"   # cargo workspace root (target/ lives here)
OUT="$CRATE_DIR/out"
LIB_NAME="libprism_ffi.a"
FFI_MODULE="PrismFFIFFI"                 # default for uniffi module_name = "PrismFFI"
IOS_MIN="17.0"
MACOS_MIN="14.0"

# Load cargo if it is installed via rustup and not already on PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
command -v cargo >/dev/null || { echo "error: cargo not found" >&2; exit 1; }
command -v xcodebuild >/dev/null || { echo "error: xcodebuild not found" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/prism-ffi.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

INSTALLED_TARGETS="$(rustup target list --installed 2>/dev/null || true)"
REQUIRED_TARGETS="aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin"
OPTIONAL_TARGETS="x86_64-apple-darwin"

cd "$ROOT"

echo "==> Ensuring rustup targets"
for t in $REQUIRED_TARGETS; do
  rustup target add "$t"
done
HAVE_X86=0
if echo "$INSTALLED_TARGETS" | grep -qx "x86_64-apple-darwin"; then
  HAVE_X86=1
fi

echo "==> Building static libraries (release)"
for t in $REQUIRED_TARGETS; do
  IPHONEOS_DEPLOYMENT_TARGET="$IOS_MIN" MACOSX_DEPLOYMENT_TARGET="$MACOS_MIN" \
    cargo build --release -p prism-ffi --lib --target "$t"
done
if [ "$HAVE_X86" = 1 ]; then
  MACOSX_DEPLOYMENT_TARGET="$MACOS_MIN" cargo build --release -p prism-ffi --lib --target x86_64-apple-darwin
fi

echo "==> Generating Swift bindings from the host cdylib"
MACOSX_DEPLOYMENT_TARGET="$MACOS_MIN" cargo build --release -p prism-ffi --lib --target aarch64-apple-darwin
HOST_DYLIB="$ROOT/target/aarch64-apple-darwin/release/libprism_ffi.dylib"
BINDINGS="$WORK/bindings"
mkdir -p "$BINDINGS"
cargo run --release -q -p prism-ffi --bin uniffi-bindgen -- \
  generate --library "$HOST_DYLIB" --language swift --out-dir "$BINDINGS"

[ -f "$BINDINGS/PrismFFI.swift" ] || { echo "error: PrismFFI.swift not generated" >&2; exit 1; }
[ -f "$BINDINGS/${FFI_MODULE}.h" ] || { echo "error: ${FFI_MODULE}.h not generated" >&2; exit 1; }

# Headers directory for xcodebuild: the C header plus a module.modulemap that exposes it as ${FFI_MODULE}.
HEADERS="$WORK/headers"
mkdir -p "$HEADERS"
cp "$BINDINGS/${FFI_MODULE}.h" "$HEADERS/"
cp "$BINDINGS/${FFI_MODULE}.modulemap" "$HEADERS/module.modulemap"

# Universal (lipo) macOS library if x86_64 is available; otherwise the arm64 library alone.
MACOS_LIB="$WORK/macos/$LIB_NAME"
mkdir -p "$WORK/macos"
if [ "$HAVE_X86" = 1 ]; then
  echo "==> lipo macOS arm64 + x86_64"
  lipo -create -output "$MACOS_LIB" \
    "$ROOT/target/aarch64-apple-darwin/release/$LIB_NAME" \
    "$ROOT/target/x86_64-apple-darwin/release/$LIB_NAME"
else
  echo "==> x86_64-apple-darwin not installed; macOS slice is arm64 only"
  cp "$ROOT/target/aarch64-apple-darwin/release/$LIB_NAME" "$MACOS_LIB"
fi

echo "==> Creating xcframework"
mkdir -p "$OUT"
rm -rf "$OUT/PrismFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$ROOT/target/aarch64-apple-ios/release/$LIB_NAME" -headers "$HEADERS" \
  -library "$ROOT/target/aarch64-apple-ios-sim/release/$LIB_NAME" -headers "$HEADERS" \
  -library "$MACOS_LIB" -headers "$HEADERS" \
  -output "$OUT/PrismFFI.xcframework"

cp "$BINDINGS/PrismFFI.swift" "$OUT/PrismFFI.swift"

echo "==> Done"
echo "    $OUT/PrismFFI.xcframework"
echo "    $OUT/PrismFFI.swift"
