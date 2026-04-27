#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$ROOT_DIR/examples/chrome-extension-poc/pkg"
TARGET_DIR="$ROOT_DIR/target/wasm32-unknown-unknown/release"
WASM_CRATE="leansig_wasm"
SCHEME="${1:-demo}"
FEATURE_ARGS=()

cd "$ROOT_DIR"

case "$SCHEME" in
  demo)
    ;;
  production|prod|lifetime18-w2)
    FEATURE_ARGS=(--features production-lifetime-18-w2)
    ;;
  *)
    printf 'Unknown scheme "%s". Use "demo" or "production".\n' "$SCHEME" >&2
    exit 2
    ;;
esac

cargo build -p leansig-wasm --target wasm32-unknown-unknown --release "${FEATURE_ARGS[@]}"
mkdir -p "$OUT_DIR"

wasm-bindgen \
  "$TARGET_DIR/${WASM_CRATE}.wasm" \
  --out-dir "$OUT_DIR" \
  --target web \
  --out-name "leansig_wasm"

printf 'Built Chrome extension assets into %s using scheme %s\n' "$OUT_DIR" "$SCHEME"
