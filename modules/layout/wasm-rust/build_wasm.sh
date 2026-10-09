#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CRATE_DIR="$ROOT/modules/layout/wasm-rust"
OUT_DIR="$ROOT/modules/frontend/html/wasm"

mkdir -p "$OUT_DIR"

export CARGO_TARGET_DIR="$ROOT/modules/layout/target"

cargo build \
  --manifest-path "$CRATE_DIR/Cargo.toml" \
  --release \
  --target wasm32-unknown-unknown

WASM_FILE="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/adalanche_layout_engine_rust.wasm"

WASM_BINDGEN_BIN="${WASM_BINDGEN_BIN:-$HOME/.cargo/bin/wasm-bindgen}"

"$WASM_BINDGEN_BIN" \
  --target no-modules \
  --out-dir "$OUT_DIR" \
  --out-name layout-engine-rust \
  "$WASM_FILE"

echo "generated: $OUT_DIR/layout-engine-rust.js"
echo "generated: $OUT_DIR/layout-engine-rust_bg.wasm"
