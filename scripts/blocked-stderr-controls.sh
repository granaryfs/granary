#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# Build each single-site inverse in a separate scratch source tree. The real
# sources are read only; patch never runs with the checkout as its directory.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
[ "$#" -eq 1 ] || { echo 'usage: blocked-stderr-controls.sh NEW_OUTPUT_DIRECTORY' >&2; exit 2; }
OUT="$1"
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo 'control output must be fresh' >&2; exit 2; }
parent="$(cd "$(dirname "$OUT")" && pwd -P)"
OUT="$parent/$(basename "$OUT")"
case "$OUT" in
  "$ROOT"|"$ROOT"/*) echo 'control sources must be outside the checkout' >&2; exit 2 ;;
esac
mkdir -m 700 "$OUT"
OUT="$(cd "$OUT" && pwd -P)"
# Cargo fingerprints each distinct scratch manifest. Sharing the dependency
# cache does not share source files or overwrite the staged fixed executable.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$OUT/target}"
for site in mount refusal panic snapshot; do
  copy="$OUT/source-$site"
  mkdir "$copy"
  cp "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$ROOT/rust-toolchain.toml" "$ROOT/clippy.toml" "$copy/"
  cp -R "$ROOT/crates" "$ROOT/.cargo" "$copy/"
  patch --batch --fuzz=0 -d "$copy" -p1 <"$ROOT/scripts/blocked-stderr-controls/$site.patch"
  cargo build --locked --manifest-path "$copy/Cargo.toml" -p granary-cli --bin gran --features conformance-breakage
  cp "$CARGO_TARGET_DIR/debug/gran" "$OUT/gran-$site"
  echo "STDERR-CONTROL-BUILD: $site OK"
done
