#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# Build each single-site inverse in a separate scratch source tree. The real
# sources are read only; patch never runs with the checkout as its directory.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
if [ "${1:-}" = '--self-test' ]; then
  [ "$#" -eq 2 ] || { echo 'usage: blocked-stderr-controls.sh --self-test NEW_OUTPUT_DIRECTORY' >&2; exit 2; }
  self_test=1
  OUT="$2"
else
  [ "$#" -eq 1 ] || { echo 'usage: blocked-stderr-controls.sh NEW_OUTPUT_DIRECTORY' >&2; exit 2; }
  self_test=0
  OUT="$1"
fi
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
copy_sources() {
  local copy="$1"
  mkdir "$copy"
  cp "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$ROOT/rust-toolchain.toml" "$ROOT/clippy.toml" "$copy/"
  cp -R "$ROOT/crates" "$ROOT/xtask" "$ROOT/.cargo" "$copy/"
}
if [ "$self_test" -eq 1 ]; then
  copy="$OUT/source-self-test"
  copy_sources "$copy"
  cargo metadata --format-version 1 --no-deps --locked --manifest-path "$copy/Cargo.toml" |
    python3 -I -c 'import json, pathlib, sys
data = json.load(sys.stdin)
root = pathlib.Path(sys.argv[1]).resolve()
def is_xtask_manifest(package):
    return pathlib.Path(package["manifest_path"]).resolve() == root / "xtask/Cargo.toml"
def staged_xtask_present(record):
    return (pathlib.Path(record["workspace_root"]).resolve() == root
            and any(is_xtask_manifest(package) and package["name"] == "xtask"
                    and package["id"] in record["workspace_members"]
                    for package in record["packages"]))
assert staged_xtask_present(data)
xtask_ids = {package["id"] for package in data["packages"] if is_xtask_manifest(package)}
assert len(xtask_ids) == 1
without_xtask = dict(data, workspace_members=[member for member in data["workspace_members"]
                                              if member not in xtask_ids])
assert not staged_xtask_present(without_xtask)
wrong_name = dict(data, packages=[dict(package, name="not-xtask") if is_xtask_manifest(package)
                                  else package for package in data["packages"]])
assert not staged_xtask_present(wrong_name)
wrong_root = dict(data, workspace_root=str(root / "other"))
assert not staged_xtask_present(wrong_root)' "$copy"
  echo 'STDERR-CONTROL-COPY: workspace metadata includes xtask'
  echo 'STDERR-CONTROL-COPY: missing xtask member, wrong name, and wrong root are refused'
  exit 0
fi
for site in mount refusal panic snapshot; do
  copy="$OUT/source-$site"
  copy_sources "$copy"
  patch --batch --fuzz=0 -d "$copy" -p1 <"$ROOT/scripts/blocked-stderr-controls/$site.patch"
  cargo build --locked --manifest-path "$copy/Cargo.toml" -p granary-cli --bin gran --features conformance-breakage
  cp "$CARGO_TARGET_DIR/debug/gran" "$OUT/gran-$site"
  echo "STDERR-CONTROL-BUILD: $site OK"
done
