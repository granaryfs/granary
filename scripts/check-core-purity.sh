#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# Three-layer purity gate for granary-core.
set -euo pipefail
# 1. sole-root cargo-deny: bans + no-build-scripts, unification-immune
cargo deny --locked --config deny.core.toml \
  --manifest-path crates/granary-core/Cargo.toml check bans licenses
# 2. isolated resolution: core compiles with ALL its features on — a
# feature-gated impurity must not hide behind a default-features check
cargo check -p granary-core --locked --all-features
# 3. no proc-macros anywhere in core's tree (normal+dev edges — dev-dep
# proc-macros must be visible), all targets, all features.
# Plain commands into temp files, NOT process substitution: a failing
# cargo inside <(...) is invisible to set -e and diff would happily
# compare two empty streams and report "no proc-macros".
tree_full=$(mktemp)
tree_nopm=$(mktemp)
trap 'rm -f "$tree_full" "$tree_nopm"' EXIT
cargo tree --locked -p granary-core -e normal,dev --target all \
  --all-features --prefix none > "$tree_full"
cargo tree --locked -p granary-core -e normal,dev,no-proc-macro --target all \
  --all-features --prefix none > "$tree_nopm"
[ -s "$tree_full" ] || { echo "ERROR: empty cargo tree output (full)" >&2; exit 1; }
[ -s "$tree_nopm" ] || { echo "ERROR: empty cargo tree output (no-proc-macro)" >&2; exit 1; }
if ! diff "$tree_full" "$tree_nopm" >/dev/null; then
  echo "ERROR: proc-macro found in granary-core dependency tree" >&2; exit 1
fi
echo "core purity: ok"
