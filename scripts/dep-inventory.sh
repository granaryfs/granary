#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# glibc language locales reorder _/space collation → perpetual CI diff
export LC_ALL=C
mkdir -p supply-chain   # first run on a clean tree
# dev edges + all features included: policy rule 6 makes dev-deps
# non-exempt, and the fips tree must not escape the inventory.
# Metadata-only — nothing is compiled.
cargo tree --locked --workspace -e normal,build,dev --all-features --target all \
  --prefix none \
  | sed -E 's| \(/[^)]*\)||; s| \(\*\)||' \
  | grep -v '^$' \
  | sort -u > supply-chain/inventory.txt
# sed strips absolute member paths (differ per machine — CI diff would be
# perpetually red) and (*) dedup markers; keeps (proc-macro).

# THE FOUR NESTED FUZZ WORKSPACES, labelled, in their own file.
#
# `--workspace` above is the ROOT workspace and sees none of them: each
# crates/*/fuzz is its own workspace with its own committed Cargo.lock.
# Nothing bumped those locks and nothing inventoried them, which is how the
# client's sat on a YANKED chacha20 0.10.1 while root held 0.10.2.
#
# A SEPARATE file, deliberately: inventory.txt is the SHIPPED graph, and
# folding ~250 fuzz-only packages into it would bury a real change to the
# thing that ships in noise from a graph nothing ships. Labelled by
# workspace, because "which of the four" is the question a reader has.
# check-inventory-fresh.sh diffs the whole supply-chain/ directory, so this
# file is covered by the same freshness gate with no change to it.
: > supply-chain/inventory-fuzz.txt
for _fuzz in crates/granary-core/fuzz crates/granary-store/fuzz crates/granary-client/fuzz crates/granary-fuse/fuzz; do
  printf '# %s\n' "$_fuzz" >> supply-chain/inventory-fuzz.txt
  cargo tree --locked --manifest-path "$_fuzz/Cargo.toml" \
    -e normal,build,dev --all-features --target all --prefix none \
    | sed -E 's| \(/[^)]*\)||; s| \(\*\)||' \
    | grep -v '^$' \
    | sort -u >> supply-chain/inventory-fuzz.txt
done
