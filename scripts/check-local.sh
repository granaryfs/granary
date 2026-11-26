#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

# Run from the repository root.
set -eu

if ! command -v cargo >/dev/null 2>&1; then
    printf '%s\n' 'cargo is required. Install Rust with rustup and add Cargo to PATH.' >&2
    exit 127
fi

export CARGO_BUILD_WARNINGS=deny
cargo fmt --check
cargo clippy --workspace --all-targets --locked
cargo nextest run --profile ci --locked -p granary-core -p granary-vfs
