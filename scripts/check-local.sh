#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

set -eu

if ! command -v cargo >/dev/null 2>&1; then
    printf '%s\n' 'cargo is required. Install Rust with rustup and add Cargo to PATH.' >&2
    exit 127
fi

if (( $# != 0 )); then
    printf 'Unexpected argument: %s\nUsage: check-local.sh\n' "$1" >&2
    exit 2
fi

script=${BASH_SOURCE[0]}
[[ $script == */* ]] || script=./$script
CDPATH='' cd -- "${script%/*}/.."
exec cargo run --quiet --locked --package xtask -- check
