#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

set -eu

if (( $# != 0 )); then
    printf 'Unexpected argument: %s\nUsage: check-local.sh\n' "$1" >&2
    exit 2
fi

script=${BASH_SOURCE[0]}
[[ $script == /* ]] || script=./$script
for (( links=0; links<40; links++ )); do
    [[ -L $script ]] || break
    target=$(readlink -n "$script" && printf '.') || exit $?
    target=${target%.}
    if [[ $target == /* ]]; then
        script=$target
    else
        script=${script%/*}/$target
    fi
done
if [[ -L $script ]]; then
    printf '%s\n' 'check-local.sh: too many symlinks' >&2
    exit 1
fi
CDPATH='' cd -P -- "${script%/*}/.."
if ! command -v cargo >/dev/null 2>&1; then
    printf '%s\n' 'cargo is required. Install Rust with rustup and add Cargo to PATH.' >&2
    exit 127
fi
exec cargo run --quiet --locked --package xtask -- check
