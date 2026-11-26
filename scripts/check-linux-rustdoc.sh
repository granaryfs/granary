#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# Assert that successful rustdoc actually documented the Linux surface.
set -euo pipefail
check() {
  [ -f "$1/granary_fuse/fn.detach_unmount.html" ] || {
    echo 'rustdoc: granary_fuse::detach_unmount is absent; Linux surface was not documented' >&2
    return 1
  }
}
if [ "$#" -eq 1 ] && [ "$1" = --self-test ]; then
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' EXIT
  mkdir "$scratch/granary_fuse"
  touch "$scratch/granary_fuse/fn.detach_unmount.html"
  check "$scratch"
  rm "$scratch/granary_fuse/fn.detach_unmount.html"
  if check "$scratch" 2> "$scratch/diagnostic"; then
    echo 'rustdoc self-test: absent surface passed' >&2; exit 1
  fi
  grep -qF 'detach_unmount is absent' "$scratch/diagnostic"
  echo 'rustdoc self-test: 2/2 controls passed'
elif [ "$#" -eq 1 ] && [[ "$1" != -* ]]; then
  check "$1"
else
  echo 'usage: check-linux-rustdoc.sh DOC_DIRECTORY | --self-test' >&2
  exit 2
fi
