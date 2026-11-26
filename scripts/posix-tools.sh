#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ $# -eq 1 && "$1" == /* && ! -e "$1" ]] || {
  echo 'posix-tools: refused -- needs one new absolute installation directory' >&2
  exit 1
}
tools="$1"
mkdir -p "$tools"
git clone https://github.com/pjd/pjdfstest.git "$tools/pjdfstest"
git -C "$tools/pjdfstest" checkout --detach 85a8aea9e685999ef0540392fd80535f873d7ff7
git clone https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git "$tools/xfstests"
git -C "$tools/xfstests" checkout --detach 3d57f543ae0c149eb460574dcfb8d688aeadbfff
cd "$tools/pjdfstest"
autoreconf -ifs
./configure
make -j2 pjdfstest
cd "$tools/xfstests"
make -j2
