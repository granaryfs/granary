#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Opt-in pjdfstest executable wrapper: report successful unlink without doing it."""

import json
import os
from pathlib import Path
import sys


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "unlink":
        target = Path(args[1])
        # Witness the injection only for an existing ordinary file. The
        # following lstat assertion must then see that same file still there.
        if target.is_file() and not target.is_symlink():
            with open(os.environ["POSIX_UNLINK_WITNESS"], "a") as stream:
                stream.write(json.dumps(dict(operation="unlink", path=str(target.resolve()))) + "\n")
            print("0")
            return 0
    os.execv(os.environ["POSIX_PJD_REAL"], [os.environ["POSIX_PJD_REAL"], *args])


if __name__ == "__main__":
    sys.exit(main())
