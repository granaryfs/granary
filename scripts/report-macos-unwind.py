#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Report the native unwind sections of the weekly Nextest build's executables."""

import json
from pathlib import Path
import platform
import subprocess
import sys


MIB = 1024 * 1024
COMPACT_UNWIND_LIMIT = 16 * MIB


def test_artifacts(log):
    artifacts = {}
    built = False
    with log.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                if not built and not line.endswith("\n"):
                    break
                raise
            if message["reason"] == "build-finished":
                built = message["success"]
            if (message["reason"] == "compiler-artifact"
                    and message["profile"]["test"] and message["executable"]):
                target = message["target"]
                artifacts[Path(message["executable"])] = (target["name"], target["kind"])
    return built, artifacts


def unwind_bytes(executable, architecture):
    output = subprocess.run(
        ["xcrun", "size", "-m", "-arch", architecture, str(executable)],
        check=True, capture_output=True, text=True,
    ).stdout
    seen_text = False
    in_text = False
    for line in output.splitlines():
        fields = line.split()
        if fields[:1] == ["Segment"]:
            in_text = fields[1] == "__TEXT:"
            seen_text |= in_text
        if in_text and fields[:2] == ["Section", "__eh_frame:"]:
            return int(fields[2])
    if not seen_text:
        raise ValueError(f"missing __TEXT segment in {executable.name}")
    return 0


def report(log):
    print("### macOS test binary unwind sections\n")
    built, artifacts = test_artifacts(log)
    if not built:
        print("The report requires a completed Cargo build.")
        return

    servers = [path for path, (name, kinds) in artifacts.items()
               if name == "granary_server" and "lib" in kinds]
    if len(servers) != 1:
        raise ValueError(f"expected one granary-server library test, found {len(servers)}")

    architecture = platform.machine()
    sizes = {path: unwind_bytes(path, architecture) for path in artifacts}
    largest = max(sizes, key=lambda path: (sizes[path], path.name))
    print(f"Measured {len(sizes)} {architecture} test executables.\n")
    print("| Executable | `__TEXT,__eh_frame` | Headroom to 16 MiB |")
    print("| --- | ---: | ---: |")
    for label, path in (("Server library", servers[0]), ("Workspace maximum", largest)):
        size = sizes[path]
        headroom = (COMPACT_UNWIND_LIMIT - size) / MIB
        print(f"| {label} (`{path.name}`) | {size:,} bytes ({size / MIB:.2f} MiB) | {headroom:+.2f} MiB |")


if __name__ == "__main__":
    report(Path(sys.argv[1]))
