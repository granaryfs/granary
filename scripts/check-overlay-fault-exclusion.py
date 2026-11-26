#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Refuse an ungated metrics accessor, unreadable artifact, or exported fault API."""
import re
import subprocess
import sys
from pathlib import Path

if not __debug__:
    raise SystemExit("OVERLAY-FAULT REFUSED: Python optimization is forbidden")

ACCESSOR_SOURCE = Path(__file__).resolve().parent.parent / "crates/granary-client/src/writable_start.rs"
ACCESSOR_GATE = '#[cfg(any(test, feature = "overlay-fault-tests"))]'


def inspect_accessor_gate(source):
    lines = source.splitlines()
    methods = [
        index
        for index, line in enumerate(lines)
        if line.strip() == "pub fn metrics_snapshot("
    ]
    gated = [
        index
        for index in methods
        if index > 0 and lines[index - 1].strip() == ACCESSOR_GATE
    ]
    if len(methods) != 1 or gated != methods:
        print("OVERLAY-FAULT REFUSED: metrics_snapshot source gate missing or ambiguous; cases=1")
        return 1
    print("OVERLAY-FAULT PASS: metrics_snapshot source gate present; cases=1")
    return 0


def inspect_accessor_source(path=ACCESSOR_SOURCE):
    try:
        source = Path(path).read_text()
    except (OSError, UnicodeError) as error:
        print("OVERLAY-FAULT REFUSED: cannot read metrics_snapshot source: " + type(error).__name__)
        return 2
    return inspect_accessor_gate(source)


def inspect(artifact):
    try:
        with Path(artifact).open("rb") as source:
            if not source.read(1):
                raise ValueError("empty artifact")
        result = subprocess.run(["nm", "-g", str(artifact)], capture_output=True, text=True, check=False)
    except (OSError, ValueError) as error:
        print("OVERLAY-FAULT REFUSED: cannot read artifact or symbols: " + type(error).__name__)
        return 2
    if result.returncode != 0:
        print("OVERLAY-FAULT REFUSED: symbol reader failed")
        return 2
    symbols = result.stdout.splitlines()
    client = [line for line in symbols if "granary_client" in line and re.search(r"\b[ABCDGIRSTVW]\b", line)]
    if not client:
        print("OVERLAY-FAULT REFUSED: no client symbols inspected")
        return 2
    armed = [line for line in client if re.search(r"FaultControl.*(?:3arm|5fired|6resume|10trace_sync|10sync_fired|10sync_point|22rename_directory_point)", line)]
    if armed:
        print(f"OVERLAY-FAULT REFUSED: arming API present; artifacts=1 symbols={len(client)} armed={len(armed)}")
        return 1
    print(f"OVERLAY-FAULT PASS: artifacts=1 symbols={len(client)} armed=0")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        raise SystemExit(subprocess.run([sys.executable, str(Path(__file__).with_name("test-overlay-fault-exclusion.py"))], check=False).returncode)
    if len(sys.argv) != 2:
        raise SystemExit("OVERLAY-FAULT REFUSED: supply exactly one client artifact")
    source_rc = inspect_accessor_source()
    if source_rc != 0:
        raise SystemExit(source_rc)
    raise SystemExit(inspect(sys.argv[1]))
