#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Foreground fault and diagnostic proofs with byte-exact restoration."""
import argparse
import difflib
import hashlib
import os
from pathlib import Path
import re
import subprocess

if not __debug__:
    raise SystemExit("sync-engine-mutations: refuses to run under python -O; its checks are assert statements")

ROOT = Path(__file__).resolve().parents[2]
ENGINE = "crates/granary-client/src/sync/engine.rs"
FAULT = "crates/granary-client/src/overlay_store/fault.rs"
MUTANTS = {
    "ambient_retry_jitter": (
        ENGINE,
        "self.0.random_u64()",
        "granary_core::rng::Rng::next_u64(&mut granary_core::rng::ProcessRng::default())",
        "engine_replay_across_processes_includes_retry_jitter",
        "engine replay changed across processes",
    ),
    "missing_failure_event": (
        ENGINE,
        "crate::observe::op_failed(crate::observe::OperationKind::Fsync, class);",
        "let _ = class;",
        "diagnostic_class_and_result_matrix",
        "wrong fsync failure count",
    ),
    "malformed_payload_class": (
        ENGINE,
        'refused("SyncRechunkContent")',
        'refused("SyncFixturePolicy")',
        "diagnostic_class_and_result_matrix",
        "wrong class corrupt",
    ),
    "missing_fault_identity": (
        FAULT,
        "state.sync_fired.push(SyncFaultEvent { name, phase, occurrence, capture, request, object_kind, }); crate::observe::sync_fault(name, phase, occurrence, object_kind);",
        "crate::observe::sync_fault(name, phase, occurrence, object_kind);",
        "sync_fault_matrix",
        "SyncFaultMissing",
    ),
}


def replace_once(source, before, after):
    positions = [i for i, char in enumerate(source) if not char.isspace()]
    compact = "".join(source[i] for i in positions)
    anchor = "".join(before.split())
    if not anchor or compact.count(anchor) != 1:
        raise ValueError("MutationAnchorNotUnique")
    start = compact.index(anchor)
    return source[:positions[start]] + after + source[positions[start + len(anchor) - 1] + 1:]


def verdict(code, output, test, marker):
    count = re.search(r"Starting (\d+) tests? across", output)
    identities = set(re.findall(r"granary-sim::sync_engine\s+([a-z_0-9]+)", output))
    if count is None or int(count.group(1)) != 1 or identities != {test}:
        raise ValueError("MutationSelectionMissingOrWrong")
    if code == 0:
        return "SURVIVED"
    if code != 100 or marker not in output:
        raise ValueError("MutationIntendedAssertionMissing")
    return "KILLED"


def run(test):
    argv = ["cargo", "nextest", "run", "--profile", "ci", "--locked", "-p", "granary-sim",
            "--features", "overlay-fault-tests", "-E", f"test(={test})"]
    result = subprocess.run(argv, cwd=ROOT, env=dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_BUILD_JOBS="1"),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
    return result.returncode, result.stdout


def self_test():
    assert replace_once("a b c", "b", "z") == "a z c"
    controls = [
        lambda: replace_once("a a", "a", "z"),
        lambda: replace_once("abc", "missing", "z"),
        lambda: verdict(100, "Starting 0 tests across", "oracle", "intended"),
        lambda: verdict(100, "Starting 1 tests across\ngranary-sim::sync_engine wrong\nintended", "oracle", "intended"),
        lambda: verdict(101, "Starting 1 tests across\ngranary-sim::sync_engine oracle", "oracle", "intended"),
    ]
    for control in controls:
        try:
            control()
        except ValueError:
            continue
        raise AssertionError("MutationMalformedControlAccepted")
    text = "Starting 1 tests across\ngranary-sim::sync_engine oracle\nintended"
    assert verdict(100, text, "oracle", "intended") == "KILLED"
    assert verdict(0, text, "oracle", "intended") == "SURVIVED"
    print("self-controls: 5 refused; valid kill and survivor accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("names", nargs="*", choices=tuple(MUTANTS))
    args = parser.parse_args()
    self_test()
    if args.self_test:
        return
    names = args.names or list(MUTANTS)
    outcomes = []
    for name in names:
        relative, before, after, test, marker = MUTANTS[name]
        path = ROOT / relative
        original = path.read_bytes()
        if not original:
            raise ValueError("MutationSourceEmpty")
        digest = hashlib.sha256(original).hexdigest()
        mutated = replace_once(original.decode(), before, after)
        print("".join(difflib.unified_diff(original.decode().splitlines(True), mutated.splitlines(True),
                                         fromfile=relative, tofile=relative)), flush=True)
        try:
            path.write_text(mutated)
            code, output = run(test)
            outcome = verdict(code, output, test, marker)
            outcomes.append(outcome)
            print(f"{name}: {outcome}; rc={code}; selected=1; assertion={marker}", flush=True)
        finally:
            path.write_bytes(original)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("MutationRestorationMismatch")
        code, output = run(test)
        if code != 0 or verdict(code, output, test, marker) != "SURVIVED":
            raise ValueError("MutationRestoredControlFailed")
        print(f"{name}: restored control PASS; source SHA-256={digest}", flush=True)
    if not outcomes or any(outcome != "KILLED" for outcome in outcomes):
        raise SystemExit("MutationSurvivorOrEmptySelection")


if __name__ == "__main__":
    main()
