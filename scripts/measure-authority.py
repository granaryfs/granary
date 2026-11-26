#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Run opt-in authority rows sequentially, exporting one JSON record and a table."""

import argparse
import copy
import contextlib
import io
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import tempfile
import time

import replay_authority

if not __debug__:  # pragma: no cover
    raise SystemExit("measure-authority.py checks with assert; run it without -O")

NAMES = ("authority_queue", "authority_validation", "authority_chain",
         "authority_log_wait", "authority_worker_poll")
RAISED = "1000000,1000000,1073741824,1073741824,4"
DEFAULT = "46,5,33554432,268435456,4"
POSITIVE_CONTROL = "4,4,33554432,268435456,4"
DEFAULT_SEED = 8
ROOT = Path(__file__).resolve().parent.parent


def shipping_artifact(path):
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ValueError("cannot read shipping artifact") from error
    if not data.startswith(b"!<arch>\n") or len(data) <= 8:
        raise ValueError("shipping artifact is not a nonempty Rust archive")
    for name in NAMES:
        if name.encode() in data:
            raise ValueError(f"measurement span in shipping artifact: {name}")
    return hashlib.sha256(data).hexdigest()


def compiled_tests(output):
    """Read nextest's serialized build output for reuse without rebuilding."""
    try:
        documents = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    except json.JSONDecodeError as error:
        raise ValueError("malformed compiled test metadata") from error
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise ValueError("missing compiled test metadata")
    metadata = documents[0]
    binaries = metadata.get("rust-binaries")
    if not isinstance(metadata.get("rust-build-meta"), dict) or not isinstance(binaries, dict):
        raise ValueError("malformed compiled test metadata")
    binary = binaries.get("granary-server")
    if (len(binaries) != 1 or not isinstance(binary, dict) or binary.get("kind") != "lib"
            or binary.get("binary-name") != "granary_server" or not binary.get("binary-path")):
        raise ValueError("compiled metadata must contain the granary-server library test")
    return metadata


def population(row):
    if not isinstance(row, dict):
        raise ValueError("measurement row must be an object")
    if "tuple" in row and not isinstance(row["tuple"], str):
        raise ValueError("tuple must be a string")
    for key in ("revision", "tree_sha256", "host", "kernel", "filesystem", "date", "command", "tuple"):
        if not row.get(key):
            raise ValueError(f"missing row metadata: {key}")
    for key in ("depth", "last_depth", "volumes", "chain_read_total_ns", "sync_total_ns",
                "publication_p50_ns", "publication_p99_ns", "driver_poll_total_ns",
                "status_p50_ns", "status_p99_ns", "submission_interarrival_p50_ns", "submission_interarrival_p99_ns"):
        if key in row:
            count(row, key)
    if count(row, "samples", 0) <= 0:
        raise ValueError("no measured cases")
    if count(row, "sample_loss", -1) != 0:
        raise ValueError("sample loss prevents a measurement conclusion")
    if row["row"] in ("pooled_transport", "stalled_status"):
        if count(row, "status_count", 0) <= 0 or count(row, "status_errors", -1) != 0:
            raise ValueError("status population is not successful")
    if row["row"] == "mixed_publish":
        if row["tuple"] != RAISED or row.get("binding_tuple") != "false":
            raise ValueError("throughput tuple could bind")
        if count(row, "mixed_get_count", 0) <= 0:
            raise ValueError("no mixed load cases")
        if row.get("collection") == "on":
            for name in NAMES:
                if count(row, f"span_{name}_count") <= 0:
                    raise ValueError(f"missing phase: {name}")
            if row.get("depth") != row.get("last_depth"):
                raise ValueError("publication samples changed depth")
    if row["row"] == "defaults_cadence":
        replay_authority.trace(row)
        label = row.get("label")
        if label not in ("defaults", "positive_control", "demand", "acceptance"):
            raise ValueError("invalid cadence label")
        if label == "defaults" and row["tuple"] != DEFAULT:
            raise ValueError("shipped control tuple mismatch")
        if label == "positive_control" and row["tuple"] != POSITIVE_CONTROL:
            raise ValueError("positive control tuple mismatch")
        if label == "demand" and row["tuple"] != RAISED:
            raise ValueError("demand tuple is not non-binding control")
        if label == "positive_control":
            if count(row, "rate_limited_429") == 0:
                raise ValueError("positive control did not reproduce 429")
        elif count(row, "rate_limited_429") != 0:
            raise ValueError("cadence produced 429")
        if count(row, "completed_publications") != count(row, "samples"):
            raise ValueError("cadence completed population mismatch")
        if row.get("sequence") not in ("get_publish", "distinct_volumes") or not row.get("seed"):
            raise ValueError("missing cadence sequence or seed")
        count(row, "seed")
    if row["row"] == "hostile_separation":
        if count(row, "b_429", -1) != 0:
            raise ValueError("hostile row B produced 429")
        if count(row, "b_failures", -1) != 0 or count(row, "status_errors", -1) != 0:
            raise ValueError("hostile row B failed")
        if any(count(row, key) <= 0 for key in ("a_attempts", "b_completed_publications", "b_publication_count", "b_read_count", "status_count", "window_ns")):
            raise ValueError("empty hostile population")
        target, stalled, covered, window = (count(row, key) for key in
            ("stall_target", "stalled_requests", "stall_covered_ns", "stall_window_ns"))
        if target <= 0 or stalled < target or covered <= 0 or window <= 0:
            raise ValueError("hostile stalled population missing")
        if (count(row, "stall_attempts") != stalled + count(row, "stall_cap_refusals") + count(row, "stall_unpolled_endings")
                or count(row, "stall_rearms", -1) != stalled - target or covered > window):
            raise ValueError("hostile stalled population mismatch")
        counts = {replay_authority.integer(key.removeprefix("a_status_"), "a_status code"): replay_authority.integer(value, key) for key, value in row.items() if key.startswith("a_status_")}
        if (sum(counts.values()) != count(row, "a_attempts")
                or sum(n for code, n in counts.items() if code != 429) != count(row, "a_admitted_attempts_lower_bound", -1)
                or count(row, "b_completed_publications") != count(row, "b_publication_count")
                or count(row, "samples") != count(row, "b_completed_publications")):
            raise ValueError("hostile population count mismatch")
    return row


def count(row, key, default=0):
    return replay_authority.integer(row.get(key, default), key)


def read_row(path):
    result = {}
    try:
        lines = path.read_text().splitlines()
    except OSError as error:
        raise ValueError("cannot read measurement row") from error
    for line in lines:
        key, separator, value = line.partition("\t")
        if not separator or not key or key in result:
            raise ValueError("malformed measurement row")
        result[key] = value
    if not result:
        raise ValueError("empty measurement row")
    return result


def crossover(rows):
    samples = sorted((r for r in rows if r.get("row") == "mixed_publish"
                      and r.get("collection") == "on" and r.get("volumes") == "1"
                      and r.get("valid_population") is True), key=lambda r: int(r["depth"]))
    below = None
    for row in samples:
        if int(row["chain_read_total_ns"]) > int(row["sync_total_ns"]):
            return {"lower_depth": below, "upper_depth": int(row["depth"]),
                    "comparison": "mean chain-read time per entry exceeds mean log-sync time per entry"}
        below = int(row["depth"])
    return {"lower_depth": below, "upper_depth": None, "comparison": "not bracketed"}


def acceptance(report, smoke, skip_wire):
    shipping = report["shipping_exclusion"].get("result") == "pass"
    passed = bool(report["rows"]) and all(r["result"] == "pass" for r in report["rows"])
    common = shipping and report["setup"].get("result") == "pass" and report["tree_unchanged_during_run"] and passed
    complete = bool(common and not smoke and not skip_wire and report["crossover"]["upper_depth"] is not None)
    return complete, 0 if complete or (smoke and common) else 1


def self_test():
    base = dict(revision="a" * 40, tree_sha256="b" * 64, host="fixture", kernel="fixture",
                filesystem="ext4", date="2026-10-06T00:00:00Z", command="fixture", tuple=RAISED,
                row="mixed_publish", samples="2", sample_loss="0", collection="on",
                depth="1", last_depth="1", mixed_get_count="2", binding_tuple="false", volumes="1",
                chain_read_total_ns="1", sync_total_ns="2", valid_population=True)
    base.update({f"span_{name}_count": "1" for name in NAMES})
    assert population(base) == base
    cases = []
    for wrong, refusal in [(None, "measurement row must be an object"),
                           (dict(base, tuple=[]), "tuple must be a string")]:
        try:
            population(wrong)
        except ValueError as error:
            assert str(error) == refusal, error
        else:
            raise AssertionError(f"shape control survived: {refusal}")
        cases.append((wrong, refusal))
    for key in ("samples", "sample_loss", "mixed_get_count", "span_authority_queue_count",
                "depth", "chain_read_total_ns", "publication_p50_ns"):
        for value in ([], {}, True, 1.5):
            wrong = dict(base, **{key: value})
            try:
                population(wrong)
            except ValueError as error:
                assert str(error) == f"invalid scalar integer: {key}", error
            else:
                raise AssertionError(f"integer shape control survived: {key}")
            cases.append((wrong, f"invalid scalar integer: {key}"))
    for key in ("revision", "tree_sha256", "host", "kernel", "filesystem", "date", "command", "tuple"):
        wrong = copy.deepcopy(base); wrong[key] = ""
        cases.append((wrong, f"missing row metadata: {key}"))
    for changes, refusal in [({"samples": "0"}, "no measured cases"),
                             ({"sample_loss": "1"}, "sample loss prevents a measurement conclusion"),
                             ({"tuple": DEFAULT}, "throughput tuple could bind"),
                             ({"binding_tuple": "true"}, "throughput tuple could bind"),
                             ({"mixed_get_count": "0"}, "no mixed load cases"),
                             ({"last_depth": "2"}, "publication samples changed depth")]:
        wrong = copy.deepcopy(base); wrong.update(changes); cases.append((wrong, refusal))
    for name in NAMES:
        wrong = copy.deepcopy(base); wrong[f"span_{name}_count"] = "0"
        cases.append((wrong, f"missing phase: {name}"))
    status = dict(base, row="stalled_status", status_count="2", status_errors="0")
    assert population(status) == status
    for field in ("status_count", "status_errors"):
        wrong = dict(status); wrong[field] = "0" if field == "status_count" else "1"
        cases.append((wrong, "status population is not successful"))
    for wrong, refusal in cases:
        try:
            population(wrong)
        except ValueError as error:
            assert str(error) == refusal, (str(error), refusal)
        else:
            raise AssertionError(f"control survived: {refusal}")
    with tempfile.TemporaryDirectory() as directory:
        artifact = Path(directory) / "library.rlib"
        artifact.write_bytes(b"!<arch>\nfixture object")
        assert shipping_artifact(artifact)
        for name in NAMES:
            artifact.write_bytes(b"!<arch>\n" + name.encode())
            try:
                shipping_artifact(artifact)
            except ValueError as error:
                assert str(error) == f"measurement span in shipping artifact: {name}"
            else:
                raise AssertionError("shipping exclusion control survived")
        for content in (b"!<arch>\n", b"not an archive"):
            artifact.write_bytes(content)
            try:
                shipping_artifact(artifact)
            except ValueError as error:
                assert str(error) == "shipping artifact is not a nonempty Rust archive"
            else:
                raise AssertionError("invalid archive control survived")
        artifact.unlink()
        try:
            shipping_artifact(artifact)
        except ValueError as error:
            assert str(error) == "cannot read shipping artifact"
        else:
            raise AssertionError("missing artifact control survived")
        row = Path(directory) / "row.tsv"
        row.write_text("row\tfixture\nsamples\t2\n")
        assert read_row(row) == {"row": "fixture", "samples": "2"}
        for content, refusal in [("", "empty measurement row"), ("row", "malformed measurement row"),
                                  ("row\ta\nrow\tb", "malformed measurement row")]:
            row.write_text(content)
            try:
                read_row(row)
            except ValueError as error:
                assert str(error) == refusal
            else:
                raise AssertionError("row parser control survived")
        row.unlink()
        try:
            read_row(row)
        except ValueError as error:
            assert str(error) == "cannot read measurement row"
        else:
            raise AssertionError("missing row control survived")
    below = dict(base, depth="100", last_depth="100", chain_read_total_ns="3", sync_total_ns="4")
    above = dict(base, depth="1000", last_depth="1000", chain_read_total_ns="5", sync_total_ns="4")
    assert crossover([base, below, above])["lower_depth"] == 100
    assert crossover([base, below, above])["upper_depth"] == 1000
    assert crossover([base, below])["upper_depth"] is None
    receipt = dict(shipping_exclusion={"result": "pass"}, setup={"result": "pass"}, tree_unchanged_during_run=True,
                   rows=[{"result": "pass"}], crossover={"upper_depth": 1000})
    assert acceptance(receipt, False, False) == (True, 0)
    for result in ("measurement span in shipping artifact: authority_queue", "cannot read shipping artifact", "build failed"):
        wrong = dict(receipt, shipping_exclusion={"result": result})
        assert acceptance(wrong, False, False) == (False, 1)
        assert acceptance(wrong, True, False) == (False, 1)
    for changes in ({"setup": {"result": "failed"}}, {"rows": []}, {"rows": [{"result": "failed"}]},
                    {"tree_unchanged_during_run": False}):
        assert acceptance(dict(receipt, **changes), False, False) == (False, 1)
    assert acceptance(dict(receipt, crossover={"upper_depth": None}), False, False) == (False, 1)
    assert acceptance(receipt, False, True) == (False, 1)
    assert acceptance(receipt, True, True) == (False, 0)
    cadence = dict(base, **replay_authority.fixture([0, 250000000]))
    cadence.update(row="defaults_cadence", tuple=RAISED, label="demand", samples="2", sequence="get_publish", seed="8")
    assert population(cadence) == cadence
    defaults = dict(cadence, tuple=DEFAULT, label="defaults")
    assert population(defaults) == defaults
    positive = copy.deepcopy(cadence)
    positive.update(tuple=POSITIVE_CONTROL, label="positive_control", samples="1",
                    completed_publications="1", rate_limited_429="1")
    attempts = positive["attempt_trace"]
    attempts[0].update(status=429, token="rate-limited")
    attempts[1].update(publication=0)
    positive["attempt_trace"] = json.dumps(attempts)
    assert population(positive) == positive
    rejected = dict(positive, label="defaults", tuple=DEFAULT)
    try:
        population(rejected)
    except ValueError as error:
        assert str(error) == "cadence produced 429", error
    else:
        raise AssertionError("cadence produced 429 control survived")
    cases.append((rejected, "cadence produced 429"))
    print("cadence zero-refusal control: cadence produced 429; 1 refusal case")
    for changes, refusal in [({"label": "invalid"}, "invalid cadence label"),
                             ({"label": "defaults", "tuple": POSITIVE_CONTROL}, "shipped control tuple mismatch"),
                             ({"label": "positive_control", "tuple": DEFAULT}, "positive control tuple mismatch"),
                             ({"label": "positive_control"}, "positive control tuple mismatch"),
                             ({"tuple": DEFAULT}, "demand tuple is not non-binding control"),
                             ({"samples": "3"}, "cadence completed population mismatch"),
                             ({"seed": ""}, "missing cadence sequence or seed"),
                             ({"label": "positive_control", "tuple": POSITIVE_CONTROL}, "positive control did not reproduce 429")]:
        wrong = dict(cadence, **changes); cases.append((wrong, refusal))
        try:
            population(wrong)
        except ValueError as error:
            assert str(error) == refusal, (str(error), refusal)
        else:
            raise AssertionError(f"control survived: {refusal}")
    hostile = dict(base, row="hostile_separation", b_429="0", b_failures="0", status_errors="0",
                   a_attempts="2", a_status_202="1", a_status_429="1", a_admitted_attempts_lower_bound="1",
                   b_completed_publications="2", b_publication_count="2", b_read_count="2", status_count="2", window_ns="1",
                   stall_target="1", stalled_requests="2", stall_attempts="3", stall_rearms="1",
                   stall_cap_refusals="1", stall_unpolled_endings="0", stall_covered_ns="1", stall_window_ns="1")
    assert population(hostile) == hostile
    for changes, refusal in [({"b_429": "1"}, "hostile row B produced 429"),
                             ({"b_failures": "1"}, "hostile row B failed"),
                             ({"a_attempts": "0"}, "empty hostile population"),
                             ({"b_completed_publications": "0"}, "empty hostile population"),
                             ({"status_count": "0"}, "empty hostile population"),
                             ({"stalled_requests": "0"}, "hostile stalled population missing"),
                             ({"stall_rearms": "0"}, "hostile stalled population mismatch"),
                             ({"stall_cap_refusals": "2"}, "hostile stalled population mismatch"),
                             ({"stall_covered_ns": "2"}, "hostile stalled population mismatch"),
                             ({"b_read_count": "0"}, "empty hostile population"),
                             ({"a_attempts": "3"}, "hostile population count mismatch"),
                             ({"a_admitted_attempts_lower_bound": "2"}, "hostile population count mismatch"),
                             ({"b_publication_count": "3"}, "hostile population count mismatch")]:
        wrong = dict(hostile, **changes); cases.append((wrong, refusal))
        try:
            population(wrong)
        except ValueError as error:
            assert str(error) == refusal, (str(error), refusal)
        else:
            raise AssertionError(f"control survived: {refusal}")
    replay_authority.self_test()
    assert cases
    setup_cases = setup_controls()
    option_controls()
    wiring_controls()
    print(f"setup controls: {setup_cases} refusal cases passed; one-build reuse verified")
    print(f"measurement controls: {len(cases) + 25} refusal cases passed; runner wiring controls passed")


def option_controls():
    saved = sys.argv
    cases = [("--tuple", DEFAULT), ("--label", "acceptance"), ("--seed", "13")]
    try:
        for option, value in cases:
            sys.argv = ["measurement", option, value]
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                try:
                    main()
                except SystemExit as error:
                    assert error.code == 2, error
                else:
                    raise AssertionError(f"suite option survived: {option}")
            assert "--tuple and --seed require --row cadence or hostile; --label requires --row cadence" in stderr.getvalue(), stderr.getvalue()
        sys.argv = ["measurement", "--row", "hostile", "--label", "demand"]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            try:
                main()
            except SystemExit as error:
                assert error.code == 2, error
            else:
                raise AssertionError("hostile label control survived")
        assert "--label requires --row cadence" in stderr.getvalue(), stderr.getvalue()
    finally:
        sys.argv = saved
    assert cases
    print("row option controls: 4 refusals: --tuple and --seed require --row cadence or hostile; --label requires --row cadence")


def setup_controls():
    valid = {"rust-build-meta": {}, "rust-binaries": {"granary-server": {
        "kind": "lib", "binary-name": "granary_server", "binary-path": "/fixture/test"}}}
    assert compiled_tests("compiler progress\n" + json.dumps(valid)) == valid
    malformed = copy.deepcopy(valid)
    malformed["rust-binaries"]["granary-server"]["kind"] = "bin"
    cases = [("compiler failed\n", "missing compiled test metadata"),
             ("[]", "missing compiled test metadata"),
             ("{broken", "malformed compiled test metadata"),
             ('{"rust-binaries": []}', "malformed compiled test metadata"),
             (json.dumps(malformed), "compiled metadata must contain the granary-server library test")]
    for output, refusal in cases:
        try:
            compiled_tests(output)
        except ValueError as error:
            assert str(error) == refusal, (str(error), refusal)
        else:
            raise AssertionError(f"setup control survived: {refusal}")
    assert cases
    return len(cases) + 4  # Four additional refusals exercise main below.


def wiring_controls():
    """Exercise build-once, setup refusal and shipping refusal in the real runner."""
    global ROOT, run_logged, read_command
    saved = ROOT, run_logged, read_command, sys.argv
    inherited = {key: os.environ.get(key) for key in
                 ("GRANARY_MEASURE_TUPLE", "GRANARY_MEASURE_SEED", "GRANARY_MEASURE_LABEL", "GRANARY_MEASURE_UNKNOWN")}
    os.environ.update(GRANARY_MEASURE_TUPLE=RAISED, GRANARY_MEASURE_SEED="999",
                      GRANARY_MEASURE_LABEL="acceptance", GRANARY_MEASURE_UNKNOWN="inherited")
    try:
        (ROOT / "target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "target", prefix="measurement-controls-") as temporary:
            ROOT = Path(temporary)
            output = ROOT / "result.json"
            artifact = ROOT / "target/debug/libgranary_server.rlib"
            artifact.parent.mkdir(parents=True)
            sys.argv = ["measurement", "--smoke", "--skip-wire", "--filesystem", "fixture",
                        "--directory", str(ROOT / "state"), "--output", str(output)]
            read_command = lambda args: "a" * 40 if args == ["git", "rev-parse", "HEAD"] else "fixture ext4" if args[0] == "findmnt" else ""
            valid_build = {"rust-build-meta": {}, "rust-binaries": {"granary-server": {
                "kind": "lib", "binary-name": "granary_server", "binary-path": "/fixture/test"}}}
            scenarios = [(b"!<arch>\nfixture object", "pass", 0, json.dumps(valid_build), None),
                         (b"!<arch>\nauthority_queue", "measurement span in shipping artifact: authority_queue", 0, json.dumps(valid_build), None),
                         (None, "cannot read shipping artifact", 0, json.dumps(valid_build), None),
                         (b"!<arch>\nfixture object", "pass", 137, "compiler killed", "test binary build failed"),
                         (b"!<arch>\nfixture object", "pass", 0, "no metadata", "missing compiled test metadata"),
                         (b"!<arch>\nfixture object", "pass", 0, '{"rust-build-meta": {}, "rust-binaries": {}}',
                          "compiled metadata must contain the granary-server library test")]
            for content, shipping, build_rc, build_output, setup_refusal in scenarios:
                calls = {"shipping": 0, "setup": 0, "rows": 0}
                received_environments = []
                def fixture_run(command, env, log):
                    log.write_text("synthetic passing command fixture\n")
                    if "build" in command:
                        assert not any(key.startswith("GRANARY_MEASURE_") for key in env)
                        calls["shipping"] += 1
                        if artifact.exists():
                            artifact.unlink()
                        if content is not None:
                            artifact.write_bytes(content)
                    elif "list" in command:
                        assert not any(key.startswith("GRANARY_MEASURE_") for key in env)
                        calls["setup"] += 1
                        assert "--locked" in command and "--lib" in command
                        log.write_text(build_output + "\n")
                        return build_rc, log.read_text()
                    else:
                        calls["rows"] += 1
                        assert "GRANARY_MEASURE_UNKNOWN" not in env
                        assert env["GRANARY_MEASURE_LOG"] == str(log)
                        received_environments.append({key: value for key, value in env.items() if key.startswith("GRANARY_MEASURE_")})
                        assert "--binaries-metadata" in command, "row must reuse the one compiled test binary"
                        assert not any(flag in command for flag in ("--locked", "--lib", "--cargo-profile", "--features", "-p"))
                        metadata_path = Path(command[command.index("--binaries-metadata") + 1])
                        assert json.loads(metadata_path.read_text()) == valid_build
                        row = dict(samples="2", sample_loss="0", tuple=RAISED)
                        if "defaults_cadence" in command[-1]:
                            suite = "--row" not in sys.argv
                            assert (env["GRANARY_MEASURE_TUPLE"], env["GRANARY_MEASURE_SEED"], env["GRANARY_MEASURE_LABEL"], env["GRANARY_MEASURE_CADENCE"]) == (
                                (DEFAULT, "8", "defaults", "2") if suite else (RAISED, "13", sys.argv[sys.argv.index("--label") + 1], "20"))
                            row = dict(replay_authority.fixture([0, 250000000]), row="defaults_cadence", tuple=env["GRANARY_MEASURE_TUPLE"], label=env["GRANARY_MEASURE_LABEL"], sequence="distinct_volumes", seed=env["GRANARY_MEASURE_SEED"], samples="2")
                            row['attempt_trace'] = json.dumps(row['attempt_trace'])
                        elif "hostile_separation" in command[-1]:
                            assert env["GRANARY_MEASURE_TUPLE"] == DEFAULT and env["GRANARY_MEASURE_SECONDS"] == "5" and env["GRANARY_MEASURE_SEED"] == "8"
                            row.update(row="hostile_separation", b_429="0", b_failures="0", status_errors="0", a_attempts="2", a_status_202="1", a_status_429="1", a_admitted_attempts_lower_bound="1", b_completed_publications="2", b_publication_count="2", b_read_count="2", status_count="2", window_ns="1", stall_target="1", stalled_requests="2", stall_attempts="3", stall_rearms="1", stall_cap_refusals="1", stall_unpolled_endings="0", stall_covered_ns="1", stall_window_ns="1")
                        elif "pooled_transport" in command[-1]:
                            row.update(row="pooled_transport", status_count="2", status_errors="0")
                        elif "stalled_routed_status" in command[-1]:
                            row.update(row="stalled_status", status_count="2", status_errors="0",
                                       status_p50_ns="1", status_p99_ns="2")
                        else:
                            row.update(row="mixed_publish", depth=env["GRANARY_MEASURE_DEPTH"],
                                       last_depth=env["GRANARY_MEASURE_DEPTH"], volumes=env["GRANARY_MEASURE_VOLUMES"],
                                       collection=env["GRANARY_MEASURE_COLLECT"], binding_tuple="false", mixed_get_count="2",
                                       chain_read_total_ns="1", sync_total_ns="2", publication_p50_ns="1",
                                       publication_p99_ns="2", driver_poll_total_ns="1")
                            row.update({f"span_{name}_count": "1" for name in NAMES})
                        (Path(env["GRANARY_MEASURE_OUTPUT"]) / "fixture.tsv").write_text(
                            "".join(f"{key}\t{value}\n" for key, value in row.items()))
                    return 0, log.read_text()
                run_logged = fixture_run
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = main()
                receipt = json.loads(output.read_text())
                assert [row["environment"] for row in receipt["rows"]] == received_environments
                assert receipt["shipping_exclusion"]["result"] == shipping
                assert calls == {"shipping": 1, "setup": 1, "rows": 0 if setup_refusal else 7}, calls
                if setup_refusal:
                    assert (code, receipt["setup"]["result"], receipt["setup"]["refusal"], receipt["rows"]) == (1, "failed", setup_refusal, [])
                    assert receipt["setup"]["exit_code"] == build_rc
                    assert receipt["linux_acceptance_complete"] is False
                else:
                    assert len(receipt["rows"]) == 7 and all(row["result"] == "pass" for row in receipt["rows"])
                    assert receipt["setup"]["result"] == "pass"
                    assert code == (0 if shipping == "pass" else 1), (code, shipping)
            content = b"!<arch>\nfixture object"
            build_rc, build_output = 0, json.dumps(valid_build)
            for options in [
                ["--row", "cadence", "--tuple", RAISED, "--seed", "13", "--label", "acceptance", "--cadence", "20", "--distinct", "1"],
                ["--row", "cadence", "--tuple", RAISED, "--seed", "13", "--label", "demand", "--cadence", "20", "--distinct", "1"],
                ["--row", "hostile", "--tuple", DEFAULT, "--seed", "8", "--seconds", "5"],
                [],
            ]:
                calls = {"shipping": 0, "setup": 0, "rows": 0}
                received_environments = []
                sys.argv = ["measurement", "--smoke", "--filesystem", "fixture", "--directory", str(ROOT / "state"), "--output", str(output), *options]
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = main()
                assert code == 0 and calls == {"shipping": 1, "setup": 1, "rows": 1 if options else 10}, (code, calls)
                receipt = json.loads(output.read_text())
                assert [row["environment"] for row in receipt["rows"]] == received_environments
                assert receipt["rows"][0]["result"] == "pass" and receipt["linux_acceptance_complete"] is False
            calls = {"shipping": 0, "setup": 0, "rows": 0}
            sys.argv[sys.argv.index("--directory") + 1] = str(ROOT.parent / "outside-state")
            refused = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(refused):
                try:
                    main()
                except SystemExit as error:
                    assert error.code == 2
                else:
                    raise AssertionError("outside-worktree directory control survived")
            assert "measurement state must be inside this worktree" in refused.getvalue()
            assert calls == {"shipping": 0, "setup": 0, "rows": 0}, calls
    finally:
        ROOT, run_logged, read_command, sys.argv = saved
        for key, value in inherited.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def read_command(args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def tree_digest():
    paths = read_command(["git", "ls-files", "--cached", "--others", "--exclude-standard"]).splitlines()
    digest = hashlib.sha256()
    for name in sorted(paths):
        path = ROOT / name
        digest.update(name.encode() + b"\0")
        digest.update(path.read_bytes() if path.is_file() else b"deleted")
    return digest.hexdigest()


def run_logged(command, env, log):
    # The return code is taken from the command itself, on its own shell line.
    script = '"$@" > "$GRANARY_MEASURE_LOG" 2>&1\nrc=$?\nprintf "rc=%s\\n" "$rc"\nexit "$rc"\n'
    result = subprocess.run(["/bin/sh", "-c", script, "measurement", *command],
                            cwd=ROOT, env=dict(env, GRANARY_MEASURE_LOG=str(log)),
                            capture_output=True, text=True)
    output = log.read_text()
    return result.returncode, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--row", choices=("suite", "cadence", "hostile"), default="suite")
    parser.add_argument("--tuple", help="explicit experimental control tuple")
    parser.add_argument("--seed", type=int, help="coordinator and fixture seed")
    parser.add_argument("--label", choices=("defaults", "positive_control", "demand", "acceptance"))
    parser.add_argument("--cadence", type=int, help="cadence population (2..1000; distinct <=64)")
    parser.add_argument("--distinct", type=int, choices=(0, 1), default=0)
    parser.add_argument("--seconds", type=int, default=60, help="hostile load window (1..60 seconds)")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--smoke", action="store_true", help="small unoptimized rows; cannot establish Linux acceptance")
    parser.add_argument("--skip-wire", action="store_true", help="omit socket rows where the sandbox refuses binds")
    parser.add_argument("--filesystem", help="required label for a non-Linux smoke run")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--extra-depth-max", type=int, default=10000)
    args = parser.parse_args()
    if args.self_test:
        self_test(); return 0
    if args.row == "suite" and any(value is not None for value in (args.tuple, args.label, args.seed)):
        parser.error("--tuple and --seed require --row cadence or hostile; --label requires --row cadence")
    if args.label is not None and args.row != "cadence":
        parser.error("--label requires --row cadence")
    if not args.directory or not args.output:
        parser.error("--directory and --output are required")
    if not 1 <= args.samples <= 100 or not 1000 <= args.extra_depth_max <= 100000:
        parser.error("samples must be 1..100; extra-depth-max must be 1000..100000")
    if platform.system() != "Linux" and not args.smoke:
        parser.error("acceptance rows require the Linux venue")
    if args.seed is not None and not 0 <= args.seed <= 18446744073709551615:
        parser.error("seed must fit u64")
    if not 1 <= args.seconds <= 60:
        parser.error("seconds must be 1..60")
    if args.cadence is not None and not 2 <= args.cadence <= (64 if args.distinct else 1000):
        parser.error("invalid cadence population")
    if args.skip_wire and args.row == "cadence":
        parser.error("cadence requires sockets; cannot combine with --skip-wire")
    directory = args.directory.resolve()
    if not directory.is_relative_to(ROOT):
        parser.error("measurement state must be inside this worktree")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    filesystem = read_command(["findmnt", "-T", str(directory), "-n", "-o", "SOURCE,FSTYPE,OPTIONS"]) \
        if platform.system() == "Linux" else args.filesystem
    if not filesystem:
        parser.error("non-Linux smoke requires --filesystem")
    metadata = dict(revision=read_command(["git", "rev-parse", "HEAD"]), tree_sha256=tree_digest(),
                    dirty=bool(read_command(["git", "status", "--porcelain"])), host=platform.node(),
                    kernel=f"{platform.system()} {platform.release()} {platform.version()} {platform.machine()}",
                    filesystem=filesystem, state_directory=str(directory),
                    venue="smoke" if args.smoke else "Linux", optimized=not args.smoke)
    report = dict(rows=[], setup=None, shipping_exclusion=None, crossover=None, collection_comparison=[],
                  triggers={str(issue): {"text": "CONTROLLER REQUIRED: copy trigger text from issue body",
                            "fired": "CONTROLLER REQUIRED: fired or not fired"} for issue in (114, 117, 185)})
    env = {key: value for key, value in os.environ.items() if not key.startswith("GRANARY_MEASURE_")}
    env["CARGO_TARGET_DIR"] = str(ROOT / "target")
    profile = "test" if args.smoke else "release"
    with tempfile.TemporaryDirectory(prefix="authority-measurements-") as temporary:
        fragments = Path(temporary)
        logs = args.output.resolve().with_suffix(".logs")
        logs.mkdir(parents=True, exist_ok=True)
        build = ["cargo", "build", "-p", "granary-server", "--lib", "--locked"]
        if not args.smoke:
            build.append("--release")
        rc, output = run_logged(build, env, logs / "shipping-build.log")
        if rc:
            report["shipping_exclusion"] = dict(result="build failed", exit_code=rc, log=str(logs / "shipping-build.log"))
        else:
            artifact = ROOT / "target" / ("debug" if args.smoke else "release") / "libgranary_server.rlib"
            try:
                sha = shipping_artifact(artifact)
                report["shipping_exclusion"] = dict(result="pass", artifact_sha256=sha,
                                                     command=shlex.join(build), **metadata)
            except ValueError as error:
                report["shipping_exclusion"] = dict(result=str(error), exit_code=1)
        build_tests = ["cargo", "nextest", "list", "-p", "granary-server", "--lib", "--locked",
                       "--profile", "ci", "--cargo-profile", profile,
                       "--list-type", "binaries-only", "--message-format", "json"]
        date = datetime.datetime.now(datetime.timezone.utc).isoformat()
        start = time.monotonic()
        rc, output = run_logged(build_tests, env, logs / "test-build.log")
        report["setup"] = dict(metadata, row="setup", tuple=RAISED, date=date,
                               command=shlex.join(build_tests), exit_code=rc,
                               duration_s=time.monotonic() - start, log=str(logs / "test-build.log"),
                               result="failed", refusal="test binary build failed" if rc else "")
        binaries_file = logs / "test-binaries.json"
        if not rc:
            try:
                binaries_file.write_text(json.dumps(compiled_tests(output)) + "\n")
                report["setup"].update(result="pass", binaries_metadata=str(binaries_file))
            except ValueError as error:
                report["setup"].update(refusal=str(error))
        if report["setup"]["result"] != "pass":
            report["crossover"] = crossover([])
            report["tree_unchanged_during_run"] = metadata["tree_sha256"] == tree_digest()
            report["linux_acceptance_complete"] = False
            write_report(args.output, report)
            print(f"setup failure: {report['setup']['refusal']}; log={report['setup']['log']}", file=sys.stderr)
            return 1
        env.update(GRANARY_MEASURE_DIR=str(directory), GRANARY_MEASURE_OUTPUT=str(fragments),
                   GRANARY_MEASURE_SMOKE="1" if args.smoke else "0", GRANARY_MEASURE_SEED=str(DEFAULT_SEED))

        def row(name, **settings):
            if name.endswith("defaults_cadence") or name.endswith("hostile_separation"):
                settings["tuple"] = DEFAULT
                settings["seed"] = DEFAULT_SEED
                if name.endswith("defaults_cadence"): settings["label"] = "defaults"
                if args.tuple is not None: settings["tuple"] = args.tuple
                if args.seed is not None: settings["seed"] = args.seed
                if args.label is not None and name.endswith("defaults_cadence"): settings["label"] = args.label
            values = {"GRANARY_MEASURE_" + key.upper(): str(value) for key, value in settings.items()}
            command = ["cargo", "nextest", "run", "--profile", "ci",
                       "--binaries-metadata", str(binaries_file), "--run-ignored", "only",
                       "--test-threads", "1", "-E", f"test(=authority::tests::measurements::{name})"]
            index = len(report["rows"])
            for path in fragments.glob("*.tsv"):
                path.unlink()
            date = datetime.datetime.now(datetime.timezone.utc).isoformat()
            start = time.monotonic()
            row_env = dict(env, **values, GRANARY_MEASURE_LOG=str(logs / f"row-{index}.log"))
            rc, output = run_logged(command, row_env, logs / f"row-{index}.log")
            elapsed = time.monotonic() - start
            common = dict(metadata, date=date, command=shlex.join(command),
                          environment={key: value for key, value in row_env.items() if key.startswith("GRANARY_MEASURE_")},
                          exit_code=rc, duration_s=elapsed, log=str(logs / f"row-{index}.log"))
            if elapsed > 40:
                print(f"row {index}: {elapsed:.1f}s exceeds 40s; see recorded duration", file=sys.stderr)
            for path in fragments.glob("*.tsv"):
                try:
                    value = dict(read_row(path), **common)
                except ValueError as error:
                    report["rows"].append(dict(common, row=name, result="missing evidence", valid_population=False,
                                               refusal=str(error), tuple=values.get("GRANARY_MEASURE_TUPLE", DEFAULT if "cadence" in name or "hostile" in name else RAISED)))
                    continue
                try:
                    population(value)
                    value["valid_population"] = True
                except ValueError as error:
                    value.update(valid_population=False, refusal=str(error))
                value["result"] = "pass" if rc == 0 and value["valid_population"] else "failed"
                report["rows"].append(value)
            if not any(r["log"] == common["log"] for r in report["rows"]):
                report["rows"].append(dict(common, row=name, result="missing evidence", valid_population=False,
                                           refusal="row exported no measurement", tuple=values.get("GRANARY_MEASURE_TUPLE", DEFAULT if "cadence" in name or "hostile" in name else RAISED)))
            print(f"row {index}: rc={rc}; log={common['log']}", file=sys.stderr)

        if args.row == "cadence":
            row("transport::authority_measurement_defaults_cadence", cadence=args.cadence or (20 if args.smoke else 1000), distinct=args.distinct)
        elif args.row == "hostile":
            row("hostile::authority_measurement_hostile_separation", seconds=args.seconds)
        else:
            if not args.skip_wire:
                row("transport::authority_measurement_pooled_transport", requests=2 if args.smoke else 1000)
                row("transport::authority_measurement_defaults_cadence", cadence=2 if args.smoke else 1000, distinct=0)
                row("transport::authority_measurement_defaults_cadence", cadence=2 if args.smoke else 32, distinct=1)
            else:
                report["excluded_rows"] = ["pooled_transport", "defaults_cadence"]
            row("rows::authority_measurement_stalled_routed_status", stalls=1 if args.smoke else 3)
            depths = [1, 2] if args.smoke else [1, 100, 1000]
            for depth in depths:
                for collection in ("off", "on"):
                    row("rows::authority_measurement_mixed_publish", depth=depth,
                        samples=2 if args.smoke else args.samples, collect=collection, volumes=1)
            if not args.smoke:
                depth = 1000
                while crossover(report["rows"])["upper_depth"] is None and depth < args.extra_depth_max:
                    depth = min(depth * 10, args.extra_depth_max)
                    for collection in ("off", "on"):
                        row("rows::authority_measurement_mixed_publish", depth=depth, samples=args.samples,
                            collect=collection, volumes=1)
            for collection in ("off", "on"):
                row("rows::authority_measurement_mixed_publish", depth=1, samples=1 if args.smoke else args.samples,
                    collect=collection, volumes=64)
    report["crossover"] = crossover(report["rows"])
    for on in report["rows"]:
        if on.get("collection") != "on" or not on.get("valid_population"):
            continue
        off = next((r for r in report["rows"] if r.get("collection") == "off"
                    and r.get("depth") == on.get("depth") and r.get("volumes") == on.get("volumes")
                    and r.get("valid_population")), None)
        if off:
            report["collection_comparison"].append(dict(depth=on["depth"], volumes=on["volumes"],
                publication_p50_on_over_off=float(on["publication_p50_ns"]) / float(off["publication_p50_ns"]),
                driver_poll_on_over_off=float(on["driver_poll_total_ns"]) / float(off["driver_poll_total_ns"]),
                on_sample_loss=on["sample_loss"], off_sample_loss=off["sample_loss"]))
    report["tree_unchanged_during_run"] = metadata["tree_sha256"] == tree_digest()
    report["linux_acceptance_complete"], exit_code = acceptance(report, args.smoke, args.skip_wire)
    if args.row != "suite":
        report["linux_acceptance_complete"] = False
        exit_code = 0 if (report["shipping_exclusion"].get("result") == "pass" and report["setup"].get("result") == "pass"
                          and report["tree_unchanged_during_run"] and report["rows"]
                          and all(r["result"] == "pass" for r in report["rows"])) else 1
    write_report(args.output, report)
    return exit_code


def write_report(destination, report):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Result: {destination}")
    print("| Row | Depth/volumes/collection | p50 ms | p99 ms | Result | Revision/tree | Host/kernel | Filesystem | Tuple | Date |")
    print("|---|---|---:|---:|---|---|---|---|---|---|")
    for r in report["rows"] or [report["setup"]]:
        prefix = "publication" if r.get("row") == "mixed_publish" else "status" if "status_p50_ns" in r else "submission_interarrival"
        p50 = count(r, prefix + "_p50_ns") / 1e6 if prefix + "_p50_ns" in r and r.get("valid_population") is not False else "unmeasured"
        p99 = count(r, prefix + "_p99_ns") / 1e6 if prefix + "_p99_ns" in r and r.get("valid_population") is not False else "unmeasured"
        columns = [r["row"], f"{r.get('depth', '-')}/{r.get('volumes', '-')}/{r.get('collection', '-')}",
                   p50, p99, r["result"], f"{r['revision']}/{r['tree_sha256'][:12]}",
                   f"{r['host']}/{r['kernel']}", r["filesystem"], r["tuple"], r["date"]]
        print("| " + " | ".join(str(v).replace("|", "\\|") for v in columns) + " |")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"measurement runner: {error}", file=sys.stderr)
        sys.exit(1)
