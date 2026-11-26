#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Validate Q3 measurement rows and retain command evidence."""

import argparse
import base64
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from fractions import Fraction
from functools import partial
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import time
from urllib.parse import urlsplit

REPOSITORY = Path(__file__).resolve().parent.parent
DESK_INPUT = ("inet", "gran_slot", "input")
Q3_RULE_COMMENT = "gran-q3 "
LOOPBACK_STORE_ENV = (
    "GRANARY_STORE",
    "GRANARY_STORE_BUCKET",
    "GRANARY_STORE_ENDPOINT",
    "GRANARY_STORE_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
)


def contained(path, root):
    path_text, root_text = str(path).casefold(), str(root).casefold()
    try:
        return os.path.commonpath((path_text, root_text)) == root_text
    except ValueError:
        return False


TEXT_FIELDS = (
    "profile",
    "workload",
    "network_path",
    "medium",
    "filesystem",
    "host",
    "kernel",
    "cpu",
    "venue",
    "root_label",
    "historical_kind",
    "raw_log",
    "raw_rc",
    "raw_log_sha256",
    "raw_rc_sha256",
    "run_root",
    "cell_kind",
    "load_model",
    "steady_state",
    "netem_delay_placement",
    "venue_backing",
    "venue_cache_mode",
    "venue_text",
    "durations_artifact",
    "durations_artifact_sha256",
)
INTENT_TEXT_FIELDS = ("intent_occupancy", "wrapper_layer")
INTEGER_FIELDS = (
    "sample_count",
    "sample_loss",
    "memory_bytes",
    "m15_delta",
    "root_bytes",
    "sample_floor",
    "m15_fallback_delta",
    "m15_reuse_delta",
    "warmup_count",
    "tid",
    "fsync_min_ns",
    "fsync_p50_ns",
    "fsync_p90_ns",
    "fsync_p99_ns",
    "fsync_max_ns",
)
DURABLE_COUNT_FIELDS = (
    "register_attempts",
    "register_repeated_arrivals",
    "background_attempts",
)
PUBLISHED_COUNT_FIELDS = (
    "successful_fsyncs",
    "logical_publishes",
    "publish_attempts",
)
INTENT_INTEGER_FIELDS = (
    "row_holders",
    "zero_row_principals",
    "retired_principals",
    "historical_principals",
    "live_roots",
    "released_rows",
    "written_bytes",
    "encode_register_bytes",
    "full_snapshot_bytes",
    "register_post_p99_ns",
    "publish_decision_p99_ns",
    "same_occupancy_publish_p99_ns",
)
INTENT_OPTIONAL_FIELDS = (
    "authority_log_wait_p99_ns",
    "cross_volume_blocked_ns",
)
METRICS = {"rtt", "control_writes", "cas", "chain_growth", "recovery_gap"}
VERDICT_METRICS = METRICS | {"wall_clock_ms"}
REQUIRED_DECIDING_METRICS = {"rtt", "control_writes"}
VENUES = {"macos", "vm", "linux-ci", "linux-desk"}
NETWORK_PATHS = {
    "dedicated-veth",
    "lo",
    "loopback",
    "host-network",
    "127.0.0.1",
    "::1",
}
LOOPBACK_PATHS = NETWORK_PATHS - {"dedicated-veth"}
ROOT_LABELS = {"707-B", "measured length"}
UPPER_BOUND = "upper bound; unreachable through enrollment mutations"
HISTORICAL_KINDS = {"in-format", UPPER_BOUND}
CELL_KINDS = {"steady", "calibration", "control"}
LOAD_MODELS = {"open-loop", "closed-loop", "closed-loop-serial"}
INTENT_OCCUPANCIES = {
    "floor",
    "p1",
    "p16",
    "zero",
    "ceiling",
    "historical",
    "upper-bound",
}
NOT_APPLICABLE = "not-applicable"
UNMEASURED = "unmeasured"
PIVOT_ROLES = {"numerator", "denominator"}
PIVOT_DIAGNOSTIC_LABEL = (
    "not at the offered rate; diagnostic only; not a comparator input"
)
PIVOT_LOWER_BOUND_LABEL = (
    "lower bound for the offered rate: tail latency does not fall as load rises"
)
PIVOT_STREAM_PLAN = "numerator=16;denominator=64@46,64@23,64@11.5"
PIVOT_WARMUP_COUNT = 64
DENOMINATOR_RATE_STREAMS = ((46.0, 64), (23.0, 64), (11.5, 64))
DENOMINATOR_CYCLE_LIMIT_NS = 64 * ((1_000_000_000 + 45) // 46)
CAUSE_NOT_ATTRIBUTED = "The recorded timings leave the cause undetermined."
PIVOT_TERMINAL_LABEL = "inconclusive: no denominator qualified"
PIVOT_NUMERATOR_UNSTEADY = "inconclusive: numerator not steady"
PIVOT_VM_DECISION_NOTE = (
    "VM timing is not a deciding row; the deciding pivot run is the desk/CI runner's"
)
CROSS_VOLUME_NOTE = (
    "The authority driver polls all volume workers in one task. A synchronous intent "
    "snapshot commit or decision log call stalls every worker until it returns. The "
    "no-sleep row measures a quiet request on another volume during a real commit, "
    "subtracting that request's alone latency from the same run. The log gate's token "
    "wait is a contrast metric because the synchronous holder never suspends."
)
STEADY_STATE_TOLERANCE = 0.10
MAX_INTEGER = 2**63 - 1
MIN_DATE = datetime(2000, 1, 1)
MAX_DATE = datetime(2100, 1, 1)
CREDENTIAL = re.compile(r"--(?:token|key)=|password|secret", re.IGNORECASE)
SAMPLE_FIELDS = frozenset(
    TEXT_FIELDS
    + INTENT_TEXT_FIELDS
    + INTEGER_FIELDS
    + INTENT_INTEGER_FIELDS
    + INTENT_OPTIONAL_FIELDS
    + (
        "offered_rate",
        "achieved_rate",
        "rtt_ms",
        "rtt_group",
        "scale",
        "command",
        "revision",
        "date",
        "hardware",
        "deciding",
        "pivot_input",
        "pivot_group",
        "pivot_role",
        "diagnostic_label",
        "pivot_append",
        "pivot_verdict",
        "pivot_scope",
        "numerator_generation_range",
        "numerator_intent_log_bytes",
        "diagnostic_depth_range",
        "register_post_p99_interval_ns",
        "publish_decision_p99_interval_ns",
        "same_occupancy_publish_p99_interval_ns",
        "same_occupancy_publish_diagnostic",
        "authority_log_wait_diagnostic",
        "verdict_metrics",
        "exit_code",
        "device_bytes",
        "device_amplification",
        "configured_rtt_ms",
        "observed_rtt_pre_ms",
        "observed_rtt_post_ms",
        "observed_rtt_ms",
        "calibration_outcome",
        "calibration_reason",
        "register_chain_head_seq",
        "rtt_band_attempts",
        "route_attempts",
        "attempt_count_source",
        "operation_kind_source",
        "netem_preflight",
        "request_correlation",
        "strace_reconciled",
        "steady_state_tolerance",
        "steady_first_half_median_ns",
        "steady_second_half_median_ns",
        "steady_first_half_p99_ns",
        "steady_second_half_p99_ns",
        "steady_exceedance_splits",
        "pivot_steady_first_half_median_ns",
        "pivot_steady_second_half_median_ns",
        "pivot_steady_first_half_p99_ns",
        "pivot_steady_second_half_p99_ns",
        "pivot_steady_exceedance_splits",
        "pivot_steady_exceedance_histograms",
        "pivot_steady_state",
        "pivot_steady_pattern",
        "pivot_steady_context",
        "pivot_steady_confound",
        "pivot_warmup_count",
        "pivot_warmup_elapsed_ns",
        "offload_state",
        "pivot_durations_artifact",
        "pivot_durations_artifact_sha256",
        "pivot_completion_artifact",
        "pivot_completion_artifact_sha256",
        "committed_transitions",
        "stream_count",
        "stream_sample_counts",
        "principal_submission_limit",
        "principal_in_flight_limit",
        "pivot_branch",
        "pivot_verdict_branch",
        "pivot_venue_kind",
        "pivot_venue_note",
        "denominator_label",
        "denominator_attempts",
        "denominator_cycle_stalls",
        "denominator_cycle_stall_issue",
        "pivot_stream_plan",
        "time_to_first_refusal_ns",
        "conflict_token_counts",
        "response_token_counts",
        "rate_limited_count",
        "max_outstanding_overall",
        "max_outstanding_per_stream",
        "sent_count",
        "diagnostic_publish_bound_ns",
        "diagnostic_publish_censored_count",
        "diagnostic_publish_p99_report",
        "diagnostic_publish_stalls",
        "diagnostic_publish_stall_ns",
        "diagnostic_warmup_publish_stalls",
        "diagnostic_warmup_publish_stall_ns",
        "diagnostic_completion_bound_ns",
        "diagnostic_completion_stalls",
        "diagnostic_completion_stall_ns",
        "diagnostic_completion_stall_issue",
        "diagnostic_outcome",
        "diagnostic_completed_count",
        "diagnostic_stall_index",
        "diagnostic_stall_phase",
        "per_stream_offered_rate",
        "publish_pilot_sample_count",
        "publish_pilot_p50_ns",
        "publish_pilot_p99_ns",
        "publish_pilot_max_ns",
        "publish_pilot_stream_count",
        "same_occupancy_publish_pilot_sample_count",
        "same_occupancy_publish_pilot_p50_ns",
        "same_occupancy_publish_pilot_p99_ns",
        "same_occupancy_publish_pilot_max_ns",
        "same_occupancy_publish_pilot_stream_count",
        "root_size_distribution",
        "rtt_k",
        "rtt_counted",
        "rtt_k_over_counted",
        "rtt_unattributed_excess",
        "event",
        "server_metrics",
        "server_observers_sha256",
    )
    + DURABLE_COUNT_FIELDS
    + PUBLISHED_COUNT_FIELDS
)


class Refused(ValueError):
    """A measurement cannot be used as evidence."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def refusal_reason(error):
    """Include subordinate cleanup refusals in the emitted refusal evidence."""
    notes = getattr(error, "__notes__", ())
    return "; ".join((str(error), *notes))


def field(row, name):
    require(name in row, f"schema-missing: {name}")
    return row.get(name)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_root(row):
    path = Path(field(row, "run_root"))
    require(path.is_absolute(), "run-root-invalid")
    try:
        path = path.resolve(strict=True)
    except OSError as error:
        raise Refused("run-root-invalid") from error
    require(path.is_dir(), "run-root-invalid")
    require(
        not contained(path, REPOSITORY),
        "work-directory-inside-repository",
    )
    return path


def artifact(row, name, label, root):
    supplied = Path(field(row, name))
    require(supplied.is_absolute(), "raw-artifact-path")
    try:
        path = supplied.resolve(strict=True)
    except OSError as error:
        raise Refused(f"{label}-missing") from error
    require(path.is_file(), f"{label}-missing")
    require(
        path.suffix == (".log" if name == "raw_log" else ".rc"), "raw-artifact-path"
    )
    require(contained(path, root), "raw-artifact-outside-run-root")
    require(
        not contained(path, REPOSITORY),
        "raw-artifact-inside-repository",
    )
    try:
        got = digest(path)
    except OSError as error:
        raise Refused(f"{label}-unreadable: {error}") from error
    require(got == field(row, name + "_sha256"), f"{label}-hash-mismatch")
    return path


def validate_command_provenance(row):
    """Bind one assembled row to its owned command and sealed raw evidence."""
    root = run_root(row)
    command = field(row, "command")
    require(
        isinstance(command, list)
        and command
        and all(isinstance(value, str) and value for value in command)
        and not credential_argv(command),
        "pivot-provenance-command",
    )
    require(
        isinstance(row.get("revision"), str)
        and re.fullmatch(r"[0-9a-f]{40}", row["revision"]),
        "pivot-provenance-revision",
    )
    require(
        isinstance(row.get("host"), str) and bool(row["host"]),
        "pivot-provenance-host",
    )
    try:
        started = datetime.strptime(field(row, "date"), "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as error:
        raise Refused("pivot-provenance-date") from error
    require(MIN_DATE <= started <= MAX_DATE, "pivot-provenance-date")
    artifact(row, "raw_log", "raw-log", root)
    rc_path = artifact(row, "raw_rc", "raw-rc", root)
    try:
        rc = rc_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise Refused("raw-rc-unreadable") from error
    require(rc == "0\n", "pivot-provenance-exit")
    return root


def durations_artifact(row, root, prefix="durations"):
    path_field = prefix + "_artifact"
    digest_field = path_field + "_sha256"
    supplied = Path(field(row, path_field))
    require(supplied.is_absolute(), f"{prefix}-artifact-path")
    try:
        path = supplied.resolve(strict=True)
    except OSError as error:
        raise Refused(f"{prefix}-artifact-missing") from error
    require(path.is_file(), f"{prefix}-artifact-not-file")
    require(path.suffix == ".ns", f"{prefix}-artifact-suffix")
    require(contained(path, root), f"{prefix}-artifact-outside-run-root")
    require(not contained(path, REPOSITORY), f"{prefix}-artifact-inside-repository")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
        pairs = [tuple(int(value) for value in line.split("\t")) for line in lines]
    except (OSError, UnicodeError, ValueError) as error:
        raise Refused(f"{prefix}-artifact-invalid") from error
    require(
        len(pairs) == row.get("sample_count")
        and all(len(pair) == 2 for pair in pairs)
        and pairs == sorted(pairs)
        and sorted(index for _, index in pairs) == list(range(len(pairs)))
        and all(value >= 0 for value, _ in pairs),
        f"{prefix}-artifact-invalid",
    )
    require(
        digest(path) == field(row, digest_field),
        f"{prefix}-artifact-hash-mismatch",
    )
    by_index = sorted(pairs, key=lambda pair: pair[1])
    return [value for value, _ in by_index]


def credential_argv(command):
    return any(CREDENTIAL.search(value) for value in command)


RECOVERY_HANDOFF_PATHS = (
    "signing-seed-path",
    "client-cert-path",
    "client-credential-path",
)


def recovery_command(gran, handoff, acknowledge_takeover):
    """Build the documented offline lost-store recovery from public handoff fields."""
    root = Path(handoff_text(handoff, "client-root-path"))
    writer = handoff_text(handoff, "client-writer")
    pin = handoff_text(handoff, "server-pin")
    publisher = handoff_text(handoff, "root-key")
    require(re.fullmatch(r"[0-9a-f]{32}", writer), "recovery-writer-invalid")
    require(re.fullmatch(r"[0-9a-f]{64}", pin), "recovery-pin-invalid")
    require(re.fullmatch(r"[0-9a-f]{64}", publisher), "recovery-publisher-invalid")
    command = [
        str(Path(gran).resolve(strict=True)),
        "--log-format",
        "json",
        "recover",
        str(root / "store"),
        handoff_text(handoff, "volume"),
        "--writer",
        writer,
        "--key-seed",
        handoff_text(handoff, "signing-seed-path"),
        "--endpoint",
        handoff_text(handoff, "base-url"),
        "--pin",
        "sha256/" + base64.b64encode(bytes.fromhex(pin)).decode("ascii"),
        "--client-cert",
        handoff_text(handoff, "client-cert-path"),
        "--client-key",
        handoff_text(handoff, "client-credential-path"),
        "--credential-context",
        handoff_text(handoff, "credential-context"),
        "--publisher-key",
        "ed25519:" + publisher,
    ]
    if acknowledge_takeover:
        command.extend(("--acknowledge-takeover", writer))
    require(not credential_argv(command), "credential-in-command")
    return command


def recorded_recovery_argv(command, handoff):
    """Replace local executable and custody paths with stable receipt labels."""
    replacements = {
        str(Path(command[0]).resolve(strict=True)): "gran@measured-revision",
        str(Path(handoff_text(handoff, "client-root-path")) / "store"):
            "@handoff/client-root-path/store",
    }
    replacements.update(
        {
            handoff_text(handoff, name): f"@handoff/{name}"
            for name in RECOVERY_HANDOFF_PATHS
        }
    )
    return [replacements.get(value, value) for value in command]


def recovery_argv_is_documented(argv, acknowledge_takeover):
    """Recognise one exact documented selection or takeover invocation."""
    expected_length = 24 if acknowledge_takeover else 22
    if not isinstance(argv, list) or len(argv) != expected_length:
        return False
    fixed = {
        0: "gran@measured-revision",
        1: "--log-format",
        2: "json",
        3: "recover",
        4: "@handoff/client-root-path/store",
        6: "--writer",
        8: "--key-seed",
        9: "@handoff/signing-seed-path",
        10: "--endpoint",
        12: "--pin",
        14: "--client-cert",
        15: "@handoff/client-cert-path",
        16: "--client-key",
        17: "@handoff/client-credential-path",
        18: "--credential-context",
        20: "--publisher-key",
    }
    return (
        all(argv[index] == value for index, value in fixed.items())
        and isinstance(argv[5], str)
        and bool(argv[5])
        and re.fullmatch(r"[0-9a-f]{32}", argv[7]) is not None
        and isinstance(argv[11], str)
        and argv[11].startswith("https://")
        and re.fullmatch(r"sha256/[A-Za-z0-9+/]{43}=", argv[13]) is not None
        and isinstance(argv[19], str)
        and bool(argv[19])
        and re.fullmatch(r"ed25519:[0-9a-f]{64}", argv[21]) is not None
        and (
            not acknowledge_takeover
            or argv[22:] == ["--acknowledge-takeover", argv[7]]
        )
        and "--log-paths" not in argv
        and "--construction-workspace-mib" not in argv
        and "--overlay-cap-bytes" not in argv
    )


def recovery_log(receipt):
    """Read one sealed recovery log and decode only its JSON event lines."""
    log = Path(receipt.get("raw_log", ""))
    try:
        lines = log.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise Refused("recovery-verb-log-unreadable") from error
    events = []
    for line in lines:
        try:
            record = json.loads(line, object_pairs_hook=unique_object)
        except (ValueError, Refused):
            continue
        if isinstance(record, dict):
            events.append(record)
    return log, lines, events


def recovery_ending(receipt):
    """Record the verbatim observable ending of one recovery invocation."""
    log, lines, records = recovery_log(receipt)
    return log, records, {
        "exit_code": receipt.get("exit_code"),
        "events_seen": records,
        "completion_line_present": any(
            line.startswith("JournalFinished:") for line in lines
        ),
    }


def validate_recovery_completion(receipt, expected_seq, observed_head):
    """Require event-backed completion and a head at the landed sequence."""
    log, records, ending = recovery_ending(receipt)
    events = [record.get("event") for record in records]
    if receipt.get("exit_code") == 2:
        raise Refused("recovery-verb-argv-bug")
    if receipt.get("exit_code") == 1:
        blocked = [
            str(record.get("reason"))
            for record in records
            if record.get("event") == "recover.journal_blocked"
        ]
        raise Refused(
            "recovery-verb-blocked:" + blocked[0]
            if blocked
            else "recovery-verb-failed"
        )
    if receipt.get("exit_code") == 3:
        raise Refused("recovery-verb-exit-3")
    if receipt.get("exit_code") == 124:
        raise Refused("recovery-verb-timeout")
    require(receipt.get("exit_code") == 0, "recovery-verb-exit")
    journal_finished = "recover.journal_finished" in events
    landed = [
        record.get("seq")
        for record in records
        if record.get("event") == "recover.landed"
    ]
    if not journal_finished and not landed and "recover.nothing" in events:
        raise Refused("recovery-verb-nothing-owed")
    require(
        journal_finished or expected_seq in landed,
        "recovery-verb-incomplete",
    )
    require(
        observed_head.get("sequence") == expected_seq,
        "recovery-verb-head-mismatch: sequence",
    )
    require(
        isinstance(observed_head.get("identifier"), str)
        and re.fullmatch(r"01[0-9a-f]{64}", observed_head["identifier"]),
        "recovery-verb-head-mismatch: identifier",
    )
    # terminal::write_line is best-effort; the structured event, not its
    # JournalFinished rendering, is the durable completion observation.
    return log, ending


SELECTION_REPORT = re.compile(
    r"selected E=([0-9]+) G=([0-9]+) "
    r"root=(blake3:[0-9a-f]{64}) parent_seq=([0-9]+)"
)


def intent_selection(handoff, index=1):
    """Read the client's signature-verified intent-row observation."""
    fields = handoff_text(handoff, f"client-intent-selection-{index}").split()
    require(
        len(fields) == 4
        and fields[0].isascii()
        and fields[0].isdigit()
        and fields[1].isascii()
        and fields[1].isdigit()
        and re.fullmatch(r"blake3:[0-9a-f]{64}", fields[2])
        and fields[3].isascii()
        and fields[3].isdigit(),
        "recovery-intent-selection-invalid",
    )
    return {
        "epoch": int(fields[0]),
        "generation": int(fields[1]),
        "root": fields[2],
        "parent_seq": int(fields[3]),
    }


def phase_one_selection(receipt, store, expected):
    """Require the unacknowledged read-only selection and its exact binding."""
    log, lines, _ = recovery_log(receipt)
    require(receipt.get("exit_code") == 1, "recovery-selection-exit")
    require(not Path(store).exists(), "recovery-selection-mutated-store")
    matches = [SELECTION_REPORT.search(line) for line in lines]
    matches = [match for match in matches if match is not None]
    require(len(matches) == 1, "recovery-selection-report-invalid")
    match = matches[0]
    observed = {
        "epoch": int(match.group(1)),
        "generation": int(match.group(2)),
        "root": match.group(3),
        "parent_seq": int(match.group(4)),
    }
    require(observed == expected, "recovery-selection-mismatch")
    require(
        any("IntentSelectionBinding: --acknowledge-takeover must name --writer" in line for line in lines),
        "recovery-selection-report-invalid",
    )
    return log, observed, recovery_ending(receipt)[2]


def recovery_verb_record(
    verb,
    command,
    handoff,
    receipt,
    elapsed,
    log,
    selection,
    ending,
    expected_result,
    store_absent_after,
    head_after_verb,
    authority_readback,
):
    return {
        "verb": verb,
        "argv": recorded_recovery_argv(command, handoff),
        "exit_code": receipt["exit_code"],
        "elapsed_ns": elapsed,
        "json_log": log.name,
        "json_log_sha256": receipt["raw_log_sha256"],
        "log_path_scope": "redacted",
        "construction_workspace_mib": "default",
        "overlay_cap_bytes": "default",
        "selection": selection,
        "selection_artifact": log.name if selection is not None else None,
        "selection_artifact_sha256": receipt["raw_log_sha256"] if selection is not None else None,
        "ending": ending,
        "expected_result": expected_result,
        "store_absent_after": store_absent_after,
        "endpoint_source": "@handoff/base-url",
        "credential_context_source": "@handoff/credential-context",
        "head_after_verb": head_after_verb,
        "authority_readback": authority_readback,
    }


def grain_id_binary(identifier):
    require(
        isinstance(identifier, str)
        and re.fullmatch(r"blake3:[0-9a-f]{64}", identifier),
        "recovery-root-evidence-invalid",
    )
    return "01" + identifier.removeprefix("blake3:")


def recovery_artifact(path, label=None):
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as error:
        raise Refused("recovery-authority-readback-missing") from error
    require(size > 0, "recovery-authority-readback-empty")
    return {
        "artifact": path.name if label is None else str(label),
        "artifact_sha256": digest(path),
    }


def validate_recovery_root_evidence(
    expected_selection,
    expected_seq,
    head_before_phase_two,
    chain_head,
    expected_writer,
    writer_state,
    fields,
):
    """Decide recovery from decoded content; retain byte identity as diagnostic."""
    required = {
        "prepared_root_id",
        "published_root_id",
        "prepared_seq",
        "published_seq",
        "prepared_parent",
        "published_parent",
        "prepared_manifest_root",
        "published_manifest_root",
        "prepared_writer",
        "published_writer",
        "field_diff",
    }
    require(set(fields) == required, "recovery-root-evidence-invalid")
    try:
        prepared_seq = int(fields["prepared_seq"])
        published_seq = int(fields["published_seq"])
    except (TypeError, ValueError) as error:
        raise Refused("recovery-root-evidence-invalid") from error
    for name in ("prepared_root_id", "published_root_id"):
        grain_id_binary(fields[name])
    for name in ("prepared_parent", "published_parent"):
        require(
            fields[name] == "none"
            or re.fullmatch(r"blake3:[0-9a-f]{64}", fields[name]),
            "recovery-root-evidence-invalid",
        )
    for name in ("prepared_manifest_root", "published_manifest_root"):
        require(
            re.fullmatch(r"blake3:[0-9a-f]{64}", fields[name]),
            "recovery-root-evidence-invalid",
        )
    require(
        re.fullmatch(r"[0-9a-f]{32}", expected_writer)
        and re.fullmatch(r"[0-9a-f]{32}", fields["prepared_writer"])
        and re.fullmatch(r"[0-9a-f]{32}", fields["published_writer"]),
        "recovery-root-evidence-invalid",
    )
    require(
        fields["prepared_root_id"] == expected_selection["root"],
        "recovery-selection-root-mismatch",
    )
    require(
        prepared_seq == published_seq == expected_seq,
        "recovery-root-sequence-mismatch",
    )
    require(
        fields["prepared_parent"] == fields["published_parent"],
        "recovery-root-parent-mismatch",
    )
    require(
        fields["prepared_manifest_root"] == fields["published_manifest_root"],
        "recovery-root-manifest-mismatch",
    )
    require(
        fields["prepared_writer"] == fields["published_writer"] == expected_writer,
        "recovery-root-writer-mismatch",
    )
    require(
        chain_head.get("sequence") == expected_seq,
        "recovery-chain-root-mismatch: sequence",
    )
    require(
        chain_head.get("identifier")
        == grain_id_binary(fields["published_root_id"]),
        "recovery-chain-root-mismatch: identifier",
    )
    require(writer_state == "released", "recovery-authority-writer-state")
    byte_identical = fields["published_root_id"] == fields["prepared_root_id"]
    field_diff = fields["field_diff"].split(",")
    require(
        field_diff != [""]
        and all(re.fullmatch(r"[a-z_]+[0-9]*", name) for name in field_diff)
        and ((field_diff == ["none"]) == byte_identical),
        "recovery-root-field-diff-invalid",
    )
    branch = (
        "exact"
        if head_before_phase_two.get("sequence") == expected_selection["parent_seq"]
        else "merge"
    )
    return {
        "head": chain_head,
        "writer_row_state": writer_state,
        "prepared_root_id": fields["prepared_root_id"],
        "published_root_id": fields["published_root_id"],
        "published_root_byte_identical": byte_identical,
        "implied_recovery_branch": branch,
        "exact_branch_byte_mismatch": branch == "exact" and not byte_identical,
        "decoded_field_diff": [] if field_diff == ["none"] else field_diff,
    }


def intent_evidence_probe(
    client_child,
    handoff,
    work,
    mode,
    readback_path,
    evidence_path,
    prepared_root_path,
    timeout,
    published_root_path=None,
):
    """Run one owned signature-verifying probe with fresh handoff fields."""
    names = (
        "client-intent-probe-mode",
        "client-intent-readback-path",
        "client-root-evidence-path",
        "client-prepared-root-path",
        "client-published-root-path",
        "client-post-recovery-intent",
    )
    for name in names:
        path = handoff / name
        if path.exists():
            path.unlink()
    private_signal(handoff / "client-intent-probe-mode", mode.encode("ascii"))
    private_signal(handoff / "client-intent-readback-path", os.fsencode(readback_path))
    private_signal(handoff / "client-root-evidence-path", os.fsencode(evidence_path))
    private_signal(handoff / "client-prepared-root-path", os.fsencode(prepared_root_path))
    if published_root_path is not None:
        private_signal(
            handoff / "client-published-root-path", os.fsencode(published_root_path)
        )
    probe = run_command(
        intent_probe_child_command(client_child, handoff),
        f"operator-recover-{mode}-evidence",
        cwd=work,
        timeout=timeout,
    )
    require(probe["exit_code"] == 0, "recovery-authority-readback-failed")
    return read_measurement_fields(evidence_path)


def run_recovery_verbs(
    gran,
    client_child,
    handoff,
    work,
    expected_selection,
    expected_landing_seq,
    timeout,
):
    """Inspect without consent, then repeat the same recovery with exact consent."""
    store = Path(handoff_text(handoff, "client-root-path")) / "store"
    require(not store.exists(), "recovery-selection-mutated-store")
    prepared_intent_path = work / "operator-recover-prepared-intent.bin"
    prepared_root_path = work / "operator-recover-prepared-root.bin"
    prepared_fields_path = work / "operator-recover-prepared-root.tsv"
    prepared_fields = intent_evidence_probe(
        client_child,
        handoff,
        work,
        "prepared",
        prepared_intent_path,
        prepared_fields_path,
        prepared_root_path,
        timeout,
    )
    expected_writer = handoff_text(handoff, "client-writer")
    require(
        set(prepared_fields) == {"root_id", "seq", "parent", "manifest_root", "writer"}
        and prepared_fields["root_id"] == expected_selection["root"]
        and prepared_fields["seq"] == str(expected_landing_seq)
        and prepared_fields["writer"] == expected_writer,
        "recovery-prepared-root-evidence-invalid",
    )
    head_before_phase_two, _ = prepublication_head(
        client_child,
        handoff,
        work,
        "operator-recover-before-phase-two-chain-head",
        timeout,
    )
    verbs = []
    for consent, stem, name in (
        (False, "operator-recover-selection", "gran recover selection"),
        (True, "operator-recover-takeover", "gran recover takeover"),
    ):
        command = recovery_command(gran, handoff, consent)
        started = time.monotonic_ns()
        receipt = run_command(command, stem, cwd=work, timeout=timeout)
        elapsed = time.monotonic_ns() - started
        if consent:
            chain_head, chain_path = chain_head_probe(
                client_child,
                handoff,
                work,
                "operator-recover-chain-head",
                timeout,
            )
            status_path = work / "operator-recover-status.bin"
            status_head = head_probe(handoff, status_path, timeout)
            status_lag = observe_status_lag(
                chain_head, status_head, "recovery-chain-status-mismatch"
            )
            published_root_path = work / "operator-recover-published-root.bin"
            volume = handoff_text(handoff, "volume")
            status, root_bytes = authority_request(
                handoff,
                "GET",
                f"/volume/{volume}/root/{expected_landing_seq:020}",
            )
            require(status == 200 and root_bytes, "recovery-published-root-readback")
            private_signal(published_root_path, root_bytes)
            readback_path = work / "operator-recover-authority-readback.bin"
            comparison_path = work / "operator-recover-root-comparison.tsv"
            comparison = intent_evidence_probe(
                client_child,
                handoff,
                work,
                "released",
                readback_path,
                comparison_path,
                prepared_root_path,
                timeout,
                published_root_path,
            )
            authority_readback = validate_recovery_root_evidence(
                expected_selection,
                expected_landing_seq,
                head_before_phase_two,
                chain_head,
                expected_writer,
                handoff_text(handoff, "client-post-recovery-intent"),
                comparison,
            )
            authority_readback.update(
                chain_head=chain_head,
                status_head=status_head,
                status_lag_seqs=status_lag,
                chain_head_artifact=recovery_artifact(
                    chain_path,
                    Path(work.name) / chain_path.name,
                ),
                head_before_phase_two=head_before_phase_two,
                prepared_intent=recovery_artifact(
                    prepared_intent_path,
                    Path(work.name) / prepared_intent_path.name,
                ),
                prepared_root=recovery_artifact(
                    prepared_root_path,
                    Path(work.name) / prepared_root_path.name,
                ),
                published_root=recovery_artifact(
                    published_root_path,
                    Path(work.name) / published_root_path.name,
                ),
                status=recovery_artifact(
                    status_path,
                    Path(work.name) / status_path.name,
                ),
                released_intent=recovery_artifact(
                    readback_path,
                    Path(work.name) / readback_path.name,
                ),
            )
            log, ending = validate_recovery_completion(
                receipt, expected_landing_seq, chain_head
            )
            selection = None
            expected_result = "journal-finished-or-landed-selected-head"
            store_absent_after = False
        else:
            log, selection, ending = phase_one_selection(
                receipt, store, expected_selection
            )
            chain_head = None
            authority_readback = None
            expected_result = "selection-report-without-local-state"
            store_absent_after = not store.exists()
        require(not contained(log, Path(handoff_text(handoff, "client-root-path"))), "recovery-verb-log-custody")
        verbs.append(
            recovery_verb_record(
                name,
                command,
                handoff,
                receipt,
                elapsed,
                log,
                selection,
                ending,
                expected_result,
                store_absent_after,
                chain_head,
                authority_readback,
            )
        )
    return verbs


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, f"duplicate-json-key: {name}")
        result[name] = value
    return result


def quantile_interval(values, quantile, confidence):
    """Return a distribution-free confidence bracket for one population quantile."""
    require(
        isinstance(values, list)
        and values
        and all(type(value) is int and value >= 0 for value in values),
        "quantile-interval-samples",
    )
    require(
        type(quantile) is float
        and 0 < quantile < 1
        and type(confidence) is float
        and 0 < confidence < 1,
        "quantile-interval-parameters",
    )
    ordered = sorted(values)
    q = Fraction(str(quantile))
    tail = (1 - Fraction(str(confidence))) / 2
    survival = Fraction(0)
    mass = q ** len(ordered)
    lower = None
    upper = None
    # For B ~ Binomial(n,q), the lower rank is the largest l with
    # P(B <= l-1) <= tail, and the upper is the smallest u with
    # P(B >= u) <= tail. Descending exact rational recurrence computes both
    # without float overflow or hard-coded sample indices.
    for rank in range(len(ordered), 0, -1):
        survival += mass
        if survival <= tail:
            upper = rank
        if lower is None and survival >= 1 - tail:
            lower = rank
        if lower is not None and upper is not None:
            break
        if rank > 1:
            mass *= Fraction(rank, len(ordered) - rank + 1) * Fraction(1 - q, q)
    require(
        lower is not None and upper is not None and lower <= upper,
        "quantile-interval-population",
    )
    return ordered[lower - 1], ordered[upper - 1]


def pivot_verdict(numerator_interval, denominator_interval):
    """Classify the ruled strict-double/100-ms pivot with interval uncertainty."""
    require(
        isinstance(numerator_interval, (tuple, list))
        and isinstance(denominator_interval, (tuple, list))
        and len(numerator_interval) == len(denominator_interval) == 2
        and all(type(value) is int and value >= 0 for value in numerator_interval)
        and all(type(value) is int and value >= 0 for value in denominator_interval)
        and numerator_interval[0] <= numerator_interval[1]
        and denominator_interval[0] <= denominator_interval[1],
        "pivot-interval-invalid",
    )
    numerator_low, numerator_high = numerator_interval
    denominator_low, denominator_high = denominator_interval
    if numerator_low > 2 * denominator_high or numerator_low > 100_000_000:
        return "pivot"
    if numerator_high <= 2 * denominator_low and numerator_high <= 100_000_000:
        return "no pivot"
    return "inconclusive"


def lower_bound_pivot_verdict(numerator_interval, denominator_interval):
    """Classify with a lower-rate denominator without declaring a pivot."""
    normal = pivot_verdict(numerator_interval, denominator_interval)
    return "no pivot" if normal == "no pivot" else "inconclusive"


def hypergeometric_tail(population, exceedances, half_size, critical):
    """Return the exact probability that either half has `critical` exceedances."""
    # For X in the first half, P(X=x) = C(K,x) C(N-K,n-x) / C(N,n).
    denominator = math.comb(population, half_size)
    lower = max(0, exceedances - (population - half_size))
    upper = min(exceedances, half_size)
    numerator = sum(
        math.comb(exceedances, first)
        * math.comb(population - exceedances, half_size - first)
        for first in range(lower, upper + 1)
        if first >= critical or exceedances - first >= critical
    )
    return Fraction(numerator, denominator)


def exceedance_split(durations, percentile):
    """Describe an exact two-sided half split above one pooled quantile."""
    population = len(durations)
    half_size = population // 2
    ordered = sorted(durations)
    threshold = ordered[math.ceil(population * percentile / 100) - 1]
    first = sum(value > threshold for value in durations[:half_size])
    second = sum(value > threshold for value in durations[half_size:])
    exceedances = first + second
    critical = next(
        candidate
        for candidate in range(1, exceedances + 2)
        if hypergeometric_tail(population, exceedances, half_size, candidate)
        <= Fraction(1, 20)
    )
    tail = hypergeometric_tail(population, exceedances, half_size, critical)
    return {
        "population": population,
        "quantile": percentile,
        "threshold_ns": threshold,
        "exceedances": exceedances,
        "critical_count": critical,
        "split": [first, second],
        "tail_probability": f"{tail.numerator}/{tail.denominator}",
    }


def median_halves_steady(first, second, tolerance):
    return abs(first - second) <= max(first, second, 1) * tolerance


def steady_state(durations, tolerance):
    """Compare half medians and exact pooled-tail exceedance splits."""
    require(
        isinstance(durations, list)
        and len(durations) >= 2
        and len(durations) % 2 == 0
        and all(type(value) is int and value >= 0 for value in durations),
        "steady-state-samples",
    )
    require(tolerance == STEADY_STATE_TOLERANCE, "steady-state-tolerance")
    midpoint = len(durations) // 2
    first_half, second_half = durations[:midpoint], durations[midpoint:]
    first_median = round(statistics.median(first_half))
    second_median = round(statistics.median(second_half))

    def p99(values):
        ordered = sorted(values)
        return ordered[math.ceil(len(ordered) * 0.99) - 1]

    first_p99, second_p99 = p99(first_half), p99(second_half)
    splits = [exceedance_split(durations, 95)]
    if len(durations) >= 1000:
        splits.append(exceedance_split(durations, 99))
    median_steady = median_halves_steady(first_median, second_median, tolerance)
    tail_steady = all(max(split["split"]) < split["critical_count"] for split in splits)
    outcome = "steady" if median_steady and tail_steady else "not steady"
    return (
        first_median,
        second_median,
        first_p99,
        second_p99,
        splits,
        outcome,
    )


def pivot_steady_pattern(steady):
    """Classify the all-late tail split without changing admissibility."""
    first_median, second_median, _, _, splits, _ = steady
    if second_median > first_median and all(
        split["exceedances"] >= 1
        and split["split"] == [0, split["exceedances"]]
        for split in splits
    ):
        return "latency-rising"
    return "other"


def pivot_exceedance_histograms(durations, splits):
    """Count pooled-quantile exceedances in consecutive 100-sample blocks."""
    require(len(durations) % 100 == 0, "pivot-exceedance-histogram-population")
    return [
        {
            "quantile": split["quantile"],
            "threshold_ns": split["threshold_ns"],
            "block_size": 100,
            "counts": [
                sum(value > split["threshold_ns"] for value in durations[start : start + 100])
                for start in range(0, len(durations), 100)
            ],
        }
        for split in splits
    ]


def validate_offload_state(text):
    """Require TSO, GSO and GRO to be observed disabled on one veth end."""
    require(isinstance(text, str) and bool(text), "offload-state-invalid")
    names = {
        "tcp-segmentation-offload": "tso",
        "generic-segmentation-offload": "gso",
        "generic-receive-offload": "gro",
    }
    observed = {}
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in names:
            state = value.strip().split(maxsplit=1)[0]
            require(state in ("on", "off"), "offload-state-invalid")
            observed[names[name]] = state == "on"
    require(set(observed) == set(names.values()), "offload-state-invalid")
    require(not any(observed.values()), "offload-state-invalid")
    return observed


def read_workload_ledger(path):
    """Read the workload child's durable fsync ledger and write-byte counter."""
    path = Path(path)
    require(path.is_absolute() and not contained(path, REPOSITORY), "recovery-ledger-path")
    try:
        rows = [
            json.loads(line, object_pairs_hook=unique_object)
            for line in path.read_text(encoding="ascii").splitlines()
        ]
    except (OSError, UnicodeError, ValueError, Refused) as error:
        raise Refused("recovery-ledger-unreadable") from error
    ledger = []
    counters = []
    for row in rows:
        require(
            isinstance(row, dict) and isinstance(row.get("kind"), str),
            "recovery-ledger-row-invalid",
        )
        if row["kind"] == "write-call-bytes":
            require(
                set(row) == {"kind", "cumulative_write_call_bytes"}
                and type(row.get("cumulative_write_call_bytes")) is int
                and row["cumulative_write_call_bytes"] > 0,
                "recovery-ledger-counter-record-invalid",
            )
            counters.append(row["cumulative_write_call_bytes"])
            continue
        require(
            row.get("kind") == "successful-fsync"
            and set(row)
            == {
                "kind",
                "operation_id",
                "content_sha256",
                "unique_content_bytes",
                "cumulative_write_call_bytes",
            }
            and isinstance(row.get("operation_id"), str)
            and bool(row["operation_id"])
            and re.fullmatch(r"[0-9a-f]{64}", str(row.get("content_sha256")))
            and type(row.get("unique_content_bytes")) is int
            and row["unique_content_bytes"] > 0
            and type(row.get("cumulative_write_call_bytes")) is int
            and row["cumulative_write_call_bytes"] > 0,
            "recovery-ledger-fsync-record-invalid",
        )
        require(
            counters and row["cumulative_write_call_bytes"] == counters[-1],
            "recovery-ledger-counter-mismatch",
        )
        ledger.append(
            {
                "operation_id": row["operation_id"],
                "content_sha256": row["content_sha256"],
                "unique_content_bytes": row["unique_content_bytes"],
            }
        )
    require(
        ledger
        and counters
        and counters == sorted(set(counters))
        and len({item["operation_id"] for item in ledger}) == len(ledger),
        "recovery-ledger-sequence-invalid",
    )
    return ledger, counters[-1], digest(path)


def bind_recovery_ledgers(expected_ledger, expected_write_bytes, loss, intact):
    """Bind the pair to both workload-written artifacts, then check the plan."""
    require(
        loss.get("ledger") == intact.get("ledger") == expected_ledger
        and loss.get("cumulative_write_call_bytes")
        == intact.get("cumulative_write_call_bytes")
        == expected_write_bytes,
        "recovery-ledger-plan-mismatch",
    )
    return loss["ledger"], loss["cumulative_write_call_bytes"]


def write_duration_artifact(path, durations):
    """Write sorted per-sample nanoseconds and return the retained artifact fields."""
    path = Path(path)
    require(path.is_absolute() and path.suffix == ".ns", "durations-artifact-path")
    require(
        isinstance(durations, list)
        and durations
        and all(type(value) is int and value >= 0 for value in durations),
        "durations-artifact-invalid",
    )
    values = sorted((value, index) for index, value in enumerate(durations))
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        data = "".join(f"{value}\t{index}\n" for value, index in values).encode("ascii")
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            require(count > 0, "durations-artifact-write")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return str(path), digest(path)


def loop_mount_option(environment=None):
    """Select only the loop node reserved for this venue run."""
    environment = os.environ if environment is None else environment
    device = environment.get("GRANARY_Q3_LOOP_DEVICE")
    if device is None:
        return "loop"
    require(re.fullmatch(r"/dev/loop[0-9]+", device), "loop-device-invalid")
    return f"loop={device}"


def venue_loop_pairs(environment=None):
    """Return the venue-owned preattached loop nodes and their image paths."""
    environment = os.environ if environment is None else environment
    devices = environment.get("GRANARY_Q3_LOOP_DEVICES")
    images = environment.get("GRANARY_Q3_LOOP_IMAGES")
    if devices is None and images is None:
        return []
    require(isinstance(devices, str) and isinstance(images, str), "loop-device-invalid")
    device_values = devices.split(",")
    image_values = images.split(",")
    require(
        len(device_values) == len(image_values) == 3,
        "loop-device-invalid",
    )
    pairs = []
    for device, image in zip(device_values, image_values):
        path = Path(image)
        require(
            re.fullmatch(r"/dev/loop[0-9]+", device)
            and path.is_absolute()
            and not contained(path, REPOSITORY),
            "loop-device-invalid",
        )
        pairs.append((device, path))
    return pairs


def recovery_image(work, environment=None):
    """Choose the first still-linked venue image, or a local loop image."""
    pairs = venue_loop_pairs(environment)
    if not pairs:
        return Path(work) / "client.img"
    for _device, image in pairs:
        if image.is_file():
            return image
    raise Refused("loop-image-exhausted")


def replacement_image(image, environment=None):
    """Choose the preattached successor while the old loop remains owned."""
    pairs = venue_loop_pairs(environment)
    if not pairs:
        return Path(image)
    for index, (_device, candidate) in enumerate(pairs):
        if candidate == Path(image):
            require(index + 1 < len(pairs), "loop-image-exhausted")
            successor = pairs[index + 1][1]
            require(successor.is_file(), "loop-image-exhausted")
            return successor
    raise Refused("loop-device-invalid")


def mount_image_command(image, mountpoint):
    for device, candidate in venue_loop_pairs():
        if candidate == Path(image):
            return ["mount", "--", device, str(mountpoint)]
    return ["mount", "-o", loop_mount_option(), "--", str(image), str(mountpoint)]


def refresh_loop_capacity(
    image, size_bytes, *, stem_prefix="image", command=None, cwd=None
):
    """Refresh and verify one preattached venue loop node after file growth."""
    command = checked if command is None else command
    for device, candidate in venue_loop_pairs():
        if candidate != Path(image):
            continue
        command(
            ["losetup", "-c", device],
            f"{stem_prefix}-loop-capacity-refresh",
            cwd=cwd,
        )
        observed = command(
            ["blockdev", "--getsize64", device],
            f"{stem_prefix}-loop-capacity-size",
            cwd=cwd,
        ).strip()
        require(
            observed.isascii()
            and observed.isdigit()
            and int(observed) == size_bytes,
            "loop-device-size-mismatch",
        )
        return


def refresh_and_mount_image(
    image,
    mountpoint,
    size_bytes,
    stem,
    *,
    capacity_stem_prefix="image",
    command=None,
    cwd=None,
):
    """Refresh a preattached node before mounting that same image."""
    command = checked if command is None else command
    refresh_loop_capacity(
        image,
        size_bytes,
        stem_prefix=capacity_stem_prefix,
        command=command,
        cwd=cwd,
    )
    command(mount_image_command(image, mountpoint), stem, cwd=cwd)


def create_and_mount_recovery_image(image, mountpoint, size_bytes, *, command=None, cwd=None):
    """Create, format, refresh, and then mount one recovery image."""
    command = checked if command is None else command
    command(["truncate", "-s", str(size_bytes), str(image)], "image-create", cwd=cwd)
    command(["mkfs.ext4", "-q", "-F", str(image)], "image-format", cwd=cwd)
    refresh_and_mount_image(
        image, mountpoint, size_bytes, "image-mount", command=command, cwd=cwd
    )


def loss_image_commands(image, mountpoint, size_bytes, replacement=None):
    """Return the bounded whole-image replacement command sequence."""
    image = Path(image)
    replacement = image if replacement is None else Path(replacement)
    mountpoint = Path(mountpoint)
    require(
        image.is_absolute()
        and mountpoint.is_absolute()
        and not contained(image, REPOSITORY)
        and not contained(mountpoint, REPOSITORY),
        "loss-image-path",
    )
    require(
        type(size_bytes) is int and 0 < size_bytes <= 4_294_967_296,
        "loss-image-size",
    )
    return [
        ["umount", "--", str(mountpoint)],
        ["truncate", "-s", str(size_bytes), str(replacement)],
        ["mkfs.ext4", "-q", "-F", str(replacement)],
        mount_image_command(replacement, mountpoint),
    ]


def abort_fuse_connection(path):
    """Abort exactly one connection selected from the owned FUSE mount."""
    try:
        descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            require(os.write(descriptor, b"1\n") == 2, "client-fuse-abort")
        finally:
            os.close(descriptor)
    except OSError as error:
        raise Refused("client-fuse-abort") from error


def observe_intact_image_uuid(image, before_uuid, evidence_dir, *, command=None):
    """Read, rather than infer, the intact image UUID after client restart."""
    command = checked if command is None else command
    after_uuid = command(
        ["blkid", "-s", "UUID", "-o", "value", str(image)],
        "intact-image-uuid-after",
        cwd=evidence_dir,
    ).strip()
    require(bool(after_uuid) and after_uuid == before_uuid, "intact-image-witness")
    return after_uuid


def stop_client_and_detach_fuse(
    running,
    mountpoint,
    evidence_dir,
    *,
    stem_prefix="client-fuse",
    command=None,
    abort=None,
):
    """Stop one owned client, abort its FUSE connection, then detach its mount."""
    command = checked if command is None else command
    abort = abort_fuse_connection if abort is None else abort
    mountpoint = Path(mountpoint)
    evidence_dir = Path(evidence_dir)
    require(
        evidence_dir.is_dir() and not contained(evidence_dir, mountpoint),
        "client-fuse-evidence-path",
    )
    record = finish_command(running, timeout=1, stop_signal=signal.SIGKILL)
    observed = command(
        ["findmnt", "-n", "-o", "FSTYPE,MAJ:MIN", "--target", str(mountpoint)],
        f"{stem_prefix}-mount",
        cwd=evidence_dir,
    ).split()
    require(
        len(observed) == 2
        and observed[0].startswith("fuse")
        and re.fullmatch(r"0:[0-9]+", observed[1]),
        "client-fuse-mount-invalid",
    )
    connection = Path("/sys/fs/fuse/connections") / observed[1].split(":", 1)[1] / "abort"
    abort(connection)
    command(
        ["umount", "-l", "--", str(mountpoint)],
        f"{stem_prefix}-unmount",
        cwd=evidence_dir,
    )
    return record


def replace_client_root_device_witness(
    handoff, image, mountpoint, evidence_dir, *, command=None, stat=None
):
    """Rebind the private-root witness only to the mounted replacement device."""
    command = checked if command is None else command
    stat = os.stat if stat is None else stat
    before = handoff_text(handoff, "client-root-device")
    require(before.isascii() and before.isdigit(), "loss-root-device-witness")
    mounted_device = stat(mountpoint).st_dev
    replacement_device = None
    for device, candidate in venue_loop_pairs():
        if candidate == Path(image):
            replacement_device = stat(device).st_rdev
            break
    if replacement_device is None:
        observed = command(
            ["findmnt", "-n", "-o", "MAJ:MIN", "--target", str(mountpoint)],
            "loss-root-device",
            cwd=evidence_dir,
        ).strip()
        major, separator, minor = observed.partition(":")
        require(
            separator
            and major.isascii()
            and major.isdigit()
            and minor.isascii()
            and minor.isdigit(),
            "loss-root-device-witness",
        )
        replacement_device = os.makedev(int(major), int(minor))
    require(
        type(mounted_device) is int
        and type(replacement_device) is int
        and mounted_device == replacement_device,
        "loss-root-device-witness",
    )
    witness = handoff / "client-root-device"
    witness.unlink()
    private_signal(witness, str(mounted_device).encode("ascii"))
    return int(before), mounted_device, replacement_device


def replace_owned_client_image(
    running,
    image,
    mountpoint,
    size_bytes,
    survival_paths,
    handoff,
    evidence_dir,
    *,
    command=None,
    abort=None,
):
    """Stop one owned child and replace only its bounded disposable image."""
    command = checked if command is None else command
    image = Path(image).resolve(strict=True)
    mountpoint = Path(mountpoint).resolve(strict=True)
    evidence_dir = Path(evidence_dir).resolve(strict=True)
    require(image.is_file() and mountpoint.is_dir(), "loss-image-witness")
    require(
        evidence_dir.is_dir() and not contained(evidence_dir, mountpoint),
        "loss-image-evidence-path",
    )
    replacement = replacement_image(image).resolve(strict=True)
    commands = loss_image_commands(image, mountpoint, size_bytes, replacement)
    paths = [Path(path).resolve(strict=True) for path in survival_paths]
    require(
        len(paths) == 3
        and all(path.is_file() and not contained(path, mountpoint) for path in paths),
        "recovery-key-custody",
    )
    before_keys = [digest(path) for path in paths]
    before_inode = image.stat().st_ino
    before_uuid = command(
        ["blkid", "-s", "UUID", "-o", "value", str(image)],
        "loss-image-uuid-before",
        cwd=evidence_dir,
    ).strip()
    require(bool(before_uuid), "loss-image-uuid-witness")
    client_record = stop_client_and_detach_fuse(
        running,
        mountpoint / "root/mount",
        evidence_dir,
        command=command,
        abort=abort,
    )
    command(commands[0], "loss-image-unmount", cwd=evidence_dir)
    try:
        image.unlink()
    except OSError as error:
        raise Refused("loss-image-delete") from error
    require(
        not image.exists()
        and not (mountpoint / "root/store").exists()
        and not (mountpoint / "root/cache").exists(),
        "loss-old-path-witness",
    )
    command(commands[1], "loss-image-create", cwd=evidence_dir)
    require(
        replacement.is_file() and replacement.stat().st_size == size_bytes,
        "loss-image-size-witness",
    )
    after_inode = replacement.stat().st_ino
    command(commands[2], "loss-image-format", cwd=evidence_dir)
    refresh_and_mount_image(
        replacement,
        mountpoint,
        size_bytes,
        "loss-image-mount",
        capacity_stem_prefix="loss-image",
        command=command,
        cwd=evidence_dir,
    )
    before_root_device, after_root_device, replacement_root_device = (
        replace_client_root_device_witness(
            handoff, replacement, mountpoint, evidence_dir, command=command
        )
    )
    after_uuid = command(
        ["blkid", "-s", "UUID", "-o", "value", str(replacement)],
        "loss-image-uuid-after",
        cwd=evidence_dir,
    ).strip()
    require(
        bool(after_uuid)
        and before_uuid != after_uuid
        and not (mountpoint / "root/store").exists()
        and not (mountpoint / "root/cache").exists(),
        "loss-image-witness",
    )
    after_keys = [digest(path) for path in paths]
    require(before_keys == after_keys, "recovery-key-survival")
    return client_record, dict(
        before_image_uuid=before_uuid,
        after_image_uuid=after_uuid,
        before_image_inode=before_inode,
        after_image_inode=after_inode,
        before_root_device=before_root_device,
        after_root_device=after_root_device,
        replacement_root_device=replacement_root_device,
        old_paths_absent=True,
        store_destroyed=True,
        cache_destroyed=True,
        signing_seed_survived=True,
        certificate_survived=True,
        credential_survived=True,
    )


def validate_row_envelope(row):
    """Apply the row-wide type, field, and venue claims shared by all row kinds."""
    require(isinstance(row, dict), "schema-row-not-object")
    unknown = sorted(set(row).difference(SAMPLE_FIELDS))
    require(not unknown, f"schema-unknown: {','.join(unknown)}")
    require(row.get("event") in (None, "measurement"), "schema-invalid: event")
    if "venue" in row:
        require(
            isinstance(row.get("venue"), str) and row.get("venue") in VENUES,
            "pivot-venue-unrecorded",
        )
        require(type(row.get("hardware")) is bool, "schema-invalid: hardware")
        require(
            not (row.get("venue") == "vm" and row.get("hardware")),
            "vm-sample-labelled-hardware",
        )


def validate_row(row):
    require(isinstance(row, dict), "schema-row-not-object")
    unknown = sorted(set(row).difference(SAMPLE_FIELDS))
    require(not unknown, f"schema-unknown: {','.join(unknown)}")
    require(row.get("event") in (None, "measurement"), "schema-invalid: event")
    for name in TEXT_FIELDS:
        require(
            isinstance(field(row, name), str) and bool(row.get(name)),
            f"schema-invalid: {name}",
        )
    profile = field(row, "profile")
    require(profile in ("durable-prepared", "published"), "schema-invalid: profile")
    count_fields = DURABLE_COUNT_FIELDS if profile == "durable-prepared" else PUBLISHED_COUNT_FIELDS
    rtt_not_applicable = (
        row.get("event") == "measurement"
        and row.get("rtt_group") is not None
        and row.get("deciding") is False
    )
    for name in INTEGER_FIELDS + count_fields:
        if rtt_not_applicable and name in {"memory_bytes", "sample_loss", "root_bytes"}:
            require(field(row, name) is None, f"schema-invalid: {name}")
            continue
        require(
            type(field(row, name)) is int and 0 <= row.get(name) <= MAX_INTEGER,
            f"schema-invalid: {name}",
        )
    require(row.get("tid") > 0, "schema-invalid: tid")
    for name in INTENT_TEXT_FIELDS:
        require(
            isinstance(field(row, name), str) and bool(row.get(name)),
            f"schema-invalid: {name}",
        )
    for name in INTENT_INTEGER_FIELDS:
        value = field(row, name)
        require(
            value is None or type(value) is int and 0 <= value <= MAX_INTEGER,
            f"schema-invalid: {name}",
        )
    authority_log_wait = field(row, "authority_log_wait_p99_ns")
    require(
        authority_log_wait == UNMEASURED
        or type(authority_log_wait) is int
        and 0 <= authority_log_wait <= MAX_INTEGER,
        "schema-invalid: authority_log_wait_p99_ns",
    )
    cross_volume_blocked = field(row, "cross_volume_blocked_ns")
    require(
        cross_volume_blocked == NOT_APPLICABLE
        or type(cross_volume_blocked) is int
        and 0 <= cross_volume_blocked <= MAX_INTEGER,
        "schema-invalid: cross_volume_blocked_ns",
    )
    device_bytes = field(row, "device_bytes")
    require(
        device_bytes == UNMEASURED
        or type(device_bytes) is int
        and 0 <= device_bytes <= MAX_INTEGER,
        "schema-invalid: device_bytes",
    )
    device_amplification = field(row, "device_amplification")
    require(
        device_amplification is None
        or type(device_amplification) in (int, float)
        and math.isfinite(device_amplification)
        and device_amplification >= 0,
        "schema-invalid: device_amplification",
    )
    exit_code = field(row, "exit_code")
    require(
        type(exit_code) is int and -255 <= exit_code <= 255,
        "schema-invalid: exit_code",
    )
    if profile == "published":
        require(
            not any(name in row for name in DURABLE_COUNT_FIELDS),
            "published-per-fsync-request-counts",
        )
        require(
            field(row, "request_correlation") == "not request-correlated",
            "published-request-correlation",
        )
        require(
            row.get("strace_reconciled") is True,
            "published-strace-reconciliation",
        )
    else:
        require(
            not any(name in row for name in PUBLISHED_COUNT_FIELDS)
            and "request_correlation" not in row
            and "strace_reconciled" not in row,
            "durable-count-shape",
        )
    venue = field(row, "venue")
    require(isinstance(venue, str) and venue in VENUES, "schema-invalid: venue")
    require(field(row, "network_path") in NETWORK_PATHS, "schema-invalid: network_path")
    require(field(row, "root_label") in ROOT_LABELS, "schema-invalid: root_label")
    require(
        field(row, "historical_kind") in HISTORICAL_KINDS,
        "schema-invalid: historical_kind",
    )
    require(field(row, "cell_kind") in CELL_KINDS, "schema-invalid: cell_kind")
    require(field(row, "load_model") in LOAD_MODELS, "schema-invalid: load_model")
    require(
        field(row, "intent_occupancy") in INTENT_OCCUPANCIES | {NOT_APPLICABLE},
        "schema-invalid: intent_occupancy",
    )
    rtt_group = field(row, "rtt_group")
    require(
        rtt_group is None or isinstance(rtt_group, str) and bool(rtt_group),
        "schema-invalid: rtt_group",
    )
    if rtt_group is not None:
        calibration_outcome = field(row, "calibration_outcome")
        calibration_reason = field(row, "calibration_reason")
        require(
            calibration_outcome in ("calibrated", "refused"),
            "schema-invalid: calibration_outcome",
        )
        require(
            calibration_reason is None
            if calibration_outcome == "calibrated"
            else isinstance(calibration_reason, str) and bool(calibration_reason),
            "schema-invalid: calibration_reason",
        )
    else:
        require(
            row.get("calibration_outcome") is None
            and row.get("calibration_reason") is None,
            "calibration-without-rtt-group",
        )
    for name in ("achieved_rate", "rtt_ms"):
        value = field(row, name)
        if rtt_not_applicable and name == "achieved_rate":
            require(value is None, f"schema-invalid: {name}")
            continue
        require(
            type(value) in (int, float)
            and value <= MAX_INTEGER
            and (type(value) is int or math.isfinite(value))
            and value >= 0,
            f"schema-invalid: {name}",
        )
    for name in (
        "configured_rtt_ms",
        "observed_rtt_pre_ms",
        "observed_rtt_post_ms",
        "observed_rtt_ms",
    ):
        value = field(row, name)
        require(
            type(value) in (int, float)
            and value <= MAX_INTEGER
            and (type(value) is int or math.isfinite(value))
            and value >= 0,
            f"schema-invalid: {name}",
        )
    offered_rate = field(row, "offered_rate")
    require(
        offered_rate is None
        if row.get("load_model") == "closed-loop"
        else type(offered_rate) in (int, float)
        and offered_rate <= MAX_INTEGER
        and (type(offered_rate) is int or math.isfinite(offered_rate))
        and offered_rate >= 0,
        "schema-invalid: offered_rate",
    )
    for name in ("hardware", "deciding", "pivot_input", "pivot_append"):
        require(type(field(row, name)) is bool, f"schema-invalid: {name}")
    require(
        not any(
            row.get(name) is not None
            for name in (
                "rtt_k",
                "rtt_counted",
                "rtt_k_over_counted",
                "rtt_unattributed_excess",
            )
        ),
        "calibration-fields-on-measurement-row",
    )
    if row.get("network_path") == "dedicated-veth":
        require(
            type(field(row, "netem_preflight")) is bool,
            "schema-invalid: netem_preflight",
        )
        require(row.get("netem_preflight") is True, "netem-preflight-required")
        require(
            field(row, "netem_delay_placement") == "client-veth-egress"
            and isinstance(field(row, "offload_state"), dict)
            and set(row.get("offload_state")) == {"host", "client"}
            and all(
                state == {"tso": False, "gso": False, "gro": False}
                for state in row.get("offload_state").values()
            ),
            "offload-state-required",
        )
    else:
        require(
            row.get("netem_preflight") is None
            and field(row, "netem_delay_placement") == NOT_APPLICABLE
            and field(row, "offload_state") is None,
            "netem-preflight-unexpected",
        )
    require(
        field(row, "attempt_count_source") == "server-counted",
        "schema-invalid: attempt_count_source",
    )
    require(
        field(row, "operation_kind_source") == "client-attested",
        "schema-invalid: operation_kind_source",
    )
    routes = field(row, "route_attempts")
    require(
        isinstance(routes, dict)
        and routes
        and all(
            isinstance(route, str)
            and bool(route)
            and type(count) is int
            and 0 <= count <= MAX_INTEGER
            for route, count in routes.items()
        ),
        "schema-invalid: route_attempts",
    )
    pivot_group = field(row, "pivot_group")
    pivot_role = field(row, "pivot_role")
    require(
        pivot_group is None or isinstance(pivot_group, str) and bool(pivot_group),
        "schema-invalid: pivot_group",
    )
    require(
        pivot_role is None
        or isinstance(pivot_role, str)
        and pivot_role in PIVOT_ROLES,
        "schema-invalid: pivot_role",
    )
    verdict = row.get("pivot_verdict")
    require(
        verdict is None
        or verdict in ("pivot", "no pivot", "inconclusive", PIVOT_NUMERATOR_UNSTEADY),
        "schema-invalid: pivot_verdict",
    )
    for name in (
        "register_post_p99_interval_ns",
        "publish_decision_p99_interval_ns",
        "same_occupancy_publish_p99_interval_ns",
    ):
        interval = row.get(name)
        require(
            interval is None
            or isinstance(interval, list)
            and len(interval) == 2
            and all(type(value) is int and 0 <= value <= MAX_INTEGER for value in interval)
            and interval[0] <= interval[1],
            f"schema-invalid: {name}",
        )
    scale = field(row, "scale")
    scale_fields = {"volumes", "principals", "root_depth"}
    require(
        isinstance(scale, dict)
        and set(scale) == scale_fields
        and all(
            type(scale.get(name)) is int and 0 <= scale.get(name) <= MAX_INTEGER
            for name in scale_fields
        ),
        "schema-invalid: scale",
    )
    command = field(row, "command")
    require(
        isinstance(command, list)
        and command
        and all(isinstance(value, str) and value for value in command),
        "schema-invalid: command",
    )
    require(not credential_argv(command), "credential-in-command")
    revision = field(row, "revision")
    require(
        isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision),
        "revision-required",
    )
    date = field(row, "date")
    require(
        isinstance(date, str)
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", date
        ),
        "date-required",
    )
    try:
        parsed_date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as error:
        raise Refused("date-required") from error
    require(MIN_DATE <= parsed_date <= MAX_DATE, "date-out-of-range")
    root = run_root(row)
    artifact(row, "raw_log", "raw-log", root)
    rc = artifact(row, "raw_rc", "raw-rc", root)
    require(row.get("sample_count") > 0, "zero-samples")
    require(row.get("sample_floor") > 0, "sample-floor")
    require(row.get("sample_count") >= row.get("sample_floor"), "sample-floor")
    require(
        row.get("cell_kind") != "steady" or row.get("sample_floor") >= 1000,
        "steady-sample-floor",
    )
    duration_values = durations_artifact(row, root)
    try:
        rc_text = rc.read_text()
    except (OSError, UnicodeError, ValueError) as error:
        raise Refused("raw-rc-invalid") from error
    require(
        re.fullmatch(r"(?:0|[1-9][0-9]*|-[1-9][0-9]*)\n", rc_text), "raw-rc-invalid"
    )
    require(len(rc_text) <= 5, "raw-rc-invalid")
    rc_value = int(rc_text)
    require(rc_value == exit_code, "raw-rc-exit-mismatch")
    require(rc_value == 0, "command-exit-nonzero")
    require(rtt_not_applicable or row.get("sample_loss") == 0, "sample-loss")
    require(
        not (row.get("venue") == "vm" and field(row, "hardware") is True),
        "vm-sample-labelled-hardware",
    )
    require(
        not (row.get("m15_delta") > 0 and field(row, "deciding") is True),
        "m15-delta-row-deciding",
    )
    require(
        row.get("deciding") is not True or row.get("m15_fallback_delta") == 1,
        "m15-fallback-calibration",
    )
    require(
        row.get("deciding") is not True or row.get("m15_reuse_delta") == 0,
        "m15-reuse-calibration",
    )
    require(row.get("cell_kind") != "steady" or row.get("warmup_count") == 32, "warmup-count")
    tolerance = field(row, "steady_state_tolerance")
    require(tolerance == STEADY_STATE_TOLERANCE, "steady-state-tolerance")
    if row.get("cell_kind") == "steady":
        (
            first,
            second,
            first_p99,
            second_p99,
            splits,
            outcome,
        ) = steady_state(duration_values, tolerance)
        require(
            (
                field(row, "steady_first_half_median_ns"),
                field(row, "steady_second_half_median_ns"),
                field(row, "steady_first_half_p99_ns"),
                field(row, "steady_second_half_p99_ns"),
                field(row, "steady_exceedance_splits"),
                field(row, "steady_state"),
            )
            == (
                first,
                second,
                first_p99,
                second_p99,
                splits,
                outcome,
            ),
            "steady-state-mismatch",
        )
        require(not (row.get("deciding") and outcome != "steady"), "not-steady")
    else:
        require(
            field(row, "steady_first_half_median_ns") is None
            and field(row, "steady_second_half_median_ns") is None
            and field(row, "steady_first_half_p99_ns") is None
            and field(row, "steady_second_half_p99_ns") is None
            and field(row, "steady_exceedance_splits") is None
            and field(row, "steady_state") == NOT_APPLICABLE,
            "steady-state-unexpected",
        )
    require(
        "kernel timer granularity" in field(row, "venue_text").casefold()
        and "cannot" in row.get("venue_text").casefold(),
        "venue-timer-caveat",
    )
    require(
        row.get("rtt_ms") == row.get("observed_rtt_ms"),
        "observed-rtt-mismatch",
    )
    require(
        row.get("fsync_min_ns")
        <= row.get("fsync_p50_ns")
        <= row.get("fsync_p90_ns")
        <= row.get("fsync_p99_ns")
        <= row.get("fsync_max_ns"),
        "fsync-distribution-order",
    )
    ordered_duration = sorted(duration_values)
    duration_percentile = lambda percent: ordered_duration[
        max(math.ceil(len(ordered_duration) * percent / 100) - 1, 0)
    ]
    require(
        (
            row.get("fsync_min_ns"),
            row.get("fsync_p50_ns"),
            row.get("fsync_p90_ns"),
            row.get("fsync_p99_ns"),
            row.get("fsync_max_ns"),
        )
        == (
            ordered_duration[0],
            duration_percentile(50),
            duration_percentile(90),
            duration_percentile(99),
            ordered_duration[-1],
        ),
        "fsync-distribution-artifact-mismatch",
    )
    if profile == "durable-prepared":
        require(
            row.get("register_repeated_arrivals") <= row.get("register_attempts"),
            "register-arrival-counts",
        )
        require(
            sum(routes.values())
            == row.get("register_attempts") + row.get("background_attempts"),
            "route-attempt-counts",
        )
    else:
        require(
            row.get("successful_fsyncs") > 0
            and row.get("successful_fsyncs")
            == row.get("sample_count") + row.get("warmup_count") + 3
            and row.get("logical_publishes") > 0
            and row.get("logical_publishes") == row.get("successful_fsyncs")
            and row.get("publish_attempts") >= row.get("logical_publishes"),
            "publish-population-invalid",
        )
        require(
            routes.get("POST /volume/:volume/publish") == row.get("publish_attempts"),
            "route-attempt-counts",
        )
    metrics = field(row, "verdict_metrics")
    require(
        isinstance(metrics, list)
        and all(isinstance(metric, str) for metric in metrics)
        and set(metrics) <= VERDICT_METRICS,
        "schema-invalid: verdict_metrics",
    )
    require(
        not (
            row.get("deciding") is True
            and not REQUIRED_DECIDING_METRICS <= set(metrics)
        ),
        "wall-clock-only-verdict",
    )
    require(
        not (row.get("rtt_ms") > 0 and row.get("network_path") in LOOPBACK_PATHS),
        "nonzero-rtt-loopback",
    )
    require(
        not (row.get("root_label") == "707-B" and row.get("root_bytes") != 707),
        "707-B-root-size",
    )
    require(
        not (
            row.get("root_label") == "measured length"
            and row.get("root_bytes") == 707
            and row.get("intent_occupancy") != "floor"
        ),
        "measured-root-size",
    )
    root_sizes = row.get("root_size_distribution")
    require(
        root_sizes is None
        or isinstance(root_sizes, dict)
        and root_sizes
        and all(
            isinstance(size, str)
            and size.isascii()
            and size.isdigit()
            and int(size) > 0
            and type(count) is int
            and count > 0
            for size, count in root_sizes.items()
        ),
        "root-size-distribution-invalid",
    )
    require(
        not row.get("pivot_input")
        or root_sizes is not None
        and sum(root_sizes.values()) == row.get("live_roots")
        and str(row.get("root_bytes")) in root_sizes,
        "pivot-root-size-distribution",
    )
    require(
        not (
            row.get("historical_kind") == UPPER_BOUND
            and field(row, "pivot_input") is True
        ),
        "upper-bound-h-pivot-input",
    )
    require(
        not (row.get("load_model") == "closed-loop" and row.get("pivot_input")),
        "closed-loop-pivot-input",
    )
    require(
        field(row, "pivot_input")
        == (pivot_group is not None and pivot_role is not None),
        "pivot-input-binding",
    )
    if not row.get("pivot_input"):
        require(
            not field(row, "pivot_append")
            and verdict is None
            and row.get("register_post_p99_interval_ns") is None
            and row.get("publish_decision_p99_interval_ns") is None
            and row.get("same_occupancy_publish_p99_interval_ns") is None
            and row.get("same_occupancy_publish_diagnostic") is None
            and row.get("authority_log_wait_diagnostic") is None,
            "pivot-result-without-input",
        )
        require(
            row.get("pivot_durations_artifact") is None
            and row.get("pivot_durations_artifact_sha256") is None,
            "pivot-artifact-without-input",
        )
    occupancy = row.get("intent_occupancy")
    if occupancy == NOT_APPLICABLE:
        require(
            row.get("wrapper_layer") == NOT_APPLICABLE
            and all(row.get(name) is None for name in INTENT_INTEGER_FIELDS)
            and authority_log_wait == UNMEASURED
            and cross_volume_blocked == NOT_APPLICABLE
            and device_bytes == UNMEASURED
            and device_amplification is None,
            "intent-not-applicable-fields",
        )
    else:
        require(
            row.get("wrapper_layer") != NOT_APPLICABLE
            and all(type(row.get(name)) is int for name in INTENT_INTEGER_FIELDS),
            "intent-fields-required",
        )
        require(
            row.get("load_model") != "closed-loop"
            or authority_log_wait == UNMEASURED,
            "authority-log-wait-unmeasured",
        )
        require(
            cross_volume_blocked == NOT_APPLICABLE,
            "cross-volume-blocking-not-applicable",
        )
        require(
            row.get("written_bytes") == 0 or row.get("encode_register_bytes") > 0,
            "encode-register-bytes",
        )
        if device_bytes == UNMEASURED:
            require(device_amplification is None, "device-amplification-unmeasured")
        else:
            require(row.get("encode_register_bytes") > 0, "encode-register-bytes")
            require(device_amplification is not None, "device-amplification")
            expected_amplification = device_bytes / row.get("encode_register_bytes")
            require(
                math.isclose(device_amplification, expected_amplification),
                "device-amplification",
            )
    shape = (
        row.get("row_holders"),
        row.get("zero_row_principals"),
        row.get("retired_principals"),
        row.get("historical_principals"),
        row.get("live_roots"),
        row.get("released_rows"),
    )
    if occupancy == "p1":
        require(shape == (1, 0, 0, 1, 16, 48), "occupancy-p1-shape")
    elif occupancy == "p16":
        require(shape == (16, 0, 0, 16, 256, 768), "occupancy-p16-shape")
    elif occupancy == "zero":
        require(shape == (0, 16_384, 0, 16_384, 0, 0), "occupancy-zero-shape")
    elif occupancy == "ceiling":
        require(
            shape == (16, 16_368, 0, 16_384, 256, 768),
            "occupancy-ceiling-shape",
        )
    elif occupancy == "historical":
        require(
            row.get("historical_principals") == 16_384
            and row.get("retired_principals") in (0, 4_096, 16_368),
            "occupancy-historical-shape",
        )
    elif occupancy == "upper-bound":
        require(
            row.get("historical_principals") == 65_536
            and row.get("historical_kind") == UPPER_BOUND
            and not row.get("pivot_input"),
            "occupancy-upper-bound-shape",
        )
    elif occupancy == "floor":
        require(
            row.get("row_holders") in (1, 16)
            and row.get("zero_row_principals") == 0
            and row.get("retired_principals") == 0
            and row.get("historical_principals") == row.get("row_holders"),
            "occupancy-floor-shape",
        )


def validate_recovery_pair(pair, artifact_root):
    """Validate the ruled loss/intact pair and its external durable ledger."""
    require(isinstance(pair, dict), "recovery-pair-type-invalid")
    allowed = {
        "profile",
        "ledger",
        "cumulative_write_call_bytes",
        "pre_loss_head_operations",
        "pre_loss_max_seq",
        "sentinel",
        "planned_operator_verbs",
        "loss",
        "intact",
        "gap_operations",
        "gap_bytes",
        "gap_label",
        "recovery_label",
        "recovery_start_event",
        "recovery_end_event",
        "injection_scope",
        "phase1_selection_artifact_sha256",
    }
    require(set(pair) == allowed, "recovery-pair-invalid")
    profile = pair.get("profile")
    require(profile in ("durable-prepared", "published"), "recovery-profile-invalid")
    ledger = pair.get("ledger")
    require(isinstance(ledger, list) and ledger, "recovery-ledger-invalid")
    operations = []
    lengths = {}
    for item in ledger:
        require(
            isinstance(item, dict)
            and set(item) == {"operation_id", "content_sha256", "unique_content_bytes"}
            and isinstance(item.get("operation_id"), str)
            and bool(item.get("operation_id"))
            and isinstance(item.get("content_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", item.get("content_sha256"))
            and type(item.get("unique_content_bytes")) is int
            and item.get("unique_content_bytes") > 0,
            "recovery-ledger-invalid",
        )
        operations.append(item.get("operation_id"))
        lengths[item.get("operation_id")] = item.get("unique_content_bytes")
    require(len(set(operations)) == len(operations), "recovery-ledger-invalid")
    require(
        type(pair.get("cumulative_write_call_bytes")) is int
        and pair.get("cumulative_write_call_bytes") >= sum(lengths.values()),
        "recovery-write-bytes-invalid",
    )
    head = pair.get("pre_loss_head_operations")
    require(
        isinstance(head, list)
        and all(isinstance(operation, str) and operation for operation in head)
        and len(set(head)) == len(head),
        "pre-loss-head-shape-invalid",
    )
    sentinel = pair.get("sentinel")
    require(
        isinstance(sentinel, dict)
        and set(sentinel) == {"operation_id", "content_sha256", "unique_content_bytes"}
        and isinstance(sentinel.get("operation_id"), str)
        and bool(sentinel.get("operation_id"))
        and re.fullmatch(r"[0-9a-f]{64}", str(sentinel.get("content_sha256")))
        and type(sentinel.get("unique_content_bytes")) is int
        and sentinel.get("unique_content_bytes") > 0,
        "recovery-sentinel-invalid",
    )
    sentinel_id = sentinel.get("operation_id")
    require(sentinel_id not in operations, "recovery-sentinel-operation-id")
    require(set(head) <= set(operations) | {sentinel_id}, "pre-loss-head-invalid")
    require(sentinel_id not in head, "sentinel-already-published")
    require(type(pair.get("pre_loss_max_seq")) is int and pair.get("pre_loss_max_seq") >= 0, "pre-loss-seq-invalid")
    verbs = pair.get("planned_operator_verbs")
    require(
        isinstance(verbs, list)
        and all(isinstance(verb, str) and verb for verb in verbs),
        "recovery-verbs-invalid",
    )
    expected_gap = [operation for operation in operations if operation not in head]
    expected_bytes = sum(lengths[operation] for operation in expected_gap)
    require(
        (pair.get("gap_operations"), pair.get("gap_bytes"))
        == (len(expected_gap), expected_bytes),
        "recovery-gap-mismatch",
    )
    require(
        pair.get("gap_label") == "observed RPO"
        and pair.get("recovery_label")
        == (
            "observed recovery execution time (excludes detection and diagnosis; "
            "injection-to-verified-head)"
        )
        and pair.get("recovery_start_event") == "loss-injection-complete"
        and pair.get("recovery_end_event") == "verified-head-after-restart"
        and pair.get("injection_scope")
        == "client process kill plus whole loop-image replacement; no power loss, no device fault",
        "recovery-observation-labels",
    )

    loss = pair.get("loss")
    intact = pair.get("intact")
    require(isinstance(loss, dict) and isinstance(intact, dict), "recovery-outcome-invalid")
    survival = ("signing_seed_survived", "certificate_survived", "credential_survived")
    require(all(loss.get(name) is True and intact.get(name) is True for name in survival), "recovery-key-survival")
    require(
        isinstance(loss.get("before_image_uuid"), str)
        and bool(loss.get("before_image_uuid"))
        and isinstance(loss.get("after_image_uuid"), str)
        and bool(loss.get("after_image_uuid"))
        and loss.get("before_image_uuid") != loss.get("after_image_uuid")
        and type(loss.get("before_image_inode")) is int
        and type(loss.get("after_image_inode")) is int
        and type(loss.get("before_root_device")) is int
        and type(loss.get("after_root_device")) is int
        and type(loss.get("replacement_root_device")) is int
        and loss.get("after_root_device") == loss.get("replacement_root_device")
        and loss.get("old_paths_absent") is True,
        "loss-image-witness",
    )
    require(loss.get("store_destroyed") is True and loss.get("cache_destroyed") is True, "loss-store-witness")
    require(
        isinstance(intact.get("before_image_uuid"), str)
        and bool(intact.get("before_image_uuid"))
        and isinstance(intact.get("after_image_uuid"), str)
        and bool(intact.get("after_image_uuid"))
        and intact.get("before_image_uuid") == intact.get("after_image_uuid")
        and type(intact.get("before_image_inode")) is int
        and type(intact.get("after_image_inode")) is int
        and intact.get("before_image_inode") == intact.get("after_image_inode"),
        "intact-image-witness",
    )
    for outcome in (loss, intact):
        require(
            type(outcome.get("elapsed_ns")) is int
            and outcome.get("elapsed_ns") > 0
            and type(outcome.get("final_max_seq")) is int
            and outcome.get("final_max_seq") >= pair.get("pre_loss_max_seq")
            and isinstance(outcome.get("operator_verbs"), list)
            and isinstance(outcome.get("final_head_operations"), list)
            and isinstance(outcome.get("final_head_id"), str)
            and re.fullmatch(r"[0-9a-f]{66}", outcome.get("final_head_id"))
            and outcome.get("content_probe_index") in (0, 1)
            and type(outcome.get("content_probe_bytes")) is int
            and outcome.get("content_probe_bytes") >= 4 * 1024 * 1024
            and len(outcome.get("final_head_operations"))
            == len(set(outcome.get("final_head_operations"))),
            "recovery-outcome-invalid",
        )
        final_chain = {
            "sequence": outcome["final_max_seq"],
            "identifier": outcome["final_head_id"],
        }
        require(
            observe_status_lag(
                final_chain,
                outcome.get("final_status_head"),
                "recovery-final-chain-status-mismatch",
            )
            == outcome.get("final_status_lag_seqs"),
            "recovery-final-status-lag-invalid",
        )
        status_artifact = outcome.get("final_status_artifact", {})
        status_relative = Path(str(status_artifact.get("artifact", "")))
        status_path = (Path(artifact_root).resolve() / status_relative).resolve()
        require(
            set(status_artifact) == {"artifact", "artifact_sha256"}
            and not status_relative.is_absolute()
            and status_relative.parts
            and ".." not in status_relative.parts
            and contained(status_path, Path(artifact_root).resolve())
            and re.fullmatch(
                r"[0-9a-f]{64}", str(status_artifact.get("artifact_sha256"))
            ),
            "recovery-final-status-artifact-invalid",
        )
        try:
            status_sha256 = digest(status_path)
            decoded_status = decode_volume_status_head(status_path.read_bytes())
        except OSError as error:
            raise Refused("recovery-final-status-artifact-missing") from error
        require(
            status_sha256 == status_artifact["artifact_sha256"]
            and decoded_status == outcome["final_status_head"],
            "recovery-final-status-artifact-invalid",
        )
        artifact = Path(str(outcome.get("ledger_artifact", "")))
        root = Path(artifact_root).resolve()
        require(
            not artifact.is_absolute()
            and artifact.parts
            and ".." not in artifact.parts
            and re.fullmatch(r"[0-9a-f]{64}", str(outcome.get("ledger_artifact_sha256"))),
            "recovery-ledger-artifact-shape-invalid",
        )
        artifact_path = (root / artifact).resolve()
        require(contained(artifact_path, root), "recovery-ledger-artifact-path-invalid")
        artifact_ledger, artifact_write_bytes, artifact_sha256 = read_workload_ledger(
            artifact_path
        )
        require(
            artifact_sha256 == outcome.get("ledger_artifact_sha256")
            and artifact_ledger == outcome.get("ledger") == ledger
            and artifact_write_bytes
            == outcome.get("cumulative_write_call_bytes")
            == pair.get("cumulative_write_call_bytes"),
            "recovery-ledger-artifact-mismatch",
        )
    actual_verbs = loss.get("operator_verbs")
    require(
        all(
            isinstance(verb, dict)
            and set(verb) == {
                "verb",
                "argv",
                "exit_code",
                "elapsed_ns",
                "json_log",
                "json_log_sha256",
                "log_path_scope",
                "construction_workspace_mib",
                "overlay_cap_bytes",
                "selection",
                "selection_artifact",
                "selection_artifact_sha256",
                "ending",
                "expected_result",
                "store_absent_after",
                "endpoint_source",
                "credential_context_source",
                "head_after_verb",
                "authority_readback",
            }
            and isinstance(verb.get("verb"), str)
            and not credential_argv(verb.get("argv"))
            and type(verb.get("exit_code")) is int
            and type(verb.get("elapsed_ns")) is int
            and verb.get("elapsed_ns") > 0
            and re.fullmatch(r"[0-9a-f]{64}", str(verb.get("json_log_sha256")))
            and verb.get("log_path_scope") == "redacted"
            and verb.get("construction_workspace_mib") == "default"
            and verb.get("overlay_cap_bytes") == "default"
            and verb.get("endpoint_source") == "@handoff/base-url"
            and verb.get("credential_context_source")
            == "@handoff/credential-context"
            and isinstance(verb.get("ending"), dict)
            and set(verb["ending"])
            == {"exit_code", "events_seen", "completion_line_present"}
            and verb["ending"].get("exit_code") == verb.get("exit_code")
            and isinstance(verb["ending"].get("events_seen"), list)
            and all(
                isinstance(event, dict)
                and isinstance(event.get("event"), str)
                and bool(event["event"])
                for event in verb["ending"]["events_seen"]
            )
            and type(verb["ending"].get("completion_line_present")) is bool
            for verb in actual_verbs
        ),
        "recovery-verbs-invalid",
    )
    loss_root = Path(artifact_root).resolve() / f"{profile}-loss"
    for verb in actual_verbs:
        log_name = Path(str(verb.get("json_log", "")))
        require(
            log_name.name == str(log_name)
            and log_name.suffix == ".log",
            "recovery-verb-log-path",
        )
        log_path = loss_root / log_name
        try:
            log_sha256 = digest(log_path)
            _, _, parsed_events = recovery_log({"raw_log": str(log_path)})
        except OSError as error:
            raise Refused("recovery-verb-log-unreadable") from error
        require(
            log_sha256 == verb.get("json_log_sha256"),
            "recovery-verb-log-hash-mismatch",
        )
        require(
            parsed_events == verb["ending"]["events_seen"],
            "recovery-verb-events-incomplete",
        )
    require([verb["verb"] for verb in actual_verbs] == verbs, "recovery-verbs-mismatch")
    require(intact.get("operator_verbs") == [], "intact-operator-verbs")
    require(
        loss.get("content_probe_index") == 0
        and intact.get("content_probe_index") == 1,
        "recovery-content-observation",
    )
    require(
        sentinel_id not in loss.get("final_head_operations"),
        "loss-sentinel-present",
    )
    require(set(loss.get("final_head_operations")) == set(operations), "loss-final-head")
    require(
        set(intact.get("final_head_operations")) == set(operations) | {sentinel_id}
        and intact.get("final_max_seq") == pair.get("pre_loss_max_seq") + 1,
        "intact-recovery-head",
    )
    if profile == "published":
        require(
            not expected_gap
            and not verbs
            and loss.get("operator_verbs") == []
            and pair.get("phase1_selection_artifact_sha256") is None
            and loss.get("final_max_seq") == pair.get("pre_loss_max_seq"),
            "published-recovery-gap",
        )
    else:
        require(bool(expected_gap), "durable-recovery-gap")
        require(
            verbs == ["gran recover selection", "gran recover takeover"]
            and len(actual_verbs) == 2,
            "durable-recovery-verbs",
        )
        selection, takeover = actual_verbs
        require(
            recovery_argv_is_documented(selection.get("argv"), False)
            and recovery_argv_is_documented(takeover.get("argv"), True)
            and selection.get("exit_code") == 1
            and takeover.get("exit_code") == 0
            and selection.get("json_log") == "operator-recover-selection.log"
            and takeover.get("json_log") == "operator-recover-takeover.log"
            and isinstance(selection.get("selection"), dict)
            and set(selection["selection"]) == {"epoch", "generation", "root", "parent_seq"}
            and selection.get("selection_artifact") == "operator-recover-selection.log"
            and selection.get("selection_artifact_sha256")
            == selection.get("json_log_sha256")
            and pair.get("phase1_selection_artifact_sha256")
            == selection.get("selection_artifact_sha256")
            and takeover.get("selection") is None
            and takeover.get("selection_artifact") is None
            and takeover.get("selection_artifact_sha256") is None,
            "durable-recovery-verbs",
        )
        authority_readback = takeover.get("authority_readback", {})
        require(
            isinstance(authority_readback, dict)
            and set(authority_readback)
            == {
                "head",
                "chain_head",
                "status_head",
                "status_lag_seqs",
                "chain_head_artifact",
                "writer_row_state",
                "prepared_root_id",
                "published_root_id",
                "published_root_byte_identical",
                "implied_recovery_branch",
                "exact_branch_byte_mismatch",
                "decoded_field_diff",
                "head_before_phase_two",
                "prepared_intent",
                "prepared_root",
                "published_root",
                "status",
                "released_intent",
            },
            "recovery-authority-readback-shape",
        )
        artifact_base = Path(artifact_root).resolve()
        decoded_status = None
        for name in (
            "chain_head_artifact",
            "prepared_intent",
            "prepared_root",
            "published_root",
            "status",
            "released_intent",
        ):
            artifact = authority_readback.get(name, {})
            artifact_path = Path(str(artifact.get("artifact", "")))
            resolved = (artifact_base / artifact_path).resolve()
            require(
                set(artifact) == {"artifact", "artifact_sha256"}
                and not artifact_path.is_absolute()
                and artifact_path.parts
                and ".." not in artifact_path.parts
                and contained(resolved, artifact_base)
                and re.fullmatch(
                    r"[0-9a-f]{64}", str(artifact.get("artifact_sha256"))
                ),
                "recovery-authority-artifact-invalid",
            )
            try:
                observed_sha256 = digest(resolved)
                if name == "status":
                    decoded_status = decode_volume_status_head(resolved.read_bytes())
            except OSError as error:
                raise Refused("recovery-authority-readback-missing") from error
            require(
                observed_sha256 == artifact.get("artifact_sha256"),
                "recovery-authority-artifact-hash-mismatch",
            )
        expected_seq = pair.get("pre_loss_max_seq") + 1
        head = authority_readback.get("head")
        before = authority_readback.get("head_before_phase_two")
        prepared_id = authority_readback.get("prepared_root_id")
        published_id = authority_readback.get("published_root_id")
        byte_identical = prepared_id == published_id
        require(
            isinstance(before, dict) and set(before) == {"sequence", "identifier"},
            "recovery-authority-before-invalid",
        )
        recorded_head = takeover.get("head_after_verb")
        chain_head = authority_readback.get("chain_head")
        status_head = authority_readback.get("status_head")
        require(
            isinstance(head, dict)
            and isinstance(chain_head, dict)
            and isinstance(recorded_head, dict),
            "durable-recovery-head-shape",
        )
        require(
            recorded_head.get("sequence")
            == chain_head.get("sequence")
            == head.get("sequence")
            == expected_seq,
            "durable-recovery-completion: head-sequence",
        )
        require(
            recorded_head.get("identifier")
            == chain_head.get("identifier")
            == head.get("identifier")
            == grain_id_binary(published_id),
            "durable-recovery-completion: head-identifier",
        )
        require(
            decoded_status == status_head,
            "recovery-status-artifact-invalid",
        )
        require(
            observe_status_lag(
                chain_head, status_head, "recovery-chain-status-mismatch"
            )
            == authority_readback.get("status_lag_seqs"),
            "recovery-status-lag-invalid",
        )
        require(
            before.get("sequence") == pair.get("pre_loss_max_seq"),
            "durable-recovery-completion: pre-loss-sequence",
        )
        branch = (
            "exact"
            if before.get("sequence") == selection["selection"]["parent_seq"]
            else "merge"
        )
        require(
            selection.get("expected_result")
            == "selection-report-without-local-state"
            and selection.get("store_absent_after") is True
            and selection.get("head_after_verb") is None
            and selection.get("authority_readback") is None
            and selection["ending"].get("exit_code") == 1
            and selection["ending"].get("completion_line_present") is False
            and takeover.get("expected_result")
            == "journal-finished-or-landed-selected-head"
            and takeover.get("store_absent_after") is False
            and authority_readback.get("writer_row_state") == "released"
            and prepared_id == selection["selection"]["root"]
            and re.fullmatch(r"blake3:[0-9a-f]{64}", str(published_id))
            and authority_readback.get("published_root_byte_identical")
            is byte_identical
            and authority_readback.get("implied_recovery_branch") == branch
            and authority_readback.get("exact_branch_byte_mismatch")
            is (branch == "exact" and not byte_identical)
            and isinstance(authority_readback.get("decoded_field_diff"), list)
            and bool(authority_readback.get("decoded_field_diff")) is (not byte_identical)
            and all(
                isinstance(name, str) and re.fullmatch(r"[a-z_]+[0-9]*", name)
                for name in authority_readback.get("decoded_field_diff", [])
            )
            and any(
                event.get("event") == "recover.journal_finished"
                or (
                    event.get("event") == "recover.landed"
                    and event.get("seq") == pair.get("pre_loss_max_seq") + 1
                )
                for event in takeover["ending"]["events_seen"]
            ),
            "durable-recovery-completion",
        )
        require(
            loss.get("final_max_seq") == pair.get("pre_loss_max_seq") + 1,
            "durable-recovery-head",
        )
        require(
            loss.get("final_head_id")
            == takeover.get("head_after_verb", {}).get("identifier")
            and loss.get("final_max_seq")
            == takeover.get("head_after_verb", {}).get("sequence"),
            "durable-recovery-takeover-head",
        )
    return len(expected_gap), expected_bytes


def validate_pivot_vm_row(row):
    require(
        row.get("venue") != "vm" or row.get("deciding") is row.get("pivot_append") is False,
        "pivot-vm-admissibility",
    )


def validate_pivot_diagnostic(row):
    """Validate the closed-loop ceiling publication as diagnostic evidence only."""
    validate_row_envelope(row)
    validate_command_provenance(row)
    validate_pivot_vm_row(row)
    require(row.get("pivot_role") == "diagnostic", "pivot-diagnostic-role")
    outcome = row.get("diagnostic_outcome")
    require(outcome in ("complete", "stalled"), "pivot-diagnostic-outcome")
    stalled = outcome == "stalled"
    if stalled:
        require(
            type(row.get("sample_count")) is int and row["sample_count"] < 368,
            "pivot-diagnostic-stalled-population",
        )
    require(
        row.get("pivot_input") is False,
        "closed-loop-pivot-input",
    )
    require(
        row.get("load_model") == "closed-loop-serial"
        and row.get("diagnostic_label") == PIVOT_DIAGNOSTIC_LABEL,
        "pivot-diagnostic-label",
    )
    require(
        row.get("profile") == "published"
        and row.get("intent_occupancy") == "ceiling"
        and type(row.get("pivot_warmup_count")) is int
        and 0 <= row.get("pivot_warmup_count") <= PIVOT_WARMUP_COUNT
        and type(row.get("pivot_warmup_elapsed_ns")) is int
        and row["pivot_warmup_elapsed_ns"] >= 0
        and row.get("stream_count") == 1
        and row.get("stream_sample_counts") == [row.get("sample_count")]
        and type(row.get("sample_count")) is int
        and 0 <= row.get("sample_count") <= 368
        and (
            stalled
            or row.get("pivot_warmup_count") == PIVOT_WARMUP_COUNT
            and row["pivot_warmup_elapsed_ns"] > 0
            and row.get("sample_count") == 368
        ),
        "pivot-diagnostic-shape",
    )
    require(
        row.get("row_holders") == 16
        and row.get("zero_row_principals") == 16_368
        and row.get("historical_principals") == 16_384
        and row.get("live_roots") == 256
        and row.get("released_rows") == 768
        and row.get("root_label") == "707-B"
        and row.get("root_bytes") == 707
        and row.get("root_size_distribution") == {"707": 256},
        "pivot-ceiling-root",
    )
    require(
        isinstance(row.get("medium"), str)
        and row["medium"].startswith("AmazonS3(")
        and (
            stalled
            and row.get("authority_log_wait_p99_ns") is None
            or type(row.get("authority_log_wait_p99_ns")) is int
            and row.get("authority_log_wait_p99_ns") > 0
        ),
        "pivot-diagnostic-observation",
    )
    samples = durations_artifact(row, run_root(row), "pivot_durations")
    expected_depth = [row["pivot_warmup_count"], row["pivot_warmup_count"] + len(samples) - 1]
    require(row.get("diagnostic_depth_range") == (expected_depth if samples else None),
            "pivot-diagnostic-depth-range")
    if stalled:
        require(
            all(
                row.get(name) is None
                for name in (
                    "pivot_steady_first_half_median_ns",
                    "pivot_steady_second_half_median_ns",
                    "pivot_steady_first_half_p99_ns",
                    "pivot_steady_second_half_p99_ns",
                    "pivot_steady_exceedance_splits",
                )
            )
            and row.get("pivot_steady_state") == "stalled"
            and row.get("pivot_steady_pattern") == "other",
            "pivot-diagnostic-steadiness",
        )
    else:
        steady = steady_state(samples, STEADY_STATE_TOLERANCE)
        require(
            (
                row.get("pivot_steady_first_half_median_ns"),
                row.get("pivot_steady_second_half_median_ns"),
                row.get("pivot_steady_first_half_p99_ns"),
                row.get("pivot_steady_second_half_p99_ns"),
                row.get("pivot_steady_exceedance_splits"),
                row.get("pivot_steady_state"),
            )
            == (*steady[:5], steady[-1]),
            "steady-state-mismatch",
        )
        require(
            row.get("pivot_steady_pattern") == pivot_steady_pattern(steady),
            "pivot-diagnostic-steadiness",
        )
    require(
        row.get("pivot_steady_context") == "serial closed loop, one volume"
        and row.get("pivot_steady_confound") == CAUSE_NOT_ATTRIBUTED,
        "pivot-diagnostic-steadiness",
    )
    publish_bound = row.get("diagnostic_publish_bound_ns")
    censored = row.get("diagnostic_publish_censored_count")
    publish_stalls = row.get("diagnostic_publish_stalls")
    publish_stall_durations = row.get("diagnostic_publish_stall_ns")
    warmup_publish_stalls = row.get("diagnostic_warmup_publish_stalls")
    warmup_publish_stall_durations = row.get(
        "diagnostic_warmup_publish_stall_ns"
    )
    completion_bound = row.get("diagnostic_completion_bound_ns")
    completion_stalls = row.get("diagnostic_completion_stalls")
    completion_durations = row.get("diagnostic_completion_stall_ns")
    require(
        publish_bound == 100_000_000
        and type(censored) is int
        and 0 <= censored <= len(samples)
        and sum(value == publish_bound for value in samples) >= censored,
        "pivot-diagnostic-censor-count",
    )
    require(
        type(publish_stalls) is int
        and publish_stalls >= 0
        and publish_stalls <= (1 if stalled else censored)
        and isinstance(publish_stall_durations, list)
        and len(publish_stall_durations) == publish_stalls
        and all(
            type(value) is int
            and value >= publish_bound + row.get("diagnostic_completion_bound_ns", 0)
            for value in publish_stall_durations
        ),
        "pivot-diagnostic-publish-stalls",
    )
    require(
        type(warmup_publish_stalls) is int
        and 0 <= warmup_publish_stalls <= 1
        and isinstance(warmup_publish_stall_durations, list)
        and len(warmup_publish_stall_durations) == warmup_publish_stalls
        and all(
            type(value) is int and value >= publish_bound + completion_bound
            for value in warmup_publish_stall_durations
        ),
        "pivot-diagnostic-warmup-publish-stalls",
    )
    completed = row.get("diagnostic_completed_count")
    stall_index = row.get("diagnostic_stall_index")
    stall_phase = row.get("diagnostic_stall_phase")
    if stalled:
        require(
            type(stall_index) is int
            and stall_index < PIVOT_WARMUP_COUNT + 368,
            "pivot-diagnostic-stall-index",
        )
    require(
        type(completed) is int
        and completed == row.get("pivot_warmup_count") + len(samples)
        and (
            not stalled
            and completed == PIVOT_WARMUP_COUNT + 368
            and stall_index is None
            and stall_phase is None
            and publish_stalls + warmup_publish_stalls == 0
            or stalled
            and type(stall_index) is int
            and stall_index == completed
            and stall_phase in ("warmup", "measured")
            and (stall_phase == "warmup")
            is (row.get("pivot_warmup_count") < PIVOT_WARMUP_COUNT)
            and publish_stalls + warmup_publish_stalls == 1
        ),
        "pivot-diagnostic-stall-state",
    )
    require(
        completion_bound == 2_000_000_000
        and type(completion_stalls) is int
        and completion_stalls >= 0
        and isinstance(completion_durations, list)
        and len(completion_durations) == completion_stalls
        and all(
            type(value) is int and value >= completion_bound
            for value in completion_durations
        )
        and row.get("diagnostic_completion_stall_issue") == "#832",
        "pivot-diagnostic-completion-stalls",
    )
    if stalled:
        require(
            row.get("same_occupancy_publish_p99_ns") is None
            and row.get("same_occupancy_publish_p99_interval_ns") is None
            and row.get("diagnostic_publish_p99_report") == "stalled",
            "pivot-diagnostic-stall-state",
        )
        return
    ordered = sorted(samples)
    expected_p99 = ordered[math.ceil(len(ordered) * 0.99) - 1]
    require(
        row.get("same_occupancy_publish_p99_ns") == expected_p99,
        "pivot-p99-artifact-mismatch",
    )
    require(
        row.get("same_occupancy_publish_p99_interval_ns")
        == list(quantile_interval(samples, 0.99, 0.95)),
        "pivot-interval-artifact-mismatch",
    )
    expected_report = (
        f"> {publish_bound}"
        if censored * 100 > len(samples)
        else str(expected_p99)
    )
    require(
        row.get("diagnostic_publish_p99_report") == expected_report,
        "pivot-diagnostic-censor-report",
    )


def validate_selected_denominator(denominator, selected_attempt):
    """Bind every selected denominator field to the same accepted attempt."""
    require(
        denominator.get("pivot_durations_artifact")
        == selected_attempt["sample_artifact"]
        and denominator.get("pivot_durations_artifact_sha256")
        == selected_attempt["sample_artifact_sha256"]
        and denominator.get("pivot_completion_artifact")
        == selected_attempt["completion_artifact"]
        and denominator.get("pivot_completion_artifact_sha256")
        == selected_attempt["completion_artifact_sha256"],
        "pivot-denominator-selected-artifacts",
    )
    require(
        denominator.get("sample_count") == selected_attempt["sample_count"]
        and denominator.get("achieved_rate") == selected_attempt["achieved_rate"]
        and denominator.get("offered_rate") == selected_attempt["rate"],
        "pivot-denominator-selected-load",
    )
    require(
        denominator.get("stream_sample_counts")
        == selected_attempt["stream_sample_counts"]
        and denominator.get("stream_count")
        == len(selected_attempt["stream_sample_counts"]),
        "pivot-denominator-selected-streams",
    )
    require(
        denominator.get("pivot_warmup_count") == selected_attempt["warmup_count"]
        and denominator.get("pivot_warmup_elapsed_ns")
        == selected_attempt["warmup_elapsed_ns"],
        "pivot-denominator-selected-warmup",
    )


def pivot_scope(numerator, selected_attempt):
    require(numerator.get("numerator_generation_range") == [2, 68],
            "pivot-numerator-generation-range")
    require(type(numerator.get("numerator_intent_log_bytes")) is int
            and numerator["numerator_intent_log_bytes"] > 0, "pivot-numerator-intent-log-length")
    denominator = (
        "no denominator qualified"
        if selected_attempt is None
        else "denominator measured on young volumes, pre-publish chain depth "
        f"≤ {selected_attempt['depth_bounds'][1]}"
    )
    low, high = numerator["numerator_generation_range"]
    return (
        f"{denominator}; numerator register generations {low}–{high}, "
        f"final intent log {numerator['numerator_intent_log_bytes']} bytes"
    )


def validate_pivot(rows):
    """Authoritatively validate the recorded pivot pair and numeric rule."""
    require(isinstance(rows, list) and len(rows) == 2, "pivot-pair-count")
    for row in rows:
        validate_row_envelope(row)
        require(
            isinstance(row.get("venue"), str) and row.get("venue") in VENUES,
            "pivot-venue-unrecorded",
        )
        require(isinstance(row.get("pivot_role"), str), "pivot-pair-roles")
    by_role = {row.get("pivot_role"): row for row in rows}
    require(set(by_role) == PIVOT_ROLES, "pivot-pair-roles")
    numerator = by_role["numerator"]
    denominator = by_role["denominator"]
    for row in (numerator, denominator):
        validate_command_provenance(row)
    branch = denominator.get("pivot_branch")
    verdict_branch = numerator.get("pivot_verdict_branch")
    numerator_unsteady = verdict_branch == "numerator-not-steady"
    require(
        verdict_branch in {"deciding-pair", "numerator-not-steady"}
        and denominator.get("pivot_verdict_branch") == verdict_branch,
        "pivot-verdict-branch",
    )
    attempts = denominator.get("denominator_attempts")
    require(
        branch in {"normal", "lower-bound", "terminal-inconclusive"}
        and isinstance(attempts, list)
        and attempts,
        "pivot-branch-invalid",
    )
    validate_denominator_attempts(attempts)
    for attempt in attempts:
        samples = durations_artifact(
            {
                "sample_count": attempt["sample_count"],
                "pivot_durations_artifact": attempt["sample_artifact"],
                "pivot_durations_artifact_sha256": attempt[
                    "sample_artifact_sha256"
                ],
            },
            run_root(denominator),
            "pivot_durations",
        )
        completion = durations_artifact(
            {
                "sample_count": attempt["completion_count"],
                "pivot_completion_artifact": attempt["completion_artifact"],
                "pivot_completion_artifact_sha256": attempt[
                    "completion_artifact_sha256"
                ],
            },
            run_root(denominator),
            "pivot_completion",
        )
        validate_denominator_cycles(attempt, samples, completion)
        if not attempt["guards_passed"]:
            continue
        steady = steady_state(samples, STEADY_STATE_TOLERANCE)
        require(
            (
                attempt["steady_first_half_median_ns"],
                attempt["steady_second_half_median_ns"],
                attempt["steady_first_half_p99_ns"],
                attempt["steady_second_half_p99_ns"],
                attempt["steady_exceedance_splits"],
                attempt["steady_state"],
            )
            == steady,
            "pivot-denominator-steadiness",
        )
    selected_attempt = None if branch == "terminal-inconclusive" else attempts[-1]
    selected_denominator_rate = None if selected_attempt is None else selected_attempt["rate"]
    expected_stalls = [
        {
            "rate": attempt["rate"],
            "bound_ns": attempt["cycle_stall_bound_ns"],
            "count": attempt["cycle_stall_count"],
            "durations_ns": attempt["cycle_stall_durations_ns"],
            "refusal_cycle_duration_ns": attempt["refusal_cycle_duration_ns"],
        }
        for attempt in attempts
    ]
    require(
        denominator.get("denominator_cycle_stalls") == expected_stalls
        and denominator.get("denominator_cycle_stall_issue") == "#832",
        "pivot-denominator-cycle-stalls",
    )
    rates = [attempt.get("rate") for attempt in attempts]
    outcomes = [attempt.get("outcome") for attempt in attempts]
    if branch == "normal":
        require(
            rates == [46.0]
            and outcomes == ["passed"]
            and denominator.get("denominator_label") == "offered-rate denominator",
            "pivot-normal-branch",
        )
    elif branch == "lower-bound":
        require(
            rates in ([46.0, 23.0], [46.0, 23.0, 11.5])
            and all(outcome != "passed" for outcome in outcomes[:-1])
            and outcomes[-1] == "passed"
            and denominator.get("denominator_label") == PIVOT_LOWER_BOUND_LABEL,
            "pivot-lower-bound-branch",
        )
    else:
        require(
            rates == [46.0, 23.0, 11.5]
            and all(outcome != "passed" for outcome in outcomes)
            and denominator.get("denominator_label") == PIVOT_TERMINAL_LABEL,
            "pivot-terminal-branch",
        )
    require(
        numerator.get("load_model") == denominator.get("load_model") == "open-loop",
        "closed-loop-pivot-input",
    )
    require(
        numerator.get("profile") == "durable-prepared"
        and numerator.get("intent_occupancy") == "ceiling"
        and type(numerator.get("register_post_p99_ns")) is int
        and numerator.get("register_post_p99_ns") > 0
        and denominator.get("profile") == "published"
        and denominator.get("intent_occupancy") == "floor"
        and (
            branch == "terminal-inconclusive"
            and denominator.get("publish_decision_p99_ns") is None
            or branch != "terminal-inconclusive"
            and denominator.get("publish_decision_p99_ns") > 0
        ),
        "pivot-pair-roles",
    )
    require(
        numerator.get("cell_kind") == ("refused" if numerator_unsteady else "steady")
        and denominator.get("cell_kind")
        == ("refused" if branch == "terminal-inconclusive" else "steady"),
        "pivot-pair-cell-kind",
    )
    require(
        (numerator.get("venue"), numerator.get("host"), numerator.get("revision"))
        == (denominator.get("venue"), denominator.get("host"), denominator.get("revision")),
        "pivot-pair-provenance",
    )
    expected_venue_kind = (
        "podman-vm" if numerator.get("venue") == "vm" else numerator.get("venue")
    )
    require(
        all(
            row.get("pivot_venue_kind") == expected_venue_kind
            and row.get("pivot_venue_note") == PIVOT_VM_DECISION_NOTE
            for row in (numerator, denominator)
        ),
        "pivot-venue-kind",
    )
    require(
        all(
            isinstance(row.get("medium"), str)
            and row["medium"].startswith("AmazonS3(")
            for row in (numerator, denominator)
        ),
        "pivot-venue-store-required",
    )
    for row in rows:
        validate_pivot_vm_row(row)
    vm = numerator.get("venue") == "vm"
    require(
        numerator.get("deciding") is (not numerator_unsteady and not vm),
        "pivot-numerator-admissibility"
        if numerator_unsteady
        else "pivot-numerator-not-deciding",
    )
    require(
        numerator.get("committed_transitions")
        == numerator.get("sample_count") + PIVOT_WARMUP_COUNT
        and denominator.get("committed_transitions") == 0,
        "pivot-transition-count",
    )
    scope = pivot_scope(numerator, selected_attempt)
    require(numerator.get("pivot_scope") == denominator.get("pivot_scope") == scope,
            "pivot-verdict-scope")
    require(
        numerator.get("pivot_warmup_count") == PIVOT_WARMUP_COUNT
        and type(numerator.get("pivot_warmup_elapsed_ns")) is int
        and numerator["pivot_warmup_elapsed_ns"] > 0
        and (
            branch == "terminal-inconclusive"
            and denominator.get("pivot_warmup_count") is None
            and denominator.get("pivot_warmup_elapsed_ns") is None
            or branch != "terminal-inconclusive"
            and denominator.get("pivot_warmup_count") == PIVOT_WARMUP_COUNT
            and type(denominator.get("pivot_warmup_elapsed_ns")) is int
            and denominator["pivot_warmup_elapsed_ns"] > 0
        ),
        "pivot-warmup-observation",
    )
    require(
        numerator.get("stream_count") == 16
        and isinstance(numerator.get("stream_sample_counts"), list)
        and len(numerator["stream_sample_counts"]) == 16
        and sum(numerator["stream_sample_counts"]) == numerator.get("sample_count")
        and (
            branch == "terminal-inconclusive"
            or denominator.get("stream_count")
            == denominator_stream_count(selected_denominator_rate)
            and isinstance(denominator.get("stream_sample_counts"), list)
            and len(denominator["stream_sample_counts"])
            == denominator["stream_count"]
            and sum(denominator["stream_sample_counts"])
            == denominator.get("sample_count")
        ),
        "pivot-stream-counts",
    )
    require(
        all(
            row.get("principal_submission_limit") == 1_000_000
            and row.get("principal_in_flight_limit") == 4
            and type(row.get("per_stream_offered_rate")) is float
            and math.isclose(
                row["per_stream_offered_rate"],
                row["offered_rate"] / row["stream_count"],
            )
            and row["per_stream_offered_rate"]
            <= row["principal_submission_limit"]
            for row in (
                (numerator,)
                if branch == "terminal-inconclusive"
                else (numerator, denominator)
            )
        ),
        "pivot-principal-limit",
    )
    if branch != "terminal-inconclusive":
        require(
            all(
                type(denominator.get(f"publish_pilot_{name}")) is int
                for name in (
                    "sample_count",
                    "p50_ns",
                    "p99_ns",
                    "max_ns",
                    "stream_count",
                )
            ),
            "pivot-pilot-types",
        )
        require(
            denominator.get("publish_pilot_sample_count", 0) >= 32,
            "pivot-pilot-population",
        )
        require(
            0 < denominator.get("publish_pilot_p50_ns", 0)
            <= denominator.get("publish_pilot_p99_ns", 0)
            <= denominator.get("publish_pilot_max_ns", 0),
            "pivot-pilot-order",
        )
        require(
            denominator.get("publish_pilot_stream_count")
            == denominator_stream_count(selected_denominator_rate),
            "pivot-pilot-stream-count",
        )
    require(
        numerator.get("pivot_stream_plan") == PIVOT_STREAM_PLAN
        and denominator.get("pivot_stream_plan") == PIVOT_STREAM_PLAN,
        "pivot-stream-plan",
    )
    require(
        numerator.get("root_label") == "707-B"
        and numerator.get("root_bytes") == 707
        and numerator.get("root_size_distribution") == {"707": 256},
        "pivot-ceiling-root",
    )
    require(
        denominator.get("root_label") == "measured length",
        "pivot-floor-root-label",
    )
    require(
        (
            numerator.get("row_holders"),
            numerator.get("zero_row_principals"),
            numerator.get("retired_principals"),
            numerator.get("historical_principals"),
            numerator.get("live_roots"),
            numerator.get("released_rows"),
        )
        == (16, 16_368, 0, 16_384, 256, 768)
        and (
            denominator.get("row_holders"),
            denominator.get("zero_row_principals"),
            denominator.get("retired_principals"),
            denominator.get("historical_principals"),
            denominator.get("live_roots"),
            denominator.get("released_rows"),
        )
        == (1, 0, 0, 1, 16, 48),
        "pivot-pair-shape",
    )
    require(
        numerator.get("offered_rate") == 46
        and (
            numerator.get("medium"),
            numerator.get("filesystem"),
            numerator.get("wrapper_layer"),
        )
        == (
            denominator.get("medium"),
            denominator.get("filesystem"),
            denominator.get("wrapper_layer"),
        )
        and (
            branch != "normal"
            or numerator.get("offered_rate") == denominator.get("offered_rate")
        )
        and (
            branch == "terminal-inconclusive"
            or denominator.get("offered_rate") == attempts[-1]["rate"]
        ),
        "pivot-pair-load-medium-wrapper",
    )
    require(
        numerator.get("achieved_rate") >= numerator.get("offered_rate") * 0.95
        and (
            branch == "terminal-inconclusive"
            or denominator.get("achieved_rate")
            >= denominator.get("offered_rate") * 0.95
        ),
        "pivot-achieved-rate-shortfall",
    )
    numerator_interval = numerator.get("register_post_p99_interval_ns")
    denominator_interval = denominator.get("publish_decision_p99_interval_ns")
    require(
        numerator_interval is not None
        and (
            branch == "terminal-inconclusive" and denominator_interval is None
            or branch != "terminal-inconclusive" and denominator_interval is not None
        ),
        "pivot-interval-missing",
    )
    expected = []
    compared = [(numerator, numerator.get("register_post_p99_ns"))]
    if branch != "terminal-inconclusive":
        compared.append((denominator, denominator.get("publish_decision_p99_ns")))
    for row, p99 in compared:
        samples = durations_artifact(row, run_root(row), "pivot_durations")
        steady = steady_state(samples, STEADY_STATE_TOLERANCE)
        require(
            (
                row.get("pivot_steady_first_half_median_ns"),
                row.get("pivot_steady_second_half_median_ns"),
                row.get("pivot_steady_first_half_p99_ns"),
                row.get("pivot_steady_second_half_p99_ns"),
                row.get("pivot_steady_exceedance_splits"),
                row.get("pivot_steady_state"),
            )
            == (*steady[:5], steady[-1]),
            "steady-state-mismatch",
        )
        require(
            row.get("pivot_steady_pattern") == pivot_steady_pattern(steady),
            "pivot-steady-pattern",
        )
        if row is numerator and numerator_unsteady:
            require(steady[-1] == "not steady", "pivot-numerator-steadiness")
            require(
                row.get("pivot_steady_exceedance_histograms")
                == pivot_exceedance_histograms(samples, steady[4]),
                "pivot-numerator-exceedance-histogram",
            )
        else:
            require(steady[-1] == "steady", "pivot-not-steady")
            require(
                row.get("pivot_steady_exceedance_histograms") is None,
                "pivot-exceedance-histogram-unexpected",
            )
        ordered = sorted(samples)
        expected_p99 = ordered[math.ceil(len(ordered) * 0.99) - 1]
        expected_interval = list(quantile_interval(samples, 0.99, 0.95))
        expected.append((expected_p99, expected_interval))
        require(
            p99 == expected_p99,
            "pivot-p99-artifact-mismatch",
        )
    if branch == "terminal-inconclusive":
        require(
            denominator.get("sample_count") is None
            and denominator.get("pivot_durations_artifact") is None
            and denominator.get("pivot_durations_artifact_sha256") is None
            and denominator.get("pivot_completion_artifact") is None
            and denominator.get("pivot_completion_artifact_sha256") is None,
            "pivot-terminal-row-artifacts",
        )
        require(
            denominator.get("offered_rate") is None
            and denominator.get("achieved_rate") is None
            and denominator.get("per_stream_offered_rate") is None,
            "pivot-terminal-row-load",
        )
    else:
        durations_artifact(
            denominator, run_root(denominator), "pivot_completion"
        )
        # durations_artifact binds the selected completion file to sample_count.
        validate_selected_denominator(denominator, selected_attempt)
        require(
            denominator.get("publish_pilot_sample_count")
            == selected_attempt["pilot"]["sample_count"]
            and denominator.get("publish_pilot_p50_ns")
            == selected_attempt["pilot"]["p50_ns"]
            and denominator.get("publish_pilot_p99_ns")
            == selected_attempt["pilot"]["p99_ns"]
            and denominator.get("publish_pilot_max_ns")
            == selected_attempt["pilot"]["max_ns"]
            and denominator.get("publish_pilot_stream_count")
            == selected_attempt["pilot"]["stream_count"],
            "pivot-denominator-selected-pilot",
        )
    require(
        numerator_interval == expected[0][1]
        and (
            branch == "terminal-inconclusive"
            or denominator_interval == expected[1][1]
        ),
        "pivot-interval-artifact-mismatch",
    )
    if numerator_unsteady:
        expected_verdict = PIVOT_NUMERATOR_UNSTEADY
    elif branch == "normal":
        expected_verdict = pivot_verdict(numerator_interval, denominator_interval)
    elif branch == "lower-bound":
        expected_verdict = lower_bound_pivot_verdict(
            numerator_interval, denominator_interval
        )
    else:
        expected_verdict = "inconclusive"
    require(
        numerator.get("same_occupancy_publish_diagnostic")
        == denominator.get("same_occupancy_publish_diagnostic")
        == PIVOT_DIAGNOSTIC_LABEL
        and numerator.get("authority_log_wait_diagnostic")
        == denominator.get("authority_log_wait_diagnostic")
        == "diagnostic only; LogGate wait is not wrapper publish duration"
        and numerator.get("same_occupancy_publish_p99_interval_ns")
        == denominator.get("same_occupancy_publish_p99_interval_ns"),
        "pivot-diagnostic-label",
    )
    require(
        numerator.get("pivot_verdict")
        == denominator.get("pivot_verdict")
        == expected_verdict
        and numerator.get("pivot_append")
        == denominator.get("pivot_append")
        == (expected_verdict == "pivot" and not vm),
        "pivot-result-mismatch",
    )


def cross_volume_document(path):
    path = Path(path).resolve()
    try:
        data = path.read_bytes()
    except OSError as error:
        raise Refused("cross-volume-artifact-unreadable") from error
    lines = data.splitlines()
    columns = (b"baseline_start_ns\tbaseline_end_ns\tcommit_start_ns\tcommit_end_ns\trequest_start_ns\t"
               b"request_queued_ns\trequest_end_ns\tcommit_ns\twait_ns\tauthority_log_wait_ns")
    rows = [line.split(b"\t") for line in lines[1:]]
    require(lines[:1] == [columns] and all(
        len(row) == 10 and all(re.fullmatch(rb"[0-9]{1,19}", value) and int(value) <= MAX_INTEGER
                              for value in row) for row in rows
    ), "cross-volume-sample-fields")
    require(len(rows) >= 100, "cross-volume-sample-floor")
    waits, gate_waits = [], []
    previous_end = 0
    for row in rows:
        bs, be, cs, ce, rs, queued, re_ns, duration, wait, gate = map(int, row)
        require(duration > 0 and duration == ce - cs, "cross-volume-commit-duration")
        require(cs < rs <= queued < ce <= re_ns, "cross-volume-overlap")
        require(previous_end <= bs < be <= cs, "cross-volume-baseline")
        require(wait == re_ns - rs - (be - bs), "cross-volume-wait")
        previous_end = re_ns
        waits.append(wait)
        gate_waits.append(gate)
    return dict(
        event="cross-volume", sample_count=len(rows), caveat=CROSS_VOLUME_NOTE,
        cross_volume_blocked_ns=sorted(waits)[math.ceil(len(rows) * 0.99) - 1],
        cross_volume_blocked_p50_ns=sorted(waits)[math.ceil(len(rows) * 0.50) - 1],
        authority_log_wait_p99_ns=sorted(gate_waits)[math.ceil(len(rows) * 0.99) - 1],
        cross_volume_samples_artifact=str(path),
        cross_volume_samples_artifact_sha256=hashlib.sha256(data).hexdigest(),
    )


def validate_cross_volume(document):
    path = document.get("cross_volume_samples_artifact")
    require(isinstance(path, str) and bool(path) and "\0" not in path, "cross-volume-artifact")
    expected = cross_volume_document(path)
    digest_field = "cross_volume_samples_artifact_sha256"
    require(document.get(digest_field) == expected[digest_field], "cross-volume-artifact-hash")
    require(document == expected and all(
        type(document[key]) is int for key, value in expected.items() if type(value) is int
    ), "cross-volume-summary")
    return 1


def mounted_server_metrics(row):
    """Rebuild the mounted window summary from the sealed server export."""
    path = Path(row["run_root"]) / "server-observers.jsonl"
    try:
        data = path.read_bytes()
        rows = [json.loads(line, object_pairs_hook=unique_object) for line in data.splitlines()]
    except (OSError, ValueError) as error:
        raise Refused("server-observers-unreadable") from error
    require(hashlib.sha256(data).hexdigest() == row.get("server_observers_sha256"),
            "server-observers-hash-mismatch")
    require(all(isinstance(item, dict) and item.get("schema") == "granary.q3.server.v2"
                and item.get("pass") == "serve" for item in rows), "server-observers-schema")
    profile = row["profile"]
    duration = [item for item in rows if item.get("kind") == "durability"]
    writes = ("intent_logical_commits", "intent_file_barriers", "intent_dir_barriers",
              "decision_log_appends", "decision_file_barriers", "decision_dir_barriers")
    require(len(duration) == 1 and type(duration[0].get("sample_loss")) is int
            and duration[0]["sample_loss"] == 0
            and all(type(duration[0].get(key)) is int and 0 <= duration[0][key] <= MAX_INTEGER
                    for key in writes)
            and duration[0][writes[0 if profile == "durable-prepared" else 3]] > 0,
            "verdict-missing-control-writes")
    population = row["sample_count"] + row["warmup_count"] + 3
    landed = [item for item in rows if item.get("kind") == "landed_window"]
    chain = ("before_max_seq", "after_max_seq", "chain_growth", "final_depth", "elapsed_ns")
    require(len(landed) == 1 and type(landed[0].get("sample_loss")) is int
            and landed[0]["sample_loss"] == 0
            and landed[0].get("intervening_roots_readable") is True
            and all(type(landed[0].get(key)) is int and 0 <= landed[0][key] <= MAX_INTEGER
                    for key in chain)
            and landed[0]["elapsed_ns"] > 0
            and landed[0]["after_max_seq"] - landed[0]["before_max_seq"] == landed[0]["chain_growth"]
            and landed[0]["after_max_seq"] == landed[0]["final_depth"]
            and (profile != "published" or landed[0]["chain_growth"] > 0),
            "verdict-missing-chain-growth")
    metrics = dict(
        control_writes_per_fsync={key: duration[0][key] / population for key in writes},
        chain={key: landed[0][key] for key in chain},
    )
    metrics["chain"]["roots_per_second"] = landed[0]["chain_growth"] * 1e9 / landed[0]["elapsed_ns"]
    prefix = f"q3-mark-{profile}-rtt-{row['configured_rtt_ms']}"
    attempts = [item for item in rows if item.get("kind") == "http_attempt"]
    sequences = [item.get("arrival_seq") for item in attempts]
    require(all(type(sequence) is int and sequence > 0 for sequence in sequences)
            and len(sequences) == len(set(sequences)), "server-observers-markers")
    bounds = [[item["arrival_seq"] for item in attempts if item.get("request_id") == prefix + suffix]
              for suffix in ("-start", "-end")]
    require(len(bounds[0]) == len(bounds[1]) == 1 and bounds[0][0] < bounds[1][0],
            "server-observers-markers")
    window = [item for item in attempts if bounds[0][0] < item["arrival_seq"] < bounds[1][0]]
    routes = Counter(f"{item.get('method')} {item.get('route')}" for item in window)
    require(routes and routes == row.get("route_attempts"), "verdict-missing-round-trips")
    if profile == "published":
        successes = [item for item in window if item.get("method") == "POST"
                     and item.get("route") == "/volume/:volume/publish" and item.get("outcome") == "success"]
        require(all(isinstance(item.get("request_id"), str) and item["request_id"]
                    and type(item.get("duration_ns")) is int and 0 < item["duration_ns"] <= MAX_INTEGER
                    for item in successes)
                and len({item["request_id"] for item in successes}) == row["logical_publishes"],
                "verdict-missing-cas-latency")
        first_success = {}
        for item in sorted(successes, key=lambda item: item["arrival_seq"]):
            first_success.setdefault(item["request_id"], item["duration_ns"])
        cas = sorted(first_success.values())
        metrics["cas_p99_ns"] = cas[math.ceil(len(cas) * 0.99) - 1]
    return metrics


VERDICT_COMPONENTS = {
    "recovery_durable_prepared": "recovery-pair", "recovery_published": "recovery-pair",
    "pivot": "pivot", "rtt_durable_prepared": None, "rtt_published": None,
    "cross_volume": "cross-volume",
}
VERDICT_POSITIONS = {"4": ("supports", "refutes", "open"), "5": ("moot", "live"), "6": ("open",)}

def verdict_evidence(references, decisions):
    """Read, authenticate, and validate the component bytes used by a verdict."""
    documents = {}
    for role, event in VERDICT_COMPONENTS.items():
        family = role.split("_")[0].replace("cross", "cross-volume")
        reference = references.get(role)
        require(isinstance(reference, dict) and set(reference) == {"path", "sha256"}
                and isinstance(reference["path"], str) and Path(reference["path"]).is_absolute(),
                f"verdict-missing-{family}" if family != "recovery" else "verdict-missing-recovery-gap")
        try:
            data = Path(reference["path"]).read_bytes()
            document = json.loads(data, object_pairs_hook=unique_object)
        except (OSError, ValueError) as error:
            raise Refused(f"verdict-component-unreadable: {role}") from error
        require(hashlib.sha256(data).hexdigest() == reference["sha256"],
                f"verdict-component-hash: {role}")
        require(isinstance(document, dict) and document.get("event") == event,
                f"verdict-component-type: {role}")
        try:
            validate(document)
        except Refused as error:
            for field_name, family in (("route_attempts", "round-trips"), ("m15_delta", "rechunk-fallback")):
                if str(error) in (f"schema-missing: {field_name}", f"schema-invalid: {field_name}"):
                    raise Refused(f"verdict-missing-{family}") from error
            raise
        documents[role] = document

    metrics, venues, calibrations, rtt_scope = {}, [], [], {}
    for profile, suffix in (("durable-prepared", "durable_prepared"), ("published", "published")):
        rtt = documents[f"rtt_{suffix}"]
        rows = [row for row in rtt["samples"] if row.get("rtt_group") == profile]
        calibration = [item for item in (rtt.get("calibrations") or []) if item["profile"] == profile]
        require(rows and calibration, "verdict-missing-rtt")
        require(all("server_metrics" in row for row in rows), "verdict-missing-control-writes")
        pair = documents[f"recovery_{suffix}"]["pair"]
        require(pair["profile"] == profile, "verdict-missing-recovery-gap")
        if profile == "durable-prepared" and decisions["5"]["position"] == "moot":
            # A validated pair has completed both arms and reconciled its loss ledger.
            require(all(type(pair[key]) is int and 0 <= pair[key] <= MAX_INTEGER
                        for key in ("gap_operations", "gap_bytes")), "verdict-recovery-unbounded")
        venues.extend(row["venue"] for row in rows)
        calibrations.append(calibration[0]["outcome"])
        rtt_scope[profile] = calibration[0]["scope"]
        metrics[profile] = dict(
            recovery_gap={key: pair[key] for key in ("gap_operations", "gap_bytes", "gap_label")},
            cells=[dict(rtt_ms=row["observed_rtt_ms"], fsync_p99_ns=row["fsync_p99_ns"],
                        round_trips_per_fsync=sum(row["route_attempts"].values()) /
                        (row["sample_count"] + row["warmup_count"] + 3),
                        rechunk_fallback_count=row["m15_delta"], **row["server_metrics"]) for row in rows],
        )
        metrics[profile]["recovery_gap"].update(
            elapsed_ns=pair["loss"]["elapsed_ns"], operator_verbs=pair["planned_operator_verbs"])
    pivot = documents["pivot"]
    numerator = next(row for row in pivot["rows"] if row["pivot_role"] == "numerator")
    if decisions["4"]["position"] != "open":
        require("vm" not in venues + [row["venue"] for row in pivot["rows"]], "verdict-vm")
        require(numerator["deciding"] and pivot["verdict"] in ("pivot", "no pivot"),
                "verdict-pivot-inconclusive")
        require("refused" not in calibrations, "verdict-rtt-calibration-refused")
    return dict(metrics=metrics, pivot_scope=numerator["pivot_scope"], rtt_scope=rtt_scope,
                cross_volume_property=documents["cross_volume"]["caveat"])


def validate_verdict_decisions(decisions):
    require(isinstance(decisions, dict) and set(decisions) == set(VERDICT_POSITIONS),
            "verdict-decisions")
    for decision, positions in VERDICT_POSITIONS.items():
        judgment = decisions[decision]
        require(isinstance(judgment, dict) and set(judgment) == {"position", "rationale"}
                and judgment["position"] in positions and isinstance(judgment["rationale"], str)
                and bool(judgment["rationale"].strip()), f"verdict-decision-{decision}")


def validate_verdict(document):
    require(set(document) == {"event", "sets_no_default", "decisions", "components",
                              "metrics", "pivot_scope", "rtt_scope", "cross_volume_property"}
            and document.get("sets_no_default") is True, "verdict-no-default")
    decisions, references = document["decisions"], document["components"]
    validate_verdict_decisions(decisions)
    require(isinstance(references, dict) and not set(references) - VERDICT_COMPONENTS.keys(),
            "verdict-components")
    for key, value in verdict_evidence(references, decisions).items():
        require(document[key] == value, f"verdict-{key}-mismatch")
    return 1


def validate_rtt_band_fields(profile, values):
    head = values.get("register_chain_head_seq")
    require(
        head is None if profile == "published" else type(head) is int and 0 < head <= MAX_INTEGER,
        "schema-invalid: register_chain_head_seq",
    )
    attempts = values.get("rtt_band_attempts")
    require(
        attempts is None
        or isinstance(attempts, list) and len(attempts) == 10
        and all(type(count) is int and 0 <= count <= MAX_INTEGER for count in attempts),
        "schema-invalid: rtt_band_attempts",
    )


def validate(document):
    """Validate a measurement document and return its nonzero row count."""
    require(isinstance(document, dict), "schema-document-not-object")
    if document.get("event") == "q3-verdict":
        return validate_verdict(document)
    if document.get("event") == "cross-volume":
        return validate_cross_volume(document)
    if document.get("event") == "pivot":
        require(
            set(document)
            == {
                "event",
                "verdict",
                "rows",
                "diagnostic",
                "commands",
                "child_bound_seconds",
                "child_elapsed_seconds",
                "progress_artifacts",
            },
            "schema-unknown: pivot",
        )
        require(isinstance(document.get("rows"), list), "pivot-document-rows-invalid")
        require(
            isinstance(document.get("diagnostic"), dict),
            "pivot-document-diagnostic-invalid",
        )
        validate_pivot(document.get("rows"))
        validate_pivot_diagnostic(document.get("diagnostic"))
        rows = document["rows"]
        diagnostic = document["diagnostic"]
        require(
            document.get("verdict") == rows[0].get("pivot_verdict")
            == rows[1].get("pivot_verdict"),
            "pivot-document-verdict-invalid",
        )
        roles = set(PIVOT_RUNS)
        commands = document.get("commands")
        bounds = document.get("child_bound_seconds")
        elapsed = document.get("child_elapsed_seconds")
        require(
            isinstance(commands, dict)
            and set(commands) == roles
            and commands["numerator"] == rows[0].get("command")
            and commands["denominator"] == rows[1].get("command")
            and commands["diagnostic"] == diagnostic.get("command")
            and all(isinstance(value, list) for value in commands.values()),
            "pivot-document-commands-invalid",
        )
        require(
            isinstance(bounds, dict)
            and set(bounds) == roles
            and all(
                type(bounds[role]) is int
                and bounds[role] == pivot_child_bound_seconds(role)
                for role in roles
            )
            and isinstance(elapsed, dict)
            and set(elapsed) == roles
            and all(
                type(elapsed[role]) in (int, float)
                and math.isfinite(elapsed[role])
                and 0 <= elapsed[role] <= bounds[role]
                for role in roles
            ),
            "pivot-document-child-timing-invalid",
        )
        progress = document.get("progress_artifacts")
        require(
            isinstance(progress, dict)
            and set(progress) == roles
            and all(
                isinstance(record, dict)
                and set(record)
                == {"outcome", "progress_file", "progress_sha256", "attempt_progress"}
                and isinstance(record["outcome"], str)
                and record["outcome"] in {"passed", "failed", "timeout"}
                and isinstance(record["progress_file"], str)
                and (
                    record["progress_sha256"] is None
                    or isinstance(record["progress_sha256"], str)
                    and re.fullmatch(r"[0-9a-f]{64}", record["progress_sha256"])
                )
                and isinstance(record["attempt_progress"], list)
                and all(
                    isinstance(attempt, dict)
                    and set(attempt) == {"path", "sha256"}
                    and isinstance(attempt["path"], str)
                    and isinstance(attempt["sha256"], str)
                    and re.fullmatch(r"[0-9a-f]{64}", attempt["sha256"])
                    for attempt in record["attempt_progress"]
                )
                for record in progress.values()
            ),
            "pivot-document-progress-invalid",
        )
        require(
            (
                rows[0].get("host"),
                rows[0].get("revision"),
                rows[0].get("venue"),
                rows[0].get("hardware"),
            )
            == (
                diagnostic.get("host"),
                diagnostic.get("revision"),
                diagnostic.get("venue"),
                diagnostic.get("hardware"),
            ),
            "pivot-document-provenance-invalid",
        )
        return len(document["rows"]) + 1
    if document.get("event") == "recovery-pair":
        require(
            set(document) == {"event", "pair", "artifact_root"},
            "schema-unknown: recovery-pair",
        )
        require(isinstance(document.get("pair"), dict), "recovery-pair-type-invalid")
        require(
            isinstance(document.get("artifact_root"), str)
            and bool(document.get("artifact_root")),
            "recovery-artifact-root-invalid",
        )
        validate_recovery_pair(document.get("pair"), document.get("artifact_root"))
        return 1
    if document.get("event") == "measurement":
        raise Refused("rtt-standalone-row")
    if document.get("event") == "calibration":
        raise Refused("rtt-standalone-calibration")
    require(
        set(document) in ({"samples"}, {"samples", "calibrations"}),
        "schema-unknown: document",
    )
    samples = field(document, "samples")
    require(isinstance(samples, list) and samples, "zero-cases")
    groups = {}
    pivot_groups = {}
    for row in samples:
        validate_row(row)
        if (
            row.get("event") == "measurement" and row.get("rtt_group") is not None
            or "register_chain_head_seq" in row or "rtt_band_attempts" in row
        ):
            validate_rtt_band_fields(row["profile"], row)
        if "server_metrics" in row or "server_observers_sha256" in row:
            require(row.get("server_metrics") == mounted_server_metrics(row),
                    "server-metrics-mismatch")
        if row.get("rtt_group") is not None:
            groups.setdefault(row.get("rtt_group"), []).append(row)
        if row.get("pivot_group") is not None:
            pivot_groups.setdefault(row.get("pivot_group"), []).append(row)
    calibrations = document.get("calibrations")
    if calibrations is not None:
        require(
            isinstance(calibrations, list)
            and all(
                isinstance(record, dict)
                and isinstance(record.get("profile"), str)
                and isinstance(record.get("outcome"), str)
                for record in calibrations
            ),
            "rtt-calibration-records-invalid",
        )
    for group, rows in groups.items():
        require(
            not all(row.get("network_path") == "loopback" for row in rows),
            "rtt-loopback-only",
        )
        require(
            len(
                {
                    row.get("configured_rtt_ms")
                    for row in rows
                    if row.get("configured_rtt_ms", 0) > 0
                }
            )
            >= 2,
            "rtt-group-needs-two-nonzero",
        )
        validate_observed_rtts(rows)
        require(
            len(
                {
                    (row.get("calibration_outcome"), row.get("calibration_reason"))
                    for row in rows
                }
            )
            == 1,
            "rtt-calibration-outcome-mismatch",
        )
        if calibrations is not None or any(
            row.get("event") == "measurement" for row in rows
        ):
            require(calibrations is not None, "rtt-calibration-record-missing")
            cells = [calibration_cell_from_row(row) for row in rows]
            expected = rtt_calibration_record(cells)
            matches = [record for record in calibrations if isinstance(record, dict) and record.get("profile") == group]
            require(len(matches) == 1 and matches[0] == expected, "rtt-calibration-record-mismatch")
            require(
                all(
                    (row.get("calibration_outcome"), row.get("calibration_reason"))
                    == (expected["outcome"], expected["reason"])
                    for row in rows
                ),
                "rtt-calibration-outcome-mismatch",
            )
    if calibrations is not None:
        require(
            len(calibrations) == len(groups)
            and sorted(record["profile"] for record in calibrations)
            == sorted(groups),
            "rtt-calibration-records-invalid",
        )
    for rows in pivot_groups.values():
        validate_pivot(rows)
    return len(samples)


def validate_smoke(
    server_rows, client_rows, cell, planned_fsyncs, profile="durable-prepared"
):
    """Validate one marker-bounded loopback correlation smoke row."""
    require(isinstance(cell, str) and cell, "smoke-cell-invalid")
    require(isinstance(server_rows, list), "server-attempts-invalid")
    require(isinstance(client_rows, list), "client-log-invalid")
    require(profile in ("durable-prepared", "published"), "measurement-profile-invalid")
    require(
        type(planned_fsyncs) is int and planned_fsyncs > 0,
        "planned-fsync-population-invalid",
    )
    attempts = [
        row
        for row in server_rows
        if isinstance(row, dict) and row.get("kind") == "http_attempt"
    ]
    require(attempts, "zero-server-attempts")
    sequences = []
    for row in attempts:
        require(row.get("schema") == "granary.q3.server.v2", "server-schema-invalid")
        sequence = row.get("arrival_seq")
        require(
            type(sequence) is int and 0 < sequence <= MAX_INTEGER,
            "server-arrival-seq-invalid",
        )
        sequences.append(sequence)
    require(len(sequences) == len(set(sequences)), "server-arrival-seq-duplicate")

    start_id = f"q3-mark-{cell}-start"
    end_id = f"q3-mark-{cell}-end"
    start = [row for row in attempts if row.get("request_id") == start_id]
    end = [row for row in attempts if row.get("request_id") == end_id]
    require(len(start) == len(end) == 1, "cell-markers-invalid")
    first, last = start[0]["arrival_seq"], end[0]["arrival_seq"]
    require(first < last, "cell-marker-order-invalid")
    require(
        not any(
            first < row["arrival_seq"] < last and row.get("request_id") is None
            for row in attempts
        ),
        "id-less-attempt-between-markers",
    )

    server_ids = {
        row.get("request_id")
        for row in attempts
        if row.get("request_id") is not None
        and row.get("request_id") not in (start_id, end_id)
    }
    require(server_ids, "zero-server-ids")
    client_ids = set()
    operation_kinds = {}
    lifecycles = {}
    for row in client_rows:
        if not isinstance(row, dict):
            continue
        spans = row.get("spans", [])
        require(isinstance(spans, list), "client-operation-spans-invalid")
        operation_spans = [
            span
            for span in spans
            if isinstance(span, dict) and span.get("name") == "op"
        ]
        if not operation_spans:
            continue
        span = operation_spans[-1]
        operation_id, operation_kind = span.get("op"), span.get("kind")
        require(
            isinstance(operation_id, str) and isinstance(operation_kind, str),
            "client-operation-span-invalid",
        )
        prior = operation_kinds.setdefault(operation_id, operation_kind)
        require(prior == operation_kind, "client-operation-kind-ambiguous")
        client_ids.add(operation_id)
        event = row.get("event")
        if event in ("op.begin", "op.end") and row.get("kind") == operation_kind:
            lifecycle = lifecycles.setdefault(operation_id, {"begin": 0, "ends": []})
            if event == "op.begin":
                lifecycle["begin"] += 1
            else:
                lifecycle["ends"].append(row.get("outcome"))
    require(server_ids <= client_ids, "server-id-absent-from-client-log")
    fsync_ids = {
        operation_id
        for operation_id, operation_kind in operation_kinds.items()
        if operation_kind == "fsync"
    }
    require(
        len(fsync_ids) == planned_fsyncs,
        "fsync-lifecycle-population-mismatch",
    )
    # A cell's operations are its fsyncs and any fsync or commit operation with
    # a request inside the markers. Teardown starts its own operations after the
    # end marker; only a delayed request from a cell operation refuses.
    cell_ids = {
        row.get("request_id")
        for row in attempts
        if first < row["arrival_seq"] < last and row.get("request_id") is not None
    }
    cell_operation_ids = fsync_ids | {
        operation_id
        for operation_id, operation_kind in operation_kinds.items()
        if operation_kind in ("fsync", "commit") and operation_id in cell_ids
    }
    require(
        not any(
            row["arrival_seq"] > last
            and row.get("request_id") in cell_operation_ids
            for row in attempts
        ),
        "attempt-after-end-marker",
    )
    register_ids = {
        row.get("request_id")
        for row in attempts
        if first < row["arrival_seq"] < last
        and row.get("method") == "POST"
        and row.get("route") == "/volume/:volume/intent"
    }
    for operation_id in fsync_ids:
        lifecycle = lifecycles.get(operation_id, {"begin": 0, "ends": []})
        require(
            lifecycle == {"begin": 1, "ends": ["ok"]},
            "fsync-lifecycle-invalid",
        )
        if profile == "durable-prepared":
            require(operation_id in register_ids, "fsync-register-missing")
    return len(cell_ids)


def rtt_band_edges(sample_count):
    return [band * sample_count // 10 for band in range(11)]


def rtt_band_arrivals(attempts, client_rows, workload_rows):
    """Count arrivals from each band's first fsync to the next band's first."""
    parents = {}
    for row in client_rows:
        spans = [
            span for span in (row.get("spans", []) if isinstance(row, dict) else [])
            if isinstance(span, dict) and span.get("name") == "op"
            and isinstance(span.get("op"), str)
        ]
        if spans and spans[0].get("kind") == "fsync":
            parents[spans[-1]["op"]] = spans[0]["op"]
    first_arrivals = {}
    for index, attempt in enumerate(attempts):
        fsync = parents.get(attempt["request_id"])
        if fsync is not None:
            first_arrivals.setdefault(fsync, index)
    warmups = sum(row["warmup"] for row in workload_rows)
    if len(first_arrivals) != len(workload_rows):
        return None
    starts = [*first_arrivals.values(), len(attempts)]
    edges = [starts[warmups + index] for index in rtt_band_edges(len(workload_rows) - warmups)]
    return [end - start for start, end in zip(edges, edges[1:])]


def validate_cell_evidence(
    server_rows,
    client_rows,
    workload_rows,
    trace_text,
    cell,
    planned_fsyncs,
    profile="durable-prepared",
):
    """Reconcile one serial mounted cell across server, client, and syscall evidence."""
    validate_smoke(server_rows, client_rows, cell, planned_fsyncs, profile)
    require(isinstance(workload_rows, list), "workload-results-invalid")
    require(len(workload_rows) == planned_fsyncs, "workload-result-count-mismatch")
    pids = set()
    tids = set()
    workload_tid = None
    durations = []
    for index, row in enumerate(workload_rows):
        require(
            isinstance(row, dict)
            and row.get("index") == index
            and type(row.get("warmup")) is bool
            and type(row.get("duration_ns")) is int
            and row.get("duration_ns") > 0
            and row.get("syscall") == "fsync"
            and row.get("return_code") == 0
            and type(row.get("pid")) is int
            and row.get("pid") > 0
            and type(row.get("tid")) is int
            and row.get("tid") > 0,
            "workload-result-invalid",
        )
        pids.add(row["pid"])
        tids.add(row["tid"])
        workload_tid = row["tid"]
        if not row["warmup"]:
            durations.append(row["duration_ns"])
    require(len(pids) == 1, "workload-pid-mismatch")
    require(len(tids) == 1, "workload-tid-mismatch")
    require(durations, "zero-samples")
    require(isinstance(trace_text, str), "workload-strace-invalid")
    traced = []
    for line in trace_text.splitlines():
        if "fsync(" not in line and "fdatasync(" not in line:
            continue
        match = re.fullmatch(
            r"(?:\[pid +)?([0-9]+)(?:\])? +(?:f(?:data)?sync)\([0-9]+\) += +(-?[0-9]+)(?: +.*)?",
            line,
        )
        require(match is not None, "workload-strace-invalid")
        traced.append((int(match.group(1)), int(match.group(2))))
    require(len(traced) == planned_fsyncs, "workload-strace-count-mismatch")
    require(
        all(tid in tids and result == 0 for tid, result in traced),
        "workload-strace-result-mismatch",
    )

    attempts = sorted(
        (row for row in server_rows if isinstance(row, dict) and row.get("kind") == "http_attempt"),
        key=lambda row: row.get("arrival_seq", 0),
    )
    first = next(row["arrival_seq"] for row in attempts if row.get("request_id") == f"q3-mark-{cell}-start")
    last = next(row["arrival_seq"] for row in attempts if row.get("request_id") == f"q3-mark-{cell}-end")
    cell_attempts = [row for row in attempts if first < row["arrival_seq"] < last]
    routes = {}
    for row in cell_attempts:
        route = f"{row.get('method')} {row.get('route')}"
        routes[route] = routes.get(route, 0) + 1
    logical_publishes = None
    if profile == "durable-prepared":
        registers = [
            row
            for row in cell_attempts
            if row.get("method") == "POST"
            and row.get("route") == "/volume/:volume/intent"
        ]
        ordinals = {}
        for row in registers:
            arrivals = ordinals.setdefault(row["request_id"], [])
            arrivals.append(len(arrivals) + 1)
        operation_kinds = {}
        for row in client_rows:
            if not isinstance(row, dict):
                continue
            spans = row.get("spans", [])
            if not isinstance(spans, list):
                continue
            for span in reversed(spans):
                if isinstance(span, dict) and span.get("name") == "op":
                    operation_kinds[span.get("op")] = span.get("kind")
                    break
        require(
            not any(
                operation_kinds.get(row.get("request_id")) == "commit"
                for row in cell_attempts
            ),
            "cell-commit-contamination",
        )
    else:
        publish_attempts = [
            row
            for row in cell_attempts
            if row.get("method") == "POST"
            and row.get("route") == "/volume/:volume/publish"
        ]
        logical_publishes = len(
            {row.get("request_id") for row in publish_attempts}
        )
        require(
            logical_publishes == planned_fsyncs and logical_publishes > 0,
            "publish-population-invalid",
        )
    summary = {
        "successful_fsyncs": planned_fsyncs,
        "durations_ns": durations,
        "tid": workload_tid,
        "route_attempts": routes,
        "rtt_band_attempts": rtt_band_arrivals(cell_attempts, client_rows, workload_rows),
        "attempt_count_source": "server-counted",
        "operation_kind_source": "client-attested",
    }
    if profile == "published":
        summary.update(
            logical_publishes=logical_publishes,
            publish_attempts=routes.get("POST /volume/:volume/publish", 0),
            request_correlation="not request-correlated",
            strace_reconciled=True,
        )
    else:
        summary.update(
            register_attempts=len(registers),
            register_repeated_arrivals=sum(
                len(values) - 1 for values in ordinals.values()
            ),
            register_arrival_ordinals=ordinals,
            background_attempts=len(cell_attempts) - len(registers),
        )
    return summary


def netem_commands(namespace, client_veth, added_rtt_ms):
    """Return client-veth-only netem setup and JSON preflight commands."""
    safe = re.compile(r"[a-zA-Z0-9_.-]{1,32}")
    require(safe.fullmatch(namespace) is not None, "network-name-invalid")
    require(
        safe.fullmatch(client_veth) is not None and client_veth != "lo",
        "netem-device-invalid",
    )
    require(type(added_rtt_ms) is int and 0 <= added_rtt_ms <= 60_000, "netem-delay-invalid")
    prefix = ["ip", "netns", "exec", namespace, "tc"]
    return [
        prefix + ["qdisc", "replace", "dev", client_veth, "root", "netem", "delay", f"{added_rtt_ms}ms"],
        prefix + ["-j", "qdisc", "show", "dev", client_veth],
    ]


def offload_commands(namespace, host_veth, client_veth):
    """Return two-ended veth offload configuration and receipt commands."""
    safe = re.compile(r"[a-zA-Z0-9_.-]{1,32}")
    require(
        safe.fullmatch(namespace)
        and all(safe.fullmatch(value) and value != "lo" for value in (host_veth, client_veth)),
        "offload-device-invalid",
    )
    disabled = ["tso", "off", "gso", "off", "gro", "off"]
    client = ["ip", "netns", "exec", namespace, "ethtool"]
    return [
        ["ethtool", "-K", host_veth, *disabled],
        [*client, "-K", client_veth, *disabled],
        ["ethtool", "-k", host_veth],
        [*client, "-k", client_veth],
    ]


def validate_netem_preflight(text, added_rtt_ms):
    """Validate the qdisc observed immediately before a cell."""
    try:
        rows = json.loads(text, object_pairs_hook=unique_object)
    except (ValueError, Refused) as error:
        raise Refused("netem-preflight-invalid") from error
    require(
        type(added_rtt_ms) is int and 0 <= added_rtt_ms <= 60_000,
        "netem-preflight-invalid",
    )
    expected_seconds = added_rtt_ms / 1000
    require(
        isinstance(rows, list)
        and len(rows) == 1
        and isinstance(rows[0], dict)
        and rows[0].get("kind") == "netem"
        and rows[0].get("root") is True
        and isinstance(rows[0].get("options"), dict),
        "netem-preflight-invalid",
    )
    options = rows[0]["options"]
    required = {"limit"} if added_rtt_ms == 0 else {"limit", "delay"}
    # The kernel also reports `seed` (netem's PRNG seed, unused with zero
    # loss, jitter and correlation), `ecn` and `gap`; each is admitted only at
    # its no-op value. Any other key (loss, duplicate, corrupt, reorder, rate,
    # slot, ...) refuses.
    noop = {"seed", "ecn", "gap"}
    require(
        required <= set(options) <= required | noop
        and type(options.get("limit")) is int
        and options["limit"] > 0
        and ("seed" not in options or type(options["seed"]) is int)
        and ("ecn" not in options or options["ecn"] is False)
        and ("gap" not in options or (type(options["gap"]) is int and options["gap"] == 0)),
        "netem-preflight-invalid",
    )
    if added_rtt_ms == 0:
        require("delay" not in options, "netem-preflight-invalid")
        return added_rtt_ms
    delay = options.get("delay")
    require(
        isinstance(delay, dict)
        and set(delay) == {"delay", "jitter", "correlation"},
        "netem-preflight-invalid",
    )
    observed_seconds = delay.get("delay")
    # One nanosecond admits JSON decimal-to-binary conversion, not another
    # millisecond-scale configuration.
    require(
        type(observed_seconds) in (int, float)
        and math.isfinite(observed_seconds)
        and abs(observed_seconds - expected_seconds) <= 0.000_000_001
        and type(delay.get("jitter", 0)) in (int, float)
        and delay.get("jitter", 0) == 0
        and type(delay.get("correlation", 0)) in (int, float)
        and delay.get("correlation", 0) == 0,
        "netem-preflight-invalid",
    )
    return added_rtt_ms


def validate_calibrated_rtts(values):
    """Return the two or more distinct calibrated nonzero RTTs."""
    require(isinstance(values, list), "rtt-calibration-invalid")
    nonzero = sorted({value for value in values if type(value) in (int, float) and value > 0})
    require(len(nonzero) >= 2, "rtt-group-needs-two-nonzero")
    return nonzero


def validate_observed_rtts(cells):
    """Require both ping anchors and their mean to observe the configured RTT."""
    baselines = [cell for cell in cells if cell.get("configured_rtt_ms") == 0]
    require(len(baselines) == 1, "rtt-observation-invalid")
    baseline = baselines[0]
    fields = ("observed_rtt_pre_ms", "observed_rtt_post_ms", "observed_rtt_ms")
    for cell in cells:
        configured = cell.get("configured_rtt_ms")
        require(
            type(configured) in (int, float)
            and math.isfinite(configured)
            and configured >= 0
            and (configured == 0 or configured > 5)
            and all(
                type(cell.get(name)) in (int, float)
                and math.isfinite(cell[name])
                and type(baseline.get(name)) in (int, float)
                and math.isfinite(baseline[name])
                for name in fields
            )
            and math.isclose(
                cell["observed_rtt_ms"],
                (cell["observed_rtt_pre_ms"] + cell["observed_rtt_post_ms"]) / 2,
            ),
            "rtt-observation-invalid",
        )
        tolerance_ms = max(configured * 0.25, 5)
        for name in fields:
            delivered = cell[name] - baseline[name]
            require(
                abs(delivered - configured) <= tolerance_ms
                and (configured == 0 or delivered <= 1.30 * configured),
                "rtt-observation-invalid",
            )
    return len(cells)


def validate_route_vector(cells):
    """Require one server-counted route vector across a profile's RTT cells."""
    require(isinstance(cells, list) and cells, "rtt-calibration-route-vector")
    vectors = []
    for cell in cells:
        require(isinstance(cell, dict), "rtt-calibration-route-vector")
        summary = cell.get("summary")
        require(isinstance(summary, dict), "rtt-calibration-route-vector")
        routes = summary.get("route_attempts")
        require(isinstance(routes, dict) and routes, "rtt-calibration-route-vector")
        vectors.append(tuple(sorted(routes.items())))
    require(len(set(vectors)) == 1, "rtt-calibration-route-vector")
    return len(cells)


def validate_rtt_run_requirements(cells):
    """Require complete calibrated RTT cells before judging a calibration group."""
    require(len(cells) >= 3 and cells[0].get("configured_rtt_ms") == 0, "rtt-calibration-invalid")
    validate_calibrated_rtts([cell.get("configured_rtt_ms") for cell in cells])
    for cell in cells:
        configured = cell.get("configured_rtt_ms")
        observed = cell.get("observed_rtt_ms")
        summary = cell.get("summary", {})
        counts_valid = (
            summary.get("register_attempts") == summary.get("successful_fsyncs")
            and summary.get("register_repeated_arrivals") == 0
            if cell.get("profile", "durable-prepared") == "durable-prepared"
            else summary.get("request_correlation") == "not request-correlated"
            and summary.get("strace_reconciled") is True
        )
        require(
            type(configured) is int
            and type(observed) in (int, float)
            and math.isfinite(observed)
            and cell.get("steady_state") in ("steady", "not steady")
            and counts_valid,
            "rtt-calibration-invalid",
        )
        durations = summary.get("durations_ns")
        routes = summary.get("route_attempts")
        successful_fsyncs = summary.get("successful_fsyncs")
        require(
            isinstance(durations, list)
            and durations
            and all(type(value) is int and value >= 0 for value in durations)
            and isinstance(routes, dict)
            and routes
            and all(type(count) is int and count >= 0 for count in routes.values())
            and type(successful_fsyncs) is int
            and successful_fsyncs > 0,
            "rtt-calibration-invalid",
        )
    validate_observed_rtts(cells)
    return len(cells)


def rtt_band_fsync(cell, start, stop):
    return statistics.median(cell["summary"]["durations_ns"][start:stop])


def validate_fsync_calibration(cells, stop):
    """Derive and bound shallow-band RTT-proportional request factors."""
    baseline_fsync = rtt_band_fsync(cells[0], 0, stop)
    baseline_rtt = cells[0]["observed_rtt_ms"]
    derivations = []
    for cell in cells[1:]:
        configured = cell["configured_rtt_ms"]
        summary = cell["summary"]
        delta_ms = (rtt_band_fsync(cell, 0, stop) - baseline_fsync) / 1_000_000
        routes = summary["route_attempts"]
        successful_fsyncs = summary["successful_fsyncs"]
        counted = sum(routes.values()) / successful_fsyncs
        delivered = cell["observed_rtt_ms"] - baseline_rtt
        require(delivered > 0, "rtt-fsync-calibration-invalid")
        k = delta_ms / delivered
        # The ping anchors measure the RTT delivered around the workload; the
        # qdisc setting is retained as configuration provenance. Counted cell
        # totals are not per-request correlation. The smallest expected wall-
        # clock delta is at least 100 ms, so no absolute tolerance floor applies.
        require(
            math.isfinite(k)
            and math.isfinite(counted)
            and counted > 0
            and 0.75 * counted <= k <= 1.30 * counted,
            "rtt-fsync-calibration-invalid",
        )
        derivations.append(
            {
                "configured_rtt_ms": configured,
                "observed_rtt_pre_ms": cell["observed_rtt_pre_ms"],
                "observed_rtt_post_ms": cell["observed_rtt_post_ms"],
                "delivered_added_rtt_ms": delivered,
                "overshoot": delivered / configured,
                "k": k,
                "counted": counted,
                "k_over_counted": k / counted,
                "unattributed_excess": k - counted,
                "label": "unattributed RTT-proportional wall-clock excess",
            }
        )
    factors = [item["k"] for item in derivations]
    require(
        factors and max(factors) <= min(factors) * 1.10,
        "rtt-fsync-calibration-invalid",
    )
    return derivations


def validate_rtt_observations(cells):
    """Require complete RTT cells whose observations meet their tolerances."""
    record = rtt_calibration_record(cells)
    if record["reason"] is not None:
        raise Refused(record["reason"])
    return len(cells)


def rtt_depth_sensitivity(cells, edges):
    """Describe matched bands without applying any calibration threshold."""
    table = []
    baseline = cells[0]
    for band, (start, stop) in enumerate(zip(edges, edges[1:])):
        baseline_fsync = rtt_band_fsync(baseline, start, stop)
        rows, factors = [], []
        for cell in cells:
            rtt = cell["configured_rtt_ms"]
            attempts = cell["summary"].get("rtt_band_attempts")
            counted = attempts[band] / (stop - start) if attempts is not None else None
            row = dict(configured_rtt_ms=rtt, counted=counted)
            if rtt:
                delivered = cell["observed_rtt_ms"] - baseline["observed_rtt_ms"]
                delta_ms = (rtt_band_fsync(cell, start, stop) - baseline_fsync) / 1_000_000
                row["k"] = delta_ms / delivered
                factors.append(row["k"])
            rows.append(row)
        table.append(dict(
            band=band + 1, sample_index_range=[start, stop - 1], cells=rows,
            agreement_ratio=max(factors) / min(factors) if min(factors) > 0 else None,
        ))
    return table


def rtt_calibration_record(cells):
    """Record shallow-depth calibration and whole-cell findings for one profile."""
    validate_rtt_run_requirements(cells)
    for cell in cells:
        validate_rtt_band_fields(cell.get("profile", "durable-prepared"), cell["summary"])
    profile = cells[0].get("profile")
    cell_order = "/".join(str(cell["configured_rtt_ms"]) for cell in cells)
    record = dict(
        event="calibration",
        profile=profile,
        outcome="calibrated",
        reason=None,
        scope=None,
        band_steadiness="10% halves median check only",
        cell_order_confound=f"Fixed cell order {cell_order} ms confounds venue ageing with RTT level.",
        whole_cell_steadiness=[
            dict(configured_rtt_ms=cell["configured_rtt_ms"], finding=cell["steady_state"],
                 confound=CAUSE_NOT_ATTRIBUTED
                 if cell["steady_state"] == "not steady" else None)
            for cell in cells
        ],
    )
    geometry = [
        (len(summary["durations_ns"]), summary["successful_fsyncs"], summary.get("register_chain_head_seq"))
        for summary in (cell["summary"] for cell in cells)
    ]
    samples, successful_fsyncs, head = geometry[0]
    edges = rtt_band_edges(samples)
    stop = edges[1]
    try:
        require(
            all(item == geometry[0] for item in geometry)
            and 2 <= stop and samples <= successful_fsyncs,
            "rtt-calibration-band-mismatch",
        )
        record["depth_sensitivity"] = rtt_depth_sensitivity(cells, edges)
        midpoint = stop // 2
        require(
            all(median_halves_steady(
                round(rtt_band_fsync(cell, 0, midpoint)), round(rtt_band_fsync(cell, midpoint, stop)),
                STEADY_STATE_TOLERANCE,
            ) for cell in cells),
            "rtt-calibration-band-not-steady",
        )
        validate_route_vector(cells)
        derivations = validate_fsync_calibration(cells, stop)
    except Refused as error:
        record.update(outcome="refused", reason=str(error))
        return record
    if profile == "published":
        d0 = 1 + successful_fsyncs - samples
        d1 = d0 + stop - 1
    else:
        d0 = d1 = head
    for derivation in derivations:
        derivation.update(band=1, sample_index_range=[0, stop - 1], pre_publish_head_seq_range=[d0, d1])
    record["rtt_derivations"] = derivations
    record["scope"] = (
        "RTT proportionality is supported only for band 1, the recorded pre-publish "
        f"head-seq range {d0}–{d1}, and the tested RTT levels. "
        f"{record['cell_order_confound']}"
    )
    return record


def calibration_cell_from_row(row):
    """Rebuild the calibration input from one sealed measurement row."""
    durations = durations_artifact(row, run_root(row))
    profile = row.get("profile")
    summary = {
        "durations_ns": durations,
        "route_attempts": row.get("route_attempts"),
        "register_chain_head_seq": row.get("register_chain_head_seq"),
        "rtt_band_attempts": row.get("rtt_band_attempts"),
        "successful_fsyncs": (
            row.get("successful_fsyncs")
            if profile == "published"
            else row.get("register_attempts")
        ),
    }
    if profile == "published":
        summary.update(
            request_correlation=row.get("request_correlation"),
            strace_reconciled=row.get("strace_reconciled"),
        )
    else:
        summary.update(
            register_attempts=row.get("register_attempts"),
            register_repeated_arrivals=row.get("register_repeated_arrivals"),
        )
    return {
        "profile": profile,
        "configured_rtt_ms": row.get("configured_rtt_ms"),
        "observed_rtt_pre_ms": row.get("observed_rtt_pre_ms"),
        "observed_rtt_post_ms": row.get("observed_rtt_post_ms"),
        "observed_rtt_ms": row.get("observed_rtt_ms"),
        "steady_state": row.get("steady_state"),
        "summary": summary,
    }


def resource_preflight(meminfo, free_disk_bytes):
    """Refuse a job that must move to a venue with sufficient memory or disk."""
    match = re.search(r"^MemAvailable:\s+([0-9]+) kB$", meminfo, re.MULTILINE)
    require(match is not None, "job-memory-preflight")
    available = int(match.group(1)) * 1024
    require(available >= 4_294_967_296, "job-memory-preflight")
    require(type(free_disk_bytes) is int and free_disk_bytes >= 21_474_836_480, "job-disk-preflight")
    return available, free_disk_bytes


def resource_preflight_for_work(work):
    """Apply the common memory and disk gate before one measurement mode."""
    work = Path(work).resolve(strict=True)
    try:
        meminfo = Path("/proc/meminfo").read_text()
        disk = os.statvfs(work)
    except OSError as error:
        raise Refused("job-resource-preflight") from error
    return resource_preflight(meminfo, disk.f_bavail * disk.f_frsize)


def new_work(path):
    """Create a private, new work directory outside the checkout."""
    path = Path(path).resolve()
    require(
        not contained(path, REPOSITORY),
        "work-directory-inside-repository",
    )
    require(not path.exists(), "work-directory-must-be-new")
    path.mkdir(mode=0o700)
    return path


def stop_group(child):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def child_environment(extra=None):
    environment = {
        "HOME": "",
        "LC_ALL": "C",
        "LANG": "C",
        # A fixed system path: the network tools (tc, ip) live in sbin, which
        # the interpreter's default search path omits.
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": "",
        "__CF_USER_TEXT_ENCODING": "0x0:0x0",
    }
    if extra:
        environment.update(extra)
    return environment


def loopback_store_environment(environment=None):
    """Select the hermetic default or one complete runner-supplied S3 venue."""
    environment = os.environ if environment is None else environment
    selected = {
        name: environment[name]
        for name in LOOPBACK_STORE_ENV
        if environment.get(name)
    }
    if not selected:
        return {"GRANARY_STORE": "memory:"}
    if selected == {"GRANARY_STORE": "memory:"}:
        return selected
    require(
        selected.get("GRANARY_STORE") == "s3:"
        and all(name in selected for name in LOOPBACK_STORE_ENV),
        "loopback-store-environment-incomplete",
    )
    return selected


def venue_storage_environment(environment=None):
    """Read the VM-observed backing/cache receipt passed into the root runner."""
    environment = os.environ if environment is None else environment
    values = {
        "venue_backing": environment.get("GRANARY_Q3_VENUE_BACKING"),
        "venue_cache_mode": environment.get("GRANARY_Q3_VENUE_CACHE_MODE"),
        "venue_text": environment.get("GRANARY_Q3_VENUE_TEXT"),
    }
    require(
        all(isinstance(value, str) and value for value in values.values()),
        "venue-storage-unrecorded",
    )
    require(
        "kernel timer granularity" in values["venue_text"].casefold()
        and "cannot" in values["venue_text"].casefold(),
        "venue-storage-caveat",
    )
    return values


def start_command(command, stem, *, cwd, environment=None):
    """Start one persistent child in a new, runner-owned process group."""
    argv = [str(value) for value in command]
    require(
        argv and stem not in ("", ".") and Path(stem).name == stem,
        "command-custody-invalid",
    )
    require(not credential_argv(argv), "credential-in-command")
    cwd = Path(cwd).resolve(strict=True)
    require(not contained(cwd, REPOSITORY), "work-directory-inside-repository")
    log, rc_path = cwd / (stem + ".log"), cwd / (stem + ".rc")
    require(not log.exists() and not rc_path.exists(), "command-evidence-exists")
    child_env = child_environment(environment)
    child_env["HOME"] = str(cwd)
    child_env["TMPDIR"] = str(cwd)
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    output = log.open("xb")
    try:
        child = subprocess.Popen(
            argv,
            cwd=cwd,
            env=child_env,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except BaseException:
        output.close()
        raise
    return dict(
        child=child,
        output=output,
        command=argv,
        cwd=cwd,
        log=log,
        rc_path=rc_path,
        started_at=started_at,
        finished=False,
    )


def finish_command(running, *, timeout=35, stop_signal=None):
    """Signal if requested, bound the wait, and seal one child's evidence."""
    require(not running["finished"], "command-already-finished")
    child = running["child"]
    if stop_signal is not None and child.poll() is None:
        try:
            os.killpg(child.pid, stop_signal)
        except ProcessLookupError:
            pass
    try:
        try:
            rc = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rc = 124
    finally:
        try:
            stop_group(child)
        finally:
            child.wait()
            running["output"].close()
    with running["rc_path"].open("x") as receipt:
        receipt.write(f"{rc}\n")
    running["finished"] = True
    return dict(
        command=running["command"],
        exit_code=rc,
        run_root=str(running["cwd"]),
        raw_log=str(running["log"]),
        raw_rc=str(running["rc_path"]),
        raw_log_sha256=digest(running["log"]),
        raw_rc_sha256=digest(running["rc_path"]),
        started_at=running["started_at"],
    )


def abort_command(running, mount=None, cleanup_stem="client-cleanup-unmount"):
    if running is not None and not running["finished"]:
        finish_command(running, timeout=1, stop_signal=signal.SIGKILL)
        if mount is not None:
            run_command(
                ["umount", "-l", "--", str(mount)],
                cleanup_stem,
                cwd=running["cwd"],
                timeout=5,
            )


def abort_restarted_client(running, mountpoint, evidence_dir):
    """Bound and detach only a restart child still owned by this outcome."""
    if running is None or running["finished"]:
        return
    try:
        stop_client_and_detach_fuse(
            running,
            mountpoint,
            evidence_dir,
            stem_prefix="restart-client-fuse",
        )
    except Refused:
        # Startup may fail before mounting FUSE. The child is already bounded;
        # retain the refusal while allowing the server and image cleanup below.
        abort_command(running)


@contextmanager
def owned_restarted_client(running, mountpoint, evidence_dir):
    """Keep restart-child cleanup active across every recovery probe failure."""
    try:
        yield running
    finally:
        abort_restarted_client(running, mountpoint, evidence_dir)


def wait_file(path, running, label, timeout=30):
    """Wait boundedly for one regular signal while its child stays alive."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if path.is_file():
                return
        except OSError as error:
            raise Refused(f"{label}-unreadable") from error
        if running["child"].poll() is not None:
            raise Refused(f"{label}-child-exited")
        time.sleep(0.01)
    raise Refused(f"{label}-timeout")


def private_signal(path, contents=b""):
    """Create and sync one runner-to-child signal with mode 0600."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, contents)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def handoff_text(handoff, name):
    path = handoff / name
    require(path.is_file(), f"handoff-missing: {name}")
    require(path.stat().st_mode & 0o777 == 0o600, f"handoff-mode: {name}")
    try:
        value = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise Refused(f"handoff-unreadable: {name}") from error
    require(0 < len(value) <= 4096, f"handoff-invalid: {name}")
    return value


def der_element(data, offset):
    """Return (start, end) of the DER element at offset, refusing malformed lengths."""
    require(offset + 2 <= len(data), "server-certificate-malformed")
    length = data[offset + 1]
    header = 2
    if length & 0x80:
        count = length & 0x7F
        require(0 < count <= 4 and offset + 2 + count <= len(data), "server-certificate-malformed")
        length = int.from_bytes(data[offset + 2:offset + 2 + count], "big")
        header += count
    end = offset + header + length
    require(end <= len(data), "server-certificate-malformed")
    return offset, end, offset + header


def spki_sha256(certificate):
    """SHA-256 of a DER certificate's SubjectPublicKeyInfo, the authority pin's input."""
    require(certificate[:1] == b"\x30", "server-certificate-malformed")
    _, _, body = der_element(certificate, 0)
    require(certificate[body:body + 1] == b"\x30", "server-certificate-malformed")
    _, tbs_end, cursor = der_element(certificate, body)
    if certificate[cursor:cursor + 1] == b"\xa0":
        cursor = der_element(certificate, cursor)[1]
    # serial, signature algorithm, issuer, validity, subject
    for _ in range(5):
        require(cursor < tbs_end, "server-certificate-malformed")
        cursor = der_element(certificate, cursor)[1]
    start, end, _ = der_element(certificate, cursor)
    require(certificate[start:start + 1] == b"\x30" and end <= tbs_end, "server-certificate-malformed")
    return hashlib.sha256(certificate[start:end]).hexdigest()


def authority_request(handoff, method, path, body=b"", headers=None):
    """Send one pinned mutual-TLS request through the server handoff."""
    base = urlsplit(handoff_text(handoff, "base-url"))
    require(
        base.scheme == "https" and base.hostname and base.port,
        "handoff-invalid: base-url",
    )
    pin = handoff_text(handoff, "server-pin")
    require(re.fullmatch(r"[0-9a-f]{64}", pin), "handoff-invalid: server-pin")
    certificate = handoff_text(handoff, "client-cert-path")
    credential = handoff_text(handoff, "client-credential-path")
    # The authority is trusted by its SPKI pin, exactly as the client trusts it;
    # the pin is checked on the peer certificate before any request is sent.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certificate, credential)
    context.set_alpn_protocols(["http/1.1"])
    connection = http.client.HTTPSConnection(
        base.hostname, base.port, context=context, timeout=10
    )
    try:
        connection.connect()
        peer = connection.sock.getpeercert(binary_form=True)
        require(peer is not None and spki_sha256(peer) == pin, "marker-server-pin-mismatch")
        connection.request(method, path, body=body, headers={} if headers is None else headers)
        response = connection.getresponse()
        result = response.status, response.read()
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        detail = getattr(error, "verify_message", None) or getattr(error, "reason", "")
        raise Refused(f"marker-request-failed: {type(error).__name__} {detail}".rstrip()) from error
    finally:
        connection.close()
    return result


def marker_request(handoff, cell, boundary):
    """Send one host-side marker over the handed-off mutual-TLS channel."""
    status, _ = authority_request(
        handoff,
        "POST",
        "/q3-marker",
        headers={"granary-request-id": f"q3-mark-{cell}-{boundary}"},
    )
    require(status == 204, "server-window-marker-refused")


def decode_volume_status_head(body):
    """Strictly decode a v1 status, returning None only when unverified."""
    require(
        isinstance(body, bytes)
        and 28 <= len(body) <= 120
        and body[:8] == b"GRNVSTAT"
        and body[8:10] == (1).to_bytes(2, "big"),
        "head-probe-invalid",
    )
    cursor = 26

    def take(count):
        nonlocal cursor
        end = cursor + count
        require(end <= len(body), "head-probe-invalid")
        value = body[cursor:end]
        cursor = end
        return value

    def presence():
        value = take(1)
        require(value in (b"\x00", b"\x01"), "head-probe-invalid")
        return value == b"\x01"

    verified = presence()
    head = None
    if verified:
        if presence():
            sequence = int.from_bytes(take(8), "big")
            identifier = take(33)
            require(
                0 < sequence < (1 << 64) - 1 and identifier[:1] == b"\x01",
                "head-probe-invalid",
            )
            head = {"sequence": sequence, "identifier": identifier.hex()}
        else:
            sequence = 0
            head = {"sequence": 0, "identifier": None}
        next_present = presence()
        can_extend = sequence <= (1 << 64) - 4
        require(next_present == can_extend, "head-probe-invalid")
        if next_present:
            require(
                int.from_bytes(take(8), "big") == sequence + 1,
                "head-probe-invalid",
            )
    if presence():
        require(
            int.from_bytes(take(8), "big") > 0 and take(33)[:1] == b"\x01",
            "head-probe-invalid",
        )
    require(cursor == len(body), "head-probe-invalid")
    return head


def poll_verified_head(read_status, timeout=30):
    """Poll boundedly until the authority supplies a verified status head."""
    deadline = time.monotonic() + timeout
    attempts = 0
    while True:
        attempts += 1
        status, body = read_status()
        require(status == 200, "head-probe-invalid")
        head = decode_volume_status_head(body)
        if head is not None:
            return head, body
        if time.monotonic() >= deadline:
            raise Refused(f"head-unverified: attempts={attempts}")
        time.sleep(min(0.01, max(0, deadline - time.monotonic())))


def head_probe(handoff, artifact=None, timeout=30):
    """Read a strictly decoded, verified authority head within a bound."""
    volume = handoff_text(handoff, "volume")
    head, body = poll_verified_head(
        lambda: authority_request(handoff, "GET", f"/volume/{volume}/status"),
        timeout,
    )
    if artifact is not None:
        private_signal(artifact, body)
    return head


def chain_head_probe(client_child, handoff, work, stem, timeout=30):
    """Run the client's signature-verifying discovery over the root chain."""
    output = work / f"{stem}.tsv"
    field = handoff / "client-chain-head-path"
    if field.exists():
        field.unlink()
    private_signal(field, os.fsencode(output))
    receipt = run_command(
        chain_head_child_command(client_child, handoff),
        stem,
        cwd=work,
        timeout=timeout,
    )
    require(receipt["exit_code"] == 0, "recovery-chain-head-failed")
    fields = read_measurement_fields(output)
    require(
        set(fields) == {"sequence", "identifier"}
        and fields["sequence"].isascii()
        and fields["sequence"].isdigit(),
        "recovery-chain-head-invalid",
    )
    sequence = int(fields["sequence"])
    identifier = fields["identifier"]
    require(
        (sequence == 0 and identifier == "none")
        or (sequence > 0 and re.fullmatch(r"blake3:[0-9a-f]{64}", identifier)),
        "recovery-chain-head-invalid",
    )
    return {
        "sequence": sequence,
        "identifier": None if sequence == 0 else grain_id_binary(identifier),
    }, output


def prepublication_head(client_child, handoff, work, stem, timeout=30):
    """Observe a possibly unpublished chain without consulting authority status."""
    return chain_head_probe(client_child, handoff, work, stem, timeout)


def observe_status_lag(chain, status, reason):
    """Validate a status snapshot that may lag the deciding verified chain."""
    for head in (chain, status):
        require(
            isinstance(head, dict)
            and set(head) == {"sequence", "identifier"}
            and type(head["sequence"]) is int
            and head["sequence"] >= 0
            and (
                head == {"sequence": 0, "identifier": None}
                or head["sequence"] > 0
                and isinstance(head["identifier"], str)
                and re.fullmatch(r"01[0-9a-f]{64}", head["identifier"])
            ),
            f"{reason}: invalid",
        )
    require(status["sequence"] <= chain["sequence"], f"{reason}: sequence")
    if status["sequence"] == chain["sequence"]:
        require(status["identifier"] == chain["identifier"], f"{reason}: identifier")
    return chain["sequence"] - status["sequence"]


def observed_head_operations(profile, lose_image, pre_loss, final, operations):
    """Name planned operations only after the server head proves their outcome."""
    expected_growth = 0 if profile == "published" and lose_image else 1
    require(
        final["sequence"] == pre_loss["sequence"] + expected_growth,
        "recovery-head-observation: sequence",
    )
    if expected_growth == 0:
        require(
            final["identifier"] == pre_loss["identifier"],
            "recovery-head-observation: identifier",
        )
    else:
        require(
            isinstance(final["identifier"], str)
            and final["identifier"] != pre_loss["identifier"],
            "recovery-head-observation: identifier",
        )
    require(
        operations == (["a-0000"] if lose_image else ["a-0000", "u-0001"]),
        "recovery-content-observation",
    )
    return operations


def observed_pre_loss_operations(profile, initial, after_a, pre_loss):
    require(
        pre_loss["sequence"] == after_a["sequence"],
        "sentinel-already-published: sequence",
    )
    require(
        pre_loss["identifier"] == after_a["identifier"],
        "sentinel-already-published: identifier",
    )
    expected_growth = 1 if profile == "published" else 0
    require(
        after_a["sequence"] == initial["sequence"] + expected_growth,
        "pre-loss-head-observation: sequence",
    )
    if expected_growth == 0:
        require(
            after_a["identifier"] == initial["identifier"],
            "pre-loss-head-observation: identifier",
        )
        return []
    require(
        isinstance(after_a["identifier"], str)
        and after_a["identifier"] != initial["identifier"],
        "pre-loss-head-observation: identifier",
    )
    return ["a-0000"]


def recovery_content_probe(handoff):
    """Read the restart child's successful byte-for-byte mounted-content probe."""
    fields = handoff_text(handoff, "client-probe-result").split()
    require(
        len(fields) == 2
        and all(value.isascii() and value.isdigit() for value in fields),
        "recovery-content-observation",
    )
    index, byte_count = map(int, fields)
    require(index in (0, 1) and byte_count > 0, "recovery-content-observation")
    operations = ["a-0000"] if index == 0 else ["a-0000", "u-0001"]
    return operations, index, byte_count


def load_json_lines(path, label):
    rows = []
    try:
        with path.open(encoding="utf-8") as source:
            for line in source:
                rows.append(json.loads(line, object_pairs_hook=unique_object))
    except (OSError, UnicodeError, ValueError, Refused) as error:
        raise Refused(f"{label}-unreadable") from error
    require(rows, f"{label}-empty")
    return rows


def namespace_commands(namespace, host_veth, client_veth, host_cidr, client_cidr):
    """Return the owned netns/veth setup, entry prefix, and teardown commands."""
    safe = re.compile(r"[a-zA-Z0-9_.-]{1,32}")
    require(
        safe.fullmatch(namespace)
        and all(
            safe.fullmatch(value) and len(value) <= 15
            for value in (host_veth, client_veth)
        ),
        "network-name-invalid",
    )
    try:
        host_address = ipaddress.ip_interface(host_cidr)
        client_address = ipaddress.ip_interface(client_cidr)
    except ValueError as error:
        raise Refused("network-address-invalid") from error
    require(
        host_address.version == client_address.version
        and host_address.network == client_address.network
        and host_address.ip != client_address.ip,
        "network-address-invalid",
    )
    setup = [
        ["ip", "netns", "add", namespace],
        ["ip", "link", "add", host_veth, "type", "veth", "peer", "name", client_veth],
        ["ip", "link", "set", client_veth, "netns", namespace],
        ["ip", "address", "add", host_cidr, "dev", host_veth],
        ["ip", "link", "set", host_veth, "up"],
        ["ip", "netns", "exec", namespace, "ip", "address", "add", client_cidr, "dev", client_veth],
        ["ip", "netns", "exec", namespace, "ip", "link", "set", client_veth, "up"],
        ["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"],
    ]
    enter = ["nsenter", f"--net=/var/run/netns/{namespace}", "--"]
    teardown = [["ip", "link", "del", host_veth], ["ip", "netns", "del", namespace]]
    return setup, enter, teardown


def network_names(work):
    """Return per-work-directory netns and IFNAMSIZ-bounded veth names."""
    suffix = hashlib.sha256(os.fsencode(work)).hexdigest()[:11]
    return f"q3-cell-{suffix}", f"q3h-{suffix}", f"q3c-{suffix}"


def wait_tracer(pid, running, timeout=30):
    """Wait until Linux reports that strace attached to every workload task."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if running["child"].poll() is not None:
            raise Refused("workload-strace-attach-failed")
        try:
            statuses = [
                status.read_text()
                for status in Path(f"/proc/{pid}/task").glob("*/status")
            ]
        except OSError:
            statuses = []
        tracers = [
            re.search(r"^TracerPid:\s+([0-9]+)$", status, re.MULTILINE)
            for status in statuses
        ]
        if statuses and all(
            match and int(match.group(1)) == running["child"].pid
            for match in tracers
        ):
            return
        time.sleep(0.01)
    raise Refused("workload-strace-attach-timeout")


def server_child_command(server_child, output, handoff, bind):
    return [
        server_child,
        "authority::tests::measurements::server_child::authority_measurement_server_observers_jsonl",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
        f"--skip=granary-q3-output={output}",
        f"--skip=granary-q3-handoff={handoff}",
        f"--skip=granary-q3-bind={bind}",
    ]


def client_child_command(client_child, handoff):
    return [
        client_child,
        "q3_client_child::q3_measurement_client_child",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
        f"--skip=granary-q3-handoff={handoff}",
    ]


def intent_probe_child_command(client_child, handoff):
    return [
        client_child,
        "q3_client_child::q3_measurement_intent_probe_child",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
        f"--skip=granary-q3-handoff={handoff}",
    ]


def chain_head_child_command(client_child, handoff):
    return [
        client_child,
        "q3_client_child::q3_measurement_chain_head_child",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
        f"--skip=granary-q3-handoff={handoff}",
    ]


def run_loopback_smoke(
    server_child,
    client_child,
    work,
    timeout=35,
    *,
    bind="127.0.0.1",
    client_prefix=(),
    cell="smoke",
    trace_path=None,
    profile="durable-prepared",
    fsync_allowance=None,
):
    """Run the persistent two-child loopback smoke lifecycle.

    `fsync_allowance` (seconds per planned fsync) raises the workload's
    completion bound for measured cells, whose length scales with the plan.
    """
    require(profile in ("durable-prepared", "published"), "measurement-profile-invalid")
    work = Path(work).resolve(strict=True)
    (work / "client").mkdir(mode=0o700)
    handoff = work / "handoff"
    handoff.mkdir(mode=0o700)
    server_output = work / "server-observers.jsonl"
    server = client = tracer = None
    try:
        server = start_command(
            server_child_command(server_child, server_output, handoff, bind),
            "server",
            cwd=work,
            environment=loopback_store_environment(),
        )
        wait_file(handoff / "ready", server, "server-handoff", timeout)
        require(handoff.stat().st_mode & 0o777 == 0o700, "handoff-directory-mode")
        server_uid = handoff_text(handoff, "server-uid")
        if trace_path is not None:
            private_signal(handoff / "client-workload-plan", b"3 32 1000")
        private_signal(handoff / "client-sync-profile", profile.encode("ascii"))

        client = start_command(
            list(client_prefix) + client_child_command(client_child, handoff),
            "client",
            cwd=work,
        )
        wait_file(
            handoff / "client-quiescent-before-start",
            client,
            "client-quiescent-before-start",
            timeout,
        )
        client_uid = handoff_text(handoff, "client-uid")
        planned_fsyncs_text = handoff_text(handoff, "client-planned-fsyncs")
        require(planned_fsyncs_text.isascii() and planned_fsyncs_text.isdigit(), "planned-fsync-population-invalid")
        planned_fsyncs = int(planned_fsyncs_text)
        require(planned_fsyncs > 0, "planned-fsync-population-invalid")
        require(
            server_uid == client_uid == str(os.geteuid())
            and (handoff / "server-uid").stat().st_uid == os.geteuid()
            and (handoff / "client-uid").stat().st_uid == os.geteuid(),
            "child-uid-mismatch",
        )
        if trace_path is not None:
            wait_file(handoff / "client-workload-pid", client, "client-workload-pid", timeout)
            workload_pid = int(handoff_text(handoff, "client-workload-pid"))
            tracer = start_command(
                ["strace", "-f", "-qq", "-e", "trace=fsync,fdatasync", "-o", str(trace_path), "-p", str(workload_pid)],
                "strace",
                cwd=work,
            )
            wait_tracer(workload_pid, tracer, timeout)
        marker_request(handoff, cell, "start")
        private_signal(handoff / "client-go")
        done_timeout = timeout
        if fsync_allowance is not None:
            done_timeout = max(timeout, planned_fsyncs * fsync_allowance)
        wait_file(
            handoff / "client-workload-done",
            client,
            "client-workload-done",
            done_timeout,
        )
        if tracer is not None:
            trace_record = finish_command(tracer, timeout=timeout)
            require(trace_record["exit_code"] == 0, "workload-strace-failed")
        marker_request(handoff, cell, "end")
        private_signal(handoff / "client-stop")
        client_record = finish_command(client, timeout=timeout)
        require(client_record["exit_code"] == 0, "client-child-failed")
        register_head = None
        if trace_path is not None and profile == "durable-prepared":
            # The register workload leaves the published head unchanged.
            register_head, _ = chain_head_probe(client_child, handoff, work, "rtt-chain-head", timeout)
        server_record = finish_command(server, timeout=timeout, stop_signal=signal.SIGINT)
        require(server_record["exit_code"] == 0, "server-child-failed")
        server_rows = load_json_lines(server_output, "server-attempts")
        client_rows = load_json_lines(Path(handoff_text(handoff, "client-log-path")), "client-log")
        if trace_path is None:
            summary = {
                "successful_fsyncs": validate_smoke(
                    server_rows, client_rows, cell, planned_fsyncs, profile
                )
            }
        else:
            workload_rows = load_json_lines(handoff / "workload-results.jsonl", "workload-results")
            summary = validate_cell_evidence(
                server_rows,
                client_rows,
                workload_rows,
                trace_path.read_text(),
                cell,
                planned_fsyncs,
                profile,
            )
            if register_head is not None:
                summary["register_chain_head_seq"] = register_head["sequence"]
            deltas = handoff_text(handoff, "client-m15-deltas").split()
            require(deltas == ["1", "0", "0"], "m15-calibration-invalid")
            summary["m15_fallback_delta"] = int(deltas[0])
            summary["m15_reuse_delta"] = int(deltas[1])
            summary["m15_delta"] = int(deltas[2])
            require(len(summary["durations_ns"]) == 1000, "steady-sample-floor")
        return dict(
            server=server_record,
            client=client_record,
            cell_population=summary["successful_fsyncs"],
            summary=summary,
            uid=int(server_uid),
        )
    finally:
        abort_command(tracer)
        abort_command(client, work / "client/root/mount")
        abort_command(server)


def checked(command, stem, *, cwd, environment=None):
    record = finish_command(
        start_command(command, stem, cwd=cwd, environment=environment)
    )
    require(record["exit_code"] == 0, f"command-failed: {stem}")
    try:
        return Path(record["raw_log"]).read_text()
    except (OSError, UnicodeError) as error:
        raise Refused(f"command-log-unreadable: {stem}") from error


def nft_error(code, output):
    return re.sub(r"^<cmdline>:[\d:-]+: ", "", output.partition("\n")[0]) if code == 1 else ""


def firewall_chain(execute, stem="network-firewall-probe"):
    code, output = execute(["nft", "-j", "-a", "list", "chain", *DESK_INPUT], stem)
    if nft_error(code, output).partition(";")[0] == "Error: No such file or directory":
        status, tables = execute(["nft", "list", "tables"], "network-firewall-tables")
        if status == 0 and all(
            len(row) >= 3 and row[0] == "table" and tuple(row[1:3]) != DESK_INPUT[:2]
            for row in map(str.split, tables.splitlines())
        ):
            return None
    if code:
        raise Refused(f"network-firewall-probe-failed: {output.strip()}")
    return output


def firewall_delete_command(handle):
    return ["nft", "delete", "rule", *DESK_INPUT, "handle", str(handle)]


def delete_firewall_rule(execute, command):
    code, output = execute(command, "network-firewall-delete")
    if code and nft_error(code, output) != "Error: Could not process rule: No such file or directory":
        raise Refused(f"command-failed: network-firewall-delete {output.strip()}".rstrip())


def firewall_rules(output):
    listing = json.loads(output)
    require(
        isinstance(listing, dict) and isinstance(listing.get("nftables"), list),
        "network-firewall-listing-invalid",
    )
    return (entry.get("rule", {}) for entry in listing["nftables"])


def firewall_command(command, stem, *, cwd):
    record = run_command(command, stem, cwd=cwd)
    return record["exit_code"], Path(record["raw_log"]).read_text()


def install_firewall_rule(work, host_veth):
    execute = partial(firewall_command, cwd=work)
    if firewall_chain(execute) is None:
        return None
    comment = Q3_RULE_COMMENT + host_veth
    # Echo the inserted rule to get its handle from the same transaction.
    record = run_command(
        ["nft", "-a", "-e", "insert", "rule", *DESK_INPUT, "iifname",
         f'"{host_veth}"', "accept", "comment", f'"{comment}"'],
        "network-firewall-insert", cwd=work,
    )
    require(record["exit_code"] == 0, "command-failed: network-firewall-insert")
    try:
        output = Path(record["raw_log"]).read_text()
    except (OSError, UnicodeError):
        output = ""
    match = re.search(rf'(?m) comment "{re.escape(comment)}" # handle ([1-9][0-9]*)[ \t]*$', output)
    if match:
        return match[1]
    error = Refused("network-firewall-handle-missing")
    try:
        listing = firewall_chain(execute, "network-firewall-lookup")
        if listing is not None:
            for rule in firewall_rules(listing):
                if rule.get("comment") == comment:
                    delete_firewall_rule(execute, firewall_delete_command(rule["handle"]))
                    break
    except (OSError, ValueError, KeyError) as cleanup_error:
        error.add_note(f"firewall rollback also refused: {cleanup_error}")
    raise error


def reap_firewall():
    def execute(command, _stem):
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=child_environment(),
        )
        return result.returncode, result.stdout

    try:
        output = firewall_chain(execute)
        if output is None:
            return 0
        live = {name for _, name in socket.if_nameindex()}
        failed = False
        for rule in firewall_rules(output):
            comment = rule.get("comment", "")
            if comment.startswith(Q3_RULE_COMMENT) and comment.removeprefix(Q3_RULE_COMMENT) not in live:
                try:
                    delete_firewall_rule(execute, firewall_delete_command(rule["handle"]))
                except Refused as error:
                    print(f"q3-venue: firewall reap failed: {error}", file=sys.stderr)
                    failed = True
        return int(failed)
    except (OSError, ValueError, KeyError) as error:
        print(f"q3-venue: firewall reap failed: {error}", file=sys.stderr)
        return 1


def observed_ping_rtt(prefix, address, stem, *, cwd):
    output = checked(
        list(prefix)
        + ["ping", "-n", "-q", "-c", "40", "-i", "0.2", address],
        stem,
        cwd=cwd,
    )
    match = re.search(r"= [0-9.]+/([0-9.]+)/[0-9.]+/[0-9.]+ ms", output)
    require(match is not None, "rtt-observation-invalid")
    return float(match.group(1))


def run_network_measurement(
    server_child, client_child, work, timeout=180, *, resource_check=None
):
    """Run both serial workload profiles in one owned client netns."""
    work = Path(work).resolve(strict=True)
    resource_check = resource_preflight_for_work if resource_check is None else resource_check
    resource_check(work)
    namespace, host_veth, client_veth = network_names(work)
    host_cidr, client_cidr = "192.0.2.1/30", "192.0.2.2/30"
    setup, enter, teardown = namespace_commands(
        namespace, host_veth, client_veth, host_cidr, client_cidr
    )
    cells = []
    calibrations = []
    owned_teardown = []
    firewall_handle = None
    measurement_error = None
    try:
        for index, command in enumerate(setup):
            checked(command, f"network-setup-{index}", cwd=work)
            if index == 0:
                owned_teardown.insert(0, teardown[1])
            elif index == 1:
                owned_teardown.insert(0, teardown[0])
        if os.environ.get("GRANARY_Q3_VENUE") == "linux-desk":
            firewall_handle = install_firewall_rule(work, host_veth)
        venue_storage = venue_storage_environment()
        for profile in ("durable-prepared", "published"):
            profile_cells = []
            for configured in (0, 10, 50):
                offloads = offload_commands(namespace, host_veth, client_veth)
                checked(offloads[0], f"offload-host-{profile}-{configured}", cwd=work)
                checked(offloads[1], f"offload-client-{profile}-{configured}", cwd=work)
                offload_state = {
                    "host": validate_offload_state(
                        checked(
                            offloads[2],
                            f"offload-preflight-host-{profile}-{configured}",
                            cwd=work,
                        )
                    ),
                    "client": validate_offload_state(
                        checked(
                            offloads[3],
                            f"offload-preflight-client-{profile}-{configured}",
                            cwd=work,
                        )
                    ),
                }
                configure, preflight = netem_commands(namespace, client_veth, configured)
                checked(configure, f"netem-{profile}-{configured}", cwd=work)
                validate_netem_preflight(
                    checked(
                        preflight,
                        f"netem-preflight-{profile}-{configured}",
                        cwd=work,
                    ),
                    configured,
                )
                cell = f"{profile}-rtt-{configured}"
                cell_work = work / cell
                cell_work.mkdir(mode=0o700)
                observed_pre = observed_ping_rtt(
                    enter,
                    host_cidr.split("/", 1)[0],
                    f"ping-pre-{profile}-{configured}",
                    cwd=work,
                )
                result = run_loopback_smoke(
                    server_child,
                    client_child,
                    cell_work,
                    timeout,
                    bind=host_cidr.split("/", 1)[0],
                    client_prefix=enter,
                    cell=cell,
                    trace_path=cell_work / "workload.strace",
                    profile=profile,
                    # Each fsync takes several round trips: bound the cell by
                    # its plan and delay, never by a fixed total.
                    fsync_allowance=2.0 + 0.05 * configured,
                )
                result["profile"] = profile
                result["revision"] = os.environ.get("GRANARY_Q3_REVISION")
                result["venue"] = os.environ.get("GRANARY_Q3_VENUE")
                result["configured_rtt_ms"] = configured
                result["observed_rtt_pre_ms"] = observed_pre
                result["observed_rtt_post_ms"] = observed_ping_rtt(
                    enter,
                    host_cidr.split("/", 1)[0],
                    f"ping-post-{profile}-{configured}",
                    cwd=work,
                )
                result["observed_rtt_ms"] = (
                    result["observed_rtt_pre_ms"] + result["observed_rtt_post_ms"]
                ) / 2
                result["steady_state"] = steady_state(
                    result["summary"]["durations_ns"], STEADY_STATE_TOLERANCE
                )[-1]
                artifact_path, artifact_sha256 = write_duration_artifact(
                    cell_work / "fsync-durations.ns", result["summary"]["durations_ns"]
                )
                result["durations_artifact"] = artifact_path
                result["durations_artifact_sha256"] = artifact_sha256
                result["netem_delay_placement"] = "client-veth-egress"
                result["offload_state"] = offload_state
                result.update(venue_storage)
                profile_cells.append(result)
            calibration = rtt_calibration_record(profile_cells)
            for result in profile_cells:
                result["calibration_outcome"] = calibration["outcome"]
                result["calibration_reason"] = calibration["reason"]
            calibrations.append(calibration)
            cells.extend(profile_cells)
        return dict(cells=cells, calibrations=calibrations)
    except Refused as error:
        measurement_error = error
        raise
    finally:
        teardown_error = None
        cleanup = [(f"network-teardown-{index}", command) for index, command in enumerate(owned_teardown)]
        if firewall_handle is not None:
            cleanup.insert(0, ("network-firewall-delete", firewall_delete_command(firewall_handle)))
        for stem, command in cleanup:
            try:
                if stem == "network-firewall-delete":
                    delete_firewall_rule(partial(firewall_command, cwd=work), command)
                else:
                    checked(command, stem, cwd=work)
            except (OSError, Refused) as error:
                if teardown_error is None:
                    teardown_error = (
                        error if isinstance(error, Refused)
                        else Refused(f"command-failed: {stem}: {error}")
                    )
        if teardown_error is not None and measurement_error is not None:
            measurement_error.add_note(f"network teardown also refused: {teardown_error}")
        elif teardown_error is not None:
            raise teardown_error


def cell_record(cell):
    """Project one validated mounted cell into its schema field names."""
    summary = cell["summary"]
    durations = summary["durations_ns"]
    ordered = sorted(durations)
    (
        first,
        second,
        first_p99,
        second_p99,
        splits,
        state,
    ) = steady_state(durations, STEADY_STATE_TOLERANCE)

    def percentile(percent):
        index = math.ceil(len(ordered) * percent / 100) - 1
        return ordered[max(index, 0)]

    receipt = cell["client"]
    revision = cell.get("revision")
    venue = cell.get("venue")
    require(
        isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision),
        "revision-required",
    )
    require(venue in VENUES, "schema-invalid: venue")
    record = dict(
        event="measurement",
        profile=cell["profile"],
        workload="4k-overwrite",
        network_path="dedicated-veth",
        medium="venue-filesystem",
        filesystem=cell["venue_backing"],
        host=os.uname().nodename,
        kernel=os.uname().release,
        cpu=f"{os.cpu_count() or 1} logical CPUs",
        venue=venue,
        root_label="measured length",
        root_bytes=None,
        historical_kind="in-format",
        cell_kind="steady",
        load_model="closed-loop",
        offered_rate=None,
        achieved_rate=None,
        scale={"volumes": 1, "principals": 1, "root_depth": 0},
        command=receipt["command"],
        revision=revision,
        date=receipt["started_at"],
        hardware=venue != "vm",
        deciding=False,
        pivot_input=False,
        pivot_group=None,
        pivot_role=None,
        pivot_append=False,
        pivot_verdict=None,
        sample_loss=None,
        memory_bytes=None,
        sample_floor=1000,
        intent_occupancy=NOT_APPLICABLE,
        wrapper_layer=NOT_APPLICABLE,
        row_holders=None,
        zero_row_principals=None,
        retired_principals=None,
        historical_principals=None,
        live_roots=None,
        released_rows=None,
        written_bytes=None,
        encode_register_bytes=None,
        full_snapshot_bytes=None,
        device_bytes=UNMEASURED,
        device_amplification=None,
        register_post_p99_ns=None,
        publish_decision_p99_ns=None,
        same_occupancy_publish_p99_ns=None,
        authority_log_wait_p99_ns=UNMEASURED,
        cross_volume_blocked_ns=NOT_APPLICABLE,
        verdict_metrics=["rtt", "control_writes"],
        pivot_durations_artifact=None,
        pivot_durations_artifact_sha256=None,
        exit_code=receipt["exit_code"],
        run_root=receipt["run_root"],
        raw_log=receipt["raw_log"],
        raw_rc=receipt["raw_rc"],
        raw_log_sha256=receipt["raw_log_sha256"],
        raw_rc_sha256=receipt["raw_rc_sha256"],
        warmup_count=32,
        sample_count=len(ordered),
        configured_rtt_ms=cell["configured_rtt_ms"],
        observed_rtt_pre_ms=cell["observed_rtt_pre_ms"],
        observed_rtt_post_ms=cell["observed_rtt_post_ms"],
        observed_rtt_ms=cell["observed_rtt_ms"],
        rtt_ms=cell["observed_rtt_ms"],
        rtt_group=cell["profile"],
        calibration_outcome=cell["calibration_outcome"],
        calibration_reason=cell["calibration_reason"],
        fsync_min_ns=ordered[0],
        fsync_p50_ns=percentile(50),
        fsync_p90_ns=percentile(90),
        fsync_p99_ns=percentile(99),
        fsync_max_ns=ordered[-1],
        steady_state_tolerance=STEADY_STATE_TOLERANCE,
        steady_first_half_median_ns=first,
        steady_second_half_median_ns=second,
        steady_first_half_p99_ns=first_p99,
        steady_second_half_p99_ns=second_p99,
        steady_exceedance_splits=splits,
        steady_state=state,
        durations_artifact=cell["durations_artifact"],
        durations_artifact_sha256=cell["durations_artifact_sha256"],
        venue_backing=cell["venue_backing"],
        venue_cache_mode=cell["venue_cache_mode"],
        venue_text=cell["venue_text"],
        m15_delta=summary["m15_delta"],
        m15_fallback_delta=summary["m15_fallback_delta"],
        m15_reuse_delta=summary["m15_reuse_delta"],
        tid=summary["tid"],
        route_attempts=summary["route_attempts"],
        rtt_band_attempts=summary.get("rtt_band_attempts"),
        attempt_count_source=summary["attempt_count_source"],
        operation_kind_source=summary["operation_kind_source"],
        netem_preflight=True,
        netem_delay_placement=cell["netem_delay_placement"],
        offload_state=cell["offload_state"],
    )
    if cell["profile"] == "published":
        record.update(
            successful_fsyncs=summary["successful_fsyncs"],
            logical_publishes=summary["logical_publishes"],
            publish_attempts=summary["publish_attempts"],
            request_correlation=summary["request_correlation"],
            strace_reconciled=summary["strace_reconciled"],
        )
    else:
        record.update(
            register_chain_head_seq=summary.get("register_chain_head_seq"),
            register_attempts=summary["register_attempts"],
            register_repeated_arrivals=summary["register_repeated_arrivals"],
            background_attempts=summary["background_attempts"],
        )
    if "server" in cell:
        record["server_observers_sha256"] = digest(Path(record["run_root"]) / "server-observers.jsonl")
        record["server_metrics"] = mounted_server_metrics(record)
    return record


def read_measurement_fields(path):
    """Read one Rust harness TSV, refusing duplicate or malformed fields."""
    fields = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("\t")
            require(separator and key and value and key not in fields, "pivot-output-invalid")
            fields[key] = value
    except (OSError, UnicodeError) as error:
        raise Refused("pivot-output-unreadable") from error
    require(fields, "pivot-output-empty")
    return fields


def measurement_integer(fields, name, refusal):
    value = fields.get(name)
    require(isinstance(value, str) and value.isascii() and value.isdigit(), refusal)
    return int(value)


def measurement_stream_counts(fields):
    count = measurement_integer(fields, "stream_count", "pivot-stream-counts")
    text = fields.get("stream_sample_counts")
    require(isinstance(text, str) and text, "pivot-stream-counts")
    values = text.split(",")
    require(
        len(values) == count
        and all(value.isascii() and value.isdigit() and int(value) > 0 for value in values),
        "pivot-stream-counts",
    )
    counts = [int(value) for value in values]
    require(sum(counts) == int(fields.get("sample_count", -1)), "pivot-stream-counts")
    return counts


def measurement_root_size_distribution(fields):
    text = fields.get("root_size_distribution")
    require(isinstance(text, str) and text, "pivot-root-size-distribution")
    result = {}
    for item in text.split(","):
        size, separator, count = item.partition(":")
        require(
            separator
            and size.isascii()
            and size.isdigit()
            and int(size) > 0
            and count.isascii()
            and count.isdigit()
            and int(count) > 0
            and size not in result,
            "pivot-root-size-distribution",
        )
        result[size] = int(count)
    return result


def measurement_denominator_attempts(fields):
    """Decode the ruled offered/half/quarter first-refusal evidence."""
    names = {
        "rates": "denominator_attempt_rates",
        "warmups": "denominator_attempt_warmups",
        "achieved_rates": "denominator_attempt_achieved_rates",
        "outcomes": "denominator_attempt_outcomes",
        "sent_counts": "denominator_attempt_sent_counts",
        "first_refusal_ns": "denominator_attempt_first_refusal_ns",
        "conflict_tokens": "denominator_attempt_conflict_tokens",
        "response_tokens": "denominator_attempt_response_tokens",
        "rate_limited_counts": "denominator_attempt_rate_limited_counts",
        "max_outstanding": "denominator_attempt_max_outstanding",
        "max_per_stream": "denominator_attempt_max_outstanding_per_stream",
        "stream_samples": "denominator_attempt_stream_sample_counts",
        "sample_files": "denominator_attempt_sample_files",
        "sample_counts": "denominator_attempt_sample_counts",
        "completion_files": "denominator_attempt_completion_files",
        "completion_counts": "denominator_attempt_completion_counts",
        "log_wait_p99": "denominator_attempt_log_wait_p99_ns",
        "pilot": "denominator_attempt_pilot_observations",
        "pilot_p99": "denominator_attempt_pilot_p99_ns",
        "stall_bound": "denominator_attempt_cycle_stall_bound_ns",
        "stall_count": "denominator_attempt_cycle_stall_counts",
        "stalls": "denominator_attempt_cycle_stall_ns",
        "refusal_cycle": "denominator_attempt_refusal_cycle_ns",
        "depth_records": "denominator_attempt_depth_records",
        "depth_bounds": "denominator_attempt_depth_bounds",
    }
    parts = {}
    for name, field_name in names.items():
        text = fields.get(field_name)
        reason = (
            "pivot-pilot-observation"
            if name in {"pilot", "pilot_p99"}
            else "pivot-denominator-attempts"
        )
        require(isinstance(text, str) and text, reason)
        parts[name] = text.split("|")
    count = len(parts["rates"])
    require(
        count > 0 and all(len(values) == count for values in parts.values()),
        "pivot-denominator-attempts",
    )
    attempts = []
    for index in range(count):
        try:
            rate = float(parts["rates"][index])
            warmup_count, warmup_elapsed_ns = (
                int(value) for value in parts["warmups"][index].split(",")
            )
            achieved_rate = float(parts["achieved_rates"][index])
            sent_count = int(parts["sent_counts"][index])
            first_refusal_ns = int(parts["first_refusal_ns"][index])
            rate_limited_count = int(parts["rate_limited_counts"][index])
            max_outstanding = int(parts["max_outstanding"][index])
            max_per_stream = [
                int(value) for value in parts["max_per_stream"][index].split(",")
            ]
            stream_samples = [
                int(value) for value in parts["stream_samples"][index].split(",")
            ]
            sample_count = int(parts["sample_counts"][index])
            completion_count = int(parts["completion_counts"][index])
            pilot = [int(value) for value in parts["pilot"][index].split(",")]
            log_wait_p99 = int(parts["log_wait_p99"][index])
        except ValueError as error:
            raise Refused("pivot-denominator-attempts") from error
        tokens = {}
        if parts["conflict_tokens"][index] != "none":
            for item in parts["conflict_tokens"][index].split(","):
                token, separator, value = item.partition(":")
                require(
                    separator
                    and token in {
                        "stale-base",
                        "not-decided",
                        "operation-bound",
                        "epoch-mismatch",
                        "volume-damaged",
                    }
                    and value.isascii()
                    and value.isdigit()
                    and int(value) > 0,
                    "pivot-denominator-conflict-token",
                )
                tokens[token] = int(value)
        response_tokens = {}
        if parts["response_tokens"][index] != "none":
            for item in parts["response_tokens"][index].split(","):
                token, separator, value = item.partition(":")
                require(
                    separator
                    and token
                    in {
                        "stale-base",
                        "not-decided",
                        "operation-bound",
                        "epoch-mismatch",
                        "volume-damaged",
                        "rate-limited",
                    }
                    and value.isascii()
                    and value.isdigit()
                    and int(value) > 0,
                    "pivot-denominator-response-token",
                )
                response_tokens[token] = int(value)
        require(
            parts["pilot_p99"][index].isascii()
            and parts["pilot_p99"][index].isdigit(),
            "pivot-denominator-pilot-p99",
        )
        require(
            parts["stall_bound"][index].isascii()
            and parts["stall_bound"][index].isdigit(),
            "pivot-denominator-stall-bound",
        )
        require(
            parts["stall_count"][index].isascii()
            and parts["stall_count"][index].isdigit(),
            "pivot-denominator-stall-count",
        )
        stall_text, *cycle_ends = parts["stalls"][index].split(";")
        stall_values = [] if stall_text == "none" else stall_text.split(",")
        ends = [
            [int(value) if value.isascii() and value.isdigit() else None
             for value in group.split(",")] if group else []
            for group in cycle_ends
        ]
        require(
            all(value.isascii() and value.isdigit() for value in stall_values),
            "pivot-denominator-stall-durations",
        )
        refusal_cycle, _, drain_note = parts["refusal_cycle"][index].partition(",")
        require(
            refusal_cycle == "none"
            or (refusal_cycle.isascii() and refusal_cycle.isdigit()),
            "pivot-denominator-refusal-cycle",
        )
        cycle_stall_bound = int(parts["stall_bound"][index])
        pilot_p99 = int(parts["pilot_p99"][index])
        cycle_stalls = [int(value) for value in stall_values]
        cycle_stall_count = int(parts["stall_count"][index])
        outcome = parts["outcomes"][index]
        require(
            math.isfinite(rate)
            and rate > 0
            and 0 < warmup_count <= PIVOT_WARMUP_COUNT
            and warmup_elapsed_ns > 0
            and math.isfinite(achieved_rate)
            and achieved_rate >= 0
            and sent_count >= 0
            and outcome in {"passed", "overlap", "cycle-deadline", "409", "429"}
            and rate_limited_count >= 0
            and max_outstanding > 0
            and max_per_stream
            and all(value >= 0 for value in max_per_stream)
            and len(stream_samples) == len(max_per_stream)
            and sum(stream_samples) == sent_count
            and 0 <= sample_count <= sent_count
            and completion_count == sample_count
            and len(pilot) == 5
            and all(value > 0 for value in pilot)
            and pilot[2] == pilot_p99
            and parts["sample_files"][index]
            and parts["completion_files"][index]
            and (log_wait_p99 > 0 or log_wait_p99 == 0 and drain_note)
            and (
                outcome == "passed" and first_refusal_ns == 0
                or outcome != "passed" and first_refusal_ns > 0
            )
            and (outcome != "409" or bool(tokens))
            and (outcome != "429" or rate_limited_count > 0)
            and all(response_tokens.get(token) == value for token, value in tokens.items())
            and response_tokens.get("rate-limited", 0) == rate_limited_count
            and (
                outcome != "passed"
                or not tokens and rate_limited_count == 0 and sent_count == 1_000
            ),
            "pivot-denominator-attempts",
        )
        require(
            pilot_p99 > 0
            and cycle_stall_bound == pilot_p99 * 10
            and cycle_stall_count == len(cycle_stalls)
            and all(value > cycle_stall_bound for value in cycle_stalls)
            and (
                (
                    outcome in {"overlap", "cycle-deadline"}
                    and refusal_cycle != "none"
                    and int(refusal_cycle) > 0
                )
                or (outcome not in {"overlap", "cycle-deadline"} and refusal_cycle == "none")
            ),
            "pivot-denominator-cycle-stall-binding",
        )
        try:
            records = []
            for item in parts["depth_records"][index].split(";"):
                if item == "none":
                    records.append(None)
                else:
                    i, lane, phase, depth = item.split(",")
                    records.append([int(i), int(lane), phase, int(depth)])
        except ValueError as error:
            raise Refused("pivot-denominator-depth-records") from error
        attempts.append(
            dict(
                rate=rate,
                depth_records=records,
                drain_note=drain_note or None,
                cycle_ends_ns=ends or None,
                depth_bounds=measurement_range(parts["depth_bounds"][index], "pivot-denominator-depth-bounds"),
                warmup_count=warmup_count,
                warmup_elapsed_ns=warmup_elapsed_ns,
                achieved_rate=achieved_rate,
                outcome=outcome,
                sent_count=sent_count,
                time_to_first_refusal_ns=first_refusal_ns,
                conflict_token_counts=tokens,
                response_token_counts=response_tokens,
                rate_limited_count=rate_limited_count,
                max_outstanding=max_outstanding,
                max_outstanding_per_stream=max_per_stream,
                stream_sample_counts=stream_samples,
                sample_file=parts["sample_files"][index],
                sample_count=sample_count,
                completion_file=parts["completion_files"][index],
                completion_count=completion_count,
                authority_log_wait_p99_ns=log_wait_p99,
                pilot=dict(
                    sample_count=pilot[0],
                    p50_ns=pilot[1],
                    p99_ns=pilot[2],
                    max_ns=pilot[3],
                    stream_count=pilot[4],
                ),
                pilot_p99_ns=pilot_p99,
                cycle_stall_bound_ns=cycle_stall_bound,
                cycle_stall_count=cycle_stall_count,
                cycle_stall_durations_ns=cycle_stalls,
                refusal_cycle_duration_ns=(
                    None if refusal_cycle == "none" else int(refusal_cycle)
                ),
            )
        )
    return attempts


def measurement_range(value, reason):
    if value == "none":
        return None
    try:
        start, end = map(int, value.split(","))
    except (AttributeError, ValueError) as error:
        raise Refused(f"{reason}-format") from error
    return [start, end]


def deadline_cycles(attempt, values, group):
    if attempt["outcome"] in {"passed", "not-steady"}:
        return values
    cutoff = attempt["time_to_first_refusal_ns"]
    ends = attempt["cycle_ends_ns"]
    return (value for value, end in zip(values, ends[group], strict=True) if end < cutoff)


def validate_denominator_cycles(attempt, decisions, completions):
    cycles = (decision + completion for decision, completion in zip(decisions, completions, strict=True))
    require(all(cycle <= DENOMINATOR_CYCLE_LIMIT_NS for cycle in deadline_cycles(attempt, cycles, 0)),
            "pivot-denominator-cycle-samples")


def validate_denominator_attempts(attempts):
    """Require first-refusal and concurrency evidence for every attempted rate."""
    required = {
        "rate",
        "warmup_count",
        "warmup_elapsed_ns",
        "achieved_rate",
        "outcome",
        "sent_count",
        "time_to_first_refusal_ns",
        "conflict_token_counts",
        "response_token_counts",
        "rate_limited_count",
        "max_outstanding",
        "max_outstanding_per_stream",
        "stream_sample_counts",
        "sample_file",
        "sample_count",
        "completion_file",
        "completion_count",
        "authority_log_wait_p99_ns",
        "pilot",
        "pilot_p99_ns",
        "cycle_stall_bound_ns",
        "cycle_stall_count",
        "cycle_stall_durations_ns",
        "refusal_cycle_duration_ns",
        "depth_records",
        "drain_note",
        "cycle_ends_ns",
        "depth_bounds",
        "steady_first_half_median_ns",
        "steady_second_half_median_ns",
        "steady_first_half_p99_ns",
        "steady_second_half_p99_ns",
        "steady_exceedance_splits",
        "steady_state",
        "steady_pattern",
        "guards_passed",
        "sample_artifact",
        "sample_artifact_sha256",
        "completion_artifact",
        "completion_artifact_sha256",
    }
    require(isinstance(attempts, list) and attempts, "pivot-denominator-attempts")
    complete_bounds = None
    for attempt in attempts:
        require(
            isinstance(attempt, dict)
            and set(attempt) == required
            and type(attempt["rate"]) is float
            and math.isfinite(attempt["rate"])
            and attempt["rate"] > 0
            and type(attempt["warmup_count"]) is int
            and 0 < attempt["warmup_count"] <= PIVOT_WARMUP_COUNT
            and type(attempt["warmup_elapsed_ns"]) is int
            and attempt["warmup_elapsed_ns"] > 0
            and type(attempt["achieved_rate"]) is float
            and math.isfinite(attempt["achieved_rate"])
            and attempt["achieved_rate"] >= 0
            and attempt["outcome"]
            in {"passed", "not-steady", "overlap", "cycle-deadline", "409", "429"}
            and type(attempt["sent_count"]) is int
            and 0 <= attempt["sent_count"] <= 1_000
            and type(attempt["time_to_first_refusal_ns"]) is int
            and isinstance(attempt["conflict_token_counts"], dict)
            and isinstance(attempt["response_token_counts"], dict)
            and type(attempt["rate_limited_count"]) is int
            and type(attempt["max_outstanding"]) is int
            and attempt["max_outstanding"] > 0
            and isinstance(attempt["max_outstanding_per_stream"], list)
            and len(attempt["max_outstanding_per_stream"])
            == denominator_stream_count(attempt["rate"])
            and all(
                type(value) is int and value >= 0
                for value in attempt["max_outstanding_per_stream"]
            )
            and isinstance(attempt["stream_sample_counts"], list)
            and len(attempt["stream_sample_counts"])
            == len(attempt["max_outstanding_per_stream"])
            and sum(attempt["stream_sample_counts"]) == attempt["sent_count"]
            and isinstance(attempt["sample_file"], str)
            and bool(attempt["sample_file"])
            and type(attempt["sample_count"]) is int
            and 0 <= attempt["sample_count"] <= attempt["sent_count"]
            and isinstance(attempt["completion_file"], str)
            and bool(attempt["completion_file"])
            and type(attempt["completion_count"]) is int
            and attempt["completion_count"] == attempt["sample_count"]
            and type(attempt["authority_log_wait_p99_ns"]) is int
            and (attempt["authority_log_wait_p99_ns"] > 0
                 or attempt["authority_log_wait_p99_ns"] == 0 and attempt["drain_note"])
            and isinstance(attempt["pilot"], dict)
            and set(attempt["pilot"])
            == {"sample_count", "p50_ns", "p99_ns", "max_ns", "stream_count"}
            and attempt["pilot"]["sample_count"] >= 32
            and 0 < attempt["pilot"]["p50_ns"] <= attempt["pilot"]["p99_ns"]
            <= attempt["pilot"]["max_ns"]
            and attempt["pilot"]["p99_ns"] == attempt["pilot_p99_ns"]
            and attempt["pilot"]["stream_count"]
            == denominator_stream_count(attempt["rate"])
            and type(attempt["guards_passed"]) is bool
            and attempt["guards_passed"]
            == (attempt["outcome"] in {"passed", "not-steady"})
            and isinstance(attempt["sample_artifact"], str)
            and isinstance(attempt["completion_artifact"], str)
            and all(
                isinstance(attempt[name], str)
                and bool(re.fullmatch(r"[0-9a-f]{64}", attempt[name]))
                for name in (
                    "sample_artifact_sha256",
                    "completion_artifact_sha256",
                )
            )
            and (
                attempt["outcome"] in {"passed", "not-steady"}
                and attempt["warmup_count"] == PIVOT_WARMUP_COUNT
                and attempt["sent_count"] == 1_000
                and attempt["sample_count"] == 1_000
                and attempt["time_to_first_refusal_ns"] == 0
                and not attempt["response_token_counts"]
                or attempt["outcome"] not in {"passed", "not-steady"}
                and attempt["time_to_first_refusal_ns"] > 0
            ),
            "pivot-denominator-attempts",
        )
        require(
            type(attempt["cycle_stall_bound_ns"]) is int
            and attempt["cycle_stall_bound_ns"] == attempt["pilot_p99_ns"] * 10,
            "pivot-denominator-stall-bound",
        )
        require(
            type(attempt["cycle_stall_count"]) is int
            and attempt["cycle_stall_count"] >= 0,
            "pivot-denominator-stall-count",
        )
        require(
            isinstance(attempt["cycle_stall_durations_ns"], list)
            and attempt["cycle_stall_count"]
            == len(attempt["cycle_stall_durations_ns"]),
            "pivot-denominator-stall-durations",
        )
        require(
            all(
                type(value) is int and value > attempt["cycle_stall_bound_ns"]
                for value in attempt["cycle_stall_durations_ns"]
            ),
            "pivot-denominator-stall-threshold",
        )
        require(
            (
                attempt["outcome"] in {"overlap", "cycle-deadline"}
                and type(attempt["refusal_cycle_duration_ns"]) is int
                and attempt["refusal_cycle_duration_ns"] > 0
            )
            or (
                attempt["outcome"] not in {"overlap", "cycle-deadline"}
                and attempt["refusal_cycle_duration_ns"] is None
            ),
            "pivot-denominator-refusal-cycle",
        )
        require(attempt["outcome"] != "cycle-deadline"
                or attempt["refusal_cycle_duration_ns"] > DENOMINATOR_CYCLE_LIMIT_NS,
                "pivot-denominator-cycle-deadline")
        outcome = attempt["outcome"]
        stalls = attempt["cycle_stall_durations_ns"]
        ends = attempt["cycle_ends_ns"]
        require((ends is None and attempt["guards_passed"]) or (
            isinstance(ends, list) and len(ends) == 2
            and all(isinstance(group, list) and len(group) == count
                    and all(type(end) is int and end >= 0 for end in group)
                    for group, count in zip(ends, (attempt["sample_count"], len(stalls)), strict=True))
        ), "pivot-denominator-cycle-ends")
        require(all(stall <= DENOMINATOR_CYCLE_LIMIT_NS for stall in deadline_cycles(attempt, stalls, 1)),
                "pivot-denominator-cycle-stall-deadline")
        require(outcome != "cycle-deadline" or attempt["time_to_first_refusal_ns"] >= DENOMINATOR_CYCLE_LIMIT_NS,
                "pivot-denominator-deadline-time")
        require(outcome != "overlap" or attempt["rate"] == 46.0
                or attempt["refusal_cycle_duration_ns"] >= DENOMINATOR_CYCLE_LIMIT_NS,
                "pivot-denominator-overlap-cycle")
        require(attempt["drain_note"] is None or (
            not attempt["guards_passed"] and attempt["drain_note"] == "pivot-request-drain-timeout"
        ), "pivot-denominator-drain-note")
        records = attempt["depth_records"]
        warmups = attempt["warmup_count"]
        streams = denominator_stream_count(attempt["rate"])
        require(
            isinstance(records, list)
            and len(records) == warmups + attempt["sent_count"]
            and all(
                record is None and not attempt["guards_passed"]
                or isinstance(record, list) and len(record) == 4
                and all(type(record[column]) is int for column in (0, 1, 3))
                and record[0] == index
                and record[2] == ("warmup" if index < warmups else "measured")
                and record[3] == index // streams
                and (index < warmups or record[1] == index % streams)
                for index, record in enumerate(records)
            ),
            "pivot-denominator-depth-sequence",
        )
        require(
            sum(record is not None for record in records[warmups:]) >= attempt["sample_count"],
            "pivot-denominator-depth-sample-coverage",
        )
        require(all(record is None or record[1] == index for index, record in enumerate(records[:warmups])),
                "pivot-denominator-warmup-lanes")
        if attempt["guards_passed"] and complete_bounds is not None:
            require(attempt["depth_bounds"] == complete_bounds, "pivot-denominator-depth-parity")
        else:
            depths = [record[3] for record in records if record is not None]
            require(attempt["depth_bounds"] == ([min(depths), max(depths)] if depths else None),
                    "pivot-denominator-depth-bounds")
        if attempt["guards_passed"]:
            complete_bounds = attempt["depth_bounds"]
        if attempt["guards_passed"]:
            steady = (
                attempt["steady_first_half_median_ns"],
                attempt["steady_second_half_median_ns"],
                attempt["steady_first_half_p99_ns"],
                attempt["steady_second_half_p99_ns"],
                attempt["steady_exceedance_splits"],
                attempt["steady_state"],
            )
            require(
                attempt["steady_state"] in {"steady", "not steady"}
                and (attempt["outcome"] == "not-steady")
                == (attempt["steady_state"] == "not steady")
                and attempt["steady_pattern"] == pivot_steady_pattern(steady),
                "pivot-denominator-steadiness",
            )
        else:
            require(
                attempt["steady_first_half_median_ns"] is None
                and attempt["steady_second_half_median_ns"] is None
                and attempt["steady_first_half_p99_ns"] is None
                and attempt["steady_second_half_p99_ns"] is None
                and attempt["steady_exceedance_splits"] is None
                and attempt["steady_state"] == NOT_APPLICABLE
                and attempt["steady_pattern"] == "other",
                "pivot-denominator-steadiness",
            )


def denominator_stream_count(rate):
    """Return the fixed pool for a ruled denominator rate."""
    for offered_rate, streams in DENOMINATOR_RATE_STREAMS:
        if type(rate) is float and math.isclose(rate, offered_rate):
            return streams
    raise Refused("pivot-denominator-rate")


def pivot_child_environment(output, environment=None):
    """Pass only the complete venue store and identity into the pivot child."""
    environment = os.environ if environment is None else environment
    missing = [name for name in LOOPBACK_STORE_ENV if not environment.get(name)]
    if missing:
        raise Refused(f"pivot-store-environment-missing: {missing[0]}")
    selected = {name: environment[name] for name in LOOPBACK_STORE_ENV}
    require(selected["GRANARY_STORE"] == "s3:", "pivot-store-environment-invalid")
    venue = environment.get("GRANARY_Q3_VENUE")
    require(venue in VENUES, "pivot-venue-unrecorded")
    return {
        **selected,
        "GRANARY_MEASURE_OUTPUT": str(output),
        "GRANARY_Q3_VENUE": venue,
    }


def command_provenance(receipt, revision):
    """Project one owned child's sealed command evidence into a row."""
    return dict(
        command=receipt["command"],
        revision=revision,
        date=receipt["started_at"],
        host=os.uname().nodename,
        run_root=str(Path(receipt["run_root"]).resolve(strict=True)),
        raw_log=receipt["raw_log"],
        raw_rc=receipt["raw_rc"],
        raw_log_sha256=receipt["raw_log_sha256"],
        raw_rc_sha256=receipt["raw_rc_sha256"],
    )


PIVOT_RUNS = {
    "numerator": (
        "authority_measurement_pivot_ceiling_register",
        "pivot_numerator",
        "pivot-numerator.progress.tsv",
        0,
    ),
    "denominator": (
        "authority_measurement_pivot_floor_publish",
        "pivot_denominator",
        "pivot-denominator.progress.tsv",
        36,
    ),
    "diagnostic": (
        "authority_measurement_pivot_ceiling_publish_diagnostic",
        "pivot_same_occupancy_publish",
        "pivot-diagnostic.progress.tsv",
        0,
    ),
}


def pivot_child_bound_seconds(role):
    """Return one pivot row's declared child bound."""
    occupancy_setup_seconds = 60
    pilot_publish_seconds = 2
    sample_count = 1_000
    warmup_count = PIVOT_WARMUP_COUNT
    offered_rate = 46
    join_and_drain_seconds = 30
    require(role in PIVOT_RUNS, "pivot-role-bound-missing")
    pilot_publish_count = PIVOT_RUNS[role][3]
    if role == "diagnostic":
        # One ceiling setup, then 64 warmups plus 368 serial requests with separate 100 ms
        # publish and 2 s completion bounds, plus drain; then a 20% margin.
        subtotal = (
            occupancy_setup_seconds
            + pilot_publish_count * pilot_publish_seconds
            + ((warmup_count + 368) * 21 + 9) // 10
            + join_and_drain_seconds
        )
        return subtotal + (subtotal + 4) // 5
    if role == "denominator":
        # The ruled 46, 23 and 11.5/s attempts each own a fresh setup, the
        # same 36-publish serial pilot and a bounded 64-prefix plus measured
        # schedule/drain. Worst case: 186+209+255=650; 20% margin.
        subtotals = [
            occupancy_setup_seconds
            + pilot_publish_count * pilot_publish_seconds
            + schedule
            + join_and_drain_seconds
            for schedule in (24, 47, 93)
        ]
        subtotal = sum(subtotals)
        return subtotal + (subtotal + 4) // 5
    # Numerator: 60 setup + ceil((64+1000)/46) schedule + 30 join/drain =
    # 114 seconds, plus a 20 percent (23 second) scheduling margin = 137.
    # Numerator has no pilot or retry branch.
    schedule_seconds = (
        warmup_count + sample_count + offered_rate - 1
    ) // offered_rate
    subtotal = (
        occupancy_setup_seconds
        + pilot_publish_count * pilot_publish_seconds
        + schedule_seconds
        + join_and_drain_seconds
    )
    return subtotal + (subtotal + 4) // 5


def pivot_progress_receipt(output, outcomes):
    """Seal every progress file that exists, including timed-out rows."""
    records = {}
    for role, (_, _, progress_name, _) in PIVOT_RUNS.items():
        path = output / progress_name
        stem = progress_name.removesuffix(".progress.tsv")
        attempt_paths = sorted(output.glob(f"{stem}*.progress.tsv"))
        records[role] = dict(
            outcome=outcomes[role],
            progress_file=str(path),
            progress_sha256=digest(path) if path.is_file() else None,
            attempt_progress=[
                dict(path=str(attempt), sha256=digest(attempt))
                for attempt in attempt_paths
            ],
        )
    path = output / "pivot-progress-artifacts.json"
    path.write_text(json.dumps(records, sort_keys=True) + "\n", encoding="utf-8")
    return records


def classify_denominator_attempts(attempts, output):
    """Apply exact steadiness to guard-passing rates and select the first usable row."""
    output = Path(output).resolve(strict=True)
    considered = []
    selected = None
    for attempt in attempts:
        sample_path = output / attempt["sample_file"]
        completion_path = output / attempt["completion_file"]
        attempt.update(
            guards_passed=attempt["outcome"] == "passed",
            sample_artifact=str(sample_path),
            sample_artifact_sha256=digest(sample_path),
            completion_artifact=str(completion_path),
            completion_artifact_sha256=digest(completion_path),
        )
        artifact_row = {
            "run_root": str(output),
            "sample_count": attempt["sample_count"],
            "pivot_durations_artifact": str(sample_path),
            "pivot_durations_artifact_sha256": attempt["sample_artifact_sha256"],
        }
        completion_row = {
            "run_root": str(output),
            "sample_count": attempt["completion_count"],
            "pivot_completion_artifact": str(completion_path),
            "pivot_completion_artifact_sha256": attempt[
                "completion_artifact_sha256"
            ],
        }
        values = durations_artifact(artifact_row, output, "pivot_durations")
        completion = durations_artifact(completion_row, output, "pivot_completion")
        require(
            len(values) == attempt["sample_count"]
            and len(completion) == attempt["completion_count"],
            "pivot-sample-population",
        )
        if attempt["guards_passed"]:
            require(
                len(values) == len(completion) == 1000,
                "pivot-sample-population",
            )
            steady = steady_state(values, STEADY_STATE_TOLERANCE)
            attempt.update(
                steady_first_half_median_ns=steady[0],
                steady_second_half_median_ns=steady[1],
                steady_first_half_p99_ns=steady[2],
                steady_second_half_p99_ns=steady[3],
                steady_exceedance_splits=steady[4],
                steady_state=steady[-1],
                steady_pattern=pivot_steady_pattern(steady),
            )
            if steady[-1] == "steady":
                selected = (attempt, values, artifact_row, completion_row)
            else:
                attempt["outcome"] = "not-steady"
        else:
            attempt.update(
                steady_first_half_median_ns=None,
                steady_second_half_median_ns=None,
                steady_first_half_p99_ns=None,
                steady_second_half_p99_ns=None,
                steady_exceedance_splits=None,
                steady_state=NOT_APPLICABLE,
                steady_pattern="other",
            )
        considered.append(attempt)
        if selected is not None:
            break
    branch = (
        "terminal-inconclusive"
        if selected is None
        else "normal"
        if len(considered) == 1
        else "lower-bound"
    )
    return considered, branch, selected


def run_pivot_measurement(server_child, work, *, resource_check=None):
    """Run and validate the three real-HTTP rows forming the pivot receipt."""
    work = Path(work).resolve(strict=True)
    resource_check = resource_preflight_for_work if resource_check is None else resource_check
    resource_check(work)
    output = work / "output"
    output.mkdir(mode=0o700)
    revision = os.environ.get("GRANARY_Q3_REVISION")
    require(
        isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision),
        "revision-required",
    )
    environment = pivot_child_environment(output)
    receipts = {}
    elapsed = {}
    outcomes = {}
    failures = []
    for role, (test_name, _, _, _) in PIVOT_RUNS.items():
        running = start_command(
            [
                server_child,
                f"authority::tests::measurements::occupancy::{test_name}",
                "--exact",
                "--ignored",
                "--nocapture",
            ],
            f"pivot-server-{role}",
            cwd=work,
            environment=environment,
        )
        bound = pivot_child_bound_seconds(role)
        child_started = time.monotonic_ns()
        receipt = finish_command(running, timeout=bound)
        child_elapsed = (time.monotonic_ns() - child_started) / 1_000_000_000
        receipts[role] = receipt
        elapsed[role] = child_elapsed
        if receipt["exit_code"] == 124:
            outcomes[role] = "timeout"
            failures.append(
                f"pivot-server-{role}-timeout: bound_seconds={bound}, "
                f"elapsed_seconds={child_elapsed:.3f}"
            )
        elif receipt["exit_code"] != 0:
            outcomes[role] = "failed"
            failures.append(
                f"pivot-server-{role}-failed: exit_code={receipt['exit_code']}"
            )
        else:
            outcomes[role] = "passed"
    progress_artifacts = pivot_progress_receipt(output, outcomes)
    if failures:
        raise Refused("; ".join(failures))
    names = {role: values[1] for role, values in PIVOT_RUNS.items()}
    raw = {
        role: read_measurement_fields(output / f"{name}.tsv")
        for role, name in names.items()
    }
    denominator_attempts, denominator_branch, selected_denominator = (
        classify_denominator_attempts(
            measurement_denominator_attempts(raw["denominator"]), output
        )
    )
    validate_denominator_attempts(denominator_attempts)
    denominator_stalls = [
        {
            "rate": attempt["rate"],
            "bound_ns": attempt["cycle_stall_bound_ns"],
            "count": attempt["cycle_stall_count"],
            "durations_ns": attempt["cycle_stall_durations_ns"],
            "refusal_cycle_duration_ns": attempt["refusal_cycle_duration_ns"],
        }
        for attempt in denominator_attempts
    ]
    require(
        raw["denominator"].get("denominator_cycle_stall_issue") == "#832",
        "pivot-denominator-cycle-stall-issue",
    )
    samples = {}
    steadiness = {}
    for role in ("numerator", "diagnostic"):
        diagnostic_stalled = (
            role == "diagnostic" and raw[role].get("diagnostic_outcome") == "stalled"
        )
        sample_path = output / raw[role].get("samples_file", "")
        artifact_row = {
            "run_root": str(output),
            "sample_count": measurement_integer(
                raw[role], "sample_count", "pivot-sample-population"
            ),
            "pivot_durations_artifact": str(sample_path),
            "pivot_durations_artifact_sha256": digest(sample_path),
        }
        values = durations_artifact(artifact_row, output, "pivot_durations")
        required_samples = 368 if role == "diagnostic" else 1000
        require(
            len(values) < required_samples if diagnostic_stalled else len(values) == required_samples,
            "pivot-sample-population",
        )
        steady = (
            (None, None, None, None, None, "stalled")
            if diagnostic_stalled
            else steady_state(values, STEADY_STATE_TOLERANCE)
        )
        samples[role] = (values, artifact_row)
        steadiness[role] = steady
    if selected_denominator is not None:
        selected_attempt, values, artifact_row, completion_row = selected_denominator
        samples["denominator"] = (values, artifact_row)
        steadiness["denominator"] = (
            selected_attempt["steady_first_half_median_ns"],
            selected_attempt["steady_second_half_median_ns"],
            selected_attempt["steady_first_half_p99_ns"],
            selected_attempt["steady_second_half_p99_ns"],
            selected_attempt["steady_exceedance_splits"],
            selected_attempt["steady_state"],
        )
    numerator_unsteady = steadiness["numerator"][-1] == "not steady"
    root_sizes = {
        role: measurement_root_size_distribution(fields)
        for role, fields in raw.items()
    }
    diagnostic = raw["diagnostic"]
    diagnostic_live_roots = measurement_integer(
        diagnostic, "live_roots", "pivot-occupancy-observation"
    )
    require(
        diagnostic.get("root_label") == "707-B"
        and measurement_integer(
            diagnostic, "root_bytes", "pivot-occupancy-observation"
        )
        == 707
        and root_sizes["diagnostic"] == {"707": diagnostic_live_roots},
        "pivot-diagnostic-ceiling-root",
    )
    diagnostic_values, diagnostic_artifact = samples["diagnostic"]
    diagnostic_stalled = diagnostic.get("diagnostic_outcome") == "stalled"
    diagnostic_p99 = (
        None
        if diagnostic_stalled
        else sorted(diagnostic_values)[math.ceil(len(diagnostic_values) * 0.99) - 1]
    )
    diagnostic_interval = (
        None
        if diagnostic_stalled
        else list(quantile_interval(diagnostic_values, 0.99, 0.95))
    )
    publish_pilot = (
        {} if selected_denominator is None else selected_denominator[0]["pilot"]
    )
    completion_artifact = {}
    if denominator_branch != "terminal-inconclusive":
        completion_artifact = {
            "pivot_completion_artifact": completion_row[
                "pivot_completion_artifact"
            ],
            "pivot_completion_artifact_sha256": completion_row[
                "pivot_completion_artifact_sha256"
            ],
        }
    rows = []
    for role in ("numerator", "denominator"):
        terminal = role == "denominator" and denominator_branch == "terminal-inconclusive"
        if terminal:
            artifact = {
                "run_root": str(output),
                "sample_count": None,
                "pivot_durations_artifact": None,
                "pivot_durations_artifact_sha256": None,
            }
            p99 = None
            interval = None
        else:
            values, artifact = samples[role]
            ordered = sorted(values)
            p99 = ordered[989]
            interval = list(quantile_interval(values, 0.99, 0.95))
        source = raw[role]
        provenance = command_provenance(receipts[role], revision)
        numerator = role == "numerator"
        selected_attempt = None if numerator or terminal else selected_denominator[0]
        log_wait = (
            measurement_integer(
                source,
                "authority_log_wait_p99_ns",
                "pivot-log-wait-observation-missing",
            )
            if numerator
            else None
            if terminal
            else selected_attempt["authority_log_wait_p99_ns"]
        )
        if numerator:
            require(
                measurement_integer(source, "p99_ns", "pivot-p99-output-mismatch")
                == p99,
                "pivot-p99-output-mismatch",
            )
        steady = None if terminal else steadiness[role]
        pilot = publish_pilot if not numerator else {}
        expected_profile = "DurablePrepared" if numerator else "Published"
        expected_occupancy = "Ceiling" if numerator else "Floor"
        require(
            source.get("profile") == expected_profile
            and source.get("occupancy") == expected_occupancy,
            "pivot-pair-roles",
        )
        row = dict(
            pivot_role=role,
            load_model="open-loop",
            profile="durable-prepared" if numerator else "published",
            intent_occupancy="ceiling" if numerator else "floor",
            register_post_p99_ns=p99 if numerator else None,
            publish_decision_p99_ns=None if numerator else p99,
            cell_kind=(
                "refused" if terminal or numerator and numerator_unsteady else "steady"
            ),
            venue=environment["GRANARY_Q3_VENUE"],
            hardware=environment["GRANARY_Q3_VENUE"] != "vm",
            deciding=numerator and not numerator_unsteady and environment["GRANARY_Q3_VENUE"] != "vm",
            root_label=source["root_label"],
            root_bytes=measurement_integer(source, "root_bytes", "pivot-occupancy-observation"),
            root_size_distribution=root_sizes[role],
            row_holders=measurement_integer(source, "row_holders", "pivot-occupancy-observation"),
            zero_row_principals=measurement_integer(
                source, "zero_row_principals", "pivot-occupancy-observation"
            ),
            retired_principals=measurement_integer(
                source, "retired_principals", "pivot-occupancy-observation"
            ),
            historical_principals=measurement_integer(
                source, "historical_principals", "pivot-occupancy-observation"
            ),
            live_roots=measurement_integer(source, "live_roots", "pivot-occupancy-observation"),
            released_rows=measurement_integer(
                source, "released_rows", "pivot-occupancy-observation"
            ),
            offered_rate=(
                float(source["offered_rate"])
                if numerator
                else None
                if terminal
                else selected_attempt["rate"]
            ),
            achieved_rate=(
                float(source["achieved_rate"])
                if numerator
                else None
                if terminal
                else selected_attempt["achieved_rate"]
            ),
            committed_transitions=measurement_integer(
                source, "committed_transitions", "pivot-transition-count"
            ),
            stream_count=(
                None
                if terminal
                else measurement_integer(source, "stream_count", "pivot-stream-counts")
                if numerator
                else selected_attempt["pilot"]["stream_count"]
            ),
            stream_sample_counts=(
                None
                if terminal
                else measurement_stream_counts(source)
                if numerator
                else selected_attempt["stream_sample_counts"]
            ),
            principal_submission_limit=measurement_integer(
                source, "principal_submission_limit", "pivot-principal-limit"
            ),
            principal_in_flight_limit=measurement_integer(
                source, "principal_in_flight_limit", "pivot-principal-limit"
            ),
            per_stream_offered_rate=(
                float(source["per_stream_offered_rate"])
                if numerator
                else None
                if terminal
                else selected_attempt["rate"]
                / selected_attempt["pilot"]["stream_count"]
            ),
            pivot_branch=(denominator_branch if not numerator else None),
            pivot_verdict_branch=(
                "numerator-not-steady" if numerator_unsteady else "deciding-pair"
            ),
            pivot_venue_kind=(
                "podman-vm"
                if environment["GRANARY_Q3_VENUE"] == "vm"
                else environment["GRANARY_Q3_VENUE"]
            ),
            pivot_venue_note=PIVOT_VM_DECISION_NOTE,
            denominator_label=(
                None
                if numerator
                else "offered-rate denominator"
                if denominator_branch == "normal"
                else PIVOT_LOWER_BOUND_LABEL
                if denominator_branch == "lower-bound"
                else PIVOT_TERMINAL_LABEL
            ),
            denominator_attempts=(denominator_attempts if not numerator else None),
            denominator_cycle_stalls=(denominator_stalls if not numerator else None),
            denominator_cycle_stall_issue=(
                raw["denominator"].get("denominator_cycle_stall_issue")
                if not numerator
                else None
            ),
            pivot_stream_plan=source.get("pivot_stream_plan"),
            pivot_steady_first_half_median_ns=(None if terminal else steady[0]),
            pivot_steady_second_half_median_ns=(None if terminal else steady[1]),
            pivot_steady_first_half_p99_ns=(None if terminal else steady[2]),
            pivot_steady_second_half_p99_ns=(None if terminal else steady[3]),
            pivot_steady_exceedance_splits=(None if terminal else steady[4]),
            pivot_steady_exceedance_histograms=(
                pivot_exceedance_histograms(samples["numerator"][0], steady[4])
                if numerator and numerator_unsteady
                else None
            ),
            pivot_steady_state=(NOT_APPLICABLE if terminal else steady[-1]),
            pivot_steady_pattern=("other" if terminal else pivot_steady_pattern(steady)),
            pivot_warmup_count=(
                measurement_integer(source, "pivot_warmup_count", "pivot-warmup-observation")
                if numerator
                else None
                if terminal
                else selected_attempt["warmup_count"]
            ),
            pivot_warmup_elapsed_ns=(
                measurement_integer(
                    source, "pivot_warmup_elapsed_ns", "pivot-warmup-observation"
                )
                if numerator
                else None
                if terminal
                else selected_attempt["warmup_elapsed_ns"]
            ),
            publish_pilot_sample_count=pilot.get("sample_count"),
            publish_pilot_p50_ns=pilot.get("p50_ns"),
            publish_pilot_p99_ns=pilot.get("p99_ns"),
            publish_pilot_max_ns=pilot.get("max_ns"),
            publish_pilot_stream_count=pilot.get("stream_count"),
            medium=source["store_kind"],
            filesystem=source["log_filesystem"],
            wrapper_layer=source["wrapper_layer"],
            register_post_p99_interval_ns=interval if numerator else None,
            publish_decision_p99_interval_ns=None if numerator else interval,
            same_occupancy_publish_p99_ns=diagnostic_p99,
            same_occupancy_publish_p99_interval_ns=diagnostic_interval,
            authority_log_wait_p99_ns=log_wait,
            same_occupancy_publish_diagnostic=PIVOT_DIAGNOSTIC_LABEL,
            authority_log_wait_diagnostic=(
                "diagnostic only; LogGate wait is not wrapper publish duration"
            ),
            **{name: value for name, value in artifact.items() if name != "run_root"},
            **provenance,
            **(
                {
                    "pivot_completion_artifact": None,
                    "pivot_completion_artifact_sha256": None,
                }
                if terminal
                else completion_artifact
                if role == "denominator"
                else {}
            ),
        )
        if numerator:
            row.update(
                numerator_generation_range=measurement_range(
                    source.get("numerator_generation_range"), "pivot-numerator-generation-range"
                ),
                numerator_intent_log_bytes=measurement_integer(
                    source, "numerator_intent_log_bytes", "pivot-numerator-intent-log-length"
                ),
            )
        rows.append(row)
    diagnostic_source = raw["diagnostic"]
    require(
        diagnostic_source.get("load_model") == "closed-loop-serial"
        and diagnostic_source.get("pivot_input") == "false"
        and diagnostic_source.get("diagnostic_label") == PIVOT_DIAGNOSTIC_LABEL,
        "pivot-diagnostic-label",
    )
    require(
        measurement_integer(diagnostic_source, "p99_ns", "pivot-p99-output-mismatch")
        == (0 if diagnostic_stalled else diagnostic_p99),
        "pivot-p99-output-mismatch",
    )
    completion_stall_count = measurement_integer(
        diagnostic_source,
        "diagnostic_completion_stalls",
        "pivot-diagnostic-completion-stalls",
    )
    completion_stall_text = diagnostic_source.get("diagnostic_completion_stall_ns")
    require(
        isinstance(completion_stall_text, str) and completion_stall_text,
        "pivot-diagnostic-completion-stalls",
    )
    if completion_stall_text == "none":
        completion_stall_durations = []
    else:
        require(
            all(
                value.isascii() and value.isdigit()
                for value in completion_stall_text.split(",")
            ),
            "pivot-diagnostic-completion-stalls",
        )
        completion_stall_durations = [
            int(value) for value in completion_stall_text.split(",")
        ]
    publish_stall_count = measurement_integer(
        diagnostic_source,
        "diagnostic_publish_stalls",
        "pivot-diagnostic-publish-stalls",
    )
    publish_stall_text = diagnostic_source.get("diagnostic_publish_stall_ns")
    require(
        isinstance(publish_stall_text, str) and publish_stall_text,
        "pivot-diagnostic-publish-stalls",
    )
    if publish_stall_text == "none":
        publish_stall_durations = []
    else:
        require(
            all(
                value.isascii() and value.isdigit()
                for value in publish_stall_text.split(",")
            ),
            "pivot-diagnostic-publish-stalls",
        )
        publish_stall_durations = [
            int(value) for value in publish_stall_text.split(",")
        ]
    warmup_publish_stall_count = measurement_integer(
        diagnostic_source,
        "diagnostic_warmup_publish_stalls",
        "pivot-diagnostic-warmup-publish-stalls",
    )
    warmup_publish_stall_text = diagnostic_source.get(
        "diagnostic_warmup_publish_stall_ns"
    )
    require(
        isinstance(warmup_publish_stall_text, str) and warmup_publish_stall_text,
        "pivot-diagnostic-warmup-publish-stalls",
    )
    if warmup_publish_stall_text == "none":
        warmup_publish_stall_durations = []
    else:
        require(
            all(
                value.isascii() and value.isdigit()
                for value in warmup_publish_stall_text.split(",")
            ),
            "pivot-diagnostic-warmup-publish-stalls",
        )
        warmup_publish_stall_durations = [
            int(value) for value in warmup_publish_stall_text.split(",")
        ]
    diagnostic_row = dict(
        pivot_role="diagnostic",
        pivot_input=False,
        deciding=False,
        pivot_append=False,
        load_model="closed-loop-serial",
        diagnostic_label=PIVOT_DIAGNOSTIC_LABEL,
        profile="published",
        venue=environment["GRANARY_Q3_VENUE"],
        hardware=environment["GRANARY_Q3_VENUE"] != "vm",
        diagnostic_outcome=diagnostic_source.get("diagnostic_outcome"),
        diagnostic_completed_count=measurement_integer(
            diagnostic_source, "diagnostic_completed_count", "pivot-diagnostic-stall-state"
        ),
        diagnostic_stall_index=(
            None
            if diagnostic_source.get("diagnostic_stall_index") == "none"
            else measurement_integer(
                diagnostic_source, "diagnostic_stall_index", "pivot-diagnostic-stall-state"
            )
        ),
        diagnostic_stall_phase=(
            None
            if diagnostic_source.get("diagnostic_stall_phase") == "none"
            else diagnostic_source.get("diagnostic_stall_phase")
        ),
        pivot_steady_first_half_median_ns=steadiness["diagnostic"][0],
        pivot_steady_second_half_median_ns=steadiness["diagnostic"][1],
        pivot_steady_first_half_p99_ns=steadiness["diagnostic"][2],
        pivot_steady_second_half_p99_ns=steadiness["diagnostic"][3],
        pivot_steady_exceedance_splits=steadiness["diagnostic"][4],
        pivot_steady_state=steadiness["diagnostic"][-1],
        pivot_steady_pattern=(
            "other"
            if diagnostic_stalled
            else pivot_steady_pattern(steadiness["diagnostic"])
        ),
        pivot_steady_context="serial closed loop, one volume",
        pivot_steady_confound=CAUSE_NOT_ATTRIBUTED,
        diagnostic_depth_range=measurement_range(
            diagnostic_source.get("diagnostic_depth_range"), "pivot-diagnostic-depth-range"
        ),
        pivot_warmup_count=measurement_integer(
            diagnostic_source, "pivot_warmup_count", "pivot-warmup-observation"
        ),
        pivot_warmup_elapsed_ns=measurement_integer(
            diagnostic_source,
            "pivot_warmup_elapsed_ns",
            "pivot-warmup-observation",
        ),
        intent_occupancy="ceiling",
        same_occupancy_publish_p99_ns=diagnostic_p99,
        same_occupancy_publish_p99_interval_ns=diagnostic_interval,
        diagnostic_publish_bound_ns=measurement_integer(
            diagnostic_source,
            "diagnostic_publish_bound_ns",
            "pivot-diagnostic-censoring",
        ),
        diagnostic_publish_censored_count=measurement_integer(
            diagnostic_source,
            "diagnostic_publish_censored_count",
            "pivot-diagnostic-censoring",
        ),
        diagnostic_publish_p99_report=diagnostic_source.get(
            "diagnostic_publish_p99_report"
        ),
        diagnostic_publish_stalls=publish_stall_count,
        diagnostic_publish_stall_ns=publish_stall_durations,
        diagnostic_warmup_publish_stalls=warmup_publish_stall_count,
        diagnostic_warmup_publish_stall_ns=warmup_publish_stall_durations,
        diagnostic_completion_bound_ns=measurement_integer(
            diagnostic_source,
            "diagnostic_completion_bound_ns",
            "pivot-diagnostic-completion-stalls",
        ),
        diagnostic_completion_stalls=completion_stall_count,
        diagnostic_completion_stall_ns=completion_stall_durations,
        diagnostic_completion_stall_issue=diagnostic_source.get(
            "diagnostic_completion_stall_issue"
        ),
        authority_log_wait_p99_ns=(
            None
            if diagnostic_stalled
            and "authority_log_wait_p99_ns" not in diagnostic_source
            else measurement_integer(
                diagnostic_source,
                "authority_log_wait_p99_ns",
                "pivot-log-wait-observation-missing",
            )
        ),
        root_label=diagnostic_source["root_label"],
        root_bytes=measurement_integer(
            diagnostic_source, "root_bytes", "pivot-occupancy-observation"
        ),
        root_size_distribution=root_sizes["diagnostic"],
        row_holders=measurement_integer(
            diagnostic_source, "row_holders", "pivot-occupancy-observation"
        ),
        zero_row_principals=measurement_integer(
            diagnostic_source,
            "zero_row_principals",
            "pivot-occupancy-observation",
        ),
        historical_principals=measurement_integer(
            diagnostic_source,
            "historical_principals",
            "pivot-occupancy-observation",
        ),
        live_roots=diagnostic_live_roots,
        released_rows=measurement_integer(
            diagnostic_source, "released_rows", "pivot-occupancy-observation"
        ),
        stream_count=measurement_integer(
            diagnostic_source, "stream_count", "pivot-stream-counts"
        ),
        stream_sample_counts=(
            [len(diagnostic_values)]
            if diagnostic_stalled
            else measurement_stream_counts(diagnostic_source)
        ),
        medium=diagnostic_source["store_kind"],
        filesystem=diagnostic_source["log_filesystem"],
        wrapper_layer=diagnostic_source["wrapper_layer"],
        **{
            name: value
            for name, value in diagnostic_artifact.items()
            if name != "run_root"
        },
        **command_provenance(receipts["diagnostic"], revision),
    )
    validate_pivot_diagnostic(diagnostic_row)
    if numerator_unsteady:
        verdict = PIVOT_NUMERATOR_UNSTEADY
    elif denominator_branch == "normal":
        verdict = pivot_verdict(
            rows[0]["register_post_p99_interval_ns"],
            rows[1]["publish_decision_p99_interval_ns"],
        )
    elif denominator_branch == "lower-bound":
        verdict = lower_bound_pivot_verdict(
            rows[0]["register_post_p99_interval_ns"],
            rows[1]["publish_decision_p99_interval_ns"],
        )
    else:
        verdict = "inconclusive"
    scope = pivot_scope(rows[0], selected_denominator[0] if selected_denominator else None)
    for row in rows:
        row["pivot_verdict"] = verdict
        row["pivot_scope"] = scope
        row["pivot_append"] = verdict == "pivot" and row["venue"] != "vm"
    validate_pivot(rows)
    return dict(
        event="pivot",
        verdict=verdict,
        rows=rows,
        diagnostic=diagnostic_row,
        commands={role: receipt["command"] for role, receipt in receipts.items()},
        child_bound_seconds={role: pivot_child_bound_seconds(role) for role in PIVOT_RUNS},
        child_elapsed_seconds=elapsed,
        progress_artifacts=progress_artifacts,
    )


def reset_client_handoff(handoff, log_path, probe_index):
    """Retain server custody fields while preparing one restart child."""
    for path in handoff.iterdir():
        if path.name.startswith(("client-", "workload-", "runner-next-")) and path.name not in {
            "client-cert-path",
            "client-credential-path",
            "client-root-device",
            "client-root-path",
            "client-sync-profile",
        }:
            path.unlink()
    private_signal(handoff / "client-log-path", os.fsencode(log_path))
    private_signal(handoff / "client-probe-index", str(probe_index).encode("ascii"))


def recovery_operation_observations(
    profile, lose_image, initial_head, a_head, pre_loss_head, final_head, probe_operations
):
    """Derive both operation observations from the independently read heads."""
    return (
        observed_pre_loss_operations(profile, initial_head, a_head, pre_loss_head),
        observed_head_operations(
            profile, lose_image, pre_loss_head, final_head, probe_operations
        ),
    )


def run_recovery_outcome(
    server_child,
    client_child,
    gran,
    work,
    profile,
    lose_image,
    timeout=180,
    *,
    operation_fixture=None,
    pre_loss_observer=None,
    operation_observer=None,
):
    """Run one real mounted A/U crash and restart outcome."""
    pre_loss_observer = (
        observed_pre_loss_operations
        if pre_loss_observer is None
        else pre_loss_observer
    )
    operation_observer = (
        recovery_operation_observations
        if operation_observer is None
        else operation_observer
    )
    if operation_fixture is not None:
        initial_head, a_head, pre_loss_head, final_head, probe_operations = operation_fixture
        return operation_observer(
            profile,
            lose_image,
            initial_head,
            a_head,
            pre_loss_head,
            final_head,
            probe_operations,
        )
    work.mkdir(mode=0o700)
    client_root = work / "client"
    client_root.mkdir(mode=0o700)
    image = recovery_image(work)
    size = 4_294_967_296
    create_and_mount_recovery_image(image, client_root, size, cwd=work)
    handoff = work / "handoff"
    handoff.mkdir(mode=0o700)
    # The ledger lives in the outcome's work directory, outside the loop image
    # mounted at `client_root`, so the loss arm's image replacement keeps it.
    ledger_path = work / "recovery-ledger.jsonl"
    server_output = work / "server-observers.jsonl"
    server = client = None
    try:
        server = start_command(
            server_child_command(server_child, server_output, handoff, "127.0.0.1"),
            "server",
            cwd=work,
            environment=loopback_store_environment(),
        )
        wait_file(handoff / "ready", server, "server-handoff", timeout)
        private_signal(handoff / "client-workload-plan", b"0 0 2")
        private_signal(handoff / "client-unsynced-last")
        private_signal(handoff / "client-runner-gates-steps")
        private_signal(handoff / "client-sync-profile", profile.encode("ascii"))
        private_signal(handoff / "client-ledger-path", os.fsencode(ledger_path))
        client = start_command(client_child_command(client_child, handoff), "client", cwd=work)
        wait_file(handoff / "client-quiescent-before-start", client, "client-ready", timeout)
        initial_head, _ = prepublication_head(
            client_child, handoff, work, "initial-chain-head", timeout
        )
        private_signal(handoff / "client-go")
        wait_file(handoff / "client-step-quiescent-0", client, "recovery-a", timeout)
        a_head, _ = prepublication_head(
            client_child, handoff, work, "after-a-chain-head", timeout
        )
        private_signal(handoff / "runner-next-0")
        wait_file(handoff / "client-step-quiescent-1", client, "recovery-u", timeout)
        pre_loss_head, _ = prepublication_head(
            client_child, handoff, work, "pre-loss-chain-head", timeout
        )
        pre_loss_operations = pre_loss_observer(
            profile, initial_head, a_head, pre_loss_head
        )
        observed_ledger, observed_write_bytes, ledger_sha256 = read_workload_ledger(
            ledger_path
        )
        pre_loss_selection = (
            intent_selection(handoff)
            if lose_image and profile == "durable-prepared"
            else None
        )
        keys = [
            Path(handoff_text(handoff, name))
            for name in ("signing-seed-path", "client-cert-path", "client-credential-path")
        ]
        if lose_image:
            _, witness = replace_owned_client_image(
                client, image, client_root, size, keys, handoff, work
            )
        else:
            before_uuid = checked(
                ["blkid", "-s", "UUID", "-o", "value", str(image)],
                "intact-image-uuid",
                cwd=work,
            ).strip()
            before_inode = image.stat().st_ino
            before_keys = [digest(path) for path in keys]
            stop_client_and_detach_fuse(
                client, client_root / "root/mount", work
            )
            witness = dict(
                before_image_uuid=before_uuid,
                after_image_uuid=None,
                before_image_inode=before_inode,
                after_image_inode=image.stat().st_ino,
                signing_seed_survived=before_keys[0] == digest(keys[0]),
                certificate_survived=before_keys[1] == digest(keys[1]),
                credential_survived=before_keys[2] == digest(keys[2]),
            )
        client = None
        old_log = Path(handoff_text(handoff, "client-log-path"))
        old_log.rename(work / "client-before-loss.jsonl")
        started = time.monotonic_ns()
        actual_verbs = []
        if lose_image and profile == "durable-prepared":
            require(pre_loss_selection is not None, "recovery-intent-selection-invalid")
            actual_verbs = run_recovery_verbs(
                gran,
                client_child,
                handoff,
                work,
                pre_loss_selection,
                pre_loss_head["sequence"] + 1,
                timeout,
            )
        reset_client_handoff(handoff, work / "client-restart.jsonl", 0 if lose_image else 1)
        restarted = start_command(
            client_child_command(client_child, handoff), "client-restart", cwd=work
        )
        with owned_restarted_client(
            restarted, client_root / "root/mount", work
        ):
            wait_file(handoff / "client-probe-result", restarted, "client-probe", timeout)
            if not lose_image:
                witness["after_image_uuid"] = observe_intact_image_uuid(
                    image,
                    witness["before_image_uuid"],
                    work,
                )
            private_signal(handoff / "client-stop")
            restarted_record = finish_command(restarted, timeout=timeout)
        require(restarted_record["exit_code"] == 0, "recovery-client-failed")
        final_head, _ = chain_head_probe(
            client_child, handoff, work, "final-chain-head", timeout
        )
        final_status_path = work / "final-status.bin"
        final_status_head = head_probe(handoff, final_status_path, timeout)
        final_status_lag = observe_status_lag(
            final_head, final_status_head, "recovery-final-chain-status-mismatch"
        )
        probe_operations, probe_index, probe_bytes = recovery_content_probe(handoff)
        _, final_operations = operation_observer(
            profile,
            lose_image,
            initial_head,
            a_head,
            pre_loss_head,
            final_head,
            probe_operations,
        )
        witness.update(
            elapsed_ns=time.monotonic_ns() - started,
            final_max_seq=final_head["sequence"],
            final_head_id=final_head["identifier"],
            final_status_head=final_status_head,
            final_status_lag_seqs=final_status_lag,
            final_status_artifact=recovery_artifact(
                final_status_path,
                Path(work.name) / final_status_path.name,
            ),
            final_head_operations=final_operations,
            content_probe_index=probe_index,
            content_probe_bytes=probe_bytes,
            operator_verbs=actual_verbs,
            ledger=observed_ledger,
            cumulative_write_call_bytes=observed_write_bytes,
            ledger_artifact=str(Path(work.name) / ledger_path.name),
            ledger_artifact_sha256=ledger_sha256,
        )
        return (
            initial_head["sequence"],
            pre_loss_head["sequence"],
            pre_loss_operations,
            witness,
        )
    finally:
        abort_command(client, client_root / "root/mount")
        abort_command(server)
        run_command(
            ["umount", "-l", "--", str(client_root)],
            "recovery-image-cleanup",
            cwd=work,
            timeout=5,
        )


def run_recovery_pair(
    server_child,
    client_child,
    gran,
    work,
    profile,
    timeout=180,
    *,
    resource_check=None,
    outcome_runner=None,
):
    """Run the loss/intact images from the same deterministic A and U."""
    work = Path(work).resolve(strict=True)
    resource_check = resource_preflight_for_work if resource_check is None else resource_check
    resource_check(work)
    outcome_runner = run_recovery_outcome if outcome_runner is None else outcome_runner
    a_bytes = bytes([1]) * (4 * 1024 * 1024)
    u_bytes = (1).to_bytes(8, "big") + bytes(4096 - 8)
    expected_ledger = [
        {
            "operation_id": "a-0000",
            "content_sha256": hashlib.sha256(a_bytes).hexdigest(),
            "unique_content_bytes": len(a_bytes),
        }
    ]
    _, loss_seq, loss_head, loss = outcome_runner(
        server_child,
        client_child,
        gran,
        work / f"{profile}-loss",
        profile,
        True,
        timeout,
    )
    _, intact_seq, intact_head, intact = outcome_runner(
        server_child,
        client_child,
        gran,
        work / f"{profile}-intact",
        profile,
        False,
        timeout,
    )
    require(
        loss_seq == intact_seq and loss_head == intact_head,
        "recovery-pair-sequence-mismatch",
    )
    expected_write_bytes = len(a_bytes) + len(u_bytes)
    ledger, write_bytes = bind_recovery_ledgers(
        expected_ledger, expected_write_bytes, loss, intact
    )
    verbs = (
        ["gran recover selection", "gran recover takeover"]
        if profile == "durable-prepared"
        else []
    )
    pair = dict(
        profile=profile,
        ledger=ledger,
        cumulative_write_call_bytes=write_bytes,
        pre_loss_head_operations=loss_head,
        pre_loss_max_seq=loss_seq,
        sentinel={
            "operation_id": "u-0001",
            "content_sha256": hashlib.sha256(u_bytes).hexdigest(),
            "unique_content_bytes": len(u_bytes),
        },
        planned_operator_verbs=verbs,
        loss=loss,
        intact=intact,
        gap_operations=0 if profile == "published" else 1,
        gap_bytes=0 if profile == "published" else len(a_bytes),
        gap_label="observed RPO",
        recovery_label=(
            "observed recovery execution time (excludes detection and diagnosis; "
            "injection-to-verified-head)"
        ),
        recovery_start_event="loss-injection-complete",
        recovery_end_event="verified-head-after-restart",
        injection_scope=(
            "client process kill plus whole loop-image replacement; "
            "no power loss, no device fault"
        ),
        phase1_selection_artifact_sha256=(
            loss["operator_verbs"][0]["selection_artifact_sha256"]
            if profile == "durable-prepared"
            else None
        ),
    )
    validate_recovery_pair(pair, work)
    return {"event": "recovery-pair", "pair": pair, "artifact_root": str(work)}


def run_command(command, stem, *, cwd, timeout=35):
    """Run one owned child and retain its combined raw log and exit status."""
    return finish_command(
        start_command(command, stem, cwd=cwd), timeout=timeout
    )


def assemble_verdict(argv):
    parser = argparse.ArgumentParser(prog="q3-measurement.py assemble-verdict")
    for role in VERDICT_COMPONENTS:
        parser.add_argument(role, type=Path)
    for decision in VERDICT_POSITIONS:
        parser.add_argument(f"--decision-{decision}", nargs=2, required=True,
                            metavar=("POSITION", "RATIONALE"))
    args = parser.parse_args(argv)
    decisions = {decision: dict(zip(("position", "rationale"), getattr(args, f"decision_{decision}")))
                 for decision in VERDICT_POSITIONS}
    validate_verdict_decisions(decisions)
    references = {role: {"path": str(path.resolve()), "sha256": digest(path)}
                  for role in VERDICT_COMPONENTS for path in (getattr(args, role),)}
    document = dict(event="q3-verdict", sets_no_default=True, decisions=decisions, components=references)
    document.update(verdict_evidence(references, decisions))
    validate(document)
    print(json.dumps(document, sort_keys=True))
    return 0


def main():
    if sys.argv[1:2] == ["assemble-verdict"]:
        try:
            return assemble_verdict(sys.argv[2:])
        except (OSError, Refused) as error:
            print(json.dumps(dict(event="refused", reason=refusal_reason(error))), file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("--cross-volume-tsv", type=Path, help="import a cross-volume TSV")
    parser.add_argument("--loopback-smoke", action="store_true")
    parser.add_argument("--network-measurement", action="store_true")
    parser.add_argument("--pivot-measurement", action="store_true")
    parser.add_argument("--recovery-measurement", action="store_true")
    parser.add_argument("--work", type=Path)
    parser.add_argument("--server-child", type=Path)
    parser.add_argument("--client-child", type=Path)
    parser.add_argument("--gran", type=Path)
    args = parser.parse_args()
    try:
        require(
            args.manifest is None or args.cross_volume_tsv is None,
            "smoke-manifest-conflict",
        )
        if any(
            (
                args.loopback_smoke,
                args.network_measurement,
                args.pivot_measurement,
                args.recovery_measurement,
            )
        ):
            require(args.manifest is None and args.cross_volume_tsv is None, "smoke-manifest-conflict")
            require(
                sum(
                    (
                        args.loopback_smoke,
                        args.network_measurement,
                        args.pivot_measurement,
                        args.recovery_measurement,
                    )
                )
                == 1,
                "measurement-mode-conflict",
            )
            require(args.work is not None, "schema-missing: work")
            require(args.server_child is not None, "schema-missing: server-child")
            require(
                args.pivot_measurement or args.client_child is not None,
                "schema-missing: client-child",
            )
            require(
                not args.recovery_measurement or args.gran is not None,
                "schema-missing: gran",
            )
            work = new_work(args.work)
            if args.pivot_measurement:
                print(json.dumps(run_pivot_measurement(args.server_child, work), sort_keys=True))
                return 0
            if args.recovery_measurement:
                for profile in ("durable-prepared", "published"):
                    print(
                        json.dumps(
                            run_recovery_pair(
                                args.server_child,
                                args.client_child,
                                args.gran,
                                work,
                                profile,
                            ),
                            sort_keys=True,
                        )
                    )
                return 0
            if args.network_measurement:
                measurement = run_network_measurement(args.server_child, args.client_child, work)
                results = measurement["cells"]
                for result in results:
                    print(json.dumps(cell_record(result), sort_keys=True))
                for calibration in measurement["calibrations"]:
                    print(json.dumps(calibration, sort_keys=True))
                samples = sum(len(result["summary"]["durations_ns"]) for result in results)
                uid = results[0]["uid"]
            else:
                result = run_loopback_smoke(args.server_child, args.client_child, work)
                samples, uid = result["cell_population"], result["uid"]
            print(
                json.dumps(
                    dict(
                        event="counts",
                        samples=samples,
                        uid=uid,
                    )
                )
            )
            return 0
        require(args.manifest is not None or args.cross_volume_tsv is not None, "schema-missing: manifest")
        require(
            args.work is None
            and args.server_child is None
            and args.client_child is None
            and args.gran is None
            and not args.network_measurement,
            "smoke-option-without-mode",
        )
        if args.cross_volume_tsv is not None:
            print(json.dumps(cross_volume_document(args.cross_volume_tsv), sort_keys=True))
            return 0
        try:
            document = json.loads(
                args.manifest.read_text(encoding="utf-8"),
                object_pairs_hook=unique_object,
            )
        except Refused:
            raise
        except (OSError, UnicodeError, ValueError) as error:
            raise Refused("manifest-unreadable") from error
        observed = validate(document)
        print(json.dumps(dict(event="counts", samples=observed)))
        return 0
    except (OSError, Refused) as error:
        try:
            sys.stdout.flush()
        except OSError:
            pass
        print(
            json.dumps(dict(event="refused", reason=refusal_reason(error))),
            file=sys.stderr,
            flush=True,
        )
        return 1


if __name__ == "__main__":
    sys.exit(reap_firewall() if sys.argv[1:] == ["--reap-firewall"] else main())
