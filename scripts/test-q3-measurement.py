#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Paired, socket-free controls for the Q3 measurement parser."""

from fractions import Fraction
import copy
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "q3_measurement", Path(__file__).with_name("q3-measurement.py")
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


FIXTURE_CERTIFICATE = (
    "MIIBXTCCAQSgAwIBAgIUJErYJkRwRuN2EEEP3/rGem+fWvEwCgYIKoZIzj0EAwIwFTETMBEGA1UE"
    "AwwKcTMtZml4dHVyZTAeFw0yNjExMTUyMzQ1MTVaFw0zNjExMTIyMzQ1MTVaMBUxEzARBgNVBAMM"
    "CnEzLWZpeHR1cmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASjNgjINi2iLULlUrGYh5fjk+6q"
    "K8PpaqyWYd41SoyRo7669iXkPVy33QCAr6FOGvRfjkday27012njA6HIBUVnozIwMDAdBgNVHQ4E"
    "FgQUIKZJcajc+6q3+vbkZMW3RJYPwukwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBE"
    "AiA9o//GZcCbEnWhguRBTmaydYJ5Sj4wEDRE8zroqOu4qwIgeXUkOj0dWZxxWhas89QS3PFrx0Zf"
    "yNWcEYFwgG9j6pA="
)


# The Rust export control hashes the full depth trace.
PIVOT_DEPTH_EXPORT = """denominator_attempt_depth_bounds	0,16
depth_trace_sha256	65fa0cba76c8c835251898b08226c76434479dc0267c45002a85e2834c751a75
diagnostic_depth_range	64,431
numerator_generation_range	2,68
numerator_intent_log_bytes	123456
"""


def denominator_depth_fixture(count, warmups=64):
    records = [
        [index, index % 64, "warmup" if index < warmups else "measured", index // 64]
        for index in range(warmups + count)
    ]
    return dict(depth_records=records, depth_bounds=[0, records[-1][3]])


def denominator_refusal_timing(count, rate):
    spacing = math.ceil(1_000_000_000 / rate)
    warmups = runner.PIVOT_WARMUP_COUNT
    ends = [(warmups + index) * spacing + 13_000_000 for index in range(count)]
    ends[-1] = (warmups + count - 1) * spacing + 450_000_000
    return dict(cycle_ends_ns=[ends, [ends[-1]]],
                time_to_first_refusal_ns=(warmups + count) * spacing)


class Q3Controls(unittest.TestCase):
    @staticmethod
    def write_duration_fixture(path, durations):
        pairs = sorted((duration, index) for index, duration in enumerate(durations))
        path.write_text("".join(f"{duration}\t{index}\n" for duration, index in pairs))

    def mounted_server_fixture(self, row):
        path = Path(row["run_root"]) / "server-observers.jsonl"
        envelope = dict(schema="granary.q3.server.v2", **{"pass": "serve"})
        profile = row["profile"]
        marker = f"q3-mark-{profile}-rtt-{row['configured_rtt_ms']}"
        population = row["sample_count"] + row["warmup_count"] + 3
        growth = population if profile == "published" else 0
        raw = [
            dict(envelope, kind="durability", sample_loss=0, intent_logical_commits=population - growth,
                 intent_file_barriers=population - growth, intent_dir_barriers=population - growth,
                 decision_log_appends=2 * growth, decision_file_barriers=2 * growth, decision_dir_barriers=0),
            dict(envelope, kind="landed_window", sample_loss=0, before_max_seq=1,
                 after_max_seq=growth + 1, final_depth=growth + 1, chain_growth=growth,
                 elapsed_ns=1_000_000_000, intervening_roots_readable=True),
            dict(envelope, kind="http_attempt", arrival_seq=1, request_id=marker + "-start"),
            dict(envelope, kind="http_attempt", arrival_seq=sum(row["route_attempts"].values()) + 2,
                 request_id=marker + "-end"),
        ]
        for route_key, count in row["route_attempts"].items():
            method, route = route_key.split(" ", 1)
            for index in range(count):
                publish = route == "/volume/:volume/publish"
                raw.append(dict(envelope, kind="http_attempt", arrival_seq=len(raw) - 2, method=method,
                                route=route, request_id=f"publish-{index % population}" if publish else f"op-{len(raw)}",
                                outcome="success", duration_ns=30 if publish and index >= population - 8 else 20))

        def seal(items):
            path.write_text("".join(json.dumps(item) + "\n" for item in items))
            row["server_observers_sha256"] = runner.digest(path)

        seal(raw)
        row["server_metrics"] = runner.mounted_server_metrics(row)
        return raw, seal

    def mounted_metrics_controls(self, document):
        document = copy.deepcopy(document)
        row = next(row for row in document["samples"] if row["profile"] == "published")
        path = Path(row["run_root"]) / "server-observers.jsonl"
        raw, seal = self.mounted_server_fixture(row)
        self.assertEqual(runner.validate(document), 6)
        self.assertEqual(row["server_metrics"]["control_writes_per_fsync"]["decision_log_appends"], 2)
        self.assertEqual(row["server_metrics"]["chain"]["roots_per_second"], 1035)
        self.assertEqual(row["server_metrics"]["cas_p99_ns"], 20)
        publish = [index for index, item in enumerate(raw) if item.get("route") == "/volume/:volume/publish"]
        self.assertEqual((len(publish), raw[publish[-3]]["request_id"], raw[publish[0]]["request_id"]),
                         (1038, "publish-0", "publish-0"))
        for index, change, reason in (
            (0, {"pass": "measurement"}, "server-observers-schema"),
            (0, {"decision_log_appends": 0}, "verdict-missing-control-writes"),
            (0, {"sample_loss": False}, "verdict-missing-control-writes"),
            (0, {"sample_loss": 1}, "verdict-missing-control-writes"),
            (1, {"chain_growth": 1034}, "verdict-missing-chain-growth"),
            (1, {"sample_loss": False}, "verdict-missing-chain-growth"),
            (1, {"sample_loss": 1}, "verdict-missing-chain-growth"),
            (2, {"request_id": "wrong"}, "server-observers-markers"),
            (2, None, "server-observers-markers"),
            (3, {"arrival_seq": "1039"}, "server-observers-markers"),
            (4, {"route": "/unexpected"}, "verdict-missing-round-trips"),
            (publish[0], {"duration_ns": 0}, "verdict-missing-cas-latency"),
        ):
            changed = raw.copy()
            changed[index] = dict(raw[index], **(change or {}))
            if change is None:
                changed[index].pop("arrival_seq")
            seal(changed)
            with self.subTest(index=index, change=change), self.assertRaisesRegex(runner.Refused, f"^{reason}$"):
                runner.validate(document)
        seal(raw)
        path.write_bytes(b" " + path.read_bytes())
        with self.assertRaisesRegex(runner.Refused, "^server-observers-hash-mismatch$"):
            runner.validate(document)
        seal(raw)
        row["server_metrics"]["cas_p99_ns"] = 21
        with self.assertRaisesRegex(runner.Refused, "^server-metrics-mismatch$"):
            runner.validate(document)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="q3-schema-")
        root = Path(self.temporary.name).resolve()
        self.log = root / "cell.log"
        self.rc = root / "cell.rc"
        self.durations = root / "cell.durations.ns"
        self.log.write_text("fixture output\n")
        self.rc.write_text("0\n")
        self.write_duration_fixture(self.durations, [1] + [2] * 998 + [4])

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self):
        def digest(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()

        rows = []
        for rtt in (0, 10, 50):
            rows.append(
                dict(
                    profile="durable-prepared",
                    workload="4k-overwrite",
                    offered_rate=23,
                    achieved_rate=23,
                    scale=dict(volumes=1, principals=1, root_depth=1),
                    rtt_ms=rtt,
                    rtt_group="calibration-a",
                    network_path="dedicated-veth",
                    medium="ssd",
                    filesystem="ext4",
                    sample_count=1000,
                    sample_loss=0,
                    command=["granary-q3-child", "--cell", str(rtt)],
                    revision="0123456789abcdef0123456789abcdef01234567",
                    date="2026-11-14T12:00:00Z",
                    host="fixture-host",
                    kernel="6.12.0",
                    cpu="fixture-cpu",
                    memory_bytes=17179869184,
                    run_root=str(self.log.parent),
                    raw_log=str(self.log),
                    raw_rc=str(self.rc),
                    raw_log_sha256=digest(self.log),
                    raw_rc_sha256=digest(self.rc),
                    venue="linux-ci",
                    hardware=False,
                    exit_code=0,
                    m15_delta=0,
                    m15_fallback_delta=1,
                    m15_reuse_delta=0,
                    warmup_count=32,
                    tid=654,
                    configured_rtt_ms=rtt,
                    observed_rtt_pre_ms=rtt,
                    observed_rtt_post_ms=rtt,
                    observed_rtt_ms=rtt,
                    calibration_outcome="calibrated",
                    calibration_reason=None,
                    fsync_min_ns=1,
                    fsync_p50_ns=2,
                    fsync_p90_ns=2,
                    fsync_p99_ns=2,
                    fsync_max_ns=4,
                    steady_state_tolerance=0.10,
                    steady_first_half_median_ns=2,
                    steady_second_half_median_ns=2,
                    steady_first_half_p99_ns=2,
                    steady_second_half_p99_ns=2,
                    steady_exceedance_splits=[
                        {
                            "population": 1000,
                            "quantile": percentile,
                            "threshold_ns": 2,
                            "exceedances": 1,
                            "critical_count": 2,
                            "split": [0, 1],
                            "tail_probability": "0/1",
                        }
                        for percentile in (95, 99)
                    ],
                    steady_state="steady",
                    durations_artifact=str(self.durations),
                    durations_artifact_sha256=digest(self.durations),
                    register_attempts=1000,
                    register_repeated_arrivals=0,
                    background_attempts=0,
                    route_attempts={"POST /volume/:volume/intent": 1000},
                    attempt_count_source="server-counted",
                    operation_kind_source="client-attested",
                    netem_preflight=True,
                    netem_delay_placement="client-veth-egress",
                    offload_state={
                        "host": {"tso": False, "gso": False, "gro": False},
                        "client": {"tso": False, "gso": False, "gro": False},
                    },
                    pivot_durations_artifact=None,
                    pivot_durations_artifact_sha256=None,
                    venue_backing="virtio block device through container bind mount",
                    venue_cache_mode="unobservable inside the container",
                    venue_text=(
                        "VM venue; kernel timer granularity limits short netem delays; "
                        "the VM cannot describe host storage cache"
                    ),
                    deciding=True,
                    verdict_metrics=[
                        "wall_clock_ms",
                        "rtt",
                        "control_writes",
                        "cas",
                        "chain_growth",
                        "recovery_gap",
                    ],
                    root_label="707-B",
                    root_bytes=707,
                    historical_kind="in-format",
                    pivot_input=False,
                    pivot_group=None,
                    pivot_role=None,
                    pivot_append=False,
                    cell_kind="steady",
                    load_model="open-loop",
                    sample_floor=1000,
                    intent_occupancy=runner.NOT_APPLICABLE,
                    wrapper_layer=runner.NOT_APPLICABLE,
                    row_holders=None,
                    zero_row_principals=None,
                    retired_principals=None,
                    historical_principals=None,
                    live_roots=None,
                    released_rows=None,
                    written_bytes=None,
                    encode_register_bytes=None,
                    full_snapshot_bytes=None,
                    device_bytes=runner.UNMEASURED,
                    register_post_p99_ns=None,
                    publish_decision_p99_ns=None,
                    same_occupancy_publish_p99_ns=None,
                    authority_log_wait_p99_ns=runner.UNMEASURED,
                    cross_volume_blocked_ns=runner.NOT_APPLICABLE,
                    device_amplification=None,
                )
            )
        return {"samples": rows}

    @staticmethod
    def rtt_cells(fsync_medians_ms):
        routes = {
            "PUT /other": 5185,
            "GET /other": 4171,
            "POST /volume/:volume/intent": 1038,
            "one-off requests": 5,
        }
        cells = []
        for configured, observed, fsync_ms in zip(
            (0, 10, 50), (0.1, 11.8, 53.0), fsync_medians_ms
        ):
            cells.append(
                dict(
                    profile="durable-prepared",
                    configured_rtt_ms=configured,
                    observed_rtt_pre_ms=observed,
                    observed_rtt_post_ms=observed,
                    observed_rtt_ms=observed,
                    steady_state="steady",
                    summary=dict(
                        durations_ns=[round(fsync_ms * 1_000_000)] * 1000,
                        register_chain_head_seq=7,
                        rtt_band_attempts=[1035] * 10,
                        successful_fsyncs=1035,
                        register_attempts=1035,
                        register_repeated_arrivals=0,
                        route_attempts=dict(routes),
                    ),
                )
            )
        return cells

    def pair(self, label, reason, malformed, valid=None):
        good = self.fixture()
        if valid:
            valid(good)
        observed = runner.validate(good)
        self.assertGreater(observed, 0)
        bad = self.fixture()
        malformed(bad)
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(bad)
        self.assertEqual(str(caught.exception), reason)
        print(f"CONTROL {label}: observed={observed} refused={caught.exception}")

    def set_population(self, document, count, kind):
        path = Path(self.temporary.name) / f"{kind}-{count}.ns"
        self.write_duration_fixture(path, [2] * count)
        row = document["samples"][0]
        row.update(
            cell_kind=kind,
            sample_count=count,
            sample_floor=count,
            durations_artifact=str(path),
            durations_artifact_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            fsync_min_ns=2,
            fsync_p50_ns=2,
            fsync_p90_ns=2,
            fsync_p99_ns=2,
            fsync_max_ns=2,
            steady_first_half_median_ns=None,
            steady_second_half_median_ns=None,
            steady_first_half_p99_ns=None,
            steady_second_half_p99_ns=None,
            steady_exceedance_splits=None,
            steady_state=runner.NOT_APPLICABLE,
        )

    @staticmethod
    def published_row(row):
        row.pop("register_attempts")
        row.pop("register_repeated_arrivals")
        row.pop("background_attempts")
        row.update(
            profile="published",
            successful_fsyncs=1035,
            logical_publishes=1035,
            publish_attempts=1035,
            request_correlation="not request-correlated",
            strace_reconciled=True,
            route_attempts={"POST /volume/:volume/publish": 1035},
        )

    @classmethod
    def published_rows(cls, document):
        for row in document["samples"]:
            cls.published_row(row)

    @staticmethod
    def loopback_row(document, index, path="loopback"):
        row = document["samples"][index]
        row["network_path"] = path
        row.pop("netem_preflight", None)
        row["netem_delay_placement"] = runner.NOT_APPLICABLE
        row["offload_state"] = None

    def pivot_pair(self, doc, numerator_ns=81_000_000, denominator_ns=40_000_000):
        numerator, denominator = doc["samples"][:2]
        self.intent_row(numerator)
        self.intent_row(denominator)
        numerator.update(
            profile="durable-prepared",
            intent_occupancy="ceiling",
            load_model="open-loop",
            offered_rate=46,
            pivot_input=True,
            pivot_group="pivot-a",
            pivot_role="numerator",
            pivot_append=True,
            register_post_p99_ns=numerator_ns,
            row_holders=16,
            zero_row_principals=16_368,
            retired_principals=0,
            historical_principals=16_384,
            live_roots=256,
            released_rows=768,
            root_size_distribution={"707": 256},
            committed_transitions=numerator["sample_count"] + runner.PIVOT_WARMUP_COUNT,
            pivot_warmup_count=runner.PIVOT_WARMUP_COUNT,
            pivot_warmup_elapsed_ns=1_391_304_352,
            stream_count=16,
            stream_sample_counts=[63] * 8 + [62] * 8,
            principal_submission_limit=1_000_000,
            principal_in_flight_limit=4,
            per_stream_offered_rate=46 / 16,
            pivot_verdict_branch="deciding-pair",
            pivot_venue_kind="linux-ci",
            pivot_venue_note=runner.PIVOT_VM_DECISION_NOTE,
            pivot_steady_exceedance_histograms=None,
            pivot_stream_plan=runner.PIVOT_STREAM_PLAN,
            medium="AmazonS3(fixture)",
        )
        denominator.update(
            profile="published",
            intent_occupancy="floor",
            load_model="open-loop",
            offered_rate=46,
            pivot_input=True,
            pivot_group="pivot-a",
            pivot_role="denominator",
            pivot_append=True,
            publish_decision_p99_ns=denominator_ns,
            row_holders=1,
            zero_row_principals=0,
            retired_principals=0,
            historical_principals=1,
            live_roots=16,
            released_rows=48,
            root_label="measured length",
            root_bytes=652,
            root_size_distribution={"652": 16},
            committed_transitions=0,
            pivot_warmup_count=runner.PIVOT_WARMUP_COUNT,
            pivot_warmup_elapsed_ns=1_391_304_352,
            stream_count=64,
            stream_sample_counts=[16] * 40 + [15] * 24,
            principal_submission_limit=1_000_000,
            principal_in_flight_limit=4,
            per_stream_offered_rate=46 / 64,
            pivot_branch="normal",
            pivot_verdict_branch="deciding-pair",
            pivot_venue_kind="linux-ci",
            pivot_venue_note=runner.PIVOT_VM_DECISION_NOTE,
            pivot_steady_exceedance_histograms=None,
            denominator_label="offered-rate denominator",
            denominator_attempts=[
                dict(
                    rate=46.0,
                    warmup_count=runner.PIVOT_WARMUP_COUNT,
                    warmup_elapsed_ns=1_391_304_352,
                    outcome="passed",
                    sent_count=1000,
                    time_to_first_refusal_ns=0,
                    conflict_token_counts={},
                    response_token_counts={},
                    rate_limited_count=0,
                    max_outstanding=4,
                    max_outstanding_per_stream=[1] * 64,
                    pilot_p99_ns=40_000_000,
                    cycle_stall_bound_ns=400_000_000,
                    cycle_stall_count=1,
                    cycle_stall_durations_ns=[450_000_000],
                    refusal_cycle_duration_ns=None,
                    drain_note=None,
                    cycle_ends_ns=None,
                )
            ],
            denominator_cycle_stalls=[
                {
                    "rate": 46.0,
                    "bound_ns": 400_000_000,
                    "count": 1,
                    "durations_ns": [450_000_000],
                    "refusal_cycle_duration_ns": None,
                }
            ],
            denominator_cycle_stall_issue="#832",
            publish_pilot_sample_count=32,
            publish_pilot_p50_ns=20_000_000,
            publish_pilot_p99_ns=40_000_000,
            publish_pilot_max_ns=45_000_000,
            publish_pilot_stream_count=64,
            pivot_stream_plan=runner.PIVOT_STREAM_PLAN,
            medium="AmazonS3(fixture)",
        )
        self.published_row(denominator)
        def pivot_artifact(row, role, value):
            samples = (
                [value - 1] * 494
                + [value] * 4
                + [value + 1] * 2
                + [value - 1] * 495
                + [value] * 3
                + [value + 1] * 2
            )
            path = Path(self.temporary.name) / f"pivot-{role}-{value}.ns"
            self.write_duration_fixture(path, samples)
            row["pivot_durations_artifact"] = str(path)
            row["pivot_durations_artifact_sha256"] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            steady = runner.steady_state(samples, runner.STEADY_STATE_TOLERANCE)
            row.update(
                pivot_steady_first_half_median_ns=steady[0],
                pivot_steady_second_half_median_ns=steady[1],
                pivot_steady_first_half_p99_ns=steady[2],
                pivot_steady_second_half_p99_ns=steady[3],
                pivot_steady_exceedance_splits=steady[4],
                pivot_steady_state=steady[-1],
                pivot_steady_pattern=runner.pivot_steady_pattern(steady),
            )
            return list(runner.quantile_interval(samples, 0.99, 0.95))

        numerator_interval = pivot_artifact(numerator, "numerator", numerator_ns)
        denominator_interval = pivot_artifact(denominator, "denominator", denominator_ns)
        completion_path = Path(self.temporary.name) / "pivot-denominator-completion.ns"
        self.write_duration_fixture(completion_path, [3_000_000] * 1000)
        denominator["pivot_completion_artifact"] = str(completion_path)
        denominator["pivot_completion_artifact_sha256"] = hashlib.sha256(
            completion_path.read_bytes()
        ).hexdigest()
        attempt = denominator["denominator_attempts"][0]
        attempt.update(
            **denominator_depth_fixture(1000),
            achieved_rate=46.0,
            stream_sample_counts=denominator["stream_sample_counts"],
            sample_file=Path(denominator["pivot_durations_artifact"]).name,
            sample_count=1000,
            completion_file=completion_path.name,
            completion_count=1000,
            authority_log_wait_p99_ns=1_000,
            pilot={
                "sample_count": 32,
                "p50_ns": 20_000_000,
                "p99_ns": 40_000_000,
                "max_ns": 45_000_000,
                "stream_count": 64,
            },
            guards_passed=True,
            sample_artifact=denominator["pivot_durations_artifact"],
            sample_artifact_sha256=denominator["pivot_durations_artifact_sha256"],
            completion_artifact=str(completion_path),
            completion_artifact_sha256=denominator[
                "pivot_completion_artifact_sha256"
            ],
            steady_first_half_median_ns=denominator[
                "pivot_steady_first_half_median_ns"
            ],
            steady_second_half_median_ns=denominator[
                "pivot_steady_second_half_median_ns"
            ],
            steady_first_half_p99_ns=denominator["pivot_steady_first_half_p99_ns"],
            steady_second_half_p99_ns=denominator[
                "pivot_steady_second_half_p99_ns"
            ],
            steady_exceedance_splits=denominator[
                "pivot_steady_exceedance_splits"
            ],
            steady_state=denominator["pivot_steady_state"],
            steady_pattern=denominator["pivot_steady_pattern"],
        )
        numerator.update(numerator_generation_range=[2, 68], numerator_intent_log_bytes=123456)
        scope = runner.pivot_scope(numerator, attempt)
        verdict = runner.pivot_verdict(numerator_interval, denominator_interval)
        for row in (numerator, denominator):
            row.update(
                achieved_rate=46,
                pivot_append=verdict == "pivot",
                pivot_verdict=verdict,
                pivot_scope=scope,
                register_post_p99_interval_ns=numerator_interval,
                publish_decision_p99_interval_ns=denominator_interval,
                same_occupancy_publish_p99_interval_ns=denominator_interval,
                same_occupancy_publish_diagnostic=runner.PIVOT_DIAGNOSTIC_LABEL,
                authority_log_wait_diagnostic=(
                    "diagnostic only; LogGate wait is not wrapper publish duration"
                ),
            )

    def closed_loop_pivot(self, doc):
        self.pivot_pair(doc)
        for row in doc["samples"][:2]:
            row.update(load_model="closed-loop", offered_rate=None)

    @staticmethod
    def intent_row(row):
        row.update(
            intent_occupancy="p1",
            wrapper_layer="server-service",
            load_model="closed-loop",
            offered_rate=None,
            row_holders=1,
            zero_row_principals=0,
            retired_principals=0,
            historical_principals=1,
            live_roots=16,
            root_size_distribution={"707": 16},
            released_rows=48,
            written_bytes=1000,
            encode_register_bytes=800,
            full_snapshot_bytes=1000,
            device_bytes=runner.UNMEASURED,
            register_post_p99_ns=10_000_000,
            publish_decision_p99_ns=5_000_000,
            same_occupancy_publish_p99_ns=7_000_000,
            authority_log_wait_p99_ns=runner.UNMEASURED,
            cross_volume_blocked_ns=runner.NOT_APPLICABLE,
            device_amplification=None,
        )

    def intent_document(self, document, **changes):
        row = document["samples"][0]
        self.intent_row(row)
        row.update(changes)

    def test_typed_documents_refuse_null_and_missing_members(self):
        pivot = {
            "event": "pivot",
            "verdict": "inconclusive",
            "rows": [],
            "diagnostic": {},
            "commands": {},
            "child_bound_seconds": {},
            "child_elapsed_seconds": {},
            "progress_artifacts": {},
        }
        recovery = {"event": "recovery-pair", "pair": {}, "artifact_root": "/tmp"}
        cases = (
            (dict(pivot, rows=None), "pivot-document-rows-invalid"),
            (dict(pivot, diagnostic=None), "pivot-document-diagnostic-invalid"),
            ({key: value for key, value in pivot.items() if key != "rows"}, "schema-unknown: pivot"),
            (
                {key: value for key, value in pivot.items() if key != "diagnostic"},
                "schema-unknown: pivot",
            ),
            (dict(recovery, pair=None), "recovery-pair-type-invalid"),
            (dict(recovery, artifact_root=None), "recovery-artifact-root-invalid"),
            (
                {key: value for key, value in recovery.items() if key != "pair"},
                "schema-unknown: recovery-pair",
            ),
            (
                {key: value for key, value in recovery.items() if key != "artifact_root"},
                "schema-unknown: recovery-pair",
            ),
        )
        for document, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate(document)
                self.assertEqual(str(caught.exception), reason)

    def test_continuation_45_required_sweep_controls(self):
        for document, reason in (
            ([], "schema-document-not-object"),
            ({"samples": [], "extra": True}, "schema-unknown: document"),
            ({"samples": []}, "zero-cases"),
        ):
            with self.assertRaises(runner.Refused) as caught:
                runner.validate(document)
            self.assertEqual(str(caught.exception), reason)
        with (
            patch.object(runner, "validate_recovery_pair") as nested,
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.validate({"event": "recovery-pair", "pair": None, "artifact_root": "/tmp"})
        self.assertEqual(str(caught.exception), "recovery-pair-type-invalid")
        nested.assert_not_called()
        loopback = [
            {"rtt_group": "g", "network_path": "loopback", "configured_rtt_ms": value,
             "calibration_outcome": "calibrated", "calibration_reason": None}
            for value in (10, 50)
        ]
        with (
            patch.object(runner, "validate_row"),
            patch.object(runner, "validate_observed_rtts"),
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.validate({"samples": loopback})
        self.assertEqual(str(caught.exception), "rtt-loopback-only")
        root = Path(self.temporary.name)
        images = [root / f"loop-{index}.img" for index in range(3)]
        devices = [f"/dev/loop{index}" for index in range(3)]
        environment = {
            "GRANARY_Q3_LOOP_DEVICES": ",".join(devices),
            "GRANARY_Q3_LOOP_IMAGES": ",".join(map(str, images)),
        }
        for malformed in (
            {"GRANARY_Q3_LOOP_DEVICES": environment["GRANARY_Q3_LOOP_DEVICES"]},
            dict(environment, GRANARY_Q3_LOOP_DEVICES="/dev/loop0"),
            dict(environment, GRANARY_Q3_LOOP_DEVICES="bad," + ",".join(devices[1:])),
        ):
            with self.assertRaises(runner.Refused) as caught:
                runner.venue_loop_pairs(malformed)
            self.assertEqual(str(caught.exception), "loop-device-invalid")
        for image in images[:2]:
            image.write_bytes(b"image")
        for image in (images[-1], images[1]):
            if image.exists():
                image.unlink()
            current = images[-1] if image == images[-1] else images[0]
            with self.assertRaises(runner.Refused) as caught:
                runner.replacement_image(current, environment)
            self.assertEqual(str(caught.exception), "loop-image-exhausted")

    def test_marker_server_pin_pair(self):
        import base64
        der = base64.b64decode("".join(FIXTURE_CERTIFICATE))
        # Expected digest computed independently by OpenSSL from the same certificate.
        self.assertEqual(
            runner.spki_sha256(der),
            "477e6bf36ea2ac22aab562ca2088695d7e78c3d3f46d5c14e8a62279f56673e0",
        )
        for label, broken in (("truncated", der[:-40]), ("not-a-sequence", b"\x04" + der[1:])):
            with self.assertRaises(runner.Refused) as caught:
                runner.spki_sha256(broken)
            self.assertEqual(str(caught.exception), "server-certificate-malformed")
            print(f"CONTROL marker certificate {label}: refused={caught.exception}")
        with patch.object(runner, "authority_request", side_effect=[(204, b""), (500, b"")]):
            runner.marker_request(self.log.parent, "fixture", "start")
            with self.assertRaisesRegex(runner.Refused, "^server-window-marker-refused$"):
                runner.marker_request(self.log.parent, "fixture", "end")

    def test_schema_and_refusal_pairs(self):
        def invalid_rc(doc):
            path = self.rc.with_name("invalid.rc")
            path.write_text("not an exit status\n")
            row = doc["samples"][0]
            row["raw_rc"] = str(path)
            row["raw_rc_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

        for field in (
            "profile workload load_model offered_rate achieved_rate scale rtt_ms rtt_group network_path medium filesystem "
            "sample_count sample_loss command revision date host kernel cpu memory_bytes raw_log raw_rc "
            "raw_log_sha256 raw_rc_sha256 run_root venue hardware exit_code m15_delta m15_fallback_delta "
            "m15_reuse_delta warmup_count configured_rtt_ms observed_rtt_pre_ms "
            "observed_rtt_post_ms observed_rtt_ms fsync_min_ns fsync_p50_ns "
            "calibration_outcome calibration_reason fsync_p90_ns steady_state_tolerance "
            "steady_first_half_median_ns steady_second_half_median_ns steady_first_half_p99_ns "
            "steady_second_half_p99_ns steady_exceedance_splits steady_state durations_artifact "
            "durations_artifact_sha256 venue_backing venue_cache_mode venue_text netem_delay_placement offload_state "
            "fsync_p99_ns fsync_max_ns tid register_attempts register_repeated_arrivals background_attempts "
            "route_attempts attempt_count_source operation_kind_source netem_preflight deciding verdict_metrics "
            "root_label root_bytes historical_kind pivot_input pivot_group pivot_role pivot_append "
            "cell_kind sample_floor intent_occupancy wrapper_layer row_holders zero_row_principals "
            "retired_principals historical_principals live_roots released_rows written_bytes "
            "encode_register_bytes full_snapshot_bytes device_bytes register_post_p99_ns "
            "publish_decision_p99_ns same_occupancy_publish_p99_ns authority_log_wait_p99_ns "
            "cross_volume_blocked_ns device_amplification"
        ).split():
            with self.subTest(field=field):
                self.pair(
                    "missing " + field,
                    "schema-missing: " + field,
                    lambda doc, field=field: doc["samples"][0].pop(field),
                )

        cases = (
            (
                "zero tid",
                "schema-invalid: tid",
                lambda d: d["samples"][0].update(tid=0),
                None,
            ),
            (
                "captured environment",
                "schema-unknown: environment",
                lambda d: d["samples"][0].update(environment={"TOKEN": "fixture"}),
                None,
            ),
            (
                "non-hex revision",
                "revision-required",
                lambda d: d["samples"][0].update(revision="x" * 40),
                None,
            ),
            (
                "non-UTC date",
                "date-required",
                lambda d: d["samples"][0].update(date="2026-11-14"),
                None,
            ),
            (
                "non-finite offered rate",
                "schema-invalid: offered_rate",
                lambda d: d["samples"][0].update(offered_rate=float("inf")),
                None,
            ),
            (
                "missing raw RC",
                "raw-rc-missing",
                lambda d: d["samples"][0].update(
                    raw_rc=str(Path(self.temporary.name) / "absent.rc")
                ),
                None,
            ),
            (
                "changed raw log",
                "raw-log-hash-mismatch",
                lambda d: d["samples"][0].update(raw_log_sha256="0" * 64),
                None,
            ),
            ("invalid raw RC", "raw-rc-invalid", invalid_rc, None),
            (
                "sample loss",
                "sample-loss",
                lambda d: d["samples"][0].update(sample_loss=1),
                None,
            ),
            (
                "zero samples",
                "zero-samples",
                lambda d: d["samples"][0].update(sample_count=0),
                None,
            ),
            (
                "VM as hardware",
                "vm-sample-labelled-hardware",
                lambda d: d["samples"][0].update(venue="vm", hardware=True),
                lambda d: d["samples"][0].update(venue="vm", hardware=False),
            ),
            (
                "loopback RTT",
                "nonzero-rtt-loopback",
                lambda d: self.loopback_row(d, 1),
                lambda d: self.loopback_row(d, 0),
            ),
            (
                "one nonzero RTT",
                "rtt-group-needs-two-nonzero",
                lambda d: d["samples"].pop(),
                None,
            ),
            (
                "deciding M15 delta",
                "m15-delta-row-deciding",
                lambda d: d["samples"][0].update(m15_delta=1),
                lambda d: d["samples"][0].update(m15_delta=1, deciding=False),
            ),
            (
                "M15 fallback calibration",
                "m15-fallback-calibration",
                lambda d: d["samples"][0].update(m15_fallback_delta=0),
                None,
            ),
            (
                "M15 bounded reuse calibration",
                "m15-reuse-calibration",
                lambda d: d["samples"][0].update(m15_reuse_delta=1),
                None,
            ),
            (
                "warm-up population",
                "warmup-count",
                lambda d: d["samples"][0].update(warmup_count=31),
                None,
            ),
            (
                "client-attested kind label",
                "schema-invalid: operation_kind_source",
                lambda d: d["samples"][0].update(operation_kind_source="server-inferred"),
                None,
            ),
            (
                "server-counted attempt label",
                "schema-invalid: attempt_count_source",
                lambda d: d["samples"][0].update(attempt_count_source="client-counted"),
                None,
            ),
            (
                "netem preflight",
                "netem-preflight-required",
                lambda d: d["samples"][1].update(netem_preflight=False),
                None,
            ),
            (
                "observed RTT",
                "observed-rtt-mismatch",
                lambda d: d["samples"][1].update(observed_rtt_ms=11),
                None,
            ),
            (
                "fsync distribution",
                "fsync-distribution-order",
                lambda d: d["samples"][0].update(fsync_p50_ns=5),
                None,
            ),
            (
                "register arrival counts",
                "register-arrival-counts",
                lambda d: d["samples"][0].update(register_repeated_arrivals=1001),
                None,
            ),
            (
                "route attempt counts",
                "route-attempt-counts",
                lambda d: d["samples"][0].update(background_attempts=1),
                None,
            ),
            (
                "wall clock verdict",
                "wall-clock-only-verdict",
                lambda d: d["samples"][0].update(verdict_metrics=["wall_clock_ms"]),
                lambda d: d["samples"][0].update(
                    verdict_metrics=["rtt", "control_writes"]
                ),
            ),
            (
                "707-B label",
                "707-B-root-size",
                lambda d: d["samples"][0].update(root_bytes=706),
                lambda d: d["samples"][0].update(
                    root_label="measured length", root_bytes=706
                ),
            ),
            (
                "upper H pivot",
                "upper-bound-h-pivot-input",
                lambda d: d["samples"][0].update(
                    historical_kind=runner.UPPER_BOUND,
                    pivot_input=True,
                    pivot_group="upper",
                    pivot_role="numerator",
                    live_roots=1,
                    root_size_distribution={"707": 1},
                ),
                lambda d: d["samples"][0].update(
                    historical_kind=runner.UPPER_BOUND, pivot_input=False
                ),
            ),
        )
        for label, reason, malformed, valid in cases:
            with self.subTest(label=label):
                self.pair(label, reason, malformed, valid)

        self.pair(
            "zero register denominator",
            "encode-register-bytes",
            lambda d: self.intent_document(d, encode_register_bytes=0),
            self.intent_document,
        )
        self.pair(
            "zero device denominator",
            "encode-register-bytes",
            lambda d: self.intent_document(
                d,
                written_bytes=0,
                device_bytes=1000,
                encode_register_bytes=0,
                device_amplification=0,
            ),
            self.intent_document,
        )
        self.pair(
            "intent occupancy spelling",
            "schema-invalid: intent_occupancy",
            lambda d: d["samples"][0].update(intent_occupancy="valid-ceiling"),
        )
        self.pair(
            "pivot binding",
            "pivot-input-binding",
            lambda d: d["samples"][0].update(
                pivot_input=True,
                pivot_group="unbound",
                live_roots=1,
                root_size_distribution={"707": 1},
            ),
        )

        def different_medium(doc):
            self.pivot_pair(doc)
            doc["samples"][1]["medium"] = "AmazonS3(other-fixture)"

        self.pair(
            "pivot different medium",
            "pivot-pair-load-medium-wrapper",
            different_medium,
            self.pivot_pair,
        )

        def wrong_result(doc):
            self.pivot_pair(doc)
            for row in doc["samples"][:2]:
                row["pivot_append"] = False

        self.pair(
            "pivot numeric result",
            "pivot-result-mismatch",
            wrong_result,
            self.pivot_pair,
        )

        def set_occupancy(doc, kind, shape, historical_kind="in-format"):
            row = doc["samples"][0]
            self.intent_row(row)
            row.update(
                intent_occupancy=kind,
                historical_kind=historical_kind,
                **dict(
                    zip(
                        (
                            "row_holders",
                            "zero_row_principals",
                            "retired_principals",
                            "historical_principals",
                            "live_roots",
                            "released_rows",
                        ),
                        shape,
                    )
                ),
            )

        occupancy_cases = (
            ("p16", (16, 0, 0, 16, 256, 768), "occupancy-p16-shape"),
            ("zero", (0, 16_384, 0, 16_384, 0, 0), "occupancy-zero-shape"),
            (
                "ceiling",
                (16, 16_368, 0, 16_384, 256, 768),
                "occupancy-ceiling-shape",
            ),
            (
                "historical",
                (0, 0, 4_096, 16_384, 0, 0),
                "occupancy-historical-shape",
            ),
        )
        for kind, shape, refusal in occupancy_cases:
            with self.subTest(intent_occupancy=kind):
                malformed_shape = list(shape)
                malformed_shape[3] -= 1
                self.pair(
                    kind + " occupancy",
                    refusal,
                    lambda d, kind=kind, malformed_shape=tuple(malformed_shape): set_occupancy(
                        d, kind, malformed_shape
                    ),
                    lambda d, kind=kind, shape=shape: set_occupancy(d, kind, shape),
                )
        self.pair(
            "upper-bound occupancy",
            "occupancy-upper-bound-shape",
            lambda d: set_occupancy(
                d,
                "upper-bound",
                (0, 0, 0, 65_535, 0, 0),
                runner.UPPER_BOUND,
            ),
            lambda d: set_occupancy(
                d,
                "upper-bound",
                (0, 0, 0, 65_536, 0, 0),
                runner.UPPER_BOUND,
            ),
        )
        standalone = self.fixture()
        standalone["samples"] = standalone["samples"][:1]
        standalone["samples"][0].update(
            rtt_group=None,
            calibration_outcome=None,
            calibration_reason=None,
        )
        self.assertGreater(runner.validate(standalone), 0)

    def test_published_v5_profile_controls(self):
        valid = self.fixture()
        self.published_rows(valid)
        observed = runner.validate(valid)
        self.assertGreater(observed, 0)

        cases = (
            (
                "request correlation label",
                "published-request-correlation",
                lambda row: row.update(request_correlation="request-correlated"),
            ),
            (
                "strace reconciliation",
                "published-strace-reconciliation",
                lambda row: row.pop("strace_reconciled"),
            ),
            (
                "per-fsync verdict counts",
                "published-per-fsync-request-counts",
                lambda row: row.update(
                    register_attempts=1000,
                    register_repeated_arrivals=0,
                    background_attempts=0,
                ),
            ),
        )
        refused = []
        for label, reason, malformed in cases:
            with self.subTest(label=label):
                invalid = self.fixture()
                self.published_rows(invalid)
                malformed(invalid["samples"][0])
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate(invalid)
                self.assertEqual(str(caught.exception), reason)
                refused.append((label, str(caught.exception)))
        self.assertGreater(len(refused), 0)
        print(f"CONTROL published v5: observed={observed} refused={refused}")

    def test_pivot_review_controls(self):
        def pivot_change(doc, change):
            self.pivot_pair(doc)
            change(*doc["samples"][:2])
            for row in doc["samples"][:2]:
                if row["cell_kind"] != "steady":
                    row.update(
                        steady_first_half_median_ns=None,
                        steady_second_half_median_ns=None,
                        steady_first_half_p99_ns=None,
                        steady_second_half_p99_ns=None,
                        steady_exceedance_splits=None,
                        steady_state=runner.NOT_APPLICABLE,
                    )

        cases = (
            (
                "pivot numerator control",
                "pivot-pair-cell-kind",
                lambda n, _d: n.update(cell_kind="control"),
            ),
            (
                "pivot denominator calibration",
                "pivot-pair-cell-kind",
                lambda _n, d: d.update(cell_kind="calibration"),
            ),
            (
                "pivot venue",
                "pivot-pair-provenance",
                lambda n, _d: n.update(venue="vm", hardware=False),
            ),
            (
                "pivot host",
                "pivot-pair-provenance",
                lambda n, _d: n.update(host="other-host"),
            ),
            (
                "pivot revision",
                "pivot-pair-provenance",
                lambda n, _d: n.update(revision="f" * 40),
            ),
            (
                "pivot deciding numerator",
                "pivot-numerator-not-deciding",
                lambda n, _d: n.update(deciding=False),
            ),
            (
                "pivot in-memory store",
                "pivot-venue-store-required",
                lambda n, d: (
                    n.update(medium="in-memory-sim"),
                    d.update(medium="in-memory-sim"),
                ),
            ),
            (
                "pivot accepted root ceiling",
                "pivot-ceiling-root",
                lambda n, _d: n.update(
                    root_label="measured length",
                    root_bytes=706,
                    root_size_distribution={"706": 256},
                ),
            ),
            (
                "pivot one-holder floor",
                "pivot-pair-shape",
                lambda _n, d: d.update(
                    row_holders=16,
                    historical_principals=16,
                    live_roots=256,
                    released_rows=768,
                    root_size_distribution={"652": 256},
                ),
            ),
            (
                "pivot ceiling role",
                "pivot-pair-roles",
                lambda n, _d: n.update(
                    intent_occupancy="p16", zero_row_principals=0, historical_principals=16
                ),
            ),
            (
                "pivot floor role",
                "pivot-pair-roles",
                lambda _n, d: d.update(intent_occupancy="p1"),
            ),
            (
                "pivot wrapper",
                "pivot-pair-load-medium-wrapper",
                lambda n, _d: n.update(wrapper_layer="client-service"),
            ),
            (
                "pivot filesystem",
                "pivot-pair-load-medium-wrapper",
                lambda n, _d: n.update(filesystem="xfs"),
            ),
            (
                "pivot offered rate",
                "pivot-pair-load-medium-wrapper",
                lambda n, _d: n.update(
                    offered_rate=24, per_stream_offered_rate=24 / 16
                ),
            ),
        )
        for label, reason, change in cases:
            with self.subTest(label=label):
                self.pair(
                    label,
                    reason,
                    lambda d, change=change: pivot_change(d, change),
                    self.pivot_pair,
                )

        self.pair(
            "pivot result without input",
            "pivot-result-without-input",
            lambda d: d["samples"][0].update(pivot_append=True),
        )
        absolute = self.fixture()
        self.pivot_pair(absolute, 101_000_000, 60_000_000)
        self.assertGreater(runner.validate(absolute), 0)
        exact_double = self.fixture()
        self.pivot_pair(exact_double, 80_000_000, 40_000_000)
        for row in exact_double["samples"][:2]:
            row["pivot_append"] = False
        self.assertGreater(runner.validate(exact_double), 0)
        boundaries = (
            ((80_000_000, 80_000_000), (40_000_000, 40_000_000), "no pivot"),
            ((80_000_001, 80_000_001), (40_000_000, 40_000_000), "pivot"),
            ((100_000_000, 100_000_000), (60_000_000, 60_000_000), "no pivot"),
            ((100_000_001, 100_000_001), (60_000_000, 60_000_000), "pivot"),
            ((79_000_000, 81_000_000), (39_000_000, 41_000_000), "inconclusive"),
            ((90_000_000, 110_000_000), (60_000_000, 60_000_000), "inconclusive"),
        )
        self.assertEqual(
            [runner.pivot_verdict(numerator, denominator) for numerator, denominator, _ in boundaries],
            [expected for _, _, expected in boundaries],
        )
        mismatch = self.fixture()
        self.pivot_pair(mismatch)
        for row in mismatch["samples"][:2]:
            row["pivot_verdict"] = "no pivot"
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(mismatch["samples"][:2])
        self.assertEqual(str(caught.exception), "pivot-result-mismatch")
        print("CONTROL pivot thresholds: absolute=101ms strict-double=80/40 observed=3")

    def test_pivot_rejects_over_limit_cycle_evidence(self):
        document = self.fixture()
        self.pivot_pair(document)
        rows = document["samples"][:2]
        runner.validate_pivot(rows)
        limit = runner.DENOMINATOR_CYCLE_LIMIT_NS
        denominator = rows[1]
        attempt = denominator["denominator_attempts"][0]
        for stall, expected in ((limit, None), (limit + 1, "pivot-denominator-cycle-stall-deadline")):
            attempt["cycle_stall_durations_ns"] = [stall]
            denominator["denominator_cycle_stalls"][0]["durations_ns"] = [stall]
            if expected is None:
                runner.validate_pivot(rows)
            else:
                with self.assertRaisesRegex(runner.Refused, f"^{expected}$"):
                    runner.validate_pivot(rows)
        attempt["cycle_stall_durations_ns"] = [limit]
        denominator["denominator_cycle_stalls"][0]["durations_ns"] = [limit]
        path = Path(denominator["pivot_completion_artifact"])
        decisions = runner.durations_artifact(denominator, Path(denominator["run_root"]), "pivot_durations")
        for extra in (0, 1):
            self.write_duration_fixture(path, [limit + extra - value for value in decisions])
            digest = runner.digest(path)
            denominator["pivot_completion_artifact_sha256"] = attempt["completion_artifact_sha256"] = digest
            if extra == 0:
                runner.validate_pivot(rows)
            else:
                with self.assertRaisesRegex(runner.Refused, "^pivot-denominator-cycle-samples$"):
                    runner.validate_pivot(rows)

    def test_pivot_depth_record_fields_are_independently_bound(self):
        document = self.fixture()
        self.pivot_pair(document)
        rows = document["samples"][:2]
        runner.validate_pivot(rows)
        for field, index, column, value in (
            ("index", 64, 0, 65),
            ("measured lane", 64, 1, 1),
            ("phase", 64, 2, "warmup"),
            ("depth", 64, 3, 0),
            ("warm-up lane", 1, 1, 0),
        ):
            with self.subTest(field=field):
                invalid = copy.deepcopy(rows)
                invalid[1]["denominator_attempts"][0]["depth_records"][index][column] = value
                reason = "warmup-lanes" if field == "warm-up lane" else "depth-sequence"
                with self.assertRaisesRegex(runner.Refused, f"^pivot-denominator-{reason}$"):
                    runner.validate_pivot(invalid)

    def test_pivot_validator_guard_controls(self):
        alternate_samples = Path(self.temporary.name) / "alternate-selected.ns"

        def select_alternate_artifact(_numerator, denominator):
            alternate_samples.write_bytes(
                Path(denominator["pivot_durations_artifact"]).read_bytes()
            )
            denominator["denominator_attempts"][0].update(
                sample_artifact=str(alternate_samples),
                sample_artifact_sha256=hashlib.sha256(
                    alternate_samples.read_bytes()
                ).hexdigest(),
            )

        def valid_rows():
            document = self.fixture()
            self.pivot_pair(document)
            return document["samples"][:2]

        def refused(reason, change):
            rows = valid_rows()
            change(rows[0], rows[1])
            with self.assertRaises(runner.Refused) as caught:
                runner.validate_pivot(rows)
            self.assertEqual(str(caught.exception), reason)

        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(valid_rows()[:1])
        self.assertEqual(str(caught.exception), "pivot-pair-count")

        cases = (
            ("pivot-numerator-generation-range", lambda n, _d: n.update(numerator_generation_range=[2, 67])),
            ("pivot-numerator-intent-log-length", lambda n, _d: n.update(numerator_intent_log_bytes=0)),
            ("pivot-verdict-scope", lambda n, _d: n.update(pivot_scope=n["pivot_scope"].replace("≤ 16", "≤ 17"))),
            ("pivot-pair-roles", lambda n, d: d.update(pivot_role=n["pivot_role"])),
            (
                "pivot-pair-roles",
                lambda n, _d: n.update(
                    register_post_p99_ns=float(n["register_post_p99_ns"])
                ),
            ),
            (
                "pivot-verdict-branch",
                lambda _n, d: d.update(pivot_verdict_branch="unexpected"),
            ),
            ("pivot-branch-invalid", lambda _n, d: d.update(pivot_branch="other")),
            (
                "pivot-denominator-steadiness",
                lambda _n, d: d["denominator_attempts"][0].update(
                    steady_first_half_median_ns=39_999_998
                ),
            ),
            (
                "pivot-denominator-cycle-stalls",
                lambda _n, d: d.update(denominator_cycle_stall_issue="#other"),
            ),
            (
                "pivot-normal-branch",
                lambda _n, d: d.update(denominator_label="lower bound"),
            ),
            ("pivot-venue-unrecorded", lambda n, d: (n.update(venue="unknown"), d.update(venue="unknown"))),
            (
                "pivot-venue-kind",
                lambda n, _d: n.update(pivot_venue_kind="podman-vm"),
            ),
            (
                "pivot-transition-count",
                lambda n, _d: n.update(committed_transitions=1_000),
            ),
            (
                "pivot-warmup-observation",
                lambda n, _d: n.update(pivot_warmup_elapsed_ns=0),
            ),
            (
                "pivot-stream-counts",
                lambda n, _d: n.update(stream_sample_counts=[1] * 16),
            ),
            (
                "pivot-principal-limit",
                lambda n, _d: n.update(principal_in_flight_limit=3),
            ),
            (
                "pivot-pilot-types",
                lambda _n, d: d.update(publish_pilot_p50_ns="20"),
            ),
            (
                "pivot-pilot-population",
                lambda _n, d: d.update(publish_pilot_sample_count=31),
            ),
            (
                "pivot-pilot-order",
                lambda _n, d: d.update(publish_pilot_p50_ns=50_000_000),
            ),
            (
                "pivot-pilot-stream-count",
                lambda _n, d: d.update(publish_pilot_stream_count=63),
            ),
            (
                "pivot-stream-plan",
                lambda _n, d: d.update(pivot_stream_plan="serial"),
            ),
            (
                "pivot-floor-root-label",
                lambda _n, d: d.update(root_label="707-B"),
            ),
            (
                "pivot-steady-pattern",
                lambda n, _d: n.update(pivot_steady_pattern="latency-rising"),
            ),
            (
                "pivot-exceedance-histogram-unexpected",
                lambda n, _d: n.update(pivot_steady_exceedance_histograms=[]),
            ),
            (
                "pivot-p99-artifact-mismatch",
                lambda n, _d: n.update(register_post_p99_ns=80_999_999),
            ),
            (
                "pivot-denominator-selected-artifacts",
                select_alternate_artifact,
            ),
            (
                "pivot-denominator-selected-load",
                lambda _n, d: d.update(achieved_rate=45),
            ),
            (
                "pivot-denominator-selected-streams",
                lambda _n, d: d["denominator_attempts"][0].update(
                    stream_sample_counts=[17] + [16] * 39 + [15] * 23 + [14]
                ),
            ),
            (
                "pivot-denominator-selected-warmup",
                lambda _n, d: d.update(pivot_warmup_elapsed_ns=2),
            ),
            (
                "pivot-denominator-selected-pilot",
                lambda _n, d: d.update(publish_pilot_max_ns=44_000_000),
            ),
            (
                "pivot-diagnostic-label",
                lambda n, _d: n.update(same_occupancy_publish_diagnostic="raw"),
            ),
        )
        for reason, change in cases:
            with self.subTest(reason=reason):
                refused(reason, change)

        provenance = (
            ("pivot-provenance-command", lambda row: row.update(command=[])),
            ("pivot-provenance-revision", lambda row: row.update(revision="bad")),
            ("pivot-provenance-date", lambda row: row.update(date="2026-11-17")),
            ("pivot-provenance-date", lambda row: row.update(date="2101-01-01T00:00:00Z")),
            ("pivot-provenance-host", lambda row: row.update(host="")),
            ("raw-log-hash-mismatch", lambda row: row.update(raw_log_sha256="0" * 64)),
            ("raw-rc-hash-mismatch", lambda row: row.update(raw_rc_sha256="0" * 64)),
        )
        for reason, change in provenance:
            with self.subTest(provenance=reason):
                refused(reason, lambda n, _d, change=change: change(n))
        rows = valid_rows()
        bad_rc = Path(self.temporary.name) / "bad.rc"
        bad_rc.write_text("1\n")
        rows[0].update(
            raw_rc=str(bad_rc),
            raw_rc_sha256=hashlib.sha256(bad_rc.read_bytes()).hexdigest(),
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(rows)
        self.assertEqual(str(caught.exception), "pivot-provenance-exit")

        attempt = valid_rows()[1]["denominator_attempts"][0]
        denominator = valid_rows()[1]
        selected_bindings = (
            (
                "pivot-denominator-selected-artifacts",
                {"pivot_durations_artifact_sha256": "0" * 64},
            ),
            (
                "pivot-denominator-selected-artifacts",
                {"pivot_completion_artifact": denominator["pivot_durations_artifact"]},
            ),
            (
                "pivot-denominator-selected-artifacts",
                {"pivot_completion_artifact_sha256": "0" * 64},
            ),
            ("pivot-denominator-selected-load", {"offered_rate": 23.0}),
            ("pivot-denominator-selected-streams", {"stream_count": 63}),
            ("pivot-denominator-selected-warmup", {"pivot_warmup_count": 63}),
        )
        for reason, changes in selected_bindings:
            with self.subTest(selected_binding=changes):
                invalid = dict(denominator, **changes)
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate_selected_denominator(invalid, attempt)
                self.assertEqual(str(caught.exception), reason)
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_denominator_attempts([])
        self.assertEqual(str(caught.exception), "pivot-denominator-attempts")
        attempt_cases = (
            ("pivot-denominator-attempts", {"rate": 0.0}),
            ("pivot-denominator-stall-bound", {"cycle_stall_bound_ns": 1}),
            ("pivot-denominator-stall-count", {"cycle_stall_count": -1}),
            ("pivot-denominator-stall-durations", {"cycle_stall_count": 2}),
            (
                "pivot-denominator-stall-threshold",
                {"cycle_stall_durations_ns": [400_000_000]},
            ),
            (
                "pivot-denominator-refusal-cycle",
                {"refusal_cycle_duration_ns": 1},
            ),
            ("pivot-denominator-steadiness", {"steady_state": "not steady"}),
        )
        for reason, changes in attempt_cases:
            with self.subTest(attempt=reason):
                invalid = dict(attempt, **changes)
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate_denominator_attempts([invalid])
                self.assertEqual(str(caught.exception), reason)

        refused_attempt = dict(attempt)
        refused_attempt.update(
            **denominator_depth_fixture(999),
            **denominator_refusal_timing(999, 46.0),
            outcome="overlap",
            sent_count=999,
            stream_sample_counts=[16] * 39 + [15] * 25,
            sample_count=999,
            completion_count=999,
            guards_passed=False,
            refusal_cycle_duration_ns=450_000_000,
            steady_first_half_median_ns=None,
            steady_second_half_median_ns=None,
            steady_first_half_p99_ns=None,
            steady_second_half_p99_ns=None,
            steady_exceedance_splits=None,
            steady_state=runner.NOT_APPLICABLE,
            steady_pattern="other",
        )
        runner.validate_denominator_attempts([refused_attempt])
        refused_attempt["steady_first_half_median_ns"] = 1
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_denominator_attempts([refused_attempt])
        self.assertEqual(str(caught.exception), "pivot-denominator-steadiness")

    def test_duration_artifact_custody_and_population_controls(self):
        root = Path(self.temporary.name).resolve()
        good = root / "good.ns"
        self.write_duration_fixture(good, [1, 2])
        row = {
            "sample_count": 2,
            "durations_artifact": str(good),
            "durations_artifact_sha256": hashlib.sha256(good.read_bytes()).hexdigest(),
        }
        self.assertEqual(runner.durations_artifact(row, root), [1, 2])

        directory = root / "directory.ns"
        directory.mkdir()
        wrong_suffix = root / "durations.txt"
        wrong_suffix.write_bytes(good.read_bytes())
        nested_root = root / "nested"
        nested_root.mkdir()
        cases = (
            ("durations-artifact-path", {**row, "durations_artifact": "good.ns"}, root),
            (
                "durations-artifact-not-file",
                {**row, "durations_artifact": str(directory)},
                root,
            ),
            (
                "durations-artifact-suffix",
                {**row, "durations_artifact": str(wrong_suffix)},
                root,
            ),
            (
                "durations-artifact-outside-run-root",
                row,
                nested_root,
            ),
            (
                "durations-artifact-invalid",
                {**row, "sample_count": 3},
                root,
            ),
        )
        for reason, invalid, artifact_root in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(runner.Refused) as caught:
                    runner.durations_artifact(invalid, artifact_root)
                self.assertEqual(str(caught.exception), reason)

        repository = root / "pretend-repository"
        repository.mkdir()
        inside = repository / "inside.ns"
        inside.write_bytes(good.read_bytes())
        inside_row = {
            **row,
            "durations_artifact": str(inside),
            "durations_artifact_sha256": hashlib.sha256(inside.read_bytes()).hexdigest(),
        }
        with (
            patch.object(runner, "REPOSITORY", repository),
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.durations_artifact(inside_row, repository)
        self.assertEqual(str(caught.exception), "durations-artifact-inside-repository")

    def test_closed_loop_guard_layers(self):
        valid_row = self.fixture()["samples"][0]
        self.intent_row(valid_row)
        runner.validate_row(valid_row)
        observed = 1

        invalid_row = self.fixture()["samples"][0]
        self.intent_row(invalid_row)
        invalid_row.update(
            pivot_input=True, pivot_group="pivot-a", pivot_role="numerator"
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_row(invalid_row)
        self.assertEqual(str(caught.exception), "closed-loop-pivot-input")

        valid_pair = self.fixture()
        self.pivot_pair(valid_pair)
        runner.validate_pivot(valid_pair["samples"][:2])
        observed += 2

        invalid_pair = self.fixture()
        self.closed_loop_pivot(invalid_pair)
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(invalid_pair["samples"][:2])
        self.assertEqual(str(caught.exception), "closed-loop-pivot-input")
        self.assertGreater(observed, 0)
        print(
            "CONTROL closed-loop guard layers: observed=3 "
            "per-row/comparator refused=closed-loop-pivot-input"
        )

    def recovery_document_fixture(self, gap_bytes=7):
        artifact_root = Path(self.temporary.name)
        if gap_bytes != 7:
            artifact_root = artifact_root / "unbounded"
            artifact_root.mkdir()
        total = gap_bytes + 12
        ledger = [
            dict(operation_id="op-a", content_sha256="a" * 64, unique_content_bytes=4),
            dict(operation_id="op-b", content_sha256="b" * 64, unique_content_bytes=gap_bytes),
        ]
        selection = {
            "epoch": 3,
            "generation": 4,
            "root": "blake3:" + "d" * 64,
            "parent_seq": 8,
        }
        base_argv = [
            "gran@measured-revision",
            "--log-format",
            "json",
            "recover",
            "@handoff/client-root-path/store",
            "v000",
            "--writer",
            "01" * 16,
            "--key-seed",
            "@handoff/signing-seed-path",
            "--endpoint",
            "https://127.0.0.1:1234",
            "--pin",
            "sha256/" + "q" * 43 + "=",
            "--client-cert",
            "@handoff/client-cert-path",
            "--client-key",
            "@handoff/client-credential-path",
            "--credential-context",
            "q3-server",
            "--publisher-key",
            "ed25519:" + "02" * 32,
        ]
        artifact_rows = [
            {"kind": "write-call-bytes", "cumulative_write_call_bytes": 4},
            {
                "kind": "successful-fsync",
                "operation_id": "op-a",
                "content_sha256": "a" * 64,
                "unique_content_bytes": 4,
                "cumulative_write_call_bytes": 4,
            },
            {"kind": "write-call-bytes", "cumulative_write_call_bytes": gap_bytes + 4},
            {
                "kind": "successful-fsync",
                "operation_id": "op-b",
                "content_sha256": "b" * 64,
                "unique_content_bytes": gap_bytes,
                "cumulative_write_call_bytes": gap_bytes + 4,
            },
            {"kind": "write-call-bytes", "cumulative_write_call_bytes": total},
        ]
        artifact_bytes = b"".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            for row in artifact_rows
        )
        artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        def status_body(sequence, identifier):
            return (
                b"GRNVSTAT"
                + (1).to_bytes(2, "big")
                + bytes(16)
                + b"\x01\x01"
                + sequence.to_bytes(8, "big")
                + bytes.fromhex(identifier)
                + b"\x01"
                + (sequence + 1).to_bytes(8, "big")
                + b"\x00"
            )

        final_loss_status = status_body(8, "01" + "c" * 64)
        final_intact_status = status_body(9, "01" + "e" * 64)
        for outcome in ("loss", "intact"):
            directory = artifact_root / f"durable-prepared-{outcome}"
            directory.mkdir()
            (directory / "recovery-ledger.jsonl").write_bytes(artifact_bytes)
            (directory / "final-status.bin").write_bytes(
                final_loss_status if outcome == "loss" else final_intact_status
            )
        selection_log = artifact_root / "durable-prepared-loss/operator-recover-selection.log"
        selection_log.write_text(
            "selected E=3 G=4 root=blake3:" + "d" * 64 + " parent_seq=8\n"
        )
        takeover_log = artifact_root / "durable-prepared-loss/operator-recover-takeover.log"
        takeover_log.write_text('{"event":"recover.landed","seq":9}\n')
        selection_log_sha256 = hashlib.sha256(selection_log.read_bytes()).hexdigest()
        takeover_log_sha256 = hashlib.sha256(takeover_log.read_bytes()).hexdigest()
        recovery_artifacts = {}
        for name in (
            "chain-head-artifact",
            "prepared-intent",
            "prepared-root",
            "published-root",
            "status",
            "released-intent",
        ):
            contents = (
                status_body(8, "01" + "c" * 64)
                if name == "status"
                else f"{name} evidence".encode()
            )
            relative = f"durable-prepared-loss/operator-recover-{name}.bin"
            (artifact_root / relative).write_bytes(contents)
            recovery_artifacts[name.replace("-", "_")] = {
                "artifact": relative,
                "artifact_sha256": hashlib.sha256(contents).hexdigest(),
            }
        observed = {"ledger": ledger, "cumulative_write_call_bytes": 19}
        self.assertEqual(
            runner.bind_recovery_ledgers(ledger, 19, observed, observed),
            (ledger, 19),
        )
        fabricated = json.loads(json.dumps(ledger))
        fabricated[0]["content_sha256"] = "e" * 64
        with self.assertRaises(runner.Refused) as caught:
            runner.bind_recovery_ledgers(fabricated, 19, observed, observed)
        self.assertEqual(str(caught.exception), "recovery-ledger-plan-mismatch")
        pair = dict(
            profile="durable-prepared",
            ledger=ledger,
            cumulative_write_call_bytes=total,
            pre_loss_head_operations=["op-a"],
            pre_loss_max_seq=8,
            sentinel=dict(
                operation_id="sentinel-u", content_sha256="c" * 64, unique_content_bytes=3
            ),
            planned_operator_verbs=["gran recover selection", "gran recover takeover"],
            loss=dict(
                operator_verbs=[
                    {
                        "verb": "gran recover selection",
                        "argv": base_argv,
                        "exit_code": 1,
                        "elapsed_ns": 11,
                        "json_log": "operator-recover-selection.log",
                        "json_log_sha256": selection_log_sha256,
                        "log_path_scope": "redacted",
                        "construction_workspace_mib": "default",
                        "overlay_cap_bytes": "default",
                        "selection": selection,
                        "selection_artifact": "operator-recover-selection.log",
                        "selection_artifact_sha256": selection_log_sha256,
                        "ending": {
                            "exit_code": 1,
                            "events_seen": [],
                            "completion_line_present": False,
                        },
                        "expected_result": "selection-report-without-local-state",
                        "store_absent_after": True,
                        "endpoint_source": "@handoff/base-url",
                        "credential_context_source": "@handoff/credential-context",
                        "head_after_verb": None,
                        "authority_readback": None,
                    },
                    {
                        "verb": "gran recover takeover",
                        "argv": base_argv
                        + ["--acknowledge-takeover", "01" * 16],
                        "exit_code": 0,
                        "elapsed_ns": 12,
                        "json_log": "operator-recover-takeover.log",
                        "json_log_sha256": takeover_log_sha256,
                        "log_path_scope": "redacted",
                        "construction_workspace_mib": "default",
                        "overlay_cap_bytes": "default",
                        "selection": None,
                        "selection_artifact": None,
                        "selection_artifact_sha256": None,
                        "ending": {
                            "exit_code": 0,
                            "events_seen": [{"event": "recover.landed", "seq": 9}],
                            "completion_line_present": False,
                        },
                        "expected_result": "journal-finished-or-landed-selected-head",
                        "store_absent_after": False,
                        "endpoint_source": "@handoff/base-url",
                        "credential_context_source": "@handoff/credential-context",
                        "head_after_verb": {
                            "sequence": 9,
                            "identifier": "01" + "e" * 64,
                        },
                        "authority_readback": {
                            "head": {
                                "sequence": 9,
                                "identifier": "01" + "e" * 64,
                            },
                            "chain_head": {
                                "sequence": 9,
                                "identifier": "01" + "e" * 64,
                            },
                            "status_head": {
                                "sequence": 8,
                                "identifier": "01" + "c" * 64,
                            },
                            "status_lag_seqs": 1,
                            "writer_row_state": "released",
                            "prepared_root_id": "blake3:" + "d" * 64,
                            "published_root_id": "blake3:" + "e" * 64,
                            "published_root_byte_identical": False,
                            "implied_recovery_branch": "exact",
                            "exact_branch_byte_mismatch": True,
                            "decoded_field_diff": ["signature_0"],
                            "head_before_phase_two": {
                                "sequence": 8,
                                "identifier": "01" + "c" * 64,
                            },
                            **recovery_artifacts,
                        },
                    },
                ],
                elapsed_ns=12,
                final_head_operations=["op-a", "op-b"],
                final_max_seq=9,
                final_head_id="01" + "e" * 64,
                final_status_head={
                    "sequence": 8,
                    "identifier": "01" + "c" * 64,
                },
                final_status_lag_seqs=1,
                final_status_artifact={
                    "artifact": "durable-prepared-loss/final-status.bin",
                    "artifact_sha256": hashlib.sha256(final_loss_status).hexdigest(),
                },
                content_probe_index=0,
                content_probe_bytes=4_194_304,
                before_image_uuid="old-uuid",
                after_image_uuid="new-uuid",
                before_image_inode=41,
                after_image_inode=52,
                before_root_device=7,
                after_root_device=8,
                replacement_root_device=8,
                old_paths_absent=True,
                store_destroyed=True,
                cache_destroyed=True,
                signing_seed_survived=True,
                certificate_survived=True,
                credential_survived=True,
                ledger=ledger,
                cumulative_write_call_bytes=total,
                ledger_artifact="durable-prepared-loss/recovery-ledger.jsonl",
                ledger_artifact_sha256=artifact_sha256,
            ),
            intact=dict(
                operator_verbs=[],
                elapsed_ns=5,
                final_head_operations=["op-a", "op-b", "sentinel-u"],
                final_max_seq=9,
                final_head_id="01" + "e" * 64,
                final_status_head={
                    "sequence": 9,
                    "identifier": "01" + "e" * 64,
                },
                final_status_lag_seqs=0,
                final_status_artifact={
                    "artifact": "durable-prepared-intact/final-status.bin",
                    "artifact_sha256": hashlib.sha256(final_intact_status).hexdigest(),
                },
                content_probe_index=1,
                content_probe_bytes=4_194_304,
                before_image_uuid="old-uuid",
                after_image_uuid="old-uuid",
                before_image_inode=41,
                after_image_inode=41,
                signing_seed_survived=True,
                certificate_survived=True,
                credential_survived=True,
                ledger=ledger,
                cumulative_write_call_bytes=total,
                ledger_artifact="durable-prepared-intact/recovery-ledger.jsonl",
                ledger_artifact_sha256=artifact_sha256,
            ),
            gap_operations=1,
            gap_bytes=gap_bytes,
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
            phase1_selection_artifact_sha256=selection_log_sha256,
        )
        return {
            "event": "recovery-pair", "pair": pair, "artifact_root": str(artifact_root)
        }

    @staticmethod
    def published_recovery_document(document):
        published = copy.deepcopy(document)
        pair = published["pair"]
        pair.update(profile="published", pre_loss_head_operations=["op-a", "op-b"],
                    planned_operator_verbs=[], gap_operations=0, gap_bytes=0,
                    phase1_selection_artifact_sha256=None)
        pair["loss"].update(operator_verbs=[], final_max_seq=8, final_head_id="01" + "c" * 64,
                            final_status_lag_seqs=0, final_head_operations=["op-a", "op-b"])
        return published

    def test_recovery_pair_controls(self):
        recovery_document = self.recovery_document_fixture()
        artifact_root = Path(recovery_document["artifact_root"])
        pair = recovery_document["pair"]
        artifact_bytes = (artifact_root / pair["loss"]["ledger_artifact"]).read_bytes()
        self.assertEqual(runner.validate_recovery_pair(pair, artifact_root), (1, 7))
        self.assertEqual(runner.validate(recovery_document), 1)
        invalid_document = json.loads(json.dumps(recovery_document))
        invalid_document["pair"]["profile"] = "other"
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(invalid_document)
        self.assertEqual(str(caught.exception), "recovery-profile-invalid")
        pre_loss = {"sequence": 8, "identifier": "a" * 66}
        final = {"sequence": 9, "identifier": "b" * 66}
        operation_fixture = (pre_loss, pre_loss, pre_loss, final, ["a-0000"])
        self.assertEqual(
            runner.run_recovery_outcome(
                None, None, None, None, "durable-prepared", True,
                operation_fixture=operation_fixture,
            ),
            ([], ["a-0000"]),
        )
        for index, replacement, reason in (
            (2, dict(pre_loss, sequence=9), "sentinel-already-published: sequence"),
            (4, [], "recovery-content-observation"),
        ):
            invalid = list(operation_fixture)
            invalid[index] = replacement
            with self.assertRaises(runner.Refused) as caught:
                runner.run_recovery_outcome(
                    None, None, None, None, "durable-prepared", True,
                    operation_fixture=tuple(invalid),
                )
            self.assertEqual(str(caught.exception), reason)
        real_initial = {"sequence": 8, "identifier": "01" + "a" * 64}
        real_after_a = {"sequence": 9, "identifier": "01" + "b" * 64}
        real_final = dict(real_after_a)
        real_keys = []
        for name in ("real-seed", "real-cert", "real-credential"):
            path = artifact_root / name
            path.write_text(name)
            real_keys.append(path)

        def drive_real_observation(
            label, observed_pre_loss, pre_observer, observer, replace=None
        ):
            real_work = artifact_root / label
            real_image = artifact_root / f"{label}.img"
            real_image.write_bytes(b"image")
            old_log = artifact_root / f"{label}-client.jsonl"
            old_log.write_text("{}\n")
            handoff_values = {
                "signing-seed-path": str(real_keys[0]),
                "client-cert-path": str(real_keys[1]),
                "client-credential-path": str(real_keys[2]),
                "client-log-path": str(old_log),
            }
            started = []

            def start(*_args, **_options):
                record = {"finished": False, "index": len(started)}
                started.append(record)
                return record

            def finish(record, **_options):
                record["finished"] = True
                return {"exit_code": 0}

            def status(_handoff, artifact, _timeout):
                artifact.write_bytes(b"status")
                return real_final

            replace = (
                Mock(return_value=({"exit_code": -signal.SIGKILL}, {}))
                if replace is None
                else replace
            )
            with (
                patch.object(runner, "recovery_image", return_value=real_image),
                patch.object(runner, "create_and_mount_recovery_image"),
                patch.object(runner, "server_child_command", return_value=["server"]),
                patch.object(runner, "client_child_command", return_value=["client"]),
                patch.object(runner, "start_command", side_effect=start),
                patch.object(runner, "finish_command", side_effect=finish),
                patch.object(runner, "wait_file"),
                patch.object(
                    runner,
                    "prepublication_head",
                    side_effect=[
                        (real_initial, None),
                        (real_after_a, None),
                        (observed_pre_loss, None),
                    ],
                ),
                patch.object(
                    runner,
                    "read_workload_ledger",
                    return_value=([], 0, "0" * 64),
                ),
                patch.object(
                    runner,
                    "handoff_text",
                    side_effect=lambda _handoff, name: handoff_values.get(name),
                ),
                patch.object(runner, "replace_owned_client_image", replace),
                patch.object(
                    runner, "chain_head_probe", return_value=(real_final, None)
                ),
                patch.object(runner, "head_probe", side_effect=status),
                patch.object(
                    runner,
                    "recovery_content_probe",
                    return_value=(["a-0000"], 0, 4_194_304),
                ),
                patch.object(runner, "abort_command"),
                patch.object(runner, "run_command"),
            ):
                result = runner.run_recovery_outcome(
                    "server",
                    "client",
                    "gran",
                    real_work,
                    "published",
                    True,
                    pre_loss_observer=pre_observer,
                    operation_observer=observer,
                )
            return result, replace

        real_pre_observer = Mock(return_value=["observed-pre-loss"])
        real_observer = Mock(return_value=(["a-0000"], ["observed-final"]))
        real_result, replace = drive_real_observation(
            "real-observation", real_after_a, real_pre_observer, real_observer
        )
        self.assertEqual(
            (real_result[2], real_result[3]["final_head_operations"]),
            (["observed-pre-loss"], ["observed-final"]),
        )
        real_pre_observer.assert_called_once()
        real_observer.assert_called_once()
        replace.assert_called_once()
        sentinel_replace = Mock(
            return_value=({"exit_code": -signal.SIGKILL}, {})
        )
        with self.assertRaises(runner.Refused) as caught:
            drive_real_observation(
                "sentinel-observation",
                dict(real_after_a, sequence=10),
                runner.observed_pre_loss_operations,
                Mock(return_value=(["a-0000"], ["observed-final"])),
                sentinel_replace,
            )
        self.assertEqual(str(caught.exception), "sentinel-already-published: sequence")
        sentinel_replace.assert_not_called()
        self.assertEqual(
            runner.observed_head_operations(
                "durable-prepared", True, pre_loss, final, ["a-0000"]
            ),
            ["a-0000"],
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.observed_head_operations(
                "durable-prepared", True, pre_loss, pre_loss, ["a-0000"]
            )
        self.assertEqual(str(caught.exception), "recovery-head-observation: sequence")
        observation_cases = (
            (
                "recovery-head-observation: identifier",
                lambda: runner.observed_head_operations(
                    "published", True, pre_loss, dict(pre_loss, identifier="c" * 66), ["a-0000"]
                ),
            ),
            (
                "recovery-head-observation: identifier",
                lambda: runner.observed_head_operations(
                    "durable-prepared",
                    False,
                    pre_loss,
                    {"sequence": 9, "identifier": pre_loss["identifier"]},
                    ["a-0000", "u-0001"],
                ),
            ),
            (
                "recovery-content-observation",
                lambda: runner.observed_head_operations(
                    "durable-prepared", False, pre_loss, final, ["a-0000"]
                ),
            ),
            (
                "sentinel-already-published: sequence",
                lambda: runner.observed_pre_loss_operations(
                    "durable-prepared",
                    pre_loss,
                    pre_loss,
                    {"sequence": 9, "identifier": pre_loss["identifier"]},
                ),
            ),
            (
                "sentinel-already-published: identifier",
                lambda: runner.observed_pre_loss_operations(
                    "durable-prepared",
                    pre_loss,
                    pre_loss,
                    dict(pre_loss, identifier="c" * 66),
                ),
            ),
            (
                "pre-loss-head-observation: sequence",
                lambda: runner.observed_pre_loss_operations(
                    "published", pre_loss, pre_loss, pre_loss
                ),
            ),
            (
                "pre-loss-head-observation: identifier",
                lambda: runner.observed_pre_loss_operations(
                    "durable-prepared",
                    pre_loss,
                    dict(pre_loss, identifier="c" * 66),
                    dict(pre_loss, identifier="c" * 66),
                ),
            ),
            (
                "pre-loss-head-observation: identifier",
                lambda: runner.observed_pre_loss_operations(
                    "published",
                    pre_loss,
                    {"sequence": 9, "identifier": pre_loss["identifier"]},
                    {"sequence": 9, "identifier": pre_loss["identifier"]},
                ),
            ),
        )
        for reason, observe in observation_cases:
            with self.subTest(observation=reason):
                with self.assertRaises(runner.Refused) as caught:
                    observe()
                self.assertEqual(str(caught.exception), reason)
        probe = Path(self.temporary.name) / "probe"
        probe.mkdir()
        runner.private_signal(probe / "client-probe-result", b"1 4194304")
        self.assertEqual(
            runner.recovery_content_probe(probe),
            (["a-0000", "u-0001"], 1, 4_194_304),
        )

        reused_inode = json.loads(json.dumps(pair))
        reused_inode["loss"]["after_image_inode"] = reused_inode["loss"]["before_image_inode"]
        self.assertEqual(
            runner.validate_recovery_pair(reused_inode, artifact_root), (1, 7)
        )

        published_pair = self.published_recovery_document(recovery_document)["pair"]
        self.assertEqual(runner.validate_recovery_pair(published_pair, artifact_root), (0, 0))
        invalid_published = json.loads(json.dumps(published_pair))
        invalid_published["phase1_selection_artifact_sha256"] = "0" * 64
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_recovery_pair(invalid_published, artifact_root)
        self.assertEqual(str(caught.exception), "published-recovery-gap")

        escaped_ledger = artifact_root / "durable-prepared-loss/escaped-ledger.jsonl"
        outside_ledger = artifact_root.parent / "outside-recovery-ledger.jsonl"
        outside_ledger.write_bytes(artifact_bytes)
        escaped_ledger.symlink_to(outside_ledger)

        with self.assertRaises(runner.Refused) as caught:
            runner.validate_recovery_pair([], artifact_root)
        self.assertEqual(str(caught.exception), "recovery-pair-type-invalid")

        cases = (
            (
                "unknown pair field",
                "recovery-pair-invalid",
                lambda value: value.update(unexpected=True),
            ),
            (
                "unknown profile",
                "recovery-profile-invalid",
                lambda value: value.update(profile="other"),
            ),
            (
                "empty ledger",
                "recovery-ledger-invalid",
                lambda value: value.update(ledger=[]),
            ),
            (
                "malformed ledger row",
                "recovery-ledger-invalid",
                lambda value: value["ledger"][0].update(unique_content_bytes=0),
            ),
            (
                "duplicate ledger operation",
                "recovery-ledger-invalid",
                lambda value: value["ledger"][1].update(operation_id="op-a"),
            ),
            (
                "write byte regression",
                "recovery-write-bytes-invalid",
                lambda value: value.update(cumulative_write_call_bytes=1),
            ),
            (
                "malformed pre-loss operations",
                "pre-loss-head-shape-invalid",
                lambda value: value.update(pre_loss_head_operations=[""]),
            ),
            (
                "malformed sentinel",
                "recovery-sentinel-invalid",
                lambda value: value["sentinel"].update(unique_content_bytes=0),
            ),
            (
                "sentinel reuses a durable operation id",
                "recovery-sentinel-operation-id",
                lambda value: value["sentinel"].update(operation_id="op-a"),
            ),
            (
                "unknown pre-loss operation",
                "pre-loss-head-invalid",
                lambda value: value.update(pre_loss_head_operations=["unknown"]),
            ),
            (
                "invalid pre-loss sequence",
                "pre-loss-seq-invalid",
                lambda value: value.update(pre_loss_max_seq=-1),
            ),
            (
                "malformed planned verb",
                "recovery-verbs-invalid",
                lambda value: value.update(planned_operator_verbs=[1]),
            ),
            (
                "wrong recovery labels",
                "recovery-observation-labels",
                lambda value: value.update(gap_label="gap"),
            ),
            (
                "missing loss outcome",
                "recovery-outcome-invalid",
                lambda value: value.update(loss=None),
            ),
            (
                "missing key survival",
                "recovery-key-survival",
                lambda value: value["loss"].update(signing_seed_survived=False),
            ),
            (
                "intact masquerading as loss",
                "loss-image-witness",
                lambda value: value["loss"].update(
                    after_image_uuid="old-uuid", after_image_inode=41
                ),
            ),
            (
                "sentinel already on head",
                "sentinel-already-published",
                lambda value: value["pre_loss_head_operations"].append("sentinel-u"),
            ),
            (
                "write-call bytes used as gap bytes",
                "recovery-gap-mismatch",
                lambda value: value.update(gap_bytes=19),
            ),
            (
                "empty loss UUID",
                "loss-image-witness",
                lambda value: value["loss"].update(after_image_uuid=""),
            ),
            (
                "replacement root device mismatch",
                "loss-image-witness",
                lambda value: value["loss"].update(after_root_device=9),
            ),
            (
                "absent intact UUIDs",
                "intact-image-witness",
                lambda value: value["intact"].update(
                    before_image_uuid=None, after_image_uuid=None
                ),
            ),
            (
                "store destruction missing",
                "loss-store-witness",
                lambda value: value["loss"].update(store_destroyed=False),
            ),
            (
                "sequence regression",
                "recovery-outcome-invalid",
                lambda value: value["loss"].update(final_max_seq=7),
            ),
            (
                "zero elapsed recovery",
                "recovery-outcome-invalid",
                lambda value: value["loss"].update(elapsed_ns=0),
            ),
            (
                "short content probe",
                "recovery-outcome-invalid",
                lambda value: value["loss"].update(content_probe_bytes=4_194_303),
            ),
            (
                "duplicate final operations",
                "recovery-outcome-invalid",
                lambda value: value["loss"].update(
                    final_head_operations=["op-a", "op-b", "op-b"]
                ),
            ),
            (
                "wrong final status lag",
                "recovery-final-status-lag-invalid",
                lambda value: value["loss"].update(final_status_lag_seqs=0),
            ),
            (
                "malformed final status artifact",
                "recovery-final-status-artifact-invalid",
                lambda value: value["loss"].update(final_status_artifact={}),
            ),
            (
                "malformed ledger artifact",
                "recovery-ledger-artifact-shape-invalid",
                lambda value: value["loss"].update(ledger_artifact="../ledger.jsonl"),
            ),
            (
                "escaped ledger artifact",
                "recovery-ledger-artifact-path-invalid",
                lambda value: value["loss"].update(
                    ledger_artifact="durable-prepared-loss/escaped-ledger.jsonl"
                ),
            ),
            (
                "malformed actual verb",
                "recovery-verbs-invalid",
                lambda value: value["loss"]["operator_verbs"][0].update(elapsed_ns=0),
            ),
            (
                "verb log path",
                "recovery-verb-log-path",
                lambda value: value["loss"]["operator_verbs"][0].update(
                    json_log="../selection.log"
                ),
            ),
            (
                "verb log digest",
                "recovery-verb-log-hash-mismatch",
                lambda value: value["loss"]["operator_verbs"][0].update(
                    json_log_sha256="0" * 64,
                    selection_artifact_sha256="0" * 64,
                ),
            ),
            (
                "verb full events",
                "recovery-verb-events-incomplete",
                lambda value: value["loss"]["operator_verbs"][1]["ending"].update(
                    events_seen=[]
                ),
            ),
            (
                "planned and actual verbs differ",
                "recovery-verbs-mismatch",
                lambda value: value.update(
                    planned_operator_verbs=["gran recover takeover", "gran recover selection"]
                ),
            ),
            (
                "intact has operator verb",
                "intact-operator-verbs",
                lambda value: value["intact"].update(operator_verbs=[{}]),
            ),
            (
                "loss final head differs",
                "loss-final-head",
                lambda value: value["loss"].update(final_head_operations=["op-a"]),
            ),
            (
                "sentinel present in loss final head",
                "loss-sentinel-present",
                lambda value: value["loss"].update(
                    final_head_operations=["op-a", "op-b", "sentinel-u"]
                ),
            ),
            (
                "intact final head differs",
                "intact-recovery-head",
                lambda value: value["intact"].update(final_head_operations=["op-a", "op-b"]),
            ),
            (
                "durable zero gap",
                "durable-recovery-gap",
                lambda value: (
                    value.update(gap_operations=0, gap_bytes=0),
                    value.update(pre_loss_head_operations=["op-a", "op-b"]),
                ),
            ),
            (
                "undocumented recovery argv",
                "durable-recovery-verbs",
                lambda value: value["loss"]["operator_verbs"][0]["argv"].pop(),
            ),
            (
                "readback shape",
                "recovery-authority-readback-shape",
                lambda value: value["loss"]["operator_verbs"][1]["authority_readback"].pop(
                    "released_intent"
                ),
            ),
            (
                "readback artifact path",
                "recovery-authority-artifact-invalid",
                lambda value: value["loss"]["operator_verbs"][1]["authority_readback"][
                    "prepared_root"
                ].update(artifact="../prepared-root.bin"),
            ),
            (
                "readback before shape",
                "recovery-authority-before-invalid",
                lambda value: value["loss"]["operator_verbs"][1]["authority_readback"][
                    "head_before_phase_two"
                ].pop("identifier"),
            ),
            (
                "readback head shape",
                "durable-recovery-head-shape",
                lambda value: value["loss"]["operator_verbs"][1]["authority_readback"].update(
                    head=None
                ),
            ),
            (
                "readback head sequence",
                "durable-recovery-completion: head-sequence",
                lambda value: value["loss"]["operator_verbs"][1]["authority_readback"][
                    "head"
                ].update(sequence=10),
            ),
            (
                "readback head identifier",
                "durable-recovery-completion: head-identifier",
                lambda value: value["loss"]["operator_verbs"][1]["authority_readback"][
                    "head"
                ].update(identifier="01" + "0" * 64),
            ),
            (
                "readback status lag",
                "recovery-status-lag-invalid",
                lambda value: value["loss"]["operator_verbs"][1]["authority_readback"].update(
                    status_lag_seqs=0
                ),
            ),
            (
                "readback pre-loss sequence",
                "durable-recovery-completion: pre-loss-sequence",
                lambda value: value["loss"]["operator_verbs"][1]["authority_readback"][
                    "head_before_phase_two"
                ].update(sequence=7),
            ),
            (
                "readback completion semantics",
                "durable-recovery-completion",
                lambda value: value["loss"]["operator_verbs"][0].update(
                    expected_result="other"
                ),
            ),
            (
                "durable final sequence",
                "durable-recovery-head",
                lambda value: value["loss"].update(
                    final_max_seq=10, final_status_lag_seqs=2
                ),
            ),
            (
                "takeover final head binding",
                "durable-recovery-takeover-head",
                lambda value: value["loss"].update(final_head_id="01" + "0" * 64),
            ),
            (
                "one recovery verb",
                "durable-recovery-verbs",
                lambda value: (
                    value["loss"].update(operator_verbs=value["loss"]["operator_verbs"][:1]),
                    value.update(planned_operator_verbs=value["planned_operator_verbs"][:1]),
                ),
            ),
            (
                "runner-fabricated ledger",
                "recovery-ledger-artifact-mismatch",
                lambda value: value["ledger"][0].update(content_sha256="e" * 64),
            ),
            (
                "changed authority readback",
                "recovery-authority-artifact-hash-mismatch",
                lambda value: value["loss"]["operator_verbs"][1][
                    "authority_readback"
                ]["status"].update(artifact_sha256="e" * 64),
            ),
            (
                "decoded recovery status not raw status",
                "recovery-status-artifact-invalid",
                lambda value: value["loss"]["operator_verbs"][1][
                    "authority_readback"
                ].update(
                    status_head={"sequence": 9, "identifier": "01" + "e" * 64},
                    status_lag_seqs=0,
                ),
            ),
            (
                "decoded final status not raw status",
                "recovery-final-status-artifact-invalid",
                lambda value: value["loss"].update(
                    final_status_head={"sequence": 9, "identifier": "01" + "e" * 64},
                    final_status_lag_seqs=0,
                ),
            ),
            (
                "driver operation constant",
                "recovery-content-observation",
                lambda value: value["loss"].update(content_probe_index=1),
            ),
        )
        for label, reason, mutate in cases:
            with self.subTest(label=label):
                malformed = json.loads(json.dumps(pair))
                mutate(malformed)
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate_recovery_pair(malformed, artifact_root)
                self.assertEqual(str(caught.exception), reason)
        self.assertGreater(len(cases), 0)

        a_bytes = bytes([1]) * (4 * 1024 * 1024)
        u_bytes = (1).to_bytes(8, "big") + bytes(4096 - 8)
        driver_ledger = [
            {
                "operation_id": "a-0000",
                "content_sha256": hashlib.sha256(a_bytes).hexdigest(),
                "unique_content_bytes": len(a_bytes),
            }
        ]
        driver_write_bytes = len(a_bytes) + len(u_bytes)
        driver_rows = [
            {"kind": "write-call-bytes", "cumulative_write_call_bytes": len(a_bytes)},
            {
                "kind": "successful-fsync",
                **driver_ledger[0],
                "cumulative_write_call_bytes": len(a_bytes),
            },
            {
                "kind": "write-call-bytes",
                "cumulative_write_call_bytes": driver_write_bytes,
            },
        ]
        driver_bytes = b"".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            for row in driver_rows
        )
        driver_pair = json.loads(json.dumps(pair))
        driver_pair.update(
            ledger=driver_ledger,
            cumulative_write_call_bytes=driver_write_bytes,
            pre_loss_head_operations=[],
            gap_bytes=len(a_bytes),
            sentinel={
                "operation_id": "u-0001",
                "content_sha256": hashlib.sha256(u_bytes).hexdigest(),
                "unique_content_bytes": len(u_bytes),
            },
        )
        for name, operations in (("loss", ["a-0000"]), ("intact", ["a-0000", "u-0001"])):
            witness = driver_pair[name]
            ledger_file = artifact_root / witness["ledger_artifact"]
            ledger_file.write_bytes(driver_bytes)
            witness.update(
                ledger=driver_ledger,
                cumulative_write_call_bytes=driver_write_bytes,
                ledger_artifact_sha256=hashlib.sha256(driver_bytes).hexdigest(),
                final_head_operations=operations,
            )

        def driver_outcome(_server, _client, _gran, _work, _profile, lose, _timeout):
            return 7, 8, [], driver_pair["loss" if lose else "intact"]

        manifest = runner.run_recovery_pair(
            "server",
            "client",
            "gran",
            artifact_root,
            "durable-prepared",
            resource_check=lambda _work: None,
            outcome_runner=driver_outcome,
        )
        self.assertEqual(runner.validate(manifest), 1)
        print(
            "CONTROL recovery pair: observed=1 refused="
            + ",".join(reason for _, reason, _ in cases)
        )

    def test_volume_status_head_controls(self):
        prefix = b"GRNVSTAT" + (1).to_bytes(2, "big") + bytes(16)
        empty = prefix + b"\x01\x00\x01" + (1).to_bytes(8, "big") + b"\x00"
        self.assertEqual(
            runner.decode_volume_status_head(empty),
            {"sequence": 0, "identifier": None},
        )

        unverified = prefix + b"\x00\x00"
        self.assertIsNone(runner.decode_volume_status_head(unverified))
        with self.assertRaises(runner.Refused) as caught:
            runner.poll_verified_head(lambda: (200, unverified), timeout=0)
        self.assertEqual(str(caught.exception), "head-unverified: attempts=1")

        head_id = b"\x01" + bytes.fromhex("ab" * 32)
        verified = (
            prefix
            + b"\x01\x01"
            + (2).to_bytes(8, "big")
            + head_id
            + b"\x01"
            + (3).to_bytes(8, "big")
            + b"\x00"
        )
        self.assertEqual(
            runner.decode_volume_status_head(verified),
            {"sequence": 2, "identifier": head_id.hex()},
        )
        malformed = empty[:-2] + b"\x02" + empty[-1:]
        refusals = 0
        for body in (malformed, empty + b"\x00"):
            with self.assertRaises(runner.Refused) as caught:
                runner.decode_volume_status_head(body)
            self.assertEqual(str(caught.exception), "head-probe-invalid")
            refusals += 1
        self.assertGreater(refusals, 0)

    def test_recovery_head_sources_and_status_lag(self):
        chain = {"sequence": 2, "identifier": "01" + "a" * 64}
        artifact = Path(self.temporary.name) / "chain.tsv"
        with (
            patch.object(
                runner, "chain_head_probe", return_value=(chain, artifact)
            ) as chain_probe,
            patch.object(
                runner,
                "head_probe",
                side_effect=AssertionError("pre-publication status read"),
            ) as status_probe,
        ):
            self.assertEqual(
                runner.prepublication_head(None, None, None, "before-a"),
                (chain, artifact),
            )
        chain_probe.assert_called_once()
        status_probe.assert_not_called()

        lagging = {"sequence": 1, "identifier": "01" + "c" * 64}
        self.assertEqual(runner.observe_status_lag(chain, lagging, "chain-status"), 1)
        cases = (
            ("sequence", {"sequence": 3, "identifier": "01" + "b" * 64}),
            ("identifier", {"sequence": 2, "identifier": "01" + "b" * 64}),
        )
        for field, status in cases:
            with self.subTest(field=field):
                with self.assertRaises(runner.Refused) as caught:
                    runner.observe_status_lag(chain, status, "chain-status")
                self.assertEqual(str(caught.exception), f"chain-status: {field}")
        self.assertGreater(len(cases), 0)

    def test_recovery_verb_command_and_completion_controls(self):
        root = Path(self.temporary.name)
        handoff = root / "recover-handoff"
        handoff.mkdir(mode=0o700)
        gran = root / "gran"
        gran.write_bytes(b"measured binary")
        gran.chmod(0o700)
        custody = {
            "client-root-path": str(root / "image/root"),
            "client-writer": "01" * 16,
            "server-pin": "ab" * 32,
            "root-key": "cd" * 32,
            "volume": "v000",
            "signing-seed-path": str(root / "signing.seed"),
            "base-url": "https://127.0.0.1:1234",
            "client-cert-path": str(root / "client.crt"),
            "client-credential-path": str(root / "client.key"),
            "credential-context": "q3-server",
        }
        for name, value in custody.items():
            runner.private_signal(handoff / name, value.encode())
        credential_value = "credential-private-value"
        (root / "client.key").write_text(credential_value)
        command = runner.recovery_command(gran, handoff, False)
        self.assertIn(str(root / "client.key"), command)
        self.assertNotIn(credential_value, command)
        self.assertNotIn("--log-paths", command)
        recorded = runner.recorded_recovery_argv(command, handoff)
        self.assertTrue(runner.recovery_argv_is_documented(recorded, False))
        takeover = runner.recorded_recovery_argv(
            runner.recovery_command(gran, handoff, True), handoff
        )
        self.assertTrue(runner.recovery_argv_is_documented(takeover, True))
        expected_selection = {
            "epoch": 3,
            "generation": 4,
            "root": "blake3:" + "d" * 64,
            "parent_seq": 8,
        }
        expected_head = {"sequence": 9, "identifier": "01" + "e" * 64}

        def completion(value, head=expected_head):
            return runner.validate_recovery_completion(value, 9, head)

        log = root / "operator-recover.log"
        log.write_text('{"event":"recover.journal_finished","base_seq":9}\n')
        receipt = {"exit_code": 0, "raw_log": str(log)}
        completed_log, ending = completion(receipt)
        self.assertEqual(completed_log, log)
        self.assertFalse(ending["completion_line_present"])
        landed = root / "operator-landed.log"
        landed.write_text('{"event":"recover.landed","seq":9}\n')
        landed_receipt = {"exit_code": 0, "raw_log": str(landed)}
        self.assertEqual(completion(landed_receipt)[0], landed)
        for rc, contents, reason in (
            (1, log.read_text(), "recovery-verb-failed"),
            (2, log.read_text(), "recovery-verb-argv-bug"),
            (3, log.read_text(), "recovery-verb-exit-3"),
            (124, log.read_text(), "recovery-verb-timeout"),
            (4, log.read_text(), "recovery-verb-exit"),
            (1, '{"event":"recover.journal_blocked","reason":"publication"}\n',
             "recovery-verb-blocked:publication"),
        ):
            log.write_text(contents)
            with self.assertRaises(runner.Refused) as caught:
                completion(dict(receipt, exit_code=rc))
            self.assertEqual(str(caught.exception), reason)

        missing_event = root / "operator-incomplete.log"
        missing_event.write_text("JournalFinished: incomplete without JSON event\n")
        with self.assertRaises(runner.Refused) as caught:
            completion({"exit_code": 0, "raw_log": str(missing_event)})
        self.assertEqual(str(caught.exception), "recovery-verb-incomplete")

        nothing = root / "operator-nothing.log"
        nothing.write_text('{"event":"recover.nothing"}\n')
        with self.assertRaises(runner.Refused) as caught:
            completion({"exit_code": 0, "raw_log": str(nothing)})
        self.assertEqual(str(caught.exception), "recovery-verb-nothing-owed")

        fence = root / "operator-fence.log"
        fence.write_text('{"event":"recover.fence_settled","how":"landed"}\n')
        with self.assertRaises(runner.Refused) as caught:
            completion({"exit_code": 0, "raw_log": str(fence)})
        self.assertEqual(str(caught.exception), "recovery-verb-incomplete")

        wrong_landing = root / "operator-wrong-landing.log"
        wrong_landing.write_text('{"event":"recover.landed","seq":8}\n')
        with self.assertRaises(runner.Refused) as caught:
            completion({"exit_code": 0, "raw_log": str(wrong_landing)})
        self.assertEqual(str(caught.exception), "recovery-verb-incomplete")
        with self.assertRaises(runner.Refused) as caught:
            completion(landed_receipt, {"sequence": 8, "identifier": "01" + "e" * 64})
        self.assertEqual(
            str(caught.exception), "recovery-verb-head-mismatch: sequence"
        )
        with self.assertRaises(runner.Refused) as caught:
            completion(landed_receipt, {"sequence": 9, "identifier": None})
        self.assertEqual(
            str(caught.exception), "recovery-verb-head-mismatch: identifier"
        )

        comparison = {
            "prepared_root_id": expected_selection["root"],
            "published_root_id": "blake3:" + "e" * 64,
            "prepared_seq": "9",
            "published_seq": "9",
            "prepared_parent": "blake3:" + "a" * 64,
            "published_parent": "blake3:" + "a" * 64,
            "prepared_manifest_root": "blake3:" + "b" * 64,
            "published_manifest_root": "blake3:" + "b" * 64,
            "prepared_writer": "01" * 16,
            "published_writer": "01" * 16,
            "field_diff": "signature_0",
        }
        readback = runner.validate_recovery_root_evidence(
            expected_selection,
            9,
            {"sequence": 8, "identifier": "01" + "c" * 64},
            expected_head,
            "01" * 16,
            "released",
            comparison,
        )
        self.assertEqual(readback["head"], expected_head)
        self.assertFalse(readback["published_root_byte_identical"])
        self.assertTrue(readback["exact_branch_byte_mismatch"])
        self.assertEqual(readback["decoded_field_diff"], ["signature_0"])

        manifest_mismatch = dict(
            comparison, published_manifest_root="blake3:" + "c" * 64
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_recovery_root_evidence(
                expected_selection,
                9,
                {"sequence": 8, "identifier": "01" + "c" * 64},
                expected_head,
                "01" * 16,
                "released",
                manifest_mismatch,
            )
        self.assertEqual(str(caught.exception), "recovery-root-manifest-mismatch")

        with self.assertRaises(runner.Refused) as caught:
            runner.validate_recovery_root_evidence(
                expected_selection,
                9,
                {"sequence": 8, "identifier": "01" + "c" * 64},
                dict(expected_head, identifier="01" + "f" * 64),
                "01" * 16,
                "released",
                comparison,
            )
        self.assertEqual(
            str(caught.exception), "recovery-chain-root-mismatch: identifier"
        )
        evidence_cases = (
            (
                "recovery-root-evidence-invalid",
                expected_selection,
                expected_head,
                "01" * 16,
                "released",
                {name: value for name, value in comparison.items() if name != "field_diff"},
            ),
            (
                "recovery-root-evidence-invalid",
                expected_selection,
                expected_head,
                "01" * 16,
                "released",
                dict(comparison, prepared_parent="bad"),
            ),
            (
                "recovery-root-evidence-invalid",
                expected_selection,
                expected_head,
                "01" * 16,
                "released",
                dict(comparison, prepared_manifest_root="bad"),
            ),
            (
                "recovery-root-evidence-invalid",
                expected_selection,
                expected_head,
                "01" * 16,
                "released",
                dict(comparison, prepared_writer="bad"),
            ),
            (
                "recovery-selection-root-mismatch",
                dict(expected_selection, root="blake3:" + "0" * 64),
                expected_head,
                "01" * 16,
                "released",
                comparison,
            ),
            (
                "recovery-root-sequence-mismatch",
                expected_selection,
                expected_head,
                "01" * 16,
                "released",
                dict(comparison, published_seq="10"),
            ),
            (
                "recovery-root-parent-mismatch",
                expected_selection,
                expected_head,
                "01" * 16,
                "released",
                dict(comparison, published_parent="blake3:" + "0" * 64),
            ),
            (
                "recovery-root-writer-mismatch",
                expected_selection,
                expected_head,
                "01" * 16,
                "released",
                dict(comparison, published_writer="02" * 16),
            ),
            (
                "recovery-chain-root-mismatch: sequence",
                expected_selection,
                dict(expected_head, sequence=10),
                "01" * 16,
                "released",
                comparison,
            ),
            (
                "recovery-authority-writer-state",
                expected_selection,
                expected_head,
                "01" * 16,
                "retained",
                comparison,
            ),
            (
                "recovery-root-field-diff-invalid",
                expected_selection,
                expected_head,
                "01" * 16,
                "released",
                dict(comparison, field_diff="none"),
            ),
        )
        for reason, selection_value, chain, writer, state, fields in evidence_cases:
            with self.subTest(root_evidence=reason, fields=fields):
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate_recovery_root_evidence(
                        selection_value,
                        9,
                        {"sequence": 8, "identifier": "01" + "c" * 64},
                        chain,
                        writer,
                        state,
                        fields,
                    )
                self.assertEqual(str(caught.exception), reason)

        selection_log = root / "operator-selection.log"
        selection_log.write_text(
            "gran recover: IntentSelectionBinding: --acknowledge-takeover must name "
            "--writer; selected E=3 G=4 root="
            + expected_selection["root"]
            + " parent_seq=8\n"
        )
        selection_receipt = {"exit_code": 1, "raw_log": str(selection_log)}
        store = root / "image/root/store"
        self.assertEqual(
            runner.phase_one_selection(selection_receipt, store, expected_selection)[1],
            expected_selection,
        )
        mismatch = dict(expected_selection, generation=5)
        with self.assertRaises(runner.Refused) as caught:
            runner.phase_one_selection(selection_receipt, store, mismatch)
        self.assertEqual(str(caught.exception), "recovery-selection-mismatch")

        runner.private_signal(
            handoff / "client-intent-selection-1",
            ("3 4 " + expected_selection["root"] + " 8").encode(),
        )
        self.assertEqual(runner.intent_selection(handoff), expected_selection)

        ledger_path = Path(self.temporary.name) / "external-ledger.jsonl"
        ledger_path.write_text(
            '{"cumulative_write_call_bytes":4,"kind":"write-call-bytes"}\n'
            '{"content_sha256":"' + "a" * 64
            + '","cumulative_write_call_bytes":4,"kind":"successful-fsync",'
            '"operation_id":"a-0000","unique_content_bytes":4}\n'
            '{"cumulative_write_call_bytes":7,"kind":"write-call-bytes"}\n'
        )
        observed_ledger, write_bytes, ledger_digest = runner.read_workload_ledger(
            ledger_path
        )
        self.assertEqual([item["operation_id"] for item in observed_ledger], ["a-0000"])
        self.assertEqual(write_bytes, 7)
        self.assertEqual(ledger_digest, hashlib.sha256(ledger_path.read_bytes()).hexdigest())
        ledger_rows = [
            {"kind": "write-call-bytes", "cumulative_write_call_bytes": 4},
            {
                "kind": "successful-fsync",
                "operation_id": "a-0000",
                "content_sha256": "a" * 64,
                "unique_content_bytes": 4,
                "cumulative_write_call_bytes": 4,
            },
        ]

        def invalid_ledger(name, rows):
            path = Path(self.temporary.name) / f"invalid-ledger-{name}.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            return path

        ledger_cases = (
            (
                "recovery-ledger-row-invalid",
                invalid_ledger("kind", [{"kind": 1}]),
            ),
            (
                "recovery-ledger-counter-record-invalid",
                invalid_ledger(
                    "counter",
                    [{"kind": "write-call-bytes", "cumulative_write_call_bytes": 0}],
                ),
            ),
            (
                "recovery-ledger-fsync-record-invalid",
                invalid_ledger(
                    "fsync",
                    [ledger_rows[0], {**ledger_rows[1], "content_sha256": "bad"}],
                ),
            ),
            (
                "recovery-ledger-counter-mismatch",
                invalid_ledger(
                    "binding",
                    [ledger_rows[0], {**ledger_rows[1], "cumulative_write_call_bytes": 5}],
                ),
            ),
            (
                "recovery-ledger-sequence-invalid",
                invalid_ledger("no-fsync", [ledger_rows[0]]),
            ),
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.read_workload_ledger(Path("relative-ledger.jsonl"))
        self.assertEqual(str(caught.exception), "recovery-ledger-path")
        for reason, path in ledger_cases:
            with self.subTest(ledger=path.name):
                with self.assertRaises(runner.Refused) as caught:
                    runner.read_workload_ledger(path)
                self.assertEqual(str(caught.exception), reason)
        commands = runner.loss_image_commands(
            Path(self.temporary.name) / "loss.img",
            Path(self.temporary.name) / "client-image",
            4_294_967_296,
        )
        self.assertEqual(
            [command[0] for command in commands],
            ["umount", "truncate", "mkfs.ext4", "mount"],
        )
        with patch.dict(os.environ, {"GRANARY_Q3_LOOP_DEVICE": "/dev/loop7"}):
            commands = runner.loss_image_commands(
                Path(self.temporary.name) / "loss.img",
                Path(self.temporary.name) / "client-image",
                4_294_967_296,
            )
        self.assertEqual(commands[-1][2], "loop=/dev/loop7")
        with patch.dict(os.environ, {"GRANARY_Q3_LOOP_DEVICE": "/dev/loop-control"}):
            with self.assertRaises(runner.Refused) as caught:
                runner.loss_image_commands(
                    Path(self.temporary.name) / "loss.img",
                    Path(self.temporary.name) / "client-image",
                    4_294_967_296,
                )
        self.assertEqual(str(caught.exception), "loop-device-invalid")
        venue_images = [Path(self.temporary.name) / f"reservation-{index}.img" for index in range(3)]
        for path in venue_images:
            path.write_bytes(b"reserved")
        venue_loops = {
            "GRANARY_Q3_LOOP_DEVICES": "/dev/loop70,/dev/loop71,/dev/loop72",
            "GRANARY_Q3_LOOP_IMAGES": ",".join(str(path) for path in venue_images),
        }
        venue_mount = Path(self.temporary.name) / "venue-client-image"
        with patch.dict(os.environ, venue_loops, clear=True):
            self.assertEqual(runner.recovery_image(Path(self.temporary.name)), venue_images[0])
            self.assertEqual(runner.replacement_image(venue_images[0]), venue_images[1])
            self.assertEqual(
                runner.mount_image_command(venue_images[1], venue_mount),
                ["mount", "--", "/dev/loop71", str(venue_mount)],
            )
            capacity_calls = []

            def capacity_command(argv, stem, **options):
                capacity_calls.append((argv, stem, options))
                return "4096\n" if stem == "image-loop-capacity-size" else ""

            runner.create_and_mount_recovery_image(
                venue_images[1],
                venue_mount,
                4096,
                command=capacity_command,
                cwd=Path(self.temporary.name),
            )
            self.assertEqual(
                [(call[0][:2], call[1]) for call in capacity_calls],
                [
                    (["truncate", "-s"], "image-create"),
                    (["mkfs.ext4", "-q"], "image-format"),
                    (["losetup", "-c"], "image-loop-capacity-refresh"),
                    (["blockdev", "--getsize64"], "image-loop-capacity-size"),
                    (["mount", "--"], "image-mount"),
                ],
            )
            with self.assertRaises(runner.Refused) as caught:
                runner.refresh_loop_capacity(
                    venue_images[1],
                    4096,
                    command=lambda *_args, **_options: "2048\n",
                    cwd=Path(self.temporary.name),
                )
            self.assertEqual(str(caught.exception), "loop-device-size-mismatch")
        with self.assertRaises(runner.Refused) as caught:
            runner.loss_image_commands(
                Path(self.temporary.name) / "loss.img",
                Path(self.temporary.name) / "client-image",
                4_294_967_297,
            )
        self.assertEqual(str(caught.exception), "loss-image-size")

        image = Path(self.temporary.name) / "loop-reservation-0.img"
        image.write_bytes(b"old")
        mountpoint = Path(self.temporary.name) / "owned-mount"
        (mountpoint / "root/store").mkdir(parents=True)
        (mountpoint / "root/cache").mkdir()
        custody = []
        for name in ("seed", "certificate", "credential"):
            path = Path(self.temporary.name) / name
            path.write_text(name)
            custody.append(path)
        handoff = Path(self.temporary.name) / "image-handoff"
        handoff.mkdir()
        outcome_evidence = Path(self.temporary.name) / "outcome-evidence"
        outcome_evidence.mkdir()
        runner.private_signal(handoff / "client-root-device", b"7")
        calls = []
        image_fault = {
            "before_uuid": "old-uuid\n",
            "after_uuid": "new-uuid\n",
            "remove_old_paths": True,
            "created_size": 4096,
            "change_key": False,
        }

        def image_command(command, stem, **options):
            calls.append((command, stem, options))
            if stem == "client-fuse-mount":
                return "fuse.granary 0:73\n"
            if stem == "loss-image-uuid-before":
                return image_fault["before_uuid"]
            if stem == "loss-image-unmount" and image_fault["remove_old_paths"]:
                (mountpoint / "root/store").rmdir()
                (mountpoint / "root/cache").rmdir()
                (mountpoint / "root").rmdir()
            if stem == "loss-image-create":
                target = Path(command[-1])
                with target.open("r+b" if target.exists() else "xb") as output:
                    output.truncate(image_fault["created_size"])
            if stem.endswith("-loop-capacity-size"):
                return f"{image_fault['created_size']}\n"
            if stem == "loss-image-uuid-after":
                if image_fault["change_key"]:
                    custody[0].write_text("changed")
                return image_fault["after_uuid"]
            if stem == "loss-root-device":
                device = mountpoint.stat().st_dev
                return f"{os.major(device)}:{os.minor(device)}\n"
            return ""

        running = {"finished": False}
        with (
            patch.object(
                runner,
                "finish_command",
                return_value={"exit_code": -signal.SIGKILL},
            ) as finish,
            patch.object(
                runner,
                "refresh_and_mount_image",
                wraps=runner.refresh_and_mount_image,
            ) as refresh_mount,
        ):
            client_record, witness = runner.replace_owned_client_image(
                running,
                image,
                mountpoint,
                4096,
                custody,
                handoff,
                outcome_evidence,
                command=image_command,
                abort=lambda path: calls.append((["abort", str(path)], "client-fuse-abort", {})),
            )
        finish.assert_called_once_with(running, timeout=1, stop_signal=signal.SIGKILL)
        self.assertEqual(
            refresh_mount.call_args.args[:3],
            (image.resolve(), mountpoint.resolve(), 4096),
        )
        self.assertEqual(client_record["exit_code"], -signal.SIGKILL)
        self.assertEqual(
            (witness["before_image_uuid"], witness["after_image_uuid"]),
            ("old-uuid", "new-uuid"),
        )
        self.assertEqual(len(calls), 10)
        self.assertEqual(
            (witness["before_root_device"], witness["after_root_device"], witness["replacement_root_device"]),
            (7, mountpoint.stat().st_dev, mountpoint.stat().st_dev),
        )
        self.assertEqual(
            calls[1][0][-1],
            str(mountpoint.resolve() / "root/mount"),
            "the FUSE mount is below the image's private root subdirectory",
        )
        self.assertTrue(
            all(
                call[2].get("cwd") == outcome_evidence.resolve()
                for call in calls
                if call[1] != "client-fuse-abort"
            ),
            "all loss command evidence stays in its outcome directory",
        )

        def reset_image_fault(**changes):
            image.unlink(missing_ok=True)
            image.write_bytes(b"old")
            (mountpoint / "root/store").mkdir(parents=True, exist_ok=True)
            (mountpoint / "root/cache").mkdir(exist_ok=True)
            for path in custody:
                path.write_text(path.name)
            (handoff / "client-root-device").write_text("7")
            (handoff / "client-root-device").chmod(0o600)
            image_fault.update(
                before_uuid="old-uuid\n",
                after_uuid="new-uuid\n",
                remove_old_paths=True,
                created_size=4096,
                change_key=False,
            )
            image_fault.update(changes)

        reset_image_fault()
        pair_images = [image.resolve()] + [
            (Path(self.temporary.name) / f"loop-reservation-{index}.img").resolve()
            for index in (1, 2)
        ]
        for path in pair_images[1:]:
            path.write_bytes(b"reserved")
        pairs = [(f"/dev/loop{70 + index}", path) for index, path in enumerate(pair_images)]
        venue_pair_environment = {
            "GRANARY_Q3_LOOP_DEVICES": ",".join(device for device, _ in pairs),
            "GRANARY_Q3_LOOP_IMAGES": ",".join(str(path) for _, path in pairs),
        }
        with (
            patch.dict(os.environ, venue_pair_environment, clear=True),
            patch.object(runner, "replace_client_root_device_witness", return_value=(7, 8, 8)),
            patch.object(
                runner,
                "refresh_and_mount_image",
                wraps=runner.refresh_and_mount_image,
            ) as pair_refresh,
        ):
            for index, current_image in enumerate(pair_images[:2]):
                if index:
                    (mountpoint / "root/store").mkdir(parents=True)
                    (mountpoint / "root/cache").mkdir()
                    (handoff / "client-root-device").write_text("7")
                    (handoff / "client-root-device").chmod(0o600)
                calls.clear()
                evidence = Path(self.temporary.name) / f"pair-outcome-{index}"
                evidence.mkdir()
                runner.create_and_mount_recovery_image(
                    current_image,
                    mountpoint,
                    4096,
                    command=image_command,
                    cwd=evidence.resolve(),
                )
                with patch.object(
                    runner, "finish_command", return_value={"exit_code": -signal.SIGKILL}
                ):
                    record, _ = runner.replace_owned_client_image(
                        {"finished": False}, current_image, mountpoint, 4096,
                        custody, handoff, evidence, command=image_command,
                        abort=lambda _path: None,
                    )
                self.assertEqual(record["exit_code"], -signal.SIGKILL)
                self.assertEqual(pair_refresh.call_args.args[0], pair_images[index + 1])
                stems = [stem for _command, stem, _options in calls]
                self.assertEqual(len(stems), len(set(stems)))
                self.assertEqual(
                    [call[2].get("cwd") for call in calls],
                    [evidence.resolve()] * len(calls),
                )

        def image_refuses(reason, paths=None):
            with (
                patch.object(
                    runner,
                    "finish_command",
                    return_value={"exit_code": -signal.SIGKILL},
                ),
                self.assertRaises(runner.Refused) as caught,
            ):
                runner.replace_owned_client_image(
                    {"finished": False},
                    image,
                    mountpoint,
                    4096,
                    custody if paths is None else paths,
                    handoff,
                    outcome_evidence,
                    command=image_command,
                    abort=lambda _path: None,
                )
            self.assertEqual(str(caught.exception), reason)

        reset_image_fault()
        with self.assertRaises(runner.Refused) as caught:
            runner.replace_owned_client_image(
                {"finished": False}, image, mountpoint, 4096, custody, handoff,
                mountpoint, command=image_command, abort=lambda _path: None,
            )
        self.assertEqual(str(caught.exception), "loss-image-evidence-path")
        with self.assertRaises(runner.Refused) as caught:
            runner.replace_owned_client_image(
                {"finished": False},
                mountpoint,
                mountpoint,
                4096,
                custody,
                handoff,
                outcome_evidence,
            )
        self.assertEqual(str(caught.exception), "loss-image-witness")
        reset_image_fault()
        image_refuses("recovery-key-custody", custody[:2])
        for reason, fault in (
            ("loss-image-uuid-witness", {"before_uuid": ""}),
            ("loss-old-path-witness", {"remove_old_paths": False}),
            ("loss-image-size-witness", {"created_size": 4095}),
            ("loss-image-witness", {"after_uuid": "old-uuid\n"}),
            ("recovery-key-survival", {"change_key": True}),
        ):
            with self.subTest(image_guard=reason):
                reset_image_fault(**fault)
                image_refuses(reason)

        device_handoff = Path(self.temporary.name) / "device-handoff"
        device_handoff.mkdir()
        runner.private_signal(device_handoff / "client-root-device", b"11")

        def device_stat(path):
            return Mock(st_dev=22) if Path(path) == mountpoint else Mock(st_rdev=22)

        with patch.object(runner, "venue_loop_pairs", return_value=[("/dev/loop9", image)]):
            self.assertEqual(
                runner.replace_client_root_device_witness(
                    device_handoff,
                    image,
                    mountpoint,
                    outcome_evidence,
                    stat=device_stat,
                ),
                (11, 22, 22),
            )
        self.assertEqual((device_handoff / "client-root-device").read_text(), "22")
        (device_handoff / "client-root-device").write_text("11")
        with (
            patch.object(runner, "venue_loop_pairs", return_value=[("/dev/loop9", image)]),
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.replace_client_root_device_witness(
                device_handoff,
                image,
                mountpoint,
                outcome_evidence,
                stat=lambda path: Mock(st_dev=22) if Path(path) == mountpoint else Mock(st_rdev=23),
            )
        self.assertEqual(str(caught.exception), "loss-root-device-witness")
        self.assertEqual((device_handoff / "client-root-device").read_text(), "11")

    def test_recovery_detaches_only_the_owned_fuse_mount_before_the_image(self):
        events = []
        running = {"finished": False}
        mountpoint = Path(self.temporary.name) / "image" / "mount"

        def finish(value, **options):
            events.append(("stop", value, options))
            value["finished"] = True
            return {"exit_code": -signal.SIGKILL}

        def command(argv, stem, **_):
            events.append((stem, argv))
            if stem == "client-fuse-mount":
                return "fuse.granary 0:73\n"
            return ""

        def abort(path):
            events.append(("abort", path))

        with patch.object(runner, "finish_command", side_effect=finish):
            record = runner.stop_client_and_detach_fuse(
                running,
                mountpoint,
                Path(self.temporary.name),
                command=command,
                abort=abort,
            )
        self.assertEqual(record["exit_code"], -signal.SIGKILL)
        self.assertEqual(
            events,
            [
                ("stop", running, {"timeout": 1, "stop_signal": signal.SIGKILL}),
                (
                    "client-fuse-mount",
                    ["findmnt", "-n", "-o", "FSTYPE,MAJ:MIN", "--target", str(mountpoint)],
                ),
                ("abort", Path("/sys/fs/fuse/connections/73/abort")),
                ("client-fuse-unmount", ["umount", "-l", "--", str(mountpoint)]),
            ],
        )

        uuid_calls = []

        def uuid_command(argv, stem, **options):
            uuid_calls.append((argv, stem, options))
            return "observed-uuid\n"

        self.assertEqual(
            runner.observe_intact_image_uuid(
                Path(self.temporary.name) / "client.img",
                "observed-uuid",
                Path(self.temporary.name),
                command=uuid_command,
            ),
            "observed-uuid",
        )
        self.assertEqual(uuid_calls[0][1], "intact-image-uuid-after")
        with self.assertRaises(runner.Refused) as caught:
            runner.observe_intact_image_uuid(
                Path(self.temporary.name) / "client.img",
                "inferred-before-uuid",
                Path(self.temporary.name),
                command=uuid_command,
            )
        self.assertEqual(str(caught.exception), "intact-image-witness")

        cleanup = {"finished": False}
        with patch.object(runner, "stop_client_and_detach_fuse") as stop:
            runner.abort_restarted_client(
                cleanup, mountpoint, Path(self.temporary.name)
            )
        stop.assert_called_once_with(
            cleanup,
            mountpoint,
            Path(self.temporary.name),
            stem_prefix="restart-client-fuse",
        )

        cleanup = {"finished": False}
        with (
            patch.object(runner, "abort_restarted_client") as abort_restart,
            self.assertRaisesRegex(RuntimeError, "probe failed"),
        ):
            with runner.owned_restarted_client(
                cleanup, mountpoint, Path(self.temporary.name)
            ):
                raise RuntimeError("probe failed")
        abort_restart.assert_called_once_with(
            cleanup, mountpoint, Path(self.temporary.name)
        )

    def test_recovery_handoff_reset_retires_runner_step_gates(self):
        handoff = Path(self.temporary.name) / "recovery-handoff"
        handoff.mkdir()
        preserved = (
            "client-cert-path",
            "client-credential-path",
            "client-root-device",
            "client-root-path",
            "client-sync-profile",
        )
        transient = (
            "client-runner-gates-steps",
            "runner-next-0",
            "workload-next-0",
        )
        for name in preserved + transient:
            runner.private_signal(
                handoff / name, b"7" if name == "client-root-device" else b""
            )
        log = Path(self.temporary.name) / "client-restart.jsonl"
        runner.reset_client_handoff(handoff, log, 1)
        self.assertTrue(all((handoff / name).is_file() for name in preserved))
        self.assertEqual((handoff / "client-root-device").read_text(), "7")
        self.assertTrue(all(not (handoff / name).exists() for name in transient))
        self.assertEqual((handoff / "client-probe-index").read_text(), "1")
        self.assertEqual(os.fsdecode((handoff / "client-log-path").read_bytes()), str(log))

    def test_real_pivot_assembly_carries_population_and_provenance(self):
        work = Path(self.temporary.name) / "pivot-work"
        work.mkdir()
        include_log_wait = True
        include_pilot = True
        terminal_artifacts = None
        numerator_samples = [30_000_000] * 1000
        field_mutation = None
        sample_count_overrides = {}
        export = dict(line.split("\t") for line in PIVOT_DEPTH_EXPORT.splitlines())
        records = denominator_depth_fixture(1000)["depth_records"]
        trace = ";".join(",".join(map(str, record)) for record in records)
        self.assertEqual(hashlib.sha256(trace.encode()).hexdigest(), export.pop("depth_trace_sha256"))
        export["denominator_attempt_depth_records"] = trace
        started_with = []
        rust_stalled_fields = dict(
            line.split("\t", 1)
            for line in (Path(__file__).parent / "q3-pivot-stalled-fields.tsv")
            .read_text()
            .splitlines()
            if not line.startswith("#")
        )
        venue_environment = {
            "GRANARY_Q3_REVISION": "0123456789abcdef0123456789abcdef01234567",
            "GRANARY_Q3_VENUE": "vm",
            "GRANARY_STORE": "s3:",
            "GRANARY_STORE_BUCKET": "granary-test",
            "GRANARY_STORE_ENDPOINT": "http://127.0.0.1:19189",
            "GRANARY_STORE_REGION": "us-east-1",
            "AWS_ACCESS_KEY_ID": "fixture-access",
            "AWS_SECRET_ACCESS_KEY": "fixture-secret",
        }

        def start(command, stem, *, cwd, environment, **___):
            role = stem.removeprefix("pivot-server-")
            started_with.append(environment)
            output = Path(cwd) / "output"
            name = {
                "numerator": "pivot_numerator",
                "denominator": "pivot_denominator",
                "diagnostic": "pivot_same_occupancy_publish",
            }[role]
            sample = output / f"{name}.ns"
            sample_count = sample_count_overrides.get(
                role, 368 if role == "diagnostic" else 1000
            )
            values = (
                numerator_samples
                if role == "numerator" and numerator_samples is not None
                else [10_000_000] * sample_count
            )
            self.write_duration_fixture(sample, values)
            completion = output / f"{name}-completion.ns"
            if role == "denominator":
                self.write_duration_fixture(completion, [3_000_000] * sample_count)
            fields = {
                    "profile": "DurablePrepared" if role == "numerator" else "Published",
                    "occupancy": "Floor" if role == "denominator" else "Ceiling",
                    "samples_file": sample.name,
                    "sample_count": str(sample_count),
                    "stream_count": (
                        "16" if role == "numerator" else "1" if role == "diagnostic" else "64"
                    ),
                    "stream_sample_counts": (
                        ",".join(["63"] * 8 + ["62"] * 8)
                        if role == "numerator"
                        else str(sample_count)
                        if role == "diagnostic"
                        else ",".join(["16"] * 40 + ["15"] * 24)
                    ),
                    "p99_ns": (
                        "0"
                        if not values
                        else str(sorted(values)[math.ceil(sample_count * 0.99) - 1])
                    ),
                    "load_model": (
                        "closed-loop-serial" if role == "diagnostic" else "open-loop"
                    ),
                    "pivot_input": "false" if role == "diagnostic" else "true",
                    "pivot_stream_plan": runner.PIVOT_STREAM_PLAN,
                    "store_kind": "AmazonS3(fixture)",
                    "log_filesystem": "ext4",
                    "wrapper_layer": "server-service",
                    "committed_transitions": "1064" if role == "numerator" else "0",
                    "pivot_warmup_count": str(runner.PIVOT_WARMUP_COUNT),
                    "pivot_warmup_elapsed_ns": "1391304352",
                    "root_label": "measured length" if role == "denominator" else "707-B",
                    "root_bytes": "652" if role == "denominator" else "707",
                    "root_size_distribution": (
                        "652:16" if role == "denominator" else "707:256"
                    ),
                    "row_holders": "1" if role == "denominator" else "16",
                    "zero_row_principals": "0" if role == "denominator" else "16368",
                    "retired_principals": "0",
                    "historical_principals": "1" if role == "denominator" else "16384",
                    "live_roots": "16" if role == "denominator" else "256",
                    "released_rows": "48" if role == "denominator" else "768",
            }
            if role == "diagnostic":
                fields["diagnostic_label"] = runner.PIVOT_DIAGNOSTIC_LABEL
                fields.update(
                    diagnostic_outcome="complete",
                    diagnostic_completed_count=str(runner.PIVOT_WARMUP_COUNT + sample_count),
                    diagnostic_stall_index="none",
                    diagnostic_stall_phase="none",
                    diagnostic_publish_bound_ns="100000000",
                    diagnostic_publish_censored_count="0",
                    diagnostic_publish_p99_report="10000000",
                    diagnostic_publish_stalls="0",
                    diagnostic_publish_stall_ns="none",
                    diagnostic_warmup_publish_stalls="0",
                    diagnostic_warmup_publish_stall_ns="none",
                    diagnostic_completion_bound_ns="2000000000",
                    diagnostic_completion_stalls="0",
                    diagnostic_completion_stall_ns="none",
                    diagnostic_completion_stall_issue="#832",
                )
            else:
                stream_count = 16 if role == "numerator" else 64
                fields.update(
                    offered_rate="46",
                    achieved_rate="46",
                    principal_submission_limit="1000000",
                    principal_in_flight_limit="4",
                    per_stream_offered_rate=str(46 / stream_count),
                )
            if include_log_wait:
                fields["authority_log_wait_p99_ns"] = "1000"
            if role == "numerator":
                fields.update({key: value for key, value in export.items() if key.startswith("numerator_")})
            if role == "diagnostic":
                fields["diagnostic_depth_range"] = export["diagnostic_depth_range"] if sample_count else "none"
            if role == "denominator":
                fields.update({key: value for key, value in export.items() if key.startswith("denominator_")})
                fields.update(
                    completion_samples_file=completion.name,
                    completion_sample_count=str(sample_count),
                    pivot_branch="normal",
                    denominator_label="offered-rate denominator",
                    denominator_attempt_rates="46",
                    denominator_attempt_warmups="64,1391304352",
                    denominator_attempt_achieved_rates="46",
                    denominator_attempt_outcomes="passed",
                    denominator_attempt_sent_counts="1000",
                    denominator_attempt_first_refusal_ns="0",
                    denominator_attempt_conflict_tokens="none",
                    denominator_attempt_response_tokens="none",
                    denominator_attempt_rate_limited_counts="0",
                    denominator_attempt_max_outstanding="4",
                    denominator_attempt_max_outstanding_per_stream=(
                        ",".join(["1"] * 64)
                    ),
                    denominator_attempt_stream_sample_counts=(
                        ",".join(["16"] * 40 + ["15"] * 24)
                    ),
                    denominator_attempt_sample_files=sample.name,
                    denominator_attempt_sample_counts=str(sample_count),
                    denominator_attempt_completion_files=completion.name,
                    denominator_attempt_completion_counts=str(sample_count),
                    denominator_attempt_log_wait_p99_ns="1000",
                    denominator_attempt_cycle_stall_bound_ns="400000000",
                    denominator_attempt_cycle_stall_counts="1",
                    denominator_attempt_cycle_stall_ns="450000000;" + ",".join(["2000000000"] * sample_count) + ";2000000000",
                    denominator_attempt_refusal_cycle_ns="none",
                    denominator_cycle_stall_issue="#832",
                )
            if role == "denominator" and include_pilot:
                fields.update(
                    denominator_attempt_pilot_observations="32,20000000,40000000,45000000,64",
                    denominator_attempt_pilot_p99_ns="40000000",
                    pilot_sample_count="32",
                    pilot_p50_ns="20000000",
                    pilot_p99_ns="40000000",
                    pilot_max_ns="45000000",
                    pilot_stream_count="64",
                    pilot_sizing_basis="observation-only-fixed-rate-pool",
                )
            if role == "denominator" and terminal_artifacts is not None:
                for filename, values in terminal_artifacts:
                    self.write_duration_fixture(output / filename, values)
            if field_mutation is not None:
                field_mutation(role, fields)
            (output / f"{name}.tsv").write_text(
                "".join(f"{key}\t{value}\n" for key, value in fields.items())
            )
            progress = output / runner.PIVOT_RUNS[role][2]
            progress.write_text("phase\toffset_ns\nrow-start\t0\n")
            log = Path(cwd) / f"pivot-server-{role}.log"
            rc = Path(cwd) / f"pivot-server-{role}.rc"
            log.write_text("pivot fixture\n")
            rc.write_text("0\n")
            receipts[role] = dict(
                command=["pivot-server", role, "--ignored"],
                exit_code=0,
                run_root=str(Path(cwd).resolve()),
                raw_log=str(log),
                raw_rc=str(rc),
                raw_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
                raw_rc_sha256=hashlib.sha256(rc.read_bytes()).hexdigest(),
                started_at="2026-11-17T12:00:00Z",
            )
            return {"finished": False, "role": role, "command": command}

        receipts = {}
        for role in runner.PIVOT_RUNS:
            log = work / f"pivot-server-{role}.log"
            rc = work / f"pivot-server-{role}.rc"
            log.write_text("pivot fixture\n")
            rc.write_text("0\n")
            receipts[role] = dict(
                command=["pivot-server", role, "--ignored"],
                exit_code=0,
                run_root=str(work),
                raw_log=str(log),
                raw_rc=str(rc),
                raw_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
                raw_rc_sha256=hashlib.sha256(rc.read_bytes()).hexdigest(),
                started_at="2026-11-17T12:00:00Z",
            )

        def finish(running, **_):
            return receipts[running["role"]]
        with (
            patch.dict(
                os.environ,
                venue_environment,
                clear=True,
            ),
            patch.object(runner, "start_command", side_effect=start),
            patch.object(runner, "finish_command", side_effect=finish),
        ):
            result = runner.run_pivot_measurement(
                "pivot-server", work, resource_check=lambda _work: None
            )
        self.assertEqual(runner.validate(result), 3)
        self.assertEqual(result["verdict"], "pivot")
        for row in result["rows"]:
            self.assertFalse(row["deciding"])
            self.assertFalse(row["pivot_append"])
            self.assertEqual(
                row["pivot_scope"],
                "denominator measured on young volumes, pre-publish chain depth ≤ 16; "
                "numerator register generations 2–68, final intent log 123456 bytes",
            )
        for role, index in (("numerator", 0), ("denominator", 1), ("diagnostic", None)):
            for field in ("deciding", "pivot_append"):
                with self.subTest(role=role, field=field):
                    invalid = copy.deepcopy(result)
                    row = invalid["diagnostic"] if index is None else invalid["rows"][index]
                    self.assertIs(row[field], False)
                    row[field] = True
                    with self.assertRaisesRegex(runner.Refused, "^pivot-vm-admissibility$"):
                        runner.validate(invalid)
        invalid_diagnostic_provenance = dict(
            result["diagnostic"], raw_log_sha256="0" * 64
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot_diagnostic(invalid_diagnostic_provenance)
        self.assertEqual(str(caught.exception), "raw-log-hash-mismatch")
        document_cases = (
            ("pivot-document-verdict-invalid", lambda value: value.update(verdict="no pivot")),
            ("pivot-document-commands-invalid", lambda value: value.update(commands=None)),
            ("pivot-document-child-timing-invalid", lambda value: value.update(child_elapsed_seconds=None)),
            ("pivot-document-progress-invalid", lambda value: value.update(progress_artifacts=None)),
            ("schema-row-not-object", lambda value: value.update(rows=[1, 2])),
            ("schema-unknown: bogus_field", lambda value: value["rows"][0].update(bogus_field=1)),
            ("vm-sample-labelled-hardware", lambda value: value["rows"][0].update(hardware=True)),
            (
                "schema-unknown: pivot_steady_issue",
                lambda value: value["diagnostic"].update(pivot_steady_issue=None),
            ),
            ("pivot-document-provenance-invalid", lambda value: value["diagnostic"].update(revision="f" * 40)),
            ("pivot-document-commands-invalid", lambda value: value["rows"][0].update(command=value["rows"][1]["command"])),
            ("pivot-venue-unrecorded", lambda value: [row.pop("venue") for row in value["rows"]]),
            ("pivot-pair-roles", lambda value: value["rows"][0].update(pivot_role=[])),
        )
        for reason, mutate in document_cases:
            invalid = json.loads(json.dumps(result))
            mutate(invalid)
            with self.assertRaises(runner.Refused) as caught:
                runner.validate(invalid)
            self.assertEqual(str(caught.exception), reason)
        self.assertEqual(result["event"], "pivot")
        self.assertEqual(
            result["child_bound_seconds"],
            {"numerator": 137, "denominator": 780, "diagnostic": 1198},
        )
        self.assertTrue(all(value >= 0 for value in result["child_elapsed_seconds"].values()))
        expected_environment = {
                **{name: venue_environment[name] for name in runner.LOOPBACK_STORE_ENV},
                "GRANARY_MEASURE_OUTPUT": str((work / "output").resolve()),
                "GRANARY_Q3_VENUE": "vm",
        }
        self.assertEqual(started_with, [expected_environment] * 3)
        self.assertTrue(all(row["sample_count"] == 1000 for row in result["rows"]))
        self.assertEqual(result["diagnostic"]["sample_count"], 368)
        self.assertEqual(result["diagnostic"]["load_model"], "closed-loop-serial")
        self.assertEqual(
            result["diagnostic"]["diagnostic_label"],
            runner.PIVOT_DIAGNOSTIC_LABEL,
        )
        self.assertFalse(result["diagnostic"]["pivot_input"])
        self.assertEqual(result["diagnostic"]["pivot_steady_confound"],
                         "The recorded timings leave the cause undetermined.")
        rising_diagnostic = [10_000_000] * 184 + [20_000_000] * 166 + [30_000_000] * 18
        diagnostic_path = Path(result["diagnostic"]["pivot_durations_artifact"])
        self.write_duration_fixture(diagnostic_path, rising_diagnostic)
        diagnostic_steady = runner.steady_state(
            rising_diagnostic, runner.STEADY_STATE_TOLERANCE
        )
        diagnostic_p99 = sorted(rising_diagnostic)[
            math.ceil(len(rising_diagnostic) * 0.99) - 1
        ]
        result["diagnostic"].update(
            pivot_durations_artifact_sha256=hashlib.sha256(
                diagnostic_path.read_bytes()
            ).hexdigest(),
            same_occupancy_publish_p99_ns=diagnostic_p99,
            same_occupancy_publish_p99_interval_ns=list(
                runner.quantile_interval(rising_diagnostic, 0.99, 0.95)
            ),
            diagnostic_publish_p99_report=str(diagnostic_p99),
            pivot_steady_first_half_median_ns=diagnostic_steady[0],
            pivot_steady_second_half_median_ns=diagnostic_steady[1],
            pivot_steady_first_half_p99_ns=diagnostic_steady[2],
            pivot_steady_second_half_p99_ns=diagnostic_steady[3],
            pivot_steady_exceedance_splits=diagnostic_steady[4],
            pivot_steady_state=diagnostic_steady[-1],
            pivot_steady_pattern=runner.pivot_steady_pattern(diagnostic_steady),
            pivot_steady_context="serial closed loop, one volume",
            pivot_steady_confound=runner.CAUSE_NOT_ATTRIBUTED,
        )
        runner.validate_pivot_diagnostic(result["diagnostic"])
        self.assertEqual(
            (
                result["diagnostic"]["pivot_steady_state"],
                result["diagnostic"]["pivot_steady_pattern"],
            ),
            ("not steady", "latency-rising"),
        )
        self.assertEqual(
            (
                result["diagnostic"]["diagnostic_warmup_publish_stalls"],
                result["diagnostic"]["diagnostic_warmup_publish_stall_ns"],
            ),
                (0, []),
        )
        offered_as_input = dict(result["diagnostic"], pivot_input=True)
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot_diagnostic(offered_as_input)
        self.assertEqual(str(caught.exception), "closed-loop-pivot-input")
        missing_label = dict(result["diagnostic"], diagnostic_label="diagnostic")
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot_diagnostic(missing_label)
        self.assertEqual(str(caught.exception), "pivot-diagnostic-label")
        diagnostic_cases = (
            ("pivot-diagnostic-outcome", {"diagnostic_outcome": []}),
            ("pivot-diagnostic-role", {"pivot_role": "numerator"}),
            ("pivot-diagnostic-shape", {"stream_count": 2}),
            ("pivot-diagnostic-depth-range", {"diagnostic_depth_range": [64, 430]}),
            ("pivot-ceiling-root", {"root_bytes": 706}),
            ("pivot-diagnostic-observation", {"authority_log_wait_p99_ns": 0}),
            (
                "steady-state-mismatch",
                {"pivot_steady_first_half_median_ns": 11_000_000},
            ),
            ("pivot-diagnostic-steadiness", {"pivot_steady_context": "other"}),
            ("pivot-diagnostic-steadiness", {"pivot_steady_pattern": "other"}),
            (
                "pivot-diagnostic-steadiness",
                {"pivot_steady_confound": (
                    "consistent with the chain walk (#866, #114); "
                    "attribution still confounded with per-publish count"
                )},
            ),
            ("pivot-diagnostic-censor-count", {"diagnostic_publish_censored_count": 369}),
            ("pivot-diagnostic-publish-stalls", {"diagnostic_publish_stalls": 1}),
            (
                "pivot-diagnostic-warmup-publish-stalls",
                {"diagnostic_warmup_publish_stalls": 2},
            ),
            (
                "pivot-diagnostic-completion-stalls",
                {"diagnostic_completion_stall_issue": "#other"},
            ),
            ("pivot-p99-artifact-mismatch", {"same_occupancy_publish_p99_ns": 1}),
            (
                "pivot-interval-artifact-mismatch",
                {"same_occupancy_publish_p99_interval_ns": [1, 2]},
            ),
            ("pivot-diagnostic-censor-report", {"diagnostic_publish_p99_report": "wrong"}),
        )
        for reason, changes in diagnostic_cases:
            with self.subTest(diagnostic=reason, changes=changes):
                invalid = dict(result["diagnostic"], **changes)
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate_pivot_diagnostic(invalid)
                self.assertEqual(str(caught.exception), reason)
        stall_samples = [100_000_000] + [10_000_000] * 367
        stall_path = work / "diagnostic-stall.ns"
        self.write_duration_fixture(stall_path, stall_samples)
        stall_steady = runner.steady_state(stall_samples, runner.STEADY_STATE_TOLERANCE)
        stalled = dict(
            result["diagnostic"],
            pivot_durations_artifact=str(stall_path),
            pivot_durations_artifact_sha256=hashlib.sha256(stall_path.read_bytes()).hexdigest(),
            diagnostic_publish_censored_count=1,
            diagnostic_publish_stalls=1,
            diagnostic_publish_stall_ns=[2_100_000_000],
            pivot_steady_first_half_median_ns=stall_steady[0],
            pivot_steady_second_half_median_ns=stall_steady[1],
            pivot_steady_first_half_p99_ns=stall_steady[2],
            pivot_steady_second_half_p99_ns=stall_steady[3],
            pivot_steady_exceedance_splits=stall_steady[4],
            pivot_steady_state=stall_steady[-1],
            pivot_steady_pattern=runner.pivot_steady_pattern(stall_steady),
        )
        for changes in (
            {"diagnostic_publish_censored_count": 0},
            {"diagnostic_publish_stall_ns": [10**15]},
        ):
            with self.assertRaises(runner.Refused) as caught:
                runner.validate_pivot_diagnostic(dict(stalled, **changes))
            self.assertIn(
                str(caught.exception),
                {"pivot-diagnostic-publish-stalls", "pivot-diagnostic-stall-state"},
            )
        self.assertTrue(all(row["venue"] == "vm" for row in result["rows"]))
        self.assertTrue(
            all(
                (row["pivot_venue_kind"], row["pivot_venue_note"])
                == ("podman-vm", runner.PIVOT_VM_DECISION_NOTE)
                for row in result["rows"]
            )
        )
        self.assertEqual(result["rows"][1]["publish_pilot_sample_count"], 32)
        self.assertTrue(result["rows"][1]["pivot_completion_artifact"].endswith(".ns"))
        completion_evidence = Path(result["rows"][1]["pivot_completion_artifact"])
        completion_root = Path(result["rows"][1]["run_root"])
        self.assertTrue(
            completion_evidence.is_file()
            and completion_evidence.suffix == ".ns"
            and runner.contained(completion_evidence.resolve(), completion_root.resolve())
            and not runner.contained(completion_evidence.resolve(), runner.REPOSITORY),
            (completion_evidence, completion_root),
        )
        self.assertEqual(
            runner.durations_artifact(
                result["rows"][1],
                Path(result["rows"][1]["run_root"]),
                "pivot_completion",
            ),
            [3_000_000] * 1000,
        )
        self.assertEqual(
            [
                (
                    row["medium"],
                    row["filesystem"],
                    row["row_holders"],
                    row["zero_row_principals"],
                )
                for row in result["rows"]
            ],
            [
                ("AmazonS3(fixture)", "ext4", 16, 16_368),
                ("AmazonS3(fixture)", "ext4", 1, 0),
            ],
        )
        self.assertEqual(
            [row["command"] for row in result["rows"]],
            [receipts["numerator"]["command"], receipts["denominator"]["command"]],
        )
        self.assertEqual(
            [row["raw_log"] for row in result["rows"]],
            [receipts["numerator"]["raw_log"], receipts["denominator"]["raw_log"]],
        )
        self.assertEqual(
            [row["date"] for row in result["rows"]] + [result["diagnostic"]["date"]],
            [receipts[role]["started_at"] for role in runner.PIVOT_RUNS],
        )
        assembly_cases = (
            (
                "pivot-denominator-cycle-stall-issue",
                "denominator",
                lambda fields: fields.update(denominator_cycle_stall_issue="#other"),
            ),
            (
                "pivot-diagnostic-ceiling-root",
                "diagnostic",
                lambda fields: fields.update(
                    root_bytes="706", root_size_distribution="706:256"
                ),
            ),
            (
                "pivot-p99-output-mismatch",
                "numerator",
                lambda fields: fields.update(p99_ns="29999999"),
            ),
            (
                "pivot-pair-roles",
                "numerator",
                lambda fields: fields.update(profile="Published"),
            ),
            (
                "pivot-diagnostic-label",
                "diagnostic",
                lambda fields: fields.update(load_model="open-loop"),
            ),
            (
                "pivot-p99-output-mismatch",
                "diagnostic",
                lambda fields: fields.update(p99_ns="9999999"),
            ),
            (
                "pivot-diagnostic-completion-stalls",
                "diagnostic",
                lambda fields: fields.pop("diagnostic_completion_stall_ns"),
            ),
            (
                "pivot-diagnostic-completion-stalls",
                "diagnostic",
                lambda fields: fields.update(diagnostic_completion_stall_ns="bad"),
            ),
            (
                "pivot-diagnostic-publish-stalls",
                "diagnostic",
                lambda fields: fields.pop("diagnostic_publish_stall_ns"),
            ),
            (
                "pivot-diagnostic-publish-stalls",
                "diagnostic",
                lambda fields: fields.update(diagnostic_publish_stall_ns="bad"),
            ),
            (
                "pivot-diagnostic-warmup-publish-stalls",
                "diagnostic",
                lambda fields: fields.pop("diagnostic_warmup_publish_stall_ns"),
            ),
            (
                "pivot-diagnostic-warmup-publish-stalls",
                "diagnostic",
                lambda fields: fields.update(
                    diagnostic_warmup_publish_stall_ns="bad"
                ),
            ),
        )
        assembly_cases += tuple(
            (reason, role, lambda fields, name=name, value=value: fields.update({name: value}))
            for reason, role, name, value in (
                ("pivot-numerator-generation-range", "numerator", "numerator_generation_range", "none"),
                ("pivot-denominator-depth-bounds", "denominator", "denominator_attempt_depth_bounds", "none"),
                ("pivot-denominator-depth-records", "denominator", "denominator_attempt_depth_records", "0,0,warmup"),
                ("pivot-denominator-depth-bounds-format", "denominator", "denominator_attempt_depth_bounds", "0,bad"),
                ("pivot-numerator-generation-range-format", "numerator", "numerator_generation_range", "2,bad"),
                ("pivot-diagnostic-depth-range-format", "diagnostic", "diagnostic_depth_range", "64,bad"),
            )
        )
        for index, (reason, role, mutate) in enumerate(assembly_cases):
            field_mutation = lambda current, fields, role=role, mutate=mutate: (
                mutate(fields) if current == role else None
            )
            invalid_work = Path(self.temporary.name) / f"pivot-assembly-{index}"
            invalid_work.mkdir()
            with (
                patch.dict(os.environ, venue_environment, clear=True),
                patch.object(runner, "start_command", side_effect=start),
                patch.object(runner, "finish_command", side_effect=finish),
                self.assertRaises(runner.Refused) as caught,
            ):
                runner.run_pivot_measurement(
                    "pivot-server", invalid_work, resource_check=lambda _work: None
                )
            self.assertEqual(str(caught.exception), reason)
        field_mutation = None
        sample_count_overrides["diagnostic"] = 367
        population_work = Path(self.temporary.name) / "pivot-assembly-population"
        population_work.mkdir()
        with (
            patch.dict(os.environ, venue_environment, clear=True),
            patch.object(runner, "start_command", side_effect=start),
            patch.object(runner, "finish_command", side_effect=finish),
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.run_pivot_measurement(
                "pivot-server", population_work, resource_check=lambda _work: None
            )
        self.assertEqual(str(caught.exception), "pivot-sample-population")
        sample_count_overrides.clear()
        sample_count_overrides["diagnostic"] = 0
        field_mutation = lambda role, fields: (
            fields.update(rust_stalled_fields)
            or fields.update(pivot_warmup_count="0", pivot_warmup_elapsed_ns="0")
            if role == "diagnostic"
            else None
        )
        stalled_work = Path(self.temporary.name) / "pivot-assembly-stalled"
        stalled_work.mkdir()
        with (
            patch.dict(os.environ, venue_environment, clear=True),
            patch.object(runner, "start_command", side_effect=start),
            patch.object(runner, "finish_command", side_effect=finish),
        ):
            stalled_document = runner.run_pivot_measurement(
                "pivot-server", stalled_work, resource_check=lambda _work: None
            )
        self.assertEqual(runner.validate(stalled_document), 3)
        self.assertEqual(
            stalled_document["diagnostic"]["pivot_steady_confound"],
            "The recorded timings leave the cause undetermined.",
        )
        self.assertEqual(
            (
                stalled_document["diagnostic"]["diagnostic_outcome"],
                stalled_document["diagnostic"]["sample_count"],
                stalled_document["diagnostic"]["diagnostic_stall_phase"],
            ),
            ("stalled", 0, "warmup"),
        )
        for reason, changes in (
            ("pivot-diagnostic-steadiness", {"pivot_steady_state": runner.NOT_APPLICABLE}),
            ("pivot-diagnostic-stall-state", {"diagnostic_stall_index": 1}),
            ("pivot-diagnostic-stall-state", {"diagnostic_publish_p99_report": "0"}),
        ):
            invalid = dict(stalled_document["diagnostic"], **changes)
            with self.assertRaises(runner.Refused) as caught:
                runner.validate_pivot_diagnostic(invalid)
            self.assertEqual(str(caught.exception), reason)
        prior_censored_path = stalled_work / "diagnostic-prior-censored.ns"
        self.write_duration_fixture(prior_censored_path, [100_000_000, 10_000_000])
        prior_censored = dict(
            stalled_document["diagnostic"],
            sample_count=2,
            diagnostic_depth_range=[64, 65],
            stream_sample_counts=[2],
            pivot_warmup_count=runner.PIVOT_WARMUP_COUNT,
            pivot_warmup_elapsed_ns=1_390_000_000,
            pivot_durations_artifact=str(prior_censored_path),
            pivot_durations_artifact_sha256=hashlib.sha256(
                prior_censored_path.read_bytes()
            ).hexdigest(),
            diagnostic_completed_count=runner.PIVOT_WARMUP_COUNT + 2,
            diagnostic_stall_index=runner.PIVOT_WARMUP_COUNT + 2,
            diagnostic_stall_phase="measured",
            diagnostic_publish_censored_count=1,
            diagnostic_publish_stalls=1,
            diagnostic_publish_stall_ns=[2_100_000_000],
            diagnostic_warmup_publish_stalls=0,
            diagnostic_warmup_publish_stall_ns=[],
        )
        runner.validate_pivot_diagnostic(prior_censored)
        for reason, changes in (
            ("pivot-diagnostic-stalled-population", {"sample_count": 368}),
            ("pivot-diagnostic-stall-index", {"diagnostic_stall_index": 432}),
        ):
            with self.assertRaises(runner.Refused) as caught:
                runner.validate_pivot_diagnostic(dict(prior_censored, **changes))
            self.assertEqual(str(caught.exception), reason)
        field_mutation = None
        sample_count_overrides.clear()
        base = dict(result["rows"][1]["denominator_attempts"][0])
        for name in (
            "guards_passed", "sample_artifact", "sample_artifact_sha256",
            "completion_artifact", "completion_artifact_sha256",
            "steady_first_half_median_ns", "steady_second_half_median_ns",
            "steady_first_half_p99_ns", "steady_second_half_p99_ns",
            "steady_exceedance_splits", "steady_state", "steady_pattern",
        ):
            base.pop(name)
        terminal_artifacts = []
        attempts = []
        for index, (rate, streams, count, outcome) in enumerate(
            ((46.0, 64, 1000, "passed"), (23.0, 64, 434, "cycle-deadline"), (11.5, 64, 217, "overlap"))
        ):
            values = ([100] * 500 + [200] * 450 + [300] * 40 + [400] * 10) if index == 0 else [100] * count
            if outcome == "cycle-deadline":
                values.pop()
            decision = f"terminal-{index}-decision.ns"
            completion = f"terminal-{index}-completion.ns"
            terminal_artifacts.extend(((decision, values), (completion, [10] * len(values))))
            attempt = dict(base)
            attempt.update(
                **denominator_depth_fixture(count),
                rate=rate, achieved_rate=rate * count / 1000, outcome=outcome,
                sent_count=count, time_to_first_refusal_ns=(0, 1_400_000_000, 2_800_000_000)[index],
                max_outstanding_per_stream=[1] * streams,
                stream_sample_counts=[count // streams + (slot < count % streams) for slot in range(streams)],
                sample_file=decision, sample_count=len(values),
                completion_file=completion, completion_count=len(values),
                cycle_ends_ns=[[1_000_000_000] * len(values), [1_000_000_000]],
                pilot={**attempt["pilot"], "stream_count": streams},
                refusal_cycle_duration_ns=(None, 1_400_000_000, 2_800_000_000)[index],
            )
            if outcome == "overlap":
                attempt["drain_note"] = "pivot-request-drain-timeout"
            if outcome == "cycle-deadline":
                attempt.update(drain_note="pivot-request-drain-timeout", authority_log_wait_p99_ns=0)
                attempt["depth_records"][-1] = None
            attempts.append(attempt)
        terminal_work = Path(self.temporary.name) / "pivot-terminal-assembly"
        terminal_work.mkdir()
        with (
            patch.dict(os.environ, venue_environment, clear=True),
            patch.object(runner, "start_command", side_effect=start),
            patch.object(runner, "finish_command", side_effect=finish),
            patch.object(runner, "measurement_denominator_attempts", return_value=attempts),
        ):
            terminal = runner.run_pivot_measurement(
                "pivot-server", terminal_work, resource_check=lambda _work: None
            )
        denominator = terminal["rows"][1]
        self.assertEqual(
            (denominator["pivot_branch"], denominator["pivot_verdict"],
             [attempt["outcome"] for attempt in denominator["denominator_attempts"]],
             [attempt["sample_count"] for attempt in denominator["denominator_attempts"]],
             denominator["sample_count"], denominator["pivot_durations_artifact"]),
            ("terminal-inconclusive", "inconclusive", ["not-steady", "cycle-deadline", "overlap"],
             [1000, 433, 217], None, None),
        )
        self.assertTrue(denominator["pivot_scope"].startswith("no denominator qualified;"))
        self.verdict_controls(result, terminal)
        invalid = copy.deepcopy(terminal)
        invalid["rows"][1]["denominator_attempts"][1]["depth_records"][-2] = None
        with self.assertRaisesRegex(runner.Refused, "^pivot-denominator-depth-sample-coverage$"):
            runner.validate(invalid)
        for field, value, reason in (
            ("depth_bounds", [0, 16], "pivot-denominator-depth-bounds"),
            ("time_to_first_refusal_ns", 1, "pivot-denominator-deadline-time"),
            ("cycle_ends_ns", [[], []], "pivot-denominator-cycle-ends"),
            ("cycle_ends_ns", None, "pivot-denominator-cycle-ends"),
            ("drain_note", "bad", "pivot-denominator-drain-note"),
            ("refusal_cycle_duration_ns", runner.DENOMINATOR_CYCLE_LIMIT_NS, "pivot-denominator-cycle-deadline"),
        ):
            invalid = copy.deepcopy(terminal)
            invalid["rows"][1]["denominator_attempts"][1][field] = value
            with self.assertRaisesRegex(runner.Refused, f"^{reason}$"):
                runner.validate(invalid)
        invalid = copy.deepcopy(terminal)
        invalid["rows"][1]["denominator_attempts"][2]["refusal_cycle_duration_ns"] = 450_000_000
        with self.assertRaisesRegex(runner.Refused, "^pivot-denominator-overlap-cycle$"):
            runner.validate(invalid)
        include_log_wait = False
        missing = Path(self.temporary.name) / "pivot-missing-log-wait"
        missing.mkdir()
        with (
            patch.dict(
                os.environ,
                venue_environment,
                clear=True,
            ),
            patch.object(runner, "start_command", side_effect=start),
            patch.object(runner, "finish_command", side_effect=finish),
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.run_pivot_measurement(
                "pivot-server", missing, resource_check=lambda _work: None
            )
        self.assertEqual(str(caught.exception), "pivot-log-wait-observation-missing")
        include_log_wait = True
        include_pilot = False
        missing_pilot = Path(self.temporary.name) / "pivot-missing-pilot"
        missing_pilot.mkdir()
        with (
            patch.dict(os.environ, venue_environment, clear=True),
            patch.object(runner, "start_command", side_effect=start),
            patch.object(runner, "finish_command", side_effect=finish),
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.run_pivot_measurement(
                "pivot-server", missing_pilot, resource_check=lambda _work: None
            )
        self.assertEqual(str(caught.exception), "pivot-pilot-observation")
        missing_store = Path(self.temporary.name) / "pivot-missing-store"
        missing_store.mkdir()
        incomplete = dict(venue_environment)
        incomplete.pop("GRANARY_STORE_REGION")
        with (
            patch.dict(os.environ, incomplete, clear=True),
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.run_pivot_measurement(
                "pivot-server", missing_store, resource_check=lambda _work: None
            )
        self.assertEqual(
            str(caught.exception),
            "pivot-store-environment-missing: GRANARY_STORE_REGION",
        )

        include_pilot = True
        numerator_samples = [20_000_000] * 38 + [10_000_000] * 462
        numerator_samples += [20_000_000] * 12 + [10_000_000] * 488
        unsteady_work = Path(self.temporary.name) / "pivot-numerator-unsteady"
        unsteady_work.mkdir()
        with (
            patch.dict(os.environ, venue_environment, clear=True),
            patch.object(runner, "start_command", side_effect=start),
            patch.object(runner, "finish_command", side_effect=finish),
        ):
            unsteady = runner.run_pivot_measurement(
                "pivot-server", unsteady_work, resource_check=lambda _work: None
            )
        self.assertEqual(unsteady["verdict"], runner.PIVOT_NUMERATOR_UNSTEADY)
        self.assertTrue(all(not row["pivot_append"] for row in unsteady["rows"]))
        numerator = unsteady["rows"][0]
        self.assertEqual(
            (
                numerator["pivot_verdict_branch"],
                numerator["deciding"],
                numerator["pivot_steady_state"],
                numerator["pivot_steady_exceedance_histograms"][0]["counts"],
            ),
            ("numerator-not-steady", False, "not steady", [38, 0, 0, 0, 0, 12, 0, 0, 0, 0]),
        )

    def verdict_rtt_fixture(self, profile, *, refused=False):
        document = self.fixture()
        if profile == "published":
            self.published_rows(document)
        for row in document["samples"]:
            rtt = row["configured_rtt_ms"]
            root = self.log.parent / f"verdict-{profile}-{refused}-{rtt}"
            root.mkdir()
            published = profile == "published"
            duration = 1 + (0 if refused else rtt * 1_000_000)
            evidence = root / "durations.ns"
            self.write_duration_fixture(evidence, [duration] * row["sample_count"])
            for name in ("fsync_min_ns", "fsync_p50_ns", "fsync_p90_ns", "fsync_p99_ns", "fsync_max_ns",
                         "steady_first_half_median_ns", "steady_second_half_median_ns",
                         "steady_first_half_p99_ns", "steady_second_half_p99_ns"):
                row[name] = duration
            log, rc = root / "cell.log", root / "cell.rc"
            log.write_bytes(self.log.read_bytes())
            rc.write_bytes(self.rc.read_bytes())
            row.update(rtt_group=profile, run_root=str(root), raw_log=str(log), raw_rc=str(rc),
                       durations_artifact=str(evidence), durations_artifact_sha256=runner.digest(evidence),
                       steady_exceedance_splits=runner.steady_state([duration] * row["sample_count"], 0.10)[4])
            if not published:
                row.update(register_attempts=1035, route_attempts={"POST /volume/:volume/intent": 1035},
                           register_chain_head_seq=1)
            self.mounted_server_fixture(row)
        calibration = runner.rtt_calibration_record([
            runner.calibration_cell_from_row(row) for row in document["samples"]])
        self.assertEqual(calibration["outcome"], "refused" if refused else "calibrated")
        for row in document["samples"]:
            row.update(calibration_outcome=calibration["outcome"], calibration_reason=calibration["reason"])
        document["calibrations"] = [calibration]
        return document

    def test_rtt_band_field_controls(self):
        durable = self.verdict_rtt_fixture("durable-prepared")
        published = self.verdict_rtt_fixture("published")
        for document in (durable, published):
            self.assertEqual(runner.validate(document), 3)
        for name, source, values in (
            ("register_chain_head_seq", durable, (True, "1")),
            ("register_chain_head_seq", published, (1,)),
            ("rtt_band_attempts", published,
             ("bad", [1], [1] * 9 + [True], [-1] + [1] * 9, [runner.MAX_INTEGER + 1] * 10)),
        ):
            for value in values:
                with self.subTest(field=name, value=value):
                    document = copy.deepcopy(source)
                    document["samples"][1][name] = value
                    reason = f"^schema-invalid: {name}$"
                    with self.assertRaisesRegex(runner.Refused, reason):
                        runner.validate(document)
                    cells = [runner.calibration_cell_from_row(row) for row in document["samples"]]
                    with self.assertRaisesRegex(runner.Refused, reason):
                        runner.validate_rtt_observations(cells)

    def verdict_controls(self, vm_pivot, terminal_pivot):
        def desk_pivot(source):
            pivot = copy.deepcopy(source)
            for row in [*pivot["rows"], pivot["diagnostic"]]:
                row.update(venue="linux-ci", hardware=True, pivot_venue_kind="linux-ci")
            pivot["rows"][0]["deciding"] = True
            for row in pivot["rows"]:
                row["pivot_append"] = pivot["verdict"] == "pivot"
            return pivot

        def cli(argv, reason=None):
            with (patch.object(sys, "argv", ["q3-measurement.py", *argv]),
                  patch("sys.stdout", new_callable=io.StringIO) as stdout,
                  patch("sys.stderr", new_callable=io.StringIO) as stderr):
                self.assertEqual(runner.main(), int(reason is not None), stderr.getvalue())
            if reason is None:
                self.assertEqual(stderr.getvalue(), "")
                return json.loads(stdout.getvalue())
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(json.loads(stderr.getvalue()), {"event": "refused", "reason": reason})

        root = self.log.parent
        durable = self.recovery_document_fixture()
        rtt = self.verdict_rtt_fixture("durable-prepared")
        inputs = dict(recovery_durable_prepared=durable, recovery_published=self.published_recovery_document(durable),
                      pivot=desk_pivot(vm_pivot), rtt_durable_prepared=rtt,
                      rtt_published=self.verdict_rtt_fixture("published"),
                      cross_volume=runner.cross_volume_document(self.cross_volume_fixture()[0]))
        paths = {role: root / f"{role}.json" for role in inputs}
        for role, component in inputs.items():
            paths[role].write_text(json.dumps(component))

        def assemble(position="supports", fallback="moot", *, reason=None):
            return cli(["assemble-verdict", *map(str, paths.values()), "--decision-4", position, "Observed",
                        "--decision-5", fallback, "Recovered", "--decision-6", "open", "Pilot pending"], reason)

        verdict = assemble()
        self.assertEqual(verdict["pivot_scope"], inputs["pivot"]["rows"][0]["pivot_scope"])
        self.assertEqual(verdict["rtt_scope"], {
            profile: inputs[f"rtt_{profile.replace('-', '_')}"]["calibrations"][0]["scope"]
            for profile in ("durable-prepared", "published")
        })
        self.assertEqual(verdict["cross_volume_property"], inputs["cross_volume"]["caveat"])
        self.assertIs(verdict["sets_no_default"], True)
        path = root / "verdict.json"

        def check(document, reason=None):
            path.write_text(json.dumps(document))
            result = cli([str(path)], reason)
            if reason is None:
                self.assertEqual(result, {"event": "counts", "samples": 1})

        check(verdict)
        for key, value, reason in (
            ("default_profile", "published", "verdict-no-default"),
            ("sets_no_default", False, "verdict-no-default"),
            ("decisions", {}, "verdict-decisions"),
            ("components", dict(verdict["components"], extra=None), "verdict-components"),
            ("metrics", {}, "verdict-metrics-mismatch"),
            ("pivot_scope", "different", "verdict-pivot_scope-mismatch"),
            ("rtt_scope", dict(verdict["rtt_scope"], published="Hand-edited scope"),
             "verdict-rtt_scope-mismatch"),
            ("cross_volume_property", "different", "verdict-cross_volume_property-mismatch"),
        ):
            with self.subTest(reason=reason):
                check(dict(verdict, **{key: value}), reason)
        for decision in ("4", "5", "6"):
            for change in ({"position": "adopted"}, {"rationale": "  "}, {"rationale": 1}):
                bad = copy.deepcopy(verdict)
                bad["decisions"][decision].update(change)
                check(bad, f"verdict-decision-{decision}")
        for role, family in zip(paths, ("recovery-gap", "recovery-gap", "pivot", "rtt", "rtt", "cross-volume")):
            bad = copy.deepcopy(verdict)
            bad["components"].pop(role)
            check(bad, f"verdict-missing-{family}")
        for changes, reason in (({"path": "pivot.json"}, "verdict-missing-pivot"),
                                ({"sha256": "0" * 64}, "verdict-component-hash: pivot"),
                                ({"path": str(root / "missing.json")}, "verdict-component-unreadable: pivot")):
            bad = copy.deepcopy(verdict)
            bad["components"]["pivot"].update(changes)
            check(bad, reason)

        def replace(role, component, base=verdict):
            bad = copy.deepcopy(base)
            paths[role].write_text(json.dumps(component))
            bad["components"][role]["sha256"] = runner.digest(paths[role])
            return bad

        check(replace("recovery_published", inputs["cross_volume"]), "verdict-component-type: recovery_published")
        check(replace("recovery_published", durable), "verdict-missing-recovery-gap")
        replace("recovery_published", inputs["recovery_published"])
        for change, reason in (({"calibrations": None}, "verdict-missing-rtt"),
                                (inputs["rtt_published"], "verdict-missing-rtt")):
            check(replace("rtt_durable_prepared", dict(rtt, **change)), reason)
        for fields, reason in ((("route_attempts",), "verdict-missing-round-trips"),
                               (("m15_delta",), "verdict-missing-rechunk-fallback"),
                               (("server_metrics", "server_observers_sha256"), "verdict-missing-control-writes")):
            component = copy.deepcopy(rtt)
            for field in fields:
                component["samples"][0].pop(field)
            check(replace("rtt_durable_prepared", component), reason)
        component = copy.deepcopy(rtt)
        for row in component["samples"]:
            row["route_attempts"] = {"POST /volume/:volume/intent": 1034, "GET /other": 1}
        check(replace("rtt_durable_prepared", component), "verdict-missing-round-trips")
        replace("rtt_durable_prepared", rtt)

        unbounded = self.recovery_document_fixture(runner.MAX_INTEGER + 1)
        replace("recovery_durable_prepared", unbounded)
        live = assemble(fallback="live")
        check(live)
        live["decisions"]["5"]["position"] = "moot"
        check(live, "verdict-recovery-unbounded")
        replace("recovery_durable_prepared", durable)

        vm_rtt = copy.deepcopy(rtt)
        vm_rtt["samples"][0].update(venue="vm", hardware=False)
        for role, component, reason in (
            ("rtt_durable_prepared", vm_rtt, "verdict-vm"),
            ("pivot", vm_pivot, "verdict-vm"),
            ("pivot", desk_pivot(terminal_pivot), "verdict-pivot-inconclusive"),
            ("rtt_durable_prepared", self.verdict_rtt_fixture("durable-prepared", refused=True),
             "verdict-rtt-calibration-refused"),
        ):
            replace(role, component)
            open_verdict = assemble(position="open")
            check(open_verdict)
            if role == "pivot" and component is vm_pivot:
                assemble(position="opne", reason="verdict-decision-4")
            open_verdict["decisions"]["4"]["position"] = "refutes"
            check(open_verdict, reason)
            replace(role, inputs[role])
        check(assemble(position="refutes"))

    def test_pivot_child_bound_and_timeout_controls(self):
        self.assertEqual(
            {role: runner.pivot_child_bound_seconds(role) for role in runner.PIVOT_RUNS},
            {"numerator": 137, "denominator": 780, "diagnostic": 1198},
        )
        environment = {
            "GRANARY_Q3_REVISION": "0123456789abcdef0123456789abcdef01234567",
            "GRANARY_Q3_VENUE": "vm",
            "GRANARY_STORE": "s3:",
            "GRANARY_STORE_BUCKET": "granary-test",
            "GRANARY_STORE_ENDPOINT": "http://127.0.0.1:19189",
            "GRANARY_STORE_REGION": "us-east-1",
            "AWS_ACCESS_KEY_ID": "fixture-access",
            "AWS_SECRET_ACCESS_KEY": "fixture-secret",
        }
        cases = (
            (
                "timeout",
                {"numerator": 0, "denominator": 0, "diagnostic": 124},
                "pivot-server-diagnostic-timeout: bound_seconds=1198, elapsed_seconds=1198.125",
            ),
            (
                "failure",
                {"numerator": 7, "denominator": 0, "diagnostic": 0},
                "pivot-server-numerator-failed: exit_code=7",
            ),
        )
        for label, exit_codes, refusal in cases:
            work = Path(self.temporary.name) / f"pivot-{label}"
            work.mkdir()
            started = []

            def start(_, stem, *, cwd, **__):
                role = stem.removeprefix("pivot-server-")
                started.append(role)
                output = Path(cwd) / "output"
                (output / runner.PIVOT_RUNS[role][2]).write_text(
                    "phase\toffset_ns\nrow-start\t0\n"
                )
                return {"role": role}

            def finish(running, *, timeout=None):
                return {"exit_code": exit_codes[running["role"]], "timeout": timeout}

            with (
                patch.dict(os.environ, environment, clear=True),
                patch.object(runner, "start_command", side_effect=start),
                patch.object(runner, "finish_command", side_effect=finish) as finish_mock,
                patch.object(
                    runner.time,
                    "monotonic_ns",
                    side_effect=[
                        0,
                        1_000_000_000,
                        2_000_000_000,
                        3_000_000_000,
                        4_000_000_000,
                        1_202_125_000_000,
                    ],
                ),
                self.assertRaises(runner.Refused) as caught,
            ):
                runner.run_pivot_measurement(
                    "pivot-server", work, resource_check=lambda _work: None
                )
            self.assertEqual(str(caught.exception), refusal)
            self.assertEqual(started, ["numerator", "denominator", "diagnostic"])
            self.assertEqual(
                [call.kwargs["timeout"] for call in finish_mock.call_args_list],
                [137, 780, 1198],
            )
            manifest = json.loads(
                (work / "output/pivot-progress-artifacts.json").read_text()
            )
            self.assertTrue(
                all(manifest[role]["progress_sha256"] for role in runner.PIVOT_RUNS)
            )

    def make_unsteady_denominator_attempt(self, first, selected):
        values = [100] * 500 + [200] * 500
        path = Path(self.temporary.name) / "denominator-unsteady.ns"
        self.write_duration_fixture(path, values)
        metrics = runner.steady_state(values, runner.STEADY_STATE_TOLERANCE)
        first.update(selected, rate=46.0, achieved_rate=46.0, outcome="not-steady",
                     sample_artifact=str(path), sample_artifact_sha256=runner.digest(path),
                     steady_first_half_median_ns=metrics[0], steady_second_half_median_ns=metrics[1],
                     steady_first_half_p99_ns=metrics[2], steady_second_half_p99_ns=metrics[3],
                     steady_exceedance_splits=metrics[4], steady_state=metrics[-1],
                     steady_pattern=runner.pivot_steady_pattern(metrics))

    def test_pivot_rising_latency_role_controls(self):
        root = Path(self.temporary.name)
        rising_path = root / "denominator-rising.ns"
        steady_path = root / "denominator-steady.ns"
        rising_completion = root / "denominator-rising-completion.ns"
        steady_completion = root / "denominator-steady-completion.ns"
        rising = [100] * 500 + [200] * 450 + [300] * 40 + [400] * 10
        steady = [100] * 1000
        for path, values in (
            (rising_path, rising),
            (steady_path, steady),
            (rising_completion, [10] * 1000),
            (steady_completion, [10] * 1000),
        ):
            self.write_duration_fixture(path, values)
        attempts = [
            {
                "rate": rate,
                "warmup_count": runner.PIVOT_WARMUP_COUNT,
                "warmup_elapsed_ns": 1_391_304_352,
                "outcome": "passed",
                "time_to_first_refusal_ns": 0,
                "sample_file": sample.name,
                "sample_count": 1000,
                "completion_file": completion.name,
                "completion_count": 1000,
                "pilot": {"p99_ns": pilot_p99},
            }
            for rate, sample, completion, pilot_p99 in (
                (46.0, rising_path, rising_completion, 40),
                (23.0, steady_path, steady_completion, 30),
            )
        ]
        classified, branch, selected = runner.classify_denominator_attempts(
            attempts, root
        )
        self.assertEqual(
            (
                [attempt["outcome"] for attempt in classified],
                classified[0]["time_to_first_refusal_ns"],
                classified[0]["steady_pattern"],
                classified[0]["pilot"]["p99_ns"],
                branch,
                selected[0]["rate"],
            ),
            (["not-steady", "passed"], 0, "latency-rising", 40, "lower-bound", 23.0),
        )
        self.assertNotEqual(
            runner.lower_bound_pivot_verdict([20, 21], [10, 10]), "pivot"
        )

        document = self.fixture()
        self.pivot_pair(document)
        numerator = document["samples"][0]
        numerator_path = root / "numerator-rising.ns"
        self.write_duration_fixture(numerator_path, rising)
        numerator_steady = runner.steady_state(rising, runner.STEADY_STATE_TOLERANCE)
        numerator.update(
            pivot_durations_artifact=str(numerator_path),
            pivot_durations_artifact_sha256=hashlib.sha256(
                numerator_path.read_bytes()
            ).hexdigest(),
            register_post_p99_ns=300,
            register_post_p99_interval_ns=list(
                runner.quantile_interval(rising, 0.99, 0.95)
            ),
            pivot_steady_first_half_median_ns=numerator_steady[0],
            pivot_steady_second_half_median_ns=numerator_steady[1],
            pivot_steady_first_half_p99_ns=numerator_steady[2],
            pivot_steady_second_half_p99_ns=numerator_steady[3],
            pivot_steady_exceedance_splits=numerator_steady[4],
            pivot_steady_state=numerator_steady[-1],
            pivot_steady_pattern=runner.pivot_steady_pattern(numerator_steady),
        )
        for row in document["samples"][:2]:
            row.update(
                pivot_verdict=runner.PIVOT_NUMERATOR_UNSTEADY,
                pivot_append=False,
                pivot_verdict_branch="numerator-not-steady",
            )
        numerator.update(
            deciding=False,
            cell_kind="refused",
            pivot_steady_exceedance_histograms=runner.pivot_exceedance_histograms(
                rising, numerator_steady[4]
            ),
        )
        runner.validate_pivot(document["samples"][:2])
        self.assertNotIn(numerator["pivot_verdict"], ("pivot", "no pivot"))
        missing_splits = dict(numerator, pivot_steady_exceedance_splits=None)
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot([missing_splits, document["samples"][1]])
        self.assertEqual(str(caught.exception), "steady-state-mismatch")

        wrong_histogram = json.loads(json.dumps(document["samples"][:2]))
        wrong_histogram[0]["pivot_steady_exceedance_histograms"][0]["counts"][0] -= 1
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(wrong_histogram)
        self.assertEqual(str(caught.exception), "pivot-numerator-exceedance-histogram")

        steady_as_unsteady = self.fixture()
        self.pivot_pair(steady_as_unsteady)
        steady_rows = steady_as_unsteady["samples"][:2]
        steady_samples = runner.durations_artifact(
            steady_rows[0], Path(steady_rows[0]["run_root"]), "pivot_durations"
        )
        for row in steady_rows:
            row.update(
                pivot_verdict=runner.PIVOT_NUMERATOR_UNSTEADY,
                pivot_append=False,
                pivot_verdict_branch="numerator-not-steady",
            )
        steady_rows[0].update(
            deciding=False,
            cell_kind="refused",
            pivot_steady_exceedance_histograms=runner.pivot_exceedance_histograms(
                steady_samples, steady_rows[0]["pivot_steady_exceedance_splits"]
            ),
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(steady_rows)
        self.assertEqual(str(caught.exception), "pivot-numerator-steadiness")

        unsteady_as_deciding = json.loads(json.dumps(document["samples"][:2]))
        for row in unsteady_as_deciding:
            row["pivot_verdict_branch"] = "deciding-pair"
        unsteady_as_deciding[0].update(
            deciding=True,
            cell_kind="steady",
            pivot_steady_exceedance_histograms=None,
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(unsteady_as_deciding)
        self.assertEqual(str(caught.exception), "pivot-not-steady")

    def test_pivot_interval_and_achieved_rate_controls(self):
        values = list(range(1, 1001))
        self.assertEqual(runner.quantile_interval(values, 0.99, 0.95), (983, 997))
        with self.assertRaises(runner.Refused) as caught:
            runner.quantile_interval(list(range(1, 368)), 0.99, 0.95)
        self.assertEqual(str(caught.exception), "quantile-interval-population")
        self.assertEqual(
            runner.quantile_interval(list(range(1, 1031)), 0.99, 0.95),
            (1013, 1026),
        )
        self.assertEqual(
            runner.quantile_interval(list(range(1, 5001)), 0.99, 0.95),
            (4936, 4964),
        )
        self.assertEqual(
            runner.pivot_verdict((101_000_001, 102_000_000), (40_000_000, 41_000_000)),
            "pivot",
        )
        self.assertEqual(
            runner.pivot_verdict((79_000_000, 81_000_000), (39_000_000, 41_000_000)),
            "inconclusive",
        )
        self.assertEqual(
            runner.lower_bound_pivot_verdict(
                (80_000_000, 82_000_000), (20_000_000, 21_000_000)
            ),
            "inconclusive",
            "a lower-rate denominator cannot prove the two-times pivot clause",
        )
        self.assertEqual(
            runner.lower_bound_pivot_verdict(
                (101_000_000, 102_000_000), (40_000_000, 41_000_000)
            ),
            "inconclusive",
            "the lower-rate verdict cannot declare a pivot",
        )

        valid = self.fixture()
        self.pivot_pair(valid)
        for row in valid["samples"][:2]:
            row.update(
                achieved_rate=44,
            )
        valid["samples"][1]["denominator_attempts"][0]["achieved_rate"] = 44.0
        self.assertGreater(runner.validate(valid), 0)
        self.assertEqual(valid["samples"][1]["stream_count"], 64)
        wrong_pool = json.loads(json.dumps(valid))
        wrong_pool["samples"][1]["denominator_attempts"][0][
            "max_outstanding_per_stream"
        ].pop()
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(wrong_pool["samples"][:2])
        self.assertEqual(str(caught.exception), "pivot-denominator-attempts")
        lower = json.loads(json.dumps(valid))
        lower_denominator = lower["samples"][1]
        refused_attempt = dict(lower_denominator["denominator_attempts"][0])
        refused_sample = Path(self.temporary.name) / "lower-refused-decision.ns"
        refused_completion = Path(self.temporary.name) / "lower-refused-completion.ns"
        self.write_duration_fixture(refused_sample, [10_000_000] * 661)
        self.write_duration_fixture(refused_completion, [3_000_000] * 661)
        refused_attempt.update(
            **denominator_depth_fixture(661),
            **denominator_refusal_timing(661, 46.0),
            outcome="overlap",
            sent_count=661,
            refusal_cycle_duration_ns=450_000_000,
            stream_sample_counts=[11] * 21 + [10] * 43,
            sample_count=661,
            sample_artifact=str(refused_sample),
            sample_artifact_sha256=hashlib.sha256(
                refused_sample.read_bytes()
            ).hexdigest(),
            completion_count=661,
            completion_artifact=str(refused_completion),
            completion_artifact_sha256=hashlib.sha256(
                refused_completion.read_bytes()
            ).hexdigest(),
            guards_passed=False,
            steady_first_half_median_ns=None,
            steady_second_half_median_ns=None,
            steady_first_half_p99_ns=None,
            steady_second_half_p99_ns=None,
            steady_exceedance_splits=None,
            steady_state=runner.NOT_APPLICABLE,
            steady_pattern="other",
        )
        passed_attempt = dict(lower_denominator["denominator_attempts"][0])
        passed_attempt.update(
            rate=23.0,
            achieved_rate=23.0,
        )
        lower_denominator.update(
            pivot_branch="lower-bound",
            denominator_label=runner.PIVOT_LOWER_BOUND_LABEL,
            denominator_attempts=[refused_attempt, passed_attempt],
            offered_rate=23.0,
            achieved_rate=23.0,
            per_stream_offered_rate=23.0 / 64,
            denominator_cycle_stalls=[
                {
                    "rate": 46.0,
                    "bound_ns": 400_000_000,
                    "count": 1,
                    "durations_ns": [450_000_000],
                    "refusal_cycle_duration_ns": 450_000_000,
                },
                {
                    "rate": 23.0,
                    "bound_ns": 400_000_000,
                    "count": 1,
                    "durations_ns": [450_000_000],
                    "refusal_cycle_duration_ns": None,
                },
            ],
            denominator_cycle_stall_issue="#832",
        )
        lower_verdict = runner.lower_bound_pivot_verdict(
            lower["samples"][0]["register_post_p99_interval_ns"],
            lower_denominator["publish_decision_p99_interval_ns"],
        )
        for row in lower["samples"][:2]:
            row.update(
                pivot_verdict=lower_verdict,
                pivot_append=lower_verdict == "pivot",
            )
        self.assertGreater(runner.validate(lower), 0)
        old_plan = copy.deepcopy(lower)
        old_plan["samples"][1]["pivot_stream_plan"] = "numerator=16;denominator=64@46,32@23,16@11.5"
        with self.assertRaisesRegex(runner.Refused, "^pivot-stream-plan$"):
            runner.validate(old_plan)
        parity = copy.deepcopy(lower)
        self.make_unsteady_denominator_attempt(parity["samples"][1]["denominator_attempts"][0], passed_attempt)
        parity["samples"][1]["denominator_cycle_stalls"][0]["refusal_cycle_duration_ns"] = None
        self.assertGreater(runner.validate(parity), 0)
        parity["samples"][1]["denominator_attempts"][1]["depth_bounds"] = [0, 17]
        with self.assertRaisesRegex(runner.Refused, "^pivot-denominator-depth-parity$"):
            runner.validate(parity)

        finished = [[4_000_000_000] * 661, [4_000_000_000]]
        for stall, reason in ((True, "pivot-denominator-cycle-stall-deadline"), (False, "pivot-denominator-cycle-samples")):
            rows = copy.deepcopy(lower["samples"][:2])
            first = rows[1]["denominator_attempts"][0]
            first.update(time_to_first_refusal_ns=3_000_000_000, cycle_ends_ns=copy.deepcopy(finished))
            if stall:
                first["cycle_stall_durations_ns"] = rows[1]["denominator_cycle_stalls"][0]["durations_ns"] = [2_000_000_000]
            else:
                self.write_duration_fixture(refused_completion, [1_990_000_000] + [3_000_000] * 660)
                first["completion_artifact_sha256"] = runner.digest(refused_completion)
            runner.validate_pivot(rows)
            first["cycle_ends_ns"][int(stall)][0] = 2_900_000_000
            with self.assertRaisesRegex(runner.Refused, f"^{reason}$"):
                runner.validate_pivot(rows)
        self.write_duration_fixture(refused_completion, [3_000_000] * 661)
        wrong_lower_label = json.loads(json.dumps(lower["samples"][:2]))
        wrong_lower_label[1]["denominator_label"] = "offered-rate denominator"
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(wrong_lower_label)
        self.assertEqual(str(caught.exception), "pivot-lower-bound-branch")
        missing_stall = json.loads(json.dumps(lower["samples"][:2]))
        missing_stall[1]["denominator_attempts"][0]["cycle_stall_count"] = 0
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(missing_stall)
        self.assertEqual(str(caught.exception), "pivot-denominator-stall-durations")

        terminal = json.loads(json.dumps(valid))
        terminal_denominator = terminal["samples"][1]
        refused_attempts = []
        for rate, stream_count, sent_count in (
            (46.0, 64, 661),
            (23.0, 64, 400),
            (11.5, 64, 200),
        ):
            attempt = dict(terminal_denominator["denominator_attempts"][0])
            sample_path = Path(self.temporary.name) / f"terminal-{rate}-decision.ns"
            completion_path = Path(self.temporary.name) / f"terminal-{rate}-completion.ns"
            self.write_duration_fixture(sample_path, [10_000_000] * sent_count)
            self.write_duration_fixture(completion_path, [3_000_000] * sent_count)
            attempt.update(
                **denominator_depth_fixture(sent_count),
                **denominator_refusal_timing(sent_count, rate),
                rate=rate,
                outcome="overlap",
                sent_count=sent_count,
                max_outstanding_per_stream=[1] * stream_count,
                stream_sample_counts=(
                    [sent_count // stream_count + 1] * (sent_count % stream_count)
                    + [sent_count // stream_count]
                    * (stream_count - sent_count % stream_count)
                ),
                sample_count=sent_count,
                sample_artifact=str(sample_path),
                sample_artifact_sha256=hashlib.sha256(
                    sample_path.read_bytes()
                ).hexdigest(),
                completion_count=sent_count,
                completion_artifact=str(completion_path),
                completion_artifact_sha256=hashlib.sha256(
                    completion_path.read_bytes()
                ).hexdigest(),
                pilot={**attempt["pilot"], "stream_count": stream_count},
                refusal_cycle_duration_ns=450_000_000 if rate == 46.0 else 2_800_000_000,
                guards_passed=False,
                steady_first_half_median_ns=None,
                steady_second_half_median_ns=None,
                steady_first_half_p99_ns=None,
                steady_second_half_p99_ns=None,
                steady_exceedance_splits=None,
                steady_state=runner.NOT_APPLICABLE,
                steady_pattern="other",
            )
            refused_attempts.append(attempt)
        terminal_denominator.update(
            pivot_branch="terminal-inconclusive",
            denominator_label=runner.PIVOT_TERMINAL_LABEL,
            denominator_attempts=refused_attempts,
            offered_rate=11.5,
            achieved_rate=None,
            cell_kind="refused",
            publish_decision_p99_ns=None,
            publish_decision_p99_interval_ns=None,
            stream_count=None,
            stream_sample_counts=None,
            sample_count=None,
            pivot_durations_artifact=None,
            pivot_durations_artifact_sha256=None,
            per_stream_offered_rate=None,
            pivot_warmup_count=None,
            pivot_warmup_elapsed_ns=None,
            denominator_cycle_stalls=[
                {
                    "rate": rate,
                    "bound_ns": 400_000_000,
                    "count": 1,
                    "durations_ns": [450_000_000],
                    "refusal_cycle_duration_ns": 450_000_000 if rate == 46.0 else 2_800_000_000,
                }
                for rate in (46.0, 23.0, 11.5)
            ],
            denominator_cycle_stall_issue="#832",
        )
        terminal_denominator["offered_rate"] = None
        terminal_denominator["pivot_completion_artifact"] = None
        terminal_denominator["pivot_completion_artifact_sha256"] = None
        for row in terminal["samples"][:2]:
            row.update(pivot_verdict="inconclusive", pivot_append=False,
                       pivot_scope=runner.pivot_scope(terminal["samples"][0], None))
        runner.validate_pivot(terminal["samples"][:2])
        terminal_artifact = json.loads(json.dumps(terminal["samples"][:2]))
        terminal_artifact[1]["pivot_durations_artifact"] = "unexpected.ns"
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(terminal_artifact)
        self.assertEqual(str(caught.exception), "pivot-terminal-row-artifacts")
        terminal_load = json.loads(json.dumps(terminal["samples"][:2]))
        terminal_load[1]["offered_rate"] = 11.5
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(terminal_load)
        self.assertEqual(str(caught.exception), "pivot-terminal-row-load")
        one_passed = json.loads(json.dumps(terminal["samples"][:2]))
        steady_attempt = valid["samples"][1]["denominator_attempts"][0]
        one_passed[1]["denominator_attempts"][2].update(
            **denominator_depth_fixture(1000),
            outcome="passed",
            achieved_rate=11.5,
            sent_count=1000,
            time_to_first_refusal_ns=0,
            refusal_cycle_duration_ns=None,
            cycle_ends_ns=steady_attempt["cycle_ends_ns"],
            guards_passed=True,
            stream_sample_counts=[16] * 40 + [15] * 24,
            sample_count=1000,
            sample_artifact=steady_attempt["sample_artifact"],
            sample_artifact_sha256=steady_attempt["sample_artifact_sha256"],
            completion_count=1000,
            completion_artifact=steady_attempt["completion_artifact"],
            completion_artifact_sha256=steady_attempt[
                "completion_artifact_sha256"
            ],
            **{
                name: steady_attempt[name]
                for name in (
                    "steady_first_half_median_ns",
                    "steady_second_half_median_ns",
                    "steady_first_half_p99_ns",
                    "steady_second_half_p99_ns",
                    "steady_exceedance_splits",
                    "steady_state",
                    "steady_pattern",
                )
            },
        )
        one_passed[1]["denominator_cycle_stalls"][2][
            "refusal_cycle_duration_ns"
        ] = None
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_pivot(one_passed)
        self.assertEqual(str(caught.exception), "pivot-terminal-branch")
        missing_token = dict(
            denominator_attempt_rates="46",
            denominator_attempt_warmups="64,1391304352",
            denominator_attempt_achieved_rates="0",
            denominator_attempt_outcomes="409",
            denominator_attempt_sent_counts="1",
            denominator_attempt_first_refusal_ns="1",
            denominator_attempt_conflict_tokens="missing:1",
            denominator_attempt_response_tokens="missing:1",
            denominator_attempt_rate_limited_counts="0",
            denominator_attempt_max_outstanding="1",
            denominator_attempt_max_outstanding_per_stream=",".join(["1"] * 64),
            denominator_attempt_stream_sample_counts=",".join(["1"] + ["0"] * 63),
            denominator_attempt_sample_files="samples.ns",
            denominator_attempt_sample_counts="1",
            denominator_attempt_completion_files="completion.ns",
            denominator_attempt_completion_counts="1",
            denominator_attempt_log_wait_p99_ns="1000",
            denominator_attempt_pilot_observations="32,20000000,40000000,45000000,64",
            denominator_attempt_pilot_p99_ns="40000000",
            denominator_attempt_cycle_stall_bound_ns="400000000",
            denominator_attempt_cycle_stall_counts="0",
            denominator_attempt_cycle_stall_ns="none",
            denominator_attempt_refusal_cycle_ns="none",
            denominator_attempt_depth_records=";".join(
                ",".join(map(str, record)) for record in denominator_depth_fixture(1)["depth_records"]
            ),
            denominator_attempt_depth_bounds="0,1",
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.measurement_denominator_attempts(missing_token)
        self.assertEqual(str(caught.exception), "pivot-denominator-conflict-token")
        valid_attempt = dict(
            missing_token,
            denominator_attempt_conflict_tokens="stale-base:1",
            denominator_attempt_response_tokens="stale-base:1",
            denominator_attempt_refusal_cycle_ns="none,pivot-request-drain-timeout",
        )
        parsed = runner.measurement_denominator_attempts(valid_attempt)[0]
        self.assertEqual((parsed["refusal_cycle_duration_ns"], parsed["drain_note"]), (None, "pivot-request-drain-timeout"))
        for reason, changes in (
            ("pivot-denominator-pilot-p99", {"denominator_attempt_pilot_p99_ns": "bad"}),
            ("pivot-denominator-cycle-stall-binding", {"denominator_attempt_cycle_stall_bound_ns": "399999999"}),
        ):
            with self.assertRaises(runner.Refused) as caught:
                runner.measurement_denominator_attempts(dict(valid_attempt, **changes))
            self.assertEqual(str(caught.exception), reason)
        forged = json.loads(json.dumps(valid))
        for row in forged["samples"][:2]:
            row["register_post_p99_interval_ns"] = [81_000_000, 81_000_000]
            row["publish_decision_p99_interval_ns"] = [40_000_000, 40_000_000]
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(forged)
        self.assertEqual(str(caught.exception), "pivot-interval-artifact-mismatch")
        cases = (
            (
                "achieved rate shortfall",
                "pivot-achieved-rate-shortfall",
                lambda rows: rows[0].update(achieved_rate=43),
            ),
            (
                "verdict without intervals",
                "pivot-interval-missing",
                lambda rows: rows[0].update(register_post_p99_interval_ns=None),
            ),
        )
        for label, reason, mutate in cases:
            with self.subTest(label=label):
                malformed = json.loads(json.dumps(valid))
                mutate(malformed["samples"][:2])
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate(malformed)
                self.assertEqual(str(caught.exception), reason)
        self.assertGreater(len(cases), 0)
        print(
            "CONTROL pivot intervals/rate: observed=2 refused="
            + ",".join(reason for _, reason, _ in cases)
        )

    def test_steady_state_and_offload_controls(self):
        with self.assertRaisesRegex(runner.Refused, "^steady-state-samples$"):
            runner.steady_state([100, 100, 100], runner.STEADY_STATE_TOLERANCE)
        steady = [100] * 500 + [100] * 500
        steady_result = runner.steady_state(steady, runner.STEADY_STATE_TOLERANCE)
        self.assertEqual(steady_result[:4], (100, 100, 100, 100))
        self.assertEqual(steady_result[-1], "steady")
        for population, exceedances, percentile, expected, probability in (
            (1000, 10, 99, 9, 0.020872),
            (1000, 50, 95, 33, 0.028596),
            (368, 18, 95, 14, 0.026967),
        ):
            values = [100] * (population - exceedances) + [200] * exceedances
            split = runner.exceedance_split(values, percentile)
            self.assertEqual(
                (
                    split["population"],
                    split["quantile"],
                    split["exceedances"],
                    split["critical_count"],
                ),
                (population, percentile, exceedances, expected),
            )
            self.assertEqual(
                round(float(Fraction(split["tail_probability"])), 6), probability
            )

        # The p95 exceedances are balanced 30/20, while all ten p99
        # exceedances occupy the first half (two percent of that half).
        tail_shift = (
            [200] * 10
            + [150] * 20
            + [100] * 470
            + [150] * 20
            + [100] * 480
        )
        tail_result = runner.steady_state(tail_shift, runner.STEADY_STATE_TOLERANCE)
        p99_split = next(
            split for split in tail_result[-2] if split["quantile"] == 99
        )
        self.assertEqual(
            (p99_split["exceedances"], p99_split["critical_count"], p99_split["split"]),
            (10, 9, [10, 0]),
        )
        self.assertEqual(tail_result[-1], "not steady")
        self.assertEqual(runner.pivot_steady_pattern(tail_result), "other")

        rising = [100] * 500 + [200] * 450 + [300] * 40 + [400] * 10
        rising_result = runner.steady_state(rising, runner.STEADY_STATE_TOLERANCE)
        self.assertEqual(
            [split["split"] for split in rising_result[-2]],
            [[0, 50], [0, 10]],
        )
        self.assertEqual(rising_result[-1], "not steady")
        self.assertEqual(runner.pivot_steady_pattern(rising_result), "latency-rising")

        flat_median = [100] * 950 + [300] * 40 + [400] * 10
        self.assertEqual(
            runner.pivot_steady_pattern(
                runner.steady_state(flat_median, runner.STEADY_STATE_TOLERANCE)
            ),
            "other",
        )

        diagnostic = [100] * 175 + [200] * 9 + [100] * 175 + [200] * 9
        diagnostic_result = runner.steady_state(
            diagnostic, runner.STEADY_STATE_TOLERANCE
        )
        self.assertEqual(len(diagnostic_result[-2]), 1)
        self.assertEqual(
            (
                diagnostic_result[-2][0]["quantile"],
                diagnostic_result[-2][0]["exceedances"],
                diagnostic_result[-2][0]["critical_count"],
            ),
            (95, 18, 14),
        )
        self.assertEqual(diagnostic_result[-1], "steady")
        median_drift = [100] * 499 + [130] + [130] * 500
        median_result = runner.steady_state(
            median_drift, runner.STEADY_STATE_TOLERANCE
        )
        self.assertEqual(median_result[-1], "not steady")
        with self.assertRaises(runner.Refused) as caught:
            runner.steady_state([1_000_000] * 500 + [50_000_000] * 500, 0.99)
        self.assertEqual(str(caught.exception), "steady-state-tolerance")
        offloads = """Features for q3h:
tcp-segmentation-offload: off
generic-segmentation-offload: off
generic-receive-offload: off
"""
        self.assertEqual(
            runner.validate_offload_state(offloads),
            {"tso": False, "gso": False, "gro": False},
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_offload_state(offloads.replace("off", "on", 1))
        self.assertEqual(str(caught.exception), "offload-state-invalid")
        venue = {
            "GRANARY_Q3_VENUE_BACKING": "/dev/vda1 ext4 rw",
            "GRANARY_Q3_VENUE_CACHE_MODE": "write back",
            "GRANARY_Q3_VENUE_TEXT": (
                "VM; kernel timer granularity applies; cannot describe host cache"
            ),
        }
        self.assertEqual(
            runner.venue_storage_environment(venue)["venue_cache_mode"], "write back"
        )
        for malformed, reason in (
            ({}, "venue-storage-unrecorded"),
            ({**venue, "GRANARY_Q3_VENUE_TEXT": "VM only"}, "venue-storage-caveat"),
        ):
            with self.assertRaises(runner.Refused) as caught:
                runner.venue_storage_environment(malformed)
            self.assertEqual(str(caught.exception), reason)

        cases = (
            (
                "steady-state receipt",
                "steady-state-mismatch",
                lambda row: row.update(steady_state="not steady"),
            ),
            (
                "duration artifact digest",
                "durations-artifact-hash-mismatch",
                lambda row: row.update(durations_artifact_sha256="0" * 64),
            ),
            (
                "netem placement",
                "offload-state-required",
                lambda row: row.update(netem_delay_placement="both-veth-egress"),
            ),
            (
                "offload receipt",
                "offload-state-required",
                lambda row: row["offload_state"]["host"].update(tso=True),
            ),
            (
                "timer caveat",
                "venue-timer-caveat",
                lambda row: row.update(venue_text="VM venue"),
            ),
        )
        for label, reason, mutate in cases:
            with self.subTest(label=label):
                malformed = self.fixture()
                mutate(malformed["samples"][0])
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate(malformed)
                self.assertEqual(str(caught.exception), reason)
        temporal = self.fixture()["samples"][0]
        temporal_path = Path(self.temporary.name) / "temporal.ns"
        self.write_duration_fixture(temporal_path, [1, 4] * 500)
        temporal.update(
            durations_artifact=str(temporal_path),
            durations_artifact_sha256=hashlib.sha256(temporal_path.read_bytes()).hexdigest(),
            fsync_min_ns=1,
            fsync_p50_ns=1,
            fsync_p90_ns=4,
            fsync_p99_ns=4,
            fsync_max_ns=4,
            steady_first_half_median_ns=2,
            steady_second_half_median_ns=2,
            steady_first_half_p99_ns=4,
            steady_second_half_p99_ns=4,
            steady_exceedance_splits=[
                {
                    "population": 1000,
                    "quantile": percentile,
                    "threshold_ns": 4,
                    "exceedances": 0,
                    "critical_count": 1,
                    "split": [0, 0],
                    "tail_probability": "0/1",
                }
                for percentile in (95, 99)
            ],
            steady_state="steady",
        )
        runner.validate_row(temporal)
        drifting = self.fixture()
        drifting_path = Path(self.temporary.name) / "drifting.ns"
        self.write_duration_fixture(drifting_path, [1] * 500 + [4] * 500)
        drifting["samples"][0].update(
            durations_artifact=str(drifting_path),
            durations_artifact_sha256=hashlib.sha256(drifting_path.read_bytes()).hexdigest(),
            fsync_min_ns=1,
            fsync_p50_ns=1,
            fsync_p90_ns=4,
            fsync_p99_ns=4,
            fsync_max_ns=4,
            steady_first_half_median_ns=1,
            steady_second_half_median_ns=4,
            steady_first_half_p99_ns=1,
            steady_second_half_p99_ns=4,
            steady_exceedance_splits=[
                {
                    "population": 1000,
                    "quantile": percentile,
                    "threshold_ns": 4,
                    "exceedances": 0,
                    "critical_count": 1,
                    "split": [0, 0],
                    "tail_probability": "0/1",
                }
                for percentile in (95, 99)
            ],
            steady_state="not steady",
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(drifting)
        self.assertEqual(str(caught.exception), "not-steady")
        self.assertGreater(len(cases), 0)
        print(
            "CONTROL steady/offload: observed=3 refused=offload-state-invalid,"
            + ",".join(reason for _, reason, _ in cases)
            + ",not-steady"
        )

    def test_intent_not_applicable_and_device_measurement(self):
        def measured_authority_wait(doc):
            self.pivot_pair(doc)
            doc["samples"][0]["authority_log_wait_p99_ns"] = 1_000_000

        not_applicable = self.fixture()
        self.assertGreater(runner.validate(not_applicable), 0)
        self.pair(
            "not-applicable intent fields",
            "intent-not-applicable-fields",
            lambda d: d["samples"][0].update(written_bytes=0),
        )
        self.pair(
            "unmeasured device amplification",
            "device-amplification-unmeasured",
            lambda d: self.intent_document(d, device_amplification=1.0),
            self.intent_document,
        )
        self.pair(
            "unmeasured closed-loop authority wait",
            "authority-log-wait-unmeasured",
            lambda d: self.intent_document(d, authority_log_wait_p99_ns=1_000_000),
            measured_authority_wait,
        )
        self.pair(
            "not-applicable cross-volume blocking",
            "cross-volume-blocking-not-applicable",
            lambda d: self.intent_document(d, cross_volume_blocked_ns=0),
            self.intent_document,
        )

        measured = self.fixture()
        self.pivot_pair(measured)
        for row in measured["samples"][:2]:
            row.update(device_bytes=1600, encode_register_bytes=800, device_amplification=2.0)
        self.assertGreater(runner.validate(measured), 0)
        measured["samples"][0]["device_amplification"] = 1.0
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(measured)
        self.assertEqual(str(caught.exception), "device-amplification")
        print("CONTROL intent applicability: observed=3 refused=device-amplification")

    def test_non_intent_authority_log_wait_applicability(self):
        self.pair(
            "non-intent authority log wait",
            "intent-not-applicable-fields",
            lambda d: d["samples"][0].update(authority_log_wait_p99_ns=0),
        )

    def test_non_intent_cross_volume_blocked_applicability(self):
        self.pair(
            "non-intent cross-volume blocked",
            "intent-not-applicable-fields",
            lambda d: d["samples"][0].update(cross_volume_blocked_ns=0),
        )

    def test_authority_log_wait_schema(self):
        self.pair(
            "authority log wait schema",
            "schema-invalid: authority_log_wait_p99_ns",
            lambda d: d["samples"][0].update(authority_log_wait_p99_ns=None),
        )

    def test_cross_volume_blocked_schema(self):
        self.pair(
            "cross-volume blocked schema",
            "schema-invalid: cross_volume_blocked_ns",
            lambda d: d["samples"][0].update(cross_volume_blocked_ns=None),
        )

    def cross_volume_fixture(self):
        path = self.log.with_name("cross_volume.tsv")
        header = ("baseline_start_ns\tbaseline_end_ns\tcommit_start_ns\tcommit_end_ns\trequest_start_ns\t"
                  "request_queued_ns\trequest_end_ns\tcommit_ns\twait_ns\tauthority_log_wait_ns\n")
        samples = [f"{i}\t{i+2}\t{i+6}\t{i+86}\t{i+10}\t{i+11}\t{i+90}\t80\t78\t3\n"
                   for i in range(0, 20_000, 200)]
        path.write_text(header + "".join(samples))
        return path, header, samples

    def test_cross_volume_export_and_refusals(self):
        path, header, samples = self.cross_volume_fixture()
        row = runner.cross_volume_document(path)
        self.assertEqual(runner.validate(row), 1)
        self.assertEqual((row["cross_volume_blocked_ns"], row["authority_log_wait_p99_ns"]), (78, 3))
        tsv = ["--cross-volume-tsv", str(path)]
        work = ["--work", str(path.parent)]
        server = ["--server-child", "server"]
        pivot = ["--pivot-measurement"]
        with (
            patch.object(sys, "argv", ["q3-measurement.py", *tsv]),
            patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            self.assertEqual(runner.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue()), row)
        for argv, reason in (
            ([str(self.log), *tsv], "smoke-manifest-conflict"),
            (["--cross-volume-tsv", str(self.log)], "cross-volume-sample-fields"),
            (pivot + tsv, "smoke-manifest-conflict"),
            (pivot + ["--loopback-smoke"], "measurement-mode-conflict"),
            (pivot, "schema-missing: work"),
            (pivot + work, "schema-missing: server-child"),
            (["--loopback-smoke"] + work + server, "schema-missing: client-child"),
            (["--recovery-measurement"] + work + server + ["--client-child", "client"], "schema-missing: gran"),
            ([], "schema-missing: manifest"),
            (tsv + work, "smoke-option-without-mode"),
        ):
            with (
                self.subTest(argv=argv),
                patch.object(sys, "argv", ["q3-measurement.py", *argv]),
                patch("sys.stdout", new_callable=io.StringIO) as stdout,
                patch("sys.stderr", new_callable=io.StringIO) as stderr,
            ):
                self.assertEqual(runner.main(), 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(json.loads(stderr.getvalue()), {"event": "refused", "reason": reason})
        for suffix, replacement in (
            ("sample-fields", samples[0].replace("\t3\n", "\t-3\n")),
            ("sample-floor", ""),
            ("commit-duration", samples[0].replace("\t80\t", "\t0\t")),
            ("overlap", samples[0].replace("\t11\t", "\t86\t")),
            ("baseline", samples[0].replace("0\t2\t", "6\t8\t", 1)),
            ("wait", samples[0].replace("\t78\t", "\t77\t")),
        ):
            path.write_text(header + replacement + "".join(samples[1:]))
            malformed = dict(row, sample_count=99 + bool(replacement), cross_volume_samples_artifact_sha256=runner.digest(path))
            with self.subTest(suffix=suffix), self.assertRaisesRegex(runner.Refused, f"^cross-volume-{suffix}$"):
                runner.validate(malformed)
        path.write_text(header + "".join(samples))
        for suffix, update in (
            ("artifact", dict(cross_volume_samples_artifact=None)),
            ("artifact-unreadable", dict(cross_volume_samples_artifact=str(path.with_suffix(".missing")))),
            ("artifact-hash", dict(cross_volume_samples_artifact_sha256="0" * 64)),
            ("summary", dict(cross_volume_blocked_ns=78.0)),
        ):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(runner.Refused, f"^cross-volume-{suffix}$"):
                runner.validate(dict(row, **update))

    def test_review_boundary_pairs(self):
        def replace_rc(doc, text, exit_code):
            path = self.rc.with_name("review.rc")
            path.write_text(text)
            row = doc["samples"][0]
            row.update(
                raw_rc=str(path),
                raw_rc_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                exit_code=exit_code,
            )

        for text, exit_code, reason in (
            ("1\n", 1, "command-exit-nonzero"),
            ("124\n", 124, "command-exit-nonzero"),
            ("-9\n", -9, "command-exit-nonzero"),
            ("137\n", 137, "command-exit-nonzero"),
            ("٠\n", 0, "raw-rc-invalid"),
            ("00\n", 0, "raw-rc-invalid"),
            ("12345\n", 0, "raw-rc-invalid"),
        ):
            with self.subTest(rc=text.strip()):
                self.pair(
                    "command exit " + text.strip(),
                    reason,
                    lambda d, text=text, exit_code=exit_code: replace_rc(
                        d, text, exit_code
                    ),
                )
        self.pair(
            "RC/row mismatch",
            "raw-rc-exit-mismatch",
            lambda d: d["samples"][0].update(exit_code=1),
        )
        self.pair(
            "RC hash",
            "raw-rc-hash-mismatch",
            lambda d: d["samples"][0].update(raw_rc_sha256="0" * 64),
        )

        for venue in ("VM", "Vm", "podman-vm", "vm ", "authority-vm"):
            with self.subTest(venue=venue):
                self.pair(
                    "venue " + repr(venue),
                    "schema-invalid: venue",
                    lambda d, venue=venue: d["samples"][0].update(
                        venue=venue, hardware=True
                    ),
                    lambda d: d["samples"][0].update(venue="vm", hardware=False),
                )

        for label in ("707B", "707 B", "707-b"):
            with self.subTest(root_label=label):
                self.pair(
                    "root label " + label,
                    "schema-invalid: root_label",
                    lambda d, label=label: d["samples"][0].update(
                        root_label=label, root_bytes=706
                    ),
                    lambda d: d["samples"][0].update(
                        root_label="measured length", root_bytes=706
                    ),
                )
        self.pair(
            "measured label at 707",
            "measured-root-size",
            lambda d: d["samples"][0].update(
                root_label="measured length", root_bytes=707
            ),
            lambda d: d["samples"][0].update(
                root_label="measured length", root_bytes=706
            ),
        )

        for kind in ("reachable", "upper-bound", "upper bound", "Upper-Bound"):
            with self.subTest(historical_kind=kind):
                self.pair(
                    "historical kind " + kind,
                    "schema-invalid: historical_kind",
                    lambda d, kind=kind: d["samples"][0].update(historical_kind=kind),
                    lambda d: d["samples"][0].update(
                        historical_kind="in-format", pivot_input=False
                    ),
                )

        for metrics in (["rtt"], ["control_writes"], ["wall_clock_ms", "chain_growth"]):
            with self.subTest(metrics=metrics):
                self.pair(
                    "deciding metrics " + repr(metrics),
                    "wall-clock-only-verdict",
                    lambda d, metrics=metrics: d["samples"][0].update(
                        verdict_metrics=metrics
                    ),
                    lambda d: d["samples"][0].update(
                        verdict_metrics=["rtt", "control_writes"]
                    ),
                )

        for path in sorted(runner.LOOPBACK_PATHS):
            with self.subTest(network_path=path):
                self.pair(
                    "nonzero RTT on " + path,
                    "nonzero-rtt-loopback",
                    lambda d, path=path: self.loopback_row(d, 1, path),
                    lambda d, path=path: self.loopback_row(d, 0, path),
                )
        self.pair(
            "duplicate configured nonzero RTT",
            "rtt-group-needs-two-nonzero",
            lambda d: d["samples"][2].update(configured_rtt_ms=10),
        )

        def observed_rtts(document, values, configured=None):
            for row, value in zip(document["samples"], values):
                row.update(rtt_ms=value, observed_rtt_pre_ms=value, observed_rtt_post_ms=value, observed_rtt_ms=value)
            if configured is not None:
                for row, value in zip(document["samples"], configured):
                    row.update(configured_rtt_ms=value)

        self.pair(
            "published fsync planned population",
            "publish-population-invalid",
            lambda d: (
                self.published_rows(d),
                d["samples"][0].update(
                    successful_fsyncs=5,
                    logical_publishes=5,
                    publish_attempts=5,
                    route_attempts={"POST /volume/:volume/publish": 5},
                ),
            ),
            self.published_rows,
        )

        self.pair(
            "configured RTT was not observed",
            "rtt-observation-invalid",
            lambda d: observed_rtts(d, (0.05, 0.05, 0.05)),
            lambda d: observed_rtts(d, (0.07, 10.86, 54.34)),
        )
        self.pair(
            "configured RTT below observation tolerance floor",
            "rtt-observation-invalid",
            lambda d: observed_rtts(d, (0.05, 0.05, 0.05), (0, 3, 4)),
            lambda d: observed_rtts(d, (0.07, 10.86, 54.34), (0, 10, 50)),
        )
        self.pair(
            "missing RTT calibration outcome",
            "schema-missing: calibration_outcome",
            lambda d: d["samples"][0].pop("calibration_outcome"),
        )
        self.pair(
            "inconsistent RTT calibration outcome",
            "rtt-calibration-outcome-mismatch",
            lambda d: d["samples"][0].update(
                calibration_outcome="refused",
                calibration_reason="rtt-fsync-calibration-invalid",
            ),
            lambda d: [
                row.update(
                    calibration_outcome="refused",
                    calibration_reason="rtt-fsync-calibration-invalid",
                )
                for row in d["samples"]
            ],
        )
        self.pair(
            "zero logical publishes",
            "publish-population-invalid",
            lambda d: (
                self.published_rows(d),
                d["samples"][0].update(logical_publishes=0),
            ),
            self.published_rows,
        )

        self.pair(
            "huge offered rate",
            "schema-invalid: offered_rate",
            lambda d: d["samples"][0].update(offered_rate=runner.MAX_INTEGER + 1),
            lambda d: d["samples"][0].update(offered_rate=runner.MAX_INTEGER),
        )
        self.pair(
            "huge sample count",
            "schema-invalid: sample_count",
            lambda d: d["samples"][0].update(sample_count=runner.MAX_INTEGER + 1),
        )

        for valid, malformed, reason in (
            (
                "2026-01-04T01:02:03Z",
                "2026-1-4T1:2:3Z",
                "date-required",
            ),
            (
                "2026-01-04T01:02:03Z",
                "2026-01-04T01:02:03z",
                "date-required",
            ),
            (
                "2000-01-01T00:00:00Z",
                "1999-12-31T23:59:59Z",
                "date-out-of-range",
            ),
            (
                "2100-01-01T00:00:00Z",
                "2100-01-01T00:00:01Z",
                "date-out-of-range",
            ),
        ):
            with self.subTest(date=malformed):
                self.pair(
                    "date " + malformed,
                    reason,
                    lambda d, malformed=malformed: d["samples"][0].update(
                        date=malformed
                    ),
                    lambda d, valid=valid: d["samples"][0].update(date=valid),
                )

        for bad, good in (
            (["child", "--token=value"], ["child", "--token-file=token.path"]),
            (["child", "--key=value"], ["child", "--key-file=key.path"]),
            (["child", "password"], ["child", "passwor"]),
            (["child", "secret"], ["child", "secre"]),
        ):
            with self.subTest(command=bad):
                self.pair(
                    "credential argv " + bad[-1],
                    "credential-in-command",
                    lambda d, bad=bad: d["samples"][0].update(command=bad),
                    lambda d, good=good: d["samples"][0].update(command=good),
                )

        self.pair(
            "steady sample floor",
            "sample-floor",
            lambda d: d["samples"][0].update(sample_count=999),
        )
        self.pair(
            "zero declared floor",
            "sample-floor",
            lambda d: (self.set_population(d, 1, "control"), d["samples"][0].update(sample_floor=0)),
            lambda d: self.set_population(d, 1, "control"),
        )
        self.pair(
            "steady declared floor",
            "steady-sample-floor",
            lambda d: d["samples"][0].update(sample_floor=999),
        )
        for kind, floor in (("calibration", 32), ("control", 1)):
            document = self.fixture()
            document["samples"] = document["samples"][:1]
            self.set_population(document, floor, kind)
            document["samples"][0].update(
                rtt_group=None,
                calibration_outcome=None,
                calibration_reason=None,
            )
            self.assertGreater(runner.validate(document), 0)
        print(
            "CONTROL review boundaries: calibration-floor=32 control-floor=1 observed=1"
        )

    def test_path_boundary_pairs(self):
        relative = self.fixture()
        relative["samples"][0]["raw_log"] = "cell.log"
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(relative)
        self.assertEqual(str(caught.exception), "raw-artifact-path")

        target = self.log.with_name("target.txt")
        target.write_text("fixture output\n")
        link = self.log.with_name("link.log")
        link.symlink_to(target)
        linked = self.fixture()
        linked["samples"][0].update(
            raw_log=str(link),
            raw_log_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(linked)
        self.assertEqual(str(caught.exception), "raw-artifact-path")

        with tempfile.TemporaryDirectory(prefix="q3-outside-") as directory:
            outside = Path(directory) / "outside.log"
            outside.write_text("fixture output\n")
            escaped = self.fixture()
            escaped["samples"][0].update(
                raw_log=str(outside),
                raw_log_sha256=hashlib.sha256(outside.read_bytes()).hexdigest(),
            )
            with self.assertRaises(runner.Refused) as caught:
                runner.validate(escaped)
            self.assertEqual(str(caught.exception), "raw-artifact-outside-run-root")

        checkout = self.log.parent / "checkout"
        checkout.mkdir()
        inside_rc = checkout / "inside.rc"
        inside_rc.write_text("0\n")
        inside = self.fixture()
        inside["samples"][0].update(
            raw_rc=str(inside_rc),
            raw_rc_sha256=hashlib.sha256(inside_rc.read_bytes()).hexdigest(),
        )
        with (
            patch.object(runner, "REPOSITORY", checkout.resolve()),
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.validate(inside)
        self.assertEqual(str(caught.exception), "raw-artifact-inside-repository")

        self.assertEqual(
            (
                runner.contained(Path("/tmp/repo/out"), Path("/tmp/repo")),
                runner.contained(Path("/TMP/REPO/out"), Path("/tmp/repo")),
                runner.contained(Path("/tmp/other"), Path("/tmp/repo")),
            ),
            (True, True, False),
        )
        self.assertGreater(runner.validate(self.fixture()), 0)
        print(
            "CONTROL paths: observed=3 relative/symlink/outside refused; casefold edge=true"
        )

    def test_command_custody_pairs(self):
        with tempfile.TemporaryDirectory(prefix="q3-custody-") as directory:
            root = Path(directory)
            work = runner.new_work(root / "work")
            record = runner.run_command(
                [sys.executable, "-c", "print('raw fixture')"], "child", cwd=work
            )
            self.assertEqual(
                (
                    (work / "child.log").read_text(),
                    (work / "child.rc").read_text(),
                    set(record),
                ),
                (
                    "raw fixture\n",
                    "0\n",
                    {
                        "command",
                        "exit_code",
                        "run_root",
                        "raw_log",
                        "raw_rc",
                        "raw_log_sha256",
                        "raw_rc_sha256",
                        "started_at",
                    },
                ),
            )
            first_stamp = Mock()
            first_stamp.strftime.return_value = "2026-11-17T12:00:00Z"
            later_stamp = Mock()
            later_stamp.strftime.return_value = "2026-11-17T12:00:01Z"
            clock = Mock()
            clock.now.side_effect = [first_stamp, later_stamp]
            with patch.object(runner, "datetime", clock):
                started = runner.run_command(
                    [sys.executable, "-c", "pass"], "started-at", cwd=work
                )
            self.assertEqual(started["started_at"], "2026-11-17T12:00:00Z")
            first_log = (work / "child.log").read_bytes()
            first_rc = (work / "child.rc").read_bytes()
            with self.assertRaises(runner.Refused) as caught:
                runner.run_command(
                    [sys.executable, "-c", "print('overwrite')"], "child", cwd=work
                )
            self.assertEqual(str(caught.exception), "command-evidence-exists")
            self.assertEqual(
                ((work / "child.log").read_bytes(), (work / "child.rc").read_bytes()),
                (first_log, first_rc),
            )
            for stem in ("", "."):
                with (
                    self.subTest(stem=stem),
                    self.assertRaises(runner.Refused) as caught,
                ):
                    runner.run_command(
                        [sys.executable, "-c", "print(1)"], stem, cwd=work
                    )
                self.assertEqual(str(caught.exception), "command-custody-invalid")
            with patch.object(runner, "REPOSITORY", root.resolve()):
                with self.assertRaises(runner.Refused) as caught:
                    runner.new_work(root / "inside")
                self.assertEqual(
                    str(caught.exception), "work-directory-inside-repository"
                )
            child = Mock(
                pid=4321,
                wait=Mock(side_effect=[subprocess.TimeoutExpired("fixture", 1), 0]),
            )
            with (
                patch.object(runner.subprocess, "Popen", return_value=child),
                patch.object(runner.os, "killpg") as killpg,
            ):
                timed = runner.run_command(["fixture"], "timed", cwd=work, timeout=1)
            self.assertEqual(Path(timed["raw_rc"]).read_text(), "124\n")
            self.assertEqual(timed["exit_code"], 124)
            killpg.assert_called_once_with(4321, signal.SIGKILL)

            abort_events = []
            running = {"finished": False, "cwd": work}

            def finish_abort(record, **options):
                abort_events.append(("finish", options))
                record["finished"] = True

            def unmount(command, stem, **options):
                abort_events.append(("unmount", command, stem, options))

            mount = work / "client" / "mount"
            with (
                patch.object(runner, "finish_command", side_effect=finish_abort),
                patch.object(runner, "run_command", side_effect=unmount),
            ):
                runner.abort_command(running, mount)
            self.assertEqual(
                abort_events,
                [
                    ("finish", {"timeout": 1, "stop_signal": signal.SIGKILL}),
                    (
                        "unmount",
                        ["umount", "-l", "--", str(mount)],
                        "client-cleanup-unmount",
                        {"cwd": work, "timeout": 5},
                    ),
                ],
            )

            with patch.dict(os.environ, {"PROBE_VAR": "present"}):
                inherited = runner.run_command(
                    [
                        sys.executable,
                        "-c",
                        "import json, os; print(json.dumps({'keys': sorted(os.environ), 'probe': 'PROBE_VAR' in os.environ}))",
                    ],
                    "environment",
                    cwd=work,
                )
            environment = json.loads(Path(inherited["raw_log"]).read_text())
            self.assertEqual(
                (environment["keys"], environment["probe"]),
                (
                    [
                        "HOME",
                        "LANG",
                        "LC_ALL",
                        "PATH",
                        "TMPDIR",
                        "__CF_USER_TEXT_ENCODING",
                    ],
                    False,
                ),
            )

            checked_output = runner.checked(
                [sys.executable, "-c", "print('checked fixture')"],
                "checked-valid",
                cwd=work,
            )
            self.assertEqual(checked_output, "checked fixture\n")
            with self.assertRaises(runner.Refused) as caught:
                runner.checked(
                    [sys.executable, "-c", "raise SystemExit(7)"],
                    "checked-failed",
                    cwd=work,
                )
            self.assertEqual(
                str(caught.exception), "command-failed: checked-failed"
            )
            self.assertGreater(len(checked_output), 0)
            print(
                "CONTROL checked command: "
                f"observed={checked_output.strip()} refused={caught.exception}"
            )

            for index, bad in enumerate(
                ("--token=value", "--key=value", "password", "secret")
            ):
                with (
                    self.subTest(argv=bad),
                    self.assertRaises(runner.Refused) as caught,
                ):
                    runner.run_command(
                        ["/bin/echo", bad], f"credential-{index}", cwd=work
                    )
                self.assertEqual(str(caught.exception), "credential-in-command")

            background = runner.run_command(
                ["/bin/sh", "-c", "(sleep 0.2; echo late) & echo early"],
                "background",
                cwd=work,
            )
            time.sleep(0.4)
            self.assertEqual(
                (
                    Path(background["raw_log"]).read_text(),
                    runner.digest(Path(background["raw_log"])),
                ),
                ("early\n", background["raw_log_sha256"]),
            )

            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(self.fixture()))
            result = subprocess.run(
                [sys.executable, runner.__file__, str(manifest)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                (result.returncode, json.loads(result.stdout)["samples"]), (0, 3)
            )
            malformed = self.fixture()
            malformed["samples"][0].pop("command")
            manifest.write_text(json.dumps(malformed))
            result = subprocess.run(
                [sys.executable, runner.__file__, str(manifest)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                (result.returncode, json.loads(result.stderr)["reason"]),
                (1, "schema-missing: command"),
            )
            duplicate = json.dumps(self.fixture()).replace(
                '"sample_loss": 0', '"sample_loss": 1, "sample_loss": 0', 1
            )
            manifest.write_text(duplicate)
            result = subprocess.run(
                [sys.executable, runner.__file__, str(manifest)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                (result.returncode, json.loads(result.stderr)["reason"]),
                (1, "duplicate-json-key: sample_loss"),
            )
            huge = self.fixture()
            huge["samples"][0]["rtt_ms"] = 10**400
            manifest.write_text(json.dumps(huge))
            result = subprocess.run(
                [sys.executable, runner.__file__, str(manifest)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                (result.returncode, json.loads(result.stderr)["reason"]),
                (1, "schema-invalid: rtt_ms"),
            )
            manifest.write_bytes(b"\xff")
            result = subprocess.run(
                [sys.executable, runner.__file__, str(manifest)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                (result.returncode, json.loads(result.stderr)["reason"]),
                (1, "manifest-unreadable"),
            )
            print(
                "CONTROL command custody: observed=3 refused=schema-missing: command "
                "work-refused=work-directory-inside-repository timeout-rc=124 owned-pid=4321 "
                "existing/empty/dot-stem=refused fixed-env=6 credentials=4-refused "
                "background-hash=stable duplicate-key=refused huge-int=refused "
                "abort-umount=umount -l -- <work>/client/mount"
            )

    def test_loopback_smoke_join_and_marker_controls(self):
        # This is the closed JSON formatter's documented shape from
        # observe/boundary.rs::encode: event fields stay top-level and the
        # exact operation identity/kind is the innermost object in spans[].
        def operation_rows(operation_id, kind="fsync"):
            span = dict(name="op", op=operation_id, kind=kind)
            return [
                dict(
                    level="DEBUG",
                    target="granary_client::event",
                    event="op.begin",
                    kind=kind,
                    spans=[span],
                ),
                dict(
                    level="DEBUG",
                    target="granary_client::event",
                    event="op.end",
                    kind=kind,
                    outcome="ok",
                    spans=[span],
                ),
            ]

        operation_id = "cor-0123456789abcdef"
        commit_id = "cor-fedcba9876543210"
        valid_server = [
            dict(
                schema="granary.q3.server.v2",
                kind="http_attempt",
                arrival_seq=1,
                request_id="q3-mark-smoke-start",
                request_id_kind="present",
                method="POST",
                route="/other",
            ),
            dict(
                schema="granary.q3.server.v2",
                kind="http_attempt",
                arrival_seq=2,
                request_id=operation_id,
                request_id_kind="present",
                method="POST",
                route="/volume/:volume/intent",
            ),
            dict(
                schema="granary.q3.server.v2",
                kind="http_attempt",
                arrival_seq=3,
                request_id=commit_id,
                request_id_kind="present",
                method="POST",
                route="/volume/:volume/publish",
            ),
            dict(
                schema="granary.q3.server.v2",
                kind="http_attempt",
                arrival_seq=4,
                request_id="q3-mark-smoke-end",
                request_id_kind="present",
                method="POST",
                route="/other",
            ),
            dict(
                schema="granary.q3.server.v2",
                kind="http_attempt",
                arrival_seq=5,
                request_id=None,
                request_id_kind="absent",
                method="PUT",
                route="/other",
            ),
        ]
        client = operation_rows(operation_id) + operation_rows(commit_id, "commit")
        observed = runner.validate_smoke(valid_server, client, "smoke", 1)
        self.assertEqual(observed, 2)

        controls = []
        # The declared population must match the client log's fsync lifecycles.
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_smoke(valid_server, client, "smoke", 2)
        self.assertEqual(str(caught.exception), "fsync-lifecycle-population-mismatch")
        controls.append(str(caught.exception))
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_smoke(valid_server, [], "smoke", 1)
        self.assertEqual(str(caught.exception), "server-id-absent-from-client-log")
        controls.append(str(caught.exception))

        invented_top_level = [
            dict(event="op.begin", kind="fsync", op=operation_id),
            dict(event="op.end", kind="fsync", outcome="ok", op=operation_id),
        ]
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_smoke(valid_server, invented_top_level, "smoke", 1)
        self.assertEqual(str(caught.exception), "server-id-absent-from-client-log")
        controls.append("top-level-op-refused")

        completion_ordered = [dict(row) for row in valid_server]
        completion_ordered.insert(
            2,
            dict(
                schema="granary.q3.server.v2",
                kind="http_attempt",
                arrival_seq=2,
                request_id=None,
                request_id_kind="absent",
                method="GET",
                route="/other",
            ),
        )
        completion_ordered[1]["arrival_seq"] = 3
        completion_ordered[3]["arrival_seq"] = 4
        completion_ordered[-2]["arrival_seq"] = 5
        completion_ordered[-1]["arrival_seq"] = 6
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_smoke(completion_ordered, client, "smoke", 1)
        self.assertEqual(str(caught.exception), "id-less-attempt-between-markers")
        controls.append(str(caught.exception))

        before_marker = [dict(row) for row in completion_ordered]
        before_marker[0]["arrival_seq"] = 2
        before_marker[2]["arrival_seq"] = 1
        self.assertGreater(
            runner.validate_smoke(before_marker, client, "smoke", 1), 0
        )

        rule_counts = {
            "fsync lifecycle": 0,
            "markers": 0,
            "arrival sequence": 0,
            "schema": 0,
            "marker order": 0,
            "operation kind": 0,
            "fsync register": 0,
            "late commit": 0,
        }
        rule_refusals = []

        def refuses(label, server_rows, client_rows, reason):
            with self.assertRaises(runner.Refused) as caught:
                runner.validate_smoke(server_rows, client_rows, "smoke", 1)
            self.assertEqual(str(caught.exception), reason)
            rule_counts[label] += 1
            rule_refusals.append(str(caught.exception))

        lifecycle_error = operation_rows(operation_id) + operation_rows(
            commit_id, "commit"
        )
        lifecycle_error[1]["outcome"] = "error"
        refuses(
            "fsync lifecycle",
            valid_server,
            lifecycle_error,
            "fsync-lifecycle-invalid",
        )
        refuses(
            "fsync lifecycle",
            valid_server,
            operation_rows(operation_id)[1:] + operation_rows(commit_id, "commit"),
            "fsync-lifecycle-invalid",
        )

        duplicate_marker = [dict(row) for row in valid_server]
        duplicate_marker.append(dict(valid_server[0], arrival_seq=6))
        refuses("markers", duplicate_marker, client, "cell-markers-invalid")

        duplicate_sequence = [dict(row) for row in valid_server]
        duplicate_sequence[-1]["arrival_seq"] = 4
        refuses(
            "arrival sequence",
            duplicate_sequence,
            client,
            "server-arrival-seq-duplicate",
        )

        old_schema = [dict(row) for row in valid_server]
        old_schema[1]["schema"] = "granary.q3.server.v1"
        refuses("schema", old_schema, client, "server-schema-invalid")

        reversed_markers = [dict(row) for row in valid_server]
        reversed_markers[0]["arrival_seq"] = 6
        refuses(
            "marker order", reversed_markers, client, "cell-marker-order-invalid"
        )

        refuses(
            "operation kind",
            valid_server,
            client + operation_rows(operation_id, "commit"),
            "client-operation-kind-ambiguous",
        )

        wrong_register = [dict(row) for row in valid_server]
        wrong_register[1]["request_id"] = commit_id
        refuses("fsync register", wrong_register, client, "fsync-register-missing")

        late_commit = [dict(row) for row in valid_server]
        late_commit.append(
            dict(
                schema="granary.q3.server.v2",
                kind="http_attempt",
                arrival_seq=6,
                request_id=commit_id,
                request_id_kind="present",
                method="GET",
                route="/other",
            )
        )
        refuses("late commit", late_commit, client, "attempt-after-end-marker")
        self.assertTrue(all(count > 0 for count in rule_counts.values()), rule_counts)

        # Teardown starts its own commit after the end marker (the unmount's
        # publication); it is not a delayed cell request and must pass.
        teardown_id = "cor-0fedcba987654321"
        teardown = [dict(row) for row in valid_server]
        teardown.append(
            dict(
                schema="granary.q3.server.v2",
                kind="http_attempt",
                arrival_seq=6,
                request_id=teardown_id,
                request_id_kind="present",
                method="POST",
                route="/volume/:volume/publish",
            )
        )
        self.assertEqual(
            runner.validate_smoke(
                teardown, client + operation_rows(teardown_id, "commit"), "smoke", 1
            ),
            2,
        )

        with self.assertRaises(runner.Refused) as caught:
            runner.validate_smoke(valid_server, client, "smoke", 0)
        self.assertEqual(str(caught.exception), "planned-fsync-population-invalid")
        controls.append(str(caught.exception))
        print(
            f"CONTROL smoke correlation: observed={observed} refused={','.join(controls)} "
            f"rule-refusals={','.join(rule_refusals)} rule-cases={rule_counts}"
        )

    def test_namespace_command_controls(self):
        setup, enter, teardown = runner.namespace_commands(
            "q3-cell", "q3-host", "q3-client", "192.0.2.1/30", "192.0.2.2/30"
        )
        self.assertEqual(
            (len(setup), enter, teardown),
            (
                8,
                ["nsenter", "--net=/var/run/netns/q3-cell", "--"],
                [
                    ["ip", "link", "del", "q3-host"],
                    ["ip", "netns", "del", "q3-cell"],
                ],
            ),
        )
        cases = [
            (("bad/name", "q3-host", "q3-client", "192.0.2.1/30", "192.0.2.2/30"), "network-name-invalid"),
            (("q3-cell", "q3-host", "q3-client", "bad", "192.0.2.2/30"), "network-address-invalid"),
            (("q3-cell", "q3-host", "q3-client", "192.0.2.1/30", "198.51.100.2/30"), "network-address-invalid"),
        ]
        self.assertGreater(len(cases), 0)
        for arguments, refusal in cases:
            with self.subTest(arguments=arguments), self.assertRaises(runner.Refused) as caught:
                runner.namespace_commands(*arguments)
            self.assertEqual(str(caught.exception), refusal)
        print("CONTROL namespace commands: observed=8 refused=3")

    def test_network_names_are_unique_and_veth_bounded(self):
        first = runner.network_names(Path("/var/tmp/granary-q3-venue.aaaaaa"))
        second = runner.network_names(Path("/var/tmp/granary-q3-venue.bbbbbb"))
        self.assertNotEqual(first, second)
        self.assertTrue(all(len(name) <= 15 for name in first[1:] + second[1:]))
        self.assertTrue(all(name.startswith("q3") for name in first + second))
        print("CONTROL network names: observed=2 unique=2 veth-max=15")

    def test_each_measurement_mode_runs_resource_preflight_first(self):
        observed = []

        def preflight(work):
            observed.append(Path(work).name)

        with tempfile.TemporaryDirectory(prefix="q3-mode-preflight-") as directory:
            root = Path(directory)
            pivot = root / "pivot"
            pivot.mkdir()
            with self.assertRaises(runner.Refused) as caught:
                runner.run_pivot_measurement("server", pivot, resource_check=preflight)
            self.assertEqual(str(caught.exception), "revision-required")

            network = root / "network"
            network.mkdir()
            with patch.object(
                runner, "checked", side_effect=runner.Refused("network-preflight-stop")
            ), self.assertRaises(runner.Refused) as caught:
                runner.run_network_measurement(
                    "server", "client", network, resource_check=preflight
                )
            self.assertEqual(str(caught.exception), "network-preflight-stop")

            recovery = root / "recovery"
            recovery.mkdir()
            witnesses = []

            def outcome(_server, _client, _gran, _work, _profile, lose, _timeout):
                witness = {
                    "ledger": [
                        {
                            "operation_id": "a-0000",
                            "content_sha256": hashlib.sha256(bytes([1]) * (4 * 1024 * 1024)).hexdigest(),
                            "unique_content_bytes": 4 * 1024 * 1024,
                        }
                    ],
                    "cumulative_write_call_bytes": 4 * 1024 * 1024 + 4096,
                    "operator_verbs": [],
                    "final_head_operations": ["observed-loss" if lose else "observed-intact"],
                }
                witnesses.append(witness)
                return 1, 7, ["observed-pre-loss"], witness

            with patch.object(runner, "validate_recovery_pair", return_value=(0, 0)):
                result = runner.run_recovery_pair(
                    "server",
                    "client",
                    "gran",
                    recovery,
                    "published",
                    resource_check=preflight,
                    outcome_runner=outcome,
                )
            self.assertEqual(result["pair"]["pre_loss_head_operations"], ["observed-pre-loss"])
            self.assertEqual(
                [item["final_head_operations"] for item in (result["pair"]["loss"], result["pair"]["intact"])],
                [["observed-loss"], ["observed-intact"]],
            )
        self.assertEqual(observed, ["pivot", "network", "recovery"])

    def test_network_teardown_only_removes_created_objects(self):
        commands = []

        def preexisting(_command, stem, **_options):
            self.assertEqual(stem, "network-setup-0")
            raise runner.Refused("command-failed: network-setup-0")

        with (
            tempfile.TemporaryDirectory(prefix="q3-network-teardown-") as directory,
            patch.object(
                runner.Path,
                "read_text",
                return_value="MemAvailable: 5000000 kB\n",
            ),
            patch.object(runner, "resource_preflight"),
            patch.object(runner, "checked", side_effect=preexisting),
            patch.object(runner.subprocess, "run") as preexisting_unchecked,
            self.assertRaises(runner.Refused) as preexisting_refusal,
        ):
            runner.run_network_measurement(
                "server", "client", Path(directory), resource_check=lambda _work: None
            )
        self.assertEqual(
            str(preexisting_refusal.exception), "command-failed: network-setup-0"
        )
        preexisting_unchecked.assert_not_called()

        def checked(command, stem, **_options):
            commands.append((stem, command))
            if stem == "network-setup-1":
                raise runner.Refused("command-failed: network-setup-1")
            return ""

        with (
            tempfile.TemporaryDirectory(prefix="q3-network-teardown-") as directory,
            patch.object(
                runner.Path,
                "read_text",
                return_value="MemAvailable: 5000000 kB\n",
            ),
            patch.object(runner, "resource_preflight"),
            patch.object(runner, "checked", side_effect=checked),
            patch.object(runner.subprocess, "run") as unchecked,
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.run_network_measurement(
                "server", "client", Path(directory), resource_check=lambda _work: None
            )
        self.assertEqual(str(caught.exception), "command-failed: network-setup-1")
        self.assertEqual(
            [stem for stem, _command in commands],
            ["network-setup-0", "network-setup-1", "network-teardown-0"],
        )
        self.assertEqual(commands[-1][1][:3], ["ip", "netns", "del"])
        unchecked.assert_not_called()

        def failed_teardown(command, stem, **_options):
            if stem == "network-setup-1":
                raise runner.Refused("command-failed: network-setup-1")
            if stem == "network-teardown-0":
                raise runner.Refused("command-failed: network-teardown-0")
            return ""

        with (
            tempfile.TemporaryDirectory(prefix="q3-network-teardown-") as directory,
            patch.object(
                runner.Path,
                "read_text",
                return_value="MemAvailable: 5000000 kB\n",
            ),
            patch.object(runner, "resource_preflight"),
            patch.object(runner, "checked", side_effect=failed_teardown),
            self.assertRaises(runner.Refused) as teardown,
        ):
            runner.run_network_measurement(
                "server", "client", Path(directory), resource_check=lambda _work: None
            )
        self.assertEqual(
            str(teardown.exception), "command-failed: network-setup-1"
        )
        self.assertIn(
            "network teardown also refused: command-failed: network-teardown-0",
            teardown.exception.__notes__,
        )
        stderr = io.StringIO()
        with (
            patch.object(sys, "argv", ["q3-measurement.py", "--network-measurement", "--work", "/unused", "--server-child", "server", "--client-child", "client"]),
            patch.object(runner, "new_work", return_value=Path("/unused")),
            patch.object(runner, "run_network_measurement", side_effect=teardown.exception),
            patch("sys.stderr", stderr),
        ):
            self.assertEqual(runner.main(), 1)
        self.assertIn("network teardown also refused", json.loads(stderr.getvalue())["reason"])
        print(
            "CONTROL network teardown: preexisting=untouched created=namespace removed=namespace "
            f"setup-refused={caught.exception} teardown-refused={teardown.exception}"
        )

    def test_desk_firewall_sequence_and_evidence(self):
        probe = ["nft", "-j", "-a", "list", "chain", "inet", "gran_slot", "input"]
        tables = ["nft", "list", "tables"]
        delete = ["nft", "delete", "rule", "inet", "gran_slot", "input", "handle", "42"]
        table_checks = ("absent", "table-present", "tables-fail")
        broken_echo = {"no-handle": "", "unreadable-echo": b"\xff"}
        for case in ("present", *table_checks, "denied", *broken_echo, "insert-fails", "delete-fails", "already-gone", "vm"):
            commands = []
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory(prefix="q3-firewall-") as directory,
                patch.dict(os.environ, {"GRANARY_Q3_VENUE": "vm" if case == "vm" else "linux-desk"}),
                patch.object(runner, "stop_group"),
                patch.object(runner, "venue_storage_environment", side_effect=runner.Refused("fixture-stop")),
            ):
                work = Path(directory).resolve()
                namespace, veth, _ = runner.network_names(work)
                insert = [
                    "nft", "-a", "-e", "insert", "rule", "inet", "gran_slot", "input",
                    "iifname", f'"{veth}"', "accept", "comment", f'"gran-q3 {veth}"',
                ]
                absent = "<cmdline>:1:1-29: Error: No such file or directory\n"
                echo = f'add rule inet gran_slot input iifname "{veth}" accept comment "gran-q3 {veth}" # handle 42\nwarning: trailing output\n'
                listing = json.dumps({"nftables": [
                    {"rule": {"handle": 41, "comment": f"gran-q3 {veth}-other"}},
                    {"rule": {"handle": 42, "comment": f"gran-q3 {veth}"}},
                ]})
                replies = {
                    tuple(probe): (1, absent) if case in table_checks else
                    (1, "Error: Operation not permitted") if case == "denied" else (0, "{}\n"),
                    tuple(tables): (int(case == "tables-fail"), "table inet gran_slot\n" if case == "table-present" else "table ip gran_slot\n"),
                    tuple(insert): (int(case == "insert-fails"), broken_echo.get(case, echo)),
                    tuple(delete): (1, "Error: Could not process rule: No such file or directory") if case == "already-gone"
                    else (int(case == "delete-fails"), ""),
                }

                def popen(command, *, stdout, **_):
                    commands.append(command)
                    code, output = replies.get(tuple(command), (0, ""))
                    if command == probe and commands.count(probe) == 2:
                        code, output = 0, listing
                    stdout.write(output if isinstance(output, bytes) else output.encode())
                    return Mock(wait=Mock(return_value=code))

                with patch.object(runner.subprocess, "Popen", side_effect=popen), self.assertRaises(runner.Refused) as caught:
                    runner.run_network_measurement("server", "client", work, resource_check=lambda _: None)
                expected = [] if case == "vm" else [probe]
                if case in table_checks:
                    expected.append(tables)
                if case in ("present", *broken_echo, "insert-fails", "delete-fails", "already-gone"):
                    expected.append(insert)
                    if case in broken_echo:
                        expected.append(probe)
                    if case != "insert-fails":
                        expected.append(delete)
                self.assertEqual(commands[8:], expected + [["ip", "link", "del", veth], ["ip", "netns", "del", namespace]])
                if case in ("present", "delete-fails", "already-gone"):
                    self.assertEqual((work / "network-firewall-insert.log").read_text(), echo)
                    self.assertEqual((work / "network-firewall-delete.rc").read_text(), f"{replies[tuple(delete)][0]}\n")
                if case != "vm":
                    probe_rc, probe_output = replies[tuple(probe)]
                    self.assertEqual((work / "network-firewall-probe.rc").read_text(), f"{probe_rc}\n")
                    self.assertEqual((work / "network-firewall-probe.log").read_text(), probe_output)
                self.assertEqual(str(caught.exception), {
                    "denied": "network-firewall-probe-failed: Error: Operation not permitted",
                    "table-present": f"network-firewall-probe-failed: {absent.strip()}",
                    "tables-fail": f"network-firewall-probe-failed: {absent.strip()}",
                    "no-handle": "network-firewall-handle-missing",
                    "unreadable-echo": "network-firewall-handle-missing",
                    "insert-fails": "command-failed: network-firewall-insert",
                }.get(case, "fixture-stop"))
                self.assertEqual(getattr(caught.exception, "__notes__", []), (
                    ["network teardown also refused: command-failed: network-firewall-delete"]
                    if case == "delete-fails" else []
                ))

    def test_firewall_reap_deletes_only_stale_q3_handles(self):
        listing = {"nftables": [{"rule": {"handle": handle, **fields}} for handle, fields in (
            (21, {"comment": "gran-q3 q3h-gone-one"}),
            (22, {"comment": "gran-q3 q3h-live"}),
            (23, {"comment": "foreign gran-q3 q3h-gone-one"}),
            (24, {}),
            (25, {"comment": "gran-q3 q3h-gone-two"}),
        )]}
        probe = ["nft", "-j", "-a", "list", "chain", "inet", "gran_slot", "input"]
        delete = ["nft", "delete", "rule", "inet", "gran_slot", "input", "handle"]
        gone = "<cmdline>:1:1-40: Error: Could not process rule: No such file or directory\n"
        for case, code, output, status in (
            ("ok", 0, "", 0), ("delete-fails", 1, "Error: Operation not permitted", 1),
            ("gone", 1, gone, 0), ("wrong-status", 2, gone, 1),
            ("other-enoent", 1, "Error: No such file or directory", 1),
            ("probe-fails", 1, "Error: Operation not permitted", 1), ("malformed", 0, "{", 1),
            ("malformed-shape", 0, '{"nftables":{}}', 1),
        ):
            probe_only = case in ("probe-fails", "malformed", "malformed-shape")

            def execute(command, **_):
                if command == probe:
                    return Mock(returncode=code if probe_only else 0, stdout=output if probe_only else json.dumps(listing))
                return Mock(returncode=code if command[-1] == "21" else 0, stdout=output)

            stderr = io.StringIO()
            with (
                self.subTest(case=case), patch("sys.stderr", stderr),
                patch.object(runner.socket, "if_nameindex", return_value=[(2, "q3h-live")]),
                patch.object(runner.subprocess, "run", side_effect=execute) as run,
            ):
                self.assertEqual(runner.reap_firewall(), status)
                self.assertEqual(bool(stderr.getvalue()), bool(status))
                if case == "probe-fails":
                    self.assertIn("network-firewall-probe-failed", stderr.getvalue())
                self.assertEqual([call.args[0] for call in run.call_args_list],
                                 [probe] if probe_only else [probe, delete + ["21"], delete + ["25"]])

    def test_main_flushes_stdout_before_a_later_refusal(self):
        events = []

        class ObservedStream(io.StringIO):
            def __init__(self, name):
                super().__init__()
                self.name = name

            def write(self, value):
                events.append((self.name, "write"))
                return super().write(value)

            def flush(self):
                events.append((self.name, "flush"))
                return super().flush()

        stdout, stderr = ObservedStream("stdout"), ObservedStream("stderr")
        first = {"event": "recovery-pair", "pair": {}, "artifact_root": "/fixture"}
        cleanup_work = Path(self.temporary.name) / "cleanup-output"
        cleanup_work.mkdir()
        calls = 0

        def recovery_with_cleanup(*_args):
            nonlocal calls
            calls += 1
            if calls == 1:
                return first
            runner.run_command(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('umount: fixture not mounted', file=sys.stderr)",
                ],
                "recovery-image-cleanup",
                cwd=cleanup_work,
            )
            raise runner.Refused("later")

        with (
            patch.object(
                sys,
                "argv",
                ["q3-measurement.py", "--recovery-measurement", "--work", "/unused", "--server-child", "server", "--client-child", "client", "--gran", "gran"],
            ),
            patch.object(runner, "new_work", return_value=Path("/unused")),
            patch.object(runner, "run_recovery_pair", side_effect=recovery_with_cleanup),
            patch("sys.stdout", stdout),
            patch("sys.stderr", stderr),
        ):
            self.assertEqual(runner.main(), 1)
        lines = (stdout.getvalue() + stderr.getvalue()).splitlines()
        self.assertEqual([json.loads(line)["event"] for line in lines], ["recovery-pair", "refused"])
        self.assertLess(events.index(("stdout", "flush")), events.index(("stderr", "write")))
        self.assertEqual(
            (cleanup_work / "recovery-image-cleanup.log").read_text(),
            "umount: fixture not mounted\n",
        )

    def test_cell_evidence_and_targeted_deletion_controls(self):
        def operations(operation_ids, missing_end=None):
            rows = []
            for operation_id in operation_ids:
                span = dict(name="op", op=operation_id, kind="fsync")
                rows.append(dict(event="op.begin", kind="fsync", spans=[span]))
                if operation_id != missing_end:
                    rows.append(
                        dict(event="op.end", kind="fsync", outcome="ok", spans=[span])
                    )
            return rows

        ids = ["cor-0000000000000001", "cor-0000000000000002"]
        server = [
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=1, request_id="q3-mark-cell-start", method="POST", route="/other"),
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=2, request_id=ids[0], method="POST", route="/volume/:volume/intent"),
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=3, request_id=ids[0], method="POST", route="/volume/:volume/intent"),
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=4, request_id=ids[1], method="POST", route="/volume/:volume/intent"),
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=5, request_id=ids[1], method="GET", route="/volume/:volume/status"),
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=6, request_id="q3-mark-cell-end", method="POST", route="/other"),
        ]
        workload = [
            dict(index=0, warmup=True, duration_ns=11, syscall="fsync", return_code=0, pid=321, tid=654),
            dict(index=1, warmup=False, duration_ns=17, syscall="fsync", return_code=0, pid=321, tid=654),
        ]
        trace = "654 fsync(7) = 0\n654 fsync(7) = 0\n"
        observed = runner.validate_cell_evidence(
            server[::-1], operations(ids), workload, trace, "cell", 2
        )
        self.assertEqual(observed["rtt_band_attempts"], [0] * 9 + [2])
        self.assertEqual(
            (
                observed["successful_fsyncs"],
                observed["register_attempts"],
                observed["register_repeated_arrivals"],
                observed["background_attempts"],
                observed["durations_ns"],
            ),
            (2, 3, 1, 1, [17]),
        )

        controls = []

        def refuses(label, server_rows, client_rows, workload_rows, trace_text, reason):
            with self.assertRaises(runner.Refused) as caught:
                runner.validate_cell_evidence(
                    server_rows, client_rows, workload_rows, trace_text, "cell", 2
                )
            self.assertEqual(str(caught.exception), reason)
            controls.append((label, str(caught.exception)))

        deleted = [row for row in server if row.get("request_id") != ids[0] or row.get("route") != "/volume/:volume/intent"]
        refuses("targeted deletion", deleted, operations(ids), workload, trace, "fsync-register-missing")
        refuses("missing outcome", server, operations(ids, ids[1]), workload, trace, "fsync-lifecycle-invalid")
        commit_id = "cor-0000000000000003"
        commit_rows = operations([commit_id])
        commit_rows[0]["spans"][0]["kind"] = "commit"
        commit_rows[0]["kind"] = "commit"
        commit_rows[1]["spans"][0]["kind"] = "commit"
        commit_rows[1]["kind"] = "commit"
        wrong_kind = [dict(row) for row in server]
        wrong_kind[1]["request_id"] = commit_id
        wrong_kind[2]["request_id"] = commit_id
        refuses("wrong kind", wrong_kind, operations(ids) + commit_rows, workload, trace, "fsync-register-missing")
        delayed = [dict(row) for row in server]
        delayed.insert(2, dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=7, request_id=None, method="GET", route="/other"))
        delayed[-1]["arrival_seq"] = 8
        refuses("delayed id-less", delayed, operations(ids), workload, trace, "id-less-attempt-between-markers")
        missing_tid = [dict(row) for row in workload]
        missing_tid[0].pop("tid")
        refuses("missing tid", server, operations(ids), missing_tid, trace, "workload-result-invalid")
        for changed, reason in (
            (None, "workload-results-invalid"),
            (workload[:1], "workload-result-count-mismatch"),
            ([workload[0], dict(workload[1], pid=322)], "workload-pid-mismatch"),
            ([dict(row, warmup=True) for row in workload], "zero-samples"),
        ):
            refuses(reason, server, operations(ids), changed, trace, reason)
        refuses("missing trace", server, operations(ids), workload, None, "workload-strace-invalid")
        contaminated = [*server[:-1], dict(server[-2], arrival_seq=6, request_id=commit_id),
                        dict(server[-1], arrival_seq=7)]
        refuses("commit traffic", contaminated, operations(ids) + commit_rows, workload, trace,
                "cell-commit-contamination")
        second_tid = [dict(row) for row in workload]
        second_tid[1]["tid"] = 655
        refuses("second tid", server, operations(ids), second_tid, trace, "workload-tid-mismatch")
        refuses("pid not tid", server, operations(ids), workload, trace.replace("654", "321"), "workload-strace-result-mismatch")
        refuses("id-less strace", server, operations(ids), workload, trace.replace("654 ", ""), "workload-strace-invalid")
        refuses("overlay sync", server, operations(ids), workload, trace + "999 fdatasync(9) = 0\n", "workload-strace-count-mismatch")
        refuses("overlay substitution", server, operations(ids), workload, trace.splitlines(True)[0] + "999 fdatasync(9) = 0\n", "workload-strace-result-mismatch")
        refuses("missing syscall", server, operations(ids), workload, trace.splitlines(True)[0], "workload-strace-count-mismatch")
        refuses("failed syscall", server, operations(ids), workload, trace.replace("= 0", "= -1", 1), "workload-strace-result-mismatch")
        self.assertGreater(len(controls), 0)
        print(f"CONTROL cell evidence: observed={observed['successful_fsyncs']} refused={controls}")

    def test_published_cell_evidence_controls(self):
        fsync_id = "cor-0000000000000001"
        commit_id = "cor-0000000000000002"

        def operation(operation_id, kind):
            span = dict(name="op", op=operation_id, kind=kind)
            return [
                dict(event="op.begin", kind=kind, spans=[span]),
                dict(event="op.end", kind=kind, outcome="ok", spans=[span]),
            ]

        server = [
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=1, request_id="q3-mark-cell-start", method="POST", route="/other"),
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=2, request_id=commit_id, method="POST", route="/volume/:volume/publish"),
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=3, request_id="q3-mark-cell-end", method="POST", route="/other"),
        ]
        commits = operation(commit_id, "commit")
        for event in commits:
            event["spans"].insert(0, dict(name="op", op=fsync_id, kind="fsync"))
        client = operation(fsync_id, "fsync") + commits
        workload = [
            dict(index=0, warmup=False, duration_ns=17, syscall="fsync", return_code=0, pid=321, tid=654)
        ]
        trace = "654 fsync(7) = 0\n"
        observed = runner.validate_cell_evidence(
            server, client, workload, trace, "cell", 1, "published"
        )
        self.assertEqual(
            (
                observed["successful_fsyncs"],
                observed["logical_publishes"],
                observed["publish_attempts"],
                observed["request_correlation"],
                observed["strace_reconciled"],
            ),
            (1, 1, 1, "not request-correlated", True),
        )
        retried = [dict(row) for row in server]
        retried.insert(2, dict(retried[1], arrival_seq=3))
        retried[-1]["arrival_seq"] = 4
        retry_observed = runner.validate_cell_evidence(
            retried, client, workload, trace, "cell", 1, "published"
        )
        self.assertEqual(
            (retry_observed["logical_publishes"], retry_observed["publish_attempts"]),
            (1, 2),
        )
        self.assertEqual(retry_observed["rtt_band_attempts"], [0] * 9 + [2])
        uncorrelatable = runner.validate_cell_evidence(
            server, operation(fsync_id, "fsync") + operation(commit_id, "commit"),
            workload, trace, "cell", 1, "published",
        )
        self.assertEqual(uncorrelatable["logical_publishes"], 1)
        self.assertIsNone(uncorrelatable["rtt_band_attempts"])
        no_publish = [dict(row) for row in server]
        no_publish[1].update(method="GET", route="/volume/:volume/status")
        with self.assertRaises(runner.Refused) as population:
            runner.validate_cell_evidence(
                no_publish, client, workload, trace, "cell", 1, "published"
            )
        self.assertEqual(str(population.exception), "publish-population-invalid")
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_cell_evidence(
                server, client, workload, "", "cell", 1, "published"
            )
        self.assertEqual(str(caught.exception), "workload-strace-count-mismatch")
        print(
            "CONTROL published cell evidence: "
            f"observed={observed['successful_fsyncs']} retries={retry_observed['publish_attempts']} "
            f"population-refused={population.exception} trace-refused={caught.exception}"
        )

    def test_netem_calibration_and_resource_controls(self):
        commands = runner.netem_commands("q3-cell", "q3-client", 10)
        self.assertEqual(
            commands,
            [
                ["ip", "netns", "exec", "q3-cell", "tc", "qdisc", "replace", "dev", "q3-client", "root", "netem", "delay", "10ms"],
                ["ip", "netns", "exec", "q3-cell", "tc", "-j", "qdisc", "show", "dev", "q3-client"],
            ],
        )
        self.assertEqual(
            runner.offload_commands("q3-cell", "q3-host", "q3-client"),
            [
                ["ethtool", "-K", "q3-host", "tso", "off", "gso", "off", "gro", "off"],
                ["ip", "netns", "exec", "q3-cell", "ethtool", "-K", "q3-client", "tso", "off", "gso", "off", "gro", "off"],
                ["ethtool", "-k", "q3-host"],
                ["ip", "netns", "exec", "q3-cell", "ethtool", "-k", "q3-client"],
            ],
        )
        nonzero = (
            '[{"kind":"netem","handle":"8002:","root":true,"refcnt":2,'
            '"options":{"limit":1000,"delay":{"delay":0.01,"jitter":0,'
            '"correlation":0}}}]'
        )
        zero = (
            '[{"kind":"netem","handle":"8002:","root":true,"refcnt":2,'
            '"options":{"limit":1000}}]'
        )
        # Captured from the podman VM venue (part 51): the kernel reports
        # seed, ecn and gap beside limit, and omits delay at 0 ms.
        venue_zero = (
            '[{"kind":"netem","handle":"8011:","root":true,"refcnt":9,'
            '"options":{"limit":1000,"seed":4177359893274408508,"ecn":false,"gap":0}}]'
        )
        venue_nonzero = (
            '[{"kind":"netem","handle":"8011:","root":true,"refcnt":9,'
            '"options":{"limit":1000,"delay":{"delay":0.01,"jitter":0,"correlation":0},'
            '"seed":4177359893274408508,"ecn":false,"gap":0}}]'
        )
        observed = [
            runner.validate_netem_preflight(nonzero, 10),
            runner.validate_netem_preflight(zero, 0),
            runner.validate_netem_preflight(venue_zero, 0),
            runner.validate_netem_preflight(venue_nonzero, 10),
        ]
        self.assertEqual(observed, [10, 0, 0, 10])
        for label, mutated in (
            ("ecn enabled", venue_zero.replace('"ecn":false', '"ecn":true')),
            ("nonzero gap", venue_zero.replace('"gap":0', '"gap":5')),
            ("loss beside no-op keys", venue_zero.replace('"gap":0', '"gap":0,"loss-random":{"loss":0.01,"correlation":0}')),
        ):
            with self.subTest(netem=label):
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate_netem_preflight(mutated, 0)
                self.assertEqual(str(caught.exception), "netem-preflight-invalid")
        netem_cases = [
            (
                '[{"kind":"netem","handle":"8002:","root":true,"refcnt":2,'
                '"options":{"limit":1000,"delay":{"delay":0.02,"jitter":0,'
                '"correlation":0},"seed":1729,"ecn":false,"gap":0}}]',
                10,
                "wrong delay",
            ),
            (
                '[{"kind":"netem","handle":"8002:","root":true,"refcnt":2,'
                '"options":{"limit":1000,"delay":{"delay":0.01,"jitter":0.001,'
                '"correlation":0},"seed":1729,"ecn":false,"gap":0}}]',
                10,
                "nonzero jitter",
            ),
            (
                '[{"kind":"netem","handle":"8002:","root":true,"refcnt":2,'
                '"options":{"limit":1000,"delay":{"delay":0.01,"jitter":0,'
                '"correlation":1},"seed":1729,"ecn":false,"gap":0}}]',
                10,
                "nonzero correlation",
            ),
            (nonzero, 0, "delay present at zero"),
            (zero, 10, "delay absent at nonzero"),
            (f"{nonzero[:-1]},{nonzero[1:]}", 10, "two rows"),
            (
                '[{"kind":"noqueue","handle":"0:","root":true,"refcnt":2,'
                '"options":{}}]',
                10,
                "non-netem kind",
            ),
            (
                '[{"kind":"netem","handle":"8002:","root":false,"refcnt":2,'
                '"options":{"limit":1000,"delay":{"delay":0.01,"jitter":0,'
                '"correlation":0},"seed":1729,"ecn":false,"gap":0}}]',
                10,
                "non-root",
            ),
            (
                '[{"kind":"netem","handle":"8002:","root":true,"refcnt":2,'
                '"options":{"limit":1000,"delay":{"delay":0.01,"jitter":0,'
                '"correlation":0},"loss":0.01,"duplicate":0,"corrupt":0}}]',
                10,
                "lossy qdisc",
            ),
        ]
        for option in ("loss-random", "loss-gemodel", "reorder", "rate", "slot"):
            malformed = json.loads(nonzero)
            malformed[0]["options"][option] = {"probability": 0}
            netem_cases.append((json.dumps(malformed), 10, f"unexpected {option}"))
        cases = [
            (lambda: runner.netem_commands("q3-cell", "lo", 10), "netem-device-invalid"),
            (lambda: runner.validate_calibrated_rtts([0, 10]), "rtt-group-needs-two-nonzero"),
            (lambda: runner.resource_preflight("MemAvailable: 1024 kB\n", 30 * 1024**3), "job-memory-preflight"),
            (lambda: runner.resource_preflight("MemAvailable: 5000000 kB\n", 10), "job-disk-preflight"),
            (
                lambda: runner.validate_rtt_observations(
                    [
                        dict(configured_rtt_ms=0, observed_rtt_pre_ms=0.1, observed_rtt_post_ms=0.1, observed_rtt_ms=0.1, steady_state="steady", summary=dict(durations_ns=[1], register_attempts=1, successful_fsyncs=1, register_repeated_arrivals=0, route_attempts={"route": 1})),
                        dict(configured_rtt_ms=10, observed_rtt_pre_ms=50, observed_rtt_post_ms=50, observed_rtt_ms=50, steady_state="steady", summary=dict(durations_ns=[10_000_001], register_attempts=1, successful_fsyncs=1, register_repeated_arrivals=0, route_attempts={"route": 1})),
                        dict(configured_rtt_ms=50, observed_rtt_pre_ms=50.1, observed_rtt_post_ms=50.1, observed_rtt_ms=50.1, steady_state="steady", summary=dict(durations_ns=[50_000_001], register_attempts=1, successful_fsyncs=1, register_repeated_arrivals=0, route_attempts={"route": 1})),
                    ]
                ),
                "rtt-observation-invalid",
            ),
        ]
        for text, configured, label in netem_cases:
            with self.subTest(netem=label):
                with self.assertRaises(runner.Refused) as caught:
                    runner.validate_netem_preflight(text, configured)
                self.assertEqual(str(caught.exception), "netem-preflight-invalid")
        for call, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(runner.Refused) as caught:
                    call()
                self.assertEqual(str(caught.exception), reason)
        self.assertEqual(runner.validate_calibrated_rtts([0, 10, 50]), [10, 50])
        self.assertGreater(len(netem_cases), 0)
        self.assertGreater(len(cases), 0)
        print(
            "CONTROL netem/resource: "
            f"observed={observed} netem-refused={len(netem_cases)} "
            f"other-refused={len(cases)}"
        )

    def test_rtt_calibration_group_controls(self):
        def cells_for_ratios(first, second):
            cells = self.rtt_cells((66.7, 66.7, 66.7))
            counted = sum(cells[0]["summary"]["route_attempts"].values()) / 1035
            baseline_rtt = cells[0]["observed_rtt_ms"]
            cells[1]["summary"]["durations_ns"] = [
                round(
                    (
                        66.7
                        + (cells[1]["observed_rtt_ms"] - baseline_rtt)
                        * counted
                        * first
                    )
                    * 1_000_000
                )
            ] * 1000
            cells[2]["summary"]["durations_ns"] = [
                round(
                    (
                        66.7
                        + (cells[2]["observed_rtt_ms"] - baseline_rtt)
                        * counted
                        * second
                    )
                    * 1_000_000
                )
            ] * 1000
            return cells

        passing = cells_for_ratios(1.256, 1.256)
        accepted = runner.rtt_calibration_record(passing)
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(accepted)
        self.assertEqual(str(caught.exception), "rtt-standalone-calibration")
        self.assertEqual(
            (
                accepted["event"],
                accepted["profile"],
                accepted["outcome"],
                accepted["reason"],
                runner.validate_rtt_observations(passing),
            ),
            ("calibration", "durable-prepared", "calibrated", None, 3),
        )
        self.assertEqual(
            [row["confound"] for row in accepted["whole_cell_steadiness"]],
            [None] * len(passing),
        )
        reordered = runner.rtt_calibration_record([passing[0], passing[2], passing[1]])
        self.assertEqual(
            reordered["cell_order_confound"],
            "Fixed cell order 0/50/10 ms confounds venue ageing with RTT level.",
        )
        self.assertEqual(
            (
                len(accepted["rtt_derivations"]),
                accepted["rtt_derivations"][0]["label"],
            ),
            (2, "unattributed RTT-proportional wall-clock excess"),
        )
        for derivation in accepted["rtt_derivations"]:
            self.assertAlmostEqual(derivation["k_over_counted"], 1.256, places=3)
            self.assertEqual(
                (derivation["band"], derivation["sample_index_range"], derivation["pre_publish_head_seq_range"]),
                (1, [0, 99], [7, 7]),
            )
            self.assertEqual(
                set(derivation),
                {
                    "configured_rtt_ms",
                    "observed_rtt_pre_ms",
                    "observed_rtt_post_ms",
                    "delivered_added_rtt_ms",
                    "overshoot",
                    "k",
                    "counted",
                    "k_over_counted",
                    "unattributed_excess",
                    "label",
                    "band",
                    "sample_index_range",
                    "pre_publish_head_seq_range",
                },
            )

        overshoot = self.rtt_cells((66.7, 190.8, 683.2))
        overshoot[1].update(
            observed_rtt_pre_ms=14.1,
            observed_rtt_post_ms=14.1,
            observed_rtt_ms=14.1,
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_observed_rtts(overshoot)
        self.assertEqual(str(caught.exception), "rtt-observation-invalid")

        for anchor in ("observed_rtt_pre_ms", "observed_rtt_post_ms"):
            one_bad_anchor = self.rtt_cells((66.7, 190.8, 683.2))
            one_bad_anchor[1].update(
                observed_rtt_pre_ms=10.1,
                observed_rtt_post_ms=10.1,
                observed_rtt_ms=12.65,
            )
            one_bad_anchor[1][anchor] = 15.2
            with self.assertRaises(runner.Refused) as caught:
                runner.validate_observed_rtts(one_bad_anchor)
            self.assertEqual(str(caught.exception), "rtt-observation-invalid")

        anchors_disagree = self.rtt_cells((66.7, 190.8, 683.2))
        anchors_disagree[1].update(
            observed_rtt_pre_ms=4.9,
            observed_rtt_post_ms=15.3,
            observed_rtt_ms=10.1,
        )
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_observed_rtts(anchors_disagree)
        self.assertEqual(str(caught.exception), "rtt-observation-invalid")

        missing_baseline = self.rtt_cells((66.7, 190.8, 683.2))[1:]
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_observed_rtts(missing_baseline)
        self.assertEqual(str(caught.exception), "rtt-observation-invalid")

        not_steady = cells_for_ratios(1, 1)
        baseline = not_steady[0]["summary"]["durations_ns"]
        baseline[:50] = [int(baseline[0] * 0.89)] * 50
        steady_refused = runner.rtt_calibration_record(not_steady)
        self.assertEqual(
            (steady_refused["outcome"], steady_refused["reason"]),
            ("refused", "rtt-calibration-band-not-steady"),
        )

        unmatched = cells_for_ratios(1, 1)
        del unmatched[2]["summary"]["durations_ns"][-10:]
        self.assertEqual(runner.rtt_calibration_record(unmatched)["reason"], "rtt-calibration-band-mismatch")

        published = cells_for_ratios(1, 1)
        for cell, tail_offset in zip(published, (0, -40_000_000, 2_000_000_000)):
            summary = cell["summary"]
            del summary["register_chain_head_seq"]
            summary.update(request_correlation="not request-correlated", strace_reconciled=True)
            durations = summary["durations_ns"]
            durations[100:] = [durations[0] + 40_000_000 * (index // 100) + tail_offset
                               for index in range(100, 1000)]
            cell.update(profile="published", steady_state=runner.steady_state(durations, 0.10)[-1])
        published[-1]["summary"]["rtt_band_attempts"] = None
        desk_shape = runner.rtt_calibration_record(published)
        self.assertEqual(desk_shape["outcome"], "calibrated")
        self.assertEqual(desk_shape["rtt_derivations"][0]["pre_publish_head_seq_range"], [36, 135])
        self.assertEqual(
            desk_shape["scope"],
            "RTT proportionality is supported only for band 1, the recorded pre-publish "
            "head-seq range 36–135, and the tested RTT levels. "
            "Fixed cell order 0/10/50 ms confounds venue ageing with RTT level.",
        )
        self.assertEqual(desk_shape["whole_cell_steadiness"][0], dict(
            configured_rtt_ms=0, finding="not steady",
            confound="The recorded timings leave the cause undetermined.",
        ))
        table = desk_shape["depth_sensitivity"]
        self.assertEqual(len(table), 10)
        self.assertEqual((table[-1]["band"], table[-1]["sample_index_range"]), (10, [900, 999]))
        self.assertGreater(table[-1]["agreement_ratio"], 1.10)
        self.assertEqual([row["counted"] for row in table[-1]["cells"]], [10.35, 10.35, None])

        zero_delivered = cells_for_ratios(1.0, 1.0)
        for name in (
            "observed_rtt_pre_ms",
            "observed_rtt_post_ms",
            "observed_rtt_ms",
        ):
            zero_delivered[1][name] = zero_delivered[0][name]
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_fsync_calibration(zero_delivered, 100)
        self.assertEqual(str(caught.exception), "rtt-fsync-calibration-invalid")

        refused = []
        for label, cells in (
            ("drift", cells_for_ratios(1.0, 1.11)),
            ("low", cells_for_ratios(0.7, 0.7)),
            ("high", cells_for_ratios(1.35, 1.35)),
        ):
            with self.subTest(label=label):
                record = runner.rtt_calibration_record(cells)
                self.assertEqual(
                    (record["outcome"], record["reason"]),
                    ("refused", "rtt-fsync-calibration-invalid"),
                )
                refused.append(record["reason"])

        differing = self.rtt_cells((66.7, 190.8, 683.2))
        differing[1]["summary"]["route_attempts"]["GET /other"] -= 1
        route_refused = runner.rtt_calibration_record(differing)
        self.assertEqual(
            (route_refused["outcome"], route_refused["reason"]),
            ("refused", "rtt-calibration-route-vector"),
        )
        self.assertGreater(len(passing), 0)
        deciding = self.fixture()
        deciding["samples"][0]["rtt_k"] = 12.0
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(deciding)
        self.assertEqual(str(caught.exception), "calibration-fields-on-measurement-row")
        print(
            "CONTROL RTT calibration: "
            f"observed={len(passing)} ratio-refused={len(refused)} "
            f"route-refused={route_refused['reason']}"
        )

    def test_rtt_calibration_run_refusals_are_not_group_records(self):
        cases = []

        duplicate = self.rtt_cells((66.7, 190.8, 683.2))
        duplicate[2]["configured_rtt_ms"] = 10
        cases.append((duplicate, "rtt-group-needs-two-nonzero"))

        missing_observed = self.rtt_cells((66.7, 190.8, 683.2))
        missing_observed[1].pop("observed_rtt_ms")
        cases.append((missing_observed, "rtt-calibration-invalid"))

        sample_loss = self.rtt_cells((66.7, 190.8, 683.2))
        sample_loss[1]["summary"]["register_attempts"] -= 1
        cases.append((sample_loss, "rtt-calibration-invalid"))

        unapplied_netem = self.rtt_cells((66.7, 190.8, 683.2))
        for cell in unapplied_netem:
            for name in (
                "observed_rtt_pre_ms",
                "observed_rtt_post_ms",
                "observed_rtt_ms",
            ):
                cell[name] = 0.05
        cases.append((unapplied_netem, "rtt-observation-invalid"))

        refusals = []
        for cells, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(runner.Refused) as caught:
                    runner.rtt_calibration_record(cells)
                self.assertEqual(str(caught.exception), reason)
                refusals.append(str(caught.exception))
        stderr = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "q3-measurement.py",
                    "--network-measurement",
                    "--work",
                    "/unused",
                    "--server-child",
                    "server",
                    "--client-child",
                    "client",
                ],
            ),
            patch.object(runner, "new_work", return_value=Path("/unused")),
            patch.object(
                runner,
                "run_network_measurement",
                side_effect=lambda *_: runner.rtt_calibration_record(sample_loss),
            ),
            patch("sys.stderr", stderr),
        ):
            self.assertEqual(runner.main(), 1)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"event": "refused", "reason": "rtt-calibration-invalid"},
        )
        self.assertGreater(len(cases), 0)
        print(
            "CONTROL RTT run refusals: "
            f"observed={len(cases)} refused={','.join(refusals)} main-rc=1"
        )

    def test_netem_fields_follow_network_path(self):
        def loopback_without_netem(document):
            self.loopback_row(document, 0)

        def loopback_claiming_netem(document):
            document["samples"][0].update(
                network_path="loopback", netem_preflight=True
            )

        self.pair(
            "loopback netem claim",
            "netem-preflight-unexpected",
            loopback_claiming_netem,
            loopback_without_netem,
        )
        nullable = self.fixture()
        self.loopback_row(nullable, 0)
        nullable["samples"][0]["netem_preflight"] = None
        observed = runner.validate(nullable)
        self.assertGreater(observed, 0)
        print(f"CONTROL loopback null netem: observed={observed}")

    def test_wait_tracer_requires_every_workload_task(self):
        running = {"child": Mock(pid=777, poll=Mock(return_value=None))}

        def proc_path(statuses):
            task_dir = Mock()
            task_dir.glob.return_value = [
                Mock(read_text=Mock(return_value=status)) for status in statuses
            ]
            return task_dir

        traced = proc_path(["Name:\ta\nTracerPid:\t777\n", "Name:\tb\nTracerPid:\t777\n"])
        with (
            patch.object(runner, "Path", return_value=traced) as path,
            patch.object(runner.time, "monotonic", side_effect=[0, 0.1]),
            patch.object(runner.time, "sleep"),
        ):
            runner.wait_tracer(321, running, timeout=0.5)
        path.assert_called_once_with("/proc/321/task")
        self.assertEqual(traced.glob.call_args.args, ("*/status",))

        partial = proc_path(["Name:\ta\nTracerPid:\t777\n", "Name:\tb\nTracerPid:\t0\n"])
        with (
            patch.object(runner, "Path", return_value=partial),
            patch.object(runner.time, "monotonic", side_effect=[0, 0.1, 1]),
            patch.object(runner.time, "sleep"),
            self.assertRaises(runner.Refused) as caught,
        ):
            runner.wait_tracer(321, running, timeout=0.5)
        self.assertEqual(str(caught.exception), "workload-strace-attach-timeout")
        print(
            "CONTROL tracer tasks: observed=2 "
            f"partial-refused={caught.exception}"
        )

    def test_network_measurement_orders_preflight_and_cells(self):
        timeline = []

        with patch.object(
            runner,
            "checked",
            return_value="rtt min/avg/max/mdev = 0.1/12.3/15.0/0.2 ms\n",
        ) as ping:
            self.assertEqual(
                runner.observed_ping_rtt(
                    ["nsenter", "--net=/netns/q3", "--"],
                    "192.0.2.1",
                    "ping-anchor",
                    cwd=Path("/tmp"),
                ),
                12.3,
            )
        self.assertEqual(
            ping.call_args.args[0],
            [
                "nsenter",
                "--net=/netns/q3",
                "--",
                "ping",
                "-n",
                "-q",
                "-c",
                "40",
                "-i",
                "0.2",
                "192.0.2.1",
            ],
        )

        def checked(command, *_args, **_options):
            timeline.append(("command", command))
            if "ethtool" in command and "-k" in command:
                return (
                    "Features:\n"
                    "tcp-segmentation-offload: off\n"
                    "generic-segmentation-offload: off\n"
                    "generic-receive-offload: off\n"
                )
            if "-j" in command:
                preflights = sum(
                    1
                    for event, prior in timeline
                    if event == "command" and "-j" in prior
                )
                delay_ms = [0, 10, 50][(preflights - 1) % 3]
                options = {"limit": 1000}
                if delay_ms:
                    options["delay"] = {
                        "delay": delay_ms / 1000,
                        "jitter": 0,
                        "correlation": 0,
                    }
                return json.dumps(
                    [
                        {
                            "kind": "netem",
                            "handle": "8002:",
                            "root": True,
                            "refcnt": 2,
                            "options": options,
                        }
                    ]
                )
            return ""

        def cell(_server, _client, work, _timeout, **options):
            timeline.append(("cell", options["cell"]))
            configured = int(options["cell"].rsplit("-", 1)[1])
            profile = options["profile"]
            self.assertEqual(options["bind"], "192.0.2.1")
            namespace = runner.network_names(Path(directory).resolve())[0]
            self.assertEqual(
                options["client_prefix"],
                ["nsenter", f"--net=/var/run/netns/{namespace}", "--"],
            )
            self.assertEqual(options["trace_path"], work / "workload.strace")
            summary = dict(
                durations_ns=[1 + configured * 1_000_000] * 1000,
                rtt_band_attempts=[1035] * 10,
                successful_fsyncs=1035,
                tid=654,
                attempt_count_source="server-counted",
                operation_kind_source="client-attested",
                m15_delta=0,
                m15_fallback_delta=1,
                m15_reuse_delta=0,
            )
            if profile == "published":
                if configured == 0:
                    summary["durations_ns"][500:] = [2] * 500
                summary.update(
                    route_attempts={
                        "PUT /other": 5185,
                        "GET /other": 4170 if configured == 50 else 4171,
                        "POST /volume/:volume/publish": 1038,
                        "one-off requests": 5,
                    },
                    publish_attempts=1038,
                    logical_publishes=1035,
                    request_correlation="not request-correlated",
                    strace_reconciled=True,
                )
            else:
                summary.update(
                    register_chain_head_seq=1,
                    route_attempts={
                        "PUT /other": 5185,
                        "GET /other": 4171,
                        "POST /volume/:volume/intent": 1038,
                        "one-off requests": 5,
                    },
                    register_attempts=1035,
                    register_repeated_arrivals=0,
                    background_attempts=9364,
                )
            log = work / "client.log"
            rc = work / "client.rc"
            log.write_text("fixture client output\n")
            rc.write_text("0\n")
            return dict(
                uid=os.geteuid(),
                summary=summary,
                client=dict(
                    command=["q3-client", options["cell"]],
                    exit_code=0,
                    run_root=str(work),
                    raw_log=str(log),
                    raw_rc=str(rc),
                    raw_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
                    raw_rc_sha256=hashlib.sha256(rc.read_bytes()).hexdigest(),
                    started_at="2026-11-17T12:00:00Z",
                ),
            )

        directory = Path(self.temporary.name) / "network-work"
        directory.mkdir()
        with (
            patch.dict(
                os.environ,
                {
                    "GRANARY_Q3_VENUE_BACKING": "/dev/vda1 ext4 rw",
                    "GRANARY_Q3_VENUE_CACHE_MODE": "write back",
                    "GRANARY_Q3_VENUE_TEXT": (
                        "VM; kernel timer granularity applies; cannot describe host cache"
                    ),
                    "GRANARY_Q3_VENUE": "vm",
                    "GRANARY_Q3_REVISION": "0123456789abcdef0123456789abcdef01234567",
                },
            ),
            patch.object(runner.Path, "read_text", return_value="MemAvailable: 5000000 kB\n"),
            patch.object(runner, "resource_preflight"),
            patch.object(runner, "checked", side_effect=checked),
            patch.object(runner, "run_loopback_smoke", side_effect=cell),
            patch.object(
                runner,
                "observed_ping_rtt",
                side_effect=[
                    0.1,
                    0.1,
                    10.1,
                    10.1,
                    50.1,
                    50.1,
                ]
                * 2,
            ),
            patch.object(runner.subprocess, "run"),
        ):
            measurement = runner.run_network_measurement("server", "client", directory)
        results = measurement["cells"]
        self.assertEqual(
            [(row["outcome"], row["reason"]) for row in measurement["calibrations"]],
            [
                ("refused", "rtt-fsync-calibration-invalid"),
                ("refused", "rtt-calibration-route-vector"),
            ],
        )
        output = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "q3-measurement.py",
                    "--network-measurement",
                    "--work",
                    "/unused",
                    "--server-child",
                    "server",
                    "--client-child",
                    "client",
                ],
            ),
            patch.object(runner, "new_work", return_value=Path(directory)),
            patch.object(runner, "run_network_measurement", return_value=measurement),
            patch("sys.stdout", output),
        ):
            self.assertEqual(runner.main(), 0)
        emitted = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(
            (
                [row["event"] for row in emitted],
                emitted[0]["fsync_p50_ns"],
                [(row["outcome"], row["reason"]) for row in emitted[6:8]],
                emitted[-1]["samples"],
            ),
            (
                ["measurement"] * 6 + ["calibration"] * 2 + ["counts"],
                1,
                [
                    ("refused", "rtt-fsync-calibration-invalid"),
                    ("refused", "rtt-calibration-route-vector"),
                ],
                6000,
            ),
        )
        self.assertEqual(
            [(result["profile"], result["configured_rtt_ms"]) for result in results],
            [
                ("durable-prepared", 0),
                ("durable-prepared", 10),
                ("durable-prepared", 50),
                ("published", 0),
                ("published", 10),
                ("published", 50),
            ],
        )
        self.assertTrue(
            all(
                result["observed_rtt_ms"]
                == (result["observed_rtt_pre_ms"] + result["observed_rtt_post_ms"]) / 2
                for result in results
            )
        )
        self.assertEqual(
            {
                (
                    result["calibration_outcome"],
                    result["calibration_reason"],
                )
                for result in results
            },
            {
                ("refused", "rtt-fsync-calibration-invalid"),
                ("refused", "rtt-calibration-route-vector"),
            },
        )
        record = runner.cell_record(results[1])
        published = runner.cell_record(results[4])
        for field, reason in (("revision", "revision-required"), ("venue", "schema-invalid: venue")):
            with self.subTest(field=field), self.assertRaisesRegex(runner.Refused, f"^{reason}$"):
                runner.cell_record(dict(results[1], **{field: "invalid"}))
        self.assertEqual(
            (record["netem_delay_placement"], record["offload_state"]),
            (
                "client-veth-egress",
                {
                    "host": {"tso": False, "gso": False, "gro": False},
                    "client": {"tso": False, "gso": False, "gro": False},
                },
            ),
        )
        manifest_rows = []
        for result in results:
            projected = runner.cell_record(result)
            with self.assertRaises(runner.Refused) as caught:
                runner.validate(projected)
            self.assertEqual(str(caught.exception), "rtt-standalone-row")
            manifest_rows.append(projected)
        group_document = {
            "samples": manifest_rows,
            "calibrations": measurement["calibrations"],
        }
        self.assertEqual(runner.validate(group_document), 6)
        self.mounted_metrics_controls(group_document)
        invalid_group_row = copy.deepcopy(group_document)
        invalid_group_row["samples"][0]["host"] = ""
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(invalid_group_row)
        self.assertEqual(str(caught.exception), "schema-invalid: host")
        no_events = copy.deepcopy(group_document)
        for row in no_events["samples"]:
            row.pop("event")
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(no_events)
        self.assertEqual(str(caught.exception), "schema-invalid: sample_loss")
        legacy_shape = copy.deepcopy(group_document)
        for row in legacy_shape["samples"]:
            row.pop("event")
            row.update(
                memory_bytes=0,
                achieved_rate=0,
                sample_loss=0,
                root_bytes=706,
            )
        legacy_shape["calibrations"][0]["reason"] = "fabricated"
        with self.assertRaises(runner.Refused) as caught:
            runner.validate(legacy_shape)
        self.assertEqual(str(caught.exception), "rtt-calibration-record-mismatch")
        calibration_cases = []
        missing = copy.deepcopy(group_document)
        missing.pop("calibrations")
        calibration_cases.append(("rtt-calibration-record-missing", missing))
        malformed = copy.deepcopy(group_document)
        malformed["calibrations"][0]["profile"] = []
        calibration_cases.append(("rtt-calibration-records-invalid", malformed))
        mismatched = copy.deepcopy(group_document)
        mismatched["calibrations"][0]["reason"] = "different"
        calibration_cases.append(("rtt-calibration-record-mismatch", mismatched))
        edited_band = copy.deepcopy(group_document)
        edited_band["calibrations"][0]["depth_sensitivity"][0]["sample_index_range"][1] += 1
        calibration_cases.append(("rtt-calibration-record-mismatch", edited_band))
        stale_confound = copy.deepcopy(group_document)
        whole_cell = stale_confound["calibrations"][1]["whole_cell_steadiness"][0]
        self.assertEqual(whole_cell["finding"], "not steady")
        whole_cell["confound"] = (
            "consistent with the chain walk (#866, #114); attribution still confounded"
        )
        calibration_cases.append(("rtt-calibration-record-mismatch", stale_confound))
        relabelled = copy.deepcopy(group_document)
        for row in relabelled["samples"][:3]:
            row.update(calibration_outcome="calibrated", calibration_reason=None)
        calibration_cases.append(("rtt-calibration-outcome-mismatch", relabelled))
        extra = copy.deepcopy(group_document)
        extra["calibrations"].append(copy.deepcopy(extra["calibrations"][0]))
        extra["calibrations"][-1]["profile"] = "extra"
        calibration_cases.append(("rtt-calibration-records-invalid", extra))
        for reason, invalid in calibration_cases:
            with self.assertRaises(runner.Refused) as caught:
                runner.validate(invalid)
            self.assertEqual(str(caught.exception), reason)
        self.assertTrue(
            all(
                row[name] is None
                for row in manifest_rows
                for name in ("memory_bytes", "achieved_rate", "sample_loss", "root_bytes")
            )
        )
        self.assertEqual(
            (record["sample_count"], record["warmup_count"], record["fsync_p99_ns"], record["tid"]),
            (1000, 32, 10_000_001, 654),
        )
        self.assertEqual(
            (
                published["profile"],
                published["request_correlation"],
                published["successful_fsyncs"],
                published["logical_publishes"],
                published["publish_attempts"],
                published["tid"],
            ),
            ("published", "not request-correlated", 1035, 1035, 1038, 654),
        )
        self.assertEqual(runner.validate_route_vector(results[:3]), 3)
        with self.assertRaises(runner.Refused) as caught:
            runner.validate_route_vector(results[3:])
        self.assertEqual(str(caught.exception), "rtt-calibration-route-vector")
        cells = [index for index, entry in enumerate(timeline) if entry[0] == "cell"]
        preflights = [index for index, entry in enumerate(timeline) if entry[0] == "command" and "-j" in entry[1]]
        self.assertEqual(len(cells), len(preflights), 6)
        self.assertTrue(all(preflight < cell_index for preflight, cell_index in zip(preflights, cells)))
        print(
            "CONTROL network cells: observed=6 emitted=6 main-rc=0 preflight-before-cell=6 "
            f"client-netns-only=6 published-route-refused={caught.exception}"
        )

    def test_persistent_smoke_lifecycle_and_uid_controls(self):
        server_rows = [
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=1, request_id="q3-mark-smoke-start", method="POST", route="/other"),
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=2, request_id="cor-0123456789abcdef", method="POST", route="/volume/:volume/intent"),
            dict(schema="granary.q3.server.v2", kind="http_attempt", arrival_seq=3, request_id="q3-mark-smoke-end", method="POST", route="/other"),
        ]
        client_rows = [
            dict(event="op.begin", kind="fsync", spans=[dict(name="op", op="cor-0123456789abcdef", kind="fsync")]),
            dict(event="op.end", kind="fsync", outcome="ok", spans=[dict(name="op", op="cor-0123456789abcdef", kind="fsync")]),
        ]

        def run_case(work, server_uid, client_uid, missing_report=None, *, refusal=None,
                     planned="1", measured=False):
            started = []
            markers = []
            signals = []
            finished = []
            timeline = []

            def start(command, stem, **_):
                running = dict(name=stem, finished=False, child=Mock(poll=Mock(return_value=None)))
                started.append((stem, command))
                return running

            def wait(path, _, label, timeout=30):
                del timeout
                if label == missing_report:
                    raise runner.Refused(f"handoff-missing: {label}")
                handoff = path.parent
                if label == "server-handoff":
                    (handoff / "server-uid").write_text(server_uid)
                    (handoff / "server-uid").chmod(0o600)
                    if refusal == "handoff-directory-mode":
                        handoff.chmod(0o755)
                elif label == "client-quiescent-before-start":
                    (handoff / "client-uid").write_text(client_uid)
                    (handoff / "client-uid").chmod(0o600)
                    (handoff / "client-planned-fsyncs").write_text(planned)
                    (handoff / "client-planned-fsyncs").chmod(0o600)
                    timeline.append(("report", label))
                elif label == "client-workload-done":
                    timeline.append(("report", label))

            def finish(running, **_):
                running["finished"] = True
                finished.append(running["name"])
                timeline.append(("finish", running["name"]))
                failure = {"strace": "workload-strace-failed", "client": "client-child-failed",
                           "server": "server-child-failed"}
                return dict(exit_code=int(refusal is not None and refusal == failure[running["name"]]))

            def marker(_, cell, edge):
                markers.append((cell, edge))
                timeline.append(("marker", edge))

            def signal(path, _contents=b""):
                signals.append(path.name)
                timeline.append(("signal", path.name))

            real_handoff_text = runner.handoff_text

            def text(directory, name):
                if name == "client-log-path":
                    return str(work / "client-events.jsonl")
                if name == "client-workload-pid":
                    return "321"
                if name == "client-m15-deltas":
                    return "2 0 0" if refusal == "m15-calibration-invalid" else "1 0 0"
                return real_handoff_text(directory, name)

            trace_path = work / "workload.strace" if measured else None
            if measured:
                trace_path.write_text("321 fsync(7) = 0\n")
            workload = [dict(index=0, warmup=False, duration_ns=17, syscall="fsync",
                             return_code=0, pid=321, tid=321)]
            with (
                patch.object(runner, "start_command", side_effect=start),
                patch.object(runner, "wait_file", side_effect=wait),
                patch.object(runner, "marker_request", side_effect=marker),
                patch.object(runner, "private_signal", side_effect=signal),
                patch.object(runner, "finish_command", side_effect=finish),
                patch.object(runner, "abort_command"),
                patch.object(runner, "load_json_lines", side_effect=[server_rows, client_rows, workload]),
                patch.object(runner, "handoff_text", side_effect=text),
                patch.object(runner, "wait_tracer"),
                patch.object(runner, "chain_head_probe", return_value=({"sequence": 7}, None)) as probe,
            ):
                if refusal is not None:
                    profile = "invalid" if refusal == "measurement-profile-invalid" else "durable-prepared"
                    with self.assertRaisesRegex(runner.Refused, f"^{refusal}$"):
                        runner.run_loopback_smoke("server", "client", work, trace_path=trace_path, profile=profile)
                    if refusal == "measurement-profile-invalid":
                        self.assertEqual(started, [])
                    if refusal == "planned-fsync-population-invalid":
                        self.assertEqual(markers, [])
                    if refusal == "steady-sample-floor":
                        probe.assert_called_once_with(
                            "client", work.resolve() / "handoff", work.resolve(), "rtt-chain-head", 35
                        )
                elif missing_report is not None:
                    with self.assertRaises(runner.Refused) as caught:
                        runner.run_loopback_smoke("server", "client", work)
                    self.assertEqual(
                        str(caught.exception),
                        f"handoff-missing: {missing_report}",
                    )
                    self.assertEqual(markers, [("smoke", "start")])
                elif server_uid == client_uid == str(os.geteuid()):
                    result = runner.run_loopback_smoke("server", "client", work)
                    self.assertEqual(
                        (result["cell_population"], result["uid"]),
                        (1, os.geteuid()),
                    )
                    self.assertEqual(
                        (len(started), markers, signals, finished),
                        (2, [("smoke", "start"), ("smoke", "end")], ["client-sync-profile", "client-go", "client-stop"], ["client", "server"]),
                    )
                    self.assertEqual(
                        timeline,
                        [
                            ("signal", "client-sync-profile"),
                            ("report", "client-quiescent-before-start"),
                            ("marker", "start"),
                            ("signal", "client-go"),
                            ("report", "client-workload-done"),
                            ("marker", "end"),
                            ("signal", "client-stop"),
                            ("finish", "client"),
                            ("finish", "server"),
                        ],
                    )
                else:
                    with self.assertRaises(runner.Refused) as caught:
                        runner.run_loopback_smoke("server", "client", work)
                    self.assertEqual(str(caught.exception), "child-uid-mismatch")

        with tempfile.TemporaryDirectory(prefix="q3-persistent-") as directory:
            root = Path(directory)
            runner_uid = str(os.geteuid())
            malformed = root / "malformed"
            malformed.mkdir(mode=0o700)
            run_case(malformed, runner_uid, str(os.geteuid() + 1))
            forged = root / "forged-owner"
            forged.mkdir(mode=0o700)
            forged_uid = str(os.geteuid() + 1)
            run_case(forged, forged_uid, forged_uid)
            valid = root / "valid"
            valid.mkdir(mode=0o700)
            run_case(valid, runner_uid, runner_uid)
            missing = root / "missing-report"
            missing.mkdir(mode=0o700)
            run_case(missing, runner_uid, runner_uid, "client-workload-done")
            for index, (refusal, planned, measured) in enumerate((
                ("measurement-profile-invalid", "1", False),
                ("handoff-directory-mode", "1", False),
                ("planned-fsync-population-invalid", "+1", False),
                ("planned-fsync-population-invalid", "0", False),
                ("client-child-failed", "1", False),
                ("server-child-failed", "1", False),
                ("workload-strace-failed", "1", True),
                ("m15-calibration-invalid", "1", True),
                ("steady-sample-floor", "1", True),
            )):
                bad = root / f"refusal-{index}"
                bad.mkdir(mode=0o700)
                run_case(bad, runner_uid, runner_uid, refusal=refusal, planned=planned, measured=measured)

            with (
                patch.object(
                    sys,
                    "argv",
                    [
                        "q3-measurement.py",
                        "--loopback-smoke",
                        "--work",
                        str(root / "main-work"),
                        "--server-child",
                        "server",
                        "--client-child",
                        "client",
                    ],
                ),
                patch.object(runner, "new_work", return_value=root),
                patch.object(
                    runner,
                    "run_loopback_smoke",
                    return_value={"cell_population": 2, "uid": os.geteuid()},
                ),
                patch("builtins.print") as printed,
            ):
                self.assertEqual(runner.main(), 0)
            self.assertEqual(
                json.loads(printed.call_args.args[0]),
                {"event": "counts", "samples": 2, "uid": os.geteuid()},
            )
        print(
            "CONTROL persistent lifecycle: observed=3 same-uid counts-samples=2 "
            "refused=child-uid-mismatch,self-reported-owner-mismatch,"
            "handoff-missing: client-workload-done"
        )

    def test_loopback_store_environment_controls(self):
        self.assertEqual(
            runner.loopback_store_environment({}), {"GRANARY_STORE": "memory:"}
        )
        valid = {
            "GRANARY_STORE": "s3:",
            "GRANARY_STORE_BUCKET": "granary-test",
            "GRANARY_STORE_ENDPOINT": "http://127.0.0.1:19189",
            "GRANARY_STORE_REGION": "us-east-1",
            "AWS_ACCESS_KEY_ID": "granary-test",
            "AWS_SECRET_ACCESS_KEY": "granary-test-secret",
        }
        self.assertEqual(runner.loopback_store_environment(valid), valid)
        malformed = dict(valid)
        del malformed["AWS_SECRET_ACCESS_KEY"]
        with self.assertRaises(runner.Refused) as caught:
            runner.loopback_store_environment(malformed)
        self.assertEqual(
            str(caught.exception), "loopback-store-environment-incomplete"
        )
        print(
            "CONTROL loopback store environment: observed=2 "
            "refused=loopback-store-environment-incomplete"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
