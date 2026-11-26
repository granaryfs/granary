#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed shipping exclusion and restart evidence identity checks."""

import argparse
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if not __debug__:  # pragma: no cover
    raise SystemExit("PUBLISH-RESTART REFUSED: its checks include asserts; run without -O.")

FEATURE = "publish-restart-tests"
PACKAGES = ("granary-cli", "granary-client", "granary-server")
SCENARIOS = {
    "retained::landing_fence_unfence_settles_retained_state": {"operator-initialise", "lock-refusal", "unanswered-cut", "landing-fence", "supervisor-controls", "unfence-refusals", "time-boundary", "reboot-without-unfence", "unfence-clean", "exact-replay", "single-decision", "completion-no-post"},
    "retained::first_append_fence_reposts_retained_state": {"operator-initialise", "lock-refusal", "unanswered-cut", "first-append-fence", "supervisor-controls", "unfence-refusals", "time-boundary", "reboot-without-unfence", "unfence-clean", "retained-repost", "single-decision", "completion-no-post"},
    "epochs::two_epoch_changes_keep_both_candidates_and_complete_with_a": {"a-captured", "e1-mismatch", "b-captured", "e2-mismatch", "empty-catalogue", "distinct-identities", "late-releases", "owned-a"},
    "epochs::delayed_a_release_after_rebase_before_b_put": {"a-held-across-reinitialise", "empty-probe", "head-resolved-cut", "a-released-before-b-put", "single-root", "client-landed"},
    "epochs::delayed_a_release_after_b_put": {"a-held-across-reinitialise", "empty-probe", "head-resolved-cut", "b-put-landed", "a-released-after-b-put", "single-root", "client-landed"},
    "epochs::credential_rotation_preserves_open_ownership": {"a-captured", "attached-c2", "revoked-c1", "foreign-principal", "checked-open", "exact-retry", "owned-a"},
    "epochs::all_submissions_retirement_contrast": {"unknown-attempt", "enrollment-unavailable", "real-epoch-mismatch", "uncertain-retained", "refusals-pruned"},
    "tails::clean_replay_reissues_exact_open": {"dispatch-cut", "captured", "clean-stop", "same-boot", "exact-reissue", "owned-completion"},
    "tails::gateway_crash_refuses_same_boot_and_recovers_after_modeled_reboot": {"dispatch-cut", "captured", "sigkill", "same-boot-refusal", "modeled-reboot", "exact-reissue", "owned-completion"},
    "tails::late_put_lands_after_unchanged_archive": {"dispatch-cut", "captured", "empty-slot", "local-archive", "late-release", "archive-refusals"},
    "tails::shipping_server_binary_publishes_once_and_lands": {"shipping-server", "accepted", "put-release", "landed", "human-output"},
    "composition::dispatch_loss_retains_uncertainty_and_resumes_without_post": {"decision", "reply-hold", "eight-unavailable", "pending", "put-release", "owned-completion"},
    "composition::unheld_reply_and_put_release_controls": {"accepted", "capture-refusals", "disconnected-release", "competing-release"},
    "composition::content_put_fault_surfaces_a_classified_backend_error": {"fault-injected", "exit-before-dispatch", "classified-diagnostic"},
    "composition::append_fence_refuses_and_retains_submission": {"append-fault", "fenced-exit", "uncertain-submission"},
    "composition::anonymous_reader_and_writer_policy_on_composed_gateway": {"anonymous-read", "write-endpoints-refused", "occupancy-unchanged"},
}
AUTHORITY_TESTS = {"shipping_local_abandonment_does_not_release_a_wedged_authority"}
CLI_TESTS = {
    "publication::tests::local_abandon_survives_pin_change_without_loading_credentials_or_source",
    "publication::tests::archive_refusal_and_explicit_new_adapter_reaches_begin",
    "publication::tests::completion_winner_drives_cache_anchor_hint_and_redisplay_without_post",
    "publication::tests::excluded_old_winner_skips_cache_and_keeps_higher_floor_but_repairs_hint",
    "publication_report::tests::output_failure_exits_one_and_reports_known_landing_or_archival_on_stderr",
}
CLIENT_TESTS = {
    "recovery::tests::lost::unsaved_lost_answers_retry_the_exact_tuple_until_release_is_durable",
    "recovery::tests::lost::witnessed_foreign_open_stops_after_one_durable_send",
    "recovery::tests::lost::later_refusal_service_and_invalid_answers_keep_the_original_retry",
    "recovery::tests::lost::forward_stale_releases_unanswered_current_twins_atomically",
    "recovery::tests::lost::stale_release_requires_a_witness_and_forward_consistent_head",
    "publication_store::tests::restart_at_every_persistence_cut_keeps_complete_generations",
    "publication_store::tests::fresh_load_rewrites_after_rename_without_directory_sync",
    "publication_store::tests::archive::abandonment_preserves_independent_namespace_vectors_and_all_evidence",
    "publication_store::tests::archive::archive_barriers_pin_bytes_ancestry_and_every_required_sync",
    "publication_store::tests::archive::archive_crash_cuts_recover_only_whole_generations_and_retry_without_rewrite",
    "publication_store::tests::archive::native_no_replace_preserves_collisions_including_dangling_symlink",
    "publication_store::tests::archive::archive_collision_during_move_preserves_both_complete_payloads",
    "publication_store::tests::archive::archive_retry_keeps_a_different_live_id_and_explicit_new_guards",
    "publication_store::tests::archive::archive_uncertainty_includes_retired_candidates_with_no_current_uncertainty",
    "recovery::tests::lost::lost_compares_owned_occupants_before_release_and_keeps_retired_twins",
    "recovery::tests::epoch_transition_draws_full_fresh_operation_and_preserves_writer",
    "recovery::tests::epoch_retry_after_unsaved_answer_preserves_third_attempt_and_retired_tuple",
    "recovery::tests::failed_interrupted_and_loaded_rebase_require_explicit_recovery",
    "recovery::tests::pending_scope_handle_and_capacity_refuse_before_network",
    "recovery::tests::persistence_faults_stop_network_and_fresh_handle_resumes",
    "recovery::tests::frozen_closure_recovers_missing_and_corrupt_local_objects",
    "recovery::tests::all_submissions_control_retirement",
    "recovery::tests::lost::bound_open_and_landed_activate_retained_history_after_a_lost_release",
    "publish_restart::tests::fail_is_rejected_at_network_cuts",
    "publish_restart::tests::fail_remains_an_io_error_only_at_persistence_cuts",
}
TESTS = {
    "c0_fresh_load_and_physical_cuts",
    "c1_begin_retains_before_send_and_ignores_changed_or_deleted_source",
    "c2_probe_started_and_delivery_require_explicit_recovery",
    "c3_probe_destination_preserves_catalogue_and_owned_completion",
    "c3_empty_retired_slot_blocks_other_target",
    "c3_retired_fixture_roundtrips_with_distinct_epoch_operations",
    "c4_attempt_and_dispatch_preserve_exact_retry_tuple",
    "continuation::c5_answer_accounting_release_and_foreign_open",
    "continuation::deferred_answer_restart_cuts_classify_once",
    "continuation::deferred_replay_failure_writes_preserve_marker",
    "continuation::c6_epoch_and_operation_saves_preserve_retired_tuples",
    "continuation::c6_epoch_oracle_rejects_lost_history_and_identity_changes",
    "continuation::c7_replacement_uses_frozen_content_and_capacity_never_evicts",
    "continuation::c8_historical_winner_complete_repair_and_output",
    "continuation::shipping_authority_routing_and_output_smoke",
    "continuation::c5_c8_physical_saves_keep_whole_successors",
    "continuation::c5_c8_failure_and_protocol_controls",
    "abandonment::c9_abandonment_cuts_preserve_capacity_and_foreign_open_history",
    "abandonment::c9_abandon_save_physical_cuts_keep_whole_catalogues",
    "abandonment::c9_archive_resync_and_failure_controls",
    "abandonment::c9_no_replace_and_explicit_new_controls",
    "abandonment::c9_pending_retired_fixture_preserves_checked_open_and_uncertainty",
    "rendezvous_report_negative_controls",
    "rendezvous_unreachable_negative_control",
    "rendezvous_unknown_cut_negative_control",
    "rendezvous_continue_and_invalid_reply_controls",
    "rendezvous_nonfallible_fail_negative_control",
    "rendezvous_exit_and_bound_negative_controls",
    "support::rendezvous_tests::abandonment_rendezvous_never_arriving_names_missing_side_and_cut",
    "support::rendezvous_tests::abandonment_rendezvous_assert_or_kill_preserves_captured_diagnostic",
    "support::rendezvous_tests::abandonment_rendezvous_slow_progress_passes",
    "support::rendezvous_tests::abandonment_rendezvous_continuous_progress_still_hits_absolute_cap",
    "c0_c4_physical_occurrences_keep_whole_generations",
}

TESTS.update({"backend::capture_framing_controls", "backend::detached_capture_remains_releasable", "tails::shipping::gateway_response_controls", "oracle::provenance_and_occupancy_controls", "composition::host_child", "composition::structural_report_controls", *SCENARIOS})


def required_tests(system="Linux"):
    return TESTS if system == "Linux" else TESTS - set(SCENARIOS)


def cut_names(source, name):
    match = re.search(rf"pub const {name}: &\[&str\] = &\[(.*?)\];", source, re.S)
    if match is None:
        raise ValueError(f"missing cut registry: {name}")
    cuts = re.findall(r'"([a-z-]+)"', match[1])
    if not cuts or len(set(cuts)) != len(cuts):
        raise ValueError(f"empty or duplicate cut registry: {name}")
    return cuts


def registry(source=None, system="Linux"):
    source = source if source is not None else Path("crates/granary-client/src/publish_restart.rs").read_text()
    cuts = cut_names(source, "CUTS")
    after_only = cut_names(source, "AFTER_ONLY_CUTS")
    physical = cut_names(source, "PHYSICAL_CUTS")
    archive = cut_names(source, "ARCHIVE_CUTS")
    if not set(after_only + physical + archive) <= set(cuts) or set(after_only) & set(physical + archive) or set(physical) & set(archive):
        raise ValueError("invalid cut properties")
    required = {f"{cut}:{side}" for cut in cuts for side in (("after",) if cut in after_only else ("before", "after"))}
    required.update(f"{stage}:{cut}:{side}:{occurrence}" for stage, occurrence in (("begin", 1), ("selection-load", 1), ("resume-load", 2), ("probe-save", 3), ("probe-result", 4), ("attempt-save", 5), ("answer-save", 6), ("epoch-save", 6), ("operation-save", 7), ("replacement-save", 5), ("complete-save", 6), ("abandon-save", 1)) for cut in physical for side in ("before", "after"))
    required.update(f"{test}:{stage}" for test, stages in SCENARIOS.items() if test in required_tests(system) for stage in stages)
    return required


def graph(data):
    packages = {p["id"]: p["name"] for p in data["packages"]}
    checked = set()
    for node in data["resolve"]["nodes"]:
        name = packages[node["id"]]
        if name in PACKAGES:
            checked.add(name)
            armed = {FEATURE, "crash-points"} & set(node["features"])
            if armed:
                raise ValueError(f"shipping feature graph enables {sorted(armed)} in {name}")
    if checked != set(PACKAGES):
        raise ValueError(f"incomplete shipping graph: {sorted(checked)}")


def audit_graph():
    # The full resolved workspace includes dev edges. In particular a server
    # dev-dependency must never arm the client via feature unification.
    result = subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1"], capture_output=True, text=True, check=True)
    graph(json.loads(result.stdout))
    print("FEATURE-GRAPH: all three packages excluded (feature resolution is profile-independent)")


def wall_result(package, result):
    message = "crash-points must never compile into a release binary" if package == "granary-server" else f"{FEATURE} must never compile into a release {package} artifact"
    if result.returncode == 0:
        raise ValueError(f"release wall missing: {package} compiled successfully")
    if message not in result.stdout + result.stderr:
        raise ValueError(f"{package} failed without its specific release wall:\n{result.stdout}\n{result.stderr}")


def inspect_shipping(path):
    binary = path.read_bytes()
    for marker in (b"GRANARY_RESTART_SOCKET", b"REACHED ", b"GRANARY_TEST_HOST_PLAN", b"GATEWAY post-dispatch unavailable"):
        if marker in binary:
            raise ValueError(f"shipping binary contains instrumentation marker: {marker.decode()}")
    print(f"SHIPPING-BINARY: instrumentation markers absent from {path}")


def armed_control(path):
    try:
        inspect_shipping(path)
    except ValueError as error:
        if not str(error).startswith("shipping binary contains instrumentation marker:"):
            raise
        print(f"ARMED-BINARY: inspection refused as required: {error}")
    else:
        raise ValueError("armed binary passed shipping inspection")


def walls():
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR") or "target").resolve()
    shipping_dir = target_dir / "publish-restart-shipping"
    subprocess.run(["cargo", "build", "--locked", "--release", "-p", "granary-cli", "--bin", "gran", "--target-dir", str(shipping_dir)], check=True)
    inspect_shipping(shipping_dir / "release/gran")
    subprocess.run(["cargo", "build", "--locked", "--release", "-p", "granary-server", "--target-dir", str(shipping_dir)], check=True)
    inspect_shipping(shipping_dir / "release/granary-server")
    for package in reversed(PACKAGES):
        cmd = ["cargo", "check", "--locked", "--release", "-p", package, "--features", "crash-points" if package == "granary-server" else FEATURE, "--target-dir", str(target_dir / "publish-restart-walls")]
        if package == "granary-cli":
            # Reach the binary's own wall independently of the client wall.
            cmd += ["--config", "profile.release.package.granary-client.debug-assertions=true"]
        result = subprocess.run(cmd, env=dict(os.environ, CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS="false"), capture_output=True, text=True, check=False)
        wall_result(package, result)
        print(f"RELEASE-WALL: {package} refused with its specific wall (exit {result.returncode})")


def selection(data, client=False, cli=False, authority=False, system="Linux"):
    suites = data["rust-suites"]
    required = CLIENT_TESTS if client else CLI_TESTS if cli else AUTHORITY_TESTS if authority else required_tests(system)
    binary = "granary_client" if client else "gran" if cli else "authority_host" if authority else "publish_restart"
    observed = set()
    for suite in suites.values():
        if suite["binary-name"] == binary and (client or cli or suite["kind"] == "test" and suite["package-name"] == "granary-server") and (not client or suite["kind"] == "lib" and suite["package-name"] == "granary-client") and (not cli or suite["kind"] == "bin" and suite["package-name"] == "granary-cli") and (not authority or suite["kind"] == "test" and suite["package-name"] == "granary-server"):
            for name, test in suite["testcases"].items():
                if test["filter-match"]["status"] == "matches" and not test["ignored"]:
                    if name in observed:
                        raise ValueError(f"duplicate selected row: {name}")
                    observed.add(name)
    extra = set() if client or cli else observed - required
    if required - observed or extra:
        raise ValueError(f"missing expected test or unexpected selection: missing={sorted(required-observed)}, extra={sorted(extra)}")


def coverage(reports, required, run, system="Linux"):
    if not reports or not required:
        raise ValueError("empty coverage set")
    expected_tests = required_tests(system)
    tests, observed = set(), set()
    for report in reports:
        lines = report.splitlines()
        if len(lines) < 3 or lines[1] != f"RUN {run}" or lines[2] != "BINARY publish_restart" or not lines[0].startswith("TEST "):
            raise ValueError("malformed coverage report")
        test = lines[0][5:]
        if test not in expected_tests or test in tests:
            raise ValueError(f"unexpected or duplicate test identity: {test}")
        tests.add(test)
        for line in lines[3:]:
            if not line.startswith("CUT ") or line[4:] not in required:
                raise ValueError(f"malformed cut report: {line}")
            if any(line[4:] == f"{row}:{stage}" and test != row for row, stages in SCENARIOS.items() for stage in stages):
                raise ValueError("scenario stage reported by wrong test")
            if test in SCENARIOS and line[4:] in observed:
                raise ValueError("duplicate scenario stage")
            observed.add(line[4:])
    if tests != expected_tests or observed != required:
        raise ValueError(f"incomplete identity coverage: missing tests={sorted(expected_tests-tests)}, missing cuts={sorted(required-observed)}")


def self_test_directory(environment=None):
    environment = os.environ if environment is None else environment
    target = environment.get("CARGO_TARGET_DIR")
    directory = Path(target).resolve() if target else Path(tempfile.gettempdir()).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def venue_evidence(environment=None, inspect=subprocess.run):
    environment = os.environ if environment is None else environment
    directory = str(Path(environment.get("TMPDIR", "/tmp")).resolve(strict=True))
    mounts = json.loads(inspect(["findmnt", "-J", "-T", directory, "-o", "FSTYPE,OPTIONS"], capture_output=True, text=True, check=True).stdout)["filesystems"]
    if len(mounts) != 1:
        raise ValueError("unreadable authority venue")
    return {"os": platform.system(), "kernel": platform.release(), "directory": directory, "filesystem": mounts[0]["fstype"], "options": mounts[0]["options"]}


def self_test():
    def refuses(label, fn):
        try:
            fn()
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            print(f"REFUSED {label}: {error}")
        else:
            raise ValueError(f"negative control accepted: {label}")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        chosen = root / "cargo-output"
        for target in (str(chosen), os.path.relpath(chosen, Path.cwd())):
            actual = self_test_directory({"CARGO_TARGET_DIR": target})
            assert (actual, actual.is_absolute(), actual.is_dir()) == (chosen, True, True), f"self-test artifacts must use the resolved Cargo target: {actual}"
        assert self_test_directory({}) == Path(tempfile.gettempdir()).resolve(), "unset Cargo target must use system temp"
        fixtures = root / "fixtures"
        fixtures.mkdir()
        link = root / "temporary-link"
        link.symlink_to(fixtures, target_is_directory=True)
        calls = []

        def inspect_mount(command, **_kwargs):
            calls.append(command)
            filesystem = "overlay" if Path(command[3]) == fixtures else "ext4"
            return subprocess.CompletedProcess(command, 0, json.dumps({"filesystems": [{"fstype": filesystem, "options": "rw,data=ordered"}]}), "")

        data = venue_evidence({"TMPDIR": str(link)}, inspect_mount)
        data.update(os="Linux", kernel="6.8.0")
        refuses("TMPDIR fixtures on unsupported storage", lambda: venue(data))
        assert (data["directory"], calls[0][3]) == (str(fixtures), str(fixtures)), f"venue must inspect resolved fixture directory: {data}, {calls}"
        default = venue_evidence({}, inspect_mount)
        default.update(os="Linux", kernel="6.8.0")
        venue(default)
        assert default["directory"] == str(Path("/tmp").resolve()), f"default fixture directory must be resolved: {default}"
        minio = subprocess.run(["bash", "scripts/minio-harness.sh", "path"], env=dict(os.environ, CARGO_TARGET_DIR=str(chosen)), capture_output=True, text=True, check=False)
        assert (minio.returncode, Path(minio.stdout.strip()).resolve().parent) == (0, Path("target/minio").resolve()), f"MinIO cache must stay shared despite Cargo target: stdout={minio.stdout!r}, stderr={minio.stderr!r}"

    good = {"packages": [{"id": name, "name": name} for name in PACKAGES], "resolve": {"nodes": [{"id": name, "features": []} for name in PACKAGES]}}
    graph(good)
    for package in PACKAGES:
        bad = json.loads(json.dumps(good))
        next(n for n in bad["resolve"]["nodes"] if n["id"] == package)["features"] = [FEATURE]
        refuses(f"feature graph {package}", lambda: graph(bad))
        message = "crash-points must never compile into a release binary" if package == "granary-server" else f"{FEATURE} must never compile into a release {package} artifact"
        wall_result(package, subprocess.CompletedProcess([], 101, message, ""))
        refuses(f"success with wall text {package}", lambda: wall_result(package, subprocess.CompletedProcess([], 0, message, "")))
        refuses(f"removed wall {package}", lambda: wall_result(package, subprocess.CompletedProcess([], 0, "", "")))
        refuses(f"unrelated build failure {package}", lambda: wall_result(package, subprocess.CompletedProcess([], 101, "", "some other compiler error")))
    crash_graph = json.loads(json.dumps(good))
    next(n for n in crash_graph["resolve"]["nodes"] if n["id"] == "granary-server")["features"] = ["crash-points"]
    refuses("server crash feature", lambda: graph(crash_graph))
    with tempfile.TemporaryDirectory(dir=self_test_directory()) as directory:
        artifact = Path(directory) / "artifact"
        artifact.write_bytes(b"feature-off artifact")
        inspect_shipping(artifact)
        for marker in (b"GRANARY_RESTART_SOCKET", b"REACHED ", b"GRANARY_TEST_HOST_PLAN", b"GATEWAY post-dispatch unavailable"):
            artifact.write_bytes(marker)
            refuses("armed marker " + marker.decode(), lambda: inspect_shipping(artifact))
            armed_control(artifact)
    tails = {
        "tails::clean_replay_reissues_exact_open": {"dispatch-cut", "captured", "clean-stop", "same-boot", "exact-reissue", "owned-completion"},
        "tails::gateway_crash_refuses_same_boot_and_recovers_after_modeled_reboot": {"dispatch-cut", "captured", "sigkill", "same-boot-refusal", "modeled-reboot", "exact-reissue", "owned-completion"},
        "tails::late_put_lands_after_unchanged_archive": {"dispatch-cut", "captured", "empty-slot", "local-archive", "late-release", "archive-refusals"},
        "tails::shipping_server_binary_publishes_once_and_lands": {"shipping-server", "accepted", "put-release", "landed", "human-output"},
    }
    composition = {
        "composition::dispatch_loss_retains_uncertainty_and_resumes_without_post": {"decision", "reply-hold", "eight-unavailable", "pending", "put-release", "owned-completion"},
        "composition::unheld_reply_and_put_release_controls": {"accepted", "capture-refusals", "disconnected-release", "competing-release"},
        "composition::content_put_fault_surfaces_a_classified_backend_error": {"fault-injected", "exit-before-dispatch", "classified-diagnostic"},
        "composition::append_fence_refuses_and_retains_submission": {"append-fault", "fenced-exit", "uncertain-submission"},
        "composition::anonymous_reader_and_writer_policy_on_composed_gateway": {"anonymous-read", "write-endpoints-refused", "occupancy-unchanged"},
    }
    assert {name: SCENARIOS.get(name) for name in composition} == composition, "composed gateway scenarios and stages must be required on Linux"
    assert {name: SCENARIOS.get(name) for name in tails} == tails, "replay/tail scenarios and stages must be required on Linux"
    epochs = {
        "epochs::two_epoch_changes_keep_both_candidates_and_complete_with_a": {"a-captured", "e1-mismatch", "b-captured", "e2-mismatch", "empty-catalogue", "distinct-identities", "late-releases", "owned-a"},
        "epochs::delayed_a_release_after_rebase_before_b_put": {"a-held-across-reinitialise", "empty-probe", "head-resolved-cut", "a-released-before-b-put", "single-root", "client-landed"},
        "epochs::delayed_a_release_after_b_put": {"a-held-across-reinitialise", "empty-probe", "head-resolved-cut", "b-put-landed", "a-released-after-b-put", "single-root", "client-landed"},
        "epochs::credential_rotation_preserves_open_ownership": {"a-captured", "attached-c2", "revoked-c1", "foreign-principal", "checked-open", "exact-retry", "owned-a"},
        "epochs::all_submissions_retirement_contrast": {"unknown-attempt", "enrollment-unavailable", "real-epoch-mismatch", "uncertain-retained", "refusals-pruned"},
    }
    assert {name: SCENARIOS.get(name) for name in epochs} == epochs, "epoch/rotation scenarios and stages must be required on Linux"
    retained = {
        "retained::landing_fence_unfence_settles_retained_state": {"operator-initialise", "lock-refusal", "unanswered-cut", "landing-fence", "supervisor-controls", "unfence-refusals", "time-boundary", "reboot-without-unfence", "unfence-clean", "exact-replay", "single-decision", "completion-no-post"},
        "retained::first_append_fence_reposts_retained_state": {"operator-initialise", "lock-refusal", "unanswered-cut", "first-append-fence", "supervisor-controls", "unfence-refusals", "time-boundary", "reboot-without-unfence", "unfence-clean", "retained-repost", "single-decision", "completion-no-post"},
    }
    assert {name: SCENARIOS.get(name) for name in retained} == retained, "retained operator scenarios and stages must be required on Linux"
    required = registry()
    source = Path("crates/granary-client/src/publish_restart.rs").read_text()
    refuses("archive cut absent from registry", lambda: registry(source.replace('    "archive-open",\n', '', 1)))
    refuses("duplicate archive registry", lambda: registry(source.replace('pub const ARCHIVE_CUTS: &[&str] = &[', 'pub const ARCHIVE_CUTS: &[&str] = &["archive-open",')))
    physical = required - {f"{row}:{stage}" for row, stages in SCENARIOS.items() for stage in stages}
    reports = ["TEST " + test + "\nRUN current\nBINARY publish_restart\n" + "".join(f"CUT {cut}\n" for cut in sorted(physical if test == sorted(TESTS)[0] else {f"{test}:{stage}" for stage in SCENARIOS.get(test, set())})) for test in sorted(TESTS)]
    native_reports = [report for report in reports if report.splitlines()[0][5:] in required_tests("Darwin")]
    coverage(native_reports, registry(system="Darwin"), "current", system="Darwin")
    refuses("macOS reports cannot satisfy Linux coverage", lambda: coverage(native_reports, required, "current", system="Linux"))
    coverage(reports, required, "current")
    refuses("empty coverage", lambda: coverage([], required, "current"))
    refuses("empty required domain", lambda: coverage(reports, set(), "current"))
    refuses("missing expected test", lambda: coverage(reports[:-1], required, "current"))
    refuses("malformed report", lambda: coverage(["nonsense"], required, "current"))
    refuses("wrong cut identity", lambda: coverage([reports[0].replace("load:after", "unknown:after")] + reports[1:], required, "current"))
    refuses("before-delivery cut", lambda: coverage([reports[0] + "CUT probe-delivered:before\n"] + reports[1:], required, "current"))
    refuses("malformed graph", lambda: graph({}))
    client = {"rust-suites": {"granary-client": {"binary-name": "granary_client", "kind": "lib", "package-name": "granary-client", "testcases": {name: {"filter-match": {"status": "matches"}, "ignored": False} for name in CLIENT_TESTS}}}}
    selection(client, client=True)
    refuses("empty client selection", lambda: selection({"rust-suites": {}}, client=True))
    for name in CLIENT_TESTS:
        missing = json.loads(json.dumps(client))
        del missing["rust-suites"]["granary-client"]["testcases"][name]
        refuses(f"missing client test {name}", lambda: selection(missing, client=True))
    cli = {"rust-suites": {"granary-cli": {"binary-name": "gran", "kind": "bin", "package-name": "granary-cli", "testcases": {name: {"filter-match": {"status": "matches"}, "ignored": False} for name in CLI_TESTS}}}}
    selection(cli, cli=True)
    wrong_cli = json.loads(json.dumps(cli))
    wrong_cli["rust-suites"]["granary-cli"]["kind"] = "lib"
    refuses("wrong CLI binary kind", lambda: selection(wrong_cli, cli=True))
    refuses("empty CLI selection", lambda: selection({"rust-suites": {}}, cli=True))
    authority = {"rust-suites": {"granary-server": {"binary-name": "authority_host", "kind": "test", "package-name": "granary-server", "testcases": {name: {"filter-match": {"status": "matches"}, "ignored": False} for name in AUTHORITY_TESTS}}}}
    selection(authority, authority=True)
    refuses("missing second-publisher wedge test", lambda: selection({"rust-suites": {}}, authority=True))
    bad = json.loads(json.dumps(authority))
    bad["rust-suites"]["granary-server"]["testcases"][next(iter(AUTHORITY_TESTS))]["ignored"] = True
    refuses("ignored second-publisher wedge test", lambda: selection(bad, authority=True))
    wrong = json.loads(json.dumps(authority))
    wrong["rust-suites"]["granary-server"]["kind"] = "bin"
    refuses("wrong second-publisher binary kind", lambda: selection(wrong, authority=True))
    for name in CLI_TESTS:
        missing = json.loads(json.dumps(cli))
        del missing["rust-suites"]["granary-cli"]["testcases"][name]
        refuses(f"missing CLI test {name}", lambda: selection(missing, cli=True))
    for name in sorted(t for t in TESTS if t.startswith(("continuation::", "abandonment::"))):
        refuses(f"missing report {name}", lambda: coverage([r for r in reports if not r.startswith("TEST " + name + "\n")], required, "current"))
    added = {"answer-save", "epoch-save", "operation-save", "replacement-save", "complete-save", "cache-repair", "hint-repair", "output-write", "abandon-save", "archive-rename", "archive-sync", *cut_names(source, "ARCHIVE_CUTS")}
    for cut in sorted(c for c in required if c.split(":", 1)[0] in added):
        missing = [r.replace(f"CUT {cut}\n", "") for r in reports]
        refuses(f"missing cut {cut}", lambda: coverage(missing, required, "current"))
    refuses("stale reports", lambda: coverage(reports, required, "next"))
    refuses("wrong report binary", lambda: coverage([r.replace("BINARY publish_restart", "BINARY other") for r in reports], required, "current"))
    refuses("duplicate reports", lambda: coverage(reports + [reports[0]], required, "current"))
    server = {"rust-suites": {"rows": {"binary-name": "publish_restart", "kind": "test", "package-name": "granary-server", "testcases": {name: {"filter-match": {"status": "matches"}, "ignored": False} for name in TESTS}}}}
    selection(server)
    native_server = json.loads(json.dumps(server))
    for row in SCENARIOS:
        native_server["rust-suites"]["rows"]["testcases"][row]["ignored"] = True
    selection(native_server, system="Darwin")
    for row in SCENARIOS:
        bad = json.loads(json.dumps(server))
        bad["rust-suites"]["rows"]["testcases"][row]["ignored"] = True
        refuses("ignored scenario " + row, lambda: selection(bad))
        refuses("missing scenario " + row, lambda: coverage([r for r in reports if not r.startswith("TEST " + row + "\n")], required, "current"))
        for stage in SCENARIOS[row]:
            missing = [r.replace(f"CUT {row}:{stage}\n", "") for r in reports]
            refuses(f"missing scenario stage {row}:{stage}", lambda: coverage(missing, required, "current"))
    duplicate = json.loads(json.dumps(server))
    duplicate["rust-suites"]["second"] = duplicate["rust-suites"]["rows"]
    refuses("duplicate scenario selection", lambda: selection(duplicate))
    stage_row = next(iter(SCENARIOS))
    stage = next(iter(SCENARIOS[stage_row]))
    duplicated = [r + f"CUT {stage_row}:{stage}\n" if r.startswith("TEST " + stage_row + "\n") else r for r in reports]
    refuses("duplicate scenario stage", lambda: coverage(duplicated, required, "current"))
    wrong = json.loads(json.dumps(server))
    wrong["rust-suites"]["rows"]["kind"] = "bin"
    refuses("wrong scenario binary", lambda: selection(wrong))
    for bad in ({}, {"os": "Linux", "filesystem": "overlay", "kernel": "6.8.0", "options": "rw"}):
        refuses("unsupported or unreadable venue", lambda: venue(bad))
    venue({"os": "Linux", "filesystem": "ext4", "kernel": "6.8.0", "options": "rw,relatime,data=ordered"})
    for filesystem, kernel, options in (("ext4", "6.7.0", "rw"), ("ext4", "6.8.0-rc1", "rw"), ("ext4", "unreadable", "rw"), ("ext4", "6.8.0", "rw,nobarrier"), ("ext4", "6.8.0", "ro")):
        refuses(f"unsupported kernel/mount {filesystem} {kernel} {options}", lambda: venue({"os": "Linux", "filesystem": filesystem, "kernel": kernel, "options": options}))
    for filesystem in ("xfs", "btrfs"):
        venue({"os": "Linux", "filesystem": filesystem, "kernel": "6.8.0", "options": "rw"})
    print("PUBLISH-RESTART: all exclusion/coverage negative controls refused")


def venue(data):
    if data["os"] != "Linux" or data["filesystem"] not in {"ext4", "xfs", "btrfs"}:
        raise ValueError("unsupported authority venue")
    kernel = re.fullmatch(r"(\d+)\.(\d+)\.[0-9]+(?:[-.][a-zA-Z0-9_.+-]+)?", data["kernel"])
    if kernel is None or "-rc" in data["kernel"] or data["filesystem"] == "ext4" and tuple(map(int, kernel.groups())) < (6, 8):
        raise ValueError("unsupported authority kernel")
    if "rw" not in data["options"].split(",") or any(v in data["options"].split(",") for v in ("nobarrier", "data=writeback")):
        raise ValueError("unsupported authority mount options")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("graph", "walls", "armed-control", "selection", "client-selection", "cli-selection", "authority-selection", "coverage", "venue", "self-test"))
    parser.add_argument("path", nargs="?")
    args = parser.parse_args()
    if args.action == "graph":
        audit_graph()
    elif args.action == "walls":
        walls()
    elif args.action == "armed-control":
        armed_control(Path(args.path))
    elif args.action in ("selection", "client-selection", "cli-selection", "authority-selection"):
        selection(json.loads(Path(args.path).read_text()), client=args.action == "client-selection", cli=args.action == "cli-selection", authority=args.action == "authority-selection", system=platform.system())
        print("SELECTION: every required test selected by identity")
    elif args.action == "coverage":
        system = platform.system()
        coverage([p.read_text() for p in sorted(Path(args.path).iterdir())], registry(system=system), os.environ["GRANARY_RESTART_RUN"], system=system)
        print("COVERAGE: every required test and registered cut side observed by identity")
    elif args.action == "venue":
        if args.path:
            data = json.loads(Path(args.path).read_text())
        else:
            data = venue_evidence()
        venue(data)
        print("VENUE-EVIDENCE: " + json.dumps(data, sort_keys=True))
        print("VENUE: supported authority storage observed")
    else:
        self_test()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print(f"PUBLISH-RESTART REFUSED: {error}", file=sys.stderr)
        sys.exit(1)
