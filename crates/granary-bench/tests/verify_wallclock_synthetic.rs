// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Verifier behaviour on an independently constructed input: schema and
//! consistency refusals, recomputation, verdict boundaries, and CLI reporting.
//! These fixtures are invented in code. They establish no real-artifact
//! evidence, measurement occurrence, or producer compatibility.
//! No fixture is loaded from a measurement record or substituted when absent.

#![expect(
    clippy::expect_used,
    reason = "fixture helpers sit outside #[test] fns (test code, standards rule 3)"
)]
#![expect(
    clippy::panic,
    reason = "a fixture path that does not address a container is a test bug, not an input"
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use granary_bench::json::Json;
use granary_bench::wallclock::{
    self, REORDERING, REQUIRED_OBSERVATIONS, RESERVED_KEYS, ROLES, Snapshot, Verdict, VerifyError,
};

// A 16 MiB corpus, a 4 MiB changed subtree, and 512 KiB of novel data.
// Uploads and downloads are deliberately different; all totals are invented.
// The 139.5 s window starts and ends between samples spaced ten seconds apart.
fn base() -> Json {
    let mut value = Json::parse(
        r#"{
          "artifact_version": 1,
          "run_id": "constructed-run",
          "harness": {"script": "constructed-input", "git_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
          "venue": {
            "node": "fixture-node", "guest": "fixture-guest", "arch": "test-arch",
            "kernel": "test-kernel", "os": "test-os", "transport": "test-transport",
            "support_tier": "test-tier"
          },
          "corpus": {
            "apparent_bytes_v_n": 16777216, "changed_subtree": "sample/",
            "changed_subtree_bytes": 4194304, "walker": "constructed-walker",
            "expected_v_n_tree_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expected_v_n1_subtree_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          },
          "timeline": {
            "warmups_ended": "2032-06-15T12:00:05.000Z",
            "delta_generated": "2032-06-15T12:00:10.000Z",
            "publish_started": "2032-06-15T12:00:20.000Z",
            "publish_ended": "2032-06-15T12:00:30.000Z",
            "workloads_started": "2032-06-15T12:00:40.000Z",
            "workloads_ended": "2032-06-15T12:02:00.000Z",
            "server_stopped": "2032-06-15T12:02:24.500Z"
          },
          "node_cpu_samples": [], "clocks": [], "per_client": [], "observations": [],
          "snapshots": {
            "server": {
              "format_version": 1, "writer_kind": "granary-server", "run_id": "constructed-run",
              "role": "server", "poisoned": false, "request_bytes": 300000,
              "requests_with_body": 4, "response_bytes_produced": 100000000,
              "drain_outcome": "drained", "listen_addr": "127.0.0.1:43210"
            }
          }
        }"#,
    )
    .expect("constructed JSON");
    populate_snapshots(&mut value);
    let clock = Json::parse(
        r#"{"client": 1, "clock_a_seconds": 2.5, "clock_a_polls": 2,
            "clock_a_poll_bytes": 800000, "clock_b_seconds": 4.5}"#,
    )
    .expect("constructed clock");
    let per_client = Json::parse(
        r#"{"client": 1,
            "observed_subtree_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "warmup_observed_tree_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "warmup_verify_observed_tree_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "exit_codes": {"warmup": 0, "warmup_verify": 0, "workload": 0, "clock_a": 0, "clock_b": 0},
            "endpoint_given": "https://127.0.0.1:43210", "seq_given": {"warmup": 1, "workload": 2}}"#,
    ).expect("constructed client record");
    for (key, template) in [("clocks", clock), ("per_client", per_client)] {
        let rows = (1..=3)
            .map(|k| {
                let mut row = template.clone();
                set(&mut row, &["client"], Json::UInt(k));
                row
            })
            .collect();
        set(&mut value, &[key], Json::Arr(rows));
    }
    let observations = [
        "no_publish",
        "stale_content",
        "wrong_server",
        "no_snapshot",
        "empty_run_id",
        "three_processes",
        "server_killed_before_snapshot",
        "expected_digests_computed_before_publish",
        "warmup_cache_dirs_were_empty",
        "no_cache_client_fails_p2",
    ]
    .into_iter()
    .map(observation)
    .collect();
    set(&mut value, &["observations"], Json::Arr(observations));
    let samples = (0..=15)
        .map(|k| sample(&stamp_of("2032-06-15", 43_200_000 + k * 10_000), 20.0))
        .collect();
    set(&mut value, &["node_cpu_samples"], Json::Arr(samples));
    value
}

#[test]
fn snapshots_accept_null_publish_and_nullable_authority_counters() {
    let mut value = base();
    let mut client = at(&mut value, &["snapshots", "client-1"]).clone();
    insert(&mut client, &[], "publish", Json::Null);
    assert!(Snapshot::from_json(&client).unwrap().publish.is_none());

    let mut publisher = at(&mut value, &["snapshots", "publisher"]).clone();
    let counters = [
        "novel_objects",
        "novel_bytes",
        "bins_uploaded",
        "bin_bytes_uploaded",
    ];
    for field in counters {
        set(&mut publisher, &["publish", field], Json::Null);
    }
    let summary = Snapshot::from_json(&publisher).unwrap().publish.unwrap();
    assert_eq!(summary.seq, 2);
    assert_eq!(summary.novel_objects, None);
    assert_eq!(summary.novel_bytes, None);
    assert_eq!(summary.bins_uploaded, None);
    assert_eq!(summary.bin_bytes_uploaded, None);
    for field in counters {
        let mut damaged = publisher.clone();
        remove(&mut damaged, &["publish"], field);
        assert!(Snapshot::from_json(&damaged).is_err(), "missing {field}");
        let mut damaged = publisher.clone();
        set(&mut damaged, &["publish", field], Json::s("invalid"));
        assert!(Snapshot::from_json(&damaged).is_err(), "invalid {field}");
    }
    for field in ["seq", "manifest_root"] {
        let mut damaged = publisher.clone();
        set(&mut damaged, &["publish", field], Json::Null);
        assert!(Snapshot::from_json(&damaged).is_err(), "null {field}");
    }
    for malformed in [Json::s("invalid"), Json::UInt(1), Json::Obj(Vec::new())] {
        set(&mut client, &["publish"], malformed);
        assert!(Snapshot::from_json(&client).is_err());
    }
    set(&mut value, &["snapshots", "publisher"], publisher);
    assert!(matches!(refusal(&value), VerifyError::Schema(_)));
}

fn populate_snapshots(value: &mut Json) {
    let client = Json::parse(
        r#"{
          "format_version": 1, "writer_kind": "granary-client", "run_id": "constructed-run",
          "role": "publisher", "poisoned": false, "response_bytes": 400000,
          "endpoint": "https://127.0.0.1:43210", "pinned_seq": 2
        }"#,
    )
    .expect("constructed client");
    for role in [
        "publisher",
        "client-1",
        "client-2",
        "client-3",
        "warmup-1",
        "warmup-2",
        "warmup-3",
        "warmup-verify-1",
        "warmup-verify-2",
        "warmup-verify-3",
    ] {
        let mut snapshot = client.clone();
        set(&mut snapshot, &["role"], Json::s(role));
        if role.starts_with("warmup-") {
            set(&mut snapshot, &["pinned_seq"], Json::UInt(1));
            let bytes = if role.starts_with("warmup-verify-") {
                1000
            } else {
                16_000_000
            };
            set(&mut snapshot, &["response_bytes"], Json::UInt(bytes));
        }
        if role == "publisher" {
            insert(&mut snapshot, &[], "publish", Json::parse(
                r#"{"seq": 2, "novel_objects": 8, "novel_bytes": 524288,
                    "bins_uploaded": 2, "bin_bytes_uploaded": 200000,
                    "manifest_root": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#,
            ).expect("constructed publish summary"));
        }
        insert(value, &["snapshots"], role, snapshot);
    }
}

fn at<'a>(value: &'a mut Json, path: &[&str]) -> &'a mut Json {
    let mut cursor = value;
    for segment in path {
        cursor = match cursor {
            Json::Obj(fields) => fields
                .iter_mut()
                .find(|(k, _)| k == segment)
                .map_or_else(|| panic!("no key `{segment}`"), |(_, v)| v),
            Json::Arr(items) => {
                let i: usize = segment.parse().expect("array index");
                items.get_mut(i).unwrap_or_else(|| panic!("no index {i}"))
            }
            _ => panic!("`{segment}` does not address a container"),
        };
    }
    cursor
}

fn set(value: &mut Json, path: &[&str], new: Json) {
    *at(value, path) = new;
}

fn insert(value: &mut Json, path: &[&str], key: &str, new: Json) {
    match at(value, path) {
        Json::Obj(fields) => fields.push((key.to_owned(), new)),
        _ => panic!("not an object"),
    }
}

fn remove(value: &mut Json, path: &[&str], key: &str) {
    match at(value, path) {
        Json::Obj(fields) => fields.retain(|(k, _)| k != key),
        _ => panic!("not an object"),
    }
}

fn uint(value: &Json, path: &[&str]) -> u64 {
    let mut copy = value.clone();
    match at(&mut copy, path) {
        Json::UInt(v) => *v,
        other => panic!("not an unsigned integer: {other:?}"),
    }
}

fn text_at(value: &Json, path: &[&str]) -> String {
    let mut copy = value.clone();
    match at(&mut copy, path) {
        Json::Str(v) => v.clone(),
        other => panic!("not a string: {other:?}"),
    }
}

fn observation_index(value: &Json, name: &str) -> usize {
    value
        .get("observations")
        .and_then(Json::items)
        .expect("observations")
        .iter()
        .position(|o| o.get("name") == Some(&Json::s(name)))
        .unwrap_or_else(|| panic!("no observation named `{name}`"))
}

fn refusal(value: &Json) -> VerifyError {
    match wallclock::verify_json(value) {
        Ok(f) => panic!("expected a refusal, got findings for run {}", f.run_id),
        Err(e) => e,
    }
}

fn accepted(value: &Json) -> wallclock::Findings {
    match wallclock::verify_json(value) {
        Ok(f) => f,
        Err(e) => panic!("expected acceptance, refused: {e}"),
    }
}

fn run_cli(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_granary-bench"))
        .args(args)
        .output()
        .expect("spawn granary-bench");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

struct ScratchDir(PathBuf);

impl ScratchDir {
    #[expect(
        clippy::disallowed_methods,
        reason = "test fixture: a scratch directory name unique to this process; \
                  disallowed_methods has no allow-in-tests knob"
    )]
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "granary-bench-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_flag_is_a_usage_error_before_the_artifact_is_opened() {
    let (ok, _, err) = run_cli(&[
        "verify-wallclock",
        "--date",
        "2026-09-09",
        "/no/such/artifact.json",
    ]);
    assert!(!ok, "a flag must be refused");
    assert!(err.contains("takes no flags"), "{err}");
    assert!(
        !err.contains("cannot read"),
        "the artifact must never be opened: {err}"
    );
}

#[test]
fn a_lone_flag_is_a_usage_error() {
    for flag in ["--help", "-h", "--machine"] {
        let (ok, _, err) = run_cli(&["verify-wallclock", flag]);
        assert!(!ok, "{flag} must be refused");
        assert!(err.contains("takes no flags"), "{flag}: {err}");
    }
}

#[test]
fn a_second_positional_is_a_usage_error() {
    let path = "/no/such/constructed.json".to_owned();
    let (ok, _, err) = run_cli(&["verify-wallclock", path.as_str(), "out.json"]);
    assert!(!ok, "an output path is not this verb's argv");
    assert!(err.contains("exactly one positional"), "{err}");
}

#[test]
fn zero_positionals_is_a_usage_error() {
    let (ok, _, err) = run_cli(&["verify-wallclock"]);
    assert!(!ok);
    assert!(err.contains("exactly one positional"), "{err}");
}

#[test]
fn a_missing_artifact_is_a_read_error_and_not_a_usage_error() {
    let (ok, _, err) = run_cli(&["verify-wallclock", "/no/such/artifact.json"]);
    assert!(!ok);
    assert!(err.contains("cannot read"), "{err}");
    assert!(!err.contains("takes no flags"), "{err}");
}

#[test]
fn a_forging_character_in_the_artifact_path_is_refused_before_the_file_is_opened() {
    let scratch = ScratchDir::new("argv-forging-test");
    let dir = scratch.path();

    for (name, code_point) in [
        ("artifact.json\nP1 VERDICT: fail\nFORGED", "000A"),
        ("artifact\u{1b}[2Jjson", "001B"),
        ("artifact\u{202e}json", "202E"),
    ] {
        let path = dir.join(name);
        let (ok, out, err) = run_cli(&["verify-wallclock", path.to_str().expect("utf-8 path")]);
        assert!(!ok, "{name:?} must be refused");
        assert!(out.is_empty(), "nothing should print to stdout: {out}");
        assert!(err.contains(&format!("U+{code_point}")), "{name:?}: {err}");
        assert!(
            !err.contains("cannot read"),
            "a `cannot read` error means the (nonexistent) file was OPENED before the \
             argv scan ran — the scan must refuse first, and did not here: {err}"
        );
        assert!(
            !err.contains("FORGED") && !err.contains("P1 VERDICT") && !err.contains('\u{1b}'),
            "the refusal must not echo the path it refuses: {err}"
        );
    }

    let clean = dir.join("artifact.json");
    std::fs::write(&clean, base().to_pretty()).expect("write constructed input");
    let (ok, out, err) = run_cli(&["verify-wallclock", clean.to_str().expect("utf-8 path")]);
    assert!(ok, "a clean path must still verify: {err}");
    assert!(out.contains("P1 VERDICT: pass"), "{out}");
}

#[test]
fn the_constructed_input_verifies_through_the_binary() {
    let scratch = ScratchDir::new("synthetic-report");
    let path = scratch.path().join("constructed.json");
    std::fs::write(&path, base().to_pretty()).expect("write constructed input");
    let path = path.to_string_lossy().into_owned();
    let (ok, out, err) = run_cli(&["verify-wallclock", path.as_str()]);
    assert!(ok, "the constructed input must verify\nstderr: {err}");
    assert!(out.contains("operator-observed checks"), "{out}");
    assert!(
        !out.to_lowercase().contains("controls"),
        "the observed checks are never called controls: {out}"
    );
    assert!(out.contains("NON-MINTING"), "{out}");
    assert!(out.contains("P1 VERDICT: pass"), "{out}");
    assert!(out.contains("P2 VERDICT: pass"), "{out}");
    for name in REQUIRED_OBSERVATIONS {
        assert!(out.contains(name), "observation {name} not reported: {out}");
    }
}

#[test]
fn unparseable_bytes_are_refused() {
    assert!(matches!(wallclock::verify("{"), Err(VerifyError::Parse(_))));
}

#[test]
fn a_reserved_key_anywhere_is_refused() {
    for key in RESERVED_KEYS {
        let mut top = base();
        insert(&mut top, &[], key, Json::s("x"));
        assert!(
            matches!(refusal(&top), VerifyError::ReservedKey(d) if d.contains(key)),
            "top-level {key}"
        );

        let mut nested = base();
        insert(&mut nested, &["snapshots", "server"], key, Json::s("x"));
        assert!(
            matches!(refusal(&nested), VerifyError::ReservedKey(d) if d.contains(key)),
            "nested {key}"
        );
    }
}

#[test]
fn an_unknown_top_level_key_is_refused() {
    let mut v = base();
    insert(&mut v, &[], "p2_ratio", Json::Num(1.0));
    assert!(matches!(refusal(&v), VerifyError::Schema(_)));
}

#[test]
fn a_duplicate_key_anywhere_is_refused() {
    let mut top = base();
    insert(&mut top, &[], "run_id", Json::s("synthetic-second-value"));
    assert!(matches!(refusal(&top), VerifyError::Schema(d) if d.contains("duplicate")));

    let mut nested = base();
    insert(
        &mut nested,
        &["snapshots", "client-1"],
        "response_bytes",
        Json::UInt(1),
    );
    assert!(matches!(refusal(&nested), VerifyError::Schema(d) if d.contains("duplicate")));
}

#[test]
fn a_root_level_refusal_names_the_artifact_not_an_empty_path() {
    let whole_artifact_is_a_string = Json::s("synthetic\u{1b}[31mFORGED");
    let e = refusal(&whole_artifact_is_a_string);
    assert!(
        matches!(&e, VerifyError::ControlCharacter(d) if d.contains("the artifact")),
        "{e}"
    );
    assert!(!format!("{e}").contains("` `"), "empty backticks: {e}");

    let mut dup = base();
    insert(&mut dup, &[], "run_id", Json::s("synthetic-second-value"));
    let e = refusal(&dup);
    assert!(
        matches!(&e, VerifyError::Schema(d) if d.contains("in `the artifact`")),
        "{e}"
    );
}

#[test]
fn a_missing_top_level_key_is_refused() {
    for key in [
        "artifact_version",
        "run_id",
        "harness",
        "venue",
        "node_cpu_samples",
        "corpus",
        "timeline",
        "clocks",
        "snapshots",
        "observations",
        "per_client",
    ] {
        let mut v = base();
        remove(&mut v, &[], key);
        assert!(
            matches!(refusal(&v), VerifyError::Schema(d) if d.contains(key)),
            "{key}"
        );
    }
}

#[test]
fn a_negative_number_anywhere_is_refused() {
    for path in [
        vec!["clocks", "0", "clock_a_seconds"],
        vec!["node_cpu_samples", "0", "cpu"],
        vec!["corpus", "changed_subtree_bytes"],
        vec!["snapshots", "server", "request_bytes"],
    ] {
        let mut v = base();
        set(&mut v, &path, Json::Int(-1));
        assert!(
            matches!(refusal(&v), VerifyError::Range(_)),
            "{}",
            path.join(".")
        );
    }
    let mut v = base();
    set(&mut v, &["clocks", "0", "clock_b_seconds"], Json::Num(-0.5));
    assert!(matches!(refusal(&v), VerifyError::Range(_)));
}

#[test]
fn a_non_finite_number_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["clocks", "0", "clock_a_seconds"],
        Json::Num(f64::INFINITY),
    );
    assert!(matches!(refusal(&v), VerifyError::Range(_)));
}

#[test]
fn a_cpu_percentage_above_one_hundred_is_refused() {
    let mut v = base();
    set(&mut v, &["node_cpu_samples", "0", "cpu"], Json::Num(100.1));
    assert!(matches!(refusal(&v), VerifyError::Range(d) if d.contains("cpu")));
}

#[test]
fn an_unlabelled_observation_is_refused() {
    let mut dropped = base();
    let i = observation_index(&dropped, "no_publish").to_string();
    remove(&mut dropped, &["observations", &i], "kind");
    assert!(matches!(refusal(&dropped), VerifyError::Observation(_)));

    let mut relabelled = base();
    let i = observation_index(&relabelled, "no_publish").to_string();
    set(
        &mut relabelled,
        &["observations", &i, "kind"],
        Json::s("recomputation"),
    );
    assert!(matches!(refusal(&relabelled), VerifyError::Observation(_)));
}

#[test]
fn a_missing_required_observation_is_refused() {
    for name in REQUIRED_OBSERVATIONS {
        let mut v = base();
        let i = observation_index(&v, name);
        match at(&mut v, &["observations"]) {
            Json::Arr(items) => {
                items.remove(i);
            }
            _ => panic!("observations is an array"),
        }
        assert!(
            matches!(refusal(&v), VerifyError::Observation(d) if d.contains(name)),
            "{name}"
        );
    }
}

#[test]
fn an_observation_with_an_unknown_outcome_is_refused() {
    let mut v = base();
    let i = observation_index(&v, "no_publish").to_string();
    set(&mut v, &["observations", &i, "outcome"], Json::s("skipped"));
    assert!(matches!(refusal(&v), VerifyError::Observation(_)));
}

#[test]
fn a_failing_observation_is_recorded_not_refused() {
    let mut v = base();
    let i = observation_index(&v, "no_publish").to_string();
    set(&mut v, &["observations", &i, "outcome"], Json::s("fail"));
    let findings = accepted(&v);
    let row = findings
        .observed
        .iter()
        .find(|o| o.name == "no_publish")
        .expect("the row is reported");
    assert_eq!(row.outcome, "fail");
    let report = findings.render("fixture");
    assert!(report.contains("1 failing"), "{report}");
}

#[test]
fn a_client_snapshot_written_by_the_server_kind_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "client-1", "writer_kind"],
        Json::s("granary-server"),
    );
    let error = refusal(&v);
    assert!(
        matches!(&error, VerifyError::Identity(d)
            if d.contains("client-1") && d.contains("written by `granary-server`")),
        "{error}"
    );

    let mut both = base();
    for key in [
        "request_bytes",
        "requests_with_body",
        "response_bytes_produced",
    ] {
        let value = uint(&both, &["snapshots", "server", key]);
        insert(
            &mut both,
            &["snapshots", "client-1"],
            key,
            Json::UInt(value),
        );
    }
    for key in ["drain_outcome", "listen_addr"] {
        let value = text_at(&both, &["snapshots", "server", key]);
        insert(&mut both, &["snapshots", "client-1"], key, Json::s(value));
    }
    set(
        &mut both,
        &["snapshots", "client-1", "writer_kind"],
        Json::s("granary-server"),
    );
    let error = refusal(&both);
    assert!(
        matches!(&error, VerifyError::Identity(d)
            if d.contains("client-1") && d.contains("written by `granary-server`")),
        "{error}"
    );
}

#[test]
fn eleven_empty_run_ids_are_refused() {
    let mut v = base();
    set(&mut v, &["run_id"], Json::s(""));
    for role in ROLES {
        set(&mut v, &["snapshots", role, "run_id"], Json::s(""));
    }
    assert!(matches!(refusal(&v), VerifyError::Identity(_)));
}

#[test]
fn a_snapshot_from_another_run_is_refused() {
    for role in ROLES {
        let mut v = base();
        set(
            &mut v,
            &["snapshots", role, "run_id"],
            Json::s("synthetic-19700101T000000Z-deadbeef"),
        );
        assert!(
            matches!(refusal(&v), VerifyError::Identity(d) if d.contains(role)),
            "{role}"
        );
    }
}

#[test]
fn a_duplicate_role_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "warmup-2", "role"],
        Json::s("warmup-1"),
    );
    assert!(matches!(refusal(&v), VerifyError::Identity(_)));
}

#[test]
fn a_missing_snapshot_is_refused() {
    for role in ROLES {
        let mut v = base();
        remove(&mut v, &["snapshots"], role);
        assert!(
            matches!(refusal(&v), VerifyError::Schema(d) if d.contains(role)),
            "{role}"
        );
    }
}

#[test]
fn a_poisoned_snapshot_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "warmup-verify-3", "poisoned"],
        Json::Bool(true),
    );
    assert!(matches!(refusal(&v), VerifyError::Identity(d) if d.contains("warmup-verify-3")));
}

#[test]
fn a_server_that_did_not_drain_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "server", "drain_outcome"],
        Json::s("deadline-expired"),
    );
    assert!(matches!(refusal(&v), VerifyError::Identity(_)));
}

#[test]
fn a_nonzero_measured_exit_code_is_refused() {
    for which in ["warmup", "warmup_verify", "workload", "clock_a", "clock_b"] {
        let mut v = base();
        set(
            &mut v,
            &["per_client", "0", "exit_codes", which],
            Json::UInt(3),
        );
        assert!(
            matches!(refusal(&v), VerifyError::Identity(d) if d.contains(which)),
            "{which}"
        );
    }
}

#[test]
fn a_client_pinned_at_the_wrong_seq_is_refused() {
    let mut v = base();
    let seq = uint(&v, &["snapshots", "publisher", "publish", "seq"]);
    set(
        &mut v,
        &["snapshots", "client-2", "pinned_seq"],
        Json::UInt(seq + 1),
    );
    assert!(matches!(refusal(&v), VerifyError::Identity(d) if d.contains("client-2")));
}

#[test]
fn a_baseline_pinned_at_the_wrong_seq_is_refused() {
    let mut v = base();
    let seq = uint(&v, &["snapshots", "publisher", "publish", "seq"]);
    set(
        &mut v,
        &["snapshots", "warmup-1", "pinned_seq"],
        Json::UInt(seq),
    );
    assert!(matches!(refusal(&v), VerifyError::Identity(d) if d.contains("warmup-1")));
}

#[test]
fn a_client_endpoint_that_differs_from_the_servers_listen_addr_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "client-3", "endpoint"],
        Json::s("https://127.0.0.1:1"),
    );
    assert!(matches!(refusal(&v), VerifyError::Route(d) if d.contains("client-3")));
}

#[test]
fn a_publisher_that_bypassed_the_server_is_refused() {
    let mut v = base();
    set(&mut v, &["snapshots", "publisher", "endpoint"], Json::Null);
    assert!(matches!(refusal(&v), VerifyError::Route(d) if d.contains("publisher")));
}

#[test]
fn an_observed_subtree_digest_that_differs_from_the_expected_is_refused() {
    for k in 0..3 {
        let mut v = base();
        set(
            &mut v,
            &["per_client", &k.to_string(), "observed_subtree_digest"],
            Json::s("0".repeat(64)),
        );
        assert!(
            matches!(refusal(&v), VerifyError::ContentIdentity(_)),
            "client {k}"
        );
    }
}

#[test]
fn a_baseline_tree_digest_that_differs_from_the_expected_is_refused() {
    for field in [
        "warmup_observed_tree_digest",
        "warmup_verify_observed_tree_digest",
    ] {
        let mut v = base();
        set(&mut v, &["per_client", "1", field], Json::s("0".repeat(64)));
        assert!(
            matches!(refusal(&v), VerifyError::ContentIdentity(d) if d.contains(field)),
            "{field}"
        );
    }
}

#[test]
fn each_of_the_five_nonzero_floors_refuses_at_zero() {
    for path in [
        vec!["snapshots", "server", "request_bytes"],
        vec!["snapshots", "server", "requests_with_body"],
        vec!["snapshots", "client-1", "response_bytes"],
        vec!["snapshots", "publisher", "publish", "novel_bytes"],
        vec!["snapshots", "warmup-1", "response_bytes"],
    ] {
        let mut v = base();
        set(&mut v, &path, Json::UInt(0));
        let last = path.last().copied().unwrap_or_default();
        assert!(
            matches!(refusal(&v), VerifyError::Floor(d) if d.contains(last)),
            "{}",
            path.join(".")
        );
    }
    for role in ["client-2", "client-3", "warmup-2", "warmup-3"] {
        let mut v = base();
        set(
            &mut v,
            &["snapshots", role, "response_bytes"],
            Json::UInt(0),
        );
        assert!(
            matches!(refusal(&v), VerifyError::Floor(d) if d.contains(role)),
            "{role}"
        );
    }
}

#[test]
fn the_under_download_floor_refuses_a_client_below_the_uploaded_bin_bytes() {
    let mut v = base();
    let uploaded = uint(
        &v,
        &["snapshots", "publisher", "publish", "bin_bytes_uploaded"],
    );
    set(
        &mut v,
        &["snapshots", "client-1", "response_bytes"],
        Json::UInt(uploaded - 1),
    );
    assert!(matches!(refusal(&v), VerifyError::Floor(d) if d.contains("bin_bytes_uploaded")));
}

#[test]
fn a_warm_cache_that_was_not_warm_is_refused() {
    let mut v = base();
    let warm = uint(&v, &["snapshots", "warmup-1", "response_bytes"]);
    set(
        &mut v,
        &["snapshots", "warmup-verify-1", "response_bytes"],
        Json::UInt(warm / 50),
    );
    assert!(matches!(refusal(&v), VerifyError::Floor(d) if d.contains("warmup-verify-1")));
}

#[test]
fn a_corpus_under_eight_mebibytes_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["corpus", "apparent_bytes_v_n"],
        Json::UInt(8 * 1024 * 1024 - 1),
    );
    assert!(matches!(refusal(&v), VerifyError::Corpus(d) if d.contains("apparent_bytes_v_n")));
}

#[test]
fn a_delta_fraction_outside_the_band_is_refused() {
    let subtree = uint(&base(), &["corpus", "changed_subtree_bytes"]);
    for novel in [subtree / 1000, subtree / 2] {
        let mut v = base();
        set(
            &mut v,
            &["snapshots", "publisher", "publish", "novel_bytes"],
            Json::UInt(novel),
        );
        assert!(
            matches!(refusal(&v), VerifyError::Corpus(d) if d.contains("delta")),
            "novel {novel}"
        );
    }
}

#[test]
fn client_kind_bytes_above_the_servers_produced_total_are_refused() {
    let mut v = base();
    let produced = uint(&v, &["snapshots", "server", "response_bytes_produced"]);
    set(
        &mut v,
        &["snapshots", "warmup-1", "response_bytes"],
        Json::UInt(produced),
    );
    assert!(matches!(refusal(&v), VerifyError::CrossCheck(_)));
}

#[test]
fn a_timeline_out_of_order_is_refused() {
    let mut v = base();
    let ended = text_at(&v, &["timeline", "publish_ended"]);
    set(&mut v, &["timeline", "warmups_ended"], Json::s(ended));
    assert!(matches!(refusal(&v), VerifyError::Timeline(_)));
}

#[test]
fn two_equal_timeline_stamps_are_refused() {
    let mut v = base();
    let started = text_at(&v, &["timeline", "publish_started"]);
    set(&mut v, &["timeline", "publish_ended"], Json::s(started));
    assert!(matches!(refusal(&v), VerifyError::Timeline(d) if d.contains("strictly")));
}

#[test]
fn a_timeline_stamp_without_millisecond_precision_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["timeline", "publish_started"],
        Json::s("2032-06-15T12:00:20Z"),
    );
    assert!(matches!(refusal(&v), VerifyError::Schema(d) if d.contains("publish_started")));
}

#[test]
fn node_samples_out_of_order_are_refused() {
    let mut v = base();
    let first = text_at(&v, &["node_cpu_samples", "0", "t"]);
    set(&mut v, &["node_cpu_samples", "5", "t"], Json::s(first));
    assert!(matches!(refusal(&v), VerifyError::NodeLoad(d) if d.contains("increasing")));
}

#[test]
fn a_gap_wider_than_fifteen_seconds_is_refused() {
    let mut v = base();
    let window_start = text_at(&v, &["timeline", "warmups_ended"]);
    let window_end = text_at(&v, &["timeline", "server_stopped"]);
    set(
        &mut v,
        &["node_cpu_samples"],
        Json::Arr(vec![
            sample("2032-06-15T11:50:00.000Z", 5.0),
            sample("2032-06-15T12:10:00.000Z", 5.0),
        ]),
    );
    assert!(
        matches!(refusal(&v), VerifyError::NodeLoad(d) if d.contains("apart")),
        "window {window_start}..{window_end}"
    );
}

#[test]
fn samples_that_do_not_cover_the_window_are_refused() {
    let mut v = base();
    let start = text_at(&v, &["timeline", "warmups_ended"]);
    match at(&mut v, &["node_cpu_samples"]) {
        Json::Arr(items) => {
            items.retain(|s| match s.get("t") {
                Some(Json::Str(t)) => t.as_str() > start.as_str(),
                _ => true,
            });
        }
        _ => panic!("node_cpu_samples is an array"),
    }
    assert!(matches!(refusal(&v), VerifyError::NodeLoad(d) if d.contains("cover")));
}

fn sample(t: &str, cpu: f64) -> Json {
    Json::Obj(vec![
        ("t".to_owned(), Json::s(t)),
        ("cpu".to_owned(), Json::Num(cpu)),
    ])
}

#[test]
fn a_node_load_outside_the_rerun_rule_is_refused() {
    for (flat, spike) in [(60.0_f64, 60.0_f64), (10.0, 90.0)] {
        let mut v = base();
        let start = text_at(&v, &["timeline", "warmups_ended"]);
        let end = text_at(&v, &["timeline", "server_stopped"]);
        let mut spiked = false;
        match at(&mut v, &["node_cpu_samples"]) {
            Json::Arr(items) => {
                for s in items.iter_mut() {
                    let Some(Json::Str(t)) = s.get("t") else {
                        panic!("sample without a stamp")
                    };
                    let inside = t.as_str() >= start.as_str() && t.as_str() <= end.as_str();
                    let cpu = if inside && !spiked { spike } else { flat };
                    if inside {
                        spiked = true;
                    }
                    *s = sample(&t.clone(), cpu);
                }
            }
            _ => panic!("node_cpu_samples is an array"),
        }
        assert!(spiked, "the fixture must place a sample inside the window");
        assert!(
            matches!(refusal(&v), VerifyError::NodeLoad(_)),
            "flat {flat} spike {spike}"
        );
    }
}

#[test]
fn padding_outside_the_window_does_not_move_the_statistic() {
    let before = accepted(&base());
    let mut v = base();
    let padded = {
        let mut items = match at(&mut v, &["node_cpu_samples"]) {
            Json::Arr(items) => items.clone(),
            _ => panic!("node_cpu_samples is an array"),
        };
        let mut pad = Vec::new();
        for minute in 0..9 {
            pad.push(sample(&format!("2032-06-15T11:2{minute}:09.000Z"), 0.0));
        }
        pad.append(&mut items);
        for minute in 4..9 {
            pad.push(sample(&format!("2032-06-15T12:5{minute}:59.000Z"), 0.0));
        }
        pad
    };
    let padded_len = padded.len();
    set(&mut v, &["node_cpu_samples"], Json::Arr(padded));
    let after = accepted(&v);
    assert!(
        before.node_cpu_mean > 0.0 && before.node_samples_in_window > 0,
        "a zeroed baseline would make every comparison below vacuous"
    );
    assert!(
        after.node_samples_total > before.node_samples_total,
        "the padding must reach the constructed input"
    );
    assert_eq!(after.node_samples_total, padded_len);
    assert_eq!(after.node_samples_in_window, before.node_samples_in_window);
    assert!(
        (after.node_cpu_mean - before.node_cpu_mean).abs() < 1e-9,
        "padding moved the mean {} -> {}",
        before.node_cpu_mean,
        after.node_cpu_mean
    );
    assert!((after.node_cpu_max - before.node_cpu_max).abs() < 1e-9);
}

#[test]
fn the_recorded_upload_ratio_moves_with_the_servers_request_bytes() {
    let before = accepted(&base());
    assert!(
        before.upload_bytes > 0,
        "the constructed baseline carries a nonzero total"
    );
    assert!(
        before.upload_ratio > 0.0,
        "the constructed baseline carries a nonzero ratio"
    );
    let mut v = base();
    let doubled = before.upload_bytes * 2;
    set(
        &mut v,
        &["snapshots", "server", "request_bytes"],
        Json::UInt(doubled),
    );
    let after = accepted(&v);
    assert_eq!(after.upload_bytes, doubled);
    assert!(
        after.upload_ratio > before.upload_ratio,
        "the ratio did not move at all"
    );
    assert!(
        (after.upload_ratio - before.upload_ratio * 2.0).abs() < 1e-9,
        "ratio {} did not follow the input (was {})",
        after.upload_ratio,
        before.upload_ratio
    );
}

#[test]
fn a_failing_p2_is_a_record_not_a_refusal() {
    let mut v = base();
    let novel = uint(&v, &["snapshots", "publisher", "publish", "novel_bytes"]);
    set(
        &mut v,
        &["snapshots", "server", "request_bytes"],
        Json::UInt(novel * 3 + 1),
    );
    let findings = accepted(&v);
    assert_eq!(findings.p2, Verdict::Fail);
    assert_eq!(findings.p1, Verdict::Pass);
    assert!(findings.render("fixture").contains("P2 VERDICT: fail"));
}

#[test]
fn a_failing_p1_is_a_record_not_a_refusal() {
    let mut v = base();
    set(
        &mut v,
        &["clocks", "1", "clock_a_seconds"],
        Json::Num(30.001),
    );
    let findings = accepted(&v);
    assert_eq!(findings.p1, Verdict::Fail);
    assert_eq!(findings.p2, Verdict::Pass);
    assert!(findings.render("fixture").contains("P1 VERDICT: fail"));
}

#[test]
fn constructed_snapshots_parse_and_a_missing_field_is_refused() {
    let mut fixture = base();
    let cases: [(&str, &[&str]); 2] = [
        (
            "server",
            &[
                "format_version",
                "writer_kind",
                "run_id",
                "role",
                "poisoned",
                "request_bytes",
                "requests_with_body",
                "response_bytes_produced",
                "drain_outcome",
                "listen_addr",
            ],
        ),
        (
            "client-1",
            &[
                "format_version",
                "writer_kind",
                "run_id",
                "role",
                "poisoned",
                "response_bytes",
                "endpoint",
                "pinned_seq",
            ],
        ),
    ];
    for (relative, required) in cases {
        let golden = at(&mut fixture, &["snapshots", relative]).clone();
        Snapshot::from_json(&golden).unwrap_or_else(|e| panic!("{relative}: {e}"));
        for field in required {
            let mut damaged = golden.clone();
            remove(&mut damaged, &[], field);
            assert!(
                Snapshot::from_json(&damaged).is_err(),
                "{relative}: a snapshot missing `{field}` must be refused"
            );
        }
    }
}

fn novel() -> u64 {
    uint(
        &base(),
        &["snapshots", "publisher", "publish", "novel_bytes"],
    )
}

fn insert_sample(value: &mut Json, t: &str, cpu: f64) {
    match at(value, &["node_cpu_samples"]) {
        Json::Arr(items) => {
            let pos = items
                .iter()
                .position(|s| matches!(s.get("t"), Some(Json::Str(x)) if x.as_str() > t))
                .unwrap_or(items.len());
            items.insert(pos, sample(t, cpu));
        }
        _ => panic!("node_cpu_samples is an array"),
    }
}

fn set_every_sample_inside(value: &mut Json, mut cpu: impl FnMut(usize) -> f64) {
    let start = text_at(value, &["timeline", "warmups_ended"]);
    let end = text_at(value, &["timeline", "server_stopped"]);
    let mut n = 0;
    match at(value, &["node_cpu_samples"]) {
        Json::Arr(items) => {
            for s in items.iter_mut() {
                let Some(Json::Str(t)) = s.get("t") else {
                    panic!("sample without a stamp")
                };
                if t.as_str() >= start.as_str() && t.as_str() <= end.as_str() {
                    let t = t.clone();
                    *s = sample(&t, cpu(n));
                    n += 1;
                }
            }
        }
        _ => panic!("node_cpu_samples is an array"),
    }
    assert!(n > 0, "no sample inside the window");
}

fn day_of(stamp: &str) -> String {
    stamp
        .get(..10)
        .unwrap_or_else(|| panic!("`{stamp}` carries no date"))
        .to_owned()
}

fn time_ms(stamp: &str) -> i64 {
    let part = |from: usize, to: usize| -> i64 {
        stamp
            .get(from..to)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or_else(|| panic!("`{stamp}` is not a millisecond stamp"))
    };
    ((part(11, 13) * 60 + part(14, 16)) * 60 + part(17, 19)) * 1000 + part(20, 23)
}

fn stamp_of(day: &str, ms: i64) -> String {
    assert!(
        (0..86_400_000).contains(&ms),
        "these rows do not cross midnight"
    );
    format!(
        "{day}T{:02}:{:02}:{:02}.{:03}Z",
        ms / 3_600_000,
        (ms / 60_000) % 60,
        (ms / 1000) % 60,
        ms % 1000
    )
}

#[test]
fn p2_fails_when_a_client_download_exceeds_the_budget() {
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "client-1", "response_bytes"],
        Json::UInt(3 * novel() + 1),
    );
    let f = accepted(&v);
    assert_eq!(f.p2, Verdict::Fail);
    assert_eq!(f.p1, Verdict::Pass);
}

#[test]
fn p1_fails_when_clock_b_exceeds_sixty_seconds() {
    let mut v = base();
    set(
        &mut v,
        &["clocks", "0", "clock_b_seconds"],
        Json::Num(60.001),
    );
    let f = accepted(&v);
    assert_eq!(f.p1, Verdict::Fail);
    assert_eq!(f.p2, Verdict::Pass);
}

#[test]
fn the_pre_registered_limits_are_inclusive_and_the_multiple_is_three() {
    let n = novel();
    let mut v = base();
    set(&mut v, &["clocks", "0", "clock_a_seconds"], Json::Num(30.0));
    assert_eq!(accepted(&v).p1, Verdict::Pass, "clock A == 30.0 s passes");

    let mut v = base();
    set(&mut v, &["clocks", "0", "clock_b_seconds"], Json::Num(60.0));
    assert_eq!(accepted(&v).p1, Verdict::Pass, "clock B == 60.0 s passes");

    let mut v = base();
    set(
        &mut v,
        &["snapshots", "server", "request_bytes"],
        Json::UInt(3 * n),
    );
    let f = accepted(&v);
    assert_eq!(f.p2, Verdict::Pass, "upload == 3x novel passes");
    assert_eq!(f.p2_budget_bytes, 3 * n, "the budget is exactly 3x novel");

    let mut v = base();
    set(
        &mut v,
        &["snapshots", "client-1", "response_bytes"],
        Json::UInt(3 * n),
    );
    assert_eq!(
        accepted(&v).p2,
        Verdict::Pass,
        "download == 3x novel passes"
    );
}

#[test]
fn a_reserved_key_inside_the_publish_summary_is_refused() {
    let mut v = base();
    insert(
        &mut v,
        &["snapshots", "publisher", "publish"],
        "digest",
        Json::s("x"),
    );
    assert!(matches!(refusal(&v), VerifyError::ReservedKey(d) if d.contains("publish.digest")));
}

#[test]
fn an_unknown_key_in_every_nested_closed_block_is_refused() {
    let blocks: [&[&str]; 9] = [
        &["corpus"],
        &["timeline"],
        &["harness"],
        &["venue"],
        &["clocks", "0"],
        &["per_client", "0"],
        &["per_client", "0", "exit_codes"],
        &["per_client", "0", "seq_given"],
        &["node_cpu_samples", "0"],
    ];
    for block in blocks {
        let mut v = base();
        insert(&mut v, block, "extra_unknown", Json::UInt(1));
        let e = refusal(&v);
        assert!(
            matches!(&e, VerifyError::Schema(d) if d.contains("unknown key `extra_unknown`")),
            "{}: {e}",
            block.join(".")
        );
    }
    let mut v = base();
    let mut extra = base();
    let extra = at(&mut extra, &["snapshots", "client-3"]).clone();
    insert(&mut v, &["snapshots"], "client-4", extra);
    assert!(matches!(refusal(&v), VerifyError::Schema(d) if d.contains("unknown key `client-4`")));
    let mut v = base();
    insert(
        &mut v,
        &["observations", "0"],
        "extra_unknown",
        Json::UInt(1),
    );
    assert!(matches!(refusal(&v), VerifyError::Observation(d) if d.contains("unknown key")));
}

#[test]
fn a_version_other_than_one_is_refused() {
    let mut v = base();
    set(&mut v, &["artifact_version"], Json::UInt(2));
    assert!(matches!(refusal(&v), VerifyError::Schema(d) if d.contains("artifact_version")));
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "server", "format_version"],
        Json::UInt(2),
    );
    assert!(matches!(refusal(&v), VerifyError::Schema(d) if d.contains("format_version")));
}

#[test]
fn a_duplicate_key_in_the_bytes_is_refused() {
    let text = base().to_pretty();
    let i = text.find("\"client-1\": {").expect("client-1");
    let j = text
        .get(i..)
        .and_then(|t| t.find("\"pinned_seq\": 2"))
        .expect("pinned_seq")
        + i;
    let head = text.get(..j).expect("head");
    let tail = text.get(j..).expect("tail");
    let dup = format!("{head}\"pinned_seq\": 2,\n      {tail}");
    assert!(
        matches!(wallclock::verify(&dup), Err(VerifyError::Schema(d)) if d.contains("duplicate key `pinned_seq`"))
    );
}

#[test]
fn a_baseline_on_the_wrong_endpoint_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "warmup-2", "endpoint"],
        Json::s("https://127.0.0.1:1"),
    );
    assert!(matches!(refusal(&v), VerifyError::Route(d) if d.contains("warmup-2")));
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "warmup-verify-3", "endpoint"],
        Json::Null,
    );
    assert!(matches!(refusal(&v), VerifyError::Route(d) if d.contains("warmup-verify-3")));
}

#[test]
fn a_warmup_verify_pinned_at_the_wrong_seq_is_refused() {
    let mut v = base();
    let seq = uint(&v, &["snapshots", "publisher", "publish", "seq"]);
    set(
        &mut v,
        &["snapshots", "warmup-verify-1", "pinned_seq"],
        Json::UInt(seq),
    );
    assert!(matches!(refusal(&v), VerifyError::Identity(d) if d.contains("warmup-verify-1")));
}

#[test]
fn the_cross_crate_bound_counts_every_client_kind_snapshot_and_is_inclusive() {
    let b = base();
    let total: u64 = [
        "publisher",
        "client-1",
        "client-2",
        "client-3",
        "warmup-1",
        "warmup-2",
        "warmup-3",
        "warmup-verify-1",
        "warmup-verify-2",
        "warmup-verify-3",
    ]
    .iter()
    .map(|r| uint(&b, &["snapshots", r, "response_bytes"]))
    .sum();
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "server", "response_bytes_produced"],
        Json::UInt(total - 1),
    );
    assert!(matches!(refusal(&v), VerifyError::CrossCheck(_)));
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "server", "response_bytes_produced"],
        Json::UInt(total),
    );
    assert_eq!(accepted(&v).client_kind_response_total, total);
}

#[test]
fn the_node_load_limits_are_inclusive_and_pinned() {
    let mut v = base();
    set_every_sample_inside(&mut v, |_| 40.0);
    assert!(
        (accepted(&v).node_cpu_mean - 40.0).abs() < 1e-9,
        "mean == 40 passes"
    );
    let mut v = base();
    set_every_sample_inside(&mut v, |_| 45.0);
    assert!(
        matches!(refusal(&v), VerifyError::NodeLoad(_)),
        "mean 45 is refused"
    );
    let mut v = base();
    set_every_sample_inside(&mut v, |i| if i == 0 { 70.0 } else { 10.0 });
    assert!(
        (accepted(&v).node_cpu_max - 70.0).abs() < 1e-9,
        "max == 70 passes"
    );
    for spike in [70.001, 75.0] {
        let mut v = base();
        set_every_sample_inside(&mut v, |i| if i == 0 { spike } else { 10.0 });
        assert!(
            matches!(refusal(&v), VerifyError::NodeLoad(_)),
            "max {spike} is refused"
        );
    }
}

#[test]
fn the_sample_gap_bound_is_inclusive_at_fifteen_seconds() {
    for (shifted, ok) in [
        ("2032-06-15T12:01:05.000Z", true),
        ("2032-06-15T12:01:05.001Z", false),
    ] {
        let mut v = base();
        match at(&mut v, &["node_cpu_samples"]) {
            Json::Arr(items) => {
                let s = items
                    .iter_mut()
                    .find(|s| s.get("t") == Some(&Json::s("2032-06-15T12:01:00.000Z")))
                    .expect("the 12:01:00 sample");
                *s = sample(shifted, 30.0);
            }
            _ => panic!("array"),
        }
        if ok {
            assert!((accepted(&v).node_max_gap_seconds - 15.0).abs() < 1e-9);
        } else {
            assert!(matches!(refusal(&v), VerifyError::NodeLoad(d) if d.contains("15001")));
        }
    }
}

#[test]
fn the_corpus_floor_is_inclusive_at_eight_mebibytes() {
    let mut v = base();
    set(
        &mut v,
        &["corpus", "apparent_bytes_v_n"],
        Json::UInt(8 * 1024 * 1024),
    );
    accepted(&v);
}

#[test]
fn the_delta_band_is_inclusive_at_both_ends() {
    let subtree = uint(&base(), &["corpus", "changed_subtree_bytes"]);
    let low = subtree.div_ceil(100);
    let high = 3 * subtree / 10;
    for (novel, ok) in [
        (low, true),
        (low - 1, false),
        (high, true),
        (high + 1, false),
    ] {
        let mut v = base();
        set(
            &mut v,
            &["snapshots", "publisher", "publish", "novel_bytes"],
            Json::UInt(novel),
        );
        if ok {
            accepted(&v);
        } else {
            assert!(
                matches!(refusal(&v), VerifyError::Corpus(d) if d.contains("delta")),
                "{novel}"
            );
        }
    }
}

#[test]
fn the_cold_warm_multiple_is_one_hundred_and_inclusive() {
    let cold = uint(&base(), &["snapshots", "warmup-1", "response_bytes"]);
    for (warm, ok) in [
        (cold / 100, true),
        (cold / 100 + 1, false),
        (cold / 80, false),
    ] {
        let mut v = base();
        set(
            &mut v,
            &["snapshots", "warmup-verify-1", "response_bytes"],
            Json::UInt(warm),
        );
        if ok {
            accepted(&v);
        } else {
            assert!(
                matches!(refusal(&v), VerifyError::Floor(d) if d.contains("warmup-verify-1")),
                "{warm}"
            );
        }
    }
}

#[test]
fn the_under_download_floor_is_inclusive() {
    let mut v = base();
    let uploaded = uint(
        &v,
        &["snapshots", "publisher", "publish", "bin_bytes_uploaded"],
    );
    set(
        &mut v,
        &["snapshots", "client-1", "response_bytes"],
        Json::UInt(uploaded),
    );
    accepted(&v);
}

#[test]
fn a_sample_on_a_window_edge_is_inside_the_window() {
    let first = text_at(&base(), &["timeline", "warmups_ended"]);
    let last = text_at(&base(), &["timeline", "server_stopped"]);
    let before = accepted(&base());

    for edge in [&first, &last] {
        let mut v = base();
        insert_sample(&mut v, edge, 100.0);
        assert!(
            matches!(refusal(&v), VerifyError::NodeLoad(d) if d.contains("max 100.00")),
            "a 100 % sample at {edge} must enter the maximum"
        );
        let mut v = base();
        insert_sample(&mut v, edge, 0.0);
        let f = accepted(&v);
        assert_eq!(f.node_samples_in_window, before.node_samples_in_window + 1);
        assert!(
            f.node_cpu_mean < before.node_cpu_mean,
            "an idle edge sample lowers the mean"
        );
    }

    let mut v = base();
    match at(&mut v, &["node_cpu_samples"]) {
        Json::Arr(items) => items
            .retain(|s| matches!(s.get("t"), Some(Json::Str(t)) if t.as_str() > first.as_str())),
        _ => panic!("array"),
    }
    insert_sample(&mut v, &first, 20.0);
    assert_eq!(
        accepted(&v).node_samples_in_window,
        before.node_samples_in_window + 1,
        "a sample AT the first stamp covers the window and enters the statistic"
    );
}

#[test]
fn a_clock_a_that_never_polled_is_refused() {
    for field in ["clock_a_polls", "clock_a_poll_bytes"] {
        for k in 0..3 {
            let mut v = base();
            set(&mut v, &["clocks", &k.to_string(), field], Json::UInt(0));
            assert!(
                matches!(refusal(&v), VerifyError::Floor(d) if d.contains(field)),
                "client {k} {field}"
            );
        }
    }
    let mut v = base();
    for k in 0..3 {
        for field in ["clock_a_polls", "clock_a_poll_bytes"] {
            set(&mut v, &["clocks", &k.to_string(), field], Json::UInt(0));
        }
    }
    assert!(matches!(refusal(&v), VerifyError::Floor(_)));
}

#[test]
fn a_clock_seconds_field_below_the_render_precision_is_refused() {
    for field in ["clock_a_seconds", "clock_b_seconds"] {
        for k in 0..3 {
            for value in [0.0, 0.0004, 0.0009] {
                let mut v = base();
                set(&mut v, &["clocks", &k.to_string(), field], Json::Num(value));
                assert!(
                    matches!(refusal(&v), VerifyError::Floor(d) if d.contains(field)),
                    "client {k} {field} = {value}"
                );
            }
        }
    }
}

#[test]
fn the_clock_seconds_floor_is_0_001s_inclusive() {
    for field in ["clock_a_seconds", "clock_b_seconds"] {
        let mut below = base();
        set(&mut below, &["clocks", "0", field], Json::Num(0.0009));
        assert!(
            matches!(refusal(&below), VerifyError::Floor(d) if d.contains(field)),
            "{field} at 0.0009 must refuse"
        );

        let mut at_floor = base();
        set(&mut at_floor, &["clocks", "0", field], Json::Num(0.001));
        accepted(&at_floor);
    }
}

#[test]
fn an_under_download_floor_with_a_zero_denominator_is_refused() {
    let mut v = base();
    set(
        &mut v,
        &["snapshots", "publisher", "publish", "bin_bytes_uploaded"],
        Json::UInt(0),
    );
    set(
        &mut v,
        &["snapshots", "client-1", "response_bytes"],
        Json::UInt(1),
    );
    assert!(matches!(refusal(&v), VerifyError::Floor(d) if d.contains("bin_bytes_uploaded")));
}

#[test]
fn an_endpoint_given_that_disagrees_with_the_clients_snapshot_is_refused() {
    for k in 0..3 {
        let mut v = base();
        set(
            &mut v,
            &["per_client", &k.to_string(), "endpoint_given"],
            Json::s("https://127.0.0.1:1"),
        );
        assert!(
            matches!(refusal(&v), VerifyError::Route(d) if d.contains("endpoint_given")),
            "client {k}"
        );
    }
}

#[test]
fn a_seq_given_that_disagrees_with_the_clients_pinned_seq_is_refused() {
    for k in 0..3 {
        let mut v = base();
        set(
            &mut v,
            &["per_client", &k.to_string(), "seq_given", "workload"],
            Json::UInt(u64::MAX),
        );
        assert!(
            matches!(refusal(&v), VerifyError::Identity(d) if d.contains("seq_given")),
            "client {k}"
        );
    }
}

#[test]
fn a_seq_given_warmup_that_disagrees_with_the_clients_pinned_seq_is_refused() {
    for k in 0..3 {
        let mut v = base();
        set(
            &mut v,
            &["per_client", &k.to_string(), "seq_given", "warmup"],
            Json::UInt(u64::MAX),
        );
        assert!(
            matches!(refusal(&v), VerifyError::Identity(d) if d.contains("seq_given.warmup")),
            "client {k}"
        );
    }
}

#[test]
fn too_few_samples_inside_the_window_are_refused() {
    let b = base();
    let start = text_at(&b, &["timeline", "warmups_ended"]);
    let end = text_at(&b, &["timeline", "server_stopped"]);
    let day = day_of(&start);
    let (first, last) = (time_ms(&start), time_ms(&end));
    assert_eq!(
        last - first,
        139_500,
        "the constructed window must match the sampling offsets"
    );
    let want = (last - first) / 12_000;
    assert!(want >= 3, "the window must demand more than a handful");

    let series = |offsets: &[i64]| -> Json {
        Json::Arr(
            offsets
                .iter()
                .map(|ms| sample(&stamp_of(&day, first + ms), 5.0))
                .collect(),
        )
    };

    let refuse_offsets: Vec<i64> = vec![
        -1_000, 13_000, 27_000, 41_000, 55_000, 69_000, 83_000, 97_000, 111_000, 125_000, 139_000,
        153_000,
    ];
    let mut v = base();
    set(&mut v, &["node_cpu_samples"], series(&refuse_offsets));
    let e = refusal(&v);
    assert!(
        matches!(&e, VerifyError::NodeLoad(d) if d.contains("inside the run window")),
        "{e}"
    );
    assert!(
        !format!("{e}").contains("apart"),
        "the fixture must fail on the COUNT, not on the spacing: {e}"
    );

    let mut accept_offsets = refuse_offsets.clone();
    accept_offsets.insert(accept_offsets.len() - 1, last - first);
    let mut v = base();
    set(&mut v, &["node_cpu_samples"], series(&accept_offsets));
    let f = accepted(&v);
    assert_eq!(
        i64::try_from(f.node_samples_in_window).unwrap_or(-1),
        want,
        "one more sample is the whole difference"
    );
}

#[test]
fn a_uniform_eleven_second_cadence_is_accepted_and_a_sparser_series_is_still_refused() {
    let b = base();
    let start = text_at(&b, &["timeline", "warmups_ended"]);
    let end = text_at(&b, &["timeline", "server_stopped"]);
    let day = day_of(&start);
    let (first, last) = (time_ms(&start), time_ms(&end));
    assert_eq!(
        last - first,
        139_500,
        "the constructed window must match the sampling offsets"
    );

    let series = |offsets: &[i64]| -> Json {
        Json::Arr(
            offsets
                .iter()
                .map(|ms| sample(&stamp_of(&day, first + ms), 5.0))
                .collect(),
        )
    };

    let cadence: Vec<i64> = (0..14).map(|step| -3_000 + step * 11_000).collect();
    let mut v = base();
    set(&mut v, &["node_cpu_samples"], series(&cadence));
    let findings = accepted(&v);
    assert_eq!(
        findings.node_samples_in_window, 12,
        "the executed counterexample holds twelve in-window samples"
    );

    let sparse: Vec<i64> = vec![
        -100, 13_900, 27_900, 41_900, 55_900, 69_900, 83_900, 97_900, 111_900, 125_900, 139_954,
    ];
    let mut v = base();
    set(&mut v, &["node_cpu_samples"], series(&sparse));
    let e = refusal(&v);
    assert!(
        matches!(&e, VerifyError::NodeLoad(d) if d.contains("inside the run window")),
        "{e}"
    );
    assert!(
        !format!("{e}").contains("apart"),
        "the sparser fixture must fail on the COUNT, not on the spacing: {e}"
    );
}

#[test]
fn a_window_with_no_in_window_sample_at_all_is_refused() {
    let mut v = base();
    let day = day_of(&text_at(&v, &["timeline", "warmups_ended"]));
    let start_ms = 40_000_i64;
    let keys = [
        "warmups_ended",
        "delta_generated",
        "publish_started",
        "publish_ended",
        "workloads_started",
        "workloads_ended",
        "server_stopped",
    ];
    for (offset, key) in keys.iter().enumerate() {
        let ms = start_ms + i64::try_from(offset).expect("small offset");
        set(&mut v, &["timeline", key], Json::s(stamp_of(&day, ms)));
    }
    let last_ms = start_ms + i64::try_from(keys.len() - 1).expect("small len");
    set(
        &mut v,
        &["node_cpu_samples"],
        Json::Arr(vec![
            sample(&stamp_of(&day, start_ms - 1), 5.0),
            sample(&stamp_of(&day, last_ms + 1), 5.0),
        ]),
    );
    let e = refusal(&v);
    assert!(
        matches!(&e, VerifyError::NodeLoad(d) if d.contains("computed over nothing")),
        "{e}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one control-character class, one refusal path, walked through every site that \
              interpolates an artifact string — a key, a value, an observation detail, the \
              escape that rewrites, DEL/C1, every reordering point and the discriminating \
              accept; splitting it would scatter one class's coverage across many functions"
)]
fn a_control_character_in_an_artifact_string_is_refused() {
    for path in [
        vec!["run_id"],
        vec!["venue", "node"],
        vec!["harness", "script"],
        vec!["corpus", "changed_subtree"],
        vec!["snapshots", "server", "listen_addr"],
        vec!["snapshots", "server", "drain_outcome"],
    ] {
        let mut v = base();
        let original = text_at(&v, &path);
        set(
            &mut v,
            &path,
            Json::s(format!("{original}\nP1 VERDICT: fail\nFORGED")),
        );
        let e = refusal(&v);
        assert!(
            matches!(&e, VerifyError::ControlCharacter(d) if d.contains(&path.join("."))),
            "{}: {e}",
            path.join(".")
        );
        assert!(
            !format!("{e}").contains("FORGED"),
            "the refusal must not echo the payload it refuses: {e}"
        );
    }

    let mut v = base();
    set(
        &mut v,
        &["venue", "node"],
        Json::s("fixture-node\u{1b}[2J\u{1b}[H\u{1b}[31mALL CHECKS FAILED"),
    );
    let e = refusal(&v);
    assert!(
        matches!(&e, VerifyError::ControlCharacter(d) if d.contains("U+001B")),
        "{e}"
    );

    for (point, name) in [('\u{7f}', "DEL"), ('\u{85}', "NEL"), ('\u{9b}', "CSI")] {
        let mut v = base();
        set(
            &mut v,
            &["venue", "node"],
            Json::s(format!("fixture-node{point}gone")),
        );
        let e = refusal(&v);
        assert!(
            matches!(&e, VerifyError::ControlCharacter(d)
                if d.contains(&format!("U+{:04X}", u32::from(point)))),
            "{name}: {e}"
        );
    }

    let mut v = base();
    let i = observation_index(&v, "no_publish").to_string();
    set(
        &mut v,
        &["observations", &i, "detail"],
        Json::s("ok\r\n  fail  no_publish"),
    );
    assert!(matches!(refusal(&v), VerifyError::ControlCharacter(_)));

    let mut v = base();
    insert(
        &mut v,
        &["snapshots", "server"],
        "unknown\u{1b}[31m",
        Json::UInt(1),
    );
    let e = refusal(&v);
    assert!(matches!(&e, VerifyError::ControlCharacter(_)), "{e}");
    assert!(
        !format!("{e}").contains('\u{1b}'),
        "the key refusal carried its own payload"
    );

    let mut v = base();
    for _ in 0..2 {
        insert(
            &mut v,
            &["snapshots", "server"],
            "dup\u{1b}[31m",
            Json::UInt(1),
        );
    }
    let e = refusal(&v);
    assert!(
        !format!("{e}").contains('\u{1b}'),
        "the duplicate refusal carried the payload: {e:?}"
    );

    let canonical = {
        let mut c = [
            '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
            '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{2028}', '\u{2029}',
        ];
        c.sort_unstable();
        c
    };
    let mut actual = REORDERING;
    actual.sort_unstable();
    assert_eq!(
        actual, canonical,
        "REORDERING must be exactly the complete Unicode bidirectional control set \
         (061C, 200E-200F, 202A-202E, 2066-2069) plus the two line separators \
         (2028-2029) — nothing more, nothing fewer, nothing swapped for another point"
    );

    for point in REORDERING {
        assert!(
            !point.is_control(),
            "U+{:04X} is `Cc`; this table exists for the points \
             `char::is_control` does NOT see, and a `Cc` member here would \
             be redundant with that check rather than closing a gap in it",
            u32::from(point)
        );
        let mut v = base();
        set(
            &mut v,
            &["venue", "node"],
            Json::s(format!("fixture-node{point}liaf :TCIDREV 1P")),
        );
        let e = refusal(&v);
        assert!(
            matches!(&e, VerifyError::ControlCharacter(_)),
            "U+{:04X}: {e}",
            u32::from(point)
        );
    }

    let mut v = base();
    set(
        &mut v,
        &["venue", "node"],
        Json::s("fixture-node P1 VERDICT: fail"),
    );
    accepted(&v);
}

#[test]
fn an_impossible_calendar_date_is_refused() {
    for bad in [
        "2026-02-31T22:49:32.032Z",
        "2026-02-30T22:49:32.032Z",
        "2026-04-31T22:49:32.032Z",
        "2026-06-31T22:49:32.032Z",
        "2026-09-31T22:49:32.032Z",
        "2026-11-31T22:49:32.032Z",
        "2025-02-29T22:49:32.032Z",
        "1900-02-29T22:49:32.032Z",
        "2026-01-00T22:49:32.032Z",
    ] {
        let mut v = base();
        set(&mut v, &["timeline", "warmups_ended"], Json::s(bad));
        assert!(
            matches!(refusal(&v), VerifyError::Schema(d)
                if d.contains("warmups_ended") && d.contains("is not a")),
            "{bad}"
        );
    }
    for good in [
        "2026-02-28T22:49:32.032Z",
        "2024-02-29T22:49:32.032Z",
        "2000-02-29T22:49:32.032Z",
        "2026-01-31T22:49:32.032Z",
    ] {
        let mut v = base();
        set(&mut v, &["timeline", "warmups_ended"], Json::s(good));
        let e = refusal(&v);
        assert!(
            !format!("{e}").contains("is not a `YYYY"),
            "{good} is a real date: {e}"
        );
    }
}

#[test]
fn a_hundred_thousand_keys_in_one_object_do_not_hang_the_scan() {
    let mut v = base();
    let mut extra: Vec<(String, Json)> = (0..100_000u32)
        .map(|i| (format!("k{i}"), Json::UInt(u64::from(i))))
        .collect();
    extra.push(("k0".to_owned(), Json::UInt(0)));
    match at(&mut v, &["snapshots", "server"]) {
        Json::Obj(fields) => fields.append(&mut extra),
        _ => panic!("the server snapshot is an object"),
    }
    assert!(matches!(refusal(&v), VerifyError::Schema(d) if d.contains("duplicate key `k0`")));
}

fn observation(name: &str) -> Json {
    Json::Obj(vec![
        ("kind".to_owned(), Json::s("observation")),
        ("name".to_owned(), Json::s(name)),
        ("outcome".to_owned(), Json::s("pass")),
        ("detail".to_owned(), Json::s("constructed observation")),
    ])
}

#[test]
fn a_hundred_thousand_observations_do_not_hang_the_scan() {
    let mut v = base();
    let mut extra: Vec<Json> = (0..100_000u32)
        .map(|i| observation(&format!("synthetic-{i}")))
        .collect();
    extra.push(observation("synthetic-0"));
    match at(&mut v, &["observations"]) {
        Json::Arr(items) => items.append(&mut extra),
        _ => panic!("observations is an array"),
    }
    assert!(
        matches!(refusal(&v), VerifyError::Observation(d) if d.contains("synthetic-0") && d.contains("appears twice")),
    );
}

#[cfg(unix)]
#[test]
fn a_non_utf8_argument_to_verify_wallclock_is_refused_without_a_panic() {
    use std::os::unix::ffi::OsStrExt;

    let bad = std::ffi::OsStr::from_bytes(b"/tmp/artifact\xffjson");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_granary-bench"))
        .arg("verify-wallclock")
        .arg(bad)
        .output()
        .expect("spawn granary-bench");
    assert_ne!(
        out.status.code(),
        Some(101),
        "101 is rustc's panic exit code — the process must not have panicked"
    );
    assert!(
        !out.status.success(),
        "a non-UTF-8 argument must be refused"
    );
    assert!(out.stdout.is_empty(), "nothing should print to stdout");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked"), "must not panic: {err}");
    assert!(
        !err.contains("unwrap"),
        "must not be an unwrap panic: {err}"
    );
    assert!(err.contains("not valid UTF-8"), "{err}");
    assert!(
        err.contains("argv[2]"),
        "argument 2 (after the binary and the subcommand) is the bad one: {err}"
    );
}

#[cfg(unix)]
#[test]
fn a_non_utf8_argument_to_a_different_subcommand_does_not_panic_either() {
    use std::os::unix::ffi::OsStrExt;

    let bad = std::ffi::OsStr::from_bytes(b"--machine\xffx1");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_granary-bench"))
        .arg("control")
        .arg(bad)
        .output()
        .expect("spawn granary-bench");
    assert_ne!(out.status.code(), Some(101), "must not panic: exit 101");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked"), "must not panic: {err}");
    assert!(err.contains("not valid UTF-8"), "{err}");
}
