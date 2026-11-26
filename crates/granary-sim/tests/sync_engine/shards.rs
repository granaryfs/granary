// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![expect(clippy::unwrap_used, reason = "checked simulator fixture invariants")]

use super::{Fixture, cuts};
use granary_client::{FaultAction, SyncOptions, SyncTarget};
use granary_core::{binmap, binstore::BinStore, hash::GrainId};

fn width(fixture: &Fixture, bytes: &[u8]) -> u8 {
    fixture
        .runtime
        .run(42, 100_000, async {
            let root = granary_core::root::decode_root(bytes).unwrap();
            binmap::decode_binmap_index(
                &fixture
                    .remote
                    .objects
                    .get_meta("v", &root.binmap_index)
                    .await
                    .unwrap(),
            )
            .unwrap()
            .prefix_bits
        })
        .unwrap()
        .0
}

#[test]
fn shard_scenarios_pin_width_and_dedup() {
    let mut cases = 0;
    for (case, want_width) in [("multi", 8), ("divergent", 0), ("fallback", 4)] {
        let fixture = Fixture::with_case(case);
        let stage = fixture.create("file", b"process boundary");
        assert!(fixture.sync(42, stage).0.is_ok(), "{case}");
        assert_eq!(width(&fixture, &fixture.registered()), want_width);
        fixture.assert_file(&fixture.registered(), "file", b"process boundary");
        assert_eq!(
            fixture.engine.binmap_exhaustion_counts().unwrap(),
            if case == "fallback" { (1, 0) } else { (0, 0) }
        );
        if case == "fallback" {
            assert!(fixture.sync(42, stage).0.is_ok());
            assert_eq!(fixture.engine.binmap_exhaustion_counts().unwrap(), (1, 1));
        }
        cases += 1;
    }
    let fixture = Fixture::with_case("multi");
    let before = granary_core::root::decode_root(&fixture.base)
        .unwrap()
        .binmap_index;
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.trace_sync();
    fixture
        .runtime
        .run(42, 100_000, async {
            fixture
                .engine
                .sync(SyncTarget::Tree, SyncOptions::default())
                .wait()
                .await
                .unwrap();
        })
        .unwrap();
    assert_eq!(
        granary_core::root::decode_root(&fixture.registered())
            .unwrap()
            .binmap_index,
        before
    );
    assert!(
        !faults
            .sync_fired()
            .iter()
            .any(|event| event.object_kind == "binmap")
    );
    assert_eq!(cases, 3);
}

#[test]
fn metadata_shard_multi_route_faults_and_cuts() {
    metadata_shard_case("multi", 4);
}
#[test]
fn metadata_shard_divergent_faults_and_cuts() {
    metadata_shard_case("divergent", 3);
}
#[test]
fn metadata_shard_fallback_faults_and_cuts() {
    metadata_shard_case("fallback", 18);
}
#[test]
fn metadata_shard_dedup_faults_and_cuts() {
    metadata_shard_case("dedup", 0);
}

#[expect(
    clippy::too_many_lines,
    reason = "one discovered tuple corpus pairs injected failures, process cuts and disarmed controls"
)]
fn metadata_shard_case(case: &str, want: usize) {
    let mut cases = 0;
    {
        let discovery = Fixture::with_case(case);
        let stage = if case == "dedup" {
            0
        } else {
            discovery.create("file", b"process boundary")
        };
        let trace = discovery.store.lock().unwrap().fault_control();
        trace.trace_sync();
        if case == "dedup" {
            discovery.sync_tree(42).0.unwrap();
        } else {
            discovery.sync(42, stage).0.unwrap();
        }
        let rows: Vec<_> = trace
            .sync_fired()
            .into_iter()
            .filter(|event| {
                event.object_kind == "binmap"
                    || event.name == "sync.registration"
                    || (case == "dedup" && event.object_kind == "sheaf")
            })
            .collect();
        assert_eq!(
            rows.iter()
                .filter(|event| event.phase == "before" && event.object_kind == "binmap")
                .count(),
            want,
            "{case}: missing shard/table/index tuple"
        );
        assert!(
            rows.iter()
                .any(|event| event.name == "sync.registration" && event.phase == "before_dispatch")
        );
        assert!(
            rows.iter()
                .any(|event| event.name == "sync.registration" && event.phase == "after_response")
        );
        let control = cuts::run_case(
            "node",
            "sync.node_upload",
            "before",
            1,
            None,
            false,
            false,
            case,
        )
        .unwrap();
        assert_eq!(control, GrainId::of(&discovery.registered()));
        for row in rows {
            let fixture = Fixture::with_case(case);
            let stage = if case == "dedup" {
                0
            } else {
                fixture.create("file", b"process boundary")
            };
            let before = fixture.registered();
            let faults = fixture.store.lock().unwrap().fault_control();
            faults.arm(row.name, row.phase, row.occurrence, FaultAction::Fail);
            assert!(if case == "dedup" {
                fixture.sync_tree(42).0.is_err()
            } else {
                fixture.sync(42, stage).0.is_err()
            });
            let fired = faults.sync_fired();
            assert_eq!(fired.len(), 1);
            let actual = fired.first().unwrap();
            assert_eq!(
                (
                    actual.name,
                    actual.phase,
                    actual.occurrence,
                    actual.object_kind,
                    actual.capture,
                    actual.request
                ),
                (
                    row.name,
                    row.phase,
                    row.occurrence,
                    row.object_kind,
                    row.capture,
                    row.request
                )
            );
            assert_eq!(
                fixture.registered() != before,
                row.name == "sync.registration" && row.phase == "after_response"
            );
            cuts::run_case(
                if row.name == "sync.registration" {
                    "registration"
                } else {
                    "node"
                },
                row.name,
                row.phase,
                row.occurrence,
                Some(row.object_kind),
                false,
                true,
                case,
            );
            cases += 1;
        }
    }
    assert_eq!(cases, if case == "dedup" { 4 } else { want * 2 + 2 });
    println!("case={case} fired fault/cut tuples={cases}");
}
