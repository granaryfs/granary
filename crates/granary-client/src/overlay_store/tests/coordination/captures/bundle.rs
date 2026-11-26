// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn bundle_retention_tracks_sync_payload_reserve_finish_and_abandon() {
    let mut cases = 0;
    for disposition in ["finish", "incomplete", "abandon"] {
        let (_scratch, io, mut client, _authority) = serving();
        let boundary = client
            .overlay_transaction(|t| {
                let stage = t.create_file(at("empty"), false)?;
                t.seal_sync(crate::SyncTarget::Stage(stage))
            })
            .unwrap();
        let before = client.overlay_bundle().unwrap();
        let mut verifier = client
            .begin_sync_payload(&boundary, 0, FileGrains::Inline(vec![]))
            .unwrap();
        assert_eq!(
            client.overlay_bundle().map(|s| s.captured_bytes),
            Ok(before.captured_bytes + 4_260_352),
            "reserve did not publish retained charge"
        );
        if disposition == "finish" {
            verifier.authenticate(&Objects::default()).unwrap();
        }
        if disposition == "abandon" {
            let trace = io.0.lock().unwrap().trace.clone();
            client.abandon_sync_payload(&boundary, verifier).unwrap();
            assert_eq!(io.0.lock().unwrap().trace, trace, "disposal performed I/O");
        } else {
            assert_eq!(
                client.finish_sync_payload(&boundary, verifier).is_ok(),
                disposition == "finish"
            );
        }
        assert_eq!(
            client.overlay_bundle().map(|s| s.captured_bytes),
            Ok(before.captured_bytes + if disposition == "finish" { 512 } else { 0 }),
            "release did not publish retained charge"
        );
        client.release_sync_boundary(&boundary).unwrap();
        assert_eq!(client.overlay_bundle().map(|s| s.captured_bytes), Ok(0));
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn bundle_retention_tracks_capture_completion_success_and_refusal() {
    let mut cases = 0;
    for accepted in [false, true] {
        let (_scratch, _io, mut client, mut authority) = serving();
        let stage = client
            .overlay_transaction(|t| {
                let stage = t.create_file(at("empty"), false)?;
                t.write(stage, 0, b"abc")?;
                Ok(stage)
            })
            .unwrap();
        let captured = capture(&mut client, stage);
        let mut objects = Objects::default();
        let (root, grains) = prepared(client.writer_uuid(), "empty", b"abc", &mut objects);
        let request = client
            .prepare_captured_registration(&root, captured.clone(), grains, &Tick(10), |_, _| true)
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        let answer = if accepted {
            authority.send(&request)
        } else {
            reply(400, Some("bad-request"), None, vec![])
        };
        assert_eq!(
            client
                .complete(
                    &request,
                    Ok(&answer),
                    &Tick(11),
                    &mut SeededRng::new(1),
                    0,
                    None
                )
                .is_ok(),
            accepted
        );
        let before = client.overlay_bundle().unwrap();
        assert!(before.captured_bytes > 0, "capture premise: {before:?}");
        let input = CaptureCoverageInput {
            prepared_root: GrainId::of(&root),
            boundary: captured.through_seq(),
            projections: vec![StageProjection {
                stage_id: stage,
                incarnation: captured.incarnation(),
                path: vec![name("empty")],
                content_boundary: captured.through_seq(),
            }],
            mutations: vec![],
            identities: vec![],
        };
        let completed = client
            .complete_capture_queue(&BTreeMap::from([(input.prepared_root, input)]), &objects)
            .unwrap();
        assert_eq!(
            (completed.len(), completed[0].result.is_ok()),
            (1, accepted)
        );
        assert_eq!(
            client
                .overlay_bundle()
                .map(|s| (s.captured_bytes, s.journal_records)),
            Ok((0, before.journal_records + if accepted { 2 } else { 0 })),
            "completion did not publish retained counters"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn bundle_retention_tracks_direct_engine_graph_reservations() {
    let (_scratch, _io, mut client, _authority) = serving();
    let before = client.overlay_bundle().unwrap();
    client.reserve_engine_graph(997).unwrap();
    assert_eq!(
        client.overlay_bundle().map(|s| s.captured_bytes),
        Ok(before.captured_bytes + 997)
    );
    client.release_engine_graph(997).unwrap();
    assert_eq!(
        client.overlay_bundle().map(|s| s.captured_bytes),
        Ok(before.captured_bytes)
    );
}

#[test]
fn bundle_retention_tracks_direct_projected_reservations() {
    let (_scratch, _io, mut client, _authority) = serving();
    let before = client.overlay_bundle().unwrap();
    let charge = client.reserve_projected_commit(1_048_576).unwrap();
    assert!(charge > 0, "projected reservation premise: {charge}");
    assert_eq!(
        client.overlay_bundle().map(|s| s.captured_bytes),
        Ok(before.captured_bytes + charge)
    );
    client.release_projected_commit(charge).unwrap();
    assert_eq!(
        client.overlay_bundle().map(|s| s.captured_bytes),
        Ok(before.captured_bytes)
    );
}

#[test]
fn bundle_retention_tracks_direct_normalization() {
    let (_scratch, _io, mut client, _authority) = serving();
    let before = client.overlay_bundle().unwrap();
    assert!(
        before.journal_records > 0,
        "normalization premise: {before:?}"
    );
    client.normalize_finished(true).unwrap();
    assert_eq!(
        client
            .overlay_bundle()
            .map(|s| (s.journal_records, s.journal_bytes)),
        Ok((0, 117))
    );
}

#[test]
fn bundle_retention_refuses_swallowed_release_measurement_failure() {
    let (_scratch, io, mut client, _authority) = serving();
    let boundary = client
        .overlay_transaction(|t| {
            let stage = t.create_file(at("empty"), false)?;
            t.seal_sync(crate::SyncTarget::Stage(stage))
        })
        .unwrap();
    client.note_capacity_refusal(&CoordinationError::Overlay(OverlayError::NoSpace));
    assert!(client.overlay_bundle().is_ok());
    io.0.lock().unwrap().fail = Some("entries");
    client.release_sync_boundary(&boundary).unwrap();
    assert_eq!(
        (client.overlay_bundle(), io.0.lock().unwrap().fail),
        (Err(granary_core::support::BundleRefusal::Unreadable), None)
    );
}

#[test]
fn bundle_retention_refuses_failed_direct_journal_read() {
    let (_scratch, io, mut client, _authority) = serving();
    assert!(client.overlay_bundle().is_ok());
    io.0.lock().unwrap().fail = Some("read");
    let failed = client.finish_normalization_required();
    assert!(
        matches!(failed, Err(CoordinationError::Overlay(OverlayError::Io(_)))),
        "journal read fault premise: {failed:?}"
    );
    assert_eq!(
        (client.overlay_bundle(), io.0.lock().unwrap().fail),
        (Err(granary_core::support::BundleRefusal::Unreadable), None)
    );
}

#[test]
fn bundle_retention_exports_valid_counters_after_mediator_poison() {
    let (_scratch, io, mut client, _authority) = serving();
    let mut expected = client.overlay_bundle().unwrap();
    expected.readiness = 4;
    io.0.lock().unwrap().fail = Some("sync");
    let failed =
        client.prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        });
    assert!(
        matches!(failed, Err(CoordinationError::Overlay(OverlayError::Io(_)))),
        "carrier fault premise: {failed:?}"
    );
    assert_eq!(
        (client.overlay_bundle(), io.0.lock().unwrap().fail),
        (Ok(expected), None)
    );
}

#[test]
fn routine_no_space_does_not_permanently_refuse_bundle() {
    let (_scratch, _io, mut client, _authority) = serving();
    let before = client.overlay_bundle().unwrap();
    let refused = client.reserve_engine_graph(u64::MAX / 2);
    assert!(
        matches!(
            refused,
            Err(CoordinationError::Overlay(OverlayError::Refused(
                "OverlayCapacityExhausted"
            )))
        ),
        "no-space premise: {refused:?}"
    );
    client.reserve_engine_graph(997).unwrap();
    client.release_engine_graph(997).unwrap();
    client.overlay_transaction(|_| Ok(())).unwrap();
    assert_eq!(
        client.overlay_bundle(),
        Ok(before),
        "routine no-space refusal left the bundle refused after successful transitions"
    );
}

#[test]
fn capacity_refusal_refreshes_measured_scalars() {
    let (_scratch, _io, mut client, _authority) = serving();
    client
        .overlay_transaction(|t| t.set_coalescing_journal_length_for_test(50_331_648))
        .unwrap();
    assert!(
        client.overlay_bundle().unwrap().commit_requested,
        "stale measurement premise"
    );
    client.note_capacity_refusal(&CoordinationError::Overlay(OverlayError::NoSpace));
    assert_eq!(
        client
            .overlay_bundle()
            .map(|summary| summary.commit_requested),
        Ok(false),
        "capacity refusal did not publish its fresh measurement"
    );
}
