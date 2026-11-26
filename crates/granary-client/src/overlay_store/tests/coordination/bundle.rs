// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::SharedWritableStore;
use granary_core::support::BundleRefusal;

#[test]
fn bundle_retention_tracks_transactions_and_invalidates_known_failures() {
    let mut cases = 0;
    for (error, refusal) in [
        (OverlayError::ContentCorrupt, BundleRefusal::Corrupt),
        (
            OverlayError::Io(io::Error::other("injected read failure")),
            BundleRefusal::Unreadable,
        ),
    ] {
        let (_scratch, io, client, _authority) = serving();
        let shared = SharedWritableStore::new(client);
        assert_eq!(
            shared
                .try_overlay_bundle()
                .map(|s| (s.namespace_entries, s.staged_files)),
            Ok((1, 0))
        );
        let before = shared.try_overlay_bundle().unwrap();
        let stage = shared
            .with(|client| client.overlay_transaction(|t| t.create_file(at("file"), false)))
            .unwrap();
        let after = shared.try_overlay_bundle().unwrap();
        assert_eq!(
            (
                after.namespace_entries,
                after.staged_files,
                after.journal_records > before.journal_records
            ),
            (2, 1, true)
        );
        shared
            .with(|client| client.overlay_transaction(|t| t.write(stage, 0, b"payload")))
            .unwrap();
        assert!(shared.try_overlay_bundle().unwrap().charged_bytes > after.charged_bytes);
        assert!(
            shared
                .with(|client| client.overlay_transaction::<()>(|_| Err(error)))
                .is_err()
        );
        assert_eq!(shared.try_overlay_bundle(), Err(refusal));
        shared
            .with(|client| client.overlay_transaction(|_| Ok(())))
            .unwrap();
        let trace = io.0.lock().unwrap().trace.len();
        assert_eq!(
            (
                shared.try_overlay_bundle(),
                io.0.lock().unwrap().trace.len()
            ),
            (Err(refusal), trace)
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
    let (_scratch, _io, client, _authority) = serving();
    let shared = SharedWritableStore::new(client);
    let mut expected = shared.try_overlay_bundle().unwrap();
    expected.readiness = 4;
    assert!(
        shared
            .with(|client| client.overlay_transaction::<()>(|_| Err(OverlayError::Poisoned)))
            .is_err()
    );
    shared
        .with(|client| client.overlay_transaction(|_| Ok(())))
        .unwrap();
    assert_eq!(
        shared.try_overlay_bundle(),
        Ok(expected),
        "poisoned summary was replaced by an old ready observation"
    );
}

#[test]
fn routine_conflict_does_not_permanently_refuse_bundle() {
    let (_scratch, _io, mut client, _authority) = serving();
    client
        .overlay_transaction(|t| t.create_file(at("file"), false))
        .unwrap();
    let before = client.overlay_bundle().unwrap();
    let conflict = client.overlay_transaction(|t| t.create_file(at("file"), false));
    assert!(
        matches!(
            conflict,
            Err(CoordinationError::Overlay(OverlayError::Refused(
                "create destination exists"
            )))
        ),
        "conflict premise: {conflict:?}"
    );
    client
        .overlay_transaction(|t| t.create_file(at("other"), false))
        .unwrap();
    assert_eq!(
        client
            .overlay_bundle()
            .map(|summary| summary.namespace_entries),
        Ok(before.namespace_entries + 1),
        "routine conflict left the bundle refused or stale"
    );
}

#[test]
fn ordinary_refusal_keeps_the_bundle_refreshable() {
    let mut cases = 0;
    for error in [
        OverlayError::Conflict,
        OverlayError::ContentUnavailable,
        OverlayError::MutationsClosed,
        OverlayError::Refused("create destination exists"),
    ] {
        let (_scratch, _io, mut client, _authority) = serving();
        let before = client.overlay_bundle().unwrap();
        let refused = client.overlay_transaction::<()>(|_| Err(error));
        assert!(refused.is_err(), "routine refusal premise: {refused:?}");
        assert_eq!(client.overlay_bundle(), Ok(before));
        client
            .overlay_transaction(|t| t.create_file(at("file"), false))
            .unwrap();
        assert_eq!(
            client
                .overlay_bundle()
                .map(|summary| summary.namespace_entries),
            Ok(before.namespace_entries + 1)
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn bundle_collection_refuses_absence_poison_and_busy_without_wait_or_io() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let absent = SharedWritableStore::new(start(&scratch, &io, 10));
    assert_eq!(absent.try_overlay_bundle(), Err(BundleRefusal::Unavailable));
    let (_scratch, io, client, _authority) = serving();
    let shared = SharedWritableStore::new(client);
    assert_eq!(shared.try_overlay_bundle().map(|s| s.readiness), Ok(3));
    let expected = shared.try_overlay_bundle().unwrap();
    let trace = io.0.lock().unwrap().trace.len();
    let owner = shared.as_arc();
    let held = owner.lock().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| send.send(shared.try_overlay_bundle()).unwrap());
        let result = receive.recv_timeout(std::time::Duration::from_millis(200));
        drop(held);
        assert_eq!(
            result,
            Ok(Err(BundleRefusal::TimedOut)),
            "collection waited for producer: {result:?}"
        );
    });
    assert_eq!(
        (
            shared.try_overlay_bundle(),
            io.0.lock().unwrap().trace.len()
        ),
        (Ok(expected), trace)
    );
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = owner.lock().unwrap();
        panic!("poison the producer lock");
    }));
    assert_eq!(shared.try_overlay_bundle(), Err(BundleRefusal::Unavailable));
}

#[test]
fn bundle_invalidation_survives_caught_failure_and_failed_reopen() {
    let (_scratch, io, mut client, _authority) = serving();
    let stage = client
        .overlay_transaction(|t| t.create_file(at("file"), false))
        .unwrap();
    let stage_path =
        io.0.lock()
            .unwrap()
            .names
            .keys()
            .find(|path| {
                path.parent()
                    .is_some_and(|parent| parent.ends_with("staging"))
            })
            .unwrap()
            .clone();
    io.mutate(&stage_path, |bytes| bytes[0] ^= 1);
    client
        .overlay_transaction(|t| {
            let failed = t.read_stage(stage, 0, 1);
            assert!(failed.is_err(), "corrupt header premise: {failed:?}");
            Ok(())
        })
        .unwrap();
    assert_eq!(
        client.overlay_bundle(),
        Err(BundleRefusal::Corrupt),
        "caught failure restored old projection"
    );

    let (_scratch, io, mut client, _authority) = serving();
    let mut h = header();
    h.writer = client.writer_uuid();
    io.0.lock().unwrap().fail = Some("read");
    let failed = client.open_overlay(h, vec![], &mut Source::default(), io.clone());
    assert!(
        matches!(failed, Err(CoordinationError::Overlay(OverlayError::Io(_)))),
        "open fault premise: {failed:?}"
    );
    assert_eq!(client.overlay_bundle(), Err(BundleRefusal::Unreadable));
}

#[test]
fn publication_poison_exports_a_poisoned_summary() {
    let (_scratch, _io, mut client, _authority) = serving();
    let mut expected = client.overlay_bundle().unwrap();
    expected.readiness = 4;
    let record = submission(
        client.snapshot().scope.clone(),
        client.writer_uuid(),
        root(client.writer_uuid(), 2),
    );
    client.fail_publication_file_sync_for_test(true);
    let failed = client.publication_transaction(|store| store.begin(&record));
    assert!(
        matches!(failed, Err(CoordinationError::Publication(_))),
        "publication poison premise: {failed:?}"
    );
    assert_eq!(client.overlay_bundle(), Ok(expected));
}
