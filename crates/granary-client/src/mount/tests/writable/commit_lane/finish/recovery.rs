// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use object_store::ObjectStoreExt as _;

/// A real landing left installed before any release, with held base-equivalent
/// stage history. The unpublished control registers the same tree at its next seq.
fn normalization_fixture(unpublished: bool) -> Stopped {
    normalization_fixture_with_displaced_parent(unpublished, false)
}

fn normalization_fixture_with_displaced_parent(
    unpublished: bool,
    displaced_parent: bool,
) -> Stopped {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    let _object = fixture
        .ready
        .backend_for_test()
        .overlay_open(&handler_path(b"a"))
        .unwrap()
        .unwrap();
    let lane = construct_commit(&fixture.engine, &fixture.runtime, 70).unwrap();
    let result = drive_commit(&fixture.engine, &fixture.runtime, &lane, 80).unwrap();
    let PublicationOutcome::Landed(done) = result.outcome else {
        panic!("fixture landing: {result:?}");
    };
    if unpublished {
        let selected = register_unpublished(&mut fixture, done.seq);
        if displaced_parent {
            let mut doc = root::decode_root(&selected).unwrap();
            doc.parent = Some(GrainId::of(b"displaced parent"));
            let (seq, parent) = (doc.seq, doc.parent);
            super::super::carry_forward::plant_registered_root(
                &mut fixture.ready,
                &fixture.state,
                super::super::carry_forward::signed(&fixture.tree.key, doc, seq, parent),
            );
        }
    }
    semantic_history(stop(fixture), Outcome::Committed(done.seq))
}

pub(super) fn local_store(stopped: &Stopped) -> crate::WritableStore<OverlayDisk> {
    let input = input(&stopped.tree, &stopped.paths);
    let store = Store::open(&stopped.paths.store).unwrap();
    let io = OverlayDisk::new(store.publication_root(), input.euid);
    let keys = granary_store::crypto::TrustedKeys::new([*stopped.tree.key.public_key()]).unwrap();
    crate::WritableStore::new(
        store,
        crate::OverlayConfig {
            scope: input.scope.clone().unwrap(),
            volume: input.volume.clone(),
            euid: input.euid,
            cap: 134_217_728,
            ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
            instance: [0; 16],
        },
        io,
        &mut Entropy(150),
        crate::FaultControl::default(),
        |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, &keys).is_ok(),
    )
    .unwrap()
}

fn classify(stopped: &Stopped) -> crate::RecoveryRule {
    local_store(stopped).recovery_rule().unwrap()
}

fn release_sends(stopped: &Stopped) -> Vec<Vec<u8>> {
    stopped
        .state
        .lock()
        .unwrap()
        .sends
        .iter()
        .filter(|bytes| granary_core::intent::decode_release(bytes).is_ok())
        .cloned()
        .collect()
}

fn publish_recovery_head(
    tree: &PublishedTree,
    runtime: &tokio::runtime::Runtime,
    content: &[u8],
    writer: [u8; 16],
) -> (u64, Vec<u8>) {
    let scratch = ScratchDir::new();
    let store = Store::open(&scratch.0.join("publication")).unwrap();
    let source = scratch.0.join("head");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("a"), content).unwrap();
    let summary = runtime
        .block_on(publish(
            &tree.remote,
            &store,
            &source,
            &tree.volume,
            &tree.key,
            &WriterIdentity::from_bytes(writer),
            stamp(),
            Policy::default(),
        ))
        .unwrap();
    let head = runtime
        .block_on(remote_handle(&tree.mem).get_root(tree.volume.as_str(), summary.seq))
        .unwrap()
        .unwrap();
    (summary.seq, head)
}

fn subsumed_fixture() -> Stopped {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    let _object = fixture
        .ready
        .backend_for_test()
        .overlay_open(&handler_path(b"a"))
        .unwrap()
        .unwrap();
    let lane = construct_commit(&fixture.engine, &fixture.runtime, 70).unwrap();
    let result = drive_commit(&fixture.engine, &fixture.runtime, &lane, 80).unwrap();
    let PublicationOutcome::Landed(done) = result.outcome else {
        panic!("fixture landing: {result:?}");
    };
    let selected = register_unpublished(&mut fixture, done.seq);
    let (head_seq, head) =
        publish_recovery_head(&fixture.tree, &fixture.runtime, DIRTY, *b"foreign-writer!!");
    let mut head = root::decode_root(&head).unwrap();
    head.writer_uuid = root::decode_root(&selected).unwrap().writer_uuid;
    let (seq, parent) = (head.seq, head.parent);
    let head = super::super::carry_forward::signed(&fixture.tree.key, head, seq, parent);
    let path = object_store::path::Path::from(format!(
        "root/{}/{}",
        fixture.tree.volume.as_str(),
        granary_core::rootstore::format_hint_body(head_seq)
    ));
    fixture
        .runtime
        .block_on(fixture.tree.mem.put(&path, head.into()))
        .unwrap();
    fixture.state.lock().unwrap().head_seq = head_seq;
    semantic_history(stop(fixture), Outcome::Committed(done.seq))
}

#[test]
fn verified_subsumption_satisfies_the_final_publication_guard() {
    let stopped = subsumed_fixture();
    let events = Events::default();
    let _guard = tracing::subscriber::set_default(events.subscriber());
    let result = recover_stopped(&stopped, crate::FaultControl::default());
    let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            result.is_ok(),
            classify(&stopped),
            text.contains("recover.subsumed"),
            text.contains("recover.journal_finished"),
        ),
        (true, crate::RecoveryRule::Nothing, true, true),
        "cases=1, {result:?}: {text}"
    );
}

#[test]
fn expired_unanswered_release_is_confirmed_by_exact_replay() {
    let stopped = normalization_fixture(false);
    let faults = crate::FaultControl::default();
    faults.arm("intent.evidence", "before", 2, crate::FaultAction::Crash);
    let first = recover_stopped(&stopped, faults.clone());
    assert_eq!(
        (first.is_err(), faults.fired().len(), classify(&stopped)),
        (true, 1, crate::RecoveryRule::Release),
        "premise: {first:?}"
    );
    let [sent] = release_sends(&stopped).try_into().unwrap();
    stopped.state.lock().unwrap().tick += 100_000;
    recover_stopped(&stopped, crate::FaultControl::default()).unwrap();
    assert_eq!(classify(&stopped), crate::RecoveryRule::Nothing);
    assert_eq!(release_sends(&stopped), [sent.clone(), sent]);
}

#[test]
fn expired_release_requires_its_own_answer_even_with_empty_readback() {
    for present in [false, true] {
        let stopped = normalization_fixture(false);
        let retained = cut_at_release_send(&stopped);
        let before = local_store(&stopped).snapshot().clone();
        let readbacks = {
            let mut state = stopped.state.lock().unwrap();
            if !present {
                state.row = None;
                state.root.clear();
                state.release_answer = crate::overlay_test_support::ReleaseAnswer::Absent;
            }
            state.next_readback_rule = Some("accepted_without_rows");
            state.calls[1]
        };
        let result = recover_stopped(&stopped, crate::FaultControl::default());
        let local = local_store(&stopped);
        if present {
            result.unwrap();
            assert_eq!(local.snapshot().phase, Phase::Released);
        } else {
            assert!(result.is_err(), "{result:?}");
            assert_eq!(local.snapshot().phase, Phase::Fenced, "{result:?}");
            assert_eq!(local.snapshot().fence, 2);
            assert_eq!(local.snapshot().handshake, before.handshake);
            assert_eq!(local.snapshot().grant, before.grant);
        }
        assert_eq!(release_sends(&stopped), [retained]);
        assert_eq!(stopped.state.lock().unwrap().calls[1], readbacks);
    }
}

#[test]
fn terminal_unanswered_release_is_not_persisted_again() {
    let stopped = normalization_fixture(false);
    let faults = crate::FaultControl::default();
    faults.arm("recover.release", "prepared", 1, crate::FaultAction::Crash);
    let first = recover_stopped(&stopped, faults.clone());
    assert_eq!(
        (first.is_err(), faults.fired().len()),
        (true, 1),
        "{first:?}"
    );
    stopped.state.lock().unwrap().tick += 100_000;
    let clock = Time(stopped.state.clone());
    let mut local = local_store(&stopped);
    local.settle_expired_release(&clock).unwrap();
    let carrier = local.snapshot().clone();
    let pending = carrier
        .pending
        .iter()
        .find(|p| p.operation == granary_core::overlay_ownership::Operation::Release)
        .unwrap();
    assert_eq!(
        (pending.attempts, pending.terminal, pending.answered),
        (0, true, false)
    );
    drop(local);
    let mut local = local_store(&stopped);
    local.settle_expired_release(&clock).unwrap();
    assert_eq!(local.snapshot(), &carrier);
    assert!(release_sends(&stopped).is_empty());
}

#[test]
fn expired_release_with_a_persisted_attempt_is_replayed_even_before_transport() {
    let stopped = normalization_fixture(false);
    let retained = cut_at_release_send(&stopped);
    recover_stopped(&stopped, crate::FaultControl::default()).unwrap();
    assert_eq!(classify(&stopped), crate::RecoveryRule::Nothing);
    assert_eq!(release_sends(&stopped), [retained]);
}

fn cut_at_release_send(stopped: &Stopped) -> Vec<u8> {
    let faults = crate::FaultControl::default();
    faults.arm("intent.send", "before", 2, crate::FaultAction::Crash);
    let first = recover_stopped(stopped, faults.clone());
    assert_eq!(
        (first.is_err(), faults.fired().len()),
        (true, 1),
        "{first:?}"
    );
    assert!(release_sends(stopped).is_empty());
    stopped.state.lock().unwrap().tick += 100_000;
    let local = local_store(stopped);
    let pending = local
        .snapshot()
        .pending
        .iter()
        .find(|p| p.operation == granary_core::overlay_ownership::Operation::Release)
        .unwrap();
    assert_eq!(
        (pending.attempts, pending.terminal, pending.answered),
        (1, false, false)
    );
    pending.body.clone()
}

#[test]
fn semantic_clean_stale_publication_keeps_recovery_refusal() {
    let stopped = normalization_fixture_with_displaced_parent(true, true);
    let runtime = runtime();
    let (seq, _) = publish_recovery_head(
        &stopped.tree,
        &runtime,
        b"foreign content\n",
        *b"foreign-writer!!",
    );
    stopped.state.lock().unwrap().head_seq = seq;
    let before = release_sends(&stopped);
    let events = Events::default();
    let _guard = tracing::subscriber::set_default(events.subscriber());
    let result = recover_stopped(&stopped, crate::FaultControl::default());
    let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string),
            release_sends(&stopped),
            text.contains("recover.journal_finished"),
            text.contains("recover.stale"),
        ),
        (
            Some("intent refused: RecoveryStale".to_owned()),
            before,
            false,
            true,
        ),
        "cases=1, {result:?}: {text}"
    );
}

/// Every crash cut of normalization and release, each re-derived from the
/// durable journal. The table runs in [`NORMALIZATION_CHUNKS`] slices, one
/// test each: every case syncs a durable fixture several times, and on Apple
/// targets that sync is a full-device flush (`F_FULLFSYNC`) whose cost grows
/// with every test flushing beside it, so one test holding all twenty
/// reached the ci profile's hard kill under a full parallel run.
const NORMALIZATION_CUTS: [(&str, &str, u64); 20] = [
    ("overlay.normalize.mark_clear", "before", 1),
    ("overlay.normalize.mark_clear", "after-sync", 1),
    ("overlay.journal.normalize", "build", 1),
    ("overlay.journal.normalize", "before", 1),
    ("overlay.journal.normalize", "after", 1),
    ("overlay.journal.normalize", "sync", 1),
    ("overlay.journal.normalize", "after_sync", 1),
    ("overlay.journal.normalize", "rename", 1),
    ("overlay.journal.normalize", "after_rename", 1),
    ("overlay.journal.normalize", "dir_sync", 1),
    ("overlay.journal.normalize", "after_dir_sync", 1),
    ("overlay.normalize.retire", "before", 1),
    ("overlay.normalize.retire", "after-sync", 1),
    ("recover.release", "before", 1),
    ("recover.release", "prepared", 1),
    ("intent.send", "before", 2),
    ("intent.reply", "before", 2),
    ("intent.evidence", "before", 2),
    ("intent.evidence", "after", 2),
    ("recover.release", "confirmed", 1),
];

/// The slices of [`NORMALIZATION_CUTS`], one per test below.
const NORMALIZATION_CHUNKS: [std::ops::Range<usize>; 4] = [0..5, 5..10, 10..15, 15..20];

#[test]
fn normalization_chunks_cover_every_cut_once() {
    let mut covered: Vec<usize> = NORMALIZATION_CHUNKS.iter().cloned().flatten().collect();
    let listed = covered.len();
    covered.sort_unstable();
    covered.dedup();
    assert_eq!(
        (listed, covered),
        (
            NORMALIZATION_CUTS.len(),
            (0..NORMALIZATION_CUTS.len()).collect::<Vec<_>>()
        ),
        "every normalization cut must run in exactly one chunk"
    );
    let mut cuts = NORMALIZATION_CUTS.to_vec();
    cuts.sort_unstable();
    cuts.dedup();
    assert_eq!(
        cuts.len(),
        NORMALIZATION_CUTS.len(),
        "a normalization cut is listed twice"
    );
}

fn normalization_crash_cut_rederives_completion(
    name: &'static str,
    phase: &'static str,
    occurrence: u64,
) {
    let stopped = normalization_fixture(false);
    let input = input(&stopped.tree, &stopped.paths);
    let area = overlay_area(&stopped.paths, &input);
    let before = journal::scan_journal(&std::fs::read(area.join("journal")).unwrap()).unwrap();
    let waters = (
        before.header.writer,
        before.state.next_stage_id(),
        before.state.highest_generation(),
    );
    let faults = crate::FaultControl::default();
    faults.arm(name, phase, occurrence, crate::FaultAction::Crash);
    let events = Events::default();
    let dispatch = events.subscriber();
    let _guard = tracing::subscriber::set_default(dispatch);
    let cut = recover_stopped(&stopped, faults.clone());
    let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            cut.is_err(),
            faults.fired().len(),
            text.contains("recover.journal_finished")
        ),
        (true, 1, false),
        "{name}/{phase}, {cut:?}: {text}"
    );
    let after_cut = classify(&stopped);
    let canonical = crate::overlay_store::journal_condition(
        &mut OverlayDisk::new(&stopped.paths.store, input.euid),
        &area,
    )
    .unwrap()
    .unwrap()
    .1;
    assert_eq!(
        after_cut,
        if !canonical {
            crate::RecoveryRule::DirtyJournal
        } else if matches!(
            (name, phase),
            ("intent.evidence", "after") | ("recover.release", "confirmed")
        ) {
            crate::RecoveryRule::Nothing
        } else {
            crate::RecoveryRule::Release
        },
        "{name}/{phase}: canonical={canonical}"
    );
    let prior = publications(&stopped);
    let result = recover_stopped(&stopped, crate::FaultControl::default());
    let after = journal::scan_journal(&std::fs::read(area.join("journal")).unwrap()).unwrap();
    assert_eq!(
        (
            result.is_ok(),
            classify(&stopped),
            publications(&stopped),
            after.header.writer,
            after.state.next_stage_id(),
            after.state.highest_generation() >= waters.2
        ),
        (
            true,
            crate::RecoveryRule::Nothing,
            prior,
            waters.0,
            waters.1,
            true
        ),
        "{name}/{phase}: {result:?}, high waters={waters:?}"
    );
    let mut restarted = restart(&stopped, &Events::default()).unwrap();
    assert_eq!(
        read_back(&mut restarted, b"a").unwrap(),
        DIRTY,
        "{name}/{phase}"
    );
}

fn normalization_chunk(chunk: usize) {
    for &(name, phase, occurrence) in &NORMALIZATION_CUTS[NORMALIZATION_CHUNKS[chunk].clone()] {
        normalization_crash_cut_rederives_completion(name, phase, occurrence);
    }
}

#[test]
fn normalization_and_release_crash_cuts_rederive_completion_1() {
    normalization_chunk(0);
}

#[test]
fn normalization_and_release_crash_cuts_rederive_completion_2() {
    normalization_chunk(1);
}

#[test]
fn normalization_and_release_crash_cuts_rederive_completion_3() {
    normalization_chunk(2);
}

#[test]
fn normalization_and_release_crash_cuts_rederive_completion_4() {
    normalization_chunk(3);
}

/// A lost release reply is resent once with the same bytes, and a rerun
/// after the release sends nothing.
#[test]
fn normalization_lost_release_reply_resends_identically() {
    let stopped = normalization_fixture(false);
    let before = sends(&stopped);
    stopped.state.lock().unwrap().release_lost_reply = true;
    let result = recover_stopped(&stopped, crate::FaultControl::default());
    let releases = stopped
        .state
        .lock()
        .unwrap()
        .sends
        .iter()
        .skip(before)
        .filter(|bytes| granary_core::intent::decode_release(bytes).is_ok())
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        (
            result.is_ok(),
            classify(&stopped),
            releases.len(),
            releases.first() == releases.get(1)
        ),
        (true, crate::RecoveryRule::Nothing, 2, true),
        "lost release: {result:?}, {releases:?}"
    );
    let before = sends(&stopped);
    let result = recover_stopped(&stopped, crate::FaultControl::default());
    assert_eq!(
        (result.is_ok(), sends(&stopped)),
        (true, before),
        "released rerun: {result:?}"
    );
}

#[test]
fn completed_settlement_and_install_do_not_hide_unfinished_remainder() {
    let stopped = normalization_fixture(true);
    stopped.state.lock().unwrap().release_delay = Some(std::time::Duration::from_secs(10));
    let (result, text) = recover_with_paused_finish_delays(
        &stopped,
        (
            std::time::Duration::from_secs(20),
            std::time::Duration::from_secs(5),
            std::time::Duration::ZERO,
        ),
        crate::SyncOptions::default().workspace_bytes,
    );
    assert_eq!(
        (
            result.is_err(),
            stopped
                .state
                .lock()
                .unwrap()
                .row
                .is_some_and(|r| matches!(r.state, ReceiptState::Live { .. })),
            text.contains("\"reason\":\"limit\""),
            text.contains("recover.journal_finished")
        ),
        (true, true, true, false),
        "cases=1, {result:?}: {text}"
    );
}

#[test]
fn deadline_expires_before_release_is_prepared() {
    let stopped = normalization_fixture(false);
    let before = release_sends(&stopped);
    let (result, text) = recover_with_paused_finish_delays(
        &stopped,
        (
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(31),
        ),
        crate::SyncOptions::default().workspace_bytes,
    );
    assert_eq!(
        (
            result.is_err(),
            release_sends(&stopped),
            text.contains("\"reason\":\"limit\""),
            text.contains("recover.journal_finished")
        ),
        (true, before, true, false),
        "cases=1, {result:?}: {text}"
    );
}

#[test]
fn recover_finishing_commit_still_obeys_the_command_deadline() {
    use std::time::Duration;

    let stopped = super::outage::residual_work();
    let sends = publications(&stopped);
    stopped.state.lock().unwrap().publish_unavailable = Some((1, Duration::from_secs(40)));
    let (result, text) = recover_with_paused_finish_delays(
        &stopped,
        Default::default(),
        crate::SyncOptions::default().workspace_bytes,
    );
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string).as_deref(),
            publications(&stopped) - sends,
            super::outage::retained_evidence(&stopped),
            text.contains("\"reason\":\"limit\""),
        ),
        (
            Some("intent refused: SyncDeadline"),
            1,
            Some((1, 0, false)),
            true
        ),
        "recovery's finishing publication must be cut before its 503: {result:?}, {text}"
    );
}

#[test]
fn recovery_command_and_shared_finish_observe_configured_workspace() {
    for command in [false, true] {
        for bound in [8_388_608, 1_073_741_824] {
            let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
            create(
                fixture.ready.backend_for_test(),
                "finish-workspace",
                &vec![7; 2_097_152],
            );
            let stopped = stop(fixture);
            let error = if command {
                recover_with_paused_finish_delays(
                    &stopped,
                    (
                        std::time::Duration::ZERO,
                        std::time::Duration::ZERO,
                        std::time::Duration::ZERO,
                    ),
                    bound,
                )
                .0
                .err()
                .map(|e| e.to_string())
            } else {
                let cfg = WritableStart {
                    construction_workspace_bytes: bound,
                    ..input(&stopped.tree, &stopped.paths)
                };
                restart_with(&cfg, &stopped.tree, &stopped.state, &Events::default())
                    .err()
                    .map(|e| e.to_string())
            };
            assert_eq!(
                (
                    error
                        .as_ref()
                        .is_some_and(|e| e.contains("SyncWorkspaceExhausted")),
                    error.is_none()
                ),
                (bound == 8_388_608, bound != 8_388_608),
                "command={command}, bound={bound}: {error:?}"
            );
        }
    }
}

pub(super) fn recover_with_paused_finish_delays(
    stopped: &Stopped,
    delays: (
        std::time::Duration,
        std::time::Duration,
        std::time::Duration,
    ),
    workspace: u64,
) -> (
    Result<crate::RecoveryOutcome, crate::RecoveryCommandError>,
    String,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let input = input(&stopped.tree, &stopped.paths);
    let (header, _) = captured_records(&stopped.paths, &input);
    let store = Store::open(&stopped.paths.store).unwrap();
    let io = OverlayDisk::new(store.publication_root(), input.euid);
    let key = SigningKey::from_seed(&stopped.tree.seed).unwrap();
    let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()]).unwrap();
    crate::recovery::FINISH_DELAYS.set(delays);
    let events = Events::default();
    let _guard = tracing::subscriber::set_default(events.subscriber());
    let result = crate::RecoveryCommand {
        construction_workspace_bytes: workspace,
        local: Some((store, io)),
        config: crate::OverlayConfig {
            scope: input.scope.clone().unwrap(),
            volume: input.volume.clone(),
            euid: input.euid,
            cap: 134_217_728,
            ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
            instance: [0; 16],
        },
        transport: &Authority::new(&stopped.tree, &stopped.state).with_publication(),
        runtime: &runtime,
        signer: &key,
        publisher_keys: &keys,
        writer: header.writer,
        acknowledge_takeover: None,
        acknowledge_resend: None,
        faults: crate::FaultControl::default(),
    }
    .run(
        &Arc::new(Time(stopped.state.clone())),
        SigningKey::from_seed(&stopped.tree.seed).unwrap(),
        &mut Entropy(130),
        granary_core::rng::SeededRng::new(2),
    );
    crate::recovery::FINISH_DELAYS.set((
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    ));
    let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
    (result, text)
}
