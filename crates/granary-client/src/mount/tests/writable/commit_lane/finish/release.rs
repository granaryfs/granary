// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Release across mount, shutdown and explicit recovery.

pub(super) mod archive_rows;
mod budget;
mod eviction;
mod handshake;

use super::*;
use crate::overlay_test_support::ReleaseAnswer;
use granary_core::overlay_ownership::{self as ownership, Carrier, Operation};

fn carrier(stopped: &Stopped) -> Carrier {
    let input = input(&stopped.tree, &stopped.paths);
    ownership::decode(
        &std::fs::read(overlay_area(&stopped.paths, &input).join("ownership")).unwrap(),
    )
    .unwrap()
}

fn release_slots(carrier: &Carrier) -> Vec<(u64, bool, bool)> {
    carrier
        .pending
        .iter()
        .filter(|pending| pending.operation == Operation::Release)
        .map(|pending| {
            (
                intent::decode_release(&pending.body).unwrap().epoch,
                pending.terminal,
                pending.answered,
            )
        })
        .collect()
}

/// Run the next start while the caller retains the stopped fixture's paths.
fn start_remount(stopped: &Stopped, entropy: u8) -> Result<Readiness, WritableStartError> {
    let input = input(&stopped.tree, &stopped.paths);
    let authority =
        Authority::with_scope_and_rule(&stopped.tree, input.scope.clone(), &stopped.state, "valid")
            .with_publication();
    start_with(
        &input,
        true,
        || {
            Ok((
                SigningKey::from_seed(&stopped.tree.seed).unwrap(),
                SigningKey::from_seed(&stopped.tree.seed).unwrap(),
                authority,
            ))
        },
        |store: &Store| OverlayDisk::new(store.publication_root(), input.euid),
        &mut Entropy(entropy),
        &Time(Arc::clone(&stopped.state)),
        &mut granary_core::rng::SeededRng::new(1),
        &mut Vec::new(),
    )
}

/// The next start with its own instance entropy, its engine attached.
fn remount(stopped: Stopped, entropy: u8) -> Result<EngineMount, WritableStartError> {
    let mut ready = start_remount(&stopped, entropy)?;
    let Stopped { tree, paths, state } = stopped;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let remote = Arc::new(Authority::new(&tree, &state).with_publication());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .unwrap(),
    );
    let metrics = crate::ClientMetrics::new(&mut Entropy(35));
    let engine = runtime
        .block_on(ready.backend_for_test().attach_sync_with_runtime(
            remote,
            content,
            Arc::new(Time(state.clone())),
            Arc::new(crate::InstantClock::default()),
            metrics.clone(),
            Arc::new(FastWaitRuntime),
            Entropy(36),
        ))
        .unwrap();
    let faults = ready
        .backend_for_test()
        .shared_mediator()
        .with(|store| Ok(store.fault_control()))
        .unwrap();
    Ok(EngineMount {
        ready,
        engine,
        runtime,
        faults,
        state,
        metrics,
        tree,
        paths,
    })
}

fn shut_down_as(
    mut fixture: EngineMount,
    trigger: Trigger,
    bound: std::time::Duration,
) -> (Outcome, Stopped) {
    let mediator = fixture.mediator();
    let shutdown = controller(
        &fixture.engine,
        mediator,
        fixture.runtime.handle().clone(),
        bound,
    );
    let outcome = shutdown.begin(trigger).outcome;
    drop(shutdown);
    (outcome, stop(fixture))
}

fn row(stopped: &Stopped) -> Receipt {
    stopped.state.lock().unwrap().row.unwrap()
}

#[test]
fn mount_remount_cycles_release_every_time() {
    let mut cases = 0;
    for profile in PROFILES {
        let mut fixture = fixture_with(profile);
        let mut log = Vec::new();
        for cycle in 0u8..9 {
            let why = format!("profile={profile:?} cycle={cycle}");
            let dirty = cycle % 3 != 1;
            if dirty {
                create(
                    fixture.ready.backend_for_test(),
                    &format!("f{cycle}"),
                    format!("bytes of cycle {cycle}\n").as_bytes(),
                );
            }
            if cycle % 3 == 2 {
                let lane = construct_commit(&fixture.engine, &fixture.runtime, 70).unwrap();
                let landed = drive_commit(&fixture.engine, &fixture.runtime, &lane, 80).unwrap();
                assert!(
                    matches!(landed.outcome, PublicationOutcome::Landed(_)),
                    "{why}: {landed:?}"
                );
            }
            let trigger =
                [Trigger::SessionEnd, Trigger::Signal, Trigger::Umount][usize::from(cycle) % 3];
            let before = fixture.state.lock().unwrap().sends.len();
            let (outcome, stopped) =
                shut_down_as(fixture, trigger, crate::sync::DEFAULT_SHUTDOWN_BOUND);
            let on_disk = carrier(&stopped);
            let authority = row(&stopped);
            log.push((
                cycle,
                outcome,
                on_disk.phase,
                release_slots(&on_disk),
                authority.epoch,
            ));
            assert!(
                matches!(outcome, Outcome::Committed(_) | Outcome::Clean),
                "{why}: shutdown {outcome:?}; log={log:?}"
            );
            assert_eq!(
                (
                    on_disk.phase,
                    release_slots(&on_disk),
                    authority.state,
                    stopped.state.lock().unwrap().sends[before..]
                        .iter()
                        .filter(|bytes| intent::decode_release(bytes).is_ok())
                        .count()
                ),
                (
                    Phase::Released,
                    vec![(authority.epoch, true, true)],
                    ReceiptState::Released,
                    1
                ),
                "{why}; log={log:?}"
            );
            fixture = remount(stopped, 41 + cycle * 3)
                .unwrap_or_else(|error| panic!("{why}: remount refused: {error}; log={log:?}"));
            for seen in 0..=cycle {
                if seen % 3 != 1 {
                    assert_eq!(
                        read_back(&mut fixture.ready, format!("f{seen}").as_bytes()).unwrap(),
                        format!("bytes of cycle {seen}\n").as_bytes(),
                        "{why}: f{seen}"
                    );
                }
            }
            cases += 1;
        }
        let (outcome, stopped) = shut_down_as(
            fixture,
            Trigger::Signal,
            crate::sync::DEFAULT_SHUTDOWN_BOUND,
        );
        assert!(
            matches!(outcome, Outcome::Clean),
            "{profile:?}: last {outcome:?}"
        );
        assert_eq!(carrier(&stopped).phase, Phase::Released);
    }
    assert_eq!(cases, 9 * PROFILES.len());
}

/// Replay the old owner's exact Release before taking over its Released row.
#[test]
fn interrupted_release_then_remount_and_release_again() {
    for (landed, late) in [(false, false), (false, true), (true, false), (true, true)] {
        let why = format!("landed={landed} late={late}");
        let stopped = interrupted(Some(landed), late);
        let before = sends(&stopped);
        let old = row(&stopped);
        let retained = carrier(&stopped)
            .pending
            .into_iter()
            .find(|p| p.operation == Operation::Release)
            .unwrap();
        let fixture =
            remount(stopped, 60).unwrap_or_else(|error| panic!("{why}: remount: {error}"));
        {
            let state = fixture.state.lock().unwrap();
            let sent = &state.sends[before..];
            assert_eq!(sent[0], retained.body, "{why}");
            assert_eq!(
                sent.iter()
                    .filter(|bytes| intent::decode_release(bytes).is_ok())
                    .count(),
                1,
                "{why}"
            );
            assert_eq!(
                intent::decode_ownership(&sent[1]).unwrap().mode,
                intent::OwnershipMode::Takeover {
                    expected_epoch: old.epoch,
                    generation: intent::decode_release(&retained.body)
                        .unwrap()
                        .generation
                        .max(old.generation),
                    state: ReceiptState::Released,
                    recovery_ack: false,
                },
                "{why}"
            );
        }
        assert_clean_release_after_remount(fixture);
    }
}

/// Stop with a prepared Release before any answer was persisted. With
/// `landed = None`, stop before dispatch.
fn interrupted(landed: Option<bool>, late: bool) -> Stopped {
    let mut fixture = fixture_with(crate::SyncProfile::default());
    let time = Time(fixture.state.clone());
    let request = fixture
        .mediator()
        .with(|store| {
            let request = store.prepare_release(&time, std::time::Duration::from_secs(1), None)?;
            if landed.is_some() {
                store.dispatch(&request, &time)?;
            }
            Ok(request)
        })
        .unwrap();
    let stopped = stop(fixture);
    let left = carrier(&stopped);
    let epoch = intent::decode_release(request.bytes()).unwrap().epoch;
    assert_eq!(
        (left.phase, release_slots(&left)),
        (Phase::Releasing, vec![(epoch, false, false)])
    );
    {
        let mut state = stopped.state.lock().unwrap();
        if landed == Some(true) {
            let generation = intent::decode_release(request.bytes()).unwrap().generation;
            let row = state.row.as_mut().unwrap();
            row.generation = row.generation.max(generation);
            row.state = ReceiptState::Released;
            state.root.clear();
        }
        if late {
            state.tick += 200_000;
        }
    }
    stopped
}

fn assert_clean_release_after_remount(fixture: EngineMount) {
    let (outcome, stopped) = shut_down_as(
        fixture,
        Trigger::SessionEnd,
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
    );
    let on_disk = carrier(&stopped);
    let remote = row(&stopped);
    assert_eq!(outcome, Outcome::Clean);
    assert_eq!(on_disk.phase, Phase::Released);
    assert_eq!(release_slots(&on_disk), [(remote.epoch, true, true)]);
    assert_eq!(remote.state, ReceiptState::Released);
}

fn recover_with(
    stopped: &Stopped,
    writer: [u8; 16],
    acknowledge: Option<[u8; 16]>,
    entropy: u8,
) -> Result<crate::RecoveryOutcome, crate::RecoveryCommandError> {
    let input = input(&stopped.tree, &stopped.paths);
    let runtime = runtime();
    let store = Store::open(&stopped.paths.store).unwrap();
    let io = OverlayDisk::new(store.publication_root(), input.euid);
    let authority = Authority::new(&stopped.tree, &stopped.state).with_publication();
    let key = SigningKey::from_seed(&stopped.tree.seed).unwrap();
    let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()]).unwrap();
    crate::RecoveryCommand {
        construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
        local: Some((store, io)),
        config: crate::OverlayConfig {
            scope: input.scope.clone().unwrap(),
            volume: input.volume.clone(),
            euid: input.euid,
            cap: 134_217_728,
            ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
            instance: [0; 16],
        },
        transport: &authority,
        runtime: &runtime,
        signer: &key,
        publisher_keys: &keys,
        writer,
        acknowledge_takeover: acknowledge,
        acknowledge_resend: None,
        faults: crate::FaultControl::default(),
    }
    .run(
        &Arc::new(Time(stopped.state.clone())),
        SigningKey::from_seed(&stopped.tree.seed).unwrap(),
        &mut Entropy(entropy),
        granary_core::rng::SeededRng::new(2),
    )
}

/// `gran recover` after a completed Release, then twice more, then a mount
/// and its shutdown.
#[test]
fn recover_after_a_completed_release_then_mount_again() {
    for dirty in [false, true] {
        let mut fixture = fixture_with(crate::SyncProfile::default());
        if dirty {
            create(fixture.ready.backend_for_test(), "a", DIRTY);
        }
        let (outcome, stopped) = shut_down_as(
            fixture,
            Trigger::Signal,
            crate::sync::DEFAULT_SHUTDOWN_BOUND,
        );
        assert!(matches!(outcome, Outcome::Committed(_) | Outcome::Clean));
        let writer = carrier(&stopped).writer;
        for run in 0..3u8 {
            let before = sends(&stopped);
            recover_with(&stopped, writer, None, 130 + run * 5)
                .unwrap_or_else(|error| panic!("dirty={dirty}, run={run}: {error}"));
            let disk = carrier(&stopped);
            let remote = row(&stopped);
            assert_eq!(disk.phase, Phase::Released);
            assert_eq!(remote.state, ReceiptState::Released);
            assert_eq!(release_slots(&disk), [(remote.epoch, true, true)]);
            assert_eq!(sends(&stopped), before);
        }
        let fixture = remount(stopped, 77)
            .unwrap_or_else(|error| panic!("dirty={dirty}: remount after recover: {error}"));
        let (outcome, stopped) = shut_down_as(
            fixture,
            Trigger::SessionEnd,
            crate::sync::DEFAULT_SHUTDOWN_BOUND,
        );
        assert!(
            matches!(outcome, Outcome::Clean),
            "dirty={dirty}: {outcome:?}"
        );
        assert_eq!(
            release_slots(&carrier(&stopped)),
            vec![(row(&stopped).epoch, true, true)]
        );
    }
}

/// Recovery confirms the retained Release durably before a later mount.
#[test]
fn recover_after_an_interrupted_release_then_mount_again() {
    for (landed, late) in [(false, false), (false, true), (true, false), (true, true)] {
        let why = format!("landed={landed} late={late}");
        let stopped = interrupted(Some(landed), late);
        let pending = carrier(&stopped);
        let retained = pending
            .pending
            .iter()
            .find(|p| p.operation == Operation::Release)
            .unwrap();
        for run in 0..2u8 {
            let before = sends(&stopped);
            recover_with(&stopped, pending.writer, None, 130 + run * 5)
                .unwrap_or_else(|error| panic!("{why} run {run}: {error}"));
            let disk = carrier(&stopped);
            let remote = row(&stopped);
            assert_eq!(disk.phase, Phase::Released, "{why}");
            assert_eq!(remote.state, ReceiptState::Released, "{why}");
            assert_eq!(release_slots(&disk), [(remote.epoch, true, true)], "{why}");
            assert_eq!(intent::decode_receipt(&disk.current).unwrap(), remote);
            let state = stopped.state.lock().unwrap();
            assert_eq!(
                &state.sends[before..],
                if run == 0 {
                    std::slice::from_ref(&retained.body)
                } else {
                    &[]
                }
            );
        }
        let fixture =
            remount(stopped, 77).unwrap_or_else(|error| panic!("{why}: remount: {error}"));
        assert_clean_release_after_remount(fixture);
    }
}

#[test]
fn terminal_refusal_of_a_rearmed_release_then_mount() {
    for (landed, token, refusal) in [
        (true, "forbidden", "IntentBackendDisagreement"),
        (false, "forbidden", "IntentBackendDisagreement"),
        (true, "no-principal", "IntentTerminalRefusal"),
        (false, "no-principal", "IntentTerminalRefusal"),
    ] {
        let why = format!("landed={landed} token={token}");
        let stopped = interrupted(Some(landed), true);
        let prior = carrier(&stopped);
        let held = prior
            .pending
            .iter()
            .find(|p| p.operation == Operation::Release)
            .unwrap();
        stopped.state.lock().unwrap().release_answer = ReleaseAnswer::Refused(403, token);
        let before = sends(&stopped);
        let result = recover_with(&stopped, prior.writer, None, 130);
        let persisted = carrier(&stopped);
        let pending = persisted
            .pending
            .iter()
            .find(|p| p.operation == Operation::Release)
            .unwrap();
        assert_eq!(
            (
                result.err().map(|error| error.to_string()).as_deref(),
                persisted.phase,
                (
                    pending.terminal,
                    pending.answered,
                    pending.attempts,
                    pending.first
                ),
                &stopped.state.lock().unwrap().sends[before..],
            ),
            (
                Some(refusal),
                Phase::Releasing,
                (false, false, held.attempts + 1, held.first),
                std::slice::from_ref(&held.body),
            ),
            "{why}: recovery refusal preserves the rearmed Release"
        );
        assert_eq!(pending.body, held.body, "{why}");
        assert!(pending.expires > held.expires, "{why}: {pending:?}");

        stopped.state.lock().unwrap().release_answer = ReleaseAnswer::Released;
        let before = sends(&stopped);
        let fixture = remount(stopped, 77)
            .unwrap_or_else(|error| panic!("{why}: remount after a refused Release: {error}"));
        {
            let state = fixture.state.lock().unwrap();
            let sent = &state.sends[before..];
            assert_eq!(
                sent.first(),
                Some(&held.body),
                "{why}: the old Release precedes succession"
            );
            assert!(
                matches!(
                    intent::decode_ownership(sent.get(1).unwrap()).unwrap().mode,
                    intent::OwnershipMode::Takeover {
                        state: ReceiptState::Released,
                        ..
                    }
                ),
                "{why}: succession must select Released"
            );
        }
        assert_clean_release_after_remount(fixture);
    }
}

#[test]
fn recover_after_an_expired_unsent_release_takes_over_the_live_row() {
    let stopped = interrupted(None, true);
    let original = carrier(&stopped);
    let before = sends(&stopped);
    let live = row(&stopped);
    assert!(matches!(live.state, ReceiptState::Live { .. }));
    recover_with(&stopped, original.writer, None, 130).unwrap();
    let released = row(&stopped);
    assert_eq!(released.state, ReceiptState::Released);
    assert!(released.epoch > live.epoch);
    let disk = carrier(&stopped);
    assert_eq!(disk.phase, Phase::Released);
    assert_eq!(release_slots(&disk), [(released.epoch, true, true)]);
    let state = stopped.state.lock().unwrap();
    let sent = &state.sends[before..];
    assert_eq!(
        intent::decode_ownership(&sent[0]).unwrap().mode,
        intent::OwnershipMode::Takeover {
            expected_epoch: live.epoch,
            generation: live.generation,
            state: live.state,
            recovery_ack: false,
        }
    );
    let [new_release] = sent
        .iter()
        .filter_map(|bytes| intent::decode_release(bytes).ok())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    assert_eq!(new_release.epoch, released.epoch);
    assert_ne!(new_release.instance, live.instance);
}
