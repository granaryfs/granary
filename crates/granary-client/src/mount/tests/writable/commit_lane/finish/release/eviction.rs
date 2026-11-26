// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Writable start and recovery after eviction of a Released row.

use super::*;
use crate::RecoveryOutcome;

#[derive(Clone, Copy, Debug)]
enum BeforeEviction {
    Released,
    TransportLoss,
    RefusedReplay,
}

fn released() -> Stopped {
    let fixture = fixture_with(crate::SyncProfile::default());
    let (outcome, stopped) = shut_down_as(
        fixture,
        Trigger::Umount,
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
    );
    let remote = stopped.state.lock().unwrap().row;
    assert_eq!(
        (
            outcome,
            carrier(&stopped).phase,
            remote.map(|row| row.state)
        ),
        (
            Outcome::Clean,
            Phase::Released,
            Some(ReceiptState::Released)
        ),
        "clean unmount must leave a Released row to evict"
    );
    stopped
}

fn evict_released_row(stopped: &Stopped) -> Receipt {
    let mut state = stopped.state.lock().unwrap();
    let evicted = state.row.take();
    assert_eq!(
        (evicted.map(|row| row.state), state.root.is_empty()),
        (Some(ReceiptState::Released), true),
        "authority state at eviction: {evicted:?}"
    );
    evicted.unwrap()
}

fn retain_takeover(stopped: &Stopped, before: BeforeEviction, released: Receipt) {
    let lost_then_refused = matches!(before, BeforeEviction::RefusedReplay);
    let first = if lost_then_refused {
        {
            let mut state = stopped.state.lock().unwrap();
            state.ownership_strict = true;
            state.ownership_lost_grants = 1;
            state.ownership_refusals = 1;
        }
        start_remount(stopped, 60)
    } else {
        let input = input(&stopped.tree, &stopped.paths);
        restart_with_rule(&input, &stopped.tree, &stopped.state, "always_lost")
    };
    let held = carrier(stopped);
    let slots: Vec<_> = held
        .pending
        .iter()
        .filter(|pending| pending.operation == Operation::Ownership)
        .map(|pending| (pending.terminal, pending.answered, pending.attempts))
        .collect();
    let remote = row(stopped);
    let (name, attempts) = if lost_then_refused {
        ("IntentTerminalRefusal", 2)
    } else {
        ("IntentStartupAttemptsExhausted", 8)
    };
    assert_eq!(
        (
            outcome(&first),
            held.phase,
            slots,
            remote.epoch,
            remote.state
        ),
        (
            name,
            Phase::Handshake,
            vec![(false, false, attempts)],
            released.epoch + u64::from(lost_then_refused),
            ReceiptState::Released
        ),
        "{before:?}: interrupted takeover before eviction"
    );
}

#[test]
fn released_row_evicted_before_takeover_replay() {
    let cases = [
        BeforeEviction::Released,
        BeforeEviction::TransportLoss,
        BeforeEviction::RefusedReplay,
    ];
    let mut recovery_failures = Vec::new();
    let starts = cases.map(|before| {
        let stopped = released();
        let released = row(&stopped);
        if !matches!(before, BeforeEviction::Released) {
            retain_takeover(&stopped, before, released);
        }
        let evicted = evict_released_row(&stopped);
        // Elapsed authority retention is independent of the client clock.
        // Keep the client's unanswered takeover within its local horizon.
        let at = {
            let mut state = stopped.state.lock().unwrap();
            state.tick += 7_200_000;
            state.tick
        };
        let held = carrier(&stopped);
        let retained = held
            .pending
            .iter()
            .find(|pending| pending.operation == Operation::Ownership && !pending.terminal);
        let window = retained.map(|pending| (pending.eligible, pending.expires));
        assert_eq!(
            window.map(|(eligible, expires)| eligible <= at && at < expires),
            (!matches!(before, BeforeEviction::Released)).then_some(true),
            "{before:?}: retained takeover window {window:?} at client tick {at}"
        );

        let recovered = matches!(before, BeforeEviction::Released).then(|| {
            recover_with(&stopped, held.writer, Some(held.writer), 65)
                .map_err(|error| error.to_string())
        });
        let sent_before = sends(&stopped);
        let mut result = start_remount(&stopped, 70);
        {
            let state = stopped.state.lock().unwrap();
            let sent = state.sends.get(sent_before);
            assert_eq!(
                (
                    sent.and_then(|body| intent::decode_ownership(body).ok())
                        .map(|ownership| ownership.mode),
                    retained.is_none_or(|pending| sent == Some(&pending.body))
                ),
                (
                    Some(intent::OwnershipMode::Takeover {
                        expected_epoch: released.epoch,
                        generation: released.generation,
                        state: ReceiptState::Released,
                        recovery_ack: false,
                    }),
                    true
                ),
                "{before:?}: the first start sends the takeover of the evicted Released row"
            );
        }
        let mut after = carrier(&stopped);
        if matches!(before, BeforeEviction::RefusedReplay)
            && result.is_err()
            && after.phase != Phase::Fenced
            && after.fence == 0
        {
            result = start_remount(&stopped, 71);
            after = carrier(&stopped);
        }
        if result.is_err() {
            let [plain, acked] = [None, Some(held.writer)].map(|ack| {
                recover_with(&stopped, held.writer, ack, 80).map_err(|error| error.to_string())
            });
            recovery_failures.push((before, plain, acked));
        }
        (
            outcome(&result),
            after.phase,
            after.fence,
            result
                .as_ref()
                .is_ok_and(|ready| ready.owner().1 > evicted.epoch),
            recovered,
        )
    });
    assert_eq!(
        starts,
        cases.map(|before| (
            "Ok",
            Phase::Serving,
            0,
            true,
            matches!(before, BeforeEviction::Released).then_some(Ok(RecoveryOutcome::NothingOwed))
        )),
        "every arm mounts with a fresh epoch after eviction; gran recover (plain, acknowledged): {recovery_failures:?}"
    );
}

#[test]
fn recover_clean_released_store_after_eviction_then_mount_once() {
    let stopped = released();
    let writer = carrier(&stopped).writer;
    stopped.state.lock().unwrap().tick += intent::released_row_retention_secs(0) * 1000;
    let evicted = evict_released_row(&stopped);
    let recovered = recover_with(&stopped, writer, None, 60).map_err(|error| error.to_string());
    let result = remount(stopped, 70);
    assert_eq!(
        (
            recovered,
            result
                .as_ref()
                .map(|_| ())
                .map_err(WritableStartError::name),
            result
                .as_ref()
                .is_ok_and(|fixture| fixture.ready.owner().1 > evicted.epoch),
        ),
        (Ok(RecoveryOutcome::NothingOwed), Ok(()), true),
        "recovery leaves nothing owed and one start mounts with a fresh epoch"
    );
    assert_clean_release_after_remount(result.unwrap_or_else(|error| panic!("remount: {error}")));
}

#[test]
fn recover_prologue_settles_a_retained_takeover_before_reporting_nothing_owed() {
    let stopped = released();
    let old = row(&stopped);
    retain_takeover(&stopped, BeforeEviction::TransportLoss, old);
    evict_released_row(&stopped);
    let before = carrier(&stopped);
    let held = before
        .pending
        .iter()
        .find(|p| p.operation == Operation::Ownership)
        .unwrap();
    stopped.state.lock().unwrap().tick += 7_200_000;
    let start_sends = sends(&stopped);
    let start_reads = stopped.state.lock().unwrap().calls[1];
    let result = recover_with(&stopped, before.writer, None, 70).map_err(|e| e.to_string());
    let after = carrier(&stopped);
    let answered = after
        .pending
        .iter()
        .find(|p| p.operation == Operation::Ownership);
    let state = stopped.state.lock().unwrap();
    assert_eq!(
        (
            result,
            after.phase,
            after.fence,
            answered.map(|p| (p.terminal, p.answered, p.attempts)),
            &state.sends[start_sends..],
            state.calls[1] - start_reads
        ),
        (
            Ok(RecoveryOutcome::NothingOwed),
            Phase::Unowned,
            0,
            Some((true, true, held.attempts + 1)),
            std::slice::from_ref(&held.body),
            1
        ),
        "the prologue settles the exact retained takeover and recovery judges one authenticated readback"
    );
}

#[test]
fn lost_release_reply_followed_by_eviction_still_fences() {
    let stopped = interrupted(Some(true), true);
    evict_released_row(&stopped);
    stopped.state.lock().unwrap().release_answer = ReleaseAnswer::Absent;
    let before = carrier(&stopped);
    let held = before
        .pending
        .iter()
        .find(|p| p.operation == Operation::Release)
        .unwrap();
    let start_sends = sends(&stopped);
    let result = start_remount(&stopped, 70);
    let after = carrier(&stopped);
    let state = stopped.state.lock().unwrap();
    assert_eq!(
        (
            before.phase,
            outcome(&result),
            after.phase,
            after.fence,
            &state.sends[start_sends..]
        ),
        (
            Phase::Releasing,
            "IntentFenced (ESTALE)",
            Phase::Fenced,
            2,
            std::slice::from_ref(&held.body)
        ),
        "re-armed Release sends its exact bytes and cannot prove it landed after eviction"
    );
}

/// Leave the clean carrier Unowned by a sole ordinary takeover refusal.
fn refused_released_takeover(stopped: &Stopped) -> Carrier {
    stopped.state.lock().unwrap().ownership_refusals = 1;
    let first = start_remount(stopped, 60);
    let after = carrier(stopped);
    assert_eq!(
        (outcome(&first), after.phase, after.fence),
        ("IntentTerminalRefusal", Phase::Unowned, 0),
        "a sole ordinary refusal must settle the takeover before a competitor is installed"
    );
    after
}

fn plant_incomplete_publication(stopped: &Stopped) {
    use granary_core::retained_submission as retained;

    let rt = runtime();
    let seq = remote_seq(&stopped.tree, &rt);
    let bytes = rt
        .block_on(remote_handle(&stopped.tree.mem).get_root(stopped.tree.volume.as_str(), seq))
        .unwrap()
        .unwrap();
    let input = input(&stopped.tree, &stopped.paths);
    let request = retained::RequestIdentity {
        epoch: [1; 16],
        operation: [2; 16],
    };
    let record = retained::Submission {
        generation: 1,
        publication_id: [3; 16],
        scope: input.scope.unwrap(),
        volume: input.volume,
        frozen: retained::FrozenIntent {
            writer_identity: carrier(stopped).writer,
            min_prefix_bits: 0,
            initial_root: bytes.clone(),
        },
        current: Some(request),
        candidates: vec![retained::Candidate {
            number: 1,
            request,
            role: retained::Role::Active,
            seq,
            id: GrainId::of(&bytes),
            root: bytes,
            evidence: retained::Evidence::default(),
        }],
        phase: retained::Phase::Ready,
        last_response: None,
        unavailable_exemptions: 0,
    };
    let mut store = Store::open(&stopped.paths.store).unwrap();
    let mut publications = store.publications(input.euid).unwrap();
    publications.begin(&record).unwrap();
    assert_eq!(
        publications
            .observe(&record.scope, &record.volume)
            .unwrap()
            .map(|record| record.is_complete()),
        Some(false),
        "an incomplete publication must be visible to acquisition admission"
    );
}

#[test]
fn writable_start_keeps_retained_acquire_while_publication_is_owed() {
    for debt_first in [true, false] {
        let stopped = released();
        let unowned = refused_released_takeover(&stopped);
        let evicted = evict_released_row(&stopped);
        let acquire = intent::OwnershipMode::Acquire {
            observed_cursor: evicted.epoch,
        };
        stopped.state.lock().unwrap().ownership_strict = true;
        if debt_first {
            plant_incomplete_publication(&stopped);
        }
        let input = input(&stopped.tree, &stopped.paths);
        let sent = sends(&stopped);
        let first = restart_with_rule(&input, &stopped.tree, &stopped.state, "always_lost");
        let held = carrier(&stopped);
        let pending = held
            .pending
            .iter()
            .find(|pending| pending.operation == Operation::Ownership && !pending.terminal);
        let row = stopped.state.lock().unwrap().row;
        if debt_first {
            let sent = sends(&stopped) - sent;
            assert_eq!(
                (outcome(&first), held == unowned, sent, row),
                ("WritableRecoveryRequired", true, 0, None),
                "the fresh Acquire control refuses before sending or persisting"
            );
        } else {
            assert_eq!(
                (
                    outcome(&first),
                    held.phase,
                    pending.map(|pending| (
                        intent::decode_ownership(&pending.body).unwrap().mode,
                        pending.answered,
                        pending.attempts,
                    )),
                    handshakes(&stopped, sent),
                    row,
                ),
                (
                    "IntentStartupAttemptsExhausted",
                    Phase::Handshake,
                    Some((acquire, false, 8)),
                    8,
                    None,
                ),
                "transport loss leaves the exact Acquire unresolved before debt appears"
            );
            plant_incomplete_publication(&stopped);
        }

        stopped.state.lock().unwrap().tick += 60_000;
        let sent = sends(&stopped);
        let refused = start_remount(&stopped, 72);
        let after = carrier(&stopped);
        let row = stopped.state.lock().unwrap().row.map(|row| row.epoch);
        assert_eq!(
            (
                outcome(&refused),
                sends(&stopped) - sent,
                after.phase,
                after == held,
                row
            ),
            ("WritableRecoveryRequired", 0, held.phase, true, None),
            "debt_first={debt_first}: publication debt must refuse every Acquire before dispatch"
        );

        Store::open(&stopped.paths.store)
            .unwrap()
            .publications(input.euid)
            .unwrap()
            .inject_selected_for_test(&held.scope, &held.volume, None)
            .unwrap();
        let resumed = start_remount(&stopped, 73);
        let state = stopped.state.lock().unwrap();
        let first = state.sends.get(sent);
        let mode = first.and_then(|body| intent::decode_ownership(body).ok());
        assert_eq!(
            (
                outcome(&resumed),
                carrier(&stopped).phase,
                mode.map(|request| request.mode),
                pending.is_none_or(|pending| first == Some(&pending.body)),
                resumed.as_ref().ok().map(|ready| ready.owner().1),
            ),
            (
                "Ok",
                Phase::Serving,
                Some(acquire),
                true,
                Some(evicted.epoch + 1 + u64::from(!debt_first)),
            ),
            "debt_first={debt_first}: after clearing debt, the next start mounts and any retained Acquire replays exactly"
        );
    }
}

#[test]
fn acquire_compares_hidden_and_concurrent_rows_and_the_current_cursor() {
    use crate::overlay_test_support::AcquireRace;
    for (why, expected) in [
        ("no competitor", "Ok"),
        ("hidden Released row", "IntentSelectionChanged"),
        ("row inserted after readback", "IntentSelectionChanged"),
        ("cursor advanced after readback", "IntentCursorChanged"),
    ] {
        let stopped = released();
        let carrier = refused_released_takeover(&stopped);
        let old = evict_released_row(&stopped);
        let observed = {
            let mut state = stopped.state.lock().unwrap();
            state.ownership_strict = true;
            let holder = Receipt {
                epoch: state.cursor + 1,
                instance: [94; 16],
                ..old
            };
            match why {
                "hidden Released row" => {
                    state.cursor = holder.epoch;
                    state.row = Some(holder);
                }
                "row inserted after readback" => {
                    state.ownership_acquire_race = Some(AcquireRace::Insert(holder));
                }
                "cursor advanced after readback" => {
                    state.ownership_acquire_race = Some(AcquireRace::AdvanceCursor);
                }
                _ => {}
            }
            state.cursor
        };
        let start_sends = sends(&stopped);
        let result = start_remount(&stopped, 70);
        let state = stopped.state.lock().unwrap();
        let attempts: Vec<_> = state.sends[start_sends..]
            .iter()
            .filter_map(|bytes| {
                intent::decode_ownership(bytes)
                    .ok()
                    .map(|request| (request.writer, request.mode))
            })
            .collect();
        assert_eq!(
            (outcome(&result), attempts.as_slice()),
            (
                expected,
                &[(
                    carrier.writer,
                    intent::OwnershipMode::Acquire {
                        observed_cursor: observed
                    }
                )][..]
            ),
            "{why}: one Acquire compares the row set and the exact observed cursor"
        );
    }
}

#[test]
fn a_visible_reacquired_row_stops_the_unowned_start_and_selects_recovery() {
    let fixture = fixture_with(crate::SyncProfile::default());
    let prepared = fixture.state.lock().unwrap().root.clone();
    let (shutdown, stopped) = shut_down_as(
        fixture,
        Trigger::Umount,
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
    );
    assert_eq!(
        shutdown,
        Outcome::Clean,
        "clean release for the competing holder"
    );
    let before = refused_released_takeover(&stopped);
    let old = evict_released_row(&stopped);
    {
        let mut state = stopped.state.lock().unwrap();
        state.ownership_strict = true;
        state.cursor += 1;
        state.row = Some(Receipt {
            epoch: state.cursor,
            instance: [95; 16],
            state: ReceiptState::Live {
                prepared_root_id: GrainId::of(&prepared),
            },
            ..old
        });
        state.root = prepared;
    }
    let start_sends = sends(&stopped);
    let result = start_remount(&stopped, 70);
    let recovery = recover_with(&stopped, before.writer, None, 75);
    assert_eq!(
        (
            outcome(&result),
            recovery
                .err()
                .map(|err| err.to_string().starts_with("IntentSelectionBinding:")),
            sends(&stopped) - start_sends
        ),
        ("WritableRecoveryRequired", Some(true), 0),
        "a Live row selects explicit recovery without an automatic ownership send"
    );
}

#[test]
fn acquire_refuses_a_readback_without_the_requested_scope() {
    for (rule, expected, count) in [
        ("valid", "Ok", 1),
        ("family_scope", "WritableIntentDiscoveryInvalid", 0),
    ] {
        let stopped = released();
        refused_released_takeover(&stopped);
        evict_released_row(&stopped);
        let start_sends = sends(&stopped);
        let input = input(&stopped.tree, &stopped.paths);
        let result = restart_with_rule(&input, &stopped.tree, &stopped.state, rule);
        let state = stopped.state.lock().unwrap();
        let acquires = state.sends[start_sends..]
            .iter()
            .filter(|bytes| intent::decode_ownership(bytes).is_ok())
            .count();
        assert_eq!(
            (outcome(&result), acquires),
            (expected, count),
            "{rule}: only authenticated readback authorizes Acquire"
        );
    }
}

#[test]
fn unowned_recovery_refuses_readback_below_the_continuity_floor() {
    let stopped = released();
    let before = refused_released_takeover(&stopped);
    let old = evict_released_row(&stopped);
    stopped.state.lock().unwrap().cursor = old.epoch - 1;
    let start_sends = sends(&stopped);
    let result = recover_with(&stopped, before.writer, None, 75);
    assert_eq!(
        (
            result.err().map(|err| err.to_string()),
            carrier(&stopped),
            sends(&stopped) - start_sends
        ),
        (
            Some("intent refused: WritableIntentDiscoveryInvalid".into()),
            before,
            0
        ),
        "recovery must check authorized continuity before reporting NothingOwed"
    );
}

/// The two ways a store reaches a fence with no Live row to select.
#[derive(Clone, Copy, Debug)]
enum Stranded {
    /// Local journal work owed after a clean release, its row evicted.
    OwedWork,
    /// A lost Release reply, the row evicted, the replay answered absent.
    LostRelease,
}

/// The stopped store in `shape`, and the evicted row.
fn stranded(shape: Stranded) -> (Stopped, Receipt) {
    match shape {
        Stranded::OwedWork => {
            let stopped = released();
            let start = input(&stopped.tree, &stopped.paths);
            let (header, mut records) = captured_records(&stopped.paths, &start);
            records.push(Record::Create {
                at: at(b"local-only"),
                kind: journal::CreateKind::Dir,
            });
            std::fs::write(
                overlay_area(&stopped.paths, &start).join("journal"),
                journal::encode_journal(&header, &records).unwrap(),
            )
            .unwrap();
            stopped.state.lock().unwrap().tick += intent::released_row_retention_secs(0) * 1000;
            let evicted = evict_released_row(&stopped);
            (stopped, evicted)
        }
        Stranded::LostRelease => {
            let stopped = interrupted(Some(true), true);
            let evicted = evict_released_row(&stopped);
            stopped.state.lock().unwrap().release_answer = ReleaseAnswer::Absent;
            (stopped, evicted)
        }
    }
}

/// A fenced store with no Live row for its writer has no in-place way back:
/// writable start stays fenced, and both `gran recover` forms refuse
/// `IntentSelectedWriterMissing` without a B5 inventory and keep the journal.
/// The operator path the guides state then holds step by step: the plan
/// admits the store, the acknowledged discard archives it and fences it, the
/// archive's reconciliation settles locally with no rows because the
/// journal holds no commit boundary and nothing retained can still land, and
/// a separate fresh store mounts with its own writer at the published head.
#[test]
fn a_fenced_store_without_a_live_row_retires_to_a_fresh_store() {
    use crate::{ArchiveReconciliation, OverlayRefusal, discard_overlay};
    use granary_core::overlay_discard::Outcome as Discard;

    for shape in [Stranded::OwedWork, Stranded::LostRelease] {
        let (stopped, evicted) = stranded(shape);
        let old = carrier(&stopped);
        let start = input(&stopped.tree, &stopped.paths);
        let area = overlay_area(&stopped.paths, &start);
        let records = captured_records(&stopped.paths, &start).1;
        let kept = || {
            (
                std::fs::read(area.join("journal")).unwrap(),
                captured_staging(&stopped.paths, &start),
            )
        };
        let before = kept();
        assert!(
            !records.iter().any(|record| matches!(
                record,
                Record::CommitBoundary { .. } | Record::ProjectedBoundary { .. }
            )),
            "{shape:?}: premise: the journal holds no commit boundary"
        );

        let fenced_start = start_remount(&stopped, 70);
        let fenced = carrier(&stopped);
        let recovered = [None, Some(old.writer)].map(|ack| {
            recover_with(&stopped, old.writer, ack, 80)
                .map(|outcome| format!("{outcome:?}"))
                .map_err(|error| (error.to_string(), error.conflict_inventory().is_some()))
        });
        let refused = (
            "intent refused: IntentSelectedWriterMissing".to_owned(),
            false,
        );
        assert_eq!(
            (
                outcome(&fenced_start),
                fenced.phase,
                fenced.fence,
                recovered,
                kept() == before,
                stopped.state.lock().unwrap().row,
            ),
            (
                "IntentFenced (ESTALE)",
                Phase::Fenced,
                2,
                [Err(refused.clone()), Err(refused)],
                true,
                None,
            ),
            "{shape:?}: no in-place repair, and the journal is kept"
        );
        drop(fenced_start);

        let scope = granary_core::overlay_discard::parse_hex(
            &start.scope.as_ref().unwrap().digest().unwrap(),
        )
        .unwrap();
        let plan = discard_overlay(&stopped.paths.store, scope, &start.volume, None).unwrap();
        let tuple = (plan.name.writer, plan.name.incarnation);
        let discarded = discard_overlay(&stopped.paths.store, scope, &start.volume, Some(tuple));
        let again = discard_overlay(&stopped.paths.store, scope, &start.volume, Some(tuple));
        let archived_start = start_remount(&stopped, 85);
        let reconciled =
            ArchiveReconciliation::open(&stopped.paths.store, scope, &start.volume, tuple)
                .map(|archive| archive.is_settled_locally())
                .map_err(crate::DiscardError::reason);
        assert_eq!(
            (
                matches!(plan.outcome, Discard::Live(_)),
                plan.name.writer == old.writer,
                discarded.map(|row| row.outcome),
                again.map(|row| row.outcome),
                outcome(&archived_start),
                reconciled,
            ),
            (
                true,
                true,
                Ok(Discard::Moved),
                Ok(Discard::AlreadyArchived),
                "OverlayArchived",
                Ok::<_, OverlayRefusal>(true),
            ),
            "{shape:?}: the plan admits the fenced store, discard archives it once, and with \
             no commit boundary reconciliation settles locally with no rows"
        );
        drop(archived_start);

        mount_a_fresh_store(stopped, shape, evicted, old.writer);
    }
}

/// Start writable service from a separate fresh store beside the retired one.
fn mount_a_fresh_store(stopped: Stopped, shape: Stranded, evicted: Receipt, old: [u8; 16]) {
    let Stopped { tree, paths, state } = stopped;
    // The absent answer stood for the evicted row; the fresh writer's
    // own row releases.
    state.lock().unwrap().release_answer = ReleaseAnswer::Released;
    let fresh = Stopped {
        tree,
        paths: Paths::new(),
        state,
    };
    let published = remote_seq(&fresh.tree, &runtime());
    let mut mounted =
        remount(fresh, 90).unwrap_or_else(|error| panic!("{shape:?}: fresh store: {error}"));
    let writer = ownership::decode(
        &std::fs::read(
            overlay_area(&mounted.paths, &input(&mounted.tree, &mounted.paths)).join("ownership"),
        )
        .unwrap(),
    )
    .unwrap()
    .writer;
    let local = read_back(&mut mounted.ready, b"local-only");
    // Control: a published directory is found the same way.
    let published_dir = read_back(&mut mounted.ready, b"empty");
    assert_eq!(
        (
            writer == old,
            mounted.ready.owner().1 > evicted.epoch,
            mounted.ready.verified_base().1,
            paths.store.exists(),
            local,
            published_dir == Err(granary_fuse::WriteError::Missing),
        ),
        (
            false,
            true,
            published,
            true,
            Err(granary_fuse::WriteError::Missing),
            false,
        ),
        "{shape:?}: a separate fresh store mounts at the published head with its own \
         writer; the retired store stays in place"
    );
    assert_clean_release_after_remount(mounted);
}
