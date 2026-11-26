// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Ownership settlement and acquisition admission with persisted local evidence.

use super::*;
use granary_core::overlay_journal::{self as journal, Record};
use granary_core::retained_submission as retained;

const AT: u64 = 1000;

fn absent() -> IntentReply {
    reply(409, Some("intent-absent"), None, vec![])
}

fn complete_absent(
    client: &mut WritableStore<SimIo>,
    request: &PendingIntent,
    at: &Tick,
) -> Result<IntentCompletion, CoordinationError> {
    client.complete(request, Ok(&absent()), at, &mut SeededRng::new(1), 0, None)
}

fn assert_absence_fence(
    client: &mut WritableStore<SimIo>,
    io: &SimIo,
    request: &PendingIntent,
    why: &str,
) {
    let result = complete_absent(client, request, &Tick(AT + 1));
    let after = ownership::decode(&io.recovered_bytes("ownership").unwrap()).unwrap();
    assert_eq!(
        (
            result.err().map(|error| error.to_string()),
            after.phase,
            after.fence
        ),
        (
            Some("intent fenced (ESTALE), recorded generation None".into()),
            Phase::Fenced,
            2
        ),
        "{why}: absence must persist the fence"
    );
}

fn reopen(
    scratch: &Scratch,
    io: &SimIo,
    client: WritableStore<SimIo>,
    edit: impl FnOnce(&mut Carrier),
) -> WritableStore<SimIo> {
    drop(client);
    io.mutate_recovered("ownership", |bytes| {
        let mut carrier = ownership::decode(bytes).unwrap();
        edit(&mut carrier);
        *bytes = ownership::encode(&carrier).unwrap();
    });
    io.crash();
    start(scratch, io, 30)
}

fn write_journal(io: &SimIo, carrier: &Carrier, records: &[Record]) {
    let mut h = header();
    h.writer = carrier.writer;
    let bytes = journal::encode_journal(&h, records).unwrap();
    io.mutate_recovered("journal", |old| *old = bytes);
    io.crash();
}

fn publication(client: &mut WritableStore<SimIo>, archive: bool) {
    let writer = client.writer_uuid();
    let bytes = root(writer, 1);
    let id = GrainId::of(&bytes);
    let scope = client.snapshot().scope.clone();
    let volume = client.snapshot().volume.clone();
    let request = retained::RequestIdentity {
        epoch: [1; 16],
        operation: [2; 16],
    };
    let mut record = retained::Submission {
        generation: 1,
        publication_id: [3; 16],
        scope: scope.clone(),
        volume: volume.clone(),
        frozen: retained::FrozenIntent {
            writer_identity: writer,
            min_prefix_bits: 0,
            initial_root: bytes.clone(),
        },
        current: Some(request),
        candidates: vec![retained::Candidate {
            number: 1,
            request,
            role: retained::Role::Active,
            seq: 1,
            id,
            root: bytes.clone(),
            evidence: retained::Evidence::default(),
        }],
        phase: retained::Phase::Ready,
        last_response: None,
        unavailable_exemptions: 0,
    };
    client
        .publication_transaction(|store| {
            store.begin(&record)?;
            if archive {
                let abandoned = store.abandon(
                    &scope,
                    &volume,
                    record.publication_id,
                    crate::MayLandAcknowledgement::Acknowledged,
                )?;
                assert!(!abandoned.archive.settled, "{abandoned:?}");
                // A complete retained record must not mask the unsettled archive.
                record.publication_id = [4; 16];
                record.current = None;
                record.phase = retained::Phase::Complete(retained::Completion {
                    seq: 1,
                    id,
                    root: bytes,
                    receipt: None,
                });
                store.inject_selected_for_test(&scope, &volume, Some(&record))?;
            }
            let observed = store.observe(&scope, &volume)?;
            assert_eq!(
                observed.as_ref().map(retained::Submission::is_complete),
                Some(archive)
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn clean_absent_takeover_answers_the_exact_request() {
    let (_scratch, io, mut client, mut authority) = released_then_reopened();
    let request = client.prepare_succession(&Tick(AT)).unwrap();
    let selected = client.snapshot().selected.clone();
    authority.row = None;
    let result = exchange(&mut client, &mut authority, &request, AT);
    let after = ownership::decode(&io.recovered_bytes("ownership").unwrap()).unwrap();
    let pending = after
        .pending
        .iter()
        .find(|p| p.operation == Operation::Ownership);
    assert_eq!(
        (
            format!("{result:?}"),
            after.phase,
            after.fence,
            after.selected,
            pending.map(|p| { (p.body.as_slice(), p.terminal, p.answered, p.attempts) })
        ),
        (
            "Ok(TakeoverAbsent)".into(),
            Phase::Unowned,
            0,
            selected,
            Some((request.bytes(), true, true, 1))
        ),
        "durable row judgment settles the exact takeover without discarding its selection"
    );
}

#[test]
fn late_absence_for_an_expired_released_takeover_matches_the_timely_one() {
    for expire_first in [false, true] {
        let (scratch, io, mut client, mut authority) = released_then_reopened();
        let request = client.prepare_succession(&Tick(AT)).unwrap();
        client.dispatch(&request, &Tick(AT)).unwrap();
        authority.row = None;
        let late = Tick(AT + 200_000_000);
        let before = if expire_first {
            client.settle_expired_handshake(&late).unwrap();
            assert_eq!(client.snapshot().phase, Phase::Unowned);
            Some((
                client.snapshot().clone(),
                io.recovered_bytes("ownership").unwrap(),
            ))
        } else {
            None
        };
        let result = complete_absent(&mut client, &request, &late);
        assert!(
            matches!(result, Ok(IntentCompletion::TakeoverAbsent)),
            "expire_first={expire_first}: {result:?}"
        );
        if let Some((snapshot, bytes)) = before {
            assert_eq!(
                (client.snapshot(), io.recovered_bytes("ownership")),
                (&snapshot, Some(bytes))
            );
        }
        drop(client);
        io.crash();
        let reopened = start(&scratch, &io, 70);
        let carrier = reopened.snapshot();
        assert_eq!(
            (carrier.phase, carrier.fence, carrier.validate()),
            (Phase::Unowned, 0, Ok(())),
            "expire_first={expire_first}"
        );
    }
}

#[test]
fn late_absence_for_an_expired_released_takeover_with_publication_debt_fences() {
    let (scratch, io, mut client, mut authority) = released_then_reopened();
    let request = client.prepare_succession(&Tick(AT)).unwrap();
    client.dispatch(&request, &Tick(AT)).unwrap();
    authority.row = None;
    let late = Tick(AT + 200_000_000);
    client.settle_expired_handshake(&late).unwrap();
    assert_eq!(client.snapshot().phase, Phase::Unowned);
    publication(&mut client, false);
    let fenced = complete_absent(&mut client, &request, &late);
    drop(client);
    io.crash();
    let reopened = start(&scratch, &io, 70);
    let carrier = reopened.snapshot();
    assert_eq!(
        (
            matches!(
                fenced,
                Err(CoordinationError::Fenced {
                    recorded_generation: None
                })
            ),
            carrier.phase,
            carrier.fence
        ),
        (true, Phase::Fenced, 2),
        "{fenced:?}"
    );
}

/// Only an expiry-settled takeover is left unchanged: a second absence for a
/// takeover the first absence already answered is owned-request absence.
#[test]
fn repeated_absence_for_a_settled_released_takeover_fences() {
    let (scratch, io, mut client, mut authority) = released_then_reopened();
    let request = client.prepare_succession(&Tick(AT)).unwrap();
    client.dispatch(&request, &Tick(AT)).unwrap();
    authority.row = None;
    let settled = complete_absent(&mut client, &request, &Tick(AT));
    assert!(
        matches!(settled, Ok(IntentCompletion::TakeoverAbsent)),
        "{settled:?}"
    );
    assert_eq!(client.snapshot().phase, Phase::Unowned);
    let repeated = complete_absent(&mut client, &request, &Tick(AT + 1));
    drop(client);
    io.crash();
    let reopened = start(&scratch, &io, 70);
    let carrier = reopened.snapshot();
    assert_eq!(
        (
            matches!(
                repeated,
                Err(CoordinationError::Fenced {
                    recorded_generation: None
                })
            ),
            carrier.phase,
            carrier.fence
        ),
        (true, Phase::Fenced, 2),
        "{repeated:?}"
    );
}

#[test]
fn live_register_and_release_absence_fences() {
    for why in ["live takeover", "register", "release"] {
        let (_scratch, io, mut client, _authority) = serving();
        let request = match why {
            "live takeover" => client.prepare_succession(&Tick(AT)).unwrap(),
            "register" => client
                .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(AT), |_, _| {
                    true
                })
                .unwrap(),
            _ => client
                .prepare_release(&Tick(AT), crate::DEFAULT_RESOLUTION_BOUND, None)
                .unwrap(),
        };
        client.dispatch(&request, &Tick(AT)).unwrap();
        assert_absence_fence(&mut client, &io, &request, why);
    }
}

#[test]
fn absent_takeover_checks_the_expected_and_current_states_independently() {
    for expected_live in [true, false] {
        let (scratch, io, mut client, _authority) = released_then_reopened();
        let request = client.prepare_succession(&Tick(AT)).unwrap();
        client.dispatch(&request, &Tick(AT)).unwrap();
        let mut client = reopen(&scratch, &io, client, |carrier| {
            let bytes = root(carrier.writer, 1);
            let live = ReceiptState::Live {
                prepared_root_id: GrainId::of(&bytes),
            };
            let mut receipt = intent::decode_receipt(&carrier.current).unwrap();
            receipt.state = live;
            if expected_live {
                carrier.selected = intent::encode_receipt(receipt).unwrap();
                carrier.selected_root = bytes;
                let pending = carrier
                    .pending
                    .iter_mut()
                    .find(|p| p.operation == Operation::Ownership)
                    .unwrap();
                let mut request = intent::decode_ownership(&pending.body).unwrap();
                let OwnershipMode::Takeover { state, .. } = &mut request.mode else {
                    panic!("{request:?}")
                };
                *state = live;
                pending.body = intent::encode_ownership(request).unwrap();
            } else {
                carrier.current = intent::encode_receipt(receipt).unwrap();
                carrier.root = bytes;
            }
        });
        let [request]: [PendingIntent; 1] =
            client
                .retained_requests()
                .try_into()
                .unwrap_or_else(|requests: Vec<_>| {
                    panic!("expected one retained takeover, got {}", requests.len())
                });
        assert_absence_fence(
            &mut client,
            &io,
            &request,
            if expected_live {
                "Live selection"
            } else {
                "Live current receipt"
            },
        );
    }
}

#[test]
fn consented_released_takeover_absence_fences() {
    for retained_fence in [0, 2] {
        let (scratch, io, mut client, _authority) = released_then_reopened();
        let request = client.prepare_succession(&Tick(AT)).unwrap();
        client.dispatch(&request, &Tick(AT)).unwrap();
        let mut client = reopen(&scratch, &io, client, |carrier| {
            carrier.fence = retained_fence;
            let slot = carrier
                .pending
                .iter()
                .position(|p| p.operation == Operation::Ownership)
                .unwrap();
            let mut request = intent::decode_ownership(&carrier.pending[slot].body).unwrap();
            let OwnershipMode::Takeover { recovery_ack, .. } = &mut request.mode else {
                panic!("{request:?}")
            };
            *recovery_ack = true;
            let body = intent::encode_ownership(request).unwrap();
            carrier.consent = ownership::recovery_consent(carrier, &body).unwrap();
            carrier.pending[slot].body = body;
        });
        let [request]: [PendingIntent; 1] =
            client
                .retained_requests()
                .try_into()
                .unwrap_or_else(|requests: Vec<_>| {
                    panic!("expected one retained takeover, got {}", requests.len())
                });
        assert_absence_fence(&mut client, &io, &request, "consented Released takeover");
    }
}

#[test]
fn absent_takeover_with_another_request_or_context_fences() {
    for why in ["nonterminal Release", "terminal Register context"] {
        let (scratch, io, mut client, _authority) = released_then_reopened();
        let request = client.prepare_succession(&Tick(AT)).unwrap();
        client.dispatch(&request, &Tick(AT)).unwrap();
        let mut client = reopen(&scratch, &io, client, |carrier| {
            let release = carrier
                .pending
                .iter_mut()
                .find(|p| p.operation == Operation::Release)
                .unwrap();
            if why == "nonterminal Release" {
                release.terminal = false;
                release.answered = false;
            } else {
                let held = intent::decode_release(&release.body).unwrap();
                let body = intent::encode_register(
                    &held.writer,
                    held.epoch,
                    &held.instance,
                    held.generation,
                    &root(held.writer, 1),
                )
                .unwrap();
                let mut register = release.clone();
                register.operation = Operation::Register;
                register.body = body;
                register.answer.clear();
                register.context = vec![1];
                carrier.pending.insert(1, register);
            }
        });
        assert_absence_fence(&mut client, &io, &request, why);
    }
}

#[test]
fn absent_takeover_outside_nonterminal_handshake_fences() {
    for why in ["terminal handshake", "outside Handshake"] {
        let (scratch, io, mut client, _authority) = released_then_reopened();
        let request = client.prepare_succession(&Tick(AT)).unwrap();
        client.dispatch(&request, &Tick(AT)).unwrap();
        let mut client = reopen(&scratch, &io, client, |carrier| {
            if why == "terminal handshake" {
                let pending = carrier
                    .pending
                    .iter_mut()
                    .find(|p| p.operation == Operation::Ownership)
                    .unwrap();
                pending.terminal = true;
            } else {
                carrier.phase = Phase::Released;
            }
        });
        assert_absence_fence(&mut client, &io, &request, why);
    }
}

#[test]
fn absent_released_takeover_with_local_work_fences() {
    for why in [
        "incomplete publication",
        "unsettled archive",
        "dirty journal",
        "open boundary",
        "unrefreshed landing",
        "staging without journal",
    ] {
        let (_scratch, mut io, mut client, _authority) = released_then_reopened();
        let request = client.prepare_succession(&Tick(AT)).unwrap();
        client.dispatch(&request, &Tick(AT)).unwrap();
        match why {
            "incomplete publication" => publication(&mut client, false),
            "unsettled archive" => publication(&mut client, true),
            "dirty journal" => write_journal(
                &io,
                client.snapshot(),
                &[Record::Create {
                    at: journal::Location {
                        parent: journal::Parent::root(),
                        name: Name::new(b"local".to_vec()).unwrap(),
                    },
                    kind: journal::CreateKind::Dir,
                }],
            ),
            "open boundary" | "unrefreshed landing" => {
                let mut records = vec![Record::CommitBoundary {
                    candidate: grain(2),
                    through_seq: 0,
                    publication_id: [1; 16],
                }];
                if why == "unrefreshed landing" {
                    records.push(Record::LandedCommit {
                        boundary_seq: 1,
                        landed_root: grain(2),
                        landed_seq: 2,
                    });
                }
                write_journal(&io, client.snapshot(), &records);
            }
            _ => {
                let files = io.tree();
                let path = files.keys().find(|path| path.ends_with("journal")).unwrap();
                io.remove(path).unwrap();
                io.create(&path.with_file_name("staging").join("0000000000000001"))
                    .unwrap();
            }
        }
        assert_absence_fence(&mut client, &io, &request, why);
    }
}

#[test]
fn absent_takeover_fails_closed_on_a_journal_read_error() {
    let (_scratch, io, mut client, _authority) = released_then_reopened();
    let request = client.prepare_succession(&Tick(AT)).unwrap();
    client.dispatch(&request, &Tick(AT)).unwrap();
    io.0.lock().unwrap().read_error_at = Some(0);
    assert_absence_fence(&mut client, &io, &request, "journal read failure");
}

fn settle_recovery_at(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    at: u64,
) -> Result<(), crate::WritableStartError> {
    crate::writable_start::settle_recovery(client, &Tick(at), |client, request, _| {
        exchange(client, authority, request, at)?;
        Ok(())
    })
}

#[test]
fn retained_acquire_waits_for_publication_debt_to_clear() {
    for expire in [false, true] {
        let (scratch, io, mut client, mut authority) = released_then_reopened();
        let takeover = client.prepare_succession(&Tick(AT)).unwrap();
        authority.row = None;
        let settled = exchange(&mut client, &mut authority, &takeover, AT);
        assert_eq!(
            (settled.unwrap(), client.snapshot().phase),
            (IntentCompletion::TakeoverAbsent, Phase::Unowned)
        );
        let acquire = client
            .prepare_acquire(authority.cursor, &Tick(AT + 10))
            .unwrap();
        // Crash after recording the dispatch while the authority is unreachable.
        client.dispatch(&acquire, &Tick(AT + 10)).unwrap();
        publication(&mut client, false);
        drop(client);
        io.crash();
        let mut client = start(&scratch, &io, 60);
        let held = client.snapshot().clone();
        let pending = held
            .pending
            .iter()
            .find(|pending| pending.operation == Operation::Ownership)
            .unwrap();
        let lifecycle = (pending.attempts, pending.terminal, pending.answered);
        assert_eq!(
            (
                held.phase,
                pending.body.as_slice(),
                lifecycle,
                client.owes_nothing(),
                authority.row,
            ),
            (
                Phase::Handshake,
                acquire.bytes(),
                (1, false, false),
                false,
                None
            ),
            "an unresolved Acquire and publication debt survived restart"
        );

        let sent = authority.sends.len();
        let result = settle_recovery_at(&mut client, &mut authority, AT + 5000);
        let durable = ownership::decode(&io.recovered_bytes("ownership").unwrap()).unwrap();
        let recovery_required = Some("WritableRecoveryRequired");
        assert_eq!(
            (
                result.err().map(|error| error.name()),
                authority.sends.len() - sent,
                client.snapshot().phase,
                durable == held,
                authority.row.map(|row| row.epoch),
            ),
            (recovery_required, 0, Phase::Handshake, true, None),
            "publication debt must stop retained Acquire before dispatch"
        );

        if expire {
            settle_recovery_at(&mut client, &mut authority, pending.expires).unwrap();
            let result = client.prepare_acquire(authority.cursor, &Tick(pending.expires));
            let refusal = result.err().map(|error| error.to_string());
            let expected = Some("intent refused: WritableRecoveryRequired");
            assert_eq!(
                (
                    client.snapshot().phase,
                    client.retained_requests().len(),
                    authority.sends.len() - sent,
                    refusal.as_deref(),
                ),
                (Phase::Unowned, 0, 0, expected),
                "expiry retires the retained Acquire and fresh admission still refuses debt"
            );
        } else {
            client
                .publication_transaction(|store| {
                    store.inject_selected_for_test(&held.scope, &held.volume, None)
                })
                .unwrap();
            let result = settle_recovery_at(&mut client, &mut authority, AT + 5001);
            let replay = std::slice::from_ref(&pending.body);
            let epoch = Some(authority.cursor);
            assert_eq!(
                (
                    result.map_err(|error| error.name()),
                    client.snapshot().phase,
                    &authority.sends[sent..],
                    authority.row.map(|row| row.epoch),
                ),
                (Ok(()), Phase::OwnedStart, replay, epoch),
                "clearing debt allows recovery to settle the exact retained Acquire"
            );
        }
    }
}

#[test]
fn retained_takeover_replays_with_publication_debt() {
    let (_scratch, _io, mut client, mut authority) = released_then_reopened();
    let takeover = client.prepare_succession(&Tick(AT)).unwrap();
    client.dispatch(&takeover, &Tick(AT)).unwrap();
    publication(&mut client, false);
    let owes_nothing = client.owes_nothing();
    assert!(
        !owes_nothing,
        "owes_nothing={owes_nothing} with an incomplete publication"
    );
    let sent = authority.sends.len();
    let result = settle_recovery_at(&mut client, &mut authority, AT + 5000);
    assert_eq!(
        (
            result.map_err(|error| error.name()),
            client.snapshot().phase,
            authority.sends[sent..]
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
        ),
        (Ok(()), Phase::OwnedStart, vec![takeover.bytes()]),
        "publication debt does not block replay of a retained Takeover"
    );
}

#[test]
fn reacquiring_after_handshake_settlement_requires_no_debt() {
    for expired in [true, false] {
        let (scratch, io, mut client, mut authority) = if expired {
            serving()
        } else {
            released_then_reopened()
        };
        let request = client.prepare_succession(&Tick(AT)).unwrap();
        if expired {
            client
                .settle_expired_handshake(&Tick(AT + 86_400_000))
                .unwrap();
            authority.row.as_mut().unwrap().state = ReceiptState::Released;
            authority.root.clear();
        } else {
            let refused = exchange_with(&mut client, &request, AT, || {
                reply(403, Some("no-principal"), None, vec![])
            });
            assert_eq!(
                refused.err().map(|error| error.to_string()).as_deref(),
                Some("intent refused: IntentTerminalRefusal")
            );
            publication(&mut client, false);
            authority.row = None;
        }
        drop(client);
        io.crash();
        let mut client = start(&scratch, &io, 40);
        let before = client.snapshot().clone();
        let result = client.prepare_acquire(authority.cursor, &Tick(AT + 90_000_000));
        assert_eq!(
            (
                before.phase,
                authority.root.is_empty(),
                result.err().map(|error| error.to_string()),
                client.snapshot()
            ),
            (
                Phase::Unowned,
                true,
                Some("intent refused: WritableRecoveryRequired".into()),
                &before
            ),
            "expired={expired}: debt refuses acquisition without changing the retained evidence"
        );
    }
}

#[test]
fn a_new_writer_with_no_history_can_acquire() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 30);
    publication(&mut client, false);
    let mut authority = Authority::default();
    acquire(&mut client, &mut authority);
    assert_eq!(
        (client.snapshot().phase, authority.cursor),
        (Phase::OwnedStart, 1)
    );
}

#[test]
fn a_retained_acquire_at_zero_is_history() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 30);
    let request = client.prepare_acquire(0, &Tick(AT)).unwrap();
    let refused = exchange_with(&mut client, &request, AT, || {
        reply(403, Some("no-principal"), None, vec![])
    });
    assert_eq!(
        refused.err().map(|error| error.to_string()).as_deref(),
        Some("intent refused: IntentTerminalRefusal")
    );
    publication(&mut client, false);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 40);
    let before = client.snapshot().clone();
    let result = client.prepare_acquire(0, &Tick(AT + 2));
    assert_eq!(
        (
            before.cursor,
            result.err().map(|error| error.to_string()),
            client.snapshot()
        ),
        (
            0,
            Some("intent refused: WritableRecoveryRequired".into()),
            &before
        ),
        "an exact persisted Acquire distinguishes a known zero cursor from a new writer"
    );
}

#[test]
fn authenticated_cursor_must_cover_every_retained_floor_source() {
    for why in [
        "current epoch",
        "selected epoch",
        "persisted cursor",
        "selected cursor",
    ] {
        let (scratch, io, mut client, _authority) = released_then_reopened();
        let request = client.prepare_succession(&Tick(AT)).unwrap();
        exchange_with(&mut client, &request, AT, || {
            reply(403, Some("no-principal"), None, vec![])
        })
        .unwrap_err();
        let mut client = reopen(&scratch, &io, client, |carrier| {
            carrier
                .pending
                .retain(|p| p.operation != Operation::Ownership);
            // Each arm has one source at the floor and all other sources below it.
            let mut receipt = intent::decode_receipt(&carrier.current).unwrap();
            carrier.selected.clear();
            carrier.cursor = 0;
            carrier.selected_cursor = 0;
            match why {
                "current epoch" => {}
                "selected epoch" => {
                    receipt.epoch += 1;
                    carrier.selected = intent::encode_receipt(receipt).unwrap();
                }
                "persisted cursor" => carrier.cursor = receipt.epoch + 1,
                _ => carrier.selected_cursor = receipt.epoch + 1,
            }
        });
        let before = client.snapshot().clone();
        let floor = intent::decode_receipt(&before.current).unwrap().epoch
            + u64::from(why != "current epoch");
        let result = client.prepare_acquire(floor - 1, &Tick(AT + 10));
        assert_eq!(
            (
                result.err().map(|error| error.to_string()),
                client.snapshot()
            ),
            (
                Some("intent refused: WritableIntentDiscoveryInvalid".into()),
                &before
            ),
            "{why}: a cursor immediately below its floor must refuse without updating the carrier"
        );
        let request = client.prepare_acquire(floor, &Tick(AT + 10)).unwrap();
        assert_eq!(
            (
                intent::decode_ownership(request.bytes()).unwrap().mode,
                client.snapshot().phase
            ),
            (
                OwnershipMode::Acquire {
                    observed_cursor: floor
                },
                Phase::Handshake
            ),
            "{why}: an equal cursor is eligible"
        );
    }
}
