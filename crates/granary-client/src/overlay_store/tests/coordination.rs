// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Mount-less authority schedules share the file/directory durability model.

mod bundle;
mod engine;

use super::*;
use crate::intent_transport::{IntentReply, IntentTransportError};
use crate::writable_store::{CoordinationError, PendingIntent, WritableStore};
use granary_core::clock::Clock;
use granary_core::intent::{self, Grant, OwnershipMode, Receipt, ReceiptState};
use granary_core::overlay_ownership::{Operation, Phase, REPLACEMENT_RESERVE};
use granary_core::rng::SeededRng;
use granary_core::root::{RootDoc, RootSig, Timestamp};

mod local_content;
mod release;

struct Tick(u64);
impl Clock for Tick {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: i64::try_from(self.0 / 1000).unwrap(),
            nanos: (self.0 % 1000) as u32 * 1_000_000,
        }
    }
}
struct Entropy(u8);
impl granary_core::secure_random::SecureRandom for Entropy {
    fn fill(
        &mut self,
        out: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        out.fill(self.0);
        self.0 += 1;
        Ok(())
    }
}
fn reply(status: u16, token: Option<&str>, media: Option<&str>, body: Vec<u8>) -> IntentReply {
    IntentReply {
        scope: Some(granary_core::retained_submission::Scope {
            authority_base: b"https://fixture.invalid".to_vec(),
            pins: vec![],
            credential_context: b"test".to_vec(),
        }),
        volume: Some(VolumeName::from_bytes(b"v").unwrap()),
        status,
        token: token.map(str::to_owned),
        media_type: media.map(str::to_owned),
        body,
        retry_after: None,
    }
}
#[derive(Default)]
struct Authority {
    row: Option<Receipt>,
    root: Vec<u8>,
    cursor: u64,
    grants: BTreeMap<GrainId, Grant>,
    sends: Vec<Vec<u8>>,
}
impl Authority {
    #[expect(
        clippy::too_many_lines,
        reason = "the deterministic fake applies each complete wire transition without network or callbacks"
    )]
    fn send(&mut self, request: &PendingIntent) -> IntentReply {
        self.sends.push(request.bytes().to_vec());
        match request.operation() {
            Operation::Ownership => {
                let decoded = intent::decode_ownership(request.bytes()).unwrap();
                let request_id = GrainId::of(request.bytes());
                if let Some(generation) = self.grants.get(&request_id)
                    && self.row.is_some_and(|row| {
                        (row.epoch, row.instance)
                            == (generation.receipt.epoch, generation.receipt.instance)
                    })
                {
                    return reply(
                        200,
                        None,
                        Some(intent::MEDIA_GRANT),
                        intent::encode_grant(*generation).unwrap(),
                    );
                }
                match decoded.mode {
                    OwnershipMode::Acquire { observed_cursor } => {
                        if self.row.is_some() {
                            return self.recorded(409, Some("intent-changed"));
                        }
                        if observed_cursor != self.cursor {
                            return reply(409, Some("intent-cursor-changed"), None, vec![]);
                        }
                        self.cursor += 1;
                        self.row = Some(Receipt {
                            writer: decoded.writer,
                            epoch: self.cursor,
                            instance: decoded.instance,
                            generation: 0,
                            state: ReceiptState::Released,
                        });
                    }
                    OwnershipMode::Takeover {
                        expected_epoch,
                        generation,
                        state,
                        ..
                    } => {
                        let Some(current) = self.row else {
                            return reply(409, Some("intent-absent"), None, vec![]);
                        };
                        if current.epoch > expected_epoch {
                            return self.recorded(409, Some("intent-superseded"));
                        }
                        if (current.epoch, current.generation, current.state)
                            != (expected_epoch, generation, state)
                        {
                            return self.recorded(409, Some("intent-changed"));
                        }
                        self.cursor += 1;
                        self.row = Some(Receipt {
                            epoch: self.cursor,
                            instance: decoded.instance,
                            ..current
                        });
                    }
                }
                let generation = Grant {
                    request_id,
                    receipt: self.row.unwrap(),
                };
                self.grants.insert(request_id, generation);
                reply(
                    200,
                    None,
                    Some(intent::MEDIA_GRANT),
                    intent::encode_grant(generation).unwrap(),
                )
            }
            Operation::Register => {
                let decoded =
                    intent::decode_register(request.bytes(), request.volume(), |_, _| true)
                        .unwrap();
                let Some(current) = self.row else {
                    return reply(409, Some("intent-absent"), None, vec![]);
                };
                if (decoded.epoch, decoded.instance) != (current.epoch, current.instance) {
                    return self.recorded(409, Some("intent-superseded"));
                }
                if decoded.generation < current.generation
                    || (decoded.generation == current.generation
                        && current.state == ReceiptState::Released)
                {
                    return self.recorded(409, Some("intent-superseded"));
                }
                if decoded.generation == current.generation
                    && current.state
                        != (ReceiptState::Live {
                            prepared_root_id: decoded.root_id(),
                        })
                {
                    return self.recorded(409, Some("intent-bound"));
                }
                self.row = Some(Receipt {
                    generation: decoded.generation,
                    state: ReceiptState::Live {
                        prepared_root_id: decoded.root_id(),
                    },
                    ..current
                });
                self.root = decoded.root.to_vec();
                self.recorded(200, None)
            }
            Operation::Release => {
                let decoded = intent::decode_release(request.bytes()).unwrap();
                let Some(current) = self.row else {
                    return reply(409, Some("intent-absent"), None, vec![]);
                };
                if (decoded.epoch, decoded.instance) != (current.epoch, current.instance) {
                    return self.recorded(409, Some("intent-superseded"));
                }
                self.row = Some(Receipt {
                    generation: decoded.generation.max(current.generation),
                    state: ReceiptState::Released,
                    ..current
                });
                self.root.clear();
                self.recorded(200, None)
            }
        }
    }
    fn recorded(&self, status: u16, token: Option<&str>) -> IntentReply {
        reply(
            status,
            token,
            Some(intent::MEDIA_RECEIPT),
            intent::encode_receipt(self.row.unwrap()).unwrap(),
        )
    }
}
fn root(writer: [u8; 16], seed: u8) -> Vec<u8> {
    granary_core::root::encode_root(&RootDoc {
        volume: VolumeName::from_bytes(b"v").unwrap(),
        seq: 1,
        parent: None,
        writer_uuid: writer,
        epoch: 1,
        timestamp: Timestamp {
            secs: i64::from(seed),
            nanos: 0,
        },
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: grain(1),
        binmap_index: grain(2),
        sheaf_head: grain(3),
        sigs: vec![RootSig {
            key_id: [4; 32],
            sig: [5; 64],
        }],
    })
    .unwrap()
}
fn try_start(
    scratch: &Scratch,
    io: &SimIo,
    entropy: u8,
) -> Result<WritableStore<SimIo>, CoordinationError> {
    let mut client = config(&scratch.0);
    client.cap = 134_217_728;
    client.ownership_completion_reserve = REPLACEMENT_RESERVE;
    WritableStore::new(
        Store::open(&scratch.0).unwrap(),
        client,
        io.clone(),
        &mut Entropy(entropy),
        FaultControl::default(),
        |_, _| true,
    )
}
fn acquire(client: &mut WritableStore<SimIo>, authority: &mut Authority) {
    let request = client.prepare_acquire(authority.cursor, &Tick(1)).unwrap();
    client.dispatch(&request, &Tick(1)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(2),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
}
fn start(scratch: &Scratch, io: &SimIo, entropy: u8) -> WritableStore<SimIo> {
    try_start(scratch, io, entropy).unwrap()
}

fn open(client: &mut WritableStore<SimIo>, io: &SimIo) {
    let mut h = header();
    h.writer = client.writer_uuid();
    client
        .open_overlay(h, vec![], &mut Source::default(), io.clone())
        .unwrap();
}
fn register(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    seed: u8,
) -> PendingIntent {
    let request = client
        .prepare_registration(
            &root(client.writer_uuid(), seed),
            vec![],
            &Tick(3),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&request, &Tick(3)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(4),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    request
}
fn serving() -> (Scratch, SimIo, WritableStore<SimIo>, Authority) {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority::default();
    acquire(&mut client, &mut authority);
    open(&mut client, &io);
    register(&mut client, &mut authority, 1);
    (scratch, io, client, authority)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one row keeps open hashing, cached-layout persistence and cap charging together"
)]
fn carrier_persist_reuses_open_unmerged_hash_and_charges_cached_lengths() {
    let scratch = Scratch::new();
    let mut io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority::default();
    acquire(&mut client, &mut authority);
    let area = scratch
        .0
        .join("overlay")
        .join(config(&scratch.0).scope.digest().unwrap())
        .join("v");
    let mut h = header();
    h.writer = client.writer_uuid();
    h.next_stage_id = 100;
    let journal = codec::encode_journal(&h, &[]).unwrap();
    io.create(&area.join("journal")).unwrap();
    io.write_at(&area.join("journal"), 0, &journal).unwrap();
    let payload = b"installed export";
    let mut hasher = codec::ResidualPayloadHasher::new(99, payload.len() as u64);
    hasher.update(payload);
    let file = codec::ResidualFile {
        stage_id: 99,
        at: at("installed"),
        exec: false,
        local_size: payload.len() as u64,
        payload_check: hasher.finalize(),
    };
    let listing = codec::UnmergedPath {
        writer: h.writer,
        record: codec::ResidualDisposition {
            boundary_seq: 1,
            publication_id: [7; 16],
            landed_root: h.base_root,
            landed_seq: h.base_seq,
            source_end: 1,
            disposition: codec::ResidualMode::KeepRemote,
            collision_count: 1,
            inventory_check: codec::residual_inventory_check(std::slice::from_ref(&file)).unwrap(),
        },
        file,
    }
    .encode()
    .unwrap();
    let mut staged = StagingHeader {
        writer: h.writer,
        stage_id: 99,
        mark: MarkState::Absent,
    }
    .encode()
    .unwrap();
    staged.extend_from_slice(payload);
    let unmerged = area.join("unmerged");
    io.create_directory(&unmerged).unwrap();
    for (name, bytes) in [
        ("0000000000000063.path", listing.as_slice()),
        ("0000000000000063", staged.as_slice()),
    ] {
        let path = unmerged.join(name);
        io.create(&path).unwrap();
        io.write_at(&path, 0, bytes).unwrap();
    }
    let trace = io.0.lock().unwrap().trace.len();
    client
        .open_overlay(h, vec![], &mut Source::default(), io.clone())
        .unwrap();
    register(&mut client, &mut authority, 1);
    let hash_passes = io.0.lock().unwrap().trace[trace..]
        .iter()
        .filter(|(operation, _)| operation == "unmerged")
        .count();
    let foreign = unmerged.join("foreign");
    io.create(&foreign).unwrap();
    let changed = client
        .set_carrier_root_for_test(Vec::new())
        .map_or_else(|error| error.to_string(), |()| "Ok".to_owned());
    io.remove(&foreign).unwrap();
    let control = ["writer", "journal"]
        .into_iter()
        .try_fold(0_u64, |total, name| {
            total.checked_add(io.length(&area.join(name)).unwrap().unwrap())
        })
        .unwrap();
    client.cap_for_test(
        control + REPLACEMENT_RESERVE + listing.len() as u64 + staged.len() as u64 - 1,
    );
    let over_cap = client
        .set_carrier_root_for_test(Vec::new())
        .unwrap_err()
        .to_string();
    let final_hash_passes = io.0.lock().unwrap().trace[trace..]
        .iter()
        .filter(|(operation, _)| operation == "unmerged")
        .count();
    assert_eq!(
        (hash_passes, changed, over_cap, final_hash_passes, 1),
        (
            1,
            "intent refused: IntentUnmergedChanged".to_owned(),
            "intent refused: IntentCapExhausted".to_owned(),
            1,
            1,
        )
    );
}

#[test]
fn carrier_persist_refuses_unclassified_unmerged_before_write() {
    let scratch = Scratch::new();
    let mut io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let area = scratch
        .0
        .join("overlay")
        .join(config(&scratch.0).scope.digest().unwrap())
        .join("v");
    io.create_directory(&area.join("unmerged")).unwrap();
    let before = io.bytes(&area.join("ownership"));
    let refusal = client.prepare_acquire(0, &Tick(1)).unwrap_err().to_string();
    assert_eq!(
        (refusal, io.bytes(&area.join("ownership")) == before, 1),
        (
            "intent refused: IntentUnmergedUnclassified".to_owned(),
            true,
            1,
        )
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "paired replay fixtures keep the stage, mirror and admission evidence together"
)]
fn initial_state_case(case: &str) -> usize {
    let scratch = Scratch::new();
    let mut io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority::default();
    acquire(&mut client, &mut authority);
    let content = GrainId::of(b"old");
    let base = vec![OverlayEntry {
        path: vec![name("f")],
        inode: 0,
        kind: OverlayKind::File {
            content: Some(content),
        },
        stage_id: None,
        size: 3,
        exec: false,
    }];
    let mut source = Source::default();
    source.0.insert(content, b"old".to_vec());
    source.0.insert(GrainId::of(b"new"), b"new".to_vec());
    let mut h = header();
    h.writer = client.writer_uuid();
    client
        .open_overlay(h, base.clone(), &mut source, io.clone())
        .unwrap();
    register(&mut client, &mut authority, 1);
    let area = scratch
        .0
        .join("overlay")
        .join(config(&scratch.0).scope.digest().unwrap())
        .join("v");
    let mut records = vec![
        codec::Record::StageBind {
            cause: if case == "copy up" {
                codec::BindCause::CopyUp
            } else {
                codec::BindCause::Rebind
            },
            at: at("f"),
            stage_id: 1,
            staged_size: 3,
            base_content: content,
        },
        codec::Record::Truncate {
            stage_id: 1,
            new_size: 3,
        },
    ];
    match case {
        "extent" => records.push(codec::Record::WriteExtent {
            stage_id: 1,
            offset: 0,
            length: 3,
            check: codec::extent_check(1, 0, b"new"),
        }),
        "zeros" => records.extend([
            codec::Record::Truncate {
                stage_id: 1,
                new_size: 1,
            },
            codec::Record::Truncate {
                stage_id: 1,
                new_size: 3,
            },
        ]),
        "size" => records.push(codec::Record::Truncate {
            stage_id: 1,
            new_size: 2,
        }),
        "namespace" => records.push(codec::Record::Move {
            from: at("f"),
            to: at("g"),
        }),
        "exec" => records.push(codec::Record::SetattrExec {
            at: at("f"),
            exec: true,
        }),
        _ => {}
    }
    h.next_stage_id = if case == "copy up" { 1 } else { 2 };
    let journal = codec::encode_journal(&h, &records).unwrap();
    let path = area.join("journal");
    io.resize(&path, 0).unwrap();
    io.write_at(&path, 0, &journal).unwrap();
    let mark = match case {
        "matching mark" | "mark content" | "mark size" => {
            codec::MarkState::Present(codec::SyncedMark {
                generation: 1,
                content: if case == "mark content" {
                    GrainId::of(b"new")
                } else {
                    content
                },
                synced_size: if case == "mark size" { 2 } else { 3 },
            })
        }
        _ => codec::MarkState::Absent,
    };
    let stage = area.join("staging").join("0000000000000001");
    io.create(&stage).unwrap();
    let mut bytes = codec::StagingHeader {
        writer: h.writer,
        stage_id: 1,
        mark,
    }
    .encode()
    .unwrap();
    bytes.extend_from_slice(match case {
        "extent" | "divergent body" | "mark content" => b"new",
        "short body" => b"ol",
        "long body" => b"old extra",
        _ => b"old",
    });
    io.write_at(&stage, 0, &bytes).unwrap();
    if case == "missing body" {
        io.remove(&stage).unwrap();
    }
    let opened = client.open_overlay(h, base, &mut source, io.clone());
    let evidence = (
        io.bytes(&path),
        io.length(&stage).unwrap().map(|_| io.bytes(&stage)),
    );
    let before = authority.sends.len();
    let result = opened.and_then(|()| client.check_initial_state());
    let ready = matches!(
        case,
        "ready" | "matching mark" | "short body" | "divergent body" | "long body" | "missing body"
    );
    let refusal = (!ready).then_some("intent refused: WritableRecoveryRequired");
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string),
            authority.sends.len() - before,
            io.bytes(&path) == evidence.0,
            io.length(&stage).unwrap().map(|_| io.bytes(&stage)) == evidence.1
        ),
        (refusal.map(str::to_owned), 0, true, true),
        "case={case}: {result:?}"
    );
    if ready {
        assert_eq!(
            (
                client
                    .overlay_transaction(|t| t.read_stage(1, 0, 3))
                    .unwrap(),
                io.length(&stage).unwrap(),
            ),
            (b"old".to_vec(), Some(163)),
            "case={case}: repaired bytes and staging length"
        );
    }
    1
}

#[test]
fn initial_state_ready_accepts_rebound_stages_and_matching_marks() {
    let mut cases = 0;
    for case in ["ready", "matching mark"] {
        cases += initial_state_case(case);
    }
    assert_eq!(cases, 2);
}

#[test]
fn initial_state_ready_repairs_short_rebound_body() {
    assert_eq!(initial_state_case("short body"), 1);
}

#[test]
fn initial_state_ready_repairs_divergent_rebound_body() {
    assert_eq!(initial_state_case("divergent body"), 1);
}

#[test]
fn initial_state_ready_repairs_long_rebound_body() {
    assert_eq!(initial_state_case("long body"), 1);
}

#[test]
fn initial_state_ready_repairs_missing_rebound_body() {
    assert_eq!(initial_state_case("missing body"), 1);
}

#[test]
fn initial_state_ready_refuses_unfinished_copy_up() {
    assert_eq!(initial_state_case("copy up"), 1);
}

#[test]
fn initial_state_ready_refuses_same_length_extents() {
    assert_eq!(initial_state_case("extent"), 1);
}

#[test]
fn initial_state_ready_refuses_shrink_regrow_zeros() {
    assert_eq!(initial_state_case("zeros"), 1);
}

#[test]
fn initial_state_ready_refuses_changed_size_namespace_and_exec() {
    let mut cases = 0;
    for case in ["size", "namespace", "exec"] {
        cases += initial_state_case(case);
    }
    assert_eq!(cases, 3);
}

#[test]
fn initial_state_ready_refuses_other_mark_content() {
    assert_eq!(initial_state_case("mark content"), 1);
}

#[test]
fn initial_state_ready_refuses_other_mark_size() {
    assert_eq!(initial_state_case("mark size"), 1);
}

#[test]
fn coordination_fresh_bootstrap_and_prepared_never_becomes_head() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority::default();
    let writer = client.writer_uuid();
    acquire(&mut client, &mut authority);
    open(&mut client, &io);
    assert!(matches!(
        client.overlay_transaction(|t| t.create_file(at("early"), false)),
        Err(CoordinationError::Overlay(
            OverlayError::PendingReconciliation
        ))
    ));
    let request = register(&mut client, &mut authority, 1);
    let id = GrainId::of(
        intent::decode_register(request.bytes(), request.volume(), |_, _| true)
            .unwrap()
            .root,
    );
    let cached = client
        .overlay_transaction(|t| Ok(t.content_exists(&id)))
        .unwrap();
    assert_eq!(
        (
            client.snapshot().phase,
            client.writer_uuid(),
            cached,
            authority.sends.len()
        ),
        (Phase::Serving, writer, false, 2)
    );
    client
        .overlay_transaction(|t| t.create_file(at("served"), false))
        .unwrap();
}

#[test]
fn coordination_unknown_retries_preserve_exact_bytes_and_horizon() {
    let (_s, _io, mut client, mut authority) = serving();
    let request = client
        .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    let original = request.bytes().to_vec();
    let expires = client.snapshot().pending.last().unwrap().expires;
    let mut time = 10;
    let mut rng = SeededRng::new(1);
    let mut cases = 0;
    for status in [0, 500, 502, 503, 429] {
        client.dispatch(&request, &Tick(time)).unwrap();
        let answer = reply(
            status,
            if status == 429 {
                Some("rate-limited")
            } else if status == 503 {
                Some("enrollment-unavailable")
            } else {
                None
            },
            None,
            vec![],
        );
        let result = if status == 0 {
            Err(IntentTransportError::Transport)
        } else {
            Ok(&answer)
        };
        client
            .complete(
                &request,
                result,
                &Tick(time + 1),
                &mut rng,
                if status == 429 { 5000 } else { 0 },
                None,
            )
            .unwrap();
        let pending = client.snapshot().pending.last().unwrap();
        assert_eq!(
            (pending.body.clone(), pending.expires),
            (original.clone(), expires)
        );
        let eligible = pending.eligible;
        assert!(
            client
                .dispatch(&request, &Tick(time + 1))
                .unwrap_err()
                .to_string()
                .contains("IntentRetryNotEligible")
        );
        time = eligible;
        cases += 1;
    }
    client.dispatch(&request, &Tick(time)).unwrap();
    let response = authority.send(&request);
    client
        .complete(&request, Ok(&response), &Tick(time + 1), &mut rng, 0, None)
        .unwrap();
    assert_eq!((cases, client.snapshot().phase), (5, Phase::Serving));
}

/// Rejects checking wall-clock eligibility before displacement or startup
/// exhaustion, and moving either refusal ahead of wall expiry.
#[test]
fn dispatch_refusal_precedence_during_backoff_and_at_expiry() {
    let mut observed = Vec::new();
    for (displaced, expected) in [
        (true, "intent refused: IntentTokenDisplaced"),
        (false, "intent refused: IntentStartupAttemptsExhausted"),
    ] {
        let (scratch, io) = (Scratch::new(), SimIo::default());
        let mut client = start(&scratch, &io, 10);
        let request = if displaced {
            let mut authority = Authority::default();
            acquire(&mut client, &mut authority);
            open(&mut client, &io);
            register(&mut client, &mut authority, 1);
            let request = client
                .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
                    true
                })
                .unwrap();
            client.displace_token_for_test();
            request
        } else {
            let request = client.prepare_acquire(0, &Tick(10)).unwrap();
            let mut at = 10;
            for _ in 0..crate::STARTUP_ATTEMPTS {
                client.dispatch_landed_replay(&request, &Tick(at)).unwrap();
                let result = client.complete_landed_replay(
                    &request,
                    Err(IntentTransportError::Transport),
                    &Tick(at),
                    &mut SeededRng::new(1),
                    0,
                    None,
                );
                assert!(
                    matches!(result, Ok(crate::IntentCompletion::Unknown)),
                    "{result:?}"
                );
                at = client.snapshot().pending.last().unwrap().eligible;
            }
            request
        };
        let held = client.snapshot().pending.last().unwrap().clone();
        let early = client.dispatch_landed_replay(&request, &Tick(held.eligible - 1));
        let expired = client.dispatch_landed_replay(&request, &Tick(held.expires));
        observed.push((
            early.map_err(|error| error.to_string()),
            expired.map_err(|error| error.to_string()),
            client.snapshot().pending.last() == Some(&held),
            expected,
        ));
    }
    assert_eq!(
        observed,
        [
            "intent refused: IntentTokenDisplaced",
            "intent refused: IntentStartupAttemptsExhausted"
        ]
        .map(|expected| (
            Err(expected.to_owned()),
            Err("intent refused: IntentRetryDeadline".to_owned()),
            true,
            expected
        ))
    );
}

/// Rejects leaving early one-shot admission in the generic refusal class or
/// changing genuine authority refusals and fences along with it.
#[test]
fn early_dispatch_is_unavailable_in_store_start_and_engine() {
    use crate::FailureClass::{Conflict, Refused, Unavailable};

    let (_scratch, _io, mut client, _) = serving();
    let request = client
        .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    let log = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(log.clone())
        .finish();
    let error =
        tracing::subscriber::with_default(subscriber, || client.dispatch(&request, &Tick(9)))
            .unwrap_err();
    let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let authority = CoordinationError::SyncRefusal(crate::SyncRefusalKind::Authorization);
    let fenced = CoordinationError::Fenced {
        recorded_generation: None,
    };
    assert_eq!(
        (
            error.to_string(),
            log.lines()
                .filter(|line| line.contains("op.failed") && line.contains("unavailable"))
                .count(),
            [&error, &authority, &fenced].map(crate::writable_start::coordination_class),
            [&error, &authority, &fenced].map(crate::sync::failure_class),
        ),
        (
            "intent refused: IntentRetryNotEligible".to_owned(),
            1,
            [Unavailable, Refused, Conflict],
            [Unavailable, Refused, Conflict]
        ),
        "{log}"
    );
}

#[test]
fn coordination_displaced_lower_generation_and_absence_are_sticky() {
    let mut cases = 0;
    for absent in [false, true] {
        let (scratch, io, mut client, mut authority) = serving();
        let request = client
            .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
                true
            })
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        if absent {
            authority.row = None;
        } else {
            let decoded = authority.row.unwrap();
            authority.row = Some(Receipt {
                epoch: decoded.epoch + 1,
                instance: [99; 16],
                generation: 1,
                ..decoded
            });
        }
        let answer = authority.send(&request);
        let result = client.complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            matches!(result, Err(CoordinationError::Fenced { .. })),
            "{result:?}"
        );
        assert_eq!(client.snapshot().phase, Phase::Fenced);
        assert!(matches!(
            client.dispatch(&request, &Tick(12)),
            Err(CoordinationError::Fenced { .. })
        ));
        assert!(matches!(
            client.overlay_transaction(|t| t.create_file(at("stale"), false)),
            Err(CoordinationError::Fenced { .. })
        ));
        drop(client);
        io.crash();
        let mut successor = start(&scratch, &io, 30);
        assert!(matches!(
            successor.prepare_acquire(authority.cursor, &Tick(20)),
            Err(CoordinationError::Fenced { .. })
        ));
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn coordination_own_overtake_retires_old_send_without_fencing() {
    let (_s, _io, mut client, mut authority) = serving();
    let low = client
        .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    client.dispatch(&low, &Tick(10)).unwrap();
    let high = client
        .prepare_registration(&root(client.writer_uuid(), 3), vec![], &Tick(11), |_, _| {
            true
        })
        .unwrap();
    client.dispatch(&high, &Tick(11)).unwrap();
    authority.send(&high);
    let overtaken = authority.send(&low);
    client
        .complete(
            &low,
            Ok(&overtaken),
            &Tick(12),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!(
        (
            client.snapshot().phase,
            client
                .snapshot()
                .pending
                .iter()
                .filter(|request| !request.terminal)
                .count()
        ),
        (Phase::Serving, 0)
    );
    assert!(
        client
            .dispatch(&low, &Tick(13))
            .unwrap_err()
            .to_string()
            .contains("IntentRequestRetired")
    );
}

#[test]
fn coordination_discovery_refuses_without_degrading_and_terminal_never_resends() {
    let mut cases = 0;
    for (status, token, reason) in [
        (404, "unknown-target", "IntentNotImplemented"),
        (404, "unknown-volume", "IntentUnknownVolume"),
        (400, "bad-request", "IntentTerminalRefusal"),
        (403, "not-enrolled", "IntentTerminalRefusal"),
        (413, "too-large", "IntentTerminalRefusal"),
    ] {
        let scratch = Scratch::new();
        let io = SimIo::default();
        let mut client = start(&scratch, &io, 10);
        let request = client.prepare_acquire(0, &Tick(1)).unwrap();
        client.dispatch(&request, &Tick(1)).unwrap();
        let answer = reply(status, Some(token), None, vec![]);
        let err = client
            .complete(
                &request,
                Ok(&answer),
                &Tick(2),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap_err();
        assert!(err.to_string().contains(reason), "{err}");
        assert_eq!(
            (
                client.snapshot().phase,
                client.snapshot().pending[0].terminal
            ),
            (Phase::Unowned, true)
        );
        assert!(
            client
                .dispatch(&request, &Tick(3))
                .unwrap_err()
                .to_string()
                .contains("IntentRequestRetired")
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[test]
fn coordination_lost_grant_reply_restart_resolves_then_transfers_fresh_token() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let writer = client.writer_uuid();
    let mut authority = Authority::default();
    let request = client.prepare_acquire(0, &Tick(1)).unwrap();
    client.dispatch(&request, &Tick(1)).unwrap();
    authority.send(&request);
    let original = request.bytes().to_vec();
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    let old = client.retained_requests().pop().unwrap();
    assert_eq!(old.bytes(), original);
    client.dispatch(&old, &Tick(2)).unwrap();
    let answer = authority.send(&old);
    client
        .complete(&old, Ok(&answer), &Tick(3), &mut SeededRng::new(1), 0, None)
        .unwrap();
    let transfer = client.prepare_succession(&Tick(4)).unwrap();
    client.dispatch(&transfer, &Tick(4)).unwrap();
    let answer = authority.send(&transfer);
    client
        .complete(
            &transfer,
            Ok(&answer),
            &Tick(5),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!(
        (
            client.writer_uuid(),
            authority.row.unwrap().instance,
            authority.row.unwrap().epoch
        ),
        (writer, [30; 16], 2)
    );
    open(&mut client, &io);
    register(&mut client, &mut authority, 2);
}

#[test]
fn coordination_release_429_deadline_keeps_live_evidence() {
    let (_s, _io, mut client, mut authority) = serving();
    let request = client
        .prepare_release(
            &Tick(100),
            crate::writable_store::DEFAULT_RESOLUTION_BOUND,
            None,
        )
        .unwrap();
    client.dispatch(&request, &Tick(100)).unwrap();
    let limit = reply(429, Some("rate-limited"), None, vec![]);
    let result = client.complete(
        &request,
        Ok(&limit),
        &Tick(101),
        &mut SeededRng::new(1),
        300_000,
        None,
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("IntentRetryDeadline")
    );
    assert_eq!(
        (
            client.snapshot().phase,
            client.snapshot().pending.last().unwrap().terminal,
            authority.row.unwrap().generation
        ),
        (Phase::Releasing, false, client.snapshot().sent)
    );
    let release = intent::decode_release(request.bytes()).unwrap();
    assert_eq!(release.generation, client.snapshot().sent);
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(102),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!(client.snapshot().phase, Phase::Released);
}

#[test]
fn coordination_carrier_crash_cuts_fire_and_preserve_canonical_requests() {
    let mut cases = 0;
    for phase in [
        "build",
        "partial",
        "before",
        "after",
        "sync",
        "after_sync",
        "rename",
        "after_rename",
        "dir_sync",
        "after_dir_sync",
    ] {
        let scratch = Scratch::new();
        let io = SimIo::default();
        let mut client = start(&scratch, &io, 10);
        client
            .fault_control()
            .arm("intent.pending", phase, 1, FaultAction::Crash);
        let result = client.prepare_acquire(0, &Tick(1));
        assert!(
            matches!(
                result,
                Err(CoordinationError::Overlay(OverlayError::InjectedCrash))
            ),
            "{phase}: {result:?}"
        );
        assert_eq!(client.fault_control().fired().len(), 1, "{phase}");
        assert!(
            client
                .prepare_acquire(0, &Tick(2))
                .unwrap_err()
                .to_string()
                .contains("IntentPersistencePoisoned")
        );
        drop(client);
        io.crash();
        let client = start(&scratch, &io, 30);
        let has_request = !client.snapshot().pending.is_empty();
        assert_eq!(
            (client.snapshot().phase, has_request),
            if phase == "after_dir_sync" {
                (Phase::Handshake, true)
            } else {
                (Phase::Unowned, false)
            },
            "cut {phase}"
        );
        cases += 1;
        let control_s = Scratch::new();
        let control_io = SimIo::default();
        let mut control = start(&control_s, &control_io, 10);
        control.prepare_acquire(0, &Tick(1)).unwrap();
        assert_eq!(control.snapshot().phase, Phase::Handshake);
    }
    assert_eq!(cases, 10);
}

#[test]
fn coordination_ceiling_reservation_batches_durable_replacements() {
    let (_scratch, io, mut client, mut authority) = serving();
    let replacements = || {
        io.0.lock()
            .unwrap()
            .trace
            .iter()
            .filter(|(operation, path)| {
                operation == "rename" && path.file_name().is_some_and(|name| name == "writer.tmp")
            })
            .count()
    };
    let before = replacements();
    for seed in 2..=64 {
        register(&mut client, &mut authority, seed);
    }
    assert_eq!(
        (client.snapshot().sent, replacements() - before),
        (64, 0),
        "reserved ceiling batch"
    );
    register(&mut client, &mut authority, 65);
    assert_eq!(
        (client.snapshot().sent, replacements() - before),
        (65, 1),
        "reserved ceiling refill"
    );
}

#[test]
fn coordination_generation_gap_is_not_reused_and_root_writer_is_bound() {
    let (scratch, io, mut client, mut authority) = serving();
    client
        .fault_control()
        .arm("intent.ceiling", "after", 1, FaultAction::Crash);
    assert!(matches!(
        client.prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        }),
        Err(CoordinationError::Overlay(OverlayError::InjectedCrash))
    ));
    assert_eq!(client.fault_control().fired().len(), 1);
    assert_eq!(client.snapshot().allocated, 1);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    let transfer = client.prepare_succession(&Tick(11)).unwrap();
    client.dispatch(&transfer, &Tick(11)).unwrap();
    let response = authority.send(&transfer);
    client
        .complete(
            &transfer,
            Ok(&response),
            &Tick(12),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    open(&mut client, &io);
    let request = client
        .prepare_registration(&root(client.writer_uuid(), 3), vec![], &Tick(13), |_, _| {
            true
        })
        .unwrap();
    let generation = intent::decode_register(request.bytes(), request.volume(), |_, _| true)
        .unwrap()
        .generation;
    assert_eq!(
        (
            generation,
            client.snapshot().allocated,
            client.snapshot().sent
        ),
        (65, 65, 65),
        "generation gap"
    );
    let wrong = client.prepare_registration(&root([99; 16], 4), vec![], &Tick(14), |_, _| true);
    assert!(
        wrong
            .unwrap_err()
            .to_string()
            .contains("IntentPreparedWriter")
    );
}

#[test]
fn coordination_startup_cursor_churn_is_bounded() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut rng = SeededRng::new(1);
    for attempt in 0..8 {
        let request = client.prepare_acquire(attempt, &Tick(attempt + 1)).unwrap();
        client.dispatch(&request, &Tick(attempt + 1)).unwrap();
        client
            .complete(
                &request,
                Ok(&reply(409, Some("intent-cursor-changed"), None, vec![])),
                &Tick(attempt + 1),
                &mut rng,
                0,
                None,
            )
            .unwrap_err();
    }
    let request = client.prepare_acquire(8, &Tick(9)).unwrap();
    assert!(
        client
            .dispatch(&request, &Tick(9))
            .unwrap_err()
            .to_string()
            .contains("IntentStartupAttemptsExhausted")
    );
    assert_eq!(client.retained_requests().len(), 1);
}

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for LogCapture {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'authority> tracing_subscriber::fmt::MakeWriter<'authority> for LogCapture {
    type Writer = Self;
    fn make_writer(&'authority self) -> Self {
        self.clone()
    }
}
#[test]
fn coordination_loud_events_and_registration_metrics_are_separate_from_commit_retries() {
    let out = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(out.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let (_s, _io, mut client, _a) = serving();
        let metrics = crate::metrics::tests::metrics();
        metrics.set_available(crate::MetricsGroup::Sync, true);
        metrics.set_available(crate::MetricsGroup::Commit, true);
        client.set_metrics(metrics.clone());
        let request = client
            .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
                true
            })
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        client
            .complete(
                &request,
                Err(IntentTransportError::Transport),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        let eligible = client.snapshot().pending.last().unwrap().eligible;
        client.dispatch(&request, &Tick(eligible)).unwrap();
        client
            .complete(
                &request,
                Ok(&reply(404, Some("unknown-target"), None, vec![])),
                &Tick(eligible + 1),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap_err();
        let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
        assert!(
            text.contains("granary_client_intent_registrations_total{result=\"unknown\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("granary_client_commit_retries_total{reason=\"transient\"} 0"),
            "{text}"
        );
    });
    let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("op.failed") && text.contains("intent_register") && text.contains("refused"),
        "{text}"
    );
    assert!(text.contains("op.retry"), "{text}");
}

#[test]
fn coordination_disk_loss_selected_writer_uses_bound_acknowledged_takeover() {
    let (_old_s, _old_io, old, authority) = serving();
    let selected_writer = old.writer_uuid();
    let selected = authority.row.unwrap();
    let bytes = intent::encode_readback(
        authority.cursor,
        &[intent::ReadbackRow {
            writer: selected_writer,
            epoch: selected.epoch,
            generation: selected.generation,
            root: &authority.root,
        }],
    )
    .unwrap();
    let readback = reply(200, None, Some(intent::MEDIA_READBACK), bytes);
    let new_s = Scratch::new();
    let io = SimIo::default();
    let mut client = config(&new_s.0);
    client.cap = 134_217_728;
    client.ownership_completion_reserve = REPLACEMENT_RESERVE;
    let selection = crate::SelectedRecovery::from_readback(
        client.scope.clone(),
        client.volume.clone(),
        selected_writer,
        &readback,
        |_, _| true,
    )
    .unwrap();
    let mut recovery = WritableStore::adopt_selected(
        Store::open(&new_s.0).unwrap(),
        client,
        io.clone(),
        &mut Entropy(30),
        FaultControl::default(),
        selection.acknowledge_displacement(),
    )
    .unwrap();
    assert_eq!(
        (
            recovery.writer_uuid(),
            recovery.snapshot().allocated,
            recovery.snapshot().selected_root.clone()
        ),
        (selected_writer, selected.generation, authority.root.clone())
    );
    let request = recovery.begin_selected_attempt(&Tick(100)).unwrap();
    let decoded = intent::decode_ownership(request.bytes()).unwrap();
    assert!(matches!(
        decoded.mode,
        OwnershipMode::Takeover {
            recovery_ack: true,
            ..
        }
    ));
    assert_eq!(
        recovery.snapshot().consent,
        granary_core::overlay_ownership::recovery_consent(recovery.snapshot(), request.bytes())
            .unwrap()
    );
    recovery.dispatch(&request, &Tick(100)).unwrap();
    let mut authority = authority;
    let answer = authority.send(&request);
    recovery
        .complete(
            &request,
            Ok(&answer),
            &Tick(101),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    open(&mut recovery, &io);
    register(&mut recovery, &mut authority, 2);
    assert_eq!(
        (
            recovery.snapshot().phase,
            authority.row.unwrap().instance,
            authority.row.unwrap().generation
        ),
        (Phase::Serving, [30; 16], 2)
    );
}

#[test]
fn coordination_retired_reply_still_fences_current_ownership() {
    let (_scratch, _io, mut client, mut authority) = serving();
    let low = client
        .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    client.dispatch(&low, &Tick(10)).unwrap();
    let high = client
        .prepare_registration(&root(client.writer_uuid(), 3), vec![], &Tick(11), |_, _| {
            true
        })
        .unwrap();
    client.dispatch(&high, &Tick(11)).unwrap();
    let answer = authority.send(&high);
    client
        .complete(
            &high,
            Ok(&answer),
            &Tick(12),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    authority.cursor += 1;
    authority.row = Some(Receipt {
        epoch: authority.cursor,
        instance: [99; 16],
        ..authority.row.unwrap()
    });
    let answer = authority.send(&low);
    let result = client.complete(
        &low,
        Ok(&answer),
        &Tick(13),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        matches!(result, Err(CoordinationError::Fenced { .. })),
        "retired displacement: {result:?}"
    );
    assert_eq!(client.snapshot().phase, Phase::Fenced);
}

#[test]
fn coordination_previous_owner_completion_cannot_fence_transferred_instance() {
    let (scratch, io, mut client, mut authority) = serving();
    let pending = client
        .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    client.dispatch(&pending, &Tick(10)).unwrap();
    authority.send(&pending);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    open(&mut client, &io);
    let previous = client.retained_requests().pop().unwrap();
    let answer = authority.send(&previous);
    client
        .complete(
            &previous,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let transfer = client.prepare_succession(&Tick(12)).unwrap();
    client.dispatch(&transfer, &Tick(12)).unwrap();
    let answer = authority.send(&transfer);
    client
        .complete(
            &transfer,
            Ok(&answer),
            &Tick(13),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let answer = authority.send(&previous);
    let result = client.complete(
        &previous,
        Ok(&answer),
        &Tick(14),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("IntentCompletionOwner")
    );
    assert_eq!(client.snapshot().phase, Phase::OwnedStart);
    register(&mut client, &mut authority, 3);
}

#[test]
fn coordination_fence_preflight_failure_poison_survives_before_first_write() {
    let (_scratch, io, mut client, mut authority) = serving();
    let pending = client
        .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    client.dispatch(&pending, &Tick(10)).unwrap();
    authority.cursor += 1;
    authority.row = Some(Receipt {
        epoch: authority.cursor,
        instance: [99; 16],
        ..authority.row.unwrap()
    });
    let answer = authority.send(&pending);
    io.0.lock().unwrap().fail = Some("entries");
    let result = client.complete(
        &pending,
        Ok(&answer),
        &Tick(11),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(matches!(
        result,
        Err(CoordinationError::Overlay(OverlayError::Io(_)))
    ));
    let denied = client.dispatch(&pending, &Tick(12));
    assert!(
        denied
            .as_ref()
            .is_err_and(|e| e.to_string().contains("IntentPersistencePoisoned")),
        "fence preflight poison: {denied:?}"
    );
}

#[test]
fn coordination_completed_pipeline_slots_are_reclaimed_without_resetting_high_water() {
    let (_scratch, _io, mut client, mut authority) = serving();
    for seed in 2..=130 {
        register(&mut client, &mut authority, seed);
    }
    assert_eq!(
        (
            client.snapshot().allocated,
            client.snapshot().sent,
            client
                .snapshot()
                .pending
                .iter()
                .filter(|p| p.operation == Operation::Register)
                .count()
        ),
        (130, 130, 0),
        "completed pipeline reclamation"
    );
}

#[test]
fn coordination_overlay_poison_survives_caught_error_and_facade_drop() {
    let (_scratch, io, mut client, _authority) = serving();
    let stage = client
        .overlay_transaction(|t| t.create_file(at("file"), false))
        .unwrap();
    io.0.lock().unwrap().fail = Some("sync");
    client
        .overlay_transaction(|t| {
            let token = t.capture(stage)?;
            assert!(matches!(t.flush_boundary(&token), Err(OverlayError::Io(_))));
            assert!(matches!(
                t.create_file(at("after"), false),
                Err(OverlayError::Poisoned)
            ));
            Ok(())
        })
        .unwrap();
    let mut h = header();
    h.writer = client.writer_uuid();
    assert!(
        client
            .open_overlay(h, vec![], &mut Source::default(), io.clone())
            .unwrap_err()
            .to_string()
            .contains("IntentPersistencePoisoned"),
        "overlay poison across facade"
    );
}

#[test]
fn coordination_peer_scope_and_volume_cannot_be_relabelled_on_completion() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority::default();
    let request = client.prepare_acquire(0, &Tick(1)).unwrap();
    client.dispatch(&request, &Tick(1)).unwrap();
    let valid = authority.send(&request);
    let mut cases = 0;
    for volume in [false, true] {
        let mut wrong = valid.clone();
        if volume {
            wrong.volume = Some(VolumeName::from_bytes(b"other").unwrap());
        } else {
            wrong.scope.as_mut().unwrap().authority_base = b"https://other.invalid".to_vec();
        }
        let result = client.complete(
            &request,
            Ok(&wrong),
            &Tick(2),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("IntentCompletionBinding")
        );
        assert_eq!(client.snapshot().phase, Phase::Handshake);
        cases += 1;
    }
    client
        .complete(
            &request,
            Ok(&valid),
            &Tick(2),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!((cases, client.snapshot().phase), (2, Phase::OwnedStart));
}

mod captures;

#[test]
fn coordination_measured_latency_survives_wall_clock_changes_and_unavailable_sample() {
    let (_s, _io, mut client, mut authority) = serving();
    let metrics = crate::metrics::tests::metrics();
    metrics.set_available(crate::MetricsGroup::Sync, true);
    client.set_metrics(metrics.clone());
    for (seed, wall, sample) in [
        (2, 1, Some(std::time::Duration::from_millis(7))),
        (3, 999_999, None),
    ] {
        let request = client
            .prepare_registration(
                &root(client.writer_uuid(), seed),
                vec![],
                &Tick(100),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&request, &Tick(100)).unwrap();
        let answer = authority.send(&request);
        client
            .complete(
                &request,
                Ok(&answer),
                &Tick(wall),
                &mut SeededRng::new(1),
                0,
                sample,
            )
            .unwrap();
    }
    let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("granary_client_intent_registrations_total{result=\"ok\"} 2"),
        "measured counter once: {text}"
    );
    assert!(
        text.contains("granary_client_intent_registration_duration_seconds_count{result=\"ok\"} 1"),
        "unavailable adds no sample: {text}"
    );
    assert!(
        text.contains(
            "granary_client_intent_registration_duration_seconds_sum{result=\"ok\"} 0.007"
        ),
        "measured duration: {text}"
    );
}

#[test]
fn coordination_release_uses_configured_enclosing_deadline_without_reset() {
    for (bound, enclosing, expired) in [(100, None, 200), (30_000, Some(150), 150)] {
        let (_s, _io, mut client, _authority) = serving();
        let request = client
            .prepare_release(
                &Tick(100),
                std::time::Duration::from_millis(bound),
                enclosing,
            )
            .unwrap();
        client.dispatch(&request, &Tick(100)).unwrap();
        assert!(
            client
                .dispatch(&request, &Tick(expired))
                .unwrap_err()
                .to_string()
                .contains("IntentRetryDeadline"),
            "configured release bound"
        );
        assert_eq!(client.snapshot().phase, Phase::Releasing);
        assert_eq!(client.retained_requests()[0].bytes(), request.bytes());
    }
}

#[test]
fn coordination_original_horizon_and_retired_send_are_guards() {
    let (_s, _io, mut client, mut authority) = serving();
    let low = client
        .prepare_registration(
            &root(client.writer_uuid(), 2),
            vec![1],
            &Tick(10),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&low, &Tick(10)).unwrap();
    assert!(
        client
            .dispatch(&low, &Tick(86_400_010))
            .unwrap_err()
            .to_string()
            .contains("IntentRetryDeadline"),
        "original horizon guard"
    );
    let high = client
        .prepare_registration(&root(client.writer_uuid(), 3), vec![], &Tick(11), |_, _| {
            true
        })
        .unwrap();
    client.dispatch(&high, &Tick(11)).unwrap();
    let answer = authority.send(&high);
    client
        .complete(
            &high,
            Ok(&answer),
            &Tick(12),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert!(
        client
            .dispatch(&low, &Tick(13))
            .unwrap_err()
            .to_string()
            .contains("IntentRequestRetired"),
        "retired send guard"
    );
}

#[test]
fn coordination_generation_exhaustion_never_wraps_or_sends() {
    let (_s, _io, mut client, authority) = serving();
    client.generation_floor_for_test(u64::MAX - 1);
    let result =
        client.prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("IntentGenerationExhausted"),
        "generation exhaustion guard"
    );
    assert_eq!(authority.row.unwrap().generation, 1);
    assert_eq!(client.snapshot().sent, 1);
}

#[test]
fn coordination_dispatch_persists_attempt_before_send() {
    let (scratch, io, mut client, _authority) = serving();
    let request = client
        .prepare_registration(
            &root(client.writer_uuid(), 2),
            vec![1],
            &Tick(10),
            |_, _| true,
        )
        .unwrap();
    let body = request.bytes().to_vec();
    client
        .fault_control()
        .arm("intent.pending", "after_dir_sync", 1, FaultAction::Crash);
    let result = client.dispatch(&request, &Tick(10));
    assert!(
        matches!(
            result,
            Err(CoordinationError::Overlay(OverlayError::InjectedCrash))
        ),
        "persist before send: {result:?}"
    );
    assert_eq!(client.fault_control().fired().len(), 1);
    drop(client);
    io.crash();
    let reopened = try_start(&scratch, &io, 30);
    assert!(
        reopened.is_ok(),
        "durable attempt carrier must reopen: {reopened:?}"
    );
    let client = reopened.unwrap();
    let pending = client.snapshot().pending.iter().find(|p| p.body == body);
    assert!(pending.is_some(), "attempt durable before send");
    assert_eq!(pending.unwrap().attempts, 1, "attempt durable before send");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the crash Cartesian product and disarmed controls assert fired seams, durable receipt and service together"
)]
fn coordination_completion_crash_matrix_retains_receipt_before_service() {
    let mut cases = 0;
    for operation in ["register", "release", "fence"] {
        for (seam, phase) in [
            ("intent.reply", "before"),
            ("intent.evidence", "before"),
            ("intent.pending", "build"),
            ("intent.pending", "partial"),
            ("intent.pending", "before"),
            ("intent.pending", "after"),
            ("intent.pending", "sync"),
            ("intent.pending", "after_sync"),
            ("intent.pending", "rename"),
            ("intent.pending", "after_rename"),
            ("intent.pending", "dir_sync"),
            ("intent.pending", "after_dir_sync"),
            ("intent.evidence", "after"),
        ] {
            let (scratch, io, mut client, mut authority) = serving();
            let request = if operation == "release" {
                client
                    .prepare_release(&Tick(10), crate::DEFAULT_RESOLUTION_BOUND, None)
                    .unwrap()
            } else {
                client
                    .prepare_registration(
                        &root(client.writer_uuid(), 2),
                        vec![1],
                        &Tick(10),
                        |_, _| true,
                    )
                    .unwrap()
            };
            client.dispatch(&request, &Tick(10)).unwrap();
            if operation == "fence" {
                authority.row = Some(Receipt {
                    epoch: 2,
                    instance: [99; 16],
                    ..authority.row.unwrap()
                });
            }
            let answer = authority.send(&request);
            client
                .fault_control()
                .arm(seam, phase, 1, FaultAction::Crash);
            let result = client.complete(
                &request,
                Ok(&answer),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None,
            );
            assert!(
                matches!(
                    result,
                    Err(CoordinationError::Overlay(OverlayError::InjectedCrash))
                ),
                "completion crash {operation}/{seam}/{phase}: {result:?}"
            );
            assert_eq!(client.fault_control().fired().len(), 1);
            drop(client);
            io.crash();
            let client = start(&scratch, &io, 30);
            let durable =
                phase == "after_dir_sync" || (seam == "intent.evidence" && phase == "after");
            assert_eq!(
                client.snapshot().pending.last().unwrap().terminal,
                durable,
                "receipt before service {operation}/{seam}/{phase}"
            );
            if durable {
                assert_eq!(
                    client.snapshot().phase,
                    match operation {
                        "release" => Phase::Released,
                        "fence" => Phase::Fenced,
                        _ => Phase::Serving,
                    }
                );
            }
            cases += 1;
        }
        let (_s, _io, mut client, mut authority) = serving();
        let request = if operation == "release" {
            client
                .prepare_release(&Tick(10), crate::DEFAULT_RESOLUTION_BOUND, None)
                .unwrap()
        } else {
            client
                .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
                    true
                })
                .unwrap()
        };
        client.dispatch(&request, &Tick(10)).unwrap();
        if operation == "fence" {
            authority.row = Some(Receipt {
                epoch: 2,
                instance: [99; 16],
                ..authority.row.unwrap()
            });
        }
        let answer = authority.send(&request);
        let result = client.complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert_eq!(
            result.is_ok(),
            operation != "fence",
            "disarmed completion control"
        );
    }
    assert_eq!(cases, 39, "nonempty completion matrix");
}

#[test]
fn coordination_status_refusals_and_unknowns_keep_exact_evidence() {
    let rows = [
        (400, "bad-request", "sync refused"),
        (401, "no-principal", "IntentBackendDisagreement"),
        (403, "no-principal", "sync authorization refused"),
        (404, "unknown-target", "IntentNotImplemented"),
        (405, "method-not-allowed", "sync refused"),
        (413, "too-large", "sync refused"),
        (404, "unknown-volume", "IntentUnknownVolume"),
        (409, "intent-quota", "IntentOverQuota"),
    ];
    let mut cases = 0;
    for (status, token, reason) in rows {
        let (_s, _io, mut client, authority) = serving();
        let request = client
            .prepare_registration(
                &root(client.writer_uuid(), 2),
                vec![1],
                &Tick(10),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        let answer = reply(status, Some(token), None, vec![]);
        let result = client.complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            result
                .as_ref()
                .is_err_and(|e| e.to_string().contains(reason)),
            "status refusal {status}/{token}: {result:?}"
        );
        assert_eq!(
            client.snapshot().current,
            intent::encode_receipt(authority.row.unwrap()).unwrap(),
            "status cannot advance acknowledgement"
        );
        assert_eq!(
            client.snapshot().pending.last().unwrap().body,
            request.bytes()
        );
        cases += 1;
    }
    for (status, token) in [
        (429, "rate-limited"),
        (503, "intent-unavailable"),
        (503, "enrollment-unavailable"),
        (500, "internal"),
        (502, "anything"),
    ] {
        let (_s, _io, mut client, authority) = serving();
        let request = client
            .prepare_registration(
                &root(client.writer_uuid(), 2),
                vec![1],
                &Tick(10),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        let answer = reply(status, Some(token), None, vec![]);
        client
            .complete(
                &request,
                Ok(&answer),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        assert!(
            !client.snapshot().pending.last().unwrap().terminal,
            "unknown is retained"
        );
        assert_eq!(
            client.snapshot().current,
            intent::encode_receipt(authority.row.unwrap()).unwrap()
        );
        cases += 1;
    }
    assert_eq!(cases, 13);
}

#[test]
fn coordination_release_deadline_survives_reopen_and_metrics_count_one_attempt() {
    let (scratch, io, mut client, _authority) = serving();
    let request = client
        .prepare_release(&Tick(100), std::time::Duration::from_millis(50), Some(140))
        .unwrap();
    client.dispatch(&request, &Tick(100)).unwrap();
    let bytes = request.bytes().to_vec();
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    let retained = client.retained_requests().pop().unwrap();
    assert_eq!(retained.bytes(), bytes);
    assert!(
        client
            .dispatch(&retained, &Tick(140))
            .unwrap_err()
            .to_string()
            .contains("IntentRetryDeadline"),
        "persisted release deadline"
    );

    let (_s, _io, mut client, _authority) = serving();
    let metrics = crate::metrics::tests::metrics();
    metrics.set_available(crate::MetricsGroup::Sync, true);
    client.set_metrics(metrics.clone());
    let request = client
        .prepare_registration(
            &root(client.writer_uuid(), 2),
            vec![1],
            &Tick(10),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    for _ in 0..2 {
        client
            .complete(
                &request,
                Err(IntentTransportError::Transport),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                Some(std::time::Duration::from_millis(7)),
            )
            .unwrap();
    }
    let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("granary_client_intent_registrations_total{result=\"unknown\"} 1"),
        "one sample per dispatch: {text}"
    );
}

#[test]
fn coordination_bound_and_changed_selection_are_terminal_backend_disagreement_is_not_ownership() {
    let (_s, _io, mut client, mut authority) = serving();
    let request = client
        .prepare_registration(
            &root(client.writer_uuid(), 2),
            vec![1],
            &Tick(10),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    authority.row = Some(Receipt {
        generation: 2,
        state: ReceiptState::Live {
            prepared_root_id: grain(99),
        },
        ..authority.row.unwrap()
    });
    let bound = authority.recorded(409, Some("intent-bound"));
    assert!(
        client
            .complete(
                &request,
                Ok(&bound),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None
            )
            .unwrap_err()
            .to_string()
            .contains("IntentBound"),
        "bound cannot acknowledge"
    );
    assert_eq!(client.snapshot().phase, Phase::Serving);
    let (_s, _io, mut client, mut authority) = serving();
    let transfer = client.prepare_succession(&Tick(10)).unwrap();
    authority.row = Some(Receipt {
        generation: 2,
        state: ReceiptState::Live {
            prepared_root_id: grain(99),
        },
        ..authority.row.unwrap()
    });
    client.dispatch(&transfer, &Tick(10)).unwrap();
    let changed = authority.recorded(409, Some("intent-changed"));
    assert!(
        client
            .complete(
                &transfer,
                Ok(&changed),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None
            )
            .unwrap_err()
            .to_string()
            .contains("IntentSelectionChanged"),
        "selection requires renewed consent"
    );
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let request = client.prepare_acquire(u64::MAX, &Tick(1)).unwrap();
    client.dispatch(&request, &Tick(1)).unwrap();
    let exhausted = reply(409, Some("intent-epoch-exhausted"), None, vec![]);
    assert!(
        client
            .complete(
                &request,
                Ok(&exhausted),
                &Tick(2),
                &mut SeededRng::new(1),
                0,
                None
            )
            .unwrap_err()
            .to_string()
            .contains("IntentEpochExhausted"),
        "epoch exhaustion cannot acquire"
    );
}

#[test]
fn coordination_network_completion_distinguishes_accepted_unknown_and_overtaken() {
    use crate::IntentCompletion;
    let mut cases = 0;
    for kind in ["accepted", "unknown", "overtaken"] {
        let (_s, _io, mut client, mut authority) = serving();
        let request = client
            .prepare_registration(
                &root(client.writer_uuid(), 2),
                vec![1],
                &Tick(10),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        let answer = if kind == "overtaken" {
            let higher = client
                .prepare_registration(
                    &root(client.writer_uuid(), 3),
                    vec![2],
                    &Tick(11),
                    |_, _| true,
                )
                .unwrap();
            client.dispatch(&higher, &Tick(11)).unwrap();
            authority.send(&higher);
            Some(authority.send(&request))
        } else if kind == "accepted" {
            Some(authority.send(&request))
        } else {
            None
        };
        let outcome = client
            .complete(
                &request,
                answer.as_ref().ok_or(IntentTransportError::Transport),
                &Tick(12),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        assert!(
            match (kind, outcome) {
                ("accepted", IntentCompletion::Accepted(receipt)) => receipt.generation == 2,
                ("unknown", IntentCompletion::Unknown) => true,
                ("overtaken", IntentCompletion::Overtaken(receipt)) => receipt.generation == 3,
                _ => false,
            },
            "typed network outcome {kind}: {outcome:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn coordination_registration_metrics_follow_judged_outcome() {
    let (_s, _io, mut client, _authority) = serving();
    let metrics = crate::metrics::tests::metrics();
    metrics.set_available(crate::MetricsGroup::Sync, true);
    client.set_metrics(metrics.clone());
    let request = client
        .prepare_registration(
            &root(client.writer_uuid(), 2),
            vec![1],
            &Tick(10),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    let mut wrong = reply(429, Some("rate-limited"), None, vec![]);
    wrong.scope.as_mut().unwrap().authority_base = b"https://other.invalid".to_vec();
    assert!(
        client
            .complete(
                &request,
                Ok(&wrong),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                Some(std::time::Duration::from_millis(7))
            )
            .unwrap_err()
            .to_string()
            .contains("IntentCompletionBinding")
    );
    let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("granary_client_intent_registrations_total{result=\"failed\"} 1"),
        "judged registration metric: {text}"
    );
    assert!(
        text.contains("granary_client_intent_registrations_total{result=\"unknown\"} 0"),
        "scope failure is not an unknown mutation: {text}"
    );
}

mod recovery_progress;
mod round1;

#[test]
fn sync_refusal_preserves_judged_authorization() {
    use crate::{SyncRefusalKind as K, writable_start::sync_mount_error};
    use granary_fuse::{MountError as M, MountSyncError as S};
    let mut observations = Vec::new();
    for (status, token, expected) in [
        (403, "no-principal", Some(K::Authorization)),
        (403, "not-enrolled", Some(K::Authorization)),
        (400, "bad-request", Some(K::Other)),
        (413, "too-large", Some(K::Other)),
        (401, "no-principal", None),
    ] {
        let (_scratch, _io, mut client, authority) = serving();
        let request = client
            .prepare_registration(
                &root(client.writer_uuid(), 2),
                vec![1],
                &Tick(10),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        let answer = reply(status, Some(token), None, vec![]);
        let error = client
            .complete(
                &request,
                Ok(&answer),
                &Tick(11),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap_err();
        let actual = match &error {
            CoordinationError::SyncRefusal(kind) => Some(*kind),
            _ => None,
        };
        observations.push((
            actual,
            sync_mount_error(&error),
            client.snapshot().current == intent::encode_receipt(authority.row.unwrap()).unwrap(),
            client.snapshot().pending.last().unwrap().terminal,
        ));
        let mapped = match expected {
            Some(K::Authorization) => M::Access,
            _ => M::Io,
        };
        assert_eq!(
            observations.last(),
            Some(&(expected, S::Backend(mapped), true, true)),
            "status={status}, token={token}, error={error:?}"
        );
    }
    assert_eq!(observations.len(), 5);
}

#[test]
fn sync_register_refusal_does_not_fail_session() {
    let out = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(out.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let (_scratch, _io, mut client, _authority) = serving();
        let request = client
            .prepare_registration(
                &root(client.writer_uuid(), 2),
                vec![1],
                &Tick(10),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        // Observe only the steady-state completion, excluding startup events.
        out.0.lock().unwrap().clear();
        let answer = reply(403, Some("not-enrolled"), None, vec![]);
        let result = client.complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            matches!(result, Err(CoordinationError::SyncRefusal(_))),
            "refusal premise: {result:?}"
        );
    });
    let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
    let failures: Vec<_> = text
        .lines()
        .filter(|line| line.contains("op.failed"))
        .collect();
    assert_eq!(
        (
            failures.len(),
            failures
                .iter()
                .any(|line| line.contains("intent_register") && line.contains("refused")),
            failures.iter().any(|line| line.contains("session"))
        ),
        (1, true, false),
        "steady-state registration events: {text}"
    );
}

/// The `op.failed` lines a steady-state registration completion emits, after
/// the authority has either replaced the owner row or refused the sender.
fn register_completion_failures(displaced: bool) -> Vec<String> {
    let out = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(out.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let (_scratch, _io, mut client, mut authority) = serving();
        let request = client
            .prepare_registration(
                &root(client.writer_uuid(), 2),
                vec![1],
                &Tick(10),
                |_, _| true,
            )
            .unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        let answer = if displaced {
            let decoded = authority.row.unwrap();
            authority.row = Some(Receipt {
                epoch: decoded.epoch + 1,
                instance: [99; 16],
                generation: 1,
                ..decoded
            });
            authority.send(&request)
        } else {
            reply(403, Some("not-enrolled"), None, vec![])
        };
        // Observe only the steady-state completion, excluding startup events.
        out.0.lock().unwrap().clear();
        let result = client.complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            matches!(
                (displaced, &result),
                (true, Err(CoordinationError::Fenced { .. }))
                    | (false, Err(CoordinationError::SyncRefusal(_)))
            ),
            "completion premise (displaced={displaced}): {result:?}"
        );
    });
    let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
    text.lines()
        .filter(|line| line.contains("op.failed"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn displaced_registration_reports_conflict_and_other_refusals_report_refused() {
    let observed: Vec<_> = [true, false]
        .into_iter()
        .map(|displaced| {
            let failures = register_completion_failures(displaced);
            (
                displaced,
                failures.len(),
                failures
                    .iter()
                    .any(|line| line.contains("intent_register") && line.contains("conflict")),
                failures
                    .iter()
                    .any(|line| line.contains("intent_register") && line.contains("refused")),
            )
        })
        .collect();
    assert_eq!(
        observed,
        [(true, 1, true, false), (false, 1, false, true)],
        "failure class by completion outcome"
    );
}
