// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::support::*;
use granary_core::{
    authlog::Epoch,
    authority_answer::{self as answer, Bound, Head, Position, PublishAnswer, Receipt},
    hash::GrainId,
    retained_submission::{
        self as retained, Candidate, LastResponse, Phase, Probe, ProbeReason, Role, Submission,
    },
    root,
};
use std::collections::BTreeSet;
use std::process::Command;
use tokio::io::AsyncWriteExt as _;

const NEXT_EPOCH: [u8; 16] = [0x44; 16];

fn active(record: &Submission) -> &Candidate {
    record
        .candidates
        .iter()
        .find(|c| c.role == Role::Active)
        .unwrap()
}
fn active_mut(record: &mut Submission) -> &mut Candidate {
    record
        .candidates
        .iter_mut()
        .find(|candidate| candidate.role == Role::Active)
        .unwrap()
}
fn position(c: &Candidate) -> Position {
    Position {
        epoch: Epoch::from_bytes(c.request.epoch),
        entry_seq: 1,
    }
}
fn reply_post(record: &Submission, reply: &Reply) -> Exchange {
    let mut e = post(record);
    match reply {
        Reply::Wire(status, _, bytes) => {
            e.status = *status;
            e.response.clone_from(bytes);
        }
        Reply::Disconnect => {
            e.status = 0;
            e.response.clear();
        }
        Reply::Historical(winner) => {
            e.status = 409;
            e.response = answer::encode(PublishAnswer::OperationBound(Bound::Landed(Receipt {
                position: position(winner),
                root_seq: winner.seq,
                stored_id: winner.id,
            })))
            .unwrap();
        }
    }
    e
}

pub(super) fn foreign(fx: &Fixture, record: &Submission) -> Vec<u8> {
    let mut doc = root::decode_root(&active(record).root).unwrap();
    doc.writer_uuid = [0x99; 16];
    let bytes = signed_root(doc);
    assert_ne!(GrainId::of(&bytes), active(record).id);
    fx.peer
        .lock()
        .unwrap()
        .roots
        .insert(ROOT_PATH.into(), bytes.clone());
    bytes
}

pub(super) fn answer_reply(case: &str, old: &Submission, occupant: &[u8]) -> Reply {
    let c = active(old);
    let head = Head::new(Some((c.seq, GrainId::of(occupant))));
    match case {
        "lost" => Reply::answer(
            200,
            PublishAnswer::Lost {
                position: position(c),
                candidate_id: c.id,
                occupant: GrainId::of(occupant),
                head: Some(head),
            },
        ),
        "stale" => Reply::answer(409, PublishAnswer::StaleBase(head)),
        "open" => Reply::answer(
            202,
            PublishAnswer::Open {
                position: position(c),
                candidate_id: c.id,
            },
        ),
        "refused" => Reply::Wire(403, Some("not-enrolled"), Vec::new()),
        "service" => Reply::Wire(503, Some("unavailable"), Vec::new()),
        "enrollment" => Reply::Wire(503, Some("enrollment-unavailable"), Vec::new()),
        "lost-reply" => Reply::Disconnect,
        _ => panic!("unknown fixture {case}"),
    }
}

pub(super) async fn uncertain(fx: &Fixture) -> Submission {
    let initial = ready(fx).await;
    fx.peer.lock().unwrap().replies.push_back(Reply::Disconnect);
    let json = run(&mut fx.command(true), 3).await;
    assert!(json.contains("\"uncertain\":true"), "{json}");
    let mut expected = live_barrier([probe(None)], None);
    expected.push(reply_post(&initial, &Reply::Disconnect));
    assert_eq!(fx.transcript(), expected);
    let old = fx.record().unwrap();
    assert_identity(&initial, &old);
    assert_eq!(old.phase, Phase::Ready);
    assert_eq!(active(&old).evidence.started, 1);
    assert_eq!(active(&old).evidence.last_answered_attempt, 0);
    assert_eq!(active(&old).root, active(&initial).root);
    assert_eq!(fx.peer.lock().unwrap().landings, 0);
    fx.reset_transcript();
    old
}

fn open_successor(before: &Submission, reply: &Reply) -> Submission {
    let mut next = before.clone();
    next.generation += 6 + u64::from(matches!(before.phase, Phase::AwaitingAnswer { .. }));
    next.phase = Phase::Ready;
    let c = &mut next.candidates[0];
    c.evidence.started += 1;
    c.evidence.last_answered_attempt = c.evidence.started;
    c.evidence.decision_seen = true;
    let Reply::Wire(status, token, bytes) = reply else {
        panic!("expected checked open reply")
    };
    next.last_response = Some(LastResponse {
        candidate: c.number,
        attempt: c.evidence.started,
        status: *status,
        token: token.unwrap_or("").as_bytes().to_vec(),
        answer: bytes.clone(),
    });
    next
}

fn answer_successor(old: &Submission, case: &str, reply: &Reply, saved: bool) -> Submission {
    let mut next = old.clone();
    next.generation += 5 + u64::from(saved); // selection/resume loads, probe start/result, attempt, answer
    next.candidates[0].evidence.started += 1;
    next.phase = Phase::AwaitingAnswer {
        candidate: 1,
        attempt: 2,
    };
    if !saved {
        return next;
    }
    next.phase = Phase::Ready;
    if case == "lost" || case == "stale" {
        next.candidates.clear();
        next.phase = Phase::Rebase;
        next.last_response = None;
    } else if let Reply::Wire(status, token, bytes) = reply {
        let evidence = &mut next.candidates[0].evidence;
        evidence.last_answered_attempt = 2;
        evidence.proved_no_write = u64::from(case == "refused" || case == "enrollment");
        evidence.decision_seen = case == "open";
        next.last_response = Some(LastResponse {
            candidate: 1,
            attempt: 2,
            status: *status,
            token: token.unwrap_or("").as_bytes().to_vec(),
            answer: bytes.clone(),
        });
    }
    next
}

fn signed_root(mut doc: root::RootDoc) -> Vec<u8> {
    let key = seed_key();
    doc.sigs.clear();
    doc.sigs.push(root::RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    root::encode_root(&doc).unwrap()
}

fn deferred_record(
    old: &Submission,
    case: &str,
    two_slots: bool,
) -> (Submission, Reply, Vec<(String, Vec<u8>)>) {
    let mut next = old.clone();
    if two_slots {
        let mut history = next.candidates[0].clone();
        history.role = Role::History;
        let mut doc = root::decode_root(&history.root).unwrap();
        doc.seq = history.seq + 1;
        doc.parent = Some(history.id);
        doc.timestamp.secs += 1;
        let candidate_root = signed_root(doc);
        let candidate = Candidate {
            number: history.number + 1,
            role: Role::Active,
            seq: history.seq + 1,
            id: GrainId::of(&candidate_root),
            root: candidate_root,
            evidence: retained::Evidence::default(),
            ..history.clone()
        };
        next.candidates = vec![history, candidate];
    }
    let active = active(&next).clone();
    let mut occupant_doc = root::decode_root(&active.root).unwrap();
    occupant_doc.writer_uuid = [0x99; 16];
    let occupant = signed_root(occupant_doc);
    let reply = answer_reply(case, &next, &occupant);
    let attempt = next
        .candidates
        .iter_mut()
        .find(|candidate| candidate.number == active.number)
        .unwrap()
        .evidence
        .start()
        .unwrap();
    next.candidates
        .iter_mut()
        .find(|candidate| candidate.number == active.number)
        .unwrap()
        .evidence
        .answer(attempt, case == "stale", case == "lost")
        .unwrap();
    let Reply::Wire(status, token, bytes) = &reply else {
        unreachable!()
    };
    next.last_response = Some(LastResponse {
        candidate: active.number,
        attempt,
        status: *status,
        token: token.unwrap_or("").as_bytes().to_vec(),
        answer: bytes.clone(),
    });
    next.phase = Phase::Unresolved(Probe {
        cycle: next.generation,
        seq: active.seq,
        reason: ProbeReason::ContentUnavailable,
    });
    next.generation += 1;
    retained::validate(&next).unwrap();
    let mut roots = Vec::new();
    if two_slots {
        let history = &next.candidates[0];
        roots.push((
            format!("/volume/alpha/root/{:020}", history.seq),
            history.root.clone(),
        ));
    }
    roots.push((format!("/volume/alpha/root/{:020}", active.seq), occupant));
    (next, reply, roots)
}

fn assert_deferred_marker(record: &Submission, answer: &LastResponse, sends: usize, case: &str) {
    assert!(
        matches!(
            record.phase,
            Phase::Unresolved(Probe {
                reason: ProbeReason::ContentUnavailable,
                ..
            })
        ),
        "{case}: wrong replay phase: {:?}",
        record.phase
    );
    assert_eq!(
        (record.last_response.as_ref(), sends),
        (Some(answer), 1),
        "{case}: replay write replaced the answer marker"
    );
}

async fn make_deferred(
    fx: &Fixture,
    case: &str,
    two_slots: bool,
) -> (Submission, LastResponse, Vec<(String, Vec<u8>)>) {
    let old = ready(fx).await;
    let (expected, reply, roots) = deferred_record(&old, case, two_slots);
    let mut prepared = expected.clone();
    prepared.phase = Phase::Ready;
    prepared.last_response = None;
    active_mut(&mut prepared).evidence = retained::Evidence::default();
    retained::validate(&prepared).unwrap();
    fx.install(&prepared);
    {
        let mut peer = fx.peer.lock().unwrap();
        peer.roots.clear();
        peer.roots_on_publish = roots.iter().cloned().collect();
        peer.probe_replies
            .extend((0..prepared.candidates.len()).map(|_| ProbeReply::Normal));
        peer.probe_replies.push_back(ProbeReply::Failed);
        peer.replies.push_back(reply);
    }
    let json = run(&mut fx.command(true), 5).await;
    assert!(
        json.contains("\"outcome\":\"unresolved\""),
        "{case}: {json}"
    );
    let deferred = fx.record().unwrap();
    let answer = deferred.last_response.clone().unwrap();
    assert_deferred_marker(&deferred, &answer, 1, case);
    assert_eq!(
        fx.transcript()
            .iter()
            .filter(|exchange| exchange.method == "POST")
            .count(),
        1,
        "{case}: initial deferral must account one send"
    );
    fx.reset_transcript();
    (deferred, answer, roots)
}

async fn classify_deferred(
    fx: &Fixture,
    marker: &Submission,
    roots: &[(String, Vec<u8>)],
    completes: bool,
    answer_case: &str,
    case: &str,
) {
    {
        let mut peer = fx.peer.lock().unwrap();
        peer.roots = roots.iter().cloned().collect();
        peer.probe = ProbeReply::Normal;
        peer.probe_replies.clear();
        peer.max_seq_replies.clear();
    }
    fx.reset_transcript();
    let json = if completes {
        run(&mut recover(fx, marker), 0).await
    } else {
        cut_command(fx, &mut recover(fx, marker), "probe-result", "after", 1).await;
        String::new()
    };
    let classified = fx.record().unwrap();
    let destination = if completes {
        matches!(classified.phase, Phase::Complete(_))
    } else {
        classified.phase == Phase::Rebase
    };
    assert_eq!(
        (destination, classified.last_response.is_some()),
        (true, completes || answer_case == "stale"),
        "{case}: restored reads did not install the ordinary destination: {classified:?}; {json}"
    );
    assert!(
        fx.transcript()
            .iter()
            .all(|exchange| exchange.method != "POST"),
        "{case}: replay resent the answered attempt: {:?}",
        fx.transcript()
    );
}

fn recover(fx: &Fixture, record: &Submission) -> Command {
    let mut cmd = fx.command(true);
    cmd.args(["--recover", &hex(&record.publication_id)]);
    cmd
}
async fn refuses_loaded_rebase(fx: &Fixture, record: &Submission) {
    fx.reset_transcript();
    let json = run(&mut fx.command(true), 5).await;
    assert!(
        json.contains("loaded rebase; explicit recovery required"),
        "{json}"
    );
    assert!(
        json.contains("continue or explicitly recover the retained publication")
            && json.contains("abandonment stops local recovery"),
        "{json}"
    );
    assert!(fx.transcript().is_empty());
    assert_catalogue(record, &fx.record().unwrap());
}

pub(super) fn preparation(
    fx: &Fixture,
    replacement: &Submission,
    previous: &BTreeSet<String>,
    base: Option<&[u8]>,
) -> Vec<Exchange> {
    let s = fx.peer.lock().unwrap();
    let b = root::decode_root(&active(replacement).root).unwrap();
    let frozen = root::decode_root(&replacement.frozen.initial_root).unwrap();
    assert_eq!(
        b.manifest_root, frozen.manifest_root,
        "replacement harvested another manifest"
    );
    assert_eq!(
        b.writer_uuid,
        writer_uuid(&b, &replacement.frozen.writer_identity),
        "replacement changed its frozen writer input"
    );
    assert_eq!(active(replacement).request, replacement.current.unwrap());
    let meta = |id| format!("/volume/alpha/meta/{id}");
    let get = |id| {
        request(
            "GET",
            &meta(id),
            Vec::new(),
            200,
            s.objects[&meta(id)].clone(),
        )
    };
    if let Some(base) = base {
        let a = root::decode_root(base).unwrap();
        assert_eq!(b.seq, a.seq + 1);
        assert_eq!(b.parent, Some(GrainId::of(base)));
        assert_eq!(
            b.manifest_root,
            root::decode_root(&replacement.frozen.initial_root)
                .unwrap()
                .manifest_root
        );
        assert_eq!(b.binmap_index, a.binmap_index);
        let index =
            granary_core::binmap::decode_binmap_index(&s.objects[&meta(a.binmap_index)]).unwrap();
        let mut e = vec![
            request(
                "GET",
                "/volume/alpha/max-seq",
                Vec::new(),
                200,
                format!("{:020}", a.seq).into_bytes(),
            ),
            probe(Some(base.to_vec())),
            get(a.sheaf_head),
            get(a.binmap_index),
            get(index.bin_table),
        ];
        e.extend(index.shards.into_iter().map(get));
        e.push(request(
            "PUT",
            &meta(b.sheaf_head),
            s.objects[&meta(b.sheaf_head)].clone(),
            201,
            Vec::new(),
        ));
        e
    } else {
        let mut e = vec![request(
            "GET",
            "/volume/alpha/max-seq",
            Vec::new(),
            404,
            Vec::new(),
        )];
        e.extend(
            preparation_transcript(&s, b.binmap_index, b.sheaf_head, previous)
                .into_iter()
                .skip(3),
        );
        e
    }
}

async fn release_tail(fx: &Fixture, saved: &Submission, occupant: &[u8]) {
    refuses_loaded_rebase(fx, saved).await;
    let previous = fx.peer.lock().unwrap().objects.keys().cloned().collect();
    fx.reset_transcript();
    cut_command(fx, &mut recover(fx, saved), "replacement-save", "after", 1).await;
    let replacement = fx.record().unwrap();
    assert_identity(saved, &replacement);
    assert_eq!(replacement.current, saved.current);
    assert_eq!(replacement.candidates.len(), 1);
    let mut expected = preparation(fx, &replacement, &previous, Some(occupant));
    // Released catalogue is empty: no recovery probe precedes base verification.
    assert_eq!(fx.transcript(), expected);
    fx.reset_transcript();
    let json = run(&mut fx.command(true), 0).await;
    assert_landed_report(&json, &replacement);
    let head = root::decode_root(occupant).unwrap().seq;
    expected = live_barrier(
        [request(
            "GET",
            "/volume/alpha/root/00000000000000000002",
            Vec::new(),
            404,
            Vec::new(),
        )],
        Some(head),
    );
    expected.extend([
        post(&replacement),
        request(
            "PUT",
            "/volume/alpha/hint",
            b"00000000000000000002".to_vec(),
            204,
            Vec::new(),
        ),
    ]);
    assert_eq!(fx.transcript(), expected);
    let s = fx.peer.lock().unwrap();
    assert_eq!(s.roots.len(), 2);
    assert_eq!(s.roots[ROOT_PATH], occupant);
    assert_eq!(
        s.roots["/volume/alpha/root/00000000000000000002"],
        active(&replacement).root
    );
    assert_eq!(s.landings, 1);
}

#[tokio::test]
async fn c5_answer_accounting_release_and_foreign_open() {
    let mut observed = Vec::new();
    for case in [
        "lost",
        "stale",
        "open",
        "refused",
        "service",
        "enrollment",
        "lost-reply",
    ] {
        for (name, side) in [
            ("dispatch", "after"),
            ("answer-save", "before"),
            ("answer-save", "after"),
        ] {
            let fx = Fixture::new().await;
            let old = uncertain(&fx).await;
            let occupant = foreign(&fx, &old);
            let head = root::decode_root(&occupant).unwrap().seq;
            let reply = answer_reply(case, &old, &occupant);
            fx.peer.lock().unwrap().replies.push_back(reply.clone());
            cut(&fx, name, side, true).await;
            let saved = fx.record().unwrap();
            let accounted = name == "answer-save" && side == "after";
            assert_eq!(
                saved,
                answer_successor(&old, case, &reply, accounted),
                "{case} {name}:{side}"
            );
            let mut expected = live_barrier([probe(Some(occupant.clone()))], Some(head));
            expected.push(reply_post(&old, &reply));
            if name == "answer-save" && (case == "lost" || case == "stale") {
                expected.extend(live_barrier([probe(Some(occupant.clone()))], Some(head)));
            }
            assert_eq!(fx.transcript(), expected, "{case} {name}:{side}");
            fx.reset_transcript();
            if case == "lost" || case == "stale" {
                let released = if accounted {
                    saved
                } else {
                    fx.peer.lock().unwrap().replies.push_back(reply.clone());
                    cut(&fx, "answer-save", "after", true).await;
                    let mut expected = live_barrier([probe(Some(occupant.clone()))], Some(head));
                    expected.push(reply_post(&old, &reply));
                    expected.extend(live_barrier([probe(Some(occupant.clone()))], Some(head)));
                    assert_eq!(fx.transcript(), expected);
                    let released = fx.record().unwrap();
                    assert_eq!(released.phase, Phase::Rebase);
                    assert!(released.candidates.is_empty());
                    assert_eq!(released.current, old.current);
                    released
                };
                release_tail(&fx, &released, &occupant).await;
            } else {
                // Each invocation of the foreign/open wedge sends once, without
                // recounting the saved answer or releasing the earlier uncertainty.
                for invocation in 1..=2 {
                    fx.reset_transcript();
                    let open = answer_reply("open", &old, &occupant);
                    fx.peer.lock().unwrap().replies.push_back(open.clone());
                    let before = fx.record().unwrap();
                    let json = run(&mut fx.command(true), 3).await;
                    assert!(
                        json.contains("possible wedge") && json.contains("\"uncertain\":true"),
                        "{json}"
                    );
                    let mut expected = live_barrier([probe(Some(occupant.clone()))], Some(head));
                    expected.push(reply_post(&old, &open));
                    assert_eq!(fx.transcript(), expected);
                    let after = fx.record().unwrap();
                    assert_eq!(after, open_successor(&before, &open));
                    assert_identity(&old, &after);
                    assert_eq!(after.current, old.current);
                    let c = active(&after);
                    assert_eq!(c.root, active(&old).root);
                    assert_eq!(c.evidence.started, 2 + invocation);
                    assert_eq!(c.evidence.last_answered_attempt, 2 + invocation);
                    assert_eq!(
                        c.evidence.proved_no_write,
                        u64::from(accounted && (case == "refused" || case == "enrollment"))
                    );
                    assert!(c.evidence.decision_seen);
                    assert_eq!(after.phase, Phase::Ready);
                    assert_eq!(fx.peer.lock().unwrap().roots[ROOT_PATH], occupant);
                    assert_eq!(fx.peer.lock().unwrap().landings, 0);
                }
            }
            observed.push(format!("{name}:{side}"));
        }
    }
    observed.sort();
    observed.dedup();
    observe(
        "continuation::c5_answer_accounting_release_and_foreign_open",
        &observed,
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "seven replay writers for both answer kinds keep each injected read result beside its durable tuple"
)]
async fn deferred_replay_failure_writes_preserve_marker() {
    let mut preservation_cases = 0;
    let mut observed = Vec::new();
    for answer_case in ["lost", "stale"] {
        for replay_case in [
            "pre-probe",
            "intermediate",
            "probe-transport",
            "listing-transport",
            "listing-below",
            "chain-missing",
            "chain-transport",
        ] {
            let fx = Fixture::new().await;
            let two_slots = matches!(replay_case, "intermediate" | "listing-below");
            let (marker, answer, roots) = make_deferred(&fx, answer_case, two_slots).await;
            let (cut_name, occurrence) = match replay_case {
                "pre-probe" => ("probe-save", 1),
                "intermediate" => ("probe-result", 1),
                "probe-transport" => {
                    fx.peer
                        .lock()
                        .unwrap()
                        .probe_replies
                        .push_back(ProbeReply::Failed);
                    ("probe-result", 1)
                }
                "listing-transport" => {
                    fx.peer
                        .lock()
                        .unwrap()
                        .max_seq_replies
                        .push_back(MaxSeqReply::Failed);
                    ("probe-result", 1)
                }
                "listing-below" => {
                    let mut peer = fx.peer.lock().unwrap();
                    peer.probe_replies
                        .extend([ProbeReply::Normal, ProbeReply::Missing]);
                    peer.max_seq_replies.push_back(MaxSeqReply::Value(Some(1)));
                    ("probe-result", 2)
                }
                "chain-missing" => {
                    let mut peer = fx.peer.lock().unwrap();
                    peer.probe_replies
                        .extend([ProbeReply::Normal, ProbeReply::Missing]);
                    peer.max_seq_replies.push_back(MaxSeqReply::Value(Some(3)));
                    ("probe-result", 1)
                }
                "chain-transport" => {
                    let mut peer = fx.peer.lock().unwrap();
                    peer.probe_replies
                        .extend([ProbeReply::Normal, ProbeReply::Failed]);
                    peer.max_seq_replies.push_back(MaxSeqReply::Value(Some(3)));
                    ("probe-result", 1)
                }
                _ => unreachable!(),
            };
            cut_command(
                &fx,
                &mut recover(&fx, &marker),
                cut_name,
                "after",
                occurrence,
            )
            .await;
            let saved = fx.record().unwrap();
            assert_deferred_marker(&saved, &answer, 1, &format!("{answer_case}/{replay_case}"));
            assert!(
                fx.transcript()
                    .iter()
                    .all(|exchange| exchange.method != "POST"),
                "{answer_case}/{replay_case}: replay dispatched before its cut"
            );
            classify_deferred(
                &fx,
                &marker,
                &roots,
                two_slots,
                answer_case,
                &format!("{answer_case}/{replay_case}"),
            )
            .await;
            observed.push(format!("{cut_name}:after"));
            preservation_cases += 1;
        }
    }
    assert_eq!(preservation_cases, 14);

    let mut integrity_cases = 0;
    for answer_case in ["lost", "stale"] {
        let fx = Fixture::new().await;
        let (marker, _, _) = make_deferred(&fx, answer_case, false).await;
        if answer_case == "lost" {
            fx.peer
                .lock()
                .unwrap()
                .probe_replies
                .push_back(ProbeReply::Oversized);
        } else {
            fx.peer.lock().unwrap().roots.insert(
                format!("/volume/alpha/root/{:020}", active(&marker).seq),
                b"malformed".to_vec(),
            );
        }
        let json = run(&mut recover(&fx, &marker), 6).await;
        let ended = fx.record().unwrap();
        assert_eq!(
            (ended.phase, ended.last_response.is_some()),
            (Phase::Ready, false),
            "{answer_case}: malformed replay did not consume the marker: {json}"
        );
        assert!(
            json.contains(
                "publication work stopped; inspect checked response and explicitly recover retained content"
            ),
            "{answer_case}: wrong integrity ending: {json}"
        );
        assert!(
            fx.transcript()
                .iter()
                .all(|exchange| exchange.method != "POST"),
            "{answer_case}: integrity replay dispatched"
        );
        integrity_cases += 1;
    }
    assert_eq!(integrity_cases, 2);
    observed.sort();
    observed.dedup();
    observe(
        "continuation::deferred_replay_failure_writes_preserve_marker",
        &observed,
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "answer accounting and every replay read cut share one restart timeline"
)]
async fn deferred_answer_restart_cuts_classify_once() {
    let mut cases = 0;
    let mut observed = Vec::new();
    for answer_case in ["lost", "stale"] {
        for side in ["before", "after"] {
            let fx = Fixture::new().await;
            let old = ready(&fx).await;
            let (expected, reply, roots) = deferred_record(&old, answer_case, false);
            let mut prepared = expected.clone();
            prepared.phase = Phase::Ready;
            prepared.last_response = None;
            active_mut(&mut prepared).evidence = retained::Evidence::default();
            retained::validate(&prepared).unwrap();
            fx.install(&prepared);
            {
                let mut peer = fx.peer.lock().unwrap();
                peer.roots.clear();
                peer.roots_on_publish = roots.iter().cloned().collect();
                peer.probe_replies
                    .extend([ProbeReply::Normal, ProbeReply::Failed]);
                peer.replies.push_back(reply);
            }
            cut(&fx, "answer-save", side, true).await;
            let saved = fx.record().unwrap();
            if side == "after" {
                assert_deferred_marker(
                    &saved,
                    expected.last_response.as_ref().unwrap(),
                    1,
                    &format!("{answer_case}/answer-save:{side}"),
                );
            } else {
                assert!(
                    matches!(saved.phase, Phase::AwaitingAnswer { .. })
                        && saved.last_response.is_none(),
                    "{answer_case}/answer-save:{side}: partial answer was durable: {saved:?}"
                );
            }
            assert_eq!(
                fx.transcript()
                    .iter()
                    .filter(|exchange| exchange.method == "POST")
                    .count(),
                1,
                "{answer_case}/answer-save:{side}: cut send count"
            );
            observed.push(format!("answer-save:{side}"));
            cases += 1;
        }

        for side in ["before", "after"] {
            let fx = Fixture::new().await;
            let (marker, answer, roots) = make_deferred(&fx, answer_case, false).await;
            cut_command(&fx, &mut recover(&fx, &marker), "probe-result", side, 1).await;
            let saved = fx.record().unwrap();
            if side == "before" {
                assert_deferred_marker(
                    &saved,
                    &answer,
                    1,
                    &format!("{answer_case}/classification:{side}"),
                );
                classify_deferred(
                    &fx,
                    &marker,
                    &roots,
                    false,
                    answer_case,
                    &format!("{answer_case}/classification:{side}"),
                )
                .await;
            } else {
                assert_eq!(
                    (saved.phase, saved.last_response.is_some()),
                    (Phase::Rebase, answer_case == "stale"),
                    "{answer_case}/classification:{side}: destination was not atomic"
                );
                assert!(
                    fx.transcript()
                        .iter()
                        .all(|exchange| exchange.method != "POST"),
                    "{answer_case}/classification:{side}: replay dispatched"
                );
            }
            observed.push(format!("probe-result:{side}"));
            cases += 1;
        }

        for (cut_name, occurrence) in [
            ("probe-delivered", 1),
            ("probe-delivered", 2),
            ("probe-result", 2),
        ] {
            let fx = Fixture::new().await;
            let (marker, answer, roots) = make_deferred(&fx, answer_case, true).await;
            let side = if cut_name == "probe-delivered" {
                "after"
            } else {
                "before"
            };
            cut_command(&fx, &mut recover(&fx, &marker), cut_name, side, occurrence).await;
            let saved = fx.record().unwrap();
            assert_deferred_marker(
                &saved,
                &answer,
                1,
                &format!("{answer_case}/{cut_name}:{side}:{occurrence}"),
            );
            classify_deferred(
                &fx,
                &marker,
                &roots,
                true,
                answer_case,
                &format!("{answer_case}/{cut_name}:{side}:{occurrence}"),
            )
            .await;
            observed.push(format!("{cut_name}:{side}"));
            cases += 1;
        }
    }
    assert_eq!(cases, 14);
    observed.sort();
    observed.dedup();
    observe(
        "continuation::deferred_answer_restart_cuts_classify_once",
        &observed,
    );
}

async fn epoch_fixture(fx: &Fixture) -> (Submission, Reply) {
    let old = uncertain(fx).await;
    let reply = Reply::answer(
        409,
        PublishAnswer::EpochMismatch {
            epoch: Epoch::from_bytes(NEXT_EPOCH),
            head: Some(Head::new(None)),
        },
    );
    fx.peer.lock().unwrap().epoch = Some(NEXT_EPOCH);
    (old, reply)
}
fn assert_epoch(old: &Submission, after: &Submission, operation_saved: bool, new_attempts: u64) {
    assert_identity(old, after);
    let mut c = old.candidates[0].clone();
    c.role = Role::Retired;
    c.evidence.started += new_attempts;
    c.evidence.proved_no_write += 1;
    c.evidence.last_answered_attempt = c.evidence.started;
    assert_eq!(after.candidates, [c]);
    assert!(!after.candidates[0].evidence.never_decided());
    if operation_saved {
        assert_eq!(after.phase, Phase::Rebase);
        let current = after.current.unwrap();
        assert_eq!(current.epoch, NEXT_EPOCH);
        assert!(
            after
                .candidates
                .iter()
                .all(|c| c.request.operation != current.operation)
        );
    } else {
        assert_eq!(after.phase, Phase::EpochRecovery { epoch: NEXT_EPOCH });
        assert_eq!(after.current, None);
    }
}

#[tokio::test]
async fn c6_epoch_and_operation_saves_preserve_retired_tuples() {
    let mut observed = Vec::new();
    for name in ["epoch-save", "operation-save"] {
        for side in ["before", "after"] {
            let fx = Fixture::new().await;
            let (old, reply) = epoch_fixture(&fx).await;
            cut(&fx, name, side, true).await;
            let saved = fx.record().unwrap();
            let mut expected = live_barrier([probe(None)], None);
            expected.push(reply_post(&old, &reply));
            assert_eq!(fx.transcript(), expected);
            if name == "epoch-save" && side == "before" {
                assert_eq!(saved, answer_successor(&old, "epoch", &reply, false));
                fx.reset_transcript();
                cut(&fx, "operation-save", "after", true).await;
                let mut expected = live_barrier([probe(None)], None);
                expected.push(reply_post(&old, &reply));
                assert_eq!(
                    fx.transcript(),
                    expected,
                    "restart must retry the old exact tuple before learning the epoch"
                );
            } else {
                assert_epoch(&old, &saved, name == "operation-save" && side == "after", 1);
                assert_eq!(
                    saved.generation,
                    old.generation
                        + 5
                        + u64::from(name == "operation-save")
                        + u64::from(side == "after")
                );
                assert_eq!(
                    saved.last_response.as_ref().unwrap().answer,
                    match &reply {
                        Reply::Wire(_, _, b) => b.clone(),
                        _ => unreachable!(),
                    }
                );
                if name != "operation-save" || side != "after" {
                    fx.reset_transcript();
                    cut(&fx, "operation-save", "after", true).await;
                    assert!(
                        fx.transcript().is_empty(),
                        "epoch recovery draw does network work"
                    );
                }
            }
            let rebased = fx.record().unwrap();
            // The pre-save kill retained an unanswered second attempt. Restart
            // sent the exact tuple again as attempt three before retiring it.
            let new_attempts = 1 + u64::from(name == "epoch-save" && side == "before");
            assert_epoch(&old, &rebased, true, new_attempts);
            refuses_loaded_rebase(&fx, &rebased).await;
            let previous = fx.peer.lock().unwrap().objects.keys().cloned().collect();
            fx.reset_transcript();
            cut_command(
                &fx,
                &mut recover(&fx, &rebased),
                "replacement-save",
                "after",
                1,
            )
            .await;
            let replacement = fx.record().unwrap();
            assert_identity(&old, &replacement);
            assert_eq!(
                replacement.current, rebased.current,
                "explicit recovery drew another operation"
            );
            assert_eq!(replacement.candidates[0], rebased.candidates[0]);
            assert_eq!(active(&replacement).request, rebased.current.unwrap());
            let mut expected = live_barrier([probe(None)], None);
            expected.extend(preparation(&fx, &replacement, &previous, None));
            assert_eq!(fx.transcript(), expected);
            fx.reset_transcript();
            let json = run(&mut fx.command(true), 0).await;
            let mut winner_record = replacement.clone();
            winner_record.candidates = vec![active(&replacement).clone()];
            assert_landed_report(&json, &winner_record);
            let mut expected = live_barrier([probe(None)], None);
            expected.extend([post(&replacement), hint()]);
            assert_eq!(fx.transcript(), expected);
            assert_eq!(
                fx.peer.lock().unwrap().roots[ROOT_PATH],
                active(&replacement).root
            );
            assert_eq!(fx.peer.lock().unwrap().landings, 1);
            observed.push(format!("{name}:{side}"));
        }
    }
    observe(
        "continuation::c6_epoch_and_operation_saves_preserve_retired_tuples",
        &observed,
    );
}

#[test]
fn c6_epoch_oracle_rejects_lost_history_and_identity_changes() {
    let mut old = retained::decode(include_bytes!(
        "../../../granary-core/tests/vectors/retained-submission/ready.bin"
    ))
    .unwrap();
    old.candidates[0].evidence.started = 1;
    for attempts in [1, 2] {
        let mut after = old.clone();
        after.candidates[0].role = Role::Retired;
        after.candidates[0].evidence.started = 1 + attempts;
        after.candidates[0].evidence.last_answered_attempt = 1 + attempts;
        after.candidates[0].evidence.proved_no_write = 1;
        after.phase = Phase::EpochRecovery { epoch: NEXT_EPOCH };
        after.current = None;
        assert_epoch(&old, &after, false, attempts);
        after.current = Some(retained::RequestIdentity {
            epoch: NEXT_EPOCH,
            operation: [0x55; 16],
        });
        after.phase = Phase::Rebase;
        assert_epoch(&old, &after, true, attempts);
        for field in [
            "history",
            "epoch",
            "operation",
            "publication",
            "writer",
            "intent",
            "attempt",
        ] {
            let mut bad = after.clone();
            match field {
                "history" => bad.candidates.clear(),
                "epoch" => bad.current.as_mut().unwrap().epoch = [0x99; 16],
                "operation" => {
                    bad.current.as_mut().unwrap().operation = old.current.unwrap().operation;
                }
                "publication" => bad.publication_id[0] ^= 1,
                "writer" => bad.frozen.writer_identity[0] ^= 1,
                "intent" => bad.frozen.min_prefix_bits ^= 1,
                "attempt" => bad.candidates[0].evidence.started -= 1,
                _ => unreachable!(),
            }
            assert!(
                std::panic::catch_unwind(|| assert_epoch(&old, &bad, true, attempts)).is_err(),
                "epoch oracle accepted {field}"
            );
            println!("REFUSED epoch oracle {field} after {attempts} new attempts");
        }
    }
    observe(
        "continuation::c6_epoch_oracle_rejects_lost_history_and_identity_changes",
        &[],
    );
}

pub(super) async fn loaded_rebase(fx: &Fixture) -> Submission {
    let old = uncertain(fx).await;
    cut(fx, "probe-save", "after", true).await;
    assert!(matches!(fx.record().unwrap().phase, Phase::ProbeStarted(_)));
    assert!(fx.transcript().is_empty());
    cut_command(fx, &mut recover(fx, &old), "probe-result", "after", 1).await;
    let rebased = fx.record().unwrap();
    assert_eq!(rebased.phase, Phase::Rebase);
    assert_catalogue(&old, &rebased);
    assert_eq!(fx.transcript(), live_barrier([probe(None)], None));
    fx.reset_transcript();
    rebased
}

#[tokio::test]
async fn c7_replacement_uses_frozen_content_and_capacity_never_evicts() {
    let mut observed = Vec::new();
    for side in ["before", "after"] {
        for deleted in [false, true] {
            let fx = Fixture::new().await;
            let old = loaded_rebase(&fx).await;
            refuses_loaded_rebase(&fx, &old).await;
            if deleted {
                std::fs::remove_dir_all(&fx.source).unwrap();
            } else {
                std::fs::write(fx.source.join("file"), b"changed content").unwrap();
            }
            let mut previous = fx.peer.lock().unwrap().objects.keys().cloned().collect();
            fx.reset_transcript();
            cut_command(&fx, &mut recover(&fx, &old), "replacement-save", side, 1).await;
            let saved = fx.record().unwrap();
            assert_identity(&old, &saved);
            assert_eq!(saved.current, old.current);
            assert!(!fx.transcript().iter().any(|e| e.method == "POST"));
            if side == "before" {
                assert_catalogue(&old, &saved);
                assert_eq!(saved.phase, Phase::Rebase);
                refuses_loaded_rebase(&fx, &saved).await;
                previous = fx.peer.lock().unwrap().objects.keys().cloned().collect();
                fx.reset_transcript();
                cut_command(&fx, &mut recover(&fx, &old), "replacement-save", "after", 1).await;
            } else {
                assert_eq!(saved.phase, Phase::Ready);
            }
            let replacement = fx.record().unwrap();
            assert_catalogue(&empty_replacement(&fx, &old, &previous), &replacement);
            assert_eq!(replacement.candidates.len(), 2);
            let mut history = old.candidates[0].clone();
            history.role = Role::History;
            assert_eq!(replacement.candidates[0], history);
            assert_ne!(replacement.candidates[0].id, active(&replacement).id);
            assert_ne!(replacement.candidates[0].root, active(&replacement).root);
            assert_identity(&old, &replacement);
            let mut expected = live_barrier([probe(None)], None);
            expected.extend(preparation(&fx, &replacement, &previous, None));
            assert_eq!(
                fx.transcript(),
                expected,
                "complete frozen reconstruction transcript"
            );
            fx.reset_transcript();
            let json = run(&mut fx.command(true), 0).await;
            let mut winner_record = replacement.clone();
            winner_record.candidates = vec![active(&replacement).clone()];
            assert_landed_report(&json, &winner_record);
            let mut expected = live_barrier([probe(None)], None);
            expected.extend([post(&replacement), hint()]);
            assert_eq!(fx.transcript(), expected);
            assert_eq!(
                fx.peer.lock().unwrap().roots[ROOT_PATH],
                active(&replacement).root
            );
            assert_eq!(fx.peer.lock().unwrap().landings, 1);
            observed.push(format!("replacement-save:{side}"));
        }
    }
    // Validated setup boundary: capacity is generated locally from a real CLI
    // publication, with every entry uncertain and distinct by request identity.
    let fx = Fixture::new().await;
    let old = capacity_fixture(&fx).await;
    for _ in 0..2 {
        fx.reset_transcript();
        let json = run(&mut recover(&fx, &old), 5).await;
        assert!(
            json.contains("candidate capacity exhausted")
                && json.contains("continue or explicitly recover the retained publication")
                && json.contains("abandonment stops local recovery"),
            "{json}"
        );
        assert_eq!(fx.transcript(), live_barrier([probe(None)], None));
        assert_catalogue(&old, &fx.record().unwrap());
        assert!(fx.peer.lock().unwrap().roots.is_empty());
    }
    observed.sort();
    observed.dedup();
    observe(
        "continuation::c7_replacement_uses_frozen_content_and_capacity_never_evicts",
        &observed,
    );
}

pub(super) async fn capacity_fixture(fx: &Fixture) -> Submission {
    let mut old = loaded_rebase(fx).await;
    for n in 2..=retained::MAX_CANDIDATES {
        let mut c = old.candidates[0].clone();
        c.number = u64::try_from(n).unwrap();
        c.role = Role::Retired;
        c.request.epoch = [0x22; 16];
        c.request.operation[15] ^= 1;
        c.request.operation[0] = u8::try_from(n).unwrap();
        old.candidates.push(c);
    }
    retained::validate(&old).unwrap();
    fx.install(&old);
    old
}

async fn history_ready(fx: &Fixture) -> Submission {
    let old = loaded_rebase(fx).await;
    let json = run(&mut cached(fx), 5).await;
    assert!(
        json.contains("loaded rebase; explicit recovery required"),
        "{json}"
    );
    assert!(fx.transcript().is_empty());
    std::fs::write(
        fx.scratch.0.join("cache/anchors/alpha"),
        b"seq 00000000000000000003\n",
    )
    .unwrap();
    let previous = fx.peer.lock().unwrap().objects.keys().cloned().collect();
    cut_command(fx, &mut recover(fx, &old), "replacement-save", "after", 1).await;
    let saved = fx.record().unwrap();
    assert_catalogue(&empty_replacement(fx, &old, &previous), &saved);
    assert_eq!(saved.candidates.len(), 2);
    assert_ne!(saved.candidates[0].root, saved.candidates[1].root);
    assert_ne!(saved.candidates[0].id, saved.candidates[1].id);
    assert_eq!(saved.candidates[0].role, Role::History);
    assert_eq!(saved.candidates[1].role, Role::Active);
    assert_eq!(saved.candidates[0].request, saved.candidates[1].request);
    let mut expected = live_barrier([probe(None)], None);
    expected.extend(preparation(fx, &saved, &previous, None));
    assert_eq!(fx.transcript(), expected);
    fx.reset_transcript();
    saved
}
fn assert_winner(fx: &Fixture, before: &Submission, cached: bool) {
    let after = fx.record().unwrap();
    assert_identity(before, &after);
    let Phase::Complete(done) = after.phase else {
        panic!("completion missing")
    };
    let a = &before.candidates[0];
    let b = &before.candidates[1];
    assert_eq!(done.id, a.id);
    assert_eq!(done.root, a.root);
    assert_ne!(done.id, b.id);
    assert_ne!(done.root, b.root);
    let s = fx.peer.lock().unwrap();
    assert_eq!(s.roots.len(), 1);
    assert_eq!(s.roots[ROOT_PATH], a.root);
    assert_eq!(s.landings, 1);
    if cached {
        let cache = fx.scratch.0.join("cache");
        assert_eq!(
            std::fs::read(cache.join("roots/alpha/00000000000000000001")).unwrap(),
            a.root
        );
        let anchor = std::fs::read_to_string(cache.join("anchors/alpha")).unwrap();
        assert_eq!(
            anchor, "seq 00000000000000000003\n",
            "winner repair lowered the existing floor"
        );
    }
}
fn cached(fx: &Fixture) -> Command {
    let mut cmd = fx.command(true);
    cmd.arg("--cache-dir").arg(fx.scratch.0.join("cache"));
    cmd
}

#[tokio::test]
async fn c8_historical_winner_complete_repair_and_output() {
    let mut observed = Vec::new();
    for name in [
        "complete-save",
        "cache-repair",
        "hint-repair",
        "output-write",
    ] {
        for side in ["before", "after"] {
            let fx = Fixture::new().await;
            let before = history_ready(&fx).await;
            let reply = Reply::Historical(before.candidates[0].clone());
            fx.peer.lock().unwrap().replies.push_back(reply.clone());
            cut_command(&fx, &mut cached(&fx), name, side, 1).await;
            let mut expected = live_barrier([probe(None)], None);
            expected.push(reply_post(&before, &reply));
            if name == "hint-repair" && side == "after" || name == "output-write" {
                expected.push(hint());
            }
            assert_eq!(fx.transcript(), expected);
            if name == "complete-save" && side == "before" {
                let saved = fx.record().unwrap();
                assert_eq!(
                    saved.phase,
                    Phase::AwaitingAnswer {
                        candidate: 2,
                        attempt: 1
                    }
                );
                assert_eq!(saved.candidates[0], before.candidates[0]);
                assert_eq!(saved.candidates[1].evidence.last_answered_attempt, 0);
            } else {
                assert_winner(
                    &fx,
                    &before,
                    name == "cache-repair" && side == "after"
                        || name == "hint-repair"
                        || name == "output-write",
                );
            }
            fx.reset_transcript();
            let json = run(&mut cached(&fx), 0).await;
            assert_landed_report(&json, &before);
            let expected = if name == "complete-save" && side == "before" {
                let mut expected = live_barrier(
                    [probe(Some(before.candidates[0].root.clone()))],
                    Some(before.candidates[0].seq),
                );
                expected.push(hint());
                expected
            } else {
                vec![hint()]
            };
            assert_eq!(
                fx.transcript(),
                expected,
                "Complete must skip catalogue recovery"
            );
            assert_winner(&fx, &before, true);
            fx.reset_transcript();
            let mut human = fx.shipping_command(true, false);
            human.arg("--cache-dir").arg(fx.scratch.0.join("cache"));
            let text = run(&mut human, 0).await;
            assert!(
                text.contains(&format!("seq=1 id={}", before.candidates[0].id))
                    && text.contains("route=authority"),
                "{text}"
            );
            assert!(
                !text.contains(&before.candidates[1].id.to_string()),
                "{text}"
            );
            assert_eq!(fx.transcript(), [hint()]);
            observed.push(format!("{name}:{side}"));
        }
    }
    // Close the actual pipe's read end after rendezvous, immediately before the
    // real write. Complete and its repairs survive the resulting EPIPE.
    let fx = Fixture::new().await;
    let before = history_ready(&fx).await;
    fx.peer
        .lock()
        .unwrap()
        .replies
        .push_back(Reply::Historical(before.candidates[0].clone()));
    let mut cmd = cached(&fx);
    let rendezvous = Rendezvous::arm(&mut cmd, &fx.scratch.0, "output-write", "before", 1);
    let mut child = Process::spawn(&mut cmd);
    let (_, mut stream) = rendezvous.reached(&mut child).await.unwrap();
    child.close_stdout();
    stream.write_all(b"continue\n").await.unwrap();
    let output = child.output().await;
    assert_exit(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("output failed"));
    assert_winner(&fx, &before, true);
    fx.reset_transcript();
    let json = run(&mut cached(&fx), 0).await;
    assert_landed_report(&json, &before);
    assert_eq!(fx.transcript(), [hint()]);
    observe(
        "continuation::c8_historical_winner_complete_repair_and_output",
        &observed,
    );
}

#[tokio::test]
async fn shipping_authority_routing_and_output_smoke() {
    let fx = Fixture::new().await;
    let mut cmd = fx.shipping_command(false, true);
    // Feature-off must ignore the armed executable's test controls entirely.
    cmd.env("GRANARY_RESTART_SOCKET", fx.scratch.0.join("absent.sock"));
    let json = run(&mut cmd, 0).await;
    let record = fx.record().unwrap();
    assert_landed_report(&json, &record);
    assert!(
        json.contains("\"route\":\"authority\"")
            && json.contains("\"routing_evidence\":{\"status\":200"),
        "{json}"
    );
    {
        let s = fx.peer.lock().unwrap();
        let root = root::decode_root(&record.frozen.initial_root).unwrap();
        let mut expected =
            preparation_transcript(&s, root.binmap_index, root.sheaf_head, &BTreeSet::new());
        expected.extend(live_barrier([probe(None)], None));
        expected.extend([post(&record), hint()]);
        assert_eq!(s.transcript, expected);
        assert_eq!(s.landings, 1);
        assert_eq!(s.roots.len(), 1);
        assert_eq!(s.roots[ROOT_PATH], record.frozen.initial_root);
    }
    std::fs::remove_dir_all(&fx.source).unwrap();
    fx.reset_transcript();
    let text = run(&mut fx.shipping_command(true, false), 0).await;
    assert!(
        text.contains(&format!("seq=1 id={}", record.candidates[0].id))
            && text.contains("route=authority"),
        "{text}"
    );
    assert_eq!(fx.transcript(), [hint()]);
    fx.reset_transcript();
    let json = run(&mut fx.shipping_command(true, true), 0).await;
    assert_landed_report(&json, &record);
    assert_eq!(fx.transcript(), [hint()]);
    observe(
        "continuation::shipping_authority_routing_and_output_smoke",
        &[],
    );
}

fn installed(name: &str, side: &str) -> bool {
    name == "scope-sync" || name == "temporary-install" && side == "after"
}

fn epoch_successor(old: &Submission, reply: &Reply) -> Submission {
    let mut next = answer_successor(old, "epoch", reply, true);
    next.phase = Phase::EpochRecovery { epoch: NEXT_EPOCH };
    next.current = None;
    next.candidates[0].role = Role::Retired;
    next.candidates[0].evidence.proved_no_write = 1;
    next
}

pub(super) fn writer_uuid(doc: &root::RootDoc, writer: &[u8; 16]) -> [u8; 16] {
    let mut preimage = b"granary-writer-uuid-v2".to_vec();
    preimage.extend(doc.timestamp.secs.to_be_bytes());
    preimage.extend(doc.timestamp.nanos.to_be_bytes());
    preimage.extend(writer);
    preimage.extend(doc.seq.to_be_bytes());
    preimage.extend(doc.volume.as_str().as_bytes());
    preimage.extend(doc.manifest_root.to_bytes());
    GrainId::of(&preimage).digest()[..16].try_into().unwrap()
}

fn empty_replacement(fx: &Fixture, old: &Submission, previous: &BTreeSet<String>) -> Submission {
    // Derive B from the independently observed sheaf upload, the original root
    // and the fixture signer. Comparing this with canonical B detects a changed
    // manifest, writer, policy, request tuple or prepared root substitution.
    let s = fx.peer.lock().unwrap();
    let sheaves: Vec<_> = s
        .objects
        .iter()
        .filter(|(path, bytes)| {
            !previous.contains(*path) && granary_core::sheaf::decode_sheaf(bytes).is_ok()
        })
        .collect();
    assert_eq!(sheaves.len(), 1);
    let sheaf = granary_core::sheaf::decode_sheaf(sheaves[0].1).unwrap();
    let mut doc = root::decode_root(&old.frozen.initial_root).unwrap();
    assert_eq!(sheaf.manifest_root, doc.manifest_root);
    assert_eq!(sheaf.parent, None);
    doc.timestamp = sheaf.timestamp;
    doc.writer_uuid = writer_uuid(&doc, &old.frozen.writer_identity);
    doc.sheaf_head = GrainId::of(sheaves[0].1);
    let bytes = signed_root(doc);
    let mut next = old.clone();
    next.generation += 5;
    next.phase = Phase::Ready;
    for c in &mut next.candidates {
        if c.role == Role::Active {
            c.role = Role::History;
        }
    }
    let mut c = old.candidates[0].clone();
    c.number = 2;
    c.role = Role::Active;
    c.request = old.current.unwrap();
    c.evidence = retained::Evidence::default();
    c.root = bytes;
    c.id = GrainId::of(&c.root);
    next.candidates.push(c);
    retained::validate(&next).unwrap();
    next
}
fn historical_successor(old: &Submission) -> Submission {
    let mut next = old.clone();
    next.generation += 6;
    next.current = None;
    next.candidates[0].role = Role::Active;
    next.candidates[0].evidence.decision_seen = true;
    next.candidates[1].role = Role::History;
    next.candidates[1].evidence.started = 1;
    next.candidates[1].evidence.proved_no_write = 1;
    next.candidates[1].evidence.last_answered_attempt = 1;
    let receipt = Receipt {
        position: position(&old.candidates[0]),
        root_seq: 1,
        stored_id: old.candidates[0].id,
    };
    next.phase = Phase::Complete(retained::Completion {
        seq: 1,
        id: receipt.stored_id,
        root: old.candidates[0].root.clone(),
        receipt: Some(receipt),
    });
    next.last_response = Some(LastResponse {
        candidate: 2,
        attempt: 1,
        status: 409,
        token: b"operation-bound".to_vec(),
        answer: answer::encode(PublishAnswer::OperationBound(Bound::Landed(receipt))).unwrap(),
    });
    retained::validate(&next).unwrap();
    next
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one physical-save matrix compares each whole successor and its restart transcript"
)]
async fn c5_c8_physical_saves_keep_whole_successors() {
    let mut observed = Vec::new();
    for (stage, occurrence) in [
        ("answer-save", 6),
        ("epoch-save", 6),
        ("operation-save", 7),
        ("replacement-save", 5),
        ("complete-save", 6),
    ] {
        for name in physical_registry() {
            for side in ["before", "after"] {
                let fx = Fixture::new().await;
                let old = if stage == "replacement-save" {
                    loaded_rebase(&fx).await
                } else if stage == "complete-save" {
                    history_ready(&fx).await
                } else {
                    uncertain(&fx).await
                };
                let previous = fx.peer.lock().unwrap().objects.keys().cloned().collect();
                let occupant = (stage == "answer-save").then(|| foreign(&fx, &old));
                let reply = match stage {
                    "answer-save" => Some(answer_reply("open", &old, occupant.as_ref().unwrap())),
                    "epoch-save" | "operation-save" => Some(Reply::answer(
                        409,
                        PublishAnswer::EpochMismatch {
                            epoch: Epoch::from_bytes(NEXT_EPOCH),
                            head: Some(Head::new(None)),
                        },
                    )),
                    "complete-save" => Some(Reply::Historical(old.candidates[0].clone())),
                    _ => None,
                };
                if let Some(reply) = &reply {
                    let mut state = fx.peer.lock().unwrap();
                    if matches!(stage, "epoch-save" | "operation-save") {
                        state.epoch = Some(NEXT_EPOCH);
                    } else {
                        state.replies.push_back(reply.clone());
                    }
                }
                let mut cmd = if stage == "replacement-save" {
                    recover(&fx, &old)
                } else {
                    fx.command(true)
                };
                let event = cut_command(&fx, &mut cmd, &name, side, occurrence).await;
                assert_eq!(event.id, hex(&old.publication_id));
                assert_eq!(event.generation, old.generation + occurrence);
                let saved = fx.record().unwrap();
                let new = installed(&name, side);
                let mut expected = match stage {
                    "answer-save" => answer_successor(&old, "open", reply.as_ref().unwrap(), new),
                    "epoch-save" if new => epoch_successor(&old, reply.as_ref().unwrap()),
                    "epoch-save" => answer_successor(&old, "epoch", reply.as_ref().unwrap(), false),
                    "operation-save" => {
                        let mut r = epoch_successor(&old, reply.as_ref().unwrap());
                        if new {
                            assert_epoch(&old, &saved, true, 1);
                            r.current = saved.current;
                            r.phase = Phase::Rebase;
                            r.generation += 1;
                        }
                        r
                    }
                    "replacement-save" if new => empty_replacement(&fx, &old, &previous),
                    "replacement-save" => {
                        let mut r = old.clone();
                        r.generation += 4;
                        r
                    }
                    "complete-save" if new => historical_successor(&old),
                    "complete-save" => {
                        let mut r = old.clone();
                        r.generation += 5;
                        r.phase = Phase::AwaitingAnswer {
                            candidate: 2,
                            attempt: 1,
                        };
                        r.candidates[1].evidence.started = 1;
                        r
                    }
                    _ => unreachable!(),
                };
                assert_eq!(
                    saved, expected,
                    "whole canonical successor {stage}:{name}:{side}"
                );
                let transcript = if stage == "replacement-save" {
                    let replacement = empty_replacement(&fx, &old, &previous);
                    let mut e = live_barrier([probe(None)], None);
                    e.extend(preparation(&fx, &replacement, &previous, None));
                    e
                } else {
                    let head = occupant.as_ref().map(|_| active(&old).seq);
                    let mut e = live_barrier([probe(occupant.clone())], head);
                    e.push(reply_post(&old, reply.as_ref().unwrap()));
                    e
                };
                assert_eq!(fx.transcript(), transcript);
                fx.reset_transcript();
                match stage {
                    "answer-save" => {
                        let open = reply.as_ref().unwrap();
                        fx.peer.lock().unwrap().replies.push_back(open.clone());
                        let json = run(&mut fx.command(true), 3).await;
                        assert!(json.contains("possible wedge"), "{json}");
                        let mut expected = live_barrier([probe(occupant)], Some(active(&old).seq));
                        expected.push(reply_post(&old, open));
                        assert_eq!(fx.transcript(), expected);
                        let after = fx.record().unwrap();
                        assert_eq!(active(&after).evidence.started, 3);
                        assert_eq!(active(&after).root, active(&old).root);
                        assert_eq!(fx.peer.lock().unwrap().landings, 0);
                    }
                    "epoch-save" | "operation-save" => {
                        if !matches!(saved.phase, Phase::Rebase) {
                            cut(&fx, "operation-save", "after", true).await;
                            assert_eq!(
                                fx.transcript(),
                                if matches!(saved.phase, Phase::AwaitingAnswer { .. }) {
                                    transcript
                                } else {
                                    Vec::new()
                                }
                            );
                        }
                        let r = fx.record().unwrap();
                        refuses_loaded_rebase(&fx, &r).await;
                        fx.reset_transcript();
                        cut_command(&fx, &mut recover(&fx, &r), "replacement-save", "after", 1)
                            .await;
                        let replacement = fx.record().unwrap();
                        assert_eq!(replacement.current, r.current);
                        assert_eq!(replacement.candidates[0], r.candidates[0]);
                        let mut e = live_barrier([probe(None)], None);
                        e.extend(preparation(&fx, &replacement, &previous, None));
                        assert_eq!(fx.transcript(), e);
                        fx.reset_transcript();
                        let json = run(&mut fx.command(true), 0).await;
                        expected.candidates = vec![active(&replacement).clone()];
                        assert_landed_report(&json, &expected);
                        let mut transcript = live_barrier([probe(None)], None);
                        transcript.extend([post(&replacement), hint()]);
                        assert_eq!(fx.transcript(), transcript);
                        assert_eq!(fx.peer.lock().unwrap().landings, 1);
                    }
                    "replacement-save" => {
                        if !new {
                            refuses_loaded_rebase(&fx, &saved).await;
                            fx.reset_transcript();
                            cut_command(
                                &fx,
                                &mut recover(&fx, &saved),
                                "replacement-save",
                                "after",
                                1,
                            )
                            .await;
                        }
                        let replacement = fx.record().unwrap();
                        fx.reset_transcript();
                        let json = run(&mut fx.command(true), 0).await;
                        expected.candidates = vec![active(&replacement).clone()];
                        assert_landed_report(&json, &expected);
                        let mut transcript = live_barrier([probe(None)], None);
                        transcript.extend([post(&replacement), hint()]);
                        assert_eq!(fx.transcript(), transcript);
                        assert_eq!(fx.peer.lock().unwrap().landings, 1);
                    }
                    "complete-save" => {
                        let json = run(&mut cached(&fx), 0).await;
                        assert_landed_report(&json, &old);
                        assert_eq!(
                            fx.transcript(),
                            if new {
                                vec![hint()]
                            } else {
                                let mut expected = live_barrier(
                                    [probe(Some(old.candidates[0].root.clone()))],
                                    Some(old.candidates[0].seq),
                                );
                                expected.push(hint());
                                expected
                            }
                        );
                        assert_winner(&fx, &old, true);
                    }
                    _ => unreachable!(),
                }
                observed.push(format!("{stage}:{name}:{side}:{occurrence}"));
            }
        }
    }
    observe(
        "continuation::c5_c8_physical_saves_keep_whole_successors",
        &observed,
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "save errors stop work and observation errors reject fail, including absence of a cache operation"
)]
async fn c5_c8_failure_and_protocol_controls() {
    for (stage, occurrence) in [
        ("answer-save", 6),
        ("epoch-save", 6),
        ("operation-save", 7),
        ("replacement-save", 5),
        ("complete-save", 6),
    ] {
        for name in [stage, "temporary-sync", "scope-sync"] {
            let fx = Fixture::new().await;
            let old = match stage {
                "replacement-save" => loaded_rebase(&fx).await,
                "complete-save" => history_ready(&fx).await,
                "epoch-save" | "operation-save" => epoch_fixture(&fx).await.0,
                _ => {
                    let r = uncertain(&fx).await;
                    let occupant = foreign(&fx, &r);
                    fx.peer
                        .lock()
                        .unwrap()
                        .replies
                        .push_back(answer_reply("open", &r, &occupant));
                    r
                }
            };
            if stage == "complete-save" {
                fx.peer
                    .lock()
                    .unwrap()
                    .replies
                    .push_back(Reply::Historical(old.candidates[0].clone()));
            }
            let mut cmd = if stage == "replacement-save" {
                recover(&fx, &old)
            } else {
                fx.command(true)
            };
            let rendezvous = Rendezvous::arm(
                &mut cmd,
                &fx.scratch.0,
                name,
                "before",
                if name == stage { 1 } else { occurrence },
            );
            let mut child = Process::spawn(&mut cmd);
            let (_, mut stream) = rendezvous.reached(&mut child).await.unwrap();
            let canonical = fx.record().unwrap();
            let transcript = fx.transcript();
            stream.write_all(b"fail\n").await.unwrap();
            let output = child.output().await;
            let json = assert_exit(&output, 1);
            assert!(!json.contains("\"outcome\":\"landed\""));
            assert_eq!(
                fx.record().unwrap(),
                canonical,
                "failed semantic barrier changed canonical bytes"
            );
            assert_eq!(
                fx.transcript(),
                transcript,
                "failed save allowed network/repair"
            );
            println!("REFUSED injected failure through {stage}:{name}'s journal error path");
        }
    }
    for name in ["cache-repair", "hint-repair", "output-write"] {
        for side in ["before", "after"] {
            let fx = Fixture::new().await;
            let old = history_ready(&fx).await;
            fx.peer
                .lock()
                .unwrap()
                .replies
                .push_back(Reply::Historical(old.candidates[0].clone()));
            let mut cmd = cached(&fx);
            let rendezvous = Rendezvous::arm(&mut cmd, &fx.scratch.0, name, side, 1);
            let mut child = Process::spawn(&mut cmd);
            let (_, mut stream) = rendezvous.reached(&mut child).await.unwrap();
            let canonical = fx.record().unwrap();
            let transcript = fx.transcript();
            stream.write_all(b"fail\n").await.unwrap();
            let output = child.output().await;
            assert_exit(&output, 1);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("rendezvous protocol error") && stderr.contains(name),
                "stdout: {}\nstderr: {stderr}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(fx.record().unwrap(), canonical);
            assert_eq!(fx.transcript(), transcript);
            println!("REFUSED fail at observation {name}:{side} as a protocol error");
        }
    }
    let fx = Fixture::new().await;
    let old = history_ready(&fx).await;
    fx.peer
        .lock()
        .unwrap()
        .replies
        .push_back(Reply::Historical(old.candidates[0].clone()));
    let mut cmd = fx.command(true);
    let rendezvous = Rendezvous::arm(&mut cmd, &fx.scratch.0, "cache-repair", "before", 1);
    let mut child = Process::spawn(&mut cmd);
    let refused = rendezvous.reached(&mut child).await.err().unwrap();
    let output = child.output().await;
    let json = assert_exit(&output, 0);
    assert!(
        refused.contains("child exit before rendezvous"),
        "{refused}\nstdout: {json}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_landed_report(&json, &old);
    let mut expected = live_barrier([probe(None)], None);
    expected.extend([
        reply_post(&old, &Reply::Historical(old.candidates[0].clone())),
        hint(),
    ]);
    assert_eq!(fx.transcript(), expected);
    println!("REFUSED cache-repair rendezvous when no cache operation runs");
    observe("continuation::c5_c8_failure_and_protocol_controls", &[]);
}
