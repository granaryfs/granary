// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Discard eligibility after a Release and retirement of a Release by an acquire grant.

use super::*;
use crate::{
    OverlayDisk, OverlayRefusal, discard_overlay,
    overlay_discard::tests::{empty_store, put},
    overlay_test_support::ScratchDir,
};
use granary_core::overlay_discard::{Outcome, parse_hex};
use granary_core::overlay_journal::{GENERATION_MAX, WriterRecord};
use std::path::PathBuf;

/// The durable overlay files of a simulated store, written into a real one.
fn materialize(
    io: &SimIo,
    with_carrier: bool,
) -> (ScratchDir, PathBuf, [u8; 32], VolumeName, Carrier) {
    let carrier = disk(io);
    let digest = carrier.scope.digest().unwrap();
    let (scratch, root, area) = empty_store(&digest, &carrier.volume);
    let writer = io.recovered_bytes("writer").expect("writer is durable");
    let journal = io.recovered_bytes("journal").expect("journal is durable");
    let record = WriterRecord::decode(&writer).unwrap();
    assert_eq!(
        crate::overlay_store::scan_clean(&journal, &record).map(|(_, clean)| clean),
        Some(true),
        "the fixture's journal is clean"
    );
    put(&area.join("writer"), &writer);
    put(&area.join("journal"), &journal);
    if with_carrier {
        put(
            &area.join("ownership"),
            &io.recovered_bytes("ownership").unwrap(),
        );
    }
    let scope = parse_hex(&digest).unwrap();
    let volume = carrier.volume.clone();
    (scratch, root, scope, volume, carrier)
}

fn shape(carrier: &Carrier) -> String {
    format!(
        "phase {:?}, fence {}, pending {:?}",
        carrier.phase,
        carrier.fence,
        carrier
            .pending
            .iter()
            .map(|p| (p.operation, p.terminal, p.answered))
            .collect::<Vec<_>>()
    )
}

/// What the plan, the acknowledged discard and the claim gate then say.
fn discard_facts(root: &std::path::Path, scope: [u8; 32], volume: &VolumeName) -> String {
    let plan = discard_overlay(root, scope, volume, None);
    let Ok(row) = &plan else {
        return format!("plan {plan:?}");
    };
    let tuple = Some((row.name.writer, row.name.incarnation));
    let moved = discard_overlay(root, scope, volume, tuple);
    let mut real = OverlayDisk::new(root, nix::unistd::geteuid().as_raw());
    let gate = crate::overlay_discard::claims::gate(&mut real, root, volume);
    format!(
        "plan {:?} bytes {}; acknowledged discard {:?}; claim gate afterwards {:?}",
        row.outcome,
        row.bytes,
        moved.map(|row| row.outcome),
        gate.map_err(|error| error.to_string())
    )
}

#[track_caller]
fn assert_not_eligible(root: &std::path::Path, scope: [u8; 32], volume: &VolumeName, why: &str) {
    let plan = discard_overlay(root, scope, volume, None);
    if matches!(&plan, Err(error) if error.reason() == OverlayRefusal::NotEligible) {
        return;
    }
    panic!(
        "{why}: the plan must refuse OverlayDiscardNotEligible; {}",
        discard_facts(root, scope, volume)
    );
}

/// A clean journal with no carrier is enough to refuse discard.
#[test]
fn discard_plan_refuses_a_clean_overlay_without_a_carrier() {
    let (_scratch, io, mut client, mut authority) = serving();
    release_ok(&mut client, &mut authority, 100, "clean unmount");
    drop(client);
    io.crash();
    let (_real, root, scope, volume, _) = materialize(&io, false);
    assert_not_eligible(&root, scope, &volume, "no carrier");
}

/// A clean unmount leaves the answered Release in its slot until the next
/// grant. Nothing is owed, so the overlay is clean.
#[test]
fn discard_plan_refuses_a_cleanly_released_overlay() {
    let (_scratch, io, mut client, mut authority) = serving();
    release_ok(&mut client, &mut authority, 100, "clean unmount");
    drop(client);
    io.crash();
    let (_real, root, scope, volume, carrier) = materialize(&io, true);
    assert_eq!(carrier.phase, Phase::Released);
    assert_eq!(carrier.fence, 0);
    assert!(
        carrier.pending.iter().all(|p| p.terminal),
        "{}",
        shape(&carrier)
    );
    assert_eq!(authority.row.unwrap().state, ReceiptState::Released);
    assert_not_eligible(
        &root,
        scope,
        &volume,
        &format!("cleanly released ({})", shape(&carrier)),
    );
}

/// A second clean unmount leaves the second Release in the slot. The new
/// grant retired the first Release.
#[test]
fn discard_plan_refuses_after_a_remount_cycle() {
    let (scratch, io, client, mut authority) = released_reopened(30);
    let mut client = client;
    start_like(&mut client, &mut authority, 1010).unwrap();
    open(&mut client, &io);
    reg(&mut client, &mut authority, 2, 1020);
    release_ok(&mut client, &mut authority, 1030, "second clean unmount");
    drop(client);
    io.crash();
    let _ = &scratch;
    let (_real, root, scope, volume, carrier) = materialize(&io, true);
    assert_not_eligible(
        &root,
        scope,
        &volume,
        &format!("released twice ({})", shape(&carrier)),
    );
}

/// A mount that registered everything can stop without a Release and hold
/// no local work. The next start succeeds its own Live row.
#[test]
fn discard_plan_refuses_a_serving_overlay_with_nothing_pending() {
    let (_scratch, io, client, _authority) = serving();
    drop(client);
    io.crash();
    let (_real, root, scope, volume, carrier) = materialize(&io, true);
    assert_eq!(carrier.fence, 0);
    assert!(
        carrier.pending.iter().all(|p| p.terminal),
        "{}",
        shape(&carrier)
    );
    assert_not_eligible(
        &root,
        scope,
        &volume,
        &format!("stopped while serving ({})", shape(&carrier)),
    );
}

#[track_caller]
fn assert_plan_admits_carrier(io: &SimIo) {
    let (_real, root, scope, volume, carrier) = materialize(io, true);
    let plan = discard_overlay(&root, scope, &volume, None);
    assert!(
        matches!(&plan, Ok(row) if matches!(row.outcome, Outcome::Live(_))),
        "expected a live discard plan for {}; got {plan:?}",
        shape(&carrier),
    );
}

#[track_caller]
fn assert_plan_admits_registration(terminal: bool, answered: bool) {
    let (_scratch, io, mut client, _) = serving();
    let request = client
        .prepare_registration(
            &root(client.writer_uuid(), 2),
            vec![],
            &Tick(100),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&request, &Tick(100)).unwrap();
    drop(client);
    io.crash();
    let mut carrier = disk(&io);
    assert_eq!((carrier.phase, carrier.fence), (Phase::Serving, 0));
    let covered = intent::encode_receipt(Receipt {
        generation: carrier.sent + 1,
        ..intent::decode_receipt(&carrier.current).unwrap()
    })
    .unwrap();
    let pending = carrier.pending.last_mut().unwrap();
    assert_eq!(
        (
            pending.operation,
            pending.terminal,
            pending.answered,
            pending.answer.is_empty(),
            pending.context.is_empty()
        ),
        (Operation::Register, false, false, true, true)
    );
    // Model terminal verdict flags in the retained slot independently of
    // the Register cleanup that normally removes a context-free terminal entry.
    pending.terminal = terminal;
    pending.answered = answered;
    if terminal && !answered {
        pending.answer = covered;
    }
    io.mutate_recovered("ownership", |bytes| {
        *bytes = ownership::encode(&carrier).unwrap();
    });
    assert_plan_admits_carrier(&io);
}

#[test]
fn discard_plan_admits_a_nonterminal_registration() {
    assert_plan_admits_registration(false, false);
}

#[test]
fn discard_plan_admits_a_terminal_unanswered_registration() {
    assert_plan_admits_registration(true, false);
}

#[test]
fn discard_plan_admits_a_registration_answered_with_refusal() {
    assert_plan_admits_registration(true, true);
}

#[test]
fn discard_plan_admits_a_fenced_carrier() {
    let (_scratch, io, client, _) = serving();
    drop(client);
    io.crash();
    let mut carrier = disk(&io);
    carrier.phase = Phase::Fenced;
    carrier.fence = 2;
    io.mutate_recovered("ownership", |bytes| {
        *bytes = ownership::encode(&carrier).unwrap();
    });
    assert_plan_admits_carrier(&io);
}

#[test]
fn discard_plan_admits_owned_start_with_settled_requests() {
    let (_scratch, io, mut client, mut authority) = released_reopened(30);
    start_like(&mut client, &mut authority, 1010).unwrap();
    drop(client);
    io.crash();
    let carrier = disk(&io);
    let pending: Vec<_> = carrier
        .pending
        .iter()
        .map(|p| {
            (
                p.operation,
                p.terminal,
                p.answered,
                p.answer.is_empty(),
                p.context.is_empty(),
            )
        })
        .collect();
    assert_eq!(
        (carrier.phase, carrier.fence, pending.as_slice()),
        (
            Phase::OwnedStart,
            0,
            [(Operation::Ownership, true, true, false, true)].as_slice()
        )
    );
    assert_plan_admits_carrier(&io);
}

#[test]
fn discard_plan_admits_an_answered_registration_with_capture_context() {
    let (_scratch, io, mut client, mut authority) = serving();
    let request = client
        .prepare_registration(
            &root(client.writer_uuid(), 2),
            vec![1],
            &Tick(100),
            |_, _| true,
        )
        .unwrap();
    let completion = exchange(&mut client, &mut authority, &request, 100).unwrap();
    assert_eq!(
        completion,
        IntentCompletion::Accepted(authority.row.unwrap())
    );
    drop(client);
    io.crash();
    let carrier = disk(&io);
    let pending = carrier.pending.last().unwrap();
    assert_eq!(
        (
            carrier.phase,
            carrier.fence,
            pending.operation,
            pending.terminal,
            pending.answered,
            pending.answer.is_empty(),
            pending.context.as_slice()
        ),
        (
            Phase::Serving,
            0,
            Operation::Register,
            true,
            true,
            false,
            [1].as_slice()
        )
    );
    assert_plan_admits_carrier(&io);
}

#[test]
fn discard_plan_admits_an_exhausted_carrier_revision() {
    let (_scratch, io, client, _) = serving();
    drop(client);
    io.crash();
    let mut carrier = disk(&io);
    carrier.revision = u64::MAX;
    io.mutate_recovered("ownership", |bytes| {
        *bytes = ownership::encode(&carrier).unwrap();
    });
    assert_plan_admits_carrier(&io);
}

#[test]
fn discard_plan_admits_an_exhausted_writer_ceiling() {
    let (_scratch, io, client, _) = serving();
    drop(client);
    io.crash();
    io.mutate_recovered("writer", |bytes| {
        let mut writer = WriterRecord::decode(bytes).unwrap();
        writer.ceiling = GENERATION_MAX;
        *bytes = writer.encode().unwrap();
    });
    assert_plan_admits_carrier(&io);
}

/// An acquire grant retires the unowned carrier's retained terminal Release
/// after the authority evicts the Released row.
#[test]
fn acquire_grant_retires_the_terminal_release() {
    let (scratch, io, client, mut authority) = released_reopened(30);
    let prior = rels(client.snapshot());
    assert_eq!(prior.len(), 1);
    let old = intent::decode_release(&prior[0].body).unwrap().epoch;
    // Eviction preserves the principal's epoch high-water.
    authority.row = None;
    authority.root.clear();
    // Model an unowned carrier that still holds the terminal Release.
    let mut unowned = client.snapshot().clone();
    unowned.phase = Phase::Unowned;
    drop(client);
    io.mutate_recovered("ownership", |bytes| {
        *bytes = ownership::encode(&unowned).unwrap();
    });
    io.crash();
    let mut client = start(&scratch, &io, 32);
    assert_eq!(rels(client.snapshot()), prior);
    let request = client
        .prepare_acquire(authority.cursor, &Tick(1010))
        .unwrap();
    // A crash after the dispatch replays the same bytes for the same grant.
    client.dispatch(&request, &Tick(1010)).unwrap();
    let _lost = authority.send(&request);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 34);
    assert_eq!(rels(client.snapshot()), prior, "no grant, no retirement");
    let retained = client.retained_requests();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].bytes(), request.bytes());
    let completion = exchange(&mut client, &mut authority, &retained[0], 1012).unwrap();
    assert_eq!(
        completion,
        IntentCompletion::Accepted(authority.row.unwrap())
    );
    assert!(epoch(client.snapshot()) > old);
    assert_eq!(rels(client.snapshot()).len(), 0, "acquire grant");
    assert_eq!(rels(&disk(&io)).len(), 0, "acquire grant, durable");
    // This process succeeds the crashed process that won the grant.
    start_like(&mut client, &mut authority, 1020).unwrap();
    open(&mut client, &io);
    reg(&mut client, &mut authority, 2, 1030);
    release_ok(&mut client, &mut authority, 1040, "release after acquire");
}
