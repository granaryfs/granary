// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Discriminating ownership, persistence and bounded-decode controls.

use super::*;
use crate::wire::CacheControl;
use granary_core::intent::{Ownership, OwnershipMode, Release};
use granary_core::root::{self, RootDoc, RootSig};
use granary_store::crypto::SigningKey;

pub(crate) fn volume() -> VolumeName {
    VolumeName::new("intent-test".into()).unwrap()
}
pub(crate) fn now() -> Timestamp {
    Timestamp {
        secs: 100,
        nanos: 0,
    }
}
pub(crate) fn keys() -> TrustedKeys {
    TrustedKeys::new([*SigningKey::from_seed(&[23; 32]).unwrap().public_key()]).unwrap()
}
pub(crate) fn root(seed: u8, name: &VolumeName) -> Vec<u8> {
    let signer = SigningKey::from_seed(&[23; 32]).unwrap();
    let mut doc = RootDoc {
        volume: name.clone(),
        seq: 1,
        parent: None,
        writer_uuid: [seed; 16],
        epoch: 1,
        timestamp: now(),
        chunker_spec: "intent-test".into(),
        manifest_root: GrainId::of(&[seed, 1]),
        binmap_index: GrainId::of(&[seed, 2]),
        sheaf_head: GrainId::of(&[seed, 3]),
        sigs: vec![RootSig {
            key_id: signer.key_id(),
            sig: [0; 64],
        }],
    };
    let bytes = root::encode_root(&doc).unwrap();
    doc.sigs.first_mut().unwrap().sig = signer.sign(root::signed_prefix(&bytes).unwrap());
    root::encode_root(&doc).unwrap()
}
pub(crate) fn acquire(w: u8, token: u8, h: u64) -> Vec<u8> {
    wire::encode_ownership(Ownership {
        writer: [w; 16],
        instance: [token; 16],
        mode: OwnershipMode::Acquire { observed_cursor: h },
    })
    .unwrap()
}
pub(crate) fn takeover(row: &Row, token: u8) -> Vec<u8> {
    wire::encode_ownership(Ownership {
        writer: row.receipt.writer,
        instance: [token; 16],
        mode: OwnershipMode::Takeover {
            expected_epoch: row.receipt.epoch,
            generation: row.receipt.generation,
            state: row.receipt.state,
            recovery_ack: true,
        },
    })
    .unwrap()
}
fn run(
    p: &mut Principal,
    operation: IntentOperation,
    body: &[u8],
    status: u16,
    token: Option<ErrorToken>,
) -> Outcome {
    let before = p.clone();
    let judged = transition(Some(p), operation, body, &volume(), &keys(), now());
    assert_eq!(
        (
            judged.outcome.status().as_u16(),
            judged.outcome.error(),
            judged.outcome.cache_control()
        ),
        (status, token, Some(CacheControl::NoStore))
    );
    if status >= 400 {
        assert_eq!((judged.next.as_ref(), &*p), (None, &before));
        assert_eq!(
            encoded(&snapshot(p.clone())),
            encoded(&snapshot(before.clone()))
        );
    } else {
        judge_success(operation, body, &judged.outcome);
    }
    if let Some(next) = judged.next {
        *p = next;
    }
    judged.outcome
}
pub(crate) fn owned(w: u8) -> Principal {
    let mut p = Principal::default();
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(w, 2, 0),
        200,
        None,
    );
    p
}
pub(crate) fn register(p: &Principal, w: u8, g: u64, seed: u8) -> Vec<u8> {
    let row = p.rows.get(&[w; 16]).unwrap();
    wire::encode_register(
        &[w; 16],
        row.receipt.epoch,
        &row.receipt.instance,
        g,
        &root(seed, &volume()),
    )
    .unwrap()
}
pub(crate) fn release(p: &Principal, w: u8, g: u64) -> Vec<u8> {
    let row = p.rows.get(&[w; 16]).unwrap();
    wire::encode_release(Release {
        writer: [w; 16],
        epoch: row.receipt.epoch,
        instance: row.receipt.instance,
        generation: g,
    })
    .unwrap()
}
pub(crate) fn snapshot(p: Principal) -> Snapshot {
    Snapshot {
        volume: volume(),
        epoch: Epoch::from_bytes([9; 16]),
        principals: BTreeMap::from([(PrincipalId::from_bytes([1; 16]), p)]),
    }
}
pub(crate) fn encoded(s: &Snapshot) -> Vec<u8> {
    let mut bytes = Vec::new();
    codec::encode(s, &mut bytes).unwrap();
    bytes
}

#[test]
fn intent_ownership_replays_exact_q_without_restoring_refresh_or_release() {
    let q = acquire(1, 2, 0);
    let mut p = Principal::default();
    let grant = run(&mut p, IntentOperation::Ownership, &q, 200, None).into_body();
    let body = register(&p, 1, 10, 3);
    run(&mut p, IntentOperation::Register, &body, 200, None);
    let body = release(&p, 1, 12);
    run(&mut p, IntentOperation::Release, &body, 200, None);
    let before = p.clone();
    assert_eq!(
        run(&mut p, IntentOperation::Ownership, &q, 200, None).body(),
        grant
    );
    assert_eq!(p, before);
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(1, 8, 0),
        409,
        Some(ErrorToken::IntentChanged),
    );
}
#[test]
fn intent_absence_and_cursor_refuse_delayed_high_generation_without_creation() {
    let mut p = owned(1);
    let reg = register(&p, 1, 100, 3);
    let rel = release(&p, 1, 100);
    let taken = takeover(p.rows.get(&[1; 16]).unwrap(), 5);
    p.rows.clear();
    for (op, body) in [
        (IntentOperation::Register, reg),
        (IntentOperation::Release, rel),
        (IntentOperation::Ownership, taken),
    ] {
        run(&mut p, op, &body, 409, Some(ErrorToken::IntentAbsent));
    }
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(1, 2, 0),
        409,
        Some(ErrorToken::IntentCursorChanged),
    );
    let h = p.h;
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(1, 4, h),
        200,
        None,
    );
    assert_eq!(p.rows.get(&[1; 16]).unwrap().receipt.epoch, 2);
}
#[test]
fn intent_epoch_and_token_fence_every_generation_and_successive_takeovers() {
    let mut p = owned(1);
    let reg = register(&p, 1, 10, 3);
    run(&mut p, IntentOperation::Register, &reg, 200, None);
    let old_high = register(&p, 1, 100, 8);
    let old_release = release(&p, 1, 100);
    let mut previous = takeover(p.rows.get(&[1; 16]).unwrap(), 5);
    for token in 5..8 {
        let q = takeover(p.rows.get(&[1; 16]).unwrap(), token);
        run(&mut p, IntentOperation::Ownership, &q, 200, None);
        if token > 5 {
            run(
                &mut p,
                IntentOperation::Ownership,
                &previous,
                409,
                Some(ErrorToken::IntentSuperseded),
            );
        }
        previous = q;
    }
    run(
        &mut p,
        IntentOperation::Register,
        &old_high,
        409,
        Some(ErrorToken::IntentSuperseded),
    );
    run(
        &mut p,
        IntentOperation::Release,
        &old_release,
        409,
        Some(ErrorToken::IntentSuperseded),
    );
    let row = p.rows.get(&[1; 16]).unwrap();
    let same_e_wrong_t = wire::encode_release(Release {
        writer: [1; 16],
        epoch: row.receipt.epoch,
        instance: [99; 16],
        generation: 100,
    })
    .unwrap();
    run(
        &mut p,
        IntentOperation::Release,
        &same_e_wrong_t,
        409,
        Some(ErrorToken::IntentSuperseded),
    );
    assert_eq!(
        (p.h, p.rows.get(&[1; 16]).unwrap().receipt.generation),
        (4, 10)
    );
}

#[test]
fn intent_released_replay_returns_the_receipt_without_renewing_retention() {
    let mut p = owned(1);
    let reg = register(&p, 1, 10, 3);
    run(&mut p, IntentOperation::Register, &reg, 200, None);
    let request = release(&p, 1, 10);
    let recorded = run(&mut p, IntentOperation::Release, &request, 200, None);
    let changed = p.rows.get(&[1; 16]).unwrap().changed;
    let later = Timestamp {
        secs: changed.secs + 3600,
        nanos: changed.nanos,
    };
    for request in [request, release(&p, 1, 9)] {
        let replay = transition(
            Some(&p),
            IntentOperation::Release,
            &request,
            &volume(),
            &keys(),
            later,
        );
        assert_eq!(replay.outcome.status().as_u16(), 200);
        assert_eq!(replay.outcome.body(), recorded.body());
        let row = replay
            .next
            .as_ref()
            .unwrap_or(&p)
            .rows
            .get(&[1; 16])
            .unwrap();
        assert_eq!(row.changed, changed);
        assert!(replay.next.is_none());
    }
}
#[test]
fn intent_takeover_compares_epoch_generation_state_and_exact_root() {
    let mut p = owned(1);
    let reg = register(&p, 1, 10, 3);
    run(&mut p, IntentOperation::Register, &reg, 200, None);
    let row = p.rows.get(&[1; 16]).unwrap().clone();
    for (epoch, g, state, error) in [
        (2, 10, row.receipt.state, ErrorToken::IntentSuperseded),
        (1, 11, row.receipt.state, ErrorToken::IntentChanged),
        (1, 10, ReceiptState::Released, ErrorToken::IntentChanged),
        (
            1,
            10,
            ReceiptState::Live {
                prepared_root_id: GrainId::of(b"wrong"),
            },
            ErrorToken::IntentChanged,
        ),
    ] {
        let q = wire::encode_ownership(Ownership {
            writer: [1; 16],
            instance: [5; 16],
            mode: OwnershipMode::Takeover {
                expected_epoch: epoch,
                generation: g,
                state,
                recovery_ack: true,
            },
        })
        .unwrap();
        run(&mut p, IntentOperation::Ownership, &q, 409, Some(error));
    }
    let q = takeover(&row, 5);
    run(&mut p, IntentOperation::Ownership, &q, 200, None);
    assert_eq!((p.h, &p.rows.get(&[1; 16]).unwrap().root), (2, &row.root));
}
#[test]
fn intent_registration_binding_and_release_max_preserve_historical_grant() {
    let mut p = owned(1);
    let reg = register(&p, 1, 10, 3);
    let first = run(&mut p, IntentOperation::Register, &reg, 200, None).into_body();
    let before = p.clone();
    assert_eq!(
        run(&mut p, IntentOperation::Register, &reg, 200, None).body(),
        first
    );
    assert_eq!(p, before);
    let other = register(&p, 1, 10, 4);
    run(
        &mut p,
        IntentOperation::Register,
        &other,
        409,
        Some(ErrorToken::IntentBound),
    );
    let lower = register(&p, 1, 9, 3);
    run(
        &mut p,
        IntentOperation::Register,
        &lower,
        409,
        Some(ErrorToken::IntentSuperseded),
    );
    for g in [9, 10, 12, 11, u64::MAX - 1] {
        let rel = release(&p, 1, g);
        let old_g = p.rows.get(&[1; 16]).unwrap().receipt.generation;
        let grant = p.rows.get(&[1; 16]).unwrap().grant;
        run(&mut p, IntentOperation::Release, &rel, 200, None);
        assert_eq!(
            (
                p.rows.get(&[1; 16]).unwrap().receipt.generation,
                p.rows.get(&[1; 16]).unwrap().grant
            ),
            (g.max(old_g), grant)
        );
    }
    run(
        &mut p,
        IntentOperation::Register,
        &reg,
        409,
        Some(ErrorToken::IntentSuperseded),
    );
    let same = register(&p, 1, u64::MAX - 1, 3);
    run(
        &mut p,
        IntentOperation::Register,
        &same,
        409,
        Some(ErrorToken::IntentSuperseded),
    );
}
#[test]
fn intent_exhaustion_quota_and_replay_order() {
    let mut p = Principal::default();
    for w in 1..=64 {
        let h = p.h;
        run(
            &mut p,
            IntentOperation::Ownership,
            &acquire(w, 2, h),
            200,
            None,
        );
    }
    let before = p.clone();
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(65, 2, 64),
        409,
        Some(ErrorToken::IntentQuota),
    );
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(1, 2, 0),
        200,
        None,
    );
    assert_eq!(p, before);
    p.h = u64::MAX;
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(1, 2, 0),
        200,
        None,
    );
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(65, 2, u64::MAX),
        409,
        Some(ErrorToken::IntentEpochExhausted),
    );
    for w in 1..=16 {
        let reg = register(&p, w, 1, w);
        run(&mut p, IntentOperation::Register, &reg, 200, None);
    }
    let replay = register(&p, 1, 1, 1);
    let refresh = register(&p, 1, 2, 4);
    run(&mut p, IntentOperation::Register, &replay, 200, None);
    run(&mut p, IntentOperation::Register, &refresh, 200, None);
    let over = register(&p, 17, 1, 17);
    run(
        &mut p,
        IntentOperation::Register,
        &over,
        409,
        Some(ErrorToken::IntentQuota),
    );
}
#[test]
fn intent_readback_is_live_only_sorted_and_principal_scoped() {
    let a = owned(1);
    let mut b = owned(1);
    let reg = register(&b, 1, 1, 4);
    run(&mut b, IntentOperation::Register, &reg, 200, None);
    let mut s = snapshot(a);
    s.principals.insert(PrincipalId::from_bytes([2; 16]), b);
    for (id, count) in [(1, 0), (2, 1)] {
        let p = s
            .principals
            .get(&PrincipalId::from_bytes([id; 16]))
            .unwrap();
        let result = transition(
            Some(p),
            IntentOperation::Readback,
            &[],
            &volume(),
            &keys(),
            now(),
        );
        assert_eq!(
            (
                result.outcome.status().as_u16(),
                result.outcome.error(),
                result.outcome.content_type()
            ),
            (200, None, Some(ContentType::IntentReadback))
        );
        let rows = wire::decode_readback(result.outcome.body(), &volume(), |doc, bytes| {
            check_signatures(doc, bytes, &keys()).is_ok()
        })
        .unwrap();
        assert_eq!(
            (
                result.outcome.status().as_u16(),
                rows.cursor,
                rows.rows.len(),
                result.next.is_none()
            ),
            (200, 1, count, true)
        );
    }
}
#[test]
fn intent_root_volume_signature_and_malformed_bodies_refuse_before_mutation() {
    let mut p = owned(1);
    let good = register(&p, 1, 1, 3);
    let mut bad_signature = good.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let other_volume = VolumeName::new("other".into()).unwrap();
    let wrong_volume =
        wire::encode_register(&[1; 16], 1, &[2; 16], 1, &root(3, &other_volume)).unwrap();
    for body in [&bad_signature, &wrong_volume] {
        run(
            &mut p,
            IntentOperation::Register,
            body,
            400,
            Some(ErrorToken::InvalidCandidate),
        );
    }
    for operation in [
        IntentOperation::Ownership,
        IntentOperation::Register,
        IntentOperation::Release,
    ] {
        run(
            &mut p,
            operation,
            b"malformed",
            400,
            Some(ErrorToken::BadRequest),
        );
    }
    run(&mut p, IntentOperation::Register, &good, 200, None);
}
#[test]
fn intent_retention_clock_replay_and_zero_row_h_are_non_regressing() {
    let mut p = owned(1);
    let age = p.rows.get(&[1; 16]).unwrap().changed;
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(1, 2, 0),
        200,
        None,
    );
    assert_eq!(p.rows.get(&[1; 16]).unwrap().changed, age);
    let mut s = snapshot(p);
    assert!(!evict(&mut s, Timestamp { secs: 99, nanos: 0 }, 0));
    assert!(!evict(
        &mut s,
        Timestamp {
            secs: 86_499,
            nanos: 999_999_999
        },
        0
    ));
    assert!(!evict(
        &mut s,
        Timestamp {
            secs: 86_500,
            nanos: 0
        },
        100_000
    ));
    assert!(evict(
        &mut s,
        Timestamp {
            secs: 86_500,
            nanos: 0
        },
        0
    ));
    assert_eq!(
        (
            s.principals.len(),
            s.principals.values().next().map(|p| (p.h, p.rows.len()))
        ),
        (1, Some((1, 0)))
    );
    let bytes = encoded(&s);
    assert_eq!(
        codec::decode(bytes.as_slice(), &volume(), Some(s.epoch), &keys()).unwrap(),
        s
    );
}
#[test]
fn intent_snapshot_roundtrip_canonical_every_cut_and_bit_flip() {
    let mut p = owned(1);
    let reg = register(&p, 1, 10, 3);
    run(&mut p, IntentOperation::Register, &reg, 200, None);
    let s = snapshot(p);
    let bytes = encoded(&s);
    let decoded = codec::decode(bytes.as_slice(), &volume(), Some(s.epoch), &keys()).unwrap();
    assert_eq!((&decoded, encoded(&decoded)), (&s, bytes.clone()));
    for cut in 0..bytes.len() {
        assert!(
            codec::decode(bytes.get(..cut).unwrap(), &volume(), Some(s.epoch), &keys()).is_err(),
            "accepted cut {cut}"
        );
    }
    for n in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        *corrupt.get_mut(n).unwrap() ^= 1;
        assert!(
            codec::decode(corrupt.as_slice(), &volume(), Some(s.epoch), &keys()).is_err(),
            "accepted bit flip {n}"
        );
    }
    assert!(
        codec::decode(
            bytes.as_slice(),
            &volume(),
            Some(Epoch::from_bytes([8; 16])),
            &keys()
        )
        .is_err()
    );
    let wrong = VolumeName::new("other".into()).unwrap();
    assert!(codec::decode(bytes.as_slice(), &wrong, Some(s.epoch), &keys()).is_err());
}
#[test]
fn intent_snapshot_checked_invalid_counts_cursor_and_grant_are_rejected() {
    let mut s = snapshot(owned(1));
    s.principals.values_mut().next().unwrap().h = 0;
    assert_eq!(
        codec::decode(unchecked(&s).as_slice(), &volume(), Some(s.epoch), &keys())
            .unwrap_err()
            .to_string(),
        "epoch-cursor"
    );
    s.principals.values_mut().next().unwrap().h = 1;
    s.principals
        .values_mut()
        .next()
        .unwrap()
        .rows
        .values_mut()
        .next()
        .unwrap()
        .grant
        .receipt
        .instance = [8; 16];
    assert_eq!(
        codec::decode(unchecked(&s).as_slice(), &volume(), Some(s.epoch), &keys())
            .unwrap_err()
            .to_string(),
        "grant-current"
    );
}

fn recheck_counts(bytes: &mut [u8], principals: u64, rows: u64) {
    let count_at = 13 + volume().as_str().len() + 16;
    let envelope_end = count_at + 16;
    bytes
        .get_mut(count_at..count_at + 8)
        .unwrap()
        .copy_from_slice(&principals.to_be_bytes());
    bytes
        .get_mut(count_at + 8..envelope_end)
        .unwrap()
        .copy_from_slice(&rows.to_be_bytes());
    let initial = GrainId::of(
        &[
            b"granary intent-store envelope v1".as_slice(),
            bytes.get(..envelope_end).unwrap(),
        ]
        .concat(),
    );
    bytes
        .get_mut(envelope_end..envelope_end + 33)
        .unwrap()
        .copy_from_slice(&initial.to_bytes());
    let footer = bytes.len() - 90;
    let mut at = envelope_end + 33;
    let mut chain = initial;
    while at < footer {
        let length = usize::try_from(u32::from_be_bytes(
            bytes.get(at..at + 4).unwrap().try_into().unwrap(),
        ))
        .unwrap();
        let end = at + 5 + length;
        chain = GrainId::of(
            &[
                b"granary intent-store frame v1".as_slice(),
                chain.to_bytes().as_slice(),
                bytes.get(at..end).unwrap(),
            ]
            .concat(),
        );
        bytes
            .get_mut(end..end + 33)
            .unwrap()
            .copy_from_slice(&chain.to_bytes());
        at = end + 33;
    }
    bytes
        .get_mut(footer + 24..footer + 57)
        .unwrap()
        .copy_from_slice(&chain.to_bytes());
    let check = GrainId::of(
        &[
            b"granary intent-store footer v1".as_slice(),
            initial.to_bytes().as_slice(),
            bytes.get(footer..footer + 57).unwrap(),
        ]
        .concat(),
    );
    bytes
        .get_mut(footer + 57..)
        .unwrap()
        .copy_from_slice(&check.to_bytes());
}
#[test]
fn intent_snapshot_count_mismatch_count_over_and_envelope_counts_never_reserve() {
    let s = snapshot(owned(1));
    let valid = encoded(&s);
    let mut mismatch = valid.clone();
    recheck_counts(&mut mismatch, 1, 2);
    assert_eq!(
        codec::decode(mismatch.as_slice(), &volume(), Some(s.epoch), &keys())
            .unwrap_err()
            .to_string(),
        "count-mismatch"
    );
    let mut huge = valid.clone();
    recheck_counts(&mut huge, u64::MAX, 1);
    assert!(codec::decode(huge.as_slice(), &volume(), Some(s.epoch), &keys()).is_err());
    let mut over = Principal::default();
    let sample = owned(1).rows.values().next().unwrap().clone();
    for n in 1..=65_u8 {
        let mut row = sample.clone();
        row.receipt.writer = [n; 16];
        row.receipt.epoch = u64::from(n);
        row.grant.receipt = row.receipt;
        over.rows.insert([n; 16], row);
    }
    over.h = 65;
    let s = snapshot(over);
    assert_eq!(
        codec::decode(unchecked(&s).as_slice(), &volume(), Some(s.epoch), &keys())
            .unwrap_err()
            .to_string(),
        "count-over"
    );
}
#[test]
fn intent_replay_requires_current_epoch_and_token_independently() {
    for epoch in [false, true] {
        let mut p = owned(1);
        let row = p.rows.get_mut(&[1; 16]).unwrap();
        if epoch {
            row.grant.receipt.epoch = 2;
        } else {
            row.grant.receipt.instance = [99; 16];
        }
        let reply = transition(
            Some(&p),
            IntentOperation::Ownership,
            &acquire(1, 2, 0),
            &volume(),
            &keys(),
            now(),
        );
        assert_eq!(
            (
                reply.outcome.status().as_u16(),
                reply.outcome.error(),
                reply.next.is_none()
            ),
            (409, Some(ErrorToken::IntentChanged), true)
        );
    }
}
#[test]
fn intent_snapshot_invalid_timestamp_state_generation_and_order_have_checked_controls() {
    let valid = snapshot(owned(1));
    assert!(
        codec::decode(
            encoded(&valid).as_slice(),
            &volume(),
            Some(valid.epoch),
            &keys()
        )
        .is_ok()
    );
    let mut wrong = valid.clone();
    wrong
        .principals
        .values_mut()
        .next()
        .unwrap()
        .rows
        .values_mut()
        .next()
        .unwrap()
        .changed
        .nanos = 1_000_000_000;
    assert_eq!(
        codec::decode(
            unchecked(&wrong).as_slice(),
            &volume(),
            Some(wrong.epoch),
            &keys()
        )
        .unwrap_err()
        .to_string(),
        "timestamp-nanos"
    );
    let mut duplicate = valid.clone();
    let p = duplicate.principals.values_mut().next().unwrap();
    let mut row = p.rows.values().next().unwrap().clone();
    row.receipt.writer = [2; 16];
    row.grant.receipt.writer = [2; 16];
    p.rows.insert([2; 16], row);
    assert_eq!(
        codec::decode(
            unchecked(&duplicate).as_slice(),
            &volume(),
            Some(duplicate.epoch),
            &keys()
        )
        .unwrap_err()
        .to_string(),
        "epoch-cursor"
    );
}

#[test]
fn intent_snapshot_five_named_goldens() {
    let mut acquired = owned(1);
    let mut empty = snapshot(Principal::default());
    empty.principals.clear();
    let zero = snapshot(Principal {
        h: 7,
        rows: BTreeMap::new(),
    });
    let acquired_snapshot = snapshot(acquired.clone());
    let body = register(&acquired, 1, 1, 3);
    run(&mut acquired, IntentOperation::Register, &body, 200, None);
    let q = takeover(acquired.rows.get(&[1; 16]).unwrap(), 5);
    run(&mut acquired, IntentOperation::Ownership, &q, 200, None);
    let live = snapshot(acquired.clone());
    let body = release(&acquired, 1, 1);
    run(&mut acquired, IntentOperation::Release, &body, 200, None);
    let released = snapshot(acquired);
    let fixtures = [
        include_str!("goldens/empty.hex"),
        include_str!("goldens/zero-row.hex"),
        include_str!("goldens/acquired.hex"),
        include_str!("goldens/live.hex"),
        include_str!("goldens/released.hex"),
    ];
    for ((name, state), fixture) in [
        ("empty", empty),
        ("zero-row", zero),
        ("acquired", acquired_snapshot),
        ("live", live),
        ("released", released),
    ]
    .into_iter()
    .zip(fixtures)
    {
        let bytes = encoded(&state);
        let mut hex = String::new();
        for byte in &bytes {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").unwrap();
        }
        let lines: Vec<_> = fixture
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect();
        assert_eq!(
            (lines.first().copied(), lines.get(1).copied()),
            (
                Some(format!("hash={}", GrainId::of(&bytes)).as_str()),
                Some(hex.as_str())
            ),
            "golden {name}"
        );
        assert_eq!(
            codec::decode(bytes.as_slice(), &volume(), Some(state.epoch), &keys()).unwrap(),
            state
        );
    }
}

fn unchecked(s: &Snapshot) -> Vec<u8> {
    let mut bytes = Vec::new();
    codec::encode_unchecked(s, &mut bytes).unwrap();
    bytes
}
#[test]
fn intent_snapshot_encoder_refuses_before_writing_invalid_state() {
    for mode in 0..6 {
        let mut s = snapshot(owned(1));
        let p = s.principals.values_mut().next().unwrap();
        let row = p.rows.values_mut().next().unwrap();
        match mode {
            0 => p.h = 0,
            1 => row.changed.nanos = 1_000_000_000,
            2 => row.grant.receipt.instance = [9; 16],
            3 => {
                row.receipt.generation = 1;
                row.receipt.state = ReceiptState::Live {
                    prepared_root_id: GrainId::of(b"wrong"),
                }
            }
            4 => {
                row.receipt.writer = [9; 16];
                row.grant.receipt.writer = [9; 16];
            }
            _ => row.grant.receipt.writer = [9; 16],
        }
        let mut bytes = Vec::new();
        let result = codec::encode(&s, &mut bytes);
        assert_eq!(
            (result.is_err(), bytes.is_empty()),
            (true, true),
            "mode {mode}: {result:?}"
        );
    }
    assert!(!encoded(&snapshot(owned(1))).is_empty());
}

#[test]
fn intent_snapshot_encoder_checks_each_structural_bound_before_any_output() {
    let mut cases = 0;
    for mode in 0..8 {
        let count = if mode == 0 {
            64
        } else if mode == 1 {
            17
        } else {
            2
        };
        let mut principal = Principal::default();
        for writer in 1..=count {
            let h = principal.h;
            run(
                &mut principal,
                IntentOperation::Ownership,
                &acquire(writer, 2, h),
                200,
                None,
            );
        }
        assert_eq!(
            (principal.h, principal.rows.len()),
            (u64::from(count), usize::from(count))
        );
        let mut s = snapshot(principal);
        let p = s.principals.values_mut().next().unwrap();
        match mode {
            0 => {
                let mut extra = p.rows.values().next().unwrap().clone();
                extra.receipt.writer = [65; 16];
                extra.receipt.epoch = 65;
                extra.grant.receipt = extra.receipt;
                p.h = 65;
                p.rows.insert([65; 16], extra);
            }
            1 => {
                for row in p.rows.values_mut() {
                    row.root = Arc::from(root(3, &volume()));
                    row.receipt.generation = 1;
                    row.receipt.state = ReceiptState::Live {
                        prepared_root_id: GrainId::of(&row.root),
                    };
                }
            }
            2 => {
                let row = p.rows.get_mut(&[2; 16]).unwrap();
                row.receipt.epoch = 1;
                row.grant.receipt.epoch = 1;
            }
            3 | 4 => {
                let row = p.rows.values_mut().next().unwrap();
                let v = if mode == 4 {
                    VolumeName::new("other".into()).unwrap()
                } else {
                    volume()
                };
                row.root = Arc::from(root(3, &v));
                row.receipt.generation = 1;
                row.receipt.state = ReceiptState::Live {
                    prepared_root_id: if mode == 3 {
                        GrainId::of(b"wrong")
                    } else {
                        GrainId::of(&row.root)
                    },
                };
            }
            5 => p.rows.values_mut().next().unwrap().grant.receipt.epoch = 2,
            6 => p.rows.values_mut().next().unwrap().grant.receipt.generation = 1,
            _ => p.rows.values_mut().next().unwrap().grant.receipt.instance = [9; 16],
        }
        let mut bytes = Vec::new();
        let result = codec::encode(&s, &mut bytes);
        assert_eq!(
            (result.is_err(), bytes.is_empty()),
            (true, true),
            "mode {mode}: {result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 8);
    assert!(!encoded(&snapshot(owned(2))).is_empty());
}

#[test]
fn intent_server_vocabulary_matches_emitted_kinds_with_non_vacuous_controls() {
    fn check(doc: &str) -> Result<usize, &'static str> {
        let section = doc
            .split("## Intent observability\n")
            .nth(1)
            .ok_or("intent observability heading missing")?;
        let listed: Vec<_> = section
            .lines()
            .filter(|line| line.starts_with("| `"))
            .map(|line| {
                line.split('|')
                    .nth(1)
                    .unwrap_or_default()
                    .trim()
                    .trim_matches('`')
            })
            .collect();
        let mut expected: Vec<_> = [
            IntentOperation::Register,
            IntentOperation::Release,
            IntentOperation::Ownership,
            IntentOperation::Readback,
        ]
        .map(IntentOperation::kind)
        .into();
        expected.push(super::STORE_KIND);
        if listed != expected {
            return Err("intent kind table differs");
        }
        Ok(listed.len())
    }
    let doc = include_str!("../../../../../docs/operating-the-authority-lifecycle.md");
    assert_eq!(check(doc), Ok(5));
    let wrong = doc.replacen("| `intent_release` |", "| `unknown` |", 1);
    assert_eq!(check(&wrong), Err("intent kind table differs"));
    let missing = doc.replace("## Intent observability", "## Other");
    assert_eq!(check(&missing), Err("intent observability heading missing"));
}

#[test]
fn intent_epoch_fences_even_when_token_matches_and_clock_rollback_cannot_renew_age() {
    let mut p = owned(1);
    let q = takeover(p.rows.values().next().unwrap(), 5);
    run(&mut p, IntentOperation::Ownership, &q, 200, None);
    for op in [IntentOperation::Release, IntentOperation::Register] {
        let bytes = if op == IntentOperation::Register {
            wire::encode_register(&[1; 16], 1, &[5; 16], 100, &root(3, &volume())).unwrap()
        } else {
            wire::encode_release(Release {
                writer: [1; 16],
                epoch: 1,
                instance: [5; 16],
                generation: 100,
            })
            .unwrap()
        };
        run(&mut p, op, &bytes, 409, Some(ErrorToken::IntentSuperseded));
    }
    let bytes = register(&p, 1, 1, 3);
    let next = transition(
        Some(&p),
        IntentOperation::Register,
        &bytes,
        &volume(),
        &keys(),
        Timestamp { secs: 99, nanos: 0 },
    )
    .next
    .unwrap();
    assert_eq!(next.rows.values().next().unwrap().changed, now());
}
#[test]
fn intent_absent_writer_never_uses_another_row() {
    let mut p = owned(1);
    for op in [
        IntentOperation::Register,
        IntentOperation::Release,
        IntentOperation::Ownership,
    ] {
        let bytes = match op {
            IntentOperation::Register => {
                wire::encode_register(&[2; 16], 1, &[2; 16], 100, &root(3, &volume())).unwrap()
            }
            IntentOperation::Release => wire::encode_release(Release {
                writer: [2; 16],
                epoch: 1,
                instance: [2; 16],
                generation: 100,
            })
            .unwrap(),
            _ => wire::encode_ownership(Ownership {
                writer: [2; 16],
                instance: [5; 16],
                mode: OwnershipMode::Takeover {
                    expected_epoch: 1,
                    generation: 0,
                    state: ReceiptState::Released,
                    recovery_ack: true,
                },
            })
            .unwrap(),
        };
        run(&mut p, op, &bytes, 409, Some(ErrorToken::IntentAbsent));
    }
}

#[test]
fn intent_retention_evicts_only_rootless_rows_and_keeps_live_roots_and_h() {
    let mut p = owned(1);
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(2, 2, 1),
        200,
        None,
    );
    let bytes = register(&p, 1, 1, 3);
    run(&mut p, IntentOperation::Register, &bytes, 200, None);
    let mut s = snapshot(p);
    assert!(evict(
        &mut s,
        Timestamp {
            secs: 100_000,
            nanos: 0
        },
        0
    ));
    let p = s.principals.values().next().unwrap();
    assert_eq!(
        (
            p.h,
            p.rows.len(),
            p.rows.contains_key(&[1; 16]),
            p.rows.contains_key(&[2; 16])
        ),
        (2, 1, true, false)
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Checked malformed fixtures share framing and one explicit case count"
)]
fn intent_snapshot_check_valid_structure_refusals_are_independent_of_hashes() {
    let valid = snapshot(owned(1));
    let bytes = encoded(&valid);
    let envelope = 78 + volume().as_str().len();
    let row_at = envelope + 64 + 5;
    let mut cases = 0;
    for (at, value, rule) in [
        (0, b'X', "envelope"),
        (9, 2, "envelope"),
        (11, 1, "envelope"),
        (envelope + 4, 9, "frame-tag"),
        (row_at + 48, 3, "root-shape"),
    ] {
        let mut bad = bytes.clone();
        *bad.get_mut(at).unwrap() = value;
        recheck_counts(&mut bad, 1, 1);
        assert_eq!(
            codec::decode(bad.as_slice(), &volume(), Some(valid.epoch), &keys())
                .unwrap_err()
                .to_string(),
            rule
        );
        cases += 1;
    }
    let wrong_volume = VolumeName::new("other".into()).unwrap();
    assert_eq!(
        codec::decode(bytes.as_slice(), &wrong_volume, Some(valid.epoch), &keys())
            .unwrap_err()
            .to_string(),
        "volume-mismatch"
    );
    cases += 1;
    assert_eq!(
        codec::decode(
            bytes.as_slice(),
            &volume(),
            Some(Epoch::from_bytes([8; 16])),
            &keys()
        )
        .unwrap_err()
        .to_string(),
        "epoch-mismatch"
    );
    cases += 1;
    let mut invalid = valid.clone();
    invalid
        .principals
        .values_mut()
        .next()
        .unwrap()
        .rows
        .values_mut()
        .next()
        .unwrap()
        .receipt
        .generation = u64::MAX;
    assert_eq!(
        codec::decode(
            unchecked(&invalid).as_slice(),
            &volume(),
            Some(valid.epoch),
            &keys()
        )
        .unwrap_err()
        .to_string(),
        "receipt-invalid"
    );
    cases += 1;
    let mut principal = owned(1);
    run(
        &mut principal,
        IntentOperation::Ownership,
        &acquire(2, 2, 1),
        200,
        None,
    );
    let mut duplicate = snapshot(principal.clone());
    let row = duplicate
        .principals
        .values_mut()
        .next()
        .unwrap()
        .rows
        .get_mut(&[2; 16])
        .unwrap();
    row.receipt.writer = [1; 16];
    row.grant.receipt.writer = [1; 16];
    assert_eq!(
        codec::decode(
            unchecked(&duplicate).as_slice(),
            &volume(),
            Some(valid.epoch),
            &keys()
        )
        .unwrap_err()
        .to_string(),
        "writer-order"
    );
    cases += 1;
    let mut ordered = snapshot(Principal::default());
    ordered
        .principals
        .insert(PrincipalId::from_bytes([2; 16]), Principal::default());
    let mut bad = encoded(&ordered);
    bad.get_mut(envelope + 64 + 5..envelope + 64 + 21)
        .unwrap()
        .fill(1);
    recheck_counts(&mut bad, 2, 0);
    assert_eq!(
        codec::decode(bad.as_slice(), &volume(), Some(valid.epoch), &keys())
            .unwrap_err()
            .to_string(),
        "principal-order"
    );
    cases += 1;
    for n in 3..=17 {
        let h = principal.h;
        run(
            &mut principal,
            IntentOperation::Ownership,
            &acquire(n, 2, h),
            200,
            None,
        );
    }
    for (writer, row) in &mut principal.rows {
        row.root = Arc::from(root(writer[0], &volume()));
        row.receipt.generation = 1;
        row.receipt.state = ReceiptState::Live {
            prepared_root_id: GrainId::of(&row.root),
        };
    }
    let over = snapshot(principal);
    assert_eq!(
        codec::decode(
            unchecked(&over).as_slice(),
            &volume(),
            Some(valid.epoch),
            &keys()
        )
        .unwrap_err()
        .to_string(),
        "quota-over"
    );
    cases += 1;
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        codec::decode(trailing.as_slice(), &volume(), Some(valid.epoch), &keys())
            .unwrap_err()
            .to_string(),
        "trailing-bytes"
    );
    cases += 1;
    let mut live = owned(1);
    let body = register(&live, 1, 1, 3);
    run(&mut live, IntentOperation::Register, &body, 200, None);
    let mut invalid = snapshot(live);
    let row = invalid
        .principals
        .values_mut()
        .next()
        .unwrap()
        .rows
        .values_mut()
        .next()
        .unwrap();
    let mut corrupt = row.root.to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    row.root = Arc::from(corrupt);
    row.receipt.state = ReceiptState::Live {
        prepared_root_id: GrainId::of(&row.root),
    };
    assert_eq!(
        codec::decode(
            unchecked(&invalid).as_slice(),
            &volume(),
            Some(valid.epoch),
            &keys()
        )
        .unwrap_err()
        .to_string(),
        "root-invalid"
    );
    cases += 1;
    assert_eq!(cases, 13);
    assert_eq!(
        codec::decode(bytes.as_slice(), &volume(), Some(valid.epoch), &keys()).unwrap(),
        valid
    );
}

#[test]
fn intent_snapshot_each_saved_grant_identity_and_generation_field_is_checked() {
    let valid = snapshot(owned(1));
    assert!(
        codec::decode(
            encoded(&valid).as_slice(),
            &volume(),
            Some(valid.epoch),
            &keys()
        )
        .is_ok()
    );
    for mode in 0..4 {
        let mut invalid = valid.clone();
        let row = invalid
            .principals
            .values_mut()
            .next()
            .unwrap()
            .rows
            .values_mut()
            .next()
            .unwrap();
        match mode {
            0 => row.grant.receipt.writer = [2; 16],
            1 => row.grant.receipt.epoch = 2,
            2 => row.grant.receipt.instance = [3; 16],
            _ => row.grant.receipt.generation = 1,
        }
        assert_eq!(
            codec::decode(
                unchecked(&invalid).as_slice(),
                &volume(),
                Some(valid.epoch),
                &keys()
            )
            .unwrap_err()
            .to_string(),
            "grant-current",
            "field {mode}"
        );
    }
}

#[test]
fn intent_snapshot_footer_fields_are_checked_independently_of_footer_hash() {
    let s = snapshot(owned(1));
    let valid = encoded(&s);
    let footer = valid.len() - 90;
    let envelope_end = 13 + volume().as_str().len() + 32;
    for at in [0, 15, 23, 56] {
        let mut bad = valid.clone();
        *bad.get_mut(footer + at).unwrap() ^= 1;
        let check = GrainId::of(
            &[
                b"granary intent-store footer v1".as_slice(),
                bad.get(envelope_end..envelope_end + 33).unwrap(),
                bad.get(footer..footer + 57).unwrap(),
            ]
            .concat(),
        );
        bad.get_mut(footer + 57..)
            .unwrap()
            .copy_from_slice(&check.to_bytes());
        assert_eq!(
            codec::decode(bad.as_slice(), &volume(), Some(s.epoch), &keys())
                .unwrap_err()
                .to_string(),
            "footer",
            "field {at}"
        );
    }
    assert_eq!(
        codec::decode(valid.as_slice(), &volume(), Some(s.epoch), &keys()).unwrap(),
        s
    );
}

fn judge_success(operation: IntentOperation, bytes: &[u8], outcome: &Outcome) {
    let reply = wire::Reply {
        status: outcome.status().as_u16(),
        media_type: outcome.content_type().map(ContentType::as_str),
        token: outcome.error().map(ErrorToken::as_str),
        body: outcome.body(),
    };
    match operation {
        IntentOperation::Ownership => assert!(matches!(
            wire::judge_ownership(bytes, &reply).unwrap(),
            wire::Verdict::Accepted(_)
        )),
        IntentOperation::Register => {
            let req = wire::decode_register(bytes, &volume(), |doc, signed| {
                check_signatures(doc, signed, &keys()).is_ok()
            })
            .unwrap();
            let req = wire::RegisterRequest {
                writer: req.writer,
                epoch: req.epoch,
                instance: req.instance,
                generation: req.generation,
                root_id: req.root_id(),
            };
            assert!(matches!(
                wire::judge_register(&req, &reply),
                wire::Verdict::Accepted(_)
            ));
        }
        IntentOperation::Release => {
            let req = wire::decode_release(bytes).unwrap();
            let req = wire::ReleaseRequest {
                writer: req.writer,
                epoch: req.epoch,
                instance: req.instance,
                generation: req.generation,
            };
            assert!(matches!(
                wire::judge_release(&req, &reply),
                wire::Verdict::Accepted(_)
            ));
        }
        IntentOperation::Readback => assert!(matches!(
            wire::judge_readback(&reply, &volume(), |doc, signed| check_signatures(
                doc,
                signed,
                &keys()
            )
            .is_ok()),
            wire::Verdict::Accepted(_)
        )),
    }
}

#[test]
fn round1_unseen_principal_has_coherent_absence_readback_and_acquire() {
    let row = owned(1).rows.remove(&[1; 16]).unwrap();
    let takeover = transition(
        None,
        IntentOperation::Ownership,
        &takeover(&row, 3),
        &volume(),
        &keys(),
        now(),
    );
    assert_eq!(takeover.outcome.error(), Some(ErrorToken::IntentAbsent));
    let read = transition(
        None,
        IntentOperation::Readback,
        &[],
        &volume(),
        &keys(),
        now(),
    );
    assert_eq!(read.outcome.status(), Status::Ok);
    let value = wire::decode_readback(read.outcome.body(), &volume(), |_, _| true).unwrap();
    assert_eq!(value.cursor, 0);
    assert!(value.rows.is_empty());
    assert!(read.next.is_none());
    let stale = transition(
        None,
        IntentOperation::Ownership,
        &acquire(1, 2, 1),
        &volume(),
        &keys(),
        now(),
    );
    assert_eq!(stale.outcome.error(), Some(ErrorToken::IntentCursorChanged));
    let acquired = transition(
        None,
        IntentOperation::Ownership,
        &acquire(1, 2, 0),
        &volume(),
        &keys(),
        now(),
    );
    assert_eq!(acquired.outcome.status(), Status::Ok);
    assert_eq!(acquired.next.unwrap().h, 1);
}

#[test]
fn released_row_is_evicted_and_its_succession_answers_absent() {
    // A clean unmount releases the row, leaving no root; retention then
    // evicts it, and the owner's conditional succession finds no row.
    let mut p = owned(1);
    let bytes = register(&p, 1, 1, 7);
    run(&mut p, IntentOperation::Register, &bytes, 200, None);
    let bytes = release(&p, 1, 1);
    run(&mut p, IntentOperation::Release, &bytes, 200, None);
    let row = p.rows.get(&[1; 16]).unwrap().clone();
    assert_eq!(
        (
            row.root.is_empty(),
            row.receipt.state,
            row.receipt.generation
        ),
        (true, ReceiptState::Released, 1)
    );
    let h = p.h;
    let mut s = snapshot(p);
    let horizon = wire::released_row_retention_secs(0);
    let later = Timestamp {
        secs: row.changed.secs + i64::try_from(horizon).unwrap(),
        nanos: row.changed.nanos,
    };
    assert!(evict(&mut s, later, 0));
    let mut p = s.principals.into_values().next().unwrap();
    assert_eq!((p.h, p.rows.len()), (h, 0));
    let succession = wire::encode_ownership(Ownership {
        writer: row.receipt.writer,
        instance: [3; 16],
        mode: OwnershipMode::Takeover {
            expected_epoch: row.receipt.epoch,
            generation: row.receipt.generation,
            state: row.receipt.state,
            recovery_ack: false,
        },
    })
    .unwrap();
    run(
        &mut p,
        IntentOperation::Ownership,
        &succession,
        409,
        Some(ErrorToken::IntentAbsent),
    );
    run(
        &mut p,
        IntentOperation::Ownership,
        &acquire(1, 3, h),
        200,
        None,
    );
}
