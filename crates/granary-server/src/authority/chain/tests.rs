// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Validity, head resolution, the next seq, and the classification table
//! row by row, over the simulator's store.

pub(in crate::authority) mod oracle;
pub(in crate::authority) mod scripted;

use std::future::Future;

use granary_sim::fakes::{Fault, Faults, Sim};

use super::*;
use crate::authority::tests::{good_root, publisher, signed_root, stranger, vol};

fn volume() -> VolumeName {
    vol("vol-chain")
}

fn keys() -> TrustedKeys {
    TrustedKeys::new([*publisher().public_key()]).unwrap()
}

fn block<T: 'static>(future: impl Future<Output = T> + 'static) -> T {
    granary_sim::scenario::run(0, Box::pin(future))
}

/// Plant a publisher-signed chain at seqs `1..=len`; each root's bytes.
fn plant_chain(sim: &Sim, len: u64, variant: u8) -> Vec<Vec<u8>> {
    let mut chain: Vec<Vec<u8>> = Vec::new();
    for seq in 1..=len {
        let parent = chain.last().map(|bytes| GrainId::of(bytes));
        let bytes = good_root(&volume(), seq, parent, variant);
        assert!(sim.admin().plant_root(&volume(), seq, bytes.clone()));
        chain.push(bytes);
    }
    chain
}

// ------------------------------------------------------------ next seq

/// A candidate extends a head only at its next seq and naming its id;
/// nothing extends a head with no next seq.
#[test]
fn only_the_next_seq_on_the_heads_id_extends_it() {
    let id = GrainId::of(b"head");
    let head = VerifiedHead::new(Some(HeadRef {
        head_seq: 4,
        head_id: id,
    }));
    assert!(head.extended_by(5, Some(id)));
    assert!(!head.extended_by(5, Some(GrainId::of(b"other"))));
    assert!(!head.extended_by(5, None));
    assert!(!head.extended_by(4, Some(id)));
    assert!(!head.extended_by(6, Some(id)));
    let empty = VerifiedHead::new(None);
    assert!(empty.extended_by(1, None));
    assert!(!empty.extended_by(1, Some(id)));
    let top = VerifiedHead::new(Some(HeadRef {
        head_seq: u64::MAX - 2,
        head_id: id,
    }));
    assert_eq!(top.next_seq, None);
    assert!(!top.extended_by(u64::MAX - 1, Some(id)));
}

// ------------------------------------------------------ head resolution

/// The head is the highest listed seq, verified with its whole chain.
#[test]
fn a_valid_chain_resolves_to_its_highest_root() {
    let sim = Sim::new();
    let chain = plant_chain(&sim, 3, 1);
    let store = sim.node(1, Faults::none());
    let head = block(async move {
        resolve_head(&store, &volume(), &keys(), &mut ChainMemo::default()).await
    });
    assert_eq!(
        head,
        Ok(VerifiedHead::new(Some(HeadRef {
            head_seq: 3,
            head_id: GrainId::of(&chain[2]),
        })))
    );
    let empty = Sim::new().node(1, Faults::none());
    let head = block(async move {
        resolve_head(&empty, &volume(), &keys(), &mut ChainMemo::default()).await
    });
    assert_eq!(head, Ok(VerifiedHead::new(None)));
}

/// Every way a head fails to verify: its own signature, a missing
/// ancestor, a replaced ancestor, an ancestor that is not a root, and a
/// failed listing or read.
#[test]
fn a_head_that_does_not_verify_is_refused() {
    type Damage = Box<dyn Fn(&Sim, &[Vec<u8>])>;
    let cases: Vec<(&str, Damage, Faults, Unverified)> = vec![
        (
            "a stranger's head",
            Box::new(|sim, chain| {
                assert!(sim.admin().delete_root(&volume(), 3));
                let bad = signed_root(
                    &volume(),
                    3,
                    Some(GrainId::of(&chain[1])),
                    9,
                    &[&stranger()],
                );
                assert!(sim.admin().plant_root(&volume(), 3, bad));
            }),
            Faults::none(),
            Unverified::Invalid,
        ),
        (
            "a missing ancestor",
            Box::new(|sim, _| assert!(sim.admin().delete_root(&volume(), 1))),
            Faults::none(),
            Unverified::Invalid,
        ),
        (
            "a replaced ancestor",
            Box::new(|sim, _| {
                assert!(sim.admin().delete_root(&volume(), 1));
                let other = good_root(&volume(), 1, None, 9);
                assert!(sim.admin().plant_root(&volume(), 1, other));
            }),
            Faults::none(),
            Unverified::Invalid,
        ),
        (
            "an ancestor that is not a root",
            Box::new(|sim, _| {
                assert!(sim.admin().delete_root(&volume(), 2));
                assert!(sim.admin().plant_root(&volume(), 2, b"junk".to_vec()));
            }),
            Faults::none(),
            Unverified::Invalid,
        ),
        (
            "a failed listing",
            Box::new(|_, _| {}),
            Faults::just(Fault::Fail(0)),
            Unverified::Unread,
        ),
        (
            "a failed ancestor read",
            Box::new(|_, _| {}),
            Faults::just(Fault::Fail(2)),
            Unverified::Unread,
        ),
    ];
    for (name, damage, faults, expected) in cases {
        let sim = Sim::new();
        let chain = plant_chain(&sim, 3, 1);
        damage(&sim, &chain);
        let store = sim.node(1, faults);
        let head = block(async move {
            resolve_head(&store, &volume(), &keys(), &mut ChainMemo::default()).await
        });
        assert_eq!(head, Err(expected), "{name}");
    }
}

// ------------------------------------------- the classification table

/// One row: what the store holds at the entry's seq (2) and at its base's
/// seq (1), the store's faults, and what the read must find.
struct Row {
    name: &'static str,
    at_seq: Option<Vec<u8>>,
    at_base: Option<Vec<u8>>,
    faults: Faults,
    expected: Classification,
}

impl Row {
    fn new(
        name: &'static str,
        at_seq: Option<&[u8]>,
        at_base: Option<&[u8]>,
        faults: Faults,
        expected: Classification,
    ) -> Self {
        Self {
            name,
            at_seq: at_seq.map(<[u8]>::to_vec),
            at_base: at_base.map(<[u8]>::to_vec),
            faults,
            expected,
        }
    }
}

/// Each row of the table, over an entry at seq 2 whose recorded base is
/// the root at seq 1 and whose recorded bytes are `recorded`.
fn rows(base_bytes: &[u8], recorded: &[u8]) -> Vec<Row> {
    let base = Some(GrainId::of(base_bytes));
    let on_base = good_root(&volume(), 2, base, 3);
    let other_base = good_root(&volume(), 1, None, 4);
    let off_base = good_root(&volume(), 2, Some(GrainId::of(&other_base)), 5);
    let other_volume = good_root(&vol("vol-other"), 2, base, 3);
    let strangers = signed_root(&volume(), 2, base, 3, &[&stranger()]);
    let none = Faults::none;
    vec![
        Row::new(
            "the recorded bytes",
            Some(recorded),
            Some(base_bytes),
            none(),
            Classification::Landed,
        ),
        Row::new(
            "a valid root on the base",
            Some(&on_base),
            Some(base_bytes),
            none(),
            Classification::Lost {
                occupant: GrainId::of(&on_base),
            },
        ),
        Row::new(
            "a valid root off the base",
            Some(&off_base),
            Some(&other_base),
            none(),
            Classification::Wedged,
        ),
        Row::new(
            "an undecodable object",
            Some(b"junk"),
            Some(base_bytes),
            none(),
            Classification::Wedged,
        ),
        Row::new(
            "another volume's root",
            Some(&other_volume),
            Some(base_bytes),
            none(),
            Classification::Wedged,
        ),
        Row::new(
            "a stranger's root",
            Some(&strangers),
            Some(base_bytes),
            none(),
            Classification::Wedged,
        ),
        Row::new(
            "an ancestor missing",
            Some(&on_base),
            None,
            none(),
            Classification::Wedged,
        ),
        Row::new(
            "nothing",
            None,
            Some(base_bytes),
            none(),
            Classification::Unresolved,
        ),
        Row::new(
            "a failed read of the seq",
            Some(&on_base),
            Some(base_bytes),
            Faults::just(Fault::Fail(0)),
            Classification::Unresolved,
        ),
        Row::new(
            "a failed read of an ancestor",
            Some(&on_base),
            Some(base_bytes),
            Faults::just(Fault::Fail(1)),
            Classification::Unresolved,
        ),
    ]
}

/// The classification table row by row, over the simulator's store.
#[test]
fn the_classification_table_row_by_row() {
    let base_bytes = good_root(&volume(), 1, None, 1);
    let base = Some(GrainId::of(&base_bytes));
    let recorded = good_root(&volume(), 2, base, 2);
    for row in rows(&base_bytes, &recorded) {
        let sim = Sim::new();
        if let Some(bytes) = row.at_base {
            assert!(sim.admin().plant_root(&volume(), 1, bytes));
        }
        if let Some(bytes) = row.at_seq {
            assert!(sim.admin().plant_root(&volume(), 2, bytes));
        }
        let store = sim.node(1, row.faults);
        let recorded = recorded.clone();
        let found =
            block(
                async move { classify_seq(&store, &volume(), &keys(), 2, base, &recorded).await },
            );
        assert_eq!(found, row.expected, "{}", row.name);
    }
}

// ----------------------------------------------------- anchored resolution

use scripted::{Call, ScriptedStore};

fn list() -> Call {
    Call::List(volume().as_str().to_owned())
}

fn above(floor: u64) -> Call {
    Call::Above(volume().as_str().to_owned(), floor)
}

fn get(seq: u64) -> Call {
    Call::Get(volume().as_str().to_owned(), seq)
}

fn root_at(chain: &[Vec<u8>], seq: u64) -> &[u8] {
    &chain[usize::try_from(seq - 1).unwrap()]
}

fn id_at(chain: &[Vec<u8>], seq: u64) -> GrainId {
    GrainId::of(root_at(chain, seq))
}

fn set(store: &ScriptedStore, seq: u64, bytes: Option<Vec<u8>>) {
    store.set(volume().as_str(), seq, bytes);
}

fn extend(store: &ScriptedStore, chain: &mut Vec<Vec<u8>>, depth: u64) {
    for seq in (u64::try_from(chain.len()).unwrap() + 1)..=depth {
        let bytes = good_root(&volume(), seq, chain.last().map(|b| GrainId::of(b)), 1);
        set(store, seq, Some(bytes.clone()));
        chain.push(bytes);
    }
}

fn expected(seq: u64, bytes: &[u8]) -> VerifiedHead {
    VerifiedHead {
        head: Some(HeadRef {
            head_seq: seq,
            head_id: GrainId::of(bytes),
        }),
        next_seq: Some(seq + 1),
    }
}

fn anchor(seq: u64, bytes: &[u8], parent: Option<GrainId>) -> Anchor {
    Anchor {
        seq,
        id: GrainId::of(bytes),
        parent,
    }
}

fn anchored(chain: &[Vec<u8>], seq: u64) -> Anchor {
    anchor(
        seq,
        root_at(chain, seq),
        (seq > 1).then(|| id_at(chain, seq - 1)),
    )
}

fn assert_memo(memo: &ChainMemo, anchor: Option<Anchor>, cursor: Option<(u64, GrainId)>) {
    assert_eq!((memo.anchor, memo.cursor), (anchor, cursor));
}

async fn resolve(store: &ScriptedStore, memo: &mut ChainMemo) -> Result<VerifiedHead, Unverified> {
    resolve_head(store, &volume(), &keys(), memo).await
}

async fn reference(store: &ScriptedStore) -> Result<VerifiedHead, Unverified> {
    oracle::resolve_head(store, &volume(), &keys()).await
}

#[test]
fn stable_store_matches_full_walk() {
    block(async {
        for depth in [0, 1, 2, 3, 64] {
            for growth in [0, 1, 3] {
                let store = ScriptedStore::default();
                let mut chain = Vec::new();
                let mut memo = ChainMemo::default();
                extend(&store, &mut chain, depth);
                assert_memo(&memo, None, None);
                assert_eq!(resolve(&store, &mut memo).await, reference(&store).await);
                if depth == 0 {
                    assert_memo(&memo, None, None);
                }
                let slow = match depth {
                    0 | 1 => None,
                    2 => Some(1),
                    _ => {
                        assert_eq!(
                            resolve(&store, &mut memo).await,
                            Ok(expected(depth, root_at(&chain, depth)))
                        );
                        assert_memo(
                            &memo,
                            Some(anchored(&chain, depth)),
                            Some((depth - 2, id_at(&chain, depth - 2))),
                        );
                        Some(depth - 2)
                    }
                };
                let top = depth + growth;
                extend(&store, &mut chain, top);
                store.take_calls();
                let actual = resolve(&store, &mut memo).await;
                let mut calls = vec![if depth == 0 { list() } else { above(depth - 1) }];
                let floor = depth.max(1);
                calls.extend((floor..=top).rev().map(get));
                calls.extend(slow.map(get));
                assert_eq!(store.take_calls(), calls, "depth {depth}, growth {growth}");
                assert_eq!(actual, reference(&store).await);
                let cursor = slow
                    .filter(|seq| *seq > 1)
                    .map(|seq| (seq - 1, id_at(&chain, seq - 1)));
                if top == 0 {
                    assert_eq!(
                        actual,
                        Ok(VerifiedHead {
                            head: None,
                            next_seq: Some(1)
                        })
                    );
                    assert_memo(&memo, None, None);
                } else {
                    assert_eq!(actual, Ok(expected(top, root_at(&chain, top))));
                    assert_memo(&memo, Some(anchored(&chain, top)), cursor);
                }
            }
        }
    });
}

/// Warm at 5, with the slow walk's next read at 3, then extend as requested.
async fn prepared(warm: bool, top: u64) -> (ScriptedStore, Vec<Vec<u8>>, ChainMemo) {
    let store = ScriptedStore::default();
    let mut chain = Vec::new();
    let mut memo = ChainMemo::default();
    extend(&store, &mut chain, 5);
    if warm {
        for _ in 0..2 {
            assert_eq!(
                resolve(&store, &mut memo).await,
                Ok(expected(5, root_at(&chain, 5)))
            );
        }
        assert_memo(
            &memo,
            Some(anchored(&chain, 5)),
            Some((3, id_at(&chain, 3))),
        );
    }
    extend(&store, &mut chain, top);
    store.take_calls();
    (store, chain, memo)
}

#[derive(Clone, Copy, Debug)]
enum Damage {
    Delete,
    Replace,
    Garbage,
    OverCap,
}

#[test]
fn damage_at_each_position_follows_the_transition_table() {
    block(async {
        for warm in [false, true] {
            for seq in [7, 5, 3, 1] {
                for damage in [
                    Damage::Delete,
                    Damage::Replace,
                    Damage::Garbage,
                    Damage::OverCap,
                ] {
                    let (store, chain, mut memo) = prepared(warm, 8).await;
                    let other = ScriptedStore::default();
                    for at in 1..=8 {
                        set(&other, at, Some(root_at(&chain, at).to_vec()));
                    }
                    for s in [&store, &other] {
                        match damage {
                            Damage::Delete => set(s, seq, None),
                            Damage::Replace => set(
                                s,
                                seq,
                                Some(good_root(
                                    &volume(),
                                    seq,
                                    (seq > 1).then(|| id_at(&chain, seq - 1)),
                                    7,
                                )),
                            ),
                            Damage::Garbage => set(s, seq, Some(b"garbage".to_vec())),
                            Damage::OverCap => s.fail(get(seq), true),
                        }
                    }
                    let actual = resolve(&store, &mut memo).await;
                    assert_eq!(reference(&other).await, Err(Unverified::Invalid));
                    let (answer, a, cursor) = match (warm, seq) {
                        (true, 1) => (
                            Ok(expected(8, root_at(&chain, 8))),
                            Some(anchored(&chain, 8)),
                            Some((2, id_at(&chain, 2))),
                        ),
                        (true, 7) => (
                            Err(Unverified::Invalid),
                            Some(anchored(&chain, 5)),
                            Some((3, id_at(&chain, 3))),
                        ),
                        _ => (Err(Unverified::Invalid), None, None),
                    };
                    assert_eq!(actual, answer, "{warm}, {seq}, {damage:?}");
                    assert_memo(&memo, a, cursor);
                    let last = if warm && seq <= 3 { 3 } else { seq };
                    let mut calls = vec![if warm { above(4) } else { list() }];
                    calls.extend((last.max(if warm { 5 } else { 1 })..=8).rev().map(get));
                    if warm && last == 3 {
                        calls.push(get(3));
                    }
                    assert_eq!(store.take_calls(), calls, "{warm}, {seq}, {damage:?}");
                }
            }
        }
    });
}

#[test]
fn anchor_identity_is_checked_before_the_link_and_before_stopping() {
    block(async {
        for warm in [false, true] {
            for (replace_anchor, replace_child) in [(true, false), (true, true), (false, true)] {
                let (store, chain, mut memo) = prepared(warm, 6).await;
                let replacement = good_root(&volume(), 5, Some(id_at(&chain, 4)), 9);
                let child = good_root(&volume(), 6, Some(GrainId::of(&replacement)), 9);
                if replace_anchor {
                    set(&store, 5, Some(replacement.clone()));
                }
                if replace_child {
                    set(&store, 6, Some(child.clone()));
                }
                let actual = resolve(&store, &mut memo).await;
                let calls = store.take_calls();
                assert_eq!(actual, reference(&store).await);
                if replace_anchor && replace_child {
                    assert_eq!(actual, Ok(expected(6, &child)));
                    assert_memo(
                        &memo,
                        Some(anchor(6, &child, Some(GrainId::of(&replacement)))),
                        None,
                    );
                    assert_eq!(calls[1..], (1..=6).rev().map(get).collect::<Vec<_>>());
                } else {
                    assert_eq!(actual, Err(Unverified::Invalid));
                    assert_eq!(calls[1..], [get(6), get(5)]);
                    if warm && !replace_anchor {
                        assert_memo(
                            &memo,
                            Some(anchored(&chain, 5)),
                            Some((3, id_at(&chain, 3))),
                        );
                    } else {
                        assert_memo(&memo, None, None);
                    }
                }
                assert_eq!(calls[0], if warm { above(4) } else { list() });
            }
        }
    });
}

#[test]
fn a_linked_replacement_leaves_the_memo_empty_when_the_full_walk_fails() {
    block(async {
        for warm in [false, true] {
            for top in [5, 6] {
                for failure in [Unverified::Invalid, Unverified::Unread] {
                    let (store, chain, mut memo) = prepared(warm, top).await;
                    let replacement = good_root(&volume(), 5, Some(id_at(&chain, 4)), 9);
                    let child = good_root(&volume(), 6, Some(GrainId::of(&replacement)), 9);
                    set(&store, 5, Some(replacement));
                    if top == 6 {
                        set(&store, 6, Some(child));
                    }
                    if failure == Unverified::Unread {
                        store.fail(get(2), false);
                    } else {
                        set(&store, 2, None);
                    }
                    assert_eq!(resolve(&store, &mut memo).await, Err(failure));
                    let mut calls = vec![if warm { above(4) } else { list() }];
                    calls.extend((2..=top).rev().map(get));
                    assert_eq!(store.take_calls(), calls);
                    assert_memo(&memo, None, None);
                    if failure == Unverified::Unread {
                        store.fail(get(2), false);
                    }
                    assert_eq!(reference(&store).await, Err(failure));
                }
            }
        }
    });
}

#[test]
fn head_damage_and_replacements_use_the_exact_stored_id() {
    block(async {
        for warm in [false, true] {
            for (top, fault) in [
                (5, "missing"),
                (5, "over cap"),
                (5, "garbage"),
                (6, "signature"),
                (6, "missing"),
                (6, "over cap"),
                (5, "replay"),
                (5, "added slot"),
            ] {
                let (store, chain, mut memo) = prepared(warm, top).await;
                let parent = Some(id_at(&chain, top - 1));
                let replacement = match fault {
                    "signature" => Some(signed_root(&volume(), top, parent, 9, &[&stranger()])),
                    "garbage" => Some(b"garbage".to_vec()),
                    "replay" => Some(good_root(&volume(), top, parent, 9)),
                    "added slot" => {
                        let mut doc =
                            granary_core::root::decode_root(root_at(&chain, top)).unwrap();
                        doc.sigs.push(granary_core::root::RootSig {
                            key_id: [0xFF; granary_core::root::KEY_ID_LEN],
                            sig: [0x88; granary_core::root::ED25519_SIG_LEN],
                        });
                        Some(granary_core::root::encode_root(&doc).unwrap())
                    }
                    _ => None,
                };
                let listing = if warm { above(4) } else { list() };
                let after_list = move |s: &ScriptedStore| s.set(volume().as_str(), top, None);
                let actual = if fault == "missing" {
                    store.after(listing.clone(), after_list);
                    resolve(&store, &mut memo).await
                } else {
                    if fault == "over cap" {
                        store.fail(get(top), true);
                    } else {
                        set(&store, top, replacement.clone());
                    }
                    resolve(&store, &mut memo).await
                };
                let mut calls = vec![listing, get(top)];
                if matches!(fault, "added slot" | "replay") {
                    let bytes = replacement.unwrap();
                    assert_ne!(GrainId::of(&bytes), id_at(&chain, top));
                    assert_eq!(actual, Ok(expected(top, &bytes)));
                    assert_memo(&memo, Some(anchor(top, &bytes, parent)), None);
                    calls.extend((1..top).rev().map(get));
                } else {
                    assert_eq!(actual, Err(Unverified::Invalid));
                    if warm && top > 5 {
                        assert_memo(
                            &memo,
                            Some(anchored(&chain, 5)),
                            Some((3, id_at(&chain, 3))),
                        );
                    } else {
                        assert_memo(&memo, None, None);
                    }
                }
                assert_eq!(store.take_calls(), calls, "{warm}, {top}, {fault}");
                if fault == "missing" {
                    set(&store, top, Some(root_at(&chain, top).to_vec()));
                    store.after(list(), after_list);
                } else if fault == "over cap" {
                    store.fail(get(top), true);
                }
                assert_eq!(actual, reference(&store).await);
            }
        }
    });
}

#[test]
fn cross_key_swap_gap_and_truncation() {
    block(async {
        for warm in [false, true] {
            let (store, chain, mut memo) = prepared(warm, 8).await;
            set(&store, 7, Some(root_at(&chain, 6).to_vec()));
            set(&store, 6, Some(root_at(&chain, 7).to_vec()));
            assert_eq!(resolve(&store, &mut memo).await, Err(Unverified::Invalid));
            assert_eq!(reference(&store).await, Err(Unverified::Invalid));
            set(&store, 7, Some(root_at(&chain, 7).to_vec()));
            set(&store, 6, Some(root_at(&chain, 6).to_vec()));
            set(
                &store,
                13,
                Some(good_root(&volume(), 13, Some(id_at(&chain, 8)), 9)),
            );
            assert_eq!(resolve(&store, &mut memo).await, Err(Unverified::Invalid));
            assert_eq!(reference(&store).await, Err(Unverified::Invalid));
            assert_memo(
                &memo,
                warm.then(|| anchored(&chain, 5)),
                warm.then(|| (3, id_at(&chain, 3))),
            );
            set(&store, 13, None);
            assert_eq!(
                resolve(&store, &mut memo).await,
                Ok(expected(8, root_at(&chain, 8)))
            );
            assert_eq!(reference(&store).await, Ok(expected(8, root_at(&chain, 8))));
            for top in [5, 4, 0] {
                let (store, chain, mut memo) = prepared(warm, 8).await;
                for seq in (top + 1)..=8 {
                    set(&store, seq, None);
                }
                let answer = resolve(&store, &mut memo).await;
                let mut calls = Vec::new();
                if warm {
                    calls.push(above(4));
                }
                if warm && top == 5 {
                    calls.extend([get(5), get(3)]);
                } else {
                    calls.push(list());
                    calls.extend((1..=top).rev().map(get));
                }
                assert_eq!(store.take_calls(), calls);
                assert_eq!(answer, reference(&store).await);
                assert_eq!(
                    answer,
                    Ok(if top == 0 {
                        VerifiedHead::new(None)
                    } else {
                        expected(top, root_at(&chain, top))
                    })
                );
                assert_memo(
                    &memo,
                    (top > 0).then(|| anchored(&chain, top)),
                    (warm && top == 5).then(|| (2, id_at(&chain, 2))),
                );
            }
        }
    });
}

#[test]
fn unread_listing_or_root_retries_from_the_same_memo() {
    block(async {
        for warm in [false, true] {
            let listings = if warm { above(4) } else { list() };
            for (top, failed) in [
                (8, listings),
                (8, get(8)),
                (8, get(7)),
                (8, get(5)),
                (5, get(5)),
                (8, get(3)),
            ] {
                let (store, chain, mut memo) = prepared(warm, top).await;
                store.fail(failed.clone(), false);
                assert_eq!(resolve(&store, &mut memo).await, Err(Unverified::Unread));
                assert_memo(
                    &memo,
                    warm.then(|| anchored(&chain, 5)),
                    warm.then(|| (3, id_at(&chain, 3))),
                );
                let calls = store.take_calls();
                assert_eq!(calls.last(), Some(&failed));
                assert_eq!(
                    resolve(&store, &mut memo).await,
                    Ok(expected(top, root_at(&chain, top)))
                );
                assert_eq!(
                    reference(&store).await,
                    Ok(expected(top, root_at(&chain, top)))
                );
                assert_memo(
                    &memo,
                    Some(anchored(&chain, top)),
                    warm.then(|| (2, id_at(&chain, 2))),
                );
            }
        }
        // A failed fresh listing after the bounded miss retains no anchor.
        let (store, _, mut memo) = prepared(true, 5).await;
        set(&store, 5, None);
        store.fail(list(), false);
        assert_eq!(resolve(&store, &mut memo).await, Err(Unverified::Unread));
        assert_eq!(store.take_calls(), [above(4), list()]);
        assert_memo(&memo, None, None);
    });
}

#[test]
fn malformed_parent_rule_fails_at_the_first_bad_root() {
    block(async {
        for warm in [false, true] {
            let (store, chain, mut memo) = prepared(warm, 8).await;
            // Both malformed chains have an otherwise valid head. One
            // fails above the anchor, and the other at seq 1.
            for at in [7_u64, 1] {
                let mut bad = if at == 1 {
                    good_root(&volume(), 2, Some(GrainId::of(b"parent")), 7)
                } else {
                    good_root(&volume(), 1, None, 7)
                };
                // Change the encoded seq while keeping the original
                // parent field. Ancestor signatures are not checked.
                let seq_offset =
                    granary_core::encoding::envelope(granary_core::encoding::ObjectType::Root)
                        .len()
                        + 1
                        + volume().as_str().len();
                bad[seq_offset..seq_offset + 8].copy_from_slice(&at.to_be_bytes());
                let mut parent = Some(GrainId::of(&bad));
                set(&store, at, Some(bad));
                for seq in (at + 1)..=8 {
                    let bytes = good_root(&volume(), seq, parent, 7);
                    parent = Some(GrainId::of(&bytes));
                    set(&store, seq, Some(bytes));
                }
                assert_eq!(resolve(&store, &mut memo).await, Err(Unverified::Invalid));
                let mut calls = vec![if warm { above(4) } else { list() }];
                calls.extend((at..=8).rev().map(get));
                assert_eq!(store.take_calls(), calls);
                assert_eq!(reference(&store).await, Err(Unverified::Invalid));
                store.take_calls();
                let retained = warm && at == 7;
                assert_memo(
                    &memo,
                    retained.then(|| anchored(&chain, 5)),
                    retained.then(|| (3, id_at(&chain, 3))),
                );
            }
        }
    });
}

#[test]
fn listing_races_observe_the_listed_head_or_a_fresh_fallback() {
    block(async {
        for race in [
            "delete after",
            "restore between",
            "absent twice",
            "growth after",
        ] {
            let (store, chain, mut memo) = prepared(true, 5).await;
            let (other, _, _) = prepared(false, 5).await;
            for (s, listing) in [(&store, above(4)), (&other, list())] {
                match race {
                    "delete after" => s.after(listing, |s| set(s, 5, None)),
                    "restore between" => {
                        set(s, 5, None);
                        let bytes = root_at(&chain, 5).to_vec();
                        s.after(listing, move |s| set(s, 5, Some(bytes)));
                    }
                    "absent twice" => set(s, 5, None),
                    "growth after" => {
                        let c = good_root(&volume(), 6, Some(id_at(&chain, 5)), 1);
                        s.after(listing, move |s| set(s, 6, Some(c)));
                    }
                    _ => unreachable!(),
                }
            }
            let actual = resolve(&store, &mut memo).await;
            let old = reference(&other).await;
            let at = |seq| Ok(expected(seq, root_at(&chain, seq)));
            let mut calls = vec![above(4)];
            let (answer, oracle, a, cursor) = match race {
                "delete after" => {
                    calls.push(get(5));
                    (
                        Err(Unverified::Invalid),
                        Err(Unverified::Invalid),
                        None,
                        None,
                    )
                }
                "absent twice" => {
                    calls.push(list());
                    calls.extend((1..=4).rev().map(get));
                    (at(4), at(4), Some(anchored(&chain, 4)), None)
                }
                // The second listing is a fresh observation. Selecting a
                // restored head here is part of the contract.
                "restore between" => {
                    calls.push(list());
                    calls.extend((1..=5).rev().map(get));
                    (at(5), at(4), Some(anchored(&chain, 5)), None)
                }
                "growth after" => {
                    calls.extend([get(5), get(3)]);
                    (
                        at(5),
                        at(5),
                        Some(anchored(&chain, 5)),
                        Some((2, id_at(&chain, 2))),
                    )
                }
                _ => unreachable!(),
            };
            assert_eq!((actual, old), (answer, oracle), "{race}");
            assert_eq!(store.take_calls(), calls);
            assert_memo(&memo, a, cursor);
        }
    });
}
