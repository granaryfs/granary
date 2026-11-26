// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! In-memory contract model. Clone/restart preserves committed state; durable
//! crash atomicity requires tests of the authority's persistence layout.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    rec: Receipt,
    root: Vec<u8>,
    grant: Grant,
    touched: u64,
}
#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct Model {
    h: u64,
    rows: BTreeMap<[u8; 16], Row>,
    now: u64,
}
struct Answer {
    token: Option<&'static str>,
    media: Option<&'static str>,
    bytes: Vec<u8>,
}
impl Answer {
    fn reply(&self) -> Reply<'_> {
        Reply {
            status: if self.token.is_some() { 409 } else { 200 },
            media_type: self.media,
            token: self.token,
            body: &self.bytes,
        }
    }
    fn receipt(token: Option<&'static str>, rec: Receipt) -> Self {
        Self {
            token,
            media: Some(MEDIA_RECEIPT),
            bytes: encode_receipt(rec).unwrap(),
        }
    }
    fn grant(grant: Grant) -> Self {
        Self {
            token: None,
            media: Some(MEDIA_GRANT),
            bytes: encode_grant(grant).unwrap(),
        }
    }
    fn refusal(token: &'static str) -> Self {
        Self {
            token: Some(token),
            media: None,
            bytes: vec![],
        }
    }
}
impl Model {
    fn ownership(&mut self, req: Ownership) -> Answer {
        let q = GrainId::of(&encode_ownership(req).unwrap());
        if let Some(row) = self.rows.get(&req.writer)
            && row.grant.request_id == q
            && row.grant.receipt.epoch == row.rec.epoch
            && row.grant.receipt.instance == row.rec.instance
        {
            return Answer::grant(row.grant); // guard: replay-without-reallocation
        }
        let (g, state, root) = match req.mode {
            OwnershipMode::Acquire { observed_cursor } => {
                if let Some(row) = self.rows.get(&req.writer) {
                    return Answer::receipt(Some("intent-changed"), row.rec);
                }
                if observed_cursor != self.h {
                    return Answer::refusal("intent-cursor-changed");
                }
                (0, ReceiptState::Released, vec![])
            }
            OwnershipMode::Takeover {
                expected_epoch,
                generation,
                state,
                ..
            } => {
                let Some(row) = self.rows.get(&req.writer) else {
                    return Answer::refusal("intent-absent");
                };
                if row.rec.epoch != expected_epoch {
                    return Answer::receipt(Some("intent-superseded"), row.rec);
                }
                if row.rec.generation != generation || row.rec.state != state {
                    // guard: conditional-takeover-compare
                    return Answer::receipt(Some("intent-changed"), row.rec);
                }
                (generation, state, row.root.clone())
            }
        };
        let Some(e) = self.h.checked_add(1) else {
            return Answer::refusal("intent-epoch-exhausted");
        };
        if !self.rows.contains_key(&req.writer) && self.rows.len() == MAX_TOTAL_ROWS {
            return Answer::refusal("intent-quota");
        }
        let rec = Receipt {
            writer: req.writer,
            epoch: e,
            instance: req.instance,
            generation: g,
            state,
        };
        let grant = Grant {
            request_id: q,
            receipt: rec,
        };
        // Install the cursor, ownership and replay record in one model transition.
        self.h = e;
        self.rows.insert(
            req.writer,
            Row {
                rec,
                root,
                grant,
                touched: self.now,
            },
        );
        Answer::grant(grant)
    }
    fn register(&mut self, req: RegisterRequest, root: &[u8]) -> Answer {
        let Some(row) = self.rows.get_mut(&req.writer) else {
            return Answer::refusal("intent-absent");
        }; // guard: absent-row-refusal
        if row.rec.epoch != req.epoch || row.rec.instance != req.instance {
            // guard: epoch-match
            return Answer::receipt(Some("intent-superseded"), row.rec);
        }
        if req.generation < row.rec.generation
            || (req.generation == row.rec.generation && row.rec.state == ReceiptState::Released)
        {
            return Answer::receipt(Some("intent-superseded"), row.rec);
        }
        if req.generation == row.rec.generation {
            let token = if row.rec.state
                == (ReceiptState::Live {
                    prepared_root_id: req.root_id,
                }) {
                None
            } else {
                Some("intent-bound")
            };
            return Answer::receipt(token, row.rec);
        }
        row.rec.generation = req.generation;
        row.rec.state = ReceiptState::Live {
            prepared_root_id: req.root_id,
        };
        row.root = root.to_vec();
        row.touched = self.now;
        Answer::receipt(None, row.rec)
    }
    fn release(&mut self, req: ReleaseRequest) -> Answer {
        let Some(row) = self.rows.get_mut(&req.writer) else {
            return Answer::refusal("intent-absent");
        };
        if row.rec.epoch != req.epoch || row.rec.instance != req.instance {
            return Answer::receipt(Some("intent-superseded"), row.rec);
        }
        let g = row.rec.generation.max(req.generation);
        if row.rec.state != ReceiptState::Released || row.rec.generation != g {
            row.touched = self.now;
        }
        row.rec.generation = g;
        row.rec.state = ReceiptState::Released;
        row.root.clear();
        Answer::receipt(None, row.rec)
    }
    fn evict(&mut self, w: [u8; 16]) {
        let row = self.rows.get(&w).unwrap();
        assert_eq!(row.rec.state, ReceiptState::Released);
        assert!(self.now - row.touched >= released_row_retention_secs(0));
        self.rows.remove(&w);
    }
}
fn acquire(w: u8, t: u8, h: u64) -> Ownership {
    Ownership {
        writer: writer(w),
        instance: inst(t),
        mode: OwnershipMode::Acquire { observed_cursor: h },
    }
}
fn transfer(rec: Receipt, t: u8) -> Ownership {
    Ownership {
        writer: rec.writer,
        instance: inst(t),
        mode: OwnershipMode::Takeover {
            expected_epoch: rec.epoch,
            generation: rec.generation,
            state: rec.state,
            recovery_ack: true,
        },
    }
}
fn regreq(rec: Receipt, g: u64, root: &[u8]) -> RegisterRequest {
    RegisterRequest {
        writer: rec.writer,
        epoch: rec.epoch,
        instance: rec.instance,
        generation: g,
        root_id: GrainId::of(root),
    }
}
fn relreq(rec: Receipt, g: u64) -> ReleaseRequest {
    ReleaseRequest {
        writer: rec.writer,
        epoch: rec.epoch,
        instance: rec.instance,
        generation: g,
    }
}
fn judge_ownership(req: &Ownership, reply: &Reply<'_>) -> Verdict<Grant> {
    super::judge_ownership(&encode_ownership(*req).unwrap(), reply).unwrap()
}

fn take(m: &mut Model, req: Ownership) -> Receipt {
    let a = m.ownership(req);
    let Verdict::Accepted(g) = judge_ownership(&req, &a.reply()) else {
        panic!("grant refused")
    };
    g.receipt
}

#[test]
fn delayed_registration_cannot_replace_a_successors_prepared_root() {
    let mut m = Model::default();
    let a = take(&mut m, acquire(1, 1, 0));
    let a10 = regreq(a, 10, &root(10));
    assert!(matches!(
        judge_register(&a10, &m.register(a10, &root(10)).reply()),
        Verdict::Accepted(_)
    ));
    let delayed_a12 = regreq(a, 12, &root(12));
    let selected = m.rows[&a.writer].rec;
    let b = take(&mut m, transfer(selected, 2));
    assert_eq!(m.rows[&a.writer].root, root(10));
    let b11 = regreq(b, 11, &root(11));
    assert!(matches!(
        judge_register(&b11, &m.register(b11, &root(11)).reply()),
        Verdict::Accepted(_)
    ));
    let before = m.clone();
    let answer = m.register(delayed_a12, &root(12));
    assert_eq!(
        judge_register(&delayed_a12, &answer.reply()),
        Verdict::Superseded(m.rows[&a.writer].rec)
    );
    assert_eq!(m, before);
    // Each epoch/token limb independently guards high generations.
    for (epoch, instance, expected) in [
        (
            a.epoch,
            b.instance,
            Verdict::Superseded(m.rows[&a.writer].rec),
        ),
        (
            b.epoch,
            a.instance,
            Verdict::Backend(Disagreement::ReceiptInstance),
        ),
    ] {
        let req = RegisterRequest {
            epoch,
            instance,
            ..delayed_a12
        };
        assert_eq!(
            judge_register(&req, &m.register(req, &root(12)).reply()),
            expected
        );
        assert_eq!(m, before);
    }
    for g in [1, 11, 100] {
        let req = relreq(a, g);
        assert!(matches!(
            judge_release(&req, &m.release(req).reply()),
            Verdict::Superseded(_)
        ));
        assert_eq!(m, before);
    }
}

#[test]
fn conditional_takeover_compares_epoch_generation_state_and_root_without_retarget() {
    let mut m = Model::default();
    let a = take(&mut m, acquire(1, 1, 0));
    let req = regreq(a, 10, &root(10));
    m.register(req, &root(10));
    let selected = m.rows[&a.writer].rec;
    let before = m.clone();
    let pending = transfer(selected, 2);
    let successor = take(&mut m, pending);
    let successor_state = m.clone();
    assert_eq!(
        judge_ownership(
            &transfer(selected, 3),
            &m.ownership(transfer(selected, 3)).reply()
        ),
        Verdict::Superseded(successor)
    );
    assert_eq!(m, successor_state);
    m = before.clone();
    for changed in [
        Receipt {
            generation: 9,
            ..selected
        },
        Receipt {
            state: ReceiptState::Released,
            ..selected
        },
        Receipt {
            state: ReceiptState::Live {
                prepared_root_id: id(99),
            },
            ..selected
        },
    ] {
        let req = transfer(changed, 2);
        let answer = m.ownership(req);
        assert_eq!(
            judge_ownership(&req, &answer.reply()),
            Verdict::Changed(selected)
        );
        assert_eq!(m, before);
    }
    let pending = transfer(selected, 2);
    m.register(regreq(a, 11, &root(11)), &root(11));
    assert!(matches!(
        judge_ownership(&pending, &m.ownership(pending).reply()),
        Verdict::Changed(_)
    ));
    m.release(relreq(a, 11));
    assert!(matches!(
        judge_ownership(&pending, &m.ownership(pending).reply()),
        Verdict::Changed(_)
    ));
    let released = m.rows[&a.writer].rec;
    let b = take(&mut m, transfer(released, 2));
    assert_eq!((b.generation, b.state), (11, ReceiptState::Released));
}

#[test]
fn lost_reply_replays_without_allocation_before_and_after_refresh_release_and_restart() {
    let mut m = Model::default();
    let req = acquire(1, 1, 0);
    let a = take(&mut m, req);
    let committed = m.clone();
    assert_eq!(take(&mut m, req), a);
    assert_eq!(m, committed);
    m.register(regreq(a, 5, &root(5)), &root(5));
    let selected = m.rows[&a.writer].rec;
    let req_b = transfer(selected, 2);
    let b = take(&mut m, req_b);
    let committed = m.clone();
    m = committed.clone(); // restart from committed state only
    assert_eq!(take(&mut m, req_b), b);
    assert_eq!(m, committed);
    m.register(regreq(b, 6, &root(6)), &root(6));
    let before = m.clone();
    assert_eq!(take(&mut m, req_b), b); // historical G=5, not restoration
    assert_eq!(m, before);
    m.release(relreq(b, 6));
    let before = m.clone();
    assert_eq!(take(&mut m, req_b), b);
    assert_eq!(m, before);
    let current = m.rows[&b.writer].rec;
    let c = take(&mut m, transfer(current, 3));
    let final_owner = take(&mut m, transfer(c, 4));
    let before = m.clone();
    assert!(matches!(
        judge_ownership(&req_b, &m.ownership(req_b).reply()),
        Verdict::Superseded(_)
    ));
    assert_eq!(m, before);
    assert!(final_owner.epoch > c.epoch && c.epoch > b.epoch);
}

#[test]
fn absent_rows_never_recreate_and_eviction_keeps_cursor_and_replay_fenced() {
    let mut m = Model::default();
    let req = acquire(1, 1, 0);
    let a = take(&mut m, req);
    m.register(regreq(a, 10, &root(10)), &root(10));
    let takeover = transfer(m.rows[&a.writer].rec, 2);
    let b = take(&mut m, takeover);
    m.release(relreq(b, 12));
    m.now = RETRANSMIT_HORIZON_SECS;
    m.evict(a.writer);
    let before = m.clone();
    let reg = regreq(a, 100, &root(100));
    let rel = relreq(a, 100);
    assert_eq!(
        judge_register(&reg, &m.register(reg, &root(100)).reply()),
        Verdict::Absent
    );
    assert_eq!(
        judge_release(&rel, &m.release(rel).reply()),
        Verdict::Absent
    );
    assert_eq!(
        judge_ownership(&takeover, &m.ownership(takeover).reply()),
        Verdict::Absent
    );
    assert_eq!(
        judge_ownership(&req, &m.ownership(req).reply()),
        Verdict::CursorChanged
    );
    assert_eq!(m, before);
    let h = m.h;
    let fresh = take(&mut m, acquire(1, 3, h));
    assert!(fresh.epoch > b.epoch);
    assert_eq!((fresh.generation, fresh.state), (0, ReceiptState::Released));
}

#[test]
fn own_overtake_is_informational_displaced_epoch_fences_even_with_same_token() {
    let mut m = Model::default();
    let a = take(&mut m, acquire(1, 1, 0));
    let g5 = regreq(a, 5, &root(5));
    m.register(g5, &root(5)); // lost reply; cumulative g6 can proceed
    let g6 = regreq(a, 6, &root(6));
    assert!(matches!(
        judge_register(&g6, &m.register(g6, &root(6)).reply()),
        Verdict::Accepted(_)
    ));
    let rec = m.rows[&a.writer].rec;
    assert_eq!(
        judge_register(&g5, &m.register(g5, &root(5)).reply()),
        Verdict::Overtaken(rec)
    );
    // B uses same T to isolate the epoch limb.
    let b = take(&mut m, transfer(rec, 1));
    assert_eq!(
        judge_register(&g5, &m.register(g5, &root(5)).reply()),
        Verdict::Superseded(b)
    );
}

#[test]
fn exhaustion_fail_closes_only_new_ownership_and_generation_is_never_reset() {
    let mut m = Model {
        h: u64::MAX - 1,
        ..Model::default()
    };
    let a = take(&mut m, acquire(1, 1, u64::MAX - 1));
    assert_eq!(a.epoch, u64::MAX);
    let req = regreq(a, u64::MAX - 1, &root(1));
    assert!(matches!(
        judge_register(&req, &m.register(req, &root(1)).reply()),
        Verdict::Accepted(_)
    ));
    let takeover = transfer(m.rows[&a.writer].rec, 2);
    assert_eq!(
        judge_ownership(&takeover, &m.ownership(takeover).reply()),
        Verdict::EpochExhausted
    );
    assert_eq!(take(&mut m, acquire(1, 1, u64::MAX - 1)), a); // replay before exhaustion
    assert!(encode_register(&a.writer, a.epoch, &a.instance, u64::MAX, &root(1)).is_err());
    let req = relreq(a, u64::MAX - 1);
    assert!(matches!(
        judge_release(&req, &m.release(req).reply()),
        Verdict::Accepted(_)
    ));
}

#[test]
fn refusals_and_replays_never_renew_released_age() {
    let mut v = Model::default();
    let a = take(&mut v, acquire(1, 1, 0));
    v.release(relreq(a, 5));
    v.now = RETRANSMIT_HORIZON_SECS;
    let before = v.clone();
    take(&mut v, acquire(1, 1, 0));
    v.release(relreq(a, 5));
    v.register(regreq(a, 4, &root(4)), &root(4));
    assert_eq!(v, before);
    v.evict(a.writer);
    assert_eq!(v.h, 1);
}

#[test]
fn acquisition_grants_check_exact_request_writer_token_epoch_and_generation() {
    let req = acquire(1, 1, 5);
    let good = Grant {
        request_id: GrainId::of(&encode_ownership(req).unwrap()),
        receipt: Receipt {
            writer: req.writer,
            epoch: 6,
            instance: req.instance,
            generation: 0,
            state: ReceiptState::Released,
        },
    };
    assert_eq!(
        judge_ownership(&req, &Answer::grant(good).reply()),
        Verdict::Accepted(good)
    );
    assert_eq!(
        judge_ownership(
            &req,
            &Answer::grant(Grant {
                request_id: id(99),
                ..good
            })
            .reply()
        ),
        Verdict::Backend(Disagreement::GrantRequestId)
    );
    for (receipt, disagreement) in [
        (
            Receipt {
                epoch: 5,
                ..good.receipt
            },
            Disagreement::ReceiptEpoch,
        ),
        (
            Receipt {
                epoch: 7,
                ..good.receipt
            },
            Disagreement::ReceiptEpoch,
        ),
        (
            Receipt {
                writer: writer(2),
                ..good.receipt
            },
            Disagreement::ReceiptWriter,
        ),
        (
            Receipt {
                instance: inst(2),
                ..good.receipt
            },
            Disagreement::ReceiptInstance,
        ),
        (
            Receipt {
                generation: 1,
                ..good.receipt
            },
            Disagreement::ReceiptGeneration,
        ),
    ] {
        assert_eq!(
            judge_ownership(&req, &Answer::grant(Grant { receipt, ..good }).reply()),
            Verdict::Backend(disagreement)
        );
    }
    let exhausted = acquire(1, 1, u64::MAX);
    let grant = Grant {
        request_id: GrainId::of(&encode_ownership(exhausted).unwrap()),
        ..good
    };
    assert_eq!(
        judge_ownership(&exhausted, &Answer::grant(grant).reply()),
        Verdict::Backend(Disagreement::ReceiptEpoch)
    );
}

#[test]
fn takeover_grants_require_forward_epoch_and_exact_preserved_snapshot() {
    let selected = Receipt {
        writer: writer(1),
        epoch: 5,
        instance: inst(1),
        generation: 3,
        state: ReceiptState::Live {
            prepared_root_id: id(3),
        },
    };
    let req = transfer(selected, 2);
    let good = Grant {
        request_id: GrainId::of(&encode_ownership(req).unwrap()),
        receipt: Receipt {
            epoch: 6,
            instance: inst(2),
            ..selected
        },
    };
    assert_eq!(
        judge_ownership(&req, &Answer::grant(good).reply()),
        Verdict::Accepted(good)
    );
    for (receipt, disagreement) in [
        (
            Receipt {
                epoch: 4,
                ..good.receipt
            },
            Disagreement::ReceiptEpoch,
        ),
        (
            Receipt {
                epoch: 5,
                ..good.receipt
            },
            Disagreement::ReceiptEpoch,
        ),
        (
            Receipt {
                generation: 4,
                ..good.receipt
            },
            Disagreement::ReceiptGeneration,
        ),
        (
            Receipt {
                state: ReceiptState::Released,
                ..good.receipt
            },
            Disagreement::ReceiptState,
        ),
        (
            Receipt {
                state: ReceiptState::Live {
                    prepared_root_id: id(99),
                },
                ..good.receipt
            },
            Disagreement::ReceiptState,
        ),
    ] {
        assert_eq!(
            judge_ownership(&req, &Answer::grant(Grant { receipt, ..good }).reply()),
            Verdict::Backend(disagreement)
        );
    }
}

#[test]
fn ownership_replies_check_media_tokens_and_strict_bodies() {
    let req = acquire(1, 1, 5);
    let answer = Answer::grant(Grant {
        request_id: GrainId::of(&encode_ownership(req).unwrap()),
        receipt: Receipt {
            writer: req.writer,
            epoch: 6,
            instance: req.instance,
            generation: 0,
            state: ReceiptState::Released,
        },
    });
    for media_type in [
        None,
        Some(MEDIA_RECEIPT),
        Some("application/vnd.granary.intent-grant.v1; charset=binary"),
        Some("Application/vnd.granary.intent-grant.v1"),
    ] {
        assert_eq!(
            judge_ownership(
                &req,
                &Reply {
                    media_type,
                    ..answer.reply()
                }
            ),
            Verdict::Backend(Disagreement::WrongMediaType)
        );
    }
    for status in [200, 201, 204] {
        assert_eq!(
            judge_ownership(
                &req,
                &Reply {
                    status,
                    token: Some("intent-changed"),
                    ..answer.reply()
                }
            ),
            Verdict::Backend(Disagreement::TokenOnSuccess)
        );
    }
    assert_eq!(
        judge_ownership(
            &req,
            &Reply {
                body: &[],
                ..answer.reply()
            }
        ),
        Verdict::Backend(Disagreement::Body(Error::ShortInput))
    );
    let receipt = answer.bytes;
    assert_eq!(
        judge_ownership(
            &req,
            &Reply {
                status: 409,
                media_type: Some(MEDIA_RECEIPT),
                token: Some("intent-changed"),
                body: &receipt
            }
        ),
        Verdict::Backend(Disagreement::Body(Error::BadMagic))
    );
    for token in ["intent-changed", "intent-superseded"] {
        let answer = Answer::refusal(token);
        assert_eq!(
            judge_ownership(&req, &answer.reply()),
            Verdict::Backend(Disagreement::WrongMediaType)
        );
        assert_eq!(
            judge_ownership(
                &req,
                &Reply {
                    media_type: Some(MEDIA_RECEIPT),
                    ..answer.reply()
                }
            ),
            Verdict::Backend(Disagreement::Body(Error::ShortInput))
        );
    }
    assert_eq!(
        judge_ownership(&req, &Answer::refusal("intent-bound").reply()),
        Verdict::Backend(Disagreement::TokenMismatch(409))
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "flat table of independent wire offsets and state coupling"
)]
fn ownership_carriers_pin_field_positions_and_state_coupled_zero() {
    let req = acquire(1, 2, HIGH);
    let bytes = encode_ownership(req).unwrap();
    assert_eq!(bytes.len(), ACQUIRE_BYTES);
    assert_eq!(bytes[10], 1);
    assert_eq!(bytes[11..27], req.writer);
    assert_eq!(bytes[27..43], req.instance);
    assert_eq!(bytes[43..51], HIGH.to_be_bytes());
    let selected = Receipt {
        writer: req.writer,
        epoch: HIGH,
        instance: req.instance,
        generation: HIGH,
        state: ReceiptState::Live {
            prepared_root_id: id(9),
        },
    };
    let take = transfer(selected, 3);
    let bytes = encode_ownership(take).unwrap();
    assert_eq!(bytes.len(), OWNERSHIP_MAX_BYTES);
    assert_eq!(bytes[10], 2);
    assert_eq!(bytes[43..51], HIGH.to_be_bytes());
    assert_eq!(bytes[51..59], HIGH.to_be_bytes());
    assert_eq!(bytes[59], 1);
    assert_eq!(bytes[60..93], id(9).to_bytes());
    assert_eq!(bytes[93], 1);
    let grant = Grant {
        request_id: GrainId::of(&bytes),
        receipt: Receipt {
            epoch: HIGH + 1,
            instance: inst(3),
            ..selected
        },
    };
    let bytes = encode_grant(grant).unwrap();
    assert_eq!(bytes.len(), GRANT_MAX_BYTES);
    assert_eq!(bytes[10..43], grant.request_id.to_bytes());
    assert_eq!(bytes[43], 1);
    assert_eq!(bytes[44..60], selected.writer);
    assert_eq!(bytes[60..68], (HIGH + 1).to_be_bytes());
    assert_eq!(bytes[68..84], inst(3));
    assert_eq!(bytes[84..92], HIGH.to_be_bytes());
    assert_eq!(bytes[92..125], id(9).to_bytes());
    let root = root(1);
    let bytes = encode_readback(
        HIGH,
        &[ReadbackRow {
            writer: writer(1),
            epoch: HIGH,
            generation: 2,
            root: &root,
        }],
    )
    .unwrap();
    assert_eq!(bytes[10..18], HIGH.to_be_bytes());
    assert_eq!(bytes[18..20], 1u16.to_be_bytes());
    assert_eq!(bytes[20..36], writer(1));
    assert_eq!(bytes[36..44], HIGH.to_be_bytes());
    assert_eq!(bytes[44..52], 2u64.to_be_bytes());
    assert_eq!(
        bytes[52..56],
        u32::try_from(root.len()).unwrap().to_be_bytes()
    );
    let released = Receipt {
        generation: 0,
        state: ReceiptState::Released,
        ..selected
    };
    assert_eq!(
        decode_receipt(&encode_receipt(released).unwrap()),
        Ok(released)
    );
    assert!(
        encode_release(Release {
            writer: released.writer,
            epoch: released.epoch,
            instance: released.instance,
            generation: 0
        })
        .is_err()
    );
    assert_eq!(
        encode_receipt(Receipt {
            generation: 0,
            ..selected
        }),
        Err(Error::BadSnapshotGeneration)
    );
    assert_eq!(
        encode_grant(Grant {
            receipt: Receipt {
                generation: 0,
                ..selected
            },
            ..grant
        }),
        Err(Error::BadSnapshotGeneration)
    );
    assert_eq!(
        encode_ownership(transfer(
            Receipt {
                generation: 0,
                ..selected
            },
            3
        )),
        Err(Error::BadSnapshotGeneration)
    );
    assert_eq!(
        encode_readback(
            HIGH - 1,
            &[ReadbackRow {
                writer: writer(1),
                epoch: HIGH,
                generation: 2,
                root: &root
            }]
        ),
        Err(Error::EpochPastCursor)
    );
    assert_eq!(
        judge_release(
            &relreq(released, 1),
            &Answer::receipt(
                None,
                Receipt {
                    epoch: HIGH + 1,
                    generation: 1,
                    ..released
                }
            )
            .reply()
        ),
        Verdict::Backend(Disagreement::ReceiptEpoch)
    );
}

#[test]
fn superseded_receipts_require_forward_epochs_and_atomic_tokens() {
    let selected = Receipt {
        writer: writer(1),
        epoch: 5,
        instance: inst(1),
        generation: 3,
        state: ReceiptState::Released,
    };
    let register = regreq(selected, 10, &root(10));
    let release = relreq(selected, 10);
    let takeover = transfer(selected, 2);
    for (rec, disagreement) in [
        (
            Receipt {
                epoch: 4,
                ..selected
            },
            Disagreement::ReceiptEpoch,
        ),
        (
            Receipt {
                epoch: 4,
                instance: inst(2),
                ..selected
            },
            Disagreement::ReceiptEpoch,
        ),
        (
            Receipt {
                instance: inst(2),
                ..selected
            },
            Disagreement::ReceiptInstance,
        ),
    ] {
        let answer = Answer::receipt(Some("intent-superseded"), rec);
        assert_eq!(
            judge_register(&register, &answer.reply()),
            Verdict::Backend(disagreement.clone())
        );
        assert_eq!(
            judge_release(&release, &answer.reply()),
            Verdict::Backend(disagreement)
        );
    }
    for epoch in [4, 5] {
        let answer = Answer::receipt(Some("intent-superseded"), Receipt { epoch, ..selected });
        assert_eq!(
            judge_ownership(&takeover, &answer.reply()),
            Verdict::Backend(Disagreement::ReceiptEpoch)
        );
    }
    for (instance, generation) in [(inst(1), 0), (inst(2), 0), (inst(1), 3), (inst(2), 3)] {
        let rec = Receipt {
            epoch: 6,
            instance,
            generation,
            ..selected
        };
        let answer = Answer::receipt(Some("intent-superseded"), rec);
        assert_eq!(
            judge_register(&register, &answer.reply()),
            Verdict::Superseded(rec)
        );
        assert_eq!(
            judge_release(&release, &answer.reply()),
            Verdict::Superseded(rec)
        );
        assert_eq!(
            judge_ownership(&takeover, &answer.reply()),
            Verdict::Superseded(rec)
        );
    }
}

#[test]
fn ownership_conflicts_validate_each_disagreement_with_receipt_media() {
    let selected = Receipt {
        writer: writer(1),
        epoch: 5,
        instance: inst(1),
        generation: 3,
        state: ReceiptState::Live {
            prepared_root_id: id(3),
        },
    };
    let acquire = acquire(1, 2, 5);
    let takeover = transfer(selected, 2);
    for req in [acquire, takeover] {
        for token in ["intent-changed", "intent-superseded"] {
            let rec = Receipt {
                writer: writer(2),
                ..selected
            };
            assert_eq!(
                judge_ownership(&req, &Answer::receipt(Some(token), rec).reply()),
                Verdict::Backend(Disagreement::ReceiptWriter)
            );
        }
    }
    assert_eq!(
        judge_ownership(
            &acquire,
            &Answer::receipt(Some("intent-changed"), selected).reply()
        ),
        Verdict::Changed(selected)
    );
    assert_eq!(
        judge_ownership(
            &acquire,
            &Answer::receipt(Some("intent-superseded"), selected).reply()
        ),
        Verdict::Backend(Disagreement::TokenMismatch(409))
    );
    assert_eq!(
        judge_ownership(
            &takeover,
            &Answer::receipt(Some("intent-changed"), selected).reply()
        ),
        Verdict::Backend(Disagreement::ReceiptState)
    );
    for epoch in [4, 6] {
        let rec = Receipt { epoch, ..selected };
        assert_eq!(
            judge_ownership(
                &takeover,
                &Answer::receipt(Some("intent-changed"), rec).reply()
            ),
            Verdict::Backend(Disagreement::ReceiptEpoch)
        );
    }
    for rec in [
        Receipt {
            generation: 4,
            ..selected
        },
        Receipt {
            state: ReceiptState::Released,
            ..selected
        },
        Receipt {
            state: ReceiptState::Live {
                prepared_root_id: id(4),
            },
            ..selected
        },
    ] {
        assert_eq!(
            judge_ownership(
                &takeover,
                &Answer::receipt(Some("intent-changed"), rec).reply()
            ),
            Verdict::Changed(rec)
        );
    }
}

#[test]
fn bodyless_ownership_tokens_are_gated_by_operation_and_mode() {
    let selected = Receipt {
        writer: writer(1),
        epoch: 5,
        instance: inst(1),
        generation: 3,
        state: ReceiptState::Released,
    };
    let acquire = acquire(1, 2, 5);
    let takeover = transfer(selected, 2);
    let register = regreq(selected, 4, &root(4));
    let release = relreq(selected, 4);
    for (token, acquire_want, takeover_want, register_want, release_want) in [
        (
            "intent-cursor-changed",
            Verdict::CursorChanged,
            Verdict::Backend(Disagreement::TokenMismatch(409)),
            Verdict::Backend(Disagreement::TokenMismatch(409)),
            Verdict::Backend(Disagreement::TokenMismatch(409)),
        ),
        (
            "intent-quota",
            Verdict::OverQuota,
            Verdict::Backend(Disagreement::TokenMismatch(409)),
            Verdict::OverQuota,
            Verdict::Backend(Disagreement::TokenMismatch(409)),
        ),
        (
            "intent-epoch-exhausted",
            Verdict::EpochExhausted,
            Verdict::EpochExhausted,
            Verdict::Backend(Disagreement::TokenMismatch(409)),
            Verdict::Backend(Disagreement::TokenMismatch(409)),
        ),
        (
            "intent-absent",
            Verdict::Backend(Disagreement::TokenMismatch(409)),
            Verdict::Absent,
            Verdict::Absent,
            Verdict::Absent,
        ),
    ] {
        let answer = Answer::refusal(token);
        assert_eq!(
            judge_ownership(&acquire, &answer.reply()),
            acquire_want,
            "acquire {token}"
        );
        assert_eq!(
            judge_ownership(&takeover, &answer.reply()),
            takeover_want,
            "takeover {token}"
        );
        assert_eq!(
            judge_register(&register, &answer.reply()),
            register_want,
            "register {token}"
        );
        assert_eq!(
            judge_release(&release, &answer.reply()),
            release_want,
            "release {token}"
        );
        assert_eq!(
            judge_readback(&answer.reply(), &vol(VOLUME), accept),
            Verdict::Backend(Disagreement::UnexpectedStatus(409))
        );
        let reply = Reply {
            media_type: Some(MEDIA_RECEIPT),
            ..answer.reply()
        };
        assert_eq!(
            judge_ownership(&takeover, &reply),
            if token == "intent-cursor-changed" || token == "intent-quota" {
                Verdict::Backend(Disagreement::TokenMismatch(409))
            } else {
                Verdict::Backend(Disagreement::UnexpectedIntentBody)
            }
        );
    }
}

#[test]
fn ownership_uses_sent_bytes_and_reports_local_decode_errors_separately() {
    let req = acquire(1, 2, 5);
    let sent = encode_ownership(req).unwrap();
    let good = Grant {
        request_id: GrainId::of(&sent),
        receipt: Receipt {
            writer: req.writer,
            epoch: 6,
            instance: req.instance,
            generation: 0,
            state: ReceiptState::Released,
        },
    };
    assert_eq!(
        super::judge_ownership(&sent, &Answer::grant(good).reply()),
        Ok(Verdict::Accepted(good))
    );
    let other_sent = encode_ownership(acquire(1, 3, 5)).unwrap();
    assert_eq!(
        super::judge_ownership(&other_sent, &Answer::grant(good).reply()),
        Ok(Verdict::Backend(Disagreement::GrantRequestId))
    );
    let mut malformed = sent.clone();
    malformed.push(0);
    for reply in [Answer::grant(good), Answer::refusal("intent-absent")] {
        assert_eq!(
            super::judge_ownership(&malformed, &reply.reply()),
            Err(Error::TrailingBytes)
        );
        assert_eq!(
            super::judge_ownership(&[], &reply.reply()),
            Err(Error::ShortInput)
        );
    }
    let mut takeover = encode_ownership(transfer(good.receipt, 3)).unwrap();
    takeover[43..51].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        super::judge_ownership(&takeover, &Answer::grant(good).reply()),
        Err(Error::EpochZero)
    );
}

#[derive(Default)]
struct Authority {
    principals: BTreeMap<u8, Model>,
}
impl Authority {
    fn principal(&mut self, principal: u8) -> &mut Model {
        self.principals.entry(principal).or_default()
    }
}

#[test]
fn one_volume_keeps_principal_cursors_and_rows_independent() {
    let mut authority = Authority::default();
    let first = take(authority.principal(1), acquire(1, 1, 0));
    // The same W and observed H belong to another authenticated principal.
    let second = take(authority.principal(2), acquire(1, 2, 0));
    assert_eq!((first.epoch, second.epoch), (1, 1));
    let successor = take(authority.principal(2), transfer(second, 3));
    assert_eq!(successor.epoch, 2);
    let another_writer = take(authority.principal(1), acquire(2, 4, 1));
    assert_eq!(another_writer.epoch, 2);
    assert_eq!(authority.principal(1).rows[&first.writer].rec, first);
    assert_eq!(authority.principal(2).rows[&second.writer].rec, successor);
    assert!(
        !authority
            .principal(2)
            .rows
            .contains_key(&another_writer.writer)
    );
    authority.principal(1).release(relreq(first, 1));
    authority.principal(1).now = RETRANSMIT_HORIZON_SECS;
    authority.principal(1).evict(first.writer);
    assert_eq!(authority.principal(1).h, 2);
    assert_eq!(authority.principal(2).h, 2);
    let third_writer = take(authority.principal(2), acquire(3, 5, 2));
    assert_eq!(third_writer.epoch, 3);
    assert_eq!(authority.principal(1).h, 2);
}

#[test]
fn receipt_and_grant_share_snapshot_bytes_and_validation() {
    for (generation, state) in [
        (0, ReceiptState::Released),
        (
            HIGH,
            ReceiptState::Live {
                prepared_root_id: id(3),
            },
        ),
    ] {
        let rec = Receipt {
            writer: writer(1),
            epoch: HIGH,
            instance: inst(2),
            generation,
            state,
        };
        let grant = Grant {
            request_id: id(4),
            receipt: rec,
        };
        let receipt_bytes = encode_receipt(rec).unwrap();
        let grant_bytes = encode_grant(grant).unwrap();
        assert_eq!(&receipt_bytes[10..], &grant_bytes[43..]);
        assert_eq!(decode_receipt(&receipt_bytes), Ok(rec));
        assert_eq!(decode_grant(&grant_bytes), Ok(grant));
        let mut bad_receipt = receipt_bytes;
        let mut bad_grant = grant_bytes;
        bad_receipt[27..35].fill(0);
        bad_grant[60..68].fill(0);
        assert_eq!(decode_receipt(&bad_receipt), Err(Error::EpochZero));
        assert_eq!(decode_grant(&bad_grant), Err(Error::EpochZero));
        assert_eq!(
            encode_receipt(Receipt { epoch: 0, ..rec }),
            Err(Error::EpochZero)
        );
        assert_eq!(
            encode_grant(Grant {
                receipt: Receipt { epoch: 0, ..rec },
                ..grant
            }),
            Err(Error::EpochZero)
        );
    }
}
