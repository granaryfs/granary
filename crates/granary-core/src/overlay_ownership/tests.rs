// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn fixture() -> Carrier {
    crate::testkit::ownership_fixture()
}

#[test]
fn canonical_roundtrip_and_every_cut_refuses() {
    let value = fixture();
    let bytes = encode(&value).unwrap();
    assert_eq!(decode(&bytes).unwrap(), value);
    assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(), bytes);
    let mut cases = 0;
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end]).is_err(), "cut {end}");
        cases += 1;
    }
    assert!(cases > 0);
    let mut flipped = bytes;
    flipped[0] ^= 1;
    assert_eq!(
        decode(&flipped).unwrap_err().to_string(),
        "ownership refused: check"
    );
}

#[test]
fn relations_have_named_refusals_and_valid_controls() {
    let mut c = fixture();
    let mut cases = 0;
    for (mutant, reason) in [
        ("water", "high water"),
        ("phase", "owned evidence"),
        ("fence", "fence missing"),
        ("scope", "scope"),
    ] {
        assert!(encode(&c).is_ok());
        let saved = c.clone();
        match mutant {
            "water" => c.sent = 1,
            "phase" => c.phase = Phase::Serving,
            "fence" => c.phase = Phase::Fenced,
            "scope" => c.scope.authority_base.clear(),
            _ => unreachable!(),
        }
        assert_eq!(encode(&c), Err(Error(reason)));
        cases += 1;
        c = saved;
    }
    assert_eq!(cases, 4);
    assert_eq!(decode(&vec![0; MAX_BYTES + 1]), Err(Error("file cap")));
}

#[test]
fn transition_relation_refuses_unacknowledged_fence_escape() {
    assert!(Phase::Unowned.transition(Phase::Handshake, false).is_ok());
    assert!(Phase::OwnedStart.transition(Phase::Serving, false).is_ok());
    assert_eq!(
        Phase::Unowned.transition(Phase::Serving, false),
        Err(Error("phase transition"))
    );
    assert_eq!(
        Phase::Fenced.transition(Phase::Handshake, false),
        Err(Error("phase transition"))
    );
    assert!(Phase::Fenced.transition(Phase::Handshake, true).is_ok());
}

#[test]
fn unowned_can_record_a_fence_without_acknowledgement() {
    let transition = Phase::Unowned.transition(Phase::Fenced, false);
    assert_eq!(transition, Ok(()));
}

#[test]
fn fenced_unconsented_takeover_requires_dispatched_unanswered_terminal_evidence() {
    let mut valid = fixture();
    let selected = Receipt {
        writer: valid.writer,
        epoch: 1,
        instance: [3; 16],
        generation: 0,
        state: ReceiptState::Released,
    };
    valid.selected = intent::encode_receipt(selected).unwrap();
    valid.phase = Phase::Fenced;
    valid.fence = 1;
    valid.fence_evidence = intent::encode_receipt(Receipt {
        epoch: 2,
        instance: [4; 16],
        ..selected
    })
    .unwrap();
    valid.pending.push(Pending {
        operation: Operation::Ownership,
        body: intent::encode_ownership(intent::Ownership {
            writer: valid.writer,
            instance: valid.instance,
            mode: intent::OwnershipMode::Takeover {
                expected_epoch: selected.epoch,
                generation: selected.generation,
                state: selected.state,
                recovery_ack: false,
            },
        })
        .unwrap(),
        context: vec![],
        first: 1,
        expires: 3,
        eligible: 2,
        attempts: 1,
        terminal: true,
        answered: false,
        answer: vec![],
    });
    let bytes = encode(&valid).unwrap();
    assert_eq!(decode(&bytes).unwrap(), valid);

    let mut cases = 0;
    for claim in ["terminal", "unanswered", "dispatched", "fenced phase"] {
        let mut bad = valid.clone();
        match claim {
            "terminal" => bad.pending[0].terminal = false,
            "unanswered" => bad.pending[0].answered = true,
            "dispatched" => bad.pending[0].attempts = 0,
            "fenced phase" => bad.phase = Phase::Handshake,
            _ => unreachable!(),
        }
        assert_eq!(
            encode(&bad)
                .map(|bytes| bytes.len())
                .map_err(|error| error.to_string()),
            Err("ownership refused: fenced takeover consent".to_owned()),
            "{claim}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn bounded_layout_arithmetic_is_exact() {
    assert_eq!(MAX_LAYOUT_BYTES, 9_107_256);
    assert_eq!(REPLACEMENT_RESERVE, 33_554_432);
}

#[test]
fn arbitrary_bytes_are_total_and_canonical() {
    for seed in 0..128 {
        crate::testkit::overlay_ownership_decode_probe(&crate::testkit::fill(
            seed,
            usize::try_from(seed).unwrap() * 31,
        ));
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one bounded fixture fills scope, roots, consent and all reserved request slots together"
)]
fn maximum_fixture() -> Carrier {
    use crate::root::{RootDoc, RootSig, Timestamp};
    let mut c = fixture();
    c.scope.authority_base = vec![b'a'; 8192];
    c.scope.credential_context = vec![b'c'; 255];
    c.scope.pins = (0..8).map(|n| [n; 32]).collect();
    c.volume = VolumeName::from_bytes(&[b'v'; 63]).unwrap();
    let root = crate::root::encode_root(&RootDoc {
        volume: c.volume.clone(),
        seq: 2,
        parent: Some(GrainId::of(b"parent")),
        writer_uuid: c.writer,
        epoch: 1,
        timestamp: Timestamp { secs: 1, nanos: 0 },
        chunker_spec: "x".repeat(255),
        manifest_root: GrainId::of(b"tree"),
        binmap_index: GrainId::of(b"bins"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![
            RootSig {
                key_id: [3; 32],
                sig: [5; 64],
            },
            RootSig {
                key_id: [4; 32],
                sig: [6; 64],
            },
        ],
    })
    .unwrap();
    assert_eq!(root.len(), 707);
    let selected = Receipt {
        writer: c.writer,
        epoch: 1,
        instance: [0; 16],
        generation: 1,
        state: ReceiptState::Live {
            prepared_root_id: GrainId::of(&root),
        },
    };
    let own = intent::Ownership {
        writer: c.writer,
        instance: c.instance,
        mode: intent::OwnershipMode::Takeover {
            expected_epoch: 1,
            generation: 1,
            state: selected.state,
            recovery_ack: true,
        },
    };
    c.handshake = intent::encode_ownership(own).unwrap();
    let granted = Receipt {
        epoch: 2,
        instance: c.instance,
        ..selected
    };
    c.grant = intent::encode_grant(intent::Grant {
        request_id: GrainId::of(&c.handshake),
        receipt: granted,
    })
    .unwrap();
    let current = Receipt {
        generation: 128,
        ..granted
    };
    c.current = intent::encode_receipt(current).unwrap();
    c.root = root.clone();
    c.selected = intent::encode_receipt(selected).unwrap();
    c.selected_root = root.clone();
    c.selected_cursor = 1;
    c.consent = recovery_consent(&c, &c.handshake).unwrap();
    c.phase = Phase::Fenced;
    c.fence = 1;
    c.fence_evidence = intent::encode_receipt(Receipt {
        epoch: 3,
        instance: [99; 16],
        ..current
    })
    .unwrap();
    c.allocated = 128;
    c.sent = 128;
    let pending = |operation, body, answer| Pending {
        operation,
        body,
        context: vec![0; CONTEXT_MAX],
        first: 0,
        expires: 86_400_000,
        eligible: 0,
        attempts: 1,
        terminal: true,
        answered: true,
        answer,
    };
    c.pending.push(pending(
        Operation::Ownership,
        c.handshake.clone(),
        intent::encode_receipt(granted).unwrap(),
    ));
    for g in 1..=128 {
        c.pending.push(pending(
            Operation::Register,
            intent::encode_register(&c.writer, 2, &c.instance, g, &root).unwrap(),
            c.current.clone(),
        ));
    }
    c.pending.push(pending(
        Operation::Release,
        intent::encode_release(intent::Release {
            writer: c.writer,
            epoch: 2,
            instance: c.instance,
            generation: 128,
        })
        .unwrap(),
        intent::encode_receipt(Receipt {
            state: ReceiptState::Released,
            ..current
        })
        .unwrap(),
    ));
    c
}

#[test]
fn maximum_supported_fixture_and_each_changed_relation_have_paired_controls() {
    let valid = maximum_fixture();
    let bytes = encode(&valid).unwrap();
    assert_eq!(
        (bytes.len(), valid.consent.len(), valid.pending.len()),
        (667_776, 8_997, 130)
    );
    assert_eq!(decode(&bytes).unwrap(), valid);
    let mut cases = 0;
    for (claim, reason) in [
        ("grant", "grant binding"),
        ("root", "snapshot root id"),
        ("water", "high water"),
        ("context", "pending context"),
        ("answer", "answer lifecycle"),
        ("order", "pending order"),
        ("count", "pending count"),
        ("fence", "fence displacement"),
        ("consent", "takeover consent"),
        ("selection", "takeover selection"),
    ] {
        assert!(encode(&valid).is_ok());
        let mut bad = valid.clone();
        match claim {
            "grant" => bad.grant[10] ^= 1,
            "root" => bad.root[0] ^= 1,
            "water" => bad.sent = 129,
            "context" => bad.pending[1].context.push(0),
            "answer" => {
                bad.pending[1].answered = true;
                bad.pending[1].terminal = false;
            }
            "order" => bad.pending.swap(1, 2),
            "count" => bad.pending.push(bad.pending[1].clone()),
            "fence" => {
                bad.fence_evidence = intent::encode_receipt(Receipt {
                    epoch: 2,
                    instance: bad.instance,
                    writer: bad.writer,
                    generation: 128,
                    state: ReceiptState::Released,
                })
                .unwrap();
            }
            "consent" => bad.consent[0] ^= 1,
            "selection" => {
                let p = &mut bad.pending[0];
                let mut req = intent::decode_ownership(&p.body).unwrap();
                if let intent::OwnershipMode::Takeover {
                    ref mut generation, ..
                } = req.mode
                {
                    *generation = 2;
                }
                p.body = intent::encode_ownership(req).unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            encode(&bad).unwrap_err().to_string(),
            format!("ownership refused: {reason}"),
            "claim {claim}"
        );
        cases += 1;
    }
    assert_eq!(cases, 10);
}
