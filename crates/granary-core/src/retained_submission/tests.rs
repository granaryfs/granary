// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
fn vector(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/vectors/retained-submission/{name}.bin",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
#[test]
fn retained_golden_vectors_and_all_truncations() {
    let dir = format!(
        "{}/tests/vectors/retained-submission",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "bin") {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        let value = decode(&bytes).unwrap();
        let name = path.file_stem().unwrap().to_str().unwrap();
        if name.starts_with("v2-") {
            let exemptions = match name {
                "v2-exemptions" => 37,
                "v2-exemptions-bound" => 1024,
                _ => 0,
            };
            assert_eq!(value.unavailable_exemptions, exemptions, "{name}");
            assert_eq!(encode(&value).unwrap(), bytes, "{name}");
        } else {
            assert_eq!(value.unavailable_exemptions, 0, "{name}");
            assert_eq!(
                encode(&value).unwrap(),
                vector(&format!("v2-{name}")),
                "{name}"
            );
        }
        assert_eq!(
            GrainId::of(&bytes).to_string(),
            std::fs::read_to_string(path.with_extension("hash"))
                .unwrap()
                .trim()
        );
        for end in 0..bytes.len() {
            assert!(
                decode(&bytes[..end]).is_err(),
                "{} truncated at {end}",
                path.display()
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        count += 1;
    }
    assert_eq!(count, 34);
}
#[test]
fn retained_reject_vectors_name_the_guard() {
    let root = env!("CARGO_MANIFEST_DIR");
    let manifest = std::fs::read_to_string(format!(
        "{root}/tests/vectors/retained-submission/rejects.tsv"
    ))
    .unwrap();
    let mut count = 0;
    for line in manifest.lines() {
        let (name, rule) = line.split_once('\t').unwrap();
        let bytes = std::fs::read(format!(
            "{root}/tests/vectors/retained-submission/reject-{name}"
        ))
        .unwrap();
        let err = decode(&bytes).unwrap_err().to_string();
        assert!(err.contains(rule), "{name}: expected {rule}, got {err}");
        count += 1;
    }
    assert!(count >= 63);
}

#[test]
fn candidate_one_cannot_adopt_a_rebased_manifest() {
    let path = format!(
        "{}/tests/vectors/retained-submission/reject-first-candidate-merged-manifest",
        env!("CARGO_MANIFEST_DIR")
    );
    assert_eq!(
        decode(&std::fs::read(path).unwrap()),
        Err(Error::Invalid("frozen manifest"))
    );
}

/// A validator that kept the old frozen-manifest rule for every candidate would
/// refuse the one document a rebase onto a moved head produces.
#[test]
fn a_later_candidate_after_the_initial_sequence_may_carry_a_merged_manifest() {
    let bytes = vector("rebased-manifest");
    let value = decode(&bytes).unwrap();
    let initial = root::decode_root(&value.frozen.initial_root).unwrap();
    let rebased = value.candidates.last().unwrap();
    let doc = root::decode_root(&rebased.root).unwrap();
    assert_eq!(
        (
            rebased.number >= 2,
            doc.seq > initial.seq,
            doc.manifest_root != initial.manifest_root,
        ),
        (true, true, true),
        "the vector must be a rebased candidate over a merged manifest"
    );
    assert_eq!(validate(&value), Ok(()));
}
#[test]
fn retained_size_cap_precedes_allocation() {
    assert_eq!(decode(&vec![0; MAX_BYTES + 1]), Err(Error::TooLarge));
    assert_eq!(MAX_BYTES, 16 * 1024 * 1024);
    assert_eq!(MAX_CANDIDATES, 128);
}
#[test]
fn evidence_preserves_earlier_uncertainty_and_refuses_replays() {
    let mut e = Evidence::default();
    assert!(e.never_decided());
    assert_eq!(e.start(), Ok(1));
    assert_eq!(e.start(), Ok(2));
    e.answer(2, true, false).unwrap();
    assert!(!e.never_decided());
    let before = e;
    assert!(e.answer(2, true, false).is_err());
    assert!(e.answer(1, true, false).is_err());
    assert!(e.answer(3, true, false).is_err());
    assert_eq!(e, before);
    let mut proved = Evidence::default();
    proved.start().unwrap();
    proved.answer(1, true, false).unwrap();
    assert!(proved.never_decided());
    proved.start().unwrap();
    proved.answer(2, true, true).unwrap();
    assert!(!proved.never_decided());
}
#[test]
fn counter_and_catalogue_exhaustion_never_drop_state() {
    let mut e = Evidence {
        started: u64::MAX,
        ..Evidence::default()
    };
    let before = e;
    assert_eq!(e.start(), Err(Error::Exhausted));
    assert_eq!(e, before);
    let mut value = decode(&vector("capacity")).unwrap();
    let before = value.clone();
    let mut extra = value.candidates[0].clone();
    extra.number = 129;
    extra.role = Role::History;
    assert_eq!(value.insert_candidate(extra), Err(Error::Exhausted));
    assert_eq!(value, before);
}
#[test]
fn completion_without_receipt_requires_status_bootstrap() {
    let value = decode(&vector("complete-chain")).unwrap();
    let Phase::Complete(done) = value.phase else {
        panic!("wrong vector");
    };
    assert_eq!(done.epoch_knowledge(), None);
    let value = decode(&vector("complete-receipt")).unwrap();
    let Phase::Complete(done) = value.phase else {
        panic!("wrong vector");
    };
    assert_eq!(done.epoch_knowledge(), Some(Epoch::from_bytes([0x11; 16])));
}
#[test]
fn encoder_refuses_invalid_values() {
    let base = decode(&vector("ready")).unwrap();
    let mut variants = Vec::new();
    let mut v = base.clone();
    v.generation = 0;
    variants.push(v);
    let mut v = base.clone();
    v.unavailable_exemptions = 1025;
    assert_eq!(encode(&v), Err(Error::Invalid("unavailable exemptions")));
    let mut v = base.clone();
    v.scope.authority_base.clear();
    variants.push(v);
    let mut v = base.clone();
    v.scope.credential_context.clear();
    variants.push(v);
    let mut v = base.clone();
    v.scope.pins.reverse();
    variants.push(v);
    let mut v = base.clone();
    v.scope.pins = vec![[0; 32]; 9];
    variants.push(v);
    let mut v = base.clone();
    v.frozen.min_prefix_bits = 13;
    variants.push(v);
    let mut v = base.clone();
    v.frozen.initial_root = vec![0; 65537];
    variants.push(v);
    let mut v = base.clone();
    v.candidates[0].id = GrainId::of(b"other");
    variants.push(v);
    let mut v = base.clone();
    v.candidates[0].evidence.last_answered_attempt = 2;
    variants.push(v);
    let mut v = base.clone();
    v.current = None;
    variants.push(v);
    let mut v = base.clone();
    v.candidates = vec![base.candidates[0].clone(); 129];
    variants.push(v);
    for v in variants {
        assert!(encode(&v).is_err());
    }
}
#[test]
fn scope_digest_is_exact_and_domain_separated() {
    let s = decode(&vector("ready")).unwrap().scope;
    let mut changed = s.clone();
    changed.authority_base.push(b'/');
    assert_ne!(s.digest().unwrap(), changed.digest().unwrap());
    changed = s.clone();
    changed.credential_context.push(b'2');
    assert_ne!(s.digest().unwrap(), changed.digest().unwrap());
    changed = s.clone();
    changed.pins.clear();
    assert_eq!(s.digest().unwrap(), changed.digest().unwrap());
    let mut bytes = Vec::new();
    put16(&mut bytes, &s.authority_base).unwrap();
    put8(&mut bytes, &s.credential_context).unwrap();
    assert_ne!(
        s.digest().unwrap(),
        blake3::hash(&bytes).to_hex().to_string()
    );
}

#[test]
fn independent_golden_fields_have_the_documented_meaning() {
    let s = decode(&vector("ready")).unwrap();
    assert_eq!(s.generation, 1);
    assert_eq!(
        s.publication_id,
        core::array::from_fn(|i| u8::try_from(i).unwrap())
    );
    assert_eq!(s.scope.authority_base, b"https://example.test/");
    assert_eq!(s.scope.credential_context, b"operator");
    assert_eq!(s.scope.pins, vec![[1; 32], [2; 32]]);
    assert_eq!(s.volume.as_str(), "vol");
    assert_eq!(s.frozen.writer_identity, [0x33; 16]);
    assert_eq!(s.frozen.min_prefix_bits, 0);
    assert_eq!(
        s.current,
        Some(RequestIdentity {
            epoch: [0x11; 16],
            operation: [0x22; 16]
        })
    );
    let c = &s.candidates[0];
    assert_eq!(c.number, 1);
    assert_eq!(c.role, Role::Active);
    assert_eq!(Some(c.request), s.current);
    assert_eq!(c.seq, 1);
    assert_eq!(c.id, GrainId::of(&s.frozen.initial_root));
    assert_eq!(c.root, s.frozen.initial_root);
    assert_eq!(
        c.evidence,
        Evidence {
            started: 1,
            ..Evidence::default()
        }
    );
    assert_eq!(s.phase, Phase::Ready);
    assert!(s.last_response.is_none());
    let path = format!(
        "{}/tests/vectors/retained-submission/scope.hash",
        env!("CARGO_MANIFEST_DIR")
    );
    assert_eq!(
        s.scope.digest().unwrap(),
        std::fs::read_to_string(path).unwrap().trim()
    );
}
#[test]
fn independent_golden_continuations_have_the_documented_meaning() {
    let s = decode(&vector("ready")).unwrap();
    let c = &s.candidates[0];
    assert_eq!(
        decode(&vector("awaiting")).unwrap().phase,
        Phase::AwaitingAnswer {
            candidate: 1,
            attempt: 1
        }
    );
    assert_eq!(decode(&vector("rebase")).unwrap().phase, Phase::Rebase);
    assert_eq!(
        decode(&vector("epoch-recovery")).unwrap().phase,
        Phase::EpochRecovery { epoch: [0x90; 16] }
    );
    assert_eq!(
        decode(&vector("probe-started")).unwrap().phase,
        Phase::ProbeStarted(Probe {
            cycle: 1,
            seq: 1,
            reason: ProbeReason::Started
        })
    );
    assert_eq!(
        decode(&vector("unresolved")).unwrap().phase,
        Phase::Unresolved(Probe {
            cycle: 1,
            seq: 1,
            reason: ProbeReason::Transport
        })
    );
    let Phase::Complete(done) = decode(&vector("complete-receipt")).unwrap().phase else {
        panic!("phase");
    };
    assert_eq!(
        done.receipt.unwrap(),
        Receipt {
            position: Position {
                epoch: Epoch::from_bytes([0x11; 16]),
                entry_seq: 7
            },
            root_seq: 1,
            stored_id: c.id
        }
    );
    let response = decode(&vector("response-answer"))
        .unwrap()
        .last_response
        .unwrap();
    assert_eq!(response.status, 202);
    assert!(response.token.is_empty());
    assert_eq!(response.candidate, 1);
    assert_eq!(response.attempt, 1);
    assert!(matches!(
        authority_answer::decode(&response.answer).unwrap(),
        authority_answer::PublishAnswer::Accepted { .. }
    ));
    let boundary = decode(&vector("scope-bounds")).unwrap();
    assert_eq!(boundary.scope.authority_base.len(), 8192);
    assert_eq!(boundary.scope.pins.len(), 8);
    assert_eq!(boundary.scope.credential_context.len(), 255);
    assert_eq!(boundary.frozen.min_prefix_bits, 12);
}
#[test]
fn response_value_bounds_apply_before_encoding() {
    let mut s = decode(&vector("response")).unwrap();
    s.last_response.as_mut().unwrap().answer = vec![0; 154];
    assert_eq!(validate(&s), Err(Error::Invalid("answer length")));
}

#[test]
fn completion_receipt_matches_any_epoch_with_identical_root() {
    let mut s = decode(&vector("complete-receipt")).unwrap();
    let mut old = s.candidates[0].clone();
    old.role = Role::Retired;
    old.request.epoch = [0x40; 16];
    old.request.operation = [0x60; 16];
    s.candidates[0].number = 2;
    s.candidates.insert(0, old);
    let bytes = encode(&s).unwrap();
    assert_eq!(decode(&bytes).unwrap(), s);
    let Phase::Complete(done) = &mut s.phase else {
        unreachable!()
    };
    done.receipt.as_mut().unwrap().position.epoch = Epoch::from_bytes([0x90; 16]);
    assert_eq!(encode(&s), Err(Error::Invalid("completion receipt")));
}

#[test]
fn frozen_initial_root_uses_candidate_sequence_range() {
    let value = decode(&vector("initial-last-candidate")).unwrap();
    assert_eq!(
        root::decode_root(&value.frozen.initial_root).unwrap().seq,
        authority_answer::LAST_CANDIDATE_SEQ
    );
    assert_eq!(encode(&value).unwrap(), vector("v2-initial-last-candidate"));
    for name in ["zero", "reserved", "maximum"] {
        let bytes = std::fs::read(format!(
            "{}/tests/vectors/retained-submission/reject-initial-seq-{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        assert!(decode(&bytes).unwrap_err().to_string().contains("root seq"));
    }
    for seq in [u64::MAX - 1, u64::MAX] {
        let mut invalid = value.clone();
        let mut root = root::decode_root(&value.frozen.initial_root).unwrap();
        root.seq = seq;
        invalid.frozen.initial_root = root::encode_root(&root).unwrap();
        assert_eq!(encode(&invalid), Err(Error::Invalid("root seq")));
    }
}
