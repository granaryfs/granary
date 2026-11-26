// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::hash::HashAlgorithm;

mod status;

fn sample() -> (Position, Receipt, GrainId) {
    let id = GrainId::from_parts(HashAlgorithm::Blake3, [0x22; 32]);
    let position = Position {
        epoch: Epoch::from_bytes([0x11; 16]),
        entry_seq: 7,
    };
    (
        position,
        Receipt {
            position,
            root_seq: 3,
            stored_id: id,
        },
        id,
    )
}

#[test]
fn publish_answer_codec_vectors() {
    let (position, receipt, id) = sample();
    let h = Head::new(Some((3, id)));
    let heads = [
        ("none", None),
        ("empty", Some(Head::new(None))),
        ("head", Some(h)),
        ("last-candidate", Some(Head::new(Some((u64::MAX - 2, id))))),
        ("last-root", Some(Head::new(Some((u64::MAX - 1, id))))),
    ];
    let mut values = Vec::new();
    for (label, head) in heads {
        values.push((
            format!("landed-{label}"),
            PublishAnswer::Landed { receipt, head },
        ));
        values.push((
            format!("lost-{label}"),
            PublishAnswer::Lost {
                position,
                candidate_id: id,
                occupant: GrainId::from_parts(HashAlgorithm::Blake3, [0x33; 32]),
                head,
            },
        ));
        values.push((
            format!("epoch-{label}"),
            PublishAnswer::EpochMismatch {
                epoch: position.epoch,
                head,
            },
        ));
    }
    values.extend([
        (
            "accepted".into(),
            PublishAnswer::Accepted {
                position,
                candidate_id: id,
            },
        ),
        (
            "open".into(),
            PublishAnswer::Open {
                position,
                candidate_id: id,
            },
        ),
        ("stale".into(), PublishAnswer::StaleBase(h)),
        (
            "bound-open".into(),
            PublishAnswer::OperationBound(Bound::Open {
                position,
                candidate_id: id,
            }),
        ),
        (
            "bound-landed".into(),
            PublishAnswer::OperationBound(Bound::Landed(receipt)),
        ),
        (
            "not-decided".into(),
            PublishAnswer::NotDecided {
                position,
                candidate_id: id,
            },
        ),
        ("damaged".into(), PublishAnswer::VolumeDamaged),
    ]);
    for (name, root) in [
        ("stale-empty", None),
        ("stale-last-extendable", Some((u64::MAX - 3, id))),
        ("stale-last-candidate", Some((u64::MAX - 2, id))),
        ("stale-last-root", Some((u64::MAX - 1, id))),
    ] {
        values.push((name.into(), PublishAnswer::StaleBase(Head::new(root))));
    }
    let mut largest = 0;
    for (name, value) in values {
        let base = format!(
            "{}/tests/vectors/authority-answer/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(format!("{base}.bin")).unwrap();
        let hash = std::fs::read_to_string(format!("{base}.hash")).unwrap();
        assert_eq!(encode(value).unwrap(), bytes, "{name}");
        assert_eq!(decode(&bytes).unwrap(), value, "{name}");
        assert_eq!(GrainId::of(&bytes).to_string(), hash.trim(), "{name}");
        largest = largest.max(bytes.len());
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_err(), "truncated {name} at {n}");
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(
            decode(&trailing).is_err(),
            "trailing byte accepted for {name}"
        );
    }
    assert_eq!(largest, MAX_BYTES);
}

#[test]
fn publish_answer_reject_vectors() {
    let path = format!(
        "{}/tests/vectors/authority-answer-rejects",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut rejects = 0;
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("reject-") {
            let name = entry.file_name().to_string_lossy().into_owned();
            let result = decode(&std::fs::read(entry.path()).unwrap());
            let error = result.unwrap_err();
            let reason = name.trim_start_matches("reject-");
            match reason {
                "magic" | "status-magic" => assert_eq!(error, Error::BadMagic),
                "trailing" | "oversize" => assert_eq!(
                    error,
                    Error::Fields(DecodeError::TrailingBytes { remaining: 1 })
                ),
                "truncated" => assert_eq!(error, Error::Fields(DecodeError::Truncated)),
                _ if reason.starts_with("version-") => assert_eq!(
                    error,
                    Error::UnknownVersion(reason.trim_start_matches("version-").parse().unwrap())
                ),
                _ if reason.starts_with("kind-") => assert_eq!(
                    error,
                    Error::UnknownKind(reason.trim_start_matches("kind-").parse().unwrap())
                ),
                _ => {
                    let what = if reason.starts_with("bound-") {
                        "bound kind"
                    } else if reason.contains("presence") {
                        "presence"
                    } else if reason.starts_with("id-") || reason == "hash-tag" {
                        "grain id"
                    } else if reason == "entry-zero" {
                        "entry sequence"
                    } else if reason.starts_with("receipt-seq-") || reason.starts_with("head-seq-")
                    {
                        "root sequence"
                    } else if reason == "lost-own-id" {
                        "lost occupant"
                    } else {
                        "head successor"
                    };
                    assert_eq!(
                        error,
                        Error::Fields(DecodeError::Invalid { what }),
                        "{name}"
                    );
                }
            }
            rejects += 1;
        }
    }
    assert!(rejects >= 20);
}

#[test]
fn encoder_refuses_invalid_values() {
    let (p, r, id) = sample();
    for n in [0, u64::MAX] {
        assert!(
            encode(PublishAnswer::Landed {
                receipt: Receipt { root_seq: n, ..r },
                head: None
            })
            .is_err()
        );
        assert!(encode(PublishAnswer::StaleBase(Head::new(Some((n, id))))).is_err());
    }
    assert!(
        encode(PublishAnswer::Accepted {
            position: Position { entry_seq: 0, ..p },
            candidate_id: id
        })
        .is_err()
    );
    assert!(
        encode(PublishAnswer::StaleBase(Head {
            root: None,
            next_seq: None
        }))
        .is_err()
    );
    assert!(
        encode(PublishAnswer::StaleBase(Head {
            root: Some((1, id)),
            next_seq: Some(3)
        }))
        .is_err()
    );
}

/// The next seq is 1 over an empty chain, `head + 1` up to
/// `u64::MAX - 2`, and none past it: never `u64::MAX` or
/// `u64::MAX - 1`, which rule 2 refuses.
#[test]
fn the_next_seq_never_names_a_seq_rule_2_refuses() {
    assert_eq!(next_seq(None), Some(1));
    assert_eq!(next_seq(Some(1)), Some(2));
    assert_eq!(next_seq(Some(u64::MAX - 3)), Some(u64::MAX - 2));
    assert_eq!(next_seq(Some(u64::MAX - 2)), None);
    assert_eq!(next_seq(Some(u64::MAX - 1)), None);
    assert_eq!(next_seq(Some(u64::MAX)), None);
    assert_eq!(LAST_CANDIDATE_SEQ, u64::MAX - 2);
}
