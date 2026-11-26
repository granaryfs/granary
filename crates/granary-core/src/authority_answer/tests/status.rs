// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use crate::authority_answer::*;
use crate::hash::HashAlgorithm;

fn id() -> GrainId {
    GrainId::from_parts(HashAlgorithm::Blake3, [0x22; 32])
}
fn epoch_value() -> Epoch {
    Epoch::from_bytes(std::array::from_fn(|n| u8::try_from(n).unwrap()))
}

/// Independently transcribe the documented layout, including literal magic,
/// version, presence and algorithm bytes. Never call either encoder here.
#[expect(
    clippy::option_option,
    reason = "the independent fixture distinguishes unverified, verified empty and verified root"
)]
fn golden(seq: Option<Option<u64>>, opened: bool) -> Vec<u8> {
    let mut bytes = b"GRNVSTAT\x00\x01".to_vec();
    bytes.extend(0u8..16);
    match seq {
        None => bytes.push(0),
        Some(root) => {
            bytes.push(1);
            if let Some(n) = root {
                bytes.push(1);
                bytes.extend(n.to_be_bytes());
                bytes.push(1);
                bytes.extend([0x22; 32]);
            } else {
                bytes.push(0);
            }
            match root {
                Some(n) if n >= u64::MAX - 2 => bytes.push(0),
                _ => {
                    bytes.push(1);
                    bytes.extend(root.map_or(1, |n| n + 1).to_be_bytes());
                }
            }
        }
    }
    bytes.push(u8::from(opened));
    if opened {
        bytes.extend(if seq == Some(Some(5)) { 7u64 } else { u64::MAX }.to_be_bytes());
        bytes.push(1);
        bytes.extend([0x22; 32]);
    }
    bytes
}

#[test]
fn volume_status_vectors() {
    let mut lengths = Vec::new();
    for (name, seq) in [
        ("unknown", None),
        ("empty", Some(None)),
        ("head", Some(Some(5))),
        ("last-extendable", Some(Some(u64::MAX - 3))),
        ("last-candidate", Some(Some(u64::MAX - 2))),
        ("last-root", Some(Some(u64::MAX - 1))),
    ] {
        for opened in [false, true] {
            let suffix = if opened { "open" } else { "closed" };
            let base = format!(
                "{}/tests/vectors/volume-status/{name}-{suffix}",
                env!("CARGO_MANIFEST_DIR")
            );
            let bytes = golden(seq, opened);
            assert_eq!(bytes, std::fs::read(format!("{base}.bin")).unwrap());
            assert_eq!(
                GrainId::of(&bytes).to_string(),
                std::fs::read_to_string(format!("{base}.hash"))
                    .unwrap()
                    .trim()
            );
            let value = VolumeStatus {
                epoch: epoch_value(),
                head: seq.map(|s| Head::new(s.map(|n| (n, id())))),
                open: opened.then_some(OpenPosition {
                    entry_seq: if seq == Some(Some(5)) { 7 } else { u64::MAX },
                    candidate_id: id(),
                }),
            };
            assert_eq!(decode_status(&bytes), Ok(value));
            assert_eq!(encode_status(value).unwrap(), bytes);
            lengths.push(bytes.len());
            for n in 0..bytes.len() {
                assert!(
                    decode_status(&bytes[..n]).is_err(),
                    "{name}-{suffix} truncated at {n}"
                );
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert_eq!(
                decode_status(&trailing),
                Err(Error::Fields(DecodeError::TrailingBytes { remaining: 1 }))
            );
        }
    }
    assert_eq!(lengths.iter().min(), Some(&28));
    assert_eq!(lengths.iter().max(), Some(&120));
    assert_eq!(STATUS_V1_MAX, 120);
}

#[test]
fn volume_status_reject_vectors() {
    let path = format!(
        "{}/tests/vectors/authority-answer-rejects",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut count = 0;
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(reason) = name.strip_prefix("status-reject-") else {
            continue;
        };
        let error = decode_status(&std::fs::read(entry.path()).unwrap()).unwrap_err();
        let expected = match reason {
            "magic" | "publish-magic" => Error::BadMagic,
            "truncated" => Error::Fields(DecodeError::Truncated),
            "trailing" | "oversize" => Error::Fields(DecodeError::TrailingBytes { remaining: 1 }),
            r if r.starts_with("version-") => {
                Error::UnknownVersion(r.trim_start_matches("version-").parse().unwrap())
            }
            r => Error::Fields(DecodeError::Invalid {
                what: if r.starts_with("presence-") {
                    "presence"
                } else if r.starts_with("id-") {
                    "grain id"
                } else if r.starts_with("head-seq-") {
                    "root sequence"
                } else if r == "entry-zero" {
                    "entry sequence"
                } else {
                    "head successor"
                },
            }),
        };
        assert_eq!(error, expected, "{name}");
        count += 1;
    }
    assert_eq!(count, 25);
    assert_eq!(decode(&golden(None, false)), Err(Error::BadMagic));
}

#[test]
fn volume_status_encoder_refuses_invalid_values() {
    let base = VolumeStatus {
        epoch: epoch_value(),
        head: None,
        open: None,
    };
    assert!(
        encode_status(VolumeStatus {
            open: Some(OpenPosition {
                entry_seq: 0,
                candidate_id: id()
            }),
            ..base
        })
        .is_err()
    );
    for h in [
        Head::new(Some((0, id()))),
        Head::new(Some((u64::MAX, id()))),
        Head {
            root: None,
            next_seq: None,
        },
        Head {
            root: None,
            next_seq: Some(2),
        },
        Head {
            root: Some((5, id())),
            next_seq: None,
        },
        Head {
            root: Some((5, id())),
            next_seq: Some(7),
        },
        Head {
            root: Some((u64::MAX - 2, id())),
            next_seq: Some(u64::MAX - 1),
        },
    ] {
        assert!(
            encode_status(VolumeStatus {
                head: Some(h),
                ..base
            })
            .is_err(),
            "{h:?}"
        );
    }
}
