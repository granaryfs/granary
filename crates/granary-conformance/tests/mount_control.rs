// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Canonical wire properties without generator dependencies in core.

use granary_core::{hash::GrainId, mount_control::*};
use proptest::prelude::*;

fn messages(instance: Instance, key: MountKey, seq: u64, elapsed_ms: u64) -> Vec<Message> {
    let mut messages = vec![
        Message::Hello(Hello {
            instance,
            key,
            mode: Mode::ReadOnly,
        }),
        Message::Hello(Hello {
            instance,
            key,
            mode: Mode::Writable {
                bound_seconds: 30,
                store: b"store".to_vec(),
            },
        }),
        Message::Stop { instance, key },
        Message::Accepted(instance),
        Message::Final {
            instance,
            result: ResultKind::RuntimeFailure,
            report: None,
        },
    ];
    for reason in [
        Reject::Starting,
        Reject::IdentityMismatch,
        Reject::MalformedRequest,
        Reject::Busy,
        Reject::Closing,
        Reject::CoordinatorLost,
    ] {
        messages.push(Message::Reject(reason));
    }
    for (kind, result) in [
        (ReportKind::Committed(seq), ResultKind::Clean),
        (ReportKind::Committed(seq), ResultKind::RuntimeFailure),
        (ReportKind::Committed(seq), ResultKind::CacheCloseFailed),
        (ReportKind::Clean, ResultKind::Clean),
        (ReportKind::Bound, ResultKind::Stopped),
        (ReportKind::Signal, ResultKind::Stopped),
        (ReportKind::UnknownCut, ResultKind::Stopped),
        (
            ReportKind::Failed(FailureClass::Io),
            ResultKind::RuntimeFailure,
        ),
        (ReportKind::Internal, ResultKind::RuntimeFailure),
        (ReportKind::Fenced, ResultKind::Fenced),
    ] {
        messages.push(Message::Final {
            instance,
            result,
            report: Some(Report {
                kind,
                elapsed_ms,
                residue: None,
            }),
        });
    }
    messages
}
fn key() -> MountKey {
    MountKey {
        namespace_dev: 1,
        namespace_ino: 2,
        mount_id: 3,
        fuse_major: 0,
        fuse_minor: 4,
    }
}
#[expect(
    clippy::unwrap_used,
    reason = "fixed hexadecimal fixture bytes (standards rule 3)"
)]
fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn mount_control_vectors() {
    let mut expected = messages([7; 16], key(), 9, 12);
    expected.extend([
        Message::Final {
            instance: [7; 16],
            result: ResultKind::Clean,
            report: None,
        },
        Message::Final {
            instance: [7; 16],
            result: ResultKind::CacheCloseFailed,
            report: None,
        },
        Message::Hello(Hello {
            instance: [7; 16],
            key: key(),
            mode: Mode::Writable {
                bound_seconds: 3600,
                store: vec![255; 4096],
            },
        }),
        Message::Final {
            instance: [7; 16],
            result: ResultKind::RuntimeFailure,
            report: Some(Report {
                kind: ReportKind::Failed(FailureClass::Internal),
                elapsed_ms: u64::MAX,
                residue: Some(Residue {
                    files: u64::MAX,
                    bytes: u64::MAX,
                    operations: u64::MAX,
                }),
            }),
        },
        Message::Final {
            instance: [7; 16],
            result: ResultKind::Clean,
            report: Some(Report {
                kind: ReportKind::Committed(u64::MAX - 1),
                elapsed_ms: u64::MAX,
                residue: None,
            }),
        },
    ]);
    let mut cases = 0;
    let rows: Vec<_> = include_str!("../vectors/mount-control.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(rows.len(), expected.len());
    for (line, message) in rows.into_iter().zip(&expected) {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 2, "vector={line}");
        let bytes = unhex(fields[0]);
        assert_eq!(
            (encode(message).unwrap(), GrainId::of(&bytes).digest_hex()),
            (bytes.clone(), fields[1].to_owned())
        );
        assert_eq!(decode(&bytes), Ok(message.clone()));
        cases += 1;
    }
    assert_eq!(cases, expected.len());
    assert_eq!(cases, 26);
}

#[test]
fn mount_control_reject_vectors() {
    let mut cases = 0;
    for line in include_str!("../vectors/mount-control-rejects.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let mut fields = line.splitn(3, ' ');
        let positive = unhex(fields.next().unwrap());
        let malformed = unhex(fields.next().unwrap());
        let reason = fields.next().unwrap();
        let value = decode(&positive).unwrap();
        assert_eq!(encode(&value).unwrap(), positive);
        assert_eq!(decode(&malformed).unwrap_err().to_string(), reason);
        cases += 1;
    }
    assert_eq!(cases, 18);
    assert_eq!(
        (MAX_BODY, MAX_STORE_PATH, VERSION, MAGIC),
        (8192, 4096, 1, *b"GRNUMCTL")
    );
    let invalid_modes = [
        Mode::Writable {
            bound_seconds: 0,
            store: b"store".to_vec(),
        },
        Mode::Writable {
            bound_seconds: 3601,
            store: b"store".to_vec(),
        },
        Mode::Writable {
            bound_seconds: 30,
            store: Vec::new(),
        },
        Mode::Writable {
            bound_seconds: 30,
            store: vec![1; 4097],
        },
        Mode::Writable {
            bound_seconds: 30,
            store: b"s\0tore".to_vec(),
        },
    ];
    for mode in invalid_modes {
        assert_eq!(
            encode(&Message::Hello(Hello {
                instance: [7; 16],
                key: key(),
                mode
            }))
            .unwrap_err()
            .to_string(),
            "invalid mount control mode/bound/store"
        );
    }
}

#[test]
fn mount_control_unknown_reject_vectors() {
    let mut cases = 0;
    for line in include_str!("../vectors/mount-control-rejects.txt")
        .lines()
        .filter(|line| line.ends_with("invalid mount control rejection"))
    {
        let mut fields = line.splitn(3, ' ');
        let positive = unhex(fields.next().unwrap());
        let malformed = unhex(fields.next().unwrap());
        assert_eq!(decode(&positive), Ok(Message::Reject(Reject::Starting)));
        assert_eq!(
            decode(&malformed).unwrap_err().to_string(),
            "invalid mount control rejection"
        );
        cases += 1;
    }
    assert_eq!(cases, 3, "unknown Reject reason vectors");
}

#[test]
fn mount_control_final_context_refusals() {
    let writable = Hello {
        instance: [7; 16],
        key: key(),
        mode: Mode::Writable {
            bound_seconds: 30,
            store: b"store".to_vec(),
        },
    };
    let readonly = Hello {
        mode: Mode::ReadOnly,
        ..writable.clone()
    };
    let final_message = Message::Final {
        instance: writable.instance,
        result: ResultKind::Clean,
        report: Some(Report {
            kind: ReportKind::Committed(9),
            elapsed_ms: 12,
            residue: None,
        }),
    };
    let absent = Message::Final {
        instance: writable.instance,
        result: ResultKind::RuntimeFailure,
        report: None,
    };
    let wrong_instance = Message::Final {
        instance: [8; 16],
        result: ResultKind::Clean,
        report: Some(Report {
            kind: ReportKind::Committed(9),
            elapsed_ms: 12,
            residue: None,
        }),
    };
    let mut cases = 0;
    for (hello, positive, malformed, reason) in [
        (
            &writable,
            final_message.clone(),
            wrong_instance,
            "invalid mount control instance",
        ),
        (
            &readonly,
            absent.clone(),
            final_message,
            "invalid mount control final result/report/mode",
        ),
        (
            &writable,
            absent.clone(),
            Message::Final {
                instance: writable.instance,
                result: ResultKind::Clean,
                report: None,
            },
            "invalid mount control final result/report/mode",
        ),
        (
            &readonly,
            absent,
            Message::Accepted(writable.instance),
            "invalid mount control message order",
        ),
    ] {
        assert_eq!(
            (
                hello.validate_final(&positive).map_err(|e| e.to_string()),
                hello.validate_final(&malformed).map_err(|e| e.to_string())
            ),
            (Ok(()), Err(reason.to_owned())),
            "hello={hello:?}; message={malformed:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn mount_control_encoder_refuses_invalid_shapes() {
    let mut cases = 0;
    for bad_key in [
        MountKey {
            namespace_ino: 0,
            ..key()
        },
        MountKey {
            mount_id: 0,
            ..key()
        },
    ] {
        let valid = Message::Stop {
            instance: [7; 16],
            key: key(),
        };
        assert_eq!(decode(&encode(&valid).unwrap()), Ok(valid));
        let malformed = Message::Stop {
            instance: [7; 16],
            key: bad_key,
        };
        assert_eq!(
            encode(&malformed).unwrap_err().to_string(),
            "invalid mount control mount key"
        );
        cases += 1;
    }
    for (result, kind, residue, reason) in [
        (
            ResultKind::Clean,
            ReportKind::Committed(0),
            None,
            "invalid mount control sequence",
        ),
        (
            ResultKind::Clean,
            ReportKind::Committed(u64::MAX),
            None,
            "invalid mount control sequence",
        ),
        (
            ResultKind::Clean,
            ReportKind::Committed(9),
            Some(Residue {
                files: 1,
                bytes: 2,
                operations: 3,
            }),
            "invalid mount control released residue",
        ),
        (
            ResultKind::Stopped,
            ReportKind::Committed(9),
            None,
            "invalid mount control final result/report/mode",
        ),
        (
            ResultKind::Clean,
            ReportKind::Failed(FailureClass::Io),
            None,
            "invalid mount control final result/report/mode",
        ),
    ] {
        let valid = Message::Final {
            instance: [7; 16],
            result: ResultKind::Clean,
            report: Some(Report {
                kind: ReportKind::Committed(9),
                elapsed_ms: 12,
                residue: None,
            }),
        };
        assert_eq!(decode(&encode(&valid).unwrap()), Ok(valid));
        let malformed = Message::Final {
            instance: [7; 16],
            result,
            report: Some(Report {
                kind,
                elapsed_ms: 12,
                residue,
            }),
        };
        assert_eq!(encode(&malformed).unwrap_err().to_string(), reason);
        cases += 1;
    }
    assert_eq!(cases, 7);
}

#[test]
fn mount_control_rejects_and_properties() {
    let values = messages([7; 16], key(), 9, 12);
    let mut cases = 0;
    for value in &values {
        let valid = encode(value).unwrap();
        assert_eq!(decode(&valid), Ok(value.clone()));
        let end = if matches!(
            value,
            Message::Hello(Hello {
                mode: Mode::Writable { .. },
                ..
            })
        ) {
            60
        } else {
            valid.len()
        };
        for cut in 0..end {
            assert!(
                decode(&valid[..cut]).is_err(),
                "truncation {cut}: {value:?}"
            );
            cases += 1;
        }
        if !matches!(
            value,
            Message::Hello(Hello {
                mode: Mode::Writable { .. },
                ..
            })
        ) {
            let mut tail = valid.clone();
            tail.push(0);
            let reason = if matches!(value, Message::Hello(_)) {
                "invalid mount control mode/bound/store"
            } else {
                "1 trailing bytes after object body"
            };
            assert_eq!(decode(&tail).unwrap_err().to_string(), reason);
        }
    }
    assert_eq!(frame_length(11_u32.to_be_bytes()), Ok(11));
    assert_eq!(frame_length(8192_u32.to_be_bytes()), Ok(8192));
    for length in [0, 10, 8193, u32::MAX] {
        assert_eq!(
            frame_length(length.to_be_bytes()).unwrap_err().to_string(),
            "invalid mount control body length (must be 11..=8192)"
        );
        cases += 1;
    }
    for (offset, byte, reason) in [
        (0, 0, "bad mount control magic"),
        (9, 2, "unknown mount control version 2"),
        (10, 6, "invalid mount control kind"),
    ] {
        let mut malformed = encode(&values[2]).unwrap();
        malformed[offset] = byte;
        assert_eq!(decode(&malformed).unwrap_err().to_string(), reason);
        cases += 1;
    }
    let hello = Hello {
        instance: [7; 16],
        key: key(),
        mode: Mode::Writable {
            bound_seconds: 30,
            store: b"store".to_vec(),
        },
    };
    for result in [
        ResultKind::Clean,
        ResultKind::RuntimeFailure,
        ResultKind::CacheCloseFailed,
    ] {
        assert!(
            hello
                .validate_final(&Message::Final {
                    instance: hello.instance,
                    result,
                    report: Some(Report {
                        kind: ReportKind::Committed(9),
                        elapsed_ms: 12,
                        residue: None
                    })
                })
                .is_ok()
        );
    }
    assert!(cases > 400, "nonempty reject corpus: {cases}");
}

proptest! {
    #[test]
    fn mount_control_unknown_reject_reason(tag in any::<u8>()) {
        let mut bytes = encode(&Message::Reject(Reject::Starting)).unwrap();
        *bytes.last_mut().unwrap() = tag;
        if (1..=6).contains(&tag) {
            prop_assert!(decode(&bytes).is_ok(), "registered Reject reason {tag}");
        } else {
            prop_assert_eq!(decode(&bytes).unwrap_err().to_string(), "invalid mount control rejection");
        }
    }
    #[test]
    fn mount_control_round_trips(instance in any::<[u8;16]>(),namespace_dev in any::<u64>(),namespace_ino in 1..=u64::MAX,mount_id in 1..=u32::MAX,fuse_major in any::<u32>(),fuse_minor in any::<u32>(),seq in 1..u64::MAX,elapsed_ms in any::<u64>()) {
        let key=MountKey{namespace_dev,namespace_ino,mount_id,fuse_major,fuse_minor};
        let mut cases=0;
        for value in messages(instance,key,seq,elapsed_ms) {
            let bytes=encode(&value).unwrap();
            prop_assert_eq!(decode(&bytes),Ok(value));
            prop_assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(),bytes);
            cases+=1;
        }
        prop_assert_eq!(cases,21);
    }
    #[test]
    fn mount_control_raw_paths_and_residue(instance in any::<[u8;16]>(),bound_seconds in 1..=3600_u32,store in prop::collection::vec(1..=255_u8,1..=4096),elapsed_ms in any::<u64>(),files in any::<u64>(),bytes in any::<u64>(),operations in any::<u64>()) {
        let hello=Message::Hello(Hello{instance,key:key(),mode:Mode::Writable{bound_seconds,store}});
        let final_message=Message::Final{instance,result:ResultKind::RuntimeFailure,report:Some(Report{kind:ReportKind::Failed(FailureClass::Internal),elapsed_ms,residue:Some(Residue{files,bytes,operations})})};
        let mut cases=0;
        for value in [hello,final_message] {
            let bytes=encode(&value).unwrap();
            prop_assert_eq!(decode(&bytes),Ok(value));
            prop_assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(),bytes);
            cases+=1;
        }
        prop_assert_eq!(cases,2);
    }
    #[test]
    fn mount_control_decoder_does_not_panic(bytes in prop::collection::vec(any::<u8>(),0..8300)) {
        if let Ok(value)=decode(&bytes) {prop_assert_eq!(encode(&value).unwrap(),bytes);}
    }
}
