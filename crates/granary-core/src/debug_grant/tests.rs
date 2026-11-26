// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Construction boundaries, canonical properties and fuzz-probe controls.

use super::*;

fn fields() -> GrantFields {
    GrantFields {
        incarnation: Incarnation::from_bytes([0; 16]),
        file_revision: 1,
        grant_generation: 1,
        action: GrantAction::Issue,
        issuer_uid: 0,
        owner: Owner::from_bytes(b"!").unwrap_or_else(|e| panic!("{e}")),
        reason: Reason::from_bytes(b"~").unwrap_or_else(|e| panic!("{e}")),
        issued_at: Timestamp { secs: 0, nanos: 0 },
        expires_at: Timestamp { secs: 0, nanos: 1 },
        scope: GrantScope::Volume(VolumeName::from_bytes(b"a").unwrap_or_else(|e| panic!("{e}"))),
        line_ceiling: 0,
        byte_ceiling: 0,
    }
}

#[test]
fn debug_grant_constructor_boundaries() {
    let grant = DebugGrant::new(fields()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(encode_grant(&grant).as_bytes().len(), 127);
    assert_eq!(decode_grant(encode_grant(&grant).as_bytes()), Ok(grant));
    for secs in [i64::MIN, -1, 0, i64::MAX - DURATION_MAX_SECS] {
        let mut candidate = fields();
        candidate.file_revision = u64::MAX;
        candidate.grant_generation = u64::MAX;
        candidate.issued_at = Timestamp {
            secs,
            nanos: 999_999_999,
        };
        candidate.expires_at = Timestamp {
            secs: secs + DURATION_MAX_SECS,
            nanos: 999_999_999,
        };
        candidate.line_ceiling = LINE_CEILING_MAX;
        candidate.byte_ceiling = BYTE_CEILING_MAX;
        let grant = DebugGrant::new(candidate).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(decode_grant(encode_grant(&grant).as_bytes()), Ok(grant));
    }
    // The final representable instant and a subsecond interval across epoch zero.
    for (issued, expires) in [
        (
            Timestamp {
                secs: i64::MAX,
                nanos: 999_999_998,
            },
            Timestamp {
                secs: i64::MAX,
                nanos: 999_999_999,
            },
        ),
        (
            Timestamp {
                secs: -1,
                nanos: 999_999_999,
            },
            Timestamp { secs: 0, nanos: 0 },
        ),
    ] {
        let mut candidate = fields();
        candidate.issued_at = issued;
        candidate.expires_at = expires;
        assert!(DebugGrant::new(candidate).is_ok());
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "explicit value/error table covers construction boundaries"
)]
fn debug_grant_constructor_refusals() {
    let invalid: &[(GrantFields, GrantValidationError)] = &[
        (
            GrantFields {
                file_revision: 0,
                ..fields()
            },
            GrantValidationError::InvalidFileRevision,
        ),
        (
            GrantFields {
                grant_generation: 0,
                ..fields()
            },
            GrantValidationError::InvalidGeneration {
                generation: 0,
                revision: 1,
            },
        ),
        (
            GrantFields {
                grant_generation: 2,
                ..fields()
            },
            GrantValidationError::InvalidGeneration {
                generation: 2,
                revision: 1,
            },
        ),
        (
            GrantFields {
                issued_at: Timestamp {
                    secs: 0,
                    nanos: 1_000_000_000,
                },
                ..fields()
            },
            GrantValidationError::InvalidNanoseconds {
                field: TimestampField::IssuedAt,
                nanos: 1_000_000_000,
            },
        ),
        (
            GrantFields {
                expires_at: Timestamp {
                    secs: 1,
                    nanos: u32::MAX,
                },
                ..fields()
            },
            GrantValidationError::InvalidNanoseconds {
                field: TimestampField::ExpiresAt,
                nanos: u32::MAX,
            },
        ),
        (
            GrantFields {
                expires_at: Timestamp { secs: 0, nanos: 0 },
                ..fields()
            },
            GrantValidationError::InvalidDuration,
        ),
        (
            GrantFields {
                expires_at: Timestamp {
                    secs: 900,
                    nanos: 1,
                },
                ..fields()
            },
            GrantValidationError::InvalidDuration,
        ),
        (
            GrantFields {
                issued_at: Timestamp {
                    secs: i64::MIN,
                    nanos: 0,
                },
                expires_at: Timestamp {
                    secs: i64::MAX,
                    nanos: 0,
                },
                ..fields()
            },
            GrantValidationError::InvalidDuration,
        ),
        (
            GrantFields {
                issued_at: Timestamp {
                    secs: i64::MAX,
                    nanos: 0,
                },
                expires_at: Timestamp {
                    secs: i64::MIN,
                    nanos: 0,
                },
                ..fields()
            },
            GrantValidationError::InvalidDuration,
        ),
        (
            GrantFields {
                line_ceiling: 1025,
                ..fields()
            },
            GrantValidationError::BudgetOverBound {
                field: BudgetField::Lines,
                value: 1025,
            },
        ),
        (
            GrantFields {
                byte_ceiling: 1_048_577,
                ..fields()
            },
            GrantValidationError::BudgetOverBound {
                field: BudgetField::Bytes,
                value: 1_048_577,
            },
        ),
    ];
    for (candidate, error) in invalid {
        assert_eq!(DebugGrant::new(candidate.clone()), Err(*error));
    }
    for (field, max) in [
        (LabelField::Owner, OWNER_MAX),
        (LabelField::Reason, REASON_MAX),
    ] {
        for raw in [Vec::new(), vec![b'a'; max + 1]] {
            assert_eq!(
                validate_label(&raw, field),
                Err(GrantValidationError::BadLabelLength {
                    field,
                    len: raw.len()
                })
            );
        }
        for byte in [0, 0x1f, b' ', 0x7f, 0x80, 0xff] {
            assert_eq!(
                validate_label(&[byte], field),
                Err(GrantValidationError::BadLabelByte { field, byte })
            );
        }
        assert_eq!(validate_label(&vec![b'~'; max], field), Ok(()));
    }
}

fn lcg() -> impl FnMut() -> u64 {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    }
}

fn label_bytes(next: &mut impl FnMut() -> u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| 0x21 + u8::try_from(next() % 94).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

fn generated_interval(next: &mut impl FnMut() -> u64) -> (Timestamp, Timestamp) {
    let secs = i64::from_be_bytes(next().to_be_bytes()).min(i64::MAX - DURATION_MAX_SECS);
    let nanos = u32::try_from(next() % 1_000_000_000).unwrap_or_else(|e| panic!("{e}"));
    let end_nanos = u64::from(nanos) + 1 + next() % 900_000_000_000;
    (
        Timestamp { secs, nanos },
        Timestamp {
            secs: secs + i64::try_from(end_nanos / 1_000_000_000).unwrap_or_else(|e| panic!("{e}")),
            nanos: u32::try_from(end_nanos % 1_000_000_000).unwrap_or_else(|e| panic!("{e}")),
        },
    )
}

fn generated_grant(
    next: &mut impl FnMut() -> u64,
    case: usize,
    action: GrantAction,
    scope_tag: u8,
    issued_at: Timestamp,
    expires_at: Timestamp,
) -> DebugGrant {
    let mut incarnation = [0; 16];
    let mut principal = [0; 16];
    for chunk in incarnation.chunks_mut(8).chain(principal.chunks_mut(8)) {
        chunk.copy_from_slice(&next().to_be_bytes());
    }
    let (file_revision, grant_generation) = match case % 4 {
        0 => (1, 1),
        1 => (u64::MAX, u64::MAX),
        2 => (u64::MAX, 1),
        _ => {
            let revision = next().max(1);
            (revision, 1 + next() % revision)
        }
    };
    let owner = Owner::from_bytes(&label_bytes(next, 1 + case % OWNER_MAX))
        .unwrap_or_else(|e| panic!("{e}"));
    let reason = Reason::from_bytes(&label_bytes(next, 1 + case)).unwrap_or_else(|e| panic!("{e}"));
    let volume_len = 1 + case % VOLUME_NAME_MAX;
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789-";
    let volume: Vec<_> = (0..volume_len)
        .map(|offset| {
            let bound = if offset == 0 || offset + 1 == volume_len {
                36
            } else {
                37
            };
            let index = usize::try_from(next() % bound).unwrap_or_else(|e| panic!("{e}"));
            *alphabet
                .get(index)
                .unwrap_or_else(|| panic!("bounded alphabet index"))
        })
        .collect();
    let volume = VolumeName::from_bytes(&volume).unwrap_or_else(|e| panic!("{e}"));
    let principal = PrincipalId::from_bytes(principal);
    let scope = match scope_tag {
        1 => GrantScope::Principal(principal),
        2 => GrantScope::Volume(volume),
        3 => GrantScope::Conjunction { principal, volume },
        _ => panic!("scope sweep covers registered tags"),
    };
    let line_ceiling = match case % 3 {
        0 => 0,
        1 => LINE_CEILING_MAX,
        _ => next() % (LINE_CEILING_MAX + 1),
    };
    let byte_ceiling = match case % 3 {
        0 => 0,
        1 => BYTE_CEILING_MAX,
        _ => next() % (BYTE_CEILING_MAX + 1),
    };
    DebugGrant::new(GrantFields {
        incarnation: Incarnation::from_bytes(incarnation),
        file_revision,
        grant_generation,
        action,
        issuer_uid: u32::try_from(next() >> 32).unwrap_or_else(|e| panic!("{e}")),
        owner,
        reason,
        issued_at,
        expires_at,
        scope,
        line_ceiling,
        byte_ceiling,
    })
    .unwrap_or_else(|e| panic!("{e}"))
}

/// Cross every action and scope with all label lengths and timestamp edges.
/// Lengths cycle through each field's entire legal range.
fn sweep_grants(mut check: impl FnMut(DebugGrant)) {
    let mut next = lcg();
    let time = |secs, nanos| Timestamp { secs, nanos };
    let mut count = 0;
    for case in 0..REASON_MAX {
        for action in [GrantAction::Issue, GrantAction::Narrow, GrantAction::Revoke] {
            for scope_tag in 1..=3 {
                let intervals = [
                    (time(i64::MIN, 0), time(i64::MIN, 1)),
                    (time(i64::MIN, 999_999_999), time(i64::MIN + 1, 0)),
                    (time(-1, 999_999_999), time(0, 0)),
                    (time(0, 0), time(900, 0)),
                    (time(0, 999_999_999), time(900, 999_999_999)),
                    (
                        time(i64::MAX - 900, 999_999_999),
                        time(i64::MAX, 999_999_999),
                    ),
                    (time(i64::MAX, 0), time(i64::MAX, 1)),
                    (time(i64::MAX, 999_999_998), time(i64::MAX, 999_999_999)),
                    generated_interval(&mut next),
                ];
                for (issued_at, expires_at) in intervals {
                    check(generated_grant(
                        &mut next, case, action, scope_tag, issued_at, expires_at,
                    ));
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 20_736, "complete grant sweep");
}

#[test]
fn debug_grant_value_round_trip() {
    sweep_grants(|grant| {
        let bytes = encode_grant(&grant);
        assert!(bytes.as_bytes().len() <= ENCODED_MAX);
        assert_eq!(decode_grant(bytes.as_bytes()), Ok(grant));
    });
}

#[test]
fn debug_grant_canonical_bytes_round_trip() {
    sweep_grants(|grant| {
        let bytes = encode_grant(&grant);
        let decoded = decode_grant(bytes.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(encode_grant(&decoded), bytes);
    });
}

#[test]
fn debug_grant_arbitrary_bytes_are_canonical() {
    let mut next = lcg();
    let mut reached_check = 0;
    let mut reached_fields = 0;
    for len in 0..=ENCODED_MAX + 1 {
        for _ in 0..16 {
            let mut bytes: Vec<_> = (0..len)
                .map(|_| u8::try_from(next() >> 56).unwrap_or_else(|e| panic!("{e}")))
                .collect();
            if let Some(magic) = bytes.get_mut(..8) {
                magic.copy_from_slice(&DEBUG_GRANT_MAGIC);
            }
            if let Some(version) = bytes.get_mut(8..10) {
                version.copy_from_slice(&DEBUG_GRANT_VERSION.to_be_bytes());
            }
            crate::testkit::debug_grant_decode_probe(&bytes);
            if decode_grant(&bytes) == Err(GrantDecodeError::BadCheck) {
                reached_check += 1;
            }
            if let Some(repaired) = crate::testkit::debug_grant_recheck_input(&bytes) {
                let result = decode_grant(&repaired);
                assert!(
                    matches!(
                        result,
                        Ok(_)
                            | Err(GrantDecodeError::Truncated
                                | GrantDecodeError::InvalidAction { .. }
                                | GrantDecodeError::InvalidScope { .. }
                                | GrantDecodeError::InvalidVolume(_)
                                | GrantDecodeError::InvalidValue(_)
                                | GrantDecodeError::TrailingData { .. })
                    ),
                    "repaired random input must reach field validation: {result:?}"
                );
                reached_fields += 1;
            }
        }
    }
    assert_eq!(reached_check, 7_712, "random inputs must reach the check");
    assert_eq!(reached_fields, 7_712, "repaired inputs must reach fields");
}

#[test]
fn debug_grant_fuzz_recheck_reaches_fields() {
    let grant = DebugGrant::new(fields()).unwrap_or_else(|e| panic!("{e}"));
    let mut damaged = encode_grant(&grant).as_bytes().to_vec();
    for byte in damaged.iter_mut().rev().take(CHECK_LEN) {
        *byte ^= 0xa5;
    }
    assert_eq!(decode_grant(&damaged), Err(GrantDecodeError::BadCheck));
    let repaired = crate::testkit::debug_grant_recheck_input(&damaged)
        .unwrap_or_else(|| panic!("bounded input"));
    assert_eq!(decode_grant(&repaired), Ok(grant));
    let (covered, _) = repaired
        .split_last_chunk::<CHECK_LEN>()
        .unwrap_or_else(|| panic!("check present"));
    let mut malformed = covered.to_vec();
    *malformed
        .get_mut(42)
        .unwrap_or_else(|| panic!("action present")) = 0;
    malformed.extend_from_slice(&[0; CHECK_LEN]);
    let repaired = crate::testkit::debug_grant_recheck_input(&malformed)
        .unwrap_or_else(|| panic!("bounded input"));
    assert_eq!(
        decode_grant(&repaired),
        Err(GrantDecodeError::InvalidAction { tag: 0 })
    );
    assert_eq!(
        crate::testkit::debug_grant_recheck_input(&[0; MIN_LEN - 1]),
        None
    );
    assert_eq!(
        crate::testkit::debug_grant_recheck_input(&[0; ENCODED_MAX + 1]),
        None
    );
}
