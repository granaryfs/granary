// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Fixed records and hand-built malformed inputs for the format vectors.

use granary_core::debug_grant::{
    BudgetField, DebugGrant, GrantAction, GrantDecodeError, GrantFields, GrantScope,
    GrantValidationError, Incarnation, LabelField, Owner, Reason, TimestampField, encode_grant,
};
use granary_core::enrollment::PrincipalId;
use granary_core::root::{VolumeName, VolumeNameError};
use granary_core::sheaf::Timestamp;

pub(crate) fn fields() -> GrantFields {
    GrantFields {
        incarnation: Incarnation::from_bytes(core::array::from_fn(|i| {
            0xa0 + u8::try_from(i).unwrap_or_else(|e| panic!("{e}"))
        })),
        file_revision: 1,
        grant_generation: 1,
        action: GrantAction::Issue,
        issuer_uid: 501,
        owner: Owner::from_bytes(b"ops").unwrap_or_else(|e| panic!("{e}")),
        reason: Reason::from_bytes(b"inspect").unwrap_or_else(|e| panic!("{e}")),
        issued_at: Timestamp {
            secs: 1_700_000_000,
            nanos: 123_456_789,
        },
        expires_at: Timestamp {
            secs: 1_700_000_900,
            nanos: 123_456_789,
        },
        scope: GrantScope::Principal(PrincipalId::from_bytes(core::array::from_fn(|i| {
            1 + u8::try_from(i).unwrap_or_else(|e| panic!("{e}"))
        }))),
        line_ceiling: 1024,
        byte_ceiling: 1_048_576,
    }
}

pub(crate) fn goldens() -> Vec<(&'static str, DebugGrant)> {
    let principal = fields();
    let volume = VolumeName::from_bytes(b"vol-a").unwrap_or_else(|e| panic!("{e}"));
    let GrantScope::Principal(id) = principal.scope else {
        panic!("principal fixture");
    };
    let conjunction = GrantFields {
        file_revision: 3,
        grant_generation: 3,
        scope: GrantScope::Conjunction {
            principal: id,
            volume: volume.clone(),
        },
        ..fields()
    };
    let narrowed = GrantFields {
        file_revision: 4,
        action: GrantAction::Narrow,
        expires_at: Timestamp {
            secs: 1_700_000_300,
            nanos: 123_456_789,
        },
        line_ceiling: 0,
        byte_ceiling: 512,
        ..conjunction.clone()
    };
    [
        ("principal", principal),
        (
            "volume",
            GrantFields {
                file_revision: 2,
                grant_generation: 2,
                scope: GrantScope::Volume(volume),
                line_ceiling: 1,
                byte_ceiling: 1024,
                ..fields()
            },
        ),
        ("conjunction", conjunction),
        ("narrowed", narrowed.clone()),
        (
            "revoked",
            GrantFields {
                file_revision: 5,
                action: GrantAction::Revoke,
                byte_ceiling: 0,
                ..narrowed
            },
        ),
        (
            "maximum",
            GrantFields {
                incarnation: Incarnation::from_bytes([0xff; 16]),
                file_revision: u64::MAX,
                grant_generation: u64::MAX,
                action: GrantAction::Issue,
                issuer_uid: u32::MAX,
                owner: Owner::from_bytes(&[b'~'; 64]).unwrap_or_else(|e| panic!("{e}")),
                reason: Reason::from_bytes(&[b'!'; 256]).unwrap_or_else(|e| panic!("{e}")),
                issued_at: Timestamp {
                    secs: i64::MIN,
                    nanos: 999_999_999,
                },
                expires_at: Timestamp {
                    secs: i64::MIN + 900,
                    nanos: 999_999_999,
                },
                scope: GrantScope::Conjunction {
                    principal: PrincipalId::from_bytes([0; 16]),
                    volume: VolumeName::from_bytes(&[b'z'; 63]).unwrap_or_else(|e| panic!("{e}")),
                },
                line_ceiling: 1024,
                byte_ceiling: 1_048_576,
            },
        ),
    ]
    .into_iter()
    .map(|(name, fields)| {
        (
            name,
            DebugGrant::new(fields).unwrap_or_else(|e| panic!("{e}")),
        )
    })
    .collect()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap_or_else(|e| panic!("{e}"));
        text
    })
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "complete hex bytes");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).unwrap_or_else(|e| panic!("{e}")),
                16,
            )
            .unwrap_or_else(|e| panic!("{e}"))
        })
        .collect()
}

pub(crate) fn checked(body: &[u8]) -> Vec<u8> {
    let mut bytes = body.to_vec();
    bytes.extend_from_slice(&blake3::derive_key("granary debug grant v1", body));
    bytes
}

pub(crate) fn base_body() -> Vec<u8> {
    let grant = DebugGrant::new(fields()).unwrap_or_else(|e| panic!("{e}"));
    let bytes = encode_grant(&grant);
    bytes
        .as_bytes()
        .split_last_chunk::<32>()
        .unwrap_or_else(|| panic!("check present"))
        .0
        .to_vec()
}

pub(crate) fn patched(body: &[u8], offset: usize, replacement: &[u8]) -> Vec<u8> {
    let mut changed = body.to_vec();
    changed
        .get_mut(offset..offset + replacement.len())
        .unwrap_or_else(|| panic!("fixture field present"))
        .copy_from_slice(replacement);
    checked(&changed)
}

/// Fixed malformed bytes with independently specified typed errors.
#[expect(
    clippy::too_many_lines,
    reason = "one fixed table pins every strict-decode refusal"
)]
pub(crate) fn rejects() -> Vec<(String, Vec<u8>, GrantDecodeError)> {
    use GrantDecodeError as D;
    use GrantValidationError as V;
    let body = base_body();
    let mut rows = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>, error: D| rows.push((name.to_owned(), bytes, error));
    add("magic", patched(&body, 0, b"X"), D::BadMagic);
    for (name, len) in [("empty", 0), ("short-magic", 7), ("short-envelope", 41)] {
        let mut bytes = checked(&body);
        bytes.truncate(len);
        add(name, bytes, D::TooShort { len });
    }
    let mut oversize = body.clone();
    oversize.resize(492, 0);
    add("oversize", checked(&oversize), D::TooLong { len: 524 });
    let mut oversize_bad_check = checked(&oversize);
    *oversize_bad_check
        .last_mut()
        .unwrap_or_else(|| panic!("check")) ^= 1;
    add(
        "oversize-bad-check",
        oversize_bad_check,
        D::TooLong { len: 524 },
    );
    let mut damaged = checked(&body);
    *damaged.last_mut().unwrap_or_else(|| panic!("check")) ^= 1;
    add("check", damaged, D::BadCheck);
    for (name, check) in [
        ("check-unkeyed", *blake3::hash(&body).as_bytes()),
        (
            "check-context",
            blake3::derive_key("granary enrollment set v1", &body),
        ),
    ] {
        let mut bytes = body.clone();
        bytes.extend_from_slice(&check);
        add(name, bytes, D::BadCheck);
    }
    for version in [0u16, 2, u16::MAX] {
        add(
            &format!("version-{version}"),
            patched(&body, 8, &version.to_be_bytes()),
            D::UnknownVersion { version },
        );
    }
    add(
        "revision-zero",
        patched(&body, 26, &0u64.to_be_bytes()),
        D::InvalidValue(V::InvalidFileRevision),
    );
    for generation in [0u64, 2, u64::MAX] {
        add(
            &format!("generation-{generation}"),
            patched(&body, 34, &generation.to_be_bytes()),
            D::InvalidValue(V::InvalidGeneration {
                generation,
                revision: 1,
            }),
        );
    }
    for tag in [0u8, 4, 255] {
        add(
            &format!("action-{tag}"),
            patched(&body, 42, &[tag]),
            D::InvalidAction { tag },
        );
        add(
            &format!("scope-{tag}"),
            patched(&body, 84, &[tag]),
            D::InvalidScope { tag },
        );
    }
    for (field, offset, start, max) in [
        (LabelField::Owner, 47, 48, 64usize),
        (LabelField::Reason, 51, 53, 256),
    ] {
        let name = match field {
            LabelField::Owner => "owner",
            LabelField::Reason => "reason",
        };
        for len in [0, max + 1] {
            let length = u16::try_from(len)
                .unwrap_or_else(|e| panic!("{e}"))
                .to_be_bytes();
            let replacement: &[u8] = if field == LabelField::Owner {
                length.get(1..).unwrap_or_else(|| panic!("u8 length"))
            } else {
                &length
            };
            add(
                &format!("{name}-length-{len}"),
                patched(&body, offset, replacement),
                D::InvalidValue(V::BadLabelLength { field, len }),
            );
        }
        for byte in [0u8, 0x1f, 0x20, 0x7f, 0x80, 0xff] {
            add(
                &format!("{name}-byte-{byte:02x}"),
                patched(&body, start, &[byte]),
                D::InvalidValue(V::BadLabelByte { field, byte }),
            );
        }
    }
    for (field, offset) in [
        (TimestampField::IssuedAt, 68),
        (TimestampField::ExpiresAt, 80),
    ] {
        let name = if field == TimestampField::IssuedAt {
            "issued"
        } else {
            "expires"
        };
        for nanos in [1_000_000_000u32, u32::MAX] {
            add(
                &format!("{name}-nanos-{nanos}"),
                patched(&body, offset, &nanos.to_be_bytes()),
                D::InvalidValue(V::InvalidNanoseconds { field, nanos }),
            );
        }
    }
    for (name, secs, nanos) in [
        ("duration-zero", 1_700_000_000i64, 123_456_789u32),
        ("duration-negative", 1_699_999_999, 123_456_789),
        ("duration-negative-nano", 1_700_000_000, 123_456_788),
        ("duration-901", 1_700_000_901, 123_456_789),
        ("duration-900-plus-nano", 1_700_000_900, 123_456_790),
    ] {
        let mut replacement = secs.to_be_bytes().to_vec();
        replacement.extend_from_slice(&nanos.to_be_bytes());
        add(
            name,
            patched(&body, 72, &replacement),
            D::InvalidValue(V::InvalidDuration),
        );
    }
    for (name, issued, expires) in [
        ("duration-extreme-positive", i64::MIN, i64::MAX),
        ("duration-extreme-negative", i64::MAX, i64::MIN),
    ] {
        let mut changed = body.clone();
        changed
            .get_mut(60..68)
            .unwrap_or_else(|| panic!("issued seconds"))
            .copy_from_slice(&issued.to_be_bytes());
        changed
            .get_mut(72..80)
            .unwrap_or_else(|| panic!("expires seconds"))
            .copy_from_slice(&expires.to_be_bytes());
        add(name, checked(&changed), D::InvalidValue(V::InvalidDuration));
    }
    for (field, offset, max) in [
        (BudgetField::Lines, 101, 1024u64),
        (BudgetField::Bytes, 109, 1_048_576),
    ] {
        let name = if field == BudgetField::Lines {
            "lines"
        } else {
            "bytes"
        };
        for value in [max + 1, u64::MAX] {
            add(
                &format!("{name}-{value}"),
                patched(&body, offset, &value.to_be_bytes()),
                D::InvalidValue(V::BudgetOverBound { field, value }),
            );
        }
    }
    let volume = goldens()
        .into_iter()
        .find(|(name, _)| *name == "volume")
        .unwrap_or_else(|| panic!("volume golden"))
        .1;
    let encoded = encode_grant(&volume);
    let volume_body = encoded
        .as_bytes()
        .split_last_chunk::<32>()
        .unwrap_or_else(|| panic!("check"))
        .0;
    for len in [0u8, 64, 255] {
        let error = if len == 0 {
            VolumeNameError::Empty
        } else {
            VolumeNameError::TooLong {
                len: usize::from(len),
            }
        };
        add(
            &format!("volume-length-{len}"),
            patched(volume_body, 85, &[len]),
            D::InvalidVolume(error),
        );
    }
    for byte in [0u8, 0x20, b'V', b'_', 0xff] {
        add(
            &format!("volume-byte-{byte:02x}"),
            patched(volume_body, 86, &[byte]),
            D::InvalidVolume(VolumeNameError::BadByte { byte }),
        );
    }
    add(
        "volume-leading-dash",
        patched(volume_body, 86, b"-"),
        D::InvalidVolume(VolumeNameError::LeadingDash),
    );
    add(
        "volume-trailing-dash",
        patched(volume_body, 90, b"-"),
        D::InvalidVolume(VolumeNameError::TrailingDash),
    );
    for end in [
        10, 25, 26, 33, 34, 41, 42, 43, 46, 47, 48, 50, 51, 52, 53, 59, 60, 67, 68, 71, 72, 79, 80,
        83, 84, 85, 100, 101, 108, 109, 116,
    ] {
        add(
            &format!("truncated-{end}"),
            checked(body.get(..end).unwrap_or_else(|| panic!("prefix"))),
            D::Truncated,
        );
    }
    for end in [85, 86, 90] {
        add(
            &format!("volume-truncated-{end}"),
            checked(volume_body.get(..end).unwrap_or_else(|| panic!("prefix"))),
            D::Truncated,
        );
    }
    let mut trailing = body.clone();
    trailing.push(0);
    add("trailing", checked(&trailing), D::TrailingData { len: 1 });
    let mut unrepaired = checked(&body);
    unrepaired.push(0);
    add("trailing-unrepaired", unrepaired, D::BadCheck);
    rows
}
