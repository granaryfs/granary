// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::runmarker`.
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (coding-standards rule 18).

use super::*;

/// Boot id 0x01..=0x10, running.
const GOLDEN_RUNNING_HEX: &str = "47524e52554e4d4b0001010102030405060708090a0b0c0d0e0f10\
     ad55d502f849fc9eaa7a1b4dfd5751112883b8ff2eccfa02e344d5b15fe8a7e9";
const GOLDEN_CLEAN_HEX: &str = "47524e52554e4d4b0001020afdc82cffdb9b1979af9524cfee1026de85d2526a\
     31c2d9b1fbfa2a2a2edb28";

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

fn golden_boot_id() -> BootId {
    BootId::from_bytes(core::array::from_fn(|i| {
        u8::try_from(i + 1).unwrap_or_else(|e| panic!("{e}"))
    }))
}

fn golden_running() -> Vec<u8> {
    unhex(GOLDEN_RUNNING_HEX)
}

fn golden_clean() -> Vec<u8> {
    unhex(GOLDEN_CLEAN_HEX)
}

/// `body` (everything before the check) with a correct check appended, so a
/// test can be wrong in exactly one way.
fn checked(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.extend_from_slice(&blake3::derive_key(CHECK_CONTEXT, body));
    out
}

/// A running marker's body with `state` in the state byte.
fn running_body_with_state(state: u8) -> Vec<u8> {
    let mut body = golden_running();
    body.truncate(RUNNING_LEN - CHECK_LEN);
    body[10] = state;
    body
}

/// A clean-length body with `state` in the state byte.
fn clean_body_with_state(state: u8) -> Vec<u8> {
    let mut body = golden_clean();
    body.truncate(CLEAN_LEN - CHECK_LEN);
    body[10] = state;
    body
}

// ============================================================ golden

#[test]
fn lengths_are_pinned() {
    assert_eq!(RUNNING_LEN, 59);
    assert_eq!(CLEAN_LEN, 43);
    assert_eq!(golden_running().len(), RUNNING_LEN);
    assert_eq!(golden_clean().len(), CLEAN_LEN);
}

#[test]
fn golden_running_encodes_and_decodes() {
    let marker = RunMarker::Running(golden_boot_id());
    assert_eq!(encode_marker(&marker).as_bytes(), golden_running());
    assert_eq!(decode_marker(&golden_running()), Ok(marker));
}

#[test]
fn golden_clean_encodes_and_decodes() {
    assert_eq!(encode_marker(&RunMarker::Clean).as_bytes(), golden_clean());
    assert_eq!(decode_marker(&golden_clean()), Ok(RunMarker::Clean));
}

#[test]
fn boot_id_bytes_round_trip() {
    let bytes = [0xA5; BOOT_ID_LEN];
    assert_eq!(BootId::from_bytes(bytes).to_bytes(), bytes);
}

#[test]
fn round_trip_over_many_boot_ids() {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    for _ in 0..2048 {
        let mut id = [0u8; BOOT_ID_LEN];
        for chunk in id.chunks_mut(8) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            chunk.copy_from_slice(&state.to_be_bytes());
        }
        let marker = RunMarker::Running(BootId::from_bytes(id));
        let encoded = encode_marker(&marker);
        let bytes = encoded.as_bytes();
        assert_eq!(bytes.len(), RUNNING_LEN);
        assert_eq!(decode_marker(bytes), Ok(marker));
        assert_eq!(encode_marker(&decode_marker(bytes).unwrap()), encoded);
    }
    // The all-zero and all-ones ids are ordinary values.
    for id in [[0u8; BOOT_ID_LEN], [0xFF; BOOT_ID_LEN]] {
        let marker = RunMarker::Running(BootId::from_bytes(id));
        assert_eq!(decode_marker(encode_marker(&marker).as_bytes()), Ok(marker));
    }
}

// ============================================================ rejects

/// A running marker cut to a clean marker's length has a legal length, so it
/// is the check that refuses it.
#[test]
fn every_truncation_is_refused_as_a_bad_length() {
    for golden in [golden_running(), golden_clean()] {
        for len in 0..golden.len() {
            let want = if len == CLEAN_LEN {
                MarkerDecodeError::BadCheck
            } else {
                MarkerDecodeError::BadLength { len }
            };
            assert_eq!(
                decode_marker(&golden[..len]),
                Err(want),
                "truncated to {len} of {}",
                golden.len()
            );
        }
    }
}

#[test]
fn trailing_bytes_are_refused_as_a_bad_length() {
    for golden in [golden_running(), golden_clean()] {
        for extra in 1..=3 {
            let mut longer = golden.clone();
            longer.extend(std::iter::repeat_n(0x00, extra));
            assert_eq!(
                decode_marker(&longer),
                Err(MarkerDecodeError::BadLength {
                    len: golden.len() + extra
                })
            );
        }
    }
}

/// Damage anywhere but the magic reads as a bad check, including the
/// version, state and boot id bytes; damage in the magic is a bad magic.
#[test]
fn every_flipped_byte_is_a_bad_check_or_a_bad_magic() {
    for golden in [golden_running(), golden_clean()] {
        for i in 0..golden.len() {
            for mask in [0x01_u8, 0xFF] {
                let mut bytes = golden.clone();
                bytes[i] ^= mask;
                let want = if i < MARKER_MAGIC.len() {
                    MarkerDecodeError::BadMagic
                } else {
                    MarkerDecodeError::BadCheck
                };
                assert_eq!(
                    decode_marker(&bytes),
                    Err(want),
                    "byte {i} of {} xor {mask:#04x}",
                    golden.len()
                );
            }
        }
    }
}

#[test]
fn a_correctly_checked_version_2_is_refused() {
    for mut body in [running_body_with_state(1), clean_body_with_state(2)] {
        body[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            decode_marker(&checked(&body)),
            Err(MarkerDecodeError::UnknownVersion { version: 2 })
        );
    }
}

#[test]
fn a_correctly_checked_bad_state_is_refused() {
    for tag in [0x00, 0x03, 0x80, 0xFF] {
        for body in [running_body_with_state(tag), clean_body_with_state(tag)] {
            assert_eq!(
                decode_marker(&checked(&body)),
                Err(MarkerDecodeError::InvalidState { tag }),
                "state {tag:#04x}"
            );
        }
    }
}

#[test]
fn clean_state_with_a_boot_id_is_refused() {
    let bytes = checked(&running_body_with_state(STATE_CLEAN));
    assert_eq!(bytes.len(), RUNNING_LEN);
    assert_eq!(
        decode_marker(&bytes),
        Err(MarkerDecodeError::StateLengthMismatch {
            tag: STATE_CLEAN,
            len: RUNNING_LEN
        })
    );
}

#[test]
fn running_state_without_a_boot_id_is_refused() {
    let bytes = checked(&clean_body_with_state(STATE_RUNNING));
    assert_eq!(bytes.len(), CLEAN_LEN);
    assert_eq!(
        decode_marker(&bytes),
        Err(MarkerDecodeError::StateLengthMismatch {
            tag: STATE_RUNNING,
            len: CLEAN_LEN
        })
    );
}

#[test]
fn bad_magic_with_a_valid_check_is_refused() {
    for mut body in [running_body_with_state(1), clean_body_with_state(2)] {
        body[0] = b'X';
        assert_eq!(
            decode_marker(&checked(&body)),
            Err(MarkerDecodeError::BadMagic)
        );
    }
}

#[test]
fn a_check_over_the_wrong_range_or_context_is_refused() {
    let body = clean_body_with_state(STATE_CLEAN);

    // Skips the magic.
    let mut short_range = body.clone();
    short_range.extend_from_slice(&blake3::derive_key(CHECK_CONTEXT, &body[8..]));
    assert_eq!(
        decode_marker(&short_range),
        Err(MarkerDecodeError::BadCheck)
    );

    // Another context string.
    let mut other_context = body.clone();
    other_context.extend_from_slice(&blake3::derive_key(
        "granary authority run marker v2",
        &body,
    ));
    assert_eq!(
        decode_marker(&other_context),
        Err(MarkerDecodeError::BadCheck)
    );

    // The unkeyed hash of the right range.
    let mut plain = body.clone();
    plain.extend_from_slice(blake3::hash(&body).as_bytes());
    assert_eq!(decode_marker(&plain), Err(MarkerDecodeError::BadCheck));

    // The right check still decodes.
    assert_eq!(decode_marker(&checked(&body)), Ok(RunMarker::Clean));
}

#[test]
fn error_messages_are_lowercase_without_a_trailing_period() {
    let errors = [
        MarkerDecodeError::BadMagic,
        MarkerDecodeError::BadLength { len: 3 },
        MarkerDecodeError::BadCheck,
        MarkerDecodeError::UnknownVersion { version: 2 },
        MarkerDecodeError::InvalidState { tag: 0 },
        MarkerDecodeError::StateLengthMismatch { tag: 1, len: 43 },
    ];
    for e in errors {
        let text = e.to_string();
        assert!(text.starts_with(|c: char| c.is_ascii_lowercase()), "{text}");
        assert!(!text.ends_with('.'), "{text}");
    }
}

#[test]
fn the_probe_accepts_goldens_and_survives_garbage() {
    crate::testkit::runmarker_decode_probe(&golden_running());
    crate::testkit::runmarker_decode_probe(&golden_clean());
    crate::testkit::runmarker_decode_probe(&[]);
    crate::testkit::runmarker_decode_probe(&[0xFF; 100]);
}

/// The probe's second decode reaches the accept path: a golden vector with
/// its check bytes damaged is refused as given, and the input the probe
/// rebuilds from it (the check recomputed) decodes to the original marker.
#[test]
fn the_probe_recheck_input_reaches_the_accept_path() {
    for golden in [golden_running(), golden_clean()] {
        let mut damaged = golden.clone();
        for byte in damaged.iter_mut().rev().take(CHECK_LEN) {
            *byte ^= 0xA5;
        }
        assert_eq!(decode_marker(&damaged), Err(MarkerDecodeError::BadCheck));
        let rebuilt = crate::testkit::runmarker_recheck_input(&damaged)
            .unwrap_or_else(|| panic!("a marker-length input must be rebuilt"));
        assert_eq!(rebuilt, golden);
        assert!(decode_marker(&rebuilt).is_ok());
    }
    assert_eq!(crate::testkit::runmarker_recheck_input(&[0; 5]), None);
}

/// A clean marker plus 16 bytes lands on the running length: the check, not
/// the length, refuses it.
#[test]
fn a_clean_marker_extended_to_the_running_length_is_a_bad_check() {
    let mut longer = golden_clean();
    longer.extend([0x00; RUNNING_LEN - CLEAN_LEN]);
    assert_eq!(decode_marker(&longer), Err(MarkerDecodeError::BadCheck));
}
