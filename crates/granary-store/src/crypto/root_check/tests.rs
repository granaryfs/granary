// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::crypto::root_check`, over real signed roots.
//!
//! Out-of-line for the same reason as `crypto`'s own tests: the crate's
//! non-test artifact has workspace consumers.

use granary_core::hash::GrainId;
use granary_core::root::{RootSig, Timestamp, VolumeName};

use super::*;
use crate::crypto::SigningKey;

const VOL: &str = "check-vol";

fn key(byte: u8) -> SigningKey {
    SigningKey::from_seed(&[byte; 32]).unwrap_or_else(|e| panic!("{e}"))
}

fn keys_of(signers: &[&SigningKey]) -> TrustedKeys {
    TrustedKeys::new(signers.iter().map(|k| *k.public_key())).unwrap_or_else(|e| panic!("{e}"))
}

fn draft(volume: &str, seq: u64, parent: Option<GrainId>) -> RootDoc {
    RootDoc {
        volume: VolumeName::new(volume.to_owned()).unwrap_or_else(|e| panic!("{e}")),
        seq,
        parent,
        writer_uuid: [3; 16],
        epoch: seq,
        timestamp: Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        },
        chunker_spec: "fastcdc-v2020/min=2048/avg=8192/max=32768".to_owned(),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: Vec::new(),
    }
}

/// A root signed by each of `signers`, in order, over its own signing
/// prefix — the way a publisher signs.
fn signed_root(
    volume: &str,
    seq: u64,
    parent: Option<GrainId>,
    signers: &[&SigningKey],
) -> Vec<u8> {
    let mut doc = draft(volume, seq, parent);
    let prefix = root::signing_prefix_of(&doc).unwrap_or_else(|e| panic!("{e}"));
    for signer in signers {
        doc.sigs.push(RootSig {
            key_id: signer.key_id(),
            sig: signer.sign(&prefix),
        });
    }
    root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"))
}

/// A seq-1 root, the simplest valid head.
fn first_root(signers: &[&SigningKey]) -> Vec<u8> {
    signed_root(VOL, 1, None, signers)
}

// ------------------------------------------------------------ key set

#[test]
fn a_key_set_refuses_no_keys() {
    assert_eq!(
        TrustedKeys::new(std::iter::empty()),
        Err(TrustedKeysError::Empty)
    );
}

#[test]
fn a_key_set_refuses_the_all_zero_key_anywhere_in_the_set() {
    let real = *key(1).public_key();
    assert_eq!(
        TrustedKeys::new([[0_u8; 32]]),
        Err(TrustedKeysError::ZeroKey)
    );
    assert_eq!(
        TrustedKeys::new([real, [0_u8; 32]]),
        Err(TrustedKeysError::ZeroKey)
    );
}

#[test]
fn a_key_set_deduplicates_by_key_id_and_ignores_order() {
    let (a, b) = (*key(1).public_key(), *key(2).public_key());
    let set = TrustedKeys::new([a, b, a]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(set.len(), 2);
    assert!(!set.is_empty());
    // Order never changes what verifies: the same root is accepted from
    // either arrangement.
    let reversed = TrustedKeys::new([b, a]).unwrap_or_else(|e| panic!("{e}"));
    let bytes = first_root(&[&key(2)]);
    assert!(check_head(&bytes, VOL, 1, &set).is_ok());
    assert!(check_head(&bytes, VOL, 1, &reversed).is_ok());
}

// --------------------------------------------------------------- head

#[test]
fn head_accepts_a_root_signed_by_the_trusted_key() {
    let k = key(1);
    let bytes = first_root(&[&k]);
    let doc = check_head(&bytes, VOL, 1, &keys_of(&[&k])).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(doc.seq, 1);
    assert_eq!(doc.volume.as_str(), VOL);
}

#[test]
fn head_accepts_a_root_signed_only_by_the_second_of_two_trusted_keys() {
    let (k1, k2) = (key(1), key(2));
    let bytes = first_root(&[&k2]);
    assert!(check_head(&bytes, VOL, 1, &keys_of(&[&k1, &k2])).is_ok());
}

#[test]
fn head_ignores_a_slot_from_a_key_outside_the_set() {
    let (trusted, stranger) = (key(1), key(9));
    let bytes = first_root(&[&stranger, &trusted]);
    assert!(check_head(&bytes, VOL, 1, &keys_of(&[&trusted])).is_ok());
}

#[test]
fn head_refuses_a_root_signed_only_by_an_untrusted_key() {
    let (trusted, stranger) = (key(1), key(9));
    let bytes = first_root(&[&stranger]);
    assert_eq!(
        check_head(&bytes, VOL, 1, &keys_of(&[&trusted])),
        Err(HeadError::NoTrustedSlot)
    );
}

#[test]
fn head_refuses_a_trusted_slot_whose_signature_does_not_verify() {
    let k = key(1);
    let mut bytes = first_root(&[&k]);
    if let Some(last) = bytes.last_mut() {
        *last ^= 0x01;
    }
    assert_eq!(
        check_head(&bytes, VOL, 1, &keys_of(&[&k])),
        Err(HeadError::BadSignature { key_id: k.key_id() })
    );
}

#[test]
fn head_refuses_a_bad_trusted_slot_even_when_another_trusted_key_signed_well() {
    let (k1, k2) = (key(1), key(2));
    // Slot order is k1 then k2; corrupt the LAST signature byte, which is
    // k2's, and the good k1 slot must not rescue it.
    let mut bytes = first_root(&[&k1, &k2]);
    if let Some(last) = bytes.last_mut() {
        *last ^= 0x01;
    }
    assert_eq!(
        check_head(&bytes, VOL, 1, &keys_of(&[&k1, &k2])),
        Err(HeadError::BadSignature {
            key_id: k2.key_id()
        })
    );
}

#[test]
fn head_refuses_bytes_changed_after_signing() {
    let k = key(1);
    let mut bytes = first_root(&[&k]);
    let prefix_len = root::signed_prefix(&bytes)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    // The last prefix byte is inside the sheaf head: the object still
    // decodes, so only the signature can catch it.
    if let Some(byte) = bytes.get_mut(prefix_len - 1) {
        *byte ^= 0x01;
    }
    assert_eq!(
        check_head(&bytes, VOL, 1, &keys_of(&[&k])),
        Err(HeadError::BadSignature { key_id: k.key_id() })
    );
}

#[test]
fn head_refuses_bytes_that_do_not_decode() {
    let k = key(1);
    assert!(matches!(
        check_head(b"not a root", VOL, 1, &keys_of(&[&k])),
        Err(HeadError::Identity(RootIdentityError::Decode(_)))
    ));
}

#[test]
fn head_refuses_a_root_of_another_volume() {
    let k = key(1);
    let bytes = signed_root("other-vol", 1, None, &[&k]);
    assert_eq!(
        check_head(&bytes, VOL, 1, &keys_of(&[&k])),
        Err(HeadError::Identity(RootIdentityError::VolumeMismatch {
            expected: VOL.to_owned(),
            found: "other-vol".to_owned(),
        }))
    );
}

#[test]
fn head_refuses_a_root_at_another_seq() {
    let k = key(1);
    let bytes = first_root(&[&k]);
    assert_eq!(
        check_head(&bytes, VOL, 2, &keys_of(&[&k])),
        Err(HeadError::Identity(RootIdentityError::SeqMismatch {
            expected: 2,
            found: 1,
        }))
    );
}

#[test]
fn head_checks_identity_before_it_reads_a_signature() {
    let (trusted, stranger) = (key(1), key(9));
    let bytes = signed_root("other-vol", 1, None, &[&stranger]);
    assert!(matches!(
        check_head(&bytes, VOL, 1, &keys_of(&[&trusted])),
        Err(HeadError::Identity(
            RootIdentityError::VolumeMismatch { .. }
        ))
    ));
}

// ------------------------------------------------------- source scan

/// The body of the fn whose signature begins with `opens`: from its first
/// `{` to the brace that closes it, found by counting braces outside string
/// literals, char literals and line comments, so the slice ends at the item's
/// own end however it is indented or followed. Comment lines are dropped.
/// Empty when `opens` or a balanced body is not found, which the callers'
/// positive controls then refuse.
fn fn_body(source: &str, opens: &str) -> String {
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or_default();
    let Some(after) = production.split(opens).nth(1) else {
        return String::new();
    };
    let Some(open) = after.find('{') else {
        return String::new();
    };
    let chars: Vec<char> = after.get(open..).unwrap_or_default().chars().collect();
    let mut depth = 0_usize;
    let mut i = 0;
    let mut end = None;
    while let Some(&c) = chars.get(i) {
        match c {
            '/' if chars.get(i + 1) == Some(&'/') => {
                while chars.get(i).is_some_and(|&c| c != '\n') {
                    i += 1;
                }
                continue;
            }
            '"' => {
                i += 1;
                while let Some(&c) = chars.get(i) {
                    if c == '\\' {
                        i += 2;
                        continue;
                    }
                    if c == '"' {
                        break;
                    }
                    i += 1;
                }
            }
            '\'' => {
                // A char literal ('x' or '\x'); a lifetime has no closing quote.
                if chars.get(i + 1) == Some(&'\\') {
                    i += 3;
                } else if chars.get(i + 2) == Some(&'\'') {
                    i += 2;
                }
            }
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let Some(end) = end else {
        return String::new();
    };
    chars
        .get(..=end)
        .unwrap_or_default()
        .iter()
        .collect::<String>()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// **`check_head` verifies over the RECEIVED bytes, never over a
/// re-encoding of the decoded document.**
///
/// A source scan rather than a behavioural row: `encode_root` is
/// canonical, so `signed_prefix(&encode_root(doc))` equals
/// `signed_prefix(bytes)` for any bytes the decoder accepted, and the two
/// implementations are observably identical without a second encoding of
/// one document, which the format exists to make impossible. Encode-then-
/// verify checks bytes THIS PROCESS produced rather than the bytes the
/// publisher signed, so every field the decoder drops or normalises stops
/// being covered by the signature, and the canonical case still passes.
#[test]
fn check_head_verifies_over_the_received_bytes_and_never_a_re_encoding() {
    const SOURCE: &str = include_str!("../root_check.rs");

    // `check_head` verifies through `check_signatures`, whose body holds
    // the signature path this row judges.
    // Comment lines are dropped, so a call commented out does not count.
    let head: String = fn_body(SOURCE, "pub fn check_head(")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        head.contains("check_signatures(&doc, bytes, keys)"),
        "check_head must verify through check_signatures over the bytes it decoded: {head}"
    );
    let body = fn_body(SOURCE, "pub fn check_signatures(");

    // Positive controls first: a gate that cannot tell "clean" from
    // "read nothing" is not a gate.
    assert!(
        body.contains("verify("),
        "this row did not read the code it is judging"
    );
    assert!(
        body.contains("root::signed_prefix(bytes)"),
        "the signature domain must be the RECEIVED bytes: {body}"
    );
    for re_encoded in ["encode_root", "signing_prefix_of"] {
        assert!(
            !body.contains(re_encoded),
            "{re_encoded:?} in the verify path checks the signature against \
             bytes this process produced rather than the bytes the publisher \
             signed"
        );
    }
}
