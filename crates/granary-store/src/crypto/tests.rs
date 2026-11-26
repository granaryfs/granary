// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::crypto` — Ed25519 root-signature signing and
//! verification over a root's signed prefix: the
//! aws-lc-rs import incantation, roundtrips, and rejection of a
//! tampered prefix or signature.
//!
//! Out-of-line: `granary-store`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-server`,
//! `granary-sim`), so the module's own tests move out of
//! the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

/// RFC 8032 §7.1 TEST 1 — the conformance pin that makes committed
/// raw seeds portable: aws-lc-rs's seed IS the RFC private key,
/// and this test keeps that fact load-bearing.
#[test]
fn rfc8032_test_vector_1() {
    let seed: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public: [u8; 32] = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let key =
        SigningKey::from_seed_and_public_key(&seed, &public).unwrap_or_else(|e| panic!("{e}"));
    let sig = key.sign(b"");
    let expected: [u8; 64] = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    assert_eq!(sig, expected);
    verify(&public, b"", &sig).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn generate_extract_reconstruct_sign_identically() {
    let (key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let rebuilt = SigningKey::from_seed_and_public_key(&seed, key.public_key())
        .unwrap_or_else(|e| panic!("{e}"));
    let msg = b"granary root signed prefix";
    assert_eq!(key.sign(msg), rebuilt.sign(msg));
    assert_eq!(key.sign(msg), key.sign(msg), "determinism");
    verify(key.public_key(), msg, &key.sign(msg)).unwrap_or_else(|e| panic!("{e}"));
}

/// `from_seed` (the recovery constructor for a missing `.pub`
/// sidecar) must derive exactly the same key `generate` produced —
/// pinned against the RFC 8032 test vector, independent of this
/// module's own round trips, so the derivation itself is checked,
/// not merely its self-consistency.
#[test]
fn from_seed_alone_reproduces_rfc8032_test_vector_1() {
    let seed: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_public: [u8; 32] =
        hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let key = SigningKey::from_seed(&seed).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(key.public_key(), &expected_public);
    let sig = key.sign(b"");
    verify(&expected_public, b"", &sig).unwrap_or_else(|e| panic!("{e}"));
}

/// `from_seed` and `from_seed_and_public_key` must agree on a
/// freshly generated key — the recovery path derives the identical
/// public key and signs identically, not merely "a valid" key.
#[test]
fn from_seed_alone_matches_generate_and_the_checking_constructor() {
    let (key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let derived = SigningKey::from_seed(&seed).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(derived.public_key(), key.public_key());
    let msg = b"granary root signed prefix";
    assert_eq!(derived.sign(msg), key.sign(msg));
    verify(derived.public_key(), msg, &derived.sign(msg)).unwrap_or_else(|e| panic!("{e}"));
}

/// The all-zero seed is a legal keypair (documented above at
/// `zeroed_key_material_fails_closed`) — `from_seed` alone must
/// reproduce its independently-derived public key too, the same
/// literal the checking-constructor test pins.
#[test]
fn from_seed_alone_on_the_all_zero_seed_matches_the_checking_constructor() {
    let zero_seed = [0u8; SEED_LEN];
    let its_public: [u8; PUBLIC_KEY_LEN] =
        hex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    let key = SigningKey::from_seed(&zero_seed).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(key.public_key(), &its_public);
}

#[test]
fn tampered_message_and_signature_fail() {
    let (key, _) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let msg = b"granary root signed prefix".to_vec();
    let sig = key.sign(&msg);
    let mut bad_msg = msg.clone();
    bad_msg[0] ^= 1;
    assert_eq!(verify(key.public_key(), &bad_msg, &sig), Err(VerifyError));
    let mut bad_sig = sig;
    bad_sig[63] ^= 1;
    assert_eq!(verify(key.public_key(), &msg, &bad_sig), Err(VerifyError));
    // Wrong key.
    let (other, _) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(verify(other.public_key(), &msg, &sig), Err(VerifyError));
}

#[test]
fn swapped_seed_and_public_are_rejected() {
    let (key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    // from_seed_and_public_key validates consistency — the reason
    // it, not from_seed_unchecked, is the constructor.
    assert!(matches!(
        SigningKey::from_seed_and_public_key(key.public_key(), &seed),
        Err(CryptoError::BadKeyMaterial)
    ));
}

/// Realistic "seed file read back as zeros" case (a truncated key
/// file, a `/dev/zero` read, an unwritten disk block): three of the
/// four seed/public-key combinations below are zero and must ALL
/// fail closed. This is the strongest argument for
/// `from_seed_and_public_key` (which validates the pair) over
/// `from_seed_unchecked` (which would trust the caller's public key
/// outright) — `swapped_seed_and_public_are_rejected` above covers
/// the swap, not the zero case.
///
/// NOT covered by an assertion here, and worth recording instead:
/// the all-zero seed WITH its OWN matching public key
/// (`3b6a27bc…`, independently derived and pinned below in
/// `all_zero_seed_paired_with_its_own_public_key_is_accepted`) is a
/// legal Ed25519 keypair — the all-zero scalar is a valid (if
/// publicly known) private key, and aws-lc-rs accepts it and signs
/// with it. That is defensible (nothing in Ed25519 requires a seed
/// to be secret-LOOKING) but adopting it as an actual signing key
/// requires deliberately supplying BOTH halves correctly — a zeroed
/// seed alone, or paired with any OTHER key's public half, is
/// refused by every case below.
#[test]
fn zeroed_key_material_fails_closed() {
    let (key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let zero_seed = [0u8; SEED_LEN];
    let zero_public = [0u8; PUBLIC_KEY_LEN];

    // Zero seed + a real (unrelated) public key: the zero seed
    // cannot produce that key.
    assert!(matches!(
        SigningKey::from_seed_and_public_key(&zero_seed, key.public_key()),
        Err(CryptoError::BadKeyMaterial)
    ));
    // A real seed + zero public key: that seed does not produce the
    // all-zero point.
    assert!(matches!(
        SigningKey::from_seed_and_public_key(&seed, &zero_public),
        Err(CryptoError::BadKeyMaterial)
    ));
    // Zero + zero: the all-zero seed's OWN public key is real but
    // non-zero (see the doc comment above and the test below) —
    // zero_public is still the WRONG key for it.
    assert!(matches!(
        SigningKey::from_seed_and_public_key(&zero_seed, &zero_public),
        Err(CryptoError::BadKeyMaterial)
    ));
}

/// The one behaviour the doc comment above records rather than
/// merely asserts: paired with its OWN public key, the all-zero
/// seed is a legal Ed25519 keypair that signs and verifies
/// correctly — a legal, if publicly known, key. The public key
/// (`3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29`)
/// was independently derived (SHA-512 seed expansion, clamping,
/// scalar multiplication by the base point, point compression — the
/// same computation this module's `SigningKey::generate` path
/// performs, done separately here) and cross-checked against this
/// module's own committed RFC 8032 TEST 1 vector before being
/// trusted as a literal; it is not a value invented for this test.
#[test]
fn all_zero_seed_paired_with_its_own_public_key_is_accepted() {
    let zero_seed = [0u8; SEED_LEN];
    let its_public: [u8; PUBLIC_KEY_LEN] =
        hex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    let key = SigningKey::from_seed_and_public_key(&zero_seed, &its_public)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(key.public_key(), &its_public);
    let msg = b"granary root signed prefix";
    let sig = key.sign(msg);
    verify(&its_public, msg, &sig).unwrap_or_else(|e| panic!("{e}"));
}

/// Ed25519 group order `L` (RFC 8032 §5.1), little-endian —
/// `2^252 + 27742317777372353535851937790883648493`. Independently
/// computed from that decimal definition, not copied from a library
/// header.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// 256-bit little-endian addition, no modular reduction. A valid
/// signature's `S` is always `< L` (canonical), so `S + L < 2L <
/// 2^253` and the sum never overflows the 32-byte result — exact
/// for exactly this use, not a general-purpose bignum.
fn add_le_256(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "deliberate: the low byte of a base-256 digit sum, exactly \
                       what the carry on the next line accounts for"
        )]
        {
            out[i] = sum as u8;
        }
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L overflowed 256 bits — S was not < L");
    out
}

/// Ed25519 signature canonicality: the low 32 bytes (`S`) of a
/// signature must encode a value `< L` (RFC 8032 §5.1 verification
/// step 2 — some implementations skip this check and accept
/// `S + L`, `S + 2L`, … as "the same" signature). The format leaves
/// the SIGNATURE SECTION malleable BY DESIGN (`sig_count` and slot
/// order are unauthenticated; policy lives in trust metadata) —
/// that choice makes per-signature canonicality MORE load-bearing,
/// not less: it is what stops each individual slot ALSO becoming a
/// malleability surface stacked on top of the section-level one
/// the format already permits. `S' = S + L` re-encodes the identical
/// scalar (mod L, so the verification equation is unaffected) as a
/// non-canonical 32-byte string; a `verify` that accepted it would
/// give one message many "different" valid signature encodings.
#[test]
fn non_canonical_signature_s_plus_l_is_rejected() {
    let (key, _) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let msg = b"granary root signed prefix";
    let sig = key.sign(msg);
    verify(key.public_key(), msg, &sig).unwrap_or_else(|e| panic!("{e}"));

    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..64]);
    let s_plus_l = add_le_256(&s, &L);
    let mut malleated = sig;
    malleated[32..64].copy_from_slice(&s_plus_l);
    assert_ne!(malleated, sig, "S + L must differ from S as bytes");

    assert_eq!(
        verify(key.public_key(), msg, &malleated),
        Err(VerifyError),
        "S + L is a non-canonical re-encoding of the same scalar mod L; \
         a correct verifier rejects it"
    );
}

/// Hostile public keys (untrusted input — house rule: never panic).
/// Each is a 32-byte pattern from a documented Ed25519 edge case,
/// independently derived and verified against a from-scratch
/// point-arithmetic implementation (cross-checked against this
/// module's own RFC 8032 TEST 1 vector) rather than copied from
/// memory:
/// - **off-curve**: `y = 2` (`02 00…00`) has no valid `x` on the
///   curve at all — `x² = (y²−1)/(dy²+1)` is a non-residue for
///   BOTH sign choices, confirmed by point decompression, not
///   merely asserted.
/// - **non-canonical** (`y ≥ p`): all-`0xff` — sign bit set, and
///   the remaining 255 bits all set give `y = 2²⁵⁵−1`, which is
///   `≥ p = 2²⁵⁵−19`. The textbook "did you reduce mod p before
///   comparing" case.
/// - **small-order**: a genuine order-8 point (a generator of the
///   curve's 8-element torsion subgroup — not the identity, and not
///   the same bytes as the all-zero case below, though both decode
///   to valid low-order points).
/// - **all-zero**: the all-zero 32 bytes decode as a VALID,
///   order-4 curve point — not a decode failure at all, just a
///   public key that could never have produced a signature over
///   any message a real signer chose.
///
/// None of these bytes are near a real key, so `verify` fails on
/// every one; the property under test is that it fails WITHOUT
/// panicking, whether the underlying cause is a decode failure, a
/// valid-but-degenerate point, or simply a mismatched signature.
#[test]
fn hostile_public_keys_do_not_panic() {
    let (key, _) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let msg = b"granary root signed prefix";
    let sig = key.sign(msg);

    let off_curve: [u8; PUBLIC_KEY_LEN] =
        hex("0200000000000000000000000000000000000000000000000000000000000000");
    let non_canonical: [u8; PUBLIC_KEY_LEN] =
        hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let small_order: [u8; PUBLIC_KEY_LEN] =
        hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
    let all_zero = [0u8; PUBLIC_KEY_LEN];

    for hostile in [off_curve, non_canonical, small_order, all_zero] {
        assert_eq!(verify(&hostile, msg, &sig), Err(VerifyError));
    }
}

#[test]
fn key_id_is_sha256_of_raw_public_key() {
    // RFC 8032 TV1 public key → its SHA-256, computed independently
    // (python3 hashlib) and pinned as a literal so the DEFINITION
    // (raw key bytes, no envelope) cannot drift.
    let public: [u8; 32] = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected: [u8; 32] =
        hex("21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9");
    assert_eq!(key_id(&public), expected);
}

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let byte = s.get(i * 2..i * 2 + 2).unwrap_or_else(|| panic!("hex len"));
        *slot = u8::from_str_radix(byte, 16).unwrap_or_else(|e| panic!("{e}"));
    }
    out
}
