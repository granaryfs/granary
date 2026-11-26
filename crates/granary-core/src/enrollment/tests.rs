// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::enrollment`.
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (coding-standards rule 18).

use std::collections::VecDeque;

use super::*;

/// The empty set.
const GOLDEN_EMPTY_HEX: &str = "47524e454e524f4c00010000000000000000\
     0ffb666ffa645872b8e5a6484e0019624c42bcc7afc574aaf2fcfe359550beaf";
/// Principal 0x01..=0x10, active, tenant `acme`; credential 0x20..=0x3F.
const GOLDEN_ONE_HEX: &str = "47524e454e524f4c000100000001000000010102030405060708090a0b0c0d0e0f10010461636d6501202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0102030405060708090a0b0c0d0e0f10\
     8137525d32e3cb956641ee0f54729a6a99f82d36bf07fcf52f4c3197cba3c2b2";
/// Principal 0x01..=0x10, active, tenant `acme`, with credentials
/// 0x20..=0x3F and 0xA0..=0xBF; principal 0x80..=0x8F, retired, tenant
/// `old-tenant`.
const GOLDEN_RETIRED_HEX: &str = "47524e454e524f4c000100000002000000020102030405060708090a0b0c0d0e0f10010461636d65808182838485868788898a8b8c8d8e8f020a6f6c642d74656e616e7401202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0102030405060708090a0b0c0d0e0f1001a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0102030405060708090a0b0c0d0e0f10\
     874a9bf19929efb91796a98bd21c9023ce825fb2275041192cdc5a430b51c981";

/// The client-SPKI digest of [`golden_spki`].
const GOLDEN_SPKI_DIGEST_HEX: &str =
    "b74706d36193ae6869a5bb5e67d31b0b4f07c57bdf47372143871794cbbb026f";

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap_or_else(|e| panic!("{e}"))))
}

fn p1() -> PrincipalId {
    PrincipalId::from_bytes(seq(0x01))
}

fn p_retired() -> PrincipalId {
    PrincipalId::from_bytes(seq(0x80))
}

fn d1() -> ClientSpkiDigest {
    ClientSpkiDigest::from_bytes(seq(0x20))
}

fn d2() -> ClientSpkiDigest {
    ClientSpkiDigest::from_bytes(seq(0xA0))
}

fn tenant(s: &str) -> TenantName {
    TenantName::parse(s).unwrap_or_else(|e| panic!("{e}"))
}

fn ok<T, E: std::fmt::Display>(r: Result<T, E>) -> T {
    r.unwrap_or_else(|e| panic!("{e}"))
}

fn one_set() -> EnrollmentSet {
    let mut set = EnrollmentSet::empty();
    ok(set.mint(p1(), tenant("acme"), d1()));
    set
}

fn retired_set() -> EnrollmentSet {
    let mut set = one_set();
    ok(set.attach(p1(), d2()));
    ok(set.mint(
        p_retired(),
        tenant("old-tenant"),
        ClientSpkiDigest::from_bytes([0x55; 32]),
    ));
    ok(set.revoke(&ClientSpkiDigest::from_bytes([0x55; 32])));
    ok(set.retire(&p_retired()));
    set
}

fn goldens() -> [(EnrollmentSet, Vec<u8>); 3] {
    [
        (EnrollmentSet::empty(), unhex(GOLDEN_EMPTY_HEX)),
        (one_set(), unhex(GOLDEN_ONE_HEX)),
        (retired_set(), unhex(GOLDEN_RETIRED_HEX)),
    ]
}

/// `body` (everything before the check) with a correct check appended, so a
/// test can be wrong in exactly one way.
fn checked(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.extend_from_slice(&blake3::derive_key(CHECK_CONTEXT, body));
    out
}

/// A raw principal record.
struct RawP<'a> {
    id: [u8; 16],
    state: u8,
    tenant_len: u8,
    tenant: &'a [u8],
}

fn rp(id: [u8; 16], state: u8, tenant: &[u8]) -> RawP<'_> {
    RawP {
        id,
        state,
        tenant_len: u8::try_from(tenant.len()).unwrap_or_else(|e| panic!("{e}")),
        tenant,
    }
}

/// A raw credential record.
struct RawC {
    kind: u8,
    digest: [u8; 32],
    principal: [u8; 16],
}

fn rc(digest: [u8; 32], principal: [u8; 16]) -> RawC {
    RawC {
        kind: 0x01,
        digest,
        principal,
    }
}

/// A body (no check) with the given header fields and records, written
/// without any of the codec's rules, so a test can break exactly one.
fn raw_body(version: u16, p_count: u32, c_count: u32, ps: &[RawP<'_>], cs: &[RawC]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"GRNENROL");
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&p_count.to_be_bytes());
    out.extend_from_slice(&c_count.to_be_bytes());
    for p in ps {
        out.extend_from_slice(&p.id);
        out.push(p.state);
        out.push(p.tenant_len);
        out.extend_from_slice(p.tenant);
    }
    for c in cs {
        out.push(c.kind);
        out.extend_from_slice(&c.digest);
        out.extend_from_slice(&c.principal);
    }
    out
}

/// A correctly checked file of version 1 whose counts match its records.
fn raw(ps: &[RawP<'_>], cs: &[RawC]) -> Vec<u8> {
    let pc = u32::try_from(ps.len()).unwrap_or_else(|e| panic!("{e}"));
    let cc = u32::try_from(cs.len()).unwrap_or_else(|e| panic!("{e}"));
    checked(&raw_body(1, pc, cc, ps, cs))
}

#[track_caller]
fn refused(bytes: &[u8], want: SetDecodeError) {
    assert_eq!(decode_set(bytes), Err(want));
}

/// An Ed25519 `SubjectPublicKeyInfo`, DER: the algorithm identifier
/// (OID 1.3.101.112) and a BIT STRING holding the 32-byte key 0x00..=0x1F.
fn golden_spki() -> Vec<u8> {
    let mut spki = unhex("302a300506032b6570032100");
    spki.extend_from_slice(&seq::<32>(0x00));
    spki
}

// ============================================================ golden

#[test]
fn constants_are_pinned() {
    assert_eq!(ENROLLMENT_MAGIC, *b"GRNENROL");
    assert_eq!(ENROLLMENT_VERSION, 1);
    assert_eq!(PRINCIPALS_MAX, 16384);
    assert_eq!(CREDENTIALS_MAX, 16384);
    assert_eq!(ENCODED_MAX, 5_275_698);
    assert_eq!(MIN_LEN, 50);
    assert_eq!(CHECK_CONTEXT, "granary enrollment set v1");
    assert_eq!(SPKI_DIGEST_CONTEXT, "granary client-enrollment spki v1");
}

#[test]
fn goldens_encode_and_decode() {
    for (set, bytes) in goldens() {
        assert_eq!(encode_set(&set).as_bytes(), bytes);
        assert_eq!(decode_set(&bytes), Ok(set));
    }
}

#[test]
fn the_golden_sets_read_back_as_built() {
    let set = ok(decode_set(&unhex(GOLDEN_RETIRED_HEX)));
    assert_eq!(set.principal_count(), 2);
    assert_eq!(set.credential_count(), 2);
    assert_eq!(set.lookup(&d1()), Some((p1(), &tenant("acme"))));
    assert_eq!(set.lookup(&d2()), Some((p1(), &tenant("acme"))));
    assert_eq!(set.lookup(&ClientSpkiDigest::from_bytes([0x55; 32])), None);
    assert_eq!(
        set.principal(&p_retired()),
        Some((PrincipalState::Retired, &tenant("old-tenant")))
    );
    assert_eq!(
        set.principal(&p1()),
        Some((PrincipalState::Active, &tenant("acme")))
    );
    let principals: Vec<_> = set
        .principals()
        .map(|(id, s, t)| (id, s, t.clone()))
        .collect();
    assert_eq!(
        principals,
        vec![
            (p1(), PrincipalState::Active, tenant("acme")),
            (p_retired(), PrincipalState::Retired, tenant("old-tenant")),
        ]
    );
    let credentials: Vec<_> = set.credentials().collect();
    assert_eq!(credentials, vec![(d1(), p1()), (d2(), p1())]);
}

#[test]
fn round_trip_over_many_sets() {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };
    for _ in 0..64 {
        let mut set = EnrollmentSet::empty();
        for _ in 0..(next() % 12) {
            let mut id = [0u8; 16];
            let mut digest = [0u8; 32];
            for chunk in id.chunks_mut(8).chain(digest.chunks_mut(8)) {
                chunk.copy_from_slice(&next().to_be_bytes());
            }
            let len = usize::try_from(next() % 255).unwrap_or(0) + 1;
            let name: Vec<u8> = (0..len)
                .map(|_| 0x21 + u8::try_from(next() % 94).unwrap_or(0))
                .collect();
            let id = PrincipalId::from_bytes(id);
            ok(set.mint(
                id,
                ok(TenantName::new(&name)),
                ClientSpkiDigest::from_bytes(digest),
            ));
            if next() % 3 == 0 {
                ok(set.revoke(&ClientSpkiDigest::from_bytes(digest)));
                ok(set.retire(&id));
            }
        }
        let encoded = encode_set(&set);
        let decoded = ok(decode_set(encoded.as_bytes()));
        assert_eq!(decoded, set);
        assert_eq!(encode_set(&decoded), encoded);
    }
}

// ============================================================ check

#[test]
fn a_check_over_the_wrong_range_or_context_is_refused() {
    let full = unhex(GOLDEN_ONE_HEX);
    let body = &full[..full.len() - CHECK_LEN];

    let mut short_range = body.to_vec();
    short_range.extend_from_slice(&blake3::derive_key(CHECK_CONTEXT, &body[8..]));
    refused(&short_range, SetDecodeError::BadCheck);

    let mut other_context = body.to_vec();
    other_context.extend_from_slice(&blake3::derive_key("granary enrollment set v2", body));
    refused(&other_context, SetDecodeError::BadCheck);

    let mut plain = body.to_vec();
    plain.extend_from_slice(blake3::hash(body).as_bytes());
    refused(&plain, SetDecodeError::BadCheck);

    assert_eq!(decode_set(&checked(body)), Ok(one_set()));
}

// ============================================================ rejects

#[test]
fn every_truncation_is_refused() {
    for (_, golden) in goldens() {
        for len in 0..golden.len() {
            let want = if len < MIN_LEN {
                SetDecodeError::TooShort { len }
            } else {
                SetDecodeError::BadCheck
            };
            assert_eq!(
                decode_set(&golden[..len]),
                Err(want),
                "truncated to {len} of {}",
                golden.len()
            );
        }
    }
}

#[test]
fn a_trailing_byte_is_a_bad_check_or_trailing_data() {
    for (_, golden) in goldens() {
        let mut longer = golden.clone();
        longer.push(0x00);
        refused(&longer, SetDecodeError::BadCheck);

        // The check recomputed over the body plus one byte.
        let mut body = golden[..golden.len() - CHECK_LEN].to_vec();
        body.push(0x00);
        refused(&checked(&body), SetDecodeError::TrailingData { len: 1 });
    }
}

#[test]
fn every_flipped_byte_is_a_bad_check_or_a_bad_magic() {
    for (_, golden) in goldens() {
        for i in 0..golden.len() {
            for mask in [0x01_u8, 0xFF] {
                let mut bytes = golden.clone();
                bytes[i] ^= mask;
                let want = if i < ENROLLMENT_MAGIC.len() {
                    SetDecodeError::BadMagic
                } else {
                    SetDecodeError::BadCheck
                };
                assert_eq!(
                    decode_set(&bytes),
                    Err(want),
                    "byte {i} of {} xor {mask:#04x}",
                    golden.len()
                );
            }
        }
    }
}

#[test]
fn bad_magic_with_a_valid_check_is_refused() {
    let mut body = raw_body(1, 0, 0, &[], &[]);
    body[0] = b'X';
    refused(&checked(&body), SetDecodeError::BadMagic);
}

#[test]
fn a_correctly_checked_version_2_is_refused() {
    refused(
        &checked(&raw_body(2, 0, 0, &[], &[])),
        SetDecodeError::UnknownVersion { version: 2 },
    );
}

#[test]
fn counts_over_the_bound_are_refused() {
    for count in [16385_u32, u32::MAX] {
        refused(
            &checked(&raw_body(1, count, 0, &[], &[])),
            SetDecodeError::CountOverBound {
                list: RecordList::Principals,
                count,
            },
        );
        refused(
            &checked(&raw_body(1, 0, count, &[], &[])),
            SetDecodeError::CountOverBound {
                list: RecordList::Credentials,
                count,
            },
        );
    }
    // The principal count is checked first.
    refused(
        &checked(&raw_body(1, 16385, 16385, &[], &[])),
        SetDecodeError::CountOverBound {
            list: RecordList::Principals,
            count: 16385,
        },
    );
}

#[test]
fn counts_that_overrun_the_length_are_refused() {
    refused(
        &checked(&raw_body(1, 1, 0, &[], &[])),
        SetDecodeError::CountsOverrunLength,
    );
    refused(
        &checked(&raw_body(1, 0, 1, &[], &[])),
        SetDecodeError::CountsOverrunLength,
    );
    refused(
        &checked(&raw_body(1, 16384, 16384, &[], &[])),
        SetDecodeError::CountsOverrunLength,
    );
    // The fixed parts fit, but a tenant runs past the end: one principal
    // claiming a 9-byte tenant with 4 bytes present.
    let p = RawP {
        id: seq(1),
        state: 1,
        tenant_len: 9,
        tenant: b"acme",
    };
    refused(
        &checked(&raw_body(1, 1, 0, &[p], &[])),
        SetDecodeError::CountsOverrunLength,
    );
    // Long tenants leave the credentials short.
    let long = [b'a'; 40];
    refused(
        &checked(&raw_body(1, 1, 1, &[rp(seq(1), 1, &long)], &[])),
        SetDecodeError::CountsOverrunLength,
    );
}

#[test]
fn invalid_states_are_refused() {
    for tag in [0x00, 0x03, 0xFF] {
        refused(
            &raw(&[rp(seq(1), tag, b"acme")], &[]),
            SetDecodeError::InvalidState { index: 0, tag },
        );
    }
}

#[test]
fn a_zero_tenant_length_is_refused() {
    refused(
        &raw(&[rp(seq(1), 1, b"")], &[]),
        SetDecodeError::BadTenantLength { index: 0 },
    );
}

#[test]
fn tenant_bytes_outside_the_charset_are_refused() {
    for byte in [0x20, 0x7F, 0x00, 0x80, 0xFF] {
        refused(
            &raw(&[rp(seq(1), 1, &[b'a', byte, b'b'])], &[]),
            SetDecodeError::BadTenantByte { index: 0, byte },
        );
    }
    // Both edges of the charset are accepted.
    assert!(decode_set(&raw(&[rp(seq(1), 1, &[0x21, 0x7E])], &[])).is_ok());
}

#[test]
fn principals_out_of_order_or_duplicated_are_refused() {
    refused(
        &raw(&[rp(seq(2), 1, b"a"), rp(seq(1), 1, b"b")], &[]),
        SetDecodeError::PrincipalsNotAscending { index: 1 },
    );
    refused(
        &raw(&[rp(seq(1), 1, b"a"), rp(seq(1), 2, b"b")], &[]),
        SetDecodeError::PrincipalsNotAscending { index: 1 },
    );
}

#[test]
fn credentials_out_of_order_or_duplicated_are_refused() {
    let ps = [rp(seq(1), 1, b"a"), rp(seq(2), 1, b"b")];
    refused(
        &raw(&ps, &[rc(seq(0x40), seq(1)), rc(seq(0x30), seq(1))]),
        SetDecodeError::CredentialsNotAscending { index: 1 },
    );
    refused(
        &raw(&ps, &[rc(seq(0x40), seq(1)), rc(seq(0x40), seq(1))]),
        SetDecodeError::CredentialsNotAscending { index: 1 },
    );
    // The same digest under two principals.
    refused(
        &raw(&ps, &[rc(seq(0x40), seq(1)), rc(seq(0x40), seq(2))]),
        SetDecodeError::CredentialsNotAscending { index: 1 },
    );
}

#[test]
fn a_credential_naming_an_absent_principal_is_refused() {
    refused(
        &raw(&[rp(seq(1), 1, b"a")], &[rc(seq(0x40), seq(9))]),
        SetDecodeError::CredentialPrincipalAbsent { index: 0 },
    );
}

#[test]
fn a_credential_naming_a_retired_principal_is_refused() {
    refused(
        &raw(&[rp(seq(1), 2, b"a")], &[rc(seq(0x40), seq(1))]),
        SetDecodeError::CredentialPrincipalRetired { index: 0 },
    );
}

#[test]
fn invalid_credential_kinds_are_refused() {
    for kind in [0x00, 0x02, 0xFF] {
        let c = RawC {
            kind,
            digest: seq(0x40),
            principal: seq(1),
        };
        refused(
            &raw(&[rp(seq(1), 1, b"a")], &[c]),
            SetDecodeError::InvalidCredentialKind { index: 0, kind },
        );
    }
}

// ============================================================ bounds

fn nth_id(n: usize) -> PrincipalId {
    let mut id = [0u8; 16];
    id[12..].copy_from_slice(
        &u32::try_from(n)
            .unwrap_or_else(|e| panic!("{e}"))
            .to_be_bytes(),
    );
    PrincipalId::from_bytes(id)
}

fn nth_digest(n: usize) -> ClientSpkiDigest {
    let mut d = [0u8; 32];
    d[28..].copy_from_slice(
        &u32::try_from(n)
            .unwrap_or_else(|e| panic!("{e}"))
            .to_be_bytes(),
    );
    ClientSpkiDigest::from_bytes(d)
}

#[test]
fn a_set_at_both_bounds_is_exactly_the_largest_encoding() {
    let longest = ok(TenantName::new(&[b'x'; TENANT_NAME_MAX]));
    let mut set = EnrollmentSet::empty();
    for n in 0..PRINCIPALS_MAX {
        ok(set.mint(nth_id(n), longest.clone(), nth_digest(n)));
    }
    let encoded = encode_set(&set);
    assert_eq!(encoded.as_bytes().len(), ENCODED_MAX);
    assert_eq!(decode_set(encoded.as_bytes()).as_ref(), Ok(&set));

    // Both bounds reached: mint refuses at the principal bound, attach at
    // the credential bound, and the set is unchanged.
    let before = set.clone();
    assert_eq!(
        set.mint(nth_id(PRINCIPALS_MAX), longest, nth_digest(PRINCIPALS_MAX)),
        Err(SetChangeError::PrincipalBoundReached)
    );
    assert_eq!(
        set.attach(nth_id(0), nth_digest(PRINCIPALS_MAX)),
        Err(SetChangeError::CredentialBoundReached)
    );
    assert_eq!(set, before);
}

#[test]
fn mint_refuses_at_the_principal_bound() {
    let mut set = EnrollmentSet::empty();
    for n in 0..PRINCIPALS_MAX {
        ok(set.mint(nth_id(n), tenant("t"), nth_digest(n)));
    }
    ok(set.revoke(&nth_digest(0)));
    let before = set.clone();
    assert_eq!(
        set.mint(
            nth_id(PRINCIPALS_MAX),
            tenant("t"),
            nth_digest(PRINCIPALS_MAX)
        ),
        Err(SetChangeError::PrincipalBoundReached)
    );
    assert_eq!(set, before);
}

#[test]
fn mint_and_attach_refuse_at_the_credential_bound() {
    let mut set = EnrollmentSet::empty();
    for n in 0..CREDENTIALS_MAX / 2 {
        ok(set.mint(nth_id(n), tenant("t"), nth_digest(2 * n)));
        ok(set.attach(nth_id(n), nth_digest(2 * n + 1)));
    }
    assert_eq!(set.credential_count(), CREDENTIALS_MAX);
    let before = set.clone();
    assert_eq!(
        set.mint(
            nth_id(CREDENTIALS_MAX),
            tenant("t"),
            nth_digest(CREDENTIALS_MAX)
        ),
        Err(SetChangeError::CredentialBoundReached)
    );
    assert_eq!(
        set.attach(nth_id(0), nth_digest(CREDENTIALS_MAX)),
        Err(SetChangeError::CredentialBoundReached)
    );
    assert_eq!(set, before);
}

// ============================================================ mutations

#[test]
fn mutations_refuse_and_leave_the_set_unchanged() {
    let mut set = retired_set();
    let before = set.clone();
    let fresh = ClientSpkiDigest::from_bytes([0x77; 32]);
    let absent = PrincipalId::from_bytes([0x66; 16]);

    let cases: [(&str, Result<(), SetChangeError>, SetChangeError); 10] = [
        (
            "mint over an active id",
            set.mint(p1(), tenant("x"), fresh),
            SetChangeError::PrincipalExists,
        ),
        (
            "mint over a retired id",
            set.mint(p_retired(), tenant("x"), fresh),
            SetChangeError::PrincipalExists,
        ),
        (
            "mint an enrolled digest",
            set.mint(absent, tenant("x"), d1()),
            SetChangeError::CredentialEnrolled,
        ),
        (
            "attach to an absent principal",
            set.attach(absent, fresh),
            SetChangeError::PrincipalAbsent,
        ),
        (
            "attach to a retired principal",
            set.attach(p_retired(), fresh),
            SetChangeError::PrincipalRetired,
        ),
        (
            "attach an enrolled digest",
            set.attach(p1(), d2()),
            SetChangeError::CredentialEnrolled,
        ),
        (
            "revoke an absent digest",
            set.revoke(&fresh),
            SetChangeError::CredentialNotEnrolled,
        ),
        (
            "retire an absent principal",
            set.retire(&absent),
            SetChangeError::PrincipalAbsent,
        ),
        (
            "retire a retired principal",
            set.retire(&p_retired()),
            SetChangeError::PrincipalRetired,
        ),
        (
            "retire a principal holding credentials",
            set.retire(&p1()),
            SetChangeError::PrincipalHoldsCredentials,
        ),
    ];
    for (what, got, want) in cases {
        assert_eq!(got, Err(want), "{what}");
    }
    assert_eq!(set, before);
}

#[test]
fn rotation_and_retirement_flow() {
    let mut set = one_set();
    // Rotation: attach the new credential, then revoke the old.
    ok(set.attach(p1(), d2()));
    ok(set.revoke(&d1()));
    assert_eq!(set.lookup(&d1()), None);
    assert_eq!(set.lookup(&d2()), Some((p1(), &tenant("acme"))));
    // Revoking the last credential keeps the record active and attachable.
    ok(set.revoke(&d2()));
    assert_eq!(
        set.principal(&p1()),
        Some((PrincipalState::Active, &tenant("acme")))
    );
    ok(set.attach(p1(), d1()));
    ok(set.revoke(&d1()));
    ok(set.retire(&p1()));
    assert_eq!(
        set.principal(&p1()),
        Some((PrincipalState::Retired, &tenant("acme")))
    );
    assert_eq!(set.principal_count(), 1);
    assert_eq!(set.credential_count(), 0);
    let round = ok(decode_set(encode_set(&set).as_bytes()));
    assert_eq!(round, set);
}

// ============================================================ minting

enum Step {
    Bytes([u8; 16]),
    /// Write this many bytes, then fail.
    FailAfter(usize),
}

/// A door that plays a script and counts its draws.
struct ScriptedDoor {
    steps: VecDeque<Step>,
    draws: usize,
}

impl ScriptedDoor {
    fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            draws: 0,
        }
    }
}

impl SecureRandom for ScriptedDoor {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        self.draws += 1;
        match self.steps.pop_front() {
            Some(Step::Bytes(b)) => {
                dest.copy_from_slice(&b);
                Ok(())
            }
            Some(Step::FailAfter(n)) => {
                for byte in dest.iter_mut().take(n) {
                    *byte = 0xEE;
                }
                Err(EntropyUnavailable)
            }
            None => panic!("the script ran out"),
        }
    }
}

#[test]
fn mint_redraws_an_id_equal_to_a_retired_record() {
    let set = retired_set();
    let fresh = [0x42; 16];
    let mut door = ScriptedDoor::new([Step::Bytes(*p_retired().as_bytes()), Step::Bytes(fresh)]);
    assert_eq!(
        mint_principal_id(&mut door, &set),
        Ok(PrincipalId::from_bytes(fresh))
    );
    assert_eq!(door.draws, 2);
}

#[test]
fn mint_redraws_an_id_equal_to_an_active_record() {
    let set = retired_set();
    let fresh = [0x43; 16];
    let mut door = ScriptedDoor::new([Step::Bytes(*p1().as_bytes()), Step::Bytes(fresh)]);
    assert_eq!(
        mint_principal_id(&mut door, &set),
        Ok(PrincipalId::from_bytes(fresh))
    );
    assert_eq!(door.draws, 2);
}

#[test]
fn mint_takes_the_first_fresh_draw_whole() {
    let mut door = ScriptedDoor::new([Step::Bytes(seq(0x90))]);
    assert_eq!(
        mint_principal_id(&mut door, &EnrollmentSet::empty()),
        Ok(PrincipalId::from_bytes(seq(0x90)))
    );
    assert_eq!(door.draws, 1);
}

#[test]
fn an_entropy_failure_after_a_partial_fill_mints_nothing() {
    let set = retired_set();
    let mut door = ScriptedDoor::new([Step::FailAfter(7)]);
    assert_eq!(mint_principal_id(&mut door, &set), Err(MintError::Entropy));
    // A failure on a redraw is the same refusal.
    let mut door = ScriptedDoor::new([Step::Bytes(*p1().as_bytes()), Step::FailAfter(15)]);
    assert_eq!(mint_principal_id(&mut door, &set), Err(MintError::Entropy));
    assert_eq!(door.draws, 2);
}

#[test]
fn eight_colliding_draws_give_up() {
    let set = retired_set();
    let mut door = ScriptedDoor::new((0..8).map(|_| Step::Bytes(*p1().as_bytes())));
    assert_eq!(
        mint_principal_id(&mut door, &set),
        Err(MintError::Collisions)
    );
    assert_eq!(door.draws, 8);
}

// ============================================================ digest

#[test]
fn the_spki_digest_is_pinned() {
    let spki = golden_spki();
    assert_eq!(spki.len(), 44);
    let digest = ClientSpkiDigest::from_spki_der(&spki);
    assert_eq!(hex(digest.as_bytes()), GOLDEN_SPKI_DIGEST_HEX);
    assert_eq!(
        digest.to_string(),
        format!("clientspki-v1:{GOLDEN_SPKI_DIGEST_HEX}")
    );
    assert_eq!(
        ClientSpkiDigest::parse_written(&digest.to_string()),
        Ok(digest)
    );
}

/// The digest is neither the unkeyed hash of the SPKI nor a key derived
/// under another context, so it cannot be confused with another digest of
/// the same key.
#[test]
fn the_spki_digest_is_domain_separated() {
    let spki = golden_spki();
    let digest = ClientSpkiDigest::from_spki_der(&spki);
    assert_ne!(digest.as_bytes(), blake3::hash(&spki).as_bytes());
    assert_ne!(
        *digest.as_bytes(),
        blake3::derive_key("granary client-enrollment spki v2", &spki)
    );
    assert_ne!(
        *digest.as_bytes(),
        blake3::derive_key("granary enrollment set v1", &spki)
    );
    assert_ne!(digest, ClientSpkiDigest::from_spki_der(&spki[..43]));
}

// ============================================================ written forms

#[test]
fn principal_written_form_round_trips() {
    let id = p1();
    let text = id.to_string();
    assert_eq!(text, "principal:0102030405060708090a0b0c0d0e0f10");
    assert_eq!(PrincipalId::parse_written(&text), Ok(id));
    assert_eq!(id.to_principal().as_bytes(), id.as_bytes());
}

#[test]
fn principal_written_form_is_strict() {
    let good = "0102030405060708090a0b0c0d0e0f10";
    let cases: &[(String, WrittenFormError)] = &[
        (
            format!("principal:{}", good.to_uppercase()),
            WrittenFormError::NotLowercaseHex,
        ),
        (
            format!("principal:{}", &good[1..]),
            WrittenFormError::WrongLength {
                expected: 32,
                len: 31,
            },
        ),
        (
            format!("principal:{good}0"),
            WrittenFormError::WrongLength {
                expected: 32,
                len: 33,
            },
        ),
        (
            format!("principal:{good} "),
            WrittenFormError::WrongLength {
                expected: 32,
                len: 33,
            },
        ),
        (
            format!("principal: {}", &good[1..]),
            WrittenFormError::NotLowercaseHex,
        ),
        (
            good.to_owned(),
            WrittenFormError::WrongPrefix {
                expected: "principal:",
            },
        ),
        (
            format!("Principal:{good}"),
            WrittenFormError::WrongPrefix {
                expected: "principal:",
            },
        ),
        (
            format!("clientspki-v1:{good}{good}"),
            WrittenFormError::WrongPrefix {
                expected: "principal:",
            },
        ),
        (
            format!("principal:{}g", &good[1..]),
            WrittenFormError::NotLowercaseHex,
        ),
    ];
    for (text, want) in cases {
        assert_eq!(PrincipalId::parse_written(text), Err(*want), "{text:?}");
    }
}

#[test]
fn digest_written_form_is_strict() {
    let good = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    assert_eq!(
        ClientSpkiDigest::parse_written(&format!("clientspki-v1:{good}")),
        Ok(d1())
    );
    assert_eq!(d1().to_string(), format!("clientspki-v1:{good}"));
    let cases: &[(String, WrittenFormError)] = &[
        (
            format!("clientspki-v1:{}", good.to_uppercase()),
            WrittenFormError::NotLowercaseHex,
        ),
        (
            format!("clientspki-v1:{}", &good[2..]),
            WrittenFormError::WrongLength {
                expected: 64,
                len: 62,
            },
        ),
        (
            format!(" clientspki-v1:{good}"),
            WrittenFormError::WrongPrefix {
                expected: "clientspki-v1:",
            },
        ),
        (
            format!("clientspki-v1:{good}\n"),
            WrittenFormError::WrongLength {
                expected: 64,
                len: 65,
            },
        ),
        (
            format!("clientspki-v2:{good}"),
            WrittenFormError::WrongPrefix {
                expected: "clientspki-v1:",
            },
        ),
        (
            good.to_owned(),
            WrittenFormError::WrongPrefix {
                expected: "clientspki-v1:",
            },
        ),
    ];
    for (text, want) in cases {
        assert_eq!(
            ClientSpkiDigest::parse_written(text),
            Err(*want),
            "{text:?}"
        );
    }
}

/// The two pastes the protocol warns about, and a key locator, are refused
/// by name by both parsers, never matched.
#[test]
fn pasted_keys_are_refused_by_name() {
    let pin = "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    let root_key = "ed25519:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    let locator = "keyid:202122232425262728292a2b2c2d2e2f";
    for (text, want) in [
        (pin, WrittenFormError::TlsServerPin),
        (root_key, WrittenFormError::RootSigningKey),
        (locator, WrittenFormError::KeyLocator),
    ] {
        assert_eq!(ClientSpkiDigest::parse_written(text), Err(want), "{text}");
        assert_eq!(PrincipalId::parse_written(text), Err(want), "{text}");
    }
    assert!(
        WrittenFormError::TlsServerPin
            .to_string()
            .contains("TLS server pin")
    );
    assert!(
        WrittenFormError::RootSigningKey
            .to_string()
            .contains("root-signing public key")
    );
}

// ============================================================ tenant

#[test]
fn tenant_names_are_checked() {
    assert_eq!(TenantName::new(b""), Err(TenantNameError::Empty));
    assert_eq!(
        TenantName::new(&[b'a'; 256]),
        Err(TenantNameError::TooLong { len: 256 })
    );
    for byte in [0x20, 0x7F, 0x00, 0x0A, 0x80] {
        assert_eq!(
            TenantName::new(&[b'a', byte]),
            Err(TenantNameError::BadByte { byte })
        );
    }
    assert_eq!(
        TenantName::parse("ac me"),
        Err(TenantNameError::BadByte { byte: 0x20 })
    );
    let longest = ok(TenantName::new(&[b'z'; 255]));
    assert_eq!(longest.as_bytes().len(), 255);
    let all: Vec<u8> = (0x21..=0x7E).collect();
    let name = ok(TenantName::new(&all));
    assert_eq!(name.to_string().as_bytes(), all.as_slice());
    assert_eq!(name.to_tenant().as_bytes(), all.as_slice());
}

// ============================================================ messages and probe

#[test]
fn error_messages_are_lowercase_without_a_trailing_period() {
    let mut texts: Vec<String> = [
        SetDecodeError::BadMagic,
        SetDecodeError::TooShort { len: 3 },
        SetDecodeError::BadCheck,
        SetDecodeError::UnknownVersion { version: 2 },
        SetDecodeError::CountOverBound {
            list: RecordList::Credentials,
            count: 16385,
        },
        SetDecodeError::CountsOverrunLength,
        SetDecodeError::InvalidState { index: 0, tag: 0 },
        SetDecodeError::BadTenantLength { index: 0 },
        SetDecodeError::BadTenantByte {
            index: 0,
            byte: 0x20,
        },
        SetDecodeError::PrincipalsNotAscending { index: 1 },
        SetDecodeError::InvalidCredentialKind { index: 0, kind: 2 },
        SetDecodeError::CredentialsNotAscending { index: 1 },
        SetDecodeError::CredentialPrincipalAbsent { index: 0 },
        SetDecodeError::CredentialPrincipalRetired { index: 0 },
        SetDecodeError::TrailingData { len: 1 },
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    texts.extend(
        [
            SetChangeError::PrincipalExists,
            SetChangeError::CredentialEnrolled,
            SetChangeError::PrincipalBoundReached,
            SetChangeError::CredentialBoundReached,
            SetChangeError::PrincipalAbsent,
            SetChangeError::PrincipalRetired,
            SetChangeError::CredentialNotEnrolled,
            SetChangeError::PrincipalHoldsCredentials,
        ]
        .iter()
        .map(ToString::to_string),
    );
    texts.extend(
        [MintError::Entropy, MintError::Collisions]
            .iter()
            .map(ToString::to_string),
    );
    texts.extend(
        [
            TenantNameError::Empty,
            TenantNameError::TooLong { len: 256 },
            TenantNameError::BadByte { byte: 0x20 },
        ]
        .iter()
        .map(ToString::to_string),
    );
    texts.extend(
        [
            WrittenFormError::TlsServerPin,
            WrittenFormError::RootSigningKey,
            WrittenFormError::KeyLocator,
            WrittenFormError::WrongPrefix {
                expected: "principal:",
            },
            WrittenFormError::WrongLength {
                expected: 32,
                len: 3,
            },
            WrittenFormError::NotLowercaseHex,
        ]
        .iter()
        .map(ToString::to_string),
    );
    for text in texts {
        assert!(
            text.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "{text}"
        );
        assert!(!text.ends_with('.'), "{text}");
    }
}

#[test]
fn the_probe_accepts_goldens_and_survives_garbage() {
    for (_, golden) in goldens() {
        crate::testkit::enrollment_decode_probe(&golden);
    }
    crate::testkit::enrollment_decode_probe(&[]);
    crate::testkit::enrollment_decode_probe(&[0xFF; 100]);
    crate::testkit::enrollment_decode_probe(&raw_body(1, 16385, 0, &[], &[]));
}

/// The probe's second decode reaches the accept path: a golden vector with
/// its check bytes damaged is refused as given, and the input the probe
/// rebuilds from it (the check recomputed) decodes to the original set.
#[test]
fn the_probe_recheck_input_reaches_the_accept_path() {
    for (set, golden) in goldens() {
        let mut damaged = golden.clone();
        for byte in damaged.iter_mut().rev().take(CHECK_LEN) {
            *byte ^= 0xA5;
        }
        refused(&damaged, SetDecodeError::BadCheck);
        let rebuilt = crate::testkit::enrollment_recheck_input(&damaged)
            .unwrap_or_else(|| panic!("a long enough input must be rebuilt"));
        assert_eq!(rebuilt, golden);
        assert_eq!(decode_set(&rebuilt), Ok(set));
    }
    assert_eq!(
        crate::testkit::enrollment_recheck_input(&[0; MIN_LEN - 1]),
        None
    );
}

#[test]
fn total_bound_precedes_hash_and_version() {
    // All fields are at their legal maximum, with sorted unique ids and
    // credentials referencing active principals. No encoder is the oracle.
    let mut bytes = Vec::with_capacity(5_275_698);
    bytes.extend_from_slice(b"GRNENROL");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&16384_u32.to_be_bytes());
    bytes.extend_from_slice(&16384_u32.to_be_bytes());
    for n in 0..16384_u128 {
        bytes.extend_from_slice(&n.to_be_bytes());
        bytes.extend_from_slice(&[1, 255]);
        bytes.extend_from_slice(&[b'x'; 255]);
    }
    for n in 0..16384_u128 {
        bytes.push(1);
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&n.to_be_bytes());
        bytes.extend_from_slice(&n.to_be_bytes());
    }
    let check = blake3::derive_key(CHECK_CONTEXT, &bytes);
    bytes.extend_from_slice(&check);
    assert_eq!(bytes.len(), 5_275_698);
    let decoded = decode_set(&bytes).expect("largest legal set");
    assert_eq!(
        (decoded.principal_count(), decoded.credential_count()),
        (16_384, 16_384)
    );
    assert_eq!(encode_set(&decoded).as_bytes(), bytes);
    // At the boundary a bad checksum still wins over version. One byte
    // beyond it must refuse before either checksum or version inspection.
    bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(decode_set(&bytes), Err(SetDecodeError::BadCheck));
    bytes.push(0);
    assert_eq!(
        decode_set(&bytes),
        Err(SetDecodeError::TooLong { len: 5_275_699 })
    );
    let covered = bytes.len() - 32;
    let check = blake3::derive_key(CHECK_CONTEXT, &bytes[..covered]);
    bytes[covered..].copy_from_slice(&check);
    assert_eq!(
        decode_set(&bytes),
        Err(SetDecodeError::TooLong { len: 5_275_699 })
    );
    bytes[0] = 0;
    assert_eq!(decode_set(&bytes), Err(SetDecodeError::BadMagic));
}
