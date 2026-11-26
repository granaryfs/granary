// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The client enrollment set, format v1:
//! which client credentials are enrolled, to which principal, under which
//! tenant. Pure bytes-to-value and value-to-bytes, plus the set's own
//! mutation rules and the client-SPKI digest: no I/O, no clock, no
//! [`crate::rng::Rng`]. Reading, locking and replacing the file are the
//! server's.
//!
//! Big-endian, no varints:
//!
//! ```text
//! magic          8     "GRNENROL"
//! version        u16   1
//! principals     u32   P, 0 ≤ P ≤ 16384
//! credentials    u32   C, 0 ≤ C ≤ 16384
//! P principal records, strictly ascending by id:
//!   id           16    opaque, minted
//!   state        u8    0x01 active, 0x02 retired; 0x00 and all else invalid
//!   tenant_len   u8    1..=255
//!   tenant       tenant_len bytes, each 0x21..=0x7E
//! C credential records, strictly ascending by (kind, digest):
//!   kind         u8    0x01 client SPKI; 0x00 and all else invalid
//!   digest       32
//!   principal    16    the id of an active principal record in this file
//! check          32    BLAKE3 derive-key "granary enrollment set v1"
//!                      over every byte before it
//! ```
//!
//! The codec is strict: [`decode_set`] accepts a byte string only if
//! [`encode_set`] of the value it returns is that same byte string, and it
//! bounds the total length before hashing and verifies the check before
//! it interprets fields after the magic, so an in-bound
//! damaged byte reads as [`SetDecodeError::BadCheck`]. Every decode failure
//! is "corrupt" to the server's reader; the variants exist for the
//! operator's message.
//!
//! An [`EnrollmentSet`] can only hold what the format can carry: it is built
//! from [`EnrollmentSet::empty`] by the mutations, which refuse anything that
//! would break a decode rule (a bound, a duplicate, a credential on a retired
//! or absent principal), or by [`decode_set`]. So [`encode_set`] is total.

use std::collections::BTreeMap;

use crate::authlog::{Principal, Tenant};
use crate::secure_random::{EntropyUnavailable, SecureRandom};

/// The set's magic.
pub const ENROLLMENT_MAGIC: [u8; 8] = *b"GRNENROL";
/// The format version this module reads and writes.
pub const ENROLLMENT_VERSION: u16 = 1;
/// The most principal records a set holds, live and retired together.
pub const PRINCIPALS_MAX: usize = 16384;
/// The most credential records a set holds.
pub const CREDENTIALS_MAX: usize = 16384;
/// The largest legal encoding: every principal at its longest tenant and
/// every credential, both at their bound. The server refuses a file larger
/// than this before reading it; the pure decoder refuses it before hashing.
pub const ENCODED_MAX: usize = 5_275_698;

/// A principal id's length in bytes.
pub const PRINCIPAL_ID_LEN: usize = 16;
/// A client-SPKI digest's length in bytes.
pub const DIGEST_LEN: usize = 32;
/// The longest tenant name in bytes.
pub const TENANT_NAME_MAX: usize = 255;

/// magic(8) + version(2) + principals(4) + credentials(4).
const HEADER_LEN: usize = 8 + 2 + 4 + 4;
pub(crate) const CHECK_LEN: usize = 32;
pub(crate) const CHECK_CONTEXT: &str = "granary enrollment set v1";
/// The shortest input that can carry a check: the header and the check.
pub(crate) const MIN_LEN: usize = HEADER_LEN + CHECK_LEN;
/// id(16) + state(1) + `tenant_len`(1): a principal record without its tenant.
const PRINCIPAL_FIXED_LEN: usize = PRINCIPAL_ID_LEN + 1 + 1;
/// kind(1) + digest(32) + principal(16).
const CREDENTIAL_LEN: usize = 1 + DIGEST_LEN + PRINCIPAL_ID_LEN;

const STATE_ACTIVE: u8 = 0x01;
const STATE_RETIRED: u8 = 0x02;
const KIND_CLIENT_SPKI: u8 = 0x01;

/// The context string of the client-SPKI digest's key derivation.
const SPKI_DIGEST_CONTEXT: &str = "granary client-enrollment spki v1";
const PRINCIPAL_PREFIX: &str = "principal:";
const DIGEST_PREFIX: &str = "clientspki-v1:";
/// The most draws [`mint_principal_id`] makes before it gives up.
const MINT_ATTEMPTS: usize = 8;

const _: () = assert!(
    ENCODED_MAX
        == HEADER_LEN
            + PRINCIPALS_MAX * (PRINCIPAL_FIXED_LEN + TENANT_NAME_MAX)
            + CREDENTIALS_MAX * CREDENTIAL_LEN
            + CHECK_LEN
);
// The bounds fit the u32 count fields.
const _: () = assert!(PRINCIPALS_MAX <= u32::MAX as usize && CREDENTIALS_MAX <= u32::MAX as usize);
// Every value of the two conversions below is within the log's caps, so
// `PrincipalId::to_principal` and `TenantName::to_tenant` cannot fail.
const _: () = assert!(PRINCIPAL_ID_LEN >= 1 && PRINCIPAL_ID_LEN <= crate::authlog::PRINCIPAL_MAX);
const _: () = assert!(TENANT_NAME_MAX <= crate::authlog::TENANT_MAX);

// ============================================================ written forms

/// Why a written principal or digest did not parse. Two pasted forms that
/// look like keys an operator holds have their own variants, so the message
/// can say what was pasted rather than only that it is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrittenFormError {
    /// A `sha256/…` TLS server pin: it
    /// names a server's key, never a client's.
    TlsServerPin,
    /// An `ed25519:…` root-signing public key.
    RootSigningKey,
    /// A `keyid:…` key locator.
    KeyLocator,
    /// Another prefix, or none; `expected` is the prefix this form takes.
    WrongPrefix { expected: &'static str },
    /// The hex after the prefix is `len` bytes long, not `expected`.
    WrongLength { expected: usize, len: usize },
    /// The hex holds a character outside `0-9a-f` (uppercase included).
    NotLowercaseHex,
}

impl std::fmt::Display for WrittenFormError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TlsServerPin => write!(
                f,
                "this is a TLS server pin, not a client credential digest or principal"
            ),
            Self::RootSigningKey => write!(
                f,
                "this is a root-signing public key, not a client credential digest or principal"
            ),
            Self::KeyLocator => write!(
                f,
                "this is a key locator, not a client credential digest or principal"
            ),
            Self::WrongPrefix { expected } => write!(f, "expected the prefix `{expected}`"),
            Self::WrongLength { expected, len } => write!(
                f,
                "expected {expected} hex characters after the prefix, found {len}"
            ),
            Self::NotLowercaseHex => write!(f, "expected lowercase hex after the prefix"),
        }
    }
}

impl std::error::Error for WrittenFormError {}

/// The value of one lowercase hex digit, or `None` for anything else.
const fn lower_hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// The lowercase hex digit for one nibble (`0..=15`).
const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + (nibble - 10)) as char,
    }
}

fn write_hex(f: &mut std::fmt::Formatter<'_>, bytes: &[u8]) -> std::fmt::Result {
    for b in bytes {
        write!(f, "{}{}", hex_digit(b >> 4), hex_digit(b & 0x0F))?;
    }
    Ok(())
}

/// Parse `prefix` followed by exactly `2 * N` lowercase hex characters.
fn parse_prefixed_hex<const N: usize>(
    s: &str,
    prefix: &'static str,
) -> Result<[u8; N], WrittenFormError> {
    if s.starts_with("sha256/") {
        return Err(WrittenFormError::TlsServerPin);
    }
    if s.starts_with("ed25519:") {
        return Err(WrittenFormError::RootSigningKey);
    }
    if s.starts_with("keyid:") {
        return Err(WrittenFormError::KeyLocator);
    }
    let hex = s
        .strip_prefix(prefix)
        .ok_or(WrittenFormError::WrongPrefix { expected: prefix })?;
    let expected = N.saturating_mul(2);
    if hex.len() != expected {
        return Err(WrittenFormError::WrongLength {
            expected,
            len: hex.len(),
        });
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let [hi, lo] = *pair else {
            return Err(WrittenFormError::NotLowercaseHex);
        };
        match (lower_hex_val(hi), lower_hex_val(lo)) {
            (Some(hi), Some(lo)) => *byte = (hi << 4) | lo,
            _ => return Err(WrittenFormError::NotLowercaseHex),
        }
    }
    Ok(out)
}

// ============================================================ values

/// A principal's id: sixteen opaque bytes drawn by [`mint_principal_id`].
/// Written `principal:` followed by 32 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId([u8; PRINCIPAL_ID_LEN]);

impl PrincipalId {
    /// An id from its [`PRINCIPAL_ID_LEN`] bytes. Every value is legal.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PRINCIPAL_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The id's bytes, as the file carries them.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PRINCIPAL_ID_LEN] {
        &self.0
    }

    /// Parse the written form, `principal:` and 32 lowercase hex.
    ///
    /// # Errors
    /// [`WrittenFormError`] naming what is wrong with `s`, including the
    /// pasted forms that are keys rather than principals.
    pub fn parse_written(s: &str) -> Result<Self, WrittenFormError> {
        parse_prefixed_hex(s, PRINCIPAL_PREFIX).map(Self)
    }

    /// The principal as the authority log records it: the id's sixteen raw
    /// bytes.
    #[must_use]
    pub fn to_principal(&self) -> Principal {
        match Principal::new(self.0.to_vec()) {
            Ok(principal) => principal,
            // A const assertion above keeps PRINCIPAL_ID_LEN within the
            // log's 1..=PRINCIPAL_MAX, so `new` cannot refuse it.
            Err(_) => unreachable!("a principal id is within the log's principal cap"),
        }
    }
}

impl std::fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(PRINCIPAL_PREFIX)?;
        write_hex(f, &self.0)
    }
}

/// The digest that identifies an enrolled client credential:
/// `blake3::derive_key("granary client-enrollment spki v1", spki_der)` over
/// the certificate's complete DER `SubjectPublicKeyInfo`. Written
/// `clientspki-v1:` followed by 64 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientSpkiDigest([u8; DIGEST_LEN]);

impl ClientSpkiDigest {
    /// The digest of a DER `SubjectPublicKeyInfo` (algorithm identifier
    /// included). The caller extracts the bytes from the certificate; no
    /// X.509 parsing happens here.
    #[must_use]
    pub fn from_spki_der(spki_der: &[u8]) -> Self {
        Self(blake3::derive_key(SPKI_DIGEST_CONTEXT, spki_der))
    }

    /// A digest from its [`DIGEST_LEN`] bytes, as the file carries them.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    /// The digest's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    /// Parse the written form, `clientspki-v1:` and 64 lowercase hex.
    ///
    /// # Errors
    /// [`WrittenFormError`] naming what is wrong with `s`; a pasted TLS
    /// server pin or root-signing key has its own variant.
    pub fn parse_written(s: &str) -> Result<Self, WrittenFormError> {
        parse_prefixed_hex(s, DIGEST_PREFIX).map(Self)
    }
}

impl std::fmt::Display for ClientSpkiDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(DIGEST_PREFIX)?;
        write_hex(f, &self.0)
    }
}

/// Why bytes are not a [`TenantName`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantNameError {
    /// No bytes.
    Empty,
    /// `len` bytes, more than [`TENANT_NAME_MAX`].
    TooLong { len: usize },
    /// A byte outside `0x21..=0x7E` (printable ASCII without the space).
    BadByte { byte: u8 },
}

impl std::fmt::Display for TenantNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty tenant name"),
            Self::TooLong { len } => write!(
                f,
                "tenant name of {len} bytes exceeds the {TENANT_NAME_MAX}-byte cap"
            ),
            Self::BadByte { byte } => write!(
                f,
                "tenant name byte 0x{byte:02x} is not printable ascii without space"
            ),
        }
    }
}

impl std::error::Error for TenantNameError {}

const fn is_tenant_byte(b: u8) -> bool {
    matches!(b, 0x21..=0x7E)
}

/// A tenant's name: 1 to 255 bytes, each printable ASCII other than the
/// space (`0x21..=0x7E`), so an operator can type it and a status line can
/// print it without escaping.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantName(Vec<u8>);

impl TenantName {
    /// A name from its bytes.
    ///
    /// # Errors
    /// [`TenantNameError`] if `bytes` is empty, longer than
    /// [`TENANT_NAME_MAX`], or holds a byte outside the charset.
    pub fn new(bytes: &[u8]) -> Result<Self, TenantNameError> {
        if bytes.is_empty() {
            return Err(TenantNameError::Empty);
        }
        if bytes.len() > TENANT_NAME_MAX {
            return Err(TenantNameError::TooLong { len: bytes.len() });
        }
        if let Some(&byte) = bytes.iter().find(|&&b| !is_tenant_byte(b)) {
            return Err(TenantNameError::BadByte { byte });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// A name as an operator types it.
    ///
    /// # Errors
    /// As [`TenantName::new`] over the string's bytes.
    pub fn parse(s: &str) -> Result<Self, TenantNameError> {
        Self::new(s.as_bytes())
    }

    /// The name's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The tenant as the authority log records it: the name's bytes.
    #[must_use]
    pub fn to_tenant(&self) -> Tenant {
        match Tenant::new(self.0.clone()) {
            Ok(tenant) => tenant,
            // A name is 1..=TENANT_NAME_MAX bytes and a const assertion
            // above keeps that within the log's TENANT_MAX.
            Err(_) => unreachable!("a tenant name is within the log's tenant cap"),
        }
    }
}

impl std::fmt::Display for TenantName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Every byte is printable ASCII, so each is its own character.
        for &b in &self.0 {
            write!(f, "{}", char::from(b))?;
        }
        Ok(())
    }
}

/// A principal record's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrincipalState {
    /// Credentials may be attached to it.
    Active,
    /// Never again: it holds no credential and none can be attached. Its
    /// record is kept so its id is never minted again.
    Retired,
}

impl std::fmt::Display for PrincipalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Active => "active",
            Self::Retired => "retired",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrincipalRecord {
    state: PrincipalState,
    tenant: TenantName,
}

// ============================================================ the set

/// Why a mutation of an [`EnrollmentSet`] was refused. A refused mutation
/// leaves the set unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetChangeError {
    /// The id is already a principal record, active or retired.
    PrincipalExists,
    /// The digest is already enrolled, to this principal or another.
    CredentialEnrolled,
    /// The set already holds [`PRINCIPALS_MAX`] principal records.
    PrincipalBoundReached,
    /// The set already holds [`CREDENTIALS_MAX`] credentials.
    CredentialBoundReached,
    /// No principal record has the id.
    PrincipalAbsent,
    /// The principal is retired.
    PrincipalRetired,
    /// The digest is not enrolled.
    CredentialNotEnrolled,
    /// The principal still holds a credential; revoke it first.
    PrincipalHoldsCredentials,
}

impl std::fmt::Display for SetChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PrincipalExists => "the principal id is already recorded",
            Self::CredentialEnrolled => "the credential is already enrolled",
            Self::PrincipalBoundReached => "the set holds the most principals it can",
            Self::CredentialBoundReached => "the set holds the most credentials it can",
            Self::PrincipalAbsent => "no such principal",
            Self::PrincipalRetired => "the principal is retired",
            Self::CredentialNotEnrolled => "the credential is not enrolled",
            Self::PrincipalHoldsCredentials => {
                "the principal still holds a credential; revoke it first"
            }
        })
    }
}

impl std::error::Error for SetChangeError {}

/// The enrollment set: principal records (every one ever minted, active or
/// retired) and the credentials enrolled to active ones. Its invariants are
/// the decoder's rules, held by every constructor and mutation: at most
/// [`PRINCIPALS_MAX`] principals and [`CREDENTIALS_MAX`] credentials, and
/// each credential names an active principal in the set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnrollmentSet {
    principals: BTreeMap<PrincipalId, PrincipalRecord>,
    credentials: BTreeMap<ClientSpkiDigest, PrincipalId>,
}

impl EnrollmentSet {
    /// The set with no principals and no credentials.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            principals: BTreeMap::new(),
            credentials: BTreeMap::new(),
        }
    }

    /// The principal and tenant a credential is enrolled to, or `None` if
    /// it is not enrolled.
    #[must_use]
    pub fn lookup(&self, digest: &ClientSpkiDigest) -> Option<(PrincipalId, &TenantName)> {
        let id = self.credentials.get(digest)?;
        let record = self.principals.get(id)?;
        Some((*id, &record.tenant))
    }

    /// A principal record's state and tenant, or `None` if there is none.
    #[must_use]
    pub fn principal(&self, id: &PrincipalId) -> Option<(PrincipalState, &TenantName)> {
        self.principals.get(id).map(|r| (r.state, &r.tenant))
    }

    /// Every principal record, ascending by id (the file's order).
    pub fn principals(&self) -> impl Iterator<Item = (PrincipalId, PrincipalState, &TenantName)> {
        self.principals
            .iter()
            .map(|(id, r)| (*id, r.state, &r.tenant))
    }

    /// Every credential and the principal it is enrolled to, ascending by
    /// digest (the file's order).
    pub fn credentials(&self) -> impl Iterator<Item = (ClientSpkiDigest, PrincipalId)> + '_ {
        self.credentials.iter().map(|(d, id)| (*d, *id))
    }

    /// The number of principal records, active and retired.
    #[must_use]
    pub fn principal_count(&self) -> usize {
        self.principals.len()
    }

    /// The number of enrolled credentials.
    #[must_use]
    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }

    /// Record a new active principal `id` under `tenant` and enroll
    /// `digest` to it.
    ///
    /// # Errors
    /// [`SetChangeError::PrincipalExists`] if `id` is any record, retired
    /// included; [`SetChangeError::CredentialEnrolled`] if `digest` is
    /// enrolled; [`SetChangeError::PrincipalBoundReached`] or
    /// [`SetChangeError::CredentialBoundReached`] at a bound. Checked in
    /// that order; the set is unchanged on any error.
    pub fn mint(
        &mut self,
        id: PrincipalId,
        tenant: TenantName,
        digest: ClientSpkiDigest,
    ) -> Result<(), SetChangeError> {
        if self.principals.contains_key(&id) {
            return Err(SetChangeError::PrincipalExists);
        }
        if self.credentials.contains_key(&digest) {
            return Err(SetChangeError::CredentialEnrolled);
        }
        if self.principals.len() >= PRINCIPALS_MAX {
            return Err(SetChangeError::PrincipalBoundReached);
        }
        if self.credentials.len() >= CREDENTIALS_MAX {
            return Err(SetChangeError::CredentialBoundReached);
        }
        self.principals.insert(
            id,
            PrincipalRecord {
                state: PrincipalState::Active,
                tenant,
            },
        );
        self.credentials.insert(digest, id);
        Ok(())
    }

    /// Enroll `digest` to the existing active principal `id`.
    ///
    /// # Errors
    /// [`SetChangeError::PrincipalAbsent`], [`SetChangeError::PrincipalRetired`],
    /// [`SetChangeError::CredentialEnrolled`] or
    /// [`SetChangeError::CredentialBoundReached`], checked in that order;
    /// the set is unchanged on any error.
    pub fn attach(
        &mut self,
        id: PrincipalId,
        digest: ClientSpkiDigest,
    ) -> Result<(), SetChangeError> {
        match self.principals.get(&id) {
            None => return Err(SetChangeError::PrincipalAbsent),
            Some(r) if r.state == PrincipalState::Retired => {
                return Err(SetChangeError::PrincipalRetired);
            }
            Some(_) => {}
        }
        if self.credentials.contains_key(&digest) {
            return Err(SetChangeError::CredentialEnrolled);
        }
        if self.credentials.len() >= CREDENTIALS_MAX {
            return Err(SetChangeError::CredentialBoundReached);
        }
        self.credentials.insert(digest, id);
        Ok(())
    }

    /// Remove `digest`'s enrollment. The principal's record stays, active,
    /// even when this was its last credential.
    ///
    /// # Errors
    /// [`SetChangeError::CredentialNotEnrolled`]; the set is unchanged.
    pub fn revoke(&mut self, digest: &ClientSpkiDigest) -> Result<(), SetChangeError> {
        self.credentials
            .remove(digest)
            .map(|_| ())
            .ok_or(SetChangeError::CredentialNotEnrolled)
    }

    /// Mark principal `id` retired, permanently. Its record is kept.
    ///
    /// # Errors
    /// [`SetChangeError::PrincipalAbsent`], [`SetChangeError::PrincipalRetired`]
    /// or [`SetChangeError::PrincipalHoldsCredentials`], checked in that
    /// order; the set is unchanged on any error.
    pub fn retire(&mut self, id: &PrincipalId) -> Result<(), SetChangeError> {
        let holds = self.credentials.values().any(|p| p == id);
        let record = self
            .principals
            .get_mut(id)
            .ok_or(SetChangeError::PrincipalAbsent)?;
        if record.state == PrincipalState::Retired {
            return Err(SetChangeError::PrincipalRetired);
        }
        if holds {
            return Err(SetChangeError::PrincipalHoldsCredentials);
        }
        record.state = PrincipalState::Retired;
        Ok(())
    }
}

// ============================================================ minting

/// Why no principal id was minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// The randomness source failed; nothing it wrote is used.
    Entropy,
    /// Every draw equalled an existing record. With a working source this
    /// does not happen; it means the source is repeating itself.
    Collisions,
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entropy => write!(f, "no cryptographic randomness was available"),
            Self::Collisions => write!(
                f,
                "{MINT_ATTEMPTS} drawn principal ids all equalled existing records"
            ),
        }
    }
}

impl std::error::Error for MintError {}

impl From<EntropyUnavailable> for MintError {
    fn from(_: EntropyUnavailable) -> Self {
        Self::Entropy
    }
}

/// Draw a principal id that is not any record in `set`, active or retired:
/// all sixteen bytes from `door`, redrawn while the draw equals a record,
/// at most eight draws.
///
/// # Errors
/// [`MintError::Entropy`] if a draw fails (its partial bytes are
/// discarded); [`MintError::Collisions`] if every draw equalled a record.
pub fn mint_principal_id(
    door: &mut impl SecureRandom,
    set: &EnrollmentSet,
) -> Result<PrincipalId, MintError> {
    for _ in 0..MINT_ATTEMPTS {
        let mut bytes = [0u8; PRINCIPAL_ID_LEN];
        door.fill(&mut bytes)?;
        let id = PrincipalId::from_bytes(bytes);
        if !set.principals.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(MintError::Collisions)
}

// ============================================================ codec

/// A set's canonical bytes, as [`encode_set`] builds them. The bytes are
/// private, so a writer that takes this type cannot be handed bytes this
/// codec did not produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSet(Vec<u8>);

impl EncodedSet {
    /// The set's bytes, at most [`ENCODED_MAX`].
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Encode a set. Infallible: every [`EnrollmentSet`] is within the
/// format's bounds and has exactly one encoding.
#[must_use]
pub fn encode_set(set: &EnrollmentSet) -> EncodedSet {
    let tenants: usize = set.principals.values().map(|r| r.tenant.0.len()).sum();
    let len = HEADER_LEN
        + set.principals.len() * PRINCIPAL_FIXED_LEN
        + tenants
        + set.credentials.len() * CREDENTIAL_LEN
        + CHECK_LEN;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&ENROLLMENT_MAGIC);
    out.extend_from_slice(&ENROLLMENT_VERSION.to_be_bytes());
    out.extend_from_slice(&count_field(set.principals.len()));
    out.extend_from_slice(&count_field(set.credentials.len()));
    for (id, record) in &set.principals {
        out.extend_from_slice(id.as_bytes());
        out.push(match record.state {
            PrincipalState::Active => STATE_ACTIVE,
            PrincipalState::Retired => STATE_RETIRED,
        });
        // 1..=TENANT_NAME_MAX, so it fits the byte.
        out.push(u8::try_from(record.tenant.0.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(&record.tenant.0);
    }
    for (digest, id) in &set.credentials {
        out.push(KIND_CLIENT_SPKI);
        out.extend_from_slice(digest.as_bytes());
        out.extend_from_slice(id.as_bytes());
    }
    let check = blake3::derive_key(CHECK_CONTEXT, &out);
    out.extend_from_slice(&check);
    EncodedSet(out)
}

/// A count's field. The set's bounds keep every count within `u32`.
fn count_field(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes()
}

/// Which of the two record lists a count names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordList {
    /// The principal records.
    Principals,
    /// The credential records.
    Credentials,
}

impl std::fmt::Display for RecordList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Principals => "principal",
            Self::Credentials => "credential",
        })
    }
}

/// Why a byte string is not an enrollment set. Every variant is "corrupt" to
/// the server's reader. [`decode_set`] reports the first of these, in
/// declaration order, that the input fails; `index` is the record's
/// position in its list, from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetDecodeError {
    /// The first eight bytes are not [`ENROLLMENT_MAGIC`].
    BadMagic,
    /// `len` bytes, too few for the header and the check.
    TooShort { len: usize },
    /// `len` bytes exceed the largest legal encoding, before hashing.
    TooLong { len: usize },
    /// The check does not match the bytes before it.
    BadCheck,
    /// A version other than [`ENROLLMENT_VERSION`].
    UnknownVersion { version: u16 },
    /// A count above its bound ([`PRINCIPALS_MAX`] or [`CREDENTIALS_MAX`]).
    CountOverBound { list: RecordList, count: u32 },
    /// The records the counts declare do not fit in the bytes before the
    /// check.
    CountsOverrunLength,
    /// A principal state that is neither active nor retired, 0x00 included.
    InvalidState { index: usize, tag: u8 },
    /// A principal's tenant length is 0.
    BadTenantLength { index: usize },
    /// A tenant byte outside `0x21..=0x7E`.
    BadTenantByte { index: usize, byte: u8 },
    /// A principal id not strictly above the one before it: out of order,
    /// or a duplicate.
    PrincipalsNotAscending { index: usize },
    /// A credential kind other than client SPKI, 0x00 included.
    InvalidCredentialKind { index: usize, kind: u8 },
    /// A credential not strictly above the one before it by kind then
    /// digest: out of order, or the same digest twice (under any
    /// principals).
    CredentialsNotAscending { index: usize },
    /// A credential names a principal with no record in the file.
    CredentialPrincipalAbsent { index: usize },
    /// A credential names a retired principal.
    CredentialPrincipalRetired { index: usize },
    /// `len` bytes remain between the last record and the check.
    TrailingData { len: usize },
}

impl std::fmt::Display for SetDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad enrollment set magic"),
            Self::TooShort { len } => write!(f, "enrollment set of {len} bytes is too short"),
            Self::TooLong { len } => write!(f, "enrollment set of {len} bytes is too long"),
            Self::BadCheck => write!(f, "enrollment set check does not match"),
            Self::UnknownVersion { version } => {
                write!(f, "unknown enrollment set version {version}")
            }
            Self::CountOverBound { list, count } => {
                write!(f, "enrollment set {list} count {count} exceeds its bound")
            }
            Self::CountsOverrunLength => {
                write!(f, "enrollment set records overrun the file's length")
            }
            Self::InvalidState { index, tag } => {
                write!(f, "principal record {index} has invalid state 0x{tag:02x}")
            }
            Self::BadTenantLength { index } => {
                write!(f, "principal record {index} has an empty tenant")
            }
            Self::BadTenantByte { index, byte } => write!(
                f,
                "principal record {index} has tenant byte 0x{byte:02x} outside the charset"
            ),
            Self::PrincipalsNotAscending { index } => {
                write!(f, "principal record {index} is out of order or a duplicate")
            }
            Self::InvalidCredentialKind { index, kind } => {
                write!(f, "credential record {index} has invalid kind 0x{kind:02x}")
            }
            Self::CredentialsNotAscending { index } => write!(
                f,
                "credential record {index} is out of order or a duplicate"
            ),
            Self::CredentialPrincipalAbsent { index } => write!(
                f,
                "credential record {index} names a principal with no record"
            ),
            Self::CredentialPrincipalRetired { index } => {
                write!(f, "credential record {index} names a retired principal")
            }
            Self::TrailingData { len } => {
                write!(f, "enrollment set has {len} bytes after its last record")
            }
        }
    }
}

impl std::error::Error for SetDecodeError {}

/// Split `N` bytes off the front of `rest`, or report an overrun.
fn take<'a, const N: usize>(rest: &mut &'a [u8]) -> Result<&'a [u8; N], SetDecodeError> {
    let (head, tail) = rest
        .split_first_chunk::<N>()
        .ok_or(SetDecodeError::CountsOverrunLength)?;
    *rest = tail;
    Ok(head)
}

/// A count field checked against its bound.
fn bounded_count(raw: [u8; 4], list: RecordList, max: usize) -> Result<usize, SetDecodeError> {
    let count = u32::from_be_bytes(raw);
    match usize::try_from(count) {
        Ok(n) if n <= max => Ok(n),
        _ => Err(SetDecodeError::CountOverBound { list, count }),
    }
}

/// Decode `count` principal records from the front of `rest` into `set`,
/// in the order and with the errors [`decode_set`] documents.
fn decode_principals(
    rest: &mut &[u8],
    count: usize,
    set: &mut EnrollmentSet,
) -> Result<(), SetDecodeError> {
    let mut previous_id: Option<PrincipalId> = None;
    for index in 0..count {
        let id = PrincipalId::from_bytes(*take::<PRINCIPAL_ID_LEN>(rest)?);
        let &[tag, tenant_len] = take::<2>(rest)?;
        let state = match tag {
            STATE_ACTIVE => PrincipalState::Active,
            STATE_RETIRED => PrincipalState::Retired,
            _ => return Err(SetDecodeError::InvalidState { index, tag }),
        };
        if tenant_len == 0 {
            return Err(SetDecodeError::BadTenantLength { index });
        }
        let (tenant, tail) = (*rest)
            .split_at_checked(usize::from(tenant_len))
            .ok_or(SetDecodeError::CountsOverrunLength)?;
        *rest = tail;
        if let Some(&byte) = tenant.iter().find(|&&b| !is_tenant_byte(b)) {
            return Err(SetDecodeError::BadTenantByte { index, byte });
        }
        if previous_id.is_some_and(|prev| prev >= id) {
            return Err(SetDecodeError::PrincipalsNotAscending { index });
        }
        previous_id = Some(id);
        set.principals.insert(
            id,
            PrincipalRecord {
                state,
                tenant: TenantName(tenant.to_vec()),
            },
        );
    }
    Ok(())
}

/// Decode `count` credential records from the front of `rest` into `set`,
/// whose principals are already decoded, in the order and with the errors
/// [`decode_set`] documents.
fn decode_credentials(
    rest: &mut &[u8],
    count: usize,
    set: &mut EnrollmentSet,
) -> Result<(), SetDecodeError> {
    let mut previous_credential: Option<(u8, ClientSpkiDigest)> = None;
    for index in 0..count {
        let &[kind] = take::<1>(rest)?;
        let digest = ClientSpkiDigest::from_bytes(*take::<DIGEST_LEN>(rest)?);
        let id = PrincipalId::from_bytes(*take::<PRINCIPAL_ID_LEN>(rest)?);
        if kind != KIND_CLIENT_SPKI {
            return Err(SetDecodeError::InvalidCredentialKind { index, kind });
        }
        if previous_credential.is_some_and(|prev| prev >= (kind, digest)) {
            return Err(SetDecodeError::CredentialsNotAscending { index });
        }
        previous_credential = Some((kind, digest));
        match set.principals.get(&id) {
            None => return Err(SetDecodeError::CredentialPrincipalAbsent { index }),
            Some(r) if r.state == PrincipalState::Retired => {
                return Err(SetDecodeError::CredentialPrincipalRetired { index });
            }
            Some(_) => {}
        }
        set.credentials.insert(digest, id);
    }
    Ok(())
}

/// Decode a set, strictly: the whole input is the set.
///
/// The checks run in this order, and the first failure is the error: the
/// magic; a length of at least the header and the check;
/// a length of at most 5,275,698 before hashing; the check over every byte
/// before the last 32; the version; each count against its bound,
/// then both against the remaining length; each principal record (state,
/// tenant length, tenant bytes, strict ascent by id); each credential (kind,
/// strict ascent, principal present, principal active); then no bytes left
/// before the check. Nothing is allocated from a count before it passes its
/// bound and the length.
///
/// # Errors
/// [`SetDecodeError`] naming the first check the input fails.
pub fn decode_set(bytes: &[u8]) -> Result<EnrollmentSet, SetDecodeError> {
    let too_short = SetDecodeError::TooShort { len: bytes.len() };
    if bytes
        .get(..ENROLLMENT_MAGIC.len())
        .is_some_and(|magic| magic != ENROLLMENT_MAGIC)
    {
        return Err(SetDecodeError::BadMagic);
    }
    if bytes.len() < MIN_LEN {
        return Err(too_short);
    }
    if bytes.len() > ENCODED_MAX {
        return Err(SetDecodeError::TooLong { len: bytes.len() });
    }
    let (covered, check) = bytes.split_last_chunk::<CHECK_LEN>().ok_or(too_short)?;
    if *check != blake3::derive_key(CHECK_CONTEXT, covered) {
        return Err(SetDecodeError::BadCheck);
    }
    let (header, mut rest) = covered.split_first_chunk::<HEADER_LEN>().ok_or(too_short)?;
    let [
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        v0,
        v1,
        p0,
        p1,
        p2,
        p3,
        c0,
        c1,
        c2,
        c3,
    ] = *header;
    let version = u16::from_be_bytes([v0, v1]);
    if version != ENROLLMENT_VERSION {
        return Err(SetDecodeError::UnknownVersion { version });
    }
    let principal_count = bounded_count([p0, p1, p2, p3], RecordList::Principals, PRINCIPALS_MAX)?;
    let credential_count =
        bounded_count([c0, c1, c2, c3], RecordList::Credentials, CREDENTIALS_MAX)?;
    // Both counts are bounded, so this cannot overflow; the checked form
    // keeps the claim local.
    let least = principal_count
        .checked_mul(PRINCIPAL_FIXED_LEN)
        .zip(credential_count.checked_mul(CREDENTIAL_LEN))
        .and_then(|(p, c)| p.checked_add(c));
    if least.is_none_or(|least| least > rest.len()) {
        return Err(SetDecodeError::CountsOverrunLength);
    }

    let mut set = EnrollmentSet::empty();
    decode_principals(&mut rest, principal_count, &mut set)?;
    decode_credentials(&mut rest, credential_count, &mut set)?;
    if !rest.is_empty() {
        return Err(SetDecodeError::TrailingData { len: rest.len() });
    }
    Ok(set)
}

#[cfg(test)]
mod tests;
