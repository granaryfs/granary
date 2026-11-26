// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Exact retained publication bytes, continuation data and checked bookkeeping. No I/O.
//!

use crate::authlog::Epoch;
use crate::authority_answer::{self, Position, Receipt};
use crate::encoding::{Cursor, DecodeError};
use crate::hash::GrainId;
use crate::root::{self, VolumeName};

/// Complete-file cap, checked before allocating decoded fields.
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
/// Catalogue capacity; reaching it must never evict a candidate.
pub const MAX_CANDIDATES: usize = 128;
/// Self-check domain, distinct from root and path hashes.
pub const CHECK_CONTEXT: &str = "granary retained-submission v1";
const MAGIC: &[u8; 8] = b"GRNSUBMS";
const VERSION: u16 = 2;
const MAX_UNAVAILABLE_EXEMPTIONS: u16 = 1024;
const ROOT_CAP: usize = 65536;
const _: () = assert!(ROOT_CAP as u64 == root::ROOT_MAX_BYTES);
// 16 KiB covers all non-candidate fields; each catalogue entry adds at most
// 128 fixed bytes plus its root. Frozen and completion roots add two more.
const _: () = assert!(16384 + (ROOT_CAP + 128) * MAX_CANDIDATES + 2 * ROOT_CAP <= MAX_BYTES);

/// Codec and checked-accounting refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A bounded read or embedded root failed.
    Decode(DecodeError),
    /// A structural or cross-field rule failed.
    Invalid(&'static str),
    /// A complete file exceeds the cap.
    TooLarge,
    /// The exact bytes do not match their check.
    BadCheck,
    /// Unsupported format version.
    Version(u16),
    /// A count or counter cannot advance; keep all retained state.
    Exhausted,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => e.fmt(f),
            Self::Invalid(rule) => write!(f, "invalid retained submission: {rule}"),
            Self::TooLarge => write!(f, "retained submission exceeds byte cap"),
            Self::BadCheck => write!(f, "retained submission check mismatch"),
            Self::Version(v) => write!(f, "unsupported retained submission version {v}"),
            Self::Exhausted => write!(f, "retained submission capacity exhausted"),
        }
    }
}
impl std::error::Error for Error {}
impl From<DecodeError> for Error {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}
fn require(ok: bool, rule: &'static str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(rule))
    }
}

/// Stable local scope. Context is an operator name, never a wire principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub authority_base: Vec<u8>,
    pub pins: Vec<[u8; 32]>,
    pub credential_context: Vec<u8>,
}
impl Scope {
    /// Validate and derive the directory component, without normalizing bytes.
    /// # Errors
    /// Invalid lengths or noncanonical pin order.
    pub fn digest(&self) -> Result<String, Error> {
        self.validate()?;
        let mut input = Vec::new();
        put16(&mut input, &self.authority_base)?;
        put8(&mut input, &self.credential_context)?;
        let mut h = blake3::Hasher::new_derive_key("granary retained-submission scope v1");
        h.update(&input);
        Ok(h.finalize().to_hex().to_string())
    }
    fn validate(&self) -> Result<(), Error> {
        require(
            (1..=8192).contains(&self.authority_base.len()),
            "authority base length",
        )?;
        require(
            (1..=255).contains(&self.credential_context.len()),
            "context length",
        )?;
        require(self.pins.len() <= 8, "pin count")?;
        require(
            self.pins.windows(2).all(|p| p.first() < p.get(1)),
            "pin order",
        )
    }
}

/// Preparation inputs retained independently of source files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenIntent {
    pub writer_identity: [u8; 16],
    pub min_prefix_bits: u8,
    pub initial_root: Vec<u8>,
}
/// One epoch's operation identity; equality is bytewise, never ordered by epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestIdentity {
    pub epoch: [u8; 16],
    pub operation: [u8; 16],
}
/// Why the exact candidate remains in the catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Active = 1,
    History = 2,
    Retired = 3,
}

/// Conservative per-attempt evidence. Applying older answers refuses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Evidence {
    pub started: u64,
    pub proved_no_write: u64,
    pub last_answered_attempt: u64,
    pub decision_seen: bool,
}
impl Evidence {
    fn validate(self) -> Result<(), Error> {
        require(
            self.proved_no_write <= self.last_answered_attempt
                && self.last_answered_attempt <= self.started
                && (!self.decision_seen || self.started != 0),
            "attempt counters",
        )
    }
    /// Record an attempt before the caller persists and sends it.
    /// # Errors
    /// Invalid counters or exhaustion, without changing the value.
    pub fn start(&mut self) -> Result<u64, Error> {
        self.validate()?;
        self.started = self.started.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(self.started)
    }
    /// Account for one checked response. Proof classification belongs to the caller.
    /// # Errors
    /// A duplicate/old/unstarted attempt or invalid counters; no partial update.
    pub fn answer(&mut self, attempt: u64, no_write: bool, decision: bool) -> Result<(), Error> {
        self.validate()?;
        require(
            attempt > self.last_answered_attempt && attempt <= self.started,
            "answer attempt",
        )?;
        let mut next = *self;
        next.last_answered_attempt = attempt;
        if no_write {
            next.proved_no_write = next
                .proved_no_write
                .checked_add(1)
                .ok_or(Error::Exhausted)?;
        }
        next.decision_seen |= decision;
        next.validate()?;
        *self = next;
        Ok(())
    }
    #[must_use]
    pub const fn never_decided(self) -> bool {
        self.started == self.proved_no_write && !self.decision_seen
    }
}
/// A signed candidate's exact stored bytes and submission history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub number: u64,
    pub role: Role,
    pub request: RequestIdentity,
    pub seq: u64,
    pub id: GrainId,
    pub root: Vec<u8>,
    pub evidence: Evidence,
}
/// Closed continuation reason registry; no diagnostic strings persist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeReason {
    Started = 0,
    Interrupted = 1,
    Transport = 2,
    Malformed = 3,
    LocalPersistence = 4,
    Capacity = 5,
    ContentUnavailable = 6,
}
/// An explicit recovery cycle and its read position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub cycle: u64,
    pub seq: u64,
    pub reason: ProbeReason,
}
/// Actual winner; absent receipt means chain recovery, not an invented position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub seq: u64,
    pub id: GrainId,
    pub root: Vec<u8>,
    pub receipt: Option<Receipt>,
}
impl Completion {
    /// Epoch knowledge for a successor publication. `None` requires status bootstrap.
    #[must_use]
    pub fn epoch_knowledge(&self) -> Option<Epoch> {
        self.receipt.map(|r| r.position.epoch)
    }
}
/// Persisted continuation data only; the coordinator owns the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Ready,
    AwaitingAnswer { candidate: u64, attempt: u64 },
    Rebase,
    EpochRecovery { epoch: [u8; 16] },
    ProbeStarted(Probe),
    Unresolved(Probe),
    Complete(Completion),
}
/// Structurally valid response bytes. This is not a checked transport response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastResponse {
    pub candidate: u64,
    pub attempt: u64,
    pub status: u16,
    pub token: Vec<u8>,
    pub answer: Vec<u8>,
}
/// One complete durable generation of a logical publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub generation: u64,
    pub publication_id: [u8; 16],
    pub scope: Scope,
    pub volume: VolumeName,
    pub frozen: FrozenIntent,
    pub current: Option<RequestIdentity>,
    pub candidates: Vec<Candidate>,
    pub phase: Phase,
    pub last_response: Option<LastResponse>,
    pub unavailable_exemptions: u16,
}
impl Submission {
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }

    /// Observe an operation binding and select its already submitted candidate.
    /// Counters belong to candidates and are never restarted by a role change.
    /// # Errors
    /// Unknown/retired/unsubmitted binding, absent current identity, or invalid
    /// resulting state. No partial change.
    pub fn activate_bound(&mut self, id: GrainId) -> Result<(), Error> {
        let mut next = self.clone();
        let bound = next
            .candidates
            .iter_mut()
            .filter(|c| c.id == id && c.role != Role::Retired && Some(c.request) == next.current)
            // Identical prepared bytes may have both unsent and submitted
            // history entries. The binding selects evidence of a real attempt.
            .min_by_key(|c| c.evidence.started == 0)
            .ok_or(Error::Invalid("binding not in current history"))?;
        require(bound.evidence.started != 0, "unsubmitted binding")?;
        bound.evidence.decision_seen = true;
        let number = bound.number;
        for c in &mut next.candidates {
            if c.number == number {
                c.role = Role::Active;
            } else if c.role == Role::Active {
                c.role = Role::History;
            }
        }
        next.phase = Phase::Ready;
        validate(&next)?;
        *self = next;
        Ok(())
    }

    /// Insert at the next catalogue position, refusing capacity without eviction.
    /// # Errors
    /// Capacity, numbering or any resulting record inconsistency. No partial change.
    pub fn insert_candidate(&mut self, candidate: Candidate) -> Result<(), Error> {
        if self.candidates.len() >= MAX_CANDIDATES {
            return Err(Error::Exhausted);
        }
        let mut next = self.clone();
        next.candidates.push(candidate);
        validate(&next)?;
        *self = next;
        Ok(())
    }
}

fn checked_root(bytes: &[u8], volume: &VolumeName) -> Result<root::RootDoc, Error> {
    require(!bytes.is_empty() && bytes.len() <= ROOT_CAP, "root length")?;
    let root = root::decode_root(bytes)?;
    require(root.volume == *volume, "root volume")?;
    require(
        (1..=authority_answer::LAST_CANDIDATE_SEQ).contains(&root.seq),
        "root seq",
    )?;
    Ok(root)
}
fn candidate(s: &Submission, number: u64) -> Result<&Candidate, Error> {
    s.candidates
        .iter()
        .find(|c| c.number == number)
        .ok_or(Error::Invalid("candidate reference"))
}

/// Validate the complete value before encoding or persisting it.
/// # Errors
/// Any format bound or structural/cross-field rule violation.
pub fn validate(s: &Submission) -> Result<(), Error> {
    require(s.generation != 0, "generation")?;
    require(
        s.unavailable_exemptions <= MAX_UNAVAILABLE_EXEMPTIONS,
        "unavailable exemptions",
    )?;
    s.scope.validate()?;
    require(s.frozen.min_prefix_bits <= 12, "preparation policy")?;
    let initial = checked_root(&s.frozen.initial_root, &s.volume)?;
    require(s.candidates.len() <= MAX_CANDIDATES, "candidate count")?;
    let mut previous = 0;
    let mut active = 0;
    for c in &s.candidates {
        require(c.number > previous, "candidate order")?;
        previous = c.number;
        let doc = checked_root(&c.root, &s.volume)?;
        require(
            doc.seq == c.seq && GrainId::of(&c.root) == c.id,
            "candidate binding",
        )?;
        if doc.manifest_root != initial.manifest_root {
            require(c.number > 1, "frozen manifest")?;
            require(doc.seq > initial.seq, "rebase sequence")?;
        }
        c.evidence.validate()?;
        if c.role == Role::Active {
            active += 1;
        }
        if !s.is_complete() && c.role != Role::Retired {
            require(s.current == Some(c.request), "current identity")?;
        }
        if c.role == Role::Retired {
            require(
                s.current.is_none_or(|i| i.epoch != c.request.epoch),
                "retired epoch",
            )?;
        }
        for other in &s.candidates {
            require(
                c.request.operation != other.request.operation
                    || c.request.epoch == other.request.epoch,
                "operation crosses epochs",
            )?;
        }
        if let Some(current) = s.current {
            require(
                current.operation != c.request.operation || current.epoch == c.request.epoch,
                "operation crosses epochs",
            )?;
        }
    }
    require(active <= 1, "active cardinality")?;
    validate_phase(s, active)?;
    if let Some(r) = &s.last_response {
        let c = candidate(s, r.candidate)?;
        require(
            r.attempt != 0 && r.attempt == c.evidence.last_answered_attempt,
            "response attempt",
        )?;
        require((100..=599).contains(&r.status), "response status")?;
        require(
            r.token.len() <= 64
                && r.token
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-'),
            "response token",
        )?;
        require(
            r.answer.len() <= authority_answer::MAX_BYTES,
            "answer length",
        )?;
        if !r.answer.is_empty() {
            authority_answer::decode(&r.answer).map_err(|_| Error::Invalid("answer bytes"))?;
        }
    }
    Ok(())
}
fn validate_phase(s: &Submission, active: usize) -> Result<(), Error> {
    match &s.phase {
        Phase::Ready => require(active == 1 && s.current.is_some(), "ready phase"),
        Phase::AwaitingAnswer {
            candidate: number,
            attempt,
        } => {
            let c = candidate(s, *number)?;
            require(
                c.role == Role::Active
                    && *attempt == c.evidence.started
                    && *attempt > c.evidence.last_answered_attempt,
                "awaiting phase",
            )
        }
        Phase::Rebase => require(s.current.is_some(), "rebase phase"),
        Phase::EpochRecovery { .. } => require(
            s.current.is_none() && s.candidates.iter().all(|c| c.role == Role::Retired),
            "epoch recovery phase",
        ),
        Phase::ProbeStarted(p) | Phase::Unresolved(p) => {
            require(
                p.cycle != 0 && s.candidates.iter().any(|c| c.seq == p.seq),
                "probe position",
            )?;
            require(
                matches!(s.phase, Phase::ProbeStarted(_)) == (p.reason == ProbeReason::Started),
                "probe reason",
            )
        }
        Phase::Complete(done) => {
            require(s.current.is_none(), "complete current identity")?;
            let matches = || {
                s.candidates
                    .iter()
                    .filter(|c| c.seq == done.seq && c.id == done.id && c.root == done.root)
            };
            require(matches().next().is_some(), "completion binding")?;
            if let Some(r) = done.receipt {
                require(
                    matches().any(|c| {
                        r.position.entry_seq != 0
                            && r.position.epoch.to_bytes() == c.request.epoch
                            && r.root_seq == c.seq
                            && r.stored_id == c.id
                    }),
                    "completion receipt",
                )?;
            }
            Ok(())
        }
    }
}

fn array<const N: usize>(c: &mut Cursor<'_>) -> Result<[u8; N], Error> {
    c.take(N)?
        .try_into()
        .map_err(|_| Error::Decode(DecodeError::Truncated))
}
fn boolean(c: &mut Cursor<'_>) -> Result<bool, Error> {
    match c.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Invalid("boolean")),
    }
}
fn bytes(c: &mut Cursor<'_>, len: usize, cap: usize) -> Result<Vec<u8>, Error> {
    require(len <= cap, "field length")?;
    Ok(c.take(len)?.to_vec())
}
fn bytes8(c: &mut Cursor<'_>, cap: usize) -> Result<Vec<u8>, Error> {
    let n = usize::from(c.u8()?);
    bytes(c, n, cap)
}
fn bytes16(c: &mut Cursor<'_>, cap: usize) -> Result<Vec<u8>, Error> {
    let n = usize::from(c.u16()?);
    bytes(c, n, cap)
}
fn root_bytes(c: &mut Cursor<'_>) -> Result<Vec<u8>, Error> {
    let n = usize::try_from(c.u32()?).map_err(|_| Error::TooLarge)?;
    bytes(c, n, ROOT_CAP)
}
fn request(c: &mut Cursor<'_>) -> Result<RequestIdentity, Error> {
    Ok(RequestIdentity {
        epoch: array(c)?,
        operation: array(c)?,
    })
}
fn grain(c: &mut Cursor<'_>) -> Result<GrainId, Error> {
    GrainId::from_bytes(c.take(33)?).map_err(|_| Error::Invalid("grain id"))
}
fn read_candidate(c: &mut Cursor<'_>) -> Result<Candidate, Error> {
    let number = c.u64()?;
    let role = match c.u8()? {
        1 => Role::Active,
        2 => Role::History,
        3 => Role::Retired,
        _ => return Err(Error::Invalid("role")),
    };
    Ok(Candidate {
        number,
        role,
        request: request(c)?,
        seq: c.u64()?,
        id: grain(c)?,
        root: root_bytes(c)?,
        evidence: Evidence {
            started: c.u64()?,
            proved_no_write: c.u64()?,
            last_answered_attempt: c.u64()?,
            decision_seen: boolean(c)?,
        },
    })
}
fn read_probe(c: &mut Cursor<'_>) -> Result<Probe, Error> {
    let cycle = c.u64()?;
    let seq = c.u64()?;
    let reason = match c.u8()? {
        0 => ProbeReason::Started,
        1 => ProbeReason::Interrupted,
        2 => ProbeReason::Transport,
        3 => ProbeReason::Malformed,
        4 => ProbeReason::LocalPersistence,
        5 => ProbeReason::Capacity,
        6 => ProbeReason::ContentUnavailable,
        _ => return Err(Error::Invalid("probe reason tag")),
    };
    Ok(Probe { cycle, seq, reason })
}
fn read_phase(c: &mut Cursor<'_>) -> Result<Phase, Error> {
    Ok(match c.u8()? {
        1 => Phase::Ready,
        2 => Phase::AwaitingAnswer {
            candidate: c.u64()?,
            attempt: c.u64()?,
        },
        3 => Phase::Rebase,
        4 => Phase::EpochRecovery { epoch: array(c)? },
        5 => Phase::ProbeStarted(read_probe(c)?),
        6 => Phase::Unresolved(read_probe(c)?),
        7 => Phase::Complete(Completion {
            seq: c.u64()?,
            id: grain(c)?,
            root: root_bytes(c)?,
            receipt: if boolean(c)? {
                Some(Receipt {
                    position: Position {
                        epoch: Epoch::from_bytes(array(c)?),
                        entry_seq: c.u64()?,
                    },
                    root_seq: c.u64()?,
                    stored_id: grain(c)?,
                })
            } else {
                None
            },
        }),
        _ => return Err(Error::Invalid("phase tag")),
    })
}

/// Strict, bounded decoding of a complete self-checking record.
/// # Errors
/// Damage, unsupported versions, bounds and every format rule violation.
pub fn decode(input: &[u8]) -> Result<Submission, Error> {
    if input.len() > MAX_BYTES {
        return Err(Error::TooLarge);
    }
    let end = input
        .len()
        .checked_sub(32)
        .ok_or(Error::Decode(DecodeError::Truncated))?;
    let (body, check) = input
        .split_at_checked(end)
        .ok_or(Error::Decode(DecodeError::Truncated))?;
    let mut c = Cursor::new(body);
    require(c.take(8)? == MAGIC, "magic")?;
    let version = c.u16()?;
    require(
        usize::try_from(c.u32()?).ok() == Some(input.len()),
        "total length",
    )?;
    require_check(body, check)?;
    if !matches!(version, 1 | VERSION) {
        return Err(Error::Version(version));
    }
    let generation = c.u64()?;
    let publication_id = array(&mut c)?;
    let authority_base = bytes16(&mut c, 8192)?;
    let count = usize::from(c.u8()?);
    require(count <= 8, "pin count")?;
    let mut pins = Vec::with_capacity(count);
    for _ in 0..count {
        pins.push(array(&mut c)?);
    }
    let credential_context = bytes8(&mut c, 255)?;
    let volume =
        VolumeName::from_bytes(&bytes8(&mut c, 63)?).map_err(|_| Error::Invalid("volume"))?;
    let frozen = FrozenIntent {
        writer_identity: array(&mut c)?,
        min_prefix_bits: c.u8()?,
        initial_root: root_bytes(&mut c)?,
    };
    let current = if boolean(&mut c)? {
        Some(request(&mut c)?)
    } else {
        None
    };
    let count = usize::from(c.u16()?);
    require(count <= MAX_CANDIDATES, "candidate count")?;
    let mut candidates = Vec::with_capacity(count);
    for _ in 0..count {
        candidates.push(read_candidate(&mut c)?);
    }
    let phase = read_phase(&mut c)?;
    let last_response = if boolean(&mut c)? {
        Some(LastResponse {
            candidate: c.u64()?,
            attempt: c.u64()?,
            status: c.u16()?,
            token: bytes8(&mut c, 64)?,
            answer: bytes16(&mut c, authority_answer::MAX_BYTES)?,
        })
    } else {
        None
    };
    let unavailable_exemptions = if version == 1 { 0 } else { c.u16()? };
    c.finish()?;
    let value = Submission {
        generation,
        publication_id,
        scope: Scope {
            authority_base,
            pins,
            credential_context,
        },
        volume,
        frozen,
        current,
        candidates,
        phase,
        last_response,
        unavailable_exemptions,
    };
    validate(&value)?;
    Ok(value)
}
fn require_check(body: &[u8], check: &[u8]) -> Result<(), Error> {
    if blake3::derive_key(CHECK_CONTEXT, body) != check {
        return Err(Error::BadCheck);
    }
    Ok(())
}
fn put8(out: &mut Vec<u8>, b: &[u8]) -> Result<(), Error> {
    out.push(u8::try_from(b.len()).map_err(|_| Error::TooLarge)?);
    out.extend_from_slice(b);
    Ok(())
}
fn put16(out: &mut Vec<u8>, b: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(
        &u16::try_from(b.len())
            .map_err(|_| Error::TooLarge)?
            .to_be_bytes(),
    );
    out.extend_from_slice(b);
    Ok(())
}
fn put_root(out: &mut Vec<u8>, b: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(
        &u32::try_from(b.len())
            .map_err(|_| Error::TooLarge)?
            .to_be_bytes(),
    );
    out.extend_from_slice(b);
    Ok(())
}
fn put_request(out: &mut Vec<u8>, r: RequestIdentity) {
    out.extend_from_slice(&r.epoch);
    out.extend_from_slice(&r.operation);
}
fn put_probe(out: &mut Vec<u8>, p: Probe) {
    out.extend_from_slice(&p.cycle.to_be_bytes());
    out.extend_from_slice(&p.seq.to_be_bytes());
    out.push(p.reason as u8);
}
fn put_phase(out: &mut Vec<u8>, p: &Phase) -> Result<(), Error> {
    match p {
        Phase::Ready => out.push(1),
        Phase::AwaitingAnswer { candidate, attempt } => {
            out.push(2);
            out.extend_from_slice(&candidate.to_be_bytes());
            out.extend_from_slice(&attempt.to_be_bytes());
        }
        Phase::Rebase => out.push(3),
        Phase::EpochRecovery { epoch } => {
            out.push(4);
            out.extend_from_slice(epoch);
        }
        Phase::ProbeStarted(p) => {
            out.push(5);
            put_probe(out, *p);
        }
        Phase::Unresolved(p) => {
            out.push(6);
            put_probe(out, *p);
        }
        Phase::Complete(done) => {
            out.push(7);
            out.extend_from_slice(&done.seq.to_be_bytes());
            out.extend_from_slice(&done.id.to_bytes());
            put_root(out, &done.root)?;
            out.push(u8::from(done.receipt.is_some()));
            if let Some(r) = done.receipt {
                out.extend_from_slice(&r.position.epoch.to_bytes());
                out.extend_from_slice(&r.position.entry_seq.to_be_bytes());
                out.extend_from_slice(&r.root_seq.to_be_bytes());
                out.extend_from_slice(&r.stored_id.to_bytes());
            }
        }
    }
    Ok(())
}
/// Canonical encoding; invalid values cannot be persisted through this codec.
/// # Errors
/// The same value rules as decode, plus bounded length arithmetic.
pub fn encode(s: &Submission) -> Result<Vec<u8>, Error> {
    validate(s)?;
    // Validated field caps bound this sum before any encoding allocation.
    let mut size = 16384usize
        .checked_add(s.frozen.initial_root.len())
        .ok_or(Error::TooLarge)?;
    for c in &s.candidates {
        size = size
            .checked_add(c.root.len())
            .and_then(|n| n.checked_add(128))
            .ok_or(Error::TooLarge)?;
    }
    if let Phase::Complete(c) = &s.phase {
        size = size.checked_add(c.root.len()).ok_or(Error::TooLarge)?;
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&s.generation.to_be_bytes());
    out.extend_from_slice(&s.publication_id);
    put16(&mut out, &s.scope.authority_base)?;
    out.push(u8::try_from(s.scope.pins.len()).map_err(|_| Error::TooLarge)?);
    for pin in &s.scope.pins {
        out.extend_from_slice(pin);
    }
    put8(&mut out, &s.scope.credential_context)?;
    put8(&mut out, s.volume.as_str().as_bytes())?;
    out.extend_from_slice(&s.frozen.writer_identity);
    out.push(s.frozen.min_prefix_bits);
    put_root(&mut out, &s.frozen.initial_root)?;
    out.push(u8::from(s.current.is_some()));
    if let Some(r) = s.current {
        put_request(&mut out, r);
    }
    out.extend_from_slice(
        &u16::try_from(s.candidates.len())
            .map_err(|_| Error::TooLarge)?
            .to_be_bytes(),
    );
    for c in &s.candidates {
        out.extend_from_slice(&c.number.to_be_bytes());
        out.push(c.role as u8);
        put_request(&mut out, c.request);
        out.extend_from_slice(&c.seq.to_be_bytes());
        out.extend_from_slice(&c.id.to_bytes());
        put_root(&mut out, &c.root)?;
        out.extend_from_slice(&c.evidence.started.to_be_bytes());
        out.extend_from_slice(&c.evidence.proved_no_write.to_be_bytes());
        out.extend_from_slice(&c.evidence.last_answered_attempt.to_be_bytes());
        out.push(u8::from(c.evidence.decision_seen));
    }
    put_phase(&mut out, &s.phase)?;
    out.push(u8::from(s.last_response.is_some()));
    if let Some(r) = &s.last_response {
        out.extend_from_slice(&r.candidate.to_be_bytes());
        out.extend_from_slice(&r.attempt.to_be_bytes());
        out.extend_from_slice(&r.status.to_be_bytes());
        put8(&mut out, &r.token)?;
        put16(&mut out, &r.answer)?;
    }
    out.extend_from_slice(&s.unavailable_exemptions.to_be_bytes());
    let len = out.len().checked_add(32).ok_or(Error::TooLarge)?;
    out.get_mut(10..14).ok_or(Error::TooLarge)?.copy_from_slice(
        &u32::try_from(len)
            .map_err(|_| Error::TooLarge)?
            .to_be_bytes(),
    );
    let check = blake3::derive_key(CHECK_CONTEXT, &out);
    out.extend_from_slice(&check);
    Ok(out)
}

#[cfg(test)]
mod tests;
