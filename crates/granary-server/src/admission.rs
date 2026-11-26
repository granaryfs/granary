// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The admission gate: §5a.6 steps 1–6, in order, over a borrowed
//! request head.
//!
//! **The step NUMBERS are this crate's enumeration; the ORDER they
//! enumerate is §5a.6's.** §5a.6 fixes the sequence and calls it
//! normative without numbering it, so the numerals below are a local
//! convention — one every "step N" reference in this crate and in
//! `handlers` shares, which is why adding a check renumbers the ones
//! after it.
//!
//! **The ORDER is normative, not an implementation detail.** §5a.6 fixes
//! it — target grammar (`404`), method (`405`), conditional refusal
//! (`400`), range form (`400`), the `BIN_MAX_BYTES` ceiling (`416`), the
//! declared maximum extent (`400`) — and says why: "an accept set that
//! depends on which check ran first is not an accept set". A conditional
//! field on `DELETE {base}/bin/{d}` is `405`; one on a malformed target
//! is `404`; `bytes=99999999999999999999-100` is `400` and not `416`,
//! because the form check precedes satisfiability; and
//! `bytes=268435456-` is `416` and not `400`, because the ceiling
//! precedes deployment policy (§7.1).
//!
//! **What this module is NOT.** It performs no body cap and makes no
//! seam call — those are §5a.6 steps 7 and 8 and belong to the handlers,
//! which is why a handler cannot see the raw target, the method, or
//! whether a conditional field was present. The whole of the order that
//! is decidable from the head is decided here, once.
//!
//! **No hyper type, and no `http` type.** Every field of
//! [`RequestHead`] is a `&str`, a slice of `&str`, or a plain value, so
//! the entire ordered gate is exercisable with no HTTP anywhere in a
//! test. An adapter's whole remaining job is to extract those strings,
//! bound the request content, and dispatch.

use crate::wire::{Allow, Outcome, Resource};
use granary_core::binfmt::{
    BIN_FIXED_HEADER_LEN, BIN_INDEX_ENTRY_LEN, BIN_MAX_BYTES, BIN_TARGET_BYTES, FRAME_COMP_MAX,
    MAX_GRAINS_PER_BIN,
};
use granary_core::hash::{DIGEST_LEN, GrainId, HashAlgorithm};
use granary_core::root::VolumeName;
use granary_core::rootstore::parse_hint_body;

// ------------------------------------------ the declared maximum extent

/// §7.1's **declared maximum extent**, the value this server is deployed
/// with: the widest mapped `len` it will serve on a bin range request.
/// A wider ask is refused WHOLE with `400` + `extent-too-wide` — never
/// truncated, never narrowed and presented as the short read.
///
/// **This server declares exactly §7.1's floor.** The
/// band is `[78 479 383, BIN_MAX_BYTES]`; every byte above the floor is
/// attacker headroom with no client contract behind it, and every byte
/// below it refuses a whole read of a bin this project's packer emits.
/// So the two ends of the useful range coincide and the declaration is
/// the floor itself.
///
/// **A literal pinned by the assertion below, not the expression
/// itself.** §7.1 requires "a static assertion pinning its declared
/// constant to the derivation so either fails a build rather than a
/// read", and a constant DEFINED as the derivation would silently move
/// when a format constant or the packing target moved — which is the
/// one event the rule exists to stop, because the floor is a wire
/// contract every client relies on (§13.1 item 10) and the packing
/// target is a policy choice independent of the bin format.
pub(crate) const DECLARED_MAX_EXTENT: u32 = 78_479_383;

const _: () = {
    // The derivation, from §7.1 and §5a.1: the largest bin the current
    // packing policy can emit — fixed header + a max-count index + the
    // packing target + one maximal closing frame. `granary-core`'s own
    // `const _` block asserts this same sum stays inside BIN_MAX_BYTES;
    // this one asserts the server's declared value IS it.
    let derived = BIN_FIXED_HEADER_LEN as u64
        + MAX_GRAINS_PER_BIN as u64 * BIN_INDEX_ENTRY_LEN as u64
        + BIN_TARGET_BYTES
        + FRAME_COMP_MAX as u64;
    assert!(
        DECLARED_MAX_EXTENT as u64 == derived,
        "§7.1: the declared maximum extent must equal the derivation \
         BIN_FIXED_HEADER_LEN + MAX_GRAINS_PER_BIN * BIN_INDEX_ENTRY_LEN \
         + BIN_TARGET_BYTES + FRAME_COMP_MAX. A format revision or a \
         packing-policy change moved it: re-open this derivation and \
         §7.1's band together, then restate the literal."
    );
    // §7.1's band, both ends. The floor half is the assertion above by
    // construction — the declaration IS the floor — so what this adds is
    // the ceiling: a declared value above BIN_MAX_BYTES could never bind
    // a served byte, because the object bounds the answer first.
    assert!(
        DECLARED_MAX_EXTENT as u64 <= BIN_MAX_BYTES,
        "§7.1: a declared maximum extent above BIN_MAX_BYTES is vacuous"
    );
};

// -------------------------------------- the ingest decompressed-sum limit

// A DoS RESOURCE LIMIT, not a format bound: it caps the WORK a verifying
// server will spend decompressing one bin (§9.2). Sized to ~4 s
// of one core at the measured ~1 GiB/s verify throughput. It is NOT a
// conforming supremum — no such value exists — and what keeps
// a conforming client under it is the packer's own close target, not the
// content: compression ratio alone does not bound a bin, so the assert
// below is the relation that matters. The `16 × BIN_MAX_BYTES` identity
// is rationale, not a derivation — this is a tunable like
// DRAIN_BUDGET_BYTES, so there is NO const-assert against a format
// constant. scripts/check-protocol-constants.py compares it with the reviewed
// limit independently of that derivation.
pub(crate) const INGEST_UNPACKED_SUM_MAX: u64 = 4_294_967_296; // 4 GiB = 16 × BIN_MAX_BYTES

const _: () = {
    // The packer TARGET and the ingest LIMIT are two different things that
    // are numerically related, NOT one shared literal: `granary-core` holds
    // the client's bin-close target and this crate holds the server's
    // refusal ceiling, and this crate is the one place that sees both. What
    // this binds is the headroom between them — a bin packed to the target
    // must never be one this server refuses.
    assert!(granary_core::binfmt::BIN_UNPACKED_TARGET_BYTES <= INGEST_UNPACKED_SUM_MAX);
};

// ------------------------------------------------------- the request head

/// What §5a.6 step 3 reads: every field NAME the request carried, plus
/// the one conditional value this profile acts on.
///
/// **`If-None-Match` carries its VALUE; no other field's value is carried
/// at all, and the asymmetry is forced.** §5a.6 defines exactly one
/// conditional — `If-None-Match` on `GET {base}/volume/{volume}/hint` —
/// and `RootStore::read_hint` takes `cached: Option<&HintToken>`, which
/// is precisely that value: a presence flag would make a matching and a
/// stale request identical at this boundary and §5.8's `304`
/// unimplementable. The other four are refused on sight, and §9.1 item 3
/// makes not parsing them a rule rather than an economy — "a refused
/// field MUST NOT be parsed, and an implementation that parses before
/// refusing has reintroduced the parser it was entitled to skip".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Conditionals<'a> {
    /// The `If-None-Match` field value, verbatim.
    pub if_none_match: Option<&'a str>,
    /// **EVERY received field NAME, in order and unfiltered** — not the
    /// ones an adapter believed were conditional, and not a flag it
    /// computed.
    ///
    /// §5a.6 fixes the SET at five names — `If-Match`, `If-None-Match`,
    /// `If-Modified-Since`, `If-Unmodified-Since`, `If-Range` — and
    /// [`admit`] matches against them here, for the reason [`Allow`] is
    /// derived and the reason `range` takes every field line rather than
    /// the first: a set the caller picks is not a set. A single
    /// `other_present: bool` would let an adapter that had never heard of
    /// `If-Range` supply `false`, and no input to this gate could tell
    /// that apart from a request carrying no conditional at all. Handing
    /// the names over instead moves the decision to the one place that
    /// holds §5a.6.
    ///
    /// NO VALUE is read from any of them, including the four refused
    /// ones: names decide, which is §9.1 item 3's rule expressed as a
    /// type. Names outside the five are ignored, so an adapter passing
    /// `Host` and `User-Agent` costs a comparison and changes nothing —
    /// and matching is ASCII-case-insensitive, because RFC 9110 §5.1
    /// makes a field name case-insensitive.
    pub fields: &'a [&'a str],
}

/// Everything about a request that §5a.6 steps 1–6 read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHead<'a> {
    /// The method token, case-sensitive (RFC 9110 §9.1).
    pub method: &'a str,
    /// The request target's whole remainder — the path WITH its query,
    /// if one arrived — undecoded. §4.3 forbids percent-decoding,
    /// normalisation, case folding and trimming, so a `%` arrives here
    /// as an ordinary byte; and a query is not a component to strip but
    /// bytes no grammar accepts, so `?` failing the segment grammar is
    /// what refuses a query-bearing target. An adapter that hands over
    /// only the path has already widened the accept set before this
    /// gate could see it.
    pub path: &'a str,
    /// The path component of the configured `{base}` (§4.1), stripped
    /// here. Empty when the base URL carries no path.
    ///
    /// §4.1 requires a base path not to end in `/` and forms every
    /// target by concatenation. A misconfigured base ending in `/` is
    /// not repaired here — it simply leaves no `/` to open the
    /// remainder, and every target answers `404` + `unknown-target`,
    /// which is the failure a deployment notices immediately.
    pub base: &'a str,
    /// **EVERY `Range` field line, in order** — not the first one.
    ///
    /// Two attacker-supplied `Range` lines are two elements here, and
    /// [`admit`] refuses more than one. A single `Option<&str>` would
    /// invite an adapter's literal `HeaderMap::get`, which yields only
    /// the first of the two while this gate believed it had seen one
    /// valid range. §7.1 already requires exactly one range-spec; the
    /// field-line count is enforceable at the same gate for free.
    pub range: &'a [&'a str],
    /// The conditional request header fields (§5a.6).
    pub conditionals: Conditionals<'a>,
    /// The peer's declared content length, **advisory and never
    /// trusted** (§5a.2).
    ///
    /// [`admit`] does not read it and MUST NOT refuse on it. §13.2 item 5
    /// is explicit that a declared length "MUST NOT size a buffer and
    /// MUST NOT stand in for the count", and the body cap is a counted
    /// bound one layer out. It rides here so that the streaming cap has
    /// the advisory value at the same boundary the rest of the head
    /// arrives on, and so that nothing downstream has to go looking for
    /// it in a place where it might be mistaken for the counted length.
    pub declared_len: Option<u64>,
}

// -------------------------------------------------------- what comes back

/// One of §4.2's operations, with its target segments already
/// parsed and its range already resolved.
///
/// Root and publish operations retain their parsed volume names; other
/// volume segments borrow the request head. A handler takes these, plus
/// an owned body where its method has one, and needs nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation<'a> {
    /// Authenticated writer-intent control operation.
    Intent {
        /// Parsed volume.
        volume: VolumeName,
        /// Registration, release, ownership or readback.
        operation: crate::authority::IntentOperation,
    },
    /// Anonymous authority observation.
    VolumeStatus {
        /// A DNS-1123 label.
        volume: VolumeName,
    },
    /// Authenticated authority publication.
    Publish {
        /// A DNS-1123 label.
        volume: VolumeName,
    },
    /// `PUT {base}/bin/{digest}`.
    PutBin {
        /// The address the body must hash to (§5.1).
        digest: [u8; DIGEST_LEN],
    },
    /// `GET {base}/bin/{digest}`, whose `Range` is REQUIRED (§5.2, §7).
    GetBinRange {
        /// The address.
        digest: [u8; DIGEST_LEN],
        /// §7.1's `first-pos`, already checked against the ceiling.
        offset: u64,
        /// §7.1's resolved length, clamped to `u32::MAX` on the
        /// open-ended and over-wide forms. Never `0`, and never past
        /// this server's `DECLARED_MAX_EXTENT` — step 6 refuses a
        /// wider ask rather than narrowing it (§7.1), so a handler
        /// receiving this value may serve it as asked.
        len: u32,
    },
    /// `PUT {base}/volume/{volume}/meta/{grain-id}`.
    PutMeta {
        /// A DNS-1123 label (§4.3).
        volume: &'a str,
        /// The address the body must hash to (§5.3).
        id: GrainId,
    },
    /// `GET {base}/volume/{volume}/meta/{grain-id}`.
    GetMeta {
        /// A DNS-1123 label (§4.3).
        volume: &'a str,
        /// The address.
        id: GrainId,
    },
    /// `PUT {base}/volume/{volume}/root/{seq}`.
    PutRoot {
        /// A DNS-1123 label (§4.3).
        volume: VolumeName,
        /// 20 ASCII digits naming a value that fits a `u64` (§4.3).
        seq: u64,
    },
    /// `GET {base}/volume/{volume}/root/{seq}`.
    GetRoot {
        /// A DNS-1123 label (§4.3).
        volume: VolumeName,
        /// 20 ASCII digits naming a value that fits a `u64` (§4.3).
        seq: u64,
    },
    /// `GET {base}/volume/{volume}/max-seq`.
    MaxSeq {
        /// A DNS-1123 label (§4.3).
        volume: &'a str,
    },
    /// `GET {base}/volume/{volume}/hint`.
    ReadHint {
        /// A DNS-1123 label (§4.3).
        volume: &'a str,
        /// The one conditional this profile defines (§5a.6), verbatim.
        /// The caller turns it into a `HintToken` for the seam.
        if_none_match: Option<&'a str>,
    },
    /// `PUT {base}/volume/{volume}/hint`.
    WriteHint {
        /// A DNS-1123 label (§4.3).
        volume: &'a str,
    },
}

impl Operation<'_> {
    /// The §4.2 resource this operation addresses.
    ///
    /// **Derived, never stored beside the operation and never supplied
    /// by a caller.** §4.2 fixes `Allow` per resource, so a resource that
    /// could disagree with the parsed target is the same caller-picks
    /// defect [`Resource::allow`] closes one level down: an operation
    /// naming `max-seq` whose resource said `Bin` would advertise `PUT`
    /// on a read-only resource with nothing able to notice. The match has
    /// no wildcard arm, so a new operation is classified here or does
    /// not compile.
    #[must_use]
    pub const fn resource(&self) -> Resource {
        match self {
            Self::Intent { operation, .. } => match operation {
                crate::authority::IntentOperation::Register
                | crate::authority::IntentOperation::Readback => Resource::Intent,
                crate::authority::IntentOperation::Release => Resource::IntentRelease,
                crate::authority::IntentOperation::Ownership => Resource::IntentOwnership,
            },
            Self::Publish { .. } => Resource::Publish,
            Self::VolumeStatus { .. } => Resource::VolumeStatus,
            Self::PutBin { .. } | Self::GetBinRange { .. } => Resource::Bin,
            Self::PutMeta { .. } | Self::GetMeta { .. } => Resource::Meta,
            Self::PutRoot { .. } | Self::GetRoot { .. } => Resource::Root,
            Self::MaxSeq { .. } => Resource::MaxSeq,
            Self::ReadHint { .. } | Self::WriteHint { .. } => Resource::Hint,
        }
    }

    /// This operation's name, as a BOUNDED token for the `served`
    /// per-request outcome counter.
    ///
    /// **A closed set of values, fixed at compile time, and that is the whole
    /// property.** A counter dimension a peer can widen is a way to make
    /// this process write more per request; the request TARGET is such a
    /// dimension and is deliberately absent from every log field this
    /// server emits. This is what an operator buckets by instead — it
    /// says which of §4.2's endpoints answered, so a refusal countable
    /// only as "some `413`" becomes "a `413` on `put_bin`", which is the
    /// difference between knowing a limit is mis-set and knowing WHICH.
    ///
    /// Snake-cased variant names rather than the §4.1 target shapes: a
    /// target is a thing a request carries and these must never be
    /// confusable with one. The match has no wildcard arm, so a new
    /// operation is named here or does not compile.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.kind().name()
    }

    pub(crate) const fn kind(&self) -> OperationKind {
        match self {
            Self::Intent { operation, .. } => match operation {
                crate::authority::IntentOperation::Register => OperationKind::IntentRegister,
                crate::authority::IntentOperation::Readback => OperationKind::IntentReadback,
                crate::authority::IntentOperation::Release => OperationKind::IntentRelease,
                crate::authority::IntentOperation::Ownership => OperationKind::IntentOwnership,
            },
            Self::Publish { .. } => OperationKind::Publish,
            Self::VolumeStatus { .. } => OperationKind::VolumeStatus,
            Self::PutBin { .. } => OperationKind::PutBin,
            Self::GetBinRange { .. } => OperationKind::GetBinRange,
            Self::PutMeta { .. } => OperationKind::PutMeta,
            Self::GetMeta { .. } => OperationKind::GetMeta,
            Self::PutRoot { .. } => OperationKind::PutRoot,
            Self::GetRoot { .. } => OperationKind::GetRoot,
            Self::MaxSeq { .. } => OperationKind::MaxSeq,
            Self::ReadHint { .. } => OperationKind::ReadHint,
            Self::WriteHint { .. } => OperationKind::WriteHint,
        }
    }
}

/// The operation set and its single mapping to closed diagnostic names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperationKind {
    IntentRegister,
    IntentRelease,
    IntentOwnership,
    IntentReadback,
    Publish,
    VolumeStatus,
    PutBin,
    GetBinRange,
    PutMeta,
    GetMeta,
    PutRoot,
    GetRoot,
    MaxSeq,
    ReadHint,
    WriteHint,
}

impl OperationKind {
    pub(crate) const AUTHENTICATED_WRITES: [Self; 8] = [
        Self::IntentRegister,
        Self::IntentRelease,
        Self::IntentOwnership,
        Self::Publish,
        Self::PutBin,
        Self::PutMeta,
        Self::PutRoot,
        Self::WriteHint,
    ];

    pub(crate) const AUTHENTICATED_READS: [Self; 1] = [Self::IntentReadback];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::IntentRegister => "intent_register",
            Self::IntentRelease => "intent_release",
            Self::IntentOwnership => "intent_ownership",
            Self::IntentReadback => "intent_readback",
            Self::Publish => "publish",
            Self::VolumeStatus => "volume_status",
            Self::PutBin => "put_bin",
            Self::GetBinRange => "get_bin_range",
            Self::PutMeta => "put_meta",
            Self::GetMeta => "get_meta",
            Self::PutRoot => "put_root",
            Self::GetRoot => "get_root",
            Self::MaxSeq => "max_seq",
            Self::ReadHint => "read_hint",
            Self::WriteHint => "write_hint",
        }
    }
}

/// A request that passed target, method, conditional and range admission.
/// The public gate admits seam operations; the adapter's configured gate
/// also admits publish and volume status. Fields remain private so callers cannot bypass
/// these checks. Write authority is separate evidence owned by the adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted<'a> {
    operation: Operation<'a>,
}

impl<'a> Admitted<'a> {
    /// The operation to perform, with its parsed components.
    #[must_use]
    pub const fn operation(&self) -> &Operation<'a> {
        &self.operation
    }

    /// The §4.2 resource, derived from the parsed target.
    #[must_use]
    pub const fn resource(&self) -> Resource {
        self.operation.resource()
    }
}

/// A request [`admit`] refused, carrying the complete response.
///
/// The field is private and every constructor below is private, so a
/// `Refusal` cannot be minted outside this module — which is what makes
/// the `405`'s `Allow` a property of the parse rather than an argument.
#[derive(Debug)]
pub struct Refusal {
    outcome: Outcome,
}

impl Refusal {
    /// `404` + `unknown-target` — step 1 (§4.3).
    fn unknown_target() -> Self {
        Self {
            outcome: Outcome::unknown_target(),
        }
    }

    /// `405` + `method-not-allowed` — step 2, carrying the parsed
    /// resource's own `Allow` (§4.2).
    fn method_not_allowed(resource: Resource) -> Self {
        Self {
            outcome: Outcome::method_not_allowed(resource),
        }
    }

    /// `400` + `bad-request` — step 3 (§5a.6).
    fn bad_request() -> Self {
        Self {
            outcome: Outcome::bad_request(),
        }
    }

    /// `400` + `bad-range` — step 4 (§7.1).
    fn bad_range_form() -> Self {
        Self {
            outcome: Outcome::bad_range_form(),
        }
    }

    /// `416` + `bad-range` — step 5 (§7.1, §7.3).
    fn range_not_satisfiable() -> Self {
        Self {
            outcome: Outcome::range_not_satisfiable(),
        }
    }

    /// `400` + `extent-too-wide` — step 6 (§7.1), the mapped `len` past
    /// this server's [`DECLARED_MAX_EXTENT`].
    fn extent_too_wide() -> Self {
        Self {
            outcome: Outcome::extent_too_wide(),
        }
    }

    /// The response, borrowed.
    #[must_use]
    pub const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// The response, moved out.
    #[must_use]
    pub fn into_outcome(self) -> Outcome {
        self.outcome
    }
}

// ------------------------------------------------------------ the segments

/// §4.3's `{digest}`: exactly 64 characters from `[0-9a-f]`.
///
/// Parsed through `granary-core`'s frozen `GrainId` text parser rather
/// than a second hex decoder written here. §4.3 gives `{digest}` and
/// `{grain-id}`'s hex half the *same* grammar, and one parser is what
/// keeps them identical — a private decoder here could drift into
/// accepting uppercase on one segment and not the other, which is an
/// accept-set divergence no golden vector would show.
fn parse_digest(segment: &str) -> Option<[u8; DIGEST_LEN]> {
    // The width is the whole of the grammar's length half, and checking
    // it first means the string built below is bounded by §4.3 rather
    // than by whatever the target carried. It narrows nothing: 64 hex
    // characters are 64 bytes, so every segment this refuses is one the
    // parser refuses one line later. §9.1 item 1 puts this segment on
    // the untrusted list, and the cheapest refusal is the one that
    // allocates nothing.
    if segment.len() != DIGEST_LEN * 2 {
        return None;
    }
    let id: GrainId = format!("{}:{segment}", HashAlgorithm::Blake3.name())
        .parse()
        .ok()?;
    Some(*id.digest())
}

/// §4.3's `{grain-id}`: exactly `blake3:` followed by 64 characters from
/// `[0-9a-f]`.
///
/// The algorithm is pinned rather than left to the registry. `GrainId`'s
/// parser accepts any *registered* algorithm name, so a second entry in
/// that registry would silently widen this wire accept set past what
/// §4.3 spells out; the check below keeps the two independent.
///
/// **No test can demonstrate the pin today, and that is a property of
/// the registry rather than a gap in the corpus.** `HashAlgorithm` has
/// exactly one variant, so the `sha256:` and `BLAKE3:` rows in
/// `every_segment_is_matched_against_its_total_grammar` are already
/// refused by `GrainId`'s own `from_name`, one step earlier; replacing
/// the line below with `Some(id)` leaves the whole suite green
/// (measured). It is future-proofing that becomes testable the day a
/// second algorithm is registered, and it must survive until then.
fn parse_grain_id(segment: &str) -> Option<GrainId> {
    let id: GrainId = segment.parse().ok()?;
    (id.algorithm() == HashAlgorithm::Blake3).then_some(id)
}

/// §4.3's `{volume}`: a DNS-1123 label.
///
/// `VolumeName` is the enforcement §4.3 names, and applying it here is
/// what makes `RootStoreError::InvalidVolume` unreachable from a served
/// request: the server's parse and the store's are the same predicate.
/// Meta, hint and max-seq keep the borrowed segment for their `&str` seams.
/// Root and publish parsing retain the name for authority admission.
fn is_volume(segment: &str) -> bool {
    VolumeName::from_bytes(segment.as_bytes()).is_ok()
}

/// §4.3's `{seq}`: exactly 20 ASCII digits **whose value fits a `u64`**.
///
/// This is `parse_hint_body`, and deliberately so: §4.3 states the bound
/// once "at the key so that all three agree" — the `{seq}` segment, a
/// `max-seq` body (§5.7) and a `PUT hint` body (§5.9). A saturating or
/// wrapping parse is the wrong answer rather than a lenient one, because
/// it accepts the segment and then addresses a *different* root; core's
/// parser refuses on `checked_mul`/`checked_add` instead.
fn parse_seq(segment: &str) -> Option<u64> {
    parse_hint_body(segment).ok()
}

/// A parsed request target: §4.2's resources, with their segments.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target<'a> {
    Intent {
        volume: VolumeName,
        resource: Resource,
    },
    VolumeStatus {
        volume: VolumeName,
    },
    Publish {
        volume: VolumeName,
    },
    Bin {
        digest: [u8; DIGEST_LEN],
    },
    Meta {
        volume: &'a str,
        id: GrainId,
    },
    Root {
        volume: VolumeName,
        seq: u64,
    },
    MaxSeq {
        volume: &'a str,
    },
    Hint {
        volume: &'a str,
    },
}

impl Target<'_> {
    /// No wildcard arm: a new target is classified here or does not
    /// compile.
    const fn resource(&self) -> Resource {
        match self {
            Self::Intent { resource, .. } => *resource,
            Self::Publish { .. } => Resource::Publish,
            Self::VolumeStatus { .. } => Resource::VolumeStatus,
            Self::Bin { .. } => Resource::Bin,
            Self::Meta { .. } => Resource::Meta,
            Self::Root { .. } => Resource::Root,
            Self::MaxSeq { .. } => Resource::MaxSeq,
            Self::Hint { .. } => Resource::Hint,
        }
    }
}

/// §5a.6 step 1 — §4.3's total grammars, over the whole target.
///
/// **Total over degenerate targets** (§4.3): an empty path, `*`, `.`,
/// `..`, `//`, non-ASCII, control bytes. The remainder is walked with an
/// iterator and matched as a fixed-arity tuple, so there is no index and
/// no slice to get wrong, and a target with a sixth segment falls to the
/// same `None` as one with none.
///
/// Nothing is decoded, trimmed, folded or normalised. `.` and `..` are
/// refused *by the grammar* — they match no literal and no segment
/// grammar — rather than by a traversal check, which §4.3 requires
/// because a check that strips or resolves them is one bug away from
/// addressing outside the intended space.
fn parse_target<'a>(path: &'a str, base: &str) -> Option<Target<'a>> {
    let rest = path.strip_prefix(base)?.strip_prefix('/')?;
    let mut segments = rest.split('/');
    // Five slots: four for the longest target and one more that must be
    // absent. A path with more segments fills the fifth and falls through.
    let head = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    );
    match head {
        (Some("volume"), Some(volume), Some("intent"), suffix, None) => {
            let resource = match suffix {
                None => Resource::Intent,
                Some("release") => Resource::IntentRelease,
                Some("ownership") => Resource::IntentOwnership,
                _ => return None,
            };
            Some(Target::Intent {
                volume: VolumeName::from_bytes(volume.as_bytes()).ok()?,
                resource,
            })
        }
        (Some("bin"), Some(digest), None, None, None) => Some(Target::Bin {
            digest: parse_digest(digest)?,
        }),
        (Some("volume"), Some(volume), Some("meta"), Some(id), None) if is_volume(volume) => {
            Some(Target::Meta {
                volume,
                id: parse_grain_id(id)?,
            })
        }
        (Some("volume"), Some(volume), Some("root"), Some(seq), None) => Some(Target::Root {
            volume: VolumeName::from_bytes(volume.as_bytes()).ok()?,
            seq: parse_seq(seq)?,
        }),
        (Some("volume"), Some(volume), Some("max-seq"), None, None) if is_volume(volume) => {
            Some(Target::MaxSeq { volume })
        }
        (Some("volume"), Some(volume), Some("hint"), None, None) if is_volume(volume) => {
            Some(Target::Hint { volume })
        }
        (Some("volume"), Some(volume), Some("status"), None, None) => Some(Target::VolumeStatus {
            volume: VolumeName::from_bytes(volume.as_bytes()).ok()?,
        }),
        (Some("volume"), Some(volume), Some("publish"), None, None) => Some(Target::Publish {
            volume: VolumeName::from_bytes(volume.as_bytes()).ok()?,
        }),
        _ => None,
    }
}

/// Whether the full target has the publish grammar (independent of method).
pub(crate) fn is_publish_target(path: &str, base: &str) -> bool {
    matches!(parse_target(path, base), Some(Target::Publish { .. }))
}

/// Whether the full target has the status grammar (independent of method).
pub(crate) fn is_status_target(path: &str, base: &str) -> bool {
    matches!(parse_target(path, base), Some(Target::VolumeStatus { .. }))
}

pub(crate) fn is_intent_target(path: &str, base: &str) -> bool {
    matches!(parse_target(path, base), Some(Target::Intent { .. }))
}

// -------------------------------------------------------------- the method

/// The methods v1 defines (§4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verb {
    Get,
    Put,
    Post,
}

/// Whether §4.2 defines `verb` on a resource whose `Allow` is `allow`.
///
/// **The accept set is read off the `Allow` value the `405` would
/// advertise**, so the set this gate accepts and the set the refusal
/// names cannot drift apart — §4.2 forbids advertising a method the
/// server answers `405`, and this is that rule expressed as one function
/// rather than two lists. No wildcard arm.
const fn permits(allow: Allow, verb: Verb) -> bool {
    match (allow, verb) {
        (Allow::GetPost, Verb::Get | Verb::Post)
        | (Allow::GetPut, Verb::Get | Verb::Put)
        | (Allow::Get, Verb::Get)
        | (Allow::Post, Verb::Post) => true,
        (Allow::GetPost, Verb::Put)
        | (Allow::GetPut, Verb::Post)
        | (Allow::Get, Verb::Put | Verb::Post)
        | (Allow::Post, Verb::Get | Verb::Put) => false,
    }
}

// --------------------------------------------------------------- the range

/// §7.1's decimal numerals: `1*DIGIT`, and nothing else — normalised to
/// the digits that carry the value.
///
/// `str::parse` alone is the wrong tool twice over — it accepts a leading
/// `+`, which `1*DIGIT` does not, and the digits are attacker-controlled
/// and "can be arbitrarily long" (RFC 9110 §14.1.2, §9.1 item 2), so a
/// numeral no `u64` holds has to reach a decision rather than wrap.
///
/// **The VALUE is deliberately not produced here.** §7.1 has three
/// different answers for a numeral wider than a `u64` — an over-wide
/// `last-pos` is accepted, a `first-pos` "too large to fit a `u64` at
/// all" is the ceiling's `416`, and either position below the other is
/// still the form check's `400` — and only the caller's place in the
/// range-spec says which. A parser that folded "does not fit" into "is
/// not a numeral" collapses all three onto `400`.
///
/// Leading zeros are stripped because `1*DIGIT` admits them and they
/// change no value; the empty string that leaves is the value zero.
fn digits(text: &str) -> Option<&str> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(text.trim_start_matches('0'))
}

/// Whether `left` names a smaller value than `right`, over two numerals
/// [`digits`] normalised.
///
/// §7.1's invalid-int-range rule compares two POSITIONS and is the FORM
/// check, which runs before the ceiling — so it has to answer for
/// numerals neither position can hold, and a `u64` comparison cannot.
/// With the leading zeros already gone the shorter numeral is the
/// smaller one, and equal widths compare byte for byte, which is what a
/// digit string gives for free.
fn is_below(left: &str, right: &str) -> bool {
    (left.len(), left) < (right.len(), right)
}

/// The numeral's value, or `None` when no `u64` holds it.
fn value(digits: &str) -> Option<u64> {
    if digits.is_empty() {
        // Every digit was a leading zero, so the value is zero and
        // `parse` — which needs `1*DIGIT` — has nothing left to read.
        return Some(0);
    }
    digits.parse::<u64>().ok()
}

/// What §5a.6 step 4 decided about the `Range` field.
///
/// **Three outcomes and not two**, because §7.1 gives a `first-pos` that
/// fits no `u64` the same answer as one at or beyond `BIN_MAX_BYTES` —
/// the ceiling rule "covers a `first-pos` too large to fit a `u64` at
/// all" — while the form check that precedes it still has to run on the
/// numerals as text. Collapsing the two refusals into one `Option` is
/// what makes an over-wide position a `400`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RangeForm {
    /// §7.1's `offset` and resolved `len`. `len` is never `0`.
    Accepted { offset: u64, len: u32 },
    /// The form was accepted and the `first-pos` fits no `u64`, so it is
    /// past the ceiling by construction (§7.1, §7.3).
    ///
    /// **What enforces that answer today is not only this variant.**
    /// Saturating [`value`] to `u64::MAX` instead of refusing lands on
    /// the same `416`, because the gate's ceiling check compares against
    /// `BIN_MAX_BYTES` and `u64::MAX` is above it; the whole suite stays
    /// green (measured). It is kept because the rule is §7.1's and the
    /// enforcement is otherwise a coincidence of two other decisions —
    /// that the ceiling is a `u64` constant below `u64::MAX`, and that
    /// the check has not moved — while saturating would put a position
    /// the request never named into the `offset` a handler then gives
    /// the seam. Wrapping instead of saturating is a live defect and the
    /// corpus catches it.
    PastCeiling,
    /// A form v1 does not accept (§7.1).
    Refused,
}

/// §5a.6 step 4 — §7.1's four range forms, mapped exactly.
///
/// [`RangeForm::Refused`] is `400` + `bad-range`: an absent field, more
/// than one field line, more than one range-spec, a suffix-range
/// (including `bytes=-0`), an invalid int-range at any numeral width, or
/// any spelling outside the grammar.
///
/// [`RangeForm::PastCeiling`] is `416` and is reached only after the
/// form check has passed, which is §7.1's precedence: "the form check
/// runs first, and the ceiling check applies only to a range whose form
/// was accepted".
///
/// The returned `len` is never `0` — the seam pins a zero-length range as
/// an error and the grammar cannot express one anyway (`bytes=10-9` is an
/// invalid int-range, not an empty one; §7.4).
fn parse_range(lines: &[&str]) -> RangeForm {
    // Exactly one field line. More than one is two attacker-supplied
    // ranges, and taking the first would be an accept set decided by the
    // adapter's `get` rather than by this gate.
    let [line] = lines else {
        return RangeForm::Refused;
    };
    let Some((unit, set)) = line.split_once('=') else {
        return RangeForm::Refused;
    };
    // The range unit is a token and RFC 9110 §16.5.1 registers unit names
    // case-insensitively; nothing in this profile narrows that. No other
    // whitespace or case liberty is taken — the value is otherwise
    // matched byte for byte.
    if !unit.eq_ignore_ascii_case("bytes") {
        return RangeForm::Refused;
    }
    // Exactly one range-spec (§7.1): a comma anywhere is multi-range, or
    // an empty list element, and both are refused.
    //
    // **What actually enforces that rule today is not this line.** `set`
    // is split at its FIRST `-` below, so a comma always lands inside
    // `first` or inside a non-empty `last`, and `digits`'s digit
    // scan refuses it there; deleting this guard leaves every comma row
    // in the corpus red-free (measured). It is kept because the rule is
    // §7.1's and the enforcement is otherwise a coincidence of two other
    // decisions — where the split falls, and how strict the numeral
    // parser is — either of which a later change could relax without
    // meaning to widen the accept set to multi-range.
    if set.contains(',') {
        return RangeForm::Refused;
    }
    let Some((first, last)) = set.split_once('-') else {
        return RangeForm::Refused;
    };
    if first.is_empty() {
        // A suffix-range, `bytes=-0` included. Refused for capability,
        // not satisfiability: computing the offset needs the bin's total
        // length and no seam operation supplies one (§7.1).
        return RangeForm::Refused;
    }
    let Some(first) = digits(first) else {
        return RangeForm::Refused;
    };
    // An absent `last-pos` is the open-ended form; a present one must be
    // `1*DIGIT` as well. `bytes=100-notanumber` is a form v1 does not
    // accept and is not over-wide — over-wide is a numeral, and this is
    // not one.
    let last = match last {
        "" => None,
        text => match digits(text) {
            Some(text) => Some(text),
            None => return RangeForm::Refused,
        },
    };

    // §7.1 step 4, THE FORM CHECK, and it runs on the numerals as text
    // so that it answers for positions no `u64` holds. An invalid
    // int-range — `last-pos` present and below `first-pos` — is refused
    // rather than ignored, because ignoring hands back a body the client
    // did not ask for. This is the precedence §7.1 fixes: the form check
    // runs first, so `bytes=99999999999999999999-100` is `400` and not
    // `416`.
    if last.is_some_and(|last| is_below(last, first)) {
        return RangeForm::Refused;
    }

    // §7.1 step 5 begins here: the form was accepted, so the ceiling now
    // applies. A `first-pos` no `u64` holds is past `BIN_MAX_BYTES` by
    // construction, and §7.1 says the ceiling rule "covers a `first-pos`
    // too large to fit a `u64` at all".
    let Some(offset) = value(first) else {
        return RangeForm::PastCeiling;
    };

    // **Open-ended and over-wide `last-pos` are ONE case** (§7.1): both
    // mean the remainder of the representation, asked for as `u32::MAX`
    // bytes and answered by the short read. Sound because BIN_MAX_BYTES
    // is far below u32::MAX, so no legal bin's tail is truncated by the
    // clamp. `value` answering `None` for a numeral wider than a `u64`
    // is exactly the over-wide case, so the two share this line.
    let Some(last_pos) = last.and_then(value) else {
        return RangeForm::Accepted {
            offset,
            len: u32::MAX,
        };
    };
    // Both positions are inclusive (RFC 9110 §14.1.2). `checked_sub`
    // rather than a bare `-`: the form check above already refused every
    // `last-pos` below `first-pos`, so this cannot borrow — and if the
    // textual comparison and the `u64` one ever disagreed, `400` is the
    // answer that disagreement calls for anyway.
    let Some(span) = last_pos.checked_sub(offset) else {
        return RangeForm::Refused;
    };
    let width = span.saturating_add(1).min(u64::from(u32::MAX));
    // The `min` above is what makes this total; the fallback is
    // unreachable and is written rather than asserted.
    let len = u32::try_from(width).unwrap_or(u32::MAX);
    RangeForm::Accepted { offset, len }
}

// -------------------------------------------------------- the conditionals

/// `If-None-Match`, lowercased — the one field name §5a.6 exempts, and
/// the one whose value this profile reads.
const IF_NONE_MATCH: &str = "if-none-match";

/// §5a.6's five conditional request header fields, lowercased.
///
/// **The set lives here and not in a caller.** §5a.6 names exactly these
/// five ("the fields are the five RFC 9110 §13.1 defines") and a server
/// that let its adapter decide which of them counted would have an accept
/// set that varied with the adapter's vintage. The array is fixed-arity,
/// so a sixth field added to the profile is added here or nowhere.
const CONDITIONAL_FIELDS: [&str; 5] = [
    "if-match",
    IF_NONE_MATCH,
    "if-modified-since",
    "if-unmodified-since",
    "if-range",
];

/// Whether `name` is one of §5a.6's five.
///
/// Case-insensitive because RFC 9110 §5.1 makes field names
/// case-insensitive — `if-range`, `If-Range` and `IF-RANGE` are one
/// field, and a case-sensitive test here would be a one-keystroke bypass
/// of the whole refusal.
fn is_conditional_field(name: &str) -> bool {
    CONDITIONAL_FIELDS
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
}

// ---------------------------------------------------------------- the gate

/// §5a.6 steps 1–6, in order.
///
/// 1. **Target grammar** (§4.3) → `404` + `unknown-target`.
/// 2. **Method** (§4.2) → `405` + `method-not-allowed`, with the parsed
///    resource's own `Allow`. `HEAD` is `405` on every resource.
/// 3. **Conditional refusal** (§5a.6) → `400` + `bad-request`, on
///    presence and without parsing the field. The one exemption is the
///    (field, resource, method) triple `If-None-Match` + hint + `GET`.
/// 4. **Range form** (§7.1) → `400` + `bad-range`, on `GET bin` only,
///    where a `Range` is REQUIRED. On every other operation a `Range` is
///    IGNORED and answered in full (§6, RFC 9110 §14.2).
/// 5. **The `BIN_MAX_BYTES` ceiling** (§7.1, §7.3) → `416` + `bad-range`,
///    decided from a frozen constant before any store is touched.
/// 6. **The declared maximum extent** (§7.1) → `400` +
///    `extent-too-wide`, on the mapped `len`, decided from
///    `admission::DECLARED_MAX_EXTENT` and equally without the store.
///    After the
///    ceiling, because a `416` is a permanent truth and this is
///    deployment policy.
///
/// `declared_len` is not read: §5a.2 makes a declared length advisory,
/// and the body cap is step 7's counted bound.
///
/// # Errors
/// A [`Refusal`] carrying the complete response — status, token, and the
/// `Allow` field on a `405`.
// The lifetime is NAMED rather than elided, and both spellings of the
// elided form are wrong here. `&RequestHead` trips
// `elided_lifetimes_in_paths`, which CI denies; `&RequestHead<'_>` with
// an `Admitted<'_>` return is E0106, because a reference to a struct that
// itself carries a lifetime is TWO input lifetime positions and elision
// then has nothing to pick. Naming `'a` on the borrowed DATA (not on the
// borrow of the head) is also what lets the result outlive the `&head`.
pub fn admit<'a>(head: &RequestHead<'a>) -> Result<Admitted<'a>, Refusal> {
    admit_declaring_inner(head, Some(DECLARED_MAX_EXTENT), false)
}

/// The seam gate with a test-selected extent declaration.
/// The production service fixes its declaration in `GrainService::new`.
#[cfg(test)]
pub(crate) fn admit_declaring<'a>(
    head: &RequestHead<'a>,
    max_extent: Option<u32>,
) -> Result<Admitted<'a>, Refusal> {
    admit_declaring_inner(head, max_extent, false)
}

/// Apply the configured extent and authority endpoint admission.
pub(crate) fn admit_authority<'a>(
    head: &RequestHead<'a>,
    max_extent: Option<u32>,
    authority: bool,
) -> Result<Admitted<'a>, Refusal> {
    admit_declaring_inner(head, max_extent, authority)
}

/// The one body all admission doors run, so the profiles cannot diverge in
/// any step but the ones they declare.
fn admit_declaring_inner<'a>(
    head: &RequestHead<'a>,
    max_extent: Option<u32>,
    authority: bool,
) -> Result<Admitted<'a>, Refusal> {
    // Step 1 — the target's total grammar. Runs first, so a malformed
    // target is `404` whatever the method and whatever else was sent.
    let target = parse_target(head.path, head.base).ok_or_else(Refusal::unknown_target)?;
    if matches!(
        target,
        Target::Intent { .. } | Target::Publish { .. } | Target::VolumeStatus { .. }
    ) && !authority
    {
        return Err(Refusal::unknown_target());
    }
    let resource = target.resource();

    // Step 2 — the method, against this resource's own set. `HEAD` and
    // every other token reach the same arm: `405` with an `Allow` that
    // names neither (§4.2).
    let verb = match head.method {
        "GET" => Verb::Get,
        "PUT" => Verb::Put,
        "POST" => Verb::Post,
        _ => return Err(Refusal::method_not_allowed(resource)),
    };
    if !permits(resource.allow(), verb) {
        return Err(Refusal::method_not_allowed(resource));
    }

    // Step 3 — the conditional refusal. The exemption is ONE (field,
    // resource, method) triple: `If-None-Match` on `GET hint`. Presence
    // is the trigger; no value is parsed, compared, or evaluated.
    //
    // The set of five is applied HERE, to the names the request actually
    // carried, so an adapter that has never heard of `If-Range` cannot
    // narrow it by omission. The `if_none_match` term is the other
    // direction of the same guard: a value handed over without its name
    // in `fields` is still a field that arrived, and outside the
    // exemption it is still refused.
    let exempt = matches!((resource, verb), (Resource::Hint, Verb::Get));
    let refused_conditional = (head.conditionals.if_none_match.is_some() && !exempt)
        || head.conditionals.fields.iter().any(|name| {
            is_conditional_field(name) && !(exempt && name.eq_ignore_ascii_case(IF_NONE_MATCH))
        });
    if refused_conditional {
        return Err(Refusal::bad_request());
    }

    // Steps 4 and 5 — the range, on `GET bin` alone. Everywhere else the
    // field is IGNORED rather than refused (§6): RFC 9110 §14.2 grants
    // ignoring outright, so it costs no deviation and states nothing
    // false, while §5a.6 refuses a conditional because §13.2.1 grants no
    // equivalent. The two rules must not be tidied into one.
    let operation = match (target, verb) {
        (Target::Intent { volume, resource }, verb) => {
            let operation = match (resource, verb) {
                (Resource::Intent, Verb::Get) => crate::authority::IntentOperation::Readback,
                (Resource::Intent, Verb::Post) => crate::authority::IntentOperation::Register,
                (Resource::IntentRelease, Verb::Post) => crate::authority::IntentOperation::Release,
                (Resource::IntentOwnership, Verb::Post) => {
                    crate::authority::IntentOperation::Ownership
                }
                _ => return Err(Refusal::method_not_allowed(resource)),
            };
            Operation::Intent { volume, operation }
        }
        (Target::Bin { digest }, Verb::Get) => {
            let (offset, len) = match parse_range(head.range) {
                RangeForm::Accepted { offset, len } => (offset, len),
                // Step 4: a form v1 does not accept, refused before
                // satisfiability is considered at all (§7.1, §8.2).
                RangeForm::Refused => return Err(Refusal::bad_range_form()),
                // Step 5, on the one route where the form check has
                // already passed and no `u64` holds the position: §7.1's
                // ceiling covers it, so it is the same `416` every other
                // position past the ceiling gets.
                RangeForm::PastCeiling => return Err(Refusal::range_not_satisfiable()),
            };
            if offset >= BIN_MAX_BYTES {
                return Err(Refusal::range_not_satisfiable());
            }
            // Step 6 — the declared maximum extent (§7.1). It binds the
            // MAPPED `len`: the value the table produced, after its
            // `u32::MAX` clamp, which is why it reads `len` here rather
            // than re-deriving anything from the numerals.
            //
            // **After the ceiling, and the order is normative.** Every
            // request past the ceiling also maps to a `len` past every
            // declared maximum, so a check placed above the line would
            // answer `400` where §7.1 requires `416` — "the ceiling is a
            // permanent truth from a frozen constant that no resizing of
            // the ask can cure, so it must not be reachable only for
            // asks a policy happens to admit".
            //
            // **Store-free, like the ceiling above it.** The bound is on
            // the ASK, not on the answer: refusing only what the store
            // could not have served would make the refusal boundary a
            // length oracle (§7.4) and cost a read per refusal.
            // Refusing only what the store could not serve is forbidden; §13.4's
            // stored-100-byte-bin row is the executable witness.
            //
            // `is_some_and` is the non-enforcing profile: §7.1 is a
            // SHOULD whose named escape is a streaming server, and
            // `None` is that declaration. The production door cannot
            // reach it (see `admit_declaring`).
            if max_extent.is_some_and(|max| len > max) {
                return Err(Refusal::extent_too_wide());
            }
            Operation::GetBinRange {
                digest,
                offset,
                len,
            }
        }
        (Target::VolumeStatus { volume }, Verb::Get) => Operation::VolumeStatus { volume },
        (Target::VolumeStatus { .. }, Verb::Put | Verb::Post) => {
            return Err(Refusal::method_not_allowed(resource));
        }
        (Target::Publish { volume }, Verb::Post) => Operation::Publish { volume },
        (Target::MaxSeq { .. }, Verb::Put)
        | (Target::Publish { .. }, Verb::Get | Verb::Put)
        | (
            Target::Bin { .. }
            | Target::Meta { .. }
            | Target::Root { .. }
            | Target::Hint { .. }
            | Target::MaxSeq { .. },
            Verb::Post,
        ) => return Err(Refusal::method_not_allowed(resource)),
        (Target::Bin { digest }, Verb::Put) => Operation::PutBin { digest },
        (Target::Meta { volume, id }, Verb::Get) => Operation::GetMeta { volume, id },
        (Target::Meta { volume, id }, Verb::Put) => Operation::PutMeta { volume, id },
        (Target::Root { volume, seq }, Verb::Get) => Operation::GetRoot { volume, seq },
        (Target::Root { volume, seq }, Verb::Put) => Operation::PutRoot { volume, seq },
        (Target::MaxSeq { volume }, Verb::Get) => Operation::MaxSeq { volume },
        (Target::Hint { volume }, Verb::Get) => Operation::ReadHint {
            volume,
            if_none_match: head.conditionals.if_none_match,
        },
        (Target::Hint { volume }, Verb::Put) => Operation::WriteHint { volume },
    };
    Ok(Admitted { operation })
}

#[cfg(test)]
mod tests;
