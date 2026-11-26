// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The root CAS contract. PURE: no `object_store` types,
//! no tokio, std only —
//! the trait is what granary-store implements and what the sim
//! and tests fake.
//!
//! **Numbered roots + put-if-absent**, not single-key If-Match: roots
//! live at `root/{volume}/{seq:020}` and are created with a create-only
//! PUT; no root is ever overwritten, so the chain is append-only by
//! construction (the `SlateDB` manifest pattern; the single-key
//! If-Match design was refuted by the Delta/Iceberg record).
//!
//! **THE ONE-PROBE RULE (normative here; every other doc site points
//! at this paragraph — scattered restatements are how four review
//! rounds found stale paraphrases):** a failed create-only PUT — any
//! failure, [`RootStoreError::AlreadyExists`] or transport — is
//! AMBIGUOUS, because an internally retried PUT can fail against the
//! caller's OWN landed first attempt. (`Ok` needs no probe: a
//! create-only success means this writer created the root.) The caller
//! resolves any FAILURE with ONE [`RootStore::get_root`] probe of the
//! attempted seq, read against this table:
//!
//! - byte-identical contents = the publish LANDED (success);
//! - foreign contents, OR a [`RootStoreError::RefusedResponse`] whose
//!   [`RefusalKind`] is [`RefusalKind::OverCap`] = a LOST RACE. An
//!   object over the object class's own read cap is one no legal publish
//!   here could have produced, so the refusal is exactly as informative
//!   as foreign bytes: a re-run re-resolves the VERIFIED head and
//!   republishes on top, or fails loudly on an invalid occupant — never
//!   blindly retry the same seq;
//! - a `RefusedResponse` of ANY OTHER kind proves nothing about the
//!   occupant — a framing fault or a work limit is a statement about the
//!   TRANSPORT, not about what holds the seq — so it is UNRESOLVED, the
//!   row below;
//! - nothing there is UNRESOLVED, not "surface the original failure".
//!   That reading is sound only when the failed PUT's own answer was
//!   TERMINAL: the store itself answered, AND the caller can prove the
//!   answering attempt was the ONLY attempt sent. No implementation in
//!   this workspace carries that proof today — `granary-store`'s adapter
//!   rides `object_store`, which retries a create PUT internally on
//!   several classes of failure, and `HttpStore` makes one send plus one
//!   resend only when the client stack proves the first request unsent;
//!   every other failure is UNRESOLVED and probed. The SERVER behind it
//!   is `object_store` too, so a terminal answer
//!   over HTTP still settles only the server's last attempt, not
//!   necessarily the only one the client's own call caused. Absent a
//!   carrier for "this was the only attempt", every "failure, then
//!   nothing at the seq" is UNRESOLVED, [`RootStoreError::Elapsed`]
//!   included: an implementation that later proves single-attempt for
//!   one of its failures may surface the original error for that case,
//!   and only that case.
//!
//! UNRESOLVED carries BOTH the PUT's own error and whatever the probe
//! established (its error, or the fact that it found nothing) — never
//! discarding either — because the outcome is genuinely unknown and a
//! re-run resolves it from the chain, not from a guess made here.
//!
//! The refusal kind is carried BY TYPE — [`RefusalKind`], assigned by
//! the producer that raises the refusal — never by matching the
//! diagnostic `reason` text, which stays free-form and MUST NOT be
//! parsed by any caller.
//!
//! **The hint is ADVISORY.** `root/{volume}/CURRENT` holds exactly the
//! 20-digit zero-padded seq ([`format_hint_body`]) so a reader can find
//! the head in one cheap, revalidatable GET (the TTL poll: `304 Not
//! Modified` costs O(1) regardless of body size, and LIST can neither
//! 304 nor be cheap). It is NEVER truth: the numbered chain and the
//! signatures are. A stale hint is a DESIGNED state — the crash window
//! between a successful root CAS and the hint PUT produces one, and it
//! is undetectable by inspection — so readers FORWARD-PROBE
//! (`get_root(hint.checked_add(1)?)`, a cheap 404 when there is
//! nothing there), `gran refresh` always probes, and every successful
//! publish repairs the hint. The probe is CHECKED, not `hint + 1`:
//! [`parse_hint_body`] accepts any 20-digit value including
//! `u64::MAX` from the attacker-writable CURRENT object (a pinned
//! accept case), so a reader built to an unchecked rule would panic
//! under `overflow-checks` or wrap to the never-valid seq 0. The rule
//! text is normative — it is what the client's reader is built from.
//!
//!
//! **SEQ 0 IS NEVER A HEAD.** [`parse_hint_body`] ACCEPTS `0` — twenty
//! zero digits is a well-formed body — but `root.rs` refuses seq 0 at
//! both encode and decode, so no root can ever exist there. Both read
//! paths therefore exclude it, and this is a CONTRACT obligation on
//! every implementation, not an adapter detail:
//!
//! - [`RootStore::max_seq`] must not return `Some(0)`. A planted
//!   `…/00000000000000000000` object would otherwise become the head and
//!   block the first publish to a fresh volume.
//! - [`RootStore::read_hint`] must answer [`HintRead::Missing`] for a
//!   body of `0`, not `Current { seq: 0 }`, which would send every
//!   reader through a doomed `get_root(0)` first.
//!
//! Stated here because a FAKE that omits it diverges from production on
//! attacker-writable input while every test still passes — the accept-set
//! divergence this module's `checked_volume` paragraph guards against in
//! the other direction.
//!
//! **SEQ `u64::MAX` IS NEVER A HEAD EITHER, and the usable seq space is
//! `1 ..= u64::MAX - 1`**. The value is RESERVED, not
//! unspellable: [`parse_hint_body`] accepts it (the pinned accept case
//! above), `put_root` still creates at it, and [`RootStore::get_root`]
//! still returns whatever is there — which is the only recovery path an
//! operator has for a planted object. What no implementation may do is
//! SELECT it, and unlike seq 0 this costs an obligation at BOTH ends:
//!
//! - [`RootStore::max_seq`] must not return `Some(u64::MAX)`. The head
//!   is the numeric maximum over the keys that EXIST and a create-only
//!   PUT never releases one, so an object planted at
//!   `…/18446744073709551615` would otherwise be the head forever with
//!   no higher seq left to publish at. Seq 0 blocks the FIRST publish to
//!   a volume; `u64::MAX` blocks EVERY publish to it. Excluding it is a
//!   SKIP in the fold, never an error, so the head falls back to the
//!   next real seq and the volume stays publishable.
//! - A PUBLISHER must not write a root there. This half gets no free
//!   ride the way seq 0 does — seq 0 is unselectable by construction (a
//!   first publish is seq 1, and `head + 1` is at least 2 because
//!   `max_seq` never answers 0), whereas `u64::MAX - 1` is a LEGAL head
//!   that `head + 1` walks straight into. A publisher whose next seq
//!   would be `u64::MAX` must REFUSE rather than write a root that the
//!   rule above then hides from every reader; a publish that reported
//!   success there would be strictly worse than one that failed
//!   (`granary_client::publish` refuses with `CounterOverflow`).
//!
//! The hint is deliberately untouched at this end of the range: it is
//! advisory and overwritable, so a hint of `u64::MAX` strands nothing,
//! and the CHECKED forward probe above is already total on it.
//!
//! This is the Iceberg `version-hint.text` failure class
//! (#1349/#1496/#1465) designed around rather than re-run.
//!
//! **CANCELLATION SAFETY: NONE of these futures is cancel-safe, and
//! [`RootStore::put_root`] is the one that hurts.** Each method's own
//! section states its case; the rule that governs callers is here,
//! because it is about the CHOREOGRAPHY rather than about any one call.
//!
//! A dropped `put_root` is WORSE than an ambiguous failure handled by
//! the one-probe rule. An ambiguous failure is at least VISIBLE — the caller
//! holds an error and runs the one probe. A dropped future returns
//! NOTHING: the request may already be in flight, it may still land
//! after the drop, and the caller has no error to react to, so the
//! one-probe never runs and the volume is left in exactly the state the
//! probe exists to resolve. `select!`ing on a `put_root`, or wrapping
//! one in `tokio::time::timeout`, therefore silently converts a
//! resolvable ambiguity into an unresolved one.
//!
//! A timeout around `put_root` must do one of two things: run the
//! [`RootStore::get_root`] probe ITSELF before reporting failure, or
//! return a DISTINCT error meaning *attempted, outcome unknown, not
//! probed* — which its own caller must then resolve. Silently mapping it
//! to a generic timeout is the bug this paragraph exists to prevent.
//!
//! **The HTTP adapter takes the second option, at the SEAM rather than around the
//! choreography.** `HttpStore::put_root` bounds its own call with a
//! per-call deadline (the idle form: a call that neither completes nor
//! fails inside it is a wedged peer, cut) and, on expiry, returns
//! [`RootStoreError::Elapsed`] — the distinct error this paragraph
//! requires, never a generic timeout. `commit`'s existing one-probe
//! branch is unconditional on ANY `put_root` failure, so an `Elapsed`
//! reaches it exactly like `AlreadyExists` or a transport error and the
//! SAME probe runs, with no new choreography. The probe's own
//! `get_root` carries its OWN per-call deadline, and a probe that
//! itself elapses is carried alongside the PUT's own error, not
//! discarded in its favour (`PublishError::ProbeUnresolved`
//! holds both errors), so the ambiguity is
//! never silently traded for a different one, nor silently narrowed to
//! only half of what is known.
//!
//! Implementation rules that live with the trait:
//! single-shot PUTs only (conditional multipart is unsupported upstream
//! and AWS caps a single PUT at 5 GiB — far above any root); version
//! tokens are ECHOED from the store, never derived; and `max_seq`
//! sorts CLIENT-side because list order is not a contract.
//!
//! The fixed-width decimal root keys let [`RootStore::max_seq_above`]
//! start a lexicographic listing after the floor's canonical key. Every
//! canonical key for a higher seq sorts after that offset. A backend
//! must still check the parsed seq numerically: a raw key that sorts
//! after the offset can normalize to the floor's key.

use std::future::Future;
use std::time::Duration;

/// Digits in an object-store root key's seq component and in the
/// CURRENT hint body: 20 covers `u64::MAX`, and zero-padded decimal
/// makes lexicographic listing agree with numeric order where a server
/// happens to sort (the client sorts numerically regardless).
pub const SEQ_KEY_DIGITS: usize = 20;

const _: () = {
    // 20 digits is exactly what u64::MAX needs — one fewer would make
    // the padding lossy, one more would break the fixed-width parse.
    assert!(u64::MAX.ilog10() as usize + 1 == SEQ_KEY_DIGITS);
};

/// An opaque store version token (an `ETag` on S3/`MinIO`). ECHOED
/// verbatim — granary never derives, parses, or compares it against
/// anything but a token the store gave it (`MinIO` returns
/// `version: None`, so the `ETag` alone is the token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HintToken(pub String);

/// The result of a conditional hint read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintRead {
    /// The cached token is still current (a real 304) — no body was
    /// transferred.
    NotModified,
    /// The hint's body, with the token to cache for the next poll.
    Current { seq: u64, token: HintToken },
    /// No hint object exists (a volume published before the first hint
    /// write, or a lost hint). NOT an error: the reader falls back to
    /// listing the chain.
    Missing,
}

/// Why a [`RootStore`] operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootStoreError {
    /// Put-if-absent found the seq occupied — an AMBIGUOUS outcome
    /// resolved by the module-level ONE-PROBE RULE (the one normative
    /// statement; see the module docs).
    AlreadyExists,
    /// A conditional update failed. This variant deliberately covers
    /// BOTH "the token was stale" and "the object vanished":
    /// `object_store` collapses them into one error (verified on
    /// `MinIO` and `InMemory`), so callers must re-read and
    /// retry rather than branch on a distinction the backend does not
    /// provide.
    Precondition,
    /// The object is not there (a 404 on a path that required one).
    NotFound,
    /// A range read's `offset + len` overflowed `u64` before any
    /// request reached the backend — refused by checked arithmetic
    /// rather than panicking (binmap.rs: `offset` carries no local
    /// upper bound, so a decoded-but-adversarial extent must be
    /// refused here, the way `binfmt::frame_bytes` refuses it on the
    /// read side).
    RangeOverflow,
    /// The volume name is not a valid [`crate::root::VolumeName`], so
    /// it was never turned into a store key. The trait takes `&str`
    /// for callers' convenience, but a name is KEY MATERIAL here —
    /// `root.rs`'s label rules are the enforcement, and an
    /// implementation must apply them itself rather than trust that a
    /// caller already did (the server, relaying a client-supplied
    /// name, is the caller this exists for).
    InvalidVolume {
        /// The rule the name violated, rendered.
        reason: String,
    },
    /// GRANARY refused the store's response before its bytes were used:
    /// the object is larger than the cap that read path enforces, or the
    /// backend answered an extent the request never asked for.
    ///
    /// Deliberately NOT [`Self::Backend`], which is "anything else the
    /// backend REPORTED". Nothing is reported here — the backend
    /// answered successfully and granary declined the answer. The
    /// distinction is what a relaying caller needs: a transport error
    /// invites a retry, while an object that exceeds a frozen format cap
    /// will exceed it again on every attempt.
    ///
    /// **PERMITTED, not required.** Implementations MAY refuse a response
    /// that exceeds the cap for the kind of object being read, and every
    /// caller must therefore tolerate this variant from any read. No
    /// implementation is OBLIGED to produce it, which is why it is not a
    /// conformance-suite semantic: the caps belong to whatever a given
    /// implementation reads from — the granary-store adapter bounds
    /// `object_store` responses against the frozen format ceilings, while
    /// an in-process fake holds owned `Vec`s that carry no advertised
    /// length and no stream, so it has nothing to bound.
    RefusedResponse {
        /// The bound that was violated, rendered.
        ///
        /// **DIAGNOSTIC ONLY — never relay this to a remote client.** It
        /// names the store key that was read, so forwarding it discloses
        /// the bucket's key layout to whoever provoked the refusal. A
        /// server maps this variant to a status and a fixed phrase, and
        /// keeps the text for its own logs.
        reason: String,
        /// WHY the response was refused, assigned by the producer that
        /// raises the refusal — never inferred from `reason`, which a
        /// caller must not parse. The ONE-PROBE RULE (module docs) is
        /// this field's reason to exist: only [`RefusalKind::OverCap`]
        /// proves the probed seq holds a foreign object, and every other
        /// kind leaves the occupant unresolved.
        kind: RefusalKind,
    },
    /// The store answered `429 Too Many Requests` or `503 Service Unavailable`
    /// — an explicit, transient refusal, never folded into [`Self::Backend`]'s free-text
    /// bucket the way a rendered status string would be, forcing
    /// string matching. A caller's retry policy cannot
    /// classify on a rendered message; it needs a TYPED signal, which is
    /// the whole reason this variant exists rather than one more
    /// `Backend("… unexpected status")`.
    Unavailable {
        /// The endpoint that answered the refusal, in the same words a
        /// caller's own seam labels already use (`"GET meta"`, `"GET
        /// bin"`, …) — never a caller-supplied string, so it carries
        /// nothing an attacker chose.
        operation: &'static str,
        /// The HTTP status supplied by the peer (`429` or `503`).
        status: u16,
    },
    /// A per-seam-call deadline expired before this
    /// call either completed or failed — a wedged peer, cut. Never a
    /// whole-flow figure: the caller's own choreography (the ONE-PROBE
    /// RULE among others) is built from a finite sequence of these
    /// individually-bounded calls, so nothing above this seam times out
    /// on its own.
    ///
    /// Deliberately typed rather than folded into [`Self::Backend`]'s
    /// free-text bucket, the same reason [`Self::Unavailable`] is: a
    /// caller's retry policy needs to know a cut wedged peer from
    /// anything the backend actually SAID. Never-retry holds BY
    /// CONSTRUCTION, not by any classifier: the variant is built
    /// outside the transport retry layer, after the whole call — both
    /// wire attempts included — was dropped, so no classifier ever
    /// sees it and nothing loops on it. Retrying a call that already
    /// ran out its own clock would spend a second deadline on the same
    /// wedge rather than surface it; a caller adding a retry loop over
    /// this variant would be re-introducing exactly that.
    Elapsed {
        /// The seam that was cut, in the same words a caller's own seam
        /// labels already use (`"PUT bin"`, `"GET meta"`, …) — never a
        /// caller-supplied string, so it carries nothing an attacker
        /// chose.
        operation: &'static str,
        /// The deadline that expired, carried so the message states the
        /// figure rather than referring to a constant.
        after: Duration,
    },
    /// The server answered a status the operation does not list (§8.1's
    /// totality rule) and no typed variant above covers it.
    ///
    /// Typed rather than rendered into [`Self::Backend`]'s free text so a
    /// caller can name the failing call and its status without parsing a
    /// message, and without echoing anything the peer chose.
    UnexpectedStatus {
        /// The endpoint that answered, in the same fixed words as
        /// [`Self::Unavailable`] (`"PUT bin"`, `"GET root"`, ...).
        operation: &'static str,
        /// The HTTP status the peer supplied.
        status: u16,
        /// The `Granary-Error` token the answer carried, kept only when it
        /// has §8.2's shape (lowercase letters, digits and `-`, a bounded
        /// length). It is for [`Display`](std::fmt::Display); a diagnostic
        /// that must not repeat peer text leaves it out.
        token: Option<String>,
    },
    /// Anything else the backend reported, as its own message.
    Backend(String),
}

impl RootStoreError {
    /// The variant as a fixed, bounded label: one word per variant, no
    /// message, no peer text.
    ///
    /// **These are NOT `Granary-Error` tokens.** The server logs this
    /// vocabulary and the client's diagnostics build on it; neither ever
    /// reaches a wire header. No wildcard arm: a new variant must be
    /// classified here before the workspace compiles.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::AlreadyExists => "already-exists",
            Self::Precondition => "precondition",
            Self::NotFound => "not-found",
            Self::RangeOverflow => "range-overflow",
            Self::InvalidVolume { .. } => "invalid-volume",
            Self::RefusedResponse { .. } => "refused-response",
            Self::Unavailable { .. } => "unavailable",
            Self::Elapsed { .. } => "elapsed",
            Self::UnexpectedStatus { .. } => "unexpected-status",
            Self::Backend(_) => "backend",
        }
    }
}

impl std::fmt::Display for RootStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists => {
                write!(f, "put-if-absent: an object already holds that seq")
            }
            Self::Precondition => write!(
                f,
                "precondition failed (stale token or object vanished — re-read and retry)"
            ),
            Self::NotFound => write!(f, "object not found"),
            Self::RangeOverflow => {
                write!(f, "range read: offset + len overflows u64")
            }
            Self::InvalidVolume { reason } => {
                write!(f, "volume name never became a store key: {reason}")
            }
            Self::RefusedResponse { reason, .. } => {
                write!(f, "refused the store's response: {reason}")
            }
            Self::Unavailable { operation, status } => match status {
                429 => write!(f, "{operation}: too many requests (429)"),
                503 => write!(f, "{operation}: service unavailable (503)"),
                _ => write!(f, "{operation}: {status}"),
            },
            Self::Elapsed { operation, after } => write!(
                f,
                "{operation}: did not complete or fail within {}s — a wedged peer, cut",
                after.as_secs()
            ),
            Self::UnexpectedStatus {
                operation,
                status,
                token: Some(token),
            } => write!(f, "store: {operation}: {status} {token}"),
            Self::UnexpectedStatus {
                operation,
                status,
                token: None,
            } => write!(f, "store: {operation}: unexpected status {status}"),
            // **`store` and not `object store`, on a SHARED seam**.
            // Two routes construct this variant and only one of them has
            // an object store: `granary-store`'s adapter wraps an
            // `object_store::Error`, and `granary-client`'s `HttpStore`
            // wraps a transport failure against a granary SERVER.
            //
            // `store` is the noun this trait is named for, the one
            // [`Self::RefusedResponse`] above already renders ("refused
            // the store's response"), and the one the server's own
            // handlers use for both ("carries text that names the
            // store"). So the two spellings on this type agree, and the
            // word is true wherever the variant is built.
            //
            // `granary-client`'s `RouteError::Store` keeps `object
            // store:` and is CORRECT: it renders an `object_store`
            // builder failure, on the one route that really has one.
            Self::Backend(msg) => write!(f, "store: {msg}"),
        }
    }
}

impl std::error::Error for RootStoreError {}

/// Why a [`RootStoreError::RefusedResponse`] was raised — the ONE-PROBE
/// RULE's typed evidence (module docs). Assigned by the producer that
/// raises the refusal, never inferred from the diagnostic `reason` text.
///
/// The set is closed to the refusals this workspace's read paths
/// produce today; a producer that needs a new reason to refuse a
/// response adds a variant here rather than overloading an existing
/// one, because the ONE-PROBE RULE branches on this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// The object is larger than the read cap for its OBJECT CLASS (a
    /// root, a meta object, a bin) — the bound no LEGAL object of that
    /// class can exceed. On the settling probe (`get_root`) that class
    /// bound is [`crate::root::ROOT_MAX_BYTES`], the root format's own
    /// reader ceiling — which is what makes this the one refusal kind
    /// that proves an occupant is foreign: an object too large to be a
    /// legal root under the FORMAT is one this writer could not have
    /// produced, on any adapter, not merely one this particular reader
    /// declined.
    ///
    /// **Trusts the store's advertised size where advertised size is
    /// the gate.** An implementation that refuses before reading a body
    /// byte (`granary-store`'s `get_bounded`) reports `OverCap` from the
    /// backend's own advertised length, never from bytes it read. A
    /// store that lies about that length to dodge this gate can already
    /// forge a lost race by returning other bytes at the probed seq —
    /// object identity is verified by comparing the CONTENT, not by
    /// trusting the store not to lie — so trusting the advertisement
    /// here adds no exposure beyond what the probe already accepts.
    OverCap,
    /// A ranged read's answer does not match the extent it asked for:
    /// wrong start, a response reaching past the requested end, an
    /// extent spanning nothing, an extent wider than the object kind
    /// being read could ever legally be, or a body that does not match
    /// its own declared extent. Never produced by the ONE-PROBE RULE's
    /// settling probe, which reads a root wholesale rather than by
    /// range.
    Extent,
    /// The transport's framing was refused: more than one trailer frame
    /// on a response body, or another non-DATA frame where at most one
    /// trailer frame is tolerated.
    Framing,
    /// A work limit was hit without any byte of progress: a run of
    /// zero-length chunks, or empty DATA frames, past the allowance a
    /// reader tolerates before refusing the response as unproductive.
    NoProgress,
}

/// The CAS contract granary-store implements.
///
/// Written DESUGARED — `fn … -> impl Future<Output = …> + Send` — for
/// three reasons: bare `async fn` in a public trait trips
/// the warn-by-default `async_fn_in_trait` lint under CI's
/// deny-warnings, the sugared form cannot express `Send` on the
/// returned future, and AFIT needs no proc-macro, so core purity holds.
/// The trait speaks owned bytes and `&str` — no `object_store` type
/// crosses this boundary.
pub trait RootStore: Send + Sync {
    /// Create `root/{volume}/{seq:020}` IF ABSENT.
    ///
    /// # Cancellation safety
    /// NOT cancel-safe, and dropping this future is worse than any error
    /// it can return: the PUT may still land, no error reaches the
    /// caller, and so the ONE-PROBE RULE never runs. Never `select!` on
    /// it, and never wrap it alone in a timeout — see the module docs for
    /// what a timeout around a publish must do instead.
    ///
    /// # Errors
    /// [`RootStoreError::AlreadyExists`] when an object already holds
    /// this seq; [`RootStoreError::Backend`] otherwise. EITHER failure
    /// is ambiguous — resolve with the module-level ONE-PROBE RULE
    ///.
    fn put_root(
        &self,
        volume: &str,
        seq: u64,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<(), RootStoreError>> + Send;

    /// Fetch one numbered root; `Ok(None)` if that seq does not exist
    /// (the cheap 404 a forward probe expects).
    ///
    /// # Cancellation safety
    /// NOT cancel-safe — a dropped future abandons a partially read
    /// response. Nothing is at RISK, though: this is a read, it leaves no
    /// state behind, and re-issuing it is always safe. The one thing a
    /// dropped `get_root` can destroy is a one-probe in progress, which
    /// is the module docs' subject, not this method's.
    ///
    /// # Errors
    /// [`RootStoreError::RefusedResponse`] if the implementation bounds
    /// what it reads and the store's answer exceeded that bound. An
    /// adapter's own read cap here is [`crate::root::ROOT_MAX_BYTES`],
    /// the root format's own reader ceiling — which is what lets the
    /// ONE-PROBE RULE (module docs) read a size-cap refusal here as
    /// "this is not our root" rather than merely "this reader declined a
    /// large answer";
    /// [`RootStoreError::Backend`] on a transport or backend failure.
    fn get_root(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, RootStoreError>> + Send;

    /// Read the advisory CURRENT hint, revalidating `cached` if given.
    ///
    /// A hint body that fails the strict parse yields
    /// [`HintRead::Missing`], never an error: the body is untrusted
    /// input and the advisory contract degrades a bad hint to a list,
    /// never to a wrong answer or a wedged refresh (see
    /// [`parse_hint_body`]).
    ///
    /// **A body of `0` degrades the same way.** It parses, but names a
    /// root that cannot exist — see the module docs.
    ///
    /// # Cancellation safety
    /// NOT cancel-safe — a dropped future abandons a partially read
    /// response. Nothing is at risk: the hint is ADVISORY, this is a
    /// read, and re-issuing it is always safe.
    ///
    /// # Errors
    /// [`RootStoreError::RefusedResponse`] if the implementation bounds
    /// what it reads and the store's answer exceeded that bound — note
    /// an implementation MAY instead degrade an over-long body to
    /// `Missing`, which the advisory contract above permits and the
    /// granary-store adapter does;
    /// [`RootStoreError::Backend`] on a transport or backend failure.
    fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> impl Future<Output = Result<HintRead, RootStoreError>> + Send;

    /// Point the hint at `seq` after a successful publish. Losing this
    /// write is survivable BY DESIGN (readers forward-probe; the next
    /// publish repairs it) — never gate a publish's success on it.
    ///
    /// # Cancellation safety
    /// NOT cancel-safe: a dropped write may still land. That is
    /// survivable here and only here — the hint is advisory, the write is
    /// an unconditional last-writer-wins overwrite of a value the next
    /// publish repairs, so both "it landed" and "it did not" are states
    /// the design already tolerates. This is the ONLY mutating method on
    /// this trait whose cancellation is harmless.
    ///
    /// # Errors
    /// [`RootStoreError::Precondition`] if the implementation used a
    /// conditional update and lost; [`RootStoreError::Backend`]
    /// otherwise.
    fn write_hint(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl Future<Output = Result<(), RootStoreError>> + Send;

    /// The highest existing seq for `volume`, or `None` for a volume
    /// with no roots. Implementations parse seqs and take the numeric
    /// maximum CLIENT-SIDE: list order is NOT a contract — S3/`MinIO`
    /// happen to sort, `InMemory`/`LocalFileSystem` promise nothing.
    ///
    /// **NEVER returns `Some(0)`, and NEVER returns `Some(u64::MAX)`** —
    /// see the module docs. Both values parse, and both can be planted
    /// as keys; neither may become the head. Seq 0 can hold no root at
    /// all, and `u64::MAX` would leave no higher seq for the next
    /// publish, so an object at either key is SKIPPED and the maximum
    /// falls back to the next real seq. `Some(u64::MAX - 1)` is an
    /// ordinary answer: the reserved value is exactly one value wide.
    ///
    /// # Cancellation safety
    /// NOT cancel-safe — a dropped future abandons a listing walk
    /// partway, and a partial walk has NO partial answer: the maximum is
    /// only correct once every key has been seen. Nothing is at risk (it
    /// is a read) but nothing is salvageable either, so a cancelled
    /// `max_seq` must be re-run from the start, never resumed.
    ///
    /// # Errors
    /// [`RootStoreError::RefusedResponse`] if the implementation bounds
    /// what it reads and the store's answer exceeded that bound;
    /// [`RootStoreError::Backend`] on a transport or backend failure.
    fn max_seq(
        &self,
        volume: &str,
    ) -> impl Future<Output = Result<Option<u64>, RootStoreError>> + Send;

    /// The highest existing seq for `volume` strictly above `floor`, or
    /// `None` if there is none. Uses the same key and sequence exclusions
    /// as [`Self::max_seq`], including seq 0 and `u64::MAX`.
    ///
    /// An implementation MAY leave unreported a listing failure caused
    /// only by a key that sorts at or below the canonical root key for
    /// `floor`.
    ///
    /// A wrapper that forwards [`Self::max_seq`] must also forward
    /// `max_seq_above` to preserve the inner store's bounded listing.
    /// An implementation without a bounded listing calls [`Self::max_seq`]
    /// and applies [`filter_above`] to its result.
    ///
    /// # Cancellation safety
    /// Like [`Self::max_seq`], a dropped listing has no partial answer.
    /// Restart the operation to obtain a result.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::max_seq`], subject to the
    /// listing-failure exception above.
    fn max_seq_above(
        &self,
        volume: &str,
        floor: u64,
    ) -> impl Future<Output = Result<Option<u64>, RootStoreError>> + Send;
}

/// Keep a maximum sequence number only if it is strictly above `floor`.
#[must_use]
pub fn filter_above(max: Option<u64>, floor: u64) -> Option<u64> {
    max.filter(|seq| *seq > floor)
}

/// Render the CURRENT hint body: exactly [`SEQ_KEY_DIGITS`]
/// zero-padded decimal digits, no newline, no prefix. The same
/// rendering forms the seq component of a root key.
#[must_use]
pub fn format_hint_body(seq: u64) -> String {
    format!("{seq:0SEQ_KEY_DIGITS$}")
}

/// Whether `seq` is one of the two values that can never be a real
/// head — seq `0`, which cannot hold a valid root, or the
/// reserved `u64::MAX` — the absent-class predicate re-derived at three
/// separate sites in `granary-client`'s anchor-file grammar (now
/// `cache/anchor.rs`) before this hoist. A pure `const fn`: no I/O, callable from
/// anywhere in the workspace that already depends on this crate.
#[must_use]
pub const fn is_reserved_seq(seq: u64) -> bool {
    seq == 0 || seq == u64::MAX
}

/// Why a CURRENT hint body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintBodyError {
    BadLength {
        len: usize,
    },
    NonDigit {
        byte: u8,
    },
    /// 20 digits that do not fit a `u64`.
    Overflow,
}

impl std::fmt::Display for HintBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLength { len } => {
                write!(
                    f,
                    "hint body is {len} bytes (want exactly {SEQ_KEY_DIGITS})"
                )
            }
            Self::NonDigit { byte } => write!(f, "hint body byte 0x{byte:02x} is not a digit"),
            Self::Overflow => write!(f, "hint body exceeds u64"),
        }
    }
}

impl std::error::Error for HintBodyError {}

/// Strict-parse a CURRENT hint body. UNTRUSTED INPUT: anyone who can
/// write the bucket can write this object, and the fixed-width form is
/// what keeps the parse total — exactly 20 ASCII digits, nothing else.
/// No trimming, no sign, no leading `+`, no trailing newline. A hint
/// that fails to parse is treated as [`HintRead::Missing`] by a
/// reader — the advisory contract means a bad hint degrades to a list,
/// never to a wrong answer.
///
/// # Errors
/// The [`HintBodyError`] naming the violated rule.
pub fn parse_hint_body(body: &str) -> Result<u64, HintBodyError> {
    let raw = body.as_bytes();
    if raw.len() != SEQ_KEY_DIGITS {
        return Err(HintBodyError::BadLength { len: raw.len() });
    }
    let mut seq: u64 = 0;
    for &b in raw {
        if !b.is_ascii_digit() {
            return Err(HintBodyError::NonDigit { byte: b });
        }
        seq = seq
            .checked_mul(10)
            .and_then(|s| s.checked_add(u64::from(b - b'0')))
            .ok_or(HintBodyError::Overflow)?;
    }
    Ok(seq)
}

#[cfg(test)]
mod tests;
