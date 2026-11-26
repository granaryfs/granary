// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The windowed, budgeted, deduplicating grain fetcher: admission bounded
//! by count and bytes, with AIMD backpressure on `Unavailable`.
//!
//! One [`Fetcher`] drives a bounded, hand-rolled multiplexer over
//! `R: BinStore` — no `tokio::spawn`, no `select!` (both clippy-banned
//! in this crate), and no `futures-util`
//! (`FuturesUnordered` is not a dependency here). The blessed shape
//! instead is a single `std::future::poll_fn`
//! holding every in-flight seam call as a
//! `Pin<Box<dyn Future<…> + Send>>`: admit while a slot and enough
//! budget remain, poll everything once, repeat until the queue and the
//! in-flight set are both empty. Nothing here is spawned, so the whole
//! run is sim-sequenceable the moment a sim drives this crate.
//!
//! **Admission is TWO independent gates, always both**:
//! `in_flight < the CURRENT window` (at rest
//! [`FETCH_WINDOW`]; halved under shed, never below [`WINDOW_FLOOR`])
//! and `in_flight_bytes + charge <= FETCH_INFLIGHT_BYTES`. Admission is
//! FIFO: a front want that does not fit the remaining budget waits
//! rather than being bypassed by a smaller want behind it — a
//! deliberate throughput trade for an ordering no test has to reason
//! about. At this profile the byte gate binds first
//! — `FETCH_INFLIGHT_BYTES / MAX_GRAIN` is 32, exactly `FETCH_WINDOW`
//! (see `http_store.rs`'s `H2_STREAM_WINDOW` / `H2_CONN_WINDOW`
//! witnesses) — so the stream count never ends up being the reason a
//! want waits at this profile; it stays a second, independent bound
//! rather than a redundant one, because a future profile could size
//! grains smaller and let it bind instead.
//!
//! **Single-flight is scoped to ONE `fetch`/`fetch_streaming` CALL, never
//! to the process, and never to a `Fetcher`'s or a `FetchState`'s
//! lifetime either — true even of the daemon's own long-lived state.**
//! Two [`Want`]s naming the same [`GrainId`] cost exactly one wire call;
//! every other requester reads the same map entry the completed call
//! filled. Duplicates are assumed IDENTICAL — the id is the content
//! address, and a binmap yields one entry per grain — so the first
//! occurrence's parameters are the ones used and later occurrences are
//! never re-examined. The one thing that is NOT content-addressed is
//! absence: a `NotFound` is scoped to the volume that was actually asked,
//! so a batch naming one id under two volumes inherits whichever answer
//! the first occurrence got. `gran`'s one-shot CLI builds one [`Fetcher`]
//! per invocation and resolves one volume with it, so that scope IS the
//! process there. **The daemon holds a long-lived [`FetchState`] across
//! FUSE callbacks, but that does NOT widen single-flight beyond one
//! call**: `admit_or_refuse`'s `seen` set and [`Slot`]'s `in_flight`
//! vector are both built fresh, local to each `fetch_streaming`
//! invocation — `FetchState` carries forward only the AIMD window and the
//! codec, nothing that tracks which ids are in flight or already
//! answered. Two callbacks racing on the same `GrainId`, even under one
//! shared `FetchState`, still cost two wire calls.
//!
//! **The 503 response handling, AIMD, stated once here rather than at every
//! call site.** [`granary_core::rootstore::RootStoreError::Unavailable`]
//! is a READ RESPONSE, not a transport failure — the transport retry never
//! sees it (that machinery is scoped to `REFUSED_STREAM` and the closed
//! CLASS B transport-failure list). On the FIRST `Unavailable` a want's
//! seam call returns, the window HALVES (floor [`WINDOW_FLOOR`]) and
//! that one want alone is re-polled ONCE, after
//! [`UNAVAILABLE_RETRY_DELAY`]; a SECOND `Unavailable` surfaces to the
//! caller rather than retrying again. Every completed fetch grows the
//! window by one slot, back up to [`FETCH_WINDOW`] (additive increase,
//! multiplicative decrease) — EXCEPT a completion that IS the
//! congestion signal: a want surfacing its second `Unavailable` frees
//! its slot and bytes but earns no growth. Each want's FIRST shed
//! halves the window independently, so a batch shed in its entirety
//! compounds down to the floor, not to one halving — and without the
//! growth exception its own surfacing completions would quietly climb
//! it back toward full, erasing the caution the persisted window
//! exists to carry. Other terminal failures (a `NotFound`, a failed
//! verification) do grow it: the server answered authoritatively, and
//! an answer is not congestion. **The bound this leaves on one want's
//! total wire attempts is FOUR**: this layer polls the seam at most
//! twice per want (the original attempt plus the one re-poll), and
//! `HttpStore::send` retries at most once more underneath each of
//! those two, for the separate transport-failure classes handled by `HttpStore::send` — 2 ×
//! 2. Four bounded attempts costs one operator-visible failure on a
//! genuinely persistent outage, which is the point of a BOUNDED retry:
//! an unbounded one would hide that outage as latency instead of
//! reporting it.
//!
//! **Why `tokio::time::timeout(delay, pending())` and not a sleep.**
//! `tokio::time::sleep`/`sleep_until` are clippy-banned in this crate
//! (use the `Clock` seam); `timeout` is the one deliberately unbanned
//! clock (a bound on how long an await may take reads no
//! clock the caller can observe). Racing `pending::<()>()` against it
//! turns that bound into a plain delay: `pending()` never completes on
//! its own, so the ONLY way the pair resolves is the timer firing, and
//! the `Elapsed` handed back is discarded — there is nothing else it
//! could mean. The idiom needs a tokio TIMER DRIVER on the running
//! runtime (`gran`'s runtime enables everything); a runtime built
//! without one panics inside tokio the first time a shed
//! engages the delay. The sim does not drive this path today —
//! it ships no simulated 503 — so a sim-replayable timer seam
//! here is deliberately not opened; if the sim ever exercises
//! this code, that question reopens THERE, not here.
//!
//! **Cache writes happen INLINE on the completion path** — a verified
//! object is written (and fsynced) by the same thread that polls the
//! multiplexer, stalling admission for the write's duration. That is a
//! deliberate cost: every sanctioned way to move the write off-thread
//! is clippy-banned in this crate (the sim must be
//! able to sequence everything), and a one-shot CLI tolerates
//! millisecond-scale stalls between fetches. A long-lived
//! daemon may not; that is its own question, not this module's.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use granary_core::binfmt::FRAME_COMP_MAX;
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::manifest::GRAIN_UNPACKED_MAX;
use granary_core::rootstore::RootStoreError;
use granary_store::bounds::META_MAX_BYTES;
use granary_store::codec::{CodecError, GrainCodec};

use crate::cache::Cache;

/// The most seam calls that may be in flight at once (measured on one
/// connection: 253 requests at 100 ms RTT took 0.84 s at this value and
/// 26.4 s serial — near-ideal `N·RTT/W`, zero shed). Behavioural — the
/// number is measured, not derived; this module's own tests pin the literal value.
pub(crate) const FETCH_WINDOW: usize = 32;

/// The most bytes that may be reserved across every in-flight want at
/// once, charged at each want's DECLARED UNPACKED size (never the
/// compressed figure on the wire — a want's charge is what will be
/// resident once it completes). At
/// [`FETCH_WINDOW`] wants of [`granary_core::thresh::MAX_GRAIN`] apiece
/// this is the tighter bound, which is why admission checks both gates
/// rather than either one alone.
pub(crate) const FETCH_INFLIGHT_BYTES: u64 = 64 * 1024 * 1024;

/// How long a want that was shed with `Unavailable` waits before its one
/// bounded re-poll.
pub(crate) const UNAVAILABLE_RETRY_DELAY: Duration = Duration::from_millis(500);

/// The floor the window's multiplicative decrease may never cross.
///
/// **MUST be `>= 1`, and that is a construction obligation, not merely
/// the chosen value.** Recovery is driven entirely by completions (+1
/// per completed fetch); a floor of `0` admits a state with nothing in
/// flight and therefore nothing that can ever complete, wedging the
/// window at `0` forever — a self-inflicted deadlock the AIMD shape
/// cannot escape from on its own.
pub(crate) const WINDOW_FLOOR: usize = 4;

const _: () = assert!(
    WINDOW_FLOOR >= 1,
    "a floor of 0 admits a state with nothing in flight and therefore \
     nothing that can ever complete, wedging the window at 0 forever — a \
     self-inflicted deadlock the AIMD shape cannot escape on its own"
);
const _: () = assert!(
    WINDOW_FLOOR <= FETCH_WINDOW,
    "the floor cannot sit above the ceiling it is a floor under"
);
const _: () = assert!(
    META_MAX_BYTES <= FETCH_INFLIGHT_BYTES,
    "a lone meta want must always admit on its own — charging more than \
     the whole budget for one want would deadlock it outright"
);
const _: () = assert!(
    GRAIN_UNPACKED_MAX as u64 <= FETCH_INFLIGHT_BYTES,
    "a lone BinRange want's admission charge — its declared unpacked_len \
     — must never alone exceed the whole budget: charging more than the \
     budget for one want refuses it outright (FetchError::OverBudget) \
     before it can ever reach the wire, rather than ever admitting it. \
     The same figure also bounds the liveness hatch's own overshoot: \
     FIFO admission means the earliest unemitted want is always at the \
     front of the queue, so it is already admitted before any later want \
     competes for the room it needs — a lone figure above the budget \
     would deadlock exactly the want the caller is blocked on"
);

/// One object the fetcher was asked to retrieve.
///
/// Both variants are content-addressed by `id`, which is what makes
/// them share one cache, one single-flight map and one admission
/// window: the objects/ CAS mixes bins and meta objects by design,
/// and this type is the fetcher's own reflection of that.
#[derive(Debug, Clone)]
pub(crate) enum Want {
    /// A grain's compressed frame, at a known offset and length inside
    /// a bin. The binmap entry's own fields, plus the grain id the
    /// entry names and the bin digest its `bin_ordinal` already
    /// resolved to — resolving `bin_ordinal` itself, and refusing a bad
    /// one, stays the caller's job.
    BinRange {
        /// The id the decompressed, verified bytes must hash to.
        id: GrainId,
        /// The bin holding the frame.
        digest: [u8; DIGEST_LEN],
        /// Where the frame starts inside the bin.
        offset: u64,
        /// The frame's compressed length, ON THE WIRE — never the
        /// decompressed grain size. Bounds the READ EXTENT and the
        /// frame-bound refusal gate; not what this want is CHARGED at
        /// (see [`Want::admission_bytes`]) — compressed wire bytes are
        /// the H2 connection window's own, separate pool,
        /// not this budget's.
        comp_len: u32,
        /// The caller's own declared decompressed size — for a
        /// duplicate reference, the LARGEST declaration across every
        /// position naming this id, so a single admission charge can
        /// never be smaller than what any one of its positions will
        /// turn out to need. What this want is CHARGED at.
        unpacked_len: u32,
    },
    /// A whole meta object (a binmap shard, a manifest node, a sheaf —
    /// anything content-addressed by [`GrainId`] and read whole).
    Meta {
        /// The volume it is filed under.
        volume: String,
        /// The id it is addressed and verified by.
        id: GrainId,
    },
}

impl Want {
    /// The cache/single-flight/results key — the SAME address for both
    /// variants, by contract (the module doc's mixed-CAS statement).
    fn id(&self) -> GrainId {
        match self {
            Self::BinRange { id, .. } | Self::Meta { id, .. } => *id,
        }
    }

    /// What this want charges against [`FETCH_INFLIGHT_BYTES`] at
    /// admission — the RESIDENT size, in both cases, never the
    /// transport-side figure.
    ///
    /// A `BinRange` charges its caller-declared `unpacked_len` — what it
    /// will actually occupy once decompressed and held, not `comp_len`
    /// (the wire-side figure, which for a highly-compressible grain can
    /// be orders of magnitude smaller and would let a whole window's
    /// worth admit on a charge that has nothing to do with what ends up
    /// resident). "Will actually occupy" is ENFORCED, not merely
    /// declared: a completion whose actual length exceeds this
    /// figure is refused before it can ever be held — by `finish()`
    /// on the wire path and by `deliver_cache_hit` on a cache hit —
    /// so a manifest cannot buy cheap admission by declaring a grain
    /// smaller than its bin's own content decompresses to. A meta
    /// want has no declared size to charge at all, so
    /// it charges [`META_MAX_BYTES`] — the bound `HttpStore::get_meta`'s
    /// own bounded read already enforces, and the only a-priori figure
    /// the client holds for an object it has not read yet. Charging
    /// zero would admit `FETCH_WINDOW` concurrent metas at up to
    /// `META_MAX_BYTES` apiece, exceeding `FETCH_INFLIGHT_BYTES`; the
    /// `const _` above proves a LONE meta want can never be charged more
    /// than the whole budget, so this charge alone cannot deadlock one —
    /// the same argument the `GRAIN_UNPACKED_MAX <= FETCH_INFLIGHT_BYTES`
    /// witness makes for a lone `BinRange` want's own declared size.
    fn admission_bytes(&self) -> u64 {
        match self {
            Self::BinRange { unpacked_len, .. } => u64::from(*unpacked_len),
            Self::Meta { .. } => META_MAX_BYTES,
        }
    }
}

/// Why one [`Want`] failed. Never a batch-wide failure — see
/// [`Fetcher::fetch`]'s own return type.
#[derive(Debug)]
pub(crate) enum FetchError {
    /// The want's own charge exceeds the WHOLE in-flight budget — it
    /// could never admit even into an empty window. Refused before any
    /// wire call, never a deadlock.
    OverBudget {
        /// The want that was refused.
        id: GrainId,
        /// What it would have charged.
        bytes: u64,
    },
    /// A `BinRange` want's `comp_len` exceeds the largest legal
    /// compressed frame ([`FRAME_COMP_MAX`]). Refused before any wire
    /// call, for the same reason a frame this large could never have
    /// been produced by the encoder.
    OverFrameBound {
        /// The want that was refused.
        id: GrainId,
        /// The frame length it claimed.
        comp_len: u32,
    },
    /// A ranged read returned fewer bytes than the extent claims — the
    /// bin is shorter than the binmap says (`get_bin_range` SHORT-READS
    /// by contract; this is the check that catches it, run BEFORE
    /// decompression is ever attempted). A seam that answered MORE than
    /// asked — a contract violation, not a short read — lands here too:
    /// `got` carries the true count either way.
    ShortExtent {
        /// The want whose extent came back short.
        id: GrainId,
        /// Bytes the extent claimed.
        want: u32,
        /// Bytes the store produced.
        got: usize,
    },
    /// A `BinRange` want's frame did not decompress.
    Codec(CodecError),
    /// The bytes came back and decoded (or, for `Meta`, arrived) but do
    /// not hash to the id that named them.
    Corrupt {
        /// The want whose bytes failed verification.
        id: GrainId,
    },
    /// A `BinRange` want's frame decompressed to MORE bytes than its own
    /// `unpacked_len` — the figure admission already charged it at
    /// (`Want::admission_bytes`). The id still hashes correctly (this is
    /// never [`Self::Corrupt`]): content addressing fixes what the
    /// bytes ARE, never what the caller CLAIMED about their length
    /// ahead of fetching them, and `unpacked_len` is that separate,
    /// untrusted claim. Refusing before the bytes are handed to the
    /// caller is what keeps a lying declaration from ever entering
    /// residency uncharged for its true size — see
    /// [`Fetcher::fetch_streaming`]'s own doc for the bound this closes.
    ///
    /// Raised on BOTH delivery paths, and they differ in what is
    /// already on disk: on the wire path `finish()` refuses
    /// before the object is cached, so it never is; on the CACHE
    /// path, the object is already cached and STAYS cached — the
    /// id is honest, the bytes hash to it, and only this want's
    /// declaration is a lie. Nothing is evicted on a refusal.
    OverDeclared {
        /// The want whose frame over-decompressed.
        id: GrainId,
        /// The declared length admission charged it at.
        declared: u32,
        /// The actual decompressed length.
        got: usize,
    },
    /// The seam call itself failed — including a SECOND consecutive
    /// `Unavailable`, which this layer's bounded re-poll does not retry
    /// a third time (the module doc's four-attempt bound).
    Remote(RootStoreError),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverBudget { id, bytes } => {
                write!(
                    f,
                    "{id} needs {bytes} bytes, over the whole in-flight budget"
                )
            }
            Self::OverFrameBound { id, comp_len } => write!(
                f,
                "{id}'s frame claims {comp_len} bytes, over the largest legal compressed frame"
            ),
            Self::ShortExtent { id, want, got } => write!(
                f,
                "extent for {id} claims {want} bytes and the bin produced {got}"
            ),
            Self::Codec(e) => write!(f, "codec: {e}"),
            Self::Corrupt { id } => write!(f, "{id} does not hash to the id that named it"),
            Self::OverDeclared { id, declared, got } => write!(
                f,
                "{id} declared {declared} bytes and decompressed to {got}"
            ),
            Self::Remote(e) => write!(f, "remote: {e}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// The outcome of one polled step: either the wire call answered, or a
/// backpressure delay elapsed. ONE output type so every in-flight
/// future — wire call or delay alike — can share the same boxed-future
/// slot (the module doc's multiplexer shape).
enum Step {
    /// A seam call answered.
    Wire(Result<Vec<u8>, RootStoreError>),
    /// [`UNAVAILABLE_RETRY_DELAY`] elapsed; re-issue the wire call.
    DelayElapsed,
}

/// One admitted want, tracked OUTSIDE its boxed future so the
/// multiplexer can inspect and re-admit it without reaching inside a
/// type-erased `Future`.
struct Slot<'r> {
    /// Bytes reserved against [`FETCH_INFLIGHT_BYTES`], released on
    /// completion.
    charge: u64,
    /// Kept to reissue the wire call on the one bounded re-poll.
    want: Want,
    /// Whether this want has already been re-polled once — the retry
    /// bound: a second `Unavailable` surfaces rather than retrying.
    retried: bool,
    step: Pin<Box<dyn Future<Output = Step> + Send + 'r>>,
}

/// Is this wire answer an `Unavailable` congestion signal? ONE definition,
/// consulted by both the halve arm and the growth suppression below, so
/// the two sides of the AIMD rule can never drift apart on what counts
/// as a shed.
fn sheds(result: &Result<Vec<u8>, RootStoreError>) -> bool {
    matches!(result, Err(RootStoreError::Unavailable { .. }))
}

/// Build the wire-call future for `want`. `Send + 'r` because it
/// borrows `remote` for exactly as long as [`Fetcher::fetch`] runs.
fn wire_step<'r, R: BinStore>(
    remote: &'r R,
    want: &Want,
) -> Pin<Box<dyn Future<Output = Step> + Send + 'r>> {
    match want.clone() {
        Want::BinRange {
            digest,
            offset,
            comp_len,
            ..
        } => Box::pin(
            async move { Step::Wire(remote.get_bin_range(&digest, offset, comp_len).await) },
        ),
        Want::Meta { volume, id } => {
            Box::pin(async move { Step::Wire(remote.get_meta(&volume, &id).await) })
        }
    }
}

/// The bounded re-poll's wait — see the module doc's timeout-idiom
/// paragraph for why this is `timeout(delay, pending())` and not a
/// sleep.
fn delay_step() -> Pin<Box<dyn Future<Output = Step> + Send>> {
    Box::pin(async {
        drop(tokio::time::timeout(UNAVAILABLE_RETRY_DELAY, std::future::pending::<()>()).await);
        Step::DelayElapsed
    })
}

/// Verify the compressed extent length, decompress and hash-authenticate one
/// bin frame, and refuse decoded bytes wider than the supplied residency bound.
pub(crate) fn verify_bin_range_frame(
    id: GrainId,
    comp_len: u32,
    unpacked_len: u32,
    bytes: &[u8],
    codec: &mut GrainCodec,
) -> Result<Vec<u8>, FetchError> {
    if bytes.len() != comp_len as usize {
        return Err(FetchError::ShortExtent {
            id,
            want: comp_len,
            got: bytes.len(),
        });
    }
    let decoded = codec.decompress_frame(bytes).map_err(FetchError::Codec)?;
    if GrainId::of(&decoded) != id {
        return Err(FetchError::Corrupt { id });
    }
    // The residency guard: `unpacked_len` is what admission
    // already charged this want at (the MAX across a
    // duplicate's positions, `resolve.rs`'s own
    // `grain_span_facts`) — `>`, not `!=`, since a grain whose
    // actual size is anywhere AT OR UNDER that charge is within
    // what was reserved for it and belongs in `held`; the exact
    // per-position `!=` a conflicting declaration deserves stays
    // at drain (`ResolveError::GrainLenMismatch`), over the
    // declaration each position actually made, not the charge's
    // own max. Only `actual > charge` breaches what was
    // reserved, and it can only mean the declaration this want
    // was charged at understated the bin's own content — never
    // a legitimate shape, since the id already proves the
    // content (and therefore its true size) is fixed. Checked
    // BEFORE caching or returning: a caller must never be able
    // to observe, hold, or persist bytes wider than what was
    // charged for them.
    if decoded.len() > unpacked_len as usize {
        return Err(FetchError::OverDeclared {
            id,
            declared: unpacked_len,
            got: decoded.len(),
        });
    }
    Ok(decoded)
}

/// Finish one completed want: verify, cache, and hand back the bytes the
/// caller asked for (or the error that refused them).
///
/// The order of checks: a `BinRange`
/// checks the extent length BEFORE decompressing (a short read must not
/// reach the codec mislabelled as corruption) and decompresses before
/// the hash check; a `Meta` object is never decompressed at all — only
/// hash-checked. **A `BinRange` also
/// checks its decompressed length against its own `unpacked_len` —
/// admission's own charge — before this function ever returns `Ok`**
/// ([`FetchError::OverDeclared`]'s own doc has the full argument); this
/// is what makes that charge a TRUE bound on what a caller can ever
/// hold, not merely what a manifest claims. `cache.insert` skipping
/// a full or degraded cache is the cache's own business, not this
/// function's; a cache HIT never reaches here at all — it is served,
/// and checked against its declaration, by `deliver_cache_hit`
/// inside [`Fetcher::fetch_streaming`]'s admission loop.
fn finish(
    want: &Want,
    result: Result<Vec<u8>, RootStoreError>,
    codec: &mut GrainCodec,
    cache: Option<&mut Cache>,
) -> Result<Vec<u8>, FetchError> {
    let bytes = result.map_err(FetchError::Remote)?;
    match want {
        Want::BinRange {
            id,
            comp_len,
            unpacked_len,
            ..
        } => {
            let (id, comp_len, unpacked_len) = (*id, *comp_len, *unpacked_len);
            let decoded = verify_bin_range_frame(id, comp_len, unpacked_len, &bytes, codec)?;
            if let Some(cache) = cache {
                cache.insert(&id, &decoded);
            }
            Ok(decoded)
        }
        Want::Meta { id, .. } => {
            let id = *id;
            if GrainId::of(&bytes) != id {
                return Err(FetchError::Corrupt { id });
            }
            if let Some(cache) = cache {
                cache.insert(&id, &bytes);
            }
            Ok(bytes)
        }
    }
}

/// Dedup and the two before-the-wire refusal gates for one batch —
/// none of it touches the seam OR the cache. A want that clears both
/// gates is queued for windowed admission, where a cache hit is
/// checked and delivered under the SAME budget the wire path uses
/// (see [`Fetcher::fetch_streaming`]'s own admission loop) — that is
/// not this function's business, since a cache hit's bytes sit
/// in the caller's holdback exactly like a wire completion's do, and
/// need the same byte gate to bound them. Everything refused HERE is
/// reported through `on_complete` immediately, UNCHARGED
/// (`charged = false`): a pre-admission refusal was never counted
/// against [`FETCH_INFLIGHT_BYTES`] in the first place, so there is
/// nothing for a caller to release for one. A duplicate is never
/// reported at all — only the first occurrence is queued, and every
/// later one reads the same completion once the batch returns.
/// Consequently the returned queue owns one `Want` per distinct id,
/// not per input position. It must remain owned across polls while the
/// window advances; its bound is O(unique ids), the same per-unique
/// class as the caller's span facts.
fn admit_or_refuse<E>(
    wants: impl IntoIterator<Item = Result<Want, E>>,
    mut on_complete: impl FnMut(GrainId, Result<Vec<u8>, FetchError>, bool) -> u64,
    counters: &mut ReadPathCounters,
) -> Result<VecDeque<Want>, E> {
    let mut queue = VecDeque::new();
    let mut seen: BTreeSet<GrainId> = BTreeSet::new();
    // TALLIED LOCALLY AND APPLIED ONLY ON SUCCESS. The `?` below returns
    // the caller's error mid-iterator, and `fetch_streaming` then drops
    // the queue without a single callback, seam call or cache lookup —
    // so a want counted straight into the session's counters would
    // report work the fetch never did. The row
    // `a_fallible_want_stream_errors_before_cache_or_wire_admission`
    // holds this line; it read 1 before the tally was made local.
    let mut tally = ReadPathCounters::default();
    for want in wants {
        let want = want?;
        let id = want.id();
        if !seen.insert(id) {
            // Single-flighted: only the FIRST occurrence is ever queued.
            // Every later one reads the same completion once the batch
            // returns.
            continue;
        }
        let charge = want.admission_bytes();
        if charge > FETCH_INFLIGHT_BYTES {
            let _ = on_complete(id, Err(FetchError::OverBudget { id, bytes: charge }), false);
            continue;
        }
        if let Want::BinRange { comp_len, .. } = &want
            && *comp_len > FRAME_COMP_MAX
        {
            let _ = on_complete(
                id,
                Err(FetchError::OverFrameBound {
                    id,
                    comp_len: *comp_len,
                }),
                false,
            );
            continue;
        }
        // COUNTED HERE, at the queue: past single-flight dedup and past
        // both refusal gates above. A duplicate reference never becomes a
        // second want, and a refused one never becomes a want at all, so
        // what this counts is what the fetch went on to do work for.
        tally.want(&want);
        queue.push_back(want);
    }
    // Past every `?`: the batch is whole, so the tally is real.
    counters.wants_bin += tally.wants_bin;
    counters.wants_meta += tally.wants_meta;
    Ok(queue)
}

/// A `BinRange` cache hit WIDER than the extent its want declared: the
/// `(declared, got)` pair `finish()` refuses on the wire path. `None`
/// for a hit at or under its declaration, and for [`Want::Meta`], which
/// declares no extent to violate.
///
/// Hoisted out of [`Fetcher::fetch_streaming`]'s
/// cache-hit branch rather than written inline: inline,
/// that function crosses `clippy::too_many_lines`
/// (110/100), and an `#[expect]` on a security-surface
/// function is a worse trade than a named predicate.
fn over_declared(want: &Want, got: usize) -> Option<(u32, usize)> {
    match want {
        Want::BinRange { unpacked_len, .. } if got > *unpacked_len as usize => {
            Some((*unpacked_len, got))
        }
        Want::BinRange { .. } | Want::Meta { .. } => None,
    }
}

/// What [`Fetcher::fetch_streaming`]'s cache-hit branch decided.
enum CacheHit {
    /// Nothing cached under this id — the want goes to the wire.
    Miss,
    /// The want is finished: delivered `Ok`, or refused `OverDeclared`.
    Done,
    /// The byte gate is full and something is in flight — put the want
    /// back at the front of the queue and stop admitting this pass.
    Defer,
}

/// Serve one want from the cache, if it is there: enforce the
/// declaration, ride the byte gate, deliver. Split out of
/// [`Fetcher::fetch_streaming`] because the declaration check
/// pushes that function past `clippy::too_many_lines` (106/100
/// with only `over_declared` hoisted, 110/100 with the check
/// written inline) — and an `#[expect]` on a security-surface
/// function is a worse trade than two named pieces.
#[derive(Clone, Copy)]
struct CacheObservation<'a> {
    metrics: Option<&'a crate::ClientMetrics>,
    phase: crate::CachePhase,
}
impl<'a> CacheObservation<'a> {
    const fn new(metrics: Option<&'a crate::ClientMetrics>, phase: crate::CachePhase) -> Self {
        Self { metrics, phase }
    }
    fn record(self, result: crate::CacheResult) {
        if let Some(metrics) = self.metrics {
            metrics.record_cache(self.phase, result);
        }
    }
}

fn deliver_cache_hit<F>(
    cache: Option<&mut Cache>,
    want: &Want,
    in_flight_bytes: &mut u64,
    in_flight_empty: bool,
    on_complete: &mut F,
    counters: &mut ReadPathCounters,
    observation: CacheObservation<'_>,
) -> CacheHit
where
    F: FnMut(GrainId, Result<Vec<u8>, FetchError>, bool) -> u64,
{
    let id = want.id();
    let Some(bytes) = cache.and_then(|c| c.get(&id)) else {
        // NOT COUNTED HERE. A miss whose want the admission byte gate then
        // defers comes back through this function on the next pass and
        // misses again — `Cache::get` is a non-consuming read, so the
        // second look is a second miss. The count lives in
        // `ReadPathCounters::admit`, at the point the want is SEATED,
        // which happens exactly once per want.
        return CacheHit::Miss;
    };
    // COUNTED ON THE `Done` ARMS ONLY, further down — not here. Between
    // this point and them sits the byte gate, which returns `Defer` and
    // has the caller push the want back onto the queue; a hit counted
    // before that gate is counted again on every later pass. Measured:
    // six wants against a 64 MiB budget reported EIGHT. Both `Done` arms
    // do count a hit — neither touched the wire, which is the question
    // the cold-read decomposition asks — and both are final for the want.
    // Already hash-verified by the cache's own read path
    // — never re-verified here. But the DECLARATION is enforced
    // here, on the cache-hit path, exactly as `finish()` enforces it
    // on the wire path: a caller must never observe, hold or pool
    // bytes wider than what its want was charged at, and the cache
    // holds objects up to `META_MAX_BYTES` under ids a manifest may
    // declare far narrower (the speculative pool's cap depends on
    // this holding on BOTH delivery paths). Nothing of this want's
    // own was charged, so nothing of its own is released — but the
    // callback's return value IS applied, exactly as a failed wire
    // completion's is: a caller holding OTHER charged completions
    // back (`emit_file`'s error mode) reports the flush it performs
    // on learning of the error, and those bytes were charged.
    if let Some((declared, got)) = over_declared(want, bytes.len()) {
        // Dropped BEFORE the callback, so the two refusal paths have the
        // same shape: `finish()` drops its decoded buffer before its
        // caller's `on_complete` runs, and these bytes were never
        // charged at all, so holding up to `META_MAX_BYTES` of them
        // across a caller's error handling would be the one place an
        // uncharged object outlives the decision to refuse it.
        drop(bytes);
        counters.cache_hits += 1;
        observation.record(crate::CacheResult::Hit);
        let released = on_complete(
            id,
            Err(FetchError::OverDeclared { id, declared, got }),
            false,
        );
        *in_flight_bytes = in_flight_bytes.saturating_sub(released);
        return CacheHit::Done;
    }
    let charge = bytes.len() as u64;
    if in_flight_bytes.saturating_add(charge) > FETCH_INFLIGHT_BYTES && !in_flight_empty {
        return CacheHit::Defer;
    }
    *in_flight_bytes += charge;
    counters.cache_hits += 1;
    observation.record(crate::CacheResult::Hit);
    let released = on_complete(id, Ok(bytes), true);
    *in_flight_bytes = in_flight_bytes.saturating_sub(released);
    CacheHit::Done
}

/// The read-path counter set — Tier 1 of the K3 follow-up.
///
/// **Every field is a count, never a duration.** Timing the read path needs
/// a monotonic seam this workspace deliberately does not have
/// (`Instant::now` has zero call sites and clippy bans it outside the
/// `Clock` seam), so duration instrumentation requires an explicit seam.
/// Counts need none of it, and they are what decomposes the cold-read gap: the
/// cold whole-tree read measured 3.54x slower than CernVM-FS
/// while moving 0.09% different bytes, so the question is not how many
/// bytes moved but how many round trips they took and how many ran at once.
///
/// **Comparability is the design constraint.** CernVM-FS does not split
/// metadata from content in its own accounting — `cvmfs/fetch.cc`
/// describes both fetch counters as "(incl. catalogs, chunks)" — so the
/// only quantity comparable across the two systems is a TOTAL spanning
/// both classes. These are those totals; the per-resource split is
/// granary's own attribution surface and has no counterpart to be
/// compared against.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadPathCounters {
    /// Wants ADMITTED to the wire — one per want that reached the origin
    /// at least once.
    ///
    /// **This is not the request total on its own.** A shed want is
    /// retried exactly once (the shed arm is guarded by
    /// `!slot.retried`), and that retry is a second request at the
    /// origin. So the quantity that pairs with CernVM-FS's
    /// `download.n_requests` is **`origin_requests + origin_sheds`**,
    /// and the two are kept apart because their difference is itself the
    /// backpressure signal.
    pub(crate) origin_requests: u64,
    /// Admitted wants the origin shed (503/backpressure). Each costs an
    /// extra round trip and halves the AIMD window, so this is both a
    /// term of the request total and the reason a run was slow.
    pub(crate) origin_sheds: u64,
    /// Wants ACCEPTED onto the admission queue, split by kind — one per
    /// distinct id, after single-flight dedup and after both refusal
    /// gates, so a duplicate reference and a refused want are neither of
    /// them a want this fetch went on to do work for.
    ///
    /// **The split is granary's own attribution surface and has no
    /// counterpart to compare against**: CernVM-FS does not separate
    /// metadata from content in its own accounting (`cvmfs/fetch.cc`
    /// describes both fetch counters as "incl. catalogs, chunks"), so
    /// only the SUM is comparable across the two systems. It is kept
    /// split because the cold-read question is which of the two classes
    /// the time is in.
    pub(crate) wants_bin: u64,
    /// See [`ReadPathCounters::wants_bin`].
    pub(crate) wants_meta: u64,
    /// Wants served from the local cache without touching the wire.
    pub(crate) cache_hits: u64,
    /// Wants the cache could not serve, so the wire had to.
    pub(crate) cache_misses: u64,
    /// See [`FetchState::inflight_high_water`].
    pub(crate) inflight_high_water: usize,
}

impl ReadPathCounters {
    /// Count one admitted origin request and pass its charge through.
    ///
    /// A pass-through rather than a bare increment on purpose: it counts
    /// without adding a statement to `fetch_streaming`, which sits one
    /// line under clippy's `too_many_lines` bound.
    ///
    /// **Called where a want is SEATED, never where one is considered.**
    /// It is called past the in-flight byte gate, which pushes a want
    /// back onto the queue: called before it, a deferred want would be
    /// counted once per pass and the total would run ahead of what the
    /// origin saw. The row `a_byte_gate_deferral_is_not_a_round_trip`
    /// holds that line.
    fn admit(&mut self, charge: u64, observation: CacheObservation<'_>) -> u64 {
        self.origin_requests += 1;
        // THE CACHE MISS IS COUNTED HERE TOO, and for the same reason the
        // request is: this is the one point a want is seated, reached
        // exactly once per want. `deliver_cache_hit` sees a want as often
        // as the byte gate defers it, so counting the miss there counted
        // the same object repeatedly. Only the MISS path reaches `admit`
        // — a hit returns `Done` or `Defer` and never falls through to
        // the admission code — so this is a miss by construction.
        self.cache_misses += 1;
        observation.record(crate::CacheResult::Miss);
        charge
    }

    /// Count one want accepted onto the queue, by kind.
    const fn want(&mut self, want: &Want) {
        match want {
            Want::BinRange { .. } => self.wants_bin += 1,
            Want::Meta { .. } => self.wants_meta += 1,
        }
    }

    /// Widen the high-water mark to `depth` if it is deeper.
    const fn observe_depth(&mut self, depth: usize) {
        if depth > self.inflight_high_water {
            self.inflight_high_water = depth;
        }
    }
}

/// The part of a fetch that OUTLIVES one call: the AIMD window a
/// shed fetcher must stay cautious with, and the zstd contexts
/// whose reuse is the whole point of `GrainCodec`. Split out of
/// `Fetcher` because the daemon must own it across FUSE callbacks
/// while `Fetcher` itself borrows the remote — `fuser::Filesystem`
/// is `'static`, so a state that borrows cannot be stored.
#[derive(Debug)]
pub(crate) struct FetchState {
    window: usize,
    codec: GrainCodec,
    counters: ReadPathCounters,
    metrics: Option<crate::ClientMetrics>,
    phase: crate::CachePhase,
}

impl FetchState {
    pub(crate) fn new() -> Result<Self, FetchError> {
        Ok(Self {
            window: FETCH_WINDOW,
            codec: GrainCodec::new().map_err(FetchError::Codec)?,
            counters: ReadPathCounters::default(),
            metrics: None,
            phase: crate::CachePhase::Startup,
        })
    }

    pub(crate) fn metrics(&self) -> Option<&crate::ClientMetrics> {
        self.metrics.as_ref()
    }

    pub(crate) fn set_metrics(&mut self, metrics: Option<crate::ClientMetrics>) {
        if let Some(metrics) = &metrics {
            metrics.set_available(crate::MetricsGroup::Cache, true);
        }
        self.metrics = metrics;
    }

    /// The deepest this state's admission loop has seated at once SINCE
    /// the last [`FetchState::arm_read_phase`] (or since `new`, if it
    /// was never armed).
    ///
    /// `0` before any wire want has been admitted — a cache hit is
    /// delivered without ever seating a slot, so a fetch served entirely
    /// from cache leaves this untouched, by design.
    ///
    /// Mount reads submit one grain per callback, whereas the preamble submits
    /// batches. Resetting at the read boundary prevents startup concurrency
    /// from obscuring the read path's depth.
    pub(crate) const fn inflight_high_water(&self) -> usize {
        self.counters.inflight_high_water
    }

    /// The whole Tier-1 counter set, for a caller reporting it.
    pub(crate) const fn counters(&self) -> ReadPathCounters {
        self.counters
    }

    /// The live admission window, which is NOT [`FETCH_WINDOW`]: it is
    /// AIMD-controlled and a shed drives it down toward
    /// [`WINDOW_FLOOR`]. Reported alongside the high-water mark because
    /// the mark is only interpretable against the width that was
    /// actually available — a saturated pass at a shed window of 4
    /// otherwise reads as an idle one at 32.
    pub(crate) const fn window(&self) -> usize {
        self.window
    }

    /// Zero the high-water mark at a PHASE BOUNDARY, so what follows is
    /// measured on its own.
    ///
    /// The mount calls this once, after the preamble and before it
    /// serves its first read. Without it the mark reports the widest
    /// thing this state ever did — which for a mount is the preamble's
    /// structure-node batch, not the content read path the instrument
    /// is pointed at. Deliberately NOT called anywhere inside `fetch`:
    /// a mark that resets per call is not a mark.
    pub(crate) fn arm_read_phase(&mut self) {
        self.phase = crate::CachePhase::Read;
        self.counters = ReadPathCounters {
            origin_requests: 0,
            origin_sheds: 0,
            wants_bin: 0,
            wants_meta: 0,
            cache_hits: 0,
            cache_misses: 0,
            inflight_high_water: 0,
        };
    }
}

/// The windowed, budgeted, deduplicating fetcher — see the module doc
/// for the mechanism, the admission rule, the 503/AIMD backpressure and
/// the single-flight scope.
#[derive(Debug)]
pub(crate) struct Fetcher<'r, R> {
    remote: &'r R,
    state: &'r mut FetchState,
}

impl<'r, R: BinStore> Fetcher<'r, R> {
    pub(crate) const fn new(remote: &'r R, state: &'r mut FetchState) -> Self {
        Self { remote, state }
    }

    /// The seam this fetcher was built over — for a caller that ALSO
    /// needs the raw `R` directly (`resolve.rs`'s `check_chain`, whose
    /// ancestor ROOT reads are never `Want`-able, only content-addressed
    /// meta objects are).
    pub(crate) const fn remote(&self) -> &'r R {
        self.remote
    }

    /// Fetch every want in `wants`, deduplicated, windowed, cached, and
    /// verified. One entry per distinct [`GrainId`] the input named —
    /// duplicates resolve to the SAME entry.
    ///
    /// **Cache is optional** (absent = no cache, today's behaviour):
    /// `None` skips the cache-first lookup on admission and
    /// the insert on completion, both silently — a cacheless resolve is
    /// this same code path with the lookaside removed, not a second one.
    ///
    /// **A thin collector over [`Fetcher::fetch_streaming`]**: every
    /// want's charge already releases correctly through that engine's
    /// own accounting (converted-and-released for a success, the
    /// original admission charge for a failure — that method's own
    /// doc), so this collector only needs to decide what to hand BACK
    /// to `fetch_streaming` as the release amount, which for a batch
    /// caller is always "everything, now": nothing here is ever
    /// buffered past its own completion.
    pub(crate) async fn fetch(
        &mut self,
        cache: Option<&mut Cache>,
        wants: impl IntoIterator<Item = Want>,
    ) -> Result<BTreeMap<GrainId, Result<Vec<u8>, FetchError>>, FetchError> {
        let mut results: BTreeMap<GrainId, Result<Vec<u8>, FetchError>> = BTreeMap::new();
        let streamed = self
            .fetch_streaming(
                cache,
                wants.into_iter().map(Ok::<Want, std::convert::Infallible>),
                |id, outcome, charged| {
                    let released = match &outcome {
                        // A cache hit is charged like any other success — see
                        // `fetch_streaming`'s own admission loop — so this arm
                        // also covers it: release its bytes in full, same as a
                        // wire completion's.
                        Ok(bytes) if charged => bytes.len() as u64,
                        // Uncharged: nothing of this want's OWN to release.
                        // Two cases reach here, not one — a pre-admission
                        // refusal, and a cache hit refused `OverDeclared`.
                        // THIS collector returns 0 for both, which is right
                        // because it holds nothing back; but the return value
                        // is NOT ignored on the second: `fetch_streaming`
                        // applies it as an extra release, exactly as it does
                        // for a failed wire completion, so a caller that DOES
                        // hold other charged completions must report its
                        // flush here. (This collector is not one: it releases
                        // at once. Its own residency bound is that three of
                        // its four production call sites pass exactly ONE
                        // want, and the fourth sends a chunk whose worst-case
                        // reservations were capped at `POOL_CAP_BYTES` before
                        // it is sent — the results map below retains each
                        // outcome until the batch returns.) Charged failure:
                        // `fetch_streaming` itself releases the original
                        // admission charge unconditionally (that method's own
                        // doc) — this return value is not consulted FOR THAT
                        // RELEASE. (It is still applied as an EXTRA release,
                        // like the refusal's above — read `fetch_streaming`'s
                        // doc as the contract, not this sentence.)
                        _ => 0,
                    };
                    results.insert(id, outcome);
                    released
                },
            )
            .await;
        if let Err(never) = streamed {
            match never {}
        }
        Ok(results)
    }

    /// Like [`Fetcher::fetch`], but drains results THROUGH `on_complete`
    /// as each want's wire call answers rather than batching everything
    /// into a returned map — the mechanism per-file reassembly needs
    /// (the charge lasts from admission until emission: a want's bytes
    /// count against [`FETCH_INFLIGHT_BYTES`] from admission until the
    /// CALLER says it is done with them, not merely until the wire call
    /// answers).
    ///
    /// **`on_complete(id, outcome, charged)` is invoked once per
    /// distinct id in `wants`.** `charged` is `false` for a refusal
    /// the budget never counted: a pre-admission refusal (nothing can
    /// be held yet, so its return value is ignored) or a cache hit
    /// wider than its want's `unpacked_len`, refused by the admission
    /// loop BEFORE it is charged — nothing of ITS own is released,
    /// but its return value is applied as an EXTRA release exactly as
    /// a failed wire completion's is (below), because a caller may be
    /// holding other, charged completions it flushes on learning of
    /// the error. `charged` is `true` for everything the admission
    /// loop actually charges: a cache hit exactly as much as a wire
    /// completion, success or failure alike — a hit's bytes sit in
    /// the caller's holdback the same way a wire completion's do, so
    /// they are charged, delivered, and released the same way too.
    ///
    /// **A successful wire completion's charge is RECONCILED against its
    /// actual byte length BEFORE the callback runs.** Admission charges
    /// a `BinRange` at its caller-declared `unpacked_len` and a `Meta`
    /// at [`META_MAX_BYTES`] (see [`Want::admission_bytes`] for why each
    /// is the right a-priori figure); on success, the tracked charge is
    /// replaced with `bytes.len()` — decompressed for a `BinRange`, the
    /// real body for a `Meta` — before this call. For an HONEST
    /// manifest this is a no-op or a small release: a `BinRange`'s
    /// actual decompressed length is at most its declared
    /// `unpacked_len` (equal, unless this id was a duplicate charged at
    /// the MAX declaration across several conflicting positions —
    /// `resolve.rs`'s own `grain_span_facts` — in which case the
    /// release is the gap between that max and this content's real
    /// size); a `Meta`'s actual body is at most [`META_MAX_BYTES`], the
    /// bound its own read enforces. The RETURN VALUE then says how many
    /// of those RECONCILED bytes to release THIS STEP: the in-order
    /// case (this is the next grain the caller is waiting to emit)
    /// returns the full reconciled length; a caller BUFFERING an
    /// out-of-order completion for later returns `0`, holding the
    /// admission gate closed as hard as an in-flight wire call would.
    /// Releasing MORE than this want's own length is how a later
    /// arrival unblocks a RUN of previously-buffered ones in one step.
    ///
    /// **The reconciliation can only ever release, never grow the
    /// charge — `finish()`'s own `unpacked_len` guard is what makes
    /// that true.** [`FetchError::OverDeclared`] refuses a `BinRange`
    /// completion whose actual decompressed length exceeds its own
    /// declared `unpacked_len` (the manifest disagreeing with the bin
    /// it itself named — never legitimate content, since a grain's
    /// declared length and its content hash are both written by the
    /// same producer) BEFORE this method's caller ever sees an `Ok`
    /// for it — so by the time this reconciliation runs, `bytes.len()
    /// <= slot.charge` already holds for every `BinRange` that reaches
    /// it, the same way `bytes.len() <= META_MAX_BYTES` already did for
    /// a `Meta`. A manifest that under-declares never reaches THIS
    /// arm at all: it surfaces as [`FetchError::OverDeclared`], on the
    /// SAME unconditional-release path any other failure takes (below)
    /// — never as an inflated charge here. This is what makes the
    /// admission charge a TRUE bound on what a caller can ever hold
    /// resident, rather than a figure the fetcher merely trusts a
    /// manifest to have told the truth about.
    ///
    /// Compressed wire bytes are never any part of this accounting —
    /// they are the H2 connection window's own, separate pool
    /// (`H2_CONN_WINDOW`), paced
    /// independently of [`FETCH_INFLIGHT_BYTES`].
    ///
    /// **The one remaining overshoot source: the admission loop's own
    /// liveness escape hatch**, which admits the front want unconditionally
    /// whenever nothing is in flight (that loop's own proof comment covers
    /// why this is the only way to close a deadlock a duplicate-spanning
    /// holdback can otherwise reach — a charged want stays resident, and
    /// therefore charged, until its LAST occurrence drains, which can
    /// leave nothing in flight to ever admit the want blocking it). Its
    /// own overshoot is bounded exactly as any single want's admission
    /// charge already is: `unpacked_len` (≤
    /// [`granary_core::manifest::GRAIN_UNPACKED_MAX`], the manifest
    /// format's own ceiling on a `BinRange`'s declared size) for a cold
    /// `BinRange`, [`META_MAX_BYTES`] for a cold `Meta`, or the actual
    /// (already hash-verified) `bytes.len()` for a cache hit — itself
    /// bounded the same way, since that is the largest either kind of
    /// object could ever have been cached at. **Within ONE admission
    /// pass, a wire want closes the gate behind itself** — the want the
    /// hatch admits is what makes `in_flight` non-empty, so the next
    /// candidate in that pass meets an armed gate.
    ///
    /// **That is per-pass, and it is NOT a bound on a caller that
    /// HOLDS.** The hatch admits one front want EVERY time `in_flight`
    /// drains to empty, and it does so on BOTH paths — this method
    /// cannot tell a held byte from a released one, so
    /// `in_flight_bytes` may already be far over budget when the gate is
    /// skipped. The two paths differ only in PACING, not in whether they
    /// are bounded:
    ///
    /// - a CACHE HIT never seats a `Slot` at all, so a run of hits is
    ///   admitted in ONE synchronous pass with the gate skipped for
    ///   every one of them (sixteen cached 8 MiB hits with a holding
    ///   callback retain 134,217,728 bytes against a 67,108,864 budget,
    ///   growing linearly with the batch);
    /// - a WIRE want paces at one per completion cycle — it is charged,
    ///   completes, is reconciled to its actual length, and its slot
    ///   leaves `in_flight`; if the callback held the bytes, the charge
    ///   stays and the next pass finds `in_flight` empty and admits
    ///   again. Slower, equally unbounded.
    ///
    /// Both are charged — "no slot" never means "free" — but a charge
    /// only bounds anything if the callback releases it, and THAT IS A
    /// CALLER OBLIGATION THIS METHOD CANNOT ENFORCE. Today's callers are
    /// safe for reasons outside this gate, and the reasons are NOT the
    /// same one: `emit_file` is pre-bounded by `duplicate_span_peak`
    /// before it fetches at all and drains its in-order prefix, so it
    /// holds only what that sweep already capped. [`Fetcher::fetch`] is
    /// safe for a DIFFERENT and narrower reason — of its four production
    /// call sites THREE pass exactly ONE want, and the fourth
    /// (`prefetch_structure_nodes`) passes a chunk whose worst-case
    /// reservations are capped at `POOL_CAP_BYTES` before it is sent, so
    /// the batch is bounded either way. Its collector does release each
    /// completion into the gate at once, so `in_flight_bytes` never
    /// accumulates; but it also RETAINS every outcome in its results map
    /// until the batch returns, and that residency is the batch's total
    /// and sits outside this gate entirely. A multi-want `fetch` would
    /// hold the whole batch resident however this gate behaved. **A new
    /// caller that HOLDS completions must carry its own bound, covering
    /// EVERYTHING it holds and not just cache hits** — a guard written
    /// for hits alone leaves the wire path open. The admission loop's
    /// own comment says the same; the speculative pool's bound is
    /// `POOL_CAP_BYTES`.
    ///
    /// **A FAILED wire completion never converts and never holds: this
    /// method releases its ORIGINAL admission charge unconditionally**,
    /// regardless of what the callback returns — an error retains
    /// nothing, so there is never a reason for a caller to keep one
    /// charged. The callback's return value is still read for a
    /// failure, but means something DIFFERENT there: EXTRA bytes to
    /// release on top of the failing want's own charge, for a caller
    /// that was ALREADY holding other completions back and needs to
    /// flush them the moment it learns holding anything further is
    /// pointless (`resolve.rs`'s `emit_file`: the first error it sees
    /// is exactly the moment it abandons its holdback buffer).
    ///
    /// **The input is consumed completely before cache or wire admission.**
    /// A fallible caller can therefore stream declarations into this
    /// method without collecting them first: an input error drops the
    /// per-unique-id queue and returns before any external read begins.
    ///
    /// **Duplicate ids in `wants` collapse to one completion**, the same
    /// way [`Fetcher::fetch`] does (`admit_or_refuse`'s own dedup) — a
    /// caller need not dedup its own want list first.
    ///
    /// # Errors
    /// Returns the first error yielded by `wants`, before any cache or
    /// wire admission. Fetch outcomes are delivered through
    /// `on_complete`, as before.
    // No `#[expect(clippy::too_many_lines)]`: the function is under
    // clippy's `too_many_lines` bound, so nothing is suppressed. The
    // admission loop is one piece; splitting it would be its own change
    // with its own review.
    pub(crate) async fn fetch_streaming<E>(
        &mut self,
        mut cache: Option<&mut Cache>,
        wants: impl IntoIterator<Item = Result<Want, E>>,
        mut on_complete: impl FnMut(GrainId, Result<Vec<u8>, FetchError>, bool) -> u64,
    ) -> Result<(), E> {
        // Hoisted ABOVE `admit_or_refuse` because the want counters are
        // taken there — at the queue, after dedup and both refusal gates.
        // Disjoint field borrow, alongside `window` and `codec` below.
        let observation = CacheObservation::new(self.state.metrics.as_ref(), self.state.phase);
        let counters = &mut self.state.counters;
        // `&mut on_complete`, not a forwarding closure: `&mut F` is itself
        // `FnMut`, so the reborrow leaves `on_complete` usable below and
        // clippy's `redundant_closure` has nothing to object to. (CI denies
        // warnings, so the closure form fails the lint lane outright.)
        let mut queue: VecDeque<Want> = admit_or_refuse(wants, &mut on_complete, counters)?;

        let window = &mut self.state.window;
        // The instrument lives on the STATE because a mount holds one
        // across FUSE callbacks, and a peak that resets per call would
        // answer a different question than the one it is here to answer.
        let codec = &mut self.state.codec;
        let mut in_flight: Vec<Slot<'r>> = Vec::new();
        // Unlike `fetch`, this pool covers bytes the CALLER is holding
        // back too — it is decremented only by what `on_complete`
        // reports released (or, on a failure, by the slot's own
        // unconverted charge, unconditionally), never unconditionally
        // at completion.
        let mut in_flight_bytes: u64 = 0;

        std::future::poll_fn(|cx| {
            loop {
                while in_flight.len() < *window {
                    let Some(want) = queue.pop_front() else {
                        break;
                    };
                    // LIVENESS ESCAPE HATCH — `!in_flight.is_empty()` is
                    // ANDed onto both byte-gate checks below, never
                    // dropped, only skipped when nothing is in flight.
                    //
                    // PROOF this closes the deadlock: the only shape that
                    // wedges `poll_fn` forever is `queue` non-empty,
                    // `in_flight` empty, and this admission pass seating
                    // NOTHING — `retain_mut` then walks zero slots
                    // (`progressed` stays `false` with no slot ever
                    // polled to register a waker) and `!in_flight.is_empty()
                    // && queue.is_empty()` is false, so `Pending` returns
                    // with no event left anywhere that could ever repoll
                    // this future. With the hatch, admission cannot end a
                    // pass that way: the front candidate is checked with
                    // `in_flight` in exactly the state this pass started
                    // it. `in_flight.is_empty()` here means "no WIRE slot
                    // is seated" — NOT "nothing admitted this pass yet",
                    // which is
                    // false: a cache hit is admitted and charged
                    // without ever seating a slot, so a RUN of hits all see
                    // an empty `in_flight` and all skip the byte gate. That
                    // is sound for LIVENESS, which is all this proof is
                    // about — each one shrinks `queue` — but it is NOT a
                    // budget bound, and the distinction is load-bearing for
                    // anyone adding a caller that HOLDS: measured on this
                    // code, sixteen cached 8 MiB hits with a holding
                    // callback retain 134,217,728 bytes against a
                    // 67,108,864 budget, growing linearly with the batch.
                    // Today's callers are safe for reasons OUTSIDE this
                    // gate, and NOT the same reason: `emit_file` is
                    // pre-bounded by `duplicate_span_peak` and drains
                    // its in-order prefix; `Fetcher::fetch` is safe
                    // because three of its four production call sites
                    // pass exactly ONE want and the fourth is pre-capped
                    // at `POOL_CAP_BYTES` (the prefetch hint chunk) —
                    // its collector does release at once, but it also
                    // RETAINS every outcome until the batch returns,
                    // which is residency this gate never sees. So a new
                    // holding caller must carry its own bound, covering
                    // everything it holds and on BOTH paths, as the speculative
                    // pool does with `POOL_CAP_BYTES`.
                    // For the liveness argument: the moment
                    // `in_flight.is_empty()` is true the byte gate is
                    // skipped and this candidate ALWAYS leaves the queue,
                    // by one of THREE routes: delivering a cache hit,
                    // REFUSING an over-declared one (`deliver_cache_hit`
                    // returns `Done` from its refusal arm BEFORE the byte
                    // gate, so that route is unconditional in
                    // `in_flight_empty`), both of which shrink `queue`;
                    // or seating a real `Slot` (making `in_flight`
                    // non-empty, and thus pollable — a real want always
                    // eventually completes or sheds, either of which sets
                    // `progressed`). Any of the three makes the wedged
                    // shape unreachable: `queue` non-empty ∧ `in_flight`
                    // empty ∧ no admission never occurs again. A future
                    // edit that re-queues a refused want instead of
                    // finishing it is the one that would break this.
                    match deliver_cache_hit(
                        cache.as_deref_mut(),
                        &want,
                        &mut in_flight_bytes,
                        in_flight.is_empty(),
                        &mut on_complete,
                        counters,
                        observation,
                    ) {
                        CacheHit::Done => continue,
                        CacheHit::Defer => {
                            queue.push_front(want);
                            break;
                        }
                        CacheHit::Miss => {}
                    }
                    let charge = want.admission_bytes();
                    if in_flight_bytes.saturating_add(charge) > FETCH_INFLIGHT_BYTES
                        && !in_flight.is_empty()
                    {
                        queue.push_front(want);
                        break;
                    }
                    // COUNTED PAST THE BYTE GATE, not before it. The gate
                    // above pushes the want back onto the queue, so a want
                    // counted before it is counted AGAIN on every later
                    // pass — measured at 8 for six objects, and the
                    // fetches that defer most are the large ones the cold-read
                    // decomposition cares about. Folded into the `+=`
                    // rather than added as a statement because
                    // `fetch_streaming` sits at its `too_many_lines`
                    // bound; `admit` returns its argument for exactly this.
                    in_flight_bytes += counters.admit(charge, observation);
                    in_flight.push(Slot {
                        charge,
                        step: wire_step(self.remote, &want),
                        want,
                        retried: false,
                    });
                }

                // Sampled HERE, at the close of the admission pass, which
                // is where `in_flight` is at its widest: the loop above
                // seats up to the whole window before anything is polled,
                // and the `retain_mut` below only ever removes. Sampling
                // after the poll would read the survivors, not the peak.
                // One statement rather than an `if`: this function sits one
                // line under clippy's `too_many_lines` bound.
                counters.observe_depth(in_flight.len());

                let mut progressed = false;
                in_flight.retain_mut(|slot| match slot.step.as_mut().poll(cx) {
                    Poll::Pending => true,
                    Poll::Ready(Step::DelayElapsed) => {
                        progressed = true;
                        slot.step = wire_step(self.remote, &slot.want);
                        true
                    }
                    Poll::Ready(Step::Wire(result)) if sheds(&result) && !slot.retried => {
                        progressed = true;
                        counters.origin_sheds += 1;
                        slot.retried = true;
                        *window = (*window / 2).max(WINDOW_FLOOR);
                        slot.step = delay_step();
                        true
                    }
                    Poll::Ready(Step::Wire(result)) => {
                        progressed = true;
                        // Growth is earned by an ANSWER — the module
                        // doc's rationale for growing on non-shed
                        // failures is "the server answered
                        // authoritatively, and an answer is not
                        // congestion". An `Elapsed` is the opposite of
                        // an answer (the peer said nothing for the whole
                        // per-call deadline), so it earns neither the
                        // shed's halving nor the answer's +1: the
                        // window a wedged peer times out against stays
                        // exactly where the last real signal left it.
                        if !sheds(&result) && !matches!(result, Err(RootStoreError::Elapsed { .. }))
                        {
                            *window = (*window + 1).min(FETCH_WINDOW);
                        }
                        let id = slot.want.id();
                        let outcome = finish(&slot.want, result, codec, cache.as_deref_mut());
                        match outcome {
                            Ok(bytes) => {
                                // Reconcile BEFORE the callback runs —
                                // see this method's own doc for why:
                                // `finish()`'s own guard already refused
                                // any BinRange whose actual size exceeds
                                // its charge, so this can only ever
                                // release, a no-op at most for an honest
                                // BinRange or Meta — never grow the
                                // running total.
                                let actual = bytes.len() as u64;
                                in_flight_bytes = in_flight_bytes
                                    .saturating_sub(slot.charge)
                                    .saturating_add(actual);
                                let released = on_complete(id, Ok(bytes), true);
                                // Never below zero: a caller reporting
                                // more than this pool actually holds
                                // cannot underflow the running total.
                                in_flight_bytes = in_flight_bytes.saturating_sub(released);
                            }
                            Err(e) => {
                                // Unconditional: an error retains
                                // nothing, so the ORIGINAL admission
                                // charge always releases in full,
                                // regardless of the callback's return.
                                // That return value means something else
                                // here — see this method's own doc — an
                                // EXTRA flush the caller reports on TOP
                                // of this want's own charge.
                                let extra = on_complete(id, Err(e), true);
                                in_flight_bytes = in_flight_bytes
                                    .saturating_sub(slot.charge)
                                    .saturating_sub(extra);
                            }
                        }
                        false
                    }
                });

                if !progressed {
                    if in_flight.is_empty() && queue.is_empty() {
                        return Poll::Ready(());
                    }
                    return Poll::Pending;
                }
            }
        })
        .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
