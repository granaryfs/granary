// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `object_store` adapters: content-addressed bins/metadata plus the
//! `RootStore` CAS implementation.
//!
//! Layout in the bucket:
//!
//! ```text
//! root/{volume}/{seq:020}   numbered signed roots, put-if-absent
//! root/{volume}/CURRENT     advisory hint: exactly the 20-digit seq
//! meta/{volume}/{2hex}/{hex}  binmap index + bin table + shards
//!                           + SHEAVES — all four kinds `get_meta`
//!                           reads, the sheaf included: a list of
//!                           meta kinds without it is incomplete
//! bins/{2hex}/{hex}         bins (grains + manifest nodes inside;
//!                           sheaves are DIRECT meta objects, never
//!                           binned)
//! ```
//!
//! Rules this module carries (all established by execution):
//! single-shot PUTs ONLY (bins are bounded far below the 5 GiB single
//! PUT cap; conditional multipart does not exist upstream and the AWS
//! MPU race is a documented footgun); `PutMode::Create` conflicts
//! surface immediately and the caller resolves them by the ONE-PROBE
//! RULE, stated normatively (and only) in the `rootstore` module docs
//! (`object_store`'s in-crate retry covers only the Update path);
//! listing
//! order is NEVER trusted (`max_seq` parses and takes the numeric max
//! client-side); the CURRENT hint is ADVISORY ONLY — its body strict-
//! parses as exactly 20 digits, a bad body degrades to `Missing`, a
//! stale hint is DESIGNED to occur (crash between root CAS and hint
//! write) and readers forward-probe while every publish repairs it.
//!
//! **Volume names alias.** `object_store::path::Path::from` normalises
//! its input (collapses repeated slashes, strips a leading/trailing
//! one), so `"a/b"`, `"a//b"`, and `"a/b/"` all resolve to the SAME
//! `root/a/b/…` and `meta/a/b/…` keyspace (verified). Every method
//! that interpolates a volume into a key therefore validates it first
//! (`checked_volume` — DNS-1123 via `VolumeName`, so `/` is refused
//! before it can address anything), returning
//! `RootStoreError::InvalidVolume`. The trait's `&str` parameter is a
//! caller convenience, NOT a licence to trust: the aliasing above is
//! why this boundary enforces the rule itself rather than assuming a
//! caller already did.

use granary_core::binfmt::{BIN_MAX_BYTES, FRAME_COMP_MAX};
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::root::VolumeName;
use granary_core::rootstore::{
    HintRead, HintToken, RefusalKind, RootStore, RootStoreError, SEQ_KEY_DIGITS, format_hint_body,
    parse_hint_body,
};
use object_store::path::Path as StorePath;
use object_store::{GetOptions, ObjectStore, ObjectStoreExt, PutMode, PutOptions};

/// The two transfer caps, re-exported from their non-feature-gated home
/// so callers that already take the `backend` feature keep this path.
///
/// The definitions live in [`crate::bounds`] because they are plain
/// `u64`s derived from `granary-core` values: naming them must not cost
/// a consumer the `object_store` closure this module carries.
pub use crate::bounds::{META_MAX_BYTES, ROOT_MAX_BYTES};

/// Render a digest as the two-level fanout path segment `ab/abcd…`.
fn fanout(digest: &[u8; DIGEST_LEN]) -> String {
    let mut hex = String::with_capacity(DIGEST_LEN * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    let (fan, _) = hex.split_at(2);
    format!("{fan}/{hex}")
}

fn backend_err(e: &object_store::Error) -> RootStoreError {
    RootStoreError::Backend(e.to_string())
}

/// The `If-None-Match` value for a cached hint token, or `None` to
/// send no conditional header at all. An empty token is the no-etag
/// degenerate case (`unwrap_or_default()` on a backend that omitted
/// an `ETag`) — treated as "no cached token" so revalidation is
/// skipped, rather than sending a malformed `If-None-Match: ""`.
///
/// Split out as a pure, named function because the
/// guard is otherwise unobservable in a hermetic test: no backend
/// measured here (`InMemory`, `MinIO`/S3) ever mints an empty `ETag`
/// for a real object, so an empty token sent as `If-None-Match: ""`
/// never accidentally MATCHES and the end-to-end `HintRead` outcome is
/// identical with or without this guard — only inspecting the
/// constructed value itself catches a regression.
fn conditional_token(cached: Option<&HintToken>) -> Option<&str> {
    cached.filter(|t| !t.0.is_empty()).map(|t| t.0.as_str())
}

/// The granary object-store surface over any `object_store` backend.
#[derive(Debug)]
pub struct GranaryStore<S: ObjectStore> {
    inner: S,
}

impl<S: ObjectStore> GranaryStore<S> {
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    /// THE NAME→KEY BOUNDARY. Every method below interpolates `volume`
    /// into a store key, so this is where an unvalidated name would
    /// become addressing: a name carrying `/` reaches outside its own
    /// prefix. The `RootStore` trait takes `&str` (83 call sites, all
    /// passing `VolumeName::as_str()` today), so the enforcement
    /// `root.rs` cites cannot be assumed — it is APPLIED here instead,
    /// failing closed, which holds for the caller this exists for: the
    /// server relaying a client-supplied name. `VolumeName` is
    /// DNS-1123 (`[a-z0-9-]`, no leading/trailing dash), so `/`, `.`,
    /// `..` and every other separator are refused by the same rules the
    /// root decoder applies.
    ///
    /// **This boundary covers name LEGALITY, not name POLICY** — do not
    /// read it as covering names completely. The reserved-name registry
    /// (`granary_core::root::is_reserved_volume_name`) makes the
    /// opposite choice at this same boundary for this same caller, and
    /// deliberately: DNS-1123 must bind EVERY writer including granary,
    /// because an illegal name cannot become a well-formed key for
    /// anyone, so applying it to every call site costs granary nothing.
    /// Reservation must NOT bind granary — a reserved name has to stay
    /// mintable by the project — so it is applied where a volume is
    /// CREATED, not on every key construction. A reserved name reaching
    /// these methods is therefore accepted, and correctly so.
    fn checked_volume(volume: &str) -> Result<(), RootStoreError> {
        VolumeName::new(volume.to_owned())
            .map(|_| ())
            .map_err(|e| RootStoreError::InvalidVolume {
                reason: e.to_string(),
            })
    }

    fn root_key(volume: &str, seq: u64) -> StorePath {
        StorePath::from(format!("root/{volume}/{}", format_hint_body(seq)))
    }

    fn hint_key(volume: &str) -> StorePath {
        StorePath::from(format!("root/{volume}/CURRENT"))
    }

    /// Upload a bin if absent. Returns `true` when it was novel —
    /// `AlreadyExists` is SUCCESS for content-addressed objects
    /// (another publish already carried identical bytes).
    ///
    /// # Errors
    /// [`RootStoreError::Backend`] on transport/backend failure.
    pub async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        // Hot path: no release-mode re-hash — the caller computed the
        // digest from these same bytes in-process (the local-store
        // idiom). Debug builds verify; PRESENCE IS NEVER INTEGRITY
        // either way: readers blake3-verify at fetch, so a poisoned or
        // colliding object is detected at consumption, not trusted at
        // dedup.
        debug_assert_eq!(GrainId::of(&bytes).digest(), digest);
        self.put_if_absent(StorePath::from(format!("bins/{}", fanout(digest))), bytes)
            .await
    }

    /// Fetch one frame extent out of a bin with one range GET.
    /// Each grain has its own frame. The caller decompresses via the
    /// codec and blake3-verifies.
    ///
    /// If the range overhangs the object (`offset + len` extends past
    /// the object's true length), the backend clamps rather than
    /// errors: the response holds however many bytes exist from
    /// `offset` onward, FEWER than `len` requested. The codec's
    /// declared-length check catches this downstream (a short frame
    /// fails to decode); this function does not itself detect or
    /// refuse it.
    ///
    /// # Errors
    /// [`RootStoreError::NotFound`] for a missing bin;
    /// [`RootStoreError::RangeOverflow`] if `offset + len`
    /// overflows `u64`. The checked arithmetic stays even though
    /// `binmap.rs` bounds `offset + comp_len` against the frozen
    /// `BIN_MAX_BYTES`: `len` here is the CALLER's, not
    /// necessarily a decoded `comp_len`, and defence in depth at
    /// a boundary that takes untrusted extents is worth one
    /// `checked_add` (`Cargo.toml` sets
    /// `overflow-checks = true`, so an unchecked add panics in
    /// release too);
    /// [`RootStoreError::RefusedResponse`] when the reported extent is
    /// not one this request could have produced — it starts elsewhere,
    /// ends past the requested end, spans nothing, or spans more than a
    /// whole bin — or when the body does not MATCH that extent, outrunning
    /// it or falling short of it;
    /// [`RootStoreError::Backend`] otherwise (including range errors —
    /// never probe bounds with suffix reads).
    pub async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        let end = offset
            .checked_add(u64::from(len))
            .ok_or(RootStoreError::RangeOverflow)?;
        let opts = GetOptions {
            range: Some((offset..end).into()),
            ..Default::default()
        };
        let key = StorePath::from(format!("bins/{}", fanout(digest)));
        match self.inner.get_opts(&key, opts).await {
            Ok(r) => {
                // THE EXTENT GATE. `meta.size` is deliberately NOT
                // consulted: it is the size of the WHOLE bin, which is
                // legitimately larger than any subrange, so gating it
                // against `len` would refuse every ranged read of a big
                // bin — including the pinned short read at offset 90 of a
                // 100-byte bin. `r.range` is the extent THIS response
                // returned, and that is what the request can be compared
                // against.
                //
                // Both halves are load-bearing, and WIDTH ALONE IS NOT
                // ENOUGH. Ask for `offset = 10, len = 100` on a 100-byte
                // bin: a backend that ignores the range answers
                // `0..100`, whose width is 100 and so passes any
                // width-only check — while the caller receives bytes from
                // offset 0 believing it asked for offset 10. That is a
                // WRONG SLICE, not an oversized transfer, which is why
                // the start is checked first.
                if r.range.start != offset {
                    return Err(RootStoreError::RefusedResponse {
                        reason: format!(
                            "bin at {key}: asked for {offset}..{end}, the response starts at {}",
                            r.range.start
                        ),
                        kind: RefusalKind::Extent,
                    });
                }
                // Short reads are legal (`end` may be less — the pinned
                // overhang semantic); over-reads are not.
                if r.range.end > end {
                    return Err(RootStoreError::RefusedResponse {
                        reason: format!(
                            "bin at {key}: asked for {offset}..{end}, the response ends at {}",
                            r.range.end
                        ),
                        kind: RefusalKind::Extent,
                    });
                }
                // What this gate RESTS ON, stated rather than implied:
                // `r.range` being the backend's honest report of what it
                // returned. A backend that lies about `r.range` too can
                // still hand back the wrong slice within the requested
                // width — undetectable here without hashing. It is
                // detected downstream instead: bins are content-addressed
                // and every reader blake3-verifies what it consumed,
                // so the failure is caught, never trusted.
                let width = r.range.end.saturating_sub(r.range.start);
                // A ZERO-WIDTH response to a request for real bytes. The
                // walk below would take a cap of zero and answer
                // `Ok(vec![])`, and an empty read is never a success on
                // this seam — the pinned semantic is that a range
                // spanning nothing is an ERROR. Guarded on `len` so the
                // degenerate `len == 0` request keeps the backend's own
                // refusal, which is the outcome pinned for it.
                if len > 0 && width == 0 {
                    return Err(RootStoreError::RefusedResponse {
                        reason: format!(
                            "bin at {key}: asked for {offset}..{end}, the response spans nothing"
                        ),
                        kind: RefusalKind::Extent,
                    });
                }
                // THE EXTENT'S OWN CEILING, DERIVED rather than borrowed
                // from the request. Everything above compares the
                // response against what the CALLER asked for, and `len`
                // is a u32 that becomes client-chosen on the relay path —
                // so a response can sit inside a 4 GiB request and pass
                // every check above while naming `width` as the transfer
                // cap. An extent of a bin cannot exceed the bin, and a bin
                // cannot exceed `BIN_MAX_BYTES`, so a wider extent is one
                // no legal object can produce.
                //
                // REFUSED, not clamped. A clamp would still admit a
                // 256 MiB transfer for a response already known to be
                // impossible; refusing costs nothing, and fails closed.
                if width > BIN_MAX_BYTES {
                    return Err(RootStoreError::RefusedResponse {
                        reason: format!(
                            "bin at {key}: the response spans {width} bytes, over the \
                             {BIN_MAX_BYTES}-byte bin ceiling"
                        ),
                        kind: RefusalKind::Extent,
                    });
                }
                // THE REFUSAL BOUND AND THE ALLOCATION BOUND ARE
                // DIFFERENT QUESTIONS, and they were one number.
                //
                // The refusal bound is a CONTRACT question: what extents
                // may this seam return? `get_bin_range` is a general range
                // read (the conformance body drives arbitrary ranges), so
                // the only defensible ceiling is the one no legal object
                // can exceed — `BIN_MAX_BYTES`, checked above. Tightening
                // it to a frame's width would refuse legal requests.
                //
                // The allocation bound is a RESOURCE question: how much
                // must be reserved BEFORE the bytes prove they exist?
                // Nothing forces that to equal the refusal bound, and
                // equating them meant a legal 256 MiB extent reserved
                // 256 MiB up front for a response that may deliver 100
                // bytes — with an allocation failure aborting the process
                // rather than returning. Conflating the two is what made
                // the tight-ceiling argument look like the only way to
                // fix the allocation.
                //
                // So: refuse at the bin ceiling, but SIZE at the largest
                // extent this seam's real caller asks for — one frame.
                // That is not a guess at a "modest" number: the resolver
                // passes a shard entry's `comp_len`, and the shard decoder
                // refuses any `comp_len` over `FRAME_COMP_MAX`, so no
                // legitimate frame read can want more than this reserves.
                // A wider extent is still legal and simply grows as bytes
                // arrive — amortised copying on a path already streaming
                // megabytes, and nothing paid up front on the path that
                // is not.
                let body = collect_bounded(
                    r,
                    width,
                    range_alloc_hint(width),
                    "bin range",
                    &key,
                    RefusalKind::Extent,
                )
                .await?;
                // THE EXTENT'S OWN FLOOR. Everything above bounds the
                // response from ABOVE — no wrong start, no over-read, no
                // impossible width, and a transfer that stops at `width`
                // — and none of it says the body ARRIVED. `width` was
                // handed to the walk as a CAP, and a cap refuses `seen >
                // cap` and nothing else, so a response declaring
                // `10..50` and delivering thirty bytes came back `Ok`
                // with thirty bytes: a truncated transfer reported as a
                // successful read.
                //
                // The distinction, because it is the whole check: a
                // NARROWER EXTENT HONESTLY DECLARED is a legal short
                // read — the pinned overhang semantic, where a request
                // past the end of a bin answers `90..100` and delivers
                // ten bytes, which this equality accepts. A BODY SHORTER
                // THAN ITS OWN DECLARED EXTENT is a backend
                // contradicting itself inside one response, and that is
                // what this refuses.
                //
                // Applied HERE and not inside `collect_bounded`, and the
                // scoping is the load-bearing part. `get_bounded` passes
                // the frozen format ceiling for an object KIND, where an
                // under-cap body is the ordinary case — a 707-byte root
                // under a 64 KiB cap — so an equality inside the walk
                // would refuse every legal root, meta object and bin in
                // the tree. `read_hint` would happen to survive one, its
                // cap being the hint's exact width and a refusal
                // degrading to `Missing` exactly as a failed parse does;
                // that is a property of THAT caller, not of the walk. A
                // cap and an exact width are different contracts, and
                // only this call site has the second.
                let got = u64::try_from(body.len()).unwrap_or(u64::MAX);
                if got != width {
                    return Err(RootStoreError::RefusedResponse {
                        reason: format!(
                            "bin at {key}: the response declared {width} bytes and delivered {got}"
                        ),
                        kind: RefusalKind::Extent,
                    });
                }
                Ok(body)
            }
            Err(object_store::Error::NotFound { .. }) => Err(RootStoreError::NotFound),
            Err(e) => Err(backend_err(&e)),
        }
    }

    /// Fetch a whole bin (ingest-verify / test path).
    ///
    /// # Errors
    /// As [`Self::get_bin_range`].
    pub async fn get_bin(&self, digest: &[u8; DIGEST_LEN]) -> Result<Vec<u8>, RootStoreError> {
        self.get_bin_bounded(digest, BIN_MAX_BYTES).await
    }

    /// Fetch a whole bin under a caller-provided cap and the bin format cap.
    ///
    /// # Errors
    /// As [`Self::get_bin`], including an over-cap bounded response refusal.
    pub async fn get_bin_bounded(
        &self,
        digest: &[u8; DIGEST_LEN],
        cap: u64,
    ) -> Result<Vec<u8>, RootStoreError> {
        self.get_bounded(
            StorePath::from(format!("bins/{}", fanout(digest))),
            cap.min(BIN_MAX_BYTES),
            "bin",
        )
        .await
    }

    /// Upload a metadata object (binmap index / bin table / shard) if
    /// absent — content-addressed under its volume, so unchanged
    /// shards dedup across publishes.
    ///
    /// # Errors
    /// [`RootStoreError::Backend`] on transport/backend failure.
    pub async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        Self::checked_volume(volume)?;
        // Same contract as put_bin: debug-verified, presence ≠
        // integrity, readers verify at fetch.
        debug_assert_eq!(&GrainId::of(&bytes), id);
        self.put_if_absent(
            StorePath::from(format!("meta/{volume}/{}", fanout(id.digest()))),
            bytes,
        )
        .await
    }

    /// Fetch a metadata object.
    ///
    /// # Errors
    /// As [`Self::get_bin`].
    pub async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.get_meta_bounded(volume, id, META_MAX_BYTES).await
    }

    /// Fetch metadata under a caller-provided cap and the metadata format cap.
    ///
    /// # Errors
    /// As [`Self::get_meta`], including an over-cap bounded response refusal.
    pub async fn get_meta_bounded(
        &self,
        volume: &str,
        id: &GrainId,
        cap: u64,
    ) -> Result<Vec<u8>, RootStoreError> {
        Self::checked_volume(volume)?;
        self.get_bounded(
            StorePath::from(format!("meta/{volume}/{}", fanout(id.digest()))),
            cap.min(META_MAX_BYTES),
            "meta object",
        )
        .await
    }

    /// Fetch a root under a caller-provided cap and the root format cap.
    ///
    /// # Errors
    /// Missing, unreadable, or over-cap response.
    pub async fn get_root_bounded(
        &self,
        volume: &str,
        seq: u64,
        cap: u64,
    ) -> Result<Vec<u8>, RootStoreError> {
        Self::checked_volume(volume)?;
        self.get_bounded(Self::root_key(volume, seq), cap.min(ROOT_MAX_BYTES), "root")
            .await
    }

    /// Put-if-absent, mapping `AlreadyExists` to `Ok(false)`.
    ///
    /// NO REPAIR PATH EXISTS FOR A SQUATTED KEY TODAY, by design, and
    /// this is where that shows. `Ok(false)` means
    /// "an object is already at this content-addressed key" — which is
    /// indistinguishable from a genuine dedup hit, because the write
    /// path never reads back what is there. A pre-planted GARBAGE
    /// object at a key granary later wants is therefore treated as
    /// landed: the publish proceeds, signs a root naming it, and no
    /// write path can ever overwrite or verify it.
    ///
    /// Why this is an availability problem and not an integrity one:
    /// every read path blake3-verifies against the id it asked for,
    /// so a squatted key produces a DETECTED failure at
    /// consumption, never a wrong answer. Recovery, until an admin
    /// verb exists, is out-of-band: delete the offending object from
    /// the bucket and re-publish, which is safe precisely because the
    /// keys are content-addressed — the correct bytes for that key are
    /// reproducible from the source tree.
    ///
    /// The ingest-side shape (recorded so it is designed, not improvised): an
    /// explicit verify-and-overwrite admin operation that GETs the key,
    /// blake3-checks it against the id, and overwrites only on
    /// mismatch. It is deliberately not on the publish path — making
    /// the hot path read-before-write would double request cost on
    /// every dedup hit to defend against a case that requires bucket
    /// write access to create.
    async fn put_if_absent(&self, key: StorePath, bytes: Vec<u8>) -> Result<bool, RootStoreError> {
        let opts = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        match self.inner.put_opts(&key, bytes.into(), opts).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::AlreadyExists { .. }) => Ok(false),
            Err(e) => Err(backend_err(&e)),
        }
    }

    /// Fetch a whole object, BOUNDED at `cap` bytes. The body of every
    /// whole-object read on this type; `cap` is the frozen format ceiling
    /// for the kind of object `what` names.
    ///
    /// # The threat model this bounds, and the one it does not
    ///
    /// The adversary in scope is **one who can plant objects under a
    /// volume prefix in the bucket** (spec §9). Planting a malformed key
    /// there is beyond the shared conformance suite's reach: it requires
    /// raw store access. The server relays
    /// objects out of a bucket such an attacker may write, so an object's
    /// size is untrusted input on every read path.
    ///
    /// Two DIFFERENT things are bounded here, and conflating them is how
    /// a gate ends up protecting neither:
    ///
    /// - **The ALLOCATION** is bounded by the advertised-size gate, which
    ///   runs before the body is touched. `GetResult::bytes()` passes the
    ///   response length to `collect_bytes` as a `Vec::with_capacity`
    ///   hint, so without this gate a lying `Content-Length` sizes the
    ///   buffer — and a Rust allocation failure ABORTS the process rather
    ///   than returning an error a caller could handle.
    /// - **The TRANSFER** is bounded by the counting reader in
    ///   [`collect_bounded`], which walks the response in the chunks the
    ///   HTTP client's read buffer produces and stops at the cap. This is
    ///   the half that survives a backend whose advertised size LIES, and
    ///   the size gate alone does not have it.
    ///
    /// **What this does NOT bound: a hostile in-process `ObjectStore`
    /// implementation.** `GetResultPayload::Stream` yields already-
    /// allocated `Bytes`, so an implementation linked into this process
    /// can hand the whole oversized object over as ONE item and the
    /// allocation has already happened before any check runs. That
    /// adversary is a supply-chain compromise, not a bucket-write
    /// compromise, and is out of scope here — said plainly because the
    /// type cannot give the guarantee, not because the case is unlikely.
    ///
    /// Residual, stated rather than implied: a backend may still cause
    /// ONE allocation of up to `cap` bytes by advertising `cap` and
    /// delivering less. It is bounded by a frozen format constant, which
    /// is the guarantee — NOT by any equivalence with planting. Against
    /// the in-scope bucket writer the two are comparable; against a
    /// hostile ENDPOINT they are not, and that adversary is the one that
    /// can lie about a length. A planted object costs an upload and
    /// occupies the bucket until removed, while an advertisement is free,
    /// leaves nothing behind and can be repeated on every request. What
    /// makes the residual acceptable is its ceiling, not its cost to the
    /// attacker.
    ///
    /// **This is a SIZE bound, never a TIME bound.** A cap on bytes says
    /// nothing about how long they take to arrive: an endpoint that
    /// dribbles one byte per second never trips a byte counter fast
    /// enough to matter. What bounds that is a caller's deadline around
    /// the whole operation (coding-standards rule 13), and no bound here
    /// substitutes for it.
    ///
    /// **A caller's `tokio::time::timeout` covers this walk only because
    /// the walk lets it**, which is worth being exact about because the
    /// intuitive belief is that a timeout works unconditionally.
    /// [`collect_bounded`] polls the body stream directly, and a stream
    /// that answers `Poll::Ready` every time never returns `Pending` on
    /// its own — a future that never hands the thread back is one whose
    /// timer is never polled and never fires, and a task abort lands only
    /// at a yield point too. The walk therefore yields DELIBERATELY,
    /// every [`BODY_YIELD_INTERVAL`] chunks, so those instruments have a
    /// point to land on at all (see `yield_once` for what the self-wake
    /// does and does not guarantee about how PROMPTLY they land).
    ///
    /// That is liveness on top of, never instead of, the walk's own
    /// bounds: it still terminates unaided (by `cap` in bytes and by
    /// [`ZERO_CHUNK_ALLOWANCE`] in empty chunks), because a bound that
    /// depends on every caller remembering a deadline is not a bound. A
    /// deadline remains worth having for the slow-dribble case above,
    /// which no local bound can see.
    ///
    /// Note the adversary differs for all of this: chunking is the HTTP
    /// client's, not the bucket writer's, so it needs a hostile ENDPOINT
    /// rather than the in-scope attacker above.
    ///
    /// # Errors
    /// [`RootStoreError::RefusedResponse`] when the advertised size or
    /// the streamed body exceeds `cap` — granary's own refusal, which is
    /// why it is not `Backend` (see that variant's docs);
    /// [`RootStoreError::NotFound`] for a missing object;
    /// [`RootStoreError::Backend`] otherwise.
    async fn get_bounded(
        &self,
        key: StorePath,
        cap: u64,
        what: &'static str,
    ) -> Result<Vec<u8>, RootStoreError> {
        match self.inner.get(&key).await {
            Ok(r) => {
                // THE ADVERTISED-SIZE GATE, before any body byte is
                // requested — the response is dropped after its headers.
                if r.meta.size > cap {
                    return Err(RootStoreError::RefusedResponse {
                        reason: format!(
                            "{what} at {key} advertises {} bytes, over the {cap}-byte cap",
                            r.meta.size
                        ),
                        kind: RefusalKind::OverCap,
                    });
                }
                let hint = r.meta.size;
                collect_bounded(r, cap, hint, what, &key, RefusalKind::OverCap).await
            }
            Err(object_store::Error::NotFound { .. }) => Err(RootStoreError::NotFound),
            Err(e) => Err(backend_err(&e)),
        }
    }
}

/// How many ZERO-LENGTH chunks one response body may contain before the
/// walk refuses it. A body's cap is counted in BYTES, so an empty chunk
/// moves no counter and buys its sender an unbounded loop for free; this
/// allowance is what makes the walk terminate on its own rather than on a
/// caller's good behaviour.
///
/// Counted over the WHOLE response, not consecutively. A consecutive
/// counter is defeated by one byte between runs — the byte cap admits
/// `cap` of those, so an interleaving sender would still get
/// `cap × allowance` iterations. Counted in total, the walk runs at most
/// `cap + ZERO_CHUNK_ALLOWANCE + 2` times against any stream: each bound
/// admits its own number and then spends ONE more iteration on the chunk
/// that trips it.
///
/// That distinction is the kind an argument can assert and a suite can
/// miss, so it is TESTED rather than reasoned:
/// `one_byte_between_runs_of_zero_length_chunks_does_not_reset_the_allowance`
/// is the only thing in the suite that fails when this counter is made
/// consecutive — an unbroken run of empties trips either version, so
/// everything else passes on the mutant.
///
/// 1,024 rather than zero because a zero-length frame is legal HTTP and a
/// client may surface one; no legitimate body has a use for a thousand.
const ZERO_CHUNK_ALLOWANCE: u32 = 1024;

/// How many listing entries `max_seq` and `max_seq_above` walk between cooperative yields.
/// It bounds the LATENCY of a cancellation, not the walk itself — see
/// `yield_once` for why the walk has no bound of its own.
const LIST_YIELD_INTERVAL: u32 = 128;

/// How many response-body chunks [`collect_bounded`] walks between
/// cooperative yields.
///
/// **A cap is not a substitute for this, and the numbers say why.** The
/// byte cap bounds how much ARRIVES; it says nothing about how many times
/// the loop runs to receive it, because a chunk may carry as little as
/// one byte. A `get_bin` body cut that finely runs 268,435,457 iterations
/// before the cap can refuse it — measured, release build, ~2 s — and a
/// walk that never returns `Pending` holds the worker for all of them.
/// Interleaving that with a yield every 128 chunks cost 1.4% of the same
/// walk and made it 2,097,152 interruption points instead of none.
///
/// Kept separate from [`LIST_YIELD_INTERVAL`] rather than shared: the two
/// walks iterate over different things at different costs, so one moving
/// must not drag the other. Both are 128 today, which is a coincidence of
/// scale, not a constraint.
const BODY_YIELD_INTERVAL: u32 = 128;

/// One cooperative yield: wake immediately, return `Pending` once, and
/// so hand the thread back to the executor.
///
/// **Why any of this is needed.** A `while let Some(x) = poll_fn(|cx|
/// …poll_next(cx)).await` loop over a stream that answers `Poll::Ready`
/// every time never returns control to the executor. Nothing else on the
/// runtime is polled until the loop ends — not a `tokio::time::timeout`
/// wrapped around it, not a task abort, neither of which can take effect
/// anywhere but at a yield point. Where a walk can also bound ITSELF it
/// does (see [`ZERO_CHUNK_ALLOWANCE`]); a listing walk cannot, because a
/// truncated listing yields a WRONG head rather than a slow one, so
/// interruptibility is all it has.
///
/// # What this is NOT: `tokio::task::yield_now`
///
/// It is not used because tokio is a DEV-dependency here and this crate
/// stays runtime-agnostic — its callers own the executor. But it is also
/// NOT the same construction, and the difference is worth stating because
/// the intuitive reading is that they are interchangeable. tokio 1.53.1,
/// `src/task/yield_now.rs`:
///
/// ```text
/// // Don't wake the task immediately, as that would push it right back
/// // onto the run queue and it could be polled again before other tasks
/// // or the IO/timer driver get a chance to run. Instead, hand the waker
/// // to the scheduler, which wakes deferred tasks only after it has run
/// // out of ready tasks and polled the driver. …
/// context::defer(cx.waker());
/// ```
///
/// The self-wake below is the construction that comment warns against.
/// Its effect, read out of the same version's multi-thread scheduler: a
/// `wake_by_ref` from inside a poll reaches `schedule_local(…, is_yield:
/// false)` and lands in the worker's LIFO SLOT, which the worker re-polls
/// directly (up to `MAX_LIFO_POLLS_PER_TICK`, 3) rather than going round
/// the run queue; the timer and I/O drivers are polled in `maintenance`,
/// which runs only when `core.tick % event_interval == 0` — 61 by
/// default. So a timer wrapped around one of these walks is reached after
/// a bounded MULTIPLE of the yield interval, not at the first yield.
///
/// **`context::defer` is `pub(crate)` to tokio**, so the good version of
/// this is not reachable from a runtime-agnostic crate at all: the choice
/// is this or nothing. What the yield therefore buys is a BOUND on how
/// long the loop runs without reaching the scheduler, and with it the
/// ability for a cancellation to land at all — not a guarantee that it
/// lands promptly. That is a real improvement over a walk that never
/// yields, where the bound is the whole walk, and it is deliberately not
/// claimed as more.
///
/// The bound is verified only as far as "the future returns `Pending`
/// periodically", which is what the two yield tests measure. The
/// scheduler behaviour above is read from tokio's source at the pinned
/// version, not measured here.
async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(move |cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
}

/// The `Vec::with_capacity` hint for a bounded walk: the caller's
/// proposed size, CLAMPED to the cap, so nothing can name an allocation
/// the walk would not accept anyway.
///
/// The hint is a SEPARATE argument from the cap rather than derived from
/// it, because a caller may want to reserve LESS than it is willing to
/// accept — `get_bin_range` does exactly that, refusing at the bin
/// ceiling while reserving only what a frame read asks for. This clamp is
/// the backstop under whatever the caller chose, not the choice itself.
///
/// A pure named function, not an inline expression, because the clamp is
/// UNOBSERVABLE through any read this type offers — see the unit test.
fn alloc_hint(advertised: u64, cap: u64) -> usize {
    usize::try_from(advertised.min(cap)).unwrap_or(0)
}

/// The `Vec::with_capacity` proposal for a ranged bin read: the extent
/// the response declared, clamped to ONE FRAME. See
/// [`GranaryStore::get_bin_range`] for why the refusal bound and the
/// allocation bound are deliberately different numbers.
///
/// A pure named function rather than an inline `min`, so the unit
/// test can inspect the value directly. Through a read it is hard to
/// see: a response whose body does not match its declared extent — a
/// legal 256 MiB extent delivering a hundred bytes, say — is REFUSED,
/// and a body that does match leaves `collect_bounded` through its
/// closing `shrink_to_fit`, which shrinks the buffer toward its
/// length.
///
/// That makes the clamp MORE load-bearing, not less, and this is the part
/// worth being exact about: the buffer is reserved BEFORE the walk, and
/// the equality that refuses the response can only run AFTER it. A
/// hostile extent therefore still names one allocation, and this clamp is
/// the only thing bounding it. Only inspecting the value catches its
/// removal — hence the unit test.
fn range_alloc_hint(width: u64) -> u64 {
    width.min(u64::from(FRAME_COMP_MAX))
}

/// Walk a response body, aborting past `cap` bytes — the TRANSFER bound
/// (see [`GranaryStore::get_bounded`] for what it does and does not
/// cover). `hint` sizes the buffer and is itself clamped to `cap`, so an
/// advertised length cannot name an arbitrary allocation.
///
/// **`over_cap_kind` is the caller's, not this walk's.** What "past the
/// cap" MEANS differs by caller: [`GranaryStore::get_bounded`] means the
/// object exceeds its own object class's read cap
/// ([`RefusalKind::OverCap`]); [`GranaryStore::get_bin_range`] passes the
/// requested extent's own width as `cap`, so the identical byte-count
/// check there means the response outran the EXTENT it declared
/// ([`RefusalKind::Extent`]). One counting walk, two meanings, so the
/// kind travels as a parameter rather than being guessed from `cap`'s
/// value. The zero-progress refusal below carries no such parameter: an
/// empty-chunk flood means the same thing — no byte of progress — on
/// every caller.
///
/// The walk is chunk-by-chunk on purpose: `GetResult::bytes()` drains the
/// stream unconditionally and only then has a length to check, so a check
/// written on its result would run after the bytes had already arrived.
///
/// **This walk terminates without help from its caller.** Nonzero chunks
/// are bounded by `cap`, zero-length ones by [`ZERO_CHUNK_ALLOWANCE`], so
/// the loop runs a bounded number of times against any stream — at most
/// `cap + ZERO_CHUNK_ALLOWANCE + 2` iterations, the two extras being the
/// first chunk PAST each bound, which is the one that refuses.
///
/// **Terminating is not the same as being interruptible, and the bound
/// above is enormous.** `cap` is `BIN_MAX_BYTES` on the widest path, so
/// one-byte chunks make that 268 million iterations; the loop polls the
/// body directly, and a stream that answers `Poll::Ready` every time
/// never returns control to the executor, so a timer wrapped around this
/// future would never be polled and a task abort would never land. Hence
/// the periodic [`yield_once`] below — a local bound is what makes the
/// walk finite, and the yield is what keeps the thread reachable while it
/// runs.
async fn collect_bounded(
    r: object_store::GetResult,
    cap: u64,
    hint: u64,
    what: &'static str,
    key: &StorePath,
    over_cap_kind: RefusalKind,
) -> Result<Vec<u8>, RootStoreError> {
    let mut out = Vec::with_capacity(alloc_hint(hint, cap));
    // No `use futures_core::Stream` here, and none is missing: `poll_next`
    // is called on a trait OBJECT (`BoxStream` is `Pin<Box<dyn Stream>>`),
    // and a `dyn Trait` receiver carries its own principal trait's methods
    // into scope. Importing the trait anyway would be an unused import,
    // which CI denies — so this crate needs no futures dependency at all.
    let mut body = r.into_stream();
    let mut seen: u64 = 0;
    let mut empty: u32 = 0;
    let mut until_yield = BODY_YIELD_INTERVAL;
    while let Some(chunk) = std::future::poll_fn(|cx| body.as_mut().poll_next(cx)).await {
        // COOPERATIVE YIELD, for the reason `max_seq`'s loop has one and
        // the bounds above do NOT supply: they cap the bytes, not the
        // iterations, and a one-byte chunking multiplies the second by
        // the first. Counted over EVERY chunk including the empty ones —
        // the iteration is what costs the thread, and a zero-length chunk
        // costs the same iteration as any other.
        until_yield = until_yield.saturating_sub(1);
        if until_yield == 0 {
            until_yield = BODY_YIELD_INTERVAL;
            yield_once().await;
        }
        let chunk = chunk.map_err(|e| backend_err(&e))?;
        // THE ZERO-PROGRESS BOUND. An empty chunk cannot move `seen`, so
        // the byte cap below can never end a stream made only of them.
        if chunk.is_empty() {
            empty = empty.saturating_add(1);
            if empty > ZERO_CHUNK_ALLOWANCE {
                return Err(RootStoreError::RefusedResponse {
                    reason: format!(
                        "{what} at {key} made no progress: more than {ZERO_CHUNK_ALLOWANCE} \
                         zero-length chunks"
                    ),
                    kind: RefusalKind::NoProgress,
                });
            }
            continue;
        }
        seen = seen.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if seen > cap {
            return Err(RootStoreError::RefusedResponse {
                reason: format!(
                    "{what} at {key} streamed past the {cap}-byte cap (the advertised size was a \
                     lie; {seen} bytes seen)"
                ),
                kind: over_cap_kind,
            });
        }
        out.extend_from_slice(&chunk);
    }
    // THE BUFFER IS HANDED BACK EXACTLY SIZED, and the caller is why.
    //
    // The reservation above is a CLAMP, not a prediction: it is one frame
    // on the range path and the kind's cap elsewhere, and past it the
    // `Vec` grows by DOUBLING. So a body that runs one byte past the
    // reservation comes back in a buffer twice its length, and at the
    // declared maximum extent the measured factor is ~1.72×
    // (78 479 383 bytes in a 134 742 160-byte allocation).
    //
    // That gap is not a rounding detail to whoever holds the result. The
    // server moves this `Vec` into a response body, and
    // `Bytes::from(Vec<u8>)` reuses the allocation without shrinking
    // unless `len == capacity` exactly — so the overshoot stays resident
    // for as long as the transport takes to drain the response, which is
    // the client's pace and not the server's. Any accounting over those
    // buffers has to charge the CAPACITY, and removing the overshoot
    // where it is created is cheaper than charging for it.
    //
    // A no-op when the reservation was right, which is the ordinary case:
    // `shrink_to_fit` does nothing at `len == capacity`.
    out.shrink_to_fit();
    Ok(out)
}

/// The bin/meta half of the storage seam. Pure delegation: every rule
/// this trait states — content-addressing, `AlreadyExists`-is-success,
/// the pinned range semantic, `checked_volume` — is already carried by
/// the inherent methods, which is what makes the seam a description of
/// the adapter rather than a second implementation of it.
///
/// The inherent methods stay: `get_bin` is deliberately outside the
/// trait (no production caller yet), and inherent resolution wins at
/// every existing call site, so nothing here changes what they do.
impl<S: ObjectStore> BinStore for GranaryStore<S> {
    async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.put_bin(digest, bytes).await
    }

    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.put_meta(volume, id, bytes).await
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.get_meta(volume, id).await
    }

    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        self.get_bin_range(digest, offset, len).await
    }
}

impl<S: ObjectStore> RootStore for GranaryStore<S> {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        Self::checked_volume(volume)?;
        let opts = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        match self
            .inner
            .put_opts(&Self::root_key(volume, seq), bytes.into(), opts)
            .await
        {
            Ok(_) => Ok(()),
            // An existing object at this seq is EITHER another
            // writer's win OR our own landed first attempt — the
            // caller disambiguates with one get_root probe (the trait
            // contract carries the rule).
            Err(object_store::Error::AlreadyExists { .. }) => Err(RootStoreError::AlreadyExists),
            Err(e) => Err(backend_err(&e)),
        }
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        match self.get_root_bounded(volume, seq, ROOT_MAX_BYTES).await {
            Ok(b) => Ok(Some(b)),
            Err(RootStoreError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        Self::checked_volume(volume)?;
        // NO RANGE HEADER, and the download is bounded by the SIZE
        // GATE below instead. `CURRENT` is attacker-writable, so an
        // oversized replacement must not make every reader download it
        // whole before discovering it is garbage — but a RANGE is the
        // wrong instrument for that bound, because no byte range is
        // satisfiable on a ZERO-LENGTH representation (RFC 9110
        // §14.1.1) and a 0-byte object is as legitimate a plant as any
        // other garbage.
        //
        // Neither range form works on a real server.
        // `Bounded(0..21)` refuses CLIENT-side on a 0-byte object
        // (`InvalidGetRange::StartTooLarge`). `Suffix(21)` passes on
        // `InMemory`, which evaluates ranges client-side and clamps,
        // and fails SERVER-side, where the range is real. Measured
        // against MinIO: a suffix range on a zero-length object is
        // answered with `Content-Range: bytes 0--1/0`, which
        // `object_store` cannot parse, and a ranged `read_hint` returned
        // `Err(Backend("Failed to parse value for CONTENT_RANGE header"))`.
        // One 0-byte PUT by any bucket writer would
        // therefore wedge every reader's poll — the exact
        // wedge the advisory contract exists to prevent.
        // Client-side and server-side range semantics
        // diverge precisely at the degenerate sizes an
        // attacker chooses, so this path does not depend on
        // them at all.
        //
        // The size gate is strictly TIGHTER than a 21-byte range: the only
        // valid body is exactly SEQ_KEY_DIGITS bytes, so any other size is
        // `Missing` on the metadata alone and the body is not read — the
        // response is dropped after its headers rather than streamed. A valid
        // hint costs 20 bytes; the 304 revalidation (conditional hint
        // polling) costs none.
        //
        // THE SIZE GATE IS NOT ITSELF A BOUND, and the body walk
        // below is what makes this path bounded. The gate
        // compares the backend's ADVERTISED `meta.size`, so a
        // store that reports 20 for a larger body walks straight
        // through it — the advertisement is the lie.
        // `GetResult::bytes()` would then drain the whole body:
        // it bounds by NEITHER the requested range NOR the
        // advertised size, it passes the response length to
        // `collect_bytes` as a `Vec::with_capacity` hint and then
        // drains the stream unconditionally. `collect_bounded`
        // therefore walks the body chunk by chunk and stops at 20
        // bytes.
        //
        // The CORRECTNESS invariant never rested on the advertisement:
        // the strict parse below is the authority, and a dishonest
        // backend costs a reader bytes, never a wrong head.
        let opts = GetOptions {
            if_none_match: conditional_token(cached).map(str::to_owned),
            ..Default::default()
        };
        let key = Self::hint_key(volume);
        match self.inner.get_opts(&key, opts).await {
            Err(object_store::Error::NotModified { .. }) => Ok(HintRead::NotModified),
            Err(object_store::Error::NotFound { .. }) => Ok(HintRead::Missing),
            Err(e) => Err(backend_err(&e)),
            Ok(r) => {
                // THE SIZE GATE, before any body byte is fetched.
                if r.meta.size != SEQ_KEY_DIGITS as u64 {
                    return Ok(HintRead::Missing);
                }
                let token = HintToken(r.meta.e_tag.clone().unwrap_or_default());
                let cap = SEQ_KEY_DIGITS as u64;
                // The kind is unobserved either way: every
                // `RefusedResponse` from this walk degrades to `Missing`
                // below, by the advisory contract rather than by kind.
                // `OverCap` names what the check IS — the hint's own
                // exact-width cap — for whoever reads this in a debugger.
                let body =
                    match collect_bounded(r, cap, cap, "hint body", &key, RefusalKind::OverCap)
                        .await
                    {
                        Ok(b) => b,
                        // A body that outruns the cap is a body the strict
                        // parse would refuse anyway, so it degrades like any
                        // other unusable hint rather than surfacing an error
                        // — the advisory contract, applied to the one
                        // failure the advertisement can manufacture.
                        Err(RootStoreError::RefusedResponse { .. }) => {
                            return Ok(HintRead::Missing);
                        }
                        Err(e) => return Err(e),
                    };
                // Advisory contract: a body that fails the strict
                // parse (not UTF-8, non-digits) degrades to Missing —
                // an attacker-writable object must never wedge or
                // misdirect a refresh. Width is already gated above,
                // and `parse_hint_body` re-checks it: the two agree by
                // construction, and the parse stays the authority.
                match std::str::from_utf8(&body).ok().map(parse_hint_body) {
                    // Seq 0 parses (20 zero digits is a well-formed
                    // body) but names a root that can never exist —
                    // `root.rs` refuses seq 0 at both encode and
                    // decode. Handing it up as `Current` would make
                    // every reader spend a doomed `get_root(0)` before
                    // recovering, so it degrades here like any other
                    // unusable body. The advisory contract held either
                    // way (the probe misses and the reader lists); this
                    // makes the store layer stop emitting a value the
                    // format layer calls impossible.
                    Some(Ok(0)) => Ok(HintRead::Missing),
                    Some(Ok(seq)) => Ok(HintRead::Current { seq, token }),
                    _ => Ok(HintRead::Missing),
                }
            }
        }
    }

    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        Self::checked_volume(volume)?;
        // Unconditional overwrite: the hint is advisory, last writer
        // wins, and every successful publish repairs it. A conditional
        // update would add a failure mode with nothing to protect.
        self.inner
            .put(
                &Self::hint_key(volume),
                format_hint_body(seq).into_bytes().into(),
            )
            .await
            .map(|_| ())
            .map_err(|e| backend_err(&e))
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        self.max_listed_seq(volume, None).await
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.max_listed_seq(volume, Some(floor)).await
    }
}

impl<S: ObjectStore> GranaryStore<S> {
    async fn max_listed_seq(
        &self,
        volume: &str,
        floor: Option<u64>,
    ) -> Result<Option<u64>, RootStoreError> {
        Self::checked_volume(volume)?;
        // A STREAMING MAXIMUM with no truncation cap: there is no sound
        // cap to choose. `list_with_delimiter`, which
        // this replaced, accumulates every page into one `Vec` inside
        // `object_store` before a caller sees a single key
        // (`objects.extend(response.objects)` in its client listing
        // loop), so no cap applied here could have prevented it. Capping
        // the LISTING instead would have imposed an undocumented maximum
        // volume lifetime that two implementations could pick
        // differently, and a truncated listing would make `max_seq`
        // return a WRONG head rather than a slow one.
        //
        // THIS FUNCTION'S accumulation is O(1) — one `u64`, whatever the
        // volume's history. Scoped honestly: a given `ObjectStore` may
        // still buffer internally, and the pinned `InMemory` one collects
        // matching metadata before it returns its stream. Nothing here
        // can bound that.
        //
        // With a floor, the listing starts after the floor's canonical
        // key, so it walks only the keys above it.
        let prefix = StorePath::from(format!("root/{volume}"));
        // No delimiter, and none is wanted: this is a flat walk of the
        // keys under the volume's root prefix, which is exactly what
        // `list` gives. See the depth rule below for what that costs.
        let offset = floor.map(|seq| Self::root_key(volume, seq));
        let mut listing = match &offset {
            Some(offset) => self.inner.list_with_offset(Some(&prefix), offset),
            None => self.inner.list(Some(&prefix)),
        };
        let mut head: Option<u64> = None;
        let mut until_yield = LIST_YIELD_INTERVAL;
        while let Some(item) = std::future::poll_fn(|cx| listing.as_mut().poll_next(cx)).await {
            // COOPERATIVE YIELD. This loop has no cap and cannot have one
            // (see the paragraph above), so what it owes the runtime is
            // interruptibility: without this, a listing that never blocks
            // starves every other task, timeout and abort on the executor
            // until it ends. A countdown rather than a modulus keeps the
            // arithmetic panic-free on any counter width.
            until_yield = until_yield.saturating_sub(1);
            if until_yield == 0 {
                until_yield = LIST_YIELD_INTERVAL;
                yield_once().await;
            }
            let meta = item.map_err(|e| backend_err(&e))?;
            // THE DEPTH RULE. `list` is FLAT AND RECURSIVE — it returns
            // every descendant of the prefix, not the direct children a
            // delimiter listing gives. A root lives at exactly ONE
            // component below `root/{volume}`, so anything deeper is not
            // a root however well-formed its last segment looks:
            // `root/{volume}/junk/00000000000000000099` would otherwise
            // parse as seq 99 and become a head that no `get_root` can
            // fetch. Checking the FILENAME alone does not catch this.
            let Some(seq) = listed_root_seq(&prefix, &meta.location) else {
                continue;
            };
            // A raw key such as the floor's canonical key with a
            // trailing slash can sort after the offset and parse as floor.
            if floor.is_none_or(|floor| seq > floor) {
                head = Some(head.map_or(seq, |best: u64| best.max(seq)));
            }
        }
        Ok(head)
    }
}

/// Parse a listed path as a canonical root directly below the volume prefix.
#[must_use]
pub fn listed_root_seq(prefix: &StorePath, location: &StorePath) -> Option<u64> {
    let mut below = location.prefix_match(prefix)?;
    let (Some(name), None) = (below.next(), below.next()) else {
        return None;
    };
    let seq = parse_hint_body(name.as_ref()).ok()?;
    // Zero cannot decode as a root, and MAX is reserved.
    (seq != 0 && seq != u64::MAX).then_some(seq)
}

#[cfg(test)]
mod tests;
