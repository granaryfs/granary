// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::fetcher` — the windowed, budgeted,
//! deduplicating grain fetcher: admission bounded by count and bytes,
//! with AIMD backpressure and one delayed re-poll on `Unavailable`.
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use std::collections::BTreeMap as StdBTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::cache::CacheOrigin;
use crate::http_store::SEAM_DEADLINE_BASE;

// ---------------------------------------------------------- fixtures

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the crate's lint policy bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
            hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
            and nothing else (`granary-fetcher-test-<pid>-<counter>` under the temp dir, created and removed by \
            this fixture), and it is load-bearing for correctness there: the counter beside it is \
            per-process, and every test binary runs in its own process, so without the pid two concurrent \
            runs generate the same name and share one directory. It reaches no hashed or signed value, and \
            nothing under test reads it: the rows here assert which wire calls were made and what the cache \
            holds afterwards, and neither is derived from the directory's name"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-fetcher-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn origin() -> CacheOrigin {
    CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x11; 32],
        root_key_id: None,
    }
}

fn fresh_cache(dir: &ScratchDir) -> Cache {
    Cache::open(&dir.0, 1024 * 1024 * 1024, &origin()).unwrap_or_else(|e| panic!("{e}"))
}

/// The third element is `payload`'s own length — the declared
/// `unpacked_len` a real caller would read off the `GrainRef`
/// naming this grain, always returned alongside the frame so every
/// site building a `Want::BinRange` from it charges admission at
/// the same figure this grain will actually decompress to.
fn frame_for(codec: &mut GrainCodec, payload: &[u8]) -> (GrainId, Vec<u8>, u32) {
    let id = GrainId::of(payload);
    let frame = codec
        .compress_grain(payload)
        .unwrap_or_else(|e| panic!("{e}"));
    let unpacked_len = u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}"));
    (id, frame, unpacked_len)
}

/// A future that returns `Pending` exactly once (re-arming its own
/// waker) before resolving. Used by [`CountingSeam`] to force a
/// real overlap window between admission and completion — without
/// it every call would resolve on its first poll, and the
/// multiplexer's own admission bookkeeping (not the seam) would be
/// the only thing a concurrency test could ever exercise.
#[derive(Debug, Default)]
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// A fake seam + counting stub: a deliberately dumb `BinStore`
/// (mirroring `binstore.rs`'s `FakeBins` and
/// `tests/seam_drivable.rs`'s `FakeRemote`) that additionally
/// counts wire calls, tracks concurrent-call high-water, and can be
/// told to shed its next `n` calls with `Unavailable` regardless of
/// which want they answer.
#[derive(Debug, Default)]
struct CountingSeam {
    bins: Mutex<StdBTreeMap<[u8; DIGEST_LEN], Vec<u8>>>,
    metas: Mutex<StdBTreeMap<(String, GrainId), Vec<u8>>>,
    concurrent: AtomicUsize,
    high_water: AtomicUsize,
    shed_remaining: AtomicUsize,
    /// Timeout fixture: the next `n` calls answer
    /// `RootStoreError::Elapsed` instead of `Unavailable` —
    /// a DIFFERENT remote-error shape, checked FIRST so a
    /// test can pin that the AIMD machinery below reacts to
    /// neither the window nor the re-poll on this one.
    elapsed_remaining: AtomicUsize,
    bin_calls: Mutex<StdBTreeMap<[u8; DIGEST_LEN], usize>>,
    meta_calls: Mutex<StdBTreeMap<(String, GrainId), usize>>,
}

impl CountingSeam {
    fn seed_bin(&self, digest: [u8; DIGEST_LEN], bytes: Vec<u8>) {
        self.bins
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .insert(digest, bytes);
    }

    fn seed_meta(&self, volume: &str, id: GrainId, bytes: Vec<u8>) {
        self.metas
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .insert((volume.to_owned(), id), bytes);
    }

    /// Shed the next `n` calls, on ANY want, with `Unavailable`.
    fn shed(&self, n: usize) {
        self.shed_remaining.store(n, Ordering::SeqCst);
    }

    /// Consume one shed token if any remain.
    fn take_shed(&self) -> bool {
        self.shed_remaining
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n > 0).then(|| n - 1)
            })
            .is_ok()
    }

    /// Answer the next `n` calls, on ANY want, with
    /// `RootStoreError::Elapsed` — a wedged-peer shape, never the
    /// `Unavailable` congestion signal.
    fn shed_elapsed(&self, n: usize) {
        self.elapsed_remaining.store(n, Ordering::SeqCst);
    }

    /// Consume one elapsed token if any remain.
    fn take_shed_elapsed(&self) -> bool {
        self.elapsed_remaining
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n > 0).then(|| n - 1)
            })
            .is_ok()
    }

    fn begin(&self) {
        let now = self.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
        self.high_water.fetch_max(now, Ordering::SeqCst);
    }

    fn end(&self) {
        self.concurrent.fetch_sub(1, Ordering::SeqCst);
    }

    fn high_water(&self) -> usize {
        self.high_water.load(Ordering::SeqCst)
    }

    fn bin_call_count(&self, digest: &[u8; DIGEST_LEN]) -> usize {
        self.bin_calls
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .get(digest)
            .copied()
            .unwrap_or(0)
    }

    fn meta_call_count(&self, volume: &str, id: &GrainId) -> usize {
        self.meta_calls
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .get(&(volume.to_owned(), *id))
            .copied()
            .unwrap_or(0)
    }
}

impl BinStore for CountingSeam {
    async fn put_bin(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        unimplemented!("the fetcher never writes")
    }

    async fn put_meta(
        &self,
        _volume: &str,
        _id: &GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        unimplemented!("the fetcher never writes")
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.begin();
        {
            let mut calls = self.meta_calls.lock().unwrap_or_else(|e| panic!("{e}"));
            *calls.entry((volume.to_owned(), *id)).or_insert(0) += 1;
        }
        YieldOnce::default().await;
        let result = if self.take_shed_elapsed() {
            Err(RootStoreError::Elapsed {
                operation: "GET meta",
                after: SEAM_DEADLINE_BASE,
            })
        } else if self.take_shed() {
            Err(RootStoreError::Unavailable {
                operation: "GET meta",
                status: 503,
            })
        } else {
            self.metas
                .lock()
                .unwrap_or_else(|e| panic!("{e}"))
                .get(&(volume.to_owned(), *id))
                .cloned()
                .ok_or(RootStoreError::NotFound)
        };
        self.end();
        result
    }

    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        _offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        self.begin();
        {
            let mut calls = self.bin_calls.lock().unwrap_or_else(|e| panic!("{e}"));
            *calls.entry(*digest).or_insert(0) += 1;
        }
        YieldOnce::default().await;
        let result = if self.take_shed_elapsed() {
            Err(RootStoreError::Elapsed {
                operation: "GET bin",
                after: SEAM_DEADLINE_BASE,
            })
        } else if self.take_shed() {
            Err(RootStoreError::Unavailable {
                operation: "GET bin",
                status: 503,
            })
        } else {
            self.bins
                .lock()
                .unwrap_or_else(|e| panic!("{e}"))
                .get(digest)
                .map(|bytes| bytes.iter().take(len as usize).copied().collect())
                .ok_or(RootStoreError::NotFound)
        };
        self.end();
        result
    }
}

// -------------------------------------------------------------- tests

/// Value pins — the behavioural row pins the numbers themselves,
/// not merely relations between them.
#[test]
fn the_window_constants_are_the_measured_profile() {
    assert_eq!(FETCH_WINDOW, 32);
    assert_eq!(FETCH_INFLIGHT_BYTES, 67_108_864);
    assert_eq!(UNAVAILABLE_RETRY_DELAY, Duration::from_millis(500));
    assert_eq!(WINDOW_FLOOR, 4);
    assert_eq!(crate::http_store::H2_STREAM_WINDOW, 2 * 1024 * 1024);
    assert_eq!(crate::http_store::H2_CONN_WINDOW, 64 * 1024 * 1024);
}

/// The largest legal construction that forces the BYTE bound to
/// bind before the stream window: a want's `comp_len` is refused
/// before any wire call once it exceeds `FRAME_COMP_MAX`
/// (8,421,385 bytes, ~8.03 MiB), so 8 MiB is the biggest admissible
/// round size (8,388,608 < 8,421,385) — and
/// `FETCH_INFLIGHT_BYTES` / 8 MiB is exactly 8, far below
/// `FETCH_WINDOW`.
#[tokio::test]
async fn the_window_never_exceeds_count_or_bytes() {
    const WANT_BYTES: u32 = 8 * 1024 * 1024;
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);

    let mut wants = Vec::new();
    for i in 0u16..12 {
        let digest = *GrainId::of(format!("digest-{i}").as_bytes()).digest();
        seam.seed_bin(digest, vec![0xAB; WANT_BYTES as usize]);
        wants.push(Want::BinRange {
            id: GrainId::of(format!("id-{i}").as_bytes()),
            digest,
            offset: 0,
            comp_len: WANT_BYTES,
            unpacked_len: WANT_BYTES,
        });
    }

    let results = fetcher
        .fetch(Some(&mut cache), wants)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(results.len(), 12, "the whole batch must still drain");
    for outcome in results.values() {
        // 8 MiB of filler is not a zstd frame: every want must fail
        // AT THE CODEC — any other variant here would mean a want
        // was answered by something other than its own seeded bytes.
        assert!(
            matches!(outcome, Err(FetchError::Codec(_))),
            "expected a codec refusal, got {outcome:?}"
        );
    }
    assert_eq!(
        seam.high_water(),
        8,
        "the byte bound (64 MiB / 8 MiB) must bind before the 32-stream window"
    );
    assert_eq!(
        fetcher.state.window, FETCH_WINDOW,
        "recovery is capped AT the full window — completions past it must not grow it further"
    );
}

/// The other admission gate, observed at the seam: wants far too
/// small for the byte bound to bind leave the stream count as the
/// only thing holding concurrency down.
#[tokio::test]
async fn the_count_gate_binds_when_bytes_do_not() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);

    let mut wants = Vec::new();
    for i in 0u16..40 {
        let payload = format!("tiny grain {i}").into_bytes();
        let (id, frame, unpacked_len) = frame_for(&mut codec, &payload);
        let digest = *GrainId::of(format!("count-gate bin {i}").as_bytes()).digest();
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        seam.seed_bin(digest, frame);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len,
        });
    }

    let results = fetcher
        .fetch(Some(&mut cache), wants)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(results.len(), 40);
    assert_eq!(
        seam.high_water(),
        FETCH_WINDOW,
        "with bytes nowhere near the budget, the stream count is the binding gate"
    );
}

/// **What this pins: admission charges a `BinRange` at its declared
/// `unpacked_len`, never `comp_len`.** Thirty-two UNIQUE,
/// highly-compressible grains (all-zero payload, one unique tag per
/// grain, so each content-addresses distinctly — `comp_len`
/// collapses to a handful of bytes each) all declare exactly
/// [`GRAIN_UNPACKED_MAX`]. Charging `comp_len` here would admit the
/// WHOLE window at once — thirty-two wants costing next to nothing
/// against the byte budget, `FETCH_WINDOW` binding instead of the
/// byte gate — a bound `comp_len` could never enforce regardless of
/// content, since highly-compressible content is exactly the shape
/// that defeats a compressed-size proxy for resident cost. Charging
/// `unpacked_len`, only eight fit (`FETCH_INFLIGHT_BYTES` /
/// `GRAIN_UNPACKED_MAX` = 8) before the byte gate closes admission.
///
/// The first grain is shed once (`CountingSeam::shed`), so its own
/// completion lands strictly after the other seven admitted
/// alongside it — the "one held-back want behind an otherwise live
/// fleet" shape a synchronous completion sweep would otherwise
/// process several conversions within, all before this held-back
/// want's own next admission check could ever see the true running
/// total.
#[tokio::test]
async fn a_compressible_fleet_is_charged_at_its_declared_size() {
    const GRAINS: usize = 32;

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    let mut wants = Vec::with_capacity(GRAINS);
    for i in 0..GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let id = GrainId::of(&payload);
        let frame = codec
            .compress_grain(&payload)
            .unwrap_or_else(|e| panic!("{e}"));
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        let mut digest = [0_u8; DIGEST_LEN];
        digest[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        seam.seed_bin(digest, frame);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
    }
    // The first grain's completion is delayed, so its own admission
    // slot stays open while the other seven admitted alongside it
    // race ahead — the shape that lets a synchronous completion
    // sweep process several conversions in one pass.
    seam.shed(1);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let results = fetcher
        .fetch(Some(&mut cache), wants)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(results.len(), GRAINS);
    for outcome in results.values() {
        match outcome {
            Ok(bytes) => assert_eq!(bytes.len(), GRAIN_UNPACKED_MAX as usize),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    let wave = FETCH_INFLIGHT_BYTES / u64::from(GRAIN_UNPACKED_MAX);
    assert_eq!(
        u64::try_from(seam.high_water()).unwrap_or(u64::MAX),
        wave,
        "charged at their declared 8 MiB each, only FETCH_INFLIGHT_BYTES / \
         GRAIN_UNPACKED_MAX = 8 of these thirty-two may ever be concurrently \
         admitted — never all 32, which is what charging comp_len (a handful \
         of bytes for this highly-compressible content) would have let \
         through instead"
    );
    assert!(
        u64::try_from(seam.high_water()).unwrap_or(u64::MAX) * u64::from(GRAIN_UNPACKED_MAX)
            <= FETCH_INFLIGHT_BYTES + u64::from(GRAIN_UNPACKED_MAX),
        "peak concurrently-resident bytes (admission high-water times each \
         want's declared size) must stay within one want's slack of the \
         budget — never the ~248 MiB (31 grains' worth) a comp_len-charged \
         admission would have let all admit, then convert upward, into"
    );
}

/// **A declared-size charge only bounds residency if a completion
/// that BREACHES it is refused, not merely under-charged.**
/// Thirty-two unique grains, each a REAL 8 MiB payload (so `id` is
/// the true hash of the true content), but each want DECLARES
/// `unpacked_len: 1` — a manifest field independent of `id`: the id
/// fixes what the bytes ARE (and therefore their true size), never
/// what a separate declaration claims about them ahead of fetching.
/// Declared at one byte, all thirty-two admit on the count gate
/// alone (`FETCH_WINDOW` exactly fits them; the byte gate — 32 × 1
/// byte — never binds) — the same shape a highly-compressible fleet
/// exploited before admission charged declared size at all.
///
/// The first grain is shed once, so its own completion lands
/// strictly after the other thirty-one — which, once admitted,
/// decompress to their REAL 8 MiB each and each individually breach
/// their own one-byte charge. Every one of them must be REFUSED
/// (`FetchError::OverDeclared`) before its bytes could ever reach a
/// caller's own holdback, or a caller buffering completions out of
/// order — exactly what the delayed first grain forces here — would
/// park all thirty-one real 8 MiB payloads before the delayed one
/// ever arrives to release anything.
#[tokio::test]
async fn a_grain_that_decompresses_past_its_declared_size_never_parks() {
    const GRAINS: usize = 32;
    const LYING_DECLARED_LEN: u32 = 1;

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    let mut wants = Vec::with_capacity(GRAINS);
    let mut ids = Vec::with_capacity(GRAINS);
    for i in 0..GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let id = GrainId::of(&payload);
        let frame = codec
            .compress_grain(&payload)
            .unwrap_or_else(|e| panic!("{e}"));
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        let mut digest = [0_u8; DIGEST_LEN];
        digest[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        seam.seed_bin(digest, frame);
        ids.push(id);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len: LYING_DECLARED_LEN,
        });
    }
    seam.shed(1);

    let mut held_bytes_sum: u64 = 0;
    let mut peak_held_bytes: u64 = 0;
    let mut seen_over_declared: BTreeSet<GrainId> = BTreeSet::new();

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    fetcher
        .fetch_streaming(
            Some(&mut cache),
            wants.into_iter().map(Ok::<Want, std::convert::Infallible>),
            |id, result, charged| {
                assert!(
                    charged,
                    "{id}: every want here admits — the byte gate never binds at a \
                 one-byte declared charge"
                );
                match result {
                    // A caller buffering an out-of-order completion —
                    // exactly what the delayed first grain forces here.
                    // Reached only if the guard this test pins is
                    // missing: with it, every one of these thirty-two
                    // is an Err below instead.
                    Ok(bytes) => {
                        held_bytes_sum += bytes.len() as u64;
                        peak_held_bytes = peak_held_bytes.max(held_bytes_sum);
                        0
                    }
                    Err(FetchError::OverDeclared { declared, got, .. }) => {
                        assert_eq!(declared, LYING_DECLARED_LEN);
                        assert_eq!(got, GRAIN_UNPACKED_MAX as usize);
                        seen_over_declared.insert(id);
                        0
                    }
                    Err(other) => panic!("{id}: expected OverDeclared, got {other:?}"),
                }
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        seen_over_declared.len(),
        GRAINS,
        "every one of the thirty-two lying wants must surface OverDeclared — \
         a manifest declaring less than a grain's real decompressed size is \
         always a lie, never legitimate content"
    );
    assert_eq!(
        peak_held_bytes, 0,
        "a lying declared size must never let a single grain's bytes reach a \
         caller's holdback at all — finish()'s own guard refuses every one of \
         these before this callback could ever see an Ok"
    );
    assert!(
        held_bytes_sum <= FETCH_INFLIGHT_BYTES + u64::from(GRAIN_UNPACKED_MAX),
        "resident bytes {held_bytes_sum} must stay within one want's slack of \
         the budget — never the ~248 MiB (31 real grains' worth) an unguarded \
         finish() would have let this callback buffer"
    );
}

/// The second `Unavailable` IS the congestion signal, so the
/// completion that surfaces it earns no +1 — the window stays at
/// the halved value it forced.
#[tokio::test]
async fn a_second_unavailable_leaves_the_window_halved() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let digest = [0xA1; DIGEST_LEN];
    let id = GrainId::of(b"shed twice, stay cautious");
    seam.shed(2);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let results = fetcher
        .fetch(
            Some(&mut cache),
            [Want::BinRange {
                id,
                digest,
                offset: 0,
                comp_len: 8,
                unpacked_len: 8,
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert!(
        matches!(
            results.get(&id),
            Some(Err(FetchError::Remote(RootStoreError::Unavailable { .. })))
        ),
        "the second Unavailable surfaces"
    );
    assert_eq!(
        fetcher.state.window,
        FETCH_WINDOW / 2,
        "halved on the shed and NOT regrown by the completion that surfaced it"
    );
}

/// The AIMD machinery reacts to `Unavailable`
/// SPECIFICALLY — [`sheds`] matches nothing else — so a
/// `RootStoreError::Elapsed` from a want rides the generic
/// remote-error path with NO window signal and NO bounded re-poll.
/// A single shed token, unlike the `Unavailable` row above's two: an
/// `Unavailable` earns one bounded re-poll before it can surface, so
/// pinning "no re-poll" needs the FIRST answer to already be the one
/// that surfaces, which is what one `Elapsed` token gives directly
/// (a second would only prove the SAME thing twice, at a re-poll
/// this shape never takes).
#[tokio::test]
async fn an_elapsed_want_neither_repolls_nor_touches_the_window() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let digest = [0xA2; DIGEST_LEN];
    let id = GrainId::of(b"elapsed rides the generic path");
    seam.shed_elapsed(1);

    // BELOW the cap, deliberately: a fresh fetcher starts at
    // `FETCH_WINDOW`, where `(window + 1).min(FETCH_WINDOW)` equals
    // `window` and "did not move" cannot be told apart from
    // "grew, capped". From the floor, an Elapsed that wrongly
    // earned the answer's +1 is visible.
    let mut fetch_state = FetchState {
        window: WINDOW_FLOOR,
        codec: GrainCodec::new().unwrap_or_else(|e| panic!("{e}")),
        counters: ReadPathCounters::default(),
        metrics: None,
        phase: crate::CachePhase::Startup,
    };
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let window_before = fetcher.state.window;
    let results = fetcher
        .fetch(
            Some(&mut cache),
            [Want::BinRange {
                id,
                digest,
                offset: 0,
                comp_len: 8,
                unpacked_len: 8,
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert!(
        matches!(
            results.get(&id),
            Some(Err(FetchError::Remote(RootStoreError::Elapsed { .. })))
        ),
        "an Elapsed remote error must surface as itself, got {:?}",
        results.get(&id)
    );
    assert_eq!(
        seam.bin_call_count(&digest),
        1,
        "no bounded re-poll: Elapsed is not the Unavailable congestion signal `sheds` matches"
    );
    assert_eq!(
        fetcher.state.window, window_before,
        "the window must not move on an Elapsed want — a timeout is not the \
         congestion signal (no halving) and not an answer (no +1)"
    );
}

/// The floor holds under a shed, and a re-poll that SUCCEEDS still
/// earns its +1 from there.
#[tokio::test]
async fn a_shed_at_the_floor_recovers_by_one() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let (id, frame, unpacked_len) = frame_for(&mut codec, b"floored");
    let digest = [0xB2; DIGEST_LEN];
    let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    seam.seed_bin(digest, frame);
    seam.shed(1);

    let mut fetch_state = FetchState {
        window: WINDOW_FLOOR,
        codec: GrainCodec::new().unwrap_or_else(|e| panic!("{e}")),
        counters: ReadPathCounters::default(),
        metrics: None,
        phase: crate::CachePhase::Startup,
    };
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let results = fetcher
        .fetch(
            Some(&mut cache),
            [Want::BinRange {
                id,
                digest,
                offset: 0,
                comp_len,
                unpacked_len,
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    match results.get(&id) {
        Some(Ok(bytes)) => assert_eq!(bytes, b"floored"),
        other => panic!("expected the re-poll to complete, got {other:?}"),
    }
    assert_eq!(seam.bin_call_count(&digest), 2);
    assert_eq!(
        fetcher.state.window,
        WINDOW_FLOOR + 1,
        "halving at the floor stays at the floor; the successful completion adds one"
    );
}

/// `FetchState` was split out of `Fetcher` for exactly one reason
/// (see the type's own doc comment): the AIMD window and the codec
/// must SURVIVE across `Fetcher` LIFETIMES, because a FUSE daemon
/// builds a fresh per-call `Fetcher` on every callback while
/// `FetchState` lives on in the daemon across all of them. Prove
/// that survival directly: shed through fetcher A over a shared
/// `FetchState` so the window halves (reusing
/// `a_second_unavailable_leaves_the_window_halved`'s two-shed-token
/// fixture, so the halved value is not itself regrown by the
/// completion that produced it), drop fetcher A, build fetcher B
/// over the SAME `FetchState`, and check the halved value is still
/// there rather than reset to `FETCH_WINDOW`. Neither
/// `Fetcher::new` resetting the window nor a `Drop` impl on
/// `Fetcher` that reset it would be caught by any other test in
/// this module — both would still pass every single-`Fetcher` shed
/// test above, because none of them ever builds a second `Fetcher`
/// over one `FetchState`.
#[tokio::test]
async fn the_window_survives_a_fresh_fetcher_over_the_same_state() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let digest = [0xB4; DIGEST_LEN];
    let id = GrainId::of(b"the window outlives the fetcher that halved it");
    seam.shed(2);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));

    {
        let mut fetcher_a = Fetcher::new(&seam, &mut fetch_state);
        let results = fetcher_a
            .fetch(
                Some(&mut cache),
                [Want::BinRange {
                    id,
                    digest,
                    offset: 0,
                    comp_len: 8,
                    unpacked_len: 8,
                }],
            )
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(
            matches!(
                results.get(&id),
                Some(Err(FetchError::Remote(RootStoreError::Unavailable { .. })))
            ),
            "two shed tokens must surface as the second Unavailable, got {:?}",
            results.get(&id)
        );
        assert_eq!(
            fetcher_a.state.window,
            FETCH_WINDOW / 2,
            "the shed must halve the window before fetcher A is dropped"
        );
        // `fetcher_a` (and its borrow of `fetch_state`) drops here.
    }

    let fetcher_b = Fetcher::new(&seam, &mut fetch_state);
    assert_eq!(
        fetcher_b.state.window,
        FETCH_WINDOW / 2,
        "a fresh Fetcher built over the SAME FetchState must inherit the \
         halved window, not FETCH_WINDOW — this is the exact boundary \
         FetchState was extracted to survive"
    );
}

/// The cache-first rule, meta half: the second fetch of the same
/// meta object is served from disk.
#[tokio::test]
async fn a_meta_hit_never_touches_the_wire() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let bytes = b"a cached meta object".to_vec();
    let id = GrainId::of(&bytes);
    seam.seed_meta("vol", id, bytes.clone());

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let want = || Want::Meta {
        volume: "vol".to_owned(),
        id,
    };
    for run in 0..2u8 {
        let results = fetcher
            .fetch(Some(&mut cache), [want()])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        match results.get(&id) {
            Some(Ok(got)) => assert_eq!(got, &bytes),
            other => panic!("run {run}: expected Ok, got {other:?}"),
        }
    }
    assert_eq!(
        seam.meta_call_count("vol", &id),
        1,
        "the second run is a cache hit — no wire call"
    );
}

/// The meta path's ONLY integrity gate: bytes that do not hash to
/// the id that named them fail the want — and never enter the cache.
#[tokio::test]
async fn a_corrupt_meta_fails_verification() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let bytes = b"the actual meta bytes".to_vec();
    let claimed = GrainId::of(b"an id the bytes do not hash to");
    seam.seed_meta("vol", claimed, bytes);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let want = || Want::Meta {
        volume: "vol".to_owned(),
        id: claimed,
    };
    for _ in 0..2u8 {
        let results = fetcher
            .fetch(Some(&mut cache), [want()])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        match results.get(&claimed) {
            Some(Err(FetchError::Corrupt { id })) => assert_eq!(*id, claimed),
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }
    assert_eq!(
        seam.meta_call_count("vol", &claimed),
        2,
        "corrupt bytes never enter the cache — the second run goes back to the wire"
    );
}

/// A bin shorter than the extent claims fails BY LENGTH, with the
/// true counts — never mislabelled as a codec failure.
#[tokio::test]
async fn a_short_extent_is_refused_before_the_codec() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let (id, frame, unpacked_len) = frame_for(&mut codec, b"short extent probe");
    let digest = [0xC3; DIGEST_LEN];
    let claimed = u32::try_from(frame.len() + 1).unwrap_or_else(|e| panic!("{e}"));
    let stored = frame.len();
    let seam = CountingSeam::default();
    seam.seed_bin(digest, frame);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let results = fetcher
        .fetch(
            Some(&mut cache),
            [Want::BinRange {
                id,
                digest,
                offset: 0,
                comp_len: claimed,
                unpacked_len,
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    match results.get(&id) {
        Some(Err(FetchError::ShortExtent { want, got, .. })) => {
            assert_eq!(*want, claimed);
            assert_eq!(*got, stored);
        }
        other => panic!("expected ShortExtent, got {other:?}"),
    }
}

/// A batch shed in its ENTIRETY: each want's first shed halves the
/// window independently, compounding to the floor — and the
/// surfacing completions of an all-shed wave must not climb it
/// back. Here every re-poll succeeds, so the floor recovers by
/// exactly one per completed want: 4 + 8 = 12.
#[tokio::test]
async fn a_fully_shed_batch_compounds_to_the_floor() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);

    let mut wants = Vec::new();
    let mut digests = Vec::new();
    for i in 0u8..8 {
        let payload = vec![0x50, i];
        let (id, frame, unpacked_len) = frame_for(&mut codec, &payload);
        let digest = [0xD0 + i; DIGEST_LEN];
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        seam.seed_bin(digest, frame);
        digests.push(digest);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len,
        });
    }
    // Every first attempt sheds; every re-poll finds the seam
    // recovered.
    seam.shed(8);

    let results = fetcher
        .fetch(Some(&mut cache), wants)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(results.len(), 8);
    for outcome in results.values() {
        assert!(outcome.is_ok(), "expected Ok, got {outcome:?}");
    }
    for digest in &digests {
        assert_eq!(
            seam.bin_call_count(digest),
            2,
            "one shed attempt plus exactly one re-poll per want"
        );
    }
    assert_eq!(
        fetcher.state.window,
        WINDOW_FLOOR + 8,
        "eight independent halvings compound to the floor; eight successful \
         completions then recover exactly eight slots"
    );
}

/// The meta admission charge, observed at the seam: each meta want
/// reserves `META_MAX_BYTES`, so 64 MiB admits exactly four at once.
#[tokio::test]
async fn meta_wants_charge_the_read_cap() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let mut wants = Vec::new();
    for i in 0u8..6 {
        let bytes = vec![i; 32];
        let id = GrainId::of(&bytes);
        seam.seed_meta("vol", id, bytes);
        wants.push(Want::Meta {
            volume: "vol".to_owned(),
            id,
        });
    }

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let results = fetcher
        .fetch(Some(&mut cache), wants)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(results.len(), 6);
    assert_eq!(
        seam.high_water(),
        4,
        "FETCH_INFLIGHT_BYTES / META_MAX_BYTES = 4 concurrent metas, never more"
    );
}

#[tokio::test]
async fn duplicate_wants_fetch_once() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let (id, frame, unpacked_len) = frame_for(&mut codec, b"duplicate payload");
    let digest = [0x11; DIGEST_LEN];
    let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    seam.seed_bin(digest, frame);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let metrics = crate::metrics::tests::metrics();
    fetch_state.set_metrics(Some(metrics.clone()));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let want = || Want::BinRange {
        id,
        digest,
        offset: 0,
        comp_len,
        unpacked_len,
    };
    let results = fetcher
        .fetch(Some(&mut cache), [want(), want()])
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(results.len(), 1, "two wants, one id, one map entry");
    match results.get(&id) {
        Some(Ok(bytes)) => assert_eq!(bytes, b"duplicate payload"),
        other => panic!("expected Ok, got {other:?}"),
    }
    assert_eq!(
        seam.bin_call_count(&digest),
        1,
        "single-flighted: one wire fetch for two identical wants"
    );
    let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"hit\"} 0\n"),
        "{output}"
    );
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"miss\"} 1\n"),
        "{output}"
    );
}

/// The FALSIFIER for the claim that serial mount reads explain the measured cold-read gap.
///
/// `mount.rs`'s `read` path fetches a ONE-element array, so however
/// wide [`FETCH_WINDOW`] is, a mount read can never seat more than one
/// slot. This row asserts that shape at the fetcher, where it is
/// deterministic, instead of inferring it from a venue timing.
///
/// Its partner below is the POSITIVE CONTROL: without one, "the
/// high-water mark is 1" is equally consistent with a counter that is
/// stuck at 1, and this row would pass for the wrong reason.
#[tokio::test]
async fn a_one_want_fetch_seats_exactly_one_slot() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let (id, frame, unpacked_len) = frame_for(&mut codec, b"one want");
    let digest = [0x51; DIGEST_LEN];
    let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    seam.seed_bin(digest, frame);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    {
        let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
        let got = fetcher
            .fetch(
                Some(&mut cache),
                [Want::BinRange {
                    id,
                    digest,
                    offset: 0,
                    comp_len,
                    unpacked_len,
                }],
            )
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        match got.get(&id) {
            Some(Ok(bytes)) => assert_eq!(bytes, b"one want"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    assert_eq!(
        fetch_state.inflight_high_water(),
        1,
        "a one-element fetch — the shape mount.rs's read path uses — must \
         never seat more than one slot, whatever FETCH_WINDOW is"
    );
}

/// POSITIVE CONTROL for the row above: the counter can report more
/// than one, so `== 1` there means the fetch was narrow rather than
/// the instrument being dead.
#[tokio::test]
async fn a_batched_fetch_seats_every_want_in_one_pass() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    let mut wants = Vec::new();
    let mut ids = Vec::new();
    for (n, body) in [b"aaaa", b"bbbb", b"cccc", b"dddd"].into_iter().enumerate() {
        let (id, frame, unpacked_len) = frame_for(&mut codec, body);
        let mut digest = [0x60; DIGEST_LEN];
        digest[0] = u8::try_from(n).unwrap_or_else(|e| panic!("{e}"));
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        seam.seed_bin(digest, frame);
        ids.push(id);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len,
        });
    }

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    {
        let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
        let got = fetcher
            .fetch(Some(&mut cache), wants)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        for id in &ids {
            assert!(matches!(got.get(id), Some(Ok(_))), "want {id:?} failed");
        }
    }

    assert_eq!(
        fetch_state.inflight_high_water(),
        4,
        "four distinct wire wants are all admitted in one pass — the \
         window is {FETCH_WINDOW}, so nothing here should be held back"
    );
}

/// The read-phase high-water mark must exclude the preamble's
/// multi-want batch, or a serial content read looks concurrent.
///
/// A mount builds ONE `FetchState` for the preamble and then moves
/// it into the session, and the preamble's structure-node prefetch
/// submits a MULTI-want batch. Without arming at the phase boundary,
/// a mount's teardown reading reports the PREAMBLE's width — and
/// under this instrument's own falsification rule an ordinary cold
/// mount would then read as refuting the serial-read-path claim.
/// This row reproduces that shape: a wide batch, then arm, then a
/// one-want fetch, and the reading must be about the second.
#[tokio::test]
async fn arming_the_read_phase_discards_the_preamble_width() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    // The "preamble": a four-want batch through the same state.
    let mut wants = Vec::new();
    for (n, body) in [b"pre1", b"pre2", b"pre3", b"pre4"].into_iter().enumerate() {
        let (id, frame, unpacked_len) = frame_for(&mut codec, body);
        let mut digest = [0x70; DIGEST_LEN];
        digest[0] = u8::try_from(n).unwrap_or_else(|e| panic!("{e}"));
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        seam.seed_bin(digest, frame);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len,
        });
    }

    // The "read": one want, the shape `fetch_grain` uses.
    let (read_id, read_frame, read_unpacked) = frame_for(&mut codec, b"the read");
    let read_digest = [0x7f; DIGEST_LEN];
    let read_comp = u32::try_from(read_frame.len()).unwrap_or_else(|e| panic!("{e}"));
    seam.seed_bin(read_digest, read_frame);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    {
        let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
        fetcher
            .fetch(Some(&mut cache), wants)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    assert_eq!(
        fetch_state.inflight_high_water(),
        4,
        "precondition: the preamble batch really did seat four — without \
         this the test could pass because nothing was ever recorded"
    );

    fetch_state.arm_read_phase();
    assert_eq!(
        fetch_state.inflight_high_water(),
        0,
        "arming zeroes the mark"
    );

    {
        let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
        fetcher
            .fetch(
                Some(&mut cache),
                [Want::BinRange {
                    id: read_id,
                    digest: read_digest,
                    offset: 0,
                    comp_len: read_comp,
                    unpacked_len: read_unpacked,
                }],
            )
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }

    assert_eq!(
        fetch_state.inflight_high_water(),
        1,
        "the read phase's reading must be about the READ, not about the \
         preamble that ran through the same state"
    );
}

/// The Tier-1 counters decompose a fetch into the terms the cold-read gap
/// needs, so each is asserted against a fetch whose shape is KNOWN
/// rather than against itself.
///
/// One want already in the cache and two that are not: the cache
/// term must be 1, the wire term 2, and the request total must equal
/// `origin_requests + origin_sheds` with no shed in a clean run.
#[tokio::test]
async fn the_counters_decompose_a_fetch_into_cache_and_wire_terms() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    // One want the cache can serve without the wire.
    let (hit_id, hit_frame, hit_unpacked) = frame_for(&mut codec, b"cached already");
    cache.insert(&hit_id, b"cached already");
    let hit_digest = [0x81; DIGEST_LEN];
    let hit_comp = u32::try_from(hit_frame.len()).unwrap_or_else(|e| panic!("{e}"));

    let mut wants = vec![Want::BinRange {
        id: hit_id,
        digest: hit_digest,
        offset: 0,
        comp_len: hit_comp,
        unpacked_len: hit_unpacked,
    }];
    // Two the cache cannot.
    for (n, body) in [b"wire one", b"wire two"].into_iter().enumerate() {
        let (id, frame, unpacked_len) = frame_for(&mut codec, body);
        let mut digest = [0x90; DIGEST_LEN];
        digest[0] = u8::try_from(n).unwrap_or_else(|e| panic!("{e}"));
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        seam.seed_bin(digest, frame);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len,
        });
    }

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let metrics = crate::metrics::tests::metrics();
    fetch_state.set_metrics(Some(metrics.clone()));
    {
        let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
        fetcher
            .fetch(Some(&mut cache), wants)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }

    let c = fetch_state.counters();
    assert_eq!(c.cache_hits, 1, "one want was seeded into the cache");
    assert_eq!(c.cache_misses, 2, "two wants were not");
    assert_eq!(
        c.origin_requests, 2,
        "only the two misses reach the wire — a cache hit never seats a slot"
    );
    assert_eq!(c.origin_sheds, 0, "the seam shed nothing in this run");
    assert_eq!(
        c.origin_requests + c.origin_sheds,
        2,
        "the request TOTAL is the sum, and it is the quantity comparable \
         to CernVM-FS's download.n_requests"
    );
    assert_eq!(c.inflight_high_water, 2, "both misses admitted in one pass");
    let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"hit\"} 1\n"),
        "{output}"
    );
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"miss\"} 2\n"),
        "{output}"
    );
}

/// A shed is a SECOND request for the same want, and the counters
/// have to say so — otherwise a run that shed every want reports the
/// same request total as one that shed none.
#[tokio::test]
async fn a_shed_adds_a_request_and_is_counted_apart_from_the_admission() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let (id, frame, unpacked_len) = frame_for(&mut codec, b"shed me once");
    let digest = [0xA1; DIGEST_LEN];
    let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    seam.seed_bin(digest, frame);
    seam.shed(1);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    {
        let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
        fetcher
            .fetch(
                Some(&mut cache),
                [Want::BinRange {
                    id,
                    digest,
                    offset: 0,
                    comp_len,
                    unpacked_len,
                }],
            )
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }

    let c = fetch_state.counters();
    assert_eq!(c.origin_sheds, 1, "the seam shed exactly once");
    assert_eq!(c.origin_requests, 1, "one want was admitted");
    assert_eq!(
        c.origin_requests + c.origin_sheds,
        2,
        "one admission plus one shed is TWO round trips at the origin — \
         the whole reason the two terms are kept apart"
    );
}

/// `fetch.wants{kind}` counts what reached the QUEUE, which is not
/// what the caller passed in.
///
/// Three things are deliberately not wants by the time this counter
/// sees them: a DUPLICATE id (single-flighted — only the first
/// occurrence is queued), a want over the whole in-flight budget, and
/// a `BinRange` over the frame bound. Counting at the queue rather
/// than at the call means the split it reports is the split the fetch
/// actually worked on.
#[tokio::test]
async fn wants_are_counted_by_kind_at_the_queue_not_at_the_call() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    let mut wants = Vec::new();

    // Two distinct bin wants...
    for (n, body) in [b"bin one", b"bin two"].into_iter().enumerate() {
        let (id, frame, unpacked_len) = frame_for(&mut codec, body);
        let mut digest = [0x70; DIGEST_LEN];
        digest[0] = u8::try_from(n).unwrap_or_else(|e| panic!("{e}"));
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        seam.seed_bin(digest, frame);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len,
        });
    }
    // ...one of them AGAIN, which is single-flighted away...
    let duplicate = wants[0].clone();
    wants.push(duplicate);
    // ...one REFUSED for exceeding the whole in-flight budget, and one
    // REFUSED for exceeding the frame bound. Both are refused inside
    // `admit_or_refuse` BEFORE the counting site, so neither is a want
    // — and this row exercises both refusals directly.
    // Each refused entry must leave the want count unchanged:
    // exceeding the in-flight budget or frame bound must not
    // count as an admitted want.
    let over_budget_len = u32::try_from(FETCH_INFLIGHT_BYTES + 1).unwrap_or_else(|e| panic!("{e}"));
    wants.push(Want::BinRange {
        id: GrainId::of(b"over budget"),
        digest: [0x73; DIGEST_LEN],
        offset: 0,
        comp_len: 16,
        unpacked_len: over_budget_len,
    });
    wants.push(Want::BinRange {
        id: GrainId::of(b"over frame bound"),
        digest: [0x74; DIGEST_LEN],
        offset: 0,
        comp_len: FRAME_COMP_MAX + 1,
        unpacked_len: 32,
    });

    // ...and three meta wants.
    for i in 0u8..3 {
        let bytes = vec![i; 32];
        let id = GrainId::of(&bytes);
        seam.seed_meta("vol", id, bytes);
        wants.push(Want::Meta {
            volume: "vol".to_owned(),
            id,
        });
    }

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    {
        let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
        let results = fetcher
            .fetch(Some(&mut cache), wants)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            results.len(),
            7,
            "seven distinct ids got an outcome — five wants plus the two \
             refusals, which are reported to the caller but never queued"
        );
    }

    let c = fetch_state.counters();
    assert_eq!(
        c.wants_bin, 2,
        "two distinct bin wants — the duplicate is single-flighted              away before the queue and must not be counted twice"
    );
    assert_eq!(c.wants_meta, 3, "three meta wants");
    assert_eq!(
        c.origin_requests, 5,
        "the five QUEUED wants each reached the wire — nothing was \
         seeded, so all five missed the cache and all five were \
         seated. The duplicate was single-flighted away and the two \
         refusals never reached admission, so neither is a round trip"
    );
    assert_eq!(
        c.cache_misses, 5,
        "and the cache term agrees with the request term on this batch: \
         five wants, five misses, five requests"
    );
    assert_eq!(
        c.wants_bin + c.wants_meta,
        5,
        "the SUM is the only quantity comparable to CernVM-FS, which              does not split metadata from content in its own accounting"
    );
}

/// A want the BYTE GATE defers is not a round trip, and counting it
/// as one inflates the very number the cold-read decomposition reads.
///
/// `meta_wants_charge_the_read_cap` already establishes the shape:
/// six meta wants against a 64 MiB budget admit exactly FOUR at once,
/// so the rest are pushed back onto the queue and admitted again on a
/// later pass. Each of those re-admissions is the SAME object being
/// seated once — the origin sees six requests, not six plus however
/// many times the gate deferred.
///
/// The seam's own request count is the oracle here rather than a
/// hand-computed constant: whatever the gate does, the counter must
/// agree with what the wire actually saw.
#[tokio::test]
async fn a_byte_gate_deferral_is_not_a_round_trip() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let mut wants = Vec::new();
    for i in 0u8..6 {
        let bytes = vec![i; 32];
        let id = GrainId::of(&bytes);
        seam.seed_meta("vol", id, bytes);
        wants.push(Want::Meta {
            volume: "vol".to_owned(),
            id,
        });
    }

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let metrics = crate::metrics::tests::metrics();
    fetch_state.set_metrics(Some(metrics.clone()));
    {
        let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
        let results = fetcher
            .fetch(Some(&mut cache), wants)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(results.len(), 6, "all six wants completed");
    }

    assert_eq!(
        seam.high_water(),
        4,
        "the precondition this row rests on: the byte gate DID defer,              so the re-admission path was exercised"
    );
    let c = fetch_state.counters();
    assert_eq!(
        c.origin_sheds, 0,
        "nothing was shed; every extra count would be a deferral"
    );
    assert_eq!(
        c.origin_requests, 6,
        "six objects were fetched, so the origin saw six requests — a want the byte gate pushed back was never sent, and counting its re-admission inflates the request total the cold-read decomposition divides by"
    );
    assert_eq!(
        c.cache_misses, 6,
        "and the CACHE terms are the same question: a deferred want re-enters \
         `deliver_cache_hit` on the next pass and asks the cache again, so \
         counting there per-pass inflates the miss total exactly as the \
         request total was inflated"
    );
    assert_eq!(
        c.cache_hits, 0,
        "nothing was seeded, so every one of the six was a miss"
    );
    let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"hit\"} 0\n"),
        "{output}"
    );
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"miss\"} 6\n"),
        "{output}"
    );
}

#[tokio::test]
async fn a_cache_hit_never_touches_the_wire() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let (id, frame, unpacked_len) = frame_for(&mut codec, b"cache me");
    let digest = [0x22; DIGEST_LEN];
    let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    seam.seed_bin(digest, frame);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let want = Want::BinRange {
        id,
        digest,
        offset: 0,
        comp_len,
        unpacked_len,
    };

    let first = fetcher
        .fetch(Some(&mut cache), [want.clone()])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match first.get(&id) {
        Some(Ok(bytes)) => assert_eq!(bytes, b"cache me"),
        other => panic!("first fetch: expected Ok, got {other:?}"),
    }
    let after_first = seam.bin_call_count(&digest);
    assert_eq!(after_first, 1);

    let second = fetcher
        .fetch(Some(&mut cache), [want])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match second.get(&id) {
        Some(Ok(bytes)) => assert_eq!(bytes, b"cache me"),
        other => panic!("second fetch: expected Ok, got {other:?}"),
    }
    assert_eq!(
        seam.bin_call_count(&digest),
        after_first,
        "second run must not touch the wire"
    );
}

#[tokio::test]
async fn unavailable_halves_the_window_and_repolls_once() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);

    // Call 1: exactly ONE want, shed exactly once — deterministic,
    // with no other want to interleave the halving against.
    let (id, frame, unpacked_len) = frame_for(&mut codec, b"shed once");
    let digest = [0x66; DIGEST_LEN];
    let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
    seam.seed_bin(digest, frame);
    seam.shed(1);

    let results = fetcher
        .fetch(
            Some(&mut cache),
            [Want::BinRange {
                id,
                digest,
                offset: 0,
                comp_len,
                unpacked_len,
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match results.get(&id) {
        Some(Ok(bytes)) => assert_eq!(bytes, b"shed once"),
        other => panic!("expected the re-polled want to complete: {other:?}"),
    }
    assert_eq!(
        seam.bin_call_count(&digest),
        2,
        "one shed attempt plus exactly one re-poll — never more"
    );
    let after_shed = FETCH_WINDOW / 2 + 1;
    assert_eq!(
        fetcher.state.window, after_shed,
        "halved on the shed, then +1 for the completion that followed"
    );

    // Call 2: several more wants, none shed — pure recovery. Every
    // one of them contributes the same +1 regardless of poll order,
    // so the final value is order-independent.
    let mut more = Vec::new();
    for i in 0u8..5 {
        let payload = vec![0x77, i];
        let (mid, mframe, munpacked_len) = frame_for(&mut codec, &payload);
        let mdigest = [0x80 + i; DIGEST_LEN];
        let mlen = u32::try_from(mframe.len()).unwrap_or_else(|e| panic!("{e}"));
        seam.seed_bin(mdigest, mframe);
        more.push(Want::BinRange {
            id: mid,
            digest: mdigest,
            offset: 0,
            comp_len: mlen,
            unpacked_len: munpacked_len,
        });
    }
    let _ = fetcher
        .fetch(Some(&mut cache), more)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        fetcher.state.window,
        (after_shed + 5).min(FETCH_WINDOW),
        "recovers by exactly one slot per completed fetch, capped at FETCH_WINDOW"
    );
}

#[tokio::test]
async fn a_meta_want_rides_the_same_backpressure() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let bytes = b"a meta object".to_vec();
    let id = GrainId::of(&bytes);
    seam.seed_meta("vol", id, bytes.clone());
    seam.shed(1);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let results = fetcher
        .fetch(
            Some(&mut cache),
            [Want::Meta {
                volume: "vol".to_owned(),
                id,
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    match results.get(&id) {
        Some(Ok(got)) => assert_eq!(got, &bytes),
        other => panic!("expected the re-polled meta want to complete: {other:?}"),
    }
    assert_eq!(
        seam.meta_call_count("vol", &id),
        2,
        "one shed attempt plus one re-poll"
    );
}

#[tokio::test]
async fn a_second_unavailable_surfaces() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let digest = [0x99; DIGEST_LEN];
    let id = GrainId::of(b"never completes");
    // Both the first attempt AND the one re-poll are shed.
    seam.shed(2);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let results = fetcher
        .fetch(
            Some(&mut cache),
            [Want::BinRange {
                id,
                digest,
                offset: 0,
                comp_len: 8,
                unpacked_len: 8,
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    match results.get(&id) {
        Some(Err(FetchError::Remote(RootStoreError::Unavailable { operation, .. }))) => {
            assert_eq!(*operation, "GET bin");
        }
        other => panic!("expected a second Unavailable to surface, got {other:?}"),
    }
    assert_eq!(
        seam.bin_call_count(&digest),
        2,
        "no third attempt after a second Unavailable"
    );
}

#[tokio::test]
async fn an_over_budget_want_is_refused_not_deadlocked() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let (good_id, good_frame, good_unpacked_len) = frame_for(&mut codec, b"still completes");
    let good_digest = [0x33; DIGEST_LEN];
    let good_len = u32::try_from(good_frame.len()).unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();
    seam.seed_bin(good_digest, good_frame);

    let over_id = GrainId::of(b"never fetched");
    let over_digest = [0x44; DIGEST_LEN];
    // Over budget by its OWN DECLARED size — the field the new
    // admission charge actually reads. `comp_len` stays a small,
    // arbitrary wire figure: irrelevant here, since the budget
    // check (on `unpacked_len`) fires and refuses before the
    // frame-bound check (on `comp_len`) is ever reached.
    let over_bytes = FETCH_INFLIGHT_BYTES + 1;
    let over_len = u32::try_from(over_bytes).unwrap_or_else(|e| panic!("{e}"));

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let results = fetcher
        .fetch(
            Some(&mut cache),
            [
                Want::BinRange {
                    id: over_id,
                    digest: over_digest,
                    offset: 0,
                    comp_len: 8,
                    unpacked_len: over_len,
                },
                Want::BinRange {
                    id: good_id,
                    digest: good_digest,
                    offset: 0,
                    comp_len: good_len,
                    unpacked_len: good_unpacked_len,
                },
            ],
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    match results.get(&over_id) {
        Some(Err(FetchError::OverBudget { bytes, .. })) => assert_eq!(*bytes, over_bytes),
        other => panic!("expected OverBudget, got {other:?}"),
    }
    match results.get(&good_id) {
        Some(Ok(bytes)) => assert_eq!(bytes, b"still completes"),
        other => {
            panic!("the over-budget want must not block the rest of the batch: {other:?}")
        }
    }
    assert_eq!(
        seam.bin_call_count(&over_digest),
        0,
        "refused before any wire call"
    );
}

#[tokio::test]
async fn an_over_frame_bound_want_is_refused_before_the_wire() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);

    let id = GrainId::of(b"over frame");
    let digest = [0x55; DIGEST_LEN];
    // Under FETCH_INFLIGHT_BYTES (so the budget gate does not fire
    // first), over FRAME_COMP_MAX.
    let comp_len = FRAME_COMP_MAX + 1;
    assert!(u64::from(comp_len) <= FETCH_INFLIGHT_BYTES);

    let results = fetcher
        .fetch(
            Some(&mut cache),
            [Want::BinRange {
                id,
                digest,
                offset: 0,
                comp_len,
                unpacked_len: comp_len,
            }],
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    match results.get(&id) {
        Some(Err(FetchError::OverFrameBound { comp_len: got, .. })) => {
            assert_eq!(*got, comp_len);
        }
        other => panic!("expected OverFrameBound, got {other:?}"),
    }
    assert_eq!(seam.bin_call_count(&digest), 0);
}

#[tokio::test]
async fn verification_failure_fails_the_want_not_the_batch() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    let mut wants = Vec::new();
    let mut good = Vec::new();
    for i in 0u8..9 {
        let payload = vec![i; 64];
        let (id, frame, unpacked_len) = frame_for(&mut codec, &payload);
        let digest = [i; DIGEST_LEN];
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        seam.seed_bin(digest, frame);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len,
        });
        good.push((id, payload));
    }

    // The tenth want: a VALID frame whose claimed id does not match
    // what it actually decompresses to.
    let (_, corrupt_frame, corrupt_unpacked_len) = frame_for(&mut codec, b"actual content");
    let wrong_id = GrainId::of(b"a different claim entirely");
    let corrupt_digest = [0xEE; DIGEST_LEN];
    let corrupt_len = u32::try_from(corrupt_frame.len()).unwrap_or_else(|e| panic!("{e}"));
    seam.seed_bin(corrupt_digest, corrupt_frame);
    wants.push(Want::BinRange {
        id: wrong_id,
        digest: corrupt_digest,
        offset: 0,
        comp_len: corrupt_len,
        unpacked_len: corrupt_unpacked_len,
    });

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let results = fetcher
        .fetch(Some(&mut cache), wants)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(results.len(), 10);
    for (id, payload) in &good {
        match results.get(id) {
            Some(Ok(bytes)) => assert_eq!(bytes, payload),
            other => panic!("{id}: expected Ok, got {other:?}"),
        }
    }
    match results.get(&wrong_id) {
        Some(Err(FetchError::Corrupt { id })) => assert_eq!(*id, wrong_id),
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

// ------------------------------------------------- fetch_streaming

#[tokio::test]
async fn a_fallible_want_stream_errors_before_cache_or_wire_admission() {
    const VOLUME: &str = "fallible-stream";
    const INPUT_ERROR: &str = "position walk failed";

    let seam = CountingSeam::default();
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let cached = b"queued before the iterator error";
    let id = GrainId::of(cached);
    cache.insert(&id, cached);
    let wants = [
        Ok(Want::Meta {
            volume: VOLUME.to_owned(),
            id,
        }),
        Err(INPUT_ERROR),
    ];
    let mut callbacks = 0_usize;
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let outcome = fetcher
        .fetch_streaming(Some(&mut cache), wants, |_id, _result, _charged| {
            callbacks = callbacks.saturating_add(1);
            0
        })
        .await;

    assert_eq!(outcome, Err(INPUT_ERROR));
    assert_eq!(
        callbacks, 0,
        "a queued want must be dropped rather than completed after a later input error"
    );
    assert_eq!(
        seam.meta_call_count(VOLUME, &id),
        0,
        "the entire fallible iterator must be consumed before the first wire admission"
    );
    assert_eq!(
        fetch_state.counters().wants_meta,
        0,
        "AND THE COUNTER AGREES WITH THAT. The first want was accepted onto \
         the queue before the iterator's error was seen, and the queue is \
         then discarded — zero callbacks, zero seam calls, no work of any \
         kind. A want tally left standing across that `?` reports a want \
         the fetch never did, and this counter exists to decompose a \
         measurement"
    );
}

/// The streaming variant's callback fires exactly once per distinct
/// id, covering every outcome shape [`Fetcher::fetch`]'s batch map
/// can hold: a cache hit, both pre-admission refusals, and a normal
/// wire success.
#[tokio::test]
async fn fetch_streaming_reports_every_outcome_exactly_once() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    // A cache hit, seeded directly — never touches the seam.
    let (hit_id, hit_frame, hit_unpacked_len) = frame_for(&mut codec, b"already cached");
    cache.insert(&hit_id, b"already cached");
    let hit_digest = [0x01; DIGEST_LEN];
    let hit_len = u32::try_from(hit_frame.len()).unwrap_or_else(|e| panic!("{e}"));

    // A normal wire success.
    let (ok_id, ok_frame, ok_unpacked_len) = frame_for(&mut codec, b"fetched over the wire");
    let ok_digest = [0x02; DIGEST_LEN];
    let ok_len = u32::try_from(ok_frame.len()).unwrap_or_else(|e| panic!("{e}"));
    seam.seed_bin(ok_digest, ok_frame);

    // The two pre-admission refusals — refused before any wire call.
    // Each is built to trip exactly ONE gate: the over-budget want's
    // `unpacked_len` alone exceeds the byte bound (its `comp_len` is
    // an arbitrary small figure, never read — the budget check fires
    // and refuses before the frame-bound check is reached); the
    // over-frame want's `comp_len` alone exceeds `FRAME_COMP_MAX`
    // while its `unpacked_len` stays well inside the byte bound, so
    // it clears the budget check and is caught by the frame check
    // instead.
    let over_budget_id = GrainId::of(b"over budget");
    let over_budget_digest = [0x03; DIGEST_LEN];
    let over_budget_len = u32::try_from(FETCH_INFLIGHT_BYTES + 1).unwrap_or_else(|e| panic!("{e}"));

    let over_frame_id = GrainId::of(b"over frame bound");
    let over_frame_digest = [0x04; DIGEST_LEN];
    let over_frame_len = FRAME_COMP_MAX + 1;

    let wants = [
        Want::BinRange {
            id: hit_id,
            digest: hit_digest,
            offset: 0,
            comp_len: hit_len,
            unpacked_len: hit_unpacked_len,
        },
        Want::BinRange {
            id: ok_id,
            digest: ok_digest,
            offset: 0,
            comp_len: ok_len,
            unpacked_len: ok_unpacked_len,
        },
        Want::BinRange {
            id: over_budget_id,
            digest: over_budget_digest,
            offset: 0,
            comp_len: 8,
            unpacked_len: over_budget_len,
        },
        Want::BinRange {
            id: over_frame_id,
            digest: over_frame_digest,
            offset: 0,
            comp_len: over_frame_len,
            unpacked_len: over_frame_len,
        },
    ];

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let mut seen: StdBTreeMap<GrainId, Result<Vec<u8>, FetchError>> = StdBTreeMap::new();
    fetcher
        .fetch_streaming(
            Some(&mut cache),
            wants.into_iter().map(Ok::<Want, std::convert::Infallible>),
            |id, result, charged| {
                // `hit_id` and `ok_id` are both admitted/charged — a
                // cache hit costs exactly as much as a wire completion.
                // Only the two pre-admission refusals cost nothing to
                // "release". Releasing the CONVERTED (decompressed)
                // length, never the compressed admission figure.
                let release = if charged {
                    result.as_ref().map_or(0, |b| b.len() as u64)
                } else {
                    0
                };
                assert!(
                    seen.insert(id, result).is_none(),
                    "{id} reported more than once"
                );
                release
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(seen.len(), 4, "every distinct id must report exactly once");
    match seen.get(&hit_id) {
        Some(Ok(bytes)) => assert_eq!(bytes, b"already cached"),
        other => panic!("expected the cache hit, got {other:?}"),
    }
    match seen.get(&ok_id) {
        Some(Ok(bytes)) => assert_eq!(bytes, b"fetched over the wire"),
        other => panic!("expected the wire success, got {other:?}"),
    }
    assert!(matches!(
        seen.get(&over_budget_id),
        Some(Err(FetchError::OverBudget { .. }))
    ));
    assert!(matches!(
        seen.get(&over_frame_id),
        Some(Err(FetchError::OverFrameBound { .. }))
    ));
    assert_eq!(
        seam.bin_call_count(&hit_digest),
        0,
        "a cache hit never touches the wire"
    );
    assert_eq!(seam.bin_call_count(&over_budget_digest), 0);
    assert_eq!(seam.bin_call_count(&over_frame_digest), 0);
}

/// A held (unreleased) completion keeps its charge reserved until a
/// LATER completion's return value releases it — and a want that
/// only fits once that release happens still gets fetched, rather
/// than the call deadlocking. Three metas (`META_MAX_BYTES` each)
/// admit alongside a tiny bin want; the metas are held (`0`
/// returned) and a fifth want (another meta) has no room to admit
/// until the tiny want's OWN completion — deliberately shed once, so
/// it lands strictly after the three holds — releases all three at
/// once. The run completing at all, with every id answered, is the
/// property under test: an implementation that released `slot.charge`
/// unconditionally (ignoring this return value) would happen to pass
/// too, since nothing here can observe exact interleaving — this is
/// a functional/no-deadlock regression check, not a timing proof;
/// see resolve.rs's `a_whole_tree_cat_streams_within_the_inflight_bound`
/// for the end-to-end bound this mechanism exists to hold.
#[tokio::test]
async fn fetch_streaming_a_held_release_unblocks_a_later_admission() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    let (trigger_id, trigger_frame, trigger_unpacked_len) = frame_for(&mut codec, b"tiny");
    let trigger_digest = [0x10; DIGEST_LEN];
    let trigger_len = u32::try_from(trigger_frame.len()).unwrap_or_else(|e| panic!("{e}"));
    seam.seed_bin(trigger_digest, trigger_frame);
    seam.shed(1);

    let held_ids: Vec<GrainId> = (0..3u8)
        .map(|i| {
            let bytes = vec![i; 8];
            let id = GrainId::of(&bytes);
            seam.seed_meta("vol", id, bytes);
            id
        })
        .collect();
    let queued_bytes = vec![0xFFu8; 8];
    let queued_id = GrainId::of(&queued_bytes);
    seam.seed_meta("vol", queued_id, queued_bytes);

    let mut wants = vec![Want::BinRange {
        id: trigger_id,
        digest: trigger_digest,
        offset: 0,
        comp_len: trigger_len,
        unpacked_len: trigger_unpacked_len,
    }];
    wants.extend(held_ids.iter().map(|&id| Want::Meta {
        volume: "vol".to_owned(),
        id,
    }));
    wants.push(Want::Meta {
        volume: "vol".to_owned(),
        id: queued_id,
    });

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let mut released: StdBTreeMap<GrainId, u64> = StdBTreeMap::new();
    fetcher
        .fetch_streaming(
            Some(&mut cache),
            wants.into_iter().map(Ok::<Want, std::convert::Infallible>),
            |id, result, charged| {
                assert!(charged, "{id}: every want here is a real wire completion");
                assert!(result.is_ok(), "{id}: expected Ok, got {result:?}");
                if id == trigger_id {
                    // The retried completion: free this want's own
                    // charge plus every held meta's.
                    let held_total = u64::try_from(held_ids.len()).unwrap_or(0) * META_MAX_BYTES;
                    let amount = u64::from(trigger_len) + held_total;
                    released.insert(id, amount);
                    amount
                } else if held_ids.contains(&id) {
                    released.insert(id, 0);
                    0
                } else {
                    released.insert(id, META_MAX_BYTES);
                    META_MAX_BYTES
                }
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(released.len(), 5, "every want must have completed");
    assert_eq!(
        seam.bin_call_count(&trigger_digest),
        2,
        "one shed attempt plus exactly one re-poll"
    );
    assert_eq!(
        seam.meta_call_count("vol", &queued_id),
        1,
        "the queued want was fetched exactly once, not deadlocked"
    );
}

/// **The measured invariant this pins: admission itself charges a
/// `BinRange` want at its DECLARED decompressed size, never the
/// compressed figure on the wire.** Eight highly-compressible grains
/// at exactly [`GRAIN_UNPACKED_MAX`] (all-zero payload, one unique
/// tag per grain so each content-addresses distinctly; `comp_len`
/// collapses to a handful of bytes each) sum to exactly
/// [`FETCH_INFLIGHT_BYTES`] by their DECLARED `unpacked_len` alone —
/// no filler, no window count, needed to prove it: `FETCH_WINDOW` is
/// 32 and this fixture never exceeds ten wants, so BYTES, not COUNT,
/// are what gate it the whole way through.
///
/// A GAP want (shed once, delayed — `CountingSeam::shed`, this
/// module's own `Unavailable` injection hook, the pattern
/// `fetch_streaming_a_held_release_unblocks_a_later_admission` uses)
/// sits at the front. Its own few declared bytes are what push the
/// EIGHTH large grain out of the opening admission pass: the first
/// seven admit alongside the gap (`gap's charge + 7 × GRAIN_UNPACKED_MAX`
/// stays under the budget), but the eighth would cross it by exactly
/// the gap's own charge, and — `in_flight` non-empty at that point —
/// is refused this pass and requeued at the front, ahead of the
/// PROBE (a modestly-sized ~1 MiB want) behind it. A strict FIFO
/// queue then keeps the probe from ever being tried while the eighth
/// grain sits in front of it, whatever room later frees up.
///
/// By the time the gap's own retry succeeds, all seven ADMITTED
/// large grains have long since completed and are HELD (the test's
/// own callback returns `0` for them — nothing has been released;
/// the gap is the one thing every other position is waiting on). Its
/// completion is the checkpoint: `seam.bin_call_count` for the
/// probe's digest, read from INSIDE the gap's own `on_complete`
/// invocation, strictly before this same call's release of the seven
/// held grains' charge — and before the eighth grain's own later
/// admission — could possibly free room for the probe. Had admission
/// still been charging the compressed figure instead, none of this
/// would have bound anything: eight grains' worth of compressed
/// bytes is noise against the budget, the eighth grain and the probe
/// would both have admitted immediately, and the checkpoint below
/// would read nonzero.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture (gap + eight large grains + probe) built and seeded in \
              sequence, then driven through one fetch_streaming call — splitting it \
              loses the shared want list and checkpoint the assertions depend on"
)]
async fn held_bytes_charge_at_their_decompressed_size() {
    const LARGE_GRAINS: usize = 8;
    const PROBE_LEN: usize = 1024 * 1024;

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    let digest_for = |tag: u64| -> [u8; DIGEST_LEN] {
        let mut d = [0_u8; DIGEST_LEN];
        d[..8].copy_from_slice(&tag.to_be_bytes());
        d
    };

    let mut wants: Vec<Want> = Vec::with_capacity(LARGE_GRAINS + 2);

    // Position 0: the gap want — shed once, so it is the one thing
    // every other position waits on.
    let (gap_id, gap_frame, gap_unpacked_len) = frame_for(&mut codec, b"gap");
    let gap_digest = digest_for(0);
    let gap_len = u32::try_from(gap_frame.len()).unwrap_or_else(|e| panic!("{e}"));
    seam.seed_bin(gap_digest, gap_frame);
    wants.push(Want::BinRange {
        id: gap_id,
        digest: gap_digest,
        offset: 0,
        comp_len: gap_len,
        unpacked_len: gap_unpacked_len,
    });

    // Eight grains at exactly GRAIN_UNPACKED_MAX, all-zero but for a
    // unique tag — declared (and, since they are honest, actual)
    // decompressed total EQUALS FETCH_INFLIGHT_BYTES; compressed
    // total is a rounding error against it, and irrelevant to
    // admission, which never reads it.
    for i in 0..LARGE_GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let id = GrainId::of(&payload);
        let frame = codec
            .compress_grain(&payload)
            .unwrap_or_else(|e| panic!("{e}"));
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        let digest = digest_for(u64::try_from(i).unwrap_or(0) + 1);
        seam.seed_bin(digest, frame);
        wants.push(Want::BinRange {
            id,
            digest,
            offset: 0,
            comp_len,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
    }

    // The probe: real (incompressible-ish) content, so its own
    // admission charge is a genuine ~1 MiB, not a rounding error.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "deliberate wraparound filler pattern, not a length computation"
    )]
    let probe_payload: Vec<u8> = (0..PROBE_LEN)
        .map(|b| (b as u32).wrapping_mul(2_654_435_761) as u8)
        .collect();
    let probe_id = GrainId::of(&probe_payload);
    let probe_frame = codec
        .compress_grain(&probe_payload)
        .unwrap_or_else(|e| panic!("{e}"));
    let probe_comp_len = u32::try_from(probe_frame.len()).unwrap_or_else(|e| panic!("{e}"));
    let probe_unpacked_len = u32::try_from(PROBE_LEN).unwrap_or_else(|e| panic!("{e}"));
    let probe_digest = digest_for(999);
    seam.seed_bin(probe_digest, probe_frame);
    wants.push(Want::BinRange {
        id: probe_id,
        digest: probe_digest,
        offset: 0,
        comp_len: probe_comp_len,
        unpacked_len: probe_unpacked_len,
    });

    seam.shed(1);

    let mut held: StdBTreeMap<GrainId, Vec<u8>> = StdBTreeMap::new();
    let mut gap_seen = false;
    let mut probe_calls_at_gap_arrival: Option<usize> = None;

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    fetcher
        .fetch_streaming(
            Some(&mut cache),
            wants.into_iter().map(Ok::<Want, std::convert::Infallible>),
            |id, result, charged| {
                assert!(charged, "{id}: every want here is a real wire completion");
                let bytes = result.unwrap_or_else(|e| panic!("{id}: expected Ok, got {e}"));
                let len = bytes.len() as u64;
                if id == gap_id {
                    // The checkpoint: read BEFORE this call's own release
                    // below could possibly have freed room for the probe.
                    probe_calls_at_gap_arrival = Some(seam.bin_call_count(&probe_digest));
                    gap_seen = true;
                    let mut total = len;
                    for (_, b) in std::mem::take(&mut held) {
                        total += b.len() as u64;
                    }
                    return total;
                }
                if gap_seen {
                    // Nothing left to hold for: release immediately.
                    return len;
                }
                held.insert(id, bytes);
                0
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        probe_calls_at_gap_arrival,
        Some(0),
        "the probe's wire call must not have happened before the gap grain \
         released the seven large grains its own tiny declared size left room \
         to admit — its own ~1 MiB request cannot jump the eighth grain, still \
         queued ahead of it, which cannot itself admit until that release"
    );
    assert_eq!(
        seam.bin_call_count(&gap_digest),
        2,
        "the gap grain: one shed attempt plus exactly one re-poll"
    );
    assert_eq!(
        seam.bin_call_count(&probe_digest),
        1,
        "the probe is fetched exactly once, once the gap's release frees room \
         for it — delayed, never starved"
    );
}

/// **A cache hit rides the same byte gate a wire completion does
/// — it is never delivered for free.** Nine grains at exactly
/// [`GRAIN_UNPACKED_MAX`] sit warm in the cache (nine × 8 MiB =
/// 72 MiB, past [`FETCH_INFLIGHT_BYTES`]); a COLD gap grain
/// (shed once, real, admitted first) reserves its own small
/// DECLARED charge ahead of them — a cache hit's own charge is
/// always its actual `bytes.len()`, read off the cache, and that
/// hit must sit at or under its want's `unpacked_len` — so the
/// nine wants declare TWICE `GRAIN_UNPACKED_MAX`, above the
/// payload as the guard requires and unequal to it so that
/// charging the declaration instead of the actual length is
/// still observable here (the loop's own comment has the
/// arithmetic); only `comp_len` is nominal (it bounds a wire
/// read, and the cache answers first). A caller that buffers
/// every delivery until the gap arrives can hold at most SEVEN
/// of the nine cached grains — the eighth's own 8 MiB, stacked
/// on the gap's own reservation, would cross the budget — so the
/// eighth and ninth must stay queued, undelivered, until the
/// gap's own release frees room, exactly as a wire completion's
/// charge would gate a later want.
///
/// The checkpoint reads how many cache hits have been delivered
/// from INSIDE the closure, at the instant the gap itself arrives
/// — before this call's own release (the gap's charge plus
/// whatever the closure was already holding) is even applied,
/// which is the earliest point an EIGHTH delivery could possibly
/// have happened if the byte gate did not bind cache hits.
#[tokio::test]
async fn a_cache_hit_rides_the_byte_gate() {
    const WARM_GRAINS: usize = 9;
    const GRAINS_THAT_FIT: usize = 7;

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let seam = CountingSeam::default();

    // The cold gap — a real want, shed once so its own retry lands
    // strictly after every cache-hit admission attempt this test
    // means to observe.
    let (gap_id, gap_frame, gap_unpacked_len) = frame_for(&mut codec, b"gap");
    let gap_digest = [0xA0_u8; DIGEST_LEN];
    let gap_len = u32::try_from(gap_frame.len()).unwrap_or_else(|e| panic!("{e}"));
    seam.seed_bin(gap_digest, gap_frame);
    seam.shed(1);

    // Nine grains, warm in the cache, decompressed sum 72 MiB —
    // past the 64 MiB budget by exactly one grain's worth.
    let mut wants: Vec<Want> = vec![Want::BinRange {
        id: gap_id,
        digest: gap_digest,
        offset: 0,
        comp_len: gap_len,
        unpacked_len: gap_unpacked_len,
    }];
    for i in 0..WARM_GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let id = GrainId::of(&payload);
        cache.insert(&id, &payload);
        // `unpacked_len` must be AT OR ABOVE the payload's true
        // size, and DELIBERATELY NOT EQUAL to it. The cache-hit
        // branch enforces the declaration the way `finish()` does on
        // the wire path, so a hit WIDER than its want is refused
        // `OverDeclared` and never charged — this row would then
        // measure the refusal rather than the byte gate. But
        // declaring the payload's EXACT size is the other trap, and
        // it is the one this row fell into when the declaration was
        // first raised: with declared == actual,
        // `want.admission_bytes()` and `bytes.len()` are the same
        // number, so "a cache hit is charged its ACTUAL length, not
        // its declaration" — the property this row's own doc asserts
        // — becomes unobservable, and swapping one for the other is
        // an equivalent mutant that the whole suite passes
        // (executed). Declaring TWICE the payload keeps every hit
        // above the payload, which is the direction the guard
        // permits, while keeping the two quantities apart: under the
        // mutant only three of the nine fit instead of seven.
        // (Over-declaring is a real production shape — a duplicate
        // is charged at the max across its positions — but only up
        // to the grain cap, so no duplicate could declare THIS
        // width.) `comp_len` is still nominal: it bounds a WIRE
        // read, and the cache answers first.
        //
        // A DECLARATION THIS WIDE CANNOT COME FROM A VALIDATED
        // MANIFEST — the decoder refuses `unpacked_len` above
        // `GRAIN_UNPACKED_MAX`, so this shape is deliberately
        // outside the production envelope, chosen because the
        // property under test is which of two NUMBERS the charge is
        // taken from, and that needs the two numbers to differ. It
        // masks no missing gate: the only things that read a hit's
        // `unpacked_len` are `admit_or_refuse`'s whole-budget check
        // (16 MiB is well under `FETCH_INFLIGHT_BYTES`) and
        // `over_declared`. But the row DEPENDS on `admit_or_refuse`
        // not gaining a `> GRAIN_UNPACKED_MAX` refusal of its own:
        // if one is ever added as defence in depth, this row goes
        // red for a reason that has nothing to do with the byte
        // gate, and the fixture — not the guard — is what to change.
        wants.push(Want::BinRange {
            id,
            digest: [0xB0_u8 + u8::try_from(i).unwrap_or(0); DIGEST_LEN],
            offset: 0,
            comp_len: 64,
            unpacked_len: GRAIN_UNPACKED_MAX * 2,
        });
    }

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let metrics = crate::metrics::tests::metrics();
    fetch_state.set_metrics(Some(metrics.clone()));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let mut delivered: usize = 0;
    let mut held_bytes_sum: u64 = 0;
    let mut delivered_at_gap_arrival: Option<usize> = None;
    let mut seen: StdBTreeMap<GrainId, usize> = StdBTreeMap::new();
    fetcher
        .fetch_streaming(
            Some(&mut cache),
            wants.into_iter().map(Ok::<Want, std::convert::Infallible>),
            |id, result, charged| {
                assert!(
                    charged,
                    "{id}: every completion here is charged — a cache \
                               hit exactly as much as the gap's wire completion"
                );
                let bytes = result.unwrap_or_else(|e| panic!("{id}: expected Ok, got {e}"));
                *seen.entry(id).or_insert(0) += 1;
                let len = bytes.len() as u64;
                if id == gap_id {
                    delivered_at_gap_arrival = Some(delivered);
                    let flush = held_bytes_sum;
                    held_bytes_sum = 0;
                    return len + flush;
                }
                delivered += 1;
                held_bytes_sum += len;
                0
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        delivered_at_gap_arrival,
        Some(GRAINS_THAT_FIT),
        "only the cache hits that fit under the byte budget (seven of nine, at \
         exactly GRAIN_UNPACKED_MAX each, once the gap's own reservation is \
         stacked on top) may have been delivered by the time the gap arrives — \
         the eighth and ninth must still be waiting, gated by the same byte \
         budget a wire completion faces, not delivered unboundedly up front"
    );
    assert_eq!(
        seen.values().sum::<usize>(),
        1 + WARM_GRAINS,
        "every want (the gap plus all nine cache hits) must complete exactly once"
    );
    assert!(
        seen.values().all(|&count| count == 1),
        "no id may complete more than once"
    );
    assert_eq!(
        seam.bin_call_count(&gap_digest),
        2,
        "the gap grain: one shed attempt plus exactly one re-poll"
    );
    let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"hit\"} 9\n"),
        "{output}"
    );
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"miss\"} 1\n"),
        "{output}"
    );
}

/// A cache hit WIDER than its want's
/// `unpacked_len` is refused at the fetcher boundary with
/// `OverDeclared { declared: 100, got: 200 }` — returned
/// as that want's `Err` in `fetch`'s results, never as
/// `Ok` — with zero wire calls. Without the guard the hit is
/// delivered `Ok`, which is the failure this row catches.
#[tokio::test]
async fn a_cache_hit_wider_than_its_declaration_is_refused_before_delivery() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let metrics = crate::metrics::tests::metrics();
    fetch_state.set_metrics(Some(metrics.clone()));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let payload = vec![0x5A_u8; 200];
    let id = GrainId::of(&payload);
    cache.insert(&id, &payload);
    let digest = [0x77_u8; DIGEST_LEN];
    let want = Want::BinRange {
        id,
        digest,
        offset: 0,
        comp_len: 1,
        unpacked_len: 100,
    };
    let results = fetcher
        .fetch(Some(&mut cache), [want])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    match results.get(&id) {
        Some(Err(FetchError::OverDeclared {
            id: got_id,
            declared,
            got,
        })) => {
            assert_eq!(*got_id, id);
            assert_eq!(*declared, 100);
            assert_eq!(*got, 200);
        }
        other => panic!("expected OverDeclared {{ declared: 100, got: 200 }}, got {other:?}"),
    }
    assert_eq!(seam.bin_call_count(&digest), 0, "zero wire calls");
    let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"hit\"} 1\n"),
        "{output}"
    );
    assert!(
        output.contains("cache_lookups_total{phase=\"startup\",result=\"miss\"} 0\n"),
        "{output}"
    );
}

/// **Legal cached content is unaffected by the guard.** A
/// `BinRange` hit at EXACTLY its declaration and one UNDER it (a
/// duplicate charged at the max across its positions,
/// `resolve.rs`'s `grain_span_facts`, whose content is the smaller
/// size) are both delivered `Ok`, and a `Want::Meta` hit — which
/// declares no extent — is delivered `Ok` at whatever size the
/// cache holds. The seam is never seeded, so a miss would fail
/// loudly rather than pass by accident: zero wire calls.
#[tokio::test]
async fn a_cache_hit_at_or_under_its_declaration_and_a_meta_hit_are_delivered() {
    const VOLUME: &str = "legal-hits";

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);

    let exact = vec![0x5B_u8; 100];
    let exact_id = GrainId::of(&exact);
    cache.insert(&exact_id, &exact);
    let under = vec![0x5C_u8; 100];
    let under_id = GrainId::of(&under);
    cache.insert(&under_id, &under);
    let meta = vec![0x5D_u8; 300];
    let meta_id = GrainId::of(&meta);
    cache.insert(&meta_id, &meta);

    let exact_digest = [0x78_u8; DIGEST_LEN];
    let under_digest = [0x79_u8; DIGEST_LEN];
    let wants = [
        Want::BinRange {
            id: exact_id,
            digest: exact_digest,
            offset: 0,
            comp_len: 1,
            unpacked_len: 100,
        },
        Want::BinRange {
            id: under_id,
            digest: under_digest,
            offset: 0,
            comp_len: 1,
            unpacked_len: 150,
        },
        Want::Meta {
            volume: VOLUME.to_owned(),
            id: meta_id,
        },
    ];
    let results = fetcher
        .fetch(Some(&mut cache), wants)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    for (id, payload) in [(exact_id, &exact), (under_id, &under), (meta_id, &meta)] {
        match results.get(&id) {
            Some(Ok(bytes)) => assert_eq!(bytes, payload),
            other => panic!("{id}: expected Ok at its cached size, got {other:?}"),
        }
    }
    assert_eq!(
        (
            seam.bin_call_count(&exact_digest),
            seam.bin_call_count(&under_digest),
            seam.meta_call_count(VOLUME, &meta_id),
        ),
        (0, 0, 0),
        "every hit answered from the cache: zero wire calls"
    );
}

/// One `fetch_streaming` completion, flattened for assertion: the id,
/// the `OverDeclared { declared, got }` pair or a rendering of whatever
/// else arrived, and the `charged` flag. Factored out because the
/// inline type is `clippy::type_complexity` (denied); the RENDERING of
/// the non-`OverDeclared` case is deliberate — a premise that can only
/// say "not the error I wanted" has to print what it actually got.
type Completion = (GrainId, Result<(u32, usize), String>, bool);

/// **The refusal's UPPER BOUNDARY and its `charged` flag, both pinned on
/// one completion.** A hit ONE byte over its declaration is
/// refused `OverDeclared { declared: 100, got: 101 }`, and the refusal is
/// reported `charged == false`. Both facts are asserted as ONE tuple
/// because both are needed to explain a red.
///
/// The over-declared cache-hit row's fixture is 200 against a
/// declaration of 100, so on its own it admits a guard with up to 99 bytes
/// of slack — or one that recognises only that row's exact numbers — and
/// it goes through `fetch`, which never exposes `charged` at all.
/// (One row does ASSERT on the flag for an error, and one other merely
/// reads it:
/// `a_grain_that_decompresses_past_its_declared_size_never_parks` asserts
/// `charged` is TRUE across thirty-two wire-path `OverDeclared`s, which
/// is the opposite case — those wants were admitted and charged before
/// their frames over-decompressed.) The `false` side had no observer
/// because no production consumer reads the flag on an `Err`:
/// [`Fetcher::fetch`]'s collector returns 0 for any `Err`, and
/// `emit_file`'s error arm ignores it. [`Fetcher::fetch_streaming`]'s doc
/// nonetheless makes `charged == false` a contract, and the speculative
/// pool is the consumer that will rely on it — so it is pinned here,
/// before that consumer exists, not after.
#[tokio::test]
async fn a_hit_one_byte_over_its_declaration_is_refused_uncharged() {
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    let seam = CountingSeam::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let payload = vec![0x5E_u8; 101];
    let id = GrainId::of(&payload);
    cache.insert(&id, &payload);
    let digest = [0x7A_u8; DIGEST_LEN];
    let want = Want::BinRange {
        id,
        digest,
        offset: 0,
        comp_len: 1,
        unpacked_len: 100,
    };
    let mut seen: Vec<Completion> = Vec::new();
    fetcher
        .fetch_streaming(
            Some(&mut cache),
            [want].into_iter().map(Ok::<Want, std::convert::Infallible>),
            |got_id, outcome, charged| {
                let summary = match outcome {
                    Err(FetchError::OverDeclared { declared, got, .. }) => Ok((declared, got)),
                    other => Err(format!("{other:?}")),
                };
                seen.push((got_id, summary, charged));
                0
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        seen,
        vec![(id, Ok((100, 101)), false)],
        "exactly one completion: OverDeclared {{ declared: 100, got: 101 }}, reported UNCHARGED"
    );
    assert_eq!(seam.bin_call_count(&digest), 0, "zero wire calls");
}

#[tokio::test]
async fn metrics_cache_disabled_misses_survive_the_read_phase_reset() {
    let seam = CountingSeam::default();
    let metrics = crate::metrics::tests::metrics();
    let mut state = FetchState::new().unwrap();
    state.set_metrics(Some(metrics.clone()));
    let id = GrainId::of(b"bytes");
    seam.seed_meta("vol", id, b"bytes".to_vec());
    let want = Want::Meta {
        volume: "vol".to_owned(),
        id,
    };
    Fetcher::new(&seam, &mut state)
        .fetch(None, [want.clone(), want.clone()])
        .await
        .unwrap();
    state.arm_read_phase();
    Fetcher::new(&seam, &mut state)
        .fetch(None, [want])
        .await
        .unwrap();
    let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
    for phase in ["startup", "read"] {
        assert!(
            text.contains(&format!(
                "cache_lookups_total{{phase=\"{phase}\",result=\"miss\"}} 1\n"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!("cache_hit_ratio{{phase=\"{phase}\"}} 0\n")),
            "{text}"
        );
    }
    assert!(text.contains("metrics_available{group=\"cache\"} 1\n"));
}
