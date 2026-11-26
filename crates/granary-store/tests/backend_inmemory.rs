// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

// This file uses `granary_store::backend` and `object_store`
// directly, neither of which exists without the `backend` feature —
// `cargo check -p granary-store --no-default-features --all-targets`
// otherwise fails to compile this test TARGET (the library itself
// compiles fine under every feature selection; only the unconditional
// test targets did not).
#![cfg(feature = "backend")]

//! Hermetic `GranaryStore` tests over `object_store::memory::InMemory`.
//! No network, no `MinIO` — this file
//! runs in every `cargo nextest run`.
//!
//! Garbage/foreign-key injection goes through the raw `Arc<InMemory>`
//! handle directly (`GranaryStore` itself only ever writes well-formed
//! bodies): each test that needs to plant bytes `GranaryStore` would
//! never produce keeps its own clone of the `Arc` alongside the
//! `GranaryStore` built from `Arc::clone` of the same handle, per the
//! task brief (`Arc<T: ObjectStore>` implements `ObjectStore`).

use futures_core::stream::BoxStream;
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::rng::{Rng, SeededRng};
use granary_core::rootstore::{HintRead, HintToken, RootStore, RootStoreError};
use granary_store::backend::GranaryStore;
use object_store::memory::InMemory;
use object_store::path::Path as StorePath;
use object_store::throttle::{ThrottleConfig, ThrottledStore};
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    ObjectStoreExt, PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// A fresh in-memory backend plus a raw handle to the same store, for
/// tests that need to plant bytes `GranaryStore`'s own API cannot
/// produce (garbage hint bodies, malformed/foreign root keys).
fn store() -> (Arc<InMemory>, GranaryStore<Arc<InMemory>>) {
    let mem = Arc::new(InMemory::new());
    let store = GranaryStore::new(Arc::clone(&mem));
    (mem, store)
}

/// Deterministic, position-distinguishing bytes (not a constant fill) —
/// a range read at the wrong offset would return DIFFERENT bytes, not
/// merely fail to be checked.
fn sample_bytes(len: u32) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 250).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

#[tokio::test]
async fn put_root_winner_then_loser_body_unchanged() {
    let (_mem, store) = store();
    assert_eq!(store.put_root("vol-1", 1, vec![0xAA]).await, Ok(()));
    // The loser sees AlreadyExists and the stored body is UNCHANGED —
    // never last-writer-wins.
    assert_eq!(
        store.put_root("vol-1", 1, vec![0xBB]).await,
        Err(RootStoreError::AlreadyExists)
    );
    assert_eq!(store.get_root("vol-1", 1).await, Ok(Some(vec![0xAA])));
}

#[tokio::test]
async fn get_root_missing_seq_is_ok_none() {
    let (_mem, store) = store();
    // Nothing published yet: the cheap forward-probe 404.
    assert_eq!(store.get_root("vol-2", 1).await, Ok(None));
    assert_eq!(store.put_root("vol-2", 1, vec![1]).await, Ok(()));
    // seq 1 exists, seq 2 does not.
    assert_eq!(store.get_root("vol-2", 2).await, Ok(None));
}

#[tokio::test]
async fn hint_lifecycle_missing_current_notmodified_new_token() {
    let (_mem, store) = store();
    assert_eq!(store.read_hint("vol-3", None).await, Ok(HintRead::Missing));

    assert_eq!(store.write_hint("vol-3", 1).await, Ok(()));
    let t1 = match store.read_hint("vol-3", None).await {
        Ok(HintRead::Current { seq: 1, token }) => token,
        other => panic!("want Current{{seq:1,..}}, got {other:?}"),
    };

    // Cheap poll: the same token revalidates.
    assert_eq!(
        store.read_hint("vol-3", Some(&t1)).await,
        Ok(HintRead::NotModified)
    );

    // A new publish moves the token; the cached one is now stale.
    assert_eq!(store.write_hint("vol-3", 2).await, Ok(()));
    match store.read_hint("vol-3", Some(&t1)).await {
        Ok(HintRead::Current { seq: 2, token }) => assert_ne!(token, t1),
        other => panic!("want Current{{seq:2,..}} with a new token, got {other:?}"),
    }
}

/// The `CURRENT` hint is untrusted input: whatever bytes end up there,
/// `read_hint` degrades to `Missing`, never an `Err` and never a wrong
/// `Current`. Every case below is planted raw (the public API only ever
/// writes the canonical 20-digit body) and all five share one volume,
/// each overwriting the last, to prove degrade-to-Missing is not a
/// one-shot fluke of a particular byte pattern.
///
/// Case (e) is here because a zero-byte body is exactly where a
/// range-bounded GET breaks this invariant: `GetRange::Bounded(0..21)`
/// is REFUSED by `object_store` with `InvalidGetRange::StartTooLarge`
/// when the object is shorter than the range start — true only for a
/// zero-byte object — surfacing as `Err(Backend(..))` instead of
/// `Missing`, and no byte range is satisfiable on a zero-length object
/// at all. `read_hint` (see its comment in `backend.rs`) therefore
/// issues no range: it gates on the advertised size, then walks a
/// bounded body.
#[tokio::test]
async fn advisory_hint_degrades_to_missing_on_every_garbage_body() {
    let (mem, store) = store();
    let key = StorePath::from("root/vol-g/CURRENT");

    // (a) non-UTF-8 bytes.
    mem.put(&key, vec![0xFF, 0xFE, 0xFD].into())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.read_hint("vol-g", None).await, Ok(HintRead::Missing));

    // (b) "42" — wrong width (not 20 digits).
    mem.put(&key, b"42".to_vec().into())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.read_hint("vol-g", None).await, Ok(HintRead::Missing));

    // (c) 20 bytes, one of them a letter.
    let mut with_letter = vec![b'0'; 19];
    with_letter.push(b'a');
    assert_eq!(with_letter.len(), 20);
    mem.put(&key, with_letter.into())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.read_hint("vol-g", None).await, Ok(HintRead::Missing));

    // (d) 20 digits, all nines — overflows u64 (u64::MAX is 20 digits
    // starting with 1).
    let overflow = "9".repeat(20);
    assert_eq!(overflow.len(), 20);
    mem.put(&key, overflow.into_bytes().into())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.read_hint("vol-g", None).await, Ok(HintRead::Missing));

    // (e) zero bytes — the range-refusal edge case `read_hint` has
    // to account for (see the doc comment above).
    mem.put(&key, Vec::new().into())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.read_hint("vol-g", None).await, Ok(HintRead::Missing));
}

/// The crash window between a successful root CAS and the hint write is
/// a DESIGNED state, not a corruption case: publish two roots, write the
/// hint for only the first, and confirm the reader's forward probe
/// (`get_root(hint + 1)`) finds the second without ever listing.
#[tokio::test]
async fn stale_hint_forward_probe_converges_without_list() {
    let (_mem, store) = store();
    assert_eq!(store.put_root("vol-5", 1, vec![1]).await, Ok(()));
    assert_eq!(store.put_root("vol-5", 2, vec![2]).await, Ok(()));
    // "Crash" before the hint update for seq 2 ever happens.
    assert_eq!(store.write_hint("vol-5", 1).await, Ok(()));

    assert!(matches!(
        store.read_hint("vol-5", None).await,
        Ok(HintRead::Current { seq: 1, .. })
    ));
    // Forward probe: hint + 1 exists, so the hint was stale.
    assert_eq!(store.get_root("vol-5", 2).await, Ok(Some(vec![2])));
}

#[tokio::test]
async fn max_seq_is_numeric_and_ignores_foreign_and_malformed_keys() {
    let (mem, store) = store();
    // InMemory lists in key order regardless of insertion order.
    // The ShuffledListing fixture exercises an unordered listing.
    for seq in [3u64, 1, 2, 10] {
        assert_eq!(store.put_root("vol-m", seq, vec![0]).await, Ok(()));
    }
    // CURRENT is present under the same prefix; it must not be mistaken
    // for a numbered root.
    assert_eq!(store.write_hint("vol-m", 3).await, Ok(()));

    // A foreign key under the prefix that isn't a seq at all.
    mem.put(
        &StorePath::from("root/vol-m/not-a-seq"),
        b"junk".to_vec().into(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));

    // A 19-digit key (too short) and a 21-digit key (too long) — both
    // excluded by the strict 20-digit parse, even though "too short"
    // would otherwise parse as a small, irrelevant number.
    let nineteen = "1".repeat(19);
    let twenty_one = "1".repeat(21);
    mem.put(
        &StorePath::from(format!("root/vol-m/{nineteen}")),
        Vec::new().into(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    mem.put(
        &StorePath::from(format!("root/vol-m/{twenty_one}")),
        Vec::new().into(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(store.max_seq("vol-m").await, Ok(Some(10)));
    assert_eq!(store.max_seq("vol-empty-for-max-seq").await, Ok(None));
}

/// A snapshot of an `InMemory` listing in a different order. The
/// `ObjectStore` default applies the offset to this same stream.
#[derive(Debug)]
struct ShuffledListing {
    inner: Arc<InMemory>,
    entries: Vec<ObjectMeta>,
}

impl std::fmt::Display for ShuffledListing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shuffled {}", self.inner)
    }
}

// The boxed signatures match ObjectStore's async methods.
type BoxFut<'a, T> = Pin<Box<dyn Future<Output = object_store::Result<T>> + Send + 'a>>;

impl ObjectStore for ShuffledListing {
    fn put_opts<'a, 'b, 'f>(
        &'a self,
        location: &'b StorePath,
        payload: PutPayload,
        opts: PutOptions,
    ) -> BoxFut<'f, PutResult>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        self.inner.put_opts(location, payload, opts)
    }

    fn put_multipart_opts<'a, 'b, 'f>(
        &'a self,
        location: &'b StorePath,
        opts: PutMultipartOptions,
    ) -> BoxFut<'f, Box<dyn MultipartUpload>>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        self.inner.put_multipart_opts(location, opts)
    }

    fn get_opts<'a, 'b, 'f>(
        &'a self,
        location: &'b StorePath,
        opts: GetOptions,
    ) -> BoxFut<'f, GetResult>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        self.inner.get_opts(location, opts)
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<StorePath>>,
    ) -> BoxStream<'static, object_store::Result<StorePath>> {
        self.inner.delete_stream(locations)
    }

    fn list(
        &self,
        prefix: Option<&StorePath>,
    ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        let entries: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| prefix.is_none_or(|prefix| entry.location.prefix_matches(prefix)))
            .cloned()
            .collect();
        Box::pin(ListingEntries(entries.into_iter()))
    }

    fn list_with_delimiter<'a, 'b, 'f>(
        &'a self,
        prefix: Option<&'b StorePath>,
    ) -> BoxFut<'f, ListResult>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        self.inner.list_with_delimiter(prefix)
    }

    fn copy_opts<'a, 'b, 'c, 'f>(
        &'a self,
        from: &'b StorePath,
        to: &'c StorePath,
        opts: CopyOptions,
    ) -> BoxFut<'f, ()>
    where
        'a: 'f,
        'b: 'f,
        'c: 'f,
        Self: 'f,
    {
        self.inner.copy_opts(from, to, opts)
    }
}

struct ListingEntries(std::vec::IntoIter<ObjectMeta>);

impl futures_core::Stream for ListingEntries {
    type Item = object_store::Result<ObjectMeta>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.next().map(Ok))
    }
}

#[tokio::test]
async fn max_seq_above_matches_full_max_in_shuffled_listings() {
    let vol = "vol-shuffled";
    let prefix = StorePath::from(format!("root/{vol}"));
    for seed in 0..16 {
        let (mem, _) = store();
        let mut rng = SeededRng::new(seed);
        let seqs: Vec<_> = (0..12).map(|i| i * 128 + 2 * rng.below(62) + 2).collect();
        let head = *seqs.last().unwrap();
        let keys = seqs.iter().map(|seq| format!("{prefix}/{seq:020}"));
        let noise = [
            format!("{prefix}/CURRENT"),
            format!("{prefix}/junk-{seed}"),
            format!("{prefix}/9999999999999999999"),
            format!("{prefix}/99999999999999999999"),
            format!("{prefix}/{:020}", 0),
            format!("{prefix}/{:020}", u64::MAX),
            format!("{prefix}/junk/{:020}", head + 2),
            format!("{prefix}/{:020}/junk", head + 4),
        ];
        for key in keys.chain(noise) {
            mem.put(&StorePath::from(key), Vec::new().into())
                .await
                .unwrap();
        }

        let mut entries = Vec::new();
        let mut listing = mem.list(Some(&prefix));
        while let Some(entry) = poll_fn(|cx| listing.as_mut().poll_next(cx)).await {
            entries.push(entry.unwrap());
        }
        for end in (1..entries.len()).rev() {
            let index = usize::try_from(rng.below(u64::try_from(end + 1).unwrap())).unwrap();
            entries.swap(end, index);
        }
        let store = GranaryStore::new(ShuffledListing {
            inner: mem,
            entries,
        });
        let full = store.max_seq(vol).await.unwrap();
        let floors = [0, head + 1, u64::MAX]
            .into_iter()
            .chain(seqs.iter().flat_map(|seq| [*seq, seq - 1]));
        for floor in floors {
            let bounded = store.max_seq_above(vol, floor).await;
            // The planted maximum also checks guards shared by both calls.
            assert_eq!(
                bounded,
                Ok(Some(head).filter(|seq| *seq > floor)),
                "seed {seed}, floor {floor}"
            );
            assert_eq!(
                bounded,
                Ok(full.filter(|seq| *seq > floor)),
                "seed {seed}, floor {floor}"
            );
        }
    }
}

#[tokio::test]
async fn bins_dedup_roundtrip_and_range_reads_exact_bytes() {
    let (_mem, store) = store();
    let data = sample_bytes(300);
    let digest = *GrainId::of(&data).digest();

    assert_eq!(store.put_bin(&digest, data.clone()).await, Ok(true));
    // Same digest again: dedup success, not an error, and not novel.
    assert_eq!(store.put_bin(&digest, data.clone()).await, Ok(false));

    assert_eq!(store.get_bin(&digest).await, Ok(data.clone()));

    let expected_slice = data
        .get(10..30)
        .unwrap_or_else(|| panic!("test buffer too short"))
        .to_vec();
    assert_eq!(
        store.get_bin_range(&digest, 10, 20).await,
        Ok(expected_slice)
    );

    let missing_digest = *GrainId::of(b"never uploaded").digest();
    assert_eq!(
        store.get_bin_range(&missing_digest, 0, 1).await,
        Err(RootStoreError::NotFound)
    );
}

#[tokio::test]
async fn meta_roundtrip_and_dedup() {
    let (_mem, store) = store();
    // Content-addressed pair: the id IS the hash of the bytes (the
    // put_meta contract; its debug_assert catches a synthetic pair).
    let bytes = b"meta object bytes".to_vec();
    let id = GrainId::of(&bytes);

    assert_eq!(store.put_meta("vol-8", &id, bytes.clone()).await, Ok(true));
    assert_eq!(store.put_meta("vol-8", &id, bytes.clone()).await, Ok(false));
    assert_eq!(store.get_meta("vol-8", &id).await, Ok(bytes));
}

// ------------------------------------------ bin-range offset overflow

/// `get_bin_range` must REFUSE an `offset` so large that `offset + len`
/// overflows `u64`, not panic. `Cargo.toml` sets
/// `overflow-checks = true`, so an unchecked `offset + u64::from(len)`
/// panics in release too — with the addition unchecked,
/// `get_bin_range(&digest, u64::MAX, 1)` was reproduced panicking at
/// `attempt to add with overflow`. No caller exists yet to hand this a
/// hostile offset (the mount read path is the intended one) — the API
/// exists to be called, and a decoded, fully-validated shard can carry
/// an unbounded `offset` per `binmap.rs`'s own contract, so the refusal
/// lives here regardless.
#[tokio::test]
async fn get_bin_range_refuses_offset_overflow_instead_of_panicking() {
    let (_mem, store) = store();
    // The digest need not exist: the overflow check runs BEFORE any
    // backend key is even constructed.
    let digest = *GrainId::of(b"a1 overflow probe").digest();
    assert_eq!(
        store.get_bin_range(&digest, u64::MAX, 1).await,
        Err(RootStoreError::RangeOverflow)
    );
}

// --------------------------------------- advisory hint body is bounded

/// The advisory-hint GET must never STREAM a mismatched body, not
/// merely be correct in its final answer — an attacker who replaces
/// `CURRENT` with an oversized body must not make every reader
/// download it whole before discovering it is garbage (the `Missing`
/// outcome is unchanged either way, which is exactly why a naive
/// assertion on the RESULT alone cannot distinguish bounded from
/// unbounded).
///
/// `read_hint` issues NO range: no byte range is
/// satisfiable on a zero-length representation, so a
/// ranged GET lets a 0-byte `CURRENT` wedge every
/// reader on a real HTTP backend. It gates on
/// `meta.size` and returns before touching the body at
/// all, so the assertion below holds with zero bytes
/// streamed — a STRONGER bound than a 21-byte range
/// would give. Read the name as "never streams a
/// mismatched body", not as evidence that a ranged GET
/// is issued. Anyone tempted to add a range here
/// should read `backend.rs`'s `read_hint` comment
/// first.
///
/// Proven with `object_store`'s own `ThrottledStore` — already a
/// transitive dependency through the `backend` feature's `tokio`
/// edge (`aws` → `aws-base` → `cloud-base` → `tokio`), so this adds
/// no new dependency. `ThrottledStore` sleeps `wait_get_per_byte`
/// for every byte actually STREAMED back through `get_opts`, making
/// elapsed time a direct, backend-agnostic proxy for how much of
/// the object was fetched: at 1ms/byte, a bounded 21-byte fetch
/// sleeps ~21ms, while an unbounded fetch of the 64 MiB body below
/// would sleep ~67,108,864ms (~18.6 hours). `tokio::time::timeout`
/// turns that would-be hang into a fast, clear test failure
/// instead.
#[tokio::test]
async fn advisory_hint_get_never_streams_a_mismatched_body() {
    let mem = Arc::new(InMemory::new());
    let key = StorePath::from("root/vol-huge-hint/CURRENT");
    let huge = vec![b'9'; 64 * 1024 * 1024];
    mem.put(&key, huge.into())
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let throttled = ThrottledStore::new(Arc::clone(&mem), ThrottleConfig::default());
    throttled.config_mut(|c| c.wait_get_per_byte = Duration::from_millis(1));
    let store = GranaryStore::new(throttled);

    match tokio::time::timeout(
        Duration::from_millis(500),
        store.read_hint("vol-huge-hint", None),
    )
    .await
    {
        Ok(result) => assert_eq!(
            result,
            Ok(HintRead::Missing),
            "an oversized body must still degrade to Missing, never Err"
        ),
        Err(elapsed) => panic!(
            "read_hint did not finish within 500ms at wait_get_per_byte=1ms ({elapsed}) — the \
             advisory GET streamed a body whose size the metadata already disqualified (an \
             unbounded fetch of this 64 MiB body would sleep ~18.6 hours here)"
        ),
    }
}

// ------------------------------------------------------------------- B

/// Part B: the bucket layout is an irreversible surface pinned by
/// NOTHING else in this suite — every other test writes and reads
/// through the same `GranaryStore` methods, so `split_at(2)` →
/// `split_at(3)`, `bins/` → `blobs/`, or dropping `{volume}` from the
/// meta path would leave the whole suite green. This test hardcodes
/// the expected key strings itself (its own hex loop, not `fanout()`)
/// and checks presence on the RAW `mem` handle, so a layout mutation
/// shows up as an object missing where the test expects it, not as a
/// round trip that still happens to work.
#[tokio::test]
async fn bucket_layout_paths_are_pinned_exactly() {
    fn hex_of(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    let (mem, store) = store();
    let vol = "vol-layout-pin-b";

    // bins/{2hex}/{hex} — the fanout split and the `bins/` prefix.
    let bin_bytes = sample_bytes(64);
    let bin_digest = *GrainId::of(&bin_bytes).digest();
    let bin_hex = hex_of(&bin_digest);
    assert_eq!(store.put_bin(&bin_digest, bin_bytes).await, Ok(true));
    let bin_key = format!("bins/{}/{bin_hex}", &bin_hex[..2]);
    assert!(
        mem.get(&StorePath::from(bin_key.clone())).await.is_ok(),
        "expected a bin at the literal path {bin_key}"
    );

    // meta/{volume}/{2hex}/{hex} — including VOLUME SCOPING, the
    // sharpest sub-case: invisible to the rest of the suite.
    let meta_bytes = b"pinned bucket layout meta probe".to_vec();
    let meta_id = GrainId::of(&meta_bytes);
    let meta_hex = hex_of(meta_id.digest());
    assert_eq!(store.put_meta(vol, &meta_id, meta_bytes).await, Ok(true));
    let meta_key = format!("meta/{vol}/{}/{meta_hex}", &meta_hex[..2]);
    assert!(
        mem.get(&StorePath::from(meta_key.clone())).await.is_ok(),
        "expected metadata at the literal path {meta_key}"
    );
    // Dropping volume scoping would land this at the unscoped path
    // instead — confirm it does not, closing the cross-volume
    // existence leak / per-volume-GC hazard by name.
    let unscoped_meta_key = format!("meta/{}/{meta_hex}", &meta_hex[..2]);
    assert!(
        mem.get(&StorePath::from(unscoped_meta_key.clone()))
            .await
            .is_err(),
        "metadata must NOT also land at the volume-unscoped path {unscoped_meta_key} — \
         that would merge every volume's metadata keyspace"
    );

    // root/{vol}/{seq:020} — the numbered root key.
    assert_eq!(store.put_root(vol, 1, vec![0xAB]).await, Ok(()));
    let root_key = format!("root/{vol}/00000000000000000001");
    assert!(
        mem.get(&StorePath::from(root_key.clone())).await.is_ok(),
        "expected a root at the literal path {root_key}"
    );

    // root/{vol}/CURRENT — the advisory hint.
    assert_eq!(store.write_hint(vol, 1).await, Ok(()));
    let hint_key = format!("root/{vol}/CURRENT");
    assert!(
        mem.get(&StorePath::from(hint_key.clone())).await.is_ok(),
        "expected the hint at the literal path {hint_key}"
    );
}

// ------------------------------------------------------------------- C

/// C2: `seq = u64::MAX` round-trips through every seq-carrying method —
/// measured true but pinned by no committed test, so
/// a narrowing regression (e.g. a cast to `u32` somewhere on the seq
/// path) would ship green.
///
/// **CHALLENGED AND KEPT.** Seq `u64::MAX` is reserved:
/// it may hold a root but may never be a HEAD, which is a
/// deliberate narrowing of exactly the thing this row guards. The
/// tripwire was not deleted and was not flipped — deleting it would
/// retire the u32-cast guard along with the rule that displaced it, and a
/// `u32` cast on the seq path is still a shipping defect. So:
///
/// - the `put_root` / `get_root` / hint round-trips at `u64::MAX` are
///   UNCHANGED and still pass — the exclusion is at head selection, and a
///   narrowing cast would still break them;
/// - only the `max_seq` row moved, to `u64::MAX - 1` — the top of the
///   USABLE range (`1 ..= u64::MAX - 1`), which is one below where it was
///   and still 20 digits, still `> u32::MAX`, so the cast it was placed
///   for is caught exactly as before;
/// - a new row asserts the SKIP itself, so the narrowing is pinned rather
///   than merely accommodated.
#[tokio::test]
async fn seq_u64_max_round_trips_through_root_and_hint() {
    let (_mem, store) = store();
    let vol = "vol-c2-seq-max";

    assert_eq!(store.put_root(vol, u64::MAX, vec![0xAB]).await, Ok(()));
    assert_eq!(store.get_root(vol, u64::MAX).await, Ok(Some(vec![0xAB])));
    // The retargeted tripwire: the highest seq a head may ever take.
    assert_eq!(store.put_root(vol, u64::MAX - 1, vec![0xAC]).await, Ok(()));
    assert_eq!(
        store.get_root(vol, u64::MAX - 1).await,
        Ok(Some(vec![0xAC]))
    );
    assert_eq!(store.max_seq(vol).await, Ok(Some(u64::MAX - 1)));

    assert_eq!(store.write_hint(vol, u64::MAX).await, Ok(()));
    match store.read_hint(vol, None).await {
        Ok(HintRead::Current { seq, .. }) => assert_eq!(seq, u64::MAX),
        other => panic!("want Current{{seq:u64::MAX,..}}, got {other:?}"),
    }
}

/// C2b: the narrowing C2 records — `max_seq` SKIPS a root planted at the
/// reserved `u64::MAX`, and answers nothing at all when that
/// is the volume's only key.
///
/// The measured state before this rule: `max_seq` answered
/// `Ok(Some(18446744073709551615))` and the volume could never be
/// published to again, because the head is the numeric maximum over keys
/// that exist, a create-only PUT never releases one, and there is no
/// higher seq. One unauthenticated `PUT root` terminated the sequence
/// permanently.
#[tokio::test]
async fn max_seq_skips_a_root_planted_at_the_reserved_top_of_the_range() {
    let (_mem, store) = store();
    let vol = "vol-c2b-seq-max-skip";

    assert_eq!(store.put_root(vol, u64::MAX, vec![0xAB]).await, Ok(()));
    assert_eq!(
        store.max_seq(vol).await,
        Ok(None),
        "a volume whose only key is the reserved u64::MAX has NO head — before max_seq skipped it, this \
         answered Some(u64::MAX) and the volume was unusable forever"
    );
    assert_eq!(
        store.get_root(vol, u64::MAX).await,
        Ok(Some(vec![0xAB])),
        "the exclusion is at the head, not at the key: the planted bytes stay readable"
    );

    // The head falls back to the next REAL seq rather than to nothing.
    assert_eq!(store.put_root(vol, 3, vec![0xCD]).await, Ok(()));
    assert_eq!(store.max_seq(vol).await, Ok(Some(3)));
}

/// C3: an end-to-end sanity check that `HintToken("")` (the shape
/// `unwrap_or_default()` produces when a backend omits `ETag`s) does not
/// error or misbehave through the full `read_hint` path. This does
/// NOT by itself pin the empty-token guard — verified by mutation
/// (dropping `backend.rs`'s `conditional_token` filter): `InMemory`
/// never mints an empty real `ETag`, so an unfiltered
/// `If-None-Match: ""` never accidentally matches one, and this test
/// stays green with or without the guard. The guard's actual pin is
/// `backend::tests::conditional_token_treats_empty_as_absent`, a unit
/// test on the extracted pure function, in `backend.rs` itself.
#[tokio::test]
async fn empty_hint_token_is_treated_as_no_cached_token() {
    let (_mem, store) = store();
    let vol = "vol-c3-empty-token";
    assert_eq!(store.write_hint(vol, 1).await, Ok(()));

    let empty = HintToken(String::new());
    match store.read_hint(vol, Some(&empty)).await {
        Ok(HintRead::Current { seq: 1, .. }) => {}
        other => panic!(
            "an empty HintToken must be treated as no cached token (revalidation \
             skipped), got {other:?}"
        ),
    }
}

/// C4: `get_bin_range` returns FEWER bytes than requested when the
/// range overhangs the object, rather than an error — pinned as
/// CURRENT behaviour, a deliberate choice over turning it into an
/// error: the codec's
/// declared-length check already refuses a short frame downstream, so
/// an error here would duplicate a check that has no caller of its
/// own yet to benefit from the duplication.
#[tokio::test]
async fn get_bin_range_short_reads_rather_than_errors_when_the_range_overhangs() {
    let (_mem, store) = store();
    let data = sample_bytes(100);
    let digest = *GrainId::of(&data).digest();
    assert_eq!(store.put_bin(&digest, data.clone()).await, Ok(true));

    // (90, 50) on a 100-byte object: the range overhangs by 40 bytes.
    let got = store
        .get_bin_range(&digest, 90, 50)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let expected = data
        .get(90..100)
        .unwrap_or_else(|| panic!("test buffer too short"));
    assert_eq!(
        got, expected,
        "an overhanging range must return the available tail, not pad or fail"
    );
    assert_eq!(got.len(), 10, "10 bytes back, not the 50 requested");
}

/// The OTHER half of the range contract, which the short-read test above
/// does not reach: a range whose START is at or past the end of the
/// object, and a zero-length range, are backend range ERRORS — not empty
/// successes. `granary_core::binstore::BinStore::get_bin_range` pins
/// both halves normatively, and this is the evidence for the half that
/// is easy to assume wrong: a fake that clamps everywhere agrees with
/// the backend on `(90, 50)` and disagrees at exactly the offsets an
/// adversarial extent produces.
#[tokio::test]
async fn get_bin_range_errors_at_or_past_the_end_and_on_a_zero_length_range() {
    let (_mem, store) = store();
    let data = sample_bytes(100);
    let digest = *GrainId::of(&data).digest();
    assert_eq!(store.put_bin(&digest, data).await, Ok(true));

    for (offset, len, why) in [
        (200u64, 8u32, "wholly past the end"),
        (100, 8, "starting exactly AT the end"),
        (10, 0, "zero-length range"),
    ] {
        let got = store.get_bin_range(&digest, offset, len).await;
        assert!(
            matches!(got, Err(RootStoreError::Backend(_))),
            "({offset}, {len}) — {why} — must be a range error, got {got:?}"
        );
    }
}

/// THE NAME→KEY BOUNDARY fails closed. The
/// `RootStore` trait takes `volume: &str`, so nothing in the type
/// system stops a caller — the server relaying a client-supplied
/// name is the one this exists for — from handing over a string that
/// reaches outside its own prefix. `object_store`'s `Path::from`
/// NORMALISES rather than refuses (the module doc's aliasing note), so
/// `"a/b"` would silently address `root/a/b/…`. Every volume-taking
/// method must refuse before the name becomes addressing.
///
/// Asserted per METHOD, not once: a guard added to `put_root` alone
/// would leave the read and hint paths open, and each method builds its
/// own key.
#[tokio::test]
async fn every_volume_taking_method_refuses_an_invalid_name() {
    let (_mem, store) = store();
    let id = GrainId::of(b"probe");

    // Each of these would ALIAS into another keyspace or a normalised
    // one if it ever reached `Path::from`.
    for bad in [
        "a/b",
        "a//b",
        "../escape",
        "",
        "UPPER",
        "trailing-",
        "-lead",
    ] {
        assert!(
            matches!(
                store.put_root(bad, 1, vec![0xAA]).await,
                Err(RootStoreError::InvalidVolume { .. })
            ),
            "put_root({bad:?}) must refuse"
        );
        assert!(
            matches!(
                store.get_root(bad, 1).await,
                Err(RootStoreError::InvalidVolume { .. })
            ),
            "get_root({bad:?}) must refuse"
        );
        assert!(
            matches!(
                store.read_hint(bad, None).await,
                Err(RootStoreError::InvalidVolume { .. })
            ),
            "read_hint({bad:?}) must refuse"
        );
        assert!(
            matches!(
                store.write_hint(bad, 1).await,
                Err(RootStoreError::InvalidVolume { .. })
            ),
            "write_hint({bad:?}) must refuse"
        );
        assert!(
            matches!(
                store.max_seq(bad).await,
                Err(RootStoreError::InvalidVolume { .. })
            ),
            "max_seq({bad:?}) must refuse"
        );
        assert!(
            matches!(
                store.put_meta(bad, &id, b"probe".to_vec()).await,
                Err(RootStoreError::InvalidVolume { .. })
            ),
            "put_meta({bad:?}) must refuse"
        );
        assert!(
            matches!(
                store.get_meta(bad, &id).await,
                Err(RootStoreError::InvalidVolume { .. })
            ),
            "get_meta({bad:?}) must refuse"
        );
    }

    // And a VALID name is unaffected — the guard refuses, it does not
    // block (a guard that refused everything would pass every
    // assertion above).
    assert_eq!(
        store.put_root("vol-boundary-ok", 1, vec![0xAA]).await,
        Ok(())
    );
    assert_eq!(
        store.get_root("vol-boundary-ok", 1).await,
        Ok(Some(vec![0xAA]))
    );
}

/// A planted seq-0 root object must not become the head. Seq 0 is never
/// valid (`root.rs` refuses it at encode and decode), so a
/// `…/00000000000000000000` object an attacker can PUT would otherwise
/// make `max_seq` resolve a head that cannot decode, blocking the first
/// publish to a fresh volume. `read_hint` already carries this rule;
/// the LIST path needed it too.
#[tokio::test]
async fn a_planted_seq_zero_root_is_not_the_head() {
    let (mem, store) = store();
    let vol = "vol-seq-zero";

    // Nothing published yet, but seq 0 is squatted.
    mem.put(
        &StorePath::from(format!("root/{vol}/00000000000000000000")),
        vec![0xAA].into(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        store.max_seq(vol).await,
        Ok(None),
        "a seq-0 object must not present itself as a head"
    );

    // A real publish still resolves normally alongside it.
    assert_eq!(store.put_root(vol, 1, vec![0xBB]).await, Ok(()));
    assert_eq!(store.max_seq(vol).await, Ok(Some(1)));
}

// ------------------------------------------------------- BinStore trait

/// Round-trip through the TRAIT, never through the inherent methods.
/// The body is GENERIC on purpose: inside it only `BinStore`'s promises
/// are known, so a delegation that stopped reaching the adapter — or a
/// dropped impl — fails here, while the same calls written against the
/// concrete `GranaryStore` would silently resolve to the inherent
/// methods and stay green.
async fn round_trip_through_the_trait<B: BinStore>(store: &B) {
    let body = sample_bytes(100);
    let digest = *GrainId::of(&body).digest();
    assert_eq!(store.put_bin(&digest, body.clone()).await, Ok(true));
    // Content-addressed: a second write is SUCCESS, reported as "not
    // novel".
    assert_eq!(store.put_bin(&digest, body.clone()).await, Ok(false));
    assert_eq!(store.get_bin_range(&digest, 0, 100).await, Ok(body.clone()));
    assert_eq!(
        store.get_bin_range(&digest, 10, 5).await,
        Ok(body.get(10..15).unwrap_or_default().to_vec())
    );

    let meta = b"a meta object through the trait".to_vec();
    let id = GrainId::of(&meta);
    assert_eq!(
        store.put_meta("vol-trait", &id, meta.clone()).await,
        Ok(true)
    );
    assert_eq!(
        store.put_meta("vol-trait", &id, meta.clone()).await,
        Ok(false)
    );
    assert_eq!(store.get_meta("vol-trait", &id).await, Ok(meta));
}

#[tokio::test]
async fn bin_store_trait_round_trips_bins_and_meta() {
    let (_mem, store) = store();
    round_trip_through_the_trait(&store).await;
}

/// The REAL adapter runs the same shared conformance body the in-core
/// fake runs. Everything `BinStore`'s docs pin — the range semantic on
/// both sides of the boundary, `NotFound` on both read paths, per-volume
/// namespacing, and `checked_volume` on BOTH volume-taking methods — is
/// asserted here through the bound rather than against the inherent
/// methods, because the bound is the surface a simulator's fake has to
/// match. A rule that holds in one implementation and not the other
/// cannot pass both sites.
#[tokio::test]
async fn adapter_satisfies_the_shared_binstore_conformance_suite() {
    let (_mem, store) = store();
    granary_core::testkit::binstore_conformance(&store).await;
}

/// The same closure for `RootStore`, which matters more than the
/// `BinStore` one: every CAS scenario the sim runs — the crash sweep,
/// re-run convergence, concurrent publishers, the ambiguous PUT whose
/// probe fails — is a `put_root`/`get_root`/`max_seq` property, so a
/// fake that diverges from this adapter proves things about the fake.
/// The seq-0 rule is the proof that the class is real: it lived only
/// here while the in-core fake implemented neither half.
#[tokio::test]
async fn adapter_satisfies_the_shared_rootstore_conformance_suite() {
    let (_mem, store) = store();
    granary_core::testkit::rootstore_conformance(&store).await;
}

/// `checked_volume` is the TRAIT's obligation, not the adapter's:
/// `object_store::path::Path::from` normalises `a/b`,
/// `a//b` and `a/b/` into one keyspace, so a name that is not DNS-1123
/// must never become a key. Reached through the bound so the trait
/// method is what is being asked, not the inherent one.
async fn trait_put_meta_refuses_a_bad_volume<B: BinStore>(store: &B) {
    let bytes = b"never lands".to_vec();
    let id = GrainId::of(&bytes);
    assert!(
        matches!(
            store.put_meta("a/b", &id, bytes.clone()).await,
            Err(RootStoreError::InvalidVolume { .. })
        ),
        "put_meta accepted a volume name that never becomes a key"
    );
    // Not a blanket refuser: a DNS-1123 name still stores, and stores as
    // NOVEL — so the refused call above wrote nothing anywhere.
    assert_eq!(store.put_meta("a-b", &id, bytes).await, Ok(true));
}

#[tokio::test]
async fn bin_store_trait_put_meta_refuses_an_invalid_volume_name() {
    let (_mem, store) = store();
    trait_put_meta_refuses_a_bad_volume(&store).await;
}

/// The trait and the inherent methods must address ONE keyspace. The
/// round trip above writes and reads through the same seam, so it stays
/// green if the delegation reached a consistently-wrong key — the seam
/// would then be self-consistent and disagree with every other caller
/// (`publish`, the `MinIO` lane, `bucket_layout_paths_are_pinned_exactly`).
/// Crossing the two is what pins it: written inherently, read through
/// the bound.
async fn read_back_through_the_trait<B: BinStore>(
    store: &B,
    digest: &[u8; DIGEST_LEN],
    volume: &str,
    id: &GrainId,
    len: u32,
) -> (Vec<u8>, Vec<u8>) {
    let bin = store
        .get_bin_range(digest, 0, len)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let meta = store
        .get_meta(volume, id)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    (bin, meta)
}

#[tokio::test]
async fn the_trait_reads_the_keyspace_the_inherent_methods_write() {
    let (_mem, store) = store();
    let body = sample_bytes(64);
    let digest = *GrainId::of(&body).digest();
    let meta = b"written through the inherent methods".to_vec();
    let id = GrainId::of(&meta);

    // Written INHERENTLY (the path `publish` and the MinIO lane use)...
    assert_eq!(
        GranaryStore::put_bin(&store, &digest, body.clone()).await,
        Ok(true)
    );
    assert_eq!(
        GranaryStore::put_meta(&store, "vol-cross", &id, meta.clone()).await,
        Ok(true)
    );
    // ...and found by the TRAIT at the same keys.
    assert_eq!(
        read_back_through_the_trait(&store, &digest, "vol-cross", &id, 64).await,
        (body, meta)
    );

    // The other direction: a trait write is a dedup hit for the
    // inherent reader, which can only be true if both name one key.
    let other = sample_bytes(32);
    let other_digest = *GrainId::of(&other).digest();
    assert_eq!(
        BinStore::put_bin(&store, &other_digest, other.clone()).await,
        Ok(true)
    );
    assert_eq!(
        GranaryStore::put_bin(&store, &other_digest, other.clone()).await,
        Ok(false)
    );
    assert_eq!(
        GranaryStore::get_bin(&store, &other_digest).await,
        Ok(other)
    );
}

// ------------------------------------------ range-read buffer capacity

/// A range read hands back a buffer sized to what ARRIVED, not to
/// wherever the growth curve landed.
///
/// **The residency is not the extent, and the gap is the finding.** The
/// walk reserves one frame (`range_alloc_hint`) and then grows by
/// DOUBLING, and `Bytes::from(Vec<u8>)` shrinks only on an exact
/// `len == capacity` fit — so an extent one byte past a frame comes back
/// in a buffer twice its size, and the server that hands it to the
/// transport holds the capacity, not the length, for as long as flow
/// control takes. At the declared maximum extent the measured factor is
/// ~1.72×; a server accounting for what it holds would have to charge
/// for the overshoot, and removing it here is cheaper than charging for
/// it.
///
/// The width is ONE BYTE past the reservation on purpose: that is the
/// smallest input that forces a single doubling, so this row fails on
/// the growth curve rather than on a large allocation, and it fails by
/// exactly the factor the closing `shrink_to_fit` removes.
#[tokio::test]
async fn a_range_read_returns_an_exactly_sized_buffer() {
    // `FRAME_COMP_MAX` is what `range_alloc_hint` clamps the reservation
    // to; naming it through the format crate rather than as a literal
    // keeps this row pinned to the constant that sizes the buffer.
    let width =
        usize::try_from(granary_core::binfmt::FRAME_COMP_MAX).unwrap_or_else(|e| panic!("{e}")) + 1;
    let (_mem, store) = store();
    let data: Vec<u8> = (0..width)
        .map(|i| u8::try_from(i % 250).unwrap_or_else(|e| panic!("{e}")))
        .collect();
    let digest = *GrainId::of(&data).digest();
    assert_eq!(store.put_bin(&digest, data.clone()).await, Ok(true));

    let len = u32::try_from(width).unwrap_or_else(|e| panic!("{e}"));
    let got = store
        .get_bin_range(&digest, 0, len)
        .await
        .unwrap_or_else(|e| panic!("the range must be served: {e:?}"));

    assert_eq!(got.len(), width, "the extent itself must be intact");
    assert_eq!(
        got.capacity(),
        got.len(),
        "a range read reserved {} and delivered {}: the caller holds the \
         capacity resident, not the length",
        got.capacity(),
        got.len()
    );
}
