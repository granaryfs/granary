// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

// This file uses `granary_store::backend` and `object_store` directly,
// neither of which exists without the `backend` feature.
#![cfg(feature = "backend")]

//! Bounded reads: no `GranaryStore` read path may stream or allocate an
//! unbounded object out of the bucket.
//!
//! **The in-memory backend cannot reach these bypasses.** It reports
//! truthful metadata, honours ranges and returns finite listings, so a
//! test written only against it exercises the honest path and proves
//! nothing about the dishonest one. The scenarios that need a dishonest
//! backend use [`HostileStore`], a configurable wrapper around the same
//! `InMemory` handle.

use granary_core::binfmt::BIN_MAX_BYTES;
use granary_core::binmap::{BIN_TABLE_MAX_BINS, SHARD_MAX_BYTES, encode_bin_table};
use granary_core::hash::{DIGEST_LEN, GRAIN_ID_BINARY_LEN, GrainId};
use granary_core::rootstore::{RefusalKind, RootStore, RootStoreError, SEQ_KEY_DIGITS};
use granary_core::sheaf::{
    SHEAF_FIXED_HEADER_LEN, SHEAF_MAX_OPS, SheafDoc, SheafOp, Timestamp, encode_sheaf,
};
use granary_store::backend::{GranaryStore, META_MAX_BYTES, ROOT_MAX_BYTES};
use object_store::memory::InMemory;
use object_store::path::Path as StorePath;
use object_store::{
    GetOptions, GetResult, GetResultPayload, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    ObjectStoreExt, PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

/// A fresh in-memory backend plus a raw handle to the same store, for
/// planting bytes `GranaryStore`'s own API cannot produce.
fn fresh() -> (Arc<InMemory>, GranaryStore<Arc<InMemory>>) {
    let mem = Arc::new(InMemory::new());
    let store = GranaryStore::new(Arc::clone(&mem));
    (mem, store)
}

/// The `ab/abcd…` fanout segment, spelled out here rather than reused
/// from the adapter: these tests plant objects at literal keys, so the
/// key must be built independently of the code under test.
fn fanout_hex(digest: &[u8; DIGEST_LEN]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(DIGEST_LEN * 2);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    format!("{}/{hex}", &hex[..2])
}

/// Plant `len` bytes at `key` through the raw handle.
async fn plant(mem: &InMemory, key: &str, len: usize) {
    plant_bytes(mem, key, vec![0x5A; len]).await;
}

/// Plant EXACTLY these bytes at `key` through the raw handle — for the
/// cases where the content matters, not just its length.
async fn plant_bytes(mem: &InMemory, key: &str, bytes: Vec<u8>) {
    mem.put(&StorePath::from(key), bytes.into())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
}

/// Drive a future to completion with a no-op waker, COUNTING the
/// `Pending`s on the way. That count is how many times the future handed
/// the thread back — the property a cooperative walk owes its executor,
/// and one that no end-to-end outcome can show.
///
/// Safe to spin here because every store this file drives is in-memory:
/// each poll is `Ready` except at a deliberate yield, so the loop is not
/// waiting on anything external.
fn poll_to_completion<F: Future>(fut: F) -> (F::Output, u32) {
    let mut fut = Box::pin(fut);
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut pends: u32 = 0;
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return (v, pends),
            Poll::Pending => pends = pends.saturating_add(1),
        }
    }
}

/// Assert a read was refused by the bound. Takes the BYTE COUNT rather
/// than the bytes: a failure here would otherwise render a multi-megabyte
/// body into the test log, which is exactly the payload these tests plant.
#[track_caller]
fn assert_refused(got: &Result<usize, RootStoreError>, what: &str) {
    assert!(
        matches!(got, Err(RootStoreError::RefusedResponse { .. })),
        "{what} must be refused by the read bound, got {got:?}"
    );
}

// ------------------------------------------------- the hostile backend

/// How [`HostileStore`] misbehaves. Every field is a SEPARATE lie, so one
/// wrapper covers every scenario that the truthful in-memory backend
/// cannot reach.
#[derive(Debug, Default, Clone, Copy)]
struct Hostility {
    /// Advertise this `meta.size` instead of the object's real length.
    /// This is the lie the advertised-size gate trusts.
    lie_size: Option<u64>,
    /// Drop the caller's range and fetch the WHOLE object. Setting
    /// `GetOptions.range` is a REQUEST, not a guarantee, and this is the
    /// backend that treats it as such.
    ignore_range: bool,
    /// Cut the body into chunks of this size before streaming it. A real
    /// HTTP backend delivers a body in read-buffer-sized pieces; a
    /// wrapper that yields one giant `Bytes` would instead be modelling
    /// the out-of-scope in-process adversary.
    chunk: usize,
    /// Report this exact `(start, end)` as the response's `range`
    /// instead of the honest one. The extent gate reads `r.range` and
    /// nothing else, so this is the only lie it can be shown.
    report_range: Option<(u64, u64)>,
    /// Stream NOTHING, whatever the object holds — the half a
    /// zero-width extent report needs to become an empty SUCCESS rather
    /// than a transfer-bound refusal.
    empty_body: bool,
    /// Prepend this many ZERO-LENGTH chunks to the body. A byte counter
    /// never moves on these, so they are the response that makes a
    /// size-bounded walk run forever.
    empty_chunks: u32,
    /// INTERLEAVE this many zero-length chunks before every body chunk,
    /// rather than prepending them all in one run. Paired with
    /// `chunk: 1` it is "this many empties between every byte" — the
    /// shape that tells a CUMULATIVE allowance apart from a consecutive
    /// one, which `empty_chunks` alone cannot, since an unbroken run
    /// trips either counter.
    empties_per_chunk: u32,
}

/// A response body that yields pre-cut chunks and COUNTS what it has
/// handed over — BYTES and CHUNKS separately. The counts are what make
/// the bounds observable: a test that only checks for an error passes
/// whether or not the reader stopped early, and a byte count alone
/// cannot see a walk that spun on zero-length chunks.
///
/// Generic in the chunk type so this file never has to name `bytes::Bytes`
/// — the `bytes` crate is `object_store`'s dependency, not granary's, and
/// inference supplies the type at the one construction site.
struct CountingChunks<T> {
    chunks: std::vec::IntoIter<T>,
    bytes: Arc<AtomicU64>,
    chunk_count: Arc<AtomicU64>,
}

impl<T: AsRef<[u8]> + Unpin> futures_core::Stream for CountingChunks<T> {
    type Item = object_store::Result<T>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = self.get_mut();
        match me.chunks.next() {
            Some(chunk) => {
                let n = u64::try_from(chunk.as_ref().len()).unwrap_or(u64::MAX);
                me.bytes.fetch_add(n, Ordering::SeqCst);
                me.chunk_count.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Some(Ok(chunk)))
            }
            None => Poll::Ready(None),
        }
    }
}

/// A configurably dishonest `ObjectStore` over the same `InMemory`
/// handle. Only `get_opts` misbehaves; everything else delegates.
///
/// Written with hand-desugared `async_trait` signatures rather than the
/// `async-trait` proc-macro: the pass-through methods return exactly the
/// boxed future the inner store already produces, so delegation is a
/// direct call and the crate needs no proc-macro dev-dependency.
#[derive(Debug)]
struct HostileStore {
    inner: Arc<InMemory>,
    how: Hostility,
    bytes: Arc<AtomicU64>,
    chunk_count: Arc<AtomicU64>,
}

impl std::fmt::Display for HostileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostileStore({:?})", self.how)
    }
}

/// The shape `#[async_trait]` generates for `ObjectStore`'s async methods.
type BoxFut<'a, T> = Pin<Box<dyn Future<Output = object_store::Result<T>> + Send + 'a>>;

impl ObjectStore for HostileStore {
    fn get_opts<'a, 'b, 'f>(
        &'a self,
        location: &'b StorePath,
        options: GetOptions,
    ) -> BoxFut<'f, GetResult>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        let how = self.how;
        let bytes = Arc::clone(&self.bytes);
        let chunk_count = Arc::clone(&self.chunk_count);
        let inner = Arc::clone(&self.inner);
        let location = location.clone();
        Box::pin(async move {
            let asked = if how.ignore_range {
                GetOptions {
                    range: None,
                    ..options
                }
            } else {
                options
            };
            let r = inner.get_opts(&location, asked).await?;
            // Everything but the payload is preserved verbatim: this
            // backend lies about SIZE and about honouring the range, and
            // about nothing else.
            let (meta, range, attributes, extensions) = (
                r.meta.clone(),
                r.range.clone(),
                r.attributes.clone(),
                r.extensions.clone(),
            );
            let whole = r.bytes().await?;
            let step = how.chunk.max(1);
            let mut chunks = Vec::new();
            for _ in 0..how.empty_chunks {
                chunks.push(whole.slice(0..0));
            }
            if !how.empty_body {
                let mut at = 0usize;
                while at < whole.len() {
                    let end = at.saturating_add(step).min(whole.len());
                    for _ in 0..how.empties_per_chunk {
                        chunks.push(whole.slice(0..0));
                    }
                    chunks.push(whole.slice(at..end));
                    at = end;
                }
            }
            Ok(GetResult {
                payload: GetResultPayload::Stream(Box::pin(CountingChunks {
                    chunks: chunks.into_iter(),
                    bytes,
                    chunk_count,
                })),
                meta: ObjectMeta {
                    size: how.lie_size.unwrap_or(meta.size),
                    ..meta
                },
                range: how.report_range.map_or(range, |(s, e)| s..e),
                attributes,
                extensions,
            })
        })
    }

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

    fn delete_stream(
        &self,
        locations: futures_core::stream::BoxStream<'static, object_store::Result<StorePath>>,
    ) -> futures_core::stream::BoxStream<'static, object_store::Result<StorePath>> {
        self.inner.delete_stream(locations)
    }

    fn list(
        &self,
        prefix: Option<&StorePath>,
    ) -> futures_core::stream::BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
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
        options: object_store::CopyOptions,
    ) -> BoxFut<'f, ()>
    where
        'a: 'f,
        'b: 'f,
        'c: 'f,
        Self: 'f,
    {
        self.inner.copy_opts(from, to, options)
    }
}

/// A `GranaryStore` over a dishonest backend, plus the raw handle for
/// planting and the counters that make "how much did the walk take"
/// observable.
struct Hostile {
    mem: Arc<InMemory>,
    /// Body bytes the backend handed over.
    bytes: Arc<AtomicU64>,
    /// Body chunks the backend handed over — the observable that moves
    /// when a walk spins on zero-length chunks and `bytes` does not.
    chunks: Arc<AtomicU64>,
    store: GranaryStore<HostileStore>,
}

fn hostile(how: Hostility) -> Hostile {
    let mem = Arc::new(InMemory::new());
    let bytes = Arc::new(AtomicU64::new(0));
    let chunks = Arc::new(AtomicU64::new(0));
    let store = GranaryStore::new(HostileStore {
        inner: Arc::clone(&mem),
        how,
        bytes: Arc::clone(&bytes),
        chunk_count: Arc::clone(&chunks),
    });
    Hostile {
        mem,
        bytes,
        chunks,
        store,
    }
}

// ------------------------------------------- whole-object cap boundary

/// `get_root`'s cap is [`ROOT_MAX_BYTES`]. Both directions: one byte
/// over is refused, and exactly at the cap is ACCEPTED — a cap off by
/// one rejects legal data, and only the accept half catches that.
#[tokio::test]
async fn get_root_refuses_over_the_cap_and_accepts_exactly_at_it() {
    let cap = usize::try_from(ROOT_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));

    let (mem, store) = fresh();
    plant(&mem, "root/vol-cap/00000000000000000001", cap + 1).await;
    assert_refused(
        &store
            .get_root("vol-cap", 1)
            .await
            .map(|b| b.map_or(0, |v| v.len())),
        "a root one byte over the cap",
    );

    let (mem, store) = fresh();
    plant(&mem, "root/vol-cap/00000000000000000001", cap).await;
    let got = store.get_root("vol-cap", 1).await;
    assert_eq!(
        got.map(|b| b.map(|v| v.len())),
        Ok(Some(cap)),
        "a root of exactly ROOT_MAX_BYTES is legal data and must be returned whole"
    );
}

/// `get_meta`'s cap is [`META_MAX_BYTES`], derived from the largest of
/// the FOUR kinds it reads. It is NOT `SHARD_MAX_BYTES`: that is the
/// budget core spends on a bin table's digest array alone, so a maximal
/// TABLE — header included — is 14 bytes larger, which
/// `get_meta_returns_a_maximal_bin_table` measures.
///
/// The refuse direction advertises `cap + 1` over a SMALL body rather
/// than planting a 16 MiB object. `meta.size` is the gate's only input
/// either way, so nothing is weakened, and a truthful 16 MiB plant would
/// cost three copies of it for no additional decision.
#[tokio::test]
async fn get_meta_refuses_over_the_cap_and_accepts_exactly_at_it() {
    let cap = usize::try_from(META_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let id = GrainId::of(b"a meta object whose bytes are not what is planted");
    let key = format!("meta/vol-cap/{}", fanout_hex(id.digest()));

    let h = hostile(Hostility {
        lie_size: Some(META_MAX_BYTES + 1),
        chunk: READ_BUFFER,
        ..Hostility::default()
    });
    plant(&h.mem, &key, 64).await;
    assert_refused(
        &h.store.get_meta("vol-cap", &id).await.map(|v| v.len()),
        "a meta object advertising one byte over the cap",
    );

    let (mem, store) = fresh();
    plant(&mem, &key, cap).await;
    assert_eq!(
        store.get_meta("vol-cap", &id).await.map(|v| v.len()),
        Ok(cap),
        "a meta object of exactly META_MAX_BYTES is legal data"
    );
}

/// The largest metadata object the format admits is a MAXIMAL BIN
/// TABLE, and this MEASURES it rather than deriving it a second time —
/// the same discipline `granary_core::root::tests::a_maximal_v1_root_encodes_inside_the_cap`
/// applies to a root.
///
/// It is the bin table and not a shard because the table's fixed header
/// sits OUTSIDE the digest array: `BIN_TABLE_MAX_BINS × DIGEST_LEN` is
/// exactly `SHARD_MAX_BYTES`, so the encoded object is that plus the
/// 14-byte header. A `get_meta` capped at `SHARD_MAX_BYTES` therefore
/// refuses a legal maximal table by 14 bytes — silently, and only once a
/// volume reaches the ceiling the format declares.
#[tokio::test]
async fn get_meta_returns_a_maximal_bin_table() {
    let bins: Vec<[u8; DIGEST_LEN]> = (0..BIN_TABLE_MAX_BINS)
        .map(|i| {
            let mut d = [0u8; DIGEST_LEN];
            let (head, _) = d.split_at_mut(4);
            head.copy_from_slice(&i.to_be_bytes());
            d
        })
        .collect();
    let table = encode_bin_table(&bins).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        table.len(),
        14 + 262_144 * 32,
        "the measured maximal bin table disagrees with the derivation in META_MAX_BYTES' docs"
    );
    assert!(
        u64::try_from(table.len()).unwrap_or(u64::MAX) > SHARD_MAX_BYTES,
        "a maximal bin table is LARGER than SHARD_MAX_BYTES — that is the whole point of this test"
    );

    let id = GrainId::of(&table);
    let want = table.len();
    let key = format!("meta/vol-table/{}", fanout_hex(id.digest()));
    let (mem, store) = fresh();
    plant_bytes(&mem, &key, table).await;
    // Length and DIGEST, never the bytes themselves: a failed
    // `assert_eq!` on the vectors renders eight megabytes into the log.
    match store.get_meta("vol-table", &id).await {
        Ok(got) => {
            assert_eq!(got.len(), want);
            assert_eq!(
                GrainId::of(&got),
                id,
                "the returned maximal bin table is not the planted one"
            );
        }
        Err(e) => panic!("a maximal bin table is legal metadata and must be readable, got {e:?}"),
    }
}

/// The FOURTH kind `get_meta` is handed. A sheaf is a DIRECTLY-ADDRESSED
/// meta object — `publish` writes it with `put_meta` and `resolve` reads
/// it back with `get_meta`, exactly as they do the binmap index — so
/// [`META_MAX_BYTES`] must admit a maximal one.
///
/// The MEASURED half of the sheaf row in that constant's derivation
/// table, the way `get_meta_returns_a_maximal_bin_table` is the measured
/// half of the bin table's: it ENCODES a maximal sheaf — a present
/// parent and `SHEAF_MAX_OPS` ops — rather than deriving the number a
/// second time.
///
/// A maximal sheaf is ~1 KiB today, so this test passes with an enormous
/// margin and would keep passing on almost any cap. That is the point of
/// its companion: the derivation asserted beside `META_MAX_BYTES` is what
/// refuses a WIDENED sheaf bound at build time, and this test is what
/// says the two numbers describe the same object.
#[tokio::test]
async fn get_meta_returns_a_maximal_sheaf() {
    let doc = SheafDoc {
        // A PRESENT parent: the widest of the two encodings, since an
        // absent one writes a bare presence byte and nothing after it.
        parent: Some(GrainId::of(b"the sheaf one commit below this one")),
        manifest_root: GrainId::of(b"the manifest root this commit published"),
        timestamp: Timestamp {
            secs: 1_760_000_000,
            nanos: 123_456_789,
        },
        ops: vec![SheafOp::PublishTree; SHEAF_MAX_OPS as usize],
    };
    // A COMPILE-TIME TRIPWIRE, and it guards the derivation rather than
    // this test. `PublishTree` repeated is MAXIMAL only while it is the
    // sole variant and carries no payload: the derivation beside
    // `META_MAX_BYTES` counts one tag byte per op and reads no constant
    // that a payload would move, so a registry that grows leaves both
    // that assertion and this measurement quietly describing a narrower
    // object than the format allows. An exhaustive match stops compiling
    // on the day that happens, which is the day to revisit both.
    match SheafOp::PublishTree {
        SheafOp::PublishTree => {}
    }
    let sheaf = encode_sheaf(&doc).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        sheaf.len(),
        SHEAF_FIXED_HEADER_LEN + GRAIN_ID_BINARY_LEN + SHEAF_MAX_OPS as usize,
        "the measured maximal sheaf disagrees with the derivation in META_MAX_BYTES' docs"
    );

    let id = GrainId::of(&sheaf);
    let want = sheaf.clone();
    let key = format!("meta/vol-sheaf/{}", fanout_hex(id.digest()));
    let (mem, store) = fresh();
    plant_bytes(&mem, &key, sheaf).await;
    assert_eq!(
        store.get_meta("vol-sheaf", &id).await,
        Ok(want),
        "a maximal sheaf is legal metadata and must be readable"
    );
}

/// `get_bin`'s cap is [`BIN_MAX_BYTES`], the frozen bin ceiling — and it
/// really is the CEILING FOR THE WHOLE OBJECT, envelope included, not for
/// a payload inside one: `encode_bin` refuses a total over it and
/// `decode_bin` refuses `bytes.len()` over it, both measured on the full
/// object. Nothing is prepended outside that total, which is what makes
/// this the one cap here that could be borrowed by name and still be
/// right.
///
/// The refuse direction advertises `cap + 1` over a SMALL body rather
/// than planting 256 MiB + 1: `meta.size` is the gate's only input either
/// way. The accept direction keeps its real 256 MiB, because only real
/// bytes can show that a cap set one byte too low would reject legal
/// data, and only a real walk can show the counting reader admits exactly
/// `cap`. That half cannot be made cheaper without giving up what it
/// proves.
#[tokio::test]
async fn get_bin_refuses_over_the_cap_and_accepts_exactly_at_it() {
    let cap = usize::try_from(BIN_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let digest = *GrainId::of(b"a bin whose bytes are not what is planted").digest();
    let key = format!("bins/{}", fanout_hex(&digest));

    {
        let h = hostile(Hostility {
            lie_size: Some(BIN_MAX_BYTES + 1),
            chunk: READ_BUFFER,
            ..Hostility::default()
        });
        plant(&h.mem, &key, 64).await;
        assert_refused(
            &h.store.get_bin(&digest).await.map(|v| v.len()),
            "a bin advertising one byte over the cap",
        );
    }
    {
        let (mem, store) = fresh();
        plant(&mem, &key, cap).await;
        assert_eq!(
            store.get_bin(&digest).await.map(|v| v.len()),
            Ok(cap),
            "a bin of exactly BIN_MAX_BYTES is legal data"
        );
    }
}

// ------------------------------------- get_bin_range: the extent gate
//
// **WHAT THESE FOUR CHECKS ARE DEFENDING, stated accurately rather than
// uniformly.** On the real `s3` backend, `object_store` 0.14.1 already
// refuses most of what they refuse, from its own HTTP client: for a range
// request `get_range_meta` (`src/client/get.rs`) errors `NotPartial`
// unless the status is 206, parses `Content-Range`, and requires
// `actual == expected` exactly — where `expected` is the requested range
// with only its END clamped to the size the response itself reported. So
// against that backend a wrong START, an end PAST the request, and a
// zero-width answer are all already impossible, and the granary checks
// for them are defence in depth against an in-process `ObjectStore` that
// does not go through that client — the `InMemory` one, this file's
// `HostileStore`, or any future implementation.
//
// The ceiling check is the different one. `expected` keeps the requested
// WIDTH whenever the response claims a large enough object, and that width
// is `len`, a `u32` that becomes CLIENT-CHOSEN on the relay path — so a
// legal, protocol-conformant 4 GiB answer is reachable through the real
// client, and `BIN_MAX_BYTES` is what refuses it.
//
// The distinction is worth keeping because it says which checks a
// dependency bump could make redundant and which one it could not.

/// `get_bin_range` is the SERVER'S PRIMARY RELAY PATH, and setting
/// `GetOptions.range` is a request, not a guarantee: a backend that
/// ignores it streams the whole object. The requested length is the cap,
/// and `meta.size` is irrelevant here — it is the size of the WHOLE bin,
/// which is legitimately larger than any subrange.
#[tokio::test]
async fn get_bin_range_refuses_a_backend_that_ignores_the_range() {
    let h = hostile(Hostility {
        ignore_range: true,
        chunk: 16,
        ..Hostility::default()
    });
    let digest = *GrainId::of(b"a bin fetched from a range-ignoring backend").digest();
    plant(&h.mem, &format!("bins/{}", fanout_hex(&digest)), 100).await;

    // 50 bytes asked for at offset 0; the whole 100-byte object comes
    // back. The response OVERSHOOTS the requested extent.
    assert_refused(
        &h.store.get_bin_range(&digest, 0, 50).await.map(|v| v.len()),
        "a whole-object response to a 50-byte range request",
    );
}

/// The bypass a width-only gate does not catch, and the reason the gate
/// checks WHERE the response starts rather than only how wide it is.
///
/// Ask for `offset = 10, len = 100` on a 100-byte bin. A correct backend
/// short-reads and answers `range = 10..100` — width 90. A backend that
/// ignores the range answers `range = 0..100` — width 100, which is
/// `<= len` and so passes a width-only check, and passes a byte counter
/// capped at 100 as well. The caller would receive bytes from offset 0
/// while believing it asked for offset 10: not an oversized transfer, a
/// WRONG SLICE.
#[tokio::test]
async fn get_bin_range_refuses_a_response_that_starts_at_the_wrong_offset() {
    let h = hostile(Hostility {
        ignore_range: true,
        chunk: 16,
        ..Hostility::default()
    });
    let digest = *GrainId::of(b"a bin whose relay response starts elsewhere").digest();
    plant(&h.mem, &format!("bins/{}", fanout_hex(&digest)), 100).await;

    // Width 100 <= len 100, so only the START check can refuse this.
    assert_refused(
        &h.store
            .get_bin_range(&digest, 10, 100)
            .await
            .map(|v| v.len()),
        "a response starting at offset 0 for a request at offset 10",
    );
}

/// **The counting walk's own cap-exceeded branch, not the after-the-fact
/// length check.** `collect_bounded` is shared between [`GranaryStore::get_bounded`]
/// (object-class cap, [`RefusalKind::OverCap`]) and
/// [`GranaryStore::get_bin_range`] (the requested extent's own width,
/// [`RefusalKind::Extent`]) — one counting walk, two callers, so only a
/// parameter tells its cap-exceeded refusal apart. A response that
/// claims a NARROW extent and then streams past it during the walk must
/// be refused as `Extent`, never `OverCap`: this is the test that goes
/// green on the wrong kind if that parameter is ever dropped or
/// swapped.
///
/// `report_range` makes every check BEFORE the walk pass — the response
/// starts at the requested offset and its declared end sits inside the
/// request — so only the walk itself can be what refuses this, and it
/// refuses on `seen > cap` while still streaming, before the
/// after-the-fact `declared/delivered` check even runs.
#[tokio::test]
async fn a_ranged_response_that_streams_past_its_own_declared_extent_is_extent_never_overcap() {
    let h = hostile(Hostility {
        report_range: Some((0, 10)),
        chunk: 16,
        ..Hostility::default()
    });
    let digest = *GrainId::of(b"a bin whose relay response under-declares its own extent").digest();
    plant(&h.mem, &format!("bins/{}", fanout_hex(&digest)), 100).await;

    let got = h.store.get_bin_range(&digest, 0, 100).await;
    let RootStoreError::RefusedResponse { kind, .. } = got
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("a response outrunning its own declared extent must be refused"))
    else {
        panic!("must be refused by granary's own bound, got {got:?}")
    };
    assert_eq!(
        *kind,
        RefusalKind::Extent,
        "a ranged read's cap is the extent IT declared, not the object class's read cap — this \
         must never surface as OverCap"
    );
}

/// **The extent gate had the transfer half and not the ALLOCATION half.**
/// `r.range`'s width was passed as the cap AND as the `Vec::with_capacity`
/// hint, unclamped by any format constant — so a backend that reports a
/// wide extent names the allocation directly. `len` is a `u32` and becomes
/// CLIENT-CHOSEN on the relay path, which puts the ceiling at 4 GiB, and a
/// Rust allocation failure aborts the process rather than returning.
///
/// The response here passes every other check — it starts exactly at the
/// requested offset and ends inside the requested end — and reports an
/// extent one byte wider than a whole maximal bin. No legal object can
/// produce that, because an extent of a bin cannot exceed the bin.
#[tokio::test]
async fn get_bin_range_refuses_an_extent_wider_than_a_whole_bin() {
    let h = hostile(Hostility {
        report_range: Some((10, 10 + BIN_MAX_BYTES + 1)),
        chunk: READ_BUFFER,
        ..Hostility::default()
    });
    let digest = *GrainId::of(b"a bin whose relay response claims a huge extent").digest();
    plant(&h.mem, &format!("bins/{}", fanout_hex(&digest)), 100).await;

    // The request is wide enough that the reported extent sits INSIDE it,
    // so the over-read check cannot be what refuses this.
    assert_refused(
        &h.store
            .get_bin_range(&digest, 10, u32::MAX)
            .await
            .map(|v| v.len()),
        "a response claiming an extent wider than BIN_MAX_BYTES",
    );
    assert_eq!(
        h.bytes.load(Ordering::SeqCst),
        0,
        "the extent must be refused before the body is touched — a clamp would still transfer"
    );
}

/// **The extent ceiling ACCEPTS exactly at the cap, and something else
/// refuses this response.** `get_bin_range_refuses_an_extent_wider_than_a
/// _whole_bin` pins one byte over; this pins the other side of that
/// boundary, where a ceiling set one byte too low would be invisible.
///
/// It has to say so INDIRECTLY, and the reason is worth stating. A
/// response declaring exactly `BIN_MAX_BYTES` and then delivering a
/// hundred bytes is refused now — a body must match its declared extent —
/// so "the ceiling accepted it" cannot be shown by an `Ok`. What shows it
/// is WHICH refusal arrives: the ceiling names the bin ceiling in its
/// reason, the extent-floor names the declared and delivered widths. The
/// second reason is proof the first check passed.
///
/// This row pins the refusal reason, not the allocation capacity:
/// capacity is not exposed to a caller receiving an `Err`.
/// `range_alloc_hint_never_exceeds_one_frame` pins the allocation hint.
#[tokio::test]
async fn an_extent_exactly_at_the_bin_ceiling_is_not_refused_by_the_ceiling() {
    let h = hostile(Hostility {
        // Exactly at the ceiling: legal, so the ceiling check must pass
        // it through and leave the refusal to the check after it.
        report_range: Some((0, BIN_MAX_BYTES)),
        chunk: READ_BUFFER,
        ..Hostility::default()
    });
    let digest = *GrainId::of(b"a bin whose relay response claims a legal huge extent").digest();
    plant(&h.mem, &format!("bins/{}", fanout_hex(&digest)), 100).await;

    let got = h.store.get_bin_range(&digest, 0, u32::MAX).await;
    let RootStoreError::RefusedResponse { reason, kind } = got
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("a 100-byte body under a 256 MiB extent must be refused"))
    else {
        panic!("must be refused by granary's own bound, got {got:?}")
    };
    assert!(
        reason.contains(&format!("declared {BIN_MAX_BYTES} bytes and delivered 100")),
        "the ceiling must ACCEPT an extent of exactly BIN_MAX_BYTES and leave the refusal to the \
         body/extent mismatch — a ceiling one byte too low would refuse here instead, and its \
         reason would say so. Got: {reason}"
    );
    assert_eq!(
        *kind,
        RefusalKind::Extent,
        "a ranged read's own body/extent mismatch is Extent, never OverCap — the two caps are \
         different questions even though this walk shares one counter for both"
    );
    assert_eq!(
        h.bytes.load(Ordering::SeqCst),
        100,
        "only the bytes that existed may be transferred — the declared extent must never become \
         the transfer"
    );
}

/// A ZERO-WIDTH response to a request for real bytes. It passes the start
/// check and the over-read check, leaves a cap of zero, and the walk then
/// answers `Ok(vec![])` — an empty READ SUCCESS, which this seam does not
/// have: the pinned semantic is that a range spanning nothing is an
/// error.
#[tokio::test]
async fn get_bin_range_refuses_a_zero_width_response_to_a_real_request() {
    let h = hostile(Hostility {
        report_range: Some((10, 10)),
        empty_body: true,
        chunk: READ_BUFFER,
        ..Hostility::default()
    });
    let digest = *GrainId::of(b"a bin whose relay response spans nothing").digest();
    plant(&h.mem, &format!("bins/{}", fanout_hex(&digest)), 100).await;

    assert_refused(
        &h.store
            .get_bin_range(&digest, 10, 50)
            .await
            .map(|v| v.len()),
        "a zero-width response to a 50-byte request",
    );
}

/// The extent gate's two BOUNDARIES, each one byte outside legal. Without
/// these the gate can be loosened by a byte in either direction and every
/// other test still passes: the range-ignoring backend overshoots by 90.
///
/// **The bin is deliberately SMALLER than the request**, and that is what
/// makes these boundary tests test anything. A 40-byte object short-reads
/// to 30 bytes, which is inside both of the reported extents below — so
/// the transfer bound cannot fire, and the only thing that can refuse
/// either response is the check being pinned. Written the obvious way,
/// against a bin large enough to fill the request, the body OVERRUNS the
/// off-by-one extent and the counting reader refuses it: the test passes
/// with the extent check deleted, having verified nothing.
#[tokio::test]
async fn get_bin_range_refuses_a_response_off_by_exactly_one_byte() {
    let digest = *GrainId::of(b"a bin whose relay response is off by one").digest();
    let key = format!("bins/{}", fanout_hex(&digest));

    // Starts ONE byte late. The caller would silently receive the wrong
    // slice, shifted by one.
    let h = hostile(Hostility {
        report_range: Some((11, 60)),
        chunk: READ_BUFFER,
        ..Hostility::default()
    });
    plant(&h.mem, &key, 40).await;
    assert_refused(
        &h.store
            .get_bin_range(&digest, 10, 50)
            .await
            .map(|v| v.len()),
        "a response starting one byte after the requested offset",
    );

    // Ends ONE byte past the requested end: one byte more than was asked
    // for, which is still an over-read.
    let h = hostile(Hostility {
        report_range: Some((10, 61)),
        chunk: READ_BUFFER,
        ..Hostility::default()
    });
    plant(&h.mem, &key, 40).await;
    assert_refused(
        &h.store
            .get_bin_range(&digest, 10, 50)
            .await
            .map(|v| v.len()),
        "a response ending one byte past the requested end",
    );
}

/// **A body SHORTER than the extent the response itself declared.** The
/// extent gate compares `r.range` against the REQUEST and stops there,
/// and the transfer bound only refuses a body that outruns its cap — so
/// a backend that declares `10..50` and then delivers thirty bytes was
/// answered `Ok` with thirty bytes and no error at all.
///
/// The distinction this pins, and it is the whole point: a NARROWER
/// EXTENT HONESTLY DECLARED is a legal short read (the pinned overhang
/// semantic, exercised right below), while a BODY SHORTER THAN ITS OWN
/// DECLARED EXTENT is a truncated transfer. The first is the backend
/// telling the truth about having less; the second is the backend
/// contradicting itself inside one response.
///
/// The bin is 40 bytes and the request is `(10, 50)`, so the honest
/// answer is `10..40` — thirty bytes. The response instead declares
/// `10..50` and hands over those same thirty. Every earlier check passes:
/// it starts where it was asked to, ends inside the requested end, spans
/// something, and is far under the bin ceiling.
#[tokio::test]
async fn get_bin_range_refuses_a_body_shorter_than_its_own_declared_extent() {
    let h = hostile(Hostility {
        report_range: Some((10, 50)),
        chunk: READ_BUFFER,
        ..Hostility::default()
    });
    let digest = *GrainId::of(b"a bin whose relay response undershoots its extent").digest();
    plant(&h.mem, &format!("bins/{}", fanout_hex(&digest)), 40).await;

    assert_refused(
        &h.store
            .get_bin_range(&digest, 10, 50)
            .await
            .map(|v| v.len()),
        "a 30-byte body under a declared 40-byte extent",
    );
}

/// The gate must not refuse the honest path. An HONOURED subrange of a
/// larger bin succeeds, including the pinned short read — `(90, 50)` on a
/// 100-byte bin returns the ten available bytes, not an error.
#[tokio::test]
async fn get_bin_range_still_accepts_every_honoured_extent() {
    let (_mem, store) = fresh();
    let data: Vec<u8> = (0..100u8).collect();
    let digest = *GrainId::of(&data).digest();
    assert_eq!(store.put_bin(&digest, data.clone()).await, Ok(true));

    assert_eq!(store.get_bin_range(&digest, 0, 100).await, Ok(data.clone()));
    assert_eq!(
        store.get_bin_range(&digest, 10, 5).await,
        Ok(data.get(10..15).unwrap_or_default().to_vec()),
        "an interior subrange of a larger bin must succeed"
    );
    assert_eq!(
        store.get_bin_range(&digest, 90, 50).await,
        Ok(data.get(90..100).unwrap_or_default().to_vec()),
        "the pinned short read must survive the extent gate"
    );
}

// ------------------------------------------ the counting reader itself

/// Chunk size for the dishonest bodies below — a stand-in for an HTTP
/// client's read buffer. A wrapper that yielded one giant `Bytes` would
/// be modelling the out-of-scope in-process adversary instead, and would
/// fail for the wrong reason.
const READ_BUFFER: usize = 8 * 1024;

/// **The size gate is not a bound.** A backend that advertises a SMALL
/// `meta.size` and then streams a LARGE body walks straight through it —
/// the gate compares the advertisement, and the advertisement is the lie.
/// Only the counting reader stops this.
///
/// The assertion is on BYTES CONSUMED, not merely on an error coming
/// back: an error alone does not distinguish a reader that stopped at the
/// cap from one that drained a megabyte and complained afterwards.
#[tokio::test]
async fn a_lying_advertised_size_is_caught_by_the_counting_reader() {
    let planted = 1024 * 1024;
    let h = hostile(Hostility {
        lie_size: Some(20),
        chunk: READ_BUFFER,
        ..Hostility::default()
    });
    plant(&h.mem, "root/vol-liar/00000000000000000001", planted).await;

    assert_refused(
        &h.store
            .get_root("vol-liar", 1)
            .await
            .map(|b| b.map_or(0, |v| v.len())),
        "a root advertising 20 bytes and streaming a megabyte",
    );

    let seen = h.bytes.load(Ordering::SeqCst);
    let planted = u64::try_from(planted).unwrap_or(u64::MAX);
    let buffer = u64::try_from(READ_BUFFER).unwrap_or(u64::MAX);
    assert!(
        seen <= ROOT_MAX_BYTES + buffer,
        "the walk must stop within one read buffer of the {ROOT_MAX_BYTES}-byte cap, it consumed \
         {seen}"
    );
    assert!(
        seen < planted,
        "the walk consumed {seen} of {planted} planted bytes — it did not stop early at all"
    );
}

/// **The advertised-size gate, on the only input that lets it DECIDE.**
/// It is a separate bound from the counting reader and needs a separate
/// test, because a truthfully oversized plant never reaches it: the walk
/// refuses that body whether the gate exists or not, so an over-cap test
/// built on truthful metadata passes with the gate deleted.
///
/// The input that isolates it is the lie in the OTHER direction —
/// `cap + 1` advertised over a SMALL body. The walk would sail through
/// 64 bytes, so the only thing that can refuse is the gate.
///
/// The assertion is ZERO BYTES CONSUMED, the same discipline the
/// transfer half gets. That is the gate's entire purpose: the response
/// is dropped after its headers, so a gate that refused after streaming
/// would be no gate at all. `cap + 1` exactly, so a gate loosened by one
/// byte fails here too.
#[tokio::test]
async fn an_advertised_size_over_the_cap_is_refused_before_a_body_byte_is_read() {
    let h = hostile(Hostility {
        lie_size: Some(ROOT_MAX_BYTES + 1),
        chunk: READ_BUFFER,
        ..Hostility::default()
    });
    plant(&h.mem, "root/vol-overclaim/00000000000000000001", 64).await;

    assert_refused(
        &h.store
            .get_root("vol-overclaim", 1)
            .await
            .map(|b| b.map_or(0, |v| v.len())),
        "a root advertising one byte over the cap",
    );
    assert_eq!(
        h.bytes.load(Ordering::SeqCst),
        0,
        "the gate must refuse on the metadata alone — no body byte may be requested"
    );
    assert_eq!(
        h.chunks.load(Ordering::SeqCst),
        0,
        "the gate must refuse before the body stream is polled at all"
    );
}

/// The transfer bound's OWN boundary, which every other test leaves
/// loose. The truthful over-cap plants are refused by the advertised-size
/// gate before the walk decides anything, and the lying-size test
/// overshoots by a megabyte — so the walk can be loosened by a byte and
/// the whole suite still passes.
///
/// One-byte chunks, and the assertion is the exact byte the walk stopped
/// at: `cap + 1` is the first count that must refuse, and stopping there
/// rather than one chunk later is the difference the mutation makes.
#[tokio::test]
async fn the_walk_refuses_at_exactly_one_byte_past_the_cap() {
    let over = ROOT_MAX_BYTES + 1;
    let h = hostile(Hostility {
        // Small enough to walk through the size gate untouched, so the
        // walk is the only thing that can refuse this.
        lie_size: Some(64),
        chunk: 1,
        ..Hostility::default()
    });
    plant(
        &h.mem,
        "root/vol-onepast/00000000000000000001",
        usize::try_from(over).unwrap_or_else(|e| panic!("{e}")),
    )
    .await;

    assert_refused(
        &h.store
            .get_root("vol-onepast", 1)
            .await
            .map(|b| b.map_or(0, |v| v.len())),
        "a body one byte past the cap",
    );
    assert_eq!(
        h.bytes.load(Ordering::SeqCst),
        over,
        "the walk must stop on the FIRST byte past the {ROOT_MAX_BYTES}-byte cap, not one chunk \
         later"
    );
}

/// The same lie against `read_hint`, whose gate is `meta.size == 20`. A
/// backend that advertises exactly 20 and streams more passes that gate
/// by construction, so the body walk is the only thing left.
///
/// The outcome is `Missing`, NOT an error: `CURRENT` is advisory, and an
/// attacker-writable object must degrade a reader to a list, never wedge
/// its refresh.
///
/// **The chunks are TINY on purpose, and the bound is the actual cap.**
/// Cut at a read-buffer's width, the very first chunk overruns any cap
/// from 20 bytes to 8 KiB, so "it stopped inside one read buffer" is true
/// of a cap widened two hundredfold — the assertion pins the CHUNK SIZE,
/// not the cap. At four bytes a chunk the walk stops within four bytes of
/// whatever the cap really is, so the assertion pins the cap itself.
#[tokio::test]
async fn a_lying_hint_size_degrades_to_missing_without_streaming_the_body() {
    const CHUNK: usize = 4;
    let planted = 8192;
    let h = hostile(Hostility {
        lie_size: Some(20),
        chunk: CHUNK,
        ..Hostility::default()
    });
    plant(&h.mem, "root/vol-liar-hint/CURRENT", planted).await;

    assert_eq!(
        h.store.read_hint("vol-liar-hint", None).await,
        Ok(granary_core::rootstore::HintRead::Missing),
        "an oversized hint body must degrade to Missing, never to an error"
    );

    let seen = h.bytes.load(Ordering::SeqCst);
    let planted = u64::try_from(planted).unwrap_or(u64::MAX);
    let cap = u64::try_from(SEQ_KEY_DIGITS).unwrap_or(u64::MAX);
    let chunk = u64::try_from(CHUNK).unwrap_or(u64::MAX);
    assert!(
        seen <= cap + chunk,
        "the hint walk must stop within one chunk of the {cap}-byte cap — the only legal hint body \
         is exactly that wide — but it consumed {seen}"
    );
    assert!(
        seen < planted,
        "the hint walk consumed {seen} of {planted} planted bytes"
    );
}

/// **The body walk owes the executor the same interruptibility the
/// listing walk does**, and the cap is not a substitute for it. A cap
/// bounds BYTES; it says nothing about how many times the loop runs to
/// reach them. A `get_bin` body delivered in one-byte chunks reaches
/// `BIN_MAX_BYTES` only after 268,435,457 iterations, and if none of them
/// returns `Pending` the thread is held for all of them — a
/// `tokio::time::timeout` around the read is never polled, a
/// `JoinHandle::abort` never lands, and every other task on that worker
/// waits.
///
/// The observable is the same one
/// `max_seq_yields_to_the_executor_while_it_walks_a_long_listing` uses:
/// the future's own POLL RESULT, counted by driving it by hand.
///
/// **This test depends on the walk's yield interval, which is private to
/// the crate.** What it needs is a body cut into MORE chunks than that
/// interval; 32,768 one-byte chunks is two orders of magnitude above it,
/// so the dependence is stated rather than tuned. Were the interval
/// widened past the chunk count this fails LOUDLY (`pends == 0`), never
/// silently.
///
/// The second assertion is what makes the yield PERIODIC rather than
/// per-chunk: yielding on every chunk would satisfy `pends > 0` and turn
/// every honest read into one scheduler round-trip per read buffer.
#[tokio::test]
async fn a_long_body_walk_yields_to_the_executor() {
    let planted = 32 * 1024;
    let h = hostile(Hostility {
        chunk: 1,
        ..Hostility::default()
    });
    plant(&h.mem, "root/vol-body-yield/00000000000000000001", planted).await;

    let (got, pends) = poll_to_completion(h.store.get_root("vol-body-yield", 1));
    assert_eq!(
        got.map(|b| b.map(|v| v.len())),
        Ok(Some(planted)),
        "the walk must still be correct"
    );
    let chunks = h.chunks.load(Ordering::SeqCst);
    assert_eq!(chunks, 32_768, "the body must arrive one byte at a time");
    assert!(
        pends > 0,
        "the walk took {chunks} body chunks in a single poll — it never handed the thread back, so \
         no timeout and no abort on the runtime could have interrupted it"
    );
    assert!(
        u64::from(pends) < chunks,
        "the walk yielded on {pends} of {chunks} chunks — a yield per chunk is a scheduler \
         round-trip per read buffer on every honest read"
    );
}

// ------------------------------------------------- zero-progress bodies

/// The zero-chunk allowance the walk enforces, MIRRORED here because the
/// real constant is private to `granary-store`.
///
/// Mirrored rather than exported on purpose: the two tests below assert
/// the EXACT chunk the walk refuses on, so widening the real constant
/// fails them loudly here instead of being silently followed. A test that
/// derives its expectation from the thing under test cannot pin it.
const ZERO_CHUNK_ALLOWANCE: u32 = 1024;

/// **A size bound cannot end a stream that delivers no size.** A body of
/// ZERO-LENGTH chunks moves the byte counter not at all, so the cap is
/// never reached and the walk runs as long as the sender keeps yielding.
///
/// The bound has to be LOCAL rather than a caller's deadline, and the
/// walk's cooperative yield does not change that: a yield makes a timeout
/// able to LAND, it does not make one exist. A caller that wrapped no
/// deadline around this read — every caller in-tree today — still needs
/// the walk to refuse on its own.
///
/// The plant is FINITE (well above the allowance) so this test terminates
/// whether or not the guard exists: without it the walk drains all of
/// them and answers `Ok`, which is a failed assertion rather than a hang.
/// The chunk count is what shows the walk stopped early — the byte
/// counter cannot, because zero-length chunks never move it.
///
/// The count is pinned EXACTLY, not merely below what was served: the
/// first chunk past the allowance is the one that must refuse, and a
/// bound asserted as "less than 8,192" survives being widened fourfold.
#[tokio::test]
async fn a_body_of_zero_length_chunks_is_refused_rather_than_walked_forever() {
    // Comfortably past the allowance, so the walk has somewhere to run to
    // if it does not refuse.
    const SERVED: u32 = 8192;

    let h = hostile(Hostility {
        empty_chunks: SERVED,
        empty_body: true,
        ..Hostility::default()
    });
    plant(&h.mem, "root/vol-nothing/00000000000000000001", 64).await;

    assert_refused(
        &h.store
            .get_root("vol-nothing", 1)
            .await
            .map(|b| b.map_or(0, |v| v.len())),
        "a response body made only of zero-length chunks",
    );
    assert_eq!(
        h.bytes.load(Ordering::SeqCst),
        0,
        "zero-length chunks carry no bytes — the byte counter cannot see this attack at all"
    );
    assert_eq!(
        h.chunks.load(Ordering::SeqCst),
        u64::from(ZERO_CHUNK_ALLOWANCE) + 1,
        "the walk must refuse on the FIRST chunk past the {ZERO_CHUNK_ALLOWANCE}-chunk allowance, \
         and on no later one"
    );
}

/// **The allowance is CUMULATIVE over the response, and ONE BYTE between
/// runs must not reset it.** A consecutive counter reads as equivalent
/// and is not: a sender that emits `ZERO_CHUNK_ALLOWANCE` empties, then a
/// single byte, then another full run, trips a consecutive counter never.
/// The byte cap admits `cap` such bytes, so the walk would run
/// `cap × allowance` iterations — at `get_bin`'s 256 MiB cap, on the order
/// of 10^11 iterations for a transfer the byte bound calls legal.
///
/// **This is the only test that separates the two counters**, which is
/// why it exists rather than being folded into the one above: an unbroken
/// run of empties is refused by either, so EVERY OTHER test in the
/// workspace passes with the counter mutated to consecutive — measured,
/// not assumed, which is the only reason the gap was visible at all.
///
/// The plant is EIGHT bytes so the MUTANT terminates and fails an
/// assertion rather than hanging: it walks all `8 × (allowance + 1)`
/// chunks and answers `Ok(8 bytes)`, where the pristine walk refuses on
/// chunk `allowance + 2` — the first empty of the SECOND run.
#[tokio::test]
async fn one_byte_between_runs_of_zero_length_chunks_does_not_reset_the_allowance() {
    let h = hostile(Hostility {
        // One body byte per run, which is the cheapest reset a sender can
        // buy and therefore the one the bound must survive.
        chunk: 1,
        empties_per_chunk: ZERO_CHUNK_ALLOWANCE,
        ..Hostility::default()
    });
    plant(&h.mem, "root/vol-interleave/00000000000000000001", 8).await;

    assert_refused(
        &h.store
            .get_root("vol-interleave", 1)
            .await
            .map(|b| b.map_or(0, |v| v.len())),
        "a body that resets each run of zero-length chunks with one byte",
    );
    assert_eq!(
        h.chunks.load(Ordering::SeqCst),
        u64::from(ZERO_CHUNK_ALLOWANCE) + 2,
        "the walk must refuse on the first empty chunk of the SECOND run — the allowance counts \
         across the whole response, so the byte in between buys the sender nothing"
    );
    assert_eq!(
        h.bytes.load(Ordering::SeqCst),
        1,
        "exactly the one interleaved byte may be consumed before the refusal"
    );
}

// ------------------------------------------------------------ max_seq

/// **`list` is FLAT and RECURSIVE.** It
/// returns every descendant of the prefix, so `root/{vol}/junk/…0099`
/// arrives at the parser alongside the real roots — and a parser that
/// looks only at the filename reads it as seq 99, handing back a head
/// that no `get_root` can fetch.
///
/// The plant is deliberately VALID-LOOKING: exactly 20 digits in the last
/// segment. A junk filename would be rejected by the strict parse and
/// would prove nothing about the depth rule.
#[tokio::test]
async fn max_seq_ignores_a_nested_key_that_looks_like_a_root() {
    let (mem, store) = fresh();
    let vol = "vol-nested";

    // One real root...
    assert_eq!(store.put_root(vol, 7, vec![0xAA]).await, Ok(()));
    // ...and a well-formed seq name one level deeper than a root lives.
    plant(&mem, &format!("root/{vol}/junk/00000000000000000099"), 4).await;
    // ...and one deeper still, so the rule is "exactly one component",
    // not "at most two".
    plant(&mem, &format!("root/{vol}/a/b/00000000000000000123"), 4).await;

    assert_eq!(
        store.max_seq(vol).await,
        Ok(Some(7)),
        "a key nested BELOW the volume's root prefix is not a root, however well-formed its last \
         segment looks"
    );
}

/// `max_seq` has the SAME non-yielding loop shape as the body walk and
/// needs a DIFFERENT remedy, because no cap can exist here: a truncated
/// listing would return a WRONG head rather than a slow one. What it can
/// do instead is stay CANCELLABLE — hand control back to the executor as
/// it walks, so a caller's timeout, a task abort and every other task on
/// the runtime are not starved until the listing ends.
///
/// The observable is the future's own POLL RESULT, counted by driving it
/// by hand. Yielding IS returning `Pending` with the waker already woken,
/// so a walk that never yields answers in a single poll and one that does
/// answers `Pending` at each yield point. Measured directly rather than
/// through a racing task: spawning one is banned by `clippy.toml` here, and it
/// would test the same property through an executor's scheduling policy
/// instead of through the future itself.
///
/// The listing is finite, so this terminates either way: without the
/// yield the assertion fails, it does not hang.
///
/// **This test depends on the walk's yield interval**, which is private to
/// the crate: 200 roots must exceed it or the walk legitimately finishes
/// in one poll and the assertion fires on a correct implementation. That
/// dependence is stated rather than hidden, and it is a LOUD one — the
/// fixture shortened to 100 (below the interval's 128) fails on
/// `pends == 0`, measured. It does not quietly stop testing anything.
#[tokio::test]
async fn max_seq_yields_to_the_executor_while_it_walks_a_long_listing() {
    let (_mem, store) = fresh();
    let vol = "vol-yield";
    // Comfortably more roots than the yield interval — see the doc above
    // for what happens if that stops being true.
    for seq in 1u64..=200 {
        assert_eq!(store.put_root(vol, seq, vec![0]).await, Ok(()));
    }

    let (got, pends) = poll_to_completion(store.max_seq(vol));
    assert_eq!(got, Ok(Some(200)), "the walk must still be correct");
    assert!(
        pends > 0,
        "max_seq walked 200 listing entries in a single poll — it never handed the thread back, \
         so no timeout and no abort on the runtime could have interrupted it"
    );
}

/// The streaming maximum is still the numeric maximum over many roots,
/// with the advisory hint and a planted seq 0 both excluded.
///
/// **Stated gap:** this asserts CORRECTNESS, not O(1) accumulation.
/// Retention is not observable through the seam — a lazy listing store
/// cannot distinguish a streaming fold from `collect()`-then-`max()`,
/// because both poll one item at a time and only the caller's retention
/// differs. An assertion that cannot fail would be worse than saying so.
#[tokio::test]
async fn max_seq_is_the_numeric_maximum_over_many_roots() {
    let (mem, store) = fresh();
    let vol = "vol-many";
    // Insertion order crosses the lexicographic/numeric boundary, and
    // the highest seq is not the last one written.
    for seq in (1u64..=250).rev() {
        assert_eq!(store.put_root(vol, seq, vec![0]).await, Ok(()));
    }
    assert_eq!(store.write_hint(vol, 3).await, Ok(()));
    plant(&mem, &format!("root/{vol}/00000000000000000000"), 4).await;

    assert_eq!(
        store.max_seq(vol).await,
        Ok(Some(250)),
        "the running maximum must be the numeric max, ignoring CURRENT and a planted seq 0"
    );
    assert_eq!(store.max_seq("vol-many-empty").await, Ok(None));
}
