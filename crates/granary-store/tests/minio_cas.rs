// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

// This file uses `granary_store::backend` and `object_store`
// directly, neither of which exists without the `backend` feature —
// `cargo check -p granary-store --no-default-features --all-targets`
// otherwise fails to compile this test TARGET (the library itself
// compiles fine under every feature selection; only the unconditional
// test targets did not).
#![cfg(feature = "backend")]
#![expect(
    clippy::disallowed_methods,
    reason = "test scratch naming — per-run volume names and a content salt in a shared \
              bucket; disallowed_methods has no allow-in-tests knob"
)]

//! `GranaryStore` tests against a REAL `MinIO` server.
//! Every test is `#[ignore]`d so `cargo nextest run`
//! stays hermetic; `scripts/minio-harness.sh test` is how this file
//! actually runs (it starts a pinned `MinIO`, exports
//! `GRANARY_MINIO_ENDPOINT`, and runs the ignored lane).
//!
//! Each `RootStore` test (root and hint) uses a volume name unique to the
//! test AND the process (`std::process::id()`), so a rerun against a
//! leftover data dir stays green instead of colliding with a previous
//! run's roots. The one bin/CAS test below has no volume of its own — it
//! keys purely on `bins/{fanout(digest)}` of its sample content — so ITS
//! rerun-safety instead comes from salting that content by the process
//! id (see `sample_bytes`), making the digest itself novel per process
//! rather than the storage key.

use granary_core::hash::GrainId;
use granary_core::rootstore::{HintRead, RootStore, RootStoreError};
use granary_store::backend::GranaryStore;
use granary_store::http_client::NoRedirectConnector;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::client::{
    HttpClient, HttpConnector, HttpError, HttpRequest, HttpResponse, HttpService,
};
use object_store::path::Path as StorePath;
use object_store::{ClientOptions, ObjectStoreExt as _};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

/// The bucket this lane addresses. Env-overridable like the endpoint,
/// user and password already are: this lane is not only the local
/// harness's — an operator also runs it against real AWS/R2 endpoints,
/// where a hardcoded bucket name would need a source edit. The default
/// is the harness's pre-created bucket.
fn bucket() -> String {
    std::env::var("GRANARY_MINIO_BUCKET").unwrap_or_else(|_| "granary-test".to_owned())
}

/// Build a fresh, independently-constructed `AmazonS3` client against
/// the harness endpoint. Called once per `GranaryStore` instance a test
/// needs — the two-way race test calls it twice to get two separate
/// clients (own connection pool each) racing the same server.
fn client() -> AmazonS3 {
    // The HTTP client every production S3 store is built with, so this suite
    // runs the store over the same transport it ships with.
    client_with_connector(NoRedirectConnector)
}

fn client_with_connector(connector: impl HttpConnector) -> AmazonS3 {
    let endpoint = std::env::var("GRANARY_MINIO_ENDPOINT").unwrap_or_else(|_| {
        panic!(
            "GRANARY_MINIO_ENDPOINT is not set — this lane only runs via \
             `scripts/minio-harness.sh test`, which starts MinIO and \
             exports it"
        )
    });
    let user = std::env::var("GRANARY_MINIO_USER").unwrap_or_else(|_| "granary-test".to_owned());
    let pass =
        std::env::var("GRANARY_MINIO_PASS").unwrap_or_else(|_| "granary-test-secret".to_owned());
    AmazonS3Builder::new()
        .with_http_connector(connector)
        .with_endpoint(endpoint)
        .with_allow_http(true)
        .with_virtual_hosted_style_request(false)
        .with_region("us-east-1")
        .with_bucket_name(bucket())
        .with_access_key_id(user)
        .with_secret_access_key(pass)
        .build()
        .unwrap_or_else(|e| panic!("{e}"))
}

fn backend() -> GranaryStore<AmazonS3> {
    GranaryStore::new(client())
}

/// Prepare a writer with its own runtime and client before either thread
/// starts, so setup failures cannot strand a peer at the barrier.
/// The returned closure runs on its own OS thread and reports whether
/// its PUT interval overlapped the peer's. See the race test below.
fn prepare_put_root(
    vol: String,
    seq: u64,
    body: Vec<u8>,
    ready: Arc<Barrier>,
    in_flight: Arc<AtomicUsize>,
) -> impl FnOnce() -> (Result<(), RootStoreError>, bool) + Send {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    let store = backend();
    move || {
        // Neither writer can issue its PUT until both independent clients
        // and runtimes are ready. There is no client-side winner ordering.
        ready.wait();
        let overlapped = in_flight.fetch_add(1, Ordering::SeqCst) == 1;
        let result = rt.block_on(store.put_root(&vol, seq, body));
        in_flight.fetch_sub(1, Ordering::SeqCst);
        (result, overlapped)
    }
}

/// A volume name unique to this test and this process — reruns against
/// a dirty data dir (or a shared bucket across runs) stay green.
fn unique_volume(tag: &str) -> String {
    format!("gtest-{tag}-{}", std::process::id())
}

/// Deterministic, position-distinguishing bytes — a range read at the
/// wrong offset returns DIFFERENT bytes, not merely an unchecked one —
/// AND salted by the process id, so the content (and therefore its
/// digest) is novel per process. `bin_dedup_and_range_read_exact_bytes_
/// on_a_one_mib_object` has no `unique_volume` of its own to lean on: it
/// keys on `bins/{fanout(digest)}` of exactly this buffer, so without the
/// salt a rerun against a persisted data dir would find the digest
/// already present and its `Ok(true)` (novel write) assertion would fail
/// deterministically (`left: Ok(false), right: Ok(true)`) — the original
/// defect report recorded this on 5 consecutive reruns, and it was
/// reproduced directly by temporarily reverting this function.
/// Two invocations of this binary get different OS-assigned pids (the
/// same assumption `unique_volume` above already makes), so this carries
/// the same rerun-safety property by the same means.
fn sample_bytes(len: u32) -> Vec<u8> {
    let pid = std::process::id();
    (0..len)
        .map(|i| u8::try_from(i.wrapping_add(pid) % 250).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

#[tokio::test]
#[ignore = "needs a live MinIO — run scripts/minio-harness.sh test"]
async fn put_root_winner_then_loser_body_unchanged() {
    let store = backend();
    let vol = unique_volume("winner-loser");

    assert_eq!(store.put_root(&vol, 1, vec![0xAA]).await, Ok(()));
    // The loser sees AlreadyExists (a genuine 412 from the server) and
    // the stored body is UNCHANGED — never last-writer-wins.
    assert_eq!(
        store.put_root(&vol, 1, vec![0xBB]).await,
        Err(RootStoreError::AlreadyExists)
    );
    assert_eq!(store.get_root(&vol, 1).await, Ok(Some(vec![0xAA])));
}

/// The cheap-poll property on a REAL server: `MinIO`'s `ETag` is
/// content-derived (an MD5 of the body, quoted per RFC 9110), not a
/// per-store counter the way `InMemory`'s is — so a 304 here is
/// evidence the revalidation actually round-tripped an `If-None-Match`
/// the server itself matched, not an artifact of a fake always agreeing
/// with itself.
#[tokio::test]
#[ignore = "needs a live MinIO — run scripts/minio-harness.sh test"]
async fn hint_lifecycle_including_a_genuine_304() {
    let store = backend();
    let vol = unique_volume("hint-lifecycle");

    assert_eq!(store.read_hint(&vol, None).await, Ok(HintRead::Missing));

    assert_eq!(store.write_hint(&vol, 1).await, Ok(()));
    let t1 = match store.read_hint(&vol, None).await {
        Ok(HintRead::Current { seq: 1, token }) => token,
        other => panic!("want Current{{seq:1,..}}, got {other:?}"),
    };

    // Revalidate with the same token: a genuine 304, empty body.
    assert_eq!(
        store.read_hint(&vol, Some(&t1)).await,
        Ok(HintRead::NotModified)
    );

    // A new publish changes the body (and the ETag with it); the cached
    // token is now stale and the reader gets the body back, not a 304.
    assert_eq!(store.write_hint(&vol, 2).await, Ok(()));
    let t2 = match store.read_hint(&vol, Some(&t1)).await {
        Ok(HintRead::Current { seq: 2, token }) => {
            assert_ne!(token, t1);
            token
        }
        other => panic!("want Current{{seq:2,..}} with a new token, got {other:?}"),
    };

    // Republish seq 1's exact body (`format_hint_body` is a pure function
    // of seq, so this is byte-identical to the very first write). MinIO's
    // ETag is an MD5 of the body (RFC 9110), not a per-store counter the
    // way InMemory's is — so this must reproduce seq 1's ORIGINAL token,
    // proving the 304 above was a genuine conditional GET the server
    // itself matched, not an artifact of a fake always agreeing with
    // itself.
    assert_eq!(store.write_hint(&vol, 1).await, Ok(()));
    let t3 = match store.read_hint(&vol, Some(&t2)).await {
        Ok(HintRead::Current { seq: 1, token }) => token,
        other => panic!("want Current{{seq:1,..}} with a new token, got {other:?}"),
    };
    assert_eq!(
        t3, t1,
        "MinIO's ETag is content-derived: republishing seq 1's exact body \
         must reproduce its original ETag"
    );
}

/// The two-way `put_root` race, run for real: two `GranaryStore`s over
/// two independently-built `AmazonS3` clients race `put_root` at the
/// same fresh seq with different bodies, 20 times. Each round must
/// produce exactly one `Ok` and one `AlreadyExists`, and the object the
/// server actually stored must be the winner's body — not a client-side
/// assumption.
///
/// Each side runs on its OWN OS thread with its OWN single-threaded
/// `tokio` runtime, not `tokio::join!` on one runtime. A current-thread
/// `join!` does not guarantee contention: the first future can complete
/// before the second is polled. The two OS threads can progress
/// independently while racing at the same TCP listener. A per-round
/// barrier releases them only after both clients and runtimes are ready.
/// An atomic counter brackets each `block_on(put_root)` call; at least one
/// round must observe both intervals in flight. This detects serialization
/// of the writer calls by the test harness without relying on win counts.
/// It does not prove overlapping network requests or detect a lock inside
/// `put_root`. `AlreadyExists` alone also holds for sequential writes; it
/// checks conditional-write behavior, not overlap. Either writer may win
/// every round under server/OS scheduling bias.
#[test]
#[ignore = "needs a live MinIO — run scripts/minio-harness.sh test"]
fn put_root_race_twenty_rounds_exactly_one_winner_each() {
    let vol = unique_volume("race");
    let reader = backend();
    let reader_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("{e}"));

    let mut any_round_overlapped = false;
    for round in 0u64..20 {
        let seq = round + 1;
        let marker = u8::try_from(round).unwrap_or_else(|e| panic!("{e}"));
        let body_a = vec![0xAA, marker];
        let body_b = vec![0xBB, marker];

        let ready = Arc::new(Barrier::new(2));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let writer_a = prepare_put_root(
            vol.clone(),
            seq,
            body_a.clone(),
            Arc::clone(&ready),
            Arc::clone(&in_flight),
        );
        let writer_b = prepare_put_root(vol.clone(), seq, body_b.clone(), ready, in_flight);
        let thread_a = std::thread::spawn(writer_a);
        let thread_b = std::thread::spawn(writer_b);

        let (res_a, overlapped_a) = thread_a
            .join()
            .unwrap_or_else(|e| panic!("thread A panicked: {e:?}"));
        let (res_b, overlapped_b) = thread_b
            .join()
            .unwrap_or_else(|e| panic!("thread B panicked: {e:?}"));
        any_round_overlapped |= overlapped_a || overlapped_b;

        let winner_body = match (&res_a, &res_b) {
            (Ok(()), Err(RootStoreError::AlreadyExists)) => &body_a,
            (Err(RootStoreError::AlreadyExists), Ok(())) => &body_b,
            other => {
                panic!("round {round}: want exactly one Ok + one AlreadyExists, got {other:?}")
            }
        };

        assert_eq!(
            reader_rt.block_on(reader.get_root(&vol, seq)),
            Ok(Some(winner_body.clone()))
        );
    }
    assert!(
        any_round_overlapped,
        "no overlapping writer PUT intervals observed in 20 rounds"
    );
}

#[tokio::test]
#[ignore = "needs a live MinIO — run scripts/minio-harness.sh test"]
async fn max_seq_numeric_max_with_scrambled_insertions_and_current_present() {
    let store = backend();
    let vol = unique_volume("max-seq");

    for seq in [3u64, 1, 2, 10] {
        assert_eq!(store.put_root(&vol, seq, vec![0]).await, Ok(()));
    }
    // CURRENT under the same prefix must not be mistaken for a root.
    assert_eq!(store.write_hint(&vol, 3).await, Ok(()));

    assert_eq!(store.max_seq(&vol).await, Ok(Some(10)));

    let empty_vol = unique_volume("max-seq-empty");
    assert_eq!(store.max_seq(&empty_vol).await, Ok(None));
}

#[tokio::test]
#[ignore = "needs a live MinIO — run scripts/minio-harness.sh test"]
async fn bin_dedup_and_range_read_exact_bytes_on_a_one_mib_object() {
    let store = backend();
    let data = sample_bytes(1024 * 1024);
    let digest = *GrainId::of(&data).digest();

    assert_eq!(store.put_bin(&digest, data.clone()).await, Ok(true));
    // Same digest again: dedup success, not an error.
    assert_eq!(store.put_bin(&digest, data.clone()).await, Ok(false));

    // A range read in the middle of the object.
    let offset = 500_000u64;
    let len = 4096u32;
    let offset_usize = usize::try_from(offset).unwrap_or_else(|e| panic!("{e}"));
    let len_usize = usize::try_from(len).unwrap_or_else(|e| panic!("{e}"));
    let expected = data
        .get(offset_usize..offset_usize + len_usize)
        .unwrap_or_else(|| panic!("test buffer too short"))
        .to_vec();

    assert_eq!(
        store.get_bin_range(&digest, offset, len).await,
        Ok(expected)
    );
}

/// THE ADVERSARIAL HINT CASES, ON A REAL SERVER.
///
/// The advisory contract is that a bad `CURRENT` body degrades to
/// `Missing` — never `Err`, which would wedge every reader's poll. The
/// hermetic lane proved that on `InMemory`, and `InMemory` was the
/// wrong witness: it evaluates ranges CLIENT-side and clamps, while a
/// real HTTP backend evaluates them server-side and `object_store`
/// hard-requires a 206 for any ranged GET. A suffix range on a
/// ZERO-LENGTH representation is unsatisfiable (RFC 9110 §14.1.1), so
/// S3/MinIO answered 416/200 and `read_hint` returned `Err(Backend)` —
/// one 0-byte PUT by any bucket writer wedged every reader, the exact
/// wedge the contract exists to prevent, reintroduced by a fix one
/// layer down and invisible because this lane had no garbage-body case
/// at all.
///
/// So the adversarial cases live HERE, against a real server, not only
/// in the hermetic lane. Each body is planted through the RAW client
/// (the `RootStore` API cannot write a malformed hint — `write_hint`
/// is total over `u64`), then read back through `read_hint`.
#[tokio::test]
#[ignore = "needs a live MinIO — run scripts/minio-harness.sh test"]
async fn garbage_hint_bodies_degrade_to_missing_on_a_real_backend() {
    let raw = client();
    let store = backend();

    // (label, body) — every one of these is a legitimate thing an
    // attacker (or a buggy peer) can PUT at an attacker-writable key.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // THE ZERO-BYTE CASE. No byte range is satisfiable on a
        // zero-length representation, so this is the one that broke.
        ("zero-byte", Vec::new()),
        // Shorter than the fixed width, but nonempty.
        ("short", b"123".to_vec()),
        // Right width, not digits.
        ("non-digit", b"00000000000000000abc".to_vec()),
        // Right width, digits, plus a trailing newline (the shape a
        // shell `echo > CURRENT` produces).
        ("trailing-newline", b"00000000000000000001\n".to_vec()),
        // Oversized: must not wedge, and must not be downloaded whole.
        ("oversized", vec![b'9'; 1024 * 1024]),
        // Not UTF-8 at the right width.
        ("non-utf8", vec![0xFF; 20]),
    ];

    for (label, body) in cases {
        let vol = unique_volume(&format!("hint-garbage-{label}"));
        let key = StorePath::from(format!("root/{vol}/CURRENT"));
        raw.put(&key, body.into())
            .await
            .unwrap_or_else(|e| panic!("{label}: plant failed: {e}"));
        assert_eq!(
            store.read_hint(&vol, None).await,
            Ok(HintRead::Missing),
            "{label}: a garbage CURRENT body must degrade to Missing on a \
             real backend, never Err — an Err here wedges every reader's \
             hint poll"
        );
    }
}

/// The forward-probe recovery a garbage hint threatens, end to end on a
/// real server: with a WEDGED-shaped hint (the 0-byte body) sitting at
/// `CURRENT`, a reader must still find the true head through the
/// documented fallback rather than failing. Proves the degradation is
/// USEFUL, not merely non-erroring — `Missing` is only the right answer
/// if the reader can still get home from it.
#[tokio::test]
#[ignore = "needs a live MinIO — run scripts/minio-harness.sh test"]
async fn a_zero_byte_hint_still_leaves_the_head_discoverable() {
    let raw = client();
    let store = backend();
    let vol = unique_volume("hint-zero-recovery");

    assert_eq!(store.put_root(&vol, 1, vec![0xAA]).await, Ok(()));
    assert_eq!(store.put_root(&vol, 2, vec![0xBB]).await, Ok(()));

    let key = StorePath::from(format!("root/{vol}/CURRENT"));
    raw.put(&key, Vec::new().into())
        .await
        .unwrap_or_else(|e| panic!("plant failed: {e}"));

    assert_eq!(store.read_hint(&vol, None).await, Ok(HintRead::Missing));
    // The Missing fallback: list the chain, client-side numeric max.
    assert_eq!(store.max_seq(&vol).await, Ok(Some(2)));
    assert_eq!(store.get_root(&vol, 2).await, Ok(Some(vec![0xBB])));
}

/// Counts outgoing `ListObjectsV2` requests and keys in `MinIO`'s raw
/// responses before the client parses the page or filters any key.
#[derive(Debug, Clone)]
struct ListTrace {
    observed: Arc<Mutex<ListObservations>>,
    last_root: String,
}

#[derive(Debug, Default)]
struct ListObservations {
    requests: usize,
    keys_per_page: Vec<usize>,
    last_root_page: Option<usize>,
}

impl ListTrace {
    fn take(&self) -> ListObservations {
        std::mem::take(&mut *self.observed.lock().unwrap_or_else(|e| panic!("{e}")))
    }
}

impl HttpConnector for ListTrace {
    fn connect(&self, options: &ClientOptions) -> object_store::Result<HttpClient> {
        Ok(HttpClient::new(TracedClient {
            inner: NoRedirectConnector.connect(options)?,
            trace: self.clone(),
        }))
    }
}

#[derive(Debug)]
struct TracedClient {
    inner: HttpClient,
    trace: ListTrace,
}

impl HttpService for TracedClient {
    // Match the boxed future in HttpService's async method signature.
    fn call<'a, 'f>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + 'f>>
    where
        'a: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            let is_list = request
                .uri()
                .query()
                .is_some_and(|query| query.split('&').any(|param| param == "list-type=2"));
            if !is_list {
                return self.inner.execute(request).await;
            }
            self.trace
                .observed
                .lock()
                .unwrap_or_else(|e| panic!("{e}"))
                .requests += 1;
            let response = self.inner.execute(request).await?;
            let (parts, body) = response.into_parts();
            let bytes = body.bytes().await?;
            let xml = std::str::from_utf8(&bytes).unwrap_or_else(|e| panic!("{e}"));
            let mut observed = self.trace.observed.lock().unwrap_or_else(|e| panic!("{e}"));
            observed
                .keys_per_page
                .push(xml.matches("<Contents>").count());
            if xml.contains(&self.trace.last_root) {
                observed.last_root_page = Some(observed.keys_per_page.len());
            }
            Ok(HttpResponse::from_parts(parts, bytes.into()))
        })
    }
}

/// Linux `MinIO` venue. The narrow probes at both depths each return one
/// key in one response. The wider probe must consume later pages even
/// when the prefix also has non-root objects and reserved sequences.
#[tokio::test]
#[ignore = "needs a live MinIO — run scripts/minio-harness.sh test"]
async fn max_seq_above_paginates_and_pushes_down_the_offset_on_minio() {
    let vol = unique_volume("list-offset");
    let trace = ListTrace {
        observed: Arc::default(),
        last_root: format!("<Key>root/{vol}/{:020}</Key>", 10_000),
    };
    let raw = client();
    let store = GranaryStore::new(client_with_connector(trace.clone()));
    let mut depth = 0;
    for top in [2_500_u64, 10_000] {
        for seq in (depth + 1)..=top {
            raw.put(
                &StorePath::from(format!("root/{vol}/{seq:020}")),
                Vec::new().into(),
            )
            .await
            .unwrap();
        }
        depth = top;
        assert_eq!(store.max_seq_above(&vol, top - 1).await, Ok(Some(top)));
        let observed = trace.take();
        eprintln!("{vol}, depth {top}, floor {}: {observed:?}", top - 1);
        assert_eq!(observed.requests, 1, "list requests at depth {top}");
        assert_eq!(observed.keys_per_page, [1], "keys returned at depth {top}");
    }

    for name in [
        format!("{:020}", 0),
        format!("{:020}", u64::MAX),
        "CURRENT".to_owned(),
        format!("junk/{:020}", depth + 1),
    ] {
        raw.put(
            &StorePath::from(format!("root/{vol}/{name}")),
            Vec::new().into(),
        )
        .await
        .unwrap();
    }
    let floor = depth - 2_500;
    let above = store.max_seq_above(&vol, floor).await;
    let observed = trace.take();
    assert!(
        observed.last_root_page.is_some_and(|page| page > 1),
        "expected the maximum on a later page: {observed:?}"
    );
    assert_eq!(observed.keys_per_page.iter().sum::<usize>(), 2_503);
    assert_eq!(above, Ok(Some(depth)));
    assert_eq!(
        above,
        store
            .max_seq(&vol)
            .await
            .map(|head| head.filter(|seq| *seq > floor))
    );
}
