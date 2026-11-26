// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::resolve` — the resolve oracle: read a
//! published volume back the way a mount would, through the pure
//! seams and nothing else.
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

// The child's items the PARENT's own rows still touch, imported by name.
// This is a `#[cfg(test)]` module, so an import used only by tests raises no
// `unused_imports` in a production build — which is why these four live here
// and not in `resolve.rs`, where three of them have no production caller.
use super::emission::{WHOLE_TREE_PATH_BUDGET, duplicate_span_peak, grain_span_facts, show};

// `resolve.rs` has no production use for these two, so it cannot carry them
// (`unused_imports` is denied) — but the parent's own rows use them. A split
// can strand an import this way, and only the compiler finds it: the seam
// analysis looks at ITEMS, and an import is not one.
use crate::fetcher::FETCH_INFLIGHT_BYTES;
use granary_core::manifest::DEPTH_MAX;
use granary_core::root;

/// The body of the fn whose signature begins with `opens`: from its first
/// `{` to the brace that closes it, found by counting braces outside string
/// literals, char literals and line comments, so the slice ends at the item's
/// own end however it is indented or followed. Comment lines are dropped.
/// Empty when `opens` or a balanced body is not found, which the callers'
/// positive controls then refuse.
fn fn_body(source: &str, opens: &str) -> String {
    let production = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or_default();
    let Some(after) = production.split(opens).nth(1) else {
        return String::new();
    };
    let Some(open) = after.find('{') else {
        return String::new();
    };
    let chars: Vec<char> = after.get(open..).unwrap_or_default().chars().collect();
    let mut depth = 0_usize;
    let mut i = 0;
    let mut end = None;
    while let Some(&c) = chars.get(i) {
        match c {
            '/' if chars.get(i + 1) == Some(&'/') => {
                while chars.get(i).is_some_and(|&c| c != '\n') {
                    i += 1;
                }
                continue;
            }
            '"' => {
                i += 1;
                while let Some(&c) = chars.get(i) {
                    if c == '\\' {
                        i += 2;
                        continue;
                    }
                    if c == '"' {
                        break;
                    }
                    i += 1;
                }
            }
            '\'' => {
                // A char literal ('x' or '\x'); a lifetime has no closing quote.
                if chars.get(i + 1) == Some(&'\\') {
                    i += 3;
                } else if chars.get(i + 2) == Some(&'\'') {
                    i += 2;
                }
            }
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let Some(end) = end else {
        return String::new();
    };
    chars
        .get(..=end)
        .unwrap_or_default()
        .iter()
        .collect::<String>()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// **The client's calls to `crypto::check_head` pass the RECEIVED bytes and
/// never a re-encoding of the decoded document.**
///
/// `granary_store`'s own scan pins that `check_head` verifies over the
/// buffer it is given. This is the caller's half: the buffer handed in must
/// be the one read from the store. Handing it `encode_root(&doc)` would pass
/// every behavioural row, because `encode_root` is canonical, while checking
/// bytes this process produced rather than the bytes the publisher signed;
/// so, as there, the source is where the difference lives and this row reads
/// it. The reader's `RootVerifier::check_head`, publisher's `state_from_head`,
/// and forwarding of received bytes from `remote_state` are covered.

#[test]
fn the_clients_head_check_is_handed_the_received_bytes_and_never_a_re_encoding() {
    const RESOLVE: &str = include_str!("../resolve.rs");
    const PUBLISH: &str = include_str!("../publish.rs");
    const CALL: &str = "crypto::check_head(";

    let remote = fn_body(PUBLISH, "async fn remote_state<");
    assert!(
        remote.contains("state_from_head(remote, volume, head, &bytes, &trusted)"),
        "remote_state must forward the received bytes to head verification"
    );
    for re_encoded in ["encode_root", "signing_prefix_of"] {
        assert!(!remote.contains(re_encoded));
    }

    for (name, body, received) in [
        (
            "RootVerifier::check_head",
            fn_body(RESOLVE, "pub(crate) fn check_head("),
            "root_bytes",
        ),
        (
            "state_from_head",
            fn_body(PUBLISH, "pub(crate) async fn state_from_head<"),
            "bytes",
        ),
    ] {
        // Positive controls first: a gate that cannot tell "clean" from
        // "read nothing" is not a gate.
        assert!(
            body.contains(CALL),
            "{name}: this row did not read the code it is judging"
        );
        for call in body.split(CALL).skip(1) {
            assert!(
                call.starts_with(&format!("{received},")),
                "{name}: check_head must be handed the received bytes \
                 `{received}` first, found {:?}",
                call.lines().next().unwrap_or_default()
            );
        }
        for re_encoded in ["encode_root", "signing_prefix_of"] {
            assert!(
                !body.contains(re_encoded),
                "{name}: {re_encoded:?} beside the head check verifies bytes \
                 this process produced rather than the bytes the publisher \
                 signed"
            );
        }
    }
}

// ------------------------------------------------- target-scoped resolve tests

use std::cell::RefCell;
use std::collections::BTreeMap as StdBTreeMap;
use std::future::Future as StdFuture;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use granary_core::binmap::ShardEntry;
use granary_core::clock::Clock;
use granary_core::hash::HashAlgorithm;
use granary_core::manifest::{
    DirEntry, EntryKind as ManifestEntryKind, FILE_INLINE_MAX_REFS, FileGrains, GRAIN_UNPACKED_MAX,
    GRAINLIST_LEAF_MAX_REFS, GrainListIndexChild, GrainRef, SymlinkTarget,
};
use granary_core::rng::{Rng, SeededRng};
use granary_core::root::{ED25519_SIG_LEN, KEY_ID_LEN, RootSig, Timestamp, VolumeName};
use granary_core::rootstore::{HintRead, HintToken, filter_above};
use granary_core::sheaf::SheafOp;
use granary_core::thresh::MAX_GRAIN;
use granary_store::codec::GrainCodec;

use crate::cache::CacheOrigin;
// These rows use `MANIFEST_NODE_MAX_BYTES`, and `use super::*` does not
// bring it: the parent `resolve.rs` does not import it, and production
// imports it only in the child modules `budget` and `structure`.
use granary_core::manifest::MANIFEST_NODE_MAX_BYTES;

use crate::fetcher::FETCH_WINDOW;

const TEST_VOLUME: &str = "resolve-test-vol";

fn seed_full_repeated_leaf_refusal(seam: &FakeSeam) -> (Name, u64) {
    const CHILDREN: u32 = 32_767;
    const LEAF_REFS: u32 = GRAINLIST_LEAF_MAX_REFS;

    let bin_digest = [0x19_u8; DIGEST_LEN];
    let refs: Vec<GrainRef> = (0..LEAF_REFS)
        .map(|i| GrainRef {
            id: routed_id(0, 0, u64::from(i)),
            unpacked_len: GRAIN_UNPACKED_MAX,
        })
        .collect();
    let leaf_bytes = manifest::encode_grain_list_leaf(&refs)
        .unwrap_or_else(|e| panic!("encode maximal shared leaf: {e}"));
    let leaf = GrainId::of(&leaf_bytes);
    let leaf_unpacked = u64::from(LEAF_REFS) * u64::from(GRAIN_UNPACKED_MAX);
    let children: Vec<GrainListIndexChild> = (1..=CHILDREN)
        .map(|i| GrainListIndexChild {
            child: leaf,
            cum_unpacked_len: u64::from(i) * leaf_unpacked,
            cum_ref_count: u64::from(i) * u64::from(LEAF_REFS),
        })
        .collect();
    let spill_bytes = manifest::encode_grain_list_index(&children)
        .unwrap_or_else(|e| panic!("encode repeated-leaf index: {e}"));
    let spill_root = GrainId::of(&spill_bytes);
    let grain_count = CHILDREN
        .checked_mul(LEAF_REFS)
        .unwrap_or_else(|| panic!("the format-accepted grain count must fit u32"));
    assert_eq!(grain_count, 4_294_836_224);
    let declared_size = u64::from(grain_count) * u64::from(GRAIN_UNPACKED_MAX);
    let file_name = Name::new(b"full-repeated-leaf.bin".to_vec())
        .unwrap_or_else(|e| panic!("build repeated-leaf file name: {e}"));
    let dir = manifest::build_dir(&[DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Spill {
                grain_count,
                root: spill_root,
            },
        },
    }])
    .unwrap_or_else(|e| panic!("build repeated-leaf directory: {e}"));

    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut entries: Vec<ShardEntry> = refs.iter().map(|r| unfetchable_entry(r.id)).collect();
    for (id, bytes) in [(leaf, leaf_bytes), (spill_root, spill_bytes)] {
        let (seeded, entry) = seed_grain(seam, &mut codec, bin_digest, &bytes);
        assert_eq!(seeded, id);
        entries.push(entry);
    }
    for (id, bytes) in &dir.nodes {
        let (seeded, entry) = seed_grain(seam, &mut codec, bin_digest, bytes);
        assert_eq!(seeded, *id);
        entries.push(entry);
    }
    assert_eq!(
        entries.len(),
        131_075,
        "131,072 content ids plus the leaf, index, and directory node must be mapped"
    );
    let binmap_index = seed_binmap(seam, 0, bin_digest, vec![entries]);
    seed_head(seam, dir.root, binmap_index);

    (
        file_name,
        u64::from(LEAF_REFS) * u64::from(GRAIN_UNPACKED_MAX),
    )
}

async fn assert_full_repeated_leaf_refuses_without_position_walk(target: ResolveTarget<'_>) {
    let seam = FakeSeam::default();
    let (file_name, expected_peak) = seed_full_repeated_leaf_refusal(&seam);
    let path = [file_name];
    let target = match target {
        ResolveTarget::Path(_) => ResolveTarget::Path(&path),
        ResolveTarget::WholeTree => ResolveTarget::WholeTree,
    };
    let outcome = resolve_at(&seam, TEST_VOLUME, 1, None, target, &mut discard_sink()).await;
    match outcome {
        Err(ResolveError::DuplicateSpanExceedsBudget { need, budget }) => {
            assert_eq!(need, expected_peak);
            assert_eq!(budget, FETCH_INFLIGHT_BYTES);
        }
        other => panic!(
            "expected the full repeated-leaf fixture to be refused at peak \
            {expected_peak}, got {other:?}"
        ),
    }
    assert_eq!(
        seam.bin_call_count([0x19_u8; DIGEST_LEN], 200_000_000),
        0,
        "the peak gate must refuse before any declared content extent is fetched"
    );
}

#[tokio::test]
async fn path_refuses_the_full_repeated_leaf_before_walking_positions() {
    assert_full_repeated_leaf_refuses_without_position_walk(ResolveTarget::Path(&[])).await;
}

#[tokio::test]
async fn whole_tree_refuses_the_full_repeated_leaf_before_walking_positions() {
    assert_full_repeated_leaf_refuses_without_position_walk(ResolveTarget::WholeTree).await;
}

/// A future that returns `Pending` exactly once before resolving —
/// forces a real overlap window between admission and completion
/// (mirrors `fetcher.rs`'s own test idiom).
#[derive(Default)]
struct YieldOnce(bool);

impl StdFuture for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// A hand-driven `RootStore + BinStore` seam: everything served is
/// bytes THIS test built, never decoded/re-encoded — the fixture
/// controls exactly what a fault-free volume would never produce
/// (a stray unreachable entry, a metadata set that would only fit
/// under an oversized budget), which is the point of a fake here
/// rather than a real backend.
#[derive(Default)]
pub(super) struct FakeSeam {
    roots: Mutex<StdBTreeMap<(String, u64), Vec<u8>>>,
    metas: Mutex<StdBTreeMap<(String, GrainId), Vec<u8>>>,
    bins: Mutex<StdBTreeMap<[u8; DIGEST_LEN], Vec<u8>>>,
    meta_calls: Mutex<StdBTreeMap<GrainId, usize>>,
    /// Keyed by (digest, offset): a `ShardEntry`'s own extent is
    /// unique per object, and `get_bin_range` never sees a claimed
    /// id — only the extent it was asked to read.
    bin_calls: Mutex<StdBTreeMap<([u8; DIGEST_LEN], u64), usize>>,
    concurrent_bytes: AtomicU64,
    high_water_bytes: AtomicU64,
    /// Sheds the FIRST `get_bin_range` call at this extent with
    /// `Unavailable` — targeted by (digest, offset) rather than by
    /// raw call ordinal, since a want's own bounded re-poll
    /// is itself another call at the SAME extent, and an ordinal
    /// count cannot tell that retry apart from a different want's
    /// first attempt. The fetcher's own retry bound then re-polls the
    /// shed want once, after `UNAVAILABLE_RETRY_DELAY`, which is
    /// what buys the OTHER admitted wants time to complete first
    /// (mirrors `fetcher.rs`'s `CountingSeam::shed`, extent-scoped).
    shed_extent: Mutex<Option<([u8; DIGEST_LEN], u64)>>,
    /// One extent that takes N EXTRA `YieldOnce` cycles before
    /// answering — a POLL-COUNT delay, never a wall-clock one, so a
    /// test can force TWO extents' own completions into a known
    /// relative order (more extra cycles resolves later) with no
    /// timer race involved.
    slow_extent: Mutex<Option<([u8; DIGEST_LEN], u64, u32)>>,
    /// The store's CURRENT hint pointer: `(seq, etag)`. `None` means
    /// `HintRead::Missing`. Independent of `roots` — a hint MAY name
    /// a seq `roots` has no entry for, which is exactly the shape
    /// discovery's own head-discovery tests need to construct.
    hint: Mutex<Option<(u64, String)>>,
    read_hint_calls: AtomicU64,
    max_seq_calls: AtomicU64,
    /// A clock-advance hook fired on the FIRST `get_meta` call this
    /// instance sees — proves a persisted hint stamp came from the
    /// WIRE-confirmation reading (discovery) rather than a LATER one
    /// (taken after the resolve proper, which always reaches
    /// `get_meta`, has started). `.take()`n so it fires at most once.
    clock_advance: Mutex<Option<(std::sync::Arc<std::sync::atomic::AtomicI64>, i64)>>,
}

impl FakeSeam {
    /// Shed the first `get_bin_range` call at `(digest, offset)`.
    pub(super) fn shed_extent(&self, digest: [u8; DIGEST_LEN], offset: u64) {
        *self.shed_extent.lock().unwrap_or_else(|e| panic!("{e}")) = Some((digest, offset));
    }

    /// Consume the shed token if `(digest, offset)` is the one
    /// target and it has not already fired.
    fn take_shed(&self, digest: [u8; DIGEST_LEN], offset: u64) -> bool {
        let mut slot = self.shed_extent.lock().unwrap_or_else(|e| panic!("{e}"));
        if *slot == Some((digest, offset)) {
            *slot = None;
            true
        } else {
            false
        }
    }

    /// Mark the first `get_bin_range` call at `(digest, offset)` to
    /// take `extra_yields` extra `YieldOnce` cycles before it
    /// answers.
    fn slow_extent(&self, digest: [u8; DIGEST_LEN], offset: u64, extra_yields: u32) {
        *self.slow_extent.lock().unwrap_or_else(|e| panic!("{e}")) =
            Some((digest, offset, extra_yields));
    }

    /// Consume the slow token if `(digest, offset)` is the one
    /// target and it has not already fired — the extra yield count,
    /// or `0` if this extent was never marked.
    fn take_slow(&self, digest: [u8; DIGEST_LEN], offset: u64) -> u32 {
        let mut slot = self.slow_extent.lock().unwrap_or_else(|e| panic!("{e}"));
        match *slot {
            Some((d, o, extra_yields)) if (d, o) == (digest, offset) => {
                *slot = None;
                extra_yields
            }
            _ => 0,
        }
    }

    fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) {
        self.roots
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .insert((volume.to_owned(), seq), bytes);
    }

    fn put_meta(&self, volume: &str, id: GrainId, bytes: Vec<u8>) {
        self.metas
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .insert((volume.to_owned(), id), bytes);
    }

    /// Set the store's CURRENT hint pointer to `(seq, token)`.
    fn set_hint(&self, seq: u64, token: &str) {
        *self.hint.lock().unwrap_or_else(|e| panic!("{e}")) = Some((seq, token.to_owned()));
    }

    /// Arm the clock-advance hook: on the FIRST `get_meta` call,
    /// `shared` is stamped to `advance_to`.
    fn advance_clock_on_first_meta_fetch(
        &self,
        shared: std::sync::Arc<std::sync::atomic::AtomicI64>,
        advance_to: i64,
    ) {
        *self.clock_advance.lock().unwrap_or_else(|e| panic!("{e}")) = Some((shared, advance_to));
    }

    /// Append `frame` to the bin named `digest`, padding a fresh bin
    /// with a header-sized prefix first (`ShardEntry::offset` must
    /// sit at or past `BIN_FIXED_HEADER_LEN`). Returns the offset
    /// `frame` was written at.
    fn append_to_bin(&self, digest: [u8; DIGEST_LEN], frame: &[u8]) -> u64 {
        let mut bins = self.bins.lock().unwrap_or_else(|e| panic!("{e}"));
        let bin = bins.entry(digest).or_insert_with(|| vec![0_u8; 14]);
        let offset = bin.len() as u64;
        bin.extend_from_slice(frame);
        offset
    }

    fn meta_call_count(&self, id: &GrainId) -> usize {
        self.meta_calls
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .get(id)
            .copied()
            .unwrap_or(0)
    }

    pub(super) fn bin_call_count(&self, digest: [u8; DIGEST_LEN], offset: u64) -> usize {
        self.bin_calls
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .get(&(digest, offset))
            .copied()
            .unwrap_or(0)
    }

    fn high_water_bytes(&self) -> u64 {
        self.high_water_bytes.load(Ordering::SeqCst)
    }

    fn begin_bytes(&self, n: u64) {
        let now = self.concurrent_bytes.fetch_add(n, Ordering::SeqCst) + n;
        self.high_water_bytes.fetch_max(now, Ordering::SeqCst);
    }

    fn end_bytes(&self, n: u64) {
        self.concurrent_bytes.fetch_sub(n, Ordering::SeqCst);
    }
}

impl RootStore for FakeSeam {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        unimplemented!("resolve never writes")
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        Ok(self
            .roots
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .get(&(volume.to_owned(), seq))
            .cloned())
    }

    async fn read_hint(
        &self,
        _volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        self.read_hint_calls.fetch_add(1, Ordering::SeqCst);
        let hint = self.hint.lock().unwrap_or_else(|e| panic!("{e}")).clone();
        Ok(match hint {
            None => HintRead::Missing,
            Some((seq, token)) => {
                if cached.map(|t| &t.0) == Some(&token) {
                    HintRead::NotModified
                } else {
                    HintRead::Current {
                        seq,
                        token: HintToken(token),
                    }
                }
            }
        })
    }

    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        unimplemented!("resolve never writes")
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        self.max_seq_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .roots
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .keys()
            .filter(|(v, _)| v == volume)
            .map(|(_, seq)| *seq)
            .max())
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

impl BinStore for FakeSeam {
    async fn put_bin(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        unimplemented!("resolve never writes")
    }

    async fn put_meta(
        &self,
        _volume: &str,
        _id: &GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        unimplemented!("resolve never writes")
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        if let Some((shared, advance_to)) = self
            .clock_advance
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .take()
        {
            shared.store(advance_to, Ordering::SeqCst);
        }
        {
            let mut calls = self.meta_calls.lock().unwrap_or_else(|e| panic!("{e}"));
            *calls.entry(*id).or_insert(0) += 1;
        }
        self.metas
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .get(&(volume.to_owned(), *id))
            .cloned()
            .ok_or(RootStoreError::NotFound)
    }

    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        {
            let mut calls = self.bin_calls.lock().unwrap_or_else(|e| panic!("{e}"));
            *calls.entry((*digest, offset)).or_insert(0) += 1;
        }
        for _ in 0..self.take_slow(*digest, offset) {
            YieldOnce::default().await;
        }
        self.begin_bytes(u64::from(len));
        YieldOnce::default().await;
        let result = if self.take_shed(*digest, offset) {
            Err(RootStoreError::Unavailable {
                operation: "GET bin",
                status: 503,
            })
        } else {
            self.bins
                .lock()
                .unwrap_or_else(|e| panic!("{e}"))
                .get(digest)
                .and_then(|bytes| {
                    let start = usize::try_from(offset).ok()?;
                    let end = start.checked_add(len as usize)?;
                    bytes.get(start..end).map(<[u8]>::to_vec)
                })
                .ok_or(RootStoreError::NotFound)
        };
        self.end_bytes(u64::from(len));
        result
    }
}

// ------------------------------------------------------ fixture glue

pub(super) fn volume() -> VolumeName {
    VolumeName::new(TEST_VOLUME.to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

fn stamp() -> Timestamp {
    Timestamp {
        secs: 1_760_000_000,
        nanos: 0,
    }
}

/// A `GrainId` that routes to shard `shard_index` under `prefix_bits`
/// (`binmap::shard_for`'s own rule: the top `prefix_bits` bits of the
/// first two digest bytes), with `salt` filling the rest for
/// uniqueness/order — never a hash of real content, which is exactly
/// right for an entry this fixture never intends to fetch.
pub(super) fn routed_id(prefix_bits: u8, shard_index: u32, salt: u64) -> GrainId {
    let top = if prefix_bits == 0 {
        0u16
    } else {
        (u16::try_from(shard_index).unwrap_or(u16::MAX)) << (16 - u32::from(prefix_bits))
    };
    let mut digest = [0_u8; DIGEST_LEN];
    digest[0..2].copy_from_slice(&top.to_be_bytes());
    digest[DIGEST_LEN - 8..].copy_from_slice(&salt.to_be_bytes());
    GrainId::from_parts(HashAlgorithm::Blake3, digest)
}

/// A `ShardEntry` that will never be fetched: a legal extent (the
/// encoder's own `check_extent` bound), pointing at a bin no test
/// ever seeds.
/// A deliberately huge, unique-looking offset — never a REAL entry's
/// extent (`seed_grain` appends starting at 14 and grows a bin one
/// frame at a time), so a call-count keyed by `(digest, offset)`
/// can never collide with something this fixture actually fetches.
pub(super) fn unfetchable_entry(id: GrainId) -> ShardEntry {
    ShardEntry {
        id,
        bin_ordinal: 0,
        offset: 200_000_000,
        comp_len: 10,
    }
}

/// Compress `payload`, seed it into `seam`'s one bin, and return the
/// `ShardEntry` naming it — a REAL, fetchable object.
pub(super) fn seed_grain(
    seam: &FakeSeam,
    codec: &mut GrainCodec,
    digest: [u8; DIGEST_LEN],
    payload: &[u8],
) -> (GrainId, ShardEntry) {
    let id = GrainId::of(payload);
    let frame = codec
        .compress_grain(payload)
        .unwrap_or_else(|e| panic!("{e}"));
    let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
    let offset = seam.append_to_bin(digest, &frame);
    (
        id,
        ShardEntry {
            id,
            bin_ordinal: 0,
            offset,
            comp_len,
        },
    )
}

/// Encode one shard, seed it as a meta object, and return its id.
fn seed_shard(seam: &FakeSeam, mut entries: Vec<ShardEntry>) -> GrainId {
    entries.sort_by_key(|e| e.id);
    let bytes = binmap::encode_shard(&entries).unwrap_or_else(|e| panic!("{e:?}"));
    let id = GrainId::of(&bytes);
    seam.put_meta(TEST_VOLUME, id, bytes);
    id
}

/// Build and seed a whole binmap (index + table + shards) naming one
/// bin digest, and return `(binmap_index_id, entries_map)` — the
/// entries map is what a real resolve would build too, handed back
/// so a test can assert against it directly.
fn seed_binmap(
    seam: &FakeSeam,
    prefix_bits: u8,
    bin_digest: [u8; DIGEST_LEN],
    shards: Vec<Vec<ShardEntry>>,
) -> GrainId {
    assert_eq!(shards.len(), 1usize << prefix_bits);
    let table_bytes = binmap::encode_bin_table(&[bin_digest]).unwrap_or_else(|e| panic!("{e:?}"));
    let table_id = GrainId::of(&table_bytes);
    seam.put_meta(TEST_VOLUME, table_id, table_bytes);

    let shard_ids: Vec<GrainId> = shards.into_iter().map(|e| seed_shard(seam, e)).collect();
    let index_bytes = binmap::encode_binmap_index(prefix_bits, table_id, &shard_ids)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let index_id = GrainId::of(&index_bytes);
    seam.put_meta(TEST_VOLUME, index_id, index_bytes);
    index_id
}

/// Seed a root + sheaf at seq 1 naming `manifest_root`/`binmap_index`,
/// unsigned (garbage sig slot — every test here resolves through the
/// UNVERIFIED entry points, which carry the slot through unread).
fn seed_head(seam: &FakeSeam, manifest_root: GrainId, binmap_index: GrainId) {
    let sheaf_bytes = sheaf::encode_sheaf(&SheafDoc {
        parent: None,
        manifest_root,
        timestamp: stamp(),
        ops: vec![SheafOp::PublishTree],
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    let sheaf_head = GrainId::of(&sheaf_bytes);
    seam.put_meta(TEST_VOLUME, sheaf_head, sheaf_bytes);

    let root_bytes = root::encode_root(&RootDoc {
        volume: volume(),
        seq: 1,
        parent: None,
        writer_uuid: [0_u8; 16],
        epoch: 1,
        timestamp: stamp(),
        chunker_spec: "resolve-test-fixture".to_owned(),
        manifest_root,
        binmap_index,
        sheaf_head,
        sigs: vec![RootSig {
            key_id: [0_u8; KEY_ID_LEN],
            sig: [0_u8; ED25519_SIG_LEN],
        }],
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    seam.put_root(TEST_VOLUME, 1, root_bytes);
}

fn discard_sink() -> impl FnMut(GrainId, &[u8]) -> Result<(), String> {
    |_, _| Ok(())
}

/// A minimal, fully valid, resolvable tree: one empty directory, at
/// seq 1 only — the smallest fixture `resolve_head_verified` can
/// walk end to end (unsigned; every caller here resolves through
/// the UNVERIFIED entry point).
fn seed_minimal_tree_at_seq1(seam: &FakeSeam) {
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x77_u8; DIGEST_LEN];
    let dir_bytes = manifest::build_dir(&[]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (_fetched_id, root_entry) = seed_grain(seam, &mut codec, bin_digest, &root_dir_payload);
    let index_id = seed_binmap(seam, 0, bin_digest, vec![vec![root_entry]]);
    seed_head(seam, root_dir_id, index_id);
}

/// A fresh `Cache::open`ed scratch dir, named per-test so parallel
/// tests never collide — the same inline pattern this module's other
/// cache-backed rows use, extracted once five rows needed it.
fn scratch_cache(name: &str) -> Cache {
    let cache_dir = std::env::temp_dir().join(format!("granary-resolve-test-{name}"));
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&cache_dir).unwrap_or_else(|e| panic!("{e}"));
    let origin = CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x33_u8; 32],
        root_key_id: None,
    };
    Cache::open(&cache_dir, 1024 * 1024 * 1024, &origin).unwrap_or_else(|e| panic!("{e}"))
}

/// A fixed reading — every test that needs "now" pins it
/// explicitly rather than reading the wall clock, matching
/// `head.rs`'s own test idiom.
struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

fn at(secs: i64) -> Box<dyn Clock> {
    Box::new(FixedClock(Timestamp { secs, nanos: 0 }))
}

fn seeded(seed: u64) -> Box<dyn Rng + Send> {
    Box::new(SeededRng::new(seed))
}

/// A `Clock` reading a shared, externally-mutable value — the
/// wire-confirmation-stamp test's instrument:
/// `FakeSeam::advance_clock_on_first_meta_fetch` bumps the SAME
/// `Arc<AtomicI64>` this reads, at a point (discovery's own wire
/// confirmation, vs. the resolve proper's first metadata fetch) that
/// lets the test prove WHICH reading a persisted stamp actually
/// used.
struct SharedNow(Arc<AtomicI64>);

impl Clock for SharedNow {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: self.0.load(Ordering::SeqCst),
            nanos: 0,
        }
    }
}

// -------------------------------------------------- hint and floor rows

/// A hint-derived candidate with no accompanying floor at all (the
/// legitimate "a hint was persisted before any floor-raising resolve
/// ever ran" state — `Cache::raise_anchor`'s own doc) must not be
/// stranded at `NoHead` when the store has since rolled back: a
/// fresh, still-within-TTL local hint answers zero-wire, names a seq
/// the store has NO root for at all, and the bounded `max_seq` retry
/// must recover the real head instead of surfacing `NoHead`.
#[tokio::test]
async fn a_fresh_hint_after_rollback_falls_back_to_max_seq_not_nohead() {
    let seam = FakeSeam::default();
    seed_minimal_tree_at_seq1(&seam);

    let mut cache = scratch_cache("fresh-hint-rollback");
    // Floor=1 (a real, previously-verified head) and a hint AHEAD of
    // it at seq 5 — the legitimate "a wire-confirmed hint was persisted
    // before the resolve it names has verified" state
    // (`Cache::raise_anchor`'s own doc): the hint seq need not equal
    // the floor except in steady state. `raise_anchor` requires a
    // real candidate to establish an anchor row at all on a fresh
    // cache dir (a bare hint-only call is a no-op with nothing to
    // attach to), so both are set in one call here.
    cache.raise_anchor(
        &volume(),
        Some(1),
        HintUpdate::Replace(PersistedHint {
            seq: 5, // no root at 5 — the store never had one, or rolled back
            token: "stale-hint".to_owned(),
            stamp_secs: 1_000,
        }),
    );

    let ctx = HeadContext::new(at(1_001), seeded(1)); // inside the TTL: the zero-wire shortcut fires
    let outcome = resolve_head_verified(
        &seam,
        TEST_VOLUME,
        &RootVerifier::unverified(),
        &ctx,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await;

    match outcome {
        Ok(o) => assert_eq!(o.seq, 1, "the bounded retry must land on the real head"),
        other => panic!(
            "a hint-derived candidate with no root must fall back to max_seq, not strand \
             the volume at NoHead: {other:?}"
        ),
    }
    assert!(
        seam.max_seq_calls.load(Ordering::SeqCst) >= 1,
        "the bounded retry must have consulted max_seq"
    );
}

/// The PERMANENT-WEDGE case: a `NotModified` wire answer whose root
/// has since been removed from the store re-derives the SAME
/// unresolvable candidate every time discovery alone is asked —
/// without the bounded retry this recurs forever. The bounded retry must answer
/// something other than `NoHead`: here, with no floor above the
/// retried candidate, the true head.
#[tokio::test]
async fn a_notmodified_whose_root_vanished_does_not_wedge() {
    let seam = FakeSeam::default();
    seed_minimal_tree_at_seq1(&seam);
    seam.set_hint(5, "t5"); // the store's OWN CURRENT pointer names 5 — no root backs it

    let mut cache = scratch_cache("notmodified-vanished");
    // Floor=5, hint={seq:5, token:"t5"} — matching the store's own
    // hint pointer exactly, so `read_hint` answers `NotModified`
    // (not `Current`) once the stamp below forces revalidation.
    cache.raise_anchor(
        &volume(),
        Some(5),
        HintUpdate::Replace(PersistedHint {
            seq: 5,
            token: "t5".to_owned(),
            stamp_secs: 0, // STALE relative to `ctx` below — forces the wire path
        }),
    );

    let ctx = HeadContext::new(at(1_000_000), seeded(1));
    let outcome = resolve_head_verified(
        &seam,
        TEST_VOLUME,
        &RootVerifier::unverified(),
        &ctx,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await;

    match outcome {
        Ok(o) => assert_eq!(o.seq, 1, "the bounded retry must land on the real head"),
        Err(ResolveError::StaleHead { .. }) => {
            // Also an honest, non-wedged answer — would occur here
            // only if a floor above the retried candidate existed,
            // which this test's fixture does not establish.
        }
        other => panic!(
            "a NotModified hint whose root vanished must not wedge the volume at NoHead \
             forever: {other:?}"
        ),
    }
    assert!(
        seam.read_hint_calls.load(Ordering::SeqCst) >= 1,
        "the stale local hint must have forced a wire revalidation"
    );
    assert!(
        seam.max_seq_calls.load(Ordering::SeqCst) >= 1,
        "the bounded retry must have consulted max_seq"
    );
}

/// A `Current` wire hint naming a seq strictly ahead of every root
/// the store actually has (the store's CURRENT pointer outran its
/// own numbered chain) must still resolve the real head via the
/// bounded retry, not surface `NoHead`.
#[tokio::test]
async fn a_current_hint_ahead_of_the_roots_resolves_the_real_head() {
    let seam = FakeSeam::default();
    seed_minimal_tree_at_seq1(&seam);
    seam.set_hint(9, "t9"); // ahead of the real chain (only seq 1 exists)

    let ctx = HeadContext::new(at(0), seeded(1));
    // No cache at all: no local hint, no floor — `read_hint` is sent
    // no cached token, so the store's `Current` answers directly.
    let outcome = resolve_head_verified(
        &seam,
        TEST_VOLUME,
        &RootVerifier::unverified(),
        &ctx,
        None,
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await;

    match outcome {
        Ok(o) => assert_eq!(o.seq, 1, "the bounded retry must land on the real head"),
        other => panic!(
            "a Current hint ahead of the real roots must resolve via the bounded retry, \
             not surface NoHead: {other:?}"
        ),
    }
    assert!(
        seam.max_seq_calls.load(Ordering::SeqCst) >= 1,
        "the bounded retry must have consulted max_seq"
    );
}

/// The persisted hint stamp must be the WIRE-confirmation reading
/// (inside discovery, at the `read_hint` 304/200 itself), never a
/// LATER one taken after the resolve that follows discovery has
/// already started. The clock advances (`1_000` -> `9_000`) on the
/// FIRST metadata fetch — a point strictly inside the resolve proper
/// and strictly after discovery has finished — so a stamp taken
/// AFTER that point is distinguishable from one taken before it.
#[tokio::test]
async fn the_hint_stamp_is_the_wire_confirmation_time() {
    let seam = FakeSeam::default();
    seed_minimal_tree_at_seq1(&seam);
    seam.set_hint(1, "t1");

    let shared = Arc::new(AtomicI64::new(1_000));
    seam.advance_clock_on_first_meta_fetch(shared.clone(), 9_000);

    let ctx = HeadContext::new(Box::new(SharedNow(shared)), seeded(1));
    let mut cache = scratch_cache("wire-confirmation-stamp");

    let outcome = resolve_head_verified(
        &seam,
        TEST_VOLUME,
        &RootVerifier::unverified(),
        &ctx,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(outcome.seq, 1);

    let anchor = cache
        .read_anchor(&volume())
        .unwrap_or_else(|| panic!("an anchor must be persisted"));
    let hint = anchor
        .hint
        .unwrap_or_else(|| panic!("a hint must be persisted"));
    assert_eq!(
        hint.stamp_secs, 1_000,
        "the persisted stamp must be the WIRE-confirmation reading (1_000), not a later \
         one taken after the resolve proper had already started (9_000)"
    );
}

/// A repeat resolve of an UNCHANGED head — the ordinary case
/// once the persisted hint is fresh — must not rewrite the anchor file at
/// all. The second call takes the zero-wire fresh-hint shortcut
/// (same seq, `HintUpdate::Unchanged`), so the combined commit's
/// own no-change comparison must skip the rename entirely.
#[tokio::test]
async fn a_repeat_resolve_of_an_unchanged_head_rewrites_nothing() {
    let seam = FakeSeam::default();
    seed_minimal_tree_at_seq1(&seam);
    seam.set_hint(1, "t1");

    let ctx = HeadContext::new(at(1_000), seeded(1));
    let mut cache = scratch_cache("repeat-resolve-unchanged");

    let first = resolve_head_verified(
        &seam,
        TEST_VOLUME,
        &RootVerifier::unverified(),
        &ctx,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(first.seq, 1);
    let writes_after_first = cache.anchor_write_count();
    assert!(
        writes_after_first >= 1,
        "the first resolve must have written the anchor at least once"
    );

    // Second call, still well inside the TTL (`ctx`'s clock is
    // fixed): the zero-wire fresh-hint shortcut answers the SAME
    // seq with no wire call at all, so nothing about the floor or
    // the hint has changed.
    let second = resolve_head_verified(
        &seam,
        TEST_VOLUME,
        &RootVerifier::unverified(),
        &ctx,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(second.seq, 1);
    assert_eq!(
        seam.read_hint_calls.load(Ordering::SeqCst),
        1,
        "the second resolve must take the zero-wire shortcut, not revalidate"
    );
    assert_eq!(
        cache.anchor_write_count(),
        writes_after_first,
        "a repeat resolve of an unchanged head must rewrite the anchor file ZERO times"
    );
}

// -------------------------------------------------------- value pins

/// A grain the binmap maps but the tree never references is never
/// asked for — oracle hole 2's discharge test.
#[tokio::test]
async fn an_unreachable_mapped_object_is_never_fetched() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x01_u8; DIGEST_LEN];

    // The whole tree: one empty directory.
    let dir_bytes = manifest::build_dir(&[]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(dir_bytes.nodes.len(), 1, "an empty dir is one leaf");
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (fetched_id, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    assert_eq!(fetched_id, root_dir_id);

    // A stray grain: mapped, never referenced by anything above.
    let stray_id = routed_id(0, 0, 1);
    let stray_entry = unfetchable_entry(stray_id);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![vec![root_entry, stray_entry]]);
    seed_head(&seam, root_dir_id, index_id);

    let outcome = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(outcome.entries.len(), 2, "both entries are mapped");

    assert_eq!(
        seam.bin_call_count(bin_digest, root_entry.offset),
        1,
        "the reachable root dir must have been fetched"
    );
    assert_eq!(
        seam.bin_call_count(bin_digest, stray_entry.offset),
        0,
        "the unreachable stray grain must NEVER be fetched"
    );
}

// -------------------------------------------------- metadata budget

/// `n` distinct, strictly-sorted entries routing to shard
/// `shard_index` under `prefix_bits`, none of them ever fetchable.
fn unfetchable_shard(prefix_bits: u8, shard_index: u32, n: u32) -> Vec<ShardEntry> {
    (0..n)
        .map(|i| unfetchable_entry(routed_id(prefix_bits, shard_index, u64::from(i))))
        .collect()
}

/// A binmap declaring enough shards, each near
/// `binmap::SHARD_MAX_ENTRIES`, that the running
/// `entries.len() * ENTRY_COST_BYTES` charge alone crosses
/// [`METADATA_BUDGET_BYTES`] partway through the shard loop — no
/// object fetch anywhere, and the CROSSING shard's own fetch count
/// must read exactly 0: admission must refuse the crossing fetch
/// before its wire call.
#[tokio::test]
async fn a_head_declaring_more_metadata_than_the_budget_is_refused_not_oomd() {
    // 13 shards of SHARD_MAX_ENTRIES each: charge crosses the budget
    // during shard 13 (index 12)'s pre-check (12 shards land, ~250.7
    // MiB; +16 MiB worst-case for the 13th exceeds 256 MiB).
    const SHARDS: u32 = 13;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x02_u8; DIGEST_LEN];

    let dir_bytes = manifest::build_dir(&[]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);

    let per_shard = binmap::SHARD_MAX_ENTRIES;
    let prefix_bits = {
        let mut bits = 0_u8;
        while (1usize << bits) < SHARDS as usize {
            bits += 1;
        }
        bits
    };
    let shard_count = 1usize << prefix_bits;
    let mut shards: Vec<Vec<ShardEntry>> = (0..SHARDS)
        .map(|s| unfetchable_shard(prefix_bits, s, per_shard))
        .collect();
    for _ in SHARDS as usize..shard_count {
        shards.push(Vec::new());
    }
    // The root dir's own entry is a REAL hash, routing wherever
    // `shard_for` actually sends it — never assumed to be shard 0.
    // Pop one filler first if that shard is already at the cap, so
    // adding the real entry never trips `TooManyEntries`.
    let root_shard = binmap::shard_for(&root_dir_id, prefix_bits);
    if shards[root_shard].len() >= per_shard as usize {
        shards[root_shard].pop();
    }
    shards[root_shard].push(root_entry);
    shards[root_shard].sort_by_key(|e| e.id);

    // Seed shards directly (bypassing `seed_binmap`'s single-bin-
    // digest assert, which does not constrain shard count).
    let table_bytes = binmap::encode_bin_table(&[bin_digest]).unwrap_or_else(|e| panic!("{e:?}"));
    let table_id = GrainId::of(&table_bytes);
    seam.put_meta(TEST_VOLUME, table_id, table_bytes);
    let shard_ids: Vec<GrainId> = shards
        .into_iter()
        .map(|entries| seed_shard(&seam, entries))
        .collect();
    let last_shard_id = *shard_ids
        .get(SHARDS as usize - 1)
        .unwrap_or_else(|| panic!("at least {SHARDS} shards"));
    let index_bytes = binmap::encode_binmap_index(prefix_bits, table_id, &shard_ids)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let index_id = GrainId::of(&index_bytes);
    seam.put_meta(TEST_VOLUME, index_id, index_bytes);
    seed_head(&seam, root_dir_id, index_id);

    let err = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await
    .expect_err("the metadata set must be refused, never materialised");
    assert!(
        matches!(err, ResolveError::MetadataBudgetExceeded { .. }),
        "expected MetadataBudgetExceeded, got {err:?}"
    );
    assert_eq!(
        seam.meta_call_count(&last_shard_id),
        0,
        "the crossing shard must never be fetched — refused BEFORE the wire call"
    );
}

/// The layer-up attack: many SMALL shards (each
/// shard's own bytes stay well under `META_MAX_BYTES`) whose combined
/// ENTRY COUNT alone crosses the budget — `entries.len() *
/// ENTRY_COST_BYTES` is what refuses this, not retained shard bytes.
#[tokio::test]
async fn the_entries_map_alone_can_cross_the_budget() {
    // 4096 "tiny" shards (PREFIX_BITS_MAX's own width): each shard
    // holds a modest entry count, so no single shard's bytes come
    // anywhere near META_MAX_BYTES, but 4096 * 600 ~= 2.46M entries
    // costs 2.46M * 128 B ~= 300 MiB — over budget on entries alone.
    const PREFIX_BITS: u8 = 12;
    const SHARD_COUNT: u32 = 1 << PREFIX_BITS;
    const PER_SHARD: u32 = 600;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x03_u8; DIGEST_LEN];

    let dir_bytes = manifest::build_dir(&[]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);

    let mut shards: Vec<Vec<ShardEntry>> = (0..SHARD_COUNT)
        .map(|s| unfetchable_shard(PREFIX_BITS, s, PER_SHARD))
        .collect();
    // The root dir's own entry is a REAL hash — route it correctly
    // rather than assuming shard 0.
    let root_shard = binmap::shard_for(&root_dir_id, PREFIX_BITS);
    shards[root_shard].push(root_entry);
    shards[root_shard].sort_by_key(|e| e.id);

    let table_bytes = binmap::encode_bin_table(&[bin_digest]).unwrap_or_else(|e| panic!("{e:?}"));
    let table_id = GrainId::of(&table_bytes);
    seam.put_meta(TEST_VOLUME, table_id, table_bytes);
    let shard_ids: Vec<GrainId> = shards
        .into_iter()
        .map(|entries| seed_shard(&seam, entries))
        .collect();
    let last_shard_id = *shard_ids
        .last()
        .unwrap_or_else(|| panic!("at least one shard"));
    let index_bytes = binmap::encode_binmap_index(PREFIX_BITS, table_id, &shard_ids)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let index_id = GrainId::of(&index_bytes);
    seam.put_meta(TEST_VOLUME, index_id, index_bytes);
    seed_head(&seam, root_dir_id, index_id);

    let err = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await
    .expect_err("2.46M entries at ENTRY_COST_BYTES each must be refused");
    assert!(
        matches!(err, ResolveError::MetadataBudgetExceeded { .. }),
        "expected MetadataBudgetExceeded, got {err:?}"
    );
    assert_eq!(
        seam.meta_call_count(&last_shard_id),
        0,
        "the crossing (last) shard must never be fetched"
    );
}

/// The crossing shard the module's own charge arithmetic predicts,
/// replaying [`fetch_meta_budgeted`]'s exact call sequence (index,
/// then table, both at `entries_len = 0`; then one
/// `charge_before_fetch` check per shard using the entries
/// count BEFORE that shard's own entries land) against the REAL
/// encoded object sizes this fixture builds — never a shard count
/// verified by hand and pinned as a comment.
fn predicted_crossing_shard(
    index_len: usize,
    table_len: usize,
    shard_byte_lens: &[usize],
    shard_entry_counts: &[usize],
) -> usize {
    let mut budget = MetadataBudget::default();
    budget.fold(index_len);
    budget.fold(table_len);
    for (i, (&len, &count)) in shard_byte_lens.iter().zip(shard_entry_counts).enumerate() {
        if budget.charge_before_fetch(META_MAX_BYTES).is_err() {
            return i;
        }
        budget.fold(len);
        budget.bump_entries(count);
    }
    panic!(
        "fixture of {} shards never crosses the budget — grow the candidate count",
        shard_byte_lens.len()
    );
}

/// The pre-fetch metadata-budget gate refuses AT the shard whose own
/// charge check would cross the budget — computed here from the
/// SAME arithmetic the gate runs
/// ([`predicted_crossing_shard`]), not a shard count verified by
/// hand. Every shard before the crossing one is fetched exactly
/// once; the crossing shard's own wire call count reads zero (kills
/// a mutant that checks the budget AFTER the fetch instead of
/// before it — that mutant would let the crossing shard's call
/// count read 1).
#[tokio::test]
async fn the_budget_refuses_at_the_true_crossing_shard() {
    const CANDIDATE_SHARDS: u32 = 13;
    let per_shard = binmap::SHARD_MAX_ENTRIES;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x09_u8; DIGEST_LEN];

    let dir_bytes = manifest::build_dir(&[]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);

    let prefix_bits = {
        let mut bits = 0_u8;
        while (1usize << bits) < CANDIDATE_SHARDS as usize {
            bits += 1;
        }
        bits
    };
    let shard_count = 1usize << prefix_bits;
    let mut shards: Vec<Vec<ShardEntry>> = (0..CANDIDATE_SHARDS)
        .map(|s| unfetchable_shard(prefix_bits, s, per_shard))
        .collect();
    for _ in CANDIDATE_SHARDS as usize..shard_count {
        shards.push(Vec::new());
    }
    let root_shard = binmap::shard_for(&root_dir_id, prefix_bits);
    if shards[root_shard].len() >= per_shard as usize {
        shards[root_shard].pop();
    }
    shards[root_shard].push(root_entry);
    shards[root_shard].sort_by_key(|e| e.id);

    let shard_entry_counts: Vec<usize> = shards.iter().map(Vec::len).collect();

    let table_bytes = binmap::encode_bin_table(&[bin_digest]).unwrap_or_else(|e| panic!("{e:?}"));
    let table_id = GrainId::of(&table_bytes);
    let table_len = table_bytes.len();
    seam.put_meta(TEST_VOLUME, table_id, table_bytes);

    let mut shard_ids: Vec<GrainId> = Vec::with_capacity(shards.len());
    let mut shard_lens: Vec<usize> = Vec::with_capacity(shards.len());
    for mut entries in shards {
        // Mirrors `seed_shard` exactly, but keeps the encoded length
        // too — the crossing prediction below needs the REAL byte
        // count, not an assumed one.
        entries.sort_by_key(|e| e.id);
        let bytes = binmap::encode_shard(&entries).unwrap_or_else(|e| panic!("{e:?}"));
        let id = GrainId::of(&bytes);
        shard_lens.push(bytes.len());
        seam.put_meta(TEST_VOLUME, id, bytes);
        shard_ids.push(id);
    }

    let index_bytes = binmap::encode_binmap_index(prefix_bits, table_id, &shard_ids)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let index_id = GrainId::of(&index_bytes);
    let index_len = index_bytes.len();
    seam.put_meta(TEST_VOLUME, index_id, index_bytes);
    seed_head(&seam, root_dir_id, index_id);

    let crossing = predicted_crossing_shard(index_len, table_len, &shard_lens, &shard_entry_counts);
    assert!(
        crossing < CANDIDATE_SHARDS as usize,
        "the crossing shard must land among the real (non-filler) shards, or \
         this fixture proves nothing about the real gate"
    );

    let err = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await
    .expect_err("the metadata set must be refused, never materialised");
    assert!(
        matches!(err, ResolveError::MetadataBudgetExceeded { .. }),
        "expected MetadataBudgetExceeded, got {err:?}"
    );

    for &id in &shard_ids[..crossing] {
        assert_eq!(
            seam.meta_call_count(&id),
            1,
            "every shard before the predicted crossing one must have been fetched"
        );
    }
    assert_eq!(
        seam.meta_call_count(&shard_ids[crossing]),
        0,
        "the crossing shard must never be fetched — refused BEFORE the wire call"
    );
}

/// Drives a resolve whose metadata budget crosses during the tree
/// walk — one `charge_before_fetch` check per structure node, at
/// [`MANIFEST_NODE_MAX_BYTES`]'s worst case, `entries_len` FIXED
/// (unlike the shard loop, nothing here grows it). Every figure
/// asserted below comes from what the run actually did
/// (`seam.bin_call_count`), never from a hand-replayed prediction of
/// which node crosses. The pre-fetch metadata-budget gate refuses
/// mid-way through the manifest STRUCTURE walk — not because binmap
/// loading alone crossed it (padding shards land comfortably under
/// budget, with a small headroom left over) but because
/// [`fetch_tree_structure`]'s own [`MANIFEST_NODE_MAX_BYTES`]-worst-case
/// pre-charge, applied once per structure node, is what finally tips
/// the running charge over.
/// Most of the tree's structure nodes succeed first (mid-pump, never
/// a refusal on the very first structure fetch); at least one never
/// does, and its own wire call count reads zero (kills a mutant that
/// drops `fetch_tree_structure`'s pre-charge entirely — that mutant
/// would let every one of them fetch, however many the tree has, and
/// the run would never surface `MetadataBudgetExceeded` at all).
///
/// **Every count here comes from what the run actually did**
/// (`seam.bin_call_count`), never from a hand-replayed prediction of
/// exactly which node crosses — `validate_dir_tree`'s own walk order
/// among sibling nodes is its own implementation detail, not a
/// contract this test binds to; the metadata-budget gate's contract
/// is only "some prefix of the pump succeeds, then it refuses",
/// which is exactly what is checked below.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture (padding shards, a wide flat tree, seeding every structure \
              node) built and driven through one resolve — splitting it loses the shared \
              fixture the assertions all read back from"
)]
async fn the_tree_pump_charges_before_it_fetches() {
    // Padding: 16 shards (an EXACT power of two — no leftover empty
    // shard slots, each of which would otherwise force its OWN
    // META_MAX_BYTES worst-case check with no entries to show for
    // it), each holding the SAME computed entry count, chosen so
    // the running charge lands close to the budget while still
    // leaving room for the SHEAF fetch's own META_MAX_BYTES
    // worst-case check right before the tree walk starts — that
    // check, not the tree walk's smaller MANIFEST_NODE_MAX_BYTES
    // one, is what sets the floor on how much headroom the
    // structure phase can ever have (this format's own worst-case
    // model, not a choice this test makes).
    const PADDING_SHARDS: u32 = 16;
    const PER_SHARD_ENTRIES: u32 = 88_000;
    // Generous: the walk needs several dozen of these to cross, at
    // ~75 KB of REAL bytes per max-size leaf against the several-MB
    // headroom the sheaf's own worst-case check leaves behind.
    const LEAVES: usize = 260;
    // A comfortable floor for "most of the tree succeeded first" —
    // measured empirically at roughly 166 of 263 nodes for this
    // exact fixture; well under that still proves mid-pump.
    const MIN_EXPECTED_SUCCESSES: usize = 100;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0c_u8; DIGEST_LEN];

    // The tree: one flat directory of `LEAVES * 256` file entries,
    // each with a maximal (255-byte) name so `build_dir` chunks it
    // into `LEAVES` max-size leaves under one or more interior
    // nodes — real per-leaf bytes, not modelled ones, are what this
    // test's crossing depends on.
    let mut flat_entries: Vec<DirEntry> = Vec::with_capacity(LEAVES * 256);
    for i in 0..(LEAVES * 256) {
        let mut name = vec![b'a'; 255];
        let tag = format!("{i:08x}");
        let tag_bytes = tag.as_bytes();
        name[255 - tag_bytes.len()..].copy_from_slice(tag_bytes);
        flat_entries.push(DirEntry {
            name: Name::new(name).unwrap_or_else(|e| panic!("{e}")),
            kind: ManifestEntryKind::File {
                exec: false,
                size: 1,
                grains: FileGrains::Inline(vec![GrainRef {
                    id: routed_id(0, 0, u64::try_from(i).unwrap_or(0)),
                    unpacked_len: 1,
                }]),
            },
        });
    }
    flat_entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let dir_bytes = manifest::build_dir(&flat_entries).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        dir_bytes.nodes.len() > LEAVES,
        "expected {LEAVES} leaves plus at least one interior node, got {}",
        dir_bytes.nodes.len()
    );
    let node_count = dir_bytes.nodes.len();

    // Seed every structure node (leaves and every interior level
    // above them, whatever shape `build_dir` produced) as a REAL,
    // fetchable grain, and route each into a padding shard.
    let prefix_bits = {
        let mut bits = 0_u8;
        while (1usize << bits) < PADDING_SHARDS as usize {
            bits += 1;
        }
        bits
    };
    let shard_count = 1usize << prefix_bits;
    assert_eq!(
        shard_count, PADDING_SHARDS as usize,
        "PADDING_SHARDS must be an exact power of two — a leftover empty \
         shard slot would force its own META_MAX_BYTES worst-case check \
         with no entries to show for it"
    );
    // Route every structure node to its shard FIRST — grouped, not
    // interleaved with filler generation — so that TWO nodes
    // landing in the SAME shard can never have the second's
    // insertion pop the first's own entry back out (a plain
    // pop-while-inserting scheme has exactly that bug: `Vec::pop`
    // removes from the END, which after the first node's `push` is
    // the first node's own entry, not a filler one).
    let mut node_entries: Vec<ShardEntry> = Vec::with_capacity(node_count);
    let mut structure_by_shard: Vec<Vec<ShardEntry>> = vec![Vec::new(); PADDING_SHARDS as usize];
    for (id, bytes) in &dir_bytes.nodes {
        let frame = codec
            .compress_grain(bytes)
            .unwrap_or_else(|e| panic!("{e}"));
        let comp_len = u32::try_from(frame.len()).unwrap_or_else(|e| panic!("{e}"));
        let offset = seam.append_to_bin(bin_digest, &frame);
        let entry = ShardEntry {
            id: *id,
            bin_ordinal: 0,
            offset,
            comp_len,
        };
        let shard = binmap::shard_for(id, prefix_bits);
        structure_by_shard[shard].push(entry);
        node_entries.push(entry);
    }
    let shards: Vec<Vec<ShardEntry>> = (0..PADDING_SHARDS as usize)
        .map(|s| {
            let extra = structure_by_shard[s].len();
            let filler_count =
                u32::try_from(PER_SHARD_ENTRIES as usize - extra).unwrap_or_else(|e| panic!("{e}"));
            let mut shard =
                unfetchable_shard(prefix_bits, u32::try_from(s).unwrap_or(0), filler_count);
            shard.extend(structure_by_shard[s].iter().copied());
            shard.sort_by_key(|e| e.id);
            shard
        })
        .collect();

    let table_bytes = binmap::encode_bin_table(&[bin_digest]).unwrap_or_else(|e| panic!("{e:?}"));
    let table_id = GrainId::of(&table_bytes);
    seam.put_meta(TEST_VOLUME, table_id, table_bytes);

    let mut shard_ids: Vec<GrainId> = Vec::with_capacity(shards.len());
    for entries in shards {
        let bytes = binmap::encode_shard(&entries).unwrap_or_else(|e| panic!("{e:?}"));
        let id = GrainId::of(&bytes);
        seam.put_meta(TEST_VOLUME, id, bytes);
        shard_ids.push(id);
    }

    let index_bytes = binmap::encode_binmap_index(prefix_bits, table_id, &shard_ids)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let index_id = GrainId::of(&index_bytes);
    seam.put_meta(TEST_VOLUME, index_id, index_bytes);
    seed_head(&seam, dir_bytes.root, index_id);

    let mut sink_calls = 0_usize;
    let err = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| {
            sink_calls += 1;
            Ok(())
        },
    )
    .await
    .expect_err(
        "a manifest whose structure nodes cross the metadata budget mid-pump \
         must never resolve",
    );
    assert!(
        matches!(err, ResolveError::MetadataBudgetExceeded { .. }),
        "expected MetadataBudgetExceeded, got {err:?}"
    );
    assert_eq!(
        sink_calls, 0,
        "emission never starts before the tree walk itself completes"
    );

    // The root itself must have been fetched — otherwise this is a
    // refusal on the very first structure attempt, not a mid-pump
    // one, and the fixture would need retuning rather than the test
    // claiming a property it did not actually exercise.
    let root_offset = node_entries
        .iter()
        .find(|e| e.id == dir_bytes.root)
        .unwrap_or_else(|| panic!("the root must have a seeded entry"))
        .offset;
    assert_eq!(
        seam.bin_call_count(bin_digest, root_offset),
        1,
        "the root/interior node itself must succeed — a refusal here would be \
         the very first structure fetch, not a MID-pump one"
    );

    let fetched = node_entries
        .iter()
        .filter(|e| seam.bin_call_count(bin_digest, e.offset) == 1)
        .count();
    assert!(
        fetched >= MIN_EXPECTED_SUCCESSES,
        "expected at least {MIN_EXPECTED_SUCCESSES} of {node_count} structure \
         nodes to succeed before the budget refused — got {fetched}, which is \
         too few to call this a MID-pump crossing"
    );
    assert!(
        fetched < node_count,
        "every structure node succeeded ({fetched} of {node_count}) — the \
         budget never actually refused anything, so this fixture proves \
         nothing about the pre-charge gate"
    );
}

/// **A wide but LEGAL grain-list leaf must resolve.** `60_000` refs
/// sits well inside `GRAINLIST_LEAF_MAX_REFS` (`131_072` — the bare
/// leaf IS the spill root, no index level over it) and well past
/// `FILE_INLINE_MAX_REFS` (128 — the file's grains canonically
/// spill), yet the leaf's own encoded width — 10-byte envelope +
/// 4-byte count + `60_000` × 37-byte refs = `2_220_014` bytes —
/// exceeds [`MAX_GRAIN`] (2 MiB), the CONTENT-grain chunker cap a
/// STRUCTURE-node fetch must never be declared against (see
/// `MANIFEST_NODE_MAX_BYTES`'s own doc for why). Every legal
/// manifest can hold a leaf this wide; a reader that refuses one
/// poisons the whole file — and, since `fetch_tree_structure` walks
/// every file's structure regardless of target, the whole volume.
///
/// The `Path` target names a DIFFERENT, small file: the wide leaf's
/// own `60_000` grain refs need only be MAPPED in the binmap (cheap,
/// and the structure walk never asks for their content), never
/// seeded as real objects. The structure walk still fetches the
/// wide leaf ITSELF, checked below — that fetch is what this test
/// is about.
#[tokio::test]
async fn a_wide_but_legal_grain_list_leaf_resolves() {
    const WIDE_REFS: u32 = 60_000;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0d_u8; DIGEST_LEN];

    let wide_refs: Vec<GrainRef> = (0..WIDE_REFS)
        .map(|i| GrainRef {
            id: routed_id(0, 0, u64::from(i)),
            unpacked_len: 1,
        })
        .collect();
    let leaf_built = manifest::build_grain_list(&wide_refs).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        leaf_built.nodes.len(),
        1,
        "60_000 <= N stays a single leaf, no index level"
    );
    let (leaf_id, leaf_bytes) = leaf_built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one leaf"));
    assert!(
        leaf_bytes.len() > MAX_GRAIN,
        "the fixture's own point: {} encoded bytes must exceed the {MAX_GRAIN}-byte \
         content-grain ceiling a structure-node fetch must never be declared at",
        leaf_bytes.len()
    );
    let (fetched_leaf_id, leaf_entry) = seed_grain(&seam, &mut codec, bin_digest, &leaf_bytes);
    assert_eq!(fetched_leaf_id, leaf_id);

    let small_name = Name::new(b"small.txt".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let small_payload = b"hi".to_vec();
    let (small_grain_id, small_entry) = seed_grain(&seam, &mut codec, bin_digest, &small_payload);

    let big_name = Name::new(b"big.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let entries = vec![
        DirEntry {
            name: big_name,
            kind: ManifestEntryKind::File {
                exec: false,
                size: u64::from(WIDE_REFS),
                grains: FileGrains::Spill {
                    grain_count: WIDE_REFS,
                    root: leaf_id,
                },
            },
        },
        DirEntry {
            name: small_name.clone(),
            kind: ManifestEntryKind::File {
                exec: false,
                size: u64::try_from(small_payload.len()).unwrap_or_else(|e| panic!("{e}")),
                grains: FileGrains::Inline(vec![GrainRef {
                    id: small_grain_id,
                    unpacked_len: u32::try_from(small_payload.len())
                        .unwrap_or_else(|e| panic!("{e}")),
                }]),
            },
        },
    ];
    let dir_built = manifest::build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(dir_built.nodes.len(), 1, "two entries fit in one dir leaf");
    let (root_id, root_bytes) = dir_built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one dir leaf"));
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_bytes);

    // The wide leaf's own 60_000 refs: mapped so `check_reachable_grains`
    // never refuses the tree, never fetched (`unfetchable_entry`'s own
    // extent points nowhere real).
    let mut shard_entries = vec![root_entry, leaf_entry, small_entry];
    shard_entries.extend(wide_refs.iter().map(|r| unfetchable_entry(r.id)));
    let index_id = seed_binmap(&seam, 0, bin_digest, vec![shard_entries]);
    seed_head(&seam, root_id, index_id);

    let path = vec![small_name];
    let outcome = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut discard_sink(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        outcome.entries.len(),
        WIDE_REFS as usize + 3,
        "root + leaf + small-file entries, plus every wide-leaf ref"
    );
    assert_eq!(
        seam.bin_call_count(bin_digest, leaf_entry.offset),
        1,
        "the structure walk must have fetched the wide leaf itself"
    );
}

/// **The ceiling still refuses a node no legal encoder could ever
/// produce.** The negative half of
/// [`a_wide_but_legal_grain_list_leaf_resolves`]: a structure node
/// TWO bytes past `MANIFEST_NODE_MAX_BYTES` is corrupt or hostile by
/// definition, and the fetcher's completion guard must still refuse
/// it — naming `MANIFEST_NODE_MAX_BYTES`, not `MAX_GRAIN`. Two
/// bytes, not one, so the `got` assertion below can tell the real
/// decompressed length apart from a hypothetical guard that stops at
/// `declared + 1` and reports that capped figure.
///
/// `finish()` hash-checks BEFORE the width check (its own doc), so
/// the oversized bytes must hash correctly to the id that names
/// them; otherwise this would surface as `Corrupt`, proving nothing
/// about the ceiling. The manifest root names these bytes directly
/// — the walk's very first structure fetch is the one under test.
#[tokio::test]
async fn a_structure_node_wider_than_any_legal_node_is_still_refused() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0e_u8; DIGEST_LEN];

    let oversized_len = MANIFEST_NODE_MAX_BYTES as usize + 2;
    let blob = vec![0xAB_u8; oversized_len];
    let (root_id, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &blob);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![vec![root_entry]]);
    seed_head(&seam, root_id, index_id);

    let outcome = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await;

    match outcome {
        Err(ResolveError::OverDeclared { id, declared, got }) => {
            assert_eq!(id, root_id, "the refusal must name the oversized node");
            assert_eq!(
                declared, MANIFEST_NODE_MAX_BYTES,
                "the charge/declaration must be MANIFEST_NODE_MAX_BYTES, never \
                 MAX_GRAIN"
            );
            assert_eq!(
                got, oversized_len,
                "the refusal must cite the node's real decompressed length"
            );
        }
        other => panic!(
            "expected a structure node past MANIFEST_NODE_MAX_BYTES to surface as \
             OverDeclared, got {other:?}"
        ),
    }
}

/// **The ceiling holds on the CACHE path too.** The fetcher's
/// cache-hit branch (`deliver_cache_hit`) enforces a want's
/// `unpacked_len` exactly as `finish()` does on the wire path,
/// so an oversized hit is refused `OverDeclared` INSIDE the
/// fetcher and reaches this resolve through `map_fetch_err` —
/// the same variant, the same fields, the pump's own re-check
/// already produced. That provenance is invisible from
/// `resolve_at` (this row is green with either check alone);
/// the mechanism is pinned at the fetcher by
/// `fetcher::tests::a_cache_hit_wider_than_its_declaration_is_refused_before_delivery`,
/// and the pump's re-check stays as defence in depth where both
/// delivery paths converge. Same oversized blob as the wire-path
/// negative above, arriving from a primed cache instead: same
/// refusal, and the wire is never touched.
#[tokio::test]
async fn a_cached_structure_node_wider_than_the_ceiling_is_refused() {
    let seam = FakeSeam::default();
    let bin_digest = [0x10_u8; DIGEST_LEN];

    let oversized_len = MANIFEST_NODE_MAX_BYTES as usize + 2;
    let blob = vec![0xCD_u8; oversized_len];
    let blob_id = GrainId::of(&blob);
    // Mapped (the pump refuses unmapped ids before any fetch), but
    // at an extent no seeded bin serves — a wire fetch would fail
    // loudly; only the cache can answer.
    let entry = unfetchable_entry(blob_id);
    let index_id = seed_binmap(&seam, 0, bin_digest, vec![vec![entry]]);
    seed_head(&seam, blob_id, index_id);

    let cache_dir = std::env::temp_dir()
        .join("granary-resolve-test-a-cached-structure-node-wider-than-the-ceiling");
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&cache_dir).unwrap_or_else(|e| panic!("{e}"));
    let origin = CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x22_u8; 32],
        root_key_id: None,
    };
    let mut cache =
        Cache::open(&cache_dir, 1024 * 1024 * 1024, &origin).unwrap_or_else(|e| panic!("{e}"));
    cache.insert(&blob_id, &blob);

    let outcome = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut discard_sink(),
    )
    .await;

    match outcome {
        Err(ResolveError::OverDeclared { id, declared, got }) => {
            assert_eq!(id, blob_id, "the refusal must name the oversized node");
            assert_eq!(
                declared, MANIFEST_NODE_MAX_BYTES,
                "the cache path must enforce the same ceiling as the wire path"
            );
            assert_eq!(got, oversized_len);
        }
        other => panic!(
            "expected a cached structure node past MANIFEST_NODE_MAX_BYTES to surface \
             as OverDeclared, got {other:?}"
        ),
    }
    assert_eq!(
        seam.bin_call_count(bin_digest, entry.offset),
        0,
        "the bytes must have come from the cache, never the wire"
    );
}

// ------------------------------------------------------ The pool

/// The smallest legal directory node: one `DirLeaf` holding a single
/// reserved-tag entry. Used where a row needs a node whose IDENTITY
/// matters and whose content does not.
pub(super) fn fifo_leaf(name: &[u8]) -> Vec<u8> {
    manifest::encode_dir_leaf(&[DirEntry {
        name: Name::new(name.to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"))
}

/// A child-DIRECTORY entry — the kind that puts an id on the nesting
/// worklist, which is what makes it a queued root.
pub(super) fn dir_entry(name: &[u8], child: GrainId) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::Dir { child },
    }
}

/// A `gran cat` of one big file: one directory holding a file of 34
/// inline 2 MiB grains (68 MiB total, comfortably over
/// `FETCH_INFLIGHT_BYTES` = 64 MiB). The PATH-targeted emission
/// streams it within the fetcher's in-flight byte bound, and the
/// emitted bytes equal the fixture's own known content exactly — the
/// equivalence control, without a pre-refactor binary to diff
/// against. (A `Path` target, not `WholeTree`: the whole-tree case
/// also emits structure-node bytes, immaterial to the bound this
/// test is about.)
#[tokio::test]
async fn a_whole_tree_cat_streams_within_the_inflight_bound() {
    const GRAINS: usize = 34;
    const GRAIN_LEN: usize = 2 * 1024 * 1024;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x04_u8; DIGEST_LEN];

    let mut refs = Vec::with_capacity(GRAINS);
    let mut entries = Vec::with_capacity(GRAINS + 1);
    let mut expected = Vec::with_capacity(GRAINS * GRAIN_LEN);
    for i in 0..GRAINS {
        // Incompressible-ish filler, distinct per grain, so a bug
        // that emitted the WRONG grain or the wrong order shows up
        // immediately in the byte comparison below. The wrap to `u8`
        // is the point (a byte-wide filler pattern), not a bug —
        // `try_from` would just replace an intentional truncation
        // with a manufactured error path.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "deliberate wraparound filler pattern, not a length computation"
        )]
        let payload: Vec<u8> = (0..GRAIN_LEN)
            .map(|b| {
                (b as u32)
                    .wrapping_mul(2_654_435_761)
                    .wrapping_add(i as u32) as u8
            })
            .collect();
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        refs.push(GrainRef {
            id,
            unpacked_len: u32::try_from(GRAIN_LEN).unwrap_or_else(|e| panic!("{e}")),
        });
        entries.push(entry);
        expected.extend_from_slice(&payload);
    }

    let file_name = Name::new(b"big.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: u64::try_from(expected.len()).unwrap_or_else(|e| panic!("{e}")),
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    entries.push(root_entry);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir_id, index_id);

    // A PATH target, deliberately: `WholeTree` also emits every
    // structure node's own bytes (the closest equivalent to a
    // whole-tree object map), which would have to be accounted for
    // separately here for no benefit — the property under test is
    // content streaming within the in-flight bound, which a single
    // targeted file already exercises fully.
    let mut collected: Vec<u8> = Vec::new();
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.extend_from_slice(bytes);
        Ok(())
    };
    let path = vec![file_name];
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        collected, expected,
        "the emitted bytes must equal the fixture's own known content, in order"
    );
    assert!(
        seam.high_water_bytes() <= FETCH_INFLIGHT_BYTES,
        "high-water in-flight bytes {} exceeded the {} byte bound",
        seam.high_water_bytes(),
        FETCH_INFLIGHT_BYTES
    );
    // The bound is not vacuous: the fixture's own total exceeds it,
    // so a resolve that (incorrectly) retained everything at once
    // would have tripped the assertion above.
    assert!(
        expected.len() as u64 > FETCH_INFLIGHT_BYTES,
        "fixture must exceed the bound for the assertion above to mean anything"
    );
}

/// The SAME fixture as [`a_whole_tree_cat_streams_within_the_inflight_bound`],
/// but the file's FIRST grain is deliberately delayed (`FakeSeam::shed`)
/// so every other grain completes and is HELD before it finally
/// arrives — forcing the holdback path
/// [`a_whole_tree_cat_streams_within_the_inflight_bound`] can pass
/// without ever exercising, since nothing there is guaranteed to
/// complete out of admission order.
///
/// The shed targets the file's first content grain's OWN extent
/// specifically (`FakeSeam::shed_extent`, not a raw call ordinal):
/// the manifest structure walk fetches the root directory node
/// first, through the SAME `get_bin_range` seam, and an ordinal
/// count cannot tell that call — or grain 0's own bounded
/// re-poll, itself another call at grain 0's extent — apart from
/// the one call this test actually means to delay.
///
/// **Bytes still arrive in FILE order** (kills a mutant that emits
/// as soon as a grain arrives rather than draining the in-order
/// prefix — with the first grain forced last, such a mutant would
/// emit grain 2 before grain 1, an ordering the exact byte
/// comparison below catches immediately). **The seam's high-water
/// in-flight bytes stays within the fetcher's own budget** (kills a
/// mutant that ignores or drops `on_complete`'s release — an
/// implementation that never releases a held grain's charge would
/// either wedge this run entirely, since admission for anything
/// past the window could never re-open, or — if it instead
/// over-releases — let far more than [`FETCH_INFLIGHT_BYTES`] worth
/// of wire reads run concurrently; either way this bound would not
/// hold, and completing at all within a delayed run is itself part
/// of what the FIFO/no-deadlock argument promises).
#[tokio::test]
async fn in_order_emission_survives_a_delayed_first_grain() {
    const GRAINS: usize = 34;
    const GRAIN_LEN: usize = 2 * 1024 * 1024;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0a_u8; DIGEST_LEN];

    let mut refs = Vec::with_capacity(GRAINS);
    let mut entries = Vec::with_capacity(GRAINS + 1);
    let mut expected = Vec::with_capacity(GRAINS * GRAIN_LEN);
    for i in 0..GRAINS {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "deliberate wraparound filler pattern, not a length computation"
        )]
        let payload: Vec<u8> = (0..GRAIN_LEN)
            .map(|b| {
                (b as u32)
                    .wrapping_mul(2_654_435_761)
                    .wrapping_add(i as u32) as u8
            })
            .collect();
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        refs.push(GrainRef {
            id,
            unpacked_len: u32::try_from(GRAIN_LEN).unwrap_or_else(|e| panic!("{e}")),
        });
        entries.push(entry);
        expected.extend_from_slice(&payload);
    }

    let file_name = Name::new(b"delayed.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: u64::try_from(expected.len()).unwrap_or_else(|e| panic!("{e}")),
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    entries.push(root_entry);
    let grain_0_offset = entries[0].offset;

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir_id, index_id);

    // Target grain 0's own extent specifically — see the doc above
    // for why an ordinal call count cannot do this safely.
    seam.shed_extent(bin_digest, grain_0_offset);

    let mut collected: Vec<u8> = Vec::new();
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.extend_from_slice(bytes);
        Ok(())
    };
    let path = vec![file_name];
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        collected, expected,
        "bytes must arrive in FILE order even though the first grain \
         completed LAST — every later grain was held for it, not emitted \
         the moment it arrived"
    );
    assert!(
        seam.high_water_bytes() <= FETCH_INFLIGHT_BYTES,
        "high-water in-flight bytes {} exceeded the {} byte bound — the \
         held grains' charge did not gate admission the way a correct \
         release must",
        seam.high_water_bytes(),
        FETCH_INFLIGHT_BYTES
    );
}

/// A three-grain file where the MIDDLE grain's real (fetched,
/// decompressed) length disagrees with what the manifest declares
/// for it — `emit_file`'s per-grain length check
/// (`ResolveError::GrainLenMismatch`), which the module doc says
/// stops emission AT the mismatch: "a position already emitted
/// before it is a proven-correct prefix, never rewound; no position
/// after it is emitted."
///
/// A counting sink tracks bytes PER ID. The mismatched grain's own
/// id must never appear in it at all (kills a mutant that emits
/// THEN checks the length — `emit-then-error`), and neither must the
/// GOOD grain after it (proving the stop is real, not merely a
/// skip of the bad one). Only the good grain BEFORE it — the proven
/// prefix — may have reached the sink.
#[tokio::test]
async fn a_length_mismatch_never_reaches_the_sink() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0b_u8; DIGEST_LEN];

    let payload0 = b"first grain, honest about its own length".to_vec();
    let (id0, entry0) = seed_grain(&seam, &mut codec, bin_digest, &payload0);
    let declared0 = u32::try_from(payload0.len()).unwrap_or_else(|e| panic!("{e}"));

    // The lying grain: the manifest declares seven bytes more than
    // this grain's real (decompressed) content actually is.
    let payload1 = b"second grain, the one whose declared length is wrong".to_vec();
    let (id1, entry1) = seed_grain(&seam, &mut codec, bin_digest, &payload1);
    let declared1 = u32::try_from(payload1.len()).unwrap_or_else(|e| panic!("{e}")) + 7;

    let payload2 = b"third grain, must never be reached".to_vec();
    let (id2, entry2) = seed_grain(&seam, &mut codec, bin_digest, &payload2);
    let declared2 = u32::try_from(payload2.len()).unwrap_or_else(|e| panic!("{e}"));

    let refs = vec![
        GrainRef {
            id: id0,
            unpacked_len: declared0,
        },
        GrainRef {
            id: id1,
            unpacked_len: declared1,
        },
        GrainRef {
            id: id2,
            unpacked_len: declared2,
        },
    ];
    // The declared file size must equal the sum of DECLARED lengths
    // — the manifest node decoder's own size/sum cross-check, which
    // runs at build time, before any fetch and long before the
    // per-grain check this test is about.
    let declared_size = u64::from(declared0) + u64::from(declared1) + u64::from(declared2);

    let file_name = Name::new(b"lying.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);

    let index_id = seed_binmap(
        &seam,
        0,
        bin_digest,
        vec![vec![entry0, entry1, entry2, root_entry]],
    );
    seed_head(&seam, root_dir_id, index_id);

    let mut bytes_for: BTreeMap<GrainId, usize> = BTreeMap::new();
    let mut sink = |id: GrainId, bytes: &[u8]| -> Result<(), String> {
        *bytes_for.entry(id).or_insert(0) += bytes.len();
        Ok(())
    };
    let path = vec![file_name];
    let err = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await
    .expect_err("a grain whose real length disagrees with its declared length must not resolve");
    assert!(
        matches!(
            err,
            ResolveError::GrainLenMismatch { id, want, got, .. }
                if id == id1 && want == declared1 && got == payload1.len()
        ),
        "expected a GrainLenMismatch naming the lying grain, got {err:?}"
    );
    assert_eq!(
        bytes_for.get(&id1),
        None,
        "the mismatched grain's own bytes must never reach the sink"
    );
    assert_eq!(
        bytes_for.get(&id2),
        None,
        "nothing after the mismatch may reach the sink either — the stop is \
         real, not a skip of the one bad grain"
    );
    assert_eq!(
        bytes_for.get(&id0).copied(),
        Some(payload0.len()),
        "the proven-correct prefix before the mismatch must still have been emitted"
    );
}

/// **An error must never wedge the fetcher — a completion that
/// arrives AFTER the first error must release its charge
/// immediately, never buffer it.** A regression here lets a later
/// `Ok` completion fall through to the normal
/// insert-and-drain path even once `first_err` was already set;
/// since the drain cursor can never advance past the position that
/// failed (nothing is ever going to fill that gap), every such
/// completion's own drain attempt finds nothing resident at the
/// stuck position and returns `0` — forever. Its charge (the
/// DECOMPRESSED size, once converted) then sits in
/// `fetch_streaming`'s `in_flight_bytes` permanently: enough of
/// those and admission has nothing left to give a still-queued
/// want room for, `in_flight` empties out as every wire call that
/// WAS admitted finishes (buggily releasing nothing), and
/// `poll_fn` returns `Pending` with no waker left to ever fire
/// again — a permanent hang, not merely a delay.
///
/// **The fixture puts real budget behind the claim.** Position 0
/// fails outright (its extent was never written). Eight ordinary
/// grains at exactly `GRAIN_UNPACKED_MAX` follow — their
/// decompressed sum is exactly `FETCH_INFLIGHT_BYTES` — then
/// filler wants fill the admission window to exactly
/// `FETCH_WINDOW`, and one WITNESS want sits excluded from wave
/// one. Under the defect the eight large grains' charge never
/// frees, so the witness can never be admitted at all — this
/// test's own manual poll loop is the tripwire: a capped loop
/// converts what would otherwise be a genuine, silent hang into a
/// clean, bounded assertion failure.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture (an erroring want, eight large grains, filler, one witness \
              want) built and driven in sequence, then checked against a manual poll \
              loop — splitting it loses the shared want list and budget arithmetic the \
              assertions depend on"
)]
fn an_error_mid_file_surfaces_and_never_wedges() {
    const LARGE_GRAINS: usize = 8;
    const FILLER_WANTS: usize = 23;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0d_u8; DIGEST_LEN];

    let mut refs: Vec<GrainRef> = Vec::new();
    let mut entries: Vec<ShardEntry> = Vec::new();

    // Position 0: fails outright — its extent was never written to
    // the seam's bin, so the wire call surfaces `NotFound`.
    let error_payload = b"never actually written".to_vec();
    let error_id = GrainId::of(&error_payload);
    refs.push(GrainRef {
        id: error_id,
        unpacked_len: u32::try_from(error_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(unfetchable_entry(error_id));

    // Positions 1..9: eight ordinary grains at exactly
    // GRAIN_UNPACKED_MAX — decompressed sum equals
    // FETCH_INFLIGHT_BYTES exactly, so a stuck charge here is
    // enough to permanently block the witness below.
    for i in 0..LARGE_GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
        entries.push(entry);
    }

    // Positions 9..32: filler wants, ordinary, trivial size — fill
    // wave one to exactly FETCH_WINDOW (1 error + 8 large + 23
    // filler = 32).
    for i in 0..FILLER_WANTS {
        let payload = format!("filler {i}").into_bytes();
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        refs.push(GrainRef {
            id,
            unpacked_len: u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}")),
        });
        entries.push(entry);
    }

    // Position 32 (the 33rd real want): the witness — excluded
    // from wave one, must be admitted only once the error frees
    // the budget.
    let witness_payload = b"witness grain".to_vec();
    let (witness_id, witness_entry) = seed_grain(&seam, &mut codec, bin_digest, &witness_payload);
    refs.push(GrainRef {
        id: witness_id,
        unpacked_len: u32::try_from(witness_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(witness_entry);

    assert_eq!(
        refs.len(),
        1 + LARGE_GRAINS + FILLER_WANTS + 1,
        "fixture shape must match this test's own trace of it"
    );
    let real_wants = 1 + LARGE_GRAINS + FILLER_WANTS;
    assert_eq!(
        real_wants, FETCH_WINDOW,
        "wave one must fill the window exactly, leaving the witness as the \
         one want excluded from it"
    );
    assert_eq!(
        u64::from(GRAIN_UNPACKED_MAX) * LARGE_GRAINS as u64,
        FETCH_INFLIGHT_BYTES,
        "the eight large grains' decompressed sum must equal the budget \
         exactly, or a stuck witness proves nothing about the wedge"
    );

    let declared_size: u64 = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
    let file_name = Name::new(b"wedge.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    entries.push(root_entry);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir_id, index_id);

    let mut sink = discard_sink();
    let path = vec![file_name];
    let fut = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    );
    let mut fut = std::pin::pin!(fut);

    let mut cx = Context::from_waker(Waker::noop());
    let mut polls: u32 = 0;
    let outcome = loop {
        polls += 1;
        assert!(
            polls < 500,
            "the resolve did not settle within a sane poll budget — this IS \
             the permanent-hang wedge: a later completion's charge stayed \
             buffered forever after the first error, leaving nothing in \
             flight to ever wake admission for the still-queued witness want"
        );
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(r) => break r,
            Poll::Pending => {}
        }
    };

    match outcome {
        Err(ResolveError::Missing { id, .. }) => {
            assert_eq!(
                id, error_id,
                "the surfaced error must be the one this fixture caused"
            );
        }
        other => panic!(
            "expected the position-0 failure to surface as ResolveError::Missing, got {other:?}"
        ),
    }
}

/// **Two positions naming the SAME grain with CONFLICTING declared
/// lengths are two SEPARATE checks, each
/// against its OWN declaration — never a single id-keyed value
/// that collapses both references down to one remembered
/// length.** Position 0 declares the grain's TRUE length; position
/// 1 (the same id, later in the file) declares a length that does
/// not match reality. Under positional truth this must fail AT
/// position 1 specifically, citing position 1's own declaration —
/// after position 0's own, genuinely correct, emission has already
/// reached the sink. Under an id-keyed check (first-wins OR
/// last-wins — this fixture kills either): whichever declaration
/// gets remembered decides BOTH positions' outcome together, so
/// either the resolve wrongly SUCCEEDS in full (first-wins: both
/// checks reuse position 0's correct length, and the actual bytes
/// really do match it) or position 0's own correct emission is
/// wrongly rejected (last-wins).
///
/// One wire fetch answers both positions (`fetch_streaming`'s own
/// admission dedups by id), so the divergence lives entirely in
/// how the ONE resulting buffer gets checked against each of the
/// two declarations that name it.
#[test]
fn a_duplicate_ref_checks_each_position_declaration() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0e_u8; DIGEST_LEN];

    let payload = b"duplicate content for positional truth".to_vec();
    let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
    let correct_len = u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}"));
    let wrong_len = correct_len + 7;

    let refs = vec![
        GrainRef {
            id,
            unpacked_len: correct_len,
        },
        GrainRef {
            id,
            unpacked_len: wrong_len,
        },
    ];
    let declared_size = u64::from(correct_len) + u64::from(wrong_len);

    let file_name = Name::new(b"duplicate.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(node_id, _)| *node_id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![vec![entry, root_entry]]);
    seed_head(&seam, root_dir_id, index_id);

    let mut calls: Vec<(GrainId, usize)> = Vec::new();
    let path = vec![file_name];
    let outcome = {
        let mut sink = |sunk_id: GrainId, bytes: &[u8]| -> Result<(), String> {
            calls.push((sunk_id, bytes.len()));
            Ok(())
        };
        let fut = resolve_at(
            &seam,
            TEST_VOLUME,
            1,
            None,
            ResolveTarget::Path(&path),
            &mut sink,
        );
        let mut fut = std::pin::pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(r) => break r,
                Poll::Pending => {}
            }
        }
    };

    match outcome {
        Err(ResolveError::GrainLenMismatch {
            id: mismatched_id,
            want,
            got,
            ..
        }) => {
            assert_eq!(
                mismatched_id, id,
                "the mismatch must be reported against this grain"
            );
            assert_eq!(
                want, wrong_len,
                "the mismatch must cite POSITION 1's own declaration, not position 0's"
            );
            assert_eq!(
                got,
                payload.len(),
                "the mismatch must cite the grain's real length"
            );
        }
        other => panic!(
            "expected position 1's own wrong declaration to surface as \
             GrainLenMismatch, got {other:?}"
        ),
    }
    assert_eq!(
        calls,
        vec![(id, payload.len())],
        "position 0's own, genuinely correct emission must have reached the sink \
         exactly once before the mismatch stopped things — never zero times (that \
         would mean position 0 was wrongly rejected too) and never twice (that \
         would mean position 1 was wrongly accepted)"
    );
}

/// **The guard compares a hit against the want's `unpacked_len` —
/// the MAX across a duplicate's positions (`grain_span_facts`) — so
/// a cached grain that fits its max but not a SMALLER occurrence is
/// delivered `Ok` by the fetcher and refused at drain, per position,
/// as `GrainLenMismatch` naming that occurrence.** The cache-path
/// twin of [`a_duplicate_ref_checks_each_position_declaration`]:
/// one grain, two positions declaring its true length and then
/// seven bytes less, resident in the cache and mapped at an extent
/// no bin serves — the bytes can only have come from the cache.
/// Position 0's correct emission reaches the sink exactly once;
/// position 1's own declaration is what the refusal names. This
/// row pins this mapping (`OverDeclared` at the fetcher for a
/// hit WIDER than its max; `GrainLenMismatch` at drain for a
/// narrower occurrence) so a later change to `emit_file`'s
/// holdback re-runs it — the register's error-timing row.
#[tokio::test]
async fn a_cached_duplicate_within_its_max_still_fails_its_smaller_position() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x11_u8; DIGEST_LEN];

    let payload = b"duplicate content, cached, positionally checked".to_vec();
    let id = GrainId::of(&payload);
    let correct_len = u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}"));
    let smaller_len = correct_len - 7;

    let refs = vec![
        GrainRef {
            id,
            unpacked_len: correct_len,
        },
        GrainRef {
            id,
            unpacked_len: smaller_len,
        },
    ];
    let declared_size = u64::from(correct_len) + u64::from(smaller_len);

    let file_name = Name::new(b"cached-dup.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(node_id, _)| *node_id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    // Mapped, but at an extent no seeded bin serves: a wire fetch
    // would fail loudly, so only the cache can answer.
    let entry = unfetchable_entry(id);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![vec![entry, root_entry]]);
    seed_head(&seam, root_dir_id, index_id);

    let cache_dir = std::env::temp_dir().join("granary-resolve-test-cached-dup-smaller-position");
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&cache_dir).unwrap_or_else(|e| panic!("{e}"));
    let origin = CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x22_u8; 32],
        root_key_id: None,
    };
    let mut cache =
        Cache::open(&cache_dir, 1024 * 1024 * 1024, &origin).unwrap_or_else(|e| panic!("{e}"));
    cache.insert(&id, &payload);

    let mut calls: Vec<(GrainId, usize)> = Vec::new();
    let path = vec![file_name];
    let outcome = {
        let mut sink = |sunk_id: GrainId, bytes: &[u8]| -> Result<(), String> {
            calls.push((sunk_id, bytes.len()));
            Ok(())
        };
        resolve_at(
            &seam,
            TEST_VOLUME,
            1,
            Some(&mut cache),
            ResolveTarget::Path(&path),
            &mut sink,
        )
        .await
    };

    match outcome {
        Err(ResolveError::GrainLenMismatch {
            id: mismatched_id,
            want,
            got,
            ..
        }) => {
            assert_eq!(
                (mismatched_id, want, got),
                (id, smaller_len, payload.len()),
                "the drain-time check must name THIS grain, cite POSITION 1's own smaller \
                 declaration, and report the cached bytes' real length"
            );
        }
        other => panic!(
            "expected position 1's smaller declaration to surface as GrainLenMismatch \
             (the hit fits its MAX declaration, so the fetcher's guard must pass it), \
             got {other:?}"
        ),
    }
    assert_eq!(
        calls,
        vec![(id, payload.len())],
        "position 0's correct emission reaches the sink exactly once before the mismatch"
    );
    assert_eq!(
        seam.bin_call_count(bin_digest, entry.offset),
        0,
        "the bytes must have come from the cache, never the wire"
    );
}

/// **A declaration SMALLER than the grain's real content fails at
/// the FETCHER, never reaches drain's own positional check.** One
/// grain, one position: the manifest declares `unpacked_len` seven
/// bytes SHORT of the payload's true length — the same shape as
/// [`a_duplicate_ref_checks_each_position_declaration`]'s position
/// 1, but with only one occurrence, so there is no earlier position
/// whose correct emission could reach the sink first. `finish()`'s
/// own guard refuses this before the bytes are ever cached or held —
/// true of the WIRE, which is this fixture's only path (it passes no
/// cache at all); a cache hit is refused by `deliver_cache_hit`
/// instead, and its object stays cached —
/// which is why the resolve surfaces
/// [`ResolveError::OverDeclared`], not
/// [`ResolveError::GrainLenMismatch`] — the drain-time check this
/// grain never lives long enough to reach.
#[test]
fn a_grain_declared_smaller_than_its_real_content_is_refused_not_held() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0f_u8; DIGEST_LEN];

    let payload = b"a grain whose manifest entry lies about its own length".to_vec();
    let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
    let real_len = u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}"));
    let lying_len = real_len - 7;

    let refs = vec![GrainRef {
        id,
        unpacked_len: lying_len,
    }];

    let file_name = Name::new(b"lying.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: u64::from(lying_len),
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(node_id, _)| *node_id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![vec![entry, root_entry]]);
    seed_head(&seam, root_dir_id, index_id);

    let mut calls: Vec<(GrainId, usize)> = Vec::new();
    let path = vec![file_name];
    let outcome = {
        let mut sink = |sunk_id: GrainId, bytes: &[u8]| -> Result<(), String> {
            calls.push((sunk_id, bytes.len()));
            Ok(())
        };
        let fut = resolve_at(
            &seam,
            TEST_VOLUME,
            1,
            None,
            ResolveTarget::Path(&path),
            &mut sink,
        );
        let mut fut = std::pin::pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(r) => break r,
                Poll::Pending => {}
            }
        }
    };

    match outcome {
        Err(ResolveError::OverDeclared {
            id: over_id,
            declared,
            got,
        }) => {
            assert_eq!(over_id, id, "the refusal must name this grain");
            assert_eq!(
                declared, lying_len,
                "the refusal must cite the charge the fetcher actually admitted at"
            );
            assert_eq!(
                got,
                payload.len(),
                "the refusal must cite the grain's real decompressed length"
            );
        }
        other => panic!(
            "expected the under-declared grain to surface as OverDeclared \
             (finish()'s own guard, never GrainLenMismatch's drain-time check — \
             this grain never reaches drain), got {other:?}"
        ),
    }
    assert_eq!(
        calls,
        Vec::new(),
        "nothing may reach the sink: the file's only grain is refused before it is \
         ever held, let alone emitted"
    );
}

/// **A cache hit's bytes must never be counted as bytes released
/// against the fetcher's in-flight budget.** A hit was never
/// CHARGED in the first place
/// (`fetch_streaming`'s own `charged` flag says so) — crediting its
/// length back on release would let the fetcher believe more room
/// exists than it actually does, admitting a LATER want before the
/// budget genuinely allows it.
///
/// **The fixture, in file order.** `bundler` — an ordinary fetched
/// grain, artificially slowed by ONE extra `YieldOnce` cycle so its
/// own completion lands strictly AFTER the eight large grains below
/// have already updated the in-flight tally. `hit` — a CACHE hit,
/// exactly [`GRAIN_UNPACKED_MAX`] bytes, resident in the cache from
/// the start, never seeded into the seam's bin at all (never
/// admitted, never charged). `gate` — slowed by TWO extra cycles
/// (later than `bundler`'s one), so nothing past it can drain while
/// `bundler` completes. Eight ordinary grains at exactly
/// [`GRAIN_UNPACKED_MAX`] behind `gate` (their decompressed sum is
/// exactly [`FETCH_INFLIGHT_BYTES`]), genuinely held once they
/// complete. Enough filler wants to fill the admission window to
/// exactly [`FETCH_WINDOW`]. One PROBE — real, ~1 MiB, excluded
/// from the first admission wave, waiting for room.
///
/// **The mechanism.** `bundler`'s own completion drains its own
/// position, then — since `hit` is already resident — drains `hit`
/// too, in the SAME callback invocation; the drain then reaches
/// `gate`'s position, finds it not yet resident (still mid-flight,
/// slower than `bundler`), and stops there — the eight large grains
/// behind `gate` are never touched by this release. A correct
/// release credits only `bundler`'s own bytes; crediting `hit`'s
/// (never-charged) bytes on top erroneously frees room in the
/// fetcher's tracked in-flight total while the eight large grains —
/// genuinely [`FETCH_INFLIGHT_BYTES`] worth, still held — remain
/// outstanding, which is exactly enough room for the probe to admit
/// before it should.
///
/// **Why this drives the future by hand.** The divergence is
/// visible for exactly ONE external poll of the resolve future —
/// the same poll in which `bundler` drains, admission re-checks the
/// budget, and (if the defect fires) the probe's `get_bin_range` is
/// first called, all synchronously, before the executor is ever
/// asked to poll again. A spawned task cannot see between those two
/// events either (and `tokio::spawn` is refused here: the spawn-ban row is
/// clippy's, but this module's wholesale test-module `#[expect]`
/// licenses the whole lint, so what actually holds the line inside
/// it is `scripts/fsguard-scan.py`'s `--banned-rows` check, which
/// refuses a non-filesystem row under a whole-module licence unless
/// the site carries its own `#[expect]`); a
/// second SHED extent lands on the SAME retry cycle as the first,
/// giving no separation at all. Driving the future by hand
/// (`Waker::noop()`, polling until `bundler`'s own id has been
/// sunk) reads the seam's call count for the probe at exactly that
/// boundary, deterministically, with no timer involved.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture (bundler, cache hit, gate, eight large grains, filler, \
              probe — five distinct roles, each load-bearing for the trace this \
              test's own doc walks through) built and driven by hand, then checked \
              at one exact poll boundary — splitting it loses the shared want list \
              and positions the trace depends on"
)]
fn a_cache_hit_never_erodes_the_budget() {
    const LARGE_GRAINS: usize = 8;
    const FILLER_WANTS: usize = 22;
    const PROBE_LEN: usize = 1024 * 1024;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0c_u8; DIGEST_LEN];

    let mut refs: Vec<GrainRef> = Vec::new();
    let mut entries: Vec<ShardEntry> = Vec::new();

    // Position 0: the bundler — slowed by one extra yield.
    let bundler_payload = b"bundler grain".to_vec();
    let (bundler_id, bundler_entry) = seed_grain(&seam, &mut codec, bin_digest, &bundler_payload);
    seam.slow_extent(bin_digest, bundler_entry.offset, 1);
    refs.push(GrainRef {
        id: bundler_id,
        unpacked_len: u32::try_from(bundler_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(bundler_entry);

    // Position 1: the cache hit — never seeded into the seam's bin
    // at all, so a stray fetch of it would surface as a hard
    // NotFound rather than silently reading real bytes.
    let mut hit_payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
    hit_payload[..8].copy_from_slice(&0xC5_u64.to_be_bytes());
    let hit_id = GrainId::of(&hit_payload);
    refs.push(GrainRef {
        id: hit_id,
        unpacked_len: GRAIN_UNPACKED_MAX,
    });
    entries.push(unfetchable_entry(hit_id));

    // Position 2: the gate — slowed by two extra yields, strictly
    // later than the bundler's one.
    let gate_payload = b"gate grain".to_vec();
    let (gate_id, gate_entry) = seed_grain(&seam, &mut codec, bin_digest, &gate_payload);
    seam.slow_extent(bin_digest, gate_entry.offset, 2);
    refs.push(GrainRef {
        id: gate_id,
        unpacked_len: u32::try_from(gate_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(gate_entry);

    // Positions 3..10: eight ordinary grains at exactly
    // GRAIN_UNPACKED_MAX — decompressed sum equals
    // FETCH_INFLIGHT_BYTES exactly.
    for i in 0..LARGE_GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
        entries.push(entry);
    }

    // Positions 10..32: filler wants, ordinary, trivial size.
    for i in 0..FILLER_WANTS {
        let payload = format!("filler {i}").into_bytes();
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        refs.push(GrainRef {
            id,
            unpacked_len: u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}")),
        });
        entries.push(entry);
    }

    // Position 32 (the 33rd real want): the probe — real,
    // incompressible-ish content, excluded from wave one.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "deliberate wraparound filler pattern, not a length computation"
    )]
    let probe_payload: Vec<u8> = (0..PROBE_LEN)
        .map(|b| (b as u32).wrapping_mul(2_654_435_761) as u8)
        .collect();
    let (probe_id, probe_entry) = seed_grain(&seam, &mut codec, bin_digest, &probe_payload);
    let probe_offset = probe_entry.offset;
    refs.push(GrainRef {
        id: probe_id,
        unpacked_len: u32::try_from(probe_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(probe_entry);

    assert_eq!(
        refs.len(),
        3 + LARGE_GRAINS + FILLER_WANTS + 1,
        "fixture shape must match this test's own trace of it"
    );
    let real_wants = 2 + LARGE_GRAINS + FILLER_WANTS;
    assert_eq!(
        real_wants, FETCH_WINDOW,
        "wave one must fill the window exactly, leaving the probe as the one \
         want excluded from it"
    );
    assert_eq!(
        u64::from(GRAIN_UNPACKED_MAX) * LARGE_GRAINS as u64,
        FETCH_INFLIGHT_BYTES,
        "the eight large grains' decompressed sum must equal the budget \
         exactly, or a probe admission proves nothing about erosion"
    );

    let declared_size: u64 = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
    let file_name = Name::new(b"budget.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    entries.push(root_entry);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir_id, index_id);

    let cache_dir =
        std::env::temp_dir().join("granary-resolve-test-a-cache-hit-never-erodes-the-budget");
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&cache_dir).unwrap_or_else(|e| panic!("{e}"));
    let origin = CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x22_u8; 32],
        root_key_id: None,
    };
    let mut cache =
        Cache::open(&cache_dir, 1024 * 1024 * 1024, &origin).unwrap_or_else(|e| panic!("{e}"));
    cache.insert(&hit_id, &hit_payload);

    let emitted: RefCell<Vec<GrainId>> = RefCell::new(Vec::new());
    let mut sink = |id: GrainId, bytes: &[u8]| -> Result<(), String> {
        emitted.borrow_mut().push(id);
        let _ = bytes;
        Ok(())
    };

    let path = vec![file_name];
    let fut = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        Some(&mut cache),
        ResolveTarget::Path(&path),
        &mut sink,
    );
    let mut fut = std::pin::pin!(fut);

    let mut cx = Context::from_waker(Waker::noop());
    let mut checkpoint: Option<usize> = None;
    let mut polls: u32 = 0;
    let outcome = loop {
        polls += 1;
        assert!(
            polls < 2000,
            "the resolve never settled within a sane poll budget — the fixture's \
             staged-completion assumptions must have drifted"
        );
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(r) => break r,
            Poll::Pending => {
                if checkpoint.is_none() && emitted.borrow().contains(&bundler_id) {
                    checkpoint = Some(seam.bin_call_count(bin_digest, probe_offset));
                }
            }
        }
    };
    outcome.unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        checkpoint,
        Some(0),
        "the probe's own wire call must not have happened by the same poll in which \
         the bundler (and, if wrongly bundled with it, the cache hit) drained — the \
         eight large grains behind `gate` are still genuinely held at that instant, \
         so only an over-release of the cache hit's never-charged bytes could open \
         room for it"
    );
    assert!(
        emitted.borrow().contains(&hit_id),
        "the cache hit's own content must still reach the sink despite being served \
         from the cache rather than the wire"
    );
}

/// **The charge lives exactly as long as the bytes do.** A file
/// whose refs repeat each of eight large grains TWICE (positions
/// 0..8 the first occurrence of each, a `gate` at position 8, then
/// positions 9..17 the SAME eight ids' second occurrence) must keep
/// ALL EIGHT grains' bytes charged for as long as `held` retains
/// them — through the first occurrence's own drain, which decrements
/// the remaining-occurrence count but does not yet reach zero, and
/// only released at the SECOND (last) occurrence's own drain, which
/// evicts them from `held` in the SAME step. `gate`, real and
/// artificially slowed, sits between the two occurrence batches so
/// the first batch fully drains — and, if a regression released
/// early, fully RELEASES — before anything past it can. The
/// checkpoint reads the seam's call count for a PROBE excluded from
/// the first admission wave the instant all eight first occurrences
/// have drained: correct code still owes the full eight-grain charge
/// at that point (the probe cannot fit), so its wire call must not
/// have happened yet.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture (eight duplicated large grains, a gate, filler, one probe) \
              built and driven by hand, then checked at one exact poll boundary — \
              splitting it loses the shared want list and positions the trace depends on"
)]
fn a_duplicate_heavy_file_stays_charged_while_held() {
    const DISTINCT_GRAINS: usize = 8;
    const FILLER_WANTS: usize = 23;
    const PROBE_LEN: usize = 1024 * 1024;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0f_u8; DIGEST_LEN];

    let mut refs: Vec<GrainRef> = Vec::new();
    let mut entries: Vec<ShardEntry> = Vec::new();

    // Positions 0..8: the FIRST occurrence of eight distinct grains
    // at exactly GRAIN_UNPACKED_MAX — decompressed sum equals
    // FETCH_INFLIGHT_BYTES exactly.
    let mut duplicate_ids = Vec::with_capacity(DISTINCT_GRAINS);
    for i in 0..DISTINCT_GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        duplicate_ids.push(id);
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
        entries.push(entry);
    }

    // Position 8: the gate — slowed, so the first batch above fully
    // drains (and, under a release-at-first-occurrence regression,
    // fully releases) before anything past it becomes reachable.
    let gate_payload = b"gate grain".to_vec();
    let (gate_id, gate_entry) = seed_grain(&seam, &mut codec, bin_digest, &gate_payload);
    seam.slow_extent(bin_digest, gate_entry.offset, 2);
    refs.push(GrainRef {
        id: gate_id,
        unpacked_len: u32::try_from(gate_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(gate_entry);

    // Positions 9..17: the SAME eight ids' second occurrence, same
    // order — `fetch_streaming`'s own admission dedups these to
    // zero further wire calls; the bytes must already be resident.
    for &id in &duplicate_ids {
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
    }

    // Positions 17..40: filler wants, ordinary, trivial size — fill
    // wave one to exactly FETCH_WINDOW (8 distinct + 1 gate + 23
    // filler = 32).
    for i in 0..FILLER_WANTS {
        let payload = format!("filler {i}").into_bytes();
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        refs.push(GrainRef {
            id,
            unpacked_len: u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}")),
        });
        entries.push(entry);
    }

    // Position 40 (the 33rd real want): the probe — real,
    // incompressible-ish content, excluded from wave one.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "deliberate wraparound filler pattern, not a length computation"
    )]
    let probe_payload: Vec<u8> = (0..PROBE_LEN)
        .map(|b| (b as u32).wrapping_mul(2_654_435_761) as u8)
        .collect();
    let (probe_id, probe_entry) = seed_grain(&seam, &mut codec, bin_digest, &probe_payload);
    let probe_offset = probe_entry.offset;
    refs.push(GrainRef {
        id: probe_id,
        unpacked_len: u32::try_from(probe_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(probe_entry);

    assert_eq!(
        refs.len(),
        2 * DISTINCT_GRAINS + 1 + FILLER_WANTS + 1,
        "fixture shape must match this test's own trace of it"
    );
    let real_wants = DISTINCT_GRAINS + 1 + FILLER_WANTS;
    assert_eq!(
        real_wants, FETCH_WINDOW,
        "wave one must fill the window exactly (the duplicate ids dedup to one \
         admission each), leaving the probe as the one want excluded from it"
    );
    assert_eq!(
        u64::from(GRAIN_UNPACKED_MAX) * DISTINCT_GRAINS as u64,
        FETCH_INFLIGHT_BYTES,
        "the eight distinct grains' decompressed sum must equal the budget \
         exactly, or an admitted probe proves nothing about early release"
    );

    let declared_size: u64 = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
    let file_name = Name::new(b"duplicate_heavy.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    entries.push(root_entry);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir_id, index_id);

    let emitted: RefCell<Vec<GrainId>> = RefCell::new(Vec::new());
    let mut sink = |id: GrainId, bytes: &[u8]| -> Result<(), String> {
        emitted.borrow_mut().push(id);
        let _ = bytes;
        Ok(())
    };

    let path = vec![file_name];
    let fut = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    );
    let mut fut = std::pin::pin!(fut);

    let mut cx = Context::from_waker(Waker::noop());
    let mut checkpoint: Option<usize> = None;
    let mut polls: u32 = 0;
    let outcome = loop {
        polls += 1;
        assert!(
            polls < 2000,
            "the resolve never settled within a sane poll budget"
        );
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(r) => break r,
            Poll::Pending => {
                if checkpoint.is_none() && emitted.borrow().len() == DISTINCT_GRAINS {
                    checkpoint = Some(seam.bin_call_count(bin_digest, probe_offset));
                }
            }
        }
    };
    outcome.unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        checkpoint,
        Some(0),
        "the probe's own wire call must not have happened by the poll in which all \
         eight first occurrences drained — none of the eight has reached its SECOND \
         (last) occurrence yet, so `held` still retains, and the budget still owes, \
         the full eight-grain charge; only an early release at the first occurrence \
         could open room for the probe here"
    );
    for id in duplicate_ids {
        assert_eq!(
            emitted.borrow().iter().filter(|&&e| e == id).count(),
            2,
            "each duplicated id must reach the sink exactly twice, once per position"
        );
    }
}

/// **Release-at-eviction composes with cache admission into a
/// liveness deadlock without the fetcher's own escape hatch.** Eight
/// distinct grains at exactly `GRAIN_UNPACKED_MAX` sit warm in the
/// cache and are referenced TWICE — once at the file's start, once
/// again at its end — with one COLD grain (`gap`, never cached, a
/// genuine wire want) named exactly once, between the two
/// occurrence batches. The eight hits admit and charge the full
/// budget (eight × 8 MiB = `FETCH_INFLIGHT_BYTES` exactly) without
/// ever occupying an admission slot (a cache hit never does); they
/// drain at their first occurrence but do not EVICT — and therefore
/// do not release — until their second, so `gap`'s own admission
/// charge, however small, cannot fit. With nothing ever admitted as
/// a real want, `in_flight` is empty, `poll_fn`'s own admission loop
/// has nothing left to poll, and without the escape hatch this
/// wedges forever: `queue` non-empty, `in_flight` empty, no waker
/// anywhere left to ever repoll the future. Under the fixed fetcher
/// this resolves cleanly — `gap` is the escape hatch's one exempted
/// want, admits unconditionally, and its own completion cascades the
/// drain through both occurrence batches.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture (eight duplicated cached grains, a cold gap, both \
              occurrence batches) built and driven in one call — splitting it loses \
              the shared want list and positions the trace depends on"
)]
async fn duplicates_spanning_a_cold_gap_never_wedge_the_gate() {
    const DISTINCT_GRAINS: usize = 8;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x12_u8; DIGEST_LEN];

    let cache_dir = std::env::temp_dir()
        .join("granary-resolve-test-duplicates-spanning-a-cold-gap-never-wedge-the-gate");
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&cache_dir).unwrap_or_else(|e| panic!("{e}"));
    let origin = CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x23_u8; 32],
        root_key_id: None,
    };
    let mut cache =
        Cache::open(&cache_dir, 1024 * 1024 * 1024, &origin).unwrap_or_else(|e| panic!("{e}"));

    let mut refs: Vec<GrainRef> = Vec::new();
    let mut entries: Vec<ShardEntry> = Vec::new();
    let mut cached_ids = Vec::with_capacity(DISTINCT_GRAINS);
    let mut cached_payloads = Vec::with_capacity(DISTINCT_GRAINS);

    // Positions 0..8: the FIRST occurrence of eight distinct,
    // cache-warm grains — decompressed sum equals FETCH_INFLIGHT_BYTES
    // exactly.
    for i in 0..DISTINCT_GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let id = GrainId::of(&payload);
        cache.insert(&id, &payload);
        cached_ids.push(id);
        cached_payloads.push(payload);
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
        entries.push(unfetchable_entry(id));
    }

    // Position 8: the cold gap — real, never cached, a genuine wire
    // want the fixed fetcher must admit unconditionally once nothing
    // else is in flight.
    let gap_payload = b"cold gap grain, never cached".to_vec();
    let (gap_id, gap_entry) = seed_grain(&seam, &mut codec, bin_digest, &gap_payload);
    let gap_offset = gap_entry.offset;
    refs.push(GrainRef {
        id: gap_id,
        unpacked_len: u32::try_from(gap_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(gap_entry);

    // Positions 9..17: the SAME eight ids' second occurrence.
    for &id in &cached_ids {
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
    }

    assert_eq!(
        refs.len(),
        2 * DISTINCT_GRAINS + 1,
        "fixture shape must match this test's own trace of it"
    );
    assert_eq!(
        u64::from(GRAIN_UNPACKED_MAX) * DISTINCT_GRAINS as u64,
        FETCH_INFLIGHT_BYTES,
        "the eight cached grains' decompressed sum must equal the budget exactly, \
         or the gap's own admission charge would fit trivially and this fixture \
         would prove nothing about the deadlock"
    );

    let declared_size: u64 = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
    let file_name = Name::new(b"cached_duplicates.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    entries.push(root_entry);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir_id, index_id);

    let mut collected: Vec<u8> = Vec::new();
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.extend_from_slice(bytes);
        Ok(())
    };
    let path = vec![file_name];
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        Some(&mut cache),
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));

    let mut expected: Vec<u8> = Vec::new();
    for payload in &cached_payloads {
        expected.extend_from_slice(payload);
    }
    expected.extend_from_slice(&gap_payload);
    for payload in &cached_payloads {
        expected.extend_from_slice(payload);
    }
    assert_eq!(
        collected, expected,
        "every position's bytes must reach the sink, in file order, including both \
         occurrences of each duplicated grain"
    );
    assert_eq!(
        seam.bin_call_count(bin_digest, gap_offset),
        1,
        "the gap must be fetched exactly once over the wire — the escape hatch \
         admits it, it is never cached, and it is never referenced twice"
    );
    assert_eq!(
        seam.bin_call_count(bin_digest, 200_000_000),
        0,
        "none of the eight duplicated grains may ever touch the wire — every one \
         of their sixteen positions must be served entirely from the cache"
    );
}

/// **The same liveness deadlock, with every grain cold — no cache
/// involved at all.** Eight distinct grains at exactly
/// `GRAIN_UNPACKED_MAX`, referenced twice each, are ALL real wire
/// wants this time; twenty-four filler wants and a cold `gap`
/// (referenced once, between the two occurrence batches) fill the
/// admission window to exactly `FETCH_WINDOW`, excluding `gap` from
/// the first admission wave. The eight large grains admit cheaply
/// (their COMPRESSED charge is tiny), complete, and CONVERT to their
/// full decompressed size once drained to their first occurrence —
/// but do not evict, so their charge stays reserved. Once every
/// wave-one want's own wire call has finished (fillers released,
/// the eight large grains held), `in_flight` empties with `gap`
/// still queued and now unable to fit — the identical wedge
/// [`duplicates_spanning_a_cold_gap_never_wedge_the_gate`] reaches
/// via the cache, reached here purely through wire completions.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture (eight duplicated large grains, filler, a gap, both \
              occurrence batches) built and driven in one call — splitting it loses \
              the shared want list and positions the trace depends on"
)]
async fn a_wire_batch_with_late_duplicates_never_wedges() {
    const DISTINCT_GRAINS: usize = 8;
    const FILLER_WANTS: usize = 24;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x13_u8; DIGEST_LEN];

    let mut refs: Vec<GrainRef> = Vec::new();
    let mut entries: Vec<ShardEntry> = Vec::new();

    // Positions 0..8: the FIRST occurrence of eight distinct, COLD
    // grains at exactly GRAIN_UNPACKED_MAX — decompressed sum equals
    // FETCH_INFLIGHT_BYTES exactly.
    let mut wire_ids = Vec::with_capacity(DISTINCT_GRAINS);
    let mut wire_payloads = Vec::with_capacity(DISTINCT_GRAINS);
    let mut wire_offsets = Vec::with_capacity(DISTINCT_GRAINS);
    for i in 0..DISTINCT_GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        wire_ids.push(id);
        wire_payloads.push(payload);
        wire_offsets.push(entry.offset);
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
        entries.push(entry);
    }

    // Positions 8..32: filler wants, ordinary, trivial size — fill
    // the rest of wave one so `gap` (below) is excluded from it.
    for i in 0..FILLER_WANTS {
        let payload = format!("filler {i}").into_bytes();
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        refs.push(GrainRef {
            id,
            unpacked_len: u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}")),
        });
        entries.push(entry);
    }

    // Position 32 (the 33rd real want): the cold gap — excluded
    // from wave one (8 distinct + 24 filler = 32 = FETCH_WINDOW),
    // and by the time a slot frees for it the eight large grains'
    // held charge has already filled the byte budget.
    let gap_payload = b"cold gap grain, wire variant".to_vec();
    let (gap_id, gap_entry) = seed_grain(&seam, &mut codec, bin_digest, &gap_payload);
    let gap_offset = gap_entry.offset;
    refs.push(GrainRef {
        id: gap_id,
        unpacked_len: u32::try_from(gap_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(gap_entry);

    // Positions 33..41: the SAME eight ids' second occurrence.
    for &id in &wire_ids {
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
    }

    assert_eq!(
        refs.len(),
        2 * DISTINCT_GRAINS + FILLER_WANTS + 1,
        "fixture shape must match this test's own trace of it"
    );
    let wave_one_wants = DISTINCT_GRAINS + FILLER_WANTS;
    assert_eq!(
        wave_one_wants, FETCH_WINDOW,
        "wave one (the eight distinct grains plus the fillers, the duplicate ids \
         deduping to one admission each) must fill the window exactly, leaving the \
         gap as the one want excluded from it"
    );
    assert_eq!(
        u64::from(GRAIN_UNPACKED_MAX) * DISTINCT_GRAINS as u64,
        FETCH_INFLIGHT_BYTES,
        "the eight large grains' decompressed sum must equal the budget exactly, \
         or the gap's own admission charge would fit trivially once a slot frees \
         and this fixture would prove nothing about the deadlock"
    );

    let declared_size: u64 = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
    let file_name = Name::new(b"wire_duplicates.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    entries.push(root_entry);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir_id, index_id);

    let mut collected: Vec<u8> = Vec::new();
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.extend_from_slice(bytes);
        Ok(())
    };
    let path = vec![file_name];
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));

    let mut expected: Vec<u8> = Vec::new();
    for payload in &wire_payloads {
        expected.extend_from_slice(payload);
    }
    for i in 0..FILLER_WANTS {
        expected.extend_from_slice(format!("filler {i}").as_bytes());
    }
    expected.extend_from_slice(&gap_payload);
    for payload in &wire_payloads {
        expected.extend_from_slice(payload);
    }
    assert_eq!(
        collected, expected,
        "every position's bytes must reach the sink, in file order, including both \
         occurrences of each duplicated grain"
    );
    for (id, offset) in wire_ids.iter().zip(wire_offsets.iter()) {
        assert_eq!(
            seam.bin_call_count(bin_digest, *offset),
            1,
            "{id}: single-flight must serve BOTH positions from the one wire \
             fetch — never re-fetched for its second occurrence"
        );
    }
    assert_eq!(
        seam.bin_call_count(bin_digest, gap_offset),
        1,
        "the gap must be fetched exactly once over the wire"
    );
}

/// **The static pre-bound refuses what the runtime gates alone
/// cannot.** Nine distinct grains at exactly `GRAIN_UNPACKED_MAX`,
/// each duplicated across a cold gap — the identical shape
/// [`duplicates_spanning_a_cold_gap_never_wedge_the_gate`] streams
/// successfully at eight grains (peak duplicate-holdback exactly
/// `FETCH_INFLIGHT_BYTES`), but at nine the peak is
/// `9 * GRAIN_UNPACKED_MAX = 72 MiB`, past the 64 MiB budget: no
/// admission order could ever stream this file within budget, since
/// the retention is forced by the POSITIONS the file itself names,
/// not by which want happens to complete first. `duplicate_span_peak`
/// catches this from `refs` alone, before `emit_file` ever looks at
/// `entries`/`bins`, builds a single `Want`, or touches the fetcher
/// — so the refusal costs zero wire calls and zero cache reads. This
/// is exactly the shape this pre-bound exists to close: with only
/// the liveness escape hatch and no static bound, a RUN of cache
/// hits (none of which ever occupies an admission slot) can each
/// individually trip the hatch and admit past the budget one at a
/// time, without limit as the duplicate count grows.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture (nine duplicated cached grains, a cold gap, both \
              occurrence batches) built and driven in one call — splitting it loses \
              the shared want list and positions the trace depends on"
)]
async fn a_duplicate_span_past_the_budget_is_refused_upfront() {
    const DISTINCT_GRAINS: usize = 9;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x15_u8; DIGEST_LEN];

    let cache_dir = std::env::temp_dir()
        .join("granary-resolve-test-a-duplicate-span-past-the-budget-is-refused-upfront");
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&cache_dir).unwrap_or_else(|e| panic!("{e}"));
    let origin = CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x24_u8; 32],
        root_key_id: None,
    };
    let mut cache =
        Cache::open(&cache_dir, 1024 * 1024 * 1024, &origin).unwrap_or_else(|e| panic!("{e}"));

    let mut refs: Vec<GrainRef> = Vec::new();
    let mut entries: Vec<ShardEntry> = Vec::new();
    let mut cached_ids = Vec::with_capacity(DISTINCT_GRAINS);

    // Positions 0..9: the FIRST occurrence of nine distinct,
    // cache-warm grains — decompressed sum is 72 MiB, past the
    // 64 MiB budget by exactly one grain's worth.
    for i in 0..DISTINCT_GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let id = GrainId::of(&payload);
        cache.insert(&id, &payload);
        cached_ids.push(id);
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
        entries.push(unfetchable_entry(id));
    }

    // Position 9: the cold gap — real, never cached; the static
    // check must refuse before this is ever fetched.
    let gap_payload = b"cold gap grain, never reached".to_vec();
    let (gap_id, gap_entry) = seed_grain(&seam, &mut codec, bin_digest, &gap_payload);
    let gap_offset = gap_entry.offset;
    refs.push(GrainRef {
        id: gap_id,
        unpacked_len: u32::try_from(gap_payload.len()).unwrap_or_else(|e| panic!("{e}")),
    });
    entries.push(gap_entry);

    // Positions 10..19: the SAME nine ids' second occurrence.
    for &id in &cached_ids {
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
    }

    assert_eq!(
        refs.len(),
        2 * DISTINCT_GRAINS + 1,
        "fixture shape must match this test's own trace of it"
    );
    let expected_peak = u64::from(GRAIN_UNPACKED_MAX) * DISTINCT_GRAINS as u64;
    assert!(
        expected_peak > FETCH_INFLIGHT_BYTES,
        "the nine cached grains' decompressed sum must exceed the budget, or this \
         fixture proves nothing about the refusal"
    );

    let declared_size: u64 = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
    let file_name =
        Name::new(b"over_budget_duplicates.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    entries.push(root_entry);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir_id, index_id);

    let mut collected: Vec<u8> = Vec::new();
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.extend_from_slice(bytes);
        Ok(())
    };
    let path = vec![file_name];
    let outcome = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        Some(&mut cache),
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await;

    match outcome {
        Err(ResolveError::DuplicateSpanExceedsBudget { need, budget }) => {
            assert_eq!(
                need, expected_peak,
                "the reported peak must be the exact duplicate-span sum, not an \
                 approximation"
            );
            assert_eq!(budget, FETCH_INFLIGHT_BYTES);
        }
        other => panic!(
            "expected DuplicateSpanExceedsBudget {{ need: {expected_peak}, budget: \
             {FETCH_INFLIGHT_BYTES} }}, got {other:?}"
        ),
    }

    // The refusal is static: nothing was ever sunk, so nothing was
    // ever fetched, cached or not (content only ever reaches the
    // sink via `fetch_streaming`'s own admission loop, which this
    // file's `wants` vector — never built — could not have driven).
    assert!(
        collected.is_empty(),
        "a statically refused file must never reach the sink at all"
    );
    assert_eq!(
        seam.bin_call_count(bin_digest, gap_offset),
        0,
        "the gap must never be fetched — the static check refuses before `emit_file` \
         builds a single `Want`"
    );
    assert_eq!(
        seam.bin_call_count(bin_digest, 200_000_000),
        0,
        "none of the nine duplicated grains' shared unfetchable placeholder offset \
         may ever be touched — zero wire calls for this file's own content"
    );
}

/// **The boundary: peak duplicate-holdback exactly equal to the
/// budget still streams.** Eight distinct grains at exactly
/// `GRAIN_UNPACKED_MAX`, each referenced twice with NO gap between
/// the two occurrence batches (this test is about the static
/// pre-bound's own arithmetic, not the liveness hatch
/// `duplicates_spanning_a_cold_gap_never_wedge_the_gate` already
/// covers) — `duplicate_span_peak` must compute EXACTLY
/// `FETCH_INFLIGHT_BYTES`, and `emit_file` must admit it: the check
/// is `>`, never `>=`.
#[tokio::test]
async fn a_boundary_duplicate_span_still_streams() {
    const DISTINCT_GRAINS: usize = 8;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x16_u8; DIGEST_LEN];

    let mut refs: Vec<GrainRef> = Vec::new();
    let mut entries: Vec<ShardEntry> = Vec::new();
    let mut payloads = Vec::with_capacity(DISTINCT_GRAINS);

    // Positions 0..8: the first occurrence of eight distinct grains
    // at exactly GRAIN_UNPACKED_MAX.
    for i in 0..DISTINCT_GRAINS {
        let mut payload = vec![0_u8; GRAIN_UNPACKED_MAX as usize];
        payload[..8].copy_from_slice(&u64::try_from(i).unwrap_or(0).to_be_bytes());
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        payloads.push(payload);
        refs.push(GrainRef {
            id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
        entries.push(entry);
    }
    // Positions 8..16: the SAME eight ids' second occurrence,
    // immediately after — no gap, nothing between the two batches.
    for e in entries.clone() {
        refs.push(GrainRef {
            id: e.id,
            unpacked_len: GRAIN_UNPACKED_MAX,
        });
    }

    // A direct check of the sweep's own arithmetic over the inline
    // facts that production derives from this exact ref sequence.
    let declaring_placeholder = GrainId::of(b"declaring node placeholder");
    let peak_facts = grain_span_facts(
        &BTreeMap::new(),
        &declaring_placeholder,
        &FileGrains::Inline(refs.clone()),
    )
    .unwrap_or_else(|e| panic!("derive boundary span facts: {e}"));
    assert_eq!(
        duplicate_span_peak(&peak_facts),
        FETCH_INFLIGHT_BYTES,
        "eight distinct grains at exactly GRAIN_UNPACKED_MAX, referenced twice each \
         with fully overlapping spans, must sweep to exactly the budget — the \
         boundary this test is named for"
    );

    let declared_size: u64 = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
    let file_name =
        Name::new(b"boundary_duplicates.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: declared_size,
            grains: FileGrains::Inline(refs),
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (
        dir_bytes.root,
        dir_bytes
            .nodes
            .iter()
            .find(|(id, _)| *id == dir_bytes.root)
            .unwrap_or_else(|| panic!("root leaf must be among the built nodes"))
            .1
            .clone(),
    );
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    entries.push(root_entry);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir_id, index_id);

    let mut collected: Vec<u8> = Vec::new();
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.extend_from_slice(bytes);
        Ok(())
    };
    let path = vec![file_name];
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("the exact-boundary span must still stream: {e}"));

    let mut expected: Vec<u8> = Vec::new();
    for payload in &payloads {
        expected.extend_from_slice(payload);
    }
    for payload in &payloads {
        expected.extend_from_slice(payload);
    }
    assert_eq!(
        collected, expected,
        "both occurrences of every duplicated grain must reach the sink, in order"
    );
}

/// **The whole-tree emission walk must accept everything
/// `validate_dir_tree` accepts.** Directory NESTING has no depth
/// bound in the format (`tree.rs`'s rule 4: the budget is per
/// directory, resetting at each one's own B-tree root); a chain of
/// `DEPTH_MAX + 1` single-entry directories, each naming the next
/// as its one child, is exactly such a tree — legal nesting depth,
/// trivial per-directory B-tree shape (one entry, no fill needed).
/// A walk that charged nesting against the SAME counter as
/// per-directory fill would wrongly refuse it at the last
/// directory (accumulated depth `DEPTH_MAX + 1`, over the bound);
/// the correct walk, resetting at each directory boundary, never
/// approaches the bound at all.
#[tokio::test]
async fn deep_directory_nesting_emits_like_it_validates() {
    let nesting = (DEPTH_MAX + 1) as usize;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x11_u8; DIGEST_LEN];

    let file_content = b"nested past DEPTH_MAX levels deep, still one directory at a time".to_vec();
    let (file_id, file_shard_entry) = seed_grain(&seam, &mut codec, bin_digest, &file_content);
    let mut entries: Vec<ShardEntry> = vec![file_shard_entry];

    let leaf_name = Name::new(b"leaf.txt".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_dir_entry = DirEntry {
        name: leaf_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: u64::try_from(file_content.len()).unwrap_or_else(|e| panic!("{e}")),
            grains: FileGrains::Inline(vec![GrainRef {
                id: file_id,
                unpacked_len: u32::try_from(file_content.len()).unwrap_or_else(|e| panic!("{e}")),
            }]),
        },
    };
    let mut dir_bytes = manifest::build_dir(&[file_dir_entry]).unwrap_or_else(|e| panic!("{e}"));
    let mut child_root = dir_bytes.root;
    for (id, bytes) in &dir_bytes.nodes {
        let (_, e) = seed_grain(&seam, &mut codec, bin_digest, bytes);
        assert_eq!(e.id, *id);
        entries.push(e);
    }

    // Wrap the innermost (file-containing) directory in `nesting - 1`
    // MORE single-entry directories, each naming the previous level
    // as its one child — `nesting` directories deep in total.
    for level in 0..nesting - 1 {
        let name = Name::new(format!("d{level}").into_bytes()).unwrap_or_else(|e| panic!("{e}"));
        let wrapper = DirEntry {
            name,
            kind: ManifestEntryKind::Dir { child: child_root },
        };
        dir_bytes = manifest::build_dir(&[wrapper]).unwrap_or_else(|e| panic!("{e}"));
        child_root = dir_bytes.root;
        for (id, bytes) in &dir_bytes.nodes {
            let (_, e) = seed_grain(&seam, &mut codec, bin_digest, bytes);
            assert_eq!(e.id, *id);
            entries.push(e);
        }
    }
    let manifest_root = child_root;

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, manifest_root, index_id);

    let mut whole_tree_content = Vec::new();
    let mut whole_sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        whole_tree_content.extend_from_slice(bytes);
        Ok(())
    };
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut whole_sink,
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "a {nesting}-deep chain of single-entry directories, legal nesting \
             under the format's own rule 4, must emit like it validates: {e}"
        )
    });

    assert!(
        whole_tree_content
            .windows(file_content.len())
            .any(|w| w == file_content.as_slice()),
        "the file at the bottom of the chain must still have been reached and emitted"
    );

    // `lookup_in_dir` is called fresh once per path component
    // already, so path resolution has no accumulated-depth counter
    // to get wrong — a parallel PATH read over the SAME fixture is
    // the cross-check that this depth fix is scoped to the
    // whole-tree walker specifically, not a coincidence of this one
    // fixture.
    // Naming order is ROOT to LEAF; the wrap loop built OUTWARD from
    // the file, so the OUTERMOST (manifest-root) wrapper is the
    // HIGHEST `level` — the path walks the levels DOWN, not up.
    let mut path: Vec<Name> = (0..nesting - 1)
        .rev()
        .map(|level| Name::new(format!("d{level}").into_bytes()).unwrap_or_else(|e| panic!("{e}")))
        .collect();
    path.push(leaf_name);
    let mut path_content = Vec::new();
    let mut path_sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        path_content.extend_from_slice(bytes);
        Ok(())
    };
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut path_sink,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(path_content, file_content);
}

/// **The whole-tree walk must not recurse on directory NESTING at
/// all — a fresh depth budget per directory removes the BOUND
/// (`deep_directory_nesting_emits_like_it_validates`, above), and
/// removing the bound while nesting still recursed on the native
/// call stack only trades a wrong refusal for a crash.**
/// `validate_dir_tree` iterates nesting on a heap-allocated worklist
/// (`tree.rs`); a manifest of ~2000 single-entry nested directories
/// is exactly what that worklist accepts (nesting is uncapped by
/// contract) and what `tree.rs`'s own doc measures a NATIVE
/// recursive walker crashing on well before this depth (roughly 500
/// frames in a debug build). This is a panic reachable from
/// untrusted input — a hostile or merely very deep manifest, not a
/// contrived one — which this crate's own rules forbid.
#[tokio::test]
async fn thousands_deep_nesting_emits_without_recursion() {
    const NESTING: usize = 2000;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x14_u8; DIGEST_LEN];

    let file_content = b"thousands of directories deep, still one at a time".to_vec();
    let (file_id, file_shard_entry) = seed_grain(&seam, &mut codec, bin_digest, &file_content);
    let mut entries: Vec<ShardEntry> = vec![file_shard_entry];

    let leaf_name = Name::new(b"leaf.txt".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_dir_entry = DirEntry {
        name: leaf_name,
        kind: ManifestEntryKind::File {
            exec: false,
            size: u64::try_from(file_content.len()).unwrap_or_else(|e| panic!("{e}")),
            grains: FileGrains::Inline(vec![GrainRef {
                id: file_id,
                unpacked_len: u32::try_from(file_content.len()).unwrap_or_else(|e| panic!("{e}")),
            }]),
        },
    };
    let mut dir_bytes = manifest::build_dir(&[file_dir_entry]).unwrap_or_else(|e| panic!("{e}"));
    let mut child_root = dir_bytes.root;
    for (id, bytes) in &dir_bytes.nodes {
        let (_, e) = seed_grain(&seam, &mut codec, bin_digest, bytes);
        assert_eq!(e.id, *id);
        entries.push(e);
    }

    // Wrap the innermost (file-containing) directory in `NESTING - 1`
    // MORE single-entry directories — `NESTING` directories deep in
    // total, thousands past DEPTH_MAX, legal under rule 4.
    for level in 0..NESTING - 1 {
        let name = Name::new(format!("d{level}").into_bytes()).unwrap_or_else(|e| panic!("{e}"));
        let wrapper = DirEntry {
            name,
            kind: ManifestEntryKind::Dir { child: child_root },
        };
        dir_bytes = manifest::build_dir(&[wrapper]).unwrap_or_else(|e| panic!("{e}"));
        child_root = dir_bytes.root;
        for (id, bytes) in &dir_bytes.nodes {
            let (_, e) = seed_grain(&seam, &mut codec, bin_digest, bytes);
            assert_eq!(e.id, *id);
            entries.push(e);
        }
    }
    let manifest_root = child_root;

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, manifest_root, index_id);

    let mut whole_tree_content = Vec::new();
    let mut whole_sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        whole_tree_content.extend_from_slice(bytes);
        Ok(())
    };
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut whole_sink,
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "a {NESTING}-deep chain of single-entry directories, legal nesting \
             under the format's own rule 4, must emit like it validates: {e}"
        )
    });

    assert!(
        whole_tree_content
            .windows(file_content.len())
            .any(|w| w == file_content.as_slice()),
        "the file at the bottom of the {NESTING}-deep chain must still have been \
         reached and emitted"
    );
}

// ------------------------------------------------------ path lookup

/// Two leaf names where one is a PREFIX of the other. A `Path`
/// target for the short name gets exactly that file's bytes — never
/// the longer file that merely starts with the same characters
/// (`lookup_in_dir`'s leaf scan matches `e.name == *name`, never a
/// prefix comparison). A target for a name strictly BETWEEN the two
/// lexically — itself naming nothing — is `NoSuchTarget` (kills a
/// mutant that matches on `starts_with` in either direction).
#[tokio::test]
async fn a_name_matches_exactly_and_never_by_prefix() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0d_u8; DIGEST_LEN];

    let short_payload = b"the short file's own bytes".to_vec();
    let (short_id, short_entry) = seed_grain(&seam, &mut codec, bin_digest, &short_payload);
    let long_payload = b"the longer file that merely starts the same way".to_vec();
    let (long_id, long_entry) = seed_grain(&seam, &mut codec, bin_digest, &long_payload);

    let short_name = Name::new(b"abc".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let long_name = Name::new(b"abcdef".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let entries = vec![
        DirEntry {
            name: short_name.clone(),
            kind: ManifestEntryKind::File {
                exec: false,
                size: u64::try_from(short_payload.len()).unwrap_or_else(|e| panic!("{e}")),
                grains: FileGrains::Inline(vec![GrainRef {
                    id: short_id,
                    unpacked_len: u32::try_from(short_payload.len())
                        .unwrap_or_else(|e| panic!("{e}")),
                }]),
            },
        },
        DirEntry {
            name: long_name,
            kind: ManifestEntryKind::File {
                exec: false,
                size: u64::try_from(long_payload.len()).unwrap_or_else(|e| panic!("{e}")),
                grains: FileGrains::Inline(vec![GrainRef {
                    id: long_id,
                    unpacked_len: u32::try_from(long_payload.len())
                        .unwrap_or_else(|e| panic!("{e}")),
                }]),
            },
        },
    ];
    let dir_bytes = manifest::build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        dir_bytes.nodes.len(),
        1,
        "two entries is one leaf, no interior"
    );
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);

    let index_id = seed_binmap(
        &seam,
        0,
        bin_digest,
        vec![vec![short_entry, long_entry, root_entry]],
    );
    seed_head(&seam, root_dir_id, index_id);

    let mut collected: Vec<u8> = Vec::new();
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.extend_from_slice(bytes);
        Ok(())
    };
    let path = vec![short_name];
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        collected, short_payload,
        "the SHORT name must get the SHORT file's bytes, never the longer \
         file that merely starts with the same prefix"
    );

    let mid_name = Name::new(b"abcd".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let mid_path = vec![mid_name];
    let err = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&mid_path),
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err(
        "a name that is only a prefix of a real file's name, and is itself no \
         file's own name, must not resolve",
    );
    assert!(
        matches!(err, ResolveError::NoSuchTarget { .. }),
        "expected NoSuchTarget, got {err:?}"
    );
}

/// A `DirInterior` tree (over 256 entries, forcing `build_dir` to
/// split into leaves under an interior node) where `Path` targets
/// into BOTH the first and the last leaf resolve to their own
/// bytes. `lookup_in_dir`'s interior routing scans children in
/// REVERSE, taking the LAST child whose `first_key <= name` —
/// dropping the `.rev()` would instead take the FIRST such child,
/// which for a `<=` predicate over ascending keys is almost always
/// children[0], routing every name past the first split into the
/// WRONG leaf. Targeting the first AND the last entry catches that:
/// the last entry's target would still (wrongly) resolve under
/// children[0] only by coincidence, never under the real fix.
#[tokio::test]
async fn an_interior_directory_routes_to_the_right_leaf() {
    const ENTRIES: usize = 300; // > DIR_LEAF_MAX_ENTRIES (256)

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0e_u8; DIGEST_LEN];

    let mut dir_entries: Vec<DirEntry> = Vec::with_capacity(ENTRIES);
    let mut payload_for: BTreeMap<Name, Vec<u8>> = BTreeMap::new();
    let mut shard_entries: Vec<ShardEntry> = Vec::with_capacity(ENTRIES + 1);
    for i in 0..ENTRIES {
        let name = Name::new(format!("{i:04}").into_bytes()).unwrap_or_else(|e| panic!("{e}"));
        let payload = format!("payload for entry {i}").into_bytes();
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        dir_entries.push(DirEntry {
            name: name.clone(),
            kind: ManifestEntryKind::File {
                exec: false,
                size: u64::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}")),
                grains: FileGrains::Inline(vec![GrainRef {
                    id,
                    unpacked_len: u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}")),
                }]),
            },
        });
        payload_for.insert(name, payload);
        shard_entries.push(entry);
    }
    dir_entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

    let dir_bytes = manifest::build_dir(&dir_entries).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        dir_bytes.nodes.len() >= 3,
        "300 entries must split into at least two leaves plus one interior, got {}",
        dir_bytes.nodes.len()
    );
    for (id, bytes) in &dir_bytes.nodes {
        let (_, entry) = seed_grain(&seam, &mut codec, bin_digest, bytes);
        assert_eq!(
            *id, entry.id,
            "seeded structure node id must match its content address"
        );
        shard_entries.push(entry);
    }

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![shard_entries]);
    seed_head(&seam, dir_bytes.root, index_id);

    // Index 0 and index (ENTRIES - 1), by SORTED order, land in the
    // FIRST and LAST leaf respectively — true for any split of a
    // strictly-sorted flat entry set into contiguous leaves,
    // regardless of exactly where the split point falls.
    for name in [
        dir_entries[0].name.clone(),
        dir_entries[ENTRIES - 1].name.clone(),
    ] {
        let expected = payload_for
            .get(&name)
            .unwrap_or_else(|| panic!("fixture must know its own payload"))
            .clone();
        let mut collected: Vec<u8> = Vec::new();
        let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
            collected.extend_from_slice(bytes);
            Ok(())
        };
        let path = vec![name];
        resolve_at(
            &seam,
            TEST_VOLUME,
            1,
            None,
            ResolveTarget::Path(&path),
            &mut sink,
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            collected, expected,
            "a target routed through the interior node must reach its own leaf's bytes"
        );
    }
}

/// A `FileGrains::Spill` file (over `FILE_INLINE_MAX_REFS` grains,
/// forcing a real grain-list tree rather than the inline vector)
/// emitted through a `Path` target, bytes in FILE order. Kills a
/// mutant that treats a `Spill` file as having no refs at all (an
/// empty walk emits nothing and the sink would receive zero bytes,
/// caught by the byte-for-byte comparison below).
#[tokio::test]
async fn a_spill_file_emits_its_grain_list_in_order() {
    const GRAINS: u32 = FILE_INLINE_MAX_REFS + 1;

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0f_u8; DIGEST_LEN];

    let mut refs: Vec<GrainRef> = Vec::with_capacity(GRAINS as usize);
    let mut expected: Vec<u8> = Vec::with_capacity(GRAINS as usize * 2);
    let mut shard_entries: Vec<ShardEntry> = Vec::with_capacity(GRAINS as usize + 2);
    for i in 0..GRAINS {
        let payload = u16::try_from(i).unwrap_or(u16::MAX).to_be_bytes().to_vec();
        let (id, entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
        refs.push(GrainRef {
            id,
            unpacked_len: u32::try_from(payload.len()).unwrap_or_else(|e| panic!("{e}")),
        });
        expected.extend_from_slice(&payload);
        shard_entries.push(entry);
    }

    let built = manifest::build_grain_list(&refs).unwrap_or_else(|e| panic!("{e:?}"));
    for (id, bytes) in &built.nodes {
        let (_, entry) = seed_grain(&seam, &mut codec, bin_digest, bytes);
        assert_eq!(
            *id, entry.id,
            "seeded grain-list node id must match its content address"
        );
        shard_entries.push(entry);
    }

    let file_name = Name::new(b"spill.bin".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let file_entry = DirEntry {
        name: file_name.clone(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: u64::try_from(expected.len()).unwrap_or_else(|e| panic!("{e}")),
            grains: FileGrains::Spill {
                grain_count: GRAINS,
                root: built.root,
            },
        },
    };
    let dir_bytes = manifest::build_dir(&[file_entry]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        dir_bytes.nodes.len(),
        1,
        "one file is one leaf, no interior"
    );
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    shard_entries.push(root_entry);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![shard_entries]);
    seed_head(&seam, root_dir_id, index_id);

    let mut collected: Vec<u8> = Vec::new();
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.extend_from_slice(bytes);
        Ok(())
    };
    let path = vec![file_name];
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        collected, expected,
        "the spill file's grains must arrive in FILE order, not empty and not \
         reordered"
    );
}

// ---------------------------------------------------- walk refusals

/// Every non-file `Path` target kind is refused BY NAME — the
/// message states which kind it actually is, never a generic
/// "no such target". A directory, a symlink, a fifo and a socket,
/// each named at the top level of one small tree.
#[tokio::test]
async fn a_directory_target_is_refused_by_kind() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x10_u8; DIGEST_LEN];

    let child_dir = manifest::build_dir(&[]).unwrap_or_else(|e| panic!("{e}"));
    let (_, child_entry) = seed_grain(&seam, &mut codec, bin_digest, &child_dir.nodes[0].1);

    let dir_name = Name::new(b"a_dir".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let symlink_name = Name::new(b"a_symlink".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let fifo_name = Name::new(b"a_fifo".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let socket_name = Name::new(b"a_socket".to_vec()).unwrap_or_else(|e| panic!("{e}"));

    let entries = vec![
        DirEntry {
            name: dir_name.clone(),
            kind: ManifestEntryKind::Dir {
                child: child_dir.root,
            },
        },
        DirEntry {
            name: fifo_name.clone(),
            kind: ManifestEntryKind::Fifo,
        },
        DirEntry {
            name: socket_name.clone(),
            kind: ManifestEntryKind::Socket,
        },
        DirEntry {
            name: symlink_name.clone(),
            kind: ManifestEntryKind::Symlink {
                target: SymlinkTarget::new(b"/somewhere".to_vec())
                    .unwrap_or_else(|e| panic!("{e}")),
            },
        },
    ];
    let mut sorted = entries;
    sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let dir_bytes = manifest::build_dir(&sorted).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        dir_bytes.nodes.len(),
        1,
        "four entries is one leaf, no interior"
    );
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![vec![child_entry, root_entry]]);
    seed_head(&seam, root_dir_id, index_id);

    for (name, must_contain) in [
        (dir_name, "directory"),
        (symlink_name, "symlink"),
        (fifo_name, "fifo"),
        (socket_name, "socket"),
    ] {
        let path = vec![name.clone()];
        let err = resolve_at(
            &seam,
            TEST_VOLUME,
            1,
            None,
            ResolveTarget::Path(&path),
            &mut |_, _| Ok(()),
        )
        .await
        .expect_err(&format!("{} must be refused as a cat target", show(&name)));
        let ResolveError::NoSuchTarget { message } = err else {
            panic!("expected NoSuchTarget for {}, got {err:?}", show(&name));
        };
        assert!(
            message.contains(must_contain),
            "expected the refusal for {} to name it as a {must_contain}, got {message:?}",
            show(&name)
        );
    }
}

/// A path component absent from its directory is refused cleanly —
/// no panic, a named `NoSuchTarget`, never an index-out-of-bounds or
/// an `unwrap` on a lookup that simply found nothing.
#[tokio::test]
async fn a_missing_component_is_refused_cleanly() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x11_u8; DIGEST_LEN];

    let dir_bytes = manifest::build_dir(&[]).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    let index_id = seed_binmap(&seam, 0, bin_digest, vec![vec![root_entry]]);
    seed_head(&seam, root_dir_id, index_id);

    let missing = Name::new(b"never-published".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let path = vec![missing];
    let err = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a name absent from the directory must not resolve");
    assert!(
        matches!(err, ResolveError::NoSuchTarget { .. }),
        "expected NoSuchTarget, got {err:?}"
    );
}

/// A symlink named as an INTERMEDIATE path component — not the
/// final target — is refused, not silently skipped as though it
/// were a directory. This is a SEPARATE check from the final-
/// component refusal `a_directory_target_is_refused_by_kind` pins:
/// the walk loop over `dirs` (every component but the last) has its
/// own match arm, and dropping THAT arm while leaving the final one
/// intact would still refuse a symlink named directly but silently
/// walk PAST one named partway down a path.
#[tokio::test]
async fn a_non_directory_mid_path_is_refused_not_skipped() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x12_u8; DIGEST_LEN];

    let symlink_name = Name::new(b"mid".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let entries = vec![DirEntry {
        name: symlink_name.clone(),
        kind: ManifestEntryKind::Symlink {
            target: SymlinkTarget::new(b"/elsewhere".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        },
    }];
    let dir_bytes = manifest::build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    let (root_dir_id, root_dir_payload) = (dir_bytes.root, dir_bytes.nodes[0].1.clone());
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_dir_payload);
    let index_id = seed_binmap(&seam, 0, bin_digest, vec![vec![root_entry]]);
    seed_head(&seam, root_dir_id, index_id);

    // The symlink is named as a MID-path component; whatever comes
    // after it is never even resolvable, since it is not a
    // directory — the walk must stop AT the symlink.
    let tail = Name::new(b"anything".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let path = vec![symlink_name.clone(), tail];
    let err = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a symlink named mid-path must not be walked through");
    let ResolveError::NoSuchTarget { message } = err else {
        panic!("expected NoSuchTarget, got {err:?}");
    };
    assert!(
        message.contains("symlink"),
        "expected the mid-path refusal to name the symlink, got {message:?}"
    );
}

/// A small, honest volume — a handful of files, one nested directory
/// — resolves to exactly its own known content through a PATH target
/// (`gran cat`'s shape), the no-regression control.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture (several files, one nested dir) exercised by several distinct \
              PATH targets in turn — splitting the arms loses the shared fixture each one \
              is checked against"
)]
async fn an_honest_small_volume_resolves_identically() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x05_u8; DIGEST_LEN];

    let mut entries = Vec::new();
    let a_content = b"the first small file\n".to_vec();
    let (a_id, a_entry) = seed_grain(&seam, &mut codec, bin_digest, &a_content);
    entries.push(a_entry);

    let b_content = b"a second, different file, still small\n".to_vec();
    let (b_id, b_entry) = seed_grain(&seam, &mut codec, bin_digest, &b_content);
    entries.push(b_entry);

    let sub_file = DirEntry {
        name: Name::new(b"inner.txt".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::File {
            exec: false,
            size: u64::try_from(b_content.len()).unwrap_or_else(|e| panic!("{e}")),
            grains: FileGrains::Inline(vec![GrainRef {
                id: b_id,
                unpacked_len: u32::try_from(b_content.len()).unwrap_or_else(|e| panic!("{e}")),
            }]),
        },
    };
    let sub_dir = manifest::build_dir(&[sub_file]).unwrap_or_else(|e| panic!("{e}"));
    for (id, bytes) in &sub_dir.nodes {
        let (_, e) = seed_grain(&seam, &mut codec, bin_digest, bytes);
        assert_eq!(e.id, *id);
        entries.push(e);
    }

    let root_entries = vec![
        DirEntry {
            name: Name::new(b"a.txt".to_vec()).unwrap_or_else(|e| panic!("{e}")),
            kind: ManifestEntryKind::File {
                exec: false,
                size: u64::try_from(a_content.len()).unwrap_or_else(|e| panic!("{e}")),
                grains: FileGrains::Inline(vec![GrainRef {
                    id: a_id,
                    unpacked_len: u32::try_from(a_content.len()).unwrap_or_else(|e| panic!("{e}")),
                }]),
            },
        },
        DirEntry {
            name: Name::new(b"sub".to_vec()).unwrap_or_else(|e| panic!("{e}")),
            kind: ManifestEntryKind::Dir {
                child: sub_dir.root,
            },
        },
    ];
    let root_dir = manifest::build_dir(&root_entries).unwrap_or_else(|e| panic!("{e}"));
    for (id, bytes) in &root_dir.nodes {
        let (_, e) = seed_grain(&seam, &mut codec, bin_digest, bytes);
        assert_eq!(e.id, *id);
        entries.push(e);
    }

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, root_dir.root, index_id);

    // Path target: exactly the nested file, nothing else.
    let mut collected = Vec::new();
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.extend_from_slice(bytes);
        Ok(())
    };
    let path = vec![
        Name::new(b"sub".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        Name::new(b"inner.txt".to_vec()).unwrap_or_else(|e| panic!("{e}")),
    ];
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::Path(&path),
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        collected, b_content,
        "the path target reads exactly that file"
    );

    // Whole-tree target: the emission must contain each file's bytes
    // and be at least as long as both files together (it also carries
    // structure node bytes). Neither emission order nor the exact node
    // set is checked here.
    let mut whole = Vec::new();
    let mut whole_sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        whole.extend_from_slice(bytes);
        Ok(())
    };
    resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut whole_sink,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let expected_content: Vec<u8> = [a_content.as_slice(), b_content.as_slice()].concat();
    assert!(
        whole
            .windows(a_content.len())
            .any(|w| w == a_content.as_slice()),
        "the whole-tree emission must contain a.txt's bytes"
    );
    assert!(
        whole
            .windows(b_content.len())
            .any(|w| w == b_content.as_slice()),
        "the whole-tree emission must contain sub/inner.txt's bytes"
    );
    assert!(
        whole.len() >= expected_content.len(),
        "whole-tree emission also carries structure node bytes, so it is at least as long \
         as the file content alone"
    );
}

/// The PRODUCTION WIRING, end to end: a `ResolveTarget::WholeTree`
/// resolve driven through `resolve_at` — never `walk_all_files`
/// called directly — refuses with
/// [`ResolveError::PathBudgetExceeded`] on a DAG that expands past
/// [`WHOLE_TREE_PATH_BUDGET`].
///
/// **Why this row exists when three cases already drive the
/// budget.** All three call `walk_all_files` directly with a budget
/// of their own, so all three keep passing with the one production
/// call site handing the walk `usize::MAX` instead of the constant
/// — the mutation was executed and survived the whole crate suite.
/// The source-text row above only reads that the arm still contains
/// `walk_all_files(`, which a mis-wired budget satisfies as well.
/// Nothing pinned that the call a consumer actually reaches is
/// wired to the budget at all. This does, and it pins the CONSTANT:
/// `attempted` alone would still match a call site passing some
/// other bound.
///
/// **The fixture is the all-empty DAG above, widened.** Eight
/// entries per level, eight levels, every entry naming the one
/// child below it: nine nodes, 8 + 8² + … + 8⁸ = 19,173,960
/// descents, and not one file. Emitting nothing is the point — the
/// wired walk refuses after 2^20 descents having allocated no
/// descriptor at all, while the mis-wired one runs all 19.2M
/// descents and returns `Ok`, so the kill is an assertion about a
/// returned value and not a timeout.
#[tokio::test]
async fn a_whole_tree_resolve_refuses_past_the_path_budget_through_the_entry_point() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x2b_u8; DIGEST_LEN];
    let mut entries = Vec::new();

    // The innermost directory: one FIFO entry, so it yields NO
    // action at all — nothing to emit, nothing to descend into.
    let leaf = manifest::build_dir(&[DirEntry {
        name: Name::new(b"fifo".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let mut child = leaf.root;
    for (id, bytes) in &leaf.nodes {
        let (_, e) = seed_grain(&seam, &mut codec, bin_digest, bytes);
        assert_eq!(e.id, *id);
        entries.push(e);
    }
    for _level in 0..8 {
        let level: Vec<DirEntry> = (0..8)
            .map(|i| DirEntry {
                name: Name::new(format!("d{i}").into_bytes()).unwrap_or_else(|e| panic!("{e}")),
                kind: ManifestEntryKind::Dir { child },
            })
            .collect();
        let built = manifest::build_dir(&level).unwrap_or_else(|e| panic!("{e}"));
        child = built.root;
        for (id, bytes) in &built.nodes {
            let (_, e) = seed_grain(&seam, &mut codec, bin_digest, bytes);
            assert_eq!(e.id, *id);
            entries.push(e);
        }
    }
    assert_eq!(entries.len(), 9, "nine nodes, and not one file among them");

    let index_id = seed_binmap(&seam, 0, bin_digest, vec![entries]);
    seed_head(&seam, child, index_id);

    let mut emitted = 0_usize;
    let mut sink = |_id: GrainId, _bytes: &[u8]| -> Result<(), String> {
        emitted += 1;
        Ok(())
    };
    let err = resolve_at(
        &seam,
        TEST_VOLUME,
        1,
        None,
        ResolveTarget::WholeTree,
        &mut sink,
    )
    .await
    .expect_err("a whole-tree resolve expanding 19,173,960 descents must refuse");
    assert!(
        matches!(
            err,
            ResolveError::PathBudgetExceeded {
                attempted: 1_048_577,
                budget: WHOLE_TREE_PATH_BUDGET
            }
        ),
        "the entry point must refuse on the action past WHOLE_TREE_PATH_BUDGET: {err:?}"
    );
    assert_eq!(
        emitted, 0,
        "the walk is hoisted above emission: a refusal reaches the caller with the sink \
         still untouched"
    );
}

// -------------------------------------------- is_transport_down

/// One row per [`RefusalKind`], pinning which side of
/// [`is_transport_down`]'s axis each one sits on: `OverCap` and `Extent`
/// are the store answering (never transport-down, same side as
/// `NotFound`); `Framing` and `NoProgress` are the transport itself
/// misbehaving (transport-down, same side as `Backend`).
#[test]
fn is_transport_down_splits_refusedresponse_by_kind() {
    let refused = |kind: RefusalKind| RootStoreError::RefusedResponse {
        reason: "test".to_owned(),
        kind,
    };
    for (kind, want) in [
        (RefusalKind::OverCap, false),
        (RefusalKind::Extent, false),
        (RefusalKind::Framing, true),
        (RefusalKind::NoProgress, true),
    ] {
        assert_eq!(
            is_transport_down(&refused(kind)),
            want,
            "RefusalKind::{kind:?} must classify as transport-down = {want}"
        );
    }
}

#[test]
fn degraded_announcement_keeps_volume_sequence_and_age_on_local_when_logging_is_off() {
    use tracing_subscriber::layer::SubscriberExt as _;
    #[derive(Default)]
    struct Local(std::sync::Mutex<Vec<Vec<u8>>>);
    impl crate::LocalRecordWriter for Local {
        fn write_local(&self, record: &crate::LocalRecord) {
            self.0.lock().unwrap().push(record.as_bytes().to_vec());
        }
    }
    let identity = "resolve::tests::degraded_announcement_keeps_volume_sequence_and_age_on_local_when_logging_is_off";
    if std::env::var("GRANARY_LOCAL_REPORT_TEST_CHILD")
        .ok()
        .as_deref()
        != Some(identity)
    {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", identity, "--nocapture"])
            .env("GRANARY_LOCAL_REPORT_TEST_CHILD", identity)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated local report control failed"
        );
        return;
    }

    let local = Arc::new(Local::default());
    crate::install_local_reports(local.clone()).unwrap();
    let context = HeadContext::new(at(100), seeded(1));
    let anchor = |stamp: Option<i64>| HeadAnchor {
        seq: 21,
        hint: stamp.map(|stamp_secs| crate::PersistedHint {
            seq: 21,
            token: "synthetic-unused-token".into(),
            stamp_secs,
        }),
    };
    let subscriber = tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::new("off"));
    tracing::subscriber::with_default(subscriber, || {
        for stamp in [Some(83), None, Some(110)] {
            announce_degraded(&context, &anchor(stamp), "synthetic-local-volume");
        }
    });
    let records = local.0.lock().unwrap();
    assert_eq!(
        records.len(),
        3,
        "real degraded seam did not emit local reports"
    );
    for (record, age) in records.iter().zip(["17s", "unknown", "unknown"]) {
        let text = std::str::from_utf8(record).unwrap();
        assert!(text.contains(&format!("volume=synthetic-local-volume seq=21 age={age}")));
        assert!(text.contains("possibly stale") && text.contains("fails closed"));
        assert!(!text.contains("synthetic-unused-token"));
    }
}
