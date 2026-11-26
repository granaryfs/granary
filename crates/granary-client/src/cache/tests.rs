// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::cache` — the client cache: a persistent,
//! crash-safe, single-writer/lockless-reader disk cache of fetched
//! objects, roots and anchors.
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
// `JournalTail` was `cache.rs`'s until the `index_load` child took its
// only production user; its one remaining caller is the row below.
use granary_core::cacheindex::JournalTail;
// `PermissionsExt` was `cache.rs`'s until the `write` child took its
// only production user (`StagedWrite`); its remaining callers are the
// `from_mode` rows below, so the import follows them here.
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

// ---------------------------------------------------------- fixtures

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the crate's lint policy bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
                      hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
                      and nothing else (`granary-cache-test-<pid>-<counter>` under the temp dir, created and removed \
                      by this fixture), and it is load-bearing for correctness there: the counter beside it is \
                      per-process, and every test binary runs in its own process, so without the pid two concurrent \
                      runs generate the same name and share one directory. It reaches no hashed or signed value, and \
                      nothing under test reads it: the cache's own hashed values are object digests and index bytes, \
                      none of which carry a path"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-cache-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if fs::remove_dir_all(&self.0).is_err() {
            make_tree_writable(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn make_tree_writable(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o755));
            if path.is_dir() {
                make_tree_writable(&path);
            }
        }
    }
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
}

fn origin() -> CacheOrigin {
    CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x11; 32],
        root_key_id: None,
    }
}

#[test]
fn lock_and_guard_keep_default_creation_and_reopen_modes() {
    let scratch = ScratchDir::new();
    let reference = scratch.0.join("default-mode");
    fs::write(&reference, b"").unwrap();
    let default_mode = fs::metadata(&reference).unwrap().permissions().mode() & 0o777;
    let root = scratch.0.join("cache");
    let cache = open(&root, 1_000_000);
    for name in ["lock", "guard"] {
        assert_eq!(
            fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777,
            default_mode,
            "{name} create"
        );
    }
    drop(cache);
    fs::write(root.join("guard"), b"").unwrap();
    for name in ["lock", "guard"] {
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o640)).unwrap();
    }
    let _cache = open(&root, 1_000_000);
    for name in ["lock", "guard"] {
        assert_eq!(
            fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777,
            0o640,
            "{name} reopen"
        );
    }
}

fn vol(s: &str) -> VolumeName {
    VolumeName::new(s.to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

/// A `FreeSpace` reporting a fixed, injected reading — the seam's
/// test double, matching `Clock`/`Rng`'s pinned-value pattern.
struct FixedFreeSpace(FreeSpaceInfo);

impl FreeSpace for FixedFreeSpace {
    fn free_space(&self) -> io::Result<FreeSpaceInfo> {
        Ok(self.0)
    }
}

/// A `FreeSpace` that reports plenty AND counts its queries — the
/// seam doubling as an observer, so a test can assert that a
/// fail-closed path returned BEFORE the free-space precheck rather
/// than merely producing the same on-disk outcome by a later
/// refusal — a distinction the on-disk outcome cannot make, since
/// a later step often refuses the same input and leaves the same
/// disk state.
#[derive(Clone)]
struct CountingFreeSpace(std::sync::Arc<AtomicU64>);

impl CountingFreeSpace {
    fn new() -> Self {
        Self(std::sync::Arc::new(AtomicU64::new(0)))
    }
    fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn reset(&self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

impl FreeSpace for CountingFreeSpace {
    fn free_space(&self) -> io::Result<FreeSpaceInfo> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(FreeSpaceInfo {
            free_bytes: 1_000_000_000_000,
            capacity_bytes: 2_000_000_000_000,
        })
    }
}

/// Comfortably above any watermark this suite exercises — every
/// test that is not ITSELF testing the free-space gate uses this,
/// never the real filesystem's free space (which a constrained CI
/// sandbox could put under 1 GiB, silently no-opping every insert
/// in a test that never meant to exercise the gate at all).
fn plenty() -> Box<dyn FreeSpace> {
    Box::new(FixedFreeSpace(FreeSpaceInfo {
        free_bytes: 1_000_000_000_000,
        capacity_bytes: 2_000_000_000_000,
    }))
}

fn open(dir: &Path, quota: u64) -> Cache {
    Cache::open_with_free_space(dir, quota, &origin(), plenty()).unwrap_or_else(|e| panic!("{e}"))
}

fn open_with(dir: &Path, quota: u64, o: &CacheOrigin) -> Result<Cache, CacheError> {
    Cache::open_with_free_space(dir, quota, o, plenty())
}

fn id_of(byte: u8) -> (GrainId, Vec<u8>) {
    let bytes = vec![byte; 64];
    (GrainId::of(&bytes), bytes)
}

/// `n` ids whose fanout directories are pairwise DIFFERENT, and the
/// fanout each one lands in. Chosen by CONSTRUCTION rather than by
/// hoping literal seeds happen to collide the right way: a fixture
/// that makes one fanout unusable proves nothing if another object
/// in the same test lands under it, because that object's own
/// fanout creation would repair the plant.
fn ids_in_distinct_fanouts(root: &Path, n: usize) -> Vec<(GrainId, Vec<u8>, PathBuf)> {
    let mut picked: Vec<(GrainId, Vec<u8>, PathBuf)> = Vec::new();
    for byte in 0..=u8::MAX {
        if picked.len() == n {
            break;
        }
        let (id, bytes) = id_of(byte);
        let Some(fanout) = object_path(root, &id).parent().map(Path::to_path_buf) else {
            continue;
        };
        if picked.iter().all(|(_, _, f)| *f != fanout) {
            picked.push((id, bytes, fanout));
        }
    }
    assert_eq!(
        picked.len(),
        n,
        "control: 256 single-byte seeds must yield {n} distinct fanouts"
    );
    picked
}

fn force_flush(cache: &mut Cache) {
    if let Mode::Writer(w) = &mut cache.mode {
        w.flush_journal_buffer().unwrap_or_else(|e| panic!("{e}"));
    }
}

// -------------------------------------------------------- unit rows

// ------------------------------------------- the CLI's origin digests

/// **Order-independence and dedup are properties of the
/// CANONICALIZATION, not of the hash** — two permutations
/// of the same pin set, and a set with a pin repeated, must all
/// digest identically; a genuinely different set must not.
#[test]
fn pin_set_digest_is_order_independent_and_deduplicates() {
    let a = [0x11_u8; 32];
    let b = [0x22_u8; 32];
    let c = [0x33_u8; 32];
    let forward = CacheOrigin::pin_set_digest(&[a, b, c]);
    let reversed = CacheOrigin::pin_set_digest(&[c, b, a]);
    let shuffled = CacheOrigin::pin_set_digest(&[b, c, a]);
    assert_eq!(forward, reversed, "order must not move the digest");
    assert_eq!(forward, shuffled, "order must not move the digest");

    let duplicated = CacheOrigin::pin_set_digest(&[a, b, c, b]);
    assert_eq!(
        forward, duplicated,
        "a repeated pin must not move the digest — the count in the preimage is the \
         CANONICALIZED (post-dedup) count"
    );

    let different = CacheOrigin::pin_set_digest(&[a, b]);
    assert_ne!(
        forward, different,
        "a genuinely different pin set must digest differently"
    );
}

/// Reimplements the pin preimage (`b"granary-cache-origin-pins-v1"` ++ canonicalized count (`u64` BE) ++ sorted, deduplicated 32-byte pins) literally, as its own oracle —
/// `writer_uuid`'s own golden-vector test (`publish.rs`) uses the same
/// shape: a silent reordering of the concatenation inside
/// `pin_set_digest` would pass every OTHER row in this file (they only
/// compare the function against itself) but fail this one.
#[test]
fn pin_set_digest_matches_the_frozen_preimage() {
    let a = [0x11_u8; 32];
    let b = [0x22_u8; 32];
    let mut expected_seed = Vec::new();
    expected_seed.extend_from_slice(b"granary-cache-origin-pins-v1");
    expected_seed.extend_from_slice(&2u64.to_be_bytes());
    expected_seed.extend_from_slice(&a);
    expected_seed.extend_from_slice(&b);
    let expected = *GrainId::of(&expected_seed).digest();
    assert_eq!(CacheOrigin::pin_set_digest(&[a, b]), expected);
    // SORTED order in the preimage: `[b, a]` as input must canonicalize
    // to the same (sorted) preimage as `[a, b]`, not `[b, a]`'s own
    // concatenation order.
    assert_eq!(CacheOrigin::pin_set_digest(&[b, a]), expected);
}

#[test]
fn pin_set_digest_of_the_empty_set_is_stable_and_distinct() {
    let empty = CacheOrigin::pin_set_digest(&[]);
    let one = CacheOrigin::pin_set_digest(&[[0x11_u8; 32]]);
    assert_ne!(empty, one);
    assert_eq!(empty, CacheOrigin::pin_set_digest(&[]));
}

#[test]
fn root_key_digest_is_deterministic_and_sensitive_to_the_key() {
    let a = [0xAA_u8; 32];
    let b = [0xBB_u8; 32];
    assert_eq!(
        CacheOrigin::root_key_digest(&a),
        CacheOrigin::root_key_digest(&a)
    );
    assert_ne!(
        CacheOrigin::root_key_digest(&a),
        CacheOrigin::root_key_digest(&b)
    );
    // And distinct from `pin_set_digest`'s domain — the two preimages
    // must not collide merely because both ultimately wrap 32-byte
    // values; the leading domain separator is what keeps them apart.
    assert_ne!(
        CacheOrigin::root_key_digest(&a),
        CacheOrigin::pin_set_digest(&[a])
    );
}

/// Reimplements the root-key preimage (`b"granary-cache-origin-rootkey-v1"` ++ the 32 raw public-key bytes) literally, as its own
/// oracle — the twin of `pin_set_digest_matches_the_frozen_preimage`.
/// Without it the root-key SEPARATOR is pinned by NO test: the
/// domain-separation row above (`…sensitive_to_the_key`) detects the
/// pin-vs-rootkey difference via the STRUCTURE — `pin_set_digest`'s
/// 8-byte count field makes the preimages different lengths — so it
/// stays green even if `root_key_digest`'s separator is swapped to the
/// pin one (a quality-lane mutation). This oracle goes red on any
/// separator or structure drift.
#[test]
fn root_key_digest_matches_the_frozen_preimage() {
    let a = [0x11_u8; 32];
    let mut expected_seed = Vec::new();
    expected_seed.extend_from_slice(b"granary-cache-origin-rootkey-v1");
    expected_seed.extend_from_slice(&a);
    let expected = *GrainId::of(&expected_seed).digest();
    assert_eq!(CacheOrigin::root_key_digest(&a), expected);
}

/// A pre-planted symlinked structural dir
/// (`index -> ../elsewhere`) must be REFUSED, not followed —
/// `create_dir_all` would follow it into a real dir and every
/// subsequent structural write would land OUTSIDE the cache root (on
/// the publish path, that publishes the cache's own index files as
/// volume content). Asserts BOTH the refusal AND that nothing was
/// written through the link.
#[test]
fn open_refuses_a_symlinked_structural_dir() {
    let scratch = ScratchDir::new();
    let cache_root = scratch.0.join("cache");
    let elsewhere = scratch.0.join("elsewhere");
    fs::create_dir_all(&cache_root).unwrap_or_else(|e| panic!("{e}"));
    fs::create_dir_all(&elsewhere).unwrap_or_else(|e| panic!("{e}"));
    // `cache/index -> ../elsewhere` — a symlink to a real dir, exactly
    // what `create_dir_all` would follow and return `Ok` for.
    std::os::unix::fs::symlink(&elsewhere, cache_root.join("index"))
        .unwrap_or_else(|e| panic!("{e}"));

    let err = Cache::open_with_free_space(&cache_root, 1_000_000, &origin(), plenty())
        .expect_err("a symlinked structural dir must be refused, not followed");
    assert!(
        matches!(err, CacheError::Io { .. }),
        "the refusal is an Io-context error naming the structural dir: {err}"
    );
    assert!(
        fs::read_dir(&elsewhere)
            .unwrap_or_else(|e| panic!("{e}"))
            .next()
            .is_none(),
        "the cache must not have written any file THROUGH the symlink into the target dir"
    );
}

/// An endpoint URL long enough to render a
/// marker over `MARKER_MAX_BYTES` is refused at WRITE time (open),
/// symmetric with the reopen bound — never a dir that opens once and
/// then can never be reopened.
#[test]
fn open_refuses_an_endpoint_that_overflows_the_marker_bound() {
    let scratch = ScratchDir::new();
    let huge = "x".repeat(usize::try_from(MARKER_MAX_BYTES).unwrap_or(usize::MAX) + 1);
    let origin = CacheOrigin {
        endpoint_url: format!("https://{huge}/"),
        pin_set_digest: [0x11; 32],
        root_key_id: None,
    };
    let err = Cache::open_with_free_space(&scratch.0, 1_000_000, &origin, plenty())
        .expect_err("an over-long endpoint must be refused at open, not on the next reopen");
    assert!(
        matches!(err, CacheError::Incompatible { .. }),
        "got {err:?}"
    );
}

// ------------------------------------------------------ TDD: basics

#[test]
fn a_cache_hit_roundtrips_and_is_hash_verified() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(1);
    assert_eq!(cache.get(&id), None);
    cache.insert(&id, &bytes);
    assert_eq!(cache.get(&id), Some(bytes));
}

#[test]
fn a_flipped_byte_is_a_miss_and_the_writer_unlinks_it() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(2);
    cache.insert(&id, &bytes);
    let path = object_path(&dir.0, &id);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    let mut tampered = bytes.clone();
    if let Some(b) = tampered.get_mut(0) {
        *b ^= 0xFF;
    }
    fs::write(&path, &tampered).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(cache.get(&id), None, "a hash mismatch must be a miss");
    assert!(!path.exists(), "the writer must unlink the corrupt file");
    // The corrupt gate really fired (not a vacuous pass): the index
    // no longer carries the id either.
    if let Mode::Writer(w) = &cache.mode {
        assert!(!w.live.contains_key(&id));
    } else {
        panic!("expected writer mode");
    }
}

/// `O_NOFOLLOW` protects only the object name itself. A symlink at
/// `objects/<2hex>` must be refused before opening the final component,
/// or corrupt-object eviction unlinks a real file outside the cache.
/// The outside file exists at the exact 64-hex name and has the wrong
/// hash, so lookup reaches the destructive branch instead of vacuously
/// returning `NotFound`.
#[test]
fn get_does_not_unlink_through_a_symlinked_fanout() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, expected) = id_of(0x42);
    let object = object_path(&dir.0, &id);
    let fanout = object
        .parent()
        .unwrap_or_else(|| panic!("an object path always has a fanout parent"));

    let outside = ScratchDir::new();
    let file_name = object
        .file_name()
        .unwrap_or_else(|| panic!("an object path always has a final component"));
    let victim = outside.0.join(file_name);
    let corrupt = b"outside file with the wrong hash";
    assert_ne!(
        GrainId::of(corrupt),
        id,
        "fixture bytes must force the hash-mismatch eviction branch"
    );
    assert_eq!(expected.len(), 64, "positive control for the expected id");
    fs::write(&victim, corrupt).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&outside.0, fanout).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        cache.get(&id),
        None,
        "a foreign fanout is still a cache miss"
    );
    assert!(
        victim.exists(),
        "a cache miss must never unlink the resolved object outside the cache"
    );
}

#[test]
fn quota_eviction_evicts_lru_single_objects() {
    let dir = ScratchDir::new();
    let (id1, b1) = id_of(1);
    let (id2, b2) = id_of(2);
    let (id3, b3) = id_of(3);
    let (id4, b4) = id_of(4);
    let object_len = b1.len() as u64;
    let mut cache = open(&dir.0, object_len * 3);

    cache.insert(&id1, &b1);
    cache.insert(&id2, &b2);
    cache.insert(&id3, &b3);
    cache.insert(&id4, &b4);
    force_flush(&mut cache);

    assert_eq!(
        cache.get(&id1),
        None,
        "the least-recently-used entry must be evicted"
    );
    assert_eq!(cache.get(&id2), Some(b2));
    assert_eq!(cache.get(&id3), Some(b3));
    assert_eq!(cache.get(&id4), Some(b4));

    if let Mode::Writer(w) = &cache.mode {
        assert_eq!(w.live.len(), 3);
        assert!(!w.live.contains_key(&id1));
    } else {
        panic!("expected writer mode");
    }

    // The task text's own claim: "journal shows the evict".
    let journal_bytes =
        fs::read(dir.0.join("index").join("journal")).unwrap_or_else(|e| panic!("{e}"));
    let (records, _tail) =
        cacheindex::decode_journal(&journal_bytes).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::Evict { id } if *id == id1)),
        "the journal must record the eviction of the LRU id"
    );
}

#[test]
fn quota_eviction_can_recover_from_an_initial_watermark_refusal() {
    struct EvictionAwareFreeSpace {
        lru_path: PathBuf,
        before_evict: FreeSpaceInfo,
        after_evict: FreeSpaceInfo,
    }

    impl FreeSpace for EvictionAwareFreeSpace {
        fn free_space(&self) -> io::Result<FreeSpaceInfo> {
            Ok(if self.lru_path.exists() {
                self.before_evict
            } else {
                self.after_evict
            })
        }
    }

    let dir = ScratchDir::new();
    let (old_id, old_bytes) = id_of(3);
    let (new_id, new_bytes) = id_of(4);
    let len = old_bytes.len() as u64;
    let capacity_bytes = 40 * WATERMARK_MIN_BYTES;
    let watermark = watermark_bytes(capacity_bytes);
    let before_evict = FreeSpaceInfo {
        free_bytes: watermark.saturating_add(len).saturating_sub(1),
        capacity_bytes,
    };
    let after_evict = FreeSpaceInfo {
        free_bytes: before_evict.free_bytes.saturating_add(len),
        capacity_bytes,
    };
    let old_path = object_path(&dir.0, &old_id);
    let seam = EvictionAwareFreeSpace {
        lru_path: old_path.clone(),
        before_evict,
        after_evict,
    };
    let mut cache = Cache::open_with_free_space(&dir.0, len, &origin(), Box::new(seam))
        .unwrap_or_else(|e| panic!("{e}"));

    cache.insert(&old_id, &old_bytes);
    let Mode::Writer(w) = &cache.mode else {
        panic!("expected writer mode");
    };
    assert!(
        !free_space_precheck(w.free_space.as_ref(), len),
        "control: while the LRU file exists, the proposed write must be one byte short"
    );

    cache.insert(&new_id, &new_bytes);

    assert!(
        !old_path.exists(),
        "the quota eviction must run despite the initial watermark refusal"
    );
    let Mode::Writer(w) = &cache.mode else {
        panic!("expected writer mode");
    };
    assert!(
        free_space_precheck(w.free_space.as_ref(), len),
        "control: unlinking the LRU file must make exactly enough modeled room"
    );
    assert_eq!(cache.get(&new_id), Some(new_bytes));
}

#[test]
fn the_free_space_gate_refuses_and_the_read_still_succeeds() {
    let dir = ScratchDir::new();
    let under_watermark = Box::new(FixedFreeSpace(FreeSpaceInfo {
        free_bytes: 100, // far below the 1 GiB floor
        capacity_bytes: 1_000_000_000_000,
    }));
    let mut cache = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), under_watermark)
        .unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = id_of(5);

    cache.insert(&id, &bytes);

    assert_eq!(cache.get(&id), None, "the insert must have been skipped");
    // The caller's own copy of the bytes is completely unaffected —
    // the cache's refusal never fails the caller's read.
    assert_eq!(bytes, vec![5u8; 64]);
}

#[test]
fn an_unclean_close_replays_the_journal_without_a_rescan() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id1, b1) = id_of(10);
    let (id2, b2) = id_of(11);
    cache.insert(&id1, &b1);
    cache.insert(&id2, &b2);
    force_flush(&mut cache);
    drop(cache); // kill-style: no close(), guard stays present

    assert!(
        dir.0.join("guard").exists(),
        "the guard must survive an unclean exit"
    );

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.walk_reads.load(Ordering::Relaxed),
        0,
        "an ordinary crash must not walk"
    );
    assert!(w.live.contains_key(&id1));
    assert!(w.live.contains_key(&id2));
}

// `abandon` is the NAMED counterpart of a
// bare drop — proof that it performs no clean-close sequence at all,
// modelled on the unclean-close test just above (which already
// proves bare destruction leaves the guard). This one pins the
// NAMED path and additionally proves the journal itself is
// untouched: not merely "guard survives" but "nothing was flushed
// or compacted".
#[test]
fn abandon_leaves_the_guard_and_does_not_touch_the_journal() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id1, b1) = id_of(40);
    cache.insert(&id1, &b1);
    force_flush(&mut cache);

    let journal_path = dir.0.join("index").join("journal");
    let len_before = fs::metadata(&journal_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();

    cache.abandon();

    assert!(
        dir.0.join("guard").exists(),
        "abandon must leave the crash guard on disk"
    );
    let len_after = fs::metadata(&journal_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert_eq!(
        len_after, len_before,
        "abandon must not flush or compact the journal"
    );
}

#[test]
fn a_torn_journal_record_is_a_trusted_prefix_not_a_rebuild() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id1, b1) = id_of(20);
    let (id2, b2) = id_of(21);
    cache.insert(&id1, &b1);
    cache.insert(&id2, &b2);
    force_flush(&mut cache);
    drop(cache); // leave the guard present

    // Flip the LAST byte of the second record's check — a
    // complete-length record whose integrity still fails must
    // truncate at record 2's own start, leaving record 1 intact.
    let journal_path = dir.0.join("index").join("journal");
    let mut bytes = fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    let insert_record_len = 1 + DIGEST_LEN + 4 + 4; // tag + digest + size + check
    let second_record_end = cacheindex::ENVELOPE_LEN + insert_record_len * 2;
    if let Some(b) = bytes.get_mut(second_record_end - 1) {
        *b ^= 0xFF;
    }
    fs::write(&journal_path, &bytes).unwrap_or_else(|e| panic!("{e}"));

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.walk_reads.load(Ordering::Relaxed),
        0,
        "a torn record is a clean decode, never a rebuild trigger"
    );
    assert!(w.live.contains_key(&id1), "the trusted prefix must survive");
    assert!(
        !w.live.contains_key(&id2),
        "the torn record must not be adopted"
    );
}

#[test]
fn a_corrupt_snapshot_falls_back_to_the_cold_rebuild() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id1, b1) = id_of(30);
    let (id2, b2) = id_of(31);
    cache.insert(&id1, &b1);
    cache.insert(&id2, &b2);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let snapshot_path = dir.0.join("index").join("snapshot");
    fs::write(&snapshot_path, b"not a valid snapshot at all").unwrap_or_else(|e| panic!("{e}"));

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert!(
        w.walk_reads.load(Ordering::Relaxed) > 0,
        "a corrupt snapshot must trigger the walk"
    );
    assert!(w.live.contains_key(&id1));
    assert!(w.live.contains_key(&id2));
    // Cold order is lexicographic-by-id, not insertion order.
    let lru = w.entries_lru();
    let mut sorted = lru.clone();
    sorted.sort_unstable_by_key(|(e, _)| *e);
    assert_eq!(lru, sorted);
}

#[test]
fn a_corrupt_journal_envelope_falls_back_to_the_cold_rebuild() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id1, b1) = id_of(40);
    let (id2, b2) = id_of(41);
    cache.insert(&id1, &b1);
    cache.insert(&id2, &b2);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let journal_path = dir.0.join("index").join("journal");
    fs::write(&journal_path, b"XXXXnotamagic").unwrap_or_else(|e| panic!("{e}"));

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert!(
        w.walk_reads.load(Ordering::Relaxed) > 0,
        "a bad journal envelope must trigger the walk"
    );
    assert!(w.live.contains_key(&id1));
    assert!(w.live.contains_key(&id2));
    // Cold order is lexicographic-by-id, not insertion order — a
    // SINGLE object cannot demonstrate an order at all.
    let lru = w.entries_lru();
    let mut sorted = lru.clone();
    sorted.sort_unstable_by_key(|(e, _)| *e);
    assert_eq!(lru, sorted);
}

/// `index/snapshot` and `index/journal` must be opened
/// `O_NOFOLLOW`, the same as `lock`/`guard` — a planted symlink
/// there must never be read through, regardless of what is on the
/// other side (an attacker-controlled file outside the cache root
/// could otherwise be substituted for the trusted index).
#[test]
fn read_index_file_bounded_refuses_a_symlinked_snapshot() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establish a real snapshot/journal

    let outside = ScratchDir::new();
    let outside_file = outside.0.join("forged-snapshot");
    fs::write(&outside_file, b"forged content from outside the cache root")
        .unwrap_or_else(|e| panic!("{e}"));

    let snapshot_path = dir.0.join("index").join("snapshot");
    fs::remove_file(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&outside_file, &snapshot_path).unwrap_or_else(|e| panic!("{e}"));

    assert!(
        matches!(
            read_index_file_bounded(&snapshot_path, "snapshot"),
            IndexFileRead::Untrustworthy
        ),
        "a symlinked index file must never be read through (O_NOFOLLOW)"
    );
}

#[test]
fn a_second_writer_degrades_to_read_only() {
    #[derive(Clone, Default)]
    struct WarnCounter(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCounter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = ScratchDir::new();
    let mut writer = open(&dir.0, 1_000_000);
    assert!(
        !writer.is_read_only_degraded(),
        "a writer-mode cache must not report degraded"
    );
    // Insert BEFORE the second opener connects — without this, the
    // "serves hits" claim below is vacuous: `get() == None` would
    // prove nothing about whether the degraded path can serve a
    // real hit at all.
    let (id, bytes) = id_of(50);
    writer.insert(&id, &bytes);

    let counter = WarnCounter::default();
    let subscriber = tracing_subscriber::registry().with(counter.clone());
    let second =
        tracing::subscriber::with_default(subscriber, || open_with(&dir.0, 1_000_000, &origin()));
    let mut second = second.unwrap_or_else(|e| panic!("{e}"));

    assert!(
        second.is_read_only_degraded(),
        "a cache that lost the lock race must report degraded"
    );
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        1,
        "exactly one warning must fire"
    );

    assert_eq!(
        second.get(&id),
        Some(bytes),
        "the degraded opener must still serve an existing hit, hash-verified"
    );

    let (other_id, other_bytes) = id_of(51);
    second.insert(&other_id, &other_bytes); // silent no-op
    assert_eq!(
        second.get(&other_id),
        None,
        "the insert must not have happened"
    );
}

#[test]
fn a_reader_mid_eviction_completes_or_misses_cleanly() {
    let dir = ScratchDir::new();
    let (id1, b1) = id_of(60);
    let (id2, b2) = id_of(61);
    let object_len = b1.len() as u64;
    let mut cache = open(&dir.0, object_len); // room for exactly one

    cache.insert(&id1, &b1);
    let path1 = object_path(&dir.0, &id1);
    let mut open_handle = File::open(&path1).unwrap_or_else(|e| panic!("{e}"));

    cache.insert(&id2, &b2); // evicts id1 (LRU) to make room

    // POSIX: the already-open descriptor keeps working after the
    // unlink — a reader racing an eviction never sees a torn read.
    let mut via_open_handle = Vec::new();
    open_handle
        .read_to_end(&mut via_open_handle)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(via_open_handle, b1);

    // A FRESH lookup after the eviction is a clean miss, never an
    // error or a torn read.
    assert_eq!(cache.get(&id1), None);
    assert_eq!(cache.get(&id2), Some(b2));
}

#[test]
fn the_marker_handshake_refuses_a_foreign_tuple() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    let marker_path = dir.0.join(MARKER_NAME);
    let mut contents = fs::read_to_string(&marker_path).unwrap_or_else(|e| panic!("{e}"));
    contents = contents.replace("chunker fastcdc-v2020/4.0.1", "chunker fastcdc-v2020/9.9.9");
    fs::write(&marker_path, contents).unwrap_or_else(|e| panic!("{e}"));

    let err = open_with(&dir.0, 1_000_000, &origin()).expect_err("a foreign tuple must be refused");
    assert!(
        matches!(err, CacheError::Incompatible { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_foreign_origin_is_refused() {
    let dir = ScratchDir::new();
    let a = origin();
    let b = CacheOrigin {
        endpoint_url: "https://other.invalid/".to_owned(),
        ..origin()
    };

    // Writer mode: a fresh solo opener with a different origin.
    drop(open_with(&dir.0, 1_000_000, &a).unwrap_or_else(|e| panic!("{e}")));
    let err =
        open_with(&dir.0, 1_000_000, &b).expect_err("a foreign origin must be refused (writer)");
    assert!(
        matches!(err, CacheError::Incompatible { .. }),
        "got {err:?}"
    );

    // Read-only-degraded mode: a second opener while the first
    // (origin A) still holds the lock.
    let dir2 = ScratchDir::new();
    let _writer_a = open_with(&dir2.0, 1_000_000, &a).unwrap_or_else(|e| panic!("{e}"));
    let err2 =
        open_with(&dir2.0, 1_000_000, &b).expect_err("a foreign origin must be refused (degraded)");
    assert!(
        matches!(err2, CacheError::Incompatible { .. }),
        "got {err2:?}"
    );
}

// ------------------------------------------------------- unit rows

#[test]
fn an_oversized_file_is_a_miss() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000_000);
    let (id, bytes) = id_of(70);
    // Insert normally FIRST, so there is a real `live` entry to
    // check for a ghost survivor — a planted-but-never-indexed id
    // cannot demonstrate that the oversized branch evicts, only that
    // it unlinks.
    cache.insert(&id, &bytes);
    let path = object_path(&dir.0, &id);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    let oversized = vec![0u8; usize::try_from(META_MAX_BYTES).unwrap_or(usize::MAX) + 1];
    fs::write(&path, &oversized).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        cache.get(&id),
        None,
        "a file over META_MAX_BYTES is a miss before any read"
    );
    assert!(!path.exists(), "the writer must unlink the oversized file");
    if let Mode::Writer(w) = &cache.mode {
        assert!(
            !w.live.contains_key(&id),
            "the oversized branch must evict the index entry, not leave a ghost that still \
             counts against quota"
        );
    } else {
        panic!("expected writer mode");
    }
}

/// The oversized branch drops the index entry and refunds its bytes
/// even when the unlink fails: the entry and the charge always go
/// together, because `total_bytes` is the sum of `live`'s sizes.
/// What stays behind is a residue on disk that no entry names —
/// `gran verify` reports it, and the accounting under-counts the
/// cache until it is cleared.
#[test]
fn an_oversized_object_whose_unlink_fails_is_still_evicted_and_refunded() {
    let oversized = vec![0u8; usize::try_from(META_MAX_BYTES).unwrap_or(usize::MAX) + 1];

    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000_000);
    let (id, bytes) = id_of(71);
    cache.insert(&id, &bytes);
    let path = object_path(&dir.0, &id);
    let fanout = path
        .parent()
        .unwrap_or_else(|| panic!("an object path always has a fanout parent"))
        .to_path_buf();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    fs::write(&path, &oversized).unwrap_or_else(|e| panic!("{e}"));
    // Unlink permission comes from the DIRECTORY, so this is what
    // makes the unlink fail while the file stays readable.
    fs::set_permissions(&fanout, fs::Permissions::from_mode(0o555))
        .unwrap_or_else(|e| panic!("{e}"));

    let got = cache.get(&id);
    let restored = fs::set_permissions(&fanout, fs::Permissions::from_mode(0o755));

    assert_eq!(got, None, "an oversized file is a miss either way");
    assert!(
        path.exists(),
        "control: the unlink really did fail — if the file is gone this test proves \
         nothing about the residue"
    );
    if let Mode::Writer(w) = &cache.mode {
        assert!(
            !w.live.contains_key(&id),
            "the index entry goes — the object is unusable whatever happened to the name"
        );
        assert_eq!(
            w.total_bytes, 0,
            "and its bytes go with it: the entry and the charge are one thing, and the \
             file left on disk is the residue gran verify reports"
        );
    } else {
        panic!("expected writer mode");
    }
    restored.unwrap_or_else(|e| panic!("{e}"));
}

/// The hash-mismatch twin of the row above, and the other caller
/// of `evict_id`.
#[test]
fn a_corrupt_object_whose_unlink_fails_is_still_evicted_and_refunded() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(72);
    cache.insert(&id, &bytes);
    let path = object_path(&dir.0, &id);
    let fanout = path
        .parent()
        .unwrap_or_else(|| panic!("an object path always has a fanout parent"))
        .to_path_buf();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    // Same length, different content: the id no longer addresses
    // what is at the name.
    fs::write(&path, vec![0xFFu8; bytes.len()]).unwrap_or_else(|e| panic!("{e}"));
    fs::set_permissions(&fanout, fs::Permissions::from_mode(0o555))
        .unwrap_or_else(|e| panic!("{e}"));

    let got = cache.get(&id);
    let restored = fs::set_permissions(&fanout, fs::Permissions::from_mode(0o755));

    assert_eq!(got, None, "a corrupt object is a miss");
    assert!(
        path.exists(),
        "control: the unlink really did fail — the file is still on disk"
    );
    if let Mode::Writer(w) = &cache.mode {
        assert!(
            !w.live.contains_key(&id),
            "the index entry goes — the bytes at that name failed verification"
        );
        assert_eq!(
            w.total_bytes, 0,
            "and its bytes go with it, leaving the residue on disk for gran verify"
        );
    } else {
        panic!("expected writer mode");
    }
    restored.unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn roots_put_get_roundtrip_with_the_20_digit_leaf() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("root-conf-cache");
    let bytes = b"a verified root document".to_vec();

    assert_eq!(cache.get_root_bytes(&v, 1), None);
    cache.put_root_bytes(&v, 1, &bytes);
    assert_eq!(cache.get_root_bytes(&v, 1), Some(bytes.clone()));

    let leaf = dir
        .0
        .join("roots")
        .join(v.as_str())
        .join("00000000000000000001");
    assert!(
        leaf.exists(),
        "the seq leaf must be the 20-digit zero-padded form"
    );
    assert_eq!(fs::read(&leaf).unwrap_or_else(|e| panic!("{e}")), bytes);
}

#[test]
fn the_free_space_gate_refuses_a_root_write_too() {
    let dir = ScratchDir::new();
    let under_watermark = Box::new(FixedFreeSpace(FreeSpaceInfo {
        free_bytes: 100,
        capacity_bytes: 1_000_000_000_000,
    }));
    let mut cache = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), under_watermark)
        .unwrap_or_else(|e| panic!("{e}"));
    let v = vol("root-conf-refuse");
    cache.put_root_bytes(&v, 1, b"root bytes");
    assert_eq!(
        cache.get_root_bytes(&v, 1),
        None,
        "the root write must have been skipped"
    );
}

#[test]
fn the_walk_skips_a_foreign_name_and_a_mismatched_fanout_and_an_oversized_file() {
    let dir = ScratchDir::new();
    {
        let cache = open(&dir.0, 1_000_000);
        drop(cache); // establish the marker + directory layout
    }

    let objects = dir.0.join("objects");
    // A legitimate, correctly-placed small object.
    let (good_id, good_bytes) = id_of(80);
    let good_path = object_path(&dir.0, &good_id);
    if let Some(parent) = good_path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{e}"));
    }
    fs::write(&good_path, &good_bytes).unwrap_or_else(|e| panic!("{e}"));

    // A non-hex file name under a legitimate fanout dir.
    fs::create_dir_all(objects.join("ab")).unwrap_or_else(|e| panic!("{e}"));
    fs::write(objects.join("ab").join("not-a-digest.txt"), b"nope")
        .unwrap_or_else(|e| panic!("{e}"));

    // A valid 64-hex name placed under the WRONG fanout directory.
    let (mismatched_id, mismatched_bytes) = id_of(81);
    let real_hex = mismatched_id.digest_hex();
    fs::create_dir_all(objects.join("00")).unwrap_or_else(|e| panic!("{e}"));
    fs::write(objects.join("00").join(&real_hex), &mismatched_bytes)
        .unwrap_or_else(|e| panic!("{e}"));

    // An oversized but otherwise well-formed entry.
    let (big_id, _) = id_of(82);
    let big_hex = big_id.digest_hex();
    let big_dir = big_hex.get(..2).unwrap_or("00").to_owned();
    fs::create_dir_all(objects.join(&big_dir)).unwrap_or_else(|e| panic!("{e}"));
    let oversized = vec![0u8; usize::try_from(META_MAX_BYTES).unwrap_or(usize::MAX) + 1];
    fs::write(objects.join(&big_dir).join(&big_hex), &oversized).unwrap_or_else(|e| panic!("{e}"));

    // Force the cold rebuild walk.
    fs::write(dir.0.join("index").join("snapshot"), b"garbage").unwrap_or_else(|e| panic!("{e}"));

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert!(w.walk_reads.load(Ordering::Relaxed) > 0);
    assert_eq!(
        w.live.len(),
        1,
        "only the one legitimate object must be adopted"
    );
    assert_eq!(w.entries_lru().first().map(|(e, _)| *e), Some(good_id));
}

// ---------------------------------------------------- more unit rows

#[test]
fn writer_open_sweeps_orphaned_txn_staging() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establish the marker + directory layout

    let orphan = dir.0.join("txn").join("12345-0");
    fs::write(&orphan, b"orphaned staging from a crashed writer").unwrap_or_else(|e| panic!("{e}"));
    assert!(orphan.exists());

    drop(open(&dir.0, 1_000_000));
    assert!(
        !orphan.exists(),
        "a writer open must sweep orphaned txn/ staging"
    );
}

/// A SYMLINK planted at a staging name must be cleared like every
/// other non-directory entry, and its target must survive.
///
/// Leaving it is a permanent wedge, not a conservative choice.
/// `atomic_write` stages under `<pid>-<counter>`, and the OS reuses
/// numeric pids while every fresh process restarts its counter at
/// zero — so a link planted at `txn/<pid>-0` makes `create_new`
/// fail `EEXIST` for that pid forever, and the sweep is the only
/// thing that ever clears the name. Removing it is safe for exactly
/// the reason the sweep can be trusted at all: `remove_file` never
/// follows its FINAL component, so the link NAME is unlinked and
/// the target is untouched. The directory half of this row is what
/// pins the one entry the sweep still leaves: a directory.
#[test]
fn writer_open_sweeps_a_symlinked_txn_entry_without_following_it() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    let outside = ScratchDir::new();
    let victim = outside.0.join("someone-elses-file");
    fs::write(&victim, b"must survive byte for byte").unwrap_or_else(|e| panic!("{e}"));

    let planted = dir.0.join("txn").join("12345-0");
    std::os::unix::fs::symlink(&victim, &planted).unwrap_or_else(|e| panic!("{e}"));

    drop(open(&dir.0, 1_000_000));

    assert!(
        fs::symlink_metadata(&planted).is_err(),
        "a symlink at a staging name wedges create_new EEXIST for that pid forever; the \
         sweep must remove the NAME"
    );
    assert_eq!(
        fs::read(&victim).unwrap_or_else(|e| panic!("{e}")),
        b"must survive byte for byte".to_vec(),
        "and remove_file must not have followed the link — the target is untouched"
    );

    // A DIRECTORY under txn/ is an anomaly, not staging, and must
    // still be left alone: the sweep widens to symlinks, not
    // to everything.
    let subdir = dir.0.join("txn").join("a-directory");
    fs::create_dir(&subdir).unwrap_or_else(|e| panic!("{e}"));
    drop(open(&dir.0, 1_000_000));
    assert!(
        fs::symlink_metadata(&subdir)
            .unwrap_or_else(|e| panic!("{e}"))
            .file_type()
            .is_dir(),
        "a directory under txn/ must not be swept"
    );
}

/// The symlink's twin. A FIFO (or a socket, or a device node) at
/// `txn/<pid>-0` wedges `create_new` with `EEXIST` for that pid
/// exactly as a symlink does, and `unlink(2)` removes all of them —
/// so "a symlink and a regular file" was never the right line. The
/// line is DIRECTORY: that one entry is an anomaly rather than
/// staging and is deliberately left alone.
#[test]
fn writer_open_sweeps_a_fifo_at_a_staging_name_and_still_leaves_a_directory() {
    use std::os::unix::fs::FileTypeExt as _;

    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    let planted = dir.0.join("txn").join("12345-0");
    crate::fsguard::testutil::mkfifo(&planted);
    assert!(
        fs::symlink_metadata(&planted).is_ok_and(|meta| meta.file_type().is_fifo()),
        "control: the plant really is a FIFO, not a regular file"
    );
    let subdir = dir.0.join("txn").join("a-directory");
    fs::create_dir(&subdir).unwrap_or_else(|e| panic!("{e}"));

    drop(open(&dir.0, 1_000_000));

    assert!(
        fs::symlink_metadata(&planted).is_err(),
        "a FIFO at a staging name wedges create_new EEXIST for that pid forever and unlink \
         removes it; the sweep must clear the NAME"
    );
    assert!(
        fs::symlink_metadata(&subdir)
            .unwrap_or_else(|e| panic!("{e}"))
            .file_type()
            .is_dir(),
        "a directory under txn/ is the one plant the sweep leaves alone"
    );
}

/// An entry the sweep cannot remove must be skipped, never
/// propagated: one such name would otherwise fail every writer open
/// of this cache forever, where the entry on its own only wedges
/// the single staging name it occupies. Unlink permission comes
/// from the DIRECTORY, not the entry, so a `0o555` `txn/` is the
/// portable way to make one name un-sweepable while leaving it
/// readable — and it is also the shape where nothing at all can be
/// staged, which the open deliberately does not detect: a write
/// that cannot stage warns per write (see the sweep's own doc).
#[test]
fn a_txn_entry_that_cannot_be_unlinked_is_skipped_not_propagated() {
    use std::os::unix::fs::FileTypeExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    let txn = dir.0.join("txn");
    let planted = txn.join("12345-0");
    crate::fsguard::testutil::mkfifo(&planted);
    assert!(
        fs::symlink_metadata(&planted).is_ok_and(|meta| meta.file_type().is_fifo()),
        "control: the plant really is a FIFO, not a regular file"
    );
    fs::set_permissions(&txn, fs::Permissions::from_mode(0o555)).unwrap_or_else(|e| panic!("{e}"));

    let opened = open_with(&dir.0, 1_000_000, &origin());
    let restored = fs::set_permissions(&txn, fs::Permissions::from_mode(0o755));

    assert!(
        opened.is_ok(),
        "an entry the sweep cannot remove must be skipped, never propagated — one such \
         name would otherwise wedge every writer open of this cache forever: {:?}",
        opened.err()
    );
    restored.unwrap_or_else(|e| panic!("{e}"));
    assert!(
        fs::symlink_metadata(&planted).is_ok_and(|meta| meta.file_type().is_fifo()),
        "control: the plant really was un-sweepable — if it is gone this test proved \
         nothing about the skip"
    );
    drop(opened);
}

#[test]
fn a_degraded_opener_never_sweeps_txn() {
    let dir = ScratchDir::new();
    let _writer = open(&dir.0, 1_000_000); // holds the exclusive lock

    let leftover = dir.0.join("txn").join("67890-0");
    fs::write(&leftover, b"the live writer's own staging file").unwrap_or_else(|e| panic!("{e}"));

    let _degraded = open_with(&dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    assert!(leftover.exists(), "a degraded opener must never sweep txn/");
}

#[test]
fn an_oversized_root_file_is_a_miss() {
    let dir = ScratchDir::new();
    let cache = open(&dir.0, 1_000_000);
    let v = vol("root-conf-oversized");
    let leaf_dir = dir.0.join("roots").join(v.as_str());
    fs::create_dir_all(&leaf_dir).unwrap_or_else(|e| panic!("{e}"));
    let leaf = leaf_dir.join("00000000000000000001");
    let oversized = vec![0u8; usize::try_from(ROOT_MAX_BYTES).unwrap_or(usize::MAX) + 1];
    fs::write(&leaf, &oversized).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        cache.get_root_bytes(&v, 1),
        None,
        "a root over ROOT_MAX_BYTES is a miss before any content read"
    );
    // Read-side only: unlike an oversized OBJECT, an oversized
    // root is never unlinked — roots are never swept.
    assert!(
        leaf.exists(),
        "the oversized root file must NOT be unlinked"
    );
}

#[test]
fn a_whitespace_endpoint_url_is_refused_before_any_disk_touch() {
    let dir = ScratchDir::new();
    let bad = CacheOrigin {
        endpoint_url: "https://exa mple.invalid/".to_owned(),
        ..origin()
    };

    let err = Cache::open_with_free_space(&dir.0, 1_000_000, &bad, plenty())
        .expect_err("an endpoint_url with an embedded space must be refused");
    assert!(
        matches!(err, CacheError::Incompatible { .. }),
        "got {err:?}"
    );

    assert!(
        !dir.0.join("lock").exists(),
        "the grammar check must run before any disk touch"
    );
    assert!(!dir.0.join("objects").exists());
    assert!(!dir.0.join(MARKER_NAME).exists());
}

// ------------------------------------------- cold-rebuild edge rows

#[test]
fn ql_an_oversized_snapshot_triggers_the_cold_rebuild_walk() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establish the marker + directory layout

    // A sparse file: cheap (no real content written), but its
    // metadata().len() alone must already refuse it, before any
    // read is attempted.
    let snapshot_path = dir.0.join("index").join("snapshot");
    let f = File::create(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    f.set_len(INDEX_FILE_MAX_BYTES + 1)
        .unwrap_or_else(|e| panic!("{e}"));
    drop(f);

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert!(
        w.walk_reads.load(Ordering::Relaxed) > 0,
        "an over-cap snapshot must route through the cold rebuild walk before any read"
    );
}

#[test]
fn ql_an_oversized_journal_triggers_the_cold_rebuild_walk() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    // A journal that is FULLY decodable on its own (a clean EOF,
    // zero torn records — every record is a valid no-op touch of
    // an id nobody ever inserted) but exceeds INDEX_FILE_MAX_BYTES.
    // Without the cap this would replay clean (walk_reads == 0);
    // the cap alone must route it to the walk instead.
    let (absent_id, _) = id_of(99);
    let touch_count = (INDEX_FILE_MAX_BYTES / 37) + 100_000; // 37 B/touch record; comfortably over the cap
    let mut body = Vec::new();
    for _ in 0..touch_count {
        cacheindex::encode_record_into(&mut body, &Record::Touch { id: absent_id });
    }
    let mut full = Vec::new();
    full.extend_from_slice(&cacheindex::MAGIC);
    full.extend_from_slice(&cacheindex::VERSION.to_be_bytes());
    full.push(2); // journal kind
    full.extend_from_slice(&body);
    assert!(
        full.len() as u64 > INDEX_FILE_MAX_BYTES,
        "fixture must actually exceed the cap"
    );

    // Sanity: taken alone (no size cap applied), this journal IS
    // fully, cleanly decodable — the size cap is the ONLY thing
    // that can be routing this to the walk, not a decode failure.
    let (records, tail) = cacheindex::decode_journal(&full).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        records.len(),
        usize::try_from(touch_count).unwrap_or(usize::MAX)
    );
    assert_eq!(tail, JournalTail::CleanEof);

    fs::write(dir.0.join("index").join("journal"), &full).unwrap_or_else(|e| panic!("{e}"));

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert!(
        w.walk_reads.load(Ordering::Relaxed) > 0,
        "an over-cap journal must route through the cold rebuild walk, not a clean replay \
         (without the cap this would replay clean, walk_reads == 0)"
    );
}

#[test]
fn ql_a_reinserted_id_is_counted_once() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(100);
    cache.insert(&id, &bytes);
    let after_first = if let Mode::Writer(w) = &cache.mode {
        w.total_bytes
    } else {
        panic!("expected writer mode");
    };

    // The object file already exists, so a second `insert` of the
    // SAME id is the ordinary idempotent no-op — total_bytes must
    // not move at all, let alone double-count.
    cache.insert(&id, &bytes);
    if let Mode::Writer(w) = &cache.mode {
        assert_eq!(
            w.total_bytes, after_first,
            "a reinsert must count the id exactly once"
        );
        assert_eq!(w.live.len(), 1);
    } else {
        panic!("expected writer mode");
    }
}

#[test]
fn a_symlinked_object_path_is_a_miss() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new(); // outside the cache root entirely
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(90);

    let outside_file = outside.0.join("planted");
    fs::write(&outside_file, &bytes).unwrap_or_else(|e| panic!("{e}"));

    let path = object_path(&dir.0, &id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{e}"));
    }
    std::os::unix::fs::symlink(&outside_file, &path).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        cache.get(&id),
        None,
        "a symlink at an object path must be a miss, never a followed read"
    );
}

#[test]
fn get_refuses_an_object_fifo_swapped_in_after_lstat_without_blocking() {
    let dir = ScratchDir::new();
    let mut seeded = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(216);
    seeded.insert(&id, &bytes);
    assert_eq!(
        seeded.get(&id),
        Some(bytes),
        "positive control: the exact object path must be readable while it is regular"
    );
    seeded.close().unwrap_or_else(|e| panic!("{e}"));

    let path = object_path(&dir.0, &id);
    let hook_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired_by_hook = hook_fired.clone();
    let swapped_path = path.clone();
    let mut hooks = PATH_READ_POST_STAT_HOOKS
        .lock()
        .unwrap_or_else(|e| panic!("{e}"));
    hooks.push(PathReadPostStatHook {
        path,
        action: Box::new(move || {
            fs::remove_file(&swapped_path).unwrap_or_else(|e| panic!("{e}"));
            crate::fsguard::testutil::mkfifo(&swapped_path);
            fired_by_hook.store(true, Ordering::SeqCst);
        }),
    });
    drop(hooks);

    let cache_root = dir.0.clone();
    let result = crate::fsguard::testutil::within_deadline(
        "Cache::get after an object leaf is swapped to a FIFO",
        move || {
            let mut cache = open(&cache_root, 1_000_000);
            cache.get(&id)
        },
    );

    assert!(
        hook_fired.load(Ordering::SeqCst),
        "control: the regular object must have been replaced immediately before its open"
    );
    assert_eq!(result, None, "a FIFO object must remain a cache miss");
}

/// A foreign entry at an object leaf is replaced by the write
/// itself. `atomic_write`'s final `rename` replaces a non-directory
/// `dest` atomically and never follows it — POSIX `rename(2)`
/// replaces the LINK, not its target — so no separate deletion
/// primitive is needed and none exists. The classification's job at
/// this arm is to say so in a `warn!` before the write runs. The
/// fanout here is a REAL directory, so it is the LEAF decision
/// under test and not the fanout guard.
#[test]
fn insert_replaces_a_foreign_object_leaf_through_the_atomic_rename() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(214);
    let victim = outside.0.join("victim");
    let victim_bytes = b"outside bytes must remain unchanged".to_vec();
    fs::write(&victim, &victim_bytes).unwrap_or_else(|e| panic!("{e}"));

    let path = object_path(&dir.0, &id);
    let parent = path
        .parent()
        .unwrap_or_else(|| panic!("an object path always has a fanout parent"))
        .to_path_buf();
    fs::create_dir_all(&parent).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim, &path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.get(&id),
        None,
        "control: the planted symlink must be a cache miss before insert"
    );
    assert!(
        fs::symlink_metadata(&parent).is_ok_and(|meta| meta.is_dir()),
        "control: the fanout is a real directory, so the leaf is what is under test"
    );

    cache.insert(&id, &bytes);

    assert!(
        fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file()),
        "the rename must replace the planted link — declining leaves the object \
         uncacheable forever, since nothing else clears the name"
    );
    assert_eq!(
        fs::read(&victim).unwrap_or_else(|e| panic!("{e}")),
        victim_bytes,
        "and the link's TARGET is untouched: rename replaces the link, never what it \
         points at"
    );
    assert_eq!(
        cache.get(&id),
        Some(bytes.clone()),
        "the object is cached, so the next read is a hit rather than another origin fetch"
    );
}

/// A DIRECTORY at the object leaf is the one foreign shape the
/// write cannot replace: `rename(2)` refuses a directory `dest`
/// (`EISDIR`/`ENOTEMPTY`), and no unlink can clear one either. So
/// the classification declines IMMEDIATELY, before the quota check
/// and before eviction — a call that can never write must not have
/// deleted other objects to make room it will never use.
#[test]
fn insert_declines_a_directory_at_the_object_leaf_before_evicting_anything() {
    let dir = ScratchDir::new();
    let picks = ids_in_distinct_fanouts(&dir.0, 2);
    let pick = |i: usize| {
        picks
            .get(i)
            .cloned()
            .unwrap_or_else(|| panic!("pick {i} is present by construction"))
    };
    let (lru_id, lru_bytes, _) = pick(0);
    let (blocked_id, blocked_bytes, _) = pick(1);
    let object_len = lru_bytes.len() as u64;

    // Room for exactly one object, so an insert that reaches the
    // eviction loop takes the one already there.
    let mut cache = open(&dir.0, object_len);
    cache.insert(&lru_id, &lru_bytes);
    assert_eq!(
        cache.get(&lru_id),
        Some(lru_bytes.clone()),
        "control: the cache really holds the object the decline must not cost"
    );

    let path = object_path(&dir.0, &blocked_id);
    fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    let inside = path.join("someone-elses-file");
    fs::write(&inside, b"must survive").unwrap_or_else(|e| panic!("{e}"));

    cache.insert(&blocked_id, &blocked_bytes);

    assert_eq!(
        cache.get(&lru_id),
        Some(lru_bytes),
        "an insert that can never write must decline BEFORE eviction: evicting first \
         spends the cache's contents on a write that never happens"
    );
    assert!(
        fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()),
        "a leaf no write can replace must be left exactly where it is"
    );
    assert_eq!(
        fs::read(&inside).unwrap_or_else(|e| panic!("{e}")),
        b"must survive".to_vec(),
        "and nothing under it may have been touched"
    );
    assert_eq!(cache.get(&blocked_id), None, "the object stays uncached");
}

/// The count and the charged bytes the writer index currently
/// holds — the pair an eviction moves and a decline must not.
fn writer_totals(cache: &Cache) -> (usize, u64) {
    let Mode::Writer(w) = &cache.mode else {
        panic!("expected writer mode");
    };
    (w.live.len(), w.total_bytes)
}

/// **A write that cannot even be STAGED must evict nothing.**
///
/// Staging BEFORE the eviction is what keeps a cache that cannot
/// write merely non-caching rather than DRAINING: an insert that
/// evicted first would spend the cache's contents on a write that
/// can never land, and each repeat would spend more, down to the
/// room the largest attempted insert needs.
///
/// **The plant is a NON-DIRECTORY at `txn/`, not a `0o555` `txn/`.**
/// A `0o555` `txn/` is the shape an operator actually meets — the
/// one `sweep_orphaned_txn_files`' own doc names, where every
/// staging `create_new` fails and the open deliberately does not
/// detect it — but it is not a refusal a TEST can rely on: a process
/// running as root, or a filesystem that ignores mode bits, writes
/// into it anyway, and the row would then go green having asserted
/// nothing. A regular file at the `txn` name makes staging's
/// `create_new` fail `ENOTDIR` for every uid on every filesystem, so
/// this regression is refused deterministically or not at all.
#[test]
fn an_insert_that_cannot_stage_evicts_nothing() {
    let dir = ScratchDir::new();
    let picks = ids_in_distinct_fanouts(&dir.0, 2);
    let pick = |i: usize| {
        picks
            .get(i)
            .cloned()
            .unwrap_or_else(|| panic!("pick {i} is present by construction"))
    };
    let (lru_id, lru_bytes, _) = pick(0);
    let (new_id, new_bytes, _) = pick(1);
    let object_len = lru_bytes.len() as u64;

    // Room for exactly one object, so the second insert must reach
    // the eviction loop and take the one already there.
    let mut cache = open(&dir.0, object_len);
    cache.insert(&lru_id, &lru_bytes);
    assert_eq!(
        cache.get(&lru_id),
        Some(lru_bytes.clone()),
        "control: the cache really holds the object the decline must not cost"
    );

    // The cache is already open and holds its lock, so nothing
    // re-sweeps or re-creates `txn/` behind this: the plant stands
    // for the rest of the row.
    let txn = dir.0.join("txn");
    fs::remove_dir_all(&txn).unwrap_or_else(|e| panic!("{e}"));
    fs::write(&txn, b"a regular file where txn/ would be").unwrap_or_else(|e| panic!("{e}"));
    assert!(
        fs::symlink_metadata(&txn).is_ok_and(|m| m.file_type().is_file()),
        "control: the plant must really be a non-directory, or nothing below refuses"
    );
    // And the refusal itself, measured rather than assumed: no uid
    // and no filesystem lets a name be created UNDER a regular file.
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(txn.join("stageability-probe"))
            .is_err(),
        "control: staging under the plant must be impossible, or the row asserts nothing"
    );

    let before = writer_totals(&cache);

    cache.insert(&new_id, &new_bytes);

    assert_eq!(
        writer_totals(&cache),
        before,
        "an insert that cannot stage must leave the index exactly as it found it — \
         both the object count and the charged bytes"
    );
    assert_eq!(
        cache.get(&lru_id),
        Some(lru_bytes),
        "and the LRU object itself must still be on disk and readable"
    );
    assert_eq!(cache.get(&new_id), None, "while nothing new was cached");
}

/// **A non-directory at `objects/<2hex>` is FOREIGN, and both paths
/// say so.** The cache creates nothing but a directory at an object
/// fanout, so a regular file (or a FIFO, or a socket) there belongs
/// to something else and no object of this cache can exist beneath
/// it — the same conclusion `store::refuse_foreign_object_fanout`
/// reaches, now reached here too.
///
/// The failure this closes is SILENCE, not unsafety. A read under
/// such a fanout fails `ENOTDIR` inside `open_regular_read`; treated
/// as an ordinary miss, every object in that fanout would be
/// permanently uncacheable and permanently un-servable with nothing
/// in the log to say why — an operator sees a cache that is simply
/// never warm. Both the read and the write must NAME it.
#[test]
fn a_non_directory_object_fanout_is_foreign_to_both_the_read_and_the_write() {
    #[derive(Clone, Default)]
    struct WarnCounter(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCounter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = ScratchDir::new();
    let picks = ids_in_distinct_fanouts(&dir.0, 2);
    let pick = |i: usize| {
        picks
            .get(i)
            .cloned()
            .unwrap_or_else(|| panic!("pick {i} is present by construction"))
    };
    let (lru_id, lru_bytes, _) = pick(0);
    let (blocked_id, blocked_bytes, blocked_fanout) = pick(1);
    let object_len = lru_bytes.len() as u64;

    // Room for exactly one object, so an insert that got past the
    // guard would reach the eviction loop and take the one already
    // there — which is what the untouched totals below refute.
    let mut cache = open(&dir.0, object_len);
    cache.insert(&lru_id, &lru_bytes);
    assert_eq!(
        cache.get(&lru_id),
        Some(lru_bytes.clone()),
        "control: the cache really holds the object the refusal must not cost"
    );

    let planted = b"a regular file where a fanout directory would be".to_vec();
    fs::write(&blocked_fanout, &planted).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        fs::symlink_metadata(&blocked_fanout).is_ok_and(|m| m.file_type().is_file()),
        "control: the plant is a REGULAR FILE, not the symlink the other rows use"
    );

    let before = writer_totals(&cache);
    let counter = WarnCounter::default();
    let subscriber = tracing_subscriber::registry().with(counter.clone());
    let served = tracing::subscriber::with_default(subscriber, || {
        let served = cache.get(&blocked_id);
        cache.insert(&blocked_id, &blocked_bytes);
        served
    });

    assert_eq!(served, None, "a foreign fanout can never serve a hit");
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        2,
        "the READ and the WRITE must each say the fanout is foreign — one warning means \
         the read is still a silent miss, which is the whole defect"
    );
    assert_eq!(
        writer_totals(&cache),
        before,
        "and the refused insert evicts nothing: the guard runs before the staging and \
         before the eviction loop"
    );
    assert_eq!(
        cache.get(&lru_id),
        Some(lru_bytes),
        "the object that was already cached is still there"
    );
    assert_eq!(
        fs::read(&blocked_fanout).unwrap_or_else(|e| panic!("{e}")),
        planted,
        "and the planted file itself is untouched — nothing here removes or replaces it"
    );
}

/// The fanout guard runs BEFORE the leaf is stat'ed or touched at
/// all. With `objects/<2hex>` pre-planted as a link to an outside
/// directory, a leaf-first `insert` would classify — and then let
/// its atomic rename REPLACE — `<outside>/<64hex>`, a path in
/// someone else's tree that the cache never created.
#[test]
fn insert_refuses_a_symlinked_fanout_before_it_touches_the_leaf() {
    use std::os::unix::fs::FileTypeExt as _;

    let dir = ScratchDir::new();
    let outside = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(219);
    let path = object_path(&dir.0, &id);
    let fanout = path
        .parent()
        .unwrap_or_else(|| panic!("an object path always has a fanout parent"))
        .to_path_buf();
    let objects = fanout
        .parent()
        .unwrap_or_else(|| panic!("a fanout always has an objects/ parent"))
        .to_path_buf();
    fs::create_dir_all(&objects).unwrap_or_else(|e| panic!("{e}"));

    // Named exactly as the object would be, so a leaf-first insert
    // reaches it: a FIFO, which is not a regular file, so a
    // leaf-first classification would call it foreign and let the
    // write replace the name.
    let escaped = outside.0.join(id.digest_hex());
    crate::fsguard::testutil::mkfifo(&escaped);
    std::os::unix::fs::symlink(&outside.0, &fanout).unwrap_or_else(|e| panic!("{e}"));

    cache.insert(&id, &bytes);

    assert!(
        fs::symlink_metadata(&escaped).is_ok_and(|meta| meta.file_type().is_fifo()),
        "insert must not classify or replace what the fanout symlink resolves to"
    );
    assert!(
        fs::symlink_metadata(&fanout).is_ok_and(|meta| meta.file_type().is_symlink()),
        "the refusal leaves the planted fanout symlink in place"
    );
    assert_eq!(cache.get(&id), None, "and nothing was cached");
}

#[test]
fn insert_refuses_a_symlinked_second_level_object_fanout() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(215);
    let path = object_path(&dir.0, &id);
    let fanout = path
        .parent()
        .unwrap_or_else(|| panic!("an object path must have a fanout parent"));

    cache.insert(&id, &bytes);
    assert_eq!(
        cache.get(&id),
        Some(bytes.clone()),
        "positive control: this cache and object fanout must accept an ordinary insert"
    );
    fs::remove_file(&path).unwrap_or_else(|e| panic!("{e}"));
    fs::remove_dir(fanout).unwrap_or_else(|e| panic!("{e}"));

    std::os::unix::fs::symlink(&outside.0, fanout).unwrap_or_else(|e| panic!("{e}"));
    let escaped = outside.0.join(id.digest_hex());
    cache.insert(&id, &bytes);

    assert!(
        !escaped.exists(),
        "cache insert must refuse the second-level fanout symlink rather than rename the \
         object through it"
    );
    assert!(
        fs::symlink_metadata(fanout).is_ok_and(|meta| meta.file_type().is_symlink()),
        "the refusal must leave the planted fanout symlink in place"
    );
}

/// A STATIC fanout swap plus this cache's own valid index is enough
/// to make quota eviction delete another content-addressed tree's
/// object. `remove_file` never follows its FINAL component, but it
/// does follow `objects/<2hex>` when that component is a symlink, and
/// content addressing puts the same bytes at the same relative path
/// in every CAS — so the index cache A wrote for itself already names
/// a file that exists over in B. Nothing races: the swap is on disk
/// before A is reopened.
#[test]
fn eviction_does_not_unlink_an_object_through_a_symlinked_fanout() {
    let a = ScratchDir::new();
    let b = ScratchDir::new();
    let (id, bytes) = id_of(217);
    let (other_id, other_bytes) = id_of(218);
    let object_len = bytes.len() as u64;

    let a_object = object_path(&a.0, &id);
    let b_object = object_path(&b.0, &id);
    let fanout_of = |p: &Path| {
        p.parent()
            .unwrap_or_else(|| panic!("an object path always has a fanout parent"))
            .to_path_buf()
    };
    let a_fanout = fanout_of(&a_object);
    let b_fanout = fanout_of(&b_object);
    assert_ne!(
        a_fanout,
        fanout_of(&object_path(&a.0, &other_id)),
        "control: the evicting insert must land in a DIFFERENT fanout, so its own \
         fanout creation cannot be what repairs or replaces the swapped one"
    );

    // The victim: a second CAS holding the same content id.
    let mut cache_b = open(&b.0, 1_000_000);
    cache_b.insert(&id, &bytes);
    assert_eq!(
        cache_b.get(&id),
        Some(bytes.clone()),
        "control: cache B must really hold the object"
    );
    cache_b.close().unwrap_or_else(|e| panic!("{e}"));

    // Cache A writes the same object, so the index it persists names
    // it — a valid index, written by the cache itself.
    let mut cache_a = open(&a.0, 1_000_000);
    cache_a.insert(&id, &bytes);
    assert_eq!(
        cache_a.get(&id),
        Some(bytes.clone()),
        "control: cache A must really hold the object"
    );
    cache_a.close().unwrap_or_else(|e| panic!("{e}"));

    // The swap: A's fanout DIRECTORY becomes a link into B's.
    fs::remove_file(&a_object).unwrap_or_else(|e| panic!("{e}"));
    fs::remove_dir(&a_fanout).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&b_fanout, &a_fanout).unwrap_or_else(|e| panic!("{e}"));

    // Reopened under a quota that makes the very next insert evict.
    let mut cache_a = open(&a.0, object_len);
    cache_a.insert(&other_id, &other_bytes);

    assert!(
        b_object.exists(),
        "quota eviction must not unlink another cache's object through a symlinked \
         fanout directory"
    );
    assert_eq!(
        fs::read(&b_object).unwrap_or_else(|e| panic!("{e}")),
        bytes,
        "the victim object must be byte-for-byte intact"
    );
    assert!(
        fs::symlink_metadata(&a_fanout).is_ok_and(|m| m.file_type().is_symlink()),
        "the refusal leaves the planted fanout symlink in place; nothing repairs it"
    );
}

/// A fanout the eviction cannot ACT on: `objects/<2hex>` replaced by
/// a regular FILE, so every unlink beneath it fails `ENOTDIR`. The
/// entry is dropped and refunded exactly as a successful eviction
/// would, and NOTHING on disk is touched — the planted entry is
/// left where it is, because this cache reports and does not
/// repair. The residue is the object still sitting under a prefix
/// `gran verify` cannot even enumerate.
#[test]
fn eviction_drops_an_entry_whose_fanout_it_cannot_classify_without_touching_the_disk() {
    let dir = ScratchDir::new();
    let (id, bytes) = id_of(220);
    let (other_id, other_bytes) = id_of(221);
    let object_len = bytes.len() as u64;
    let other_len = other_bytes.len() as u64;
    let object = object_path(&dir.0, &id);
    let fanout = object
        .parent()
        .unwrap_or_else(|| panic!("an object path always has a fanout parent"))
        .to_path_buf();
    assert_ne!(
        fanout,
        object_path(&dir.0, &other_id)
            .parent()
            .unwrap_or_else(|| panic!("an object path always has a fanout parent"))
            .to_path_buf(),
        "control: the evicting insert must land in a DIFFERENT fanout, so its own fanout \
         creation cannot be what repairs the planted one"
    );

    let mut cache = open(&dir.0, 1_000_000);
    cache.insert(&id, &bytes);
    assert_eq!(
        cache.get(&id),
        Some(bytes.clone()),
        "control: the cache must really hold the object the index names"
    );
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    // A regular FILE where the fanout directory was: not a symlink,
    // so the symlink guard says nothing about it, and every path
    // operation beneath it fails ENOTDIR.
    fs::remove_file(&object).unwrap_or_else(|e| panic!("{e}"));
    fs::remove_dir(&fanout).unwrap_or_else(|e| panic!("{e}"));
    fs::write(&fanout, b"not a directory").unwrap_or_else(|e| panic!("{e}"));

    // Reopened under a quota that makes the very next insert evict.
    let mut cache = open(&dir.0, object_len);
    cache.insert(&other_id, &other_bytes);

    if let Mode::Writer(w) = &cache.mode {
        assert!(
            !w.live.contains_key(&id),
            "the entry goes: an eviction that stops on a fanout it cannot classify stops \
             there on every later call too, because that entry is by_seq's head every time"
        );
        assert_eq!(
            w.total_bytes, other_len,
            "its bytes are refunded with it, and what is charged is the object just \
             written"
        );
        assert!(
            w.live.contains_key(&other_id),
            "so the insert that needed the room SUCCEEDS"
        );
    } else {
        panic!("expected writer mode");
    }
    assert_eq!(
        fs::read(&fanout).unwrap_or_else(|e| panic!("{e}")),
        b"not a directory".to_vec(),
        "and the planted entry is untouched — the cache reports, it does not repair"
    );
    assert_eq!(
        cache.get(&other_id),
        Some(other_bytes),
        "the object really was cached, not just indexed"
    );
}

/// A foreign leaf is replaced by `atomic_write`'s final rename and
/// by nothing else, so an insert that never reaches that rename
/// must leave the name exactly as it found it. An object larger
/// than the whole quota can never be cached — the size gate
/// declines above the write — so both the planted name and the
/// cache's existing contents survive an insert that has no
/// successful outcome at all.
#[test]
fn an_insert_declined_for_size_never_reaches_the_rename_that_replaces_the_leaf() {
    let dir = ScratchDir::new();
    let (small_id, small_bytes) = id_of(80);
    let quota = small_bytes.len() as u64;
    let huge_bytes = vec![9u8; small_bytes.len() * 2];
    let huge_id = GrainId::of(&huge_bytes);
    assert!(
        huge_bytes.len() as u64 > quota,
        "control: the object must be larger than the whole quota"
    );

    let victim = dir.0.join("victim");
    fs::write(&victim, b"the planted link's target").unwrap_or_else(|e| panic!("{e}"));
    let dest = object_path(&dir.0, &huge_id);
    let fanout = dest
        .parent()
        .unwrap_or_else(|| panic!("an object path always has a fanout parent"));
    fs::create_dir_all(fanout).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim, &dest).unwrap_or_else(|e| panic!("{e}"));

    let mut cache = open(&dir.0, quota);
    cache.insert(&small_id, &small_bytes);
    cache.insert(&huge_id, &huge_bytes);

    assert!(
        fs::symlink_metadata(&dest).is_ok_and(|m| m.file_type().is_symlink()),
        "an insert that can never succeed must not have reached the rename that replaces \
         the name"
    );
    assert_eq!(
        fs::read(&victim).unwrap_or_else(|e| panic!("{e}")),
        b"the planted link's target".to_vec(),
        "control: nothing followed the planted link either way"
    );
    assert_eq!(
        cache.get(&small_id),
        Some(small_bytes),
        "control: the unfittable insert must not have flushed the cache to make room it \
         can never use"
    );
}

/// The root twin: `put_root_bytes` replaces a foreign leaf only
/// through `atomic_write`'s rename, which sits BELOW the watermark
/// — so a write the watermark refuses has changed nothing at the
/// name.
#[test]
fn a_root_write_refused_by_the_watermark_never_reaches_the_rename_that_replaces_the_leaf() {
    let dir = ScratchDir::new();
    let v = vol("root-replace-order");
    let bytes = b"a verified root document".to_vec();

    let victim = dir.0.join("victim");
    fs::write(&victim, b"the planted link's target").unwrap_or_else(|e| panic!("{e}"));
    let dest = root_bytes_path(&dir.0, &v, 7);
    let volume_dir = dest
        .parent()
        .unwrap_or_else(|| panic!("a root path always has a volume parent"));
    fs::create_dir_all(volume_dir).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim, &dest).unwrap_or_else(|e| panic!("{e}"));

    // Free space sitting exactly ON the watermark: any write at all
    // is refused.
    let capacity_bytes = 40 * WATERMARK_MIN_BYTES;
    let seam = FixedFreeSpace(FreeSpaceInfo {
        free_bytes: watermark_bytes(capacity_bytes),
        capacity_bytes,
    });
    let mut cache = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(seam))
        .unwrap_or_else(|e| panic!("{e}"));
    if let Mode::Writer(w) = &cache.mode {
        assert!(
            !free_space_precheck(w.free_space.as_ref(), bytes.len() as u64),
            "control: the watermark must really refuse this write"
        );
    } else {
        panic!("expected writer mode");
    }

    cache.put_root_bytes(&v, 7, &bytes);

    assert!(
        fs::symlink_metadata(&dest).is_ok_and(|m| m.file_type().is_symlink()),
        "a root write the watermark refuses must not have reached the rename that \
         replaces the name"
    );
    assert_eq!(
        fs::read(&victim).unwrap_or_else(|e| panic!("{e}")),
        b"the planted link's target".to_vec(),
        "control: nothing followed the planted link either way"
    );
}

/// An object the cache cannot unlink must not be able to decline
/// anything. Eviction takes `by_seq`'s head, attempts the unlink,
/// and drops the entry — refunding its bytes — whatever the unlink
/// did, so the pressured insert always makes progress. A failed
/// unlink leaves a RESIDUE: a file on disk that no index entry
/// names, which `gran verify` reports as `adopted` and which makes
/// the accounting an under-count until it is cleared. That costs
/// disk, not the cache's ability to insert; keeping the entry
/// instead costs every later insert, because that same object is
/// the head every time.
#[test]
fn eviction_drops_the_entry_for_an_object_it_cannot_unlink_and_leaves_a_residue() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = ScratchDir::new();
    let picks = ids_in_distinct_fanouts(&dir.0, 3);
    let pick = |i: usize| {
        picks
            .get(i)
            .cloned()
            .unwrap_or_else(|| panic!("pick {i} is present by construction"))
    };
    let (residue_id, residue_bytes, residue_fanout) = pick(0);
    let (evictable_id, evictable_bytes, _) = pick(1);
    let (fresh_id, fresh_bytes, _) = pick(2);
    let object_len = residue_bytes.len() as u64;
    let residue_object = object_path(&dir.0, &residue_id);

    // Room for exactly two objects, so the third insert has to evict.
    let mut cache = open(&dir.0, object_len * 2);
    cache.insert(&residue_id, &residue_bytes);
    cache.insert(&evictable_id, &evictable_bytes);
    assert!(
        residue_object.exists(),
        "control: the object that is about to become un-unlinkable is really cached"
    );

    // Unlink needs write permission on the DIRECTORY, not on the
    // entry, so this makes exactly one object permanently
    // un-unlinkable while leaving it readable.
    fs::set_permissions(&residue_fanout, fs::Permissions::from_mode(0o555))
        .unwrap_or_else(|e| panic!("{e}"));
    cache.insert(&fresh_id, &fresh_bytes);
    let restored = fs::set_permissions(&residue_fanout, fs::Permissions::from_mode(0o755));

    if let Mode::Writer(w) = &cache.mode {
        assert!(
            !w.live.contains_key(&residue_id),
            "the entry goes whatever the unlink did: an eviction one un-unlinkable object \
             can stop declines every later insert too, since that object is by_seq's head \
             every time"
        );
        assert_eq!(
            w.total_bytes,
            object_len * 2,
            "and its bytes go with it — total_bytes is the sum of live's sizes, so an \
             entry dropped without its refund makes that untrue"
        );
        assert!(
            w.live.contains_key(&fresh_id),
            "so the quota-pressured insert SUCCEEDS"
        );
        assert!(
            w.live.contains_key(&evictable_id),
            "and only the head was taken: the loop stops as soon as the write fits"
        );
    } else {
        panic!("expected writer mode");
    }
    restored.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        fs::read(&residue_object).unwrap_or_else(|e| panic!("{e}")),
        residue_bytes,
        "the residue: the file is still on disk and byte-identical, named by no index \
         entry — gran verify reports it as adopted, and the accounting under-counts the \
         cache until it is cleared"
    );
}

#[test]
fn ql_oversized_file_that_hashes_to_its_id_is_refused_before_read() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000_000);
    let bytes = vec![0u8; usize::try_from(META_MAX_BYTES).unwrap_or(usize::MAX) + 1];
    let id = GrainId::of(&bytes); // the id genuinely matches these bytes
    let path = object_path(&dir.0, &id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{e}"));
    }
    fs::write(&path, &bytes).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        cache.get(&id),
        None,
        "a file over META_MAX_BYTES is refused by the SIZE gate alone — its bytes genuinely \
         hash to the claimed id, so only the size check (never a hash mismatch) can be \
         refusing it here"
    );
    assert!(!path.exists(), "the writer must unlink the oversized file");
}

struct ErringFreeSpace;
impl FreeSpace for ErringFreeSpace {
    fn free_space(&self) -> io::Result<FreeSpaceInfo> {
        Err(io::Error::other("simulated free-space query failure"))
    }
}

#[test]
fn ql_free_space_query_error_is_fail_safe() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(ErringFreeSpace))
            .unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = id_of(91);

    cache.insert(&id, &bytes);

    assert_eq!(
        cache.get(&id),
        None,
        "a free-space query failure must refuse the write, never assume there is room"
    );
}

#[test]
fn ql_a_write_after_a_torn_tail_survives_the_next_reopen() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id1, b1) = id_of(92);
    cache.insert(&id1, &b1);
    force_flush(&mut cache);
    drop(cache); // leave the guard present

    // Tear the ONLY record's check byte — the trusted prefix is
    // then empty, so the next writer open must TRUNCATE the
    // physical file down to the envelope before appending anything
    // new (the "ignored TruncateTo" mutant would append after the
    // garbage instead, silently losing every later write on the
    // NEXT reopen).
    let journal_path = dir.0.join("index").join("journal");
    let mut bytes = fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    let insert_record_len = 1 + DIGEST_LEN + 4 + 4;
    let record_end = cacheindex::ENVELOPE_LEN + insert_record_len;
    if let Some(b) = bytes.get_mut(record_end - 1) {
        *b ^= 0xFF;
    }
    fs::write(&journal_path, &bytes).unwrap_or_else(|e| panic!("{e}"));

    let mut reopened = open(&dir.0, 1_000_000);
    let (id2, b2) = id_of(93);
    reopened.insert(&id2, &b2);
    reopened.close().unwrap_or_else(|e| panic!("{e}"));

    let third = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &third.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.walk_reads.load(Ordering::Relaxed),
        0,
        "no walk should have been needed"
    );
    assert!(
        w.live.contains_key(&id2),
        "the write made AFTER the torn tail must survive the reopen AFTER that — proving \
         the truncation actually happened rather than appending past the garbage"
    );
}

#[test]
fn a_failed_journal_write_rolls_back_its_partial_record() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id1, bytes1) = id_of(212);
    let (id2, bytes2) = id_of(213);
    cache.insert(&id1, &bytes1);
    cache.insert(&id2, &bytes2);

    let journal_path = dir.0.join("index").join("journal");
    let Mode::Writer(w) = &mut cache.mode else {
        panic!("expected writer mode");
    };
    let known_good_len = w.journal_len;
    let buffered_len = w.journal_buf.len();
    let partial_len = 5;
    assert!(
        partial_len < buffered_len,
        "control: the injected write must be a strict, non-empty prefix"
    );
    w.journal_write_fail_after = Some(partial_len);
    let result = w.flush_journal_buffer();
    assert!(result.is_err(), "control: the injected write must fail");
    assert_eq!(
        w.journal_buf.len(),
        buffered_len,
        "a failed flush must keep the complete records buffered for retry"
    );
    assert_eq!(
        w.journal_len, known_good_len,
        "failed bytes must never advance the trusted journal length"
    );
    assert_eq!(
        fs::metadata(&journal_path)
            .unwrap_or_else(|e| panic!("{e}"))
            .len(),
        known_good_len,
        "the physical journal must be truncated back to its last-known-good length"
    );

    w.flush_journal_buffer().unwrap_or_else(|e| panic!("{e}"));
    drop(cache);

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert!(
        w.live.contains_key(&id1) && w.live.contains_key(&id2),
        "control: after the successful retry and reopen, every buffered record must replay"
    );
}

#[test]
fn ql_a_read_promotes_recency_so_the_true_lru_is_evicted() {
    let dir = ScratchDir::new();
    let (a_id, a_bytes) = id_of(94);
    let (b_id, b_bytes) = id_of(95);
    let (c_id, c_bytes) = id_of(96);
    let (d_id, d_bytes) = id_of(97);
    let object_len = a_bytes.len() as u64;
    let mut cache = open(&dir.0, object_len * 3);

    cache.insert(&a_id, &a_bytes);
    cache.insert(&b_id, &b_bytes);
    cache.insert(&c_id, &c_bytes);
    assert_eq!(cache.get(&a_id), Some(a_bytes.clone())); // promotes A to most-recent
    cache.insert(&d_id, &d_bytes); // must evict B (now the true LRU), never A

    assert_eq!(
        cache.get(&a_id),
        Some(a_bytes),
        "A was just read; it must survive"
    );
    assert_eq!(
        cache.get(&b_id),
        None,
        "B is now the true LRU and must be evicted"
    );
    assert_eq!(cache.get(&c_id), Some(c_bytes));
    assert_eq!(cache.get(&d_id), Some(d_bytes));
}

/// **What this pins, precisely: the state AFTER `close`**, with enough
/// touches to have crossed `JOURNAL_COMPACT_RECORDS` before `close`
/// ever runs. It does NOT, on its own, distinguish "inline
/// compaction fired mid-session" from "nothing fired until `close`'s
/// own `maybe_compact` did" — `close` calls `maybe_compact` too, so the
/// post-close journal is envelope-only either way, and a version of
/// this test that deleted the inline call entirely would still
/// pass it. The mid-session property — that touches ALONE
/// compact the journal before `close` ever runs — is pinned separately,
/// by `touches_alone_compact_the_journal_before_close_ever_runs` below,
/// which asserts mid-session and ends in `abandon()` so no close can
/// run at all.
#[test]
fn ql_many_touches_trigger_compaction() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(98);
    cache.insert(&id, &bytes); // record 1 of the journal

    // 1 (the insert above) + 65_536 touches = 65_537 total records,
    // crossing JOURNAL_COMPACT_RECORDS (65_536) on the LAST touch.
    for _ in 0..65_536u32 {
        assert_eq!(cache.get(&id), Some(bytes.clone()));
    }

    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let journal_bytes =
        fs::read(dir.0.join("index").join("journal")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        journal_bytes.len(),
        cacheindex::ENVELOPE_LEN,
        "compaction must reset the journal to envelope-only"
    );

    let snapshot_bytes =
        fs::read(dir.0.join("index").join("snapshot")).unwrap_or_else(|e| panic!("{e}"));
    let entries = cacheindex::decode_snapshot(&snapshot_bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        entries,
        vec![(id, u32::try_from(bytes.len()).unwrap_or(u32::MAX))]
    );

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.walk_reads.load(Ordering::Relaxed),
        0,
        "a clean compacted state must replay without walking"
    );
    assert!(w.live.contains_key(&id));
}

/// The inline compaction requirement
/// — a long-lived, read-mostly mount compacts its own journal
/// without ever calling `close` — had NO test that could tell it
/// apart from `close`'s own `maybe_compact`:
/// `ql_many_touches_trigger_compaction` above always calls `close`
/// before it looks at the journal, so mutant M1 (delete the
/// `maybe_compact` call inside `append_journal_record`) and mutant
/// M10 (make compaction fire only for `Record::Insert`, so `Touch`
/// — the dominant driver for a read-only mount — no longer triggers
/// it) both pass every existing test in this suite; `close`'s own
/// compaction papers over either deletion identically. This test
/// observes the journal MID-SESSION, with NOTHING closed, so only
/// the inline trigger inside `append_journal_record` (reached here
/// through `touch_id`) can be responsible for what it sees; it ends
/// in `abandon()` rather than `close()` so no close can run at all,
/// at any point, including via `Drop`.
#[test]
fn touches_alone_compact_the_journal_before_close_ever_runs() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(98);
    cache.insert(&id, &bytes);
    for _ in 0..65_536u32 {
        assert_eq!(cache.get(&id), Some(bytes.clone()));
    }
    // NOTHING has closed this cache. The trigger under test is the
    // one inside `append_journal_record`, reached from `touch_id`.
    let journal_len = fs::metadata(dir.0.join("index").join("journal"))
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert_eq!(
        journal_len,
        cacheindex::ENVELOPE_LEN as u64,
        "touches alone must compact the journal mid-session, with no close()"
    );
    let Mode::Writer(w) = &cache.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.journal_total_records, 0,
        "the inline compaction must have reset the record counter mid-session"
    );
    cache.abandon();
}

// --------------------------------------------------- Cache::maintain

/// A durable, on-disk cache whose journal already holds more than
/// `JOURNAL_COMPACT_RECORDS` records for ONE real, hash-verifiable
/// object — built by a real `insert()` (one durable object, one
/// `Insert` record), then extended by appending many valid `Touch`
/// records for that SAME id directly to the on-disk journal file.
///
/// This is deliberately NOT built by calling `insert`/`get` enough
/// times to cross the threshold live: the inline-trigger step makes
/// `append_journal_record` itself compact inline the instant a LIVE
/// call crosses the threshold (see `ql_many_touches_trigger_compaction`
/// above), so a live session can never be observed sitting over
/// threshold with nothing having compacted it yet. Appending the extra
/// records straight to the file reaches that state the ONLY other way
/// it arises in practice: `load_index`'s replay on `open` sets
/// `journal_total_records` directly from the decoded count, never
/// through `append_journal_record` — matching a mount that reopens an
/// old, already-oversized journal (say, one whose earlier compaction
/// was declined by a free-space refusal that has since cleared) and has
/// not yet served a single request.
fn seed_cache_over_the_compaction_threshold(dir: &Path) -> (GrainId, Vec<u8>) {
    let (id, bytes) = id_of(77);
    let mut seed = open(dir, 1_000_000);
    seed.insert(&id, &bytes); // one durable object + one Insert record
    seed.close().unwrap_or_else(|e| panic!("{e}"));

    let journal_path = dir.join("index").join("journal");
    let mut journal_bytes = fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    // 1 (the insert above) + JOURNAL_COMPACT_RECORDS touches = one
    // more than the threshold, every one a valid, replayable touch
    // of a LIVE id.
    for _ in 0..JOURNAL_COMPACT_RECORDS {
        cacheindex::encode_record_into(&mut journal_bytes, &Record::Touch { id });
    }
    assert!(
        journal_bytes.len() as u64 <= INDEX_FILE_MAX_BYTES,
        "control: the fixture must stay under the cold-rebuild-walk cap, or this would be \
         testing the walk instead of compaction"
    );
    fs::write(&journal_path, &journal_bytes).unwrap_or_else(|e| panic!("{e}"));
    (id, bytes)
}

/// Both the call and the no-call control. A fresh session opened onto an
/// already-over-threshold journal (see the fixture doc above)
/// compacts it when `maintain()` is called and NOTHING else touches
/// the cache in between; the identical fixture, opened the same
/// way but with `maintain()` never called and no `get`/`insert`
/// either (either would append a journal record and trigger
/// inline compaction, which is not what this half tests),
/// stays exactly as oversized as the fixture left it.
#[test]
fn maintain_compacts_an_already_over_threshold_journal_and_a_call_free_session_does_not() {
    let with_dir = ScratchDir::new();
    let (id, bytes) = seed_cache_over_the_compaction_threshold(&with_dir.0);
    let mut with_maintain = open(&with_dir.0, 1_000_000);
    {
        let Mode::Writer(w) = &with_maintain.mode else {
            panic!("expected writer mode");
        };
        assert!(
            w.journal_total_records > JOURNAL_COMPACT_RECORDS,
            "control: the fixture must already be over threshold at open, before maintain() \
             ever runs"
        );
    }

    with_maintain.maintain();

    let compacted_journal_bytes =
        fs::read(with_dir.0.join("index").join("journal")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        compacted_journal_bytes.len(),
        cacheindex::ENVELOPE_LEN,
        "maintain() must compact an already-over-threshold journal down to envelope-only"
    );
    assert_eq!(
        with_maintain.get(&id),
        Some(bytes.clone()),
        "the cache must still serve the object correctly after maintain() compacts"
    );

    let without_dir = ScratchDir::new();
    seed_cache_over_the_compaction_threshold(&without_dir.0);
    let oversized_len = fs::metadata(without_dir.0.join("index").join("journal"))
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert!(
        oversized_len > cacheindex::ENVELOPE_LEN as u64,
        "control: the fixture itself must be oversized before the no-maintain half even opens it"
    );
    let no_maintain = open(&without_dir.0, 1_000_000);
    no_maintain.abandon(); // never call maintain(), never get/insert
    let untouched_journal_len = fs::metadata(without_dir.0.join("index").join("journal"))
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert_eq!(
        untouched_journal_len, oversized_len,
        "without maintain(), an already-over-threshold journal must stay exactly as it was"
    );
}

/// `maintain()` on a read-only-degraded cache must be
/// a silent no-op — the same `Mode::Writer`/`Mode::ReadOnlyDegraded`
/// mechanism every other mutator already uses (`insert`,
/// `raise_anchor`, ...), reused rather than re-derived.
#[test]
fn maintain_is_a_no_op_in_read_only_degraded_mode() {
    let dir = ScratchDir::new();
    // Held for the whole test so the second opener below stays
    // degraded throughout.
    let _writer = open(&dir.0, 1_000_000);

    let mut degraded = open_with(&dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        degraded.is_read_only_degraded(),
        "control: the second opener must be degraded"
    );

    degraded.maintain(); // must not panic

    assert!(
        degraded.is_read_only_degraded(),
        "maintain() must not change a degraded cache's mode"
    );
}

/// A `maintain()` whose write fails must leave the
/// cache usable — the next `get` and `insert` still work, matching
/// every other cache write's existing contract (a failure is logged,
/// never fatal, and never corrupts the in-memory index).
#[test]
fn maintain_after_a_failed_write_leaves_the_cache_usable() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(200);
    cache.insert(&id, &bytes);

    let buffered_len = {
        let Mode::Writer(w) = &mut cache.mode else {
            panic!("expected writer mode");
        };
        let buffered_len = w.journal_buf.len();
        w.journal_write_fail_after = Some(0); // fail the flush outright
        buffered_len
    };
    assert!(
        buffered_len > 0,
        "control: something must be buffered for maintain()'s flush to fail on"
    );

    cache.maintain(); // must log and swallow the failure, never panic

    let (id2, bytes2) = id_of(201);
    cache.insert(&id2, &bytes2);
    assert_eq!(
        cache.get(&id2),
        Some(bytes2),
        "insert after a failed maintain() must still work"
    );
    assert_eq!(
        cache.get(&id),
        Some(bytes),
        "a pre-existing entry must still be readable after a failed maintain()"
    );
}

/// Mutant M6 (`maintain()`
/// compacts but never flushes) survives every existing test: every
/// test that calls `maintain()` above either crosses a compaction
/// threshold (so `compact()`'s own journal-truncate reopen
/// incidentally leaves nothing buffered) or asserts nothing about
/// `journal_buf` at all. This test keeps the journal deliberately
/// UNDER both thresholds — so compaction cannot run and cannot mask
/// the flush — and pins a control FIRST: the insert must leave a
/// record BUFFERED, with nothing yet on the physical journal file,
/// before `maintain()` ever runs.
#[test]
fn maintain_flushes_buffered_records_when_compaction_does_not_run() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id, bytes) = id_of(210);
    cache.insert(&id, &bytes);

    let journal_path = dir.0.join("index").join("journal");
    let before = fs::metadata(&journal_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    {
        let Mode::Writer(w) = &cache.mode else {
            panic!("expected writer mode");
        };
        assert!(
            !w.journal_buf.is_empty(),
            "control: the insert must leave a record BUFFERED, not yet on disk"
        );
        assert!(
            w.journal_total_records <= JOURNAL_COMPACT_RECORDS
                && w.journal_len <= JOURNAL_COMPACT_BYTES,
            "control: must be UNDER threshold, so compaction cannot mask the flush"
        );
    }
    assert_eq!(
        before,
        cacheindex::ENVELOPE_LEN as u64,
        "control: nothing has reached the journal file yet"
    );

    cache.maintain();

    let after = fs::metadata(&journal_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert!(
        after > before,
        "maintain() must FLUSH the buffered records to disk even when compaction does \
         not run (before={before}, after={after})"
    );
    let Mode::Writer(w) = &cache.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.journal_buf.len(),
        0,
        "the buffer must be empty after maintain()"
    );
    cache.abandon();
}

/// `compact`'s free-space-refusal LATCH holds a refused compaction
/// until the journal grows: a tracked touch/evict/insert with no new
/// flush does not re-run the whole `compact`
/// body after a refusal. Each retry would perform a full snapshot
/// encode plus two free-space queries, and past the first precheck
/// a staged write, fsync, and rename too. This test asserts that the
/// refusal is latched by counting the calls entering `compact`
/// (`compaction_attempts`, a
/// `#[cfg(test)]` counter on `WriterState` following the
/// `walk_reads`/`anchor_writes` idiom of this module) — the direct
/// measure of the property under test, which needs no `FreeSpace` fake
/// of its own. The journal is already over BOTH
/// thresholds (`seed_cache_over_the_compaction_threshold`), every
/// `get` below is a HIT (so every one reaches `append_journal_record`
/// via `touch_id`), and the free-space seam refuses every write, so
/// every attempt this test could observe is a genuine refusal, never
/// a success that would reset the counters on its own.
#[test]
fn qa_probe_every_hit_pays_a_full_compaction_under_a_sustained_refusal() {
    let dir = ScratchDir::new();
    let (id, bytes) = seed_cache_over_the_compaction_threshold(&dir.0);

    let refusing = Box::new(FixedFreeSpace(FreeSpaceInfo {
        free_bytes: 100, // far below the watermark floor — every precheck refuses
        capacity_bytes: 1_000_000_000_000,
    }));
    let mut cache = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), refusing)
        .unwrap_or_else(|e| panic!("{e}"));

    for _ in 0..20 {
        assert_eq!(cache.get(&id), Some(bytes.clone()));
    }

    let Mode::Writer(w) = &cache.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.compaction_attempts.load(Ordering::Relaxed),
        1,
        "the latch must allow exactly one compaction attempt per flush, not one per hit \
         (before refusal retries were latched, this was 20 — one per hit)"
    );
    cache.abandon();
}

/// The latch must guard the ERROR door too, not only the two
/// free-space refusals. A genuine `Err` — here, a simulated
/// snapshot-write failure, deliberately NOT the free-space watermark
/// and NOT the reopen failure `journal_broken` latches onto (a
/// separate mechanism) — must set `compaction_stalled_at`. Otherwise
/// every later tracked touch or eviction re-runs the whole `compact`
/// body. This is the error-door counterpart of the refusal-door
/// test
/// `qa_probe_every_hit_pays_a_full_compaction_under_a_sustained_refusal`
/// above, which checks the same latch
/// on the refusal door.
///
/// EXECUTED mutation: making `maybe_compact` clear the latch before
/// calling `compact` and simply propagate its `Result<(), _>` leaves
/// `compaction_attempts` at 20 here, as observed in the executed
/// mutation.
#[test]
fn qa_probe_every_hit_pays_a_full_compaction_under_a_sustained_error() {
    let dir = ScratchDir::new();
    let (id, bytes) = seed_cache_over_the_compaction_threshold(&dir.0);
    let mut cache = open(&dir.0, 1_000_000);
    {
        let Mode::Writer(w) = &mut cache.mode else {
            panic!("expected writer mode");
        };
        w.compact_snapshot_write_fail = true;
    }

    for _ in 0..20 {
        assert_eq!(cache.get(&id), Some(bytes.clone()));
    }

    let Mode::Writer(w) = &cache.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.compaction_attempts.load(Ordering::Relaxed),
        1,
        "the latch must guard the ERROR door too — one compaction attempt per flush, not \
         one per hit (before errors were latched, a genuine Err left the latch \
         cleared and every hit re-ran compact)"
    );
    cache.abandon();
}

/// A failed journal
/// reopen mid-session must not be survivable-and-silent. Forces the
/// reopen failure `compact` hits after the fresh empty envelope has
/// already been renamed over `index/journal` (`journal_reopen_fail`,
/// the same style as `journal_write_fail_after`), then checks both
/// halves of the `journal_broken` state: (a) a later
/// `append_journal_record` call (via another cache hit) must not
/// write into the now-orphaned journal — `journal_buf`'s length must
/// not move at all, not merely "not reach disk" — and (b)
/// `Cache::close` must report the loss as an `Err`, not silently
/// succeed (a `Cache::close` returning `Ok` while the on-disk journal
/// was unwritable from partway through the session onward).
///
/// EXECUTED mutation: reverting `journal_broken`'s early return in
/// `append_journal_record` leaves `journal_buf.len()` growing on the
/// second `get`; reverting `Cache::close`'s `journal_broken` check
/// leaves it returning `Ok(())`; both outcomes were observed in the
/// executed mutations.
#[test]
fn a_failed_journal_reopen_stops_writes_and_close_reports_it() {
    let dir = ScratchDir::new();
    let (id, bytes) = seed_cache_over_the_compaction_threshold(&dir.0);
    let mut cache = open(&dir.0, 1_000_000);
    {
        let Mode::Writer(w) = &mut cache.mode else {
            panic!("expected writer mode");
        };
        w.journal_reopen_fail = true;
    }

    // A hit crosses the (already-crossed) threshold and triggers the
    // automatic compaction attempt, which fails at the reopen step.
    assert_eq!(cache.get(&id), Some(bytes.clone()));

    let buffered_before = {
        let Mode::Writer(w) = &mut cache.mode else {
            panic!("expected writer mode");
        };
        assert!(
            w.journal_broken,
            "control: the reopen failure must have set journal_broken"
        );
        w.journal_buf.len()
    };

    // (a) a subsequent append_journal_record call must not write —
    // not even into the in-memory buffer, let alone the orphaned
    // file.
    assert_eq!(cache.get(&id), Some(bytes.clone()));
    {
        let Mode::Writer(w) = &cache.mode else {
            panic!("expected writer mode");
        };
        assert_eq!(
            w.journal_buf.len(),
            buffered_before,
            "append_journal_record must refuse to buffer (let alone write) a record once \
             the journal is broken"
        );
    }

    // (b) Cache::close must report the loss, not silently succeed —
    // and specifically via `close`'s OWN named report, not merely
    // whatever raw error a retried `compact` attempt happens to
    // produce (that retry still runs — `journal_broken` gates
    // nothing on `maybe_compact` itself, see its own doc — and would
    // also return an `Err`, which is why this checks the MESSAGE,
    // not just the variant).
    let err = cache
        .close()
        .expect_err("close must report a broken journal, not silently succeed");
    let CacheError::Io { context, .. } = &err else {
        panic!("got {err:?}, expected a named CacheError::Io reporting the lost journal");
    };
    assert!(
        context.contains("mid-session"),
        "got context {context:?}, expected close's own named report about the journal being \
         lost mid-session, not compact's own raw reopen-failure message"
    );
}

/// The hot-path retry latch must
/// not gag an EXPLICIT call. `maintain()` is a caller saying "try
/// now" — it must ignore a stale refusal latch and try again,
/// because the caller may know the world has changed even though
/// this idle cache's own `journal_len` never moved to invalidate
/// the latch on its own. `maintain()` calls `maybe_compact` directly,
/// not the hot path's latched `maybe_compact_throttled`: otherwise a
/// second explicit call after free space cleared would be gagged. The
/// latch key (`journal_len`) cannot change on a cache that served
/// nothing in between, so a throttled call would still match the stale
/// entry and return `Ok(())` without re-querying free space.
/// This test requires the explicit call to try again.
#[test]
fn maintain_ignores_and_clears_a_stale_refusal_latch() {
    let dir = ScratchDir::new();
    let (id, bytes) = seed_cache_over_the_compaction_threshold(&dir.0);

    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(true)); // refusing from the start
    let free_space = SwitchableFreeSpace {
        plenty: FreeSpaceInfo {
            free_bytes: 1_000_000_000_000,
            capacity_bytes: 2_000_000_000_000,
        },
        refusing: FreeSpaceInfo {
            free_bytes: 100,
            capacity_bytes: 1_000_000_000_000,
        },
        refuse: refuse.clone(),
    };
    let mut cache = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(free_space))
        .unwrap_or_else(|e| panic!("{e}"));

    cache.maintain(); // refused by the watermark; the latch is set at the current journal_len

    let refused_len = fs::metadata(dir.0.join("index").join("journal"))
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert!(
        refused_len > cacheindex::ENVELOPE_LEN as u64,
        "control: the first maintain() must have been genuinely refused by the watermark, \
         not silently succeeded"
    );

    // Another process frees disk space. This cache is idle: nothing
    // touches the journal, so journal_len does not move.
    refuse.store(false, Ordering::SeqCst);

    cache.maintain(); // the EXPLICIT call must ignore the stale latch and try again

    let compacted_len = fs::metadata(dir.0.join("index").join("journal"))
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert_eq!(
        compacted_len,
        cacheindex::ENVELOPE_LEN as u64,
        "an explicit maintain() must compact once free space clears, even though \
         journal_len never changed since the refusal that set the latch — before this \
         fix, the latch (matching on journal_len alone) gagged this second, explicit call \
         exactly the way it must gag the automatic hot-path one, and the oversized journal \
         survived a cleared refusal"
    );
    assert_eq!(
        cache.get(&id),
        Some(bytes),
        "the cache must still serve the object correctly after the explicit compaction"
    );
    cache.abandon();
}

/// The same explicit-call retry property at
/// `close()`. `close` consumes the cache, so this uses its own fresh
/// instance rather than test 1's — `maintain()` still sets the latch
/// under refusal first, exactly as above, so `close()` is the one
/// call being asked whether it honours or ignores a STALE latch.
#[test]
fn close_ignores_and_clears_a_stale_refusal_latch() {
    let dir = ScratchDir::new();
    let (id, _bytes) = seed_cache_over_the_compaction_threshold(&dir.0);

    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(true)); // refusing from the start
    let free_space = SwitchableFreeSpace {
        plenty: FreeSpaceInfo {
            free_bytes: 1_000_000_000_000,
            capacity_bytes: 2_000_000_000_000,
        },
        refusing: FreeSpaceInfo {
            free_bytes: 100,
            capacity_bytes: 1_000_000_000_000,
        },
        refuse: refuse.clone(),
    };
    let mut cache = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(free_space))
        .unwrap_or_else(|e| panic!("{e}"));

    cache.maintain(); // refused by the watermark; the latch is set at the current journal_len

    let refused_len = fs::metadata(dir.0.join("index").join("journal"))
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert!(
        refused_len > cacheindex::ENVELOPE_LEN as u64,
        "control: the maintain() above must have been genuinely refused by the watermark, \
         not silently succeeded"
    );

    // Another process frees disk space. This cache is idle: nothing
    // touches the journal, so journal_len does not move.
    refuse.store(false, Ordering::SeqCst);

    cache.close().unwrap_or_else(|e| panic!("{e}")); // the EXPLICIT close() must ignore the stale latch

    let compacted_len = fs::metadata(dir.0.join("index").join("journal"))
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert_eq!(
        compacted_len,
        cacheindex::ENVELOPE_LEN as u64,
        "close() must compact once free space clears, even though journal_len never moved \
         since the earlier maintain() call's refusal set the latch — a clean shutdown must \
         not leave an oversized journal behind just because an idle cache's own latch key \
         never changed"
    );

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert!(w.live.contains_key(&id));
}

/// The byte-threshold-only fixture is unreachable; the next paragraph
/// explains why this uses the record threshold. Mutant M9 (delete
/// `close`'s own `maybe_compact` call) survives every existing test
/// because `append_journal_record`'s inline compaction
/// already catches every threshold crossing an append itself can
/// produce, the instant it happens
/// (`touches_alone_compact_the_journal_before_close_ever_runs`
/// above). The ONE case the inline trigger structurally cannot catch
/// is a journal already over threshold when THIS session opened it,
/// with no append happening this session at all — `close`'s own
/// explicit call is the only thing that can compact that.
///
/// The brief's literal framing for this item — "buffer records so
/// only the final flush crosses the BYTE threshold, staying under
/// the record threshold throughout" — is not reachable with this
/// format's fixed record sizes: `JOURNAL_COMPACT_RECORDS` (65,536)
/// times the largest encoded record (`Insert`: 1 tag + 32 digest + 4
/// size + 4 check = 41 bytes) is 2,686,976 bytes, which is UNDER
/// `JOURNAL_COMPACT_BYTES` (4 MiB = 4,194,304 bytes). So the
/// record-count threshold is always crossed — and caught inline —
/// strictly before the byte threshold ever could be; there is no
/// sequence of real records that crosses the byte threshold while
/// the record count stays at or under its own threshold. This test
/// pins mutant M9 by the record axis instead, using the same
/// already-over-threshold-at-open fixture used above
/// for `maintain()`, with `close()` in place of `maintain()` and
/// zero `get`/`insert` calls in between so the inline trigger has no
/// opportunity to run at all this session.
#[test]
fn close_compacts_an_already_over_threshold_journal_with_no_activity_this_session() {
    let dir = ScratchDir::new();
    let (id, _bytes) = seed_cache_over_the_compaction_threshold(&dir.0);
    let cache = open(&dir.0, 1_000_000);
    {
        let Mode::Writer(w) = &cache.mode else {
            panic!("expected writer mode");
        };
        assert!(
            w.journal_total_records > JOURNAL_COMPACT_RECORDS,
            "control: the fixture must already be over threshold at open, before close() \
             ever runs and with no get/insert in between"
        );
    }

    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let journal_bytes =
        fs::read(dir.0.join("index").join("journal")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        journal_bytes.len(),
        cacheindex::ENVELOPE_LEN,
        "close() must compact an already-over-threshold journal even with ZERO get/insert \
         calls this session — the inline trigger never ran, so only close()'s own \
         maybe_compact call can be responsible"
    );

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert!(w.live.contains_key(&id));
}

/// Mutant M4′ (initialise
/// `WriterState.root` from a NONEXISTENT path, so every compaction
/// `Err`s and the counters stay untouched) survives because nothing
/// pins that the field actually names the cache's OWN root — every
/// existing test that exercises it does so only through operations
/// that use it validly, never checking the value itself. (The
/// `w.root` vs `self.root` choice inside `maintain()` is a
/// DIFFERENT, TRULY EQUIVALENT mutant — both come from the same
/// `&Path` binding in `open_with_free_space`, and nothing ever
/// reassigns either field — not hunted here.) This is a PROVENANCE
/// pin, not a behaviour test: the cheapest honest assertion is a
/// direct field read compared against `Cache::root()`.
#[test]
fn writer_state_root_names_the_cache_own_root() {
    let dir = ScratchDir::new();
    let cache = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &cache.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.root.as_path(),
        cache.root(),
        "WriterState.root must name this cache's own root"
    );
}

#[test]
fn ql_a_degraded_opener_refuses_an_absent_marker() {
    let dir = ScratchDir::new();
    let _writer = open(&dir.0, 1_000_000); // holds the lock; marker already written

    fs::remove_file(dir.0.join(MARKER_NAME)).unwrap_or_else(|e| panic!("{e}"));

    let err = open_with(&dir.0, 1_000_000, &origin())
        .expect_err("a degraded opener must refuse an absent marker, never silently adopt");
    assert!(
        matches!(err, CacheError::Incompatible { .. }),
        "got {err:?}"
    );
}

#[test]
fn ql_an_object_larger_than_the_quota_does_not_flush_the_cache() {
    let dir = ScratchDir::new();
    let (small_id, small_bytes) = id_of(1);
    let quota = small_bytes.len() as u64; // room for exactly the small object
    let mut cache = open(&dir.0, quota);
    cache.insert(&small_id, &small_bytes);
    assert_eq!(cache.get(&small_id), Some(small_bytes.clone()));

    let huge_len = usize::try_from(quota).unwrap_or(usize::MAX) * 2;
    let huge_bytes = vec![7u8; huge_len];
    let huge_id = GrainId::of(&huge_bytes);
    cache.insert(&huge_id, &huge_bytes);

    assert_eq!(
        cache.get(&huge_id),
        None,
        "an object larger than the whole quota must be refused"
    );
    assert_eq!(
        cache.get(&small_id),
        Some(small_bytes),
        "the pre-existing entry must survive — an unfittable insert must not flush it to \
         make room it can never use"
    );
}

/// A `FreeSpace` double whose answer can be flipped mid-test via a shared
/// `Arc<AtomicBool>` — needed because `pp_close_with_buffer_and_free_space_refusal`
/// needs plenty of room during `insert` and a refusal only at `close`.
/// `Arc<AtomicBool>`, not `Rc<Cell<bool>>`: `FreeSpace: Send` now, and an `Rc` is
/// never `Send` regardless of what it wraps.
struct SwitchableFreeSpace {
    plenty: FreeSpaceInfo,
    refusing: FreeSpaceInfo,
    refuse: Arc<std::sync::atomic::AtomicBool>,
}
impl FreeSpace for SwitchableFreeSpace {
    fn free_space(&self) -> io::Result<FreeSpaceInfo> {
        Ok(if self.refuse.load(Ordering::SeqCst) {
            self.refusing
        } else {
            self.plenty
        })
    }
}

#[test]
fn pp_close_with_buffer_and_free_space_refusal() {
    let dir = ScratchDir::new();
    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let free_space = SwitchableFreeSpace {
        plenty: FreeSpaceInfo {
            free_bytes: 1_000_000_000_000,
            capacity_bytes: 2_000_000_000_000,
        },
        refusing: FreeSpaceInfo {
            free_bytes: 100,
            capacity_bytes: 1_000_000_000_000,
        },
        refuse: refuse.clone(),
    };
    let mut cache = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(free_space))
        .unwrap_or_else(|e| panic!("{e}"));

    let (id, bytes) = id_of(99);
    cache.insert(&id, &bytes); // buffered insert record, well under the 4 KiB flush threshold
    assert!(
        object_path(&dir.0, &id).exists(),
        "the object itself is ALREADY durable (fsync + rename)"
    );

    refuse.store(true, Ordering::SeqCst); // every write is now refused by the watermark
    cache.close().unwrap_or_else(|e| panic!("{e}")); // close() itself must still return Ok

    assert!(
        object_path(&dir.0, &id).exists(),
        "the object survives on disk regardless of the refusal"
    );

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert_eq!(
        w.walk_reads.load(Ordering::Relaxed),
        0,
        "the refusal must not force a walk"
    );
    assert!(
        !w.live.contains_key(&id),
        "pins the documented single-object crash window: the buffered insert record, \
         refused at close, never reached the journal — the object is on disk but stays \
         UNINDEXED until a cold rebuild adopts it (gran verify reports it, and repairs \
         nothing)"
    );
}

#[test]
fn ql_a_refused_journal_reset_does_not_crash_the_next_open() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establish the marker + directory layout

    // An untrustworthy (over-cap) snapshot forces the cold rebuild
    // walk, with the journal ABSENT going in — the walk's own
    // journal-reset write is what a sustained refusal can leave
    // unwritten.
    let snapshot_path = dir.0.join("index").join("snapshot");
    let f = File::create(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    f.set_len(INDEX_FILE_MAX_BYTES + 1)
        .unwrap_or_else(|e| panic!("{e}"));
    drop(f);
    fs::remove_file(dir.0.join("index").join("journal")).unwrap_or_else(|e| panic!("{e}"));

    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(true)); // refusing from the very first open
    let free_space = SwitchableFreeSpace {
        plenty: FreeSpaceInfo {
            free_bytes: 1_000_000_000_000,
            capacity_bytes: 2_000_000_000_000,
        },
        refusing: FreeSpaceInfo {
            free_bytes: 100,
            capacity_bytes: 1_000_000_000_000,
        },
        refuse: refuse.clone(),
    };

    // The walk's journal-reset write is refused by the watermark,
    // leaving the journal genuinely absent; the open must still
    // succeed, not die with CacheError::Io (the journal open, NotFound).
    let mut cache = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(free_space))
        .unwrap_or_else(|e| {
            panic!(
                "open must succeed as writer even when the walk's own journal-reset \
                     write was refused: {e}"
            )
        });

    refuse.store(false, Ordering::SeqCst); // restore plenty of room
    let (id, bytes) = id_of(102);
    cache.insert(&id, &bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let reopened = open(&dir.0, 1_000_000);
    let Mode::Writer(w) = &reopened.mode else {
        panic!("expected writer mode");
    };
    assert!(
        w.live.contains_key(&id),
        "the insert made after the recovery must survive the next reopen"
    );
}

#[test]
fn a_symlinked_root_path_is_a_miss() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new(); // outside the cache root entirely
    let cache = open(&dir.0, 1_000_000);
    let v = vol("root-conf-symlink");

    let outside_file = outside.0.join("planted-root");
    fs::write(&outside_file, b"not a real cached root").unwrap_or_else(|e| panic!("{e}"));

    let leaf_dir = dir.0.join("roots").join(v.as_str());
    fs::create_dir_all(&leaf_dir).unwrap_or_else(|e| panic!("{e}"));
    let leaf = leaf_dir.join("00000000000000000001");
    std::os::unix::fs::symlink(&outside_file, &leaf).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        cache.get_root_bytes(&v, 1),
        None,
        "a symlink at a root path must be a miss, never a followed read"
    );
}

#[test]
fn get_root_bytes_refuses_a_symlink_swapped_in_after_lstat() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new();
    let v = vol("root-open-symlink-swap");
    let path = root_bytes_path(&dir.0, &v, 1);
    let expected = b"verified root bytes";
    let mut seeded = open(&dir.0, 1_000_000);
    seeded.put_root_bytes(&v, 1, expected);
    assert_eq!(
        seeded.get_root_bytes(&v, 1),
        Some(expected.to_vec()),
        "positive control: the exact root path must be readable while it is regular"
    );
    seeded.close().unwrap_or_else(|e| panic!("{e}"));

    let victim = outside.0.join("attacker-root");
    let victim_bytes = b"attacker-selected root bytes".to_vec();
    fs::write(&victim, &victim_bytes).unwrap_or_else(|e| panic!("{e}"));
    let hook_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired_by_hook = hook_fired.clone();
    let swapped_path = path.clone();
    let mut hooks = PATH_READ_POST_STAT_HOOKS
        .lock()
        .unwrap_or_else(|e| panic!("{e}"));
    hooks.push(PathReadPostStatHook {
        path: path.clone(),
        action: Box::new(move || {
            fs::remove_file(&swapped_path).unwrap_or_else(|e| panic!("{e}"));
            std::os::unix::fs::symlink(&victim, &swapped_path).unwrap_or_else(|e| panic!("{e}"));
            fired_by_hook.store(true, Ordering::SeqCst);
        }),
    });
    drop(hooks);

    let cache = open(&dir.0, 1_000_000);
    let result = cache.get_root_bytes(&v, 1);

    assert!(
        hook_fired.load(Ordering::SeqCst),
        "control: the regular root must have been replaced immediately before its open"
    );
    assert_eq!(
        result, None,
        "a swapped-in root symlink must be a miss, never followed to unverified bytes"
    );
    assert!(
        fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink()),
        "control: the planted symlink must remain at the root path"
    );
}

#[test]
fn put_root_bytes_refuses_a_symlinked_second_level_volume_dir() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("root-volume-dir-symlink");
    let bytes = b"verified signed root bytes";
    let path = root_bytes_path(&dir.0, &v, 1);
    let volume_dir = path
        .parent()
        .unwrap_or_else(|| panic!("a root path must have a volume parent"));

    cache.put_root_bytes(&v, 1, bytes);
    assert_eq!(
        fs::read(&path).unwrap_or_else(|e| panic!("{e}")),
        bytes,
        "positive control: this cache and volume dir must accept an ordinary root write"
    );
    fs::remove_file(&path).unwrap_or_else(|e| panic!("{e}"));
    fs::remove_dir(volume_dir).unwrap_or_else(|e| panic!("{e}"));

    std::os::unix::fs::symlink(&outside.0, volume_dir).unwrap_or_else(|e| panic!("{e}"));
    let escaped = outside.0.join("00000000000000000001");
    cache.put_root_bytes(&v, 1, bytes);

    assert!(
        !escaped.exists(),
        "cache root writes must refuse the second-level volume symlink rather than rename \
         through it"
    );
    assert!(
        fs::symlink_metadata(volume_dir).is_ok_and(|meta| meta.file_type().is_symlink()),
        "the refusal must leave the planted volume-dir symlink in place"
    );
}

/// A DANGLING symlink at the leaf is where a following check and a
/// non-following one diverge observably: `exists()` reports a
/// dangling symlink as ABSENT (its target does not exist), so a
/// following check cannot tell this state from an empty name at all.
/// `fs::symlink_metadata` never follows, so the entry is seen for
/// what it is — FOREIGN, since this cache writes only regular files
/// at a root leaf — and the write says so before replacing it.
/// `atomic_write`'s `rename` is what clears it, atomically and
/// without following it.
#[test]
fn put_root_bytes_replaces_a_dangling_symlink_through_the_atomic_rename() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("root-leaf-dangling-symlink");
    let bytes = b"verified signed root bytes";
    let path = root_bytes_path(&dir.0, &v, 1);
    let volume_dir = path
        .parent()
        .unwrap_or_else(|| panic!("a root path must have a volume parent"));
    fs::create_dir_all(volume_dir).unwrap_or_else(|e| panic!("{e}"));
    let nowhere = dir.0.join("nowhere-does-not-exist");
    std::os::unix::fs::symlink(&nowhere, &path).unwrap_or_else(|e| panic!("{e}"));

    cache.put_root_bytes(&v, 1, bytes);

    assert!(
        fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file()),
        "the rename must replace the planted link — declining leaves this root \
         permanently uncacheable, since nothing else clears the name"
    );
    assert_eq!(
        cache.get_root_bytes(&v, 1),
        Some(bytes.to_vec()),
        "and the root is readable afterwards"
    );
    assert!(
        !nowhere.exists(),
        "the dangling target is not created by anything here"
    );
}

/// The non-dangling twin, and the property that makes the replace
/// safe: `rename(2)` replaces the NAME at `dest` and never follows
/// it, so a link planted at the leaf is replaced and the file it
/// pointed at stays byte-identical. The volume DIRECTORY is
/// classified non-followingly first, so nothing here reaches
/// outside the cache root either.
#[test]
fn put_root_bytes_replaces_a_foreign_leaf_through_the_atomic_rename() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("root-leaf-foreign-symlink");
    let bytes = b"verified signed root bytes";
    let path = root_bytes_path(&dir.0, &v, 1);
    let volume_dir = path
        .parent()
        .unwrap_or_else(|| panic!("a root path must have a volume parent"));
    fs::create_dir_all(volume_dir).unwrap_or_else(|e| panic!("{e}"));
    let victim = outside.0.join("someone-elses-file");
    let victim_bytes = b"outside bytes must remain unchanged".to_vec();
    fs::write(&victim, &victim_bytes).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim, &path).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        fs::symlink_metadata(volume_dir).is_ok_and(|meta| meta.is_dir()),
        "control: the volume directory is real, so it is the LEAF decision under test"
    );

    cache.put_root_bytes(&v, 1, bytes);

    assert!(
        fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file()),
        "the rename must replace the planted link and write the root in its place"
    );
    assert_eq!(
        fs::read(&victim).unwrap_or_else(|e| panic!("{e}")),
        victim_bytes,
        "and the link's TARGET is untouched: rename replaces the link, never what it \
         points at"
    );
    assert_eq!(
        cache.get_root_bytes(&v, 1),
        Some(bytes.to_vec()),
        "the root is readable afterwards"
    );
}

/// A DIRECTORY at a root leaf is the one foreign shape no write can
/// replace, so the classification declines and says so rather than
/// leaving the failure to `atomic_write`'s rename.
#[test]
fn put_root_bytes_declines_a_directory_at_the_leaf() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("root-leaf-directory");
    let path = root_bytes_path(&dir.0, &v, 1);
    fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));
    let inside = path.join("someone-elses-file");
    fs::write(&inside, b"must survive").unwrap_or_else(|e| panic!("{e}"));

    cache.put_root_bytes(&v, 1, b"verified signed root bytes");

    assert!(
        fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()),
        "a leaf no write can replace must be left exactly where it is"
    );
    assert_eq!(
        fs::read(&inside).unwrap_or_else(|e| panic!("{e}")),
        b"must survive".to_vec(),
        "and nothing under it may have been touched"
    );
    assert_eq!(cache.get_root_bytes(&v, 1), None, "the root stays uncached");
}

/// `symlink_metadata(&dest).is_ok()` splits the world in two where
/// there are THREE answers. An `Err` that is
/// not `NotFound` — `ENOTDIR` because a path component is a regular
/// file, `EACCES` on a locked-down parent, any transient I/O
/// failure — was folded into "absent", so put-if-absent went on to
/// write. That matters because the write does not re-check: if the
/// condition clears before `atomic_write`'s `rename`, the rename
/// REPLACES an existing root. The classification now uses the
/// three-way shape (`Ok` present, `Err(NotFound)` absent, anything
/// else warn and return), so an unreadable `dest` fails CLOSED.
///
/// `ENOTDIR` is the reachable, deterministic member of the class:
/// a regular FILE where the volume directory should be.
#[test]
fn put_root_bytes_refuses_when_the_leaf_cannot_be_classified_at_all() {
    let dir = ScratchDir::new();
    let counter = CountingFreeSpace::new();
    let mut cache =
        Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(counter.clone()))
            .unwrap_or_else(|e| panic!("{e}"));
    counter.reset(); // ignore whatever `open` itself queried
    let v = vol("root-leaf-unclassifiable");
    let path = root_bytes_path(&dir.0, &v, 1);
    let volume_dir = path
        .parent()
        .unwrap_or_else(|| panic!("a root path must have a volume parent"));
    let grandparent = volume_dir
        .parent()
        .unwrap_or_else(|| panic!("a volume dir must have a parent"));
    fs::create_dir_all(grandparent).unwrap_or_else(|e| panic!("{e}"));
    // A regular FILE where the volume DIRECTORY belongs: every
    // stat of anything below it now fails ENOTDIR, not NotFound.
    fs::write(volume_dir, b"not a directory").unwrap_or_else(|e| panic!("{e}"));
    let err = fs::symlink_metadata(&path)
        .expect_err("fixture precondition: the leaf must not be classifiable");
    assert_ne!(
        err.kind(),
        io::ErrorKind::NotFound,
        "fixture precondition: the error must NOT be NotFound — that is the whole point of \
         this test, and a NotFound here would make it a duplicate of the absent case: {err}"
    );

    cache.put_root_bytes(&v, 1, b"verified signed root bytes");

    // The observable is that the function RETURNED AT THE
    // CLASSIFICATION, not that the bytes failed to land. Asserting
    // only the latter proves nothing: with the leaf folded into
    // "absent", `create_structural_dir` refuses the same ENOTDIR
    // one step later and the on-disk outcome is identical — this
    // test passed against the unfixed code until it counted the
    // precheck instead. The precheck is the first thing past the
    // classification, so a zero count is the fail-closed proof.
    assert_eq!(
        counter.count(),
        0,
        "an unclassifiable leaf must return AT the put-if-absent classification: nothing \
         past it may run, because nothing past it re-checks the leaf before \
         atomic_write's rename replaces whatever is there"
    );
    assert_eq!(
        fs::read(volume_dir).unwrap_or_else(|e| panic!("{e}")),
        b"not a directory".to_vec(),
        "and nothing on disk was touched, with no panic"
    );
}

#[test]
fn ql_the_journal_buffer_is_bounded_under_sustained_refusal() {
    #[derive(Clone, Default)]
    struct WarnCounter(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCounter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = ScratchDir::new();
    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let free_space = SwitchableFreeSpace {
        plenty: FreeSpaceInfo {
            free_bytes: 1_000_000_000_000,
            capacity_bytes: 2_000_000_000_000,
        },
        refusing: FreeSpaceInfo {
            free_bytes: 100,
            capacity_bytes: 1_000_000_000_000,
        },
        refuse: refuse.clone(),
    };
    let mut cache = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(free_space))
        .unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = id_of(103);
    cache.insert(&id, &bytes);
    refuse.store(true, Ordering::SeqCst); // every subsequent flush is refused, sustained

    let counter = WarnCounter::default();
    let subscriber = tracing_subscriber::registry().with(counter.clone());
    tracing::subscriber::with_default(subscriber, || {
        for _ in 0..1800 {
            assert_eq!(cache.get(&id), Some(bytes.clone()));
        }
    });

    if let Mode::Writer(w) = &cache.mode {
        assert!(
            w.journal_buf.len() <= JOURNAL_BUF_MAX_BYTES,
            "the buffer must never grow past its cap"
        );
    } else {
        panic!("expected writer mode");
    }
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        1,
        "exactly one drop-warning must fire for one cap-crossing"
    );
}

#[test]
fn a_marker_over_the_size_bound_is_incompatible() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establish a valid marker first

    let marker_path = dir.0.join(MARKER_NAME);
    let oversized = vec![b'x'; usize::try_from(MARKER_MAX_BYTES).unwrap_or(usize::MAX) + 1];
    fs::write(&marker_path, &oversized).unwrap_or_else(|e| panic!("{e}"));

    let err = open_with(&dir.0, 1_000_000, &origin())
        .expect_err("an over-cap marker must be refused, not read unbounded");
    assert!(
        matches!(err, CacheError::Incompatible { .. }),
        "got {err:?}"
    );
}

#[test]
fn open_refuses_a_preexisting_symlinked_txn_dir() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establish the marker + directory layout

    let outside = ScratchDir::new();
    let outside_file = outside.0.join("do-not-delete");
    fs::write(&outside_file, b"must survive").unwrap_or_else(|e| panic!("{e}"));

    let txn_path = dir.0.join("txn");
    fs::remove_dir_all(&txn_path).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&outside.0, &txn_path).unwrap_or_else(|e| panic!("{e}"));

    let err = open_with(&dir.0, 1_000_000, &origin())
        .expect_err("a txn/ symlink present at open must refuse the cache");
    assert!(
        matches!(err, CacheError::Io { .. }),
        "the structural refusal must retain I/O context: {err}"
    );

    assert!(
        outside_file.exists(),
        "a refused symlinked txn/ must never delete outside the cache root"
    );
}

#[test]
fn a_symlinked_lock_path_fails_cleanly_without_truncating_the_target() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establish the marker + directory layout

    let outside = ScratchDir::new();
    let outside_file = outside.0.join("do-not-truncate");
    fs::write(&outside_file, b"must survive intact").unwrap_or_else(|e| panic!("{e}"));

    let lock_path = dir.0.join("lock");
    fs::remove_file(&lock_path).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&outside_file, &lock_path).unwrap_or_else(|e| panic!("{e}"));

    let err = open_with(&dir.0, 1_000_000, &origin())
        .expect_err("a symlinked lock path must refuse (O_NOFOLLOW), never follow");
    assert!(matches!(err, CacheError::Io { .. }), "got {err:?}");
    assert_eq!(
        fs::read(&outside_file).unwrap_or_else(|e| panic!("{e}")),
        b"must survive intact",
        "O_NOFOLLOW must refuse before any truncation, not after"
    );
}

#[test]
fn ql_the_walk_adoption_cap_stops_adopting_and_warns() {
    #[derive(Clone, Default)]
    struct WarnCounter(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCounter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establish the marker + directory layout

    // Four legitimate, distinct, correctly-fanned-out objects.
    for byte in 0u8..4 {
        let (id, bytes) = id_of(120u8.wrapping_add(byte));
        let path = object_path(&dir.0, &id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{e}"));
        }
        fs::write(&path, &bytes).unwrap_or_else(|e| panic!("{e}"));
    }

    let walk_reads = AtomicU64::new(0);
    let txn_counter = AtomicU64::new(0);
    let free_space = plenty();

    let counter = WarnCounter::default();
    let subscriber = tracing_subscriber::registry().with(counter.clone());
    let state = tracing::subscriber::with_default(subscriber, || {
        cold_rebuild_walk_capped(&dir.0, &walk_reads, &txn_counter, free_space.as_ref(), 2)
            .unwrap_or_else(|e| panic!("{e}"))
    });

    assert_eq!(
        state.entries.len(),
        2,
        "adoption must stop at the injected cap, not adopt all four"
    );
    assert!(
        counter.0.load(Ordering::SeqCst) >= 1,
        "the cap being reached must warn"
    );
}

/// A fanout-level `dir_path.is_dir()` (`Path::is_dir`, which
/// FOLLOWS a symlink whose target is a directory) walks a
/// pre-planted `objects/<2hex> -> <outside dir>` straight through,
/// and a validly-named file inside it gets ADOPTED into the writer's
/// index. `verify.rs::scan_objects` classifies the identical shape
/// with `dir_entry.file_type()` (never follows); this mirrors it.
///
/// End-to-end through the real `Cache` writer path, not just the
/// walk function: the planted id, if wrongly adopted, is the
/// OLDEST index entry (seq 0, adopted before any of the inserts
/// below), so it is the very FIRST candidate a tiny-quota LRU
/// eviction picks — and eviction unlinks by NAME through
/// `object_path`, which resolves straight through the symlinked
/// fanout component. Forcing that eviction and asserting the
/// outside file survives proves the refusal holds across the whole
/// chain, not just the walk's own return value.
#[test]
fn cold_rebuild_never_adopts_through_a_symlinked_fanout_directory() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establishes objects/, txn/, index/, the initial empty snapshot+journal

    let (id, bytes) = id_of(77);
    let dir_hex = &id.digest_hex()[..2];
    let fanout = dir.0.join("objects").join(dir_hex);
    std::os::unix::fs::symlink(&outside.0, &fanout).unwrap_or_else(|e| panic!("{e}"));
    let victim_path = outside.0.join(id.digest_hex());
    let victim_bytes = b"must never be adopted or removed by the cache".to_vec();
    fs::write(&victim_path, &victim_bytes).unwrap_or_else(|e| panic!("{e}"));
    let _ = &bytes; // the planted content need not match the real id; structure alone must not be adopted

    // Force the NEXT open to WALK rather than trust the (valid,
    // empty) snapshot the first open already wrote: delete the
    // snapshot, leaving the journal present — load_index's own
    // (Absent snapshot, Present journal) arm walks unconditionally
    // (see load_index's match arm just above `IndexFileRead::Absent`).
    fs::remove_file(dir.0.join("index").join("snapshot")).unwrap_or_else(|e| panic!("{e}"));

    let mut cache = open(&dir.0, 200); // tiny quota: the inserts below must force LRU eviction
    for byte in 0u8..8 {
        let (oid, obytes) = id_of(30u8.wrapping_add(byte));
        cache.insert(&oid, &obytes);
    }

    assert!(
        victim_path.exists(),
        "a symlinked fanout directory must never be walked into by cold rebuild — if it \
         were wrongly adopted, this forced-eviction sequence would have unlinked it \
         THROUGH the symlink, outside the cache root"
    );
    assert_eq!(
        fs::read(&victim_path).unwrap_or_else(|e| panic!("{e}")),
        victim_bytes,
        "even if somehow selected as a candidate, the bytes outside the cache root must \
         never be modified"
    );
}

/// Companion to the fanout-directory case just above: a REAL
/// (non-symlinked) fanout directory containing a symlinked LEAF must
/// never be adopted either. `admit_walk_entry` reads the leaf via
/// `DirEntry::metadata()`, which std implements as `fstatat` with
/// `AT_SYMLINK_NOFOLLOW` on every platform this crate builds for —
/// so this is a PIN rather than a red→green regression test: it
/// fails the moment the site is edited to
/// `fs::metadata(entry.path())` (the FOLLOWING form, one easy edit
/// away, on this crate's ban list). Its value is guarding the
/// non-following property, not proving a past defect fixed.
#[test]
fn cold_rebuild_never_adopts_a_symlinked_leaf_inside_a_real_fanout_directory() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    let (id, bytes) = id_of(88);
    let dir_hex = &id.digest_hex()[..2];
    let fanout = dir.0.join("objects").join(dir_hex);
    fs::create_dir_all(&fanout).unwrap_or_else(|e| panic!("{e}")); // a REAL fanout dir, not symlinked

    let victim_path = outside.0.join("victim");
    fs::write(&victim_path, &bytes).unwrap_or_else(|e| panic!("{e}"));
    let leaf = fanout.join(id.digest_hex());
    std::os::unix::fs::symlink(&victim_path, &leaf).unwrap_or_else(|e| panic!("{e}"));

    let walk_reads = AtomicU64::new(0);
    let txn_counter = AtomicU64::new(0);
    let free_space = plenty();
    let state = cold_rebuild_walk_capped(
        &dir.0,
        &walk_reads,
        &txn_counter,
        free_space.as_ref(),
        walk_adoption_cap(),
    )
    .unwrap_or_else(|e| panic!("{e}"));

    assert!(
        state.entries.iter().all(|(eid, _)| *eid != id),
        "a symlinked leaf must never be adopted into the index, real bytes behind it or not"
    );
}

/// The two free-space prechecks are ONE against the
/// COMBINED footprint, and this is the window that made it
/// necessary. Free space is set ABOVE the ~11-byte journal envelope
/// and BELOW the snapshot — checked separately, the snapshot
/// rewrite is skipped while the journal reset still lands, and in
/// `load_index`'s (snapshot present-and-decodable, journal
/// untrustworthy) arm that leaves a VALID-but-stale snapshot beside
/// an empty journal, which the next open decodes as authoritative:
/// no rebuild, and every object inserted since silently missing
/// from the index.
///
/// Mutation probe for whoever reviews this: split the combined
/// precheck back into two and this test fails on the journal
/// byte-identity assertion.
#[test]
fn a_refused_snapshot_rewrite_never_empties_the_journal_on_its_own() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    // Enough objects that the snapshot is comfortably larger than
    // the journal envelope the watermark must still admit.
    for byte in 0u8..8 {
        let (id, bytes) = id_of(200u8.wrapping_add(byte));
        let path = object_path(&dir.0, &id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{e}"));
        }
        fs::write(&path, &bytes).unwrap_or_else(|e| panic!("{e}"));
    }

    let journal_path = dir.0.join("index").join("journal");
    let snapshot_path = dir.0.join("index").join("snapshot");
    let journal_before = fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    let snapshot_before = fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));

    // The watermark is max(1 GiB, 5% of capacity). Sit just above
    // it by the journal envelope's size and just below it by the
    // snapshot's — the exact gap the two-precheck form fell into.
    let journal_len = empty_journal_bytes().len() as u64;
    let watermark = 1024 * 1024 * 1024;
    let free_space: Box<dyn FreeSpace> = Box::new(FixedFreeSpace(FreeSpaceInfo {
        free_bytes: watermark + journal_len + 8,
        capacity_bytes: 2 * watermark,
    }));
    assert!(
        free_space_precheck(free_space.as_ref(), journal_len),
        "fixture precondition: the journal envelope alone must be ADMITTED"
    );
    assert!(
        !free_space_precheck(free_space.as_ref(), snapshot_before.len() as u64 + 512),
        "fixture precondition: a snapshot-sized write must be REFUSED"
    );

    let walk_reads = AtomicU64::new(0);
    let txn_counter = AtomicU64::new(0);
    cold_rebuild_walk_capped(
        &dir.0,
        &walk_reads,
        &txn_counter,
        free_space.as_ref(),
        walk_adoption_cap(),
    )
    .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}")),
        journal_before,
        "a refused snapshot rewrite must leave the journal ALONE — emptying it on its own \
         is the data-loss window the combined precheck closes"
    );
    assert_eq!(
        fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}")),
        snapshot_before,
        "and the snapshot is untouched too: either both writes land or neither does"
    );
}

/// C17a: the journal's APPEND open followed symlinks, and the
/// guard in front of it is `journal_path.exists()`, which follows
/// them too — so a link whose target exists skipped the creation
/// write that would have REPLACED it, and every subsequent journal
/// record was appended THROUGH the link, outside the cache root.
///
/// **The free-space fixture is not decoration — it is what makes
/// the defect reachable, and writing this test is what proved it.**
/// With plenty of space the cold-rebuild walk's journal reset
/// `atomic_write`s over the path, and its `rename` REPLACES the
/// symlink rather than following it; the victim is safe by
/// accident and `Cache::open` succeeds. The link only survives to
/// the append open when that reset is refused by the watermark
/// (or is planted between the index read and the open). So the
/// watermark refusal is the precondition, and under it the open
/// must fail ELOOP rather than append through.
#[test]
fn a_symlinked_journal_is_refused_and_never_appended_through() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    let outside = ScratchDir::new();
    let victim = outside.0.join("someone-elses-file");
    fs::write(&victim, b"must survive byte for byte").unwrap_or_else(|e| panic!("{e}"));

    let journal_path = dir.0.join("index").join("journal");
    fs::remove_file(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim, &journal_path).unwrap_or_else(|e| panic!("{e}"));

    // Under the watermark, so the walk's journal reset is refused
    // and the planted link is still there when the append open runs.
    let under_watermark: Box<dyn FreeSpace> = Box::new(FixedFreeSpace(FreeSpaceInfo {
        free_bytes: 1,
        capacity_bytes: 2 * 1024 * 1024 * 1024,
    }));
    let opened = Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), under_watermark);
    assert!(
        opened.is_err(),
        "a symlinked journal is tampered state; opening the cache must refuse, never open \
         it for append and write cache records through the link"
    );
    assert_eq!(
        fs::read(&victim).unwrap_or_else(|e| panic!("{e}")),
        b"must survive byte for byte".to_vec(),
        "the victim file must be byte-identical"
    );
    assert!(
        fs::symlink_metadata(&journal_path)
            .unwrap_or_else(|e| panic!("{e}"))
            .file_type()
            .is_symlink(),
        "fixture precondition: the link must still be in place at the append open — if a \
         write replaced it, this test is no longer exercising the defect"
    );
}

/// A DANGLING symlink at `index/journal` must be REFUSED on an
/// ordinary open — one with AMPLE free space, i.e. the open every
/// real deployment performs.
///
/// **The free-space fixture is the whole point of this test, and an
/// under-watermark one hides the defect.** A dangling link at that
/// name classifies as `Untrustworthy` (the `O_NOFOLLOW` read fails
/// `ELOOP`), which sends `load_index` to the cold rebuild — and the
/// rebuild's own snapshot+journal `atomic_write` is a `rename` onto
/// the name, which REPLACES the planted link before any later
/// presence check can ever see it. Under a watermark that rebuild
/// write is refused, the link survives to the append open, and the
/// test passes without exercising the ordinary path at all. So the
/// refusal has to happen BEFORE any rebuild write: `load_index`
/// classifies both index names first and refuses a non-regular
/// entry outright.
///
/// Both halves are asserted: `Cache::open` fails, AND the planted
/// link is still in place with nothing created at its target — a
/// refusal that erased the tampered state on the way to refusing
/// would be the defect wearing a refusal's clothes.
#[test]
fn a_dangling_symlinked_journal_is_refused_rather_than_silently_replaced() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    let outside = ScratchDir::new();
    let never_created = outside.0.join("target-that-does-not-exist");
    assert!(
        fs::symlink_metadata(&never_created).is_err(),
        "fixture precondition: the link's target must NOT exist — a live target makes this \
         test a duplicate of the one below, which is exactly how the gap survived"
    );

    let journal_path = dir.0.join("index").join("journal");
    fs::remove_file(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&never_created, &journal_path).unwrap_or_else(|e| panic!("{e}"));

    // AMPLE space: the ordinary open, with the cold rebuild's own
    // writes fully enabled and nothing suppressing them. The
    // counting seam is the ORDERING observable — the rebuild's
    // snapshot+journal write is gated by the free-space precheck,
    // so a refusal that happens before any rebuild write leaves the
    // query count at zero (`a_foreign_entry_at_the_snapshot_name_…`
    // carries the positive control that this counter does move).
    let counting = CountingFreeSpace::new();
    let opened =
        Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(counting.clone()));
    assert_eq!(
        counting.count(),
        0,
        "the refusal must come BEFORE the cold rebuild's own writes — nothing past the \
         classification may run, because the rebuild's rename replaces the planted entry"
    );
    assert!(
        opened.is_err(),
        "a DANGLING symlink at index/journal is tampered state exactly as a live one is; \
         opening the cache must refuse, never classify it absent and replace it"
    );
    assert!(
        fs::symlink_metadata(&journal_path)
            .unwrap_or_else(|e| panic!("{e}"))
            .file_type()
            .is_symlink(),
        "the planted link must still be in place — if a rebuild write replaced it, the \
         tampered state was erased instead of reported and this is the defect"
    );
    assert!(
        fs::symlink_metadata(&never_created).is_err(),
        "and nothing may have been created AT the link's target either"
    );
}

/// The same rule for the OTHER index name, and for a non-symlink
/// foreign entry: a DIRECTORY at `index/snapshot` must be refused
/// before the rebuild's snapshot write, not walked around.
///
/// This row also carries the POSITIVE CONTROL for the ordering
/// assertion both these tests rest on: after the refusal, the same
/// cache with a merely CORRUPT (not foreign) snapshot is reopened
/// and the free-space counter MUST move — otherwise "the counter
/// stayed at zero" would prove nothing about ordering, only that
/// the seam is never consulted at all.
#[test]
fn a_foreign_entry_at_the_snapshot_name_is_refused_before_any_rebuild_write() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));

    let snapshot_path = dir.0.join("index").join("snapshot");
    fs::remove_file(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    fs::create_dir(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));

    let counting = CountingFreeSpace::new();
    let opened =
        Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(counting.clone()));
    assert!(
        opened.is_err(),
        "a directory at index/snapshot is foreign; the open must refuse rather than treat \
         it as an unreadable snapshot and rebuild over it"
    );
    assert_eq!(
        counting.count(),
        0,
        "and it must refuse BEFORE the cold rebuild's free-space-gated writes"
    );
    assert!(
        fs::symlink_metadata(&snapshot_path)
            .unwrap_or_else(|e| panic!("{e}"))
            .file_type()
            .is_dir(),
        "and the foreign entry must still be there, reported rather than removed"
    );

    // CONTROL: a corrupt-but-REGULAR snapshot is the ordinary
    // rebuild trigger, and it does reach the free-space seam.
    fs::remove_dir(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    fs::write(&snapshot_path, b"not a snapshot").unwrap_or_else(|e| panic!("{e}"));
    counting.reset();
    drop(Cache::open_with_free_space(
        &dir.0,
        1_000_000,
        &origin(),
        Box::new(counting.clone()),
    ));
    assert!(
        counting.count() > 0,
        "control: an ordinary cold rebuild DOES query the free-space seam, so a zero count \
         above is evidence of ordering rather than of an unused seam"
    );
}

/// C15/C29: one FIFO test per hardened OPEN, not one per verb.
/// Root detection refuses first, so an end-to-end FIFO test never
/// reaches this reader — it needs its own. Behind a bounded join,
/// because without `O_NONBLOCK` this call never returns.
#[test]
fn a_fifo_index_file_is_untrustworthy_promptly_rather_than_blocking() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));
    let snapshot_path = dir.0.join("index").join("snapshot");
    fs::remove_file(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    crate::fsguard::testutil::mkfifo(&snapshot_path);

    let probe = snapshot_path.clone();
    let read = crate::fsguard::testutil::within_deadline(
        "read_index_file_bounded on a FIFO snapshot",
        move || read_index_file_bounded(&probe, "snapshot"),
    );
    assert!(
        matches!(read, IndexFileRead::Untrustworthy),
        "a FIFO at an index path is the untrustworthy class, never Absent and never a \
         blocking open"
    );
    let _ = fs::remove_file(&snapshot_path);
}

// ---------------------------------------------- anchor discipline rows

#[test]
fn a_successful_anchor_replacement_fsyncs_its_destination_directory() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let volume = vol("durable-anchor");
    assert_eq!(cache.anchor_directory_fsync_count(), 0);

    cache.raise_anchor(&volume, Some(1), HintUpdate::Unchanged);

    assert_eq!(
        cache.anchor_write_count(),
        1,
        "control: one rename occurred"
    );
    assert_eq!(
        cache.anchor_directory_fsync_count(),
        1,
        "the successful anchor rename must be followed by one destination-directory fsync"
    );
}

#[test]
fn a_fifo_anchor_is_treated_as_absent_without_blocking_the_writer() {
    let dir = ScratchDir::new();
    let volume = vol("fifo-anchor");
    let anchor_path = anchor_path(&dir.0, &volume);
    let mut seeded = open(&dir.0, 1_000_000);
    seeded.raise_anchor(&volume, Some(16), HintUpdate::Unchanged);
    seeded.close().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        fs::symlink_metadata(&anchor_path).is_ok_and(|meta| meta.is_file()),
        "control: the pre-stat anchor entry must be a regular file"
    );

    let hook_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired_by_hook = hook_fired.clone();
    let swapped_path = anchor_path.clone();
    let mut hooks = PATH_READ_POST_STAT_HOOKS
        .lock()
        .unwrap_or_else(|e| panic!("{e}"));
    hooks.push(PathReadPostStatHook {
        path: anchor_path.clone(),
        action: Box::new(move || {
            fs::remove_file(&swapped_path).unwrap_or_else(|e| panic!("{e}"));
            crate::fsguard::testutil::mkfifo(&swapped_path);
            fired_by_hook.store(true, Ordering::SeqCst);
        }),
    });
    drop(hooks);

    let cache_root = dir.0.clone();
    let result = crate::fsguard::testutil::within_deadline(
        "raise_anchor while the writer flock is held and the anchor path is a FIFO",
        move || -> Result<Option<HeadAnchor>, String> {
            let mut cache =
                Cache::open_with_free_space(&cache_root, 1_000_000, &origin(), plenty())
                    .map_err(|e| e.to_string())?;
            let volume = vol("fifo-anchor");
            cache.raise_anchor(&volume, Some(17), HintUpdate::Unchanged);
            Ok(cache.read_anchor(&volume))
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));

    assert!(
        hook_fired.load(Ordering::SeqCst),
        "control: the regular file must have been swapped after stat and before open"
    );
    assert_eq!(result.map(|anchor| anchor.seq), Some(17));
    assert!(
        fs::symlink_metadata(&anchor_path).is_ok_and(|meta| meta.is_file()),
        "the foreign FIFO must be atomically replaced by a regular anchor file"
    );
}

/// An unpersistable REPLACEMENT hint must RETAIN the prior good
/// hint, not erase it — a store that briefly answers a malformed
/// `ETag` (or one that momentarily fails the strict grammar for any
/// other reason) must not cost the reader the last GOOD hint it had.
#[test]
fn an_unpersistable_replacement_keeps_the_prior_good_hint() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("replacement-hint-vol");

    cache.raise_anchor(
        &v,
        Some(5),
        HintUpdate::Replace(PersistedHint {
            seq: 5,
            token: "good".to_owned(),
            stamp_secs: 100,
        }),
    );
    let before = cache
        .read_anchor(&v)
        .and_then(|a| a.hint)
        .unwrap_or_else(|| panic!("a good hint must persist"));
    assert_eq!(before.token, "good");

    // A malformed (space-containing) token — unpersistable, but the
    // floor candidate is unchanged (5) so this call is otherwise a
    // pure hint replacement attempt.
    cache.raise_anchor(
        &v,
        Some(5),
        HintUpdate::Replace(PersistedHint {
            seq: 5,
            token: "bad token".to_owned(),
            stamp_secs: 200,
        }),
    );

    let anchor = cache
        .read_anchor(&v)
        .unwrap_or_else(|| panic!("the anchor must still exist"));
    assert_eq!(anchor.seq, 5, "the floor must be unaffected");
    let hint = anchor
        .hint
        .unwrap_or_else(|| panic!("the PRIOR good hint must survive, not be erased"));
    assert_eq!(
        hint.token, "good",
        "an unpersistable replacement must RETAIN the prior good hint, not erase it"
    );
    assert_eq!(
        hint.stamp_secs, 100,
        "the retained hint must be the OLD one, not a mix with the failed replacement"
    );
}

/// An EMPTY token (the expected shape on an `ETag`-less backend
/// — `granary-store`'s `HintToken(String::new())` fabrication) must
/// not warn; a genuinely MALFORMED non-empty token still does.
#[test]
fn an_empty_token_omits_the_hint_line_without_warning() {
    #[derive(Clone, Default)]
    struct WarnCounter(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCounter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("empty-token-vol");

    let counter = WarnCounter::default();
    let subscriber = tracing_subscriber::registry().with(counter.clone());
    tracing::subscriber::with_default(subscriber, || {
        cache.raise_anchor(
            &v,
            Some(9),
            HintUpdate::Replace(PersistedHint {
                seq: 9,
                token: String::new(),
                stamp_secs: 1,
            }),
        );
    });

    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        0,
        "an EMPTY token is an expected backend state (an ETag-less store), not a warning"
    );
    let anchor = cache
        .read_anchor(&v)
        .unwrap_or_else(|| panic!("the floor must still write"));
    assert_eq!(anchor.seq, 9);
    assert_eq!(
        anchor.hint, None,
        "an unpersistable (empty) token must still omit the hint line"
    );

    // Contrast: a genuinely MALFORMED non-empty token still warns.
    let counter2 = WarnCounter::default();
    let subscriber2 = tracing_subscriber::registry().with(counter2.clone());
    tracing::subscriber::with_default(subscriber2, || {
        cache.raise_anchor(
            &v,
            Some(10),
            HintUpdate::Replace(PersistedHint {
                seq: 10,
                token: "has space".to_owned(),
                stamp_secs: 2,
            }),
        );
    });
    assert_eq!(
        counter2.0.load(Ordering::SeqCst),
        1,
        "a genuinely malformed non-empty token must still warn"
    );
}

/// The anchor floor write is EXEMPT from the free-space
/// watermark — a full-LRU steady state (the ORDINARY case, not an
/// edge case) must never silently disable rollback protection. Contrasted against
/// an ordinary object insert, which the SAME watermark still
/// refuses.
#[test]
fn the_anchor_floor_rises_even_under_the_free_space_watermark() {
    struct NoFreeSpace;
    impl FreeSpace for NoFreeSpace {
        fn free_space(&self) -> io::Result<FreeSpaceInfo> {
            Ok(FreeSpaceInfo {
                free_bytes: 0,
                capacity_bytes: 1_000_000_000,
            })
        }
    }

    let dir = ScratchDir::new();
    let mut cache =
        Cache::open_with_free_space(&dir.0, 1_000_000, &origin(), Box::new(NoFreeSpace))
            .unwrap_or_else(|e| panic!("{e}"));
    let v = vol("watermark-floor-vol");

    cache.raise_anchor(&v, Some(7), HintUpdate::Unchanged);
    assert_eq!(
        cache.read_anchor(&v).map(|a| a.seq),
        Some(7),
        "the anchor floor must rise even when the free-space watermark refuses every \
         other write"
    );

    // Contrast: an ordinary object insert IS still refused by the
    // same watermark — the exemption is anchor-specific, not global.
    let (id, bytes) = id_of(210);
    cache.insert(&id, &bytes);
    assert_eq!(
        cache.get(&id),
        None,
        "an object insert must still be refused by the watermark"
    );
}

/// The anchor render/parse round-trip property, as a seeded deterministic
/// sweep (`granary_core::rng`'s own precedent — a seed and a `below`
/// draw, not the `proptest` crate this workspace has not adopted in
/// this crate) over arbitrary VALID `HeadAnchor`/`PersistedHint`
/// values: `render_anchor_bytes` then `parse_anchor_bytes` must
/// recover the identical value, and re-rendering that must reproduce
/// the identical bytes. The inverse direction from
/// `crate::fuzz_probe::anchor_decode_probe`'s canonical-form check
/// (decode-then-encode, over arbitrary bytes); this is
/// encode-then-decode, over arbitrary VALID values.
#[test]
fn a_seeded_sweep_of_valid_anchors_round_trips_through_render_and_parse() {
    use granary_core::rng::{Rng as _, SeededRng};

    fn random_non_reserved_seq(rng: &mut SeededRng) -> u64 {
        loop {
            // `below` excludes its bound, so `u64::MAX` never comes
            // out of it on its own — only the `0` half of the
            // reserved class needs the retry loop.
            let candidate = rng.below(u64::MAX);
            if !is_reserved_seq(candidate) {
                return candidate;
            }
        }
    }

    fn random_token(rng: &mut SeededRng) -> String {
        let alphabet: Vec<u8> = (ANCHOR_TOKEN_MIN_BYTE..=ANCHOR_TOKEN_MAX_BYTE).collect();
        let max_len_minus_one = u64::try_from(ANCHOR_TOKEN_MAX_LEN - 1).unwrap_or(0);
        let len = usize::try_from(1 + rng.below(max_len_minus_one)).unwrap_or(1);
        let alphabet_len = u64::try_from(alphabet.len()).unwrap_or(1);
        (0..len)
            .map(|_| {
                let idx = usize::try_from(rng.below(alphabet_len)).unwrap_or(0);
                char::from(*alphabet.get(idx).unwrap_or(&ANCHOR_TOKEN_MIN_BYTE))
            })
            .collect()
    }

    // `i64::MAX` fits `u64` exactly (never a truncating cast); the
    // `unwrap_or` branch is unreachable, kept only to avoid an `as`.
    let stamp_ceiling = u64::try_from(i64::MAX).unwrap_or(u64::MAX);

    let mut rng = SeededRng::new(0xA17C_0812);
    for _ in 0..2000 {
        let seq = random_non_reserved_seq(&mut rng);
        let hint = if rng.below(2) == 0 {
            None
        } else {
            Some(PersistedHint {
                seq: random_non_reserved_seq(&mut rng),
                token: random_token(&mut rng),
                stamp_secs: i64::try_from(rng.below(stamp_ceiling)).unwrap_or(0),
            })
        };

        let bytes = render_anchor_bytes(seq, hint.as_ref());
        let decoded = parse_anchor_bytes(&bytes)
            .unwrap_or_else(|| panic!("a value this writer produced must parse back: {seq}"));
        assert_eq!(decoded.seq, seq);
        assert_eq!(decoded.hint, hint);
        let re = render_anchor_bytes(decoded.seq, decoded.hint.as_ref());
        assert_eq!(re, bytes, "render -> parse -> render must be stable");
    }
}

// --------------------------------------------------- mount anchor

/// The mount anchor lives at `anchors/<volume>.mount`. If some
/// volume `V` could be literally named `"<name>.mount"`, its SHARED
/// anchor `anchors/V` would sit at the exact path this crate uses
/// for the MOUNT anchor of the volume named `"<name>"`. Pinned here
/// as a test, not just asserted in a comment: [`VolumeName`]'s
/// DNS-1123 grammar (`[a-z0-9-]` only, `root.rs`'s
/// `volume_name_is_a_dns_1123_label` already covers the general
/// `BadByte` case) has no `.` byte to give a volume name, so this
/// collision is impossible today — this test is what stops a LATER
/// widening of that grammar (e.g. a hierarchical volume name) from
/// silently reopening it.
#[test]
fn a_volume_name_can_never_collide_with_the_mount_anchor_suffix() {
    assert!(
        matches!(
            VolumeName::new("some-volume.mount".to_owned()),
            Err(granary_core::root::VolumeNameError::BadByte { byte: b'.' })
        ),
        "a volume literally named \"<name>.mount\" must be impossible, or the mount \
         anchor's naming scheme can collide with a shared anchor"
    );
}

/// Root eviction refuses a SYMLINKED volume directory.
///
/// `unlink` does not follow its final component, but it follows every
/// intermediate one — the "a NOFOLLOW guard covers one component, not
/// the path" shape this repo already paid for on `UMOUNT_NOFOLLOW`. With
/// `roots/<volume>` planted as a symlink, eviction would delete a file
/// outside the cache entirely. `put_root_bytes` has refused this since
/// it was written; the eviction path is new and needed the same guard.
#[test]
fn root_eviction_refuses_a_symlinked_volume_directory() {
    let dir = ScratchDir::new();
    let outside = ScratchDir::new();
    // The filename is built the SAME way production builds it. A
    // hand-typed literal of the wrong width makes the unlink a no-op and
    // the test passes whether the guard exists or not — which is exactly
    // what the mutation probe caught on the first attempt.
    let victim = outside
        .0
        .join(format!("{:0width$}", 7, width = paths::ROOT_SEQ_WIDTH));
    std::fs::write(&victim, b"a file that belongs to someone else")
        .unwrap_or_else(|e| panic!("{e}"));

    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("evict-vol");
    // Plant the symlink where the volume's root directory would be.
    let roots_dir = dir.0.join("roots");
    std::fs::create_dir_all(&roots_dir).unwrap_or_else(|e| panic!("{e}"));
    let planted = roots_dir.join("evict-vol");
    if planted.exists() {
        std::fs::remove_dir_all(&planted).unwrap_or_else(|e| panic!("{e}"));
    }
    std::os::unix::fs::symlink(&outside.0, &planted).unwrap_or_else(|e| panic!("{e}"));

    cache.evict_root_bytes(&v, 7);

    assert!(
        victim.exists(),
        "eviction followed a symlinked volume directory and deleted a file outside the cache"
    );
}

/// The no-write-when-unchanged skip, made OBSERVABLE. Bytes on disk
/// cannot tell "skipped" from "wrote the identical bytes again", which
/// is exactly why `anchor_writes` exists for the shared anchor; the
/// mount anchor has its own skip and needed its own counter.
#[test]
fn raising_the_mount_anchor_to_an_unchanged_seq_skips_the_write() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("m-skip-vol");

    cache
        .raise_mount_anchor(&v, 9)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cache.mount_anchor_write_count(), 1);

    // Same seq: nothing to do.
    cache
        .raise_mount_anchor(&v, 9)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.mount_anchor_write_count(),
        1,
        "an unchanged seq must SKIP the rename, not rewrite identical bytes"
    );

    // Lower seq: the max is unchanged, so also nothing to do.
    cache
        .raise_mount_anchor(&v, 4)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cache.mount_anchor_write_count(), 1);

    // Higher seq: a real write.
    cache
        .raise_mount_anchor(&v, 11)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cache.mount_anchor_write_count(), 2);
    assert_eq!(cache.read_mount_anchor(&v), Some(11));
}

/// A floor that cannot be written REPORTS, and a reset that cannot
/// happen REPORTS. Both are security-bearing rather than best-effort:
/// the first silently disarms the only rollback defence these modes
/// have, and the second tells an operator a floor is gone when it is
/// not. Built by planting a DIRECTORY where each file belongs.
#[test]
fn a_mount_anchor_write_and_reset_that_cannot_happen_are_reported() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("m-fail-vol");
    let planted = dir.0.join("anchors").join("m-fail-vol.mount");
    std::fs::create_dir_all(&planted).unwrap_or_else(|e| panic!("{e}"));

    let err = cache
        .raise_mount_anchor(&v, 5)
        .expect_err("a floor that cannot be persisted must be reported");
    assert!(
        err.contains("mount-private floor"),
        "the error must name what could not be stored: {err}"
    );

    let err = cache
        .reset_mount_anchor(&v)
        .expect_err("a reset that cannot happen must be reported");
    assert!(
        err.contains("cannot remove"),
        "the error must name the failed action: {err}"
    );
}

/// The DEGRADED refusal of `reset_mount_anchor` is reached the
/// same way three shipped `mount::tests` rows reach degraded mode — a
/// second `Cache::open` on a directory whose writer lock is already held
/// in THIS process. Stable at full suite concurrency (three full runs);
/// the refusal must name `read-only-degraded`, never accept the reset.
#[test]
fn resetting_the_mount_anchor_in_degraded_mode_is_refused_not_silent() {
    let dir = ScratchDir::new();
    let v = vol("m-degraded-vol");
    let _holder = open(&dir.0, 1_000_000);
    let mut degraded = open(&dir.0, 1_000_000);
    assert!(
        degraded.is_read_only_degraded(),
        "the second open must be read-only-degraded, or this test proves nothing"
    );
    let err = degraded
        .reset_mount_anchor(&v)
        .expect_err("a degraded cache cannot clear a floor and must say so");
    assert!(
        err.contains("read-only-degraded"),
        "the refusal must name the condition: {err}"
    );
}

/// An absent-class candidate must not REPLACE a live
/// floor. `parse_anchor_seq` refuses a reserved seq on READ, so
/// persisting one leaves a file that is present and unreadable — the
/// rollback defence silently gone. Pins `raise_mount_anchor`'s
/// `is_reserved_seq` refusal, which nothing else did.
///
/// **The `0` half above constrains nothing on its own.** `v`'s floor
/// is pre-seeded at 5, so `existing.map_or(seq, |e| e.max(seq))` is
/// `max(5, 0) == 5` and the `existing == Some(new_seq)` no-op skip
/// returns before the branch the guard protects is ever reached —
/// `if seq == u64::MAX` (never checking 0 at all) passes this loop
/// identically. `v2` below has NO pre-seeded floor, so
/// `raise_mount_anchor(&v2, 0)` reaches that branch for real. This
/// asserts on the FILE — present-and-unreadable (the narrowed guard)
/// vs. genuinely absent (the real one) — because that is the actual
/// HARM: `parse_anchor_seq` refuses a reserved seq on READ, so a
/// persisted 0 leaves the rollback defence present and unreadable
/// rather than merely unraised. Running the narrowed-guard mutation
/// also moves `mount_anchor_write_count` because it reaches
/// `fetch_add`, so the counter is not the only discriminator. Do NOT
/// read that movement as licence to replace the file-existence
/// assertion with a counter check: the replacement would stop naming
/// the actual harm.
/// The file assertion is therefore load-bearing.
#[test]
fn an_absent_class_candidate_never_replaces_a_live_mount_floor() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("m-reserved-vol");
    cache
        .raise_mount_anchor(&v, 5)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cache.read_mount_anchor(&v), Some(5));
    for candidate in [0_u64, u64::MAX] {
        cache
            .raise_mount_anchor(&v, candidate)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            cache.read_mount_anchor(&v),
            Some(5),
            "candidate {candidate} is absent-class and must not disturb the live floor"
        );
    }

    // A SECOND volume, no pre-seeded floor: the `0` half's real
    // hazard. `existing` starts `None`, so a narrowed guard that only
    // checks `u64::MAX` would let `new_seq = existing.map_or(0, ...) == 0`
    // through to the write, leaving `anchors/<v2>.mount` PRESENT and
    // UNREADABLE (`read_mount_anchor` still answers `None`, because
    // `parse_anchor_seq` refuses a reserved seq on read too — a
    // present-but-unreadable file is worse than an absent one: it
    // looks like a floor was persisted when it was not).
    let v2 = vol("m-reserved-vol-fresh");
    assert_eq!(
        cache.read_mount_anchor(&v2),
        None,
        "fixture precondition: v2 must start with no floor at all"
    );
    cache
        .raise_mount_anchor(&v2, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.read_mount_anchor(&v2),
        None,
        "seq 0 on a volume with no existing floor must still be refused"
    );
    let v2_path = mount_anchor_path(&dir.0, &v2);
    assert!(
        !v2_path.exists(),
        "seq 0 must never even create anchors/<volume>.mount — {} exists",
        v2_path.display()
    );
}

/// `--reset-floor` on an ABSENT floor is success, not an error: absent
/// is the goal state. The control for the test above, which would
/// otherwise pass against an implementation that reports every reset.
#[test]
fn resetting_an_absent_mount_anchor_is_success() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("m-absent-vol");
    cache
        .reset_mount_anchor(&v)
        .unwrap_or_else(|e| panic!("absent is the goal state, not a failure: {e}"));
    assert_eq!(cache.read_mount_anchor(&v), None);
}

#[test]
fn mount_anchor_round_trips_and_keeps_the_monotonic_max() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("anchor-round-trip-vol");

    assert_eq!(
        cache.read_mount_anchor(&v),
        None,
        "no mount anchor exists before the first raise"
    );

    cache
        .raise_mount_anchor(&v, 7)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cache.read_mount_anchor(&v), Some(7));

    cache
        .raise_mount_anchor(&v, 3)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.read_mount_anchor(&v),
        Some(7),
        "a lower candidate must never lower the mount-private floor (monotonic max)"
    );

    cache
        .raise_mount_anchor(&v, 12)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.read_mount_anchor(&v),
        Some(12),
        "a higher candidate must still raise it"
    );
}

/// R3/R6's whole point: the mount-private floor and the shared
/// `gran cat` floor are two independent write sites. Raising either
/// one must never move the other, in either direction.
#[test]
fn the_mount_anchor_and_the_shared_anchor_are_independent() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let v = vol("anchor-independence-vol");

    cache
        .raise_mount_anchor(&v, 9)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cache.read_mount_anchor(&v), Some(9));
    assert_eq!(
        cache.read_anchor(&v),
        None,
        "raising the mount-private floor must not create or move the shared anchor"
    );

    cache.raise_anchor(&v, Some(20), HintUpdate::Unchanged);
    assert_eq!(cache.read_anchor(&v).map(|a| a.seq), Some(20));
    assert_eq!(
        cache.read_mount_anchor(&v),
        Some(9),
        "raising the shared floor must not move the mount-private one, even to a strictly \
         higher seq"
    );
}

/// The mount anchor is a floor and NEVER a hint. A file carrying
/// a `hint` line — a shape this module's OWN renderer can
/// produce for the SHARED anchor — is a grammar deviation for
/// the mount anchor's own narrower grammar and must be refused
/// WHOLE, never accepted with the hint silently dropped.
#[test]
fn a_mount_anchor_file_carrying_a_hint_is_refused_whole() {
    let dir = ScratchDir::new();
    let cache = open(&dir.0, 1_000_000);
    let v = vol("anchor-with-hint-vol");
    let path = mount_anchor_path(&dir.0, &v);

    let bytes = render_anchor_bytes(
        9,
        Some(&PersistedHint {
            seq: 9,
            token: "etag".to_owned(),
            stamp_secs: 100,
        }),
    );
    fs::write(&path, &bytes).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        cache.read_mount_anchor(&v),
        None,
        "a mount anchor carrying a hint line must be refused whole, never accepted with \
         the hint silently ignored"
    );
}

/// The mount anchor reuses the shared anchor's strict grammar
/// wholesale (no second parser). Every malformed shape enumerated by
/// `parse_anchor_bytes` must
/// degrade this file to absent too.
#[test]
fn a_mount_anchor_rejects_every_malformed_shape_the_shared_parser_does() {
    let dir = ScratchDir::new();
    let cache = open(&dir.0, 1_000_000);
    let v = vol("anchor-malformed-vol");
    let path = mount_anchor_path(&dir.0, &v);

    let long_seq = format!("0{}7", "0".repeat(ANCHOR_SEQ_WIDTH));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("short (fewer than 20 digits)", b"seq 7\n".to_vec()),
        (
            "long (more than 20 digits)",
            format!("seq {long_seq}\n").into_bytes(),
        ),
        ("wrong prefix", b"anchor 00000000000000000007\n".to_vec()),
        (
            "trailing bytes after the line",
            b"seq 00000000000000000007\nx".to_vec(),
        ),
        ("no trailing newline", b"seq 00000000000000000007".to_vec()),
        (
            "non-digit in the seq field",
            b"seq 0000000000000000000x\n".to_vec(),
        ),
        (
            "reserved seq zero (absent-class)",
            format!("seq {}\n", "0".repeat(ANCHOR_SEQ_WIDTH)).into_bytes(),
        ),
        (
            "reserved seq u64::MAX (absent-class)",
            format!("seq {}\n", u64::MAX).into_bytes(),
        ),
        ("non-UTF-8 bytes", b"seq 0000000000000000000\xff\n".to_vec()),
    ];

    for (label, bytes) in cases {
        fs::write(&path, &bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            cache.read_mount_anchor(&v),
            None,
            "malformed shape must degrade the whole mount anchor file to absent: {label}"
        );
    }
}

/// The size bound: an over-cap file must read as absent — and it
/// must do so BECAUSE of the size check specifically, not merely as
/// an accident of the strict parse also failing (this format's own
/// legal shapes never exceed ~600 bytes, so any over-cap file also
/// fails the strict grammar regardless — the size check is what
/// stops the read itself from ever growing unbounded on
/// attacker-writable disk, which a bare `None` return cannot show on
/// its own). Asserted by capturing the SPECIFIC warning message
/// `read_anchor_bytes_bounded` emits for the size case, distinct
/// from the generic "failed strict parse" one.
#[test]
fn an_oversized_mount_anchor_is_refused_by_the_size_bound_specifically() {
    #[derive(Clone, Default)]
    struct MessageCapture(Arc<std::sync::Mutex<Vec<String>>>);

    struct MessageVisitor<'a>(&'a mut Option<String>);
    impl tracing::field::Visit for MessageVisitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                *self.0 = Some(format!("{value:?}"));
            }
        }
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for MessageCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                let mut msg = None;
                event.record(&mut MessageVisitor(&mut msg));
                if let Some(m) = msg {
                    self.0.lock().unwrap_or_else(|e| panic!("{e}")).push(m);
                }
            }
        }
    }
    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = ScratchDir::new();
    let cache = open(&dir.0, 1_000_000);
    let v = vol("anchor-oversized-vol");
    let path = mount_anchor_path(&dir.0, &v);

    let cap = usize::try_from(ANCHOR_FILE_MAX_BYTES).unwrap_or(usize::MAX);
    let oversized = vec![b'0'; cap + 1];
    fs::write(&path, &oversized).unwrap_or_else(|e| panic!("{e}"));

    let capture = MessageCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let result = tracing::subscriber::with_default(subscriber, || cache.read_mount_anchor(&v));

    assert_eq!(
        result, None,
        "an over-cap mount anchor file must read as absent"
    );
    let messages = capture.0.lock().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        messages
            .iter()
            .any(|m| m.contains("exceeds the size bound")),
        "the size bound specifically (not an incidental parse failure) must be what \
         refuses an over-cap file; messages seen: {messages:?}"
    );
}

/// A degraded process never writes an anchor of either kind (matches
/// `insert`'s own pattern) — same `Mode::Writer`/`Mode::ReadOnlyDegraded`
/// mechanism [`Cache::raise_anchor`] already uses, reused rather than
/// re-derived.
#[test]
fn raise_mount_anchor_is_a_no_op_in_read_only_degraded_mode() {
    let dir = ScratchDir::new();
    // Held for the whole test (dropped last, declared first) so the
    // second opener below stays degraded throughout.
    let writer = open(&dir.0, 1_000_000);
    let v = vol("anchor-degraded-vol");

    let mut degraded = open_with(&dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        degraded.is_read_only_degraded(),
        "control: the second opener must be degraded"
    );

    degraded
        .raise_mount_anchor(&v, 5)
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        degraded.read_mount_anchor(&v),
        None,
        "a degraded process must never write a mount anchor"
    );
    assert_eq!(
        writer.read_mount_anchor(&v),
        None,
        "the writer sees no mount anchor either, proving the degraded call truly wrote \
         nothing rather than writing somewhere the degraded handle itself cannot see"
    );
}

// ---------------------------------------------------- open_for_verify

#[test]
fn open_for_verify_loads_a_trusted_index_when_the_lock_is_free() {
    let dir = ScratchDir::new();
    let (id1, b1) = id_of(60);
    let mut cache = open(&dir.0, 1_000_000);
    cache.insert(&id1, &b1);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let vc = Cache::open_for_verify(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let VerifyCache::WithIndex { index, .. } = vc else {
        panic!("expected index mode when the lock is free");
    };
    let VerifyIndex::Trusted(index) = index else {
        panic!("a healthy cache's index must be TRUSTED, not reported as damaged: {index:?}");
    };
    assert!(index.entries.iter().any(|(id, _)| *id == id1));
}

#[test]
fn open_for_verify_is_report_only_when_the_lock_is_held() {
    let dir = ScratchDir::new();
    let holder = open(&dir.0, 1_000_000); // keep the writer lock held

    let vc = Cache::open_for_verify(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(vc, VerifyCache::ReportOnly),
        "a held lock must yield report-only, never a block or a mutation"
    );
    drop(holder);
}

#[test]
fn open_for_verify_creates_nothing_on_a_bare_directory() {
    let dir = ScratchDir::new(); // exists, but no marker/lock/etc.
    let err = Cache::open_for_verify(&dir.0)
        .expect_err("a bare directory with no cache marker must be refused");
    assert!(
        matches!(err, CacheError::Incompatible { .. }),
        "got {err:?}"
    );
    assert!(
        !dir.0.join("lock").exists(),
        "open_for_verify must create nothing"
    );
    assert!(
        !dir.0.join("index").exists(),
        "open_for_verify must create nothing"
    );
}

/// The spec-named negative: a FOREIGN tuple must be
/// refused through THIS entry point specifically, not merely
/// through `open`.
#[test]
fn a_foreign_tuple_is_refused_through_open_for_verify() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000)); // establish a real cache + marker

    let marker_path = dir.0.join(MARKER_NAME);
    let contents = fs::read_to_string(&marker_path).unwrap_or_else(|e| panic!("{e}"));
    let tampered = contents.replacen("chunker ", "chunker FOREIGN-", 1);
    assert_ne!(
        contents, tampered,
        "the test must actually change the tuple"
    );
    fs::write(&marker_path, tampered).unwrap_or_else(|e| panic!("{e}"));

    let err = Cache::open_for_verify(&dir.0)
        .expect_err("a foreign chunker tuple must be refused through open_for_verify");
    assert!(
        matches!(err, CacheError::Incompatible { .. }),
        "got {err:?}"
    );
}

/// `open_for_verify`'s whole point on the origin line: its VALUE is
/// never compared — only its presence and shape. A marker whose
/// origin differs from anything (there is no `CacheOrigin` argument
/// to differ FROM) must still open cleanly.
#[test]
fn open_for_verify_ignores_the_origin_value() {
    let dir = ScratchDir::new();
    let odd_origin = CacheOrigin {
        endpoint_url: "https://totally-different.invalid/".to_owned(),
        pin_set_digest: [0x99; 32],
        root_key_id: Some([0x77; 32]),
    };
    drop(open_with(&dir.0, 1_000_000, &odd_origin).unwrap_or_else(|e| panic!("{e}")));

    let vc = Cache::open_for_verify(&dir.0)
        .unwrap_or_else(|e| panic!("an unusual-but-well-formed origin must still open: {e}"));
    assert!(matches!(vc, VerifyCache::WithIndex { .. }));
}

#[test]
fn open_for_verify_refuses_a_missing_origin_line() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));
    let marker_path = dir.0.join(MARKER_NAME);
    let contents = fs::read_to_string(&marker_path).unwrap_or_else(|e| panic!("{e}"));
    let tuple_only: String = contents.lines().take(3).collect::<Vec<_>>().join("\n") + "\n";
    fs::write(&marker_path, tuple_only).unwrap_or_else(|e| panic!("{e}"));

    let err =
        Cache::open_for_verify(&dir.0).expect_err("a marker with no origin line must be refused");
    assert!(
        matches!(err, CacheError::Incompatible { .. }),
        "got {err:?}"
    );
}

#[test]
fn open_for_verify_refuses_a_symlinked_lock() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));
    let outside = ScratchDir::new();
    let outside_file = outside.0.join("do-not-touch");
    fs::write(&outside_file, b"must survive").unwrap_or_else(|e| panic!("{e}"));
    fs::remove_file(dir.0.join("lock")).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&outside_file, dir.0.join("lock")).unwrap_or_else(|e| panic!("{e}"));

    let err =
        Cache::open_for_verify(&dir.0).expect_err("a symlinked lock must be refused (O_NOFOLLOW)");
    assert!(matches!(err, CacheError::Io { .. }), "got {err:?}");
    assert_eq!(
        fs::read(&outside_file).unwrap_or_else(|e| panic!("{e}")),
        b"must survive"
    );
}

/// `open_for_verify`'s own symlinked-`objects/` guard — checked
/// before `lock` is even opened, so the refusal happens whether or
/// not anyone would otherwise win the lock.
#[test]
fn open_for_verify_refuses_a_symlinked_objects_dir() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));
    fs::remove_dir_all(dir.0.join("objects")).unwrap_or_else(|e| panic!("{e}"));
    let elsewhere = ScratchDir::new();
    std::os::unix::fs::symlink(&elsewhere.0, dir.0.join("objects"))
        .unwrap_or_else(|e| panic!("{e}"));

    let err = Cache::open_for_verify(&dir.0)
        .expect_err("a symlinked objects/ must be refused, not walked");
    assert!(matches!(err, CacheError::Io { .. }), "got {err:?}");
}

/// The `index/` half of the same guard.
#[test]
fn open_for_verify_refuses_a_symlinked_index_dir() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));
    fs::remove_dir_all(dir.0.join("index")).unwrap_or_else(|e| panic!("{e}"));
    let elsewhere = ScratchDir::new();
    std::os::unix::fs::symlink(&elsewhere.0, dir.0.join("index")).unwrap_or_else(|e| panic!("{e}"));

    let err = Cache::open_for_verify(&dir.0)
        .expect_err("a symlinked index/ must be refused, not read or written through");
    assert!(matches!(err, CacheError::Io { .. }), "got {err:?}");
}

/// `txn/` is refused on the same terms as `objects/` and `index/`,
/// and this row exists to keep the guard TOTAL over the structural
/// directories rather than over the ones an exploit was written for
/// first. `atomic_write` stages the reconciled snapshot here, so a
/// symlinked `txn/` puts a verify-authored temp file inside the
/// linked-to directory even though the rename destination is
/// separately guarded.
#[test]
fn open_for_verify_refuses_a_symlinked_txn_dir() {
    let dir = ScratchDir::new();
    drop(open(&dir.0, 1_000_000));
    fs::remove_dir_all(dir.0.join("txn")).unwrap_or_else(|e| panic!("{e}"));
    let elsewhere = ScratchDir::new();
    let victim = elsewhere.0.join("keep-me");
    fs::write(&victim, b"untouched").unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&elsewhere.0, dir.0.join("txn")).unwrap_or_else(|e| panic!("{e}"));

    let err = Cache::open_for_verify(&dir.0)
        .expect_err("a symlinked txn/ must be refused, not staged through");
    assert!(matches!(err, CacheError::Io { .. }), "got {err:?}");
    assert!(
        victim.exists(),
        "the refusal must happen before anything is staged in the linked-to directory"
    );
}

// -------------------------------------------- load_index_read_only

#[test]
fn load_index_read_only_never_rewrites_a_corrupt_snapshot() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id1, b1) = id_of(70);
    cache.insert(&id1, &b1);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let snapshot_path = dir.0.join("index").join("snapshot");
    fs::write(&snapshot_path, b"not a valid snapshot").unwrap_or_else(|e| panic!("{e}"));
    let before = fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));

    // NOT "folds to empty" any more — that WAS the false-clean.
    // A snapshot that exists and cannot be decoded is reported.
    match load_index_read_only(&dir.0) {
        VerifyIndex::Untrusted { rel_path, .. } => assert_eq!(rel_path, "index/snapshot"),
        VerifyIndex::Trusted(state) => panic!(
            "a corrupt snapshot must never read as a trustworthy index — folding it to \
             empty is what let a damaged cache verify clean: {:?}",
            state.entries
        ),
    }
    let after = fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(before, after, "load_index_read_only must never write");
}

/// A TORN TAIL is not the same as an untrustworthy journal.
/// `decode_journal` reports exactly how far the clean prefix runs,
/// and the fold uses only that — so the pair is still TRUSTED and
/// the trusted prefix is what gets compared. Nothing truncates the
/// file: the torn tail is the next WRITER's business, and this path
/// has no writer.
#[test]
fn a_torn_journal_tail_is_trusted_up_to_its_clean_prefix() {
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 1_000_000);
    let (id1, b1) = id_of(80);
    let (id2, b2) = id_of(81);
    cache.insert(&id1, &b1);
    cache.insert(&id2, &b2);
    force_flush(&mut cache);
    drop(cache); // leave the guard present

    let journal_path = dir.0.join("index").join("journal");
    let mut bytes = fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    let insert_record_len = 1 + DIGEST_LEN + 4 + 4; // tag + digest + size + check
    let second_record_end = cacheindex::ENVELOPE_LEN + insert_record_len * 2;
    if let Some(b) = bytes.get_mut(second_record_end - 1) {
        *b ^= 0xFF;
    }
    fs::write(&journal_path, &bytes).unwrap_or_else(|e| panic!("{e}"));

    let before = fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    let VerifyIndex::Trusted(index) = load_index_read_only(&dir.0) else {
        panic!("a torn TAIL is a decodable prefix, not an untrustworthy journal");
    };
    assert!(
        index.entries.iter().any(|(id, _)| *id == id1),
        "the trusted prefix must survive"
    );
    assert!(
        !index.entries.iter().any(|(id, _)| *id == id2),
        "the torn record must not be adopted"
    );
    assert_eq!(
        fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}")),
        before,
        "and the tear is left exactly as found — this path never truncates"
    );
}

const fn assert_send<T: Send>() {}
const fn assert_send_sync_static<T: Send + Sync + 'static>() {}

#[test]
fn a_cache_can_live_in_a_fuse_filesystem() {
    // `fuser::Filesystem` is `Send + Sync + 'static`. The mount holds the
    // cache behind one mutex, so `Cache: Send` is the load-bearing half;
    // `Mutex<Cache>` supplies `Sync`.
    assert_send::<Cache>();
    assert_send_sync_static::<std::sync::Mutex<Cache>>();
}

#[test]
fn a_cache_error_reports_the_class_its_own_variant_names() {
    let io = CacheError::Io {
        context: String::new(),
        source: io::Error::from(io::ErrorKind::PermissionDenied),
    };
    let incompatible = CacheError::Incompatible {
        detail: String::new(),
    };
    assert_eq!(
        io.failure_class(),
        crate::FailureClass::Io,
        "cache error class: io"
    );
    assert_eq!(
        incompatible.failure_class(),
        crate::FailureClass::Refused,
        "cache error class: incompatible"
    );
}

#[test]
fn bundle_projection_uses_writer_counters_or_degraded_tag_without_io() {
    use granary_core::support::BundleCache;
    let dir = ScratchDir::new();
    let mut cache = open(&dir.0, 17);
    let Mode::Writer(writer) = &mut cache.mode else {
        panic!("writer fixture unavailable");
    };
    writer.total_bytes = 19;
    writer.journal_len = 23;
    writer.live.insert(GrainId::of(b"first-object"), (1, 3));
    writer.live.insert(GrainId::of(b"second-object"), (2, 5));
    cache.root = PathBuf::from("not-an-existing-cache-root");
    assert!(
        cache.bundle_projection()
            == BundleCache::Writer {
                quota_bytes: 17,
                total_bytes: 19,
                live_objects: 2,
                journal_bytes: 23
            },
        "support cache projection lost or inferred counters"
    );
    cache.mode = Mode::ReadOnlyDegraded;
    assert!(
        cache.bundle_projection() == BundleCache::ReadOnlyDegraded,
        "degraded cache invented writer counters"
    );
}
