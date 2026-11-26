// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::mount` — the mount session: what
//! a read-only FUSE mount trusts, and how it resolves its
//! own head once, at open time, rather than on every read.
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
use granary_core::cacheindex::{self, Record};
use granary_core::hash::DIGEST_LEN;
use granary_core::identity::WriterIdentity;
use granary_core::root::{self, ED25519_SIG_LEN, KEY_ID_LEN, RootDoc, RootSig, Timestamp};
use granary_core::rootstore::{RootStoreError, filter_above};
use granary_store::backend::GranaryStore;
use granary_store::crypto::SigningKey;
use object_store::memory::InMemory;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cache::JOURNAL_COMPACT_RECORDS;
use crate::publish::{Policy, publish};
use crate::store::Store;

use crate::overlay_test_support::{
    Authority, AuthorityState, Entropy, FILE_CONTENT, Paths, PublishedTree, RangeFault,
    RangeReadPause, ReleaseAnswer, ScratchDir, Time, input, mounted_operation_tree, origin,
    remote_handle, runtime_workspace_scratch, stamp, test_process_id, vol, write_operation_source,
};
#[cfg(target_os = "linux")]
use crate::overlay_test_support::{WritableFixtureCore, writable_fixture_core};

// -------------------------------------------------- counting remote

/// The counters [`CountingRemote`] updates, held behind an `Arc` so
/// a test can keep reading them after the wrapper itself has been
/// MOVED into `MountSession::open` and dropped on that function's
/// return (every call takes `remote` by value) — rows 5 and 13
/// both need the count AFTER `open` has already returned `Err`.
#[derive(Default)]
struct Counts {
    root: AtomicU64,
    meta: AtomicU64,
    bin: AtomicU64,
    fail_root: AtomicBool,
    shed_root: AtomicBool,
}

impl Counts {
    /// Every `get_root` call from here on fails with a transport
    /// error rather than reaching the wrapped store.
    fn fail_root_calls(&self) {
        self.fail_root.store(true, Ordering::SeqCst);
    }

    /// Every `get_root` call from here on is shed with a `503` the store
    /// answers rather than reaching the wrapped store.
    fn shed_root_calls(&self) {
        self.shed_root.store(true, Ordering::SeqCst);
    }

    /// The count this file's rows 5 and 13 assert on: every ROOT,
    /// META and BIN call this wrapper saw — never only one counter, or
    /// a wrapper that widens with a NEW call kind would silently stop
    /// being counted by an assertion that only reads the old counters.
    ///
    /// `max_seq` and `read_hint` are deliberately NOT counted: they are
    /// head DISCOVERY, not the fetching whose absence rows 5 and 13
    /// assert. Widening this to "every call" would make row 5's
    /// expected count depend on whether the test discovered or named
    /// its seq, which is not the property either row is about.
    fn total(&self) -> u64 {
        self.root.load(Ordering::SeqCst)
            + self.meta.load(Ordering::SeqCst)
            + self.bin.load(Ordering::SeqCst)
    }
}

/// A thin delegating `RootStore + BinStore` wrapper counting every
/// call by kind, and able to fail `get_root` on demand — this file's
/// rows 5, 10 and 13 all need to observe or control exactly how
/// many, and which, store calls a mount made.
struct CountingRemote<'a, R> {
    inner: &'a R,
    counts: Arc<Counts>,
    metrics: Option<crate::ClientMetrics>,
}

impl<'a, R> CountingRemote<'a, R> {
    /// Returns the wrapper (to hand to `MountSession::open`,
    /// consuming it) alongside a `Counts` handle the caller keeps
    /// for itself.
    fn new(inner: &'a R) -> (Self, Arc<Counts>) {
        let counts = Arc::new(Counts::default());
        (
            Self {
                inner,
                counts: Arc::clone(&counts),
                metrics: None,
            },
            counts,
        )
    }
}

impl<R: RootStore> RootStore for CountingRemote<'_, R> {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        unimplemented!("the mount never writes")
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.counts.root.fetch_add(1, Ordering::SeqCst);
        if self.counts.fail_root.load(Ordering::SeqCst) {
            return Err(RootStoreError::Backend(
                "CountingRemote: get_root armed to fail".to_owned(),
            ));
        }
        if self.counts.shed_root.load(Ordering::SeqCst) {
            return Err(RootStoreError::Unavailable {
                operation: "GET root",
                status: 503,
            });
        }
        self.inner.get_root(volume, seq).await
    }

    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        self.inner.read_hint(volume, cached).await
    }

    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        unimplemented!("the mount never writes")
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        self.inner.max_seq(volume).await
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.inner.max_seq_above(volume, floor).await
    }
}

impl<R: BinStore> BinStore for CountingRemote<'_, R> {
    async fn put_bin(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        unimplemented!("the mount never writes")
    }

    async fn put_meta(
        &self,
        _volume: &str,
        _id: &GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        unimplemented!("the mount never writes")
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.counts.meta.fetch_add(1, Ordering::SeqCst);
        self.inner.get_meta(volume, id).await
    }

    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        self.counts.bin.fetch_add(1, Ordering::SeqCst);
        if let Some(metrics) = &self.metrics {
            metrics.record_transport(crate::ByteDirection::Up, 7);
        }
        self.inner.get_bin_range(digest, offset, len).await
    }
}

fn scratch_cache_dir() -> ScratchDir {
    ScratchDir::new()
}

// ------------------------------------------------ row 2: no trust mode is refused

/// NEGATIVE: no trust mode given is refused, and the message names
/// all three.
#[test]
fn no_trust_mode_is_refused_naming_all_three() {
    let tree = PublishedTree::publish("no-trust-mode");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let err = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("zero trust modes must be refused");

    assert!(
        matches!(err, MountError::NoTrustMode),
        "got {err:?}, wanted MountError::NoTrustMode"
    );
    let message = err.to_string();
    for flag in ["--root-key", "--manifest-root", "--trust-server"] {
        assert!(
            message.contains(flag),
            "the no-trust-mode message must name {flag}: {message}"
        );
    }
}

// ------------------------------------------------ row 3: conflicting trust modes are refused

/// NEGATIVE: two modes given is refused.
#[test]
fn two_trust_modes_given_together_is_refused() {
    let tree = PublishedTree::publish("two-trust-modes");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let err = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        // The CORRECT pin, deliberately: with a wrong one the trust
        // gate could be deleted entirely and this row would still pass,
        // on the pin mismatch further down rather than on the gate.
        // Executed with and without the gate —
        // with the gate removed and this pin correct, `open` returns Ok
        // and the mount silently accepts two trust modes at once.
        Some(tree.manifest_root),
        true, // trust_server AND manifest_root both given
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("two trust modes together must be refused");

    assert!(
        matches!(err, MountError::ConflictingTrustModes),
        "got {err:?}, wanted MountError::ConflictingTrustModes"
    );
}

// ------------------------------------------------ row 4: trust-server cannot allow_other

/// NEGATIVE: `--trust-server` with `allow_other` is refused.
#[test]
fn trust_server_with_allow_other_is_refused() {
    let tree = PublishedTree::publish("trust-server-allow-other");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let err = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions {
            allow_other: true,
            allow_root: false,
        },
        &mut sink,
    )
    .expect_err("--trust-server --allow-other must be refused");

    assert!(
        matches!(
            err,
            MountError::MachineWideRequiresRootKey {
                option: "allow_other"
            }
        ),
        "got {err:?}, wanted MachineWideRequiresRootKey{{option: \"allow_other\"}}"
    );
}

// ------------------------------------------------ row 9: neither keyless mode can share the mount

/// NEGATIVE: `--manifest-root --allow-other` is refused, and so is
/// `--trust-server --allow-other`. A mount carrying `allow_other`
/// is machine-wide and machine-wide requires `--root-key` —
/// **in BOTH keyless modes, not only `--trust-server`** (trap 1):
/// an implementation that checks only `TrustServer` (as row 4's
/// GREEN step deliberately left this) passes row 4 while letting
/// `--manifest-root --allow-other` expose a keyless mount to every
/// local user.
#[test]
fn manifest_root_with_allow_other_is_refused_too() {
    let tree = PublishedTree::publish("manifest-root-allow-other");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let err = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        Some(tree.manifest_root),
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions {
            allow_other: true,
            allow_root: false,
        },
        &mut sink,
    )
    .expect_err("--manifest-root --allow-other must be refused too");

    assert!(
        matches!(
            err,
            MountError::MachineWideRequiresRootKey {
                option: "allow_other"
            }
        ),
        "got {err:?}, wanted MachineWideRequiresRootKey{{option: \"allow_other\"}}"
    );
}

/// `allow_root` is the OTHER half of the machine-wide set, and it had
/// no coverage at all: every other test builds `MountOptions::default()`
/// or sets `allow_root: false`, so the guard could be deleted with the
/// whole suite green and a keyless mount exposed to root. Both options
/// x both keyless modes, in one loop, so adding a third machine-wide
/// option cannot quietly go untested on one axis.
#[test]
fn every_machine_wide_option_is_refused_in_both_keyless_modes() {
    for (name, options) in [
        (
            "allow_other",
            MountOptions {
                allow_other: true,
                allow_root: false,
            },
        ),
        (
            "allow_root",
            MountOptions {
                allow_other: false,
                allow_root: true,
            },
        ),
    ] {
        for keyless in ["--manifest-root", "--trust-server"] {
            let tree = PublishedTree::publish("machine-wide-option");
            let cache_dir = scratch_cache_dir();
            let mut sink = Vec::new();
            let (pin, trust_server) = if keyless == "--manifest-root" {
                (Some(tree.manifest_root), false)
            } else {
                (None, true)
            };
            let err = MountSession::open(
                tree.remote,
                tree.volume,
                None,
                pin,
                trust_server,
                None,
                &cache_dir.0,
                1_000_000,
                &origin(),
                options,
                &mut sink,
            )
            .err()
            .unwrap_or_else(|| {
                panic!("{keyless} {name} must be refused: machine-wide requires --root-key")
            });
            let MountError::MachineWideRequiresRootKey { option } = err else {
                panic!("{keyless} {name}: wanted MachineWideRequiresRootKey, got {err:?}");
            };
            assert_eq!(option, name, "the refusal must name the option it refused");
        }
    }
}

// ------------------------------------------------ row 1: all trust modes mount and read

/// Each of the three modes mounts a published tree and reads a
/// file's bytes. `--root-key`'s share of the row.
#[test]
fn root_key_mode_mounts_and_reads_a_file() {
    let tree = PublishedTree::publish("root-key-mount");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();
    let metrics = crate::metrics::tests::metrics();

    let (mut remote, counts) = CountingRemote::new(&tree.remote);
    metrics.set_available(crate::MetricsGroup::Transport, true);
    remote.metrics = Some(metrics.clone());
    let mut session = MountSession::open(
        remote,
        tree.volume,
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("root-key mode must mount a healthy tree: {e}"));

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("fetch_grain must read the file's bytes back: {e}"));
    assert_eq!(bytes, FILE_CONTENT);
    let report = session
        .metrics()
        .expect("session must retain its recorder")
        .snapshot()
        .unwrap()
        .render_prometheus()
        .unwrap();
    let offered = counts.bin.load(Ordering::SeqCst) * 7;
    assert!(offered > 0, "the fixture must exercise transport");
    assert!(
        report.contains(&format!("direction=\"up\"}} {offered}\n")),
        "transport and cache must share a recorder: {report}"
    );
    assert!(
        report.contains("metrics_available{group=\"cache\"} 1\n"),
        "{report}"
    );
    let startup = report
        .lines()
        .find(|line| {
            line.starts_with(
                "granary_client_cache_lookups_total{phase=\"startup\",result=\"miss\"}",
            )
        })
        .and_then(|line| line.rsplit_once(' '))
        .and_then(|(_, value)| value.parse::<u64>().ok());
    assert!(
        startup.is_some_and(|value| value > 0),
        "startup observations must precede the phase reset: {startup:?}; {report}"
    );
    assert!(
        report.contains("cache_lookups_total{phase=\"read\",result=\"miss\"} 1\n"),
        "{report}"
    );
    assert!(
        metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
            .contains("cache_lookups_total{phase=\"read\",result=\"miss\"} 1\n")
    );
}

/// Opening a mount must maintain an already oversized cache journal.
/// The long-lived mount writer must call `Cache::maintain()`.
/// The cache directory here is seeded, BEFORE `MountSession::open` ever touches it, with a journal
/// already over `JOURNAL_COMPACT_RECORDS` — the same raw-append recipe
/// `cache.rs`'s own `seed_cache_over_the_compaction_threshold` fixture
/// uses (a live session's own inline compaction on append would
/// immediately undo an over-threshold journal built through ordinary
/// `insert`/`get`, so the extra records are appended directly to the
/// physical file instead).
///
/// The on-disk journal length alone cannot tell "wired `maintain()`
/// compacted it" apart from "the inline append trigger compacted it
/// during the mount's own preamble resolution" — a real mount's
/// resolve caches grains of its own, and either a MISS it populates
/// or a HIT it touches can reach the inline append trigger just as
/// readily as `maintain()` can, at whatever point resolve happens to
/// touch the cache first. `Cache::maintain_call_count` (a
/// `#[cfg(test)]` accessor mirroring `anchor_write_count`'s own
/// idiom) pins the WIRING directly and unambiguously instead: it
/// counts entries into `Cache::maintain` specifically, which only
/// `MountSession::open`'s new call can produce.
#[test]
fn mount_session_open_compacts_an_already_over_threshold_journal() {
    let tree = PublishedTree::publish("over-threshold-journal");
    let cache_dir = scratch_cache_dir();
    let seed_id = GrainId::of(b"cache maintenance seed object");
    let seed_bytes = b"cache maintenance seed object".to_vec();
    {
        let mut seed =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seed.insert(&seed_id, &seed_bytes); // one durable object + one Insert record
        seed.close().unwrap_or_else(|e| panic!("{e}"));
    }
    let journal_path = cache_dir.0.join("index").join("journal");
    let mut journal_bytes = std::fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    // 1 (the insert above) + JOURNAL_COMPACT_RECORDS touches = one
    // more than the threshold, every one a valid, replayable touch
    // of a LIVE id — matching `seed_cache_over_the_compaction_threshold`'s
    // own recipe in `cache.rs`.
    for _ in 0..JOURNAL_COMPACT_RECORDS {
        cacheindex::encode_record_into(&mut journal_bytes, &Record::Touch { id: seed_id });
    }
    std::fs::write(&journal_path, &journal_bytes).unwrap_or_else(|e| panic!("{e}"));
    let oversized_len = std::fs::metadata(&journal_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert!(
        oversized_len > cacheindex::ENVELOPE_LEN as u64,
        "control: the fixture must be oversized before MountSession::open ever touches it"
    );

    let mut sink = Vec::new();
    let session = MountSession::open(
        tree.remote,
        tree.volume,
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("MountSession::open over a healthy tree must succeed: {e}"));

    assert_eq!(
        session
            .cache
            .as_ref()
            .unwrap_or_else(|| panic!("session must still hold its cache"))
            .maintain_call_count(),
        1,
        "MountSession::open must call Cache::maintain() exactly once"
    );
    // NOT an exact envelope-only check: a real mount's own preamble
    // resolution caches grains of its own (a MISS the fetcher
    // populates, or a HIT `touch_id` records), and either one can
    // ALSO reach the inline compaction trigger the instant it appends —
    // which this fixture's already-over-threshold journal invites
    // just as readily as `maintain()` does. That is not a bug: it
    // only means this particular fixture does not isolate WHICH
    // mechanism got there first, which is exactly why
    // `maintain_call_count` above, not this byte count, is what
    // pins the wiring. What this can still assert honestly is the
    // END STATE: the oversized journal must not have survived
    // `MountSession::open` untouched.
    let compacted_len = std::fs::metadata(&journal_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    assert!(
        compacted_len < oversized_len,
        "the already-over-threshold journal must not still be oversized by the time \
         MountSession::open returns (before={oversized_len}, after={compacted_len})"
    );
}

/// The structure map must have only one resident copy: `snapshot()`
/// MOVES the structure map into the `Snapshot` — after
/// it, the session's own copy is empty. A non-empty
/// `pre.nodes` here is a second resident copy.
#[test]
fn snapshot_moves_the_structure_map_rather_than_cloning_it() {
    let tree = PublishedTree::publish_nested("snapshot-moves-structure-map");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();
    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        session.structure_node(&tree.manifest_root).is_some(),
        "resident before snapshot()"
    );
    // ASSERT THE FIXTURE before relying on it: this row's whole
    // discriminating power is that the map holds MORE than the
    // root, so a walk that deleted only the root's entry would
    // leave something behind. On the single-node shape the other
    // rows use, it would not.
    assert!(
        session.structure_node_count() > 1,
        "the nested fixture must publish more than one structure node, \
         or emptying the map cannot be told from removing the root: {}",
        session.structure_node_count()
    );
    let _snap = session
        .snapshot(AttrPolicy { uid: 0, gid: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        session.structure_node(&tree.manifest_root).is_none(),
        "snapshot() must MOVE the structure map out, not clone it"
    );
    // The id lookup above cannot establish this. A walk that cloned
    // the map and removed just the root's entry answers `None` to
    // it while leaving every OTHER node doubly resident — which is
    // the whole defect. The count catches that, and it catches it
    // only because this row publishes the NESTED fixture: on the
    // one-file tree the other rows use, emptying the map and
    // deleting its single entry are indistinguishable, and this
    // assertion passed that mutant when it was first written.
    assert_eq!(
        session.structure_node_count(),
        0,
        "snapshot() must leave the session's map EMPTY, not merely \
         missing the root: a clone that removes one id is not a move"
    );
}

/// The CLI's own use: `snapshot()` is the bridge `open`'s
/// `Preamble` never needed until now — proves it indexes the SAME
/// tree `open` already resolved, not an empty or wrongly-rooted
/// one, by looking the published file up BY NAME through the
/// built `Snapshot` and checking the leaf id it returns is the
/// file `open`/`fetch_grain` already proved readable.
#[test]
fn snapshot_indexes_the_resolved_tree_by_name() {
    let tree = PublishedTree::publish("snapshot-by-name");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("root-key mode must mount a healthy tree: {e}"));

    let snap = session
        .snapshot(AttrPolicy { uid: 0, gid: 0 })
        .unwrap_or_else(|e| panic!("snapshot() must index the already-resolved tree: {e}"));
    let entry = snap
        .lookup(&tree.manifest_root, b"f.txt")
        .unwrap_or_else(|e| panic!("f.txt must be found under the manifest root: {e:?}"));
    let granary_core::manifest::EntryKind::File { grains, .. } = &entry.kind else {
        panic!("f.txt must decode as a File entry, got {:?}", entry.kind);
    };
    let granary_core::manifest::FileGrains::Inline(refs) = grains else {
        panic!(
            "a {}-byte file must be inline, got {grains:?}",
            FILE_CONTENT.len()
        );
    };
    let [only] = refs.as_slice() else {
        panic!("a single-chunk file must carry exactly one inline ref, got {refs:?}");
    };
    assert_eq!(
        only.id, tree.file_id,
        "the content grain snapshot() names for f.txt must be the SAME grain \
         open()/fetch_grain already proved readable — a snapshot built from the wrong \
         tree, or with nodes and manifest_root out of sync, would pass Snapshot::new's \
         own structural checks and still name the wrong content grain"
    );
}

/// A mutation against
/// the test above — clearing `pre.nodes` entirely
/// BEFORE `Snapshot::new` is built, so `Snapshot::new` itself
/// receives an empty map (`snapshot()`'s own `std::mem::take` also
/// empties the session's map before the callee runs, but hands the
/// callee the ORIGINAL — the difference is which map the callee
/// gets, not when the session's is emptied) — dies at the
/// `unwrap_or_else` panic on `snapshot()`'s own call, a reachable
/// node absent from the map being `Snapshot::new`'s OWN structural
/// refusal, before ever reaching the `assert_eq!` that is the
/// sibling test's actual headline claim. The kill is legitimate,
/// but it kills for the WRONG reason, and no tested
/// mutation reached the id assertion. **None exists to
/// find**: `MountSession::snapshot` is five lines with no branch
/// to mutate — it only assembles `Snapshot::new`'s arguments — and
/// every one of `manifest_root: GrainId`, `timestamp: Timestamp`,
/// `tree: TreeStats` and `policy: AttrPolicy` is a different type,
/// so there is no argument-swap mutant either. Emptying,
/// truncating or clearing `nodes` BEFORE the call all die at the
/// identical gate. (`snapshot()` itself empties `self.pre.nodes`,
/// by `std::mem::take` — but AFTER handing `Snapshot::new` the
/// original, non-empty map, not before. That is a different
/// operation from this mutation and does not die here:
/// `Snapshot::new` still gets a full map, and the sibling test
/// still passes.)
///
/// So this constructs the scenario the sibling's own doc names
/// directly — "nodes and `manifest_root` out of sync" — from OUTSIDE
/// `snapshot()`, the way a real integration defect between
/// `resolve.rs`'s `Preamble` construction and this bridge could:
/// overwrite the REAL root directory node's bytes (same key,
/// `tree.manifest_root`) with a DIFFERENT, but still perfectly
/// well-formed, single-entry `DirLeaf` naming "f.txt" against an
/// unrelated grain. `Snapshot::new` never re-hashes a node's bytes
/// against the id that supposedly names them — that check runs at
/// FETCH time, in `resolve.rs`'s own walk, not here — so it accepts
/// the swap, structurally valid, and STILL names the wrong content
/// grain. This is the id assertion, reached and failing for real,
/// proving the sibling's claim is not aspirational.
#[test]
fn snapshot_names_the_wrong_grain_when_a_root_node_is_swapped_for_another_valid_one() {
    let tree = PublishedTree::publish("snapshot-swapped-root-node");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("root-key mode must mount a healthy tree: {e}"));

    // A DIFFERENT, but perfectly well-formed, single-entry DirLeaf —
    // decodable, trivially strictly-sorted (one entry), naming
    // "f.txt" against a grain id that is NOT tree.file_id. Swapped
    // in under the SAME key the real root already occupies: nodes
    // and manifest_root are now out of sync exactly as the sibling
    // test's own doc describes, with the key (and so Snapshot::new's
    // own reachability check) still satisfied.
    let decoy_id = GrainId::of(b"decoy content, never really stored");
    let decoy_root = granary_core::manifest::encode_dir_leaf(&[granary_core::manifest::DirEntry {
        name: granary_core::manifest::Name::new(b"f.txt".to_vec())
            .unwrap_or_else(|e| panic!("{e}")),
        kind: granary_core::manifest::EntryKind::File {
            exec: false,
            size: u64::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
            grains: granary_core::manifest::FileGrains::Inline(vec![
                granary_core::manifest::GrainRef {
                    id: decoy_id,
                    unpacked_len: u32::try_from(FILE_CONTENT.len())
                        .unwrap_or_else(|e| panic!("{e}")),
                },
            ]),
        },
    }])
    .unwrap_or_else(|e| panic!("a single-entry DirLeaf must encode: {e}"));
    session.pre.nodes.insert(tree.manifest_root, decoy_root);

    let snap = session.snapshot(AttrPolicy { uid: 0, gid: 0 }).unwrap_or_else(|e| {
        panic!("Snapshot::new must accept the swapped node — it is structurally valid, just wrong: {e}")
    });
    let entry = snap
        .lookup(&tree.manifest_root, b"f.txt")
        .unwrap_or_else(|e| panic!("f.txt must still be found under the swapped root: {e:?}"));
    let granary_core::manifest::EntryKind::File { grains, .. } = &entry.kind else {
        panic!("f.txt must decode as a File entry, got {:?}", entry.kind);
    };
    let granary_core::manifest::FileGrains::Inline(refs) = grains else {
        panic!("a single-chunk file must be inline, got {grains:?}");
    };
    let [only] = refs.as_slice() else {
        panic!("a single-chunk file must carry exactly one inline ref, got {refs:?}");
    };
    assert_eq!(
        only.id, decoy_id,
        "snapshot() must report whatever the (possibly wrong) node in pre.nodes actually \
         says — proving the sibling test's assert_eq! is reachable and would fail exactly \
         like this if nodes and manifest_root were ever really out of sync"
    );
    assert_ne!(
        only.id, tree.file_id,
        "fixture precondition: the decoy grain must differ from the real one, or this test \
         proves nothing"
    );
}

/// Row 1, `--manifest-root`'s share.
#[test]
fn manifest_root_mode_mounts_and_reads_a_file() {
    let tree = PublishedTree::publish("manifest-root-mount");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        Some(tree.manifest_root),
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("manifest-root mode must mount a healthy tree: {e}"));

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("fetch_grain must read the file's bytes back: {e}"));
    assert_eq!(bytes, FILE_CONTENT);
}

/// Row 1, `--trust-server`'s share.
#[test]
fn trust_server_mode_mounts_and_reads_a_file() {
    let tree = PublishedTree::publish("trust-server-mount");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("trust-server mode must mount a healthy tree: {e}"));

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("fetch_grain must read the file's bytes back: {e}"));
    assert_eq!(bytes, FILE_CONTENT);
}

// ------------------------------------------------ row 7: floor-keeping modes refuse a degraded cache

/// NEGATIVE, R6: a cache directory whose writer lock is already
/// held refuses the mount under `--root-key` and `--trust-server`.
/// R6 binds BOTH floor-keeping modes, and only `--trust-server` had a
/// test. Moving `TrustMode::RootKey(_)` from the refusing arm to the
/// warning arm keeps the match exhaustive and the suite green, while
/// letting a `--root-key` mount run with a floor it cannot persist.
#[test]
fn a_held_writer_lock_refuses_under_root_key_too() {
    let tree = PublishedTree::publish("writer-lock-root-key");
    let cache_dir = scratch_cache_dir();
    let _holder = Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    let mut sink = Vec::new();

    let err = MountSession::open(
        remote_handle(&tree.mem),
        tree.volume.clone(),
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("--root-key keeps a floor, so a degraded cache must refuse it too");
    assert!(
        matches!(err, MountError::DegradedCacheRefused),
        "wanted DegradedCacheRefused, got {err:?}"
    );
    assert!(
        err.to_string().contains("--cache-dir"),
        "the refusal must name the fix: {err}"
    );
}

/// The refusal must name the fix (`--cache-dir`).
#[test]
fn a_held_writer_lock_refuses_under_trust_server_naming_cache_dir() {
    let tree = PublishedTree::publish("writer-lock-trust-server");
    let cache_dir = scratch_cache_dir();
    // Hold the writer lock BEFORE the mount ever opens the cache.
    let _holder = Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    let mut sink = Vec::new();

    let err = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("a held writer lock must refuse the mount under --trust-server");

    assert!(
        matches!(err, MountError::DegradedCacheRefused),
        "got {err:?}, wanted MountError::DegradedCacheRefused"
    );
    let message = err.to_string();
    assert!(
        message.contains("--cache-dir"),
        "the refusal must name the fix (--cache-dir): {message}"
    );
}

/// POSITIVE: under `--manifest-root`, which keeps no
/// floor, a held writer lock costs only performance — WARN loudly
/// and serve.
#[test]
fn a_held_writer_lock_warns_and_serves_under_manifest_root() {
    let tree = PublishedTree::publish("writer-lock-manifest-root");
    let cache_dir = scratch_cache_dir();
    let _holder = Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        Some(tree.manifest_root),
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("--manifest-root must serve on a degraded cache: {e}"));

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("fetch_grain must still read the file's bytes: {e}"));
    assert_eq!(bytes, FILE_CONTENT);

    let sink_text = String::from_utf8_lossy(&sink);
    assert!(
        sink_text.contains("read-only"),
        "a degraded cache under --manifest-root must warn LOUDLY that the cache is \
         read-only for this session: {sink_text}"
    );
}

// ------------------------------------------------ row 10: a transport-down start is refused

/// NEGATIVE: a transport-down start is refused rather than served
/// from cache. Structural: the mount's own
/// `resolve_root` call always passes `degraded: None` and never
/// takes any retry-from-cache path, so a wire failure surfaces
/// directly — even with a cache entry sitting right there at the
/// same `(volume, seq)`, seeded here exactly as a prior successful
/// resolve would have left it.
#[test]
fn a_transport_down_start_is_refused_rather_than_served_from_cache() {
    let tree = PublishedTree::publish("transport-down-start");
    let cache_dir = scratch_cache_dir();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    let honest_root_bytes = rt
        .block_on(tree.remote.get_root(tree.volume.as_str(), 1))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("fixture precondition: seq 1 must exist"));

    // Seed the cache with the HONEST root bytes, exactly as a
    // prior successful resolve through this cache directory would
    // have left it.
    {
        let mut seeding_cache =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding_cache.put_root_bytes(&tree.volume, 1, &honest_root_bytes);
    }

    let (counting, counts) = CountingRemote::new(&tree.remote);
    counts.fail_root_calls();
    let mut sink = Vec::new();

    let err = MountSession::open(
        counting,
        tree.volume,
        None,
        None,
        true,
        Some(1),
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("a transport-down start must be refused rather than served from cache");

    assert!(
        matches!(err, MountError::Resolve(_)),
        "got {err:?}, wanted the transport failure to surface as a Resolve error"
    );
}

// ------------------------------------------------ row 5: a pin mismatch stops after the root fetch

/// NEGATIVE: `--manifest-root` with a digest that is not the
/// root's is refused BEFORE the binmap, the sheaf or the tree are
/// fetched — asserted by counting store calls, and the count must
/// be the root fetch and NOTHING MORE.
#[test]
fn manifest_root_mismatch_is_refused_after_exactly_one_store_call() {
    let tree = PublishedTree::publish("manifest-root-mismatch");
    let cache_dir = scratch_cache_dir();
    let wrong_pin = GrainId::of(b"not this tree's real manifest root");
    let (counting, counts) = CountingRemote::new(&tree.remote);
    let mut sink = Vec::new();

    let err = MountSession::open(
        counting,
        tree.volume,
        None,
        Some(wrong_pin),
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("a --manifest-root pin that does not match must be refused");

    assert!(
        matches!(
            err,
            MountError::PinMismatch {
                expected,
                ..
            } if expected == wrong_pin
        ),
        "got {err:?}, wanted MountError::PinMismatch naming {wrong_pin}"
    );
    assert_eq!(
        counts.total(),
        1,
        "the pin check must refuse after the root fetch and NOTHING MORE — no binmap, \
         sheaf or tree fetch may happen on the strength of a manifest_root this mode does \
         not even trust yet"
    );
}

// ------------------------------------------------ row 13: a bad signature stops after the root fetch

/// Row 13: a root whose signature does NOT verify under
/// `TrustMode::RootKey` fails with the signature error having
/// performed EXACTLY ONE store fetch — the root itself — and
/// nothing more. Pins the root-acquisition ordering
/// ("RETURNS before anything is fetched on the strength of `doc`'s
/// contents") by the count, not just the error variant: moving the
/// check to run one step later is an EQUIVALENT MUTANT from the
/// error-variant alone, so the count is the only thing that can catch
/// it.
#[test]
fn a_bad_signature_under_root_key_fails_after_exactly_one_store_call() {
    let tree = PublishedTree::publish("bad-signature-root-key");
    let cache_dir = scratch_cache_dir();
    // A key that never signed this tree's root — the honest
    // publisher used `tree.key`, not this one.
    let (wrong_key, _seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let (counting, counts) = CountingRemote::new(&tree.remote);
    let mut sink = Vec::new();

    let err = MountSession::open(
        counting,
        tree.volume,
        Some(Box::new(*wrong_key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("a root-key that never signed this root must be refused");

    assert!(
        matches!(err, MountError::Resolve(ResolveError::UnknownSigner { .. })),
        "got {err:?}, wanted MountError::Resolve(ResolveError::UnknownSigner {{ .. }})"
    );
    assert_eq!(
        counts.total(),
        1,
        "the signature check must fail after EXACTLY ONE store fetch — the root itself \
         — and nothing more"
    );
}

// ---------------------------------------------- rows 6a/6b/6c: cache/wire root disagreement

/// 6a. POSITIVE, keyless: in `--trust-server` (and `--manifest-root`,
/// covered by the sibling row below), a cache holding different
/// bytes for the same `(volume, seq)` MOUNTS, proceeds on the wire
/// bytes, and REPORTS an equivocation finding naming both digests —
/// on the same surface as the `gran mount: pinned …` line, never
/// only logged.
#[test]
fn keyless_trust_server_cache_wire_mismatch_mounts_and_reports_equivocation() {
    const CACHED_GARBAGE: &[u8] = b"not the real root bytes at all";
    let tree = PublishedTree::publish("cache-wire-mismatch-trust-server");
    let cache_dir = scratch_cache_dir();
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding.put_root_bytes(&tree.volume, 1, CACHED_GARBAGE);
    }
    let expected_cached_id = GrainId::of(CACHED_GARBAGE);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    let real_root_bytes = rt
        .block_on(remote_handle(&tree.mem).get_root(tree.volume.as_str(), 1))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("fixture precondition: seq 1's real root must exist"));
    let expected_wire_id = GrainId::of(&real_root_bytes);
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| {
        panic!("a keyless cache/wire mismatch must still mount, on the wire bytes: {e}")
    });

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("must proceed on the wire bytes: {e}"));
    assert_eq!(
        bytes, FILE_CONTENT,
        "must serve the WIRE bytes, not the cached ones"
    );

    let sink_text = String::from_utf8_lossy(&sink);
    assert!(
        sink_text.to_uppercase().contains("EQUIVOCATION"),
        "the finding must be OBSERVABLE on the sink, not only a tracing::warn!: {sink_text}"
    );
    // And it must SURVIVE the sink. The `writeln!` is one-shot and
    // unchecked, so a daemonised mount with a closed sink would keep
    // no record at all; the session holds the finding so the adapter
    // and CLI can report it on a surface that outlives `open`.
    let kept = session
        .equivocation()
        .unwrap_or_else(|| panic!("the finding must be retained on the session"))
        .render_finding();
    // Both labels are in the finding's template, so only the DIGESTS
    // bound to them say what disagreed.
    assert!(
        kept.contains(&format!("wire={expected_wire_id}")),
        "the retained finding must name the WIRE digest: {kept}"
    );
    assert!(
        kept.contains(&format!("cached={expected_cached_id}")),
        "the retained finding must name the CACHED digest: {kept}"
    );
}

/// 6a's `--manifest-root` share: both it and `--trust-server`
/// are keyless modes.
#[test]
fn keyless_manifest_root_cache_wire_mismatch_mounts_and_reports_equivocation() {
    let tree = PublishedTree::publish("cache-wire-mismatch-manifest-root");
    let cache_dir = scratch_cache_dir();
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding.put_root_bytes(&tree.volume, 1, b"not the real root bytes at all");
    }
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        Some(tree.manifest_root),
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| {
        panic!("a keyless cache/wire mismatch must still mount, on the wire bytes: {e}")
    });

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("must proceed on the wire bytes: {e}"));
    assert_eq!(bytes, FILE_CONTENT);

    let sink_text = String::from_utf8_lossy(&sink);
    assert!(
        sink_text.to_uppercase().contains("EQUIVOCATION"),
        "the finding must be OBSERVABLE on the sink: {sink_text}"
    );
}

/// 6b. NEGATIVE, `--root-key`, cached bytes VERIFY: two different
/// signature-valid roots at one seq is publisher equivocation. The
/// mount REFUSES and names both digests.
#[test]
fn root_key_cached_root_that_also_verifies_is_refused_as_equivocation() {
    let tree = PublishedTree::publish("cache-wire-mismatch-root-key");
    let cache_dir = scratch_cache_dir();

    // A SECOND root at the same seq, DIFFERENT bytes, signed by
    // the SAME key — this is what publisher equivocation actually
    // looks like: only the key holder could produce it.
    let mut forged = RootDoc {
        volume: tree.volume.clone(),
        seq: 1,
        parent: None,
        writer_uuid: [0xAA; 16],
        epoch: 1,
        timestamp: Timestamp {
            secs: 1_760_000_001,
            nanos: 0,
        },
        chunker_spec: "forged-but-signed".to_owned(),
        manifest_root: tree.manifest_root,
        binmap_index: tree.manifest_root,
        sheaf_head: tree.manifest_root,
        sigs: Vec::new(),
    };
    let prefix = root::signing_prefix_of(&forged).unwrap_or_else(|e| panic!("{e:?}"));
    forged.sigs.push(RootSig {
        key_id: tree.key.key_id(),
        sig: tree.key.sign(&prefix),
    });
    let forged_bytes = root::encode_root(&forged).unwrap_or_else(|e| panic!("{e:?}"));

    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding.put_root_bytes(&tree.volume, 1, &forged_bytes);
    }

    let mut sink = Vec::new();
    let err = MountSession::open(
        tree.remote,
        tree.volume,
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("two different, both validly-signed, roots at one seq must be refused");

    assert!(
        matches!(err, MountError::CachedRootEquivocation { .. }),
        "got {err:?}, wanted MountError::CachedRootEquivocation"
    );
}

/// 6c. POSITIVE, `--root-key`, cached bytes DO NOT verify: local
/// corruption. The mount EVICTS the entry and proceeds on the
/// verified wire bytes.
#[test]
fn root_key_cached_root_that_does_not_verify_is_evicted_and_wire_bytes_win() {
    let tree = PublishedTree::publish("unverified-cached-root-evicted");
    let cache_dir = scratch_cache_dir();
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        // Garbage at the cached root path directly — not even a
        // decodable root, let alone a validly-signed one.
        seeding.put_root_bytes(&tree.volume, 1, b"pure garbage, not a root at all");
    }
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume.clone(),
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| {
        panic!("corrupt local cache under --root-key must evict and proceed on wire: {e}")
    });

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("must proceed on the verified wire bytes: {e}"));
    assert_eq!(bytes, FILE_CONTENT);
    drop(session);

    let after = Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        after.get_root_bytes(&tree.volume, 1),
        None,
        "the corrupt cached root must have been evicted, not merely bypassed"
    );
}

// ------------------------------------------------ row 8: planted heads and freshness floors

const PLANTED_SEQ: u64 = 10_000_000_000;

/// R3's attack, planted directly on the store: an UNSIGNED root at
/// a seq far above the real head, copying the real tree's
/// `manifest_root`/`binmap_index`/`sheaf_head` — a stranger's `PUT
/// root` needs no signature and no key to do this (create-if-
/// absent, validates nothing).
fn plant_forged_root_at(tree: &PublishedTree, planted_seq: u64) {
    let forged = RootDoc {
        volume: tree.volume.clone(),
        seq: planted_seq,
        // Any id: the mount never runs `check_chain`, so `parent`
        // is never dereferenced — only the encoder's own
        // seq/parent-presence rule (`root::signing_prefix_of`)
        // cares that it is `Some` for a seq other than 1.
        parent: Some(GrainId::of(b"a parent id the mount never walks to")),
        writer_uuid: [0xCC; 16],
        epoch: 1,
        timestamp: Timestamp {
            secs: 1_760_000_003,
            nanos: 0,
        },
        chunker_spec: "planted-by-a-stranger".to_owned(),
        manifest_root: tree.manifest_root,
        binmap_index: tree.binmap_index,
        sheaf_head: tree.sheaf_head,
        // A garbage sig slot, never an EMPTY vec (the encoder
        // requires at least one) — all-zero, so it names no real
        // key and matches nobody's configured anchor. A stranger
        // planting this has no key to sign with; this is what
        // "unsigned" looks like in a format that always carries a
        // slot.
        sigs: vec![RootSig {
            key_id: [0_u8; KEY_ID_LEN],
            sig: [0_u8; ED25519_SIG_LEN],
        }],
    };
    let bytes = root::encode_root(&forged).unwrap_or_else(|e| panic!("{e:?}"));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    rt.block_on(
        tree.remote
            .put_root(tree.volume.as_str(), planted_seq, bytes),
    )
    .unwrap_or_else(|e| panic!("{e}"));
}

/// Under `RootKey` the mount refuses at the verifier, before any
/// floor write — an unsigned planted root carries no signature at
/// all for the configured key to find.
#[test]
fn r3_attack_root_key_refuses_at_the_verifier_before_any_floor_write() {
    let tree = PublishedTree::publish("planted-head-root-key");
    plant_forged_root_at(&tree, PLANTED_SEQ);
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let err = MountSession::open(
        tree.remote,
        tree.volume.clone(),
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("an unsigned planted root must be refused at the verifier");

    assert!(
        matches!(err, MountError::Resolve(ResolveError::UnknownSigner { .. })),
        "got {err:?}, wanted MountError::Resolve(ResolveError::UnknownSigner {{ .. }})"
    );

    let cache = Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.read_mount_anchor(&tree.volume),
        None,
        "no floor may be written on a refusal that happens before the floor raise"
    );
}

/// Under `ManifestRoot` the mount SUCCEEDS (its acceptance
/// predicate is seq-independent) and no floor file is written at
/// all.
#[test]
fn r3_attack_manifest_root_succeeds_and_writes_no_floor_file() {
    let tree = PublishedTree::publish("planted-head-manifest-root");
    plant_forged_root_at(&tree, PLANTED_SEQ);
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume.clone(),
        None,
        Some(tree.manifest_root),
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("--manifest-root's pin must accept the planted seq: {e}"));

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(bytes, FILE_CONTENT);
    drop(session);

    let cache = Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.read_mount_anchor(&tree.volume),
        None,
        "--manifest-root reads no floor and writes none — no floor file at all"
    );
}

/// Under `TrustServer` the mount SUCCEEDS and the private floor IS
/// raised to the planted seq — the accepted, documented cost of
/// keeping the only rollback defence the unverified default has.
/// The recovery is what is under test: the SHARED floor stays
/// untouched, the later `StaleHead` refusal names
/// `anchors/<volume>.mount` and mentions `--reset-floor`, and
/// `--reset-floor` clears it and the mount then succeeds.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one coherent three-phase scenario (poison, observe the recovery's own shape, \
              --reset-floor) — splitting it would scatter the three phases R3's own \
              narrative reads as one story"
)]
fn r3_attack_trust_server_raises_the_private_floor_and_reset_floor_recovers() {
    let tree = PublishedTree::publish("planted-head-trust-server");
    plant_forged_root_at(&tree, PLANTED_SEQ);
    let cache_dir = scratch_cache_dir();

    // 1. The poisoning: a discovery-based TrustServer mount
    // accepts the planted seq and raises its private floor to it.
    let mut sink = Vec::new();
    let mut session = MountSession::open(
        tree.remote,
        tree.volume.clone(),
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("--trust-server must accept the planted seq: {e}"));
    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(bytes, FILE_CONTENT);
    drop(session);

    {
        let cache =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            cache.read_mount_anchor(&tree.volume),
            Some(PLANTED_SEQ),
            "the mount-private floor must be raised to the planted seq"
        );
        assert_eq!(
            cache.read_anchor(&tree.volume),
            None,
            "the SHARED floor must be untouched — that is `cat`'s own rollback defence"
        );
    }

    // 2. The recovery's shape, and it goes through DISCOVERY, which
    // is the only thing the floor binds. R3's narrative: the
    // operator deletes the plant, `max_seq` falls back to the real
    // head, and every later mount from that cache directory fails
    // `StaleHead`. Deleting the plant is what makes discovery land
    // on seq 1 — using an explicit `--seq 1` here would test the
    // opposite of the contract (see the sibling test below).
    // The plant is gone: a store serving the same volume with only
    // the honest head, which is what `max_seq` falling back means.
    let honest = PublishedTree::publish("planted-head-trust-server");
    let mut sink2 = Vec::new();
    let err = MountSession::open(
        remote_handle(&honest.mem),
        honest.volume.clone(),
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink2,
    )
    .expect_err("discovery at the real seq must refuse under the poisoned private floor");
    assert!(
        matches!(
            err,
            MountError::StaleHead {
                kind: FloorKind::MountPrivate,
                ..
            }
        ),
        "got {err:?}, wanted MountError::StaleHead naming the mount-private floor"
    );
    let message = err.to_string();
    assert!(
        message.contains("anchors/<volume>.mount"),
        "the refusal must name the file to delete: {message}"
    );
    assert!(
        message.contains("--reset-floor"),
        "the refusal must mention the recovery flag: {message}"
    );

    // 3. --reset-floor clears it and the mount then succeeds.
    {
        let mut cache =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        cache
            .reset_mount_anchor(&tree.volume)
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let mut sink3 = Vec::new();
    let mut recovered = MountSession::open(
        remote_handle(&tree.mem),
        tree.volume,
        None,
        None,
        true,
        Some(1),
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink3,
    )
    .unwrap_or_else(|e| panic!("--reset-floor must let the honest seq mount again: {e}"));
    let recovered_bytes = recovered
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(recovered_bytes, FILE_CONTENT);
}

// ----------------------------------------------- row 12: structure nodes remain resident

/// The mount holds `nodes` after `open` returns — the structure
/// map is non-empty, and a second access performs NO store call
/// (Test 12 is about RETENTION: a non-empty map alone is not proof
/// — an implementation that re-fetches everything on every access
/// would also show a non-empty map right after `open`).
#[test]
fn the_mount_retains_nodes_and_a_second_access_makes_no_store_call() {
    let tree = PublishedTree::publish("retained-nodes");
    let cache_dir = scratch_cache_dir();
    let (counting, counts) = CountingRemote::new(&tree.remote);
    let mut sink = Vec::new();

    let session = MountSession::open(
        counting,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("{e}"));

    assert!(
        session.structure_node(&tree.file_id).is_none(),
        "the file's CONTENT grain is never a structure node"
    );
    // The root directory node itself: `pre.nodes` is keyed by every
    // manifest STRUCTURE node the walk visited, and the tree's own
    // root directory is always one of them.
    let root_dir_id = tree.manifest_root;
    assert!(
        session.structure_node(&root_dir_id).is_some(),
        "the structure map must be non-empty after open() returns"
    );

    let after_open = counts.total();
    // A second access to the SAME retained structure.
    assert!(session.structure_node(&root_dir_id).is_some());
    assert_eq!(
        counts.total(),
        after_open,
        "a second access to the retained structure map must make NO store call"
    );
}

// ------------------------------------------------ mutation-probe coverage

/// Refusal requirement: **when BOTH floors block, say
/// so and name BOTH, lowest-risk action first.** Naming only the higher
/// one routes the operator to the more dangerous shared-floor deletion,
/// and the mount then still fails on the other.
///
/// The TIE counts as both: with `mount_floor == shared_floor`, naming
/// only the mount-private floor points at `--reset-floor`, which
/// alone does not unblock it.
#[test]
fn when_both_floors_block_the_refusal_names_both_and_carries_the_basis() {
    for (mount_floor, shared_floor) in [(900_u64, 800_u64), (900, 900), (800, 900)] {
        let tree = PublishedTree::publish("both-floors");
        let cache_dir = scratch_cache_dir();
        {
            let mut cache =
                Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
            cache
                .raise_mount_anchor(&tree.volume, mount_floor)
                .unwrap_or_else(|e| panic!("{e}"));
            cache.raise_anchor(
                &tree.volume,
                Some(shared_floor),
                crate::cache::HintUpdate::Unchanged,
            );
        }
        let mut sink = Vec::new();
        let err = MountSession::open(
            remote_handle(&tree.mem),
            tree.volume.clone(),
            None,
            None,
            true,
            None,
            &cache_dir.0,
            1_000_000,
            &origin(),
            MountOptions::default(),
            &mut sink,
        )
        .expect_err("seq 1 is below both floors");
        let MountError::StaleHead { kind, mode, .. } = &err else {
            panic!("wanted StaleHead, got {err:?}");
        };
        assert_eq!(
            *kind,
            FloorKind::Both,
            "both floors are above seq 1 ({mount_floor}, {shared_floor}), so both must be named"
        );
        assert_eq!(*mode, "--trust-server", "the refusal carries the mode");
        let message = err.to_string();
        for needle in [
            "anchors/<volume>.mount",
            "anchors/<volume>",
            "--reset-floor",
            &mount_floor.to_string(),
            &shared_floor.to_string(),
        ] {
            assert!(
                message.contains(needle),
                "the refusal must carry {needle}: {message}"
            );
        }
        // Lowest-risk action FIRST.
        let reset_at = message.find("--reset-floor").unwrap_or(usize::MAX);
        let dangerous_at = message.find("more dangerous").unwrap_or(0);
        assert!(
            reset_at < dangerous_at,
            "the lowest-risk action must come first: {message}"
        );
    }
}

/// A floor that cannot be PERSISTED refuses the mount, in the two modes
/// that keep one. Otherwise the mount accepts seq N, stores nothing, and
/// the next discovery is free to accept an authentic older seq with the
/// only rollback defence these modes have silently disarmed.
#[test]
fn a_floor_that_cannot_be_persisted_refuses_the_mount() {
    let tree = PublishedTree::publish("floor-not-persisted");
    let cache_dir = scratch_cache_dir();
    // A DIRECTORY where the floor file belongs: the write cannot land.
    let planted = cache_dir
        .0
        .join("anchors")
        .join("floor-not-persisted.mount");
    std::fs::create_dir_all(&planted).unwrap_or_else(|e| panic!("{e}"));

    let mut sink = Vec::new();
    let err = MountSession::open(
        remote_handle(&tree.mem),
        tree.volume.clone(),
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("a mount that cannot persist its floor must not pretend to have one");
    assert!(
        matches!(err, MountError::FloorNotPersisted { .. }),
        "wanted FloorNotPersisted, got {err:?}"
    );

    // CONTROL: --manifest-root keeps NO floor, so the same planted
    // directory must not stop it. Without this control, a mount that
    // refused whenever anchors/<volume>.mount is unwritable would pass
    // the row above, and would brick the one mode R3 says must never
    // read or write a floor.
    let mut sink2 = Vec::new();
    let session = MountSession::open(
        remote_handle(&tree.mem),
        tree.volume.clone(),
        None,
        Some(tree.manifest_root),
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink2,
    )
    .unwrap_or_else(|e| panic!("--manifest-root keeps no floor and must be unaffected: {e}"));
    drop(session);
}

/// Row 8c: **an explicit `--seq` is NOT bound by the floor**, and this
/// is the escape hatch, not an oversight.
///
/// The floor binds DISCOVERY'S OWN ANSWER, never a
/// user-commanded `--seq`. As `ResolveError::StaleHead` records, an
/// explicit seq is the user's command. The floor answers a STORE lying
/// about where the head is; an operator naming a seq is not that, and the explicit `--seq`
/// route around a poisoned floor would be worthless if the very defence
/// it routes around also refused it.
///
/// **This test exists because the property was implemented backwards
/// once already.** Without a red for the carve-out, the row-8 recovery
/// test reads as if the floor should bind everything, and the next
/// round "fixes" the code to match it.
#[test]
fn an_explicit_seq_is_not_bound_by_a_poisoned_floor() {
    let tree = PublishedTree::publish("explicit-seq-poisoned-floor");
    let cache_dir = scratch_cache_dir();
    // Poison the mount-private floor directly, far above the real head.
    {
        let mut cache =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        cache
            .raise_mount_anchor(&tree.volume, PLANTED_SEQ)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cache.read_mount_anchor(&tree.volume), Some(PLANTED_SEQ));
    }
    // Discovery is refused — the floor is doing its job.
    let mut sink = Vec::new();
    let refused = MountSession::open(
        remote_handle(&tree.mem),
        tree.volume.clone(),
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    );
    assert!(
        matches!(refused, Err(MountError::StaleHead { .. })),
        "discovery below a poisoned floor must refuse"
    );
    drop(refused);
    // The SAME seq, named explicitly, is the operator's command and
    // mounts. If this goes red, read `MountError`'s seq rules before "fixing" it.
    let mut sink2 = Vec::new();
    let session = MountSession::open(
        remote_handle(&tree.mem),
        tree.volume.clone(),
        None,
        None,
        true,
        Some(1),
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink2,
    )
    .unwrap_or_else(|e| {
        panic!("an explicit --seq is a COMMAND and must not be bound by the floor: {e}")
    });
    drop(session);
}

/// A cached root must be compared regardless of its AGE.
/// Kills: "skip the comparison when the cached root is older than some
/// age" (a required degenerate, with a realistic threshold). Roots are
/// never evicted, so an old cached root is the ordinary case.
///
/// **Asserts the mismatch's CONTENT, not merely `is_some()`.** An
/// implementation that always records SOME mismatch — never comparing
/// anything — could satisfy only that weaker assertion. The digests are built
/// from the SAME expression production uses (`GrainId::of`), one over
/// the literal cached bytes this fixture seeds and one over the real
/// wire root fetched independently through a second handle onto the
/// same backing store, never a hand-typed literal.
#[test]
fn still_compares_a_cached_root_backdated_by_a_year() {
    const CACHED_GARBAGE: &[u8] = b"not the real root bytes at all";
    let tree = PublishedTree::publish("cached-root-old");
    let cache_dir = scratch_cache_dir();
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding.put_root_bytes(&tree.volume, 1, CACHED_GARBAGE);
    }
    let expected_cached_id = GrainId::of(CACHED_GARBAGE);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    let real_root_bytes = rt
        .block_on(remote_handle(&tree.mem).get_root(tree.volume.as_str(), 1))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("fixture precondition: seq 1's real root must exist"));
    let expected_wire_id = GrainId::of(&real_root_bytes);
    let root_path = cache_dir
        .0
        .join("roots")
        .join(tree.volume.as_str())
        .join(format!("{:020}", 1));
    // A FIXED absolute instant in 2001, never a clock read: this crate
    // bans `SystemTime::now` outside the Clock seam, and the mount test
    // module's wholesale fs licence does not cover that row.
    let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    let f = std::fs::OpenOptions::new()
        .read(true)
        .open(&root_path)
        .unwrap_or_else(|e| panic!("open {}: {e}", root_path.display()));
    f.set_times(std::fs::FileTimes::new().set_modified(old))
        .unwrap_or_else(|e| panic!("set_times: {e}"));
    drop(f);
    let observed = std::fs::metadata(&root_path)
        .and_then(|m| m.modified())
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        observed < std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_100_000_000),
        "the fixture must actually backdate the file; mtime was {observed:?}"
    );

    let mut sink = Vec::new();
    let session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("must still mount on the wire bytes: {e}"));
    let kept = session
        .equivocation()
        .unwrap_or_else(|| panic!("a cached root must be compared regardless of its AGE"))
        .render_finding();
    assert!(
        kept.contains(&format!("wire={expected_wire_id}")),
        "the finding must name the WIRE digest, not merely record that SOMETHING \
         disagreed: {kept}"
    );
    assert!(
        kept.contains(&format!("cached={expected_cached_id}")),
        "the finding must name the CACHED digest, not merely record that SOMETHING \
         disagreed: {kept}"
    );
}

/// `fetch_grain` must refuse bytes SHORTER than the
/// manifest declares. The fetcher rejects a grain longer than
/// declared but not a short one, and the mount skips `emit_target`
/// where `gran cat`'s own `GrainLenMismatch` lives — this seam is
/// the only place the check exists, and nothing pinned it.
///
/// **Only the SHORT direction, deliberately.** This test's own
/// production check is `bytes.len() != unpacked_len` — an inequality,
/// not a one-sided comparison — but the LONG direction, a
/// `bytes.len()` ABOVE `unpacked_len`, is unreachable at this call
/// site to construct honestly: the fetcher's own residency guard
/// already refuses an over-wide grain UPSTREAM, so `fetch_grain`
/// never sees one — the `outcome.map_err(...)` a few lines above this
/// method's own length check returns `Err` first, with
/// [`FetchError::OverDeclared`]. That guard is on BOTH delivery
/// paths, and saying so matters here because this call site is
/// CACHE-FIRST: `finish()` covers the wire, and `deliver_cache_hit`
/// only started covering a cache hit once the fetcher enforced that
/// guard there too — before, this "unreachable" was false for exactly
/// the cached case. This check's `!=` form is still correct (it is
/// the seam's own stated contract, answering for itself rather than
/// trusting the fetcher's upstream guard across the boundary), and
/// the SHORT direction below is the only one this test can honestly
/// assert without fabricating a fixture that proves nothing.
#[test]
fn fetch_grain_refuses_a_grain_shorter_than_declared() {
    let tree = PublishedTree::publish("short-grain");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();
    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let declared = u32::try_from(FILE_CONTENT.len() + 1).unwrap_or_else(|e| panic!("{e}"));
    let err = session
        .fetch_grain(&tree.file_id, declared)
        .expect_err("bytes shorter than the declared length must be refused");
    assert!(
        err.to_string().contains("where the manifest declares"),
        "the refusal must name the length disagreement: {err}"
    );
}

/// BOTH keyless modes state what
/// is and is not checked, ON THE SINK — and `--root-key`
/// does NOT, or a degenerate that always prints would pass.
///
/// **All THREE trust modes, not two.** The production arm is
/// `TrustMode::ManifestRoot(_) | TrustMode::TrustServer`. A two-row
/// loop over `TrustServer` and `RootKey` never exercises
/// `--manifest-root`: splitting the production arm so `ManifestRoot`
/// silently returns `RootVerifier::unverified()` without printing
/// leaves such a loop green — a `--manifest-root` mount would then
/// tell the operator nothing about the root signature not being
/// checked.
#[test]
fn keyless_modes_state_what_is_not_checked_and_root_key_does_not() {
    for (root_key, manifest_root, trust_server, expect_said, mode_name) in [
        (false, false, true, true, "--trust-server"),
        (false, true, false, true, "--manifest-root"),
        (true, false, false, false, "--root-key"),
    ] {
        let tree = PublishedTree::publish("keyless-notice");
        let cache_dir = scratch_cache_dir();
        let mut sink = Vec::new();
        let session = MountSession::open(
            tree.remote,
            tree.volume,
            root_key.then(|| Box::new(*tree.key.public_key())),
            manifest_root.then_some(tree.manifest_root),
            trust_server,
            None,
            &cache_dir.0,
            1_000_000,
            &origin(),
            MountOptions::default(),
            &mut sink,
        )
        .unwrap_or_else(|e| panic!("{mode_name}: {e}"));
        drop(session);
        let text = String::from_utf8_lossy(&sink).to_string();
        let said = text.contains("SIGNATURE is NOT checked");
        assert_eq!(
            said, expect_said,
            "{mode_name} must state what is not checked exactly when keyless \
             (if-and-only-if — a degenerate that always prints must still fail): {text}"
        );
    }
}

/// The mount reports volume, seq, the
/// root's `GrainId`, and an explicit "history: not checked" line
/// — the diagnostic substitute for the dropped chain walk.
///
/// **All THREE trust modes, not one.** PROVEN: wrapping both reporting
/// `writeln!`s in `if matches!(&trust, TrustMode::RootKey(_))` left a
/// single-row (`--root-key`-only) version of this fixture green —
/// the diagnostic substitute for the dropped chain walk would
/// then vanish for exactly the two modes, `--manifest-root` and
/// `--trust-server`, that most need it, since neither has a
/// signature check to fall back on.
///
/// **The `seq=` needle is ANCHORED, not a bare substring.** A bare
/// `"seq=1"` also matches `seq=12`; `"seq=1 root="` cannot.
///
/// **The `root=` digest is checked against the ACTUAL root's
/// `GrainId`, not merely the `blake3:` prefix.** A bare
/// `"root=blake3:"` needle passes for ANY `GrainId`, hand-typed or
/// not. The expected value is
/// built from the SAME expression production uses
/// (`GrainId::of(&pre.root_bytes)`), over root bytes fetched
/// independently through a second handle onto the SAME backing
/// store — never a literal.
///
/// **The whole pinned line is compared, not a substring.** It must be
/// exactly `gran mount: pinned volume=… seq=1 root=<root id>
/// manifest-root=<manifest id>`, so a swapped pair, a repeated field
/// or trailing text fails. `manifest-root=` carries the tree's own
/// manifest id, the value `--manifest-root` accepts and `gran publish`
/// prints on its `manifest-root` line; the fixture's root id and
/// manifest id are first required to differ, so the line can tell
/// them apart.
#[test]
fn the_mount_reports_what_it_pinned_and_that_history_is_unchecked() {
    for (root_key, manifest_root, trust_server, mode_name) in [
        (true, false, false, "--root-key"),
        (false, true, false, "--manifest-root"),
        (false, false, true, "--trust-server"),
    ] {
        let tree = PublishedTree::publish("pin-report");

        // The expected root id, computed the same way production
        // does (`GrainId::of` over the wire root bytes) but from an
        // INDEPENDENT second handle onto the same backing store —
        // `tree.remote` is moved into `open` below, and `pre.root_bytes`
        // is that same wire read, unchanged, per `resolve_root`'s own
        // doc.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("{e}"));
        let expected_root_bytes = rt
            .block_on(remote_handle(&tree.mem).get_root(tree.volume.as_str(), 1))
            .unwrap_or_else(|e| panic!("{mode_name}: {e}"))
            .unwrap_or_else(|| {
                panic!("{mode_name}: fixture precondition: seq 1's root must exist")
            });
        let expected_root_id = GrainId::of(&expected_root_bytes);
        assert_ne!(
            expected_root_id, tree.manifest_root,
            "{mode_name}: fixture precondition: the root document and the manifest must be different objects"
        );

        let cache_dir = scratch_cache_dir();
        let mut sink = Vec::new();
        let session = MountSession::open(
            tree.remote,
            tree.volume.clone(),
            root_key.then(|| Box::new(*tree.key.public_key())),
            manifest_root.then_some(tree.manifest_root),
            trust_server,
            None,
            &cache_dir.0,
            1_000_000,
            &origin(),
            MountOptions::default(),
            &mut sink,
        )
        .unwrap_or_else(|e| panic!("{mode_name}: {e}"));
        drop(session);
        let text = String::from_utf8_lossy(&sink).to_string();
        for needle in [
            "volume=pin-report".to_owned(),
            "seq=1 root=".to_owned(),
            format!("root={expected_root_id}"),
            "history: not checked".to_owned(),
        ] {
            assert!(
                text.contains(&needle),
                "{mode_name}: the report must carry {needle:?}: {text}"
            );
        }
        let pinned = format!(
            "gran mount: pinned volume=pin-report seq=1 root={expected_root_id} manifest-root={}",
            tree.manifest_root
        );
        assert!(
            text.lines().any(|l| l == pinned),
            "{mode_name}: the report must carry exactly {pinned:?}: {text}"
        );
    }
}

/// Extra regression, for the mutant ("a floor is read
/// under --manifest-root"): none of the twelve numbered test groups above
/// exercises a cache directory that ALREADY carries a floor above
/// the seq a `--manifest-root` mount is about to accept — every
/// row 8 sub-test starts from a fresh cache dir, so a mutation that
/// makes `--manifest-root` read the floor too still passes the
/// whole suite. Pinned here: raise the mount-private floor first
/// (as a prior `--trust-server` mount would), then mount the SAME
/// cache dir under `--manifest-root` at a LOWER seq and require it
/// to succeed — proving the floor is genuinely never consulted for
/// this mode, not merely never written by it.
///
/// **The seq must be DISCOVERED.** With an explicit `--seq` the floor
/// block is skipped for every mode, so the test would pass against the
/// very mutation it exists to kill.
#[test]
fn manifest_root_ignores_a_pre_existing_floor_above_its_own_seq() {
    let tree = PublishedTree::publish("manifest-root-ignores-floor");
    let cache_dir = scratch_cache_dir();
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        // A floor far above the real seq 1 — as if a prior
        // `--trust-server` mount had already accepted a much
        // higher seq on this same cache directory.
        seeding
            .raise_mount_anchor(&tree.volume, 999)
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        Some(tree.manifest_root),
        false,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| {
        panic!("--manifest-root must ignore a pre-existing floor above its own seq: {e}")
    });

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(bytes, FILE_CONTENT);
}

// ------------------------------------------- reserved-seq follow-up

/// A `RootStore + BinStore` double whose `max_seq` answers a FIXED
/// value, for the discovered-door reserved-seq refusal below. The
/// guard under test fires immediately after `candidate_seq` is
/// bound, before any other store call `MountSession::open` makes —
/// so every other method here should be genuinely unreached once the
/// guard exists. Each still returns a distinct, graceful
/// `RootStoreError::Backend` naming itself rather than panicking:
/// before the guard is wired in (the TDD red below), that turns into
/// a controlled `Err` the assertions can inspect — a real assertion
/// failure on the wrong `MountError` variant, never a bare panic —
/// and once the guard exists these calls never happen at all, so
/// what they return stops mattering. If the guard is ever moved past
/// another store call, the DISTINCT message here names exactly which
/// one fired.
struct FixedMaxSeq(u64);

/// One `RootStoreError::Backend` per method, so a red caused by a
/// wrong call site is distinguishable from one caused by another.
fn unreached(method: &str) -> RootStoreError {
    RootStoreError::Backend(format!(
        "FixedMaxSeq::{method}: the reserved-seq guard should have refused before this \
         call was ever made"
    ))
}

impl RootStore for FixedMaxSeq {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        Err(unreached("put_root"))
    }

    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        Err(unreached("get_root"))
    }

    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        Err(unreached("read_hint"))
    }

    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        Err(unreached("write_hint"))
    }

    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        Ok(Some(self.0))
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

impl BinStore for FixedMaxSeq {
    async fn put_bin(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        Err(unreached("put_bin"))
    }

    async fn put_meta(
        &self,
        _volume: &str,
        _id: &GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        Err(unreached("put_meta"))
    }

    async fn get_meta(&self, _volume: &str, _id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        Err(unreached("get_meta"))
    }

    async fn get_bin_range(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _offset: u64,
        _len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        Err(unreached("get_bin_range"))
    }
}

/// NEGATIVE, explicit door: `--seq 0` and `--seq u64::MAX` are both
/// refused as `ReservedSeqCandidate`, carrying `discovered: false` —
/// an operator naming a reserved seq is a mistake, never the store's
/// claim about the head. No real tree is needed: the guard fires
/// before any store call, so a bare `vol()` and a fresh cache dir are
/// enough.
#[test]
fn explicit_reserved_seq_is_refused_naming_the_explicit_door() {
    for reserved in [0_u64, u64::MAX] {
        let cache_dir = scratch_cache_dir();
        let mut sink = Vec::new();
        let err = MountSession::open(
            FixedMaxSeq(1), // max_seq is never called on the explicit-seq path
            vol("reserved-seq-explicit"),
            None,
            None,
            true,
            Some(reserved),
            &cache_dir.0,
            1_000_000,
            &origin(),
            MountOptions::default(),
            &mut sink,
        )
        .expect_err("an explicit reserved --seq must be refused");
        assert!(
            matches!(
                err,
                MountError::ReservedSeqCandidate {
                    seq,
                    discovered: false
                } if seq == reserved
            ),
            "got {err:?}, wanted ReservedSeqCandidate{{seq: {reserved}, discovered: false}}"
        );
        let message = err.to_string();
        assert!(
            message.contains("--seq"),
            "the explicit-door message must name the flag: {message}"
        );
        assert!(
            message.contains("1 ..= 18446744073709551614"),
            "the explicit-door message must name the usable range: {message}"
        );
        // The message must name the seq it REFUSED. Without this the
        // two arms could print a hard-coded literal — which they did
        // before the refusal messages were corrected — and a
        // third reserved value added to `is_reserved_seq` later would
        // be reported to the operator as some other number entirely.
        assert!(
            message.contains(&format!("seq {reserved}")),
            "the message must name the refused seq {reserved}: {message}"
        );
    }
}

/// NEGATIVE, discovered door: a `max_seq` answer of `0` or
/// `u64::MAX` is refused as `ReservedSeqCandidate`, carrying
/// `discovered: true` — the `RootStore` implementation has violated
/// its own `max_seq` contract (`granary_core::rootstore`'s module
/// doc), and the operator-facing message says so rather than naming
/// `--seq`, which was never given.
#[test]
fn discovered_reserved_seq_is_refused_naming_the_discovered_door() {
    for reserved in [0_u64, u64::MAX] {
        let cache_dir = scratch_cache_dir();
        let mut sink = Vec::new();
        let err = MountSession::open(
            FixedMaxSeq(reserved),
            vol("reserved-seq-discovered"),
            None,
            None,
            true,
            None,
            &cache_dir.0,
            1_000_000,
            &origin(),
            MountOptions::default(),
            &mut sink,
        )
        .expect_err("a max_seq answer of a reserved value must be refused");
        assert!(
            matches!(
                err,
                MountError::ReservedSeqCandidate {
                    seq,
                    discovered: true
                } if seq == reserved
            ),
            "got {err:?}, wanted ReservedSeqCandidate{{seq: {reserved}, discovered: true}}"
        );
        let message = err.to_string();
        assert!(
            !message.contains("--seq"),
            "the discovered-door message must not blame a flag nobody gave: {message}"
        );
        assert!(
            message.contains("max_seq") && message.contains("contract"),
            "the discovered-door message must name the violated contract: {message}"
        );
    }
}

/// CONTROL: an ordinary, non-reserved seq still mounts, both when
/// named explicitly and when discovered via `max_seq`. Without this,
/// a guard mistakenly written as "refuse every candidate" would pass
/// both refusal tests above and nothing here would catch it.
#[test]
fn an_ordinary_seq_still_mounts_explicit_and_discovered() {
    for seq in [None, Some(1_u64)] {
        let tree = PublishedTree::publish("ordinary-seq-control");
        let cache_dir = scratch_cache_dir();
        let mut sink = Vec::new();
        let session = MountSession::open(
            tree.remote,
            tree.volume,
            None,
            None,
            true,
            seq,
            &cache_dir.0,
            1_000_000,
            &origin(),
            MountOptions::default(),
            &mut sink,
        )
        .unwrap_or_else(|e| panic!("an ordinary seq ({seq:?}) must still mount: {e}"));
        drop(session);
    }
}

// ------------------------------------------------ the adapter's first pass

/// The adapter's EARLY pick: `ReservedSeqCandidate`
/// fires right after the runtime is built, before the floor
/// check, root acquisition or preamble ever run. `MountSession::open`'s
/// own `Cache::open` call here is a genuine writer open (nothing else
/// holds the lock), so IT creates the guard file on open — the
/// refusal must CLOSE it rather than merely drop it (`Cache` has no
/// `Drop` impl), or the guard survives an error the operator will see,
/// on the NEXT open, as "the previous writer did not close cleanly" — a
/// false positive about a writer that never crashed.
#[test]
fn reserved_seq_refusal_leaves_no_guard_file() {
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let err = MountSession::open(
        FixedMaxSeq(0),
        vol("reserved-seq-no-guard"),
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("a reserved discovered seq must be refused");
    assert!(
        matches!(err, MountError::ReservedSeqCandidate { .. }),
        "got {err:?}, wanted MountError::ReservedSeqCandidate"
    );

    assert!(
        !cache_dir.0.join("guard").exists(),
        "an EARLY post-Cache::open refusal must not leave the crash guard behind"
    );
}

/// The adapter's LATE pick: `FloorNotPersisted`
/// is the LAST fallible step before `Ok`. Deliberately
/// a DIFFERENT step than the early pick above, not two flavours
/// of the same one. Same planted-directory fixture as
/// own `a_floor_that_cannot_be_persisted_refuses_the_mount`.
#[test]
fn floor_not_persisted_refusal_leaves_no_guard_file() {
    let tree = PublishedTree::publish("floor-refusal-no-guard");
    let cache_dir = scratch_cache_dir();
    // A DIRECTORY where the floor file belongs: the write cannot land.
    let planted = cache_dir
        .0
        .join("anchors")
        .join("floor-refusal-no-guard.mount");
    std::fs::create_dir_all(&planted).unwrap_or_else(|e| panic!("{e}"));
    let mut sink = Vec::new();

    let err = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("a floor that cannot be persisted must refuse the mount");
    assert!(
        matches!(err, MountError::FloorNotPersisted { .. }),
        "got {err:?}, wanted MountError::FloorNotPersisted"
    );

    assert!(
        !cache_dir.0.join("guard").exists(),
        "a LATE post-Cache::open refusal must not leave the crash guard behind"
    );
}

/// A mount
/// refused because its OWN cache opened READ-ONLY-DEGRADED must not
/// disturb the guard belonging to whichever process actually holds
/// the writer lock. The error-path `Cache::close(cache)` in `open`
/// runs on the DEGRADED cache — never the holder's — and safety
/// rests entirely on `Cache::close`'s own `let Mode::Writer(w) = ..
/// else { return Ok(()) }` early return. Nothing else pinned that
/// before this test: a mutation that adds `fs::remove_file(guard)`
/// to that `else` arm left the full suite at 642/642.
#[test]
fn degraded_refusal_leaves_the_holders_guard_intact() {
    let tree = PublishedTree::publish("degraded-keeps-guard");
    let cache_dir = scratch_cache_dir();
    // The HOLDER: a genuine writer, opened first, so the mount's own
    // `Cache::open` below finds the lock taken and opens degraded.
    let _holder = Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    let mut sink = Vec::new();

    let err = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("a degraded cache must refuse the mount under --trust-server");
    assert!(
        matches!(err, MountError::DegradedCacheRefused),
        "wanted DegradedCacheRefused, got {err:?}"
    );

    assert!(
        cache_dir.0.join("guard").exists(),
        "a degraded-cache refusal must not remove the LIVE WRITER's guard file"
    );
}

/// CONTROL: a SUCCESSFUL open must keep its cache, not close it — the
/// guard is still there and `fetch_grain` still works. Without this,
/// "close on error" could have been implemented as "close always"
/// and every guard-absent assertion above would still pass.
///
/// The guard must
/// survive while the session is ALIVE and
/// must be GONE once the session drops without `shutdown` ever
/// having been called — the `Drop` backstop, not `shutdown`, is
/// what removes it here.
#[test]
fn a_successful_open_keeps_its_cache_and_guard() {
    let tree = PublishedTree::publish("successful-open-keeps-guard");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("a healthy tree must mount: {e}"));

    assert!(
        cache_dir.0.join("guard").exists(),
        "a successful open must keep its cache open, guard and all"
    );

    let bytes = session
        .fetch_grain(
            &tree.file_id,
            u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("fetch_grain must still work after a successful open: {e}"));
    assert_eq!(bytes, FILE_CONTENT);

    drop(session);
    assert!(
        !cache_dir.0.join("guard").exists(),
        "dropping the session without calling shutdown must still remove the guard, via \
         the Drop backstop"
    );
}

/// `MountBackend::shutdown` must CLOSE the cache, not merely drop
/// it: `Cache` has no `Drop` impl, so a bare drop leaves the guard
/// file in place — the same defect as an unclosed error path, just
/// triggered from the OTHER end of the session's life.
#[test]
fn shutdown_closes_the_cache() {
    let tree = PublishedTree::publish("shutdown-closes-cache");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("a healthy tree must mount: {e}"));

    assert!(
        cache_dir.0.join("guard").exists(),
        "the guard must be present while the session is live"
    );

    granary_fuse::MountBackend::shutdown(&mut session)
        .unwrap_or_else(|e| panic!("shutdown must succeed on a live session: {e}"));

    assert!(
        !cache_dir.0.join("guard").exists(),
        "shutdown must CLOSE the cache, removing the guard, not merely drop it"
    );
}

/// `MountBackend::abandon` must leave the
/// crash guard behind — the opposite of `shutdown`'s own contract,
/// proved in the SAME test so a reader sees both halves of one
/// contract rather than trusting that `abandon` merely compiles.
/// `abandon` takes `self.cache`, so this session's own `Drop`
/// (the panicking()-blind backstop) finds nothing left to close.
#[test]
fn abandon_leaves_the_guard_and_shutdown_still_does_not() {
    let tree = PublishedTree::publish("abandon-keeps-guard");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let mut abandoned = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("a healthy tree must mount: {e}"));

    assert!(
        cache_dir.0.join("guard").exists(),
        "the guard must be present while the session is live"
    );

    granary_fuse::MountBackend::abandon(&mut abandoned);
    drop(abandoned);

    assert!(
        cache_dir.0.join("guard").exists(),
        "abandon must leave the crash guard on disk, even after the session that \
         called it is dropped"
    );

    // The other half, so this is a real contrast and not merely "a
    // test that always finds the guard": a COMPARABLE session put
    // through `shutdown` instead must leave no guard at all.
    let tree2 = PublishedTree::publish("abandon-shutdown-control");
    let cache_dir2 = scratch_cache_dir();
    let mut sink2 = Vec::new();
    let mut shut_down = MountSession::open(
        tree2.remote,
        tree2.volume,
        None,
        None,
        true,
        None,
        &cache_dir2.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink2,
    )
    .unwrap_or_else(|e| panic!("a healthy tree must mount: {e}"));

    granary_fuse::MountBackend::shutdown(&mut shut_down)
        .unwrap_or_else(|e| panic!("shutdown must succeed on a live session: {e}"));
    drop(shut_down);

    assert!(
        !cache_dir2.0.join("guard").exists(),
        "a comparable session put through shutdown instead must leave NO guard"
    );
}

/// `shutdown` is documented as called ONCE, but must still be
/// idempotent: a second call must return `Ok(())`, not error or
/// panic.
#[test]
fn shutdown_is_idempotent() {
    let tree = PublishedTree::publish("shutdown-idempotent");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("a healthy tree must mount: {e}"));

    granary_fuse::MountBackend::shutdown(&mut session)
        .unwrap_or_else(|e| panic!("the first shutdown must succeed: {e}"));
    let second = granary_fuse::MountBackend::shutdown(&mut session);
    assert!(
        matches!(second, Ok(())),
        "a second shutdown must be Ok(()), not error or panic: {second:?}"
    );
}

/// `fetch_grain` after `shutdown` must FAIL — a use-after-shutdown is
/// a bug in the caller, and the seam must say so rather than
/// silently serve from the wire (`Fetcher::fetch(None, ..)` is a
/// supported, silent cacheless path that still succeeds; passing
/// `None` unconditionally is exactly the defect this row guards against).
/// Assert on the message so this cannot also pass for an unrelated
/// transport reason.
#[test]
fn fetch_grain_after_shutdown_fails() {
    let tree = PublishedTree::publish("fetch-after-shutdown");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();
    let file_id = tree.file_id;
    let declared = u32::try_from(FILE_CONTENT.len()).unwrap_or_else(|e| panic!("{e}"));

    let mut session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("a healthy tree must mount: {e}"));

    granary_fuse::MountBackend::shutdown(&mut session)
        .unwrap_or_else(|e| panic!("shutdown must succeed: {e}"));

    let err = session
        .fetch_grain(&file_id, declared)
        .expect_err("a read after shutdown must fail, not silently serve from the wire");
    assert!(
        err.to_string().contains("shut down"),
        "the refusal must name the reason (already shut down), not an unrelated transport \
         failure: {err}"
    );
}

// -------------------------------- the adapter's panic and close-failure regressions

/// A PANIC while the
/// session is alive must NOT run the `Drop` backstop's clean-exit
/// close — the guard is the crash signal, and removing it here
/// would tell the next open a crash that just happened never did.
/// Spawns a thread that opens a session and then panics while it
/// is still in scope, so `Drop::drop` runs DURING that thread's
/// unwind (`std::thread::panicking()` is true only then — never for
/// a panic caught upstream and dropped normally afterward). The
/// guard must survive that drop.
#[test]
fn a_panic_while_the_session_is_alive_leaves_the_guard_and_the_cache_unclosed() {
    let tree = PublishedTree::publish("panic-leaves-guard");
    let cache_dir = scratch_cache_dir();
    let cache_dir_path = cache_dir.0.clone();

    let handle = std::thread::spawn(move || {
        let mut sink = Vec::new();
        // `_session`, not `session`: the leading underscore only
        // suppresses the unused-binding lint, it does NOT drop the
        // value early — `_session` still lives until this closure's
        // scope ends, which is exactly what the panic below unwinds
        // through.
        let _session = MountSession::open(
            tree.remote,
            tree.volume,
            None,
            None,
            true,
            None,
            &cache_dir_path,
            1_000_000,
            &origin(),
            MountOptions::default(),
            &mut sink,
        )
        .unwrap_or_else(|e| panic!("a healthy tree must mount: {e}"));
        panic!("simulated FUSE-callback panic with the session still alive");
    });

    assert!(
        handle.join().is_err(),
        "control: the spawned thread must actually have panicked, or this test proves \
         nothing about a panicking Drop"
    );

    assert!(
        cache_dir.0.join("guard").exists(),
        "a Drop that runs during a panic unwind must leave the crash guard in place — \
         removing it here would tell the next open a crash never happened"
    );
}

/// The `Drop` backstop
/// must not discard a genuine close failure silently — it has to
/// warn, naming the cache root, because a daemon that never calls
/// `shutdown` and hits a real I/O failure here (ENOSPC, EACCES)
/// would otherwise leave the guard behind with no diagnostic
/// anywhere. Same mechanism the error-path test below uses for `open`'s own
/// error path: `remove_file(guard)` is the operation that actually
/// fails, and directory WRITE permission is what gates it, so
/// making the cache directory non-writable right after a
/// successful open (guard already on disk, permission still
/// normal at that point) forces it deterministically — no
/// `FreeSpace` seam, no thread race.
///
/// **Skips under uid 0**: root ignores a directory's mode bits (so
/// would a filesystem mounted to ignore them), so `0o555` would
/// refuse nothing and this fixture would verify nothing. Detected
/// via the OWNER of the freshly created scratch directory: this
/// process created it, so if the kernel says uid 0 owns it, this
/// process's own effective uid is 0.
#[test]
fn a_drop_close_failure_is_warned_with_a_root_class_and_leaves_the_guard() {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[derive(Clone, Default)]
    struct EventCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    struct FieldVisitor(String);
    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                let mut visitor = FieldVisitor(String::new());
                event.record(&mut visitor);
                self.0
                    .lock()
                    .unwrap_or_else(|e| panic!("{e}"))
                    .push(visitor.0);
            }
        }
    }

    let cache_dir = scratch_cache_dir();
    let owner_uid = std::fs::metadata(&cache_dir.0)
        .unwrap_or_else(|e| panic!("{e}"))
        .uid();
    if owner_uid == 0 {
        eprintln!(
            "skipping a_drop_close_failure_is_warned_with_a_root_class_and_leaves_the_guard: \
             running as uid 0 — a 0o555 cache directory refuses nothing to root, so this \
             fixture would verify nothing"
        );
        return;
    }

    let tree = PublishedTree::publish("drop-close-failure-warns");
    let mut sink = Vec::new();
    let session = MountSession::open(
        tree.remote,
        tree.volume,
        None,
        None,
        true,
        None,
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .unwrap_or_else(|e| panic!("a healthy tree must mount: {e}"));

    assert!(
        cache_dir.0.join("guard").exists(),
        "control: a successful open must have created the guard, or this test proves \
         nothing about its removal failing"
    );

    std::fs::set_permissions(&cache_dir.0, std::fs::Permissions::from_mode(0o555))
        .unwrap_or_else(|e| panic!("{e}"));

    let capture = EventCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    tracing::subscriber::with_default(subscriber, || drop(session));

    let restored = std::fs::set_permissions(&cache_dir.0, std::fs::Permissions::from_mode(0o755));

    assert!(
        cache_dir.0.join("guard").exists(),
        "control: the guard removal must actually have failed, or this test proves \
         nothing about the warning path"
    );
    let root_str = cache_dir.0.display().to_string();
    let messages = capture.0.lock().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        messages
            .iter()
            .any(|m| m.contains("closing the cache failed")
                && m.contains("crash guard may remain")),
        "the Drop backstop must warn on a close failure, naming that the guard may remain; \
         messages seen: {messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("<cache-root>"))
            && messages.iter().all(|m| !m.contains(&root_str)),
        "the telemetry warning must carry the root class without its spelling; messages seen: {messages:?}"
    );
    drop(messages);
    restored.unwrap_or_else(|e| panic!("{e}"));
}

/// This store double leaves every method `unreached` except `max_seq`,
/// which performs a SIDE EFFECT before answering — it chmods the
/// cache directory `0o555`, then returns the reserved seq `0`.
/// `max_seq` is the ONE call `open_with_cache` makes, for a
/// DISCOVERED seq, between `Cache::open` (already run inside
/// `MountSession::open`, already created the guard as a real
/// writer cache) and the reserved-seq check that refuses the mount
/// — so the chmod lands exactly between "guard exists" and "the
/// error path tries to remove it", with no thread race.
struct ChmodBeforeReservedSeq(std::path::PathBuf);

impl RootStore for ChmodBeforeReservedSeq {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        Err(unreached("put_root"))
    }

    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        Err(unreached("get_root"))
    }

    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        Err(unreached("read_hint"))
    }

    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        Err(unreached("write_hint"))
    }

    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o555))
            .unwrap_or_else(|e| panic!("test setup: chmod the cache dir 0o555: {e}"));
        Ok(Some(0)) // reserved: forces ReservedSeqCandidate right after
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

impl BinStore for ChmodBeforeReservedSeq {
    async fn put_bin(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        Err(unreached("put_bin"))
    }

    async fn put_meta(
        &self,
        _volume: &str,
        _id: &GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        Err(unreached("put_meta"))
    }

    async fn get_meta(&self, _volume: &str, _id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        Err(unreached("get_meta"))
    }

    async fn get_bin_range(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _offset: u64,
        _len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        Err(unreached("get_bin_range"))
    }
}

/// The close-failure
/// warning in `open`'s own error path had NO test — a revert to
/// `let _ = Cache::close(cache);`, or an accidental
/// `return Err(close_err)` that swallowed the ORIGINAL mount
/// error, would both have stayed green. [`ChmodBeforeReservedSeq`]
/// forces the failure deterministically.
///
/// Skips under uid 0 for the same reason `a_drop_close_failure_...`
/// above does.
#[test]
fn a_close_failure_in_the_error_path_returns_the_original_error_and_warns_the_sink() {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let cache_dir = scratch_cache_dir();
    let owner_uid = std::fs::metadata(&cache_dir.0)
        .unwrap_or_else(|e| panic!("{e}"))
        .uid();
    if owner_uid == 0 {
        eprintln!(
            "skipping \
             a_close_failure_in_the_error_path_returns_the_original_error_and_warns_the_sink: \
             running as uid 0 — a 0o555 cache directory refuses nothing to root, so this \
             fixture would verify nothing"
        );
        return;
    }

    let mut sink = Vec::new();
    let err = MountSession::open(
        ChmodBeforeReservedSeq(cache_dir.0.clone()),
        vol("error-path-close-failure"),
        None,
        None,
        true,
        None, // discovered: max_seq IS called, which is where the chmod happens
        &cache_dir.0,
        1_000_000,
        &origin(),
        MountOptions::default(),
        &mut sink,
    )
    .expect_err("a reserved discovered seq must still be refused");

    let restored = std::fs::set_permissions(&cache_dir.0, std::fs::Permissions::from_mode(0o755));

    assert!(
        matches!(
            err,
            MountError::ReservedSeqCandidate {
                seq: 0,
                discovered: true
            }
        ),
        "got {err:?}, wanted the ORIGINAL mount error \
         ReservedSeqCandidate{{seq: 0, discovered: true}} — a fix that returned the close \
         failure instead would be a regression"
    );
    assert!(
        cache_dir.0.join("guard").exists(),
        "control: the guard removal must actually have failed, or this test proves \
         nothing about the warning"
    );
    let message = String::from_utf8_lossy(&sink);
    assert!(
        message.contains("closing the cache after a refused mount failed"),
        "the sink must carry the close-failure warning: {message}"
    );
    restored.unwrap_or_else(|e| panic!("{e}"));
}

// ------------------------------- the `sink` parameter's atomicity, structurally

/// Every write into `open`'s `sink` parameter goes through `write_fmt`.
///
/// **Why this needs a guard and not a comment.** A caller may hand `sink` a
/// writer whose message boundary is `write_fmt` — one complete message per
/// call, admitted whole to a bounded queue or reported lost. `granary-cli`
/// hands it exactly that. [`std::io::Write`] puts no boundary anywhere else:
/// a direct `sink.write_all(..)` is a fragment, and under queue pressure such
/// a writer can admit a PREFIX and drop the remainder while returning `Ok`,
/// truncating operator text.
///
/// **The COUNT of writes into the parameter is not asserted** — it is a
/// population every edit moves, and pinning it would make this row fail
/// for the wrong reason. What is asserted is the PROPERTY: no direct call
/// appears at all.
///
/// The forbidden set is spellings, not a shape, so a new way to write a
/// fragment arrives as an edit a reviewer reads. The needles are ASSEMBLED
/// from fragments so this row does not match itself.
#[test]
fn every_write_into_the_open_sink_parameter_is_a_whole_message() {
    const SOURCE: &str = include_str!("../mount.rs");

    for (head, tail) in [
        ("sink.write", "_all("),
        ("sink.write", "("),
        ("sink.write", "_fmt("),
        ("sink.", "flush("),
        ("Write::write", "(sink"),
        ("Write::write", "_all(sink"),
        ("Write::write", "_fmt(sink"),
        ("Write::", "flush(sink"),
    ] {
        let needle = format!("{head}{tail}");
        assert!(
            !SOURCE.contains(&needle),
            "`{needle}` writes a FRAGMENT into the caller's sink. A caller \
             whose message boundary is `write_fmt` cannot see where such a \
             write ends, so under backpressure it can admit a prefix and drop \
             the rest while reporting success. Use `writeln!`."
        );
    }

    // A POSITIVE control: the property above is worth nothing if the file
    // holds no writes into the parameter at all — a renamed parameter, or a
    // relocated function, would leave every needle absent and this row green
    // over a subject that had moved.
    // NOTE the blind spot this control has, because it is why the qualified
    // spellings above are refused rather than merely discouraged: a
    // `std::io::Write::write_all(sink, ..)` contains `sink,` and would be
    // COUNTED HERE as an acceptable write, masking itself.
    let writes = SOURCE.matches("sink.report(").count();
    assert!(
        writes >= 5,
        "only {writes} write(s) into the `sink` parameter found — the subject \
         of this row has moved or been renamed, and the assertions above are \
         green over nothing"
    );
}

// ------------------------------------------------ accepting a published root after open

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A successor of the tree's honest head for `volume` at `seq`, signed by
/// `key`: `parent` names the real head, and the manifest, binmap and sheaf
/// are the tree's own, so the root names real metadata. `epoch` and
/// `writer_uuid` are the caller's, so two roots at one seq can differ.
fn sign_root(
    tree: &PublishedTree,
    key: &SigningKey,
    volume: &VolumeName,
    seq: u64,
    epoch: u64,
    writer_uuid: [u8; 16],
) -> Vec<u8> {
    let head = current_thread_runtime()
        .block_on(remote_handle(&tree.mem).get_root(tree.volume.as_str(), tree.seq))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("fixture precondition: the honest head must exist"));
    let mut doc = RootDoc {
        volume: volume.clone(),
        seq,
        parent: Some(GrainId::of(&head)),
        writer_uuid,
        epoch,
        timestamp: Timestamp {
            secs: 1_760_000_002,
            nanos: 0,
        },
        chunker_spec: "published-after-open".to_owned(),
        manifest_root: tree.manifest_root,
        binmap_index: tree.binmap_index,
        sheaf_head: tree.sheaf_head,
        sigs: Vec::new(),
    };
    let prefix = root::signing_prefix_of(&doc).unwrap_or_else(|e| panic!("{e:?}"));
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    root::encode_root(&doc).unwrap_or_else(|e| panic!("{e:?}"))
}

/// Put `bytes` into the tree's store as the root of `volume` at `seq`.
fn put_root(tree: &PublishedTree, volume: &VolumeName, seq: u64, bytes: Vec<u8>) {
    current_thread_runtime()
        .block_on(remote_handle(&tree.mem).put_root(volume.as_str(), seq, bytes))
        .unwrap_or_else(|e| panic!("{e}"));
}

/// Sign a root of `volume` at `seq` under the tree's key with `writer_uuid`,
/// put it into the tree's store, and read it back as a `PublishedRoot` under
/// that key.
fn publish_and_read(
    tree: &PublishedTree,
    volume: &VolumeName,
    seq: u64,
    writer_uuid: [u8; 16],
) -> crate::sync::PublishedRoot {
    put_root(
        tree,
        volume,
        seq,
        sign_root(tree, &tree.key, volume, seq, 1, writer_uuid),
    );
    read_published(tree, volume, seq)
}

fn trusted(tree: &PublishedTree) -> granary_store::crypto::TrustedKeys {
    granary_store::crypto::TrustedKeys::new([*tree.key.public_key()])
        .unwrap_or_else(|e| panic!("{e:?}"))
}

fn read_published(
    tree: &PublishedTree,
    volume: &VolumeName,
    seq: u64,
) -> crate::sync::PublishedRoot {
    current_thread_runtime()
        .block_on(crate::sync::PublishedRoot::read(
            &remote_handle(&tree.mem),
            volume,
            seq,
            None,
            &trusted(tree),
        ))
        .unwrap_or_else(|e| panic!("fixture precondition: the planted root must read back: {e}"))
}

/// Open a session on the tree's volume at the discovered head, in the mode
/// the three flags select.
fn open_session(
    tree: &PublishedTree,
    cache_dir: &Path,
    root_key: bool,
    manifest_root: bool,
    trust_server: bool,
    sink: &mut Vec<u8>,
) -> MountSession<GranaryStore<Arc<InMemory>>> {
    MountSession::open(
        remote_handle(&tree.mem),
        tree.volume.clone(),
        root_key.then(|| Box::new(*tree.key.public_key())),
        manifest_root.then_some(tree.manifest_root),
        trust_server,
        None,
        cache_dir,
        1_000_000,
        &origin(),
        MountOptions::default(),
        sink,
    )
    .unwrap_or_else(|e| panic!("a healthy tree must mount: {e}"))
}

/// Shut the session down and reopen its cache directory, so the floors and
/// cached roots it persisted can be read back.
fn close_and_reopen(
    mut session: MountSession<GranaryStore<Arc<InMemory>>>,
    cache_dir: &Path,
) -> Cache {
    granary_fuse::MountBackend::shutdown(&mut session)
        .unwrap_or_else(|e| panic!("shutdown must succeed: {e}"));
    drop(session);
    Cache::open(cache_dir, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"))
}

/// A `PublishedRoot` read for another volume under the same key cannot raise
/// this volume's floor: the session's own head check refuses it before any
/// cache write. Without that check, B's seq would raise A's floor and the
/// corrupt cached root at A's seq 5 would be evicted.
#[test]
fn accept_published_refuses_a_root_of_another_volume_before_touching_the_cache() {
    let tree = PublishedTree::publish("accept-volume-a");
    let cache_dir = scratch_cache_dir();
    let garbage = b"pure garbage, not a root at all";
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding.put_root_bytes(&tree.volume, 5, garbage);
    }
    let mut sink = Vec::new();
    let mut session = open_session(&tree, &cache_dir.0, true, false, false, &mut sink);
    let other = vol("accept-volume-b");
    let root = publish_and_read(&tree, &other, 5, [0xBB; 16]);

    let err = session
        .accept_published(&root, &mut sink)
        .expect_err("another volume's root must be refused");

    let after = close_and_reopen(session, &cache_dir.0);
    assert_eq!(
        (
            matches!(
                err,
                MountError::Resolve(ResolveError::Mismatch { what: "volume", .. })
            ),
            after.read_mount_anchor(&tree.volume),
            after.get_root_bytes(&tree.volume, 5),
        ),
        (true, Some(1), Some(garbage.to_vec())),
        "got {err:?}"
    );
}

/// Accepting a published root raises the MOUNT-PRIVATE floor to its seq and
/// nothing else: the shared anchor keeps its bytes.
#[test]
fn accept_published_raises_only_the_mount_private_floor() {
    let tree = PublishedTree::publish("accept-private-floor");
    let cache_dir = scratch_cache_dir();
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding.raise_anchor(&tree.volume, Some(1), crate::cache::HintUpdate::Unchanged);
    }
    let shared_path = cache_dir.0.join("anchors").join(tree.volume.as_str());
    let read_shared =
        || std::fs::read(&shared_path).unwrap_or_else(|e| panic!("{}: {e}", shared_path.display()));
    let shared_before = read_shared();
    let mut sink = Vec::new();
    let mut session = open_session(&tree, &cache_dir.0, true, false, false, &mut sink);
    let root = publish_and_read(&tree, &tree.volume, 2, [0xAA; 16]);

    session
        .accept_published(&root, &mut sink)
        .unwrap_or_else(|e| panic!("a published successor must be accepted: {e}"));

    let after = close_and_reopen(session, &cache_dir.0);
    assert_eq!(
        (
            after.read_mount_anchor(&tree.volume),
            read_shared() == shared_before,
        ),
        (Some(2), true)
    );
}

/// A cached root at the accepted seq that ALSO verifies is publisher
/// equivocation: refused, with the private floor unchanged.
#[test]
fn accept_published_refuses_a_cached_root_that_also_verifies() {
    let tree = PublishedTree::publish("accept-equivocation");
    let cache_dir = scratch_cache_dir();
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        let forged = sign_root(&tree, &tree.key, &tree.volume, 2, 1, [0xAA; 16]);
        seeding.put_root_bytes(&tree.volume, 2, &forged);
    }
    let mut sink = Vec::new();
    let mut session = open_session(&tree, &cache_dir.0, true, false, false, &mut sink);
    let root = publish_and_read(&tree, &tree.volume, 2, [0xCC; 16]);

    let err = session
        .accept_published(&root, &mut sink)
        .expect_err("two different, both validly-signed, roots at one seq must be refused");

    let after = close_and_reopen(session, &cache_dir.0);
    assert_eq!(
        (
            matches!(err, MountError::CachedRootEquivocation { .. }),
            after.read_mount_anchor(&tree.volume),
        ),
        (true, Some(1)),
        "got {err:?}"
    );
}

/// A cached root at the accepted seq that FAILS the session's check is local
/// corruption: evicted, reported on the sink, and the floor is raised.
#[test]
fn accept_published_evicts_a_cached_root_that_fails_verification() {
    let tree = PublishedTree::publish("accept-unverified-cached");
    let cache_dir = scratch_cache_dir();
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding.put_root_bytes(&tree.volume, 2, b"pure garbage, not a root at all");
    }
    let mut sink = Vec::new();
    let mut session = open_session(&tree, &cache_dir.0, true, false, false, &mut sink);
    let root = publish_and_read(&tree, &tree.volume, 2, [0xCC; 16]);
    sink.clear();

    session
        .accept_published(&root, &mut sink)
        .unwrap_or_else(|e| panic!("a corrupt cached root must be evicted, not refused: {e}"));

    let after = close_and_reopen(session, &cache_dir.0);
    let sink_text = String::from_utf8_lossy(&sink);
    assert_eq!(
        (
            after.get_root_bytes(&tree.volume, 2),
            sink_text.contains(
                "the cached root at (volume=accept-unverified-cached, seq=2) did not verify"
            ),
            after.read_mount_anchor(&tree.volume),
        ),
        (None, true, Some(2)),
        "sink: {sink_text}"
    );
}

/// A floor that cannot be persisted refuses the accept: the raise is last
/// and not best-effort, as at open, and the floor on disk stays where open
/// left it. Skips under uid 0, which a `0o555` directory refuses nothing.
#[test]
fn accept_published_refuses_when_the_private_floor_cannot_be_persisted() {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    let tree = PublishedTree::publish("accept-floor-not-persisted");
    let cache_dir = scratch_cache_dir();
    if std::fs::metadata(&cache_dir.0)
        .unwrap_or_else(|e| panic!("{e}"))
        .uid()
        == 0
    {
        eprintln!("skipping: running as uid 0, which a 0o555 directory refuses nothing");
        return;
    }
    let mut sink = Vec::new();
    let mut session = open_session(&tree, &cache_dir.0, true, false, false, &mut sink);
    let root = publish_and_read(&tree, &tree.volume, 2, [0xCC; 16]);
    // The floor file exists from open; a read-only `anchors/` keeps it
    // readable while the rename that would replace it cannot land.
    let anchors = cache_dir.0.join("anchors");
    std::fs::set_permissions(&anchors, std::fs::Permissions::from_mode(0o555))
        .unwrap_or_else(|e| panic!("{e}"));

    let result = session.accept_published(&root, &mut sink);

    let restored = std::fs::set_permissions(&anchors, std::fs::Permissions::from_mode(0o755));
    drop(session);
    restored.unwrap_or_else(|e| panic!("{e}"));
    let after = Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        (
            matches!(result, Err(MountError::FloorNotPersisted { .. })),
            after.read_mount_anchor(&tree.volume),
        ),
        (true, Some(1)),
        "got {result:?}"
    );
}

/// After `shutdown` the cache is gone: a root accepted then has nowhere to
/// persist its floor, so it is refused rather than silently kept, and the
/// floor on disk is what open left.
#[test]
fn accept_published_refuses_after_the_session_has_shut_down() {
    let tree = PublishedTree::publish("accept-after-shutdown");
    let cache_dir = scratch_cache_dir();
    let mut sink = Vec::new();
    let mut session = open_session(&tree, &cache_dir.0, true, false, false, &mut sink);
    granary_fuse::MountBackend::shutdown(&mut session)
        .unwrap_or_else(|e| panic!("shutdown must succeed: {e}"));
    let root = publish_and_read(&tree, &tree.volume, 2, [0xCC; 16]);

    let err = session
        .accept_published(&root, &mut sink)
        .expect_err("a shut-down session must refuse");

    drop(session);
    let after = Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        (
            matches!(
                err,
                MountError::PublishedRootRefused {
                    reason: "the mount session has already shut down"
                }
            ),
            after.read_mount_anchor(&tree.volume),
        ),
        (true, Some(1)),
        "got {err:?}"
    );
}

/// A session opened without a root key has nothing to check a published root
/// against: `--manifest-root` keeps no floor and `--trust-server` has no
/// key, so both refuse before the same-seq comparison, writing nothing. A
/// different root cached at the accepted seq would otherwise be reported as
/// equivocation on the sink. Case count 2.
#[test]
fn accept_published_refuses_a_session_opened_without_a_root_key() {
    let garbage = b"pure garbage, not a root at all";
    let mut observations = Vec::new();
    for (case, manifest_root, trust_server, floor) in [
        ("manifest-root", true, false, None),
        ("trust-server", false, true, Some(1)),
    ] {
        let tree = PublishedTree::publish("accept-keyless");
        let cache_dir = scratch_cache_dir();
        {
            let mut seeding =
                Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
            seeding.put_root_bytes(&tree.volume, 2, garbage);
        }
        let mut sink = Vec::new();
        let mut session = open_session(
            &tree,
            &cache_dir.0,
            false,
            manifest_root,
            trust_server,
            &mut sink,
        );
        let root = publish_and_read(&tree, &tree.volume, 2, [0xCC; 16]);
        sink.clear();
        let err = session
            .accept_published(&root, &mut sink)
            .expect_err("a keyless session must refuse");
        let after = close_and_reopen(session, &cache_dir.0);
        observations.push((
            case,
            matches!(
                err,
                MountError::PublishedRootRefused {
                    reason: "a re-pin needs a session opened with a root key"
                }
            ),
            sink.is_empty(),
            after.get_root_bytes(&tree.volume, 2) == Some(garbage.to_vec()),
            after.read_mount_anchor(&tree.volume),
            floor,
        ));
    }
    assert_eq!(
        observations,
        vec![
            ("manifest-root", true, true, true, None, None),
            ("trust-server", true, true, true, Some(1), Some(1)),
        ]
    );
}

/// A published root below the session's mount-private floor is a rollback:
/// refused as `StaleHead` before the same-seq comparison, so a corrupt cached
/// root at that seq is neither evicted nor reported, and the floor stays at
/// the higher seq already accepted. Without the refusal the accept evicts the
/// cached root and succeeds, its floor raise a no-op.
#[test]
fn accept_published_refuses_a_seq_below_the_floor_before_touching_the_cache() {
    let tree = PublishedTree::publish("accept-below-floor");
    let cache_dir = scratch_cache_dir();
    let garbage = b"pure garbage, not a root at all";
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding.put_root_bytes(&tree.volume, 2, garbage);
    }
    let mut sink = Vec::new();
    let mut session = open_session(&tree, &cache_dir.0, true, false, false, &mut sink);
    let higher = publish_and_read(&tree, &tree.volume, 3, [0xAA; 16]);
    session
        .accept_published(&higher, &mut sink)
        .unwrap_or_else(|e| panic!("fixture precondition: seq 3 must be accepted: {e}"));
    let lower = publish_and_read(&tree, &tree.volume, 2, [0xCC; 16]);
    sink.clear();

    let result = session.accept_published(&lower, &mut sink);

    let after = close_and_reopen(session, &cache_dir.0);
    assert_eq!(
        (
            matches!(
                result,
                Err(MountError::StaleHead {
                    candidate: 2,
                    mount_floor: 3,
                    kind: FloorKind::MountPrivate,
                    ..
                })
            ),
            after.get_root_bytes(&tree.volume, 2),
            sink.is_empty(),
            after.read_mount_anchor(&tree.volume),
        ),
        (true, Some(garbage.to_vec()), true, Some(3)),
        "got {result:?}"
    );
}

/// A published root at the reserved `u64::MAX`, validly signed, is refused
/// as `open_with_cache` refuses that candidate, before the same-seq
/// comparison: a corrupt cached root there is neither evicted nor reported,
/// and the floor stays where open left it. Without the refusal the accept
/// evicts the cached root and succeeds, its floor raise persisting nothing.
#[test]
fn accept_published_refuses_a_reserved_seq_before_touching_the_cache() {
    let tree = PublishedTree::publish("accept-reserved-seq");
    let cache_dir = scratch_cache_dir();
    let garbage = b"pure garbage, not a root at all";
    {
        let mut seeding =
            Cache::open(&cache_dir.0, 1_000_000, &origin()).unwrap_or_else(|e| panic!("{e}"));
        seeding.put_root_bytes(&tree.volume, u64::MAX, garbage);
    }
    let mut sink = Vec::new();
    let mut session = open_session(&tree, &cache_dir.0, true, false, false, &mut sink);
    let root = publish_and_read(&tree, &tree.volume, u64::MAX, [0xCC; 16]);
    sink.clear();

    let err = session
        .accept_published(&root, &mut sink)
        .expect_err("a root at a reserved seq must be refused");

    let after = close_and_reopen(session, &cache_dir.0);
    assert_eq!(
        (
            matches!(
                err,
                MountError::ReservedSeqCandidate {
                    seq: u64::MAX,
                    discovered: true,
                }
            ),
            after.get_root_bytes(&tree.volume, u64::MAX),
            sink.is_empty(),
            after.read_mount_anchor(&tree.volume),
        ),
        (true, Some(garbage.to_vec()), true, Some(1)),
        "got {err:?}"
    );
}

/// The read helper reserves no successor: a published root at the terminal
/// seq, or at the maximal epoch, is readable where the write-reserving
/// `state_from_head` refuses it, and its binmap is the root's own. Case
/// count 2.
#[test]
fn state_from_published_accepts_read_side_counter_maxima() {
    let tree = PublishedTree::publish("read-side-maxima");
    let remote = remote_handle(&tree.mem);
    let runtime = current_thread_runtime();
    let head = runtime
        .block_on(remote.get_root(tree.volume.as_str(), tree.seq))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("fixture precondition: the honest head must exist"));
    let honest = runtime
        .block_on(crate::publish::state_from_head(
            &remote,
            &tree.volume,
            tree.seq,
            &head,
            &trusted(&tree),
        ))
        .unwrap_or_else(|e| panic!("fixture precondition: the honest head must read: {e}"));
    let mut observations = Vec::new();
    let mut expected = Vec::new();
    for (seq, epoch, overflow) in [(u64::MAX - 1, 1, "root seq"), (2, u64::MAX, "root epoch")] {
        put_root(
            &tree,
            &tree.volume,
            seq,
            sign_root(&tree, &tree.key, &tree.volume, seq, epoch, [0xAA; 16]),
        );
        let root = read_published(&tree, &tree.volume, seq);
        let read = runtime
            .block_on(crate::publish::state_from_published(&remote, &root))
            .map(|state| (state.known.len(), state.bins.len()))
            .map_err(|e| e.to_string());
        let reserved = runtime
            .block_on(crate::publish::state_from_head(
                &remote,
                &tree.volume,
                seq,
                root.bytes(),
                &trusted(&tree),
            ))
            .err()
            .map(|e| match e {
                crate::PublishError::CounterOverflow { what } => what,
                other => panic!("the write-reserving read refused for another reason: {other}"),
            });
        observations.push((seq, read, reserved));
        expected.push((
            seq,
            Ok((honest.known.len(), honest.bins.len())),
            Some(overflow),
        ));
    }
    assert_eq!(observations, expected);
}

impl<R> MountMetrics for CountingRemote<'_, R> {
    fn client_metrics(&self) -> Option<&crate::ClientMetrics> {
        self.metrics.as_ref()
    }
}
impl MountMetrics for FixedMaxSeq {
    fn client_metrics(&self) -> Option<&crate::ClientMetrics> {
        None
    }
}
impl MountMetrics for ChmodBeforeReservedSeq {
    fn client_metrics(&self) -> Option<&crate::ClientMetrics> {
        None
    }
}

mod writable;
