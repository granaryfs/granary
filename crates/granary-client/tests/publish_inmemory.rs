// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Publish semantics, proven hermetically: `gran publish` against an
//! `object_store::memory::InMemory` bucket — no `MinIO`, no network, no
//! credentials (the `MinIO` lane proves the BACKEND; this file proves the
//! PUBLISH LOGIC).
//!
//! Unlike `harvest_integration.rs` — which moved to `granary-cli` with
//! the binary it drives — this file cannot drive the compiled
//! binary: the binary needs an S3 endpoint, and the whole point here is
//! an in-process bucket. It consumes the `granary_client` LIB instead —
//! the same curated surface granary-sim uses, so what this suite can
//! reach is exactly what an out-of-crate caller can reach.
//!
//! Everything asserted about a publish is read back through the REMOTE
//! path — root bytes from `get_root`, binmap objects from `get_meta`,
//! grains from `get_bin_range` + the codec — never from the local store
//! that produced them. The local store is used only as an INDEPENDENT
//! enumeration of what should have been published (its
//! `objects/<2hex>/<64hex>` files are the grain+node set, derived from
//! the filesystem rather than from `publish`'s own bookkeeping).

#![cfg(unix)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use granary_core::binmap::{self, ShardEntry};
use granary_core::clock::Clock;
use granary_core::encoding::DecodeError;
use granary_core::hash::{DIGEST_LEN, GrainId, HashAlgorithm};
use granary_core::identity::WriterIdentity;
use granary_core::manifest::validate_dir_tree;
use granary_core::rng::SeededRng;
use granary_core::root::{self, RootDoc, Timestamp};
use granary_core::rootstore::{RefusalKind, RootStore, RootStoreError};
use granary_core::sheaf::{SheafDoc, SheafOp};
use granary_core::testkit;
use granary_core::thresh::CHUNKER_SPEC;
use granary_store::backend::{GranaryStore, ROOT_MAX_BYTES};
use granary_store::crypto::{self, SigningKey};
use object_store::ObjectStoreExt;
use object_store::memory::InMemory;
use object_store::path::Path as StorePath;

use granary_client::{
    HeadContext, Policy, PublishError, PublishSummary, ResolveOutcome, ResolveTarget, Store,
};

// ------------------------------------------------------------- scratch dir

/// Test-only scratch dir: unique per test, removed on drop. 0444 store
/// object files resist removal of their PARENT on some systems — chmod
/// the tree writable first if the plain remove fails.
struct ScratchDir(PathBuf);

impl ScratchDir {
    // Scoped to this function rather than the crate: a crate-level
    // expect would silence the ban over every future addition to this
    // file, and the pid belongs in exactly one place here.
    #[expect(
        clippy::disallowed_methods,
        reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
    )]
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "granary-publish-it-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if std::fs::remove_dir_all(&self.0).is_err() {
            make_tree_writable(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn make_tree_writable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
            if path.is_dir() {
                make_tree_writable(&path);
            }
        }
    }
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
}

// ------------------------------------------------------------- fixtures

/// The synthetic source tree: a small file, a subdirectory holding one
/// MULTI-GRAIN file (1.5 MiB of xorshift bytes — above the 256 KiB
/// average and the 128 KiB minimum, so the chunker cuts several
/// grains), and a symlink. Deterministic: same bytes on every platform.
fn build_tree(root: &Path) {
    std::fs::create_dir_all(root.join("sub")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(root.join("a.txt"), b"granary publish fixture\n")
        .unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(root.join("sub/big.bin"), testkit::fill(0x5EED, 1_500_000))
        .unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink("a.txt", root.join("link")).unwrap_or_else(|e| panic!("{e}"));
}

fn volume() -> root::VolumeName {
    root::VolumeName::new("cp3-vol".to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

/// A name inside the reserved registry — DNS-1123-legal, so the format
/// accepts it and only admission refuses it.
fn reserved_volume() -> root::VolumeName {
    root::VolumeName::new("gran-reserved".to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

fn stamp(secs: i64) -> Timestamp {
    Timestamp { secs, nanos: 0 }
}

/// A pinned clock for this file's one `HeadContext` — nothing here
/// exercises hint freshness (`head.rs`'s own test module owns that), so a
/// fixed reading keeps the one row that needs a context deterministic.
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        stamp(0)
    }
}

fn head_ctx() -> HeadContext {
    HeadContext::new(Box::new(FixedClock), Box::new(SeededRng::new(1)))
}

/// The writer identity every publish in this file uses. PINNED, like
/// the timestamps beside it: the root bytes this suite asserts on are
/// signed over a `writer_uuid` derived from it, so a value that varied
/// per run would put an ambient input back into bytes the suite
/// compares.
fn identity() -> WriterIdentity {
    WriterIdentity::from_bytes(*b"publish-inmemory")
}

/// Every object id the local store holds, read from the FILESYSTEM
/// (`objects/<2hex>/<64hex>`) — an enumeration of the grain+node set
/// that owes nothing to `publish`'s own accounting.
fn store_object_ids(store_dir: &Path) -> BTreeSet<GrainId> {
    let mut out = BTreeSet::new();
    let objects = store_dir.join("objects");
    for fan in std::fs::read_dir(&objects).unwrap_or_else(|e| panic!("{e}")) {
        let fan = fan.unwrap_or_else(|e| panic!("{e}")).path();
        if !fan.is_dir() {
            continue;
        }
        for obj in std::fs::read_dir(&fan).unwrap_or_else(|e| panic!("{e}")) {
            let name = obj.unwrap_or_else(|e| panic!("{e}")).file_name();
            let hex = name.to_str().unwrap_or_else(|| panic!("utf-8 object name"));
            let mut digest = [0u8; DIGEST_LEN];
            for (i, slot) in digest.iter_mut().enumerate() {
                let byte = hex
                    .get(i * 2..i * 2 + 2)
                    .unwrap_or_else(|| panic!("64 hex chars, got {hex}"));
                *slot = u8::from_str_radix(byte, 16).unwrap_or_else(|e| panic!("{e}"));
            }
            out.insert(GrainId::from_parts(HashAlgorithm::Blake3, digest));
        }
    }
    out
}

/// Every counter of a [`HarvestStats`], as one comparable value.
/// Destructured EXHAUSTIVELY on purpose: a counter added to the struct
/// stops this compiling instead of quietly dropping out of the
/// comparisons that use it.
fn harvest_shape(h: granary_client::HarvestStats) -> [u64; 9] {
    let granary_client::HarvestStats {
        dirs,
        files,
        symlinks,
        grains_total,
        grains_novel,
        bytes_total,
        bytes_novel,
        nodes_total,
        nodes_novel,
    } = h;
    [
        dirs,
        files,
        symlinks,
        grains_total,
        grains_novel,
        bytes_total,
        bytes_novel,
        nodes_total,
        nodes_novel,
    ]
}

/// A whole [`PublishSummary`] as one comparable value, for the same
/// reason and with the same exhaustive destructuring as
/// [`harvest_shape`] — grouped only because a tuple's `PartialEq` stops
/// at twelve elements.
#[expect(
    clippy::type_complexity,
    reason = "the shape IS the point: naming it as an alias would let a field silently leave it"
)]
fn summary_shape(
    s: &PublishSummary,
) -> (
    (u64, u64, u64, u64, u64, u64, u64, u64, u64),
    (bool, u8, bool),
    (GrainId, GrainId, GrainId),
    [u64; 9],
) {
    let PublishSummary {
        seq,
        epoch,
        novel_objects,
        novel_bytes,
        bins_planned,
        bins_uploaded,
        bin_bytes_uploaded,
        shards_total,
        shards_rewritten,
        sheaf_uploaded,
        prefix_bits,
        manifest_root,
        binmap_index,
        sheaf_head,
        hint_written,
        harvest,
    } = *s;
    (
        (
            seq,
            epoch,
            novel_objects,
            novel_bytes,
            bins_planned,
            bins_uploaded,
            bin_bytes_uploaded,
            shards_total,
            shards_rewritten,
        ),
        (sheaf_uploaded, prefix_bits, hint_written),
        (manifest_root, binmap_index, sheaf_head),
        harvest_shape(harvest),
    )
}

// ------------------------------------------------------------- remote view

/// The golden beside `writer_uuid` pins the FUNCTION; this pins the
/// CALL. Without it, `prepare` passing the wrong seq, a constant
/// identity, or another writer's identity leaves every test green — the
/// suite asserts on root bytes but never on what `writer_uuid` should
/// have been. Re-derives from the root's OWN decoded fields, so a
/// disagreement between what was signed and what the inputs say is
/// visible.
///
/// This duplicates the production layout, which is normally the
/// mutation-survival hazard. It is acceptable here only because the
/// literal golden beside `writer_uuid` independently pins that layout:
/// a change that drifted both is still caught there.
fn assert_writer_uuid_derives_from_the_roots_own_fields(doc: &RootDoc) {
    let mut seed = Vec::new();
    seed.extend_from_slice(b"granary-writer-uuid-v2");
    seed.extend_from_slice(&doc.timestamp.secs.to_be_bytes());
    seed.extend_from_slice(&doc.timestamp.nanos.to_be_bytes());
    seed.extend_from_slice(identity().as_bytes());
    seed.extend_from_slice(&doc.seq.to_be_bytes());
    seed.extend_from_slice(doc.volume.as_str().as_bytes());
    seed.extend_from_slice(&doc.manifest_root.to_bytes());
    let digest = *GrainId::of(&seed).digest();
    let expected: [u8; 16] = digest
        .get(..16)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_else(|| panic!("a blake3 digest is 32 bytes"));
    assert_eq!(
        doc.writer_uuid, expected,
        "writer_uuid does not derive from this root's own seq/volume/timestamp/manifest_root          — the CALL passed something the root does not carry"
    );
}

/// The publisher's signature over the root bytes AS STORED — never a
/// re-encode-and-verify, which would check the encoder against itself.
///
/// Not part of the oracle: verifying needs the publishing key, which a
/// reader resolving a volume does not necessarily hold. This suite does
/// hold it, so it checks here.
fn verify_signature(view: &ResolveOutcome, key: &SigningKey) {
    let prefix = root::signed_prefix(&view.root_bytes).unwrap_or_else(|e| panic!("{e}"));
    let sig = view
        .doc
        .sigs
        .first()
        .unwrap_or_else(|| panic!("root carries a signature"));
    assert_eq!(sig.key_id, key.key_id(), "signed under the publisher's key");
    crypto::verify(key.public_key(), prefix, &sig.sig).unwrap_or_else(|e| panic!("{e}"));
}

/// The commit record, with the placement rule the oracle does not
/// enforce: a sheaf is a DIRECTLY-ADDRESSED meta object, so it
/// resolves through `get_meta` — which the oracle
/// did, or this view would not exist — and it must NEVER also appear as
/// a binmap entry. That second half is a publish-policy property, not a
/// resolvability one, so it lives here rather than in the oracle.
fn sheaf_of(view: &ResolveOutcome) -> &SheafDoc {
    assert!(
        !view.entries.contains_key(&view.doc.sheaf_head),
        "the sheaf must NOT be in the binmap"
    );
    &view.sheaf
}

// ------------------------------------------------------------- harness

/// One test's world: an in-memory bucket, a signing key, and a scratch
/// root holding `source/` and `store/` as SIBLINGS (harvest refuses a
/// store nested in its source).
struct World {
    dir: ScratchDir,
    mem: Arc<InMemory>,
    remote: GranaryStore<Arc<InMemory>>,
    key: SigningKey,
}

impl World {
    fn new() -> Self {
        let (key, _seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
        Self::with_key(key)
    }

    /// A world whose publishing key is the CALLER'S — so two worlds can
    /// be built that differ in nothing at all, which is what lets two
    /// publish paths be compared on the bytes they sign (Ed25519 signing
    /// is deterministic, RFC 8032).
    fn with_key(key: SigningKey) -> Self {
        let dir = ScratchDir::new();
        std::fs::create_dir_all(dir.path("source")).unwrap_or_else(|e| panic!("{e}"));
        let mem = Arc::new(InMemory::new());
        let remote = GranaryStore::new(Arc::clone(&mem));
        Self {
            dir,
            mem,
            remote,
            key,
        }
    }

    fn source(&self) -> PathBuf {
        self.dir.path("source")
    }

    fn store_dir(&self) -> PathBuf {
        self.dir.path("store")
    }

    /// One publish invocation, opening (and releasing) the local store
    /// exactly as the CLI does.
    async fn publish(&self, secs: i64, policy: Policy) -> Result<PublishSummary, PublishError> {
        let store = Store::open(&self.store_dir()).unwrap_or_else(|e| panic!("{e}"));
        granary_client::publish(
            &self.remote,
            &store,
            &self.source(),
            &volume(),
            &self.key,
            &identity(),
            stamp(secs),
            policy,
        )
        .await
    }

    async fn publish_ok(&self, secs: i64, policy: Policy) -> PublishSummary {
        self.publish(secs, policy)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// The volume at `seq`, resolved through the LIB's oracle — the same
    /// body the simulator runs against fakes, so a rule this suite pins
    /// is a rule the sim gets too.
    ///
    /// The oracle carries no key and no fixture knowledge, so the two
    /// checks that need those stay here: the signature (see
    /// [`verify_signature`]) and the writer-uuid derivation below.
    async fn view(&self, seq: u64) -> ResolveOutcome {
        let (view, _objects) = self.view_with_objects(seq).await;
        view
    }

    /// [`Self::view`], plus the whole-tree object map a COLLECTOR sink
    /// gathers — the replacement for the removed
    /// `ResolveOutcome.objects` field (materialisation is the caller's
    /// choice; this is that choice, for the tests that re-validate the
    /// tree over remote bytes independently).
    async fn view_with_objects(&self, seq: u64) -> (ResolveOutcome, BTreeMap<GrainId, Vec<u8>>) {
        let (view, objects) =
            granary_client::resolve_at_collecting(&self.remote, volume().as_str(), seq)
                .await
                .unwrap_or_else(|e| panic!("resolve seq {seq}: {e}"));
        assert_writer_uuid_derives_from_the_roots_own_fields(&view.doc);
        (view, objects)
    }
}

// ------------------------------------------------------------- tests

/// First publish: the root lands at seq 1, decodes, verifies under
/// the publisher's key, names the volume it was published to — and the
/// binmap resolves EVERY grain and manifest node the local store holds,
/// each one fetched back through a range GET and hashed.
#[tokio::test]
async fn first_publish_lands_and_reads_back() {
    let w = World::new();
    build_tree(&w.source());

    let summary = w.publish_ok(1_760_000_000, Policy::default()).await;
    assert_eq!(summary.seq, 1);

    let (view, objects) = w.view_with_objects(1).await;
    // The summary describes the root that actually landed — checked
    // against the bytes read back out of the bucket, not trusted.
    assert_eq!(summary.epoch, 1);
    assert_eq!(summary.manifest_root, view.doc.manifest_root);
    assert_eq!(summary.binmap_index, view.doc.binmap_index);
    assert_eq!(summary.sheaf_head, view.doc.sheaf_head);
    assert!(
        summary.novel_bytes > 1_500_000,
        "novel bytes {} covers the whole fixture",
        summary.novel_bytes
    );
    assert!(summary.bin_bytes_uploaded > 0);
    assert_eq!(view.doc.volume.as_str(), "cp3-vol");
    assert_eq!(view.doc.seq, 1);
    assert_eq!(view.doc.parent, None, "seq 1 has no parent");
    assert_eq!(view.doc.epoch, 1);
    assert_eq!(view.doc.chunker_spec, CHUNKER_SPEC.to_string());
    assert_eq!(view.doc.timestamp, stamp(1_760_000_000));
    verify_signature(&view, &w.key);

    // The published id set IS the local store's object set — neither
    // more (no chaff) nor less (nothing dropped). The expectation comes
    // from the filesystem, not from `summary`.
    let expected = store_object_ids(&w.store_dir());
    let published: BTreeSet<GrainId> = view.entries.keys().copied().collect();
    assert!(
        expected.contains(&view.doc.manifest_root),
        "manifest root is one of the harvested objects"
    );
    assert!(
        !published.contains(&view.doc.sheaf_head),
        "the sheaf is meta, never a binmap entry"
    );
    assert_eq!(
        published, expected,
        "binmap covers exactly the harvested objects"
    );
    assert!(summary.sheaf_uploaded, "the commit record was written");
    assert!(
        expected.len() > 5,
        "fixture must be multi-grain, got {} objects",
        expected.len()
    );

    // Full read-back: every entry fetched by range GET, decompressed,
    // and hash-checked (inside `fetch`), then the manifest re-validated
    // over ONLY those remote bytes.
    let stats = validate_dir_tree(&view.doc.manifest_root, &|id| objects.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.dirs, 2, "root + sub");
    assert_eq!(stats.files, 2);
    assert_eq!(stats.symlinks, 1);
    assert_eq!(stats.bytes, 1_500_000 + 24);
    // The harvest's own counters and the remote walk's must agree —
    // two independent counts of the same tree.
    assert_eq!(summary.harvest.dirs, stats.dirs);
    assert_eq!(summary.harvest.files, stats.files);
    assert_eq!(summary.harvest.symlinks, stats.symlinks);
    assert_eq!(summary.harvest.bytes_total, stats.bytes);

    // The sheaf is the first link of the chain.
    let sheaf = sheaf_of(&view);
    assert_eq!(sheaf.parent, None);
    assert_eq!(sheaf.manifest_root, view.doc.manifest_root);
    assert_eq!(sheaf.ops, vec![SheafOp::PublishTree]);
    assert_eq!(sheaf.timestamp, stamp(1_760_000_000));

    // The hint points at the head (advisory, but a successful publish
    // repairs it).
    assert_eq!(
        w.remote
            .max_seq(volume().as_str())
            .await
            .unwrap_or_else(|e| panic!("{e}")),
        Some(1)
    );
    assert!(summary.hint_written);
    drop(w.mem);
}

/// The delta property: appending ONE file to a published tree
/// uploads that file's grains, the nodes that changed, and the new
/// commit record — nothing else. The chain (root parent, sheaf parent)
/// is verified link by link, and the shards that did not change dedup on
/// content address instead of being re-uploaded.
#[tokio::test]
async fn republish_uploads_only_the_delta() {
    let w = World::new();
    build_tree(&w.source());
    // A 4-bit routing width: with 16 shards a delta touches a few and
    // leaves the rest byte-identical, which is what makes the dedup
    // observable at all (at bits = 0 there is one shard and every
    // publish rewrites it).
    let policy = Policy { min_prefix_bits: 4 };

    let first = w.publish_ok(1_760_000_000, policy).await;
    let view1 = w.view(1).await;
    let objects_before = view1.entries.len();

    std::fs::write(
        w.source().join("c.txt"),
        b"appended after the first publish\n",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    // Deliberately DEFAULT policy for the republish: the width floor now
    // has to come from the published root (`prefix_bits` is monotonic per
    // volume). A publisher that forgot to read it would
    // narrow this volume back to a single shard.
    let second = w.publish_ok(1_760_000_060, Policy::default()).await;
    let (view2, objects) = w.view_with_objects(2).await;

    // Chain: root parent is the PREVIOUS ROOT'S BYTES, sheaf parent is
    // the previous sheaf.
    assert_eq!(second.seq, 2);
    assert_eq!(view2.doc.seq, 2);
    assert_eq!(view2.doc.parent, Some(GrainId::of(&view1.root_bytes)));
    assert_eq!(view2.doc.epoch, 2, "epoch = parent.epoch + 1 (v1)");
    verify_signature(&view2, &w.key);
    let sheaf2 = sheaf_of(&view2);
    assert_eq!(sheaf2.parent, Some(view1.doc.sheaf_head));
    assert_eq!(sheaf2.manifest_root, view2.doc.manifest_root);
    assert_ne!(
        view2.doc.manifest_root, view1.doc.manifest_root,
        "the tree changed"
    );

    // The delta: one grain for c.txt and the root dir leaf that now
    // names it. (The sheaf is meta — it is not in these counts.)
    assert!(
        second.novel_objects < 10,
        "delta publish uploaded {} objects",
        second.novel_objects
    );
    assert!(
        objects_before > 5,
        "the volume must be much larger than the delta ({objects_before} objects)"
    );
    assert_eq!(
        u64::try_from(view2.entries.len() - objects_before).unwrap_or_else(|e| panic!("{e}")),
        second.novel_objects,
        "the binmap grew by exactly the novel objects"
    );
    assert_eq!(second.bins_planned, 1, "one bin holds the whole delta");
    assert_eq!(second.bins_uploaded, 1);
    assert!(second.sheaf_uploaded);
    assert!(
        !view2.entries.contains_key(&view2.doc.sheaf_head),
        "the sheaf is never a binmap entry"
    );

    // Shard dedup: unchanged shards are content-identical, so `put_meta`
    // reports them as already present.
    assert_eq!(second.prefix_bits, 4);
    assert_eq!(second.shards_total, 16);
    assert!(
        second.shards_rewritten < second.shards_total,
        "every shard was rewritten ({} of {})",
        second.shards_rewritten,
        second.shards_total
    );
    assert!(
        second.shards_rewritten >= 1,
        "the delta must land somewhere"
    );
    let deduped = second.shards_total - second.shards_rewritten;
    assert!(deduped >= 1, "no shard deduped");
    let unchanged: Vec<&GrainId> = view2
        .shard_ids
        .iter()
        .zip(&view1.shard_ids)
        .filter(|(new, old)| new == old)
        .map(|(new, _)| new)
        .collect();
    assert_eq!(
        u64::try_from(unchanged.len()).unwrap_or_else(|e| panic!("{e}")),
        deduped,
        "the shards that deduped are exactly the ones whose id did not move"
    );
    assert_eq!(view2.prefix_bits, view1.prefix_bits, "width never narrows");

    // Everything the volume has EVER published still resolves through
    // the remote path — the old objects were not disturbed by the
    // rewrite, and the new manifest validates over remote bytes only.
    let stats = validate_dir_tree(&view2.doc.manifest_root, &|id| objects.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.files, 3);
    assert_eq!(first.seq, 1);
    drop(w.mem);
}

/// Dedup-only republish:
/// republishing an IDENTICAL tree advances seq and the
/// sheaf chain, keeps `manifest_root`, and writes EXACTLY TWO objects —
/// the commit record and the root. No bin, no shard, no bin table, no
/// new binmap index: the new root carries the previous root's
/// `binmap_index` id byte for byte.
#[tokio::test]
async fn dedup_only_republish_writes_only_the_sheaf_and_the_root() {
    let w = World::new();
    build_tree(&w.source());
    let policy = Policy { min_prefix_bits: 4 };
    w.publish_ok(1_760_000_000, policy).await;
    let second = w.publish_ok(1_760_000_060, Policy::default()).await;
    let view2 = w.view(2).await;

    let third = w.publish_ok(1_760_000_120, Policy::default()).await;
    let (view3, objects) = w.view_with_objects(3).await;

    assert_eq!(third.seq, 3, "seq advances on a dedup-only publish");
    assert_eq!(view3.doc.epoch, 3);
    assert_eq!(view3.doc.parent, Some(GrainId::of(&view2.root_bytes)));
    assert_eq!(
        view3.doc.manifest_root, view2.doc.manifest_root,
        "identical tree, identical manifest root"
    );
    verify_signature(&view3, &w.key);

    // The sheaf advanced, and it is the ONLY object written besides the
    // root: it is meta, so it never touches the bin/binmap layer.
    assert_ne!(view3.doc.sheaf_head, view2.doc.sheaf_head);
    assert!(third.sheaf_uploaded);
    let sheaf3 = sheaf_of(&view3);
    assert_eq!(sheaf3.parent, Some(view2.doc.sheaf_head));
    assert_eq!(sheaf3.manifest_root, view3.doc.manifest_root);
    assert_eq!(third.novel_objects, 0, "no grain, no manifest node");
    assert_eq!(third.bins_planned, 0);
    assert_eq!(third.bins_uploaded, 0);
    assert_eq!(third.bin_bytes_uploaded, 0);
    assert_eq!(third.shards_rewritten, 0, "the binmap was not rebuilt");

    // Byte-identical binmap: same index id, same bin-table id, same
    // shard ids, same entries, same bin table.
    assert_eq!(
        view3.doc.binmap_index, view2.doc.binmap_index,
        "the new root reuses the previous binmap index"
    );
    assert_eq!(third.binmap_index, view2.doc.binmap_index);
    assert_eq!(view3.bin_table, view2.bin_table, "bin table id unchanged");
    assert_eq!(view3.shard_ids, view2.shard_ids);
    assert_eq!(view3.entries, view2.entries);
    assert_eq!(view3.bins, view2.bins);
    assert_eq!(third.shards_total, second.shards_total);

    // …and the whole volume still reads back through that binmap.
    validate_dir_tree(&view3.doc.manifest_root, &|id| objects.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    drop(w.mem);
}

/// `untouched`'s SECOND conjunct (`prefix_bits ==
/// state.prefix_bits`) is load-bearing, and a publish that raises
/// `min_prefix_bits` while ALSO having new objects to map cannot
/// show it, because `new_entries.is_empty()` is already false there.
/// This test isolates it: an otherwise
/// dedup-only republish (identical tree, nothing new) that raises
/// `min_prefix_bits` from 2 to 6 must still REBUILD — reused
/// (`new_entries.is_empty()`) is not the same question as
/// unchanged-width, and dropping the second conjunct would silently
/// keep serving the 4-shard binmap while the SUMMARY still claims
/// `prefix_bits=6, shards_total=64` — the operator's request discarded,
/// the summary disagreeing with the object it names. Assertions read the
/// PUBLISHED object back (`view2.prefix_bits`, `view2.shard_ids.len()`),
/// not merely the summary, so a dropped conjunct cannot pass by only
/// getting the summary's bookkeeping right.
#[tokio::test]
async fn raising_min_prefix_bits_on_a_dedup_only_publish_forces_a_rebuild() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(1_760_000_000, Policy { min_prefix_bits: 2 })
        .await;
    let view1 = w.view(1).await;
    assert_eq!(view1.prefix_bits, 2);
    assert_eq!(view1.shard_ids.len(), 4);

    let second = w
        .publish_ok(1_760_000_060, Policy { min_prefix_bits: 6 })
        .await;
    let (view2, objects) = w.view_with_objects(2).await;

    assert_eq!(
        second.novel_objects, 0,
        "identical tree — nothing new to map"
    );
    assert_eq!(second.prefix_bits, 6, "the summary claims the new width");
    assert_eq!(second.shards_total, 64, "the summary claims 64 shards");
    // The object the root actually names must agree with the summary —
    // this is the assertion a dropped conjunct fails.
    assert_eq!(
        view2.prefix_bits, 6,
        "the PUBLISHED index must actually carry the new width"
    );
    assert_eq!(
        view2.shard_ids.len(),
        64,
        "the PUBLISHED index must actually have 64 shards"
    );
    assert_ne!(
        view2.doc.binmap_index, view1.doc.binmap_index,
        "a real rebuild is a NEW object, not the reused 4-shard index"
    );
    assert!(
        second.shards_rewritten > 0,
        "a real rebuild writes shard objects"
    );

    // …and the volume still resolves entirely through the new binmap.
    validate_dir_tree(&view2.doc.manifest_root, &|id| objects.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    drop(w.mem);
}

/// Lost CAS race: a second writer claims the seq between this
/// publish's state read and its put-if-absent. v1 fails LOUDLY — no
/// rebase loop — and leaves nothing behind at the next seq.
#[tokio::test]
async fn lost_cas_race_fails_loudly_and_writes_nothing_further() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(1_760_000_000, Policy::default()).await;

    // Prepared: everything uploaded, seq 2 not yet claimed. This is the
    // exact window a real race lands in.
    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let prepared = granary_client::prepare(
        &w.remote,
        &store,
        &w.source(),
        &volume(),
        &w.key,
        &identity(),
        stamp(1_760_000_060),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(prepared.seq(), 2);

    // The other writer, on its own handle over the same bucket.
    let racer = GranaryStore::new(Arc::clone(&w.mem));
    racer
        .put_root(volume().as_str(), 2, b"another writer's root".to_vec())
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let err = granary_client::commit(&w.remote, prepared)
        .await
        .err()
        .unwrap_or_else(|| panic!("commit must refuse a taken seq"));
    match &err {
        PublishError::LostRace {
            volume: v,
            attempted,
            head,
        } => {
            assert_eq!(v, "cp3-vol");
            assert_eq!(*attempted, 2);
            assert_eq!(*head, 2, "the diagnostic listing head");
        }
        other => panic!("wrong error: {other}"),
    }
    let msg = err.to_string();
    assert!(msg.contains("seq 2"), "message must name the seq: {msg}");
    assert!(
        msg.contains("cp3-vol"),
        "message must name the volume: {msg}"
    );

    // Nothing was written past the contested seq, and the occupant's bytes
    // are untouched.
    assert_eq!(
        w.remote
            .get_root(volume().as_str(), 3)
            .await
            .unwrap_or_else(|e| panic!("{e}")),
        None
    );
    assert_eq!(
        w.remote
            .get_root(volume().as_str(), 2)
            .await
            .unwrap_or_else(|e| panic!("{e}")),
        Some(b"another writer's root".to_vec())
    );
    drop(w.mem);
}

/// **The one-probe rule BRANCHES on `get_root`, so every outcome
/// `get_root` can produce is a branch — including the read bound's
/// refusal.** An object larger than `ROOT_MAX_BYTES` planted at our seq
/// is DEFINITIVELY FOREIGN: no publish this client could have made
/// produces one, since a maximal root is three orders of magnitude
/// smaller. The probe therefore has its answer, and that the answer
/// arrives as a refusal rather than as bytes changes nothing about what
/// it says — the seq is occupied by someone else.
///
/// Bounding the read moved this case from `Ok(Some(foreign))` to
/// `Err(RefusedResponse)`, and the fall-through arm reports the ORIGINAL
/// put error instead: the publish still fails safely, but the operator is
/// told "the backend said `AlreadyExists`" rather than "you lost the race
/// for seq 2, the head is 2" — the diagnostic the probe exists to produce.
///
/// The bound tolerating a new error variant is not the same as every
/// caller tolerating it. This is the one production caller that DECIDES
/// on `get_root`'s shape.
#[tokio::test]
async fn an_unreadably_large_object_at_our_seq_is_still_a_lost_race() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(1_760_000_000, Policy::default()).await;

    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let prepared = granary_client::prepare(
        &w.remote,
        &store,
        &w.source(),
        &volume(),
        &w.key,
        &identity(),
        stamp(1_760_000_060),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(prepared.seq(), 2);

    // Planted through the RAW handle: `put_root` would refuse nothing
    // here, but no granary write path produces an object this size, which
    // is precisely what makes it recognisably foreign.
    let oversized = usize::try_from(ROOT_MAX_BYTES + 1).unwrap_or_else(|e| panic!("{e}"));
    w.mem
        .put(
            &StorePath::from("root/cp3-vol/00000000000000000002"),
            vec![0x5A; oversized].into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // The probe really cannot read it — the premise of the whole test —
    // and the refusal's KIND is what `commit` now branches on: only
    // `OverCap` proves the occupant foreign.
    assert!(
        matches!(
            w.remote.get_root(volume().as_str(), 2).await,
            Err(RootStoreError::RefusedResponse {
                kind: RefusalKind::OverCap,
                ..
            })
        ),
        "the planted object must be refused as OverCap by the read bound, or this test proves \
         nothing"
    );

    let err = granary_client::commit(&w.remote, prepared)
        .await
        .err()
        .unwrap_or_else(|| panic!("commit must refuse a taken seq"));
    match &err {
        PublishError::LostRace {
            volume: v,
            attempted,
            head,
        } => {
            assert_eq!(v, "cp3-vol");
            assert_eq!(*attempted, 2);
            assert_eq!(
                *head, 2,
                "the contested seq is the floor, and the listing sees the planted key"
            );
        }
        other => panic!(
            "an unreadable object at our seq is a LOST RACE, not a transport failure: {other}"
        ),
    }
    drop(w.mem);
}

/// Empty volume: an empty directory is encodable, so
/// the path exists — one manifest node, one bin, and (the same deviation
/// as the dedup-only case) the commit record alongside it.
#[tokio::test]
async fn empty_volume_publishes() {
    let w = World::new();
    let summary = w.publish_ok(1_760_000_000, Policy::default()).await;
    let (view, objects) = w.view_with_objects(1).await;

    assert_eq!(summary.seq, 1);
    assert_eq!(summary.novel_objects, 1, "the empty dir leaf");
    assert_eq!(summary.bins_planned, 1);
    assert_eq!(summary.bins_uploaded, 1);
    assert_eq!(summary.prefix_bits, 0, "one shard for a one-object volume");
    assert_eq!(summary.shards_total, 1);
    assert_eq!(view.entries.len(), 1, "one binmap entry");
    assert_eq!(view.bins.len(), 1, "one bin");
    assert_eq!(
        view.entries.keys().copied().collect::<Vec<GrainId>>(),
        vec![view.doc.manifest_root],
        "the mapped volume is exactly its root node"
    );
    // …plus the commit record, directly addressed.
    assert!(summary.sheaf_uploaded);
    let sheaf = sheaf_of(&view);
    assert_eq!(sheaf.parent, None);
    assert_eq!(sheaf.manifest_root, view.doc.manifest_root);

    let stats = validate_dir_tree(&view.doc.manifest_root, &|id| objects.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.dirs, 1);
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.files, 0);
    drop(w.mem);
}

/// The publish set is the MANIFEST CLOSURE, not "everything in the
/// local store": an object harvested earlier and no longer referenced by
/// the tree is not uploaded. (A store-wide publish would pass every
/// other test in this file — this is the one that distinguishes them.)
#[tokio::test]
async fn unreachable_objects_in_the_local_store_are_not_published() {
    let w = World::new();
    build_tree(&w.source());
    // Harvest a file into the store, then remove it from the source: its
    // grain is in the local CAS and reachable from NO published tree.
    let orphan_bytes = b"only ever harvested, never published\n";
    std::fs::write(w.source().join("orphan.txt"), orphan_bytes).unwrap_or_else(|e| panic!("{e}"));
    {
        let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
        granary_client::harvest(&w.source(), &store).unwrap_or_else(|e| panic!("{e}"));
    }
    std::fs::remove_file(w.source().join("orphan.txt")).unwrap_or_else(|e| panic!("{e}"));
    let orphan = GrainId::of(orphan_bytes);
    assert!(
        store_object_ids(&w.store_dir()).contains(&orphan),
        "the orphan grain must be in the local store for this test to mean anything"
    );

    w.publish_ok(1_760_000_000, Policy::default()).await;
    let view = w.view(1).await;
    assert!(
        !view.entries.contains_key(&orphan),
        "an unreachable local object was published"
    );
    drop(w.mem);
}

/// Two BYTE-IDENTICAL files is an ordinary tree, not a
/// contrived fixture — no existing fixture had duplicate content, so
/// `push_grain`'s dedup (`emitted.insert`, which keeps a repeated grain id
/// out of the packer's frame list) was reachable by NO test: removing
/// it passed the whole suite while this exact tree — two files sharing
/// one grain — dies in `binfmt::encode_bin` with "duplicate grain id …
/// in one bin" the moment two references to the SAME grain reach one
/// bin's frame list.
#[tokio::test]
async fn two_byte_identical_files_publish_successfully() {
    let w = World::new();
    let shared = b"these two files hold the exact same bytes\n";
    std::fs::write(w.source().join("a.txt"), shared).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(w.source().join("b.txt"), shared).unwrap_or_else(|e| panic!("{e}"));

    let summary = w.publish_ok(1_760_000_000, Policy::default()).await;
    let (view, objects) = w.view_with_objects(1).await;
    assert_eq!(summary.seq, 1);

    // Both files resolve, through the remote path, to the SAME shared
    // grain — content addressing working as intended — and the tree
    // still validates as two files over one grain's worth of bytes.
    let stats = validate_dir_tree(&view.doc.manifest_root, &|id| objects.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.files, 2, "two files published");
    assert_eq!(
        stats.bytes,
        2 * u64::try_from(shared.len()).unwrap_or_else(|e| panic!("{e}")),
        "two files, each counted at its own declared size — dedup is a \
         STORAGE property (one shared grain), not a manifest property"
    );
    drop(w.mem);
}

/// A head root whose signature does not check out is refused — the
/// `key_id` matching is not the check, the SIGNATURE is.
#[tokio::test]
async fn a_tampered_head_root_is_refused() {
    use object_store::ObjectStoreExt as _;

    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(1_760_000_000, Policy::default()).await;
    let view = w.view(1).await;

    // Same key_id, same alg, same length — one flipped signature byte.
    let mut tampered = view.root_bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    root::decode_root(&tampered).unwrap_or_else(|e| panic!("still a decodable root: {e}"));
    w.mem
        .put(
            &object_store::path::Path::from("root/cp3-vol/00000000000000000001"),
            tampered.into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let err = granary_client::publish(
        &w.remote,
        &store,
        &w.source(),
        &volume(),
        &w.key,
        &identity(),
        stamp(1_760_000_060),
        Policy::default(),
    )
    .await
    .err()
    .unwrap_or_else(|| panic!("a tampered chain must not be extended"));
    assert!(
        matches!(err, PublishError::BadSignature { seq: 1 }),
        "wrong error: {err}"
    );
    drop(w.mem);
}

/// The trust model is self-publish: a publisher
/// extends only a chain it signed. A head root carrying
/// nobody's signature but a stranger's is refused BEFORE
/// anything is uploaded — publishing over it would silently
/// fork the volume under a key this client cannot check.
#[tokio::test]
async fn a_head_root_this_key_did_not_sign_is_refused() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(1_760_000_000, Policy::default()).await;

    let (stranger, _seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let err = granary_client::publish(
        &w.remote,
        &store,
        &w.source(),
        &volume(),
        &stranger,
        &identity(),
        stamp(1_760_000_060),
        Policy::default(),
    )
    .await
    .err()
    .unwrap_or_else(|| panic!("a foreign chain must not be extended"));
    assert!(
        matches!(err, PublishError::UnknownSigner { seq: 1 }),
        "wrong error: {err}"
    );
    drop(w.mem);
}

/// Cross-volume replay: a root copied
/// verbatim into another volume's key space VERIFIES — the signature
/// says who wrote it, never what it was for. The publisher must require
/// the embedded name to be the volume it fetched from, so a replayed
/// root can never become the parent of a real one.
#[tokio::test]
async fn a_root_replayed_into_another_volume_is_refused() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(1_760_000_000, Policy::default()).await;
    let view = w.view(1).await;

    // Same bytes, same signature, different key space.
    let other = root::VolumeName::new("other-vol".to_owned()).unwrap_or_else(|e| panic!("{e}"));
    let planter = GranaryStore::new(Arc::clone(&w.mem));
    planter
        .put_root(other.as_str(), 1, view.root_bytes.clone())
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let err = granary_client::publish(
        &w.remote,
        &store,
        &w.source(),
        &other,
        &w.key,
        &identity(),
        stamp(1_760_000_060),
        Policy::default(),
    )
    .await
    .err()
    .unwrap_or_else(|| panic!("a replayed root must not be extended"));
    match &err {
        PublishError::VolumeMismatch { want, got } => {
            assert_eq!(want, "other-vol");
            assert_eq!(got, "cp3-vol");
        }
        other => panic!("wrong error: {other}"),
    }
    drop(w.mem);
}

/// C3: a binmap object the head root names but the bucket does not
/// have is refused BY NAME (`MissingMeta`) — the same shape
/// `MissingRoot` already gives a missing root one layer up, rather than
/// a bare `Remote(NotFound)` that names neither the volume, the head
/// seq, nor which object.
#[tokio::test]
async fn missing_binmap_index_is_refused_by_name() {
    use object_store::ObjectStoreExt as _;

    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(1_760_000_000, Policy::default()).await;
    let view1 = w.view(1).await;

    // Delete the binmap index directly from the bucket — the same
    // "concurrent delete" scenario `MissingRoot`'s doc already names.
    let hex = view1.doc.binmap_index.digest_hex();
    let fan = &hex[..2];
    let key = object_store::path::Path::from(format!("meta/{}/{fan}/{hex}", volume().as_str()));
    w.mem.delete(&key).await.unwrap_or_else(|e| panic!("{e}"));

    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let err = granary_client::publish(
        &w.remote,
        &store,
        &w.source(),
        &volume(),
        &w.key,
        &identity(),
        stamp(1_760_000_060),
        Policy::default(),
    )
    .await
    .err()
    .unwrap_or_else(|| panic!("a missing binmap index must be refused"));
    match &err {
        PublishError::MissingMeta {
            what,
            id,
            volume: v,
            seq,
        } => {
            assert_eq!(*what, "binmap index");
            assert_eq!(*id, view1.doc.binmap_index);
            assert_eq!(v, "cp3-vol");
            assert_eq!(*seq, 1);
        }
        other => panic!("wrong error: {other}"),
    }
    let msg = err.to_string();
    assert!(msg.contains("binmap index"), "names the role: {msg}");
    assert!(msg.contains("cp3-vol"), "names the volume: {msg}");
    assert!(msg.contains(" 1"), "names the seq: {msg}");
    drop(w.mem);
}

// ---------------------------- the production-path guards ------------

/// Re-sign a forged head at seq 2 whose binmap layout the test controls.
/// Everything goes through the PUBLIC content-addressed APIs — no raw
/// handles — so what this forges is exactly what a hostile-but-signed
/// publisher could place.
///
/// `mutate_shards` corrupts the binmap layout (routing, ordinals — any
/// field of any `ShardEntry`, since the closure gets the grouped shards
/// directly); `mutate_doc` runs LAST, after every other field is set to
/// its normal, internally-consistent value but BEFORE signing, so a
/// test can make the signed doc itself inconsistent (e.g. a `seq` that
/// disagrees with the key it is about to be stored at) — something
/// `mutate_shards` alone can never reach, since it never sees the doc.
async fn forge_head(
    w: &World,
    mutate_shards: impl FnOnce(&mut Vec<Vec<ShardEntry>>),
    mutate_doc: impl FnOnce(&mut RootDoc),
) -> Result<(), PublishError> {
    let v1 = w.view(1).await;
    let vol = volume();
    // Regroup the head's entries by their CORRECT shard...
    let shard_count = 1usize << v1.prefix_bits;
    let mut grouped: Vec<Vec<ShardEntry>> = vec![Vec::new(); shard_count];
    for e in v1.entries.values() {
        grouped
            .get_mut(binmap::shard_for(&e.id, v1.prefix_bits))
            .unwrap_or_else(|| panic!("route"))
            .push(*e);
    }
    // ...then let the test corrupt the LAYOUT (each shard stays
    // internally sorted so only the cross-object rule is violated).
    mutate_shards(&mut grouped);
    for g in &mut grouped {
        g.sort_by_key(|e| e.id);
    }
    let mut shard_ids = Vec::new();
    for g in &grouped {
        let bytes = binmap::encode_shard(g).unwrap_or_else(|e| panic!("{e}"));
        let id = GrainId::of(&bytes);
        w.remote
            .put_meta(vol.as_str(), &id, bytes)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        shard_ids.push(id);
    }
    let index_bytes = binmap::encode_binmap_index(v1.prefix_bits, v1.bin_table, &shard_ids)
        .unwrap_or_else(|e| panic!("{e}"));
    let index_id = GrainId::of(&index_bytes);
    w.remote
        .put_meta(vol.as_str(), &index_id, index_bytes)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mut doc = v1.doc.clone();
    doc.seq = 2;
    doc.parent = Some(GrainId::of(&v1.root_bytes));
    doc.epoch += 1;
    doc.binmap_index = index_id;
    doc.sigs.clear();
    mutate_doc(&mut doc);
    let prefix = root::signing_prefix_of(&doc).unwrap_or_else(|e| panic!("{e}"));
    doc.sigs.push(root::RootSig {
        key_id: w.key.key_id(),
        sig: w.key.sign(&prefix),
    });
    let bytes = root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
    w.remote
        .put_root(vol.as_str(), 2, bytes)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // A publish reading this head must refuse it during remote_state.
    w.publish(300, Policy::default()).await.map(|_| ())
}

/// A signed, content-addressed, locally-valid binmap whose entries sit
/// in the WRONG shards is refused as remote state.
#[tokio::test]
async fn misrouted_binmap_head_is_refused() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(100, Policy { min_prefix_bits: 2 }).await;
    let err = forge_head(
        &w,
        |grouped| {
            // Move one entry from its home shard to a different one.
            let from = grouped
                .iter()
                .position(|g| !g.is_empty())
                .unwrap_or_else(|| panic!("no entries"));
            let e = grouped
                .get_mut(from)
                .unwrap_or_else(|| panic!("from"))
                .pop()
                .unwrap_or_else(|| panic!("entry"));
            let to = (from + 1) % grouped.len();
            grouped.get_mut(to).unwrap_or_else(|| panic!("to")).push(e);
        },
        |_| {},
    )
    .await
    .expect_err("misrouted binmap must be refused");
    assert!(
        matches!(
            err,
            PublishError::Decode {
                what: "binmap shard",
                source: DecodeError::Invalid {
                    what: "shard entry routed to the wrong shard"
                }
            }
        ),
        "got {err:?}"
    );
    drop(w.mem);
}

/// The same grain id in TWO shards is refused. At fixed prefix bits an
/// id has exactly ONE home shard, so a cross-shard duplicate NECESSARILY
/// misroutes one copy — the routing refusal is the observable behaviour,
/// and the separate cross-shard uniqueness check in `remote_state` is
/// unreachable-by-construction defense behind it (kept, and recorded as
/// such).
#[tokio::test]
async fn duplicate_id_across_shards_is_refused() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(100, Policy { min_prefix_bits: 2 }).await;
    let err = forge_head(
        &w,
        |grouped| {
            let from = grouped
                .iter()
                .position(|g| !g.is_empty())
                .unwrap_or_else(|| panic!("no entries"));
            let e = *grouped
                .get(from)
                .and_then(|g| g.first())
                .unwrap_or_else(|| panic!("entry"));
            let to = (from + 1) % grouped.len();
            grouped.get_mut(to).unwrap_or_else(|| panic!("to")).push(e);
        },
        |_| {},
    )
    .await
    .expect_err("cross-shard duplicate must be refused");
    assert!(
        matches!(
            err,
            PublishError::Decode {
                what: "binmap shard",
                source: DecodeError::Invalid {
                    what: "shard entry routed to the wrong shard"
                }
            }
        ),
        "got {err:?}"
    );
    drop(w.mem);
}

/// `SeqMismatch` — the head root's embedded `seq` field
/// disagreeing with the KEY it lives at. `forge_head` sets
/// `doc.seq = 2`, runs its `mutate_doc` hook, signs, and only then
/// stores the doc at key 2, so this test's hook sets `doc.seq = 3`
/// to pull the field and the key apart.
#[tokio::test]
async fn seq_mismatch_between_the_doc_field_and_its_key_is_refused() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(100, Policy { min_prefix_bits: 2 }).await;
    let err = forge_head(&w, |_| {}, |doc| doc.seq = 3)
        .await
        .expect_err("a doc.seq disagreeing with its key must be refused");
    assert!(
        matches!(
            err,
            PublishError::SeqMismatch {
                key_seq: 2,
                doc_seq: 3
            }
        ),
        "got {err:?}"
    );
    drop(w.mem);
}

/// `validate_ordinals`'s cross-object bound — a shard entry's
/// `bin_ordinal` past the bin table's length. `bin_ordinal` is a
/// public field of `ShardEntry`, and `forge_head` hands its
/// `mutate_shards` closure the grouped shards directly, so
/// this test sets that field past the table's end
/// through the closure, with no change to
/// `forge_head` itself.
#[tokio::test]
async fn shard_ordinal_past_the_bin_table_is_refused() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(100, Policy { min_prefix_bits: 2 }).await;
    let err = forge_head(
        &w,
        |grouped| {
            let g = grouped
                .iter_mut()
                .find(|g| !g.is_empty())
                .unwrap_or_else(|| panic!("no entries"));
            let e = g.first_mut().unwrap_or_else(|| panic!("entry"));
            // Past the ACTUAL table, but INSIDE the frozen ceiling
            // `BIN_TABLE_MAX_BINS` — `encode_shard` refuses any ordinal
            // at or past that ceiling (`u32::MAX` included), so such a
            // value could not even be minted into a shard. This value
            // is the case
            // `validate_ordinals` actually exists for: only a caller
            // holding the bin table can know the table is shorter than
            // this, which is precisely the cross-object rule under
            // test here.
            e.bin_ordinal = binmap::BIN_TABLE_MAX_BINS - 1;
        },
        |_| {},
    )
    .await
    .expect_err("an out-of-range bin_ordinal must be refused");
    assert!(
        matches!(
            err,
            PublishError::Decode {
                what: "binmap shard",
                source: DecodeError::Invalid {
                    what: "shard bin_ordinal past bin table"
                }
            }
        ),
        "got {err:?}"
    );
    drop(w.mem);
}

/// The CLI wrapper and the generic entry point must not drift apart.
/// `prepare` harvests and then delegates to `prepare_from_manifest`; the
/// simulator calls `prepare_from_manifest` directly, so those are two
/// doors into the same publish. Nothing else in this suite compares
/// them: a wrapper that passed a different timestamp, identity, policy
/// or manifest root through — or one that stopped delegating and grew a
/// second copy of the flow — would leave every other test here green
/// while the simulated path published something the shipped path never
/// produces.
///
/// TWO WORLDS, differing in nothing, rather than two calls against one
/// bucket. Same fixture bytes, same volume, same writer identity, same
/// timestamp, same policy, same signing key (from one seed — Ed25519
/// signing is deterministic, RFC 8032), each with its own empty bucket
/// and its own fresh local store. So both halves resolve seq 1 against
/// an empty volume from a FIRST harvest, and every field of both
/// summaries is directly comparable — including the novel counts, which
/// a second harvest into a warm store would zero for a legitimate
/// reason and so could not be asserted on.
#[tokio::test]
async fn prepare_from_manifest_publishes_exactly_what_the_cli_wrapper_does() {
    let (_key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let key = || SigningKey::from_seed(&seed).unwrap_or_else(|e| panic!("{e}"));

    // The wrapper, exactly as the CLI runs it: harvest inside `prepare`.
    let wrapped = World::with_key(key());
    build_tree(&wrapped.source());
    let store = Store::open(&wrapped.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let via_wrapper = granary_client::prepare(
        &wrapped.remote,
        &store,
        &wrapped.source(),
        &volume(),
        &wrapped.key,
        &identity(),
        stamp(1_760_000_000),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let wrapper_root_bytes = via_wrapper.root_bytes.clone();
    let wrapper_seq = via_wrapper.seq();
    drop(store); // release the flock

    // The seam the sim drives: harvest hoisted out, the manifest root and
    // its stats handed in.
    let seamed = World::with_key(key());
    build_tree(&seamed.source());
    let store = Store::open(&seamed.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let (manifest_root, stats) =
        granary_client::harvest(&seamed.source(), &store).unwrap_or_else(|e| panic!("{e}"));
    let via_seam = granary_client::prepare_from_manifest(
        &seamed.remote,
        &store,
        manifest_root,
        stats,
        &volume(),
        &wrapped.key,
        &identity(),
        stamp(1_760_000_000),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(via_seam.seq(), wrapper_seq, "the same seq is claimed");
    assert_eq!(
        via_seam.root_bytes, wrapper_root_bytes,
        "the wrapper and the seam must sign byte-identical roots"
    );

    // The whole SUMMARY, not just the signed bytes. No harvest stat
    // enters the root's preimage, so a wrapper that dropped or defaulted
    // the stats it passes through — or a seam that ignored the ones it
    // was handed — signs identical roots and is invisible above.
    let from_seam = granary_client::commit(&seamed.remote, via_seam)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let from_wrapper = granary_client::commit(&wrapped.remote, via_wrapper)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // Non-vacuous: the fixture makes every counter non-zero, so a
    // `HarvestStats::default()` on either side fails the comparisons
    // below rather than matching a zero it was compared against.
    assert!(
        harvest_shape(stats).iter().all(|n| *n > 0),
        "the fixture must make every harvest counter non-zero: {stats:?}"
    );
    assert_eq!(
        harvest_shape(from_seam.harvest),
        harvest_shape(stats),
        "the seam must carry the stats it was HANDED into its summary"
    );
    assert_eq!(
        summary_shape(&from_wrapper),
        summary_shape(&from_seam),
        "the wrapper and the seam must report the same publish, field for field"
    );
    assert_eq!(manifest_root, from_wrapper.manifest_root);
    drop(wrapped.mem);
    drop(seamed.mem);
}

/// The ambiguous-retry probe: when OUR OWN bytes already sit at the
/// target seq (a landed first attempt surfacing as `AlreadyExists`), the
/// publish is a SUCCESS, not a lost race — the read-after-write
/// self-identification probe is what establishes it.
#[tokio::test]
async fn own_landed_root_is_not_a_lost_race() {
    let w = World::new();
    build_tree(&w.source());
    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let prepared = granary_client::prepare(
        &w.remote,
        &store,
        &w.source(),
        &volume(),
        &w.key,
        &identity(),
        stamp(100),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    drop(store); // release the flock before the second open below
    // Simulate the landed first attempt.
    w.remote
        .put_root(
            volume().as_str(),
            prepared.seq(),
            prepared.root_bytes.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let summary = granary_client::commit(&w.remote, prepared)
        .await
        .unwrap_or_else(|e| panic!("self-identified retry must succeed: {e}"));
    assert!(
        summary.hint_written,
        "the hint is written on the self-identified path"
    );
    // And a DIFFERENT publisher's bytes at the seq is still a loud race:
    let store2 = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let p2 = granary_client::prepare(
        &w.remote,
        &store2,
        &w.source(),
        &volume(),
        &w.key,
        &identity(),
        stamp(200),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    w.remote
        .put_root(volume().as_str(), p2.seq(), b"not our bytes".to_vec())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let err = granary_client::commit(&w.remote, p2)
        .await
        .expect_err("foreign bytes at the seq is a lost race");
    assert!(matches!(err, PublishError::LostRace { .. }), "got {err:?}");
    drop(w.mem);
}

// ------------------------------------------- reserved-name admission

/// The registry is enforced at the CHOKE POINT, not at the CLI wrapper.
/// A library caller reaching `prepare_from_manifest` + `commit` directly
/// — the surface the simulator drives, and the one an out-of-crate
/// caller has — must be refused too, or the CLI gate reserves nothing.
#[tokio::test]
async fn a_reserved_volume_cannot_be_created_through_the_library_path() {
    let w = World::new();
    build_tree(&w.source());
    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let (manifest_root, stats) =
        granary_client::harvest(&w.source(), &store).unwrap_or_else(|e| panic!("{e}"));
    let err = granary_client::prepare_from_manifest(
        &w.remote,
        &store,
        manifest_root,
        stats,
        &reserved_volume(),
        &w.key,
        &identity(),
        stamp(100),
        Policy::default(),
    )
    .await
    .expect_err("the generic entry point must refuse a reserved volume");
    assert!(
        matches!(&err, PublishError::ReservedVolumeName { volume } if volume == "gran-reserved"),
        "got {err:?}"
    );
    // Refused BEFORE anything was claimed: the volume still does not
    // exist, so the refusal is a reservation and not a late error.
    assert_eq!(
        w.remote
            .max_seq("gran-reserved")
            .await
            .unwrap_or_else(|e| panic!("{e}")),
        None,
        "nothing may have been created"
    );
    // …and nothing was UPLOADED under its prefix either, which a
    // refusal placed after the upload steps would not give. The id
    // below is what this exact tree writes under `meta/{volume}/`,
    // learned by publishing it to a non-reserved volume in the same
    // bucket — so the absence asserted next is the absence of a key
    // that demonstrably does get written somewhere.
    drop(store); // release the flock
    let summary = w.publish_ok(200, Policy::default()).await;
    assert!(
        matches!(
            w.remote
                .get_meta("gran-reserved", &summary.binmap_index)
                .await,
            Err(RootStoreError::NotFound)
        ),
        "the refused publish must have written nothing under the reserved prefix"
    );
    w.remote
        .get_meta(volume().as_str(), &summary.binmap_index)
        .await
        .unwrap_or_else(|e| panic!("non-vacuity: this id IS written for a permitted volume: {e}"));
    drop(w.mem);
}

/// The same refusal through the CLI's own door, so both entry points are
/// covered by the one gate rather than by two that can drift.
#[tokio::test]
async fn a_reserved_volume_cannot_be_created_through_the_cli_wrapper() {
    let w = World::new();
    build_tree(&w.source());
    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let err = granary_client::publish(
        &w.remote,
        &store,
        &w.source(),
        &reserved_volume(),
        &w.key,
        &identity(),
        stamp(100),
        Policy::default(),
    )
    .await
    .expect_err("the CLI wrapper must refuse a reserved volume");
    assert!(
        matches!(&err, PublishError::ReservedVolumeName { volume } if volume == "gran-reserved"),
        "got {err:?}"
    );
    // What the operator READS has to match what happened. The remote is
    // clean and the local store is not, and the message says both — the
    // idiom `MissingObject` ("nothing uploaded") and `LostRace`
    // ("Nothing was committed") already set for residue.
    let msg = err.to_string();
    assert!(msg.contains("gran-reserved"), "names the volume: {msg}");
    assert!(
        msg.contains("Nothing was uploaded"),
        "states the remote residue: {msg}"
    );
    assert!(
        msg.contains("the local store may already hold this tree"),
        "does not let the operator read it as 'nothing happened': {msg}"
    );
    // The refusal is REMOTE-only, and the variant's doc says so: this
    // door harvests the whole source tree into the LOCAL store before
    // the gate is reached, so a refused publish leaves the local CAS
    // fully populated. Pinned by IDENTITY against the object set a
    // PERMITTED publish of the same tree produces — a bare "not empty"
    // would also pass on a store holding one stray object, and the
    // claim being made is that the whole harvest already ran.
    drop(store); // release the flock
    let after_refusal = store_object_ids(&w.store_dir());
    w.publish_ok(200, Policy::default()).await;
    assert_eq!(
        after_refusal,
        store_object_ids(&w.store_dir()),
        "the refused publish had already harvested the complete object set"
    );
    assert!(
        !after_refusal.is_empty(),
        "…and that set is not empty, or the equality above compares nothing"
    );
    drop(w.mem);
}

/// The registry reserves who may CREATE a reserved name, NOT who may
/// publish to one that exists — a reserved volume must stay mintable by
/// granary and extendable afterwards.
///
/// The head bytes seeded here are deliberately junk: the assertion is
/// that the publish gets PAST the reserved-name gate and then fails on
/// the head root, which a blanket refusal at the top of
/// `prepare_from_manifest` could not do.
#[tokio::test]
async fn an_existing_reserved_volume_is_not_refused_by_the_registry() {
    let w = World::new();
    build_tree(&w.source());
    w.remote
        .put_root("gran-reserved", 1, b"not a root".to_vec())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let (manifest_root, stats) =
        granary_client::harvest(&w.source(), &store).unwrap_or_else(|e| panic!("{e}"));
    let err = granary_client::prepare_from_manifest(
        &w.remote,
        &store,
        manifest_root,
        stats,
        &reserved_volume(),
        &w.key,
        &identity(),
        stamp(100),
        Policy::default(),
    )
    .await
    .expect_err("the seeded head does not decode, so this publish still fails");
    assert!(
        matches!(
            &err,
            PublishError::Decode {
                what: "head root",
                ..
            }
        ),
        "an EXISTING reserved volume must fail on its head, not on admission: got {err:?}"
    );
    drop(w.mem);
}

/// The claim run to its END rather than to the gate: a reserved volume
/// that exists is not merely "not refused at admission", it publishes a
/// real seq 2 that resolves. The test above stops at the gate and then
/// dies on junk head bytes, which cannot distinguish "extendable" from
/// "gets one step further before failing".
///
/// Seq 1 is minted the way granary itself would mint it — a REAL root,
/// re-signed for the reserved name (the bytes carry the volume, so a
/// verbatim copy would be a cross-volume replay), with the metadata
/// objects that root names copied into the reserved volume's own
/// prefix. Bins are volume-independent, so only `meta/` needs the copy;
/// if that copy were incomplete the publish below would fail with
/// `MissingMeta` instead of succeeding, so its completeness is asserted
/// by the outcome and not assumed.
#[tokio::test]
async fn an_existing_reserved_volume_extends_to_a_real_seq_2() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(100, Policy::default()).await;
    let v1 = w.view(1).await;
    let reserved = reserved_volume();

    for id in [v1.doc.binmap_index, v1.bin_table, v1.doc.sheaf_head]
        .into_iter()
        .chain(v1.shard_ids.iter().copied())
    {
        let bytes = w
            .remote
            .get_meta(volume().as_str(), &id)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        w.remote
            .put_meta(reserved.as_str(), &id, bytes)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let mut doc = v1.doc.clone();
    doc.volume = reserved.clone();
    doc.sigs.clear();
    let prefix = root::signing_prefix_of(&doc).unwrap_or_else(|e| panic!("{e}"));
    doc.sigs.push(root::RootSig {
        key_id: w.key.key_id(),
        sig: w.key.sign(&prefix),
    });
    let seed = root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
    let seed_id = GrainId::of(&seed);
    w.remote
        .put_root(reserved.as_str(), 1, seed)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // The SAME gated door that refuses creation, on the SAME name.
    let store = Store::open(&w.store_dir()).unwrap_or_else(|e| panic!("{e}"));
    let summary = granary_client::publish(
        &w.remote,
        &store,
        &w.source(),
        &reserved,
        &w.key,
        &identity(),
        stamp(300),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("a reserved volume that EXISTS must stay extendable: {e}"));
    assert_eq!(summary.seq, 2, "the publish landed at seq 2");

    // Read back through the REMOTE path, like every other assertion in
    // this file: the extension is a root that resolves, not a summary.
    let mut sink = |_id: GrainId, _bytes: &[u8]| Ok(());
    let view = granary_client::resolve_at(
        &w.remote,
        reserved.as_str(),
        2,
        None,
        ResolveTarget::WholeTree,
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("seq 2 of a reserved volume must resolve: {e}"));
    assert!(
        root::is_reserved_volume_name(&view.doc.volume),
        "the volume extended here must actually be a reserved name, or this proves nothing"
    );
    assert_eq!(view.doc.volume.as_str(), "gran-reserved");
    assert_eq!(view.doc.seq, 2);
    assert_eq!(view.doc.epoch, 2);
    assert_eq!(
        view.doc.parent,
        Some(seed_id),
        "seq 2 chains onto the seed root, so this is an EXTENSION and not a second seq 1"
    );
    assert_writer_uuid_derives_from_the_roots_own_fields(&view.doc);
    verify_signature(&view, &w.key);
    drop(w.mem);
}

/// The WRITE side of reserving `u64::MAX`: a head at `u64::MAX - 1` refuses with
/// `CounterOverflow` rather than publishing a root nobody can ever read.
///
/// **This is the half a read-side-only rule gets WRONG, and it is the
/// reason the rule has a write side at all.** With `max_seq` skipping
/// `u64::MAX`, a head of `u64::MAX - 1` stays valid — the read rule
/// REQUIRES it to — so `head.checked_add(1)` yields `Some(u64::MAX)`,
/// `commit` writes a root there and **the publish reports success**. The
/// read rule then hides that root from every reader, the next publish
/// selects `u64::MAX` again, gets `AlreadyExists`, and the one-probe finds
/// its own foreign bytes: `LostRace`, which the module doc calls
/// deliberately terminal. Forever. That is strictly worse than the status
/// quo, which at least never claims success.
///
/// The POSITIVE CONTROL is the middle of the test, and it is what stops
/// this from pinning "refuses near the top of the range": `u64::MAX - 2`
/// is an ordinary head, it publishes to `u64::MAX - 1`, and the root it
/// wrote is then VISIBLE AS THE HEAD — selected by `max_seq`, fetched,
/// decoded and signature-verified. Asserting only `Ok(())` there would
/// have pinned the silent-data-loss state green.
///
/// It deliberately does NOT assert that the result *resolves*, and the
/// body below says why: `check_chain` walks every seq from the head down
/// to 1 and refuses a hole, so no volume with a planted far head resolves
/// — whether or not `u64::MAX` is reserved. Reserving it governs head
/// SELECTION, which is what this asserts.
#[tokio::test]
async fn a_head_at_the_top_of_the_usable_range_refuses_rather_than_publishing_an_invisible_root() {
    let w = World::new();
    build_tree(&w.source());
    w.publish_ok(100, Policy::default()).await;
    let v1 = w.view(1).await;
    let vol = volume();

    // Plant a VALIDLY SIGNED head at u64::MAX - 2 — the overflow bites
    // only on a decodable root at the top of the range (opaque bytes die
    // at `decode_root` first), so only the volume's own key can reach it.
    let mut doc = v1.doc.clone();
    doc.seq = u64::MAX - 2;
    doc.epoch += 1;
    doc.parent = Some(GrainId::of(&v1.root_bytes));
    doc.sigs.clear();
    let prefix = root::signing_prefix_of(&doc).unwrap_or_else(|e| panic!("{e}"));
    doc.sigs.push(root::RootSig {
        key_id: w.key.key_id(),
        sig: w.key.sign(&prefix),
    });
    let bytes = root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
    w.remote
        .put_root(vol.as_str(), u64::MAX - 2, bytes)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        w.remote.max_seq(vol.as_str()).await,
        Ok(Some(u64::MAX - 2)),
        "the plant must really be the head, or nothing below proves anything"
    );

    // POSITIVE CONTROL: u64::MAX - 2 publishes to u64::MAX - 1...
    let summary = w
        .publish(200, Policy::default())
        .await
        .unwrap_or_else(|e| panic!("u64::MAX - 2 is an ordinary head and must publish: {e}"));
    assert_eq!(summary.seq, u64::MAX - 1, "the top of the USABLE range");

    // ...and the root it wrote is VISIBLE at the head — the exact thing a
    // read-side-only rule would have destroyed, since the skip that hides
    // u64::MAX must not hide u64::MAX - 1.
    //
    // Asserted through `max_seq` + `get_root` + decode + verify rather
    // than through `resolve_head`, and the reason is a property of the
    // CHAIN rather than of reserving u64::MAX: `resolve_at_verified` runs
    // `check_chain`, which walks every seq from the head down to 1 and
    // refuses a hole, so NO volume whose head was planted at a far seq can
    // resolve — whether or not u64::MAX is reserved. That reservation governs head
    // SELECTION, which is what this asserts. (The refusal below is the
    // other half of the same proof: it is `CounterOverflow` and not
    // `NoHead`/`MissingRoot`, which means `remote_state` fetched, decoded
    // and signature-verified the root at u64::MAX - 1 as the head before
    // it ever reached the increment.)
    assert_eq!(
        w.remote.max_seq(vol.as_str()).await,
        Ok(Some(u64::MAX - 1)),
        "the published root must be SELECTED as the head — one below the reserved value"
    );
    let head_bytes = w
        .remote
        .get_root(vol.as_str(), u64::MAX - 1)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the publish reported seq u64::MAX - 1 but wrote nothing"));
    let head_doc = root::decode_root(&head_bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(head_doc.seq, u64::MAX - 1);
    assert_eq!(head_doc.volume, vol);
    let prefix = root::signed_prefix(&head_bytes).unwrap_or_else(|e| panic!("{e}"));
    let sig = head_doc
        .sigs
        .first()
        .unwrap_or_else(|| panic!("the head carries a signature"));
    assert_eq!(sig.key_id, w.key.key_id());
    crypto::verify(w.key.public_key(), prefix, &sig.sig).unwrap_or_else(|e| panic!("{e}"));

    // THE ROW: the next publish must REFUSE, not succeed invisibly.
    let refused = w.publish(300, Policy::default()).await;
    assert!(
        matches!(
            refused,
            Err(PublishError::CounterOverflow { what: "root seq" })
        ),
        "a head at u64::MAX - 1 must refuse with CounterOverflow rather than write a root at \
         the reserved u64::MAX and report success, got {refused:?}"
    );
    // Nothing was written at the reserved seq — the refusal is before the
    // CAS, not a cleanup after it.
    assert_eq!(
        w.remote.get_root(vol.as_str(), u64::MAX).await,
        Ok(None),
        "the refusal must be BEFORE the write: no root may exist at the reserved seq"
    );
    assert_eq!(
        w.remote.max_seq(vol.as_str()).await,
        Ok(Some(u64::MAX - 1)),
        "and the head must be exactly where it was — a refused publish moves nothing"
    );
    drop(w.mem);
}

/// Excluding `u64::MAX` from head selection restores publishing:
/// a volume whose ONLY key is `u64::MAX` PUBLISHES.
///
/// Measured before that exclusion: `max_seq` answered
/// `Ok(Some(18446744073709551615))` and the publish died at the decode
/// wall — `decode head root: bad magic`. One unauthenticated `PUT root`
/// at the top of the range made a fresh volume permanently unusable, with
/// no recovery: create-only means the slot is never released, and there is
/// no higher seq. This is the capability that exclusion RESTORES, not merely
/// a denial it adds.
#[tokio::test]
async fn a_volume_squatted_at_the_reserved_seq_still_takes_its_first_publish() {
    let w = World::new();
    build_tree(&w.source());
    let vol = volume();

    // The squat: opaque bytes no key signed, at the reserved seq.
    w.remote
        .put_root(
            vol.as_str(),
            u64::MAX,
            b"squatted by an unauthenticated PUT".to_vec(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        w.remote.max_seq(vol.as_str()).await,
        Ok(None),
        "the squat must not present itself as a head"
    );

    let summary = w.publish_ok(100, Policy::default()).await;
    assert_eq!(
        summary.seq, 1,
        "the first publish to a squatted volume is seq 1"
    );
    let v1 = w.view(1).await;
    assert_eq!(v1.doc.seq, 1);
    assert_eq!(
        granary_client::resolve_head_collecting(&w.remote, vol.as_str(), &head_ctx())
            .await
            .unwrap_or_else(|e| panic!("{e}"))
            .0
            .doc
            .seq,
        1,
        "and it is the HEAD — the squatted key is skipped, not merely tolerated"
    );

    // The squatted bytes are still there, byte for byte: the exclusion is
    // at the head, not at the key, and this is the operator's only look at
    // what was planted.
    assert_eq!(
        w.remote.get_root(vol.as_str(), u64::MAX).await,
        Ok(Some(b"squatted by an unauthenticated PUT".to_vec()))
    );
    drop(w.mem);
}

// No row here tests a publish deadline: the per-call deadline lives
// entirely inside `HttpStore`, so an in-memory fake `RootStore` (this
// file's `World::remote`) never sees a deadline of any kind. A
// healthy publish succeeding is covered by every other row in this file
// that calls `World::publish`; a reserved volume name being refused is
// `a_reserved_volume_cannot_be_created_through_the_library_path`, above.

/// A file whose bytes ARE a
/// directory node's encoding shares that node's id, and a
/// publish walk that gated emission and expansion on one set
/// would record the id as a grain and then never expand the
/// node. The collision is asserted to have FORMED (three
/// objects in the local store, `z`'s id among them) before
/// anything is asserted about the publish — a fixture where it
/// did not form passes the publish half for the wrong reason.
#[tokio::test]
async fn a_file_that_encodes_a_later_directory_node_does_not_truncate_the_publish_set() {
    use granary_core::manifest::{
        DirEntry, EntryKind, FileGrains, GrainRef, Name, tree::build_dir,
    };
    let w = World::new();
    // 1. `z`'s one-entry leaf, built by the SAME encoder harvest will use.
    let leaf_bytes = b"z-leaf";
    let leaf_grain_id = GrainId::of(leaf_bytes);
    let z_entry = DirEntry {
        name: Name::new(b"leaf".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: EntryKind::File {
            exec: false,
            size: leaf_bytes.len() as u64,
            grains: FileGrains::Inline(vec![GrainRef {
                id: leaf_grain_id,
                unpacked_len: u32::try_from(leaf_bytes.len()).unwrap_or_else(|e| panic!("{e}")),
            }]),
        },
    };
    let built = build_dir(&[z_entry]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(built.nodes.len(), 1, "one entry is one leaf");
    let (z_id, z_bytes) = built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one node"));
    assert_eq!(built.root, z_id);
    // 2. `a` (lexically before `z`) IS `z`'s node; `z/leaf` is the real file.
    std::fs::write(w.source().join("a"), &z_bytes).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir(w.source().join("z")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(w.source().join("z/leaf"), leaf_bytes).unwrap_or_else(|e| panic!("{e}"));
    // 3. Publish. Assert the collision FORMED before asserting anything else.
    let summary = w.publish_ok(1_760_000_000, Policy::default()).await;
    let local = store_object_ids(&w.store_dir());
    assert!(
        local.contains(&z_id),
        "`a`'s own grain must land under the id `z` was built from"
    );
    assert!(local.contains(&leaf_grain_id));
    // THIS is the assertion that establishes the collision, and the one
    // above is not: content-addressed harvest stores `a`'s grain under
    // `GrainId::of(a's bytes)` = `z_id` whether or not the harvested `z`
    // DIRECTORY leaf hashes there too. Only the COUNT can tell those
    // apart — an unformed collision leaves `z`'s leaf as a fourth,
    // separate object.
    assert_eq!(
        local.len(),
        3,
        "root leaf, the shared id, the inner grain — THREE, not four: the \
         harvested `z` leaf hashes to `a`'s grain id rather than to one of \
         its own"
    );
    // 4. The publish set must hold all three, and the volume must resolve.
    assert_eq!(
        summary.novel_objects, 3,
        "2 would mean `z` was never expanded"
    );
    let (_view, objects) = w.view_with_objects(1).await;
    assert!(
        objects.contains_key(&leaf_grain_id),
        "the leaf's grain must be in the resolved volume's object map"
    );
}

/// The DIRECTORY-child shape: `z`'s single entry is a
/// directory `q` holding one file, and `a`'s bytes ARE `z`'s node.
/// A walk that never opens `z` leaves `q` out of the publish
/// set, and the resolve then fails `Tree { MissingObject { id: q } }` —
/// a walk that only re-validates inline grain refs fails this row.
#[tokio::test]
async fn a_file_that_encodes_a_directory_node_naming_a_subdirectory_does_not_truncate_the_publish_set()
 {
    use granary_core::manifest::{
        DirEntry, EntryKind, FileGrains, GrainRef, Name, tree::build_dir,
    };
    let w = World::new();
    let q_file = b"q-file";
    let q_grain = GrainId::of(q_file);
    let q_built = build_dir(&[DirEntry {
        name: Name::new(b"file".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: EntryKind::File {
            exec: false,
            size: q_file.len() as u64,
            grains: FileGrains::Inline(vec![GrainRef {
                id: q_grain,
                unpacked_len: u32::try_from(q_file.len()).unwrap_or_else(|e| panic!("{e}")),
            }]),
        },
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let q_id = q_built.root;
    let z_built = build_dir(&[DirEntry {
        name: Name::new(b"q".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: EntryKind::Dir { child: q_id },
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let (z_id, z_bytes) = z_built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one node"));
    std::fs::write(w.source().join("a"), &z_bytes).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(w.source().join("z/q")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(w.source().join("z/q/file"), q_file).unwrap_or_else(|e| panic!("{e}"));
    let summary = w.publish_ok(1_760_000_000, Policy::default()).await;
    let local = store_object_ids(&w.store_dir());
    assert!(
        local.contains(&z_id),
        "`a`'s own grain must land under the id `z` was built from"
    );
    assert!(local.contains(&q_id));
    assert!(local.contains(&q_grain));
    // As in the row above: the COUNT is what establishes the collision.
    assert_eq!(
        local.len(),
        4,
        "root leaf, the shared id, q, q's grain — FOUR, not five: the \
         harvested `z` leaf hashes to `a`'s grain id rather than to one of \
         its own"
    );
    // Not `view_with_objects`: no writer-uuid assertion, and a failure panics with `{e:?}`.
    let outcome = granary_client::resolve_at_collecting(&w.remote, volume().as_str(), 1).await;
    let (_view, objects) = match outcome {
        Ok(v) => v,
        Err(e) => panic!("resolve failed: {e:?}"),
    };
    assert!(objects.contains_key(&q_grain));
    assert_eq!(
        summary.novel_objects, 4,
        "2 would mean `z` was never expanded"
    );
}
