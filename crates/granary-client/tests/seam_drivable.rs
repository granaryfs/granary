// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The publish seam is drivable by a SECOND implementation — no
//! filesystem, no `object_store`, no `GranaryStore`.
//!
//! This is the property the simulator's whole shape rests on:
//! `prepare_from_manifest` is generic over `RootStore + BinStore`
//! and `GrainSource` precisely so a simulator can drive it against
//! fakes. Every other test in this crate drives it against the real
//! adapters, which monomorphises the generic function but proves
//! nothing about a second implementation — the bounds could quietly
//! grow a requirement only `GranaryStore` and `Store` satisfy, and
//! everything would stay green until the simulator was written.
//!
//! So the fakes here are deliberately minimal and deliberately dumb:
//! `BTreeMap`s behind a `Mutex`, with no knowledge of publish's flow. If
//! this file stops compiling, the seam has stopped being a seam.
//!
//! It doubles as the only coverage of [`PublishError::Source`], the arm
//! the pure local surface produces.

#![cfg(unix)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use granary_client::{
    AnchorError, Cache, CacheOrigin, HeadContext, HintUpdate, Policy, PublishError, ResolveError,
    ResolveOutcome, ResolveTarget, RootVerifier, commit, prepare_from_manifest, resolve_at,
    resolve_at_verified, resolve_head, resolve_head_verified,
};
use granary_core::binstore::BinStore;
use granary_core::clock::Clock;
use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::identity::WriterIdentity;
use granary_core::manifest::{self, EntryKind, validate_dir_tree};
use granary_core::rng::SeededRng;
use granary_core::root::{self, Timestamp, VolumeName};
use granary_core::rootstore::{
    HintRead, HintToken, RefusalKind, RootStore, RootStoreError, filter_above,
};
use granary_core::sheaf;
use granary_store::crypto::{self, SigningKey};
use tracing_subscriber::layer::SubscriberExt as _;

// ----------------------------------------------------------------- fakes

#[derive(Debug, Default)]
struct FakeRemote {
    roots: Mutex<BTreeMap<(String, u64), Vec<u8>>>,
    hints: Mutex<BTreeMap<String, (u64, u64)>>,
    bins: Mutex<BTreeMap<[u8; DIGEST_LEN], Vec<u8>>>,
    meta: Mutex<BTreeMap<(String, GrainId), Vec<u8>>>,
    /// Degraded mode: when set, every `RootStore`/`BinStore`
    /// method refuses with this error before touching any of the
    /// maps above — the "the server just went down" fault the
    /// degraded-read tests below drive. `None` (the `Default`)
    /// changes nothing for every OTHER test in this file.
    refuse: Mutex<Option<RootStoreError>>,
}

fn poisoned<T>(_: T) -> RootStoreError {
    RootStoreError::Backend("fake mutex poisoned".to_owned())
}

impl FakeRemote {
    /// Flip the seam to refusing every call with a
    /// TRANSPORT-DOWN error (`RootStoreError::Backend`) —
    /// the shape degraded mode's fallback is meant to catch.
    fn go_down(&self) {
        self.refuse_with(RootStoreError::Backend("the server is down".to_owned()));
    }

    /// Flip the seam to refusing every call with `err` specifically —
    /// what `a_non_transport_error_does_not_trigger_a_degraded_attempt`
    /// needs to plant a non-transport-down refusal.
    fn refuse_with(&self, err: RootStoreError) {
        *self
            .refuse
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(err);
    }

    /// The one gate every trait method below calls first.
    fn check_up(&self) -> Result<(), RootStoreError> {
        match &*self
            .refuse
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

/// The name→key boundary is a CONTRACT obligation on every
/// implementation, not the adapter's private business. A fake
/// that skips it accepts names production refuses.
fn checked(volume: &str) -> Result<(), RootStoreError> {
    VolumeName::new(volume.to_owned())
        .map(|_| ())
        .map_err(|e| RootStoreError::InvalidVolume {
            reason: e.to_string(),
        })
}

impl RootStore for FakeRemote {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        self.check_up()?;
        checked(volume)?;
        let mut roots = self.roots.lock().map_err(poisoned)?;
        match roots.entry((volume.to_owned(), seq)) {
            std::collections::btree_map::Entry::Occupied(_) => Err(RootStoreError::AlreadyExists),
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(bytes);
                Ok(())
            }
        }
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.check_up()?;
        checked(volume)?;
        Ok(self
            .roots
            .lock()
            .map_err(poisoned)?
            .get(&(volume.to_owned(), seq))
            .cloned())
    }

    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        self.check_up()?;
        checked(volume)?;
        let hints = self.hints.lock().map_err(poisoned)?;
        match hints.get(volume) {
            // Seq 0 names a root that cannot exist, so it is never a head.
            None | Some(&(0, _)) => Ok(HintRead::Missing),
            Some(&(seq, version)) => {
                let token = HintToken(version.to_string());
                if cached == Some(&token) {
                    Ok(HintRead::NotModified)
                } else {
                    Ok(HintRead::Current { seq, token })
                }
            }
        }
    }

    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        self.check_up()?;
        checked(volume)?;
        let mut hints = self.hints.lock().map_err(poisoned)?;
        let next = hints.get(volume).map_or(1, |&(_, v)| v + 1);
        hints.insert(volume.to_owned(), (seq, next));
        Ok(())
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        self.check_up()?;
        checked(volume)?;
        Ok(self
            .roots
            .lock()
            .map_err(poisoned)?
            .keys()
            .filter(|(v, _)| v == volume)
            .map(|(_, s)| *s)
            // Neither reserved end of the range is ever a head: seq 0
            // nor u64::MAX. A fifth
            // implementation of the contract, so it carries the contract.
            .filter(|&s| s != 0 && s != u64::MAX)
            .max())
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

impl FakeRemote {
    /// Drop the root at `seq`. The only way to build a TRUNCATED chain:
    /// [`RootStore`] has no delete, because nothing in production removes
    /// a root — the shape still has to be reachable from a test, since a
    /// bucket someone else can write is exactly where it comes from.
    fn remove_root(&self, volume: &str, seq: u64) {
        self.roots
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .remove(&(volume.to_owned(), seq));
    }
}

impl BinStore for FakeRemote {
    async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.check_up()?;
        let mut bins = self.bins.lock().map_err(poisoned)?;
        Ok(bins.insert(*digest, bytes).is_none())
    }

    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.check_up()?;
        checked(volume)?;
        let mut meta = self.meta.lock().map_err(poisoned)?;
        Ok(meta.insert((volume.to_owned(), *id), bytes).is_none())
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.check_up()?;
        checked(volume)?;
        self.meta
            .lock()
            .map_err(poisoned)?
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
        self.check_up()?;
        let end = offset
            .checked_add(u64::from(len))
            .ok_or(RootStoreError::RangeOverflow)?;
        let bins = self.bins.lock().map_err(poisoned)?;
        let bytes = bins.get(digest).ok_or(RootStoreError::NotFound)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= bytes.len() || len == 0 {
            return Err(RootStoreError::Backend("invalid range".to_owned()));
        }
        let stop = usize::try_from(end).unwrap_or(usize::MAX).min(bytes.len());
        Ok(bytes.get(start..stop).unwrap_or_default().to_vec())
    }
}

#[derive(Debug, Default)]
struct FakeSource {
    objects: Mutex<BTreeMap<GrainId, Vec<u8>>>,
}

impl FakeSource {
    fn put(&self, bytes: Vec<u8>) -> GrainId {
        let id = GrainId::of(&bytes);
        self.insert_raw(id, bytes);
        id
    }

    /// Store bytes under an id they do NOT hash to — the only way to
    /// reach [`GrainSourceError::Corrupt`] through a fake.
    fn insert_raw(&self, id: GrainId, bytes: Vec<u8>) {
        self.objects
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .insert(id, bytes);
    }
}

impl GrainSource for FakeSource {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| GrainSourceError::Backend("fake mutex poisoned".to_owned()))?;
        let bytes = objects.get(id).ok_or(GrainSourceError::Missing(*id))?;
        if GrainId::of(bytes) == *id {
            Ok(bytes.clone())
        } else {
            Err(GrainSourceError::Corrupt(*id))
        }
    }

    fn has(&self, id: &GrainId) -> bool {
        self.objects
            .lock()
            .is_ok_and(|objects| objects.contains_key(id))
    }
}

// ------------------------------------------------------------- fixtures

fn key() -> SigningKey {
    SigningKey::from_seed(&[7u8; 32]).unwrap_or_else(|e| panic!("{e}"))
}

fn identity() -> WriterIdentity {
    WriterIdentity::from_bytes(*b"seam-drivable-16")
}

fn now() -> Timestamp {
    Timestamp {
        secs: 1_760_000_000,
        nanos: 0,
    }
}

fn volume() -> VolumeName {
    VolumeName::new("seam-vol".to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

/// A pinned clock for every `HeadContext` this file builds — matches
/// `now()`'s own "a constant, not a clock read" reasoning: nothing here
/// exercises hint freshness itself (that is `head.rs`'s own test module's
/// job), so a fixed reading keeps every row deterministic.
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        now()
    }
}

/// A fresh discovery context for a single call — this file's tests are
/// about the resolve ORACLE, not about head discovery mechanics, so each
/// call gets an unseeded-but-deterministic (fixed-seed) context of its
/// own rather than sharing one across independent assertions.
fn head_ctx() -> HeadContext {
    HeadContext::new(Box::new(FixedClock), Box::new(SeededRng::new(1)))
}

/// A one-file manifest tree built entirely in memory: the grain, then a
/// directory leaf naming it. No harvest, no filesystem.
fn seed_tree(source: &FakeSource) -> GrainId {
    let body = b"a grain that never touched a disk".to_vec();
    let len = u32::try_from(body.len()).unwrap_or_else(|e| panic!("{e}"));
    let grain = source.put(body);
    let entries = vec![manifest::DirEntry {
        name: manifest::Name::new(b"f".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(len),
            grains: manifest::FileGrains::Inline(vec![manifest::GrainRef {
                id: grain,
                unpacked_len: len,
            }]),
        },
    }];
    let leaf = manifest::encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    source.put(leaf)
}

/// One honest publish through the fakes, resolved. The seq-1 volume
/// every chain fixture below extends.
async fn published_volume() -> (FakeRemote, ResolveOutcome) {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let manifest_root = seed_tree(&source);
    let prepared = prepare_from_manifest(
        &remote,
        &source,
        manifest_root,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    commit(&remote, prepared)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let view = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("a committed volume must resolve: {e}"));
    (remote, view)
}

/// A link of the chain as the store holds it: the root bytes exactly as
/// put, plus both decoded documents.
///
/// The next link is built from THIS, never from a re-resolution, because
/// half these fixtures are deliberately broken and resolving them is the
/// thing under test.
struct Link {
    root_bytes: Vec<u8>,
    doc: root::RootDoc,
    sheaf: sheaf::SheafDoc,
}

fn link(view: &ResolveOutcome) -> Link {
    Link {
        root_bytes: view.root_bytes.clone(),
        doc: view.doc.clone(),
        sheaf: view.sheaf.clone(),
    }
}

/// A link that has not been stored yet, so a test can break exactly one
/// field of it and nothing else.
struct Draft {
    doc: root::RootDoc,
    sheaf: sheaf::SheafDoc,
}

impl Draft {
    /// The next link after `prev`, chaining correctly on BOTH chains:
    /// the root's parent is the previous root's STORED BYTES, the
    /// sheaf's parent is the previous root's `sheaf_head`. Same tree,
    /// same binmap — a dedup-only republish, which is the cheapest
    /// honest link there is.
    ///
    /// The signature is left as the previous root's and is therefore
    /// wrong. The oracle does not check it and does not need to (module
    /// docs): these are structural fixtures, not authenticity ones.
    fn after(prev: &Link) -> Self {
        Self {
            doc: root::RootDoc {
                seq: prev.doc.seq + 1,
                parent: Some(GrainId::of(&prev.root_bytes)),
                epoch: prev.doc.epoch + 1,
                ..prev.doc.clone()
            },
            sheaf: sheaf::SheafDoc {
                parent: Some(prev.doc.sheaf_head),
                ..prev.sheaf.clone()
            },
        }
    }

    /// Encode and store: the sheaf first, then the root pointing at the
    /// id the stored sheaf bytes actually hash to. `put_root` is
    /// put-if-absent, so an occupied seq must be removed first.
    async fn store(self, remote: &FakeRemote) -> Link {
        self.store_signed_by(remote, None).await
    }

    /// [`Self::store`], with the root signed by `signer` over its own
    /// signing prefix once the sheaf head is settled. `None` keeps the
    /// previous root's (now wrong) signature slots.
    async fn store_signed_by(mut self, remote: &FakeRemote, signer: Option<&SigningKey>) -> Link {
        let sheaf_bytes = sheaf::encode_sheaf(&self.sheaf).unwrap_or_else(|e| panic!("{e}"));
        let sheaf_head = GrainId::of(&sheaf_bytes);
        remote
            .put_meta(volume().as_str(), &sheaf_head, sheaf_bytes)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        self.doc.sheaf_head = sheaf_head;
        if let Some(signer) = signer {
            let prefix = root::signing_prefix_of(&self.doc).unwrap_or_else(|e| panic!("{e}"));
            self.doc.sigs = vec![root::RootSig {
                key_id: signer.key_id(),
                sig: signer.sign(&prefix),
            }];
        }
        let root_bytes = root::encode_root(&self.doc).unwrap_or_else(|e| panic!("{e}"));
        remote
            .put_root(volume().as_str(), self.doc.seq, root_bytes.clone())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        Link {
            root_bytes,
            doc: self.doc,
            sheaf: self.sheaf,
        }
    }
}

/// A trust anchor for a key a test HOLDS, so every honest call site
/// spells the refusal path once here rather than fifteen times.
///
/// `RootVerifier::trusting` is fallible on purpose — the all-zero key is
/// refused (`AnchorError::ZeroKey`) — and a real key is never that
/// value, so this unwrap is the "cannot happen" arm rather than a
/// swallowed error.
fn anchor(public: &[u8; 32]) -> RootVerifier {
    RootVerifier::trusting(*public).unwrap_or_else(|e| panic!("a real key is an anchor: {e}"))
}

/// Sixty-four lowercase hex digits, so a pinned key id reads as the
/// value an operator would see.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0F] {
            out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('?'));
        }
    }
    out
}

// ---------------------------------------------------------------- tests

/// The load-bearing one: a publish end to end against fakes only.
#[tokio::test]
async fn the_seam_publishes_against_fakes_with_no_filesystem_and_no_object_store() {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let manifest_root = seed_tree(&source);

    let prepared = prepare_from_manifest(
        &remote,
        &source,
        manifest_root,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("prepare_from_manifest: {e}"));

    assert_eq!(prepared.seq(), 1, "a fresh volume starts at seq 1");
    let root_bytes = prepared.root_bytes.clone();

    let summary = commit(&remote, prepared)
        .await
        .unwrap_or_else(|e| panic!("commit: {e}"));
    assert_eq!(summary.seq, 1);

    // The root is readable back THROUGH THE TRAIT and decodes.
    let stored = remote
        .get_root(volume().as_str(), 1)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("no root at seq 1"));
    assert_eq!(stored, root_bytes, "committed bytes are the prepared bytes");
    let doc = root::decode_root(&stored).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(doc.manifest_root, manifest_root);
    assert!(doc.parent.is_none(), "seq 1 has no parent");
}

/// A republish through the same fakes: the chain links, which is the
/// property scenario 2 will lean on.
#[tokio::test]
async fn a_republish_against_fakes_advances_the_seq_and_links_the_chain() {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let manifest_root = seed_tree(&source);

    let mut first_root = Vec::new();
    for expected_seq in 1..=2u64 {
        let prepared = prepare_from_manifest(
            &remote,
            &source,
            manifest_root,
            granary_client::HarvestStats::default(),
            &volume(),
            &key(),
            &identity(),
            now(),
            Policy::default(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(prepared.seq(), expected_seq);
        if expected_seq == 1 {
            first_root = prepared.root_bytes.clone();
        }
        commit(&remote, prepared)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }

    let second = remote
        .get_root(volume().as_str(), 2)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("no root at seq 2"));
    let doc = root::decode_root(&second).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.parent,
        Some(GrainId::of(&first_root)),
        "the chain must link to the previous root's bytes"
    );
}

/// `PublishError::Source` is what the pure local surface produces, and
/// nothing else in the suite reaches it.
#[tokio::test]
async fn a_local_object_missing_from_the_seam_surfaces_as_source_missing() {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    // A manifest root nothing was ever stored under.
    let absent = GrainId::of(b"never stored");

    let err = prepare_from_manifest(
        &remote,
        &source,
        absent,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .expect_err("an absent manifest root cannot publish");
    assert!(
        matches!(err, PublishError::Source(GrainSourceError::Missing(id)) if id == absent),
        "expected Source(Missing), got {err:?}"
    );
}

#[tokio::test]
async fn a_corrupt_local_object_surfaces_as_source_corrupt() {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let manifest_root = seed_tree(&source);
    // Replace the root's bytes with something that does not hash to it.
    source.insert_raw(manifest_root, b"not what this id names".to_vec());

    let err = prepare_from_manifest(
        &remote,
        &source,
        manifest_root,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .expect_err("a corrupt manifest root cannot publish");
    assert!(
        matches!(err, PublishError::Source(GrainSourceError::Corrupt(id)) if id == manifest_root),
        "expected Source(Corrupt), got {err:?}"
    );
}

/// The resolve oracle runs over a SECOND implementation of the seams:
/// the same body that reads a real bucket resolves a volume that only
/// ever existed in `BTreeMap`s, all the way down to the grain bytes.
///
/// The depth is the point. An oracle that stopped at the metadata layer
/// — "the head decodes", or an object count — cannot see an object
/// uploaded in the wrong order, because the head still names ids that
/// still resolve. Only a full read-back through `get_bin_range` does.
#[tokio::test]
async fn the_oracle_resolves_a_publish_end_to_end_through_the_seam() {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let manifest_root = seed_tree(&source);

    let prepared = prepare_from_manifest(
        &remote,
        &source,
        manifest_root,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    commit(&remote, prepared)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let mut objects: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let mut sink = |id: GrainId, bytes: &[u8]| -> Result<(), String> {
        objects.insert(id, bytes.to_vec());
        Ok(())
    };
    let resolved = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut sink,
    )
    .await
    .unwrap_or_else(|e| panic!("a committed volume must resolve: {e}"));
    assert_eq!(resolved.seq, 1);
    assert_eq!(resolved.doc.manifest_root, manifest_root);
    assert_eq!(resolved.sheaf.manifest_root, manifest_root);
    // Every object came back through a range read, decompressed and
    // re-hashed — so the tree validates over REMOTE bytes only.
    let stats = validate_dir_tree(&manifest_root, &|id| objects.get(id).cloned())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 33);
    assert_eq!(
        objects.keys().copied().collect::<Vec<GrainId>>(),
        resolved.entries.keys().copied().collect::<Vec<GrainId>>(),
        "every binmap entry must have been fetched"
    );
}

/// "Resolves completely" has to mean the HEAD'S TREE resolves, not
/// merely that every object the binmap happens to list came back.
///
/// A head naming a manifest root the binmap does not map is a volume
/// that cannot be read at all — and it is exactly the shape an ordering
/// defect produces, because the root is written last and names objects
/// an earlier step was supposed to have uploaded. An oracle that only
/// fetched the binmap's own entries would call this volume resolved: the
/// entries all fetch, the count is right, the head decodes.
#[tokio::test]
async fn a_head_naming_an_unmapped_manifest_root_does_not_resolve() {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let manifest_root = seed_tree(&source);

    let prepared = prepare_from_manifest(
        &remote,
        &source,
        manifest_root,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    commit(&remote, prepared)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // Seq 2: the same binmap, and a commit record that AGREES with the
    // head about which tree was published — an ordering defect leaves
    // the root and its sheaf consistent, and only the objects missing.
    // Reusing seq 1's sheaf would instead plant a second, different
    // defect and let the oracle refuse this volume without ever walking
    // the tree. The signature is now wrong, which the oracle does not
    // check and does not need to — this is a structural claim, not an
    // authenticity one.
    let resolved = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let unmapped = GrainId::of(b"a manifest root the binmap never mapped");
    let mut sheaf = resolved.sheaf.clone();
    sheaf.manifest_root = unmapped;
    // A seq-2 sheaf chains to seq 1's. Cloning seq 1's record leaves it
    // parentless, which is a SECOND defect and not the one this test
    // names — a fixture broken two ways stops proving which break the
    // assertion caught.
    sheaf.parent = Some(resolved.doc.sheaf_head);
    let sheaf_bytes = sheaf::encode_sheaf(&sheaf).unwrap_or_else(|e| panic!("{e}"));
    let sheaf_head = GrainId::of(&sheaf_bytes);
    remote
        .put_meta(volume().as_str(), &sheaf_head, sheaf_bytes)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mut doc = resolved.doc.clone();
    doc.seq = 2;
    doc.parent = Some(GrainId::of(&resolved.root_bytes));
    doc.epoch = 2;
    doc.manifest_root = unmapped;
    doc.sheaf_head = sheaf_head;
    let bytes = root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
    remote
        .put_root(volume().as_str(), 2, bytes)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let err = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a head whose tree is not there must not resolve");
    assert!(
        matches!(err, ResolveError::Tree { .. }),
        "expected a tree failure, got {err:?}"
    );
}

/// A manifest may declare a length its grain does not have, and nothing
/// below the oracle catches it. The encoder checks a file's `size`
/// against the sum of its declared lengths; the tree walk checks
/// declared lengths against a grain list's own cumulative bookkeeping.
/// Both are agreements AMONG manifest nodes. Neither consults the bytes,
/// because the walk fetches manifest nodes and an inline grain reference
/// is a leaf it never opens.
///
/// The oracle is the one place holding both the declaration and the
/// object, so it is the one place the disagreement is visible. Left
/// unchecked, every content address verifies, every decode succeeds, and
/// the resolution reports a file whose bytes are not there — a reader
/// assembling it lands on offsets the grain does not have.
#[tokio::test]
async fn a_grain_shorter_than_the_manifest_declares_does_not_resolve() {
    let remote = FakeRemote::default();
    let source = FakeSource::default();

    // One byte of payload, declared as 8 MiB, with `size` set to match
    // the declaration — which is all the encoder compares it against.
    let declared = manifest::GRAIN_UNPACKED_MAX;
    let grain = source.put(b"x".to_vec());
    let entries = vec![manifest::DirEntry {
        name: manifest::Name::new(b"f".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(declared),
            grains: manifest::FileGrains::Inline(vec![manifest::GrainRef {
                id: grain,
                unpacked_len: declared,
            }]),
        },
    }];
    let leaf = manifest::encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    let manifest_root = source.put(leaf);

    // The honest publish path takes it: prepare and commit move grains
    // by id, and never compare a declared length to the bytes either.
    let prepared = prepare_from_manifest(
        &remote,
        &source,
        manifest_root,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    commit(&remote, prepared)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let err = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a grain shorter than its declaration must not resolve");
    assert!(
        matches!(
            err,
            ResolveError::GrainLenMismatch { id, node, want, got }
                if id == grain && node == manifest_root && want == declared && got == 1
        ),
        "expected a grain-length mismatch, got {err:?}"
    );
}

/// A signature says who wrote a document, never what it belongs to —
/// which is why the root's volume and seq are cross-checked against the
/// key it was fetched from. The commit record needs the same treatment
/// for the same reason.
///
/// This sheaf is impeccable: correctly encoded, stored under the id its
/// own bytes hash to, named by the root that was fetched. It describes a
/// different published tree. Content addressing cannot tell the two
/// apart — it proves a document is intact, never that it belongs to the
/// document naming it — so without the cross-check the oracle reports a
/// complete resolution whose commit record is for another volume state.
#[tokio::test]
async fn a_sheaf_describing_a_different_tree_does_not_resolve() {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let manifest_root = seed_tree(&source);

    let prepared = prepare_from_manifest(
        &remote,
        &source,
        manifest_root,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    commit(&remote, prepared)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let resolved = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));

    // A valid commit record for a tree this root does not name.
    let other_tree = GrainId::of(b"a tree this root never published");
    let mut sheaf = resolved.sheaf.clone();
    sheaf.manifest_root = other_tree;
    // A seq-2 sheaf chains to seq 1's. Cloning seq 1's record leaves it
    // parentless, which is a SECOND defect and not the one this test
    // names — a fixture broken two ways stops proving which break the
    // assertion caught.
    sheaf.parent = Some(resolved.doc.sheaf_head);
    let sheaf_bytes = sheaf::encode_sheaf(&sheaf).unwrap_or_else(|e| panic!("{e}"));
    let sheaf_head = GrainId::of(&sheaf_bytes);
    remote
        .put_meta(volume().as_str(), &sheaf_head, sheaf_bytes)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // Seq 2: the honest tree, the honest binmap, that commit record.
    let mut doc = resolved.doc.clone();
    doc.seq = 2;
    doc.parent = Some(GrainId::of(&resolved.root_bytes));
    doc.epoch = 2;
    doc.sheaf_head = sheaf_head;
    let bytes = root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
    remote
        .put_root(volume().as_str(), 2, bytes)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let err = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a sheaf describing another tree must not resolve");
    assert!(
        matches!(
            err,
            ResolveError::SheafTreeMismatch { root, sheaf }
                if root == manifest_root && sheaf == other_tree
        ),
        "expected a sheaf/root tree mismatch, got {err:?}"
    );
}

/// A volume with no head is an OUTCOME, not a panic — and it is the
/// common one under a crash sweep, where most crash points leave the
/// head unchanged. The helper this oracle replaces panicked here, which
/// is why it could not express "resolves completely or has no head" at
/// all.
#[tokio::test]
async fn a_volume_with_no_head_resolves_to_no_head_rather_than_panicking() {
    let remote = FakeRemote::default();
    assert!(
        matches!(
            resolve_head(
                &remote,
                volume().as_str(),
                &head_ctx(),
                None,
                ResolveTarget::WholeTree,
                &mut |_, _| Ok(())
            )
            .await,
            Err(ResolveError::NoHead)
        ),
        "an unpublished volume must resolve to NoHead"
    );
    assert!(
        matches!(
            resolve_at(
                &remote,
                volume().as_str(),
                7,
                None,
                ResolveTarget::WholeTree,
                &mut |_, _| Ok(())
            )
            .await,
            Err(ResolveError::NoHead)
        ),
        "an absent seq must resolve to NoHead"
    );
}

/// A root's `parent` is a CLAIM about ancestry, and an intact root
/// makes it just as convincingly as a forged one — the id is inside the
/// signed prefix, so it is well-formed either way, and every other check
/// the oracle runs is confined to a single seq. Nothing but a comparison
/// against the root actually stored below can tell the two apart.
///
/// Left unchecked, a volume whose history is a fabrication
/// resolves `Ok`, which is what "resolves completely" would then
/// mean to a grain server ingesting a chain it did not write.
#[tokio::test]
async fn a_root_naming_a_fabricated_parent_does_not_resolve() {
    let (remote, view1) = published_volume().await;

    let mut draft = Draft::after(&link(&view1));
    draft.doc.parent = Some(GrainId::of(b"a root this volume never published"));
    draft.store(&remote).await;

    let err = resolve_at(
        &remote,
        volume().as_str(),
        2,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a root naming a parent that is not there must not resolve");
    assert!(
        matches!(
            err,
            ResolveError::ParentMismatch { seq: 2, expected, .. }
                if expected == GrainId::of(&view1.root_bytes)
        ),
        "expected a parent mismatch naming seq 1's root, got {err:?}"
    );
}

/// The commit chain forking underneath an intact ROOT chain. Every root
/// links correctly, every object is present and hashes, and the sheaf at
/// seq 2 descends from a commit record this volume never published — so
/// the history the sheaf chain tells and the history the roots tell are
/// different histories.
///
/// The root-parent check above cannot see it: it never opens the sheaf.
/// The within-seq `SheafTreeMismatch` cannot either: this sheaf names
/// the right tree.
#[tokio::test]
async fn a_sheaf_chain_fork_does_not_resolve() {
    let (remote, view1) = published_volume().await;

    let mut draft = Draft::after(&link(&view1));
    draft.sheaf.parent = Some(GrainId::of(b"a commit record on another chain"));
    draft.store(&remote).await;

    let err = resolve_at(
        &remote,
        volume().as_str(),
        2,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a sheaf descending from another chain must not resolve");
    assert!(
        matches!(
            err,
            ResolveError::SheafChainMismatch { seq: 2, expected, .. }
                if expected == Some(view1.doc.sheaf_head)
        ),
        "expected a sheaf-chain mismatch against seq 1's sheaf head, got {err:?}"
    );
}

/// A truncated chain is a BROKEN volume and must never classify as an
/// empty one. The distinction is the whole reason `ChainBroken` exists
/// as its own variant: a sweep asserts "resolves completely **or** has
/// no head", so a missing ancestor reported as `NoHead` would be read as
/// the legitimate unpublished state and PASS that property — with two
/// published seqs sitting in the bucket.
#[tokio::test]
async fn a_missing_ancestor_is_chain_broken_and_never_no_head() {
    let (remote, view1) = published_volume().await;
    let l2 = Draft::after(&link(&view1)).store(&remote).await;
    Draft::after(&l2).store(&remote).await;

    remote.remove_root(volume().as_str(), 1);

    let err = resolve_at(
        &remote,
        volume().as_str(),
        3,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a chain missing an ancestor must not resolve");
    assert!(
        matches!(err, ResolveError::ChainBroken { seq: 1 }),
        "expected the absent ancestor to be named, got {err:?}"
    );
    assert!(
        !matches!(err, ResolveError::NoHead),
        "a truncated chain is broken, not headless: {err:?}"
    );
}

/// What makes "full walk" a claim rather than a hope. The chain is three
/// links long and the break is in the OLDEST one — a walk that checked
/// only the newest link, or only the link below the head, passes this
/// test's setup and reports a volume whose earliest commit descends from
/// nothing this volume published.
///
/// Everything above the break chains correctly, so the error's `seq` is
/// also the assertion that the walk got all the way down before it
/// stopped.
#[tokio::test]
async fn the_chain_walk_reaches_the_oldest_link() {
    let (remote, view1) = published_volume().await;
    let mut broken = Draft::after(&link(&view1));
    broken.sheaf.parent = Some(GrainId::of(b"a commit record on another chain"));
    let l2 = broken.store(&remote).await;
    Draft::after(&l2).store(&remote).await;

    let err = resolve_at(
        &remote,
        volume().as_str(),
        3,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a break at the oldest link must not resolve");
    assert!(
        matches!(
            err,
            ResolveError::SheafChainMismatch { seq: 2, expected, .. }
                if expected == Some(view1.doc.sheaf_head)
        ),
        "expected the walk to reach seq 2's link, got {err:?}"
    );
}

/// The base of the chain. A first commit is parentless by definition
/// (`SheafDoc::parent` — "`None` only for a volume's first commit"), and
/// nothing below the oracle enforces it: the sheaf format accepts a
/// parent at any position, and the ROOT decoder's parent/seq cross-rule
/// covers only the root's own parent, never the sheaf's.
///
/// Without this check the walk terminates one link early on every
/// volume, and a chain whose seq-1 commit claims a predecessor —
/// history spliced onto a volume that has none — resolves `Ok`.
#[tokio::test]
async fn a_first_commit_sheaf_must_be_parentless() {
    let (remote, view1) = published_volume().await;

    let draft = Draft {
        doc: view1.doc.clone(),
        sheaf: sheaf::SheafDoc {
            parent: Some(GrainId::of(b"a commit before the first commit")),
            ..view1.sheaf.clone()
        },
    };
    // Replace, rather than extend: `put_root` is put-if-absent.
    remote.remove_root(volume().as_str(), 1);
    draft.store(&remote).await;

    let err = resolve_at(
        &remote,
        volume().as_str(),
        1,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a first commit claiming a predecessor must not resolve");
    assert!(
        matches!(
            err,
            ResolveError::SheafChainMismatch {
                seq: 1,
                expected: None,
                ..
            }
        ),
        "expected seq 1's sheaf to be required parentless, got {err:?}"
    );
}

/// The positive control the four tests above are worthless without: a
/// chain that is correct at every link resolves at EVERY seq, including
/// the head whose walk covers all three links.
///
/// A walk that refused something legitimate would leave every one of
/// them passing — they only ever assert that a resolution failed.
#[tokio::test]
async fn a_correct_three_link_chain_resolves_at_every_seq() {
    let (remote, view1) = published_volume().await;
    let l2 = Draft::after(&link(&view1)).store(&remote).await;
    Draft::after(&l2).store(&remote).await;

    for seq in 1..=3u64 {
        let view = resolve_at(
            &remote,
            volume().as_str(),
            seq,
            None,
            ResolveTarget::WholeTree,
            &mut |_, _| Ok(()),
        )
        .await
        .unwrap_or_else(|e| panic!("a correctly chained volume must resolve at seq {seq}: {e}"));
        assert_eq!(view.seq, seq);
    }
}

/// A head-only reader's behaviour, pinned: the signers of a head's
/// ancestors are never checked, and the signer of a root that is itself the
/// head of a resolve always is. Seq 1 is signed only by K1, seq 2 only by
/// K2 and seq 3 by K3. A reader trusting K3 alone resolves seq 3, by seq and
/// by head discovery, walking the chain through the K1 and K2 roots, because
/// the head's signature covers the parent id and the walk binds each
/// ancestor by content. The same reader resolving seq 1 or seq 2 as the head
/// refuses each with `UnknownSigner`, since the signature is checked on
/// whichever root is the head. Trusting K1 or K2 alone refuses seq 3 the
/// same way, so the pass is not an unverified read in disguise.
#[tokio::test]
async fn a_head_only_reader_ignores_the_signers_of_ancestors() {
    let (k1, k2, k3) = (
        key(),
        SigningKey::from_seed(&[8_u8; 32]),
        SigningKey::from_seed(&[9_u8; 32]),
    );
    let (k2, k3) = (
        k2.unwrap_or_else(|e| panic!("{e}")),
        k3.unwrap_or_else(|e| panic!("{e}")),
    );
    // `published_volume` signs seq 1 with `key()`, which is K1.
    let (remote, view1) = published_volume().await;
    let l2 = Draft::after(&link(&view1))
        .store_signed_by(&remote, Some(&k2))
        .await;
    Draft::after(&l2).store_signed_by(&remote, Some(&k3)).await;

    let reader = anchor(k3.public_key());
    let by_seq = resolve_at_verified(
        &remote,
        volume().as_str(),
        3,
        &reader,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("a head signed by the trusted key must resolve: {e}"));
    assert_eq!(by_seq.seq, 3);
    let by_head = resolve_head_verified(
        &remote,
        volume().as_str(),
        &reader,
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("head discovery must resolve the same chain: {e}"));
    assert_eq!(by_head.seq, 3);

    for ancestor_seq in [1_u64, 2] {
        let err = resolve_at_verified(
            &remote,
            volume().as_str(),
            ancestor_seq,
            &reader,
            None,
            ResolveTarget::WholeTree,
            &mut |_, _| Ok(()),
        )
        .await
        .expect_err(
            "an ancestor is refused when it is itself the head and its signer is untrusted",
        );
        assert!(
            matches!(err, ResolveError::UnknownSigner { seq } if seq == ancestor_seq),
            "the K3-only reader resolving seq {ancestor_seq} as the head: expected \
             UnknownSigner, got {err:?}"
        );
    }

    for (name, untrusted) in [("K1", &k1), ("K2", &k2)] {
        let err = resolve_at_verified(
            &remote,
            volume().as_str(),
            3,
            &anchor(untrusted.public_key()),
            None,
            ResolveTarget::WholeTree,
            &mut |_, _| Ok(()),
        )
        .await
        .expect_err("a head signed by nobody the reader trusts must not resolve");
        assert!(
            matches!(err, ResolveError::UnknownSigner { seq: 3 }),
            "trusting {name} alone: expected the head's signer to be refused, got {err:?}"
        );
    }
}

// ------------------------------------------------------------- scratch dir

/// Test-only scratch dir for `Cache::open`'s disk-backed structures:
/// unique per test, removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    #[expect(
        clippy::disallowed_methods,
        reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
    )]
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "granary-seam-drivable-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cache_origin() -> CacheOrigin {
    CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x22; 32],
        root_key_id: None,
    }
}

fn fresh_cache(dir: &ScratchDir) -> Cache {
    Cache::open(&dir.0, 1024 * 1024 * 1024, &cache_origin()).unwrap_or_else(|e| panic!("{e}"))
}

/// Both `cache.put_root_bytes` call sites — the head's, at
/// `resolve_at_verified`'s own tail once the whole resolve verifies, and
/// the ancestor's, inside `check_chain`'s loop over every seq below the
/// head — must independently fire. A seq-2 chain resolved once with a
/// cache present leaves BOTH seqs readable straight back out of the
/// cache, with no further wire call: `Cache::get_root_bytes` is a plain,
/// synchronous, disk-backed lookup, never a network read, so reading it
/// twice here proves the write happened rather than proving anything
/// about a second resolve.
///
/// Two independent assertions, one per write site, so dropping EITHER
/// call (two distinct mutants) is caught: dropping the head's write
/// leaves seq 2 absent while seq 1 (written by `check_chain`) still
/// shows; dropping the ancestor's write leaves seq 1 absent while seq 2
/// (written by the caller) still shows.
#[tokio::test]
async fn a_cached_chain_serves_head_and_ancestor_roots() {
    let (remote, view1) = published_volume().await;
    let l2 = Draft::after(&link(&view1)).store(&remote).await;

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);

    resolve_at(
        &remote,
        volume().as_str(),
        2,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("a correctly chained volume must resolve: {e}"));

    assert_eq!(
        cache.get_root_bytes(&volume(), 2),
        Some(l2.root_bytes.clone()),
        "the HEAD's root bytes must be written to the cache once the whole \
         resolve verifies"
    );
    assert_eq!(
        cache.get_root_bytes(&volume(), 1),
        Some(view1.root_bytes.clone()),
        "the ANCESTOR's root bytes must be written to the cache by \
         check_chain's own walk, independently of the head's write"
    );
}

/// `check_chain` runs LAST among the validation checks and BEFORE
/// emission (`resolve.rs`'s module doc, `resolve_at_verified`'s own
/// comment at the call site) — the one step that reaches an external
/// consumer must never run before the whole history, ancestor chain
/// included, has verified. A counting sink over the SAME missing-
/// ancestor fixture `a_missing_ancestor_is_chain_broken_and_never_no_head`
/// uses proves it: zero bytes may reach the sink before `ChainBroken`
/// surfaces, whether tree-structure bytes (a `WholeTree` target also
/// emits every structure node) or content grains.
#[tokio::test]
async fn a_broken_ancestor_emits_nothing() {
    let (remote, view1) = published_volume().await;
    let l2 = Draft::after(&link(&view1)).store(&remote).await;
    Draft::after(&l2).store(&remote).await;

    remote.remove_root(volume().as_str(), 1);

    let mut sink_bytes: usize = 0;
    let err = resolve_at(
        &remote,
        volume().as_str(),
        3,
        None,
        ResolveTarget::WholeTree,
        &mut |_, bytes| {
            sink_bytes += bytes.len();
            Ok(())
        },
    )
    .await
    .expect_err("a chain missing an ancestor must not resolve");
    assert!(
        matches!(err, ResolveError::ChainBroken { seq: 1 }),
        "expected the absent ancestor to be named, got {err:?}"
    );
    assert_eq!(
        sink_bytes, 0,
        "no bytes — structure or content — may reach the sink before the \
         ancestor chain is verified"
    );
}

/// What a reader with a configured root key does, and what it
/// does NOT do.
///
/// **Four states, and the middle two are the ones a rejection-only suite
/// cannot separate.** A root signed by the configured key resolves; a
/// root signed by SOMEBODY ELSE is `UnknownSigner` — the slot is not
/// there to check, which is a different fact from a check that failed;
/// the configured key's own slot with one byte of signature flipped is
/// `BadSignature`; and the unverified anchor reads the very same
/// mutated volume without complaint, which is what proves the refusals
/// above came from the verifier rather than from the oracle's own
/// structural checks.
///
/// **The anchor is CONSTRUCTED, not chosen per call.** `resolve_at` is
/// the `unverified()` wrapper and nothing else, so there is no call
/// shape that skips a configured verifier — the last assertion here
/// names that wrapper explicitly so a future overload cannot quietly
/// make the anchor an argument again.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one signer/anchor fixture checked through five distinct resolve calls in turn \
              (trusted, stranger, flipped signature, unverified, plain) — splitting the arms \
              loses the shared fixture each one is checked against, and the sink/target \
              params padded every call by three lines"
)]
async fn resolve_at_verified_accepts_the_configured_signer_and_rejects_a_stranger() {
    let (remote, view1) = published_volume().await;
    let trusted = anchor(key().public_key());
    assert!(
        trusted.is_verifying(),
        "a configured anchor must actually check something"
    );

    let view = resolve_at_verified(
        &remote,
        volume().as_str(),
        1,
        &trusted,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the volume's own signer must verify: {e}"));
    assert_eq!(view.seq, 1);
    let head = resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the head path must verify the same way: {e}"));
    assert_eq!(head.seq, 1);

    let stranger = SigningKey::from_seed(&[9_u8; 32]).unwrap_or_else(|e| panic!("{e}"));
    let stranger_anchor = anchor(stranger.public_key());
    let err = resolve_at_verified(
        &remote,
        volume().as_str(),
        1,
        &stranger_anchor,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a root no configured key signed must not resolve");
    assert!(
        matches!(err, ResolveError::UnknownSigner { seq: 1 }),
        "expected the absent slot to be named, got {err:?}"
    );

    // The configured key's OWN slot, one signature byte flipped: the
    // key_id still matches, so this reaches the crypto call the row
    // above never gets to.
    let mut mutated = view1.root_bytes.clone();
    if let Some(byte) = mutated.last_mut() {
        *byte ^= 0x01;
    }
    assert_ne!(mutated, view1.root_bytes, "the flip must change the bytes");
    remote.remove_root(volume().as_str(), 1);
    remote
        .put_root(volume().as_str(), 1, mutated)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let err = resolve_at_verified(
        &remote,
        volume().as_str(),
        1,
        &trusted,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a flipped signature must not resolve");
    assert!(
        matches!(err, ResolveError::BadSignature { seq: 1 }),
        "expected the failed check to be named, got {err:?}"
    );

    // The SAME store, read with no anchor: still a structurally whole
    // volume. Without this the two refusals above would be consistent
    // with an oracle that simply stopped resolving this store at all.
    let unverified = resolve_at_verified(
        &remote,
        volume().as_str(),
        1,
        &RootVerifier::unverified(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the unverified anchor reads the same volume: {e}"));
    assert_eq!(unverified.seq, 1);
    let plain = resolve_at(
        &remote,
        volume().as_str(),
        1,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("`resolve_at` is the unverified wrapper: {e}"));
    assert_eq!(plain.seq, 1);
    let plain_head = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("`resolve_head` is the unverified wrapper: {e}"));
    assert_eq!(plain_head.seq, 1);
}

/// **The all-zero public key is a FAIL-OPEN SENTINEL, and this
/// row is the forgery a zeroed anchor admits.**
///
/// `granary_net::pin::PinnedServerVerifier::new` refuses the all-zero
/// DIGEST for a stated reason — it "is exactly what an unset, zeroed
/// configuration field looks like — so accepting it is how a fail-open
/// default reaches production". The signing-key counterpart to the TLS pin
/// shipped without the mirror, and here the consequence is sharper than
/// a dead anchor.
///
/// **A zeroed key does not refuse everything; it accepts forgeries.**
/// The all-zero encoding decodes `y = 0`, so `x² = -1`, which has a
/// root in `F_p` — a VALID curve point, of ORDER 4. Under RFC 8032's
/// non-cofactored verification `[S]B = R + [h]A`, an all-zero signature
/// reads `identity = R + [h]A` with both terms inside that order-4
/// subgroup, which holds for roughly one message in four. The forged
/// root below carries ONE slot: the publicly computable `key_id`
/// `SHA256(32 zero bytes)`, and sixty-four zero bytes as the signature.
/// No private key exists for it, and none was used to build it.
///
/// **The fixture is a MEASURED forgery, not a hoped-for one.** One root
/// in four is not all of them, so a fixture landing in the other three
/// quarters would assert nothing while still looking like this test —
/// which is why the `crypto::verify` line below is an ASSERTION and not
/// a comment. It fails loudly if a change to the published fixture
/// moves the signed prefix off an accepting one, rather than leaving
/// this row quietly proving nothing.
///
/// **Measured before the guard existed**, on this exact fixture:
/// `resolve_at_verified` under `trusting([0u8; 32])` returned
/// `Ok(seq 1)` — a volume resolved completely off a root nobody signed.
/// The guard is what makes that anchor unconstructible.
#[tokio::test]
async fn the_all_zero_root_key_is_refused_and_the_forgery_it_admits_is_real() {
    let (remote, view1) = published_volume().await;
    let zero_key = [0_u8; 32];

    // The slot a forger writes. `key_id` here is public arithmetic over
    // public bytes — pinned as a literal so this row states the value an
    // operator's zeroed field files itself under, rather than deriving
    // both sides of the comparison from one call.
    let forged_key_id = crypto::key_id(&zero_key);
    assert_eq!(
        hex32(&forged_key_id),
        "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        "SHA-256 of thirty-two zero bytes is a public constant; addressing \
         the slot costs a forger nothing"
    );
    let forged = root::encode_root(&root::RootDoc {
        sigs: vec![root::RootSig {
            key_id: forged_key_id,
            sig: [0_u8; 64],
        }],
        ..view1.doc.clone()
    })
    .unwrap_or_else(|e| panic!("{e}"));

    // THE EVIDENCE. Not "a zero signature might verify" — this one does,
    // over these exact bytes, at the crypto layer, with the all-zero
    // public key. Everything below is only meaningful because of it.
    let prefix = root::signed_prefix(&forged).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        crypto::verify(&zero_key, prefix, &[0_u8; 64]),
        Ok(()),
        "this fixture is supposed to BE a working forgery; if the zero \
         signature no longer verifies over it, the prefix moved into the \
         three-quarters where it would not have and this row proves nothing"
    );

    // The forged root REPLACES the honest one. The unverified anchor
    // still resolves the volume completely, so every refusal below is
    // the anchor's doing rather than a store this test broke.
    remote.remove_root(volume().as_str(), 1);
    remote
        .put_root(volume().as_str(), 1, forged)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let carried = resolve_at(
        &remote,
        volume().as_str(),
        1,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the forged root is structurally whole: {e}"));
    assert_eq!(carried.seq, 1);

    // THE GUARD. The only anchor whose `key_id` matches that slot cannot
    // be built, so no call shape reaches `resolve_at_verified` with it.
    assert!(
        matches!(RootVerifier::trusting(zero_key), Err(AnchorError::ZeroKey)),
        "a zeroed configuration field must not become a trust anchor"
    );

    // And the honest anchor names the forged slot for what it is.
    let err = resolve_at_verified(
        &remote,
        volume().as_str(),
        1,
        &anchor(key().public_key()),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a root the configured key did not sign must not resolve");
    assert!(
        matches!(err, ResolveError::UnknownSigner { seq: 1 }),
        "expected the absent slot to be named, got {err:?}"
    );
}

/// **The READER's slot match compares all thirty-two `key_id` bytes.**
///
/// `granary_core::root` carries the ENCODER-side sibling —
/// `encoder_accepts_key_ids_sharing_every_byte_but_the_last`, whose note
/// records that narrowing that scan to `key_id[0]` left 231/231 green
/// until the test existed. The reader half is the key-id lookup inside
/// `granary_store::crypto::check_head` (`TrustedKeys`'s slot match); this
/// row drives it through the reader, so narrowing that compare to
/// `key_id[0]` turns it red.
///
/// **It matters because `key_id` is NOT signed.** `signed_prefix` stops
/// before the signature section, so the slot's `key_id` is attacker- or
/// corruption-writable on a root whose signature is otherwise perfect,
/// and a narrowed compare is wrong in both directions:
///
/// - **DENIAL.** A garbage first slot the narrowed compare matches is
///   the slot that gets verified, and it does not verify, so a correctly
///   signed root reads as `BadSignature`.
/// - **ACCEPTANCE.** Rewriting a signed root's slot `key_id` leaves the
///   signature verifying under the configured key, so a narrowed reader
///   accepts a slot addressed to a key it does not hold — which the full
///   compare refuses as `UnknownSigner`.
///
/// **EVERY BYTE POSITION, not a favourite one.** A row that only flipped
/// the last byte would pass a compare that read `key_id[31]` alone, and
/// one that only flipped the first would pass a compare that read
/// `key_id[0]` — the hole is not closed by picking a different single
/// byte, it is closed by covering all of them. Each iteration below
/// differs from the anchor's `key_id` in EXACTLY ONE position, so any
/// compare that omits position `i` matches the decoy at `i` and goes
/// red. That makes this exhaustive against every proper subset of the
/// thirty-two bytes, which is the whole accept set a narrowing can
/// choose from. Sixty-four resolutions, tens of milliseconds.
#[tokio::test]
async fn the_reader_matches_every_byte_of_a_key_id() {
    let (remote, view1) = published_volume().await;
    let trusted = anchor(key().public_key());
    let honest = *view1
        .doc
        .sigs
        .first()
        .unwrap_or_else(|| panic!("a published root carries its signer's slot"));
    assert_eq!(
        honest.key_id,
        key().key_id(),
        "the fixture's slot must be the configured key's, or neither arm \
         below is about the compare"
    );

    for at in 0..honest.key_id.len() {
        // ARM 1 — DENIAL. A decoy differing at exactly `at`, placed
        // FIRST so a compare omitting `at` returns it from `find`,
        // carrying a signature that does not verify. The anchor's own
        // slot follows, untouched.
        let mut decoy = honest;
        decoy.key_id[at] ^= 0x01;
        decoy.sig[0] ^= 0x01;
        assert_eq!(
            decoy
                .key_id
                .iter()
                .zip(honest.key_id.iter())
                .filter(|(d, h)| d != h)
                .count(),
            1,
            "the decoy must differ in exactly one position, not {at} and others"
        );
        let two_slots = root::encode_root(&root::RootDoc {
            sigs: vec![decoy, honest],
            ..view1.doc.clone()
        })
        .unwrap_or_else(|e| panic!("{e}"));
        remote.remove_root(volume().as_str(), 1);
        remote
            .put_root(volume().as_str(), 1, two_slots)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let view = resolve_at_verified(
            &remote,
            volume().as_str(),
            1,
            &trusted,
            None,
            ResolveTarget::WholeTree,
            &mut |_, _| Ok(()),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "byte {at}: the configured key's own slot is in this root; a \
                     compare that skipped byte {at} would have taken the decoy \
                     instead: {e}"
            )
        });
        assert_eq!(view.seq, 1);

        // ARM 2 — ACCEPTANCE. One slot, the REAL signature, and a
        // `key_id` rewritten at exactly `at`. `key_id` is outside the
        // signed prefix, so the signature still verifies — the only
        // thing between this root and a reader is the compare.
        let mut relabelled = honest;
        relabelled.key_id[at] ^= 0x01;
        let mislabelled = root::encode_root(&root::RootDoc {
            sigs: vec![relabelled],
            ..view1.doc.clone()
        })
        .unwrap_or_else(|e| panic!("{e}"));
        let prefix = root::signed_prefix(&mislabelled).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            crypto::verify(key().public_key(), prefix, &relabelled.sig),
            Ok(()),
            "byte {at}: the rewrite must leave the signature VALID, or this \
             arm is the BadSignature row rather than the compare's"
        );
        remote.remove_root(volume().as_str(), 1);
        remote
            .put_root(volume().as_str(), 1, mislabelled)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let err = match resolve_at_verified(
            &remote,
            volume().as_str(),
            1,
            &trusted,
            None,
            ResolveTarget::WholeTree,
            &mut |_, _| Ok(()),
        )
        .await
        {
            Ok(view) => panic!(
                "byte {at}: a slot addressed to a key_id this reader does not \
                 hold resolved anyway, at seq {}",
                view.seq
            ),
            Err(err) => err,
        };
        assert!(
            matches!(err, ResolveError::UnknownSigner { seq: 1 }),
            "byte {at}: expected the slot to be unmatched, got {err:?}"
        );
    }
}

/// **Authenticating the whole chain rests on `parent` being INSIDE the signed
/// prefix — this is the runnable half of a claim that was only prose.**
///
/// `granary_store::crypto::check_head` and `check_chain` both rest on ONE
/// signature authenticating the whole history, because `check_chain` binds
/// each ancestor to its child by `GrainId::of(&parent_bytes)` against a
/// `parent` field the head's signature covers. Both would
/// go on working after a format change that moved the signature
/// boundary above `parent`: the chain would quietly stop being
/// authenticated and every existing row would stay green, because no
/// row anywhere asserts where that boundary sits relative to `parent`.
///
/// A thirty-three-byte pattern (presence byte plus the id) is not
/// something a two-hundred-and-fifty-six-byte prefix carries by
/// coincidence, so a containment search is a sound instrument here and
/// needs no offset arithmetic duplicated out of `granary_core::root`.
#[tokio::test]
async fn a_roots_parent_is_covered_by_its_own_signature() {
    let (remote, view1) = published_volume().await;
    let l2 = Draft::after(&link(&view1)).store(&remote).await;
    let parent = l2
        .doc
        .parent
        .unwrap_or_else(|| panic!("a seq-2 root names its parent"));
    assert_eq!(
        parent,
        GrainId::of(&view1.root_bytes),
        "the fixture must chain by PREIMAGE over the stored ancestor bytes, \
         or this row is not about the property check_chain relies on"
    );

    let prefix = root::signed_prefix(&l2.root_bytes).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        prefix.len() < l2.root_bytes.len(),
        "the signed prefix must be a STRICT prefix, or `inside it` is vacuous"
    );
    let encoded = parent.to_bytes();
    assert!(
        prefix.windows(encoded.len()).any(|w| w == encoded),
        "the parent id is outside the signed prefix, so a root's claim about \
         its own ancestry is unsigned — and the head's single signature then \
         authenticates the head alone, not the chain (see \
         `check_chain`)"
    );
}

/// The dyn-compatibility `GrainSource`'s docs promise is only real if
/// consumers write `+ ?Sized`. This is the assertion that keeps it true.
#[tokio::test]
async fn the_local_seam_is_reachable_through_dyn() {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let manifest_root = seed_tree(&source);
    let dynamic: &dyn GrainSource = &source;

    let prepared = prepare_from_manifest(
        &remote,
        dynamic,
        manifest_root,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(prepared.seq(), 1);
}

// -------------------------------------------------- degraded-mode fixtures

/// A one-file, TWO-grain tree — `seed_tree`'s single-grain shape cannot
/// model "position 0 cached, position 1 evicted" at all, and that
/// distinction is the whole point of
/// `a_partially_cached_file_fails_not_truncates`.
async fn published_volume_two_grain_file() -> (FakeRemote, ResolveOutcome, GrainId, GrainId) {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let body_a = b"grain A: stays cached".to_vec();
    let body_b = b"grain B: gets evicted before the degraded read".to_vec();
    let len_a = u32::try_from(body_a.len()).unwrap_or_else(|e| panic!("{e}"));
    let len_b = u32::try_from(body_b.len()).unwrap_or_else(|e| panic!("{e}"));
    let grain_a = source.put(body_a);
    let grain_b = source.put(body_b);
    let entries = vec![manifest::DirEntry {
        name: manifest::Name::new(b"f".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(len_a) + u64::from(len_b),
            grains: manifest::FileGrains::Inline(vec![
                manifest::GrainRef {
                    id: grain_a,
                    unpacked_len: len_a,
                },
                manifest::GrainRef {
                    id: grain_b,
                    unpacked_len: len_b,
                },
            ]),
        },
    }];
    let leaf = manifest::encode_dir_leaf(&entries).unwrap_or_else(|e| panic!("{e}"));
    let manifest_root = source.put(leaf);
    let prepared = prepare_from_manifest(
        &remote,
        &source,
        manifest_root,
        granary_client::HarvestStats::default(),
        &volume(),
        &key(),
        &identity(),
        now(),
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    commit(&remote, prepared)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let view = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("a committed volume must resolve: {e}"));
    (remote, view, grain_a, grain_b)
}

/// Where `Cache` stores a content-addressed object on disk (mirrors
/// the cache module's own `object_path` (`cache/paths.rs`), which is
/// `pub(crate)` and so not exposed to this crate — the frozen on-disk shape is what a test reaching around the
/// public API to model a competing-writer eviction is allowed to know).
fn cached_object_path(scratch: &ScratchDir, id: &GrainId) -> PathBuf {
    let hex = id.digest_hex();
    let fanout = hex.get(..2).unwrap_or("00");
    scratch.0.join("objects").join(fanout).join(&hex)
}

/// Where `Cache` stores a root's raw bytes on disk (Roots section, same
/// doc) — the 20-digit zero-padded leaf `cache.rs`'s own suite pins.
fn cached_root_path(scratch: &ScratchDir, seq: u64) -> PathBuf {
    scratch
        .0
        .join("roots")
        .join(volume().as_str())
        .join(format!("{seq:020}"))
}

/// One captured `tracing::warn!` event's fields — just the ones the
/// degraded-announce tests below need.
#[derive(Debug, Default, Clone)]
struct DegradedWarnFields {
    message: Option<String>,
    volume: Option<String>,
    seq: Option<u64>,
    age: Option<String>,
}

impl tracing::field::Visit for DegradedWarnFields {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "seq" {
            self.seq = Some(value);
        } else if field.name() == "age" {
            self.age = Some(value.to_string());
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.text(field.name(), value);
    }

    /// The fallback every other `record_*` funnels through — a
    /// `%`-sigil field's value arrives here, not through `record_str`
    /// (mirrors `cache.rs`'s own capture idiom).
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        self.text(field.name(), rendered.trim_matches('"'));
    }
}

impl DegradedWarnFields {
    fn text(&mut self, name: &str, value: &str) {
        match name {
            "message" => self.message = Some(value.to_owned()),
            "volume" => self.volume = Some(value.to_owned()),
            "age" => self.age = Some(value.to_owned()),
            _other => {}
        }
    }
}

/// Every WARN-level event recorded, in order — proves the ANNOUNCE half
/// of rule (c) (naming the volume/seq/age), not merely that the resolve
/// did not panic.
#[derive(Clone, Default)]
struct WarnCapture(std::sync::Arc<Mutex<Vec<DegradedWarnFields>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut fields = DegradedWarnFields::default();
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(fields);
    }
}

/// `n` seqs of the SAME tree, published as a dedup-only republish chain
/// and every one PROPERLY SIGNED with `key()` —
/// `a_republish_against_fakes_advances_the_seq_and_links_the_chain`'s
/// own loop, generalised and returning each `Prepared::root_bytes`
/// captured before `commit` consumes it.
///
/// **Why this and not `Draft::after(..).store(..)`.** `Draft` leaves
/// the previous root's signature on the new document — deliberately
/// WRONG once the seq/epoch/parent change (that struct's own doc: "the
/// oracle does not check it and does not need to… these are structural
/// fixtures, not authenticity ones"). The gate below requires a
/// VERIFYING reader for every degraded serve, so a degraded-read
/// fixture with `seq >= 2` needs multi-seq SIGNATURES, not merely
/// multi-seq structure — `Draft` answers a question these tests do
/// not ask.
async fn published_volume_chain(seqs: u64) -> (FakeRemote, Vec<Vec<u8>>) {
    let remote = FakeRemote::default();
    let source = FakeSource::default();
    let manifest_root = seed_tree(&source);
    let mut root_bytes = Vec::new();
    for expected_seq in 1..=seqs {
        let prepared = prepare_from_manifest(
            &remote,
            &source,
            manifest_root,
            granary_client::HarvestStats::default(),
            &volume(),
            &key(),
            &identity(),
            now(),
            Policy::default(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(prepared.seq(), expected_seq);
        root_bytes.push(prepared.root_bytes.clone());
        commit(&remote, prepared)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    (remote, root_bytes)
}

// ----------------------------------------------------- degraded-mode tests

/// Test 2: the fresh-process shape — `cache.close()`, a NEW
/// `Cache::open` on the SAME dir, and a NEW remote that refuses
/// everything (nothing carried in memory from the warm resolve). The
/// volume is published TWICE first, so the degraded read's `check_chain`
/// runs with `seq >= 2` — making ancestor-root reads
/// through the SAME cache-read helper as the head root load-bearing.
///
/// **Verifying reader (gate rule (e)):** a transport-down degraded
/// serve now requires a `RootVerifier` that actually checks something —
/// see `resolve_head_degraded`'s own doc. Both the warm and the
/// degraded call use `anchor(key().public_key())` so the SAME reader
/// identity is exercised warm and cold, matching how a real client
/// would be configured.
#[tokio::test]
async fn server_down_after_a_fresh_process_still_serves_cached_reads() {
    let (remote, roots) = published_volume_chain(2).await;
    let trusted = anchor(key().public_key());

    let scratch = ScratchDir::new();
    let mut warm_cache = fresh_cache(&scratch);
    let mut warm_collected: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let warm = resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut warm_cache),
        ResolveTarget::WholeTree,
        &mut |id, bytes| {
            warm_collected.insert(id, bytes.to_vec());
            Ok(())
        },
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed while the server is up: {e}"));
    assert_eq!(warm.seq, 2);
    warm_cache.close().unwrap_or_else(|e| panic!("{e}"));

    // Fresh process: a NEW Cache::open on the same dir, a NEW remote.
    let mut fresh = fresh_cache(&scratch);
    let dead = FakeRemote::default();
    dead.go_down();

    let mut degraded_collected: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let degraded = resolve_head_verified(
        &dead,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut fresh),
        ResolveTarget::WholeTree,
        &mut |id, bytes| {
            degraded_collected.insert(id, bytes.to_vec());
            Ok(())
        },
    )
    .await
    .unwrap_or_else(|e| panic!("a degraded read from a fresh process must still succeed: {e}"));

    assert_eq!(degraded.seq, 2, "must serve the seq it was warmed at");
    assert_eq!(degraded.root_bytes, roots[1], "byte-identical root bytes");
    assert_eq!(
        degraded_collected, warm_collected,
        "byte-identical content, object for object"
    );
}

/// Test 3: never-silently-partial. One grain of a two-grain file is
/// evicted from the cache between the warm resolve and the degraded
/// one — the residency pre-flight must catch this BEFORE the sink
/// is ever called, not after streaming the first (cached) grain.
#[tokio::test]
async fn a_partially_cached_file_fails_not_truncates() {
    let (remote, _view, _grain_a, grain_b) = published_volume_two_grain_file().await;
    let trusted = anchor(key().public_key());
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed: {e}"));

    // Evict grain B's cached object directly off disk — the shape a
    // competing writer's own quota eviction leaves behind between the
    // warm resolve and the degraded one.
    let evicted = cached_object_path(&scratch, &grain_b);
    std::fs::remove_file(&evicted).unwrap_or_else(|e| panic!("{e}"));

    let dead = FakeRemote::default();
    dead.go_down();

    let mut sink_bytes: usize = 0;
    let path_name = manifest::Name::new(b"f".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let err = resolve_head_verified(
        &dead,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::Path(&[path_name]),
        &mut |_, bytes| {
            sink_bytes += bytes.len();
            Ok(())
        },
    )
    .await
    .expect_err("a partially cached file must fail, not truncate");

    match err {
        ResolveError::Degraded { missing, .. } => {
            assert!(
                missing.contains(&grain_b.to_string()),
                "expected the missing grain named, got {missing:?}"
            );
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
    assert_eq!(sink_bytes, 0, "zero bytes may reach the sink");
}

/// Test 4: rule (c) — a degraded serve is always
/// announced, exactly once, naming the volume and the seq.
#[tokio::test]
async fn degraded_serves_are_announced() {
    let (remote, _warm_view) = published_volume().await;
    let trusted = anchor(key().public_key());
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed: {e}"));

    let dead = FakeRemote::default();
    dead.go_down();

    let capture = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    let outcome = resolve_head_verified(
        &dead,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await;
    drop(guard);
    let outcome =
        outcome.unwrap_or_else(|e| panic!("the degraded resolve must still succeed: {e}"));

    let events = capture
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(
        events.len(),
        1,
        "exactly one degraded-read warning must fire per invocation, got {events:?}"
    );
    let event = &events[0];
    assert_eq!(
        event.volume.as_deref(),
        Some("<volume>"),
        "the telemetry warn must classify the volume, got {event:?}"
    );
    assert_eq!(
        event.seq,
        Some(outcome.seq),
        "the warn must name the seq being served, got {event:?}"
    );
    let age = event.age.clone().unwrap_or_default();
    assert!(
        age == "unknown" || age.parse::<i64>().is_ok(),
        "the warn must name a computed age or 'unknown', got {age:?}"
    );
}

/// Test 5: a no-hint anchor (`resolve_at` raises the
/// floor but never touches the hint) must report the
/// age as UNKNOWN, never a fabricated figure.
#[tokio::test]
async fn a_no_hint_anchor_produces_an_unknown_age_not_a_fabricated_one() {
    let (remote, _view) = published_volume().await;
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_at(
        &remote,
        volume().as_str(),
        1,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed: {e}"));
    assert_eq!(
        cache.read_anchor(&volume()).and_then(|a| a.hint),
        None,
        "resolve_at must never persist a hint — or this row proves nothing"
    );

    let dead = FakeRemote::default();
    dead.go_down();

    let capture = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    let trusted = anchor(key().public_key());
    let outcome = resolve_head_verified(
        &dead,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await;
    drop(guard);
    outcome.unwrap_or_else(|e| panic!("the degraded resolve must still succeed: {e}"));

    let events = capture
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(events.len(), 1, "got {events:?}");
    assert_eq!(
        events[0].age.as_deref(),
        Some("unknown"),
        "a no-hint anchor must report an UNKNOWN age, never a fabricated figure, got {:?}",
        events[0]
    );
}

/// Test 6: the no-re-emit guard. Once a byte has reached the sink, a
/// LATER transport failure in the same resolve must surface as the
/// bare transport error and must NOT retry degraded — a retry would
/// re-run the whole resolve and write the already-sent prefix twice.
///
/// **This row was VACUOUS as first written.** It drove the KEYLESS
/// `resolve_head`, so once rule (e) landed the degraded fallback
/// refused at the `is_verifying()` gate regardless of the `emitted`
/// guard: deleting `!emitted` from `resolve_head_verified`'s trigger left
/// the whole suite green, because this was the only mid-emission
/// `go_down()` and it could never reach the guard. It now drives a
/// VERIFYING reader, so the guard is the ONLY thing standing between a
/// mid-emission transport failure and a degraded retry, and it has a
/// positive control: with the guard PRESENT the resolve surfaces
/// `Remote(_)` (no fallback); with it DELETED the fallback runs, its
/// whole-set residency pre-flight finds the deliberately-uncached content
/// and returns `Degraded { .. }` — a DIFFERENT error variant this row's
/// `matches!(Remote(_))` assertion catches. (Actual double-emission —
/// `sink_calls == 2` — additionally requires the pre-flight to pass, i.e.
/// resident content, which cannot coexist with a normal attempt that
/// fails on that same content; the pre-flight is the guard's outer layer
/// and rule (d)'s own rows are its control. This row pins the guard's
/// no-fallback behaviour, which the pre-flight does not.)
#[tokio::test]
async fn a_transport_failure_after_emission_started_does_not_retry_degraded() {
    let (remote, warm_view) = published_volume().await;
    let trusted = anchor(key().public_key());
    let bogus = manifest::Name::new(b"does-not-exist".to_vec()).unwrap_or_else(|e| panic!("{e}"));

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);

    // Warm metadata + structure only, deliberately leaving content
    // UNCACHED: a Path target naming a file that does not exist still
    // runs the whole unconditional metadata/structure fetch before
    // failing at lookup (`emit_target`'s own doc).
    let warm_err = resolve_at(
        &remote,
        volume().as_str(),
        1,
        Some(&mut cache),
        ResolveTarget::Path(&[bogus]),
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a bogus path must fail lookup");
    assert!(
        matches!(warm_err, ResolveError::NoSuchTarget { .. }),
        "got {warm_err:?}"
    );

    // Seed the root + anchor floor by hand (public Cache API): the
    // bogus-path warm above never reaches resolve_at_verified_impl's
    // tail, which is the only place that would otherwise do it.
    cache.put_root_bytes(&volume(), 1, &warm_view.root_bytes);
    cache.raise_anchor(&volume(), Some(1), HintUpdate::Unchanged);

    let mut sink_calls = 0usize;
    let err = resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| {
            sink_calls += 1;
            if sink_calls == 1 {
                // The transport goes down ONLY once something has
                // already reached the sink (the tree's one structure
                // node, emitted before any content grain) — modelling a
                // failure mid-resolve, not one before it ever started.
                remote.go_down();
            }
            Ok(())
        },
    )
    .await
    .expect_err("the content fetch must fail once the transport goes down");

    assert!(
        matches!(err, ResolveError::Remote(_)),
        "a transport failure AFTER emission started must surface as the bare transport error, \
         never retried degraded (a retry would return Degraded here — the mutant tell). got {err:?}"
    );
    assert_eq!(
        sink_calls, 1,
        "the sink must have been fed exactly the one structure-node prefix, never twice"
    );
}

/// Test 7: an explicit seq is a COMMAND, never a
/// recovery — `resolve_at_verified` must never fall back to the
/// cache, even with a fully populated one and a dead transport.
#[tokio::test]
async fn an_explicit_seq_never_degrades() {
    let (remote, _warm_view) = published_volume().await;
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_at(
        &remote,
        volume().as_str(),
        1,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed: {e}"));

    remote.go_down();

    let err = resolve_at_verified(
        &remote,
        volume().as_str(),
        1,
        &RootVerifier::unverified(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("an explicit seq must never fall back to the cache");

    assert!(
        matches!(err, ResolveError::Remote(_)),
        "expected the bare transport error, got {err:?}"
    );
}

/// Test 8: ancestor-chain coverage. A degraded read of a `seq >=
/// 2` volume must walk `check_chain`'s ancestor loop ENTIRELY
/// from the cache — this fails loudly (an `Err`, not `Ok`) if
/// ancestor reads bypass the cache, since `remote` cannot answer anything.
#[tokio::test]
async fn a_degraded_read_walks_the_ancestor_chain_entirely_from_the_cache() {
    let (remote, _roots) = published_volume_chain(2).await;
    let trusted = anchor(key().public_key());

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed: {e}"));

    remote.go_down();

    let outcome = resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("a degraded read of a chained volume must still resolve: {e}"));

    assert_eq!(outcome.seq, 2);
}

/// Test 9: a degraded read whose ANCESTOR root (not the head's
/// own) is absent from the cache must fail as `Degraded`, never
/// `ChainBroken` — `ChainBroken` is a claim about the volume's own
/// history that a degraded cache miss has no standing to make.
#[tokio::test]
async fn a_degraded_read_with_a_missing_ancestor_root_is_degraded_not_chain_broken() {
    let (remote, _roots) = published_volume_chain(2).await;
    let trusted = anchor(key().public_key());

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed: {e}"));

    // Evict the ANCESTOR (seq 1) root directly off disk.
    let path = cached_root_path(&scratch, 1);
    std::fs::remove_file(&path).unwrap_or_else(|e| panic!("{e}"));

    remote.go_down();

    let err = resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a missing ancestor root must fail the degraded read");

    match err {
        ResolveError::Degraded { missing, .. } => {
            assert!(
                missing.contains("seq 1"),
                "expected the missing ancestor named, got {missing:?}"
            );
        }
        other => panic!("expected Degraded, not e.g. ChainBroken, got {other:?}"),
    }
}

/// Test 10: the transport-down predicate. A NON-transport
/// `RootStoreError` — the store ANSWERED, it just refused the response
/// — must never trigger a degraded attempt: it surfaces unchanged.
#[tokio::test]
async fn a_non_transport_error_does_not_trigger_a_degraded_attempt() {
    let (remote, _view) = published_volume().await;
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed: {e}"));

    remote.refuse_with(RootStoreError::RefusedResponse {
        reason: "test: oversized response".to_owned(),
        kind: RefusalKind::OverCap,
    });

    let err = resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a RefusedResponse must not be swallowed into a degraded serve");

    assert!(
        matches!(
            err,
            ResolveError::Remote(RootStoreError::RefusedResponse { .. })
        ),
        "expected RefusedResponse to surface unchanged (never Degraded, never a silent cache \
         serve), got {err:?}"
    );
}

// ------------------------------------------------ degraded-fallback rows

/// Rule (e)'s own positive control. A KEYLESS reader with a
/// FULLY WARM cache and a dead transport must get the ORIGINAL
/// transport error, never a degraded serve, with the refusal announced
/// exactly once — and the warning must not claim a cached head exists
/// (the gate runs before `read_anchor` ever executes, so `event.seq` is
/// never set here, unlike `announce_degraded`'s own warn). This is
/// exactly the fixture an unpatched `resolve_head_degraded` served
/// content from before this gate existed.
#[tokio::test]
async fn a_keyless_reader_never_degrades_even_with_a_warm_cache() {
    let (remote, _view) = published_volume().await;
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head(
        &remote,
        volume().as_str(),
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed: {e}"));

    let dead = FakeRemote::default();
    dead.go_down();

    let capture = WarnCapture::default();
    let guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
    let mut sink_bytes = 0usize;
    let err = resolve_head(
        &dead,
        volume().as_str(),
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, b| {
            sink_bytes += b.len();
            Ok(())
        },
    )
    .await
    .expect_err("a keyless reader must never degrade, even from a fully warm cache");
    drop(guard);

    assert!(
        matches!(err, ResolveError::Remote(_)),
        "expected the ORIGINAL transport error unchanged, got {err:?}"
    );
    assert_eq!(
        sink_bytes, 0,
        "no cache-dir content may reach the sink either"
    );

    let events = capture
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(
        events.len(),
        1,
        "the refusal must be announced exactly once, got {events:?}"
    );
    assert_eq!(
        events[0].volume.as_deref(),
        Some("<volume>"),
        "the telemetry refusal warn must classify the volume, got {:?}",
        events[0]
    );
    assert_eq!(
        events[0].seq, None,
        "the refusal runs BEFORE read_anchor, so it must never name a seq — that would claim a \
         cached head exists when the gate has not looked yet, got {:?}",
        events[0]
    );
}

/// Rejects the "serve the newest cached root"
/// degenerate: the degraded candidate IS the anchor floor,
/// never whatever else happens to be sitting in the cache. Honestly
/// reachable: a crash between `Cache::put_root_bytes(vol, 2, ..)` and
/// the following `Cache::raise_anchor(vol, Some(2), ..)` leaves exactly
/// this state — seq 2's root cached and authentic, but the floor never
/// moved past seq 1.
#[tokio::test]
async fn a_cache_with_two_authentic_roots_serves_the_anchor_not_the_newest() {
    let (remote, roots) = published_volume_chain(2).await;
    let trusted = anchor(key().public_key());

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    // Warm at seq 1 ONLY: caches seq 1's full content/metadata and
    // raises the anchor floor to 1.
    resolve_at_verified(
        &remote,
        volume().as_str(),
        1,
        &trusted,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve at seq 1 must succeed: {e}"));
    assert_eq!(cache.read_anchor(&volume()).map(|a| a.seq), Some(1));

    // The other half of the modelled crash: seq 2's AUTHENTIC root
    // bytes land in the cache (as a real client's own `put_root_bytes`
    // call would put them), but nothing ever raises the anchor past 1.
    cache.put_root_bytes(&volume(), 2, &roots[1]);
    assert!(
        cache.get_root_bytes(&volume(), 2).is_some(),
        "seq 2's root must actually be cached for this row to test anything"
    );

    let dead = FakeRemote::default();
    dead.go_down();

    let outcome = resolve_head_verified(
        &dead,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("a degraded read at the anchor floor must succeed: {e}"));

    assert_eq!(
        outcome.seq, 1,
        "the degraded candidate is the ANCHOR, not the newest cached root — serving seq 2 here \
         would serve a seq the anchor never accepted"
    );
}

/// A missing ANCHOR root must return the
/// ORIGINAL transport error, never a walk down to an older seq the
/// cache still holds. Select only the anchor's seq: `Some(a) =>
/// candidate a.seq`, and `cache.get_root_bytes(vol, a.seq)` must be
/// `Some` or the original error returns — there is no second attempt at
/// a lower seq.
#[tokio::test]
async fn a_missing_anchor_root_never_walks_down_to_an_older_cached_seq() {
    let (remote, _roots) = published_volume_chain(2).await;
    let trusted = anchor(key().public_key());

    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    // A normal warm resolve at the head (seq 2): caches BOTH seq 1
    // (check_chain's ancestor walk) and seq 2 (the head), and raises
    // the anchor floor to 2.
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("the warm resolve must succeed: {e}"));
    assert_eq!(cache.read_anchor(&volume()).map(|a| a.seq), Some(2));
    assert!(
        cache.get_root_bytes(&volume(), 1).is_some(),
        "seq 1 must be cached too, or this row cannot tell a refusal from a starved fixture"
    );

    // Evict ONLY the anchor's own root (seq 2) — seq 1 stays cached and
    // authentic.
    let path = cached_root_path(&scratch, 2);
    std::fs::remove_file(&path).unwrap_or_else(|e| panic!("{e}"));

    let dead = FakeRemote::default();
    dead.go_down();

    let err = resolve_head_verified(
        &dead,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a missing anchor root must fail, never walk down to an older cached seq");

    assert!(
        matches!(err, ResolveError::Remote(_)),
        "expected the ORIGINAL transport error, never Degraded and never a seq-1 fallback, got \
         {err:?}"
    );
}

/// Degraded-read fix, item D row 6 — pins that the residency pre-flight is
/// HASH-VERIFIED (`Cache::get`), not a `stat`. Confirmed against the
/// mutant this row exists to kill: a `symlink_metadata().is_file()`
/// presence probe in `residency_preflight`'s place passes every OTHER
/// row in this suite and still truncates for real.
#[tokio::test]
async fn a_corrupt_cached_grain_is_a_miss_not_a_truncation() {
    let (remote, _view, _grain_a, grain_b) = published_volume_two_grain_file().await;
    let trusted = anchor(key().public_key());
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("warm: {e}"));

    // CORRUPT, not absent, and the SAME LENGTH: a size or presence check
    // passes this, only a hash check catches it.
    let object_path = cached_object_path(&scratch, &grain_b);
    let honest = std::fs::read(&object_path).unwrap_or_else(|e| panic!("{e}"));
    let mut corrupt = honest.clone();
    let Some(first_byte) = corrupt.first_mut() else {
        panic!("the fixture grain must be non-empty for a flipped bit to mean anything");
    };
    *first_byte ^= 0xff;
    assert_eq!(corrupt.len(), honest.len(), "same length, one flipped bit");
    // The cache writes objects `0444`; `remove_file` first —
    // deleting an entry needs write access to the DIRECTORY, not the
    // file — then a fresh `write` creates a new, writable file at the
    // same path. A bare overwrite of the existing 0444 file fails with
    // EACCES before the plant ever lands.
    std::fs::remove_file(&object_path).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&object_path, &corrupt).unwrap_or_else(|e| panic!("{e}"));

    let dead = FakeRemote::default();
    dead.go_down();
    let mut sink_bytes = 0usize;
    let name = manifest::Name::new(b"f".to_vec()).unwrap_or_else(|e| panic!("{e}"));
    let err = resolve_head_verified(
        &dead,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::Path(&[name]),
        &mut |_, b| {
            sink_bytes += b.len();
            Ok(())
        },
    )
    .await
    .expect_err("a corrupt cached grain must fail the degraded read");
    assert!(
        matches!(err, ResolveError::Degraded { .. }),
        "a corrupt object must be a pre-flight MISS (Degraded), not a wire fall-through; got \
         {err:?}"
    );
    assert_eq!(sink_bytes, 0, "zero bytes may reach the sink");
}

/// A clock a fixed hour past [`now`], so a test can assert the
/// announced age is a COMPUTED elapsed figure and not any constant.
struct ClockPlusHour;

impl Clock for ClockPlusHour {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: now().secs + 3600,
            nanos: 0,
        }
    }
}

/// Degraded-read fix, item D row 7 — `degraded_serves_are_announced`'s own age
/// assertion (`age == "unknown" || age.parse::<i64>().is_ok()`) is
/// VACUOUS: it holds for every implementation, including one that
/// always reports `"unknown"` or any other valid integer. This row pins
/// the exact computed value instead.
#[tokio::test]
async fn the_announced_age_is_the_computed_elapsed_seconds() {
    let (remote, _view) = published_volume().await;
    let trusted = anchor(key().public_key());
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("warm: {e}"));
    let stamp = cache
        .read_anchor(&volume())
        .and_then(|a| a.hint)
        .unwrap_or_else(|| panic!("the warm resolve must persist a hint"))
        .stamp_secs;

    let dead = FakeRemote::default();
    dead.go_down();
    let later = HeadContext::new(Box::new(ClockPlusHour), Box::new(SeededRng::new(1)));
    let capture = WarnCapture::default();
    let guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
    let outcome = resolve_head_verified(
        &dead,
        volume().as_str(),
        &trusted,
        &later,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await;
    drop(guard);
    outcome.unwrap_or_else(|e| panic!("the degraded resolve must succeed: {e}"));

    let events = capture
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(events.len(), 1, "got {events:?}");
    let expected = (now().secs + 3600 - stamp).to_string();
    assert_eq!(
        events[0].age.as_deref(),
        Some(expected.as_str()),
        "the age must be the COMPUTED elapsed seconds, never a constant; got {:?}",
        events[0]
    );
}

/// `Unavailable` (a `503`) is the store ANSWERING, so it must SURFACE
/// to the caller, never trigger a stale degraded serve. Degrading on a
/// `503` let an UNAUTHENTICATED load-shed — or a rolling-deploy drain —
/// silently pin
/// every warm-cache verifying reader to its stale anchor seq, and it
/// contradicted the requirement that a `503` is a read RESPONSE
/// the fetcher's AIMD handles, then surfaces. This is now the NEGATIVE
/// control that `Unavailable` sits on `is_transport_down`'s `false` side:
/// a one-line regression moving it back to `true` fails here. The warm
/// cache is fully populated, so ONLY the classification — not a cache
/// miss — decides the outcome. [`a_degraded_read_recovers_from_elapsed`]
/// and the `Backend`-via-`go_down` rows are the TRUE side's positive
/// controls.
#[tokio::test]
async fn an_unavailable_response_surfaces_not_degrades() {
    let (remote, _view) = published_volume().await;
    let trusted = anchor(key().public_key());
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("warm: {e}"));

    remote.refuse_with(RootStoreError::Unavailable {
        operation: "GET root",
        status: 503,
    });

    let err = resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .expect_err("a 503 is the store answering; it must surface, not serve a stale cache seq");
    assert!(
        matches!(
            err,
            ResolveError::Remote(RootStoreError::Unavailable { .. })
        ),
        "the 503 must surface UNCHANGED as the transport error, never be papered over by a \
         degraded serve; got {err:?}"
    );
}

/// `Elapsed` (a wedged peer cut by its own per-seam deadline) is the
/// store producing NO answer, so it stays on `is_transport_down`'s TRUE
/// side and DOES recover degraded — the positive control that a
/// no-answer transport failure still degrades, paired with the
/// `Backend`-via-`go_down` rows. Contrast
/// [`an_unavailable_response_surfaces_not_degrades`], the answered-`503`
/// case that must NOT degrade.
#[tokio::test]
async fn a_degraded_read_recovers_from_elapsed() {
    let (remote, _view) = published_volume().await;
    let trusted = anchor(key().public_key());
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("warm: {e}"));

    remote.refuse_with(RootStoreError::Elapsed {
        operation: "GET root",
        after: std::time::Duration::from_secs(30),
    });

    let outcome = resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("Elapsed must trigger a real degraded serve, got Err: {e}"));
    assert_eq!(outcome.seq, 1);
}

/// Degraded-read fix, item E — rule (d) for `WholeTree` specifically.
/// `a_partially_cached_file_fails_not_truncates` uses `ResolveTarget::
/// Path`, the one target that emits NOTHING before `emit_file` runs.
/// `WholeTree` emits every structure node before any file, so a
/// per-file pre-flight alone cannot keep its sink clean: a degraded
/// `WholeTree` runs the whole-set `residency_preflight` before its
/// first sink call. That row's `assert_eq!(sink_bytes, 0)` exercises
/// only `Path`; this row is `WholeTree`'s own proof.
#[tokio::test]
async fn a_degraded_whole_tree_partial_emits_no_bytes() {
    let (remote, _view, _grain_a, grain_b) = published_volume_two_grain_file().await;
    let trusted = anchor(key().public_key());
    let scratch = ScratchDir::new();
    let mut cache = fresh_cache(&scratch);
    resolve_head_verified(
        &remote,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("warm: {e}"));
    std::fs::remove_file(cached_object_path(&scratch, &grain_b)).unwrap_or_else(|e| panic!("{e}"));

    let dead = FakeRemote::default();
    dead.go_down();
    let mut sink_bytes = 0usize;
    let err = resolve_head_verified(
        &dead,
        volume().as_str(),
        &trusted,
        &head_ctx(),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, b| {
            sink_bytes += b.len();
            Ok(())
        },
    )
    .await
    .expect_err("a partially cached tree must fail");
    assert!(matches!(err, ResolveError::Degraded { .. }), "got {err:?}");
    assert_eq!(
        sink_bytes, 0,
        "rule (d): zero bytes may reach the sink on a degraded partial, WholeTree included"
    );
}
