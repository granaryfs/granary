// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::binstore` — the bin/meta object store contract.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::root::VolumeName;
use crate::testkit::block_on;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Mutex;

/// The whole point of the desugared trait shape: the
/// futures must be `Send`, which sugared `async fn` in a trait
/// cannot express.
fn assert_send<T: Send>(_: &T) {}

/// GENERIC on purpose. Called with a concrete fake, `assert_send`
/// would only witness that THIS impl's futures happen to be `Send`
/// and would stay green if the trait dropped `+ Send`. Inside a
/// generic body the bound is the only thing known, so this stops
/// compiling the moment the trait stops promising it.
fn assert_trait_futures_are_send<S: BinStore>(store: &S) {
    let digest = [0u8; DIGEST_LEN];
    let id = GrainId::of(b"m");
    assert_send(&store.put_bin(&digest, vec![1]));
    assert_send(&store.put_meta("v", &id, vec![1]));
    assert_send(&store.get_meta("v", &id));
    assert_send(&store.get_bin_range(&digest, 0, 1));
}

/// A minimal in-memory [`BinStore`]: std only, no tokio, no
/// `object_store`.
#[derive(Debug, Default)]
struct FakeBins {
    bins: Mutex<BTreeMap<[u8; DIGEST_LEN], Vec<u8>>>,
    meta: Mutex<BTreeMap<(String, GrainId), Vec<u8>>>,
}

fn poisoned<T>(_: T) -> RootStoreError {
    RootStoreError::Backend("fake bin store mutex poisoned".to_owned())
}

/// The contract's obligation, carried by the FAKE and not only by
/// the adapter: a name that is not a [`VolumeName`] never becomes a
/// key. A fake that skips this accepts names production refuses.
fn checked_volume(volume: &str) -> Result<(), RootStoreError> {
    VolumeName::new(volume.to_owned())
        .map(|_| ())
        .map_err(|e| RootStoreError::InvalidVolume {
            reason: e.to_string(),
        })
}

/// Written with `async fn` on purpose: an IMPLEMENTOR gets the
/// sugar, and the trait's `+ Send` is still checked here. The
/// desugaring is only needed on the TRAIT, where the sugar cannot
/// express `Send`.
impl BinStore for FakeBins {
    async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        // The content-address contract, asserted the way the
        // granary-store adapter asserts it — so a conformance suite
        // run against both agrees instead of panicking on one.
        debug_assert_eq!(*GrainId::of(&bytes).digest(), *digest);
        let mut bins = self.bins.lock().map_err(poisoned)?;
        match bins.entry(*digest) {
            // Content-addressed: an occupant is SUCCESS, not an
            // error — `false` means "not novel".
            Entry::Occupied(_) => Ok(false),
            Entry::Vacant(v) => {
                v.insert(bytes);
                Ok(true)
            }
        }
    }

    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        checked_volume(volume)?;
        let mut meta = self.meta.lock().map_err(poisoned)?;
        match meta.entry((volume.to_owned(), *id)) {
            Entry::Occupied(_) => Ok(false),
            Entry::Vacant(v) => {
                v.insert(bytes);
                Ok(true)
            }
        }
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        checked_volume(volume)?;
        let meta = self.meta.lock().map_err(poisoned)?;
        meta.get(&(volume.to_owned(), *id))
            .cloned()
            .ok_or(RootStoreError::NotFound)
    }

    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        let end = offset
            .checked_add(u64::from(len))
            .ok_or(RootStoreError::RangeOverflow)?;
        let bins = self.bins.lock().map_err(poisoned)?;
        let bytes = bins.get(digest).ok_or(RootStoreError::NotFound)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        // A range that starts at or past the end, or that spans
        // nothing, is a backend range error — not an empty success.
        // Clamping these instead would make the fake accept extents
        // the real backend refuses.
        if start >= bytes.len() || len == 0 {
            return Err(RootStoreError::Backend(format!(
                "invalid range: wanted range starting at {offset}, but object was only {} bytes long",
                bytes.len()
            )));
        }
        // Only the END is clamped: the start is in bounds above, so
        // an overhanging range short-reads the available tail.
        let stop = usize::try_from(end).unwrap_or(usize::MAX).min(bytes.len());
        Ok(bytes.get(start..stop).unwrap_or_default().to_vec())
    }
}

fn bin(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    *GrainId::of(bytes).digest()
}

/// The fake runs the SHARED conformance suite — the same body the
/// granary-store adapter runs. A rule that holds here and not there
/// (or the reverse) cannot pass both.
#[test]
fn fake_satisfies_the_shared_binstore_conformance_suite() {
    let store = FakeBins::default();
    block_on(crate::testkit::binstore_conformance(&store));
}

#[test]
fn trait_is_implementable_without_tokio_and_futures_are_send() {
    let store = FakeBins::default();
    // Through the bound, not through the concrete impl.
    assert_trait_futures_are_send(&store);
    // And the fake really runs with no executor: one poll finishes
    // every one of these, or `block_on` panics.
    // Content-addressed pairs, per the put_bin/put_meta contract —
    // a mismatched pair trips the adapter's debug_assert, so the
    // fake's tests must not model one.
    let meta = vec![1u8];
    let id = GrainId::of(&meta);
    let body = vec![1u8];
    let digest = bin(&body);
    assert_eq!(block_on(store.put_bin(&digest, body)), Ok(true));
    assert_eq!(block_on(store.put_meta("v", &id, meta.clone())), Ok(true));
    assert_eq!(block_on(store.get_meta("v", &id)), Ok(meta));
    assert_eq!(block_on(store.get_bin_range(&digest, 0, 1)), Ok(vec![1]));
}

/// `AlreadyExists` is SUCCESS for content-addressed objects: the
/// answer is "was it novel", never an error.
#[test]
fn puts_report_novelty_and_never_error_on_a_second_write() {
    let store = FakeBins::default();
    let body = b"a bin".to_vec();
    let digest = bin(&body);
    assert_eq!(block_on(store.put_bin(&digest, body.clone())), Ok(true));
    assert_eq!(block_on(store.put_bin(&digest, body.clone())), Ok(false));

    let id = GrainId::of(b"a meta object");
    assert_eq!(
        block_on(store.put_meta("v", &id, b"a meta object".to_vec())),
        Ok(true)
    );
    assert_eq!(
        block_on(store.put_meta("v", &id, b"a meta object".to_vec())),
        Ok(false)
    );
    assert_eq!(
        block_on(store.get_meta("v", &id)),
        Ok(b"a meta object".to_vec())
    );
    // Volumes are separate key spaces, so the same id is novel again
    // under another volume.
    assert_eq!(
        block_on(store.put_meta("w", &id, b"a meta object".to_vec())),
        Ok(true)
    );
    assert_eq!(
        block_on(store.get_meta("nope-v", &id)),
        Err(RootStoreError::NotFound)
    );
}

/// The PINNED semantic, BOTH halves, plus the two error paths that
/// share this method. The boundary cases are the point: a fake that
/// clamps everywhere agrees with the adapter on `(90,50)` and
/// disagrees at exactly the offsets an adversarial extent produces.
#[test]
fn get_bin_range_short_reads_inside_and_errors_at_or_past_the_end() {
    let store = FakeBins::default();
    let body: Vec<u8> = (0..100u8).collect();
    let digest = bin(&body);
    block_on(store.put_bin(&digest, body.clone())).unwrap();

    assert_eq!(
        block_on(store.get_bin_range(&digest, 10, 5)),
        Ok((10..15u8).collect::<Vec<u8>>())
    );
    // (90, 50) on a 100-byte object overhangs by 40: ten bytes back,
    // not fifty, and not an error.
    let got = block_on(store.get_bin_range(&digest, 90, 50)).unwrap();
    assert_eq!(got, (90..100u8).collect::<Vec<u8>>());
    assert_eq!(got.len(), 10);
    // Starting AT or PAST the end is a range ERROR, not an empty
    // success — matching the adapter, which answers `Invalid range`.
    for (off, len) in [(200u64, 8u32), (100, 8)] {
        assert!(
            matches!(
                block_on(store.get_bin_range(&digest, off, len)),
                Err(RootStoreError::Backend(_))
            ),
            "({off},{len}) must be a range error, not an empty read"
        );
    }
    // A zero-length range spans nothing and is likewise an error.
    assert!(matches!(
        block_on(store.get_bin_range(&digest, 10, 0)),
        Err(RootStoreError::Backend(_))
    ));
    // Checked arithmetic, not a panic, on an adversarial extent.
    assert_eq!(
        block_on(store.get_bin_range(&digest, u64::MAX, 1)),
        Err(RootStoreError::RangeOverflow)
    );
    // A bin that does not exist is NotFound — never an empty read.
    assert_eq!(
        block_on(store.get_bin_range(&bin(b"absent"), 0, 8)),
        Err(RootStoreError::NotFound)
    );
}

/// `checked_volume` is part of the CONTRACT: every implementation
/// validates the name before it becomes a key, because
/// `object_store::path::Path::from` normalises `a/b`, `a//b` and
/// `a/b/` into the same keyspace.
#[test]
fn put_meta_refuses_a_volume_name_that_never_becomes_a_key() {
    let store = FakeBins::default();
    let body = vec![1u8];
    let id = GrainId::of(&body);
    for bad in ["a/b", "a//b", "a/b/", "", "-a", "Vol"] {
        assert!(
            VolumeName::new(bad.to_owned()).is_err(),
            "{bad} must be rejected by VolumeName for this test to mean anything"
        );
        assert!(
            matches!(
                block_on(store.put_meta(bad, &id, body.clone())),
                Err(RootStoreError::InvalidVolume { .. })
            ),
            "put_meta accepted {bad}"
        );
        assert!(
            matches!(
                block_on(store.get_meta(bad, &id)),
                Err(RootStoreError::InvalidVolume { .. })
            ),
            "get_meta accepted {bad}"
        );
    }
    // Not a blanket refuser — a DNS-1123 name still stores, and it
    // stores as NOVEL, so none of the refused calls wrote anything.
    assert_eq!(block_on(store.put_meta("a-b", &id, body)), Ok(true));
}
