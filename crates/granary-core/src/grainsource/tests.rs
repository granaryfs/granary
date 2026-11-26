// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::grainsource` — the local-store read contract.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use std::collections::BTreeMap;

/// A minimal in-memory [`GrainSource`]: std only, no futures, no
/// filesystem. The map is keyed by the id a caller ASKS for, which
/// is what lets a test store bytes that do not hash to their key.
#[derive(Debug, Default)]
struct FakeSource {
    objects: BTreeMap<GrainId, Vec<u8>>,
}

impl FakeSource {
    /// Store `bytes` under their own id — the honest case.
    fn insert(&mut self, bytes: &[u8]) -> GrainId {
        let id = GrainId::of(bytes);
        self.objects.insert(id, bytes.to_vec());
        id
    }

    /// Store `bytes` under a FOREIGN id — bit rot, a truncated
    /// write, or a hostile local store.
    fn insert_corrupt(&mut self, id: GrainId, bytes: &[u8]) {
        self.objects.insert(id, bytes.to_vec());
    }
}

impl GrainSource for FakeSource {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        let bytes = self.objects.get(id).ok_or(GrainSourceError::Missing(*id))?;
        // The read path is the verified path.
        if GrainId::of(bytes) == *id {
            Ok(bytes.clone())
        } else {
            Err(GrainSourceError::Corrupt(*id))
        }
    }

    fn has(&self, id: &GrainId) -> bool {
        self.objects.contains_key(id)
    }
}

#[test]
fn get_returns_the_bytes_when_they_hash_to_the_id() {
    let mut source = FakeSource::default();
    let id = source.insert(b"a grain");
    assert_eq!(source.get(&id), Ok(b"a grain".to_vec()));
    assert!(source.has(&id));
}

#[test]
fn get_returns_missing_when_nothing_is_stored_under_the_id() {
    let source = FakeSource::default();
    let absent = GrainId::of(b"never stored");
    assert_eq!(source.get(&absent), Err(GrainSourceError::Missing(absent)));
    assert!(!source.has(&absent));
}

/// The read path VERIFIES. `has` does not — presence is not an
/// integrity claim, and this is the case that separates them.
#[test]
fn get_returns_corrupt_when_the_stored_bytes_do_not_hash_to_the_id() {
    let mut source = FakeSource::default();
    let id = GrainId::of(b"the real bytes");
    source.insert_corrupt(id, b"not the real bytes");
    assert_eq!(source.get(&id), Err(GrainSourceError::Corrupt(id)));
    assert!(
        source.has(&id),
        "has() reports presence only — it must not verify"
    );
}

/// Synchronous on purpose, which is also what makes this the one
/// seam here that is dyn-compatible.
#[test]
fn trait_is_dyn_compatible() {
    let mut source = FakeSource::default();
    let id = source.insert(b"dyn");
    let erased: &dyn GrainSource = &source;
    assert!(erased.has(&id));
    assert_eq!(erased.get(&id), Ok(b"dyn".to_vec()));
}

#[test]
fn errors_display_their_semantics() {
    let id = GrainId::of(b"x");
    // Each variant renders something that DISTINGUISHES it.
    // `!is_empty()` alone passes for any non-empty string, including
    // another variant's message, so it pins nothing.
    for (e, needle) in [
        (GrainSourceError::Missing(id), "no object"),
        (GrainSourceError::Corrupt(id), "do not hash"),
        (GrainSourceError::Backend("boom".to_owned()), "boom"),
    ] {
        let rendered = e.to_string();
        assert!(
            rendered.contains(needle),
            "{e:?} rendered as {rendered:?}, which does not carry {needle:?}"
        );
    }
    // The id is in the message: a bare "corrupt" names nothing.
    assert!(
        GrainSourceError::Corrupt(id)
            .to_string()
            .contains(&id.to_string())
    );
}
