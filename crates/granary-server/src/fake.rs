// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A second implementation of both seams, shared by every test site in
//! this crate that needs a store with real state.
//!
//! **One body, driven from two sides.** `seam_drivable` drives it
//! through [`crate::admit`] and [`crate::dispatch`] with no HTTP at all;
//! the loopback battery drives it through the adapter over a real TLS
//! connection. A fake per site is how two sites come to disagree about
//! what the seam does, and neither one's tests can see it.
//!
//! It is a second IMPLEMENTATION rather than a script — it answers out
//! of `BTreeMap`s and is held to the pinned semantics by the shared
//! conformance bodies in `granary_core::testkit`, the same bodies the
//! production adapter, core's own fakes and the simulator's store run,
//! so a rule that holds in one implementation and not another cannot
//! pass at every site.
//!
//! So it is deliberately minimal and deliberately dumb: `BTreeMap`s
//! behind a `Mutex`, with no knowledge of the protocol it is being
//! driven through. If this file stops compiling, the seam has stopped
//! being a seam.
//!
//! **Both seam traits are RPITIT and therefore dyn-incompatible**,
//! so every route to it is by generic bound; `&dyn
//! RootStore` is not available and that is expected.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Mutex;

use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::root::VolumeName;
use granary_core::rootstore::{HintRead, HintToken, RootStore, RootStoreError, filter_above};

/// What the fake holds for one volume's hint.
#[derive(Clone, Debug)]
struct Hint {
    /// The seq the hint names.
    seq: u64,
    /// How many times this volume's hint has been WRITTEN — the counter
    /// [`HINT_TOKEN_STEM`] mints the opaque entity-tag from.
    writes: u64,
    /// A version token planted VERBATIM, which `read_hint` answers with
    /// in place of the minted one.
    ///
    /// `None` is the ordinary case and the only one `write_hint` can
    /// produce. It exists because a store's token is opaque and its
    /// SHAPE is the store's business: a mint that counts writes can
    /// never produce a tag carrying obs-text, and a test that needs a
    /// server holding one has no protocol request that would create it.
    planted: Option<String>,
}

/// A second implementation of both seams, entirely in memory.
///
/// It knows the semantics `RootStore` and `BinStore` pin and nothing
/// else — no protocol, no HTTP, no idea which handler is calling.
#[derive(Debug, Default)]
pub(crate) struct FakeSeam {
    bins: Mutex<BTreeMap<[u8; DIGEST_LEN], Vec<u8>>>,
    meta: Mutex<BTreeMap<(String, GrainId), Vec<u8>>>,
    roots: Mutex<BTreeMap<(String, u64), Vec<u8>>>,
    hints: Mutex<BTreeMap<String, Hint>>,
}

/// The stem every entity-tag this fake mints carries: the token is
/// `"{HINT_TOKEN_STEM}{writes}"`, quoted, where `writes` is how many
/// times that volume's hint has been written.
///
/// **The write count is the point, and the stem is not.** Besides the
/// token itself, all a handler has is the volume and the seq; what it
/// never sees is how many times the store has been written. So a hint
/// written TWICE TO THE SAME SEQ mints two different tokens against a
/// request a handler cannot tell apart, and any `ETag` it computed for
/// itself — from the seq, from the volume, from a constant — is the same
/// string across both. That is what
/// `seam_drivable`'s revalidation test drives, and it is what forbids a
/// seq-derived validator: not one arithmetic relation, but every rule
/// that reaches its answer without the token.
///
/// The stem only raises the floor: no arithmetic on a seq produces this
/// string, so a fabrication has to hardcode it. It does not close
/// anything on its own, and no assertion on a SINGLE observed token
/// could — one value is always reproducible by a constant, and a
/// constant is a function of the seq like any other.
///
/// Minting a fresh token for an unchanged seq is a fidelity choice the
/// contract permits rather than one it requires: [`HintToken`] is opaque
/// and echoed verbatim, and §5.8 constrains only that it MUST change
/// when the seq does. A generation-numbered backend behaves this way; a
/// content-hashed entity-tag would not.
pub(crate) const HINT_TOKEN_STEM: &str = "seam-fake-hint-";

impl FakeSeam {
    /// How many objects the fake holds, across every map it has.
    ///
    /// `0` is the whole of the claim "nothing was written"; reading one
    /// key back is not. A handler that accepted a mismatched payload and
    /// stored it under the payload's own re-hashed digest writes a key
    /// no probe would think to read, and a `put_root` that stored before
    /// answering `413` and a `put_meta` that stored before answering
    /// `400` write two different maps.
    ///
    /// **What a LENGTH cannot see: a `write_hint` that MOVED an existing
    /// hint.** An insert over an occupied key leaves `len()` unchanged,
    /// so this count alone does not exclude that route; the
    /// content-sensitive guard is the scripted fake's CALL LIST, which
    /// records every seam invocation — a routed write shows up there
    /// whatever it did to the maps.
    ///
    /// A poisoned lock counts as `usize::MAX` and never as empty: the
    /// one answer this must not get wrong is "there is nothing here".
    pub(crate) fn objects(&self) -> usize {
        fn count<K, V>(map: &Mutex<BTreeMap<K, V>>) -> usize {
            map.lock().map_or(usize::MAX, |map| map.len())
        }
        count(&self.bins)
            .saturating_add(count(&self.meta))
            .saturating_add(count(&self.roots))
            .saturating_add(count(&self.hints))
    }

    /// Plant a hint at `seq` whose version token is `token` VERBATIM.
    ///
    /// **Test control, not a seam operation**, and it exists for the one
    /// thing no request can ask for: the SHAPE of the store's opaque
    /// token. `write_hint` mints `"{HINT_TOKEN_STEM}{writes}"`, which is
    /// always ASCII, so a server holding a tag with obs-text inside its
    /// quotes is unreachable through the protocol — and that is exactly
    /// the store a lossy-decoding adapter would answer a false `304`
    /// against.
    ///
    /// It counts as a write, so the mint's counter still moves and a
    /// later `write_hint` cannot mint a token this volume already
    /// handed out.
    pub(crate) fn plant_hint(&self, volume: &str, seq: u64, token: &str) {
        // Fail LOUD on a poisoned lock, exactly as `objects()` refuses
        // to answer a count it cannot trust: a plant that silently
        // no-ops arms nothing, and the row that believed it planted a
        // fixture then fails pointing at the server instead of here.
        let mut hints = self
            .hints
            .lock()
            .expect("the hints lock is poisoned; the fixture cannot arm");
        {
            let writes = hints.get(volume).map_or(1, |hint| hint.writes + 1);
            hints.insert(
                volume.to_owned(),
                Hint {
                    seq,
                    writes,
                    planted: Some(token.to_owned()),
                },
            );
        }
    }
}

fn poisoned<T>(_: T) -> RootStoreError {
    RootStoreError::Backend("fake seam mutex poisoned".to_owned())
}

/// The name→key boundary is a CONTRACT obligation on every
/// implementation, not the adapter's private business: a fake
/// that skips it accepts names production refuses, and that divergence
/// is invisible to tests either side writes for itself.
fn checked(volume: &str) -> Result<(), RootStoreError> {
    VolumeName::from_bytes(volume.as_bytes())
        .map(|_| ())
        .map_err(|error| RootStoreError::InvalidVolume {
            reason: error.to_string(),
        })
}

impl BinStore for FakeSeam {
    async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        // The content-address contract, asserted the way core's own
        // `FakeBins` and the `granary-store` adapter both assert it. The
        // trait makes it a MAY rather than a MUST, so this is fidelity
        // and not conformance — and what it buys is that "the handler
        // verifies the address ABOVE the seam" stops being an argument
        // and becomes a checked property: a handler that dropped its
        // check reaches this line with a mismatched pair.
        debug_assert_eq!(*GrainId::of(&bytes).digest(), *digest);
        let mut bins = self.bins.lock().map_err(poisoned)?;
        match bins.entry(*digest) {
            // Content-addressed: an occupant holds the same bytes, so
            // this is success reporting "not novel", never an error.
            Entry::Occupied(_) => Ok(false),
            Entry::Vacant(slot) => {
                slot.insert(bytes);
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
        checked(volume)?;
        // The same MAY on the other addressed object (§5.3), asserted
        // where the `granary-store` adapter asserts it and for the same
        // reason as `put_bin` above.
        debug_assert_eq!(GrainId::of(&bytes), *id);
        let mut meta = self.meta.lock().map_err(poisoned)?;
        match meta.entry((volume.to_owned(), *id)) {
            Entry::Occupied(_) => Ok(false),
            Entry::Vacant(slot) => {
                slot.insert(bytes);
                Ok(true)
            }
        }
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
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
        let end = offset
            .checked_add(u64::from(len))
            .ok_or(RootStoreError::RangeOverflow)?;
        let bins = self.bins.lock().map_err(poisoned)?;
        let bytes = bins.get(digest).ok_or(RootStoreError::NotFound)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        // A range starting at or past the end, or spanning nothing, is a
        // backend range error and never an empty success. Clamping these
        // is the divergence that makes a fake accept extents production
        // refuses, which is the half a whole-object read cannot see.
        if start >= bytes.len() || len == 0 {
            return Err(RootStoreError::Backend(
                "invalid range: starts at or past the end of the object".to_owned(),
            ));
        }
        // Only the END is clamped: the start is in bounds above, so an
        // overhanging range short-reads the tail that is there.
        let stop = usize::try_from(end).unwrap_or(usize::MAX).min(bytes.len());
        Ok(bytes.get(start..stop).unwrap_or_default().to_vec())
    }
}

impl RootStore for FakeSeam {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        checked(volume)?;
        let mut roots = self.roots.lock().map_err(poisoned)?;
        match roots.entry((volume.to_owned(), seq)) {
            // Put-if-absent, and the property is not the error: a
            // last-writer-wins store answers the same `AlreadyExists`
            // and breaks the append-only chain anyway.
            Entry::Occupied(_) => Err(RootStoreError::AlreadyExists),
            Entry::Vacant(slot) => {
                slot.insert(bytes);
                Ok(())
            }
        }
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        checked(volume)?;
        Ok(self
            .roots
            .lock()
            .map_err(poisoned)?
            .get(&(volume.to_owned(), seq))
            .cloned())
    }

    /// The token is minted QUOTED, the way S3 and `MinIO` hand an
    /// entity-tag back, and that is load-bearing rather than cosmetic.
    /// The server tries a store's token verbatim before quoting it
    /// (§5.8, §6), so against a bare-token store the value a client
    /// echoes is not the value the store holds, no `If-None-Match` can
    /// revalidate, and §5.8's `304` is unreachable end to end.
    ///
    /// Nothing here derives the token from the seq — it is
    /// [`HINT_TOKEN_STEM`] over the volume's WRITE COUNT — and the test
    /// checks that rather than asserting it: a hint rewritten to the
    /// same seq mints a new token where a seq-derived scheme would mint
    /// the one it minted before.
    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        checked(volume)?;
        let hints = self.hints.lock().map_err(poisoned)?;
        match hints.get(volume) {
            // Seq 0 names a root that cannot exist, so a hint of 0 is
            // the same answer as no hint at all.
            None => Ok(HintRead::Missing),
            Some(hint) if hint.seq == 0 => Ok(HintRead::Missing),
            Some(hint) => {
                let token = HintToken(hint.planted.clone().unwrap_or_else(|| {
                    format!("\"{HINT_TOKEN_STEM}{writes}\"", writes = hint.writes)
                }));
                if cached == Some(&token) {
                    Ok(HintRead::NotModified)
                } else {
                    Ok(HintRead::Current {
                        seq: hint.seq,
                        token,
                    })
                }
            }
        }
    }

    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        checked(volume)?;
        let mut hints = self.hints.lock().map_err(poisoned)?;
        // Every write mints a new token, a rewrite to the same seq
        // included: what a handler sees is unchanged there, and the
        // store's answer is not.
        let writes = hints.get(volume).map_or(1, |hint| hint.writes + 1);
        hints.insert(
            volume.to_owned(),
            Hint {
                seq,
                writes,
                planted: None,
            },
        );
        Ok(())
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        checked(volume)?;
        Ok(self
            .roots
            .lock()
            .map_err(poisoned)?
            .keys()
            .filter(|(name, _)| name == volume)
            .map(|(_, seq)| *seq)
            // Numeric, and neither end of the range is ever a head: a
            // root planted at seq 0 would block the first publish to a
            // fresh volume forever, and one planted at the RESERVED
            // u64::MAX would block every publish to it.
            .filter(|&seq| seq != 0 && seq != u64::MAX)
            .max())
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}
