// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The bin/meta object contract. PURE:
//! no `object_store` types, no tokio, std only — the trait is what
//! granary-store implements and what the sim fakes.
//!
//! **Errors are [`RootStoreError`], not an enum of this module's own.**
//! Every method here already returns that type on the granary-store
//! side; a parallel enum would split the error surface — two names for
//! `NotFound`, two for `Backend` — and force a lossy conversion at the
//! one boundary that must not lose information, for no gain.
//!
//! Written DESUGARED — `fn … -> impl Future<Output = …> + Send` — for
//! three reasons: bare `async fn` in a public trait trips the
//! warn-by-default `async_fn_in_trait` lint under CI's deny-warnings,
//! the sugared form cannot express `Send` on the returned future, and
//! AFIT needs no proc-macro, so core purity holds. The trait speaks
//! owned bytes and `&str` — no `object_store` type crosses this
//! boundary. RPITIT also makes it dyn-INcompatible, as with
//! [`crate::rootstore::RootStore`]: callers take `R: BinStore`, not
//! `&dyn BinStore`.
//!
//! **`checked_volume` is part of the CONTRACT, not of the adapter.**
//! The same volume-validation obligation binds `RootStore` and `BinStore`.
//! Every implementation — production adapter, test fake,
//! sim node — validates the volume name as a [`crate::root::VolumeName`]
//! (DNS-1123) BEFORE it becomes a key, because
//! `object_store::path::Path::from` normalises its input: `a/b`, `a//b`
//! and `a/b/` all address the SAME keyspace. The `&str` parameter is a
//! caller convenience, never a licence to trust. A fake that skips the
//! check accepts names production refuses — an accept-set divergence,
//! and a scenario that passes in the sim against a store that would
//! have rejected it proves nothing.
//!
//! **`get_bin` is deliberately absent.** Nothing calls it; whole-bin
//! reads land with the fetcher, and a trait method with no caller
//! cannot be tested for the property that matters.
//!
//! **[`BinStore::get_bin_range`]'s range semantic is PINNED** by that
//! method's docs, and it turns on where the range STARTS: a range
//! beginning inside the object may overhang the end and then
//! short-reads; a range beginning AT or PAST the end, or a zero-length
//! range, is a backend range error. Without pinning both halves, two
//! implementations legitimately differ — one short-reads, one 416s —
//! and the sim's oracle then agrees with the wrong one. The semantic is
//! the adapter's MEASURED behaviour, not an aspiration, and
//! granary-store's in-memory backend suite exercises all four
//! boundaries.
//!
//! **CANCELLATION SAFETY: none of these futures is cancel-safe, and
//! CONTENT-ADDRESSING is why that is survivable here.** A dropped
//! [`BinStore::put_bin`] or [`BinStore::put_meta`] may still land, and
//! the caller cannot tell — but the key is the hash of the bytes, so what
//! lands is exactly what a retry would write, and a retry sees at worst
//! `Ok(false)`. That is the whole difference from
//! [`crate::rootstore::RootStore::put_root`], where the seq is NOT
//! content-addressed and a dropped PUT leaves an ambiguity that only the
//! one-probe rule can resolve. Nothing on this trait needs a probe.
//!
//! The reads leave no state behind at all, so a cancelled read costs
//! only the work. Per-method sections state each case.
//!
//! **`AlreadyExists` is SUCCESS here.** These objects are
//! content-addressed, so an existing occupant holds the same bytes the
//! caller was about to write: [`BinStore::put_bin`] and
//! [`BinStore::put_meta`] answer `bool` — "was it novel" — and never
//! surface [`RootStoreError::AlreadyExists`]. That is the opposite of
//! `put_root`, where the seq is NOT content-addressed and an occupant is
//! the ambiguous outcome the one-probe rule resolves.

use crate::hash::{DIGEST_LEN, GrainId};
use crate::rootstore::RootStoreError;
use std::future::Future;

/// The bin/meta object contract granary-store implements.
pub trait BinStore: Send + Sync {
    /// Upload a bin if absent. `Ok(true)` when it was novel.
    ///
    /// The bin is addressed by `digest` alone — bins are global, not
    /// per-volume, so the same content uploaded from two volumes is one
    /// object.
    ///
    /// **CONTRACT: `digest` MUST be `blake3(bytes)`.** These objects are
    /// content-addressed, so a mismatched pair would store bytes under
    /// an id that does not name them — silently unresolvable later, and
    /// undetectable from the object alone. Implementations MAY
    /// `debug_assert` it (the granary-store adapter does); none is
    /// required to check it in release, so callers do not get to rely on
    /// being caught.
    ///
    /// # Cancellation safety
    /// NOT cancel-safe: a dropped future may still land the PUT. Harmless
    /// — the key is `blake3(bytes)`, so anything that lands is what a
    /// retry would write, and the retry answers `Ok(false)`. No probe is
    /// owed (see the module docs).
    ///
    /// # Errors
    /// [`RootStoreError::Backend`] on a transport or backend failure.
    /// An object already at the key is NOT an error (`Ok(false)`).
    fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<bool, RootStoreError>> + Send;

    /// Upload a meta object if absent. `Ok(true)` when it was novel.
    ///
    /// **CONTRACT: `id` MUST be `GrainId::of(&bytes)`** — the same
    /// content-address obligation as [`BinStore::put_bin`], for the same
    /// reason.
    ///
    /// # Errors
    /// [`RootStoreError::InvalidVolume`] when `volume` is not a valid
    /// [`crate::root::VolumeName`] — checked by the implementation, per
    /// the module docs, before the name becomes a key;
    /// [`RootStoreError::Backend`] on a transport or backend failure. An
    /// object already at the key is NOT an error (`Ok(false)`).
    ///
    /// # Cancellation safety
    /// NOT cancel-safe, and harmless for the same reason as
    /// [`BinStore::put_bin`]: the key is the content address, so a PUT
    /// that lands after a drop is byte-identical to the retry's.
    fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<bool, RootStoreError>> + Send;

    /// Fetch a meta object whole.
    ///
    /// # Errors
    /// [`RootStoreError::InvalidVolume`] for a name that never becomes a
    /// key; [`RootStoreError::NotFound`] when no such object exists;
    /// [`RootStoreError::RefusedResponse`] if the implementation bounds
    /// what it reads and the store's answer exceeded that bound;
    /// [`RootStoreError::Backend`] on a transport or backend failure.
    ///
    /// # Cancellation safety
    /// NOT cancel-safe — a dropped future abandons a partially read
    /// response — but it leaves no state behind and re-issuing is safe.
    fn get_meta(
        &self,
        volume: &str,
        id: &GrainId,
    ) -> impl Future<Output = Result<Vec<u8>, RootStoreError>> + Send;

    /// Fetch a byte range of a bin.
    ///
    /// **PINNED, and the boundary matters more than the common case.**
    /// The rule turns on where the range STARTS:
    ///
    /// - `offset < len(object)` — the range may overhang the end, and
    ///   then it SHORT-READS: the available tail is returned, FEWER
    ///   bytes than requested, never an error and never padding.
    ///   Callers needing the full extent check the returned length.
    /// - `offset >= len(object)`, or `len == 0` — a
    ///   [`RootStoreError::Backend`] range error (an implementation that
    ///   reaches its store over HTTP reports the server's refusal as
    ///   [`RootStoreError::UnexpectedStatus`]). There is no empty-read
    ///   success in this contract.
    ///
    /// The second bullet is the half that is easy to get wrong: an
    /// implementation that clamps everywhere and answers `Ok(vec![])`
    /// disagrees with the backend at exactly the offsets an adversarial
    /// extent produces. Both bullets are the ADAPTER's measured
    /// behaviour over `object_store` — `(90,50)` on a 100-byte bin
    /// yields 10 bytes, while `(200,8)`, `(100,8)` and `(10,0)` all
    /// yield `Invalid range` — and `granary-store`'s in-memory backend
    /// suite exercises all four.
    ///
    /// # Errors
    /// [`RootStoreError::RangeOverflow`] when `offset + len` overflows
    /// `u64` before any request reaches the backend (refused by checked
    /// arithmetic, not by panicking — `offset` may come from a decoded
    /// but adversarial extent); [`RootStoreError::NotFound`] when the
    /// bin does not exist; [`RootStoreError::RefusedResponse`] if the
    /// implementation checks the response against the extent it asked
    /// for and the answer was not one this request could have produced;
    /// [`RootStoreError::Backend`] for a range that
    /// starts at or past the end of the object, for `len == 0`, and on
    /// any transport or backend failure.
    ///
    /// # Cancellation safety
    /// NOT cancel-safe — a dropped future abandons a partially read
    /// response, and a PARTIAL extent is never an answer here: callers
    /// check the returned length against what they asked for, so a
    /// truncated read must be re-issued whole, never stitched.
    fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> impl Future<Output = Result<Vec<u8>, RootStoreError>> + Send;
}

#[cfg(test)]
mod tests;
