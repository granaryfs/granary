// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a volume's root chain says, verified from the head down to seq 1.
//!
//! **A valid root** at seq `s` passes [`check_head`] under the volume's
//! publisher keys (strict decode, the volume, `s`, and a verifying slot
//! from the set), and then its root chain is walked down to seq 1: each
//! ancestor is **re-read from the store**, and [`check_link`] holds the
//! child's parent id to the id of the bytes stored there and those bytes
//! to a strict root of this volume at that seq; the root at seq 1 names no
//! parent. Ancestors' signatures are not checked: the head's signature
//! covers its parent id, which binds every ancestor transitively. No
//! content object is read. Classification uses this full walk.
//!
//! **Head resolution** can stop at the worker's in-memory anchor when
//! the stored bytes there still have the anchor's id and the link into
//! them verifies. It then checks one more ancestor per resolution, with
//! the cursor working down to seq 1 before starting another pass. Damage
//! below the anchor can go unnoticed until that read or a full walk.
//! The anchor is empty after a start and after a publication wedge.
//!
//! **How a walk fails.** A missing ancestor, one that fails its link, or a
//! size-cap refusal at any seq the walk reads makes the root **not
//! valid**. Any other failed read says nothing about validity: the root is
//! **unread**. Head resolution answers both as a damaged volume (spec §3
//! rule 6); a classification read answers the first as a wedge and the
//! second as unresolved (spec §4.2).

use granary_core::authority_answer::next_seq;
use granary_core::hash::GrainId;
use granary_core::root::{VolumeName, check_link};
use granary_core::rootstore::{RefusalKind, RootStore, RootStoreError};
use granary_store::crypto::{TrustedKeys, check_head};

use super::content::store::{Admission, max_seq};
use super::content::{ValidationAttempt, ValidationError, ValidationObject};

/// A chain head: its seq and the id of the bytes stored there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadRef {
    /// The head's seq.
    pub head_seq: u64,
    /// The id of the root stored at `head_seq`.
    pub head_id: GrainId,
}

/// A verified chain head (spec §4.5), and the seq a candidate on top of
/// it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedHead {
    /// The head's seq and stored id; `None` for a volume with no root.
    pub head: Option<HeadRef>,
    /// The seq a candidate extending this head carries; `None` when no
    /// seq above the head can be published.
    pub next_seq: Option<u64>,
}

impl VerifiedHead {
    /// The verified head `head` (`None` for an empty chain) and its next
    /// seq.
    #[must_use]
    pub fn new(head: Option<HeadRef>) -> Self {
        Self {
            head,
            next_seq: next_seq(head.map(|h| h.head_seq)),
        }
    }

    /// Whether a candidate at `seq` naming `parent` extends this head:
    /// its seq is the next seq, and its parent is the head's stored id
    /// (no parent over an empty chain).
    pub(crate) fn extended_by(&self, seq: u64, parent: Option<GrainId>) -> bool {
        self.next_seq == Some(seq) && parent == self.head.map(|h| h.head_id)
    }
}

/// The head of the worker's latest successful resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Anchor {
    seq: u64,
    id: GrainId,
    parent: Option<GrainId>,
}

/// One root read, with the anchor's id when the read was at the anchor's
/// seq and the stored id still matched it.
struct AnchorRead {
    bytes: Vec<u8>,
    matched: Option<GrainId>,
}

/// A volume worker's in-memory head verification state.
#[derive(Debug, Default)]
pub(crate) struct ChainMemo {
    anchor: Option<Anchor>,
    /// The slow walk's next read: a seq below the anchor, and the id the
    /// root above it names.
    cursor: Option<(u64, GrainId)>,
}

impl ChainMemo {
    pub(super) fn established(head: HeadRef, parent: Option<GrainId>) -> Self {
        Self {
            anchor: Some(Anchor {
                seq: head.head_seq,
                id: head.head_id,
                parent,
            }),
            cursor: None,
        }
    }

    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    /// Read the root at `seq` and report the anchor's id if it matches
    /// the stored id at that seq.
    ///
    /// A definitive miss or changed id at the anchor ends its use even
    /// when a subsequent head or link check fails. A failed read alone
    /// does not change what is known.
    async fn read_at<S: RootStore>(
        &mut self,
        source: &mut ChainSource<'_, S>,
        volume: &VolumeName,
        seq: u64,
    ) -> Result<AnchorRead, Unverified> {
        let read = source.read(volume, seq).await;
        let anchor = self.anchor.filter(|anchor| anchor.seq == seq);
        let matched = match (anchor, &read) {
            (Some(anchor), Ok(bytes)) if GrainId::of(bytes) == anchor.id => Some(anchor.id),
            (Some(_), Ok(_) | Err(Unverified::Invalid)) => {
                self.clear();
                None
            }
            _ => None,
        };
        read.map(|bytes| AnchorRead { bytes, matched })
    }

    /// Check one ancestor below a matched anchor and return the next
    /// cursor. An unread result leaves the pass at the same seq.
    async fn slow_step<S: RootStore>(
        &self,
        source: &mut ChainSource<'_, S>,
        volume: &VolumeName,
        anchor: Anchor,
    ) -> Result<Option<(u64, GrainId)>, Unverified> {
        if anchor.seq == 1 {
            return Ok(None);
        }
        // The matched anchor passed the parent rule when it was set.
        let (seq, id) = self
            .cursor
            .or_else(|| anchor.parent.map(|parent| (anchor.seq - 1, parent)))
            .ok_or(Unverified::Invalid)?;
        let bytes = source.read(volume, seq).await?;
        let ancestor =
            check_link(Some(id), &bytes, volume.as_str(), seq).map_err(|_| Unverified::Invalid)?;
        if (seq == 1) != ancestor.parent.is_none() {
            return Err(Unverified::Invalid);
        }
        Ok(ancestor.parent.map(|parent| (seq - 1, parent)))
    }
}

/// Why a root chain did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unverified {
    /// Not a valid root: its own check, a link, a missing ancestor or a
    /// size-cap refusal.
    Invalid,
    /// A read failed with something that says nothing about validity.
    Unread,
    /// Admission exhausted work before establishing the head.
    WorkLimit,
    /// The bounded attempt could not finish its reads.
    Unavailable,
}

struct ChainSource<'a, S> {
    store: &'a S,
    admission: Option<(&'a Admission, &'a mut ValidationAttempt)>,
}

impl<S: RootStore> ChainSource<'_, S> {
    async fn read(&mut self, volume: &VolumeName, seq: u64) -> Result<Vec<u8>, Unverified> {
        match self.admission.as_mut() {
            Some((source, attempt)) => attempt
                .read(*source, ValidationObject::Root(volume, seq), false)
                .await
                .map_err(|error| Self::from_validation(error, attempt)),
            None => read_present(self.store, volume, seq).await,
        }
    }

    async fn listed(
        &mut self,
        volume: &VolumeName,
        floor: Option<u64>,
    ) -> Result<Option<u64>, Unverified> {
        if let Some((source, attempt)) = self.admission.as_mut() {
            return max_seq(source, attempt, volume, floor)
                .await
                .map_err(|error| Self::from_validation(error, attempt));
        }
        match floor {
            Some(floor) => self.store.max_seq_above(volume.as_str(), floor).await,
            None => self.store.max_seq(volume.as_str()).await,
        }
        .map_err(|_| Unverified::Unread)
    }

    fn from_validation(error: ValidationError, attempt: &ValidationAttempt) -> Unverified {
        match error {
            ValidationError::WorkLimit | ValidationError::LengthLimit => Unverified::WorkLimit,
            ValidationError::Unavailable if attempt.expired() => Unverified::Unavailable,
            ValidationError::Unavailable => Unverified::Unread,
            ValidationError::InvalidReference | ValidationError::MissingReference => {
                Unverified::Invalid
            }
        }
    }
}

/// Whether `e` is the one read refusal that proves the object at the seq
/// is not a legal root: larger than the root format's own cap.
const fn over_cap(e: &RootStoreError) -> bool {
    matches!(
        e,
        RootStoreError::RefusedResponse {
            kind: RefusalKind::OverCap,
            ..
        }
    )
}

/// Read the root at `seq`: its bytes, [`Unverified::Invalid`] for nothing
/// there or a size-cap refusal, [`Unverified::Unread`] for any other
/// failure.
async fn read_present<S: RootStore>(
    store: &S,
    volume: &VolumeName,
    seq: u64,
) -> Result<Vec<u8>, Unverified> {
    match store.get_root(volume.as_str(), seq).await {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(Unverified::Invalid),
        Err(e) if over_cap(&e) => Err(Unverified::Invalid),
        Err(_) => Err(Unverified::Unread),
    }
}

/// Walk the root chain below a root at `seq` whose parent id is
/// `parent`, re-reading ancestors down to seq 1 or stopping at a
/// matching anchor after its link verifies (module docs).
async fn walk<S: RootStore>(
    source: &mut ChainSource<'_, S>,
    volume: &VolumeName,
    seq: u64,
    parent: Option<GrainId>,
    mut memo: Option<&mut ChainMemo>,
) -> Result<(), Unverified> {
    let mut parent = parent;
    let mut at = seq;
    while at > 1 {
        at -= 1;
        // A root above seq 1 with no parent fails before its ancestor is
        // read: no stored bytes can match an absent id.
        let Some(expected) = parent else {
            return Err(Unverified::Invalid);
        };
        let AnchorRead { bytes, matched } = if let Some(memo) = memo.as_deref_mut() {
            memo.read_at(source, volume, at).await?
        } else {
            AnchorRead {
                bytes: source.read(volume, at).await?,
                matched: None,
            }
        };
        let ancestor = check_link(Some(expected), &bytes, volume.as_str(), at)
            .map_err(|_| Unverified::Invalid)?;
        if matched.is_some() {
            return Ok(());
        }
        parent = ancestor.parent;
    }
    // Parentless iff seq 1: the root at seq 1, the head itself or the
    // last ancestor walked, names no parent.
    if parent.is_some() {
        return Err(Unverified::Invalid);
    }
    Ok(())
}

/// Check the head under `keys` and its links down to seq 1 or a
/// matching anchor. `matched` carries the result of the head read's
/// anchor comparison and allows the walk to be skipped on a match.
/// Return the head's parsed parent.
///
/// # Errors
/// [`Unverified`].
async fn verify_root<S: RootStore>(
    source: &mut ChainSource<'_, S>,
    volume: &VolumeName,
    keys: &TrustedKeys,
    seq: u64,
    bytes: &[u8],
    matched: bool,
    memo: &mut ChainMemo,
) -> Result<Option<GrainId>, Unverified> {
    let doc = check_head(bytes, volume.as_str(), seq, keys).map_err(|_| Unverified::Invalid)?;
    if !matched {
        walk(source, volume, seq, doc.parent, Some(memo)).await?;
    }
    Ok(doc.parent)
}

/// The volume's verified head (spec §4.5): the chain's highest seq as the
/// store lists it, never the advisory hint. Re-read its chain down to
/// seq 1 or through the anchor and one further ancestor. An empty chain
/// verifies with no head and leaves the memo empty.
///
/// # Errors
/// The head does not verify: the listing or a read failed, nothing is at
/// the listed seq, or the root there is not valid. Spec §3 rule 6 answers
/// every one as a damaged volume.
pub(crate) async fn resolve_head<S: RootStore>(
    store: &S,
    volume: &VolumeName,
    keys: &TrustedKeys,
    memo: &mut ChainMemo,
) -> Result<VerifiedHead, Unverified> {
    resolve_head_for_admission(store, volume, keys, memo, None).await
}

pub(super) async fn resolve_head_for_admission<S: RootStore>(
    store: &S,
    volume: &VolumeName,
    keys: &TrustedKeys,
    memo: &mut ChainMemo,
    admission: Option<(&Admission, &mut ValidationAttempt)>,
) -> Result<VerifiedHead, Unverified> {
    let mut source = ChainSource { store, admission };
    let work = async {
        let bounded = if let Some(anchor) = memo.anchor {
            let listed = source.listed(volume, Some(anchor.seq - 1)).await?;
            if listed.is_none() {
                memo.clear();
            }
            listed
        } else {
            None
        };
        let head_seq = if let Some(seq) = bounded {
            seq
        } else {
            let Some(seq) = source.listed(volume, None).await? else {
                return Ok(VerifiedHead::new(None));
            };
            seq
        };
        let AnchorRead { bytes, matched } = memo.read_at(&mut source, volume, head_seq).await?;
        let parent = verify_root(
            &mut source,
            volume,
            keys,
            head_seq,
            &bytes,
            matched.is_some(),
            memo,
        )
        .await?;
        let cursor = if let Some(anchor) = memo.anchor {
            match memo.slow_step(&mut source, volume, anchor).await {
                Ok(cursor) => cursor,
                Err(Unverified::Invalid) => {
                    memo.clear();
                    return Err(Unverified::Invalid);
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let head_id = matched.unwrap_or_else(|| GrainId::of(&bytes));
        *memo = ChainMemo {
            anchor: Some(Anchor {
                seq: head_seq,
                id: head_id,
                parent,
            }),
            cursor,
        };
        Ok(VerifiedHead::new(Some(HeadRef { head_seq, head_id })))
    };
    #[cfg(test)]
    let work = tracing::Instrument::instrument(
        work,
        tracing::trace_span!("authority_chain", phase = "resolve_head"),
    );
    work.await
}

/// What one classification read found at an entry's seq (spec §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Classification {
    /// The entry's recorded final bytes.
    Landed,
    /// A valid root that extends the recorded base; `occupant` is its
    /// stored id.
    Lost { occupant: GrainId },
    /// Anything else there: an object that is not a valid root, one off
    /// the recorded base, or a size-cap refusal at the seq or an
    /// ancestor.
    Wedged,
    /// Nothing there, or a read of the seq or of an ancestor failed.
    Unresolved,
}

/// One classification read of `seq`, judged against the entry's recorded
/// final bytes and recorded base (spec §4.2). Only the recorded bytes are
/// landed; only a valid root whose parent is the recorded base (no parent
/// at seq 1) is lost. A root off the base wedges without its chain being
/// walked: no ancestor can make it lost.
pub(crate) async fn classify_seq<S: RootStore>(
    store: &S,
    volume: &VolumeName,
    keys: &TrustedKeys,
    seq: u64,
    base: Option<GrainId>,
    final_bytes: &[u8],
) -> Classification {
    let work = async {
        let bytes = match store.get_root(volume.as_str(), seq).await {
            Ok(Some(bytes)) => bytes,
            Err(e) if over_cap(&e) => return Classification::Wedged,
            Ok(None) | Err(_) => return Classification::Unresolved,
        };
        if bytes == final_bytes {
            return Classification::Landed;
        }
        let Ok(doc) = check_head(&bytes, volume.as_str(), seq, keys) else {
            return Classification::Wedged;
        };
        if doc.parent != base {
            return Classification::Wedged;
        }
        let mut source = ChainSource {
            store,
            admission: None,
        };
        match walk(&mut source, volume, seq, doc.parent, None).await {
            Ok(()) => Classification::Lost {
                occupant: GrainId::of(&bytes),
            },
            Err(Unverified::Invalid) => Classification::Wedged,
            Err(_) => Classification::Unresolved,
        }
    };
    #[cfg(test)]
    let work = tracing::Instrument::instrument(
        work,
        tracing::trace_span!("authority_chain", phase = "classify_seq"),
    );
    work.await
}

#[cfg(test)]
pub(super) mod tests;
