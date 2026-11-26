// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Full-walk reference for comparison with head resolution.

use super::super::*;

/// Walk the root chain below a root at `seq` whose parent id is
/// `parent`, re-reading every ancestor down to seq 1 (module docs).
async fn walk<S: RootStore>(
    store: &S,
    volume: &VolumeName,
    seq: u64,
    parent: Option<GrainId>,
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
        let bytes = read_present(store, volume, at).await?;
        let ancestor = check_link(Some(expected), &bytes, volume.as_str(), at)
            .map_err(|_| Unverified::Invalid)?;
        parent = ancestor.parent;
    }
    // Parentless iff seq 1: the root at seq 1, the head itself or the
    // last ancestor walked, names no parent.
    if parent.is_some() {
        return Err(Unverified::Invalid);
    }
    Ok(())
}

/// Whether `bytes`, read at `seq`, are a valid root of `volume` under
/// `keys` (module docs): the parsed root's parent on success.
///
/// # Errors
/// [`Unverified`].
pub(crate) async fn verify_root<S: RootStore>(
    store: &S,
    volume: &VolumeName,
    keys: &TrustedKeys,
    seq: u64,
    bytes: &[u8],
) -> Result<Option<GrainId>, Unverified> {
    let doc = check_head(bytes, volume.as_str(), seq, keys).map_err(|_| Unverified::Invalid)?;
    walk(store, volume, seq, doc.parent).await?;
    Ok(doc.parent)
}

/// The volume's verified head (spec §4.5): the chain's highest seq as the
/// store lists it, never the advisory hint, read and verified as a valid
/// root. An empty chain verifies with no head.
///
/// # Errors
/// The head does not verify: the listing or a read failed, nothing is at
/// the listed seq, or the root there is not valid. Spec §3 rule 6 answers
/// every one as a damaged volume.
pub(crate) async fn resolve_head<S: RootStore>(
    store: &S,
    volume: &VolumeName,
    keys: &TrustedKeys,
) -> Result<VerifiedHead, Unverified> {
    let work = async {
        let listed = store
            .max_seq(volume.as_str())
            .await
            .map_err(|_| Unverified::Unread)?;
        let Some(head_seq) = listed else {
            return Ok(VerifiedHead::new(None));
        };
        let bytes = read_present(store, volume, head_seq).await?;
        verify_root(store, volume, keys, head_seq, &bytes).await?;
        Ok(VerifiedHead::new(Some(HeadRef {
            head_seq,
            head_id: GrainId::of(&bytes),
        })))
    };
    #[cfg(test)]
    let work = tracing::Instrument::instrument(
        work,
        tracing::trace_span!("authority_chain", phase = "resolve_head"),
    );
    work.await
}
