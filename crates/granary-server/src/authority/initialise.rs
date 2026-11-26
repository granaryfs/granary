// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The shared initialise decision, independent of engine fencing and locking.

use granary_core::authlog::{Classified, EPOCH_LEN, Envelope, Epoch, classify};
use granary_core::root::VolumeName;
use granary_core::secure_random::SecureRandom;

use super::InitialiseError;

pub(crate) enum Prepared {
    Create(Envelope),
    Keep {
        envelope: Envelope,
        committed_len: usize,
        tail_len: usize,
    },
}

pub(crate) fn prepare(
    bytes: Option<&[u8]>,
    volume: &VolumeName,
    random: &mut impl SecureRandom,
) -> Result<Prepared, InitialiseError> {
    let Some(bytes) = bytes else {
        let mut draw = [0; EPOCH_LEN];
        random
            .fill(&mut draw)
            .map_err(|_| InitialiseError::EntropyUnavailable)?;
        return Ok(Prepared::Create(Envelope::new(
            volume.clone(),
            Epoch::from_bytes(draw),
        )));
    };
    match classify(bytes, volume).map_err(InitialiseError::Damaged)? {
        Classified::NoEnvelope => Err(InitialiseError::NoEnvelope),
        Classified::Log { records, .. } if !records.is_empty() => {
            Err(InitialiseError::LogHasRecords)
        }
        Classified::Log {
            envelope,
            committed_len,
            tail_len,
            ..
        } => Ok(Prepared::Keep {
            envelope,
            committed_len,
            tail_len,
        }),
    }
}
