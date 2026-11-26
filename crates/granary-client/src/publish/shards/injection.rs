// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Test-only final-byte corruption bound to one captured base and load mode.

use super::{Build, GrainId, PublishError, State, binmap};
use std::cell::Cell;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Corruption {
    Slot,
    DropEntry,
}
#[derive(Debug, Clone, Copy)]
struct Selection {
    base: GrainId,
    full: bool,
    corruption: Corruption,
}
std::thread_local! {
    static SELECTED: Cell<Option<Selection>> = const { Cell::new(None) };
}
#[derive(Debug)]
pub(crate) struct Guard(Option<Selection>);
impl Drop for Guard {
    fn drop(&mut self) {
        SELECTED.set(self.0);
    }
}
pub(crate) fn arm(base: GrainId, full: bool, corruption: Corruption) -> Guard {
    Guard(SELECTED.replace(Some(Selection {
        base,
        full,
        corruption,
    })))
}
/// Carry the selected final-byte fault into a blocking worker.
pub(crate) fn capture() -> impl FnOnce() -> Guard + Send {
    let selected = SELECTED.get();
    move || Guard(SELECTED.replace(selected))
}
pub(in crate::publish) fn apply(state: &State, built: &mut Build) -> Result<(), PublishError> {
    let Some(selection) = SELECTED.get() else {
        return Ok(());
    };
    if state.parent != Some(selection.base) || state.full != selection.full {
        return Ok(());
    }
    let invalid = || PublishError::BinmapConstruction;
    let mut index = binmap::decode_binmap_index(&built.index_bytes).map_err(|_| invalid())?;
    let at = built
        .shards
        .iter()
        .find_map(|(at, (_, bytes))| {
            binmap::decode_shard(bytes)
                .ok()
                .filter(|entries| !entries.is_empty())
                .map(|_| *at)
        })
        .ok_or_else(invalid)?;
    match selection.corruption {
        Corruption::Slot => {
            if index.shards.len() < 2 {
                return Err(invalid());
            }
            let next = (at + 1) % index.shards.len();
            index.shards.swap(at, next);
        }
        Corruption::DropEntry => {
            let (_, bytes) = built.shards.get(&at).ok_or_else(invalid)?;
            let mut entries = binmap::decode_shard(bytes).map_err(|_| invalid())?;
            entries.pop().ok_or_else(invalid)?;
            let bytes = binmap::encode_shard(&entries)?;
            let id = GrainId::of(&bytes);
            built.shards.insert(at, (id, bytes));
            *index.shards.get_mut(at).ok_or_else(invalid)? = id;
        }
    }
    built.index_bytes =
        binmap::encode_binmap_index(index.prefix_bits, index.bin_table, &index.shards)?;
    built.index_id = GrainId::of(&built.index_bytes);
    Ok(())
}
