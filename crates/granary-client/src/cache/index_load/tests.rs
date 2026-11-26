// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::cache::index_load` — index recovery: the bounded
//! readers, the per-entry admission rule, the capped walk and the two load
//! paths.
//!
//! Out-of-line, beside its child. It carries the
//! file-scoped `#![cfg(test)]` shield the fsguard
//! scanner needs at this depth, and NO `#![expect]`:
//! the one row the caller map gives this child
//! round-trips a byte string and touches no filesystem.

#![cfg(test)]

use super::*;

#[test]
fn an_empty_journal_round_trips_through_decode_journal() {
    let bytes = empty_journal_bytes();
    let (records, tail) = cacheindex::decode_journal(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(records, Vec::new());
    assert_eq!(tail, JournalTail::CleanEof);
}
