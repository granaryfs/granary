// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared integration-test support. Lives under `tests/`, NOT in the
//! library: `assert_golden` does real file and env I/O, and
//! granary-core's lib stays pure (no I/O — hard rule). It cannot hide
//! behind a feature either: the purity gate deliberately compiles the
//! lib with --all-features.

/// Golden-vector gate. Every
/// golden test funnels through here so the regen guard cannot be
/// forgotten per-file: `GRANARY_REGEN_VECTORS=1` rewrites the file
/// (refused under CI — regen is a deliberate local format event),
/// then the committed bytes must match exactly.
///
/// # Panics
/// On mismatch (a format event) or I/O failure.
pub(crate) fn assert_golden(path: &std::path::Path, actual: &str) {
    if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
        assert!(
            std::env::var_os("CI").is_none(),
            "refusing to regenerate golden vectors under CI — regen is a deliberate local format event"
        );
        std::fs::write(path, actual).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        eprintln!("regenerated {}", path.display());
    }
    let committed = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {} (regen locally first?): {e}", path.display()));
    assert_eq!(
        actual, committed,
        "golden vectors drifted — this is a FORMAT EVENT, not a test to update casually"
    );
}
