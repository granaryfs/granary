// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::cache::space` — the free-space
//! determinism seam (the `Clock`/`Rng` shape applied to a kernel
//! interface `granary-core`'s purity gate forbids).
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

/// This module's own fixed free-space-reading test double.
struct FixedReading(FreeSpaceInfo);

impl FreeSpace for FixedReading {
    fn free_space(&self) -> io::Result<FreeSpaceInfo> {
        Ok(self.0)
    }
}

#[test]
fn a_small_capacity_uses_a_capacity_relative_watermark() {
    let capacity_bytes = WATERMARK_MIN_BYTES / 2;
    let write_len = 64;
    let empty = FixedReading(FreeSpaceInfo {
        free_bytes: capacity_bytes,
        capacity_bytes,
    });
    assert!(
        free_space_precheck(&empty, write_len),
        "an empty sub-1-GiB filesystem must have room for a small cache write"
    );

    let percentage_watermark = capacity_bytes / WATERMARK_PERCENT_DIVISOR;
    let full = FixedReading(FreeSpaceInfo {
        free_bytes: percentage_watermark
            .saturating_add(write_len)
            .saturating_sub(1),
        capacity_bytes,
    });
    assert!(
        !free_space_precheck(&full, write_len),
        "control: a small filesystem with less than its 5% reserve after the write must \
         still refuse it"
    );
}
