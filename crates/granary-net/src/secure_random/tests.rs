// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use granary_core::secure_random::SecureRandom;

use super::OsSecureRandom;

/// Two 16-byte draws differ, and neither is the untouched buffer: the
/// fill reads a generator, not a constant. Catches an implementation
/// that returns `Ok` without writing, or one that restarts a fixed
/// stream per handle.
#[test]
fn two_handles_draw_two_distinct_full_width_values() {
    let mut first = [0u8; 16];
    let mut second = [0u8; 16];
    OsSecureRandom::new().fill(&mut first).unwrap();
    OsSecureRandom::new().fill(&mut second).unwrap();
    assert_ne!(first, [0u8; 16], "first draw untouched: {first:?}");
    assert_ne!(second, [0u8; 16], "second draw untouched: {second:?}");
    assert_ne!(first, second, "two draws repeated: {first:?}");
}
