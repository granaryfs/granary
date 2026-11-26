// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The re-issue delay: bounded, growing to its cap, and fixed by a seed.

use granary_sim::rng::Rng as SimRng;

use super::*;

/// Each delay lies in the upper half of its ceiling, the ceiling doubles
/// from the base per re-issue and stops at the cap, and a seed fixes
/// every value.
#[test]
fn the_delay_grows_to_its_cap_with_jitter_from_the_seam() {
    let mut rng = SimRng::seeded(1, 1);
    for reissue in 0..40_u64 {
        let ceiling = REISSUE_BASE
            .saturating_mul(1_u32 << reissue.min(16))
            .min(REISSUE_CAP);
        let delay = reissue_delay(reissue, &mut rng);
        assert!(delay <= ceiling, "{reissue}: {delay:?} over {ceiling:?}");
        assert!(delay >= ceiling / 2, "{reissue}: {delay:?} under half");
    }
    assert!(reissue_delay(u64::MAX, &mut rng) <= REISSUE_CAP);
    let draws = |seed| {
        let mut rng = SimRng::seeded(seed, 1);
        (0..8)
            .map(|n| reissue_delay(n, &mut rng))
            .collect::<Vec<_>>()
    };
    assert_eq!(draws(5), draws(5));
    assert_ne!(draws(5), draws(6));
}
