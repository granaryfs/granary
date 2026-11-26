// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn debug_grant_reader_counters_saturate() {
    let counters = Counters::default();
    for counter in [
        &counters.refreshes,
        &counters.reloads,
        &counters.refusals,
        &counters.unreadable,
        &counters.stalled,
        &counters.applications,
        &counters.retirements,
    ] {
        counter.store(u64::MAX, Ordering::Relaxed);
        increment(counter);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
