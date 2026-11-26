// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn refusal_counters_remain_bounded() {
    let counters = RefusalCounters::default();
    assert_eq!(counters.totals.len(), 35);
    let p = |n: usize| PrincipalId::from_bytes((n as u128).to_be_bytes());
    for n in 0..PRINCIPALS_MAX {
        counters.record(ErrorToken::BadRequest, Some(p(n)));
    }
    // Updating the oldest row does not refresh its insertion age.
    counters.record(ErrorToken::RateLimited, Some(p(0)));
    counters.record(ErrorToken::NoPrincipal, None);
    counters.record(ErrorToken::BadRequest, Some(p(PRINCIPALS_MAX)));
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.principals.len(), PRINCIPALS_MAX);
    assert!(!snapshot.principals.contains_key(&p(0)));
    assert!(snapshot.principals.contains_key(&p(1)));
    assert_eq!(
        snapshot.totals[&ErrorToken::BadRequest],
        PRINCIPALS_MAX as u64 + 1
    );
    assert_eq!(snapshot.totals[&ErrorToken::RateLimited], 1);
    assert_eq!(snapshot.totals[&ErrorToken::NoPrincipal], 1);
    for n in PRINCIPALS_MAX + 1..=PRINCIPALS_MAX * 2 {
        counters.record(ErrorToken::BadRequest, Some(p(n)));
    }
    assert_eq!(counters.snapshot().principals.len(), PRINCIPALS_MAX);
    counters.totals[&ErrorToken::BadRequest].store(u64::MAX, Ordering::Relaxed);
    {
        let mut state = counters.principals.lock().unwrap();
        state
            .principals
            .get_mut(&p(PRINCIPALS_MAX + 1))
            .unwrap()
            .insert(ErrorToken::BadRequest, u64::MAX);
    }
    counters.record(ErrorToken::BadRequest, Some(p(PRINCIPALS_MAX + 1)));
    assert_eq!(
        counters.snapshot().totals[&ErrorToken::BadRequest],
        u64::MAX
    );
    assert_eq!(
        counters.snapshot().principals[&p(PRINCIPALS_MAX + 1)][&ErrorToken::BadRequest],
        u64::MAX
    );
}
