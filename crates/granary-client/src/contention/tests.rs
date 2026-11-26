// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

struct Random;
impl granary_core::secure_random::SecureRandom for Random {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        bytes.fill(1);
        Ok(())
    }
}

fn exported(metrics: &ClientMetrics) -> String {
    metrics.snapshot().unwrap().render_prometheus().unwrap()
}

#[test]
fn contention_threshold_accepts_finite_rates_and_refuses_invalid_values() {
    let mut cases = 0;
    for value in ["0.249", "0.25", "0.251", "1"] {
        let actual = ContentionThreshold::parse(value);
        assert!(actual.is_ok(), "{value}: {actual:?}");
        cases += 1;
    }
    for value in [
        "0", "-0", "NaN", "inf", "-inf", "-0.01", "1.01", "", "garbage",
    ] {
        assert_eq!(
            ContentionThreshold::parse(value).unwrap_err().to_string(),
            "--contention-rate needs a finite rate greater than 0 and at most 1",
            "{value}"
        );
        cases += 1;
    }
    assert_eq!(cases, 13);
}

#[test]
fn contention_window_requires_four_outcomes_then_evicts_and_restarts_empty() {
    let mut cases = 0;
    for (label, rate, expected) in [
        ("just above rate", "0.249", true),
        ("exact rate", "0.25", true),
        ("just below rate", "0.251", false),
    ] {
        let metrics = ClientMetrics::new(&mut Random);
        let mut window = Window::default();
        window.set_threshold(ContentionThreshold::parse(rate).unwrap());
        for result in [CommitResult::Exhausted, CommitResult::Ok, CommitResult::Ok] {
            window.record(result, Some(&metrics));
            assert_eq!(
                (
                    window.decision,
                    exported(&metrics).contains("granary_client_contention_flag")
                ),
                (None, false),
                "{label}: {}",
                exported(&metrics)
            );
        }
        window.record(CommitResult::Ok, Some(&metrics));
        assert_eq!(
            (
                window.observed,
                window.outcomes.count_ones(),
                window.decision
            ),
            (4, 1, Some(expected)),
            "{label}"
        );
        for _ in 0..13 {
            window.record(CommitResult::Ok, Some(&metrics));
        }
        assert_eq!(
            (
                window.observed,
                window.outcomes.count_ones(),
                window.decision
            ),
            (16, 0, Some(false)),
            "{label}"
        );
        let restarted = Window::default();
        let fresh_metrics = ClientMetrics::new(&mut Random);
        restarted.publish(&fresh_metrics);
        assert_eq!(
            (
                restarted.observed,
                restarted.decision,
                exported(&fresh_metrics).contains("granary_client_contention_flag")
            ),
            (0, None, false),
            "{label}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}
