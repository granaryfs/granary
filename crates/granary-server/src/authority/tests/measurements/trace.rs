// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complete client attempts and conservative byte-credit checks for serial cadence.

use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub(super) struct Attempt {
    pub index: usize,
    pub send_ns: u128,
    pub end_ns: u128,
    pub publication: usize,
    pub operation: String,
    pub volume: String,
    pub status: u16,
    pub token: String,
    pub body_bytes: usize,
}
impl Attempt {
    pub(super) fn json(&self) -> String {
        // Identities and outcome tokens have restricted wire grammars; the
        // validator refuses delimiters before this serializer is called.
        format!(
            "{{\"attempt\":{},\"send_ns\":{},\"end_ns\":{},\"publication\":{},\"operation\":\"{}\",\"volume\":\"{}\",\"status\":{},\"token\":\"{}\",\"body_bytes\":{}}}",
            self.index,
            self.send_ns,
            self.end_ns,
            self.publication,
            self.operation,
            self.volume,
            self.status,
            self.token,
            self.body_bytes
        )
    }
}

pub(super) fn checked_trace(
    attempts: &[Attempt],
    submissions: usize,
    refused: usize,
    completed: usize,
    tuple: &str,
) -> Result<(), &'static str> {
    if attempts.is_empty() || completed == 0 {
        return Err("empty attempt population");
    }
    if attempts.len() != submissions || attempts.iter().enumerate().any(|(i, a)| a.index != i) {
        return Err("missing attempt in trace");
    }
    if attempts.iter().filter(|a| a.status == 429).count() != refused {
        return Err("trace 429 count mismatch");
    }
    let mut successes = BTreeSet::new();
    let (_, _, byte_rate, byte_burst, cap) = crate::ControlsConfig::parse(tuple)
        .map_err(|_| "invalid experimental tuple")?
        .tuple();
    let mut credit = u128::from(byte_burst) * 1_000_000_000;
    let mut last_send = 0;
    let mut previous_completion = 0;
    for a in attempts {
        if a.send_ns < previous_completion || a.end_ns < a.send_ns {
            return Err("non-monotonic or overlapping attempt time");
        }
        if a.operation.is_empty()
            || a.volume.is_empty()
            || [&a.operation, &a.volume, &a.token]
                .iter()
                .any(|s| s.contains(['"', '\\', '\t', '\n', '\r']))
        {
            return Err("invalid attempt identity or token");
        }
        if ![200, 202, 429].contains(&a.status) {
            return Err("unsuccessful cadence attempt");
        }
        if a.publication >= completed {
            return Err("trace completed population mismatch");
        }
        if a.status != 429 {
            successes.insert(a.publication);
        }
        if cap <= 1 || a.body_bytes == 0 || a.body_bytes as u64 > granary_core::root::ROOT_MAX_BYTES
        {
            return Err("cadence byte or cap premise failed");
        }
        // Debit every offered body at send time, including 429 bodies. This
        // overstates server consumption and gives it no extra network refill.
        credit = credit
            .saturating_add((a.send_ns - last_send).saturating_mul(u128::from(byte_rate)))
            .min(u128::from(byte_burst) * 1_000_000_000);
        let cost = a.body_bytes as u128 * 1_000_000_000;
        if cost > credit {
            return Err("cadence byte bucket could bind");
        }
        credit -= cost;
        last_send = a.send_ns;
        previous_completion = a.end_ns;
    }
    if successes.len() != completed {
        return Err("trace completed population mismatch");
    }
    Ok(())
}

pub(super) fn checked_label(label: &str, tuple: &str) -> Result<(), &'static str> {
    match label {
        "defaults" if tuple != super::rows::DEFAULT => Err("shipped control tuple mismatch"),
        "positive_control" if tuple != super::rows::POSITIVE_CONTROL => {
            Err("positive control tuple mismatch")
        }
        "demand" if tuple != super::rows::RAISED => Err("demand tuple is not non-binding control"),
        "defaults" | "positive_control" | "demand" | "acceptance" => Ok(()),
        _ => Err("invalid cadence label"),
    }
}
pub(super) fn checked_outcome(label: &str, refused: usize) -> Result<(), &'static str> {
    if label == "positive_control" {
        if refused == 0 {
            return Err("positive control did not reproduce 429");
        }
    } else if refused != 0 {
        return Err("cadence produced 429");
    }
    Ok(())
}

#[test]
fn authority_measurement_cadence_label_controls() {
    use super::rows::{DEFAULT, POSITIVE_CONTROL, RAISED};
    assert_eq!(
        crate::ControlsConfig::default().tuple(),
        (46, 5, 33_554_432, 268_435_456, 4)
    );
    for (label, tuple, refused) in [
        ("defaults", DEFAULT, 0),
        ("positive_control", POSITIVE_CONTROL, 1),
        ("demand", RAISED, 0),
        ("acceptance", "8,2,33554432,268435456,4", 0),
    ] {
        assert_eq!(checked_label(label, tuple), Ok(()));
        assert_eq!(checked_outcome(label, refused), Ok(()));
    }
    let cases = [
        ("defaults", RAISED, "shipped control tuple mismatch"),
        (
            "defaults",
            POSITIVE_CONTROL,
            "shipped control tuple mismatch",
        ),
        (
            "positive_control",
            DEFAULT,
            "positive control tuple mismatch",
        ),
        ("demand", DEFAULT, "demand tuple is not non-binding control"),
        ("invalid", DEFAULT, "invalid cadence label"),
    ];
    assert!(!cases.is_empty());
    for (label, tuple, message) in cases {
        assert_eq!(checked_label(label, tuple), Err(message));
    }
    assert_eq!(
        checked_outcome("positive_control", 0),
        Err("positive control did not reproduce 429")
    );
    for label in ["defaults", "demand", "acceptance"] {
        assert_eq!(checked_outcome(label, 1), Err("cadence produced 429"));
    }
    assert_eq!(cases.len(), 5, "cadence label named refusal cases");
}

#[test]
fn authority_measurement_attempt_trace_controls() {
    use super::rows::DEFAULT;
    let valid = vec![Attempt {
        index: 0,
        send_ns: 0,
        end_ns: 1,
        publication: 0,
        operation: "01".into(),
        volume: "v".into(),
        status: 202,
        token: String::new(),
        body_bytes: 200,
    }];
    assert_eq!(checked_trace(&valid, 1, 0, 1, DEFAULT), Ok(()));
    let mut cases = vec![
        (Vec::new(), 0, 0, 0, DEFAULT, "empty attempt population"),
        (valid.clone(), 2, 0, 1, DEFAULT, "missing attempt in trace"),
        (valid.clone(), 1, 1, 1, DEFAULT, "trace 429 count mismatch"),
        (
            valid.clone(),
            1,
            0,
            2,
            DEFAULT,
            "trace completed population mismatch",
        ),
        (
            valid.clone(),
            1,
            0,
            1,
            "4,4,33554432,268435456,1",
            "cadence byte or cap premise failed",
        ),
        (valid.clone(), 1, 0, 1, "bad", "invalid experimental tuple"),
    ];
    for (mut wrong, message) in [
        (valid.clone(), "missing attempt in trace"),
        (valid.clone(), "non-monotonic or overlapping attempt time"),
        (valid.clone(), "invalid attempt identity or token"),
        (valid.clone(), "unsuccessful cadence attempt"),
        (valid.clone(), "cadence byte or cap premise failed"),
        (valid.clone(), "trace completed population mismatch"),
    ] {
        let a = wrong.first_mut().unwrap();
        match message {
            "missing attempt in trace" => a.index = 1,
            "non-monotonic or overlapping attempt time" => a.send_ns = 2,
            "invalid attempt identity or token" => a.operation = "\"".into(),
            "unsuccessful cadence attempt" => a.status = 0,
            "cadence byte or cap premise failed" => a.body_bytes = 65_537,
            _ => a.publication = 1,
        }
        cases.push((wrong, 1, 0, 1, DEFAULT, message));
    }
    let byte_trace: Vec<_> = (0..4097)
        .map(|i| Attempt {
            index: i,
            publication: i,
            end_ns: 0,
            body_bytes: 65_536,
            ..valid.first().unwrap().clone()
        })
        .collect();
    cases.push((
        byte_trace,
        4097,
        0,
        4097,
        "4,4,1,268435456,4",
        "cadence byte bucket could bind",
    ));
    assert!(!cases.is_empty());
    for (trace, sent, refused, completed, tuple, message) in &cases {
        assert_eq!(
            checked_trace(trace, *sent, *refused, *completed, tuple),
            Err(*message)
        );
    }
    assert!(!cases.is_empty(), "attempt trace named refusal cases");
}
