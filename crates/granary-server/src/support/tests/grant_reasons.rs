// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{Incarnation, SupportSnapshot, Timestamp, snapshot_from_observation, source};
use crate::{
    debug_grant::{clock::ClockFailure, reader::Reason},
    diagnostics::{CaptureError, CaptureUnsupported},
};
use std::collections::BTreeSet;

// The same arms enumerate samples and require exhaustive enum coverage.
macro_rules! reason_cases {
    ($kind:ty; $($pattern:pat => $values:expr),+ $(,)?) => {{
        let classify = |value: $kind| match value {
            $($pattern => stringify!($pattern)),+
        };
        let mut samples = Vec::new();
        $(
            let cases: Vec<$kind> = $values;
            assert!(!cases.is_empty(), "no samples for {}", stringify!($pattern));
            for value in cases {
                assert_eq!(classify(value), stringify!($pattern));
                samples.push(value);
            }
        )+
        samples
    }};
}

fn enum_reasons() -> BTreeSet<&'static str> {
    let clocks = reason_cases!(ClockFailure;
        ClockFailure::UnsupportedProfile => vec![ClockFailure::UnsupportedProfile],
        ClockFailure::Source => vec![ClockFailure::Source],
        ClockFailure::Overflow => vec![ClockFailure::Overflow],
    );
    let unsupported = reason_cases!(CaptureUnsupported;
        CaptureUnsupported::ContextualCeiling => vec![CaptureUnsupported::ContextualCeiling],
        CaptureUnsupported::Ceiling => vec![CaptureUnsupported::Ceiling],
        CaptureUnsupported::Instrumentation => vec![CaptureUnsupported::Instrumentation],
        CaptureUnsupported::Producer => vec![CaptureUnsupported::Producer],
        CaptureUnsupported::Clock => vec![CaptureUnsupported::Clock],
    );
    let captures = reason_cases!(CaptureError;
        CaptureError::StaleRevision => vec![CaptureError::StaleRevision],
        CaptureError::Unsupported(_) => unsupported.into_iter().map(CaptureError::Unsupported).collect(),
        CaptureError::InvalidEntries => vec![CaptureError::InvalidEntries],
        CaptureError::RetiredSlot => vec![CaptureError::RetiredSlot],
        CaptureError::NonMonotonicSlot => vec![CaptureError::NonMonotonicSlot],
        CaptureError::LeaseMismatch => vec![CaptureError::LeaseMismatch],
        CaptureError::Poisoned => vec![CaptureError::Poisoned],
        CaptureError::RevisionOverflow => vec![CaptureError::RevisionOverflow],
    );
    let reasons = reason_cases!(Reason;
        Reason::Missing => vec![Reason::Missing],
        Reason::Unreadable => vec![Reason::Unreadable],
        Reason::Stalled => vec![Reason::Stalled],
        Reason::Unprotected => vec![Reason::Unprotected],
        Reason::Oversize => vec![Reason::Oversize],
        Reason::Corrupt => vec![Reason::Corrupt],
        Reason::Directory => vec![Reason::Directory],
        Reason::StaleIncarnation => vec![Reason::StaleIncarnation],
        Reason::FutureIssued => vec![Reason::FutureIssued],
        Reason::Expired => vec![Reason::Expired],
        Reason::Rollback => vec![Reason::Rollback],
        Reason::RevisionConflict => vec![Reason::RevisionConflict],
        Reason::Widening => vec![Reason::Widening],
        Reason::Retired => vec![Reason::Retired],
        Reason::Revoked => vec![Reason::Revoked],
        Reason::Clock(_) => clocks.iter().copied().map(Reason::Clock).collect(),
        Reason::Capture(_) => captures.into_iter().map(Reason::Capture).collect(),
        Reason::SlotOverflow => vec![Reason::SlotOverflow],
    );
    assert_eq!(reasons.len(), 31, "nonempty exhaustive enum samples");
    reasons
        .into_iter()
        .map(Reason::as_str)
        .chain(clocks.into_iter().map(ClockFailure::as_str))
        .collect()
}

fn snapshot_literals(reader: &'static str) -> Result<BTreeSet<&'static str>, &'static str> {
    let (_, observation) = reader
        .split_once("pub(crate) fn observation(&self)")
        .ok_or("reader observation missing")?;
    let (_, reason) = observation
        .split_once("let reason =")
        .ok_or("snapshot reason expression missing")?;
    let (expression, _) = reason
        .split_once("let snapshot =")
        .ok_or("snapshot construction missing")?;
    let mut parts = expression.split('"');
    let _prefix = parts.next();
    let mut reasons = BTreeSet::new();
    while let Some(literal) = parts.next() {
        let _after = parts.next().ok_or("unterminated reason literal")?;
        if literal.is_empty()
            || !literal
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        {
            return Err("invalid reason literal");
        }
        reasons.insert(literal);
    }
    if reasons.is_empty() {
        return Err("snapshot has no literal reasons");
    }
    Ok(reasons)
}

#[test]
fn support_grant_reader_reasons_round_trip() {
    let mut reasons = enum_reasons();
    reasons.extend(snapshot_literals(include_str!("../../debug_grant/reader.rs")).unwrap());
    assert_eq!(reasons.len(), 26, "all unique reader reasons are exercised");
    for reason in reasons {
        let mut observation = source();
        observation.debug_grant.as_mut().unwrap().reason = Some(reason);
        let projected = snapshot_from_observation(
            Incarnation::from_bytes([0x41; 16]),
            Timestamp { secs: 60, nanos: 0 },
            &observation,
        )
        .unwrap();
        let encoded = projected.encode();
        assert!(
            encoded.is_ok(),
            "reader reason {reason} must encode: {encoded:?}"
        );
        let bytes = encoded.unwrap();
        let decoded = SupportSnapshot::decode(&bytes).unwrap();
        assert_eq!((decoded.clone(), decoded.encode()), (projected, Ok(bytes)));
    }
}

#[test]
fn support_reader_reason_inventory_refuses_missing_source() {
    let valid =
        "pub(crate) fn observation(&self) {let reason = Some(\"expired\"); let snapshot = value;}";
    assert_eq!(snapshot_literals(valid), Ok(["expired"].into()));
    assert_eq!(
        snapshot_literals(include_str!("../../debug_grant/reader.rs")),
        Ok(["capture-refused", "expired"].into())
    );
    let cases = [
        ("", "reader observation missing"),
        (
            "pub(crate) fn observation(&self) {}",
            "snapshot reason expression missing",
        ),
        (
            "pub(crate) fn observation(&self) {let reason = None;}",
            "snapshot construction missing",
        ),
        (
            "pub(crate) fn observation(&self) {let reason = Some(\"expired); let snapshot = value;}",
            "unterminated reason literal",
        ),
        (
            "pub(crate) fn observation(&self) {let reason = None; let snapshot = value;}",
            "snapshot has no literal reasons",
        ),
        (
            "pub(crate) fn observation(&self) {let reason = Some(\"\"); let snapshot = value;}",
            "invalid reason literal",
        ),
    ];
    let mut count = 0;
    for (input, refusal) in cases {
        assert_eq!(snapshot_literals(input), Err(refusal), "source {input:?}");
        count += 1;
    }
    assert_eq!(count, 6, "nonempty malformed source controls");
}
