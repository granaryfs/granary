// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::projection::base;
use super::*;
use granary_core::support::{BundleOverlay, BundleRefusal};
use std::collections::BTreeSet;

fn refusal_literals(source: &str, marker: &str, found: &mut BTreeSet<String>) {
    let mut remainder = source;
    while let Some((_, after_marker)) = remainder.split_once(marker) {
        let after_marker = after_marker.trim_start();
        if let Some(quoted) = after_marker.strip_prefix('"')
            && let Some(end) = quoted.find('"')
        {
            found.insert(quoted[..end].to_owned());
        }
        remainder = after_marker.get(1..).unwrap_or_default();
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "the test inventories the crate's checked-in Rust sources"
)]
fn rust_sources(path: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(path).unwrap_or_else(|error| panic!("{path:?}: {error}")) {
        let path = entry.unwrap_or_else(|error| panic!("{error}")).path();
        if path.is_dir() {
            if path.file_name().is_none_or(|name| name != "tests") {
                rust_sources(&path, found);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && path.file_name().is_none_or(|name| name != "tests.rs")
        {
            found.push(path);
        }
    }
}

#[test]
fn bundle_projection_preserves_every_scalar_without_io() {
    let mut f = Fixture::with_base(
        vec![base("a", 2), base("b", 3), base("c", 4)],
        Source::default(),
    );
    f.create();
    f.overlay.config.cap = 1_000_000;
    f.overlay.summary = OverlaySummary {
        records: 7,
        charged_bytes: 11,
        reserved_bytes: 13,
        orphan_bytes: 17,
        captured_bytes: 19,
        swept_files: 23,
        swept_bytes: 29,
        commit_requested: true,
        ..OverlaySummary::default()
    };
    f.overlay.journal.get_mut().unwrap().length = 31;
    let trace = f.io.0.lock().unwrap().trace.clone();
    let mut cases = 0;
    for (readiness, tag) in [
        (OverlayReadiness::PendingReconciliation, 1),
        (OverlayReadiness::PendingRecovery, 2),
        (OverlayReadiness::Ready, 3),
        (OverlayReadiness::Poisoned, 4),
    ] {
        f.overlay.readiness = readiness;
        for commit_state in 0..=2 {
            let commits = &mut f.overlay.journal.get_mut().unwrap().completion.commits;
            commits.clear();
            if commit_state != 0 {
                commits.insert(
                    1,
                    CompletionSlot {
                        landed: (commit_state == 2).then(|| grain(3)),
                        ..CompletionSlot::default()
                    },
                );
            }
            let expected = BundleOverlay {
                readiness: tag,
                commit_state,
                namespace_entries: 5,
                free_entries: 26,
                cap: 1_000_000,
                staged_files: 1,
                journal_records: 7,
                charged_bytes: 11,
                reserved_bytes: 13,
                orphan_bytes: 17,
                captured_bytes: 19,
                swept_files: 23,
                swept_bytes: 29,
                journal_bytes: 31,
                commit_requested: true,
            };
            assert_eq!(f.overlay.bundle_projection(), Ok(expected));
            let bytes = f.overlay.bundle_projection().unwrap().encode().unwrap();
            assert_eq!(
                (bytes.len(), granary_core::support::BUNDLE_OVERLAY_MAX),
                (99, 256)
            );
            assert_eq!(BundleOverlay::decode(&bytes).unwrap(), expected);
            cases += 1;
        }
    }
    f.overlay.readiness = OverlayReadiness::Ready;
    let mut retained = f.overlay.bundle_projection();
    let mut poisoned = retained.unwrap();
    poisoned.readiness = 4;
    OverlayError::Poisoned.invalidate_bundle(&mut retained);
    assert_eq!(retained, Ok(poisoned));
    OverlayError::Io(io::Error::other("unreadable")).invalidate_bundle(&mut retained);
    OverlayError::Poisoned.invalidate_bundle(&mut retained);
    assert_eq!(retained, Err(BundleRefusal::Unreadable));
    OverlayError::ContentCorrupt.invalidate_bundle(&mut retained);
    OverlayError::NoSpace.invalidate_bundle(&mut retained);
    assert_eq!(retained, Err(BundleRefusal::Corrupt));
    f.overlay.summary.commit_requested = false;
    assert!(!f.overlay.bundle_projection().unwrap().commit_requested);
    f.overlay.replayed = false;
    assert_eq!(
        f.overlay.bundle_projection(),
        Err(BundleRefusal::Unavailable)
    );
    assert_eq!((cases, f.io.0.lock().unwrap().trace.clone()), (12, trace));
}

#[test]
fn bundle_projection_refuses_swallowed_settlement_failure() {
    let mut f = Fixture::new();
    assert!(f.overlay.bundle_projection().is_ok());
    f.io.0.lock().unwrap().fail = Some("entries");
    f.overlay.note_capacity_refusal();
    assert_eq!(
        (f.overlay.bundle_projection(), f.io.0.lock().unwrap().fail),
        (Err(BundleRefusal::Unreadable), None)
    );
}

#[test]
fn recorded_damage_is_not_downgraded_by_routine_failures() {
    let mut cases = 0;
    for (damage, refusal) in [
        (
            OverlayError::Io(io::Error::other("unreadable")),
            BundleRefusal::Unreadable,
        ),
        (OverlayError::ContentCorrupt, BundleRefusal::Corrupt),
    ] {
        let mut f = Fixture::new();
        f.overlay.record_bundle_failure(&damage);
        for routine in [
            OverlayError::NoSpace,
            OverlayError::Conflict,
            OverlayError::ContentUnavailable,
            OverlayError::Refused("create destination exists"),
        ] {
            f.overlay.record_bundle_failure(&routine);
            assert_eq!(
                f.overlay.bundle_failure(),
                Some(refusal),
                "routine failure downgraded recorded damage"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 8);
}

#[test]
fn journal_fenced_latches_corrupt() {
    let f = Fixture::new();
    let mut retained = f.overlay.bundle_projection();
    OverlayError::Refused("journal fenced").invalidate_bundle(&mut retained);
    assert_eq!(retained, Err(BundleRefusal::Corrupt));
}

#[test]
fn routine_refusal_literal_keeps_projection_refreshable() {
    let f = Fixture::new();
    let expected = f.overlay.bundle_projection();
    let mut retained = expected;
    OverlayError::Refused("create destination exists").invalidate_bundle(&mut retained);
    assert_eq!(retained, expected);
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the test inventories the crate's checked-in Rust sources"
)]
fn every_overlay_refusal_literal_has_exactly_one_bundle_class() {
    let groups = super::super::bundle::REFUSAL_GROUPS;
    assert_eq!(
        groups
            .iter()
            .map(|(refusal, _)| *refusal)
            .collect::<Vec<_>>(),
        vec![
            Some(BundleRefusal::Corrupt),
            Some(BundleRefusal::Unreadable),
            None,
        ],
        "bundle refusal table must retain damage, unreadable and routine groups"
    );
    let mut classified = BTreeSet::new();
    for (_, reasons) in groups {
        for reason in *reasons {
            assert!(
                classified.insert((*reason).to_owned()),
                "refusal literal appears in more than one group: {reason}"
            );
        }
    }

    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let mut paths = Vec::new();
    rust_sources(&source_root, &mut paths);
    let mut source = BTreeSet::new();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let relative = path
            .strip_prefix(&source_root)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        if relative == std::path::Path::new("overlay_store.rs")
            || relative.starts_with("overlay_store")
        {
            refusal_literals(&text, "refused(", &mut source);
        } else {
            refusal_literals(&text, "OverlayError::refused(", &mut source);
            refusal_literals(&text, "OverlayError::Refused(", &mut source);
        }
    }
    assert!(
        source.contains("journal fenced") && source.contains("create destination exists"),
        "source scan missed its damage or routine positive control: {source:?}"
    );
    let unclassified = source.difference(&classified).cloned().collect::<Vec<_>>();
    let stale = classified.difference(&source).cloned().collect::<Vec<_>>();
    assert_eq!(
        (unclassified, stale, source.len()),
        (Vec::<String>::new(), Vec::<String>::new(), classified.len()),
        "every production refusal literal must occur in exactly one bundle group"
    );
}
