// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

mod corpus;
mod oracle;
mod publication;
mod rebuild;
mod terminal;

#[test]
fn stale_inode_association_refuses_service_and_stays_poisoned() {
    let mut f = Fixture::new();
    f.create();
    let valid = f.overlay.entries(&mut f.store, &f.owner).unwrap();
    assert_eq!(
        (valid.len(), f.overlay.readiness()),
        (1, OverlayReadiness::Ready)
    );
    f.overlay
        .namespace
        .entries
        .get_mut(&vec![name("f")])
        .unwrap()
        .inode += 1;
    let result = f.overlay.entries(&mut f.store, &f.owner);
    let observed = (result.err().map(|e| e.to_string()), f.overlay.readiness());
    assert_eq!(
        observed,
        (
            Some("overlay persistence poisoned".into()),
            OverlayReadiness::Poisoned
        )
    );
    assert!(matches!(
        f.overlay.entries(&mut f.store, &f.owner),
        Err(OverlayError::Poisoned)
    ));
}

#[test]
fn wrong_primary_path_refuses_service_and_stays_poisoned() {
    let mut f = Fixture::new();
    f.create();
    let valid = f.overlay.entries(&mut f.store, &f.owner).unwrap();
    assert_eq!(
        (valid.len(), f.overlay.readiness()),
        (1, OverlayReadiness::Ready)
    );
    f.overlay
        .namespace
        .entries
        .get_mut(&vec![name("f")])
        .unwrap()
        .path = vec![name("other")];
    let result = f.overlay.entries(&mut f.store, &f.owner);
    assert_eq!(
        (result.err().map(|e| e.to_string()), f.overlay.readiness()),
        (
            Some("overlay persistence poisoned".into()),
            OverlayReadiness::Poisoned
        )
    );
}

#[test]
fn inconsistent_candidate_poisons_without_publishing_or_appending() {
    let mut f = Fixture::new();
    f.create();
    let entries = f.overlay.entries(&mut f.store, &f.owner).unwrap();
    let journal = f.io.bytes(&f.overlay.journal_path());
    let mut candidate = f.overlay.namespace.clone();
    candidate.entries.get_mut(&vec![name("f")]).unwrap().inode += 1;
    let result = f.overlay.fold_candidate(
        &mut candidate,
        &Record::SetattrExec {
            at: at("f"),
            exec: true,
        },
    );
    assert_eq!(
        (
            result.err().map(|e| e.to_string()),
            f.overlay.readiness(),
            f.overlay
                .namespace
                .entries
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            f.io.bytes(&f.overlay.journal_path())
        ),
        (
            Some("overlay persistence poisoned".into()),
            OverlayReadiness::Poisoned,
            entries,
            journal
        )
    );
}
