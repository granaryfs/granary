// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::oracle::{answers, directory, names};
use super::*;

fn entries() -> Vec<OverlayEntry> {
    vec![directory("z"), directory("a"), directory("z/child")]
}

fn permute(f: &mut Fixture) -> Vec<(Vec<Name>, u64)> {
    let paths: Vec<_> = f.overlay.namespace.entries.keys().cloned().collect();
    for (offset, path) in paths.iter().enumerate() {
        f.overlay
            .namespace
            .assign_inode(path, 101 + u64::try_from(offset).unwrap())
            .unwrap();
    }
    f.overlay
        .namespace
        .entries
        .iter()
        .map(|(p, e)| (p.clone(), e.inode))
        .collect()
}

fn identities(f: &Fixture) -> Vec<(Vec<Name>, u64)> {
    f.overlay
        .namespace
        .entries
        .iter()
        .map(|(p, e)| (p.clone(), e.inode))
        .collect()
}

fn assert_changed_assignments(f: &Fixture, retained: &[(Vec<Name>, u64)]) {
    let assigned = Namespace::base(&f.overlay.base).unwrap();
    let changed = retained
        .iter()
        .filter(|(path, inode)| {
            assigned
                .entries
                .get(path)
                .is_some_and(|entry| entry.inode != *inode)
        })
        .count();
    assert_eq!(
        (retained.len(), changed),
        (3, 3),
        "actual retained/assigned differences: {retained:?}, assigned={:?}",
        assigned.entries
    );
}

fn assert_sticky_refusal(f: &mut Fixture) {
    let path = names("z");
    let inode = f.overlay.namespace.entries.get(&path).unwrap().inode;
    f.overlay
        .namespace
        .inject_inverse_reference(inode, names("a"));
    let first = f
        .overlay
        .query_path(&f.store, &f.owner, &path)
        .err()
        .map(|e| e.to_string());
    let second = f
        .overlay
        .query_inode(&f.store, &f.owner, inode)
        .err()
        .map(|e| e.to_string());
    assert_eq!(
        (first, second, f.overlay.readiness()),
        (
            Some("overlay persistence poisoned".into()),
            Some("overlay persistence poisoned".into()),
            OverlayReadiness::Poisoned,
        )
    );
}

#[test]
fn base_rebuild_admits_every_assigned_identity() {
    let result = Namespace::base(&entries());
    assert_eq!(
        result
            .as_ref()
            .map(|ns| ns.entries.len())
            .map_err(ToString::to_string),
        Ok(3),
        "base admission must rebuild before service"
    );
    let mut ns = result.unwrap();
    let expected: Vec<_> = ns.entries.values().cloned().collect();
    for entry in &expected {
        assert_eq!(ns.query_inode(entry.inode).unwrap(), Some(entry));
    }
    assert_eq!(
        expected.len(),
        3,
        "nonzero base associations: {}",
        expected.len()
    );
    let first = expected.first().unwrap();
    ns.inject_inverse_reference(first.inode, names("missing"));
    assert_eq!(
        ns.query_inode(first.inode).err().map(|e| e.to_string()),
        Some("overlay persistence poisoned".into())
    );
    eprintln!("base routes=1; assigned associations=3; malformed refusals=1");
}

#[test]
fn replay_rebuild_preserves_changed_identities_before_service() {
    let mut f = Fixture::with_base(entries(), Source::default());
    let retained = permute(&mut f);
    assert_changed_assignments(&f, &retained);
    let before = answers(&mut f);
    assert_eq!(before, Ok([3, 3, 3, 4, 4]));
    let result = f.overlay.recover(&mut f.store, &f.owner, &mut f.source);
    assert_eq!(
        (result.err().map(|e| e.to_string()), f.overlay.readiness()),
        (None, OverlayReadiness::Ready),
        "replay rebuild must finish before service"
    );
    assert_eq!((identities(&f), answers(&mut f)), (retained, before));
    assert_sticky_refusal(&mut f);
    eprintln!(
        "replay routes=1; changed assigned/preserved identities=3; malformed sticky refusals=1"
    );
}

#[test]
fn landed_rebuild_preserves_changed_identities_before_service() {
    let mut f = Fixture::with_base(entries(), Source::default());
    let retained = permute(&mut f);
    assert_changed_assignments(&f, &retained);
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let result = f.overlay.replace_landed(&mut f.store, &f.owner, proof);
    assert_eq!(
        (result.err().map(|e| e.to_string()), f.overlay.readiness()),
        (None, OverlayReadiness::Ready),
        "landed rebuild must finish before service"
    );
    assert_eq!(
        (identities(&f), answers(&mut f)),
        (retained, Ok([3, 3, 3, 4, 4]))
    );
    assert_sticky_refusal(&mut f);
    eprintln!(
        "landed routes=1; changed assigned/preserved identities=3; malformed sticky refusals=1"
    );
}

#[test]
fn rejected_rebuild_preserves_changed_identities_before_service() {
    let mut f = Fixture::with_base(entries(), Source::default());
    let retained = permute(&mut f);
    assert_changed_assignments(&f, &retained);
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    let boundary = f
        .overlay
        .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
        .unwrap();
    let result = f
        .overlay
        .replace_rejected(&mut f.store, &f.owner, boundary, [7; 16]);
    assert_eq!(
        (result.err().map(|e| e.to_string()), f.overlay.readiness()),
        (None, OverlayReadiness::Ready),
        "rejected rebuild must finish before service"
    );
    assert_eq!(
        (identities(&f), answers(&mut f)),
        (retained, Ok([3, 3, 3, 4, 4]))
    );
    assert_sticky_refusal(&mut f);
    eprintln!(
        "rejected routes=1; changed assigned/preserved identities=3; malformed sticky refusals=1"
    );
}

fn assert_early_preservation_refusal(
    f: &mut Fixture,
    install: impl FnOnce(&mut Fixture) -> Result<(), OverlayError>,
) {
    let retained = permute(f);
    assert_changed_assignments(f, &retained);
    assert_eq!(answers(f), Ok([3, 3, 3, 4, 4]));
    let valid = f.overlay.namespace.clone();
    let duplicate = f.overlay.namespace.entries.get(&names("a")).unwrap().inode;
    f.overlay
        .namespace
        .entries
        .get_mut(&names("z"))
        .unwrap()
        .inode = duplicate;
    let malformed = identities(f);
    let distinct = malformed
        .iter()
        .map(|(_, inode)| inode)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        (malformed.len(), distinct.len(), f.overlay.readiness()),
        (3, 2, OverlayReadiness::Ready),
        "actual preserved-identity fault premise: {malformed:?}"
    );
    let mut candidate = Namespace::base(&f.overlay.base).unwrap();
    assert_eq!(
        candidate
            .preserve_inodes(&f.overlay.namespace, &BTreeMap::new())
            .err()
            .map(|e| e.to_string()),
        Some("overlay persistence poisoned".into()),
        "malformed preservation must fail rebuilding before installation"
    );
    let journal = f.io.bytes(&f.overlay.journal_path());
    let result = install(f);
    assert_eq!(
        (result.err().map(|e| e.to_string()), f.overlay.readiness()),
        (
            Some("overlay persistence poisoned".into()),
            OverlayReadiness::Poisoned
        ),
        "replacement must poison at the preservation error before any service query"
    );
    assert_eq!(
        (identities(f), f.io.bytes(&f.overlay.journal_path())),
        (malformed, journal),
        "failed image must not publish or switch the canonical journal"
    );
    assert_repaired_namespace_refuses(f, valid, duplicate);
    eprintln!(
        "replacement routes=1; primary identities=3; differing assignments=3; early rebuild faults=1; repaired sticky refusals=2"
    );
}

fn assert_repaired_namespace_refuses(f: &mut Fixture, valid: Namespace, inode: u64) {
    f.overlay.namespace = valid;
    assert_eq!(
        (
            f.overlay
                .query_path(&f.store, &f.owner, &names("z"))
                .err()
                .map(|e| e.to_string()),
            f.overlay
                .query_inode(&f.store, &f.owner, inode)
                .err()
                .map(|e| e.to_string()),
            f.overlay.readiness()
        ),
        (
            Some("overlay persistence poisoned".into()),
            Some("overlay persistence poisoned".into()),
            OverlayReadiness::Poisoned
        ),
        "repairing the fault must not admit service without recovery"
    );
}

#[test]
fn landed_preservation_rebuild_error_poisons_before_service() {
    let mut f = Fixture::with_base(entries(), Source::default());
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    assert_early_preservation_refusal(&mut f, |f| {
        f.overlay
            .replace_landed(&mut f.store, &f.owner, proof)
            .map(|_| ())
    });
}

#[test]
fn rejected_preservation_rebuild_error_poisons_before_service() {
    let mut f = Fixture::with_base(entries(), Source::default());
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    let boundary = f
        .overlay
        .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
        .unwrap();
    assert_early_preservation_refusal(&mut f, |f| {
        f.overlay
            .replace_rejected(&mut f.store, &f.owner, boundary, [7; 16])
    });
}
