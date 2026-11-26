// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::oracle::{directory, names};
use super::*;
use crate::overlay_store::{OverlayQuery, OverlayQueryEntry};
use granary_fuse::{Callback, CallbackObserver as _, CallbackOutcome, MountError, WriteError};

fn query(f: &mut Fixture, callback: Callback, inode: u64) -> Result<(), OverlayError> {
    let path = names("d/file");
    let expected = OverlayQueryEntry {
        entry: f.overlay.namespace.entries.get(&path).cloned(),
        nlink: 1,
    };
    let answer = match callback {
        Callback::Lookup => {
            f.overlay
                .query_lookup(&f.store, &f.owner, &names("d"), &name("file"))?
        }
        Callback::Getattr => f.overlay.query_path(&f.store, &f.owner, &path)?,
        Callback::Readdir | Callback::Readdirplus => {
            let OverlayQuery::Found(directory) =
                f.overlay.query_directory(&f.store, &f.owner, &names("d"))?
            else {
                panic!("fixture directory must exist")
            };
            let OverlayQuery::Found(page) =
                f.overlay
                    .query_children(&f.store, &f.owner, &directory.cursor)?
            else {
                panic!("fixture page must exist")
            };
            assert_eq!(
                (
                    directory.directory.nlink,
                    directory.parent.nlink,
                    page.entries,
                    page.next.is_none()
                ),
                (2, 3, vec![expected], true)
            );
            return Ok(());
        }
        Callback::Read => {
            let observed = f.overlay.query_inode(&f.store, &f.owner, inode)?;
            assert_eq!(observed, OverlayQuery::Found(expected));
            let bytes = f
                .overlay
                .read_base(&mut f.store, &f.owner, &path, 0, 4, &mut f.source)?;
            assert_eq!(bytes, b"body");
            return Ok(());
        }
        actual => panic!("unexpected query callback: {actual:?}"),
    };
    assert_eq!(answer, OverlayQuery::Found(expected));
    Ok(())
}

fn counters(metrics: &crate::ClientMetrics, callback: Callback) -> (u64, u64) {
    let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
    let count = |outcome: &str| {
        let prefix = format!(
            "granary_client_fuse_requests_total{{callback=\"{}\",outcome=\"{outcome}\"}} ",
            callback.as_str()
        );
        text.lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    (count("ok"), count("failed"))
}

fn fault(callback: Callback) {
    let mut source = Source::default();
    source.0.insert(GrainId::of(b"body"), b"body".to_vec());
    let mut file = directory("d/file");
    file.kind = OverlayKind::File {
        content: Some(GrainId::of(b"body")),
    };
    file.size = 4;
    let mut f = Fixture::with_base(vec![directory("d"), file], source);
    let inode = f
        .overlay
        .namespace
        .entries
        .get(&names("d/file"))
        .unwrap()
        .inode;
    let metrics = crate::ClientMetrics::new(&mut Fixed);
    metrics.set_available(crate::MetricsGroup::Fuse, true);
    let observer = crate::mount::FuseObserver {
        metrics: Some(metrics.clone()),
        writability: granary_fuse::MountWritability::Writable,
    };
    assert!(
        observer.begin(callback).is_none(),
        "query callback must not begin an OverlayWrite event"
    );
    let (valid, _) = measure_query(|| query(&mut f, callback, inode));
    assert_eq!(
        (
            valid.err().map(|e| e.to_string()),
            f.overlay.namespace.entries.len()
        ),
        (None, 2)
    );
    observer.completed(callback, CallbackOutcome::Ok);
    assert_eq!(counters(&metrics, callback), (1, 0));
    f.overlay
        .namespace
        .entries
        .get_mut(&names("d/file"))
        .unwrap()
        .inode += 100;
    for failed in 1..=2 {
        let (result, _) = measure_query(|| query(&mut f, callback, inode));
        let error = result.unwrap_err();
        let refusal = error.to_string();
        let mapped = crate::writable_start::write_error(&crate::CoordinationError::Overlay(error));
        assert_eq!(mapped, WriteError::Backend(MountError::Io));
        let WriteError::Backend(cause) = mapped else {
            unreachable!()
        };
        observer.completed(callback, CallbackOutcome::Failed(cause));
        assert_eq!(
            (
                refusal.as_str(),
                mapped.errno(),
                f.overlay.readiness(),
                counters(&metrics, callback)
            ),
            (
                "overlay persistence poisoned",
                MountError::Io.errno(),
                OverlayReadiness::Poisoned,
                (1, failed)
            ),
            "real namespace fault, sticky retry and production observer counter: callback={callback:?}"
        );
        if failed == 1 {
            f.overlay
                .namespace
                .entries
                .get_mut(&names("d/file"))
                .unwrap()
                .inode = inode;
        }
    }
    eprintln!(
        "callback={callback:?}; namespace fault routes=1; sticky refusals=2; production failed-counter increments=(1, 1); successful-counter delta=0; OverlayWrite scopes=0"
    );
}

#[test]
fn indexed_lookup_poison_and_observer_counter_are_exact() {
    fault(Callback::Lookup);
}

#[test]
fn indexed_getattr_poison_and_observer_counter_are_exact() {
    fault(Callback::Getattr);
}

#[test]
fn indexed_readdir_poison_and_observer_counter_are_exact() {
    fault(Callback::Readdir);
}

#[test]
fn indexed_readdirplus_poison_and_observer_counter_are_exact() {
    fault(Callback::Readdirplus);
}

#[test]
fn indexed_read_poison_and_observer_counter_are_exact() {
    fault(Callback::Read);
}

#[test]
fn read_content_failure_classes_increment_only_failed_counter() {
    let mut cases = 0;
    for (error, cause) in [
        (OverlayError::ContentUnavailable, MountError::Unavailable),
        (OverlayError::ContentCorrupt, MountError::Corrupt),
    ] {
        let metrics = crate::ClientMetrics::new(&mut Fixed);
        metrics.set_available(crate::MetricsGroup::Fuse, true);
        let observer = crate::mount::FuseObserver {
            metrics: Some(metrics.clone()),
            writability: granary_fuse::MountWritability::Writable,
        };
        observer.completed(Callback::Read, CallbackOutcome::Ok);
        assert_eq!(counters(&metrics, Callback::Read), (1, 0));
        let mapped = crate::writable_start::write_error(&crate::CoordinationError::Overlay(error));
        assert_eq!(mapped, WriteError::Backend(cause));
        let WriteError::Backend(actual) = mapped else {
            unreachable!()
        };
        let outcome = CallbackOutcome::Failed(actual);
        observer.completed(Callback::Read, outcome);
        assert_eq!(
            (
                mapped.errno(),
                outcome,
                counters(&metrics, Callback::Read),
                observer.begin(Callback::Read).is_none()
            ),
            (
                MountError::Io.errno(),
                CallbackOutcome::Failed(cause),
                (1, 1),
                true
            )
        );
        cases += 1;
    }
    assert_eq!(
        cases, 2,
        "nonzero unavailable/corrupt observer routes: {cases}"
    );
    eprintln!(
        "content-failure READ observer routes=2; each failed-counter increment=1; successful-counter delta=0; OverlayWrite scopes=0"
    );
}
