// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::super::super::commit_lane::finish::{Stopped, recover_stopped};
use super::*;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one mounted restart pair keeps kernel bytes, admitted work and release evidence together"
)]
fn writable_linux_start_recover_restart_preserves_admitted_work() {
    if !venue("writable_linux_start_recover_restart_preserves_admitted_work") {
        return;
    }
    let mut cases = 0;
    for blocked in [false, true] {
        let fixture = SyncMount::with_profile(
            sync_deadline(),
            Hook::Bound,
            crate::SyncProfile::DurablePrepared,
        );
        let file = fixture.file();
        file.write_at(b"acknowledged", 0).unwrap();
        file.sync_all().unwrap();
        std::fs::write(fixture.paths.mountpoint.join("residual"), b"remaining").unwrap();
        let mut expected = FILE_CONTENT.to_vec();
        expected.resize(expected.len().max(12), 0);
        expected
            .get_mut(..12)
            .unwrap()
            .copy_from_slice(b"acknowledged");
        assert_eq!(
            (
                std::fs::read(fixture.paths.mountpoint.join("f.txt")).unwrap(),
                std::fs::read(fixture.paths.mountpoint.join("residual")).unwrap()
            ),
            (expected.clone(), b"remaining".to_vec())
        );
        drop(file);
        fixture
            .faults
            .arm("sync.commit", "before_submit", 1, crate::FaultAction::Fail);
        let state = fixture.state.clone();
        let (paths, tree) = fixture.finish_shared_cache();
        let stopped = Stopped {
            paths: Arc::into_inner(paths)
                .unwrap_or_else(|| panic!("stopped mount retained its paths")),
            tree: Arc::into_inner(tree)
                .unwrap_or_else(|| panic!("stopped mount retained its tree")),
            state,
        };
        assert_eq!(
            stopped.state.lock().unwrap().publications.len(),
            0,
            "shutdown sent despite its cut"
        );
        let events = Events::default();
        let _guard = tracing::subscriber::set_default(events.subscriber());
        if blocked {
            let faults = crate::FaultControl::default();
            faults.arm("sync.commit", "before_submit", 1, crate::FaultAction::Fail);
            let result = recover_stopped(&stopped, faults.clone());
            let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                (
                    result.is_err(),
                    faults.sync_fired().len(),
                    text.contains("recover.journal_blocked"),
                    text.contains("recover.journal_finished"),
                    stopped
                        .state
                        .lock()
                        .unwrap()
                        .row
                        .is_some_and(|r| r.state == ReceiptState::Released)
                ),
                (true, 1, true, false, false),
                "cases={}, {result:?}: {text}",
                cases + 1
            );
        }
        let result = recover_stopped(&stopped, crate::FaultControl::default());
        let persisted = {
            let state = stopped.state.lock().unwrap();
            (state.publications.len(), state.row.map(|r| r.state))
        };
        assert_eq!(
            (result.is_ok(), persisted),
            (true, (1, Some(ReceiptState::Released))),
            "blocked={blocked}: {result:?}"
        );
        let start = input(&stopped.tree, &stopped.paths);
        let area = stopped
            .paths
            .store
            .join("overlay")
            .join(start.scope.as_ref().unwrap().digest().unwrap())
            .join(start.volume.as_str());
        let header = crate::overlay_store::journal_condition(
            &mut OverlayDisk::new(&stopped.paths.store, start.euid),
            &area,
        )
        .unwrap()
        .unwrap();
        assert_eq!((header.0.base_seq, header.1), (2, true));
        let Stopped { paths, tree, state } = stopped;
        let state = Arc::into_inner(state)
            .unwrap_or_else(|| panic!("recovery retained its authority"))
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        let restarted = SyncMount::shared_cache_with_authority(
            sync_deadline(),
            crate::SyncProfile::DurablePrepared,
            state,
            Arc::new(paths),
            Arc::new(tree),
        )
        .unwrap();
        assert_eq!(
            (
                std::fs::read(restarted.paths.mountpoint.join("f.txt")).unwrap(),
                std::fs::read(restarted.paths.mountpoint.join("residual")).unwrap(),
                restarted.served_pin().1
            ),
            (expected, b"remaining".to_vec(), 2)
        );
        restarted.finish();
        cases += 1;
    }
    assert_eq!(cases, 2);
}
