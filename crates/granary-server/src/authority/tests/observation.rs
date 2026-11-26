// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn status_tracks_last_head_verification() {
    for path in 0..3 {
        for schedule in [0, 1, 17] {
            let root = good_root(&a(), 1, None, 1);
            let d = decision_of(1, 1, &root);
            let records = if path == 1 {
                vec![d.clone(), attestation(&d), landed(&d)]
            } else {
                vec![]
            };
            let world = World::with_records(&a(), &records, Faults::none());
            world.plant(&a(), 1, &root);
            let (handle, driver) = world.start(&[a()]);
            assert_eq!(
                handle.volume_view(&a()).unwrap().status().unwrap().head,
                None
            );
            let store = world.store.clone();
            let admin = world.sim.admin();
            let (end, ()) = run_beside(schedule, driver, async move {
                let sub = match path {
                    0 => submission_at(Epoch::from_bytes([0xFF; 16]), &a(), 1, b"bad candidate"),
                    1 => submission(&a(), 1, &root),
                    _ => submission(&a(), 2, &good_root(&a(), 1, None, 2)),
                };
                let answer = handle.submit(sub.clone()).await;
                assert!(matches!(
                    answer,
                    Answer::EpochMismatch { .. } | Answer::Landed { .. } | Answer::StaleBase { .. }
                ));
                let view = handle.volume_view(&a()).unwrap().status().unwrap();
                assert_eq!(
                    view.head,
                    Some(granary_core::authority_answer::Head {
                        root: Some((1, GrainId::of(&root))),
                        next_seq: Some(2)
                    })
                );
                store.set_read_fault(&a(), 1, Some(ReadFault::Transport));
                let answer = handle.submit(sub.clone()).await;
                assert!(matches!(
                    answer,
                    Answer::EpochMismatch { head: None, .. }
                        | Answer::Landed { head: None, .. }
                        | Answer::Validation(crate::ValidationError::Unavailable)
                ));
                assert_eq!(
                    handle.volume_view(&a()).unwrap().status().unwrap().head,
                    None,
                    "path {path} retained failed verification"
                );
                store.set_read_fault(&a(), 1, None);
                assert!(admin.delete_root(&a(), 1));
                // Rule 0 and recorded lookup verify an empty chain too. A new
                // candidate instead reaches a decision, so stop before that PUT.
                if path != 2 {
                    handle.submit(sub).await;
                    assert_eq!(
                        handle.volume_view(&a()).unwrap().status().unwrap().head,
                        Some(granary_core::authority_answer::Head {
                            root: None,
                            next_seq: Some(1)
                        })
                    );
                }
                handle.stop().await;
            });
            assert_eq!(end, RunEnd::Stopped);
            assert!(world.log.violations().is_empty());
        }
    }
}

#[track_caller]
pub(super) fn assert_verified_status(
    handle: &AuthorityHandle,
    head: Option<VerifiedHead>,
    open: OpenPosition,
) {
    let view = handle.volume_view(&a()).unwrap();
    assert_eq!(
        view,
        VolumeView::Log {
            epoch: World::position(1).epoch,
            head,
            open: Some(open)
        }
    );
    let status = view.status().unwrap();
    assert_eq!(
        status.head,
        head.map(|value| granary_core::authority_answer::Head {
            root: value.head.map(|root| (root.head_seq, root.head_id)),
            next_seq: value.next_seq,
        })
    );
    assert_eq!(status.open, Some(open));
}
