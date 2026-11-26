// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use granary_core::hash::GrainId;
use std::sync::{Arc, Barrier};

#[test]
fn status_snapshot_is_coherent() {
    let a = VolumeView::Log {
        epoch: Epoch::from_bytes([1; 16]),
        head: Some(VerifiedHead::new(None)),
        open: None,
    };
    let b = VolumeView::Log {
        epoch: Epoch::from_bytes([2; 16]),
        head: None,
        open: Some(OpenPosition {
            entry_seq: 99,
            candidate_id: GrainId::of(b"open"),
        }),
    };
    let slot = Arc::new(VolumeSlot::new(None));
    slot.replace(a);
    let before = Arc::new(Barrier::new(5));
    let after = Arc::new(Barrier::new(5));
    let torn = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|threads| {
        for _ in 0..4 {
            let (slot, before, after) = (slot.clone(), before.clone(), after.clone());
            let torn = &torn;
            threads.spawn(move || {
                for _ in 0..1000 {
                    before.wait();
                    for _ in 0..16 {
                        let got = slot.load();
                        if got != a && got != b {
                            torn.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                        std::thread::yield_now();
                    }
                    after.wait();
                }
            });
        }
        for n in 0..1000 {
            before.wait();
            slot.replace(if n % 2 == 0 { b } else { a });
            after.wait();
        }
    });
    assert!(
        !torn.load(std::sync::atomic::Ordering::SeqCst),
        "torn volume view"
    );
    // The barriers make each replacement overlap a bounded read phase. The
    // mutex's same guard for whole-value load/replace excludes a mixed value
    // even when a scheduler never samples the transition in this test.
}

#[test]
fn observation_size_is_bounded() {
    assert!(std::mem::size_of::<VolumeView>() <= 160);
    assert!(!std::mem::needs_drop::<VolumeView>());
    assert!(!std::mem::needs_drop::<OpenPosition>());
    assert!(!std::mem::needs_drop::<VerifiedHead>());
    assert_eq!(granary_core::authority_answer::STATUS_V1_MAX, 120);
}
