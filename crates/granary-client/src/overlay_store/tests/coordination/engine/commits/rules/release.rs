// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Recovery over fenced carriers retaining Release evidence.

use super::*;
use granary_core::overlay_ownership::{Operation, Phase};

fn slots(local: &WritableStore<SimIo>) -> Vec<(u64, bool, bool)> {
    local
        .snapshot()
        .pending
        .iter()
        .filter(|pending| pending.operation == Operation::Release)
        .map(|pending| {
            (
                intent::decode_release(&pending.body).unwrap().epoch,
                pending.terminal,
                pending.answered,
            )
        })
        .collect()
}

/// `release`: none, an unresolved one, or one the displacement itself answered.
fn fenced_fixture(
    runtime: &tokio::runtime::Runtime,
    release: &str,
) -> (Scratch, SimIo, Arc<Remote>, [u8; 16]) {
    let fixture = runtime.block_on(Fixture::new());
    fixture.create("local", b"sealed");
    let writer = fixture.store.lock().unwrap().writer_uuid();
    let bytes = runtime.block_on(super::selected::one_file(
        &fixture.remote,
        b"local",
        b"sealed",
        writer,
    ));
    let time = fixture.remote.time.clone();
    let registered = {
        let mut local = fixture.store.lock().unwrap();
        let request = local
            .prepare_registration(&bytes, vec![], time.as_ref(), |_, _| true)
            .unwrap();
        local.dispatch(&request, time.as_ref()).unwrap();
        let answer = fixture.remote.authority.lock().unwrap().send(&request);
        local
            .complete(
                &request,
                Ok(&answer),
                time.as_ref(),
                &mut SeededRng::new(2),
                0,
                None,
            )
            .unwrap();
        assert_eq!(local.snapshot().phase, Phase::Serving);
        request
    };
    let pending_release = (release != "none").then(|| {
        let mut local = fixture.store.lock().unwrap();
        let request = local
            .prepare_release(time.as_ref(), Duration::from_secs(30), None)
            .unwrap();
        local.dispatch(&request, time.as_ref()).unwrap();
        if release == "unresolved" {
            let unknown = local
                .complete(
                    &request,
                    Err(IntentTransportError::Transport),
                    time.as_ref(),
                    &mut SeededRng::new(2),
                    0,
                    None,
                )
                .unwrap();
            assert_eq!(unknown, crate::IntentCompletion::Unknown);
        }
        request
    });
    // Another instance takes the row over.
    {
        let mut authority = fixture.remote.authority.lock().unwrap();
        authority.cursor += 1;
        let cursor = authority.cursor;
        let row = authority.row.as_mut().unwrap();
        row.epoch = cursor;
        row.instance = [99; 16];
    }
    {
        // The displacement reaches this process on the Release's own answer,
        // or on a duplicate reply to the answered registration.
        let fencing = if release == "answered" {
            pending_release.clone().unwrap()
        } else {
            registered
        };
        let answer = fixture.remote.authority.lock().unwrap().send(&fencing);
        let mut local = fixture.store.lock().unwrap();
        let fenced = local.complete(
            &fencing,
            Ok(&answer),
            time.as_ref(),
            &mut SeededRng::new(2),
            0,
            None,
        );
        assert!(
            matches!(fenced, Err(CoordinationError::Fenced { .. })),
            "{release}: {fenced:?}"
        );
        assert_eq!(local.snapshot().phase, Phase::Fenced);
    }
    published::settle_disk(&fixture.io);
    let (scratch, io, remote, local) = fixture.reload_carrier();
    drop(local);
    (scratch, io, remote, writer)
}

#[test]
fn recovery_command_over_a_fenced_carrier_holding_a_release() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for release in ["none", "answered", "unanswered", "unresolved"] {
        for late in [false, true] {
            let (scratch, io, remote, writer) = fenced_fixture(&runtime, release);
            let local = start(&scratch, &io, 150);
            let prior = slots(&local);
            let displaced = remote.authority.lock().unwrap().row.unwrap().epoch;
            match release {
                "none" => assert!(prior.is_empty()),
                "answered" => assert_eq!(prior, [(displaced - 1, true, true)]),
                _ => assert_eq!(prior, [(displaced - 1, false, false)]),
            }
            drop(local);
            if late {
                remote.time.wall.fetch_add(120, Ordering::Relaxed);
            }
            for run in 0..3u8 {
                let ack = (run == 0).then_some(writer);
                boundary_command_with_ack(
                    &scratch,
                    &io,
                    &remote,
                    &runtime,
                    writer,
                    ack,
                    None,
                    FaultControl::default(),
                )
                .unwrap_or_else(|error| panic!("release={release} late={late} run={run}: {error}"));
                let local = start(&scratch, &io, 151 + run);
                let row = remote.authority.lock().unwrap().row.unwrap();
                assert!(row.epoch > displaced);
                assert_eq!(row.state, ReceiptState::Released);
                assert_eq!(local.snapshot().phase, Phase::Released);
                assert_eq!(slots(&local), [(row.epoch, true, true)]);
                if run == 1 {
                    remote.time.wall.fetch_add(120, Ordering::Relaxed);
                }
            }
        }
    }
}
