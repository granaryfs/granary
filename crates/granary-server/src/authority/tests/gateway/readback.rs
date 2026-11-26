// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::future::{Future, poll_fn};
use std::sync::atomic::AtomicBool;

struct HeldBody {
    polled: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
}

impl Body for HeldBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.polled.store(true, Ordering::SeqCst);
        if self.released.load(Ordering::SeqCst) {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

#[tokio::test]
async fn readback_releases_shared_permit_before_draining_request_body() {
    let (fx, driver) = Fx::new(true, &[], &[]).await;
    let mut tasks = spawn_driver(driver);
    fx.handle.initialise(&a()).await.unwrap();
    fx.service.maintain_intents().await.unwrap();
    let polled = Arc::new(AtomicBool::new(false));
    let released = Arc::new(AtomicBool::new(false));
    let read = fx.send(request(
        "GET",
        &format!("/volume/{}/intent", a().as_str()),
        HeldBody {
            polled: polled.clone(),
            released: released.clone(),
        },
    ));
    tokio::pin!(read);
    tokio::time::timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            assert!(read.as_mut().poll(cx).is_pending());
            if polled.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    let budget = fx.service.read_budget();
    assert!(budget.in_flight() >= 20, "response charged before drain");
    let permits = fx.service.read_permits_handle();
    assert_eq!(
        permits.available_permits(),
        8,
        "a charged readback must release its shared permit before body drain"
    );
    let held = permits.try_acquire_many(8).unwrap();
    released.store(true, Ordering::SeqCst);
    let response = read.await;
    check(&response, 200, None);
    assert!(budget.in_flight() >= 20, "response retains its byte charge");
    drop(response);
    assert_eq!(budget.in_flight(), 0);
    drop(held);
    fx.handle.stop().await;
    assert_eq!(tasks.join_next().await.unwrap().unwrap(), RunEnd::Stopped);
}

#[tokio::test]
async fn readback_flood_limits_concurrent_enrollment_lookups_to_eight() {
    use crate::protected_dir::tests::Pause;
    let (fx, driver) = Fx::new(true, &[], &[]).await;
    let mut tasks = spawn_driver(driver);
    fx.handle.initialise(&a()).await.unwrap();
    fx.service.maintain_intents().await.unwrap();
    let pause = Arc::new(Pause::default());
    fx.reader.hold_refresh(pause.clone());
    let path = format!("/volume/{}/intent", a().as_str());
    // One principal's 24 simultaneously polled requests contend for the
    // shared pool. A paused real refresh keeps admitted lookups in flight.
    let mut reads: Vec<_> = (0..24)
        .map(|_| Box::pin(fx.send(request("GET", &path, Full::new(Bytes::new())))))
        .collect();
    poll_fn(|cx| {
        for read in &mut reads {
            assert!(read.as_mut().poll(cx).is_pending());
        }
        Poll::Ready(())
    })
    .await;
    let active = fx.reader.active_lookups();
    let available = fx.service.read_permits_handle().available_permits();
    // Release before assertions so a killed guard never strands a blocking
    // refresh during runtime shutdown. Futures have not been repolled.
    pause.release();
    assert_eq!(
        active, 8,
        "only eight readbacks may enter enrollment lookup"
    );
    assert_eq!(available, 0, "lookups own all eight shared read permits");
    drop(reads);
    assert_eq!(fx.reader.active_lookups(), 0, "cancellation ends lookups");
    assert_eq!(fx.service.read_permits_handle().available_permits(), 8);
    check(
        &fx.send(request("GET", &path, Full::new(Bytes::new())))
            .await,
        200,
        None,
    );
    assert_eq!(fx.reader.active_lookups(), 0);
    fx.handle.stop().await;
    assert_eq!(tasks.join_next().await.unwrap().unwrap(), RunEnd::Stopped);
}

#[tokio::test]
async fn repairing_enrollment_does_not_initialise_volume_state() {
    let (fx, driver) = Fx::new(true, &[], &[]).await;
    let mut tasks = spawn_driver(driver);
    let set = fx.config.enrollment_dir.join(crate::enrollment::SET_NAME);
    let saved = std::fs::read(&set).unwrap();
    std::fs::write(&set, b"corrupt synthetic enrollment").unwrap();
    assert_eq!(
        fx.service.maintain_intents().await,
        Err(crate::wire::ErrorToken::EnrollmentUnavailable)
    );
    for entry in std::fs::read_dir(&fx.state_dir).unwrap() {
        let path = entry.unwrap().path();
        assert!(
            !matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("log" | "intent")
            ),
            "failed enrollment maintenance must create no per-volume state file"
        );
    }
    std::fs::write(set, saved).unwrap();
    assert_eq!(fx.service.maintain_intents().await, Ok(()));
    for extension in ["log", "intent"] {
        assert!(
            !fx.state_dir
                .join(format!("{}.{extension}", a().as_str()))
                .exists()
        );
    }

    fx.handle.initialise(&a()).await.unwrap();
    fx.service.maintain_intents().await.unwrap();
    for extension in ["log", "intent"] {
        assert!(
            fx.state_dir
                .join(format!("{}.{extension}", a().as_str()))
                .is_file()
        );
    }
    fx.handle.stop().await;
    assert_eq!(tasks.join_next().await.unwrap().unwrap(), RunEnd::Stopped);
}
