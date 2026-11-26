// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{Fx, a, secure};
use crate::{
    SupportWriter,
    debug_grant::DebugGrantHost,
    protected_dir::{NixOps, tests::scratch},
};
use granary_core::{sheaf::Timestamp, support::SupportSnapshot};
use std::{sync::atomic::Ordering, time::Duration};
#[tokio::test]
async fn support_writer_cached_observation_only() {
    let (mut fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let host = DebugGrantHost::new(&mut secure(17)).unwrap();
    let (sink, _lines) = crate::sink::tests::queue();
    let (capture, _subscriber) =
        host.subscriber(tracing_subscriber::EnvFilter::new("info"), sink, true);
    fx.service = fx
        .service
        .clone()
        .with_debug_grants(&host, &fx.config.enrollment_dir, true, capture)
        .unwrap();
    let path = scratch("support-cached");
    let configuration = crate::bound_configuration(
        crate::retain_configuration(
            &fx.config,
            host.incarnation(),
            2,
            Duration::from_secs(10),
            None,
        )
        .unwrap(),
        "127.0.0.1:12345".parse().unwrap(),
    );
    let mut writer = SupportWriter::new(
        &path,
        true,
        configuration,
        fx.clock.clone(),
        fx.service.clone(),
    );
    let before = fx.service.observation().unwrap();
    let store = fx.store.calls.load(Ordering::SeqCst);
    writer.publish_for_test(&NixOps).unwrap();
    let decoded =
        SupportSnapshot::decode(&std::fs::read(path.join("SUPPORT-SNAPSHOT")).unwrap()).unwrap();
    assert_eq!(
        (
            decoded,
            fx.store.calls.load(Ordering::SeqCst),
            fx.service.observation().unwrap()
        ),
        (
            crate::snapshot_from_observation(
                host.incarnation(),
                Timestamp { secs: 0, nanos: 0 },
                &before
            )
            .unwrap(),
            store,
            before
        )
    );
    writer.start_for_test();
    tokio::time::timeout(Duration::from_secs(2), async {
        while writer.in_flight_for_test() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fx.clock.set(60_000_000_000);
    writer.tick_for_test();
    tokio::time::timeout(Duration::from_secs(2), async {
        while writer.in_flight_for_test() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(path.join("SUPPORT-CONFIGURATION").is_file());
    assert_eq!(
        SupportSnapshot::decode(&std::fs::read(path.join("SUPPORT-SNAPSHOT")).unwrap())
            .unwrap()
            .sampled_at
            .secs,
        60
    );
    std::fs::remove_dir_all(path).unwrap();
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Linux file attacks with composed serving service"
)]
async fn support_writer_linux_planted_names_still_serves() {
    use granary_core::rootstore::RootStore;
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, body::Bytes};
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let known = b"known support grain".to_vec();
    fx.store
        .inner
        .put_root("probe", 1, known.clone())
        .await
        .unwrap();
    let path = scratch("support-serving-plants");
    let incarnation = granary_core::debug_grant::Incarnation::from_bytes([1; 16]);
    let configuration = crate::bound_configuration(
        crate::retain_configuration(&fx.config, incarnation, 2, Duration::from_secs(10), None)
            .unwrap(),
        "127.0.0.1:12345".parse().unwrap(),
    );
    let writer = SupportWriter::new(
        &path,
        true,
        configuration,
        fx.clock.clone(),
        fx.service.clone(),
    );
    let sentinel = path.join("sentinel");
    std::fs::write(&sentinel, b"sentinel").unwrap();
    let mut count = 0;
    for name in [
        "SUPPORT-CONFIGURATION",
        "SUPPORT-CONFIGURATION.tmp",
        "SUPPORT-SNAPSHOT",
        "SUPPORT-SNAPSHOT.tmp",
    ] {
        for symlink in [false, true] {
            let plant = path.join(name);
            if symlink {
                std::os::unix::fs::symlink(&sentinel, &plant).unwrap();
            } else {
                nix::unistd::mkfifo(
                    &plant,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )
                .unwrap();
            }
            let result = if name.starts_with("SUPPORT-CONFIGURATION") {
                writer.publish_configuration_for_test(&NixOps)
            } else {
                writer.publish_for_test(&NixOps)
            };
            let response = fx
                .service
                .request_for_test(
                    Request::builder()
                        .method("GET")
                        .uri("/volume/probe/root/00000000000000000001")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await;
            let status = response.status().as_u16();
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec();
            assert_eq!(
                (result, status, body),
                (
                    Err(crate::SupportError("support name refused")),
                    200,
                    known.clone()
                )
            );
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
            assert!(std::fs::symlink_metadata(&plant).is_ok());
            std::fs::remove_file(plant).unwrap();
            count += 1;
        }
    }
    assert_eq!(count, 8);
    std::fs::remove_dir_all(path).unwrap();
    std::fs::remove_dir_all(fx.dir).unwrap();
}
