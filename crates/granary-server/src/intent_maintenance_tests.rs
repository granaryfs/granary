// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#![cfg(test)]

use super::*;
use granary_core::enrollment::{ClientSpkiDigest, TenantName};
use granary_core::root::VolumeName;
use granary_core::runmarker::BootId;
use granary_server::{ControlsConfig, RunEnd, VerbOptions};
use granary_sim::rng::Rng;
use granary_sim::secure_random::SeededSecureRandom;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Mutex;
use tracing::instrument::WithSubscriber as _;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn events(&self, event: &str) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|line| line.contains(&format!("event=\"{event}\"")))
            .map(str::to_owned)
            .collect()
    }
    fn lines(&self) -> Vec<String> {
        self.events("intent_maintenance_failed")
    }
}

#[tokio::test]
async fn split_round1_maintenance_reports_every_failing_volume() {
    maintenance_schedule(true, false).await;
}

#[tokio::test]
async fn maintenance_ticks_never_initialise_fresh_or_orphan_volumes() {
    maintenance_schedule(false, false).await;
}

#[expect(
    clippy::too_many_lines,
    reason = "one product schedule drives normal states, all volume failures and recovery"
)]
async fn maintenance_schedule(failing: bool, stopped: bool) {
    #[expect(clippy::disallowed_methods, reason = "unique test scratch directory")]
    let dir = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("granary-intent-maintenance-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let state_dir = dir.join("state");
    let enrollment_dir = dir.join("enrollment");
    for path in [&dir, &state_dir, &enrollment_dir] {
        if path != &dir {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    granary_server::mint(
        &enrollment_dir,
        VerbOptions {
            accept_unsupported_filesystem: true,
        },
        &TenantName::parse("test").unwrap(),
        ClientSpkiDigest::from_bytes([1; 32]),
        &mut SeededSecureRandom::from_key([1; 32]),
    )
    .unwrap();
    let reader = EnrollmentReader::open(&enrollment_dir, true).unwrap();
    let key = *granary_store::crypto::SigningKey::from_seed(&[7; 32])
        .unwrap()
        .public_key();
    let mut config = config::authority::AuthorityConfig {
        authority_profile: config::authority::AuthorityProfile::SingleProcess,
        state_dir: state_dir.clone(),
        enrollment_dir: enrollment_dir.clone(),
        client_ca: dir.join("unused-ca"),
        volumes: ["vol-a", "vol-b", "vol-c"]
            .map(|name| (VolumeName::new(name.to_owned()).unwrap(), vec![key]))
            .into_iter()
            .collect(),
        accept_unsupported_filesystem: true,
        controls: ControlsConfig::default(),
    };
    // Explicit offline creation leaves an orphan when its log is lost.
    let args = [
        "initialise".into(),
        "--state-dir".into(),
        state_dir.as_os_str().to_owned(),
        "--volume".into(),
        "vol-c".into(),
        "--accept-unsupported-filesystem".into(),
    ];
    #[expect(
        clippy::disallowed_methods,
        reason = "offline CLI owns its runtime on a blocking thread"
    )]
    let created = tokio::task::spawn_blocking(move || {
        granary_server::run_lifecycle_command_line(
            &args,
            &mut SeededSecureRandom::from_key([3; 32]),
            || Ok(0),
            || Ok(BootId::from_bytes([1; 16])),
            &mut Vec::new(),
            &mut Vec::new(),
        )
    })
    .await
    .unwrap();
    assert_eq!(created, 0);
    std::fs::remove_file(state_dir.join("vol-c.log")).unwrap();
    let orphan = std::fs::read(state_dir.join("vol-c.intent")).unwrap();
    let log = FileLog::new(&state_dir, true).unwrap();
    if failing {
        use granary_core::decisionlog::DecisionLog as _;
        let damaged = VolumeName::new("vol-d".into()).unwrap();
        log.initialise(&granary_core::authlog::encode_envelope(
            &granary_core::authlog::Envelope::new(
                damaged.clone(),
                granary_core::authlog::Epoch::from_bytes([8; 16]),
            ),
        ))
        .await
        .unwrap();
        config.volumes.insert(damaged, vec![key]);
        // A configuration/worker disagreement must retain its distinct token.
        config
            .volumes
            .insert(VolumeName::new("vol-e".into()).unwrap(), vec![key]);
    }
    let store = Arc::new(GranaryStore::new(Arc::new(
        object_store::memory::InMemory::new(),
    )));
    let volumes = config
        .volumes
        .keys()
        .filter(|volume| volume.as_str() != "vol-e")
        .map(|volume| {
            VolumeConfig::new(volume.clone(), TrustedKeys::new([key]).unwrap())
                .with_intents(log.intent_store())
        })
        .collect();
    let (handle, driver) = granary_server::start(
        AuthorityParts {
            admission: granary_server::Admission::unavailable(),
            log,
            store: GranaryStore::new(Arc::new(object_store::memory::InMemory::new())),
            clock: WallClock,
            rng: Rng::seeded(1, 1),
            secure_random: SeededSecureRandom::from_key([2; 32]),
            pause: TimerPause,
        },
        BootId::from_bytes([1; 16]),
        volumes,
    )
    .await
    .unwrap();
    let service = GrainService::new(store, "", 1).with_authority_writes(
        reader,
        Arc::new(PrincipalControls::new(config.controls, Arc::new(WallClock))),
        Arc::new(granary_server::refusals::RefusalCounters::default()),
        &config,
        handle.clone(),
    );
    let mut tasks = tokio::task::JoinSet::new();
    #[expect(clippy::disallowed_methods, reason = "drive the real authority worker")]
    tasks.spawn(driver.run());
    handle
        .initialise(&VolumeName::new("vol-a".into()).unwrap())
        .await
        .unwrap();
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    );
    let set = enrollment_dir.join("ENROLLMENT");
    let saved = std::fs::read(&set).unwrap();
    let healthy_path = state_dir.join("vol-a.intent");
    let healthy = std::fs::read(&healthy_path).unwrap();
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    // A normal startup pass skips fresh/orphan volumes and permits readiness.
    let maintenance = intent_maintenance(service.clone(), receiver)
        .with_subscriber(subscriber.clone())
        .await
        .with_subscriber(subscriber.clone());
    let failures = usize::from(failing) * 2;
    assert_eq!(captured.lines().len(), failures);
    if failing {
        assert!(captured.lines()[0].contains("volume=\"vol-d\""));
        assert!(captured.lines()[0].contains("reason=\"unavailable\""));
        assert!(captured.lines()[1].contains("volume=\"vol-e\""));
        assert!(captured.lines()[1].contains("reason=\"unknown-volume\""));
    }
    let normal = captured.events("intent_maintenance_uninitialised");
    assert_eq!(normal.len(), 2);
    assert!(normal.iter().any(|line| line.contains("volume=\"vol-b\"")));
    assert!(normal.iter().any(|line| line.contains("volume=\"vol-c\"")));
    if stopped {
        assert_eq!(handle.stop().await, RunEnd::Stopped);
        assert_eq!(tasks.join_next().await.unwrap().unwrap(), RunEnd::Stopped);
        assert_eq!(
            service
                .maintain_intents()
                .with_subscriber(subscriber.clone())
                .await,
            Err(granary_server::ErrorToken::Stopped)
        );
        let failures = captured.lines();
        assert_eq!(failures.len(), 3);
        for name in ["vol-a", "vol-b", "vol-c"] {
            assert!(
                failures
                    .iter()
                    .any(|line| line.contains(&format!("volume=\"{name}\""))
                        && line.contains("reason=\"stopped\""))
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
        return;
    }
    assert_ne!(
        std::fs::read(&healthy_path).unwrap(),
        healthy,
        "healthy enrollment must progress despite unavailable volumes"
    );
    let unchanged = || {
        assert!(!state_dir.join("vol-b.log").exists());
        assert!(!state_dir.join("vol-b.intent").exists());
        assert!(!state_dir.join("vol-c.log").exists());
        assert_eq!(
            std::fs::read(state_dir.join("vol-c.intent")).unwrap(),
            orphan
        );
    };
    unchanged();
    tokio::pin!(maintenance);
    std::future::poll_fn(|cx| {
        assert!(maintenance.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    #[expect(
        clippy::disallowed_methods,
        reason = "register the immediate timer tick"
    )]
    tokio::time::sleep(Duration::from_millis(10)).await;
    std::future::poll_fn(|cx| {
        assert!(maintenance.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    std::fs::write(&set, b"corrupt enrollment").unwrap();
    tick().await;
    drive_until(maintenance.as_mut(), "failed enrollment", || {
        captured.lines().len() == failures + 1
    })
    .await;
    unchanged();
    std::fs::write(&set, &saved).unwrap();
    let (new, _) = granary_server::mint(
        &enrollment_dir,
        VerbOptions {
            accept_unsupported_filesystem: true,
        },
        &TenantName::parse("test").unwrap(),
        ClientSpkiDigest::from_bytes([9; 32]),
        &mut SeededSecureRandom::from_key([9; 32]),
    )
    .unwrap();
    let before = std::fs::read(&healthy_path).unwrap();
    tick().await;
    drive_until(maintenance.as_mut(), "restored enrollment", || {
        std::fs::read(&healthy_path).unwrap() != before
            && captured.lines().len() == failures * 2 + 1
    })
    .await;
    unchanged();
    assert_ne!(std::fs::read(&healthy_path).unwrap(), before);
    // Repeated normal passes stay silent and preserve the orphan bytes.
    service
        .maintain_intents()
        .with_subscriber(subscriber.clone())
        .await
        .ok();
    assert_eq!(captured.events("intent_maintenance_uninitialised").len(), 2);
    unchanged();
    handle
        .initialise(&VolumeName::new("vol-b".into()).unwrap())
        .await
        .unwrap();
    handle
        .initialise(&VolumeName::new("vol-c".into()).unwrap())
        .await
        .unwrap();
    let created = state_dir.join("vol-b.intent");
    let empty = std::fs::read(&created).unwrap();
    tick().await;
    drive_until(
        maintenance.as_mut(),
        "maintenance after explicit initialise",
        || std::fs::read(&created).unwrap() != empty && captured.lines().len() == failures * 4 + 1,
    )
    .await;
    assert_eq!(captured.lines().len(), failures * 4 + 1);
    assert_eq!(captured.events("intent_maintenance_uninitialised").len(), 2);
    // Readback for the newly enrolled principal proves the maintenance population.
    let read = handle
        .intent(
            &VolumeName::new("vol-b".into()).unwrap(),
            new,
            granary_server::IntentOperation::Readback,
            Vec::new(),
        )
        .await;
    assert_eq!(read.status().as_u16(), 200);
    assert!(captured.lines()[failures].contains("reason=\"enrollment-unavailable\""));
    assert!(
        captured
            .lines()
            .iter()
            .all(|line| !line.contains("provision="))
    );
    shutdown.send(true).unwrap();
    tick().await;
    maintenance.await;
    assert_eq!(handle.stop().await, RunEnd::Stopped);
    assert_eq!(tasks.join_next().await.unwrap().unwrap(), RunEnd::Stopped);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn split_round1_maintenance_does_not_hide_stopped_uninitialised_volumes() {
    maintenance_schedule(false, true).await;
}

async fn tick() {
    // Resume real time before enrollment's blocking filesystem work runs.
    tokio::time::pause();
    tokio::time::advance(Duration::from_mins(1)).await;
    tokio::time::resume();
}

async fn drive_until<F: std::future::Future<Output = ()>>(
    mut maintenance: std::pin::Pin<&mut F>,
    phase: &str,
    done: impl Fn() -> bool,
) {
    let driven = tokio::time::timeout(Duration::from_secs(5), async {
        while !done() {
            std::future::poll_fn(|cx| {
                assert!(maintenance.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        driven.is_ok(),
        "periodic intent maintenance did not reach the expected state: {phase}"
    );
}
