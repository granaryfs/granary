// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{Flight, Kind, Publisher, STAGES, SUPPORT_INTERVAL, Ticker, TimerWait, Wait, Work};
use crate::{
    protected_dir::tests::{Call, Phase, Recorder, scratch},
    protected_dir::{DirOps, NixOps, ProtectedDir, exclusive_temp_flags},
    protected_replace,
    support::{SupportError, SupportSnapshot},
};
use granary_core::{clock::Clock, sheaf::Timestamp};
use std::os::unix::fs::MetadataExt as _;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
#[derive(Default)]
struct Time(AtomicI64);
impl Clock for Time {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: self.0.load(Ordering::SeqCst),
            nanos: 0,
        }
    }
}
#[derive(Default)]
struct Jobs {
    finished: Arc<AtomicBool>,
    calls: Mutex<Vec<(Kind, Timestamp)>>,
}
struct Held(Arc<AtomicBool>);
impl Flight for Held {
    fn finished(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
impl Work for Arc<Jobs> {
    fn launch(&self, kind: Kind, time: Timestamp) -> std::io::Result<Box<dyn Flight>> {
        self.calls.lock().unwrap().push((kind, time));
        Ok(Box::new(Held(self.finished.clone())))
    }
}
#[derive(Default)]
struct Wake {
    ready: AtomicBool,
    gaps: Mutex<Vec<Duration>>,
}
impl Wait for Wake {
    fn wait(&self, gap: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.gaps.lock().unwrap().push(gap);
        Box::pin(poll_fn(|_| {
            if self.ready.swap(false, Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }))
    }
}
fn poll<F: Future<Output = ()> + ?Sized>(future: Pin<&mut F>) -> Poll<()> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
#[expect(
    clippy::duration_suboptimal_units,
    reason = "the invalid-clock assertion spells the full 60-second interval"
)]
fn support_writer_invalid_clock_waits_without_publishing() {
    struct Reading(Mutex<Timestamp>);
    impl Clock for Reading {
        fn now(&self) -> Timestamp {
            *self.0.lock().unwrap()
        }
    }
    let clock = Arc::new(Reading(Mutex::new(Timestamp { secs: 0, nanos: 0 })));
    let jobs = Arc::new(Jobs::default());
    jobs.finished.store(true, Ordering::SeqCst);
    let wait = Wake::default();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let mut run = std::pin::pin!(Ticker::new(jobs.clone(), clock.clone()).run(&wait, shutdown));
    assert!(poll(run.as_mut()).is_pending());
    for (index, secs) in [60, 120].into_iter().enumerate() {
        *clock.0.lock().unwrap() = Timestamp {
            secs,
            nanos: 1_000_000_000,
        };
        wait.ready.store(true, Ordering::SeqCst);
        assert!(poll(run.as_mut()).is_pending());
        let gaps = wait.gaps.lock().unwrap();
        assert_eq!(
            (
                gaps.last().copied(),
                gaps.len(),
                jobs.calls.lock().unwrap().len()
            ),
            (Some(Duration::from_secs(60)), index + 2, 1),
            "invalid clock must wait 60 seconds without publishing"
        );
    }
    *clock.0.lock().unwrap() = Timestamp {
        secs: 180,
        nanos: 0,
    };
    wait.ready.store(true, Ordering::SeqCst);
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(
        jobs.calls.lock().unwrap().as_slice(),
        [
            (Kind::Configuration, Timestamp { secs: 0, nanos: 0 }),
            (
                Kind::Snapshot,
                Timestamp {
                    secs: 180,
                    nanos: 0
                }
            )
        ],
        "valid clock recovery resumes sampling"
    );
    stop.send(true).unwrap();
    assert!(poll(run.as_mut()).is_ready());
}

#[tokio::test(start_paused = true)]
async fn support_writer_timer_wait_observes_delay() {
    let wait = TimerWait;
    let mut waited = wait.wait(Duration::from_millis(250));
    assert!(
        poll(waited.as_mut()).is_pending(),
        "production TimerWait must not complete before virtual time advances"
    );
    tokio::time::advance(Duration::from_millis(249)).await;
    assert!(
        poll(waited.as_mut()).is_pending(),
        "production TimerWait must remain pending before the requested delay"
    );
    // Tokio's timer wheel may round the wakeup to the next millisecond tick.
    tokio::time::advance(Duration::from_millis(2)).await;
    assert!(
        poll(waited.as_mut()).is_ready(),
        "production TimerWait must complete after the requested delay"
    );
}

#[test]
#[expect(
    clippy::duration_suboptimal_units,
    reason = "the fixed cadence assertions spell 60 seconds independently"
)]
fn support_writer_clock_drives_fixed_ticks() {
    let time = Arc::new(Time::default());
    let jobs = Arc::new(Jobs::default());
    jobs.finished.store(true, Ordering::SeqCst);
    let wait = Wake::default();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let mut run = std::pin::pin!(Ticker::new(jobs.clone(), time.clone()).run(&wait, shutdown));
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(
        wait.gaps.lock().unwrap().as_slice(),
        [Duration::from_secs(60)]
    );
    for secs in [0, 59] {
        time.0.store(secs, Ordering::SeqCst);
        wait.ready.store(true, Ordering::SeqCst);
        assert!(poll(run.as_mut()).is_pending());
    }
    assert_eq!(
        jobs.calls.lock().unwrap().len(),
        1,
        "a wait wake alone cannot trigger a tick"
    );
    for secs in [60, 600, 600, 599, 659, 660] {
        time.0.store(secs, Ordering::SeqCst);
        wait.ready.store(true, Ordering::SeqCst);
        assert!(poll(run.as_mut()).is_pending());
    }
    let calls = jobs.calls.lock().unwrap().clone();
    assert_eq!(
        calls
            .iter()
            .map(|(kind, t)| (*kind, t.secs))
            .collect::<Vec<_>>(),
        [
            (Kind::Configuration, 0),
            (Kind::Snapshot, 60),
            (Kind::Snapshot, 600),
            (Kind::Snapshot, 660)
        ]
    );
    assert_eq!(SUPPORT_INTERVAL, Duration::from_secs(60));
    time.0.store(720, Ordering::SeqCst);
    wait.ready.store(true, Ordering::SeqCst);
    stop.send(true).unwrap();
    assert!(poll(run.as_mut()).is_ready());
    assert_eq!(
        jobs.calls.lock().unwrap().len(),
        4,
        "shutdown outranks a simultaneous due tick"
    );
}
#[test]
fn support_writer_single_flight() {
    let time = Arc::new(Time::default());
    let jobs = Arc::new(Jobs::default());
    let mut ticker = Ticker::new(jobs.clone(), time.clone());
    ticker.start();
    for secs in [60, 120, 180] {
        time.0.store(secs, Ordering::SeqCst);
        ticker.tick();
    }
    assert_eq!(
        jobs.calls.lock().unwrap().len(),
        1,
        "startup owns the same flight slot"
    );
    jobs.finished.store(true, Ordering::SeqCst);
    time.0.store(240, Ordering::SeqCst);
    ticker.tick();
    jobs.finished.store(false, Ordering::SeqCst);
    time.0.store(300, Ordering::SeqCst);
    ticker.tick();
    assert_eq!(
        jobs.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(kind, _)| *kind)
            .collect::<Vec<_>>(),
        [Kind::Configuration, Kind::Snapshot]
    );
}
#[test]
fn support_configuration_written_once() {
    let time = Arc::new(Time::default());
    let jobs = Arc::new(Jobs::default());
    jobs.finished.store(true, Ordering::SeqCst);
    let mut ticker = Ticker::new(jobs.clone(), time.clone());
    ticker.start();
    ticker.start();
    for secs in [60, 120, 180] {
        time.0.store(secs, Ordering::SeqCst);
        ticker.tick();
        ticker.start();
    }
    assert_eq!(
        jobs.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(kind, _)| *kind)
            .collect::<Vec<_>>(),
        [
            Kind::Configuration,
            Kind::Snapshot,
            Kind::Snapshot,
            Kind::Snapshot
        ]
    );
}
fn publisher(path: &std::path::Path) -> Publisher {
    Publisher {
        path: path.into(),
        accept: true,
        configuration: crate::support::tests::configuration(),
        clock: Arc::new(Time::default()),
        cached: Arc::new(|| Some(crate::support::tests::source())),
    }
}
#[test]
fn support_writer_guard_faults() {
    let path = scratch("support-guards");
    let publisher = publisher(&path);
    assert_eq!(
        publisher.publish(&NixOps, Kind::Snapshot, Timestamp { secs: 0, nanos: 0 }),
        Ok(())
    );
    let old = std::fs::read(path.join("SUPPORT-SNAPSHOT")).unwrap();
    assert!(exclusive_temp_flags().contains(nix::fcntl::OFlag::O_NONBLOCK));
    let ops = Recorder::with_descriptor_kind(0o010_000);
    assert_eq!(
        publisher.publish(&ops, Kind::Snapshot, Timestamp { secs: 0, nanos: 0 }),
        Err(SupportError("support publication failed"))
    );
    assert_eq!(
        (
            std::fs::read(path.join("SUPPORT-SNAPSHOT")).unwrap(),
            ops.calls().iter().any(|call| matches!(call, Call::WriteAt))
        ),
        (old, false)
    );
    assert!(
        path.join("SUPPORT-SNAPSHOT.tmp").is_file(),
        "refused descriptor name is preserved"
    );
    std::fs::remove_file(path.join("SUPPORT-SNAPSHOT.tmp")).unwrap();
    assert_eq!(
        publisher.publish(&NixOps, Kind::Snapshot, Timestamp { secs: 1, nanos: 0 }),
        Err(SupportError("support clock regressed"))
    );
    let ops = Recorder::root_publication(17, 17);
    assert!(
        protected_replace::locked_server(&ops, &path, true, &STAGES).is_err(),
        "root server cannot borrow another owner's directory"
    );
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Linux filesystem publication venue"
)]
fn support_writer_linux_planted_names() {
    let path = scratch("support-plants");
    let publisher = publisher(&path);
    let sentinel = path.join("sentinel");
    std::fs::write(&sentinel, b"keep sentinel").unwrap();
    let mut count = 0;
    for kind in [Kind::Configuration, Kind::Snapshot] {
        assert_eq!(
            publisher.publish(&NixOps, kind, Timestamp { secs: 0, nanos: 0 }),
            Ok(())
        );
        for name in [kind.names().0, kind.names().1] {
            for link in [false, true] {
                let plant = path.join(name);
                let _removed = std::fs::remove_file(&plant);
                if link {
                    std::os::unix::fs::symlink(&sentinel, &plant).unwrap();
                } else {
                    nix::unistd::mkfifo(
                        &plant,
                        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                    )
                    .unwrap();
                }
                let before = std::fs::symlink_metadata(&plant).unwrap();
                assert_eq!(
                    publisher.publish(&NixOps, kind, Timestamp { secs: 0, nanos: 0 }),
                    Err(SupportError("support name refused"))
                );
                assert_eq!(
                    (
                        std::fs::symlink_metadata(&plant).unwrap().ino(),
                        std::fs::read(&sentinel).unwrap()
                    ),
                    (before.ino(), b"keep sentinel".to_vec())
                );
                std::fs::remove_file(&plant).unwrap();
                count += 1;
            }
        }
    }
    assert_eq!(count, 8);
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux syscall and FIFO venue")]
fn support_writer_linux_nonblocking_temp() {
    let path = scratch("support-temp");
    let directory = ProtectedDir::for_server(&NixOps, &path, true).unwrap();
    let file = NixOps.create_excl_at(&directory.dir, "probe").unwrap();
    let flags = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFL).unwrap();
    assert!(nix::fcntl::OFlag::from_bits_truncate(flags).contains(nix::fcntl::OFlag::O_NONBLOCK));
    assert!(NixOps.fstat(&file).unwrap().is_file());
    drop(file);
    let ops = Recorder::with_fifo_creation();
    let result = publisher(&path).publish(&ops, Kind::Snapshot, Timestamp { secs: 0, nanos: 0 });
    assert_eq!(
        (
            result,
            ops.calls().iter().any(|call| matches!(call, Call::WriteAt))
        ),
        (Err(SupportError("support publication failed")), false)
    );
    assert!(
        !std::fs::symlink_metadata(path.join("SUPPORT-SNAPSHOT.tmp"))
            .unwrap()
            .is_file()
    );
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux durable replacement venue")]
fn support_writer_linux_durable_replace() {
    durable_faults();
}
#[test]
fn support_writer_publication_faults() {
    durable_faults();
}
fn durable_faults() {
    let mut count = 0;
    for fault in [0, 1, 2, 3, 4] {
        let path = scratch("support-durability");
        let mut publisher = publisher(&path);
        let initial = crate::snapshot_from_observation(
            publisher.configuration.incarnation,
            Timestamp { secs: 0, nanos: 0 },
            &crate::support::tests::source(),
        )
        .unwrap()
        .encode()
        .unwrap();
        std::fs::write(path.join("SUPPORT-SNAPSHOT"), initial).unwrap();
        let old = std::fs::read(path.join("SUPPORT-SNAPSHOT")).unwrap();
        publisher.clock = Arc::new(Time(AtomicI64::new(1)));
        let ops = Recorder::new();
        ops.set_hook(move |call, phase| {
            let fail = matches!(
                (fault, call, phase),
                (1, Call::SyncFile { .. }, Phase::Before)
                    | (2, Call::RenameAt(..), Phase::Before)
                    | (3, Call::RenameAt(..), Phase::After)
                    | (4, Call::SyncDir { .. }, Phase::Before)
            );
            if fail {
                Err(std::io::Error::other("injected publication failure"))
            } else {
                Ok(())
            }
        });
        let result = publisher.publish(&ops, Kind::Snapshot, Timestamp { secs: 0, nanos: 0 });
        let final_bytes = std::fs::read(path.join("SUPPORT-SNAPSHOT")).unwrap();
        assert!(SupportSnapshot::decode(&final_bytes).is_ok());
        assert_eq!(
            (result, final_bytes == old),
            (
                if fault == 0 {
                    Ok(())
                } else if fault == 1 {
                    Err(SupportError("support publication failed"))
                } else {
                    Err(SupportError("support publication uncertain"))
                },
                matches!(fault, 1 | 2)
            )
        );
        let calls = ops.calls();
        let actual: Vec<_> = calls
            .iter()
            .filter_map(|call| match call {
                Call::Lock { .. } => Some("lock"),
                Call::SyncFile { .. } => Some("file-sync"),
                Call::RenameAt(..) => Some("rename"),
                Call::SyncDir { .. } => Some("directory-sync"),
                _ => None,
            })
            .collect();
        let expected = match fault {
            1 => vec!["lock", "file-sync"],
            2 | 3 => vec!["lock", "file-sync", "rename"],
            _ => vec!["lock", "file-sync", "rename", "directory-sync"],
        };
        let locked = calls.iter().find_map(|call| {
            if let Call::Lock { ino } = call {
                Some(*ino)
            } else {
                None
            }
        });
        let inode = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&path).unwrap());
        assert_eq!(
            (actual, locked),
            (expected, Some(inode)),
            "descriptor-relative lock and durability order"
        );
        count += 1;
        std::fs::remove_dir_all(path).unwrap();
    }
    assert_eq!(count, 5);
}

#[tokio::test]
async fn support_writer_blocking_job_thread() {
    let path = scratch("support-thread");
    let mut source = publisher(&path);
    let caller = std::thread::current().id();
    let (send, receive) = std::sync::mpsc::channel();
    source.cached = Arc::new(move || {
        send.send(std::thread::current().id()).unwrap();
        Some(crate::support::tests::source())
    });
    let flight = Arc::new(source)
        .launch(Kind::Snapshot, Timestamp { secs: 0, nanos: 0 })
        .unwrap();
    let observed = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_ne!(
        observed, caller,
        "observation and file I/O must run on the blocking job thread"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while !flight.finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        SupportSnapshot::decode(&std::fs::read(path.join("SUPPORT-SNAPSHOT")).unwrap()).is_ok()
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn support_writer_shutdown_detaches() {
    let time = Arc::new(Time::default());
    let jobs = Arc::new(Jobs::default());
    let wait = Wake::default();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let mut run = std::pin::pin!(Ticker::new(jobs.clone(), time).run(&wait, shutdown));
    assert!(poll(run.as_mut()).is_pending());
    stop.send(true).unwrap();
    assert_eq!(
        (
            poll(run.as_mut()).is_ready(),
            jobs.calls.lock().unwrap().len(),
            jobs.finished.load(Ordering::SeqCst)
        ),
        (true, 1, false),
        "shutdown returns with the existing flight held, without a final flush"
    );
}
#[test]
fn support_writer_name_preflight() {
    let path = scratch("support-preflight");
    let publisher = publisher(&path);
    publisher
        .publish(&NixOps, Kind::Snapshot, Timestamp { secs: 0, nanos: 0 })
        .unwrap();
    let mut count = 0;
    for name in ["SUPPORT-SNAPSHOT.tmp", "SUPPORT-SNAPSHOT"] {
        let plant = path.join(name);
        let _removed = std::fs::remove_file(&plant);
        let sentinel = path.join("sentinel");
        std::fs::write(&sentinel, b"sentinel").unwrap();
        std::os::unix::fs::symlink(&sentinel, &plant).unwrap();
        if name == "SUPPORT-SNAPSHOT" {
            std::fs::write(path.join("SUPPORT-SNAPSHOT.tmp"), b"stale").unwrap();
        }
        let result = publisher.publish(&NixOps, Kind::Snapshot, Timestamp { secs: 0, nanos: 0 });
        assert_eq!(
            (
                result,
                std::fs::symlink_metadata(&plant).is_ok_and(|stat| stat.file_type().is_symlink()),
                path.join("SUPPORT-SNAPSHOT.tmp").exists()
                    || std::fs::symlink_metadata(path.join("SUPPORT-SNAPSHOT.tmp")).is_ok()
            ),
            (Err(SupportError("support name refused")), true, true)
        );
        std::fs::remove_file(&plant).unwrap();
        let _removed = std::fs::remove_file(path.join("SUPPORT-SNAPSHOT.tmp"));
        count += 1;
    }
    assert_eq!(count, 2);
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn support_writer_directory_revalidated_after_lock() {
    let path = scratch("support-identity");
    let old = path.with_extension("old");
    let ops = Recorder::new();
    let moved = Arc::new(AtomicBool::new(false));
    let source = path.clone();
    let destination = old.clone();
    ops.set_hook(move |call, phase| {
        if matches!((call, phase), (Call::Lock { .. }, Phase::After))
            && !moved.swap(true, Ordering::SeqCst)
        {
            std::fs::rename(&source, &destination)?;
            std::fs::create_dir(&source)?;
            std::fs::set_permissions(&source, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        }
        Ok(())
    });
    assert_eq!(
        publisher(&path).publish(&ops, Kind::Snapshot, Timestamp { secs: 0, nanos: 0 }),
        Err(SupportError("support directory refused"))
    );
    assert_eq!(
        (
            path.join("SUPPORT-SNAPSHOT").exists(),
            old.join("SUPPORT-SNAPSHOT").exists()
        ),
        (false, false)
    );
    std::fs::remove_dir_all(path).unwrap();
    std::fs::remove_dir_all(old).unwrap();
}

#[tokio::test]
async fn support_configuration_failure_is_not_retried() {
    let parent = scratch("support-startup-failure");
    let path = parent.join("SUPPORT");
    let clock = Arc::new(Time::default());
    let mut source = publisher(&path);
    source.clock = clock.clone();
    let mut ticker = Ticker::new(Arc::new(source), clock.clone());
    ticker.start();
    tokio::time::timeout(Duration::from_secs(2), async {
        while ticker
            .flight
            .as_ref()
            .is_some_and(|flight| !flight.finished())
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    clock.0.store(60, Ordering::SeqCst);
    ticker.tick();
    ticker.start();
    tokio::time::timeout(Duration::from_secs(2), async {
        while ticker
            .flight
            .as_ref()
            .is_some_and(|flight| !flight.finished())
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let decoded =
        SupportSnapshot::decode(&std::fs::read(path.join("SUPPORT-SNAPSHOT")).unwrap()).unwrap();
    assert_eq!(
        (
            path.join("SUPPORT-CONFIGURATION").exists(),
            decoded.incarnation,
            decoded.sampled_at.secs
        ),
        (
            false,
            crate::support::tests::configuration().incarnation,
            60
        )
    );
    std::fs::remove_dir_all(parent).unwrap();
}

#[test]
fn support_writer_self_checks() {
    let configuration = crate::support::tests::configuration();
    let bytes = configuration.encode().unwrap();
    assert_eq!(super::verify_configuration(&configuration, &bytes), Ok(()));
    let mut other = configuration.clone();
    other.listen_port += 1;
    assert_eq!(
        super::verify_configuration(&other, &bytes),
        Err(SupportError("support self check"))
    );
    let snapshot = crate::snapshot_from_observation(
        configuration.incarnation,
        Timestamp { secs: 0, nanos: 0 },
        &crate::support::tests::source(),
    )
    .unwrap();
    let bytes = snapshot.encode().unwrap();
    assert_eq!(super::verify_snapshot(&snapshot, &bytes), Ok(()));
    let mut other = snapshot;
    other.enrollment.sequence += 1;
    assert_eq!(
        super::verify_snapshot(&other, &bytes),
        Err(SupportError("support self check"))
    );
    let mut bad = bytes;
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        super::verify_snapshot(&other, &bad),
        Err(SupportError("support checksum"))
    );
    let path = scratch("support-missing-observation");
    let mut source = publisher(&path);
    source.cached = Arc::new(|| None);
    assert_eq!(
        source.publish(&NixOps, Kind::Snapshot, Timestamp { secs: 0, nanos: 0 }),
        Err(SupportError("support observation missing"))
    );
    assert!(!path.join("SUPPORT-SNAPSHOT").exists());
    std::fs::remove_dir_all(path).unwrap();
}
