// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::disallowed_methods,
    reason = "Real filesystem and process venue schedules require runtime tasks; simulator ordering is not their oracle"
)]

//! Shared-gate persistence, restart and concurrent principal schedules.

use super::{FixedClock, YieldPause, boot, rng};
use crate::authority::file_log::{DirState, FileLogOn, FileOps, Held, Kind, StdFileOps};
use crate::authority::intent::persistence::FileIntent;
use crate::authority::intent::tests as fixture;
use crate::authority::{self, AuthorityParts, IntentOperation, RunEnd, VolumeConfig};
use crate::wire::ErrorToken;
use granary_core::decisionlog::{DecisionLog as _, LogIoError};
use granary_core::enrollment::{ClientSpkiDigest, EnrollmentSet, PrincipalId, TenantName};
use granary_sim::fakes::{Faults, Sim};
use granary_sim::secure_random::SeededSecureRandom;
use std::fs::File;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

#[derive(Clone)]
pub(crate) struct Recording {
    real: Arc<StdFileOps>,
    calls: Arc<Mutex<Vec<&'static str>>>,
    fail: Arc<Mutex<Option<&'static str>>>,
    fail_ready: Arc<AtomicBool>,
}
impl Recording {
    fn call(&self, name: &'static str) -> io::Result<()> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(name);
        let mut fail = self.fail.lock().unwrap_or_else(PoisonError::into_inner);
        if fail.as_ref() == Some(&name) {
            *fail = None;
            Err(io::Error::other("injected sync failure"))
        } else {
            Ok(())
        }
    }
    #[cfg(all(feature = "overlay-fault-tests", feature = "crash-points"))]
    pub(crate) fn fail_next_sync(&self) {
        *self.fail.lock().unwrap() = Some("file-sync");
    }
    #[cfg(all(feature = "overlay-fault-tests", feature = "crash-points"))]
    pub(crate) fn sync_failure_fired(&self) -> bool {
        self.fail.lock().unwrap().is_none()
    }
    pub(crate) fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }
    pub(crate) fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}
impl FileOps for Recording {
    type File = File;
    fn check_state(&self) -> io::Result<()> {
        self.real.check_state()
    }
    fn stat_at(&self, n: &str) -> io::Result<Option<Kind>> {
        self.real.stat_at(n)
    }
    fn dir_state(&self) -> io::Result<DirState> {
        self.real.dir_state()
    }
    fn create_new(&self, n: &str) -> io::Result<File> {
        self.call("create")?;
        self.real.create_new(n)
    }
    fn open_rw(&self, n: &str) -> io::Result<File> {
        self.real.open_rw(n)
    }
    fn read_marker(&self, n: &str) -> io::Result<Vec<u8>> {
        self.real.read_marker(n)
    }
    fn read_all(&self, f: &File) -> io::Result<Vec<u8>> {
        self.real.read_all(f)
    }
    fn pwrite(&self, f: &File, at: u64, b: &[u8]) -> io::Result<usize> {
        self.call("write")?;
        self.real.pwrite(f, at, b)
    }
    fn sync_file(&self, f: &File) -> io::Result<()> {
        use std::os::unix::fs::FileExt as _;
        let mut magic = [0; 8];
        if self.fail_ready.load(Ordering::SeqCst)
            && f.read_at(&mut magic, 0)? == 8
            && magic == *b"GRNINSTO"
            && self.fail_ready.swap(false, Ordering::SeqCst)
        {
            return Err(io::Error::other("injected installed intent sync failure"));
        }
        self.call("file-sync")?;
        self.real.sync_file(f)
    }
    fn sync_dir(&self, d: Held) -> io::Result<()> {
        self.call("dir-sync")?;
        self.real.sync_dir(d)
    }
    fn truncate(&self, f: &File, n: u64) -> io::Result<()> {
        self.real.truncate(f, n)
    }
    fn link(&self, a: &str, b: &str) -> io::Result<()> {
        self.call("link")?;
        self.real.link(a, b)
    }
    fn unlink(&self, n: &str) -> io::Result<()> {
        self.real.unlink(n)
    }
    fn rename(&self, a: &str, b: &str) -> io::Result<()> {
        self.call("rename")?;
        self.real.rename(a, b)
    }
}
pub(crate) fn scratch() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    #[expect(
        clippy::disallowed_methods,
        reason = "process id only isolates test directories"
    )]
    let pid = std::process::id();
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let path = parent.join(format!(
        "intent-store-{pid}-{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}
pub(crate) fn enrolled() -> EnrollmentSet {
    let mut set = EnrollmentSet::empty();
    for n in [1, 2] {
        set.mint(
            PrincipalId::from_bytes([n; 16]),
            TenantName::new(b"tenant").unwrap(),
            ClientSpkiDigest::from_bytes([n; 32]),
        )
        .unwrap();
    }
    set
}
pub(crate) fn recording(path: &std::path::Path) -> Recording {
    Recording {
        real: Arc::new(StdFileOps::open(path, true).unwrap()),
        calls: Arc::default(),
        fail: Arc::default(),
        fail_ready: Arc::default(),
    }
}
pub(crate) fn recording_log(
    rec: Recording,
) -> (
    impl granary_core::decisionlog::DecisionLog,
    Arc<authority::IntentStore>,
) {
    let intents = FileIntent::store(Arc::new(rec.clone()));
    (FileLogOn::with_ops(rec), intents)
}
pub(crate) async fn start(
    rec: Recording,
    at: u8,
) -> (
    authority::AuthorityHandle,
    impl std::future::Future<Output = RunEnd>,
) {
    let (log, io) = recording_log(rec);
    let parts = AuthorityParts {
        admission: crate::Admission::chain_fixture(),
        log,
        store: Sim::new().node(0, Faults::none()),
        clock: FixedClock,
        rng: rng(1),
        secure_random: SeededSecureRandom::for_incarnation(1, 1),
        pause: YieldPause,
    };
    let configs = vec![VolumeConfig::new(fixture::volume(), fixture::keys()).with_intents(io)];
    let (handle, driver) = authority::start(parts, boot(at), configs).await.unwrap();
    (handle, driver.run())
}
pub(crate) async fn initialise_and_enroll(
    handle: &authority::AuthorityHandle,
) -> crate::wire::Outcome {
    handle.initialise(&fixture::volume()).await.unwrap();
    handle
        .maintain_intents(&fixture::volume(), &enrolled(), 0)
        .await
}

fn check(outcome: &crate::wire::Outcome, status: u16, token: Option<ErrorToken>) {
    assert_eq!(
        (outcome.status().as_u16(), outcome.error()),
        (status, token)
    );
}

#[tokio::test]
async fn intent_sync_order_readback_no_write_and_all_refusals_leave_identical_store() {
    let path = scratch();
    let rec = recording(&path);
    let (handle, driver) = start(rec.clone(), 1).await;
    let request = async {
        check(&initialise_and_enroll(&handle).await, 200, None);
        rec.clear();
        let principal = PrincipalId::from_bytes([1; 16]);
        check(
            &handle
                .intent(
                    &fixture::volume(),
                    principal,
                    IntentOperation::Ownership,
                    fixture::acquire(1, 2, 0),
                )
                .await,
            200,
            None,
        );
        let calls = rec.calls();
        let barriers: Vec<_> = calls
            .iter()
            .copied()
            .filter(|s| matches!(*s, "file-sync" | "rename" | "dir-sync"))
            .collect();
        assert_eq!(barriers, ["file-sync", "rename", "dir-sync"]);
        let state = std::fs::read(path.join("intent-test.intent")).unwrap();
        for (op, bytes, status, token) in [
            (
                IntentOperation::Ownership,
                fixture::acquire(1, 7, 0),
                409,
                Some(ErrorToken::IntentChanged),
            ),
            (
                IntentOperation::Ownership,
                fixture::acquire(2, 2, 0),
                409,
                Some(ErrorToken::IntentCursorChanged),
            ),
            (
                IntentOperation::Release,
                b"bad".to_vec(),
                400,
                Some(ErrorToken::BadRequest),
            ),
            (
                IntentOperation::Register,
                b"bad".to_vec(),
                400,
                Some(ErrorToken::BadRequest),
            ),
            (IntentOperation::Readback, Vec::new(), 200, None),
            (
                IntentOperation::Ownership,
                fixture::acquire(1, 2, 0),
                200,
                None,
            ),
        ] {
            rec.clear();
            check(
                &handle
                    .intent(&fixture::volume(), principal, op, bytes)
                    .await,
                status,
                token,
            );
            assert_eq!(
                (
                    std::fs::read(path.join("intent-test.intent")).unwrap(),
                    rec.calls()
                ),
                (state.clone(), Vec::new())
            );
        }
        handle.stop().await
    };
    let driving = tokio::spawn(driver);
    let run = request.await;
    let ended = driving.await.unwrap();
    assert_eq!((ended, run), (RunEnd::Stopped, RunEnd::Stopped));
    drop(handle);
    drop(rec);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn intent_failed_file_or_directory_sync_fences_and_same_boot_restart_refuses() {
    use tracing_subscriber::prelude::*;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(EventLayer(Arc::clone(&observed)));
    let _default = tracing::subscriber::set_default(subscriber);
    for seam in ["file-sync", "dir-sync"] {
        let path = scratch();
        let rec = recording(&path);
        let (handle, driver) = start(rec.clone(), 1).await;
        let request = async {
            check(&initialise_and_enroll(&handle).await, 200, None);
            *rec.fail.lock().unwrap() = Some(seam);
            check(
                &handle
                    .intent(
                        &fixture::volume(),
                        PrincipalId::from_bytes([1; 16]),
                        IntentOperation::Ownership,
                        fixture::acquire(1, 2, 0),
                    )
                    .await,
                503,
                Some(ErrorToken::Fenced),
            );
            let from = rec.calls().len();
            let unknown = granary_core::root::VolumeName::new("unknown".into()).unwrap();
            check(
                &handle
                    .intent(
                        &unknown,
                        PrincipalId::from_bytes([2; 16]),
                        IntentOperation::Readback,
                        Vec::new(),
                    )
                    .await,
                503,
                Some(ErrorToken::Fenced),
            );
            assert_eq!(rec.calls().len(), from);
        };
        let driving = tokio::spawn(driver);
        let () = request.await;
        let end = driving.await.unwrap();
        assert!(matches!(end, RunEnd::Fenced(_)));
        assert!(
            handle
                .watch_fence()
                .borrow()
                .as_ref()
                .is_some_and(|f| f.call == authority::LogCall::IntentStore
                    && f.cause == authority::FenceCause::Failed(LogIoError::SyncFailed))
        );
        drop(handle);
        drop(rec);
        let log = authority::FileLog::new(&path, true).unwrap();
        assert!(matches!(
            authority::marker_admits(log.read_marker().await.unwrap(), boot(1)),
            Err(authority::StartRefused::RunningInThisBoot)
        ));
        drop(log);
        std::fs::remove_dir_all(path).unwrap();
    }
    let events = observed.lock().unwrap();
    assert!(events.iter().any(
        |fields| fields.get("event").is_some_and(|s| s == "op.failed")
            && fields.get("kind").is_some_and(|s| s == "intent_ownership")
            && fields.get("error").is_some_and(|s| s.contains("fenced"))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "One concurrent timeline preserves both principals across restart"
)]
async fn intent_multi_principal_concurrent_acquire_register_release_restart_and_get_flood() {
    let path = scratch();
    let rec = recording(&path);
    let (handle, driver) = start(rec.clone(), 1).await;
    let request = async {
        check(&initialise_and_enroll(&handle).await, 200, None);
        rec.clear();
        let v = fixture::volume();
        let a = PrincipalId::from_bytes([1; 16]);
        let b = PrincipalId::from_bytes([2; 16]);
        let (a_grant, b_grant) = concurrent(
            &handle,
            &v,
            (a, IntentOperation::Ownership, fixture::acquire(1, 2, 0)),
            (b, IntentOperation::Ownership, fixture::acquire(1, 2, 0)),
        )
        .await;
        check(&a_grant, 200, None);
        check(&b_grant, 200, None);
        let r_a =
            granary_core::intent::encode_register(&[1; 16], 1, &[2; 16], 1, &fixture::root(3, &v))
                .unwrap();
        let r_b =
            granary_core::intent::encode_register(&[1; 16], 1, &[2; 16], 1, &fixture::root(4, &v))
                .unwrap();
        let (ra, rb) = concurrent(
            &handle,
            &v,
            (a, IntentOperation::Register, r_a),
            (b, IntentOperation::Register, r_b),
        )
        .await;
        check(&ra, 200, None);
        check(&rb, 200, None);
        let barriers: Vec<_> = rec
            .calls()
            .into_iter()
            .filter(|s| matches!(*s, "file-sync" | "rename" | "dir-sync"))
            .collect();
        assert_eq!(barriers, ["file-sync", "rename", "dir-sync"].repeat(4));
        let flooding_handle = handle.clone();
        let flooding_volume = v.clone();
        let flood = tokio::spawn(async move {
            for _ in 0..128 {
                check(
                    &flooding_handle
                        .intent(&flooding_volume, b, IntentOperation::Readback, Vec::new())
                        .await,
                    200,
                    None,
                );
            }
        });
        let release = granary_core::intent::encode_release(granary_core::intent::Release {
            writer: [1; 16],
            epoch: 1,
            instance: [2; 16],
            generation: 1,
        })
        .unwrap();
        let released = handle
            .intent(&v, a, IntentOperation::Release, release)
            .await;
        flood.await.unwrap();
        check(&released, 200, None);
        let roots = handle.intent_roots(&v).await.unwrap();
        assert_eq!(
            roots.iter().map(|r| r.bytes.to_vec()).collect::<Vec<_>>(),
            [fixture::root(4, &v)]
        );
        handle.stop().await
    };
    let driving = tokio::spawn(driver);
    let run = request.await;
    let ended = driving.await.unwrap();
    assert_eq!((ended, run), (RunEnd::Stopped, RunEnd::Stopped));
    drop(handle);
    drop(rec);
    let rec = recording(&path);
    let (handle, driver) = start(rec.clone(), 1).await;
    let request = async {
        for (n, count) in [(1, 0), (2, 1)] {
            let result = handle
                .intent(
                    &fixture::volume(),
                    PrincipalId::from_bytes([n; 16]),
                    IntentOperation::Readback,
                    Vec::new(),
                )
                .await;
            check(&result, 200, None);
            let read =
                granary_core::intent::decode_readback(result.body(), &fixture::volume(), |d, b| {
                    granary_store::crypto::check_signatures(d, b, &fixture::keys()).is_ok()
                })
                .unwrap();
            assert_eq!((read.cursor, read.rows.len()), (1, count));
        }
        handle.stop().await
    };
    let driving = tokio::spawn(driver);
    let run = request.await;
    let ended = driving.await.unwrap();
    assert_eq!((ended, run), (RunEnd::Stopped, RunEnd::Stopped));
    drop(handle);
    drop(rec);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intent_release_races_same_writer_takeover() {
    use granary_core::intent::{self, Ownership, OwnershipMode, ReceiptState, Release};

    let path = scratch();
    let (handle, driver) = start(recording(&path), 1).await;
    let driving = tokio::spawn(driver);
    check(&initialise_and_enroll(&handle).await, 200, None);
    let volume = fixture::volume();
    let principal = PrincipalId::from_bytes([1; 16]);
    let acquired = handle
        .intent(
            &volume,
            principal,
            IntentOperation::Ownership,
            fixture::acquire(1, 2, 0),
        )
        .await;
    check(&acquired, 200, None);
    let current = intent::decode_grant(acquired.body()).unwrap().receipt;
    let root = fixture::root(3, &volume);
    let register =
        intent::encode_register(&current.writer, current.epoch, &current.instance, 1, &root)
            .unwrap();
    let registered = handle
        .intent(&volume, principal, IntentOperation::Register, register)
        .await;
    check(&registered, 200, None);
    let current = intent::decode_receipt(registered.body()).unwrap();
    let release = intent::encode_release(Release {
        writer: current.writer,
        epoch: current.epoch,
        instance: current.instance,
        generation: current.generation,
    })
    .unwrap();
    let takeover = intent::encode_ownership(Ownership {
        writer: current.writer,
        instance: [3; 16],
        mode: OwnershipMode::Takeover {
            expected_epoch: current.epoch,
            generation: current.generation,
            state: current.state,
            recovery_ack: false,
        },
    })
    .unwrap();
    let (takeover, released) = concurrent(
        &handle,
        &volume,
        (principal, IntentOperation::Ownership, takeover),
        (principal, IntentOperation::Release, release.clone()),
    )
    .await;
    let replay = handle
        .intent(&volume, principal, IntentOperation::Release, release)
        .await;
    let roots = handle.intent_roots(&volume).await.unwrap();
    if takeover.status().as_u16() == 200 {
        let successor = intent::decode_grant(takeover.body()).unwrap().receipt;
        assert!(successor.epoch > current.epoch);
        assert_eq!(successor.instance, [3; 16]);
        for refused in [released, replay] {
            check(&refused, 409, Some(ErrorToken::IntentSuperseded));
            assert_eq!(intent::decode_receipt(refused.body()).unwrap(), successor);
        }
        assert_eq!(
            roots
                .iter()
                .map(|row| row.bytes.as_ref())
                .collect::<Vec<_>>(),
            [&root]
        );
    } else {
        check(&takeover, 409, Some(ErrorToken::IntentChanged));
        for accepted in [released, replay] {
            check(&accepted, 200, None);
            assert_eq!(
                intent::decode_receipt(accepted.body()).unwrap(),
                intent::Receipt {
                    state: ReceiptState::Released,
                    ..current
                }
            );
        }
        assert!(roots.is_empty());
    }
    assert_eq!(handle.stop().await, RunEnd::Stopped);
    assert_eq!(driving.await.unwrap(), RunEnd::Stopped);
    drop(handle);
    std::fs::remove_dir_all(path).unwrap();
}

#[cfg(feature = "crash-points")]
#[test]
#[ignore = "child process of the intent crash matrix"]
fn intent_crash_driver() {
    use crate::authority::crash::{self, Plan, Site};
    let path = PathBuf::from(std::env::var_os("GRANARY_INTENT_STATE").unwrap());
    let pipe = PathBuf::from(std::env::var_os("GRANARY_INTENT_PIPE").unwrap());
    let site = std::env::var("GRANARY_INTENT_CUT").unwrap();
    let operation = std::env::var("GRANARY_INTENT_OPERATION").unwrap();
    let plan = if site == "list" {
        Plan::List
    } else {
        Plan::Kill {
            site: Site::parse(&site).unwrap(),
            k: 1,
        }
    };
    crash::install(&pipe, plan).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    if operation == "offline-initialise" {
        let args = [
            "initialise".into(),
            "--state-dir".into(),
            path.as_os_str().to_owned(),
            "--volume".into(),
            fixture::volume().as_str().into(),
            "--accept-unsupported-filesystem".into(),
        ];
        let code = crate::run_lifecycle_command_line(
            &args,
            &mut SeededSecureRandom::for_incarnation(1, 1),
            || Ok(0),
            || Ok(boot(1)),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert_eq!(code, 0);
        return;
    }
    runtime.block_on(async {
        let rec = recording(&path);
        let (handle, driver) = start(rec, 1).await;
        let request = async {
            let p = PrincipalId::from_bytes([1; 16]);
            let body = std::fs::read(path.join("request")).unwrap();
            let op = match operation.as_str() {
                "acquire" | "takeover-live" | "takeover-released" => IntentOperation::Ownership,
                "register" => IntentOperation::Register,
                "release-live" | "release-released" => IntentOperation::Release,
                "maintain" => {
                    check(
                        &handle
                            .maintain_intents(&fixture::volume(), &enrolled(), 0)
                            .await,
                        200,
                        None,
                    );
                    let _end = handle.stop().await;
                    return;
                }
                "initialise" => {
                    handle.initialise(&fixture::volume()).await.unwrap();
                    let _end = handle.stop().await;
                    return;
                }
                _ => panic!("unknown harness operation"),
            };
            let result = handle.intent(&fixture::volume(), p, op, body).await;
            check(&result, 200, None);
            crash::note("INTENT answered durable");
            let _end = handle.stop().await;
        };
        let driving = tokio::spawn(driver);
        let () = request.await;
        let end = driving.await.unwrap();
        assert_eq!(end, RunEnd::Stopped);
    });
}

#[cfg(feature = "crash-points")]
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Linux authority venue: process crash/restart matrix"
)]
#[expect(
    clippy::disallowed_methods,
    clippy::too_many_lines,
    reason = "bounded polling only waits for the harness-owned child seam"
)]
fn intent_crash_cut_rows() {
    use crate::authority::crash::Site;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    let cuts = [
        Site::IntentPartialWrite,
        Site::IntentBeforeTemporary,
        Site::IntentTemporaryCreated,
        Site::IntentTemporaryWritten,
        Site::IntentFileSynced,
        Site::IntentRenamed,
        Site::IntentDirectorySynced,
        Site::IntentStateInstalled,
        Site::IntentBeforeReply,
        Site::IntentReplySent,
    ];
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut cases = 0;
    for operation in [
        "acquire",
        "takeover-live",
        "takeover-released",
        "register",
        "release-live",
        "release-released",
    ] {
        for cut in cuts.into_iter().map(Some).chain([None]) {
            let path = scratch();
            let mut p = if operation == "acquire" {
                crate::authority::intent::Principal::default()
            } else {
                fixture::owned(1)
            };
            if matches!(operation, "takeover-live" | "release-live") {
                let body = fixture::register(&p, 1, 1, 3);
                p = crate::authority::intent::transition(
                    Some(&p),
                    IntentOperation::Register,
                    &body,
                    &fixture::volume(),
                    &fixture::keys(),
                    fixture::now(),
                )
                .next
                .unwrap();
            }
            let bytes = match operation {
                "acquire" => fixture::acquire(1, 2, 0),
                "takeover-live" | "takeover-released" => {
                    fixture::takeover(p.rows.get(&[1; 16]).unwrap(), 5)
                }
                "register" => fixture::register(&p, 1, 1, 3),
                _ => fixture::release(&p, 1, 1),
            };
            let old = fixture::snapshot(p);
            let op = match operation {
                "register" => IntentOperation::Register,
                "release-live" | "release-released" => IntentOperation::Release,
                _ => IntentOperation::Ownership,
            };
            let next = crate::authority::intent::transition(
                old.principals.values().next(),
                op,
                &bytes,
                &fixture::volume(),
                &fixture::keys(),
                granary_core::clock::Clock::now(&FixedClock),
            )
            .next
            .unwrap();
            let mut new = old.clone();
            new.principals
                .insert(PrincipalId::from_bytes([1; 16]), next);
            let log = authority::FileLog::new(&path, true).unwrap();
            runtime.block_on(async {
                log.write_marker(&granary_core::runmarker::encode_marker(
                    &granary_core::runmarker::RunMarker::Clean,
                ))
                .await
                .unwrap();
                log.initialise(&granary_core::authlog::encode_envelope(
                    &granary_core::authlog::Envelope::new(fixture::volume(), old.epoch),
                ))
                .await
                .unwrap();
            });
            // These fixtures are validated and closed before the child takes custody.
            let io = log.intent_store();
            io.io.commit(&old).unwrap();
            drop(io);
            drop(log);
            std::fs::write(path.join("request"), &bytes).unwrap();
            let pipe = path.join("points");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "authority::tests::intents::intent_crash_driver",
                    "--ignored",
                    "--test-threads=1",
                ])
                .env("GRANARY_INTENT_STATE", &path)
                .env("GRANARY_INTENT_PIPE", &pipe)
                .env("GRANARY_INTENT_OPERATION", operation)
                .env(
                    "GRANARY_INTENT_CUT",
                    cut.map_or_else(|| "list".to_owned(), Site::name),
                )
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut reached = false;
            let mut done = false;
            for _ in 0..500 {
                let text = std::fs::read_to_string(&pipe).unwrap_or_default();
                if let Some(cut) = cut {
                    if text
                        .lines()
                        .any(|l| l == format!("REACHED {} 1", cut.name()))
                    {
                        reached = true;
                        break;
                    }
                } else if child
                    .try_wait()
                    .unwrap()
                    .is_some_and(|status| status.success())
                {
                    done = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if cut.is_some() {
                if !reached {
                    // Abort cleanup is not a crash-cut observation.
                    let _ = child.kill();
                    let _ = child.wait();
                }
                assert!(
                    reached,
                    "named seam did not fire: {operation} {cut:?}; got {:?}",
                    std::fs::read_to_string(&pipe)
                );
                // Only this harness-owned child is ever killed.
                child.kill().unwrap();
            } else {
                if !done {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                assert!(done, "disarmed control did not finish: {operation}");
            }
            child.wait().unwrap();
            let named = std::fs::read(path.join("intent-test.intent")).unwrap();
            let recovered = crate::authority::intent::codec::decode(
                named.as_slice(),
                &fixture::volume(),
                Some(old.epoch),
                &fixture::keys(),
            )
            .unwrap();
            // Process kill cannot erase page cache: rename has deterministically selected the new name.
            let installed = cut.is_none()
                || matches!(
                    cut,
                    Some(
                        Site::IntentRenamed
                            | Site::IntentDirectorySynced
                            | Site::IntentStateInstalled
                            | Site::IntentBeforeReply
                            | Site::IntentReplySent
                    )
                );
            assert_eq!(
                &recovered,
                if installed { &new } else { &old },
                "{operation} {cut:?}"
            );
            let log = authority::FileLog::new(&path, true).unwrap();
            runtime.block_on(async {
                let marker = log.read_marker().await.unwrap();
                if cut.is_some() {
                    assert!(matches!(
                        authority::marker_admits(marker, boot(1)),
                        Err(authority::StartRefused::RunningInThisBoot)
                    ));
                } else {
                    authority::marker_admits(marker, boot(1)).unwrap();
                }
            });
            drop(log);
            // A changed boot here models recovery admission; it is not a host reboot claim.
            runtime.block_on(async {
                let rec = recording(&path);
                let (handle, driver) = start(rec, 2).await;
                let request = async {
                    let result = handle
                        .intent(
                            &fixture::volume(),
                            PrincipalId::from_bytes([1; 16]),
                            op,
                            bytes,
                        )
                        .await;
                    check(&result, 200, None);
                    let _end = handle.stop().await;
                };
                let driving = tokio::spawn(driver);
                let () = request.await;
                let end = driving.await.unwrap();
                assert_eq!(end, RunEnd::Stopped);
            });
            cases += 1;
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    assert_eq!(cases, 66);
}

#[tokio::test]
async fn intent_missing_corrupt_and_mismatched_state_never_resets_allocator() {
    for damage in ["missing", "corrupt", "mismatch"] {
        let path = scratch();
        let log = authority::FileLog::new(&path, true).unwrap();
        let epoch = granary_core::authlog::Epoch::from_bytes([8; 16]);
        log.write_marker(&granary_core::runmarker::encode_marker(
            &granary_core::runmarker::RunMarker::Clean,
        ))
        .await
        .unwrap();
        log.initialise(&granary_core::authlog::encode_envelope(
            &granary_core::authlog::Envelope::new(fixture::volume(), epoch),
        ))
        .await
        .unwrap();
        if damage == "corrupt" {
            std::fs::write(path.join("intent-test.intent"), b"corrupt").unwrap();
        }
        let old = fixture::snapshot(fixture::owned(1));
        if damage == "mismatch" {
            log.intent_store().io.commit(&old).unwrap();
        }
        drop(log);
        let rec = recording(&path);
        let (handle, driver) = start(rec.clone(), 1).await;
        let request = async {
            check(
                &handle
                    .intent(
                        &fixture::volume(),
                        PrincipalId::from_bytes([1; 16]),
                        IntentOperation::Ownership,
                        fixture::acquire(1, 2, 0),
                    )
                    .await,
                503,
                Some(ErrorToken::Unavailable),
            );
            assert!(handle.intent_roots(&fixture::volume()).await.is_err());
            let calls = rec.calls();
            let maintenance = handle
                .maintain_intents(&fixture::volume(), &enrolled(), 0)
                .await;
            assert_eq!(
                (
                    maintenance.status().as_u16(),
                    maintenance.error(),
                    rec.calls()
                ),
                (503, Some(ErrorToken::Unavailable), calls)
            );
            let before = std::fs::read(path.join("intent-test.intent")).ok();
            assert!(matches!(
                handle.initialise(&fixture::volume()).await.unwrap(),
                authority::Initialised::Kept { .. }
            ));
            check(
                &handle
                    .intent(
                        &fixture::volume(),
                        PrincipalId::from_bytes([1; 16]),
                        IntentOperation::Readback,
                        vec![],
                    )
                    .await,
                503,
                Some(ErrorToken::Unavailable),
            );
            assert_eq!(std::fs::read(path.join("intent-test.intent")).ok(), before);
            handle.stop().await
        };
        let driving = tokio::spawn(driver);
        let run = request.await;
        let end = driving.await.unwrap();
        assert_eq!((end, run), (RunEnd::Stopped, RunEnd::Stopped));
        drop(handle);
        drop(rec);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[tokio::test]
async fn intent_only_files_require_marker_and_are_observed_for_unfence() {
    let mut cases = 0;
    for name in ["intent-test.intent", "intent-test.intent.tmp"] {
        let path = scratch();
        let log = authority::FileLog::new(&path, true).unwrap();
        authority::marker_admits(log.read_marker().await.unwrap(), boot(1)).unwrap();
        std::fs::write(path.join(name), b"present").unwrap();
        assert!(matches!(
            authority::marker_admits(log.read_marker().await.unwrap(), boot(1)),
            Err(authority::StartRefused::StateDirectoryOccupied)
        ));
        let times = log.state_times().unwrap();
        assert_eq!(times.files.len(), 1);
        let after = times
            .files
            .iter()
            .chain(&times.directories)
            .map(|(s, _)| *s)
            .max()
            .unwrap()
            + 1;
        crate::lifecycle::unfence_log(&log, after, &times, boot(1))
            .await
            .unwrap();
        let marker = log.read_marker().await.unwrap();
        let mut changed = times.clone();
        changed.files.first_mut().unwrap().0 = after;
        assert!(
            crate::lifecycle::unfence_log(&log, after, &changed, boot(1))
                .await
                .unwrap_err()
                .to_string()
                .contains("unfence requires a host reboot")
        );
        assert_eq!(log.read_marker().await.unwrap(), marker);
        cases += 1;
        drop(log);
        std::fs::remove_dir_all(path).unwrap();
    }
    assert_eq!(cases, 2);
}

#[derive(Clone)]
struct EventLayer(Arc<Mutex<Vec<std::collections::BTreeMap<String, String>>>>);
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Fields(std::collections::BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().to_owned(), value.to_owned());
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }
        }
        let mut fields = Fields(std::collections::BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

#[tokio::test]
async fn intent_log_initialisation_rebind_emits_store_success_and_failure_events() {
    use tracing_subscriber::prelude::*;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(EventLayer(Arc::clone(&observed)));
    let _default = tracing::subscriber::set_default(subscriber);
    let mut results = Vec::new();
    for seam in [None, Some("file-sync"), Some("dir-sync")] {
        let path = scratch();
        let log = authority::FileLog::new(&path, true).unwrap();
        let old = fixture::snapshot(fixture::owned(1));
        log.write_marker(&granary_core::runmarker::encode_marker(
            &granary_core::runmarker::RunMarker::Clean,
        ))
        .await
        .unwrap();
        log.intent_store().io.commit(&old).unwrap();
        drop(log);
        let rec = recording(&path);
        let (handle, driver) = start(rec.clone(), 1).await;
        let driving = tokio::spawn(driver);
        observed.lock().unwrap().clear();
        *rec.fail.lock().unwrap() = seam;
        let answer = handle.initialise(&fixture::volume()).await;
        if seam.is_none() {
            let epoch = match answer {
                Ok(authority::Initialised::Created { epoch }) => epoch,
                other => panic!("expected new bound log, got {other:?}"),
            };
            let bytes = std::fs::read(path.join("intent-test.intent")).unwrap();
            let new = crate::authority::intent::codec::decode(
                bytes.as_slice(),
                &fixture::volume(),
                Some(epoch),
                &fixture::keys(),
            )
            .unwrap();
            assert_eq!(new.principals, old.principals);
            assert_ne!(epoch, old.epoch);
        } else {
            assert!(
                matches!(answer, Err(authority::InitialiseError::Fenced)),
                "got {answer:?}"
            );
        }
        let events = observed
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.get("kind").is_some_and(|kind| kind == "intent_store"))
            .map(|f| {
                (
                    f.get("event").cloned(),
                    f.get("outcome").cloned(),
                    f.get("class").cloned(),
                )
            })
            .collect::<Vec<_>>();
        results.push(events);
        let _end = handle.stop().await;
        let _driven = driving.await.unwrap();
        drop(handle);
        drop(rec);
        std::fs::remove_dir_all(path).unwrap();
    }
    let begin = (Some("op.begin".to_owned()), None, None);
    let ok = (Some("op.end".to_owned()), Some("ok".to_owned()), None);
    let failed = (Some("op.failed".to_owned()), None, Some("io".to_owned()));
    let end_failed = (Some("op.end".to_owned()), Some("failed".to_owned()), None);
    assert_eq!(
        results,
        vec![
            vec![begin.clone(), ok],
            vec![begin.clone(), failed.clone(), end_failed.clone()],
            vec![begin, failed, end_failed]
        ]
    );
}

#[cfg(feature = "crash-points")]
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Linux authority venue: explicit initialise/rebind/eviction cuts"
)]
#[expect(
    clippy::disallowed_methods,
    clippy::too_many_lines,
    reason = "bounded polling waits only for the harness-owned child"
)]
fn intent_lifecycle_crash_rows() {
    use crate::authority::crash::Site;
    use std::process::{Command, Stdio};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut cases = 0;
    for site in [
        Site::IntentProvisioned,
        Site::IntentProvisionLogSynced,
        Site::IntentRebound,
        Site::IntentEvicted,
    ] {
        for armed in [false, true] {
            let path = scratch();
            let old = fixture::snapshot(fixture::owned(1));
            let log = authority::FileLog::new(&path, true).unwrap();
            runtime
                .block_on(log.write_marker(&granary_core::runmarker::encode_marker(
                    &granary_core::runmarker::RunMarker::Clean,
                )))
                .unwrap();
            if site == Site::IntentEvicted {
                runtime
                    .block_on(log.initialise(&granary_core::authlog::encode_envelope(
                        &granary_core::authlog::Envelope::new(fixture::volume(), old.epoch),
                    )))
                    .unwrap();
            }
            log.intent_store().io.commit(&old).unwrap();
            drop(log);
            std::fs::write(path.join("request"), []).unwrap();
            let pipe = path.join("points");
            let operation = if site == Site::IntentEvicted {
                "maintain"
            } else {
                "initialise"
            };
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "authority::tests::intents::intent_crash_driver",
                    "--ignored",
                    "--test-threads=1",
                ])
                .env("GRANARY_INTENT_STATE", &path)
                .env("GRANARY_INTENT_PIPE", &pipe)
                .env("GRANARY_INTENT_OPERATION", operation)
                .env(
                    "GRANARY_INTENT_CUT",
                    if armed { site.name() } else { "list".into() },
                )
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut reached = false;
            let mut done = false;
            for _ in 0..500 {
                let lines = std::fs::read_to_string(&pipe).unwrap_or_default();
                if armed
                    && lines
                        .lines()
                        .any(|l| l == format!("REACHED {} 1", site.name()))
                {
                    reached = true;
                    break;
                }
                if !armed && child.try_wait().unwrap().is_some_and(|s| s.success()) {
                    done = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if armed {
                if !reached {
                    // Abort cleanup is not a crash-cut observation.
                    let _ = child.kill();
                    let _ = child.wait();
                }
                assert!(
                    reached,
                    "{site:?} did not fire; got {:?}",
                    std::fs::read_to_string(&pipe)
                );
                child.kill().unwrap();
            } else {
                if !done {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                assert!(done, "{site:?} disarmed control did not finish");
            }
            child.wait().unwrap();
            let bytes = std::fs::read(path.join("intent-test.intent")).unwrap();
            let named = crate::authority::intent::codec::decode(
                bytes.as_slice(),
                &fixture::volume(),
                None,
                &fixture::keys(),
            )
            .unwrap();
            let own = named
                .principals
                .get(&PrincipalId::from_bytes([1; 16]))
                .unwrap();
            assert_eq!(
                (own.h, own.rows.len()),
                (1, usize::from(site != Site::IntentEvicted))
            );
            runtime.block_on(async {
                let rec = recording(&path);
                let (handle, driver) = start(rec, 2).await;
                let request = async {
                    if !path.join("intent-test.log").exists() {
                        let before = std::fs::read(path.join("intent-test.intent")).unwrap();
                        check(
                            &handle
                                .maintain_intents(&fixture::volume(), &enrolled(), 0)
                                .await,
                            503,
                            Some(ErrorToken::Unavailable),
                        );
                        check(
                            &handle
                                .intent(
                                    &fixture::volume(),
                                    PrincipalId::from_bytes([1; 16]),
                                    IntentOperation::Readback,
                                    Vec::new(),
                                )
                                .await,
                            503,
                            Some(ErrorToken::Unavailable),
                        );
                        assert_eq!(
                            std::fs::read(path.join("intent-test.intent")).unwrap(),
                            before
                        );
                        assert!(!path.join("intent-test.log").exists());
                    }

                    check(&initialise_and_enroll(&handle).await, 200, None);
                    let result = handle
                        .intent(
                            &fixture::volume(),
                            PrincipalId::from_bytes([1; 16]),
                            IntentOperation::Readback,
                            Vec::new(),
                        )
                        .await;
                    check(&result, 200, None);
                    let read = granary_core::intent::decode_readback(
                        result.body(),
                        &fixture::volume(),
                        |_, _| true,
                    )
                    .unwrap();
                    assert_eq!(read.cursor, 1);
                    let _end = handle.stop().await;
                };
                let driving = tokio::spawn(driver);
                let () = request.await;
                let end = driving.await.unwrap();
                assert_eq!(end, RunEnd::Stopped);
            });
            cases += 1;
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    assert_eq!(cases, 8);
}

async fn concurrent(
    handle: &authority::AuthorityHandle,
    volume: &granary_core::root::VolumeName,
    (left, left_op, left_body): (PrincipalId, IntentOperation, Vec<u8>),
    (right, right_op, right_body): (PrincipalId, IntentOperation, Vec<u8>),
) -> (crate::wire::Outcome, crate::wire::Outcome) {
    let cloned = handle.clone();
    let v = volume.clone();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let first_barrier = Arc::clone(&barrier);
    let first = tokio::spawn(async move {
        first_barrier.wait().await;
        cloned.intent(&v, left, left_op, left_body).await
    });
    barrier.wait().await;
    let second = handle.intent(volume, right, right_op, right_body).await;
    (first.await.unwrap(), second)
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Paired startup cases retain identical committed state and custody fixtures"
)]
async fn intent_startup_barriers_and_leftover_temporaries_never_promote_unknown_state() {
    let mut cases = 0;
    for mode in ["valid-temp", "unsafe-temp", "installed-sync-failed"] {
        let path = scratch();
        let log = authority::FileLog::new(&path, true).unwrap();
        let old = fixture::snapshot(fixture::owned(1));
        log.write_marker(&granary_core::runmarker::encode_marker(
            &granary_core::runmarker::RunMarker::Clean,
        ))
        .await
        .unwrap();
        log.initialise(&granary_core::authlog::encode_envelope(
            &granary_core::authlog::Envelope::new(fixture::volume(), old.epoch),
        ))
        .await
        .unwrap();
        log.intent_store().io.commit(&old).unwrap();
        drop(log);
        if mode == "valid-temp" {
            let mut temporary = old.clone();
            temporary.principals.values_mut().next().unwrap().h = 99;
            std::fs::write(
                path.join("intent-test.intent.tmp"),
                fixture::encoded(&temporary),
            )
            .unwrap();
            std::fs::set_permissions(
                path.join("intent-test.intent.tmp"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        if mode == "unsafe-temp" {
            std::os::unix::fs::symlink("intent-test.intent", path.join("intent-test.intent.tmp"))
                .unwrap();
        }
        let rec = recording(&path);
        rec.fail_ready
            .store(mode == "installed-sync-failed", Ordering::SeqCst);
        let io = FileIntent::store(Arc::new(rec.clone()));
        let parts = AuthorityParts {
            admission: crate::Admission::chain_fixture(),
            log: FileLogOn::with_ops(rec.clone()),
            store: Sim::new().node(0, Faults::none()),
            clock: FixedClock,
            rng: rng(1),
            secure_random: SeededSecureRandom::for_incarnation(1, 1),
            pause: YieldPause,
        };
        let result = authority::start(
            parts,
            boot(1),
            vec![VolumeConfig::new(fixture::volume(), fixture::keys()).with_intents(io)],
        )
        .await;
        drop(rec);
        if mode == "valid-temp" {
            let (handle, driver) = result.unwrap();
            let driving = tokio::spawn(driver.run());
            let answer = handle
                .intent(
                    &fixture::volume(),
                    PrincipalId::from_bytes([1; 16]),
                    IntentOperation::Readback,
                    Vec::new(),
                )
                .await;
            check(&answer, 200, None);
            assert_eq!(
                granary_core::intent::decode_readback(
                    answer.body(),
                    &fixture::volume(),
                    |doc, signed| granary_store::crypto::check_signatures(
                        doc,
                        signed,
                        &fixture::keys()
                    )
                    .is_ok()
                )
                .unwrap()
                .cursor,
                1
            );
            assert!(!path.join("intent-test.intent.tmp").exists());
            assert_eq!(
                std::fs::read(path.join("intent-test.intent")).unwrap(),
                fixture::encoded(&old)
            );
            assert_eq!(handle.stop().await, RunEnd::Stopped);
            assert_eq!(driving.await.unwrap(), RunEnd::Stopped);
            drop(handle);
        } else {
            assert!(
                matches!(result, Err(authority::StartRefused::Fenced(_))),
                "expected intent startup fence"
            );
            let log = authority::FileLog::new(&path, true).unwrap();
            let marker = log.read_marker().await.unwrap();
            assert!(matches!(
                authority::marker_admits(marker, boot(1)),
                Err(authority::StartRefused::RunningInThisBoot)
            ));
            drop(log);
        }
        cases += 1;
        std::fs::remove_dir_all(path).unwrap();
    }
    assert_eq!(cases, 3);
}

#[tokio::test]
async fn intent_corrupt_intent_only_state_cannot_be_reprovisioned_without_known_h() {
    let path = scratch();
    let log = authority::FileLog::new(&path, true).unwrap();
    log.write_marker(&granary_core::runmarker::encode_marker(
        &granary_core::runmarker::RunMarker::Clean,
    ))
    .await
    .unwrap();
    std::fs::write(path.join("intent-test.intent"), b"corrupt allocator").unwrap();
    std::fs::set_permissions(
        path.join("intent-test.intent"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    drop(log);
    let rec = recording(&path);
    let (handle, driver) = start(rec.clone(), 1).await;
    let driving = tokio::spawn(driver);
    rec.clear();
    assert_eq!(
        handle.initialise(&fixture::volume()).await,
        Err(authority::InitialiseError::IntentUnavailable)
    );
    assert_eq!(
        (
            std::fs::read(path.join("intent-test.intent")).unwrap(),
            rec.calls()
        ),
        (b"corrupt allocator".to_vec(), Vec::new())
    );
    assert!(!path.join("intent-test.log").exists());
    assert_eq!(handle.stop().await, RunEnd::Stopped);
    assert_eq!(driving.await.unwrap(), RunEnd::Stopped);
    drop(handle);
    drop(rec);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn explicit_initialise_creates_snapshot_and_maintenance_retry_does_not_write() {
    let path = scratch();
    let rec = recording(&path);
    let (handle, driver) = start(rec.clone(), 1).await;
    let request = async {
        rec.clear();
        check(
            &handle
                .maintain_intents(&fixture::volume(), &enrolled(), 0)
                .await,
            503,
            Some(ErrorToken::Unavailable),
        );
        assert!(rec.calls().is_empty());
        assert!(!path.join("intent-test.log").exists());
        assert!(!path.join("intent-test.intent").exists());

        let epoch = match handle.initialise(&fixture::volume()).await.unwrap() {
            authority::Initialised::Created { epoch } => epoch,
            other @ authority::Initialised::Kept { .. } => panic!("expected create: {other:?}"),
        };
        assert!(path.join("intent-test.intent").exists());
        let bytes = std::fs::read(path.join("intent-test.intent")).unwrap();
        let state = crate::authority::intent::codec::decode(
            bytes.as_slice(),
            &fixture::volume(),
            Some(epoch),
            &fixture::keys(),
        )
        .unwrap();
        assert!(state.principals.is_empty());
        check(
            &handle
                .maintain_intents(&fixture::volume(), &enrolled(), 0)
                .await,
            200,
            None,
        );
        rec.clear();
        check(
            &handle
                .maintain_intents(&fixture::volume(), &enrolled(), 0)
                .await,
            200,
            None,
        );
        assert!(
            rec.calls().is_empty(),
            "idempotent maintenance must not commit"
        );
        handle.stop().await
    };
    let driving = tokio::spawn(driver);
    let stopped = request.await;
    let end = driving.await.unwrap();
    assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn round1_buffered_commit_and_no_change_retries_do_not_write() {
    let path = scratch();
    let rec = recording(&path);
    let (handle, driver) = start(rec.clone(), 1).await;
    let request = async {
        check(&initialise_and_enroll(&handle).await, 200, None);
        rec.clear();
        let principal = PrincipalId::from_bytes([1; 16]);
        let q = fixture::acquire(1, 2, 0);
        check(
            &handle
                .intent(
                    &fixture::volume(),
                    principal,
                    IntentOperation::Ownership,
                    q.clone(),
                )
                .await,
            200,
            None,
        );
        assert_eq!(
            rec.calls().iter().filter(|&&c| c == "write").count(),
            1,
            "small snapshot must be one buffered write"
        );
        check(
            &handle
                .intent(
                    &fixture::volume(),
                    principal,
                    IntentOperation::Release,
                    fixture::release(&fixture::owned(1), 1, 1),
                )
                .await,
            200,
            None,
        );
        for (op, body) in [
            (IntentOperation::Ownership, q),
            (
                IntentOperation::Release,
                fixture::release(&fixture::owned(1), 1, 1),
            ),
            (IntentOperation::Readback, vec![]),
        ] {
            rec.clear();
            check(
                &handle.intent(&fixture::volume(), principal, op, body).await,
                200,
                None,
            );
            assert!(rec.calls().is_empty(), "replay/read must not commit");
        }
        handle.stop().await
    };
    let driving = tokio::spawn(driver);
    let stopped = request.await;
    let end = driving.await.unwrap();
    assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn round1_request_clones_no_snapshot_and_validates_only_changed_principal() {
    use crate::authority::intent::{SNAPSHOT_CLONES, codec::PRINCIPAL_VALIDATIONS};
    let path = scratch();
    let rec = recording(&path);
    let (handle, driver) = start(rec, 1).await;
    let request = async {
        check(&initialise_and_enroll(&handle).await, 200, None);
        SNAPSHOT_CLONES.store(0, Ordering::SeqCst);
        PRINCIPAL_VALIDATIONS.store(0, Ordering::SeqCst);
        check(
            &handle
                .intent(
                    &fixture::volume(),
                    PrincipalId::from_bytes([1; 16]),
                    IntentOperation::Ownership,
                    fixture::acquire(1, 2, 0),
                )
                .await,
            200,
            None,
        );
        assert_eq!(SNAPSHOT_CLONES.load(Ordering::SeqCst), 0);
        assert_eq!(PRINCIPAL_VALIDATIONS.load(Ordering::SeqCst), 1);
        handle.stop().await
    };
    let driving = tokio::spawn(driver);
    let stopped = request.await;
    let end = driving.await.unwrap();
    assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn round1_shared_intent_status_mapping() {
    for (token, status) in [
        (ErrorToken::UnknownVolume, 404),
        (ErrorToken::Fenced, 503),
        (ErrorToken::Stopped, 503),
        (ErrorToken::Unavailable, 503),
    ] {
        let super::super::intent_worker::ResultValue::Answer(outcome) =
            super::super::intent_worker::refused(token)
        else {
            panic!("refusal must be an answer")
        };
        check(&outcome, status, Some(token));
    }
}

#[tokio::test]
async fn round1_corrupt_initialise_and_disabled_store_are_non_fencing() {
    for enabled in [false, true] {
        let path = scratch();
        let rec = recording(&path);
        let io = FileIntent::store(Arc::new(rec.clone()));
        if enabled {
            std::fs::write(path.join("intent-test.intent"), b"corrupt allocator").unwrap();
        }
        let log = FileLogOn::with_ops(rec.clone());
        log.write_marker(&granary_core::runmarker::encode_marker(
            &granary_core::runmarker::RunMarker::Clean,
        ))
        .await
        .unwrap();
        let config = VolumeConfig::new(fixture::volume(), fixture::keys());
        let config = if enabled {
            config.with_intents(io)
        } else {
            config
        };
        let parts = AuthorityParts {
            admission: crate::Admission::chain_fixture(),
            log,
            store: Sim::new().node(0, Faults::none()),
            clock: FixedClock,
            rng: rng(1),
            secure_random: SeededSecureRandom::for_incarnation(1, 1),
            pause: YieldPause,
        };
        let (handle, driver) = authority::start(parts, boot(1), vec![config])
            .await
            .unwrap();
        let request = async {
            let answer = handle.initialise(&fixture::volume()).await;
            if enabled {
                assert_eq!(answer, Err(authority::InitialiseError::IntentUnavailable));
                assert!(!path.join("intent-test.log").exists());
            } else {
                assert!(answer.is_ok());
            }
            check(
                &handle
                    .intent(
                        &fixture::volume(),
                        PrincipalId::from_bytes([1; 16]),
                        IntentOperation::Readback,
                        vec![],
                    )
                    .await,
                503,
                Some(ErrorToken::Unavailable),
            );
            handle.stop().await
        };
        let driving = tokio::spawn(driver.run());
        let stopped = request.await;
        let end = driving.await.unwrap();
        assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[tokio::test]
async fn round1_failed_buffered_write_never_retries_on_drop() {
    let path = scratch();
    let rec = recording(&path);
    let (handle, driver) = start(rec.clone(), 1).await;
    let request = async {
        check(&initialise_and_enroll(&handle).await, 200, None);
        rec.clear();
        *rec.fail.lock().unwrap() = Some("write");
        check(
            &handle
                .intent(
                    &fixture::volume(),
                    PrincipalId::from_bytes([1; 16]),
                    IntentOperation::Ownership,
                    fixture::acquire(1, 2, 0),
                )
                .await,
            503,
            Some(ErrorToken::Fenced),
        );
        assert_eq!(
            rec.calls(),
            ["create", "write"],
            "no Drop flush or sync after write failure"
        );
        handle.stop().await
    };
    let driving = tokio::spawn(driver);
    let stopped = request.await;
    let end = driving.await.unwrap();
    assert!(matches!(
        (end, stopped),
        (RunEnd::Fenced(_), RunEnd::Fenced(_))
    ));
    std::fs::remove_dir_all(path).unwrap();
}

#[cfg(feature = "crash-points")]
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires Linux process crash venue"
)]
#[expect(
    clippy::disallowed_methods,
    clippy::too_many_lines,
    reason = "bounded waits and kills only for harness-owned children"
)]
fn round1_initialise_snapshot_first_crash_rows() {
    use crate::authority::crash::Site;
    use std::process::{Command, Stdio};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for operation in ["initialise", "offline-initialise"] {
        for prior in [false, true] {
            for cut in [
                Some(Site::IntentBeforeTemporary),
                Some(Site::IntentTemporaryCreated),
                Some(Site::IntentPartialWrite),
                Some(Site::IntentTemporaryWritten),
                Some(Site::IntentFileSynced),
                Some(Site::IntentRenamed),
                Some(Site::IntentDirectorySynced),
                Some(Site::IntentRebound),
                Some(Site::IntentProvisioned),
                Some(Site::IntentProvisionLogSynced),
                None,
            ]
            .into_iter()
            .filter(|cut| operation != "offline-initialise" || *cut != Some(Site::IntentRebound))
            {
                let path = scratch();
                let mut old = fixture::snapshot(fixture::owned(1));
                let p = old.principals.values().next().unwrap();
                let registered = crate::authority::intent::transition(
                    Some(p),
                    IntentOperation::Register,
                    &fixture::register(p, 1, 1, 3),
                    &fixture::volume(),
                    &fixture::keys(),
                    fixture::now(),
                )
                .next
                .unwrap();
                *old.principals.values_mut().next().unwrap() = registered;
                let log = authority::FileLog::new(&path, true).unwrap();
                runtime
                    .block_on(log.write_marker(&granary_core::runmarker::encode_marker(
                        &granary_core::runmarker::RunMarker::Clean,
                    )))
                    .unwrap();
                if prior {
                    log.intent_store().io.commit(&old).unwrap();
                }
                drop(log);
                std::fs::write(path.join("request"), []).unwrap();
                let pipe = path.join("points");
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "authority::tests::intents::intent_crash_driver",
                        "--ignored",
                        "--test-threads=1",
                    ])
                    .env("GRANARY_INTENT_STATE", &path)
                    .env("GRANARY_INTENT_PIPE", &pipe)
                    .env("GRANARY_INTENT_OPERATION", operation)
                    .env(
                        "GRANARY_INTENT_CUT",
                        cut.map_or_else(|| "list".to_owned(), Site::name),
                    )
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let mut reached = false;
                for _ in 0..500 {
                    if let Some(site) = cut {
                        if std::fs::read_to_string(&pipe)
                            .unwrap_or_default()
                            .lines()
                            .any(|l| l == format!("REACHED {} 1", site.name()))
                        {
                            reached = true;
                            break;
                        }
                    } else if child
                        .try_wait()
                        .unwrap()
                        .is_some_and(|status| status.success())
                    {
                        reached = true;
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                if cut.is_some() || !reached {
                    child.kill().unwrap();
                }
                child.wait().unwrap();
                assert!(reached, "{operation} {cut:?} never reached its cut");
                let named = std::fs::read(path.join("intent-test.intent")).ok();
                if let Some(bytes) = named {
                    let decoded = crate::authority::intent::codec::decode(
                        bytes.as_slice(),
                        &fixture::volume(),
                        None,
                        &fixture::keys(),
                    )
                    .unwrap();
                    if prior {
                        assert_eq!(decoded.principals, old.principals);
                    } else {
                        assert!(decoded.principals.is_empty());
                    }
                } else {
                    assert!(!prior);
                }
                let (handle, driver) = runtime.block_on(start(recording(&path), 2));
                runtime.block_on(async {
                    let request = async {
                        handle.initialise(&fixture::volume()).await.unwrap();
                        let result = handle
                            .intent(
                                &fixture::volume(),
                                PrincipalId::from_bytes([1; 16]),
                                IntentOperation::Readback,
                                vec![],
                            )
                            .await;
                        check(&result, 200, None);
                        let read = granary_core::intent::decode_readback(
                            result.body(),
                            &fixture::volume(),
                            |_, _| true,
                        )
                        .unwrap();
                        assert_eq!(
                            (read.cursor, read.rows.len()),
                            if prior { (1, 1) } else { (0, 0) }
                        );
                        handle.stop().await
                    };
                    let driving = tokio::spawn(driver);
                    let stopped = request.await;
                    let end = driving.await.unwrap();
                    assert_eq!((end, stopped), (RunEnd::Stopped, RunEnd::Stopped));
                });
                std::fs::remove_dir_all(path).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn split_round1_same_epoch_initialise_commits_snapshot() {
    use crate::authority::{gate::LogGate, intent_worker::Intents, worker::Engine};
    let path = scratch();
    let rec = recording(&path);
    let io = FileIntent::store(Arc::new(rec.clone()));
    let old = fixture::snapshot(fixture::owned(1));
    io.io.commit(&old).unwrap();
    let intents = Intents::load(Some(io), &fixture::volume(), &fixture::keys());
    rec.clear();
    let log = FileLogOn::with_ops(rec.clone());
    let random = Mutex::new(SeededSecureRandom::for_incarnation(1, 1));
    let rng = Mutex::new(rng(1));
    let gate = LogGate::default();
    let shared = authority::Shared::default();
    let engine = Engine {
        log: &log,
        store: &(),
        clock: &FixedClock,
        rng: &rng,
        secure_random: &random,
        pause: &YieldPause,
        gate: &gate,
        shared: &shared,
    };
    intents
        .rebind(&engine, &fixture::volume(), old.epoch)
        .await
        .unwrap();
    assert_eq!(
        rec.calls(),
        ["create", "write", "file-sync", "rename", "dir-sync"]
    );
    assert_eq!(
        std::fs::read(path.join("intent-test.intent")).unwrap(),
        fixture::encoded(&old)
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the lifecycle matrix checks protected bytes, writes and explicit recovery"
)]
async fn maintenance_requires_existing_matching_pair_and_preserves_orphans() {
    use granary_core::authlog::{Envelope, Epoch, encode_envelope};
    let mut cases = 0;
    for mode in [
        "neither",
        "orphan",
        "orphan-corrupt",
        "temporary-only",
        "missing",
        "corrupt",
        "mismatch",
        "valid",
    ] {
        let path = scratch();
        let log = authority::FileLog::new(&path, true).unwrap();
        let owned = fixture::owned(1);
        let registered = crate::authority::intent::transition(
            Some(&owned),
            IntentOperation::Register,
            &fixture::register(&owned, 1, 1, 3),
            &fixture::volume(),
            &fixture::keys(),
            fixture::now(),
        )
        .next
        .unwrap();
        let old = fixture::snapshot(registered);
        let has_log = matches!(mode, "missing" | "corrupt" | "mismatch" | "valid");
        log.write_marker(&granary_core::runmarker::encode_marker(
            &granary_core::runmarker::RunMarker::Clean,
        ))
        .await
        .unwrap();
        if has_log {
            let epoch = if mode == "mismatch" {
                Epoch::from_bytes([8; 16])
            } else {
                old.epoch
            };
            log.initialise(&encode_envelope(&Envelope::new(fixture::volume(), epoch)))
                .await
                .unwrap();
        }
        match mode {
            "orphan" | "mismatch" | "valid" => log.intent_store().io.commit(&old).unwrap(),
            "orphan-corrupt" | "corrupt" => {
                std::fs::write(path.join("intent-test.intent"), b"corrupt allocator").unwrap();
            }
            "temporary-only" => {
                std::fs::write(path.join("intent-test.intent.tmp"), fixture::encoded(&old))
                    .unwrap();
            }
            _ => {}
        }
        drop(log);
        let snapshot = std::fs::read(path.join("intent-test.intent")).ok();
        let temporary = std::fs::read(path.join("intent-test.intent.tmp")).ok();
        let rec = recording(&path);
        let (handle, driver) = start(rec.clone(), 1).await;
        let driving = tokio::spawn(driver);
        rec.clear();
        for _ in 0..3 {
            let answer = handle
                .maintain_intents(&fixture::volume(), &enrolled(), 0)
                .await;
            if mode == "valid" {
                check(&answer, 200, None);
            } else {
                check(&answer, 503, Some(ErrorToken::Unavailable));
                assert_eq!(rec.calls(), Vec::<&str>::new());
                assert_eq!(
                    std::fs::read(path.join("intent-test.intent")).ok(),
                    snapshot
                );
                assert_eq!(
                    std::fs::read(path.join("intent-test.intent.tmp")).ok(),
                    temporary
                );
            }
            assert_eq!(path.join("intent-test.log").exists(), has_log);
        }
        if mode == "orphan" || mode == "neither" {
            assert!(matches!(
                handle.initialise(&fixture::volume()).await.unwrap(),
                authority::Initialised::Created { .. }
            ));
            check(
                &handle
                    .maintain_intents(&fixture::volume(), &enrolled(), 0)
                    .await,
                200,
                None,
            );
            if mode == "orphan" {
                let bytes = std::fs::read(path.join("intent-test.intent")).unwrap();
                let rebound = crate::authority::intent::codec::decode(
                    bytes.as_slice(),
                    &fixture::volume(),
                    None,
                    &fixture::keys(),
                )
                .unwrap();
                assert_eq!(
                    rebound.principals[&PrincipalId::from_bytes([1; 16])],
                    old.principals[&PrincipalId::from_bytes([1; 16])]
                );
            }
        }
        if mode == "missing" || mode == "mismatch" {
            let before = std::fs::read(path.join("intent-test.intent")).ok();
            assert!(matches!(
                handle.initialise(&fixture::volume()).await.unwrap(),
                authority::Initialised::Kept { .. }
            ));
            assert_eq!(std::fs::read(path.join("intent-test.intent")).ok(), before);
            check(
                &handle
                    .maintain_intents(&fixture::volume(), &enrolled(), 0)
                    .await,
                503,
                Some(ErrorToken::Unavailable),
            );
        }
        assert_eq!(handle.stop().await, RunEnd::Stopped);
        assert_eq!(driving.await.unwrap(), RunEnd::Stopped);
        drop((handle, rec));
        std::fs::remove_dir_all(path).unwrap();
        cases += 1;
    }
    assert_eq!(cases, 8);
}

#[tokio::test]
async fn explicit_initialise_snapshot_barriers_precede_log_and_failures_fence() {
    for failure in [None, Some("file-sync"), Some("dir-sync")] {
        let path = scratch();
        let rec = recording(&path);
        let (handle, driver) = start(rec.clone(), 1).await;
        let driving = tokio::spawn(driver);
        rec.clear();
        *rec.fail.lock().unwrap() = failure;
        let answer = handle.initialise(&fixture::volume()).await;
        let calls = rec.calls();
        if failure.is_some() {
            assert_eq!(answer, Err(authority::InitialiseError::Fenced));
            assert!(!path.join("intent-test.log").exists());
            assert!(
                !calls.contains(&"link"),
                "snapshot failure must precede log publication"
            );
            check(
                &handle
                    .maintain_intents(&fixture::volume(), &enrolled(), 0)
                    .await,
                503,
                Some(ErrorToken::Fenced),
            );
            assert_eq!(
                rec.calls(),
                calls,
                "fenced maintenance cannot retry a mutation"
            );
            assert!(matches!(handle.stop().await, RunEnd::Fenced(_)));
            assert!(matches!(driving.await.unwrap(), RunEnd::Fenced(_)));
        } else {
            assert!(matches!(
                answer.unwrap(),
                authority::Initialised::Created { .. }
            ));
            let link = calls.iter().position(|&c| c == "link").unwrap();
            assert!(
                calls[..link]
                    .windows(3)
                    .any(|c| c == ["file-sync", "rename", "dir-sync"]),
                "durable snapshot must precede log link: {calls:?}"
            );
            assert_eq!(handle.stop().await, RunEnd::Stopped);
            assert_eq!(driving.await.unwrap(), RunEnd::Stopped);
        }
        drop((handle, rec));
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn split_round1_existing_log_recovery_has_no_provision_entry_point() {
    assert!(!include_str!("../../authority.rs").contains("pub async fn provision_intents"));
    assert!(!include_str!("../intent_worker.rs").contains("Work::Provision"));
}

#[test]
fn split_round1_maintenance_comment_describes_retention() {
    assert!(
        include_str!("../../main.rs")
            .contains("/// Run enrollment and retention maintenance at startup and every minute.")
    );
}

#[test]
fn split_round1_observability_table_describes_initialise() {
    assert!(include_str!("../../../../../docs/operating-the-authority-lifecycle.md").contains(
        "| `intent_store` | explicit initialise snapshot installation, enrollment/retention maintenance and root visits |"
    ));
}

#[cfg(feature = "crash-points")]
#[tokio::test]
async fn split_round1_worker_initialise_cuts_require_intent_store() {
    use crate::authority::crash::{self, Plan};
    for enabled in [false, true] {
        let path = scratch();
        let rec = recording(&path);
        let config = VolumeConfig::new(fixture::volume(), fixture::keys());
        let config = if enabled {
            config.with_intents(FileIntent::store(Arc::new(rec.clone())))
        } else {
            config
        };
        let (handle, driver) = authority::start(
            AuthorityParts {
                admission: crate::Admission::chain_fixture(),
                log: FileLogOn::with_ops(rec),
                store: Sim::new().node(0, Faults::none()),
                clock: FixedClock,
                rng: rng(1),
                secure_random: SeededSecureRandom::for_incarnation(1, 1),
                pause: YieldPause,
            },
            boot(1),
            vec![config],
        )
        .await
        .unwrap();
        let driving = tokio::spawn(driver.run());
        let pipe = path.join("points");
        crash::install(&pipe, Plan::List).unwrap();
        handle.initialise(&fixture::volume()).await.unwrap();
        handle.stop().await;
        driving.await.unwrap();
        let points = std::fs::read_to_string(pipe).unwrap();
        for site in ["IntentProvisioned", "IntentProvisionLogSynced"] {
            assert_eq!(
                points
                    .lines()
                    .filter(|line| line.starts_with(&format!("HIT {site} ")))
                    .count(),
                usize::from(enabled),
                "{site}: enabled={enabled}"
            );
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[tokio::test]
async fn split_round1_worker_maintenance_failure_names_volume() {
    use tracing_subscriber::prelude::*;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(EventLayer(Arc::clone(&observed)));
    let _default = tracing::subscriber::set_default(subscriber);
    let path = scratch();
    let (handle, driver) = start(recording(&path), 1).await;
    let driving = tokio::spawn(driver);
    let result = handle
        .maintain_intents(&fixture::volume(), &enrolled(), 0)
        .await;
    check(&result, 503, Some(ErrorToken::Unavailable));
    let events = observed.lock().unwrap().clone();
    let failures = events
        .iter()
        .filter(|fields| {
            fields
                .get("event")
                .is_some_and(|event| event == "op.failed")
        })
        .collect::<Vec<_>>();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].get("volume").unwrap(), "intent-test");
    assert!(failures[0].get("error").unwrap().contains("unavailable"));
    assert_eq!(handle.stop().await, RunEnd::Stopped);
    assert_eq!(driving.await.unwrap(), RunEnd::Stopped);
    std::fs::remove_dir_all(path).unwrap();
}
