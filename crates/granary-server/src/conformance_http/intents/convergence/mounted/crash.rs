// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process deaths at retained persistence seams against a surviving authority.

use super::*;
use granary_core::overlay_journal::{self as journal, MarkState, Record, StagingHeader};
use granary_core::retained_submission::Scope;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::process::ExitStatusExt as _;

const CHILD: &str = "GRANARY_CLIENT_CRASH_CHILD";
const CHILD_TEST: &str =
    "conformance_http::intents::convergence::mounted::crash::client_crash_child";
const PREFIX: &[u8] = b"acknowledged prefix";
const KEPT: &[u8] = b"journaled work";
const TAIL: &[u8] = b" appended work";
const UNNAMED_ID: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut {
    UnjournaledWrite,
    JournaledWrite,
    Uploaded,
    Registered,
    LandedReadback,
    LandedRefresh,
    BeforeReplace,
    RenameDirectory,
}

impl Cut {
    fn seam(self) -> (&'static str, &'static str) {
        match self {
            Self::UnjournaledWrite => ("overlay.stage.write", "after"),
            Self::JournaledWrite => ("overlay.journal.append", "after"),
            Self::Uploaded => ("sync.registration", "before_dispatch"),
            Self::Registered => ("sync.reply", "before"),
            Self::LandedReadback => ("sync.commit", "landed_readback"),
            Self::LandedRefresh => ("sync.commit", "landed_refresh"),
            Self::BeforeReplace => ("sync.commit", "before_replace"),
            Self::RenameDirectory => ("fuse.sync.rename_directory", "before"),
        }
    }

    fn published(self) -> bool {
        matches!(
            self,
            Self::LandedReadback | Self::LandedRefresh | Self::BeforeReplace
        )
    }

    fn profile(self) -> SyncProfile {
        if self.published() {
            SyncProfile::Published
        } else {
            SyncProfile::DurablePrepared
        }
    }
}

// These files contain only fixture locations and public authority metadata.
// The seed and mTLS key remain in the harness's checked custody directory.
pub(super) struct WriterInputs {
    pub(super) root: PathBuf,
    pub(super) keys: PathBuf,
    pub(super) endpoint: String,
    pub(super) pin: [u8; 32],
}

impl WriterInputs {
    pub(super) fn save(harness: &Harness, label: &str) -> Self {
        let root = harness.fixture.dir.join(label);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = format!("https://{}", harness.server.as_ref().unwrap().addr);
        std::fs::write(root.join("endpoint"), &endpoint).unwrap();
        std::fs::write(root.join("pin"), harness.fixture.pin).unwrap();
        std::fs::write(root.join("keys"), harness.keys.0.as_os_str().as_bytes()).unwrap();
        Self {
            root,
            keys: harness.keys.0.clone(),
            endpoint,
            pin: harness.fixture.pin,
        }
    }

    pub(super) fn load(root: PathBuf) -> Self {
        let endpoint = std::fs::read_to_string(root.join("endpoint")).unwrap();
        let pin = std::fs::read(root.join("pin")).unwrap().try_into().unwrap();
        let keys = PathBuf::from(std::ffi::OsString::from_vec(
            std::fs::read(root.join("keys")).unwrap(),
        ));
        Self {
            root,
            keys,
            endpoint,
            pin,
        }
    }

    fn scope(&self) -> Scope {
        Scope {
            authority_base: self.endpoint.as_bytes().to_vec(),
            pins: vec![self.pin],
            credential_context: vec![0],
        }
    }

    fn overlay(&self) -> PathBuf {
        self.overlay_for(&self.scope())
    }

    pub(super) fn overlay_for(&self, scope: &Scope) -> PathBuf {
        self.root
            .join("store/overlay")
            .join(scope.digest().unwrap())
            .join(super::super::super::wire_fixture::volume().as_str())
    }

    fn mount(&self, random: u8, profile: SyncProfile) -> WritableHandle {
        let clock = super::super::super::Ticks(Arc::new(AtomicU64::new(100)));
        self.mount_with(random, profile, &self.scope(), &clock, |_| {})
    }

    pub(super) fn mount_with<C: granary_core::clock::Clock + Clone + 'static>(
        &self,
        random: u8,
        profile: SyncProfile,
        scope: &Scope,
        clock: &C,
        arm: impl FnOnce(&FaultControl),
    ) -> WritableHandle {
        let store = self.root.join("store");
        let cache = self.root.join("cache");
        let mountpoint = self.root.join("mount");
        for path in [&store, &cache, &mountpoint] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let seed = self.keys.join("root.seed");
        let certificate = self.keys.join("client-0.pem");
        let credential_key = self.keys.join("client-0.key");
        let public = *SigningKey::from_seed(&[23; 32]).unwrap().public_key();
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        let input = WritableStart {
            volume: super::super::super::wire_fixture::volume(),
            process: WritableProcess {
                ruid: uid,
                rgid: gid,
                egid: gid,
                set_id_tainted: false,
            },
            foreground: true,
            force: false,
            mountpoint: &mountpoint,
            root_key: Some(public),
            manifest_root: None,
            trust_server: false,
            options: MountOptions {
                allow_other: false,
                allow_root: false,
            },
            seq: None,
            seed: Some(&seed),
            certificate: Some(&certificate),
            credential_key: Some(&credential_key),
            scope: Some(scope.clone()),
            store: Some(&store),
            cache: Some(&cache),
            cache_origin: CacheOrigin {
                endpoint_url: self.endpoint.clone(),
                pin_set_digest: CacheOrigin::pin_set_digest(&[self.pin]),
                root_key_id: Some(CacheOrigin::root_key_digest(&public)),
            },
            cache_quota: CACHE_QUOTA,
            contention_threshold: granary_client::ContentionThreshold::default(),
            construction_workspace_bytes: granary_client::SyncOptions::default().workspace_bytes,
            overlay_cap_bytes: 134_217_728,
            reset_floor: false,
            policy: granary_vfs::AttrPolicy { uid, gid },
            euid: uid,
            sync_profile: profile,
            view: ViewMode::Default,
        };
        WritableHandle::start_with(&input, clock, random, self.overlay_for(scope), arm)
    }
}

pub(super) struct ClientChild {
    child: std::process::Child,
    abort: Option<std::fs::File>,
    root: PathBuf,
}

impl ClientChild {
    fn start(inputs: &WriterInputs, cut: Cut, armed: bool) -> Self {
        let (point, phase) = cut.seam();
        std::fs::write(
            inputs.root.join("cut"),
            format!("{point}\n{phase}\n{armed}"),
        )
        .unwrap();
        Self::spawn(inputs, CHILD, CHILD_TEST)
    }

    pub(super) fn spawn(inputs: &WriterInputs, child_env: &str, test: &str) -> Self {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                test,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(child_env, &inputs.root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::fs::File::create(inputs.root.join("stdout")).unwrap())
            .stderr(std::fs::File::create(inputs.root.join("stderr")).unwrap())
            .spawn()
            .unwrap();
        Self {
            child,
            abort: None,
            root: inputs.root.clone(),
        }
    }

    fn diagnostics(&self) -> String {
        format!(
            "stdout: {}\nstderr: {}",
            std::fs::read_to_string(self.root.join("stdout")).unwrap(),
            std::fs::read_to_string(self.root.join("stderr")).unwrap()
        )
    }

    pub(super) fn ready(&mut self, expected: &str) {
        let started = Instant::now();
        loop {
            if let Ok(witness) = std::fs::read_to_string(self.root.join("ready")) {
                assert_eq!(
                    witness,
                    expected,
                    "client cut witness: {}",
                    self.diagnostics()
                );
                assert!(
                    self.child.try_wait().unwrap().is_none(),
                    "client exited before parent observed the cut: {}",
                    self.diagnostics()
                );
                let mount = self.root.join("mount");
                let connection = mount_connection(&mount)
                    .unwrap()
                    .expect("ready client has no FUSE connection");
                self.abort = Some(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(format!("/sys/fs/fuse/connections/{connection}/abort"))
                        .unwrap(),
                );
                return;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "client exited before the named seam: {}",
                self.diagnostics()
            );
            assert!(
                started.elapsed() < WAIT,
                "client never reached the named seam: {}",
                self.diagnostics()
            );
            std::thread::sleep(JOIN_POLL);
        }
    }

    fn wait(&mut self, bound: Duration) -> io::Result<Option<std::process::ExitStatus>> {
        let started = Instant::now();
        loop {
            let status = self.child.try_wait()?;
            if status.is_some() || started.elapsed() >= bound {
                return Ok(status);
            }
            std::thread::sleep(JOIN_POLL);
        }
    }

    pub(super) fn stop(&mut self, armed: bool) {
        if armed {
            self.child.kill().unwrap();
        } else {
            self.child
                .stdin
                .take()
                .unwrap()
                .write_all(b"finish")
                .unwrap();
        }
        let bound = if armed {
            ABORT_JOIN_BOUND
        } else {
            WRITABLE_JOIN_BOUND
        };
        let mut status = self.wait(bound).unwrap();
        let forced = status.is_none();
        if forced {
            self.abort
                .as_mut()
                .expect("client FUSE connection abort unavailable")
                .write_all(b"1")
                .unwrap();
            status = self.wait(ABORT_JOIN_BOUND).unwrap();
        }
        write_direct(
            format!(
                "{{\"event\":\"integration.fuse_cleanup\",\"mount\":{:?},\"forced\":{forced},\"joined\":{}}}\n",
                self.root.join("mount").display().to_string(),
                status.is_some()
            )
            .as_bytes(),
        );
        let status =
            status.unwrap_or_else(|| panic!("client did not stop: {}", self.diagnostics()));
        assert_eq!(
            (status.success(), status.signal()),
            (!armed, armed.then_some(9)),
            "client termination: {status:?}; {}",
            self.diagnostics()
        );
        if armed {
            umount2(
                &self.root.join("mount"),
                MntFlags::MNT_DETACH | MntFlags::UMOUNT_NOFOLLOW,
            )
            .unwrap();
        }
    }
}

impl Drop for ClientChild {
    fn drop(&mut self) {
        // Abort before killing so closing the child's self-served files cannot
        // leave it waiting on its own dead FUSE worker.
        if self.child.try_wait().ok().flatten().is_none() {
            let forced = self
                .abort
                .as_mut()
                .is_some_and(|abort| abort.write_all(b"1").is_ok());
            let _ = self.child.kill();
            let joined = self.wait(ABORT_JOIN_BOUND).ok().flatten().is_some();
            write_direct(
                format!(
                    "{{\"event\":\"integration.fuse_cleanup\",\"mount\":{:?},\"forced\":{forced},\"joined\":{joined}}}\n",
                    self.root.join("mount").display().to_string()
                )
                .as_bytes(),
            );
        }
        let mount = self.root.join("mount");
        if mount_connection(&mount).ok().flatten().is_some() {
            let _ = umount2(&mount, MntFlags::MNT_DETACH | MntFlags::UMOUNT_NOFOLLOW);
        }
    }
}

#[test]
#[ignore = "re-executed by the crash rows with an isolated client process"]
#[expect(
    clippy::too_many_lines,
    reason = "the child keeps the armed operation and its pre-kill witness in one ordered sequence"
)]
fn client_crash_child() {
    let root = PathBuf::from(std::env::var_os(CHILD).expect("client fixture directory"));
    let inputs = WriterInputs::load(root);
    let config = std::fs::read_to_string(inputs.root.join("cut")).unwrap();
    let mut config = config.lines();
    let point = config.next().unwrap();
    let phase = config.next().unwrap();
    let armed = config.next().unwrap().parse::<bool>().unwrap();
    let cut = [
        Cut::UnjournaledWrite,
        Cut::JournaledWrite,
        Cut::Uploaded,
        Cut::Registered,
        Cut::LandedReadback,
        Cut::LandedRefresh,
        Cut::BeforeReplace,
        Cut::RenameDirectory,
    ]
    .into_iter()
    .find(|cut| cut.seam() == (point, phase))
    .unwrap();
    let captured = capture(LogPaths::Redacted);
    let writer = inputs.mount(81, cut.profile());
    let prefix = std::fs::File::create(writer.mountpoint.join("prefix")).unwrap();
    (&prefix).write_all(PREFIX).unwrap();
    prefix.sync_all().unwrap();
    let work = std::fs::File::create(writer.mountpoint.join("work")).unwrap();
    (&work).write_all(KEPT).unwrap();
    let (point, phase) = cut.seam();
    if armed {
        writer.faults.arm(point, phase, 1, FaultAction::Block);
    } else {
        writer.faults.trace_sync();
    }
    let mountpoint = writer.mountpoint.clone();
    let operation = std::thread::spawn(move || {
        (&work).write_all(TAIL).unwrap();
        match cut {
            Cut::UnjournaledWrite | Cut::JournaledWrite => (),
            Cut::RenameDirectory => {
                std::fs::rename(mountpoint.join("work"), mountpoint.join("renamed")).unwrap();
                std::fs::File::open(&mountpoint)
                    .unwrap()
                    .sync_all()
                    .unwrap();
            }
            _ => work.sync_all().unwrap(),
        }
        work
    });
    let work = if armed {
        wait_until(
            || {
                writer
                    .faults
                    .fired()
                    .iter()
                    .any(|event| (event.name, event.phase, event.occurrence) == (point, phase, 1))
                    || writer.faults.sync_fired().iter().any(|event| {
                        (event.name, event.phase, event.occurrence) == (point, phase, 1)
                    })
            },
            "client fault did not fire",
        );
        assert!(
            !operation.is_finished(),
            "client operation returned before the cut"
        );
        if cut == Cut::RenameDirectory {
            assert!(
                writer
                    .faults
                    .sync_fired()
                    .iter()
                    .any(|event| event
                        .rename_directory
                        .is_some_and(|context| context.journal_cursor > 0
                            && context.directory_inode.is_none())),
                "directory cut has no root-directory journal witness"
            );
        }
        None
    } else {
        let work = join_within(operation, WAIT, "clean operation did not finish");
        if point.starts_with("overlay.") {
            // Overlay seams have no unarmed trace; the checked extents
            // witness the completed write and append, not the exact hook.
            let (_, records) = read_journal(&inputs.overlay());
            assert!(records.iter().any(|record| matches!(record,
                Record::WriteExtent { stage_id, offset: 0, length, check }
                    if *length == KEPT.len() as u64
                        && *check == journal::extent_check(*stage_id, 0, KEPT)
                        && records.iter().any(|record| matches!(record,
                            Record::WriteExtent { stage_id: tail_stage, offset, length, check }
                                if tail_stage == stage_id && *offset == KEPT.len() as u64
                                    && *length == TAIL.len() as u64
                                    && *check == journal::extent_check(*stage_id, *offset, TAIL))))),
                "clean control has no journaled work and append: {records:?}");
        } else {
            assert!(
                writer.faults.sync_fired().iter().any(|event| {
                    (event.name, event.phase, event.occurrence) == (point, phase, 1)
                }),
                "clean control did not traverse the named seam"
            );
        }
        Some(work)
    };
    // The parent sees this witness only after the retained firing and the
    // blocked caller have both been checked, then sends SIGKILL itself.
    std::fs::write(inputs.root.join("events"), captured.lines().join("\n")).unwrap();
    std::fs::write(
        inputs.root.join("ready.next"),
        format!("{point}/{phase}/{armed}"),
    )
    .unwrap();
    std::fs::rename(inputs.root.join("ready.next"), inputs.root.join("ready")).unwrap();
    let mut command = Vec::new();
    std::io::stdin().read_to_end(&mut command).unwrap();
    assert_eq!(command, b"finish");
    drop(work);
    drop(prefix);
    writer.finish();
}

fn read_journal(path: &Path) -> (journal::JournalScan, Vec<Record>) {
    let mut records = Vec::new();
    let scan = journal::scan_journal_with(
        &std::fs::read(path.join("journal")).unwrap(),
        |_, record| {
            records.push(record.clone());
        },
    )
    .unwrap();
    (scan, records)
}

#[expect(
    clippy::too_many_lines,
    reason = "each process-death arm and its clean control share the same restart assertions"
)]
fn run(cut: Cut) {
    if !venue(&format!("client_crash_{cut:?}")) {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cases = 0;
    for armed in [true, false] {
        let harness = Harness::new(None, LogPaths::Redacted);
        let inputs = WriterInputs::save(&harness, "client");
        let mut child = ClientChild::start(&inputs, cut, armed);
        let (point, phase) = cut.seam();
        child.ready(&format!("{point}/{phase}/{armed}"));
        let events = std::fs::read_to_string(inputs.root.join("events")).unwrap();
        if armed {
            let event = if point.starts_with("overlay.") {
                "overlay.fault"
            } else {
                "sync.fault"
            };
            assert!(
                events
                    .lines()
                    .any(|line| field(line, "event") == Some(event)
                        && field(line, "point") == Some(point)
                        && field(line, "phase") == Some(phase)
                        && number_field(line, "occurrence") == Some(1)),
                "named fault event absent before kill: {events}"
            );
        }
        let seq_at_cut = head_seq(&harness);
        let root_at_cut = root(&harness, seq_at_cut);
        child.stop(armed);
        let settled_seq = head_seq(&harness);
        let settled_root = root(&harness, settled_seq);
        if armed && cut.published() {
            assert_eq!(
                (settled_seq, &settled_root),
                (seq_at_cut, &root_at_cut),
                "publication advanced after the blocked post-CAS seam"
            );
        }
        let overlay = inputs.overlay();
        let (scan, records) = read_journal(&overlay);
        if armed {
            let stages: Vec<_> = records
                .iter()
                .filter_map(|record| match record {
                    Record::WriteExtent {
                        stage_id,
                        offset: 0,
                        length,
                        check,
                    } if *length == KEPT.len() as u64
                        && *check == journal::extent_check(*stage_id, 0, KEPT) =>
                    {
                        Some(*stage_id)
                    }
                    _ => None,
                })
                .collect();
            let [stage] = stages.as_slice() else {
                panic!("crash has no unique journaled work stage: {records:?}");
            };
            let payload =
                std::fs::read(overlay.join("staging").join(format!("{stage:016x}"))).unwrap();
            let tail_recorded = records.iter().any(|record| matches!(record,
                Record::WriteExtent { stage_id, offset, length, check }
                    if stage_id == stage && *offset == KEPT.len() as u64 && *length == TAIL.len() as u64
                        && *check == journal::extent_check(*stage, *offset, TAIL)));
            assert_eq!(
                (payload.get(160..), tail_recorded),
                (
                    Some([KEPT, TAIL].concat().as_slice()),
                    cut != Cut::UnjournaledWrite
                ),
                "cut did not separate the staged append from its journal record: {cut:?}; {records:?}"
            );
            if cut.published() {
                assert!(records.iter().any(|record| matches!(record,
                    Record::LandedCommit { landed_seq, landed_root, .. }
                        if *landed_seq == seq_at_cut && *landed_root == granary_core::hash::GrainId::of(&root_at_cut))),
                    "post-CAS cut has no retained landing: {records:?}");
            }
        }
        // A well-formed, unsynced stage with the same writer but no journal
        // binding must be swept, even alongside recoverable named staging.
        let unnamed = overlay.join("staging").join(format!("{UNNAMED_ID:016x}"));
        let mut bytes = StagingHeader {
            writer: scan.header.writer,
            stage_id: UNNAMED_ID,
            mark: MarkState::Absent,
        }
        .encode()
        .unwrap();
        bytes.extend_from_slice(b"untrusted unnamed content");
        std::fs::write(&unnamed, bytes).unwrap();
        std::fs::set_permissions(&unnamed, std::fs::Permissions::from_mode(0o600)).unwrap();
        harness.capture.clear();
        let restarted = inputs.mount(82, cut.profile());
        let recovery = harness.capture.lines();
        assert_eq!(
            restarted.writer, scan.header.writer,
            "restart changed writer identity"
        );
        assert!(
            recovery
                .iter()
                .any(|line| field(line, "event") == Some("overlay.recovery")
                    && matches!(
                        field(line, "outcome"),
                        Some("clean" | "repaired" | "pending")
                    )),
            "restart served without a recovery event: {recovery:?}"
        );
        assert_eq!(
            (
                unnamed.exists(),
                recovery
                    .iter()
                    .any(|line| field(line, "event") == Some("overlay.sweep")
                        && number_field(line, "files").is_some_and(|files| files > 0))
            ),
            (false, true),
            "unnamed staging was trusted or not reported: {recovery:?}"
        );
        let (_, after) = read_journal(&overlay);
        assert!(
            !after.iter().any(|record| matches!(
                record,
                Record::WriteExtent { .. }
                    | Record::CommitBoundary { .. }
                    | Record::ProjectedBoundary { .. }
                    | Record::LandedCommit { .. }
            )),
            "mount served with unfinished recovery: {after:?}"
        );
        let work_name = if cut == Cut::RenameDirectory {
            "renamed"
        } else {
            "work"
        };
        let expected = if armed && cut == Cut::UnjournaledWrite {
            KEPT.to_vec()
        } else {
            [KEPT, TAIL].concat()
        };
        assert_eq!(
            (
                std::fs::read(restarted.mountpoint.join("prefix")).unwrap(),
                std::fs::read(restarted.mountpoint.join(work_name)).unwrap()
            ),
            (PREFIX.to_vec(), expected.clone()),
            "first reads after restart: {cut:?}/{armed}"
        );
        restarted.finish();
        let seq_after = head_seq(&harness);
        if armed && !cut.published() {
            // Startup finishes the dirty journal in one commit; the prepared
            // cuts have not published, and shutdown has no work left to land.
            assert_eq!(
                seq_after,
                settled_seq + 1,
                "recovery did not publish exactly once: {cut:?}/{armed}"
            );
        } else {
            assert_eq!(
                (seq_after, root(&harness, seq_after)),
                (settled_seq, settled_root),
                "restart duplicated a landed publication: {cut:?}/{armed}"
            );
        }
        let reader = harness.reader();
        assert_eq!(
            (
                std::fs::read(reader.mountpoint.join("prefix")).unwrap(),
                std::fs::read(reader.mountpoint.join(work_name)).unwrap(),
                mounted_names(&reader.mountpoint)
            ),
            (PREFIX.to_vec(), expected, {
                let mut names = vec!["prefix".to_owned(), work_name.to_owned()];
                names.sort();
                names
            }),
            "authority reader lost or duplicated recovered content: {cut:?}/{armed}"
        );
        reader.finish();
        harness.stop();
        cases += 1;
    }
    write_direct(format!("{{\"event\":\"integration.client_crash\",\"point\":\"{}\",\"phase\":\"{}\",\"cases\":{cases}}}\n", cut.seam().0, cut.seam().1).as_bytes());
}

#[test]
fn writable_linux_client_crash_unjournaled_write() {
    run(Cut::UnjournaledWrite);
}
#[test]
fn writable_linux_client_crash_journaled_write() {
    run(Cut::JournaledWrite);
}
#[test]
fn writable_linux_client_crash_uploaded() {
    run(Cut::Uploaded);
}
#[test]
fn writable_linux_client_crash_registered() {
    run(Cut::Registered);
}
#[test]
fn writable_linux_client_crash_landed_readback() {
    run(Cut::LandedReadback);
}
#[test]
fn writable_linux_client_crash_landed_refresh() {
    run(Cut::LandedRefresh);
}
#[test]
fn writable_linux_client_crash_before_replace() {
    run(Cut::BeforeReplace);
}
#[test]
fn writable_linux_client_crash_rename_directory() {
    run(Cut::RenameDirectory);
}
