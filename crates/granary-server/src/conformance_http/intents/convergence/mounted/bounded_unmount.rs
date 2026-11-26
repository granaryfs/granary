// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded writable-daemon endings against the surviving HTTP authority.

use super::*;
use granary_core::retained_submission::Scope;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, Command, ExitStatus};

const CHILD_ENV: &str = "GRANARY_BOUNDED_UNMOUNT_CHILD";
const CHILD_BINARY: &str = "GRANARY_BOUNDED_UNMOUNT_TEST_BINARY";
const GRAN_BINARY: &str = "GRANARY_BOUNDED_UNMOUNT_GRAN";
const CHILD_TEST: &str = "attach::tests::bounded_unmount::bounded_unmount_child";
const BOUND: Duration = Duration::from_secs(10);
const EXIT_SLACK: Duration = Duration::from_secs(8);
/// The healthy control's flush limit, half the bound: the dirty set flushes in
/// about 0.5 s on an idle runner and grows with load, while a stalled store
/// runs to the bound, so the two stay apart.
const HEALTHY_LIMIT: Duration = Duration::from_secs(5);
const TOTAL_BYTES: u64 = 983_040;
const UNSYNCED_BYTES: u64 = 786_432;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    DurablePrepared,
    Published,
}

impl Profile {
    fn name(self) -> &'static str {
        match self {
            Self::DurablePrepared => "durable-prepared",
            Self::Published => "published",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    Gran,
    Plain,
    Signal,
}

impl Ending {
    fn trigger(self) -> &'static str {
        match self {
            Self::Gran => "umount",
            Self::Plain => "session_end",
            Self::Signal => "signal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    Stalled,
    Graduated,
}

impl Fault {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Stalled => "stalled",
            Self::Graduated => "graduated",
        }
    }

    fn residue(self) -> Option<(u64, u64)> {
        match self {
            Self::None => None,
            Self::Stalled => Some((5, TOTAL_BYTES)),
            Self::Graduated => Some((3, UNSYNCED_BYTES)),
        }
    }

    fn occurrence(self) -> Option<u64> {
        match self {
            Self::None => None,
            Self::Stalled => Some(1),
            Self::Graduated => Some(3),
        }
    }
}

struct Inputs {
    root: PathBuf,
    store: PathBuf,
    mount: PathBuf,
    overlay: PathBuf,
    scope: Scope,
}

impl Inputs {
    fn new(harness: &Harness, profile: Profile, fault: Fault, mode: &str) -> Self {
        let root = harness.fixture.dir.join(format!(
            "bounded-{}-{}-{mode}",
            profile.name(),
            fault.name()
        ));
        let store = root.join("store");
        let cache = root.join("cache");
        let mount = root.join("mount");
        for path in [&root, &store, &cache, &mount] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let endpoint = format!("https://{}", harness.addr);
        let scope = Scope {
            authority_base: endpoint.as_bytes().to_vec(),
            pins: vec![harness.fixture.pin],
            credential_context: b"principal-0".to_vec(),
        };
        let overlay = store
            .join("overlay")
            .join(scope.digest().unwrap())
            .join(harness.fixture.volume().as_str());
        let mut public = String::from("ed25519:");
        for byte in harness.key.public_key() {
            use std::fmt::Write as _;
            write!(public, "{byte:02x}").unwrap();
        }
        let fields = [
            ("endpoint", endpoint),
            (
                "pin",
                granary_net::config::render_tls_pin(&harness.fixture.pin),
            ),
            ("root_key", public),
            ("seed", harness.seed.display().to_string()),
            (
                "certificate",
                harness.keys.path("client-0.pem").display().to_string(),
            ),
            (
                "credential_key",
                harness.keys.path("client-0.key").display().to_string(),
            ),
            ("volume", harness.fixture.volume().as_str().to_owned()),
            ("store", store.display().to_string()),
            ("cache", cache.display().to_string()),
            ("mount", mount.display().to_string()),
            ("profile", profile.name().to_owned()),
            ("fault", fault.name().to_owned()),
            ("mode", mode.to_owned()),
        ];
        std::fs::write(
            root.join("config"),
            fields
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        Self {
            root,
            store,
            mount,
            overlay,
            scope,
        }
    }

    fn reconfigure(&self, profile: Profile, mode: &str) {
        let text = std::fs::read_to_string(self.root.join("config")).unwrap();
        let text = text
            .lines()
            .map(|line| {
                if line.starts_with("fault=") {
                    "fault=none".to_owned()
                } else if line.starts_with("mode=") {
                    format!("mode={mode}")
                } else if line.starts_with("profile=") {
                    format!("profile={}", profile.name())
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(self.root.join("config"), text).unwrap();
        for name in [
            "ready",
            "fault",
            "events",
            "reports",
            "stdout",
            "stderr",
            "gran.stdout",
            "gran.stderr",
        ] {
            match std::fs::remove_file(self.root.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove stale bounded witness {name}: {error}"),
            }
        }
    }
}

struct Client {
    child: Child,
    root: PathBuf,
}

struct CompletedClient {
    status: ExitStatus,
    operator_report: String,
}

impl Client {
    fn own(child: Child, root: &Path) -> Self {
        Self {
            child,
            root: root.to_path_buf(),
        }
    }

    fn start(inputs: &Inputs) -> Self {
        let binary = std::env::var_os(CHILD_BINARY)
            .unwrap_or_else(|| panic!("{CHILD_BINARY} must name the staged CLI libtest"));
        let child = Command::new(binary)
            .args([
                "--exact",
                CHILD_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, &inputs.root)
            .stdout(std::fs::File::create(inputs.root.join("stdout")).unwrap())
            .stderr(std::fs::File::create(inputs.root.join("stderr")).unwrap())
            .spawn()
            .unwrap();
        Self::own(child, &inputs.root)
    }

    fn diagnostics(&self) -> String {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            std::fs::read_to_string(self.root.join("stdout")).unwrap_or_default(),
            std::fs::read_to_string(self.root.join("stderr")).unwrap_or_default()
        )
    }

    fn ready(&mut self, expected: &str) {
        let started = Instant::now();
        loop {
            if std::fs::read_to_string(self.root.join("ready"))
                .ok()
                .as_deref()
                == Some(expected)
            {
                assert!(
                    self.child.try_wait().unwrap().is_none(),
                    "bounded client exited before readiness: {}",
                    self.diagnostics()
                );
                return;
            }
            assert!(
                started.elapsed() < WAIT,
                "bounded client did not become ready: {}",
                self.diagnostics()
            );
            std::thread::sleep(JOIN_POLL);
        }
    }

    fn wait_for_exit(&mut self, bound: Duration) -> Option<CompletedClient> {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let operator_report = std::fs::read_to_string(self.root.join("stderr")).unwrap();
                return Some(CompletedClient {
                    status,
                    operator_report,
                });
            }
            if started.elapsed() >= bound {
                return None;
            }
            std::thread::sleep(JOIN_POLL);
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn trigger(ending: Ending, inputs: &Inputs, pid: u32) -> Option<Client> {
    match ending {
        Ending::Gran => {
            let binary = std::env::var_os(GRAN_BINARY)
                .unwrap_or_else(|| panic!("{GRAN_BINARY} must name the ordinary gran binary"));
            Some(Client::own(
                Command::new(binary)
                    .arg("umount")
                    .arg(&inputs.mount)
                    .stdout(std::fs::File::create(inputs.root.join("gran.stdout")).unwrap())
                    .stderr(std::fs::File::create(inputs.root.join("gran.stderr")).unwrap())
                    .spawn()
                    .unwrap(),
                &inputs.root,
            ))
        }
        Ending::Plain => {
            umount2(&inputs.mount, MntFlags::UMOUNT_NOFOLLOW).unwrap();
            None
        }
        Ending::Signal => {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap()),
                nix::sys::signal::Signal::SIGTERM,
            )
            .unwrap();
            None
        }
    }
}

fn wait_command(command: &mut Client, bound: Duration) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = command.child.try_wait().unwrap() {
            return status;
        }
        assert!(started.elapsed() < bound, "gran umount exceeded {bound:?}");
        std::thread::sleep(JOIN_POLL);
    }
}

fn event_count(events: &str, event: &str) -> usize {
    events
        .lines()
        .filter(|line| field(line, "event") == Some(event))
        .count()
}

fn clean_exit_event(line: &str) -> Option<String> {
    use granary_client::{
        BackoffCause, BackoffOutcome, COMMIT_BACKOFF, COMMIT_STOPPED, CommitStopCause,
        FailureClass, MOUNT_UNMOUNT, OP_BEGIN, OP_END, OP_FAILED, OP_RETRY, OperationKind, Outcome,
        RetryReason, UnmountCause, UnmountOutcome, UnmountTrigger,
    };
    use std::fmt::Write as _;

    let event = field(line, "event")?;
    match event {
        COMMIT_STOPPED => {
            let cause = CommitStopCause::parse(field(line, "cause")?)?.as_str();
            return Some(format!("{COMMIT_STOPPED} cause={cause}"));
        }
        COMMIT_BACKOFF => {
            let cause = BackoffCause::parse(field(line, "cause")?)?.as_str();
            let outcome = BackoffOutcome::parse(field(line, "outcome")?)?.as_str();
            return Some(format!("{COMMIT_BACKOFF} cause={cause} outcome={outcome}"));
        }
        MOUNT_UNMOUNT => {
            let trigger = UnmountTrigger::parse(field(line, "trigger")?)?.as_str();
            let outcome = UnmountOutcome::parse(field(line, "outcome")?)?.as_str();
            let cause = field(line, "cause")
                .and_then(UnmountCause::parse)
                .map_or("none", UnmountCause::as_str);
            let mut report = format!("{MOUNT_UNMOUNT} {trigger} outcome={outcome} cause={cause}");
            for name in ["files", "bytes", "operations", "seq", "elapsed_ms"] {
                if let Some(value) = number_field(line, name) {
                    write!(report, " {name}={value}").unwrap();
                }
            }
            return Some(report);
        }
        _ => {}
    }

    let kind = OperationKind::parse(field(line, "kind")?)?;
    if !matches!(
        kind,
        OperationKind::Commit
            | OperationKind::Fsync
            | OperationKind::IntentRegister
            | OperationKind::Rebase
            | OperationKind::Unmount
            | OperationKind::View
    ) {
        return None;
    }
    let kind = kind.as_str();
    match event {
        OP_BEGIN => Some(format!("{OP_BEGIN} {kind}")),
        OP_END => {
            let outcome = Outcome::parse(field(line, "outcome")?)?.as_str();
            Some(format!("{OP_END} {kind} outcome={outcome}"))
        }
        OP_FAILED => {
            let class = FailureClass::parse(field(line, "class")?)?.as_str();
            Some(format!("{OP_FAILED} {kind} class={class}"))
        }
        OP_RETRY => {
            let attempt = number_field(line, "attempt")?;
            let reason = RetryReason::parse(field(line, "reason")?)?.as_str();
            Some(format!(
                "{OP_RETRY} {kind} attempt={attempt} reason={reason}"
            ))
        }
        _ => None,
    }
}

fn clean_exit_events(events: &str) -> String {
    // The capture terminates each record with a newline. An early read can end mid-record.
    let events = events
        .rsplit_once('\n')
        .map_or("", |(complete, _)| complete);
    let line_count = events.lines().count();
    let mut recent: Vec<_> = events
        .lines()
        .rev()
        .enumerate()
        .filter_map(|(offset, line)| {
            clean_exit_event(line).map(|event| format!("{} {event}", line_count - offset))
        })
        .take(16)
        .collect();
    recent.reverse();
    recent.join("\n")
}

fn report_clean_exit_events(events: Option<&str>) {
    if let Some(events) = events {
        write_direct(
            format!(
                "recent shutdown operations (event line numbers):\n{}\n",
                clean_exit_events(events)
            )
            .as_bytes(),
        );
    } else {
        write_direct(b"recent shutdown operations unavailable\n");
    }
}

fn semantic_operations(inputs: &Inputs) -> u64 {
    use granary_core::overlay_journal::Record;

    let mut operations = 0_u64;
    granary_core::overlay_journal::scan_journal_with(
        &std::fs::read(inputs.overlay.join("journal")).unwrap(),
        |_, record| {
            if !matches!(
                record,
                Record::IntentRegistered { .. }
                    | Record::CommitBoundary { .. }
                    | Record::LandedCommit { .. }
                    | Record::CommitAttempt { .. }
                    | Record::CommitFence { .. }
                    | Record::ProjectedBoundary { .. }
            ) {
                operations += 1;
            }
        },
    )
    .unwrap();
    operations
}

struct RegisteredPreparedRoot {
    id: granary_core::hash::GrainId,
    bytes: Vec<u8>,
}

fn local_manifest_file_sizes(
    inputs: &Inputs,
    manifest_root: granary_core::hash::GrainId,
) -> BTreeMap<String, u64> {
    use granary_core::manifest::EntryKind;

    let store = granary_client::Store::open(&inputs.store).unwrap();
    granary_core::manifest::validate_dir_tree(&manifest_root, &|id| {
        granary_core::grainsource::GrainSource::get(&store, id).ok()
    })
    .unwrap();
    let bytes = granary_core::grainsource::GrainSource::get(&store, &manifest_root).unwrap();
    let (kind, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
    assert_eq!(kind, granary_core::encoding::ObjectType::DirLeaf);
    granary_core::manifest::decode_dir_leaf(cursor)
        .unwrap()
        .into_iter()
        .map(|entry| {
            let name = String::from_utf8(entry.name.as_bytes().to_vec()).unwrap();
            let EntryKind::File {
                exec: false, size, ..
            } = entry.kind
            else {
                panic!("prepared manifest entry {name:?} is not a non-executable file");
            };
            (name, size)
        })
        .collect()
}

fn reader_file_sizes(harness: &Harness) -> BTreeMap<String, u64> {
    let mut reader = harness.reader();
    let mountpoint = reader.mountpoint.clone();
    let reads = spawn_fuse(move || {
        std::fs::read_dir(mountpoint)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name().into_string().unwrap();
                let size = u64::try_from(std::fs::read(entry.path()).unwrap().len()).unwrap();
                (name, size)
            })
            .collect()
    });
    let files = join_fuse_within(
        reads,
        &mut reader.mount,
        WAIT,
        "recovered reader mount wedged",
    );
    reader.finish();
    files
}

fn registered_prepared_root(harness: &Harness, inputs: &Inputs) -> RegisteredPreparedRoot {
    let trusted = TrustedKeys::new([*harness.key.public_key()]).unwrap();
    let reply = harness
        .runtime
        .block_on(
            harness
                .fixture
                .client(harness.addr, 0)
                .intent_readback_once(&inputs.scope, &harness.fixture.volume(), |doc, prefix| {
                    granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok()
                }),
        )
        .unwrap();
    let readback = granary_core::intent::decode_readback(
        reply.body(),
        &harness.fixture.volume(),
        |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok(),
    )
    .unwrap();
    let [row] = readback.rows.as_slice() else {
        panic!(
            "graduated shutdown has {} live intent rows",
            readback.rows.len()
        );
    };
    let bytes = row.root.to_vec();
    let id = row.root_id();
    let doc = verify_root(&bytes, &trusted);
    assert_eq!(
        local_manifest_file_sizes(inputs, doc.manifest_root),
        BTreeMap::from([
            ("file-0".to_owned(), 65_536),
            ("file-1".to_owned(), 131_072),
        ]),
        "registered prepared root does not carry the acknowledged prefix"
    );
    RegisteredPreparedRoot { id, bytes }
}

fn assert_recovered_partition(harness: &Harness, prepared: &RegisteredPreparedRoot, base: u64) {
    let trusted = TrustedKeys::new([*harness.key.public_key()]).unwrap();
    let base_root = root(harness, base);
    let published = root(harness, base + 1);
    let prepared_doc = verify_root(&prepared.bytes, &trusted);
    let published_doc = verify_root(&published, &trusted);
    let base_id = granary_core::hash::GrainId::of(&base_root);
    let published_id = granary_core::hash::GrainId::of(&published);
    assert_eq!(
        prepared.id,
        granary_core::hash::GrainId::of(&prepared.bytes)
    );
    assert_eq!(
        (
            prepared_doc.seq,
            prepared_doc.parent,
            published_doc.seq,
            published_doc.parent,
            published_doc.writer_uuid,
        ),
        (
            base + 1,
            Some(base_id),
            base + 1,
            Some(base_id),
            prepared_doc.writer_uuid,
        ),
        "recovery landing is not a same-writer candidate on the registered root's base"
    );
    assert_ne!(
        published_id, prepared.id,
        "dirty recovery published the registered prefix instead of the residual commit"
    );
    assert_ne!(
        published_doc.manifest_root, prepared_doc.manifest_root,
        "dirty recovery did not derive a manifest containing the residual files"
    );
    let files = reader_file_sizes(harness);
    assert_eq!(
        (files.get("file-0"), files.get("file-1")),
        (Some(&65_536), Some(&131_072)),
        "recovered publication lost the acknowledged 196,608-byte prefix"
    );
    assert_eq!(
        files,
        BTreeMap::from([
            ("file-0".to_owned(), 65_536),
            ("file-1".to_owned(), 131_072),
            ("file-2".to_owned(), 196_608),
            ("file-3".to_owned(), 262_144),
            ("file-4".to_owned(), 327_680),
        ]),
        "recovered publication does not contain the acknowledged prefix and residual files"
    );
}

fn assert_retained(harness: &Harness, inputs: &Inputs, minimum_stages: usize) {
    let journal = std::fs::read(inputs.overlay.join("journal")).unwrap();
    let mut records = 0;
    granary_core::overlay_journal::scan_journal_with(&journal, |_, _| records += 1).unwrap();
    let stages = std::fs::read_dir(inputs.overlay.join("staging"))
        .unwrap()
        .count();
    assert!(records > 0, "timeout discarded the overlay journal");
    assert!(
        stages >= minimum_stages,
        "timeout retained {stages} stages, expected at least {minimum_stages}"
    );
    let trusted = TrustedKeys::new([*harness.key.public_key()]).unwrap();
    let readback = harness
        .runtime
        .block_on(
            harness
                .fixture
                .client(harness.addr, 0)
                .intent_readback_once(&inputs.scope, &harness.fixture.volume(), |doc, prefix| {
                    granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok()
                }),
        )
        .unwrap();
    let rows = granary_core::intent::decode_readback(
        readback.body(),
        &harness.fixture.volume(),
        |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok(),
    )
    .unwrap()
    .rows;
    assert_eq!(rows.len(), 1, "timeout did not retain one live intent row");
}

#[expect(
    clippy::too_many_lines,
    reason = "one ordered integration row keeps trigger, bounded exit, exact residue, recovery, \
              and authority readback assertions in causal order"
)]
fn ending_once(profile: Profile, ending: Ending, fault: Fault) {
    let harness = Harness::new(None, LogPaths::Redacted);
    let inputs = Inputs::new(&harness, profile, fault, "dirty");
    let base = head_seq(&harness);
    let mut child = Client::start(&inputs);
    child.ready(fault.name());
    let initial_operations = semantic_operations(&inputs);
    assert_eq!(
        head_seq(&harness),
        base,
        "background coalescing moved the head before the ending began"
    );
    let started = Instant::now();
    let mut command = trigger(ending, &inputs, child.child.id());
    let expected = if fault == Fault::None { 0 } else { 4 };
    if let Some(command) = command.as_mut() {
        let status = wait_command(command, BOUND + EXIT_SLACK);
        if fault == Fault::None && status.code() != Some(expected) {
            let events = std::fs::read_to_string(inputs.root.join("events"));
            report_clean_exit_events(events.as_deref().ok());
        }
        assert_eq!(
            status.code(),
            Some(expected),
            "gran umount status={status:?}"
        );
    }
    let completed = child.wait_for_exit(BOUND + EXIT_SLACK);
    let elapsed = started.elapsed();
    let elapsed_ms = elapsed.as_millis();
    let events = std::fs::read_to_string(inputs.root.join("events"));
    let flush_ms = events.as_deref().ok().and_then(|events| {
        events
            .lines()
            .find(|line| field(line, "event") == Some("mount.unmount"))
            .and_then(|line| number_field(line, "elapsed_ms"))
    });
    write_direct(
        format!(
            "{{\"event\":\"integration.bounded_unmount\",\"ending\":\"{}\",\"fault\":\"{}\",\"flush_ms\":{},\"elapsed_ms\":{elapsed_ms}}}\n",
            ending.trigger(),
            fault.name(),
            flush_ms.map_or_else(|| "null".to_owned(), |ms| ms.to_string()),
        )
        .as_bytes(),
    );
    if fault == Fault::None
        && completed
            .as_ref()
            .is_none_or(|completed| !completed.status.success())
    {
        report_clean_exit_events(events.as_deref().ok());
    }
    let completed = completed
        .unwrap_or_else(|| panic!("daemon exceeded bound plus slack: {}", child.diagnostics()));
    let status = completed.status;
    assert_eq!(
        (status.code(), status.signal()),
        (Some(expected), None),
        "daemon status={status:?}; {}",
        child.diagnostics()
    );
    let events = events.unwrap();
    if fault == Fault::None {
        let flush_ms = flush_ms.unwrap_or_else(|| {
            panic!(
                "healthy flush missing mount.unmount elapsed_ms: flush_ms=null, elapsed_ms={elapsed_ms}\n{events}"
            )
        });
        assert_eq!(
            (
                Duration::from_millis(flush_ms) <= HEALTHY_LIMIT,
                elapsed <= BOUND + EXIT_SLACK,
            ),
            (true, true),
            "healthy flush must stay within half of {BOUND:?} and exit within {:?}: flush_ms={flush_ms}, elapsed_ms={elapsed_ms}\n{events}",
            BOUND + EXIT_SLACK,
        );
    } else {
        assert!(
            elapsed >= BOUND.saturating_sub(Duration::from_millis(500))
                && elapsed <= BOUND + EXIT_SLACK,
            "bounded failure elapsed {elapsed:?}"
        );
    }
    let reports = completed.operator_report;
    let gran_report = if ending == Ending::Gran {
        format!(
            "{}{}",
            std::fs::read_to_string(inputs.root.join("gran.stdout")).unwrap(),
            std::fs::read_to_string(inputs.root.join("gran.stderr")).unwrap()
        )
    } else {
        String::new()
    };
    assert_eq!(event_count(&events, "mount.unmount"), 1, "{events}");
    assert!(
        events.lines().any(|line| {
            field(line, "event") == Some("mount.unmount")
                && field(line, "trigger") == Some(ending.trigger())
        }),
        "ending trigger absent: {events}"
    );
    if ending == Ending::Signal {
        assert_eq!(
            event_count(&events, "client.gran.mount.received.signal.unmounting"),
            1,
            "SIGTERM was not observed by the production signal path: {events}"
        );
    }
    if let Some((files, bytes)) = fault.residue() {
        let operations = initial_operations + u64::from(fault == Fault::Graduated) * 2;
        let fault_witness = std::fs::read_to_string(inputs.root.join("fault")).unwrap();
        let witness: Vec<_> = fault_witness.split('/').collect();
        let expected_occurrence = fault
            .occurrence()
            .expect("a residue-bearing fault has an occurrence");
        assert!(
            witness.len() == 5
                && witness[0] == "sync.registration"
                && witness[1] == "before_dispatch"
                && witness[2].parse::<u64>().ok() == Some(expected_occurrence)
                && witness[3].parse::<u64>().is_ok_and(|capture| capture > 0)
                && witness[4] == "true",
            "armed fault lacks nonzero identity: {fault_witness}"
        );
        assert!(
            reports.contains(&format!("{files} files ({bytes} bytes) unsynced"))
                && reports.contains(&format!("{operations} operations uncommitted"))
                && reports.contains(&inputs.store.display().to_string())
                && reports.contains("preserve it; the next mount with this store can finish")
                && reports.contains("explicit recovery")
                && reports.contains("daemon stopped (exit 4)"),
            "timeout report is incomplete: {reports}"
        );
        if ending == Ending::Gran {
            assert!(
                gran_report.contains(&format!("{files} files ({bytes} bytes) unsynced"))
                    && gran_report.contains(&inputs.store.display().to_string())
                    && gran_report.contains("next mount with this store can finish"),
                "gran umount omitted the bounded status: {gran_report}"
            );
        }
        assert!(event_count(&events, "sync.fault") > 0, "{events}");
        let unmount_begin = events.lines().position(|line| {
            field(line, "event") == Some("op.begin") && field(line, "kind") == Some("unmount")
        });
        let fault_event = events
            .lines()
            .position(|line| field(line, "event") == Some("sync.fault"));
        assert!(
            matches!((unmount_begin, fault_event), (Some(begin), Some(fired)) if begin < fired),
            "the armed fault was consumed before shutdown latched: {events}"
        );
        assert!(
            events.lines().any(|line| {
                field(line, "event") == Some("mount.unmount")
                    && number_field(line, "files") == Some(files)
                    && number_field(line, "bytes") == Some(bytes)
                    && number_field(line, "operations") == Some(operations)
            }),
            "timeout event has the wrong exact residue: {events}"
        );
        assert_retained(&harness, &inputs, usize::try_from(files).unwrap());
        let prepared =
            (fault == Fault::Graduated).then(|| registered_prepared_root(&harness, &inputs));
        let at_timeout = head_seq(&harness);
        assert_eq!(at_timeout, base, "timeout published despite its held fault");
        inputs.reconfigure(profile, "recover");
        let mut restarted = Client::start(&inputs);
        restarted.ready("recovered");
        assert_eq!(
            head_seq(&harness),
            base + 1,
            "recovery did not leave the authority at the expected head by readiness"
        );
        if let Some(prepared) = prepared.as_ref() {
            assert_recovered_partition(&harness, prepared, base);
        }
        let mut recovery_command = trigger(ending, &inputs, restarted.child.id());
        if let Some(command) = recovery_command.as_mut() {
            assert!(wait_command(command, BOUND + EXIT_SLACK).success());
        }
        let recovery = restarted
            .wait_for_exit(BOUND + EXIT_SLACK)
            .unwrap_or_else(|| {
                panic!("recovered daemon did not exit: {}", restarted.diagnostics())
            });
        assert_eq!(recovery.status.code(), Some(0));
        let recovery_events = std::fs::read_to_string(inputs.root.join("events")).unwrap();
        let recovery_event = recovery_events
            .lines()
            .position(|line| field(line, "event") == Some("overlay.recovery"));
        let startup_end = recovery_events.lines().position(|line| {
            field(line, "event") == Some("mount.unmount") && field(line, "trigger") == Some("start")
        });
        assert!(
            matches!((recovery_event, startup_end), (Some(recovery), Some(end)) if recovery < end),
            "startup recovery did not precede its completion event: {recovery_events}"
        );
    } else {
        if ending == Ending::Gran {
            assert!(
                gran_report.contains("shutdown committed seq="),
                "gran umount omitted the committed sequence: {gran_report}"
            );
        }
        assert!(
            events.lines().any(|line| {
                field(line, "event") == Some("op.end")
                    && field(line, "kind") == Some("commit")
                    && field(line, "outcome") == Some("ok")
            }),
            "healthy shutdown has no completed commit: {events}"
        );
        assert_eq!(head_seq(&harness), base + 1);
    }
    let reader = harness.reader();
    for (index, size) in [65_536, 131_072, 196_608, 262_144, 327_680]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            std::fs::read(reader.mountpoint.join(format!("file-{index}"))).unwrap(),
            vec![b'a' + u8::try_from(index).unwrap(); size]
        );
    }
    reader.finish();
    harness.stop();
}

fn run(cases: &[(Profile, Ending)], fault: Fault) {
    if !venue(&format!("bounded_unmount_{fault:?}")) {
        return;
    }
    let _row = ROW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for &(profile, ending) in cases {
        ending_once(profile, ending, fault);
        if fault != Fault::None {
            ending_once(profile, ending, Fault::None);
        }
    }
}

#[test]
fn clean_exit_events_report_only_recent_typed_operations() {
    let mut events = "{\"event\":\"op.begin\",\"kind\":\"commit\"}\n".repeat(20);
    events.push_str(concat!(
        "{\"event\":\"op.begin\",\"kind\":\"private-kind\"}\n",
        "{\"event\":\"op.retry\",\"kind\":\"intent_register\",\"attempt\":2,\"reason\":\"transient\"}\n",
        "{\"event\":\"op.failed\",\"kind\":\"commit\",\"class\":\"private-class\"}\n",
        "{\"event\":\"op.failed\",\"kind\":\"commit\",\"class\":\"unavailable\",\"op\":\"private-id\"}\n",
        "{\"event\":\"op.end\",\"kind\":\"commit\",\"outcome\":\"failed\",\"error\":\"private-error\"}\n",
        "{\"event\":\"commit.stopped\",\"cause\":\"private-cause\"}\n",
        "{\"event\":\"commit.stopped\",\"cause\":\"fenced\",\"op\":\"private-id\"}\n",
        "{\"event\":\"commit.backoff\",\"cause\":\"outage\",\"outcome\":\"entered\"}\n",
        "{\"event\":\"mount.unmount\",\"trigger\":\"session_end\",\"outcome\":\"incomplete\",\"cause\":\"failed\",\"files\":0,\"bytes\":0,\"operations\":15,\"elapsed_ms\":662}\n",
        "{\"event\":\"mount.unmount\",\"trigger\":\"umount\",\"outcome\":\"committed\",\"seq\":2,\"elapsed_ms\":500}\n",
    ));
    let report = clean_exit_events(&events);
    events.push_str(
        r#"{"event":"mount.unmount","trigger":"session_end","outcome":"incomplete","elapsed_ms":1"#,
    );
    assert_eq!(
        clean_exit_events(&events),
        report,
        "an incomplete last record must not replace a complete event"
    );
    let rows: Vec<_> = report.lines().collect();
    assert_eq!(rows.len(), 16);
    assert_eq!(rows.first().copied(), Some("12 op.begin commit"));
    assert_eq!(
        &rows[9..],
        [
            "22 op.retry intent_register attempt=2 reason=transient",
            "24 op.failed commit class=unavailable",
            "25 op.end commit outcome=failed",
            "27 commit.stopped cause=fenced",
            "28 commit.backoff cause=outage outcome=entered",
            "29 mount.unmount session_end outcome=incomplete cause=failed files=0 bytes=0 operations=15 elapsed_ms=662",
            "30 mount.unmount umount outcome=committed cause=none seq=2 elapsed_ms=500",
        ]
    );
}

#[test]
fn writable_linux_bounded_unmount_healthy() {
    run(
        &[
            (Profile::DurablePrepared, Ending::Gran),
            (Profile::Published, Ending::Gran),
            (Profile::DurablePrepared, Ending::Plain),
            (Profile::DurablePrepared, Ending::Signal),
        ],
        Fault::None,
    );
}

#[test]
fn writable_linux_bounded_unmount_stalled() {
    run(
        &[
            (Profile::DurablePrepared, Ending::Gran),
            (Profile::Published, Ending::Gran),
            (Profile::DurablePrepared, Ending::Plain),
            (Profile::DurablePrepared, Ending::Signal),
        ],
        Fault::Stalled,
    );
}

#[test]
fn writable_linux_bounded_unmount_graduated() {
    run(
        &[
            (Profile::DurablePrepared, Ending::Gran),
            (Profile::DurablePrepared, Ending::Plain),
            (Profile::DurablePrepared, Ending::Signal),
        ],
        Fault::Graduated,
    );
}
