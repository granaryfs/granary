// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::protected_dir::tests::{Call, Phase, Recorder, chmod, scratch};
use granary_core::authlog::{Envelope, Epoch, encode_envelope};
use std::{
    os::unix::fs::MetadataExt as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
struct Time(Timestamp);
impl Clock for Time {
    fn now(&self) -> Timestamp {
        self.0
    }
}
fn vector(name: &str) -> Vec<u8> {
    let row = include_str!("../../../../granary-core/tests/vectors/support_v1.tsv")
        .lines()
        .find(|l| l.split('\t').next() == Some(name))
        .unwrap();
    row.split('\t')
        .nth(1)
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
struct Fixture {
    root: std::path::PathBuf,
    s: std::path::PathBuf,
    d: std::path::PathBuf,
    out: std::path::PathBuf,
    snapshot: SupportSnapshot,
    config: SupportConfiguration,
}
impl Fixture {
    fn new() -> Self {
        let root = scratch("support-export");
        let s = root.join("support");
        let d = root.join("state");
        let out = root.join("output");
        for path in [&s, &d, &out] {
            std::fs::create_dir(path).unwrap();
            chmod(path, 0o700);
        }
        let snapshot = SupportSnapshot::decode(&vector("snapshot")).unwrap();
        let mut config = SupportConfiguration::decode(&vector("configuration")).unwrap();
        config.volumes = snapshot.volumes.keys().map(|v| (v.clone(), 1)).collect();
        let f = Self {
            root,
            s,
            d,
            out,
            snapshot,
            config,
        };
        f.write_pair();
        for v in f.config.volumes.keys() {
            std::fs::write(
                f.d.join(format!("{}.log", v.as_str())),
                encode_envelope(&Envelope::new(v.clone(), Epoch::from_bytes([7; 16]))).as_bytes(),
            )
            .unwrap();
        }
        f
    }
    fn write_pair(&self) {
        for (name, bytes) in [
            ("SUPPORT-SNAPSHOT", self.snapshot.encode().unwrap()),
            ("SUPPORT-CONFIGURATION", self.config.encode().unwrap()),
        ] {
            std::fs::write(self.s.join(name), bytes).unwrap();
            chmod(&self.s.join(name), 0o600);
        }
    }
    fn request(&self) -> SupportExportRequest<'_> {
        SupportExportRequest {
            support_dir: &self.s,
            state_dir: &self.d,
            expected_incarnation: None,
            accept_unsupported_filesystem: true,
        }
    }
    fn clock(&self) -> Time {
        Time(Timestamp {
            secs: self.snapshot.sampled_at.secs + 120,
            nanos: self.snapshot.sampled_at.nanos,
        })
    }
    fn archive(&self) -> SupportArchive {
        let bytes = read_support_export(self.request(), &self.clock()).unwrap();
        SupportArchive::decode(&bytes).unwrap()
    }
    fn positive(&self) {
        let a = self.archive();
        assert_eq!(
            (
                a.members.len(),
                a.manifest.incarnation,
                a.members[b"snapshot.bin".as_slice()].clone(),
                a.members[b"configuration.bin".as_slice()].clone()
            ),
            (
                6,
                self.snapshot.incarnation,
                self.snapshot.encode().unwrap(),
                self.config.encode().unwrap()
            ),
            "valid exact-byte fixture"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for path in [&self.s, &self.d, &self.out] {
            chmod(path, 0o700);
        }
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
fn refusal(a: &SupportArchive, kind: SourceKind, id: &[u8]) -> EntryStatus {
    a.manifest
        .entries
        .iter()
        .find(|e| e.kind == kind && e.id == id)
        .unwrap()
        .status
        .clone()
}
fn published(result: Result<(), SupportExportError>) -> String {
    result.map_or_else(|e| e.to_string(), |()| "published".into())
}
fn outcome(result: Result<Vec<u8>, SupportExportError>) -> String {
    match result {
        Ok(_) => "accepted".into(),
        Err(e) => e.to_string(),
    }
}
#[test]
fn support_export_incarnation_checks() {
    let mut f = Fixture::new();
    f.positive();
    let mut request = f.request();
    request.expected_incarnation = Some(f.snapshot.incarnation);
    assert!(read_support_export(request, &f.clock()).is_ok());
    request.expected_incarnation = Some(Incarnation::from_bytes([9; 16]));
    assert_eq!(
        outcome(read_support_export(request, &f.clock())),
        "support expected incarnation mismatch"
    );
    f.config.incarnation = Incarnation::from_bytes([8; 16]);
    f.write_pair();
    assert_eq!(
        outcome(read_support_export(f.request(), &f.clock())),
        "support incarnation disagreement"
    );
    let mut request = f.request();
    request.expected_incarnation = Some(f.config.incarnation);
    assert_eq!(
        outcome(read_support_export(request, &f.clock())),
        "support incarnation disagreement"
    );
    f.config.incarnation = f.snapshot.incarnation;
    f.config
        .volumes
        .remove(&VolumeName::new("alpha".into()).unwrap());
    f.write_pair();
    assert_eq!(
        outcome(read_support_export(f.request(), &f.clock())),
        "support inventory disagreement"
    );
}
#[test]
fn support_export_stalled_writer_age() {
    let f = Fixture::new();
    f.positive();
    let t = f.snapshot.sampled_at;
    let cases = [
        (
            Timestamp {
                secs: t.secs + 120,
                nanos: t.nanos,
            },
            support::AgeStatus::Fresh,
            120,
            0,
        ),
        (
            Timestamp {
                secs: t.secs + 120,
                nanos: t.nanos + 1,
            },
            support::AgeStatus::StalledWriter,
            120,
            1,
        ),
        (
            Timestamp {
                secs: t.secs + 121,
                nanos: t.nanos,
            },
            support::AgeStatus::StalledWriter,
            121,
            0,
        ),
        (
            Timestamp {
                secs: t.secs - 1,
                nanos: t.nanos,
            },
            support::AgeStatus::ClockRegressed,
            1,
            0,
        ),
    ];
    for (time, status, seconds, nanos) in cases {
        let bytes = read_support_export(f.request(), &Time(time)).unwrap();
        let a = SupportArchive::decode(&bytes).unwrap();
        assert_eq!(
            (
                a.manifest.sampled_at,
                a.manifest.exported_at,
                a.manifest.age
            ),
            (
                t,
                time,
                SnapshotAge {
                    status,
                    seconds,
                    nanos
                }
            )
        );
    }
}
#[test]
#[cfg(unix)]
fn support_export_linux_symlink_components() {
    let f = Fixture::new();
    f.positive();
    let link = f.root.join("linked");
    std::os::unix::fs::symlink(&f.s, &link).unwrap();
    for (s, d) in [(&link, &f.d), (&f.s, &link)] {
        let r = SupportExportRequest {
            support_dir: s,
            state_dir: d,
            ..f.request()
        };
        assert!(
            outcome(read_support_export(r, &f.clock()))
                .contains("symbolic link or not a directory")
        );
    }
    let ancestor = f.root.join("ancestor");
    std::os::unix::fs::symlink(&f.root, &ancestor).unwrap();
    let through = ancestor.join("support");
    assert!(
        outcome(read_support_export(
            SupportExportRequest {
                support_dir: &through,
                ..f.request()
            },
            &f.clock()
        ))
        .contains("symbolic link or not a directory")
    );
    let sentinel = f.root.join("sentinel");
    std::fs::write(&sentinel, b"secret sentinel").unwrap();
    let log = f.d.join("alpha.log");
    std::fs::remove_file(&log).unwrap();
    std::os::unix::fs::symlink(&sentinel, &log).unwrap();
    let a = f.archive();
    assert_eq!(
        (
            refusal(&a, SourceKind::Log, b"alpha"),
            a.members
                .values()
                .any(|b| b.windows(15).any(|w| w == b"secret sentinel"))
        ),
        (EntryStatus::Refused(ExportRefusal::Symlink), false)
    );
    std::fs::remove_file(&log).unwrap();
    std::fs::write(
        &log,
        encode_envelope(&Envelope::new(
            VolumeName::new("alpha".into()).unwrap(),
            Epoch::from_bytes([7; 16]),
        ))
        .as_bytes(),
    )
    .unwrap();
    let ops = Recorder::new();
    let state = walk(&ops, &f.d, true).unwrap();
    let swapped = log.clone();
    let target = sentinel.clone();
    ops.set_hook(move |call, phase| {
        if *call == Call::OpenReadAt("alpha.log".into()) && phase == Phase::Before {
            std::fs::remove_file(&swapped)?;
            std::os::unix::fs::symlink(&target, &swapped)?;
        }
        Ok(())
    });
    assert_eq!(
        read_log(&ops, &state, &VolumeName::new("alpha".into()).unwrap()),
        Err(ExportRefusal::Symlink),
        "leaf no-follow rejects a swap after preflight"
    );
    let required = f.s.join("SUPPORT-SNAPSHOT");
    std::fs::remove_file(&required).unwrap();
    std::os::unix::fs::symlink(&sentinel, &required).unwrap();
    assert_eq!(
        outcome(read_support_export(f.request(), &f.clock())),
        "required SUPPORT-SNAPSHOT: symlink"
    );
}
#[test]
#[cfg(unix)]
#[allow(clippy::too_many_lines)] // Keep the paired source-size controls in one row.
fn support_export_linux_oversize_sources() {
    let f = Fixture::new();
    f.positive();
    let ops = Recorder::new();
    let held = walk(&ops, &f.s, true).unwrap();
    ops.clear_calls();
    for (name, cap) in [
        ("SUPPORT-SNAPSHOT", support::SNAPSHOT_MAX),
        ("SUPPORT-CONFIGURATION", support::CONFIGURATION_MAX),
    ] {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(f.s.join(name))
            .unwrap();
        file.set_len(u64::try_from(cap + 1).unwrap()).unwrap();
        assert_eq!(
            (
                read_required(&ops, &held, name, cap),
                ops.calls().iter().filter(|c| **c == Call::ReadAt).count()
            ),
            (Err(ExportRefusal::Oversize), 0),
            "fstat cap before content read"
        );
        f.write_pair();
        ops.clear_calls();
    }
    // The cap-plus-one read must detect growth, rather than truncate to fstat.
    let source = f.s.join("SUPPORT-CONFIGURATION");
    let ready = Arc::new(AtomicBool::new(false));
    let ready_hook = ready.clone();
    ops.set_hook(move |call, phase| {
        if *call == Call::ReadAt
            && phase == Phase::Before
            && !ready_hook.swap(true, Ordering::SeqCst)
        {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&source)?
                .set_len(32769)?;
        }
        Ok(())
    });
    assert_eq!(
        read_required(&ops, &held, "SUPPORT-CONFIGURATION", 32768),
        Err(ExportRefusal::Oversize)
    );
    f.write_pair();
    let v = VolumeName::new("alpha".into()).unwrap();
    let prefix = encode_envelope(&Envelope::new(v.clone(), Epoch::from_bytes([7; 16])))
        .as_bytes()
        .to_vec();
    let log = f.d.join("alpha.log");
    let mut body = prefix.clone();
    body.resize(1024 * 1024, 0x53);
    std::fs::write(&log, &body).unwrap();
    let ops = Recorder::new();
    let state = walk(&ops, &f.d, true).unwrap();
    ops.clear_calls();
    let meta = SupportLogMetadata::decode(&read_log(&ops, &state, &v).unwrap()).unwrap();
    assert_eq!(
        (
            meta.volume,
            meta.epoch,
            meta.envelope_version,
            meta.size,
            ops.calls().iter().filter(|c| **c == Call::ReadAt).count()
        ),
        (v.clone(), Epoch::from_bytes([7; 16]), 1, 1_048_576, 2),
        "only header and declared prefix are read"
    );
    let described = NixOps.stat_at(&state.dir, "alpha.log").unwrap();
    assert_eq!(
        (meta.uid, meta.gid, meta.permissions, meta.mtime, meta.ctime),
        (
            described.uid,
            described.gid,
            described.perms(),
            Timestamp {
                secs: described.mtime.0,
                nanos: u32::try_from(described.mtime.1).unwrap()
            },
            Timestamp {
                secs: described.ctime.0,
                nanos: u32::try_from(described.ctime.1).unwrap()
            }
        ),
        "descriptor fields retained exactly"
    );
    let mut corrupt = prefix.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    let mut version = prefix.clone();
    version[8..10].copy_from_slice(&2_u16.to_be_bytes());
    let foreign = encode_envelope(&Envelope::new(
        VolumeName::new("omega".into()).unwrap(),
        Epoch::from_bytes([7; 16]),
    ))
    .as_bytes()
    .to_vec();
    for bytes in [corrupt, version, foreign, prefix[..11].to_vec()] {
        std::fs::write(&log, bytes).unwrap();
        assert_eq!(read_log(&ops, &state, &v), Err(ExportRefusal::Corrupt));
    }
    let mut bad = prefix;
    bad[10..12].copy_from_slice(&4097_u16.to_be_bytes());
    bad.resize(8192, 0x53);
    std::fs::write(&log, bad).unwrap();
    ops.clear_calls();
    assert_eq!(
        (
            read_log(&ops, &state, &v),
            ops.calls().iter().filter(|c| **c == Call::ReadAt).count()
        ),
        (Err(ExportRefusal::OversizeEnvelope), 1),
        "declared envelope cap precedes allocation/read"
    );
    let changed = log.clone();
    let once = Arc::new(AtomicBool::new(false));
    let hook_once = once.clone();
    std::fs::write(
        &log,
        encode_envelope(&Envelope::new(v.clone(), Epoch::from_bytes([7; 16]))).as_bytes(),
    )
    .unwrap();
    ops.set_hook(move |call, phase| {
        if *call == Call::ReadAt && phase == Phase::After && !hook_once.swap(true, Ordering::SeqCst)
        {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&changed)?
                .write_all(b"changed")?;
        }
        Ok(())
    });
    assert_eq!(
        read_log(&ops, &state, &v),
        Err(ExportRefusal::ChangedDuringRead)
    );
}
#[test]
#[cfg(unix)]
fn support_export_linux_special_sources() {
    let f = Fixture::new();
    f.positive();
    let v = VolumeName::new("alpha".into()).unwrap();
    let log = f.d.join("alpha.log");
    std::fs::remove_file(&log).unwrap();
    nix::unistd::mkfifo(&log, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    let ops = Recorder::new();
    let state = walk(&ops, &f.d, true).unwrap();
    ops.clear_calls();
    assert_eq!(
        (
            read_log(&ops, &state, &v),
            ops.calls()
                .iter()
                .filter(|c| matches!(c, Call::OpenReadAt(_) | Call::ReadAt))
                .count()
        ),
        (Err(ExportRefusal::NonRegular), 0)
    );
    std::fs::remove_file(&log).unwrap();
    std::fs::create_dir(&log).unwrap();
    assert_eq!(read_log(&ops, &state, &v), Err(ExportRefusal::NonRegular));
    std::fs::remove_dir(&log).unwrap();
    // Swap after the no-follow preflight. Inspect real descriptor flags before
    // returning the open, so dropping NONBLOCK fails an assertion, not a hang.
    std::fs::write(
        &log,
        encode_envelope(&Envelope::new(v.clone(), Epoch::from_bytes([7; 16]))).as_bytes(),
    )
    .unwrap();
    let swap = log.clone();
    let checked = Arc::new(AtomicBool::new(false));
    let check_hook = checked.clone();
    ops.set_hook(move |call, phase| {
        if *call == Call::OpenReadAt("alpha.log".into()) && phase == Phase::Before {
            // Inspect a regular descriptor before the FIFO substitution: a
            // missing flag fails here instead of blocking in the mutant open.
            let fd =
                NixOps.open_read_at(&std::fs::File::open(swap.parent().unwrap())?, "alpha.log")?;
            let flags =
                nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_GETFL).map_err(io::Error::from)?;
            assert!(
                OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK),
                "source open must carry O_NONBLOCK"
            );
            check_hook.store(true, Ordering::SeqCst);
            std::fs::remove_file(&swap)?;
            nix::unistd::mkfifo(&swap, Mode::S_IRUSR | Mode::S_IWUSR).map_err(io::Error::from)?;
        }
        Ok(())
    });
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = read_log(&ops, &state, &v);
        send.send((
            result,
            ops.calls().iter().filter(|c| **c == Call::ReadAt).count(),
        ))
        .unwrap();
    });
    let result = receive
        .recv_timeout(Duration::from_secs(3))
        .expect("nonblocking FIFO read must finish within watchdog");
    worker.join().unwrap();
    assert_eq!(
        (result, checked.load(Ordering::SeqCst)),
        ((Err(ExportRefusal::NonRegular), 0), true),
        "post-open descriptor type refuses FIFO without a read"
    );
    let device = Recorder::with_descriptor_kind(0o020_000);
    let root = walk(&device, &f.d, true).unwrap();
    std::fs::remove_file(&log).unwrap();
    std::fs::write(&log, b"regular preflight").unwrap();
    device.clear_calls();
    assert_eq!(
        (
            read_log(&device, &root, &VolumeName::new("alpha".into()).unwrap()),
            device
                .calls()
                .iter()
                .filter(|c| **c == Call::ReadAt)
                .count()
        ),
        (Err(ExportRefusal::NonRegular), 0),
        "device descriptor substituted after regular preflight"
    );
    // Required special sources fail the whole export.
    let required = f.s.join("SUPPORT-CONFIGURATION");
    std::fs::remove_file(&required).unwrap();
    nix::unistd::mkfifo(&required, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    assert_eq!(
        outcome(read_support_export(f.request(), &f.clock())),
        "required SUPPORT-CONFIGURATION: non-regular"
    );
}
#[test]
fn support_export_unknown_and_planted_key() {
    let f = Fixture::new();
    f.positive();
    for root in [&f.s, &f.d] {
        std::fs::write(
            root.join("planted-private.key"),
            b"synthetic secret key sentinel",
        )
        .unwrap();
        std::fs::write(root.join("attacker-filename"), b"unknown content").unwrap();
    }
    let ops = Recorder::new();
    let result = collect(&ops, f.request(), &f.clock());
    assert!(
        result.is_ok(),
        "unknown sources must yield a complete export with refused entries: {result:?}"
    );
    let (bytes, _, _) = result.unwrap();
    let a = SupportArchive::decode(&bytes).unwrap();
    let unknowns: Vec<_> = a
        .manifest
        .entries
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                SourceKind::UnknownSupport | SourceKind::UnknownState
            )
        })
        .collect();
    let opens: Vec<_> = ops
        .calls()
        .into_iter()
        .filter_map(|c| {
            if let Call::OpenReadAt(n) = c {
                Some(n)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        (
            unknowns.len(),
            unknowns.iter().all(|e| e.id.starts_with(b"unknown-")
                && e.status == EntryStatus::Refused(ExportRefusal::NotAllowlisted)),
            opens.len(),
            opens
                .iter()
                .any(|n| n.contains("key") || n.contains("attacker")),
            a.members.len()
        ),
        (4, true, 6, false, 6)
    );
    for secret in [
        b"synthetic secret key sentinel".as_slice(),
        b"planted-private.key",
        b"attacker-filename",
        b"unknown content",
    ] {
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
    }
}
#[test]
fn support_export_entry_and_byte_caps() {
    let f = Fixture::new();
    f.positive();
    for root in [&f.s, &f.d] {
        for i in 0..1030 {
            std::fs::write(root.join(format!("unknown-{i}")), b"excluded").unwrap();
        }
    }
    let roots = [
        walk(&NixOps, &f.s, true).unwrap(),
        walk(&NixOps, &f.d, true).unwrap(),
    ];
    let mut scanned = Vec::new();
    for (root, kind) in roots
        .iter()
        .zip([SourceKind::UnknownSupport, SourceKind::UnknownState])
    {
        let truncated = scan(root, kind, &f.config, &mut scanned).unwrap();
        let unknown = scanned.iter().filter(|e| e.kind == kind).count();
        assert_eq!(
            (truncated, unknown <= 1024, unknown > 0),
            (true, true, true),
            "root {kind:?} scan count {unknown}"
        );
    }
    let a = f.archive();
    let unknown = |kind| a.manifest.entries.iter().filter(|e| e.kind == kind).count();
    assert_eq!(
        (
            a.manifest.support_truncated,
            a.manifest.state_truncated,
            unknown(SourceKind::SupportSummary),
            unknown(SourceKind::StateSummary),
            unknown(SourceKind::UnknownSupport) <= 1024,
            unknown(SourceKind::UnknownState) <= 1024,
            a.manifest.entries.len() <= 2116,
            a.manifest.encode().unwrap().len() <= 541_952,
            a.encode().unwrap().len() <= 16_777_216
        ),
        (true, true, 1, 1, true, true, true, true, true)
    );
    assert!(
        unknown(SourceKind::UnknownSupport) >= 1022 && unknown(SourceKind::UnknownState) >= 1020
    );
}
#[test]
fn support_export_required_failures_and_flock_scope() {
    let f = Fixture::new();
    f.positive();
    let ops = Recorder::new();
    let support_path = f.s.clone();
    let released = Arc::new(AtomicBool::new(false));
    let flag = released.clone();
    ops.set_hook(move |call, phase| {
        if let Call::OpenReadAt(name) = call
            && name.as_bytes().ends_with(b".log")
            && phase == Phase::Before
        {
            let other = walk(&NixOps, &support_path, true).unwrap();
            let result = NixOps.try_lock(&other.dir);
            assert!(
                result.is_ok(),
                "support flock must be released before log inspection: {result:?}"
            );
            flag.store(true, Ordering::SeqCst);
        }
        Ok(())
    });
    let (bytes, support, state) = collect(&ops, f.request(), &f.clock()).unwrap();
    // Opening a separate description and taking LOCK_NB demonstrates that the
    // paired-read flock is released while the source descriptors remain held.
    let other = walk(&NixOps, &f.s, true).unwrap();
    assert!(NixOps.try_lock(&other.dir).is_ok());
    let locks: Vec<_> = ops
        .calls()
        .into_iter()
        .filter_map(|c| {
            if let Call::Lock { ino } = c {
                Some(ino)
            } else {
                None
            }
        })
        .collect();
    assert_eq!((locks, bytes.is_empty()), (vec![support.stat.ino], false));
    assert_ne!(support.stat.ino, state.stat.ino);
    assert!(
        released.load(Ordering::SeqCst),
        "nonempty log inspection control"
    );
    let failing = Recorder::new();
    failing.set_hook(|call, phase| {
        if *call == Call::ReadAt && phase == Phase::Before {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected unreadable source",
            ))
        } else {
            Ok(())
        }
    });
    assert_eq!(
        outcome(collect(&failing, f.request(), &f.clock()).map(|(b, _, _)| b)),
        "required SUPPORT-SNAPSHOT: unreadable"
    );
    for name in ["SUPPORT-SNAPSHOT", "SUPPORT-CONFIGURATION"] {
        std::fs::remove_file(f.s.join(name)).unwrap();
        assert_eq!(
            outcome(read_support_export(f.request(), &f.clock())),
            format!("required {name}: missing")
        );
        f.write_pair();
        chmod(&f.s.join(name), 0o622);
        assert_eq!(
            outcome(read_support_export(f.request(), &f.clock())),
            format!("required {name}: unprotected")
        );
        f.write_pair();
        std::fs::write(f.s.join(name), b"corrupt").unwrap();
        assert_eq!(
            outcome(read_support_export(f.request(), &f.clock())),
            format!("required {name}: corrupt")
        );
        f.write_pair();
    }
}
#[test]
#[cfg(unix)]
fn support_export_output_containment_by_identity() {
    use crate::support::publish::{self, PathLinks};
    let f = Fixture::new();
    f.positive();
    let ops = Recorder::new();
    let (bytes, s, d) = collect(&ops, f.request(), &f.clock()).unwrap();
    let outside = f.out.join("archive");
    publish::publish(&ops, &PathLinks, f.request(), &outside, &s, &d, &bytes).unwrap();
    assert_eq!(std::fs::read(outside).unwrap(), bytes);
    for source in [&f.s, &f.d] {
        let nested = source.join("nested");
        let parent = nested.join("deeper");
        std::fs::create_dir_all(&parent).unwrap();
        chmod(&nested, 0o700);
        chmod(&parent, 0o700);
        let relocated = f.root.join("renamed-source");
        std::fs::rename(source, &relocated).unwrap();
        let out = relocated.join("nested/deeper/archive");
        assert!(
            !out.parent().unwrap().starts_with(&f.s) && !out.parent().unwrap().starts_with(&f.d),
            "the alternate spelling must miss both lexical prefixes: {out:?}"
        );
        ops.clear_calls();
        let result = published(publish::publish(
            &ops,
            &PathLinks,
            f.request(),
            &out,
            &s,
            &d,
            &bytes,
        ));
        std::fs::rename(&relocated, source).unwrap();
        assert_eq!(
            (
                result,
                parent.join("archive").exists(),
                ops.calls()
                    .iter()
                    .any(|c| matches!(c, Call::CreateExclAt(_)))
            ),
            ("output inside source tree".into(), false, false),
            "a source ancestor's identity must refuse before temporary creation"
        );
    }
}

#[test]
#[cfg(unix)]
fn support_export_output_temporary_namespace() {
    use crate::support::publish::{self, PathLinks};
    let f = Fixture::new();
    f.positive();
    let ops = Recorder::new();
    let (bytes, s, d) = collect(&ops, f.request(), &f.clock()).unwrap();
    let positive = f.out.join("archive");
    publish::publish(&ops, &PathLinks, f.request(), &positive, &s, &d, &bytes).unwrap();
    assert_eq!(std::fs::read(positive).unwrap(), bytes);
    // Nextest isolates this test; the positive control consumed sequence zero.
    let collision = format!(".support-export-1-{}.tmp", GrainId::of(&bytes));
    for name in [
        collision.as_str(),
        ".SUPPORT-EXPORT-reserved.tmp",
        ".ſupport-export-reserved.tmp",
    ] {
        let out = f.out.join(name);
        ops.clear_calls();
        assert_eq!(
            (
                published(publish::publish(
                    &ops,
                    &PathLinks,
                    f.request(),
                    &out,
                    &s,
                    &d,
                    &bytes
                )),
                out.exists(),
                ops.calls()
                    .iter()
                    .any(|c| matches!(c, Call::CreateExclAt(_)))
            ),
            ("output name is in temporary namespace".into(), false, false),
            "temporary namespace must refuse before creation: {name}"
        );
    }
    for name in ["ordinary", ".archive", ".support-exported"] {
        let out = f.out.join(name);
        publish::publish(&ops, &PathLinks, f.request(), &out, &s, &d, &bytes).unwrap();
        assert_eq!(std::fs::read(out).unwrap(), bytes);
    }
}

#[test]
#[cfg(unix)]
fn support_export_temporary_removed_once() {
    use crate::support::publish::{self, Links};
    use std::sync::{Mutex, atomic::AtomicUsize};
    struct CountRemovals(Mutex<Vec<std::path::PathBuf>>);
    impl Links for CountRemovals {
        fn remove(&self, path: &Path) -> io::Result<()> {
            self.0.lock().unwrap().push(path.to_path_buf());
            std::fs::remove_file(path)
        }
    }
    let f = Fixture::new();
    f.positive();
    let ops = Recorder::new();
    let (bytes, s, d) = collect(&ops, f.request(), &f.clock()).unwrap();
    for fail_second_sync in [false, true] {
        let links = CountRemovals(Mutex::new(Vec::new()));
        let ops = Recorder::new();
        let syncs = AtomicUsize::new(0);
        ops.set_hook(move |call, phase| {
            if matches!(call, Call::SyncDir { .. })
                && phase == Phase::Before
                && syncs.fetch_add(1, Ordering::Relaxed) == 1
                && fail_second_sync
            {
                return Err(io::Error::other("injected second directory sync failure"));
            }
            Ok(())
        });
        let out = f.out.join(format!("archive-{fail_second_sync}"));
        let result = publish::publish(&ops, &links, f.request(), &out, &s, &d, &bytes);
        let removed = links.0.lock().unwrap();
        assert_eq!(
            (
                if fail_second_sync {
                    matches!(result, Err(SupportExportError::PublicationUncertain(_)))
                } else {
                    result.is_ok()
                },
                std::fs::read(out).unwrap() == bytes,
                removed.len(),
                removed.iter().all(|p| !p.exists())
            ),
            (true, true, 1, true),
            "successful unlink disarms cleanup, second sync fault: {fail_second_sync}; {result:?}"
        );
    }
}

#[test]
#[cfg(unix)]
#[allow(clippy::too_many_lines, clippy::items_after_statements)] // Local attack seams belong with their paired controls.
fn support_export_linux_private_no_replace() {
    use crate::support::publish::{self, Links, PathLinks};
    let f = Fixture::new();
    f.positive();
    let ops = Recorder::new();
    let (bytes, s, d) = collect(&ops, f.request(), &f.clock()).unwrap();
    let dest = f.out.join("archive");
    publish_support_export(f.request(), &dest, &f.clock()).unwrap();
    assert_eq!(
        (
            std::fs::read(&dest).unwrap(),
            std::fs::metadata(&dest).unwrap().mode() & 0o7777,
            std::fs::metadata(&f.out).unwrap().mode() & 0o7777,
            std::fs::read_dir(&f.out).unwrap().count()
        ),
        (bytes.clone(), 0o600, 0o700, 1)
    );
    assert_eq!(
        publish::publish(&ops, &PathLinks, f.request(), &dest, &s, &d, &bytes)
            .unwrap_err()
            .to_string(),
        "output already exists"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), bytes);
    struct Race;
    impl Links for Race {
        fn before_link(&self, _from: &Path, to: &Path) -> io::Result<()> {
            std::fs::write(to, b"planted destination")
        }
        fn remove(&self, path: &Path) -> io::Result<()> {
            std::fs::remove_file(path)
        }
    }
    let race = f.out.join("racing");
    let result = publish::publish(&ops, &Race, f.request(), &race, &s, &d, &bytes);
    assert_eq!(
        (
            matches!(result, Err(SupportExportError::Io(ref e)) if e.kind() == io::ErrorKind::AlreadyExists),
            std::fs::read(&race).unwrap()
        ),
        (true, b"planted destination".to_vec()),
        "link refuses racing destination"
    );
    for mode in [Mode::empty(), Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP] {
        let restricted = Recorder::with_create_mode(mode);
        let out = f.out.join(format!("mode-{}", mode.bits()));
        publish::publish(&restricted, &PathLinks, f.request(), &out, &s, &d, &bytes).unwrap();
        assert_eq!(std::fs::metadata(out).unwrap().mode() & 0o7777, 0o600);
    }
    for source in [&f.s, &f.d] {
        assert_eq!(
            publish::publish(
                &ops,
                &PathLinks,
                f.request(),
                &source.join("bad"),
                &s,
                &d,
                &bytes
            )
            .unwrap_err()
            .to_string(),
            "output inside source tree"
        );
    }
    chmod(&f.out, 0o750);
    assert!(
        publish::publish(
            &ops,
            &PathLinks,
            f.request(),
            &f.out.join("unsafe"),
            &s,
            &d,
            &bytes
        )
        .is_err()
    );
    chmod(&f.out, 0o700);
    let planted_ops = Recorder::new();
    let planting_root = f.out.clone();
    let planted = Arc::new(std::sync::Mutex::new(None));
    let plant_hook = planted.clone();
    planted_ops.set_hook(move |call, phase| {
        if let Call::CreateExclAt(name) = call
            && phase == Phase::Before
            && plant_hook.lock().unwrap().is_none()
        {
            let path = planting_root.join(name);
            std::fs::write(&path, b"existing temporary sentinel")?;
            chmod(&path, 0o600);
            *plant_hook.lock().unwrap() = Some(path);
        }
        Ok(())
    });
    let exclusive = f.out.join("exclusive");
    publish::publish(
        &planted_ops,
        &PathLinks,
        f.request(),
        &exclusive,
        &s,
        &d,
        &bytes,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(planted.lock().unwrap().as_ref().unwrap()).map_err(|e| e.kind()),
        Ok(b"existing temporary sentinel".to_vec()),
        "exclusive creation must preserve a planted temporary"
    );
    let descriptor = Recorder::with_descriptor_kind(0o010_000);
    let special = f.out.join("special-temp");
    assert_eq!(
        (
            publish::publish(
                &descriptor,
                &PathLinks,
                f.request(),
                &special,
                &s,
                &d,
                &bytes
            )
            .unwrap_err()
            .to_string(),
            special.exists(),
            descriptor.calls().contains(&Call::WriteAt)
        ),
        ("unsafe archive temporary".into(), false, false)
    );
    chmod(&f.out, 0o500);
    assert_eq!(
        publish::publish(
            &ops,
            &PathLinks,
            f.request(),
            &f.out.join("strict"),
            &s,
            &d,
            &bytes
        )
        .unwrap_err()
        .to_string(),
        "output parent must be invoking uid and 0700"
    );
    chmod(&f.out, 0o700);
    if !nix::unistd::geteuid().is_root() {
        let root_caller = Recorder::with_euid(0);
        assert_eq!(
            publish::publish(
                &root_caller,
                &PathLinks,
                f.request(),
                &f.out.join("root"),
                &s,
                &d,
                &bytes
            )
            .unwrap_err()
            .to_string(),
            "output parent must be invoking uid and 0700"
        );
    }
    for (stage, uncertain) in [
        (Call::WriteAt, false),
        (Call::SyncFile { ino: 0 }, false),
        (Call::SyncDir { ino: 0 }, true),
    ] {
        let failing = Recorder::new();
        let wanted = stage.clone();
        failing.set_hook(move |call, phase| {
            if phase == Phase::Before
                && (*call == wanted
                    || matches!(
                        (call, &wanted),
                        (Call::SyncFile { .. }, Call::SyncFile { .. })
                            | (Call::SyncDir { .. }, Call::SyncDir { .. })
                    ))
            {
                return Err(io::Error::other("injected publication fault"));
            }
            Ok(())
        });
        let out = f.out.join(format!("fault-{uncertain}-{stage:?}"));
        let result = publish::publish(&failing, &PathLinks, f.request(), &out, &s, &d, &bytes);
        assert_eq!(
            (
                matches!(result, Err(SupportExportError::PublicationUncertain(_))),
                out.exists()
            ),
            (uncertain, uncertain),
            "stage {stage:?}: {result:?}"
        );
        if uncertain {
            assert_eq!(std::fs::read(out).unwrap(), bytes);
        }
    }
    for before_sync in [true, false] {
        let linked = Recorder::new();
        let directory = f.out.clone();
        let sibling = directory.join(format!("temporary-link-{before_sync}"));
        let sibling_hook = sibling.clone();
        linked.set_hook(move |call, phase| {
            if phase == Phase::After {
                let name = match call {
                    Call::CreateExclAt(name) if before_sync => Some(name.clone()),
                    Call::SyncFile { .. } if !before_sync => std::fs::read_dir(&directory)?
                        .collect::<io::Result<Vec<_>>>()?
                        .into_iter()
                        .find(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".support-export-")
                                && entry.metadata().is_ok_and(|m| m.len() > 27)
                        })
                        .map(|entry| entry.file_name().to_string_lossy().into_owned()),
                    _ => None,
                };
                if let Some(name) = name {
                    std::fs::hard_link(directory.join(name), &sibling_hook)?;
                }
            }
            Ok(())
        });
        let out = f.out.join(format!("linked-temporary-{before_sync}"));
        let result = publish::publish(&linked, &PathLinks, f.request(), &out, &s, &d, &bytes);
        assert_eq!(
            (
                published(result),
                out.exists(),
                linked.calls().contains(&Call::WriteAt)
            ),
            (
                if before_sync {
                    "archive temporary is not sole regular".into()
                } else {
                    "archive temporary is not sole private regular".into()
                },
                false,
                !before_sync
            ),
            "a linked temporary must refuse at the corresponding descriptor check"
        );
        std::fs::remove_file(sibling).unwrap();
    }
    struct RefuseRemoval;
    impl Links for RefuseRemoval {
        fn remove(&self, _path: &Path) -> io::Result<()> {
            Err(io::Error::other("injected temporary removal failure"))
        }
    }
    let cleanup = f.out.join("cleanup-failed");
    let result = publish::publish(&ops, &RefuseRemoval, f.request(), &cleanup, &s, &d, &bytes);
    assert_eq!(
        (
            matches!(result, Err(SupportExportError::PublicationUncertain(_))),
            std::fs::read(&cleanup).unwrap()
        ),
        (true, bytes.clone()),
        "post-link cleanup failure retains the complete artifact with uncertainty"
    );
    for entry in std::fs::read_dir(&f.out).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".support-export-")
            && entry.metadata().unwrap().len() > 27
        {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    struct RecheckSwap;
    impl Links for RecheckSwap {
        fn link(&self, from: &Path, to: &Path) -> io::Result<()> {
            std::fs::hard_link(from, to)
        }
        fn remove(&self, path: &Path) -> io::Result<()> {
            std::fs::remove_file(path)
        }
        fn named_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
            let bytes = std::fs::read(path)?;
            std::fs::remove_file(path)?;
            std::fs::write(path, bytes)?;
            chmod(path, 0o600);
            std::fs::symlink_metadata(path)
        }
    }
    let recheck = f.out.join("recheck");
    assert_eq!(
        (
            published(publish::publish(
                &ops,
                &RecheckSwap,
                f.request(),
                &recheck,
                &s,
                &d,
                &bytes
            )),
            recheck.exists()
        ),
        ("archive temporary changed".into(), false),
        "fresh pathname identity must agree with the verified descriptor"
    );
    let replaced = Recorder::new();
    let directory = f.out.clone();
    replaced.set_hook(move |call, phase| {
        if matches!(call, Call::SyncFile { .. }) && phase == Phase::After {
            let temp = std::fs::read_dir(&directory)?
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .find(|p| {
                    std::fs::metadata(p).unwrap().len() > 27
                        && p.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".support-export-")
                })
                .unwrap();
            let length = std::fs::metadata(&temp)?.len();
            std::fs::remove_file(&temp)?;
            std::fs::write(&temp, vec![0; usize::try_from(length).unwrap()])?;
            chmod(&temp, 0o600);
        }
        Ok(())
    });
    let replant = f.out.join("replanted");
    assert_eq!(
        (
            published(publish::publish(
                &replaced,
                &PathLinks,
                f.request(),
                &replant,
                &s,
                &d,
                &bytes
            )),
            replant.exists()
        ),
        ("archive temporary content mismatch".into(), false)
    );
}

#[test]
#[cfg(unix)]
fn support_export_linux_socket_sources() {
    let f = Fixture::new();
    f.positive();
    let log = f.d.join("alpha.log");
    std::fs::remove_file(&log).unwrap();
    let socket = std::os::unix::net::UnixListener::bind(&log).unwrap();
    let ops = Recorder::new();
    let state = walk(&ops, &f.d, true).unwrap();
    ops.clear_calls();
    assert_eq!(
        (
            read_log(&ops, &state, &VolumeName::new("alpha".into()).unwrap()),
            ops.calls()
                .iter()
                .filter(|c| matches!(c, Call::OpenReadAt(_) | Call::ReadAt))
                .count()
        ),
        (Err(ExportRefusal::NonRegular), 0)
    );
    drop(socket);
}

#[test]
#[cfg(target_os = "linux")]
fn support_export_linux_device_sources_as_root() {
    if !nix::unistd::geteuid().is_root() {
        return;
    }
    let f = Fixture::new();
    f.positive();
    let path = f.d.join("alpha.log");
    std::fs::remove_file(&path).unwrap();
    let device = std::fs::metadata("/dev/null").unwrap().rdev();
    // Root in a user namespace (a rootless container) has no CAP_MKNOD over
    // real devices; the FIFO and socket rows cover the same type guard there.
    match nix::sys::stat::mknod(
        &path,
        nix::sys::stat::SFlag::S_IFCHR,
        Mode::S_IRUSR | Mode::S_IWUSR,
        device,
    ) {
        Ok(()) => {}
        Err(nix::errno::Errno::EPERM) => return,
        Err(e) => panic!("mknod: {e}"),
    }
    let ops = Recorder::new();
    let state = walk(&ops, &f.d, true).unwrap();
    ops.clear_calls();
    assert_eq!(
        (
            read_log(&ops, &state, &VolumeName::new("alpha".into()).unwrap()),
            ops.calls()
                .iter()
                .filter(|c| matches!(c, Call::OpenReadAt(_) | Call::ReadAt))
                .count()
        ),
        (Err(ExportRefusal::NonRegular), 0)
    );
}
