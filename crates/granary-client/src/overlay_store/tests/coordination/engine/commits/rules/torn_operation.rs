// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Power cuts between the frames one truncate or one write appends (its own
//! record, then one record per surviving fragment of an older write), and a
//! stage body written back without its record. After the reopen, what the
//! mount reads must be what the next fsync acknowledges and the next commit
//! publishes, and no acknowledged byte may be replaced by one the user never
//! wrote after the acknowledgement.

use super::*;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn fsync(rt: &tokio::runtime::Runtime, f: &Fixture, stage: u64) -> Result<(), String> {
    rt.block_on(async {
        f.engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await
    })
    .map_err(|e| e.to_string())
}

fn fsyncdir(rt: &tokio::runtime::Runtime, f: &Fixture) {
    rt.block_on(async {
        f.engine
            .sync(SyncTarget::Directory(None), SyncOptions::default())
            .wait()
            .await
    })
    .unwrap();
}

fn truncate(f: &Fixture, stage: u64, size: u64) {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, size))
        .unwrap();
}

fn persist(f: &Fixture) {
    let _ = try_persist_content(f);
}

/// Crash and reopen over the newest installed head.
fn restart(rt: &tokio::runtime::Runtime, f: Fixture) -> Result<Fixture, String> {
    let seq = *f
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .0;
    let result = if seq == 1 {
        rt.block_on(f.try_restart_over(vec![]))
    } else {
        rt.block_on(f.try_restart_at_head())
    };
    result.map_err(|e| e.to_string())
}

pub(super) fn copy_up_y(f: &Fixture) -> u64 {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.copy_up(crate::overlay_store::tests::incremental::loc("y")))
        .unwrap()
}

fn live(io: &SimIo, file_name: &str) -> Vec<u8> {
    let m = io.0.lock().unwrap();
    let (_, id) = m
        .names
        .iter()
        .find(|(p, _)| {
            p.file_name().is_some_and(|n| n == file_name)
                && p.components().any(|c| c.as_os_str() == "overlay")
        })
        .unwrap();
    m.files[id].0.clone()
}

fn records(journal: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    granary_core::overlay_journal::scan_journal_with(journal, |seq, record| {
        let text = format!("{record:?}");
        let kind = text.split([' ', '{', '(']).next().unwrap_or("");
        let detail = match record {
            Record::WriteExtent { offset, length, .. } => format!(" @{offset}+{length}"),
            Record::Truncate { new_size, .. } => format!(" to {new_size}"),
            _ => String::new(),
        };
        out.push(format!("{seq}:{kind}{detail}"));
    })
    .unwrap();
    out
}

fn marks(f: &Fixture, stage: u64) -> Vec<(GrainId, u64)> {
    let journal = live(&f.io, "journal");
    let mut out = Vec::new();
    granary_core::overlay_journal::scan_journal_with(&journal, |_, record| {
        if let Record::FileSynced {
            stage_id,
            synced_size,
            content,
            ..
        } = record
            && *stage_id == stage
        {
            out.push((*content, *synced_size));
        }
    })
    .unwrap();
    out
}

fn mark_bytes(f: &Fixture, stage: u64) -> Option<Vec<u8>> {
    let (content, size) = *marks(f, stage).last()?;
    Some(
        f.content
            .read_content(content, 0, usize::try_from(size).unwrap())
            .unwrap(),
    )
}

fn text(bytes: Option<&[u8]>) -> String {
    bytes.map_or_else(
        || "(none)".to_owned(),
        |b| format!("{:?}", String::from_utf8_lossy(b)),
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Start {
    /// A new file, fsynced as `y-data-1`.
    Synced,
    /// A published `y-data-1`, copied up.
    Published,
    /// A new file whose first write was never fsynced: no mark, no base.
    Fresh,
    /// As `Synced`, then overwritten unsynced and rolled back to its mark.
    RolledBack,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Then {
    Fsync,
    Commit,
}

/// One row: a start, work before the cut operation (which may fsync), the
/// writes made after the newest acknowledgement, and the cut operation.
struct Row {
    label: &'static str,
    start: Start,
    before: fn(&tokio::runtime::Runtime, &Fixture, u64),
    /// Every write after the acknowledgement the row ends on, the cut
    /// operation's included: the only bytes that may replace acknowledged ones.
    later_writes: &'static [(u64, &'static [u8])],
    last: fn(&Fixture, u64),
}

struct Built {
    rt: tokio::runtime::Runtime,
    f: Fixture,
    y: u64,
    acknowledged: Option<Vec<u8>>,
    before: usize,
    journal: Vec<u8>,
}

fn build(row: &Row) -> Built {
    let rt = rt();
    let mut f = rt.block_on(Fixture::new());
    fsyncdir(&rt, &f);
    let y = match row.start {
        Start::Synced => {
            let y = f.create("y", b"y-data-1");
            fsync(&rt, &f, y).unwrap();
            y
        }
        Start::RolledBack => {
            let y = f.create("y", b"y-data-1");
            fsync(&rt, &f, y).unwrap();
            published::write(&f, y, 0, b"Y-DATA-2");
            let w = f.create("w", b"w-data");
            fsync(&rt, &f, w).unwrap();
            f = restart(&rt, f)
                .unwrap_or_else(|e| panic!("{}: the rollback setup refused: {e}", row.label));
            persist(&f);
            assert_eq!(
                published::local_file(&f, "y").as_deref(),
                Some(&b"y-data-1"[..]),
                "{}: the setup rolls y back to its mark",
                row.label
            );
            y
        }
        Start::Fresh => {
            let y = f.create("y", b"");
            fsyncdir(&rt, &f);
            y
        }
        Start::Published => {
            f.create("y", b"y-data-1");
            rt.block_on(published::commit_all(&f, 70));
            persist(&f);
            copy_up_y(&f)
        }
    };
    (row.before)(&rt, &f, y);
    let acknowledged = mark_bytes(&f, y).or_else(|| {
        (row.start == Start::Published).then(|| published::head_file(&f, "y").unwrap())
    });
    let before = live(&f.io, "journal").len();
    (row.last)(&f, y);
    let journal = live(&f.io, "journal");
    Built {
        rt,
        f,
        y,
        acknowledged,
        before,
        journal,
    }
}

/// Byte `p` of `captured` keeps an acknowledged byte or one a later write put there.
fn replaced_acknowledged(row: &Row, acknowledged: &[u8], captured: &[u8]) -> Option<usize> {
    captured.iter().enumerate().position(|(p, byte)| {
        let p = p as u64;
        let kept = usize::try_from(p)
            .ok()
            .and_then(|i| acknowledged.get(i))
            .is_some_and(|a| a == byte);
        let written = row.later_writes.iter().any(|(offset, bytes)| {
            p >= *offset
                && usize::try_from(p - offset)
                    .ok()
                    .and_then(|i| bytes.get(i))
                    .is_some_and(|b| b == byte)
        });
        !kept && !written
    })
}

/// Keep the journal up to each frame boundary of the last operation (and one
/// torn cut), write every stage body back, power loss, reopen, then fsync or
/// commit. Returns each cut's violations.
fn cut_between_frames(row: &Row, then: Then) -> Vec<String> {
    let first = build(row);
    let mut cuts = vec![0, 1];
    for keep in 2..=first.journal.len() - first.before {
        let cut = first.before + keep;
        if records(&first.journal[..cut]).len() != records(&first.journal[..cut - 1]).len() {
            cuts.push(keep);
        }
    }
    assert!(
        cuts.len() >= 3,
        "{}: the last operation appends no frame",
        row.label
    );
    let (first_before, first_journal) = (first.before, first.journal.clone());
    drop(first);
    let mut bad = Vec::new();
    for keep in cuts {
        let Built {
            rt,
            f,
            y,
            acknowledged,
            before,
            journal,
        } = build(row);
        // Each cut is a frame boundary of the first build's journal; a rebuild
        // with other frames would cut somewhere else. Random identifiers may
        // differ, frame lengths and records may not.
        assert_eq!(
            (before, journal.len(), records(&journal)),
            (first_before, first_journal.len(), records(&first_journal)),
            "{}: the rebuilt journal differs from the first build",
            row.label
        );
        let cut = before + keep;
        persist(&f);
        // Page writeback: every stage body whole, the journal up to the cut.
        published::settle_disk(&f.io);
        f.io.mutate_recovered("journal", |durable| durable.truncate(cut));
        let frames: Vec<_> = records(&journal[..cut])
            .into_iter()
            .rev()
            .take(3)
            .rev()
            .collect();
        let at = format!(
            "{} {then:?}: journal cut {keep} bytes into the operation (last frames {frames:?})",
            row.label
        );
        let f = match restart(&rt, f) {
            Ok(f) => f,
            Err(e) => {
                bad.push(format!("{at}: the reopen refused: {e}"));
                continue;
            }
        };
        persist(&f);
        let read = published::local_file(&f, "y");
        let captured = match then {
            Then::Fsync => {
                if let Err(e) = fsync(&rt, &f, y) {
                    bad.push(format!("{at}: the fsync refused: {e}"));
                    continue;
                }
                // With no new record the fsync found the file equal to its
                // mark, or, with no mark, to its published base, and
                // acknowledged that content again.
                mark_bytes(&f, y).or_else(|| published::head_file(&f, "y"))
            }
            Then::Commit => {
                rt.block_on(published::commit_all(&f, 110));
                persist(&f);
                published::head_file(&f, "y")
            }
        };
        if read != captured {
            bad.push(format!(
                "{at}: the file reads {}, the capture names {}",
                text(read.as_deref()),
                text(captured.as_deref())
            ));
        }
        if let (Some(acknowledged), Some(captured)) = (&acknowledged, &captured)
            && let Some(p) = replaced_acknowledged(row, acknowledged, captured)
        {
            bad.push(format!(
                "{at}: byte {p} of the capture {} replaces acknowledged {} with a byte nobody wrote",
                text(Some(captured)),
                text(Some(acknowledged))
            ));
        }
        let after = published::local_file(&f, "y");
        if after != read {
            bad.push(format!(
                "{at}: the file read {} before the capture and {} after it",
                text(read.as_deref()),
                text(after.as_deref())
            ));
        }
    }
    bad
}

fn check(row: &Row) {
    let mut bad = Vec::new();
    for then in [Then::Fsync, Then::Commit] {
        bad.extend(cut_between_frames(row, then));
    }
    assert!(bad.is_empty(), "{} diverging cuts: {bad:#?}", bad.len());
}

fn nothing(_: &tokio::runtime::Runtime, _: &Fixture, _: u64) {}
fn write_xx(_: &tokio::runtime::Runtime, f: &Fixture, y: u64) {
    published::write(f, y, 2, b"XX");
}
fn write_abcdef(_: &tokio::runtime::Runtime, f: &Fixture, y: u64) {
    published::write(f, y, 1, b"ABCDEF");
}
fn write_fresh(_: &tokio::runtime::Runtime, f: &Fixture, y: u64) {
    published::write(f, y, 0, b"fresh-data");
}
fn write_ab_then_fsync(rt: &tokio::runtime::Runtime, f: &Fixture, y: u64) {
    published::write(f, y, 0, b"AB");
    fsync(rt, f, y).unwrap();
}
fn truncate_3(f: &Fixture, y: u64) {
    truncate(f, y, 3);
}
fn write_zz_inside(f: &Fixture, y: u64) {
    published::write(f, y, 3, b"zz");
}
fn write_zz_over_base(f: &Fixture, y: u64) {
    published::write(f, y, 4, b"ZZ");
}

const XX: &[(u64, &[u8])] = &[(2, b"XX")];
const ABCDEF_ZZ: &[(u64, &[u8])] = &[(1, b"ABCDEF"), (3, b"zz")];

/// The worst row: a new file fsynced as `y-data-1`, then only `truncate 3`
/// (a truncate frame and a fragment frame for bytes 0-3). Nothing unsynced
/// was written, so every capture must be `y-d`.
#[test]
fn truncate_without_its_fragment_keeps_synced_bytes() {
    check(&Row {
        label: "truncate, synced file, no other write",
        start: Start::Synced,
        before: nothing,
        later_writes: &[],
        last: truncate_3,
    });
}

#[test]
fn truncate_without_its_fragment_synced_file() {
    check(&Row {
        label: "XX then truncate, synced file",
        start: Start::Synced,
        before: write_xx,
        later_writes: XX,
        last: truncate_3,
    });
}

#[test]
fn truncate_without_its_fragment_published_file() {
    check(&Row {
        label: "XX then truncate, published file",
        start: Start::Published,
        before: write_xx,
        later_writes: XX,
        last: truncate_3,
    });
}

#[test]
fn truncate_without_its_fragment_fresh_file() {
    check(&Row {
        label: "truncate, never-synced file",
        start: Start::Fresh,
        before: write_fresh,
        later_writes: &[],
        last: truncate_3,
    });
}

#[test]
fn write_without_its_fragments_synced_file() {
    check(&Row {
        label: "ABCDEF then zz, synced file",
        start: Start::Synced,
        before: write_abcdef,
        later_writes: ABCDEF_ZZ,
        last: write_zz_inside,
    });
}

#[test]
fn write_without_its_fragments_published_file() {
    check(&Row {
        label: "ABCDEF then zz, published file",
        start: Start::Published,
        before: write_abcdef,
        later_writes: ABCDEF_ZZ,
        last: write_zz_inside,
    });
}

#[test]
fn truncate_without_its_fragment_rolled_back_file() {
    check(&Row {
        label: "XX then truncate, rolled-back file",
        start: Start::RolledBack,
        before: write_xx,
        later_writes: XX,
        last: truncate_3,
    });
}

#[test]
fn truncate_without_its_fragment_rolled_back_file_no_other_write() {
    check(&Row {
        label: "truncate, rolled-back file, no other write",
        start: Start::RolledBack,
        before: nothing,
        later_writes: &[],
        last: truncate_3,
    });
}

#[test]
fn write_without_its_fragments_rolled_back_file() {
    check(&Row {
        label: "ABCDEF then zz, rolled-back file",
        start: Start::RolledBack,
        before: write_abcdef,
        later_writes: ABCDEF_ZZ,
        last: write_zz_inside,
    });
}

/// A copied-up file, `AB` at 0 fsynced, then `ZZ` at 4 over base bytes: the
/// first cut keeps the stage body's `ZZ` without the record that claims it.
#[test]
fn unjournaled_write_over_base_bytes_after_fsync() {
    check(&Row {
        label: "AB fsynced, then ZZ over base bytes, published file",
        start: Start::Published,
        before: write_ab_then_fsync,
        later_writes: &[(4, b"ZZ")],
        last: write_zz_over_base,
    });
}

#[test]
fn replacement_drops_a_mirrored_mark_hidden_by_rollback() {
    use granary_core::overlay_journal::{MarkState, STAGING_HEADER_LEN, StagingHeader};

    let rt = rt();
    let f = rt.block_on(Fixture::new());
    f.create("y", b"ABCD");
    rt.block_on(published::commit_all(&f, 70));
    persist(&f);
    let y = copy_up_y(&f);
    let stage = format!("{y:016x}");

    published::write(&f, y, 4, b"+");
    published::settle_disk(&f.io);
    f.io.mutate_recovered(&stage, |body| body.truncate(STAGING_HEADER_LEN + 4));
    let f = restart(&rt, f).unwrap();
    let journal = records(&live(&f.io, "journal"));
    assert_eq!(
        (
            published::local_file(&f, "y"),
            journal
                .iter()
                .filter_map(|record| record.split_once(':'))
                .map(|(_, kind)| kind)
                .filter(|kind| *kind == "StageRollback")
                .collect::<Vec<_>>(),
        ),
        (Some(b"ABCD".to_vec()), vec!["StageRollback"]),
        "premise: the lost append rolls back to the published base"
    );

    published::write(&f, y, 0, b"X");
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("overlay.mark.sync", "after", 1, FaultAction::Crash);
    let interrupted = fsync(&rt, &f, y);
    let raw = f.io.recovered_bytes(&stage).unwrap();
    let header = StagingHeader::decode(&raw[..STAGING_HEADER_LEN]).unwrap();
    let mirror = match header.mark {
        MarkState::Present(mark) => Some(f.content.read_content(mark.content, 0, 4).unwrap()),
        _ => None,
    };
    assert_eq!(
        (
            interrupted.is_err(),
            faults
                .fired()
                .iter()
                .map(|hit| (hit.name, hit.phase))
                .collect::<Vec<_>>(),
            mirror,
            marks(&f, y),
        ),
        (
            true,
            vec![("overlay.mark.sync", "after")],
            Some(b"XBCD".to_vec()),
            vec![],
        ),
        "premise: the X receipt survives only in the staging header"
    );
    let mut f = restart(&rt, f).unwrap();
    published::write(&f, y, 0, b"Y");
    published::hold(&f, "y");
    rt.block_on(published::commit_all(&f, 80));
    persist(&f);

    for (reopen, seed) in [(1, 90), (2, 100)] {
        f = restart(&rt, f).unwrap();
        published::hold(&f, "y");
        let read = published::local_file(&f, "y");
        fsync(&rt, &f, y).unwrap();
        let synced = mark_bytes(&f, y).or_else(|| published::head_file(&f, "y"));
        rt.block_on(published::commit_all(&f, seed));
        let committed = published::head_file(&f, "y");
        assert_eq!(
            (
                text(read.as_deref()),
                text(synced.as_deref()),
                text(committed.as_deref())
            ),
            (
                r#""YBCD""#.to_owned(),
                r#""YBCD""#.to_owned(),
                r#""YBCD""#.to_owned()
            ),
            "reopen {reopen}: read, fsync and commit must agree with the landed bytes"
        );
        persist(&f);
    }
}

#[test]
fn recovery_replacement_repairs_a_carried_stages_unchecked_bytes() {
    let rt = rt();
    let f = rt.block_on(Fixture::new());
    f.create("y", b"ABCD");
    rt.block_on(published::commit_all(&f, 60));
    persist(&f);
    let y = copy_up_y(&f);
    published::write(&f, y, 0, b"XY");

    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "before_replace", 1, FaultAction::Fail);
    let interrupted = rt.block_on(first_commit_fault(&f, "before_replace"));
    assert_eq!(
        (
            interrupted.map(|error| error.to_string()),
            durable_commit_state(&f),
            published::head_file(&f, "y"),
        ),
        (
            Some(CoordinationError::Refused("SyncInjectedFault").to_string()),
            (Some(("complete", 1)), (true, true)),
            Some(b"XYCD".to_vec()),
        ),
        "premise: XYCD landed durably and replacement is owed"
    );
    persist(&f);
    let before = live(&f.io, "journal").len();
    published::write(&f, y, 0, b"Z");
    let journal = live(&f.io, "journal");
    let count = records(&journal[..before]).len();
    let cut = (before + 1..journal.len())
        .find(|&cut| records(&journal[..cut]).len() == count + 1)
        .unwrap_or_else(|| {
            panic!(
                "the overwrite appended {:?}",
                records(&journal)[count..].to_vec()
            )
        });
    let suffix = records(&journal);
    let suffix: Vec<_> = suffix[count..]
        .iter()
        .filter_map(|record| record.split_once(':').map(|(_, kind)| kind))
        .collect();
    assert_eq!(suffix, ["WriteExtent @0+1", "WriteExtent @1+1"]);
    published::settle_disk(&f.io);
    f.io.mutate_recovered("journal", |durable| durable.truncate(cut));

    let base = f.remote.published.lock().unwrap()[&2].clone();
    let f = rt
        .block_on(f.try_restart_at_published(2, base, false))
        .unwrap();
    let lane = f.engine.recover_commit(SyncOptions::default()).unwrap();
    rt.block_on(Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(90),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    )))
    .unwrap();

    let read = published::local_file(&f, "y");
    fsync(&rt, &f, y).unwrap();
    let synced = mark_bytes(&f, y);
    rt.block_on(published::commit_all(&f, 100));
    let committed = published::head_file(&f, "y");
    assert_eq!(
        (
            text(read.as_deref()),
            text(synced.as_deref()),
            text(committed.as_deref())
        ),
        (
            r#""ZYCD""#.to_owned(),
            r#""ZYCD""#.to_owned(),
            r#""ZYCD""#.to_owned()
        ),
        "the first read, fsync and commit after recovery must agree with the installed image"
    );
}
