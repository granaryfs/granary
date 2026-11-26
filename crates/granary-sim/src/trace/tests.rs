// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::trace` — the sim's replay artifact:
//! the structured operation log the fakes append to, and its
//! formatter.
//!
//! Out-of-line: `granary-sim`'s non-test artifact has its
//! own `tests/` directory
//! (`crates/granary-sim/tests/replay_across_processes.rs`,
//! `scenarios.rs`) and its own `[[bin]]`
//! (`src/bin/sim-replay.rs`) — either alone is enough. What
//! does NOT apply: nothing in the workspace depends on
//! `granary-sim`; `granary-sim` depends on `granary-client`,
//! not the reverse. So the module's own tests move out of
//! the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::{
    Address, Barrier, Damage, DrawRow, Fill, IoKind, LogCall, LogOp, LogPath, LogViolation, Op,
    Outcome, Refusal, Trace, TraceError, TruncationDraw, Verdict, Volume,
};
use std::io;

const A: Address = Address::new([0xaa; 32]);
const B: Address = Address::new([0xbb; 32]);
const C: Address = Address::new([0xcc; 32]);

fn demo() -> Volume {
    Volume::new("demo").expect("demo is a DNS-1123 label")
}

/// A trace touching every [`Op`] and every [`Outcome`] variant.
fn every_variant() -> Trace {
    let mut t = Trace::new();
    let vol = demo;
    t.record(0, Op::MaxSeq { volume: vol() }, Outcome::Ok);
    t.record(0, Op::PutBin { addr: A }, Outcome::Novel);
    t.record(
        1,
        Op::PutMeta {
            volume: vol(),
            addr: B,
        },
        Outcome::Unchanged,
    );
    t.record(
        1,
        Op::PutRoot {
            volume: vol(),
            seq: 2,
            addr: C,
        },
        Outcome::Ok,
    );
    t.record(
        0,
        Op::WriteHint {
            volume: vol(),
            seq: 2,
        },
        Outcome::Ok,
    );
    t.record(
        2,
        Op::GetBinRange {
            addr: A,
            offset: 10,
            len: 5,
        },
        Outcome::Ok,
    );
    t.record(
        2,
        Op::GetMeta {
            volume: vol(),
            addr: B,
        },
        Outcome::Failed(TraceError::NotFound),
    );
    t.record(
        2,
        Op::GetRoot {
            volume: vol(),
            seq: 9,
        },
        Outcome::Absent,
    );
    t.record(
        2,
        Op::ReadHint { volume: vol() },
        Outcome::Failed(TraceError::Io(IoKind::PermissionDenied)),
    );
    t.record(3, Op::GetGrain { addr: C }, Outcome::Ok);
    t.record(3, Op::HasGrain { addr: C }, Outcome::Absent);
    // The rejected-name sentinel is part of the rendered surface, so
    // it belongs in the corpus the alphabet and ambient-value tests
    // run over — not only in the volume tests below.
    t.record(
        3,
        Op::MaxSeq {
            volume: Volume::rejected(),
        },
        Outcome::Failed(TraceError::InvalidVolume),
    );
    record_held_and_admin(&mut t);
    for op in every_log_op() {
        t.record(5, Op::Log(op), Outcome::Ok);
    }
    t.record(
        5,
        Op::Log(LogOp::FileSync {
            path: LogPath::Marker,
        }),
        Outcome::Failed(TraceError::SyncFailed),
    );
    t.record(
        5,
        Op::Log(LogOp::Call {
            call: LogCall::Truncate,
            volume: Some(demo()),
        }),
        Outcome::Failed(TraceError::OutOfRange),
    );
    t
}

/// Every [`LogOp`] variant at least once, and every path, call, row,
/// barrier and violation name.
fn every_log_op() -> Vec<LogOp> {
    let mut ops = log_calls_and_steps();
    ops.extend(log_crash_and_harness_ops());
    ops
}

/// [`every_log_op`]'s first half: the calls and the steps.
fn log_calls_and_steps() -> Vec<LogOp> {
    let log = || LogPath::Log(demo());
    let mut ops: Vec<LogOp> = [
        LogCall::ReadMarker,
        LogCall::WriteMarker,
        LogCall::Read,
        LogCall::RemoveTemporary,
        LogCall::Initialise,
        LogCall::CompleteNamespace,
        LogCall::Append,
        LogCall::Truncate,
        LogCall::Resync,
    ]
    .into_iter()
    .map(|call| LogOp::Call {
        call,
        volume: matches!(call, LogCall::Append).then(demo),
    })
    .collect();
    ops.extend([
        LogOp::Write {
            path: log(),
            len: 3,
            addr: A,
        },
        LogOp::FileSync {
            path: LogPath::Temp(demo()),
        },
        LogOp::DirSync {
            path: LogPath::StateDir,
        },
        LogOp::Create {
            path: LogPath::MarkerTemp,
            exclusive: false,
        },
        LogOp::Create {
            path: LogPath::Temp(demo()),
            exclusive: true,
        },
        LogOp::Mkdir {
            path: LogPath::StateDir,
        },
        LogOp::Link {
            from: LogPath::Temp(demo()),
            to: log(),
        },
        LogOp::Unlink {
            path: LogPath::Temp(demo()),
        },
        LogOp::Rename {
            from: LogPath::MarkerTemp,
            to: LogPath::Marker,
        },
        LogOp::Truncate {
            path: log(),
            len: 44,
        },
        LogOp::Read {
            path: LogPath::Anchor,
        },
    ]);
    ops
}

/// [`every_log_op`]'s second half: the ends of a run, the draws, the
/// faults, the violations and the harness's own entries.
fn log_crash_and_harness_ops() -> Vec<LogOp> {
    let log = || LogPath::Log(demo());
    let mut ops = vec![
        LogOp::Restart,
        LogOp::Crash {
            pending: 3,
            kept: 1,
        },
        LogOp::Draw {
            path: log(),
            truncation: TruncationDraw::Kept,
            base: 44,
            written: 10,
            kept: 4,
            garbage: 2,
            fill: Fill::Seeded,
        },
        LogOp::Draw {
            path: log(),
            truncation: TruncationDraw::None,
            base: 0,
            written: 0,
            kept: 0,
            garbage: 0,
            fill: Fill::Zero,
        },
        LogOp::Draw {
            path: log(),
            truncation: TruncationDraw::Undone,
            base: 0,
            written: 0,
            kept: 0,
            garbage: 0,
            fill: Fill::None,
        },
    ];
    ops.extend(
        [
            DrawRow::RecordAbsent,
            DrawRow::RecordTorn,
            DrawRow::RecordWholeUnsynced,
            DrawRow::MarkAbsentOrTorn,
            DrawRow::Survivor,
            DrawRow::LostWithUndoneTruncation,
        ]
        .into_iter()
        .map(|row| LogOp::Row {
            path: log(),
            at: 44,
            row,
        }),
    );
    ops.extend([
        LogOp::File {
            path: log(),
            len: 3,
            addr: B,
        },
        LogOp::StateDir { present: true },
        LogOp::StateDir { present: false },
        LogOp::Damage {
            path: log(),
            damage: Damage::Detectable,
            start: 50,
            end: 51,
        },
        LogOp::Damage {
            path: log(),
            damage: Damage::Residual,
            start: 60,
            end: 90,
        },
    ]);
    ops.extend(log_violation_ops());
    ops.extend(log_verdict_ops());
    ops.extend([
        LogOp::Seed {
            path: LogPath::Temp(demo()),
            len: 0,
            addr: C,
        },
        LogOp::SeedEmptyStateDir,
        LogOp::Reset,
    ]);
    ops
}

/// Every [`LogViolation`], as the log entries that record them.
fn log_violation_ops() -> Vec<LogOp> {
    [
        LogViolation::MarkBeforeRecordSync,
        LogViolation::WriteBeforeBarrier(Barrier::Marker),
        LogViolation::WriteBeforeBarrier(Barrier::Initialise),
        LogViolation::WriteBeforeBarrier(Barrier::CompleteNamespace),
        LogViolation::WriteBeforeBarrier(Barrier::Truncation),
        LogViolation::WriteBeforeBarrier(Barrier::SurvivorResync),
        LogViolation::AfterFence,
        LogViolation::SameBootAfterFence,
        LogViolation::TailNotTruncated,
        LogViolation::ConcurrentCall,
        LogViolation::EpochMismatch,
        LogViolation::OverlappingCall,
        LogViolation::StepAfterFence,
    ]
    .into_iter()
    .map(LogOp::Violation)
    .collect()
}

/// [`every_log_op`]'s verdicts: each shape, and each refusal's reason.
fn log_verdict_ops() -> Vec<LogOp> {
    let log = || LogPath::Log(demo());
    let mut ops = Vec::new();
    ops.extend(
        [
            Verdict::Absent,
            Verdict::NoEnvelope,
            Verdict::Log {
                records: 3,
                committed: 900,
                tail: 12,
            },
            Verdict::Refused {
                reason: Refusal::UnknownVersion,
                offset: 0,
            },
            Verdict::Refused {
                reason: Refusal::EnvelopeMalformed,
                offset: 0,
            },
            Verdict::Refused {
                reason: Refusal::WrongVolume,
                offset: 0,
            },
            Verdict::Refused {
                reason: Refusal::DamagedHistory,
                offset: 44,
            },
            Verdict::Refused {
                reason: Refusal::Grammar(6),
                offset: 700,
            },
        ]
        .into_iter()
        .map(|verdict| LogOp::Verdict {
            path: log(),
            verdict,
        }),
    );
    ops
}

/// [`every_variant`]'s tail: a held write's two entries and the admin
/// handle's three, in the order the line-format pin expects.
fn record_held_and_admin(t: &mut Trace) {
    let vol = demo;
    t.record(
        1,
        Op::PutRoot {
            volume: vol(),
            seq: 3,
            addr: A,
        },
        Outcome::Failed(TraceError::Deferred),
    );
    t.record(
        1,
        Op::ReleaseRoot {
            volume: vol(),
            seq: 3,
            addr: A,
        },
        Outcome::Failed(TraceError::AlreadyExists),
    );
    t.record(
        4,
        Op::AdminPlantRoot {
            volume: vol(),
            seq: 7,
            addr: B,
        },
        Outcome::Ok,
    );
    t.record(
        4,
        Op::AdminDeleteRoot {
            volume: vol(),
            seq: 0,
        },
        Outcome::Absent,
    );
    t.record(4, Op::AdminListRoots { volume: vol() }, Outcome::Ok);
}

#[test]
fn render_pins_the_line_format() {
    let (a, b, c) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
    let expected = format!(
        "n0 max-seq vol=demo -> ok\n\
         n0 put-bin addr={a} -> novel\n\
         n1 put-meta vol=demo addr={b} -> unchanged\n\
         n1 put-root vol=demo seq=2 addr={c} -> ok\n\
         n0 write-hint vol=demo seq=2 -> ok\n\
         n2 get-bin-range addr={a} off=10 len=5 -> ok\n\
         n2 get-meta vol=demo addr={b} -> failed(not-found)\n\
         n2 get-root vol=demo seq=9 -> absent\n\
         n2 read-hint vol=demo -> failed(io:permission-denied)\n\
         n3 get-grain addr={c} -> ok\n\
         n3 has-grain addr={c} -> absent\n\
         n3 max-seq vol=-rejected- -> failed(invalid-volume)\n\
         n1 put-root vol=demo seq=3 addr={a} -> failed(deferred)\n\
         n1 release-root vol=demo seq=3 addr={a} -> failed(already-exists)\n\
         n4 admin-plant-root vol=demo seq=7 addr={b} -> ok\n\
         n4 admin-delete-root vol=demo seq=0 -> absent\n\
         n4 admin-list-roots vol=demo -> ok\n\
         n5 log-call call=read-marker -> ok\n\
         n5 log-call call=write-marker -> ok\n\
         n5 log-call call=read -> ok\n\
         n5 log-call call=remove-temporary -> ok\n\
         n5 log-call call=initialise -> ok\n\
         n5 log-call call=complete-namespace -> ok\n\
         n5 log-call call=append vol=demo -> ok\n\
         n5 log-call call=truncate -> ok\n\
         n5 log-call call=resync -> ok\n\
         n5 log-write path=log:demo len=3 addr={a} -> ok\n\
         n5 log-file-sync path=tmp:demo -> ok\n\
         n5 log-dir-sync path=state -> ok\n\
         n5 log-create path=marker-tmp excl=no -> ok\n\
         n5 log-create path=tmp:demo excl=yes -> ok\n\
         n5 log-mkdir path=state -> ok\n\
         n5 log-link from=tmp:demo to=log:demo -> ok\n\
         n5 log-unlink path=tmp:demo -> ok\n\
         n5 log-rename from=marker-tmp to=marker -> ok\n\
         n5 log-truncate path=log:demo len=44 -> ok\n\
         n5 log-read path=anchor -> ok\n\
         n5 log-restart -> ok\n\
         n5 log-crash ns-pending=3 ns-kept=1 -> ok\n\
         n5 log-draw path=log:demo trunc=kept base=44 written=10 kept=4 garbage=2 fill=seeded -> ok\n\
         n5 log-draw path=log:demo trunc=none base=0 written=0 kept=0 garbage=0 fill=zero -> ok\n\
         n5 log-draw path=log:demo trunc=undone base=0 written=0 kept=0 garbage=0 fill=none -> ok\n\
         n5 log-row path=log:demo at=44 row=record-absent -> ok\n\
         n5 log-row path=log:demo at=44 row=record-torn -> ok\n\
         n5 log-row path=log:demo at=44 row=record-whole-unsynced -> ok\n\
         n5 log-row path=log:demo at=44 row=mark-absent-or-torn -> ok\n\
         n5 log-row path=log:demo at=44 row=survivor -> ok\n\
         n5 log-row path=log:demo at=44 row=lost-truncation-undone -> ok\n\
         n5 log-file path=log:demo len=3 addr={b} -> ok\n\
         n5 log-state-dir present=yes -> ok\n\
         n5 log-state-dir present=no -> ok\n\
         n5 log-damage path=log:demo kind=detectable start=50 end=51 -> ok\n\
         n5 log-damage path=log:demo kind=residual start=60 end=90 -> ok\n\
         n5 log-violation kind=mark-before-record-sync -> ok\n\
         n5 log-violation kind=write-before-barrier:marker -> ok\n\
         n5 log-violation kind=write-before-barrier:initialise -> ok\n\
         n5 log-violation kind=write-before-barrier:complete-namespace -> ok\n\
         n5 log-violation kind=write-before-barrier:truncation -> ok\n\
         n5 log-violation kind=write-before-barrier:survivor-resync -> ok\n\
         n5 log-violation kind=after-fence -> ok\n\
         n5 log-violation kind=same-boot-after-fence -> ok\n\
         n5 log-violation kind=tail-not-truncated -> ok\n\
         n5 log-violation kind=concurrent-call -> ok\n\
         n5 log-violation kind=epoch-mismatch -> ok\n\
         n5 log-violation kind=overlapping-call -> ok\n\
         n5 log-violation kind=step-after-fence -> ok\n\
         n5 log-verdict path=log:demo result=absent -> ok\n\
         n5 log-verdict path=log:demo result=no-envelope -> ok\n\
         n5 log-verdict path=log:demo result=log records=3 committed=900 tail=12 -> ok\n\
         n5 log-verdict path=log:demo result=refused reason=unknown-version offset=0 -> ok\n\
         n5 log-verdict path=log:demo result=refused reason=envelope-malformed offset=0 -> ok\n\
         n5 log-verdict path=log:demo result=refused reason=wrong-volume offset=0 -> ok\n\
         n5 log-verdict path=log:demo result=refused reason=damaged-history offset=44 -> ok\n\
         n5 log-verdict path=log:demo result=refused reason=grammar-rule-6 offset=700 -> ok\n\
         n5 log-seed path=tmp:demo len=0 addr={c} -> ok\n\
         n5 log-seed-empty-state-dir -> ok\n\
         n5 log-reset -> ok\n\
         n5 log-file-sync path=marker -> failed(sync-failed)\n\
         n5 log-call call=truncate vol=demo -> failed(out-of-range)\n"
    );
    assert_eq!(every_variant().render(), expected);
}

#[test]
fn equal_traces_render_byte_identically() {
    let rendered = every_variant().render();
    assert_eq!(rendered, every_variant().render());
    // Two empty renderings are also equal, so the equality above
    // cannot stand on its own.
    assert!(!rendered.is_empty());
}

/// The property the negative proof rests on: `writer_uuid` changes
/// exactly one thing — the bytes of the signed root — so an artifact
/// that did not carry the root's content address would render
/// identically with and without an ambient pid in the preimage, and
/// the proof would pass while proving nothing.
#[test]
fn a_put_of_different_bytes_renders_differently() {
    let put = |addr| {
        let mut t = Trace::new();
        t.record(
            0,
            Op::PutRoot {
                volume: demo(),
                seq: 1,
                addr,
            },
            Outcome::Ok,
        );
        t.render()
    };
    assert_ne!(put(A), put(B));
}

/// A one-bit difference in the LAST byte must survive the
/// rendering: an address truncated for readability would let two
/// distinct objects render the same.
#[test]
fn the_whole_address_reaches_the_rendering() {
    let mut high = [0u8; 32];
    if let Some(last) = high.last_mut() {
        *last = 1;
    }
    let put = |digest| {
        let mut t = Trace::new();
        t.record(
            0,
            Op::PutBin {
                addr: Address::new(digest),
            },
            Outcome::Novel,
        );
        t.render()
    };
    assert_ne!(put([0u8; 32]), put(high));
    assert!(put(high).contains(&"00".repeat(31)), "{}", put(high));
}

#[test]
fn the_error_vocabulary_is_fixed() {
    let failed = |kind: io::ErrorKind| {
        let mut t = Trace::new();
        t.record(
            0,
            Op::HasGrain { addr: A },
            Outcome::Failed(TraceError::Io(kind.into())),
        );
        t.render()
    };
    // Two kinds std has not named must collapse to the SAME word:
    // `ErrorKind`'s own `Debug` is not a fixed vocabulary.
    assert_eq!(
        failed(io::ErrorKind::WouldBlock),
        failed(io::ErrorKind::Interrupted)
    );
    assert!(
        failed(io::ErrorKind::WouldBlock).contains("failed(io:other)"),
        "{}",
        failed(io::ErrorKind::WouldBlock)
    );
    // A named kind keeps its own word.
    assert!(
        failed(io::ErrorKind::PermissionDenied).contains("failed(io:permission-denied)"),
        "{}",
        failed(io::ErrorKind::PermissionDenied)
    );
}

/// The label rules, byte for byte, exercised THROUGH the
/// delegation: these are the names that can reach `vol=` in the
/// artifact, and a relaxation in `granary_core::root::VolumeName`
/// that let a separator or a path through would fail here rather
/// than silently widen what the sim will render.
#[test]
fn the_volume_alphabet_is_the_dns_1123_label_rule() {
    for good in ["demo", "d", "0", "vol-1", "a-b-c", "9-9"] {
        assert!(Volume::new(good).is_some(), "{good:?} was rejected");
    }
    for bad in [
        "",                     // empty
        "DEMO",                 // uppercase is rejected, never folded
        "demo.example",         // '.' is not in the label alphabet
        "demo_1",               // nor '_'
        "-demo",                // leading dash
        "demo-",                // trailing dash
        "a b",                  // the field separator
        "demo\nx",              // the line separator
        "vol=x",                // the key/value separator
        "/var/folders/t/x/vol", // the shape that defeated rule 3
    ] {
        assert!(Volume::new(bad).is_none(), "{bad:?} was accepted");
    }
    assert!(Volume::new(&"a".repeat(63)).is_some());
    assert!(Volume::new(&"a".repeat(64)).is_none());
    // The sentinel is unforgeable: it leads with a dash, so no
    // accepted name can equal it.
    assert!(Volume::new(Volume::REJECTED).is_none());
    assert!(Volume::rejected().is_rejected());
    assert!(!demo().is_rejected());
}

/// The collision that made [`Trace::render`] non-injective: a
/// ONE-entry trace whose volume carried the outcome separator and a
/// line break rendered byte-identically to a TWO-entry trace. It is
/// now unconstructible — the check is at the point of record, so
/// there is no path from the string to the artifact.
#[test]
fn a_volume_cannot_smuggle_a_second_line_into_the_artifact() {
    let attack = "demo -> ok\nn0 read-hint vol=evil";
    assert!(Volume::new(attack).is_none());

    let one = {
        let mut t = Trace::new();
        t.record(
            0,
            Op::ReadHint {
                volume: Volume::new(attack).unwrap_or_else(Volume::rejected),
            },
            Outcome::Ok,
        );
        t
    };
    let two = {
        let mut t = Trace::new();
        t.record(0, Op::ReadHint { volume: demo() }, Outcome::Ok);
        t.record(
            0,
            Op::ReadHint {
                volume: Volume::new("evil").expect("evil is a DNS-1123 label"),
            },
            Outcome::Ok,
        );
        t
    };
    assert_eq!(one.entries().len(), 1);
    assert_eq!(two.entries().len(), 2);
    assert_ne!(one.render(), two.render(), "{}", one.render());
}

/// The root-writing operations for the injectivity corpus below. They
/// share every field — `(volume, seq, addr)` — so only the operation
/// word tells a PUT from its later release or from an operator's plant,
/// and only the outcome tells a held write's two fates apart.
fn root_writing_corpus() -> Vec<(&'static str, Trace)> {
    let one = |op: Op, outcome| {
        let mut t = Trace::new();
        t.record(0, op, outcome);
        t
    };
    let (seq, addr) = (1, A);
    let put = |outcome| {
        one(
            Op::PutRoot {
                volume: demo(),
                seq,
                addr,
            },
            outcome,
        )
    };
    let release = |outcome| {
        one(
            Op::ReleaseRoot {
                volume: demo(),
                seq,
                addr,
            },
            outcome,
        )
    };
    let delete = |seq| {
        one(
            Op::AdminDeleteRoot {
                volume: demo(),
                seq,
            },
            Outcome::Ok,
        )
    };
    let refused = Outcome::Failed(TraceError::AlreadyExists);
    vec![
        (
            "put-root, deferred",
            put(Outcome::Failed(TraceError::Deferred)),
        ),
        (
            "put-root, injected",
            put(Outcome::Failed(TraceError::Injected)),
        ),
        ("release, landed", release(Outcome::Ok)),
        ("release, refused", release(refused)),
        (
            "admin plant",
            one(
                Op::AdminPlantRoot {
                    volume: demo(),
                    seq,
                    addr,
                },
                Outcome::Ok,
            ),
        ),
        ("admin delete", delete(1)),
        ("admin delete, other seq", delete(11)),
        (
            "admin list",
            one(Op::AdminListRoots { volume: demo() }, Outcome::Ok),
        ),
    ]
}

/// Rule 5, as the property and not as an anecdote: no two
/// structurally different traces render the same bytes. Each pair
/// below differs in exactly one place — the node, the op, a field,
/// the outcome, the entry count — so a rendering that dropped or
/// merged any of them shows up here.
#[test]
fn structurally_different_traces_never_render_identically() {
    let read = |node, volume| {
        let mut t = Trace::new();
        t.record(node, Op::ReadHint { volume }, Outcome::Ok);
        t
    };
    let evil = || Volume::new("evil").expect("evil is a DNS-1123 label");
    let hint = |seq, outcome| {
        let mut t = Trace::new();
        t.record(
            0,
            Op::WriteHint {
                volume: demo(),
                seq,
            },
            outcome,
        );
        t
    };
    let range = |offset, len| {
        let mut t = Trace::new();
        t.record(
            0,
            Op::GetBinRange {
                addr: A,
                offset,
                len,
            },
            Outcome::Ok,
        );
        t
    };
    let two_reads = {
        let mut t = read(0, demo());
        t.record(0, Op::ReadHint { volume: evil() }, Outcome::Ok);
        t
    };
    let corpus: Vec<(&str, Trace)> = [
        ("empty", Trace::new()),
        ("one read", read(0, demo())),
        ("one read, other node", read(1, demo())),
        ("one read, other volume", read(0, evil())),
        ("one read, rejected volume", read(0, Volume::rejected())),
        ("two reads", two_reads),
        ("max-seq, same volume", {
            let mut t = Trace::new();
            t.record(0, Op::MaxSeq { volume: demo() }, Outcome::Ok);
            t
        }),
        ("hint seq 2", hint(2, Outcome::Ok)),
        ("hint seq 22", hint(22, Outcome::Ok)),
        ("hint seq 2, other outcome", hint(2, Outcome::Novel)),
        ("range 1..24", range(1, 23)),
        ("range 12..15", range(12, 3)),
    ]
    .into_iter()
    .chain(root_writing_corpus())
    .collect();
    for (i, (name_a, a)) in corpus.iter().enumerate() {
        for (name_b, b) in corpus.iter().skip(i + 1) {
            assert_ne!(
                a.render(),
                b.render(),
                "{name_a:?} and {name_b:?} render identically"
            );
        }
    }
}

/// The two tests below are only as strong as the corpus they run
/// over: a NEW [`Op`] variant carrying free text would pass both
/// vacuously if `every_variant` never built one. The match has no
/// `_` arm, so adding a variant stops this file compiling, and the
/// set equality then forces the fixture to grow rather than letting
/// a new arm satisfy the compiler alone.
#[test]
fn every_variant_really_builds_every_op() {
    const OP_KINDS: usize = 16;
    fn kind(op: &Op) -> usize {
        match op {
            Op::PutBin { .. } => 0,
            Op::PutMeta { .. } => 1,
            Op::PutRoot { .. } => 2,
            Op::WriteHint { .. } => 3,
            Op::GetBinRange { .. } => 4,
            Op::GetMeta { .. } => 5,
            Op::GetRoot { .. } => 6,
            Op::ReadHint { .. } => 7,
            Op::MaxSeq { .. } => 8,
            Op::GetGrain { .. } => 9,
            Op::HasGrain { .. } => 10,
            Op::ReleaseRoot { .. } => 11,
            Op::AdminPlantRoot { .. } => 12,
            Op::AdminDeleteRoot { .. } => 13,
            Op::AdminListRoots { .. } => 14,
            Op::Log(_) => 15,
        }
    }
    let mut seen: Vec<usize> = every_variant()
        .entries()
        .iter()
        .map(|e| kind(&e.op))
        .collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen,
        (0..OP_KINDS).collect::<Vec<usize>>(),
        "every_variant no longer builds every Op, so the alphabet and \
         ambient-value tests below cover less than they claim"
    );
}

/// The same guard one level down: every [`LogOp`] variant is in
/// [`every_log_op`], so the alphabet and ambient-value tests cover it.
#[test]
fn every_log_op_really_builds_every_log_variant() {
    const LOG_KINDS: usize = 23;
    fn kind(op: &LogOp) -> usize {
        match op {
            LogOp::Call { .. } => 0,
            LogOp::Write { .. } => 1,
            LogOp::FileSync { .. } => 2,
            LogOp::DirSync { .. } => 3,
            LogOp::Create { .. } => 4,
            LogOp::Mkdir { .. } => 5,
            LogOp::Link { .. } => 6,
            LogOp::Unlink { .. } => 7,
            LogOp::Rename { .. } => 8,
            LogOp::Truncate { .. } => 9,
            LogOp::Read { .. } => 10,
            LogOp::Restart => 11,
            LogOp::Crash { .. } => 12,
            LogOp::Draw { .. } => 13,
            LogOp::Row { .. } => 14,
            LogOp::File { .. } => 15,
            LogOp::StateDir { .. } => 16,
            LogOp::Damage { .. } => 17,
            LogOp::Violation(_) => 18,
            LogOp::Verdict { .. } => 22,
            LogOp::Seed { .. } => 19,
            LogOp::SeedEmptyStateDir => 20,
            LogOp::Reset => 21,
        }
    }
    let mut seen: Vec<usize> = every_log_op().iter().map(kind).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen, (0..LOG_KINDS).collect::<Vec<usize>>());
}

/// Rule 3 as a CLOSED ALPHABET rather than a scan for two
/// separators. A scan can only refuse the shapes someone thought of;
/// a closed alphabet refuses everything nobody did — which is the
/// only form that catches, say, a hostname reaching a scenario's
/// trace, where no golden vector exists to compare against.
#[test]
fn the_rendered_alphabet_is_closed() {
    let rendered = every_variant().render();
    assert!(!rendered.is_empty());
    for (i, ch) in rendered.char_indices() {
        assert!(
            matches!(ch, 'a'..='z' | '0'..='9' | '-' | '=' | ':' | ' ' | '>' | '(' | ')' | '\n'),
            "byte {i} is {ch:?}, outside the artifact's alphabet: {rendered}"
        );
    }
}

/// The alphabet cannot catch a bare pid — digits are legal, and a
/// content address is digits and lowercase hex — so the pair is
/// needed: this one names the ambient values directly.
#[expect(
    clippy::disallowed_methods,
    reason = "the test's whole job is to prove the pid is ABSENT"
)]
#[test]
fn no_ambient_value_of_this_process_reaches_the_artifact() {
    let rendered = every_variant().render();
    assert!(!rendered.is_empty());
    let mut ambient: Vec<String> = vec![std::process::id().to_string()];
    for key in [
        "HOME",
        "USER",
        "LOGNAME",
        "PWD",
        "TMPDIR",
        "CARGO_MANIFEST_DIR",
    ] {
        if let Ok(v) = std::env::var(key)
            && !v.is_empty()
        {
            ambient.push(v);
        }
    }
    for needle in &ambient {
        assert!(
            !rendered.contains(needle.as_str()),
            "an ambient value ({needle}) reached the artifact: {rendered}"
        );
    }
}

#[test]
fn nothing_rendered_looks_like_a_path() {
    let rendered = every_variant().render();
    assert!(!rendered.is_empty());
    for sep in ['/', '\\'] {
        assert!(
            !rendered.contains(sep),
            "a path separator reached the artifact: {rendered}"
        );
    }
}

#[test]
fn is_empty_refuses_a_vacuous_artifact() {
    let mut t = Trace::new();
    assert!(t.is_empty());
    assert!(t.render().is_empty());
    t.record(0, Op::PutBin { addr: A }, Outcome::Novel);
    assert!(!t.is_empty());
    assert_eq!(t.entries().len(), 1);
}
