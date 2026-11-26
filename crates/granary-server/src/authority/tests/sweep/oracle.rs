// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The sweep's oracle: the durability properties checked against what the
//! harness observed — the timeline, the fake's draws and violations, and
//! the store's objects — never by asking the engine what it did.
//!
//! **Acknowledged** is judged per process: a record is acknowledged at a
//! point of a process's timeline when its `append` returned `Ok` earlier
//! in that process, or when it was committed in the log the process read
//! at its start and that log's re-sync returned `Ok` earlier.

use std::collections::BTreeMap;

use granary_core::authlog::{Classified, Epoch, Record, RecordBody, classify};
use granary_core::hash::GrainId;
use granary_core::root::{VolumeName, decode_root};
use granary_core::rootstore::RootStore;
use granary_core::runmarker::RunMarker;
use granary_sim::decision_log::CrashReport;
use granary_sim::trace::{DrawRow, LogPath, LogViolation};

use super::super::{
    Answer, Bound, HeadRef, InitialiseError, Initialised, Position, Receipt, Reply, marker_says,
};
use super::harness::{Ev, Found};
use super::run::{End, Run, read_log};
use super::{VOLUMES, a, b, vol};

/// What a run got wrong, each named.
pub(super) fn check(run: &Run) -> Vec<String> {
    let mut out = Checker {
        run,
        failures: Vec::new(),
    };
    out.script();
    out.violations();
    out.restarts();
    for process in 1..=run.processes {
        out.process(process);
    }
    out.one_order();
    out.preserved();
    out.recovery();
    out.end();
    out.failures
}

struct Checker<'a> {
    run: &'a Run,
    failures: Vec<String>,
}

/// The events of one process, with their index in the whole timeline.
fn events_of(run: &Run, process: u32) -> impl Iterator<Item = (usize, &Ev)> {
    run.timeline
        .iter()
        .enumerate()
        .filter(move |(_, (p, _))| *p == process)
        .map(|(i, (_, ev))| (i, ev))
}

/// Records acknowledged so far in a process, per volume.
#[derive(Default)]
struct Acked {
    appended: BTreeMap<VolumeName, Vec<Record>>,
    at_start: BTreeMap<VolumeName, Vec<Record>>,
    resynced: BTreeMap<VolumeName, bool>,
}

impl Acked {
    fn records(&self, volume: &VolumeName) -> Vec<&Record> {
        let mut out: Vec<&Record> = self.appended.get(volume).into_iter().flatten().collect();
        if self.resynced.get(volume).copied().unwrap_or(false) {
            out.extend(self.at_start.get(volume).into_iter().flatten());
        }
        out
    }

    fn find(&self, volume: &VolumeName, pred: impl Fn(&Record) -> bool) -> Option<Record> {
        self.records(volume).into_iter().find(|r| pred(r)).cloned()
    }

    fn decision(&self, volume: &VolumeName, seq: u64, candidate: GrainId) -> bool {
        self.find(volume, |r| {
            r.seq() == seq
                && matches!(r.body(), RecordBody::Decision { identity, .. }
                    if identity.candidate_id() == candidate)
        })
        .is_some()
    }

    fn landed(&self, volume: &VolumeName, seq: u64) -> bool {
        self.find(volume, |r| {
            r.seq() == seq && matches!(r.body(), RecordBody::Landed { .. })
        })
        .is_some()
    }

    fn lost(&self, volume: &VolumeName, seq: u64, occupant: GrainId) -> bool {
        self.find(volume, |r| {
            r.seq() == seq
                && matches!(r.body(), RecordBody::Lost { occupant_id, .. } if *occupant_id == occupant)
        })
        .is_some()
    }
}

/// What one process has seen so far, as the checks need it.
#[derive(Default)]
struct Seen {
    acked: Acked,
    fenced: bool,
    /// The epoch of each log this process created: `Created` answers
    /// from these.
    initialised: BTreeMap<VolumeName, Epoch>,
    /// The epoch of each log this process read or created: `Kept`
    /// answers from these.
    known_epoch: BTreeMap<VolumeName, Epoch>,
    namespace: BTreeMap<VolumeName, bool>,
    /// Logs read with a tail recovery has not yet truncated.
    untruncated: BTreeMap<VolumeName, u64>,
    /// The last read of each (volume, seq).
    reads: BTreeMap<(String, u64), Found>,
    /// Reads since the current epoch probe began, kept apart from outcome evidence.
    epoch_reads: BTreeMap<(String, u64), Found>,
}

impl Seen {
    /// A mutating call returned: a failure fences (a temporary's removal
    /// excepted), and a successful truncation, re-sync or namespace
    /// completion discharges what it owes.
    fn ended(&mut self, call: &str, volume: Option<&VolumeName>, ok: bool) {
        if !ok && call != "remove-temporary" {
            self.fenced = true;
        }
        if ok && let Some(volume) = volume {
            match call {
                "truncate" => {
                    self.untruncated.remove(volume);
                }
                "resync" => {
                    self.acked.resynced.insert(volume.clone(), true);
                }
                "complete-namespace" => {
                    self.namespace.insert(volume.clone(), true);
                }
                _ => {}
            }
        }
    }

    /// A log was read. `false` when it was read again with a tail still
    /// untruncated.
    fn read(
        &mut self,
        volume: &VolumeName,
        epoch: Option<Epoch>,
        records: &[Record],
        tail: u64,
    ) -> bool {
        self.acked
            .at_start
            .entry(volume.clone())
            .or_insert_with(|| records.to_vec());
        if let Some(epoch) = epoch {
            self.known_epoch.insert(volume.clone(), epoch);
        }
        tail == 0 || self.untruncated.insert(volume.clone(), tail).is_none()
    }
}

/// The decision at position `seq` among `records`: its root seq and its
/// candidate id.
fn decided(records: &[&Record], seq: u64) -> Option<(u64, GrainId)> {
    records.iter().find_map(|r| match r.body() {
        RecordBody::Decision {
            identity, root_seq, ..
        } if r.seq() == seq => Some((*root_seq, identity.candidate_id())),
        _ => None,
    })
}

impl Checker<'_> {
    fn fail(&mut self, what: impl Into<String>) {
        self.failures.push(what.into());
    }

    /// What the client found wrong.
    fn script(&mut self) {
        for failure in self.run.script.failures.clone() {
            self.fail(format!("script: {failure}"));
        }
    }

    /// O1 through the fake: no ordering violation, except the one a
    /// same-boot restart the table admits records where a killed or
    /// failed call had fenced the disk.
    fn violations(&mut self) {
        let mut allowed = Vec::new();
        for restart in &self.run.restarts {
            if restart.admitted {
                for v in &restart.violations {
                    if *v == LogViolation::SameBootAfterFence {
                        allowed.push(*v);
                    } else {
                        self.fail(format!("an admitted same-boot restart recorded {v:?}"));
                    }
                }
            }
        }
        let mut all = self.run.log.violations();
        for v in &allowed {
            if let Some(i) = all.iter().position(|w| w == v) {
                all.remove(i);
            }
        }
        if !all.is_empty() {
            self.fail(format!("the fake recorded {all:?}"));
        }
    }

    /// O6: between the first running rename and the final clean rename a
    /// same-boot restart always refuses, and an admitted one is at a
    /// point the table cannot see.
    fn restarts(&mut self) {
        for r in &self.run.restarts {
            if r.renames == 1 && r.expected != super::run::Table::RunningInThisBoot {
                self.fail(format!(
                    "process {} ended between its running and clean renames, yet the table says {:?}",
                    r.process, r.expected
                ));
            }
            if r.admitted && r.renames == 1 {
                self.fail(format!(
                    "process {}: a same-boot restart admitted",
                    r.process
                ));
            }
        }
    }

    /// O1, O3 and O5 within one process.
    fn process(&mut self, process: u32) {
        let mut seen = Seen::default();
        let mut killed = false;
        let mut epoch_probe = None;
        for (i, ev) in events_of(self.run, process) {
            if killed {
                self.fail(format!(
                    "process {process}: event {i} after the kill: {ev:?}"
                ));
                continue;
            }
            match ev {
                Ev::Start | Ev::Cut { .. } => {}
                Ev::EpochProbe { volume } => {
                    epoch_probe = Some(volume.clone());
                    seen.epoch_reads.clear();
                }
                Ev::Killed => killed = true,
                Ev::Undecodable { volume } => self.fail(format!(
                    "process {process}: an append to {} that does not decode as its next record",
                    volume.as_str()
                )),
                Ev::Begin { call, volume } => {
                    if seen.fenced {
                        self.fail(format!(
                            "process {process}: {call} on {volume:?} began after the fence"
                        ));
                    }
                }
                Ev::End { call, volume, ok } => seen.ended(call, volume.as_ref(), *ok),
                Ev::Read {
                    volume,
                    epoch,
                    records,
                    tail,
                } => {
                    if !seen.read(volume, *epoch, records, *tail) {
                        self.fail(format!(
                            "process {process}: {} read again with its tail untruncated",
                            volume.as_str()
                        ));
                    }
                }
                Ev::Initialised { volume, epoch } => {
                    seen.initialised.insert(volume.clone(), *epoch);
                    seen.known_epoch.insert(volume.clone(), *epoch);
                }
                Ev::Appending { volume, record, .. } => {
                    if epoch_probe.as_ref() == Some(volume)
                        && matches!(record.body(), RecordBody::Decision { .. })
                    {
                        self.fail(format!("process {process}: epoch probe wrote a decision"));
                    }
                    self.tail_guard(&seen, process, volume, "appended to");
                    self.outcome_read(process, i, volume, record, &seen.acked, &seen.reads);
                }
                Ev::Acked { volume, record } => {
                    seen.acked
                        .appended
                        .entry(volume.clone())
                        .or_default()
                        .push(record.clone());
                }
                Ev::Put { volume, seq, id } => {
                    self.tail_guard(&seen, process, &vol(volume), "published");
                    if seen.fenced {
                        self.fail(format!("process {process}: a PUT after the fence"));
                    }
                    self.put(process, volume, *seq, *id, &seen.acked);
                }
                Ev::Got { volume, seq, found } => {
                    seen.reads.insert((volume.clone(), *seq), *found);
                    seen.epoch_reads.insert((volume.clone(), *seq), *found);
                }
                Ev::Emit { volume, reply } => {
                    self.tail_guard(&seen, process, volume, "answered for");
                    self.emitted(process, volume, reply, &seen);
                    if epoch_probe.as_ref() == Some(volume) {
                        if !matches!(
                            reply,
                            Reply::Answer(Answer::EpochMismatch { .. } | Answer::Fenced)
                        ) {
                            self.fail(format!("process {process}: epoch probe emitted {reply:?}"));
                        }
                        epoch_probe = None;
                    }
                }
            }
        }
    }

    /// Nothing is appended, published or answered for a log whose tail
    /// recovery has not yet truncated.
    fn tail_guard(&mut self, seen: &Seen, process: u32, volume: &VolumeName, what: &str) {
        if seen.untruncated.contains_key(volume) {
            self.fail(format!(
                "process {process}: {} {what} before its tail was truncated",
                volume.as_str()
            ));
        }
    }

    /// O5: an outcome's append follows a classification read that found
    /// what the outcome records.
    fn outcome_read(
        &mut self,
        process: u32,
        at: usize,
        volume: &VolumeName,
        record: &Record,
        acked: &Acked,
        reads: &BTreeMap<(String, u64), Found>,
    ) {
        let expected = match record.body() {
            RecordBody::Landed { .. } | RecordBody::Lost { .. } => record.seq(),
            _ => return,
        };
        let records = acked.records(volume);
        let Some((root_seq, candidate)) = decided(&records, expected) else {
            self.fail(format!(
                "process {process}: an outcome at {expected} with no acknowledged decision"
            ));
            return;
        };
        let found = reads.get(&(volume.as_str().to_owned(), root_seq)).copied();
        let roots = &self.run.roots;
        match record.body() {
            RecordBody::Landed { .. } => {
                if found != Some(Found::Id(candidate)) {
                    self.fail(format!(
                        "process {process}: landed at event {at} after a read that found {found:?}"
                    ));
                }
            }
            RecordBody::Lost { occupant_id, .. } => {
                let f3 = GrainId::of(&roots.f3);
                if found != Some(Found::Id(*occupant_id))
                    || *occupant_id != f3
                    || candidate != GrainId::of(&roots.c3)
                {
                    self.fail(format!(
                        "process {process}: lost to {occupant_id:?} at event {at} after a read that found {found:?}"
                    ));
                }
            }
            _ => {}
        }
    }

    /// O1 and O3 for a PUT: the entry's attestation is acknowledged, the
    /// entry is not closed, and the bytes are the attested ones at the
    /// decided seq.
    fn put(&mut self, process: u32, volume: &str, seq: u64, id: GrainId, acked: &Acked) {
        let vol = vol(volume);
        let attested = acked.find(&vol, |r| match r.body() {
            RecordBody::Attestation {
                stored_id,
                final_root,
                ..
            } => {
                *stored_id == id
                    && decode_root(final_root.as_bytes()).is_ok_and(|doc| doc.seq == seq)
            }
            _ => false,
        });
        match attested {
            None => self.fail(format!(
                "process {process}: PUT of {id:?} at {volume}/{seq} with no acknowledged attestation of those bytes there"
            )),
            Some(attestation) => {
                let closed = acked
                    .find(&vol, |r| {
                        r.seq() == attestation.seq()
                            && matches!(r.body(), RecordBody::Landed { .. } | RecordBody::Lost { .. })
                    })
                    .is_some();
                if closed {
                    self.fail(format!(
                        "process {process}: PUT at {volume}/{seq} after its entry closed"
                    ));
                }
            }
        }
    }

    /// O1 for a reply: it follows the acknowledgement of every record it
    /// reports; after a fence, it is `Fenced`.
    fn emitted(&mut self, process: u32, volume: &VolumeName, reply: &Reply, seen: &Seen) {
        let (acked, fenced) = (&seen.acked, seen.fenced);
        let ctx = format!("process {process}: {} emitted {reply:?}", volume.as_str());
        match reply {
            Reply::Answer(answer) => {
                if fenced && *answer != Answer::Fenced {
                    self.fail(format!("{ctx} after the fence"));
                }
                if let Some(head) = head_of(answer) {
                    self.head(&ctx, volume, head);
                }
                let ok = match answer {
                    Answer::EpochMismatch { epoch, head } => {
                        if let Some(head) = head.and_then(|h| h.head)
                            && seen
                                .epoch_reads
                                .get(&(volume.as_str().to_owned(), head.head_seq))
                                != Some(&Found::Id(head.head_id))
                        {
                            self.fail(format!("{ctx}: epoch mismatch head lacks a fresh read"));
                        }
                        seen.known_epoch.get(volume) == Some(epoch)
                    }
                    Answer::Accepted {
                        position,
                        candidate_id,
                    }
                    | Answer::Open {
                        position,
                        candidate_id,
                    }
                    | Answer::NotDecided {
                        position,
                        candidate_id,
                    }
                    | Answer::OperationBound(Bound::Open {
                        position,
                        candidate_id,
                    }) => acked.decision(volume, position.seq, *candidate_id),
                    Answer::Landed { receipt, .. }
                    | Answer::OperationBound(Bound::Landed(receipt)) => {
                        acked.decision(volume, receipt.position.seq, receipt.stored_id)
                            && acked.landed(volume, receipt.position.seq)
                    }
                    Answer::Lost {
                        position,
                        candidate_id,
                        occupant,
                        ..
                    } => {
                        acked.decision(volume, position.seq, *candidate_id)
                            && acked.lost(volume, position.seq, *occupant)
                    }
                    _ => true,
                };
                if !ok {
                    self.fail(format!("{ctx} before what it reports was acknowledged"));
                }
            }
            Reply::Initialised(result) => {
                if fenced && *result != Err(InitialiseError::Fenced) {
                    self.fail(format!("{ctx} after the fence"));
                }
                match result {
                    Ok(Initialised::Created { epoch }) => {
                        if seen.initialised.get(volume) != Some(epoch) {
                            self.fail(format!("{ctx} with no initialise under that epoch"));
                        }
                    }
                    Ok(Initialised::Kept { epoch }) => {
                        if !seen.namespace.get(volume).copied().unwrap_or(false) {
                            self.fail(format!("{ctx} before its namespace was completed"));
                        }
                        if seen.known_epoch.get(volume) != Some(epoch) {
                            self.fail(format!("{ctx} under an epoch its log does not carry"));
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    /// A head an answer carries names a root the harness made valid at
    /// that seq of that volume.
    fn head(&mut self, ctx: &str, volume: &VolumeName, head: HeadRef) {
        let r = &self.run.roots;
        let chain: Vec<&[u8]> = if *volume == b() {
            vec![&r.d1]
        } else {
            vec![&r.c1, &r.c2, &r.f3, &r.c3p, &r.c4]
        };
        let expected = usize::try_from(head.head_seq)
            .ok()
            .and_then(|seq| seq.checked_sub(1))
            .and_then(|i| chain.get(i));
        if expected.map(|bytes| GrainId::of(bytes)) != Some(head.head_id) {
            self.fail(format!("{ctx}: a head the harness never made valid"));
        }
    }

    /// O2: every position one candidate, every candidate one position,
    /// across every process.
    fn one_order(&mut self) {
        let mut by_position: BTreeMap<(VolumeName, Position), GrainId> = BTreeMap::new();
        let mut by_candidate: BTreeMap<(VolumeName, GrainId), Position> = BTreeMap::new();
        for (_, ev) in &self.run.timeline {
            let Ev::Emit {
                volume,
                reply: Reply::Answer(answer),
            } = ev
            else {
                continue;
            };
            let Some((position, candidate)) = decided_in(answer) else {
                continue;
            };
            let p = by_position
                .entry((volume.clone(), position))
                .or_insert(candidate);
            if *p != candidate {
                self.fail(format!(
                    "{} position {position:?} named {p:?} and then {candidate:?}",
                    volume.as_str()
                ));
            }
            let c = by_candidate
                .entry((volume.clone(), candidate))
                .or_insert(position);
            if *c != position {
                self.fail(format!(
                    "{} candidate {candidate:?} at {c:?} and then {position:?}",
                    volume.as_str()
                ));
            }
        }
    }

    /// O4: an outcome once answered is answered again the same.
    fn preserved(&mut self) {
        let mut outcomes: BTreeMap<(VolumeName, GrainId), Answer> = BTreeMap::new();
        for (_, ev) in &self.run.timeline {
            let Ev::Emit {
                volume,
                reply: Reply::Answer(answer),
            } = ev
            else {
                continue;
            };
            let (candidate, outcome) = match answer {
                Answer::Landed { receipt, .. } => (
                    receipt.stored_id,
                    Answer::Landed {
                        receipt: *receipt,
                        head: None,
                    },
                ),
                Answer::Lost {
                    position,
                    candidate_id,
                    occupant,
                    ..
                } => (
                    *candidate_id,
                    Answer::Lost {
                        position: *position,
                        candidate_id: *candidate_id,
                        occupant: *occupant,
                        head: None,
                    },
                ),
                Answer::Accepted { candidate_id, .. } | Answer::Open { candidate_id, .. } => {
                    if let Some(earlier) = outcomes.get(&(volume.clone(), *candidate_id)) {
                        self.fail(format!(
                            "{} {candidate_id:?} answered {answer:?} after {earlier:?}",
                            volume.as_str()
                        ));
                    }
                    continue;
                }
                _ => continue,
            };
            let earlier = outcomes
                .entry((volume.clone(), candidate))
                .or_insert_with(|| outcome.clone());
            if *earlier != outcome {
                self.fail(format!(
                    "{} {candidate:?} answered {outcome:?} after {earlier:?}",
                    volume.as_str()
                ));
            }
        }
    }

    /// O4 across each host crash: the next process's start reads exactly
    /// the records the crashed process had acknowledged, adopted at its
    /// start, or left as a drawn survivor.
    fn recovery(&mut self) {
        let run = self.run;
        let mut committed: BTreeMap<VolumeName, Vec<Record>> = BTreeMap::new();
        for (process, report) in &run.crashes {
            let mut acked: BTreeMap<VolumeName, Vec<Record>> = BTreeMap::new();
            let mut appending: Vec<(VolumeName, u64, Record)> = Vec::new();
            for (_, ev) in events_of(run, *process) {
                match ev {
                    Ev::Read {
                        volume, records, ..
                    } => {
                        let known = committed.entry(volume.clone()).or_default();
                        for r in records {
                            if !known.contains(r) {
                                // Committed on the medium before this
                                // process: a survivor of an earlier crash
                                // the earlier check already judged.
                                known.push(r.clone());
                            }
                        }
                    }
                    Ev::Appending {
                        volume,
                        record,
                        offset,
                    } => appending.push((volume.clone(), *offset, record.clone())),
                    Ev::Acked { volume, record } => {
                        acked
                            .entry(volume.clone())
                            .or_default()
                            .push(record.clone());
                    }
                    _ => {}
                }
            }
            for (volume, records) in acked {
                committed.entry(volume).or_default().extend(records);
            }
            for survivor in survivors(report, &appending, &mut self.failures, *process) {
                let (volume, record) = survivor;
                let known = committed.entry(volume).or_default();
                if !known.contains(&record) {
                    known.push(record);
                }
            }
            // The next process's first read of each volume is recovery's
            // classification of the medium.
            let next = process + 1;
            let mut judged = std::collections::BTreeSet::new();
            for (_, ev) in events_of(run, next) {
                if let Ev::Read {
                    volume, records, ..
                } = ev
                    && judged.insert(volume.clone())
                {
                    // The committed set only grows across crashes, and is
                    // built in the log's order (what an earlier process
                    // read, then what the crashed one acknowledged, then
                    // the survivor it left last), so equality here is also
                    // §5.2's prefix extension.
                    let expected = committed.get(volume).cloned().unwrap_or_default();
                    let got = records.clone();
                    if got != expected {
                        self.fail(format!(
                            "after process {process}'s crash, {} recovered {} records, expected {}: {:?} vs {:?}",
                            volume.as_str(),
                            got.len(),
                            expected.len(),
                            got.iter().map(|r| (r.seq(), tag(r))).collect::<Vec<_>>(),
                            expected.iter().map(|r| (r.seq(), tag(r))).collect::<Vec<_>>(),
                        ));
                    }
                }
            }
        }
    }

    /// The run's end: the final logs, the store, the marker.
    fn end(&mut self) {
        let run = self.run;
        match run.end {
            End::SafeRefusal => {
                for name in VOLUMES {
                    if !matches!(read_log(&run.log, &vol(name)), Ok(None)) {
                        self.fail(format!("a safe refusal with {name}'s log on the medium"));
                    }
                }
            }
            End::Clean => {
                if run.script.finished.is_none() {
                    self.fail("the script did not finish");
                }
                for volume in [a(), b()] {
                    let bytes = match read_log(&run.log, &volume) {
                        Ok(Some(bytes)) => bytes,
                        other => {
                            self.fail(format!(
                                "{}'s log at the end reads {other:?}",
                                volume.as_str()
                            ));
                            continue;
                        }
                    };
                    match classify(&bytes, &volume) {
                        Ok(Classified::Log {
                            records, tail_len, ..
                        }) => {
                            if records != run.roots.expected(&volume) {
                                self.fail(format!(
                                    "{}'s final records are not the script's: {:?}",
                                    volume.as_str(),
                                    records
                                        .iter()
                                        .map(|r| (r.seq(), tag(r)))
                                        .collect::<Vec<_>>()
                                ));
                            }
                            if tail_len != 0 {
                                self.fail(format!("{} ends with a tail", volume.as_str()));
                            }
                        }
                        other => self.fail(format!(
                            "{}'s final log does not classify: {other:?}",
                            volume.as_str()
                        )),
                    }
                }
                if marker_says(&run.log) != Some(RunMarker::Clean) {
                    self.fail("the marker is not clean at the end");
                }
                let r = &run.roots;
                let chain: [(&VolumeName, u64, &[u8]); 6] = [
                    (&a(), 1, &r.c1),
                    (&a(), 2, &r.c2),
                    (&a(), 3, &r.f3),
                    (&a(), 4, &r.c3p),
                    (&a(), 5, &r.c4),
                    (&b(), 1, &r.d1),
                ];
                let oracle = run.sim.oracle();
                for (volume, seq, bytes) in chain {
                    let volume_name = volume.as_str().to_owned();
                    let expected = bytes.to_vec();
                    let oracle = &oracle;
                    let got = block_ref(async move { oracle.get_root(&volume_name, seq).await });
                    if got.as_ref().ok().and_then(|g| g.as_ref()) != Some(&expected) {
                        self.fail(format!(
                            "the store does not hold the script's root at {}/{seq}",
                            volume.as_str()
                        ));
                    }
                }
            }
        }
    }
}

/// Drive a borrowing future to completion under the simulator's
/// scheduler, which takes only `'static` tasks.
pub(super) fn block_ref<T: 'static>(future: impl std::future::Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    for _ in 0..1_000 {
        if let std::task::Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            return out;
        }
    }
    panic!("a store read never finished")
}

/// The chain head an answer names, if it names one: a verified head
/// that is not the empty chain's.
fn head_of(answer: &Answer) -> Option<HeadRef> {
    match answer {
        Answer::EpochMismatch {
            head: Some(head), ..
        }
        | Answer::Landed {
            head: Some(head), ..
        }
        | Answer::Lost {
            head: Some(head), ..
        }
        | Answer::StaleBase { head } => head.head,
        _ => None,
    }
}

/// The position and candidate an answer names as decided.
fn decided_in(answer: &Answer) -> Option<(Position, GrainId)> {
    match answer {
        Answer::Accepted {
            position,
            candidate_id,
        }
        | Answer::Open {
            position,
            candidate_id,
        }
        | Answer::NotDecided {
            position,
            candidate_id,
        }
        | Answer::Lost {
            position,
            candidate_id,
            ..
        }
        | Answer::OperationBound(Bound::Open {
            position,
            candidate_id,
        }) => Some((*position, *candidate_id)),
        Answer::Landed {
            receipt:
                Receipt {
                    position,
                    stored_id,
                    ..
                },
            ..
        }
        | Answer::OperationBound(Bound::Landed(Receipt {
            position,
            stored_id,
            ..
        })) => Some((*position, *stored_id)),
        _ => None,
    }
}

/// A record's tag, for messages and ordering.
pub(super) const fn tag(record: &Record) -> u8 {
    match record.body() {
        RecordBody::Decision { .. } => 1,
        RecordBody::Attestation { .. } => 2,
        RecordBody::Landed { .. } => 3,
        RecordBody::Lost { .. } => 4,
    }
}

/// The records a crash's draw left as survivors, found by the offset each
/// was appended at: `(volume, record)`. A survivor row with no append at
/// its offset is a failure.
pub(super) fn survivors(
    report: &CrashReport,
    appending: &[(VolumeName, u64, Record)],
    failures: &mut Vec<String>,
    process: u32,
) -> Vec<(VolumeName, Record)> {
    let mut out = Vec::new();
    for (path, offset, row) in &report.rows {
        if *row != DrawRow::Survivor {
            continue;
        }
        let LogPath::Log(volume) = path else {
            continue;
        };
        match appending
            .iter()
            .find(|(v, o, _)| v.as_str() == volume.as_str() && o == offset)
        {
            Some((v, _, record)) => out.push((v.clone(), record.clone())),
            None => failures.push(format!(
                "process {process}: a survivor at {volume}/{offset} with no append there"
            )),
        }
    }
    out
}
