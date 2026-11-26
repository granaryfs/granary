// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the crash harness expects, computed from the disk and the pipe
//! alone: the state recovery must rebuild (an independent replay of the
//! committed records, written from the durability oracle's recovery rule,
//! not the engine's), the marker table's answer, and the dependencies of
//! each reply and PUT.

use std::collections::BTreeMap;
use std::path::Path;

use granary_core::authlog::{
    Classified, Envelope, Record, RecordBody, SubmissionIdentity, classify,
};
use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use granary_core::runmarker::{BootId, RunMarker, decode_marker};

/// One volume's log, read from a copy.
#[derive(Debug, Clone)]
pub(super) struct Log {
    pub(super) bytes: Vec<u8>,
    pub(super) envelope: Envelope,
    pub(super) epoch: String,
    pub(super) records: Vec<Record>,
    pub(super) committed_len: usize,
}

/// A volume's log in the state directory at `state`: `None` when absent
/// or holding no envelope.
///
/// # Panics
/// A log `classify` refuses: recovery would refuse it too, and the
/// harness never expects one.
pub(super) fn read_log(state: &Path, volume: &VolumeName) -> Option<Log> {
    let bytes = std::fs::read(state.join(format!("{}.log", volume.as_str()))).ok()?;
    match classify(&bytes, volume) {
        Ok(Classified::NoEnvelope) => None,
        Ok(Classified::Log {
            envelope,
            records,
            committed_len,
            ..
        }) => Some(Log {
            epoch: format!("{:?}", envelope.epoch()),
            envelope,
            bytes,
            records,
            committed_len,
        }),
        Err(e) => panic!("{}: the log is refused: {e:?}", volume.as_str()),
    }
}

/// Where an accepted candidate's publication stands.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Standing {
    Open,
    Landed,
    Lost(GrainId),
}

impl Standing {
    fn render(&self) -> String {
        match self {
            Self::Open => "open".to_owned(),
            Self::Landed => "landed".to_owned(),
            Self::Lost(occupant) => format!("lost:{occupant:?}"),
        }
    }
}

/// The open entry, as the oracle's recovery rule rebuilds it.
struct Entry {
    seq: u64,
    identity: SubmissionIdentity,
    root_seq: u64,
    base: Option<GrainId>,
    candidate: GrainId,
    attested: bool,
    decided_at: String,
}

/// The state the committed records of `log` give, rendered as the
/// driver's `STATE` lines: an independent replay (module docs). Each
/// decision takes its position and binds its operation to its candidate;
/// an attestation marks the open entry attested; an outcome closes it,
/// recording landed or lost for its identity and its operation.
pub(super) fn model(volume: &VolumeName, log: Option<&Log>) -> Vec<String> {
    let v = volume.as_str();
    let Some(log) = log else {
        return vec![format!("STATE {v} nolog")];
    };
    // (seq, root_seq, standing) by identity, and (candidate, seq,
    // root_seq, standing) by operation.
    let mut recorded: BTreeMap<SubmissionIdentity, (u64, u64, Standing)> = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    let mut open: Option<Entry> = None;
    let mut highest = 0;
    for record in &log.records {
        let seq = record.seq();
        highest = highest.max(seq);
        let identity = record.body().identity().clone();
        let op = (
            identity.tenant().clone(),
            identity.principal().clone(),
            identity.operation().clone(),
        );
        match record.body() {
            RecordBody::Decision {
                root_seq,
                base,
                decided_at,
                candidate,
                ..
            } => {
                recorded.insert(identity.clone(), (seq, *root_seq, Standing::Open));
                bindings.insert(
                    op,
                    (identity.candidate_id(), seq, *root_seq, Standing::Open),
                );
                open = Some(Entry {
                    seq,
                    identity,
                    root_seq: *root_seq,
                    base: *base,
                    candidate: GrainId::of(candidate.as_bytes()),
                    attested: false,
                    decided_at: format!("{decided_at:?}"),
                });
            }
            RecordBody::Attestation { .. } => {
                if let Some(entry) = open.as_mut() {
                    entry.attested = true;
                }
            }
            RecordBody::Landed { .. } | RecordBody::Lost { .. } => {
                let standing = match record.body() {
                    RecordBody::Lost { occupant_id, .. } => Standing::Lost(*occupant_id),
                    _ => Standing::Landed,
                };
                if let Some(r) = recorded.get_mut(&identity) {
                    r.2 = standing.clone();
                }
                if let Some(b) = bindings.get_mut(&op) {
                    b.3 = standing;
                }
                open = None;
            }
        }
    }
    let mut lines = vec![format!(
        "STATE {v} epoch={} next={:?}",
        log.epoch,
        highest.checked_add(1)
    )];
    for (identity, (seq, root_seq, standing)) in &recorded {
        lines.push(format!(
            "STATE {v} recorded identity={identity:?} seq={seq} root_seq={root_seq} outcome={}",
            standing.render()
        ));
    }
    for ((tenant, principal, operation), (candidate, seq, root_seq, standing)) in &bindings {
        lines.push(format!(
            "STATE {v} binding op={tenant:?}/{principal:?}/{operation:?} candidate={candidate:?} \
             seq={seq} root_seq={root_seq} outcome={}",
            standing.render()
        ));
    }
    if let Some(e) = open {
        lines.push(format!(
            "STATE {v} open seq={} identity={:?} root_seq={} base={:?} candidate={:?} \
             attested={} decided_at={}",
            e.seq, e.identity, e.root_seq, e.base, e.candidate, e.attested, e.decided_at
        ));
    }
    lines
}

/// What a start answers, by spec §6.2's marker table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Table {
    /// The start proceeds.
    Admit,
    /// Running under this boot.
    RunningInThisBoot,
    /// A missing marker beside other files.
    Occupied,
    /// A malformed marker.
    Malformed,
}

impl Table {
    /// The `REFUSED` line's `StartRefused` variant, for a refusal.
    pub(super) const fn refusal(self) -> Option<&'static str> {
        match self {
            Self::Admit => None,
            Self::RunningInThisBoot => Some("RunningInThisBoot"),
            Self::Occupied => Some("StateDirectoryOccupied"),
            Self::Malformed => Some("MarkerMalformed"),
        }
    }
}

/// The marker table's answer for a start under `boot` over the state
/// directory at `state`, read from the directory itself.
pub(super) fn table(state: &Path, boot: BootId) -> Table {
    if let Ok(bytes) = std::fs::read(state.join("MARKER")) {
        return match decode_marker(&bytes) {
            Ok(RunMarker::Running(at)) if at == boot => Table::RunningInThisBoot,
            Ok(_) => Table::Admit,
            Err(_) => Table::Malformed,
        };
    }
    let occupied = std::fs::read_dir(state).is_ok_and(|mut entries| entries.next().is_some());
    if occupied {
        Table::Occupied
    } else {
        Table::Admit
    }
}

/// The first `Position { .., seq: N }` in a rendered answer: the entry the
/// answer reports.
pub(super) fn position(rendered: &str) -> Option<u64> {
    let at = rendered.find("Position {")?;
    let rest = rendered.get(at..)?;
    let seq_at = rest.find("seq: ")?;
    let digits: String = rest
        .get(seq_at + 5..)?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// What a sent reply depends on being committed: `(record kind, position)`,
/// or the log's existence with an epoch; `None` for a reply that reports
/// nothing written.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Needs {
    Decision(u64),
    Outcome(u64),
    Envelope,
}

/// The dependency of a `REPLY` line's rendered answer: `Ok(None)` for an
/// answer that reports nothing written, and an error for a rendering the
/// harness cannot read, so a change to how an answer renders fails the
/// check instead of skipping it.
pub(super) fn needs(rendered: &str) -> Result<Option<Needs>, String> {
    let variant: String = rendered
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    let at = || {
        position(rendered)
            .ok_or_else(|| format!("no position in a reply that reports one: {rendered}"))
    };
    Ok(match variant.as_str() {
        "Landed" | "Lost" => Some(Needs::Outcome(at()?)),
        "OperationBound" if rendered.starts_with("OperationBound(Landed(") => {
            Some(Needs::Outcome(at()?))
        }
        "OperationBound" if rendered.starts_with("OperationBound(Open {") => {
            Some(Needs::Decision(at()?))
        }
        "Accepted" | "Open" | "NotDecided" => Some(Needs::Decision(at()?)),
        "Ok" if rendered.starts_with("Ok(Created {") || rendered.starts_with("Ok(Kept {") => {
            Some(Needs::Envelope)
        }
        "NoLog" | "InvalidCandidate" | "StaleBase" | "VolumeDamaged" | "UnconfiguredVolume"
        | "Fenced" | "Stopped" | "Err" => None,
        _ => return Err(format!("a reply the harness cannot read: {rendered}")),
    })
}

/// Whether `log` holds, committed, what `need` names.
pub(super) fn holds(log: Option<&Log>, need: &Needs, rendered: &str) -> bool {
    let Some(log) = log else {
        return false;
    };
    match need {
        Needs::Envelope => rendered.contains(&log.epoch),
        Needs::Decision(seq) => log
            .records
            .iter()
            .any(|r| r.seq() == *seq && matches!(r.body(), RecordBody::Decision { .. })),
        Needs::Outcome(seq) => log.records.iter().any(|r| {
            r.seq() == *seq
                && matches!(
                    r.body(),
                    RecordBody::Landed { .. } | RecordBody::Lost { .. }
                )
        }),
    }
}

/// The attestation committed for position `seq` in `log`: its volume's
/// root seq comes from the decision, its id from the attestation.
pub(super) fn attested(log: &Log, seq: u64) -> Option<(u64, GrainId)> {
    let root_seq = log.records.iter().find_map(|r| match r.body() {
        RecordBody::Decision { root_seq, .. } if r.seq() == seq => Some(*root_seq),
        _ => None,
    })?;
    let id = log.records.iter().find_map(|r| match r.body() {
        RecordBody::Attestation { stored_id, .. } if r.seq() == seq => Some(*stored_id),
        _ => None,
    })?;
    Some((root_seq, id))
}
