// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One volume's state, and the one function that changes it.
//!
//! [`VolumeState::apply`] is the only way a volume's state moves. Replay
//! feeds it the committed records `classify` returned; the live path
//! feeds it each record after that record's `append` has returned `Ok`,
//! never before. So nothing reads state a record would create before the
//! record is committed, and the state after recovery is exactly the state
//! the same records gave while the engine ran: there is one code path,
//! and a test compares the two.
//!
//! **Replay re-classifies nothing.** `apply` takes a record and nothing
//! else: it has no store and no clock to consult, so a committed landed
//! or lost outcome is restored exactly as it was written.
//!
//! `apply` holds each record to the committed log's grammar
//! through the same [`Grammar`] `classify` uses, and refuses one that
//! breaks it without changing anything. On replay a refusal cannot happen
//! for a log `classify` accepted; on the live path the engine calls
//! [`VolumeState::check`] before it appends, so a record the state would
//! refuse never reaches the log. Were `apply` still to refuse a record
//! once it was appended, the engine fences rather than serve a state the
//! log disagrees with (the worker's `commit`).

use std::collections::BTreeMap;

use granary_core::authlog::{
    Envelope, Grammar, GrammarRule, Operation, Principal, Record, RecordBody, RootBytes,
    SeqZeroError, SubmissionIdentity, Tenant,
};
use granary_core::hash::GrainId;
use granary_core::sheaf::Timestamp;

/// Where an accepted candidate's publication stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Decided, with no outcome recorded yet.
    Open,
    /// The candidate's bytes are the chain's at its seq.
    Landed,
    /// Another valid root took the seq; `occupant` is its stored id.
    Lost { occupant: GrainId },
}

/// An operation's binding: its latest decision's candidate id and where
/// that candidate's publication stands (spec §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) candidate_id: GrainId,
    /// The decision's position in the log.
    pub(crate) seq: u64,
    /// The seq the decided candidate is published at.
    pub(crate) root_seq: u64,
    pub(crate) outcome: Outcome,
}

/// The decision recorded for one submission identity (the operation plus
/// the candidate id), whose answer a resubmission of the same candidate
/// gets back (spec §3 rule 3): accepted at position `seq`, to be
/// published at `root_seq`; `outcome` is where its publication stands.
/// Only an accepted candidate is recorded: a stale one is answered
/// afresh each time, and nothing is kept of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Recorded {
    pub(crate) seq: u64,
    pub(crate) root_seq: u64,
    pub(crate) outcome: Outcome,
}

/// The volume's open entry: an accepted candidate whose outcome is not
/// yet recorded. At most one exists (spec §1, "one open publication").
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenEntry {
    pub(crate) seq: u64,
    pub(crate) identity: SubmissionIdentity,
    pub(crate) root_seq: u64,
    pub(crate) base: Option<GrainId>,
    /// The decided candidate's bytes: for an unprofiled volume also the
    /// final bytes its attestation records (spec §4.1).
    pub(crate) candidate: RootBytes,
    /// Whether the entry's attestation has committed. Its final bytes
    /// are the candidate's: the grammar holds an attestation's stored id
    /// to the candidate id, and the codec holds the stored id to the
    /// final bytes' id.
    pub(crate) attested: bool,
    pub(crate) decided_at: Timestamp,
}

/// Why the state refused a record: the committed log's grammar rule it
/// breaks, as [`Grammar`] judges it. The state is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyError {
    /// The refused record's seq.
    pub seq: u64,
    /// The rule it breaks.
    pub rule: GrammarRule,
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "record {} breaks the committed log's grammar: {}",
            self.seq, self.rule
        )
    }
}

impl std::error::Error for ApplyError {}

/// An operation's key: the tenant, the principal and the operation
/// identity (spec §2: an operation is scoped to all three).
type OperationKey = (Tenant, Principal, Operation);

pub(crate) fn operation_key(identity: &SubmissionIdentity) -> OperationKey {
    (
        identity.tenant().clone(),
        identity.principal().clone(),
        identity.operation().clone(),
    )
}

/// One volume's state: its envelope, the committed log's grammar state,
/// every operation's binding, every recorded answer, and the open entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VolumeState {
    envelope: Envelope,
    /// The committed prefix as the grammar sees it: the highest position
    /// and every rule's bookkeeping.
    grammar: Grammar,
    bindings: BTreeMap<OperationKey, Binding>,
    recorded: BTreeMap<SubmissionIdentity, Recorded>,
    open: Option<OpenEntry>,
    /// A refusal the next [`Self::apply`] returns in place of applying,
    /// for a test to prove what a refused committed record does.
    #[cfg(test)]
    refuse_next_apply: Option<ApplyError>,
}

impl VolumeState {
    /// The state of a log holding its envelope and no record.
    pub(crate) fn new(envelope: Envelope) -> Self {
        Self {
            envelope,
            grammar: Grammar::new(),
            bindings: BTreeMap::new(),
            recorded: BTreeMap::new(),
            open: None,
            #[cfg(test)]
            refuse_next_apply: None,
        }
    }

    /// The state `records` give, applied in order to an empty log under
    /// `envelope`: recovery's replay.
    ///
    /// # Errors
    /// The refusal of the first record [`Self::apply`] refuses, which
    /// names that record's seq.
    pub(crate) fn replay(envelope: Envelope, records: &[Record]) -> Result<Self, ApplyError> {
        let mut state = Self::new(envelope);
        for record in records {
            state.apply(record)?;
        }
        Ok(state)
    }

    pub(crate) const fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// Every field of the state as the crash harness's `STATE` lines, in a
    /// fixed order: the epoch and the next position, each recorded
    /// decision, each binding, and the open entry. The harness's model of
    /// recovery renders the same lines from its own replay.
    #[cfg(all(test, feature = "crash-points"))]
    pub(crate) fn crash_lines(&self) -> Vec<String> {
        let volume = self.envelope.volume().as_str();
        let outcome = |outcome: &Outcome| match outcome {
            Outcome::Open => "open".to_owned(),
            Outcome::Landed => "landed".to_owned(),
            Outcome::Lost { occupant } => format!("lost:{occupant:?}"),
        };
        let mut lines = vec![format!(
            "STATE {volume} epoch={:?} next={:?}",
            self.envelope.epoch(),
            self.next_seq()
        )];
        for (identity, recorded) in &self.recorded {
            lines.push(format!(
                "STATE {volume} recorded identity={identity:?} seq={} root_seq={} outcome={}",
                recorded.seq,
                recorded.root_seq,
                outcome(&recorded.outcome)
            ));
        }
        for ((tenant, principal, operation), binding) in &self.bindings {
            lines.push(format!(
                "STATE {volume} binding op={tenant:?}/{principal:?}/{operation:?} candidate={:?} \
                 seq={} root_seq={} outcome={}",
                binding.candidate_id,
                binding.seq,
                binding.root_seq,
                outcome(&binding.outcome)
            ));
        }
        if let Some(open) = &self.open {
            lines.push(format!(
                "STATE {volume} open seq={} identity={:?} root_seq={} base={:?} candidate={:?} \
                 attested={} decided_at={:?}",
                open.seq,
                open.identity,
                open.root_seq,
                open.base,
                GrainId::of(open.candidate.as_bytes()),
                open.attested,
                open.decided_at
            ));
        }
        lines
    }

    /// The open entry, if one is open.
    pub(crate) const fn open(&self) -> Option<&OpenEntry> {
        self.open.as_ref()
    }

    /// The answer recorded for `identity`, if one is (spec §3 rule 3).
    pub(crate) fn recorded(&self, identity: &SubmissionIdentity) -> Option<&Recorded> {
        self.recorded.get(identity)
    }

    /// The binding of `identity`'s operation, if it has one (spec §5).
    pub(crate) fn binding(&self, identity: &SubmissionIdentity) -> Option<&Binding> {
        self.bindings.get(&operation_key(identity))
    }

    /// The position the next decision takes: one past the highest
    /// committed. `None` only past `u64::MAX` records, which no
    /// log can hold.
    pub(crate) const fn next_seq(&self) -> Option<u64> {
        self.grammar.highest_seq().checked_add(1)
    }

    /// The attestation the open entry is owed: the entry's decision
    /// committed and its attestation did not. Built from the recorded
    /// decision alone — for an unprofiled volume the final bytes are the
    /// candidate bytes and their stored id is the candidate id (spec
    /// §4.1, §6.4).
    ///
    /// # Errors
    /// [`SeqZeroError`] if the entry's seq is 0, which no entry a record
    /// opened can carry.
    pub(crate) fn owed_attestation(&self) -> Result<Option<Record>, SeqZeroError> {
        let Some(entry) = self.open.as_ref().filter(|entry| !entry.attested) else {
            return Ok(None);
        };
        Record::new(
            entry.seq,
            RecordBody::Attestation {
                identity: entry.identity.clone(),
                stored_id: GrainId::of(entry.candidate.as_bytes()),
                final_root: entry.candidate.clone(),
            },
        )
        .map(Some)
    }

    /// Whether [`Self::apply`] would accept `record`, changing nothing.
    ///
    /// # Errors
    /// The grammar rule `record` breaks.
    pub(crate) fn check(&self, record: &Record) -> Result<(), ApplyError> {
        self.grammar.check(record).map_err(|rule| ApplyError {
            seq: record.seq(),
            rule,
        })
    }

    /// Apply one committed record: the only change a volume's state ever
    /// undergoes (module docs).
    ///
    /// # Errors
    /// The grammar rule `record` breaks; the state is then unchanged.
    pub(crate) fn apply(&mut self, record: &Record) -> Result<(), ApplyError> {
        let seq = record.seq();
        #[cfg(test)]
        if let Some(refusal) = self.refuse_next_apply.take() {
            return Err(refusal);
        }
        self.grammar
            .apply(record)
            .map_err(|rule| ApplyError { seq, rule })?;
        match record.body() {
            RecordBody::Decision {
                identity,
                root_seq,
                base,
                decided_at,
                candidate,
            } => {
                self.bindings.insert(
                    operation_key(identity),
                    Binding {
                        candidate_id: identity.candidate_id(),
                        seq,
                        root_seq: *root_seq,
                        outcome: Outcome::Open,
                    },
                );
                self.recorded.insert(
                    identity.clone(),
                    Recorded {
                        seq,
                        root_seq: *root_seq,
                        outcome: Outcome::Open,
                    },
                );
                self.open = Some(OpenEntry {
                    seq,
                    identity: identity.clone(),
                    root_seq: *root_seq,
                    base: *base,
                    candidate: candidate.clone(),
                    attested: false,
                    decided_at: *decided_at,
                });
            }
            RecordBody::Attestation { .. } => {
                if let Some(entry) = self.open.as_mut() {
                    entry.attested = true;
                }
            }
            RecordBody::Landed { identity } => self.close(identity, Outcome::Landed),
            RecordBody::Lost {
                identity,
                occupant_id,
            } => self.close(
                identity,
                Outcome::Lost {
                    occupant: *occupant_id,
                },
            ),
        }
        Ok(())
    }

    /// Make the next [`Self::apply`] return `refusal`, changing nothing.
    #[cfg(test)]
    pub(crate) const fn refuse_next_apply(&mut self, refusal: ApplyError) {
        self.refuse_next_apply = Some(refusal);
    }

    /// Replace the open entry's candidate bytes with `candidate`, leaving
    /// the grammar's record of the entry as it was: the owed attestation
    /// built from it is then one the grammar refuses.
    #[cfg(test)]
    pub(crate) fn replace_open_candidate(&mut self, candidate: RootBytes) {
        if let Some(entry) = self.open.as_mut() {
            entry.candidate = candidate;
        }
    }

    /// Close the open entry with `outcome`: its binding and its recorded
    /// answer both take it.
    fn close(&mut self, identity: &SubmissionIdentity, outcome: Outcome) {
        if let Some(binding) = self.bindings.get_mut(&operation_key(identity)) {
            binding.outcome = outcome;
        }
        if let Some(recorded) = self.recorded.get_mut(identity) {
            recorded.outcome = outcome;
        }
        self.open = None;
    }
}

#[cfg(test)]
mod tests;
