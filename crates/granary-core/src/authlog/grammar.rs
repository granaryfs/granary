// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The committed log's grammar determines
//! which record may follow a committed
//! prefix. [`Grammar`] is the one implementation of the seven rules;
//! [`super::classify`] holds a file's records to it, and the authority
//! engine holds each record it replays or appends to it.

use std::collections::{BTreeMap, BTreeSet};

use crate::hash::GrainId;

use super::record::{Record, RecordBody};
use super::submission::{Operation, Principal, SubmissionIdentity, Tenant};

/// The seven grammar rules for committed records. A grammar violation
/// identifies the rule the record broke. Its `Display` implementation
/// reports the corresponding number from 1 to 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrammarRule {
    /// A decision's `seq` was not one more than the highest seq before
    /// it.
    Rule1SequencePosition,
    /// A decision appeared while an entry was open.
    Rule2ConcurrentEntry,
    /// An attestation appeared with no entry open, at the wrong seq, or
    /// against an already-attested entry.
    Rule3AttestationPreconditions,
    /// A landed/lost outcome appeared with no entry open, at the wrong
    /// seq, or against a not-yet-attested entry.
    Rule4OutcomePreconditions,
    /// An attestation or outcome's identity (or, for an attestation,
    /// its `final_root`) did not match the entry's decision.
    Rule5IdentityMismatch,
    /// A decision was recorded for an operation whose earlier decision
    /// already landed.
    Rule6LandedOperationReplay,
    /// A decision was recorded for a submission identity an earlier
    /// decision already recorded.
    Rule7DuplicateAnswer,
}

impl std::fmt::Display for GrammarRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = match self {
            Self::Rule1SequencePosition => 1,
            Self::Rule2ConcurrentEntry => 2,
            Self::Rule3AttestationPreconditions => 3,
            Self::Rule4OutcomePreconditions => 4,
            Self::Rule5IdentityMismatch => 5,
            Self::Rule6LandedOperationReplay => 6,
            Self::Rule7DuplicateAnswer => 7,
        };
        write!(f, "rule {n}")
    }
}

/// The state one open entry carries while its attestation/outcome are
/// awaited.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenEntry {
    seq: u64,
    identity: SubmissionIdentity,
    /// The decision's own candidate id (`identity.candidate_id()` at the
    /// time the entry opened). Comparing ids rather than cloning the
    /// (up to [`super::submission::ROOT_BYTES_MAX`]-byte) candidate bytes
    /// is sound where the field
    /// rules tie each side's id to its own bytes —
    /// `candidate_id == GrainId::of(candidate)` for a decision,
    /// `stored_id == GrainId::of(final_root)` for an attestation — so id
    /// equality and byte equality agree. The decoder enforces both rules,
    /// and [`super::encode_append`] refuses a record that breaks either,
    /// so a record that passes this grammar and is then encoded or was
    /// decoded carries its candidate's bytes.
    candidate_id: GrainId,
    attested: bool,
}

/// The committed log's running grammar state: the committed prefix as
/// far as the seven rules need it. [`Self::check`] asks whether a record
/// may follow the prefix; [`Self::apply`] also extends the prefix by it.
///
/// `landed_operations` is a `Tenant -> Principal -> {Operation}` trie
/// rather than a flat set of cloned byte tuples, so the rule-6 lookup
/// every decision pays borrows the identity's own fields instead
/// of allocating three `Vec`s per call; only closing an entry as landed
/// (rare) clones anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grammar {
    highest_seq: u64,
    open_entry: Option<OpenEntry>,
    landed_operations: BTreeMap<Tenant, BTreeMap<Principal, BTreeSet<Operation>>>,
    answered_identities: BTreeSet<SubmissionIdentity>,
}

impl Grammar {
    /// The grammar state of a log holding no record.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest committed entry sequence; 0 before the first record.
    #[must_use]
    pub const fn highest_seq(&self) -> u64 {
        self.highest_seq
    }

    fn operation_landed(&self, identity: &SubmissionIdentity) -> bool {
        self.landed_operations
            .get(identity.tenant())
            .and_then(|by_principal| by_principal.get(identity.principal()))
            .is_some_and(|operations| operations.contains(identity.operation()))
    }

    fn mark_operation_landed(&mut self, identity: &SubmissionIdentity) {
        self.landed_operations
            .entry(identity.tenant().clone())
            .or_default()
            .entry(identity.principal().clone())
            .or_default()
            .insert(identity.operation().clone());
    }

    /// Rules 1, 2, 6 and 7: the checks on a decision, the one record
    /// kind that takes the next position.
    fn check_next_position(&self, record: &Record) -> Result<(), GrammarRule> {
        let identity = record.body().identity();
        if self.open_entry.is_some() {
            return Err(GrammarRule::Rule2ConcurrentEntry);
        }
        let expected = self.highest_seq.checked_add(1);
        if expected != Some(record.seq()) {
            return Err(GrammarRule::Rule1SequencePosition);
        }
        if self.operation_landed(identity) {
            return Err(GrammarRule::Rule6LandedOperationReplay);
        }
        if self.answered_identities.contains(identity) {
            return Err(GrammarRule::Rule7DuplicateAnswer);
        }
        Ok(())
    }

    /// Whether `record` may follow the committed prefix, changing
    /// nothing.
    ///
    /// # Errors
    /// The [`GrammarRule`] `record` breaks.
    pub fn check(&self, record: &Record) -> Result<(), GrammarRule> {
        let identity = record.body().identity();
        match record.body() {
            RecordBody::Decision { .. } => self.check_next_position(record),
            RecordBody::Attestation { stored_id, .. } => {
                let Some(entry) = self.open_entry.as_ref() else {
                    return Err(GrammarRule::Rule3AttestationPreconditions);
                };
                if entry.seq != record.seq() || entry.attested {
                    return Err(GrammarRule::Rule3AttestationPreconditions);
                }
                if entry.identity != *identity || entry.candidate_id != *stored_id {
                    return Err(GrammarRule::Rule5IdentityMismatch);
                }
                Ok(())
            }
            RecordBody::Landed { .. } | RecordBody::Lost { .. } => {
                let Some(entry) = self.open_entry.as_ref() else {
                    return Err(GrammarRule::Rule4OutcomePreconditions);
                };
                if entry.seq != record.seq() || !entry.attested {
                    return Err(GrammarRule::Rule4OutcomePreconditions);
                }
                if entry.identity != *identity {
                    return Err(GrammarRule::Rule5IdentityMismatch);
                }
                // A correct writer classifies a read that finds the
                // entry's own bytes as landed, never lost (spec §4.2) —
                // a `Lost` naming the entry's own stored id is a grammar
                // violation, not a legal outcome.
                if matches!(record.body(), RecordBody::Lost { occupant_id, .. } if *occupant_id == entry.candidate_id)
                {
                    return Err(GrammarRule::Rule5IdentityMismatch);
                }
                Ok(())
            }
        }
    }

    /// Extend the committed prefix by `record`, if [`Self::check`]
    /// accepts it.
    ///
    /// # Errors
    /// The [`GrammarRule`] `record` breaks; the state is then unchanged.
    pub fn apply(&mut self, record: &Record) -> Result<(), GrammarRule> {
        self.check(record)?;
        let identity = record.body().identity();
        match record.body() {
            RecordBody::Decision { .. } => {
                self.take_next_position(record);
                self.open_entry = Some(OpenEntry {
                    seq: record.seq(),
                    identity: identity.clone(),
                    candidate_id: identity.candidate_id(),
                    attested: false,
                });
            }
            RecordBody::Attestation { .. } => {
                if let Some(entry) = self.open_entry.as_mut() {
                    entry.attested = true;
                }
            }
            RecordBody::Landed { .. } => {
                self.mark_operation_landed(identity);
                self.open_entry = None;
            }
            RecordBody::Lost { .. } => self.open_entry = None,
        }
        Ok(())
    }

    /// A decision [`Self::check`] accepted takes the next position and
    /// answers its submission identity.
    fn take_next_position(&mut self, record: &Record) {
        self.highest_seq = record.seq();
        self.answered_identities
            .insert(record.body().identity().clone());
    }
}
