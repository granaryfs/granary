// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use granary_client::{CheckedLost, PublishRequest};
use granary_core::{
    hash::GrainId,
    retained_submission::{Candidate, Phase, Role, Submission},
};
use std::collections::{BTreeMap, BTreeSet};

type CandidateKey = ([u8; 16], [u8; 16], [u8; 16], u64, GrainId);
fn key(r: &Submission, c: &Candidate) -> CandidateKey {
    // Catalogue numbers can be reused after release. Evidence and attempt
    // uniqueness belong to the exact publication, request identity and bytes.
    (
        r.publication_id,
        c.request.epoch,
        c.request.operation,
        c.number,
        c.id,
    )
}

type ExactKey = ([u8; 16], [u8; 16], [u8; 16], GrainId);
fn exact(r: &Submission, c: &Candidate) -> ExactKey {
    (r.publication_id, c.request.epoch, c.request.operation, c.id)
}
fn request_key(req: &PublishRequest) -> ([u8; 16], Vec<u8>, GrainId) {
    (
        req.epoch().to_bytes(),
        req.operation().to_vec(),
        req.candidate().id(),
    )
}

/// Independent attempt and occupancy history. No coordinator classification or
/// comparison helper is reused by the oracle.
#[derive(Debug, Default)]
pub(super) struct Oracle {
    catalogue: BTreeMap<CandidateKey, (u64, GrainId, u64, Role)>,
    proofs: BTreeMap<CandidateKey, u64>,
    decisions: BTreeSet<GrainId>,
    lost: BTreeSet<ExactKey>,
    accepted: BTreeSet<([u8; 16], Vec<u8>, GrainId)>,
    stale: BTreeSet<ExactKey>,
    foreign: BTreeMap<ExactKey, (GrainId, u64)>,
    invocation: u64,
    retry_witness: BTreeMap<ExactKey, GrainId>,
    observed: BTreeSet<u64>,
    operations: BTreeMap<Vec<u8>, [u8; 16]>,
    sent: BTreeSet<(CandidateKey, u64)>,
    failed_probe: BTreeMap<u64, u64>,
}
impl Oracle {
    pub(super) fn begin_invocation(&mut self, invocation: u64) {
        self.invocation = invocation;
    }
    pub(super) fn no_write(&mut self, r: &Submission, number: u64) {
        if let Some(c) = r.candidates.iter().find(|c| c.number == number) {
            *self.proofs.entry(key(r, c)).or_default() += 1;
        }
    }
    #[cfg(test)]
    pub(super) fn decided(&mut self, id: GrainId) {
        self.decisions.insert(id);
    }
    pub(super) fn decided_request(&mut self, req: &PublishRequest) {
        self.accepted.insert(request_key(req));
    }
    pub(super) fn occupancy(&mut self, r: &Submission, seq: u64, id: GrainId, invocation: u64) {
        self.invocation = invocation;
        if r.candidates.iter().any(|c| c.seq == seq && c.id == id) {
            return;
        }
        for c in r
            .candidates
            .iter()
            .filter(|c| c.role == Role::Active && c.seq == seq)
        {
            self.foreign.insert(exact(r, c), (id, invocation));
        }
    }
    pub(super) fn forward_stale(
        &mut self,
        r: &Submission,
        req: &PublishRequest,
        head: granary_core::authority_answer::Head,
        engine_absence: bool,
    ) {
        let Some(c) = r.candidates.iter().find(|c| {
            c.role == Role::Active
                && c.id == req.candidate().id()
                && c.request.epoch == req.epoch().to_bytes()
                && c.request.operation.as_slice() == req.operation()
        }) else {
            return;
        };
        let k = exact(r, c);
        if engine_absence
            && !self.accepted.contains(&request_key(req))
            && let Some(foreign) = self.retry_witness.get(&k)
            && head
                .root
                .is_some_and(|(seq, id)| seq >= c.seq && (seq != c.seq || id == *foreign))
        {
            self.stale.insert(k);
        }
    }
    pub(super) fn checked_lost(
        &mut self,
        r: &Submission,
        number: u64,
        req: &PublishRequest,
        lost: CheckedLost,
    ) {
        if let Some(answered) = r.candidates.iter().find(|c| {
            c.number == number
                && c.id == lost.decision().candidate_id()
                && c.request.epoch == lost.decision().position().epoch.to_bytes()
                && c.request.epoch == req.epoch().to_bytes()
                && c.request.operation.as_slice() == req.operation()
                && c.id == req.candidate().id()
        }) {
            // A checked outcome closes every current Active/History entry for
            // these bytes, including twins with their own catalogue numbers.
            for c in r.candidates.iter().filter(|c| {
                c.id == answered.id
                    && c.request == answered.request
                    && c.role != granary_core::retained_submission::Role::Retired
            }) {
                self.lost.insert(exact(r, c));
            }
        }
    }
    pub(super) fn probe(
        &mut self,
        seq: u64,
        occupied: bool,
        failed: bool,
        invocation: u64,
        explicit: bool,
    ) -> Option<String> {
        if let Some(prior) = self.failed_probe.get(&seq)
            && (!explicit || *prior == invocation)
        {
            return Some("failed probe repeated without a new explicit invocation".into());
        }
        if failed {
            self.failed_probe.insert(seq, invocation);
        } else {
            self.failed_probe.remove(&seq);
        }
        if occupied {
            self.observed.insert(seq);
        }
        None
    }
    pub(super) fn send(&mut self, r: Option<&Submission>, req: &PublishRequest) -> Option<String> {
        let Some(r) = r else {
            return Some("send without durable record".into());
        };
        let Phase::AwaitingAnswer { candidate, attempt } = r.phase else {
            return Some("send without durable attempt".into());
        };
        let Some(c) = r.candidates.iter().find(|c| c.number == candidate) else {
            return Some("send candidate missing".into());
        };
        if c.root.as_slice() != req.candidate().bytes().as_ref()
            || c.request.epoch != req.epoch().to_bytes()
            || c.request.operation.as_slice() != req.operation()
            || c.evidence.started != attempt
            || c.evidence.last_answered_attempt >= attempt
        {
            return Some("durable exact tuple/accounting mismatch".into());
        }
        if !self.sent.insert((key(r, c), attempt)) {
            return Some("send reuses an attempt".into());
        }
        if r.candidates.iter().any(|c| {
            c.role == granary_core::retained_submission::Role::Retired
                && c.seq != req.candidate().seq()
        }) {
            return Some("send past an unresolved retired candidate".into());
        }
        let k = exact(r, c);
        self.retry_witness.remove(&k);
        if let Some((id, invocation)) = self.foreign.get(&k)
            && *invocation == self.invocation
        {
            self.retry_witness.insert(k, *id);
        }
        None
    }
    pub(super) fn check(
        &mut self,
        r: Option<&Submission>,
        roots: &BTreeMap<(String, u64), Vec<u8>>,
    ) -> Vec<String> {
        let mut errors = Vec::new();
        let Some(r) = r else { return errors };
        let current: BTreeSet<_> = r.candidates.iter().map(|c| key(r, c)).collect();
        for (candidate @ (publication, epoch, operation, _, _), (seq, id, started, role)) in
            &self.catalogue
        {
            if *publication == r.publication_id && !current.contains(candidate) {
                let all_no_write = self.proofs.get(candidate).copied().unwrap_or(0) == *started
                    && !self.decisions.contains(id)
                    && !self.accepted.contains(&(*epoch, operation.to_vec(), *id));
                let tuple = (*publication, *epoch, *operation, *id);
                let retired_dead = *role == Role::Retired && self.observed.contains(seq);
                let stale_safe = self.stale.contains(&tuple)
                    && !self.accepted.contains(&(*epoch, operation.to_vec(), *id));
                if !all_no_write
                    && !retired_dead
                    && !(*role != Role::Retired && (self.lost.contains(&tuple) || stale_safe))
                {
                    errors.push("potentially decided candidate released without independent settlement or retirement evidence".into());
                }
            }
        }
        for c in &r.candidates {
            self.catalogue
                .insert(key(r, c), (c.seq, c.id, c.evidence.started, c.role));
            if self
                .operations
                .insert(c.request.operation.to_vec(), c.request.epoch)
                .is_some_and(|old| old != c.request.epoch)
            {
                errors.push("operation crosses epochs".into());
            }
        }
        if let Some(identity) = r.current
            && self
                .operations
                .insert(identity.operation.to_vec(), identity.epoch)
                .is_some_and(|old| old != identity.epoch)
        {
            errors.push("current operation crosses epochs".into());
        }
        let landed: BTreeSet<_> = self
            .catalogue
            .iter()
            .filter(|((p, _, _, _, _), _)| *p == r.publication_id)
            .filter_map(|(_, (seq, id, _, _))| {
                roots
                    .get(&(r.volume.as_str().to_owned(), *seq))
                    .filter(|bytes| GrainId::of(bytes) == *id)
                    .map(|_| (*seq, *id))
            })
            .collect();
        if landed.len() > 1 {
            errors.push("more than one landing per logical publication".into());
        }
        if let Phase::Complete(done) = &r.phase
            && (!landed.contains(&(done.seq, done.id))
                || roots.get(&(r.volume.as_str().to_owned(), done.seq)) != Some(&done.root)
                || GrainId::of(&done.root) != done.id)
        {
            errors.push("completion does not identify actual own bytes".into());
        }
        errors
    }
}

#[cfg(test)]
mod tests;
