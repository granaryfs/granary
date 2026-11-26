// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The sweep's workload: its roots, the client's script, and the records
//! a finished run's logs must hold.
//!
//! The script is **idempotent across a restart**: every step re-submits
//! the same epoch and bytes under the same operation and reads the
//! recorded answer, and every out-of-band action is a one-shot whose "done" flag lives in
//! [`Script`], which outlives the processes of a run. The two stale-base
//! probes run once per run: their flag is set when their answer arrives,
//! and they precede, in the script, every step that would change their
//! answer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use granary_core::authlog::{EPOCH_LEN, Epoch, Record};
use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use granary_core::rootstore::RootStore;
use granary_sim::fakes::{Admin, SimStore};
use granary_sim::sched::yield_once;

use super::super::{
    Answer, AuthorityHandle, HeadRef, InitialiseError, Initialised, Receipt, RunEnd, Submission,
    VerifiedHead, attestation, decision_of, good_root, landed, lost, submission_at,
};
use super::harness::{Ev, Hooks, Timeline};
use super::{a, b};

/// Bytes planted at a decided seq: not a root at all.
pub(super) const JUNK: &[u8] = b"a squatter at the decided seq";

/// How many `Open` answers a client sees before it removes a squatter.
const OPENS_BEFORE_REMOVAL: u32 = 3;

/// How many submissions a settle makes before it calls the run stuck.
const SETTLE_LIMIT: u32 = 20_000;

/// The workload's roots, each publisher-signed for its volume.
#[derive(Debug, Clone)]
pub(super) struct Roots {
    /// A's seq 1.
    pub(super) c1: Vec<u8>,
    /// A second seq-1 root: stale once `c1` is the head.
    pub(super) x: Vec<u8>,
    /// A's seq 2, over `c1`.
    pub(super) c2: Vec<u8>,
    /// A foreign root at A's seq 3 over `c2`: it wins the seq.
    pub(super) f3: Vec<u8>,
    /// The authority's candidate at A's seq 3 over `c2`: it loses.
    pub(super) c3: Vec<u8>,
    /// The rebase: A's seq 4 over `f3`.
    pub(super) c3p: Vec<u8>,
    /// A's seq 5 over `c3p`.
    pub(super) c4: Vec<u8>,
    /// B's seq 1.
    pub(super) d1: Vec<u8>,
}

impl Roots {
    pub(super) fn new() -> Self {
        let c1 = good_root(&a(), 1, None, 1);
        let x = good_root(&a(), 1, None, 2);
        let c2 = good_root(&a(), 2, Some(GrainId::of(&c1)), 1);
        let f3 = good_root(&a(), 3, Some(GrainId::of(&c2)), 0xF3);
        let c3 = good_root(&a(), 3, Some(GrainId::of(&c2)), 1);
        let c3p = good_root(&a(), 4, Some(GrainId::of(&f3)), 1);
        let c4 = good_root(&a(), 5, Some(GrainId::of(&c3p)), 1);
        let d1 = good_root(&b(), 1, None, 1);
        Self {
            c1,
            x,
            c2,
            f3,
            c3,
            c3p,
            c4,
            d1,
        }
    }

    /// The hooks the world fires at store operations: `f3` planted
    /// before the first PUT at A's seq 3, junk before the first at B's
    /// seq 1 and A's seq 5, and A's seq 4 deleted after its first
    /// successful PUT, before the classification read.
    pub(super) fn hooks(&self) -> Hooks {
        Hooks {
            plant_before_put: vec![
                (a().as_str().to_owned(), 3, self.f3.clone(), false),
                (b().as_str().to_owned(), 1, JUNK.to_vec(), false),
                (a().as_str().to_owned(), 5, JUNK.to_vec(), false),
            ],
            delete_after_put: vec![(a().as_str().to_owned(), 4, false)],
        }
    }

    /// The records a finished run's log of `volume` holds, in order: each
    /// entry's decision, attestation and outcome, at the positions the
    /// script's order gives them.
    pub(super) fn expected(&self, volume: &VolumeName) -> Vec<Record> {
        let entry = |seq: u64, operation: u8, candidate: &[u8], occupant: Option<&[u8]>| {
            let d = decision_of(seq, operation, candidate);
            let outcome = match occupant {
                None => landed(&d),
                Some(occupant) => lost(&d, GrainId::of(occupant)),
            };
            vec![d.clone(), attestation(&d), outcome]
        };
        if *volume == b() {
            return entry(1, OP_D1, &self.d1, None);
        }
        [
            entry(1, OP_C1, &self.c1, None),
            entry(2, OP_C2, &self.c2, None),
            entry(3, OP_C3, &self.c3, Some(&self.f3)),
            entry(4, OP_C3, &self.c3p, None),
            entry(5, OP_C4, &self.c4, None),
        ]
        .concat()
    }
}

pub(super) const OP_C1: u8 = 1;
pub(super) const OP_C2: u8 = 2;
pub(super) const OP_D1: u8 = 3;
pub(super) const OP_C3: u8 = 4;
pub(super) const OP_C4: u8 = 5;

/// What the client keeps across the processes of one run.
#[derive(Debug, Default)]
pub(super) struct Script {
    /// The ahead-of-head probe has been answered.
    pub(super) ahead_probed: bool,
    /// The stale probe has been answered.
    pub(super) stale_probed: bool,
    /// Squatters removed, by `(volume, seq)`.
    pub(super) removed: Vec<(String, u64)>,
    /// The epoch each volume's log was created under, as `Created`
    /// answered it.
    pub(super) created: BTreeMap<VolumeName, Epoch>,
    /// Submissions built once and retained across retransmissions and process deaths.
    pub(super) submissions: BTreeMap<(VolumeName, u8, GrainId), Submission>,
    /// What the script found wrong.
    pub(super) failures: Vec<String>,
    /// Arms reached, by name, for the matrix's counts.
    pub(super) arms: BTreeMap<&'static str, u32>,
    /// The script ran to its end and the stop answered.
    pub(super) finished: Option<RunEnd>,
}

impl Script {
    fn fail(&mut self, what: String) {
        self.failures.push(what);
    }

    fn arm(&mut self, name: &'static str) {
        *self.arms.entry(name).or_insert(0) += 1;
    }
}

/// Why the script stopped early: the engine fenced or stopped.
struct Down;

/// What a client needs beside the engine's handle.
#[derive(Debug, Clone)]
pub(super) struct Client {
    pub(super) roots: Roots,
    pub(super) script: Arc<Mutex<Script>>,
    pub(super) hooks: Arc<Mutex<Hooks>>,
    /// The simulator's oracle store: reads that are not part of the run.
    pub(super) oracle: Arc<SimStore>,
    pub(super) admin: Admin,
    pub(super) timeline: Arc<Timeline>,
}

impl Client {
    fn fail(&self, what: String) {
        self.script.lock().unwrap().fail(what);
    }

    fn arm(&self, name: &'static str) {
        self.script.lock().unwrap().arm(name);
    }

    /// Run the script to its end, or until the engine fences or stops.
    pub(super) async fn run(self, handle: AuthorityHandle) {
        if self.script_body(&handle).await.is_ok() {
            let end = handle.stop().await;
            self.script.lock().unwrap().finished = Some(end);
        }
    }

    async fn script_body(&self, handle: &AuthorityHandle) -> Result<(), Down> {
        let r = &self.roots;
        self.initialise(handle, &a()).await?;
        self.initialise(handle, &b()).await?;
        self.epoch_probes(handle).await?;

        // The ahead-of-head probe: `c2` over an empty chain.
        if !self.script.lock().unwrap().ahead_probed {
            let answer = handle.submit(self.submission(&a(), OP_C2, &r.c2)).await;
            match answer {
                Answer::StaleBase { head } if head == VerifiedHead::new(None) => {
                    self.arm("stale-ahead-of-head");
                }
                Answer::Fenced | Answer::Stopped => return Err(Down),
                other => self.fail(format!("the ahead-of-head probe answered {other:?}")),
            }
            self.script.lock().unwrap().ahead_probed = true;
        }

        // `c1` lands; its duplicate gets the recorded answer.
        let c1 = self.settle(handle, &a(), OP_C1, &r.c1, None).await?;
        let c1_receipt = match c1 {
            Answer::Landed { receipt, .. } if receipt.stored_id == GrainId::of(&r.c1) => receipt,
            other => {
                self.fail(format!("c1 settled as {other:?}"));
                return Err(Down);
            }
        };
        match handle.submit(self.submission(&a(), OP_C1, &r.c1)).await {
            Answer::Landed { receipt, .. } if receipt == c1_receipt => self.arm("duplicate-landed"),
            Answer::Fenced | Answer::Stopped => return Err(Down),
            other => self.fail(format!("c1's duplicate answered {other:?}")),
        }

        // The stale probe: `x` under operation 2, stale against `c1`.
        if !self.script.lock().unwrap().stale_probed {
            let answer = handle.submit(self.submission(&a(), OP_C2, &r.x)).await;
            let c1_head = VerifiedHead::new(Some(HeadRef {
                head_seq: 1,
                head_id: GrainId::of(&r.c1),
            }));
            match answer {
                Answer::StaleBase { head } if head == c1_head => self.arm("stale-refused"),
                Answer::Fenced | Answer::Stopped => return Err(Down),
                other => self.fail(format!("the stale probe answered {other:?}")),
            }
            self.script.lock().unwrap().stale_probed = true;
        }

        // `c2` (refused ahead, now extending; operation 2's only answers
        // were refusals) and `d1` (B's seq-1 wedge), side by side.
        for (volume, operation, candidate) in [(a(), OP_C2, &r.c2), (b(), OP_D1, &r.d1)] {
            match handle
                .submit(self.submission(&volume, operation, candidate))
                .await
            {
                Answer::Fenced | Answer::Stopped => return Err(Down),
                Answer::Accepted { .. } | Answer::Open { .. } | Answer::Landed { .. } => {}
                other => self.fail(format!("{} answered {other:?}", volume.as_str())),
            }
        }
        let c2 = self.settle(handle, &a(), OP_C2, &r.c2, None).await?;
        self.expect_landed("c2", &c2, &r.c2);
        let d1 = self
            .settle(handle, &b(), OP_D1, &r.d1, Some((b(), 1)))
            .await?;
        self.expect_landed("d1", &d1, &r.d1);

        // `c3` loses to `f3`; its rebase `c3p` lands after a delete
        // between its PUT and its read.
        let c3 = self.settle(handle, &a(), OP_C3, &r.c3, None).await?;
        match c3 {
            Answer::Lost { occupant, .. } if occupant == GrainId::of(&r.f3) => self.arm("lost"),
            other => self.fail(format!("c3 settled as {other:?}")),
        }
        let c3p = self.settle(handle, &a(), OP_C3, &r.c3p, None).await?;
        self.expect_landed("c3p", &c3p, &r.c3p);

        // `c4`: a wedge above seq 1, removed.
        let c4 = self
            .settle(handle, &a(), OP_C4, &r.c4, Some((a(), 5)))
            .await?;
        self.expect_landed("c4", &c4, &r.c4);
        self.epoch_probes(handle).await?;
        Ok(())
    }

    /// Reuse the original submission, including its epoch, on every retry.
    fn submission(&self, volume: &VolumeName, operation: u8, candidate: &[u8]) -> Submission {
        let mut script = self.script.lock().unwrap();
        let epoch = script.created[volume];
        script
            .submissions
            .entry((volume.clone(), operation, GrainId::of(candidate)))
            .or_insert_with(|| submission_at(epoch, volume, operation, candidate))
            .clone()
    }

    /// Probe both logs at every process's beginning and at the workload's end.
    /// The timeline oracle checks fresh head evidence and forbids decisions
    /// between the probe and its emitted answer, including interrupted probes.
    async fn epoch_probes(&self, handle: &AuthorityHandle) -> Result<(), Down> {
        for volume in [a(), b()] {
            let epoch = self.script.lock().unwrap().created[&volume];
            let wrong = if epoch == Epoch::from_bytes([0; EPOCH_LEN]) {
                Epoch::from_bytes([1; EPOCH_LEN])
            } else {
                Epoch::from_bytes([0; EPOCH_LEN])
            };
            // A valid candidate can expose a guard that accidentally admits a decision.
            let candidate = if volume == a() {
                &self.roots.c1
            } else {
                &self.roots.d1
            };
            self.timeline.push(Ev::EpochProbe {
                volume: volume.clone(),
            });
            match handle
                .submit(submission_at(wrong, &volume, 0xEE, candidate))
                .await
            {
                Answer::EpochMismatch { epoch: current, .. } if current == epoch => {
                    self.arm("epoch-mismatch");
                }
                Answer::Fenced | Answer::Stopped => return Err(Down),
                other => self.fail(format!(
                    "epoch probe for {} answered {other:?}",
                    volume.as_str()
                )),
            }
        }
        Ok(())
    }

    fn expect_landed(&self, name: &str, answer: &Answer, bytes: &[u8]) {
        match answer {
            Answer::Landed {
                receipt: Receipt { stored_id, .. },
                ..
            } if *stored_id == GrainId::of(bytes) => {}
            other => self.fail(format!("{name} settled as {other:?}")),
        }
    }

    async fn initialise(&self, handle: &AuthorityHandle, volume: &VolumeName) -> Result<(), Down> {
        let answer = handle.initialise(volume).await;
        let mut script = self.script.lock().unwrap();
        let earlier = script.created.get(volume).copied();
        match answer {
            Ok(Initialised::Created { epoch }) => {
                if let Some(earlier) = earlier {
                    script.fail(format!(
                        "{} created again under {epoch:?} after {earlier:?}",
                        volume.as_str()
                    ));
                }
                script.created.insert(volume.clone(), epoch);
            }
            Ok(Initialised::Kept { epoch }) => {
                if earlier.is_some_and(|earlier| earlier != epoch) {
                    script.fail(format!("{} kept under another epoch", volume.as_str()));
                }
                script.created.entry(volume.clone()).or_insert(epoch);
                script.arm("initialise-kept");
            }
            Err(InitialiseError::LogHasRecords) => {}
            Err(InitialiseError::Fenced | InitialiseError::Stopped) => return Err(Down),
            Err(other) => script.fail(format!("initialise {} answered {other:?}", volume.as_str())),
        }
        Ok(())
    }

    /// Submit until the answer is no longer `Accepted` or `Open`,
    /// removing `squatter` once the entry has been seen open a few times.
    async fn settle(
        &self,
        handle: &AuthorityHandle,
        volume: &VolumeName,
        operation: u8,
        candidate: &[u8],
        squatter: Option<(VolumeName, u64)>,
    ) -> Result<Answer, Down> {
        let sub = self.submission(volume, operation, candidate);
        let mut opens = 0;
        for _ in 0..SETTLE_LIMIT {
            match handle.submit(sub.clone()).await {
                Answer::Accepted { .. } | Answer::Open { .. } => {
                    opens += 1;
                    if opens >= OPENS_BEFORE_REMOVAL
                        && let Some((volume, seq)) = &squatter
                    {
                        self.remove_squatter(volume, *seq).await;
                    }
                    yield_once().await;
                }
                Answer::Fenced | Answer::Stopped => return Err(Down),
                other => return Ok(other),
            }
        }
        self.fail(format!("{} never settled", volume.as_str()));
        Err(Down)
    }

    /// Delete the junk at `(volume, seq)` if the hook planted it there and
    /// it is still there: an operator's repair of a wedge.
    async fn remove_squatter(&self, volume: &VolumeName, seq: u64) {
        let key = (volume.as_str().to_owned(), seq);
        if self.script.lock().unwrap().removed.contains(&key) {
            return;
        }
        let planted = self
            .hooks
            .lock()
            .unwrap()
            .plant_before_put
            .iter()
            .any(|(v, s, _, fired)| *v == key.0 && *s == seq && *fired);
        if !planted {
            return;
        }
        if let Ok(Some(bytes)) = self.oracle.get_root(volume.as_str(), seq).await
            && bytes == JUNK
        {
            let _ = self.admin.delete_root(volume, seq);
            self.script.lock().unwrap().removed.push(key);
            self.arm("squatter-removed");
        }
    }
}
