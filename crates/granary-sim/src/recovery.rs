// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Publication recovery with separate client, authority and store lifetimes.
//! Sync cuts model ordering and crash recovery, not physical power-loss durability.

mod oracle;
mod world;
use crate::{
    fakes::{Faults, Sim},
    scenario,
    secure_random::SeededSecureRandom,
};
use granary_client::{
    PublicationHandle, PublicationOutcome, PublicationResult, RecoveryDelay, RecoveryIntent,
    RecoveryParts, begin_publication, resume_publication,
};
use granary_core::{
    clock::Clock,
    retained_submission::Scope,
    root::{Timestamp, VolumeName},
};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use world::{Action, Journal, Transport, World};

/// Reproducible result, including every journal, authority and store event.
#[derive(Debug)]
pub struct RecoveryRun {
    pub seed: u64,
    pub events: Vec<String>,
    pub completion: granary_core::retained_submission::Completion,
}
impl RecoveryRun {
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "recovery seed {}\n{}\nwinner {} {}\n",
            self.seed,
            self.events.join("\n"),
            self.completion.seq,
            self.completion.id
        )
    }
}
/// A failing oracle or scenario names its replay seed and complete trace.
#[derive(Debug, Clone)]
pub struct RecoveryRunError {
    pub seed: u64,
    pub reason: String,
    pub events: Vec<String>,
}
impl std::fmt::Display for RecoveryRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "recovery seed {}: {}\n{}",
            self.seed,
            self.reason,
            self.events.join("\n")
        )
    }
}
impl std::error::Error for RecoveryRunError {}

struct ClockValue(i64);
impl Clock for ClockValue {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: self.0,
            nanos: 0,
        }
    }
}
struct Delay;
impl RecoveryDelay for Delay {
    fn jitter(&mut self, d: Duration) -> Duration {
        d
    }
    fn wait(&mut self, _d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(crate::sched::yield_once())
    }
}

/// Repeated client incarnations, lost replies and store writes surviving restarts.
/// Ordinary seed bits choose epoch-race winners, reply timing, probe failures,
/// delayed processing and persistence cuts. Reserved recovery seeds select
/// same-epoch foreign contention and exact replay. Every fair run must settle.
/// # Errors
/// Any safety or progress invariant violation; includes the seed and event trace.
pub fn recovery_run(seed: u64) -> Result<RecoveryRun, RecoveryRunError> {
    scenario::run(
        seed,
        Box::pin(async move {
            match schedule(seed) {
                Schedule::Epochs => run(seed).await,
                Schedule::AcceptedForeign => foreign_run(seed, true, false, None).await,
                Schedule::UndecidedForeign => foreign_run(seed, false, false, None).await,
            }
        }),
    )
}

enum Schedule {
    Epochs,
    AcceptedForeign,
    UndecidedForeign,
}
fn schedule(seed: u64) -> Schedule {
    match seed {
        26801 => Schedule::AcceptedForeign,
        26802 => Schedule::UndecidedForeign,
        _ => Schedule::Epochs,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixed regression schedule with all independent lifetime events visible"
)]
async fn run(seed: u64) -> Result<RecoveryRun, RecoveryRunError> {
    let sim = Sim::new();
    let manifest = scenario::seed_tree(&sim, scenario::ONE);
    let shared = Arc::new(Mutex::new(World::new(sim, seed)));
    let key = scenario::key();
    let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()])
        .map_err(|e| failure(&shared, e.to_string()))?;
    let scope = Scope {
        authority_base: b"https://sim-authority".to_vec(),
        pins: vec![],
        credential_context: b"writer".to_vec(),
    };
    let volume = VolumeName::new(scenario::VOLUME.to_owned())
        .map_err(|e| failure(&shared, e.to_string()))?;
    let mut journal = Journal::new(shared.clone());
    let transport = Transport {
        world: shared.clone(),
        store: lock(&shared).sim.node(1, Faults::none()),
    };
    let mut random = SeededSecureRandom::for_incarnation(seed, 0);
    let mut delay = Delay;
    lock(&shared).actions.push_back(if seed & 8 == 0 {
        Action::DecideAndLose
    } else {
        Action::QueueAndLose
    });
    let first = begin_publication(
        RecoveryParts {
            transport: &transport,
            journal: &mut journal,
            publisher_keys: &keys,
            signer: &key,
            secure: &mut random,
            clock: &ClockValue(1),
            delay: &mut delay,
        },
        scope,
        volume,
        manifest,
        granary_client::Policy::default(),
    )
    .await
    .map_err(|e| failure(&shared, e.to_string()))?;
    let handle = first.handle;
    transport.process_queued().await;
    let first_record = { lock(&shared).record() };
    let a = first_record
        .and_then(|r| r.candidates.first().cloned())
        .ok_or_else(|| failure(&shared, "missing A".into()))?;
    for epoch in 2..=3 {
        {
            let mut w = lock(&shared);
            w.reinitialise(epoch);
            w.crash();
            w.actions.push_back(Action::DecideAndLose);
        }
        random = SeededSecureRandom::for_incarnation(seed, epoch);
        journal = Journal::new(shared.clone());
        let out = resume_publication(
            RecoveryParts {
                transport: &transport,
                journal: &mut journal,
                publisher_keys: &keys,
                signer: &key,
                secure: &mut random,
                clock: &ClockValue(i64::from(epoch)),
                delay: &mut delay,
            },
            &handle,
            RecoveryIntent::Continue,
        )
        .await
        .map_err(|e| failure(&shared, e.to_string()))?;
        if out.outcome != PublicationOutcome::Pending {
            return Err(failure(&shared, format!("epoch {epoch}: {out:?}")));
        }
        if epoch == 2 {
            let w = lock(&shared);
            let r = w.record().ok_or_else(|| w.failure("missing B"))?;
            let b = r.candidates.last().ok_or_else(|| w.failure("missing B"))?;
            if a.id == b.id {
                return Err(w.failure("A and B are byte-identical"));
            }
        }
    }
    // A and B are now retired; C is an uncertain same-slot competitor.
    {
        let w = lock(&shared);
        let r = w
            .record()
            .ok_or_else(|| w.failure("no retired catalogue"))?;
        if r.candidates
            .iter()
            .filter(|c| c.role == granary_core::retained_submission::Role::Retired)
            .count()
            != 2
        {
            return Err(w.failure("both retirements must remain"));
        }
    }
    if seed & 4 != 0 {
        lock(&shared).fail_probe = true;
        invoke(
            &shared,
            &transport,
            &keys,
            &key,
            &handle,
            4,
            RecoveryIntent::Continue,
        )
        .await?;
        let before = lock(&shared).probe_calls;
        invoke(
            &shared,
            &transport,
            &keys,
            &key,
            &handle,
            5,
            RecoveryIntent::Continue,
        )
        .await?;
        if lock(&shared).probe_calls != before {
            return Err(failure(&shared, "unauthorized repeated probe".into()));
        }
        lock(&shared).fail_probe = false;
    }
    if seed & 16 != 0 {
        // Discoverable full-generation cut, independently crash before settling.
        {
            let mut w = lock(&shared);
            w.fail_cut = Some((
                w.replacements + 2,
                usize::try_from((seed / 32) % 5).unwrap_or(0),
            ));
        }
        let _ = invoke(
            &shared,
            &transport,
            &keys,
            &key,
            &handle,
            6,
            RecoveryIntent::ExplicitRecovery,
        )
        .await;
        {
            let mut w = lock(&shared);
            w.fail_cut = None;
            w.crash();
        }
    }
    let foreign = seed & 2 != 0 && seed != 19307;
    let expected = {
        let w = lock(&shared);
        let record = w.record().ok_or_else(|| w.failure("no final catalogue"))?;
        record
            .candidates
            .get(usize::from(seed & 1 == 0))
            .map(|c| c.id)
    };
    if foreign {
        use granary_core::rootstore::RootStore as _;
        let source = { lock(&shared).sim.oracle() };
        let prepared = granary_client::prepare_from_manifest(
            &source,
            &source,
            manifest,
            granary_client::HarvestStats::default(),
            &scenario::volume(),
            &key,
            &scenario::identity(99),
            scenario::now(),
            granary_client::Policy::default(),
        )
        .await
        .map_err(|e| failure(&shared, e.to_string()))?;
        source
            .put_root(scenario::VOLUME, 1, prepared.root_bytes)
            .await
            .map_err(|e| failure(&shared, e.to_string()))?;
        lock(&shared).event("foreign root at retired slot".into());
    } else {
        transport.release(usize::from(seed & 1 == 0)).await?;
    }
    transport.release_all().await?;
    if foreign {
        let rebased = invoke(
            &shared,
            &transport,
            &keys,
            &key,
            &handle,
            7,
            RecoveryIntent::ExplicitRecovery,
        )
        .await?;
        if rebased.outcome != PublicationOutcome::Pending {
            return Err(failure(&shared, "foreign occupancy did not rebase".into()));
        }
        transport.release_all().await?;
    }
    let done = invoke(
        &shared,
        &transport,
        &keys,
        &key,
        &handle,
        8,
        RecoveryIntent::ExplicitRecovery,
    )
    .await?;
    let PublicationOutcome::Landed(completion) = done.outcome else {
        return Err(failure(
            &shared,
            format!("fair settling run did not complete: {done:?}"),
        ));
    };
    if (!foreign && Some(completion.id) != expected) || (foreign && completion.seq != 2) {
        return Err(failure(&shared, "wrong winning candidate".into()));
    }
    let before = lock(&shared).send_calls;
    let again = invoke(
        &shared,
        &transport,
        &keys,
        &key,
        &handle,
        9,
        RecoveryIntent::Continue,
    )
    .await?;
    if again.outcome != PublicationOutcome::Landed(completion.clone())
        || lock(&shared).send_calls != before
    {
        return Err(failure(&shared, "completion is not terminal".into()));
    }
    let w = lock(&shared);
    if !w.violations.is_empty() {
        return Err(RecoveryRunError {
            seed,
            reason: w.violations.join("; "),
            events: w.events.clone(),
        });
    }
    Ok(RecoveryRun {
        seed,
        events: w.events.clone(),
        completion,
    })
}
/// Same-epoch contention with independently dropped replies and delayed processing.
#[expect(
    clippy::too_many_lines,
    reason = "one contention schedule keeps the crash cuts and independent lifetime events visible"
)]
async fn foreign_run(
    seed: u64,
    accepted: bool,
    before: bool,
    cut: Option<usize>,
) -> Result<RecoveryRun, RecoveryRunError> {
    let sim = Sim::new();
    let manifest = scenario::seed_tree(&sim, scenario::ONE);
    let shared = Arc::new(Mutex::new(World::new(sim, seed)));
    let key = scenario::key();
    let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()])
        .map_err(|e| failure(&shared, e.to_string()))?;
    let transport = Transport {
        world: shared.clone(),
        store: lock(&shared).sim.node(1, Faults::none()),
    };
    let mut journal = Journal::new(shared.clone());
    let mut random = SeededSecureRandom::for_incarnation(seed, 0);
    let mut delay = Delay;
    lock(&shared).actions.push_back(if before {
        Action::QueueAndLose
    } else if accepted {
        Action::AcceptedContestAndLose
    } else {
        Action::QueuedForeignAndLose
    });
    let first = begin_publication(
        RecoveryParts {
            transport: &transport,
            journal: &mut journal,
            publisher_keys: &keys,
            signer: &key,
            secure: &mut random,
            clock: &ClockValue(1),
            delay: &mut delay,
        },
        Scope {
            authority_base: b"https://sim-authority".to_vec(),
            pins: vec![],
            credential_context: b"writer".to_vec(),
        },
        scenario::volume(),
        manifest,
        granary_client::Policy::default(),
    )
    .await
    .map_err(|e| failure(&shared, e.to_string()))?;
    if first.outcome != PublicationOutcome::Pending {
        return Err(failure(
            &shared,
            "first fault did not retain uncertainty".into(),
        ));
    }
    let initial_record = { lock(&shared).record() };
    let initial = initial_record.ok_or_else(|| failure(&shared, "no initial record".into()))?;
    let original = initial
        .candidates
        .first()
        .cloned()
        .ok_or_else(|| failure(&shared, "no original candidate".into()))?;
    if before {
        transport.process_queued().await;
        transport.foreign_current()?;
        lock(&shared).defer_classification = true;
        let out = invoke(
            &shared,
            &transport,
            &keys,
            &key,
            &first.handle,
            1,
            RecoveryIntent::Continue,
        )
        .await?;
        let w = lock(&shared);
        if out.outcome != PublicationOutcome::Pending
            || w.send_calls != 2
            || w.record()
                .is_none_or(|r| !r.candidates.iter().any(|c| c.id == original.id))
        {
            return Err(w.failure("before-retry decision was released instead of stopping open"));
        }
        drop(w);
        lock(&shared).event("before-retry duplicate rule 3 open retained".into());
        lock(&shared).defer_classification = false;
    }
    if let Some(stage) = cut {
        let mut w = lock(&shared);
        // load, probe start/end, attempt, answer: interrupt the release save.
        w.fail_cut = Some((w.replacements + 5, stage));
    }
    let replay = invoke(
        &shared,
        &transport,
        &keys,
        &key,
        &first.handle,
        2,
        RecoveryIntent::Continue,
    )
    .await;
    if cut.is_some() {
        if replay.is_ok() {
            return Err(failure(&shared, "release cut did not fire".into()));
        }
        {
            let mut w = lock(&shared);
            w.fail_cut = None;
            w.crash();
        }
        invoke(
            &shared,
            &transport,
            &keys,
            &key,
            &first.handle,
            3,
            RecoveryIntent::ExplicitRecovery,
        )
        .await?;
    } else {
        replay?;
    }
    {
        let mut w = lock(&shared);
        let r = w
            .record()
            .ok_or_else(|| w.failure("missing replay record"))?;
        if r.candidates.iter().any(|c| c.id == original.id) || r.current != initial.current {
            return Err(w.failure("exact replay did not release under the original identity"));
        }
        w.event(if accepted || before {
            "accepted foreign exact replay lost released".into()
        } else {
            "undecided foreign exact retry forward-stale released".into()
        });
    }
    if accepted || before {
        transport.replay_lost(&initial)?;
    }
    transport.process_queued().await;
    transport.release_all().await?;
    let done = invoke(
        &shared,
        &transport,
        &keys,
        &key,
        &first.handle,
        4,
        RecoveryIntent::ExplicitRecovery,
    )
    .await?;
    let PublicationOutcome::Landed(completion) = done.outcome else {
        return Err(failure(&shared, "fair foreign run did not land".into()));
    };
    if completion.seq != 2 {
        return Err(failure(&shared, "foreign run landed at wrong slot".into()));
    }
    let before_sends = lock(&shared).send_calls;
    let again = invoke(
        &shared,
        &transport,
        &keys,
        &key,
        &first.handle,
        5,
        RecoveryIntent::Continue,
    )
    .await?;
    if again.outcome != PublicationOutcome::Landed(completion.clone())
        || lock(&shared).send_calls != before_sends
    {
        return Err(failure(&shared, "foreign completion not terminal".into()));
    }
    let w = lock(&shared);
    if !w.violations.is_empty() {
        return Err(w.failure(&w.violations.join("; ")));
    }
    Ok(RecoveryRun {
        seed,
        events: w.events.clone(),
        completion,
    })
}

async fn invoke(
    shared: &Arc<Mutex<World>>,
    transport: &Transport,
    keys: &granary_store::crypto::TrustedKeys,
    key: &granary_store::crypto::SigningKey,
    handle: &PublicationHandle,
    incarnation: u32,
    intent: RecoveryIntent,
) -> Result<PublicationResult, RecoveryRunError> {
    let mut j = Journal::new(shared.clone());
    let mut random = SeededSecureRandom::for_incarnation(lock(shared).seed, incarnation);
    let mut delay = Delay;
    {
        let mut w = lock(shared);
        w.explicit = intent == RecoveryIntent::ExplicitRecovery;
        w.event(format!("invoke {incarnation} {intent:?}"));
    }
    resume_publication(
        RecoveryParts {
            transport,
            journal: &mut j,
            publisher_keys: keys,
            signer: key,
            secure: &mut random,
            clock: &ClockValue(i64::from(incarnation)),
            delay: &mut delay,
        },
        handle,
        intent,
    )
    .await
    .map_err(|e| failure(shared, e.to_string()))
}
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn failure(shared: &Mutex<World>, reason: String) -> RecoveryRunError {
    let w = lock(shared);
    RecoveryRunError {
        seed: w.seed,
        reason,
        events: w.events.clone(),
    }
}

#[cfg(test)]
mod tests;
