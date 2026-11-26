// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The epoch and the cryptographic-randomness seam (spec §6.3): an epoch
//! is drawn from that seam and never from the `Rng` seam, all sixteen of
//! its bytes are the draw, only initialise's creation of a missing log
//! draws, and a failed draw refuses that creation and nothing else.

use std::sync::atomic::{AtomicUsize, Ordering};

use granary_core::secure_random::EntropyUnavailable;

use super::*;

/// The engine's parts over `log`, its jitter seeded with `rng_seed` and
/// its cryptographic randomness from `secure_random`.
fn parts_drawing<E>(
    log: &Arc<SimDecisionLog>,
    rng_seed: u64,
    secure_random: E,
) -> AuthorityParts<SharedLog, TestStore, FixedClock, SimRng, E, YieldPause> {
    AuthorityParts {
        admission: crate::Admission::chain_fixture(),
        log: SharedLog(Arc::clone(log)),
        store: TestStore::dead(),
        clock: FixedClock,
        rng: rng(rng_seed),
        secure_random,
        pause: YieldPause,
    }
}

/// Start an engine over `volumes` drawing from `secure_random`.
fn start_drawing<E: SecureRandom + Send + 'static>(
    log: &Arc<SimDecisionLog>,
    volumes: &[VolumeName],
    secure_random: E,
) -> (AuthorityHandle, DriverOn<FixedClock, E>) {
    let parts = parts_drawing(log, 1, secure_random);
    let volumes = configs(volumes);
    block(async move { start(parts, boot(1), volumes).await }).unwrap()
}

/// The envelope at `volume`'s name: its epoch and its record count.
fn envelope_at(log: &Arc<SimDecisionLog>, volume: &VolumeName) -> (Epoch, usize) {
    let bytes = read_log(log, volume).unwrap();
    let Classified::Log {
        envelope, records, ..
    } = classify(&bytes, volume).unwrap()
    else {
        panic!("an envelope was written");
    };
    (envelope.epoch(), records.len())
}

/// Hands out a fixed sixteen bytes.
struct Known([u8; EPOCH_LEN]);

impl SecureRandom for Known {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        for (slot, byte) in dest.iter_mut().zip(self.0) {
            *slot = byte;
        }
        Ok(())
    }
}

/// Always fails, after writing `written` bytes of 0xEE (a partial fill),
/// and counts its calls.
struct Failing {
    written: usize,
    calls: Arc<AtomicUsize>,
}

impl Failing {
    fn new(written: usize) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                written,
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

impl SecureRandom for Failing {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        for slot in dest.iter_mut().take(self.written) {
            *slot = 0xEE;
        }
        Err(EntropyUnavailable)
    }
}

/// **The epoch comes from the cryptographic-randomness seam, never the
/// `Rng` seam.** Three runs: the same `Rng` seed with two stream seeds,
/// and another `Rng` seed with the first stream seed. The epoch follows
/// the stream and ignores the `Rng`: an epoch drawn from the `Rng` would
/// repeat across the first two runs (a repeated process seed repeating an
/// epoch after log loss) and move in the third.
#[test]
fn the_epoch_follows_the_secure_stream_and_ignores_the_rng() {
    let epoch_of = |rng_seed: u64, secure_seed: u64| {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        let parts = parts_drawing(&log, rng_seed, secure(secure_seed));
        let (handle, driver) =
            block(async move { start(parts, boot(1), configs(&[a()])).await }).unwrap();
        let (end, answer) = run_beside(0, driver, async move {
            let answer = handle.initialise(&a()).await;
            handle.stop().await;
            answer
        });
        assert_eq!((end, log.violations()), (RunEnd::Stopped, vec![]));
        let Ok(Initialised::Created { epoch }) = answer else {
            panic!("a missing log is created: {answer:?}");
        };
        assert_eq!(envelope_at(&log, &a()), (epoch, 0));
        epoch
    };
    assert_eq!(
        (epoch_of(5, 5), epoch_of(5, 6), epoch_of(6, 5)),
        (first_epoch(5), first_epoch(6), first_epoch(5))
    );
    assert_ne!(first_epoch(5), first_epoch(6));
}

/// **All sixteen bytes.** A source that hands out known bytes yields
/// exactly those bytes as the epoch the answer reports and the created
/// envelope carries: a draw truncated, masked, or mixed with anything
/// else fails here.
#[test]
fn the_created_envelope_carries_exactly_the_drawn_bytes() {
    let drawn: [u8; EPOCH_LEN] = std::array::from_fn(|i| 0xA0 ^ u8::try_from(i).unwrap());
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (handle, driver) = start_drawing(&log, &[a()], Known(drawn));
    let (end, answer) = run_beside(0, driver, async move {
        let answer = handle.initialise(&a()).await;
        handle.stop().await;
        answer
    });
    let epoch = Epoch::from_bytes(drawn);
    assert_eq!(
        (end, answer, envelope_at(&log, &a())),
        (
            RunEnd::Stopped,
            Ok(Initialised::Created { epoch }),
            (epoch, 0)
        )
    );
}

/// **A failed draw refuses creation, and only creation.** Before any byte
/// is written and after a partial fill alike, initialise of a missing log
/// answers the typed refusal: no `initialise` log call, nothing at the
/// log's name, no fence, and no state installed (a second initialise
/// draws again and refuses again, rather than finding a log). The engine
/// then stops cleanly.
#[test]
fn a_failed_draw_refuses_the_creation_and_fences_nothing() {
    for written in [0, 8] {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        let (failing, draws) = Failing::new(written);
        let (handle, driver) = start_drawing(&log, &[a()], failing);
        let (end, (answers, fence)) = run_beside(0, driver, async move {
            let before = handle.volume_view(&a());
            let answers = [handle.initialise(&a()).await, handle.initialise(&a()).await];
            assert_eq!(
                handle.volume_view(&a()),
                before,
                "failed initialise changed the observation"
            );
            let fence = handle.fence();
            handle.stop().await;
            (answers, fence)
        });
        let refused = Err(InitialiseError::EntropyUnavailable);
        assert_eq!(
            (
                answers,
                fence,
                end,
                draws.load(Ordering::SeqCst),
                calls(&sim, "initialise").len(),
                read_log(&log, &a()),
                marker_says(&log),
                log.violations(),
            ),
            (
                [refused.clone(), refused],
                None,
                RunEnd::Stopped,
                2,
                0,
                None,
                Some(RunMarker::Clean),
                vec![],
            ),
            "after a fill that wrote {written} bytes"
        );
    }
}

/// **Recovery, an envelope-only log and every refusing initialise make
/// no draw.** Against a source that always fails: A holds committed
/// records and B only an envelope at the start, so the start recovers
/// both; initialise then keeps B's epoch and refuses A as before, and C
/// and D, whose names gain a file with no envelope and another volume's
/// log behind the engine's back, keep their refusals too. The source is
/// never called.
#[test]
fn recovery_keeping_and_refusals_make_no_draw() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (env_a, records_a) = landed_log(&a());
    seed(&log, &a(), log_bytes(&env_a, &records_a));
    let env_b = envelope(&b(), 0x0B);
    seed(&log, &b(), log_bytes(&env_b, &[]));
    seed_marker(&log, &RunMarker::Clean);
    let d = vol("vol-d");
    let (failing, draws) = Failing::new(0);
    let (handle, driver) = start_drawing(&log, &[a(), b(), c(), d.clone()], failing);
    let started_draws = draws.load(Ordering::SeqCst);

    let (other_env, other_records) = landed_log(&vol("vol-z"));
    let planted = log_bytes(&other_env, &other_records);
    let client_log = Arc::clone(&log);
    let (end, answers) = run_beside(0, driver, async move {
        client_log.seed_bytes(&c(), b"junk".to_vec()).await;
        client_log.seed_bytes(&d, planted).await;
        let answers = vec![
            handle.initialise(&a()).await,
            handle.initialise(&b()).await,
            handle.initialise(&c()).await,
            handle.initialise(&d).await,
        ];
        handle.stop().await;
        answers
    });
    assert_eq!(
        (
            started_draws,
            draws.load(Ordering::SeqCst),
            end,
            answers.first().cloned(),
            answers.get(1).cloned(),
            answers.get(2).cloned(),
            calls(&sim, "initialise").len(),
            log.violations(),
        ),
        (
            0,
            0,
            RunEnd::Stopped,
            Some(Err(InitialiseError::LogHasRecords)),
            Some(Ok(Initialised::Kept {
                epoch: env_b.epoch()
            })),
            Some(Err(InitialiseError::NoEnvelope)),
            0,
            vec![],
        )
    );
    assert!(
        matches!(answers.get(3), Some(Err(InitialiseError::Damaged(_)))),
        "{answers:?}"
    );
}

/// **An unreadable log name keeps its refusal, and draws nothing.** The
/// read of A's name fails; initialise answers `Unreadable` against a
/// source that always fails, and never calls it.
#[test]
fn an_unreadable_name_refuses_as_before_and_makes_no_draw() {
    let dry = Sim::new();
    let dry_log = sim_log(&dry, LogFaults::none());
    start_on(&dry_log, boot(1), &[a()]).unwrap();
    // The worker's first log step after the start is its removal of A's
    // temporary; its read of A is the second.
    let read_step = dry_log.steps() + 1;
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: read_step }));
    let (failing, draws) = Failing::new(0);
    let (handle, driver) = start_drawing(&log, &[a()], failing);
    let (end, answer) = run_beside(0, driver, async move {
        let answer = handle.initialise(&a()).await;
        handle.stop().await;
        answer
    });
    assert!(
        matches!(answer, Err(InitialiseError::Unreadable(_))),
        "{answer:?}"
    );
    assert_eq!(
        (draws.load(Ordering::SeqCst), end, log.violations()),
        (0, RunEnd::Stopped, vec![])
    );
}
