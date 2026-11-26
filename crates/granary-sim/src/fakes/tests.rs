// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the simulated world (`Sim`) — one type implementing
//! `RootStore`, `BinStore` and `GrainSource` over `BTreeMap`s, plus the
//! fault schedule the scenarios inject through it.
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

use super::*;
use crate::sched::{Scheduler, Task};
use crate::trace::Entry;
// The fixture is HOISTED into the lib rather than kept private here:
// the scenarios and the scenario-runner binary drive the same tree,
// key, identity, clock and driver these tests do, and a second copy
// of a driver diverges exactly where it matters (see
// [`crate::scenario`]'s module doc).
use crate::scenario::{
    ONE, Published, TWO, VOLUME as VOL, publish_on, publish_with, resolve, resolve_collecting, run,
    seed_tree,
};
use granary_client::Policy;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Poll a seam operation by hand and assert it suspends EXACTLY once.
///
/// The direct form of the property the whole harness rests on: a
/// `Ready` first poll is the ready-shaped fake, and a second
/// `Pending` would mean the operation suspends more than once, which
/// would make an operation index cover two scheduling points.
fn pends_once<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        fut.as_mut().poll(&mut cx).is_pending(),
        "the operation did not suspend — a ready-shaped fake makes interleaving impossible"
    );
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the operation suspended more than once"),
    }
}

/// A bin and its digest, as a real caller would pair them.
fn a_bin() -> ([u8; DIGEST_LEN], Vec<u8>) {
    let bytes: Vec<u8> = (0..100u8).collect();
    (*GrainId::of(&bytes).digest(), bytes)
}

// ------------------------------------------------- the closure

/// The structural closure for the accept-set divergence class: the
/// same suite body runs against granary-core's in-crate fake, the
/// production granary-store adapter, and this one. A rule that holds
/// in the sim and not in production cannot pass all three.
#[test]
fn the_fake_passes_binstore_conformance_with_faults_disabled() {
    let sim = Sim::new();
    let store = sim.node(0, Faults::none());
    assert!(store.faults.is_empty(), "conformance runs fault-free");
    let task: Task<()> =
        Box::pin(async move { granary_core::testkit::binstore_conformance(&store).await });
    let () = run(1, task);
    assert!(
        !sim.trace().is_empty(),
        "a conformance run that recorded nothing would be a vacuous pass"
    );
}

/// The same closure for the seam every CAS scenario actually rides
/// on. The crash sweep, the re-run convergence, the concurrent
/// publishers and the ambiguous PUT whose probe fails are all
/// `put_root`/`get_root`/`max_seq` properties — so a `RootStore` that
/// diverges from the production adapter makes those scenarios prove
/// something about this fake instead of about granary.
#[test]
fn the_fake_passes_rootstore_conformance_with_faults_disabled() {
    let sim = Sim::new();
    let store = sim.node(0, Faults::none());
    assert!(store.faults.is_empty(), "conformance runs fault-free");
    let task: Task<()> =
        Box::pin(async move { granary_core::testkit::rootstore_conformance(&store).await });
    let () = run(1, task);
    assert!(
        !sim.trace().is_empty(),
        "a conformance run that recorded nothing would be a vacuous pass"
    );
}

// ------------------------------------------------- suspension

/// Declare the remote-seam operation kinds AND the list of them from
/// one set of names, so the list cannot fall behind the enum. That
/// is the whole reason for the macro: a hand-written `ALL` beside a
/// hand-written enum is two lists, and the coverage check below is
/// only as strong as the weaker one.
macro_rules! remote_ops {
    ($($kind:ident),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum RemoteOp { $($kind),+ }

        impl RemoteOp {
            const ALL: &[RemoteOp] = &[$(RemoteOp::$kind),+];
        }
    };
}

remote_ops!(
    PutBin,
    GetBinRange,
    PutMeta,
    GetMeta,
    MaxSeq,
    PutRoot,
    GetRoot,
    WriteHint,
    ReadHint,
);

/// Which remote-seam operation an artifact entry is, or `None` for
/// the synchronous local seam.
///
/// **The match has NO wildcard arm, and that is the load-bearing
/// part.** Every store operation must record an [`Op`] (module doc,
/// rule 1), so a new seam method brings a new `Op` variant, and a new
/// `Op` variant stops this function compiling until it is either
/// mapped to a `RemoteOp` — which does not exist until it is added to
/// `remote_ops!` above, which grows `ALL`, which fails the coverage
/// assertion until the method is actually driven — or declared local
/// in the arm below.
fn remote_op(op: &Op) -> Option<RemoteOp> {
    match op {
        Op::PutBin { .. } => Some(RemoteOp::PutBin),
        Op::GetBinRange { .. } => Some(RemoteOp::GetBinRange),
        Op::PutMeta { .. } => Some(RemoteOp::PutMeta),
        Op::GetMeta { .. } => Some(RemoteOp::GetMeta),
        Op::MaxSeq { .. } => Some(RemoteOp::MaxSeq),
        Op::PutRoot { .. } => Some(RemoteOp::PutRoot),
        Op::GetRoot { .. } => Some(RemoteOp::GetRoot),
        Op::WriteHint { .. } => Some(RemoteOp::WriteHint),
        Op::ReadHint { .. } => Some(RemoteOp::ReadHint),
        // The one seam with no future to suspend, by construction —
        // and, not seam methods at all, the store applying an earlier
        // `put_root` and the out-of-band admin handle. The decision log
        // is another seam, whose steps' suspension
        // `crate::decision_log`'s own tests assert.
        Op::GetGrain { .. }
        | Op::HasGrain { .. }
        | Op::ReleaseRoot { .. }
        | Op::AdminPlantRoot { .. }
        | Op::AdminDeleteRoot { .. }
        | Op::AdminListRoots { .. }
        | Op::Log(_) => None,
    }
}

/// The anti-vacuity proof. granary-core's own fakes are ready-shaped —
/// their shared harness asserts `the fake future never pends` — and a
/// fake written that way here would make two publishers unable to
/// interleave however the scheduler was written, so every
/// concurrency scenario built on it would pass without a race ever
/// happening.
///
/// The list of operations below is written out BY HAND, and the
/// coverage check at the end is what stops that hand-written list
/// silently going stale: a seam method added without a line here
/// would ship un-asserted, which is a real hole in a test whose
/// whole claim is the word EVERY. What closes it is the chain
/// through [`remote_op`] — new method → new [`Op`] variant → that
/// match stops compiling → a new `RemoteOp` in `remote_ops!` → a
/// longer `ALL` → this test fails naming the operation nobody drove.
///
/// **The one gap, stated rather than papered over:** the chain
/// starts at "every operation records an `Op`". A seam method that
/// traced nothing, or that reused an existing variant, would slip
/// past — but it would already be violating the module doc's first
/// rule, and an operation nothing recorded is invisible to the
/// cross-process replay check as well.
#[test]
fn every_store_operation_suspends_exactly_once() {
    let sim = Sim::new();
    let store = sim.node(0, Faults::none());
    let (digest, bin) = a_bin();
    let meta = b"a meta object".to_vec();
    let id = GrainId::of(&meta);

    assert_eq!(pends_once(store.put_bin(&digest, bin)), Ok(true));
    assert_eq!(
        pends_once(store.get_bin_range(&digest, 0, 4)),
        Ok(vec![0, 1, 2, 3])
    );
    assert_eq!(pends_once(store.put_meta(VOL, &id, meta.clone())), Ok(true));
    assert_eq!(pends_once(store.get_meta(VOL, &id)), Ok(meta));
    assert_eq!(pends_once(store.max_seq(VOL)), Ok(None));
    assert_eq!(
        pends_once(store.put_root(VOL, 1, b"a root".to_vec())),
        Ok(())
    );
    assert_eq!(
        pends_once(store.get_root(VOL, 1)),
        Ok(Some(b"a root".to_vec()))
    );
    assert_eq!(pends_once(store.write_hint(VOL, 1)), Ok(()));
    assert!(matches!(
        pends_once(store.read_hint(VOL, None)),
        Ok(HintRead::Current { seq: 1, .. })
    ));
    assert_eq!(store.store_ops(), 9, "nine store operations, nine indices");

    // Every remote operation the artifact's vocabulary knows about
    // was driven above — see this test's doc for why the coverage is
    // taken from the trace rather than trusted to the list.
    let driven: Vec<RemoteOp> = sim
        .trace()
        .entries()
        .iter()
        .filter_map(|e| remote_op(&e.op))
        .collect();
    for kind in RemoteOp::ALL {
        assert!(
            driven.contains(kind),
            "{kind:?} was never driven through pends_once: a seam operation that suspends \
             twice, or not at all, would ship un-asserted"
        );
    }
}

/// The one seam that cannot suspend, stated as a test rather than
/// left as a surprise: [`GrainSource`] is synchronous, so its
/// operations trace and honour a crash but have no await point to
/// offer — and they are not part of the fault index space, because
/// the crash model is about the REMOTE store.
#[test]
fn the_local_seam_is_traced_although_a_sync_seam_cannot_suspend() {
    let sim = Sim::new();
    let store = sim.node(0, Faults::none());
    let id = sim.put_grain(b"a grain".to_vec());
    assert!(store.has(&id));
    assert_eq!(store.get(&id), Ok(b"a grain".to_vec()));
    let rendered = sim.trace().render();
    assert!(rendered.contains("has-grain"), "{rendered}");
    assert!(rendered.contains("get-grain"), "{rendered}");
    assert_eq!(store.store_ops(), 0, "local reads are traced, not indexed");
}

// ------------------------------------------------- the contract

/// `checked_volume` is a CONTRACT obligation on every implementation
/// — every volume-taking method, not just the ones a scenario
/// happens to call.
#[test]
fn an_invalid_volume_is_refused_by_every_volume_taking_method() {
    let sim = Sim::new();
    let store = sim.node(0, Faults::none());
    let id = GrainId::of(b"m");
    for bad in ["a/b", "a//b", "a/b/", "", "-a", "Vol"] {
        let refused = |what: &str, got: bool| {
            assert!(got, "{what} accepted the invalid volume {bad:?}");
        };
        refused(
            "put_root",
            matches!(
                pends_once(store.put_root(bad, 1, vec![1])),
                Err(RootStoreError::InvalidVolume { .. })
            ),
        );
        refused(
            "get_root",
            matches!(
                pends_once(store.get_root(bad, 1)),
                Err(RootStoreError::InvalidVolume { .. })
            ),
        );
        refused(
            "read_hint",
            matches!(
                pends_once(store.read_hint(bad, None)),
                Err(RootStoreError::InvalidVolume { .. })
            ),
        );
        refused(
            "write_hint",
            matches!(
                pends_once(store.write_hint(bad, 1)),
                Err(RootStoreError::InvalidVolume { .. })
            ),
        );
        refused(
            "max_seq",
            matches!(
                pends_once(store.max_seq(bad)),
                Err(RootStoreError::InvalidVolume { .. })
            ),
        );
        refused(
            "put_meta",
            matches!(
                pends_once(store.put_meta(bad, &id, vec![1])),
                Err(RootStoreError::InvalidVolume { .. })
            ),
        );
        refused(
            "get_meta",
            matches!(
                pends_once(store.get_meta(bad, &id)),
                Err(RootStoreError::InvalidVolume { .. })
            ),
        );
    }
    // The refusal is RECORDED, under the unforgeable sentinel — an
    // operation that vanished from the artifact is a step of the run
    // the replay check cannot see.
    let rendered = sim.trace().render();
    assert!(rendered.contains("vol=-rejected-"), "{rendered}");
    assert!(rendered.contains("failed(invalid-volume)"), "{rendered}");
}

/// What the sim's [`Volume`] and `granary_core::root::VolumeName`
/// must agree about.
///
/// `Volume::new` delegates validation to `VolumeName`, so
/// acceptance is checked here to pin that delegation. What a
/// wrapper can still get wrong is everything AFTER the check, and
/// that is the rest of this test: an accepted name must reach the
/// artifact byte for byte (a normalizing or truncating copy would
/// render two distinct volumes alike, which is rule 5), it must
/// never collide with the unforgeable sentinel, and the two
/// construction paths — validating and already-validated — must
/// produce the same value, which is what lets `checked_volume` hand
/// a name to `Volume::from_checked` with no fallback.
#[test]
fn the_sim_volume_alphabet_agrees_with_granary_core() {
    let long = "a".repeat(63);
    let too_long = "a".repeat(64);
    let names = [
        "demo",
        "d",
        "0",
        "vol-1",
        "a-b-c",
        "9-9",
        "",
        "DEMO",
        "demo.example",
        "demo_1",
        "-demo",
        "demo-",
        "a b",
        "demo\nx",
        "vol=x",
        "a/b",
        Volume::REJECTED,
        long.as_str(),
        too_long.as_str(),
    ];
    for name in names {
        let checked = VolumeName::from_bytes(name.as_bytes());
        let vol = Volume::new(name);
        assert_eq!(
            vol.is_some(),
            checked.is_ok(),
            "the sim and granary-core disagree about {name:?}"
        );
        if let (Some(vol), Ok(checked)) = (vol, checked) {
            assert_eq!(
                vol.as_str(),
                name,
                "an accepted name must reach the artifact unchanged"
            );
            assert!(
                !vol.is_rejected(),
                "an accepted name must not collide with the sentinel: {name:?}"
            );
            assert_eq!(
                vol,
                Volume::from_checked(&checked),
                "the two construction paths disagree about {name:?}"
            );
        }
    }
}

// ------------------------------------------------- the fault set

#[test]
fn fail_refuses_the_operation_and_nothing_lands() {
    let sim = Sim::new();
    let store = sim.node(0, Faults::just(Fault::Fail(0)));
    assert!(pends_once(store.put_root(VOL, 1, b"a root".to_vec())).is_err());
    assert_eq!(
        pends_once(store.get_root(VOL, 1)),
        Ok(None),
        "a refused put must leave nothing behind"
    );
}

/// The distinction from [`Fault::Fail`] is the whole reason this
/// variant exists, and it is NOT visible in the error: both report
/// failure, and the artifact renders both as `failed(injected)`. It
/// is visible only in the STORE, which is what this asserts — two
/// worlds, identical but for the injection, read back through a
/// fault-free handle.
#[test]
fn land_but_report_failure_applies_the_write_and_still_errors() {
    let bytes = b"a root that landed anyway".to_vec();

    let landing = Sim::new();
    let a = landing.node(0, Faults::just(Fault::LandButReportFailure(0)));
    assert!(pends_once(a.put_root(VOL, 1, bytes.clone())).is_err());

    let refusing = Sim::new();
    let b = refusing.node(0, Faults::just(Fault::Fail(0)));
    assert!(pends_once(b.put_root(VOL, 1, bytes.clone())).is_err());

    let reader = landing.node(1, Faults::none());
    assert_eq!(
        pends_once(reader.get_root(VOL, 1)),
        Ok(Some(bytes)),
        "LandButReportFailure must leave the root at the seq"
    );
    let other = refusing.node(1, Faults::none());
    assert_eq!(
        pends_once(other.get_root(VOL, 1)),
        Ok(None),
        "Fail must leave nothing — otherwise the two faults are one fault"
    );
}

/// The probe is `commit`'s one read-back after a failed `put_root`.
/// Failing it reaches the arm that returns
/// `PublishError::ProbeUnresolved`, carrying both the put's own
/// error and the probe's — and the scoping matters as much as the
/// failure: a `get_root` before any `put_root` failure is the
/// HEAD read, and failing that would stop a publish before it ever
/// reached commit.
#[test]
fn fail_probe_fails_the_get_root_that_follows_a_failed_put_root() {
    let sim = Sim::new();
    let store = sim.node(
        0,
        Faults::none().with(Fault::Fail(0)).with(Fault::FailProbe),
    );
    assert_eq!(
        pends_once(store.put_root(VOL, 1, b"r".to_vec())),
        Err(injected()),
        "the put_root's own injected failure"
    );
    assert_eq!(
        pends_once(store.get_root(VOL, 1)),
        Err(injected_probe()),
        "the probe after a failed put_root must fail too — and with its OWN message, or \
         `commit`'s promise to carry both the put's error and the probe's own is \
         unassertable"
    );

    let untouched = sim.node(1, Faults::just(Fault::FailProbe));
    assert_eq!(
        pends_once(untouched.get_root(VOL, 1)),
        Ok(None),
        "a get_root before any put_root failure is the head read, not the probe"
    );
}

#[test]
fn crash_at_refuses_that_operation_and_every_one_after_it() {
    let sim = Sim::new();
    let grain = sim.put_grain(b"a local object".to_vec());
    let (digest, bin) = a_bin();
    let store = sim.node(0, Faults::just(Fault::CrashAt(1)));

    assert_eq!(pends_once(store.put_bin(&digest, bin.clone())), Ok(true));
    assert!(!store.crashed());
    assert!(pends_once(store.put_root(VOL, 1, b"r".to_vec())).is_err());
    assert!(store.crashed(), "the crash point poisons the node");
    assert!(
        pends_once(store.write_hint(VOL, 1)).is_err(),
        "everything after the crash point is refused too"
    );
    assert!(
        store.get(&grain).is_err(),
        "a dead node does not read its local store either"
    );

    let reader = sim.node(1, Faults::none());
    assert_eq!(pends_once(reader.get_root(VOL, 1)), Ok(None));
    assert!(
        matches!(
            pends_once(reader.read_hint(VOL, None)),
            Ok(HintRead::Missing)
        ),
        "the hint write was after the crash point"
    );
    assert_eq!(
        pends_once(reader.get_bin_range(&digest, 0, 100)),
        Ok(bin),
        "what landed BEFORE the crash point survives it"
    );
}

/// [`Fault::FailFrom`]: ordinary before the threshold, refused at and
/// past it — the "the transport just went down and stays down" shape,
/// distinct from [`Fault::CrashAt`] in that the node itself is never
/// poisoned (`crashed()` stays `false`): this models a remote that
/// stopped answering, not a local process that died.
#[test]
fn fail_from_refuses_every_operation_at_or_past_the_index_without_crashing() {
    let sim = Sim::new();
    let (digest, bin) = a_bin();
    let store = sim.node(0, Faults::just(Fault::FailFrom(1)));

    assert_eq!(
        pends_once(store.put_bin(&digest, bin)),
        Ok(true),
        "before the threshold, ordinary"
    );
    assert!(
        pends_once(store.put_root(VOL, 1, b"r".to_vec())).is_err(),
        "at the threshold, refused"
    );
    assert!(
        pends_once(store.get_root(VOL, 1)).is_err(),
        "past the threshold, still refused"
    );
    assert!(
        !store.crashed(),
        "FailFrom is a standing refusal, not a crash-and-poison"
    );
}

/// The release point, pinned at both edges. The caller is told the
/// PUT failed; the root is absent through exactly `release_after`
/// later store operations and present from the next one on — which is
/// what separates a deferral from [`Fault::LandButReportFailure`]
/// (present at the first read) and from [`Fault::Fail`] (never
/// present). The release is recorded under the issuing node, ahead of
/// the operation it was applied in front of.
#[test]
fn defer_put_reports_failure_and_lands_only_at_its_release_point() {
    let sim = Sim::new();
    let writer = sim.node(
        0,
        Faults::just(Fault::DeferPut {
            at: 0,
            release_after: 2,
        }),
    );
    let bytes = b"a held root".to_vec();
    assert_eq!(
        pends_once(writer.put_root(VOL, 1, bytes.clone())),
        Err(injected()),
        "the caller must be told the PUT failed"
    );
    let reader = sim.node(1, Faults::none());
    let reads: Vec<Option<Vec<u8>>> = (0..3)
        .map(|_| {
            pends_once(reader.get_root(VOL, 1))
                .unwrap_or_else(|e| panic!("a fault-free read failed: {e}"))
        })
        .collect();
    assert_eq!(
        reads,
        vec![None, None, Some(bytes)],
        "absent through release_after = 2 later operations, present from the third"
    );
    let rendered: Vec<String> = sim
        .trace()
        .entries()
        .iter()
        .map(|e| format!("n{} {} -> {}", e.node, e.op, e.outcome))
        .collect();
    let words: Vec<&str> = rendered
        .iter()
        .map(|l| l.split(' ').nth(1).unwrap_or_default())
        .collect();
    assert_eq!(
        words,
        [
            "put-root",
            "get-root",
            "get-root",
            "release-root",
            "get-root"
        ],
        "{rendered:#?}"
    );
    assert!(
        rendered
            .first()
            .is_some_and(|l| l.starts_with("n0 ") && l.ends_with("-> failed(deferred)")),
        "{rendered:#?}"
    );
    assert!(
        rendered
            .get(3)
            .is_some_and(|l| l.starts_with("n0 ") && l.ends_with("-> ok")),
        "the release is recorded under the issuing node, as landed: {rendered:#?}"
    );
    assert_eq!(
        (writer.store_ops(), reader.store_ops()),
        (1, 3),
        "a release is not an operation either node issued"
    );
}

/// Create-only at release: a held write whose seq was taken meanwhile
/// is REFUSED, the occupant stays, and the artifact says so. An
/// implementation that released with an overwriting insert would
/// leave the held bytes at the seq and fail the read below.
#[test]
fn a_released_write_never_overwrites_and_its_refusal_is_recorded() {
    let sim = Sim::new();
    let late = sim.node(
        0,
        Faults::just(Fault::DeferPut {
            at: 0,
            release_after: 1,
        }),
    );
    assert!(pends_once(late.put_root(VOL, 1, b"late".to_vec())).is_err());
    let other = sim.node(1, Faults::none());
    assert_eq!(
        pends_once(other.put_root(VOL, 1, b"first".to_vec())),
        Ok(()),
        "the held write has not landed yet, so the seq is free"
    );
    assert_eq!(
        pends_once(other.get_root(VOL, 1)),
        Ok(Some(b"first".to_vec())),
        "the late write must not overwrite the root that landed first"
    );
    let release: Vec<Entry> = sim
        .trace()
        .entries()
        .iter()
        .filter(|e| matches!(e.op, Op::ReleaseRoot { .. }))
        .cloned()
        .collect();
    assert_eq!(
        release
            .iter()
            .map(|e| (e.node, e.outcome))
            .collect::<Vec<_>>(),
        vec![(0, Outcome::Failed(TraceError::AlreadyExists))],
        "exactly one release, by node 0, refused"
    );
}

/// On anything but a `put_root` the deferral is a plain refusal: a
/// hint write under it applies nothing, now or later.
#[test]
fn defer_put_on_another_write_is_a_plain_refusal() {
    let sim = Sim::new();
    let store = sim.node(
        0,
        Faults::just(Fault::DeferPut {
            at: 0,
            release_after: 0,
        }),
    );
    assert_eq!(pends_once(store.write_hint(VOL, 1)), Err(injected()));
    let reader = sim.node(1, Faults::none());
    assert!(matches!(
        pends_once(reader.read_hint(VOL, None)),
        Ok(HintRead::Missing)
    ));
    assert!(
        !sim.trace()
            .entries()
            .iter()
            .any(|e| matches!(e.op, Op::ReleaseRoot { .. })),
        "nothing was held, so nothing is released"
    );
}

/// The oracle is the CHECK, not the run: reads through
/// [`Sim::oracle`] mid-run neither count toward a held write's release
/// point nor trigger its release. Two worlds run the same writer and
/// the same run reader; one of them also has the oracle read the seq
/// before every run operation. The run's own entries must be
/// identical in both — the release at the same boundary — and the
/// oracle must see the seq empty until the run released the write.
#[test]
fn a_mid_run_oracle_read_does_not_change_when_a_held_write_lands() {
    let run = |oracle_reads: bool| -> (Vec<String>, Vec<Option<Vec<u8>>>) {
        let sim = Sim::new();
        let writer = sim.node(
            0,
            Faults::just(Fault::DeferPut {
                at: 0,
                release_after: 2,
            }),
        );
        assert!(pends_once(writer.put_root(VOL, 1, b"held".to_vec())).is_err());
        let reader = sim.node(1, Faults::none());
        let oracle = sim.oracle();
        let mut seen_by_oracle = Vec::new();
        for _ in 0..3 {
            if oracle_reads {
                for _ in 0..3 {
                    seen_by_oracle.push(
                        pends_once(oracle.get_root(VOL, 1))
                            .unwrap_or_else(|e| panic!("the oracle read failed: {e}")),
                    );
                }
            }
            let _ = pends_once(reader.get_root(VOL, 1));
        }
        if oracle_reads {
            seen_by_oracle.push(
                pends_once(oracle.get_root(VOL, 1))
                    .unwrap_or_else(|e| panic!("the oracle read failed: {e}")),
            );
        }
        let run_entries = sim
            .trace()
            .entries()
            .iter()
            .filter(|e| e.node != Sim::ORACLE_NODE)
            .map(|e| format!("n{} {} -> {}", e.node, e.op, e.outcome))
            .collect();
        (run_entries, seen_by_oracle)
    };
    let (without, _) = run(false);
    let (with, seen) = run(true);
    assert_eq!(
        with, without,
        "mid-run oracle reads moved the release of the held write"
    );
    assert_eq!(
        seen,
        [vec![None; 9], vec![Some(b"held".to_vec())]].concat(),
        "nine oracle reads before the run's third operation must see the seq empty, and the \
         read after it must see the released root"
    );
    let reader_reads: Vec<&str> = without
        .iter()
        .filter(|l| l.starts_with("n1 "))
        .map(|l| l.rsplit(" -> ").next().unwrap_or_default())
        .collect();
    assert_eq!(
        reader_reads,
        ["absent", "absent", "ok"],
        "the premise: the run releases the held write before its third read acts"
    );
}

/// The reserved indices name the check and the operator in the
/// artifact; a publisher handed one would be indistinguishable from
/// them, and the oracle one would also stop counting toward releases.
#[test]
#[should_panic(expected = "is reserved")]
fn a_publisher_cannot_take_the_oracle_index() {
    let _ = Sim::new().node(Sim::ORACLE_NODE, Faults::none());
}

/// See [`a_publisher_cannot_take_the_oracle_index`].
#[test]
#[should_panic(expected = "is reserved")]
fn a_publisher_cannot_take_the_admin_index() {
    let _ = Sim::new().node(Sim::ADMIN_NODE, Faults::none());
}

// ------------------------------------------------- the admin handle

/// The operator's reach, which no `put_root` caller has: seq 0 and
/// `u64::MAX` can be planted, listed and deleted, while `max_seq` keeps
/// refusing both as heads. A plant is create-only; a delete reports
/// whether it removed anything; every call is recorded under
/// [`Sim::ADMIN_NODE`] and none is a store operation.
#[test]
fn admin_plants_lists_and_deletes_any_seq_outside_the_seam() {
    let sim = Sim::new();
    let admin = sim.admin();
    let vol = crate::scenario::volume();
    for seq in [0, 5, u64::MAX] {
        assert!(admin.plant_root(&vol, seq, format!("planted {seq}").into_bytes()));
    }
    assert!(
        !admin.plant_root(&vol, 5, b"a second plant".to_vec()),
        "a plant is create-only"
    );
    assert_eq!(admin.root_seqs(&vol), vec![0, 5, u64::MAX]);

    let reader = sim.node(1, Faults::none());
    assert_eq!(
        pends_once(reader.get_root(VOL, 5)),
        Ok(Some(b"planted 5".to_vec())),
        "the refused second plant left the first in place"
    );
    assert_eq!(
        pends_once(reader.max_seq(VOL)),
        Ok(Some(5)),
        "0 and u64::MAX are never a head"
    );
    assert_eq!(
        pends_once(reader.get_root(VOL, u64::MAX)),
        Ok(Some(format!("planted {}", u64::MAX).into_bytes()))
    );

    assert!(admin.delete_root(&vol, 5));
    assert!(!admin.delete_root(&vol, 5), "nothing left to delete");
    assert_eq!(pends_once(reader.max_seq(VOL)), Ok(None));
    assert!(admin.delete_root(&vol, 0));
    assert!(admin.delete_root(&vol, u64::MAX));
    assert_eq!(admin.root_seqs(&vol), Vec::<u64>::new());

    let trace = sim.trace();
    let admin_entries: Vec<(&Op, Outcome)> = trace
        .entries()
        .iter()
        .filter(|e| e.node == Sim::ADMIN_NODE)
        .map(|e| (&e.op, e.outcome))
        .collect();
    assert_eq!(admin_entries.len(), 10, "{}", trace.render());
    assert!(
        admin_entries
            .iter()
            .all(|(op, _)| !crate::scenario::is_store_op(op)),
        "an admin call is never a store operation"
    );
    assert_eq!(reader.store_ops(), 4);
}

/// Admin calls do not move a held write's release point: only store
/// operations count. A driver that inspects the world between runs
/// must not change WHEN a deferred PUT lands.
#[test]
fn admin_calls_do_not_advance_a_held_release() {
    let sim = Sim::new();
    let writer = sim.node(
        0,
        Faults::just(Fault::DeferPut {
            at: 0,
            release_after: 0,
        }),
    );
    assert!(pends_once(writer.put_root(VOL, 1, b"held".to_vec())).is_err());
    let admin = sim.admin();
    let vol = crate::scenario::volume();
    for _ in 0..3 {
        assert_eq!(admin.root_seqs(&vol), Vec::<u64>::new(), "still held");
    }
    let reader = sim.node(1, Faults::none());
    assert_eq!(
        pends_once(reader.get_root(VOL, 1)),
        Ok(Some(b"held".to_vec())),
        "released before the next STORE operation acts"
    );
    assert_eq!(admin.root_seqs(&vol), vec![1]);
}

// ------------------------------------------------- the sweep range

/// The operation count is DATA-DEPENDENT — change the fixture and it
/// moves — so a sweep discovers its own range from
/// [`SimStore::store_ops`] rather than hard-coding one. The literals
/// below are THIS fixture's measured counts, asserted here (and
/// nowhere else) so that a change to the publish flow's operation
/// sequence shows up as one failing test rather than silently
/// re-scoping every sweep that was written against it.
#[test]
fn a_publish_and_a_republish_have_discoverable_operation_counts() {
    let sim = Sim::new();
    let one = seed_tree(&sim, ONE);
    let two = seed_tree(&sim, TWO);

    let first = publish_on(&sim, 0, Faults::none(), one, Policy::default());
    let (first_ops, first) = (first.ops, first.outcome);
    assert!(first.is_ok(), "first publish: {:?}", first.err());
    let dedup = publish_on(&sim, 1, Faults::none(), one, Policy::default());
    let (dedup_ops, dedup) = (dedup.ops, dedup.outcome);
    assert!(dedup.is_ok(), "dedup-only republish: {:?}", dedup.err());
    let delta = publish_on(&sim, 2, Faults::none(), two, Policy::default());
    let (delta_ops, delta) = (delta.ops, delta.outcome);
    assert!(delta.is_ok(), "delta republish: {:?}", delta.err());

    // A first publish: max_seq, put_bin, put_meta ×3 (shard, bin
    // table, index), put_meta (sheaf), put_root, write_hint.
    assert_eq!(first_ops, 8, "a first publish of this fixture");
    // A dedup-only republish: five reads to resolve and verify the
    // head it is extending, then only the sheaf and the root — the
    // binmap is reused wholesale, not rebuilt.
    assert_eq!(dedup_ops, 8, "a dedup-only republish of this fixture");
    // A delta republish pays the same five reads AND rebuilds the
    // binmap (bin, shard, bin table, index), so it is the longest of
    // the three.
    assert_eq!(delta_ops, 12, "a delta republish of this fixture");
    assert!(
        delta_ops > first_ops,
        "a republish reads the head it extends, so a delta costs more than a first publish"
    );
}

/// The suspension test above proves the MECHANISM; this proves the
/// EFFECT. Two publishers driven by one scheduler must actually
/// interleave through the fakes — if the operations were
/// ready-shaped, the first publisher polled would run to completion
/// before the second was polled at all, and every concurrency
/// scenario built on this store would pass without a race ever
/// happening.
///
/// One pinned seed, which is a FIXTURE check and not a licence to
/// single-seed a race: the scheduler's own docs measure ~7% of seeds
/// producing a fully segregated schedule, so a scenario asserting a
/// race property sweeps seeds instead.
#[test]
fn two_publishers_interleave_through_the_fakes() {
    let sim = Sim::new();
    let root = seed_tree(&sim, ONE);
    let tasks: Vec<Task<Published>> = vec![
        Box::pin(publish_with(
            sim.node(0, Faults::none()),
            root,
            Policy::default(),
        )),
        Box::pin(publish_with(
            sim.node(1, Faults::none()),
            root,
            Policy::default(),
        )),
    ];
    let results = Scheduler::new(42).run(tasks);
    assert_eq!(results.len(), 2);

    let nodes: Vec<u32> = sim.trace().entries().iter().map(|e| e.node).collect();
    assert!(!nodes.is_empty(), "the run recorded nothing");
    let handoffs = nodes.windows(2).filter(|w| w.first() != w.last()).count();
    assert!(
        handoffs > 1,
        "the schedule is segregated by publisher — the fakes gave it nowhere to \
         interleave: {nodes:?}"
    );
}

// ------------------------------------------------- the oracle

#[test]
fn a_completed_publish_resolves_through_the_oracle() {
    let sim = Sim::new();
    let root = seed_tree(&sim, ONE);
    let summary = publish_on(&sim, 0, Faults::none(), root, Policy::default()).outcome;
    assert!(summary.is_ok(), "{:?}", summary.err());

    let (resolved, objects) = resolve_collecting(&sim).expect("a committed volume resolves");
    assert_eq!(resolved.seq, 1);
    assert_eq!(resolved.doc.manifest_root, root);
    assert_eq!(
        objects.len(),
        resolved.entries.len(),
        "every mapped object came back out of its bin"
    );
}

/// Most crash points are before the root CAS, and they all leave the
/// head exactly where it was — which is why `NoHead` is an outcome
/// and not a panic.
#[test]
fn a_crash_before_the_root_leaves_the_volume_with_no_head() {
    let sim = Sim::new();
    let root = seed_tree(&sim, ONE);
    let summary = publish_on(
        &sim,
        0,
        Faults::just(Fault::CrashAt(0)),
        root,
        Policy::default(),
    )
    .outcome;
    assert!(
        summary.is_err(),
        "a crashed publish must not report success"
    );
    assert!(
        matches!(resolve(&sim), Err(ResolveError::NoHead)),
        "a crash at the first operation leaves no head at all"
    );
}
