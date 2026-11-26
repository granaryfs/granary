// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Another writer's head observed through the bound engine: the advisory
//! deferral before any read, the reports a boundary owes, the refusal memo,
//! the closed latch, a dead store's close, and the mount's own boundary.

use super::*;
use crate::sync::{HeadObserver, Observed};

type Observer = HeadObserver<Authority, FastWaitRuntime>;

/// What an observation answered, as text.
#[expect(
    clippy::ref_option,
    reason = "each row borrows the answer it builds or receives, as text"
)]
fn observed(result: &Option<Result<Observed, crate::CoordinationError>>) -> String {
    format!("{result:?}")
}

impl BoundMount {
    /// An observer of the fixture's authority, armed with its engine, as
    /// the binding arms the mount's own.
    fn observer(&self) -> Arc<Observer> {
        let observer = Arc::new(HeadObserver::new(
            Arc::new(Authority::new(&self.tree, &self.state)),
            Arc::new(FastWaitRuntime),
            self.tree.volume.clone(),
            Arc::new(Time(self.state.clone())),
            crate::ViewMode::Default,
            Some(self.metrics.clone()),
        ));
        assert!(
            observer.arm(Arc::new(self.engine.clone())),
            "premise: the first arming"
        );
        observer
    }
    /// One boundary's observation, run to its end; `None` when the observer
    /// starts none.
    fn observe(
        &self,
        observer: &Arc<Observer>,
        writers: bool,
    ) -> Option<Result<Observed, crate::CoordinationError>> {
        let observation = observer.observe(writers)?;
        Some(
            self.runtime
                .block_on(observation)
                .expect("the observation ran"),
        )
    }
    /// (head probes, root reads, range reads) so far.
    fn reads(&self) -> (usize, usize, usize) {
        let state = self.state.lock().unwrap();
        (state.probes, state.root_reads, state.ranges.len())
    }
    /// Poison the mediator through a failed shrink of a staged `f.txt`.
    fn poison(&self) {
        self.write_path(b"f.txt", b"local", false);
        let mediator = self.mediator();
        let crate::overlay_store::OverlayQuery::Found(found) = mediator
            .overlay_transaction(|overlay| overlay.query_path(&handler_path(b"f.txt")))
            .unwrap()
        else {
            panic!("premise: f.txt is in the view")
        };
        let stage = found.entry.and_then(|entry| entry.stage_id).unwrap();
        self.faults.arm(
            "overlay.stage.truncate",
            "before",
            1,
            crate::FaultAction::Fail,
        );
        let shrink = mediator.overlay_transaction(|overlay| overlay.truncate(stage, 2));
        assert!(shrink.is_err(), "premise: the shrink poisons the store");
    }
}

/// Every `mount.view` event `events` holds, as (level, cause, outcome, seq).
fn view_event_fields(events: &Events) -> Vec<(String, String, String, String)> {
    let field = |line: &str, key: &str| {
        line.split(&format!("\"{key}\":"))
            .nth(1)
            .map(|rest| rest.trim_start_matches('"'))
            .and_then(|rest| rest.split(['"', ',', '}']).next())
            .unwrap_or_default()
            .to_owned()
    };
    String::from_utf8(events.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| line.contains("\"event\":\"mount.view\""))
        .map(|line| {
            (
                field(line, "level"),
                field(line, "cause"),
                field(line, "outcome"),
                field(line, "seq"),
            )
        })
        .collect()
}

/// How many `op.failed` events with `kind=view` `events` holds.
fn view_failures(events: &Events) -> usize {
    String::from_utf8(events.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"op.failed\"") && line.contains("\"kind\":\"view\"")
        })
        .count()
}

/// The `outcome` of each `mount.view` event with `cause=adopted` that
/// `events` holds.
fn view_outcomes(events: &Events) -> Vec<String> {
    view_event_fields(events)
        .into_iter()
        .filter(|(_, cause, _, _)| cause == "adopted")
        .map(|(_, _, outcome, _)| outcome)
        .collect()
}

/// Every observation that reaches a verdict reports one `mount.view` event
/// at the head's seq with `cause=adopted`: installed and deferred at INFO, a
/// refusal before or under the gate and a close at WARN as refused. "No
/// answer yet" reports none. Case count 6.
#[test]
fn adoption_reports_each_verdict_as_an_adopted_view_event() {
    let mut observations = Vec::new();
    let mut expected = Vec::new();
    for case in [
        "installed",
        "deferred",
        "refused before the gate",
        "refused under the gate",
        "closed",
        "no answer yet",
    ] {
        let fixture = BoundMount::new();
        let observer = fixture.observer();
        disjoint_head(&fixture.tree, &fixture.runtime);
        let mut head = fixture.tree.seq + 1;
        match case {
            "deferred" => *fixture.gate.writers.lock().unwrap() = Some(true),
            "refused before the gate" => {
                // A head no journal header can carry as its base.
                let (base_id, mut doc) =
                    root_doc(&fixture.tree, &fixture.runtime, fixture.tree.seq);
                doc.seq = u64::MAX - 1;
                doc.parent = Some(base_id);
                head = sign_and_put(&fixture.tree, &fixture.runtime, doc);
            }
            "refused under the gate" => {
                let anchor = fixture
                    .paths
                    .cache
                    .join("anchors")
                    .join(fixture.tree.volume.as_str());
                std::fs::write(anchor, format!("seq {:020}\n", head + 1)).unwrap();
            }
            "closed" => fixture.plant_equivocation(head),
            "no answer yet" => {
                fixture.state.lock().unwrap().next_range_fault = Some(RangeFault::Unavailable);
            }
            _ => {}
        }
        let events = Events::default();
        let result = tracing::subscriber::with_default(events.subscriber(), || {
            fixture.observe(&observer, false)
        });
        let event = |level: &str, outcome: &str| {
            vec![(
                level.to_owned(),
                "adopted".to_owned(),
                outcome.to_owned(),
                head.to_string(),
            )]
        };
        observations.push((case, view_event_fields(&events)));
        expected.push((
            case,
            match case {
                "installed" => event("INFO", "installed"),
                "deferred" => event("INFO", "deferred"),
                "no answer yet" => vec![],
                _ => event("WARN", "refused"),
            },
        ));
        assert!(
            (case == "no answer yet") == result.as_ref().is_some_and(Result::is_err),
            "{case}: premise, the observation's answer is {}",
            observed(&result)
        );
    }
    assert_eq!(observations, expected, "(case, mount.view events)");
    assert_eq!(observations.len(), 6);
}

/// A mount holding work of its own defers before any root or range read,
/// and reports the deferral once per episode. Dirty: two boundaries over a
/// head H defer with no read and one event. The mount's own landing then
/// rebases onto H, and the next boundary finds the head unchanged at the
/// landed seq; a later head installs over the clean mount, and a new local
/// write defers again, reported again. Writer: a write-capable descriptor
/// defers with no read, and once it is closed the head installs. Case
/// count 2.
#[test]
fn observer_defers_without_network_and_reports_the_rising_edge() {
    let deferred = |seq| observed(&Some(Ok(Observed::Deferred(seq))));
    // Dirty.
    let fixture = BoundMount::new();
    let observer = fixture.observer();
    fixture.write_path(b"f.txt", b"local", false);
    disjoint_head(&fixture.tree, &fixture.runtime);
    let head = fixture.tree.seq + 1;
    let events = Events::default();
    let (deferrals, landing, later, again, outcomes) =
        tracing::subscriber::with_default(events.subscriber(), || {
            let mut deferrals = Vec::new();
            for _ in 0..2 {
                let (_, roots, ranges) = fixture.reads();
                let result = observed(&fixture.observe(&observer, false));
                let (_, after_roots, after_ranges) = fixture.reads();
                deferrals.push((
                    result,
                    after_roots - roots,
                    after_ranges - ranges,
                    view_outcomes(&events).len(),
                ));
            }
            let lane = fixture.construct(70);
            assert!(
                landed(&fixture.drive(&lane, 80)),
                "premise: the mount's own commit lands, rebased onto H"
            );
            let landed_seq = remote_seq(&fixture.tree, &fixture.runtime);
            let unchanged = observed(&fixture.observe(&observer, false));
            let landing = (unchanged, fixture.pin_seq(), landed_seq);
            let later = publish_source(&fixture.tree, &fixture.runtime, |source| {
                write_operation_source(source, FILE_CONTENT);
                std::fs::write(source.join("later.txt"), b"a later head\n").unwrap();
            });
            let later = (observed(&fixture.observe(&observer, false)), later);
            fixture.write_path(b"f.txt", b"again", false);
            let again = publish_source(&fixture.tree, &fixture.runtime, |source| {
                write_operation_source(source, FILE_CONTENT);
                std::fs::write(source.join("again.txt"), b"another head\n").unwrap();
            });
            let again = (observed(&fixture.observe(&observer, false)), again);
            (deferrals, landing, later, again, view_outcomes(&events))
        });
    let (landed_seq, later_seq, again_seq) = (landing.2, later.1, again.1);
    assert_eq!(
        (deferrals, landing, later, again, outcomes),
        (
            vec![(deferred(head), 0, 0, 1), (deferred(head), 0, 0, 1)],
            (
                observed(&Some(Ok(Observed::Unchanged))),
                Some(landed_seq),
                landed_seq
            ),
            (
                observed(&Some(Ok(Observed::Installed(later_seq)))),
                later_seq
            ),
            (deferred(again_seq), again_seq),
            vec![
                "deferred".to_owned(),
                "installed".to_owned(),
                "deferred".to_owned()
            ],
        ),
        "dirty: ((answer, root reads, range reads, events) per deferral, (answer after the \
         landing, pin, landed seq), (answer, later head), (answer, head of a second episode), \
         every event)"
    );

    // Writer.
    let fixture = BoundMount::new();
    let observer = fixture.observer();
    disjoint_head(&fixture.tree, &fixture.runtime);
    let head = fixture.tree.seq + 1;
    let (_, roots, ranges) = fixture.reads();
    let writer = observed(&fixture.observe(&observer, true));
    let (_, after_roots, after_ranges) = fixture.reads();
    let closed = observed(&fixture.observe(&observer, false));
    assert_eq!(
        (writer, after_roots - roots, after_ranges - ranges, closed),
        (
            deferred(head),
            0,
            0,
            observed(&Some(Ok(Observed::Installed(head))))
        ),
        "writer: (answer with the descriptor held, root reads, range reads, answer once closed)"
    );
}

/// A head refused once is not tried again: a corrupt head at s is refused
/// and reported, the next boundary probing s reads no root and reports
/// nothing, and a valid head at s + 1 installs.
#[test]
fn observer_does_not_retry_a_refused_head() {
    let fixture = BoundMount::new();
    let observer = fixture.observer();
    let (base_id, doc) = root_doc(&fixture.tree, &fixture.runtime, fixture.tree.seq);
    let corrupt = publish_without(
        &fixture.tree,
        &fixture.runtime,
        fixture.tree.seq,
        doc.manifest_root,
    );
    let events = Events::default();
    let observed_all = tracing::subscriber::with_default(events.subscriber(), || {
        let first = (
            observed(&fixture.observe(&observer, false)),
            view_outcomes(&events).len(),
        );
        let (_, roots, _) = fixture.reads();
        let second = observed(&fixture.observe(&observer, false));
        let (_, after_roots, _) = fixture.reads();
        let second = (second, after_roots - roots, view_outcomes(&events).len());
        let mut valid = doc.clone();
        valid.seq = corrupt + 1;
        valid.parent = Some(base_id);
        let valid = sign_and_put(&fixture.tree, &fixture.runtime, valid);
        let third = observed(&fixture.observe(&observer, false));
        (first, second, (third, valid), observer.state_for_test().0)
    });
    let valid = corrupt + 1;
    assert_eq!(
        observed_all,
        (
            (observed(&Some(Ok(Observed::HeadRefused(corrupt)))), 1),
            (observed(&Some(Ok(Observed::Unchanged))), 0, 1),
            (observed(&Some(Ok(Observed::Installed(valid)))), valid),
            corrupt,
        ),
        "((boundary 1, events), (boundary 2, root reads, events), (boundary 3, valid seq), \
         highest refused seq)"
    );
}

/// A closed view is not observed again: an equivocating cached root closes
/// the view at the first boundary, and the next starts no observation and
/// sends no probe.
#[test]
fn observer_stops_after_a_closed_view() {
    let fixture = BoundMount::new();
    let observer = fixture.observer();
    disjoint_head(&fixture.tree, &fixture.runtime);
    let head = fixture.tree.seq + 1;
    fixture.plant_equivocation(head);
    let first = observed(&fixture.observe(&observer, false));
    let (probes, _, _) = fixture.reads();
    let second = observed(&fixture.observe(&observer, false));
    let (after, _, _) = fixture.reads();
    assert_eq!(
        (first, fixture.view_pending(), second, after - probes),
        (
            observed(&Some(Ok(Observed::Closed(Some(head))))),
            Some(true),
            observed(&None),
            0
        ),
        "(boundary 1, view pending, boundary 2, probes it sent)"
    );
}

/// A head whose new node failed to read at the transport is "no answer
/// yet": nothing is latched or reported, and the next boundary probes the
/// same head again and installs it.
#[test]
fn observer_retries_a_head_whose_node_read_failed() {
    let fixture = BoundMount::new();
    let observer = fixture.observer();
    disjoint_head(&fixture.tree, &fixture.runtime);
    let head = fixture.tree.seq + 1;
    fixture.state.lock().unwrap().next_range_fault = Some(RangeFault::Unavailable);
    let events = Events::default();
    let first = tracing::subscriber::with_default(events.subscriber(), || {
        let result = fixture.observe(&observer, false);
        (
            observed(&result),
            observer.state_for_test().0,
            view_outcomes(&events).len(),
        )
    });
    let second = observed(&fixture.observe(&observer, false));
    let no_answer: Option<Result<Observed, crate::CoordinationError>> =
        Some(Err(crate::OverlayError::ContentUnavailable.into()));
    assert_eq!(
        (first, second, fixture.pin_seq()),
        (
            (observed(&no_answer), 0, 0),
            observed(&Some(Ok(Observed::Installed(head)))),
            Some(head)
        ),
        "((boundary 1, highest refused seq, events), boundary 2, pin seq)"
    );
}

/// A close of a dead store that never reached the gate closed nothing, so
/// the observer does not latch: the first boundary's close finds the adapter
/// gone and is "no answer yet", with the view open and nothing revoked. The
/// adapter answers again, and the next boundary closes and revokes the view
/// and latches.
#[test]
fn a_failed_close_does_not_latch_the_observer() {
    let fixture = BoundMount::new();
    let observer = fixture.observer();
    disjoint_head(&fixture.tree, &fixture.runtime);
    fixture.poison();
    fixture
        .gate
        .forced
        .lock()
        .unwrap()
        .push_back(Forced::Busy(SlotBusy::Abandoned));
    let failed = observed(&fixture.observe(&observer, false));
    let first = (
        failed,
        fixture.view_pending(),
        fixture.sends().len(),
        observer.state_for_test().1,
    );
    let closed = observed(&fixture.observe(&observer, false));
    let sent = eventually(|| fixture.sends().len() == 1);
    let second = (
        closed,
        fixture.view_pending(),
        sent,
        observer.state_for_test().1,
    );
    let lost: Option<Result<Observed, crate::CoordinationError>> =
        Some(Err(crate::sync::refused("ViewAdapterLost")));
    assert_eq!(
        (first, second),
        (
            (observed(&lost), Some(false), 0, false),
            (
                observed(&Some(Ok(Observed::Closed(None)))),
                Some(true),
                true,
                true
            ),
        ),
        "((boundary 1, view pending, sends, latched), (boundary 2, view pending, revoked, latched))"
    );
}

/// A store that refuses its own base serves nothing more, so the next
/// boundary closes and revokes the view without reading the head's root or
/// any node, and the boundary after it observes nothing. No head was adopted
/// or refused, so the close reports only its own `op.failed{kind=view}`. Case poison: a
/// failed shrink poisons the mediator. Case fenced: a same-path conflict
/// fences it. Case count 2.
#[test]
fn a_dead_store_closes_the_view_at_the_next_boundary() {
    let mut observations = Vec::new();
    let mut expected = Vec::new();
    for case in ["poison", "fenced"] {
        let fixture = BoundMount::new();
        let observer = fixture.observer();
        if case == "poison" {
            disjoint_head(&fixture.tree, &fixture.runtime);
            fixture.poison();
        } else {
            fixture.write_path(b"f.txt", b"local", false);
            let lane = fixture.construct(70);
            foreign_head(&fixture.tree, &fixture.runtime);
            let fenced = fixture.drive(&lane, 80);
            assert!(
                matches!(fenced, Err(crate::CoordinationError::Fenced { .. })),
                "premise: the lane fences: {fenced:?}"
            );
        }
        let sends = fixture.sends().len();
        let (_, roots, ranges) = fixture.reads();
        let events = Events::default();
        let closed = tracing::subscriber::with_default(events.subscriber(), || {
            observed(&fixture.observe(&observer, false))
        });
        let reports = (view_event_fields(&events).len(), view_failures(&events));
        let sent = eventually(|| fixture.sends().len() == sends + 1);
        let (probes, after_roots, after_ranges) = fixture.reads();
        let next = observed(&fixture.observe(&observer, false));
        let (after_probes, _, _) = fixture.reads();
        observations.push((
            case,
            closed,
            reports,
            fixture.view_pending(),
            sent,
            after_roots - roots,
            after_ranges - ranges,
            next,
            after_probes - probes,
        ));
        expected.push((
            case,
            observed(&Some(Ok(Observed::Closed(None)))),
            (0, 1),
            Some(true),
            true,
            0,
            0,
            observed(&None),
            0,
        ));
    }
    assert_eq!(
        observations, expected,
        "(case, boundary, (mount.view events, op.failed view events), view pending, revoked, \
         root reads, range reads, next boundary, its probes)"
    );
    assert_eq!(observations.len(), 2);
}

/// The mount's own view boundary looks for heads once its binding has
/// armed it: bound, a boundary probes and installs the remote head;
/// attached but never bound, a boundary sends no probe and serves the
/// view it has.
#[test]
fn a_bound_mount_adopts_at_its_view_boundary_and_an_unbound_one_never_probes() {
    use granary_fuse::{BoundaryKind, BoundaryOutcome, MountBackend as _};
    let bound = BoundMount::new();
    let (unbound, _binding) = BoundMount::unbound(multi_thread());
    let mut observations = Vec::new();
    for (case, fixture) in [("bound", &bound), ("unbound", &unbound)] {
        disjoint_head(&fixture.tree, &fixture.runtime);
        let boundary = fixture
            .with_mount(|mount| mount.view_boundary())
            .flatten()
            .expect("premise: an attached engine gives the mount a boundary");
        let (probes, _, _) = fixture.reads();
        let outcome = boundary.wait(BoundaryKind::Open, &|| false);
        let (after, _, _) = fixture.reads();
        observations.push((case, outcome, after - probes, fixture.pin_seq()));
    }
    let head = bound.tree.seq + 1;
    assert_eq!(
        observations,
        vec![
            ("bound", BoundaryOutcome::Installed, 1, Some(head)),
            ("unbound", BoundaryOutcome::Served, 0, Some(head - 1)),
        ],
        "(case, boundary outcome, probes, pin seq)"
    );
}

/// Each bound landing clears an unreachable episode before either the gated
/// install or an unattended install begins. Case count 2.
#[test]
fn a_bound_hooks_refresh_clears_the_unreachable_state() {
    use granary_fuse::{BoundaryKind, BoundaryOutcome, MountBackend as _};
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for unattended in [false, true] {
        let fixture = if unattended {
            let (fixture, binding) = BoundMount::unbound(multi_thread());
            binding.bind_unattended_for_test().unwrap();
            fixture.engine.install_locally();
            fixture
        } else {
            BoundMount::new()
        };
        fixture.state.lock().unwrap().probe_fault = Some(RootStoreError::Backend("down".into()));
        let boundary = fixture
            .with_mount(|mount| mount.view_boundary())
            .flatten()
            .expect("premise: a bound engine gives the mount a boundary");
        let entered = boundary.wait(BoundaryKind::Open, &|| false);
        let stale = boundary
            .label()
            .and_then(Result::ok)
            .is_some_and(|label| label.starts_with(b"stale:"));
        assert_eq!(
            (entered, stale),
            (BoundaryOutcome::Served, true),
            "premise: the boundary entered the unreachable state"
        );

        let (send, receive) = std::sync::mpsc::channel();
        let at_install = boundary.clone();
        *fixture.gate.before_attempt.lock().unwrap() = Some(Box::new(move || {
            let fresh = at_install
                .label()
                .and_then(Result::ok)
                .is_some_and(|label| label.starts_with(b"fresh:"));
            let _ = send.send(fresh);
        }));
        fixture.write_path(b"f.txt", b"landing", false);
        let lane = fixture.construct(61);
        let seq = fixture.tree.seq + 1;
        let events = Events::default();
        let landed = tracing::subscriber::with_default(events.subscriber(), || {
            fixture.drive(&lane, 62).unwrap()
        });
        let install_state = if unattended {
            None
        } else {
            receive.recv_timeout(BOUND).ok()
        };
        let rendered = fixture
            .metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap();
        let gauge = rendered
            .lines()
            .find_map(|line| line.strip_prefix("granary_client_mount_view_stale "))
            .and_then(|value| value.parse::<u64>().ok());
        let fresh_events: Vec<_> = view_event_fields(&events)
            .into_iter()
            .filter(|(_, cause, outcome, _)| cause == "landed" && outcome == "fresh")
            .collect();
        observed.push((
            unattended,
            matches!(landed.outcome, crate::PublicationOutcome::Landed(_)),
            boundary
                .label()
                .and_then(Result::ok)
                .is_some_and(|label| label.starts_with(b"fresh:")),
            fresh_events,
            gauge,
            install_state,
        ));
        expected.push((
            unattended,
            true,
            true,
            vec![(
                "INFO".to_owned(),
                "landed".to_owned(),
                "fresh".to_owned(),
                seq.to_string(),
            )],
            Some(0),
            (!unattended).then_some(true),
        ));
    }
    assert_eq!(
        observed, expected,
        "(unattended, landed, fresh label, mount.view fresh events, gauge, fresh at install)"
    );
    assert_eq!(observed.len(), 2);
}

/// A boundary while a write-capable descriptor is held defers, and once it
/// has deferred, later boundaries with the descriptor still held still
/// probe the head so an outage is seen, while reading no root or range.
#[test]
fn a_held_writer_probes_but_reads_nothing() {
    let fixture = BoundMount::new();
    let observer = fixture.observer();
    disjoint_head(&fixture.tree, &fixture.runtime);
    let head = fixture.tree.seq + 1;
    let (probes, roots, ranges) = fixture.reads();
    let answers: Vec<_> = (0..3)
        .map(|_| observed(&fixture.observe(&observer, true)))
        .collect();
    let (after, after_roots, after_ranges) = fixture.reads();
    assert_eq!(
        (
            answers,
            after - probes,
            after_roots - roots,
            after_ranges - ranges
        ),
        (
            vec![
                observed(&Some(Ok(Observed::Deferred(head)))),
                observed(&Some(Ok(Observed::StillDeferred))),
                observed(&Some(Ok(Observed::StillDeferred)))
            ],
            3,
            0,
            0,
        ),
        "(each boundary's answer with the descriptor held, probes, root reads, range reads)"
    );
}

/// A deferral episode ends at any answer that is not a deferral: a held
/// writer defers over a corrupt head, the head is then refused, and a
/// later deferral over a valid head is reported again.
#[test]
fn a_refusal_between_deferrals_reports_the_second_episode() {
    let fixture = BoundMount::new();
    let observer = fixture.observer();
    let (base_id, doc) = root_doc(&fixture.tree, &fixture.runtime, fixture.tree.seq);
    let corrupt = publish_without(
        &fixture.tree,
        &fixture.runtime,
        fixture.tree.seq,
        doc.manifest_root,
    );
    let events = Events::default();
    let answers = tracing::subscriber::with_default(events.subscriber(), || {
        let deferred = observed(&fixture.observe(&observer, true));
        let refused = observed(&fixture.observe(&observer, false));
        let mut valid = doc.clone();
        valid.seq = corrupt + 1;
        valid.parent = Some(base_id);
        let valid = sign_and_put(&fixture.tree, &fixture.runtime, valid);
        let again = observed(&fixture.observe(&observer, true));
        (deferred, refused, (again, valid))
    });
    let valid = corrupt + 1;
    assert_eq!(
        (answers, view_outcomes(&events)),
        (
            (
                observed(&Some(Ok(Observed::Deferred(corrupt)))),
                observed(&Some(Ok(Observed::HeadRefused(corrupt)))),
                (observed(&Some(Ok(Observed::Deferred(valid)))), valid),
            ),
            vec![
                "deferred".to_owned(),
                "refused".to_owned(),
                "deferred".to_owned()
            ],
        ),
        "((deferral, refusal, (second deferral, its head)), every adopted event)"
    );
}

/// A store that dies while a write-capable descriptor is held is still
/// closed at the next boundary: a deferral with the writer held skips only
/// the probe, not the store's own check, so the view is closed and revoked
/// with its one `op.failed{kind=view}`.
#[test]
fn a_store_that_dies_under_a_held_writer_closes_at_the_next_boundary() {
    let fixture = BoundMount::new();
    let observer = fixture.observer();
    disjoint_head(&fixture.tree, &fixture.runtime);
    let head = fixture.tree.seq + 1;
    let deferred = observed(&fixture.observe(&observer, true));
    fixture.poison();
    let sends = fixture.sends().len();
    let (probes, _, _) = fixture.reads();
    let events = Events::default();
    let closed = tracing::subscriber::with_default(events.subscriber(), || {
        observed(&fixture.observe(&observer, true))
    });
    let sent = eventually(|| fixture.sends().len() == sends + 1);
    let (after, _, _) = fixture.reads();
    assert_eq!(
        (
            deferred,
            closed,
            fixture.view_pending(),
            sent,
            view_failures(&events),
            after - probes
        ),
        (
            observed(&Some(Ok(Observed::Deferred(head)))),
            observed(&Some(Ok(Observed::Closed(None)))),
            Some(true),
            true,
            1,
            0
        ),
        "(first boundary, next boundary with the writer still held, view pending, revoked, \
         op.failed view events, probes the next boundary sent)"
    );
}
