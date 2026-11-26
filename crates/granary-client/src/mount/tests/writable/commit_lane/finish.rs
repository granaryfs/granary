// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The next start finishes what an interrupted shutdown left: each ending a
//! shutdown or a crash can leave, restarted on the same store and cache.

use super::shutdown::{PROFILES, controller, create, unmount_lines, wait_until};
use super::*;
use crate::sync::{Cause, Cut, MountShutdown as _, Outcome, Trigger};
use crate::writable_start::{
    FinishFault, FinishHooks, finish_hooks_for_test, finish_report_for_test,
    late_local_work_for_test, start_faults_for_test,
};
use granary_core::overlay_journal::{
    self as journal, Location, MarkState, Parent, Record, StagingHeader, SyncedMark,
};
use granary_core::overlay_ownership::Phase;
use granary_fuse::MountBackend as _;

/// How long a first process's shutdown runs before its cut.
const BOUND: std::time::Duration = std::time::Duration::from_secs(2);

/// The bytes the first process leaves dirty in `a`.
const DIRTY: &[u8] = b"bytes a shutdown left behind\n";

type Readiness = crate::WritableReadiness<Authority, OverlayDisk>;

mod release;

mod outage;
mod recovery;
mod residual;

fn exhausted_recovery_fixture(uncertain: bool) -> Stopped {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    if uncertain {
        fixture.state.lock().unwrap().publish_timeouts = 8;
    } else {
        fixture.state.lock().unwrap().publish_refusals = 8;
    }
    let lane = construct_commit(&fixture.engine, &fixture.runtime, 70).unwrap();
    let result = drive_commit(&fixture.engine, &fixture.runtime, &lane, 80).unwrap();
    assert!(
        matches!(result.outcome, PublicationOutcome::Exhausted),
        "uncertain={uncertain}: {result:?}"
    );
    let stopped = stop(fixture);
    if uncertain {
        let runtime = runtime();
        disjoint_head(&stopped.tree, &runtime);
        stopped.state.lock().unwrap().head_seq = remote_seq(&stopped.tree, &runtime);
    }
    stopped
}

pub(in crate::mount::tests::writable) fn recover_stopped(
    stopped: &Stopped,
    faults: crate::FaultControl,
) -> Result<(), crate::RecoveryCommandError> {
    let input = input(&stopped.tree, &stopped.paths);
    let (header, _) = captured_records(&stopped.paths, &input);
    let runtime = runtime();
    let store = Store::open(&stopped.paths.store).unwrap();
    let io = OverlayDisk::new(store.publication_root(), input.euid);
    let authority = Authority::new(&stopped.tree, &stopped.state).with_publication();
    let key = SigningKey::from_seed(&stopped.tree.seed).unwrap();
    let keys = granary_store::crypto::TrustedKeys::new([*key.public_key()]).unwrap();
    crate::RecoveryCommand {
        construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
        local: Some((store, io)),
        config: crate::OverlayConfig {
            scope: input.scope.clone().unwrap(),
            volume: input.volume.clone(),
            euid: input.euid,
            cap: 134_217_728,
            ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
            instance: [0; 16],
        },
        transport: &authority,
        runtime: &runtime,
        signer: &key,
        publisher_keys: &keys,
        writer: header.writer,
        acknowledge_takeover: None,
        acknowledge_resend: None,
        faults,
    }
    .run(
        &Arc::new(Time(stopped.state.clone())),
        SigningKey::from_seed(&stopped.tree.seed).unwrap(),
        &mut Entropy(130),
        granary_core::rng::SeededRng::new(2),
    )
    .map(|_| ())
}

#[test]
fn the_recovery_verb_repairs_archived_live_duplicates_before_stripping() {
    let mut outcomes = Vec::new();
    for linked in [false, true] {
        let stopped = exhausted_recovery_fixture(false);
        let faults = crate::FaultControl::default();
        faults.arm("recover.archive", "renamed", 1, crate::FaultAction::Fail);
        let result = recover_stopped(&stopped, faults.clone());
        assert!(result.is_err(), "rename cut did not fire: {result:?}");
        assert_eq!(faults.fired().len(), 1);
        let input = input(&stopped.tree, &stopped.paths);
        let archive = Store::open(&stopped.paths.store)
            .unwrap()
            .publications(input.euid)
            .unwrap()
            .list_archives(&input.volume)
            .unwrap()
            .remove(0);
        let live = archive
            .path
            .with_file_name(format!("{}.sub", archive.submission.volume.as_str()));
        if linked {
            std::fs::hard_link(&archive.path, &live).unwrap();
        } else {
            std::fs::copy(&archive.path, &live).unwrap();
        }
        let result = recover_stopped(&stopped, crate::FaultControl::default());
        let completed = Store::open(&stopped.paths.store)
            .unwrap()
            .publications(input.euid)
            .unwrap()
            .load(input.scope.as_ref().unwrap(), &input.volume)
            .unwrap();
        outcomes.push((
            linked,
            result.err().map(|e| e.to_string()),
            live.exists(),
            completed.is_some_and(|record| {
                record.is_complete() && record.publication_id != archive.submission.publication_id
            }),
        ));
    }
    assert_eq!(
        outcomes,
        [false, true].map(|linked| (linked, None, true, true))
    );
}

#[test]
fn proof_settlement_returns_both_exhausted_lanes_to_normal_service() {
    let mut outcomes = Vec::new();
    let mut logs = Vec::new();
    for uncertain in [false, true] {
        let stopped = exhausted_recovery_fixture(uncertain);
        let settled = recover_stopped(&stopped, crate::FaultControl::default());
        assert!(settled.is_ok(), "uncertain={uncertain}: {settled:?}");
        let input = input(&stopped.tree, &stopped.paths);
        let archive_uncertain = Store::open(&stopped.paths.store)
            .unwrap()
            .publications(input.euid)
            .unwrap()
            .list_archives(&input.volume)
            .unwrap()
            .iter()
            .any(|a| a.uncertain);
        let events = Events::default();
        let mut result = restart(&stopped, &events);
        logs.push(String::from_utf8(events.0.lock().unwrap().clone()).unwrap());
        let refusal = result.as_ref().err().map(|e| format!("{e:?}"));
        let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
        let attached = if let Ok(ready) = &mut result {
            let backend = ready.backend_for_test();
            let remote = Arc::new(Authority::new(&stopped.tree, &stopped.state).with_publication());
            let content = Arc::new(backend.sync_content(remote.clone()).unwrap());
            let runtime = runtime();
            let engine = runtime.block_on(backend.attach_sync_with_runtime(
                remote,
                content,
                Arc::new(Time(stopped.state.clone())),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(90)),
                Arc::new(FastWaitRuntime),
                Entropy(91),
            ));
            engine.is_ok()
        } else {
            false
        };
        outcomes.push((uncertain, refusal, bytes, attached, archive_uncertain));
    }
    assert_eq!(
        outcomes,
        [false, true].map(|uncertain| (uncertain, None, Some(Ok(DIRTY.to_vec())), true, false)),
        "{logs:?}"
    );
}

/// What a stopped first process leaves for the next start.
pub(in crate::mount::tests::writable) struct Stopped {
    pub(in crate::mount::tests::writable) tree: PublishedTree,
    pub(in crate::mount::tests::writable) paths: Paths,
    pub(in crate::mount::tests::writable) state: Arc<Mutex<AuthorityState>>,
}

/// Leave no root registered, in the mount's carrier and in the authority's
/// row alike.
fn clear_registered_root(fixture: &mut EngineMount) {
    {
        let mut state = fixture.state.lock().unwrap();
        let row = state.row.as_mut().unwrap();
        row.state = ReceiptState::Released;
        state.root.clear();
    }
    fixture
        .mediator()
        .with(|store| store.set_carrier_root_for_test(Vec::new()))
        .unwrap();
}

/// The id of the root published at `seq`, if any.
fn root_at(stopped: &Stopped, runtime: &tokio::runtime::Runtime, seq: u64) -> Option<GrainId> {
    runtime
        .block_on(remote_handle(&stopped.tree.mem).get_root(stopped.tree.volume.as_str(), seq))
        .unwrap()
        .map(|bytes| GrainId::of(&bytes))
}

/// The engine fixture in `profile`, its engine driven by two workers.
fn fixture_with(profile: crate::SyncProfile) -> EngineMount {
    EngineMount::with_profile(
        Paths::new(),
        mounted_operation_tree(),
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
        profile,
    )
}

/// Stop the fixture's process as a crash or an ended shutdown would leave
/// it: its runtime stops without running another step, a blocked fault is
/// released into nothing, and every holder of the store lets it go.
fn stop(fixture: EngineMount) -> Stopped {
    let EngineMount {
        ready,
        engine,
        runtime,
        faults,
        state,
        tree,
        paths,
        ..
    } = fixture;
    runtime.shutdown_background();
    faults.resume();
    drop(engine);
    drop(ready);
    wait_until("the stopped process lets the store go", || {
        Store::open(&paths.store).is_ok()
    });
    Stopped { tree, paths, state }
}

/// Run shutdown, permit an observation or persisted test change after its
/// report, then stop the process.
fn shut_down(
    mut fixture: EngineMount,
    bound: std::time::Duration,
    after: impl FnOnce(&mut EngineMount, Outcome),
) -> (Outcome, Stopped) {
    let mediator = fixture.mediator();
    let shutdown = controller(
        &fixture.engine,
        mediator,
        fixture.runtime.handle().clone(),
        bound,
    );
    let outcome = shutdown.begin(Trigger::SessionEnd).outcome;
    drop(shutdown);
    after(&mut fixture, outcome);
    (outcome, stop(fixture))
}

fn no_shutdown_change(_: &mut EngineMount, _: Outcome) {}

/// The next start on the stopped store and cache, through an authority that
/// publishes, its events written to `events`.
fn restart(stopped: &Stopped, events: &Events) -> Result<Readiness, WritableStartError> {
    let input = input(&stopped.tree, &stopped.paths);
    restart_with(&input, &stopped.tree, &stopped.state, events)
}

fn restart_with(
    input: &WritableStart<'_>,
    tree: &PublishedTree,
    state: &Arc<Mutex<AuthorityState>>,
    events: &Events,
) -> Result<Readiness, WritableStartError> {
    tracing::subscriber::with_default(events.subscriber(), || {
        restart_publishing(input, tree, state)
    })
}

/// The start's refusal name, or `Ok`.
fn outcome(result: &Result<Readiness, WritableStartError>) -> &'static str {
    result
        .as_ref()
        .map_or_else(WritableStartError::name, |_| "Ok")
}

/// The registrations sent from the `from`th send on, as each prepared
/// root's id, seq and parent.
fn registered(stopped: &Stopped, from: usize) -> Vec<(GrainId, u64, Option<GrainId>)> {
    stopped.state.lock().unwrap().sends[from..]
        .iter()
        .filter_map(|bytes| intent::decode_register(bytes, &stopped.tree.volume, |_, _| true).ok())
        .map(|request| {
            let doc = root::decode_root(request.root).unwrap();
            (request.root_id(), doc.seq, doc.parent)
        })
        .collect()
}

/// How many ownership handshakes were sent from the `from`th send on.
fn handshakes(stopped: &Stopped, from: usize) -> usize {
    stopped.state.lock().unwrap().sends[from..]
        .iter()
        .filter(|bytes| intent::decode_ownership(bytes).is_ok())
        .count()
}

fn sends(stopped: &Stopped) -> usize {
    stopped.state.lock().unwrap().sends.len()
}

fn publications(stopped: &Stopped) -> usize {
    stopped.state.lock().unwrap().publications.len()
}

/// The authority's head and its id.
fn head(stopped: &Stopped, runtime: &tokio::runtime::Runtime) -> (GrainId, u64) {
    let seq = remote_seq(&stopped.tree, runtime);
    (root_doc(&stopped.tree, runtime, seq).0, seq)
}

/// The `mount.unmount` lines a start emitted, as their trigger, outcome
/// and seq or cause.
fn start_endings(events: &Events) -> Vec<(String, String, String)> {
    let field = |line: &str, name: &str| {
        line.split(&format!("\"{name}\":"))
            .nth(1)
            .map(|rest| {
                rest.trim_start_matches('"')
                    .split(['"', ',', '}'])
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .unwrap_or_default()
    };
    unmount_lines(events)
        .iter()
        .map(|line| {
            let tail = if line.contains("\"cause\"") {
                field(line, "cause")
            } else {
                field(line, "seq")
            };
            (field(line, "trigger"), field(line, "outcome"), tail)
        })
        .collect()
}

/// A start's committed ending at `seq`.
fn committed(seq: u64) -> Vec<(String, String, String)> {
    vec![("start".to_owned(), "committed".to_owned(), seq.to_string())]
}

/// A start's clean ending on the base at `seq`.
fn clean(seq: u64) -> Vec<(String, String, String)> {
    vec![("start".to_owned(), "clean".to_owned(), seq.to_string())]
}

/// The bytes of `path` the restarted mount serves.
fn read_back(ready: &mut Readiness, path: &[u8]) -> Result<Vec<u8>, granary_fuse::WriteError> {
    let backend = ready.backend_for_test();
    let path: Vec<_> = path
        .split(|byte| *byte == b'/')
        .map(|name| granary_core::manifest::Name::new(name.to_vec()))
        .collect::<Result<_, _>>()
        .map_err(|_| granary_fuse::WriteError::Invalid)?;
    let object = backend
        .overlay_open(&path)?
        .ok_or(granary_fuse::WriteError::Missing)?;
    backend.prepare_object(object)?;
    let bytes = backend.read_object(object, 0, 65_536);
    backend.overlay_close(object)?;
    bytes
}

fn at(name: &[u8]) -> Location {
    Location {
        parent: Parent::root(),
        name: granary_core::manifest::Name::new(name.to_vec()).unwrap(),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A shutdown cut while its file's registration is held to the bound
/// leaves the journal dirty on B. The next start publishes one root L at
/// B + 1 holding the dirty bytes, registers the carrier's root, then L
/// itself as the landing's refresh, then L's tree at L + 1 as the serving
/// start does, and serves L. A start that served the dirty journal as it
/// stands refuses, and one whose landing went through the absent adapter's
/// gate refuses the adapter.
#[test]
fn start_finishes_a_dirty_journal_on_its_base() {
    let rt = runtime();
    let mut cases = 0;
    for profile in PROFILES {
        let mut fixture = fixture_with(profile);
        create(fixture.ready.backend_for_test(), "a", DIRTY);
        fixture.faults.arm(
            "sync.registration",
            "before_dispatch",
            1,
            crate::FaultAction::Block,
        );
        let carrier = GrainId::of(
            &fixture
                .mediator()
                .with(|s| Ok(s.snapshot().root.clone()))
                .unwrap(),
        );
        let (cut, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
        let base = stopped.tree.seq;
        let before = sends(&stopped);
        let events = Events::default();
        let faults = crate::FaultControl::default();
        faults.arm(
            "overlay.replace.rename",
            "before",
            2,
            crate::FaultAction::Fail,
        );
        start_faults_for_test(faults.clone());
        let mut result = restart(&stopped, &events);
        start_faults_for_test(crate::FaultControl::default());
        assert!(faults.fired().is_empty());
        let (landed, seq) = head(&stopped, &rt);
        let base_id = root_doc(&stopped.tree, &rt, base).0;
        let roots = registered(&stopped, before);
        let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
        assert_eq!(
            (
                cut,
                outcome(&result),
                (publications(&stopped), seq),
                roots
                    .iter()
                    .map(|(id, _, _)| *id)
                    .take(2)
                    .collect::<Vec<_>>(),
                roots
                    .iter()
                    .map(|(_, seq, parent)| (*seq, *parent))
                    .collect::<Vec<_>>(),
                result.as_ref().ok().map(|ready| ready.verified_base().1),
                bytes,
                start_endings(&events),
            ),
            (
                Outcome::Incomplete(Cause::Deadline),
                "Ok",
                (1, base + 1),
                vec![carrier, landed],
                vec![
                    (base + 1, Some(base_id)),
                    (base + 1, Some(base_id)),
                    (base + 2, Some(landed)),
                ],
                Some(base + 1),
                Some(Ok(DIRTY.to_vec())),
                committed(base + 1),
            ),
            "profile={profile:?}: {:?}",
            result.as_ref().err()
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
    let (bound, inner, timeout, selected) = crate::writable_start::finish_future_sizes_for_test();
    #[cfg(not(feature = "publish-restart-tests"))]
    let limits = (24_832, 12_544, 49_664);
    #[cfg(feature = "publish-restart-tests")]
    let limits = (25_856, 13_056, 51_200);
    assert_eq!(
        (
            bound > 0 && bound <= limits.0,
            inner > 0 && inner <= limits.1,
            timeout > 0 && timeout <= limits.2,
            selected,
        ),
        (true, true, true, 0),
        "test-Authority finish futures: bound={bound}, inner={inner}, timeout={timeout}, limits={limits:?}; production-HttpStore selected future is measured separately"
    );
}

#[test]
fn journal_absent_unmerged_prevents_stage_id_restart() {
    let mut rows = Vec::new();

    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let start_input = input(&tree, &paths);
    let (first, state, _) = attempt(&start_input, &tree, "valid", &Events::default());
    drop(first.unwrap());
    let area = overlay_area(&paths, &start_input);
    std::fs::remove_file(area.join("journal")).unwrap();
    std::fs::create_dir(area.join("unmerged")).unwrap();
    std::fs::set_permissions(
        area.join("unmerged"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let held = area.join("unmerged/0000000000000001");
    std::fs::write(&held, b"held").unwrap();
    std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o600)).unwrap();
    let result = super::super::restart(&start_input, &tree, &state);
    rows.push((
        "serving start",
        match result {
            Err(WritableStartError::Coordination(error)) => error.to_string(),
            Ok(_) => "Ok".to_owned(),
            Err(error) => format!("other: {}", error.name()),
        },
        area.join("journal").exists(),
    ));

    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
    finish_hooks_for_test(FinishHooks {
        fault: FinishFault::JournalAbsentWithUnmerged,
        ..FinishHooks::default()
    });
    let result = restart(&stopped, &Events::default());
    finish_hooks_for_test(FinishHooks::default());
    let finish_area = overlay_area(&stopped.paths, &input(&stopped.tree, &stopped.paths));
    rows.push((
        "interrupted finish",
        match result {
            Err(WritableStartError::Coordination(error)) => error.to_string(),
            Ok(_) => "Ok".to_owned(),
            Err(error) => format!("other: {}", error.name()),
        },
        finish_area.join("journal").exists(),
    ));

    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (
                    "serving start",
                    "intent refused: IntentUnmergedUnclassified".to_owned(),
                    false,
                ),
                (
                    "interrupted finish",
                    "overlay refused: journal missing beside unmerged".to_owned(),
                    false,
                ),
            ],
            2,
        )
    );
}

/// The same cut, then another writer publishes D above B: the phase's
/// session is at B, its commit rebases onto D before its first attempt, so
/// no attempt is answered stale-base, and lands at D + 1,
/// and the serving session and the journal's header are on D + 1. With no
/// registered root, the phase registers B's tree at B + 1 first.
#[test]
fn start_finishes_on_an_advanced_head() {
    let rt = runtime();
    let mut cases = 0;
    for profile in PROFILES {
        for registered_root in [true, false] {
            let mut fixture = fixture_with(profile);
            create(fixture.ready.backend_for_test(), "a", DIRTY);
            fixture.faults.arm(
                "sync.registration",
                "before_dispatch",
                1,
                crate::FaultAction::Block,
            );
            if !registered_root {
                clear_registered_root(&mut fixture);
            }
            let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
            let base = stopped.tree.seq;
            let (base_id, base_doc) = root_doc(&stopped.tree, &rt, base);
            disjoint_head(&stopped.tree, &rt);
            let advanced = base + 1;
            let before = sends(&stopped);
            let events = Events::default();
            let faults = crate::FaultControl::default();
            faults.arm(
                "overlay.replace.rename",
                "before",
                2,
                crate::FaultAction::Fail,
            );
            start_faults_for_test(faults.clone());
            let mut result = restart(&stopped, &events);
            start_faults_for_test(crate::FaultControl::default());
            assert!(faults.fired().is_empty());
            let (landed, seq) = head(&stopped, &rt);
            let first = registered(&stopped, before).first().copied();
            let header = captured_records(&stopped.paths, &input(&stopped.tree, &stopped.paths)).0;
            let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
            let first_tree = (!registered_root).then(|| {
                let bytes = stopped.state.lock().unwrap().sends[before..]
                    .iter()
                    .find_map(|bytes| {
                        intent::decode_register(bytes, &stopped.tree.volume, |_, _| true)
                            .ok()
                            .map(|request| request.root.to_vec())
                    })
                    .unwrap();
                root::decode_root(&bytes).unwrap().manifest_root
            });
            assert_eq!(
                (
                    outcome(&result),
                    (
                        publications(&stopped),
                        stopped.state.lock().unwrap().stale_bases,
                        seq
                    ),
                    result.as_ref().ok().map(|ready| ready.verified_base().1),
                    (header.base_root, header.base_seq),
                    first.map(|(_, seq, parent)| (seq, parent)),
                    first_tree,
                    bytes,
                    start_endings(&events),
                ),
                (
                    "Ok",
                    (1, 0, advanced + 1),
                    Some(advanced + 1),
                    (landed, advanced + 1),
                    Some((base + 1, Some(base_id))),
                    (!registered_root).then_some(base_doc.manifest_root),
                    Some(Ok(DIRTY.to_vec())),
                    committed(advanced + 1),
                ),
                "profile={profile:?}, registered root={registered_root}: {:?}",
                result.as_ref().err()
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

/// A lane cut before its submission, or cut before the rebase another
/// writer's head made it owe, with a file written after its boundary: the
/// next start registers nothing before the attach, lands the lane under
/// explicit recovery, then publishes the rest once, above the head.
#[test]
fn start_finishes_a_retained_lane_then_the_rest() {
    let rt = runtime();
    let mut cases = 0;
    for profile in PROFILES {
        for phase in ["before_submit", "before_rebase"] {
            let mut fixture = fixture_with(profile);
            let object = dirty(&mut fixture);
            fixture
                .faults
                .arm("sync.commit", phase, 1, crate::FaultAction::Fail);
            let lane = fixture.construct(70).unwrap();
            if phase == "before_rebase" {
                disjoint_head(&fixture.tree, &fixture.runtime);
            }
            let cut = fixture.drive(&lane, 80);
            assert!(
                cut.as_ref()
                    .is_err_and(|error| error.to_string().contains("SyncInjectedFault")),
                "premise: the first drive is cut: {cut:?}"
            );
            fixture
                .ready
                .backend_for_test()
                .overlay_close(object)
                .unwrap();
            create(fixture.ready.backend_for_test(), "later", DIRTY);
            let stopped = stop(fixture);
            // The head the lane lands above: the base, or the other writer's.
            let head = remote_seq(&stopped.tree, &rt);
            let attempts = publications(&stopped);
            let before = sends(&stopped);
            let events = Events::default();
            let mut result = restart(&stopped, &events);
            let roots: Vec<_> = registered(&stopped, before)
                .iter()
                .map(|(id, seq, _)| (Some(*id), *seq))
                .collect();
            let bytes = result
                .as_mut()
                .ok()
                .map(|ready| (read_back(ready, b"f.txt"), read_back(ready, b"later")));
            assert_eq!(
                (
                    outcome(&result),
                    (
                        publications(&stopped) - attempts,
                        remote_seq(&stopped.tree, &rt)
                    ),
                    roots.get(..2).map(<[_]>::to_vec),
                    bytes,
                    start_endings(&events),
                ),
                (
                    "Ok",
                    (2, head + 2),
                    Some(vec![
                        (root_at(&stopped, &rt, head + 1), head + 1),
                        (root_at(&stopped, &rt, head + 2), head + 2)
                    ]),
                    Some((Ok(dirty_bytes()), Ok(DIRTY.to_vec()))),
                    committed(head + 2),
                ),
                "profile={profile:?}, cut {phase}: {:?}",
                result.as_ref().err()
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

/// A landing and refresh left durable before journal replacement.
fn recorded_landing(
    profile: crate::SyncProfile,
    remote_files: &[&str],
    bytes: &[u8],
    empty_files: usize,
) -> (Outcome, Stopped) {
    let mut fixture = fixture_with(profile);
    create(fixture.ready.backend_for_test(), "a", bytes);
    for index in 0..empty_files {
        create(
            fixture.ready.backend_for_test(),
            &format!("empty-{index:02}"),
            b"",
        );
    }
    if !remote_files.is_empty() {
        publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
            for name in remote_files {
                if let Some(name) = name.strip_prefix('!') {
                    std::fs::remove_dir_all(source.join(name)).unwrap();
                    continue;
                }
                std::fs::create_dir_all(source.join(name).parent().unwrap()).unwrap();
                std::fs::write(source.join(name), FOREIGN_CONTENT).unwrap();
            }
        });
    }
    fixture
        .faults
        .arm("sync.commit", "before_replace", 1, crate::FaultAction::Fail);
    shut_down(
        fixture,
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
        no_shutdown_change,
    )
}

/// A shutdown's commit landed and recorded, cut before its replacement:
/// the next start publishes nothing, consumes the durable refresh witness and
/// serves L after registering only its next prepared root.
#[test]
fn start_finishes_a_recorded_landing() {
    let rt = runtime();
    let mut cases = 0;
    for profile in PROFILES {
        let (cut, stopped) = recorded_landing(profile, &[], DIRTY, 0);
        let base = stopped.tree.seq;
        let landed = (publications(&stopped), remote_seq(&stopped.tree, &rt));
        let before = sends(&stopped);
        let events = Events::default();
        let mut result = restart(&stopped, &events);
        let landed_id = root_at(&stopped, &rt, base + 1);
        let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
        assert_eq!(
            (
                (cut, landed),
                outcome(&result),
                publications(&stopped),
                registered(&stopped, before)
                    .iter()
                    .map(|(id, seq, _)| (Some(*id) == landed_id, *seq))
                    .collect::<Vec<_>>(),
                result
                    .as_ref()
                    .ok()
                    .map(|ready| (ready.verified_base().2, ready.verified_base().1)),
                bytes,
                start_endings(&events),
            ),
            (
                (
                    Outcome::Incomplete(Cause::Failed(crate::FailureClass::Io)),
                    (1, base + 1)
                ),
                "Ok",
                1,
                vec![(false, base + 2)],
                landed_id.map(|id| (id, base + 1)),
                Some(Ok(DIRTY.to_vec())),
                committed(base + 1),
            ),
            "profile={profile:?}: {:?}",
            result.as_ref().err()
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A shutdown's commit cut after its boundary is recorded and before its
/// publication record begins: the next start strips the boundary, which
/// was never sent, and one publication carries the records.
#[test]
fn start_strips_a_boundary_with_no_record() {
    let rt = runtime();
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.faults.arm(
        "sync.commit",
        "boundary_recorded",
        1,
        crate::FaultAction::Fail,
    );
    let (cut, stopped) = shut_down(
        fixture,
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
        no_shutdown_change,
    );
    let base = stopped.tree.seq;
    let boundaries = captured_records(&stopped.paths, &input(&stopped.tree, &stopped.paths))
        .1
        .iter()
        .filter(|record| matches!(record, Record::CommitBoundary { .. }))
        .count();
    let published = publications(&stopped);
    let events = Events::default();
    let mut result = restart(&stopped, &events);
    let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
    assert_eq!(
        (
            (cut, boundaries, published),
            outcome(&result),
            (publications(&stopped), remote_seq(&stopped.tree, &rt)),
            bytes,
            start_endings(&events),
        ),
        (
            (
                Outcome::Incomplete(Cause::Failed(crate::FailureClass::Io)),
                1,
                0
            ),
            "Ok",
            (1, base + 1),
            Some(Ok(DIRTY.to_vec())),
            committed(base + 1),
        ),
        "{:?}",
        result.as_ref().err()
    );
}

/// A file's registration answered as unavailable and cut before its
/// completion leaves a Register with its capture's context, which the
/// succession retires: the next start fails the reopened capture, commits
/// the stage, and registers one refresh.
#[test]
fn start_fails_a_reopened_capture_and_commits_its_stage() {
    let rt = runtime();
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.state.lock().unwrap().registrations_served = Some(0);
    fixture.faults.arm(
        "sync.registration",
        "after_response",
        1,
        crate::FaultAction::Block,
    );
    let (cut, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
    stopped.state.lock().unwrap().registrations_served = None;
    let base = stopped.tree.seq;
    let contexts = {
        let input = input(&stopped.tree, &stopped.paths);
        let bytes = std::fs::read(overlay_area(&stopped.paths, &input).join("ownership")).unwrap();
        granary_core::overlay_ownership::decode(&bytes)
            .unwrap()
            .pending
            .iter()
            .filter(|pending| !pending.context.is_empty())
            .count()
    };
    let before = sends(&stopped);
    let events = Events::default();
    let mut result = restart(&stopped, &events);
    let landed = root_at(&stopped, &rt, base + 1);
    let refreshes = registered(&stopped, before)
        .iter()
        .filter(|(id, _, _)| Some(*id) == landed)
        .count();
    let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
    assert_eq!(
        (
            (cut, contexts),
            outcome(&result),
            (publications(&stopped), remote_seq(&stopped.tree, &rt)),
            refreshes,
            bytes,
            start_endings(&events),
        ),
        (
            (Outcome::Incomplete(Cause::Deadline), 1),
            "Ok",
            (1, base + 1),
            1,
            Some(Ok(DIRTY.to_vec())),
            committed(base + 1),
        ),
        "{:?}",
        result.as_ref().err()
    );
}

/// A first start, then `stop` on its ready mount before its process ends.
fn first_start(
    tree: &PublishedTree,
    paths: &Paths,
    stop: impl FnOnce(&mut Readiness, &Arc<Mutex<AuthorityState>>),
) -> Arc<Mutex<AuthorityState>> {
    let (result, state, _) = attempt(&input(tree, paths), tree, "valid", &Events::default());
    let mut ready = result.unwrap_or_else(|error| panic!("first start refused: {error}"));
    stop(&mut ready, &state);
    drop(ready);
    state
}

/// Create `name` with a stage made durable and its record never appended:
/// a crash right after the staging directory's sync.
fn crash_after_stage(ready: &mut Readiness, name: &[u8]) {
    let faults = ready.mediator_for_test().fault_control();
    faults.arm(
        "overlay.stage.dir_sync",
        "after",
        1,
        crate::FaultAction::Fail,
    );
    let created = ready
        .backend_for_test()
        .overlay_mutate(granary_fuse::OverlayMutation::Create {
            path: &handler_path(name),
            kind: granary_vfs::NodeKind::File,
            exec: false,
        });
    assert!(created.is_err(), "premise: the create is cut");
}

/// The journal's bytes and every staging file.
fn evidence(paths: &Paths, tree: &PublishedTree) -> (Vec<u8>, BTreeMap<String, Vec<u8>>) {
    let input = input(tree, paths);
    (
        std::fs::read(overlay_area(paths, &input).join("journal")).unwrap(),
        captured_staging(paths, &input),
    )
}

/// A stage made durable with no record beside a clean journal: the next
/// start's phase replays on B, sweeps it, finds nothing owed and reports a
/// clean finish, registering nothing of its own, and the start serves B.
/// With another writer's head D published first, the start then carries the
/// clean journal to D and serves D, which a start that took the staging for
/// clean refuses as a base mismatch. Beside a dirty journal, the phase
/// commits the journal and never the stage. Given a valid mark by hand, the
/// stage is damage: the phase refuses and keeps the journal, the stage and
/// the registered root.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one stage left by a crash, in four settings"
)]
fn orphan_stage_sweeps_but_synced_orphan_evidence_is_preserved() {
    let rt = runtime();
    let mut outcomes = Vec::new();
    for case in ["clean", "advanced head", "dirty journal", "valid mark"] {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let mut writer = [0; 16];
        let state = first_start(&tree, &paths, |ready, _| {
            writer = ready.mediator_for_test().writer_uuid();
            if case == "dirty journal" {
                ready
                    .mediator_for_test()
                    .overlay_transaction(|overlay| {
                        overlay.namespace_record(Record::Move {
                            from: at(b"f.txt"),
                            to: at(b"moved.txt"),
                        })
                    })
                    .unwrap();
            }
            crash_after_stage(ready, b"new");
        });
        let stopped = Stopped { tree, paths, state };
        let staged = evidence(&stopped.paths, &stopped.tree).1;
        if case == "valid mark" {
            let (name, _) = staged.iter().next().unwrap();
            let stage_id = u64::from_str_radix(name, 16).unwrap();
            let header = StagingHeader {
                writer,
                stage_id,
                mark: MarkState::Present(SyncedMark {
                    synced_size: 0,
                    content: GrainId::of(b""),
                    generation: 1,
                }),
            }
            .encode()
            .unwrap();
            let input = input(&stopped.tree, &stopped.paths);
            let path = overlay_area(&stopped.paths, &input)
                .join("staging")
                .join(name);
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[..header.len()].copy_from_slice(&header);
            std::fs::write(&path, bytes).unwrap();
        }
        if case == "advanced head" {
            disjoint_head(&stopped.tree, &rt);
        }
        let base = stopped.tree.seq;
        let registered_root = stopped.state.lock().unwrap().root.clone();
        let before = (
            evidence(&stopped.paths, &stopped.tree),
            registered_root,
            sends(&stopped),
        );
        let events = Events::default();
        let mut result = restart(&stopped, &events);
        let after = evidence(&stopped.paths, &stopped.tree);
        let roots = registered(&stopped, before.2);
        let served = result.as_ref().ok().map(|ready| ready.verified_base().1);
        let files = result.as_mut().ok().map(|ready| {
            (
                read_back(ready, b"new").is_err(),
                read_back(ready, b"moved.txt").is_ok(),
            )
        });
        let observed = (
            outcome(&result),
            (staged.len(), after.1.len()),
            served,
            roots.len(),
            publications(&stopped),
            files,
            start_endings(&events),
        );
        let expected = match case {
            "clean" => (
                "Ok",
                (1, 0),
                Some(base),
                1,
                0,
                Some((true, false)),
                clean(base),
            ),
            "advanced head" => (
                "Ok",
                (1, 0),
                Some(base + 1),
                1,
                0,
                Some((true, false)),
                clean(base),
            ),
            "dirty journal" => (
                "Ok",
                (1, 0),
                Some(base + 1),
                3,
                1,
                Some((true, true)),
                committed(base + 1),
            ),
            _ => (
                "unnamed synced staging evidence",
                (1, 1),
                None,
                0,
                0,
                None,
                vec![(
                    "start".to_owned(),
                    "incomplete".to_owned(),
                    "failed".to_owned(),
                )],
            ),
        };
        if case == "valid mark" {
            let registered_root = stopped.state.lock().unwrap().root.clone();
            assert_eq!(
                (after == before.0, registered_root == before.1),
                (true, true),
                "valid mark: the journal, the stage and the registered root are kept"
            );
        }
        outcomes.push(observed == expected);
        assert_eq!(observed, expected, "{case}: {:?}", result.as_ref().err());
    }
    assert_eq!(outcomes, [true; 4]);
    assert_eq!(outcomes.len(), 4, "nonzero orphan-stage cases");
}

/// Replay accepts and syncs a valid torn tail, but a journal naming an
/// unanchored stage whose file is absent refuses without changing evidence.
#[test]
fn torn_tail_replays_and_missing_unanchored_stage_refuses() {
    let mut cases = 0;
    for missing in [false, true] {
        let stopped = if missing {
            let tree = mounted_operation_tree();
            let paths = Paths::new();
            let state = first_start(&tree, &paths, |ready, _| {
                create(ready.backend_for_test(), "a", DIRTY);
            });
            let stopped = Stopped { tree, paths, state };
            let input = input(&stopped.tree, &stopped.paths);
            let staging = overlay_area(&stopped.paths, &input).join("staging");
            let names: Vec<_> = std::fs::read_dir(&staging)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(names.len(), 1, "premise: one unanchored stage");
            std::fs::remove_file(&names[0]).unwrap();
            stopped
        } else {
            let tree = mounted_operation_tree();
            let paths = Paths::new();
            let state = first_start(&tree, &paths, |_, _| ());
            let input = input(&tree, &paths);
            let path = overlay_area(&paths, &input).join("journal");
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                bytes.len() > journal::JOURNAL_HEADER_LEN + 4,
                "premise: the journal holds a record"
            );
            std::fs::write(&path, &bytes[..bytes.len() - 3]).unwrap();
            Stopped { tree, paths, state }
        };
        let input = input(&stopped.tree, &stopped.paths);
        let path = overlay_area(&stopped.paths, &input).join("journal");
        let before = (sends(&stopped), evidence(&stopped.paths, &stopped.tree));
        let events = Events::default();
        let result = restart(&stopped, &events);
        if missing {
            assert_eq!(
                (
                    outcome(&result),
                    registered(&stopped, before.0).len(),
                    evidence(&stopped.paths, &stopped.tree) == before.1,
                    start_endings(&events),
                ),
                (
                    "missing unanchored staging",
                    0,
                    true,
                    vec![(
                        "start".to_owned(),
                        "incomplete".to_owned(),
                        "failed".to_owned(),
                    )],
                ),
                "missing stage: {:?}",
                result.as_ref().err()
            );
        } else {
            assert_eq!(
                (
                    journal::scan_journal(&std::fs::read(&path).unwrap())
                        .map(|scan| scan.end == journal::JournalEnd::Clean)
                        .ok(),
                    outcome(&result),
                    registered(&stopped, before.0).len(),
                    publications(&stopped),
                    start_endings(&events),
                ),
                (Some(true), "Ok", 1, 0, clean(stopped.tree.seq)),
                "torn tail: {:?}",
                result.as_ref().err()
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2, "nonzero paired replay cases");
}

/// A second authenticated replay read fails after the first missing stage was
/// durably rebuilt. Completion stays absent; a restored read reopens both.
#[test]
fn failed_authenticated_read_after_repair_never_reports_completion() {
    let tree = mounted_operation_tree();
    let paths = Paths::new();
    let state = first_start(&tree, &paths, |ready, _| {
        for path in [b"f.txt".as_slice(), b"sub/g.txt".as_slice()] {
            let path: Vec<_> = path
                .split(|byte| *byte == b'/')
                .map(|name| granary_core::manifest::Name::new(name.to_vec()).unwrap())
                .collect();
            let object = ready
                .backend_for_test()
                .overlay_open(&path)
                .unwrap()
                .unwrap();
            assert!(object > 0, "premise: writable object identity");
            ready.backend_for_test().prepare_object(object).unwrap();
            ready
                .backend_for_test()
                .overlay_mutate(granary_fuse::OverlayMutation::BoundSetattr {
                    object,
                    size: Some(FILE_CONTENT.len() as u64),
                    exec: None,
                })
                .unwrap();
        }
    });
    let stopped = Stopped { tree, paths, state };
    let input = input(&stopped.tree, &stopped.paths);
    let staging = overlay_area(&stopped.paths, &input).join("staging");
    let names: Vec<_> = std::fs::read_dir(&staging)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(names.len(), 2, "premise: two anchored stages");
    for path in &names {
        std::fs::remove_file(path).unwrap();
    }
    let faults = crate::FaultControl::default();
    faults.arm(
        "overlay.replay.authenticated_read",
        "before",
        2,
        crate::FaultAction::Fail,
    );
    start_faults_for_test(faults.clone());
    let events = Events::default();
    let result = restart(&stopped, &events);
    start_faults_for_test(crate::FaultControl::default());
    let staged = captured_staging(&stopped.paths, &input);
    let repaired = staged
        .values()
        .filter(|bytes| bytes.get(160..) == Some(FILE_CONTENT))
        .count();
    assert_eq!(
        (
            result.is_err(),
            format!("{:?}", result.as_ref().err()).contains("overlay injected fault"),
            faults.fired().len(),
            repaired,
            start_endings(&events),
        ),
        (
            true,
            true,
            1,
            1,
            vec![(
                "start".to_owned(),
                "incomplete".to_owned(),
                "failed".to_owned(),
            )],
        ),
        "failed authenticated read after repair: {:?}",
        result.as_ref().err()
    );
    let restored = Events::default();
    let mut result = restart(&stopped, &restored);
    let bytes = result
        .as_mut()
        .ok()
        .map(|ready| (read_back(ready, b"f.txt"), read_back(ready, b"sub/g.txt")));
    assert_eq!(
        (outcome(&result), bytes, start_endings(&restored)),
        (
            "Ok",
            Some((Ok(FILE_CONTENT.to_vec()), Ok(FILE_CONTENT.to_vec()))),
            committed(stopped.tree.seq + 1),
        ),
        "restored read: {:?}",
        result.as_ref().err()
    );
}

/// The phase's commit held past its bound, before its submission or once
/// its landing is recorded and before its readback: the start refuses as
/// the authority's unavailability, keeps every journal record, every
/// staging file and the carrier, and reports the deadline; the next start
/// finds the lane and lands it, or finishes the recorded landing without
/// publishing again.
#[test]
fn a_phase_past_its_bound_refuses_and_keeps_everything() {
    // The finish bound under test. Wider than the module's BOUND so that the
    // restart reaches the held phase before it expires, even when its durable
    // syncs are contended full-device flushes (F_FULLFSYNC on Apple).
    const PHASE_BOUND: std::time::Duration = std::time::Duration::from_secs(6);
    let rt = runtime();
    let mut cases = 0;
    for profile in PROFILES {
        for phase in ["before_submit", "landed_readback"] {
            let mut fixture = fixture_with(profile);
            create(fixture.ready.backend_for_test(), "a", DIRTY);
            fixture.faults.arm(
                "sync.registration",
                "before_dispatch",
                1,
                crate::FaultAction::Block,
            );
            let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
            let base = stopped.tree.seq;
            let input = input(&stopped.tree, &stopped.paths);
            let (_, records) = captured_records(&stopped.paths, &input);
            let staging = captured_staging(&stopped.paths, &input);
            let faults = crate::FaultControl::default();
            faults.arm("sync.commit", phase, 1, crate::FaultAction::Block);
            start_faults_for_test(faults.clone());
            finish_hooks_for_test(FinishHooks {
                bound: Some(PHASE_BOUND),
                budget: Some(PHASE_BOUND),
                dispatch_floor: Some(BOUND / 2),
                ..FinishHooks::default()
            });
            let resume = std::thread::spawn({
                let faults = faults.clone();
                move || {
                    super::shutdown::wait_fired(&faults, "sync.commit", phase);
                    std::thread::sleep(PHASE_BOUND + std::time::Duration::from_secs(1));
                    faults.resume();
                }
            });
            let events = Events::default();
            let result = restart(&stopped, &events);
            resume.join().unwrap();
            finish_hooks_for_test(FinishHooks::default());
            let (_, kept) = captured_records(&stopped.paths, &input);
            let carrier = granary_core::overlay_ownership::decode(
                &std::fs::read(overlay_area(&stopped.paths, &input).join("ownership")).unwrap(),
            )
            .unwrap();
            let first = (
                outcome(&result),
                kept.starts_with(&records),
                staging
                    .keys()
                    .all(|name| captured_staging(&stopped.paths, &input).contains_key(name)),
                carrier.phase,
                publications(&stopped),
                start_endings(&events),
            );
            let again = Events::default();
            let second = restart(&stopped, &again);
            assert_eq!(
                (
                    first,
                    outcome(&second),
                    (publications(&stopped), remote_seq(&stopped.tree, &rt)),
                    start_endings(&again),
                ),
                (
                    (
                        "WritableAuthorityUnavailable",
                        true,
                        true,
                        Phase::Serving,
                        usize::from(phase == "landed_readback"),
                        vec![(
                            "start".to_owned(),
                            "incomplete".to_owned(),
                            "deadline".to_owned()
                        )],
                    ),
                    "Ok",
                    (1, base + 1),
                    committed(base + 1),
                ),
                "profile={profile:?}, held at {phase}: {:?}",
                second.as_ref().err()
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

/// A `Retry-After` wait in the finish's pre-engine registration is cut by
/// the finish's admission-time bound and reported exactly as an engine cut.
/// Wall-clock observation allows 750 ms for a loaded worker to be rescheduled.
#[test]
fn a_pre_engine_retry_wait_uses_the_finish_bound() {
    const FINISH_BOUND: std::time::Duration = std::time::Duration::from_millis(250);
    const SCHEDULER_MARGIN: std::time::Duration = std::time::Duration::from_millis(750);
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
    {
        let mut state = stopped.state.lock().unwrap();
        state.intent_retry_after = Some(60);
        state.intent_wait_delay = Some(std::time::Duration::from_secs(2));
    }
    finish_hooks_for_test(FinishHooks {
        bound: Some(FINISH_BOUND),
        ..FinishHooks::default()
    });
    let events = Events::default();
    let started = crate::SyncRuntime::now(&crate::TokioSyncRuntime);
    let result = restart(&stopped, &events);
    let elapsed = crate::SyncRuntime::now(&crate::TokioSyncRuntime)
        .checked_duration_since(started)
        .unwrap_or_default();
    let report = finish_report_for_test();
    finish_hooks_for_test(FinishHooks::default());
    let state = stopped.state.lock().unwrap();
    let observed_wait = state.intent_wait_observed;
    let wait_within_remaining = observed_wait.is_none_or(|(wait_started, waited)| {
        let spent = wait_started
            .checked_duration_since(started)
            .unwrap_or_default();
        let remaining = FINISH_BOUND.saturating_sub(spent);
        waited <= remaining.saturating_add(SCHEDULER_MARGIN)
    });
    assert_eq!(
        (
            outcome(&result),
            start_endings(&events),
            report.map(|report| (report.outcome, report.cut)),
            elapsed <= FINISH_BOUND.saturating_add(SCHEDULER_MARGIN),
            wait_within_remaining,
        ),
        (
            "WritableAuthorityUnavailable",
            vec![(
                "start".to_owned(),
                "incomplete".to_owned(),
                "deadline".to_owned(),
            )],
            Some((Outcome::Incomplete(Cause::Deadline), Some(Cut::Bound))),
            true,
            true,
        ),
        "pre-engine retry cut: {:?}, elapsed={elapsed:?}, observed_wait={observed_wait:?}, margin={SCHEDULER_MARGIN:?}",
        result.as_ref().err(),
    );
}

/// A root read that returns after the finish bound is refused before local
/// snapshot or replay work begins.
#[test]
fn an_open_that_returns_after_the_finish_bound_does_not_replay() {
    const FINISH_BOUND: std::time::Duration = std::time::Duration::from_millis(100);
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
    let faults = crate::FaultControl::default();
    faults.arm(
        "overlay.replay.authenticated_read",
        "before",
        1,
        crate::FaultAction::Fail,
    );
    start_faults_for_test(faults.clone());
    finish_hooks_for_test(FinishHooks {
        bound: Some(FINISH_BOUND),
        after_open_delay: Some(FINISH_BOUND * 2),
        ..FinishHooks::default()
    });
    let events = Events::default();
    let result = restart(&stopped, &events);
    let report = finish_report_for_test();
    let late_local_work = late_local_work_for_test();
    finish_hooks_for_test(FinishHooks::default());
    start_faults_for_test(crate::FaultControl::default());
    assert_eq!(
        (
            outcome(&result),
            faults.fired().len(),
            late_local_work,
            report.map(|report| (report.outcome, report.cut)),
            start_endings(&events),
        ),
        (
            "WritableAuthorityUnavailable",
            0,
            false,
            Some((Outcome::Incomplete(Cause::Deadline), Some(Cut::Bound))),
            vec![(
                "start".to_owned(),
                "incomplete".to_owned(),
                "deadline".to_owned(),
            )],
        ),
        "late open must cut before replay: {:?}",
        result.as_ref().err()
    );
}

/// An authority answer produced by a non-yielding poll just after the bound is
/// retained locally before the finish reports its deadline cut.
#[test]
fn a_late_pre_engine_answer_is_recorded_before_the_deadline_cut() {
    const FINISH_BOUND: std::time::Duration = std::time::Duration::from_millis(100);
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
    stopped.state.lock().unwrap().intent_reply_block = Some(FINISH_BOUND * 2);
    finish_hooks_for_test(FinishHooks {
        bound: Some(FINISH_BOUND),
        ..FinishHooks::default()
    });
    let events = Events::default();
    let result = restart(&stopped, &events);
    let report = finish_report_for_test();
    finish_hooks_for_test(FinishHooks::default());
    let input = input(&stopped.tree, &stopped.paths);
    let carrier = granary_core::overlay_ownership::decode(
        &std::fs::read(overlay_area(&stopped.paths, &input).join("ownership")).unwrap(),
    )
    .unwrap();
    let state = stopped.state.lock().unwrap();
    let applied = state.registration_requests.last().copied();
    let completed = carrier
        .pending
        .iter()
        .find(|pending| Some(GrainId::of(&pending.body)) == applied)
        .map(|pending| pending.terminal);
    assert_eq!(
        (
            outcome(&result),
            state.row.is_some(),
            completed != Some(false),
            report.map(|report| (report.outcome, report.cut)),
            start_endings(&events),
        ),
        (
            "WritableAuthorityUnavailable",
            true,
            true,
            Some((Outcome::Incomplete(Cause::Deadline), Some(Cut::Bound))),
            vec![(
                "start".to_owned(),
                "incomplete".to_owned(),
                "deadline".to_owned(),
            )],
        ),
        "late answer settlement: {:?}",
        result.as_ref().err()
    );
}

/// Local pre-engine invariants and post-engine mediator poison each preserve
/// the finish's own refusal and emit exactly one ending.
#[test]
fn every_finish_exit_reports_its_own_outcome_once() {
    let mut cases = 0;
    for case in ["base", "pin", "poison"] {
        let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
        create(fixture.ready.backend_for_test(), "a", DIRTY);
        fixture.faults.arm(
            "sync.registration",
            "before_dispatch",
            1,
            crate::FaultAction::Block,
        );
        let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
        finish_hooks_for_test(FinishHooks {
            unchanged_base: case == "poison",
            fault: match case {
                "base" => FinishFault::MissingBase,
                "pin" => FinishFault::MissingPin,
                _ => FinishFault::PoisonBeforeReport,
            },
            ..FinishHooks::default()
        });
        let events = Events::default();
        let result = restart(&stopped, &events);
        let report = finish_report_for_test();
        finish_hooks_for_test(FinishHooks::default());
        let expected = if case == "poison" {
            "WritableRecoveryRequired"
        } else {
            "SyncBase"
        };
        let class = if case == "poison" {
            crate::observe::FailureClass::Internal
        } else {
            crate::observe::FailureClass::Refused
        };
        assert_eq!(
            (
                outcome(&result),
                report.map(|report| report.outcome),
                start_endings(&events),
            ),
            (
                expected,
                Some(Outcome::Incomplete(Cause::Failed(class))),
                vec![(
                    "start".to_owned(),
                    "incomplete".to_owned(),
                    "failed".to_owned(),
                )],
            ),
            "case={case}: {:?}",
            result.as_ref().err()
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

/// An engine that answers without moving the journal's base violates the
/// start finish invariant even when every residual obligation is clear.
#[test]
fn an_engine_finish_that_does_not_move_the_base_is_refused() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
    finish_hooks_for_test(FinishHooks {
        unchanged_base: true,
        ..FinishHooks::default()
    });
    let events = Events::default();
    let result = restart(&stopped, &events);
    finish_hooks_for_test(FinishHooks::default());
    assert_eq!(
        (
            outcome(&result),
            start_endings(&events),
            events.failed("internal"),
        ),
        (
            "WritableRecoveryRequired",
            vec![(
                "start".to_owned(),
                "incomplete".to_owned(),
                "failed".to_owned(),
            )],
            true,
        ),
        "unchanged post-engine base: {:?}",
        result.as_ref().err()
    );
}

/// A fenced carrier refuses before any phase, which reports nothing:
/// `Phase::Fenced` as the intent's fence. A journal's `CommitFence` record
/// fences the phase at its boundary, as recovery required, reported as a
/// fence. Neither sends a registration or a publication.
#[test]
fn a_fenced_store_runs_no_phase() {
    let mut outcomes = Vec::new();
    for case in ["fenced phase", "commit fence"] {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let state = first_start(&tree, &paths, |ready, _| {
            let mediator = ready.mediator_for_test();
            mediator
                .overlay_transaction(|overlay| {
                    overlay.namespace_record(Record::Move {
                        from: at(b"f.txt"),
                        to: at(b"moved.txt"),
                    })
                })
                .unwrap();
            if case == "fenced phase" {
                mediator.phase_for_test(Phase::Fenced).unwrap();
            } else {
                mediator
                    .overlay_transaction(|overlay| {
                        let capture = overlay.capture_boundary()?;
                        let boundary =
                            overlay.record_boundary(capture, GrainId::of(b"candidate"), [7; 16])?;
                        overlay.record_commit_fence(boundary, [7; 16])
                    })
                    .unwrap();
            }
        });
        let stopped = Stopped { tree, paths, state };
        let before = sends(&stopped);
        let events = Events::default();
        let result = restart(&stopped, &events);
        outcomes.push((
            case,
            outcome(&result),
            registered(&stopped, before).len(),
            publications(&stopped),
            start_endings(&events),
        ));
    }
    assert_eq!(
        outcomes,
        [
            ("fenced phase", "IntentFenced (ESTALE)", 0, 0, vec![]),
            (
                "commit fence",
                "WritableRecoveryRequired",
                0,
                0,
                vec![("start".to_owned(), "fenced".to_owned(), "failed".to_owned())]
            ),
        ]
    );
}

/// After the phase the same store serves: the start opens one store, the
/// phase's registrations and the serving owner share one instance, and one
/// handshake is sent. An engine clone still held at the teardown refuses
/// the hand-back after the finish reported its commit, with the start's
/// own failure reported beside it; a detach while a lane is retained
/// refuses too.
#[test]
fn the_phase_hands_the_store_back() {
    let mut outcomes = Vec::new();
    let mut stopped_seq = 0;
    for held in [false, true] {
        let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
        create(fixture.ready.backend_for_test(), "a", DIRTY);
        fixture.faults.arm(
            "sync.registration",
            "before_dispatch",
            1,
            crate::FaultAction::Block,
        );
        let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
        stopped_seq = stopped.tree.seq;
        let before = sends(&stopped);
        finish_hooks_for_test(FinishHooks {
            hold_engine: held,
            ..FinishHooks::default()
        });
        let events = Events::default();
        let opens = crate::store::opens_for_test();
        let result = restart(&stopped, &events);
        let opens = crate::store::opens_for_test() - opens;
        finish_hooks_for_test(FinishHooks::default());
        let instances: BTreeSet<[u8; 16]> = stopped.state.lock().unwrap().sends[before..]
            .iter()
            .filter_map(|bytes| {
                intent::decode_register(bytes, &stopped.tree.volume, |_, _| true).ok()
            })
            .map(|request| request.instance)
            .collect();
        // The finish committed, then the hand-back refused the start: the
        // commit's event stands, and the start's failure is its own.
        outcomes.push((
            held,
            outcome(&result),
            (opens, handshakes(&stopped, before), instances.len()),
            result
                .as_ref()
                .ok()
                .map(|ready| instances.contains(&ready.owner().2)),
            (start_endings(&events), events.failed("internal")),
        ));
    }
    let tree = mounted_operation_tree();
    let paths = Paths::new();
    let (result, _, _) = attempt(&input(&tree, &paths), &tree, "valid", &Events::default());
    let mut ready = result.unwrap();
    let mediator = ready.mediator_for_test();
    let free = mediator.detach_sync_engine();
    mediator.hold_adoption_for_test(crate::writable_store::sync_engine::AdoptionHold::CommitLane);
    let laned = mediator.detach_sync_engine();
    assert_eq!(
        (outcomes, free, laned),
        (
            vec![
                (
                    false,
                    "Ok",
                    (1, 1, 1),
                    Some(true),
                    (committed(stopped_seq + 1), false)
                ),
                (
                    true,
                    "WritableFinishLeaked",
                    (1, 1, 1),
                    None,
                    (committed(stopped_seq + 1), true)
                ),
            ],
            true,
            false
        )
    );
}

/// The phase closes its session's cache before the serving session opens
/// it, which then holds the cache's writer lock. A phase session kept open
/// across that open leaves the serving cache degraded, which the serving
/// session refuses.
#[test]
fn the_phase_closes_its_cache_before_the_serving_open() {
    let mut outcomes = Vec::new();
    for kept in [false, true] {
        let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
        create(fixture.ready.backend_for_test(), "a", DIRTY);
        fixture.faults.arm(
            "sync.registration",
            "before_dispatch",
            1,
            crate::FaultAction::Block,
        );
        let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
        finish_hooks_for_test(FinishHooks {
            keep_session: kept,
            ..FinishHooks::default()
        });
        let events = Events::default();
        let result = restart(&stopped, &events);
        finish_hooks_for_test(FinishHooks::default());
        // A second open while the serving session lives finds the writer
        // lock held: it opens degraded.
        let input = input(&stopped.tree, &stopped.paths);
        let probe =
            crate::Cache::open(&stopped.paths.cache, input.cache_quota, &input.cache_origin)
                .unwrap();
        let locked = probe.is_read_only_degraded();
        crate::Cache::close(probe).unwrap();
        outcomes.push((kept, outcome(&result), result.is_ok().then_some(locked)));
        drop(result);
    }
    assert_eq!(
        outcomes,
        [
            (false, "Ok", Some(true)),
            (true, "DegradedCacheRefused", None)
        ]
    );
}

/// A sync's prepared root R registered when the process stopped: the
/// phase registers R again, not B's tree; with no root registered, B's
/// tree at B + 1.
#[test]
fn the_phase_registers_the_carrier_root_not_the_base() {
    let rt = runtime();
    let mut outcomes = Vec::new();
    for registered_root in [true, false] {
        let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
        let object = dirty(&mut fixture);
        fixture
            .ready
            .backend_for_test()
            .overlay_close(object)
            .unwrap();
        fixture.sync_tree().unwrap();
        let synced = fixture
            .mediator()
            .with(|s| Ok(s.snapshot().root.clone()))
            .unwrap();
        if !registered_root {
            clear_registered_root(&mut fixture);
        }
        let stopped = stop(fixture);
        let base = stopped.tree.seq;
        let (base_id, base_doc) = root_doc(&stopped.tree, &rt, base);
        let before = sends(&stopped);
        let events = Events::default();
        let result = restart(&stopped, &events);
        let first = stopped.state.lock().unwrap().sends[before..]
            .iter()
            .find_map(|bytes| {
                intent::decode_register(bytes, &stopped.tree.volume, |_, _| true)
                    .ok()
                    .map(|request| request.root.to_vec())
            })
            .unwrap();
        let doc = root::decode_root(&first).unwrap();
        outcomes.push((
            registered_root,
            outcome(&result),
            if registered_root {
                GrainId::of(&first) == GrainId::of(&synced)
            } else {
                (doc.seq, doc.parent, doc.manifest_root)
                    == (base + 1, Some(base_id), base_doc.manifest_root)
            },
        ));
    }
    assert_eq!(outcomes, [(true, "Ok", true), (false, "Ok", true)]);
}

/// A shutdown that committed or found nothing owed leaves a clean journal:
/// the next start runs no phase, sends only its own registration, and
/// carries the journal when another writer's head moved.
#[test]
fn a_clean_journal_runs_no_phase() {
    let rt = runtime();
    let mut outcomes = Vec::new();
    for profile in PROFILES {
        for written in [false, true] {
            for moved in [false, true] {
                let mut fixture = fixture_with(profile);
                if written {
                    create(fixture.ready.backend_for_test(), "a", DIRTY);
                }
                let (cut, stopped) = shut_down(
                    fixture,
                    crate::sync::DEFAULT_SHUTDOWN_BOUND,
                    no_shutdown_change,
                );
                if moved {
                    publish_source(&stopped.tree, &rt, |source| {
                        write_operation_source(source, FILE_CONTENT);
                        std::fs::write(source.join("remote.txt"), DIRTY).unwrap();
                    });
                }
                let before = sends(&stopped);
                let events = Events::default();
                let result = restart(&stopped, &events);
                let served = result.as_ref().ok().map(|ready| ready.verified_base().1);
                outcomes.push((
                    (profile, written, moved),
                    matches!(cut, Outcome::Committed(_) | Outcome::Clean),
                    outcome(&result),
                    registered(&stopped, before).len(),
                    start_endings(&events).len(),
                    served == Some(remote_seq(&stopped.tree, &rt)),
                ));
            }
        }
    }
    let expected: Vec<_> = outcomes
        .iter()
        .map(|(case, ..)| (*case, true, "Ok", 1, 0, true))
        .collect();
    assert_eq!(outcomes.len(), 8);
    assert_eq!(outcomes, expected);
}

/// A committed shutdown leaves only the next start's registration, even
/// while a held file keeps its rebound stage in the journal.
#[test]
fn a_clean_restart_after_a_held_durable_commit() {
    clean_restart(crate::SyncProfile::DurablePrepared, true);
}

#[test]
fn a_clean_restart_after_a_closed_durable_commit() {
    clean_restart(crate::SyncProfile::DurablePrepared, false);
}

#[test]
fn a_clean_restart_after_a_held_published_commit() {
    clean_restart(crate::SyncProfile::Published, true);
}

#[test]
fn a_clean_restart_after_a_closed_published_commit() {
    clean_restart(crate::SyncProfile::Published, false);
}

fn clean_restart(profile: crate::SyncProfile, held: bool) {
    let mut fixture = fixture_with(profile);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    let object = held.then(|| {
        fixture
            .ready
            .backend_for_test()
            .overlay_open(&handler_path(b"a"))
            .unwrap()
            .unwrap()
    });
    let mediator = fixture.mediator();
    let shutdown = controller(
        &fixture.engine,
        mediator,
        fixture.runtime.handle().clone(),
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
    );
    let cut = shutdown.begin(Trigger::SessionEnd).outcome;
    drop(shutdown);
    if let Some(object) = object {
        fixture
            .ready
            .backend_for_test()
            .overlay_close(object)
            .unwrap();
    }
    let records = fixture.records();
    let stopped = stop(fixture);
    let before = sends(&stopped);
    let events = Events::default();
    let mut result = restart(&stopped, &events);
    let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
    assert_eq!(
        (
            cut,
            outcome(&result),
            registered(&stopped, before).len(),
            bytes
        ),
        (Outcome::Committed(2), "Ok", 1, Some(Ok(DIRTY.to_vec()))),
        "profile={profile:?}, held={held}; records={records:?}; result={:?}; endings={:?}",
        result.as_ref().err(),
        start_endings(&events)
    );
}

/// A sync mark for an older byte version is cleared before a held stage is
/// rebound to a later landing; replay cannot load it as the new base's mark.
#[test]
fn a_clean_restart_after_a_held_commit_clears_an_older_sync_mark() {
    let mut cases = 0;
    for profile in PROFILES {
        let mut fixture = fixture_with(profile);
        create(
            fixture.ready.backend_for_test(),
            "a",
            b"older synced bytes\n",
        );
        let object = fixture
            .ready
            .backend_for_test()
            .overlay_open(&handler_path(b"a"))
            .unwrap()
            .unwrap();
        fixture.sync_tree().unwrap();
        let synced = fixture.staging();
        let mark = synced.values().next().map(|bytes| {
            StagingHeader::decode(bytes.get(..160).unwrap())
                .unwrap()
                .mark
        });
        assert!(
            matches!(mark, Some(MarkState::Present(_))),
            "profile={profile:?}; mark={mark:?}; records={:?}",
            fixture.records()
        );
        fixture
            .ready
            .backend_for_test()
            .overlay_mutate(granary_fuse::OverlayMutation::BoundWrite {
                object,
                offset: 0,
                bytes: DIRTY,
                append: false,
            })
            .unwrap();
        let lane = fixture.construct(70).unwrap();
        let landing = fixture.drive(&lane, 71);
        let rebound = fixture.staging();
        let marks: Vec<_> = rebound
            .values()
            .map(|bytes| {
                StagingHeader::decode(bytes.get(..160).unwrap())
                    .unwrap()
                    .mark
            })
            .collect();
        assert_eq!(
            (landed(&landing), marks),
            (true, vec![MarkState::Absent]),
            "profile={profile:?}; landing={landing:?}; records={:?}",
            fixture.records()
        );
        fixture
            .ready
            .backend_for_test()
            .overlay_close(object)
            .unwrap();
        let stopped = stop(fixture);
        let before = sends(&stopped);
        let events = Events::default();
        let mut result = restart(&stopped, &events);
        let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
        assert_eq!(
            (outcome(&result), registered(&stopped, before).len(), bytes),
            ("Ok", 1, Some(Ok(DIRTY.to_vec()))),
            "profile={profile:?}; result={:?}; endings={:?}",
            result.as_ref().err(),
            start_endings(&events)
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// Suffix writes and shrink/regrow edits on a rebound stage are owed work:
/// the next start commits their bytes before serving.
#[test]
fn start_recovers_dirty_rebound_stages() {
    let mut cases = 0;
    for profile in PROFILES {
        for extent in [true, false] {
            let mut fixture = fixture_with(profile);
            create(fixture.ready.backend_for_test(), "a", DIRTY);
            let object = fixture
                .ready
                .backend_for_test()
                .overlay_open(&handler_path(b"a"))
                .unwrap()
                .unwrap();
            let mediator = fixture.mediator();
            let shutdown = controller(
                &fixture.engine,
                mediator,
                fixture.runtime.handle().clone(),
                crate::sync::DEFAULT_SHUTDOWN_BOUND,
            );
            let cut = shutdown.begin(Trigger::SessionEnd).outcome;
            drop(shutdown);
            fixture
                .ready
                .backend_for_test()
                .overlay_close(object)
                .unwrap();
            let stopped = stop(fixture);
            let input = input(&stopped.tree, &stopped.paths);
            let area = overlay_area(&stopped.paths, &input);
            let (header, mut records) = captured_records(&stopped.paths, &input);
            let stage_id = records.iter().find_map(|record| match record {
                Record::StageBind {
                    stage_id,
                    cause: journal::BindCause::Rebind,
                    ..
                } => Some(*stage_id),
                _ => None,
            });
            assert_eq!(
                (cut, stage_id),
                (Outcome::Committed(2), Some(1)),
                "records={records:?}"
            );
            let stage_id = stage_id.unwrap();
            let expected = if extent {
                let bytes = vec![b'x'; DIRTY.len()];
                records.push(Record::WriteExtent {
                    stage_id,
                    offset: 0,
                    length: bytes.len() as u64,
                    check: journal::extent_check(stage_id, 0, &bytes),
                });
                let path = area.join("staging").join(format!("{stage_id:016x}"));
                let mut staged = std::fs::read(&path).unwrap();
                staged.truncate(160);
                staged.extend_from_slice(&bytes);
                std::fs::write(path, staged).unwrap();
                bytes
            } else {
                records.extend([
                    Record::Truncate {
                        stage_id,
                        new_size: 1,
                    },
                    Record::Truncate {
                        stage_id,
                        new_size: DIRTY.len() as u64,
                    },
                ]);
                let mut bytes = vec![0; DIRTY.len()];
                bytes[0] = DIRTY[0];
                bytes
            };
            std::fs::write(
                area.join("journal"),
                journal::encode_journal(&header, &records).unwrap(),
            )
            .unwrap();
            let before = sends(&stopped);
            let events = Events::default();
            let mut result = restart(&stopped, &events);
            let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
            assert_eq!(
                (
                    outcome(&result),
                    bytes,
                    registered(&stopped, before).len(),
                    start_endings(&events)
                ),
                ("Ok", Some(Ok(expected)), 3, committed(3)),
                "profile={profile:?}, extent={extent}; records={records:?}; result={:?}",
                result.as_ref().err()
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

/// A process stopped while its Release was retained, the Release now
/// expired and the journal dirty: the start settles the Release, takes
/// ownership again, then finishes the journal.
#[test]
fn a_crash_in_the_release_settles_before_the_phase() {
    let rt = runtime();
    let tree = mounted_operation_tree();
    let paths = Paths::new();
    let state = first_start(&tree, &paths, |ready, state| {
        create(ready.backend_for_test(), "a", DIRTY);
        let time = Time(Arc::clone(state));
        ready
            .mediator_for_test()
            .prepare_release(&time, std::time::Duration::from_secs(1), None)
            .unwrap();
    });
    let phase = {
        let input = input(&tree, &paths);
        granary_core::overlay_ownership::decode(
            &std::fs::read(overlay_area(&paths, &input).join("ownership")).unwrap(),
        )
        .unwrap()
        .phase
    };
    state.lock().unwrap().tick += 10_000;
    let stopped = Stopped { tree, paths, state };
    let before = sends(&stopped);
    let events = Events::default();
    let mut result = restart(&stopped, &events);
    let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
    assert_eq!(
        (
            phase,
            outcome(&result),
            handshakes(&stopped, before),
            (publications(&stopped), remote_seq(&stopped.tree, &rt)),
            bytes,
            start_endings(&events),
        ),
        (
            Phase::Releasing,
            "Ok",
            1,
            (1, stopped.tree.seq + 1),
            Some(Ok(DIRTY.to_vec())),
            committed(stopped.tree.seq + 1),
        ),
        "{:?}",
        result.as_ref().err()
    );
}

/// The loader reads the seed once and builds two keys from it that sign
/// alike. After a phase whose engine took one, the serving mount's engine
/// attaches with the other.
#[test]
fn two_keys_from_one_seed() {
    let tree = mounted_operation_tree();
    let paths = Paths::new();
    let input = input(&tree, &paths);
    provision(&input, &tree, "valid");
    let loaded = crate::load_existing_signing_key_with_spare(&paths.seed, input.euid).unwrap();
    let spare = loaded.spare.as_ref().unwrap();
    let signatures = (
        loaded.key.sign(b"the same bytes"),
        spare.sign(b"the same bytes"),
    );
    let unspared = crate::load_existing_signing_key(&paths.seed, input.euid)
        .unwrap()
        .spare
        .is_none();
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
    let events = Events::default();
    let mut ready = restart(&stopped, &events).unwrap();
    let rt = runtime();
    let remote = Arc::new(Authority::new(&stopped.tree, &stopped.state).with_publication());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .unwrap(),
    );
    let attached = rt.block_on(ready.backend_for_test().attach_sync_with_runtime(
        remote,
        content,
        Arc::new(Time(stopped.state.clone())),
        Arc::new(crate::InstantClock::default()),
        crate::ClientMetrics::new(&mut Entropy(35)),
        Arc::new(FastWaitRuntime),
        Entropy(36),
    ));
    assert_eq!(
        (
            signatures.0 == signatures.1,
            (loaded.key.public_key() == spare.public_key(), unspared),
            start_endings(&events).len(),
            attached.as_ref().err().map(ToString::to_string),
        ),
        (true, (true, true), 1, None)
    );
}

/// A journal another writer wrote is refused before any phase runs, as
/// replay refuses it, whether it holds work or only bookkeeping: no phase
/// reports, nothing is sent, and the journal is kept byte for byte.
#[test]
fn another_writers_journal_is_refused_before_any_phase() {
    let mut outcomes = Vec::new();
    for dirty in [false, true] {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let state = first_start(&tree, &paths, |ready, _| {
            if dirty {
                ready
                    .mediator_for_test()
                    .overlay_transaction(|overlay| {
                        overlay.namespace_record(Record::Move {
                            from: at(b"f.txt"),
                            to: at(b"moved.txt"),
                        })
                    })
                    .unwrap();
            }
        });
        let input = input(&tree, &paths);
        let (mut header, records) = captured_records(&paths, &input);
        header.writer = [0x5a; 16];
        let path = overlay_area(&paths, &input).join("journal");
        std::fs::write(&path, journal::encode_journal(&header, &records).unwrap()).unwrap();
        let stopped = Stopped { tree, paths, state };
        let before = (std::fs::read(&path).unwrap(), sends(&stopped));
        let events = Events::default();
        let result = restart(&stopped, &events);
        outcomes.push((
            dirty,
            outcome(&result),
            start_endings(&events),
            registered(&stopped, before.1).len(),
            publications(&stopped),
            std::fs::read(&path).unwrap() == before.0,
        ));
    }
    assert_eq!(
        outcomes,
        [false, true].map(|dirty| (dirty, "writer ceiling or identity", vec![], 0, 0, true))
    );
}

/// A finish cut at its bound while a blocking call it made runs on past
/// it: the start returns within the bound and its runtime's shutdown
/// slack, leaving the blocking call to end on its own.
#[test]
fn a_cut_finish_returns_within_its_bound_and_slack() {
    const BLOCK_RELEASE: std::time::Duration =
        BOUND.saturating_add(std::time::Duration::from_secs(20));
    // The return signal proves the ordering. Keep the backstop five seconds before forced release.
    const RETURN_LIMIT: std::time::Duration =
        BLOCK_RELEASE.saturating_sub(std::time::Duration::from_secs(5));
    const BOUND_TOLERANCE: std::time::Duration = std::time::Duration::from_millis(10);

    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let (_, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
    let faults = crate::FaultControl::default();
    faults.arm(
        "sync.commit",
        "landed_readback",
        1,
        crate::FaultAction::Block,
    );
    start_faults_for_test(faults.clone());
    finish_hooks_for_test(FinishHooks {
        bound: Some(BOUND),
        budget: Some(BOUND),
        dispatch_floor: Some(BOUND / 2),
        ..FinishHooks::default()
    });
    // A start that waited for the blocking call is released only here,
    // long after the bound, so the row ends either way.
    let (returned, release) = std::sync::mpsc::channel::<()>();
    let resume = std::thread::spawn({
        let faults = faults.clone();
        move || {
            let start_returned = release.recv_timeout(BLOCK_RELEASE).is_ok();
            faults.resume();
            start_returned
        }
    });
    let events = Events::default();
    let started = std::time::Instant::now();
    let result = restart(&stopped, &events);
    let report = finish_report_for_test();
    let elapsed = started.elapsed();
    let _ = returned.send(());
    let start_returned = resume.join().unwrap();
    finish_hooks_for_test(FinishHooks::default());
    let fired = faults
        .sync_fired()
        .iter()
        .any(|event| event.name == "sync.commit" && event.phase == "landed_readback");
    assert_eq!(
        (
            start_returned,
            fired,
            outcome(&result),
            report.map(|report| (
                report.outcome,
                report.cut,
                std::time::Duration::from_millis(report.elapsed_ms)
                    >= BOUND.saturating_sub(BOUND_TOLERANCE),
            )),
            elapsed < RETURN_LIMIT,
        ),
        (
            true,
            true,
            "WritableAuthorityUnavailable",
            Some((Outcome::Incomplete(Cause::Deadline), Some(Cut::Bound), true)),
            true,
        ),
        "restart elapsed={elapsed:?}, finish report={report:?}"
    );
}

fn register_unpublished(fixture: &mut EngineMount, seq: u64) -> Vec<u8> {
    let published = fixture
        .runtime
        .block_on(remote_handle(&fixture.tree.mem).get_root(fixture.tree.volume.as_str(), seq))
        .unwrap()
        .unwrap();
    let doc = root::decode_root(&published).unwrap();
    let seq = doc.seq + 1;
    let prepared =
        super::carry_forward::signed(&fixture.tree.key, doc, seq, Some(GrainId::of(&published)));
    super::carry_forward::plant_registered_root(
        &mut fixture.ready,
        &fixture.state,
        prepared.clone(),
    );
    prepared
}

fn semantic_clean_fixture(unpublished: bool) -> Stopped {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    let _object = fixture
        .ready
        .backend_for_test()
        .overlay_open(&handler_path(b"a"))
        .unwrap()
        .unwrap();
    let mut selected = None;
    let (cut, stopped) = shut_down(
        fixture,
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
        |fixture, cut| {
            if !unpublished {
                return;
            }
            let Outcome::Committed(seq) = cut else {
                panic!("premise: semantic-clean fixture shutdown committed: {cut:?}");
            };
            selected = Some(register_unpublished(fixture, seq));
        },
    );
    let input = input(&stopped.tree, &stopped.paths);
    if let Some(selected) = selected {
        let mut store = Store::open(&stopped.paths.store).unwrap();
        let retained = store
            .publications(input.euid)
            .unwrap()
            .load(input.scope.as_ref().unwrap(), &input.volume)
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                retained.is_complete(),
                retained.frozen.initial_root != selected,
                stopped.state.lock().unwrap().root == selected,
            ),
            (true, true, true),
            "premise: older Complete R beside unpublished selected P"
        );
    }
    semantic_history(stopped, cut)
}

fn semantic_history(stopped: Stopped, cut: Outcome) -> Stopped {
    let input = input(&stopped.tree, &stopped.paths);
    let (header, mut records) = captured_records(&stopped.paths, &input);
    let stage = records.iter().find_map(|record| match record {
        Record::StageBind { stage_id, .. } => Some(*stage_id),
        _ => None,
    });
    assert_eq!(
        (cut, stage),
        (Outcome::Committed(2), Some(1)),
        "{records:?}"
    );
    records.push(Record::Truncate {
        stage_id: stage.unwrap(),
        new_size: DIRTY.len() as u64,
    });
    let area = overlay_area(&stopped.paths, &input);
    std::fs::write(
        area.join("journal"),
        journal::encode_journal(&header, &records).unwrap(),
    )
    .unwrap();
    stopped
}

fn check_semantic_clean_history(debts: &[&'static str]) {
    use crate::writable_store::sync_engine::FINISH_DEBT;
    let mut cases = 0;
    for &debt in debts {
        let stopped = semantic_clean_fixture(true);
        let input = input(&stopped.tree, &stopped.paths);
        let area = overlay_area(&stopped.paths, &input);
        let before = evidence(&stopped.paths, &stopped.tree);
        FINISH_DEBT.set(debt);
        let events = Events::default();
        let mut result = restart(&stopped, &events);
        FINISH_DEBT.set("");
        let mut io = OverlayDisk::new(&stopped.paths.store, input.euid);
        let journal_clean = crate::overlay_store::journal_condition(&mut io, &area)
            .unwrap()
            .unwrap()
            .1;
        let bytes = result.as_mut().ok().map(|ready| read_back(ready, b"a"));
        if debt.is_empty() {
            assert_eq!(
                (
                    outcome(&result),
                    journal_clean,
                    publications(&stopped),
                    bytes,
                    start_endings(&events)
                ),
                (
                    "Ok",
                    true,
                    1,
                    Some(Ok(DIRTY.to_vec())),
                    clean(stopped.tree.seq + 1)
                ),
                "{debt}: {:?}",
                result.as_ref().err()
            );
        } else {
            assert_eq!(
                (
                    outcome(&result),
                    journal_clean,
                    publications(&stopped),
                    evidence(&stopped.paths, &stopped.tree) == before
                ),
                ("WritableRecoveryRequired", false, 1, true),
                "debt={debt}: {:?}",
                result.as_ref().err()
            );
        }
        cases += 1;
    }
    assert_eq!(cases, debts.len());
    assert!(cases > 0);
}

#[test]
fn semantic_clean_history_publication_and_requests() {
    check_semantic_clean_history(&["", "publication", "request", "context"]);
}

#[test]
fn semantic_clean_history_captures_and_handles() {
    check_semantic_clean_history(&["", "capture", "handle", "retained"]);
}

#[test]
fn semantic_clean_history_replay_and_readiness() {
    check_semantic_clean_history(&["", "lane", "replay", "readiness"]);
}

#[test]
fn semantic_clean_history_stages_and_completion() {
    check_semantic_clean_history(&["", "snapshot", "stage", "completion"]);
}

#[test]
fn semantic_clean_history_version_and_namespace() {
    check_semantic_clean_history(&["", "version", "namespace"]);
}

#[test]
fn semantic_clean_history_coalesced_selection_needs_no_new_publication() {
    let stopped = semantic_clean_fixture(true);
    let input = input(&stopped.tree, &stopped.paths);
    let area = overlay_area(&stopped.paths, &input);
    stopped.state.lock().unwrap().reject_publications = true;
    let events = Events::default();
    let mut result = restart(&stopped, &events);
    let mut io = OverlayDisk::new(&stopped.paths.store, input.euid);
    let journal_clean = crate::overlay_store::journal_condition(&mut io, &area)
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(
        (
            outcome(&result),
            journal_clean,
            publications(&stopped),
            result.as_mut().ok().map(|ready| read_back(ready, b"a")),
            start_endings(&events),
        ),
        (
            "Ok",
            true,
            1,
            Some(Ok(DIRTY.to_vec())),
            clean(stopped.tree.seq + 1),
        ),
        "verified parent manifest proves the selection despite refusal of new publications: {:?}",
        result.as_ref().err()
    );
    let (bound, inner, timeout, selected) = crate::writable_start::finish_future_sizes_for_test();
    assert_eq!(
        (bound, inner, timeout, selected > 0, selected <= 16_384),
        (0, 0, 0, true, true),
        "production-HttpStore selected-publication future: bound={bound}, inner={inner}, timeout={timeout}, selected={selected}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one crash table keeps every normalization barrier and its common postcondition together"
)]
fn normalization_and_release_crash_cuts_rederive_completion() {
    let cuts = [
        ("overlay.normalize.mark_clear", "before"),
        ("overlay.normalize.mark_clear", "after-sync"),
        ("overlay.journal.normalize", "build"),
        ("overlay.journal.normalize", "before"),
        ("overlay.journal.normalize", "after"),
        ("overlay.journal.normalize", "sync"),
        ("overlay.journal.normalize", "after_sync"),
        ("overlay.journal.normalize", "rename"),
        ("overlay.journal.normalize", "after_rename"),
        ("overlay.journal.normalize", "dir_sync"),
        ("overlay.journal.normalize", "after_dir_sync"),
        ("overlay.normalize.retire", "before"),
        ("overlay.normalize.retire", "after-sync"),
    ];
    let mut cases = 0;
    for (seam, phase) in cuts {
        let stopped = semantic_clean_fixture(false);
        let input = input(&stopped.tree, &stopped.paths);
        let area = overlay_area(&stopped.paths, &input);
        let before = journal::scan_journal(&std::fs::read(area.join("journal")).unwrap()).unwrap();
        let high_waters = (
            before.header.writer,
            before.state.next_stage_id(),
            before.state.highest_generation(),
            before.header.base_root,
            before.header.base_seq,
        );
        let faults = crate::FaultControl::default();
        faults.arm(seam, phase, 1, crate::FaultAction::Crash);
        start_faults_for_test(faults.clone());
        let cut_events = Events::default();
        let cut = restart(&stopped, &cut_events);
        start_faults_for_test(crate::FaultControl::default());
        let cut_endings = start_endings(&cut_events);
        assert_eq!(
            (
                cut.is_err(),
                faults.fired().len(),
                cut_endings
                    .iter()
                    .all(|(_, outcome, _)| outcome != "clean" && outcome != "committed"),
            ),
            (true, 1, true),
            "cut {seam}/{phase}: {:?}, {cut_endings:?}",
            cut.as_ref().err()
        );
        let cut_scan =
            journal::scan_journal(&std::fs::read(area.join("journal")).unwrap()).unwrap();
        let durable_waters = (
            cut_scan.header.writer,
            cut_scan.state.next_stage_id(),
            cut_scan.state.highest_generation(),
            cut_scan.header.base_root,
            cut_scan.header.base_seq,
        );
        assert_eq!(
            (
                durable_waters.0,
                durable_waters.1,
                durable_waters.2 >= high_waters.2,
                durable_waters.3,
                durable_waters.4,
            ),
            (
                high_waters.0,
                high_waters.1,
                true,
                high_waters.3,
                high_waters.4,
            ),
            "durable cut high waters {seam}/{phase}: {durable_waters:?}"
        );
        let recovered_events = Events::default();
        let mut recovered = restart(&stopped, &recovered_events);
        let after = journal::scan_journal(&std::fs::read(area.join("journal")).unwrap()).unwrap();
        let after_waters = (
            after.header.writer,
            after.state.next_stage_id(),
            after.state.highest_generation(),
            after.header.base_root,
            after.header.base_seq,
        );
        let bytes = recovered.as_mut().ok().map(|ready| read_back(ready, b"a"));
        let expected_endings = if (seam, phase) == ("overlay.normalize.retire", "after-sync") {
            Vec::new()
        } else {
            clean(stopped.tree.seq + 1)
        };
        assert_eq!(
            (
                outcome(&recovered),
                after.end == journal::JournalEnd::Clean,
                (
                    after_waters.0,
                    after_waters.1,
                    after_waters.2 >= durable_waters.2,
                    after_waters.3,
                    after_waters.4,
                ),
                captured_staging(&stopped.paths, &input).is_empty(),
                publications(&stopped),
                bytes,
                start_endings(&recovered_events),
            ),
            (
                "Ok",
                true,
                (
                    durable_waters.0,
                    durable_waters.1,
                    true,
                    durable_waters.3,
                    durable_waters.4,
                ),
                true,
                1,
                Some(Ok(DIRTY.to_vec())),
                expected_endings,
            ),
            "reopen {seam}/{phase}: {:?}",
            recovered.as_ref().err()
        );
        cases += 1;
    }
    assert_eq!(cases, cuts.len(), "nonzero normalization cut cases");
    assert_eq!(
        crate::overlay_store::tests::replacement::normalized_stage_retirement_survives_crash(),
        13,
        "nonzero crash-consistent normalization barriers"
    );
}
