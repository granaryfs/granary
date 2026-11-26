// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A restart after another writer advanced the head: a clean journal on the
//! older base starts on the discovered head, and a registered prepared root
//! whose content is published is accepted when its tree is not the head's.

use super::*;
use granary_core::overlay_journal::{self as journal, IntentCause, Location, Parent, Record};
use granary_core::rootstore::RefusalKind;

const REMOTE_CONTENT: &[u8] = b"a head another writer published\n";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The overlay journal's bytes, and whether a temporary sits beside it.
fn journal_files(paths: &Paths, input: &WritableStart<'_>) -> (Vec<u8>, bool) {
    let area = overlay_area(paths, input);
    (
        std::fs::read(area.join("journal")).unwrap(),
        area.join("journal.next").exists(),
    )
}

/// Every `overlay.recovery` outcome among `events`, in order.
fn recovery_outcomes(events: &Events) -> Vec<String> {
    String::from_utf8(events.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| line.contains("\"event\":\"overlay.recovery\""))
        .map(|line| {
            let (_, rest) = line.split_once("\"outcome\":\"").unwrap();
            rest.split('"').next().unwrap().to_owned()
        })
        .collect()
}

/// [`restart`], its events written to `events`.
fn restart_observed(
    input: &WritableStart<'_>,
    tree: &PublishedTree,
    state: &Arc<Mutex<AuthorityState>>,
    events: &Events,
) -> Result<crate::WritableReadiness<Authority, OverlayDisk>, WritableStartError> {
    tracing::subscriber::with_default(events.subscriber(), || restart(input, tree, state))
}

/// The overlay refusal a start ended with, if it ended with one.
fn overlay_refusal(
    result: &Result<crate::WritableReadiness<Authority, OverlayDisk>, WritableStartError>,
) -> Option<&'static str> {
    match result {
        Err(WritableStartError::Coordination(crate::CoordinationError::Overlay(
            crate::OverlayError::Refused(reason),
        ))) => Some(reason),
        _ => None,
    }
}

/// The start's refusal name, or `Ok` for a start that succeeded.
fn outcome(
    result: &Result<crate::WritableReadiness<Authority, OverlayDisk>, WritableStartError>,
) -> &'static str {
    result
        .as_ref()
        .map_or_else(WritableStartError::name, |_| "Ok")
}

/// `doc` at `seq` with `parent`, signed by `key`, encoded.
pub(super) fn signed(
    key: &SigningKey,
    mut doc: RootDoc,
    seq: u64,
    parent: Option<GrainId>,
) -> Vec<u8> {
    doc.seq = seq;
    doc.parent = parent;
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    root::encode_root(&doc).unwrap()
}

fn put_root(tree: &PublishedTree, runtime: &tokio::runtime::Runtime, seq: u64, bytes: Vec<u8>) {
    runtime
        .block_on(remote_handle(&tree.mem).put_root(tree.volume.as_str(), seq, bytes))
        .unwrap();
}

/// The root at `seq` re-signed at `seq + 1` with the root at `seq` as its
/// parent: the next head, on the same tree. Returns its id.
fn extend_head(tree: &PublishedTree, runtime: &tokio::runtime::Runtime, seq: u64) -> GrainId {
    let (parent, doc) = root_doc(tree, runtime, seq);
    let bytes = signed(&tree.key, doc, seq + 1, Some(parent));
    let id = GrainId::of(&bytes);
    put_root(tree, runtime, seq + 1, bytes);
    id
}

/// Replace the journal on disk with `header` and `records`.
fn plant_journal(
    paths: &Paths,
    input: &WritableStart<'_>,
    header: journal::JournalHeader,
    records: &[Record],
) {
    std::fs::write(
        overlay_area(paths, input).join("journal"),
        journal::encode_journal(&header, records).unwrap(),
    )
    .unwrap();
}

fn root_location(name: &[u8]) -> Location {
    Location {
        parent: Parent::root(),
        name: granary_core::manifest::Name::new(name.to_vec()).unwrap(),
    }
}

/// A first start on the tree's base, then `stop` run on the ready mount
/// before its process stops without release.
fn first_start(
    tree: &PublishedTree,
    input: &WritableStart<'_>,
    stop: impl FnOnce(
        &mut crate::WritableReadiness<Authority, OverlayDisk>,
        &Arc<Mutex<AuthorityState>>,
    ),
) -> Arc<Mutex<AuthorityState>> {
    let (result, state, _) = attempt(input, tree, "valid", &Events::default());
    let mut ready = result.unwrap_or_else(|error| panic!("first start refused: {error}"));
    stop(&mut ready, &state);
    drop(ready);
    state
}

/// What a journal left unchanged by a refused restart shows: the overlay
/// refusal, whether its bytes are unchanged, and whether a temporary sits
/// beside it.
type NotCarried = (Option<&'static str>, bool, bool);

/// One refusal case: the journal a first start leaves, changed by `change`
/// before its process stops, restarted on a newer head.
fn journal_not_carried(
    change: impl FnOnce(
        &Paths,
        &WritableStart<'_>,
        &mut crate::WritableReadiness<Authority, OverlayDisk>,
    ),
) -> NotCarried {
    let rt = runtime();
    let tree = mounted_operation_tree();
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let state = first_start(&tree, &input, |ready, _| change(&paths, &input, ready));
    publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
    let (before, _) = journal_files(&paths, &input);
    let result = restart(&input, &tree, &state);
    let (after, temporary) = journal_files(&paths, &input);
    (overlay_refusal(&result), after == before, temporary)
}

/// One journal holding work: the journal a first start leaves, changed by
/// `change` before its process stops, restarted on a newer head. The start
/// finishes it on its own base before serving: what the start answers, and
/// whether the journal it leaves is on the head finishing produced.
fn journal_finished(
    change: impl FnOnce(&mut crate::WritableReadiness<Authority, OverlayDisk>),
) -> (&'static str, bool) {
    let rt = runtime();
    let tree = mounted_operation_tree();
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let state = first_start(&tree, &input, |ready, _| change(ready));
    disjoint_head(&tree, &rt);
    let result = restart_publishing(&input, &tree, &state);
    let head = remote_seq(&tree, &rt);
    let (header, _) = captured_records(&paths, &input);
    (
        outcome(&result),
        (header.base_root, header.base_seq) == (root_doc(&tree, &rt, head).0, head),
    )
}

/// The same journal opened by the store itself on a newer head with the
/// carry disabled. A start reaches its open with no registration retained,
/// because its succession closes every one, so only a direct open reaches
/// the disabled carry.
fn journal_not_carried_when_disabled() -> NotCarried {
    let rt = runtime();
    let tree = mounted_operation_tree();
    let paths = Paths::new();
    let input = input(&tree, &paths);
    first_start(&tree, &input, |_, _| ());
    publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
    let (head, _) = root_doc(&tree, &rt, tree.seq + 1);
    let (before, _) = journal_files(&paths, &input);
    let config = crate::OverlayConfig {
        scope: input.scope.clone().unwrap(),
        volume: input.volume.clone(),
        euid: input.euid,
        cap: 134_217_728,
        ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
        instance: [0; 16],
    };
    let mut store = crate::WritableStore::new(
        Store::open(&paths.store).unwrap(),
        config,
        OverlayDisk::new(&paths.store, input.euid),
        &mut Entropy(60),
        crate::FaultControl::default(),
        |_, _| true,
    )
    .unwrap();
    let header = journal::JournalHeader {
        writer: store.writer_uuid(),
        base_root: head,
        base_seq: tree.seq + 1,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    let result = store.open_overlay_local(
        header,
        vec![],
        OverlayDisk::new(&paths.store, input.euid),
        false,
    );
    let (after, temporary) = journal_files(&paths, &input);
    let refusal = match result {
        Err(crate::CoordinationError::Overlay(crate::OverlayError::Refused(reason))) => {
            Some(reason)
        }
        _ => None,
    };
    (refusal, after == before, temporary)
}

/// A clean journal written on the base B restarts on the head D another writer
/// published: the journal is rewritten on D with its counters and no record
/// of its own, the pin is D, and replay's one recovery event reports the
/// repair. A control restart with no head moved reports a clean recovery.
/// Every other clean journal keeps today's base refusal, untouched: on a seq
/// above D's, on D's seq under another id, or opened with the carry
/// disabled; one naming a foreign writer is refused as replay refuses it,
/// before it is read as clean. A journal holding work is finished on B by
/// the start before it serves, which then serves the head finishing
/// produced: one with a namespace record, or holding an open boundary no
/// publication names. Beside a staging file that is no staging file at all,
/// the finishing replay on B refuses its header, untouched.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of carry and refusal cases over the same start fixture"
)]
fn a_clean_journal_on_an_older_base_starts_on_the_discovered_head() {
    let rt = runtime();
    let mut cases = 0;
    {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let state = first_start(&tree, &input, |_, _| ());
        let (old, _) = journal_files(&paths, &input);
        let old = journal::scan_journal(&old).unwrap();
        publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
        let (head, _) = root_doc(&tree, &rt, tree.seq + 1);
        let events = Events::default();
        let result = restart_observed(&input, &tree, &state, &events);
        let pin = result
            .as_ref()
            .map(|ready| ready.verified_base().clone())
            .ok();
        let (header, records) = captured_records(&paths, &input);
        let (registered, generation) = {
            let state = state.lock().unwrap();
            (GrainId::of(&state.root), state.row.unwrap().generation)
        };
        // The carried journal holds no record; the restart's own registration
        // on D is the one record after it.
        assert_eq!(
            (
                outcome(&result),
                (header.base_root, header.base_seq),
                (header.next_stage_id, header.receipt_generation),
                records,
                pin,
                recovery_outcomes(&events),
            ),
            (
                "Ok",
                (head, tree.seq + 1),
                (old.state.next_stage_id(), old.state.highest_generation()),
                vec![Record::IntentRegistered {
                    generation,
                    prepared_root: registered,
                    cause: IntentCause::DirectorySync,
                }],
                Some((tree.volume.clone(), tree.seq + 1, head)),
                vec!["repaired".to_owned()],
            ),
            "clean: {:?}",
            result.as_ref().err()
        );
        cases += 1;
    }
    let finished = [
        (
            "namespace record",
            journal_finished(|ready| {
                ready
                    .mediator_for_test()
                    .overlay_transaction(|overlay| {
                        overlay.namespace_record(Record::Move {
                            from: root_location(b"f.txt"),
                            to: root_location(b"moved.txt"),
                        })
                    })
                    .unwrap();
            }),
        ),
        (
            "open boundary",
            journal_finished(|ready| {
                ready
                    .mediator_for_test()
                    .overlay_transaction(|overlay| {
                        let capture = overlay.capture_boundary()?;
                        overlay.record_boundary(capture, GrainId::of(b"candidate"), [7; 16])
                    })
                    .unwrap();
            }),
        ),
    ];
    cases += finished.len();
    assert_eq!(
        finished,
        [
            ("namespace record", ("Ok", true)),
            ("open boundary", ("Ok", true))
        ],
        "a journal holding work is finished before the start serves"
    );
    let staging = journal_not_carried(|paths, input, _| {
        let stage = overlay_area(paths, input)
            .join("staging")
            .join("0000000000000001");
        std::fs::write(&stage, [0; 160]).unwrap();
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o600)).unwrap();
    });
    cases += 1;
    assert_eq!(
        staging,
        (Some("staging header"), true, false),
        "staging file"
    );
    let refusals = vec![
        (
            "seq above the head",
            journal_not_carried(|paths, input, _| {
                let (mut header, records) = captured_records(paths, input);
                header.base_seq += 5;
                plant_journal(paths, input, header, &records);
            }),
        ),
        (
            "the head's seq under another id",
            journal_not_carried(|paths, input, _| {
                let (mut header, records) = captured_records(paths, input);
                header.base_seq += 1;
                header.base_root = GrainId::of(b"another root at the head's seq");
                plant_journal(paths, input, header, &records);
            }),
        ),
        ("carry disabled", journal_not_carried_when_disabled()),
        (
            "foreign writer",
            journal_not_carried(|paths, input, _| {
                let (mut header, records) = captured_records(paths, input);
                header.writer = [0x5a; 16];
                plant_journal(paths, input, header, &records);
            }),
        ),
    ];
    cases += refusals.len();
    let expected: Vec<_> = refusals
        .iter()
        .map(|(case, _)| {
            // Another writer's journal is refused before it is read as clean.
            let refusal = if *case == "foreign writer" {
                "writer ceiling or identity"
            } else {
                "base root/sequence mismatch"
            };
            (*case, (Some(refusal), true, false))
        })
        .collect();
    assert_eq!(refusals, expected, "every other journal keeps its refusal");
    {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let state = first_start(&tree, &input, |_, _| ());
        let events = Events::default();
        let result = restart_observed(&input, &tree, &state, &events);
        assert_eq!(
            (outcome(&result), recovery_outcomes(&events)),
            ("Ok", vec!["clean".to_owned()]),
            "control: a restart on its own base carries nothing"
        );
    }
    assert_eq!(cases, 8);
}

/// The registered root the first start left, as the authority holds it.
fn registered_root(state: &Arc<Mutex<AuthorityState>>) -> Vec<u8> {
    state.lock().unwrap().root.clone()
}

/// Make `bytes` the registered prepared root, in the mount's carrier and in
/// the authority's live receipt alike.
pub(super) fn plant_registered_root(
    ready: &mut crate::WritableReadiness<Authority, OverlayDisk>,
    state: &Arc<Mutex<AuthorityState>>,
    bytes: Vec<u8>,
) {
    let mut state = state.lock().unwrap();
    let row = state.row.as_mut().unwrap();
    row.state = ReceiptState::Live {
        prepared_root_id: GrainId::of(&bytes),
    };
    state.root.clone_from(&bytes);
    drop(state);
    ready
        .backend_for_test()
        .shared_mediator()
        .with(|store| store.set_carrier_root_for_test(bytes))
        .unwrap();
}

/// The registered prepared root P is accepted when its content is published:
/// P itself at its seq, or P's parent at the seq below holding P's tree. Each
/// case publishes the head D above P's seq, so a fault planted at P's seq or
/// the seq below meets no read but the rule's own. Accepted: the start's own
/// registration on B after a carry; a landing's refresh registration L, read
/// at its own seq with any read below it failing; and a journal already on D
/// with P still on B. Refused: a transient read at either seq as retryable,
/// a refused store answer or a parent signed by another key as permanent,
/// a parent whose tree differs from P's in any one field, and no parent at
/// the seq below.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of the rule's thirteen read outcomes over the same start fixture"
)]
fn a_registered_root_with_published_content_is_accepted() {
    let rt = runtime();
    let elapsed = || RootStoreError::Elapsed {
        operation: "GET root",
        after: std::time::Duration::from_secs(1),
    };
    let over_cap = || RootStoreError::RefusedResponse {
        reason: "root above its cap".to_owned(),
        kind: RefusalKind::OverCap,
    };
    let mut outcomes = Vec::new();

    // Carried: P is the start's registration on B, B+1 holds another root and
    // D is B+2.
    {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let state = first_start(&tree, &input, |_, _| ());
        publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
        let head = extend_head(&tree, &rt, tree.seq + 1);
        let result = restart(&input, &tree, &state);
        if result.is_ok() {
            let parent = root::decode_root(&registered_root(&state)).unwrap().parent;
            assert_eq!(parent, Some(head), "carried: the new registration is on D");
        }
        outcomes.push(("carried", outcome(&result)));
    }

    // Landed: the mount lands L and stops without release; P = L, and any
    // read below L's seq fails.
    {
        let mut fixture = EngineMount::new();
        let object = dirty(&mut fixture);
        granary_fuse::MountBackend::overlay_close(fixture.ready.backend_for_test(), object)
            .unwrap();
        fixture.sync_tree().unwrap();
        let lane = fixture.construct(60).unwrap();
        assert!(
            landed(&fixture.drive(&lane, 61)),
            "fixture precondition: L lands"
        );
        let landed_seq = remote_seq(&fixture.tree, &fixture.runtime);
        let EngineMount {
            ready,
            engine,
            runtime: engine_runtime,
            state,
            tree,
            paths,
            ..
        } = fixture;
        drop(engine);
        drop(ready);
        drop(engine_runtime);
        let landed_root = root_doc(&tree, &rt, landed_seq).0;
        assert_eq!(
            GrainId::of(&registered_root(&state)),
            landed_root,
            "fixture precondition: the landing's refresh registered L"
        );
        publish_source(&tree, &rt, |source| {
            write_operation_source(source, REMOTE_CONTENT);
        });
        state
            .lock()
            .unwrap()
            .root_fault
            .insert(landed_seq - 1, elapsed());
        let result = restart(&input(&tree, &paths), &tree, &state);
        outcomes.push(("landed", outcome(&result)));
    }

    // Same base: the journal is already on D, while P is still the start's
    // registration on B.
    {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let state = first_start(&tree, &input, |_, _| ());
        let on_base = registered_root(&state);
        publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
        extend_head(&tree, &rt, tree.seq + 1);
        // The carried restart moves the journal to D; its own registration
        // is then replaced by P on B again.
        let events = Events::default();
        let result = restart(&input, &tree, &state).and_then(|mut carried| {
            plant_registered_root(&mut carried, &state, on_base);
            drop(carried);
            restart_observed(&input, &tree, &state, &events)
        });
        if result.is_ok() {
            assert_eq!(
                recovery_outcomes(&events),
                ["clean"],
                "same base: the journal was already on D"
            );
        }
        outcomes.push(("same base", outcome(&result)));
    }

    // Arm 1 faulted at P's seq, with D above it.
    for (case, fault) in [
        ("arm 1 transient", elapsed()),
        ("arm 1 readback", over_cap()),
    ] {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let state = first_start(&tree, &input, |_, _| ());
        publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
        extend_head(&tree, &rt, tree.seq + 1);
        let seq = root::decode_root(&registered_root(&state)).unwrap().seq;
        state.lock().unwrap().root_fault.insert(seq, fault);
        let result = restart(&input, &tree, &state);
        outcomes.push((case, outcome(&result)));
    }

    // Arm 2 faulted at the seq below P's, P's own seq holding another root.
    for (case, fault) in [
        ("arm 2 transient", elapsed()),
        ("arm 2 readback", over_cap()),
    ] {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let state = first_start(&tree, &input, |_, _| ());
        publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
        extend_head(&tree, &rt, tree.seq + 1);
        let seq = root::decode_root(&registered_root(&state)).unwrap().seq;
        state.lock().unwrap().root_fault.insert(seq - 1, fault);
        let result = restart(&input, &tree, &state);
        outcomes.push((case, outcome(&result)));
    }

    // Arm 2 signature: B+1 holds the remote head, B+2 its copy signed by a
    // foreign key, B+3 a copy under the tree's key and D is B+4. P carries
    // B's tree at B+3 with the foreign root as its parent, signed by the
    // mount key.
    {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let (foreign, _) = SigningKey::generate().unwrap();
        let mut planted = Vec::new();
        let state = first_start(&tree, &input, |ready, state| {
            let (_, base) = root_doc(&tree, &rt, tree.seq);
            publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
            let (remote, doc) = root_doc(&tree, &rt, tree.seq + 1);
            let foreign_root = signed(&foreign, doc, tree.seq + 2, Some(remote));
            let foreign_id = GrainId::of(&foreign_root);
            put_root(&tree, &rt, tree.seq + 2, foreign_root);
            let (_, doc) = root_doc(&tree, &rt, tree.seq + 1);
            put_root(
                &tree,
                &rt,
                tree.seq + 3,
                signed(&tree.key, doc, tree.seq + 3, Some(foreign_id)),
            );
            extend_head(&tree, &rt, tree.seq + 3);
            planted = signed(&tree.key, base, tree.seq + 3, Some(foreign_id));
            plant_registered_root(ready, state, planted.clone());
        });
        let doc = root::decode_root(&planted).unwrap();
        let read = |seq, expected| {
            rt.block_on(crate::sync::PublishedRoot::read(
                &tree.remote,
                &tree.volume,
                seq,
                Some(expected),
                &trusted(&tree),
            ))
            .err()
            .map(|error| match error {
                crate::CoordinationError::Refused(name) => name,
                _ => "another error",
            })
        };
        assert_eq!(
            (
                read(doc.seq, GrainId::of(&planted)),
                read(doc.seq - 1, doc.parent.unwrap()),
            ),
            (Some("ViewRootMismatch"), Some("SyncCommitSignature")),
            "arm 2 signature: arm 1 meets another root, arm 2 the foreign signature"
        );
        let result = restart(&input, &tree, &state);
        outcomes.push(("arm 2 signature", outcome(&result)));
    }

    // Arm 2 changed tree: P is the start's registration on B with one tree
    // field changed, so its parent B holds another tree.
    for (case, field) in [
        ("changed manifest", "manifest"),
        ("changed binmap", "binmap"),
        ("changed sheaf", "sheaf"),
        ("changed chunker", "chunker"),
    ] {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let state = first_start(&tree, &input, |ready, state| {
            let registered = ready.mediator_for_test().snapshot().root.clone();
            let mut doc = root::decode_root(&registered).unwrap();
            match field {
                "manifest" => {
                    doc.manifest_root = granary_core::manifest::build_dir(&[]).unwrap().root;
                }
                "binmap" => doc.binmap_index = GrainId::of(b"changed-binmap"),
                "sheaf" => doc.sheaf_head = GrainId::of(b"changed-sheaf"),
                "chunker" => doc.chunker_spec.push_str("-changed"),
                _ => unreachable!(),
            }
            let (seq, parent) = (doc.seq, doc.parent);
            plant_registered_root(ready, state, signed(&tree.key, doc, seq, parent));
        });
        publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
        extend_head(&tree, &rt, tree.seq + 1);
        let result = restart(&input, &tree, &state);
        outcomes.push((case, outcome(&result)));
    }

    // Parent absent: B+1 holds the remote head, B+2 nothing, B+3 a copy of
    // the remote head and D is B+4. P carries B's tree at B+3.
    {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let state = first_start(&tree, &input, |ready, state| {
            let (base_id, base) = root_doc(&tree, &rt, tree.seq);
            publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
            let (remote, doc) = root_doc(&tree, &rt, tree.seq + 1);
            put_root(
                &tree,
                &rt,
                tree.seq + 3,
                signed(&tree.key, doc, tree.seq + 3, Some(remote)),
            );
            extend_head(&tree, &rt, tree.seq + 3);
            plant_registered_root(
                ready,
                state,
                signed(&tree.key, base, tree.seq + 3, Some(base_id)),
            );
        });
        let result = restart(&input, &tree, &state);
        outcomes.push(("parent absent", outcome(&result)));
    }
    assert_eq!(
        outcomes,
        [
            ("carried", "Ok"),
            ("landed", "Ok"),
            ("same base", "Ok"),
            ("arm 1 transient", "WritableAuthorityUnavailable"),
            ("arm 1 readback", "WritableDiscoveryInvalid"),
            ("arm 2 transient", "WritableAuthorityUnavailable"),
            ("arm 2 readback", "WritableDiscoveryInvalid"),
            ("arm 2 signature", "WritableDiscoveryInvalid"),
            ("changed manifest", "WritableRecoveryRequired"),
            ("changed binmap", "WritableRecoveryRequired"),
            ("changed sheaf", "WritableRecoveryRequired"),
            ("changed chunker", "WritableRecoveryRequired"),
            ("parent absent", "WritableRecoveryRequired"),
        ]
    );
}

/// Begin a publication the process then never finishes: an in-doubt publish
/// retained in the mount's publication store.
fn begin_unfinished_publication(
    ready: &mut crate::WritableReadiness<Authority, OverlayDisk>,
    input: &WritableStart<'_>,
) {
    let fixture = include_bytes!(
        "../../../../../../granary-core/tests/vectors/retained-submission/ready.bin"
    );
    let mut submission = granary_core::retained_submission::decode(fixture).unwrap();
    submission.scope = input.scope.clone().unwrap();
    submission.volume = input.volume.clone();
    for candidate in &mut submission.candidates {
        let mut doc = root::decode_root(&candidate.root).unwrap();
        doc.volume = input.volume.clone();
        candidate.root = root::encode_root(&doc).unwrap();
        candidate.id = GrainId::of(&candidate.root);
    }
    let mut frozen = root::decode_root(&submission.frozen.initial_root).unwrap();
    frozen.volume = input.volume.clone();
    submission.frozen.initial_root = root::encode_root(&frozen).unwrap();
    ready
        .mediator_for_test()
        .publication_transaction(|store| store.begin(&submission))
        .unwrap();
}

/// A restart that refuses leaves the clean journal on its own base, byte for
/// byte, however late in the start it refuses: for a registered root whose
/// tree no published root holds, for a transient read of the registered
/// root's seq, and beside a publication still in doubt, where replay's base
/// refusal now meets the uncarried journal first. The head moved in every
/// case, so a carry would otherwise have rewritten the journal.
#[test]
fn a_refused_start_leaves_the_journal_on_its_base() {
    let rt = runtime();
    let mut outcomes = Vec::new();
    for case in [
        "unpublished root",
        "transient read",
        "unfinished publication",
    ] {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let state = first_start(&tree, &input, |ready, state| match case {
            "unpublished root" => {
                let registered = ready.mediator_for_test().snapshot().root.clone();
                let mut doc = root::decode_root(&registered).unwrap();
                doc.manifest_root = granary_core::manifest::build_dir(&[]).unwrap().root;
                let (seq, parent) = (doc.seq, doc.parent);
                plant_registered_root(ready, state, signed(&tree.key, doc, seq, parent));
            }
            "unfinished publication" => begin_unfinished_publication(ready, &input),
            _ => {}
        });
        publish_head(&tree, &rt, REMOTE_CONTENT, |_| ());
        extend_head(&tree, &rt, tree.seq + 1);
        if case == "transient read" {
            let seq = root::decode_root(&registered_root(&state)).unwrap().seq;
            state.lock().unwrap().root_fault.insert(
                seq,
                RootStoreError::Elapsed {
                    operation: "GET root",
                    after: std::time::Duration::from_secs(1),
                },
            );
        }
        let (before, _) = journal_files(&paths, &input);
        let result = restart(&input, &tree, &state);
        let (after, temporary) = journal_files(&paths, &input);
        outcomes.push((case, outcome(&result), after == before, temporary));
    }
    assert_eq!(
        outcomes,
        [
            ("unpublished root", "WritableRecoveryRequired", true, false),
            (
                "transient read",
                "WritableAuthorityUnavailable",
                true,
                false
            ),
            (
                "unfinished publication",
                "base root/sequence mismatch",
                true,
                false
            ),
        ]
    );
}

/// The start carries only with no request retained and no publication in
/// doubt. A start reaches its open with every intent request settled, its
/// succession closing any registration, so a retained request is built on a
/// ready mount and the start's gate is asked about it directly.
#[test]
fn the_carry_waits_for_every_retained_request_and_a_settled_publication() {
    let tree = mounted_operation_tree();
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, state, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = result.unwrap();
    ready
        .mediator_for_test()
        .prepare_release(
            &Time(Arc::clone(&state)),
            std::time::Duration::from_secs(10),
            None,
        )
        .unwrap();
    let retained = ready.mediator_for_test().retained_requests();
    let permitted = crate::writable_start::carry_permitted;
    assert_eq!(
        (
            retained
                .iter()
                .map(PendingIntent::operation)
                .collect::<Vec<_>>(),
            permitted(&retained, false),
            permitted(&[], true),
            permitted(&[], false),
        ),
        (vec![Operation::Release], false, false, true)
    );
}
