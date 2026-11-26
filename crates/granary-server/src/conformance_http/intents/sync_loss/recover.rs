// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The explicit recovery command against the production authority judge.
//! Each writer is a real store whose syncs the authority acknowledged before
//! the store was lost; a row named for the judge alone sends packets itself.

use super::*;
#[cfg(feature = "overlay-fault-tests")]
mod journal;
use granary_client::RecoveryCommand;
use granary_core::overlay_journal::DeleteKind;
use granary_core::overlay_ownership::{Operation, Phase};
use granary_core::root::{RootSig, signing_prefix_of};

/// A writer the authority holds no row for.
const ABSENT: [u8; 16] = [1; 16];

async fn prepared(
    fx: &Fixture,
    http: &HttpStore,
    files: &[(&str, &[u8])],
    writer: [u8; 16],
) -> Vec<u8> {
    let content = Content::default();
    let entries: Vec<_> = files
        .iter()
        .map(|(name, bytes)| {
            let id = GrainId::of(bytes);
            content.objects.lock().unwrap().insert(id, bytes.to_vec());
            manifest::DirEntry {
                name: Name::new(name.as_bytes().to_vec()).unwrap(),
                kind: manifest::EntryKind::File {
                    exec: false,
                    size: bytes.len() as u64,
                    grains: FileGrains::Inline(vec![manifest::GrainRef {
                        id,
                        unpacked_len: u32::try_from(bytes.len()).unwrap(),
                    }]),
                },
            }
        })
        .collect();
    let tree = manifest::build_dir(&entries).unwrap();
    content.objects.lock().unwrap().extend(tree.nodes);
    let (key, _) = signer();
    let root = granary_client::prepare_from_manifest(
        http,
        &content,
        tree.root,
        granary_client::HarvestStats::default(),
        &fx.volume(),
        &key,
        &granary_core::identity::WriterIdentity::from_bytes(writer),
        fx.clock.now(),
        Policy::default(),
    )
    .await
    .unwrap();
    let mut doc = granary_core::root::decode_root(&root.root_bytes).unwrap();
    doc.writer_uuid = writer;
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&signing_prefix_of(&doc).unwrap()),
    });
    granary_core::root::encode_root(&doc).unwrap()
}

pub(in crate::conformance_http::intents) async fn land(
    fx: &Fixture,
    addr: SocketAddr,
    http: &HttpStore,
    root: Vec<u8>,
    label: &str,
) {
    let path = fx.dir.join(label);
    let mut disk = Store::open(&path).unwrap();
    let (key, keys) = signer();
    let writer = granary_core::root::decode_root(&root).unwrap().writer_uuid;
    let result = begin_exact_publication(
        RecoveryParts {
            transport: http,
            journal: &mut disk
                .publications(std::fs::metadata(&path).unwrap().uid())
                .unwrap(),
            publisher_keys: &keys,
            signer: &key,
            secure: &mut SeededSecureRandom::for_incarnation(
                71,
                u32::try_from(NEXT_RUN.fetch_add(1, Ordering::Relaxed)).unwrap(),
            ),
            clock: &fx.clock,
            delay: &mut RecoveryBackoff {
                rng: SeededRng::new(2),
            },
        },
        fx.scope(addr, 0),
        fx.volume(),
        writer,
        root,
    )
    .await;
    assert!(
        matches!(&result, Ok(result) if matches!(result.outcome, PublicationOutcome::Landed(_))),
        "fixture landing: {result:?}"
    );
}

async fn command(
    fx: &Fixture,
    addr: SocketAddr,
    remote: Arc<Cut>,
    path: PathBuf,
    writer: [u8; 16],
    acknowledge_takeover: Option<[u8; 16]>,
) -> Result<(), String> {
    let scope = fx.scope(addr, 0);
    let volume = fx.volume();
    let clock = fx.clock.clone();
    *remote.recovery_clock.lock().unwrap() = Some(clock.clone());
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    tokio::task::spawn_blocking(move || {
        let _dispatch = tracing::dispatcher::set_default(&dispatch);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let disk = Store::open(&path).unwrap();
        let (key, keys) = signer();
        let landing_key = signer().0;
        RecoveryCommand {
            construction_workspace_bytes: granary_client::SyncOptions::default().workspace_bytes,
            acknowledge_resend: None,
            faults: remote.recovery_faults.clone(),
            local: Some((
                disk,
                OverlayDisk::new(&path, std::fs::metadata(&path).unwrap().uid()),
            )),
            config: config(&path, scope, volume),
            transport: remote.as_ref(),
            runtime: &runtime,
            signer: &key,
            publisher_keys: &keys,
            writer,
            acknowledge_takeover,
        }
        .run(
            &Arc::new(clock),
            landing_key,
            &mut SeededSecureRandom::for_incarnation(
                81,
                u32::try_from(NEXT_RUN.fetch_add(1, Ordering::Relaxed)).unwrap(),
            ),
            SeededRng::new(2),
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    })
    .await
    .unwrap()
}

static NEXT_RUN: AtomicU64 = AtomicU64::new(0);

/// What the authority holds of a writer whose store was lost: its id, the
/// receipt its store last held and its registered prepared root.
struct Lost {
    writer: [u8; 16],
    receipt: Receipt,
    root: Vec<u8>,
}

/// A writer attached at `label` over an empty base, the base, and its content.
async fn writer_at(fx: &Fixture, addr: SocketAddr, label: &str) -> (Writer, Vec<u8>, Arc<Content>) {
    let content = Arc::new(Content::default());
    let mut secure = SeededSecureRandom::from_key([31; 32]);
    let (writer, base) =
        Box::pin(attach(fx, addr, &fx.dir.join(label), &content, &mut secure)).await;
    (writer, base, content)
}

/// Sync each of `stages`, then the namespace; the authority acknowledges
/// them by registering the writer's prepared root.
async fn acknowledged(writer: &Writer, stages: &[u64]) {
    for target in stages
        .iter()
        .map(|stage| SyncTarget::Stage(*stage))
        .chain([SyncTarget::Directory(None)])
    {
        writer
            .engine
            .sync(target, SyncOptions::default())
            .wait()
            .await
            .unwrap();
    }
}

fn recorded(writer: &Writer) -> Lost {
    let local = writer.local.lock().unwrap();
    let snapshot = local.snapshot();
    Lost {
        writer: local.writer_uuid(),
        receipt: intent::decode_receipt(&snapshot.current).unwrap(),
        root: snapshot.root.clone(),
    }
}

/// An acknowledged sync of `stages`, then the writer's whole store lost.
async fn lose(fx: &Fixture, writer: Writer, label: &str, stages: &[u64]) -> Lost {
    acknowledged(&writer, stages).await;
    let lost = recorded(&writer);
    writer.crash().await;
    std::fs::remove_dir_all(fx.dir.join(label)).unwrap();
    lost
}

/// A writer that wrote `files` over an empty base and lost its store after
/// their acknowledged sync; and the base.
async fn lost(fx: &Fixture, addr: SocketAddr, files: &[(&str, &[u8])]) -> (Lost, Vec<u8>) {
    let (writer, base, _) = writer_at(fx, addr, "lost-store").await;
    let stages: Vec<_> = files
        .iter()
        .map(|(name, bytes)| writer.create(name, bytes))
        .collect();
    (lose(fx, writer, "lost-store", &stages).await, base)
}

/// A writer whose acknowledged sync registered an older `a`, whose commit of
/// a sealed `a` the authority installed without the writer hearing, and
/// whose store was then lost; and the landed head. The row still names the
/// older prepared root.
async fn landed_then_lost(fx: &Fixture, addr: SocketAddr) -> (Lost, Vec<u8>) {
    let (writer, _, _) = writer_at(fx, addr, "lost-store").await;
    let stage = writer.create("a", b"older a");
    acknowledged(&writer, &[stage]).await;
    let lost = recorded(&writer);
    writer.write(stage, b"sealed a");
    *writer.remote.hold.lock().unwrap() = Some(Hold::Landed);
    let options = SyncOptions {
        resolution_bound: Duration::from_secs(10),
        ..SyncOptions::default()
    };
    let mut secure = SeededSecureRandom::from_key([33; 32]);
    let lane = writer
        .engine
        .construct_commit(options, &mut secure)
        .await
        .unwrap();
    let answered = Box::pin(writer.engine.drive_commit(
        &lane,
        &mut secure,
        &mut RecoveryBackoff {
            rng: SeededRng::new(2),
        },
        RecoveryIntent::Continue,
        options,
    ))
    .await
    .map_or_else(|error| error.to_string(), |_| "answered".to_owned());
    writer.crash().await;
    std::fs::remove_dir_all(fx.dir.join("lost-store")).unwrap();
    let landed = head(fx, addr).await;
    let row = selected_root(fx, addr, lost.writer).await;
    assert_eq!(
        (
            answered.as_str(),
            row.as_deref() == Some(lost.root.as_slice()),
            landed != lost.root,
            granary_core::root::decode_root(&landed)
                .unwrap()
                .writer_uuid
                == lost.writer,
        ),
        ("intent refused: SyncDeadline", true, true, true),
        "unanswered landing premise: (answer, row names the older root, head moved, head carries W)"
    );
    (lost, landed)
}

/// The authority's ownership allocator cursor and its count of live rows.
async fn readback(fx: &Fixture, addr: SocketAddr) -> (u64, usize) {
    let http = fx.client(addr, 0);
    let reply = http
        .intent_readback_once(&fx.scope(addr, 0), &fx.volume(), verifies(&signer().1))
        .await
        .unwrap();
    let decoded =
        intent::decode_readback(reply.body(), &fx.volume(), verifies(&signer().1)).unwrap();
    (decoded.cursor, decoded.rows.len())
}

async fn live_rows(fx: &Fixture, addr: SocketAddr) -> usize {
    readback(fx, addr).await.1
}

/// The prepared root the authority's live row for `writer` names.
async fn selected_root(fx: &Fixture, addr: SocketAddr, writer: [u8; 16]) -> Option<Vec<u8>> {
    let http = fx.client(addr, 0);
    let reply = http
        .intent_readback_once(&fx.scope(addr, 0), &fx.volume(), verifies(&signer().1))
        .await
        .unwrap();
    intent::decode_readback(reply.body(), &fx.volume(), verifies(&signer().1))
        .unwrap()
        .rows
        .iter()
        .find(|row| row.writer == writer)
        .map(|row| row.root.to_vec())
}

/// The phase a store's carrier persisted.
fn phase(fx: &Fixture, addr: SocketAddr, label: &str) -> Phase {
    let path = fx.dir.join(label);
    WritableStore::new(
        Store::open(&path).unwrap(),
        config(&path, fx.scope(addr, 0), fx.volume()),
        OverlayDisk::new(&path, std::fs::metadata(&path).unwrap().uid()),
        &mut SeededSecureRandom::from_key([43; 32]),
        FaultControl::default(),
        verifies(&signer().1),
    )
    .unwrap()
    .snapshot()
    .phase
}

#[tokio::test]
async fn a5_exact_parent_lands_releases_and_restarts_without_another_send() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let (lost, _) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
    let remote = Arc::new(Cut::new(fx.client(server.addr, 0)));
    let path = fx.dir.join("recovered");
    let result = command(
        &fx,
        server.addr,
        remote.clone(),
        path.clone(),
        lost.writer,
        Some(lost.writer),
    )
    .await;
    let again = command(&fx, server.addr, remote.clone(), path, lost.writer, None).await;
    assert_eq!(
        (
            result,
            again,
            head(&fx, server.addr).await == lost.root,
            head_file(&fx, server.addr, "a").await,
            live_rows(&fx, server.addr).await,
            remote.recovery_sends.lock().unwrap().len()
        ),
        (Ok(()), Ok(()), true, Some(b"prepared a".to_vec()), 0, 2)
    );
    server.stop().await;
}

#[tokio::test]
async fn a6_disjoint_rebase_keeps_both_writers_changes() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let (lost, _) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
    let http = fx.client(server.addr, 0);
    let foreign = prepared(&fx, &http, &[("b", b"foreign b")], [77; 16]).await;
    land(&fx, server.addr, &http, foreign, "foreign-store").await;
    let result = command(
        &fx,
        server.addr,
        Arc::new(Cut::new(http)),
        fx.dir.join("recovered"),
        lost.writer,
        Some(lost.writer),
    )
    .await;
    assert_eq!(
        (
            result,
            head_file(&fx, server.addr, "a").await,
            head_file(&fx, server.addr, "b").await,
            live_rows(&fx, server.addr).await
        ),
        (
            Ok(()),
            Some(b"prepared a".to_vec()),
            Some(b"foreign b".to_vec()),
            0
        )
    );
    server.stop().await;
}

/// The writer's own commit landed `a`; its lost sync then modified (or
/// deleted) `a` while a foreign landing deleted (or modified) it.
#[tokio::test]
async fn a7_modify_against_delete_conflicts_keep_the_intent_and_head() {
    let mut outcomes = Vec::new();
    for ours_deletes in [false, true] {
        let fx = Fixture::new(None);
        let server = fx.start(1, roomy(), true, None).await;
        let (writer, _, _) = writer_at(&fx, server.addr, "lost-store").await;
        let a = writer.create("a", b"base a");
        writer.hold("a");
        writer
            .commit(&mut SeededSecureRandom::from_key([33; 32]))
            .await;
        let synced = if ours_deletes {
            writer
                .local
                .lock()
                .unwrap()
                .overlay_transaction(|t| {
                    t.namespace_record(Record::Delete {
                        at: at("a"),
                        kind: DeleteKind::File { stage_id: Some(a) },
                    })
                })
                .unwrap();
            vec![]
        } else {
            writer.write(a, b"our a");
            vec![a]
        };
        let lost = lose(&fx, writer, "lost-store", &synced).await;
        let http = fx.client(server.addr, 0);
        let theirs: &[(&str, &[u8])] = if ours_deletes {
            &[("a", b"their a")]
        } else {
            &[]
        };
        let foreign = prepared(&fx, &http, theirs, [77; 16]).await;
        land(&fx, server.addr, &http, foreign.clone(), "foreign-store").await;
        let remote = Arc::new(Cut::new(http));
        let result = command(
            &fx,
            server.addr,
            remote.clone(),
            fx.dir.join("recovered"),
            lost.writer,
            Some(lost.writer),
        )
        .await;
        outcomes.push((
            ours_deletes,
            result.err(),
            head(&fx, server.addr).await == foreign,
            live_rows(&fx, server.addr).await,
            remote.recovery_sends.lock().unwrap().len(),
        ));
        server.stop().await;
    }
    let conflict = Some("RecoveryConflict".to_owned());
    assert_eq!(
        outcomes,
        [
            (false, conflict.clone(), true, 1, 1),
            (true, conflict, true, 1, 1)
        ],
        "(ours deletes, refusal, head kept, live rows, ownership sends)"
    );
}

/// A row changed between the readback and the takeover, by a refresh, a
/// takeover or a release: one readback, one takeover, and a stop.
#[tokio::test]
async fn a8_changed_selection_stops_after_one_readback_and_takeover() {
    for race in ["intent-changed", "intent-superseded", "released"] {
        let fx = Fixture::new(None);
        let server = fx.start(1, roomy(), true, None).await;
        let (lost, base) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
        let row = lost.receipt;
        let remote = Arc::new(Cut::new(fx.client(server.addr, 0)));
        *remote.recovery_race.lock().unwrap() = Some(match race {
            "intent-changed" => (
                Operation::Register,
                intent::encode_register(
                    &row.writer,
                    row.epoch,
                    &row.instance,
                    row.generation + 1,
                    &lost.root,
                )
                .unwrap(),
            ),
            "intent-superseded" => (Operation::Ownership, takeover(row, 6)),
            _ => (Operation::Release, release(row, row.generation)),
        });
        let result = command(
            &fx,
            server.addr,
            remote.clone(),
            fx.dir.join("recovered"),
            lost.writer,
            Some(lost.writer),
        )
        .await;
        let sends = remote.recovery_sends.lock().unwrap().len();
        assert_eq!(
            (
                result.err(),
                remote.recovery_reads.load(Ordering::Relaxed),
                sends,
                head(&fx, server.addr).await == base,
                live_rows(&fx, server.addr).await
            ),
            (
                Some("IntentSelectionChanged".into()),
                1,
                1,
                true,
                usize::from(race != "released")
            ),
            "{race}"
        );
        server.stop().await;
    }
}

#[tokio::test]
async fn a1_a9_conflict_while_a2_a3_have_published_ancestry() {
    for row_name in ["a1", "a2", "a3", "a9"] {
        let fx = Fixture::new(None);
        let server = fx.start(1, roomy(), true, None).await;
        let http = fx.client(server.addr, 0);
        let lost = if matches!(row_name, "a1" | "a9") {
            landed_then_lost(&fx, server.addr).await.0
        } else {
            let (lost, _) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
            land(&fx, server.addr, &http, lost.root.clone(), "landed-store").await;
            lost
        };
        if row_name == "a3" {
            let descendant = prepared(&fx, &http, &[("a", b"descendant a")], [77; 16]).await;
            land(&fx, server.addr, &http, descendant, "descendant-store").await;
        }
        if row_name == "a9" {
            let row = lost.receipt;
            let scope = fx.scope(server.addr, 0);
            let moved = http
                .intent_takeover_once(&scope, &fx.volume(), &takeover(row, 3))
                .await
                .unwrap();
            let moved = granted(&moved).receipt;
            let landed = head(&fx, server.addr).await;
            let refresh = intent::encode_register(
                &row.writer,
                row.epoch,
                &row.instance,
                row.generation + 1,
                &landed,
            )
            .unwrap();
            let reply = http
                .intent_register_once(&scope, &fx.volume(), &refresh, verifies(&signer().1))
                .await
                .unwrap();
            let verdict = reply.registration(&intent::RegisterRequest {
                writer: row.writer,
                epoch: row.epoch,
                instance: row.instance,
                generation: row.generation + 1,
                root_id: GrainId::of(&landed),
            });
            assert_eq!(
                (
                    reply.status(),
                    matches!(verdict, Verdict::Superseded(receipt) if receipt == moved)
                ),
                (409, true),
                "A9 premise: {verdict:?}"
            );
        }
        let before = head(&fx, server.addr).await;
        let remote = Arc::new(Cut::new(http));
        let result = command(
            &fx,
            server.addr,
            remote.clone(),
            fx.dir.join("recovered"),
            lost.writer,
            Some(lost.writer),
        )
        .await;
        assert_eq!(
            (
                result,
                head(&fx, server.addr).await == before,
                live_rows(&fx, server.addr).await,
                remote.recovery_sends.lock().unwrap().len()
            ),
            if matches!(row_name, "a1" | "a9") {
                // An older prepared sibling and a displaced owner's landing
                // are log-identical: writer identity cannot prove publication.
                (Err("RecoveryConflict".into()), true, 1, 1)
            } else {
                (Ok(()), true, 0, 2)
            },
            "{row_name}: only published ancestry permits release"
        );
        if matches!(row_name, "a1" | "a9") {
            assert_eq!(
                selected_root(&fx, server.addr, lost.writer).await,
                Some(lost.root)
            );
        }
        server.stop().await;
    }
}

#[tokio::test]
async fn a4_verified_divergent_history_is_stale_and_keeps_the_row() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let (lost, base) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
    let row = lost.receipt;
    let http = fx.client(server.addr, 0);
    let (key, keys) = signer();
    let mut doc = granary_core::root::decode_root(&lost.root).unwrap();
    doc.parent = Some(GrainId::of(b"a different verified history"));
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&signing_prefix_of(&doc).unwrap()),
    });
    let root = granary_core::root::encode_root(&doc).unwrap();
    let register = intent::encode_register(
        &row.writer,
        row.epoch,
        &row.instance,
        row.generation + 1,
        &root,
    )
    .unwrap();
    let reply = http
        .intent_register_once(
            &fx.scope(server.addr, 0),
            &fx.volume(),
            &register,
            verifies(&keys),
        )
        .await
        .unwrap();
    assert_eq!(
        reply.status(),
        200,
        "divergent prepared root premise: status={} body={:?}",
        reply.status(),
        reply.body()
    );
    let remote = Arc::new(Cut::new(http));
    let result = command(
        &fx,
        server.addr,
        remote.clone(),
        fx.dir.join("recovered"),
        lost.writer,
        Some(lost.writer),
    )
    .await;
    assert_eq!(
        (
            result.err(),
            head(&fx, server.addr).await == base,
            live_rows(&fx, server.addr).await,
            remote.recovery_sends.lock().unwrap().len()
        ),
        (Some("intent refused: RecoveryStale".into()), true, 1, 1)
    );
    server.stop().await;
}

/// An earlier recovery's store survives, owned by its granted takeover with
/// a clean journal and the prepared root unpublished: the command succeeds
/// that ownership before publishing. (A mounted writer's own store holds
/// captured journal records, which explicit recovery finishes under its bound.)
#[tokio::test]
async fn a10_intact_owned_store_succeeds_itself_before_publishing() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let (lost, _) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
    let http = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let readback = http
        .intent_readback_once(&scope, &fx.volume(), verifies(&signer().1))
        .await
        .unwrap();
    let mut local =
        super::super::recovery(&fx, scope.clone(), &readback, lost.writer, "intact-store");
    let request = local.begin_selected_attempt(&fx.clock).unwrap();
    local.dispatch(&request, &fx.clock).unwrap();
    let reply = http
        .intent_takeover_once(&scope, &fx.volume(), request.bytes())
        .await
        .unwrap();
    complete(&mut local, &request, &reply, &fx.clock);
    let owned = intent::decode_receipt(&local.snapshot().current)
        .unwrap()
        .epoch;
    drop(local);
    let remote = Arc::new(Cut::new(http));
    let result = command(
        &fx,
        server.addr,
        remote.clone(),
        fx.dir.join("intact-store"),
        lost.writer,
        None,
    )
    .await;
    let (sends, first) = {
        let sends = remote.recovery_sends.lock().unwrap();
        (
            sends.len(),
            sends
                .first()
                .map(|send| intent::decode_ownership(send).unwrap().mode),
        )
    };
    assert_eq!(
        (
            result,
            head(&fx, server.addr).await == lost.root,
            sends,
            matches!(first, Some(OwnershipMode::Takeover { expected_epoch, recovery_ack: false, .. }) if expected_epoch == owned)
        ),
        (Ok(()), true, 2, true),
        "first send: {first:?}"
    );
    server.stop().await;
}

/// The judge alone: a takeover packet whose epoch, generation, state or root
/// id differs from the row is refused, and the exact one is granted.
#[tokio::test]
async fn judge_alone_compares_takeover_epoch_generation_state_and_root_id() {
    for limb in ["epoch", "generation", "state", "root id"] {
        let fx = Fixture::new(None);
        let server = fx.start(1, roomy(), true, None).await;
        let (lost, _) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
        let http = fx.client(server.addr, 0);
        let scope = fx.scope(server.addr, 0);
        let advanced = http
            .intent_takeover_once(&scope, &fx.volume(), &takeover(lost.receipt, 6))
            .await
            .unwrap();
        let row = granted(&advanced).receipt;
        let mut selected = row;
        match limb {
            "epoch" => selected.epoch = row.epoch.checked_sub(1).unwrap(),
            "generation" => selected.generation += 1,
            "state" => selected.state = intent::ReceiptState::Released,
            _ => {
                selected.state = intent::ReceiptState::Live {
                    prepared_root_id: GrainId::of(b"foreign prepared root"),
                }
            }
        }
        let body = takeover(selected, 3);
        let answer = http
            .intent_takeover_once(&scope, &fx.volume(), &body)
            .await
            .unwrap();
        let refused = answer.ownership(&body).unwrap();
        assert_eq!(
            (
                answer.status(),
                matches!(refused, Verdict::Superseded(_) if limb == "epoch")
                    || matches!(refused, Verdict::Changed(_) if limb != "epoch")
            ),
            (409, true),
            "{limb}: {refused:?}"
        );
        let control = takeover(row, 4);
        let accepted = http
            .intent_takeover_once(&scope, &fx.volume(), &control)
            .await
            .unwrap();
        assert!(
            matches!(accepted.ownership(&control).unwrap(), Verdict::Accepted(_)),
            "{limb}: paired exact selection failed"
        );
        server.stop().await;
    }
}

/// An adoption persisted its selection; the row then changed at the
/// authority in one compared limb before the takeover was sent. The command
/// sends the persisted selection, not the row as it now reads: the judge
/// refuses it, the allocator's cursor does not move and the carrier stays
/// unowned. The judge never rebinds a root at the same generation, so the
/// root id changes with the generation.
#[tokio::test]
async fn adopted_takeover_sends_each_persisted_limb_after_the_row_changed() {
    let mut outcomes = Vec::new();
    for limb in ["epoch", "generation", "state", "root id"] {
        let fx = Fixture::new(None);
        let server = fx.start(1, roomy(), true, None).await;
        let (lost, _) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
        let row = lost.receipt;
        let http = fx.client(server.addr, 0);
        let scope = fx.scope(server.addr, 0);
        let selected = http
            .intent_readback_once(&scope, &fx.volume(), verifies(&signer().1))
            .await
            .unwrap();
        drop(super::super::recovery(
            &fx,
            scope.clone(),
            &selected,
            lost.writer,
            "adopted-store",
        ));
        let refresh = |root: &[u8]| {
            intent::encode_register(
                &row.writer,
                row.epoch,
                &row.instance,
                row.generation + 1,
                root,
            )
            .unwrap()
        };
        let changed = match limb {
            "epoch" => http
                .intent_takeover_once(&scope, &fx.volume(), &takeover(row, 6))
                .await
                .unwrap(),
            "generation" => http
                .intent_register_once(
                    &scope,
                    &fx.volume(),
                    &refresh(&lost.root),
                    verifies(&signer().1),
                )
                .await
                .unwrap(),
            "state" => http
                .intent_release_once(&scope, &fx.volume(), &release(row, row.generation))
                .await
                .unwrap(),
            _ => {
                let other = prepared(&fx, &http, &[("a", b"another a")], lost.writer).await;
                http.intent_register_once(
                    &scope,
                    &fx.volume(),
                    &refresh(&other),
                    verifies(&signer().1),
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(
            changed.status(),
            200,
            "{limb} premise: body={:?}",
            changed.body()
        );
        let cursor = readback(&fx, server.addr).await.0;
        let remote = Arc::new(Cut::new(http));
        let result = command(
            &fx,
            server.addr,
            remote.clone(),
            fx.dir.join("adopted-store"),
            lost.writer,
            None,
        )
        .await;
        let sends = remote.recovery_sends.lock().unwrap().len();
        outcomes.push((
            limb,
            result.err(),
            remote.recovery_reads.load(Ordering::Relaxed),
            sends,
            readback(&fx, server.addr).await.0 == cursor,
            phase(&fx, server.addr, "adopted-store"),
        ));
        server.stop().await;
    }
    let changed = Some("IntentSelectionChanged".to_owned());
    assert_eq!(
        outcomes,
        [
            ("epoch", changed.clone(), 0, 1, true, Phase::Fenced),
            ("generation", changed.clone(), 0, 1, true, Phase::Unowned),
            ("state", changed.clone(), 0, 1, true, Phase::Unowned),
            ("root id", changed, 0, 1, true, Phase::Unowned),
        ],
        "(limb, refusal, readbacks, takeover sends, cursor kept, carrier phase)"
    );
}

#[tokio::test]
async fn restart_after_adoption_starts_the_retained_takeover_without_reselecting() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let (lost, _) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
    let http = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let readback = http
        .intent_readback_once(&scope, &fx.volume(), verifies(&signer().1))
        .await
        .unwrap();
    let local = super::super::recovery(&fx, scope, &readback, lost.writer, "adopted-store");
    let body = local.snapshot().pending[0].body.clone();
    drop(local);
    let remote = Arc::new(Cut::new(http));
    let result = command(
        &fx,
        server.addr,
        remote.clone(),
        fx.dir.join("adopted-store"),
        lost.writer,
        None,
    )
    .await;
    let (sends, exact) = {
        let sends = remote.recovery_sends.lock().unwrap();
        (sends.len(), sends.first() == Some(&body))
    };
    assert_eq!(
        (
            result,
            remote.recovery_reads.load(Ordering::Relaxed),
            sends,
            exact,
            head(&fx, server.addr).await == lost.root,
            live_rows(&fx, server.addr).await
        ),
        (Ok(()), 0, 3, true, true, 0)
    );
    server.stop().await;
}

#[expect(
    clippy::too_many_lines,
    reason = "one ownership schedule binds repeated takeovers, delayed packets, lost replies, restart and released eviction"
)]
#[tokio::test]
async fn delayed_refresh_and_release_never_regain_ownership_after_repeated_takeovers() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let (lost, _) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
    let old = lost.receipt;
    let http = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let later = old.generation + 1;
    let refresh =
        intent::encode_register(&old.writer, old.epoch, &old.instance, later, &lost.root).unwrap();
    let mut current = old;
    for token in [3, 4, 5] {
        let body = takeover(current, token);
        let first = http
            .intent_takeover_once(&scope, &fx.volume(), &body)
            .await
            .unwrap();
        let retry = http
            .intent_takeover_once(&scope, &fx.volume(), &body)
            .await
            .unwrap();
        assert_eq!(
            (first.status(), retry.status(), first.body() == retry.body()),
            (200, 200, true),
            "token={token}: lost-reply replay allocated another epoch"
        );
        current = granted(&first).receipt;
        for generation in [old.generation - 1, old.generation, later] {
            let answer = http
                .intent_release_once(&scope, &fx.volume(), &release(old, generation))
                .await
                .unwrap();
            assert_eq!(
                (
                    answer.status(),
                    intent::decode_receipt(answer.body()).unwrap()
                ),
                (409, current),
                "old release G={generation} must report the current lower-G owner"
            );
        }
        let answer = http
            .intent_register_once(&scope, &fx.volume(), &refresh, verifies(&signer().1))
            .await
            .unwrap();
        assert_eq!(
            (
                answer.status(),
                intent::decode_receipt(answer.body()).unwrap()
            ),
            (409, current),
            "a delayed refresh at G={later} must not displace the current E at G={}",
            old.generation
        );
    }
    let addr = server.stop().await;
    let server = fx.start(2, roomy(), false, Some(addr)).await;
    let remote = Arc::new(Cut::new(fx.client(addr, 0)));
    remote.lose_takeover.store(true, Ordering::Relaxed);
    let result = command(
        &fx,
        addr,
        remote.clone(),
        fx.dir.join("recovered"),
        lost.writer,
        Some(lost.writer),
    )
    .await;
    let (sends, identical) = {
        let sends = remote.recovery_sends.lock().unwrap();
        (sends.len(), sends[0] == sends[1])
    };
    assert_eq!(
        (result, sends, identical, live_rows(&fx, addr).await),
        (Ok(()), 3, true, 0)
    );
    let retained_cursor = readback(&fx, addr).await.0;
    assert!(
        retained_cursor > current.epoch,
        "the command's takeover must advance the cursor: {retained_cursor}, previous owner {current:?}"
    );
    fx.clock.0.store(1_000_000, Ordering::Relaxed);
    assert_eq!(
        server
            .handle
            .maintain_intents(&fx.volume(), &fx.enrolled(), 0)
            .await
            .status()
            .as_u16(),
        200
    );
    let addr = server.stop().await;
    let server = fx.start(3, roomy(), false, Some(addr)).await;
    let http = fx.client(addr, 0);
    let absent = http
        .intent_release_once(&scope, &fx.volume(), &release(old, later))
        .await
        .unwrap();
    assert!(matches!(
        absent.release(&intent::ReleaseRequest {
            writer: old.writer,
            epoch: old.epoch,
            instance: old.instance,
            generation: later
        }),
        Verdict::Absent
    ));
    let remote = Arc::new(Cut::new(http));
    let nothing = command(
        &fx,
        addr,
        remote.clone(),
        fx.dir.join("after-eviction"),
        lost.writer,
        Some(lost.writer),
    )
    .await;
    assert_eq!(
        (nothing.err(), remote.recovery_sends.lock().unwrap().len()),
        (
            Some("intent refused: IntentSelectedWriterMissing".into()),
            0
        )
    );
    let cursor = readback(&fx, addr).await.0;
    assert_eq!(
        cursor, retained_cursor,
        "eviction and restart must retain the allocator cursor"
    );
    let next = remote
        .inner
        .intent_acquire_once(&scope, &fx.volume(), &acquire(2, 6, cursor))
        .await
        .unwrap();
    assert!(
        granted(&next).receipt.epoch > retained_cursor,
        "eviction and restart must preserve the ownership allocator"
    );
    server.stop().await;
}

/// A landing the writer never heard of, its store then lost and the
/// authority restarted: the command refuses unproved siblings and keeps the row.
#[tokio::test]
async fn lost_store_after_an_unanswered_landing_conflicts_after_authority_restart() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let (lost, landed) = landed_then_lost(&fx, server.addr).await;
    let addr = server.stop().await;
    let server = fx.start(2, roomy(), false, Some(addr)).await;
    let selected = granary_core::root::decode_root(&lost.root).unwrap();
    let published = granary_core::root::decode_root(&landed).unwrap();
    let parent_bytes = fx
        .client(addr, 0)
        .get_root(fx.volume().as_str(), 1)
        .await
        .unwrap()
        .unwrap();
    let parent = granary_core::root::decode_root(&parent_bytes).unwrap();
    let parent_id = GrainId::of(&parent_bytes);
    let shapes = (
        (selected.seq, selected.parent, selected.writer_uuid),
        (published.seq, published.parent, published.writer_uuid),
        parent.seq,
        selected.manifest_root == published.manifest_root,
        selected.manifest_root == parent.manifest_root,
        lost.root == landed,
    );
    // These are log-identical to A1/A9 and displacement: same-writer,
    // same-parent siblings with different manifests, not a published selection.
    assert_eq!(
        shapes,
        (
            (2, Some(parent_id), lost.writer),
            (2, Some(parent_id), lost.writer),
            1,
            false,
            false,
            false
        ),
        "premise: an older acknowledged tree and newer landing are unproved siblings; selected/head shapes and manifest equality (head, parent): {shapes:?}"
    );
    let remote = Arc::new(Cut::new(fx.client(addr, 0)));
    let recovered = command(
        &fx,
        addr,
        remote.clone(),
        fx.dir.join("recovered"),
        lost.writer,
        Some(lost.writer),
    )
    .await;
    assert_eq!(
        (
            recovered,
            head(&fx, addr).await == landed,
            head_file(&fx, addr, "a").await,
            live_rows(&fx, addr).await,
            selected_root(&fx, addr, lost.writer).await == Some(lost.root.clone()),
            remote.recovery_sends.lock().unwrap().len(),
            remote.publication_sends.lock().unwrap().len(),
        ),
        (
            Err("RecoveryConflict".into()),
            true,
            Some(b"sealed a".to_vec()),
            1,
            true,
            1,
            0
        ),
        "an unproved selected sibling remains live after restart and conflict"
    );
    server.stop().await;
}

#[tokio::test]
async fn a0_missing_writer_stops_without_takeover() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let (lost, _) = lost(&fx, server.addr, &[("a", b"prepared a")]).await;
    let remote = Arc::new(Cut::new(fx.client(server.addr, 0)));
    let result = command(
        &fx,
        server.addr,
        remote.clone(),
        fx.dir.join("recovered"),
        ABSENT,
        Some(ABSENT),
    )
    .await;
    let sends = remote.recovery_sends.lock().unwrap().len();
    assert_eq!(
        (
            lost.writer != ABSENT,
            result.err(),
            sends,
            live_rows(&fx, server.addr).await
        ),
        (
            true,
            Some("intent refused: IntentSelectedWriterMissing".into()),
            0,
            1
        )
    );
    server.stop().await;
}

/// A candidate B already published cannot replace B's later acknowledged selection.
#[tokio::test]
async fn repro_displaced_landing_must_not_replace_the_displacers_acknowledged_sync() {
    displaced_landing(true, false, false, b"from A").await;
}

/// Equal same-name changes coalesce; B's additional acknowledged selection stays live.
#[tokio::test]
async fn repro_displaced_rebased_commit_must_not_replace_the_displacers_acknowledged_sync() {
    displaced_landing(true, false, true, b"from A").await;
}

/// Different same-name values conflict before any publication send.
#[tokio::test]
async fn repro_displaced_rebased_different_values_conflict_before_send() {
    displaced_landing(true, false, true, b"from X").await;
}

/// The same, except that A's row already names its own landed head when B
/// takes over, so B's recovery publishes nothing and B mounts on A's base.
#[tokio::test]
async fn repro_displaced_second_commit_must_not_replace_the_displacers_acknowledged_sync() {
    displaced_landing(true, true, true, b"from A").await;
}

/// An unchanged startup root coalesces while A's stalled commit holds unsynced work.
#[tokio::test]
async fn repro_displaced_first_commit_over_startup_root_must_not_replace_the_displacers_sync() {
    displaced_landing(false, false, true, b"from A").await;
}

#[expect(
    clippy::too_many_lines,
    reason = "five displacement schedules share the same stores and exact selection checks"
)]
async fn displaced_landing(synced: bool, landed_first: bool, unsynced: bool, local_a: &[u8]) {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let addr = server.addr;
    let (a, _base, content) = writer_at(&fx, addr, "store-a").await;
    let stage = a.create("a", b"from A");
    if synced {
        acknowledged(&a, &[stage]).await;
    }
    let w = recorded(&a).writer;
    if landed_first {
        let first = a.commit(&mut SeededSecureRandom::from_key([32; 32])).await;
        assert_eq!(
            selected_root(&fx, addr, w).await,
            Some(first),
            "premise: first landing refreshed"
        );
    }
    let conflicting = local_a != b"from A";
    if conflicting {
        assert!(synced && !landed_first && unsynced);
        // Leave the earlier registration at "from A" for B's takeover,
        // but capture different same-length bytes in A's stalled candidate.
        a.write(stage, local_a);
    }
    if unsynced {
        a.create("a2", b"unsynced on A");
    }
    let before_construct = selected_root(&fx, addr, w).await;
    let options = SyncOptions {
        resolution_bound: Duration::from_secs(10),
        ..SyncOptions::default()
    };
    let mut secure = SeededSecureRandom::from_key([33; 32]);
    let lane = a
        .engine
        .construct_commit(options, &mut secure)
        .await
        .unwrap();
    assert_eq!(
        selected_root(&fx, addr, w).await,
        before_construct,
        "premise: constructing the commit does not replace the acknowledged root"
    );
    let head_before_b = head(&fx, addr).await;
    let path_b = fx.dir.join("store-b");
    let recovered = command(
        &fx,
        addr,
        Arc::new(Cut::new(fx.client(addr, 0))),
        path_b.clone(),
        w,
        Some(w),
    )
    .await;
    let r2 = head(&fx, addr).await;
    assert_eq!(
        (recovered, r2 == head_before_b),
        (Ok(()), landed_first || !synced),
        "premise: only recovery of an unpublished nonempty tree advances head"
    );
    let b = Box::pin(reopen(
        &fx,
        addr,
        &path_b,
        &content,
        &r2,
        true,
        &mut SeededSecureRandom::from_key([35; 32]),
    ))
    .await;
    if synced && !landed_first && unsynced {
        assert_eq!(
            granary_core::root::decode_root(&recorded(&b).root)
                .unwrap()
                .manifest_root,
            granary_core::root::decode_root(&r2).unwrap().manifest_root,
            "B inherits the exact recovered namespace before adding b"
        );
        assert_eq!(
            (a.read("a"), head_file(&fx, addr, "a").await),
            (Some(local_a.to_vec()), Some(b"from A".to_vec())),
            "compare A's captured bytes with B's recovered base bytes"
        );
    }
    let stage_b = b.create("b", b"acknowledged on B");
    acknowledged(&b, &[stage_b]).await;
    let p_b = recorded(&b);
    assert_eq!(
        (
            p_b.writer,
            selected_root(&fx, addr, w).await,
            head(&fx, addr).await == r2
        ),
        (w, Some(p_b.root.clone()), true),
        "premise: B acknowledged an unpublished prepared root"
    );
    if synced && !landed_first && !unsynced {
        let record = a
            .local
            .lock()
            .unwrap()
            .publication_transaction(|journal| journal.load(&fx.scope(addr, 0), &fx.volume()))
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                record.frozen.initial_root.as_slice(),
                record.candidates.len(),
                record
                    .candidates
                    .first()
                    .map(|candidate| candidate.root.as_slice()),
            ),
            (r2.as_slice(), 1, Some(r2.as_slice())),
            "premise: B already published A's exact retained candidate"
        );
    }
    let before = a.remote.publication_sends.lock().unwrap().len();
    let answered = Box::pin(a.engine.drive_commit(
        &lane,
        &mut secure,
        &mut RecoveryBackoff {
            rng: SeededRng::new(2),
        },
        RecoveryIntent::Continue,
        options,
    ))
    .await;
    let sent: Vec<_> = a
        .remote
        .publication_sends
        .lock()
        .unwrap()
        .iter()
        .skip(before)
        .cloned()
        .collect();
    let after_a = head(&fx, addr).await;
    if conflicting {
        assert_eq!(
            (
                matches!(
                    &answered,
                    Err(CoordinationError::Fenced {
                        recorded_generation: None
                    })
                ),
                sent.len(),
                after_a == r2
            ),
            (true, 0, true),
            "same-name rebase must conflict before a send: {answered:?}"
        );
    } else if synced && !landed_first && !unsynced {
        // The coordinator recognizes its candidate in the chain without a POST;
        // ownership loss still fences its subsequent landing refresh.
        assert_eq!(
            (
                matches!(&answered, Err(CoordinationError::Fenced { recorded_generation: Some(generation) })
                    if *generation == p_b.receipt.generation),
                sent.len(),
                after_a == r2,
                head_file(&fx, addr, "b").await,
            ),
            (true, 0, true, None),
            "an already published candidate requires no send before its fenced refresh: {answered:?}"
        );
    } else {
        assert_eq!(
            (
                answered.is_err(),
                sent.is_empty(),
                head_file(&fx, addr, "b").await
            ),
            (true, false, None),
            "landing loses ownership at refresh: {answered:?}"
        );
        if synced && !landed_first {
            assert!(
                matches!(&answered, Err(CoordinationError::Fenced { recorded_generation: Some(generation) })
                    if *generation == p_b.receipt.generation),
                "equal additions land once, then lose ownership at refresh: {answered:?}"
            );
            assert_eq!(
                head_file(&fx, addr, "a2").await,
                Some(b"unsynced on A".to_vec())
            );
        }
        let landed = granary_core::root::decode_root(&after_a).unwrap();
        assert_eq!(
            (landed.parent, landed.writer_uuid, after_a != r2),
            (Some(GrainId::of(&r2)), w, true),
            "unsafe sibling landing premise"
        );
        assert_eq!(sent.last(), Some(&after_a), "A really lands its candidate");
        assert_eq!(
            sent.len(),
            1,
            "one candidate lands without a duplicate send"
        );
    }
    assert_eq!(
        head_file(&fx, addr, "a").await,
        Some(b"from A".to_vec()),
        "the same-name value must remain in head after A lands or refuses"
    );
    assert_eq!(selected_root(&fx, addr, w).await, Some(p_b.root.clone()));
    drop(lane);
    b.crash().await;
    std::fs::remove_dir_all(&path_b).unwrap();
    a.crash().await;
    let remote = Arc::new(Cut::new(fx.client(addr, 0)));
    let result = command(
        &fx,
        addr,
        remote.clone(),
        fx.dir.join("store-a"),
        w,
        Some(w),
    )
    .await;
    let expected = if conflicting {
        "IntentSelectionChanged"
    } else {
        "intent refused: RecoveryJournalBlocked"
    };
    assert_eq!(
        (
            result,
            selected_root(&fx, addr, w).await,
            head(&fx, addr).await == after_a,
            remote.publication_sends.lock().unwrap().len()
        ),
        (Err(expected.into()), Some(p_b.root.clone()), true, 0),
        "A must refuse without replacing, refreshing or releasing B's exact selection"
    );
    assert!(
        !remote
            .recovery_sends
            .lock()
            .unwrap()
            .iter()
            .any(
                |bytes| intent::decode_register(bytes, &fx.volume(), |_, _| true).is_ok()
                    || intent::decode_release(bytes).is_ok()
            ),
        "no refresh or release"
    );
    if !synced || landed_first || (unsynced && !conflicting) {
        // With B's disk gone, a separate fresh store recovers the selected
        // root through its own parent and publishes B's disjoint addition.
        let fresh = Arc::new(Cut::new(fx.client(addr, 0)));
        let recovered = command(&fx, addr, fresh.clone(), fx.dir.join("store-c"), w, Some(w)).await;
        assert_eq!(
            (
                recovered,
                head_file(&fx, addr, "b").await,
                live_rows(&fx, addr).await,
                fresh.publication_sends.lock().unwrap().len()
            ),
            (Ok(()), Some(b"acknowledged on B".to_vec()), 0, 1),
            "fresh-store recovery must publish the selected bytes before release"
        );
        assert_eq!(head_file(&fx, addr, "a").await, Some(b"from A".to_vec()));
        if unsynced {
            assert_eq!(
                head_file(&fx, addr, "a2").await,
                Some(b"unsynced on A".to_vec())
            );
        }
    }
    server.stop().await;
}

/// A displaced journal with no boundary must not replace another store's sync.
#[expect(
    clippy::too_many_lines,
    reason = "one displacement schedule keeps exact selection and send checks across both retries"
)]
async fn fenced_journal_selection(unsynced: bool, same_name: bool, clean: bool) {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let addr = server.addr;
    let (a, _, content) = writer_at(&fx, addr, "store-a").await;
    let w = recorded(&a).writer;
    if unsynced {
        a.create(if same_name { "b" } else { "a2" }, b"unsynced on A");
    }
    let path_b = fx.dir.join("store-b");
    assert_eq!(
        command(
            &fx,
            addr,
            Arc::new(Cut::new(fx.client(addr, 0))),
            path_b.clone(),
            w,
            Some(w)
        )
        .await,
        Ok(())
    );
    let base = head(&fx, addr).await;
    let b = Box::pin(reopen(
        &fx,
        addr,
        &path_b,
        &content,
        &base,
        true,
        &mut SeededSecureRandom::from_key([35; 32]),
    ))
    .await;
    let stage = b.create("b", b"acknowledged on B");
    acknowledged(&b, &[stage]).await;
    let p_b = recorded(&b);
    assert_eq!(
        (
            selected_root(&fx, addr, w).await,
            head(&fx, addr).await == base
        ),
        (Some(p_b.root.clone()), true),
        "premise: B's acknowledged unpublished selection"
    );
    if clean {
        // Learn the displacement without adding any namespace record.
        let result = a
            .engine
            .sync(SyncTarget::Directory(None), SyncOptions::default())
            .wait()
            .await;
        assert!(
            matches!(result, Err(CoordinationError::Fenced { .. })),
            "{result:?}"
        );
    } else {
        let stage = a.create("a3", b"late on A");
        for target in [SyncTarget::Stage(stage), SyncTarget::Directory(None)] {
            let result = a.engine.sync(target, SyncOptions::default()).wait().await;
            assert!(
                matches!(result, Err(CoordinationError::Fenced { .. })),
                "displaced sync: {result:?}"
            );
        }
    }
    assert_eq!(a.local.lock().unwrap().snapshot().phase, Phase::Fenced);
    b.crash().await;
    std::fs::remove_dir_all(&path_b).unwrap();
    a.crash().await;
    let mut cases = 0;
    for acknowledgement in [Some(w), None] {
        let remote = Arc::new(Cut::new(fx.client(addr, 0)));
        let result = command(
            &fx,
            addr,
            remote.clone(),
            fx.dir.join("store-a"),
            w,
            acknowledgement,
        )
        .await;
        let root = head(&fx, addr).await;
        let selected = selected_root(&fx, addr, w).await;
        let b_file = head_file(&fx, addr, "b").await;
        let sends = remote.recovery_sends.lock().unwrap();
        let registers = sends
            .iter()
            .filter(|bytes| intent::decode_register(bytes, &fx.volume(), |_, _| true).is_ok())
            .count();
        let releases = sends
            .iter()
            .filter(|bytes| intent::decode_release(bytes).is_ok())
            .count();
        if clean {
            assert_eq!(
                (result, selected, b_file, releases),
                (
                    Ok(()),
                    None,
                    Some(b"acknowledged on B".to_vec()),
                    usize::from(cases == 0)
                ),
                "clean selected root is published before release"
            );
        } else {
            assert_eq!(
                (
                    result,
                    selected,
                    root == base,
                    b_file,
                    remote.publication_sends.lock().unwrap().len(),
                    registers,
                    releases
                ),
                (
                    Err("intent refused: RecoveryJournalBlocked".into()),
                    Some(p_b.root.clone()),
                    true,
                    None,
                    0,
                    0,
                    0
                ),
                "dirty selection attempt {cases}"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
    server.stop().await;
}

#[tokio::test]
async fn secseat_fenced_dirty_journal_unsynced_only() {
    fenced_journal_selection(true, false, false).await;
}

#[tokio::test]
async fn secseat_fenced_dirty_journal_none_before() {
    fenced_journal_selection(false, false, false).await;
}

#[tokio::test]
async fn fenced_dirty_journal_same_name_preserves_the_selection() {
    fenced_journal_selection(true, true, false).await;
}

#[tokio::test]
async fn fenced_clean_journal_publishes_the_selection_before_release() {
    fenced_journal_selection(false, false, true).await;
}
