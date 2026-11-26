// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Explicit recovery of a lost store's registered root through the bounded
//! recovery journal: it is merged against its own parent onto a newer head.

use super::*;
use crate::PublicationJournal as _;
use granary_core::manifest::{DirEntry, EntryKind, GrainRef, Name};

fn signer() -> SigningKey {
    SigningKey::from_seed(&[39; 32]).unwrap()
}

/// A one-file tree prepared over the remote's head and uploaded, signed as
/// `writer`, and not published.
pub(super) async fn one_file(
    remote: &Remote,
    name: &[u8],
    body: &[u8],
    writer: [u8; 16],
) -> Vec<u8> {
    files(remote, &[(name, body)], writer).await
}

/// Prepare and upload a flat tree over the remote's head.
pub(super) async fn files(remote: &Remote, files: &[(&[u8], &[u8])], writer: [u8; 16]) -> Vec<u8> {
    let content = Content::default();
    let mut entries: Vec<_> = files
        .iter()
        .map(|&(name, body)| file_entry(&content, name, body))
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let leaf = manifest::encode_dir_leaf(&entries).unwrap();
    let tree = GrainId::of(&leaf);
    content.objects.lock().unwrap().insert(tree, leaf);
    prepare_tree(remote, &content, tree, writer).await
}

fn file_entry(content: &Content, name: &[u8], body: &[u8]) -> DirEntry {
    let grain = GrainId::of(body);
    content.objects.lock().unwrap().insert(grain, body.to_vec());
    DirEntry {
        name: Name::new(name.to_vec()).unwrap(),
        kind: EntryKind::File {
            exec: false,
            size: body.len() as u64,
            grains: FileGrains::Inline(vec![GrainRef {
                id: grain,
                unpacked_len: u32::try_from(body.len()).unwrap(),
            }]),
        },
    }
}

async fn prepare_tree(
    remote: &Remote,
    content: &Content,
    tree: GrainId,
    writer: [u8; 16],
) -> Vec<u8> {
    let head = remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    let head = granary_core::root::decode_root(&head).unwrap();
    let prepared = crate::prepare_from_manifest(
        remote,
        content,
        tree,
        crate::HarvestStats::default(),
        &head.volume,
        &signer(),
        &granary_core::identity::WriterIdentity::from_bytes(writer),
        head.timestamp,
        crate::Policy { min_prefix_bits: 0 },
    )
    .await
    .unwrap();
    let mut doc = granary_core::root::decode_root(&prepared.root_bytes).unwrap();
    doc.writer_uuid = writer;
    doc.sigs.clear();
    let prefix = granary_core::root::signing_prefix_of(&doc).unwrap();
    doc.sigs.push(RootSig {
        key_id: signer().key_id(),
        sig: signer().sign(&prefix),
    });
    granary_core::root::encode_root(&doc).unwrap()
}

/// The JSON lines this thread's events render to while its guard is held.
#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Events {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Events {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
impl Events {
    pub(super) fn guard(&self) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(crate::subscriber(
            crate::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            self.clone(),
        ))
    }
    /// Each `recover.*` event's name with its numeric and label fields.
    pub(super) fn recover(&self) -> Vec<String> {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .filter_map(|line| {
                let name = line
                    .split("\"event\":\"recover.")
                    .nth(1)?
                    .split('"')
                    .next()?;
                Some(
                    [
                        "relation",
                        "seq",
                        "chain_len",
                        "path",
                        "token",
                        "how",
                        "base_seq",
                        "reason",
                    ]
                    .into_iter()
                    .filter_map(|field| {
                        let value = line.split(&format!("\"{field}\":")).nth(1)?;
                        let value = value.split([',', '}']).next()?.trim_matches('"');
                        Some(format!("{field}={value}"))
                    })
                    .fold(name.to_owned(), |out, field| out + " " + &field),
                )
            })
            .collect()
    }
}

/// The writer of the lost store whose row the fixtures register.
pub(super) const WRITER: [u8; 16] = [31; 16];

/// A fresh store that took over `WRITER`'s row registering `prepared`, still
/// in its handshake, with the takeover it awaits and the authority.
fn selected(
    prepared: &[u8],
) -> (
    Scratch,
    SimIo,
    WritableStore<SimIo>,
    PendingIntent,
    Authority,
) {
    let (scratch, selection, authority) = selection(prepared);
    let io = SimIo::default();
    let mut client = WritableStore::adopt_selected(
        Store::open(&scratch.0).unwrap(),
        settings(&scratch),
        io.clone(),
        &mut Entropy(30),
        crate::FaultControl::default(),
        selection.acknowledge_takeover(WRITER).unwrap(),
    )
    .unwrap();
    let request = client.begin_selected_attempt(&Tick(10)).unwrap();
    (scratch, io, client, request, authority)
}

/// `WRITER`'s row registering `prepared`, selected from a readback for a
/// fresh store, and the authority holding it.
pub(super) fn selection(prepared: &[u8]) -> (Scratch, crate::SelectedRecovery, Authority) {
    let (_s, _io, _old, mut authority) = serving();
    let writer = WRITER;
    authority.row = Some(Receipt {
        writer,
        state: ReceiptState::Live {
            prepared_root_id: GrainId::of(prepared),
        },
        ..authority.row.unwrap()
    });
    authority.root = prepared.to_vec();
    let scratch = Scratch::new();
    let row = authority.row.unwrap();
    let readback = intent::encode_readback(
        authority.cursor,
        &[intent::ReadbackRow {
            writer,
            epoch: row.epoch,
            generation: row.generation,
            root: prepared,
        }],
    )
    .unwrap();
    let settings = settings(&scratch);
    let selection = crate::SelectedRecovery::from_readback(
        settings.scope.clone(),
        settings.volume.clone(),
        writer,
        &reply(200, None, Some(intent::MEDIA_READBACK), readback),
        |_, _| true,
    )
    .unwrap();
    (scratch, selection, authority)
}

fn settings(scratch: &Scratch) -> OverlayConfig {
    let mut settings = config(&scratch.0);
    settings.cap = 134_217_728;
    settings.ownership_completion_reserve = REPLACEMENT_RESERVE;
    settings
}

/// A fresh store that took over `WRITER`'s row registering `prepared`,
/// granted, with the authority that granted it.
fn granted(prepared: &[u8]) -> (Scratch, SimIo, WritableStore<SimIo>, Authority) {
    let (scratch, io, mut client, request, mut authority) = selected(prepared);
    client.dispatch(&request, &Tick(10)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    (scratch, io, client, authority)
}

/// The names in a landed one-leaf manifest.
pub(super) async fn landed_names(remote: &Remote, root: &[u8]) -> Vec<Vec<u8>> {
    let doc = granary_core::root::decode_root(root).unwrap();
    let (_, objects) = crate::resolve_at_collecting(remote, "v", doc.seq)
        .await
        .unwrap();
    let (_, cursor) = granary_core::encoding::open_envelope(&objects[&doc.manifest_root]).unwrap();
    manifest::decode_dir_leaf(cursor)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name.as_bytes().to_vec())
        .collect()
}

async fn recover(
    fx: &Fixture,
    client: &mut WritableStore<SimIo>,
    writer: [u8; 16],
    prepared: Vec<u8>,
) -> crate::SelectedPublication {
    try_recover(fx, client, writer, prepared).await.unwrap()
}

async fn try_recover(
    fx: &Fixture,
    client: &mut WritableStore<SimIo>,
    writer: [u8; 16],
    prepared: Vec<u8>,
) -> Result<crate::SelectedPublication, crate::RecoveryError> {
    let trusted = TrustedKeys::new([*signer().public_key()]).unwrap();
    let scope = client.snapshot().scope.clone();
    let volume = client.snapshot().volume.clone();
    let mut journal = crate::RecoveryJournal::new(client, &*fx.remote, &trusted);
    crate::begin_selected_publication(
        crate::RecoveryParts {
            transport: &*fx.remote,
            journal: &mut journal,
            publisher_keys: &trusted,
            signer: &signer(),
            secure: &mut Entropy(90),
            clock: fx.remote.time.as_ref(),
            delay: &mut Delay,
        },
        scope,
        volume,
        writer,
        prepared,
    )
    .await
}

#[tokio::test]
async fn recovery_journal_observes_configured_workspace() {
    for bound in [1, 64] {
        let fx = Fixture::new().await;
        let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
        let foreign = one_file(&fx.remote, b"b", b"foreign b", [77; 16]).await;
        fx.remote.published.lock().unwrap().insert(2, foreign);
        let (_scratch, _io, mut client, _authority) = granted(&prepared);
        client.construction_workspace_bytes = bound;
        let result = try_recover(&fx, &mut client, WRITER, prepared).await;
        let diagnostic = match &result {
            Err(error) => Some(error.to_string()),
            Ok(crate::SelectedPublication::Driven(result)) => result.diagnostic.clone(),
            _ => None,
        };
        assert_eq!(
            (
                diagnostic
                    .as_ref()
                    .is_some_and(|e| e.contains("SyncWorkspaceExhausted")),
                matches!(&result, Ok(crate::SelectedPublication::Driven(r)) if matches!(r.outcome, PublicationOutcome::Landed(_)))
            ),
            (bound == 1, bound != 1),
            "bound={bound}: {result:?}"
        );
    }
}

#[tokio::test]
async fn recovery_empty_authority_refuses_a_parented_prepared_root_as_integrity() {
    for empty in [false, true] {
        let fx = Fixture::new().await;
        let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
        let (_scratch, _io, mut client, _authority) = granted(&prepared);
        if empty {
            fx.remote.published.lock().unwrap().clear();
        }
        let result = try_recover(&fx, &mut client, WRITER, prepared).await;
        assert_eq!(
            (
                matches!(
                    &result,
                    Err(crate::RecoveryError::RemoteIntegrity(
                        "empty authority for parented prepared root"
                    ))
                ),
                fx.remote.publication_sends.lock().unwrap().len(),
            ),
            (empty, usize::from(!empty)),
            "empty={empty}: {result:?}"
        );
    }
}

#[tokio::test]
async fn recovery_load_requires_the_current_instances_grant() {
    let fx = Fixture::new().await;
    let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
    let (scratch, io, mut client, request, mut authority) = selected(&prepared);
    let trusted = TrustedKeys::new([*signer().public_key()]).unwrap();
    let scope = client.snapshot().scope.clone();
    let volume = client.snapshot().volume.clone();
    let before = crate::RecoveryJournal::new(&mut client, &*fx.remote, &trusted)
        .load(&scope, &volume)
        .map_err(|error| error.to_string());
    client.dispatch(&request, &Tick(10)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let after = crate::RecoveryJournal::new(&mut client, &*fx.remote, &trusted)
        .load(&scope, &volume)
        .map_err(|error| error.to_string());
    assert_eq!(
        (
            before
                .as_ref()
                .is_err_and(|error| error.contains("IntentOwnershipPending")),
            after
        ),
        (true, Ok(None)),
        "load before grant: {before:?}"
    );
    try_recover(&fx, &mut client, WRITER, prepared)
        .await
        .unwrap();
    let before = retained(&mut client).unwrap();
    drop(client);
    io.crash();
    let mut rerun = start(&scratch, &io, 41);
    let load = crate::RecoveryJournal::new(&mut rerun, &*fx.remote, &trusted)
        .load(&scope, &volume)
        .map_err(|error| error.to_string());
    assert_eq!(
        (
            load.as_ref()
                .is_err_and(|error| error.contains("IntentFreshInstanceRequired")),
            retained(&mut rerun).unwrap() == before
        ),
        (true, true),
        "the re-run must refuse before changing the retained generation: {load:?}"
    );
}

#[tokio::test]
async fn recovery_corrupt_remote_during_rebase_refuses_instead_of_unresolved() {
    let mut merge_faults = 0;
    let mut journal_faults = 0;
    for failing in 0..=12 {
        let fx = Fixture::new().await;
        let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
        let foreign = one_file(&fx.remote, b"b", b"foreign b", [77; 16]).await;
        fx.remote.published.lock().unwrap().insert(2, foreign);
        let (_scratch, _io, mut client, _authority) = granted(&prepared);
        if failing != 0 {
            fx.remote.corrupt_probe.store(
                fx.remote.probes.load(Ordering::Relaxed) + failing,
                Ordering::Relaxed,
            );
        }
        let result = try_recover(&fx, &mut client, WRITER, prepared).await;
        if failing == 0 {
            assert!(
                matches!(&result, Ok(crate::SelectedPublication::Driven(result)) if matches!(result.outcome, PublicationOutcome::Landed(_))),
                "healthy control: {result:?}"
            );
        } else if retained(&mut client).is_some_and(|record| !record.is_complete()) {
            merge_faults += 1;
            journal_faults += usize::from(matches!(
                &result,
                Err(crate::RecoveryError::RemoteIntegrity("recovery merge"))
            ));
            assert_eq!(
                (
                    matches!(&result, Err(crate::RecoveryError::RemoteIntegrity(_))),
                    fx.remote.publication_sends.lock().unwrap().len()
                ),
                (true, 0),
                "corrupt probe {failing} after retained begin: {result:?}"
            );
        }
    }
    assert!(
        merge_faults > journal_faults && journal_faults > 0,
        "both direct and journal-mapped integrity failures must reach the retained rebase: (all, journal-mapped) = ({merge_faults}, {journal_faults})"
    );
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "test plants a corrupt regular CAS leaf to prove recovery's operator-actionable refusal"
)]
async fn recovery_corrupt_local_leaf_refuses_with_an_operator_remedy() {
    for (corrupt, rebased) in [(false, false), (true, false), (false, true), (true, true)] {
        let fx = Fixture::new().await;
        let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
        if rebased {
            let foreign = one_file(&fx.remote, b"b", b"foreign b", [77; 16]).await;
            fx.remote.published.lock().unwrap().insert(2, foreign);
        }
        let (scratch, _io, mut client, _authority) = granted(&prepared);
        if corrupt {
            let id = granary_core::root::decode_root(&prepared)
                .unwrap()
                .manifest_root;
            let hex = id.digest_hex();
            let fanout = scratch.0.join("objects").join(&hex[..2]);
            std::fs::create_dir_all(&fanout).unwrap();
            std::fs::write(fanout.join(hex), b"corrupt local leaf").unwrap();
        }
        let result = try_recover(&fx, &mut client, WRITER, prepared).await;
        assert_eq!(
            (
                result.as_ref().err().is_some_and(|error| error
                    .to_string()
                    .contains("RecoveryLocalObjectCorrupt")
                    && error.to_string().contains("quarantine")),
                fx.remote.publication_sends.lock().unwrap().len()
            ),
            (corrupt, usize::from(!corrupt)),
            "corrupt={corrupt}, rebased={rebased}: {result:?}"
        );
    }
}

#[test]
fn recovery_command_changed_selection_stops_with_one_read_and_send() {
    for token in [
        None,
        Some("intent-changed"),
        Some("intent-superseded"),
        Some("intent-absent"),
    ] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let fx = runtime.block_on(Fixture::new());
        let prepared = runtime.block_on(one_file(&fx.remote, b"a", b"recovered a", WRITER));
        let (scratch, _selection, authority) = selection(&prepared);
        *fx.remote.authority.lock().unwrap() = authority;
        fx.remote
            .change_selection
            .store(token == Some("intent-changed"), Ordering::Relaxed);
        fx.remote
            .supersede_selection
            .store(token == Some("intent-superseded"), Ordering::Relaxed);
        fx.remote
            .forget_selection
            .store(token == Some("intent-absent"), Ordering::Relaxed);
        let events = Events::default();
        let _events = events.guard();
        let result = command_on(&scratch, &fx.remote, &runtime, WRITER, Some(WRITER));
        assert_eq!(
            (
                result,
                fx.remote.recovery_reads.load(Ordering::Relaxed),
                fx.remote.recovery_sends.load(Ordering::Relaxed),
                fx.remote.publication_sends.lock().unwrap().len()
            ),
            if token.is_some() {
                (Err("IntentSelectionChanged".into()), 1, 1, 0)
            } else {
                (Ok(()), 1, 2, 1)
            },
            "token={token:?}: {:?}",
            events.recover()
        );
        if let Some(token) = token {
            assert!(
                events
                    .recover()
                    .iter()
                    .any(|event| event == &format!("selection_changed token={token}")),
                "{:?}",
                events.recover()
            );
        }
    }
}

#[test]
fn intact_recovery_superseded_succession_requires_renewed_consent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fx = runtime.block_on(Fixture::new());
    let prepared = runtime.block_on(one_file(&fx.remote, b"a", b"recovered a", WRITER));
    let (scratch, io, local, mut authority) = granted(&prepared);
    let original = authority.row.unwrap();
    authority.cursor += 1;
    authority.row = Some(Receipt {
        epoch: authority.cursor,
        instance: [99; 16],
        ..original
    });
    let first_send = authority.sends.len();
    *fx.remote.authority.lock().unwrap() = authority;
    drop(local);

    let events = Events::default();
    let _events = events.guard();
    let run = |ack| command_on_with_io(&scratch, &fx.remote, &runtime, WRITER, ack, io.clone());
    let result = run(None);
    {
        let authority = fx.remote.authority.lock().unwrap();
        let sent = &authority.sends[first_send..];
        assert_eq!(
            (
                result.as_ref().err().map(String::as_str),
                events.recover(),
                fx.remote.recovery_reads.load(Ordering::Relaxed),
                sent.len(),
                sent.first()
                    .map(|body| intent::decode_ownership(body).unwrap().mode),
                fx.remote.publication_sends.lock().unwrap().len(),
            ),
            (
                Some("IntentSelectionChanged"),
                vec!["selection_changed token=intent-superseded".to_owned()],
                0,
                1,
                Some(OwnershipMode::Takeover {
                    expected_epoch: original.epoch,
                    generation: original.generation,
                    state: original.state,
                    recovery_ack: false,
                }),
                0,
            )
        );
    }

    io.crash();
    assert_eq!(
        run(None),
        Err("intent refused: IntentSelectedWriterMissing".into())
    );
    assert_eq!(fx.remote.recovery_reads.load(Ordering::Relaxed), 0);
    assert_eq!(fx.remote.publication_sends.lock().unwrap().len(), 0);
    let fresh = {
        let mut authority = fx.remote.authority.lock().unwrap();
        assert_eq!(authority.sends.len(), first_send + 1);
        // Move beyond the fence receipt so only a fresh readback can select this epoch.
        authority.cursor += 1;
        let fresh = Receipt {
            epoch: authority.cursor,
            instance: [100; 16],
            ..authority.row.unwrap()
        };
        authority.row = Some(fresh);
        fresh
    };

    assert_eq!(run(Some(WRITER)), Ok(()));
    assert_eq!(fx.remote.recovery_reads.load(Ordering::Relaxed), 1);
    let authority = fx.remote.authority.lock().unwrap();
    let [takeover, release] = &authority.sends[first_send + 1..] else {
        panic!("renewed consent must send one takeover and one release");
    };
    assert_eq!(
        intent::decode_ownership(takeover).unwrap().mode,
        OwnershipMode::Takeover {
            expected_epoch: fresh.epoch,
            generation: fresh.generation,
            state: fresh.state,
            recovery_ack: true,
        }
    );
    assert_eq!(
        intent::decode_release(release).unwrap().generation,
        fresh.generation
    );
    assert_eq!(fx.remote.publication_sends.lock().unwrap().len(), 1);
}

#[test]
fn recovery_command_names_a_readback_transport_failure_apart_from_a_refused_body() {
    let mut outcomes = Vec::new();
    for failure in [
        crate::IntentTransportError::Transport,
        crate::IntentTransportError::Deadline,
        crate::IntentTransportError::Backend,
        crate::IntentTransportError::InvalidRequest,
    ] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let fx = runtime.block_on(Fixture::new());
        let prepared = runtime.block_on(one_file(&fx.remote, b"a", b"recovered a", WRITER));
        let (scratch, _selection, authority) = selection(&prepared);
        *fx.remote.authority.lock().unwrap() = authority;
        *fx.remote.readback_failure.lock().unwrap() = Some(failure);
        let result = command_on(&scratch, &fx.remote, &runtime, WRITER, Some(WRITER));
        outcomes.push((
            failure,
            result.err(),
            fx.remote.recovery_sends.load(Ordering::Relaxed),
        ));
    }
    let unavailable = Some("WritableIntentUnavailable".to_owned());
    let invalid = Some("WritableIntentDiscoveryInvalid".to_owned());
    assert_eq!(
        outcomes,
        [
            (
                crate::IntentTransportError::Transport,
                unavailable.clone(),
                0
            ),
            (crate::IntentTransportError::Deadline, unavailable, 0),
            (crate::IntentTransportError::Backend, invalid.clone(), 0),
            (crate::IntentTransportError::InvalidRequest, invalid, 0),
        ],
        "(readback failure, refusal, takeover sends)"
    );
}

#[test]
fn recovery_command_without_a_store_reports_the_selection_whatever_is_acknowledged() {
    for acknowledge_takeover in [None, Some([9; 16]), Some(WRITER)] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let fx = runtime.block_on(Fixture::new());
        let prepared = runtime.block_on(one_file(&fx.remote, b"a", b"recovered a", WRITER));
        let (scratch, _selection, authority) = selection(&prepared);
        *fx.remote.authority.lock().unwrap() = authority;
        let trusted = TrustedKeys::new([*signer().public_key()]).unwrap();
        let result = crate::RecoveryCommand {
            construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
            acknowledge_resend: None,
            faults: crate::FaultControl::default(),
            local: None::<(Store, SimIo)>,
            config: settings(&scratch),
            transport: fx.remote.as_ref(),
            runtime: &runtime,
            signer: &signer(),
            publisher_keys: &trusted,
            writer: WRITER,
            acknowledge_takeover,
        }
        .run(
            &fx.remote.time,
            signer(),
            &mut Entropy(90),
            SeededRng::new(2),
        )
        .map_err(|error| error.to_string());
        assert_eq!(
            (
                result.as_ref().err().map(|error| error.starts_with(
                    "IntentSelectionBinding: --acknowledge-takeover must name --writer; selected E="
                )),
                fx.remote.recovery_reads.load(Ordering::Relaxed),
                fx.remote.recovery_sends.load(Ordering::Relaxed),
            ),
            (Some(true), 1, 0),
            "acknowledge={acknowledge_takeover:?}: {result:?}"
        );
    }
}

/// Run the command on a fresh store, through the same authority and content
/// transport as the writer that lost its disk.
pub(super) fn command_on(
    scratch: &Scratch,
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    writer: [u8; 16],
    acknowledge_takeover: Option<[u8; 16]>,
) -> Result<(), String> {
    command_on_with_io(
        scratch,
        remote,
        runtime,
        writer,
        acknowledge_takeover,
        SimIo::default(),
    )
}

fn command_on_with_io(
    scratch: &Scratch,
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    writer: [u8; 16],
    acknowledge_takeover: Option<[u8; 16]>,
    io: SimIo,
) -> Result<(), String> {
    let trusted = TrustedKeys::new([*signer().public_key()]).unwrap();
    crate::RecoveryCommand {
        construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
        acknowledge_resend: None,
        faults: crate::FaultControl::default(),
        local: Some((Store::open(&scratch.0).unwrap(), io)),
        config: settings(scratch),
        transport: remote,
        runtime,
        signer: &signer(),
        publisher_keys: &trusted,
        writer,
        acknowledge_takeover,
    }
    .run(&remote.time, signer(), &mut Entropy(90), SeededRng::new(2))
    .map(|_| ())
    .map_err(|error| error.to_string())
}

#[test]
fn recovery_command_resumes_the_retained_rebase_after_succession() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cut = None;
    let mut outcomes = Vec::new();
    for failing in 1..=12 {
        let fx = runtime.block_on(Fixture::new());
        let prepared = runtime.block_on(one_file(&fx.remote, b"a", b"recovered a", WRITER));
        let foreign = runtime.block_on(one_file(&fx.remote, b"b", b"foreign b", [77; 16]));
        fx.remote.published.lock().unwrap().insert(2, foreign);
        let (scratch, io, mut client, authority) = granted(&prepared);
        let probes = fx.remote.probes.load(Ordering::Relaxed);
        fx.remote
            .failed_probe
            .store(probes + failing, Ordering::Relaxed);
        let result = runtime.block_on(try_recover(&fx, &mut client, WRITER, prepared));
        fx.remote.failed_probe.store(0, Ordering::Relaxed);
        let begun = retained(&mut client).is_some_and(|record| !record.is_complete());
        let sends = fx.remote.publication_sends.lock().unwrap().len();
        outcomes.push(format!(
            "probe={failing}: begun={begun}, sends={sends}, {result:?}"
        ));
        if begun && sends == 0 {
            cut = Some((fx, scratch, io, client, authority));
            break;
        }
    }
    let Some((fx, scratch, io, client, authority)) = cut else {
        panic!("no retained rebase before dispatch: {outcomes:?}");
    };
    drop(client);
    io.crash();
    *fx.remote.authority.lock().unwrap() = authority;
    let trusted = TrustedKeys::new([*signer().public_key()]).unwrap();
    let result = crate::RecoveryCommand {
        construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
        acknowledge_resend: None,
        faults: crate::FaultControl::default(),
        local: Some((Store::open(&scratch.0).unwrap(), io)),
        config: settings(&scratch),
        transport: fx.remote.as_ref(),
        runtime: &runtime,
        signer: &signer(),
        publisher_keys: &trusted,
        writer: WRITER,
        acknowledge_takeover: None,
    }
    .run(
        &fx.remote.time,
        signer(),
        &mut Entropy(90),
        SeededRng::new(2),
    )
    .map(|_| ())
    .map_err(|error| error.to_string());
    let root = fx.remote.published.lock().unwrap().get(&3).cloned();
    let names = root
        .as_ref()
        .map(|root| runtime.block_on(landed_names(&fx.remote, root)));
    assert_eq!(
        (
            result,
            fx.remote.recovery_reads.load(Ordering::Relaxed),
            fx.remote.recovery_sends.load(Ordering::Relaxed),
            fx.remote.publication_sends.lock().unwrap().len(),
            names
        ),
        (Ok(()), 0, 2, 1, Some(vec![b"a".to_vec(), b"b".to_vec()])),
        "rule 3a must resume only after its own succession and release after landing"
    );
}

#[test]
fn recovery_command_restarts_an_adoption_before_or_after_its_attempt_begins() {
    for started in [false, true] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let fx = runtime.block_on(Fixture::new());
        let prepared = runtime.block_on(one_file(&fx.remote, b"a", b"recovered a", WRITER));
        let (scratch, selection, authority) = selection(&prepared);
        let io = SimIo::default();
        let mut local = WritableStore::adopt_selected(
            Store::open(&scratch.0).unwrap(),
            settings(&scratch),
            io.clone(),
            &mut Entropy(30),
            crate::FaultControl::default(),
            selection.acknowledge_takeover(WRITER).unwrap(),
        )
        .unwrap();
        if started {
            local.begin_selected_attempt(&Tick(10)).unwrap();
        }
        let body = local.snapshot().pending[0].body.clone();
        drop(local);
        io.crash();
        *fx.remote.authority.lock().unwrap() = authority;
        let before = fx.remote.authority.lock().unwrap().sends.len();
        let trusted = TrustedKeys::new([*signer().public_key()]).unwrap();
        let result = crate::RecoveryCommand {
            construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
            acknowledge_resend: None,
            faults: crate::FaultControl::default(),
            local: Some((Store::open(&scratch.0).unwrap(), io)),
            config: settings(&scratch),
            transport: fx.remote.as_ref(),
            runtime: &runtime,
            signer: &signer(),
            publisher_keys: &trusted,
            writer: WRITER,
            acknowledge_takeover: None,
        }
        .run(
            &fx.remote.time,
            signer(),
            &mut Entropy(90),
            SeededRng::new(2),
        )
        .map(|_| ())
        .map_err(|error| error.to_string());
        let authority = fx.remote.authority.lock().unwrap();
        assert_eq!(
            (
                result,
                fx.remote.recovery_reads.load(Ordering::Relaxed),
                authority.sends.len() - before,
                authority.sends.get(before) == Some(&body),
                fx.remote.publication_sends.lock().unwrap().len()
            ),
            (Ok(()), 0, 3, true, 1),
            "started={started}: retained adoption, succession, publication and release must use the persisted selection"
        );
    }
}

#[test]
fn adoption_settles_ownership_from_failed_install_before_refusing() {
    let prepared = root(WRITER, 7);
    let (scratch, selection, _) = selection(&prepared);
    let io = SimIo::default();
    let faults = FaultControl::default();
    faults.arm("intent.pending", "dir_sync", 1, FaultAction::Fail);
    let adopt = |faults, selection: crate::SelectedRecovery| {
        WritableStore::adopt_selected(
            Store::open(&scratch.0).unwrap(),
            settings(&scratch),
            io.clone(),
            &mut Entropy(30),
            faults,
            selection.acknowledge_takeover(WRITER).unwrap(),
        )
    };
    let first = adopt(faults.clone(), selection.clone());
    assert_eq!(
        (
            first.is_err(),
            faults.fired().len(),
            io.recovered_bytes("ownership").is_none()
        ),
        (true, 1, true),
        "ownership install: {first:?}, faults {:?}",
        faults.fired()
    );
    let second = adopt(FaultControl::default(), selection);
    assert_eq!(
        (
            second.err().map(|error| error.to_string()).as_deref(),
            io.recovered_bytes("ownership").is_some()
        ),
        (Some("intent refused: IntentAdoptionBesideEvidence"), true),
        "adoption must settle the evidence it refuses beside"
    );
}

#[tokio::test]
async fn selected_recovery_onto_its_unchanged_parent_publishes_exactly_then_releases() {
    let events = Events::default();
    let _events = events.guard();
    let fx = Fixture::new().await;
    let writer = WRITER;
    let prepared = one_file(&fx.remote, b"a", b"recovered a", writer).await;
    let (_scratch, mut io, mut client, _authority) = granted(&prepared);
    let generation = intent::decode_receipt(&client.snapshot().current)
        .unwrap()
        .generation;
    let crate::SelectedPublication::Driven(result) =
        recover(&fx, &mut client, writer, prepared.clone()).await
    else {
        panic!("an unchanged parent is an exact publication")
    };
    let PublicationOutcome::Landed(done) = result.outcome else {
        panic!("the exact root did not land: {result:?}")
    };
    let absent = client.recovery_rule().unwrap();
    // A journal beside the completed publication: clean, then holding work
    // (a staging file only a replay on its base removes).
    let area = client
        .recovery_store()
        .publication_root()
        .join("overlay")
        .join(client.snapshot().scope.digest().unwrap())
        .join("v");
    let mut h = header();
    h.writer = client.writer_uuid();
    io.create(&area.join("journal")).unwrap();
    io.write_at(&area.join("journal"), 0, &h.encode().unwrap())
        .unwrap();
    let clean = client.recovery_rule().unwrap();
    io.directory(&area.join("staging")).unwrap();
    io.create(&area.join("staging").join("1")).unwrap();
    let dirty = client.recovery_rule().unwrap();
    assert_eq!(
        (absent, clean, dirty),
        (
            crate::RecoveryRule::Release,
            crate::RecoveryRule::Release,
            crate::RecoveryRule::DirtyJournal,
        ),
        "(absent, clean, dirty journal): rule 3b releases only over an absent or clean one"
    );
    assert!(
        matches!(dirty.admitted(), Ok(crate::RecoveryRule::DirtyJournal)),
        "a dirty journal admits the shared finish before any release"
    );
    io.remove(&area.join("staging").join("1")).unwrap();
    let rule = client.recovery_rule().unwrap();
    let release = client
        .prepare_recovery_release(&Tick(20), crate::DEFAULT_RESOLUTION_BOUND)
        .unwrap();
    assert_eq!(
        (
            done.root == prepared,
            fx.remote.publication_sends.lock().unwrap().len(),
            rule,
            intent::decode_release(release.bytes()).unwrap().generation,
            events.recover(),
        ),
        (
            true,
            1,
            crate::RecoveryRule::Release,
            generation,
            vec!["landed seq=2".to_owned()],
        ),
        "(landed P exactly, sends, rule after landing, release generation, events)"
    );
}

#[tokio::test]
async fn selected_recovery_requires_content_proof_across_same_writer_siblings() {
    for equal in [false, true] {
        let fx = Fixture::new().await;
        let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
        let landed = if equal {
            prepared.clone()
        } else {
            one_file(&fx.remote, b"a", b"landed a", WRITER).await
        };
        fx.remote.published.lock().unwrap().insert(2, landed);
        let (_scratch, _io, mut client, _authority) = granted(&prepared);
        let result = try_recover(&fx, &mut client, WRITER, prepared.clone()).await;
        assert_eq!(
            (
                matches!(&result, Ok(crate::SelectedPublication::Subsumed { .. })),
                matches!(&result, Err(crate::RecoveryError::Journal(error)) if error.kind == crate::PublicationStoreErrorKind::Conflict),
                client.snapshot().root == prepared,
                fx.remote.publication_sends.lock().unwrap().len()
            ),
            (equal, !equal, true, 0),
            "equal={equal}: {result:?}"
        );
    }
}

#[tokio::test]
async fn selected_recovery_rebases_against_its_own_parent_onto_a_foreign_head() {
    let events = Events::default();
    let _events = events.guard();
    let fx = Fixture::new().await;
    let writer = WRITER;
    // P changes `a` over the published base; a foreign writer then lands `b`.
    let prepared = one_file(&fx.remote, b"a", b"recovered a", writer).await;
    let foreign = one_file(&fx.remote, b"b", b"foreign b", [77; 16]).await;
    fx.remote.published.lock().unwrap().insert(2, foreign);
    let (_scratch, _io, mut client, _authority) = granted(&prepared);
    let result = recover(&fx, &mut client, writer, prepared).await;
    let crate::SelectedPublication::Driven(result) = result else {
        panic!("a disjoint foreign head is a rebase: {result:?}")
    };
    let PublicationOutcome::Landed(done) = result.outcome else {
        panic!("the rebased candidate did not land: {result:?}")
    };
    let doc = granary_core::root::decode_root(&done.root).unwrap();
    let store = client.recovery_store();
    assert_eq!(
        (
            doc.seq,
            doc.writer_uuid,
            landed_names(&fx.remote, &done.root).await,
            store.has(&GrainId::of(b"recovered a")),
            store.has(&GrainId::of(b"foreign b")),
            events.recover(),
        ),
        (
            3,
            writer,
            vec![b"a".to_vec(), b"b".to_vec()],
            true,
            false,
            vec!["landed seq=3".to_owned(), "rebased chain_len=1".to_owned()],
        ),
        "(seq, writer, landed names, P's novel grain staged, head's grain fetched, events)"
    );
}

#[tokio::test]
async fn selected_recovery_reports_a_same_path_conflict_and_publishes_nothing() {
    let events = Events::default();
    let _events = events.guard();
    let fx = Fixture::new().await;
    // P and a foreign head both change `a` over P's parent.
    let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
    let foreign = one_file(&fx.remote, b"a", b"foreign a", [77; 16]).await;
    fx.remote.published.lock().unwrap().insert(2, foreign);
    let (_scratch, _io, mut client, _authority) = granted(&prepared);
    let result = try_recover(&fx, &mut client, WRITER, prepared).await;
    let landed = matches!(
        &result,
        Ok(crate::SelectedPublication::Driven(driven))
            if matches!(driven.outcome, PublicationOutcome::Landed(_))
    );
    assert_eq!(
        (
            landed,
            fx.remote.publication_sends.lock().unwrap().len(),
            events.recover(),
        ),
        (false, 0, vec!["conflict path=<file>".to_owned()]),
        "(landed, publication sends, events): {result:?}"
    );
}

#[test]
fn a_readback_without_the_selected_writer_selects_nothing() {
    let events = Events::default();
    let _events = events.guard();
    let scratch = Scratch::new();
    let settings = settings(&scratch);
    let readback = intent::encode_readback(1, &[]).unwrap();
    let selected = crate::SelectedRecovery::from_readback(
        settings.scope.clone(),
        settings.volume.clone(),
        WRITER,
        &reply(200, None, Some(intent::MEDIA_READBACK), readback),
        |_, _| true,
    );
    assert_eq!(
        (refusal(selected), events.recover()),
        (
            Some("IntentSelectedWriterMissing"),
            vec!["nothing".to_owned()]
        ),
        "(refusal, events): no row for the writer is A0"
    );
}

/// An acknowledgement naming another writer is refused, so no
/// acknowledged selection exists for an adoption to take.
#[test]
fn an_acknowledgement_naming_another_writer_adopts_nothing() {
    let (_scratch, selection, _authority) = selection(&root(WRITER, 7));
    assert_eq!(
        refusal(selection.acknowledge_takeover([32; 16])),
        Some("IntentSelectionBinding"),
        "another writer's acknowledgement acknowledges nothing"
    );
}

/// The takeover an adoption retains names the persisted selection limb by
/// limb, carries the consent recomputed over that selection, is not sent
/// before its attempt begins, and is the request the authority grants.
#[test]
fn adoption_retains_a_takeover_of_exactly_the_persisted_selection() {
    let (_scratch, _io, mut client, request, mut authority) = selected(&root(WRITER, 7));
    let carrier = client.snapshot().clone();
    let chosen = intent::decode_receipt(&carrier.selected).unwrap();
    let OwnershipMode::Takeover {
        expected_epoch,
        generation,
        state,
        recovery_ack,
    } = intent::decode_ownership(request.bytes()).unwrap().mode
    else {
        panic!("a selected recovery retains a takeover")
    };
    let row = authority
        .row
        .map(|row| (row.epoch, row.generation, row.state));
    let sends = authority.sends.len();
    client.dispatch(&request, &Tick(10)).unwrap();
    let answer = authority.send(&request);
    assert_eq!(
        (
            (expected_epoch, generation, state, recovery_ack),
            row,
            carrier.consent
                == granary_core::overlay_ownership::recovery_consent(&carrier, request.bytes())
                    .unwrap(),
            sends,
            (answer.status, answer.token),
        ),
        (
            (chosen.epoch, chosen.generation, chosen.state, true),
            Some((chosen.epoch, chosen.generation, chosen.state)),
            true,
            2,
            (200, None),
        ),
        "((sent E, G, state, ack), authority row, consent binds the selection, \
         sends before the attempt, answer)"
    );
}

/// Resume the retained recovery publication through a recovery journal, as
/// rule 3a does.
async fn resume(
    fx: &Fixture,
    client: &mut WritableStore<SimIo>,
) -> Result<crate::PublicationResult, crate::RecoveryError> {
    let trusted = TrustedKeys::new([*signer().public_key()]).unwrap();
    let handle = crate::PublicationHandle {
        scope: client.snapshot().scope.clone(),
        volume: client.snapshot().volume.clone(),
        publication_id: retained(client).unwrap().publication_id,
    };
    let mut journal = crate::RecoveryJournal::new(client, &*fx.remote, &trusted);
    crate::recovery::resume_store_publication(
        crate::RecoveryParts {
            transport: &*fx.remote,
            journal: &mut journal,
            publisher_keys: &trusted,
            signer: &signer(),
            secure: &mut Entropy(91),
            clock: fx.remote.time.as_ref(),
            delay: &mut Delay,
        },
        &handle,
        RecoveryIntent::ExplicitRecovery,
        WRITER,
    )
    .await
}

/// The retained record, read without writing.
pub(super) fn retained(
    client: &mut WritableStore<SimIo>,
) -> Option<granary_core::retained_submission::Submission> {
    let scope = client.snapshot().scope.clone();
    let volume = client.snapshot().volume.clone();
    client
        .publication_transaction(|store| store.observe(&scope, &volume))
        .unwrap()
}

/// Rule 3a: a rebased recovery cut after its record began and before any
/// send, by a failed root probe inside the merge. The re-run's fresh
/// instance is placed in rule 3a; its resume refuses at the first record
/// replacement before its own succession, sending nothing, and after the
/// succession it lands the merged candidate.
#[tokio::test]
async fn a_rebased_recovery_cut_before_its_first_send_resumes_after_the_reruns_succession() {
    let mut cut = None;
    for failing in 1..=12 {
        let fx = Fixture::new().await;
        let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
        let foreign = one_file(&fx.remote, b"b", b"foreign b", [77; 16]).await;
        fx.remote.published.lock().unwrap().insert(2, foreign);
        let (scratch, io, mut client, authority) = granted(&prepared);
        let probes = fx.remote.probes.load(Ordering::Relaxed);
        fx.remote
            .failed_probe
            .store(probes + failing, Ordering::Relaxed);
        let result = try_recover(&fx, &mut client, WRITER, prepared).await;
        fx.remote.failed_probe.store(0, Ordering::Relaxed);
        let begun = retained(&mut client).is_some_and(|record| !record.is_complete());
        let landed = matches!(
            &result,
            Ok(crate::SelectedPublication::Driven(driven))
                if matches!(driven.outcome, PublicationOutcome::Landed(_))
        );
        if !landed && begun && fx.remote.publication_sends.lock().unwrap().is_empty() {
            cut = Some((fx, scratch, io, client, authority));
            break;
        }
    }
    let (fx, scratch, io, client, mut authority) =
        cut.expect("a failed root probe stops the drive after the record began");
    drop(client);
    io.crash();
    let mut rerun = start(&scratch, &io, 41);
    let rule = rerun.recovery_rule().unwrap();
    let early = resume(&fx, &mut rerun)
        .await
        .map(|_| ())
        .map_err(|error| error.to_string());
    let sent_early = fx.remote.publication_sends.lock().unwrap().len();
    let transfer = rerun.prepare_succession(&Tick(31)).unwrap();
    rerun.dispatch(&transfer, &Tick(31)).unwrap();
    let answer = authority.send(&transfer);
    rerun
        .complete(
            &transfer,
            Ok(&answer),
            &Tick(32),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let result = resume(&fx, &mut rerun).await.unwrap();
    let PublicationOutcome::Landed(done) = result.outcome else {
        panic!("the resumed candidate did not land: {result:?}")
    };
    let doc = granary_core::root::decode_root(&done.root).unwrap();
    assert_eq!(
        (
            rule,
            early
                .as_ref()
                .is_err_and(|error| error.contains("IntentFreshInstanceRequired")),
            sent_early,
            (doc.seq, doc.writer_uuid),
            landed_names(&fx.remote, &done.root).await,
            rerun.recovery_rule().unwrap(),
        ),
        (
            crate::RecoveryRule::ResumeRecovery,
            true,
            0,
            (3, WRITER),
            vec![b"a".to_vec(), b"b".to_vec()],
            crate::RecoveryRule::Release,
        ),
        "(re-run rule, resume refused before succession: {early:?}, sends before it, \
         landed (seq, writer), landed names, rule after landing)"
    );
}

/// Rule 0 before rule 3b: a rebased recovery lands, and its release is
/// answered by a displacement, which fences the carrier beside the completed
/// record of the registered root. That run and its re-run report the lost
/// ownership and send no further release.
#[tokio::test]
async fn a_release_answered_by_a_displacement_is_reported_by_rule_zero_and_never_resent() {
    let events = Events::default();
    let _events = events.guard();
    let fx = Fixture::new().await;
    let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
    let foreign = one_file(&fx.remote, b"b", b"foreign b", [77; 16]).await;
    fx.remote.published.lock().unwrap().insert(2, foreign);
    let (scratch, io, mut client, mut authority) = granted(&prepared);
    let crate::SelectedPublication::Driven(_) = recover(&fx, &mut client, WRITER, prepared).await
    else {
        panic!("a disjoint foreign head is a rebase")
    };
    let before = client.recovery_rule().unwrap();
    let complete = retained(&mut client).is_some_and(|record| record.is_complete());
    let release = client
        .prepare_recovery_release(&Tick(20), crate::DEFAULT_RESOLUTION_BOUND)
        .unwrap();
    client.dispatch(&release, &Tick(20)).unwrap();
    authority.row = authority.row.map(|row| Receipt {
        epoch: row.epoch + 1,
        ..row
    });
    let answer = authority.send(&release);
    let displaced = client
        .complete(
            &release,
            Ok(&answer),
            &Tick(21),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .map(|_| ())
        .map_err(|error| error.to_string());
    let rule = client.recovery_rule().unwrap();
    let refused = refusal(rule.admitted());
    let sends = authority.sends.len();
    drop(client);
    io.crash();
    let mut rerun = start(&scratch, &io, 42);
    let rerun_rule = rerun.recovery_rule().unwrap();
    let rerun_refused = refusal(rerun_rule.admitted());
    assert_eq!(
        (
            before,
            displaced.is_err(),
            (rule, refused),
            (rerun.snapshot().phase, rerun_rule, rerun_refused),
            authority.sends.len() - sends,
            complete,
            events.recover(),
        ),
        (
            crate::RecoveryRule::Release,
            true,
            (
                crate::RecoveryRule::OwnershipLost,
                Some("IntentSelectedWriterMissing")
            ),
            (
                Phase::Fenced,
                crate::RecoveryRule::OwnershipLost,
                Some("IntentSelectedWriterMissing"),
            ),
            0,
            true,
            vec![
                "landed seq=3".to_owned(),
                "rebased chain_len=1".to_owned(),
                "selection_changed token=none".to_owned(),
                "selection_changed token=none".to_owned(),
            ],
        ),
        "(rule before the release, displaced answer refused: {displaced:?}, (rule, refusal), \
         re-run (phase, rule, refusal), sends after the displacement, record complete, events)"
    );
}

/// The refusal a coordination step answered, or `None` when it succeeded.
fn refusal<T>(result: Result<T, CoordinationError>) -> Option<&'static str> {
    match result {
        Ok(_) => None,
        Err(CoordinationError::Refused(name)) => Some(name),
        Err(error) => panic!("expected a named refusal: {error}"),
    }
}

#[tokio::test]
async fn selected_recovery_refuses_a_writer_other_than_the_stores() {
    let fx = Fixture::new().await;
    // P is signed as the writer passed in, so only the binding to the
    // store's own writer can refuse it.
    let other = [32; 16];
    let prepared = one_file(&fx.remote, b"a", b"recovered a", other).await;
    let (_scratch, _io, mut client, _authority) = granted(&prepared);
    let result = try_recover(&fx, &mut client, other, prepared).await;
    assert_eq!(
        (
            result.map(|_| ()).map_err(|error| error.to_string()),
            fx.remote.publication_sends.lock().unwrap().len(),
        ),
        (
            Err(crate::RecoveryError::Invalid("selected writer").to_string()),
            0
        ),
        "(outcome, publication sends): only the store's own writer is recovered"
    );
}

#[test]
fn a_carrier_in_its_handshake_is_reported_by_rule_zero() {
    let events = Events::default();
    let _events = events.guard();
    let (_scratch, _io, mut client, _request, _authority) = selected(&root(WRITER, 7));
    let rule = client.recovery_rule().unwrap();
    assert_eq!(
        (
            client.snapshot().phase,
            rule,
            refusal(rule.admitted()),
            events.recover(),
        ),
        (
            Phase::Handshake,
            crate::RecoveryRule::OwnershipLost,
            Some("IntentSelectedWriterMissing"),
            vec!["selection_changed token=none".to_owned()],
        ),
        "(phase, rule, refusal, events): a handshake holds no grant, so it only reports"
    );
}

/// A release refused after the grant's serving edge persisted leaves what a
/// crash there leaves: an owned serving carrier whose process is gone. The
/// next run places the store in rule 3b again, cannot release before its own
/// succession, and after it releases the selected generation.
#[tokio::test]
async fn a_release_cut_after_serving_persisted_is_released_after_the_next_runs_succession() {
    let fx = Fixture::new().await;
    let prepared = one_file(&fx.remote, b"a", b"recovered a", WRITER).await;
    let (scratch, io, mut client, mut authority) = granted(&prepared);
    let generation = intent::decode_receipt(&client.snapshot().current)
        .unwrap()
        .generation;
    let crate::SelectedPublication::Driven(_) = recover(&fx, &mut client, WRITER, prepared).await
    else {
        panic!("an unchanged parent is an exact publication")
    };
    // An unrepresentable bound refuses inside the ordinary release, after
    // the serving edge persisted.
    let cut = refusal(client.prepare_recovery_release(&Tick(20), std::time::Duration::MAX));
    let cut_phase = client.snapshot().phase;
    drop(client);
    io.crash();
    let mut rerun = start(&scratch, &io, 40);
    let rule = rerun.recovery_rule().unwrap();
    let early = refusal(rerun.prepare_recovery_release(&Tick(30), crate::DEFAULT_RESOLUTION_BOUND));
    let transfer = rerun.prepare_succession(&Tick(31)).unwrap();
    rerun.dispatch(&transfer, &Tick(31)).unwrap();
    let answer = authority.send(&transfer);
    rerun
        .complete(
            &transfer,
            Ok(&answer),
            &Tick(32),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let release = rerun
        .prepare_recovery_release(&Tick(33), crate::DEFAULT_RESOLUTION_BOUND)
        .unwrap();
    rerun.dispatch(&release, &Tick(33)).unwrap();
    let answer = authority.send(&release);
    rerun
        .complete(
            &release,
            Ok(&answer),
            &Tick(34),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!(
        (
            (cut, cut_phase),
            rule,
            early,
            intent::decode_release(release.bytes()).unwrap().generation,
            rerun.snapshot().phase,
            authority.row.map(|row| row.state),
        ),
        (
            (Some("IntentDeadlineOverflow"), Phase::Serving),
            crate::RecoveryRule::Release,
            Some("IntentFreshInstanceRequired"),
            generation,
            Phase::Released,
            Some(ReceiptState::Released),
        ),
        "((cut refusal, phase left), re-run rule, release before succession, \
         release generation, final phase, authority row)"
    );
}

/// A displacement during Ownership must stop settlement; Release and
/// landed-refresh displacements persist their fence for classification.
#[tokio::test]
async fn recovery_settlement_propagates_displaced_ownership() {
    let mut rows = Vec::new();
    for operation in [Operation::Ownership, Operation::Release] {
        let prepared = root(WRITER, 7);
        let (scratch, io, mut local, request, mut authority) = if operation == Operation::Ownership
        {
            selected(&prepared)
        } else {
            let (scratch, io, mut local, authority) = serving();
            let request = local
                .prepare_release(&Tick(10), Duration::from_secs(1), None)
                .unwrap();
            (scratch, io, local, request, authority)
        };
        authority.row = authority.row.map(|row| Receipt {
            epoch: row.epoch + 1,
            ..row
        });
        let sent_before = authority.sends.len();
        let result = settle_displaced_request(&mut local, &request, &mut authority);
        rows.push((
            operation,
            result.err().map(|error| error.name()),
            local.snapshot().phase,
            authority.sends.len() - sent_before,
        ));
        drop((local, io, scratch));
    }
    assert_eq!(
        rows,
        [
            (
                Operation::Ownership,
                Some("IntentFenced (ESTALE)"),
                Phase::Fenced,
                1
            ),
            (Operation::Release, None, Phase::Fenced, 1),
        ]
    );
    let mut succession = Vec::new();
    for absent in [false, true] {
        let (scratch, io, mut local, mut authority) = granted(&root(WRITER, 7));
        let request = local.prepare_succession(&Tick(11)).unwrap();
        let selected = authority.row.unwrap();
        assert_eq!(
            intent::decode_ownership(request.bytes()).unwrap().mode,
            OwnershipMode::Takeover {
                expected_epoch: selected.epoch,
                generation: selected.generation,
                state: selected.state,
                recovery_ack: false,
            }
        );
        let successor = Receipt {
            epoch: selected.epoch + 1,
            instance: [99; 16],
            ..selected
        };
        authority.row = (!absent).then_some(successor);
        let result = settle_displaced_request(&mut local, &request, &mut authority);
        drop(local);
        io.crash();
        let reopened = start(&scratch, &io, 40);
        let carrier = reopened.snapshot();
        let evidence = if absent {
            vec![]
        } else {
            intent::encode_receipt(successor).unwrap()
        };
        succession.push((
            result.err().map(|error| error.name()),
            carrier.phase,
            carrier.fence,
            carrier.fence_evidence == evidence,
            carrier
                .pending
                .iter()
                .any(|pending| pending.body == request.bytes()),
        ));
    }
    assert_eq!(
        succession,
        [
            (Some("IntentFenced (ESTALE)"), Phase::Fenced, 1, true, false),
            (Some("IntentFenced (ESTALE)"), Phase::Fenced, 2, true, false),
        ],
        "(refusal, reopened phase, fence, exact evidence, retained succession)"
    );
}

fn settle_displaced_request(
    local: &mut WritableStore<SimIo>,
    request: &PendingIntent,
    authority: &mut Authority,
) -> Result<(), crate::WritableStartError> {
    crate::writable_start::settle_recovery(local, &Tick(11), |local, pending, landed| {
        assert!(pending.bytes() == request.bytes() && !landed);
        local.dispatch(pending, &Tick(11))?;
        let answer = authority.send(pending);
        local.complete(
            pending,
            Ok(&answer),
            &Tick(12),
            &mut SeededRng::new(1),
            0,
            None,
        )?;
        Ok(())
    })
}

#[test]
fn recovery_succession_without_an_answer_retains_exact_request() {
    let (scratch, io, mut local, _) = granted(&root(WRITER, 7));
    let request = local.prepare_succession(&Tick(11)).unwrap();
    local.dispatch(&request, &Tick(11)).unwrap();
    assert!(matches!(
        local.complete(
            &request,
            Err(crate::IntentTransportError::Transport),
            &Tick(12),
            &mut SeededRng::new(1),
            0,
            None,
        ),
        Ok(crate::writable_store::IntentCompletion::Unknown)
    ));
    drop(local);
    io.crash();
    let reopened = start(&scratch, &io, 40);
    assert_eq!(reopened.snapshot().phase, Phase::Handshake);
    assert_eq!(reopened.snapshot().fence, 0);
    let [retained] = reopened.snapshot().pending.as_slice() else {
        panic!("the unanswered succession must survive reopen");
    };
    assert_eq!(
        (retained.attempts, retained.terminal, retained.answered),
        (1, false, false)
    );
    assert!(retained.body == request.bytes() && retained.answer.is_empty());
}

#[test]
fn recovery_succession_fence_and_retirement_share_one_carrier_revision() {
    for cut in [None, Some("partial"), Some("after_dir_sync")] {
        let (scratch, io, mut local, mut authority) = serving();
        local
            .prepare_registration(&root(local.writer_uuid(), 7), vec![1], &Tick(10), |_, _| {
                true
            })
            .unwrap();
        let request = local.prepare_succession(&Tick(11)).unwrap();
        local.dispatch(&request, &Tick(11)).unwrap();
        let previous = io.recovered_bytes("ownership").unwrap();
        let mut expected = local.snapshot().clone();
        let successor = Receipt {
            epoch: authority.cursor + 1,
            instance: [99; 16],
            ..authority.row.unwrap()
        };
        authority.row = Some(successor);
        let answer = authority.send(&request);
        let faults = local.fault_control();
        if let Some(cut) = cut {
            faults.arm("intent.pending", cut, 1, FaultAction::Crash);
        }
        let result = local.complete(
            &request,
            Ok(&answer),
            &Tick(12),
            &mut SeededRng::new(1),
            0,
            None,
        );
        if cut.is_some() {
            assert!(
                matches!(
                    result,
                    Err(CoordinationError::Overlay(OverlayError::InjectedCrash))
                ),
                "{cut:?}: {result:?}"
            );
            assert_eq!(faults.fired().len(), 1);
            assert!(matches!(
                local.prepare_succession(&Tick(13)),
                Err(CoordinationError::Refused("IntentPersistencePoisoned"))
            ));
        } else {
            assert!(
                matches!(result, Err(CoordinationError::Fenced { recorded_generation: Some(generation) }) if generation == successor.generation),
                "{result:?}"
            );
        }
        drop(local);
        io.crash();
        let reopened = start(&scratch, &io, 40);
        let carrier = reopened.snapshot();
        if cut == Some("partial") {
            assert!(
                io.recovered_bytes("ownership").unwrap() == previous,
                "a partial write must preserve every byte of the previous carrier"
            );
        } else {
            expected.revision += 1;
            expected.phase = Phase::Fenced;
            expected.fence = 1;
            expected.fence_evidence = intent::encode_receipt(successor).unwrap();
            expected
                .pending
                .retain(|pending| pending.body != request.bytes());
        }
        assert_eq!(carrier.revision, expected.revision, "{cut:?}");
        assert!(
            *carrier == expected,
            "{cut:?}: fence, evidence and retirement must survive together"
        );
    }
}

#[tokio::test]
async fn selected_recovery_refuses_overlapping_modify_and_delete_after_displacement() {
    let mut cases = 0;
    for name in [b"a".as_slice(), b"b"] {
        let fx = Fixture::new().await;
        let base = one_file(&fx.remote, b"a", b"original", WRITER).await;
        fx.remote.published.lock().unwrap().insert(2, base);
        let prepared = one_file(&fx.remote, name, b"acknowledged", WRITER).await;
        let landed = one_file(&fx.remote, b"a", b"landed modification", WRITER).await;
        fx.remote.published.lock().unwrap().insert(3, landed);
        let (_scratch, _io, mut client, _authority) = granted(&prepared);
        let result = try_recover(&fx, &mut client, WRITER, prepared.clone()).await;
        assert_eq!(
            (
                matches!(&result, Err(crate::RecoveryError::Journal(error))
            if error.kind == crate::PublicationStoreErrorKind::Conflict),
                client.snapshot().root == prepared,
                fx.remote.publication_sends.lock().unwrap().len()
            ),
            (true, true, 0),
            "name={name:?}: {result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn parentless_selection_requires_its_exact_genesis_before_release() {
    let fx = Fixture::new().await;
    let mut doc =
        granary_core::root::decode_root(&fx.remote.published.lock().unwrap()[&1]).unwrap();
    doc.writer_uuid = WRITER;
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: signer().key_id(),
        sig: signer().sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    let genesis = granary_core::root::encode_root(&doc).unwrap();
    fx.remote
        .published
        .lock()
        .unwrap()
        .insert(1, genesis.clone());
    let mut cases = 0;
    for different in [false, true] {
        let mut selected = doc.clone();
        selected.timestamp.secs += i64::from(different);
        selected.sigs.clear();
        selected.sigs.push(RootSig {
            key_id: signer().key_id(),
            sig: signer().sign(&granary_core::root::signing_prefix_of(&selected).unwrap()),
        });
        let bytes = granary_core::root::encode_root(&selected).unwrap();
        assert_eq!(subsumed(&fx.remote, &bytes), !different);
        let (_scratch, _io, mut local, _) = granted(&bytes);
        let result = try_recover(&fx, &mut local, WRITER, bytes).await;
        assert_eq!(
            (
                matches!(&result, Ok(crate::SelectedPublication::Subsumed { .. })),
                matches!(&result, Ok(crate::SelectedPublication::Stale)),
                fx.remote.publication_sends.lock().unwrap().len()
            ),
            (!different, different, 0),
            "different={different}: {result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn subsumption_oracle_requires_content_and_checks_the_walk_end_parent() {
    let fx = Fixture::new().await;
    let mut cases = 0;
    let prepared = one_file(&fx.remote, b"a", b"selected", WRITER).await;
    let sibling = one_file(&fx.remote, b"b", b"different", WRITER).await;
    fx.remote.published.lock().unwrap().insert(2, sibling);
    assert!(
        !subsumed(&fx.remote, &prepared),
        "same writer is not content proof"
    );
    cases += 1;
    fx.remote
        .published
        .lock()
        .unwrap()
        .insert(2, prepared.clone());
    assert!(
        subsumed(&fx.remote, &prepared),
        "exact root witnesses publication"
    );
    cases += 1;
    let parent = granary_core::root::decode_root(&fx.remote.published.lock().unwrap()[&1]).unwrap();
    let mut selected = granary_core::root::decode_root(&prepared).unwrap();
    selected.manifest_root = parent.manifest_root;
    selected.sigs.clear();
    selected.sigs.push(RootSig {
        key_id: signer().key_id(),
        sig: signer().sign(&granary_core::root::signing_prefix_of(&selected).unwrap()),
    });
    let bytes = granary_core::root::encode_root(&selected).unwrap();
    assert!(
        subsumed(&fx.remote, &bytes),
        "the verified parent is a manifest witness"
    );
    cases += 1;
    assert_eq!(cases, 3);
}

#[test]
fn lost_store_recovery_preserves_a_newer_landed_deletion() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (following_commit, equal_content) in [(false, true), (true, true), (false, false)] {
        let (fx, prepared) = runtime.block_on(async {
            let fx = Fixture::new().await;
            let prepared = one_file(&fx.remote, b"x", b"acknowledged", WRITER).await;
            // The whole manifests differ: x alone is carried before its deletion.
            fx.create(
                "x",
                if equal_content {
                    b"acknowledged"
                } else {
                    b"independent"
                },
            );
            fx.create("other", b"landed only");
            let lane = fx
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70))
                .await
                .unwrap();
            land_without_refresh(&fx, &lane).await;
            let landed = one_file(&fx.remote, b"other", b"landed only", WRITER).await;
            let seq = granary_core::root::decode_root(&landed).unwrap().seq;
            assert_eq!(seq, 3);
            fx.remote.published.lock().unwrap().insert(seq, landed);
            if following_commit {
                let next = one_file(&fx.remote, b"other", b"later edit", [77; 16]).await;
                fx.remote.published.lock().unwrap().insert(seq + 1, next);
            }
            (fx, prepared)
        });
        let (scratch, _, authority) = selection(&prepared);
        *fx.remote.authority.lock().unwrap() = authority;
        let before = fx.remote.publication_sends.lock().unwrap().len();
        assert_eq!(
            command_on(&scratch, &fx.remote, &runtime, WRITER, Some(WRITER)),
            Ok(())
        );
        let head = fx
            .remote
            .published
            .lock()
            .unwrap()
            .last_key_value()
            .unwrap()
            .1
            .clone();
        assert_eq!(
            runtime.block_on(landed_names(&fx.remote, &head)),
            if equal_content {
                vec![b"other".to_vec()]
            } else {
                vec![b"other".to_vec(), b"x".to_vec()]
            }
        );
        assert_eq!(
            fx.remote.publication_sends.lock().unwrap().len(),
            before + 1
        );
        assert_eq!(
            fx.remote.authority.lock().unwrap().row.unwrap().state,
            ReceiptState::Released
        );
    }
}

#[test]
fn lost_store_recovery_preserves_a_later_directory_deletion() {
    const LOCAL: &[u8] = b"selected sibling";
    const OTHER: &[u8] = b"published sibling";
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (fx, prepared, deleted_head, expected_manifest) = runtime.block_on(async {
        let fx = Fixture::new().await;
        let content = Content::default();
        let subtree = manifest::build_dir(&[file_entry(&content, b"x", b"carried")]).unwrap();
        let directory = DirEntry {
            name: Name::new(b"d".to_vec()).unwrap(),
            kind: EntryKind::Dir {
                child: subtree.root,
            },
        };
        let local = file_entry(&content, b"local", LOCAL);
        let other = file_entry(&content, b"other", OTHER);
        let selected_tree = manifest::build_dir(&[directory.clone(), local.clone()]).unwrap();
        let ancestor_tree = manifest::build_dir(&[directory, other.clone()]).unwrap();
        let expected_manifest = manifest::build_dir(&[local, other]).unwrap().root;
        content.objects.lock().unwrap().extend(
            subtree
                .nodes
                .into_iter()
                .chain(selected_tree.nodes)
                .chain(ancestor_tree.nodes),
        );

        let prepared = prepare_tree(&fx.remote, &content, selected_tree.root, WRITER).await;
        let ancestor = prepare_tree(&fx.remote, &content, ancestor_tree.root, [77; 16]).await;
        let trusted = TrustedKeys::new([*signer().public_key()]).unwrap();
        let selected_doc = granary_store::crypto::check_head(&prepared, "v", 2, &trusted).unwrap();
        let ancestor_doc = granary_store::crypto::check_head(&ancestor, "v", 2, &trusted).unwrap();
        assert_eq!(selected_doc.parent, Some(fx.base));
        assert_eq!(ancestor_doc.parent, Some(fx.base));
        assert_ne!(selected_doc.manifest_root, ancestor_doc.manifest_root);
        let ancestor_id = GrainId::of(&ancestor);
        fx.remote.published.lock().unwrap().insert(2, ancestor);

        let head = one_file(&fx.remote, b"other", OTHER, [77; 16]).await;
        let head_doc = granary_store::crypto::check_head(&head, "v", 3, &trusted).unwrap();
        assert_eq!(head_doc.parent, Some(ancestor_id));
        let deleted_head = GrainId::of(&head);
        fx.remote.published.lock().unwrap().insert(3, head);
        (fx, prepared, deleted_head, expected_manifest)
    });

    let (scratch, _, authority) = selection(&prepared);
    *fx.remote.authority.lock().unwrap() = authority;
    assert_eq!(
        command_on(&scratch, &fx.remote, &runtime, WRITER, Some(WRITER)),
        Ok(())
    );
    let recovered = fx
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    let doc = granary_core::root::decode_root(&recovered).unwrap();
    assert_eq!((doc.seq, doc.parent), (4, Some(deleted_head)));
    assert_eq!(doc.manifest_root, expected_manifest);
    let (_, objects) = runtime
        .block_on(crate::resolve_at_collecting(&*fx.remote, "v", 4))
        .unwrap();
    for bytes in [LOCAL, OTHER] {
        assert_eq!(
            objects.get(&GrainId::of(bytes)).map(Vec::as_slice),
            Some(bytes)
        );
    }
    assert_eq!(
        fx.remote.publication_sends.lock().unwrap().as_slice(),
        std::slice::from_ref(&recovered)
    );
    let row = fx.remote.authority.lock().unwrap().row.unwrap();
    assert_eq!((row.writer, row.state), (WRITER, ReceiptState::Released));
}

#[tokio::test]
async fn selected_recovery_merges_identical_concurrent_additions() {
    let fx = Fixture::new().await;
    let prepared = one_file(&fx.remote, b"x", b"identical", WRITER).await;
    fx.create("x", b"identical");
    fx.create("other", b"landed only");
    let lane = fx
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    land_without_refresh(&fx, &lane).await;
    let (_scratch, _io, mut client, _authority) = granted(&prepared);
    let result = try_recover(&fx, &mut client, WRITER, prepared).await;
    assert!(
        matches!(result, Ok(crate::SelectedPublication::Driven(_))),
        "{result:?}"
    );
    let head = fx
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    assert_eq!(
        landed_names(&fx.remote, &head).await,
        vec![b"other".to_vec(), b"x".to_vec()]
    );
}
