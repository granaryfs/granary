// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    ContentSource, FaultControl, MayLandAcknowledgement, OverlayConfig, OverlayError, OverlayStore,
    OwnershipStatus, PublicationHandle, PublicationJournal, PublicationStore,
    PublicationStoreError, RecoveryBackoff, RecoveryIntent, RecoveryParts,
    overlay_test_support::{Authority, AuthorityState, Entropy, PublishedTree, Time},
};
use granary_core::{
    grainsource::{GrainSource, GrainSourceError},
    retained_submission::{Scope, Submission, decode},
};
use granary_store::crypto::TrustedKeys;
use std::sync::{Arc, Mutex};

struct NoContent;
impl ContentSource for NoContent {
    fn read_verified(&mut self, _: GrainId, _: u64, _: usize) -> Result<Vec<u8>, OverlayError> {
        panic!("unexpected recovery content access")
    }
}

// Reaching the generic-resume check independently requires an earlier load
// that can supply a record without its own discard gate or generation write.
struct Loaded<'a, 'b> {
    store: &'a mut PublicationStore<'b>,
    gate_refused: bool,
}
impl GrainSource for Loaded<'_, '_> {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.store.get(id)
    }
    fn has(&self, id: &GrainId) -> bool {
        self.store.has(id)
    }
}
impl PublicationJournal for Loaded<'_, '_> {
    fn load(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.store.observe(scope, volume)
    }
    fn check_generic_resume(&mut self, record: &Submission) -> Result<(), PublicationStoreError> {
        let result = self.store.check_generic_resume(record);
        self.gate_refused = result.is_err();
        result
    }
    fn begin(&mut self, record: &Submission) -> Result<(), PublicationStoreError> {
        self.store.begin(record)
    }
    async fn replace(
        &mut self,
        generation: u64,
        record: &Submission,
    ) -> Result<(), PublicationStoreError> {
        self.store.replace(generation, record)
    }
}
async fn resume(
    journal: &mut impl PublicationJournal,
    tree: &PublishedTree,
    transport: &Authority,
    authority: &Arc<Mutex<AuthorityState>>,
    handle: &PublicationHandle,
) -> Result<crate::PublicationResult, crate::RecoveryError> {
    crate::resume_publication(
        RecoveryParts {
            transport,
            journal,
            publisher_keys: &TrustedKeys::new([*tree.key.public_key()]).unwrap(),
            signer: &tree.key,
            secure: &mut Entropy(29),
            clock: &Time(Arc::clone(authority)),
            delay: &mut RecoveryBackoff {
                rng: granary_core::rng::SeededRng::new(1),
            },
        },
        handle,
        RecoveryIntent::Continue,
    )
    .await
}

fn record() -> Submission {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../granary-core/tests/vectors/retained-submission/ready.bin");
    let mut bytes = Vec::new();
    fsguard::open_regular_read(&path)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    decode(&bytes).unwrap()
}

#[derive(Debug, Clone, Copy)]
enum State {
    Live,
    Archived,
    IntentOnly,
}

#[test]
fn discard_gates_intent_live() {
    matrix(State::Live);
}

#[test]
fn discard_gates_intent_archive() {
    matrix(State::Archived);
}

#[test]
fn discard_gates_intent_only() {
    matrix(State::IntentOnly);
}

#[expect(
    clippy::too_many_lines,
    reason = "the dispatch rows and their shared real-disk fixture form one claim matrix"
)]
fn matrix(state: State) {
    let (_scratch, root, _, _, _) = fixture();
    let record = record();
    let writer = record.frozen.writer_identity;
    let config = OverlayConfig {
        scope: record.scope.clone(),
        volume: record.volume.clone(),
        euid: nix::unistd::geteuid().as_raw(),
        cap: 1_048_576,
        ownership_completion_reserve: 2048,
        instance: [22; 16],
    };
    let digest = config.scope.digest().unwrap();
    let area = root
        .join("overlay")
        .join(&digest)
        .join(config.volume.as_str());
    let scope = area.parent().unwrap();
    let claim = DiscardName {
        volume: config.volume.clone(),
        writer,
        incarnation: [3; 32],
    };
    let header = JournalHeader {
        writer,
        base_root: GrainId::of(b"gate base"),
        base_seq: 1,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    let mut store = Store::open_existing(&root).unwrap().0;
    let mut io = OverlayDisk::new(&root, config.euid);
    store
        .publications(config.euid)
        .unwrap()
        .begin(&record)
        .unwrap();
    io.create_directory(scope).unwrap();
    let selected = match state {
        State::Live => Some(area.clone()),
        State::Archived => Some(scope.join(claim.leaf(false))),
        State::IntentOnly => None,
    };
    if let Some(selected) = selected {
        io.create_directory(&selected).unwrap();
        io.create_directory(&selected.join("staging")).unwrap();
        put(&selected.join("journal"), &header.encode().unwrap());
        let writer = WriterRecord {
            writer,
            volume: config.volume.clone(),
            ceiling: 0,
        };
        put(&selected.join("writer"), &writer.encode().unwrap());
    }
    put(&scope.join(claim.leaf(true)), b"");
    let pub_scope = root.join("publications").join(&digest);
    let temp = pub_scope.join(format!("{}.sub.tmp-901", config.volume.as_str()));
    put(&temp, b"frozen publication temporary");
    let baseline = snapshot(&root);
    let reason = if matches!(state, State::Archived) {
        "OverlayArchived"
    } else {
        "OverlayDiscardPending"
    };
    let refused = |row: &str, result: Result<(), String>| {
        let error = result.expect_err(row);
        assert!(error.contains(reason), "{row}, {state:?}: {error}");
        assert_eq!(
            snapshot(&root),
            baseline,
            "{row}, {state:?} wrote to the store"
        );
    };
    let faults = FaultControl::default();
    refused(
        "establish writer",
        crate::OverlayStore::establish_writer(
            &mut store,
            &config,
            &mut io,
            &mut Entropy(29),
            &faults,
        )
        .map(|_| ())
        .map_err(|e| e.to_string()),
    );
    refused(
        "recovery open",
        OverlayStore::open(
            &mut store,
            config.clone(),
            header,
            vec![],
            &OwnershipStatus::PendingReconciliation,
            &mut NoContent,
            OverlayDisk::new(&root, config.euid),
            faults.clone(),
        )
        .map(|_| ())
        .map_err(|e| e.to_string()),
    );
    refused(
        "recovery journal condition",
        crate::overlay_store::journal_condition(&mut io, &area)
            .map(|_| ())
            .map_err(|e| e.to_string()),
    );
    refused(
        "recovery landed scan",
        crate::overlay_store::landed_commits(&mut io, &area)
            .map(|_| ())
            .map_err(|e| e.to_string()),
    );

    let mut pub_store = store.publications_read_only(config.euid).unwrap();
    refused(
        "scoped load",
        pub_store
            .load(&config.scope, &config.volume)
            .map(|_| ())
            .map_err(|e| e.to_string()),
    );
    let tree = PublishedTree::publish("discard-gate-transport");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let authority = Arc::new(Mutex::new(AuthorityState::default()));
    let transport = Authority::new(&tree, &authority);
    let handle = PublicationHandle {
        scope: record.scope.clone(),
        volume: record.volume.clone(),
        publication_id: record.publication_id,
    };
    for isolate_resume_gate in [false, true] {
        let result = if isolate_resume_gate {
            let mut loaded = Loaded {
                store: &mut pub_store,
                gate_refused: false,
            };
            let result =
                runtime.block_on(resume(&mut loaded, &tree, &transport, &authority, &handle));
            assert!(loaded.gate_refused, "generic resume passed its own gate");
            result
        } else {
            runtime.block_on(resume(
                &mut pub_store,
                &tree,
                &transport,
                &authority,
                &handle,
            ))
        };
        refused(
            if isolate_resume_gate {
                "generic resume gate"
            } else {
                "generic resume"
            },
            result.map(|_| ()).map_err(|e| e.to_string()),
        );
        assert!(authority.lock().unwrap().publications.is_empty());
    }
    refused(
        "direct selection",
        pub_store
            .select_direct(&config.volume, None)
            .map(|_| ())
            .map_err(|e| e.to_string()),
    );
    refused(
        "abandon",
        pub_store
            .abandon(
                &config.scope,
                &config.volume,
                record.publication_id,
                MayLandAcknowledgement::Acknowledged,
            )
            .map(|_| ())
            .map_err(|e| e.to_string()),
    );

    drop(pub_store);

    // A sweep has no selected volume. It must leave the frozen temporary
    // untouched and remain usable for unrelated publications.
    drop(store.publications(config.euid).unwrap());
    assert_eq!(
        snapshot(&root),
        baseline,
        "publication sweep wrote to the store"
    );
    let mut other = config.clone();
    other.volume = VolumeName::from_bytes(b"unaffected").unwrap();
    let other_temp = pub_scope.join("unaffected.sub.tmp-902");
    put(&other_temp, b"sweep this");
    store
        .publications(config.euid)
        .unwrap()
        .select_direct(&other.volume, None)
        .unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&other_temp).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let unchanged = snapshot(&root);
    let temp_key = temp.strip_prefix(&root).unwrap();
    assert_eq!(unchanged[temp_key], baseline[temp_key]);
    OverlayStore::establish_writer(&mut store, &other, &mut io, &mut Entropy(29), &faults).unwrap();

    let fresh = root.parent().unwrap().join("fresh-store");
    let mut store = Store::open(&fresh).unwrap();
    let mut io = OverlayDisk::new(&fresh, config.euid);
    let acquired =
        OverlayStore::establish_writer(&mut store, &config, &mut io, &mut Entropy(41), &faults)
            .unwrap();
    assert_eq!(acquired.writer, [41; 16]);
    assert_ne!(acquired.writer, writer);
    assert!(authority.lock().unwrap().publications.is_empty());
}
