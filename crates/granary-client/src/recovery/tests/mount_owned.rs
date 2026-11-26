// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{OverlayDisk, OverlayIo, Store};
use granary_core::overlay_journal::{self as journal, JournalHeader, Record};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

struct Scratch(std::path::PathBuf);
impl Scratch {
    #[expect(
        clippy::disallowed_methods,
        reason = "create only an exclusively claimed test-owned scratch directory"
    )]
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cwd = std::env::current_dir().unwrap();
        let root = cwd
            .ancestors()
            .find(|p| p.join("Cargo.lock").is_file())
            .unwrap();
        let path = root
            .join("target")
            .join(format!("mount-resume-{}-{n}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    #[expect(
        clippy::disallowed_methods,
        reason = "remove only the exclusively claimed test-owned scratch directory and its fixture contents"
    )]
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct DiskJournal<'a> {
    publications: crate::PublicationStore<'a>,
    durable: std::sync::Arc<std::sync::Mutex<Option<Submission>>>,
}
impl granary_core::grainsource::GrainSource for DiskJournal<'_> {
    fn has(&self, id: &GrainId) -> bool {
        granary_core::grainsource::GrainSource::has(&self.publications, id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, granary_core::grainsource::GrainSourceError> {
        granary_core::grainsource::GrainSource::get(&self.publications, id)
    }
}
impl PublicationJournal for DiskJournal<'_> {
    fn check_generic_resume(
        &mut self,
        record: &Submission,
    ) -> Result<(), crate::PublicationStoreError> {
        PublicationJournal::check_generic_resume(&mut self.publications, record)
    }
    fn load(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, crate::PublicationStoreError> {
        let record = self.publications.load(scope, volume)?;
        self.durable.lock().unwrap().clone_from(&record);
        Ok(record)
    }
    fn begin(&mut self, record: &Submission) -> Result<(), crate::PublicationStoreError> {
        self.publications.begin(record)?;
        *self.durable.lock().unwrap() = Some(record.clone());
        Ok(())
    }
    async fn replace(
        &mut self,
        generation: u64,
        record: &Submission,
    ) -> Result<(), crate::PublicationStoreError> {
        self.publications.replace(generation, record)?;
        *self.durable.lock().unwrap() = Some(record.clone());
        Ok(())
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one disk fixture pairs ten admission cases, including custody and read failures"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "reads and damages only fixture files inside the test-owned scratch directory"
)]
async fn generic_resume_refuses_an_open_mount_boundary_before_send() {
    let mut count = 0;
    for case in [
        "absent overlay",
        "unrelated publication",
        "mount owned",
        "fenced mount owned",
        "missing journal",
        "unreadable area",
        "unreadable journal",
        "malformed journal",
        "oversized journal",
        "torn journal",
    ] {
        let scratch = Scratch::new();
        let uid = std::fs::metadata(&scratch.0).unwrap().uid();
        let mut store = Store::open(&scratch.0).unwrap();
        let (transport, _, key, keys, mut entropy, mut delay) = setup();
        let mut retained = record();
        retained.candidates[0].evidence = Evidence::default();
        let mut disk = OverlayDisk::new(&scratch.0, uid);
        if case != "absent overlay" {
            let overlay = scratch.0.join("overlay");
            disk.create_directory(&overlay).unwrap();
            let scope = overlay.join(retained.scope.digest().unwrap());
            disk.create_directory(&scope).unwrap();
            let area = scope.join(retained.volume.as_str());
            if case == "unreadable area" {
                disk.create(&area).unwrap();
            } else {
                disk.create_directory(&area).unwrap();
                disk.create_directory(&area.join("staging")).unwrap();
            }
            let path = area.join("journal");
            if case == "unreadable area" || case == "missing journal" {
                // The area exists but has lost its canonical journal.
            } else if case == "unreadable journal" {
                disk.create_directory(&path).unwrap();
            } else {
                let header = JournalHeader {
                    writer: retained.frozen.writer_identity,
                    base_root: GrainId::of(b"base"),
                    base_seq: 1,
                    next_stage_id: 1,
                    receipt_generation: 0,
                };
                let bytes = if case == "malformed journal" {
                    b"malformed".to_vec()
                } else if case == "torn journal" {
                    let mut bytes = header.encode().unwrap();
                    bytes.push(1);
                    bytes
                } else {
                    let mut records = vec![Record::CommitBoundary {
                        through_seq: 0,
                        candidate: GrainId::of(&retained.frozen.initial_root),
                        publication_id: if case == "unrelated publication" {
                            [8; 16]
                        } else {
                            retained.publication_id
                        },
                    }];
                    if case == "fenced mount owned" {
                        records.push(Record::CommitFence {
                            boundary_seq: 1,
                            publication_id: retained.publication_id,
                        });
                    }
                    journal::encode_journal(&header, &records).unwrap()
                };
                disk.create(&path).unwrap();
                disk.write_at(&path, 0, &bytes).unwrap();
                if case == "oversized journal" {
                    disk.resize(&path, journal::JOURNAL_MAX as u64 + 1).unwrap();
                }
                disk.sync(&path).unwrap();
                disk.sync_directory(&area).unwrap();
            }
        }
        let mut publications = DiskJournal {
            publications: store.publications(uid).unwrap(),
            durable: transport.durable.clone(),
        };
        publications.begin(&retained).unwrap();
        transport.remote.lock().unwrap().plans.push_back(Plan::Land);
        let result = resume_publication(
            RecoveryParts {
                transport: &transport,
                journal: &mut publications,
                publisher_keys: &keys,
                signer: &key,
                secure: &mut entropy,
                clock: &FixedClock(1),
                delay: &mut delay,
            },
            &handle(&retained),
            RecoveryIntent::Continue,
        )
        .await;
        let sends = transport.remote.lock().unwrap().sends.len();
        match case {
            "absent overlay" | "unrelated publication" => assert_eq!(
                (
                    matches!(
                        result.as_ref().map(|r| &r.outcome),
                        Ok(PublicationOutcome::Landed(_))
                    ),
                    sends
                ),
                (true, 1),
                "{case}: {result:?}"
            ),
            "mount owned" => assert_eq!(
                (
                    result.err().map(|e| match e {
                        RecoveryError::Journal(e) => e.reason,
                        other => other.to_string(),
                    }),
                    sends
                ),
                (
                    Some("publication belongs to an open mount commit".to_owned()),
                    0
                )
            ),
            _ => {
                let reason = result.as_ref().err().map(|e| match e {
                    RecoveryError::Journal(e) => e.reason.clone(),
                    other => other.to_string(),
                });
                let text = reason.as_deref().unwrap_or("");
                let refused = match case {
                    "fenced mount owned" => {
                        text == "commit publication 07070707070707070707070707070707 fenced (ESTALE)"
                    }
                    "missing journal" => text == "overlay journal missing from existing area",
                    "unreadable area" => text.ends_with("Not a directory (os error 20)"),
                    "unreadable journal" => text.ends_with("is not a regular file"),
                    "malformed journal" => text == "journal fenced at byte 0: bad journal magic",
                    "oversized journal" => text == "overlay journal exceeds cap",
                    "torn journal" => text == "overlay journal requires recovery",
                    _ => unreachable!(),
                };
                assert_eq!((refused, sends), (true, 0), "{case}: refusal={reason:?}");
            }
        }
        count += 1;
    }
    assert_eq!(count, 10);
}
