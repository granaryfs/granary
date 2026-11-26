// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use granary_core::{
    authority_answer::{self, Head, PublishAnswer},
    hash::GrainId,
    retained_submission::{Completion, LastResponse, Phase, Probe, ProbeReason},
};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(target_os = "linux"))]
fn workspace_root() -> PathBuf {
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    cwd.ancestors()
        .find(|root| {
            root.join("Cargo.lock").is_file() && root.join("crates/granary-client").is_dir()
        })
        .expect("physical workspace root")
        .to_owned()
}

fn scratch_base() -> PathBuf {
    #[cfg(target_os = "linux")]
    let base = std::env::temp_dir().canonicalize().unwrap();
    #[cfg(not(target_os = "linux"))]
    let base = workspace_root().join("target");
    base
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = scratch_base().join(format!("publication-store-test-{n}"));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("{e}"),
            }
        }
    }
    fn uid(&self) -> u32 {
        fs::symlink_metadata(&self.0).unwrap().uid()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fixture(name: &str) -> Submission {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../granary-core/tests/vectors/retained-submission/{name}.bin"
    ));
    codec::decode(&fs::read(path).unwrap()).unwrap()
}
fn complete(s: &mut Submission) {
    let c = &s.candidates[0];
    s.phase = Phase::Complete(Completion {
        seq: c.seq,
        id: c.id,
        root: c.root.clone(),
        receipt: None,
    });
    s.current = None;
}

#[test]
fn retained_read_io_is_distinct_from_malformed_input() {
    let path = Path::new("retained.sub");
    let transient = retained_read_error(path, &io::Error::other("injected read failure"));
    let malformed = retained_read_error(
        path,
        &io::Error::new(io::ErrorKind::InvalidData, "injected malformed input"),
    );
    assert_eq!(
        ((transient.kind, malformed.kind), 2),
        (
            (
                PublicationStoreErrorKind::Io,
                PublicationStoreErrorKind::Refused,
            ),
            2,
        ),
        "transient retained-record I/O must remain retryable while malformed input fails closed"
    );
}

#[test]
fn terminal_refusal_allows_another_scope_to_load_and_replace() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let mut old = fixture("ready");
    old.candidates[0].evidence = granary_core::retained_submission::Evidence::default();
    let attempt = old.candidates[0].evidence.start().unwrap();
    old.candidates[0]
        .evidence
        .answer(attempt, true, false)
        .unwrap();
    old.last_response = Some(granary_core::retained_submission::LastResponse {
        candidate: 1,
        attempt,
        status: 400,
        token: b"invalid-candidate".to_vec(),
        answer: vec![],
    });
    assert!(crate::sync::terminal_non_landing(&old));
    p.begin(&old).unwrap();
    let mut new = fixture("ready");
    new.scope.credential_context.push(b'2');
    new.publication_id = [99; 16];
    p.begin(&new).unwrap();
    let mut loaded = p
        .load(&new.scope, &new.volume)
        .expect("terminal refusal blocked another scope")
        .unwrap();
    assert_eq!(loaded.publication_id, new.publication_id);
    loaded.generation += 1;
    p.replace(2, &loaded).unwrap();
}

#[test]
fn deferred_answer_blocks_terminal_store_consumers() {
    let mut deferred = fixture("ready");
    deferred.candidates[0].evidence = granary_core::retained_submission::Evidence::default();
    let attempt = deferred.candidates[0].evidence.start().unwrap();
    deferred.candidates[0]
        .evidence
        .answer(attempt, true, false)
        .unwrap();
    deferred.last_response = Some(LastResponse {
        candidate: deferred.candidates[0].number,
        attempt,
        status: 409,
        token: b"stale-base".to_vec(),
        answer: authority_answer::encode(PublishAnswer::StaleBase(Head::new(Some((
            deferred.candidates[0].seq,
            GrainId::of(b"claimed occupant"),
        )))))
        .unwrap(),
    });
    deferred.phase = Phase::Unresolved(Probe {
        cycle: deferred.generation,
        seq: deferred.candidates[0].seq,
        reason: ProbeReason::ContentUnavailable,
    });
    granary_core::retained_submission::validate(&deferred).unwrap();
    let mut applied = deferred.clone();
    applied.phase = Phase::Ready;
    assert_eq!(
        (
            crate::sync::terminal_non_landing(&deferred),
            crate::sync::terminal_non_landing(&applied),
        ),
        (false, true),
        "only the complete deferred tuple must stay live"
    );

    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut publications = store.publications(scratch.uid()).unwrap();
    publications.begin(&deferred).unwrap();
    let mut next = fixture("ready");
    next.scope.credential_context.push(b'2');
    next.publication_id = [98; 16];
    let begin = publications.begin(&next).unwrap_err();
    let load = publications.load(&next.scope, &next.volume).unwrap_err();
    assert_eq!(
        (
            begin.reason.as_str(),
            load.reason.as_str(),
            publications
                .load(&deferred.scope, &deferred.volume)
                .unwrap()
                .map(|record| record.phase),
        ),
        (
            "publication is not complete",
            "non-complete publication under another scope",
            Some(deferred.phase),
        ),
        "publication-store admission must preserve and expose the live deferred record"
    );

    let applied_scratch = Scratch::new();
    let mut applied_store = Store::open(&applied_scratch.0).unwrap();
    let mut applied_publications = applied_store.publications(applied_scratch.uid()).unwrap();
    applied_publications.begin(&applied).unwrap();
    let loaded_applied = applied_publications
        .load(&applied.scope, &applied.volume)
        .unwrap()
        .map(|record| (record.phase, record.last_response));
    applied_publications.begin(&next).unwrap();
    assert_eq!(
        (
            loaded_applied,
            applied_publications
                .load(&next.scope, &next.volume)
                .unwrap()
                .map(|record| record.publication_id),
        ),
        (
            Some((applied.phase, applied.last_response)),
            Some(next.publication_id),
        ),
        "the same full answer in its applied destination must admit another scope"
    );
}

#[test]
fn durable_store_round_trip_new_refusal_completion_and_recovery() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let mut s = fixture("ready");
    assert!(p.load(&s.scope, &s.volume).unwrap().is_none());
    p.begin(&s).unwrap();
    s.generation += 1;
    assert_eq!(p.load(&s.scope, &s.volume).unwrap(), Some(s.clone()));
    let path = p.path(&s.scope, &s.volume).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );
    let mut new = s.clone();
    new.generation = 1;
    new.publication_id = [0xff; 16];
    assert!(
        p.begin(&new)
            .unwrap_err()
            .to_string()
            .contains("not complete")
    );
    s.generation = 3;
    complete(&mut s);
    p.replace(2, &s).unwrap();
    let mut successor = s.clone();
    successor.generation = 4;
    assert!(
        p.replace(3, &successor)
            .unwrap_err()
            .to_string()
            .contains("terminal")
    );
    let recovered = p.recover(&s.scope, &s.volume).unwrap();
    assert_eq!(recovered.generation, 4);
    let mut duplicate = s.clone();
    duplicate.generation = 1;
    assert!(
        p.begin(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("identity already exists")
    );
    p.begin(&new).unwrap();
    new.generation = 2;
    assert_eq!(p.load(&new.scope, &new.volume).unwrap(), Some(new));
}
#[test]
fn volume_scan_refuses_renamed_context_or_respelled_base() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    for change_base in [false, true] {
        let mut other = s.clone();
        other.publication_id = [0xff; 16];
        if change_base {
            other.scope.authority_base.push(b'/');
        } else {
            other.scope.credential_context.push(b'2');
        }
        let expected = p.path(&s.scope, &s.volume).unwrap();
        assert_eq!(
            p.load(&other.scope, &other.volume).unwrap_err().path,
            expected
        );
        assert_eq!(p.begin(&other).unwrap_err().path, expected);
    }
    // Even when the requested scope also exists, the scan cannot stop there.
    let mut other = s.clone();
    other.scope.credential_context.push(b'2');
    let other_path = p.path(&other.scope, &other.volume).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(other_path.parent().unwrap())
        .unwrap();
    fs::write(&other_path, codec::encode(&other).unwrap()).unwrap();
    fs::set_permissions(&other_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(p.load(&s.scope, &s.volume).unwrap_err().path, other_path);
}
#[test]
fn load_refuses_corruption_size_scope_and_path_mismatch() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let path = p.path(&s.scope, &s.volume).unwrap();
    let bytes = fs::read(&path).unwrap();
    let mut scope = s.scope.clone();
    scope.pins.clear();
    assert_eq!(p.load(&scope, &s.volume).unwrap_err().path, path);
    fs::write(&path, b"broken").unwrap();
    assert_eq!(p.load(&s.scope, &s.volume).unwrap_err().path, path);
    fs::write(&path, &bytes).unwrap();
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(codec::MAX_BYTES as u64 + 1)
        .unwrap();
    assert!(
        p.load(&s.scope, &s.volume)
            .unwrap_err()
            .to_string()
            .contains("cap")
    );
    let mut wrong = s.clone();
    wrong.scope.credential_context.push(b'x');
    fs::write(&path, codec::encode(&wrong).unwrap()).unwrap();
    assert!(
        p.load(&s.scope, &s.volume)
            .unwrap_err()
            .to_string()
            .contains("path")
    );
    fs::write(&path, &bytes).unwrap();
}
#[test]
fn protected_records_refuse_symlinks_hardlinks_nonregular_owner_and_mode() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let path = p.path(&s.scope, &s.volume).unwrap();
    let saved = path.with_extension("saved");
    fs::rename(&path, &saved).unwrap();
    symlink(&saved, &path).unwrap();
    assert_eq!(p.load(&s.scope, &s.volume).unwrap_err().path, path);
    fs::remove_file(&path).unwrap();
    fs::hard_link(&saved, &path).unwrap();
    assert!(p.load(&s.scope, &s.volume).is_err());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(
        p.load(&s.scope, &s.volume)
            .unwrap_err()
            .to_string()
            .contains("not a regular file")
    );
    fs::remove_dir(&path).unwrap();
    crate::fsguard::testutil::mkfifo(&path);
    let fifo = path.clone();
    let refusal =
        crate::fsguard::testutil::within_deadline("retained submission FIFO", move || {
            fsguard::open_sole_regular_read(&fifo, "a retained submission")
        })
        .unwrap_err();
    assert!(refusal.to_string().contains("not a regular file"));
    assert!(
        p.load(&s.scope, &s.volume)
            .unwrap_err()
            .to_string()
            .contains("not a regular file")
    );
    fs::remove_file(&path).unwrap();
    fs::rename(&saved, &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(p.load(&s.scope, &s.volume).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let file = fsguard::open_sole_regular_read(&path, "test").unwrap();
    assert!(protected(&file, &path, scratch.uid() + 1, Some(0o600)).is_err());
    assert!(protected(&file, &path, scratch.uid(), Some(0o600)).is_ok());
}
#[test]
fn protected_directories_refuse_symlinks_owner_modes_and_foreign_entries() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    assert!(store.publications(scratch.uid() + 1).is_err());
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let publications = scratch.0.join("publications");
    let moved = scratch.0.join("saved");
    fs::rename(&publications, &moved).unwrap();
    symlink(&moved, &publications).unwrap();
    assert!(p.load(&s.scope, &s.volume).is_err());
    fs::remove_file(&publications).unwrap();
    fs::rename(&moved, &publications).unwrap();
    fs::set_permissions(&publications, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(p.load(&s.scope, &s.volume).is_err());
    fs::set_permissions(&publications, fs::Permissions::from_mode(0o700)).unwrap();
    let scope = p
        .path(&s.scope, &s.volume)
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    fs::rename(&scope, &moved).unwrap();
    symlink(&moved, &scope).unwrap();
    assert!(p.load(&s.scope, &s.volume).is_err());
    fs::remove_file(&scope).unwrap();
    fs::rename(&moved, &scope).unwrap();
    let invalid_scope = publications.join("0".repeat(64));
    fs::write(&invalid_scope, b"not a directory").unwrap();
    assert!(p.load(&s.scope, &s.volume).is_err());
    fs::remove_file(invalid_scope).unwrap();
}
#[cfg(target_vendor = "apple")]
#[test]
fn protected_directory_refuses_granting_acl() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&fixture("ready")).unwrap();
    }
    let publications = scratch.0.join("publications");
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone allow read"])
        .arg(&publications)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(store.publications(scratch.uid()).is_err());
    assert!(
        std::process::Command::new("chmod")
            .arg("-N")
            .arg(&publications)
            .status()
            .unwrap()
            .success()
    );
}
#[test]
fn exclusive_temporary_is_never_adopted_and_existing_bytes_survive() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
    }
    let mut p = store.publications(scratch.uid()).unwrap();
    let path = p.path(&s.scope, &s.volume).unwrap();
    let temp = path.with_extension("sub.tmp-1");
    let mut newer = s.clone();
    newer.generation = 999;
    fs::write(&temp, codec::encode(&newer).unwrap()).unwrap();
    let mut expected = s.clone();
    expected.generation = 2;
    assert_eq!(p.load(&s.scope, &s.volume).unwrap(), Some(expected));
    let saved = fs::read(&temp).unwrap();
    let recovered = p.recover(&s.scope, &s.volume).unwrap();
    assert_eq!(recovered.generation, 3);
    assert_eq!(fs::read(&temp).unwrap(), saved);
    fs::remove_file(&path).unwrap();
    assert_eq!(p.load(&s.scope, &s.volume).unwrap(), None);
}
#[test]
fn generation_and_frozen_intent_guards() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    let mut next = s.clone();
    next.generation = 2;
    assert!(p.begin(&next).is_err());
    p.begin(&s).unwrap();
    assert!(p.replace(2, &next).is_err());
    let mut wrong = next.clone();
    wrong.publication_id = [99; 16];
    assert!(p.replace(1, &wrong).is_err());
    wrong = next.clone();
    wrong.frozen.writer_identity = [99; 16];
    assert!(p.replace(1, &wrong).is_err());
    p.replace(1, &next).unwrap();
    assert!(p.replace(1, &next).is_err());
    let mut skipped = next.clone();
    skipped.generation = 4;
    assert!(p.replace(2, &skipped).is_err());
    next.generation = u64::MAX;
    let path = p.path(&s.scope, &s.volume).unwrap();
    fs::write(&path, codec::encode(&next).unwrap()).unwrap();
    assert!(
        p.recover(&s.scope, &s.volume)
            .unwrap_err()
            .to_string()
            .contains("generation exhausted")
    );
}
#[test]
fn persistence_failure_requires_new_store_and_fresh_generation() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    let marker = scratch.0.join(crate::store::MARKER_NAME);
    let bytes = fs::read(&marker).unwrap();
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
        fs::remove_file(&marker).unwrap();
        assert!(p.recover(&s.scope, &s.volume).is_err());
        fs::write(&marker, &bytes).unwrap();
        assert!(
            p.recover(&s.scope, &s.volume)
                .unwrap_err()
                .to_string()
                .contains("reload")
        );
    }
    drop(store);
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    assert_eq!(p.recover(&s.scope, &s.volume).unwrap().generation, 2);
    assert_eq!(p.load(&s.scope, &s.volume).unwrap().unwrap().generation, 3);
}
#[test]
fn publication_lock_excludes_second_owner() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    p.begin(&fixture("ready")).unwrap();
    assert!(matches!(
        Store::open(&scratch.0),
        Err(crate::store::StoreError::Locked)
    ));
}

#[derive(Default)]
struct Model {
    names: BTreeMap<PathBuf, usize>,
    durable_names: BTreeMap<PathBuf, usize>,
    data: BTreeMap<usize, Vec<u8>>,
    synced: BTreeMap<usize, Vec<u8>>,
    dirs: BTreeSet<PathBuf>,
    durable_dirs: BTreeSet<PathBuf>,
    events: Vec<String>,
    cut: usize,
    after: bool,
}
impl Model {
    fn before(&mut self, name: String) -> io::Result<()> {
        self.events.push(name);
        if self.events.len() == self.cut && !self.after {
            return Err(io::Error::other("injected before operation"));
        }
        Ok(())
    }
    fn after(&self) -> io::Result<()> {
        if self.events.len() == self.cut && self.after {
            return Err(io::Error::other("injected after operation"));
        }
        Ok(())
    }
    fn recovered(&self, path: &Path) -> Option<Vec<u8>> {
        if !path
            .ancestors()
            .skip(1)
            .filter(|p| p.starts_with("/store"))
            .all(|p| self.durable_dirs.contains(p))
        {
            return None;
        }
        self.durable_names
            .get(path)
            .map(|inode| self.synced.get(inode).cloned().unwrap_or_default())
    }
}
impl Persistence for Model {
    type File = usize;
    fn sync_marker(&mut self, _: &Path) -> io::Result<()> {
        self.before("marker".into())?;
        self.after()
    }
    fn ensure_directory(&mut self, path: &Path) -> io::Result<()> {
        self.before(format!("mkdir {}", path.display()))?;
        self.dirs.insert(path.to_owned());
        self.after()
    }
    fn sync_directory(&mut self, path: &Path) -> io::Result<()> {
        self.before(format!("dirsync {}", path.display()))?;
        for dir in &self.dirs {
            if dir.parent() == Some(path) {
                self.durable_dirs.insert(dir.clone());
            }
        }
        self.durable_names.retain(|p, _| p.parent() != Some(path));
        for (p, inode) in &self.names {
            if p.parent() == Some(path) {
                self.durable_names.insert(p.clone(), *inode);
            }
        }
        self.after()
    }
    fn create(&mut self, path: &Path) -> io::Result<(PathBuf, usize)> {
        self.before("create".into())?;
        let temp = path.with_extension("temp");
        let inode = self.data.len() + 1;
        assert!(self.names.insert(temp.clone(), inode).is_none());
        self.data.insert(inode, Vec::new());
        self.after()?;
        Ok((temp, inode))
    }
    fn write(&mut self, file: &mut usize, bytes: &[u8]) -> io::Result<()> {
        self.before("write".into())?;
        self.data.insert(*file, bytes.to_vec());
        self.after()
    }
    fn sync_file(&mut self, file: &usize) -> io::Result<()> {
        self.before("filesync".into())?;
        self.synced.insert(*file, self.data[file].clone());
        self.after()
    }
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        self.before("rename".into())?;
        let inode = self.names.remove(from).unwrap();
        self.names.insert(to.to_owned(), inode);
        self.after()
    }
    fn open_record(&mut self, path: &Path) -> io::Result<usize> {
        self.before("open-record".into())?;
        let inode = *self
            .names
            .get(path)
            .ok_or_else(|| io::Error::other("missing record"))?;
        self.after()?;
        Ok(inode)
    }
    fn rename_no_replace(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        self.before("rename-no-replace".into())?;
        if self.names.contains_key(to) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        let inode = self
            .names
            .remove(from)
            .ok_or_else(|| io::Error::other("missing live"))?;
        self.names.insert(to.to_owned(), inode);
        self.after()
    }
    fn unlink(&mut self, path: &Path) -> io::Result<()> {
        self.before("unlink".into())?;
        self.names
            .remove(path)
            .ok_or_else(|| io::Error::other("missing live"))?;
        self.after()
    }
}
#[test]
fn restart_at_every_persistence_cut_keeps_complete_generations() {
    let root = Path::new("/store");
    let path = Path::new("/store/publications/scope/vol.sub");
    let old = codec::encode(&fixture("ready")).unwrap();
    for existing in [false, true] {
        for state in [
            "awaiting",
            "epoch-recovery",
            "probe-started",
            "unresolved",
            "complete-chain",
            "complete-receipt",
        ] {
            let mut next = fixture(state);
            next.generation = 2;
            let bytes = codec::encode(&next).unwrap();
            for after in [false, true] {
                for cut in 0..=12 {
                    let mut fs = Model {
                        cut,
                        after,
                        ..Model::default()
                    };
                    fs.dirs.insert(root.to_owned());
                    if existing {
                        for dir in [
                            root,
                            Path::new("/store/publications"),
                            path.parent().unwrap(),
                        ] {
                            fs.dirs.insert(dir.to_owned());
                            fs.durable_dirs.insert(dir.to_owned());
                        }
                        fs.names.insert(path.to_owned(), 1);
                        fs.durable_names = fs.names.clone();
                        fs.data.insert(1, old.clone());
                        fs.synced = fs.data.clone();
                    }
                    let result = durable_replace(&mut fs, root, path, &bytes);
                    let recovered = fs.recovered(path);
                    if cut == 0 {
                        result.unwrap();
                        assert_eq!(recovered, Some(bytes.clone()));
                        assert_eq!(
                            fs.events,
                            [
                                "marker",
                                "dirsync /store",
                                "dirsync /",
                                "mkdir /store/publications",
                                "dirsync /store",
                                "mkdir /store/publications/scope",
                                "dirsync /store/publications",
                                "create",
                                "write",
                                "filesync",
                                "rename",
                                "dirsync /store/publications/scope"
                            ]
                        );
                    } else {
                        assert!(result.is_err(), "cut {cut}, after {after}");
                        if let Some(found) = recovered {
                            assert!(found == old || found == bytes);
                            codec::decode(&found).unwrap();
                        } else {
                            assert!(!existing, "existing record disappeared at {cut}");
                        }
                    }
                    // A rename may survive a failed directory barrier. Only synced
                    // complete data is eligible; never choose a temporary by generation.
                    if fs.events.iter().any(|e| e == "rename")
                        && after
                        && let Some(inode) = fs.names.get(path)
                    {
                        assert!(fs.synced[inode] == old || fs.synced[inode] == bytes);
                    }
                }
            }
        }
    }
}

mod archive;

#[test]
fn temporary_counter_exhaustion_preserves_canonical_record() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    p.disk.temporary = u64::MAX;
    assert!(
        p.recover(&s.scope, &s.volume)
            .unwrap_err()
            .to_string()
            .contains("temporary counter exhausted")
    );
    assert!(p.load(&s.scope, &s.volume).is_err());
    assert_eq!(
        p.read(
            &p.path(&s.scope, &s.volume).unwrap(),
            &s.volume,
            retained_read_error
        )
        .unwrap(),
        Some(s)
    );
}

#[test]
fn oversize_metadata_refuses_before_any_read_or_allocation() {
    struct RefuseRead;
    impl Read for RefuseRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read attempted"))
        }
    }
    let result = read_bounded(RefuseRead, codec::MAX_BYTES as u64 + 1).unwrap_err();
    assert!(result.to_string().contains("exceeds byte cap"));
    assert!(
        read_bounded(RefuseRead, 0)
            .unwrap_err()
            .to_string()
            .contains("read attempted")
    );
}

#[test]
fn fresh_load_rewrites_after_rename_without_directory_sync() {
    for name in ["ready", "complete-receipt"] {
        let scratch = Scratch::new();
        let mut s = fixture(name);
        {
            let mut store = Store::open(&scratch.0).unwrap();
            let mut p = store.publications(scratch.uid()).unwrap();
            let path = p.path(&s.scope, &s.volume).unwrap();
            p.disk.fail_directory_sync = Some(path.parent().unwrap().to_owned());
            assert!(
                p.begin(&s)
                    .unwrap_err()
                    .reason
                    .contains("Input/output error")
            );
            assert_eq!(
                p.read(&path, &s.volume, retained_read_error).unwrap(),
                Some(s.clone())
            ); // rename landed
        }
        // No handle-local state or Store survives: this is also the process-reopen path.
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        let loaded = p.load(&s.scope, &s.volume).unwrap().unwrap();
        s.generation = 2;
        assert_eq!(loaded, s);
        let path = p.path(&s.scope, &s.volume).unwrap();
        assert_eq!(
            p.read(&path, &s.volume, retained_read_error).unwrap(),
            Some(s.clone())
        );
        // A fresh load must itself fail closed when its final sync fails.
        p.disk.fail_directory_sync = Some(path.parent().unwrap().to_owned());
        assert!(p.load(&s.scope, &s.volume).is_err());
    }
}

#[test]
fn read_inspection_resyncs_the_whole_chain_without_rewriting() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    let path;
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
        path = p.path(&s.scope, &s.volume).unwrap();
    }
    let scope = path.parent().unwrap().to_owned();
    let leftover = scope.join("vol.sub.tmp-9");
    fs::write(&leftover, b"leftover").unwrap();
    let state = || {
        (
            fs::read(&path).unwrap(),
            fs::metadata(&path).unwrap().ino(),
            leftover.exists(),
        )
    };
    let before = state();
    let mut p = store.publications_read_only(scratch.uid()).unwrap();
    let root = p.root().to_owned();
    let mut outcomes = Vec::new();
    for step in [
        "marker",
        "root",
        "parent",
        "publications",
        "scope",
        "record",
    ] {
        match step {
            "marker" => p.disk.fail_marker_sync = true,
            "root" => p.disk.fail_directory_sync = Some(root.clone()),
            "parent" => p.disk.fail_directory_sync = root.parent().map(Path::to_owned),
            "publications" => p.disk.fail_directory_sync = Some(root.join("publications")),
            "scope" => p.disk.fail_directory_sync = Some(scope.clone()),
            _ => p.disk.fail_file_sync = true,
        }
        let refusal = p.inspect_selected(&s.scope, &s.volume).unwrap_err();
        outcomes.push((step, refusal.kind));
        p.disk.fail_marker_sync = false;
        p.disk.fail_directory_sync = None;
        p.disk.fail_file_sync = false;
    }
    let after_failures = state();
    let clean = p.inspect_selected(&s.scope, &s.volume).unwrap();
    assert_eq!(
        (
            outcomes,
            after_failures == before,
            state() == before,
            clean,
            6,
        ),
        (
            [
                "marker",
                "root",
                "parent",
                "publications",
                "scope",
                "record"
            ]
            .map(|step| (step, PublicationStoreErrorKind::Io))
            .to_vec(),
            true,
            true,
            Some(s),
            6,
        ),
        "a read-only inspection must cross every barrier step as an I/O failure and rewrite nothing"
    );
}

#[test]
fn enumeration_skips_non_scope_names_without_opening_them() {
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStringExt as _;
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
    }
    let publications = scratch.0.join("publications");
    fs::write(publications.join(".DS_Store"), b"metadata").unwrap();
    symlink("absent", publications.join("unrelated")).unwrap();
    fs::write(publications.join("é"), b"metadata").unwrap();
    for name in [
        "B".repeat(64),
        "a".repeat(63),
        "g".repeat(64),
        "a".repeat(65),
    ] {
        symlink("absent", publications.join(name)).unwrap();
    }
    #[cfg(target_os = "linux")]
    fs::write(
        publications.join(std::ffi::OsString::from_vec(vec![0xff])),
        b"",
    )
    .unwrap();
    crate::fsguard::testutil::mkfifo(&publications.join("ignored-fifo"));
    let mut p = store.publications(scratch.uid()).unwrap();
    let loaded = p.load(&s.scope, &s.volume).unwrap().unwrap();
    assert_eq!(loaded.publication_id, s.publication_id);
    let scope = publications.join("a".repeat(64));
    symlink("absent", &scope).unwrap();
    assert_eq!(p.load(&s.scope, &s.volume).unwrap_err().path, scope);
}

#[test]
fn open_removes_only_exact_scope_temporary_names() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    let path;
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
        path = p.path(&s.scope, &s.volume).unwrap();
    }
    let scope = path.parent().unwrap();
    let saved = fs::read(&path).unwrap();
    for name in ["vol.sub.tmp-1", "other.sub.tmp-18446744073709551615"] {
        fs::write(scope.join(name), b"unfinished").unwrap();
    }
    let keep = [
        "vol.sub.tmp-0",
        "vol.sub.tmp-01",
        "vol.sub.tmp-+1",
        "vol.sub.tmp-18446744073709551616",
        "vol.sub.tmp-1.bak",
        "INVALID.sub.tmp-1",
        "notes",
    ];
    for name in keep {
        fs::write(scope.join(name), b"keep").unwrap();
    }
    let outside = scratch.0.join("vol.sub.tmp-1");
    fs::write(&outside, b"outside").unwrap();
    symlink(&outside, scope.join("vol.sub.tmp-2")).unwrap();
    let p = store.publications(scratch.uid()).unwrap();
    assert!(!scope.join("vol.sub.tmp-1").exists());
    assert!(!scope.join("other.sub.tmp-18446744073709551615").exists());
    assert!(fs::symlink_metadata(scope.join("vol.sub.tmp-2")).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    for name in keep {
        assert_eq!(fs::read(scope.join(name)).unwrap(), b"keep");
    }
    assert_eq!(fs::read(&path).unwrap(), saved);
    assert_eq!(
        p.read(&path, &s.volume, retained_read_error).unwrap(),
        Some(s)
    );
}

#[test]
fn writable_nonsticky_store_root_refuses_with_fix() {
    let scratch = Scratch::new();
    let s = fixture("ready");
    let mut store = Store::open(&scratch.0).unwrap();
    let path;
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
        path = p.path(&s.scope, &s.volume).unwrap();
    }
    let temporary = path.with_extension("sub.tmp-1");
    for mode in [0o775, 0o707] {
        {
            let mut p = store.publications(scratch.uid()).unwrap();
            fs::write(&temporary, b"keep until the root is protected").unwrap();
            fs::set_permissions(&scratch.0, fs::Permissions::from_mode(mode)).unwrap();
            let err = p.load(&s.scope, &s.volume).unwrap_err();
            assert_eq!(err.path, scratch.0);
            assert!(
                err.to_string()
                    .contains(&format!("chmod go-w {}", scratch.0.display()))
            );
        }
        drop(store);
        store = Store::open(&scratch.0).unwrap();
        assert_eq!(fs::metadata(&scratch.0).unwrap().mode() & 0o7777, mode);
        let err = store.publications(scratch.uid()).unwrap_err();
        assert_eq!(err.path, scratch.0);
        assert!(
            err.to_string()
                .contains(&format!("chmod go-w {}", scratch.0.display()))
        );
        assert_eq!(
            fs::read(&temporary).unwrap(),
            b"keep until the root is protected"
        );
        fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn trust_sticky_writable_root_refuses_with_fix() {
    let scratch = Scratch::new();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o1777)).unwrap();
    let mut store = Store::open(&scratch.0).unwrap();
    let err = store.publications(scratch.uid()).unwrap_err();
    assert_eq!(err.path, scratch.0);
    assert!(err.to_string().contains("chmod go-w"));
    assert_eq!(fs::metadata(&scratch.0).unwrap().mode() & 0o7777, 0o1777);
}

#[test]
fn new_store_root_is_private() {
    let scratch = Scratch::new();
    let root = scratch.0.join("ancestor/store");
    let mut store = Store::open(&root).unwrap();
    assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(root.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    assert_eq!(p.load(&s.scope, &s.volume).unwrap().unwrap().generation, 2);
}

#[test]
fn new_store_root_is_private_under_umask_0002() {
    // Set the process-wide umask only in a child, so concurrent tests keep
    // their own creation permissions.
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", "umask 0002; exec \"$@\"", "sh"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "publication_store::tests::new_store_root_is_private",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("1 passed"), "{stdout}");
}

#[test]
fn sticky_publication_directories_accept_only_private_permissions() {
    special_mode_publication_directories_accept_only_private_permissions(0o1000);
}

#[cfg(target_os = "linux")]
#[test]
fn setgid_publication_directories_accept_only_private_permissions() {
    special_mode_publication_directories_accept_only_private_permissions(0o2000);
}

fn special_mode_publication_directories_accept_only_private_permissions(special: u32) {
    let scratch = Scratch::new();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(special | 0o700)).unwrap();
    let mut store = Store::open(&scratch.0).unwrap();
    let publications = scratch.0.join("publications");
    fs::create_dir(&publications).unwrap();
    fs::set_permissions(&publications, fs::Permissions::from_mode(special | 0o700)).unwrap();
    assert_eq!(
        fs::metadata(&publications).unwrap().mode() & 0o7777,
        special | 0o700
    );
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let path = p.path(&s.scope, &s.volume).unwrap();
    let scope = path.parent().unwrap();
    fs::set_permissions(scope, fs::Permissions::from_mode(special | 0o700)).unwrap();
    assert_eq!(p.load(&s.scope, &s.volume).unwrap().unwrap().generation, 2);
    for mode in [0o750, 0o707] {
        fs::set_permissions(scope, fs::Permissions::from_mode(special | mode)).unwrap();
        assert_eq!(p.load(&s.scope, &s.volume).unwrap_err().path, scope);
    }
}

#[test]
fn writable_publications_refused_on_every_open_and_load() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
    }
    let publications = scratch.0.join("publications");
    for mode in [0o775, 0o707] {
        {
            let mut p = store.publications(scratch.uid()).unwrap();
            fs::set_permissions(&publications, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(p.load(&s.scope, &s.volume).unwrap_err().path, publications);
        }
        assert_eq!(
            store.publications(scratch.uid()).unwrap_err().path,
            publications
        );
        fs::set_permissions(&publications, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn trust_missing_ancestors_are_private() {
    let scratch = Scratch::new();
    let a = scratch.0.join("a");
    let b = a.join("b");
    let root = b.join("root");
    let _store = Store::open(&root).unwrap();
    for path in [&a, &b, &root] {
        assert_eq!(
            fs::metadata(path).unwrap().mode() & 0o777,
            0o700,
            "{}",
            path.display()
        );
    }
}

#[test]
fn trust_writable_ancestor_refuses_with_fix() {
    let scratch = Scratch::new();
    let a = scratch.0.join("a");
    let root = a.join("root");
    let mut store = Store::open(&root).unwrap();
    fs::set_permissions(&a, fs::Permissions::from_mode(0o770)).unwrap();
    let err = store.publications(scratch.uid()).unwrap_err();
    assert_eq!(err.path, a);
    assert!(err.to_string().contains("chmod go-w"));
    assert_eq!(fs::metadata(&a).unwrap().mode() & 0o7777, 0o770);
}

#[test]
fn trust_sticky_writable_ancestor_accepts() {
    let scratch = Scratch::new();
    let a = scratch.0.join("a");
    let root = a.join("root");
    let mut store = Store::open(&root).unwrap();
    fs::set_permissions(&a, fs::Permissions::from_mode(0o1777)).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    p.begin(&fixture("ready")).unwrap();
    assert_eq!(fs::metadata(&a).unwrap().mode() & 0o7777, 0o1777);
}

#[test]
fn trust_readable_root_accepts() {
    let scratch = Scratch::new();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    p.begin(&fixture("ready")).unwrap();
    assert_eq!(fs::metadata(&scratch.0).unwrap().mode() & 0o7777, 0o755);
}

#[test]
fn trust_new_lock_is_private() {
    let scratch = Scratch::new();
    let _store = Store::open(&scratch.0).unwrap();
    assert_eq!(
        fs::metadata(scratch.0.join("lock")).unwrap().mode() & 0o777,
        0o600
    );
}

#[test]
fn trust_existing_lock_becomes_private() {
    let scratch = Scratch::new();
    let lock = scratch.0.join("lock");
    drop(Store::open(&scratch.0).unwrap());
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    let _store = Store::open(&scratch.0).unwrap();
    assert_eq!(fs::metadata(&lock).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn trust_search_only_direct_parent_refuses() {
    let scratch = Scratch::new();
    if scratch.uid() == 0 {
        return; // Root bypasses permission bits.
    }
    let parent = scratch.0.join("parent");
    let mut store = Store::open(&parent.join("root")).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o111)).unwrap();
    let opened = fsguard::open_directory(&parent);
    let result = store.publications(scratch.uid());
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(opened.unwrap_err().raw_os_error(), Some(libc::EACCES));
    let err = result.unwrap_err();
    assert_eq!(err.path, parent);
    assert_eq!(
        err.reason,
        "the store's parent directory must be readable: every write syncs it"
    );
}

#[test]
fn trust_search_only_higher_ancestor() {
    let scratch = Scratch::new();
    let a = scratch.0.join("a");
    let mut store = Store::open(&a.join("parent/root")).unwrap();
    fs::set_permissions(&a, fs::Permissions::from_mode(0o711)).unwrap();
    assert!(store.publications(scratch.uid()).is_ok());

    // The fixture is euid-owned: remove owner read too to exercise EACCES,
    // as a non-root caller encounters at a root-owned 0711 ancestor.
    fs::set_permissions(&a, fs::Permissions::from_mode(0o111)).unwrap();
    let opened = fsguard::open_directory(&a);
    let result = store.publications(scratch.uid());
    fs::set_permissions(&a, fs::Permissions::from_mode(0o700)).unwrap();
    if scratch.uid() != 0 {
        assert_eq!(opened.unwrap_err().raw_os_error(), Some(libc::EACCES));
        #[cfg(target_vendor = "apple")]
        {
            let err = result.unwrap_err();
            assert_eq!(err.path, a);
            assert!(
                err.reason
                    .contains("an ancestor that cannot be read cannot have its ACL checked")
            );
        }
        #[cfg(not(target_vendor = "apple"))]
        assert!(result.is_ok(), "{result:?}");
    } else {
        assert!(result.is_ok(), "{result:?}");
    }
}

#[test]
fn trust_unreadable_writable_ancestor_refuses_with_fix() {
    let scratch = Scratch::new();
    let a = scratch.0.join("a");
    let mut store = Store::open(&a.join("root")).unwrap();
    fs::set_permissions(&a, fs::Permissions::from_mode(0o133)).unwrap();
    let result = store.publications(scratch.uid());
    fs::set_permissions(&a, fs::Permissions::from_mode(0o700)).unwrap();
    let err = result.unwrap_err();
    assert_eq!(err.path, a);
    assert!(err.reason.contains("chmod go-w"), "{err}");
}

#[test]
fn trust_leading_parent_components_resolve_and_accept() {
    let scratch = Scratch::new();
    let cwd = std::env::current_dir().unwrap();
    // Reach the filesystem root lexically, then spell the fixture from there.
    // The extra parent also verifies that popping `/` leaves `/`.
    let mut given = PathBuf::from(".");
    for _ in cwd.components() {
        given.push("..");
    }
    given.push(scratch.0.strip_prefix("/").unwrap());
    given.push("root");
    let mut store = Store::open(&given).unwrap();
    assert_eq!(store.publication_root(), scratch.0.join("root"));
    assert!(store.publications(scratch.uid()).is_ok());
}

#[test]
fn directory_open_errors_distinguish_symlink_and_not_directory() {
    let path = Path::new("/component");
    let symlink = directory_open_error(path, &io::Error::from_raw_os_error(libc::ELOOP));
    assert_eq!(symlink.path, path);
    assert!(symlink.reason.contains("name the symlink target directly"));
    let not_dir = directory_open_error(path, &io::Error::from_raw_os_error(libc::ENOTDIR));
    assert_eq!(not_dir.path, path);
    assert!(not_dir.reason.contains("component is not a directory"));
    assert!(!not_dir.reason.contains("symlink"));
}

#[test]
fn a_directory_open_is_io_only_when_the_device_the_filesystem_or_a_resource_failed() {
    let path = Path::new("/component");
    let kinds: Vec<_> = [
        ("EIO", libc::EIO),
        ("ESTALE", libc::ESTALE),
        ("ENOMEM", libc::ENOMEM),
        ("EMFILE", libc::EMFILE),
        ("ELOOP", libc::ELOOP),
        ("ENOTDIR", libc::ENOTDIR),
        ("EACCES", libc::EACCES),
    ]
    .into_iter()
    .map(|(name, errno)| {
        let refusal = directory_open_error(path, &io::Error::from_raw_os_error(errno));
        (name, refusal.kind, refusal.path == path)
    })
    .chain([(
        "other",
        directory_open_error(path, &io::Error::other("wrong owner")).kind,
        true,
    )])
    .collect();
    let io = PublicationStoreErrorKind::Io;
    let refused = PublicationStoreErrorKind::Refused;
    assert_eq!(
        (kinds, 8),
        (
            vec![
                ("EIO", io, true),
                ("ESTALE", io, true),
                ("ENOMEM", io, true),
                ("EMFILE", io, true),
                ("ELOOP", refused, true),
                ("ENOTDIR", refused, true),
                ("EACCES", refused, true),
                ("other", refused, true),
            ],
            8
        ),
        "an ancestor open must fail closed unless the device, the filesystem or a kernel resource failed"
    );
}

// Each row injects one failure after the placement; the entry is the only
// caller that reaches the site, so a site left on a refusal names itself.
#[test]
fn inspection_reports_a_failed_directory_open_or_read_as_io() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    let live = {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
        p.path(&s.scope, &s.volume).unwrap()
    };
    let digest = s.scope.digest().unwrap();
    let mut p = store.publications_read_only(scratch.uid()).unwrap();
    let root = p.root().to_owned();
    let publications = root.join("publications");
    let scope = live.parent().unwrap().to_owned();
    let rows = [
        ("observe", "open", root.clone()),
        ("observe", "open again", root.clone()),
        ("observe", "open", publications.clone()),
        ("observe", "read", publications.clone()),
        ("observe", "open", scope.clone()),
        ("archived", "open", root.clone()),
        ("archived", "open", publications.clone()),
        ("archived", "read", publications.clone()),
        ("archived", "open", scope.clone()),
        ("archived", "read", scope.clone()),
        ("inspect_selected", "open", publications.clone()),
        ("inspect_selected", "read", scope.clone()),
    ];
    let mut outcomes = Vec::new();
    for (entry, fault, target) in &rows {
        match *fault {
            "open" => p.disk.fail_directory_open = Some(target.clone()),
            // The first open of the root is the ancestry walk's; the entry's
            // own open of it is the second.
            "open again" => {
                p.disk.fail_directory_open = Some(target.clone());
                p.disk
                    .fail_directory_open_after
                    .store(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => p.disk.fail_directory_read = Some(target.clone()),
        }
        let refusal = match *entry {
            "observe" => p.observe(&s.scope, &s.volume).map(|_| ()),
            "archived" => p.archived(&digest, &s.volume, s.publication_id).map(|_| ()),
            _ => p.inspect_selected(&s.scope, &s.volume).map(|_| ()),
        }
        .unwrap_err();
        outcomes.push((*entry, *fault, (refusal.kind, refusal.path)));
        p.disk.fail_directory_open = None;
        p.disk
            .fail_directory_open_after
            .store(0, std::sync::atomic::Ordering::Relaxed);
        p.disk.fail_directory_read = None;
    }
    let premise = (
        p.observe(&s.scope, &s.volume).unwrap().as_ref() == Some(&s),
        p.archived(&digest, &s.volume, s.publication_id).unwrap(),
    );
    assert_eq!(
        (outcomes, premise, rows.len()),
        (
            rows.iter()
                .map(|(entry, fault, target)| (
                    *entry,
                    *fault,
                    (PublicationStoreErrorKind::Io, target.clone())
                ))
                .collect::<Vec<_>>(),
            (true, false),
            12
        ),
        "a failed open or read of a store directory under inspection is an I/O failure naming that directory"
    );
}

#[test]
fn placing_a_store_for_inspection_reports_a_failed_directory_open_or_read_as_io() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    let live = {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
        p.path(&s.scope, &s.volume).unwrap()
    };
    let root = store.publication_root().to_owned();
    let publications = root.join("publications");
    let scope = live.parent().unwrap().to_owned();
    let rows = [
        ("open", root),
        ("open", publications.clone()),
        ("open", scope.clone()),
        ("read", publications),
    ];
    let mut outcomes = Vec::new();
    for (fault, target) in &rows {
        match *fault {
            "open" => store.publication_fail_directory.open = Some(target.clone()),
            _ => store.publication_fail_directory.read = Some(target.clone()),
        }
        let refusal = store
            .publications_read_only(scratch.uid())
            .map(|_| ())
            .unwrap_err();
        outcomes.push((*fault, (refusal.kind, refusal.path)));
        store.publication_fail_directory = crate::store::DirectoryFaults::default();
    }
    let placed = store.publications_read_only(scratch.uid()).is_ok();
    assert_eq!(
        (outcomes, placed, rows.len()),
        (
            rows.iter()
                .map(|(fault, target)| (*fault, (PublicationStoreErrorKind::Io, target.clone())))
                .collect::<Vec<_>>(),
            true,
            4
        ),
        "placing a read-only handle must report a failed directory open or read as I/O"
    );
}

#[test]
fn a_symlinked_or_non_directory_scope_is_refused_by_inspection_and_by_load() {
    let mut outcomes = Vec::new();
    for replacement in ["symlink", "file"] {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let s = fixture("ready");
        let scope = {
            let mut p = store.publications(scratch.uid()).unwrap();
            p.begin(&s).unwrap();
            p.path(&s.scope, &s.volume)
                .unwrap()
                .parent()
                .unwrap()
                .to_owned()
        };
        if replacement == "symlink" {
            let moved = scratch.0.join("saved");
            fs::rename(&scope, &moved).unwrap();
            symlink(&moved, &scope).unwrap();
        } else {
            fs::remove_dir_all(&scope).unwrap();
            fs::write(&scope, b"not a directory").unwrap();
        }
        let placed = store
            .publications_read_only(scratch.uid())
            .map(|_| ())
            .unwrap_err();
        let written = store.publications(scratch.uid()).map(|_| ()).unwrap_err();
        outcomes.push((
            replacement,
            (placed.kind, placed.path == scope),
            (written.kind, written.path == scope),
        ));
    }
    let refused = (PublicationStoreErrorKind::Refused, true);
    assert_eq!(
        (outcomes, 2),
        (
            vec![("symlink", refused, refused), ("file", refused, refused)],
            2
        ),
        "a scope component that is a symlink or not a directory is custody, never a retryable I/O failure"
    );
}

#[test]
fn a_writing_handle_reports_a_failed_directory_open_as_io_and_a_replaced_scope_as_refused() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let publications = p.root().join("publications");
    let scope = p.path(&s.scope, &s.volume).unwrap();
    let scope = scope.parent().unwrap().to_owned();
    let mut outcomes = Vec::new();
    // `abandon` opens the publications directory before the scope, so the scope
    // row is the only one that reaches its second open.
    for (entry, target) in [
        ("load", &publications),
        ("abandon", &publications),
        ("abandon", &scope),
        ("list_archives", &publications),
        ("list_archives", &scope),
    ] {
        p.disk.fail_directory_open = Some(target.clone());
        let refusal = match entry {
            "load" => p.load(&s.scope, &s.volume).map(|_| ()),
            "abandon" => p
                .abandon(
                    &s.scope,
                    &s.volume,
                    s.publication_id,
                    MayLandAcknowledgement::Acknowledged,
                )
                .map(|_| ()),
            _ => p.list_archives(&s.volume).map(|_| ()),
        }
        .unwrap_err();
        outcomes.push((entry, (refusal.kind, refusal.path)));
        p.disk.fail_directory_open = None;
    }
    let moved = scratch.0.join("saved");
    fs::rename(&scope, &moved).unwrap();
    symlink(&moved, &scope).unwrap();
    let replaced = p.load(&s.scope, &s.volume).unwrap_err();
    outcomes.push(("replaced", (replaced.kind, replaced.path)));
    let io = PublicationStoreErrorKind::Io;
    assert_eq!(
        (outcomes, 6),
        (
            vec![
                ("load", (io, publications.clone())),
                ("abandon", (io, publications.clone())),
                ("abandon", (io, scope.clone())),
                ("list_archives", (io, publications)),
                ("list_archives", (io, scope.clone())),
                ("replaced", (PublicationStoreErrorKind::Refused, scope)),
            ],
            6
        ),
        "a writing handle classifies a directory open as inspection does"
    );
}

// A writing placement also lists each scope to remove store temporaries; that
// listing is a read like the others, while the unlink is a mutation.
#[test]
fn placing_a_store_for_writing_reports_a_failed_directory_open_or_read_as_io() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    let live = {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.begin(&s).unwrap();
        p.path(&s.scope, &s.volume).unwrap()
    };
    let publications = store.publication_root().join("publications");
    let scope = live.parent().unwrap().to_owned();
    let rows = [
        ("open", publications.clone()),
        ("open", scope.clone()),
        ("read", publications),
        ("read", scope),
    ];
    let mut outcomes = Vec::new();
    for (fault, target) in &rows {
        match *fault {
            "open" => store.publication_fail_directory.open = Some(target.clone()),
            _ => store.publication_fail_directory.read = Some(target.clone()),
        }
        let refusal = store.publications(scratch.uid()).map(|_| ()).unwrap_err();
        outcomes.push((*fault, (refusal.kind, refusal.path)));
        store.publication_fail_directory = crate::store::DirectoryFaults::default();
    }
    let placed = store.publications(scratch.uid()).is_ok();
    assert_eq!(
        (outcomes, placed, rows.len()),
        (
            rows.iter()
                .map(|(fault, target)| (*fault, (PublicationStoreErrorKind::Io, target.clone())))
                .collect::<Vec<_>>(),
            true,
            4
        ),
        "placing a writing handle must report a failed directory open or listing as I/O"
    );
}

// A regular file in a directory's place reports ENOTDIR. A symlink opened
// with O_DIRECTORY|O_NOFOLLOW reports ENOTDIR or ELOOP depending on the
// platform, so a symlink row accepts either operator hint; each still names
// how to fix the store.
#[test]
fn a_replaced_store_directory_keeps_its_operator_hint_at_every_open_site() {
    let not_dir = "component is not a directory";
    let symlinked = "name the symlink target directly";
    let mut outcomes = Vec::new();
    for replacement in ["symlink", "file"] {
        for component in ["publications", "scope"] {
            let scratch = Scratch::new();
            let mut store = Store::open(&scratch.0).unwrap();
            let s = fixture("ready");
            let mut p = store.publications(scratch.uid()).unwrap();
            p.begin(&s).unwrap();
            let publications = p.root().join("publications");
            let scope = p.path(&s.scope, &s.volume).unwrap();
            let scope = scope.parent().unwrap().to_owned();
            let replaced = if component == "scope" {
                &scope
            } else {
                &publications
            };
            if replacement == "symlink" {
                let moved = scratch.0.join("saved");
                fs::rename(replaced, &moved).unwrap();
                symlink(&moved, replaced).unwrap();
            } else {
                fs::remove_dir_all(replaced).unwrap();
                fs::write(replaced, b"not a directory").unwrap();
            }
            let mut refusals = vec![
                ("observe", p.observe(&s.scope, &s.volume).map(|_| ())),
                ("list_archives", p.list_archives(&s.volume).map(|_| ())),
                (
                    "abandon",
                    p.abandon(
                        &s.scope,
                        &s.volume,
                        s.publication_id,
                        MayLandAcknowledgement::Acknowledged,
                    )
                    .map(|_| ()),
                ),
            ];
            drop(p);
            refusals.push((
                "read-only placement",
                store.publications_read_only(scratch.uid()).map(|_| ()),
            ));
            refusals.push((
                "writing placement",
                store.publications(scratch.uid()).map(|_| ()),
            ));
            for (entry, result) in refusals {
                let refusal = result.unwrap_err();
                outcomes.push((
                    replacement,
                    component,
                    entry,
                    (
                        refusal.kind,
                        refusal.path == *replaced,
                        refusal.reason.contains(not_dir)
                            || (replacement == "symlink" && refusal.reason.contains(symlinked)),
                    ),
                ));
            }
        }
    }
    let kept = (PublicationStoreErrorKind::Refused, true, true);
    let mut expected = Vec::new();
    for replacement in ["symlink", "file"] {
        for component in ["publications", "scope"] {
            for entry in [
                "observe",
                "list_archives",
                "abandon",
                "read-only placement",
                "writing placement",
            ] {
                expected.push((replacement, component, entry, kept));
            }
        }
    }
    assert_eq!(
        (outcomes, 20),
        (expected, 20),
        "a symlinked or non-directory store directory is custody refused with the hint that says how to fix it"
    );
}

#[test]
fn filesystem_root_syncs_itself_as_parent() {
    let mut model = Model::default();
    durable_replace(
        &mut model,
        Path::new("/"),
        Path::new("/publications/scope/vol.sub"),
        b"record",
    )
    .unwrap();
    assert_eq!(&model.events[..3], ["marker", "dirsync /", "dirsync /"]);
    assert!(!model.events.iter().any(|event| event == "dirsync ."));
}

fn relative_root(scratch: &Scratch) -> PathBuf {
    #[cfg(target_os = "linux")]
    let base = PathBuf::from("/");
    #[cfg(not(target_os = "linux"))]
    let base = workspace_root();
    let cwd = std::env::current_dir().unwrap();
    let mut given = PathBuf::new();
    for _ in cwd.strip_prefix(&base).unwrap().components() {
        given.push("..");
    }
    given.push(scratch.0.strip_prefix(&base).unwrap());
    given
}

#[test]
fn trust_relative_root_is_stored_absolute() {
    let scratch = Scratch::new();
    let given = relative_root(&scratch).join("root");
    let store = Store::open(&given).unwrap();
    assert!(store.publication_root().is_absolute());
    assert_eq!(store.publication_root(), scratch.0.join("root"));
}

#[test]
fn trust_parent_component_refuses_with_fix() {
    let scratch = Scratch::new();
    fs::create_dir(scratch.0.join("child")).unwrap();
    let given = relative_root(&scratch).join("child/../root");
    let mut store = Store::open(&given).unwrap();
    let err = store.publications(scratch.uid()).unwrap_err();
    assert!(
        err.to_string().contains("spell the path without .."),
        "{err}"
    );
}

#[test]
fn trust_symlink_ancestor_refuses_with_fix() {
    let scratch = Scratch::new();
    let real = scratch.0.join("real");
    let link = scratch.0.join("link");
    fs::create_dir(&real).unwrap();
    symlink(&real, &link).unwrap();
    let mut store = Store::open(&link.join("root")).unwrap();
    let err = store.publications(scratch.uid()).unwrap_err();
    assert_eq!(err.path, link);
    // O_DIRECTORY|O_NOFOLLOW may report ENOTDIR for a symlink on Linux.
    assert!(
        err.to_string().contains("name the symlink target directly")
            || err.to_string().contains("component is not a directory"),
        "{err}"
    );
}

#[cfg(target_vendor = "apple")]
fn add_acl(path: &Path, entry: &str) {
    assert!(
        std::process::Command::new("chmod")
            .args(["+a", entry])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

#[cfg(target_vendor = "apple")]
fn clear_acl(path: &Path) {
    assert!(
        std::process::Command::new("chmod")
            .arg("-N")
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn trust_root_granting_acl_refuses_with_fix() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    add_acl(&scratch.0, "everyone allow read");
    let result = store.publications(scratch.uid());
    clear_acl(&scratch.0);
    let err = result.unwrap_err();
    assert_eq!(err.path, scratch.0);
    assert!(err.to_string().contains("the store root"), "{err}");
    assert!(err.to_string().contains("ls -le"), "{err}");
    assert!(err.to_string().contains("chmod -a# <index>"), "{err}");
    assert!(!err.to_string().contains("chmod -N"), "{err}");
}

#[cfg(target_vendor = "apple")]
#[test]
fn trust_ancestor_granting_acl_refuses_with_fix() {
    let scratch = Scratch::new();
    let a = scratch.0.join("a");
    let mut store = Store::open(&a.join("root")).unwrap();
    add_acl(&a, "everyone allow read");
    let result = store.publications(scratch.uid());
    clear_acl(&a);
    let err = result.unwrap_err();
    assert_eq!(err.path, a);
    assert!(err.to_string().contains("a store ancestor"), "{err}");
    assert!(err.to_string().contains("ls -le"), "{err}");
    assert!(err.to_string().contains("chmod -a# <index>"), "{err}");
    assert!(!err.to_string().contains("chmod -N"), "{err}");
}

#[cfg(target_vendor = "apple")]
#[test]
fn trust_ancestor_deny_acl_accepts() {
    let scratch = Scratch::new();
    let a = scratch.0.join("a");
    let mut store = Store::open(&a.join("root")).unwrap();
    add_acl(&a, "everyone deny delete");
    let result = store.publications(scratch.uid());
    clear_acl(&a);
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn ancestor_judge_refuses_another_uid() {
    assert_eq!(judge_ancestor(123, 0o755, 456), Err(Broken::AncestorOwner));
}
#[test]
fn ancestor_judge_accepts_root_owner() {
    assert_eq!(judge_ancestor(0, 0o755, 456), Ok(()));
}
#[test]
fn ancestor_judge_refuses_group_write() {
    assert_eq!(
        judge_ancestor(456, 0o775, 456),
        Err(Broken::AncestorWritable)
    );
}
#[test]
fn ancestor_judge_accepts_sticky_write() {
    assert_eq!(judge_ancestor(456, 0o1777, 456), Ok(()));
}
#[test]
fn root_judge_refuses_root_owner_for_nonroot_caller() {
    assert_eq!(judge_root(0, 0o700, 456), Err(Broken::RootOwner));
}
#[test]
fn root_judge_accepts_readable_mode() {
    assert_eq!(judge_root(456, 0o755, 456), Ok(()));
}
#[test]
fn root_judge_refuses_group_write() {
    assert_eq!(judge_root(456, 0o775, 456), Err(Broken::RootWritable));
}
#[test]
fn root_judge_refuses_sticky_write() {
    assert_eq!(judge_root(456, 0o1777, 456), Err(Broken::RootWritable));
}
#[test]
fn root_judge_accepts_private_mode() {
    assert_eq!(judge_root(456, 0o700, 456), Ok(()));
}
#[test]
fn shape_judge_refuses_parent_components() {
    assert_eq!(
        judge_shape(Path::new("/store/../root")),
        Err(Broken::ParentComponent)
    );
}
#[test]
fn shape_judge_refuses_relative_paths() {
    assert_eq!(
        judge_shape(Path::new("store/root")),
        Err(Broken::RelativePath)
    );
}
#[test]
fn shape_judge_accepts_absolute_paths() {
    assert_eq!(judge_shape(Path::new("/store/root")), Ok(()));
}
#[test]
fn empty_store_root_refuses() {
    let err = Store::open(Path::new("")).unwrap_err();
    assert!(err.to_string().contains("store root must not be empty"));
}

#[test]
fn ancestor_walk_refuses_outermost_untrusted_component_first() {
    let scratch = Scratch::new();
    let a = scratch.0.join("a");
    let b = a.join("b");
    let root = b.join("root");
    let mut store = Store::open(&root).unwrap();
    for path in [&a, &b, &root] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o770)).unwrap();
    }
    for path in [&a, &b, &root] {
        assert_eq!(store.publications(scratch.uid()).unwrap_err().path, *path);
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert!(store.publications(scratch.uid()).is_ok());
}

#[test]
fn direct_selection_checks_all_scopes_and_preserves_archive_acknowledgement() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut record = fixture("ready");
    let mut publications = store.publications(scratch.uid()).unwrap();
    publications.begin(&record).unwrap();
    for acknowledgement in [None, Some(MayLandAcknowledgement::Acknowledged)] {
        let error = publications
            .select_direct(&record.volume, acknowledgement)
            .unwrap_err();
        assert_eq!(error.kind, PublicationStoreErrorKind::Selection);
    }
    let archive = publications
        .abandon(
            &record.scope,
            &record.volume,
            record.publication_id,
            MayLandAcknowledgement::Acknowledged,
        )
        .unwrap();
    assert_eq!(
        publications
            .select_direct(&record.volume, None)
            .unwrap_err()
            .kind,
        PublicationStoreErrorKind::Abandoned
    );
    let selected = publications
        .select_direct(&record.volume, Some(MayLandAcknowledgement::Acknowledged))
        .unwrap();
    assert_eq!(
        selected.archives.first().unwrap().path,
        archive.archive.path
    );
    record.publication_id = [99; 16];
    complete(&mut record);
    record.generation = 1;
    publications.begin(&record).unwrap();
    let selected = publications
        .select_direct(&record.volume, Some(MayLandAcknowledgement::Acknowledged))
        .unwrap();
    assert_eq!(
        selected.completed.first().unwrap().1.publication_id,
        record.publication_id
    );
}

#[test]
fn publication_poison_survives_facade_recreation() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        p.disk.fail_file_sync = true;
        assert!(p.begin(&s).is_err());
        assert!(p.poisoned);
    }
    let mut p = store.publications(scratch.uid()).unwrap();
    let result = p.begin(&s);
    assert!(
        result
            .as_ref()
            .is_err_and(|e| e.reason.contains("persistence failed")),
        "facade poison: {result:?}"
    );
    drop(p);
    drop(store);
    let mut store = Store::open(&scratch.0).unwrap();
    store
        .publications(scratch.uid())
        .unwrap()
        .begin(&s)
        .unwrap();
}
