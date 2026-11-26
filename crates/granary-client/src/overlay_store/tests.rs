// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The crash model persists file contents and directory entries independently.
// @file-disposition: STAYS — the simulator and its transaction tests share the overlay crash-persistence invariant; test-only fixtures and instrumentation remain together.
use super::*;
mod bundle;
mod carry_forward;
mod commit;
mod incremental;
mod indexes;
mod projection;
pub(crate) mod publish_hold;
mod queries;
mod recreate;
pub(crate) mod replacement;
mod residual;
mod residual_disposition;
mod rollback;
mod snapshot;
mod sync_objects;
mod unmerged;
use std::collections::BTreeSet;
use std::io;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::sync::{Arc, Mutex};

fn rollback_count(bytes: &[u8]) -> usize {
    let mut count = 0;
    let scan = codec::scan_journal_with(bytes, |_, record| {
        count += usize::from(matches!(record, Record::StageRollback { .. }));
    })
    .unwrap();
    assert_eq!(scan.end, codec::JournalEnd::Clean);
    count
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SimIo(Arc<Mutex<Model>>);
#[derive(Debug, Default)]
struct Model {
    names: BTreeMap<PathBuf, u64>,
    directories: BTreeSet<PathBuf>,
    durable_names: BTreeMap<PathBuf, u64>,
    durable_directories: BTreeSet<PathBuf>,
    // Until the parent barrier, the durable child entries of the moved
    // directory object are indexed under its previous name.
    directory_move: Option<(PathBuf, PathBuf)>,
    root: Option<PathBuf>,
    files: BTreeMap<u64, (Vec<u8>, Vec<u8>)>,
    next: u64,
    trace: Vec<(String, PathBuf)>,
    fail: Option<&'static str>,
    fail_path: Option<PathBuf>,
    grow_after_read: Option<PathBuf>,
    short_read_at: Option<u64>,
    read_error_at: Option<u64>,
    read_lengths: Vec<(PathBuf, usize)>,
    unmerged_error: Option<io::Error>,
}
impl Model {
    fn persist_directory_move(&mut self, parent: &Path) {
        if self
            .directory_move
            .as_ref()
            .is_some_and(|(old, _)| old.parent() == Some(parent))
        {
            let (old, new) = self.directory_move.take().unwrap();
            self.durable_directories = std::mem::take(&mut self.durable_directories)
                .into_iter()
                .map(|p| rebase(&p, &old, &new))
                .collect();
            self.durable_names = std::mem::take(&mut self.durable_names)
                .into_iter()
                .map(|(p, id)| (rebase(&p, &old, &new), id))
                .collect();
        }
    }

    /// The directories and names a crash right now would leave, by the same rule
    /// `SimIo::crash` applies.
    fn recovered(&self) -> (BTreeSet<PathBuf>, BTreeMap<PathBuf, u64>) {
        let mut directories = BTreeSet::new();
        for p in &self.durable_directories {
            if Some(p) == self.root.as_ref()
                || p.parent()
                    .is_some_and(|parent| directories.contains(parent))
            {
                directories.insert(p.clone());
            }
        }
        let names = self
            .durable_names
            .iter()
            .filter(|(p, _)| {
                p.parent()
                    .is_some_and(|parent| directories.contains(parent))
            })
            .map(|(p, id)| (p.clone(), *id))
            .collect();
        (directories, names)
    }
}

fn rebase(path: &Path, old: &Path, new: &Path) -> PathBuf {
    match path.strip_prefix(old) {
        Ok(rest) if rest.as_os_str().is_empty() => new.to_owned(),
        Ok(rest) => new.join(rest),
        Err(_) => path.to_owned(),
    }
}

impl SimIo {
    pub(crate) fn crash(&self) {
        let mut m = self.0.lock().unwrap();
        (m.directories, m.names) = m.recovered();
        m.directory_move = None;
        for (live, durable) in m.files.values_mut() {
            *live = durable.clone();
        }
    }
    pub(crate) fn tree(&self) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        let m = self.0.lock().unwrap();
        m.directories
            .iter()
            .map(|p| (p.clone(), None))
            .chain(
                m.names
                    .iter()
                    .map(|(p, id)| (p.clone(), Some(m.files[id].0.clone()))),
            )
            .collect()
    }
    /// The bytes a crash right now would leave in the file with this name, or
    /// none if the name itself would not survive. Nothing is flushed or changed.
    fn recovered_bytes(&self, file_name: &str) -> Option<Vec<u8>> {
        let m = self.0.lock().unwrap();
        let (_, names) = m.recovered();
        let (_, id) = names
            .iter()
            .find(|(path, _)| path.file_name().is_some_and(|name| name == file_name))?;
        Some(m.files[id].1.clone())
    }
    fn mutate_recovered(&self, file_name: &str, body: impl FnOnce(&mut Vec<u8>)) {
        let mut m = self.0.lock().unwrap();
        let (_, names) = m.recovered();
        let id = names
            .iter()
            .find_map(|(path, id)| {
                (path.file_name().is_some_and(|name| name == file_name)
                    && path
                        .components()
                        .any(|component| component.as_os_str() == "overlay"))
                .then_some(*id)
            })
            .expect("durable fixture file is missing");
        body(&mut m.files.get_mut(&id).unwrap().1);
    }
    fn mutate(&self, p: &Path, body: impl FnOnce(&mut Vec<u8>)) {
        let mut m = self.0.lock().unwrap();
        let id = *m.names.get(p).unwrap();
        body(&mut m.files.get_mut(&id).unwrap().0);
    }
    fn bytes(&self, p: &Path) -> Vec<u8> {
        let m = self.0.lock().unwrap();
        m.files.get(m.names.get(p).unwrap()).unwrap().0.clone()
    }
    fn operation(&self, op: &str, p: &Path) -> io::Result<()> {
        let mut m = self.0.lock().unwrap();
        m.trace.push((op.into(), p.into()));
        if m.fail == Some(op) && m.fail_path.as_deref().is_none_or(|path| path == p) {
            m.fail = None;
            m.fail_path = None;
            return Err(io::Error::other("model injected I/O"));
        }
        Ok(())
    }
}
impl OverlayIo for SimIo {
    fn establish(&mut self, root: &Path) -> io::Result<()> {
        {
            let mut m = self.0.lock().unwrap();
            m.root = Some(root.into());
            m.directories.insert(root.into());
            m.durable_directories.insert(root.into());
        }
        self.sync_directory(root)
    }
    fn check_root(&mut self, _: &Path, _: u32) -> io::Result<()> {
        Ok(())
    }
    fn directory(&mut self, p: &Path) -> io::Result<()> {
        if self.0.lock().unwrap().directories.contains(p) {
            Ok(())
        } else {
            Err(io::ErrorKind::NotFound.into())
        }
    }
    fn entries(&mut self, p: &Path) -> io::Result<Vec<String>> {
        self.operation("entries", p)?;
        self.directory(p)?;
        let m = self.0.lock().unwrap();
        Ok(m.names
            .keys()
            .chain(m.directories.iter())
            .filter(|n| n.parent() == Some(p))
            .map(|n| n.file_name().unwrap().to_str().unwrap().to_owned())
            .collect())
    }
    fn length(&mut self, p: &Path) -> io::Result<Option<u64>> {
        self.operation("length", p)?;
        let m = self.0.lock().unwrap();
        Ok(m.names
            .get(p)
            .map(|id| m.files.get(id).unwrap().0.len() as u64))
    }
    fn modified(&mut self, _: &Path) -> io::Result<Option<(i64, i64)>> {
        Ok(None)
    }
    fn read_at(&mut self, p: &Path, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        self.operation("read", p)?;
        let mut m = self.0.lock().unwrap();
        m.read_lengths.push((p.into(), length));
        if m.read_error_at == Some(offset) {
            return Err(io::Error::other("model injected read error"));
        }
        let id = *m.names.get(p).ok_or(io::ErrorKind::NotFound)?;
        let b = &m.files.get(&id).unwrap().0;
        let start = (usize::try_from(offset).unwrap()).min(b.len());
        let mut bytes = b[start..b.len().min(start.saturating_add(length))].to_vec();
        if m.short_read_at == Some(offset) {
            bytes.pop();
        }
        if m.grow_after_read.as_deref() == Some(p) {
            m.grow_after_read = None;
            m.files.get_mut(&id).unwrap().0.push(0);
        }
        Ok(bytes)
    }
    fn unmerged_inventory(
        &mut self,
        area: &Path,
        cap: u64,
    ) -> io::Result<super::io::UnmergedInventory> {
        self.operation("unmerged", area)?;
        let mut m = self.0.lock().unwrap();
        if let Some(error) = m.unmerged_error.take() {
            return Err(error);
        }
        let directory = area.join("unmerged");
        if !m.directories.contains(&directory) {
            return Ok(super::io::UnmergedInventory {
                present: false,
                entries: Vec::new(),
            });
        }
        let mut total = 0_u64;
        let mut answer = Vec::new();
        for (path, id) in m
            .names
            .iter()
            .filter(|(path, _)| path.parent() == Some(&directory))
        {
            if answer.len() == super::unmerged::UNMERGED_ENTRY_MAX {
                return Err(io::Error::other("unmerged capacity refused"));
            }
            let bytes = m.files[id].0.clone();
            total = total
                .checked_add(bytes.len() as u64)
                .filter(|sum| *sum <= cap)
                .ok_or_else(|| io::Error::other("unmerged capacity refused"))?;
            let links = m.names.values().filter(|other| *other == id).count() as u64;
            if links > 2 {
                return Err(io::Error::other("unmerged leaf custody refused"));
            }
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let (kept, payload_check) = if name.strip_suffix(".path").is_some()
                || name.strip_suffix(".path.next").is_some()
            {
                (bytes.clone(), None)
            } else {
                let listing = m
                    .names
                    .get(&directory.join(format!("{name}.path")))
                    .or_else(|| m.names.get(&directory.join(format!("{name}.path.next"))))
                    .and_then(|listing| codec::UnmergedPath::decode(&m.files[listing].0).ok());
                let check = listing.and_then(|listing| {
                    let payload = bytes.get(codec::STAGING_HEADER_LEN..)?;
                    let mut hash = codec::ResidualPayloadHasher::new(
                        listing.file.stage_id,
                        listing.file.local_size,
                    );
                    for chunk in payload.chunks(BUFFER) {
                        hash.update(chunk);
                    }
                    Some(hash.finalize())
                });
                (
                    bytes
                        .get(..bytes.len().min(codec::STAGING_HEADER_LEN))
                        .unwrap()
                        .to_vec(),
                    check,
                )
            };
            answer.push(super::io::UnmergedEntry {
                name,
                prefix: kept,
                length: bytes.len() as u64,
                links,
                payload_check,
            });
        }
        answer.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(super::io::UnmergedInventory {
            present: true,
            entries: answer,
        })
    }
    fn create_directory(&mut self, p: &Path) -> io::Result<()> {
        self.0.lock().unwrap().directories.insert(p.into());
        Ok(())
    }
    fn create(&mut self, p: &Path) -> io::Result<()> {
        self.operation("create", p)?;
        let mut m = self.0.lock().unwrap();
        if m.names.contains_key(p) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        m.next += 1;
        let id = m.next;
        m.names.insert(p.into(), id);
        m.files.insert(id, (vec![], vec![]));
        Ok(())
    }
    fn write_at(&mut self, p: &Path, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.operation("write", p)?;
        let mut m = self.0.lock().unwrap();
        let id = *m.names.get(p).ok_or(io::ErrorKind::NotFound)?;
        let b = &mut m.files.get_mut(&id).unwrap().0;
        let end = usize::try_from(offset).unwrap() + bytes.len();
        b.resize(b.len().max(end), 0);
        b[usize::try_from(offset).unwrap()..end].copy_from_slice(bytes);
        Ok(())
    }
    fn resize(&mut self, p: &Path, length: u64) -> io::Result<()> {
        self.operation("resize", p)?;
        let mut m = self.0.lock().unwrap();
        let id = *m.names.get(p).ok_or(io::ErrorKind::NotFound)?;
        m.files
            .get_mut(&id)
            .unwrap()
            .0
            .resize(usize::try_from(length).unwrap(), 0);
        Ok(())
    }
    fn sync(&mut self, p: &Path) -> io::Result<()> {
        self.operation("sync", p)?;
        let mut m = self.0.lock().unwrap();
        let id = *m.names.get(p).ok_or(io::ErrorKind::NotFound)?;
        let (b, d) = m.files.get_mut(&id).unwrap();
        *d = b.clone();
        Ok(())
    }
    fn sync_directory(&mut self, p: &Path) -> io::Result<()> {
        self.operation("dir_sync", p)?;
        let mut m = self.0.lock().unwrap();
        m.persist_directory_move(p);
        let old = m
            .directory_move
            .as_ref()
            .map(|(old, new)| rebase(p, new, old));
        let durable = old.as_deref().unwrap_or(p);
        m.durable_directories
            .retain(|n| n.parent() != Some(durable));
        let dirs: Vec<_> = m
            .directories
            .iter()
            .filter(|n| n.parent() == Some(p))
            .map(|n| rebase(n, p, durable))
            .collect();
        m.durable_directories.extend(dirs);
        m.durable_names.retain(|n, _| n.parent() != Some(durable));
        let children: Vec<_> = m
            .names
            .iter()
            .filter(|(n, _)| n.parent() == Some(p))
            .map(|(n, id)| (rebase(n, p, durable), *id))
            .collect();
        m.durable_names.extend(children);
        Ok(())
    }
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        self.operation("rename", from)?;
        let mut m = self.0.lock().unwrap();
        if m.directories.contains(from) {
            assert_eq!(from.parent(), to.parent());
            assert!(m.directory_move.is_none(), "one unsynced directory move");
            if m.directories.contains(to) || m.names.contains_key(to) {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            m.directories = std::mem::take(&mut m.directories)
                .into_iter()
                .map(|p| rebase(&p, from, to))
                .collect();
            m.names = std::mem::take(&mut m.names)
                .into_iter()
                .map(|(p, id)| (rebase(&p, from, to), id))
                .collect();
            m.directory_move = Some((from.to_owned(), to.to_owned()));
            return Ok(());
        }
        let id = m.names.remove(from).ok_or(io::ErrorKind::NotFound)?;
        m.names.insert(to.into(), id);
        Ok(())
    }
    fn remove(&mut self, p: &Path) -> io::Result<()> {
        self.operation("remove", p)?;
        self.0
            .lock()
            .unwrap()
            .names
            .remove(p)
            .ok_or(io::ErrorKind::NotFound)?;
        Ok(())
    }
}

struct Scratch(PathBuf);
impl Scratch {
    #[expect(
        clippy::disallowed_methods,
        reason = "create and chmod only an exclusively claimed test-owned scratch directory"
    )]
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let current = std::env::current_dir().unwrap();
        let workspace = current
            .ancestors()
            .find(|path| path.join("Cargo.lock").is_file() && path.join("crates").is_dir())
            .unwrap_or_else(|| panic!("workspace not found from {}", current.display()));
        let parent = workspace.join("target").canonicalize().unwrap();
        loop {
            let path = parent.join(format!(
                "overlay-test-{}",
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    return Self(path);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("scratch creation: {e}"),
            }
        }
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
struct Fixed;
impl granary_core::secure_random::SecureRandom for Fixed {
    fn fill(
        &mut self,
        b: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        b.fill(17);
        Ok(())
    }
}
#[derive(Default)]
struct Source(BTreeMap<GrainId, Vec<u8>>);
impl ContentSource for Source {
    fn read_verified(&mut self, c: GrainId, o: u64, n: usize) -> Result<Vec<u8>, OverlayError> {
        self.0
            .get(&c)
            .and_then(|b| b.get(usize::try_from(o).unwrap()..usize::try_from(o).unwrap() + n))
            .map(<[u8]>::to_vec)
            .ok_or(OverlayError::Refused("source range unavailable"))
    }
}
fn grain(b: u8) -> GrainId {
    GrainId::of(&[b])
}
fn name(s: &str) -> Name {
    Name::new(s.as_bytes().to_vec()).unwrap()
}
fn at(s: &str) -> codec::Location {
    codec::Location {
        parent: codec::Parent::new(vec![]).unwrap(),
        name: name(s),
    }
}
#[expect(
    clippy::disallowed_methods,
    reason = "read metadata only for the test-owned scratch root"
)]
fn config(root: &Path) -> OverlayConfig {
    OverlayConfig {
        scope: Scope {
            authority_base: b"https://fixture.invalid".to_vec(),
            pins: vec![],
            credential_context: b"test".to_vec(),
        },
        volume: VolumeName::new("v".into()).unwrap(),
        euid: std::fs::metadata(root).unwrap().uid(),
        cap: 1_048_576,
        ownership_completion_reserve: 2048,
        instance: [34; 16],
    }
}
fn header() -> JournalHeader {
    JournalHeader {
        writer: [17; 16],
        base_root: grain(1),
        base_seq: 1,
        next_stage_id: 1,
        receipt_generation: 0,
    }
}
pub(crate) fn submission(
    scope: granary_core::retained_submission::Scope,
    writer: [u8; 16],
    bytes: Vec<u8>,
) -> granary_core::retained_submission::Submission {
    use granary_core::retained_submission::*;
    let doc = granary_core::root::decode_root(&bytes).unwrap();
    let request = RequestIdentity {
        epoch: [3; 16],
        operation: [4; 16],
    };
    Submission {
        generation: 1,
        publication_id: [8; 16],
        scope,
        volume: doc.volume,
        frozen: FrozenIntent {
            writer_identity: writer,
            min_prefix_bits: 0,
            initial_root: bytes.clone(),
        },
        current: Some(request),
        candidates: vec![Candidate {
            number: 1,
            role: Role::Active,
            request,
            seq: doc.seq,
            id: GrainId::of(&bytes),
            root: bytes,
            evidence: Evidence::default(),
        }],
        phase: Phase::Ready,
        last_response: None,
        unavailable_exemptions: 0,
    }
}
struct Fixture {
    overlay: OverlayStore<SimIo>,
    store: Store,
    io: SimIo,
    owner: OwnershipStatus,
    source: Source,
    _scratch: Scratch,
}
impl Fixture {
    fn new() -> Self {
        Self::with_base(vec![], Source::default())
    }
    fn with_base(base: Vec<OverlayEntry>, source: Source) -> Self {
        Self::with_base_capped(base, source, 1_048_576)
    }
    fn with_base_capped(base: Vec<OverlayEntry>, mut source: Source, cap: u64) -> Self {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let mut c = config(&scratch.0);
        c.cap = cap;
        let mut io = SimIo::default();
        let writer = OverlayStore::establish_writer(
            &mut store,
            &c,
            &mut io,
            &mut Fixed,
            &FaultControl::default(),
        )
        .unwrap();
        let area = scratch
            .0
            .join("overlay")
            .join(c.scope.digest().unwrap())
            .join("v");
        io.create(&area.join("ownership")).unwrap();
        io.write_at(&area.join("ownership"), 0, b"external carrier")
            .unwrap();
        io.sync(&area.join("ownership")).unwrap();
        io.sync_directory(&area).unwrap();
        let owner = OwnershipStatus::Durable(OwnershipPermission {
            scope: c.scope.digest().unwrap(),
            volume: c.volume.clone(),
            writer: writer.writer,
            high_water: 0,
        });
        let overlay = OverlayStore::open(
            &mut store,
            c,
            header(),
            base,
            &owner,
            &mut source,
            io.clone(),
            FaultControl::default(),
        )
        .unwrap();
        let mut f = Self {
            overlay,
            store,
            io,
            owner,
            source,
            _scratch: scratch,
        };
        f.overlay.raise_ceiling(&mut f.store, 100).unwrap();
        f
    }
    fn create(&mut self) -> u64 {
        self.overlay
            .create_file(&mut self.store, &self.owner, at("f"), false)
            .unwrap()
    }
    fn write(&mut self, id: u64, b: &[u8]) {
        self.overlay
            .write(&mut self.store, &self.owner, id, 0, b)
            .unwrap();
    }
    fn reopen(&mut self) -> Result<(), OverlayError> {
        self.reopen_with_faults(FaultControl::default())
    }
    fn reopen_with_faults(&mut self, faults: FaultControl) -> Result<(), OverlayError> {
        let bytes = self.io.bytes(&self.overlay.journal_path());
        let h = codec::scan_journal(&bytes)
            .map_err(|_| OverlayError::Refused("fixture journal scan"))?
            .header;
        self.overlay = OverlayStore::open(
            &mut self.store,
            self.overlay.config.clone(),
            h,
            self.overlay.base.clone(),
            &self.owner,
            &mut self.source,
            self.io.clone(),
            faults,
        )?;
        Ok(())
    }
    fn persistence_since(&self, cursor: usize) -> Vec<(String, PathBuf)> {
        self.io.0.lock().unwrap().trace[cursor..]
            .iter()
            .filter(|(op, _)| !matches!(op.as_str(), "entries" | "length" | "read" | "unmerged"))
            .cloned()
            .collect()
    }
    fn open_barriers(&self) -> [(String, PathBuf); 3] {
        [
            ("dir_sync".into(), self.overlay.area.clone()),
            ("dir_sync".into(), self.overlay.area.join("staging")),
            ("sync".into(), self.overlay.journal_path()),
        ]
    }
    fn sync(&mut self, id: u64, g: u64) -> CaptureToken {
        self.sync_with_content(id, g, |source, token| {
            let bytes = token.chunks.concat();
            let content = GrainId::of(&bytes);
            source.0.insert(content, bytes);
            content
        })
    }
    fn sync_with_content(
        &mut self,
        id: u64,
        g: u64,
        content: impl FnOnce(&mut Source, &CaptureToken) -> GrainId,
    ) -> CaptureToken {
        let token = self
            .overlay
            .capture(&mut self.store, &self.owner, id)
            .unwrap();
        self.overlay
            .flush_boundary(&mut self.store, &self.owner, &token)
            .unwrap();
        let content = content(&mut self.source, &token);
        self.overlay
            .record_file_synced(
                &mut self.store,
                &self.owner,
                &RegisteredCapture {
                    capture: token.clone(),
                    writer: [17; 16],
                    generation: g,
                    prepared_root: grain(2),
                    content,
                },
            )
            .unwrap();
        token
    }
    fn landing(&mut self, proof: LandedProof) -> LandedProof {
        self.overlay
            .record_landed(&mut self.store, &self.owner, &proof)
            .unwrap();
        self.refresh(&proof);
        proof
    }
    fn refresh(&mut self, proof: &LandedProof) {
        self.overlay
            .record_intent_registered(
                &mut self.store,
                &self.owner,
                20,
                proof.landed_root,
                codec::IntentCause::LandedRefresh,
            )
            .unwrap();
    }
    /// The journal and every stage file, byte for byte.
    fn journal_and_stages(&mut self) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        let staging = self.overlay.area.join("staging");
        let mut names = self.io.entries(&staging).unwrap();
        names.sort();
        let stages = names
            .into_iter()
            .map(|name| {
                let bytes = self.io.bytes(&staging.join(&name));
                (name, bytes)
            })
            .collect();
        (self.io.bytes(&self.overlay.journal_path()), stages)
    }
    /// The sealed boundary and the proof of what would land on it, with no
    /// landing or refresh recorded yet.
    fn boundary_proof(&mut self) -> LandedProof {
        let capture = self
            .overlay
            .capture_boundary(&mut self.store, &self.owner)
            .unwrap();
        let boundary = self
            .overlay
            .record_boundary(&mut self.store, &self.owner, capture, grain(3), [7; 16])
            .unwrap();
        let nodes: Vec<_> = self.overlay.namespace.entries.values().cloned().collect();
        let entries: Vec<_> = nodes
            .into_iter()
            .map(|mut e| {
                if let Some(id) = e.stage_id {
                    let stage = self.io.bytes(&self.overlay.stage_path(id));
                    let bytes = stage.get(160..).unwrap().to_vec();
                    assert_eq!(bytes.len(), usize::try_from(e.size).unwrap());
                    let c = GrainId::of(&bytes);
                    self.source.0.insert(c, bytes);
                    e.kind = OverlayKind::File { content: Some(c) };
                }
                e.stage_id = None;
                e
            })
            .collect();
        LandedProof {
            boundary_seq: boundary,
            landed_root: grain(3),
            landed_seq: 2,
            captured_entries: entries.clone(),
            entries,
        }
    }
}

#[test]
fn capture_shrink_floor_and_exact_release() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, &[8; 100]);
    let first = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    let second = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    let before = f.io.bytes(&f.overlay.stage_path(id));
    assert!(matches!(
        f.overlay.truncate(&mut f.store, &f.owner, id, 0),
        Err(OverlayError::PendingShrink)
    ));
    assert_eq!(
        (
            f.io.bytes(&f.overlay.stage_path(id)),
            f.overlay.namespace.stages[&id].size
        ),
        (before, 100)
    );
    f.overlay
        .flush_boundary(&mut f.store, &f.owner, &first)
        .unwrap();
    let content = grain(8);
    f.source.0.insert(content, vec![8; 100]);
    f.overlay
        .record_file_synced(
            &mut f.store,
            &f.owner,
            &RegisteredCapture {
                capture: first.clone(),
                writer: [17; 16],
                generation: 1,
                prepared_root: grain(2),
                content,
            },
        )
        .unwrap();
    assert_eq!(
        (
            f.overlay.namespace.stages[&id].mark.unwrap().synced_size,
            f.overlay.summary().captured_bytes
        ),
        (100, 100)
    );
    assert!(matches!(
        f.overlay.truncate(&mut f.store, &f.owner, id, 0),
        Err(OverlayError::PendingShrink)
    ));
    f.overlay.complete_failed_capture(&second).unwrap();
    assert!(
        f.overlay
            .complete_failed_capture(&second)
            .unwrap_err()
            .to_string()
            .contains("capture context")
    );
    f.overlay.truncate(&mut f.store, &f.owner, id, 0).unwrap();
    f.overlay.truncate(&mut f.store, &f.owner, id, 120).unwrap();
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 120)
            .unwrap(),
        vec![0; 120]
    );
    let mut wrong = first;
    wrong.instance = [0; 16];
    assert!(f.overlay.validate_capture(&wrong).is_err());
}

#[test]
fn orphan_boundary_blocks_but_post_boundary_orphan_rebinds() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: at("f"),
                kind: codec::DeleteKind::File { stage_id: Some(id) },
            },
        )
        .unwrap();
    f.write(id, b"orphan");
    let old = f.io.bytes(&f.overlay.journal_path());
    assert!(matches!(
        f.overlay.capture_boundary(&mut f.store, &f.owner),
        Err(OverlayError::PendingBoundary)
    ));
    assert_eq!(
        (
            f.io.bytes(&f.overlay.journal_path()),
            f.overlay.summary().orphan_bytes
        ),
        (old, 166)
    );
    f.overlay.close_stage(&mut f.store, id).unwrap();
    assert!(
        f.overlay
            .write(&mut f.store, &f.owner, id, 0, b"no")
            .is_err()
    );
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert!(
        !f.io
            .0
            .lock()
            .unwrap()
            .names
            .contains_key(&f.overlay.stage_path(id))
    );
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: at("f"),
                kind: codec::DeleteKind::File { stage_id: Some(id) },
            },
        )
        .unwrap();
    f.write(id, b"new");
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert_eq!(
        (
            f.overlay.entries(&mut f.store, &f.owner).unwrap().len(),
            f.overlay
                .read_stage(&mut f.store, &f.owner, id, 0, 3)
                .unwrap()
        ),
        (0, b"new".to_vec())
    );
}

#[test]
fn ownership_pending_preserves_all_bytes_and_charges_carriers() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"bytes");
    let tmp = f.overlay.area.join("ownership.tmp");
    f.io.create(&tmp).unwrap();
    f.io.write_at(&tmp, 0, b"temporary carrier").unwrap();
    let before = f.io.0.lock().unwrap().names.clone();
    let old = f.io.bytes(&f.overlay.journal_path());
    let mut pending = OverlayStore::open(
        &mut f.store,
        f.overlay.config.clone(),
        header(),
        vec![],
        &OwnershipStatus::PendingReconciliation,
        &mut f.source,
        f.io.clone(),
        FaultControl::default(),
    )
    .unwrap();
    assert_eq!(
        (pending.readiness(), f.io.0.lock().unwrap().names.clone()),
        (OverlayReadiness::PendingReconciliation, before)
    );
    assert!(
        pending
            .create_file(
                &mut f.store,
                &OwnershipStatus::PendingReconciliation,
                at("x"),
                false
            )
            .is_err()
    );
    assert_eq!(f.io.bytes(&f.overlay.journal_path()), old);
    assert!(
        pending.summary().charged_bytes
            >= f.io.bytes(&tmp).len() as u64
                + f.io.bytes(&pending.area.join("ownership")).len() as u64
    );
    f.io.remove(&pending.area.join("ownership")).unwrap();
    assert!(matches!(
        pending.recover(&mut f.store, &f.owner, &mut f.source),
        Err(OverlayError::PendingReconciliation)
    ));
}

#[test]
fn byte_exact_cap_and_future_rebind_reserve() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"cap");
    let len = f.overlay.journal.lock().unwrap().length;
    let charged = f.overlay.charge().unwrap();
    let reserve = f.overlay.reserve(len, 1).unwrap();
    assert_eq!(
        reserve,
        117 + (len - 117)
            + 4577
            + 1732
            + 122
            + f.overlay.writer.encode().unwrap().len() as u64
            + 2048
    );
    f.overlay.config.cap = charged + reserve;
    assert!(f.overlay.capacity(0, len, 1).is_ok());
    assert!(matches!(
        f.overlay.capacity(1, len, 1),
        Err(OverlayError::NoSpace)
    ));
    let before = f.io.bytes(&f.overlay.stage_path(id));
    assert!(matches!(
        f.overlay.write(&mut f.store, &f.owner, id, 3, b"x"),
        Err(OverlayError::NoSpace)
    ));
    assert_eq!(f.io.bytes(&f.overlay.stage_path(id)), before);
    let p = codec::Parent::new(vec![Name::new(vec![b'p'; 32]).unwrap(); 128]).unwrap();
    let n = Name::new(vec![b'n'; 255]).unwrap();
    let frame = codec::encode_record(
        &header(),
        1,
        &Record::StageBind {
            at: codec::Location { parent: p, name: n },
            cause: codec::BindCause::Rebind,
            stage_id: 1,
            staged_size: 0,
            base_content: grain(2),
        },
    )
    .unwrap();
    assert_eq!(frame.len(), 4577);
}

#[test]
fn every_sync_record_has_its_own_barrier_pair() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"sync");
    f.io.0.lock().unwrap().trace.clear();
    f.sync(id, 1);
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let trace = f.io.0.lock().unwrap().trace.clone();
    let j = f.overlay.journal_path();
    let journal: Vec<_> = trace
        .iter()
        .filter(|(_, p)| p == &j)
        .map(|(op, _)| op.as_str())
        .filter(|op| matches!(*op, "sync" | "write"))
        .collect();
    assert_eq!(
        journal,
        [
            "sync", "sync", "write", "sync", "sync", "write", "sync", "sync", "write", "sync",
            "sync", "write", "sync"
        ]
    );
    let stage = f.overlay.stage_path(id);
    let mark = trace
        .iter()
        .rposition(|(op, p)| op == "write" && p == &stage)
        .unwrap();
    assert_eq!(trace.get(mark + 1), Some(&("sync".into(), stage)));
    assert_eq!(proof.landed_seq, 2);
}

#[test]
fn rollback_restores_prefix_and_failed_rollback_poisons() {
    let mut f = Fixture::new();
    let old = f.io.bytes(&f.overlay.journal_path());
    let faults = f.overlay.fault_control();
    faults.arm(
        "overlay.journal.append",
        "partial",
        1,
        FaultAction::Short(9),
    );
    assert!(
        f.overlay
            .namespace_record(
                &mut f.store,
                &f.owner,
                Record::Create {
                    at: at("d"),
                    kind: codec::CreateKind::Dir
                }
            )
            .is_err()
    );
    assert_eq!(
        (
            f.io.bytes(&f.overlay.journal_path()),
            f.overlay.summary().records,
            faults.fired().len()
        ),
        (old, 0, 1)
    );
    assert_eq!(
        f.io.0
            .lock()
            .unwrap()
            .trace
            .iter()
            .rev()
            .take(2)
            .map(|(op, _)| op.as_str())
            .collect::<Vec<_>>(),
        ["sync", "resize"]
    );
    faults.arm("overlay.journal.append", "partial", 1, FaultAction::Fail);
    f.io.0.lock().unwrap().fail = Some("resize");
    assert!(
        f.overlay
            .namespace_record(
                &mut f.store,
                &f.owner,
                Record::Create {
                    at: at("d"),
                    kind: codec::CreateKind::Dir
                }
            )
            .is_err()
    );
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Poisoned);
    assert!(matches!(
        f.overlay.entries(&mut f.store, &f.owner),
        Err(OverlayError::Poisoned)
    ));
}

#[test]
fn short_extension_recovery_and_live_extent_corruption() {
    let mut f = Fixture::new();
    let id = f.create();
    f.overlay.truncate(&mut f.store, &f.owner, id, 100).unwrap();
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(
        (
            f.overlay.namespace.stages[&id].size,
            f.overlay
                .read_stage(&mut f.store, &f.owner, id, 0, 100)
                .unwrap()
        ),
        (100, vec![0; 100])
    );
    f.write(id, b"abc");
    f.sync(id, 1);
    f.io.mutate(&f.overlay.stage_path(id), |b| b[160] ^= 1);
    let old = f.io.bytes(&f.overlay.journal_path());
    assert!(
        f.reopen()
            .unwrap_err()
            .to_string()
            .contains("live extent mismatch")
    );
    assert_eq!(f.io.bytes(&f.overlay.journal_path()), old);
}

fn short_large_live_extent(mismatch: bool) -> (Fixture, u64, Vec<u8>) {
    use granary_core::manifest::{FileGrains, GrainRef, node::file_payload};

    let offset = 19;
    let length = 2 * BUFFER + 17;
    let bytes: Vec<_> = (0..offset + length + 23)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let object = GrainId::of(&bytes);
    let payload = file_payload(
        bytes.len() as u64,
        &FileGrains::Inline(vec![GrainRef {
            id: object,
            unpacked_len: u32::try_from(bytes.len()).unwrap(),
        }]),
    )
    .unwrap();
    let content = GrainId::of(&payload);
    let mut source = Source::default();
    source.0.insert(content, bytes.clone());
    let mut f = Fixture::with_base(
        vec![OverlayEntry {
            path: vec![name("f")],
            inode: 2,
            kind: OverlayKind::File {
                content: Some(content),
            },
            stage_id: None,
            size: bytes.len() as u64,
            exec: false,
        }],
        source,
    );
    f.store.put(&object, &bytes).unwrap();
    f.store.put(&content, &payload).unwrap();
    let id = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    let mut written = bytes[offset..offset + length].to_vec();
    if mismatch {
        *written.last_mut().unwrap() ^= 1;
    }
    f.overlay
        .write(&mut f.store, &f.owner, id, offset as u64, &written)
        .unwrap();
    assert!(matches!(
        f.overlay.namespace.stages[&id].extents.get(&(offset as u64)),
        Some(Record::WriteExtent { length: n, .. }) if *n == length as u64
    ));
    if mismatch {
        let through_seq = f.overlay.summary().records;
        f.overlay
            .append(&Record::CommitBoundary {
                candidate: grain(1),
                through_seq,
                publication_id: [1; 16],
            })
            .unwrap();
    }
    let path = f.overlay.stage_path(id);
    f.io.mutate(&path, |stage| stage.truncate(160 + offset + BUFFER));
    f.io.sync(&path).unwrap();
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.crash();
    (f, id, bytes)
}

fn reopen_with_local_content(f: &mut Fixture) -> Result<(), OverlayError> {
    let h = codec::scan_journal(&f.io.bytes(&f.overlay.journal_path()))
        .unwrap()
        .header;
    f.overlay = OverlayStore::open_shared(
        &f.store,
        f.overlay.config.clone(),
        h,
        f.overlay.base.clone(),
        &f.owner,
        &mut local_content::LocalContent::new(&f.store),
        f.io.clone(),
        FaultControl::default(),
        false,
    )?;
    Ok(())
}

#[test]
fn reopen_waits_for_checkpoint_grain_even_with_a_full_unchecked_body() {
    let mut f = Fixture::new();
    let id = f.create();
    let bytes = b"synced";
    let object = GrainId::of(bytes);
    let size = bytes.len() as u64;
    let payload = granary_core::manifest::node::file_payload(
        size,
        &granary_core::manifest::FileGrains::Inline(vec![granary_core::manifest::GrainRef {
            id: object,
            unpacked_len: u32::try_from(bytes.len()).unwrap(),
        }]),
    )
    .unwrap();
    let content = GrainId::of(&payload);
    f.store.put(&content, &payload).unwrap();
    f.write(id, bytes);
    f.sync_with_content(id, 1, |_, _| content);
    // Keep the truncate but lose its fragment check. All bytes still look present.
    f.overlay
        .append(&Record::Truncate {
            stage_id: id,
            new_size: 3,
        })
        .unwrap();
    let path = f.overlay.stage_path(id);
    f.io.resize(&path, 163).unwrap();
    f.io.sync(&path).unwrap();
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.crash();

    let reopen = reopen_with_local_content(&mut f);
    let retry = f.overlay.recover(&mut f.store, &f.owner, &mut Unavailable);
    assert_eq!(
        (
            reopen.as_ref().err().map(ToString::to_string).as_deref(),
            retry.as_ref().err().map(ToString::to_string).as_deref(),
            f.overlay.readiness(),
        ),
        (
            Some("overlay recovery awaits verified content"),
            Some("overlay recovery awaits verified content"),
            OverlayReadiness::PendingRecovery,
        ),
        "reopen: {reopen:?}, retry: {retry:?}"
    );

    f.store.put(&object, bytes).unwrap();
    reopen_with_local_content(&mut f).unwrap();
    let read = f
        .overlay
        .read_stage(&mut f.store, &f.owner, id, 0, 3)
        .unwrap();
    let eager = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    let lazy = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let mut captured = Vec::new();
    for part in f
        .overlay
        .captured_parts(&mut f.store, &f.owner, &lazy, &lazy.files()[0], 0)
        .unwrap()
    {
        let CapturedPart::Immutable {
            content,
            offset,
            length,
        } = part
        else {
            panic!("expected checkpoint part, got {part:?}");
        };
        captured.extend(
            local_content::LocalContent::new(&f.store)
                .read_verified(content, offset, length)
                .unwrap(),
        );
    }
    assert_eq!(
        (
            read.as_slice(),
            eager.chunks.concat().as_slice(),
            captured.as_slice()
        ),
        (&b"syn"[..], &b"syn"[..], &b"syn"[..])
    );
}

#[test]
fn replay_repairs_a_rebind_from_its_admitted_receipt_mirror() {
    let base = GrainId::of(b"before");
    let mut f = Fixture::with_base(
        vec![OverlayEntry {
            path: vec![name("f")],
            inode: 2,
            kind: OverlayKind::File {
                content: Some(base),
            },
            stage_id: None,
            size: 6,
            exec: false,
        }],
        Source(BTreeMap::from([(base, b"before".to_vec())])),
    );
    let id = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    f.write(id, b"synced");
    f.sync(id, 1);

    // A rebind has no dirty span. Its valid receipt mirror has no journal mark.
    let journal = f.overlay.journal_path();
    let header = JournalHeader {
        next_stage_id: id + 1,
        receipt_generation: 1,
        ..codec::scan_journal(&f.io.bytes(&journal)).unwrap().header
    };
    let mut rebound = header.encode().unwrap();
    rebound.extend(
        codec::encode_record(
            &header,
            1,
            &Record::StageBind {
                at: at("f"),
                cause: codec::BindCause::Rebind,
                stage_id: id,
                staged_size: 6,
                base_content: base,
            },
        )
        .unwrap(),
    );
    f.io.mutate(&journal, |bytes| *bytes = rebound);
    f.reopen().unwrap();
    let seal = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let seen = f
        .overlay
        .read_stage(&mut f.store, &f.owner, id, 0, 6)
        .unwrap();
    let captured = snapshot::materialize(&mut f, &seal, &seal.files()[0]).concat();
    assert_eq!(
        (
            String::from_utf8_lossy(&seen).as_ref(),
            String::from_utf8_lossy(&captured).as_ref()
        ),
        ("synced", "synced")
    );
}

#[test]
fn short_large_live_extent_recovers_from_local_anchor() {
    let (mut f, id, bytes) = short_large_live_extent(false);
    reopen_with_local_content(&mut f).unwrap();
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Ready);
    assert_eq!(f.io.bytes(&f.overlay.stage_path(id))[160..], bytes);
    let mut read = Vec::new();
    while read.len() < bytes.len() {
        let part = f
            .overlay
            .read_stage(&mut f.store, &f.owner, id, read.len() as u64, BUFFER)
            .unwrap();
        assert!(!part.is_empty());
        read.extend_from_slice(&part);
    }
    assert!(
        read == bytes,
        "recovered stage reads differ from the anchor"
    );
}

#[test]
fn short_large_live_extent_local_anchor_mismatch_refuses_before_repair() {
    let (mut f, id, _) = short_large_live_extent(true);
    let journal = f.io.bytes(&f.overlay.journal_path());
    let stage = f.io.bytes(&f.overlay.stage_path(id));
    let error = reopen_with_local_content(&mut f).unwrap_err();
    assert!(
        matches!(error, OverlayError::Refused("refetched extent mismatch")),
        "expected refetched extent mismatch, got {error:?}"
    );
    assert_eq!(f.io.bytes(&f.overlay.journal_path()), journal);
    assert_eq!(f.io.bytes(&f.overlay.stage_path(id)), stage);
}

#[test]
fn global_evidence_validation_precedes_every_sweep() {
    let mut f = Fixture::new();
    let a = f.overlay.stage_path(30);
    let b = f.overlay.stage_path(31);
    for (id, p) in [(30, &a), (31, &b)] {
        f.io.create(p).unwrap();
        f.io.write_at(
            p,
            0,
            &StagingHeader {
                writer: [17; 16],
                stage_id: id,
                mark: if id == 31 {
                    MarkState::Present(SyncedMark {
                        synced_size: 0,
                        content: grain(2),
                        generation: 1,
                    })
                } else {
                    MarkState::Absent
                },
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
    }
    assert!(
        f.reopen()
            .unwrap_err()
            .to_string()
            .contains("unnamed synced staging evidence")
    );
    assert!(f.io.length(&a).unwrap().is_some());
    f.io.remove(&b).unwrap();
    f.reopen().unwrap();
    assert_eq!(
        (f.io.length(&a).unwrap(), f.overlay.summary().swept_files),
        (None, 1)
    );
}

/// A capture's flush syncs the journal after its stage's `StageBind`, so a
/// synced mark is always named by a durable record: a crash right after the
/// mark's own sync, dropping every byte not synced, reopens with the stage
/// named and its header's mark standing, and nothing refused. A capture never
/// flushed cannot reach the mark: its `FileSynced` refuses first, and the
/// same crash leaves its unsynced stage to the sweep.
#[test]
fn the_flush_makes_the_stage_bind_durable_before_its_mark() {
    let mut outcomes = Vec::new();
    for flushed in [true, false] {
        let mut f = Fixture::new();
        let id = f.create();
        f.write(id, b"synced bytes");
        let token = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
        if flushed {
            f.overlay
                .flush_boundary(&mut f.store, &f.owner, &token)
                .unwrap();
        }
        let content = GrainId::of(&token.chunks.concat());
        let faults = f.overlay.fault_control();
        faults.arm("overlay.mark.sync", "after", 1, FaultAction::Crash);
        let synced = f.overlay.record_file_synced(
            &mut f.store,
            &f.owner,
            &RegisteredCapture {
                capture: token,
                writer: [17; 16],
                generation: 2,
                prepared_root: grain(2),
                content,
            },
        );
        f.io.crash();
        let reopened = f.reopen().map_err(|error| error.to_string());
        let path = f.overlay.stage_path(id);
        let header = f.io.length(&path).unwrap().map(|_| {
            StagingHeader::decode(&f.io.bytes(&path)[..160])
                .unwrap()
                .mark
        });
        let named = f.overlay.namespace.stages.get(&id).map(|stage| stage.mark);
        outcomes.push((
            flushed,
            synced.map_err(|error| error.to_string()),
            faults.fired().len(),
            reopened,
            header,
            named,
        ));
    }
    let mark = SyncedMark {
        synced_size: 12,
        content: GrainId::of(b"synced bytes"),
        generation: 2,
    };
    assert_eq!(
        outcomes,
        [
            (
                true,
                Err("overlay simulated crash".to_owned()),
                1,
                Ok(()),
                Some(MarkState::Present(mark)),
                Some(Some(mark)),
            ),
            (
                false,
                Err("overlay refused: capture was not flushed".to_owned()),
                0,
                Ok(()),
                None,
                None,
            ),
        ]
    );
}

#[test]
fn replacement_requires_refresh_and_includes_build_install_gap() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let plan = f
        .overlay
        .prepare_replacement(&mut f.store, &f.owner, proof)
        .unwrap();
    f.write(id, b"new");
    f.io.sync(&f.overlay.stage_path(id)).unwrap();
    f.overlay
        .install_replacement(&mut f.store, &f.owner, plan)
        .unwrap();
    assert_eq!(
        (
            f.overlay.namespace.stages.contains_key(&id),
            f.overlay.read_stage(&mut f.store, &f.owner, id, 0, 3).ok()
        ),
        (true, Some(b"new".to_vec()))
    );
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 3)
            .unwrap(),
        b"new"
    );
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let bytes = f.io.bytes(&f.overlay.journal_path());
    let mut cut = codec::JOURNAL_HEADER_LEN;
    codec::scan_journal_with(&bytes, |seq, record| {
        if !matches!(
            record,
            Record::IntentRegistered {
                cause: codec::IntentCause::LandedRefresh,
                ..
            }
        ) {
            cut += codec::encode_record(&header(), seq, record).unwrap().len();
        }
    })
    .unwrap();
    f.io.resize(&f.overlay.journal_path(), cut as u64).unwrap();
    let before = f.journal_and_stages();
    assert!(!before.1.is_empty(), "the stage must be on disk");
    let refused = f
        .overlay
        .prepare_replacement(&mut f.store, &f.owner, proof)
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("durable landing/refresh required"),
        "{refused}"
    );
    assert_eq!(f.journal_and_stages(), before, "refusal wrote to disk");
}

/// A journal cut short of the landing, or holding a refresh with no landing
/// under it, is refused before the journal or any stage is touched.
#[test]
fn replacement_refuses_a_cut_journal_and_leaves_journal_and_staging_untouched() {
    let mut cases = 0;
    for missing in ["landing", "landing under a refresh"] {
        let mut f = Fixture::new();
        let id = f.create();
        f.write(id, b"old");
        let proof = if missing == "landing" {
            let proof = f.boundary_proof();
            let proof = f.landing(proof);
            let bytes = f.io.bytes(&f.overlay.journal_path());
            let mut cut = codec::JOURNAL_HEADER_LEN;
            let mut reached = false;
            codec::scan_journal_with(&bytes, |seq, record| {
                reached |= matches!(record, Record::LandedCommit { .. });
                if !reached {
                    cut += codec::encode_record(&header(), seq, record).unwrap().len();
                }
            })
            .unwrap();
            f.io.resize(&f.overlay.journal_path(), cut as u64).unwrap();
            proof
        } else {
            let proof = f.boundary_proof();
            f.refresh(&proof);
            proof
        };
        let before = f.journal_and_stages();
        assert!(!before.1.is_empty(), "{missing}: the stage must be on disk");
        let refused = f
            .overlay
            .prepare_replacement(&mut f.store, &f.owner, proof)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("durable landing/refresh required"),
            "{missing}: {refused}"
        );
        assert_eq!(
            f.journal_and_stages(),
            before,
            "{missing}: refusal wrote to disk"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "alter only owned fixture permissions and links to prove repeated custody refusal"
)]
fn disk_custody_rechecked_on_each_touch() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let c = config(&scratch.0);
    let mut disk = OverlayDisk::new(&scratch.0, c.euid);
    OverlayStore::establish_writer(
        &mut store,
        &c,
        &mut disk,
        &mut Fixed,
        &FaultControl::default(),
    )
    .unwrap();
    let area = scratch
        .0
        .join("overlay")
        .join(c.scope.digest().unwrap())
        .join("v");
    let path = area.join("writer");
    let before = std::fs::read(&path).unwrap();
    assert!(disk.read_at(&path, 0, 133).is_ok());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        disk.read_at(&path, 0, 133)
            .unwrap_err()
            .to_string()
            .contains("custody owner/mode refused")
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = area.join("alias");
    std::fs::hard_link(&path, &link).unwrap();
    assert!(disk.read_at(&path, 0, 133).is_err());
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(disk.read_at(&link, 0, 133).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn crash_and_failure_matrix_has_fired_seams_and_disarmed_controls() {
    let points = [
        ("overlay.stage.write", "before"),
        ("overlay.stage.write", "partial"),
        ("overlay.stage.write", "after"),
        ("overlay.journal.append", "before"),
        ("overlay.journal.append", "partial"),
        ("overlay.journal.append", "after"),
        ("overlay.journal.pre_sync", "before"),
        ("overlay.journal.pre_sync", "after"),
        ("overlay.journal.post_sync", "before"),
        ("overlay.journal.post_sync", "after"),
        ("overlay.mark.write", "before"),
        ("overlay.mark.write", "partial"),
        ("overlay.mark.write", "after"),
        ("overlay.mark.sync", "before"),
        ("overlay.mark.sync", "after"),
        ("overlay.stage.sync", "before"),
        ("overlay.stage.sync", "after"),
        ("overlay.stage.dir_sync", "before"),
        ("overlay.stage.dir_sync", "after"),
    ];
    let mut cases = 0;
    for (seam, phase) in points {
        for action in [FaultAction::Crash, FaultAction::Fail] {
            for armed in [true, false] {
                let mut f = Fixture::new();
                let id = f.create();
                f.write(id, b"old");
                f.sync(id, 1);
                let faults = f.overlay.fault_control();
                if armed {
                    faults.arm(seam, phase, 1, action);
                }
                let result = if seam == "overlay.stage.write" {
                    f.overlay
                        .write(&mut f.store, &f.owner, id, 0, b"new")
                        .map(|_| ())
                } else if seam.starts_with("overlay.journal") {
                    f.overlay
                        .record_intent_registered(
                            &mut f.store,
                            &f.owner,
                            2,
                            grain(2),
                            codec::IntentCause::DirectorySync,
                        )
                        .map(|_| ())
                } else {
                    let token = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
                    match f.overlay.flush_boundary(&mut f.store, &f.owner, &token) {
                        Err(e) => Err(e),
                        Ok(()) => f.overlay.record_file_synced(
                            &mut f.store,
                            &f.owner,
                            &RegisteredCapture {
                                capture: token,
                                writer: [17; 16],
                                generation: 2,
                                prepared_root: grain(2),
                                content: GrainId::of(b"old"),
                            },
                        ),
                    }
                };
                assert_eq!(
                    (result.is_err(), faults.fired().len()),
                    (armed, usize::from(armed)),
                    "{seam}/{phase}/{action:?}: {result:?}"
                );
                if !armed && seam == "overlay.stage.write" {
                    f.sync(id, 2);
                }
                f.io.crash();
                f.reopen().unwrap();
                assert_eq!(
                    f.overlay
                        .read_stage(&mut f.store, &f.owner, id, 0, 3)
                        .unwrap(),
                    if !armed && seam == "overlay.stage.write" {
                        b"new"
                    } else {
                        b"old"
                    },
                    "{seam}/{phase}/{action:?}"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 76);
}

#[test]
fn replacement_crash_matrix_keeps_old_or_complete_new_journal() {
    let points = [
        ("overlay.replace.build", "before"),
        ("overlay.replace.build", "partial"),
        ("overlay.replace.build", "after"),
        ("overlay.replace.quiesced", "before"),
        ("overlay.replace.sync", "before"),
        ("overlay.replace.sync", "after"),
        ("overlay.replace.rename", "before"),
        ("overlay.replace.rename", "after"),
        ("overlay.replace.dir_sync", "before"),
        ("overlay.replace.dir_sync", "after"),
        ("overlay.replace.switched", "after"),
        ("overlay.retire.mark_clear", "before"),
        ("overlay.retire.mark_clear", "after-sync"),
        ("overlay.retire.unlink", "before"),
        ("overlay.retire.unlink", "after-sync"),
    ];
    let mut cases = 0;
    for action in [FaultAction::Crash, FaultAction::Fail] {
        for (seam, phase) in points {
            for armed in [true, false] {
                let mut f = Fixture::new();
                let id = f.create();
                f.write(id, b"old");
                f.sync(id, 1);
                let proof = f.boundary_proof();
                let proof = f.landing(proof);
                let faults = f.overlay.fault_control();
                if armed {
                    faults.arm(seam, phase, 1, action);
                }
                let result = f
                    .overlay
                    .replace_landed(&mut f.store, &f.owner, proof.clone());
                assert_eq!(
                    (result.is_err(), faults.fired().len()),
                    (armed, usize::from(armed)),
                    "{seam}/{phase}: {result:?}"
                );
                f.io.crash();
                let bytes = f.io.bytes(&f.overlay.journal_path());
                let h = codec::scan_journal(&bytes).unwrap().header;
                let new = h.base_root == proof.landed_root;
                let base = if new { proof.entries.clone() } else { vec![] };
                let reopened = OverlayStore::open(
                    &mut f.store,
                    f.overlay.config.clone(),
                    h,
                    base,
                    &f.owner,
                    &mut f.source,
                    f.io.clone(),
                    FaultControl::default(),
                )
                .unwrap();
                assert_eq!(
                    reopened.readiness(),
                    if new {
                        OverlayReadiness::Ready
                    } else {
                        OverlayReadiness::PendingRecovery
                    },
                    "{seam}/{phase}"
                );
                if new {
                    assert!(!reopened.namespace.stages.contains_key(&id));
                } else {
                    assert!(reopened.namespace.stages.contains_key(&id));
                }
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 60);
}

#[test]
fn sweep_and_tail_cut_crash_matrix_restarts_idempotently() {
    let mut cases = 0;
    for action in [FaultAction::Crash, FaultAction::Fail] {
        for (seam, phases) in [
            (
                "overlay.sweep.remove",
                vec!["before", "after", "after-dir-sync"],
            ),
            (
                "overlay.tail.cut",
                vec!["before", "after-cut", "after-sync"],
            ),
        ] {
            for phase in phases {
                for armed in [true, false] {
                    let mut f = Fixture::new();
                    let id = f.create();
                    f.write(id, b"old");
                    f.sync(id, 1);
                    if seam == "overlay.sweep.remove" {
                        let p = f.overlay.stage_path(30);
                        f.io.create(&p).unwrap();
                        f.io.write_at(
                            &p,
                            0,
                            &StagingHeader {
                                writer: [17; 16],
                                stage_id: 30,
                                mark: MarkState::Absent,
                            }
                            .encode()
                            .unwrap(),
                        )
                        .unwrap();
                        f.io.sync(&p).unwrap();
                        f.io.sync_directory(&f.overlay.area.join("staging"))
                            .unwrap();
                    } else {
                        let path = f.overlay.journal_path();
                        let n = f.io.length(&path).unwrap().unwrap();
                        f.io.write_at(&path, n, &[0, 0]).unwrap();
                        f.io.sync(&path).unwrap();
                    }
                    let faults = f.overlay.fault_control();
                    if armed {
                        faults.arm(seam, phase, 1, action);
                    }
                    let result = f.overlay.recover(&mut f.store, &f.owner, &mut f.source);
                    assert_eq!(
                        (result.is_err(), faults.fired().len()),
                        (armed, usize::from(armed)),
                        "{seam}/{phase}: {result:?}"
                    );
                    f.io.crash();
                    f.reopen().unwrap();
                    assert_eq!(
                        f.overlay
                            .read_stage(&mut f.store, &f.owner, id, 0, 3)
                            .unwrap(),
                        b"old"
                    );
                    assert!(f.io.length(&f.overlay.stage_path(30)).unwrap().is_none());
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 24);
}

#[test]
fn copy_up_base_routing_and_extent_refresh_preserve_surviving_bytes() {
    let content = grain(9);
    let mut source = Source::default();
    source.0.insert(content, b"abcdef".to_vec());
    let base = vec![OverlayEntry {
        path: vec![name("f")],
        inode: 8,
        kind: OverlayKind::File {
            content: Some(content),
        },
        stage_id: None,
        size: 6,
        exec: true,
    }];
    let mut f = Fixture::with_base(base, source);
    assert_eq!(
        f.overlay
            .read_base(&mut f.store, &f.owner, &[name("f")], 1, 3, &mut f.source)
            .unwrap(),
        b"bcd"
    );
    let id = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, id, 0, b"ABCDEF")
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, id, 2, b"xy")
        .unwrap();
    assert_eq!(
        f.overlay.namespace.stages[&id]
            .extents
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [0, 2, 4]
    );
    f.sync(id, 1);
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 6)
            .unwrap(),
        b"ABxyEF"
    );
    f.io.mutate(&f.overlay.stage_path(id), |b| b[160] ^= 1);
    assert!(
        f.overlay
            .write(&mut f.store, &f.owner, id, 0, b"z")
            .unwrap_err()
            .to_string()
            .contains("live extent mismatch")
    );
}

#[test]
fn establishment_crash_matrix_never_promotes_temporary_state() {
    let mut cases = 0;
    for action in [FaultAction::Crash, FaultAction::Fail] {
        for seam in ["overlay.writer", "overlay.journal.create"] {
            for phase in [
                "build",
                "before",
                "partial",
                "after",
                "sync",
                "after_sync",
                "rename",
                "after_rename",
                "dir_sync",
                "after_dir_sync",
            ] {
                for armed in [true, false] {
                    let scratch = Scratch::new();
                    let mut store = Store::open(&scratch.0).unwrap();
                    let c = config(&scratch.0);
                    let mut io = SimIo::default();
                    let faults = FaultControl::default();
                    if seam == "overlay.writer" && armed {
                        faults.arm(seam, phase, 1, action);
                    }
                    let writer = OverlayStore::establish_writer(
                        &mut store, &c, &mut io, &mut Fixed, &faults,
                    );
                    if seam == "overlay.writer" {
                        assert_eq!(
                            (writer.is_err(), faults.fired().len()),
                            (armed, usize::from(armed)),
                            "{phase}: {writer:?}"
                        );
                        io.crash();
                    }
                    let writer = OverlayStore::establish_writer(
                        &mut store,
                        &c,
                        &mut io,
                        &mut Fixed,
                        &FaultControl::default(),
                    )
                    .unwrap();
                    let area = scratch
                        .0
                        .join("overlay")
                        .join(c.scope.digest().unwrap())
                        .join("v");
                    io.create(&area.join("ownership")).unwrap();
                    io.write_at(&area.join("ownership"), 0, b"external carrier")
                        .unwrap();
                    io.sync(&area.join("ownership")).unwrap();
                    io.sync_directory(&area).unwrap();
                    let owner = OwnershipStatus::Durable(OwnershipPermission {
                        scope: c.scope.digest().unwrap(),
                        volume: c.volume.clone(),
                        writer: writer.writer,
                        high_water: 0,
                    });
                    if seam == "overlay.journal.create" && armed {
                        faults.arm(seam, phase, 1, action);
                    }
                    let mut source = Source::default();
                    let result = OverlayStore::open(
                        &mut store,
                        c.clone(),
                        header(),
                        vec![],
                        &owner,
                        &mut source,
                        io.clone(),
                        faults.clone(),
                    );
                    if seam == "overlay.journal.create" {
                        assert_eq!(
                            (result.is_err(), faults.fired().len()),
                            (armed, usize::from(armed)),
                            "{phase}: {result:?}"
                        );
                        io.crash();
                    }
                    let ready = OverlayStore::open(
                        &mut store,
                        c,
                        header(),
                        vec![],
                        &owner,
                        &mut source,
                        io,
                        FaultControl::default(),
                    )
                    .unwrap();
                    assert_eq!(ready.readiness(), OverlayReadiness::Ready);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 80);
}

#[test]
fn stage_creation_shrink_and_rollback_crash_matrix() {
    let mut cases = 0;
    for action in [FaultAction::Crash, FaultAction::Fail] {
        for (seam, phases) in [
            ("overlay.stage.create", vec!["before", "partial", "after"]),
            ("overlay.stage.truncate", vec!["before", "after"]),
            (
                "overlay.append.rollback",
                vec!["before", "after-cut", "after-sync"],
            ),
        ] {
            for phase in phases {
                for armed in [true, false] {
                    let mut f = Fixture::new();
                    let id = f.create();
                    f.write(id, b"old");
                    f.sync(id, 1);
                    let faults = f.overlay.fault_control();
                    if armed {
                        faults.arm(seam, phase, 1, action);
                    }
                    let result = if seam == "overlay.stage.create" {
                        f.overlay
                            .create_file(&mut f.store, &f.owner, at("second"), false)
                            .map(|_| ())
                    } else if seam == "overlay.stage.truncate" {
                        f.overlay.truncate(&mut f.store, &f.owner, id, 1)
                    } else {
                        f.io.0.lock().unwrap().fail = Some("write");
                        f.overlay
                            .namespace_record(
                                &mut f.store,
                                &f.owner,
                                Record::Create {
                                    at: at("d"),
                                    kind: codec::CreateKind::Dir,
                                },
                            )
                            .map(|_| ())
                    };
                    assert_eq!(
                        (result.is_err(), faults.fired().len()),
                        (
                            armed || seam == "overlay.append.rollback",
                            usize::from(armed)
                        ),
                        "{seam}/{phase}: {result:?}"
                    );
                    f.io.crash();
                    f.reopen().unwrap();
                    assert_eq!(
                        f.overlay
                            .read_stage(&mut f.store, &f.owner, id, 0, 3)
                            .unwrap(),
                        b"old"
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 32);
}

#[test]
fn missing_synced_stage_refetches_but_bad_provider_refuses() {
    struct Missing;
    impl ContentSource for Missing {
        fn read_verified(&mut self, _: GrainId, _: u64, _: usize) -> Result<Vec<u8>, OverlayError> {
            Err(OverlayError::ContentUnavailable)
        }
    }
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"synced");
    f.sync(id, 1);
    let path = f.overlay.stage_path(id);
    f.io.remove(&path).unwrap();
    f.reopen().unwrap();
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 6)
            .unwrap(),
        b"synced"
    );
    f.io.remove(&path).unwrap();
    f.source.0.clear();
    let names = f.io.0.lock().unwrap().names.clone();
    assert!(
        f.reopen()
            .unwrap_err()
            .to_string()
            .contains("source range unavailable")
    );
    assert_eq!(f.io.0.lock().unwrap().names, names);
    let log = LogBytes::default();
    let dispatch = observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        log.clone(),
    );
    tracing::subscriber::with_default(dispatch, || {
        assert!(matches!(
            f.overlay.recover(&mut f.store, &f.owner, &mut Missing),
            Err(OverlayError::ContentUnavailable)
        ));
        assert_eq!(
            (f.overlay.readiness(), f.io.0.lock().unwrap().names == names),
            (OverlayReadiness::PendingRecovery, true)
        );
        assert!(f.overlay.entries(&mut f.store, &f.owner).is_err());
    });
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("\"outcome\":\"pending\""), "{text}");
    assert!(!text.contains("\"kind\":\"overlay_write\""), "{text}");
    assert!(!text.contains("\"event\":\"overlay.refused\""), "{text}");
    let content = f
        .overlay
        .namespace
        .stages
        .get(&id)
        .unwrap()
        .mark
        .unwrap()
        .content;
    f.source.0.insert(content, b"synced".to_vec());
    f.overlay
        .recover(&mut f.store, &f.owner, &mut f.source)
        .unwrap();
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 6)
            .unwrap(),
        b"synced"
    );
}

#[derive(Clone, Default)]
struct LogBytes(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for LogBytes {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBytes {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}
#[test]
fn loud_failure_and_fault_events_are_stable_and_path_free() {
    let log = LogBytes::default();
    let dispatch = observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        log.clone(),
    );
    tracing::subscriber::with_default(dispatch, || {
        let mut f = Fixture::new();
        let id = f.create();
        f.write(id, b"bad");
        f.sync(id, 1);
        let point = f.overlay.fault_control();
        point.arm("overlay.journal.append", "before", 1, FaultAction::Fail);
        assert!(
            f.overlay
                .namespace_record(
                    &mut f.store,
                    &f.owner,
                    Record::Create {
                        at: at("d"),
                        kind: codec::CreateKind::Dir
                    }
                )
                .is_err()
        );
        f.io.mutate(&f.overlay.stage_path(id), |b| b[160] ^= 1);
        assert_eq!(
            f.reopen().unwrap_err().to_string(),
            "overlay refused: live extent mismatch"
        );
    });
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    for event in [
        "overlay.recovery",
        "overlay.refused",
        "overlay.fault",
        "op.failed",
    ] {
        assert!(
            text.contains(&format!("\"event\":\"{event}\"")),
            "{event}: {text}"
        );
    }
    assert!(!text.contains("overlay-test-"));
    assert!(text.contains("\"point\":\"overlay.journal.append\""));
    assert!(text.contains("\"kind\":\"journal_append\""));
    let source_log = LogBytes::default();
    let dispatch = observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        source_log.clone(),
    );
    tracing::subscriber::with_default(dispatch, || {
        let mut source = Source::default();
        source.0.insert(grain(9), b"x".to_vec());
        assert_eq!(verified(&mut source, grain(9), 0, 1).unwrap(), b"x");
        assert!(source_log.0.lock().unwrap().is_empty());
        source.0.clear();
        assert!(verified(&mut source, grain(9), 0, 1).is_err());
    });
    let text = String::from_utf8(source_log.0.lock().unwrap().clone()).unwrap();
    assert!(
        !text.contains("\"event\":\"op.failed\""),
        "content helper duplicated the terminal operation event: {text}"
    );
}

#[test]
fn every_fired_fault_point_emits_its_event_in_every_production_phase() {
    let phases = [
        ("before", "before"),
        ("after", "after"),
        ("partial", "partial"),
        ("after-cut", "after_cut"),
        ("after-sync", "after_sync"),
        ("build", "build"),
        ("sync", "sync"),
        ("after_sync", "after_sync"),
        ("rename", "rename"),
        ("after_rename", "after_rename"),
        ("dir_sync", "dir_sync"),
        ("after_dir_sync", "after_dir_sync"),
    ];
    let mut cases = 0;
    for point in [
        "overlay.writer",
        "overlay.journal.create",
        "overlay.tail.cut",
    ] {
        for (seam, emitted) in phases {
            let log = LogBytes::default();
            let dispatch = observe::subscriber(
                observe::LogFormat::Json,
                tracing_subscriber::EnvFilter::new("warn"),
                log.clone(),
            );
            let faults = FaultControl::default();
            faults.arm(point, seam, 1, FaultAction::Fail);
            let action =
                tracing::subscriber::with_default(dispatch, || faults.point(point, seam, 3));
            assert_eq!(action, Some(FaultAction::Fail), "{point}/{seam} must fire");
            let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
            assert!(
                text.contains("\"event\":\"overlay.fault\"")
                    && text.contains(&format!("\"point\":\"{point}\""))
                    && text.contains(&format!("\"phase\":\"{emitted}\"")),
                "{point}/{seam} emitted nothing: {text}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 36);
}

#[test]
fn every_sync_fault_point_the_engine_fires_emits_through_the_facade() {
    let fired = [
        ("sync.capture", "after", "none"),
        ("sync.upload", "before", "bin"),
        ("sync.upload", "accepted", "bin"),
        ("sync.node_upload", "before", "manifest"),
        ("sync.node_upload", "accepted", "grain_list"),
        ("sync.node_upload", "before", "binmap"),
        ("sync.node_upload", "accepted", "sheaf"),
        ("sync.registration", "before_dispatch", "none"),
        ("sync.registration", "after_response", "none"),
        ("sync.reply", "before", "none"),
        ("sync.commit", "captured", "none"),
        ("sync.commit", "boundary_recorded", "none"),
        ("sync.commit", "before_rebase", "none"),
        ("sync.commit", "after_rebase", "none"),
        ("sync.commit", "before_replace", "none"),
        ("sync.commit", "landed_readback", "none"),
        ("sync.commit", "landed_refresh", "none"),
        ("sync.commit_wait", "before", "none"),
        ("sync.floor", "checked", "none"),
        ("fuse.sync.view", "observed", "none"),
        ("fuse.sync.view", "cleared", "none"),
        ("fuse.sync.rename_directory", "before", "directory"),
        ("fuse.sync.reply", "before", "none"),
        ("sync.unlisted", "unlisted", "unlisted"),
    ];
    for (point, phase, kind) in fired {
        let log = LogBytes::default();
        let dispatch = observe::subscriber(
            observe::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("warn"),
            log.clone(),
        );
        let faults = FaultControl::default();
        faults.arm(point, phase, 1, FaultAction::Fail);
        let action = tracing::subscriber::with_default(dispatch, || {
            if point == "fuse.sync.rename_directory" {
                faults.rename_directory_point(crate::RenameDirectoryFaultContext {
                    journal_cursor: 3,
                    directory_inode: None,
                })
            } else {
                faults.sync_point(point, phase, 3, None, kind)
            }
        });
        assert_eq!(action, Some(FaultAction::Fail), "{point}/{phase} must fire");
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        let (want_point, want_phase, want_kind) = if point == "sync.unlisted" {
            ("other", "other", "other")
        } else {
            (point, phase, kind)
        };
        assert!(
            text.contains("\"event\":\"sync.fault\"")
                && text.contains(&format!("\"point\":\"{want_point}\""))
                && text.contains(&format!("\"phase\":\"{want_phase}\""))
                && text.contains(&format!("\"object_kind\":\"{want_kind}\"")),
            "{point}/{phase}/{kind} emitted nothing: {text}"
        );
    }
}

#[test]
fn reopened_in_doubt_commit_can_land_refresh_and_replace_before_service() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.sync(id, 1);
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    let boundary = f
        .overlay
        .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
        .unwrap();
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(f.overlay.readiness(), OverlayReadiness::PendingRecovery);
    assert!(f.overlay.entries(&mut f.store, &f.owner).is_err());
    assert_eq!(
        f.overlay.recovery_commits(&mut f.store, &f.owner).unwrap(),
        [RecoveryCommit::Boundary {
            index: boundary,
            candidate: grain(3),
            through_seq: boundary - 1,
            publication_id: [7; 16],
            selection: BoundarySelection::Tree,
        }]
    );
    let entries = vec![OverlayEntry {
        path: vec![name("f")],
        inode: 1,
        kind: OverlayKind::File {
            content: Some(GrainId::of(b"old")),
        },
        stage_id: None,
        size: 3,
        exec: false,
    }];
    let proof = LandedProof {
        boundary_seq: boundary,
        landed_root: grain(3),
        landed_seq: 2,
        captured_entries: entries.clone(),
        entries,
    };
    f.overlay
        .record_landed(&mut f.store, &f.owner, &proof)
        .unwrap();
    assert!(f.overlay.entries(&mut f.store, &f.owner).is_err());
    f.overlay
        .record_intent_registered(
            &mut f.store,
            &f.owner,
            20,
            grain(3),
            codec::IntentCause::LandedRefresh,
        )
        .unwrap();
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert_eq!(f.overlay.entries(&mut f.store, &f.owner).unwrap().len(), 1);
}

#[test]
fn writer_namespace_input_budget_and_receipt_guards_refuse_before_mutation() {
    let mut f = Fixture::new();
    let old = f.io.bytes(&f.overlay.journal_path());
    assert!(
        f.overlay
            .namespace_record(
                &mut f.store,
                &f.owner,
                Record::Create {
                    at: at("unsafe"),
                    kind: codec::CreateKind::File {
                        exec: false,
                        stage_id: 1
                    }
                }
            )
            .unwrap_err()
            .to_string()
            .contains("namespace record kind")
    );
    assert_eq!(f.io.bytes(&f.overlay.journal_path()), old);
    assert!(
        f.overlay
            .raise_ceiling(&mut f.store, 99)
            .unwrap_err()
            .to_string()
            .contains("ceiling rollback/exhaustion")
    );
    let id = f.create();
    f.write(id, b"data");
    let capture = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    let mut receipt = RegisteredCapture {
        capture: capture.clone(),
        writer: [17; 16],
        generation: 1,
        prepared_root: grain(2),
        content: GrainId::of(b"data"),
    };
    assert!(
        f.overlay
            .record_file_synced(&mut f.store, &f.owner, &receipt)
            .unwrap_err()
            .to_string()
            .contains("capture was not flushed")
    );
    f.overlay
        .flush_boundary(&mut f.store, &f.owner, &capture)
        .unwrap();
    receipt.writer = [0; 16];
    assert!(
        f.overlay
            .record_file_synced(&mut f.store, &f.owner, &receipt)
            .unwrap_err()
            .to_string()
            .contains("receipt writer/ceiling")
    );
    receipt.writer = [17; 16];
    receipt.generation = 101;
    assert!(
        f.overlay
            .record_file_synced(&mut f.store, &f.owner, &receipt)
            .is_err()
    );
    receipt.generation = 1;
    f.overlay
        .record_file_synced(&mut f.store, &f.owner, &receipt)
        .unwrap();
    let path = f.overlay.journal_path();
    let actual = f.io.bytes(&path);
    f.io.resize(&path, codec::JOURNAL_MAX as u64 + 1).unwrap();
    assert!(
        f.overlay
            .journal_bytes()
            .unwrap_err()
            .to_string()
            .contains("input budget")
    );
    f.io.mutate(&path, |b| *b = actual);
    let header = f.overlay.header(id).unwrap();
    let mut bad = header;
    bad.writer = [0; 16];
    f.io.write_at(&f.overlay.stage_path(id), 0, &bad.encode().unwrap())
        .unwrap();
    assert!(
        f.overlay
            .header(id)
            .unwrap_err()
            .to_string()
            .contains("staging binding")
    );
}

#[test]
fn commit_cursor_is_captured_before_preparation_and_preserves_later_writes() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.sync(id, 1);
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    let through = capture.through_seq();
    let mut entries = capture.entries().to_vec();
    for e in &mut entries {
        e.stage_id = None;
        e.kind = OverlayKind::File {
            content: Some(GrainId::of(b"old")),
        };
    }
    f.write(id, b"new");
    f.io.sync(&f.overlay.stage_path(id)).unwrap();
    let b = f
        .overlay
        .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
        .unwrap();
    let mut observed = None;
    codec::scan_journal_with(&f.io.bytes(&f.overlay.journal_path()), |seq, record| {
        if seq == b
            && let Record::CommitBoundary { through_seq, .. } = record
        {
            observed = Some(*through_seq);
        }
    })
    .unwrap();
    assert_eq!(observed, Some(through));
    let proof = LandedProof {
        boundary_seq: b,
        landed_root: grain(3),
        landed_seq: 2,
        captured_entries: entries.clone(),
        entries,
    };
    f.overlay
        .record_landed(&mut f.store, &f.owner, &proof)
        .unwrap();
    f.overlay
        .record_intent_registered(
            &mut f.store,
            &f.owner,
            20,
            grain(3),
            codec::IntentCause::LandedRefresh,
        )
        .unwrap();
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 3)
            .unwrap(),
        b"new"
    );
}

#[test]
fn unsafe_pre_boundary_orphan_replacement_refuses_without_truncation() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: at("f"),
                kind: codec::DeleteKind::File { stage_id: Some(id) },
            },
        )
        .unwrap();
    let through_seq = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
    let boundary = f
        .overlay
        .append(&Record::CommitBoundary {
            candidate: grain(3),
            through_seq,
            publication_id: [7; 16],
        })
        .unwrap();
    f.write(id, b"new");
    let proof = LandedProof {
        boundary_seq: boundary,
        landed_root: grain(3),
        landed_seq: 2,
        captured_entries: vec![],
        entries: vec![],
    };
    f.overlay
        .record_landed(&mut f.store, &f.owner, &proof)
        .unwrap();
    f.overlay
        .record_intent_registered(
            &mut f.store,
            &f.owner,
            20,
            grain(3),
            codec::IntentCause::LandedRefresh,
        )
        .unwrap();
    let old = f.io.bytes(&f.overlay.journal_path());
    assert!(
        f.overlay
            .prepare_replacement(&mut f.store, &f.owner, proof)
            .unwrap_err()
            .to_string()
            .contains("retained orphan has no landed Location")
    );
    assert_eq!(
        (
            f.io.bytes(&f.overlay.journal_path()),
            f.io.length(&f.overlay.stage_path(id)).unwrap()
        ),
        (old, Some(163))
    );
}

#[test]
fn namespace_bind_and_mark_conflicts_refuse_with_valid_counterparts() {
    let content = grain(9);
    let base = vec![OverlayEntry {
        path: vec![name("f")],
        inode: 1,
        kind: OverlayKind::File {
            content: Some(content),
        },
        stage_id: None,
        size: 0,
        exec: false,
    }];
    let mut ns = Namespace::base(&base).unwrap();
    let good = Record::StageBind {
        at: at("f"),
        cause: codec::BindCause::CopyUp,
        stage_id: 1,
        staged_size: 0,
        base_content: content,
    };
    ns.fold(&good).unwrap();
    let mut bad = good;
    if let Record::StageBind { base_content, .. } = &mut bad {
        *base_content = grain(8);
    }
    assert!(
        Namespace::base(&base)
            .unwrap()
            .fold(&bad)
            .unwrap_err()
            .to_string()
            .contains("bind base content")
    );
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.sync(id, 1);
    f.write(id, b"new");
    let capture = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    f.overlay
        .flush_boundary(&mut f.store, &f.owner, &capture)
        .unwrap();
    let receipt = RegisteredCapture {
        capture: capture.clone(),
        writer: [17; 16],
        generation: 1,
        prepared_root: grain(2),
        content: GrainId::of(b"new"),
    };
    let before = f.io.bytes(&f.overlay.stage_path(id));
    assert!(
        f.overlay
            .record_file_synced(&mut f.store, &f.owner, &receipt)
            .unwrap_err()
            .to_string()
            .contains("mark generation conflict")
    );
    assert_eq!(f.io.bytes(&f.overlay.stage_path(id)), before);
    let mut receipt = receipt;
    receipt.generation = 2;
    f.overlay
        .record_file_synced(&mut f.store, &f.owner, &receipt)
        .unwrap();
}

#[test]
fn admitted_commit_completes_at_cap_without_spending_future_write_reserve() {
    let mut empty = Fixture::new();
    let capture = empty
        .overlay
        .capture_boundary(&mut empty.store, &empty.owner)
        .unwrap();
    let boundary = empty
        .overlay
        .record_boundary(&mut empty.store, &empty.owner, capture, grain(3), [7; 16])
        .unwrap();
    let proof = LandedProof {
        boundary_seq: boundary,
        landed_root: grain(3),
        landed_seq: 2,
        captured_entries: vec![],
        entries: vec![],
    };
    let len = empty.overlay.journal.lock().unwrap().length;
    empty.overlay.config.cap =
        empty.overlay.charge().unwrap() + empty.overlay.reserve(len, 0).unwrap();
    empty
        .overlay
        .record_landed(&mut empty.store, &empty.owner, &proof)
        .unwrap();
    empty
        .overlay
        .record_intent_registered(
            &mut empty.store,
            &empty.owner,
            20,
            grain(3),
            codec::IntentCause::LandedRefresh,
        )
        .unwrap();
    empty
        .overlay
        .replace_landed(&mut empty.store, &empty.owner, proof)
        .unwrap();
    assert_eq!(empty.overlay.readiness(), OverlayReadiness::Ready);
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.sync(id, 1);
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    let entries = vec![OverlayEntry {
        path: vec![name("f")],
        inode: 1,
        kind: OverlayKind::File {
            content: Some(GrainId::of(b"old")),
        },
        stage_id: None,
        size: 3,
        exec: false,
    }];
    let boundary = f
        .overlay
        .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
        .unwrap();
    let proof = LandedProof {
        boundary_seq: boundary,
        landed_root: grain(3),
        landed_seq: 2,
        captured_entries: entries.clone(),
        entries,
    };
    let len = f.overlay.journal.lock().unwrap().length;
    f.overlay.config.cap = f.overlay.charge().unwrap() + f.overlay.reserve(len, 1).unwrap();
    f.overlay
        .record_landed(&mut f.store, &f.owner, &proof)
        .unwrap();
    f.overlay
        .record_intent_registered(
            &mut f.store,
            &f.owner,
            20,
            grain(3),
            codec::IntentCause::LandedRefresh,
        )
        .unwrap();
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Ready);
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "create and alter only owned fixture files and directories to prove descriptor custody refusal"
)]
fn descriptor_owner_link_directory_mode_and_acl_guards() {
    let scratch = Scratch::new();
    let uid = std::fs::metadata(&scratch.0).unwrap().uid();
    let mut disk = OverlayDisk::new(&scratch.0, uid);
    let path = scratch.0.join("leaf");
    std::fs::write(&path, b"fixture").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    assert!(disk.protected(&file, &path, false).is_ok());
    let wrong = OverlayDisk::new(&scratch.0, uid + 1);
    assert!(
        wrong
            .protected(&file, &path, false)
            .unwrap_err()
            .to_string()
            .contains("custody owner/mode refused")
    );
    let alias = scratch.0.join("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(
        disk.protected(&file, &path, false)
            .unwrap_err()
            .to_string()
            .contains("type/link refused")
    );
    std::fs::remove_file(alias).unwrap();
    let dir = scratch.0.join("child");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(disk.directory(&dir).is_ok());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        disk.directory(&dir)
            .unwrap_err()
            .to_string()
            .contains("custody owner/mode refused")
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    #[cfg(target_vendor = "apple")]
    {
        let result = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(result.status.success(), "ACL fixture: {result:?}");
        assert!(
            disk.protected(&file, &path, false)
                .unwrap_err()
                .to_string()
                .contains("ACL")
        );
        let result = std::process::Command::new("chmod")
            .arg("-N")
            .arg(&path)
            .output()
            .unwrap();
        assert!(result.status.success(), "ACL cleanup: {result:?}");
        assert!(disk.protected(&file, &path, false).is_ok());
    }
}

#[test]
fn ownership_context_and_foreign_entries_refuse_without_repair() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    let old = f.io.bytes(&f.overlay.journal_path());
    let names = f.io.0.lock().unwrap().names.clone();
    let mut cases = 0;
    for field in 0..4 {
        let mut wrong = f.owner.clone();
        if let OwnershipStatus::Durable(OwnershipPermission {
            scope,
            volume,
            writer,
            high_water,
        }) = &mut wrong
        {
            match field {
                0 => scope.push('x'),
                1 => *volume = VolumeName::new("wrong".into()).unwrap(),
                2 => *writer = [0; 16],
                _ => *high_water = 101,
            }
        }
        let component = OverlayStore::open(
            &mut f.store,
            f.overlay.config.clone(),
            header(),
            vec![],
            &wrong,
            &mut f.source,
            f.io.clone(),
            FaultControl::default(),
        )
        .unwrap();
        assert_eq!(
            (component.readiness(), f.io.0.lock().unwrap().names.clone()),
            (OverlayReadiness::PendingReconciliation, names.clone()),
            "field {field}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
    assert_eq!(f.io.bytes(&f.overlay.journal_path()), old);
    let path = f.overlay.area.join("foreign");
    f.io.create(&path).unwrap();
    assert!(
        f.reopen()
            .unwrap_err()
            .to_string()
            .contains("foreign volume entry")
    );
    f.io.remove(&path).unwrap();
    let path = f.overlay.area.join("staging").join("not-a-stage");
    f.io.create(&path).unwrap();
    assert!(
        f.reopen()
            .unwrap_err()
            .to_string()
            .contains("foreign staging name")
    );
    f.io.remove(&path).unwrap();
    f.overlay.config.cap = u64::MAX;
    assert!(matches!(
        f.overlay.capacity(0, codec::JOURNAL_MAX as u64 - 4576, 1),
        Err(OverlayError::NoSpace)
    ));
}

#[test]
fn non_cap_admission_and_seal_exits_clear_an_earlier_cap_measurement() {
    let mut f = Fixture::new();
    let length = f.overlay.journal.lock().unwrap().length;
    let stages = f.overlay.namespace.stages.len();
    let summary = f.overlay.summary();
    f.overlay.config.cap = summary.charged_bytes + summary.reserved_bytes + summary.captured_bytes;
    assert!(matches!(
        f.overlay.capacity(1, length, stages),
        Err(OverlayError::NoSpace)
    ));
    assert!(f.overlay.capacity_exhaustion.is_some());
    assert!(matches!(
        f.overlay.capacity(0, codec::JOURNAL_MAX as u64, stages),
        Err(OverlayError::NoSpace)
    ));
    assert!(f.overlay.named_capacity_exhaustion().is_none());

    assert!(matches!(
        f.overlay.capacity(1, length, stages),
        Err(OverlayError::NoSpace)
    ));
    f.overlay.next_capture = u64::MAX;
    let seal = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree);
    assert!(
        matches!(seal, Err(OverlayError::Refused("capture exhaustion"))),
        "seal overflow premise: {seal:?}"
    );
    assert!(f.overlay.named_capacity_exhaustion().is_none());
}

#[test]
fn cap_exhaustion_records_the_failing_measurement_not_the_cached_summary() {
    let mut f = Fixture::new();
    let (length, completion) = {
        let journal = f.overlay.journal.lock().unwrap();
        (journal.length, journal.completion.clone())
    };
    let stages = f.overlay.namespace.stages.len();
    let measured = f.overlay.measure(length, stages, &completion).unwrap();
    f.overlay.config.cap = measured.charged + measured.reserved + measured.captured;
    f.overlay.summary.charged_bytes = 0;
    f.overlay.summary.reserved_bytes = 0;
    f.overlay.summary.captured_bytes = 0;
    assert!(matches!(
        f.overlay.capacity(1, length, stages),
        Err(OverlayError::NoSpace)
    ));
    let exhausted = f.overlay.capacity_exhaustion.unwrap();
    assert_eq!(
        (
            exhausted.charged,
            exhausted.reserved,
            exhausted.captured,
            exhausted.needed,
        ),
        (measured.charged, measured.reserved, measured.captured, 1)
    );
}

/// The journal length alone asks for a commit, at exactly 48 MiB: an off-by-one
/// there would wait a record too long, or commit a record too early.
#[test]
fn journal_length_requests_a_commit_at_exactly_48_mib() {
    let mut f = Fixture::new();
    f.overlay.config.cap = 134_217_728;
    let stages = f.overlay.namespace.stages.len();
    let mut requested = Vec::new();
    for length in [50_331_647, 50_331_648] {
        f.overlay.capacity(0, length, stages).unwrap();
        assert!(
            f.overlay.summary.charged_bytes < f.overlay.config.cap / 4 * 3,
            "journal length {length}: the charge arm must stay below its threshold, charged {}",
            f.overlay.summary.charged_bytes
        );
        requested.push(f.overlay.summary.commit_requested);
    }
    assert_eq!(requested, [false, true]);
}

#[test]
fn mirrored_receipt_survives_lost_file_synced_frame() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"mark");
    let capture = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    f.overlay
        .flush_boundary(&mut f.store, &f.owner, &capture)
        .unwrap();
    let content = GrainId::of(b"mark");
    f.source.0.insert(content, b"mark".to_vec());
    let faults = f.overlay.fault_control();
    faults.arm("overlay.journal.append", "before", 1, FaultAction::Crash);
    assert!(
        f.overlay
            .record_file_synced(
                &mut f.store,
                &f.owner,
                &RegisteredCapture {
                    capture,
                    writer: [17; 16],
                    generation: 1,
                    prepared_root: grain(2),
                    content
                }
            )
            .is_err()
    );
    assert_eq!(faults.fired().len(), 1);
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(
        (
            f.overlay.namespace.stages[&id].mark.map(|m| m.generation),
            f.overlay
                .read_stage(&mut f.store, &f.owner, id, 0, 4)
                .unwrap()
        ),
        (Some(1), b"mark".to_vec())
    );
}

#[test]
fn captured_named_receipt_finishes_after_unlink_without_resurrection() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    let capture = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    assert_eq!(capture.captured_path(), Some(&[name("f")][..]));
    f.overlay
        .flush_boundary(&mut f.store, &f.owner, &capture)
        .unwrap();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: at("f"),
                kind: codec::DeleteKind::File { stage_id: Some(id) },
            },
        )
        .unwrap();
    assert!(matches!(
        f.overlay.capture_boundary(&mut f.store, &f.owner),
        Err(OverlayError::PendingBoundary)
    ));
    let content = GrainId::of(b"old");
    f.source.0.insert(content, b"old".to_vec());
    f.overlay
        .record_file_synced(
            &mut f.store,
            &f.owner,
            &RegisteredCapture {
                capture,
                writer: [17; 16],
                generation: 1,
                prepared_root: grain(2),
                content,
            },
        )
        .unwrap();
    assert_eq!(
        (
            f.overlay.entries(&mut f.store, &f.owner).unwrap().len(),
            f.overlay.summary().orphan_bytes,
            f.overlay.summary().captured_bytes
        ),
        (0, 163, 0)
    );
    let local = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    assert_eq!(local.captured_path(), None);
    f.overlay
        .flush_boundary(&mut f.store, &f.owner, &local)
        .unwrap();
    assert!(
        f.overlay
            .record_file_synced(
                &mut f.store,
                &f.owner,
                &RegisteredCapture {
                    capture: local.clone(),
                    writer: [17; 16],
                    generation: 2,
                    prepared_root: grain(2),
                    content
                }
            )
            .unwrap_err()
            .to_string()
            .contains("orphan capture has no prepared-root name")
    );
    f.overlay.complete_failed_capture(&local).unwrap();
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(f.overlay.entries(&mut f.store, &f.owner).unwrap().len(), 0);
}

#[test]
fn captures_bind_scope_volume_writer_and_boundary_epoch() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    let original = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    assert!(f.overlay.validate_capture(&original).is_ok());
    for field in 0..3 {
        let mut wrong = original.clone();
        match field {
            0 => wrong.scope.push('x'),
            1 => wrong.volume = VolumeName::new("wrong".into()).unwrap(),
            _ => wrong.writer = [0; 16],
        }
        assert!(
            f.overlay
                .validate_capture(&wrong)
                .unwrap_err()
                .to_string()
                .contains("capture context"),
            "field {field}"
        );
    }
    let mut f = Fixture::new();
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert!(
        f.overlay
            .record_boundary(&mut f.store, &f.owner, capture, grain(4), [8; 16])
            .unwrap_err()
            .to_string()
            .contains("boundary capture context")
    );
}

#[test]
fn later_completed_pair_keeps_its_mapped_cursor_and_replacement_owed() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"old");
    f.sync(id, 1);
    let proof = f.boundary_proof();
    let first = f.landing(proof);
    f.write(id, b"mid");
    f.io.sync(&f.overlay.stage_path(id)).unwrap();
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    let entries = vec![OverlayEntry {
        path: vec![name("f")],
        inode: 1,
        kind: OverlayKind::File {
            content: Some(GrainId::of(b"mid")),
        },
        stage_id: None,
        size: 3,
        exec: false,
    }];
    f.source.0.insert(GrainId::of(b"mid"), b"mid".to_vec());
    let boundary = f
        .overlay
        .record_boundary(&mut f.store, &f.owner, capture, grain(4), [8; 16])
        .unwrap();
    let mut second = LandedProof {
        boundary_seq: boundary,
        landed_root: grain(4),
        landed_seq: 3,
        captured_entries: entries.clone(),
        entries,
    };
    f.overlay
        .record_landed(&mut f.store, &f.owner, &second)
        .unwrap();
    f.overlay
        .record_intent_registered(
            &mut f.store,
            &f.owner,
            21,
            grain(4),
            codec::IntentCause::LandedRefresh,
        )
        .unwrap();
    f.overlay
        .replace_landed(&mut f.store, &f.owner, first)
        .unwrap();
    assert_eq!(f.overlay.readiness(), OverlayReadiness::PendingRecovery);
    let evidence = f.overlay.recovery_commits(&mut f.store, &f.owner).unwrap();
    assert_eq!(evidence.len(), 2);
    let index = evidence
        .iter()
        .find_map(|r| match r {
            RecoveryCommit::Boundary {
                index,
                publication_id,
                ..
            } if *publication_id == [8; 16] => Some(*index),
            _ => None,
        })
        .unwrap();
    assert!(evidence.iter().any(|r|matches!(r,RecoveryCommit::Landed {boundary_seq,root,seq:3,..} if *boundary_seq==index&&*root==grain(4))));
    second.boundary_seq = index;
    f.overlay
        .replace_landed(&mut f.store, &f.owner, second)
        .unwrap();
    assert_eq!(
        (
            f.overlay.readiness(),
            f.overlay.entries(&mut f.store, &f.owner).unwrap()[0]
                .kind
                .clone()
        ),
        (
            OverlayReadiness::Ready,
            OverlayKind::File {
                content: Some(GrainId::of(b"mid"))
            }
        )
    );
}

#[test]
fn valid_transactions_emit_no_failure_events() {
    let log = LogBytes::default();
    let dispatch = observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        log.clone(),
    );
    tracing::subscriber::with_default(dispatch, || {
        let mut f = Fixture::new();
        let id = f.create();
        f.write(id, b"good");
        f.sync(id, 1);
        let proof = f.boundary_proof();
        let proof = f.landing(proof);
        f.overlay
            .replace_landed(&mut f.store, &f.owner, proof)
            .unwrap();
    });
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert!(
        !text.contains("\"event\":\"op.failed\""),
        "unexpected failure event: {text}"
    );
    assert!(!text.contains("\"event\":\"overlay.refused\""));
}

struct Unavailable;
impl ContentSource for Unavailable {
    fn read_verified(&mut self, _: GrainId, _: u64, _: usize) -> Result<Vec<u8>, OverlayError> {
        Err(OverlayError::ContentUnavailable)
    }
}

#[test]
fn round1_ownership_retry_preserves_handles_and_captures() {
    use granary_core::manifest::{FileGrains, GrainRef, node::file_payload};

    let mut f = Fixture::new();
    let id = f.create();
    let landed = b"held";
    f.write(id, landed);
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    let capture = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    assert!(matches!(
        f.overlay
            .entries(&mut f.store, &OwnershipStatus::PendingReconciliation),
        Err(OverlayError::PendingReconciliation)
    ));
    assert!(f.overlay.entries(&mut f.store, &f.owner).is_ok());
    f.overlay
        .recover(&mut f.store, &f.owner, &mut f.source)
        .unwrap();
    assert_eq!(f.overlay.namespace.stages[&id].handles, 1);
    f.overlay.validate_capture(&capture).unwrap();
    f.overlay.complete_failed_capture(&capture).unwrap();
    // Replacement before first service after replay repairs from local checkpoint content.
    let object = GrainId::of(landed);
    let payload = file_payload(
        4,
        &FileGrains::Inline(vec![GrainRef {
            id: object,
            unpacked_len: 4,
        }]),
    )
    .unwrap();
    let content = GrainId::of(&payload);
    f.store.put(&object, landed).unwrap();
    f.store.put(&content, &payload).unwrap();
    let mut proof = f.boundary_proof();
    proof.entries[0].kind = OverlayKind::File {
        content: Some(content),
    };
    proof.captured_entries.clone_from(&proof.entries);
    let proof = f.landing(proof);
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: at("f"),
                kind: codec::DeleteKind::File { stage_id: Some(id) },
            },
        )
        .unwrap();
    f.overlay
        .recover(&mut f.store, &f.owner, &mut f.source)
        .unwrap();
    assert_eq!(f.overlay.namespace.stages[&id].handles, 1);
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert!(f.io.length(&f.overlay.stage_path(id)).unwrap().is_some());
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 4)
            .unwrap(),
        b"held"
    );
}

#[test]
fn round1_replacement_errors_release_credit_and_temporary() {
    let mut f = Fixture::new();
    f.create();
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let plan = f
        .overlay
        .prepare_replacement(&mut f.store, &f.owner, proof.clone())
        .unwrap();
    f.overlay.config.cap = 1;
    assert!(matches!(
        f.overlay.install_replacement(&mut f.store, &f.owner, plan),
        Err(OverlayError::NoSpace)
    ));
    assert_eq!(
        f.io.length(&f.overlay.area.join("journal.next")).unwrap(),
        None
    );
    let record = Record::Create {
        at: at("denied"),
        kind: codec::CreateKind::Dir,
    };
    let journal = f.overlay.journal.lock().unwrap();
    let frame = codec::encode_record(&journal.header, journal.state.next_seq(), &record).unwrap();
    let length = journal.length + frame.len() as u64;
    let completion = journal.completion.clone();
    drop(journal);
    let reserved = f
        .overlay
        .reserve_with(length, 1, &completion)
        .unwrap()
        .saturating_sub(completion.consumed());
    f.overlay.config.cap = f.overlay.charge().unwrap() + frame.len() as u64 + reserved - 1;
    let before = f.io.bytes(&f.overlay.journal_path());
    assert!(matches!(
        f.overlay.namespace_record(&mut f.store, &f.owner, record),
        Err(OverlayError::NoSpace)
    ));
    assert_eq!(f.io.bytes(&f.overlay.journal_path()), before);
    f.overlay.config.cap = 1_048_576;
    let plan = f
        .overlay
        .prepare_replacement(&mut f.store, &f.owner, proof.clone())
        .unwrap();
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    f.overlay
        .fault_control()
        .arm("overlay.journal.append", "before", 1, FaultAction::Fail);
    assert!(
        f.overlay
            .install_replacement(&mut f.store, &f.owner, plan)
            .is_err()
    );
    assert_eq!(
        f.io.length(&f.overlay.area.join("journal.next")).unwrap(),
        None
    );
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
}

#[test]
fn round1_truncate_journals_before_resize() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"extent");
    let faults = f.overlay.fault_control();
    faults.arm("overlay.stage.truncate", "after", 1, FaultAction::Crash);
    assert!(matches!(
        f.overlay.truncate(&mut f.store, &f.owner, id, 2),
        Err(OverlayError::InjectedCrash)
    ));
    assert_eq!(
        faults.fired(),
        vec![FaultEvent {
            name: "overlay.stage.truncate",
            phase: "after",
            occurrence: 1,
            record_index: 0
        }]
    );
    // Persist the stage and journal as a possible writeback order at the cut.
    f.io.sync(&f.overlay.stage_path(id)).unwrap();
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.crash();
    f.reopen().unwrap();
    // The truncate retired the extent before its fragment was journaled.
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 2)
            .unwrap(),
        b"\0\0"
    );
}

#[test]
fn round1_capture_identity_is_unique_across_opens() {
    let mut f = Fixture::new();
    let id = f.create();
    let stale = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    f.reopen().unwrap();
    let fresh = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    assert!(f.overlay.complete_failed_capture(&stale).is_err());
    f.overlay.validate_capture(&fresh).unwrap();
}

fn copy_fixture(size: usize) -> Fixture {
    let content = grain(8);
    Fixture::with_base(
        vec![OverlayEntry {
            path: vec![name("f")],
            inode: 1,
            kind: OverlayKind::File {
                content: Some(content),
            },
            stage_id: None,
            size: size as u64,
            exec: false,
        }],
        Source(BTreeMap::from([(content, vec![42; size])])),
    )
}

#[test]
fn round1_intact_copy_up_needs_checkpoint_content() {
    let mut f = copy_fixture(BUFFER * 2 + 7);
    let id = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    let source = std::mem::take(&mut f.source);
    let unavailable = f.reopen();
    assert!(
        matches!(
            unavailable,
            Err(OverlayError::Refused("source range unavailable"))
        ),
        "{unavailable:?}"
    );
    f.source = source;
    f.reopen().unwrap();
    assert_eq!(
        f.overlay
            .read_stage(&mut f.store, &f.owner, id, 0, 7)
            .unwrap(),
        vec![42; 7]
    );
}

#[test]
fn round1_short_unnamed_header_sweeps_only_canonical_prefix() {
    for valid in [true, false] {
        let mut f = Fixture::new();
        let path = f.overlay.stage_path(1);
        f.io.create(&path).unwrap();
        let mut bytes = StagingHeader {
            writer: [17; 16],
            stage_id: 1,
            mark: MarkState::Absent,
        }
        .encode()
        .unwrap();
        bytes.truncate(79);
        if !valid {
            bytes[0] ^= 1;
        }
        f.io.write_at(&path, 0, &bytes).unwrap();
        if valid {
            f.reopen().unwrap();
            assert_eq!(f.io.length(&path).unwrap(), None);
            assert_eq!(f.overlay.sweep_manifest()[0].bytes, 79);
        } else {
            assert!(f.reopen().is_err());
            assert_eq!(f.io.bytes(&path), bytes);
        }
    }
}

#[test]
fn round1_pending_replay_ceiling_is_retryable() {
    let mut f = Fixture::new();
    f.create();
    let mut pending = OverlayStore::open(
        &mut f.store,
        f.overlay.config.clone(),
        header(),
        vec![],
        &OwnershipStatus::PendingReconciliation,
        &mut f.source,
        f.io.clone(),
        FaultControl::default(),
    )
    .unwrap();
    let before = f.io.bytes(&pending.area.join("writer"));
    assert!(matches!(
        pending.raise_ceiling(&mut f.store, 101),
        Err(OverlayError::PendingReconciliation)
    ));
    assert_eq!(f.io.bytes(&pending.area.join("writer")), before);
    pending
        .recover(&mut f.store, &f.owner, &mut f.source)
        .unwrap();
    pending.raise_ceiling(&mut f.store, 101).unwrap();
}

#[test]
fn round1_copy_up_unavailable_is_retryable() {
    let mut f = copy_fixture(BUFFER + 7);
    assert!(matches!(
        f.overlay.copy_up(
            &mut f.store,
            &f.owner,
            at("f"),
            &mut ReadbackDelayed(&mut f.source, false)
        ),
        Err(OverlayError::ContentUnavailable)
    ));
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Ready);
    assert_eq!(f.io.length(&f.overlay.stage_path(1)).unwrap(), None);
    assert_eq!(
        f.overlay
            .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
            .unwrap(),
        1
    );
}

#[test]
fn round1_append_refuses_changed_journal_length() {
    for grow in [true, false] {
        let mut f = Fixture::new();
        let path = f.overlay.journal_path();
        if grow {
            f.io.mutate(&path, |b| b.extend_from_slice(b"other writer"));
        } else {
            f.io.mutate(&path, |b| {
                b.pop();
            });
        }
        let before = f.io.bytes(&path);
        assert!(
            f.overlay
                .namespace_record(
                    &mut f.store,
                    &f.owner,
                    Record::Create {
                        at: at("d"),
                        kind: codec::CreateKind::Dir
                    }
                )
                .is_err()
        );
        assert_eq!(f.io.bytes(&path), before);
        assert_eq!(f.overlay.readiness(), OverlayReadiness::Poisoned);
    }
}

#[test]
fn round1_writer_trailing_bytes_refused_everywhere() {
    let mut f = Fixture::new();
    f.overlay.writer.volume = VolumeName::new("v".repeat(63)).unwrap();
    let bytes = f.overlay.writer.encode().unwrap();
    assert_eq!(bytes.len(), 132);
    let path = f.overlay.area.join("writer");
    f.io.write_at(&path, 0, &bytes).unwrap();
    f.io.write_at(&path, 132, b"trailing").unwrap();
    assert!(f.overlay.entries(&mut f.store, &f.owner).is_err());
    let mut c = f.overlay.config.clone();
    c.volume = f.overlay.writer.volume.clone();
    let area = f
        .overlay
        .root
        .join("overlay")
        .join(&f.overlay.scope)
        .join(c.volume.as_str());
    f.io.create_directory(&area).unwrap();
    f.io.create_directory(&area.join("staging")).unwrap();
    f.io.create(&area.join("writer")).unwrap();
    f.io.write_at(
        &area.join("writer"),
        0,
        &[bytes, b"trailing".to_vec()].concat(),
    )
    .unwrap();
    assert!(
        OverlayStore::establish_writer(
            &mut f.store,
            &c,
            &mut f.io,
            &mut Fixed,
            &FaultControl::default()
        )
        .is_err()
    );
    assert!(
        OverlayStore::open(
            &mut f.store,
            c,
            header(),
            vec![],
            &f.owner,
            &mut f.source,
            f.io.clone(),
            FaultControl::default()
        )
        .is_err()
    );
}

#[test]
fn round1_capacity_does_not_walk_staging() {
    let mut f = Fixture::new();
    let id = f.create();
    for i in 0..10 {
        f.overlay
            .create_file(&mut f.store, &f.owner, at(&format!("other{i}")), false)
            .unwrap();
    }
    f.io.0.lock().unwrap().trace.clear();
    f.write(id, b"one small write");
    let staging = f.overlay.area.join("staging");
    let trace = &f.io.0.lock().unwrap().trace;
    assert!(!trace.iter().any(|(op, p)| op == "entries" && *p == staging));
    assert!(
        !trace
            .iter()
            .any(|(op, p)| op == "length" && p.parent() == Some(&staging))
    );
}

#[test]
fn round1_capture_reads_each_byte_once() {
    let mut f = Fixture::new();
    let id = f.create();
    let mut data = vec![42; BUFFER * 3 + 11];
    f.write(id, &data);
    for (offset, bytes) in [
        (BUFFER - 2, b"cross".as_slice()),
        (BUFFER * 2 + 13, b"last".as_slice()),
    ] {
        f.overlay
            .write(&mut f.store, &f.owner, id, offset as u64, bytes)
            .unwrap();
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    f.io.0.lock().unwrap().trace.clear();
    let token = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    assert_eq!(token.chunks().concat(), data);
    let path = f.overlay.stage_path(id);
    let count =
        f.io.0
            .lock()
            .unwrap()
            .trace
            .iter()
            .filter(|(op, p)| op == "read" && *p == path)
            .count();
    assert_eq!(count, 5); // one header and four content chunks
}

#[test]
fn round1_failed_install_does_not_strand_next_preparation() {
    let mut f = Fixture::new();
    f.create();
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let plan = f
        .overlay
        .prepare_replacement(&mut f.store, &f.owner, proof.clone())
        .unwrap();
    assert!(matches!(
        f.overlay
            .install_replacement(&mut f.store, &OwnershipStatus::PendingReconciliation, plan),
        Err(OverlayError::PendingReconciliation)
    ));
    assert_eq!(
        f.io.length(&f.overlay.area.join("journal.next")).unwrap(),
        None
    );
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
}

#[test]
fn round1_replay_never_sweeps_a_held_stage() {
    let mut f = Fixture::new();
    let id = f.create();
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    let path = f.overlay.stage_path(id);
    let before = f.io.bytes(&path);
    f.io.resize(&f.overlay.journal_path(), 117).unwrap();
    assert!(
        f.overlay
            .recover(&mut f.store, &f.owner, &mut f.source)
            .is_err()
    );
    assert_eq!(f.io.bytes(&path), before);
    assert_eq!(f.overlay.namespace.stages[&id].handles, 1);
}

#[test]
fn round1_failed_copy_up_cleanup_poison_retains_evidence() {
    let mut f = copy_fixture(3);
    f.io.0.lock().unwrap().fail = Some("remove");
    assert!(matches!(
        f.overlay
            .copy_up(&mut f.store, &f.owner, at("f"), &mut Unavailable),
        Err(OverlayError::Io(_))
    ));
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Poisoned);
    assert!(f.io.length(&f.overlay.stage_path(1)).unwrap().is_some());
}

#[test]
fn round1_accounting_matches_inventory_after_mutations() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"stage bytes");
    let expected = f.overlay.charge().unwrap();
    f.overlay.io.inventory().unwrap();
    assert_eq!(f.overlay.charge().unwrap(), expected);
    f.overlay.truncate(&mut f.store, &f.owner, id, 2).unwrap();
    let expected = f.overlay.charge().unwrap();
    f.overlay.io.inventory().unwrap();
    assert_eq!(f.overlay.charge().unwrap(), expected);
    let token = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    f.overlay.complete_failed_capture(&token).unwrap();
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    let expected = f.overlay.charge().unwrap();
    f.overlay.io.inventory().unwrap();
    assert_eq!(f.overlay.charge().unwrap(), expected);
}

#[test]
fn round1_capture_refuses_corrupt_and_short_bytes() {
    for short in [true, false] {
        let mut f = if short {
            copy_fixture(BUFFER + 7)
        } else {
            Fixture::new()
        };
        let id = if short {
            f.overlay
                .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
                .unwrap()
        } else {
            let id = f.create();
            f.write(id, &vec![42; BUFFER + 7]);
            id
        };
        f.io.mutate(&f.overlay.stage_path(id), |b| {
            if short {
                b.pop();
            } else {
                b[160] ^= 1;
            }
        });
        assert!(f.overlay.capture(&mut f.store, &f.owner, id).is_err());
        assert_eq!(f.overlay.readiness(), OverlayReadiness::Poisoned);
        assert!(f.overlay.snapshots.is_empty());
    }
}

#[test]
fn round1_writer_length_change_during_read_refuses() {
    let mut f = Fixture::new();
    f.io.0.lock().unwrap().grow_after_read = Some(f.overlay.area.join("writer"));
    assert!(f.overlay.entries(&mut f.store, &f.owner).is_err());
}

#[test]
fn round1_ceiling_pending_content_and_store_binding() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"anchor");
    f.sync(id, 1);
    f.io.remove(&f.overlay.stage_path(id)).unwrap();
    assert!(matches!(
        f.overlay.recover(&mut f.store, &f.owner, &mut Unavailable),
        Err(OverlayError::ContentUnavailable)
    ));
    assert!(matches!(
        f.overlay.raise_ceiling(&mut f.store, 101),
        Err(OverlayError::PendingReconciliation)
    ));
    f.overlay
        .recover(&mut f.store, &f.owner, &mut f.source)
        .unwrap();
    f.overlay.raise_ceiling(&mut f.store, 101).unwrap();
    let scratch = Scratch::new();
    let mut other = Store::open(&scratch.0).unwrap();
    assert!(f.overlay.raise_ceiling(&mut other, 102).is_err());
}

#[test]
fn round1_accounting_refuses_overflow_and_stage_rename() {
    let mut f = Fixture::new();
    let id = f.create();
    let path = f.overlay.stage_path(id);
    f.io.0.lock().unwrap().trace.clear();
    assert!(f.overlay.io.write_at(&path, u64::MAX, b"x").is_err());
    assert!(
        !f.io
            .0
            .lock()
            .unwrap()
            .trace
            .iter()
            .any(|(op, _)| op == "write")
    );
    assert!(
        f.overlay
            .io
            .rename(&path, &f.overlay.stage_path(2))
            .is_err()
    );
    assert!(f.io.length(&path).unwrap().is_some());
}

#[test]
fn round1_pending_open_still_checks_staging_inventory() {
    let mut f = Fixture::new();
    let path = f.overlay.area.join("staging").join("foreign");
    f.io.create(&path).unwrap();
    assert!(
        OverlayStore::open(
            &mut f.store,
            f.overlay.config.clone(),
            header(),
            vec![],
            &OwnershipStatus::PendingReconciliation,
            &mut f.source,
            f.io.clone(),
            FaultControl::default()
        )
        .is_err()
    );
}

struct ReadbackDelayed<'a>(&'a mut Source, bool);
impl ContentSource for ReadbackDelayed<'_> {
    fn read_verified(
        &mut self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        if self.1 {
            return Err(OverlayError::ContentUnavailable);
        }
        self.1 = true;
        self.0.read_verified(content, offset, length)
    }
}

#[test]
fn round1_unbound_stage_physical_charge_tracks_write_and_resize() {
    let mut f = Fixture::new();
    let path = f.overlay.stage_path(1);
    f.overlay.io.create(&path).unwrap();
    let header = StagingHeader {
        writer: [17; 16],
        stage_id: 1,
        mark: MarkState::Absent,
    }
    .encode()
    .unwrap();
    f.overlay.io.write_at(&path, 0, &header).unwrap();
    f.overlay.io.write_at(&path, 160, b"not bound yet").unwrap();
    let expected = f.overlay.charge().unwrap();
    f.overlay.io.inventory().unwrap();
    assert_eq!(f.overlay.charge().unwrap(), expected);
    f.overlay.io.resize(&path, 163).unwrap();
    let expected = f.overlay.charge().unwrap();
    f.overlay.io.inventory().unwrap();
    assert_eq!(f.overlay.charge().unwrap(), expected);
}

#[test]
fn round1_replacement_cleanup_failure_poison_retains_temporary() {
    let mut f = Fixture::new();
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let plan = f
        .overlay
        .prepare_replacement(&mut f.store, &f.owner, proof)
        .unwrap();
    f.io.0.lock().unwrap().fail = Some("remove");
    assert!(matches!(
        f.overlay
            .install_replacement(&mut f.store, &OwnershipStatus::PendingReconciliation, plan),
        Err(OverlayError::Io(_))
    ));
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Poisoned);
    assert!(
        f.io.length(&f.overlay.area.join("journal.next"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn round1_capture_checks_header_even_for_empty_stage() {
    let mut f = Fixture::new();
    let id = f.create();
    f.io.mutate(&f.overlay.stage_path(id), |b| b[0] ^= 1);
    assert!(f.overlay.capture(&mut f.store, &f.owner, id).is_err());
    assert!(f.overlay.snapshots.is_empty());
}

#[test]
fn round1_named_short_header_repairs_unnamed_short_header_only_sweeps() {
    for named in [true, false] {
        let mut f = Fixture::new();
        let id = if named { f.create() } else { 1 };
        let path = f.overlay.stage_path(id);
        if named {
            f.io.resize(&path, 0).unwrap();
        } else {
            f.io.create(&path).unwrap();
        }
        f.io.0.lock().unwrap().trace.clear();
        f.reopen().unwrap();
        if named {
            f.overlay.header(id).unwrap();
        } else {
            assert_eq!(f.io.length(&path).unwrap(), None);
            assert!(
                !f.io
                    .0
                    .lock()
                    .unwrap()
                    .trace
                    .iter()
                    .any(|(op, p)| op == "write" && *p == path)
            );
        }
    }
}

#[test]
fn owned_replays_and_reserves_before_initial_registration_but_cannot_mutate() {
    let mut f = Fixture::new();
    f.owner = OwnershipStatus::Owned(OwnershipPermission {
        scope: f.overlay.scope.clone(),
        volume: f.overlay.config.volume.clone(),
        writer: f.overlay.writer.writer,
        high_water: 0,
    });
    f.reopen().unwrap();
    let replayed = f.overlay.replayed;
    let reserved = f.overlay.raise_ceiling(&mut f.store, 101).is_ok();
    let mutation = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("premature"), false);
    assert_eq!(
        (
            replayed,
            reserved,
            matches!(mutation, Err(OverlayError::PendingReconciliation))
        ),
        (true, true, true),
        "owned bootstrap must replay/reserve without serving: {mutation:?}"
    );
}

mod coordination;

#[test]
fn overlay_readiness_result_requires_use() {
    let source = include_str!("../overlay_store.rs");
    assert!(
        source.contains("#[must_use]\n    pub fn readiness("),
        "public overlay readiness must remain must_use"
    );
}

#[test]
fn admission_checks_share_publication_settlement() {
    let source = include_str!("../writable_store.rs");
    let checks = source
        .split("pub(crate) fn check_initial_state(")
        .nth(1)
        .unwrap()
        .split("fn check(&self)")
        .next()
        .unwrap();
    assert_eq!(
        checks.matches(".publications(self.config.euid)?").count(),
        1,
        "initial and serving admission must share the publication settlement check"
    );
}
