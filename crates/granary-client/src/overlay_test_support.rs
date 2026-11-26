// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Writable-engine support shared by the mounted and cross-crate daemon tests.

mod authority;

pub use authority::Authority;
#[cfg(test)]
pub(crate) use authority::{AcquireRace, RangeFault, RangeReadPause};
pub(crate) use authority::{AuthorityState, Entropy, ReleaseAnswer, Time};

#[cfg(feature = "overlay-fault-tests")]
use crate::FaultAction;
#[cfg(feature = "overlay-fault-tests")]
use crate::WritableSyncRuntime;
use crate::{CacheOrigin, SyncProfile, ViewMode, WritableProcess, WritableStart};
#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
use crate::{
    FaultControl, OverlayDisk, SharedWritableStore, ShutdownHandle, WritableAttachment,
    WritableReadiness,
};
#[cfg(any(test, feature = "overlay-fault-tests"))]
use granary_core::hash::GrainId;
use granary_core::identity::WriterIdentity;
#[cfg(feature = "overlay-fault-tests")]
use granary_core::intent::{self, ReceiptState};
#[cfg(feature = "overlay-fault-tests")]
use granary_core::overlay_ownership::Phase;
use granary_core::retained_submission::Scope;
use granary_core::root::{Timestamp, VolumeName};
use granary_store::backend::GranaryStore;
use granary_store::crypto::SigningKey;
use object_store::memory::InMemory;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
use std::time::Duration;

#[cfg(test)]
pub(crate) fn block_for_test(delay: std::time::Duration) {
    let mutex = std::sync::Mutex::new(());
    let guard = mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // No notifier exists, so the predicate only absorbs spurious wakeups.
    drop(std::sync::Condvar::new().wait_timeout_while(guard, delay, |()| true));
}

/// Test-only scratch directory for publication inputs, removed on drop.
pub(crate) struct ScratchDir(pub(crate) PathBuf);

impl ScratchDir {
    #[expect(
        clippy::disallowed_methods,
        reason = "name and create a test-owned temporary publication directory"
    )]
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "granary-mount-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap_or_else(|error| panic!("{error}"));
        Self(path)
    }
}

impl Drop for ScratchDir {
    #[expect(
        clippy::disallowed_methods,
        reason = "remove only the uniquely named test-owned publication directory"
    )]
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Read a mounted FUSE connection's anonymous minor without issuing a request.
#[cfg(target_os = "linux")]
pub(crate) fn mount_connection(path: &Path) -> std::io::Result<Option<u64>> {
    let mut escaped = Vec::new();
    for &byte in path.as_os_str().as_bytes() {
        match byte {
            b' ' => escaped.extend_from_slice(b"\\040"),
            b'\t' => escaped.extend_from_slice(b"\\011"),
            b'\n' => escaped.extend_from_slice(b"\\012"),
            b'\\' => escaped.extend_from_slice(b"\\134"),
            _ => escaped.push(byte),
        }
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "read Linux mount identity for the test-owned FUSE mount"
    )]
    let mountinfo = std::fs::read("/proc/self/mountinfo")?;
    for line in mountinfo.split(|&byte| byte == b'\n') {
        let mut fields = line.split(|&byte| byte == b' ');
        let device = fields.nth(2);
        if fields.nth(1) != Some(escaped.as_slice()) {
            continue;
        }
        let kind = fields.skip_while(|field| *field != b"-").nth(1);
        if !kind.is_some_and(|field| field == b"fuse" || field.starts_with(b"fuse.")) {
            return Err(std::io::Error::other("test mount is not FUSE"));
        }
        let minor = device
            .and_then(|value| value.strip_prefix(b"0:"))
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| {
                std::io::Error::other("test FUSE mount has no anonymous device number")
            })?;
        return Ok(Some(minor));
    }
    Ok(None)
}

/// Open the abort descriptor while the fixture still owns its device number.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn arm_fuse_abort(
    connection: std::io::Result<Option<u64>>,
    connections: &Path,
) -> (Option<u64>, Option<std::fs::File>) {
    let connection = match connection {
        Ok(Some(connection)) => connection,
        other => {
            eprintln!("mount test cleanup: connection abort unavailable: {other:?}");
            return (None, None);
        }
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "pin this test mount's fusectl abort descriptor before device-number reuse"
    )]
    let abort = match std::fs::OpenOptions::new()
        .write(true)
        .open(connections.join(connection.to_string()).join("abort"))
    {
        Ok(abort) => Some(abort),
        Err(error) => {
            eprintln!("mount test cleanup: connection abort unavailable: {error}");
            None
        }
    };
    (Some(connection), abort)
}

/// A fusectl abort descriptor pinned to one mounted fixture.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct ArmedFuseAbort(std::fs::File);

#[cfg(target_os = "linux")]
impl ArmedFuseAbort {
    /// Pin `path`'s abort descriptor while its mount identity is still owned.
    #[must_use]
    pub fn arm(path: &Path) -> Option<Self> {
        arm_fuse_abort(
            mount_connection(path),
            Path::new("/sys/fs/fuse/connections"),
        )
        .1
        .map(Self)
    }

    /// Abort through the pinned descriptor; success means the connection lived.
    pub fn abort(&mut self) -> bool {
        use std::io::Write as _;

        self.0.write_all(b"1").is_ok()
    }
}

/// Content used by the shared one-file publication fixture.
pub(crate) const FILE_CONTENT: &[u8] = b"mount test fixture file content\n";

/// The one Python descriptor probe used by both mounted and daemon tests.
///
/// The both mode keeps the mounted fixture's numeric READ/LIST protocol.
/// Directory and file modes keep the daemon row's named diagnostic protocol.
#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
pub const HELD_HANDLE_SCRIPT: &str = r"
import ctypes,mmap,os,sys
libc=ctypes.CDLL(None,use_errno=True)
libc.getdents64.restype=ctypes.c_long
libc.getdents64.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t]
buf=ctypes.create_string_buffer(8192)
mode=sys.argv[2]
root=sys.argv[1]
direct=sys.argv[3:]==['direct']
directory=mode in ('both','directory')
dirfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY) if directory else -1
file_flags=os.O_RDONLY|os.O_DIRECT if direct else os.O_RDONLY
filefd=os.open(os.path.join(root,'f.txt') if mode=='both' else root,file_flags) if mode in ('both','file') else -1
direct_buf=mmap.mmap(-1,mmap.PAGESIZE) if direct else None
def read(named):
    if direct:
        try:
            # A request past EOF can trigger GETATTR before FUSE sends READ.
            os.preadv(filefd,[memoryview(direct_buf)[:16]],0)
            return 0
        except OSError as error:
            return error.errno
    try:
        os.posix_fadvise(filefd,0,0,os.POSIX_FADV_DONTNEED)
    except OSError as error:
        return ('posix_fadvise:'+str(error.errno)) if named else error.errno
    try:
        os.pread(filefd,16 if mode=='both' else 1,0)
        return 'ok' if named else 0
    except OSError as error:
        return ('pread:'+str(error.errno)) if named else error.errno
def listing(named):
    try:
        os.lseek(dirfd,0,os.SEEK_SET)
    except OSError as error:
        return ('lseek:'+str(error.errno)) if named else error.errno
    ctypes.set_errno(0)
    n=libc.getdents64(dirfd,buf,len(buf))
    if n<0:
        return ('getdents64:'+str(ctypes.get_errno())) if named else ctypes.get_errno()
    return 'ok' if named else (-1 if n==0 else 0)
named=mode!='both'
first=listing(named) if directory else read(named)
print('OPEN',first,flush=True)
for line in sys.stdin:
    print(read(named) if line.startswith('READ') or mode=='file' else listing(named),flush=True)
";

pub(crate) fn origin() -> CacheOrigin {
    CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x11; 32],
        root_key_id: None,
    }
}

pub(crate) fn vol(value: &str) -> VolumeName {
    VolumeName::new(value.to_owned()).unwrap_or_else(|error| panic!("{error}"))
}

pub(crate) const fn stamp() -> Timestamp {
    Timestamp {
        secs: 1_760_000_000,
        nanos: 0,
    }
}

/// Paths owned by one writable fixture and removed together.
pub(crate) struct Paths {
    pub(crate) scratch: PathBuf,
    key_scratch: Option<PathBuf>,
    pub(crate) store: PathBuf,
    pub(crate) cache: PathBuf,
    pub(crate) seed: PathBuf,
    pub(crate) mountpoint: PathBuf,
    pub(crate) certificate: PathBuf,
    pub(crate) credential_key: PathBuf,
    uid: u32,
    gid: u32,
}

impl Paths {
    #[expect(
        clippy::disallowed_methods,
        reason = "create one uniquely named fixture tree and resolve its test-owned base"
    )]
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture owns and validates its selected scratch base"
    )]
    pub(crate) fn new() -> Self {
        #[cfg(target_os = "linux")]
        let base = std::env::temp_dir().canonicalize().unwrap();
        #[cfg(not(target_os = "linux"))]
        let base = runtime_workspace_scratch().unwrap();
        std::fs::create_dir_all(&base).unwrap();
        Self::with_store_base(&base)
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "create one uniquely named fixture tree beneath the caller's test-owned base"
    )]
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture owns every path created beneath the selected scratch base"
    )]
    pub(crate) fn with_store_base(base: &Path) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = base.canonicalize().unwrap();
        let scratch = base.join(format!(
            "writable-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::set_permissions(
            &scratch,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let metadata = scratch.metadata().unwrap();
        let uid = metadata.uid();
        let gid = metadata.gid();
        let key_scratch = crate::signing_seed_paths(&scratch.join("seed"), uid)
            .is_err()
            .then(|| protected_key_scratch(uid));
        let key_root = key_scratch.as_ref().unwrap_or(&scratch).clone();
        let mountpoint = scratch.join("mountpoint");
        std::fs::create_dir(&mountpoint).unwrap();
        Self {
            mountpoint,
            store: scratch.join("writable-store"),
            cache: scratch.join("writable-cache"),
            seed: key_root.join("seed"),
            certificate: key_root.join("certificate"),
            credential_key: key_root.join("credential-key"),
            scratch,
            key_scratch,
            uid,
            gid,
        }
    }
}

impl Drop for Paths {
    fn drop(&mut self) {
        #[expect(
            clippy::disallowed_methods,
            reason = "remove only this fixture's uniquely named scratch trees"
        )]
        {
            let _ = std::fs::remove_dir_all(&self.scratch);
            if let Some(path) = &self.key_scratch {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "locate the fixture's workspace-owned scratch root"
)]
#[expect(
    clippy::unwrap_used,
    reason = "the fixture process starts from a valid current directory"
)]
pub(crate) fn runtime_workspace_scratch() -> Option<PathBuf> {
    let cwd = std::env::current_dir().unwrap();
    cwd.ancestors()
        .find(|path| path.join("Cargo.lock").is_file() && path.join("crates").is_dir())
        .map(|workspace| workspace.join("target/test-scratch"))
}

#[cfg(test)]
pub(crate) fn test_process_id() -> u32 {
    #[expect(
        clippy::disallowed_methods,
        reason = "the process id only makes the fixture-owned scratch name unique"
    )]
    std::process::id()
}

#[expect(
    clippy::disallowed_methods,
    reason = "create a fixture-only private-key directory accepted by production custody"
)]
#[expect(
    clippy::unwrap_used,
    reason = "accepted custody paths have a checked parent and fixture-owned current directory"
)]
fn protected_key_scratch(euid: u32) -> PathBuf {
    use std::os::unix::fs::DirBuilderExt as _;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let cwd = std::env::current_dir().unwrap();
    let mut candidates = Vec::new();
    if let Some(workspace) = runtime_workspace_scratch() {
        candidates.push(workspace);
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home));
    }
    candidates.extend(cwd.ancestors().map(Path::to_path_buf));
    for base in candidates {
        let Ok(checked) = crate::signing_seed_paths(&base.join("fixture-seed"), euid) else {
            continue;
        };
        let base = checked.seed().parent().unwrap();
        let directory = base.join(format!(
            "writable-keys-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        if std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .is_err()
        {
            continue;
        }
        assert!(crate::signing_seed_paths(&directory.join("seed"), euid).is_ok());
        return directory;
    }
    panic!("no writable directory satisfying signing-key custody for uid {euid}");
}

/// One small publication used by mount and writable-engine fixtures.
pub(crate) struct PublishedTree {
    pub(crate) seq: u64,
    pub(crate) seed: [u8; 32],
    #[cfg(test)]
    pub(crate) remote: GranaryStore<Arc<InMemory>>,
    pub(crate) mem: Arc<InMemory>,
    pub(crate) key: SigningKey,
    pub(crate) volume: VolumeName,
    #[cfg(test)]
    pub(crate) file_id: GrainId,
    #[cfg(test)]
    pub(crate) manifest_root: GrainId,
    #[cfg(test)]
    pub(crate) binmap_index: GrainId,
    #[cfg(test)]
    pub(crate) sheaf_head: GrainId,
}

pub(crate) fn remote_handle(mem: &Arc<InMemory>) -> GranaryStore<Arc<InMemory>> {
    GranaryStore::new(Arc::clone(mem))
}

#[cfg(test)]
impl PublishedTree {
    pub(crate) fn publish(volume_name: &str) -> Self {
        Self::publish_shape(volume_name, false)
    }

    pub(crate) fn publish_nested(volume_name: &str) -> Self {
        Self::publish_shape(volume_name, true)
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "publish a fixture-owned source through the real publication path"
    )]
    fn publish_shape(volume_name: &str, nested: bool) -> Self {
        let scratch = ScratchDir::new();
        let source = scratch.0.join("source");
        let store_dir = scratch.0.join("publication");
        std::fs::create_dir_all(&source).unwrap_or_else(|error| panic!("{error}"));
        std::fs::write(source.join("f.txt"), FILE_CONTENT)
            .unwrap_or_else(|error| panic!("{error}"));
        if nested {
            std::fs::create_dir_all(source.join("sub")).unwrap_or_else(|error| panic!("{error}"));
            std::fs::write(source.join("sub").join("g.txt"), FILE_CONTENT)
                .unwrap_or_else(|error| panic!("{error}"));
        }
        publish_tree(&source, &store_dir, volume_name)
    }
}

fn publish_tree(source: &Path, store_dir: &Path, volume_name: &str) -> PublishedTree {
    let mem = Arc::new(InMemory::new());
    let remote = GranaryStore::new(Arc::clone(&mem));
    let (key, seed) = SigningKey::generate().unwrap_or_else(|error| panic!("{error}"));
    let volume = vol(volume_name);
    let store = crate::Store::open(store_dir).unwrap_or_else(|error| panic!("{error}"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("{error}"));
    let summary = runtime
        .block_on(crate::publish(
            &remote,
            &store,
            source,
            &volume,
            &key,
            &WriterIdentity::from_bytes(*b"mount-writer-id!"),
            stamp(),
            crate::Policy::default(),
        ))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(summary.seq, 1, "fixture precondition: honest head");
    #[cfg(test)]
    let (outcome, collected) = runtime
        .block_on(crate::resolve::resolve_at_collecting(
            &remote,
            volume.as_str(),
            1,
        ))
        .unwrap_or_else(|error| panic!("{error}"));
    #[cfg(test)]
    let file_id = *collected
        .iter()
        .find_map(|(id, bytes)| (bytes.as_slice() == FILE_CONTENT).then_some(id))
        .unwrap_or_else(|| panic!("fixture publication must contain f.txt"));
    PublishedTree {
        seq: summary.seq,
        seed,
        #[cfg(test)]
        remote,
        mem,
        key,
        volume,
        #[cfg(test)]
        file_id,
        #[cfg(test)]
        manifest_root: outcome.doc.manifest_root,
        #[cfg(test)]
        binmap_index: outcome.doc.binmap_index,
        #[cfg(test)]
        sheaf_head: outcome.doc.sheaf_head,
    }
}

pub(crate) fn mounted_operation_tree() -> PublishedTree {
    let scratch = ScratchDir::new();
    let source = scratch.0.join("source");
    write_operation_source(&source, FILE_CONTENT);
    publish_tree(&source, &scratch.0.join("publication"), "v")
}

#[expect(
    clippy::disallowed_methods,
    reason = "create the fixture-owned operation-tree source"
)]
#[expect(
    clippy::unwrap_used,
    reason = "every operation-tree path is inside the uniquely owned fixture"
)]
pub(crate) fn write_operation_source(source: &Path, file: &[u8]) {
    std::fs::create_dir(source).unwrap();
    std::fs::create_dir(source.join("sub")).unwrap();
    std::fs::create_dir(source.join("empty")).unwrap();
    std::fs::write(source.join("f.txt"), file).unwrap();
    std::fs::write(source.join("sub/g.txt"), FILE_CONTENT).unwrap();
    std::os::unix::fs::symlink("f.txt", source.join("original-link")).unwrap();
}

pub(crate) fn input<'a>(tree: &PublishedTree, paths: &'a Paths) -> WritableStart<'a> {
    WritableStart {
        construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
        overlay_cap_bytes: 134_217_728,
        contention_threshold: crate::ContentionThreshold::default(),
        volume: tree.volume.clone(),
        process: WritableProcess {
            ruid: paths.uid,
            rgid: paths.gid,
            egid: paths.gid,
            set_id_tainted: false,
        },
        foreground: true,
        force: false,
        mountpoint: &paths.mountpoint,
        root_key: Some(*tree.key.public_key()),
        manifest_root: None,
        trust_server: false,
        options: crate::MountOptions::default(),
        seq: None,
        seed: Some(&paths.seed),
        certificate: Some(&paths.certificate),
        credential_key: Some(&paths.credential_key),
        scope: Some(Scope {
            authority_base: b"https://fixture.invalid".to_vec(),
            pins: vec![],
            credential_context: b"fixture".to_vec(),
        }),
        store: Some(&paths.store),
        cache: Some(&paths.cache),
        cache_origin: origin(),
        cache_quota: 268_435_456,
        reset_floor: false,
        policy: granary_vfs::AttrPolicy {
            uid: paths.uid,
            gid: paths.gid,
        },
        euid: paths.uid,
        sync_profile: SyncProfile::default(),
        view: ViewMode::Default,
    }
}

/// Shared publication, admission, attachment and control assembly.
#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
pub(crate) struct WritableFixtureCore<S> {
    pub(crate) attachment: WritableAttachment<Authority, OverlayDisk>,
    pub(crate) sync_runtime: S,
    pub(crate) control: AuthorityControl,
    pub(crate) shutdown: ShutdownHandle,
}

#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
#[expect(
    clippy::too_many_arguments,
    reason = "fixture assembly keeps independent mount, publication and restart-authority controls explicit"
)]
pub(crate) fn writable_fixture_core<S>(
    profile: SyncProfile,
    view: ViewMode,
    shutdown_bound: Option<Duration>,
    publication: bool,
    authority_state: Option<AuthorityState>,
    paths: &Arc<Paths>,
    tree: &PublishedTree,
    finish: impl FnOnce(
        WritableReadiness<Authority, OverlayDisk>,
        &PublishedTree,
        &Arc<Mutex<AuthorityState>>,
        Option<Duration>,
    ) -> Result<
        (
            WritableAttachment<Authority, OverlayDisk>,
            S,
            ShutdownHandle,
        ),
        String,
    >,
) -> Result<WritableFixtureCore<S>, String> {
    let cfg = WritableStart {
        sync_profile: profile,
        view,
        ..input(tree, paths)
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "write the fixture's generated signing seed"
    )]
    std::fs::write(&paths.seed, tree.seed).map_err(|error| error.to_string())?;
    #[expect(
        clippy::disallowed_methods,
        reason = "make the fixture's generated signing seed private"
    )]
    std::fs::set_permissions(&paths.seed, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    let state = Arc::new(Mutex::new(authority_state.unwrap_or_else(|| {
        AuthorityState {
            head_seq: tree.seq,
            ..AuthorityState::default()
        }
    })));
    let authority = Authority::with_scope_and_rule(tree, cfg.scope.clone(), &state, "sync_publish");
    // A daemon's engine commits through this authority; a mount that attaches
    // its own publishing remote keeps startup's no-upload guard here.
    let authority = if publication {
        authority.with_publication()
    } else {
        authority
    };
    let key = SigningKey::from_seed(&tree.seed).map_err(|error| error.to_string())?;
    let spare = SigningKey::from_seed(&tree.seed).map_err(|error| error.to_string())?;
    let ready = crate::writable_start::start_with(
        &cfg,
        true,
        || Ok((key, spare, authority)),
        |store| OverlayDisk::new(store.publication_root(), cfg.euid),
        &mut Entropy(20),
        &Time(Arc::clone(&state)),
        &mut granary_core::rng::SeededRng::new(1),
        &mut Vec::new(),
    )
    .map_err(|error| format!("{error:?}: {error}"))?;
    let (attachment, sync_runtime, shutdown) = finish(ready, tree, &state, shutdown_bound)?;
    let mediator = attachment.backend.shared_mediator().clone();
    let faults = mediator
        .with(|store| Ok(store.fault_control()))
        .map_err(|error| error.to_string())?;
    #[cfg(feature = "overlay-fault-tests")]
    let scope = cfg
        .scope
        .clone()
        .ok_or_else(|| "fixture scope missing after admission".to_owned())?;
    let control = AuthorityControl {
        state,
        faults,
        mediator,
        paths: Arc::clone(paths),
        #[cfg(feature = "overlay-fault-tests")]
        scope,
        #[cfg(feature = "overlay-fault-tests")]
        shutdown: shutdown.clone(),
    };
    Ok(WritableFixtureCore {
        attachment,
        sync_runtime,
        control,
        shutdown,
    })
}

/// Persistent evidence left by a bounded shutdown.
#[cfg(feature = "overlay-fault-tests")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeptState {
    pub journal_records: usize,
    pub staging_files: usize,
    pub authority_intent: bool,
    pub local_intent: bool,
}

/// Controls and observations for one in-process authority and writable store.
#[derive(Clone)]
#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
pub struct AuthorityControl {
    state: Arc<Mutex<AuthorityState>>,
    faults: FaultControl,
    mediator: SharedWritableStore,
    paths: Arc<Paths>,
    #[cfg(feature = "overlay-fault-tests")]
    scope: Scope,
    #[cfg(feature = "overlay-fault-tests")]
    shutdown: ShutdownHandle,
}

#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
impl std::fmt::Debug for AuthorityControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityControl")
            .field("mountpoint", &self.paths.mountpoint)
            .finish_non_exhaustive()
    }
}

#[cfg(any(feature = "overlay-fault-tests", target_os = "linux"))]
impl AuthorityControl {
    #[must_use]
    #[cfg(feature = "overlay-fault-tests")]
    pub fn mountpoint(&self) -> &Path {
        &self.paths.mountpoint
    }

    #[must_use]
    #[cfg(feature = "overlay-fault-tests")]
    pub fn store_path(&self) -> &Path {
        &self.paths.store
    }

    #[must_use]
    #[cfg(feature = "overlay-fault-tests")]
    pub fn shutdown(&self) -> ShutdownHandle {
        self.shutdown.clone()
    }

    #[cfg(feature = "overlay-fault-tests")]
    pub fn stall_before_dispatch(&self) {
        self.faults.arm(
            "sync.registration",
            "before_dispatch",
            1,
            FaultAction::Block,
        );
    }

    #[must_use]
    #[cfg(feature = "overlay-fault-tests")]
    pub fn dispatch_is_stalled(&self) -> bool {
        self.stalled_dispatch().is_some()
    }

    /// Identity recorded by the currently armed registration stall.
    #[must_use]
    #[cfg(feature = "overlay-fault-tests")]
    pub fn stalled_dispatch(&self) -> Option<(u64, u64, Option<GrainId>)> {
        self.faults
            .sync_fired()
            .into_iter()
            .find(|event| event.name == "sync.registration" && event.phase == "before_dispatch")
            .map(|event| (event.occurrence, event.capture, event.request))
    }

    /// Whether an open writable descriptor is suppressing quiescent coalescing.
    ///
    /// # Errors
    /// The fixture's writable mediator is poisoned or refuses inspection.
    #[cfg(feature = "overlay-fault-tests")]
    pub fn has_open_write_handles(&self) -> Result<bool, String> {
        self.mediator
            .with(|store| Ok(store.has_open_write_handles()))
            .map_err(|error| error.to_string())
    }

    /// Whether coordination has no pending authority request or publication.
    ///
    /// # Errors
    /// The fixture's writable mediator is poisoned or refuses inspection.
    #[cfg(feature = "overlay-fault-tests")]
    pub fn coordination_is_idle(&self) -> Result<bool, String> {
        match self.mediator.check_quiescent() {
            Ok(()) => Ok(true),
            Err(crate::CoordinationError::Refused("WritableRecoveryRequired")) => Ok(false),
            Err(error) => Err(error.to_string()),
        }
    }

    #[cfg(feature = "overlay-fault-tests")]
    pub fn release_stall(&self) {
        self.faults.resume();
    }

    #[cfg(feature = "overlay-fault-tests")]
    pub fn supersede(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release_answer = ReleaseAnswer::Superseded;
    }

    #[must_use]
    #[cfg(feature = "overlay-fault-tests")]
    pub fn head_seq(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .head_seq
    }

    #[must_use]
    #[cfg(feature = "overlay-fault-tests")]
    pub fn registrations(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .registration_requests
            .len()
    }

    #[must_use]
    #[cfg(feature = "overlay-fault-tests")]
    pub fn registration_requests_since(&self, start: usize) -> Vec<GrainId> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .registration_requests
            .get(start..)
            .unwrap_or_default()
            .to_vec()
    }

    #[must_use]
    #[cfg(feature = "overlay-fault-tests")]
    pub fn publications(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .publications
            .len()
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn state(&self) -> &Arc<Mutex<AuthorityState>> {
        &self.state
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn faults(&self) -> &FaultControl {
        &self.faults
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn mediator(&self) -> &SharedWritableStore {
        &self.mediator
    }

    /// Read the journal, staging area and retained ownership intent in place.
    ///
    /// # Errors
    /// Missing or malformed fixture state, or a poisoned mediator.
    #[cfg(feature = "overlay-fault-tests")]
    pub fn kept_state(&self) -> Result<KeptState, String> {
        let area = self
            .paths
            .store
            .join("overlay")
            .join(self.scope.digest().map_err(|error| error.to_string())?)
            .join("v");
        #[expect(
            clippy::disallowed_methods,
            reason = "read the fixture-owned journal as retained-state evidence"
        )]
        let bytes = std::fs::read(area.join("journal")).map_err(|error| error.to_string())?;
        let mut journal_records = 0;
        granary_core::overlay_journal::scan_journal_with(&bytes, |_, _| {
            journal_records += 1;
        })
        .map_err(|error| error.to_string())?;
        #[expect(
            clippy::disallowed_methods,
            reason = "enumerate the fixture-owned staging area as retained-state evidence"
        )]
        let staging_files = std::fs::read_dir(area.join("staging"))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
            .len();
        #[expect(
            clippy::disallowed_methods,
            reason = "read the fixture-owned ownership carrier as retained-state evidence"
        )]
        let ownership = std::fs::read(area.join("ownership")).map_err(|error| error.to_string())?;
        let (phase, current) = self
            .mediator
            .with(|store| Ok((store.snapshot().phase, store.snapshot().current.clone())))
            .map_err(|error| error.to_string())?;
        let local_receipt = intent::decode_receipt(&current).ok();
        let local_intent = !ownership.is_empty()
            && matches!(phase, Phase::OwnedStart | Phase::Serving | Phase::Releasing)
            && local_receipt
                .is_some_and(|receipt| matches!(receipt.state, ReceiptState::Live { .. }));
        let authority_intent = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .row
            .is_some_and(|authority| {
                local_receipt.is_some_and(|local| {
                    matches!(authority.state, ReceiptState::Live { .. })
                        && (authority.writer, authority.epoch, authority.instance)
                            == (local.writer, local.epoch, local.instance)
                })
            });
        Ok(KeptState {
            journal_records,
            staging_files,
            authority_intent,
            local_intent,
        })
    }
}

/// The real writable backend, sync executor and controls consumed by a daemon row.
#[cfg(feature = "overlay-fault-tests")]
pub struct WritableDaemonParts {
    pub attachment: WritableAttachment<Authority, OverlayDisk>,
    pub sync_runtime: WritableSyncRuntime,
    pub control: AuthorityControl,
    pub shutdown: ShutdownHandle,
}

#[cfg(feature = "overlay-fault-tests")]
impl std::fmt::Debug for WritableDaemonParts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WritableDaemonParts")
            .field("control", &self.control)
            .finish_non_exhaustive()
    }
}

/// Build a real writable attachment and sync engine over the shared fixture.
///
/// # Errors
/// Fixture I/O, publication, admission or engine attachment failure.
#[cfg(feature = "overlay-fault-tests")]
pub fn writable_daemon_parts(
    profile: SyncProfile,
    shutdown_bound: Duration,
) -> Result<WritableDaemonParts, String> {
    let paths = Arc::new(Paths::new());
    let tree = mounted_operation_tree();
    let parts = writable_fixture_core(
        profile,
        ViewMode::Default,
        Some(shutdown_bound),
        true,
        None,
        &paths,
        &tree,
        |ready, _tree, state, bound| {
            let mut attachment = ready.attach();
            if let Some(bound) = bound {
                attachment.set_shutdown_bound(bound);
            }
            let sync_runtime = attachment
                .start_sync(Arc::new(Time(Arc::clone(state))))
                .map_err(|error| error.to_string())?;
            let shutdown = attachment
                .shutdown_handle()
                .ok_or_else(|| "attached engine did not publish a shutdown handle".to_owned())?;
            Ok((attachment, sync_runtime, shutdown))
        },
    )?;
    Ok(WritableDaemonParts {
        attachment: parts.attachment,
        sync_runtime: parts.sync_runtime,
        control: parts.control,
        shutdown: parts.shutdown,
    })
}

#[cfg(all(test, feature = "overlay-fault-tests"))]
mod tests {
    use super::*;

    #[test]
    fn writable_daemon_support_builds_both_profiles() {
        let mut cases = 0;
        for profile in [SyncProfile::DurablePrepared, SyncProfile::Published] {
            let parts = writable_daemon_parts(profile, Duration::from_secs(1)).unwrap();
            #[expect(
                clippy::disallowed_methods,
                reason = "positive control for the fixture-owned mountpoint and writable store"
            )]
            let observed = (
                parts.control.head_seq(),
                parts.control.registrations(),
                parts.control.registration_requests_since(0).len(),
                parts.control.publications(),
                parts.control.shutdown().report(),
                parts
                    .control
                    .kept_state()
                    .map(|state| (state.authority_intent, state.local_intent)),
                parts.control.mountpoint().is_dir(),
                parts.control.store_path().is_dir(),
            );
            assert_eq!(
                observed,
                (1, 1, 1, 0, None, Ok((true, true)), true, true),
                "profile={profile:?}: shared daemon support"
            );
            let released = parts
                .control
                .shutdown()
                .begin(crate::ShutdownTrigger::SessionEnd)
                .outcome;
            let after_release = parts
                .control
                .kept_state()
                .map(|state| (state.authority_intent, state.local_intent));
            assert_eq!(
                (released, after_release),
                (crate::ShutdownOutcome::Clean, Ok((false, false)))
            );
            cases += 1;
        }
        assert_eq!(cases, 2);
    }
}
