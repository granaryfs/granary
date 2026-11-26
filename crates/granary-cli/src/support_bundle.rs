// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Support-bundle collection, invocation and protected publication.

#[cfg(any(test, target_os = "linux"))]
use granary_core::support::BundleOverlay;
#[cfg(any(test, target_os = "linux"))]
use granary_core::support::{BundleCache, BundleConfiguration, BundleLogs, BundleMetrics};
use granary_core::{
    cacheindex,
    clock::Clock as _,
    hash::GrainId,
    overlay_journal,
    sheaf::Timestamp,
    support::{
        BUNDLE_ARCHIVE_MAX, BUNDLE_MANIFEST_ENTRIES_MAX, BUNDLE_MANIFEST_MAX,
        BUNDLE_METRICS_SCHEMA, BundleArchive, BundleEntry, BundleEntryStatus, BundleKind,
        BundleManifest, BundleRefusal, BundleVersion,
    },
};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
    process::ExitCode,
};

const _: () = assert!(
    granary_client::METRICS_SCHEMA_VERSION == 2
        && BUNDLE_METRICS_SCHEMA == 2
        && granary_client::CACHE_MARKER_VERSION == 1
        && cacheindex::VERSION == 1
        && overlay_journal::VERSION == 1
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Declaration {
    None,
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MountDeclaration {
    Unknown,
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Args {
    output: PathBuf,
    mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Live(PathBuf),
    Offline {
        cache: Declaration,
        overlay: Declaration,
        store: Declaration,
        mountpoint: MountDeclaration,
    },
}

fn take_value(
    args: &[OsString],
    index: &mut usize,
    flag: &'static str,
) -> Result<OsString, String> {
    *index = index.saturating_add(1);
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn declaration(value: OsString) -> Declaration {
    if value == "none" {
        Declaration::None
    } else {
        Declaration::Path(PathBuf::from(value))
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &'static str) -> Result<(), String> {
    if slot.is_some() {
        Err(format!("{flag} repeated option"))
    } else {
        *slot = Some(value);
        Ok(())
    }
}

pub(crate) fn parse(args: &[OsString]) -> Result<Args, String> {
    let mut output = None;
    let mut target = None;
    let mut offline = None;
    let mut cache = None;
    let mut overlay = None;
    let mut store = None;
    let mut mountpoint = None;
    let mut index = 0usize;
    while let Some(arg) = args.get(index) {
        match arg.to_str() {
            Some("--output") => set_once(
                &mut output,
                PathBuf::from(take_value(args, &mut index, "--output")?),
                "--output",
            )?,
            Some("--offline") => set_once(&mut offline, (), "--offline")?,
            Some("--cache-dir") => set_once(
                &mut cache,
                declaration(take_value(args, &mut index, "--cache-dir")?),
                "--cache-dir",
            )?,
            Some("--overlay-dir") => set_once(
                &mut overlay,
                declaration(take_value(args, &mut index, "--overlay-dir")?),
                "--overlay-dir",
            )?,
            Some("--store-dir") => set_once(
                &mut store,
                declaration(take_value(args, &mut index, "--store-dir")?),
                "--store-dir",
            )?,
            Some("--mountpoint") => {
                let value = take_value(args, &mut index, "--mountpoint")?;
                set_once(
                    &mut mountpoint,
                    if value == "unknown" {
                        MountDeclaration::Unknown
                    } else {
                        MountDeclaration::Path(PathBuf::from(value))
                    },
                    "--mountpoint",
                )?;
            }
            Some(flag) if flag.starts_with('-') => return Err("unknown option".to_owned()),
            _ => set_once(&mut target, PathBuf::from(arg), "live target")?,
        }
        index = index.saturating_add(1);
    }
    let output = output.ok_or_else(|| "--output is required".to_owned())?;
    if target.is_some() && offline.is_some() {
        return Err("live target cannot be combined with --offline".to_owned());
    }
    if let Some(target) = target {
        if cache.is_some() || overlay.is_some() || store.is_some() || mountpoint.is_some() {
            return Err("offline declarations require --offline".to_owned());
        }
        return Ok(Args {
            output,
            mode: Mode::Live(target),
        });
    }
    if offline.is_none() {
        return Err("live target or --offline is required".to_owned());
    }
    let cache = cache.ok_or_else(|| "--cache-dir is required with --offline".to_owned())?;
    let overlay = overlay.ok_or_else(|| "--overlay-dir is required with --offline".to_owned())?;
    let store = store.ok_or_else(|| "--store-dir is required with --offline".to_owned())?;
    let mountpoint =
        mountpoint.ok_or_else(|| "--mountpoint is required with --offline".to_owned())?;
    let any_path = [&cache, &overlay, &store]
        .into_iter()
        .any(|item| matches!(item, Declaration::Path(_)));
    if any_path && mountpoint == MountDeclaration::Unknown {
        return Err("unknown mountpoint cannot be mixed with a source path".to_owned());
    }
    Ok(Args {
        output,
        mode: Mode::Offline {
            cache,
            overlay,
            store,
            mountpoint,
        },
    })
}

fn add<F>(
    kind: BundleKind,
    value: Result<(usize, F), BundleRefusal>,
    entries: &mut Vec<BundleEntry>,
    members: &mut BTreeMap<BundleKind, Vec<u8>>,
) -> Result<(), &'static str>
where
    F: FnOnce() -> Result<Vec<u8>, BundleRefusal>,
{
    let status = match value {
        Ok((length, produce)) => {
            bounded_allocation(length, kind.cap(), |_| {})?;
            let encoded_length = u32::try_from(length).map_err(|_| "support size bound")?;
            match produce() {
                Ok(bytes) => {
                    if bytes.len() != length {
                        return Err("support size bound");
                    }
                    let digest = *GrainId::of(&bytes).digest();
                    members.insert(kind, bytes);
                    BundleEntryStatus::Exported {
                        length: encoded_length,
                        digest,
                    }
                }
                Err(reason) => BundleEntryStatus::Refused(reason),
            }
        }
        Err(reason) => BundleEntryStatus::Refused(reason),
    };
    entries.push(BundleEntry { kind, status });
    Ok(())
}

fn bounded_allocation(
    length: usize,
    cap: usize,
    allocate: impl FnOnce(usize),
) -> Result<(), &'static str> {
    if length > cap {
        return Err("support size bound");
    }
    allocate(length);
    Ok(())
}

fn preflight_with(
    entries: &[BundleEntry],
    members: &BTreeMap<BundleKind, Vec<u8>>,
    allocate: impl FnOnce(usize),
) -> Result<(), &'static str> {
    if entries.len() != BUNDLE_MANIFEST_ENTRIES_MAX || members.len() > BUNDLE_MANIFEST_ENTRIES_MAX {
        return Err("support count bound");
    }
    let manifest = entries
        .iter()
        .try_fold(64usize, |size, entry| {
            size.checked_add(match entry.status {
                BundleEntryStatus::Exported { .. } => 47 + entry.kind.member_name().len(),
                BundleEntryStatus::Refused(_) => 10,
            })
        })
        .ok_or("support size bound")?;
    bounded_allocation(manifest, BUNDLE_MANIFEST_MAX, |_| {})?;
    let archive = members
        .iter()
        .try_fold(
            56usize.checked_add(manifest).ok_or("support size bound")?,
            |size, (kind, bytes)| {
                size.checked_add(5)
                    .and_then(|n| n.checked_add(kind.member_name().len()))
                    .and_then(|n| n.checked_add(bytes.len()))
            },
        )
        .ok_or("support size bound")?;
    bounded_allocation(archive, BUNDLE_ARCHIVE_MAX, allocate)
}

fn preflight(
    entries: &[BundleEntry],
    members: &BTreeMap<BundleKind, Vec<u8>>,
) -> Result<(), &'static str> {
    preflight_with(entries, members, |_| {})
}

type MemberProducer<F> = Result<(usize, F), BundleRefusal>;
#[cfg(any(test, target_os = "linux"))]
type BoxProducer = Box<dyn FnOnce() -> Result<Vec<u8>, BundleRefusal> + Send>;

#[cfg(any(test, target_os = "linux"))]
fn member(
    length: usize,
    encode: impl FnOnce() -> Result<Vec<u8>, BundleRefusal> + Send + 'static,
) -> (usize, BoxProducer) {
    (length, Box::new(encode))
}

#[cfg(any(test, target_os = "linux"))]
fn live_logs(
    history: &granary_client::BundleHistory,
) -> Result<MemberProducer<BoxProducer>, &'static str> {
    let snapshot = match history.try_snapshot() {
        Ok(snapshot) => snapshot,
        Err(granary_client::BundleSnapshotError::Unavailable) => {
            return Ok(Err(BundleRefusal::Unavailable));
        }
        Err(granary_client::BundleSnapshotError::CountBound) => {
            return Err("support count bound");
        }
        Err(granary_client::BundleSnapshotError::SizeBound) => {
            return Err("support size bound");
        }
    };
    let length = snapshot
        .records()
        .len()
        .checked_mul(2)
        .and_then(|framing| framing.checked_add(snapshot.encoded_bytes()))
        .and_then(|records| records.checked_add(10))
        .ok_or("support size bound")?;
    Ok(Ok(member(length, move || {
        BundleLogs {
            lost: snapshot.lost(),
            records: snapshot
                .records()
                .iter()
                .map(|record| record.as_str().to_owned())
                .collect(),
        }
        .encode()
        .map_err(|_| BundleRefusal::Unavailable)
    })))
}

#[cfg(any(test, target_os = "linux"))]
fn live_failures(history: &granary_client::BundleHistory) -> MemberProducer<BoxProducer> {
    match history.try_failure_snapshot() {
        Ok(failures) => {
            let length = failures.entries.iter().fold(2usize, |length, failure| {
                length + 12 + usize::from(failure.correlation.is_some()) * 8
            });
            Ok(member(length, move || {
                failures.encode().map_err(|_| BundleRefusal::Unavailable)
            }))
        }
        Err(_) => Err(BundleRefusal::Unavailable),
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) struct LiveOwners {
    pub(crate) configuration: Result<BundleConfiguration, BundleRefusal>,
    pub(crate) history: granary_client::BundleHistory,
    pub(crate) metrics: Option<granary_client::ClientMetrics>,
    pub(crate) overlay:
        Option<std::sync::Arc<dyn Fn() -> Result<BundleOverlay, BundleRefusal> + Send + Sync>>,
}

#[cfg(any(test, target_os = "linux"))]
impl LiveOwners {
    pub(crate) fn collect(
        &self,
        bundled_at: Timestamp,
        cache: Result<BundleCache, BundleRefusal>,
    ) -> Result<BundleArchive, &'static str> {
        let version = writer_version()?;
        let logs = live_logs(&self.history)?;
        let failures = live_failures(&self.history);
        let configuration = self.configuration.map_or_else(Err, |value| {
            Ok(member(34, move || {
                value.encode().map_err(|_| BundleRefusal::Unavailable)
            }))
        });
        let overlay =
            self.overlay
                .as_ref()
                .map_or(
                    Err(BundleRefusal::NotApplicable),
                    |projection| match projection() {
                        Ok(value) => Ok(member(99, move || {
                            value.encode().map_err(|_| BundleRefusal::Unavailable)
                        })),
                        Err(reason) => Err(reason),
                    },
                );
        let cache = match cache {
            Ok(value) => Ok(member(
                if matches!(value, BundleCache::Writer { .. }) {
                    33
                } else {
                    1
                },
                move || value.encode().map_err(|_| BundleRefusal::Unavailable),
            )),
            Err(reason) => Err(reason),
        };
        let metrics = match self
            .metrics
            .as_ref()
            .map(granary_client::ClientMetrics::snapshot)
        {
            Some(Ok(snapshot)) => {
                let value: BundleMetrics = snapshot.bundle_projection();
                Ok(member(2_577, move || {
                    value.encode().map_err(|_| BundleRefusal::Unavailable)
                }))
            }
            Some(Err(_)) | None => Err(BundleRefusal::Unavailable),
        };
        let version = Ok(member(27, move || {
            version.encode().map_err(|_| BundleRefusal::Unavailable)
        }));
        assemble(
            bundled_at,
            [
                (BundleKind::Version, version),
                (BundleKind::Configuration, configuration),
                (BundleKind::Logs, logs),
                (BundleKind::Overlay, overlay),
                (BundleKind::Cache, cache),
                (BundleKind::Failures, failures),
                (BundleKind::Metrics, metrics),
            ],
        )
    }
}

pub(crate) fn assemble<F>(
    bundled_at: Timestamp,
    values: [(BundleKind, MemberProducer<F>); BUNDLE_MANIFEST_ENTRIES_MAX],
) -> Result<BundleArchive, &'static str>
where
    F: FnOnce() -> Result<Vec<u8>, BundleRefusal>,
{
    let mut entries = Vec::new();
    let mut members = BTreeMap::new();
    for (kind, value) in values {
        add(kind, value, &mut entries, &mut members)?;
    }
    preflight(&entries, &members)?;
    Ok(BundleArchive {
        manifest: BundleManifest {
            bundled_at,
            entries,
        },
        members,
    })
}

pub(crate) fn offline_archive(
    bundled_at: Timestamp,
    version: BundleVersion,
    overlay_configured: bool,
    cache_configured: bool,
) -> Result<BundleArchive, &'static str> {
    let version = move || version.encode().map_err(|_| BundleRefusal::Unencodable);
    assemble(
        bundled_at,
        [
            (BundleKind::Version, Ok((27, version))),
            (BundleKind::Configuration, Err(BundleRefusal::Unavailable)),
            (BundleKind::Logs, Err(BundleRefusal::Unavailable)),
            (
                BundleKind::Overlay,
                Err(if overlay_configured {
                    BundleRefusal::Unavailable
                } else {
                    BundleRefusal::NotApplicable
                }),
            ),
            (
                BundleKind::Cache,
                Err(if cache_configured {
                    BundleRefusal::Unavailable
                } else {
                    BundleRefusal::NotApplicable
                }),
            ),
            (BundleKind::Failures, Err(BundleRefusal::Unavailable)),
            (BundleKind::Metrics, Err(BundleRefusal::Unavailable)),
        ],
    )
}

fn package_component(value: &str) -> Result<u32, &'static str> {
    value.parse().map_err(|_| "build version unavailable")
}

pub(crate) fn writer_version() -> Result<BundleVersion, &'static str> {
    let features = u8::from(cfg!(feature = "overlay-fault-tests"))
        | (u8::from(cfg!(feature = "publish-restart-tests")) << 1)
        | (u8::from(cfg!(feature = "conformance-breakage")) << 2);
    Ok(BundleVersion {
        package_major: package_component(env!("CARGO_PKG_VERSION_MAJOR"))?,
        package_minor: package_component(env!("CARGO_PKG_VERSION_MINOR"))?,
        package_patch: package_component(env!("CARGO_PKG_VERSION_PATCH"))?,
        prerelease: !env!("CARGO_PKG_VERSION_PRE").is_empty(),
        target_os: if cfg!(target_os = "linux") {
            1
        } else if cfg!(target_os = "macos") {
            2
        } else {
            3
        },
        target_arch: if cfg!(target_arch = "x86_64") {
            1
        } else if cfg!(target_arch = "aarch64") {
            2
        } else {
            3
        },
        debug_assertions: cfg!(debug_assertions),
        features,
        metrics_schema: BUNDLE_METRICS_SCHEMA,
        cache_marker_version: granary_client::CACHE_MARKER_VERSION,
        cache_index_version: cacheindex::VERSION,
        overlay_journal_version: overlay_journal::VERSION,
    })
}

fn report(reason: &str) {
    crate::terminal::write_line(format_args!("gran: support bundle: {reason}"));
}

fn publication_result(result: Result<(), granary_client::PrivateArchiveError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error.to_string());
            ExitCode::from(match error.class() {
                granary_client::PrivateArchiveErrorClass::Refused => 1,
                granary_client::PrivateArchiveErrorClass::PublicationUncertain => 3,
            })
        }
    }
}

fn offline_mount(path: &Path) -> Result<((u64, u64), Option<u64>), &'static str> {
    let (identity, parent_device) =
        granary_client::prove_mountpoint(path).map_err(|_| "source separation unavailable")?;
    let device = (identity.0 != parent_device).then_some(identity.0);
    Ok((identity, device))
}

fn invoke_offline_with_mount<'a>(
    args: &'a Args,
    invoking_uid: u32,
    mounted_namespace: impl FnOnce(
        &'a Path,
        (u64, u64),
        Option<u64>,
    ) -> granary_client::MountedNamespace<'a>,
) -> ExitCode {
    let Mode::Offline {
        cache,
        overlay,
        store,
        mountpoint,
    } = &args.mode
    else {
        report("invalid offline invocation");
        return ExitCode::FAILURE;
    };
    let declarations = [cache, overlay, store];
    let roots = declarations
        .into_iter()
        .filter_map(|declaration| match declaration {
            Declaration::Path(path) => Some(path.as_path()),
            Declaration::None => None,
        })
        .collect::<Vec<_>>();
    let mount_evidence = match mountpoint {
        MountDeclaration::Path(path) => match offline_mount(path) {
            Ok(evidence) => Some((path.as_path(), evidence)),
            Err(reason) => {
                report(reason);
                return ExitCode::FAILURE;
            }
        },
        MountDeclaration::Unknown => None,
    };
    let mounted =
        mount_evidence.map(|(path, (identity, device))| mounted_namespace(path, identity, device));
    let parent = match granary_client::prepare_private_archive_parent(
        &args.output,
        granary_client::ArchiveSources::new(&roots, mounted),
        invoking_uid,
    ) {
        Ok(parent) => parent,
        Err(error) => {
            report(&error.to_string());
            return ExitCode::FAILURE;
        }
    };
    let version = match writer_version() {
        Ok(version) => version,
        Err(reason) => {
            report(reason);
            return ExitCode::FAILURE;
        }
    };
    let overlay_configured = matches!(overlay, Declaration::Path(_));
    let cache_configured = matches!(cache, Declaration::Path(_));
    let archive = match offline_archive(
        crate::WallClock.now(),
        version,
        overlay_configured,
        cache_configured,
    ) {
        Ok(archive) => archive,
        Err(reason) => {
            report(reason);
            return ExitCode::FAILURE;
        }
    };
    let Ok(bytes) = archive.encode() else {
        report("support encoding failed");
        return ExitCode::FAILURE;
    };
    drop(archive);
    if BundleArchive::decode(&bytes).is_err() {
        report("support encoding failed");
        return ExitCode::FAILURE;
    }
    publication_result(granary_client::publish_private_archive(parent, &bytes))
}

fn invoke_offline(args: &Args, invoking_uid: u32) -> ExitCode {
    invoke_offline_with_mount(args, invoking_uid, granary_client::MountedNamespace::new)
}

#[cfg(any(test, target_os = "linux"))]
type ProvedLiveRoot = (PathBuf, (u64, u64));

#[cfg(any(test, target_os = "linux"))]
fn prove_live_roots(
    mounted_target: Option<&Path>,
    sources: &[granary_core::support_trigger::SourceRoot],
) -> Result<Vec<ProvedLiveRoot>, &'static str> {
    use std::os::unix::ffi::OsStringExt as _;

    let mut roots = Vec::with_capacity(sources.len());
    for source in sources {
        let path = PathBuf::from(OsString::from_vec(source.path.clone()));
        let mut components = path.components();
        if !matches!(components.next(), Some(std::path::Component::RootDir))
            || !components.all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err("source separation unavailable");
        }
        if mounted_target.is_some_and(|target| path.starts_with(target)) {
            continue;
        }
        let (identity, _) =
            granary_client::prove_mountpoint(&path).map_err(|_| "source separation unavailable")?;
        if identity != (source.dev, source.ino) {
            return Err("source separation unavailable");
        }
        roots.push((path, identity));
    }
    Ok(roots)
}

#[cfg(any(test, target_os = "linux"))]
fn roots_still_match(roots: &[ProvedLiveRoot]) -> Result<(), &'static str> {
    let matched = roots.iter().all(|(root, expected)| {
        granary_client::prove_mountpoint(root).is_ok_and(|(identity, _)| identity == *expected)
    });
    matched.then_some(()).ok_or("source separation unavailable")
}

#[cfg(target_os = "linux")]
fn fuse_device(major: u32, minor: u32) -> u64 {
    libc::makedev(major, minor)
}

#[cfg(all(test, not(target_os = "linux")))]
fn fuse_device(major: u32, minor: u32) -> u64 {
    (u64::from(major) << 32) | u64::from(minor)
}

#[cfg(target_os = "linux")]
fn invoke_live(args: &Args, target: &Path, invoking_uid: u32) -> ExitCode {
    invoke_live_with(
        args,
        invoking_uid,
        || crate::attach::request_support_bundle(target, invoking_uid),
        report,
    )
}

#[cfg(any(test, target_os = "linux"))]
fn invoke_live_with(
    args: &Args,
    invoking_uid: u32,
    request: impl FnOnce() -> Result<
        (
            PathBuf,
            granary_core::support_trigger::SourceLayout,
            BundleArchive,
        ),
        crate::attach::SupportRequestFailure,
    >,
    report_reason: impl Fn(&str),
) -> ExitCode {
    let (resolved_target, layout, archive) = match request() {
        Ok(reply) => reply,
        Err(crate::attach::SupportRequestFailure::Unavailable) => {
            report_reason("support producer unavailable");
            return ExitCode::FAILURE;
        }
        Err(crate::attach::SupportRequestFailure::Malformed) => {
            report_reason("malformed support reply");
            return ExitCode::FAILURE;
        }
    };
    let mounted_target = matches!(
        layout.mount,
        granary_core::support_trigger::MountState::Mounted { .. }
    )
    .then_some(resolved_target.as_path());
    let roots = match prove_live_roots(mounted_target, &layout.roots) {
        Ok(roots) => roots,
        Err(reason) => {
            report_reason(reason);
            return ExitCode::FAILURE;
        }
    };
    let root_refs = roots
        .iter()
        .map(|(path, _)| path.as_path())
        .collect::<Vec<_>>();
    let root_identities = roots
        .iter()
        .map(|(_, identity)| *identity)
        .collect::<Vec<_>>();
    let mounted = match layout.mount {
        granary_core::support_trigger::MountState::Mounted { mountpoint, key } => {
            Some(granary_client::MountedNamespace::new(
                &resolved_target,
                mountpoint,
                Some(fuse_device(key.fuse_major, key.fuse_minor)),
            ))
        }
        granary_core::support_trigger::MountState::Absent => None,
    };
    let parent = match granary_client::prepare_private_archive_parent(
        &args.output,
        granary_client::ArchiveSources::with_expected_identities(
            &root_refs,
            &root_identities,
            mounted,
        ),
        invoking_uid,
    ) {
        Ok(parent) => parent,
        Err(error) => {
            report_reason(&error.to_string());
            return ExitCode::FAILURE;
        }
    };
    if let Err(reason) = roots_still_match(&roots) {
        report_reason(reason);
        return ExitCode::FAILURE;
    }
    let Ok(bytes) = archive.encode() else {
        report_reason("malformed support reply");
        return ExitCode::FAILURE;
    };
    publication_result(granary_client::publish_private_archive(parent, &bytes))
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn invoke_live_fixture(
    args: &Args,
    target: &Path,
    invoking_uid: u32,
    report_reason: impl Fn(&str),
) -> ExitCode {
    invoke_live_with(
        args,
        invoking_uid,
        || crate::attach::request_support_bundle(target, invoking_uid),
        report_reason,
    )
}

#[cfg(not(target_os = "linux"))]
fn invoke_live(_: &Args, _: &Path, _: u32) -> ExitCode {
    report("support producer unavailable");
    ExitCode::FAILURE
}

pub(crate) fn invoke(args: &Args) -> ExitCode {
    let credentials = crate::admission::process_credentials();
    if crate::admission::set_id_refusal(&credentials).is_some() {
        report("set-ID execution");
        return ExitCode::FAILURE;
    }
    match &args.mode {
        Mode::Live(target) => invoke_live(args, target, credentials.euid),
        Mode::Offline { .. } => invoke_offline(args, credentials.euid),
    }
}

#[cfg(test)]
mod tests;
