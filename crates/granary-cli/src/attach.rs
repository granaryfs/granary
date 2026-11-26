// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! mount lifecycle errors can strand a FUSE attachment, detach an unrelated
//! filesystem, or misreport whether shutdown completed.
//!
//! Inbound names: `MOUNT_HELP`, `invoked_as_mount_gran`, `parse_mount`,
//! `parse_umount`, `parse_mount_gran`, `parse_construction_workspace`,
//! `cmd_mount`, `cmd_umount`, and the
//! inferred `MountArgs` return type. The remaining dispatch tests also read
//! `MountOutcome` and `mount_exit_code`, and on feature builds
//! `MountRefusal` and `mount_attempt_with_credentials`; the refusal payload
//! also exposes the `MountPreflightError` type.
//!
//! Reach into the residue: `ProcessCredentials`, `process_credentials`,
//! `set_id_refusal`, `NoPinsRemedy`, `pins_from`, `cache_origin`,
//! `WireSnapshotArgs`, `wire_snapshot_args`, `write_wire_snapshot_if_requested`,
//! `parse_cat_seq`, `DEFAULT_CACHE_QUOTA_BYTES`, and `WallClock`. Direct
//! credential field reads are `euid` and `egid`; the pin parser selects
//! `NoPinsRemedy::MountHasNoSecondRoute`.
//! `cmd_mount_gran` stays in the crate root because it calls `usage`.
// @file-disposition-lines: 4405
// @file-disposition: SPLIT — The kernel's mount table is a second subject and lives in attach/mount_table.rs, whose one production reach back into this file is MountPreflightError. WHAT REMAINS THE SUBJECT HERE is the attachment LIFECYCLE — parsing, preflight, attachment, shutdown and detachment, whose ORDERING decides whether an attachment is stranded, an unrelated filesystem is detached, or shutdown is misreported. The mount_table child holds the OBSERVATION and this file holds the POLICY: TargetRows reports what the kernel's rows say, and umount_preflight_verdict and umount_postcheck_verdict decide what that permits, deliberately disagreeing about AllGran. The control child owns endpoint custody, authenticated wire exchange and bounded result delivery. This file owns control startup, coordinator ordering, outcome classification and command policy. The evidence functions live in the children and their callers, which fix the ordering, stay in this file. check-file-dispositions.sh reads this directive at EVERY size, and the line-count assertion above is the half it can check; the subject sentences here are maintained by hand, because whether they are true is not a machine question.

use std::ffi::{OsStr, OsString};
#[cfg(any(test, all(target_os = "linux", feature = "conformance-breakage")))]
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use granary_client::WireByteHandle;
use granary_client::{AmbientNetwork, Cache, HttpStore, MountOptions, MountSession};
use granary_core::clock::Clock;
use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
#[cfg(any(test, target_os = "linux"))]
use granary_core::support::BundleCache;
use granary_core::support::{BundleConfiguration, BundleRefusal};
#[cfg(any(test, target_os = "linux"))]
use granary_core::support_trigger::SourceLayout;
#[cfg(target_os = "linux")]
use granary_core::support_trigger::{MountState as SupportMountState, RootRole, SourceRoot};
use granary_net::config::{ENV_TLS_PINS, SIGNING_KEY_LEN, parse_signing_key};
use granary_net::pin::SpkiPin;

use crate::admission::{ProcessCredentials, process_credentials, set_id_refusal};
#[cfg(target_os = "linux")]
use crate::write_wire_snapshot_if_requested;
use crate::{
    DEFAULT_CACHE_QUOTA_BYTES, NoPinsRemedy, WallClock, WireSnapshotArgs, cache_origin,
    parse_cat_seq, pins_from, wire_snapshot_args,
};

#[cfg(any(test, target_os = "linux"))]
mod control;
mod metrics_export;
mod mount_table;
#[cfg(target_os = "linux")]
use mount_table::still_mounted_via_findmnt;
use mount_table::{TargetRows, refuse_if_already_mounted};

#[cfg(any(test, target_os = "linux"))]
fn support_mount_matches(
    mount: granary_core::support_trigger::MountState,
    observed: &[mount_table::ControlMount],
    admitted: u32,
) -> bool {
    match (mount, observed) {
        (granary_core::support_trigger::MountState::Mounted { key, .. }, [observed]) => {
            observed.owner == admitted && observed.key == key
        }
        (granary_core::support_trigger::MountState::Absent, []) => true,
        _ => false,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn request_support_bundle(
    target: &Path,
    admitted: u32,
) -> Result<
    (PathBuf, SourceLayout, granary_core::support::BundleArchive),
    control::SupportRequestFailure,
> {
    request_support_bundle_with(
        target,
        admitted,
        |resolved| {
            let namespace = mount_table::mount_namespace()
                .map_err(|_| control::SupportRequestFailure::Unavailable)?;
            control::request_live(resolved, namespace, admitted)
        },
        mount_table::control_mounts,
    )
}

#[cfg(any(test, target_os = "linux"))]
fn request_support_bundle_with(
    target: &Path,
    admitted: u32,
    request: impl FnOnce(
        &Path,
    ) -> Result<
        (SourceLayout, granary_core::support::BundleArchive),
        control::SupportRequestFailure,
    >,
    observe: impl FnOnce(&Path) -> std::io::Result<Vec<mount_table::ControlMount>>,
) -> Result<
    (PathBuf, SourceLayout, granary_core::support::BundleArchive),
    control::SupportRequestFailure,
> {
    let resolved = resolve_for_verification(target)
        .map_err(|_| control::SupportRequestFailure::Unavailable)?;
    let (layout, archive) = request(&resolved)?;
    let observed = observe(&resolved).map_err(|_| control::SupportRequestFailure::Unavailable)?;
    if !support_mount_matches(layout.mount, &observed, admitted) {
        return Err(control::SupportRequestFailure::Malformed);
    }
    Ok((resolved, layout, archive))
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) use control::SupportRequestFailure;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::MountScratchDir;

/// `gran mount`'s help, HOISTED OUT the same way [`crate::CAT_HELP`] is,
/// so a row can assert over the text rather than trust that prose
/// written once stays true.
///
/// **Four things this text is REQUIRED to say, and each has its own
/// test:** a trust mode is mandatory and why (a mount is
/// long-lived and ambient, so it must not pick a trust posture
/// silently); `--reset-floor` is DISCOURAGED and why (clearing the
/// mount-private floor before the planted root that raised it is
/// gone just re-poisons it); what `--allow-other` actually exposes
/// (every local user who can reach the mountpoint, reading the
/// whole snapshot and executing signed-exec entries under their own
/// credentials); and the exit codes.
pub(crate) const MOUNT_HELP: &str = "\x20      gran mount <volume> <mountpoint> --endpoint <url> --pin \
     sha256/... \
     (--root-key ed25519:<64 hex> | --manifest-root <algo>:<hex> | --trust-server) \
     --cache-dir <path> --foreground \
     [--seq N] [--uid N] [--gid N] [--allow-other] [--support-bundle] \
     [--reset-floor] [--force]\n\
     \x20        Metrics opt-in (all four required): --metrics-listen <127.0.0.1:port|[::1]:port>\n\
     \x20        --metrics-token-file <private-file> --metrics-tls-cert <file> --metrics-tls-key <private-file>.\n\
     \x20        Writable opt-in: --writable [--commit-on-sync] [--view strict] [--contention-rate <rate>] [--construction-workspace-mib N] [--overlay-cap-bytes N] [--shutdown-bound <seconds>] --key-seed <existing-private-file> --store-dir <path>\n\
     \x20        --client-cert <file> --client-key <private-file> --credential-context <context>.\n\
     \x20        Requires --root-key, Owner ACL, discovered base (no --seq), ready durable intent.\n\
     \x20        --commit-on-sync: fsync, fdatasync, fsyncdir and O_SYNC/O_DSYNC writes return only\n\
     \x20        once their own publication has landed; without it they return once registered.\n\
     \x20        --view strict: a file or directory open, a lookup of a missing name and a rewound\n\
     \x20        listing fail with ETIMEDOUT rather than being served while the authority's head cannot be confirmed.\n\
     \x20        RW attachment serves writes into the local overlay; a sync registers or publishes them.\n\
     \x20        --shutdown-bound <seconds> (1 to 3600, default 30): SIGTERM or SIGINT syncs, commits and\n\
     \x20        releases within it, then unmounts; a signal after the first stop request stops shutdown at once.\n\
     \x20        Exactly one of --root-key, --manifest-root or --trust-server is \
     REQUIRED:\n\
     \x20        a mount is long-lived and ambient — many programs traverse it, \
     unaware\n\
     \x20        where the bytes came from — so it must not pick a trust posture \
     silently.\n\
     \x20        --cache-dir <path> is REQUIRED — the mount's whole read path \
     serves\n\
     \x20        through it for the life of the session; there is no default \
     directory\n\
     \x20        convention (no XDG or systemd location is \
     defined).\n\
     \x20        --foreground is REQUIRED — backgrounding (detaching from the \
     terminal)\n\
     \x20        is not implemented: no pidfile or \
     log-redirection\n\
     \x20        contract exists yet. The systemd unit and the CI lane both \
     already\n\
     \x20        pass it.\n\
     \x20        --reset-floor is DISCOURAGED. It clears the mount-private \
     freshness\n\
     \x20        floor at anchors/<volume>.mount and nothing else. Clearing it \
     while a\n\
     \x20        planted root that raised the floor is still in the store lets the \
     mount\n\
     \x20        succeed and then re-poison the floor the instant the plant is \
     removed.\n\
     \x20        Delete the plant FIRST; pass this flag second, never the other \
     order.\n\
     \x20        --allow-other lets every local user who can reach the mountpoint \
     read\n\
     \x20        the whole snapshot and execute entries carrying the signed exec \
     bit,\n\
     \x20        under their own credentials — root included. It is refused unless \
     the\n\
     \x20        trust mode is --root-key: a mount readable by every local user \
     is a\n\
     \x20        machine-wide entry point, and delegating content authority for a \
     whole\n\
     \x20        machine is a decision only a publisher signature can \
     carry.\n\
     \x20        Use an empty directory as the mountpoint. --force skips only \
     the\n\
     \x20        empty-directory check. Even with --force, gran mount refuses \
     a\n\
     \x20        non-directory or a path that is already mounted. It checks \
     the\n\
     \x20        mountpoint before opening /dev/fuse.\n\
     \x20        Exit codes: 0 clean / 1 runtime failure / 2 usage error (this \
     text) /\n\
     \x20        3 unmounted, but the cache could not be closed cleanly /\n\
     \x20        4 shutdown stopped, everything kept / 5 fenced.";

// ============================================================
// `gran mount`'s parsing, argv[0] dispatch, the mountpoint
// pre-flight, the option-set call site, and the exit-code mapping
// — everything testable without a kernel. Nothing in THIS section
// constructs a `fuser::Session`, calls `MountSession::open`, or
// wires "mount"/"umount" into `main`'s dispatch; the daemon, the
// shutdown coordinator and `gran umount`'s own implementation are
// a separate section further down, and that is where the wiring
// lives.
// ============================================================

/// `gran mount`'s parsed operands. Matches [`crate::parse_cat`]'s shape:
/// no clap, `Result<T, String>`, one struct per verb.
///
/// **`root_key`/`manifest_root`/`trust_server` are the raw parsed
/// trust triple, not [`granary_client`]'s own `TrustMode`** —
/// that type (and `MountOptions`, `MountSession::open`) is
/// `pub(crate)` to the LIB crate and invisible here, in the BIN
/// crate; the daemon linkage is where the triple becomes one. The
/// exclusivity check below duplicates the check
/// `MountSession::open` already makes on its own inputs — belt
/// over the same buckle, catching this usage error as `usage()`
/// (exit 2) at parse time rather than as a runtime failure one
/// layer down, exactly the way [`crate::parse_publish_checked`]'s own
/// `--pin`/`--direct-s3` exclusivity check already does.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "eight independent CLI flags (trust_server, allow_other, foreground, reset_floor, \
              force, writable, commit_on_sync, support_bundle), each named 1:1 by an operand `parse_mount` \
              accepts — not encoded state, so a state machine would not reduce the count, only \
              rename it"
)]
pub(crate) struct MountArgs {
    volume: VolumeName,
    mountpoint: PathBuf,
    endpoint: String,
    tls_pins: Vec<SpkiPin>,
    root_key: Option<[u8; SIGNING_KEY_LEN]>,
    manifest_root: Option<GrainId>,
    trust_server: bool,
    cache_dir: Option<PathBuf>,
    seq: Option<u64>,
    uid: Option<u32>,
    gid: Option<u32>,
    allow_other: bool,
    foreground: bool,
    reset_floor: bool,
    #[cfg_attr(
        not(any(test, target_os = "linux")),
        expect(
            dead_code,
            reason = "the support producer starts only inside the Linux daemon; parsing remains portable"
        )
    )]
    support_bundle: bool,
    support_context: Option<SupportContext>,
    /// The pre-flight refuses a non-empty mount point unless `--force`
    /// is given (see `mount_preflight`). Valueless, so it is special-cased
    /// in `parse_mount` with the other seven valueless flags: falling
    /// through to the value-taking branch would eat the next argument.
    force: bool,
    writable: bool,
    /// Each sync answers on its own publication rather than on its
    /// durable registration. Valueless, and only with `--writable`.
    commit_on_sync: bool,
    /// The writable shutdown's bound, in seconds: `--shutdown-bound`, or
    /// [`DEFAULT_SHUTDOWN_BOUND_SECS`].
    #[cfg_attr(
        not(any(test, target_os = "linux")),
        expect(
            dead_code,
            reason = "read in production only where the writable daemon starts its engine, \
                      which is target_os = \"linux\"-gated; parsed on every platform so \
                      parse_mount needs no cfg split"
        )
    )]
    shutdown_bound: u32,
    key_seed: Option<PathBuf>,
    store_dir: Option<PathBuf>,
    contention_threshold: granary_client::ContentionThreshold,
    construction_workspace_bytes: u64,
    overlay_cap_bytes: u64,
    view: granary_client::ViewMode,
    credential: crate::publish_config::PublishConfiguration,
    /// `Some` iff `--breakage <name>` parsed. `parse_mount`
    /// itself does NOT refuse on `None` —
    /// `mount_attempt_with_credentials` does, as its first check, on
    /// every platform this crate compiles for, which is
    /// what keeps this field genuinely read everywhere the feature is
    /// on and makes no dead-code exemption necessary here.
    #[cfg(feature = "conformance-breakage")]
    breakage: Option<granary_fuse::Breakage>,
    /// The wire-byte snapshot trio, or `None` in ordinary use. Read
    /// in production only inside `run_fuse_daemon`, itself
    /// `target_os = "linux"` gated (the daemon body — see that
    /// function's own doc) — parsed and carried on every platform so
    /// `parse_mount` needs no platform split of its own, and read
    /// directly by this module's own `parse_mount` tests on every
    /// platform too, but otherwise genuinely unread on a non-Linux,
    /// non-test build, where `mount_attempt_with_credentials` never
    /// reaches the daemon at all.
    wire: Option<WireSnapshotArgs>,
    metrics: metrics_export::Options,
}

pub(crate) fn writable_flag_given(args: &[OsString]) -> bool {
    let mut value = false;
    for arg in args {
        if value {
            value = false;
            continue;
        }
        let flag = arg.to_str().unwrap_or_default();
        if flag == "--writable" {
            return true;
        }
        value = flag.starts_with("--")
            && !matches!(
                flag,
                "--trust-server"
                    | "--allow-other"
                    | "--foreground"
                    | "--reset-floor"
                    | "--force"
                    | "--commit-on-sync"
            );
    }
    false
}

fn parse_mount_u32_flag(flag: &str, value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("{flag}: {value:?} is not a u32"))
}

pub(crate) fn parse_construction_workspace(value: &str) -> Result<u64, String> {
    let mib = parse_mount_u32_flag("--construction-workspace-mib", value)?;
    if !(1024..=16384).contains(&mib) {
        return Err("--construction-workspace-mib must be between 1024 and 16384 MiB".into());
    }
    u64::from(mib)
        .checked_mul(1_048_576)
        .ok_or_else(|| "--construction-workspace-mib overflows bytes".into())
}

pub(crate) fn parse_overlay_cap(value: &str) -> Result<u64, String> {
    const MIN_OVERLAY_CAP_BYTES: u64 = 44_938_292;
    let cap = value
        .parse::<u64>()
        .map_err(|_| format!("--overlay-cap-bytes: {value:?} is not a decimal u64"))?;
    if cap < MIN_OVERLAY_CAP_BYTES {
        return Err("--overlay-cap-bytes must be at least 44938292 bytes".into());
    }
    Ok(cap)
}

/// A writable shutdown's bound when `--shutdown-bound` is not given: inside
/// systemd's default 90-second stop timeout with the cache close after it.
const DEFAULT_SHUTDOWN_BOUND_SECS: u32 = 30;

/// The bounds `--shutdown-bound` accepts, in seconds.
const SHUTDOWN_BOUND_SECS: std::ops::RangeInclusive<u32> = 1..=3600;

/// The exact stderr line an armed binary prints. Every
/// breakage round greps FOR this string with `<name>` the same token
/// [`granary_fuse::Breakage::parse`] accepts; the baseline round greps
/// for its ABSENCE. A pure function so the byte string is pinned by a
/// unit test rather than only ever read inside the `target_os =
/// "linux"` daemon body nothing on this machine can drive.
#[cfg(any(test, feature = "conformance-breakage"))]
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own test calls it directly, so the byte string is pinned with no \
                  daemon or kernel mount anywhere near it"
    )
)]
fn breakage_banner(name: &str) -> String {
    format!("BREAKAGE ACTIVE: {name}")
}

/// Emit the executable banner contract through the caller's protected writer.
/// Its reserved admission is independent of the tracing filter.
#[cfg(any(test, all(target_os = "linux", feature = "conformance-breakage")))]
fn emit_breakage_banner(name: &str, log: &mut dyn Write) {
    let _ = writeln!(log, "{}", breakage_banner(name));
}

/// Parse `gran mount`'s operands.
///
/// **The quirk [`crate::parse_cat`] has and this must not inherit.** In
/// `parse_cat` EVERY `--`-prefixed token consumes the next argument —
/// there is no valueless flag there to expose it. This verb has seven
/// (`--writable`, `--commit-on-sync`, `--trust-server`, `--allow-other`,
/// `--foreground`, `--reset-floor`, `--force`), so each is special-cased
/// BEFORE the value-taking branch, and [`writable_flag_given`] skips none of
/// them as a value,
/// on [`crate::parse_publish_checked`]'s own `--direct-s3` precedent: falling through
/// would eat the next argument, so `--trust-server --endpoint x` would
/// silently swallow `--endpoint` as `--trust-server`'s "value" and then
/// fail on `x` as an unexpected positional — or worse, succeed with the
/// wrong field populated, if `x` were itself shaped like a flag.
///
/// `--seq` goes through [`parse_cat_seq`] — the SAME parser `gran cat`
/// uses, not a second one — so the two reserved seqs it refuses by name
/// stay refused here too; the mount session's own head-selection guard
/// depends on that door staying shut for every caller.
#[expect(
    clippy::too_many_lines,
    reason = "one flag-by-flag parse table (endpoint, pin, three trust-mode flags, cache-dir, \
              seq, uid, gid, seven more valueless flags, positionals) plus its cross-flag \
              refusals is one linear surface, on `crate::parse_publish`'s own \
              too_many_lines precedent — splitting the table across helpers hides which \
              flags are mutually exclusive, the property the refusals check"
)]
pub(crate) fn parse_mount(args: &[OsString]) -> Result<MountArgs, String> {
    let mut positional: Vec<&OsString> = Vec::new();
    let mut endpoint: Option<String> = None;
    let mut pins: Vec<SpkiPin> = Vec::new();
    let mut root_key: Option<[u8; SIGNING_KEY_LEN]> = None;
    let mut manifest_root: Option<GrainId> = None;
    let mut trust_server = false;
    let mut cache_dir: Option<PathBuf> = None;
    let mut seq: Option<u64> = None;
    let mut uid: Option<u32> = None;
    let mut gid: Option<u32> = None;
    let mut allow_other = false;
    let mut foreground = false;
    let mut reset_floor = false;
    let mut support_bundle = false;
    let mut force = false;
    let mut writable = writable_flag_given(args);
    let mut commit_on_sync = false;
    let mut shutdown_bound = None;
    let mut key_seed = None;
    let mut store_dir = None;
    let mut contention_threshold = None;
    let mut construction_workspace_bytes = None;
    let mut overlay_cap_bytes = None;
    let mut view = None;
    let mut credential = crate::publish_config::PublishConfiguration::default();
    #[cfg(feature = "conformance-breakage")]
    let mut breakage: Option<granary_fuse::Breakage> = None;
    let mut wire_snapshot: Option<PathBuf> = None;
    let mut wire_run_id: Option<String> = None;
    let mut wire_role: Option<String> = None;
    let mut metrics = metrics_export::Options::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let text = arg.to_str().unwrap_or_default();
        // The eight valueless flags, BEFORE the value-taking branch —
        // see the function doc for why order here is load-bearing.
        match text {
            "--writable" => {
                writable = true;
                continue;
            }
            "--commit-on-sync" => {
                commit_on_sync = true;
                continue;
            }
            "--trust-server" => {
                trust_server = true;
                continue;
            }
            "--allow-other" => {
                allow_other = true;
                continue;
            }
            "--foreground" => {
                foreground = true;
                continue;
            }
            "--reset-floor" => {
                reset_floor = true;
                continue;
            }
            "--support-bundle" => {
                support_bundle = true;
                continue;
            }
            "--force" => {
                force = true;
                continue;
            }
            _ => {}
        }
        if text.starts_with("--") {
            let value = it
                .next()
                .ok_or_else(|| format!("{text} needs a value"))?
                .clone();
            let as_string = || {
                value
                    .to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{text}: value is not valid UTF-8"))
            };
            match text {
                "--endpoint" => endpoint = Some(as_string()?),
                "--pin" => pins.extend(pins_from(
                    "--pin",
                    &as_string()?,
                    NoPinsRemedy::MountHasNoSecondRoute,
                )?),
                "--root-key" => {
                    root_key = Some(
                        parse_signing_key(&as_string()?).map_err(|e| format!("--root-key: {e}"))?,
                    );
                }
                "--manifest-root" => {
                    manifest_root = Some(
                        as_string()?
                            .parse::<GrainId>()
                            .map_err(|e| format!("--manifest-root: {e}"))?,
                    );
                }
                "--key-seed" => key_seed = Some(PathBuf::from(value)),
                "--store-dir" => store_dir = Some(PathBuf::from(value)),
                "--contention-rate" => {
                    contention_threshold = Some(
                        granary_client::ContentionThreshold::parse(&as_string()?)
                            .map_err(|error| error.to_string())?,
                    );
                }
                "--construction-workspace-mib" => {
                    construction_workspace_bytes =
                        Some(parse_construction_workspace(&as_string()?)?);
                }
                "--overlay-cap-bytes" => {
                    overlay_cap_bytes = Some(parse_overlay_cap(&as_string()?)?);
                }
                "--view" => {
                    let value = as_string()?;
                    if value != "strict" {
                        return Err(format!("--view: {value:?} is not \"strict\""));
                    }
                    view = Some(granary_client::ViewMode::Strict);
                }
                "--client-cert" | "--client-key" | "--credential-context" => {
                    credential.option(text, Some(&value))?;
                }
                "--metrics-listen"
                | "--metrics-token-file"
                | "--metrics-tls-cert"
                | "--metrics-tls-key" => {
                    metrics.option(text, value)?;
                }
                "--cache-dir" => cache_dir = Some(PathBuf::from(value)),
                "--seq" => {
                    let value = as_string()?;
                    seq = Some(if writable {
                        value
                            .parse::<u64>()
                            .map_err(|_| "--seq needs an unsigned integer".to_owned())?
                    } else {
                        parse_cat_seq(&value)?
                    });
                }
                "--shutdown-bound" => {
                    let seconds = parse_mount_u32_flag("--shutdown-bound", &as_string()?)?;
                    if !SHUTDOWN_BOUND_SECS.contains(&seconds) {
                        return Err(format!(
                            "--shutdown-bound: {seconds} is not between {} and {} seconds",
                            SHUTDOWN_BOUND_SECS.start(),
                            SHUTDOWN_BOUND_SECS.end()
                        ));
                    }
                    shutdown_bound = Some(seconds);
                }
                "--uid" => uid = Some(parse_mount_u32_flag("--uid", &as_string()?)?),
                "--gid" => gid = Some(parse_mount_u32_flag("--gid", &as_string()?)?),
                // The wire-byte snapshot trio's flags — see
                // `wire_snapshot_args` for the all-or-nothing check.
                "--wire-snapshot" => wire_snapshot = Some(PathBuf::from(value)),
                "--wire-run-id" => wire_run_id = Some(as_string()?),
                "--wire-role" => wire_role = Some(as_string()?),
                // `--breakage` TAKES a value, so it belongs here — not
                // in the valueless block above (this function's own
                // doc's TRAP). The name->variant parse itself lives
                // in granary-fuse
                // so it stays unit-testable with no `target_os =
                // "linux"` daemon anywhere near it.
                #[cfg(feature = "conformance-breakage")]
                "--breakage" => {
                    let name = as_string()?;
                    breakage = Some(granary_fuse::Breakage::parse(&name).ok_or_else(|| {
                        format!(
                            "--breakage: {name:?} is not a recognised variant (accepted: {})",
                            granary_fuse::Breakage::ALL
                                .iter()
                                .map(|b| b.name())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })?);
                }
                other => return Err(format!("unknown flag {other}")),
            }
        } else {
            positional.push(arg);
        }
    }
    let [volume, mountpoint] = positional.as_slice() else {
        return Err(format!(
            "expected 2 positional arguments (volume, mountpoint), got {}",
            positional.len()
        ));
    };
    let volume = volume
        .to_str()
        .ok_or_else(|| "volume name is not valid UTF-8".to_owned())?;
    let wire = wire_snapshot_args(wire_snapshot, wire_run_id, wire_role)?;
    if pins.is_empty() {
        return Err(format!(
            "--pin sha256/... is required: gran mount reads through a granary server over \
             pinned TLS, and there is no unpinned route. {ENV_TLS_PINS} is NOT read on this \
             path — an exported value does not supply this, deliberately (see `parse_cat`, \
             the same reasoning)"
        ));
    }
    let given_count = [root_key.is_some(), manifest_root.is_some(), trust_server]
        .into_iter()
        .filter(|given| *given)
        .count();
    if !writable
        && (commit_on_sync
            || shutdown_bound.is_some()
            || key_seed.is_some()
            || store_dir.is_some()
            || contention_threshold.is_some()
            || construction_workspace_bytes.is_some()
            || overlay_cap_bytes.is_some()
            || view.is_some()
            || credential.certificate.is_some()
            || credential.key.is_some()
            || credential.context.is_some())
    {
        return Err("writable operands require --writable".to_owned());
    }
    if !writable && given_count == 0 {
        return Err(
            "no trust mode given: exactly one of --root-key, --manifest-root or \
             --trust-server is required — a mount is long-lived and ambient, so it must not \
             pick a trust posture silently"
                .to_owned(),
        );
    }
    if !writable && given_count > 1 {
        return Err(
            "more than one of --root-key, --manifest-root and --trust-server was given; \
             exactly one is required"
                .to_owned(),
        );
    }
    // `parse_mount` only PARSES `--breakage` into
    // `MountArgs.breakage` (an unknown name is a parse error, refused
    // above where the value is read) — it does NOT refuse on absence.
    // A feature-built binary REFUSES TO START without it,
    // which is a runtime-start property, not a parse property: the
    // refusal lives in `mount_attempt_with_credentials`, as the FIRST
    // check, so it fires identically whether `MountArgs` came from
    // this function or from `parse_mount_gran` (a
    // per-key `-o breakage=` vocabulary in `parse_mount_gran` was
    // REJECTED: that arm would have been gated by `#[cfg(feature)]`
    // alone, with no harness/caller check, so an installed feature
    // binary could be armed through a REAL fstab `-o` line — widening
    // the arming path to accept ordinary fstab input instead
    // of guarding it).
    metrics.check()?;
    Ok(MountArgs {
        volume: VolumeName::new(volume.to_owned()).map_err(|e| e.to_string())?,
        mountpoint: PathBuf::from(mountpoint),
        endpoint: endpoint.ok_or_else(|| "--endpoint is required".to_owned())?,
        tls_pins: pins,
        root_key,
        manifest_root,
        trust_server,
        cache_dir,
        seq,
        uid,
        gid,
        allow_other,
        foreground,
        reset_floor,
        support_bundle,
        support_context: None,
        force,
        writable,
        commit_on_sync,
        shutdown_bound: shutdown_bound.unwrap_or(DEFAULT_SHUTDOWN_BOUND_SECS),
        key_seed,
        store_dir,
        contention_threshold: contention_threshold.unwrap_or_default(),
        construction_workspace_bytes: construction_workspace_bytes
            .unwrap_or(granary_client::SyncOptions::default().workspace_bytes),
        overlay_cap_bytes: overlay_cap_bytes.unwrap_or(134_217_728),
        view: view.unwrap_or_default(),
        credential,
        #[cfg(feature = "conformance-breakage")]
        breakage,
        wire,
        metrics,
    })
}

impl MountArgs {
    /// Select presence, counts and closed settings without retaining input strings.
    fn bundle_configuration(
        &self,
        logging: &crate::logging::Settings,
    ) -> Result<BundleConfiguration, BundleRefusal> {
        let tls_pin_count =
            u16::try_from(self.tls_pins.len()).map_err(|_| BundleRefusal::Unencodable)?;
        let publisher_key_count = u16::try_from(self.credential.publishers.configured_count())
            .map_err(|_| BundleRefusal::Unencodable)?;
        Ok(BundleConfiguration {
            mount_mode: if self.writable { 2 } else { 1 },
            root_key_configured: self.root_key.is_some(),
            manifest_root_pinned: self.manifest_root.is_some(),
            trust_server: self.trust_server,
            tls_pin_count,
            cache_configured: self.cache_dir.is_some(),
            seq_pinned: self.seq.is_some(),
            uid_override: self.uid.is_some(),
            gid_override: self.gid.is_some(),
            allow_other: self.allow_other,
            foreground: self.foreground,
            reset_floor: self.reset_floor,
            force: self.force,
            key_seed_configured: self.key_seed.is_some(),
            store_dir_configured: self.store_dir.is_some(),
            contention_threshold_bits: self.contention_threshold.to_bits(),
            certificate_configured: self.credential.certificate.is_some(),
            key_configured: self.credential.key.is_some(),
            credential_context_configured: self.credential.context.is_some(),
            publisher_key_count,
            wire_snapshot_configured: self.wire.is_some(),
            log_format: match logging.format {
                granary_client::LogFormat::Text => 1,
                granary_client::LogFormat::Json => 2,
            },
            log_destination: if logging.file.is_some() { 2 } else { 1 },
            log_paths: match logging.paths {
                granary_client::LogPaths::Redacted => 1,
                granary_client::LogPaths::Full => 2,
            },
            log_filter_source: logging.filter_source,
        })
    }

    pub(crate) fn arm_support(
        &mut self,
        logging: &crate::logging::Settings,
        history: granary_client::BundleHistory,
    ) {
        self.support_context = Some(SupportContext {
            configuration: self.bundle_configuration(logging),
            history,
        });
    }
}

#[derive(Debug, Clone)]
struct SupportContext {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "the live producer is Linux-only")
    )]
    configuration: Result<BundleConfiguration, BundleRefusal>,
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "the live producer is Linux-only")
    )]
    history: granary_client::BundleHistory,
}

#[cfg(target_os = "linux")]
struct SupportOwners {
    context: SupportContext,
    metrics: Option<granary_client::ClientMetrics>,
    overlay: Option<granary_client::SharedWritableStore>,
    roots: Vec<(RootRole, PathBuf)>,
}

#[cfg(any(test, target_os = "linux"))]
trait SupportBackend {
    fn bundle_cache(&self) -> Result<BundleCache, BundleRefusal>;
}

#[cfg(any(test, target_os = "linux"))]
fn support_cache_refusal(busy: granary_fuse::SlotBusy) -> BundleRefusal {
    if busy == granary_fuse::SlotBusy::Taken {
        BundleRefusal::TimedOut
    } else {
        BundleRefusal::Unavailable
    }
}

#[cfg(target_os = "linux")]
impl<R> SupportBackend for MountSession<R> {
    fn bundle_cache(&self) -> Result<BundleCache, BundleRefusal> {
        MountSession::bundle_cache(self)
    }
}

#[cfg(target_os = "linux")]
impl<R, P: granary_client::OverlayIo> SupportBackend for granary_client::WritableMount<R, P> {
    fn bundle_cache(&self) -> Result<BundleCache, BundleRefusal> {
        granary_client::WritableMount::bundle_cache(self)
    }
}

#[cfg(target_os = "linux")]
fn prove_support_roots(roots: &[(RootRole, PathBuf)]) -> std::io::Result<Vec<SourceRoot>> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut sources = Vec::with_capacity(roots.len());
    for (role, root) in roots {
        let (identity, _) = granary_client::prove_mountpoint(root)
            .map_err(|_| std::io::Error::other("support source identity unavailable"))?;
        sources.push(SourceRoot {
            role: *role,
            path: root.as_os_str().as_bytes().to_vec(),
            dev: identity.0,
            ino: identity.1,
        });
    }
    Ok(sources)
}

#[cfg(target_os = "linux")]
fn support_layout(
    mountpoint: (u64, u64),
    key: granary_core::mount_control::MountKey,
    roots: Vec<SourceRoot>,
) -> SourceLayout {
    SourceLayout {
        mount: SupportMountState::Mounted { mountpoint, key },
        roots,
    }
}

#[cfg(target_os = "linux")]
fn resolve_support_roots(
    roots: impl IntoIterator<Item = (RootRole, PathBuf)>,
) -> Result<Vec<(RootRole, PathBuf)>, granary_client::WritableStartError> {
    roots
        .into_iter()
        .map(|(role, root)| granary_client::managed_path(&root).map(|root| (role, root)))
        .collect()
}

#[cfg(any(test, target_os = "linux"))]
fn collect_support<B: granary_fuse::MountBackend + SupportBackend>(
    view: &granary_fuse::ViewHandle<DaemonBackend<B>>,
    owners: &crate::support_bundle::LiveOwners,
    bundled_at: granary_core::sheaf::Timestamp,
) -> Result<granary_core::support::BundleArchive, &'static str> {
    let cache = view
        .try_observe(|daemon| daemon.session.bundle_cache())
        .map_err(|(busy, _)| busy)
        .unwrap_or_else(|busy| Err(support_cache_refusal(busy)));
    owners.collect(bundled_at, cache)
}

#[cfg(any(test, target_os = "linux"))]
fn support_absence_after<E>(
    producer: Option<&control::SupportProducer>,
    operation: impl FnOnce() -> Result<(), E>,
    listed: impl FnOnce() -> std::io::Result<bool>,
) -> Result<(), E> {
    let result = operation();
    if result.is_ok()
        && matches!(listed(), Ok(false))
        && let Some(producer) = producer
    {
        producer.mark_absent();
    }
    result
}

/// `gran umount <mountpoint>` — PARSING ONLY. Modeled on [`crate::parse_verify`]:
/// one positional, no flags at all. The daemon section implements the verb
/// itself (`granary_fuse::detach_unmount`); this
/// crate constructs nothing from the returned path today.
pub(crate) fn parse_umount(args: &[OsString]) -> Result<PathBuf, String> {
    let mut positional: Vec<&OsString> = Vec::new();
    for arg in args {
        let text = arg.to_str().unwrap_or_default();
        if text.starts_with("--") {
            return Err(format!("unknown flag {text}"));
        }
        positional.push(arg);
    }
    let [mountpoint] = positional.as_slice() else {
        return Err(format!(
            "expected 1 positional argument (mountpoint), got {}",
            positional.len()
        ));
    };
    Ok(PathBuf::from(*mountpoint))
}

// ---------------------------------------------- Step 2: argv[0] dispatch

/// Whether this process was invoked as `mount.gran`. `/sbin/mount.gran`
/// is a SYMLINK to `gran` (`JuiceFS`'s model), not a separate binary, so
/// the only signal available is argv\[0\]'s FILE NAME — never the whole
/// path, since the symlink can live anywhere an administrator put it
/// and `mount(8)` itself invokes the helper by whatever path it found.
pub(crate) fn invoked_as_mount_gran(argv0: &OsStr) -> bool {
    Path::new(argv0).file_name() == Some(OsStr::new("mount.gran"))
}

/// One `mount(8)`-convention invocation, parsed but not yet translated:
/// `device dir [-o opt1,opt2,...]`. Repeated `-o` occurrences ACCUMULATE
/// (mount(8) itself allows this), and each comma-separated option is
/// either a bare `key` (a valueless flag) or `key=value`.
#[derive(Debug)]
struct MountGranInvocation {
    device: OsString,
    dir: OsString,
    options: Vec<(String, Option<String>)>,
}

/// Parse the `mount(8)` helper calling convention itself — positionals
/// and `-o` — without yet deciding what any option MEANS. Kept separate
/// from the translation below so the two can be tested independently:
/// a malformed invocation (wrong arity, a dangling `-o`) is a different
/// failure from a well-formed one naming an option `gran mount` does
/// not recognise.
fn parse_mount_gran_argv(args: &[OsString]) -> Result<MountGranInvocation, String> {
    let mut positional: Vec<&OsString> = Vec::new();
    let mut options: Vec<(String, Option<String>)> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "-o" {
            let value = it.next().ok_or_else(|| "-o needs a value".to_owned())?;
            let value = value
                .to_str()
                .ok_or_else(|| "-o: value is not valid UTF-8".to_owned())?;
            for opt in value.split(',') {
                if opt.is_empty() {
                    // `-o allow_other,,foreground` and a trailing comma
                    // are both mount(8)-legal; an empty slot names
                    // nothing and is silently skipped, matching how the
                    // real `mount` command's own `-o` parser treats it.
                    continue;
                }
                match opt.split_once('=') {
                    Some((k, v)) => options.push((k.to_owned(), Some(v.to_owned()))),
                    None => options.push((opt.to_owned(), None)),
                }
            }
            continue;
        }
        positional.push(arg);
    }
    let [device, dir] = positional.as_slice() else {
        return Err(format!(
            "mount.gran: expected 2 positional arguments (device, dir), got {}",
            positional.len()
        ));
    };
    Ok(MountGranInvocation {
        device: (*device).clone(),
        dir: (*dir).clone(),
        options,
    })
}

/// Translate a `mount.gran` invocation into `gran mount`'s own native
/// flag grammar, then parse THAT through [`parse_mount`] — the SAME
/// validation every native invocation gets, not a second copy of it.
///
/// **A machine-wide entry point requires `--root-key`.**
/// `mount.gran` therefore refuses `trust_server` and `manifest_root`
/// even though [`parse_mount`] would otherwise accept either — checked
/// HERE, after translation, because only this layer knows the process
/// arrived as `mount.gran` rather than a native `gran mount`
/// invocation; `parse_mount` itself has no argv\[0\] to consult.
///
/// # Errors
/// Whatever [`parse_mount_gran_argv`] or [`parse_mount`] reports, an
/// unrecognised or malformed `-o` option, or a trust mode other than `--root-key`.
pub(crate) fn parse_mount_gran(args: &[OsString]) -> Result<MountArgs, String> {
    // THE `-o` KEY VOCABULARY IS A RULE, NOT A LIST, and the rule is the
    // whole reason it can be documented in an fstab line or a systemd unit
    // without anyone memorising a table: **an `-o` key is the native long
    // flag with its leading `--` removed and every `-` replaced by `_`.**
    // `--trust-server` is `trust_server`, `--root-key` is `root_key`,
    // `--cache-dir` is `cache_dir`. `allow_other` additionally matches
    // libfuse's own spelling, which is what an operator coming from any
    // other FUSE filesystem will already type.
    //
    // Stated here because the invocation
    // shape (`device dir -o opt1,opt2`) does not determine
    // the key names — and an
    // invented list is a thing later documentation contradicts, while a
    // derivable rule is not. The arms below are exhaustive over the native
    // flags precisely so this rule has no exceptions to remember.
    let invocation = parse_mount_gran_argv(args)?;
    let mut native: Vec<OsString> = vec![invocation.device, invocation.dir];
    for (key, value) in invocation.options {
        match (key.as_str(), value) {
            ("trust_server", None) => native.push(OsString::from("--trust-server")),
            ("allow_other", None) => native.push(OsString::from("--allow-other")),
            ("foreground", None) => native.push(OsString::from("--foreground")),
            ("reset_floor", None) => native.push(OsString::from("--reset-floor")),
            ("force", None) => native.push(OsString::from("--force")),
            ("endpoint", Some(v)) => {
                native.push(OsString::from("--endpoint"));
                native.push(OsString::from(v));
            }
            ("pin", Some(v)) => {
                native.push(OsString::from("--pin"));
                native.push(OsString::from(v));
            }
            ("root_key", Some(v)) => {
                native.push(OsString::from("--root-key"));
                native.push(OsString::from(v));
            }
            ("manifest_root", Some(v)) => {
                native.push(OsString::from("--manifest-root"));
                native.push(OsString::from(v));
            }
            ("cache_dir", Some(v)) => {
                native.push(OsString::from("--cache-dir"));
                native.push(OsString::from(v));
            }
            ("seq", Some(v)) => {
                native.push(OsString::from("--seq"));
                native.push(OsString::from(v));
            }
            ("uid", Some(v)) => {
                native.push(OsString::from("--uid"));
                native.push(OsString::from(v));
            }
            ("gid", Some(v)) => {
                native.push(OsString::from("--gid"));
                native.push(OsString::from(v));
            }
            ("trust_server" | "allow_other" | "foreground" | "reset_floor" | "force", Some(_)) => {
                return Err(format!("mount.gran: -o {key} takes no value"));
            }
            (
                "endpoint" | "pin" | "root_key" | "manifest_root" | "cache_dir" | "seq" | "uid"
                | "gid",
                None,
            ) => {
                return Err(format!("mount.gran: -o {key} needs a value ({key}=...)"));
            }
            (other, _) => return Err(format!("mount.gran: unknown -o option {other}")),
        }
    }
    let parsed = parse_mount(&native)?;
    if parsed.trust_server || parsed.manifest_root.is_some() {
        return Err(
            "mount.gran: --trust-server and --manifest-root are refused for this entry point \
             — a machine-wide mount requires --root-key"
                .to_owned(),
        );
    }
    Ok(parsed)
}

// -------------------------------------------------- Step 3: pre-flight

/// Why [`mount_preflight`] refused, or could not finish. **Each variant
/// names the condition it found** rather than collapsing into
/// one generic "refused" — an operator acting on
/// this needs to know whether to `mkdir`, `umount` something else
/// first, or pass `--force`.
#[derive(Debug)]
pub(crate) enum MountPreflightError {
    NotFound(PathBuf),
    NotADirectory(PathBuf),
    /// The final component is a symlink. Never followed — same
    /// discipline as every other fsguard-routed open in this crate.
    Symlink(PathBuf),
    #[cfg_attr(
        not(any(test, target_os = "linux")),
        expect(
            dead_code,
            reason = "constructed only by mount_table::refuse_if_already_mounted's Linux arm \
                      — the only arm that can read /proc/self/mountinfo at all — which is \
                      live on Linux (mount_preflight, its unconditional caller, is \
                      reachable from main()'s own \"mount\" dispatch); on every other platform \
                      mount_preflight instead reaches the MountCheckUnsupported arm below, so \
                      this variant is never constructed there outside this module's own tests \
                      (the CONSTRUCTOR lives in the mount_table child, which is why the \
                      name is qualified; the tests that build this variant are this \
                      module's `tests`)"
        )
    )]
    AlreadyMounted(PathBuf),
    NotEmpty(PathBuf),
    /// The already-mounted check has no implementation on this OS, so
    /// the pre-flight refuses by name here rather than silently skipping
    /// it. `os` is [`std::env::consts::OS`], not a filesystem read.
    #[cfg_attr(
        all(target_os = "linux", not(test)),
        expect(
            dead_code,
            reason = "the EXACT MIRROR of `AlreadyMounted` above. \
                      Constructed only by \
                      `mount_table::refuse_if_already_mounted`'s NON-Linux arm, so on Linux \
                      nothing outside this module's own tests ever builds it. \
                      a plain build on a non-Linux host does not compile `granary-cli`'s \
                      Linux-gated code, and `CARGO_BUILD_WARNINGS=deny` turns this warning into \
                      failures in lint (clippy and the musl build) and test"
        )
    )]
    MountCheckUnsupported {
        os: &'static str,
    },
    Io {
        path: PathBuf,
        detail: String,
    },
}

impl std::fmt::Display for MountPreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "{}: no such directory", p.display()),
            Self::NotADirectory(p) => write!(f, "{}: not a directory", p.display()),
            Self::Symlink(p) => write!(
                f,
                "{}: a symlink, not a real mountpoint (symlinks are never followed)",
                p.display()
            ),
            Self::AlreadyMounted(p) => write!(f, "{}: already a mount point", p.display()),
            Self::NotEmpty(p) => write!(
                f,
                "{}: not empty (pass --force to mount over its contents)",
                p.display()
            ),
            Self::MountCheckUnsupported { os } => write!(
                f,
                "cannot check whether the mountpoint is already a mount point on {os} — gran \
                 mount's already-mounted pre-flight check reads /proc/self/mountinfo and only \
                 runs on Linux"
            ),
            Self::Io { path, detail } => write!(f, "{}: {detail}", path.display()),
        }
    }
}

impl std::error::Error for MountPreflightError {}

/// Step 3: refuse before anything touches `/dev/fuse`. libfuse itself
/// refuses NOTHING about a non-empty mountpoint or a double mount, so
/// `gran mount` implements its own: the mountpoint exists, is a
/// directory, is not already a mount, and is empty unless `force`.
///
/// **The existence/type/symlink check below uses `symlink_metadata`
/// (lstat), not `open_directory`.** A check that uses
/// `open_directory`'s `O_DIRECTORY | O_NOFOLLOW` open and classifies a
/// symlink by matching `ELOOP` on the raw errno — measured WRONG on this
/// box: macOS returns `ENOTDIR` (raw 20), not `ELOOP`, for that exact
/// open on a symlink pointing at a real directory (confirmed with a
/// standalone probe against the pinned toolchain, not assumed), so a
/// symlinked mountpoint would be silently misreported as
/// [`MountPreflightError::NotADirectory`] — a wrong condition name on the
/// one property this check makes load-bearing. `symlink_metadata` (the
/// clippy.toml-documented "safe half" of the fs-ban class, lstat-backed
/// and never banned) answers `is_symlink()` directly, with no errno
/// guessing and no platform divergence to rediscover on Linux CI.
///
/// # Errors
/// The first [`MountPreflightError`] to fire, in that order.
fn mount_preflight(mountpoint: &Path, force: bool) -> Result<(), MountPreflightError> {
    let meta = std::fs::symlink_metadata(mountpoint).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            MountPreflightError::NotFound(mountpoint.to_owned())
        } else {
            MountPreflightError::Io {
                path: mountpoint.to_owned(),
                detail: e.to_string(),
            }
        }
    })?;
    if meta.file_type().is_symlink() {
        return Err(MountPreflightError::Symlink(mountpoint.to_owned()));
    }
    if !meta.is_dir() {
        return Err(MountPreflightError::NotADirectory(mountpoint.to_owned()));
    }
    refuse_if_already_mounted(mountpoint)?;
    if !force {
        refuse_if_nonempty(mountpoint)?;
    }
    Ok(())
}

/// The mountpoint's emptiness has no `fsguard` primitive — that module
/// answers "does this exist, is it a directory, is it a symlink" but
/// not "how many entries does it have", and `mount_preflight`'s own
/// `symlink_metadata` check already answered those three, immediately
/// before this runs. `mountpoint` is re-resolved by this call, which is
/// the same accepted second check-then-use
/// [`refuse_if_already_mounted`]'s doc comment names.
#[expect(
    clippy::disallowed_methods,
    reason = "no fsguard primitive lists directory entries; mountpoint was already proved to \
              be a real, non-symlink directory by symlink_metadata in mount_preflight \
              immediately before this call — this is a second, accepted check-then-use, not \
              the first resolution of an unvalidated path"
)]
fn refuse_if_nonempty(mountpoint: &Path) -> Result<(), MountPreflightError> {
    let mut entries = std::fs::read_dir(mountpoint).map_err(|e| MountPreflightError::Io {
        path: mountpoint.to_owned(),
        detail: e.to_string(),
    })?;
    // `ReadDir::next()` yields `Option<io::Result<DirEntry>>`, and an
    // `is_some()` here would count a FAILED enumeration as proof the
    // directory is non-empty. The
    // shape is fail-SAFE — it refuses rather than mounting — but the
    // refusal it produces is `NotEmpty`, whose message tells the operator
    // to pass `--force`. Following that advice would bypass an emptiness
    // check that never actually ran, on a directory whose real problem was
    // an I/O error the operator was never shown. A refusal that names the
    // wrong condition sends the operator at the wrong remedy.
    first_entry_verdict(entries.next(), mountpoint)
}

/// The three-way decision `refuse_if_nonempty` makes about the first
/// directory entry, extracted so it can be TESTED.
///
/// `ReadDir::next()`'s error arm is not constructible in process — it
/// needs an enumeration that fails midway, which no portable fixture can
/// force — so a version of this living inline would have its most
/// interesting branch reachable only on a filesystem misbehaving in CI.
/// Generic over the item because `DirEntry` has no public constructor
/// either; the decision never looks at the entry, only at whether there
/// was one.
fn first_entry_verdict<T>(
    first: Option<std::io::Result<T>>,
    mountpoint: &Path,
) -> Result<(), MountPreflightError> {
    match first {
        None => Ok(()),
        Some(Ok(_)) => Err(MountPreflightError::NotEmpty(mountpoint.to_owned())),
        Some(Err(e)) => Err(MountPreflightError::Io {
            path: mountpoint.to_owned(),
            detail: e.to_string(),
        }),
    }
}

// ------------------------------------------ Step 8: the exit-code mapping

/// `gran mount`'s and `gran umount`'s exit-code classification
/// — the numbers stated in [`MOUNT_HELP`]. A PURE function so
/// the daemon and shutdown coordinator can classify their own
/// outcome and get back the number this help text promises,
/// without re-deriving the mapping at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountOutcome {
    /// The mount served, then unmounted cleanly (or `gran umount`
    /// detached it), with nothing left to report.
    Clean,
    /// Any failure that is neither a usage error nor the cache-close
    /// case below: `Session::run` failing, a pre-flight refusal, a
    /// resolve/anchor failure, ...
    RuntimeFailure,
    /// A usage error — matches [`crate::usage`]'s own code. **Never
    /// constructed outside this module's own tests today**: every
    /// `cmd_mount`/`cmd_umount` early return that fires before
    /// `parse_mount`/`parse_umount` themselves would have already
    /// failed goes through `RuntimeFailure` instead, so this split adds no
    /// production call that builds this specific variant — it exists so
    /// a caller COULD reuse `usage()`'s own code through this
    /// classification (`mount_exit_code_usage_matches_usage_fn` pins
    /// that the two agree) without daemon code ever needing to.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no production call site constructs this variant — parse failures return \
                      usage() directly (main()'s own dispatch), never through this \
                      classification; kept for the exit-code CONTRACT this enum states and \
                      that this module's own tests assert against usage()'s real code"
        )
    )]
    Usage,
    /// The mount (or `gran umount`) unwound cleanly, but the cache
    /// could not be closed — DISTINCT from `RuntimeFailure` so a script
    /// driving this exit code can tell "the read path failed" from
    /// "everything served correctly and only the final housekeeping
    /// write did not".
    CacheCloseFailed,
    /// A writable mount's shutdown was stopped by its bound or by a further
    /// stop signal before it finished: nothing was lost, and the overlay, staging
    /// and intent are kept for the next start.
    #[cfg_attr(
        not(any(test, target_os = "linux")),
        expect(
            dead_code,
            reason = "constructed only by mount_shutdown_outcome, whose production caller \
                      is the target_os = \"linux\"-gated daemon; this module's own tests \
                      construct it on every platform"
        )
    )]
    Stopped,
    /// The authority fenced a writable mount's ownership or its commit: the
    /// overlay is kept and its recovery is explicit.
    #[cfg_attr(
        not(any(test, target_os = "linux")),
        expect(
            dead_code,
            reason = "constructed only by mount_shutdown_outcome, whose production caller \
                      is the target_os = \"linux\"-gated daemon; this module's own tests \
                      construct it on every platform"
        )
    )]
    Fenced,
}

pub(crate) fn mount_exit_code(outcome: MountOutcome) -> ExitCode {
    match outcome {
        MountOutcome::Clean => ExitCode::from(0),
        MountOutcome::RuntimeFailure => ExitCode::from(1),
        MountOutcome::Usage => ExitCode::from(2),
        MountOutcome::CacheCloseFailed => ExitCode::from(3),
        MountOutcome::Stopped => ExitCode::from(4),
        MountOutcome::Fenced => ExitCode::from(5),
    }
}

// ============================================================
// The daemon, the shutdown coordinator, and `gran umount`. Everything
// up to here was pure parsing/pre-flight; everything below is what
// wires it to a real `fuser::Session` and gives it a correct shutdown.
//
// **Every decision this coordinator makes is a named function taking
// plain values** — that is this section's own rule, which made it
// possible to construct mutations against its tests:
// a choice living inside a thread closure or after
// `Session::new` is one no test can reach. [`Exit`],
// [`mount_shutdown_outcome`] and [`run_coordinator`] below need no
// `fuser::Session`, no kernel and no real signal to test — the actual
// thread/channel/`SessionUnmounter` wiring that calls them is
// `#[cfg(target_os = "linux")]`, at the bottom of this section, and is
// deliberately thin: everything it could delegate to a plain function
// already has been.
// ============================================================

/// What reaches the shutdown coordinator, on its one channel:
///
/// - `SessionEnded`: the session thread's own `Session::run` returned, for
///   ANY reason — a clean unmount, an I/O error, or (the arm most easily
///   forgotten) an EXTERNAL unmount that ended the session with no signal
///   delivered at all. **This is why the coordinator cannot wait on signals
///   alone**. The session thread's guard sends it on a panic too.
/// - `Signal(name)`: a signal thread received SIGINT or SIGTERM; it sends one
///   per delivery. `name` is `"SIGINT"` or `"SIGTERM"`.
/// - `Teardown`: the kernel session has ended and `destroy` is running; the
///   first statement of the daemon backend's shutdown sends it.
/// - `Outcome(report)`: a pre-unmount shutdown thread answered; each such thread
///   sends exactly one (`OutcomeGuard`).
/// - `ControlUmount`: an authenticated owner requested shutdown; the control
///   loop sends at most one, before registering its subscribers.
/// - `ControlError`: a once-per-kind transient accept warning or fatal service
///   loss. It is reported without ending the mount or changing shutdown.
///
/// No payload on `SessionEnded`: `Session::run`'s own `io::Result<()>` is
/// authoritative from the join, when it happens, rather than from whichever
/// message won the race — carrying it twice would invite the two to
/// disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "produced only by run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own tests construct and match on it directly on every platform, \
                  which is what proves the type and run_coordinator's own logic without a \
                  kernel"
    )
)]
enum Exit {
    SessionEnded,
    Signal(&'static str),
    Teardown,
    Outcome(granary_client::ShutdownReport),
    /// The control service enqueued its first admitted owner request.
    ControlUmount,
    /// A control transport failure; reporting loss never ends the FUSE session.
    ControlError {
        kind: std::io::ErrorKind,
        fatal: bool,
    },
}

/// How long a daemon waits, after its unmount, for the kernel to begin
/// tearing its session down. Once [`Exit::Teardown`] has arrived the wait is
/// for `destroy` itself, whose cache close may compact, and has no bound of
/// the daemon's own; a further signal, or the service manager's stop
/// timeout, ends it.
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        dead_code,
        reason = "read only by run_fuse_daemon, itself target_os = \"linux\"-gated; this \
                  module's own tests pass shorter graces to run_coordinator directly"
    )
)]
const SESSION_END_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// How the session thread ended, as far as the daemon could see it.
#[derive(Debug)]
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "built only by session_verdict, whose production caller is the target_os = \
                  \"linux\"-gated daemon; this module's own tests build every variant"
    )
)]
enum SessionVerdict {
    /// The session thread was joined, and its end classified.
    Joined(granary_fuse::SessionEnd),
    /// The session thread panicked.
    Panicked,
    /// The daemon stopped waiting without joining it, with whether the mount
    /// was still in the table then.
    NotJoined { listed: std::io::Result<bool> },
}

/// The daemon's exit, from what its shutdown, its session and its cache
/// reported — plain values in, a [`MountOutcome`] out, first match wins:
///
/// 1. **The data.** A fenced shutdown is [`MountOutcome::Fenced`], one cut by
///    its bound or a further signal [`MountOutcome::Stopped`], one that failed
///    or was lost a runtime failure, and so is an attached `engine` with no
///    report at all: `destroy` found the adapter's lock poisoned and
///    abandoned instead, or the session thread itself panicked. A script's
///    next action depends on these — preserve a kept store, recover a fenced
///    one — so they outrank the session, whose diagnostics are emitted
///    either way.
/// 2. **The session and the unflushed store.** A join that did not classify
///    clean, a panic, a daemon that stopped waiting with the mount still
///    listed or unverifiable, or an engine-less writable backend's
///    `WritableShutdownCoordinationFailed:` close string, is a runtime
///    failure.
/// 3. **The cache.** A close error, or a daemon that stopped waiting with
///    the mount gone (so `destroy` never closed the cache), is
///    [`MountOutcome::CacheCloseFailed`]; everything else is clean.
///
/// A kept shutdown is therefore never 0; a released one is 0 or 3 when its
/// session ended clean or its daemon gave up with the mount gone, and 1
/// otherwise.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own tests call it directly with plain values on every platform, \
                  needing no fuser::Session anywhere near it"
    )
)]
fn mount_shutdown_outcome(
    report: Option<granary_client::ShutdownReport>,
    engine: bool,
    session: &SessionVerdict,
    cache: Option<Result<(), String>>,
) -> MountOutcome {
    use granary_client::{ShutdownCause, ShutdownOutcome};
    match report.map(|report| report.outcome) {
        Some(ShutdownOutcome::Fenced) => return MountOutcome::Fenced,
        Some(ShutdownOutcome::Incomplete(ShutdownCause::Deadline)) => {
            return MountOutcome::Stopped;
        }
        Some(ShutdownOutcome::Incomplete(_)) => return MountOutcome::RuntimeFailure,
        None if engine => return MountOutcome::RuntimeFailure,
        Some(ShutdownOutcome::Committed(_) | ShutdownOutcome::Clean) | None => (),
    }
    let unflushed = cache.as_ref().is_some_and(|close| {
        close
            .as_ref()
            .is_err_and(|error| error.starts_with("WritableShutdownCoordinationFailed:"))
    });
    let gone_unjoined = matches!(session, SessionVerdict::NotJoined { listed: Ok(false) });
    let clean = matches!(
        session,
        SessionVerdict::Joined(granary_fuse::SessionEnd::Clean)
    );
    if unflushed || !(clean || gone_unjoined) {
        return MountOutcome::RuntimeFailure;
    }
    if gone_unjoined || cache.is_some_and(|close| close.is_err()) {
        return MountOutcome::CacheCloseFailed;
    }
    MountOutcome::Clean
}

#[cfg(any(test, target_os = "linux"))]
fn finish_control(
    control: control::Control,
    report: Option<granary_client::ShutdownReport>,
    engine: bool,
    session: &SessionVerdict,
    cache_close: impl FnOnce() -> Option<Result<(), String>>,
) -> MountOutcome {
    let outcome = mount_shutdown_outcome(report, engine, session, cache_close());
    control.finish(outcome, report);
    outcome
}

#[cfg(any(test, target_os = "linux"))]
fn start_control<T>(
    target: &DetachTarget,
    start: impl FnOnce(&Path) -> std::io::Result<T>,
    report: impl FnOnce(std::fmt::Arguments<'_>),
) -> Option<T> {
    let target = match target {
        DetachTarget::Resolved(target) => target,
        DetachTarget::Unavailable(why) => {
            report(format_args!(
                "gran mount: control endpoint unavailable: {}",
                why.message
            ));
            return None;
        }
    };
    match start(target) {
        Ok(control) => Some(control),
        Err(error) => {
            report(format_args!(
                "gran mount: control endpoint unavailable: {error}"
            ));
            None
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn start_support<T>(
    target: &DetachTarget,
    start: impl FnOnce(&Path) -> std::io::Result<T>,
    report: impl FnOnce(std::fmt::Arguments<'_>),
) -> Option<T> {
    let DetachTarget::Resolved(target) = target else {
        report(format_args!("gran mount: support producer unavailable"));
        return None;
    };
    if let Ok(support) = start(target) {
        Some(support)
    } else {
        report(format_args!("gran mount: support producer unavailable"));
        None
    }
}

#[cfg(any(test, target_os = "linux"))]
fn control_mount_key(
    observed: std::io::Result<Vec<mount_table::ControlMount>>,
    owner: u32,
    report: impl FnOnce(std::fmt::Arguments<'_>),
) -> Option<granary_core::mount_control::MountKey> {
    let reason = match observed {
        Ok(observed) => match observed.as_slice() {
            [mount] if mount.owner == owner => return Some(mount.key),
            [mount] => format!(
                "kernel FUSE owner {} differs from admitted owner {owner}",
                mount.owner
            ),
            _ => format!(
                "expected exactly one granary FUSE row, found {}",
                observed.len()
            ),
        },
        Err(error) => error.to_string(),
    };
    report(format_args!(
        "gran mount: control mount identity/owner capture failed: {reason}"
    ));
    None
}

fn report_control_error(kind: std::io::ErrorKind, fatal: bool) {
    if fatal {
        crate::terminal::write_line(format_args!(
            "gran mount: control service failed ({kind:?}); owner umount falls back to detach with unknown shutdown outcome; the mount and signal path remain available"
        ));
    } else {
        crate::terminal::write_line(format_args!(
            "gran mount: control accept failed ({kind:?}); retrying"
        ));
    }
}

/// The session's verdict, with its diagnostic.
///
/// Every join goes through [`granary_fuse::classify_session_end`]. `listed`
/// is read after the join, so fuser's own drop-unmount has already run; the
/// daemon never writes its connection's `abort`, so no end is forced. An
/// `ECONNABORTED` that raced the unmount's teardown with the mount gone is
/// the clean end the classifier names, recorded at debug level; a clean
/// event-loop end with the mount gone emits nothing; every other verdict is
/// warned about. A daemon that did not join reports both the mount table
/// and fusectl observations.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own tests call it directly with plain io::Error values on every \
                  platform, needing no fuser::Session anywhere near it"
    )
)]
fn session_verdict(
    unmount: std::io::Result<()>,
    joined: Option<std::thread::Result<std::io::Result<()>>>,
    listed: impl FnOnce() -> std::io::Result<bool>,
    connection_alive: impl FnOnce() -> Option<bool>,
) -> SessionVerdict {
    let joined = match joined {
        None => {
            use granary_client::{FuseConnection, MountListing};

            let listed = listed();
            let listing = match &listed {
                Ok(false) => MountListing::Gone,
                Ok(true) => MountListing::Listed,
                Err(_) => MountListing::Unknown,
            };
            let connection = match connection_alive() {
                Some(true) => FuseConnection::Alive,
                Some(false) => FuseConnection::Gone,
                None => FuseConnection::Unknown,
            };
            granary_client::OperatorDiagnostic::gran_mount_the_fuse_session_did_not_end_after_its_unmount(
                listing,
                connection,
            )
            .emit();
            return SessionVerdict::NotJoined { listed };
        }
        Some(Err(_panic)) => {
            granary_client::OperatorDiagnostic::gran_mount_the_fuse_session_thread_panicked()
                .emit();
            return SessionVerdict::Panicked;
        }
        Some(Ok(joined)) => joined,
    };
    let raced = joined.is_err();
    let end = granary_fuse::classify_session_end(granary_fuse::SessionEndEvidence {
        unmount,
        joined,
        forced: false,
        listed: listed(),
    });
    match (&end, raced) {
        (granary_fuse::SessionEnd::Clean, true) => {
            granary_client::OperatorDiagnostic::gran_mount_the_fuse_session_ended_econnaborted_racing_its_unmount()
                .emit();
        }
        (granary_fuse::SessionEnd::Clean, false) => (),
        _ => {
            granary_client::OperatorDiagnostic::gran_mount_the_fuse_session_ended_with_an_error(
                granary_client::FailureClass::Io,
            )
            .emit();
        }
    }
    SessionVerdict::Joined(end)
}

/// The unmount the classifier weighs: on the session-end path the kernel's
/// own, so `Ok(())`; on the signal path the daemon's unmount, or its detach
/// when the unmount failed, which succeeds once the detach does (a busy
/// root mount's `EBUSY`).
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own tests call it directly on every platform"
    )
)]
fn unmount_evidence(
    arm: Exit,
    unmount: std::io::Result<()>,
    detach: Option<Result<(), granary_client::FailureClass>>,
) -> std::io::Result<()> {
    match (arm, unmount, detach) {
        (Exit::SessionEnded, _, _) | (_, Ok(()), _) | (_, Err(_), Some(Ok(()))) => Ok(()),
        (_, Err(error), _) => Err(error),
    }
}

/// The identity of the mount at the resolved detach target, captured once
/// the session exists and before it serves, so that the end of the session
/// can ask whether THIS mount is still in the table wherever it has moved
/// since.
///
/// A failed capture is returned as the error the end of the session will
/// read, so a mount whose presence cannot be checked never classifies as
/// gone, and it is warned about once here with its class. An unavailable
/// target was already reported at startup and is not reported again.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own tests call it directly on every platform, needing no \
                  fuser::Session anywhere near it"
    )
)]
fn capture_mount_identity(target: &DetachTarget) -> std::io::Result<granary_fuse::MountIdentity> {
    match target {
        DetachTarget::Resolved(path) => {
            granary_fuse::MountIdentity::capture(path).inspect_err(|error| {
                let class = match error.kind() {
                    std::io::ErrorKind::InvalidData => granary_client::FailureClass::Corrupt,
                    std::io::ErrorKind::NotFound => granary_client::FailureClass::Unavailable,
                    _ => granary_client::FailureClass::Io,
                };
                granary_client::OperatorDiagnostic::gran_mount_could_not_capture_the_mount_identity(
                    class,
                )
                .emit();
            })
        }
        DetachTarget::Unavailable(why) => Err(std::io::Error::other(why.message.clone())),
    }
}

/// What the shutdown coordinator did, in the order it did it.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "constructed only inside run_coordinator, itself called only from \
                  run_fuse_daemon (target_os = \"linux\"-gated) — this module's own tests read \
                  every field directly on every platform, needing no fuser::Session/kernel \
                  anywhere near it"
    )
)]
struct Coordinated<T> {
    /// The first stop request or session end; a `Teardown` before it is counted in
    /// `teardown_seen`.
    arm: Exit,
    unmount: std::io::Result<()>,
    /// `None` when `unmount` succeeded and no fallback was needed.
    detach: Option<Result<(), granary_client::FailureClass>>,
    /// `None` when the session thread was not joined: the daemon stopped
    /// waiting for its session to end.
    joined: Option<T>,
    /// The report a pre-unmount shutdown thread answered, before the unmount.
    report: Option<granary_client::ShutdownReport>,
    /// Every signal received, the first included.
    #[cfg_attr(
        all(not(test), target_os = "linux"),
        expect(
            dead_code,
            reason = "held so a TEST can count the signals the coordinator acted on; \
                      run_coordinator has already acted on each one, and run_fuse_daemon \
                      needs only what they led to"
        )
    )]
    signals: usize,
    /// Whether `destroy` announced that it was running.
    #[cfg_attr(
        all(not(test), target_os = "linux"),
        expect(
            dead_code,
            reason = "held so a TEST can see whether the teardown notice arrived; \
                      run_coordinator has already acted on it by lifting the grace"
        )
    )]
    teardown_seen: bool,
}

/// How the coordinator stops a writable mount's engine before its unmount.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "built only by run_fuse_daemon, itself target_os = \"linux\"-gated; this \
                  module's own tests build it with fake closures on every platform"
    )
)]
struct EngineStop<S, X> {
    /// Begin the shutdown on a thread of its own, which answers with exactly
    /// one [`Exit::Outcome`]; `Err` when that thread could not be spawned,
    /// and then nothing was begun.
    start: S,
    /// Cut the shutdown, running or not yet begun.
    expire: X,
}

/// The shutdown coordinator, minus everything that needs a kernel: one
/// channel of [`Exit`] in, the order of the ending out.
///
/// **Serving.** The first `Signal` or `ControlUmount`, for a writable mount
/// with an engine (`stop`), calls `start` with its distinct trigger. Only a
/// signal emits the received-signal diagnostic:
/// the shutdown runs BEFORE the unmount, while the adapter still serves, so
/// its outcome is a message on this channel and never depends on the join.
/// A failed `start`, or a mount with no engine, goes straight to the
/// unmount; `destroy` then runs the sequence on the session-end path, and
/// its outcome is read from the handle after the join. A `SessionEnded`
/// (an external unmount) goes straight to the unmount too: an idempotent
/// call when the mount is already gone.
///
/// **Stopping.** Every later `Signal` calls `expire`, which cuts the
/// sequence at its next poll; controls only subscribe, and `Teardown` and
/// `SessionEnded` are noted. The
/// wait ends at the `Outcome`, which the sequence answers within its bound
/// and margin.
///
/// **Unmounting.** The unmount makes the kernel end the session's
/// `/dev/fuse` read so that `run` can return. A failed unmount — a busy root
/// mount's `EBUSY` — is warned about and falls back to `detach`
/// (`MNT_DETACH`), which removes the mount from the table at once. Neither
/// is a promise that the session ends soon: a non-root daemon's unmount is
/// fuser's lazy `fusermount -u -z`, which answers `Ok` with a descriptor
/// still held, and a detached connection lives until its last close.
///
/// **Draining.** So the join waits for `SessionEnded` on the channel, never
/// blindly: a join that follows one returns as soon as the session thread's
/// closure ends. Before `Teardown` an absolute `grace` deadline on `now` covers
/// only the kernel's teardown after an unmount with nothing held; when it
/// runs out the daemon exits without the join, and the process exit closes
/// `/dev/fuse`. Once `Teardown` has arrived the wait is for `destroy`,
/// whose cache close is not the daemon's to cut. A signal while draining
/// ends the wait, except where an engine's sequence may still be running
/// in `destroy` (no report yet): it is expired instead, and the wait goes on
/// while `Teardown` says that sequence is running and will answer.
///
/// **Pulled out of the real wiring so it is testable without any of it.**
/// `rx` is a real `mpsc::Receiver<Exit>`, but `start`, `expire`, `unmount`,
/// `detach` and `join` are closures a test can substitute to observe call
/// ORDER while keeping every `fuser::Session`, kernel and tokio runtime out
/// of the test binary. `join`'s return type is generic so a test can hand
/// back a plain marker while production hands back the real
/// `std::thread::Result<std::io::Result<()>>`.
///
/// A channel with every sender dropped has no real trigger in production:
/// the daemon keeps a sender for `start`. It is still handled rather than
/// `.unwrap()`'d — this crate denies `unwrap_used` — as a session that
/// ended without saying why.
///
/// **`unmount`'s own `Result` is reported, not discarded**: it is logged
/// where it fails and returned, so a caller can weigh it without
/// re-deriving it from `joined`.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own tests drive it with a real mpsc::Receiver plus fake \
                  closures on every platform, needing no fuser::Session/kernel anywhere near it"
    )
)]
#[expect(
    clippy::too_many_lines,
    reason = "one state loop keeps begin-before-unmount and bounded draining order visible"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the coordinator also owns cancellation of the optional listener"
)]
fn run_coordinator<T, S, X>(
    rx: &std::sync::mpsc::Receiver<Exit>,
    metrics: Option<granary_net::metrics_listener::Listener>,
    stop: Option<EngineStop<S, X>>,
    unmount: impl FnOnce() -> std::io::Result<()>,
    detach: impl FnOnce() -> Result<(), granary_client::FailureClass>,
    join: impl FnOnce() -> T,
    grace: std::time::Duration,
    now: impl Fn() -> tokio::time::Instant,
) -> Coordinated<T>
where
    S: FnOnce(granary_client::ShutdownTrigger) -> std::io::Result<()>,
    X: Fn(),
{
    let (start, expire) = match stop {
        Some(EngineStop { start, expire }) => (Some(start), Some(expire)),
        None => (None, None),
    };
    let mut teardown = false;
    let mut ended = false;
    let mut signals = 0_usize;
    let mut report = None;
    // Serving: no shutdown thread runs yet, so no outcome can arrive.
    let arm = loop {
        match rx.recv().unwrap_or(Exit::SessionEnded) {
            Exit::Teardown => teardown = true,
            Exit::Outcome(_) => (),
            Exit::ControlError { kind, fatal } => report_control_error(kind, fatal),
            arm @ (Exit::Signal(_) | Exit::ControlUmount | Exit::SessionEnded) => break arm,
        }
    };
    drop(metrics);
    let stopping = match arm {
        Exit::Signal(name) => {
            signals += 1;
            granary_client::OperatorDiagnostic::gran_mount_received_signal_unmounting(
                granary_client::SignalKind::from_adapter(name),
            )
            .emit();
            start.is_some_and(|start| start(granary_client::ShutdownTrigger::Signal).is_ok())
        }
        Exit::ControlUmount => {
            start.is_some_and(|start| start(granary_client::ShutdownTrigger::Umount).is_ok())
        }
        _ => {
            ended = true;
            false
        }
    };
    // Stopping: the sequence answers within its bound and margin.
    if stopping {
        loop {
            match rx.recv() {
                Ok(Exit::Signal(_)) => {
                    signals += 1;
                    if let Some(expire) = &expire {
                        expire();
                    }
                }
                Ok(Exit::Teardown) => teardown = true,
                Ok(Exit::ControlUmount) => (),
                Ok(Exit::ControlError { kind, fatal }) => report_control_error(kind, fatal),
                Ok(Exit::SessionEnded) => ended = true,
                Ok(Exit::Outcome(answer)) => {
                    report = Some(answer);
                    break;
                }
                // Every sender is gone, so no outcome can come.
                Err(_) => {
                    ended = true;
                    break;
                }
            }
        }
    }
    let (unmount_result, detach_result) = unmount_or_detach(unmount, detach);
    // Draining: the join only ever follows a `SessionEnded`.
    let mut expired = false;
    let grace_end = now().checked_add(grace);
    let joined = loop {
        if ended {
            break Some(join());
        }
        let next = if teardown {
            rx.recv()
                .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected)
        } else {
            let remaining = grace_end.map_or(std::time::Duration::ZERO, |end| {
                end.saturating_duration_since(now())
            });
            if remaining.is_zero() {
                break None;
            }
            rx.recv_timeout(remaining)
        };
        match next {
            Ok(Exit::SessionEnded) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                ended = true;
            }
            Ok(Exit::Teardown) => teardown = true,
            // Each shutdown thread sends one outcome, already taken.
            Ok(Exit::Outcome(_) | Exit::ControlUmount) => (),
            Ok(Exit::ControlError { kind, fatal }) => report_control_error(kind, fatal),
            Ok(Exit::Signal(_)) => {
                signals += 1;
                match (&expire, report) {
                    // A sequence `destroy` runs, or has yet to run, is cut;
                    // once it is running it answers, and the session end
                    // follows. A signal after that cut ends the wait for
                    // `destroy`'s cache close too.
                    (Some(expire), None) if !expired => {
                        expire();
                        expired = true;
                        if !teardown {
                            break None;
                        }
                    }
                    _ => break None,
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break None,
        }
    };
    Coordinated {
        arm,
        unmount: unmount_result,
        detach: detach_result,
        joined,
        report,
        signals,
        teardown_seen: teardown,
    }
}

/// Unmount, and when that fails, warn and fall back to `detach`, warning
/// with its outcome too: the unmount's result, and the detach's when it ran.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_coordinator, whose production caller is the \
                  target_os = \"linux\"-gated daemon"
    )
)]
fn unmount_or_detach(
    unmount: impl FnOnce() -> std::io::Result<()>,
    detach: impl FnOnce() -> Result<(), granary_client::FailureClass>,
) -> (
    std::io::Result<()>,
    Option<Result<(), granary_client::FailureClass>>,
) {
    let unmounted = unmount();
    if unmounted.is_ok() {
        return (unmounted, None);
    }
    granary_client::OperatorDiagnostic::gran_mount_unmount_failed_falling_back_to_a_lazy(
        granary_client::FailureClass::Io,
    )
    .emit();
    let detached = detach();
    match &detached {
        Ok(()) => {
            granary_client::OperatorDiagnostic::gran_mount_the_mount_was_lazily_detached_mnt_detach().emit();
        }
        Err(detach_error) => {
            granary_client::OperatorDiagnostic::gran_mount_both_the_plain_unmount_and_the_mnt(
                granary_client::FailureClass::Io,
                *detach_error,
            )
            .emit();
        }
    }
    (unmounted, Some(detached))
}

/// A writable mount's shutdown as the daemon drives it: implemented by the
/// engine's [`granary_client::ShutdownHandle`] and by the tests' fake, so
/// the coordinator's rows need no engine.
#[cfg(any(test, target_os = "linux"))]
trait DaemonStop: Send + Sync {
    /// Run the requested shutdown, while the session serves, and
    /// answer its report.
    fn begin(&self, trigger: granary_client::ShutdownTrigger) -> granary_client::ShutdownReport;
    /// Cut it, running or not yet begun.
    #[cfg_attr(
        all(test, not(target_os = "linux")),
        expect(
            dead_code,
            reason = "called by the target_os = \"linux\"-gated daemon's coordinator closure; \
                      this module's portable rows drive the coordinator with closures of their \
                      own"
        )
    )]
    fn expire(&self);
    /// The report of a shutdown that has ended, `None` before it has.
    fn report(&self) -> Option<granary_client::ShutdownReport>;
}

#[cfg(target_os = "linux")]
impl DaemonStop for granary_client::ShutdownHandle {
    fn begin(&self, trigger: granary_client::ShutdownTrigger) -> granary_client::ShutdownReport {
        granary_client::ShutdownHandle::begin(self, trigger)
    }
    fn expire(&self) {
        granary_client::ShutdownHandle::expire(self);
    }
    fn report(&self) -> Option<granary_client::ShutdownReport> {
        granary_client::ShutdownHandle::report(self)
    }
}

/// Sends the one [`Exit::Outcome`] each pre-unmount shutdown thread owes: its
/// report through [`OutcomeGuard::send`] when `begin` returns, or a lost
/// one from its `Drop` when `begin` unwinds.
///
/// Unlike [`SessionEndedGuard`], which sends on every exit because its
/// thread has no other send, this guard is disarmed by its normal send, so
/// each shutdown thread sends exactly one `Outcome`, and the coordinator,
/// which waits for exactly one, never reads a second as the answer.
#[cfg(any(test, target_os = "linux"))]
struct OutcomeGuard(Option<std::sync::mpsc::Sender<Exit>>);

#[cfg(any(test, target_os = "linux"))]
impl OutcomeGuard {
    fn send(mut self, report: granary_client::ShutdownReport) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(Exit::Outcome(report));
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
impl Drop for OutcomeGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(Exit::Outcome(granary_client::ShutdownReport::lost()));
        }
    }
}

/// Begin `stop`'s shutdown on a `granary-shutdown` thread that answers with
/// one [`Exit::Outcome`] on `tx`, whether `begin` returns or unwinds.
///
/// # Errors
///
/// The thread could not be spawned, and nothing was begun.
#[cfg(any(test, target_os = "linux"))]
fn start_shutdown(
    stop: std::sync::Arc<dyn DaemonStop>,
    tx: std::sync::mpsc::Sender<Exit>,
    trigger: granary_client::ShutdownTrigger,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("granary-shutdown".into())
        .spawn(move || {
            let guard = OutcomeGuard(Some(tx));
            let report = stop.begin(trigger);
            guard.send(report);
        })
        .map(drop)
}

/// The shutdown's report: the pre-unmount worker's message, else what the handle
/// holds once `destroy` has run the sequence on the session-end path.
#[cfg(any(test, target_os = "linux"))]
fn shutdown_report(
    message: Option<granary_client::ShutdownReport>,
    stop: Option<&dyn DaemonStop>,
) -> Option<granary_client::ShutdownReport> {
    message.or_else(|| stop.and_then(DaemonStop::report))
}

/// The one line a writable daemon prints as it exits, from its shutdown's
/// report and the operator's own `--store-dir` as given; `None` for a
/// read-only mount (`ending` is `None`), which prints nothing.
///
/// A stopped shutdown's line names what actually cut it, from the report's
/// recorded cut. Every kept outcome names the store and what the next start
/// does with it: interrupted non-fenced state can finish before serving, while
/// fenced or damaged state requires explicit recovery.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own tests call it directly on every platform"
    )
)]
fn shutdown_status_line(
    command: &str,
    ending: Option<(Option<granary_client::ShutdownReport>, &Path)>,
) -> Option<String> {
    use granary_client::{ShutdownCause, ShutdownCut, ShutdownOutcome};
    use std::os::unix::ffi::OsStrExt as _;
    let (report, store) = ending?;
    let store = escaped_path(store.as_os_str().as_bytes());
    let refused = "preserve it; the next mount with this store can finish interrupted non-fenced shutdown before serving; fenced or damaged state needs explicit recovery";
    let Some(report) = report else {
        return Some(format!(
            "{command}: the shutdown did not run; the overlay is kept in {store}: {refused}"
        ));
    };
    let ms = report.elapsed_ms;
    let left = report.residue.map_or_else(
        || "what was left could not be read".to_owned(),
        |left| {
            format!(
                "{} files ({} bytes) unsynced, {} operations uncommitted",
                left.files, left.bytes, left.operations
            )
        },
    );
    let kept = format!("the overlay, staging and intent are kept in {store}: {refused}");
    Some(match report.outcome {
        ShutdownOutcome::Committed(seq) => {
            format!("{command}: shutdown committed seq={seq} in {ms} ms")
        }
        ShutdownOutcome::Clean => format!("{command}: shutdown had nothing to commit"),
        ShutdownOutcome::Incomplete(ShutdownCause::Deadline) => {
            let by = match report.cut {
                Some(ShutdownCut::Signal) => "by a signal",
                Some(ShutdownCut::Bound) => "at its bound",
                None => "; the cut was not recorded",
            };
            let separator = if report.cut.is_none() { "" } else { " " };
            format!("{command}: shutdown stopped{separator}{by} after {ms} ms: {left}; {kept}")
        }
        ShutdownOutcome::Incomplete(ShutdownCause::Failed(class)) => format!(
            "{command}: shutdown failed ({}) after {ms} ms: {left}; {kept}",
            class.as_str()
        ),
        ShutdownOutcome::Incomplete(ShutdownCause::Internal) => {
            format!("{command}: shutdown lost its sequence after {ms} ms: {left}; {kept}")
        }
        ShutdownOutcome::Fenced => format!(
            "{command}: shutdown fenced after {ms} ms: {left}; the authority refused this mount's \
             ownership or its commit; the overlay is kept in {store}: preserve it; recovery is \
             explicit"
        ),
    })
}

fn escaped_path(path: &[u8]) -> String {
    path.iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

#[cfg(any(test, target_os = "linux"))]
fn mount_status_line(
    command: &str,
    ending: Option<(Option<granary_client::ShutdownReport>, &Path)>,
    outcome: MountOutcome,
) -> String {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    let mut line = shutdown_status_line(command, ending)
        .unwrap_or_else(|| format!("{command}: read-only daemon ending"));
    if let Some((report, store)) = ending {
        match report {
            Some(report)
                if matches!(
                    report.outcome,
                    granary_client::ShutdownOutcome::Committed(_)
                        | granary_client::ShutdownOutcome::Clean
                ) =>
            {
                if matches!(report.outcome, granary_client::ShutdownOutcome::Clean) {
                    let _ = write!(line, " in {} ms", report.elapsed_ms);
                }
                let _ = write!(
                    line,
                    "; store {}; counts not reported",
                    escaped_path(store.as_os_str().as_bytes())
                );
            }
            None => line.push_str("; elapsed time and counts unknown"),
            _ => (),
        }
    }
    line.push_str(match outcome {
        MountOutcome::Clean => "; daemon ending clean (exit 0)",
        MountOutcome::RuntimeFailure | MountOutcome::Usage => {
            "; daemon session/cache ending was not clean (exit 1)"
        }
        MountOutcome::CacheCloseFailed => {
            "; daemon session/cache ending was not clean; cache failed or was not closed (exit 3)"
        }
        MountOutcome::Stopped => "; daemon stopped (exit 4)",
        MountOutcome::Fenced => "; daemon fenced (exit 5)",
    });
    line
}

/// Guarantees [`Exit::SessionEnded`] reaches the shutdown coordinator
/// even when the session thread's own closure PANICS instead of
/// returning normally. The guard sends the notification when it drops,
/// including during unwinding.
///
/// `mpsc::Receiver::recv()` returns `Err` only once EVERY `Sender` has
/// dropped. A bare `tx.send(Exit::SessionEnded)` written as a statement
/// AFTER `fuser_session.run()` never executes on an unwind — and the two
/// signal threads hold their own live `Sender`s parked forever awaiting
/// a signal that may never come, so `recv()` then blocks for good. The
/// daemon hangs with its mount still in place: worse than `fuser`'s
/// own unmount defect (a busy root mount's `umount(2)` fails, and the
/// daemon exits 0 with the mount still there).
///
/// A `Drop` impl runs during an unwind too (unless the unwind strategy
/// is `panic = "abort"`, which this workspace does not set), so wrapping
/// the send in a guard's `Drop` sends it unconditionally, on every path
/// out of the closure — normal return OR panic — exactly once.
///
/// Portable and gate-free on purpose (unlike the daemon body that
/// constructs it): a real `mpsc::channel`, a real spawned thread and a
/// real panic are enough to prove this on every platform, with no
/// `fuser::Session` or kernel anywhere near the test.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "constructed only by run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own test constructs and drops it directly (via a real thread panic) on \
                  every platform, needing no fuser::Session/kernel anywhere near it"
    )
)]
struct SessionEndedGuard(std::sync::mpsc::Sender<Exit>);

impl Drop for SessionEndedGuard {
    fn drop(&mut self) {
        let _ = self.0.send(Exit::SessionEnded);
    }
}

/// Read the cache-close outcome even when the `Mutex` guarding it was
/// POISONED. `.lock().ok().and_then(...)`
/// silently answers `None` on a poisoned lock, indistinguishable from
/// "the mount never got as far as `destroy`", so a real cache-close
/// failure that happened to poison the mutex while being recorded would
/// exit 0 instead of 3 — silently losing the exit-status signal that the
/// cache failed to close cleanly. `PoisonError::into_inner()` recovers the guarded value
/// regardless of poisoning, so the last value written is read either
/// way.
///
/// Portable (plain `std::sync::Mutex`, no `fuser`/kernel involved), so
/// it is tested directly by deliberately poisoning a mutex on every
/// platform.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own test poisons a real Mutex directly on every platform, needing no \
                  fuser::Session/kernel anywhere near it"
    )
)]
fn read_cache_close_slot(
    slot: &std::sync::Mutex<Option<Result<(), String>>>,
) -> Option<Result<(), String>> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Record the cache-close outcome, recovering a POISONED slot rather
/// than skipping the write. The mirror of `read_cache_close_slot`, and
/// for the same reason: a slot left empty is indistinguishable from
/// "destroy never ran", which `mount_shutdown_outcome` reads as a clean
/// shutdown — so a lock poisoned by an unrelated panic would turn a real
/// close FAILURE into exit 0. The value is a plain `Option`, so a
/// poisoned mutex's contents are as usable as an unpoisoned one's.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from DaemonBackend::shutdown, itself target_os = \"linux\"-gated — \
                  this module's own test poisons a real Mutex directly on every platform, needing \
                  no fuser::Session/kernel anywhere near it"
    )
)]
fn write_cache_close_slot(
    slot: &std::sync::Mutex<Option<Result<(), String>>>,
    outcome: Result<(), String>,
) {
    let mut guard = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Some(outcome);
}

/// Report a DECIDED FAILURE and then say so, in that order — the failure-arm
/// sibling of [`report_then_wait`], which covers the success arm.
///
/// **The ordering is the whole function and the three spellings are not
/// equivalent.** Suppose a handled-failure arm in `run_fuse_daemon`'s two
/// signal threads logged and THEN reported. The real subscriber writes into
/// `crate::sink`'s bounded queue, where no producer blocks on the destination, but a
/// diagnostic that did block would stall that thread having reported nothing,
/// with its sender alive, and `await_signal_readiness` would block before the
/// kernel mount exists; sender hygiene cannot reach a sender whose thread is alive.
///
/// **Reporting first is not enough either.** A thread that has reported and
/// still holds its clone keeps the channel connected, so a sibling dying
/// pre-report disconnects nothing and the second `recv()` blocks — the exact
/// hang [`report_then_wait`] exists to close.
/// The sender is RELEASED before the diagnostic runs, so a blocked diagnostic
/// cannot retain a reported sender.
///
/// **What this does NOT claim.** It fixes sender ownership and nothing
/// wider: whether a diagnostic can block is a property of the writer it
/// goes through, not of this function. `gran mount`'s tracing subscriber
/// writes into `crate::sink`'s bounded queue (installed in `main()`),
/// whose producers never block on the destination; a diagnostic routed
/// anywhere else is outside what this function controls.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "its only callers are run_fuse_daemon's two signal threads, themselves \
                  target_os = \"linux\"-gated — this module's own tests drive it on every \
                  platform with a plain mpsc::Sender and an injected diagnostic, asserting from \
                  INSIDE that diagnostic that the report is already buffered AND the channel is \
                  already disconnected, which is the whole property it exists to hold"
    )
)]
fn report_failure_then(ready: std::sync::mpsc::Sender<()>, diagnostic: impl FnOnce()) {
    let _ = ready.send(());
    // Unlike `report_then_wait`'s, the explicit `drop` here is the
    // MECHANISM rather than documentation. That function is a plain `fn` whose
    // local drops at return, before its wait is ever polled; this one RUNS the
    // diagnostic itself, so without this line the sender lives across it and a
    // blocked diagnostic keeps the channel connected. Mutation-proved: removing
    // it reddens the release row and leaves the send row green.
    drop(ready);
    diagnostic();
}

/// Report readiness on `tx`, RELEASE it, and only then wait.
///
/// The release is the whole point. [`await_signal_readiness`] reads exactly
/// twice and treats `Err` as "a report will never come" — but `recv()`
/// returns `Err` only when EVERY `Sender` is gone. A thread that reported and
/// then parked while still holding its clone leaves one live sender behind
/// the buffered report, so a sibling that dies before reporting disconnects
/// nothing and the second read blocks. Dropping here costs nothing: a value
/// already sent is BUFFERED in the channel and outlives its sender.
///
/// It does NOT rescue a sibling that HANGS rather than dies — a thread
/// blocked anywhere before it reports still owns its sender, and the
/// second read then blocks. This closes only the dying case, which is
/// the one a disconnect can signal.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "its only callers are run_fuse_daemon's two signal threads, themselves \
                  target_os = \"linux\"-gated — this module's own tests drive it on every \
                  platform with a plain mpsc::Sender, asserting from INSIDE the wait that the \
                  sender was already released, which is the whole property it exists to hold"
    )
)]
fn report_then_wait<F: std::future::Future>(
    tx: std::sync::mpsc::Sender<()>,
    wait: F,
) -> impl std::future::Future<Output = F::Output> {
    let _ = tx.send(());
    // The SIGNATURE is what enforces the early release. While this clone
    // lives, `recv()` cannot return `Err`, so a sibling that dies before
    // reporting disconnects nothing. Because this is a plain `fn`, `tx` is a
    // local that drops when the function RETURNS — before the wait is ever
    // polled — so the explicit `drop` below is documentation rather than the
    // mechanism: a mutation deleting the `drop` alone changed nothing, both
    // tests green. The shape that DOES fail is an `async move` block holding
    // `tx` across the wait: under that mutation the proxy test fails in
    // milliseconds and the end-to-end one hangs until nextest kills it at
    // its timeout.
    drop(tx);
    // NOT an `async fn`, deliberately, and that is the same point from the other
    // side. This `fn` sends at the STATEMENT; an `async fn` would
    // send only on first poll, so a caller that built the future and never
    // polled it — stored it, raced it, dropped it on an early return — would
    // never report, and the main thread would block in `await_signal_readiness`
    // before `Session::new` — the hang this function exists to
    // close.
    wait
}

/// Forward every delivery `next` polls to the coordinator as `name`, until
/// the stream ends or the coordinator is gone, and answer how many were
/// sent. The first signal starts the shutdown; every later one expires it.
///
/// tokio coalesces signals that arrive before a poll, so two sent together
/// may be one delivery; the operator sends again.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "its only callers are run_fuse_daemon's two signal threads, themselves \
                  target_os = \"linux\"-gated — this module's own tests drive it on every \
                  platform with a scripted poll and a plain mpsc channel"
    )
)]
async fn forward_signals(
    mut next: impl FnMut(&mut std::task::Context<'_>) -> std::task::Poll<Option<()>>,
    tx: std::sync::mpsc::Sender<Exit>,
    name: &'static str,
) -> usize {
    let mut sent = 0;
    while std::future::poll_fn(&mut next).await.is_some() {
        if tx.send(Exit::Signal(name)).is_err() {
            break;
        }
        sent += 1;
    }
    sent
}

/// Blocks until both signal producer threads have reported readiness —
/// the readiness handshake, pulled out of `run_fuse_daemon` so it is
/// testable with a real `mpsc::Receiver` and nothing OS-signal-shaped
/// anywhere near it. Exactly two reports are expected, one per signal
/// thread (`run_fuse_daemon`'s own two `std::thread::spawn` calls); each
/// thread sends the INSTANT it knows whether it armed or failed to,
/// which is what lets this function return before `Session::new` — and
/// so before the kernel mount exists — with the guarantee that no signal
/// thread is still mid-registration.
///
/// **Cannot hang waiting for a report that will never come —
/// CONDITIONALLY.** A thread that DIES before sending
/// drops its `ready_tx` clone on the way out (Rust drops live locals on every
/// exit path, panics included, since this workspace does not set
/// `panic = "abort"`). But `recv()` returns `Err` only when EVERY `Sender` is
/// gone, and **one sender dropping is not an event at all** — so this holds
/// only if no OTHER sender is alive.
///
/// A signal thread that reported and then parked inside `block_on` still
/// HOLDING its clone would break that condition: a sibling that died
/// pre-send would disconnect nothing and the second read would block
/// forever (REPRODUCED with this function copied verbatim into a
/// standalone program under a watchdog). [`report_then_wait`] prevents it:
/// a reporting thread releases its sender before it waits, so the only live
/// senders are ones that have not reported yet. `run_fuse_daemon` moving its
/// own last clone into the second thread is necessary too, not sufficient.
///
/// **Defence in depth: a diagnostic cannot hold a reported sender.**
/// Every handled-failure arm in the two signal threads goes through
/// [`report_failure_then`], which reports and RELEASES its sender
/// before it diagnoses. The current diagnostics are typed warnings
/// through the sink and do not wait on stderr; a diagnostic whose
/// writer could block would otherwise hold the sender while it
/// blocked.
///
/// **The warning below cannot stall this function on stderr.** It is
/// a typed warning, and `main()` installs the subscriber with a
/// `crate::sink` writer: tracing records go to its TELEMETRY stream,
/// which a full queue drops rather than waits on, and no sink
/// producer ever blocks on the destination. A dead sibling therefore
/// costs at most a warning that may be dropped, never a blocked write
/// here; whether the warning is delivered still depends on stderr
/// draining.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own tests drive it with a real mpsc::Receiver and plain () sends on \
                  every platform, needing no tokio runtime/kernel/OS signal anywhere near it"
    )
)]
fn await_signal_readiness(ready_rx: &std::sync::mpsc::Receiver<()>) {
    for _ in 0..2 {
        if ready_rx.recv().is_err() {
            granary_client::OperatorDiagnostic::gran_mount_a_signal_readiness_report_never_arrived_before().emit();
            break;
        }
    }
}

// ---------------------------------------------------------- `gran mount`

/// The daemonize-vs-foreground decision, pulled out of
/// `cmd_mount` into its own named function taking a plain `bool` so a
/// test can observe it directly — `cmd_mount` itself has several OTHER
/// early returns that map to the identical `RuntimeFailure` exit code,
/// so a test asserting only on that code cannot tell "refused for
/// backgrounding" from "refused for an unrelated reason": a test on
/// the exit code alone would be vacuous.
///
/// **Both `--foreground` and the default put the session on its own
/// `std::thread` and run the coordinator on the main thread — the ONLY
/// difference is whether the process detaches from the terminal
/// first**. Detaching (the default) needs a
/// double-fork/setsid/fd-close daemonization, but no pidfile convention
/// or log-redirection contract is specified. The default is refused here
/// rather than inventing those contracts, following this crate's rule to
/// stop on a contradiction rather than improvise. The systemd unit and CI
/// lane both pass `--foreground`, so this is the path that matters most in
/// production
/// regardless.
fn mount_requires_foreground(foreground: bool) -> Option<&'static str> {
    if foreground {
        None
    } else {
        Some(
            "gran mount: backgrounding (the default) is not implemented — \
             pass --foreground. The systemd unit and the CI lane both already do.",
        )
    }
}

/// Why [`mount_attempt_with_credentials`] refused, before ever reaching
/// the platform-gated daemon tail.
/// Folding all TEN of these into `MountOutcome::RuntimeFailure`'s one
/// exit code left no way for a test calling `cmd_mount` itself to tell
/// "pre-flight refused" from an unrelated early failure — exactly the
/// vacuous-test shape
/// `cmd_mount_refuses_backgrounding_before_touching_anything_else`'s own
/// doc already named for the foreground gate alone.
///
/// **This is only the `ExitCode` translation, not the sequence.**
/// `mount_attempt_with_credentials` below is ONE single, linear, ordered
/// function, for the reason its own `too_many_lines` expectation gives —
/// nothing here extracts a DECISION into a helper; this enum is only what
/// the thin wrapper below matches on. Every variant maps to
/// `MountOutcome::RuntimeFailure` there, so every refusal exits with the
/// runtime-failure code `MOUNT_HELP` states.
#[derive(Debug)]
pub(crate) enum MountRefusal {
    Writable,
    MetricsConfiguration,
    /// A feature-built `gran mount`
    /// REFUSES TO START without `--breakage`. This is a
    /// RUNTIME-start property, not a parse
    /// property, so it lives here — the ONE function both entry
    /// points converge on (`cmd_mount_gran` -> `parse_mount_gran` ->
    /// `cmd_mount` -> this function, unconditionally; `gran mount`
    /// -> `parse_mount` -> `cmd_mount` -> this function, same) —
    /// rather than duplicated per-parser or, worse, exposed as a
    /// second arming vocabulary through `mount.gran`'s `-o` options
    /// (rejected: that would have let a REAL fstab line arm a
    /// feature binary with no harness/caller check at all, widening
    /// the arming path to accept ordinary fstab input).
    #[cfg(feature = "conformance-breakage")]
    BreakageRequired,
    /// A set-ID `gran mount` invocation, which mounts a filesystem.
    /// Every credential-using command calls `set_id_refusal`. In
    /// `mount_attempt_with_credentials` it runs before any mount work
    /// (the foreground gate, the pre-flight, `MountSession::open`);
    /// only a conformance-breakage build's `--breakage` refusal and
    /// `GRANARY_STDERR_PANIC` trigger run before it.
    SetIdExecution,
    Foreground,
    Preflight(
        #[cfg_attr(
            not(test),
            expect(
                dead_code,
                reason = "the specific MountPreflightError is read only by this module's own \
                          tests (mount_attempt_calls_preflight_and_reports_which_refusal_fired) \
                          matching on it to prove WHICH pre-flight condition fired — a real \
                          `gran mount` invocation only needs to know a refusal happened at all, \
                          which the bounded terminal reporter already reported \
                          before constructing this variant"
            )
        )]
        MountPreflightError,
    ),
    CacheDirRequired,
    ResetFloorOpen,
    ResetFloorReset,
    ResetFloorClose,
    Store,
    SessionOpen,
    Snapshot,
}

/// `gran mount`'s real body: pre-flight, open the session,
/// build its [`granary_vfs::Snapshot`], then hand both to the
/// platform-gated daemon body. Returns a typed [`MountRefusal`] on every
/// early exit rather than printing-and-exiting directly, so a test can
/// match on WHICH decision fired — every diagnostic below is still
/// printed at its own call site, in order, exactly as before; only the
/// exit-code CHOICE moved to [`cmd_mount`], the thin wrapper below this
/// function.
///
/// `report` is the bounded direct terminal writer in production. It is separate
/// from the queued `log`, so a refusal attempts delivery within a bound;
/// tests can inject a blocked destination without touching process stderr.
///
/// Everything above the platform split is real, cross-platform logic —
/// `MountSession::open` needs no `fuser` dependency at all, so it and
/// everything before it run for real (and are compile-checked) on this
/// dev machine; only the last step, actually constructing a
/// `fuser::Session`, is Linux-only. The
/// platform-gated tail's own outcome (Linux: whatever
/// `run_fuse_daemon` reports; elsewhere: always `RuntimeFailure`) is
/// the final platform-specific decision, and is a [`MountOutcome`]
/// already — it needs no [`MountRefusal`] variant of its own.
#[expect(
    clippy::too_many_lines,
    reason = "one linear mount sequence — foreground gate, pre-flight, reset-floor, the store, \
              the session, the snapshot, then the platform-gated daemon body — on parse_mount's \
              own too_many_lines precedent in this file: splitting an ordered sequence of \
              early returns across helpers hides the order, which is the property worth \
              keeping visible here. The ExitCode translation lives in cmd_mount below; the \
              ordered sequence lives in exactly one function"
)]
pub(crate) fn mount_attempt_with_credentials(
    margs: &MountArgs,
    credentials: &ProcessCredentials,
    log: &mut dyn granary_client::LocalReporter,
    report: &dyn Fn(std::fmt::Arguments<'_>),
) -> Result<MountOutcome, MountRefusal> {
    // The ABSOLUTE first action
    // — ahead of even the set-ID check just below — a
    // feature-built `gran mount` REFUSES TO START without
    // `--breakage`. Refusing to start is a
    // runtime-start property, so it belongs here rather than in
    // either parser: this is the ONE function BOTH entry points
    // converge on (`gran mount` -> `parse_mount` -> `cmd_mount`
    // -> here; `mount.gran` -> `parse_mount_gran` -> `cmd_mount`
    // -> here, unconditionally — see `main`'s own dispatch and
    // `cmd_mount_gran`), so one check here covers both with no
    // per-parser duplication and no second arming vocabulary.
    #[cfg(feature = "conformance-breakage")]
    if margs.breakage.is_none() {
        report(format_args!(
            "gran mount: --breakage <name> is required: this binary was built with \
             conformance-breakage, which must never mount honestly. \
             Accepted: {}",
            granary_fuse::Breakage::ALL
                .iter()
                .map(|b| b.name())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        return Err(MountRefusal::BreakageRequired);
    }

    // Only an explicitly armed debug conformance binary can reach this trigger.
    // The panic is on the main thread, with the real hook already installed.
    #[cfg(feature = "conformance-breakage")]
    if std::env::var_os("GRANARY_STDERR_PANIC").as_deref() == Some(std::ffi::OsStr::new("1")) {
        crate::conformance_stderr_checkpoint("panic");
        std::panic::panic_any("stderr conformance panic");
    }

    // The first REMAINING action —
    // before the foreground gate, before any pre-flight, before any
    // side effect: a set-ID `gran mount` invocation, which mounts a
    // filesystem, is refused here. Every credential-using command
    // calls `set_id_refusal` at its own entry, and this is the
    // `gran mount` one.
    if let Some(e) = set_id_refusal(credentials) {
        if margs.metrics.configured() {
            granary_client::op_failed(
                granary_client::OperationKind::Session,
                granary_client::FailureClass::Refused,
            );
        }
        report(format_args!("gran mount: {e}"));
        return Err(MountRefusal::SetIdExecution);
    }

    // Extracted (see mount_requires_foreground's own doc) so a test can
    // observe this refusal in isolation from every OTHER early return
    // below it, all of which map to the SAME RuntimeFailure exit code.
    if let Some(message) = mount_requires_foreground(margs.foreground) {
        report(format_args!("{message}"));
        return Err(MountRefusal::Foreground);
    }

    let metrics_config = margs.metrics.prepare(credentials.euid).map_err(|error| {
        report(format_args!("gran mount: {error}"));
        MountRefusal::MetricsConfiguration
    })?;

    if let Err(e) = mount_preflight(&margs.mountpoint, margs.force) {
        report(format_args!("gran mount: {e}"));
        return Err(MountRefusal::Preflight(e));
    }

    if margs.writable {
        return writable_mount_attempt(margs, credentials, metrics_config, log, report);
    }

    // A mount's cache is not optional the way `gran cat`'s is:
    // `MountSession::open` takes `cache_dir: &Path`, not an `Option`,
    // because the session's whole `GrainFetch` path reads through it
    // for the mount's entire life. `MOUNT_HELP` states `--cache-dir` is
    // required, but the shared parse leaves it an `Option` (every other
    // verb's own convention) — so this is where the gap closes: a real
    // runtime refusal,
    // named, rather than a silently invented default directory (no XDG
    // or systemd location is defined for one, and this crate does not
    // invent one).
    let Some(cache_dir) = margs.cache_dir.as_deref() else {
        #[cfg(feature = "conformance-breakage")]
        crate::conformance_stderr_checkpoint("cache-dir-refusal");
        report(format_args!(
            "gran mount: --cache-dir <path> is required — the mount's whole read path serves \
             through it for the life of the session"
        ));
        return Err(MountRefusal::CacheDirRequired);
    };

    let origin = cache_origin(&margs.endpoint, &margs.tls_pins, margs.root_key.as_ref());

    // `--reset-floor`: clears anchors/<volume>.mount and
    // NOTHING else, before the mount itself ever opens the SAME
    // directory as a second, held-open writer — `Cache::open` uses a
    // writer flock per directory, so this has to close cleanly before
    // `MountSession::open` opens it again just below.
    if margs.reset_floor {
        match Cache::open(cache_dir, DEFAULT_CACHE_QUOTA_BYTES, &origin) {
            Ok(mut cache) => {
                let reset_result = cache.reset_mount_anchor(&margs.volume);
                let close_result = Cache::close(cache);
                if let Err(e) = reset_result {
                    report(format_args!("gran mount --reset-floor: {e}"));
                    return Err(MountRefusal::ResetFloorReset);
                }
                if let Err(e) = close_result {
                    report(format_args!("gran mount --reset-floor: cache close: {e}"));
                    return Err(MountRefusal::ResetFloorClose);
                }
            }
            Err(e) => {
                report(format_args!("gran mount --reset-floor: {e}"));
                return Err(MountRefusal::ResetFloorOpen);
            }
        }
    }

    let store = match HttpStore::new(&margs.endpoint, margs.tls_pins.clone(), &AmbientNetwork) {
        Ok(s) => s,
        Err(e) => {
            report(format_args!("gran mount: {e}"));
            return Err(MountRefusal::Store);
        }
    };
    let metrics =
        granary_client::ClientMetrics::new(&mut granary_net::secure_random::OsSecureRandom::new());
    let store = store.with_metrics(metrics.clone());
    // The handle is taken BEFORE `store` moves into `MountSession::open`
    // below — the same `Arc` every clone of the store's counter charges,
    // so the total read at clean exit is the session's real one.
    let wire_handle = store.wire_bytes();

    // The uid/gid every synthesised attribute reports (MOUNT_HELP: "The
    // invented uid and gid are PRESENTATION, not confidentiality") —
    // `--uid`/`--gid` when given, else this process's own effective
    // ids. This is the SAME `credentials` this function's first
    // check already consulted, snapshotted once per invocation by the
    // caller — not a second, independent `process_credentials()` read.
    let policy = granary_vfs::AttrPolicy {
        uid: margs.uid.unwrap_or(credentials.euid),
        gid: margs.gid.unwrap_or(credentials.egid),
    };

    // >>> THE CALLER'S DESTINATION, NOT `std::io::stderr()`. <<< The library
    // takes `sink` as a PARAMETER precisely so the caller decides where its
    // one-shot reports land. Handing it a BLOCKING handle would put its
    // `writeln!`s into a real stderr, on the startup path, before the
    // kernel filesystem exists, where a peer who fills that pipe wedges
    // the mount. What the caller passes is threaded in, so a test
    // can supply a destination that never drains and watch this call return
    // anyway.
    let session = MountSession::open(
        store,
        margs.volume.clone(),
        margs.root_key.map(Box::new),
        margs.manifest_root,
        margs.trust_server,
        margs.seq,
        cache_dir,
        DEFAULT_CACHE_QUOTA_BYTES,
        &origin,
        MountOptions {
            allow_other: margs.allow_other,
            allow_root: false,
        },
        log,
    );
    let mut session = match session {
        Ok(s) => s,
        Err(e) => {
            report(format_args!("gran mount: {e}"));
            return Err(MountRefusal::SessionOpen);
        }
    };
    // MountSession's retained record means a cached root and the
    // wire root disagreed at open, and the mount proceeded on the WIRE
    // bytes. `open`'s own one-shot sink write already told an operator
    // watching THIS invocation; `tracing` is what tells one watching
    // logs on a long-lived, daemonised mount instead.
    if session.equivocation().is_some() {
        granary_client::OperatorDiagnostic::gran_mount_a_cached_root_and_the_wire_root().emit();
    }
    let snapshot = match session.snapshot(policy) {
        Ok(s) => s,
        Err(e) => {
            report(format_args!("gran mount: {e}"));
            return Err(MountRefusal::Snapshot);
        }
    };

    // The inode table's per-mount generation stamp (`GranaryFs::new`'s
    // own doc: distinct across remounts matters for e.g. NFS export).
    // Wall-clock seconds is not a proof of distinctness for two mounts
    // started in the same second, but the mount is a CLI-invoked,
    // by-hand operation with no such use case documented in
    // `docs/operating-a-mount.md`, so exact precision is not load-bearing here —
    // this is the same ambient-time seam `cmd_publish`'s own
    // identity/timestamp reads already use, at the CLI edge only.
    let generation = u64::try_from(WallClock.now().secs).unwrap_or(0);

    let config = granary_fuse::session_config(margs.allow_other);

    #[cfg(target_os = "linux")]
    {
        let export = metrics_export::start(metrics_config, &metrics);
        let support = if margs.support_bundle {
            let Some(context) = margs.support_context.clone() else {
                report(format_args!("gran mount: support producer unavailable"));
                return Err(MountRefusal::SessionOpen);
            };
            let Ok(roots) = resolve_support_roots([(RootRole::Cache, cache_dir.to_owned())]) else {
                report(format_args!("gran mount: support producer unavailable"));
                return Err(MountRefusal::SessionOpen);
            };
            Some(SupportOwners {
                context,
                metrics: session.metrics().cloned(),
                overlay: None,
                roots,
            })
        } else {
            None
        };
        let wire = MountWireSnapshot {
            config: margs.wire.clone(),
            handle: wire_handle,
            endpoint: margs.endpoint.clone(),
            pinned_seq: margs.seq,
        };
        Ok(run_fuse_daemon(
            session,
            snapshot,
            generation,
            granary_fuse::MountWritability::ReadOnly,
            &margs.mountpoint,
            &config,
            #[cfg(feature = "conformance-breakage")]
            margs.breakage,
            &wire,
            None,
            None,
            support,
            export,
            credentials.euid,
            granary_core::mount_control::Mode::ReadOnly,
            spawn_signal_threads,
            #[cfg(feature = "conformance-breakage")]
            log,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            session,
            snapshot,
            generation,
            config,
            wire_handle,
            metrics_config,
        );
        report(format_args!(
            "gran mount: FUSE mounts are Linux-only; this build was compiled for {} (fuser's \
             own macos-no-mount configuration makes Session::new fail at runtime here \
             regardless — this refusal names the reason instead of leaking that internal \
             error string)",
            std::env::consts::OS
        ));
        Ok(MountOutcome::RuntimeFailure)
    }
}

/// `gran mount`: the thin wrapper over
/// [`mount_attempt_with_credentials`] — every diagnostic line is already
/// printed at its own call site inside that function, so this only
/// builds the process's credential snapshot (ONCE per
/// invocation) and maps the typed result to the [`ExitCode`] that
/// `MOUNT_HELP` states and the tests pin. For testing:
/// `mount_attempt_with_credentials` is
/// what a test should call to tell WHICH refusal fired; this wrapper is
/// what a test should call to prove `cmd_mount` itself still wires it
/// in.
/// `--commit-on-sync` selects the published profile; without it a writable
/// mount keeps the durable-prepared default.
fn sync_profile(args: &MountArgs) -> granary_client::SyncProfile {
    if args.commit_on_sync {
        granary_client::SyncProfile::Published
    } else {
        granary_client::SyncProfile::DurablePrepared
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "ordered startup keeps admission, engine attachment and kernel handoff visible"
)]
fn writable_mount_attempt(
    args: &MountArgs,
    credentials: &ProcessCredentials,
    metrics_config: Option<granary_net::metrics_listener::Configuration>,
    log: &mut dyn granary_client::LocalReporter,
    report: &dyn Fn(std::fmt::Arguments<'_>),
) -> Result<MountOutcome, MountRefusal> {
    use granary_client::{WritableStart, start_writable};
    let scope = args
        .credential
        .context
        .as_ref()
        .map(|context| {
            granary_client::publication_config::publication_scope(
                &args.endpoint,
                &args.tls_pins,
                context,
            )
        })
        .transpose()
        .map_err(|_| {
            granary_client::op_failed(
                granary_client::OperationKind::Session,
                granary_client::FailureClass::Refused,
            );
            report(format_args!("gran mount: WritableScopeRefused"));
            MountRefusal::Writable
        })?;
    let input = WritableStart {
        contention_threshold: args.contention_threshold,
        construction_workspace_bytes: args.construction_workspace_bytes,
        overlay_cap_bytes: args.overlay_cap_bytes,
        volume: args.volume.clone(),
        process: granary_client::WritableProcess {
            ruid: credentials.ruid,
            rgid: credentials.rgid,
            egid: credentials.egid,
            set_id_tainted: credentials.set_id_tainted,
        },
        foreground: args.foreground,
        force: args.force,
        mountpoint: &args.mountpoint,
        root_key: args.root_key,
        manifest_root: args.manifest_root,
        trust_server: args.trust_server,
        options: MountOptions {
            allow_other: args.allow_other,
            allow_root: false,
        },
        seq: args.seq,
        seed: args.key_seed.as_deref(),
        certificate: args.credential.certificate.as_deref(),
        credential_key: args.credential.key.as_deref(),
        scope,
        store: args.store_dir.as_deref(),
        cache: args.cache_dir.as_deref(),
        cache_origin: cache_origin(&args.endpoint, &args.tls_pins, args.root_key.as_ref()),
        cache_quota: DEFAULT_CACHE_QUOTA_BYTES,
        reset_floor: args.reset_floor,
        policy: granary_vfs::AttrPolicy {
            uid: args.uid.unwrap_or(credentials.euid),
            gid: args.gid.unwrap_or(credentials.egid),
        },
        euid: credentials.euid,
        sync_profile: sync_profile(args),
        view: args.view,
    };
    let proof = start_writable(
        &input,
        &WallClock,
        &mut granary_core::rng::ProcessRng::new(),
        &mut granary_net::secure_random::OsSecureRandom::new(),
        log,
    );
    let proof = match proof {
        Ok(proof) => proof,
        Err(error) => {
            report(format_args!("gran mount: {error}"));
            return Err(MountRefusal::Writable);
        }
    };
    #[cfg(target_os = "linux")]
    let wire_handle = proof.wire_bytes();
    let attachment = proof.attach();
    #[cfg(target_os = "linux")]
    {
        let mut attachment = attachment;
        attachment.set_shutdown_bound(std::time::Duration::from_secs(args.shutdown_bound.into()));
        let _sync_runtime = attachment
            .start_sync(std::sync::Arc::new(WallClock))
            .map_err(|error| {
                report(format_args!("gran mount: {error}"));
                MountRefusal::Writable
            })?;
        let export = if let Some(config) = metrics_config {
            let (metrics, _) = attachment.bundle_handles();
            let Some(metrics) = metrics else {
                granary_client::op_failed(
                    granary_client::OperationKind::Session,
                    granary_client::FailureClass::Internal,
                );
                report(format_args!("gran mount: metrics store unavailable"));
                return Err(MountRefusal::MetricsConfiguration);
            };
            metrics_export::start(Some(config), &metrics)
        } else {
            None
        };
        let support = if args.support_bundle {
            let Some(context) = args.support_context.clone() else {
                report(format_args!("gran mount: support producer unavailable"));
                return Err(MountRefusal::Writable);
            };
            let (metrics, overlay) = attachment.bundle_handles();
            let mut roots = Vec::new();
            if let Some(cache) = &args.cache_dir {
                roots.push((RootRole::Cache, cache.clone()));
            }
            if let Some(store) = &args.store_dir {
                roots.push((RootRole::Overlay, store.join("overlay")));
                roots.push((RootRole::Store, store.clone()));
            }
            let Ok(roots) = resolve_support_roots(roots) else {
                report(format_args!("gran mount: support producer unavailable"));
                return Err(MountRefusal::Writable);
            };
            Some(SupportOwners {
                context,
                metrics,
                overlay: Some(overlay),
                roots,
            })
        } else {
            None
        };
        let wire = MountWireSnapshot {
            config: args.wire.clone(),
            handle: wire_handle,
            endpoint: args.endpoint.clone(),
            pinned_seq: None,
        };
        // `start_writable` refuses a writable mount without a store, so a
        // started engine always has one to name.
        let stop = attachment
            .shutdown_handle()
            .zip(args.store_dir.as_deref())
            .map(|(handle, store)| {
                (
                    std::sync::Arc::new(handle) as std::sync::Arc<dyn DaemonStop>,
                    store,
                )
            });
        // Every later landing installs as the view this daemon serves.
        let bind = attachment
            .backend
            .take_view_binding()
            .map(|binding| Box::new(move |view| binding.bind(view, daemon_session)) as BindView<_>);
        Ok(run_fuse_daemon(
            attachment.backend,
            attachment.snapshot,
            u64::try_from(WallClock.now().secs).unwrap_or(0),
            granary_fuse::MountWritability::Writable,
            &args.mountpoint,
            &attachment.config,
            #[cfg(feature = "conformance-breakage")]
            args.breakage,
            &wire,
            bind,
            stop,
            support,
            export,
            credentials.euid,
            granary_core::mount_control::Mode::Writable {
                bound_seconds: args.shutdown_bound,
                store: {
                    use std::os::unix::ffi::OsStrExt as _;
                    args.store_dir
                        .as_deref()
                        .map(|store| store.as_os_str().as_bytes().to_vec())
                        .unwrap_or_default()
                },
            },
            spawn_signal_threads,
            #[cfg(feature = "conformance-breakage")]
            log,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop((attachment, metrics_config));
        report(format_args!("gran mount: WritablePlatformUnsupported"));
        Err(MountRefusal::Writable)
    }
}

pub(crate) fn cmd_mount(
    margs: &MountArgs,
    log: &mut dyn granary_client::LocalReporter,
) -> ExitCode {
    let credentials = process_credentials();
    match mount_attempt_with_credentials(margs, &credentials, log, &crate::terminal::write_line) {
        Ok(outcome) => mount_exit_code(outcome),
        Err(_) => mount_exit_code(MountOutcome::RuntimeFailure),
    }
}

// -------------------------------------------------------- `gran umount`

/// Ask the owner daemon for its settled shutdown, session and cache result.
/// Root crossing uids detaches only. Only a verified pre-Stop absent/refused
/// endpoint permits emergency detach, which still reports outcome unavailable.
/// A lost receipt after Stop never authorizes another detach or connection.
///
/// The caller supplies a nonblocking reporting sink in production; tests inject
/// a sink to observe set-ID and non-Linux refusals. Credentials are sampled once.
pub(crate) fn cmd_umount(mountpoint: &Path, err: &mut dyn std::io::Write) -> ExitCode {
    let credentials = process_credentials();
    cmd_umount_with_credentials(mountpoint, &credentials, err)
}

/// See [`cmd_umount`]'s own doc. The set-ID refusal is this function's
/// FIRST action — before the platform split, before any pre-flight,
/// before any side effect — and, unlike every diagnostic below it, is
/// written to the `err` SINK rather than `eprintln!`'d directly: that
/// sink is a parameter precisely so a test can assert what was written,
/// which an inline `eprintln!` literal is not.
fn cmd_umount_with_credentials(
    mountpoint: &Path,
    credentials: &ProcessCredentials,
    err: &mut dyn std::io::Write,
) -> ExitCode {
    if let Some(e) = set_id_refusal(credentials) {
        let _ = writeln!(err, "gran umount: {e}");
        return mount_exit_code(MountOutcome::RuntimeFailure);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = err;
        mount_exit_code(cmd_umount_linux(mountpoint, credentials.euid))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mountpoint;
        let _ = writeln!(
            err,
            "gran umount: not supported on {} — nix::mount::umount2 does not exist here; gran \
             umount is a Linux-only verb (this build's gran mount refuses to mount here for the \
             same reason)",
            std::env::consts::OS
        );
        mount_exit_code(MountOutcome::RuntimeFailure)
    }
}

/// Why a mountpoint could not be resolved for verification: the operator
/// text, and the closed class the telemetry diagnostic reports instead of it.
#[derive(Debug, PartialEq, Eq)]
struct VerifyRefusal {
    class: granary_client::FailureClass,
    message: String,
}
impl VerifyRefusal {
    fn io(message: String) -> Self {
        Self {
            class: granary_client::FailureClass::Io,
            message,
        }
    }
}
impl std::fmt::Display for VerifyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// The closed class of a failed lazy detach, derived from the error.
#[cfg(target_os = "linux")]
fn detach_failure_class(error: &granary_fuse::UnmountError) -> granary_client::FailureClass {
    use granary_client::FailureClass;
    use granary_fuse::UnmountError;
    match error {
        UnmountError::NoFinalComponent { .. } | UnmountError::ParentNotCanonical { .. } => {
            FailureClass::Refused
        }
        UnmountError::NoFusermountHelper { .. } => FailureClass::Unavailable,
        _ => FailureClass::Io,
    }
}

/// Resolve `mountpoint` to the absolute form `findmnt`'s TARGET column
/// reports. Splits `mountpoint`
/// into a canonical parent directory and a literal final component,
/// joined back together — mirroring `granary_fuse::unmount`'s own
/// private `resolve_target` deliberately, for the identical reason:
/// **the mountpoint itself is never touched.**
///
/// **Why not `std::fs::canonicalize` on the WHOLE path.**
/// `granary-fuse/src/unmount.rs`'s own
/// doc names exactly why that is unsafe here: the target of a `gran
/// umount` is by definition a FUSE mountpoint that may be wedged, and
/// resolving the FINAL component crosses the mount boundary to do it —
/// on an aborted mount that fails `ENOTCONN`, on an unanswered one it
/// HANGS until killed. This function runs BEFORE control lookup or `detach_unmount` even
/// starts (`cmd_umount_linux`'s first step), i.e. on a target that may
/// be wedged in exactly the way `gran umount` exists to recover — so it
/// is squarely on the path that hazard applies to, not adjacent to it.
/// Modern `realpath(3)` was measured to SUCCEED on a wedged mountpoint
/// on current glibc/musl (it resolves a symlink component with
/// `readlink(2)` rather than `lstat(2)`, and a FUSE root inode answers
/// `readlink` from mount-time metadata without reaching the daemon) —
/// but `unmount.rs`'s own doc is explicit that nothing promises this,
/// and this function makes the identical choice `resolve_target` already
/// made rather than resting on the same accident of libc a second time:
/// canonicalize only the PARENT (an ordinary directory on an ordinary
/// filesystem), and take the final component literally.
///
/// **Unlike `resolve_target`, this does not refuse when the parent's
/// canonical form differs from its lexical one.** `resolve_target`
/// refuses that case because its result feeds a PRIVILEGED `umount2(2)`
/// call, and a symlinked ancestor is a TOCTOU vector for redirecting
/// it — that function's own "path guard" doc section. This function's
/// result never reaches a syscall; it is only ever compared, byte for
/// byte, against `findmnt`'s own TARGET column, which is itself a fully
/// resolved absolute path. Using the canonical parent unconditionally is
/// what makes THAT comparison correct; refusing here would buy no
/// additional safety (the actual detach is independently guarded by
/// `resolve_target`'s own check, immediately before the privileged call)
/// and would only make ordinary use through a symlinked ancestor
/// mismatch verification instead.
///
/// **REFUSES on failure rather than falling back to the argument AS
/// GIVEN.** A fallback would be the fail-open shape this crate refuses
/// everywhere else, treating "could not resolve the path" as "definitely
/// unmounted" whenever the argument is RELATIVE: a relative path can
/// never match findmnt's absolute TARGET column, so verification would
/// silently answer "not mounted" over a mount that might still be
/// wedged.
///
/// Portable (`canonicalize` on the PARENT only, exactly like
/// `resolve_target` itself, is cross-platform), so it is tested directly
/// against a real scratch directory and a real nonexistent parent on
/// every platform, with no `findmnt`/kernel/wedged mount anywhere near
/// it.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called from cmd_umount_linux AND from detach_target_for, both target_os = \
                  \"linux\"-gated (directly, or via run_fuse_daemon) — this module's own tests \
                  call it directly against a real scratch directory and a real nonexistent path \
                  on every platform, needing no findmnt/kernel anywhere near it"
    )
)]
#[expect(
    clippy::disallowed_methods,
    reason = "READ-ONLY path resolution of the operator's own gran umount argument, so it can be \
              compared against findmnt's own fully-resolved TARGET column — the same READ-ONLY \
              resolution refuse_if_already_mounted's own canonical() helper already licenses for \
              the identical reason, one layer up (mount time rather than umount time). Only the \
              PARENT directory is canonicalized — the mountpoint itself, which may \
              be a wedged FUSE mount, is never touched, for the same reason \
              granary_fuse::unmount's own resolve_target does not touch it either"
)]
fn resolve_for_verification(mountpoint: &Path) -> Result<PathBuf, VerifyRefusal> {
    let requested = std::path::absolute(mountpoint).map_err(|e| {
        VerifyRefusal::io(format!(
            "could not resolve {} to an absolute path ({e}) — refusing to verify rather than \
             treating an unresolved path as \"definitely unmounted\"",
            mountpoint.display()
        ))
    })?;
    let mut components = requested.components();
    let Some(Component::Normal(final_component)) = components.next_back() else {
        return Err(VerifyRefusal {
            class: granary_client::FailureClass::Refused,
            message: format!(
                "refusing to verify {}: it does not name a mountpoint -- it is a filesystem \
                 root, or it ends in `..`, and neither is something gran umount acts on",
                requested.display()
            ),
        });
    };
    let lexical_parent = components.as_path();
    let canonical_parent = std::fs::canonicalize(lexical_parent).map_err(|e| {
        VerifyRefusal::io(format!(
            "could not resolve {}'s parent directory {} to its canonical form ({e}) — refusing \
             to verify rather than treating an unresolved path as \"definitely unmounted\"",
            mountpoint.display(),
            lexical_parent.display()
        ))
    })?;
    Ok(canonical_parent.join(final_component))
}

/// What `run_fuse_daemon`'s lazy-detach fallback should hand to
/// `granary_fuse::detach_unmount` at shutdown — decided ONCE, at
/// startup, rather than lazily when
/// the signal arrives.
///
/// `detach_unmount`'s own `resolve_target` canonicalizes the PARENT and
/// refuses when it disagrees with the lexical parent
/// (`UnmountError::ParentNotCanonical`) — so a mount made through a
/// symlinked ancestor (`gran mount /tmp/link/x` where `/tmp/link ->
/// /real`) mounts fine (the mountpoint pre-flight only checks the FINAL
/// component for a symlink), and an EBUSY fallback handed the raw path
/// would refuse with `ParentNotCanonical`, leaving the mount attached —
/// failing precisely in the case it exists for. [`resolve_for_verification`]
/// already produces the one shape `resolve_target` accepts (a canonical
/// parent joined to the literal final component), so a resolved path's
/// own parent trivially already equals its canonical form.
///
/// The RAW mountpoint is never used as a fallback on a resolution
/// failure: a failure here means the
/// decision is [`DetachTarget::Unavailable`], carrying the reason,
/// rather than a path.
#[derive(Debug, PartialEq, Eq)]
enum DetachTarget {
    /// Hand this path to `detach_unmount` — it satisfies `resolve_target`.
    Resolved(PathBuf),
    /// `resolve_for_verification` refused; this is both what an
    /// operator sees at startup and what the shutdown path reports
    /// instead of attempting a detach that would only fail the same way.
    Unavailable(VerifyRefusal),
}

/// The pure decision behind [`DetachTarget`] — a plain function of
/// `mountpoint`, portable and testable on every platform exactly like
/// [`resolve_for_verification`] itself, which is all this calls.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from run_fuse_daemon, itself target_os = \"linux\"-gated — this \
                  module's own tests call it directly against a real scratch directory reached \
                  through a symlink, needing no FUSE session anywhere near it"
    )
)]
fn detach_target_for(mountpoint: &Path) -> DetachTarget {
    match resolve_for_verification(mountpoint) {
        Ok(resolved) => DetachTarget::Resolved(resolved),
        Err(why) => DetachTarget::Unavailable(VerifyRefusal {
            class: why.class,
            message: format!(
                "gran mount: the lazy-detach fallback is unavailable for {}: {why} — an EBUSY \
                 session-unmounter failure will not be able to fall back to a detach, and will \
                 report this reason instead of unmounting",
                mountpoint.display()
            ),
        }),
    }
}

/// Whether `gran umount` may proceed to `detach_unmount` at all, from
/// the PRE-check's own verdict, before any detach is attempted.
/// Calling `detach_unmount` FIRST and asking whether a `gran` source was
/// there only AFTERWARD would let a privileged `gran umount /mnt/other`
/// lazily detach an unrelated ext4/NFS/FUSE filesystem and then report
/// success
/// (no granary source remains at that path afterwards either way).
///
/// A pre-check that could not verify anything is a REFUSAL, not a
/// silent skip — the same "could not verify" shape `still_mounted_via_
/// findmnt`'s own `Err` arm already uses, applied here before the first
/// privileged syscall rather than only after it.
///
/// **Authorizes ONLY [`TargetRows::AllGran`].** `umount2`
/// detaches the TOPMOST mount at a path, so a pre-check that stopped at
/// the FIRST matching row would let a lower `gran` row on an over-mounted
/// target authorize detaching an unrelated upper filesystem.
/// [`TargetRows::Mixed`] gets its OWN refusal, distinct from
/// [`TargetRows::Absent`]'s: it names that the target carries a mount
/// that is not granary's, that `umount2` detaches the TOPMOST one
/// regardless, and that this command will not detach a mount it cannot
/// attest is granary's own.
///
/// **This is a POLICY, not an exact attestation.** Refusing `Mixed`
/// also refuses a legitimate stack with a granary mount ON TOP of
/// something else at one pathname. granary's own `gran mount`
/// pre-flight never creates that (it refuses an already-mounted or
/// non-empty target), but `mount --beneath` or a unit file outside this
/// binary's control can. This is fail-closed on purpose, because
/// nothing in the row list says which mount is topmost.
///
/// **`SOURCE=gran` is a LABEL, not provenance.** Any FUSE filesystem may
/// set `fsname=gran` (`mount -t tmpfs gran /mnt/other` does exactly
/// this) — so this whole check is a sanity check against detaching the
/// wrong thing, never an authorization proof.
///
/// Pure — a plain `std::io::Result<TargetRows>` in, a plain `Result` out
/// — so it is tested directly with synthetic `Ok`/`Err` inputs on every
/// platform, with no process or filesystem anywhere near it.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from detach_umount_linux, itself target_os = \"linux\"-gated — this \
                  module's own tests call it directly with synthetic Ok/Err values on every \
                  platform, needing no findmnt/kernel anywhere near it"
    )
)]
fn umount_preflight_verdict(pre_check: std::io::Result<TargetRows>) -> Result<(), String> {
    match pre_check {
        Ok(TargetRows::AllGran) => Ok(()),
        Ok(TargetRows::Absent) => Err(
            "refusing: not a granary mount (no `gran` source found there) — detach_unmount is \
             never called on a target this process never established was its own"
                .to_owned(),
        ),
        Ok(TargetRows::Mixed { .. }) => Err(
            "refusing: the target carries a mount that is not granary's, and umount2 detaches \
             only the TOPMOST mount at a path — this command will not detach a mount it cannot \
             attest is granary's own"
                .to_owned(),
        ),
        Err(e) => Err(format!(
            "could not verify it is a granary mount before detaching ({e}) — refusing rather \
             than guessing"
        )),
    }
}

/// Whether the target is "still mounted" AFTER `detach_unmount` has
/// already run — the sibling [`umount_preflight_verdict`] already is,
/// on the OTHER side of the same detach. Keeping the pre-check
/// -> detach -> post-check ordering and this mapping from
/// [`TargetRows`] to outcome only inline in
/// `detach_umount_linux` prevents the default suite from testing them:
/// the function and its only caller are Linux-gated, and the only
/// test of `cmd_umount` returns early under
/// `cfg!(target_os = "linux")`. With that inline shape, the junction
/// was untested on every platform running this repo's default CI suite,
/// so a mutation inside it could not be killed by that suite.
///
/// **"Still mounted" here means [`TargetRows::AllGran`] or
/// [`TargetRows::Mixed`] with `any_gran: true`** — a granary row is
/// still there, alone or mixed in with something else. `Absent` and
/// `Mixed { any_gran: false }` mean no granary row remains, i.e. the
/// detach worked.
///
/// **The ASYMMETRY with [`umount_preflight_verdict`] is deliberate — the
/// two ask DIFFERENT questions of the same [`TargetRows`] data** (see
/// that type's own doc). The pre-flight authorizes ONLY `AllGran`,
/// because `umount2` detaches the TOPMOST mount at a path and an
/// over-mounted target must never let a lower granary row authorize
/// detaching an unrelated upper filesystem. The post-check instead
/// treats `Mixed { any_gran: true }` as still-mounted: after the detach,
/// ANY remaining granary row at the target means granary's mount is
/// still there, regardless of what else shares the path.
///
/// **Pure, so it is tested directly with synthetic [`TargetRows`]
/// values on every platform** this repo targets, so the outcome
/// mapping has coverage independent of Linux-only detach calls.
///
/// Returns `Result<(), &'static str>` rather than a bare `MountOutcome`,
/// mirroring `umount_preflight_verdict`'s own shape: a helper that
/// returned only the outcome would leave the operator-facing
/// `eprintln!` at the call site as an unassertable literal — the same
/// problem the non-Linux refusal avoids with its diagnostic sink.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from detach_umount_linux, itself target_os = \"linux\"-gated — this \
                  module's own tests call it directly with synthetic TargetRows values on every \
                  platform, needing no findmnt/kernel anywhere near it"
    )
)]
fn umount_postcheck_verdict(post_check: TargetRows) -> Result<(), &'static str> {
    match post_check {
        TargetRows::Absent | TargetRows::Mixed { any_gran: false } => Ok(()),
        TargetRows::AllGran | TargetRows::Mixed { any_gran: true } => {
            Err("is still mounted after detach_unmount")
        }
    }
}

#[cfg(target_os = "linux")]
fn cmd_umount_linux(mountpoint: &Path, admitted: u32) -> MountOutcome {
    let real = match resolve_for_verification(mountpoint) {
        Ok(p) => p,
        Err(e) => {
            crate::terminal::write_line(format_args!("gran umount: {e}"));
            return MountOutcome::RuntimeFailure;
        }
    };
    let observed = match mount_table::control_mounts(&real)
        .map_err(|error| error.to_string())
        .and_then(|mounts| umount_control_target(&mounts, admitted))
    {
        Ok(Some(observed)) => observed,
        Ok(None) => {
            crate::terminal::write_line(format_args!(
                "gran umount: detach only; shutdown outcome was not requested"
            ));
            return detach_umount_linux(mountpoint, &real);
        }
        Err(error) => {
            crate::terminal::write_line(format_args!("gran umount: {error}"));
            return MountOutcome::RuntimeFailure;
        }
    };
    owner_umount(
        || {
            control::umount(&real, observed, admitted, &|line| {
                crate::terminal::write_line(format_args!("{line}"));
            })
        },
        || detach_umount_linux(mountpoint, &real),
        &|line| crate::terminal::write_line(format_args!("{line}")),
    )
}

#[cfg(any(test, target_os = "linux"))]
fn owner_umount(
    attempt: impl FnOnce() -> Result<MountOutcome, control::Failure>,
    detach: impl FnOnce() -> MountOutcome,
    report: &dyn Fn(&str),
) -> MountOutcome {
    match attempt() {
        Ok(outcome) => outcome,
        Err(error) if error.absent_before_stop => {
            if detach() == MountOutcome::Clean {
                report("gran umount: detached; shutdown outcome unavailable");
            }
            MountOutcome::RuntimeFailure
        }
        Err(_) => MountOutcome::RuntimeFailure,
    }
}

#[cfg(any(test, target_os = "linux"))]
fn umount_control_target(
    mounts: &[mount_table::ControlMount],
    admitted: u32,
) -> Result<Option<mount_table::ControlMount>, String> {
    if admitted == 0 && !mounts.is_empty() && mounts.iter().all(|mount| mount.owner != 0) {
        return Ok(None);
    }
    let [mount] = mounts else {
        return Err("refusing: owner wait requires exactly one granary mount row".into());
    };
    if mount.owner != admitted {
        return Err("refusing: mount belongs to another uid".into());
    }
    Ok(Some(*mount))
}

#[cfg(target_os = "linux")]
fn detach_umount_linux(mountpoint: &Path, real: &Path) -> MountOutcome {
    // Established BEFORE the first privileged syscall below,
    // never after. `still_mounted_via_findmnt` is the SAME helper the
    // post-check uses further down, with the OPPOSITE expectation (here
    // it must answer `AllGran`: this really is, unambiguously, a
    // granary mount).
    if let Err(e) = umount_preflight_verdict(still_mounted_via_findmnt(real)) {
        crate::terminal::write_line(format_args!("gran umount: {e}"));
        return MountOutcome::RuntimeFailure;
    }
    if let Err(e) = granary_fuse::detach_unmount(mountpoint) {
        crate::terminal::write_line(format_args!("gran umount: {e}"));
        return MountOutcome::RuntimeFailure;
    }
    // The post-detach check, routed through `umount_postcheck_verdict` —
    // see that function's own doc for the mapping and the deliberate
    // asymmetry with the pre-flight above.
    match still_mounted_via_findmnt(real) {
        Ok(rows) => match umount_postcheck_verdict(rows) {
            Ok(()) => MountOutcome::Clean,
            Err(why) => {
                crate::terminal::write_line(format_args!(
                    "gran umount: {} {why}",
                    mountpoint.display()
                ));
                MountOutcome::RuntimeFailure
            }
        },
        Err(e) => {
            crate::terminal::write_line(format_args!(
                "gran umount: could not verify the unmount ({e}) — is findmnt installed?"
            ));
            MountOutcome::RuntimeFailure
        }
    }
}

// ------------------------------------------- the Linux-only daemon body
//
// Everything below this line touches `fuser::Session` directly and is
// gated to Linux because the
// workspace's `fuser` line carries `macos-no-mount` UNCONDITIONALLY
// (Cargo.toml's own comment on that line), and macOS's own build.rs
// arm for that configuration makes `Session::new`'s private `Mount::new`
// ALWAYS return `io::Error::other("Mount is not enabled; this is
// test-only configuration")` — never a real mount, on this workspace's
// pin, regardless of host OS support. Gating the whole daemon body here
// turns that internal string into the NAMED, operator-facing refusal
// `cmd_mount`'s non-Linux arm prints instead, and keeps every DECISION
// this body makes ([`Exit`], [`mount_shutdown_outcome`], the pre-flight,
// the store/cache/session/snapshot construction) in the ungated,
// testable region above.

/// The "shared exit slot" `granary_fuse::MountBackend::shutdown`'s own
/// doc requires: `Filesystem::destroy`
/// calls `inner.backend.shutdown()` and DISCARDS the `Result` (that
/// method returns `()`, and `granary-fuse` depends on neither `tracing`
/// nor this slot). This wrapper is what lets the failure reach `main`
/// anyway.
///
/// `GrainFetch` delegates straight to the [`MountSession`] this type
/// owns; `MountBackend::shutdown` calls the SAME inner method, then
/// writes its `Result` into `cache_close` before returning it —
/// unchanged, so a DIRECT caller (a test) still gets the honest value,
/// and the slot is a side channel, not a replacement.
///
/// **Why the write is visible to `main`'s later read.**
/// `Filesystem::destroy` runs on the session's own OS thread, inside
/// `Session::run`, before `run` returns; after a join, `main` reads
/// `cache_close` only once `session_thread.join()` has returned. A
/// `JoinHandle::join` happens-after everything the joined thread did before
/// exiting, so the write below is ordered before the read. A daemon that
/// stopped waiting reads the slot without a join, under the same `Mutex`,
/// and may find it empty.
///
/// `exit` tells the coordinator that the kernel session has ended and
/// `destroy` is running, which lifts its grace: the cache close that
/// follows may take longer than the kernel's teardown.
#[cfg(any(test, target_os = "linux"))]
struct DaemonBackend<B> {
    session: B,
    cache_close: std::sync::Arc<std::sync::Mutex<Option<Result<(), String>>>>,
    exit: std::sync::mpsc::Sender<Exit>,
}

/// The session a daemon's adapter wraps, as a view install reaches it.
#[cfg(any(test, target_os = "linux"))]
fn daemon_session<B>(daemon: &mut DaemonBackend<B>) -> &mut B {
    &mut daemon.session
}

/// Binds an engine's view hook to the daemon's adapter once the kernel
/// session exists.
#[cfg(target_os = "linux")]
type BindView<B> = Box<
    dyn FnOnce(
        granary_fuse::ViewHandle<DaemonBackend<B>>,
    ) -> Result<(), granary_client::CoordinationError>,
>;

/// What [`run_fuse_daemon`] needs to write its own wire-byte
/// snapshot at clean exit, bundled so the daemon's already-long
/// parameter list does not grow four more scalars.
#[cfg(target_os = "linux")]
struct MountWireSnapshot {
    config: Option<WireSnapshotArgs>,
    handle: WireByteHandle,
    endpoint: String,
    pinned_seq: Option<u64>,
}

#[cfg(any(test, target_os = "linux"))]
impl<B: granary_fuse::MountBackend> granary_vfs::GrainFetch for DaemonBackend<B> {
    fn grain(
        &mut self,
        id: &GrainId,
        unpacked_len: u32,
    ) -> Result<Vec<u8>, granary_vfs::GrainUnavailable> {
        granary_vfs::GrainFetch::grain(&mut self.session, id, unpacked_len)
    }
}

#[cfg(any(test, target_os = "linux"))]
impl<B: granary_fuse::MountBackend> granary_fuse::MountBackend for DaemonBackend<B> {
    type DirectoryCursor = B::DirectoryCursor;
    fn overlay_path(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.session.overlay_path(path)
    }
    fn overlay_lookup(
        &mut self,
        parent: &[granary_core::manifest::Name],
        name: &granary_core::manifest::Name,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.session.overlay_lookup(parent, name)
    }
    fn overlay_directory(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<granary_fuse::OverlayDirectory<Self::DirectoryCursor>, granary_fuse::WriteError>
    {
        self.session.overlay_directory(path)
    }
    fn overlay_children(
        &mut self,
        cursor: &Self::DirectoryCursor,
    ) -> Result<granary_fuse::OverlayChildren<Self::DirectoryCursor>, granary_fuse::WriteError>
    {
        self.session.overlay_children(cursor)
    }

    fn overlay_nodes(
        &mut self,
    ) -> Result<Vec<granary_fuse::OverlayNode>, granary_fuse::WriteError> {
        self.session.overlay_nodes()
    }
    fn overlay_capacity(
        &mut self,
    ) -> Result<granary_fuse::OverlayCapacity, granary_fuse::WriteError> {
        self.session.overlay_capacity()
    }
    fn overlay_readlink(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<Vec<u8>, granary_fuse::WriteError> {
        self.session.overlay_readlink(path)
    }
    fn prepare_shrink_retry(
        &mut self,
        request: granary_fuse::MountShrinkRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        self.session.prepare_shrink_retry(request)
    }

    fn prepare_sync(
        &mut self,
        request: granary_fuse::MountSyncRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        self.session.prepare_sync(request)
    }

    fn overlay_open(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<Option<u64>, granary_fuse::WriteError> {
        self.session.overlay_open(path)
    }
    fn overlay_object(
        &mut self,
        object: u64,
    ) -> Result<granary_fuse::OverlayNode, granary_fuse::WriteError> {
        self.session.overlay_object(object)
    }
    fn overlay_close(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        self.session.overlay_close(object)
    }
    fn prepare_object(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        self.session.prepare_object(object)
    }
    fn prepare_detach(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<(), granary_fuse::WriteError> {
        self.session.prepare_detach(path)
    }
    fn read_object(
        &mut self,
        object: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, granary_fuse::WriteError> {
        self.session.read_object(object, offset, length)
    }
    fn prepare_overlay(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<(), granary_fuse::WriteError> {
        self.session.prepare_overlay(path)
    }
    fn overlay_setattr(
        &mut self,
        path: &[granary_core::manifest::Name],
        size: Option<u64>,
        exec: Option<bool>,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.session.overlay_setattr(path, size, exec)
    }
    fn overlay_mutate(
        &mut self,
        operation: granary_fuse::OverlayMutation<'_>,
    ) -> Result<(), granary_fuse::WriteError> {
        self.session.overlay_mutate(operation)
    }

    fn callback_observer(&self) -> Option<std::sync::Arc<dyn granary_fuse::CallbackObserver>> {
        self.session.callback_observer()
    }
    fn view_boundary(&self) -> Option<std::sync::Arc<dyn granary_fuse::ViewBoundary>> {
        self.session.view_boundary()
    }
    fn mutation_readiness(&mut self) -> Result<(), granary_fuse::MountError> {
        self.session.mutation_readiness()
    }
    fn shutdown(&mut self) -> Result<(), String> {
        let _ = self.exit.send(Exit::Teardown);
        let result = granary_fuse::MountBackend::shutdown(&mut self.session);
        write_cache_close_slot(&self.cache_close, result.clone());
        result
    }

    fn abandon(&mut self) {
        granary_fuse::MountBackend::abandon(&mut self.session);
        // Nothing goes into `cache_close`: a crash was detected, so
        // there is no close outcome to report, and `None` in that slot
        // already means "destroy reported none" — which is the truth
        // here. Exit-code precedence is unaffected: a worker panic
        // already makes `run_failed` win in `mount_shutdown_outcome`.
    }
}

/// Producers 2 and 3: the SIGINT and SIGTERM threads, which `run_fuse_daemon`
/// starts BEFORE `Session::new` creates the kernel mount, each reporting on
/// `ready_tx` once it knows whether it armed and then forwarding every
/// delivery of its signal on `tx` ([`forward_signals`]).
///
/// Spawning a thread earlier than `Session::new` is not the same as ARMING
/// it: if the thread has not yet run, a signal during `Session::new`'s own
/// mount/handshake — which takes measurable wall-clock time — would take the
/// DEFAULT termination path AFTER the kernel mount already existed,
/// bypassing the coordinated shutdown and the cache close and potentially
/// leaving an `ENOTCONN` mount behind. Each thread sends on `ready_tx` the
/// INSTANT it knows whether it armed (successfully registered) or failed,
/// and [`await_signal_readiness`] blocks the main thread on BOTH reports
/// before `Session::new` runs — so by the time the mount exists, every
/// signal thread has either already registered its handler or already gone
/// deaf and said so.
#[cfg(target_os = "linux")]
fn spawn_signal_threads(tx: std::sync::mpsc::Sender<Exit>, ready_tx: std::sync::mpsc::Sender<()>) {
    // SIGINT uses `signal(SignalKind::interrupt())`, the SAME
    // registration-then-await shape as SIGTERM below, not
    // `tokio::signal::ctrl_c()`. `ctrl_c()` registers
    // only on its FIRST POLL (inside an `.await`), so it
    // offers no synchronous point at which this thread could
    // know "registered" vs "not yet" to report on `ready_tx`;
    // `signal(SignalKind::interrupt())` registers at
    // CONSTRUCTION, exactly like `SignalKind::terminate()`,
    // which is what makes a readiness report possible here
    // at all. Both threads check their own registration
    // `Result` before reporting, and both treat a stream that
    // ended (`poll_recv` answering `None`) as no signal, so
    // neither reports a SIGINT or SIGTERM for a signal it did
    // not receive.
    let tx_sigint = tx.clone();
    let ready_sigint = ready_tx.clone();
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            // OS resource exhaustion building a second tiny runtime;
            // nothing this thread can do but leave SIGINT unhandled —
            // SIGTERM and an external plain unmount (SessionEnded) are
            // still live producers, so the mount is not stuck, only
            // deaf to this one signal. The readiness report is sent
            // regardless (a FAILURE to arm is still a decided outcome,
            // never a hang for `await_signal_readiness` to wait out).
            report_failure_then(ready_sigint, || {
                granary_client::OperatorDiagnostic::gran_mount_could_not_build_a_runtime_for_sigint().emit();
            });
            return;
        };
        rt.block_on(async {
            let Ok(mut sigint) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            else {
                report_failure_then(ready_sigint, || {
                    granary_client::OperatorDiagnostic::gran_mount_could_not_register_a_sigint_handler_this(granary_client::FailureClass::Io).emit();
                });
                return;
            };
            // `Signal::poll_recv` yields `Option<()>`, and `None` would mean
            // the stream will never yield again — NOT that a signal arrived.
            //
            // **On the PINNED tokio that `None` cannot occur, and the
            // warning below is defensive rather than reachable.** tokio's
            // `Signal::recv` is `{ self.inner.recv().await; Some(()) }` — read
            // at source, not inferred from the signature. The TYPE admits
            // `None` and a later version could use it, so the check stays;
            // for the same reason the warning is not a reachable
            // stderr-blocking site.
            let forwarded = report_then_wait(
                ready_sigint,
                forward_signals(|context| sigint.poll_recv(context), tx_sigint, "SIGINT"),
            )
            .await;
            if forwarded == 0 {
                granary_client::OperatorDiagnostic::gran_mount_the_sigint_stream_ended_without_delivering_a().emit();
            }
        });
    });

    // SIGTERM, same shape. **One thread PER signal, not one thread awaiting
    // both.**
    //
    // The reason is NOT the `tokio::select!` ban, though awaiting two
    // futures concurrently on one runtime is exactly what that macro does.
    // The BAN is real — every clippy.toml in the workspace carries the
    // `tokio::select` row — but it does NOT force two threads. This
    // workspace already writes exactly that race as a biased hand-rolled
    // `std::future::poll_fn`, in `granary-server`'s shutdown trigger and in
    // `granary-net`'s accept loop. Two threads here is a CHOICE, and its
    // cost is stated rather than hidden: both threads keep forwarding until
    // the process exits, parked in their own `block_on` — dead weight, not
    // a leak with consequences. Each releases its `ready_tx` clone before
    // parking ([`report_then_wait`]) — a clone kept alive for the rest of
    // the process's life would make a sibling's pre-send death unobservable.
    //
    // The LAST readiness clone: moving `ready_tx` itself here (rather than
    // cloning again) leaves no copy behind in this function's scope. If that
    // copy lingered, a thread that panicked before ever sending would not
    // make `ready_rx.recv()` return `Err`, and `await_signal_readiness` could
    // hang waiting for a report that will never come.
    //
    // NECESSARY, NOT SUFFICIENT. One sender dropping produces no event, and
    // `recv()` returns `Err` only on TOTAL disconnection. With both threads
    // parked holding their clones, a sibling that died pre-send would leave
    // one sender alive and the second read would block. Each thread
    // therefore releases its clone the moment it has reported (see
    // [`report_then_wait`]), so the only live senders are ones that have not
    // reported yet.
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            // Logged, not silently swallowed. A SIGTERM-deaf daemon under
            // systemd hangs to TimeoutStopSec and then takes SIGKILL — which
            // skips `destroy`, so the shutdown and `Cache::close` never run.
            report_failure_then(ready_tx, || {
                granary_client::OperatorDiagnostic::gran_mount_could_not_build_a_runtime_for_sigterm().emit();
            });
            return;
        };
        rt.block_on(async {
            let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            else {
                report_failure_then(ready_tx, || {
                    granary_client::OperatorDiagnostic::gran_mount_could_not_register_a_sigterm_handler_this().emit();
                });
                return;
            };
            // Same `Option<()>` reading as the SIGINT arm: a stream that
            // ENDED is not a signal that arrived, so it forwards nothing.
            let _ = report_then_wait(
                ready_tx,
                forward_signals(|context| term.poll_recv(context), tx, "SIGTERM"),
            )
            .await;
        });
    });
}

/// A writable daemon's engine shutdown, and the operator's own `--store-dir`
/// its status line names.
#[cfg(target_os = "linux")]
type DaemonStopping<'a> = (std::sync::Arc<dyn DaemonStop>, &'a Path);

/// The daemon body proper: build the channel and the adapter, start the two
/// signal producers FIRST (`signals`; production passes
/// [`spawn_signal_threads`]) and wait for both to report readiness
/// ([`await_signal_readiness`]) before ever mounting, take the unmounter
/// (fact 3 — after `run(self)` consumes the session it is too late), spawn
/// the session thread (fact 1's consequence — it needs its own OS thread
/// because the mount's own is busy `block_on`ing `GrainFetch` calls from
/// the FUSE callback thread), then hand everything real to
/// [`run_coordinator`], [`session_verdict`] and [`mount_shutdown_outcome`],
/// and print [`mount_status_line`]'s line.
#[cfg(target_os = "linux")]
#[expect(
    clippy::too_many_lines,
    reason = "the daemon's lifecycle is ONE ordered sequence and its order is the \
              correctness property: take the unmounter before `run` consumes the session, \
              arm both signal threads and WAIT for their readiness before the kernel mount \
              exists, then hand everything to `run_coordinator`. Splitting it would put a \
              function boundary between steps whose ordering is that property, so no one \
              piece would show a reader the order it depends on; the file takes this expect \
              elsewhere on the same ground. **Only Linux ever compiles this**, so the \
              lint fires nowhere else and this attribute is unfulfilled on no platform \
              that builds it"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "a writable daemon also receives its view binding and its engine's shutdown, \
              a test its own signal producer, and an armed one the protected banner \
              destination"
)]
fn run_fuse_daemon<B: granary_fuse::MountBackend + SupportBackend>(
    session: B,
    snapshot: granary_vfs::Snapshot,
    generation: u64,
    writability: granary_fuse::MountWritability,
    mountpoint: &Path,
    config: &fuser::Config,
    #[cfg(feature = "conformance-breakage")] breakage: Option<granary_fuse::Breakage>,
    wire: &MountWireSnapshot,
    bind: Option<BindView<B>>,
    stop: Option<DaemonStopping<'_>>,
    support: Option<SupportOwners>,
    metrics: Option<granary_net::metrics_listener::Listener>,
    control_owner: u32,
    control_mode: granary_core::mount_control::Mode,
    signals: impl FnOnce(std::sync::mpsc::Sender<Exit>, std::sync::mpsc::Sender<()>),
    #[cfg(feature = "conformance-breakage")] log: &mut dyn Write,
) -> MountOutcome {
    // Before the adapter, so `destroy` can say it is running. The daemon
    // keeps a sender for the shutdown thread, so the coordinator's channel
    // never disconnects while it runs.
    let (tx, rx) = std::sync::mpsc::channel::<Exit>();
    let cache_close: std::sync::Arc<std::sync::Mutex<Option<Result<(), String>>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let backend = DaemonBackend {
        session,
        cache_close: std::sync::Arc::clone(&cache_close),
        exit: tx.clone(),
    };
    // `GranaryFs::new` verifies the snapshot it was handed admits no
    // looser a `readlink` bound than this adapter can serve. A refusal here
    // is a pre-flight one — before any signal thread is spawned and before
    // the kernel mount exists — so the early return below leaves nothing to
    // unwind. Dropping `backend` (and so the `MountSession` it owns) on this
    // path still closes the cache: `MountSession`'s `Drop`
    // (`granary-client/src/mount.rs`) takes `self.cache` and calls
    // `Cache::close`, logging a close failure through `tracing` rather than
    // losing the signal.
    let fs = match granary_fuse::GranaryFs::new(snapshot, backend, generation, writability) {
        Ok(fs) => fs,
        Err(e) => {
            if config.mount_options.contains(&fuser::MountOption::RW) {
                granary_client::op_failed(
                    granary_client::OperationKind::Session,
                    granary_client::FailureClass::Io,
                );
                crate::terminal::write_line(format_args!("gran mount: WritableMountAttachFailed"));
            } else {
                crate::terminal::write_line(format_args!("gran mount: {e}"));
            }
            return MountOutcome::RuntimeFailure;
        }
    };
    // Arm the mount and print the grepped banner BEFORE
    // `fuser::Session::new` below ever takes `fs` — a feature build
    // with no `--breakage` never reaches this function at all (the
    // mutual refusal is `mount_attempt_with_credentials`'s own first
    // check, not `parse_mount`'s), so `breakage`
    // is always `Some` here on that build; this still handles `None`
    // rather than asserting, matching the "no panic reachable from a
    // CLI-composed value" rule the rest of this crate holds to.
    #[cfg(feature = "conformance-breakage")]
    let mut fs = fs;
    #[cfg(feature = "conformance-breakage")]
    if let Some(breakage) = breakage {
        fs.set_breakage(breakage);
        crate::conformance_stderr_checkpoint("banner");
        emit_breakage_banner(breakage.name(), log);
    }

    // The readiness handshake ([`spawn_signal_threads`]): both producers
    // report before the kernel mount below exists.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    signals(tx.clone(), ready_tx);

    // Block until both signal threads have reported, before
    // the kernel mount below is ever created.
    await_signal_readiness(&ready_rx);

    // Resolved BEFORE `Session::new` below is even called: `Session::new`
    // takes `P: AsRef<Path>` and so does not consume `mountpoint`, but
    // this keeps the `detach` closure's own capture independent of that
    // call's borrow. `detach_target_for`
    // decides ONCE, here, rather than lazily inside the closure at
    // shutdown, because a `resolve_for_verification` failure is
    // something an OPERATOR can act on while the mount is still healthy
    // — by the time the closure below would run, the daemon is already
    // exiting and there is nothing left for anyone to act on.
    let detach_target = detach_target_for(mountpoint);
    if let DetachTarget::Unavailable(why) = &detach_target {
        granary_client::OperatorDiagnostic::gran_mount_detach_target_unavailable_lazy_detach_cannot_be(why.class).emit();
    }
    let support_view = fs.view_handle();
    let mut view = fs.view_handle();
    // The directory, every source root and the support endpoint are still
    // pre-mount objects here. Their identities and pinned descriptors anchor
    // custody without issuing an operation to the FUSE session; the mount key
    // captured from mountinfo below identifies the mounted object at the same
    // resolved pathname that a requester independently observes. In particular,
    // neither a source beneath the mountpoint nor a runtime directory covered by
    // it may be walked after Session::new hides them behind the as-yet-unserved
    // mount.
    let support_proof = if let Some(support) = &support {
        let DetachTarget::Resolved(target) = &detach_target else {
            crate::terminal::write_line(format_args!("gran mount: support producer unavailable"));
            return MountOutcome::RuntimeFailure;
        };
        let Ok((identity, _)) = granary_client::prove_mountpoint(target) else {
            crate::terminal::write_line(format_args!("gran mount: support producer unavailable"));
            return MountOutcome::RuntimeFailure;
        };
        let Ok(roots) = prove_support_roots(&support.roots) else {
            crate::terminal::write_line(format_args!("gran mount: support producer unavailable"));
            return MountOutcome::RuntimeFailure;
        };
        let Some(endpoint) = start_support(
            &detach_target,
            |target| control::Support::prepare(control_owner, target),
            crate::terminal::write_line,
        ) else {
            return MountOutcome::RuntimeFailure;
        };
        Some((identity, roots, endpoint))
    } else {
        None
    };
    let Some(mut control) = start_control(
        &detach_target,
        |target| control::Control::start(control_owner, target, control_mode, tx.clone()),
        crate::terminal::write_line,
    ) else {
        return MountOutcome::RuntimeFailure;
    };
    let mut fuser_session = match fuser::Session::new(fs, mountpoint, config) {
        Ok(s) => s,
        Err(e) => {
            if config.mount_options.contains(&fuser::MountOption::RW) {
                granary_client::op_failed(
                    granary_client::OperationKind::Session,
                    granary_client::FailureClass::Io,
                );
                crate::terminal::write_line(format_args!("gran mount: WritableMountAttachFailed"));
            } else {
                crate::terminal::write_line(format_args!("gran mount: {e}"));
            }
            return MountOutcome::RuntimeFailure;
        }
    };
    // Captured now, while the mount is fresh at the resolved path and before
    // the session serves, so that the end of the session can ask whether
    // THIS mount is still in the table wherever it has moved since. A failed
    // capture is kept as the error the end of the session will read: a
    // mount whose presence cannot be checked never classifies as gone.
    let identity = capture_mount_identity(&detach_target);
    let observed = match &detach_target {
        DetachTarget::Resolved(target) => mount_table::control_mounts(target),
        DetachTarget::Unavailable(_) => Err(std::io::Error::other("unresolved control target")),
    };
    let Some(key) = control_mount_key(observed, control_owner, crate::terminal::write_line) else {
        return MountOutcome::RuntimeFailure;
    };
    let (_support_service, support_presence) = if let Some(support) = support {
        let DetachTarget::Resolved(_) = &detach_target else {
            crate::terminal::write_line(format_args!("gran mount: support producer unavailable"));
            return MountOutcome::RuntimeFailure;
        };
        let Some((mountpoint, roots, endpoint)) = support_proof else {
            crate::terminal::write_line(format_args!("gran mount: support producer unavailable"));
            return MountOutcome::RuntimeFailure;
        };
        let layout = support_layout(mountpoint, key, roots);
        let owners = crate::support_bundle::LiveOwners {
            configuration: support.context.configuration,
            history: support.context.history,
            metrics: support.metrics,
            overlay: support.overlay.map(|overlay| {
                std::sync::Arc::new(move || overlay.try_overlay_bundle())
                    as std::sync::Arc<
                        dyn Fn() -> Result<granary_core::support::BundleOverlay, BundleRefusal>
                            + Send
                            + Sync,
                    >
            }),
        };
        let producer = control::SupportProducer::new(layout, move || {
            collect_support(&support_view, &owners, WallClock.now()).map_err(std::io::Error::other)
        });
        let presence = producer.clone();
        let Some(service) = start_support(
            &detach_target,
            |_target| control::Support::start(control_owner, endpoint, producer),
            crate::terminal::write_line,
        ) else {
            return MountOutcome::RuntimeFailure;
        };
        (Some(service), Some(presence))
    } else {
        (None, None)
    };
    if let Err(error) = control.serving(key) {
        crate::terminal::write_line(format_args!("gran mount: control startup failed: {error}"));
        return MountOutcome::RuntimeFailure;
    }
    if let Some(bind) = bind {
        view.set_notifier(std::sync::Arc::new(fuser_session.notifier()));
        if bind(view).is_err() {
            granary_client::op_failed(
                granary_client::OperationKind::Session,
                granary_client::FailureClass::Io,
            );
            crate::terminal::write_line(format_args!("gran mount: WritableMountAttachFailed"));
            return MountOutcome::RuntimeFailure;
        }
    }
    // FACT 3: taken BEFORE `run(self)` below consumes `fuser_session` —
    // a `SessionUnmounter` taken after `Session::spawn()`/`run()` finds
    // `None` and silently returns `Ok(())` having done nothing.
    let mut unmounter = fuser_session.unmount_callable();

    // The shutdown thread's sender: the daemon keeps it, so the
    // coordinator's channel stays connected while the coordinator runs.
    let tx_shutdown = tx.clone();

    // Producer 1: the session thread, taking the ORIGINAL `tx`.
    // FACT 1: `run` blocks its calling thread in `thread.join()` even at
    // `n_threads = 1` (`session_config`'s own `n_threads = Some(1)`), so
    // it needs its own OS thread or nothing below this point ever runs.
    // `tokio::spawn`/`spawn_blocking` are banned workspace-wide;
    // `std::thread::spawn` is not a `tokio` seam.
    //
    // The send is a `SessionEndedGuard`'s `Drop`, not a bare
    // statement after `run()` — see that type's own doc for why a
    // statement placed there never runs on a panic and hangs the
    // coordinator's `rx.recv()` forever.
    let session_thread = std::thread::spawn(move || {
        let _guard = SessionEndedGuard(tx);
        fuser_session.run()
    });

    let engine = stop.as_ref().map(|(stop, _)| std::sync::Arc::clone(stop));
    let unmount_presence = support_presence.clone();
    let detach_presence = support_presence.clone();
    let unmount_identity = identity.as_ref().ok().cloned();
    let detach_identity = identity.as_ref().ok().cloned();
    let coordinated = run_coordinator(
        &rx,
        metrics,
        engine.as_ref().map(|engine| EngineStop {
            start: |trigger| start_shutdown(std::sync::Arc::clone(engine), tx_shutdown, trigger),
            expire: || engine.expire(),
        }),
        || {
            support_absence_after(
                unmount_presence.as_ref(),
                || unmounter.unmount(),
                || {
                    unmount_identity
                        .as_ref()
                        .map_or(Ok(true), granary_fuse::MountIdentity::listed)
                },
            )
        },
        || match &detach_target {
            DetachTarget::Resolved(p) => support_absence_after(
                detach_presence.as_ref(),
                || granary_fuse::detach_unmount(p).map_err(|e| detach_failure_class(&e)),
                || {
                    detach_identity
                        .as_ref()
                        .map_or(Ok(true), granary_fuse::MountIdentity::listed)
                },
            ),
            DetachTarget::Unavailable(why) => Err(why.class),
        },
        || session_thread.join(),
        SESSION_END_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    // `joined` is `None` when the daemon stopped waiting for its session
    // to end: the grace ran out with a descriptor or namespace copy still
    // held, or a signal ended the wait.
    let connection_identity = identity.as_ref().ok().cloned();
    let session = session_verdict(
        unmount_evidence(coordinated.arm, coordinated.unmount, coordinated.detach),
        coordinated.joined,
        || identity.and_then(|identity| identity.listed()),
        || connection_identity.and_then(|identity| identity.connection_alive().ok()),
    );
    // Session classification never adds another detach. fuser may already
    // have removed this mount before its worker reports a failure, exposing
    // another filesystem at the same pathname. The coordinator owns the
    // unmount fallback; the administrative command owns its attested detach.
    // Recovers the slot even if the Mutex was poisoned,
    // rather than `.lock().ok()` silently answering None for that case
    // too (indistinguishable from "destroy never ran").
    let report = shutdown_report(coordinated.report, engine.as_deref());
    let outcome = finish_control(control, report, engine.is_some(), &session, || {
        read_cache_close_slot(&cache_close)
    });
    let line = mount_status_line(
        "gran mount",
        stop.map(|(_, store)| (report, store)),
        outcome,
    );
    crate::terminal::write_line(format_args!("{line}"));
    // Written here — after the session has ended AND the cache has
    // closed (both folded into `outcome` above already), and ONLY on a
    // clean exit. A `RuntimeFailure`/`CacheCloseFailed` outcome means
    // the session did not end the way this measurement needs, the same
    // reasoning the server's own writer uses for `DeadlineExpired`.
    if outcome == MountOutcome::Clean {
        write_wire_snapshot_if_requested(
            wire.config.as_ref(),
            &wire.handle,
            Some(&wire.endpoint),
            wire.pinned_seq,
        );
    }
    outcome
}
