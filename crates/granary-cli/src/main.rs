// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
// @file-disposition-lines: 2170
// @file-disposition: SPLIT — The crate root keeps argument parsing, command dispatch and the subjects not cut out as children; each separated subject is its own child module. src/keys.rs holds private-key custody: the Ed25519 signing seed `gran publish` signs roots with, and its public sidecar. src/attach.rs holds the mount/umount attachment lifecycle, and its child src/attach/mount_table.rs holds the reading of the kernel's mount table. src/path_separation.rs holds the filesystem-separation refusals, which run before the store, cache or seed file they protect is created. src/admission.rs holds execution admission and the process-identity snapshot, and reaches no sibling. src/sink.rs holds the stderr sink whose writes never block on the destination, src/logging.rs the selection of log format, destination and filter and the destination the sink drains, and src/terminal.rs the direct terminal diagnostics. src/support_bundle.rs owns live and offline bundle parsing, bounded assembly, live owner collection and private archive publication. The crate root's unit tests are out of line in src/tests.rs. An item several children share belongs to the subject whose invariant it implements, never to the count of its consumers. src/publication.rs owns publication selection, routing and coordinator dispatch; src/publication_report.rs owns typed publication results and their human/JSON rendering. src/recover.rs owns explicit writer recovery flags and its credential and key custody boundary. src/overlay_discard.rs owns discard selection and output; its reconcile child owns reconciliation routing. SIX subjects are still held in this file, each a candidate child at its own measured seam — origin, wire_snapshot, cat, thresh, harvest, verify; re-measure before deriving one, because every landing moves the spans. check-file-dispositions.sh reads this directive at every size, and the `@file-disposition-lines` assertion above is the half it can check; the subject sentences are maintained by hand. check-fsguard-sites.sh points maintainers at this directive for the remaining subjects, which is why it must move with the code.

//! `gran` — the granary CLI. `gran thresh <file>` prints the grain
//! table (offset, length, grain id) and the pinned chunker algorithm, version and parameters.
//! `gran harvest <source-dir> <store-dir>` walks a source tree
//! into a local CAS store and prints its manifest root id + stats.
//! `gran publish <store-dir> <source-dir> <volume> --endpoint URL
//! --pin sha256/PIN --key-seed FILE` selects retained work or harvests
//! a fresh publication through the checked authority coordinator.
//! Argument parsing is hand-rolled until the command surface grows
//! (the client binary is named `gran`; a parser dependency is not yet justified).
//!
//! **A thin binary over `granary_client`.** The store, the harvest
//! walk and the publish flow live in the lib;
//! what stays here is CLI-only — argument parsing, key file
//! handling, the wall-clock [`Clock`] implementation and the
//! writer identity drawn from the operating system's entropy.

// `disallowed_types` is `allow` in this crate's lint table. The binary's
// root opts in because it links aws-lc: `clippy.toml` bans aws-lc's
// generator outside the cryptographic-randomness seam's one sanctioned draw
// (`granary_net::secure_random::OsSecureRandom`), and a ban this root
// did not deny would be configured and never enforced.
#![deny(clippy::disallowed_types)]

// Cargo.toml's `[lints.clippy]` denies `allow_attributes` and
// `allow_attributes_without_reason` for every target. These reject
// outer `#[allow]` and reasonless `#[expect]` after macro expansion.
// A reasoned inner `#![allow(clippy::disallowed_methods, ...)]`
// passes those lints; `scripts/check-fsguard-sites.sh`
// refuses it through its source scanner.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use granary_client::{
    AmbientNetwork, Cache, CacheOrigin, ClientTotals, HeadContext, HttpStore, PublishSummary,
    ResolveError, ResolveOutcome, ResolveTarget, RootVerifier, Store, WireByteHandle, harvest,
    open_regular_read, resolve_at_verified, resolve_head_verified, wire_snapshot_trio_is_valid,
    write_client_snapshot,
};
use granary_core::binstore::BinStore;
use granary_core::clock::Clock;
use granary_core::hash::GrainId;
use granary_core::identity::{WRITER_IDENTITY_LEN, WriterIdentity};
use granary_core::manifest::Name;
use granary_core::rng::ProcessRng;
use granary_core::root::{Timestamp, VolumeName};
use granary_core::rootstore::RootStore;
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};
use granary_core::thresh::{self, OwnedGrain};
use granary_net::config::{ENV_TLS_PINS, SIGNING_KEY_LEN, parse_pin_set, parse_signing_key};
use granary_net::pin::SpkiPin;

// Private-key custody, a separate subject in its own child. The crate root
// reads exactly three names back out of it. Its own reach is one name,
// `ProcessCredentials`, and only that type's `euid` field — a SIBLING reach
// into `admission`, NOT a reach into this file. `keys.rs` imports it from
// `crate::admission` directly and its own header carries the matching
// sentence; amend the two together.
mod overlay_discard;
mod publication;
mod publication_report;
mod publish_config;
mod recover;
mod support_bundle;

mod keys;

mod attach;
use attach::{
    MOUNT_HELP, cmd_mount, cmd_umount, invoked_as_mount_gran, parse_mount, parse_mount_gran,
    parse_umount,
};

// Filesystem separation: its OUTBOUND reach into the crate ROOT is ZERO.
// `gran publish` checks managed paths on resume and all source separations on fresh work;
// `gran harvest` calls the store/source refusals.
//
// `refuse_key_seed_nesting` calls `crate::keys::public_key_path`:
// path separation depends on the sibling `keys` module.
mod path_separation;
use path_separation::{refuse_nesting, refuse_store_as_source};

// Execution admission and the process-identity snapshot. ZERO outbound;
// `publish`, `attach` and `keys` all reach it and it reaches none of them,
// which puts it at the bottom of the sibling dependency order.
mod admission;
use admission::{ProcessCredentials, process_credentials, set_id_refusal};

// The stderr sink: a write that never blocks on the destination, with
// reserved admission and priority of service for a user-facing result. A
// peer who can provoke a log line can fill this process's stderr pipe, and a
// synchronous write to a backpressured stderr blocks the thread performing
// it — which on the mount path is a wedge before the kernel filesystem
// exists, not a logging complaint.
mod sink;
mod terminal;

// Output selection: the format, the destination (standard error or a rotated
// file) and the filter, chosen by flag, environment or configuration file. The
// destination it builds is the writer the sink above drains; it changes
// nothing about the sink itself.
mod logging;

/// Build the CLI's log filter from a raw `RUST_LOG` value, WITHOUT writing
/// anything, and hand any complaint back to the caller instead of printing it.
///
/// The filter is constructed before a subscriber exists, so a diagnostic
/// emitted from inside this function is a synchronous write to a stderr
/// nothing in this process controls yet. A peer who can fill that pipe can
/// therefore stop `gran mount` before the kernel filesystem exists. Returning
/// the complaint is what lets the caller emit it through the writer it
/// installs, so the report moves with that writer and needs no second repair
/// when the writer changes.
///
/// `raw` is the whole of what reading the variable can produce, so this
/// function has no ambient input and a test drives every case directly. It
/// takes the `Result` rather than a string because the three outcomes are
/// genuinely different: a value, no variable at all, and a variable whose
/// bytes are not UTF-8. The dependency's own reader collapses the last two
/// with `unwrap_or_default`, which silently runs at the default level after
/// an operator set the variable — the same silence this function exists to
/// remove for a malformed value.
fn env_filter_from(
    raw: Result<String, std::env::VarError>,
) -> (
    tracing_subscriber::EnvFilter,
    Option<granary_client::FilterDetail>,
) {
    let default_directive = || tracing_subscriber::filter::LevelFilter::INFO.into();
    let default = || tracing_subscriber::EnvFilter::default().add_directive(default_directive());
    let raw = match raw {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return (default(), Some(granary_client::FilterDetail::NotUnicode));
        }
    };
    match tracing_subscriber::EnvFilter::builder()
        .with_default_directive(default_directive())
        .parse(&raw)
    {
        Ok(filter) => (filter, None),
        // The value is rejected WHOLE, not directive by directive. The lossy
        // parser keeps whichever directives it could read, so a typo in one
        // of them leaves a filter nobody asked for silently in force; falling
        // back to the default is the outcome the report below describes, and
        // an operator who wanted the readable half can say so.
        //
        // `EnvFilter::default()` carries no directives, so adding the default
        // one back gives exactly what an unset `RUST_LOG` produces — the same
        // filter, built without a second parse that would need its own error
        // arm.
        Err(_) => (default(), Some(granary_client::FilterDetail::Malformed)),
    }
}

// This wall rejects rendezvous with debug assertions disabled. It is not total:
// CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true bypasses it; the exclusion gate inspects the executable.
#[cfg(all(feature = "publish-restart-tests", not(debug_assertions)))]
compile_error!("publish-restart-tests must never compile into a release granary-cli artifact");

#[expect(
    clippy::too_many_lines,
    reason = "descriptor capture, sink/subscriber installation and command dispatch form one ordered startup boundary; command bodies are separate functions"
)]
fn main() -> ExitCode {
    #[cfg(feature = "publish-restart-tests")]
    if let Err(error) = granary_client::publish_restart::initialize() {
        terminal::write_line(format_args!("restart rendezvous: {error}"));
        return ExitCode::FAILURE;
    }
    terminal::install_panic_hook();
    let mut process_args = std::env::args_os();
    // `argv[0]`'s file name is the ONLY signal `mount.gran` (a
    // symlink to this same binary, JuiceFS's model) has to
    // identify itself by — checked BEFORE the subcommand-word
    // dispatch below, because when invoked that way there IS no
    // subcommand word: every remaining argument is `mount.gran`'s
    // own `device dir -o opt1,opt2` operand list.
    let argv0 = process_args.next().unwrap_or_default();
    let mount_gran = invoked_as_mount_gran(&argv0);
    let process_args = process_args.collect::<Vec<_>>();
    if !mount_gran
        && let Ok((_, support_args)) = logging::Flags::split(process_args.clone())
        && support_args
            .first()
            .and_then(|arg| arg.to_str())
            .is_some_and(|arg| arg == "support-bundle")
    {
        return match support_bundle::parse(support_args.get(1..).unwrap_or_default()) {
            Ok(args) => support_bundle::invoke(&args),
            Err(error) => {
                terminal::write_line(format_args!("gran: support bundle: {error}"));
                ExitCode::from(2)
            }
        };
    }
    // Offline overlay refusals use fixed redacted JSON on stderr.
    if !mount_gran && process_args.first().is_some_and(|arg| arg == "overlay") {
        return overlay_discard::invoke(process_args.get(1..).unwrap_or_default());
    }
    let prepared = match logging::prepare(mount_gran, process_args, env_filter_from) {
        Ok(prepared) => prepared,
        Err(exit) => return exit,
    };
    let logging::Prepared {
        settings: log_settings,
        file: log_file,
        filter: env_filter,
        complaint: filter_complaint,
        args,
    } = prepared;
    // The sink, installed BEFORE the subscriber that writes through it. Its
    // worker is held for the whole of `main`: dropping it closes and drains
    // within a bound, so an ordinary return flushes what is queued while a
    // wedged stderr still cannot stop the exit.
    let original_stderr = match logging::capture_stderr(&std::io::stderr()) {
        Ok(stderr) => stderr,
        Err(exit) => return exit,
    };
    let bundle_history = granary_client::BundleHistory::default();
    let (log_sink, _log_worker) = sink::sink_to(logging::Destination::with_policy(
        original_stderr,
        log_file,
        log_settings.format,
        log_settings.paths,
        bundle_history.clone(),
    ));
    if let Err(exit) = log_sink.install_local_reports() {
        return exit;
    }
    // STDERR, never the default `stdout` — `granary-server`'s
    // own `main.rs` makes the identical choice for the identical
    // reason (log noise off the primary content stream), and `gran
    // cat`'s primary content stream IS stdout: the file's bytes.
    // `gran cat` reaches a `tracing::*!` call site through its
    // cache path: when `--cache-dir` threads a `Cache` into
    // `cat_resolve`, a degraded-serve announcement (`resolve.rs`'s
    // `announce_degraded`) at the default writer would land IN the
    // file `gran cat` is streaming to stdout, corrupting it — the
    // exact defect `the_cat_help_names_cache_dir_and_says_
    // what_a_degraded_read_is` test's "announced on stderr" claim
    // would otherwise make false.
    // THE SINK, not `std::io::stderr`: tracing records go through
    // the process sink rather than writing stderr on this thread.
    if let Err(error) = logging::install_with_history(
        &log_settings,
        env_filter,
        log_sink.clone(),
        bundle_history.clone(),
    ) {
        terminal::write_line(format_args!("gran: cannot install logging: {error}"));
        return ExitCode::FAILURE;
    }
    // Every event emitted within an operation span carries that span's
    // correlation id. The session span is entered on this thread, so the
    // events this thread emits carry the run's id. A thread or task that does
    // not open its own operation span carries none; the operations that need
    // one open it where they run.
    let session = logging::session_span();
    let _session_entered = session.as_ref().map(tracing::Span::enter);
    granary_client::log_config(log_settings.format, logging::destination_of(&log_settings));
    // A malformed value selects the default INFO filter, so this WARN always
    // passes. Only `log.config` (a DEBUG line, absent at the default filter)
    // can precede it, so the queue is all but empty and backpressure cannot
    // refuse its admission. Delivery still depends on stderr.
    if let Some((reason, detail)) = filter_complaint {
        granary_client::log_filter_rejected(reason, detail);
    }
    // The destination `gran mount`'s one-shot reports land on: the sink's
    // Local stream, which shares reserved admission and priority with Protected.
    // The typed report method selects Local; other operator results use Protected.
    // Those reports are user-facing results — the pinned root an operator
    // reads, an equivocation finding — not telemetry, so they must not be
    // dropped to make room for a resolve round's INFO line.
    let mut mount_log = log_sink.protected_writer();
    if invoked_as_mount_gran(&argv0) {
        return cmd_mount_gran_with_support(
            &args,
            &mut mount_log,
            Some((&log_settings, bundle_history.clone())),
        );
    }
    let rest = args.get(1..).unwrap_or_default();
    match args.first().and_then(|c| c.to_str()) {
        Some("thresh") => match rest {
            [path] => cmd_thresh(Path::new(path)),
            _ => usage(),
        },
        Some("harvest") => match rest {
            [src, store_dir] => cmd_harvest(Path::new(src), Path::new(store_dir)),
            _ => usage(),
        },
        Some("publish") => {
            let mut json = false;
            let mut configuration = publish_config::PublishConfiguration::default();
            match parse_publish_checked(
                rest,
                &|name| std::env::var(name).ok(),
                &mut configuration,
                &mut json,
            ) {
                Ok(args) => cmd_publish(&args),
                Err(error) => publication_report::InvocationReport::usage(error).render(
                    json,
                    &mut std::io::stdout(),
                    &mut std::io::stderr(),
                ),
            }
        }
        Some("recover") => match recover::parse(rest, &|name| std::env::var(name).ok()) {
            Ok(args) => recover::invoke(&args, log_settings.paths),
            Err(error) => {
                terminal::write_line(format_args!("gran recover: {error}"));
                usage()
            }
        },
        Some("cat") => match parse_cat(rest) {
            Ok(args) => cmd_cat(&args),
            Err(e) => {
                terminal::write_line(format_args!("gran cat: {e}"));
                usage()
            }
        },
        Some("verify") => match parse_verify(rest) {
            Ok(root) => cmd_verify(&root),
            Err(e) => {
                terminal::write_line(format_args!("gran verify: {e}"));
                usage()
            }
        },
        Some("mount") => match parse_mount(rest) {
            Ok(mut margs) => {
                margs.arm_support(&log_settings, bundle_history.clone());
                cmd_mount(&margs, &mut mount_log)
            }
            Err(e) => {
                report_mount_argument_refusal(rest, &e, &terminal::write_line);
                usage()
            }
        },
        Some("umount") => match parse_umount(rest) {
            Ok(mountpoint) => cmd_umount(&mountpoint, &mut mount_log),
            Err(e) => {
                terminal::write_line(format_args!("gran umount: {e}"));
                usage()
            }
        },
        _ => usage(),
    }
}

/// `gran cat`'s help, HOISTED OUT of [`usage`] so a row can read it.
///
/// **The honest-guarantee rule binds this text.** It says
/// it in as many words: neither the CLI's help nor its output
/// may claim signature verification on the no-key path — and
/// no mode may claim FRESHNESS, since the seq comes from
/// the untrusted store's `max_seq`. The runtime warning in
/// [`reader_verifier`] is checked against exactly that list of forbidden
/// words because its sink is a parameter; an inline `eprintln!` literal
/// is unreachable from any assertion, which is how a claim gets added
/// here and stays. So the literal moves out and the same loop runs over
/// it.
const CAT_HELP: &str = "\x20      gran cat <volume> <path> --endpoint <url> --pin sha256/... \
     [--root-key ed25519:<64 hex>] [--seq N] [--cache-dir <path>]\n\
     \x20        WITH --root-key: the content, the structure AND the root \
     SIGNATURE are checked.\n\
     \x20        WITHOUT it: content and structure only — the bytes are what \
     SOME writer\n\
     \x20        published, not a writer you trust. Neither mode says the head \
     is the\n\
     \x20        newest one: the seq comes from the store being read.\n\
     \x20        --seq N reads exactly seq N instead of the head — the manual \
     way out of\n\
     \x20        a volume whose head one planted root has made unreadable. It \
     never\n\
     \x20        engages by itself: without it, a head that will not resolve \
     stays an\n\
     \x20        error rather than becoming a quiet read of an older tree.\n\
     \x20        --cache-dir <path> caches fetched objects and roots on disk, \
     reused\n\
     \x20        across runs. It is bound to ONE trust configuration — the \
     endpoint, the\n\
     \x20        pin set, and whether --root-key was given — and naming a \
     different one\n\
     \x20        against the same directory is refused rather than silently \
     mixed. When\n\
     \x20        the transport is unreachable and this cache already holds a \
     resolvable\n\
     \x20        head, a --root-key reader is served the cached tree instead of \
     failing:\n\
     \x20        every object is re-hashed on read, the served head is \
     possibly stale,\n\
     \x20        and the read is always announced on stderr. A reader with no \
     --root-key\n\
     \x20        never degrades this way — with no key to check a cached root \
     against,\n\
     \x20        it reports the transport failure instead.";

/// `gran verify`'s help, HOISTED OUT the same way [`CAT_HELP`] is.
/// States the two root-type/mode splits and, in the operator's own
/// terms, the one thing that most needs saying: this verb REPORTS and
/// REPAIRS NOTHING, in either mode. A cache's corrupt object is
/// refetchable and could in principle be reclaimed, but reclaiming it
/// means naming it by a path rebuilt after the walk, which is exactly
/// the operation this crate cannot yet perform safely — so the help
/// says what verify does, not what a later version will.
const VERIFY_HELP: &str = "\x20      gran verify <store-or-cache-root>\n\
     \x20        Root-type detection: a store marker selects STORE mode, a cache \
     marker\n\
     \x20        selects CACHE mode; both present, neither, or either one \
     unreadable\n\
     \x20        is cannot-open (exit 2).\n\
     \x20        VERIFY REPORTS WHAT IS WRONG AND REPAIRS NOTHING. It never \
     deletes,\n\
     \x20        rewrites or reclaims anything under the root, in either mode. A \
     corrupt\n\
     \x20        object is reported and LEFT ON DISK; a cache reclaims one on its \
     own\n\
     \x20        next read of it, or you can remove the cache directory outright.\n\
     \x20        STORE mode re-hashes every object and reports corrupt, foreign \
     and\n\
     \x20        oversized files.\n\
     \x20        CACHE mode does the same and, when the writer lock is free AND \
     the\n\
     \x20        snapshot/journal pair is trustworthy, additionally COMPARES the \
     index:\n\
     \x20        dropped (indexed, file gone), adopted (on disk, unindexed) and \
     size-\n\
     \x20        mismatch. If the lock is held by another process, or the index \
     itself\n\
     \x20        cannot be read, that comparison is skipped — the unreadable index \
     file\n\
     \x20        is reported as a finding of its own, never as a clean run. Verify \
     never\n\
     \x20        blocks waiting for the lock.\n\
     \x20        One finding per line on stdout: \
     <kind>\\t<encoded-path>\\t<expected>\\t<actual>.\n\
     \x20        Diagnostics on stderr. Exit 0 clean / 1 findings / 2 \
     cannot-open.";

/// The whole usage message, BUILT rather than printed, so a row can
/// assert that what [`CAT_HELP`] says is what an operator is shown — a
/// const that is never printed is the "exists and is never called"
/// shape wearing different clothes.
fn usage_text() -> String {
    format!(
        "usage: gran [--log-format text|json] [--log-file <path>] [--log-filter <directives>] [--log-paths redacted|full] \
         [--log-config <path>] <command> ...\n\
         \x20        The logging options come first. The same settings are read from \
         GRANARY_LOG_FORMAT,\n\
         \x20        GRANARY_LOG_FILE, GRANARY_LOG_FILTER and GRANARY_LOG_CONFIG; a flag \
         beats the\n\
         \x20        environment, which beats the configuration file. A value that is not \
         understood\n\
         \x20        is refused.\n\
         \x20      gran thresh <file>\n\
         \x20      gran harvest <source-dir> <store-dir>\n\
         \x20      gran publish <store-dir> <source-dir> <volume> \
         --endpoint <url> [--key-seed <file>] \
         [--pin sha256/... | --direct-s3 --bucket <name>] \
         [--cache-dir <path>] [--publish-mode auto|authority|legacy-server]\n\
         \x20        [--client-cert FILE --client-key FILE] [--credential-context NAME]\n\
         \x20        [--publisher-key ed25519:<64 lowercase hex>] [--json]\n\
         \x20        [--new | --recover ID | --abandon ID --acknowledge-may-land]\n\
         \x20        --key-seed is required except for local abandonment.\n\
         {CAT_HELP}\n\
         {recover_help}\n\
         \x20      gran overlay discard --help | gran overlay reconcile --help\n\
         {VERIFY_HELP}\n\
         {MOUNT_HELP}\n\
         \x20      gran umount <mountpoint>\n\
         \x20        Detach a granary mount from a DIFFERENT process than the one \
         serving\n\
         \x20        it: closes nothing itself, detaches the kernel mount, then \
         verifies\n\
         \x20        it is actually gone. Linux only.\n\
         \x20      gran support-bundle <mountpoint> --output <file>\n\
         \x20      gran support-bundle --output <file> --offline \
         --cache-dir <dir|none> --overlay-dir <dir|none> \
         --store-dir <dir|none> --mountpoint <dir|unknown>",
        recover_help = recover::HELP,
    )
}

fn usage() -> ExitCode {
    terminal::write_line(format_args!("{}", usage_text()));
    ExitCode::from(2)
}

/// Every `gran` subcommand that touches the filesystem acquires the
/// credential snapshot and refuses a set-ID invocation FIRST. `harvest` reads a source tree and writes objects into a caller-named store at
/// mode 0444, so under set-ID it is the clearest confused deputy of the four:
/// a privileged read of a directory the invoker cannot open, exported to one
/// they can.
///
/// The split into a `_with_credentials` half is `cmd_publish`'s, and it is
/// what makes the refusal testable without a set-ID process: the test supplies
/// the snapshot. The refusal is BEFORE `Store::open`, which creates the store's structural
/// directories and its lock file, so a refused invocation
/// leaves no footprint, which is the observable its tests assert on rather
/// than an exit code every other failure also produces.
fn cmd_harvest(source: &Path, store_dir: &Path) -> ExitCode {
    let credentials = process_credentials();
    cmd_harvest_with_credentials(source, store_dir, &credentials, &mut std::io::stderr())
}

fn cmd_harvest_with_credentials(
    source: &Path,
    store_dir: &Path,
    credentials: &ProcessCredentials,
    err: &mut dyn std::io::Write,
) -> ExitCode {
    if let Some(e) = set_id_refusal(credentials) {
        let _ = writeln!(err, "gran harvest: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = refuse_store_as_source(source).and_then(|()| refuse_nesting(source, store_dir))
    {
        eprintln!("gran harvest: {e}");
        return ExitCode::FAILURE;
    }
    let store = match Store::open(store_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gran harvest: {e}");
            return ExitCode::FAILURE;
        }
    };
    match harvest(source, &store) {
        Ok((manifest_root, s)) => {
            println!("manifest-root {manifest_root}");
            println!("dirs {} files {} symlinks {}", s.dirs, s.files, s.symlinks);
            println!(
                "grains {} novel {} bytes {} novel {}",
                s.grains_total, s.grains_novel, s.bytes_total, s.bytes_novel
            );
            println!("manifest nodes {} novel {}", s.nodes_total, s.nodes_novel);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("gran harvest: {e}");
            ExitCode::FAILURE
        }
    }
}

// --------------------------------------------------- the wire-byte snapshot

/// The `--wire-snapshot`/`--wire-run-id`/`--wire-role` trio, shared by
/// `gran cat`, `gran mount` and `gran publish` — ALL THREE or none.
/// Absent in ordinary use; the harness sets these on the command line
/// of exactly the process they are for, never in its own environment.
#[derive(Debug, Clone)]
struct WireSnapshotArgs {
    path: PathBuf,
    run_id: String,
    role: String,
}

/// Resolve the trio from three already-parsed `Option`s, refusing a
/// partial set. Shared by every command's own parser so the three
/// cannot drift into three different all-or-nothing checks.
///
/// **The VALUES are validated here too, not only their presence.**
/// Before value validation, a complete but malformed trio —
/// `gran mount --wire-role clientt-1` (note the typo), for example —
/// parsed cleanly, ran the entire verb, and
/// was refused only when [`write_wire_snapshot_if_requested`] (or
/// `gran publish`'s own writer) finally tried to write the snapshot
/// at exit. This is the client's counterpart to `granary-server`'s
/// own `wire_snapshot_trio_is_valid` — the presence check above
/// still runs first, so a partial trio keeps naming which flag is
/// missing rather than being reinterpreted as a value error.
fn wire_snapshot_args(
    path: Option<PathBuf>,
    run_id: Option<String>,
    role: Option<String>,
) -> Result<Option<WireSnapshotArgs>, String> {
    let wire = match (path, run_id, role) {
        (Some(path), Some(run_id), Some(role)) => WireSnapshotArgs { path, run_id, role },
        (None, None, None) => return Ok(None),
        (path, run_id, role) => {
            return Err(format!(
                "--wire-snapshot ({}), --wire-run-id ({}) and --wire-role ({}) must be given \
                 together or not at all",
                wire_flag_presence(path.as_ref()),
                wire_flag_presence(run_id.as_ref()),
                wire_flag_presence(role.as_ref()),
            ));
        }
    };
    wire_snapshot_trio_is_valid(&wire.path, &wire.run_id, &wire.role)
        .map_err(|error| format!("--wire-snapshot/--wire-run-id/--wire-role: {error}"))?;
    Ok(Some(wire))
}

/// Whether an `Option` a flag parser collected is set — the three-word
/// fragment [`wire_snapshot_args`]'s refusal names each flag with.
fn wire_flag_presence<T>(value: Option<&T>) -> &'static str {
    if value.is_some() { "given" } else { "absent" }
}

/// Write the wire-byte snapshot for a NON-publish writer (`gran
/// cat`, `gran mount`), or do nothing if the trio was never given.
/// A refused write is reported to stderr and does NOT change the
/// caller's own exit code: the write is auxiliary instrumentation
/// an operator opted into, and the verb's own read already
/// succeeded or failed on its own terms by the time this runs.
fn write_wire_snapshot_if_requested(
    wire: Option<&WireSnapshotArgs>,
    handle: &WireByteHandle,
    endpoint: Option<&str>,
    pinned_seq: Option<u64>,
) {
    let Some(wire) = wire else {
        return;
    };
    let totals = ClientTotals {
        response_bytes: handle.total(),
        endpoint: endpoint.map(str::to_owned),
        pinned_seq,
        publish: None,
    };
    if let Err(error) = write_client_snapshot(&wire.path, &wire.run_id, &wire.role, &totals) {
        #[cfg(feature = "conformance-breakage")]
        conformance_stderr_checkpoint("wire-snapshot-failed");
        terminal::write_line(format_args!("wire-snapshot not written: {error}"));
    }
}

/// Independent witnesses for the Linux stderr harness. The forwarded feature's
/// release compile wall excludes this entire helper from production binaries.
/// A missing witness is a failed probe; never fall back to the stream under test.
#[cfg(feature = "conformance-breakage")]
#[expect(
    clippy::disallowed_methods,
    reason = "debug conformance witness in a harness-owned directory; absent from production, \
              independent of the stderr destination under test"
)]
fn conformance_stderr_checkpoint(name: &str) {
    if let Some(directory) = std::env::var_os("GRANARY_STDERR_PROBE")
        && std::fs::write(PathBuf::from(directory).join(name), b"reached\n").is_err()
    {
        std::process::exit(97);
    }
}

// ------------------------------------------------------------- publish

/// Checked publication operands and explicit route, identity and selection options.
/// Store first; source is unused for retained recovery and local abandonment.
/// Unknown flags refuse with a fixed diagnostic.
struct PublishArgs {
    store_dir: PathBuf,
    source: PathBuf,
    volume: VolumeName,
    endpoint: String,
    /// Required only on the `--direct-s3` path; the server path has no
    /// bucket, which is the point of it.
    bucket: Option<String>,
    key_seed: PathBuf,
    configuration: publish_config::PublishConfiguration,
    mode: publication::PublishMode,
    selection: publication::Selection,
    json: bool,
    /// The TLS pin set, from `--pin` or [`ENV_TLS_PINS`]. `Some`
    /// selects the through-the-server route.
    tls_pins: Option<Vec<SpkiPin>>,
    /// The explicit opt-out back to the bucket.
    direct_s3: bool,
    /// The local object/root cache. Absent (the default) means the
    /// anchor/root persistence a successful publish mandates simply does
    /// not run — the floor this cache dir tracks stays lower, stated
    /// rather than hidden. REFUSED together with `direct_s3`: the
    /// direct-S3 route has no endpoint/pin origin to bind a cache dir to.
    cache_dir: Option<PathBuf>,
    /// The wire-byte snapshot trio, or `None` in ordinary use.
    wire: Option<WireSnapshotArgs>,
}

impl std::fmt::Debug for PublishArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishArgs")
            .field("direct_s3", &self.direct_s3)
            .field("pins_configured", &self.tls_pins.is_some())
            .field("cache_configured", &self.cache_dir.is_some())
            .field("wire_configured", &self.wire.is_some())
            .finish_non_exhaustive()
    }
}

/// One pin list, from ONE named source — refused when it names no pins.
///
/// **`parse_pin_set` answers `Ok(vec![])` for an empty or whitespace-only
/// list**, and an empty pin set is the set that refuses EVERY certificate
/// (`PinnedServerVerifier::new` accepts one deliberately, so that "not
/// configured yet" can never mean "accept anything"). A value naming no
/// pins is therefore not a transport, and the two things it could be
/// taken for are both wrong: as a PIN SET it selects the
/// through-the-server route with a verifier nothing can satisfy, and the
/// operator hears about their typo as a handshake failure; as ABSENT it
/// falls through to the opt-out, and the operator who blanked the
/// variable gets a bucket publish nobody asked for.
///
/// So it is a usage error naming its own source — `--pin` or
/// `GRANARY_TLS_PINS` — and BOTH entry points run through here, which is
/// what keeps them from disagreeing. An exported-but-empty
/// `GRANARY_TLS_PINS` is an error; the message says to unset it.
///
/// **The REMEDY is the caller's, because the two commands have
/// different ones.** Sharing the check is the point; sharing the advice
/// would not be, since `gran cat` has neither a bucket to opt out to nor
/// an environment fallback to unset — offering it either is advice for
/// something that does not exist, and an operator who follows it lands
/// on `unknown flag --direct-s3`.
fn pins_from(source: &str, raw: &str, remedy: NoPinsRemedy) -> Result<Vec<SpkiPin>, String> {
    let parsed = parse_pin_set(raw).map_err(|e| format!("{source}: {e}"))?;
    if parsed.is_empty() {
        return Err(format!(
            "{source}: names no pins. Give at least one sha256/... pin{}",
            remedy.advice()
        ));
    }
    Ok(parsed)
}

/// What the operator may do INSTEAD of naming pins — one variant per
/// command, because the alternatives really do differ.
#[derive(Clone, Copy)]
enum NoPinsRemedy {
    /// `gran publish`: the pin set SELECTS a route, so "no pins" is a
    /// state with two legitimate readings and the message has to name
    /// both — the bucket opt-out, and unsetting the variable whose
    /// blanking produced this.
    PublishMayOptOutToTheBucket,
    /// `gran cat`: pins are the transport and there is nothing else to
    /// be. No second route, and `GRANARY_TLS_PINS` is not read on this
    /// path, so the only correct advice is to name a pin.
    ReadHasNoSecondRoute,
    /// `gran mount`: the SAME shape as `gran cat` — pins are the
    /// transport, no second route, no environment fallback — but a
    /// distinct variant rather than reusing `ReadHasNoSecondRoute`,
    /// whose advice text names `gran cat` literally and would
    /// misname the command an operator is actually running.
    MountHasNoSecondRoute,
    RecoverHasNoSecondRoute,
}

impl NoPinsRemedy {
    fn advice(self) -> &'static str {
        match self {
            Self::RecoverHasNoSecondRoute => {
                ". `gran recover` requires a pinned granary server; unset an empty GRANARY_TLS_PINS or supply --pin sha256/..."
            }
            Self::PublishMayOptOutToTheBucket => {
                " (unset the variable if that is what you meant), or opt out to the \
                 bucket with --direct-s3 --bucket <name>"
            }
            Self::ReadHasNoSecondRoute => {
                ". `gran cat` reads only through a pinned granary server: there is no \
                 unpinned route to fall back to, and GRANARY_TLS_PINS is not read on \
                 this path"
            }
            Self::MountHasNoSecondRoute => {
                ". `gran mount` reads only through a pinned granary server: there is no \
                 unpinned route to fall back to, and GRANARY_TLS_PINS is not read on \
                 this path"
            }
        }
    }
}

/// The CLI's quota POLICY default — 10 GiB.
/// `Cache::open` takes the quota as a parameter, not an invariant of its
/// own, so this figure belongs here rather than in `cache.rs`; its own
/// literal-pinning test lives in this module's test suite.
const DEFAULT_CACHE_QUOTA_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Compose a `CacheOrigin` from THIS invocation's CLI
/// inputs — never a value read back off disk, never guessed. `endpoint`
/// is the `--endpoint` value VERBATIM; `pins` goes through
/// [`CacheOrigin::pin_set_digest`] (sorted, deduplicated — order and
/// repetition do not move the digest); `root_key` is the reader/writer's
/// 32 raw public-key bytes when one is in play.
///
/// **The keyed/keyless asymmetry lives here, in the CALLER, not in this
/// function**: `cat` passes `None` when `--root-key` is absent
/// (composing `root_key_id: None`, the integrity-only mode) and
/// `Some(&public)` when it is given; `publish` always passes
/// `Some(&public)` (from `key.public_key()` directly, never
/// re-read from the `.pub` sidecar `load_or_create_key` just wrote). One
/// cache dir shared between an integrity-only `cat` and a `publish` is
/// therefore `CacheError::Incompatible` by construction, which is
/// correct and stated in [`CAT_HELP`].
fn cache_origin(endpoint: &str, pins: &[SpkiPin], root_key: Option<&[u8; 32]>) -> CacheOrigin {
    CacheOrigin {
        endpoint_url: endpoint.to_owned(),
        pin_set_digest: CacheOrigin::pin_set_digest(pins),
        root_key_id: root_key.map(CacheOrigin::root_key_digest),
    }
}

/// Ensures [`Cache::close`] runs on every exit of the function that opens
/// it, success or failure alike, without a
/// duplicated close call at each of `cmd_cat`'s (or `cmd_publish`'s)
/// several early returns. `None` when `--cache-dir` was not given — the
/// no-op case, matching every write method's own silent-no-op-without-a-
/// cache-dir contract. A close failure warns and never fails an
/// otherwise-successful read: the guard simply survives and the next
/// open rebuilds it (`Cache::close`'s own doc).
struct CacheOnDrop(Option<Cache>);

impl Drop for CacheOnDrop {
    fn drop(&mut self) {
        if let Some(cache) = self.0.take()
            && let Err(e) = cache.close()
        {
            terminal::write_line(format_args!("gran: warning: closing cache: {e}"));
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the checked option table and cross-option refusals form one parser"
)]
fn parse_publish_checked(
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<String>,
    configuration: &mut publish_config::PublishConfiguration,
    json: &mut bool,
) -> Result<PublishArgs, String> {
    let mut mode = None;
    let mut selection = publication::Selection::Ordinary;
    let mut selected = false;
    let mut acknowledged = false;
    let mut first_error = None;
    let mut positional: Vec<&OsString> = Vec::new();
    let mut endpoint: Option<String> = None;
    let mut bucket: Option<String> = None;
    let mut key_seed: Option<PathBuf> = None;
    let mut pins: Option<Vec<SpkiPin>> = None;
    let mut direct_s3 = false;
    let mut cache_dir: Option<PathBuf> = None;
    let mut wire_snapshot: Option<PathBuf> = None;
    let mut wire_run_id: Option<String> = None;
    let mut wire_role: Option<String> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let text = arg.to_str().unwrap_or_default();
        let mut value = || it.next().ok_or_else(|| format!("{text} needs a value"));
        let as_string = |value: &OsString| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{text}: value is not valid UTF-8"))
        };
        let result = (|| -> Result<(), String> {
            match text {
                "--json" => *json = true,
                "--publish-mode" => {
                    mode = Some(publication::PublishMode::parse(&as_string(value()?)?)?);
                }
                "--new" | "--recover" | "--abandon" => {
                    let next = match text {
                        "--new" => publication::Selection::New,
                        "--recover" => publication::Selection::Recover(publication::parse_id(
                            &as_string(value()?)?,
                        )?),
                        _ => publication::Selection::Abandon(publication::parse_id(&as_string(
                            value()?,
                        )?)?),
                    };
                    if selected {
                        return Err("--new, --recover and --abandon are mutually exclusive".into());
                    }
                    selection = next;
                    selected = true;
                }
                "--acknowledge-may-land" => acknowledged = true,
                "--direct-s3" => direct_s3 = true,
                "--endpoint" => endpoint = Some(as_string(value()?)?),
                "--bucket" => bucket = Some(as_string(value()?)?),
                "--key-seed" => key_seed = Some(PathBuf::from(value()?)),
                // LAST-WINS, like `--endpoint`: one cache dir, so a repeat is a correction.
                "--cache-dir" => cache_dir = Some(PathBuf::from(value()?)),
                // The wire-byte snapshot trio is checked together below.
                "--wire-snapshot" => wire_snapshot = Some(PathBuf::from(value()?)),
                "--wire-run-id" => wire_run_id = Some(as_string(value()?)?),
                "--wire-role" => wire_role = Some(as_string(value()?)?),
                // Pin occurrences accumulate; each comma-separated list uses the shared parser.
                "--pin" => {
                    pins.get_or_insert_with(Vec::new).extend(pins_from(
                        "--pin",
                        &as_string(value()?)?,
                        NoPinsRemedy::PublishMayOptOutToTheBucket,
                    )?);
                }
                flag if publish_config::FLAGS.contains(&flag) => {
                    configuration.option(flag, Some(value()?.as_os_str()))?;
                }
                flag if flag.starts_with("--") => return Err("unknown publish option".to_owned()),
                _ => positional.push(arg),
            }
            Ok(())
        })();
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    if mode.is_some() && direct_s3 {
        return Err("--publish-mode conflicts with --direct-s3".into());
    }
    if acknowledged && !matches!(selection, publication::Selection::Abandon(_)) {
        return Err("--acknowledge-may-land requires --abandon".into());
    }
    if matches!(selection, publication::Selection::Abandon(_)) && !acknowledged {
        return Err("--abandon requires --acknowledge-may-land".into());
    }
    if matches!(
        selection,
        publication::Selection::Recover(_) | publication::Selection::Abandon(_)
    ) && (direct_s3 || mode == Some(publication::PublishMode::LegacyServer))
    {
        return Err("recovery and abandonment require server authority selection".into());
    }
    if matches!(selection, publication::Selection::Abandon(_))
        && (cache_dir.is_some()
            || wire_snapshot.is_some()
            || wire_run_id.is_some()
            || wire_role.is_some())
    {
        return Err("--abandon conflicts with cache and wire output".into());
    }
    configuration.validate(direct_s3)?;
    let wire = wire_snapshot_args(wire_snapshot, wire_run_id, wire_role)?;
    let [store_dir, source, volume] = positional.as_slice() else {
        return Err(format!(
            "expected 3 positional arguments (store-dir, source-dir, volume), got {}",
            positional.len()
        ));
    };
    let volume = volume
        .to_str()
        .ok_or_else(|| "volume name is not valid UTF-8".to_owned())?;
    // The environment is the fallback, never an override: a `--pin` on the
    // command line and a `GRANARY_TLS_PINS` in the shell must not silently
    // union into a set the operator never wrote.
    //
    // Through the SAME `pins_from` the flag uses, and no blank filter of
    // its own: a variable exported empty is a value the operator set, and
    // reading it as "unset" here while the flag read it as "a pin set"
    // was the whole disagreement.
    if pins.is_none()
        && let Some(raw) = env(ENV_TLS_PINS)
    {
        pins = Some(pins_from(
            ENV_TLS_PINS,
            &raw,
            NoPinsRemedy::PublishMayOptOutToTheBucket,
        )?);
    }
    if pins.is_none() && !direct_s3 {
        // NAME BOTH OPTIONS, and never fall back to the bucket. An
        // operator who forgot to set the pins is exactly the person a
        // silent fallback would publish without them.
        return Err(format!(
            "no transport chosen: publish through a granary server with \
             --pin sha256/... (or {ENV_TLS_PINS}), or opt out to the bucket \
             with --direct-s3 --bucket <name>"
        ));
    }
    if pins.is_some() && direct_s3 {
        return Err(format!(
            "--pin (or {ENV_TLS_PINS}) and --direct-s3 are two different \
             trust models; choose one"
        ));
    }
    // A server route refuses a bucket in both this parser and `open_publish_route`.
    if pins.is_some() && bucket.is_some() {
        return Err(format!(
            "--pin (or {ENV_TLS_PINS}) publishes THROUGH a granary server, which never \
             names a bucket, and --bucket names one; choose one — drop --bucket, or opt \
             out to the bucket with --direct-s3 --bucket <name>"
        ));
    }
    if direct_s3 && bucket.is_none() {
        return Err("--direct-s3 needs --bucket <name>".to_owned());
    }
    // The direct-S3 route has no endpoint/pin origin to bind a
    // cache dir to (`CacheOrigin` is built from `--endpoint` and the pin
    // set, neither of which the bucket route has) — refused by name
    // rather than silently ignoring `--cache-dir`.
    if cache_dir.is_some() && direct_s3 {
        return Err(
            "--cache-dir and --direct-s3 cannot be combined: a cache dir is bound to the \
             --endpoint and pin set of the through-the-server route, which --direct-s3 has \
             neither of"
                .to_owned(),
        );
    }
    let parsed = PublishArgs {
        store_dir: PathBuf::from(store_dir),
        source: PathBuf::from(source),
        volume: VolumeName::new(volume.to_owned()).map_err(|e| e.to_string())?,
        endpoint: endpoint.ok_or_else(|| "--endpoint is required".to_owned())?,
        bucket,
        key_seed: if matches!(selection, publication::Selection::Abandon(_)) {
            key_seed.unwrap_or_default()
        } else {
            key_seed.ok_or_else(|| "--key-seed is required".to_owned())?
        },
        configuration: configuration.clone(),
        mode: mode.unwrap_or_default(),
        selection,
        json: *json,
        tls_pins: pins,
        direct_s3,
        cache_dir,
        wire,
    };
    if matches!(
        selection,
        publication::Selection::Recover(_) | publication::Selection::Abandon(_)
    ) && parsed.configuration.context.is_none()
    {
        return Err("--credential-context is required for recovery and abandonment".into());
    }
    if let Some(pins) = &parsed.tls_pins {
        granary_net::pin::PinnedServerVerifier::new(
            pins.clone(),
            granary_net::crypto_provider().into(),
        )
        .map_err(|error| granary_client::HttpStoreError::Pins(error).to_string())?;
    }
    Ok(parsed)
}

/// Decompose a pre-1970 distance into Unix-epoch `(secs, nanos)`, with `nanos` a non-negative offset below one second.
///
/// A PURE FUNCTION the Err arm CALLS, rather than logic inlined there,
/// for one testable reason: that arm cannot be reached without a
/// pre-1970 system clock, so a test that reimplements the rule locally
/// stays green when the production arm is reverted. The test therefore
/// calls this function rather than restating its rule.
///
/// `checked_add` rather than `s + 1`: at `whole == i64::MAX` the
/// `try_from` SUCCEEDS and `s + 1` overflows, panicking under
/// `overflow-checks`.
fn pre_epoch_parts(whole: u64, subsec: u32) -> (i64, u32) {
    if subsec == 0 {
        (i64::try_from(whole).map_or(i64::MIN, |s| -s), 0)
    } else {
        (
            i64::try_from(whole)
                .ok()
                .and_then(|s| s.checked_add(1))
                .map_or(i64::MIN, |s| -s),
            1_000_000_000 - subsec,
        )
    }
}

/// THE wall-clock read SITE in this binary (a publish reads it once,
/// for the root's timestamp; the writer identity reads no clock, being
/// drawn from the cryptographic-randomness seam), and the CLI's
/// implementation of the [`Clock`] seam. Everything downstream —
/// `publish` and the `writer_uuid` preimage — takes its time from a
/// `Clock`, so swapping this unit struct for a pinned one, beside a
/// known [`SecureRandom`] for the identity, is all it takes to make the
/// whole path reproducible. The simulator reaches the same place by a shorter
/// route and constructs no `Clock` at all: `publish` takes a
/// `Timestamp` by value, so the sim hands it a pinned constant and
/// mints its identity from a node id. The seam is what makes BOTH
/// possible — it is why no time reaches the publish path except as a
/// value a caller chose.
#[derive(Clone, Copy)]
struct WallClock;

impl Clock for WallClock {
    #[expect(
        clippy::disallowed_methods,
        reason = "this IS the Clock seam's wall-clock implementation; the ambient read is \
                  isolated here and reaches callers only as a Timestamp value"
    )]
    fn now(&self) -> Timestamp {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        match d {
            Ok(d) => Timestamp {
                secs: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                nanos: d.subsec_nanos(),
            },
            // Before 1970: negative seconds are valid in this
            // Unix-epoch timestamp representation.
            //
            // `nanos` is a NON-NEGATIVE OFFSET FORWARD from `secs`
            // (the decoder refuses `nanos >= 1_000_000_000`, and
            // there is no sign to carry). So the instant is
            // `secs + nanos/1e9`, and negating only the seconds is
            // wrong whenever there is a sub-second part: at
            // 1969-12-31T23:59:58.5Z the duration before the epoch is
            // 1.5 s, and `secs: -1, nanos: 500_000_000` encodes
            // epoch − 0.5 s, not − 1.5 s. The correct decomposition
            // floors: `secs = -(whole + 1)` and `nanos = 1e9 - subsec`
            // when a sub-second part exists. This lands in a SIGNED,
            // hash-chained root, so it is a consensus value, not a
            // display detail.
            Err(e) => {
                let d = e.duration();
                let (secs, nanos) = pre_epoch_parts(d.as_secs(), d.subsec_nanos());
                Timestamp { secs, nanos }
            }
        }
    }
}

/// A new publication's writer identity: all sixteen bytes drawn from
/// `entropy`, the cryptographic-randomness seam. The
/// binary passes [`granary_net::secure_random::OsSecureRandom`], the operating system's entropy.
///
/// **Nothing two publishers can share enters it.** No host name, pid,
/// clock reading or mint count: each of those is a value a second
/// publisher — another process on this host, another host, another
/// task in this process — can hold too, and `writer_uuid` is a SIGNED
/// root field, so two publishers holding one identity mint
/// byte-identical roots. The loser of a CAS race then reads its own
/// bytes back through the one-probe rule, concludes it won, and both
/// report success. Two draws collide only with the birthday probability
/// on 128 bits, on the deployment condition `OsSecureRandom` states: a
/// running process is never cloned live.
///
/// **One per new publication.** `gran publish` calls this once, before
/// `prepare`; the prepared bytes carry the identity, and a
/// retransmission of them never calls this again.
///
/// Freshness is the caller's responsibility. Re-running at the same
/// position in the same stream produces the same identity:
/// a test passes a local [`SecureRandom`] that returns known bytes.
///
/// # Errors
/// [`EntropyUnavailable`] when the draw failed. The caller refuses the
/// publish: the bytes a failed fill left behind are never used.
fn writer_identity(entropy: &mut impl SecureRandom) -> Result<WriterIdentity, EntropyUnavailable> {
    let mut bytes = [0u8; WRITER_IDENTITY_LEN];
    entropy.fill(&mut bytes)?;
    Ok(WriterIdentity::from_bytes(bytes))
}

/// Capture the process credentials so publication can reject a set-ID invocation
/// before opening the store or signing key.
fn cmd_publish(args: &PublishArgs) -> ExitCode {
    let credentials = process_credentials();
    cmd_publish_with_credentials(args, &credentials)
}

fn cmd_publish_with_credentials(args: &PublishArgs, credentials: &ProcessCredentials) -> ExitCode {
    let report = publication::invoke(args, credentials);
    report.render(args.json, &mut std::io::stdout(), &mut std::io::stderr())
}

/// An advisory write was skipped: warn on `err` (best effort — a
/// failure here is never this function's business, see
/// [`report_publish`]'s own contract for why) and record it on `out`
/// (part of the publish record proper, so its own write is fallible and
/// propagates like every other line's).
fn advisory_skip(
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
    warning: &str,
    stdout_line: &str,
) -> std::io::Result<()> {
    let _ = writeln!(err, "{warning}");
    writeln!(out, "{stdout_line}")
}

/// Print a successful publish, once — shared by both routes so the two
/// cannot drift into reporting different things about the same flow.
///
/// The sinks are PARAMETERS so a unit test can capture what this
/// function actually printed — `println!`/`eprintln!` write to the
/// process's real stdout/stderr, which nothing in a test controls. That
/// captures the bytes it wrote, including advisory and output-failure paths.
///
/// `cache_write_skipped == true` means both write-through calls
/// (`put_root_bytes`, `raise_anchor`) were contract no-ops — the cache
/// opened read-only degraded. `false` does NOT mean either call
/// succeeded: a Writer-mode cache can still decline one. The decline
/// set, as the cache actually implements it: the free-space watermark;
/// a DIRECTORY at the destination (the one shape no write can replace,
/// since `rename(2)` refuses a directory `dest`); a destination or
/// volume directory that could not be classified at all (fail closed);
/// and an I/O failure, which `raise_anchor` only logs. NOT "a foreign
/// entry at the destination" in general — a symlink, FIFO or socket at
/// the name is REPLACED by the write's own atomic rename, which never
/// follows it. This flag reports the lock-contention cause alone, never
/// "the cache write-through landed".
///
/// **The record reached stdout, or the exit code says it did not.** The
/// summary lines and the two advisories all go through the same
/// fallible path; the first write failure on `out` — most likely one of
/// the advisories, since they print LAST — stops the rest and turns
/// into [`ExitCode::FAILURE`], with a best-effort stderr line naming the
/// seq so the operator does not read a truncated record as the whole
/// story. The remote publish this reports on is never undone by a
/// failure here: `commit()` already returned `Ok` before this function
/// is ever called.
fn report_publish(
    volume: &VolumeName,
    s: &PublishSummary,
    cache_write_skipped: bool,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> ExitCode {
    let result = (|| -> std::io::Result<()> {
        writeln!(
            out,
            "published {} seq {} epoch {}",
            volume.as_str(),
            s.seq,
            s.epoch
        )?;
        writeln!(out, "manifest-root {}", s.manifest_root)?;
        writeln!(
            out,
            "dirs {} files {} symlinks {}",
            s.harvest.dirs, s.harvest.files, s.harvest.symlinks
        )?;
        writeln!(
            out,
            "novel objects {} bytes {}",
            s.novel_objects, s.novel_bytes
        )?;
        writeln!(
            out,
            "bins {} uploaded {} ({} bytes)",
            s.bins_planned, s.bins_uploaded, s.bin_bytes_uploaded
        )?;
        writeln!(
            out,
            "binmap {} prefix_bits {} shards {} rewritten {}",
            s.binmap_index, s.prefix_bits, s.shards_total, s.shards_rewritten
        )?;
        writeln!(
            out,
            "sheaf {} ({})",
            s.sheaf_head,
            if s.sheaf_uploaded {
                "written"
            } else {
                "already present"
            }
        )?;
        if !s.hint_written {
            // The operator's warning belongs here and not in `commit`: the
            // library has a sim caller that must not print at all. A failed
            // hint is advisory, so the publish still succeeds — the line is a
            // warning, not an error, and the exit status stays SUCCESS.
            advisory_skip(
                out,
                err,
                "gran publish: warning: hint write failed; readers forward-probe",
                "hint NOT updated (advisory; readers forward-probe)",
            )?;
        }
        if cache_write_skipped {
            // Same class as the hint warning: the PUBLISH succeeded; a local
            // advisory write was skipped. Exit stays SUCCESS (the hint_written
            // precedent), and the message says what to DO.
            advisory_skip(
                out,
                err,
                // `gran publish` takes `--key-seed`, never `--root-key`, so
                // "the same --root-key as this publish" would name a flag
                // this command does not have. What the reader needs is the
                // PUBLIC half of the key this publish's seed derives.
                "gran publish: warning: cache write-through skipped — the cache was opened \
                 read-only because another process held its lock when this publish started, \
                 so this publish did not raise the cache's freshness floor. Once the other \
                 process has released the cache lock, a warm `gran cat --cache-dir <same dir>` \
                 (same endpoint and TLS pins as this publish, and the root key this publish's \
                 seed derives — `--root-key` on `gran cat`) raises it.",
                "cache NOT updated (advisory; a warm `gran cat --cache-dir <same dir>` once \
                 the lock is free raises the floor)",
            )?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `error:`, not `warning:` — the exit is FAILURE, and a log
            // filter reads severity off the prefix. The two advisories
            // above are warnings because the command still succeeds;
            // this one is the failure itself.
            let _ = writeln!(
                err,
                "gran publish: error: stdout write failed ({e}); the publish landed \
                 remotely at seq {} regardless — this record is incomplete",
                s.seq
            );
            ExitCode::FAILURE
        }
    }
}

// ----------------------------------------------------------------- cat

/// Split the path operand into manifest [`Name`]s, refusing every
/// non-name LOCALLY — before a socket is opened.
///
/// The grammar is slash-separated manifest names with ONE leading `/`
/// stripped, so `/a/b` and `a/b` name the same file and nothing else is
/// folded. Every component then goes through [`Name::new`], which is the
/// SAME validator the manifest encoder used when the entry was written:
/// a second grammar here would be a second accept set, and the shapes it
/// admitted that `Name` does not could never match an entry anyway.
///
/// **Why `..` is refused rather than resolved.** The walk carries a
/// current directory and descends; a `..` that popped that stack is a
/// real traversal to a SIBLING subtree, reachable from a path the
/// operator wrote for one file. `.` is refused for the neighbouring
/// reason: it is not a name in the manifest, so resolving it would be
/// this command inventing a path grammar the format does not have. Both
/// are already [`NameError`](granary_core::manifest::NameError) variants
/// — `Name::new` refuses them, and
/// `Dot`/`DotDot`/`Empty` arrive here as its own message.
///
/// A trailing slash (`a/`) and a doubled one (`a//b`) both produce an
/// EMPTY component, which `Name::new` refuses as `Empty`. Neither is
/// silently folded away: `gran cat vol a/` asked for something the
/// manifest cannot name, and saying so is better than reading `a`.
///
/// **Raw BYTES, not `&str`.** Manifest names are arbitrary bytes and
/// non-UTF-8 is accepted, so a UTF-8 operand would make every
/// file whose name is not valid UTF-8 unreadable through this command —
/// on the very platforms whose paths are byte strings. The refusals
/// render the offending component lossily, and quoted, so a name written
/// by a stranger cannot repaint the terminal.
fn split_cat_path(path: &[u8]) -> Result<Vec<Name>, String> {
    // ONE leading slash, and no repeated stripping: `//a` then carries
    // an empty first component and is refused below, which is the
    // honest answer for a path that is not the one the operator meant.
    let body = path.strip_prefix(b"/").unwrap_or(path);
    if body.is_empty() {
        return Err(
            "the path names the volume root, which is a directory — name a file inside it"
                .to_owned(),
        );
    }
    let mut out = Vec::new();
    for component in body.split(|b| *b == b'/') {
        let name = Name::new(component.to_vec()).map_err(|e| {
            format!(
                "path component {:?}: {e} (the path is slash-separated manifest names; \
                 `.` and `..` are not names, and this walk has no parent link)",
                String::from_utf8_lossy(component)
            )
        })?;
        out.push(name);
    }
    Ok(out)
}

/// `gran cat <volume> <path> --endpoint <url> --pin sha256/...
/// [--root-key ed25519:...]`. Positionals lead (the volume, then the
/// path inside it), then the transport, then the OPTIONAL reader anchor.
///
/// Unknown flags are refused rather than ignored, on `parse_publish`'s
/// reasoning: a mistyped `--root-keys` must not read a volume with no
/// signature check while the operator believes they asked for one.
#[derive(Debug)]
struct CatArgs {
    volume: VolumeName,
    /// The path operand AS GIVEN — an `OsString`, because manifest names are
    /// arbitrary bytes and a `String` here would make a file with a
    /// non-UTF-8 name unreachable. Split by [`split_cat_path`], which
    /// runs before any I/O.
    path: OsString,
    endpoint: String,
    /// The TLS pin set. REQUIRED: cat has no second route to fall
    /// back to, so there is nothing for a missing value to select.
    tls_pins: Vec<SpkiPin>,
    /// The root-signing public key trusted by the reader. `None` is the INTEGRITY-ONLY mode —
    /// see [`reader_verifier`] for what each mode delivers.
    root_key: Option<[u8; SIGNING_KEY_LEN]>,
    /// `--seq N`: resolve at exactly this seq instead of at the head.
    ///
    /// An explicitly selected seq permits reading below a poisoned head: an
    /// unauthenticated peer can plant a root at any free seq above a
    /// volume's head, after which `max_seq` answers the planted seq and
    /// the head path hard-fails — while the honest head sits intact one
    /// seq below.
    ///
    /// **`None` is the head path, and nothing anywhere turns a failure
    /// INTO a seq.** The automatic form — walk down to the highest seq
    /// that resolves — was designed and rejected;
    /// what makes the manual form sound is precisely that the
    /// default path still fails loudly, so there is no fallback for an
    /// attacker to steer.
    ///
    /// **The accept set is `1 ..= u64::MAX - 1`, and that is a decision,
    /// not an arithmetic fact.** Seq 0 is never a head:
    /// `root.rs` refuses seq 0 at encode AND decode, so no root can
    /// be stored there; seq `u64::MAX` is reserved and can never be
    /// a head. Both are refused in [`parse_cat_seq`] rather
    /// than passed down, where 0 would come back as a `decode_root`
    /// complaint and `u64::MAX` as a bare absence — neither of which
    /// names the reason.
    seq: Option<u64>,
    /// The local object/root cache. Absent (the default) is
    /// today's behaviour unchanged — no lookaside, no degraded fallback
    /// when the transport is down.
    cache_dir: Option<PathBuf>,
    /// The wire-byte snapshot trio, or `None` in ordinary use.
    wire: Option<WireSnapshotArgs>,
}

/// Parse `gran cat`'s operands.
///
/// **Which flags are last-wins and which accumulate, and why they
/// differ.** `--endpoint` and `--root-key` are LAST-WINS: each names one
/// thing, and a second occurrence is a correction. `--pin` ACCUMULATES,
/// exactly as it does in [`parse_publish_checked`]: a pin set is a SET (RFC
/// 7469's primary plus a pre-generated backup), so a second `--pin`
/// naming the backup must not silently discard the primary. Both
/// behaviours are pinned by test — the point is that they are DECIDED
/// rather than inherited from the shape of a match arm.
///
/// **`GRANARY_TLS_PINS` is deliberately NOT read here, and the reason is
/// what the fallback could DO.** Cat's `--pin` is required, so the
/// outcome of finding no pins is a refusal. A fallback layered on top
/// of a refusal is one-directional: it can only ever turn "refused"
/// into "read", never the reverse — so the whole of what reading the
/// variable would add is a read the operator did not spell, through a
/// server whose identity came from ambient process state. That is the
/// opposite of explicit server-trust configuration, where the trust is meant to be
/// visible in the invocation that used it, and a stale export from an
/// earlier session is exactly the value nobody re-reads.
///
/// `parse_publish` is not the same case and its fallback is not an
/// inconsistency: there, the pin set SELECTS a route, so "no pins" is a
/// decision (go to the bucket) rather than a refusal, and the operator
/// needs a way to express that decision in the same place the bucket
/// credentials already live. A fallback that chooses between two
/// spelled-out routes is not a fallback that manufactures a read.
///
/// **`--root-key` goes through the SHIPPED parser** —
/// `granary_net::config::parse_signing_key`, which the server's own
/// configuration uses. A second parser here would be a second accept
/// set: the `keyid:` case is the load-bearing one, since a locator is
/// not a key and a reader configured with one can check nothing.
fn parse_cat(args: &[OsString]) -> Result<CatArgs, String> {
    let mut positional: Vec<&OsString> = Vec::new();
    let mut endpoint: Option<String> = None;
    let mut pins: Vec<SpkiPin> = Vec::new();
    let mut root_key: Option<[u8; SIGNING_KEY_LEN]> = None;
    let mut seq: Option<u64> = None;
    let mut cache_dir: Option<PathBuf> = None;
    let mut wire_snapshot: Option<PathBuf> = None;
    let mut wire_run_id: Option<String> = None;
    let mut wire_role: Option<String> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let text = arg.to_str().unwrap_or_default();
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
                    NoPinsRemedy::ReadHasNoSecondRoute,
                )?),
                "--root-key" => {
                    root_key = Some(
                        parse_signing_key(&as_string()?).map_err(|e| format!("--root-key: {e}"))?,
                    );
                }
                "--seq" => seq = Some(parse_cat_seq(&as_string()?)?),
                // LAST-WINS, like `--endpoint`/`--root-key`: one cache
                // dir, so a repeat is a correction.
                "--cache-dir" => cache_dir = Some(PathBuf::from(value)),
                // The wire-byte snapshot trio's flags — see
                // `wire_snapshot_args` for the all-or-nothing check.
                "--wire-snapshot" => wire_snapshot = Some(PathBuf::from(value)),
                "--wire-run-id" => wire_run_id = Some(as_string()?),
                "--wire-role" => wire_role = Some(as_string()?),
                other => return Err(format!("unknown flag {other}")),
            }
        } else {
            positional.push(arg);
        }
    }
    let wire = wire_snapshot_args(wire_snapshot, wire_run_id, wire_role)?;
    let [volume, path] = positional.as_slice() else {
        return Err(format!(
            "expected 2 positional arguments (volume, path), got {}",
            positional.len()
        ));
    };
    let volume = volume
        .to_str()
        .ok_or_else(|| "volume name is not valid UTF-8".to_owned())?;
    if pins.is_empty() {
        // `GRANARY_TLS_PINS` is NAMED, and named as ignored: an
        // operator who has it exported for their publishes has every
        // reason to read "is required" as "is missing" and go looking
        // for why their configured value did not take. Saying nothing
        // about it leaves them debugging the variable instead of typing
        // the flag.
        return Err(format!(
            "--pin sha256/... is required: cat reads through a granary server over pinned \
             TLS, and there is no unpinned route. {ENV_TLS_PINS} is NOT read on this path \
             — an exported value does not supply this, deliberately (see `parse_cat`)"
        ));
    }
    Ok(CatArgs {
        volume: VolumeName::new(volume.to_owned()).map_err(|e| e.to_string())?,
        path: (*path).clone(),
        endpoint: endpoint.ok_or_else(|| "--endpoint is required".to_owned())?,
        tls_pins: pins,
        root_key,
        seq,
        cache_dir,
        wire,
    })
}

/// Parse `--seq`'s value: a plain decimal seq inside the usable range
/// `1 ..= u64::MAX - 1`.
///
/// **Deliberately NOT `granary_core::rootstore::parse_hint_body`, and
/// the difference is the FORM.** That parser decodes an untrusted
/// twenty-byte WIRE body — exactly twenty ASCII digits, zero-padded —
/// and the fixed width is what keeps its parse total on bytes anyone who
/// can write the bucket can write. This value is neither wire-form nor
/// network input: it is an operand the operator typed, and requiring
/// `--seq 00000000000000000002` of them would be a harsher accept set
/// bought with no safety. So `str::parse` decides the NUMBER.
///
/// **The digit guard above it decides the GRAMMAR, and it is not a
/// second decimal parser.** `u64::from_str` also accepts a leading `+`,
/// which is one seq with two spellings for nothing; the guard removes it
/// along with signs, separators and non-ASCII digits. Leading zeros are
/// KEPT on purpose — that is the spelling of the bucket key
/// (`root/{volume}/{20-digit seq}`) and of the `max-seq` and hint
/// bodies, so a seq an operator read out of the store names the seq they
/// read. Nothing on this path is hashed or signed, so two spellings of
/// one number cost nothing here; a hashed format would owe the opposite
/// answer.
fn parse_cat_seq(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "--seq: {value:?} is not a decimal seq — ASCII digits only, with no sign, \
             separator or unit"
        ));
    }
    let seq: u64 = value.parse().map_err(|_| {
        format!(
            "--seq: {value:?} does not fit a u64 — the usable seq range is \
             1 ..= 18446744073709551614"
        )
    })?;
    // The two ends of the range, refused HERE so the reason is the one
    // the operator is told. Both are excluded from head selection
    // everywhere else in the tree; this flag must not become the one
    // path that asks for a seq the rest of the system has ruled out.
    if seq == 0 {
        return Err(
            "--seq: seq 0 is never a head — a root cannot be stored there at all, \
             so the usable seq range is 1 ..= 18446744073709551614"
                .to_owned(),
        );
    }
    if seq == u64::MAX {
        return Err(
            "--seq: seq 18446744073709551615 is reserved and can never be a head, \
             so the usable seq range is 1 ..= 18446744073709551614"
                .to_owned(),
        );
    }
    Ok(seq)
}

/// `gran verify <store-or-cache-root>`. Modeled on [`parse_cat`]:
/// exactly one positional, no endpoint/pins (verify never touches the
/// network), unknown flags refused rather than ignored — a mistyped
/// flag must not silently run verify against the wrong assumptions.
fn parse_verify(args: &[OsString]) -> Result<PathBuf, String> {
    let mut positional: Vec<&OsString> = Vec::new();
    for arg in args {
        let text = arg.to_str().unwrap_or_default();
        if text.starts_with("--") {
            return Err(format!("unknown flag {text}"));
        }
        positional.push(arg);
    }
    let [root] = positional.as_slice() else {
        return Err(format!(
            "expected 1 positional argument (store-or-cache root), got {}",
            positional.len()
        ));
    };
    Ok(PathBuf::from(*root))
}

// Fixed-vocabulary diagnostics can be shown for writable mounts.
fn public_mount_argument_error(error: &str) -> bool {
    // These diagnostics contain only fixed vocabulary and counts, never operands.
    error.starts_with("--pin sha256/... is required:")
        || error.starts_with("expected 2 positional arguments (volume, mountpoint), got ")
        || matches!(
            error,
            "--endpoint is required"
                | "volume name is not valid UTF-8"
                | "--seq needs an unsigned integer"
                | "writable operands require --writable"
        )
        || [
            "--endpoint",
            "--pin",
            "--root-key",
            "--manifest-root",
            "--key-seed",
            "--store-dir",
            "--client-cert",
            "--client-key",
            "--credential-context",
            "--cache-dir",
            "--seq",
            "--uid",
            "--gid",
            "--wire-snapshot",
            "--wire-run-id",
            "--wire-role",
        ]
        .iter()
        .any(|flag| {
            error == format!("{flag} needs a value")
                || error == format!("{flag}: value is not valid UTF-8")
                || error == format!("{flag} needs a nonempty file path")
        })
}

fn report_mount_argument_refusal(
    args: &[OsString],
    error: &str,
    report: &dyn Fn(std::fmt::Arguments<'_>),
) {
    let writable = attach::writable_flag_given(args);
    let metrics = error.starts_with("--metrics-");
    if writable || metrics {
        granary_client::op_failed(
            granary_client::OperationKind::Session,
            granary_client::FailureClass::Refused,
        );
        if writable && !metrics && !public_mount_argument_error(error) {
            report(format_args!("gran mount: WritableArgumentsRefused"));
            return;
        }
    }
    report(format_args!("gran mount: {error}"));
}

/// `mount.gran <device> <dir> [-o opt1,opt2,...]`: translate,
/// then run the SAME [`cmd_mount`] every native invocation runs — never
/// a second copy of the daemon logic.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the test wrapper omits support context")
)]
fn cmd_mount_gran(args: &[OsString], log: &mut dyn granary_client::LocalReporter) -> ExitCode {
    cmd_mount_gran_with_support(args, log, None)
}

fn cmd_mount_gran_with_support(
    args: &[OsString],
    log: &mut dyn granary_client::LocalReporter,
    support: Option<(&logging::Settings, granary_client::BundleHistory)>,
) -> ExitCode {
    match parse_mount_gran(args) {
        Ok(mut margs) => {
            if let Some((settings, history)) = support {
                margs.arm_support(settings, history);
            }
            cmd_mount(&margs, log)
        }
        Err(e) => {
            terminal::write_line(format_args!("mount.gran: {e}"));
            usage()
        }
    }
}

/// Resolve the tree `gran cat` is about to walk, at the entry point
/// `--seq` selects — the head when it is absent, exactly that seq when
/// it is present.
///
/// **The selection happens BEFORE the first request and never after a
/// failure, and that is the whole safety argument for the flag.**
/// The automatic form — resolve the head, and on failure
/// walk down to the highest seq that resolves — was designed and
/// rejected: one request at `H + N + 1` puts the honest head
/// outside any bound, and a head chosen by a validity predicate is no
/// longer monotone by construction, which is the rollback defence
/// nothing else in the tree names. A seq a HUMAN supplied has neither
/// problem, and it has that property only while the default path keeps
/// failing loudly. So there is no `Err` arm here that reaches for a
/// second seq, and no future one may be added: `--seq` is an
/// instruction, never a recovery.
async fn cat_resolve<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    seq: Option<u64>,
    verifier: &RootVerifier,
    cache: Option<&mut Cache>,
    path: &[Name],
    out: &mut impl std::io::Write,
) -> Result<ResolveOutcome, ResolveError> {
    // `cache` is `None` when `--cache-dir` was not given, which
    // keeps `gran cat`'s cacheless behaviour exactly what it was — the
    // same code path with the lookaside removed (`fetcher.rs`'s own
    // doc). With no cache dir, discovery has no anchor and no persisted
    // hint, so this is full discovery every time (`head.rs`'s own
    // self-check) — the same shape `max_seq` alone always was.
    //
    // `--seq` stays strict. `resolve_at_verified` gains
    // NO degraded fallback — only the head path (`resolve_head_verified`)
    // ever serves from the cache when the transport is down.
    let mut sink = |_id: GrainId, bytes: &[u8]| -> Result<(), String> {
        out.write_all(bytes).map_err(|e| e.to_string())
    };
    let target = ResolveTarget::Path(path);
    match seq {
        None => {
            // Constructed HERE, at the edge — never inside library code:
            // `WallClock` and
            // `ProcessRng` are this binary's own ambient doors for time
            // and jitter; `publish` reads the same `WallClock` for its
            // timestamp (its identity comes from `OsSecureRandom`).
            let head_ctx = HeadContext::new(Box::new(WallClock), Box::new(ProcessRng::new()));
            resolve_head_verified(
                remote, volume, verifier, &head_ctx, cache, target, &mut sink,
            )
            .await
        }
        Some(at) => {
            resolve_at_verified(remote, volume, at, verifier, cache, target, &mut sink).await
        }
    }
}

/// Render a resolve failure for `gran cat`, distinguishing the ONE
/// variant whose meaning depends on how the seq was chosen.
///
/// Both entry points answer `NoHead`, and on the default path its text
/// is already right: `max_seq` found nothing, so the volume has no head.
/// Under `--seq` the same variant means something much narrower — this
/// one key is empty — and rendering it the same way would report a
/// volume with a perfectly good head one seq below as unpublished, which
/// is exactly the confusion an operator reaching for this flag is trying
/// to get out of. The other variants render identically on both paths:
/// most describe a volume broken in a way the seq did not choose, and
/// the two that describe no damage at all — a target the tree does not
/// contain, and a tree wider than one resolve may expand — do not depend
/// on the seq either.
fn cat_resolve_message(seq: Option<u64>, err: &ResolveError) -> String {
    match (seq, err) {
        (Some(at), ResolveError::NoHead) => format!(
            "no root at seq {at} — that key holds nothing. --seq reads exactly the seq \
             given and never falls back, so this says nothing about the volume: without \
             --seq, gran cat reads whatever seq max_seq answers"
        ),
        _ => err.to_string(),
    }
}

/// Fetch a published volume's HEAD, verify it, and stream one file's
/// bytes to stdout.
///
/// **Path-scoped emission through the verified resolve — never a
/// name→node lookup run against the wire on its own.** `cat_resolve`
/// names ONE file (`ResolveTarget::Path`) and hands the resolve a sink;
/// content grains for that file are fetched on demand and streamed
/// straight to stdout as the resolve runs, never proven whole and
/// buffered first. What is NOT scoped down is the tree's own
/// STRUCTURE: `validate_dir_tree`, `check_reachable_grains`, the sheaf
/// cross-check and the parent-chain walk all still run over the WHOLE
/// verified tree, exactly as strictly as a whole-tree resolve runs
/// them — only the CONTENT a target does not need goes unfetched. The
/// gate argument this rests on: the tree walked is always the
/// VERIFIED root's, fetched through the same seam and budget as
/// everything else the resolve checks, and the caller supplies only a
/// target name and a sink for bytes — never an object set of its own
/// choosing.
///
/// **The head is `max_seq`, not the advisory hint**, for the reason
/// `resolve_head` gives: a publish that landed its root and failed its
/// hint write is a SUCCESS, so a reader trusting the hint would report
/// no head for a volume that has one.
///
/// **`--seq N` overrides that head, and only when an operator types
/// it** — an in-band escape hatch for a volume whose head one
/// planted root has made unreadable. It is MANUAL by
/// design, not by omission: see [`cat_resolve`] for why an automatic
/// walk-down was rejected, and [`CatArgs::seq`] for the accept set.
///
/// The local refusals run FIRST — a path the manifest cannot name costs
/// no round trip, and a refusal that needed a server to produce it is a
/// refusal an unhelpful server can withhold.
/// Every `gran` subcommand that touches the filesystem acquires the
/// credential snapshot and refuses a set-ID invocation FIRST. `cat` opens its `--cache-dir` and writes a `--wire-snapshot` to paths the
/// caller names, both of them before or independent of the transport.
///
/// The split into a `_with_credentials` half is `cmd_publish`'s, and it is
/// what makes the refusal testable without a set-ID process: the test supplies
/// the snapshot. The refusal is BEFORE `Cache::open`, which this command deliberately runs
/// ahead of the transport so that a refusal cannot be withheld by an unhelpful
/// server, so a refused invocation
/// leaves no footprint, which is the observable its tests assert on rather
/// than an exit code every other failure also produces.
fn cmd_cat(args: &CatArgs) -> ExitCode {
    let credentials = process_credentials();
    cmd_cat_with_credentials(args, &credentials, &mut terminal::write_line)
}

fn cmd_cat_with_credentials(
    args: &CatArgs,
    credentials: &ProcessCredentials,
    report: &mut dyn FnMut(std::fmt::Arguments<'_>),
) -> ExitCode {
    if let Some(e) = set_id_refusal(credentials) {
        report(format_args!("gran cat: {e}"));
        return ExitCode::FAILURE;
    }
    let path = match split_cat_path(args.path.as_bytes()) {
        Ok(p) => p,
        Err(e) => {
            report(format_args!("gran cat: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Before the store, so a refused `--root-key` costs no connection
    // and the mode warning reaches the operator ahead of the bytes.
    let verifier = match reader_verifier(args.root_key, report) {
        Ok(v) => v,
        Err(e) => {
            report(format_args!("gran cat: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // `Cache::open` runs BEFORE the transport — with
    // existing local refusals (`split_cat_path`, `reader_verifier`) and
    // before `HttpStore::new` and the runtime — on `cmd_cat`'s own stated
    // rule that a refusal needing a server is a refusal an unhelpful
    // server can withhold. This ordering is also what makes the
    // CLI-level `Incompatible` negative drivable with no server running
    // at all. `CacheOnDrop`'s `Drop` impl calls `Cache::close()` on every
    // exit below, success or failure alike.
    let mut cache_guard = CacheOnDrop(None);
    if let Some(dir) = &args.cache_dir {
        // `root_key_id` is `None` in integrity-only mode
        // (keyless) and `Some(digest)` when `--root-key` was given — the
        // SAME asymmetry `reader_verifier` just applied to `verifier`.
        let origin = cache_origin(&args.endpoint, &args.tls_pins, args.root_key.as_ref());
        match Cache::open(dir, DEFAULT_CACHE_QUOTA_BYTES, &origin) {
            Ok(c) => cache_guard.0 = Some(c),
            Err(e) => {
                report(format_args!("gran cat: {e}"));
                return ExitCode::FAILURE;
            }
        }
    }
    // The HTTP constructor, and the root key does NOT flow through
    // it: the transport's trust (which SERVER) and the volume's trust
    // (which WRITER) require two separately configured trust anchors, and
    // merging them would let one configuration satisfy the other.
    let store = match HttpStore::new(&args.endpoint, args.tls_pins.clone(), &AmbientNetwork) {
        Ok(s) => s,
        Err(e) => {
            report(format_args!("gran cat: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            report(format_args!("gran cat: runtime: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // THE READ IS BOUNDED PER SEAM CALL, NOT AS A WHOLE FLOW,
    // replacing the original whole-read bound, for `cmd_publish`'s
    // reason and one more.
    //
    // Each seam call carries an idle-form deadline
    // (`granary_client::SEAM_DEADLINE_BASE`), so a peer that
    // completes the TLS handshake and then answers nothing is cut at its
    // own call rather than wedging this command for as long as the
    // terminal is open. Cat is MORE exposed than publish, not less: a
    // resolve issues one seam call per mapped object across the whole
    // volume, so every object is a stall point — and the per-call form is
    // exactly what makes that many stall points cheap to cover,
    // automatically, with nothing at this call site to remember.
    //
    // WHAT IT DOES NOT COVER, and this is not a hedge. A tokio timeout
    // fires at an await point, so the structural validation the resolve
    // runs after its last fetch is outside every one of them.
    // `gran cat` is bounded against a peer that stops answering on any
    // one call. It is not bounded in general, and no line here may be
    // read as saying it is.
    //
    // **The emit rides INSIDE the same per-call bounds as every other
    // fetch:** a target's grains are fetched on demand and streamed to
    // the sink AS THE RESOLVE RUNS, rather than proven whole and written
    // in a second pass — the windowed, budgeted read this mechanism
    // exists for, and each on-demand fetch is its own deadline-bounded
    // seam call like any other. `write_all` below still waits on the
    // operator's own downstream process, chosen on their own command
    // line, and a BLOCKED write is a synchronous stretch like any other:
    // no seam call is in flight while it blocks, so it does not itself
    // defeat any call's protection against an unresponsive PEER (the
    // next fetch's own deadline starts fresh once the write returns),
    // but a stalled downstream consumer can still hold this command open
    // indefinitely — a write blocks on the OPERATOR's own process, which
    // no seam deadline bounds and never did.
    //
    // Every grain is hash- and length-verified before reaching the sink,
    // so a failure later in the file can leave only a valid prefix on
    // stdout. The sink writes as the resolve runs; callers must check
    // the command's exit status even when they receive some output.
    //
    // Buffered, and flushed EXPLICITLY: `Stdout` is a line writer, so a
    // file with no trailing newline would otherwise sit in the buffer
    // until drop, where a write error has nowhere to go but a silent
    // drop — a truncated file reported as a success.
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let resolve_result = runtime.block_on(cat_resolve(
        &store,
        args.volume.as_str(),
        args.seq,
        &verifier,
        cache_guard.0.as_mut(),
        &path,
        &mut out,
    ));
    if let Err(e) = resolve_result {
        let message = cat_resolve_message(args.seq, &e);
        report(format_args!("gran cat: {message}"));
        return ExitCode::FAILURE;
    }
    if let Err(e) = out.flush() {
        report(format_args!("gran cat: stdout: {e}"));
        return ExitCode::FAILURE;
    }
    // Written before the verb returns `ExitCode::SUCCESS`, per
    // the wire-byte snapshot rule for `gran cat`/`gran publish`.
    write_wire_snapshot_if_requested(
        args.wire.as_ref(),
        &store.wire_bytes(),
        Some(&args.endpoint),
        args.seq,
    );
    ExitCode::SUCCESS
}

/// Build the reader's root verifier from the optional `--root-key`, and
/// state on `warn` what its absence costs.
///
/// **The two modes deliver DIFFERENT guarantees, and this is where the
/// difference is spoken.** With a key the resolve refuses a root no
/// configured key signed and a signature that does not verify, so the
/// tree is content-, structure- AND authenticity-checked. Without one
/// the content and structure checks all still run — every object is
/// re-hashed against the id that named it, the manifest tree is walked,
/// every grain is located and length-checked, the sheaf and parent
/// chains are cross-checked — and the signature slot is carried through
/// unread. That is INTEGRITY, not authenticity: the bytes are what SOME
/// writer published.
///
/// **Neither mode says the head is FRESH**: the seq
/// comes from the untrusted store's `max_seq`, so a peer that answers
/// with an older seq gets an older tree that is authentic at that seq.
/// Nothing printed by this command may suggest otherwise.
///
/// The supplied reporter attempts the warning whenever this function
/// constructs an unverified reader.
///
/// # Errors
/// The [`granary_client::AnchorError`] text when the key is refused —
/// today the all-zero value, which is a fail-open sentinel rather than
/// an anchor. `trusting` is fallible and unwrapping it would turn a
/// mistyped configuration into a panic.
fn reader_verifier(
    root_key: Option<[u8; SIGNING_KEY_LEN]>,
    warn: &mut dyn FnMut(std::fmt::Arguments<'_>),
) -> Result<RootVerifier, String> {
    let Some(public) = root_key else {
        // Cat reports the integrity-only mode before opening the cache or
        // transport so the warning precedes file output. Reading can
        // proceed even if stderr cannot deliver the warning.
        warn(format_args!(
            "gran cat: warning: no --root-key, so the root SIGNATURE is NOT checked.\n\
             gran cat: warning: the content and structure checks still run — every object \
             is re-hashed against the id that named it, the manifest tree is walked, and \
             every grain is located and length-checked. That is INTEGRITY: the bytes are \
             what SOME writer published, not a writer you trust.\n\
             gran cat: warning: pass --root-key ed25519:<64 lowercase hex digits> to \
             check the root signature as well."
        ));
        return Ok(RootVerifier::unverified());
    };
    RootVerifier::trusting(public).map_err(|e| format!("--root-key: {e}"))
}

/// `gran verify`'s set-ID refusal at CLI admission.
///
/// **The refusal lives HERE and not in `run_verify`.** That entry point is a
/// public library API with callers of its own, and a CLI-shaped whole-process
/// admission policy pushed into it would bind consumers that legitimately run
/// privileged. Both external families said so independently.
///
/// **It refuses with exit 2, not 1.** `run_verify`'s contract is 0 clean, 1
/// FINDINGS, 2 cannot-open; refusing with 1 would report a corrupt store.
fn cmd_verify(root: &Path) -> ExitCode {
    let credentials = process_credentials();
    cmd_verify_with_credentials(root, &credentials, &mut std::io::stderr())
}

fn cmd_verify_with_credentials(
    root: &Path,
    credentials: &ProcessCredentials,
    err: &mut dyn std::io::Write,
) -> ExitCode {
    if let Some(e) = set_id_refusal(credentials) {
        let _ = writeln!(err, "gran verify: {e}");
        return ExitCode::from(2);
    }
    granary_client::run_verify(root)
}

/// The argument is a REGULAR FILE — the operator's own spelling of one,
/// resolved. `gran thresh ./latest` on a symlink to a regular file
/// reads that file: the path came off the command line rather than out
/// of a store or a cache, so no trust boundary separates it from what
/// it resolves to, and following the link is what the command was asked
/// to do.
///
/// Anything that is not a regular file — a pipe, a FIFO, a socket, a
/// device node — is REFUSED, promptly, and named for what it is. It is
/// not read: `gran thresh <file>` has never documented consuming a
/// stream, and a chunker report over one would describe bytes nobody
/// can re-read. Prompt is the load-bearing word, and it is what the
/// guarded `open_regular_read` buys: a plain read open of a FIFO BLOCKS
/// until a writer appears, so this would otherwise hang with nothing
/// printed — the one failure a diagnostic command must not have.
/// `O_NONBLOCK` prevents that hang for a FIFO, and the fstat behind it
/// refuses every other non-regular kind once the open returns.
///
/// Every message names the path AS TYPED, not the resolution: the
/// operator is being told about the argument they gave.
///
/// Every `gran` subcommand that touches the filesystem acquires the
/// credential snapshot and refuses a set-ID invocation FIRST. `thresh` canonicalizes its argument under an `#[expect]` whose stated reason
/// is that the path is *"the operator's own command-line path"* — true of the
/// REAL uid and not of the effective one, and the file is then opened and its
/// grain lengths printed, which discloses shape without any symlink at all.
///
/// The split into a `_with_credentials` half is `cmd_publish`'s, and it is
/// what makes the refusal testable without a set-ID process: the test supplies
/// the snapshot. The refusal is BEFORE `canonicalize`, so the argument is never resolved, so a refused invocation
/// leaves no footprint, which is the observable its tests assert on rather
/// than an exit code every other failure also produces.
fn cmd_thresh(path: &Path) -> ExitCode {
    let credentials = process_credentials();
    cmd_thresh_with_credentials(path, &credentials, &mut std::io::stderr())
}

fn cmd_thresh_with_credentials(
    path: &Path,
    credentials: &ProcessCredentials,
    err: &mut dyn std::io::Write,
) -> ExitCode {
    if let Some(e) = set_id_refusal(credentials) {
        let _ = writeln!(err, "gran thresh: {e}");
        return ExitCode::FAILURE;
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "the argument is the operator's own command-line path, not a name that arrived \
                  from a store or a cache, so there is no boundary here for a followed link to \
                  cross — resolving it is what `gran thresh ./latest` asks for. The result is \
                  opened for reading and nothing else: nothing is created, written or compared"
    )]
    let resolved = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("gran thresh: {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let file = match open_regular_read(&resolved) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("gran thresh: {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    println!("{:>12}  {:>9}  grain", "offset", "length");
    let mut count: u64 = 0;
    let mut total: u64 = 0;
    for grain in thresh::grains_streaming(file) {
        match grain {
            Ok(g) => {
                println!("{}", format_grain_line(&g));
                count += 1;
                total += g.length as u64;
            }
            Err(e) => {
                eprintln!("gran thresh: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    println!(
        "{count} grains, {total} bytes, chunker {}",
        thresh::CHUNKER_SPEC
    );
    ExitCode::SUCCESS
}

/// One grain-table row: offset, length, id — fixed-width numeric columns.
fn format_grain_line(g: &OwnedGrain) -> String {
    format!(
        "{:>12}  {:>9}  {}",
        g.offset,
        g.length,
        GrainId::of(&g.data)
    )
}

#[cfg(test)]
use tests::parse_publish_options;
#[cfg(test)]
mod tests;
