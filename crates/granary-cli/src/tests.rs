// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate` (the crate root) — the `gran` binary's argument
//! parsing, its subcommand dispatch, and the seams those commands drive.
//!
//! Out-of-line: `granary-cli`'s non-test artifact is a `[[bin]]`
//! of this crate's own, so the crate root's tests move out of the
//! parent file while it keeps its path and declares `#[cfg(test)]
//! mod tests;`. A crate root has no module directory — its
//! children live directly in `src/`, not in `src/main/` — so this
//! file sits at `src/tests.rs` rather than under one — the form
//! `granary-net/src/tests.rs` already takes.
//!
//! **The binary's two test bodies live here, out of line.** No second crate
//! root shares this `src/`, so the `src/tests.rs` path is unambiguously this
//! bin's.
//!
//! The second body, `tokio_signal_feature`, is a leaf beneath
//! this one at `src/tests/tokio_signal_feature.rs`, not a second sibling
//! declaration in the parent.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories and pinned executable; disallowed_methods has no allow-in-tests knob"
)]

mod tokio_signal_feature;

pub(crate) mod observability_scan;

use super::*;
use crate::attach::{MountOutcome, MountScratchDir, mount_exit_code};
#[cfg(feature = "conformance-breakage")]
use crate::attach::{MountRefusal, mount_attempt_with_credentials};
use crate::keys::SeedScratchDir;
use std::fs::File;
// Test-only: the combined `prepare`+`commit` convenience wrapper.
// `cmd_publish` calls the two separately, so this
// name is otherwise unused outside the test suite that still wants
// the one-call form for its own fixtures.
use granary_client::{Policy, PublishError, publish};
use granary_net::secure_random::OsSecureRandom;
use granary_store::backend::GranaryStore;
// Imported HERE rather than inherited through `use super::*`: custody took
// `SigningKey` out of the crate root's imports with it, and two rows below
// still mint a key directly.
use granary_store::crypto::SigningKey;
use object_store::memory::InMemory;
use std::os::unix::ffi::OsStringExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ----------------------------------------- time and writer identity at the CLI edge

/// A cryptographic-randomness source that hands out a known stream:
/// `start`, `start + 1`, ... one byte at a time, so successive fills
/// continue the stream as the seam requires, and a test knows exactly
/// which bytes each draw received.
struct KnownStream(u8);

impl SecureRandom for KnownStream {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        for slot in dest {
            *slot = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// A source that writes `written` bytes of 0xEE and then fails: a
/// partial fill.
struct FailsAfter(usize);

impl SecureRandom for FailsAfter {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        for slot in dest.iter_mut().take(self.0) {
            *slot = 0xEE;
        }
        Err(EntropyUnavailable)
    }
}

/// The sixteen bytes `KnownStream(start)`'s first draw gives.
fn known(start: u8) -> [u8; WRITER_IDENTITY_LEN] {
    std::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap()))
}

// No test in this file scans for a whole-flow deadline wrapper: there
// is no fixed whole-flow total, and every seam call carries its own
// deadline instead. The property "no unbounded await on a peer" lives
// BELOW this
// file, at the seam itself: `crate::http_store`'s
// `under_seam_deadline` for every `HttpStore` caller (see that
// module's literal-asserting constant tests and the per-seam-call
// negative rows in `tests/http_store.rs`), and
// `crate::direct_deadline`'s `DirectStoreDeadline` for every
// `PublishRoute::DirectS3` caller (see that module's own
// literal-asserting constant test). What NEITHER seam covers: any
// future `block_on` over a future that is neither of those two
// wrapped calls, which arrives with no gate anywhere.

/// `WallClock` is the binary's ONE ambient time read site, and it
/// must satisfy the seam rather than sit beside it — asserted
/// through a `&impl Clock` so a `WallClock` that stopped
/// implementing the trait fails to compile. The timestamp nanosecond bound
/// is the property worth asserting on the value: a `nanos >= 1e9`
/// reading is refused by every encoder downstream, so producing one
/// here would fail a publish at signing time rather than at the
/// clock.
#[test]
fn wall_clock_implements_the_seam_and_yields_a_valid_d11_timestamp() {
    fn read(clock: &impl Clock) -> Timestamp {
        clock.now()
    }
    let t = read(&WallClock);
    assert!(t.is_valid(), "nanos must be under one second: {t:?}");
}

/// **Two independent publishers that share every ambient fact mint
/// distinct identities.** Each stands for a separate `gran publish`
/// process making its FIRST publication: same host, same pid, same
/// clock reading, same mint ordinal (zero), so a derivation from any of
/// those — the host/pid/clock/ordinal hash included — gives both the same
/// identity. Only the entropy each draws differs, and the identity is
/// exactly that entropy: nothing a second publisher can share reaches it.
#[test]
fn two_first_publications_sharing_host_pid_clock_and_ordinal_differ() {
    let first = writer_identity(&mut KnownStream(0x10)).unwrap();
    let second = writer_identity(&mut KnownStream(0x80)).unwrap();
    assert_eq!(
        (*first.as_bytes(), *second.as_bytes()),
        (known(0x10), known(0x80)),
        "each identity must be its own publisher's sixteen drawn bytes"
    );
    assert_ne!(first, second);
}

/// **All sixteen bytes, and only them.** A known stream yields exactly
/// its first sixteen bytes as the identity: a substitution that keeps
/// fewer (a truncated draw padded with zeros, a UUID's version bits
/// masked in) or that hashes the draw with anything else fails here.
#[test]
fn the_identity_is_exactly_the_sixteen_drawn_bytes() {
    let identity = writer_identity(&mut KnownStream(0xF8)).unwrap();
    assert_eq!(*identity.as_bytes(), known(0xF8));
}

/// **A second publication from one process draws again.** Two mints
/// from one source continue its stream, so they cannot repeat: a pid
/// names one process, not one publish, and two publishes from one
/// process would otherwise mint byte-identical roots.
#[test]
fn two_mints_from_one_source_continue_its_stream() {
    let mut stream = KnownStream(0);
    let first = writer_identity(&mut stream).unwrap();
    let second = writer_identity(&mut stream).unwrap();
    assert_eq!(
        (*first.as_bytes(), *second.as_bytes()),
        (known(0), known(16)),
        "the second mint must take the stream's next sixteen bytes"
    );
}

/// **A failed draw refuses, whatever it wrote.** Before any byte and
/// after a partial fill alike, the answer is the error: the bytes a
/// failed fill left behind never become an identity.
#[test]
fn a_failed_draw_refuses_the_identity_even_after_a_partial_fill() {
    for written in [0, 8, 15] {
        assert_eq!(
            writer_identity(&mut FailsAfter(written)),
            Err(EntropyUnavailable),
            "after {written} bytes written"
        );
    }
}

/// The binary's own source reads the operating system's entropy: two
/// mints from it differ and are not the untouched buffer.
#[test]
fn the_operating_system_source_mints_distinct_identities() {
    let mut entropy = OsSecureRandom::new();
    let first = writer_identity(&mut entropy).unwrap();
    let second = writer_identity(&mut entropy).unwrap();
    assert_ne!(first, second);
    assert_ne!(*first.as_bytes(), [0u8; WRITER_IDENTITY_LEN]);
}

#[test]
fn grain_line_format() {
    let g = OwnedGrain {
        offset: 1_048_576,
        length: 524_288,
        data: b"abc".to_vec(),
    };
    let line = format_grain_line(&g);
    let id = GrainId::of(b"abc").to_string();
    assert_eq!(line, format!("{:>12}  {:>9}  {id}", 1_048_576, 524_288));
}

/// `gran thresh ./latest` where `latest` is a symlink to a regular
/// file is an ordinary thing to type, and it reads the file the
/// operator named. The argument is the operator's own spelling, not
/// a name that arrived from a store or a cache, so there is no
/// boundary here for a followed link to cross.
#[test]
fn thresh_follows_a_symlink_to_a_regular_file() {
    let dir = ScratchDir::new();
    let target = dir.0.join("big");
    std::fs::write(&target, vec![0xab; 512]).unwrap_or_else(|e| panic!("{e}"));
    let link = dir.0.join("latest");
    std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cmd_thresh(&link),
        ExitCode::SUCCESS,
        "a symlink to a regular file must be read, not refused"
    );
}

/// A link with nothing on the other end is reported, promptly. The
/// resolution is the thing that fails here, and it must fail as a
/// message and an exit code rather than as a panic or a wait.
#[test]
fn thresh_reports_a_dangling_symlink_rather_than_hanging_or_panicking() {
    let dir = ScratchDir::new();
    let link = dir.0.join("dangling");
    std::os::unix::fs::symlink(dir.0.join("gone"), &link).unwrap_or_else(|e| panic!("{e}"));
    let run = move || cmd_thresh(&link);
    assert_eq!(
        within_deadline("gran thresh on a dangling symlink", run),
        ExitCode::FAILURE,
        "a dangling link must be reported, not followed and not waited on"
    );
}

// -------------------------------------------------------- scratch dir

/// A child owned by a fixture, reaped on success and killed on unwind.
#[cfg(target_os = "linux")]
pub(crate) struct OwnedChild(pub(crate) std::process::Child);

#[cfg(target_os = "linux")]
impl OwnedChild {
    pub(crate) fn wait(&mut self) -> std::process::ExitStatus {
        for _ in 0..3000 {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            pause(std::time::Duration::from_millis(10));
        }
        panic!("owned child {} did not exit within 30 s", self.0.id());
    }
}

#[cfg(target_os = "linux")]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Keep the executable reachable after changing uid, even under a private checkout.
#[cfg(target_os = "linux")]
pub(crate) fn test_command() -> std::process::Command {
    let mut command = std::process::Command::new("/proc/self/fd/0");
    command.stdin(std::process::Stdio::from(
        File::open("/proc/self/exe").unwrap(),
    ));
    command
}

/// Wait out `duration` on a receive that never arrives.
pub(crate) fn pause(duration: std::time::Duration) {
    let (_never, wait) = std::sync::mpsc::channel::<()>();
    let _ = wait.recv_timeout(duration);
}

/// Test-only scratch dir: unique per test, removed on drop.
// `pub(crate)` for `crate::keys::tests`, where the seed fixture's own
// positive control went with it.
pub(crate) struct ScratchDir(pub(crate) PathBuf);

impl ScratchDir {
    pub(crate) fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
            hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
            and nothing else (`granary-client-main-test-<pid>-<counter>` under the temp dir, created and removed by \
            this fixture), and it is load-bearing for correctness there: the counter beside it is \
            per-process, and every test binary runs in its own process, so without the pid two concurrent \
            runs generate the same name and share one directory. It reaches no hashed or signed value, and \
            nothing under test reads it: the rows here assert CLI exit codes, stderr text and the files the \
            command left behind, and the scratch directory's name appears in none of them"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-client-main-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn within_deadline<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("{what} did not return within 5s"))
}

// --------------------------------------- process credential policy

#[test]
fn publish_refuses_set_id_credentials_before_opening_store_or_creating_seed() {
    let dir = SeedScratchDir::new();
    let source = dir.0.join("source");
    let store_dir = dir.0.join("store");
    std::fs::create_dir(&source).unwrap_or_else(|e| panic!("{e}"));
    let actual = process_credentials();
    let refused = ProcessCredentials {
        ruid: actual.euid.wrapping_add(1),
        euid: actual.euid,
        rgid: actual.egid,
        egid: actual.egid,
        set_id_tainted: false,
    };
    let unsafe_seed = dir.0.join("unsafe-seed");
    let args = |key_seed| PublishArgs {
        store_dir: store_dir.clone(),
        source: source.clone(),
        volume: vol("set-id-order-probe"),
        endpoint: "http://127.0.0.1:1".to_owned(),
        bucket: None,
        key_seed,
        configuration: crate::publish_config::PublishConfiguration::default(),
        mode: crate::publication::PublishMode::Auto,
        selection: crate::publication::Selection::Ordinary,
        json: false,
        tls_pins: None,
        direct_s3: false,
        cache_dir: None,
        wire: None,
    };

    let _ = cmd_publish_with_credentials(&args(unsafe_seed.clone()), &refused);
    assert!(
        !store_dir.exists() && !unsafe_seed.exists() && !unsafe_seed.with_extension("pub").exists(),
        "the set-ID refusal must precede the first publish mutation: seed creation"
    );

    let safe_seed = dir.0.join("safe-seed");
    let safe = ProcessCredentials {
        ruid: actual.euid,
        euid: actual.euid,
        rgid: actual.egid,
        egid: actual.egid,
        set_id_tainted: false,
    };
    let _ = cmd_publish_with_credentials(&args(safe_seed.clone()), &safe);
    assert!(
        store_dir.exists(),
        "positive control: safe execution opens the store before route validation"
    );
}

/// A second PATH NAME for the already-open private seed must not turn
/// that seed into ordinary publishable source content. The identity is
/// captured from the held descriptor before the hard link is planted,
/// matching the production load-then-harvest order. The rootless remote
/// assertion proves refusal happens before commit; the second publish is
/// the positive control that an ordinary source still publishes.
#[tokio::test]
async fn publish_refuses_a_hard_link_alias_of_the_open_seed() {
    let dir = ScratchDir::new();
    let source = dir.0.join("source");
    let store_dir = dir.0.join("store");
    std::fs::create_dir(&source).unwrap_or_else(|e| panic!("{e}"));

    let seed_path = dir.0.join("seed");
    let (key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&seed_path, seed).unwrap_or_else(|e| panic!("{e}"));
    let held_seed = File::open(&seed_path).unwrap_or_else(|e| panic!("{e}"));
    let seed_identity =
        granary_client::FileIdentity::from_file(&held_seed).unwrap_or_else(|e| panic!("{e}"));
    let alias = source.join("ordinary-looking.bin");
    std::fs::hard_link(&seed_path, &alias).unwrap_or_else(|e| panic!("{e}"));

    let mem = Arc::new(InMemory::new());
    let remote = GranaryStore::new(Arc::clone(&mem));
    let store = Store::open(&store_dir).unwrap_or_else(|e| panic!("{e}"));
    let volume = vol("seed-alias-refusal");
    let identity = WriterIdentity::from_bytes(*b"seed-alias-test!");
    let result = granary_client::publish_excluding_file(
        &remote,
        &store,
        &source,
        seed_identity,
        &volume,
        &key,
        &identity,
        Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        },
        Policy::default(),
    )
    .await;
    assert!(
        matches!(
            result,
            Err(PublishError::Harvest(
                granary_client::HarvestError::RefusedFileIdentity { .. }
            ))
        ),
        "a hard-link alias of the private seed must refuse the publish, got {result:?}"
    );
    assert_eq!(
        remote
            .max_seq(volume.as_str())
            .await
            .unwrap_or_else(|e| panic!("{e}")),
        None,
        "the refused source must not publish a root"
    );

    std::fs::remove_file(&alias).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(source.join("ordinary.txt"), b"ordinary publish")
        .unwrap_or_else(|e| panic!("{e}"));
    let summary = granary_client::publish_excluding_file(
        &remote,
        &store,
        &source,
        seed_identity,
        &volume,
        &key,
        &identity,
        Timestamp {
            secs: 1_760_000_001,
            nanos: 0,
        },
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("ordinary publish must succeed: {e}"));
    assert_eq!(summary.seq, 1, "positive-control publish must commit");
}

// --------------------------------------------------------- key handling

// ------------------------------------------------------ parse_publish

pub(crate) fn osstr(s: &str) -> OsString {
    OsString::from(s)
}

pub(crate) fn vol(s: &str) -> VolumeName {
    VolumeName::new(s.to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

/// Duplicate `--bucket` flags: the later one silently wins. Pinned
/// as CURRENT behaviour (not endorsed as correct) — a future change
/// away from last-wins is then a deliberate decision, not an
/// accidental one.
#[test]
fn parse_publish_duplicate_flag_last_wins() {
    let args: Vec<OsString> = [
        "store",
        "src",
        "vol",
        "--endpoint",
        "http://a",
        "--bucket",
        "first-bucket",
        "--bucket",
        "second-bucket",
        "--key-seed",
        "seed-path",
        "--direct-s3",
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let parsed = parse_publish(&args, &|_| None).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        parsed.bucket.as_deref(),
        Some("second-bucket"),
        "the LATER --bucket silently wins"
    );
}

/// A non-UTF-8 argument standing where a flag NAME belongs does not
/// hit the "value is not valid UTF-8" refusal (that check covers
/// only a flag's VALUE): `arg.to_str().unwrap_or_default()` turns it
/// into `""`, which does not start with `--`, so it is silently
/// reclassified as a POSITIONAL. A mangled `--bucket` therefore
/// degrades to a generic arity error rather than the named "unknown
/// flag" refusal the module doc promises for a mistyped flag. Pinned
/// as CURRENT behaviour and reported rather than changed: the
/// remedy here is test strengthening, not a parser change.
#[test]
fn parse_publish_non_utf8_flag_name_is_reclassified_as_positional_not_refused() {
    let bad = OsString::from_vec(vec![0xFF, 0xFE, 0x80]);
    let args: Vec<OsString> = vec![osstr("store"), osstr("src"), osstr("vol"), bad];
    let err = parse_publish(&args, &|_| None).expect_err("4 positionals must not parse as 3");
    assert!(
        err.contains("expected 3 positional"),
        "the non-UTF-8 flag-shaped argument was silently treated as a 4th positional, \
         producing an arity error instead of a named flag refusal: {err}"
    );
}

/// `nanos` is a NON-NEGATIVE offset forward from `secs`,
/// so a pre-1970 instant cannot be encoded by negating the seconds
/// and keeping the sub-second part — that names an instant 1 second
/// LATER than intended, in a signed, hash-chained root. The
/// decomposition must floor.
#[test]
fn pre_epoch_timestamps_floor_rather_than_negate() {
    // THE PRODUCTION FUNCTION, called — not a local copy of its
    // rule. A local reimplementation of the decomposition would
    // stay green if the production arm were reverted.
    let decompose = pre_epoch_parts;
    // 1.5 s before the epoch = 1969-12-31T23:59:58.5Z.
    // WRONG (the negating convention): secs -1, nanos 500_000_000,
    // which reads as epoch - 0.5 s.
    assert_eq!(decompose(1, 500_000_000), (-2, 500_000_000));
    // Whole seconds need no flooring.
    assert_eq!(decompose(1, 0), (-1, 0));
    assert_eq!(decompose(0, 0), (0, 0));
    // And the encoded instant is right: secs + nanos/1e9 == -1.5.
    let (secs, nanos) = decompose(1, 500_000_000);
    assert_eq!(secs, -2);
    assert_eq!(nanos, 500_000_000);
    // -2 s + 0.5 s = -1.5 s, stated in integer nanoseconds so the
    // assertion carries no float rounding of its own.
    assert_eq!(
        i128::from(secs) * 1_000_000_000 + i128::from(nanos),
        -1_500_000_000
    );
    // Every nanos stays below 1_000_000_000, as the decoder requires.
    for subsec in [1u32, 999_999_999, 500_000_000] {
        let (_, n) = decompose(3, subsec);
        assert!(n < 1_000_000_000, "nanos {n} must stay under 1e9");
    }
    // At the largest u64 that converts to i64, adding a fractional
    // second must clamp to the representable floor without
    // overflow.
    let at_boundary = u64::try_from(i64::MAX).unwrap_or(u64::MAX);
    assert_eq!(decompose(at_boundary, 1), (i64::MIN, 999_999_999));
    assert_eq!(decompose(u64::MAX, 1), (i64::MIN, 999_999_999));
    assert_eq!(decompose(at_boundary, 0), (-i64::MAX, 0));
}

// ------------------------------------------------- --cache-dir

/// The CLI's cache quota POLICY default (`Cache::open`
/// itself takes the quota as a parameter and has no default of its
/// own) — pinned as a literal so a unit change is a deliberate edit
/// to this row, not a silent drift.
#[test]
fn default_cache_quota_bytes_is_pinned_at_ten_gib() {
    assert_eq!(DEFAULT_CACHE_QUOTA_BYTES, 10 * 1024 * 1024 * 1024);
    assert_eq!(DEFAULT_CACHE_QUOTA_BYTES, 10_737_418_240);
}

/// `--cache-dir` is OPTIONAL and LAST-WINS on `gran cat` — absent
/// means no cache, today's behaviour.
#[test]
fn parse_cat_accepts_cache_dir_and_is_absent_by_default() {
    let none = parse_cat(&cat_argv(&["--pin", &a_pin()])).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(none.cache_dir, None, "no --cache-dir must stay uncached");
    let parsed = parse_cat(&cat_argv(&[
        "--pin",
        &a_pin(),
        "--cache-dir",
        "/tmp/a",
        "--cache-dir",
        "/tmp/b",
    ]))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        parsed.cache_dir,
        Some(PathBuf::from("/tmp/b")),
        "the LAST --cache-dir wins — one cache dir, and a repeat is a correction"
    );
}

/// Same flag, same shape, on `gran publish` — the
/// flag exists on BOTH parsers even though the demo only ever passes
/// it to `cat`.
#[test]
fn parse_publish_accepts_cache_dir_and_is_absent_by_default() {
    let none = parse_publish(&publish_argv(&["--pin", &a_pin()]), &|_| None)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(none.cache_dir, None);
    let parsed = parse_publish(
        &publish_argv(&["--pin", &a_pin(), "--cache-dir", "/tmp/store-cache"]),
        &|_| None,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.cache_dir, Some(PathBuf::from("/tmp/store-cache")));
}

/// **`--cache-dir` with `--direct-s3` is REFUSED** — the direct-S3
/// route has no endpoint/pin origin to bind a cache dir to.
#[test]
fn parse_publish_refuses_cache_dir_with_direct_s3() {
    let err = parse_publish(
        &publish_argv(&[
            "--direct-s3",
            "--bucket",
            "b",
            "--cache-dir",
            "/tmp/store-cache",
        ]),
        &|_| None,
    )
    .expect_err("a direct-S3 publish has no origin for a cache dir to bind to");
    assert!(
        err.contains("--cache-dir") && err.contains("--direct-s3"),
        "the refusal must name both flags, got: {err}"
    );
    // POSITIVE CONTROL: --cache-dir alone (server route) is accepted,
    // so the row above is discriminating on --direct-s3, not merely
    // refusing --cache-dir outright.
    let parsed = parse_publish(
        &publish_argv(&["--pin", &a_pin(), "--cache-dir", "/tmp/store-cache"]),
        &|_| None,
    )
    .unwrap_or_else(|e| panic!("--cache-dir alone must be accepted: {e}"));
    assert_eq!(parsed.cache_dir, Some(PathBuf::from("/tmp/store-cache")));
}

/// **Cache-origin composition and keyed/keyless behavior, from the
/// function the CLI actually calls** — never re-derived by the test.
/// `cat` without `--root-key` composes `root_key_id: None`;
/// `--root-key` given composes `Some(CacheOrigin::root_key_digest)`;
/// `endpoint_url` is the `--endpoint` value VERBATIM; `pin_set_digest`
/// is `CacheOrigin::pin_set_digest` over the exact pin slice given.
#[test]
fn cache_origin_composes_cli_inputs_with_and_without_a_root_key() {
    let pins = [[0xAB_u8; 32], [0xCD_u8; 32]];
    let keyless = cache_origin("https://h.example:9", &pins, None);
    assert_eq!(keyless.endpoint_url, "https://h.example:9");
    assert_eq!(keyless.pin_set_digest, CacheOrigin::pin_set_digest(&pins));
    assert_eq!(
        keyless.root_key_id, None,
        "a keyless reader composes no root_key_id at all"
    );

    let public = [0x42_u8; 32];
    let keyed = cache_origin("https://h.example:9", &pins, Some(&public));
    assert_eq!(
        keyed.root_key_id,
        Some(CacheOrigin::root_key_digest(&public)),
        "a supplied key composes Some(digest), through the shared library function"
    );
    // Everything else about the origin is unchanged by the key.
    assert_eq!(keyed.endpoint_url, keyless.endpoint_url);
    assert_eq!(keyed.pin_set_digest, keyless.pin_set_digest);
}

// ------------------------------ the DEFAULT publish route (HTTP)

/// A hex `sha256/` pin, rendered the way the config parser reads it.
pub(crate) fn a_pin() -> String {
    // 32 bytes of 0xAB, base64 — produced by the same encoder the
    // parser decodes with, so this row cannot pass against a
    // rendering neither side agrees on.
    format!("sha256/{}", granary_net::b64::encode_pin(&[0xAB_u8; 32]))
}

fn publish_argv(extra: &[&str]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = [
        "store",
        "src",
        "vol",
        "--endpoint",
        "https://h",
        "--key-seed",
        "seed",
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    argv.extend(extra.iter().map(|s| osstr(s)));
    argv
}

/// NEITHER pins nor the opt-out is a usage error that NAMES BOTH
/// options — never a silent fall back to the bucket. The operator who
/// forgot to set the pins is exactly the person a fallback would
/// publish without them.
#[test]
fn publish_with_no_transport_names_both_options() {
    let err = parse_publish(&publish_argv(&[]), &|_| None)
        .expect_err("no transport chosen must not default to the bucket");
    assert!(
        err.contains("--pin") && err.contains(ENV_TLS_PINS) && err.contains("--direct-s3"),
        "the refusal must name every way out of it, got: {err}"
    );
}

/// Pins configured select the through-the-server route.
#[test]
fn publish_with_a_pin_flag_takes_the_server_route() {
    let parsed = parse_publish(&publish_argv(&["--pin", &a_pin()]), &|_| None)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.tls_pins.as_deref(), Some(&[[0xAB_u8; 32]][..]));
    assert!(!parsed.direct_s3);
    assert!(parsed.bucket.is_none(), "the server route has no bucket");
}

/// `--wire-snapshot`/`--wire-run-id`/`--wire-role`: all
/// three, given together, parse into the trio verbatim.
#[test]
fn publish_parses_the_wire_snapshot_trio_when_all_three_are_given() {
    let parsed = parse_publish(
        &publish_argv(&[
            "--pin",
            &a_pin(),
            "--wire-snapshot",
            "/tmp/snap.json",
            "--wire-run-id",
            "run-1",
            "--wire-role",
            "publisher",
        ]),
        &|_| None,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let wire = parsed.wire.expect("all three given");
    assert_eq!(wire.path, PathBuf::from("/tmp/snap.json"));
    assert_eq!(wire.run_id, "run-1");
    assert_eq!(wire.role, "publisher");
}

/// A PARTIAL trio is refused, naming which of the three is absent.
#[test]
fn publish_refuses_a_partial_wire_snapshot_trio() {
    let err = parse_publish(
        &publish_argv(&[
            "--pin",
            &a_pin(),
            "--wire-snapshot",
            "/tmp/snap.json",
            "--wire-run-id",
            "run-1",
        ]),
        &|_| None,
    )
    .expect_err("path and run-id given, role absent");
    assert!(
        err.contains("--wire-snapshot")
            && err.contains("--wire-run-id")
            && err.contains("--wire-role"),
        "the refusal must name all three flags, got: {err}"
    );
}

/// **A role VALUE outside the closed vocabulary is refused at parse
/// time, before `gran publish` does any work.**
/// All three flags were PRESENT — `wire_snapshot_args`'s own
/// all-or-nothing check passes — but the misspelled `"clientt-1"`
/// is not a role this trio accepts. Before value validation,
/// `parse_publish` never looked past presence, so a bad
/// role reached `write_wire_snapshot_if_requested` only at the very
/// end of a completed publish.
#[test]
fn publish_refuses_a_bad_role_value_before_doing_any_work() {
    let err = parse_publish(
        &publish_argv(&[
            "--pin",
            &a_pin(),
            "--wire-snapshot",
            "/tmp/snap.json",
            "--wire-run-id",
            "run-1",
            "--wire-role",
            "clientt-1",
        ]),
        &|_| None,
    )
    .expect_err("clientt-1 is not in the closed role vocabulary");
    assert!(
        err.contains("vocabulary"),
        "the refusal must be traceable to SnapshotError::UnknownRole specifically \
         (its Display text is the only one of the four value-refusal variants that \
         contains \"vocabulary\"), not merely to SOME value error, got: {err}"
    );
}

/// The environment is the FALLBACK for the flag, and it selects the
/// same route — so a shell that exports the pins needs no flag.
#[test]
fn publish_reads_pins_from_the_environment_when_the_flag_is_absent() {
    let pin = a_pin();
    let parsed = parse_publish(&publish_argv(&[]), &|name| {
        (name == ENV_TLS_PINS).then(|| pin.clone())
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.tls_pins.as_deref(), Some(&[[0xAB_u8; 32]][..]));
}

/// **A pin value that names no pins is a usage error, and it is the
/// same error from BOTH entry points.** `parse_pin_set` answers
/// `Ok(vec![])` for an empty or whitespace-only list, and an empty
/// pin set is the set that refuses EVERY certificate — so a value
/// naming no pins is never a transport, whichever entry point
/// carried it. The two agree because they run through one function:
/// the older shape filtered the blank VARIABLE and not the blank
/// FLAG, so `--pin ""` selected the through-the-server route with a
/// pin set nothing can satisfy, and the operator was told about it
/// as a handshake failure rather than as the configuration error it
/// is.
#[test]
fn a_pin_value_naming_no_pins_is_refused_from_either_entry_point() {
    for blank in ["", "   "] {
        let flag = parse_publish(&publish_argv(&["--pin", blank]), &|_| None)
            .expect_err("a --pin value naming no pins is not a route");
        assert!(
            flag.contains("--pin") && flag.contains("names no pins"),
            "the refusal must name the flag it came from, got: {flag}"
        );
        let var = parse_publish(&publish_argv(&[]), &|name| {
            (name == ENV_TLS_PINS).then(|| blank.to_owned())
        })
        .expect_err("a pin variable naming no pins is not a route");
        assert!(
            var.contains(ENV_TLS_PINS) && var.contains("names no pins"),
            "the refusal must name the variable it came from, got: {var}"
        );
        // Publish's REMEDY is publish's: the bucket opt-out and the
        // variable it may have come from.
        assert!(
            flag.contains("--direct-s3") && flag.contains("unset the variable"),
            "publish has both, and the message must offer them: {flag}"
        );

        // Cat runs the same CHECK and gets a different REMEDY,
        // because it has neither. Offering `--direct-s3` here is
        // advice for a flag the next line refuses as an unknown
        // flag, and offering the variable is advice for one cat
        // deliberately does not read.
        let read = parse_cat(&cat_argv(&["--pin", blank]))
            .expect_err("a --pin value naming no pins is not a transport");
        assert!(
            read.contains("--pin") && read.contains("names no pins"),
            "the refusal must name the flag it came from, got: {read}"
        );
        assert!(
            !read.contains("--direct-s3") && !read.contains("--bucket"),
            "cat has no bucket to opt out to, and rejects the flag by name: {read}"
        );
        assert!(
            read.contains(ENV_TLS_PINS) && read.contains("not read"),
            "and must say the variable is ignored rather than suggest unsetting it: \
             {read}"
        );
    }
}

/// A blank value is refused rather than read as ABSENT, and this is
/// the row that tells the two designs apart. Under empty-means-absent
/// an exported-but-empty `GRANARY_TLS_PINS` falls through to "unset"
/// and the opt-out runs: the operator who blanked the variable gets a
/// bucket publish and no word about it. Empty-means-error says so
/// instead, and `unset` is the one-line fix the message asks for.
#[test]
fn a_blank_pin_variable_is_not_silently_absent() {
    let err = parse_publish(&publish_argv(&["--direct-s3", "--bucket", "b"]), &|name| {
        (name == ENV_TLS_PINS).then(String::new)
    })
    .expect_err("a blank pin variable is a configuration error, not an absence");
    assert!(
        err.contains(ENV_TLS_PINS),
        "the refusal must name the variable, got: {err}"
    );
}

/// **`--pin` plus `--bucket` is refused BY NAME.** The
/// through-the-server route never names a bucket, so the flag was
/// parsed and thrown away — the same user error `--pin --direct-s3`
/// refuses outright, answered two different ways.
#[test]
fn publish_with_a_pin_and_a_bucket_refuses_naming_both_flags() {
    let err = parse_publish(
        &publish_argv(&["--pin", &a_pin(), "--bucket", "b"]),
        &|_| None,
    )
    .expect_err("the server route has nowhere to put a bucket");
    assert!(
        err.contains("--pin") && err.contains("--bucket"),
        "the refusal must name both flags, got: {err}"
    );
}

/// The pins' SOURCE does not change the answer: a bucket is just as
/// discarded when the pins came from the environment.
#[test]
fn pins_from_the_environment_plus_a_bucket_refuses_too() {
    let pin = a_pin();
    let err = parse_publish(&publish_argv(&["--bucket", "b"]), &|name| {
        (name == ENV_TLS_PINS).then(|| pin.clone())
    })
    .expect_err("the server route has nowhere to put a bucket");
    assert!(
        err.contains(ENV_TLS_PINS) && err.contains("--bucket"),
        "the refusal must name both, got: {err}"
    );
}

/// `--pin` ACCUMULATES. A pin set is a set — RFC 7469's primary plus a
/// pre-generated backup — so a second flag naming the backup must not
/// discard the primary the way `--bucket` discards its predecessor.
#[test]
fn pin_flags_accumulate_rather_than_last_wins() {
    let second = format!("sha256/{}", granary_net::b64::encode_pin(&[0xCD_u8; 32]));
    let parsed = parse_publish(
        &publish_argv(&["--pin", &a_pin(), "--pin", &second]),
        &|_| None,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        parsed.tls_pins.as_deref(),
        Some(&[[0xAB_u8; 32], [0xCD_u8; 32]][..]),
        "the backup slot must not evict the primary"
    );
}

/// BOTH is a usage error: two trust models, and an invocation that
/// quietly picked one would leave an operator believing the wrong
/// thing about which one they got.
#[test]
fn publish_with_both_transports_refuses() {
    let err = parse_publish(
        &publish_argv(&["--pin", &a_pin(), "--direct-s3", "--bucket", "b"]),
        &|_| None,
    )
    .expect_err("pins plus the opt-out is two trust models");
    assert!(err.contains("trust models"), "got: {err}");
}

/// `--direct-s3` is VALUELESS, and the parser must not eat the flag
/// that follows it. Handled before the value-taking branch: falling
/// through would swallow `--bucket` and then fail with an arity error
/// naming neither.
#[test]
fn the_opt_out_flag_does_not_swallow_the_next_flag() {
    let parsed = parse_publish(&publish_argv(&["--direct-s3", "--bucket", "b"]), &|_| None)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(parsed.direct_s3);
    assert_eq!(parsed.bucket.as_deref(), Some("b"));
}

/// The opt-out needs a bucket, and says so rather than failing later.
#[test]
fn the_opt_out_without_a_bucket_refuses() {
    let err = parse_publish(&publish_argv(&["--direct-s3"]), &|_| None)
        .expect_err("--direct-s3 has nowhere to write without a bucket");
    assert!(err.contains("--bucket"), "got: {err}");
}

// ---------------------------------------------------------- cat

/// **Test 1: the path grammar** is refused LOCALLY, before a
/// socket is opened: an empty component, `.` and `..` are all
/// invalid manifest names, and `..` in particular would be a real
/// traversal — the walk holds a node STACK, so a component that
/// popped it would reach a sibling subtree the operator did not
/// name. Refusing here means the refusal costs no round trip
/// and cannot depend on what a server chose to send back.
#[test]
fn split_cat_path_refuses_empty_dot_and_dotdot() {
    for bad in ["", "/", "a//b", "a/./b", "a/../b", "..", ".", "a/"] {
        let err = split_cat_path(bad.as_bytes())
            .err()
            .unwrap_or_else(|| panic!("{bad:?} must be refused before any fetch"));
        assert!(!err.is_empty(), "the refusal must say something: {bad:?}");
    }
    // And the shapes that ARE legal still parse, leading slash
    // stripped, so the refusals above are not simply "refuse
    // everything".
    let parsed = split_cat_path(b"/dir/file.txt").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed.first().map(Name::as_bytes), Some(&b"dir"[..]));
    assert_eq!(parsed.get(1).map(Name::as_bytes), Some(&b"file.txt"[..]));
}

/// The path operand, through the shipped local grammar — a test that
/// hand-built the `Name` vector would walk a path `gran cat` cannot
/// be given.
fn cat_path(path: &str) -> Vec<Name> {
    split_cat_path(path.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

/// The honest-guarantee vocabulary:
/// the words that would claim more than EITHER cat mode delivers —
/// a signature check the no-key path does not do, and a freshness
/// claim neither path can make, since the seq comes from the
/// untrusted store's `max_seq`.
///
/// One table, read by the runtime warning's row and by the help
/// text's, so the two texts cannot drift into being held to
/// different lists.
const OVERCLAIMS: [&str; 5] = ["verified", "authentic", "signed by", "latest", "up to date"];

/// **Test 7:** without `--root-key` the read PROCEEDS and the
/// operator is told, on stderr, exactly what was and was not
/// checked. The warning is not decoration: the two modes
/// differ in the guarantee they deliver, and a reader who is
/// not told which one they got will assume the stronger.
///
/// The sink is a PARAMETER rather than an ambient `eprintln!`
/// so the warning is impossible to build the unverified
/// verifier without — and so this row can read what was
/// actually written instead of scanning source for a call.
#[test]
fn cat_without_root_key_warns_but_proceeds() {
    let mut warned = Vec::new();
    let verifier = reader_verifier(None, &mut |message| warned.push(message.to_string()))
        .unwrap_or_else(|e| panic!("it must proceed: {e}"));
    assert!(
        !verifier.is_verifying(),
        "no key means no signature check — the verifier must say so"
    );
    let text = warned.join("\n");
    assert!(
        text.contains("signature") && text.contains("NOT"),
        "the warning must name what was skipped, got: {text}"
    );
    assert!(
        text.contains("--root-key"),
        "and how to get the stronger mode, got: {text}"
    );
    // The honest-guarantee rule: this path checks
    // content and structure, and nothing on it may read as a claim
    // that a signature was checked or that the head is fresh.
    for forbidden in OVERCLAIMS {
        assert!(
            !text.contains(forbidden),
            "the no-key warning must not claim {forbidden:?}, got: {text}"
        );
    }

    // WITH a key there is nothing to warn about, and the verifier
    // really is armed.
    let mut quiet = Vec::new();
    let key = parse_signing_key(&format!("ed25519:{}", "ab".repeat(32)))
        .unwrap_or_else(|e| panic!("{e}"));
    let armed = reader_verifier(Some(key), &mut |message| quiet.push(message.to_string()))
        .unwrap_or_else(|e| panic!("a real key: {e}"));
    assert!(armed.is_verifying(), "--root-key must arm the verifier");
    assert!(quiet.is_empty(), "and silence the warning, got: {quiet:?}");

    // The all-zero key is a fail-open sentinel, not an anchor, and
    // `RootVerifier::trusting` is FALLIBLE for that reason — its
    // refusal must reach the operator rather than be unwrapped.
    let err = reader_verifier(Some([0_u8; SIGNING_KEY_LEN]), &mut |_| {})
        .err()
        .unwrap_or_else(|| panic!("the all-zero key must be refused"));
    assert!(err.contains("all-zero"), "got: {err}");
}

/// The source text of `env_filter_from`'s body, for the row that refuses a
/// write inside it.
///
/// Sliced from the function's signature to the first `\n}` at column zero,
/// which is where rustfmt closes a top-level item in this file. It PANICS
/// rather than returning an empty string when either anchor is missing: a
/// slicer that silently returns nothing makes every assertion over the result
/// vacuously true, which is the shape this repository keeps paying for.
fn env_filter_from_body() -> String {
    let source = production_source();
    let start = source
        .find("fn env_filter_from(")
        .expect("`main.rs` defines `env_filter_from`");
    let rest = &source[start..];
    let end = rest
        .find("\n}\n")
        .expect("`env_filter_from` closes at column zero");
    rest[..end].to_owned()
}

/// The binary's production source — what a source-scan row must count
/// in, so that the row judges the BINARY rather than its own text.
///
/// **The property, stated before the code so that the code
/// can be judged against
/// it:** *test-fixture and test-assertion text must never be able to
/// compensate for an absent production occurrence.* A scan that can see
/// test text is a scan whose needles can be satisfied by the needles
/// themselves, and then the production code it exists to pin can be
/// deleted with every row still green.
///
/// Were these tests inline in `main.rs`, a function that split that file
/// at `#[cfg(test)] mod tests {` and asserted the marker PRESENT would
/// fail open: the marker's text also appears inside the test module, so
/// the assertion holds when the real marker is broken, the split yields
/// the WHOLE FILE, and the test module's own text satisfies the counts. The mutation that shows
/// it: break the marker, delete the production `eprintln!`, and put a
/// string carrying the needle in the test module — such a row stays GREEN.
///
/// This module is its own file, so a missing marker cannot widen
/// anything. The same failure arrives from the other side instead: test
/// text coming INTO `main.rs`. So the assertion inverts, and it is
/// written against the ATTRIBUTE RUN rather than against two adjacent
/// lines, because a two-line form misses a stacked attribute:
/// `#[cfg(test)]` / `#[cfg(unix)]` / `mod planted {` holds a
/// whole test module whose `const _: &str = "<needle>"` satisfies a
/// caller's count, while a marker of `"#[cfg(test)]\nmod "` never matches
/// it at all and the guard passes.
///
/// `#[cfg(test)] fn` would be admitted by NAME, not by shape, and the set is
/// empty of them today. **What a removal does is the reason to trust the
/// mechanism**: when an admitted member leaves `main.rs`, every row that
/// calls this function goes red on the per-member floor naming it, where a
/// shape test would pass; the set demands an edit here, which is the point.
/// Adding another takes the same deliberate line.
///
/// **>>> THE SUBJECT IS ONE FILE AND THE CRATE'S PRODUCTION CODE IS NOT
/// ONE FILE, SO EVERY `count() == 0` ROW HERE NEEDS A POSITIVE ANCHOR. <<<**
/// Production code also lives in files other than `main.rs`. The
/// command in the paragraph after the class definition lists the files
/// under `crates/granary-cli/src`, other than files whose name ends in
/// `tests.rs`, that contain `#[cfg(test)]`, `main.rs` among them —
/// not every production file — and no count of either is written here.
/// This function
/// deliberately keeps reading `main.rs` ALONE — widening the haystack would
/// let a sibling's text satisfy a needle, which is the pollution the whole
/// mechanism exists to prevent — and the price of that narrowness is exactly
/// this: **a zero count over one filename is satisfied equally by "the
/// property holds" and by "the code left this file".**
///
/// The rule, so a future row does not add an unanchored zero: **every
/// `matches(x).count() == 0` must sit beside a `count() == 1` (or more) on the
/// same construct family.** `cat_resolves_through_the_verifying_entry_point`
/// is the shape: its two zeroes each pair with a one on the `_verified`
/// spelling. If `cat` moves out of `main.rs`, those ones drop to zero
/// and FAIL; without them the zeroes alone would go quietly green.
///
/// **Every file under `crates/granary-cli/src` other
/// than `main.rs` whose name does not end in
/// `tests.rs` and that contains `#[cfg(test)]` carries
/// test items of its own, and NONE of them is guarded
/// by anything here** — the admitted set governs
/// `main.rs` and `main.rs` only. That is correct while
/// nothing scans them, and it stops being correct the
/// moment a row adds one to a haystack. **That set is
/// a CLASS, not a list**, and it is not the set of
/// `main.rs`'s children — `attach/mount_table.rs` is
/// not a child of `main.rs` at all, so a reader
/// checking only the direct children of `main.rs`
/// would miss it.
///
/// **RE-DERIVE IT RATHER THAN RE-READING IT**, because a hand-kept list
/// falls short whenever another file gains `#[cfg(test)]` items:
/// `grep -rl '#\[cfg(test)\]' crates/granary-cli/src | grep -v 'tests\.rs$'`
/// prints the class, plus `main.rs` itself. Nothing asserts it —
/// `production_source()` scans `include_str!("main.rs")` alone and no gate
/// enumerates the children — so a command a reader can run beats a sentence
/// somebody has to maintain.
///
/// The marker is assembled from fragments so that placing this helper
/// in the scanned source cannot make the marker match itself.
fn production_source() -> &'static str {
    // Relative to THIS file, which sits beside `main.rs` in `src/`.
    const SOURCE: &str = include_str!("main.rs");

    // THE ADMITTED SET, as (attribute, item) PAIRS — never a shape test.
    // Each shape test this set replaces is defeated by something that
    // shares the shape:
    //
    //   * matching `#[cfg(test)]\nmod ` as two adjacent lines is defeated by
    //     an INTERVENING attribute — `#[cfg(test)]` / `#[cfg(unix)]` /
    //     `mod planted { … }` never matches, so a whole test module sits
    //     inside the scan with the guard green;
    //   * requiring the item to end in `;` is defeated by anything else that
    //     ends in `;` — `#[cfg(test)] const NEEDLE: &str = "<a needle>";`
    //     passes, and its literal is then inside `SOURCE`, which is the
    //     precise property this function exists to deny.
    //
    // A set has neither hole: an item reaches production text only by being
    // written down here, which is an edit a reviewer sees.
    let admitted = [
        ("#[cfg(test)]", "mod tests;"),
        ("#[cfg(test)]", "use tests::parse_publish_options;"),
        (
            "#[cfg(all(feature = \"publish-restart-tests\", not(debug_assertions)))]",
            "compile_error!(\"publish-restart-tests must never compile into a release granary-cli artifact\");",
        ),
        (
            "#[cfg(feature = \"publish-restart-tests\")]",
            "if let Err(error) = granary_client::publish_restart::initialize() {",
        ),
    ];

    // Assemble fragments so these lines cannot match their own marker.
    let cfg = ["#[", "cfg("].concat();
    let test = ["te", "st"].concat();

    // DELIBERATELY WIDER THAN THE ATTRIBUTE IT LOOKS FOR. Anything opening
    // `#[cfg(` and naming `test` anywhere is caught — `all(test, unix)`,
    // `any(test, …)`, a `feature = "fastest"` false positive — and then has
    // to be in the set EXACTLY. Every way of being wrong here fails LOUDLY
    // and is admitted by a human, which is the only direction a control of
    // this kind may err in. The same goes for the two shapes this line
    // scanner cannot see through: a `#[cfg(test)]` inside a block comment or
    // a raw string in `main.rs` produces a false REFUSAL, not a false pass.
    let mut seen = vec![0_usize; admitted.len()];
    let mut lines = SOURCE.lines();
    while let Some(line) = lines.next() {
        let attribute = line.trim();
        if !(attribute.starts_with(&cfg) && attribute.contains(&test)) {
            continue;
        }
        // Walk to the end of the attribute run. A one-line
        // `#[cfg(test)] mod planted { … }` never gets here: its whole line is
        // the `attribute`, which then matches no admitted spelling.
        let mut item = "";
        for next in lines.by_ref() {
            let trimmed = next.trim();
            if trimmed.is_empty() || trimmed.starts_with("#[") || trimmed.starts_with("//") {
                continue;
            }
            item = trimmed;
            break;
        }
        let mut matched = false;
        for (index, (gate, prefix)) in admitted.iter().enumerate() {
            if *gate == attribute && item.starts_with(prefix) {
                if let Some(count) = seen.get_mut(index) {
                    *count += 1;
                }
                matched = true;
                break;
            }
        }
        assert!(
            matched,
            "`{attribute}` / `{item}` is test-gated in the crate root and is not in this \
             function's admitted set, so its text is inside every scan this function feeds: \
             a fixture string there can supply a needle the production code has lost. Move \
             it out of line, or admit it here by its exact spelling."
        );
    }

    // THE FLOOR, and it is per-member rather than a total: a total is
    // satisfied by a swap, and a loop over zero occurrences asserts nothing
    // at all. `mod tests;` being present is what makes the scan subject a
    // production-only file in the first place.
    for (index, (gate, prefix)) in admitted.iter().enumerate() {
        assert_eq!(
            seen.get(index).copied().unwrap_or(0),
            1,
            "`{gate}` / `{prefix}` must appear exactly once in the crate root"
        );
    }
    SOURCE
}

/// A [`PublishSummary`] with every field at an inert default —
/// `report_publish`'s two conditional lines (`hint_written`,
/// `cache_write_skipped`) are what these tests vary; nothing else
/// about the summary matters to them.
fn dummy_publish_summary(hint_written: bool) -> PublishSummary {
    PublishSummary {
        seq: 1,
        epoch: 1,
        novel_objects: 0,
        novel_bytes: 0,
        bins_planned: 0,
        bins_uploaded: 0,
        bin_bytes_uploaded: 0,
        shards_total: 0,
        shards_rewritten: 0,
        sheaf_uploaded: false,
        prefix_bits: 0,
        manifest_root: GrainId::of(b"report-publish-test-root"),
        binmap_index: GrainId::of(b"report-publish-test-binmap"),
        sheaf_head: GrainId::of(b"report-publish-test-sheaf"),
        hint_written,
        harvest: granary_client::HarvestStats::default(),
    }
}

/// Runs `report_publish` into two owned buffers and asserts the exit
/// code once, so every row below only has to state what the text
/// should (or should not) contain.
fn captured_report(hint_written: bool, cache_write_skipped: bool) -> (String, String) {
    let volume = vol("report-publish-test");
    let summary = dummy_publish_summary(hint_written);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = report_publish(&volume, &summary, cache_write_skipped, &mut out, &mut err);
    assert_eq!(code, ExitCode::SUCCESS, "the exit code stays SUCCESS");
    (
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

/// The cache-skip warning's required substance ON STDERR: the
/// lock-contention cause, the remedy naming `gran cat` AND the
/// `--cache-dir` it has to be given, the freshness floor, and the
/// provenance of the key the remedy needs — `gran publish` takes
/// `--key-seed`, so the remedy cannot tell the reader to reuse a
/// `--root-key` this command never had. A bare
/// `contains("cache write-through skipped")` stays green if the
/// whole remedy sentence is deleted; this does not.
const CACHE_SKIP_REQUIRED: [&str; 5] = [
    "another process held",
    "gran cat",
    "--cache-dir",
    "freshness floor",
    "seed derives",
];

/// The same warning's required substance ON STDOUT, where the
/// record itself is written: the one-line advisory has to carry the
/// remedy too, because an operator reading a redirected stdout
/// never sees the stderr sentence at all.
const CACHE_SKIP_REQUIRED_STDOUT: [&str; 2] = ["gran cat --cache-dir", "raises the floor"];

/// What the message discipline forbids, in either sink, on every
/// row: the write-through caches ROOT + anchor only (never
/// "offline"), a skipped write is never phrased as landing ("cache
/// updated" bare), and a degraded read's blindness is never
/// overclaimed to be total.
const MESSAGE_FORBIDDEN: [&str; 3] = ["offline", "cache updated", "no degraded read can"];

/// `report_publish`'s two advisories (`hint_written`, `cache_write_skipped`)
/// each fire on their own sinks exactly when their write was
/// skipped, the unconditional record always reaches `out` first,
/// and the message discipline holds on every row — not just the one
/// under test.
#[test]
fn report_publish_advisories_fire_exactly_when_their_write_was_skipped() {
    for (hint_written, cache_write_skipped, expect_hint, expect_cache) in [
        (true, false, false, false),
        (false, false, true, false),
        (true, true, false, true),
        (false, true, true, true),
    ] {
        let (out_text, err_text) = captured_report(hint_written, cache_write_skipped);

        assert!(
            out_text.contains("published report-publish-test seq"),
            "the unconditional record must reach stdout regardless of either advisory, \
             got: {out_text}"
        );
        // The tree's id is labelled `manifest-root`, the word
        // `gran mount` uses for the same id (`manifest-root=`) and the
        // flag that accepts it; `root` names the root document, a
        // different object, so no line labels the manifest id `root`.
        let expected = format!(
            "manifest-root {}",
            dummy_publish_summary(hint_written).manifest_root
        );
        assert!(
            out_text.lines().any(|l| l == expected),
            "stdout must carry {expected:?}, got: {out_text}"
        );
        assert!(
            !out_text.lines().any(|l| l.starts_with("root ")),
            "no line may still label the manifest id `root`, got: {out_text}"
        );

        if expect_hint {
            assert!(
                err_text.contains("hint write failed"),
                "got stderr: {err_text}"
            );
            assert!(
                out_text.contains("hint NOT updated"),
                "got stdout: {out_text}"
            );
        } else {
            assert!(
                !err_text.contains("hint write failed"),
                "got stderr: {err_text}"
            );
            assert!(
                !out_text.contains("hint NOT updated"),
                "got stdout: {out_text}"
            );
        }

        if expect_cache {
            assert!(
                out_text.contains("cache NOT updated"),
                "got stdout: {out_text}"
            );
            for phrase in CACHE_SKIP_REQUIRED {
                assert!(
                    err_text.contains(phrase),
                    "the warning must carry {phrase:?}, got: {err_text}"
                );
            }
            for phrase in CACHE_SKIP_REQUIRED_STDOUT {
                assert!(
                    out_text.contains(phrase),
                    "the stdout advisory must carry {phrase:?}, got: {out_text}"
                );
            }
        } else {
            assert!(
                !err_text.contains("cache write-through skipped"),
                "got stderr: {err_text}"
            );
            assert!(
                !out_text.contains("cache NOT updated"),
                "got stdout: {out_text}"
            );
        }

        for forbidden in MESSAGE_FORBIDDEN {
            assert!(
                !out_text.contains(forbidden),
                "stdout must never claim {forbidden:?}, got: {out_text}"
            );
            assert!(
                !err_text.contains(forbidden),
                "stderr must never claim {forbidden:?}, got: {err_text}"
            );
        }
    }
}

/// A sink whose `write` fails once it has accepted `ok_writes`
/// calls. `ok_writes: 0` is the unconditional form (the first write
/// fails); a positive figure lets the record's opening lines land
/// and fails a LATER one, which is what tells "the call stopped at
/// the first failure" apart from "the call never wrote anything".
struct FailingSink {
    ok_writes: usize,
    accepted: usize,
    refused: usize,
}

impl std::io::Write for FailingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.accepted < self.ok_writes {
            self.accepted += 1;
            return Ok(buf.len());
        }
        self.refused += 1;
        Err(std::io::Error::other("simulated stdout write failure"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A stdout write that fails must not read as a success: the
/// summary and its advisories share one fallible path, so the
/// FIRST failing write on `out` turns the whole call into
/// [`ExitCode::FAILURE`] with a best-effort stderr note naming the
/// seq — the remote publish this reports on already landed and is
/// not undone by a local print failing.
///
/// Two rows, because the unconditional sink alone cannot see the
/// property: a call that gave up before writing anything at all
/// produces the identical outcome. The second row lets two writes
/// land and fails the third, so the assertions below hold for a
/// failure that arrives MID-record.
///
/// The stderr note is an `error:`, not a `warning:` — the exit is
/// FAILURE, and a log filter reads severity off the prefix. The two
/// advisories `report_publish` can also print are warnings because
/// the command still succeeds through them.
#[test]
fn report_publish_fails_rather_than_report_a_truncated_record() {
    let volume = vol("report-publish-test");
    let summary = dummy_publish_summary(true);

    for ok_writes in [0, 2] {
        let mut sink = FailingSink {
            ok_writes,
            accepted: 0,
            refused: 0,
        };
        let mut err = Vec::new();
        let code = report_publish(&volume, &summary, false, &mut sink, &mut err);
        assert_eq!(
            code,
            ExitCode::FAILURE,
            "a truncated record must not report SUCCESS (ok_writes {ok_writes})"
        );
        assert_eq!(
            sink.accepted, ok_writes,
            "control: the record must actually reach the {ok_writes}th write, or this row \
             is testing the unconditional case again"
        );
        assert_eq!(
            sink.refused, 1,
            "the call must stop at the FIRST failing write — a second refusal means it \
             carried on writing a record it already knows is truncated"
        );
        let err_text = String::from_utf8_lossy(&err);
        assert!(
            err_text.contains(&format!("seq {}", summary.seq)),
            "the failure note must name the seq the publish landed at, got: {err_text}"
        );
        assert!(
            err_text.contains("gran publish: error: stdout write failed"),
            "the note is an error, not a warning — the exit is FAILURE, got: {err_text}"
        );
    }
}

/// **The CLI's help is held to the same honest-guarantee rule as the
/// runtime warning**, stated explicitly: neither the
/// CLI's help nor its output may claim signature verification on
/// the no-key path.
///
/// It was correct and unreadable — an inline `eprintln!` literal in
/// [`usage`], which no assertion could reach. Hoisting it to
/// [`CAT_HELP`] is what lets the same table run over it, and
/// [`usage_text`] is what keeps the hoisted const from becoming a
/// second text nobody is shown.
#[test]
fn the_cat_help_claims_no_more_than_either_mode_delivers() {
    for forbidden in OVERCLAIMS {
        assert!(
            !CAT_HELP.contains(forbidden),
            "the help must not claim {forbidden:?}, got: {CAT_HELP}"
        );
    }
    // Positive control: a table run over the wrong text passes
    // every row above.
    assert!(
        CAT_HELP.contains("--root-key") && CAT_HELP.contains("SIGNATURE"),
        "this row did not read the help it is judging: {CAT_HELP}"
    );
    // And it says the two things the no-key mode has to say — what
    // is checked, and that neither mode speaks to freshness.
    assert!(
        CAT_HELP.contains("SOME writer"),
        "the no-key mode must be named as integrity, not authenticity: {CAT_HELP}"
    );
    assert!(
        CAT_HELP.contains("newest"),
        "and neither mode may leave freshness unspoken: {CAT_HELP}"
    );
    // The const is what an operator actually sees.
    assert!(
        usage_text().contains(CAT_HELP),
        "a help const that `usage` does not print is a second text nobody reads"
    );
}

/// **The `--cache-dir` help text names what a degraded
/// read IS — a possibly-stale read served from the cache, always
/// announced — and must not claim freshness or verification for it.**
/// `OVERCLAIMS` already scans the whole const for the forbidden
/// words (including "hash-verified", which trips "verified"); this
/// row is the POSITIVE half that a table of absences alone cannot
/// give: a help text that mentions `--cache-dir` nowhere at all would
/// pass every negative row above just as well as this one's text
/// does.
#[test]
fn the_cat_help_names_cache_dir_and_says_what_a_degraded_read_is() {
    assert!(CAT_HELP.contains("--cache-dir"), "got: {CAT_HELP}");
    assert!(
        CAT_HELP.contains("re-hashed on read"),
        "content and structure are still checked on a degraded serve — the help must \
         say so without the banned word \"verified\": {CAT_HELP}"
    );
    assert!(
        CAT_HELP.contains("possibly stale"),
        "a degraded serve is never claimed fresh: {CAT_HELP}"
    );
    assert!(
        CAT_HELP.contains("announced") && CAT_HELP.contains("stderr"),
        "and it must say the serve is ALWAYS announced, not silent: {CAT_HELP}"
    );
    // The keyed/keyless asymmetry, restated where an operator reads it: a
    // cache dir is bound to one trust configuration, so mixing keyed
    // and keyless invocations against the same directory is refused
    // rather than silently mixed.
    assert!(
        CAT_HELP
            .to_ascii_lowercase()
            .contains("trust configuration"),
        "the help must say a cache dir is bound to one trust configuration \
         — keyed and keyless invocations cannot share it: {CAT_HELP}"
    );
    assert!(
        usage_text().contains("--cache-dir"),
        "a flag `usage` does not print is a flag nobody finds"
    );
}

/// `gran cat <volume> <path> --endpoint <url> --pin <pin>` with
/// `extra` appended.
fn cat_argv(extra: &[&str]) -> Vec<OsString> {
    let mut v = vec![osstr("vol"), osstr("dir/file.txt")];
    v.extend([osstr("--endpoint"), osstr("https://example.test")]);
    v.extend(extra.iter().map(|s| osstr(s)));
    v
}

/// The same trio, again, on `gran cat`.
#[test]
fn cat_parses_the_wire_snapshot_trio_when_all_three_are_given() {
    let parsed = parse_cat(&cat_argv(&[
        "--pin",
        &a_pin(),
        "--wire-snapshot",
        "/tmp/snap.json",
        "--wire-run-id",
        "run-1",
        "--wire-role",
        "client-1",
    ]))
    .unwrap_or_else(|e| panic!("{e}"));
    let wire = parsed.wire.expect("all three given");
    assert_eq!(wire.path, PathBuf::from("/tmp/snap.json"));
    assert_eq!(wire.run_id, "run-1");
    assert_eq!(wire.role, "client-1");
}

/// A PARTIAL trio is refused on `gran cat` too.
#[test]
fn cat_refuses_a_partial_wire_snapshot_trio() {
    let err = parse_cat(&cat_argv(&["--pin", &a_pin(), "--wire-role", "client-1"]))
        .expect_err("role given, path and run-id absent");
    assert!(
        err.contains("--wire-snapshot") && err.contains("--wire-run-id"),
        "got: {err}"
    );
}

/// **A role VALUE outside the closed vocabulary is refused by
/// `gran cat`.** All three flags are present, but `"clientt-1"`
/// is a misspelled role outside that vocabulary: refused at parse
/// time, before `gran cat` reads anything.
#[test]
fn cat_refuses_a_bad_role_value_before_doing_any_work() {
    let err = parse_cat(&cat_argv(&[
        "--pin",
        &a_pin(),
        "--wire-snapshot",
        "/tmp/snap.json",
        "--wire-run-id",
        "run-1",
        "--wire-role",
        "clientt-1",
    ]))
    .expect_err("clientt-1 is not in the closed role vocabulary");
    assert!(
        err.contains("vocabulary"),
        "the refusal must be traceable to SnapshotError::UnknownRole specifically \
         (its Display text is the only one of the four value-refusal variants that \
         contains \"vocabulary\"), not merely to SOME value error, got: {err}"
    );
}

/// The transport is REQUIRED and so is the endpoint: cat has no
/// second route, so a missing value selects nothing and must be
/// refused by name rather than defaulted.
#[test]
fn parse_cat_requires_an_endpoint_and_a_pin() {
    let err = parse_cat(&cat_argv(&[])).expect_err("no pin is no transport");
    assert!(err.contains("--pin"), "got: {err}");
    // And it NAMES the variable it does not read. An operator with
    // `GRANARY_TLS_PINS` exported for their publishes reads "is
    // required" as "is missing" and goes debugging the value they
    // already set; the refusal has to say the value is ignored here.
    assert!(
        err.contains(ENV_TLS_PINS) && err.contains("NOT read"),
        "the refusal must name the variable it deliberately ignores, got: {err}"
    );

    let err = parse_cat(&[osstr("vol"), osstr("f"), osstr("--pin"), osstr(&a_pin())])
        .expect_err("no endpoint is nowhere to read from");
    assert!(err.contains("--endpoint"), "got: {err}");

    // And two positionals are required, no more and no fewer.
    let err = parse_cat(&[osstr("vol"), osstr("--pin"), osstr(&a_pin())])
        .expect_err("a path is required");
    assert!(err.contains("positional"), "got: {err}");
}

/// **`--endpoint` and `--root-key` are LAST-WINS; `--pin`
/// ACCUMULATES.** The asymmetry is deliberate and is stated in
/// `parse_cat`'s own doc: each of the first two names ONE thing, so
/// a repeat is a correction, while a pin set is a SET and a second
/// `--pin` naming the backup must not evict the primary.
#[test]
fn parse_cat_last_wins_for_single_valued_flags_and_accumulates_pins() {
    let second = format!("sha256/{}", granary_net::b64::encode_pin(&[0xCD_u8; 32]));
    let key_a = format!("ed25519:{}", "ab".repeat(32));
    let key_b = format!("ed25519:{}", "cd".repeat(32));
    let parsed = parse_cat(&cat_argv(&[
        "--pin",
        &a_pin(),
        "--pin",
        &second,
        "--root-key",
        &key_a,
        "--root-key",
        &key_b,
        "--endpoint",
        "https://later.test",
    ]))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        parsed.tls_pins.as_slice(),
        &[[0xAB_u8; 32], [0xCD_u8; 32]],
        "the backup slot must not evict the primary"
    );
    assert_eq!(
        parsed.root_key,
        Some([0xCD_u8; 32]),
        "the LAST --root-key wins — one anchor, and a repeat is a correction"
    );
    assert_eq!(
        parsed.endpoint, "https://later.test",
        "the LAST --endpoint wins"
    );
}

/// A mistyped flag is REFUSED, never ignored. `--root-keys` silently
/// dropped is a read with no signature check by an operator who
/// believes they asked for one.
#[test]
fn parse_cat_refuses_an_unknown_flag() {
    let err = parse_cat(&cat_argv(&["--pin", &a_pin(), "--root-keys", "x"]))
        .expect_err("a mistyped flag must not be ignored");
    assert!(err.contains("unknown flag"), "got: {err}");
    assert!(err.contains("--root-keys"), "and must name it, got: {err}");
}

// ---------------------------------------------------------- parse_verify

#[test]
fn parse_verify_accepts_exactly_one_positional() {
    let root = parse_verify(&[OsString::from("/some/root")]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(root, PathBuf::from("/some/root"));
}

#[test]
fn parse_verify_refuses_zero_positionals() {
    let err = parse_verify(&[]).expect_err("no root at all must be refused");
    assert!(err.contains("expected 1 positional"), "got: {err}");
}

#[test]
fn parse_verify_refuses_extra_positionals() {
    let err = parse_verify(&[OsString::from("a"), OsString::from("b")])
        .expect_err("a second positional (endpoint/pins) must be refused");
    assert!(err.contains("expected 1 positional"), "got: {err}");
}

/// verify never touches the network — no `--endpoint`/`--pin`, and
/// an unknown flag is refused rather than silently ignored, on
/// `parse_cat`'s own precedent.
#[test]
fn parse_verify_refuses_an_unknown_flag() {
    let err = parse_verify(&[OsString::from("--endpoint"), OsString::from("x")])
        .expect_err("verify takes no flags at all");
    assert!(err.contains("unknown flag"), "got: {err}");
    assert!(err.contains("--endpoint"), "and must name it, got: {err}");
}

#[test]
fn the_verify_help_tells_an_operator_that_nothing_is_repaired() {
    let text = usage_text();
    assert!(
        text.contains("gran verify"),
        "the usage text must show the verb"
    );
    assert!(
        text.contains("STORE mode") && text.contains("CACHE mode"),
        "both root types must be named"
    );
    // The help must say that verification repairs nothing and
    // leaves corrupt objects on disk.
    assert!(
        text.contains("REPAIRS NOTHING"),
        "the help must say plainly that verify does not repair: {text}"
    );
    assert!(
        text.contains("LEFT ON DISK"),
        "and must say what happens to a corrupt object instead: {text}"
    );
    assert!(
        !text.contains("DELETES"),
        "no surviving claim that verify deletes anything: {text}"
    );
    // C19: the index comparison is CONDITIONAL, and an operator who
    // reads a missing `dropped` line as a healthy index has been
    // misled by a help text that promised the comparison always
    // runs.
    assert!(
        text.contains("trustworthy"),
        "the help must qualify when the index comparison happens: {text}"
    );
}

/// `--root-key` runs through the SHIPPED `parse_signing_key`, not a
/// second parser written here. The `keyid:` row is the load-bearing
/// one (§9a): a locator is not a key, and a reader configured with
/// one can check no signature at all while every rejection-only test
/// still passes.
#[test]
fn parse_cat_root_key_reuses_the_shipped_parser() {
    for bad in [
        "keyid:ababababababababababababababababababababababababababababababababab",
        "sha256/9cvkMbAwLn9O0YZS/Gm+J7KptTwLK+jY+u5x0eCHPZE=",
        &"ab".repeat(32),
        &format!("ed25519:{}", "AB".repeat(32)),
        "ed25519:abcd",
    ] {
        let err = parse_cat(&cat_argv(&["--pin", &a_pin(), "--root-key", bad]))
            .expect_err("only `ed25519:` + 64 lowercase hex is a key");
        assert!(err.contains("--root-key"), "got: {err}");
    }
}

// ------------------------------------------- `--seq N`

/// **`--seq` is ABSENT by default and last-wins when given.**
///
/// The default half is the load-bearing one: this
/// flag must never engage by itself,
/// so an invocation that does not name it must carry no seq at all
/// — not a defaulted one, and not one recovered from a failure.
#[test]
fn parse_cat_seq_is_absent_by_default_and_last_wins() {
    let none = parse_cat(&cat_argv(&["--pin", &a_pin()])).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        none.seq, None,
        "no --seq must stay the head path, with no seq of its own"
    );
    let parsed = parse_cat(&cat_argv(&["--pin", &a_pin(), "--seq", "7", "--seq", "9"]))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        parsed.seq,
        Some(9),
        "the LAST --seq wins — it names ONE seq, so a repeat is a correction"
    );
}

/// **Seq 0 and seq `u64::MAX` are refused AT THE CLI, by name.**
///
/// Both are excluded from head selection everywhere else in the
/// tree: `root.rs` refuses 0 at encode AND
/// decode, so no root can exist there at all; `u64::MAX` is
/// reserved — it may hold a root and can never be a head,
/// so no conforming publisher writes one. Letting either through
/// would make this the one client path that asks for a seq the rest
/// of the system has ruled out, and the answer would arrive as a
/// `decode_root` complaint or as a bare absence — neither of which
/// names the reason.
#[test]
fn parse_cat_refuses_the_two_reserved_seqs() {
    for (bad, why) in [("0", "seq 0"), ("18446744073709551615", "reserved")] {
        let err = parse_cat(&cat_argv(&["--pin", &a_pin(), "--seq", bad]))
            .expect_err("neither end of the range can be a head");
        assert!(
            err.contains("--seq"),
            "the refusal must name the flag, got: {err}"
        );
        assert!(err.contains(why), "and must say why, got: {err}");
    }
    // POSITIVE CONTROL: the seq immediately inside each refusal is
    // ACCEPTED. Without this the two rows above cannot tell a bound
    // from a flag that refuses everything.
    for (good, want) in [("1", 1_u64), ("18446744073709551614", u64::MAX - 1)] {
        let parsed = parse_cat(&cat_argv(&["--pin", &a_pin(), "--seq", good]))
            .unwrap_or_else(|e| panic!("{good} is inside the usable range: {e}"));
        assert_eq!(parsed.seq, Some(want), "{good} must parse");
    }
}

/// **The value is a PLAIN DECIMAL, and the accept set is DECIDED
/// rather than inherited from `u64::from_str`.**
///
/// `from_str` accepts a leading `+`, which is a second spelling of a
/// seq for no gain; the ASCII-digit guard in [`parse_cat`] removes
/// it. Leading ZEROS are deliberately kept — that is the exact form
/// of the bucket key and of the `max-seq`/`hint` bodies, so an
/// operator who copied a seq out of the store gets the read they
/// meant. Nothing on this path is hashed or signed, so two
/// spellings of one number cost nothing here.
#[test]
fn parse_cat_refuses_a_seq_that_is_not_a_plain_decimal() {
    for bad in [
        "",
        "abc",
        "1e3",
        "0x10",
        " 1",
        "1 ",
        "+1",
        "-1",
        "1_000",
        "\u{0661}",
        "18446744073709551616",
        "999999999999999999999999999",
    ] {
        let err = parse_cat(&cat_argv(&["--pin", &a_pin(), "--seq", bad]))
            .expect_err("only a plain decimal seq is a seq");
        assert!(
            err.contains("--seq"),
            "the refusal must name the flag, got: {err}"
        );
    }
    // POSITIVE CONTROL, and the leading-zero decision made visible:
    // the 20-digit zero-padded WIRE spelling of seq 1 names the same
    // seq as `1`.
    let padded = parse_cat(&cat_argv(&[
        "--pin",
        &a_pin(),
        "--seq",
        "00000000000000000001",
    ]))
    .unwrap_or_else(|e| panic!("the zero-padded key form is the same seq: {e}"));
    assert_eq!(padded.seq, Some(1));
}

/// **"no root at the seq you named" and "this volume has no head"
/// are different answers and must not share a message.**
///
/// Both entry points answer `NoHead`, and the default path's text is
/// load-bearing — it is what a legitimately unpublished volume says
/// — so the distinguishing has to happen where the seq is known: at
/// the call site, never in the shared `Display`.
#[test]
fn a_missing_root_at_a_named_seq_reads_differently_from_an_empty_volume() {
    let head = cat_resolve_message(None, &ResolveError::NoHead);
    assert_eq!(
        head,
        ResolveError::NoHead.to_string(),
        "the default path's text is EXACTLY as it was"
    );
    let at = cat_resolve_message(Some(7), &ResolveError::NoHead);
    assert_ne!(head, at, "the two absences must not read alike");
    assert!(
        at.contains("seq 7"),
        "and must name the seq asked for: {at}"
    );
    assert!(at.contains("--seq"), "and the flag that asked for it: {at}");
    // Every OTHER variant is the same failure whichever entry point
    // produced it, so the seq must not repaint those.
    let broken = ResolveError::Mismatch {
        what: "seq",
        key: "3".to_owned(),
        doc: "4".to_owned(),
    };
    assert_eq!(
        cat_resolve_message(None, &broken),
        cat_resolve_message(Some(3), &broken),
        "only the ABSENCE means something different under --seq"
    );
}

/// The help an operator is shown names the flag, and says the one
/// condition the flag's safety depends on: it is MANUAL.
#[test]
fn the_cat_help_names_the_seq_flag_and_says_it_is_manual() {
    assert!(CAT_HELP.contains("--seq"), "got: {CAT_HELP}");
    // POSITIVE: the help states the flag is operator-driven.
    assert!(
        CAT_HELP.contains("manual"),
        "the help must say the flag is MANUAL: {CAT_HELP}"
    );
    // NEGATIVE, and this half is the one that matters.
    // An assertion that a phrase is PRESENT cannot police what else
    // the sentence says, so the absence is asserted too. This is the
    // only row guarding the property the whole design rests on;
    // `OVERCLAIMS` does not reach it.
    for banned in [
        "automatic",
        "automatically",
        "falls back",
        "fallback",
        "if the head",
    ] {
        assert!(
            !CAT_HELP.to_ascii_lowercase().contains(banned),
            "the help must not advertise an automatic fallback ({banned:?} present) — \
             automatic walk-down after a head failure is forbidden, and `cat_resolve` \
             chooses before the first request: {CAT_HELP}"
        );
    }
    assert!(
        usage_text().contains("--seq"),
        "a flag `usage` does not print is a flag nobody finds"
    );
}

/// The bytes the planted-root recovery test publishes and reads back. Small on
/// purpose: that row is about WHICH root is resolved, not about the
/// chunker.
const HONEST_HEAD_BYTES: &[u8] = b"the honest head's bytes, one seq below the planted one\n";

/// `gran cat`'s two steps — resolve at the selected entry point,
/// then walk one name out of the tree — with the resolve failure
/// rendered exactly as [`cmd_cat`] renders it.
async fn cat_read_bytes<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    seq: Option<u64>,
    verifier: &RootVerifier,
    name: &str,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    cat_resolve(
        remote,
        volume,
        seq,
        verifier,
        None,
        &cat_path(name),
        &mut out,
    )
    .await
    .map_err(|e| cat_resolve_message(seq, &e))?;
    Ok(out)
}

/// **THE MOTIVATING SCENARIO, end to end.**
///
/// An unauthenticated peer plants one object at a free seq above the
/// head. `max_seq` then answers the planted seq and the head path
/// hard-fails — the volume is unreadable through `gran cat` even
/// though the honest head is intact one seq below. `--seq <honest
/// head>` is the in-band escape hatch, and this row is what proves
/// it does its job: the same bytes, byte for byte, out of a volume
/// the default path can no longer read.
///
/// **Why the row is HERE.** `publish_inmemory.rs` consumes the LIB,
/// and the library half — `resolve_at` — is not what this row tests.
/// The capability under test is the SELECTION, which lives in this
/// binary, so a row driving the
/// library would pass with the flag unshipped. It does not belong at
/// `harvest_integration.rs`'s level either: driving the compiled
/// binary needs a pinned TLS endpoint, which would put the transport
/// in the way of the thing under test.
#[tokio::test]
async fn seq_reads_the_honest_head_of_a_volume_a_planted_root_denied() {
    let dir = ScratchDir::new();
    let source = dir.0.join("source");
    let store_dir = dir.0.join("store");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(source.join("f.txt"), HONEST_HEAD_BYTES).unwrap_or_else(|e| panic!("{e}"));

    let mem = Arc::new(InMemory::new());
    let remote = GranaryStore::new(Arc::clone(&mem));
    let (key, _seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let volume = vol("cat-seq-planted-root");
    let identity = WriterIdentity::from_bytes(*b"cat-seq-testing!");
    let store = Store::open(&store_dir).unwrap_or_else(|e| panic!("{e}"));
    let summary = publish(
        &remote,
        &store,
        &source,
        &volume,
        &key,
        &identity,
        Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        },
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(summary.seq, 1, "the honest head is seq 1");
    drop(store);

    let verifier = RootVerifier::trusting(*key.public_key()).unwrap_or_else(|e| panic!("{e}"));
    let vol = volume.as_str();

    // POSITIVE CONTROL 1: on a HEALTHY volume the two paths agree,
    // and both produce the source bytes.
    let by_head = cat_read_bytes(&remote, vol, None, &verifier, "f.txt")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        by_head.as_slice(),
        HONEST_HEAD_BYTES,
        "the head path reads the file"
    );
    let by_seq = cat_read_bytes(&remote, vol, Some(1), &verifier, "f.txt")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        by_seq, by_head,
        "--seq at the actual head is the same read, byte for byte"
    );

    // THE ATTACK: one unauthenticated `PUT root` of junk at the free
    // seq above the head. Nothing on the write path refuses it,
    // and `max_seq` now answers 2.
    remote
        .put_root(vol, 2, b"not a root at all".to_vec())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let denied = cat_read_bytes(&remote, vol, None, &verifier, "f.txt")
        .await
        .expect_err("the head path is exactly what a planted root denies");
    assert!(
        !denied.contains("has no head"),
        "the volume HAS a head; the denial is a BROKEN one, got: {denied}"
    );
    // **That `expect_err` IS the no-silent-fallback property**, read
    // under the exact condition a fallback would fire: the default
    // path errors on a poisoned head rather than quietly serving the
    // honest one below it. An automatic walk-down
    // would have returned `by_head` right there, and
    // nothing else in this file would have noticed.
    assert!(
        denied.contains("decode root"),
        "the head path must report the PLANTED root, never read past it: {denied}"
    );

    // THE FEATURE: the honest head is still readable, and identical.
    let recovered = cat_read_bytes(&remote, vol, Some(1), &verifier, "f.txt")
        .await
        .unwrap_or_else(|e| panic!("--seq is the in-band escape hatch: {e}"));
    assert_eq!(
        recovered, by_head,
        "--seq <honest head> returns byte-identical content under the attack"
    );

    // And an UNOCCUPIED seq is a clear, distinguishable refusal —
    // not the empty-volume message, on a volume holding two roots.
    let empty = cat_read_bytes(&remote, vol, Some(3), &verifier, "f.txt")
        .await
        .expect_err("nothing is stored at seq 3");
    assert!(empty.contains("seq 3"), "got: {empty}");
    assert!(
        !empty.contains("the volume has no head"),
        "an unoccupied seq is not an unpublished volume, got: {empty}"
    );
}

/// **`cmd_cat` resolves through the VERIFYING entry point.**
///
/// `resolve_head` and `resolve_head_verified` differ by one argument
/// and are observably identical on every volume whose head the
/// configured key signed — so a call site that swapped one for the
/// other would leave `--root-key` parsed, the verifier built, the
/// warning suppressed, and NOTHING checked, with every row in this
/// file still green. That is the "a gate the caller can opt out of
/// is not a gate" shape, and the only place it is visible is the
/// call site.
///
/// A source scan for the same reason the deadline row uses one: the
/// arm needs a live peer. Needles assembled so this row's own text
/// matches neither — belt and braces, because [`production_source`]
/// reads a different FILE (`main.rs`) from the one this row is written
/// in.
#[test]
fn cat_resolves_through_the_verifying_entry_point() {
    let production = production_source();
    let verifying = ["resolve_head", "_verified("].concat();
    let bare = ["resolve_head", "("].concat();
    assert_eq!(
        production.matches(&verifying).count(),
        1,
        "cat resolves through resolve_head_verified, exactly once"
    );
    assert_eq!(
        production.matches(&bare).count(),
        0,
        "and never through the unverified one, which would silently discard \
         --root-key while every other row stayed green"
    );
    // `--seq` has the SAME pair and the same trap: `resolve_at` and
    // `resolve_at_verified` differ by one argument and agree on
    // every volume whose root the configured key signed, so an
    // escape hatch wired to the bare one would read a planted root
    // with `--root-key` on the command line and nothing checked.
    let verifying_at = ["resolve_at", "_verified("].concat();
    let bare_at = ["resolve_at", "("].concat();
    assert_eq!(
        production.matches(&verifying_at).count(),
        1,
        "--seq resolves through resolve_at_verified, exactly once"
    );
    assert_eq!(
        production.matches(&bare_at).count(),
        0,
        "and never through the unverified one — the escape hatch must not be \
         the one read in this binary that skips the anchor"
    );
}

// ---------------------------- the walk's arms no fixture reached
//
// Ten rows closing gaps a mutation sweep found: each one names a
// mutant that stayed GREEN against the whole suite, and each was
// confirmed to flip that mutant RED. They are grouped here rather
// than folded into the rows above because what they have in common
// is not a subject — it is that the ACCEPT side of the suite could
// not tell the two behaviours apart.

pub(crate) fn root_key_str() -> String {
    format!("ed25519:{}", "ab".repeat(32))
}

/// In the mutation sweep, `cmd_mount_gran`'s own body was
/// EXECUTED replaced with `let _ = args; mount_exit_code(MountOutcome::
/// Clean)` — the `/sbin/mount.gran` machine-wide entry point ignoring
/// its operands and reporting success unconditionally — and the
/// suite stayed green: nothing had ever called `cmd_mount_gran`
/// itself. A mountpoint that does not exist is enough to prove real
/// forwarding: `cmd_mount`'s own pre-flight `NotFound` refusal is
/// reached only if `parse_mount_gran`'s translation genuinely ran
/// AND its result was genuinely handed to `cmd_mount`.
///
/// **On a feature-on build** this exact mount.gran
/// invocation does not REACH pre-flight: `mount_attempt_
/// with_credentials`'s `BreakageRequired` check fires FIRST,
/// unconditionally, because `parse_mount_gran`
/// has NO way to arm `breakage`: re-adding an `-o breakage=`
/// vocabulary is forbidden — its absence is not an
/// oversight here, it is the point. The `assert_eq!` below still
/// passes on a feature-on build, but for a DIFFERENT reason than
/// its own name/doc claims — the same "passes without reaching its
/// own named behaviour" class also found in the two sibling
/// tests. Unlike those two, this one CANNOT be armed the
/// same way (there is nothing to pass `--breakage` to on the
/// mount.gran path), so this test adds a SEPARATE, PRECISE
/// assertion for the feature-on case: it does not settle for
/// "some refusal happened" (which `cmd_mount_gran`'s own `ExitCode`
/// return type cannot distinguish anyway) — it re-derives `margs`
/// through the SAME `parse_mount_gran` call `cmd_mount_gran` itself
/// makes, and checks that `mount_attempt_with_credentials` answers
/// EXACTLY `BreakageRequired`, ruling out a wiring skip that
/// happened to still land on SOME other RuntimeFailure-mapped
/// refusal by coincidence.
#[test]
fn cmd_mount_gran_forwards_a_parsed_invocation_into_cmd_mount() {
    let dir = MountScratchDir::new();
    let missing = dir.0.join("does-not-exist");
    let key = root_key_str();
    let pin = a_pin();
    let args: Vec<OsString> = vec![
        osstr("vol"),
        OsString::from(missing.as_os_str()),
        osstr("-o"),
        osstr(&format!(
            "endpoint=https://h,pin={pin},root_key={key},foreground"
        )),
    ];
    assert_eq!(
        cmd_mount_gran(&args, &mut Vec::new()),
        mount_exit_code(MountOutcome::RuntimeFailure),
        "a successfully parsed mount.gran invocation must reach cmd_mount's own refusal, \
         never report success without ever calling it"
    );
    #[cfg(feature = "conformance-breakage")]
    {
        let margs = parse_mount_gran(&args).unwrap_or_else(|e| panic!("{e}"));
        let credentials = process_credentials();
        assert!(
            matches!(
                mount_attempt_with_credentials(
                    &margs,
                    &credentials,
                    &mut Vec::new(),
                    &crate::terminal::write_line
                ),
                Err(MountRefusal::BreakageRequired)
            ),
            "on a feature build, mount.gran forwarding must be provable PRECISELY: \
             parse_mount_gran can never arm breakage, so mount_attempt_with_credentials \
             must refuse with BreakageRequired specifically, not merely \"some\" refusal"
        );
    }
}

/// The OTHER half of the same mutation: replacing the whole function
/// body ALSO replaces the parse-failure arm, so a malformed
/// invocation would have reported 0 (`Clean`) too, not `usage()`'s
/// exit 2. `parse_mount_gran`'s own tests already prove the parser
/// itself refuses this; this proves `cmd_mount_gran` still turns
/// that refusal into the right exit code rather than swallowing it.
#[test]
fn cmd_mount_gran_reports_usage_on_an_unparseable_invocation() {
    let args: Vec<OsString> = vec![osstr("only-one-positional")];
    assert_eq!(cmd_mount_gran(&args, &mut Vec::new()), usage());
}

#[test]
fn usage_text_includes_mount_help() {
    // The same "never printed is never called" property CAT_HELP's
    // own doc comment names, pinned for MOUNT_HELP too.
    assert!(usage_text().contains(MOUNT_HELP));
    assert!(usage_text().contains("gran umount <mountpoint>"));
}

// ------------------------------------- set-ID refusals for harvest, thresh, verify and cat

/// A credential snapshot that `set_id_refusal` must reject, and one it must
/// accept. Paired, because a refusal test whose only assertion is "it failed"
/// cannot tell the new refusal from every other way the command can fail —
/// which is the reading `cmd_umount_with_credentials_refuses_set_id_execution`
/// already insists on, and the exact defect class this repository has recorded
/// as "the right code for the wrong reason".
fn mismatched_uid() -> ProcessCredentials {
    ProcessCredentials {
        ruid: 1_000,
        euid: 1_001,
        rgid: 2_000,
        egid: 2_000,
        set_id_tainted: false,
    }
}

/// The TAINT-ONLY condition: every visible id matches and the platform probe
/// still says the process entered through set-ID handling. On Linux that is
/// `AT_SECURE`, which also reports gained file capabilities.
///
/// **It gets its own fixture because without it every row here is satisfied by
/// a bare uid comparison.** `set_id_refusal` has three firing conditions, and
/// a suite that drove only one would let a refusal rewritten as
/// `ruid != euid` keep it green while admitting the entry
/// with equal IDs but set-ID taint.
fn tainted_only() -> ProcessCredentials {
    ProcessCredentials {
        ruid: 1_000,
        euid: 1_000,
        rgid: 2_000,
        egid: 2_000,
        set_id_tainted: true,
    }
}

fn credentials_that_pass() -> ProcessCredentials {
    ProcessCredentials {
        ruid: 1_000,
        euid: 1_000,
        rgid: 2_000,
        egid: 2_000,
        set_id_tainted: false,
    }
}

/// `gran harvest` refuses a set-ID invocation BEFORE it opens the
/// store. The store directory not existing afterwards is the decisive half:
/// an exit code alone is satisfied by every other failure this command has,
/// whereas `Store::open` creates its structural directories and a lock file,
/// so "the store was never created" is the refusal's own footprint.
#[test]
fn cmd_harvest_refuses_set_id_execution_before_opening_the_store() {
    let scratch = ScratchDir::new();
    let source = scratch.0.join("src");
    let store = scratch.0.join("store");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(source.join("a"), b"hello").unwrap_or_else(|e| panic!("{e}"));

    let mut err = Vec::new();
    let code = cmd_harvest_with_credentials(&source, &store, &mismatched_uid(), &mut err);
    assert_eq!(
        code,
        ExitCode::FAILURE,
        "a set-ID gran harvest must fail, never reach Store::open"
    );
    assert!(
        !store.exists(),
        "the refusal must precede Store::open, which creates the store directory"
    );
    // The MESSAGE, not just the code: FAILURE is what every other harvest
    // failure returns too, so without this a deleted `writeln!` is silent.
    let message = String::from_utf8_lossy(&err);
    assert!(
        message.contains("real uid 1000 differs from effective uid 1001"),
        "the sink must name the set-ID condition that fired: {message}"
    );

    // And the TAINT-ONLY condition, on the same fixture.
    let scratch2 = ScratchDir::new();
    let source2 = scratch2.0.join("src");
    let store2 = scratch2.0.join("store");
    std::fs::create_dir_all(&source2).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(source2.join("a"), b"hello").unwrap_or_else(|e| panic!("{e}"));
    let mut err2 = Vec::new();
    assert_eq!(
        cmd_harvest_with_credentials(&source2, &store2, &tainted_only(), &mut err2),
        ExitCode::FAILURE,
        "a taint-only snapshot must refuse too — every id matches in it"
    );
    assert!(!store2.exists());
    assert!(
        String::from_utf8_lossy(&err2).contains("set_id_tainted=true"),
        "the taint condition must be the one named"
    );
}

/// The POSITIVE CONTROL for the row above, and without it that row is
/// satisfied by a `cmd_harvest` that refuses everything. Same fixture, same
/// paths, only the credentials differ — so the store's existence is
/// attributable to nothing else.
#[test]
fn cmd_harvest_under_ordinary_credentials_still_opens_the_store() {
    let scratch = ScratchDir::new();
    let source = scratch.0.join("src");
    let store = scratch.0.join("store");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(source.join("a"), b"hello").unwrap_or_else(|e| panic!("{e}"));

    let _ = cmd_harvest_with_credentials(
        &source,
        &store,
        &credentials_that_pass(),
        &mut std::io::sink(),
    );
    assert!(
        store.exists(),
        "ordinary credentials must not be refused — the store is created as before"
    );
}

/// `gran thresh` refuses a set-ID invocation before it canonicalizes
/// or opens its argument. The `#[expect(clippy::disallowed_methods)]` on that
/// `canonicalize` is justified by the argument being "the operator's own
/// command-line path", and under set-ID the operator and the effective
/// principal are not the same principal.
#[test]
fn cmd_thresh_refuses_set_id_execution() {
    let scratch = ScratchDir::new();
    let path = scratch.0.join("grains.bin");
    std::fs::write(&path, b"not a real bin").unwrap_or_else(|e| panic!("{e}"));

    let mut err = Vec::new();
    assert_eq!(
        cmd_thresh_with_credentials(&path, &mismatched_uid(), &mut err),
        ExitCode::FAILURE,
        "a set-ID gran thresh must fail before it resolves its argument"
    );
    assert!(
        String::from_utf8_lossy(&err).contains("real uid 1000 differs from effective uid 1001"),
        "the sink must name the condition that fired"
    );

    let mut err2 = Vec::new();
    assert_eq!(
        cmd_thresh_with_credentials(&path, &tainted_only(), &mut err2),
        ExitCode::FAILURE,
        "the taint-only condition must refuse here too"
    );
    assert!(String::from_utf8_lossy(&err2).contains("set_id_tainted=true"));
}

/// The POSITIVE CONTROL, and the discriminator is exact: `gran thresh` on a
/// readable file it finds no grains in exits **0**. So the pair is 0 under
/// ordinary credentials and FAILURE under set-ID ones, on the identical path —
/// a refusal test whose partner succeeds, rather than one whose partner fails
/// for a second reason and proves nothing.
#[test]
fn cmd_thresh_under_ordinary_credentials_reaches_its_argument() {
    let scratch = ScratchDir::new();
    let present = scratch.0.join("grains.bin");
    std::fs::write(&present, b"not a real bin").unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        cmd_thresh_with_credentials(&present, &credentials_that_pass(), &mut std::io::sink()),
        ExitCode::SUCCESS,
        "ordinary credentials must reach the resolver, which reads this file happily"
    );
}

/// `gran verify` refuses a set-ID invocation before
/// `granary_client::run_verify` opens the store-or-cache root. The refusal
/// exits **2**, joining that entry point's cannot-open class: exit 1 means
/// FINDINGS there, so refusing with 1 would report a corrupt store.
#[test]
fn cmd_verify_refuses_set_id_execution_with_the_cannot_open_code() {
    let scratch = ScratchDir::new();
    let source = scratch.0.join("src");
    let store = scratch.0.join("store");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(source.join("a"), b"hello").unwrap_or_else(|e| panic!("{e}"));
    // A REAL store, so ordinary credentials give 0 here (the row below proves
    // that). An empty directory would give 2 for cannot-open and this row
    // would pass without the refusal existing at all.
    assert_eq!(
        cmd_harvest_with_credentials(
            &source,
            &store,
            &credentials_that_pass(),
            &mut std::io::sink()
        ),
        ExitCode::SUCCESS,
        "fixture: the store must harvest cleanly or this row proves nothing"
    );

    let mut err = Vec::new();
    assert_eq!(
        cmd_verify_with_credentials(&store, &mismatched_uid(), &mut err),
        ExitCode::from(2),
        "a set-ID gran verify must refuse with the cannot-open code, never with 1 (findings)"
    );
    // Exit 2 is shared with usage() and with cannot-open, so the message is
    // what makes this row about the refusal at all.
    assert!(
        String::from_utf8_lossy(&err).contains("real uid 1000 differs from effective uid 1001"),
        "the sink must name the condition that fired"
    );

    let mut err2 = Vec::new();
    assert_eq!(
        cmd_verify_with_credentials(&store, &tainted_only(), &mut err2),
        ExitCode::from(2),
        "the taint-only condition must refuse here too"
    );
    assert!(String::from_utf8_lossy(&err2).contains("set_id_tainted=true"));
}

/// The POSITIVE CONTROL, and it is what makes the row above discriminate. An
/// EMPTY directory is cannot-open, so `run_verify` returns 2 for it — the same
/// 2 the refusal returns, and a pair built on that proves nothing. The store
/// here is REAL, harvested by the command above, so the library returns 0 and
/// the two credentials give different answers on the identical root.
#[test]
fn cmd_verify_under_ordinary_credentials_reaches_the_library() {
    let scratch = ScratchDir::new();
    let source = scratch.0.join("src");
    let store = scratch.0.join("store");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(source.join("a"), b"hello").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cmd_harvest_with_credentials(
            &source,
            &store,
            &credentials_that_pass(),
            &mut std::io::sink()
        ),
        ExitCode::SUCCESS,
        "fixture: the store must harvest cleanly or this row proves nothing"
    );

    assert_eq!(
        cmd_verify_with_credentials(&store, &credentials_that_pass(), &mut std::io::sink()),
        ExitCode::SUCCESS,
        "ordinary credentials must reach run_verify, which finds this store clean"
    );
}

/// `gran cat` refuses a set-ID invocation before it opens the cache.
/// `--cache-dir` is the decisive observable: `Cache::open` creates the
/// directory and a lock file BEFORE any transport is built, which is the
/// ordering `cmd_cat`'s own comment states ("a refusal needing a server is a
/// refusal an unhelpful server can withhold"). So a refusal that fired leaves
/// no cache behind, and one that did not leaves one even though no server is
/// listening.
#[test]
fn cmd_cat_refuses_set_id_execution_before_opening_the_cache() {
    let scratch = ScratchDir::new();
    let cache = scratch.0.join("cache");
    let args = parse_cat(&cat_argv(&[
        "--pin",
        &a_pin(),
        "--cache-dir",
        &cache.to_string_lossy(),
    ]))
    .unwrap_or_else(|e| panic!("{e}"));

    let mut err = String::new();
    let code = cmd_cat_with_credentials(&args, &mismatched_uid(), &mut |message| {
        err.push_str(&message.to_string());
    });
    assert_eq!(
        code,
        ExitCode::FAILURE,
        "a set-ID gran cat must fail, never reach Cache::open"
    );
    assert!(
        !cache.exists(),
        "the refusal must precede Cache::open, which creates the cache directory"
    );
    assert!(
        err.contains("real uid 1000 differs from effective uid 1001"),
        "the sink must name the condition that fired"
    );

    let cache2 = scratch.0.join("cache2");
    let args2 = parse_cat(&cat_argv(&[
        "--pin",
        &a_pin(),
        "--cache-dir",
        &cache2.to_string_lossy(),
    ]))
    .unwrap_or_else(|e| panic!("{e}"));
    let mut err2 = String::new();
    assert_eq!(
        cmd_cat_with_credentials(&args2, &tainted_only(), &mut |message| {
            err2.push_str(&message.to_string());
        }),
        ExitCode::FAILURE,
        "the taint-only condition must refuse here too"
    );
    assert!(!cache2.exists());
    assert!(err2.contains("set_id_tainted=true"));
}

/// The positive control: the identical invocation under ordinary credentials
/// gets past the refusal and DOES create the cache — it still fails, because
/// nothing is listening on the endpoint, but the cache directory is the proof
/// that the failure happened downstream of the refusal rather than at it.
#[test]
fn cmd_cat_under_ordinary_credentials_opens_the_cache_before_the_transport() {
    let scratch = ScratchDir::new();
    let cache = scratch.0.join("cache");
    let args = parse_cat(&cat_argv(&[
        "--pin",
        &a_pin(),
        "--cache-dir",
        &cache.to_string_lossy(),
    ]))
    .unwrap_or_else(|e| panic!("{e}"));

    let _ = cmd_cat_with_credentials(&args, &credentials_that_pass(), &mut |_| {});
    assert!(
        cache.exists(),
        "ordinary credentials must not be refused — the cache is opened as before"
    );
}

// ------------------------------------------- the log filter, built before any writer exists

/// `RUST_LOG` is honoured, and the value the caller passes is the value that
/// decides the filter.
///
/// This row is also the guard against the construction reading the
/// ENVIRONMENT instead of its argument: the test process has no `RUST_LOG`,
/// so an implementation that consults the variable returns the bare default
/// here and the directive below never appears.
#[test]
fn a_well_formed_rust_log_is_honoured_and_complains_about_nothing() {
    let (filter, complaint) = crate::env_filter_from(Ok("granary_client=debug".to_owned()));
    assert_eq!(filter.to_string(), "granary_client=debug");
    assert_eq!(complaint, None, "a valid filter has nothing to report");
}

/// An unset or empty `RUST_LOG` is the INFO default, unchanged, and silent.
///
/// The control for the three rows around it: an empty filter has no complaint
/// to report at all, so a suite that goes green on it alone has established nothing.
#[test]
fn an_unset_rust_log_is_the_info_default_and_complains_about_nothing() {
    let (filter, complaint) = crate::env_filter_from(Ok(String::new()));
    assert_eq!(filter.to_string(), "info");
    assert_eq!(complaint, None);
}

/// A malformed `RUST_LOG` comes back as a closed detail the caller owns, rather than
/// being printed from inside the construction.
///
/// That distinction is what this row pins. The dependency's lossy parser
/// prints the complaint itself, with a bare `eprintln!`, at a point where no
/// subscriber and therefore no writer of ours exists yet — so on a
/// backpressured stderr that print is a synchronous write that blocks the
/// process before `gran mount` reaches a kernel mount.
#[test]
fn a_malformed_rust_log_is_handed_back_as_a_complaint_rather_than_printed() {
    let (_filter, complaint) = crate::env_filter_from(Ok("====".to_owned()));
    let complaint = complaint.expect("a malformed directive owes the operator a report");
    assert!(matches!(complaint, granary_client::FilterDetail::Malformed));
}

/// A malformed directive does not leave its VALID neighbours applied.
///
/// This is the row that separates a strict parse from the lossy one plus a
/// complaint of our own. `parse_lossy` drops only the directives it cannot
/// read and keeps the rest, so `granary_client=debug,====` leaves
/// `granary_client=debug` in force; a strict parse rejects the value whole and
/// runs on the default. An implementation that kept the lossy parser and
/// merely printed its own diagnostic passes every other row here and fails
/// this one.
#[test]
fn a_malformed_directive_does_not_leave_its_valid_neighbours_applied() {
    let (filter, complaint) = crate::env_filter_from(Ok("granary_client=debug,====".to_owned()));
    assert_eq!(
        filter.to_string(),
        "info",
        "a rejected value falls back to the default directive, not to its readable half"
    );
    assert!(complaint.is_some());
}

/// The binary asks no dependency to print a filter complaint on its behalf.
///
/// The three rows above test what the construction RETURNS; this one closes
/// the escape none of them can see — a second, unrelated call site reaching
/// for the lossy parser later. It is a SET of forbidden spellings rather than
/// a shape test, so a new one arrives as an edit a reviewer reads.
///
/// The needles are ASSEMBLED from fragments for the same reason
/// [`production_source`]'s marker is: this row must not match itself if it is
/// ever moved into the file it scans.
#[test]
fn the_cli_asks_no_dependency_to_print_a_filter_complaint_for_it() {
    let production = production_source();
    // FIVE spellings, not two. `EnvFilter::new`, `EnvFilter::from_env` and
    // `EnvFilter::from_default_env` each reach a lossy parser internally —
    // verified in the pinned 0.3.23 source, where the first calls
    // `parse_lossy` and the other two call `from_env_lossy`. Note
    // `EnvFilter::from_env` is a DIFFERENT function from the builder's
    // `from_env`, which is strict: same name, opposite behaviour, and reading
    // only one of them is how this set came to be three short.
    for (head, tail) in [
        ("from_env", "_lossy"),
        ("parse", "_lossy"),
        ("EnvFilter:", ":new"),
        ("EnvFilter:", ":from_env"),
        ("from_default", "_env"),
    ] {
        let needle = format!("{head}{tail}");
        assert!(
            !production.contains(&needle),
            "`{needle}` prints an invalid directive from inside the dependency, \
             before any writer of ours exists"
        );
    }
}

/// A `RUST_LOG` whose bytes are not UTF-8 is reported, not silently ignored.
///
/// The dependency's reader is `env::var(..).unwrap_or_default()`, which maps
/// this case onto the same empty string an UNSET variable produces — so an
/// operator who set the variable gets the default level and no word about
/// why. It is the same silence a malformed directive had, in the one case
/// that never reaches a parser at all.
#[test]
fn a_rust_log_that_is_not_utf8_is_reported_rather_than_read_as_unset() {
    use std::os::unix::ffi::OsStringExt as _;
    let not_utf8 = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
    let (filter, complaint) = crate::env_filter_from(Err(std::env::VarError::NotUnicode(not_utf8)));
    assert_eq!(filter.to_string(), "info");
    let complaint = complaint.expect("a variable that was SET owes the operator a report");
    assert!(matches!(
        complaint,
        granary_client::FilterDetail::NotUnicode
    ));
}

/// The subscriber is installed over the SINK, never over `std::io::stderr`.
///
/// One line in `main` covers the library's whole tracing inventory, so the
/// property is worth a guard rather than a comment: reverting it produces
/// only an `unused variable` warning, and a warning is a weaker coupling than
/// a row that names what must be true.
///
/// The forbidden spelling is a SET, not a shape — a new way to hand the
/// subscriber a blocking destination arrives as an edit a reviewer reads.
#[test]
fn the_subscriber_is_installed_over_the_sink() {
    let production = production_source();
    // No closing paren here either: the sink is `Clone` and `main` hands the
    // installer a clone while keeping one for the mount path, so
    // `log_sink.clone()` is the live spelling and `log_sink` would be
    // another. Both are correct; anchoring on the binding is what this row is
    // actually about. The installer (`logging::install_with_history`) passes that writer
    // to the subscriber builder unchanged, which the second half checks.
    assert!(
        production
            .split_whitespace()
            .collect::<String>()
            .contains("logging::install_with_history(&log_settings,env_filter,log_sink"),
        "`main` must give the subscriber the sink"
    );
    let installer = include_str!("logging.rs");
    let installer = installer
        .split("\n#[cfg(test)]\nmod tests;")
        .next()
        .expect("`logging.rs` ends with its out-of-line tests");
    assert!(
        installer.split_whitespace().collect::<String>().contains("granary_client::closed_subscriber_with_paths(settings.format,filter,writer,settings.paths,history,"),
        "`logging::install_with_history` must hand the subscriber the writer and independent history it was given"
    );
    for (head, tail) in [("std::io::", "stderr"), ("std::io::", "stdout")] {
        // No closing paren: `.with_writer(std::io::stderr)` (the fn item) and
        // `.with_writer(std::io::stderr())` (the value) are the same defect,
        // and a needle ending in `)` matches only the first.
        for (source, needle) in [
            (production, format!(".with_writer({head}{tail}")),
            (production, format!("env_filter, {head}{tail}")),
            (production, format!("env_filter,\n        {head}{tail}")),
            (installer, format!("writer = {head}{tail}")),
            (installer, format!(".with_writer({head}{tail}")),
        ] {
            assert!(
                !source.contains(&needle),
                "`{needle}` hands the subscriber a BLOCKING destination, which is \
                 the synchronous stderr write the sink exists to remove"
            );
        }
    }
}

/// `gran mount` hands the library's `sink` parameter the process's sink, not
/// a blocking handle.
///
/// The library takes `sink` as a parameter. This row checks the CLI's
/// choice of destination at the call site.
///
/// This scans `attach.rs`, which is where the call lives; the SET is
/// spellings rather than a shape, so a new blocking destination arrives as an
/// edit a reviewer reads.
#[test]
fn the_mount_call_site_passes_the_process_sink() {
    const ATTACH: &str = include_str!("attach.rs");

    // A POSITIVE control first: every assertion below is vacuous if the call
    // is not in this file.
    assert!(
        ATTACH.contains("MountSession::open("),
        "the subject of this row has left `attach.rs`; the assertions below \
         would be green over nothing"
    );
    // >>> AND WHERE THE THREADED DESTINATION COMES FROM, WHICH SCANNING
    // `attach.rs` ALONE CANNOT SEE. <<< A guard that only checks the callee
    // receives a binding named `log` passes while `main` builds that binding
    // from a fresh blocking handle. The construction is in `main.rs`, so it
    // is asserted there.
    assert!(
        production_source().contains("log_sink.protected_writer()"),
        "`main` must build the mount destination from the PROCESS sink's \
         protected stream — a binding named `log` proves nothing about what \
         it was built from"
    );
    let call = ATTACH.find("MountSession::open(").expect("checked above");
    let after = &ATTACH[call..];
    let close = after.find("\n    );").expect("the open call closes");
    assert!(
        after[..close].contains("\n        log,"),
        "`MountSession::open` must be passed the threaded destination"
    );
    for (head, tail) in [("std::io::", "stderr()"), ("std::io::", "stdout()")] {
        let needle = format!("{head}{tail}");
        // Any CONSTRUCTION of a blocking handle, not one call shape: the
        // removed code bound it to a local first, so a needle anchored to
        // `&mut ...` matched it zero times.
        let constructed = ATTACH
            .lines()
            .filter(|l| l.contains(&needle))
            .filter(|l| !l.trim_start().starts_with("//"))
            .count();
        assert_eq!(
            constructed, 0,
            "`{needle}` builds a BLOCKING destination in the mount path — the \
             wedge before the kernel filesystem exists"
        );
    }
}

/// The body of `env_filter_from` writes NOTHING.
///
/// The four rows above read the value the function RETURNS, and all four
/// stay green under an implementation that violates the no-write
/// contract: parse strictly, then
/// `eprintln!` the complaint from inside the construction. That is the same
/// synchronous pre-subscriber write one layer up, and no assertion over a
/// return value can see it.
///
/// So this row reads the function's own SOURCE, sliced from its signature to
/// the first line that closes at column zero, and refuses a set of write
/// spellings inside it.
#[test]
fn the_filter_construction_writes_nothing() {
    let body = env_filter_from_body();
    for needle in [
        "eprintln!",
        "eprint!",
        "println!",
        "print!",
        "write!",
        "writeln!",
        "stderr",
        "stdout",
    ] {
        assert!(
            !body.contains(needle),
            "`{needle}` inside `env_filter_from` is a write made BEFORE any \
             subscriber exists — the escape this row refuses. Body was:\n{body}"
        );
    }
}

/// The complaint is emitted AFTER the subscriber is installed.
///
/// The other half of the pre-subscriber-write rule: a report hoisted above
/// the install writes to a destination this process has not chosen yet, which
/// is the property this rule turns on and which nothing else here pins.
/// Both anchors are literal text in `main`, so a rename that moves the
/// emission breaks this row rather than silently passing it.
#[test]
fn the_filter_complaint_is_emitted_after_the_subscriber_is_installed() {
    let production = production_source();
    let init = production
        .find("logging::install_with_history(")
        .expect("`main` installs the subscriber with independent history");
    let emit = production
        .find("if let Some((reason, detail)) = filter_complaint {")
        .expect("`main` emits the filter complaint");
    assert!(
        init < emit,
        "the complaint is emitted at byte {emit}, before the install at {init} — \
         a write to a destination this process has not chosen yet"
    );
}

pub(crate) fn parse_publish(
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<PublishArgs, String> {
    parse_publish_options(
        args,
        env,
        &mut publish_config::PublishConfiguration::default(),
    )
}

pub(crate) fn parse_publish_options(
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<String>,
    configuration: &mut publish_config::PublishConfiguration,
) -> Result<PublishArgs, String> {
    parse_publish_checked(args, env, configuration, &mut false)
}

#[test]
fn writable_argument_diagnostic_excludes_untrusted_operand_text() {
    use std::cell::RefCell;
    let output = RefCell::new(String::new());
    let report =
        |message: std::fmt::Arguments<'_>| output.borrow_mut().push_str(&message.to_string());
    let mut cases = 0;
    for writable in [false, true] {
        output.borrow_mut().clear();
        let args = if writable {
            vec![OsString::from("--writable")]
        } else {
            vec![]
        };
        report_mount_argument_refusal(&args, "synthetic operand sentinel", &report);
        assert_eq!(
            output.borrow().as_str(),
            if writable {
                "gran mount: WritableArgumentsRefused"
            } else {
                "gran mount: synthetic operand sentinel"
            },
            "untrusted writable argument diagnostics must remain redacted"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_missing_pin_keeps_actionable_diagnostic() {
    use std::cell::RefCell;
    let args = [
        "v",
        "mountpoint",
        "--writable",
        "--foreground",
        "--endpoint",
        "https://fixture.invalid",
    ]
    .map(OsString::from);
    let error = parse_mount(&args).unwrap_err();
    let output = RefCell::new(String::new());
    report_mount_argument_refusal(&args, &error, &|message| {
        output.borrow_mut().push_str(&message.to_string());
    });
    assert!(
        output.borrow().contains("--pin sha256/... is required"),
        "missing pin must keep its non-secret diagnostic"
    );
}

/// Only the parent runs this arm: nextest's ordinary invocation is inert.
#[test]
fn session_install_child() {
    if std::env::var_os("GRANARY_TEST_SESSION_CHILD").is_none() {
        return;
    }
    let settings = logging::Settings {
        filter_source: 1,
        paths: granary_client::LogPaths::Redacted,
        format: granary_client::LogFormat::Json,
        file: None,
        filter: None,
    };
    logging::install_with_history(
        &settings,
        tracing_subscriber::EnvFilter::new("trace"),
        std::io::stdout,
        granary_client::BundleHistory::default(),
    )
    .expect("subscriber installation");
    let session = logging::session_span();
    let _session_entered = session.as_ref().map(tracing::Span::enter);
    granary_client::log_config(
        granary_client::LogFormat::Json,
        granary_client::LogDestination::Stderr,
    );
}

#[test]
fn projection_layer_and_session_span_install_before_any_verb_dispatches() {
    let main_src =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs")).unwrap();
    let install_pos = main_src
        .find("logging::install_with_history(")
        .expect("main must call logging::install_with_history");
    let span_pos = main_src
        .find("let session = logging::session_span();")
        .expect("main must open the session correlation span");
    let enter_pos = main_src
        .find("let _session_entered = session.as_ref().map(tracing::Span::enter);")
        .expect("main must enter the session correlation span");
    // Every dispatch site of each verb, not only its first, follows the enter.
    let early: Vec<(&str, usize, Vec<usize>)> = [
        "cmd_mount_gran(",
        "cmd_thresh(",
        "cmd_harvest(",
        "cmd_publish(",
        "cmd_cat(",
        "cmd_verify(",
        "cmd_mount(",
        "cmd_umount(",
    ]
    .into_iter()
    .map(|call| {
        let sites: Vec<usize> = main_src.match_indices(call).map(|(pos, _)| pos).collect();
        let before: Vec<usize> = sites
            .iter()
            .copied()
            .filter(|pos| *pos < enter_pos)
            .collect();
        (call, sites.len(), before)
    })
    .filter(|(_, sites, before)| *sites == 0 || !before.is_empty())
    .collect();
    assert_eq!(
        (install_pos < span_pos && span_pos < enter_pos, early),
        (true, vec![]),
        "install at {install_pos}, span at {span_pos}, enter at {enter_pos}; \
         (verb, sites, sites before the enter) for a verb with no site or an early one"
    );
    // The install path itself: a child runs `logging::install_with_history`
    // and the session span as `main` does, and its one event must carry the
    // session's correlation id. A subscriber that is built but not installed
    // leaves the child silent.
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "tests::session_install_child", "--nocapture"])
        .env("GRANARY_TEST_SESSION_CHILD", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("session install child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ids: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains("\"event\":\"log.config\""))
        .filter_map(|line| line.split_once("\"op\":\"")?.1.split('"').next())
        .collect();
    assert_eq!(
        (
            output.status.success(),
            ids.len(),
            ids.iter().all(|id| id
                .strip_prefix("cor-")
                .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()))),
        ),
        (true, 1, true),
        "session install child: {stdout}"
    );
}

#[test]
fn recovery_dispatch_passes_the_configured_path_policy() {
    let production = production_source().split_whitespace().collect::<String>();
    assert_eq!(
        production
            .matches("recover::invoke(&args,log_settings.paths)")
            .count(),
        1
    );
}
