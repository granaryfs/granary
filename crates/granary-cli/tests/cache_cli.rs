// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! CLI-level `--cache-dir` refusals, driven through the
//! COMPILED BINARY (`env!("CARGO_BIN_EXE_gran")`) — never `cmd_cat` or
//! `cat_resolve` in-process — because both rows are about the CLI's OWN
//! wiring, alongside the library behaviour `seam_drivable.rs` covers.
//!
//! - [`cat_refuses_a_cache_dir_populated_from_a_different_endpoint`]:
//!   the `Cache::open`-before-the-transport ordering, which is
//!   what makes an origin mismatch refusable with NO SERVER running at
//!   all.
//! - [`a_keyless_cat_never_degrades_against_a_warm_cache_and_a_dead_server`]:
//!   the CLI-surface twin of `seam_drivable.rs`'s
//!   `a_keyless_reader_never_degrades_even_with_a_warm_cache` — proving
//!   `main.rs` threads the ABSENCE of `--root-key` into a verifier the
//!   library then refuses to degrade for, rather than proving the
//!   library's own refusal (already covered there).
//! - [`cat_cache_io_refusal_keeps_its_exit_when_stderr_fails`] checks the
//!   diagnostic and process status for a local directory-creation failure.
//!
//! The cache I/O refusal happens before transport setup. The origin and
//! keyless fixtures use unused loopback ports so they can run without a
//! granary server.

#![cfg(unix)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use granary_client::{Cache, CacheError, CacheOrigin, HintUpdate, PersistedHint};
use granary_core::root::VolumeName;
use granary_net::b64::encode_pin;

// ------------------------------------------------------------- scratch dir

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
                      hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
                      and nothing else (`granary-cache-cli-<pid>-<counter>` under the temp dir, created and removed by \
                      this fixture), and it is load-bearing for correctness there: the counter beside it is \
                      per-process, and every test binary runs in its own process, so without the pid two concurrent \
                      runs generate the same name and share one directory. It reaches no hashed or signed value, and \
                      nothing this file compares is derived from it: both rows assert CLI exit codes and stderr text, \
                      and the directory name appears in neither"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-cache-cli-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ------------------------------------------------------------- binary driver

struct CatOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

fn cat_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gran"));
    command.arg("cat").args(args);
    command
}

fn run_cat(args: &[&str]) -> CatOutput {
    let out = cat_command(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn gran cat: {e}"));
    CatOutput {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A syntactically valid `sha256/...` pin over 32 fixed bytes — neither
/// row here ever completes a TLS handshake, so the pin's CONTENT never
/// matters, only that it parses and that both a real `gran cat`
/// invocation and this file's own `CacheOrigin` construction compute the
/// same [`CacheOrigin::pin_set_digest`] from it.
const PIN_BYTES: [u8; 32] = [0xAB; 32];

fn a_pin() -> String {
    format!("sha256/{}", encode_pin(&PIN_BYTES))
}

#[test]
fn cat_cache_io_refusal_keeps_its_exit_when_stderr_fails() {
    use std::{
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::Stdio,
    };

    let scratch = ScratchDir::new();
    let cache = scratch.path().join("cache-is-a-file");
    let original = b"cache-directory blocker";
    fs::write(&cache, original).unwrap();
    let endpoint = "not-a-url"; // A transport attempt would fail locally as well.
    let origin = CacheOrigin {
        endpoint_url: endpoint.to_owned(),
        pin_set_digest: CacheOrigin::pin_set_digest(&[PIN_BYTES]),
        root_key_id: None,
    };
    let Err(error @ CacheError::Io { .. }) = Cache::open(&cache, 1024 * 1024, &origin) else {
        panic!("a regular file must fail cache directory creation");
    };
    let pin = a_pin();
    let args = [
        "vol",
        "f.txt",
        "--endpoint",
        endpoint,
        "--pin",
        &pin,
        "--cache-dir",
        cache.to_str().unwrap(),
    ];
    let command = || {
        let mut command = cat_command(&args);
        command.env_clear().env("GRANARY_LOG_FILTER", "off");
        command
    };
    let healthy = command().output().unwrap();
    let stderr = String::from_utf8(healthy.stderr).unwrap();
    assert_eq!(healthy.status.code(), Some(1), "{stderr}");
    assert!(healthy.stdout.is_empty());
    assert!(
        stderr.starts_with(
            "gran cat: warning: no --root-key, so the root SIGNATURE is NOT checked.\n"
        )
    );
    assert_eq!(
        stderr.lines().last(),
        Some(format!("gran cat: {error}").as_str())
    );

    let (stderr, peer) = UnixStream::pair().unwrap();
    drop(peer);
    let failed = command()
        .stderr(Stdio::from(OwnedFd::from(stderr)))
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1));
    assert!(failed.stdout.is_empty());
    assert_eq!(fs::read(cache).unwrap(), original);
}

fn base_url(addr: SocketAddr) -> String {
    format!("https://{addr}")
}

/// A port nothing is listening on: bind an ephemeral port, then drop the
/// listener immediately. Nothing else on this machine can rebind it
/// inside this row's own short lifetime, and unlike a hardcoded low port
/// number this needs no assumption about what else might be running here.
fn dead_server_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    drop(listener);
    base_url(addr)
}

/// Two DISTINCT dead endpoints — bound simultaneously (so the OS cannot
/// hand the second bind the first's just-freed port) and both dropped
/// once both addresses are captured.
fn two_dead_server_endpoints() -> (String, String) {
    let a = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind: {e}"));
    let b = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind: {e}"));
    let addr_a = a.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let addr_b = b.local_addr().unwrap_or_else(|e| panic!("{e}"));
    drop(a);
    drop(b);
    (base_url(addr_a), base_url(addr_b))
}

// ----------------------------------------------- the Incompatible negative

/// **The CLI-level `Incompatible` negative**: `cat --endpoint B`
/// against a cache dir populated from endpoint A. `Cache::open` runs
/// before the transport, so this is drivable with NO SERVER running at
/// all — the first invocation's own READ fails too (nothing is listening
/// at either endpoint), and that failure is irrelevant to this row: only
/// the marker `Cache::open` wrote on that first, successful OPEN matters.
///
/// **The origin is composed through the CLI path, never a hand-built
/// struct**: both invocations below are the real `gran cat` binary,
/// given only the flags an operator would type. This proves `main.rs`'s
/// OWN `cache_origin` composition actually varies with `--endpoint`, not
/// merely that `Cache::open`'s marker check works in general (already
/// `cache.rs`'s own unit tests, e.g. `the_marker_handshake_refuses_a_
/// foreign_tuple`).
#[test]
fn cat_refuses_a_cache_dir_populated_from_a_different_endpoint() {
    let scratch = ScratchDir::new();
    let cache_dir = scratch.path().join("cache");
    let cache_dir_str = cache_dir
        .to_str()
        .unwrap_or_else(|| panic!("non-utf8 path"));
    let pin = a_pin();
    let (endpoint_a, endpoint_b) = two_dead_server_endpoints();

    let first = run_cat(&[
        "vol",
        "f.txt",
        "--endpoint",
        &endpoint_a,
        "--pin",
        &pin,
        "--cache-dir",
        cache_dir_str,
    ]);
    assert!(
        !first.success,
        "nothing is listening at either endpoint in this test; the READ itself must fail: \
         stdout={:?} stderr={:?}",
        first.stdout, first.stderr
    );
    assert!(
        !first.stderr.to_ascii_lowercase().contains("incompatible"),
        "the FIRST open, against an empty cache dir, must succeed and write the marker \
         (its later READ failing is expected and irrelevant here): {}",
        first.stderr
    );
    assert!(
        cache_dir.join("granary-cache").exists(),
        "Cache::open must have created the marker file on the first, successful open"
    );

    let second = run_cat(&[
        "vol",
        "f.txt",
        "--endpoint",
        &endpoint_b,
        "--pin",
        &pin,
        "--cache-dir",
        cache_dir_str,
    ]);
    assert!(
        !second.success,
        "an incompatible cache dir must refuse the read"
    );
    assert!(
        second.stderr.to_ascii_lowercase().contains("incompatible"),
        "the SECOND open, against a cache dir populated from a DIFFERENT endpoint, must fail \
         with the named CacheError::Incompatible — no server needed at all: stdout={:?} \
         stderr={:?}",
        second.stdout,
        second.stderr
    );
}

// ---------------------------------------------------- the keyless negative

/// **The CLI-surface twin of `seam_drivable.rs`'s
/// `a_keyless_reader_never_degrades_even_with_a_warm_cache`.** A KEYLESS
/// `gran cat` (no `--root-key`) against a `--cache-dir` that already
/// holds a resolvable head, with the server now dead, must exit with the
/// transport error — never serve anything from the cache — because
/// degraded fallback refuses a non-verifying reader before the cache is
/// read at all.
///
/// **"warm" is built directly through the library** (`Cache::open` +
/// `put_root_bytes` + `raise_anchor`), not through a real publish+read —
/// granary-cli cannot depend on granary-server (the reverse edge is a
/// licence-boundary violation, `seam_drivable.rs`'s own doc), so a real
/// end-to-end warm-up is the DEMO SCRIPT's job, not a Rust integration
/// test's. This is legitimate here specifically because rule (e) is
/// checked BEFORE `read_anchor`/`get_root_bytes` ever run — the cached
/// root's bytes are garbage and are never read on this path either way;
/// what is under test is that the CLI wires the missing `--root-key`
/// into a verifier the library refuses to degrade for, at all. The
/// origin uses the SAME public `CacheOrigin::pin_set_digest` function
/// `main.rs`'s own `cache_origin` calls, so this is compatible with what
/// the real invocation below composes, never a guessed byte pattern.
#[test]
fn a_keyless_cat_never_degrades_against_a_warm_cache_and_a_dead_server() {
    let scratch = ScratchDir::new();
    let cache_dir = scratch.path().join("cache");
    let endpoint = dead_server_endpoint();
    let pin = a_pin();
    let vol = VolumeName::new("vol".to_owned()).unwrap_or_else(|e| panic!("{e}"));

    let origin = CacheOrigin {
        endpoint_url: endpoint.clone(),
        pin_set_digest: CacheOrigin::pin_set_digest(&[PIN_BYTES]),
        // KEYLESS: matches exactly what the CLI composes for a `cat`
        // invocation with no `--root-key`.
        root_key_id: None,
    };
    {
        let mut cache =
            Cache::open(&cache_dir, 1024 * 1024, &origin).unwrap_or_else(|e| panic!("{e}"));
        // Garbage bytes on purpose: rule (e) refuses a keyless reader
        // BEFORE this is ever read, so what is cached here must not
        // matter to the outcome.
        cache.put_root_bytes(&vol, 1, b"not a real signed root; never read by this test");
        cache.raise_anchor(
            &vol,
            Some(1),
            HintUpdate::Replace(PersistedHint {
                seq: 1,
                token: "t".to_owned(),
                stamp_secs: 0,
            }),
        );
        cache.close().unwrap_or_else(|e| panic!("{e}"));
    }

    let out = run_cat(&[
        "vol",
        "f.txt",
        "--endpoint",
        &endpoint,
        "--pin",
        &pin,
        "--cache-dir",
        cache_dir
            .to_str()
            .unwrap_or_else(|| panic!("non-utf8 path")),
        // Deliberately no --root-key.
    ]);

    assert!(
        !out.success,
        "a keyless reader must never degrade, warm cache or not: stdout={:?} stderr={:?}",
        out.stdout, out.stderr
    );
    assert!(
        out.stdout.is_empty(),
        "rule (e) refuses before any emission begins, so NO bytes reach stdout: {:?}",
        out.stdout
    );
    assert!(
        !out.stderr.to_ascii_lowercase().contains("incompatible"),
        "this must fail on the KEYLESS gate, not on an origin mismatch — an Incompatible \
         verdict here would prove nothing about rule (e): {}",
        out.stderr
    );
    // The refusal must be OBSERVABLE, on STDERR specifically — `main`'s
    // tracing subscriber is wired to stderr (NO `tracing::*!`
    // call site in this crate was reachable from the CLI before
    // `--cache-dir`, so that flag introduced it; it is not a
    // pre-existing one — see `main.rs`'s note on why that claim is
    // stated as reachability rather than as a list of modules).
    // stdout must carry
    // NONE of it, since stdout is the file's own content stream.
    //
    // **The specific phrase asserted is `resolve_head_degraded`'s OWN
    // rule (e) warn, not `reader_verifier`'s unconditional "no
    // --root-key" notice.** The latter fires for EVERY keyless `cat`,
    // cache or no cache, transport up or down — a row that accepted it
    // alone would pass even if `cmd_cat` silently dropped the cache
    // parameter (`cache_guard.0.as_mut()` mutated to `None`) and never
    // reached the degraded fallback at all. "transport-down degraded
    // serve" appears ONLY on the path that actually threaded the cache
    // through, hit a transport-down error, found nothing emitted, and
    // reached rule (e) — the CLI-specific wiring this row exists to
    // prove.
    //
    // **This phrase is the SOLE discriminating assertion here** (quality
    // lane): the cache holds GARBAGE bytes, so a bypassed rule-(e)
    // gate would fail on `decode root` anyway, leaving `!success` and an
    // empty stdout satisfied either way. The ROBUST, valid-bytes coverage
    // of rule (e) — observing a bypassed gate actually SERVE content —
    // lives in the library twin `a_keyless_reader_never_degrades_even_
    // with_a_warm_cache` (`seam_drivable.rs`), which warms with a real
    // published volume. This CLI row's narrow job is only to prove
    // `main.rs` threads the absent `--root-key` through; if the rule-(e)
    // warn is ever reworded, update this literal (and prefer planting
    // library-produced valid bytes to make the outcome assertions bite).
    assert!(
        out.stderr.contains("transport-down degraded serve"),
        "the rule (e) refusal specifically must be observable on stderr, got stdout={:?} \
         stderr={:?}",
        out.stdout,
        out.stderr
    );
}
