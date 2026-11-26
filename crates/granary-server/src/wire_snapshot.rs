// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The server's wire-byte snapshot — the shutdown-time record
//! that seals [`crate::adapter::WriteBudget`]'s process-wide
//! request-byte total, alongside the run-id/role/writer-kind bookkeeping
//! that keeps five files from five different runs from being confused
//! for one another.
//!
//! **Emits, never parses.** The ingest parser — a different crate, a
//! different review — is the consumer; nothing here reads a byte back.
//! Per `docs/dependency-policy.md` rule 1 the object is hand-written
//! rather than pulled in through a `serde_json` dependency — the schema
//! is nine fixed fields, no nesting, no arrays, so a general-purpose
//! writer buys nothing a fixed `String` builder does not already give.
//!
//! **This is a SEPARATE piece of code from `granary-client`'s own
//! writer**, deliberately — see this crate's own licence header against
//! that crate's. The RULE (the field list, the role vocabulary, the
//! atomic-publish hygiene) is shared; the type and the code are not.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

/// The closed role vocabulary is explicit. A writer refuses
/// any string outside this list, and refuses an empty one, because
/// equality among empty roles is not identity.
const ROLE_VOCABULARY: &[&str] = &[
    "server",
    "publisher",
    "client-1",
    "client-2",
    "client-3",
    "warmup-1",
    "warmup-2",
    "warmup-3",
    "warmup-verify-1",
    "warmup-verify-2",
    "warmup-verify-3",
];

/// Why [`write_server_snapshot`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SnapshotError {
    /// The destination path the harness supplied is empty — an
    /// unexpanded shell variable's shape. Refused
    /// for the same reason an empty `run_id` is: an empty `Path` still
    /// stats as `NotFound` (so [`confirmed_absent`] would read it as
    /// "absent" instead of "malformed") and [`temp_path_for`] would
    /// build `.tmp` alone, which resolves in the process's CURRENT
    /// WORKING DIRECTORY rather than under any destination this trio
    /// names.
    EmptyPath,
    /// The `run_id` the harness supplied is empty.
    EmptyRunId,
    /// The `role` the harness supplied is empty.
    EmptyRole,
    /// The `role` the harness supplied is not in the closed vocabulary
    /// (`ROLE_VOCABULARY`, private to this module).
    UnknownRole,
    /// The destination already existed before this write attempted.
    AlreadyExists,
    /// A filesystem operation failed; the `String` is `Display`-rendered
    /// from the underlying [`std::io::Error`], the no-panic rule's usual
    /// shape for a diagnostic this layer cannot recover from.
    Io(String),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPath => write!(f, "the wire-snapshot destination path is empty"),
            Self::EmptyRunId => write!(f, "the wire-snapshot run id is empty"),
            Self::EmptyRole => write!(f, "the wire-snapshot role is empty"),
            Self::UnknownRole => write!(
                f,
                "the wire-snapshot role is not one of the closed vocabulary"
            ),
            Self::AlreadyExists => {
                write!(f, "the wire-snapshot destination already exists")
            }
            Self::Io(detail) => write!(f, "wire-snapshot write failed: {detail}"),
        }
    }
}

/// The counters a server snapshot seals — read off
/// [`crate::adapter::WriteBudget`] at shutdown, after every connection
/// has drained and the totals are final.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServerTotals {
    /// `None` iff the process-wide request-byte counter poisoned.
    pub(crate) request_bytes: Option<u64>,
    pub(crate) requests_with_body: u64,
    /// The DEMOTED response-byte figure — produced, never confirmed
    /// received. It is not a client-confirmed received-byte count.
    pub(crate) response_bytes_produced: u64,
}

/// `dest` joins `run_id`/`role` in the trio this
/// checks, because a `wire_snapshot_trio_is_valid` that
/// validated only two of the three operator-supplied values let
/// `GRANARY_WIRE_SNAPSHOT=""` (an unexpanded shell variable) passed
/// startup, served a whole instrumented run, and only THEN produced the
/// symptom described on [`SnapshotError::EmptyPath`] — an empty path is
/// refused HERE, before any of that.
///
/// **Only the empty string is refused, not every relative path.** A bare
/// relative filename (`"snapshot.json"`, no directory component) has a
/// real parent — the process's current working directory — and
/// [`temp_path_for`] builds a real temp file beside it there, so the
/// write-then-rename hygiene this module documents still holds; the only
/// difference from an absolute path is WHICH directory, an operator
/// choice this function has no basis to second-guess. It is the empty
/// string specifically that has no parent at all and no real name to
/// resolve, which is the mechanism behind every symptom `EmptyPath`'s
/// own doc lists.
fn validate(dest: &Path, run_id: &str, role: &str) -> Result<(), SnapshotError> {
    if dest.as_os_str().is_empty() {
        return Err(SnapshotError::EmptyPath);
    }
    if run_id.is_empty() {
        return Err(SnapshotError::EmptyRunId);
    }
    if role.is_empty() {
        return Err(SnapshotError::EmptyRole);
    }
    if !ROLE_VOCABULARY.contains(&role) {
        return Err(SnapshotError::UnknownRole);
    }
    Ok(())
}

/// Whether `dest`/`run_id`/`role` form a legal
/// wire-snapshot trio — the SAME check `write_server_snapshot` makes
/// before ever writing, exposed at the crate's public boundary
/// (re-exported from `lib.rs`) so `main.rs` — the `[[bin]]` target, a
/// SEPARATE crate from this `[lib]`, so it cannot reach `validate` or
/// `SnapshotError` directly — can refuse a malformed trio at STARTUP,
/// before the listener ever binds, rather than only discovering it at
/// the shutdown-time write after a whole run has already been served.
///
/// **`dest` is part of this check so an empty destination path is
/// refused at startup** — the function's own name is "trio", and until then it
/// validated two of the three. (`SnapshotError` itself is
/// crate-private, so its variant is named here in prose rather than as
/// an intra-doc link from this `pub fn`'s own doc.)
///
/// The refusal reason is `Display`-rendered into the `Err` rather than
/// handing back `SnapshotError` itself, so that type can stay
/// `pub(crate)`: this function is the ONE door a caller outside this
/// library needs, not a reason to widen the error type's own audience.
///
/// # Errors
///
/// The `Display` text of the underlying `SnapshotError` — an empty
/// destination path, an empty run id, an empty role, or a role outside
/// the closed vocabulary.
pub fn wire_snapshot_trio_is_valid(dest: &Path, run_id: &str, role: &str) -> Result<(), String> {
    validate(dest, run_id, role).map_err(|error| error.to_string())
}

fn write_json_string(out: &mut String, v: &str) {
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = std::fmt::Write::write_fmt(out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Render the snapshot body — the exact bytes [`write_server_snapshot`]
/// writes, factored out so the golden-fixture test can call it directly
/// against fixed inputs with no filesystem in the way.
fn render(run_id: &str, role: &str, listen_addr: &str, totals: ServerTotals) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"format_version\": 1,\n");
    out.push_str("  \"writer_kind\": \"granary-server\",\n");
    out.push_str("  \"run_id\": ");
    write_json_string(&mut out, run_id);
    out.push_str(",\n");
    out.push_str("  \"role\": ");
    write_json_string(&mut out, role);
    out.push_str(",\n");
    let poisoned = totals.request_bytes.is_none();
    out.push_str("  \"poisoned\": ");
    out.push_str(if poisoned { "true" } else { "false" });
    out.push_str(",\n");
    out.push_str("  \"request_bytes\": ");
    match totals.request_bytes {
        Some(n) => {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{n}"));
        }
        None => out.push_str("null"),
    }
    out.push_str(",\n");
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!("  \"requests_with_body\": {},\n", totals.requests_with_body),
    );
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "  \"response_bytes_produced\": {},\n",
            totals.response_bytes_produced
        ),
    );
    out.push_str("  \"drain_outcome\": \"drained\",\n");
    out.push_str("  \"listen_addr\": ");
    write_json_string(&mut out, listen_addr);
    out.push('\n');
    out.push_str("}\n");
    out
}

/// The temporary path this write publishes through before the atomic
/// rename — `dest` with a `.tmp` suffix appended to its whole file
/// name, so it sits beside `dest` on the same filesystem (a rename
/// across filesystems is not atomic) and cannot collide with a
/// differently-named destination.
fn temp_path_for(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

/// Decide whether `dest` is confirmed ABSENT, from an already-taken
/// [`std::fs::symlink_metadata`] result — a pure decision over the
/// `Result` rather than a filesystem call itself, so a unit test can
/// drive every branch (including an arbitrary stat error) without
/// depending on an OS-specific race or permission fixture.
///
/// **Fail CLOSED on an unreadable answer:** only a definite `NotFound`
/// is treated as "absent". `Ok` (something is there) refuses as
/// `AlreadyExists`, and every OTHER stat error (permission denied, a
/// broken parent path, an I/O failure) refuses too, as `Io` — this
/// process cannot tell "absent" from "the filesystem call itself
/// failed" any other way, and treating an ambiguous failure as "must
/// not be there" is the direction that would overwrite a file this
/// process never actually confirmed is absent.
fn confirmed_absent(
    dest: &Path,
    stat: std::io::Result<std::fs::Metadata>,
) -> Result<(), SnapshotError> {
    match stat {
        Ok(_) => Err(SnapshotError::AlreadyExists),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SnapshotError::Io(format!(
            "{}: cannot confirm absent: {e}",
            dest.display()
        ))),
    }
}

/// Write the server snapshot to `dest`, or refuse.
///
/// **Hygiene, in order:** `dest`/`run_id`/`role` are validated FIRST — a
/// refused trio must never partially create the destination. The
/// destination is then required ABSENT — [`confirmed_absent`] over
/// [`std::fs::symlink_metadata`] rather than [`Path::exists`], so a
/// broken symlink at `dest` still refuses rather than reading as
/// "nothing there", and so does a stat this process could not complete
/// at all. The body is written to a TEMPORARY file, created EXCLUSIVE
/// and refusing a symlink at its own name (see
/// [`create_temp_exclusive`]), and only then published onto `dest`
/// by a mechanism that REFUSES rather than replaces if something now
/// occupies that name (see
/// [`publish_no_replace`]).
///
/// # Errors
/// [`SnapshotError`], naming which of the above failed.
pub(crate) fn write_server_snapshot(
    dest: &Path,
    run_id: &str,
    role: &str,
    listen_addr: &str,
    totals: ServerTotals,
) -> Result<(), SnapshotError> {
    validate(dest, run_id, role)?;
    confirmed_absent(dest, std::fs::symlink_metadata(dest))?;
    write_body_and_publish(dest, run_id, role, listen_addr, totals)
}

/// The write-then-publish half of [`write_server_snapshot`], split out
/// so a test can drive it directly against a `dest` that bypasses
/// `confirmed_absent`'s own check (exercised separately) — the only way
/// to reach a REAL publish failure here without either `unsafe` FFI
/// (this crate has none, and inherits the workspace's
/// `unsafe_code = "forbid"` outright) or an unsynchronized thread race
/// to force `dest` to appear in the window `confirmed_absent` cannot
/// see across.
///
/// Every failure path below, from the
/// moment `tmp` is successfully created onward, removes `tmp` — best
/// effort, and NEVER masking the original error — before returning.
/// `tmp`'s name is DETERMINISTIC (`<dest>.tmp`), so a temp left behind
/// by one failed attempt would otherwise refuse EVERY later attempt at
/// the SAME `dest` at `create_temp_exclusive`'s own `EEXIST`, an opaque
/// `Io` naming the TEMP path rather than the failure that actually
/// caused it — permanently disabling the snapshot for that destination
/// over one transient failure. The same shape `granary-client`'s own
/// `store.rs::atomic_write` already uses for its txn-staged write.
fn write_body_and_publish(
    dest: &Path,
    run_id: &str,
    role: &str,
    listen_addr: &str,
    totals: ServerTotals,
) -> Result<(), SnapshotError> {
    let body = render(run_id, role, listen_addr, totals);
    let tmp = temp_path_for(dest);
    let mut file = create_temp_exclusive(&tmp)?;
    let result: Result<(), SnapshotError> = (|| {
        file.write_all(body.as_bytes())
            .map_err(|e| SnapshotError::Io(format!("{}: {e}", tmp.display())))?;
        file.flush()
            .map_err(|e| SnapshotError::Io(format!("{}: {e}", tmp.display())))?;
        drop(file);
        // `body.as_bytes()` is the content anchor
        // `publish_no_replace` verifies the reopened `tmp` against.
        // It replaces an `fstat`-at-create-time identity
        // comparison based on `(dev, ino)`, which was unsound on a
        // filesystem that recycles inode numbers.
        // Passed directly rather than re-derived, so what is compared
        // is exactly what this call itself wrote, nothing recomputed.
        publish_no_replace(&tmp, dest, body.as_bytes())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Create `tmp` as a NEW regular file, opened for writing with
/// exclusive creation and refusing a symlink at that name rather than
/// following it, before the wire-snapshot body is ever written to it.
///
/// A plain [`std::fs::File::create`] is unsuitable here: it both
/// FOLLOWS a symlink and
/// TRUNCATES a pre-existing file at `tmp`'s name. A stale `.tmp` left by
/// a previous run, or a symlink an attacker able to write into this
/// directory preplanted, would each have been written through with
/// this process's own privileges. `O_CREAT|O_EXCL` refuses ANY
/// pre-existing name outright, symlink or otherwise, before
/// `O_NOFOLLOW`'s own refusal would ever get a chance to matter — the
/// same two flags `granary-client`'s `fsguard::create_regular_exclusive`
/// already uses for its own temp-then-rename writer (this crate has no
/// `fsguard`: `granary-core` stays I/O-free and this AGPL crate does not
/// share code with the Apache client, so the same two-flag discipline is
/// applied directly here instead of imported).
///
/// **Create `tmp` with mode `0o600`, independent of the
/// process umask.** Without an explicit mode, a
/// permissive umask (`000`) leaves `tmp` world-writable at the moment
/// of creation — a local writer in this directory would then not even
/// need to unlink-and-replant to corrupt the body: a plain `O_WRONLY`
/// open of the SAME inode, no `O_CREAT`, would do, and the dev/ino
/// identity check in [`publish_no_replace`] passes vacuously because
/// the inode never changed. `0o600` closes that regardless of umask.
/// (The byte-for-byte content check would ALSO catch
/// this specific corruption — the bytes it verifies would no longer
/// match what this process wrote — but `0o600` closes the hole at its
/// source rather than relying on that as the only backstop.)
///
/// # Errors
/// [`SnapshotError::Io`] naming `tmp`, for whatever the open reports —
/// including `AlreadyExists` for a pre-existing name (symlink or
/// regular file) and `ErrorKind::Other`/`ELOOP` should a TOCTOU still
/// present a symlink at the exact instant of the open.
fn create_temp_exclusive(tmp: &Path) -> Result<std::fs::File, SnapshotError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(tmp)
        .map_err(|e| SnapshotError::Io(format!("{}: {e}", tmp.display())))
}

/// Refuse `f` (already opened at `path`)
/// unless it is a SOLE-LINKED regular file — the server's own
/// `refuse_non_sole_regular`, ported from `granary-client`'s
/// `fsguard::refuse_non_sole_regular` for the reason
/// [`publish_no_replace`]'s own doc gives for not sharing the code
/// directly. `nlink() != 1` is what catches a hard link to a file that
/// already exists elsewhere: this process's own writes through
/// [`create_temp_exclusive`] always leave exactly one.
fn refuse_non_sole_regular(f: std::fs::File, path: &Path) -> Result<std::fs::File, SnapshotError> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = f
        .metadata()
        .map_err(|e| SnapshotError::Io(format!("{}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(SnapshotError::Io(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if meta.nlink() != 1 {
        return Err(SnapshotError::Io(format!(
            "{} has {} links; a write-then-publish temporary must have exactly one",
            path.display(),
            meta.nlink()
        )));
    }
    Ok(f)
}

/// Whether a re-checked [`std::fs::Metadata`]
/// (an `lstat` of `tmp` immediately before the publish) still names the
/// SAME file [`publish_no_replace`] already verified through its open
/// descriptor — the server-side twin of `granary-client`'s
/// `fsguard::same_identity`. A pure comparison over two REAL `Metadata`
/// values, so a test drives the mismatch directly rather than landing
/// the actual race between two statements of one synchronous call —
/// the same discipline this module's own `confirmed_absent` test
/// already uses.
fn same_identity(verified: &std::fs::Metadata, recheck: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    verified.dev() == recheck.dev() && verified.ino() == recheck.ino()
}

/// **The reopened file's bytes, rather than a create-time `(dev, ino)`
/// comparison, are the content anchor** — the server-side twin of `granary-client`'s
/// `fsguard::verify_published_body`, ported rather than shared for the
/// same reason [`create_temp_exclusive`]'s own doc gives for
/// duplicating its two open flags instead of importing them.
///
/// A create-time anchor — comparing the descriptor `publish_no_replace`
/// reopens against an `fstat` this process took at
/// [`create_temp_exclusive`] time, by `(dev, ino)` — **is UNSOUND on a
/// filesystem that recycles inode numbers**, and this
/// crate ships for two of them: ext4 and tmpfs both reuse a freed inode
/// for the very next create in the same directory, routinely. A
/// co-tenant that watches for the exclusive create, `unlink`s `tmp`,
/// and `creat`s a fresh file in its place regularly gets handed back
/// the SAME inode number this process just released — a `(dev, ino)`
/// comparison finds them equal, the reopen's `fstat` matches the
/// create-time one, and the forgery publishes with `Ok(())`, no
/// diagnostic. Under test the replant reproduced on Linux and not on
/// macOS/APFS; the content check below does not depend on either
/// platform's inode behaviour. **Do not "simplify" this check to a
/// dev/ino comparison.**
///
/// The published artifact is a small JSON snapshot this process
/// rendered and wrote to `tmp` moments earlier, so authorship can be
/// checked directly instead: `f`'s bytes must equal `expected` — the
/// exact bytes [`write_body_and_publish`] wrote, kept in memory rather
/// than re-derived. Whatever the inode says, a replant whose content
/// differs is refused.
///
/// **Bounded, not a full read of whatever is at `tmp`:** the read is
/// capped to `expected.len() + 1` bytes via [`std::io::Read::take`], so
/// a co-tenant that swaps in a huge file at `tmp`'s name cannot make
/// this call read it in full before refusing — the extra `+ 1` is
/// enough to detect "longer than expected" without needing to know how
/// much longer.
///
/// A fresh file replanted with the IDENTICAL content this process
/// wrote is NOT refused by this check (nor could dev/ino ever have
/// distinguished it from a genuine race either). That is accepted, not
/// missed: the attacker gains nothing from the substitution — the
/// bytes that reach `dest` are the bytes this process itself produced,
/// byte for byte. See
/// `publish_no_replace_refuses_a_fresh_regular_file_replanted_at_the_temp_name`'s
/// companion row for that case, documented directly.
fn verify_published_body(
    f: &std::fs::File,
    path: &Path,
    expected: &[u8],
) -> Result<(), SnapshotError> {
    use std::io::Read as _;
    let mut buf = Vec::with_capacity(expected.len() + 1);
    f.take(expected.len() as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| SnapshotError::Io(format!("{}: {e}", path.display())))?;
    if buf != expected {
        return Err(SnapshotError::Io(format!(
            "{} does not hold the bytes this process wrote; refusing to publish",
            path.display()
        )));
    }
    Ok(())
}

/// Publish `tmp` onto `dest` by a mechanism
/// that REFUSES rather than replaces a `dest` that exists at the moment
/// of publish — including one that appeared AFTER
/// [`confirmed_absent`]'s own check, which is not atomic with this call.
///
/// [`std::fs::rename`] is unsuitable here because on Unix it SILENTLY
/// REPLACES an existing destination, so the
/// [`SnapshotError::AlreadyExists`] refusal [`confirmed_absent`]
/// promises would not be enforced at the moment a race made it
/// matter: a destination created between the check and the rename
/// would simply be overwritten, with the caller none the wiser.
///
/// **The mechanism, and why it is the SAME on every platform this
/// workspace ships for, rather than `renameat2`/`RENAME_NOREPLACE` on
/// Linux with a `link`+`unlink` fallback elsewhere.** `link(2)` creates
/// the new NAME and refuses one that already exists as ONE atomic
/// kernel operation — the existence check and the publish cannot be
/// pulled apart by a concurrent writer, so this CLOSES the gap rather
/// than narrowing it, on Linux exactly as it does on macOS. The
/// alternative named in the review that raised this finding —
/// `renameat2(RENAME_NOREPLACE)` on Linux — needs a raw `libc` FFI call,
/// which needs `unsafe`: this crate inherits the WORKSPACE's
/// `unsafe_code = "forbid"` and does not relax it the way
/// `granary-client` does (three named FFI sites in that OTHER
/// crate). A safe wrapper exists (`nix::fcntl::renameat2`, cfg-gated to
/// `target_os = "linux", target_env = "gnu"`), but reaching it would add
/// a new dependency edge used solely by this path on exactly ONE
/// platform this development machine cannot execute-test (Darwin) —
/// only type-checked by cross-compiling. `link`+`unlink` gives the
/// IDENTICAL refuse-not-replace guarantee through ONE code path instead
/// of two, fully exercised by this crate's own test suite on every
/// platform CI runs it on.
///
/// **Residual:** between `hard_link` succeeding and `remove_file`
/// running, `dest` and `tmp` are momentarily two names for the SAME
/// inode — `dest` is already published with the correct bytes at that
/// point, so this is cleanup debt, not a correctness gap. **The
/// function must not report `Io` if `remove_file` itself fails after
/// `hard_link` succeeds** — `dest` by then holds the right
/// content, durably, so a failing cleanup of the now-redundant `tmp`
/// name must not turn that durable success into a reported failure.
/// [`PublishOutcome::LeftoverTemp`] carries the cleanup error for an
/// advisory log while preserving the successful publish outcome.
///
/// **`tmp` is RE-VERIFIED by pathname
/// immediately before the link, not trusted because this process wrote
/// it once.** Were `publish_no_replace` to take only the PATH, nothing
/// between the body write finishing (in the caller,
/// [`write_body_and_publish`]) and the `hard_link` below would re-check
/// that the name still pointed at that same file. A local writer able to
/// create names in the SAME directory — a co-tenant, or a compromised
/// process running as a cooperating user; this module's whole hygiene
/// already assumes that boundary, see [`create_temp_exclusive`]'s own
/// doc — can replace `tmp` in that window with a symlink or a hard link
/// to a file this process never wrote, and `hard_link`'s treatment of a
/// symlink SOURCE is platform-defined (POSIX leaves it unspecified;
/// Linux's `link(2)` does not dereference it, other platforms may),
/// so the published bytes at `dest` are not provably this server's own
/// snapshot at all.
///
/// **The content check is the anchor.** A create-time `(dev, ino)`
/// comparison is unsound on filesystems that recycle inode numbers.
/// [`verify_published_body`] compares the reopened bytes with the exact
/// bytes this process wrote; its own doc gives the full rationale.
/// This function must retain that content anchor rather than relying on
/// a dev/ino comparison.
///
/// The pre-link pathname re-verification compares the reopened descriptor
/// against a FRESH `lstat` of the same pathname — self-consistency
/// between two statements of `publish_no_replace`, and nothing else.
/// What ties the reopened descriptor back to the file THIS PROCESS
/// actually wrote is [`verify_published_body`]: the published artifact
/// is a small JSON snapshot this process rendered moments earlier, so
/// this call reads the reopened descriptor and refuses unless its bytes
/// are EXACTLY the bytes [`write_body_and_publish`] wrote — whatever
/// the inode says. That is what refuses a fresh, solitary-linked
/// regular file replanted at `tmp`'s name (which passes both
/// `O_NOFOLLOW` and the nlink check above): its content differs from
/// what this process wrote, so the comparison fails even when the
/// inode does not.
///
/// **The mechanism is `granary-client`'s `fsguard::publish_regular`
/// together with its byte-for-byte content anchor, ported rather than
/// shared** — this crate has
/// no `fsguard`, the same reason [`create_temp_exclusive`]'s own doc
/// gives for duplicating its two open flags instead of importing them:
/// `granary-core` stays I/O-free and this AGPL crate does not share
/// code with the Apache client. Both steps are reachable with SAFE
/// `std`/`libc` (`OpenOptions` with
/// `custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)`, `MetadataExt`'s
/// `dev`/`ino`/`nlink`, `Read::take` for the bounded content read) —
/// this crate inherits the workspace's `unsafe_code = "forbid"` and the
/// client's own `unsafe` relaxation is three named FFI sites
/// elsewhere in that crate, none of them `fsguard`.
///
/// 1. Re-open `tmp` with `O_NOFOLLOW | O_NONBLOCK` — a symlink there
///    fails the open outright (`ELOOP`); `O_NONBLOCK` makes a FIFO
///    swapped in at `tmp`'s name fail the open rather than block
///    forever. Without that flag, a FIFO plant wedges this call and the
///    whole shutdown-time snapshot write in `open()`, so execution
///    never reaches the `fstat` that would otherwise refuse it.
///    `O_NONBLOCK` is the
///    flag `granary-client`'s own `fsguard::publish_regular` already
///    carries on this exact open; the server's copy had dropped it in
///    the port.
/// 2. [`refuse_non_sole_regular`] on that descriptor: a non-regular
///    file (a FIFO, a device) or one with more than one link (a hard
///    link to a file that already exists somewhere else — the write
///    THIS process did through [`create_temp_exclusive`] always leaves
///    exactly one) is refused.
/// 3. [`verify_published_body`] reads that
///    descriptor's bytes (bounded to `expected_body.len() + 1`) and
///    refuses unless they are EXACTLY the bytes this process's OWN
///    call to [`write_body_and_publish`] wrote. A mismatch means `tmp`
///    was unlinked and replanted with different content at ANY point
///    since this process created it, and is refused — independent of
///    what inode number the replant happens to land on.
/// 4. [`same_identity`] compares that same descriptor's `fstat` against
///    a FRESH `lstat` of the pathname, the last check before the
///    `hard_link` a few lines down. A mismatch means the name was
///    replaced again in the interval since step 3's check, and is
///    refused.
///
/// **Residual, now genuinely narrow, but for a DIFFERENT reason than
/// the discarded `(dev, ino)` analysis claimed:** step 3 ties the reopened descriptor's CONTENT
/// back to the bytes this process wrote, closing the entire span from
/// [`create_temp_exclusive`] returning to this function's own reopen
/// for every replant that changes what gets published — the window the
/// pathname re-open and identity checks alone left open, and the one the reproduced
/// exploit used. A replant with BYTE-IDENTICAL content is not refused
/// (see [`verify_published_body`]'s own doc for why that is accepted,
/// not missed: the attacker gains nothing from it). What remains is
/// step 4's own gap: the interval from the final pathname check (the
/// `lstat`) to the `hard_link` below it, inside the operator's OWN
/// directory — the same trust boundary this module's doc already draws
/// around every structural open here. Closing that fully needs a
/// primitive that links FROM A DESCRIPTOR rather than a pathname —
/// `openat2`/`AT_EMPTY_PATH`-shaped, needing raw `libc` FFI and
/// therefore `unsafe` — which this crate does not spend here, the same
/// choice the client's own `fsguard.rs` makes and documents. The
/// residual is a race an attacker must win against this function's OWN
/// final check-to-link interval, not the whole span from this process's
/// write to its publish.
///
/// # Errors
/// [`SnapshotError::Io`] if the re-open, the sole-regular check, the
/// content check, or the pre-link identity re-check above fails or
/// disagrees; [`SnapshotError::AlreadyExists`] if `dest` already exists
/// at the moment of publish (checked-and-created atomically by `link`,
/// so this is authoritative even when [`confirmed_absent`]'s earlier
/// check is stale); [`SnapshotError::Io`] if `hard_link` itself fails
/// for any other reason. A `remove_file` failure AFTER a successful
/// `hard_link` is logged (`tracing::warn!`) and returns `Ok(())`.
fn publish_no_replace(tmp: &Path, dest: &Path, expected_body: &[u8]) -> Result<(), SnapshotError> {
    let reopened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(tmp)
        .map_err(|e| SnapshotError::Io(format!("{}: {e}", tmp.display())))?;
    let verified = refuse_non_sole_regular(reopened, tmp)?;
    // The byte-for-byte content check below replaces the
    // `same_identity(&verified_meta, created)` comparison against
    // create-time metadata: that comparison used `(dev, ino)` and
    // was unsound on a filesystem that recycles inode numbers. See
    // `verify_published_body`'s own doc for the full rationale.
    verify_published_body(&verified, tmp, expected_body)?;
    let verified_meta = verified
        .metadata()
        .map_err(|e| SnapshotError::Io(format!("{}: {e}", tmp.display())))?;
    let recheck = std::fs::symlink_metadata(tmp)
        .map_err(|e| SnapshotError::Io(format!("{}: {e}", tmp.display())))?;
    if !same_identity(&verified_meta, &recheck) {
        return Err(SnapshotError::Io(format!(
            "{} no longer names the file this process just verified; refusing to publish",
            tmp.display()
        )));
    }
    drop(verified);

    let hard_link_result = std::fs::hard_link(tmp, dest);
    // `remove_file` is only ATTEMPTED
    // once `hard_link` itself succeeded — when `hard_link` fails, `tmp`
    // is left untouched; the caller's own stale-temp cleanup is
    // the one that decides what happens to it.
    let remove_result = if hard_link_result.is_ok() {
        std::fs::remove_file(tmp)
    } else {
        Ok(())
    };
    let outcome = publish_outcome(hard_link_result, remove_result);
    if let PublishOutcome::LeftoverTemp(ref remove_err) = outcome {
        tracing::warn!(
            tmp = %tmp.display(),
            dest = %dest.display(),
            error = %remove_err,
            "wire-snapshot publish: the temp file could not be removed after a \
             successful hard_link — the destination is published and correct; \
             the temp name is a leftover, not a failure"
        );
    }
    outcome.into_result().map_err(|link_err| {
        if link_err.kind() == std::io::ErrorKind::AlreadyExists {
            SnapshotError::AlreadyExists
        } else {
            SnapshotError::Io(format!(
                "{} -> {}: {link_err}",
                tmp.display(),
                dest.display()
            ))
        }
    })
}

/// A [`publish_no_replace`] attempt resolves from the ALREADY-TAKEN
/// results of `hard_link` and, only when that succeeds, the follow-up
/// `remove_file` — a pure
/// decision over two `io::Result`s, neither of which this function's own
/// code can influence, so a test can drive the "`hard_link` landed but the
/// temp cleanup failed" branch directly with SYNTHETIC results.
///
/// **A real fixture (a directory this process can create a NEW hard
/// link into but cannot unlink an existing name from) was tried and
/// discarded.** On every filesystem this crate ships for, `link(2)` and
/// `unlink(2)` are gated by the SAME directory-write permission check —
/// so the condition that would make the follow-up `remove_file` fail
/// almost always makes the PRECEDING `hard_link` fail too, and the
/// error return right after `hard_link` would then
/// already refuse, for the same underlying reason, through a DIFFERENT
/// call site than the cleanup branch. A row built on that fixture cannot
/// tell whether the cleanup branch is present — the
/// exact shape [`confirmed_absent`]'s own test above already documents
/// for an unrelated check in this same file.
///
/// **The decision itself:** once `hard_link` succeeds, `dest` is
/// published — durable and byte-correct, at that instant. A failing
/// `remove_file` of `tmp` afterward is cleanup debt, not a publish
/// failure: [`PublishOutcome::LeftoverTemp`] carries the removal error
/// for an advisory log only, and [`publish_no_replace`] still returns
/// `Ok(())`. Returning the `remove_file` error directly as
/// `SnapshotError::Io` would conflate the two: it would
/// turn a durable success into a reported failure, and the ONE caller
/// of this function (`write_wire_snapshot` in `serve.rs`) would map that Err
/// to "wire-snapshot not written", misreporting a publish that in fact
/// succeeded.
#[derive(Debug)]
enum PublishOutcome {
    /// `hard_link` succeeded and the temp name is gone too.
    Clean,
    /// `hard_link` succeeded; the temp name survives because
    /// `remove_file` failed. Carries that failure for an advisory log.
    LeftoverTemp(std::io::Error),
    /// `hard_link` itself failed — the publish never happened.
    Failed(std::io::Error),
}

fn publish_outcome(
    hard_link: std::io::Result<()>,
    remove_temp: std::io::Result<()>,
) -> PublishOutcome {
    match hard_link {
        Err(e) => PublishOutcome::Failed(e),
        Ok(()) => match remove_temp {
            Ok(()) => PublishOutcome::Clean,
            Err(e) => PublishOutcome::LeftoverTemp(e),
        },
    }
}

impl PublishOutcome {
    /// The `Result` [`publish_no_replace`] itself reports for this
    /// outcome — split out from the `tracing::warn!` beside its call
    /// site so a test can pin the "`LeftoverTemp` still maps to `Ok`"
    /// wiring directly, independent of the log call. Without this
    /// split, a mutation that swapped `LeftoverTemp`'s arm back to
    /// `Err` would be caught only
    /// by `publish_outcome`'s OWN unit test, never by anything
    /// exercising `publish_no_replace` itself.
    fn into_result(self) -> std::io::Result<()> {
        match self {
            Self::Clean | Self::LeftoverTemp(_) => Ok(()),
            Self::Failed(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests;
