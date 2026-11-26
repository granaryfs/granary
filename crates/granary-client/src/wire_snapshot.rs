// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The client's wire-byte snapshot: the clean-exit record that
//! seals [`crate::http_store::WireByteHandle`]'s process-wide
//! response-byte total, alongside the same run-id/role/writer-kind
//! bookkeeping the server's own snapshot carries.
//!
//! **Emits, never parses.** The propagation harness's own ingest
//! verb is the consumer. Per `docs/dependency-policy.md` rule 1
//! this is hand-written rather than a `serde_json` dependency,
//! the same choice `granary-server`'s own writer makes.
//!
//! **A SEPARATE piece of code from `granary-server`'s own writer,
//! deliberately.** This crate is Apache; the server's writer lives in
//! the AGPL crate. The RULE (the field list, the role vocabulary, the
//! atomic-publish hygiene) is shared; the type and the code are not.

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The closed role vocabulary is IDENTICAL to the
/// server's own list, and necessarily a separate copy: see this
/// module's own doc for why the two writers cannot share code.
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

/// Why [`write_client_snapshot`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// The destination path the harness supplied
    /// is empty — an unexpanded shell variable's shape,
    /// `granary-server`'s own `SnapshotError::EmptyPath` twin.
    /// Refused for the same reason: an empty `Path` still stats as
    /// `NotFound` (so `confirmed_absent` would read it as "absent"
    /// rather than "malformed"), and `temp_path_for` would build
    /// `.tmp` alone, resolving in the process's CURRENT WORKING
    /// DIRECTORY rather than under any destination this trio names.
    /// (Both are private helpers in this module, named here in prose
    /// rather than as intra-doc links — `SnapshotError` is `pub`, and
    /// rustdoc refuses a public item's doc linking to a private one.)
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
    /// A filesystem operation failed; `Display`-rendered from the
    /// underlying [`std::io::Error`].
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

impl std::error::Error for SnapshotError {}

/// The `PublishSummary` fields the harness needs,
/// Publication counters are unavailable for retained authority completion.
/// Direct counters are embedded from the struct — never re-parsed
/// from `gran publish`'s own stdout summary line.
#[derive(Debug, Clone)]
pub struct PublishFields {
    pub seq: u64,
    pub novel_objects: Option<u64>,
    pub novel_bytes: Option<u64>,
    pub bins_uploaded: Option<u64>,
    pub bin_bytes_uploaded: Option<u64>,
    /// The canonical `<algorithm>:<hex>` text form.
    pub manifest_root: Option<String>,
}

/// What one client-kind snapshot seals.
#[derive(Debug, Clone)]
pub struct ClientTotals {
    /// `None` iff the process-wide response-byte counter poisoned.
    pub response_bytes: Option<u64>,
    /// The `--endpoint` verbatim, or `None` on the `--direct-s3` route.
    pub endpoint: Option<String>,
    /// The `--seq` pin, or `None` when the head was discovered.
    pub pinned_seq: Option<u64>,
    /// Present exactly when the writer was `gran publish`.
    pub publish: Option<PublishFields>,
}

/// `dest` joins `run_id`/`role` in the trio this
/// checks, matching the server's own `validate` for the destination
/// as well as the two labels. **Only the empty string is
/// refused, not every relative path** — the same rule and the same
/// reason `granary-server`'s own `validate` states: a bare relative
/// filename (`"snapshot.json"`, no directory component) has a real
/// parent, the process's own current working directory, so the
/// write-then-rename hygiene this module documents still holds: the
/// only difference from an absolute path is WHICH directory, an
/// operator choice this function has no basis to second-guess.
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
/// wire-snapshot trio — the SAME check [`write_client_snapshot`]
/// makes before ever writing, exposed at this crate's public boundary
/// (re-exported from `lib.rs`) so `main.rs` — the `[[bin]]` target, a
/// SEPARATE crate from this `[lib]`, so it cannot reach `validate` or
/// `SnapshotError` directly — can refuse a malformed trio at
/// ARGUMENT-PARSE time, before `gran cat`/`gran mount`/`gran publish`
/// does any work, rather than only discovering it when the verb's own
/// exit tries to write the snapshot. The client-side twin of
/// `granary-server`'s own `wire_snapshot_trio_is_valid` — see that
/// function's own doc for why the error comes back `Display`-rendered
/// into a `String` rather than as `SnapshotError` itself.
///
/// `wire_snapshot_args` (granary-cli's `main.rs`) checks both that all
/// three of `--wire-snapshot`/`--wire-run-id`/`--wire-role` are given
/// together and that their VALUES are valid. Thus `gran mount --wire-role
/// clientt-1` (note the typo) is refused at argument-parse time instead
/// of running the entire mount and failing only at unmount, when the
/// snapshot would be written.
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

fn write_json_string_or_null(out: &mut String, v: Option<&str>) {
    match v {
        Some(text) => write_json_string(out, text),
        None => out.push_str("null"),
    }
}

fn write_json_u64_or_null(out: &mut String, v: Option<u64>) {
    match v {
        Some(n) => {
            let _ = std::fmt::Write::write_fmt(out, format_args!("{n}"));
        }
        None => out.push_str("null"),
    }
}

/// Render the snapshot body — factored out so the golden-fixture test
/// can call it directly against fixed inputs.
fn render(run_id: &str, role: &str, totals: &ClientTotals) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"format_version\": 1,\n");
    out.push_str("  \"writer_kind\": \"granary-client\",\n");
    out.push_str("  \"run_id\": ");
    write_json_string(&mut out, run_id);
    out.push_str(",\n");
    out.push_str("  \"role\": ");
    write_json_string(&mut out, role);
    out.push_str(",\n");
    let poisoned = totals.response_bytes.is_none();
    out.push_str("  \"poisoned\": ");
    out.push_str(if poisoned { "true" } else { "false" });
    out.push_str(",\n");
    out.push_str("  \"response_bytes\": ");
    write_json_u64_or_null(&mut out, totals.response_bytes);
    out.push_str(",\n");
    out.push_str("  \"endpoint\": ");
    write_json_string_or_null(&mut out, totals.endpoint.as_deref());
    out.push_str(",\n");
    out.push_str("  \"pinned_seq\": ");
    write_json_u64_or_null(&mut out, totals.pinned_seq);
    if let Some(publish) = &totals.publish {
        out.push_str(",\n");
        out.push_str("  \"publish\": {\n");
        let _ =
            std::fmt::Write::write_fmt(&mut out, format_args!("    \"seq\": {},\n", publish.seq));
        for (name, value) in [
            ("novel_objects", publish.novel_objects),
            ("novel_bytes", publish.novel_bytes),
            ("bins_uploaded", publish.bins_uploaded),
            ("bin_bytes_uploaded", publish.bin_bytes_uploaded),
        ] {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("    \"{name}\": "));
            write_json_u64_or_null(&mut out, value);
            out.push_str(",\n");
        }
        out.push_str("    \"manifest_root\": ");
        write_json_string_or_null(&mut out, publish.manifest_root.as_deref());
        out.push('\n');
        out.push_str("  }\n");
    } else {
        out.push_str(",\n  \"publish\": null\n");
    }
    out.push_str("}\n");
    out
}

/// The temporary path this write publishes through before the atomic
/// rename — the same shape `granary-server`'s own writer uses.
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
/// **Fail CLOSED on an unreadable answer**, the same as the server's
/// own writer: only a definite `NotFound` is treated as "absent". `Ok`
/// (something is there) refuses as `AlreadyExists`, and every OTHER
/// stat error (permission denied, a broken parent path, an I/O failure)
/// refuses too, as `Io` — this process cannot tell "absent" from "the
/// filesystem call itself failed" any other way, and treating an
/// ambiguous failure as "must not be there" is the direction that would
/// overwrite a file this process never actually confirmed is absent.
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

/// Write the client's wire-byte snapshot to `dest`, or refuse.
///
/// Same hygiene as `granary-server`'s own writer:
/// `dest`/`run_id`/`role` validated first, the destination
/// required absent (`confirmed_absent`), the body written to a
/// temporary file and only then renamed onto `dest`.
///
/// # Errors
/// [`SnapshotError`], naming which of the above failed.
pub fn write_client_snapshot(
    dest: &Path,
    run_id: &str,
    role: &str,
    totals: &ClientTotals,
) -> Result<(), SnapshotError> {
    validate(dest, run_id, role)?;
    // The lstat-backed SAFE half of `fsguard`'s banned class (see that
    // module's doc): reading whether something is at `dest` at all,
    // never following it.
    confirmed_absent(dest, std::fs::symlink_metadata(dest))?;
    write_body_and_publish(dest, run_id, role, totals)
}

/// The write-then-publish half of [`write_client_snapshot`], split out
/// so a test can drive it directly against a `dest` that bypasses
/// `confirmed_absent`'s own check (exercised separately) — the only way
/// to reach a REAL publish failure here without either `unsafe` FFI
/// (`setrlimit`, forbidden outside the three permitted unsafe sites in this
/// crate — two in `cache/space.rs`, one in `cache/write.rs`) to force a
/// write failure, or an unsynchronized
/// thread race to force `dest` to appear in the window
/// `confirmed_absent` cannot see across.
///
/// Every failure path below, from the
/// moment `tmp` is successfully created onward, removes `tmp` —
/// best effort, and NEVER masking the original error — before
/// returning. `tmp`'s name is DETERMINISTIC (`<dest>.tmp`), so a
/// temp left behind by one failed attempt would otherwise refuse
/// EVERY later attempt at the SAME `dest` at
/// `create_regular_exclusive`'s own `EEXIST`, an opaque `Io` naming
/// the TEMP path rather than the failure that actually caused it —
/// permanently disabling the snapshot for that destination over one
/// transient failure. The same shape `store.rs`'s own
/// `atomic_write` already uses for its txn-staged write.
#[expect(
    clippy::disallowed_methods,
    reason = "the best-effort cleanup of this function's OWN just-created temp file on its \
              own failure path — the identical `let _ = fs::remove_file(&tmp)` shape \
              `store.rs::atomic_write` already licenses for the same reason: `from` is a name \
              this process itself created moments ago via `fsguard::create_regular_exclusive` \
              and never anything a symlink/hard-link/FIFO plant could redirect, so this is not \
              the class of write-through-a-planted-name hazard fsguard's guarded opens defend \
              against"
)]
fn write_body_and_publish(
    dest: &Path,
    run_id: &str,
    role: &str,
    totals: &ClientTotals,
) -> Result<(), SnapshotError> {
    let body = render(run_id, role, totals);
    let tmp = temp_path_for(dest);
    let mut file = crate::fsguard::create_regular_exclusive(&tmp)
        .map_err(|e| SnapshotError::Io(format!("{}: {e}", tmp.display())))?;
    let result: Result<(), SnapshotError> = (|| {
        file.write_all(body.as_bytes())
            .map_err(|e| SnapshotError::Io(format!("{}: {e}", tmp.display())))?;
        file.flush()
            .map_err(|e| SnapshotError::Io(format!("{}: {e}", tmp.display())))?;
        drop(file);
        // `publish_regular` now refuses
        // rather than replaces a `dest` that appeared after the
        // `confirmed_absent` check above — surfaced here as the
        // SAME `SnapshotError::AlreadyExists` variant the early
        // check itself produces, so a caller cannot tell
        // "caught early" from "caught at publish" apart, which
        // is the point: both mean the same thing happened.
        //
        // `body.as_bytes()` is the content anchor
        // `publish_regular` verifies the reopened `tmp` against — see
        // that function's own doc for why this REPLACES the former
        // `fstat`-at-create-time identity comparison, which was
        // unsound on a filesystem that recycles inode numbers.
        // Passed directly rather than re-derived, so what is compared
        // is exactly what this call itself wrote, nothing recomputed.
        crate::fsguard::publish_regular(&tmp, dest, body.as_bytes()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                SnapshotError::AlreadyExists
            } else {
                SnapshotError::Io(format!("{} -> {}: {e}", tmp.display(), dest.display()))
            }
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests;
