// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Misreading the kernel's account of what is mounted decides a mount state
//! the path does not have — a target reported free while a filesystem is
//! mounted there, and a granary-labelled mount read as gone while it stands.
//!
//! **What this module deliberately does NOT list among those
//! consequences:** *"detaching a filesystem this process did not attach"*.
//! That claim fails twice over: `SOURCE=gran` is a LABEL and not proof of
//! ownership (`findmnt_rows_at_target`'s own doc says so), and `gran umount`
//! is a different process from the daemon, so "this process" is the wrong
//! discriminator. That failure also needs the parent's POLICY
//! (`umount_preflight_verdict`) to be wrong, so claiming it here would
//! misattribute it.
//!
//! **Two doors onto the same external state, and both are read here.**
//! `/proc/self/mountinfo` directly (`refuse_if_already_mounted` and `control_mounts`,
//! through `read_bounded` and `mountinfo_lists_target`) and `findmnt -rno
//! TARGET,FSTYPE,SOURCE` (`still_mounted_via_findmnt`, through
//! `classify_findmnt_exit` and `findmnt_rows_at_target`). They have
//! DIFFERENT escape grammars — mountinfo's octal `\040`, findmnt's hex
//! `\x20` — which is why both `mountinfo_unescape` and `findmnt_unescape`
//! exist and why neither may be used on the other's output.
//!
//! **What the parent keeps, because it is policy and not observation.**
//! `TargetRows` reports what the rows SAY; `umount_preflight_verdict` and
//! `umount_postcheck_verdict` decide what that PERMITS, and they deliberately
//! disagree about `AllGran`. `refuse_if_nonempty` and `first_entry_verdict`
//! read a DIRECTORY, not a table, and stay with the pre-flight whose
//! invariant they implement.
//!
//! Inbound names — what `attach` reads back: `TargetRows` (and its `Absent`,
//! `AllGran` and `Mixed` variants, and `Mixed`'s `any_gran` field, none of
//! which a lexical seam measure can see), `still_mounted_via_findmnt` and
//! `refuse_if_already_mounted`, `ControlMount`, `control_mounts` and
//! `mount_namespace`. Control observation reuses the strict FUSE parser;
//! `umount_control_target` in the parent decides owner wait or root detach.
//!
//! **Reach into the parent, PRODUCTION half: ONE name, `MountPreflightError`**
//! — eight references, all from `refuse_if_already_mounted`'s two arms. **The
//! TEST half also reaches `umount_control_target` and `MountScratchDir`** (`mount_table/tests.rs`,
//! through the `#[cfg(test)] pub(crate) use` that `attach.rs` already carried),
//! and the scope is stated because a later cut of this file will read this
//! paragraph for its closed reach set and a bare "ONE name" undercounts it. The
//! alternative is to give this module its own error type so production reaches
//! nothing in the parent; it is NOT recommended because it would move the
//! `AlreadyMounted` and `MountCheckUnsupported` arms out of the parent's
//! refusal payload. A child may use a closed set of explicitly named parent
//! items; here the production set is the shared `MountPreflightError` type.

use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use granary_client::open_regular_read;

use super::MountPreflightError;

#[cfg(test)]
mod tests;

/// The kernel mount owner's identity, independent of inode presentation ids.
#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ControlMount {
    pub key: granary_core::mount_control::MountKey,
    pub owner: u32,
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn control_mounts_in(
    bytes: &[u8],
    path: &Path,
    namespace: (u64, u64),
) -> std::io::Result<Vec<ControlMount>> {
    let rows = granary_fuse::mountinfo_rows_at(bytes, path)?;
    if rows.iter().any(|row| !row.fuse || row.source != b"gran") {
        return Err(std::io::Error::other(
            "refusing: the target carries a mount that is not granary's",
        ));
    }
    let mut mounts = Vec::new();
    for row in rows {
        let mut owners = row
            .super_options
            .split(|b| *b == b',')
            .filter_map(|option| option.strip_prefix(b"user_id="));
        let first = owners.next();
        let owner = first
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u32>().ok());
        let (Some(owner), None) = (owner, owners.next()) else {
            return Err(std::io::Error::other(
                "refusing: missing, duplicate or malformed FUSE user_id",
            ));
        };
        if namespace.1 == 0 || row.mount_id == 0 {
            return Err(std::io::Error::other(
                "refusing: invalid mount namespace or mount id",
            ));
        }
        mounts.push(ControlMount {
            owner,
            key: granary_core::mount_control::MountKey {
                namespace_dev: namespace.0,
                namespace_ino: namespace.1,
                mount_id: row.mount_id,
                fuse_major: row.device.0,
                fuse_minor: row.device.1,
            },
        });
    }
    Ok(mounts)
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::disallowed_methods,
    reason = "read-only followed metadata of the kernel mount namespace link; no mounted-root access"
)]
pub(super) fn mount_namespace() -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let namespace = std::fs::metadata("/proc/self/ns/mnt")?;
    Ok((namespace.dev(), namespace.ino()))
}

#[cfg(target_os = "linux")]
pub(super) fn control_mounts(path: &Path) -> std::io::Result<Vec<ControlMount>> {
    let file = open_regular_read(Path::new("/proc/self/mountinfo"))?;
    control_mounts_in(
        &read_bounded(file, MOUNTINFO_MAX_BYTES)?,
        path,
        mount_namespace()?,
    )
}

/// Read at most `limit + 1` bytes from `r`, refusing when that many are
/// actually read. The `limit + 1`th byte is what proves there is at
/// least one more the caller could not see — `Read::take(limit)` alone
/// cannot express this: it silently STOPS at its bound and reports
/// `Ok`, which turns "too big to check" into "nothing found" here, the
/// fail-open shape this project has paid for repeatedly. Pure over any
/// [`std::io::Read`], so it is tested on both platforms this repo targets even though its
/// real callers — `refuse_if_already_mounted`'s Linux arm (reading
/// `/proc/self/mountinfo`) and `still_mounted_via_findmnt_with` (reading
/// findmnt's piped stdout) — are not.
///
/// # Errors
/// Whatever the underlying read reports, or `InvalidData` naming the
/// bound when the read reaches `limit + 1` bytes.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "reachable in production via two callers — refuse_if_already_mounted's Linux \
                  arm (mount_preflight, its unconditional caller, is reachable from main()'s own \
                  \"mount\" dispatch) and still_mounted_via_findmnt_with (reachable only from \
                  target_os = \"linux\"-gated cmd_umount_linux) — neither of which is REACHABLE \
                  in production outside target_os = \"linux\", so this stays unreachable in a \
                  non-test build everywhere else; this module's own tests call it directly on \
                  every platform. still_mounted_via_findmnt_with itself compiles on every \
                  platform and carries a cfg_attr expectation, not a cfg gate"
    )
)]
fn read_bounded(r: impl std::io::Read, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut r.take(limit + 1), &mut buf)?;
    if buf.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "exceeds the {limit}-byte bound; refusing rather than checking a truncated \
                 mount table, which could hide an existing mount and permit a double mount"
            ),
        ));
    }
    Ok(buf)
}

/// A generous bound on `/proc/self/mountinfo`'s size — this process's
/// own mount table, which it does not control the length of, but which
/// has no business running to hundreds of megabytes. Matches this
/// crate's other bounded reads' discipline (`MARKER_MAX_BYTES` et al.)
/// without borrowing their figure, which is sized for a different
/// format. Enforced by [`read_bounded`], which REFUSES rather than
/// silently truncating when a real mount table exceeds it.
#[cfg(target_os = "linux")]
const MOUNTINFO_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Refuse a mountpoint that is already listed in `/proc/self/mountinfo`
/// — the ONLY reliable "is this already a mount" source on Linux (a
/// `statfs`-based heuristic cannot tell a bind mount or an empty
/// filesystem apart from an unmounted directory the way this can).
///
/// **Untestable on this box.** granary-fuse and this crate build on
/// macOS for development, but `/proc` does not exist there — this
/// function cannot compile-check, let alone run, outside Linux CI. The
/// PARSING logic it depends on ([`read_bounded`], [`mountinfo_lists_target`],
/// [`mountinfo_unescape`]) is deliberately factored out as pure
/// functions of `&[u8]` (never `&str` — a mount path is arbitrary
/// bytes, not necessarily UTF-8) so THAT half is tested on every
/// platform; only the read of the real pseudo-file is gated here.
#[cfg(target_os = "linux")]
pub(super) fn refuse_if_already_mounted(mountpoint: &Path) -> Result<(), MountPreflightError> {
    // `mountpoint` was already proved to EXIST (and not be a symlink) by
    // `symlink_metadata` in `mount_preflight`, immediately before this
    // call — `canonicalize` here resolves its real absolute path so it
    // can be compared against mountinfo's own field 5, which the kernel
    // reports fully resolved. This is a SECOND check-then-use, not a
    // closure of the window the earlier check opened: the eventual
    // `mount(2)`/`umount2` re-resolves the path itself and fails safely
    // if the target moved in between. This pre-flight accepts
    // that check-then-use window rather than
    // defending against it.
    #[expect(
        clippy::disallowed_methods,
        reason = "READ-ONLY path resolution of a mountpoint already proved to exist by \
                  symlink_metadata in the parent's mount_preflight, immediately before it \
                  calls this function; needed to compare against mountinfo's own \
                  fully-resolved field 5. This arm moved into a child module, so \
                  \"immediately above\" became a relative anchor into another file and is \
                  named by module here instead"
    )]
    fn canonical(path: &Path) -> Result<PathBuf, MountPreflightError> {
        std::fs::canonicalize(path).map_err(|e| MountPreflightError::Io {
            path: path.to_owned(),
            detail: e.to_string(),
        })
    }
    let real = canonical(mountpoint)?;
    let mountinfo_path = Path::new("/proc/self/mountinfo");
    let f = open_regular_read(mountinfo_path).map_err(|e| MountPreflightError::Io {
        path: mountinfo_path.to_owned(),
        detail: e.to_string(),
    })?;
    let bytes = read_bounded(f, MOUNTINFO_MAX_BYTES).map_err(|e| MountPreflightError::Io {
        path: mountinfo_path.to_owned(),
        detail: e.to_string(),
    })?;
    if mountinfo_lists_target(&bytes, &real) {
        return Err(MountPreflightError::AlreadyMounted(mountpoint.to_owned()));
    }
    Ok(())
}

/// A NAMED mount-preflight refusal on every platform without a
/// `/proc/self/mountinfo` — never a silent skip.
#[cfg(not(target_os = "linux"))]
pub(super) fn refuse_if_already_mounted(mountpoint: &Path) -> Result<(), MountPreflightError> {
    let _ = mountpoint;
    Err(MountPreflightError::MountCheckUnsupported {
        os: std::env::consts::OS,
    })
}

/// Whether `mountinfo` bytes (the `/proc/[pid]/mountinfo` format,
/// `proc_pid_mountinfo(5)`) list `target` — an ALREADY-canonical path —
/// as a mount point (field 5). Pure and platform-independent, so it is
/// tested on both platforms this repo targets even though its only real
/// caller ([`refuse_if_already_mounted`]'s Linux arm) is not.
///
/// "Both platforms" is Linux and macOS: there is no Windows leg in this
/// repo's CI matrix, which matters because the byte comparison below goes
/// through `OsStrExt`, a Unix-only trait.
///
/// **Bytes, not `&str`.** `/proc/self/mountinfo` escapes only space,
/// tab, newline and backslash; every other byte — including an
/// arbitrary non-UTF-8 byte in some OTHER mount's path, unrelated to
/// the one being checked — appears RAW. A `&str`-based read
/// (`read_to_string`) would make any such unrelated mount a local
/// denial of service against `gran mount`, refusing the whole
/// pre-flight before parsing ever ran. Comparison is byte-for-byte
/// throughout, with no lossy conversion anywhere in this path: a lossy
/// decode could make two different byte sequences compare equal, which
/// is worse than the bug it would replace.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "reachable in production only via refuse_if_already_mounted's Linux arm, \
                  which does not exist outside target_os = \"linux\" at all; this module's own \
                  tests call this function directly on every platform"
    )
)]
fn mountinfo_lists_target(mountinfo: &[u8], target: &Path) -> bool {
    let target_bytes = target.as_os_str().as_bytes();
    for line in mountinfo.split(|&b| b == b'\n') {
        let mut fields = line.split(|&b| b == b' ');
        // Fields 1-4 (mount ID, parent ID, major:minor, root) are
        // skipped; field 5 is the mount point.
        for _ in 0..4 {
            if fields.next().is_none() {
                break;
            }
        }
        let Some(raw) = fields.next() else { continue };
        if mountinfo_unescape(raw).as_slice() == target_bytes {
            return true;
        }
    }
    false
}

/// The single octal escape at `bytes[i..]`, if `bytes[i]` is `\` and the
/// three bytes after it are octal digits — `None` otherwise, including
/// when there are not three more bytes to look at. `.get()` throughout,
/// never indexing: this crate denies `clippy::indexing_slicing`.
fn octal_escape_at(bytes: &[u8], i: usize) -> Option<u8> {
    if *bytes.get(i)? != b'\\' {
        return None;
    }
    let d1 = *bytes.get(i + 1)?;
    let d2 = *bytes.get(i + 2)?;
    let d3 = *bytes.get(i + 3)?;
    // A single byte's largest legal octal escape is `\377` (255), so the
    // FIRST digit can only ever legally be 0..=3 — admitting it up to
    // b'7' let `(d1 - b'0') * 64` reach 7*64 = 448, which does not fit a
    // `u8` and PANICS (this workspace's release profile also sets
    // overflow-checks = true, so this is not a debug-only concern).
    // Narrowing the accept set here makes the overflow UNREPRESENTABLE
    // rather than merely avoided: with d1 constrained to 0..=3, the
    // largest value this expression can ever produce is
    // 3*64 + 7*8 + 7 = 255, which always fits.
    if !(b'0'..=b'3').contains(&d1) || !(b'0'..=b'7').contains(&d2) || !(b'0'..=b'7').contains(&d3)
    {
        return None;
    }
    Some((d1 - b'0') * 64 + (d2 - b'0') * 8 + (d3 - b'0'))
}

/// Decode mountinfo's octal escapes (`\040` for space, and the same
/// grammar for tab, newline and backslash) so a mount point containing
/// one of those bytes still compares correctly. Bytes in, bytes out —
/// no UTF-8 requirement and NO lossy conversion: the field may contain
/// an arbitrary byte that is not valid UTF-8 on its own (mountinfo
/// never escapes it), and this function must return it unchanged, byte
/// for byte. A lossy round-trip would collapse that byte to the
/// replacement character, making two genuinely different paths compare
/// equal — worse than the non-UTF-8-refuses-everything bug it would
/// replace.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "reachable in production only via refuse_if_already_mounted's Linux arm \
                  (through mountinfo_lists_target), which does not exist outside \
                  target_os = \"linux\" at all; this module's own tests call this function \
                  directly on every platform"
    )
)]
fn mountinfo_unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0usize;
    while let Some(&b) = field.get(i) {
        if let Some(decoded) = octal_escape_at(field, i) {
            out.push(decoded);
            i += 4;
        } else {
            out.push(b);
            i += 1;
        }
    }
    out
}

/// One hex digit's value, either case, or `None`. `0..=15` by
/// construction, so `hi * 16 + lo` is at most 255 and cannot overflow a
/// `u8` — the same "make the overflow unrepresentable rather than merely
/// avoided" discipline `octal_escape_at` states for its own first digit.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode findmnt(8) `--raw`'s hex escapes (`\x<code>`, e.g. `\x20` for
/// a space) — the escape grammar findmnt actually uses,
/// distinct from `/proc/self/mountinfo`'s octal one [`mountinfo_unescape`]
/// decodes. findmnt(8) itself: "All potentially unsafe characters are
/// hex-escaped (`\x<code>`)", and util-linux's `include/carefulputc.h`
/// `fputs_nonblank` is the implementation behind that wording — it
/// escapes `isblank`, `0x5c` (the backslash itself), `!isprint` and
/// `iscntrl`, each as `\x%02x`.
///
/// **Fallible on purpose — the difference from [`mountinfo_unescape`].**
/// That function copies an unrecognised backslash sequence literally,
/// which is right for mountinfo: a raw, unescaped backslash is legal
/// there. It is WRONG here: `fputs_nonblank` escapes the backslash
/// itself, so a raw backslash cannot occur in well-formed findmnt
/// output at all. A `\` that does not begin a complete `\xHH` escape
/// means this byte string is not what this parser assumes it is, and
/// silently copying it through would reproduce, one layer down, the
/// post-check failure of treating uncertainty as verified absence — treating unparsed
/// bytes as if they had been read correctly. Returning `None` for the
/// WHOLE field instead means nothing gets concluded from it.
///
/// **Both hex cases are accepted, deliberately.** findmnt(8)'s own
/// contract is `\x<code>`; util-linux's current implementation emits
/// lowercase. Accepting only lowercase would be a hard refusal against
/// a conforming implementation that happened to emit uppercase, and
/// admitting uppercase here adds no ambiguity — this decodes a foreign
/// tool's output, not a canonical format whose accept set must stay
/// minimal.
///
/// **One pass, left to right — never rescanned.** A path that literally
/// contains the four bytes `\`, `x`, `2`, `0` arrives from findmnt as
/// `\x5cx20` (the backslash escaped, then the three literal bytes `x`,
/// `2`, `0`); a single pass decodes the `\x5c` down to one `\` byte and
/// copies `x`, `2`, `0` unchanged, which is correct. Decoding the result
/// a second time would turn that literal `x20` into a space, which
/// would be wrong.
///
/// `.get()` throughout, never indexing: this crate denies
/// `clippy::indexing_slicing`.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "reachable in production only via still_mounted_via_findmnt_with, itself \
                  reachable only from target_os = \"linux\"-gated cmd_umount_linux — this \
                  module's own tests call this function directly on every platform"
    )
)]
fn findmnt_unescape(field: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0usize;
    while let Some(&b) = field.get(i) {
        if b == b'\\' {
            if *field.get(i + 1)? != b'x' {
                return None;
            }
            let hi = hex_digit(*field.get(i + 2)?)?;
            let lo = hex_digit(*field.get(i + 3)?)?;
            out.push(hi * 16 + lo);
            i += 4;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Some(out)
}

/// Whether `fstype` (the raw FSTYPE column `findmnt -rno TARGET,FSTYPE,
/// SOURCE` reports, unescaped) names a FUSE-family filesystem.
/// Bare `fuse` is what a root `mount(2)` (this binary's own
/// privileged `gran mount` path) always registers as: `Subtype` is a
/// fusermount-group option the direct root path never passes.
/// `fuse.gran` is the other real shape, from the fusermount-group path.
/// Matching the FAMILY (`fuse` or any `fuse.<subtype>`), not the exact
/// string, is deliberate: this checks what a FUSE mount looks like, not
/// what THIS crate's own mount happens to be named, and a hypothetical
/// future subtype would still pass without another edit here.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from findmnt_rows_at_target, itself reachable in production only \
                  under target_os = \"linux\" (it COMPILES everywhere and carries the same \
                  cfg_attr expectation this one does; it is not cfg-gated) — this module's own \
                  tests call it directly with plain byte-slice fstype values on every platform, \
                  needing no findmnt binary anywhere near it"
    )
)]
fn is_fuse_family_fstype(fstype: &[u8]) -> bool {
    fstype == b"fuse" || fstype.starts_with(b"fuse.")
}

/// What the rows naming one exact target say — which is not the same
/// question in the two places it is asked. The PRE-FLIGHT must know that
/// the thing `umount2` will detach is a granary mount; the POST-CHECK
/// must know whether any granary mount is still there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetRows {
    /// No row names this target.
    Absent,
    /// Every row naming this target is a granary mount.
    AllGran,
    /// At least one row naming this target is NOT a granary mount, so
    /// the target is over-mounted (or shares its name with something
    /// else). `any_gran` says whether a granary mount is among them.
    Mixed { any_gran: bool },
}

/// What every row in `findmnt -rno TARGET,FSTYPE,SOURCE`'s raw output
/// (`stdout`) says about `target`: `gran umount`'s verification rule is to
/// inspect EVERY matching row, not the first. A lower granary row
/// cannot establish the type of an over-mounted target. The pre-flight
/// and post-check ask DIFFERENT questions of the same data (see
/// [`TargetRows`]'s own doc): the pre-flight must know that the thing
/// `umount2` will detach really is a granary mount, and only "every row
/// here is granary's" answers that; the post-check must know whether
/// ANY granary mount is still there.
///
/// **SOURCE alone is not proof.** `FSName("gran")`
/// (`granary-fuse`'s `session_config`) sets the mount SOURCE to the
/// literal string `gran` on both the root and the fusermount-group
/// path, which is why this matches on it at all — but SOURCE is a
/// string `mount -t tmpfs gran /mnt/other` can set on an entirely
/// unrelated filesystem, at the operator's own choosing. **Why not
/// FSTYPE alone either**: a root `mount(2)` registers as plain `fuse`,
/// never `fuse.gran` (`Subtype` is a fusermount-group-only option), so
/// a check keyed on the EXACT string `fuse.gran` would read a real,
/// still-mounted `gran` filesystem as already gone. The row test closes
/// both: SOURCE must be `gran` AND FSTYPE must be in the FUSE family
/// ([`is_fuse_family_fstype`] checks the second half) — the tmpfs
/// impostor fails that half, and both real shapes still pass it.
///
/// **Why not `fuser`'s own `is_mounted`.** It is a private function
/// this crate has no access to, and it answers
/// `true` for a mount stuck in the `ENOTCONN` state, so a self-heal
/// guard built on it would read a wedged mount as healthy. This checks
/// the SAME mount table `findmnt` reads, independently.
///
/// **Bytes, not `&str`, and unescaped with [`findmnt_unescape`] —
/// NOT [`mountinfo_unescape`].** findmnt(8) `--raw`'s escape
/// grammar is hex (`\x<code>`), not `/proc/self/mountinfo`'s octal
/// (`\NNN`) — see `findmnt_unescape`'s own doc for the full argument.
/// An octal decoder cannot decode a hex-escaped path correctly.
///
/// **Column framing is decided per matching row, before FSTYPE/SOURCE
/// are decoded, and requires EXACTLY three raw fields — no more, no
/// fewer.** Scoped to a row whose TARGET already matches — see the
/// field-count discussion below for why an unrelated
/// row's own framing must never reach this check at all. findmnt
/// escapes a space INSIDE a field as `\x20`, so a raw, unescaped space
/// byte in the row can only ever be a column separator — decoding a
/// field's escapes afterward can never turn a decoded byte back into a
/// column boundary the framing already fixed. The argv this parser's
/// input comes from is fixed at `-rno TARGET,FSTYPE,SOURCE`, and
/// libsmartcols (findmnt's own formatter) prints the separator after
/// every column that is not the last, whatever the cell holds — so a
/// well-formed row has exactly two raw separators, INCLUDING when a
/// column is empty (an empty SOURCE gives `"TARGET FSTYPE "`, three
/// fields with an empty third). That is what makes exactly-three safe
/// rather than merely stricter: a MATCHING row with a FOURTH raw field
/// is unaccounted-for input this parser has no argv-shaped explanation
/// for, not a row to fold the extra bytes into SOURCE — folding it
/// would be fail-closed for the PRE-FLIGHT (an unauthorized row is
/// refused either way) but fail-OPEN for the POST-CHECK, where the
/// folded, non-`gran` source would make a genuinely still-mounted row
/// read as `Mixed { any_gran: false }`, which maps to "the mount is
/// gone."
/// The same bytes cannot mean two different things depending on which
/// call site reads them, so this refuses instead — see
/// `findmnt_rows_at_target_is_none_for_a_matching_row_with_a_fourth_raw_field`
/// below.
///
/// `None` means the output could not be parsed and NOTHING may be
/// concluded from it: a TARGET field whose [`findmnt_unescape`] fails,
/// on ANY row (the row might still be ours, whatever
/// its own field count), or — only for a row whose decoded TARGET
/// actually matches — a field count other than exactly three, or an
/// FSTYPE or SOURCE whose [`findmnt_unescape`] fails. A row whose
/// decoded TARGET plainly names some OTHER mount is skipped outright,
/// whatever its own field count or the rest of its bytes — see the
/// field-count discussion below. Skipping a malformed row instead of
/// returning `None` for a row that COULD be ours would let an
/// unreadable possible match become a false conclusion that the mount
/// is absent.
///
/// **TARGET is decoded and compared BEFORE
/// FSTYPE/SOURCE are decoded at all, for every row.** Decoding all
/// three fields up front would let ONE row anywhere in the WHOLE mount
/// table whose FSTYPE or SOURCE fails to decode make this return `None`
/// for every other row too — including rows for completely unrelated
/// mounts: a healthy granary mount would become un-unmountable because
/// of some OTHER filesystem's odd row, and a SUCCESSFUL detach would
/// report "could not verify the unmount". Deciding TARGET first and
/// `continue`-ing past a non-matching row WITHOUT decoding its
/// FSTYPE/SOURCE keeps every fail-closed property that matters — a row
/// whose OWN target cannot be decoded still returns `None`, because it
/// might BE the sought target and this parser cannot tell — while never
/// letting an unrelated row's unreadable bytes decide a DIFFERENT
/// target's verdict.
///
/// **The field-count check itself is scoped to a matching row.** Running
/// the SHAPE check — exactly three raw fields — on every row, before
/// TARGET is looked at, would let one unrelated row whose framing this
/// parser does not expect (too few fields, a stray fourth) return
/// `None` for the WHOLE table: the same "one odd row poisons the
/// verdict" coupling as above, for framing instead of decoding. So the
/// row's first field is taken as the candidate TARGET and decoded, and
/// a row that plainly names some OTHER mount is `continue`d past BEFORE
/// the field-count check ever runs on it — only a row whose TARGET
/// already matches is held to the exactly-three-fields rule. Every
/// strictness this parser applies is scoped to rows that could be the
/// target; a row for somebody else's mount cannot decide anything.
///
/// Pure, so it is tested directly against a captured findmnt-shaped
/// fixture on every platform this repo targets, even though the process
/// that produces its real input (`findmnt`) exists on only one of them.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from still_mounted_via_findmnt_with, itself reachable in \
                  production only from target_os = \"linux\"-gated cmd_umount_linux (it COMPILES \
                  everywhere; it is not cfg-gated) — this module's own tests call it directly \
                  against a captured findmnt-shaped fixture on every platform, needing no findmnt \
                  binary anywhere near it"
    )
)]
fn findmnt_rows_at_target(stdout: &[u8], target: &Path) -> Option<TargetRows> {
    let target_bytes = target.as_os_str().as_bytes();
    let mut any_gran = false;
    let mut any_non_gran = false;
    for line in stdout.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        // TARGET — the row's first field — is
        // decoded and compared BEFORE anything else about the row is
        // checked, INCLUDING its own field count. A row whose own
        // TARGET cannot be decoded might still BE our target, so that
        // failure keeps returning `None` for the whole table —
        // inconclusive, the fail-closed rule that also governs
        // decode order. But once TARGET decodes and plainly
        // names some OTHER mount, `continue` past it immediately: the
        // field-count check below never runs on it, so an unrelated
        // row's own unexpected framing (too few fields, a stray
        // fourth) cannot decide OUR target's verdict — the "one odd
        // row poisons the verdict" coupling, closed for framing as it
        // is for decoding. See this
        // function's own doc for the full rationale.
        let mut fields = line.split(|&b| b == b' ');
        let Some(t) = fields.next() else {
            // `line` was just checked non-empty, so `split` on it always
            // yields at least one item — kept as a real `None` return
            // rather than an `.unwrap()` this crate denies, not because
            // this arm is believed reachable.
            return None;
        };
        let t = findmnt_unescape(t)?;
        if t != target_bytes {
            continue;
        }
        // Column framing is decided HERE, only for a row whose TARGET
        // already matches — see this function's own doc for why a
        // decoded space can never disturb it, and for why EXACTLY three
        // fields total (the fourth `fields.next()` must be `None`) is
        // required rather than folding a fourth raw field into SOURCE.
        let (Some(fstype), Some(source), None) = (fields.next(), fields.next(), fields.next())
        else {
            return None;
        };
        let fstype = findmnt_unescape(fstype)?;
        let source = findmnt_unescape(source)?;
        if source == b"gran" && is_fuse_family_fstype(&fstype) {
            any_gran = true;
        } else {
            any_non_gran = true;
        }
    }
    Some(match (any_gran, any_non_gran) {
        (false, false) => TargetRows::Absent,
        (any_gran, true) => TargetRows::Mixed { any_gran },
        (true, false) => TargetRows::AllGran,
    })
}

/// The `findmnt` binaries [`still_mounted_via_findmnt`] may run, in
/// the order it tries them, as ABSOLUTE paths — never a bare name —
/// for the SAME reason `granary_fuse::detach_unmount`'s own
/// `FUSERMOUNT_CANDIDATES` is a fixed absolute list (that file's own
/// doc explains the same inherited-PATH risk). `gran umount` can run
/// as root (a root-owned systemd unit, or
/// a `sudo` invocation that keeps the caller's environment), and
/// `Command::new("findmnt")` resolves the name through the process's
/// INHERITED `PATH`. An attacker-writable directory early in that
/// `PATH` would let a forged `findmnt` decide this command's own
/// verification result on BOTH the pre-check and the
/// post-check — a forged "yes, gran is here" on the pre-check would
/// grant detach permission for a target that never earned it, and a
/// forged "no, nothing's here" on the post-check would report
/// `Clean` over a mount still fully attached.
const FINDMNT_CANDIDATES: &[&str] = &["/usr/bin/findmnt", "/bin/findmnt"];

/// A generous bound on `findmnt -rno TARGET,FSTYPE,SOURCE`'s whole-table
/// stdout. The same figure and the same reason as
/// `MOUNTINFO_MAX_BYTES` (Linux-only, so not linked here), which bounds
/// the identical data (this process's own mount table) read a
/// different way — through `/proc/self/mountinfo` directly rather than
/// through `findmnt`. Enforced by [`read_bounded`], which REFUSES
/// rather than silently truncating a real mount table that exceeds it,
/// exactly like its mountinfo-reading sibling.
const FINDMNT_STDOUT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Pins this constant's own doc claim — "the same figure and the same
/// reason as `MOUNTINFO_MAX_BYTES`" — rather than leaving it an
/// assertion nothing checks: before this, raising `FINDMNT_STDOUT_MAX_
/// BYTES` to 40 MiB or lowering it to 400 KiB each left the suite
/// green, because the one test naming it passes the SAME constant to
/// both sides of its own comparison. `target_os = "linux"`-gated
/// because `MOUNTINFO_MAX_BYTES` is (`/proc/self/mountinfo` exists
/// nowhere else) — the honest cost of that gate is that the macOS dev
/// loop never evaluates this assertion at all; CI's Linux lane is what
/// would actually catch the two figures drifting apart.
#[cfg(target_os = "linux")]
const _: () = assert!(FINDMNT_STDOUT_MAX_BYTES == MOUNTINFO_MAX_BYTES);

/// `findmnt -rno TARGET,FSTYPE,SOURCE`'s raw exit status and stdout,
/// reduced to two outcomes (see [`classify_findmnt_exit`]): whole-table
/// mode has no conclusive "nothing matched" exit status.
///
/// Pure, so it is tested directly against synthetic exit-code/stdout
/// pairs on every platform, exactly like [`findmnt_rows_at_target`]
/// above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "produced only by classify_findmnt_exit and consumed only by \
                  still_mounted_via_findmnt_with, itself reachable only from \
                  target_os = \"linux\"-gated cmd_umount_linux — this module's own tests \
                  construct and match on it directly on every platform. classify_findmnt_exit \
                  is where both variants are built"
    )
)]
enum FindmntVerdict {
    /// Exit 0 with non-empty stdout — the caller should inspect stdout
    /// itself.
    Ran,
    /// Anything else — could not verify.
    Inconclusive,
}

/// A WHOLE-TABLE `findmnt` invocation (no `--target` filter)
/// treats only exit 0 with non-empty stdout as a completed listing.
/// Every other combination is inconclusive, so an empty-stdout error
/// cannot be mistaken for proof that the mount is absent.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from still_mounted_via_findmnt_with, itself reachable only from \
                  target_os = \"linux\"-gated cmd_umount_linux — this module's own tests call it \
                  directly with synthetic exit-code/stdout pairs on every platform"
    )
)]
fn classify_findmnt_exit(status_code: Option<i32>, stdout_is_empty: bool) -> FindmntVerdict {
    match status_code {
        Some(0) if !stdout_is_empty => FindmntVerdict::Ran,
        _ => FindmntVerdict::Inconclusive,
    }
}

/// The Linux-only half `findmnt_rows_at_target` cannot be: actually
/// running `findmnt` and reading its output.
///
/// Production always calls [`still_mounted_via_findmnt`], which passes
/// [`FINDMNT_CANDIDATES`] and [`FINDMNT_STDOUT_MAX_BYTES`]; both are
/// parameters here (mirroring `fusermount_lazy_unmount_with`'s own
/// shape) so this file's own tests can drive this with a fake helper
/// script and a small byte bound instead of requiring a real `findmnt`
/// binary and writing multiple real megabytes of fixture data to
/// exercise the stdout byte cap.
///
/// PRIVATE ON PURPOSE — same reasoning as `fusermount_lazy_unmount_with`:
/// a gate whose set the caller picks is not a gate.
///
/// **Piped, not `.output()`.** `.output()` buffers the
/// WHOLE table with no bound at all, twice per unmount (this and the
/// post-check). This spawns with
/// `stdin(Stdio::null())`, `stderr(Stdio::null())` (nothing here reads
/// `findmnt`'s stderr, so discarding it loses nothing),
/// and `stdout(Stdio::piped())`, then reads the `ChildStdout` through
/// [`read_bounded`] at `stdout_limit`.
///
/// **Read BEFORE `wait()`.** Waiting first would deadlock against a
/// child blocked writing into a full pipe once its buffer fills; the
/// read must drain the pipe first.
///
/// **The `ChildStdout` is passed BY VALUE into [`read_bounded`]**, so
/// the pipe closes as soon as the read ends, at the call site itself —
/// no code runs between `read_bounded` returning and the end of the
/// match arm below, so a `&mut` would close the fd at exactly the same
/// point and present the child an identical syscall sequence either
/// way; no observable difference is claimed for by-value here. The
/// shape is chosen because it makes the close's timing obvious to a
/// reader at the call site, not because a reference would behave
/// differently.
///
/// **Every successful spawn reaches `wait()`** — the cap-exceeded path,
/// a read error, and a missing stdout handle all `kill()` (its result
/// ignored: the child may already have exited) and then `wait()` before
/// returning the error. Rust does not reap a `Child` on `Drop`, and the
/// status is classified only after BOTH the bounded read and the wait
/// succeed.
///
/// **A byte cap is not a TIME bound.** A helper that emits little and
/// never exits still hangs here, exactly as an `.output()` call would:
/// this function has no time bound, and none is claimed for it.
#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from still_mounted_via_findmnt, itself reachable only from \
                  target_os = \"linux\"-gated cmd_umount_linux — this module's own tests drive \
                  it directly with a fake helper script on every platform, needing no findmnt \
                  binary anywhere near it"
    )
)]
fn still_mounted_via_findmnt_with(
    candidates: &[&str],
    mountpoint: &Path,
    stdout_limit: u64,
) -> std::io::Result<TargetRows> {
    // `symlink_metadata`, not `exists` — this crate's own clippy.toml
    // bans `Path::exists` (the extra fs rows check-fsguard-sites.sh
    // audits), and `symlink_metadata` is that ban list's own "safe
    // half" of the fs class (lstat-backed, never follows), the same
    // idiom `path_separation::refuse_if_dangling` uses for the identical
    // "does something exist here" question — needing no licence of its
    // own, unlike granary-fuse's own `fusermount_lazy_unmount_with` in
    // a sibling crate whose clippy.toml does not ban `exists` at all.
    let Some(binary) = candidates
        .iter()
        .map(Path::new)
        .find(|p| p.is_absolute() && std::fs::symlink_metadata(p).is_ok())
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "no findmnt helper found among the fixed absolute candidates {candidates:?}; \
                 PATH is deliberately not searched, because this command can run as root"
            ),
        ));
    };
    let mut child = std::process::Command::new(binary)
        .args(["-rno", "TARGET,FSTYPE,SOURCE"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    // Read BEFORE wait(): see this function's own doc — waiting first
    // would deadlock against a child blocked writing into a full pipe.
    let stdout_result = match child.stdout.take() {
        Some(stdout) => read_bounded(stdout, stdout_limit),
        None => Err(std::io::Error::other(
            "the findmnt child process had no stdout handle to read",
        )),
    };
    let stdout = match stdout_result {
        Ok(bytes) => bytes,
        Err(e) => {
            // Every successful spawn reaches wait() — Rust does not
            // reap a Child on Drop. kill()'s result is ignored: the
            // child may already have exited.
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    let status = child.wait()?;

    match classify_findmnt_exit(status.code(), stdout.is_empty()) {
        FindmntVerdict::Ran => findmnt_rows_at_target(&stdout, mountpoint).ok_or_else(|| {
            std::io::Error::other(
                "findmnt's output did not parse — a malformed row, or a field with an escape \
                 sequence this parser does not recognize — refusing rather than guessing",
            )
        }),
        FindmntVerdict::Inconclusive => Err(std::io::Error::other(format!(
            "findmnt exited with {:?} and {} bytes of stdout — could not verify",
            status.code(),
            stdout.len()
        ))),
    }
}

#[cfg_attr(
    not(any(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "called only from cmd_umount_linux, itself target_os = \"linux\"-gated — this \
                  module's own tests drive still_mounted_via_findmnt_with directly (the \
                  production entry point adds nothing but the fixed candidate list and byte \
                  bound)"
    )
)]
pub(super) fn still_mounted_via_findmnt(mountpoint: &Path) -> std::io::Result<TargetRows> {
    still_mounted_via_findmnt_with(FINDMNT_CANDIDATES, mountpoint, FINDMNT_STDOUT_MAX_BYTES)
}
