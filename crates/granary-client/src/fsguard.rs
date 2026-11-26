// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Opening a file under a root this process does not control.
//!
//! Every structural file a store or a cache opens — the marker, the
//! lock, `index/snapshot`, `index/journal`, an object leaf — is named
//! by a path the process REBUILDS, under a directory another user may
//! be able to write into. Two things can be planted at such a name,
//! and the byte caps elsewhere in this crate stop neither:
//!
//! - a **symlink**, which an ordinary open FOLLOWS, so the read (or
//!   the truncating create, for a lock) lands outside the root;
//! - a **FIFO or socket**, on which an `O_RDONLY` open BLOCKS until a
//!   writer appears — and an `O_WRONLY` open blocks until a reader
//!   does. The caller does not fail; it hangs, having reported
//!   nothing. A bound on how many bytes are read is no defence at all
//!   against never reaching the read.
//!
//! So both flags travel together at every such open — `O_NOFOLLOW`
//! for the first, `O_NONBLOCK` for the second — followed by an
//! `fstat` on the OPEN DESCRIPTOR that refuses anything which is not a
//! regular file. The stat is on the descriptor, never a second
//! path-based `lstat`, so what was opened is what was judged.
//!
//! `O_CLOEXEC` is deliberately absent: Rust's std already sets it on
//! every `File`, and a redundant flag invites the next reader to
//! believe it is doing something.
//!
//! **A third plant is a HARD LINK, and it defeats both flags.** It is
//! not a symlink, so `O_NOFOLLOW` does not apply; it does not block,
//! so `O_NONBLOCK` does not apply; and it IS a regular file, so the
//! `fstat` type check passes. `link(2)` needs no read permission on
//! the target and no privilege, and macOS has no `protected_hardlinks`
//! equivalent — this crate's `verify.rs` already establishes all of
//! that for the READ path, where a multiply-linked object is reported
//! `foreign`. The WRITING opens below need the same reasoning, and
//! need it more: a truncating create destroys the target's contents
//! before any check can run, and an appending open writes the cache's
//! journal into it. So both of those refuse a descriptor whose link
//! count is not exactly one, and neither may use `O_TRUNC`, because
//! `O_TRUNC` acts AT OPEN, before any `fstat` exists to consult.
//!
//! **The stated residual is DEVICE NODES.** Linux gives `O_NONBLOCK`
//! no ordinary non-blocking semantics for block devices, and
//! character-device open behaviour is driver-specific, so a device
//! node can still block before the `fstat` runs. Creating one requires
//! `mknod` (root, or `CAP_MKNOD`) — an attacker who already owns the
//! machine, which is outside the trust domain these guards defend:
//! that attacker can write INTO the root, not load kernel drivers.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

mod private_archive;
pub use private_archive::{
    ArchiveSources, MountedNamespace, PrivateArchiveError, PrivateArchiveErrorClass,
    PrivateArchiveParent, PrivateArchiveRefusal, prepare_private_archive_parent, prove_mountpoint,
    publish_private_archive,
};

/// What probing a marker-shaped file found. **A tri-state, because a
/// `bool` cannot say the one thing root-type detection has to know.**
/// "There is no marker of this kind here" lets the OTHER marker decide
/// the root's type; "there is something here I could not read" must
/// refuse the root outright. Collapsed to `false`, an over-cap or
/// unreadable cache marker beside a valid store marker silently
/// selects STORE mode and runs the wrong verification against a
/// directory whose type is genuinely ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkerProbe {
    /// A regular, in-bounds, UTF-8 file whose FIRST line is that
    /// marker's identifying key.
    Present,
    /// Nothing at the path — or a file that is plainly not that marker
    /// (readable, in bounds, first line some other key). Not being a
    /// marker is a different answer from not being readable, and
    /// conflating them would let a stray file refuse a whole root.
    Absent,
    /// Something is there and could not be classified: over the byte
    /// bound, not UTF-8, not a regular file, a symlink, or any other
    /// I/O failure. FAIL CLOSED — never folded into [`Self::Absent`].
    Unreadable,
}

/// Refuse a descriptor that is not a regular file with EXACTLY ONE
/// link. Shared by the private-seed read and structural writes so they
/// cannot drift on the descriptor judgment; `what` keeps each caller's
/// refusal specific without duplicating the guard.
///
/// `nlink != 1` covers both hazards in one comparison and they are not
/// the same hazard. Above one means the name is a HARD LINK to
/// something else: writing through it writes into a file the attacker
/// chose and could not otherwise touch. Zero means the file was
/// unlinked after this descriptor was opened, so the bytes would go to
/// a name nothing can reach — not an attack, but not a lock or a
/// journal either, and refusing costs the caller one retry.
fn refuse_non_sole_regular(f: File, path: &Path, what: &str) -> io::Result<File> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if meta.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} has {} links; {what} must have exactly one",
                path.display(),
                meta.nlink()
            ),
        ));
    }
    Ok(f)
}

fn refuse_non_regular(f: File, path: &Path) -> io::Result<File> {
    if f.metadata()?.is_file() {
        Ok(f)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        ))
    }
}

/// Open `path` for reading with the full discipline (see the module
/// doc). A symlink fails `ELOOP`, a FIFO or socket fails
/// `InvalidData` PROMPTLY rather than blocking, and an absent file
/// still reports `NotFound` so callers can keep distinguishing it.
///
/// # Errors
/// Whatever the open reports (including `NotFound` and `ELOOP`), or
/// `InvalidData` when the opened descriptor is not a regular file.
#[doc(hidden)]
#[expect(
    clippy::disallowed_methods,
    reason = "the guarded READ primitive itself: O_NOFOLLOW refuses a symlink, O_NONBLOCK makes a FIFO \
              or socket fail promptly instead of blocking, and refuse_non_regular fstats the \
              OPEN DESCRIPTOR — so what was opened is what was judged. This IS the form the fs \
              ban points every other call site toward"
)]
pub fn open_regular_read(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    refuse_non_regular(f, path)
}

/// Open an existing directory without following a symlink at its final
/// component. Used when a caller needs the directory descriptor itself,
/// rather than a file beneath it.
///
/// # Errors
/// Whatever the open reports, including `ELOOP` for a symlink and
/// `ENOTDIR` for anything that is not a directory.
#[doc(hidden)]
#[expect(
    clippy::disallowed_methods,
    reason = "the guarded DIRECTORY primitive: O_DIRECTORY refuses anything that is not a directory and \
              O_NOFOLLOW refuses a symlink at the final component, both at open time. The \
              descriptor is used for fsync and dirfd-relative work, never read through"
)]
pub fn open_directory(path: &Path) -> io::Result<File> {
    #[cfg(test)]
    before_directory_open(path);
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(test)]
type DirectoryOpenHook = (std::path::PathBuf, Box<dyn FnOnce()>);

#[cfg(test)]
thread_local! {
    pub(crate) static DIRECTORY_OPEN_HOOK: std::cell::RefCell<Option<DirectoryOpenHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn before_directory_open(path: &Path) {
    let hook = DIRECTORY_OPEN_HOOK.with_borrow_mut(|hook| {
        hook.as_ref()
            .is_some_and(|(target, _)| target == path)
            .then(|| hook.take().unwrap().1)
    });
    if let Some(hook) = hook {
        hook();
    }
}

/// Open `path` for reading with the full discipline and require the
/// opened regular file to have exactly one link. This is the read-side
/// counterpart to the writable structural opens: callers read through
/// the returned descriptor, so the path is resolved only once.
///
/// `what` names the file in a refusal (`"a private seed"`), so the
/// message says which file must not be followed or linked.
///
/// # Errors
/// Whatever the open reports (including `NotFound` and `ELOOP`), or
/// `InvalidData` when the opened descriptor is not a sole regular file.
#[doc(hidden)]
#[expect(
    clippy::disallowed_methods,
    reason = "the guarded SOLE-LINK read primitive: the same O_NOFOLLOW/O_NONBLOCK open, plus \
              refuse_non_sole_regular, which rejects a descriptor whose link count is not one — \
              the hard-link plant O_NOFOLLOW cannot see"
)]
pub fn open_sole_regular_read(path: &Path, what: &str) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} is a symlink; {what} must not be followed",
                        path.display()
                    ),
                )
            } else {
                e
            }
        })?;
    refuse_non_sole_regular(f, path, what)
}

/// Create-or-open `path` as a lock file — write, create, truncate —
/// with mode 0600 on create and reopen when `private`, or the default create
/// mode (0666 filtered by umask) and unchanged reopen permissions otherwise —
/// with the same discipline. `O_NONBLOCK` matters in the OTHER
/// direction here: an `O_WRONLY` open of a FIFO blocks until a READER
/// appears, and with `O_NONBLOCK` it fails `ENXIO` immediately
/// instead. `O_TRUNC` is a no-op on a FIFO, so the `fstat` is what
/// actually refuses one whose reader happens to be present.
///
/// # Errors
/// Whatever the open reports, or `InvalidData` when the opened
/// descriptor is not a regular file.
#[expect(
    clippy::disallowed_methods,
    reason = "the guarded LOCK primitive: deliberately NOT .truncate(true), because O_TRUNC acts at \
              open and would empty a hard-linked victim before any check could refuse it. The \
              file is opened intact, fstatted for regular-and-sole-link, and only then set_len(0). \
              Private store locks use mode 0600 at creation and descriptor chmod on reopen; \
              cache lock and guard files keep default creation and existing permissions"
)]
pub(crate) fn create_regular_lock(path: &Path, private: bool) -> io::Result<File> {
    // NOT `.truncate(true)`: `O_TRUNC` acts at OPEN, so a hard link
    // planted here would be emptied before any check could refuse it.
    // The file is opened intact, judged, and only then truncated.
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(if private { 0o600 } else { 0o666 })
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let f = refuse_non_sole_regular(f, path, "a writable structural file")?;
    if private {
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.set_len(0)?;
    Ok(f)
}

/// Open an EXISTING file for appending with the same discipline. The
/// journal is the caller here, and both halves matter: `O_NOFOLLOW`
/// because a symlink at `index/journal` would otherwise receive every
/// record the cache writes, and `O_NONBLOCK` because an `O_WRONLY`
/// open of a FIFO blocks until a reader appears — and if a reader IS
/// present, the open succeeds and the records go into a pipe instead
/// of a file, which is why the `fstat` refusal is not optional either.
/// Never creates: a caller that needs the file to exist must have
/// written it, so `NotFound` stays a real answer.
///
/// # Errors
/// Whatever the open reports, or `InvalidData` when the opened
/// descriptor is not a regular file.
#[expect(
    clippy::disallowed_methods,
    reason = "the guarded APPEND primitive: O_NOFOLLOW so journal records cannot be written through a \
              symlink, O_NONBLOCK so an O_WRONLY open of a FIFO fails instead of waiting for a \
              reader, and refuse_non_sole_regular for the FIFO-with-a-reader and hard-link \
              cases the flags alone do not cover. Never creates"
)]
pub(crate) fn open_regular_append(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    refuse_non_sole_regular(f, path, "a writable structural file")
}

/// Create `path` as a NEW regular file — write, create, EXCLUSIVE — for
/// a write-then-rename publish (the wire-byte snapshot writers).
/// `O_EXCL` refuses a pre-existing name outright, symlink or otherwise,
/// before `O_NOFOLLOW`'s own refusal would ever get a chance to matter.
///
/// # Errors
/// `AlreadyExists` if `path` is already there, or whatever the open
/// otherwise reports (including `InvalidData` if a hard link or a FIFO
/// somehow still reaches the `fstat` check below).
#[expect(
    clippy::disallowed_methods,
    reason = "the guarded EXCLUSIVE-CREATE primitive: O_CREAT|O_EXCL refuses a pre-existing name outright \
              (symlink or otherwise) before O_NOFOLLOW's own refusal would ever get a chance to matter, and \
              O_NONBLOCK plus refuse_non_sole_regular cover the FIFO/hard-link residual the same way \
              create_regular_lock's do"
)]
pub(crate) fn create_regular_exclusive(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        // `0o600`, not whatever the process umask
        // would otherwise leave. Without an explicit mode, a
        // permissive umask (`000`) leaves `path` world-writable at the
        // moment of creation — a local writer in this directory would
        // not even need to unlink-and-replant to corrupt the body: a
        // plain `O_WRONLY` open of the SAME inode, no `O_CREAT`, would
        // do, and the dev/ino identity check in `publish_regular`
        // passes vacuously because the inode never changed. `0o600`
        // closes that regardless of umask. (The content
        // anchor in `verify_published_body`, added later, would ALSO catch this specific
        // corruption — the bytes it verifies would no longer match
        // what this process wrote — but `0o600` closes the hole at its
        // source rather than relying on that as the only backstop.)
        .mode(0o600)
        .open(path)?;
    refuse_non_sole_regular(f, path, "a new structural file")
}

/// Open an existing singly linked regular file for positional updates.
#[expect(
    clippy::disallowed_methods,
    reason = "guarded update primitive: O_NOFOLLOW and O_NONBLOCK plus descriptor regular/sole-link checks; no creation, truncation or permission repair"
)]
pub(crate) fn open_regular_update(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    refuse_non_sole_regular(file, path, "control state")
}

/// Publish `from` onto `to` after re-verifying `from` is still
/// the sole-linked regular file this process itself just created
/// via [`create_regular_exclusive`] — AND that the PATHNAME `from`
/// still names that SAME verified
/// file at the moment of publish, not merely at the moment of the
/// open above. `to` must not already exist; `hard_link` makes the
/// publish itself the final authority on that (a caller's own
/// earlier `std::fs::symlink_metadata` check, the lstat-backed
/// SAFE half of this module's own banned class — see the module
/// doc — is a fail-fast convenience, not the guarantee).
///
/// **Nothing here is anchored to an `fstat` taken at create time and
/// compared by `(dev, ino)`: THAT ANCHOR IS UNSOUND — see
/// [`verify_published_body`]'s own doc for the mechanism and
/// why. This function verifies against the written bytes; do
/// not "simplify" it to a dev/ino comparison.**
///
/// The pathname check (the `recheck` a few lines down) compares the reopened
/// descriptor against a FRESH `lstat` of the same pathname —
/// self-consistency between two statements of `publish_regular`, and
/// nothing else. What ties the reopened descriptor back to the file
/// THIS PROCESS actually wrote is [`verify_published_body`]: the
/// published artifact is a small JSON snapshot this process rendered
/// moments earlier, so this call reads the reopened descriptor and
/// refuses unless its bytes are EXACTLY `expected_body` — whatever the
/// inode says. That is what refuses a fresh, solitary-linked regular
/// file replanted at `from`'s name (which passes both `O_NOFOLLOW` and
/// the nlink check above): its content differs from what this process
/// wrote, so the comparison fails even when the inode does not.
///
/// # Errors
/// Whatever re-verifying `from`, the content check, the pathname
/// re-check, or `hard_link` itself reports.
/// [`io::ErrorKind::AlreadyExists`] means `to` already existed at
/// the moment of publish. **A failing `remove_file` of `from` AFTER
/// a successful `hard_link` is NOT an error here** (the outcome
/// is explained by [`PublishOutcome`]): `to` is durably
/// published by that point, and a leftover temp name is cleanup
/// debt, logged via typed warning, not a reported failure.
#[expect(
    clippy::disallowed_methods,
    reason = "the guarded PUBLISH primitive: `from` is re-opened and fstatted sole-regular immediately \
              before the publish, closing the TOCTOU between this process's own create and this call \
              (a fresh pathname check narrows the RESIDUAL further, and content verification ties it \
              back to the BYTES this process wrote — see the function body); `hard_link` \
              creates the new NAME at `to` and refuses one that already exists as ONE atomic kernel \
              operation, so there is no window between checking `to` absent and publishing for a \
              concurrent writer to land in — this REPLACES the prior `std::fs::rename`, which on Unix \
              silently overwrites an existing `to` instead of refusing it; `remove_file` clears the \
              now-redundant `from` name once the link has succeeded"
)]
pub(crate) fn publish_regular(from: &Path, to: &Path, expected_body: &[u8]) -> io::Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(from)?;
    let verified = refuse_non_sole_regular(f, from, "a write-then-rename temporary")?;

    // Verify the reopened file's bytes against `expected_body`, not a
    // create-time `(dev, ino)`, which is unsound on a filesystem that
    // recycles inode numbers; `verify_published_body`'s doc says why.
    verify_published_body(&verified, from, expected_body)?;

    // The fstat below judges the OPEN DESCRIPTOR;
    // everything below acts on the PATHNAME `from`, and nothing yet
    // proves the name still resolves to the SAME file in between.
    // NARROWED here, not closed: an `lstat` of `from`, compared by
    // (dev, ino) against the descriptor just verified, catches a
    // directory writer that unlinked and replanted `from` in the
    // interval since — the plant is refused rather than published.
    //
    // The residual is the gap between THIS lstat and the `hard_link`
    // two lines down: two back-to-back syscalls, inside the operator's
    // OWN directory — the same trust boundary this module's doc already
    // draws around every structural open here. There is no safe-Rust
    // primitive that links FROM A DESCRIPTOR rather than a pathname, so
    // this residual cannot be closed further without `unsafe` FFI,
    // which this crate licenses only at the named sites inventoried by
    // scripts/check-unsafe-sites.sh, and does not spend here.
    let verified_meta = verified.metadata()?;
    let recheck = std::fs::symlink_metadata(from)?;
    if !same_identity(&verified_meta, &recheck) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} no longer names the file this process just verified; refusing to publish",
                from.display()
            ),
        ));
    }

    // `hard_link` + `remove_file`, not
    // `std::fs::rename` — see this function's own `#[expect]`
    // reason above for why. `to` appearing after the caller's
    // own `confirmed_absent`-shaped check is therefore
    // REFUSED (`AlreadyExists`), not silently replaced.
    let hard_link_result = std::fs::hard_link(from, to);
    // `remove_file` is only ATTEMPTED once
    // `hard_link` itself succeeded — when `hard_link` fails, `from` is
    // left untouched (the caller's own stale-temp cleanup is
    // the one that decides what happens to it; see `publish_outcome`'s
    // own doc for why this function must not conflate the two).
    let remove_result = if hard_link_result.is_ok() {
        std::fs::remove_file(from)
    } else {
        Ok(())
    };
    let outcome = publish_outcome(hard_link_result, &remove_result);
    if let PublishOutcome::LeftoverTemp = outcome {
        crate::observe::OperatorDiagnostic::wire_snapshot_publish_the_temp_file_could_not_be(
            crate::FailureClass::Io,
        )
        .emit_paths(&[
            crate::observe::PathSlot::Path("from", crate::LogPath::file(from)),
            crate::observe::PathSlot::Path("to", crate::LogPath::file(to)),
        ]);
    }
    outcome.into_result()
}

/// What a [`publish_regular`] attempt
/// resolves to, decided from the ALREADY-TAKEN results of `hard_link`
/// and (only when that succeeded) the follow-up `remove_file` — a pure
/// decision over two `io::Result`s, neither of which this function's
/// own code can influence, so a test can drive the "`hard_link` landed
/// but the temp cleanup failed" branch directly with SYNTHETIC results.
///
/// **A real fixture (a directory this process can create a NEW hard
/// link into but cannot unlink an existing name from) was tried and
/// discarded.** On every filesystem this crate ships for, `link(2)` and
/// `unlink(2)` are gated by the SAME directory-write permission check —
/// so the condition that would make the follow-up `remove_file` fail
/// almost always makes the PRECEDING `hard_link` fail too, which is
/// `Failed` — the refusal a `?` right after `hard_link` would give
/// anyway, for the same underlying reason, at a DIFFERENT call site
/// than the `remove_file` branch decided here. A row built on that
/// fixture could not tell this decision apart from its absence — the
/// exact shape
/// `confirmed_absent`'s own test (in `wire_snapshot.rs`) already
/// documents for an unrelated check.
///
/// **The decision itself:** once `hard_link` succeeds, `to` is
/// published — durable and byte-correct, at that instant. A failing
/// `remove_file` of `from` afterward is cleanup debt, not a publish
/// failure: [`PublishOutcome::LeftoverTemp`] is advisory only, and [`publish_regular`] still returns
/// `Ok(())`. Conflating the two — returning the `remove_file` error
/// directly — would turn a durable success into a reported failure,
/// and a caller that maps that to "not written" would then refuse a
/// RETRY at `to` with `AlreadyExists`, compounding a misreport of a
/// publish that in fact succeeded.
#[derive(Debug)]
enum PublishOutcome {
    /// `hard_link` succeeded and the temp name is gone too.
    Clean,
    /// `hard_link` succeeded; the temp name survives because
    /// `remove_file` failed. The removal failure is advisory only.
    LeftoverTemp,
    /// `hard_link` itself failed — the publish never happened.
    Failed(io::Error),
}

fn publish_outcome(hard_link: io::Result<()>, remove_temp: &io::Result<()>) -> PublishOutcome {
    match hard_link {
        Err(e) => PublishOutcome::Failed(e),
        Ok(()) => match remove_temp {
            Ok(()) => PublishOutcome::Clean,
            Err(_) => PublishOutcome::LeftoverTemp,
        },
    }
}

impl PublishOutcome {
    /// The `Result` [`publish_regular`] itself reports for this outcome
    /// — split out from the typed warning beside its call site so a
    /// test can pin the "`LeftoverTemp` still maps to `Ok`" wiring
    /// directly, independent of the log call. Without this split, a
    /// mutation that swapped `LeftoverTemp`'s arm to `Err` (the
    /// misreport this result mapping prevents) would be caught only by
    /// `publish_outcome`'s OWN unit test, never by anything exercising
    /// `publish_regular` itself — the right mapping and the wrong one
    /// share every visible symptom except the one line that matters, and
    /// this split lets the test distinguish them directly.
    fn into_result(self) -> io::Result<()> {
        match self {
            Self::Clean | Self::LeftoverTemp => Ok(()),
            Self::Failed(e) => Err(e),
        }
    }
}

/// Whether a RE-CHECKED [`std::fs::Metadata`] (an
/// `lstat` of `from` immediately before the publish) still names the
/// SAME file as the metadata [`publish_regular`] already verified
/// through its open descriptor. Factored out to a pure comparison
/// over two REAL `Metadata` values — neither branch's code can
/// influence which — so a test can drive the mismatch directly, the
/// same discipline `wire_snapshot.rs`'s own `confirmed_absent` test
/// uses and documents: the actual race this guards against (a
/// directory writer unlinking and replanting `from` between the fstat
/// and the publish) cannot be landed BETWEEN two statements of one
/// function call from inside a synchronous, single-threaded test.
fn same_identity(verified: &std::fs::Metadata, recheck: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    verified.dev() == recheck.dev() && verified.ino() == recheck.ino()
}

/// **Verify content, not a create-time identity.** Comparing the
/// descriptor `publish_regular` reopens against an `fstat` this process
/// took at [`create_regular_exclusive`] time, by `(dev, ino)`, is
/// **UNSOUND on a filesystem that recycles inode numbers**,
/// and this crate ships for two of them: ext4 and tmpfs both reuse
/// a freed inode for the very next create in the same directory,
/// routinely. A co-tenant that watches for the exclusive create,
/// `unlink`s `from`, and `creat`s a fresh file in its place
/// regularly gets handed back the SAME inode number this process
/// just released — a `(dev, ino)` comparison finds them equal, the
/// reopen's `fstat` matches the create-time one, and the forgery
/// publishes with `Ok(())`, no diagnostic. Under test the replant
/// reproduced on Linux and not on macOS/APFS; the content check below does not
/// depend on either platform's inode behaviour. **Do not "simplify"
/// this check to a dev/ino comparison.**
///
/// The published artifact is a small JSON snapshot this process
/// rendered and wrote to `from` moments earlier, so authorship can be
/// checked directly instead: `f`'s bytes must equal `expected` — the
/// exact bytes [`crate::wire_snapshot::write_body_and_publish`] wrote,
/// kept in memory rather than re-derived. Whatever the inode says, a
/// replant whose content differs is refused.
///
/// **Bounded, not a full read of whatever is at `from`:** the read is
/// capped to `expected.len() + 1` bytes via [`std::io::Read::take`], so
/// a co-tenant that swaps in a huge file at `from`'s name cannot make
/// this call read it in full before refusing — the extra `+ 1` is
/// enough to detect "longer than expected" without needing to know how
/// much longer.
///
/// A fresh file replanted with the IDENTICAL content this process
/// wrote is NOT refused by this check (nor could dev/ino ever have
/// distinguished it from a genuine race either). That is accepted, not
/// missed: the attacker gains nothing from the substitution — the
/// bytes that reach `to` are the bytes this process itself produced,
/// byte for byte. See
/// `publish_regular_allows_a_fresh_regular_file_replanted_at_the_source_name_with_identical_content`
/// for that row, documented directly.
fn verify_published_body(f: &File, path: &Path, expected: &[u8]) -> io::Result<()> {
    use std::io::Read as _;
    let mut buf = Vec::with_capacity(expected.len() + 1);
    f.take(expected.len() as u64 + 1).read_to_end(&mut buf)?;
    if buf != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} does not hold the bytes this process wrote; refusing to publish",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) use tests::testutil;

#[cfg(test)]
mod tests;
