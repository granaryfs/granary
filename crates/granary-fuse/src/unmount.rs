// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Linux `umount2(2)` path, implementing libfuse's own unmount shape.
//!
//! **The reason this exists at all**: `fuser` 0.18's own unmount
//! calls plain `umount(2)` and only falls back on `EPERM`, holds the
//! `/dev/fuse` fd open across the call, and `Drop for Mount` merely
//! `warn!`s on failure — so a busy root unmount returns `EBUSY` and
//! the daemon exits 0 with the mount still in place. Closing the fd
//! first is the caller's job; this file owns the syscall.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus};

use nix::errno::Errno;
use nix::mount::{MntFlags, umount2};

/// The `fusermount` helper binaries this module may run, in the order it
/// tries them, as ABSOLUTE paths — never bare names.
///
/// **Why absolute, and why a fixed list.** `Command::new("fusermount3")`
/// resolves the name through the process's INHERITED `PATH`. `gran
/// umount` can run as root (a root-owned systemd unit, or a `sudo`
/// invocation that keeps the caller's environment), and if `PATH` then
/// begins with any directory the caller can write, an attacker-supplied
/// binary is executed with this process's credentials. Even an
/// UNPRIVILEGED fake is a defect on its own: one that simply exits `0`
/// reproduces exactly the false-success this whole module exists to
/// prevent — `detach_unmount` would report the mount detached having
/// detached nothing.
///
/// The list is a compile-time constant for the same reason it is not an
/// environment variable (the way `fuser`'s own `FUSERMOUNT_PATH` is) and
/// not a public parameter: a gate whose set the caller picks is not a
/// gate. [`fusermount_lazy_unmount_with`] takes the list as an argument
/// so this module's tests (now `unmount/tests.rs`) can drive it with fakes, and it is private —
/// the only production call site is [`fusermount_lazy_unmount`], which
/// passes this constant and nothing else.
///
/// Both spellings of both names are listed because `/bin` is a symlink
/// to `/usr/bin` on merged-`/usr` distributions and a real directory on
/// the rest, and because a mount created through `fuser`'s legacy
/// `fusermount` binary-name resolution can only be detached by also
/// trying that name (see [`detach_unmount`]'s doc comment).
const FUSERMOUNT_CANDIDATES: &[&str] = &[
    "/usr/bin/fusermount3",
    "/bin/fusermount3",
    "/usr/bin/fusermount",
    "/bin/fusermount",
];

/// Failure detaching the mount at a target path.
#[derive(Debug)]
pub enum UnmountError {
    /// The target could not be resolved to an absolute path (this never
    /// touches the filesystem — [`std::path::absolute`] is lexical only —
    /// so the only realistic cause is `getcwd(2)` failing on a relative
    /// target, e.g. because the current directory was itself removed).
    AbsolutePath(std::io::Error),
    /// The absolute target does not end in an ordinary named component:
    /// it is a root (`/`, `//`) or it ends in `..`. Neither names a
    /// mountpoint this function is willing to act on — `gran umount /`
    /// is not a thing this function does, and a `..`-terminated spelling
    /// asks the kernel to re-resolve the path in a way the parent check
    /// below cannot vouch for.
    NoFinalComponent {
        /// The lexically-absolute form of the caller's input.
        requested: PathBuf,
    },
    /// `std::fs::canonicalize` on the target's PARENT directory failed —
    /// most commonly because the parent does not exist.
    ///
    /// **The parent, never the target.** The target is a FUSE mountpoint
    /// and may be wedged; see [`detach_unmount`]'s doc comment for why
    /// nothing on the path to the syscall is allowed to stat it.
    CanonicalizeParent {
        /// The lexical parent that could not be resolved.
        parent: PathBuf,
        /// Why it could not be resolved.
        source: std::io::Error,
    },
    /// The target's parent directory is not its own canonical form: its
    /// fully symlink- and `..`-resolved spelling does not byte-for-byte
    /// match the lexical one. A symlink anywhere in the ancestor chain,
    /// or a `..` component, produces exactly this — and neither is safe
    /// to unmount through, because `UMOUNT_NOFOLLOW` protects only the
    /// FINAL component and the kernel traverses ancestors regardless.
    ParentNotCanonical {
        /// The lexically-absolute form of the caller's input.
        requested: PathBuf,
        /// The lexical parent of that input.
        lexical_parent: PathBuf,
        /// What that parent actually resolves to on disk.
        canonical_parent: PathBuf,
    },
    /// `umount2(2)` failed with something other than `EPERM` (`EPERM` is
    /// not an error here — it is what routes to the `fusermount3`/
    /// `fusermount` fallback below, the same shape libfuse itself uses).
    Umount2(Errno),
    /// `umount2(2)` returned `EPERM`, so the fallback was needed, and
    /// none of the fixed absolute helper paths in `FUSERMOUNT_CANDIDATES`
    /// exists on this system. `PATH` is deliberately NOT consulted, so
    /// "the helper is installed somewhere else" is reported here rather
    /// than papered over by running whatever `PATH` happens to name.
    NoFusermountHelper {
        /// Every candidate path that was looked for and not found.
        searched: Vec<PathBuf>,
    },
    /// Every `fusermount` helper that exists on this system was tried and
    /// none detached the mount. Each attempt is carried separately,
    /// naming the absolute binary it ran, rather than collapsing to
    /// whichever failed last.
    FusermountFallbackFailed {
        /// One entry per helper that was actually run, in the order run.
        attempts: Vec<FusermountAttempt>,
    },
}

/// One `<helper> -u -z -- <target>` run that did not detach the mount.
#[derive(Debug)]
pub struct FusermountAttempt {
    /// The absolute path of the helper binary this attempt ran. Reported
    /// so a caller (and this module's own tests) can see that the binary
    /// came from `FUSERMOUNT_CANDIDATES` and not from `PATH`.
    pub binary: PathBuf,
    /// How the attempt failed.
    pub outcome: FusermountOutcome,
}

/// The two ways one `fusermount` helper run can fail.
#[derive(Debug)]
pub enum FusermountOutcome {
    /// The binary could not be spawned (it vanished between the
    /// existence check and the spawn, or is not executable).
    Spawn(std::io::Error),
    /// The binary ran and exited reporting failure.
    Failed(ExitStatus),
}

impl fmt::Display for FusermountOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FusermountOutcome::Spawn(err) => write!(f, "could not be started: {err}"),
            FusermountOutcome::Failed(status) => write!(f, "exited with {status}"),
        }
    }
}

impl fmt::Display for FusermountAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.binary.display(), self.outcome)
    }
}

impl fmt::Display for UnmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnmountError::AbsolutePath(err) => {
                write!(f, "could not resolve the target to an absolute path: {err}")
            }
            UnmountError::NoFinalComponent { requested } => write!(
                f,
                "refusing to unmount {}: it does not name a mountpoint -- it is a filesystem \
                 root, or it ends in `..`, and neither is something this command unmounts",
                requested.display()
            ),
            UnmountError::CanonicalizeParent { parent, source } => write!(
                f,
                "could not resolve the target's parent directory {} to its canonical \
                 (symlink-free) form: {source}",
                parent.display()
            ),
            UnmountError::ParentNotCanonical {
                requested,
                lexical_parent,
                canonical_parent,
            } => write!(
                f,
                "refusing to unmount {}: its parent directory {} resolves to {}, which is a \
                 different path -- a symlink somewhere in the ancestor chain, or a `..` \
                 component, would produce exactly this mismatch, and neither is safe to \
                 unmount through",
                requested.display(),
                lexical_parent.display(),
                canonical_parent.display()
            ),
            UnmountError::Umount2(errno) => write!(f, "umount2 failed: {errno}"),
            UnmountError::NoFusermountHelper { searched } => {
                write!(
                    f,
                    "umount2 was refused and no fusermount helper is installed at any of the \
                     paths this command will run ("
                )?;
                for (index, path) in searched.iter().enumerate() {
                    if index > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", path.display())?;
                }
                write!(
                    f,
                    "); PATH is deliberately not searched, because this command can run as root"
                )
            }
            UnmountError::FusermountFallbackFailed { attempts } => {
                write!(f, "no fusermount helper detached the mount:")?;
                for (index, attempt) in attempts.iter().enumerate() {
                    if index > 0 {
                        write!(f, ";")?;
                    }
                    write!(f, " {attempt}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for UnmountError {}

/// Splits `target` into a canonical parent directory and a final
/// component, and returns the two joined back together — the path
/// `umount2(2)` will be given.
///
/// **The mountpoint itself is never touched.** See [`detach_unmount`]'s
/// doc comment: this is the whole point of the function.
fn resolve_target(target: &Path) -> Result<PathBuf, UnmountError> {
    // Lexical only: `std::path::absolute` reads `getcwd(2)` for a
    // relative input and otherwise performs no filesystem access at all.
    let requested = std::path::absolute(target).map_err(UnmountError::AbsolutePath)?;

    // Split lexically. `Components` normalises away trailing separators
    // and `.` components as it iterates, so `/mnt/gran/` and `/mnt/gran`
    // both yield the same (parent, final) pair -- which is what removes
    // the trailing-separator bypass entirely rather than trying to
    // detect it: the path handed to the kernel below is rebuilt from the
    // pair and can no longer carry a trailing separator. `..` and a
    // bare root are the two spellings with no ordinary final component,
    // and both are refused.
    let (lexical_parent, final_component) = {
        let mut components = requested.components();
        match components.next_back() {
            Some(Component::Normal(name)) => {
                (components.as_path().to_path_buf(), name.to_os_string())
            }
            _ => {
                return Err(UnmountError::NoFinalComponent {
                    requested: requested.clone(),
                });
            }
        }
    };

    // The ONE filesystem access on the path to the syscall, and it is on
    // the PARENT: an ordinary directory on an ordinary filesystem, not
    // the FUSE mountpoint.
    let canonical_parent = std::fs::canonicalize(&lexical_parent).map_err(|source| {
        UnmountError::CanonicalizeParent {
            parent: lexical_parent.clone(),
            source,
        }
    })?;
    if canonical_parent != lexical_parent {
        return Err(UnmountError::ParentNotCanonical {
            requested,
            lexical_parent,
            canonical_parent,
        });
    }

    Ok(canonical_parent.join(final_component))
}

/// Detaches the FUSE mount at `target`, following libfuse's own shape:
/// `umount2(target, MNT_DETACH | UMOUNT_NOFOLLOW)` first, and on `EPERM`
/// — which is what an unprivileged caller always gets from the raw
/// syscall on Linux — the setuid `fusermount3 -u -z --` helper, and if
/// THAT fails too, the plain `fusermount -u -z --` alias (fuser's own
/// mount path resolves either name — see `FUSERMOUNT_BIN`/
/// `FUSERMOUNT3_BIN` in fuser's `fuse_pure.rs` — so a mount made through
/// the legacy binary can only ever be detached by also trying it here).
/// The helpers are run from the fixed absolute paths in
/// `FUSERMOUNT_CANDIDATES`, never through `PATH`.
///
/// `target` is resolved to an absolute path FIRST, before any of that.
/// This is not cosmetic: a relative, `-`-leading spelling (e.g. `-V`)
/// passed bare to `fusermount3` is parsed as an option rather than a
/// path — so a successful option invocation need not unmount anything.
/// Resolving to an absolute path means a `-`-leading spelling cannot
/// arise at all (an absolute path always starts with `/`); the
/// `--` terminator on every fallback call below is the second,
/// independent line of defence.
///
/// # The path guard: canonicalise the PARENT, never the target
///
/// The absolute target is split into a parent directory and a final
/// component, the PARENT is canonicalised, and the canonical parent is
/// required to match the lexical one byte for byte. The syscall is then
/// given `canonical_parent.join(final_component)`.
///
/// **Nothing on the path to the syscall stats the mountpoint**, and that
/// is a hard requirement, not an optimisation. The target of a `gran
/// umount` is by definition a FUSE mountpoint, and it may be wedged:
/// once its daemon dies, is killed, or deadlocks, anything reaching INTO
/// the filesystem either fails with `ENOTCONN` (the connection was
/// aborted) or never returns at all (the connection is up and nobody is
/// answering). Both shapes were built and measured directly, in a
/// privileged container with `/dev/fuse`: on an aborted mount `lstat`
/// returns `ENOTCONN`; on an unanswered one `lstat` hangs until killed.
/// A userspace probe of the target on the way to the syscall would
/// therefore turn "recover a wedged mount" — the single case a lazy
/// forced unmount exists for — into an error or a hang. The kernel's own
/// `umount2` path resolution stops AT the mountpoint instead of entering
/// the filesystem, so the syscall is safe on a wedged mount; only
/// userspace probing of the target is not.
///
/// The guard canonicalises only the parent, so recovery does not depend
/// on how `realpath` inspects a potentially wedged mountpoint.
///
/// What the parent comparison is guarding against: `gran umount` can run
/// as root against a mountpoint under a user-writable directory, and
/// `UMOUNT_NOFOLLOW` only protects the FINAL path component — the kernel
/// still traverses symlinks in every intermediate component, and
/// `std::path::absolute` is lexical, so it neither resolves nor rejects a
/// symlinked ancestor. An unprivileged user who owns any ancestor could
/// otherwise replace it with a symlink and choose which mount the root
/// process detaches. Requiring the parent to be its own canonical form
/// rejects a symlink ANYWHERE in the ancestor chain and any `..`
/// component in one comparison. `UMOUNT_NOFOLLOW` then guards the final
/// component, which is exactly and only what that flag does — so between
/// them the whole path is covered.
///
/// A trailing separator is handled by construction rather than by
/// detection. `std::path::absolute` preserves a trailing `/`, and the
/// kernel then dereferences a symlinked final component DESPITE
/// `UMOUNT_NOFOLLOW` (measured: `umount2("/tmp/link", NOFOLLOW)` is
/// refused with `EINVAL`; the same call on `"/tmp/link/"` dereferences
/// the symlink and succeeds). The split above discards the separator —
/// the path passed to the syscall is rebuilt from a parent and a single
/// component and cannot carry one — so the bypass has no spelling left.
///
/// # The residual, which is NOT closed
///
/// The parent comparison is a check-then-use. The check runs, and then
/// `umount2(2)` resolves the path again for itself; between those two
/// moments an attacker who owns an ancestor directory can swap that
/// component. **This is not a one-shot race they have to win on the
/// first try.** Nothing stops them exchanging a real directory and a
/// symlink in a loop, as fast as the kernel will let them, and
/// re-running that loop on every invocation of `gran umount` until one
/// lands. What the comparison buys is that a symlink planted and left in
/// place is refused outright, and that the window they must hit is
/// microseconds wide instead of unbounded. That raises the cost and
/// narrows the window. It does not close the class.
///
/// The complete fix is a resolution primitive that binds the check and
/// the use to the same object: `openat2(2)` with `RESOLVE_NO_SYMLINKS`
/// (nix 0.31.3 exposes this safely as `nix::fcntl::openat2`, `OpenHow`
/// and `ResolveFlag`; `unsafe` is therefore NOT the obstacle for this
/// option), or
/// a component-wise `O_NOFOLLOW | O_DIRECTORY` walk ending in an
/// operation relative to the resulting directory fd. Neither is taken,
/// for one reason: **`umount2(2)` takes a PATH, not a file descriptor.**
/// There is no `fumount2` and no `AT_`-style variant, so an fd obtained
/// by a symlink-free resolution cannot be handed to the syscall. Getting
/// back to a path means `/proc/self/fd/N` or a `fchdir`-relative
/// spelling, and this module has NOT established that either preserves
/// the binding through `umount2`'s own `LOOKUP_MOUNTPOINT` resolution
/// (and `fchdir` is process-global state this function cannot assume it
/// owns exclusively). Until that is established and tested, the residual
/// stands, and it is an ancestor-directory TOCTOU.
///
/// The second layer lives outside this function and is `gran
/// umount`'s ALONE: its pre-flight verifies the target is a genuine
/// gran mount (`findmnt -rno TARGET,FSTYPE,SOURCE`, on `SOURCE`) just
/// before this call; the daemon's shutdown detach has none. A second
/// check-then-use, so it narrows the window without closing it.
///
/// # Errors
///
/// Returns [`UnmountError`] if the target cannot be resolved to an
/// absolute path, does not end in an ordinary named component, has a
/// parent that cannot be canonicalised or is not already its own
/// canonical form, or if neither `umount2` nor any installed
/// `fusermount` helper detaches the mount.
pub fn detach_unmount(target: &Path) -> Result<(), UnmountError> {
    let resolved = resolve_target(target)?;
    match umount2(&resolved, MntFlags::MNT_DETACH | MntFlags::UMOUNT_NOFOLLOW) {
        Ok(()) => Ok(()),
        Err(Errno::EPERM) => fusermount_lazy_unmount(&resolved),
        Err(errno) => Err(UnmountError::Umount2(errno)),
    }
}

/// Runs `<binary> -u -z -- <target>`, reporting which of the two ways it
/// can fail to detach the mount.
fn try_fusermount(binary: &Path, target: &Path) -> Result<(), FusermountOutcome> {
    let status = Command::new(binary)
        .arg("-u")
        .arg("-z")
        .arg("--")
        .arg(target)
        .status()
        .map_err(FusermountOutcome::Spawn)?;
    if status.success() {
        Ok(())
    } else {
        Err(FusermountOutcome::Failed(status))
    }
}

/// The production fallback: the fixed `FUSERMOUNT_CANDIDATES` list and
/// nothing else.
///
/// `target` must already have been through [`resolve_target`]: this
/// function does no path resolution of its own, and the helper binaries
/// have no `UMOUNT_NOFOLLOW` equivalent — they need the guarded path
/// even more than the raw `umount2` call does.
fn fusermount_lazy_unmount(target: &Path) -> Result<(), UnmountError> {
    fusermount_lazy_unmount_with(FUSERMOUNT_CANDIDATES, target)
}

/// The mechanism behind [`fusermount_lazy_unmount`], with the candidate
/// list as a parameter so this module's tests (`unmount/tests.rs`) can drive it with fake
/// helpers instead of planting binaries on `PATH`.
///
/// PRIVATE ON PURPOSE. The production call site passes the fixed
/// constant, and no public seam lets a caller choose the binary — a gate
/// whose set the caller picks is not a gate.
///
/// A candidate that is not ABSOLUTE is refused rather than run: that is
/// what makes "`PATH` is never consulted" a property of this mechanism
/// rather than a property of how the constant happens to be spelled
/// today. A candidate that does not exist is skipped, so an
/// installation carrying only one of the two helper names reports the
/// real failure of the one it has, not a spawn error for the one it does
/// not.
fn fusermount_lazy_unmount_with(candidates: &[&str], target: &Path) -> Result<(), UnmountError> {
    let mut attempts = Vec::new();
    let mut searched = Vec::new();
    for candidate in candidates {
        let binary = PathBuf::from(candidate);
        if !binary.is_absolute() || !binary.exists() {
            searched.push(binary);
            continue;
        }
        match try_fusermount(&binary, target) {
            Ok(()) => return Ok(()),
            Err(outcome) => attempts.push(FusermountAttempt { binary, outcome }),
        }
    }
    if attempts.is_empty() {
        Err(UnmountError::NoFusermountHelper { searched })
    } else {
        Err(UnmountError::FusermountFallbackFailed { attempts })
    }
}

/// Is `path` a mount point right now, according to the kernel?
///
/// `Ok(true)` when field 5 (the mount point) of some `/proc/self/mountinfo`
/// line decodes to exactly `path`'s bytes, `Ok(false)` when no line does,
/// and `Err` when the answer could not be obtained at all — mountinfo
/// unreadable, or a row not in the format the kernel writes.
/// "Could not look" is never reported as "not mounted": every caller in
/// this crate's tests removes a scratch directory on `Ok(false)` ONLY, so a
/// blind check can never license `remove_dir_all` against a possibly-live
/// mount, and a "still mounted" assertion fails loudly on an unreadable
/// mountinfo rather than passing vacuously.
///
/// Shared by this module's tests (out of line at `unmount/tests.rs`) and by
/// `mechanism.rs` (which cannot reach into a `mod tests`), hence file scope,
/// `pub(crate)`, test-only. The row parser is the session-end module's, which
/// production uses to tell whether a session's mount is still listed.
#[cfg(test)]
pub(crate) fn mount_state(path: &Path) -> std::io::Result<bool> {
    let mountinfo = std::fs::read("/proc/self/mountinfo")?;
    crate::session_end::mountinfo_lists(&mountinfo, path)
}

#[cfg(test)]
mod tests;
