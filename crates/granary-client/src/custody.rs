// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Private-key custody on load: opening a private key file that this
//! process will trust, and judging it on the descriptor it reads through.
//!
//! **Failure domain.** A key file another user can read has leaked its
//! key; one another user can write, or one reached through a link they
//! planted, is a key they chose. Either way the credential is no longer
//! the operator's.
//!
//! [`open_private_key`] is the one load path. It opens the file once,
//! without following a symlink and without blocking on a FIFO, and refuses
//! a descriptor that is not a regular file with exactly one link. Then, on
//! that same descriptor:
//!
//! - its owner must be the effective uid the caller names;
//! - its mode must grant nothing to group or other (`mode & 0o077 == 0`);
//!   a mode stricter than `0600`, such as `0400`, is accepted;
//! - on macOS, no extended ACL entry may grant access to it.
//!
//! What was opened is what was judged, and what the caller reads: no check
//! here goes back to the path. Creating a key, and anything a caller keeps
//! beside it, is the caller's.
//!
//! The ACL check runs on macOS only. Linux POSIX.1e ACLs make the group mode
//! bits the ACL mask, so the mode check already sees a grant there; `NFSv4`
//! ACLs presented by a Linux client do not, and that residual is not closed
//! here.

use std::fs::File;
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use crate::fsguard::open_sole_regular_read;

/// Open the private key file at `path` for reading, refusing it unless it is
/// in the custody this module describes.
///
/// `euid` is the process's effective uid, as the caller's credential
/// snapshot read it: the file must be owned by it. `noun` names the file in
/// a refusal (`"seed"`, `"key"`).
///
/// The returned descriptor is the one every check was made on; read the key
/// through it.
///
/// # Errors
///
/// The refusal, naming `path`: the file is missing or cannot be opened, is a
/// symlink, is not a regular file, has more than one link, is owned by
/// another uid, grants group or other any access, or carries a granting ACL
/// (or its ACLs cannot be inspected).
pub fn open_private_key(path: &Path, euid: u32, noun: &str) -> Result<File, String> {
    let file = open_sole_regular_read(path, &format!("a private {noun}"))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.uid() != euid {
        return Err(format!(
            "{}: {noun} is owned by uid {}, but the running uid is {euid} — a private key owned \
             by another user is refused rather than trusted",
            path.display(),
            metadata.uid(),
        ));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{}: {noun} permissions are {mode:03o}, want 0600 — a private key readable or \
             writable by group/other is refused rather than trusted. Run: chmod 600 {}",
            path.display(),
            path.display()
        ));
    }
    refuse_granting_acl_on_fd(file.as_fd(), path, &format!("a private {noun}"))?;
    Ok(file)
}

/// macOS extended-ACL inspection: the one audited FFI boundary for it.
///
/// `pub` so the CLI's custody tests can drive its classifiers directly;
/// no caller outside this crate uses it otherwise.
#[cfg(target_vendor = "apple")]
#[doc(hidden)]
#[expect(
    unsafe_code,
    reason = "macOS extended ACL inspection requires direct libSystem FFI; this module is the \
              single audited boundary for its declarations and calls"
)]
pub mod acl {
    use std::ffi::{CStr, CString};
    use std::io;
    use std::os::fd::{AsRawFd as _, BorrowedFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    type Acl = *mut libc::c_void;
    type AclEntry = *mut libc::c_void;

    const ACL_TYPE_EXTENDED: libc::c_uint = 256;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_NEXT_ENTRY: libc::c_int = -1;
    const ACL_UNDEFINED_TAG: libc::c_uint = 0;
    const ACL_EXTENDED_ALLOW: libc::c_uint = 1;
    const ACL_EXTENDED_DENY: libc::c_uint = 2;

    // SAFETY: these declarations exactly match the macOS SDK ABI: ACL and ACL-entry handles are
    // opaque pointers, acl_type_t and acl_tag_t are unsigned int, and acl_get_entry's entry_id is
    // a plain int. libSystem owns the symbols and Rust already links it on Apple targets.
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_uint) -> Acl;
        fn acl_get_link_np(path: *const libc::c_char, acl_type: libc::c_uint) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut AclEntry) -> libc::c_int;
        fn acl_get_tag_type(entry: AclEntry, tag_type: *mut libc::c_uint) -> libc::c_int;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    enum AclObject<'a> {
        Path(&'a CStr),
        Fd(BorrowedFd<'a>),
    }

    /// Why an ACL walk stopped short of the last entry.
    #[derive(Debug)]
    pub enum WalkFailure {
        /// `acl_get_tag_type` failed.
        Tag(io::Error),
        /// An entry carried a tag that is neither allow nor deny.
        UnexpectedTag(libc::c_uint),
        /// `acl_get_entry` failed for a reason other than exhaustion.
        Entry(io::Error),
    }

    /// The classification of a non-zero `acl_get_entry` return.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EntryWalkOutcome {
        /// `-1` with `errno == EINVAL`: the walk is done, not broken.
        Exhausted,
        /// Any other non-zero return, or `-1` with any other errno: the
        /// walk itself failed and the path must be refused. Carries the
        /// raw errno so the caller can build the refusal's `io::Error`.
        Failed(libc::c_int),
    }

    /// Classifies a non-zero `acl_get_entry` return as either normal walk
    /// exhaustion or an ACL-walk failure that must refuse the path.
    /// `errno` must be the value captured immediately after the call that
    /// produced `ret` (before any allocation, formatting, or further FFI
    /// call). This function performs no FFI itself — deliberately, so a
    /// table test can reach every row without a live ACL — but that also
    /// means it cannot check its own precondition.
    ///
    /// **Precondition, from `acl_get_entry(3)`**
    /// (`$(xcrun --show-sdk-path)/usr/share/man/man3/acl_get_entry.3`): the
    /// man page documents `acl_get_entry` returning `0` on success and
    /// `-1` otherwise (the reversed-from-POSIX convention is documented,
    /// not merely observed), and names three conditions that produce `-1`
    /// with `errno == EINVAL`:
    ///   - (a) `acl` does not point to a valid ACL;
    ///   - (b) `entry_id` is neither `ACL_FIRST_ENTRY`, `ACL_NEXT_ENTRY`,
    ///     nor a valid entry index;
    ///   - (c) `entry_id` is `ACL_NEXT_ENTRY` and the last entry has
    ///     already been returned.
    ///
    /// Only (c) is exhaustion. Classifying `-1`/`EINVAL` as
    /// [`EntryWalkOutcome::Exhausted`] is sound ONLY when the caller
    /// independently guarantees:
    ///   - `acl` came from a getter call that itself already succeeded
    ///     (rules out (a)); and
    ///   - `entry_id` was passed as `ACL_FIRST_ENTRY` or `ACL_NEXT_ENTRY`,
    ///     never a raw index (rules out (b)).
    ///
    /// Both hold at this module's only call site, in `refuse_granting_acl`:
    /// the loop reaches this classifier only after a getter call that did
    /// not report an error, and `entry_id` there is only ever
    /// `ACL_FIRST_ENTRY` or `ACL_NEXT_ENTRY` — asserted at that call site
    /// in debug builds, since this function's `(ret, errno)`-only
    /// signature cannot see the handle or the selector to check them
    /// itself. A future caller that walks by raw index, or that reuses
    /// this classifier for a different, not-yet-validated ACL handle,
    /// would silently re-enter the same fail-open the selector checks
    /// prevent, and this function alone cannot stop it.
    ///
    /// One more case: `ACL_FIRST_ENTRY` against a zero-entry ACL is
    /// observed on this platform to also return `-1`/`EINVAL`, but it
    /// matches none of (a)/(b)/(c) by name — `entry_id` there *is*
    /// `ACL_FIRST_ENTRY`, so it is not (b), and it is not
    /// `ACL_NEXT_ENTRY`, so it is not (c) either. This classifier still
    /// treats it as `Exhausted`, which is the semantically correct
    /// outcome (an ACL with no entries grants nothing), but it is an
    /// accept reached through an arm the man page describes only as an
    /// error path, not as "no entries". It is NOT reachable through this
    /// module's getters and no test covers it: `acl_get_link_np` and
    /// `acl_get_fd_np` return NULL with `ENOENT` for a path carrying no
    /// extended ACL, which the caller answers before any entry walk
    /// begins. A non-NULL zero-entry ACL exists only in memory, from
    /// `acl_init(0)`, which this module never constructs.
    #[must_use]
    pub fn walk_step_outcome(ret: libc::c_int, errno: libc::c_int) -> EntryWalkOutcome {
        if ret == -1 && errno == libc::EINVAL {
            EntryWalkOutcome::Exhausted
        } else {
            EntryWalkOutcome::Failed(errno)
        }
    }

    /// Maps a classified `acl_get_entry` step to the walk-failure state
    /// the loop accumulates. Pure and FFI-free, so a test can drive it
    /// with a synthetic [`EntryWalkOutcome::Failed`] and assert that a
    /// failure is not silently dropped — the mutation this guards against
    /// is the call site no longer wiring `Failed` through to
    /// `walk_failure`, which is the same fail-open shape the classifier
    /// prevents, one layer up at the call site instead.
    #[must_use]
    pub fn walk_failure_for_entry_walk_outcome(outcome: EntryWalkOutcome) -> Option<WalkFailure> {
        match outcome {
            EntryWalkOutcome::Exhausted => None,
            EntryWalkOutcome::Failed(errno) => {
                Some(WalkFailure::Entry(io::Error::from_raw_os_error(errno)))
            }
        }
    }

    /// Debug-only precondition checks for `walk_step_outcome`, plus the
    /// classify-and-wire call. Split out of `refuse_granting_acl` only to
    /// stay under the function-length lint; this is exactly what that
    /// call site does for a non-zero `acl_get_entry` return. `acl` is
    /// only compared for nullness here, never dereferenced -- no `unsafe`
    /// needed.
    fn walk_failure_for_entry_step(
        acl: Acl,
        entry_id: libc::c_int,
        ret: libc::c_int,
        errno: libc::c_int,
    ) -> Option<WalkFailure> {
        debug_assert!(
            !acl.is_null(),
            "acl_get_entry(3) condition (a): handle must be valid"
        );
        debug_assert!(
            entry_id == ACL_FIRST_ENTRY || entry_id == ACL_NEXT_ENTRY,
            "acl_get_entry(3) condition (b): entry_id must be a named selector, got {entry_id}"
        );
        walk_failure_for_entry_walk_outcome(walk_step_outcome(ret, errno))
    }

    /// Refuse `path` (not followed) if an extended ACL entry grants access
    /// to it, or if its ACLs cannot be inspected.
    ///
    /// # Errors
    ///
    /// The refusal, naming `path`.
    pub fn refuse_granting_acl_at_path(path: &Path) -> Result<(), String> {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            format!(
                "{}: cannot inspect ACLs because the path contains a NUL byte; refusing private \
                 key material",
                path.display()
            )
        })?;
        refuse_granting_acl(
            &AclObject::Path(&c_path),
            path,
            "private key material",
            false,
        )
        .map_err(AclRefusal::into_message)
    }

    /// Refuse the open file `fd` if an extended ACL entry grants access to
    /// it, or if its ACLs cannot be inspected; `shown` names it.
    ///
    /// # Errors
    ///
    /// The refusal, naming `shown`.
    pub fn refuse_granting_acl_on_fd(
        fd: BorrowedFd<'_>,
        shown: &Path,
        what: &str,
    ) -> Result<(), String> {
        refuse_granting_acl(&AclObject::Fd(fd), shown, what, false)
            .map_err(AclRefusal::into_message)
    }

    /// Refuse granting ACLs on a store root or ancestor, advising removal of
    /// only the granting entry so protective deny entries survive.
    ///
    /// # Errors
    /// The refusal, naming `shown`, if any entry grants access or inspection fails.
    pub fn refuse_granting_directory_acl_on_fd(
        fd: BorrowedFd<'_>,
        shown: &Path,
        what: &str,
    ) -> Result<(), String> {
        refuse_granting_acl(&AclObject::Fd(fd), shown, what, true).map_err(AclRefusal::into_message)
    }

    /// Classify an ACL getter's failure: `ENOENT` means the object carries
    /// no ACL; anything else refuses, naming `shown`.
    ///
    /// # Errors
    ///
    /// The refusal, for every failure but `ENOENT`.
    pub fn classify_acl_get_failure(error: &io::Error, shown: &Path) -> Result<(), String> {
        classify_acl_get_failure_for(error, shown, "private key material")
            .map_err(AclRefusal::into_message)
    }

    pub(crate) enum AclRefusal {
        Foreign(String),
        Io(String),
    }

    impl AclRefusal {
        fn into_message(self) -> String {
            match self {
                Self::Foreign(message) | Self::Io(message) => message,
            }
        }
    }

    pub(crate) fn inspect_discard_acl(
        fd: BorrowedFd<'_>,
        directory: bool,
    ) -> Result<(), AclRefusal> {
        refuse_granting_acl(
            &AclObject::Fd(fd),
            Path::new("overlay discard evidence"),
            "discard evidence",
            directory,
        )
    }

    fn classify_acl_get_failure_for(
        error: &io::Error,
        shown: &Path,
        what: &str,
    ) -> Result<(), AclRefusal> {
        match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(()),
            Some(libc::EOPNOTSUPP) => Err(AclRefusal::Foreign(format!(
                "{}: the volume cannot report ACLs; refusing {what} because \
                 ownership and mode cannot establish exclusive access on this volume",
                shown.display()
            ))),
            _ => Err(AclRefusal::Io(format!(
                "{}: cannot inspect ACLs; refusing {what}: {error}",
                shown.display()
            ))),
        }
    }

    fn refuse_granting_acl(
        object: &AclObject<'_>,
        shown: &Path,
        what: &str,
        preserve_denies: bool,
    ) -> Result<(), AclRefusal> {
        // SAFETY: a path variant holds a valid NUL-terminated string for the duration of the
        // getter, and an fd variant holds a live borrowed descriptor. Neither getter retains its
        // argument. A non-null ACL handle remains valid until exactly one acl_free below; each
        // entry handle is obtained from that live ACL, and all out-pointers are aligned writable
        // locals of the ABI-declared type. No ACL-owned pointer escapes this block.
        unsafe {
            let (acl, get_error) = match object {
                AclObject::Path(path) => {
                    let acl = acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED);
                    let error = if acl.is_null() {
                        // Capture errno before formatting, allocation, or any later FFI call.
                        Some(io::Error::last_os_error())
                    } else {
                        None
                    };
                    (acl, error)
                }
                AclObject::Fd(fd) => {
                    let acl = acl_get_fd_np(fd.as_raw_fd(), ACL_TYPE_EXTENDED);
                    let error = if acl.is_null() {
                        // Capture errno before formatting, allocation, or any later FFI call.
                        Some(io::Error::last_os_error())
                    } else {
                        None
                    };
                    (acl, error)
                }
            };
            if let Some(error) = get_error {
                return classify_acl_get_failure_for(&error, shown, what);
            }

            let mut grants_access = false;
            let mut entry_id = ACL_FIRST_ENTRY;
            // Every exit from this loop names its own `Option<WalkFailure>` via
            // `break`, on purpose: there is no mutable `walk_failure` slot left with a
            // stale default that a dropped arm could leave unset.
            let walk_failure: Option<WalkFailure> = loop {
                let mut entry: AclEntry = std::ptr::null_mut();
                let entry_ret = acl_get_entry(acl, entry_id, &raw mut entry);
                if entry_ret != 0 {
                    // Capture errno immediately, before any allocation, formatting, or
                    // further FFI call, so the classifier sees exactly what this call
                    // left behind.
                    let entry_errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    break walk_failure_for_entry_step(acl, entry_id, entry_ret, entry_errno);
                }
                let mut tag_type = ACL_UNDEFINED_TAG;
                if acl_get_tag_type(entry, &raw mut tag_type) != 0 {
                    // Capture errno before formatting, allocation, or acl_free.
                    break Some(WalkFailure::Tag(io::Error::last_os_error()));
                }
                match tag_type {
                    ACL_EXTENDED_ALLOW => grants_access = true,
                    ACL_EXTENDED_DENY => {}
                    other => break Some(WalkFailure::UnexpectedTag(other)),
                }
                entry_id = ACL_NEXT_ENTRY;
            };

            let free_error = if acl_free(acl) == 0 {
                None
            } else {
                // Capture errno immediately after the failing release call too.
                Some(io::Error::last_os_error())
            };

            if let Some(failure) = walk_failure {
                return match failure {
                    WalkFailure::Tag(error) => Err(AclRefusal::Io(format!(
                        "{}: cannot inspect an ACL entry tag; refusing {what}: \
                         {error}",
                        shown.display()
                    ))),
                    WalkFailure::UnexpectedTag(tag) => Err(AclRefusal::Foreign(format!(
                        "{}: ACL inspection returned unexpected tag {tag}; refusing {what}",
                        shown.display()
                    ))),
                    WalkFailure::Entry(error) => Err(AclRefusal::Io(format!(
                        "{}: the ACL walk failed; refusing {what}: {error}",
                        shown.display()
                    ))),
                };
            }
            if grants_access {
                let remedy = if preserve_denies {
                    format!(
                        "ls -le {} lists entries; remove the granting entry with chmod -a# <index> {}",
                        shown.display(),
                        shown.display()
                    )
                } else {
                    format!("chmod -N {}", shown.display())
                };
                return Err(AclRefusal::Foreign(format!(
                    "{}: an ACL entry grants access; {what} must not carry any ACL ALLOW entry. Run: {remedy}",
                    shown.display(),
                )));
            }
            if let Some(error) = free_error {
                return Err(AclRefusal::Io(format!(
                    "{}: cannot release the inspected ACL; refusing {what}: \
                     {error}",
                    shown.display()
                )));
            }
            Ok(())
        }
    }
}

#[cfg(target_vendor = "apple")]
pub use acl::refuse_granting_acl_at_path;
#[cfg(target_vendor = "apple")]
pub(crate) use acl::refuse_granting_acl_on_fd;
#[cfg(target_vendor = "apple")]
pub(crate) use acl::refuse_granting_directory_acl_on_fd;
#[cfg(target_vendor = "apple")]
pub(crate) use acl::{AclRefusal, inspect_discard_acl};
#[cfg(not(target_vendor = "apple"))]
pub(crate) use refuse_granting_acl_on_fd as refuse_granting_directory_acl_on_fd;

/// Refuse `path` if an extended ACL entry grants access to it: off macOS,
/// nothing to inspect (the module docs say why).
///
/// # Errors
///
/// None off macOS.
#[cfg(not(target_vendor = "apple"))]
// The signature MATCHES the Apple arm deliberately: these are the same two
// functions, and a caller must not be able to tell which target it is on.
// Being exported, it is outside Clippy's `unnecessary_wraps`, which would
// otherwise ask for the `Result` to be dropped on this arm alone.
pub fn refuse_granting_acl_at_path(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_vendor = "apple"))]
// The signature MATCHES the Apple arm deliberately: these are the same two
// functions, and a caller must not be able to tell which target it is on.
// Clippy's `unnecessary_wraps` sees only the arm it is compiling and asks for
// the `Result` to be dropped — which would compile on Linux and break the
// build on macOS. The lint is target-blind here; the signature is not
// negotiable.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Ok-only body is the non-Apple ARM of a two-arm cfg; the Apple \
              arm returns Err and both must share one signature"
)]
pub(crate) fn refuse_granting_acl_on_fd(
    _fd: std::os::fd::BorrowedFd<'_>,
    _shown: &Path,
    _what: &str,
) -> Result<(), String> {
    Ok(())
}
