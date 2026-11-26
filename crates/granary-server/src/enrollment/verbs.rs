// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The local verbs that change the enrollment set, as a library.
//!
//! Every verb walks the directory with the verb's protection rule (its
//! effective uid must be the directory's owner `O` or root). [`list`] then
//! reads the set as the server's reader does, taking no lock and creating
//! nothing: the mutating verbs publish only by rename, so a read sees one
//! whole file, old or new.
//!
//! A mutating verb takes an exclusive `flock` on the enrollment directory
//! itself, through the descriptor the walk holds, and keeps it from before
//! it reads the set until after the directory sync. No lock file is
//! created, opened or consulted (a file named `LOCK` left by an earlier
//! build is ignored), so there is nothing a crashed verb can leave behind
//! to block the next one: the kernel drops the lock with the process. The
//! protection rule gives the directory no group or other access, so only
//! `O` and root can open it to hold the lock. Under the lock the verb
//! removes a crashed verb's leftover temporary, reads the set, applies its
//! change in memory, and replaces the file:
//!
//! 1. encode the new set, decode the encoding again and compare (nothing
//!    has touched the disk yet);
//! 2. create `ENROLLMENT.tmp` with `O_CREAT | O_EXCL | O_NOFOLLOW`, mode
//!    0o600; a root-run verb `fchown`s it to `O` and the directory's group
//!    before writing anything, so every file it leaves is the server's to
//!    read;
//! 3. write it all and sync it;
//! 4. `renameat` it over `ENROLLMENT`;
//! 5. sync the directory; when the file was missing before (the first
//!    mint, or a mint after the file was lost), also sync the directory's
//!    parent, through the descriptor the walk held;
//! 6. release the lock and return.
//!
//! An I/O failure before step 4 changed nothing: the verb reports it as
//! [`VerbError::Unwritten`]. A failure from step 4 on is
//! [`VerbError::Io`], never success: the change may or may not be visible,
//! and the operator runs [`list`] before retrying.
//!
//! A verb never overwrites a set it could not read: a corrupt, oversize or
//! unprotected file is refused, nothing written, and the repair is the
//! operator's (restore the file from a backup). Only [`mint`] accepts a
//! missing file, as the empty set.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use granary_core::enrollment::{
    ClientSpkiDigest, EnrollmentSet, MintError, PrincipalId, SetChangeError, SetDecodeError,
    TenantName, WrittenFormError, decode_set, encode_set, mint_principal_id,
};
use granary_core::secure_random::SecureRandom;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;

use crate::protected_replace::{self, ReplaceError, Stages};

use super::{ReadOutcome, SET_NAME, TEMP_NAME, UnavailableReason, Verdict, read_set};
use crate::protected_dir::{DirOps, FileRuleBroken, NixOps, ProtectedDir, ProtectionError};

/// Options every verb takes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerbOptions {
    /// The operator's explicit acknowledgement that a component's
    /// filesystem type is outside the supported table. It lifts the type
    /// refusals of the walk and nothing else.
    pub accept_unsupported_filesystem: bool,
}

/// Why a verb refused: nothing was written.
#[derive(Debug)]
pub enum VerbRefusal {
    /// The directory fails the protection rule.
    Directory(ProtectionError),
    /// There is no set yet, and only `mint` creates one.
    NoSet,
    /// `ENROLLMENT` fails the file rule.
    Unprotected(FileRuleBroken),
    /// `ENROLLMENT` is larger than the largest legal set.
    Oversize {
        /// Its size in bytes.
        size: i64,
    },
    /// `ENROLLMENT` is not a valid set.
    Corrupt(SetDecodeError),
    /// The set refused the change.
    Change(SetChangeError),
    /// No principal id could be minted.
    Mint(MintError),
    /// The new set's encoding did not decode to the same set.
    SelfCheck,
}

impl std::fmt::Display for VerbRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Directory(e) => write!(f, "the enrollment directory is not protected: {e}"),
            Self::NoSet => write!(f, "no enrollment set; mint a principal first"),
            Self::Unprotected(rule) => write!(
                f,
                "{SET_NAME} is {rule}; fix it, or restore it from a backup"
            ),
            Self::Oversize { size } => write!(
                f,
                "{SET_NAME} is {size} bytes, larger than any valid set; restore it from a backup"
            ),
            Self::Corrupt(e) => write!(
                f,
                "{SET_NAME} is not a valid enrollment set ({e}); restore it from a backup"
            ),
            Self::Change(e) => write!(f, "{e}"),
            Self::Mint(e) => write!(f, "no principal was minted: {e}"),
            Self::SelfCheck => write!(
                f,
                "the new set's encoding did not decode to the same set; nothing was written"
            ),
        }
    }
}

/// Why a verb failed.
#[derive(Debug)]
pub enum VerbError {
    /// Refused; nothing was written.
    Refused(VerbRefusal),
    /// An I/O failure before the rename that publishes the change: nothing
    /// was changed.
    Unwritten {
        /// What the verb was doing.
        during: &'static str,
        /// The failure.
        source: io::Error,
    },
    /// An I/O failure from the rename on: the change may or may not be
    /// visible. Run [`list`] before retrying.
    Io {
        /// What the verb was doing.
        during: &'static str,
        /// The failure.
        source: io::Error,
    },
}

impl std::fmt::Display for VerbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "refused, nothing written: {r}"),
            Self::Unwritten { during, source } => {
                write!(f, "I/O failure {during}: {source}; nothing was changed")
            }
            Self::Io { during, source } => write!(
                f,
                "I/O failure {during}: {source}; the change may or may not be visible, run \
                 `list` before retrying"
            ),
        }
    }
}

impl std::error::Error for VerbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(VerbRefusal::Directory(e)) => Some(e),
            Self::Unwritten { source, .. } | Self::Io { source, .. } => Some(source),
            Self::Refused(_) => None,
        }
    }
}

const fn refused(r: VerbRefusal) -> VerbError {
    VerbError::Refused(r)
}

/// An I/O failure before the rename: nothing was changed.
fn unwritten(during: &'static str) -> impl FnOnce(io::Error) -> VerbError {
    move |source| VerbError::Unwritten { during, source }
}

/// What [`list`] found: the verdict the server's reader would reach on the
/// file now, and the set when it is readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListReport {
    /// A valid set.
    Ok(EnrollmentSet),
    /// No set the server would use.
    Unavailable {
        /// The reader's reason.
        reason: UnavailableReason,
        /// The detail, for the operator.
        detail: String,
    },
}

/// Why a `--credential` argument did not name a credential.
#[derive(Debug)]
pub enum CredentialError {
    /// A written form that is not a client-SPKI digest.
    Written(WrittenFormError),
    /// The certificate file could not be read or parsed.
    Certificate {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        detail: String,
    },
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Written(e) => write!(f, "{e}"),
            Self::Certificate { path, detail } => {
                write!(f, "certificate {}: {detail}", path.display())
            }
        }
    }
}

impl std::error::Error for CredentialError {}

/// A credential argument's digest: either its written form
/// (`clientspki-v1:` and 64 lowercase hex), or a PEM certificate file whose
/// first `CERTIFICATE` block is the end-entity certificate, whose complete
/// DER `SubjectPublicKeyInfo` is digested.
///
/// A pasted TLS server pin, root-signing key or key locator is refused with
/// a message naming what it is; anything else without the digest's prefix
/// is read as a path.
///
/// # Errors
/// [`CredentialError`].
pub fn resolve_credential(arg: &OsStr) -> Result<ClientSpkiDigest, CredentialError> {
    if let Some(s) = arg.to_str() {
        match ClientSpkiDigest::parse_written(s) {
            Ok(digest) => return Ok(digest),
            Err(WrittenFormError::WrongPrefix { .. }) => {}
            Err(e) => return Err(CredentialError::Written(e)),
        }
    }
    certificate_digest(Path::new(arg))
}

/// The client-SPKI digest of the first certificate in a PEM file.
fn certificate_digest(path: &Path) -> Result<ClientSpkiDigest, CredentialError> {
    let failed = |detail: String| CredentialError::Certificate {
        path: path.to_path_buf(),
        detail,
    };
    let mut certificates =
        CertificateDer::pem_file_iter(path).map_err(|e| failed(e.to_string()))?;
    let first = match certificates.next() {
        Some(Ok(cert)) => cert,
        Some(Err(e)) => return Err(failed(e.to_string())),
        None => return Err(failed("holds no CERTIFICATE block".to_owned())),
    };
    granary_net::identity::client_spki_digest(&first)
        .map_err(|e| failed(format!("does not parse: {e}")))
}

/// Mint a principal under `tenant` with `credential` as its first
/// credential. Its id is sixteen bytes from `door`, redrawn while it
/// equals any principal record, active or retired. A missing set is the
/// empty set.
///
/// # Errors
/// [`VerbError`]: refused (nothing written) when the credential is already
/// enrolled, at a bound, when `door` fails, or when the directory or the
/// set fails its checks; an I/O failure otherwise.
pub fn mint(
    dir: &Path,
    options: VerbOptions,
    tenant: &TenantName,
    credential: ClientSpkiDigest,
    door: &mut impl SecureRandom,
) -> Result<(PrincipalId, ClientSpkiDigest), VerbError> {
    mint_on(&NixOps, dir, options, tenant, credential, door)
}

/// Attach `credential` to the existing active principal `principal`.
///
/// # Errors
/// [`VerbError`]: refused when the principal is absent or retired, the
/// credential is enrolled, at the bound, or with no set.
pub fn attach(
    dir: &Path,
    options: VerbOptions,
    principal: PrincipalId,
    credential: ClientSpkiDigest,
) -> Result<(PrincipalId, ClientSpkiDigest), VerbError> {
    attach_on(&NixOps, dir, options, principal, credential)
}

/// Revoke `credential`. Answers the principal it was enrolled to, whose
/// record stays active.
///
/// # Errors
/// [`VerbError`]: refused when the credential is not enrolled, or with no
/// set.
pub fn revoke(
    dir: &Path,
    options: VerbOptions,
    credential: ClientSpkiDigest,
) -> Result<(PrincipalId, ClientSpkiDigest), VerbError> {
    revoke_on(&NixOps, dir, options, credential)
}

/// Retire `principal` for good. Its record is kept, so its id is never
/// minted again.
///
/// # Errors
/// [`VerbError`]: refused when the principal is absent, already retired,
/// or still holds a credential, or with no set.
pub fn retire(
    dir: &Path,
    options: VerbOptions,
    principal: PrincipalId,
) -> Result<PrincipalId, VerbError> {
    retire_on(&NixOps, dir, options, principal)
}

/// What the server's reader would find in the set now, with the same walk,
/// type check, protection check and decode. Takes no lock and creates
/// nothing (module docs).
///
/// # Errors
/// [`VerbError`] when the directory fails its checks. A file the reader
/// would refuse is an [`ListReport::Unavailable`], not an error.
pub fn list(dir: &Path, options: VerbOptions) -> Result<ListReport, VerbError> {
    list_on(&NixOps, dir, options)
}

pub(crate) fn mint_on(
    ops: &impl DirOps,
    dir: &Path,
    options: VerbOptions,
    tenant: &TenantName,
    credential: ClientSpkiDigest,
    door: &mut impl SecureRandom,
) -> Result<(PrincipalId, ClientSpkiDigest), VerbError> {
    mutate(ops, dir, options, true, |set| {
        if set.lookup(&credential).is_some() {
            return Err(VerbRefusal::Change(SetChangeError::CredentialEnrolled));
        }
        let id = mint_principal_id(door, set).map_err(VerbRefusal::Mint)?;
        set.mint(id, tenant.clone(), credential)
            .map_err(VerbRefusal::Change)?;
        Ok((id, credential))
    })
}

pub(crate) fn attach_on(
    ops: &impl DirOps,
    dir: &Path,
    options: VerbOptions,
    principal: PrincipalId,
    credential: ClientSpkiDigest,
) -> Result<(PrincipalId, ClientSpkiDigest), VerbError> {
    mutate(ops, dir, options, false, |set| {
        set.attach(principal, credential)
            .map_err(VerbRefusal::Change)?;
        Ok((principal, credential))
    })
}

pub(crate) fn revoke_on(
    ops: &impl DirOps,
    dir: &Path,
    options: VerbOptions,
    credential: ClientSpkiDigest,
) -> Result<(PrincipalId, ClientSpkiDigest), VerbError> {
    mutate(ops, dir, options, false, |set| {
        let principal = set
            .lookup(&credential)
            .map(|(p, _)| p)
            .ok_or(VerbRefusal::Change(SetChangeError::CredentialNotEnrolled))?;
        set.revoke(&credential).map_err(VerbRefusal::Change)?;
        Ok((principal, credential))
    })
}

pub(crate) fn retire_on(
    ops: &impl DirOps,
    dir: &Path,
    options: VerbOptions,
    principal: PrincipalId,
) -> Result<PrincipalId, VerbError> {
    mutate(ops, dir, options, false, |set| {
        set.retire(&principal).map_err(VerbRefusal::Change)?;
        Ok(principal)
    })
}

pub(crate) fn list_on(
    ops: &impl DirOps,
    dir: &Path,
    options: VerbOptions,
) -> Result<ListReport, VerbError> {
    let protected = ProtectedDir::for_verb(ops, dir, options.accept_unsupported_filesystem)
        .map_err(|e| refused(VerbRefusal::Directory(e)))?;
    let outcome = read_set(ops, &protected.dir, protected.owner());
    Ok(match outcome.outcome() {
        Ok(set) => ListReport::Ok(EnrollmentSet::clone(set)),
        Err(reason) => ListReport::Unavailable {
            reason,
            detail: describe(&outcome),
        },
    })
}

/// What a read found, in the operator's words.
fn describe(outcome: &ReadOutcome) -> String {
    match outcome {
        ReadOutcome::Missing => format!("no {SET_NAME} file; mint a principal first"),
        ReadOutcome::Link => format!("{SET_NAME} is {}", FileRuleBroken::Link),
        ReadOutcome::Io(e) => e.to_string(),
        ReadOutcome::Loaded { verdict, .. } => match verdict {
            Verdict::Set(_) => format!("{SET_NAME} is a valid set"),
            Verdict::Unprotected(rule) => format!("{SET_NAME} is {rule}"),
            Verdict::Oversize { size } => {
                format!("{SET_NAME} is {size} bytes, larger than any valid set")
            }
            Verdict::Corrupt(e) => e.to_string(),
        },
    }
}

const STAGES: Stages = Stages {
    lock: "locking the enrollment directory",
    cleanup: "removing a leftover ENROLLMENT.tmp",
    create: "creating ENROLLMENT.tmp",
    chown: "giving ENROLLMENT.tmp to the directory's owner",
    chmod: "setting ENROLLMENT.tmp mode to 0600",
    write: "writing ENROLLMENT.tmp",
    file_sync: "syncing ENROLLMENT.tmp",
    rename: "renaming ENROLLMENT.tmp over ENROLLMENT",
    dir_sync: "syncing the enrollment directory",
    parent_sync: "syncing the enrollment directory's parent",
};

impl From<ReplaceError> for VerbError {
    fn from(error: ReplaceError) -> Self {
        match error {
            ReplaceError::Directory(e) => refused(VerbRefusal::Directory(e)),
            ReplaceError::Unwritten { during, source } => Self::Unwritten { during, source },
            ReplaceError::Io { during, source } => Self::Io { during, source },
        }
    }
}

/// Run one change under the exclusive lock and replace the file (module
/// docs). `allow_missing` lets a missing file stand for the empty set.
fn mutate<T>(
    ops: &impl DirOps,
    dir: &Path,
    options: VerbOptions,
    allow_missing: bool,
    change: impl FnOnce(&mut EnrollmentSet) -> Result<T, VerbRefusal>,
) -> Result<T, VerbError> {
    let (protected, lock) =
        protected_replace::locked(ops, dir, options.accept_unsupported_filesystem, &STAGES)?;
    protected_replace::cleanup(ops, &protected, TEMP_NAME, &STAGES)?;
    let (mut set, was_missing) = match read_set(ops, &protected.dir, protected.owner()) {
        ReadOutcome::Missing if allow_missing => (EnrollmentSet::empty(), true),
        ReadOutcome::Missing => return Err(refused(VerbRefusal::NoSet)),
        ReadOutcome::Link => return Err(refused(VerbRefusal::Unprotected(FileRuleBroken::Link))),
        ReadOutcome::Io(e) => return Err(unwritten("reading ENROLLMENT")(e)),
        ReadOutcome::Loaded { verdict, .. } => match verdict {
            Verdict::Set(set) => (Arc::unwrap_or_clone(set), false),
            Verdict::Unprotected(rule) => return Err(refused(VerbRefusal::Unprotected(rule))),
            Verdict::Oversize { size } => return Err(refused(VerbRefusal::Oversize { size })),
            Verdict::Corrupt(e) => return Err(refused(VerbRefusal::Corrupt(e))),
        },
    };
    let value = change(&mut set).map_err(refused)?;
    replace(ops, &protected, &set, was_missing)?;
    drop(lock);
    Ok(value)
}

/// Steps 1 to 5 of the module docs.
fn replace(
    ops: &impl DirOps,
    protected: &ProtectedDir,
    set: &EnrollmentSet,
    was_missing: bool,
) -> Result<(), VerbError> {
    let encoded = encode_set(set);
    match decode_set(encoded.as_bytes()) {
        Ok(back) if back == *set => {}
        _ => return Err(refused(VerbRefusal::SelfCheck)),
    }
    protected_replace::publish(
        ops,
        protected,
        (TEMP_NAME, SET_NAME),
        encoded.as_bytes(),
        was_missing,
        &STAGES,
    )
    .map_err(VerbError::from)
}
