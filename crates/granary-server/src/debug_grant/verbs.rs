// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Grant policy under the enrollment directory's flock. Publication uses
//! the same protected replacement as enrollment; show is a lock-free read.

use std::fs::File;
use std::io;
use std::path::Path;

use granary_core::clock::Clock;
use granary_core::debug_grant::{
    BYTE_CEILING_MAX, DURATION_MAX_SECS, DebugGrant, ENCODED_MAX, GrantAction, GrantFields,
    GrantScope, Incarnation, LINE_CEILING_MAX, Owner, Reason, decode_grant, encode_grant,
};
use granary_core::enrollment::PrincipalState;
use granary_core::sheaf::Timestamp;

use crate::enrollment::{Identity, ReadOutcome, VerbOptions, Verdict, read_set};
use crate::protected_dir::{DirOps, ProtectedDir, ProtectionError, is_link_refusal, judge_file};
use crate::protected_replace::{self, ReplaceError, Stages};

pub(super) const NAME: &str = "DEBUG-GRANT";
pub(super) const TEMP: &str = "DEBUG-GRANT.tmp";
const STAGES: Stages = Stages {
    lock: "locking the enrollment directory",
    cleanup: "removing a leftover DEBUG-GRANT.tmp",
    create: "creating DEBUG-GRANT.tmp",
    chown: "giving DEBUG-GRANT.tmp to the directory's owner",
    chmod: "setting DEBUG-GRANT.tmp mode to 0600",
    write: "writing DEBUG-GRANT.tmp",
    file_sync: "syncing DEBUG-GRANT.tmp",
    rename: "renaming DEBUG-GRANT.tmp over DEBUG-GRANT",
    dir_sync: "syncing the enrollment directory",
    parent_sync: "syncing the enrollment directory's parent",
};

#[derive(Debug)]
pub(super) enum Error {
    Refused(&'static str),
    Directory(ProtectionError),
    Unwritten {
        during: &'static str,
        source: io::Error,
    },
    Uncertain {
        during: &'static str,
        source: io::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(code) => write!(f, "refused, nothing written: {code}"),
            Self::Directory(e) => write!(f, "refused, nothing written: {e}"),
            Self::Unwritten { during, source } => {
                write!(f, "refused, nothing written: {during}: {source}")
            }
            Self::Uncertain { during, source } => write!(
                f,
                "{during}: {source}; publication may be visible; run show before retrying"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Directory(e) => Some(e),
            Self::Unwritten { source, .. } | Self::Uncertain { source, .. } => Some(source),
            Self::Refused(_) => None,
        }
    }
}

impl From<ReplaceError> for Error {
    fn from(e: ReplaceError) -> Self {
        match e {
            ReplaceError::Directory(e) => Self::Directory(e),
            ReplaceError::Unwritten { during, source } => Self::Unwritten { during, source },
            ReplaceError::Io { during, source } => Self::Uncertain { during, source },
        }
    }
}

fn read_error(source: io::Error) -> Error {
    Error::Unwritten {
        during: "reading DEBUG-GRANT",
        source,
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Expected {
    pub(super) incarnation: Incarnation,
    pub(super) revision: u64,
}

#[derive(Debug, Clone)]
pub(super) struct Issue {
    pub(super) scope: GrantScope,
    pub(super) duration: u64,
    pub(super) lines: u64,
    pub(super) bytes: u64,
    pub(super) owner: Owner,
    pub(super) reason: Reason,
}

#[derive(Debug, Clone)]
pub(super) struct Narrow {
    pub(super) generation: u64,
    pub(super) scope: GrantScope,
    pub(super) expires_at: Timestamp,
    pub(super) lines: u64,
    pub(super) bytes: u64,
}

#[derive(Debug, Clone)]
pub(super) enum Mutation {
    Issue(Issue),
    Narrow(Narrow),
    Revoke { generation: u64 },
}

pub(super) fn mutate_on(
    ops: &impl DirOps,
    dir: &Path,
    options: VerbOptions,
    expected: Expected,
    mutation: &Mutation,
    clock: &dyn Clock,
) -> Result<DebugGrant, Error> {
    let (protected, lock) =
        protected_replace::locked(ops, dir, options.accept_unsupported_filesystem, &STAGES)?;
    // The lock must refer to the walked directory still named by the operator.
    let at_path = ops.stat_path(dir).map_err(|source| Error::Unwritten {
        during: "checking the directory path",
        source,
    })?;
    if !protected.stat.same_directory(&at_path) {
        return Err(Error::Refused("directory-replaced"));
    }
    protected_replace::cleanup(ops, &protected, TEMP, &STAGES)?;
    let current = read(ops, &protected)?;
    let revision = current.as_ref().map_or(0, |g| g.fields().file_revision);
    if revision != expected.revision {
        return Err(Error::Refused("revision-mismatch"));
    }
    let next_revision = revision
        .checked_add(1)
        .ok_or(Error::Refused("revision-overflow"))?;
    let grant = match mutation {
        Mutation::Issue(issue) => issue_record(
            ops,
            &protected,
            expected,
            next_revision,
            current.as_ref(),
            issue,
            clock,
        )?,
        Mutation::Narrow(narrow) => {
            let old = existing(current.as_ref(), expected, narrow.generation)?;
            let grant = narrow_record(old, next_revision, narrow, clock)?;
            if matches!(&old.fields().scope, GrantScope::Volume(_)) {
                check_principal(ops, &protected, &narrow.scope)?;
            }
            grant
        }
        Mutation::Revoke { generation } => {
            let old = existing(current.as_ref(), expected, *generation)?;
            if old.fields().action == GrantAction::Revoke {
                return Err(Error::Refused("revoked"));
            }
            let mut fields = old.fields().clone();
            fields.file_revision = next_revision;
            fields.action = GrantAction::Revoke;
            validated(fields)?
        }
    };
    let encoded = encode_grant(&grant);
    if decode_grant(encoded.as_bytes()).as_ref() != Ok(&grant) {
        return Err(Error::Refused("self-check"));
    }
    protected_replace::publish(
        ops,
        &protected,
        (TEMP, NAME),
        encoded.as_bytes(),
        current.is_none(),
        &STAGES,
    )?;
    drop(lock);
    Ok(grant)
}

fn checked_now(clock: &dyn Clock) -> Result<Timestamp, Error> {
    let now = clock.now();
    if !now.is_valid() {
        return Err(Error::Refused("invalid-clock"));
    }
    Ok(now)
}

fn validated(fields: GrantFields) -> Result<DebugGrant, Error> {
    DebugGrant::new(fields).map_err(|_| Error::Refused("invalid-record"))
}

fn issue_record(
    ops: &impl DirOps,
    protected: &ProtectedDir,
    expected: Expected,
    revision: u64,
    current: Option<&DebugGrant>,
    issue: &Issue,
    clock: &dyn Clock,
) -> Result<DebugGrant, Error> {
    if !(1..=u64::try_from(DURATION_MAX_SECS).unwrap_or(0)).contains(&issue.duration) {
        return Err(Error::Refused("duration-bound"));
    }
    if !(1..=LINE_CEILING_MAX).contains(&issue.lines)
        || !(1024..=BYTE_CEILING_MAX).contains(&issue.bytes)
    {
        return Err(Error::Refused("issuance-budget"));
    }
    let now = checked_now(clock)?;
    if let Some(old) = current {
        let f = old.fields();
        if f.incarnation == expected.incarnation
            && f.action != GrantAction::Revoke
            && now < f.expires_at
        {
            return Err(Error::Refused("live-grant"));
        }
    }
    check_principal(ops, protected, &issue.scope)?;
    let generation = current
        .map_or(0, |g| g.fields().grant_generation)
        .checked_add(1)
        .ok_or(Error::Refused("generation-overflow"))?;
    let seconds = i64::try_from(issue.duration).map_err(|_| Error::Refused("duration-bound"))?;
    let expires_at = Timestamp {
        secs: now
            .secs
            .checked_add(seconds)
            .ok_or(Error::Refused("timestamp-overflow"))?,
        nanos: now.nanos,
    };
    validated(GrantFields {
        incarnation: expected.incarnation,
        file_revision: revision,
        grant_generation: generation,
        action: GrantAction::Issue,
        issuer_uid: protected.euid,
        owner: issue.owner.clone(),
        reason: issue.reason.clone(),
        issued_at: now,
        expires_at,
        scope: issue.scope.clone(),
        line_ceiling: issue.lines,
        byte_ceiling: issue.bytes,
    })
}

fn check_principal(
    ops: &impl DirOps,
    protected: &ProtectedDir,
    scope: &GrantScope,
) -> Result<(), Error> {
    let principal = match scope {
        GrantScope::Principal(p) | GrantScope::Conjunction { principal: p, .. } => p,
        GrantScope::Volume(_) => return Ok(()),
    };
    let set = match read_set(ops, &protected.dir, protected.owner()) {
        ReadOutcome::Loaded {
            verdict: Verdict::Set(set),
            ..
        } => set,
        ReadOutcome::Io(source) => {
            return Err(Error::Unwritten {
                during: "reading ENROLLMENT",
                source,
            });
        }
        _ => return Err(Error::Refused("enrollment-unavailable")),
    };
    match set.principal(principal) {
        Some((PrincipalState::Active, _)) => Ok(()),
        Some((PrincipalState::Retired, _)) => Err(Error::Refused("principal-retired")),
        None => Err(Error::Refused("principal-absent")),
    }
}

fn existing(
    current: Option<&DebugGrant>,
    expected: Expected,
    generation: u64,
) -> Result<&DebugGrant, Error> {
    let grant = current.ok_or(Error::Refused("missing-grant"))?;
    let f = grant.fields();
    if f.incarnation != expected.incarnation {
        return Err(Error::Refused("incarnation-mismatch"));
    }
    if f.grant_generation != generation {
        return Err(Error::Refused("generation-mismatch"));
    }
    Ok(grant)
}

fn narrow_record(
    old: &DebugGrant,
    revision: u64,
    narrow: &Narrow,
    clock: &dyn Clock,
) -> Result<DebugGrant, Error> {
    let f = old.fields();
    if f.action == GrantAction::Revoke {
        return Err(Error::Refused("revoked"));
    }
    let now = checked_now(clock)?;
    if now >= f.expires_at {
        return Err(Error::Refused("expired"));
    }
    if !included(&narrow.scope, &f.scope) {
        return Err(Error::Refused("scope-widening"));
    }
    if narrow.expires_at > f.expires_at {
        return Err(Error::Refused("expiry-extension"));
    }
    if narrow.lines > f.line_ceiling || narrow.bytes > f.byte_ceiling {
        return Err(Error::Refused("budget-increase"));
    }
    if narrow.scope == f.scope
        && narrow.expires_at == f.expires_at
        && narrow.lines == f.line_ceiling
        && narrow.bytes == f.byte_ceiling
    {
        return Err(Error::Refused("unchanged"));
    }
    let mut fields = f.clone();
    fields.file_revision = revision;
    fields.action = GrantAction::Narrow;
    fields.scope = narrow.scope.clone();
    fields.expires_at = narrow.expires_at;
    fields.line_ceiling = narrow.lines;
    fields.byte_ceiling = narrow.bytes;
    validated(fields)
}

pub(super) fn included(new: &GrantScope, old: &GrantScope) -> bool {
    match (old, new) {
        (
            GrantScope::Principal(a),
            GrantScope::Principal(b) | GrantScope::Conjunction { principal: b, .. },
        ) => a == b,
        (
            GrantScope::Volume(a),
            GrantScope::Volume(b) | GrantScope::Conjunction { volume: b, .. },
        ) => a == b,
        (
            GrantScope::Conjunction {
                principal: a,
                volume: av,
            },
            GrantScope::Conjunction {
                principal: b,
                volume: bv,
            },
        ) => a == b && av == bv,
        _ => false,
    }
}

pub(super) fn show_on(
    ops: &impl DirOps,
    dir: &Path,
    options: VerbOptions,
) -> Result<Option<DebugGrant>, Error> {
    let protected = ProtectedDir::for_verb(ops, dir, options.accept_unsupported_filesystem)
        .map_err(Error::Directory)?;
    read(ops, &protected)
}

/// The descriptor-backed content verdict shared by verbs and the reader.
/// I/O failures never enter the reader's held-verdict cache.
pub(super) enum FileRead {
    Missing,
    Link,
    Io(io::Error),
    Loaded {
        file: File,
        identity: Identity,
        verdict: Result<Vec<u8>, &'static str>,
    },
}

fn read(ops: &impl DirOps, protected: &ProtectedDir) -> Result<Option<DebugGrant>, Error> {
    match read_file(ops, protected) {
        FileRead::Missing => Ok(None),
        FileRead::Link => Err(Error::Refused("grant-symlink")),
        FileRead::Io(error) => Err(read_error(error)),
        FileRead::Loaded { verdict, .. } => {
            let bytes = verdict.map_err(Error::Refused)?;
            decode_grant(&bytes)
                .map(Some)
                .map_err(|_| Error::Refused("grant-corrupt"))
        }
    }
}

/// Bounded before allocation, descriptor-relative, no-follow and nonblocking.
pub(super) fn read_file(ops: &impl DirOps, protected: &ProtectedDir) -> FileRead {
    let file = match ops.open_read_at(&protected.dir, NAME) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return FileRead::Missing,
        Err(e) if is_link_refusal(&e) => return FileRead::Link,
        Err(e) => return FileRead::Io(e),
    };
    let stat = match ops.fstat(&file) {
        Ok(stat) => stat,
        Err(e) => return FileRead::Io(e),
    };
    let identity = Identity::of(&stat);
    let verdict = if judge_file(&stat, protected.owner()).is_err() {
        Err("grant-unprotected")
    } else if stat.mode & 0o077 != 0 {
        Err("grant-accessible")
    } else if let Some(size) = usize::try_from(stat.size)
        .ok()
        .filter(|&n| n <= ENCODED_MAX)
    {
        let bytes = match read_exactly(ops, &file, size) {
            Ok(bytes) => bytes,
            Err(e) => return FileRead::Io(e),
        };
        let after = match ops.fstat(&file) {
            Ok(stat) => stat,
            Err(e) => return FileRead::Io(e),
        };
        if identity == Identity::of(&after) {
            Ok(bytes)
        } else {
            Err("grant-changed")
        }
    } else {
        Err("grant-oversize")
    };
    FileRead::Loaded {
        file,
        identity,
        verdict,
    }
}

fn read_exactly(ops: &impl DirOps, file: &File, size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; size];
    let mut filled = 0;
    while filled < size {
        let rest = bytes
            .get_mut(filled..)
            .ok_or_else(|| io::Error::other("inconsistent read"))?;
        match ops.read_at(file, rest, u64::try_from(filled).unwrap_or(u64::MAX)) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let mut probe = [0];
    loop {
        match ops.read_at(file, &mut probe, u64::try_from(size).unwrap_or(u64::MAX)) {
            Ok(0) => return Ok(bytes),
            Ok(_) => return Err(io::Error::other("file grew during read")),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}
