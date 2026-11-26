// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local verbs over a protected scratch directory and the recording `DirOps`
//! double, with fixed clock readings and complete decoded-byte assertions.

mod cli;
mod protection;
mod reader;
mod verbs;

use std::path::PathBuf;

use granary_core::clock::Clock;
use granary_core::debug_grant::{
    DebugGrant, GrantAction, GrantFields, GrantScope, Incarnation, Owner, Reason, encode_grant,
};
use granary_core::enrollment::{
    ClientSpkiDigest, EnrollmentSet, PrincipalId, TenantName, encode_set,
};
use granary_core::root::VolumeName;
use granary_core::sheaf::Timestamp;

use super::verbs::{Error, Expected, Issue, Mutation, NAME, Narrow, mutate_on};
use crate::enrollment::VerbOptions;
use crate::protected_dir::NixOps;
use crate::protected_dir::tests::{chmod, scratch};

struct Fx {
    base: PathBuf,
    dir: PathBuf,
}
impl Fx {
    fn new() -> Self {
        let base = scratch("debug-grant");
        let dir = base.join("enroll");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o700);
        Self { base, dir }
    }
    fn bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.dir.join(NAME)).ok()
    }
    fn put_bytes(&self, bytes: &[u8]) {
        std::fs::write(self.dir.join(NAME), bytes).unwrap();
        chmod(&self.dir.join(NAME), 0o600);
    }
    fn put(&self, grant: &DebugGrant) {
        self.put_bytes(encode_grant(grant).as_bytes());
    }
    fn enrollment(&self, retired: bool) {
        let mut set = EnrollmentSet::empty();
        let digest = ClientSpkiDigest::from_bytes([1; 32]);
        set.mint(id(1), TenantName::parse("acme").unwrap(), digest)
            .unwrap();
        if retired {
            set.revoke(&digest).unwrap();
            set.retire(&id(1)).unwrap();
        }
        let path = self.dir.join("ENROLLMENT");
        std::fs::write(&path, encode_set(&set).as_bytes()).unwrap();
        chmod(&path, 0o600);
    }
}
impl Drop for Fx {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.base);
    }
}

struct Fixed(Timestamp);
impl Clock for Fixed {
    fn now(&self) -> Timestamp {
        self.0
    }
}
const NOW: Fixed = Fixed(Timestamp {
    secs: 100,
    nanos: 123,
});
const OPTIONS: VerbOptions = VerbOptions {
    accept_unsupported_filesystem: true,
};
fn id(n: u8) -> PrincipalId {
    PrincipalId::from_bytes([n; 16])
}
fn volume(s: &str) -> VolumeName {
    VolumeName::from_bytes(s.as_bytes()).unwrap()
}
fn incarnation() -> Incarnation {
    Incarnation::from_bytes([0x42; 16])
}
fn expected(revision: u64) -> Expected {
    Expected {
        incarnation: incarnation(),
        revision,
    }
}
fn base(scope: GrantScope) -> DebugGrant {
    DebugGrant::new(GrantFields {
        incarnation: incarnation(),
        file_revision: 4,
        grant_generation: 2,
        action: GrantAction::Issue,
        issuer_uid: 987,
        owner: Owner::from_bytes(b"operator").unwrap(),
        reason: Reason::from_bytes(b"incident").unwrap(),
        issued_at: NOW.0,
        expires_at: Timestamp {
            secs: 700,
            nanos: 123,
        },
        scope,
        line_ceiling: 50,
        byte_ceiling: 50_000,
    })
    .unwrap()
}
fn issue(scope: GrantScope) -> Mutation {
    Mutation::Issue(Issue {
        scope,
        duration: 600,
        lines: 50,
        bytes: 50_000,
        owner: Owner::from_bytes(b"operator").unwrap(),
        reason: Reason::from_bytes(b"incident").unwrap(),
    })
}
fn narrow(scope: GrantScope) -> Narrow {
    Narrow {
        generation: 2,
        scope,
        expires_at: Timestamp {
            secs: 700,
            nanos: 123,
        },
        lines: 49,
        bytes: 50_000,
    }
}
fn apply(
    fx: &Fx,
    expected: Expected,
    mutation: &Mutation,
    clock: &dyn Clock,
) -> Result<DebugGrant, Error> {
    mutate_on(&NixOps, &fx.dir, OPTIONS, expected, mutation, clock)
}
#[track_caller]
fn refused(result: Result<impl std::fmt::Debug, Error>, code: &str) -> Error {
    assert!(
        matches!(&result, Err(Error::Refused(got)) if *got == code),
        "expected refusal {code}, got {result:?}"
    );
    result.unwrap_err()
}
