// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The enrollment reader, the verbs and their command line, over the real
//! filesystem in a scratch directory, with the recording double of
//! `protected_dir`'s tests where an order, a failure or a stall is the
//! subject.
//!
//! Every walk passes the filesystem acknowledgement: macOS, where these
//! run first, has no type table. Root-only arms return early when not run
//! as root; their names end in `_as_root`.

mod cli;
mod reader;
mod venue;
mod verbs;

use std::collections::VecDeque;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use granary_core::enrollment::{
    ClientSpkiDigest, EnrollmentSet, PrincipalId, TenantName, encode_set,
};
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};

use super::reader::ReaderOn;
use super::verbs::VerbOptions;
use super::{SET_NAME, TEMP_NAME};
use crate::protected_dir::tests::{Recorder, chmod, scratch};

/// A scratch base holding the enrollment directory `enroll`, mode 0o700.
struct Fx {
    base: PathBuf,
    dir: PathBuf,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = scratch(tag);
        let dir = base.join("enroll");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o700);
        Self { base, dir }
    }

    fn set_path(&self) -> PathBuf {
        self.dir.join(SET_NAME)
    }

    /// The file's bytes, or `None` when there is none.
    fn bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.set_path()).ok()
    }

    /// Replace the set by a rename of a fresh file (a new inode), 0o600.
    fn put(&self, set: &EnrollmentSet) {
        self.put_bytes(encode_set(set).as_bytes());
    }

    fn put_bytes(&self, bytes: &[u8]) {
        let temp = self.base.join("put.tmp");
        std::fs::write(&temp, bytes).unwrap();
        chmod(&temp, 0o600);
        std::fs::rename(&temp, self.set_path()).unwrap();
    }

    fn reader(&self, ops: Recorder) -> ReaderOn<Recorder> {
        ReaderOn::open(ops, &self.dir, true, Duration::from_secs(5)).unwrap()
    }
}

const OPTS: VerbOptions = VerbOptions {
    accept_unsupported_filesystem: true,
};

fn digest(n: u8) -> ClientSpkiDigest {
    ClientSpkiDigest::from_bytes([n; 32])
}

fn id(n: u8) -> PrincipalId {
    PrincipalId::from_bytes([n; 16])
}

fn tenant(s: &str) -> TenantName {
    TenantName::parse(s).unwrap()
}

/// A set of one active principal `id(p)` under `t` holding `digest(d)`.
fn one(p: u8, t: &str, d: u8) -> EnrollmentSet {
    let mut set = EnrollmentSet::empty();
    set.mint(id(p), tenant(t), digest(d)).unwrap();
    set
}

/// A door that yields the queued ids in order, then fails.
#[derive(Debug)]
struct Door(VecDeque<[u8; 16]>);

impl Door {
    fn of(ids: &[u8]) -> Self {
        Self(ids.iter().map(|n| [*n; 16]).collect())
    }
}

impl SecureRandom for Door {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        let next = self.0.pop_front().ok_or(EntropyUnavailable)?;
        if dest.len() != next.len() {
            return Err(EntropyUnavailable);
        }
        dest.copy_from_slice(&next);
        Ok(())
    }
}

/// A door that writes half of what it is asked for, then fails.
#[derive(Debug)]
struct PartialDoor;

impl SecureRandom for PartialDoor {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        let half = dest.len() / 2;
        for b in dest.iter_mut().take(half) {
            *b = 0xAA;
        }
        Err(EntropyUnavailable)
    }
}

/// Run `fut` to completion on a current-thread runtime with a timer.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(fut)
}

/// Make a FIFO at `path`.
fn fifo(path: &Path) {
    nix::unistd::mkfifo(path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
}

/// The temporary's name, for the order assertions.
fn temp() -> String {
    TEMP_NAME.to_owned()
}

/// The inode of `path`.
fn ino(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).unwrap().ino()
}

/// Open `path` for an in-place rewrite.
fn open_rw(path: &Path) -> File {
    std::fs::OpenOptions::new().write(true).open(path).unwrap()
}
