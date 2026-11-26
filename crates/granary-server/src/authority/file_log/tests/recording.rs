// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The recording double on the adapter's file-operations seam: every call
//! is delegated to the real one on a scratch directory and recorded, in
//! order, with its result and, for a call on an open file, the unique
//! generation of the description it went through. The double can fail
//! the `n`th sync, script a `pwrite`'s result, plant a file or a link at a
//! name just after its removal, and cut the process dead at any call.
//!
//! The double owns the real operations, which hold the state directory
//! and its lock; a test keeps a [`Tap`] (the record and the script), so
//! the lock goes when the adapter does, as a process's would.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::super::{DirState, FileLogConfigError, FileOps, Held, Kind, StdFileOps};

/// More calls than any test's workload makes: past it the adapter is
/// looping (a write loop that never shrinks its buffer, say), and the
/// test fails instead of hanging.
const CALL_LIMIT: usize = 10_000;

/// One recorded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Call {
    /// The operation's name: `fstatat`, `pwrite`, `sync_file`, ...
    pub(super) op: &'static str,
    /// The name it named in the state directory, if it named one: `state`
    /// for the state directory's own name (its check and its sync), and
    /// `anchor` for its parent's sync.
    pub(super) path: Option<PathBuf>,
    /// The description it went through, if any: its generation.
    pub(super) generation: Option<u64>,
    /// For `pwrite`, the offset and the length asked for.
    pub(super) at: Option<(u64, usize)>,
    /// Whether it returned `Ok`.
    pub(super) ok: bool,
    /// For an event the test adds beside the syscalls (a PUT, a reply, a
    /// record found committed on disk), what it was.
    pub(super) note: Option<String>,
}

/// A scripted `pwrite` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Write {
    /// Write only this many bytes, and say so.
    Short(usize),
    /// Write nothing and return `Interrupted`.
    Interrupted,
    /// Write nothing and return `Ok(0)`.
    Zero,
    /// Write nothing and fail.
    Fail,
}

/// What to plant at a name just after the double removes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Plant {
    File,
    Symlink(PathBuf),
}

/// What the double does beyond delegating.
#[derive(Debug, Default)]
pub(super) struct Script {
    /// Fail the sync (file or directory) with this index, from 0.
    pub(super) fail_sync: Option<usize>,
    /// Scripted results for the next `pwrite`s, in order.
    pub(super) writes: VecDeque<Write>,
    /// After an `unlink` of this path's last component, plant this at
    /// the path.
    pub(super) plant: Option<(PathBuf, Plant)>,
    /// Die at the call with this index, from 0: that call and every one
    /// after it fails without acting.
    pub(super) cut_at: Option<usize>,
}

/// The record and the script, shared with the test.
#[derive(Debug, Default)]
pub(super) struct Shared {
    pub(super) calls: Mutex<Vec<Call>>,
    pub(super) script: Mutex<Script>,
    syncs: Mutex<usize>,
    dead: Mutex<bool>,
}

impl Shared {
    pub(super) fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub(super) fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.script.lock().unwrap()
    }

    /// Add an event beside the syscalls, on the same timeline.
    pub(super) fn event(&self, op: &'static str, note: String) {
        self.calls.lock().unwrap().push(Call {
            op,
            path: None,
            generation: None,
            at: None,
            ok: true,
            note: Some(note),
        });
    }
}

/// A description the double opened: its generation and the real file.
#[derive(Debug)]
pub(super) struct RecFile {
    generation: u64,
    file: std::fs::File,
}

/// A test's handle on a [`Recording`]: its record and its script.
#[derive(Debug, Clone)]
pub(super) struct Tap {
    pub(super) shared: Arc<Shared>,
}

/// The recording double, over the real operations on one state
/// directory.
#[derive(Debug)]
pub(super) struct Recording {
    pub(super) shared: Arc<Shared>,
    generations: AtomicU64,
    real: StdFileOps,
    /// The state directory's name, which the record uses for its check.
    name: PathBuf,
}

impl Recording {
    /// The double over the provisioned state directory at `state`, the
    /// filesystem type acknowledged (the tests' scratch filesystem is
    /// whatever the host's is).
    pub(super) fn new(state: &Path) -> Self {
        Self::open(state, true).unwrap_or_else(|e| panic!("{}: {e}", state.display()))
    }

    /// The double over `state`, or the real operations' refusal.
    pub(super) fn open(state: &Path, accept: bool) -> Result<Self, FileLogConfigError> {
        Ok(Self {
            shared: Arc::new(Shared::default()),
            generations: AtomicU64::new(1),
            real: StdFileOps::open(state, accept)?,
            name: PathBuf::from(state.file_name().unwrap()),
        })
    }

    pub(super) fn tap(&self) -> Tap {
        Tap {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Whether the call about to be made is cut: it and every later one
    /// fail without acting.
    fn cut(&self) -> bool {
        let index = self.shared.calls.lock().unwrap().len();
        let mut dead = self.shared.dead.lock().unwrap();
        if self.shared.script().cut_at == Some(index) {
            *dead = true;
        }
        *dead
    }

    fn record(
        &self,
        op: &'static str,
        path: Option<&Path>,
        generation: Option<u64>,
        at: Option<(u64, usize)>,
        ok: bool,
    ) {
        let made = {
            let mut calls = self.shared.calls.lock().unwrap();
            calls.push(Call {
                op,
                path: path.map(Path::to_path_buf),
                generation,
                at,
                ok,
                note: None,
            });
            calls.len()
        };
        assert!(
            made <= CALL_LIMIT,
            "{made} calls: the adapter is looping (the last was {op})"
        );
    }

    fn dead_error() -> io::Error {
        io::Error::other("the process was cut")
    }

    /// Record `op` on `path`, unless the process is cut.
    fn on_path<T>(
        &self,
        op: &'static str,
        path: &Path,
        act: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        if self.cut() {
            self.record(op, Some(path), None, None, false);
            return Err(Self::dead_error());
        }
        let out = act();
        self.record(op, Some(path), None, None, out.is_ok());
        out
    }

    /// Whether this sync is the one to fail, counting it.
    fn fail_this_sync(&self) -> bool {
        let mut syncs = self.shared.syncs.lock().unwrap();
        let index = *syncs;
        *syncs += 1;
        self.shared.script().fail_sync == Some(index)
    }

    fn open_file(
        &self,
        op: &'static str,
        path: &Path,
        act: impl FnOnce() -> io::Result<std::fs::File>,
    ) -> io::Result<RecFile> {
        if self.cut() {
            self.record(op, Some(path), None, None, false);
            return Err(Self::dead_error());
        }
        match act() {
            Ok(file) => {
                let generation = self.generations.fetch_add(1, Ordering::SeqCst);
                self.record(op, Some(path), Some(generation), None, true);
                Ok(RecFile { generation, file })
            }
            Err(e) => {
                self.record(op, Some(path), None, None, false);
                Err(e)
            }
        }
    }
}

impl FileOps for Recording {
    type File = RecFile;

    fn check_state(&self) -> io::Result<()> {
        self.on_path("fstatat", &self.name.clone(), || self.real.check_state())
    }

    fn stat_at(&self, name: &str) -> io::Result<Option<Kind>> {
        self.on_path("fstatat", Path::new(name), || self.real.stat_at(name))
    }

    fn dir_state(&self) -> io::Result<DirState> {
        self.on_path("dir_state", &self.name.clone(), || self.real.dir_state())
    }

    fn create_new(&self, name: &str) -> io::Result<RecFile> {
        self.open_file("create_new", Path::new(name), || self.real.create_new(name))
    }

    fn open_rw(&self, name: &str) -> io::Result<RecFile> {
        self.open_file("open_rw", Path::new(name), || self.real.open_rw(name))
    }

    fn read_marker(&self, name: &str) -> io::Result<Vec<u8>> {
        self.on_path("read_marker", Path::new(name), || {
            self.real.read_marker(name)
        })
    }

    fn read_all(&self, file: &RecFile) -> io::Result<Vec<u8>> {
        if self.cut() {
            self.record("read_all", None, Some(file.generation), None, false);
            return Err(Self::dead_error());
        }
        let out = self.real.read_all(&file.file);
        self.record("read_all", None, Some(file.generation), None, out.is_ok());
        out
    }

    fn pwrite(&self, file: &RecFile, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        let at = Some((offset, bytes.len()));
        if self.cut() {
            self.record("pwrite", None, Some(file.generation), at, false);
            return Err(Self::dead_error());
        }
        let scripted = self.shared.script().writes.pop_front();
        let out = match scripted {
            None => self.real.pwrite(&file.file, offset, bytes),
            Some(Write::Short(n)) => self.real.pwrite(
                &file.file,
                offset,
                bytes.get(..n.min(bytes.len())).unwrap_or_default(),
            ),
            Some(Write::Interrupted) => Err(io::Error::from(io::ErrorKind::Interrupted)),
            Some(Write::Zero) => Ok(0),
            Some(Write::Fail) => Err(io::Error::other("injected write failure")),
        };
        self.record("pwrite", None, Some(file.generation), at, out.is_ok());
        out
    }

    fn sync_file(&self, file: &RecFile) -> io::Result<()> {
        if self.cut() {
            self.record("sync_file", None, Some(file.generation), None, false);
            return Err(Self::dead_error());
        }
        let out = if self.fail_this_sync() {
            Err(io::Error::other("injected sync failure"))
        } else {
            self.real.sync_file(&file.file)
        };
        self.record("sync_file", None, Some(file.generation), None, out.is_ok());
        out
    }

    fn sync_dir(&self, dir: Held) -> io::Result<()> {
        let named = match dir {
            Held::State => self.name.clone(),
            Held::Anchor => PathBuf::from("anchor"),
        };
        if self.cut() {
            self.record("sync_dir", Some(&named), None, None, false);
            return Err(Self::dead_error());
        }
        let out = if self.fail_this_sync() {
            Err(io::Error::other("injected sync failure"))
        } else {
            self.real.sync_dir(dir)
        };
        self.record("sync_dir", Some(&named), None, None, out.is_ok());
        out
    }

    fn truncate(&self, file: &RecFile, len: u64) -> io::Result<()> {
        if self.cut() {
            self.record("truncate", None, Some(file.generation), None, false);
            return Err(Self::dead_error());
        }
        let out = self.real.truncate(&file.file, len);
        self.record(
            "truncate",
            None,
            Some(file.generation),
            Some((len, 0)),
            out.is_ok(),
        );
        out
    }

    fn link(&self, from: &str, to: &str) -> io::Result<()> {
        self.on_path("link", Path::new(to), || self.real.link(from, to))
    }

    fn unlink(&self, name: &str) -> io::Result<()> {
        let out = self.on_path("unlink", Path::new(name), || self.real.unlink(name));
        let plant = {
            let mut script = self.shared.script();
            match &script.plant {
                Some((at, _)) if at.file_name() == Some(std::ffi::OsStr::new(name)) => {
                    script.plant.take()
                }
                _ => None,
            }
        };
        if let Some((at, plant)) = plant {
            match plant {
                Plant::File => std::fs::write(&at, b"planted").unwrap(),
                Plant::Symlink(target) => std::os::unix::fs::symlink(target, &at).unwrap(),
            }
        }
        out
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.on_path("rename", Path::new(to), || self.real.rename(from, to))
    }
}
