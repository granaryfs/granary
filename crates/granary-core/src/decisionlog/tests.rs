// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::decisionlog` — a core, in-memory
//! `DecisionLog` fake with **no crash model** (the simulator's
//! crash-consistency fake, with the inode/namespace model and the
//! injected faults, lives in `granary-sim` instead). Out-of-line:
//! `granary-core`'s non-test artifact has workspace consumers, so the
//! module's own tests move out of the parent file (coding-standards
//! rule 18), the same as `rootstore/tests.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use super::*;
use crate::authlog::{Append, EncodedEnvelope};
use crate::root::VolumeName;
use crate::runmarker::EncodedMarker;
use crate::testkit::{DecisionLogFixture, block_on};

/// The state a `DecisionLog` fake needs, and nothing a crash could ever
/// tear: one flag for the state directory's existence, an optional
/// marker, each volume's log bytes as one atomic value, and the set of
/// volumes with a leftover temporary. Every method here is the CORRECT
/// semantic; [`InMemoryLog::overwrite_on_initialise`] is the only place
/// this fake can deliberately misbehave.
#[derive(Default)]
struct State {
    dir_exists: bool,
    marker: Option<Vec<u8>>,
    volumes: BTreeMap<VolumeName, Vec<u8>>,
    temporaries: BTreeSet<VolumeName>,
}

impl State {
    fn read_marker(&self) -> MarkerRead {
        if let Some(bytes) = &self.marker {
            return MarkerRead::Present(bytes.clone());
        }
        let state_dir = if !self.dir_exists {
            StateDirectory::Absent
        } else if self.volumes.is_empty() && self.temporaries.is_empty() {
            StateDirectory::Empty
        } else {
            StateDirectory::Occupied
        };
        MarkerRead::Missing { state_dir }
    }

    fn seed_marker_bytes(&mut self, bytes: &[u8]) {
        self.dir_exists = true;
        self.marker = Some(bytes.to_vec());
    }

    fn write_marker(&mut self, bytes: Vec<u8>) {
        self.dir_exists = true;
        self.marker = Some(bytes);
    }

    fn read(&self, volume: &VolumeName) -> Option<Vec<u8>> {
        self.volumes.get(volume).cloned()
    }

    /// The correct semantic: `AlreadyExists`, nothing changed.
    fn initialise(&mut self, envelope: &EncodedEnvelope) -> Result<(), LogIoError> {
        self.dir_exists = true;
        // The exact leftover temporary goes first, whatever follows.
        self.temporaries.remove(envelope.volume());
        if self.volumes.contains_key(envelope.volume()) {
            return Err(LogIoError::AlreadyExists);
        }
        self.volumes
            .insert(envelope.volume().clone(), envelope.as_bytes().to_vec());
        Ok(())
    }

    /// The DELIBERATELY WRONG semantic — the positive control's whole
    /// reason to exist: silently overwrites an existing log instead of
    /// refusing. See `the_conformance_suite_catches_an_initialise_that_overwrites`.
    fn initialise_overwriting(&mut self, envelope: &EncodedEnvelope) {
        self.dir_exists = true;
        self.temporaries.remove(envelope.volume());
        self.volumes
            .insert(envelope.volume().clone(), envelope.as_bytes().to_vec());
    }

    fn complete_namespace(&mut self, volume: &VolumeName) -> Result<(), LogIoError> {
        if self.volumes.contains_key(volume) {
            self.temporaries.remove(volume);
            Ok(())
        } else {
            Err(LogIoError::NotFound)
        }
    }

    fn append(&mut self, append: &Append) -> Result<(), LogIoError> {
        let bytes = self
            .volumes
            .get_mut(append.volume())
            .ok_or(LogIoError::NotFound)?;
        bytes.extend_from_slice(append.record());
        bytes.extend_from_slice(append.mark());
        Ok(())
    }

    fn truncate(&mut self, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        let bytes = self.volumes.get_mut(volume).ok_or(LogIoError::NotFound)?;
        let Ok(len) = usize::try_from(len) else {
            // A `len` that does not even fit `usize` is certainly past
            // the end of any real `Vec<u8>`.
            return Err(LogIoError::OutOfRange);
        };
        if len > bytes.len() {
            return Err(LogIoError::OutOfRange);
        }
        bytes.truncate(len);
        Ok(())
    }

    fn resync(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        if self.volumes.contains_key(volume) {
            Ok(())
        } else {
            Err(LogIoError::NotFound)
        }
    }

    fn remove_temporary(&mut self, volume: &VolumeName) -> bool {
        self.temporaries.remove(volume)
    }

    fn seed_bytes(&mut self, volume: &VolumeName, bytes: Vec<u8>) {
        self.dir_exists = true;
        self.volumes.insert(volume.clone(), bytes);
    }

    fn seed_empty_state_dir(&mut self) {
        self.dir_exists = true;
    }

    fn seed_temporary(&mut self, volume: &VolumeName) {
        self.dir_exists = true;
        self.temporaries.insert(volume.clone());
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// A core, in-memory `DecisionLog`: no crash model, no ordering
/// checks — a straightforwardly correct implementation of the trait's
/// basic semantics, the role `rootstore/tests.rs`'s `FakeStore` plays
/// for `RootStore`. The crash-consistency ordering checks (the fake
/// enforcing the spec's commit order) belong to `granary-sim`'s fake
/// instead.
///
/// `overwrite_on_initialise` is THE POSITIVE CONTROL's only difference
/// from a correct fake (`InMemoryLog::with_overwriting_initialise`):
/// when true, `initialise` overwrites an existing log instead of
/// refusing `AlreadyExists`, a plausible wrong implementation the shared
/// suite must catch.
#[derive(Default)]
struct InMemoryLog {
    state: Mutex<State>,
    overwrite_on_initialise: bool,
}

impl InMemoryLog {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|e| panic!("fake decision log mutex poisoned: {e}"))
    }

    /// See [`Self::overwrite_on_initialise`]'s docs.
    fn with_overwriting_initialise() -> Self {
        Self {
            overwrite_on_initialise: true,
            ..Self::default()
        }
    }
}

/// Written with `async fn` on purpose: an IMPLEMENTOR gets the sugar,
/// and the trait's `+ Send` is still checked here, the same convention
/// `rootstore/tests.rs`'s `FakeStore` documents.
impl DecisionLog for InMemoryLog {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        Ok(self.lock().read_marker())
    }

    async fn write_marker(&self, marker: &EncodedMarker) -> Result<(), LogIoError> {
        self.lock().write_marker(marker.as_bytes().to_vec());
        Ok(())
    }

    async fn read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        Ok(self.lock().read(volume))
    }

    async fn remove_temporary(&self, volume: &VolumeName) -> Result<bool, LogIoError> {
        Ok(self.lock().remove_temporary(volume))
    }

    async fn initialise(&self, envelope: &EncodedEnvelope) -> Result<(), LogIoError> {
        if self.overwrite_on_initialise {
            // THE BUG: never refuses, so a second initialise silently
            // replaces the first log's bytes.
            self.lock().initialise_overwriting(envelope);
            Ok(())
        } else {
            self.lock().initialise(envelope)
        }
    }

    async fn complete_namespace(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.lock().complete_namespace(volume)
    }

    async fn append(&self, append: &Append) -> Result<(), LogIoError> {
        self.lock().append(append)
    }

    async fn truncate(&self, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        self.lock().truncate(volume, len)
    }

    async fn resync(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.lock().resync(volume)
    }
}

impl DecisionLogFixture for InMemoryLog {
    async fn seed_bytes(&self, volume: &VolumeName, bytes: Vec<u8>) {
        self.lock().seed_bytes(volume, bytes);
    }

    async fn seed_marker_bytes(&self, bytes: &[u8]) {
        self.lock().seed_marker_bytes(bytes);
    }

    async fn seed_empty_state_dir(&self) {
        self.lock().seed_empty_state_dir();
    }

    async fn seed_temporary(&self, volume: &VolumeName) {
        self.lock().seed_temporary(volume);
    }

    async fn reset(&self) {
        self.lock().reset();
    }
}

#[test]
fn the_fake_passes_the_shared_decisionlog_conformance_suite() {
    let log = InMemoryLog::default();
    block_on(crate::testkit::decisionlog_conformance(&log));
}

/// THE POSITIVE CONTROL: a fake whose `initialise` overwrites an
/// existing log — exactly the plausible wrong implementation
/// `decisionlog_initialise_twice_is_already_exists_and_unchanged`
/// exists to catch — must fail the shared suite. Run without this
/// `#[should_panic]`, the test goes red with
/// "initialise on an occupied name must be `AlreadyExists`", proving the
/// suite is not vacuously green; kept red-then-green here as this
/// mutation's permanent regression guard.
#[test]
#[should_panic(expected = "initialise on an occupied name must be AlreadyExists")]
fn the_conformance_suite_catches_an_initialise_that_overwrites() {
    let log = InMemoryLog::with_overwriting_initialise();
    block_on(crate::testkit::decisionlog_conformance(&log));
}
