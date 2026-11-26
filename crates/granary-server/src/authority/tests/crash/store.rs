// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The crash harness's root store: a directory whose state outlives the
//! killed process, so the harness reads the store's outcome from it.
//!
//! A root is the file `<volume>/<seq>`. A PUT writes its bytes to a
//! temporary named for the PUT, hard-links the temporary to the root's
//! name (which fails when the name is taken: the conditional PUT), then
//! removes the temporary. So a root is published whole or not at all, as
//! `object_store`'s local backend publishes an object. A temporary a kill
//! leaves is inert (no read or listing sees it), and a later PUT of the same
//! name removes it before creating its own, so a leftover that is still a
//! second name of a published root is never written through.
//!
//! Every PUT writes its `PUT` line to the crash pipe before it is sent and
//! its `PUT-RESULT` when it returns; every `get_root` writes a `GET` line
//! as it returns.
//!
//! **The foreign writer**: the first PUT at A's seq 3 publishes `f3` at
//! that name just before it, then leaves a `planted` file, so the plant
//! happens once however many processes run. A kill between the two leaves
//! `f3` in place, and the next process's plant finds the name taken and
//! changes nothing.

use std::io;
use std::path::{Path, PathBuf};

use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use granary_core::rootstore::{HintRead, HintToken, RootStore, RootStoreError, filter_above};

use super::super::super::crash;

/// The directory store.
#[derive(Debug, Clone)]
pub(super) struct DirStore {
    root: PathBuf,
    /// The root published at A's seq 3 before the first PUT there.
    plant: Option<(String, u64, Vec<u8>)>,
}

impl DirStore {
    pub(super) fn new(root: &Path, plant: Option<(String, u64, Vec<u8>)>) -> Self {
        Self {
            root: root.to_path_buf(),
            plant,
        }
    }

    fn root_path(&self, volume: &str, seq: u64) -> PathBuf {
        self.root.join(volume).join(seq.to_string())
    }

    fn hint_path(&self, volume: &str) -> PathBuf {
        self.root.join(format!("{volume}.hint"))
    }

    /// Publish `bytes` at `(volume, seq)` if the name is free: the
    /// temporary, the link, the temporary's removal, a crash site between
    /// each when `sites` is set.
    fn publish(&self, volume: &str, seq: u64, bytes: &[u8], sites: bool) -> io::Result<()> {
        std::fs::create_dir_all(self.root.join(volume))?;
        let temp = self.root.join(format!(
            ".put-{volume}-{seq}-{}",
            hex(GrainId::of(bytes).digest())
        ));
        // A temporary a kill left may still be a second name of a published
        // root (a kill after the link, before its removal): writing through
        // it would rewrite the root. So it goes first, and the new one is
        // created, never opened.
        match std::fs::remove_file(&temp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        {
            use std::io::Write as _;
            let mut file = std::fs::File::options()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(bytes)?;
        }
        if sites {
            crash_point!(PutTempWritten);
        }
        let linked = std::fs::hard_link(&temp, self.root_path(volume, seq));
        if linked.is_ok() && sites {
            crash_point!(PutLinked);
        }
        // The PUT's result is the link's: once linked, the root is
        // published, and a temporary left behind is inert.
        let _ = std::fs::remove_file(&temp);
        if sites {
            crash_point!(PutTempRemoved);
        }
        linked
    }

    /// The foreign writer (module docs).
    fn plant_before(&self, volume: &str, seq: u64) -> io::Result<()> {
        let Some((at_volume, at_seq, bytes)) = &self.plant else {
            return Ok(());
        };
        let planted = self.root.join("planted");
        if at_volume != volume || *at_seq != seq || planted.exists() {
            return Ok(());
        }
        match self.publish(volume, seq, bytes, false) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        std::fs::write(planted, b"")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn checked(volume: &str) -> Result<(), RootStoreError> {
    VolumeName::from_bytes(volume.as_bytes())
        .map(|_| ())
        .map_err(|error| RootStoreError::InvalidVolume {
            reason: error.to_string(),
        })
}

fn backend(e: &io::Error) -> RootStoreError {
    RootStoreError::Backend(e.to_string())
}

impl RootStore for DirStore {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        checked(volume)?;
        self.plant_before(volume, seq).map_err(|e| backend(&e))?;
        crash::note(&format!("PUT {volume} {seq} {:?}", GrainId::of(&bytes)));
        crash_point!(PutSent);
        let out = match self.publish(volume, seq, &bytes, true) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Err(RootStoreError::AlreadyExists)
            }
            Err(e) => Err(backend(&e)),
        };
        let result = match &out {
            Ok(()) => "ok",
            Err(RootStoreError::AlreadyExists) => "exists",
            Err(_) => "err",
        };
        crash::note(&format!("PUT-RESULT {volume} {seq} {result}"));
        crash_point!(PutReturned);
        out
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        checked(volume)?;
        let out = match std::fs::read(self.root_path(volume, seq)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(backend(&e)),
        };
        let found = match &out {
            Ok(Some(bytes)) => format!("{:?}", GrainId::of(bytes)),
            Ok(None) => "none".to_owned(),
            Err(_) => "err".to_owned(),
        };
        crash::note(&format!("GET {volume} {seq} {found}"));
        out
    }

    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        checked(volume)?;
        let body = match std::fs::read_to_string(self.hint_path(volume)) {
            Ok(body) => body,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HintRead::Missing),
            Err(e) => return Err(backend(&e)),
        };
        // `<seq> <writes>`: the token is the write count, so a rewrite to
        // the same seq mints a new one.
        let mut parts = body.split_whitespace();
        let (Some(Ok(seq)), Some(writes)) = (parts.next().map(str::parse::<u64>), parts.next())
        else {
            return Ok(HintRead::Missing);
        };
        if seq == 0 {
            return Ok(HintRead::Missing);
        }
        let token = HintToken(format!("\"w{writes}\""));
        if cached == Some(&token) {
            Ok(HintRead::NotModified)
        } else {
            Ok(HintRead::Current { seq, token })
        }
    }

    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        checked(volume)?;
        let path = self.hint_path(volume);
        let writes = std::fs::read_to_string(&path)
            .ok()
            .and_then(|body| body.split_whitespace().nth(1)?.parse::<u64>().ok())
            .map_or(1, |w| w.saturating_add(1));
        std::fs::create_dir_all(&self.root).map_err(|e| backend(&e))?;
        std::fs::write(path, format!("{seq} {writes}")).map_err(|e| backend(&e))
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        checked(volume)?;
        let entries = match std::fs::read_dir(self.root.join(volume)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(backend(&e)),
        };
        let mut max = None;
        for entry in entries {
            let entry = entry.map_err(|e| backend(&e))?;
            // Seq 0 and seq `u64::MAX` are never a head (a planted one
            // stays readable): the seam's rule.
            if let Some(seq) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u64>().ok())
                .filter(|seq| *seq != 0 && *seq != u64::MAX)
            {
                max = Some(max.map_or(seq, |m: u64| m.max(seq)));
            }
        }
        Ok(max)
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

/// The store holds the seam's semantics: the shared conformance body.
#[test]
fn the_directory_store_passes_the_rootstore_conformance_body() {
    let dir = super::scratch();
    let store = DirStore::new(&dir, None);
    super::super::block(async move {
        granary_core::testkit::rootstore_conformance(&store).await;
    });
    let _ = std::fs::remove_dir_all(dir);
}
