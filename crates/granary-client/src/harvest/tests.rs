// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::harvest` — walking a source tree,
//! chunking+hashing files, building the manifest content tree
//! and writing grains + manifest objects into the
//! local store.
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;

struct ScratchDir(PathBuf);
impl ScratchDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
            hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
            and nothing else (`granary-harvest-test-<pid>-<counter>` under the temp dir, created and removed by \
            this fixture), and it is load-bearing for correctness there: the counter beside it is \
            per-process, and every test binary runs in its own process, so without the pid two concurrent \
            runs generate the same name and share one directory. It reaches no hashed or signed value, and \
            nothing under test reads it: the rows here assert what the harvest walk found and what it wrote, \
            against a tree this fixture built, and the scratch NAME is an input to neither"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-harvest-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A bare `fs::File::open` on the source-tree path — no `O_NONBLOCK` —
/// so a FIFO at that path (a swap between classification and open in
/// production; planted directly here to exercise the open itself)
/// BLOCKS the harvest thread forever. `fsguard::open_regular_read`
/// closes it, the same class the cache's own structural opens are
/// closed against — and `within_deadline` turns a regression back
/// into this test failing loudly rather than `nextest` hanging at
/// 0% CPU.
#[test]
fn harvest_file_on_a_fifo_refuses_promptly_rather_than_hanging() {
    let store_dir = ScratchDir::new();
    let store = Store::open(&store_dir.0).unwrap_or_else(|e| panic!("{e}"));
    let source_dir = ScratchDir::new();
    let fifo_path = source_dir.0.join("looks-like-a-regular-file");
    crate::fsguard::testutil::mkfifo(&fifo_path);
    let ino = std::fs::symlink_metadata(&fifo_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .ino();

    let result = crate::fsguard::testutil::within_deadline("harvest_file on a FIFO", move || {
        let mut stats = HarvestStats::default();
        harvest_file(&fifo_path, ino, &store, &mut stats, &[])
    });

    assert!(
        result.is_err(),
        "a FIFO must be refused, never opened as file content"
    );
}
