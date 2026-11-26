// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `granconf` — the differential oracle's pure half.
//! Four verbs, none of which touches a mount, a server or a container:
//! `dump` renders a directory tree as a stable, byte-sorted text
//! artifact; `compare` classifies divergences between two such
//! artifacts; `gendir` builds a seeded, adversarial-but-legal source
//! tree; `verify-cases` proves a dump actually contains the cases
//! `gendir` claims to generate. The breakage feature, orchestrator and
//! real mount live in `granary-fuse` and
//! `scripts/`, not here — this crate is provable by unit test alone.

pub mod compare;
pub mod escape;
pub mod gendir;
pub mod row;
pub mod verify_cases;
pub mod walk;
