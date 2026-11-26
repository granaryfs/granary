// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Pure logic for granary: formats, chunking, protocol types.
//! No I/O, no tokio, no wall clocks — enforced by `deny.core.toml`,
//! the isolated `cargo check -p granary-core` CI gate, and clippy seams.

#![deny(clippy::disallowed_types)] // HashMap/HashSet/RandomState banned in core (sim determinism)

pub mod authlog;
pub mod authority_answer;
pub mod binfmt;
pub mod binmap;
pub mod binstore;
pub mod cacheindex;
pub mod clock;
pub mod debug_grant;
pub mod decisionlog;
pub mod encoding;
pub mod enrollment;
pub mod grainsource;
pub mod hash;
pub mod identity;
pub mod intent;
pub mod manifest;
pub mod mount_control;
pub mod netid;
pub mod overlay_discard;
pub mod overlay_journal;
pub mod overlay_ownership;
pub mod retained_archive;
pub mod retained_submission;
pub mod rng;
pub mod root;
pub mod rootstore;
pub mod runmarker;
pub mod secure_random;
pub mod sheaf;
pub mod support;
pub mod support_trigger;
pub mod thresh;

#[doc(hidden)]
pub mod testkit;
