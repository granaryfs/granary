// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::rootstore` — the root CAS contract.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::testkit::block_on;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// The whole point of the desugared trait shape: the
/// futures must be `Send`, which sugared `async fn` in a trait
/// cannot express.
fn assert_send<T: Send>(_: &T) {}

/// A minimal in-memory `RootStore`: std only, no tokio, no
/// `object_store`. Hints carry a monotonic counter as their opaque
/// token — the ECHOED version, modelling an `ETag`; nothing derives a
/// token from the seq.
#[derive(Debug, Default)]
struct FakeStore {
    roots: Mutex<BTreeMap<(String, u64), Vec<u8>>>,
    hints: Mutex<BTreeMap<String, (u64, u64)>>,
}

fn poisoned<T>(_: T) -> RootStoreError {
    RootStoreError::Backend("fake store mutex poisoned".to_owned())
}

/// The contract's obligation, carried by the FAKE and not only by
/// the adapter (see [`RootStoreError::InvalidVolume`]): a name that
/// is not a [`crate::root::VolumeName`] never becomes a key. A fake
/// that skips this accepts names production refuses.
fn checked_volume(volume: &str) -> Result<(), RootStoreError> {
    crate::root::VolumeName::new(volume.to_owned())
        .map(|_| ())
        .map_err(|e| RootStoreError::InvalidVolume {
            reason: e.to_string(),
        })
}

/// Written with `async fn` on purpose: an IMPLEMENTOR gets the
/// sugar, and the trait's `+ Send` is still checked here (drop a
/// `!Send` value across an await in one of these bodies and this
/// impl stops compiling). The desugaring is only needed on the
/// TRAIT, where the sugar cannot express `Send`.
impl RootStore for FakeStore {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        checked_volume(volume)?;
        let mut roots = self.roots.lock().map_err(poisoned)?;
        match roots.entry((volume.to_owned(), seq)) {
            std::collections::btree_map::Entry::Occupied(_) => Err(RootStoreError::AlreadyExists),
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(bytes);
                Ok(())
            }
        }
    }

    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        checked_volume(volume)?;
        let roots = self.roots.lock().map_err(poisoned)?;
        Ok(roots.get(&(volume.to_owned(), seq)).cloned())
    }

    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        checked_volume(volume)?;
        let hints = self.hints.lock().map_err(poisoned)?;
        match hints.get(volume) {
            // No hint, and a hint of 0, are the same answer: seq 0
            // names a root that cannot exist, so offering it would
            // send every reader through a doomed `get_root(0)`
            // before it recovered by listing.
            None | Some(&(0, _)) => Ok(HintRead::Missing),
            Some(&(seq, version)) => {
                let token = HintToken(version.to_string());
                if cached == Some(&token) {
                    Ok(HintRead::NotModified)
                } else {
                    Ok(HintRead::Current { seq, token })
                }
            }
        }
    }

    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        checked_volume(volume)?;
        let mut hints = self.hints.lock().map_err(poisoned)?;
        let next = hints.get(volume).map_or(1, |&(_, v)| v + 1);
        hints.insert(volume.to_owned(), (seq, next));
        Ok(())
    }

    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        checked_volume(volume)?;
        let roots = self.roots.lock().map_err(poisoned)?;
        // Sorted CLIENT-side: list order is not a contract.
        Ok(roots
            .keys()
            .filter(|(v, _)| v == volume)
            .map(|(_, s)| *s)
            // Seq 0 can hold no root, so it is never the head; and
            // seq u64::MAX is RESERVED — a create-only
            // PUT there would otherwise pin the head at the top of
            // the range forever, leaving no seq to publish at.
            .filter(|&s| s != 0 && s != u64::MAX)
            .max())
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

/// The structural closure for the accept-set divergence class: the
/// same suite body runs here, against the production granary-store
/// adapter, and against the sim's fake. A rule that holds in one and
/// not another cannot pass all three sites — which is the only check
/// that catches a fake drifting from production, because each side's
/// own tests stay self-consistent while they disagree.
#[test]
fn the_fake_passes_the_shared_rootstore_conformance_suite() {
    let store = FakeStore::default();
    block_on(crate::testkit::rootstore_conformance(&store));
}

#[test]
fn trait_is_implementable_without_tokio_and_futures_are_send() {
    let store = FakeStore::default();
    assert_send(&store.put_root("v", 1, vec![1]));
    assert_send(&store.get_root("v", 1));
    assert_send(&store.read_hint("v", None));
    assert_send(&store.write_hint("v", 1));
    assert_send(&store.max_seq("v"));
    assert_send(&store.max_seq_above("v", 0));
}

#[test]
fn put_root_is_put_if_absent() {
    let store = FakeStore::default();
    assert_eq!(block_on(store.put_root("v", 1, vec![0xAA])), Ok(()));
    // The loser of the race sees AlreadyExists and the stored body
    // is UNCHANGED — never last-writer-wins.
    assert_eq!(
        block_on(store.put_root("v", 1, vec![0xBB])),
        Err(RootStoreError::AlreadyExists)
    );
    assert_eq!(block_on(store.get_root("v", 1)), Ok(Some(vec![0xAA])));
    assert_eq!(block_on(store.get_root("v", 2)), Ok(None));
    // Volumes are separate key spaces.
    assert_eq!(block_on(store.put_root("w", 1, vec![0xCC])), Ok(()));
    assert_eq!(block_on(store.get_root("w", 1)), Ok(Some(vec![0xCC])));
}

#[test]
fn hint_is_echoed_and_revalidates() {
    let store = FakeStore::default();
    assert_eq!(block_on(store.read_hint("v", None)), Ok(HintRead::Missing));
    assert_eq!(block_on(store.write_hint("v", 1)), Ok(()));
    let first = match block_on(store.read_hint("v", None)) {
        Ok(HintRead::Current { seq, token }) => {
            assert_eq!(seq, 1);
            token
        }
        other => panic!("want Current, got {other:?}"),
    };
    // Cheap poll: the same token revalidates (the 304 path).
    assert_eq!(
        block_on(store.read_hint("v", Some(&first))),
        Ok(HintRead::NotModified)
    );
    // A new publish moves the token; the cached one is now stale and
    // the reader gets the body back rather than a 304.
    assert_eq!(block_on(store.write_hint("v", 2)), Ok(()));
    assert_eq!(
        block_on(store.read_hint("v", Some(&first))),
        Ok(HintRead::Current {
            seq: 2,
            token: HintToken("2".to_owned())
        })
    );
}

/// The hint is ADVISORY: the crash window (root CAS succeeded, hint
/// PUT lost) is DESIGNED, so a reader that trusts the hint alone
/// reads a stale volume. The numbered chain is the truth, and
/// forward-probing is what closes the gap.
#[test]
fn stale_hint_is_a_designed_state_and_forward_probe_closes_it() {
    let store = FakeStore::default();
    block_on(store.put_root("v", 1, vec![1])).unwrap();
    block_on(store.write_hint("v", 1)).unwrap();
    // Publish seq 2, then "crash" before the hint update.
    block_on(store.put_root("v", 2, vec![2])).unwrap();
    assert!(matches!(
        block_on(store.read_hint("v", None)),
        Ok(HintRead::Current { seq: 1, .. })
    ));
    // Forward probe: hint + 1 exists, so the hint was stale.
    assert_eq!(block_on(store.get_root("v", 2)), Ok(Some(vec![2])));
    assert_eq!(block_on(store.get_root("v", 3)), Ok(None));
    // The chain's own answer, sorted client-side.
    assert_eq!(block_on(store.max_seq("v")), Ok(Some(2)));
    assert_eq!(block_on(store.max_seq("nope")), Ok(None));
}

#[test]
fn max_seq_is_numeric_not_lexicographic() {
    let store = FakeStore::default();
    for seq in [9u64, 10, 2] {
        block_on(store.put_root("v", seq, vec![0])).unwrap();
    }
    // "10" < "9" lexicographically; the answer must be 10.
    assert_eq!(block_on(store.max_seq("v")), Ok(Some(10)));
}

#[test]
fn filter_above_excludes_the_floor_and_lower_sequences() {
    assert_eq!(filter_above(Some(10), 9), Some(10));
    assert_eq!(filter_above(Some(10), 10), None);
    assert_eq!(filter_above(Some(10), 11), None);
    assert_eq!(filter_above(None, 0), None);
}

#[test]
fn hint_body_is_exactly_twenty_digits_strict_parsed() {
    assert_eq!(SEQ_KEY_DIGITS, 20);
    assert_eq!(format_hint_body(1), "00000000000000000001");
    assert_eq!(format_hint_body(0), "00000000000000000000");
    assert_eq!(format_hint_body(u64::MAX), "18446744073709551615");
    for seq in [1u64, 2, 42, u64::MAX] {
        assert_eq!(parse_hint_body(&format_hint_body(seq)), Ok(seq));
    }
    // Untrusted input: every non-canonical form is refused.
    assert_eq!(
        parse_hint_body("1"),
        Err(HintBodyError::BadLength { len: 1 })
    );
    assert_eq!(
        parse_hint_body("000000000000000000001"),
        Err(HintBodyError::BadLength { len: 21 })
    );
    assert_eq!(
        parse_hint_body("0000000000000000000a"),
        Err(HintBodyError::NonDigit { byte: b'a' })
    );
    assert_eq!(
        parse_hint_body("+0000000000000000001"),
        Err(HintBodyError::NonDigit { byte: b'+' })
    );
    assert_eq!(
        parse_hint_body("0000000000000000001\n"),
        Err(HintBodyError::NonDigit { byte: b'\n' })
    );
    // 20 digits that do not fit u64.
    assert_eq!(
        parse_hint_body("99999999999999999999"),
        Err(HintBodyError::Overflow)
    );
}

#[test]
fn is_reserved_seq_covers_exactly_the_two_absent_class_values() {
    assert!(is_reserved_seq(0));
    assert!(is_reserved_seq(u64::MAX));
    assert!(!is_reserved_seq(1));
    assert!(!is_reserved_seq(u64::MAX - 1));
    assert!(!is_reserved_seq(42));
}

#[test]
fn errors_display_their_semantics() {
    // A DISTINGUISHING substring per variant. `!is_empty()` alone
    // passes for any non-empty string — including another variant's
    // message — so it pins nothing: swapping two renderings outright
    // survives it.
    for (e, needle) in [
        (RootStoreError::AlreadyExists, "already holds"),
        (RootStoreError::Precondition, "precondition"),
        (RootStoreError::NotFound, "not found"),
        (RootStoreError::RangeOverflow, "overflow"),
        (
            RootStoreError::RefusedResponse {
                reason: "over the 64-byte cap".to_owned(),
                kind: RefusalKind::OverCap,
            },
            "over the 64-byte cap",
        ),
        (RootStoreError::Backend("boom".to_owned()), "boom"),
        (
            RootStoreError::Unavailable {
                operation: "GET meta",
                status: 503,
            },
            "GET meta",
        ),
        (
            RootStoreError::Elapsed {
                operation: "PUT root",
                after: Duration::from_secs(30),
            },
            "PUT root",
        ),
    ] {
        let rendered = e.to_string();
        assert!(
            rendered.contains(needle),
            "{e:?} rendered as {rendered:?}, which does not carry {needle:?}"
        );
    }
    for (status, expected) in [
        (429, "GET meta: too many requests (429)"),
        (503, "GET meta: service unavailable (503)"),
        (502, "GET meta: 502"),
    ] {
        assert_eq!(
            RootStoreError::Unavailable {
                operation: "GET meta",
                status,
            }
            .to_string(),
            expected
        );
    }
    // The seam is SHARED, so no rendering may name a
    // component only one route has. `object store` was true of
    // granary-store's `object_store` adapter and false of the
    // through-the-server client, where the peer is a granary server
    // and the caller holds no bucket at all. Yet an observed failure
    // told the operator `object store:` on exactly that route.
    // The noun that IS true on both is the one the trait is named
    // for and the one `RefusedResponse` above already uses.
    for e in [
        RootStoreError::Backend("boom".to_owned()),
        RootStoreError::RefusedResponse {
            reason: "over the 64-byte cap".to_owned(),
            kind: RefusalKind::OverCap,
        },
    ] {
        let rendered = e.to_string();
        assert!(
            !rendered.contains("object store"),
            "{e:?} rendered as {rendered:?}, naming a component the through-the-server \
             route does not have"
        );
        assert!(
            rendered.contains("store"),
            "{e:?} rendered as {rendered:?}, which no longer says whose failure it is"
        );
    }
    assert!(
        HintBodyError::Overflow
            .to_string()
            .to_ascii_lowercase()
            .contains("u64")
    );
}

/// Seq 0 parses but can hold no root, so neither read path may offer
/// it as a head. This is a CONTRACT obligation (see the module
/// docs), and it lived only in the granary-store adapter for a time —
/// which is exactly how a fake diverges from production on
/// attacker-writable input while every test stays green.
#[test]
fn seq_zero_is_never_a_head_on_either_read_path() {
    let store = FakeStore::default();
    // A root planted at seq 0 must not become the head.
    assert_eq!(block_on(store.put_root("v", 0, vec![9])), Ok(()));
    assert_eq!(block_on(store.max_seq("v")), Ok(None));
    // A real root still resolves normally alongside it.
    assert_eq!(block_on(store.put_root("v", 1, vec![1])), Ok(()));
    assert_eq!(block_on(store.max_seq("v")), Ok(Some(1)));

    // A hint of 0 degrades to Missing, not `Current { seq: 0 }`.
    assert_eq!(block_on(store.write_hint("v", 0)), Ok(()));
    assert_eq!(block_on(store.read_hint("v", None)), Ok(HintRead::Missing));
    // And a real hint still reads back.
    assert_eq!(block_on(store.write_hint("v", 1)), Ok(()));
    assert!(matches!(
        block_on(store.read_hint("v", None)),
        Ok(HintRead::Current { seq: 1, .. })
    ));
}

/// The labels are the server's log vocabulary and the client's diagnostic
/// vocabulary at once, so each is pinned by name, and two variants never
/// share one.
#[test]
fn kind_labels_are_pinned_one_per_variant() {
    let all = [
        (RootStoreError::AlreadyExists, "already-exists"),
        (RootStoreError::Precondition, "precondition"),
        (RootStoreError::NotFound, "not-found"),
        (RootStoreError::RangeOverflow, "range-overflow"),
        (
            RootStoreError::InvalidVolume {
                reason: String::new(),
            },
            "invalid-volume",
        ),
        (
            RootStoreError::RefusedResponse {
                reason: String::new(),
                kind: RefusalKind::OverCap,
            },
            "refused-response",
        ),
        (
            RootStoreError::Unavailable {
                operation: "GET meta",
                status: 503,
            },
            "unavailable",
        ),
        (
            RootStoreError::Elapsed {
                operation: "PUT root",
                after: Duration::from_secs(1),
            },
            "elapsed",
        ),
        (
            RootStoreError::UnexpectedStatus {
                operation: "PUT bin",
                status: 500,
                token: None,
            },
            "unexpected-status",
        ),
        (RootStoreError::Backend("boom".to_owned()), "backend"),
    ];
    for (error, label) in &all {
        assert_eq!(error.kind(), *label, "{error:?}");
    }
    let mut labels: Vec<_> = all.iter().map(|(error, _)| error.kind()).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), all.len());
}

/// An unexpected status renders as the free-text `Backend` it replaced did,
/// with the token only when one was kept.
#[test]
fn unexpected_status_renders_its_call_status_and_token() {
    let error = |token: Option<&str>| RootStoreError::UnexpectedStatus {
        operation: "PUT bin",
        status: 403,
        token: token.map(str::to_owned),
    };
    assert_eq!(
        error(Some("no-principal")).to_string(),
        "store: PUT bin: 403 no-principal"
    );
    assert_eq!(
        error(None).to_string(),
        "store: PUT bin: unexpected status 403"
    );
}
