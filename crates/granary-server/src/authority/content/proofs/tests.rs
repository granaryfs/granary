// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn live_byte_cap_refuses_the_next_bucket_even_with_a_slot() {
    const ONE_BUCKET: usize = BUCKET_BYTES + ENTRY_BYTES;
    let pool = Proofs::with_limits(ONE_BUCKET, ONE_BUCKET);
    let permit = Arc::new(Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap());
    let allocation = Allocation::new(pool.clone(), &permit);
    let id = GrainId::of(b"first length");
    let mut first = Lengths::default();
    first.insert(&allocation, id, 1).unwrap();
    assert_eq!(pool.live_bytes(), ONE_BUCKET);
    let mut second = Lengths::default();
    assert_eq!(
        second.insert(&allocation, id, 1),
        Err(ValidationError::Unavailable)
    );
    assert_eq!(second.get(&id), None);
    assert_eq!(pool.live_bytes(), ONE_BUCKET);
    drop(first);
    second.insert(&allocation, id, 1).unwrap();
    assert_eq!(pool.live_bytes(), ONE_BUCKET);
    drop(second);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn allocation_requires_a_live_slot() {
    let pool = Proofs::new(DEFAULT_VALIDATIONS);
    let permit = Arc::new(Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap());
    let allocation = Allocation::new(pool.clone(), &permit);
    drop(permit);
    assert_eq!(
        Lengths::default().insert(&allocation, GrainId::of(b"unreserved length"), 1),
        Err(ValidationError::Unavailable),
    );
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn default_live_limit_includes_all_reserved_proofs() {
    let pool = Proofs::new(DEFAULT_VALIDATIONS);
    assert_eq!(PROOF_BYTES, 100_794_368);
    assert_eq!(pool.0.resident_limit, 368_181_248);
    assert_eq!(pool.0.live_limit, 1 << 30);
    assert_eq!(
        Proofs::new(DEFAULT_VALIDATIONS + 1).0.live_limit,
        (1 << 30) + 2 * PROOF_BYTES,
    );
}

#[test]
fn pending_budget_charges_and_returns_the_proof_bytes() {
    use super::super::{RootReferences, ValidationCandidate, binmap::Cache};

    const ONE_BUCKET: usize = BUCKET_BYTES + ENTRY_BYTES;
    let mut pool = Proofs::new(DEFAULT_VALIDATIONS);
    Arc::get_mut(&mut pool.0).unwrap().pending = Arc::new(Semaphore::new(2 * ONE_BUCKET));
    let permit = Arc::new(Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap());
    let allocation = Allocation::new(pool.clone(), &permit);
    let proof = |payload: &[u8]| {
        let id = GrainId::of(payload);
        let mut lengths = Lengths::default();
        lengths.insert(&allocation, id, 1).unwrap();
        VerifiedContent {
            root: ValidationCandidate::new(
                VolumeName::from_bytes(b"test-volume").unwrap(),
                id,
                None,
                RootReferences {
                    manifest: id,
                    binmap: id,
                    sheaf: id,
                },
            ),
            cache: Cache::default(),
            lengths,
        }
    };
    let first = pool.retain_pending(proof(b"first")).unwrap();
    assert_eq!(pool.0.pending.available_permits(), ONE_BUCKET);
    let second = pool.retain_pending(proof(b"second")).unwrap();
    assert_eq!(pool.0.pending.available_permits(), 0);
    assert!(pool.retain_pending(proof(b"third")).is_none());
    assert_eq!(pool.live_bytes(), 2 * ONE_BUCKET);
    drop(first);
    let third = pool.retain_pending(proof(b"third")).unwrap();
    second.install(&pool);
    assert_eq!(pool.0.pending.available_permits(), ONE_BUCKET);
    drop(third);
    assert_eq!(pool.0.pending.available_permits(), 2 * ONE_BUCKET);
    assert_eq!(pool.live_bytes(), ONE_BUCKET);
}
