// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[derive(Default)]
pub(crate) struct TestClock(Mutex<i128>);

impl TestClock {
    pub(crate) fn set(&self, nanos: i128) {
        *self.0.lock().unwrap() = nanos;
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        let now = *self.0.lock().unwrap();
        Timestamp {
            secs: i64::try_from(now.div_euclid(1_000_000_000)).unwrap(),
            nanos: u32::try_from(now.rem_euclid(1_000_000_000)).unwrap(),
        }
    }
}

const A: PrincipalId = PrincipalId::from_bytes([1; 16]);
const B: PrincipalId = PrincipalId::from_bytes([2; 16]);

fn fixture() -> (PrincipalControls, Arc<TestClock>) {
    let clock = Arc::new(TestClock::default());
    (
        PrincipalControls::new(ControlsConfig::default(), clock.clone()),
        clock,
    )
}

fn refused(result: Result<WritePermit, ControlRefusal>) -> u32 {
    result.unwrap_err().retry_after
}

#[test]
fn defaults_release_cap_with_one_submission_token_remaining() {
    let (controls, _) = fixture();
    let permits: Vec<_> = (0..4).map(|_| controls.admit(A, true).unwrap()).collect();
    assert_eq!(refused(controls.admit(A, true)), 1);
    drop(permits);
    drop(
        controls
            .admit(A, true)
            .expect("the fifth token outlasts the cap"),
    );
    assert_eq!(
        refused(controls.admit(A, true)),
        1,
        "submissions remain spent"
    );
}

#[test]
fn principal_rates_and_cap_are_independent() {
    let (controls, clock) = fixture();
    for _ in 0..5 {
        drop(controls.admit(A, true).unwrap());
    }
    assert_eq!(refused(controls.admit(A, true)), 1);
    drop(
        controls
            .admit(B, true)
            .expect("B has its own submission allowance"),
    );
    let permit = controls.admit(A, false).unwrap();
    permit.charge_bytes(BIN_MAX_BYTES).unwrap();
    assert_eq!(permit.charge_bytes(1).unwrap_err().retry_after, 8);
    controls
        .admit(B, false)
        .unwrap()
        .charge_bytes(1)
        .expect("B has its own bytes");
    drop(permit);
    clock.set(8_000_000_000);
    let permits: Vec<_> = (0..4).map(|_| controls.admit(A, false).unwrap()).collect();
    assert_eq!(refused(controls.admit(A, false)), 1);
    drop(controls.admit(B, false).expect("B has its own cap"));
    drop(permits);
}

#[test]
fn write_cap_releases_on_completion() {
    let (controls, _) = fixture();
    let mut permits: Vec<_> = (0..4).map(|_| controls.admit(A, false).unwrap()).collect();
    assert_eq!(refused(controls.admit(A, false)), 1);
    drop(permits.pop());
    let replacement = controls.admit(A, false).unwrap();
    assert_eq!(refused(controls.admit(A, false)), 1);
    drop((replacement, permits));
}

#[test]
fn rates_refill_only_through_clock() {
    let clock = Arc::new(TestClock::default());
    // A quarter-second submission refill isolates backward-clock and byte accounting.
    let controls = PrincipalControls::new(
        ControlsConfig::parse("4,4,33554432,268435456,4").unwrap(),
        clock.clone(),
    );
    for _ in 0..4 {
        drop(controls.admit(A, true).unwrap());
    }
    let permit = controls.admit(A, false).unwrap();
    permit.charge_bytes(BIN_MAX_BYTES).unwrap();
    clock.set(249_999_999);
    assert_eq!(refused(controls.admit(A, true)), 1);
    clock.set(250_000_000);
    drop(controls.admit(A, true).unwrap());
    clock.set(0);
    assert_eq!(
        refused(controls.admit(A, true)),
        1,
        "backward time grants nothing"
    );
    clock.set(249_999_999);
    assert_eq!(
        refused(controls.admit(A, true)),
        1,
        "refill resumes from the lower watermark"
    );
    clock.set(250_000_000);
    drop(controls.admit(A, true).unwrap());
    // Exactly half a second of byte credit, independent of submission debits.
    permit.charge_bytes(16 * 1024 * 1024).unwrap();
    assert_eq!(permit.charge_bytes(1).unwrap_err().retry_after, 8);
    clock.set(8_249_999_999);
    assert_eq!(
        permit.charge_bytes(BIN_MAX_BYTES).unwrap_err().retry_after,
        8
    );
    clock.set(16_249_999_999);
    permit.charge_bytes(BIN_MAX_BYTES).unwrap();
    // One byte needs just over 29 ns at the default rate; fractional
    // credit survives observations and non-content frames.
    clock.set(16_250_000_014);
    permit.charge_bytes(0).unwrap();
    clock.set(16_250_000_029);
    permit.charge_bytes(1).unwrap();
    let rates = controls
        .states
        .lock()
        .unwrap()
        .get(&A)
        .unwrap()
        .rates
        .lock()
        .unwrap()
        .bytes
        .credit;
    assert_eq!(rates, 6_632_960);
    let config = ControlsConfig::parse("1,1,33554432,268435457,4").unwrap();
    let controls = PrincipalControls::new(config, clock);
    let permit = controls.admit(B, true).unwrap();
    assert_eq!(
        permit.charge_bytes(u64::MAX).unwrap_err().retry_after,
        9,
        "delay rounds up"
    );
}

#[test]
fn defaults_bound_submission_burst_and_refill() {
    assert_eq!(
        ControlsConfig::default().tuple(),
        (46, 5, 33_554_432, 268_435_456, 4)
    );
    let (controls, clock) = fixture();
    for _ in 0..5 {
        drop(controls.admit(A, true).unwrap());
    }
    assert_eq!(refused(controls.admit(A, true)), 1);
    clock.set(21_739_130);
    assert_eq!(refused(controls.admit(A, true)), 1);
    clock.set(21_739_131);
    drop(controls.admit(A, true).unwrap());
    assert_eq!(refused(controls.admit(A, true)), 1);
}

#[test]
fn byte_bucket_refills_after_backward_clock_step() {
    let (controls, clock) = fixture();
    let config = ControlsConfig::default();
    let permit = controls.admit(A, false).unwrap();
    permit.charge_bytes(config.byte_burst).unwrap();

    let lower = -3_600_000_000_000;
    clock.set(lower);
    assert_eq!(
        permit.charge_bytes(1).unwrap_err().retry_after,
        8,
        "a one-hour backward step grants no credit"
    );

    let full_refill = i128::from(config.byte_burst.div_ceil(config.byte_rate)) * 1_000_000_000;
    clock.set(lower + full_refill);
    permit
        .charge_bytes(config.byte_burst)
        .expect("the byte bucket must be full after its refill time from the lower watermark");
    assert_eq!(permit.charge_bytes(1).unwrap_err().retry_after, 8);
}

#[test]
fn eviction_requires_fresh_state() {
    let (controls, clock) = fixture();
    let permit = controls.admit(A, true).unwrap();
    permit.charge_bytes(BIN_MAX_BYTES).unwrap();
    drop(permit);
    for n in 2..100 {
        drop(
            controls
                .admit(PrincipalId::from_bytes([n; 16]), false)
                .unwrap(),
        );
    }
    assert!(
        controls.states.lock().unwrap().contains_key(&A),
        "depleted idle state survives churn"
    );
    assert_eq!(controls.states.lock().unwrap().len(), 2);
    let permit = controls.admit(A, false).unwrap();
    clock.set(8_000_000_000);
    drop(controls.admit(B, false).unwrap());
    assert!(
        controls.states.lock().unwrap().contains_key(&A),
        "full state with a live permit survives"
    );
    drop(permit);
    drop(
        controls
            .admit(PrincipalId::from_bytes([101; 16]), false)
            .unwrap(),
    );
    assert!(
        !controls.states.lock().unwrap().contains_key(&A),
        "only full and idle is swept"
    );
    assert_eq!(controls.states.lock().unwrap().len(), 1);
}
