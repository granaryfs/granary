// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A route result deadline includes setup, assertions and fixture teardown.

use std::sync::mpsc;
use std::time::Duration;

const RECOVERY_BOUND: Duration = Duration::from_secs(6);

pub(super) fn run(
    name: &'static str,
    phase: &'static str,
    bound: Duration,
    action: impl FnOnce() + Send + 'static,
    recover: impl FnOnce() -> String,
) -> Result<(), String> {
    eprintln!("mounted sync fault route start: {name}/{phase}; bound={bound:?}");
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
        let _ = sender.send(outcome);
    });
    let outcome = receiver.recv_timeout(bound);
    let reason = match &outcome {
        Ok(Ok(())) => {
            // No fixture or user action remains after the worker sends its result.
            return worker
                .join()
                .map_err(|_| format!("route={name}/{phase}: result worker panicked"));
        }
        Ok(Err(_)) => "panicked",
        Err(mpsc::RecvTimeoutError::Timeout) => "exceeded route bound",
        Err(mpsc::RecvTimeoutError::Disconnected) => "lost result worker",
    };
    let observed = recover();
    let settled = outcome.is_ok() || receiver.recv_timeout(RECOVERY_BOUND).is_ok();
    // A worker still blocked in the kernel cannot be joined with a bound; it is
    // detached and ends with this test's process (nextest runs one per test).
    let reaped = if settled || worker.is_finished() {
        worker.join().is_ok().to_string()
    } else {
        "false (still blocked; detached until the test process exits)".to_owned()
    };
    Err(format!(
        "route={name}/{phase}: {reason} ({bound:?}); {observed}; worker_reaped={reaped}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_linux_fault_route_completed_and_stalled_controls() {
        let mut cases = 0;
        for stalled in [false, true] {
            let (release, wait) = mpsc::channel();
            let (started, ready) = mpsc::channel();
            let (completed, returned) = mpsc::channel();
            let result = run(
                "sync.floor",
                "checked",
                if stalled {
                    Duration::from_millis(50)
                } else {
                    Duration::from_secs(1)
                },
                move || {
                    started.send(()).unwrap();
                    if stalled {
                        wait.recv().unwrap();
                    }
                    completed.send(()).unwrap();
                },
                || {
                    // The 50 ms bound can expire before the worker is scheduled;
                    // wait for its start, then require it to be still pending.
                    let started = ready.recv_timeout(Duration::from_secs(5)).is_ok();
                    let returned = returned.try_recv();
                    assert_eq!(
                        (started, returned),
                        (true, Err(mpsc::TryRecvError::Empty)),
                        "stalled route must start and remain pending before recovery"
                    );
                    release.send(()).unwrap();
                    "fired=[sync.floor/checked]; outcomes=[]; sync_returned=false; shrink_returned=false"
                        .to_owned()
                },
            );
            if stalled {
                let refusal = result.unwrap_err();
                for expected in [
                    "route=sync.floor/checked: exceeded route bound (50ms)",
                    "fired=[sync.floor/checked]; outcomes=[]",
                    "sync_returned=false; shrink_returned=false",
                    "worker_reaped=true",
                ] {
                    assert!(refusal.contains(expected), "{refusal}");
                }
                assert_eq!(
                    returned.try_recv(),
                    Ok(()),
                    "recovery must release the route"
                );
                eprintln!("{refusal}");
            } else {
                assert_eq!(
                    (result, ready.try_recv(), returned.try_recv()),
                    (Ok(()), Ok(()), Ok(())),
                    "a successful result must come from the completed route"
                );
            }
            cases += 1;
        }
        assert_eq!(cases, 2);
        eprintln!("fault route deadline controls: {cases} cases");
    }

    #[test]
    fn writable_linux_fault_route_panic_controls() {
        let result = run(
            "sync.capture",
            "after",
            Duration::from_secs(1),
            || assert_eq!(1, 2, "injected route failure"),
            || {
                "fired=[sync.capture/after]; outcomes=[]; sync_returned=false; shrink_returned=false".to_owned()
            },
        );
        let refusal = result.unwrap_err();
        for expected in [
            "route=sync.capture/after: panicked (1s)",
            "fired=[sync.capture/after]; outcomes=[]",
            "sync_returned=false; shrink_returned=false",
            "worker_reaped=true",
        ] {
            assert!(refusal.contains(expected), "{refusal}");
        }
        eprintln!("{refusal}");
        eprintln!("fault route panic control: 1 case");
    }
}
