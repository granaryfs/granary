<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Server processes in CI

A `std::process::Child` does not kill its process when dropped. Fixture ownership
must exist immediately after spawn and remain in the waiting caller. A drop guard
handles ordinary return and panic unwinding; it cannot execute after abort or
SIGKILL. Bash EXIT traps also run on ordinary TERM termination; traps cannot
execute after SIGKILL.

## Launch inventory

| Launcher | Success | Failure or panic | Test timeout, SIGKILL, job cancellation |
| --- | --- | --- | --- |
| `crates/granary-server/tests/binary_signals.rs` | Signals the shipped server, observes exit, reaps it. | `Reaped` owns startup; `process::ChildGuard` owns the bounded exit wait and kills/reaps on unwind. | A local wait timeout drops the guard. Forced process death bypasses it; CI's final process check detects surviving server binaries. |
| `crates/granary-server/tests/shipped_store_config.rs` | Signals serving fixtures; startup-refusal fixtures observe exit. | `Reaped`, `Spawned`, and the bounded wait guard kill/reap held children. | Forced death bypasses Drop; final CI check applies. The fanout row never signals a PID after reaping it. |
| `crates/granary-server/tests/authority_config.rs` | Reads startup refusal and reaps the binary. | Guard remains in the caller while a separate thread reads stderr. Timeout and unwind kill/reap it. | Forced death bypasses Drop; final CI check applies. |
| `crates/granary-server/tests/authority_host.rs` and `authority_host/support.rs` | `Process::exit` observes status and stderr EOF; `ExportProcess` observes export completion. Explicit binary verbs use bounded capture. | `Process` and `ExportProcess` are constructed before pipe/thread setup. Their Drop implementations kill/reap; command capture also retains ownership. | Runtime timeout unwinds through ownership. SIGKILL/abort bypasses it; final CI check applies. |
| `crates/granary-server/tests/publish_restart/{process,composition,shipping,tails,retained}.rs` | Shared `Process` observes exit, or intentionally kills and reaps a restart fixture. Composition owns its host and MinIO. | Existing `Process` and `Minio` drops kill/reap; ownership precedes readiness checks. | Runtime timeout drops the fixture; forced test death bypasses it. The final CI check is the backstop. |
| `crates/granary-server/tests/{enrollment_cli,debug_grant_cli,support_export_cli}.rs` and `support_export/fixture.rs` | Explicit CLI verbs finish; enrollment also checks ordinary startup refusal. Shared guarded output captures both pipes and observes status. | The capture guard owns the process through pipe setup, reader startup, bounded wait, and refusal. | Forced test death bypasses the guard; final CI check applies. These normally execute finite verbs rather than serving. |
| `scripts/stack.sh` | Execution probe refuses startup without a listen address. `start` deliberately transfers running server/MinIO ownership to its caller via state files; `stop` checks identities, sends TERM, waits, escalates to KILL and verifies death. | Partial-start EXIT cleanup is armed before MinIO/server startup; Bash TERM termination also reaches it. | SIGKILL bypasses partial cleanup. A successful start requires caller cleanup or external containment; standalone start intentionally leaves services running. |
| `scripts/conformance.sh`, `scripts/demo.sh` | Their EXIT teardown calls `stack.sh stop`. | The same EXIT teardown runs on failure and on TERM. | SIGKILL bypasses it. Neither runs in `ci.yml`; `linux-container.sh` runs them in a container, whose PID namespace contains every descendant. |
| `scripts/publish-restart.sh` | Runs only cargo; the Rust fixture guards reap servers. | Same guards. | nextest runs each test in its own process group, so a shell-level group kill cannot reach a test's server; the CI final process check applies. |
| `.github/workflows/ci.yml` FUSE stack | Runs `stack.sh start` inside a transient systemd stack scope. Always-teardown stops stack and scopes; existing hard gate checks units/mounts. | The same always-teardown handles failed steps. | Scope teardown covers descendants of killed tests while the runner can execute cleanup. The final process check additionally observes server binaries. |
| `scripts/linux-container.sh` | Conformance/demo delegate to the scripts above; publish-restart delegates through `authority-venue.sh`. The unit stack deliberately remains in its container until container teardown. | Container teardown removes its PID namespace and all contained server processes. | A killed container main process destroys the namespace. Killing only the host launcher can leave a container until its owner removes it; this script is a local Linux venue, not invoked by `ci.yml`. |

`deadline_exit.rs` launches its own integration-test executable, not the
`granary-server` executable. It uses `Reaped` for startup and the same bounded
wait guard for shutdown. `mounted/mod.rs` launches the client, not the server.
The FUSE and client mounted fixtures consume an externally supplied server;
`granary-conformance` launches no server. `scripts/minio-harness.sh` launches only
MinIO; `scripts/check-publish-restart.py` builds and inspects server bytes without
executing them. Measurement scripts (`m7-demo.sh`, `m10-*.sh`, and research
fixtures) are not invoked by CI and do not provide CI process containment.

## Final job check

The `test`, `breakage`, `crash-points`, `publish-restart` and `fuse` jobs record a
process baseline before running server-capable steps and execute
`check-server-processes.py check` with `if: always()` at their end. The weekly
macOS test job does the same. A missing baseline or failed/malformed process
inventory refuses the check; a clean result includes a nonzero observation count.
A new server identity in the job's checkout or runner temporary tree fails the
job. Linux checks additionally signal survivors through pidfds, after rechecking
the identity, and still fail the job. Already-present processes and processes in
other workspace trees are excluded. Linux identity uses `/proc` start ticks;
macOS uses `ps` start time and executable path. No process arguments or
environment bytes are read or printed.

Attribution requires exclusive use of each runner workspace and temporary tree
for the job's duration. Executables launched outside both trees, an observer that
silently hides processes, and a runner stopped before its final step remain
outside this check's guarantee. A hard cancellation or host failure that prevents
all cleanup requires external runner/cgroup teardown. A process that deliberately
changes its executable name also escapes this inventory; the fixtures execute
known server binaries without doing so. No supplied orphan PID alone identifies
which fixture originally launched it.

`check-server-processes.py self-test` exercises scanner/refusal
fixtures and workflow wiring; `live-self-test` separately plants an orphan and
checks real CLI failure, cleanup and clean success. Live observation requires a
host that permits `ps` and, on Linux, `/proc` inspection and pidfds.
