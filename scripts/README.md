<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# `scripts/`

The gate scripts CI runs, and the local lanes a developer can run by hand.

**Determine callers from executable invocations, not filename mentions.**
A filename in a COMMENT is not an invocation; read the call sites.

## The gates

**[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) is the list that runs**, and every gate in it is
a script here, so any of them can be run by hand.

| gate | what it refuses |
|---|---|
| [`check-core-purity.sh`](check-core-purity.sh) | I/O, tokio, clocks or proc-macros reaching `granary-core` |
| [`check-file-dispositions.sh`](check-file-dispositions.sh) | a `crates/*/src` file over 3,000 lines with no `// @file-disposition:` directive; and, at EVERY size, an `// @file-disposition-lines: <N>` assertion that no longer matches the file |
| [`check-fsguard-sites.sh`](check-fsguard-sites.sh) | an unaudited filesystem-lint licence; pins the licensed-site count |
| [`check-unsafe-sites.sh`](check-unsafe-sites.sh) | an `unsafe` site outside the per-crate table the gate carries |
| [`check-licence-boundary.sh`](check-licence-boundary.sh) | AGPL server logic reaching an Apache crate |
| [`check-licence-resolved.py`](check-licence-resolved.py) | the same boundary, over what `cargo metadata` resolved and what rustc's own dep-info compiled — the spellings a text scan cannot reach |
| [`check-vfs-purity.sh`](check-vfs-purity.sh), [`check-vfs-deps.sh`](check-vfs-deps.sh), [`check-vfs-root-shape.sh`](check-vfs-root-shape.sh) | `granary-vfs`'s source and dependency axes; and the root SHAPE of both gated crates, `granary-vfs` and `granary-fuse` |
| [`check-protocol-constants.py`](check-protocol-constants.py) | wire spellings, resource assignments and limits that differ from the reviewed compatibility rows |
| [`check-server-log-path.sh`](check-server-log-path.sh) | a runtime-worker log bypassing `tracing`, a standard-stream handle outside the allow list, or missing production request-span/`served` instrumentation |
| [`check-mount-write-path.sh`](check-mount-write-path.sh) | a bare mount standard-stream write (no terminal exceptions); only the bounded direct writer and main's sink construction may obtain stderr; missing sources, anchors, panic-hook installation or scan boundaries also refuse |
| [`check-inventory-fresh.sh`](check-inventory-fresh.sh) | a [`supply-chain/`](../supply-chain/) inventory stale against the locks |
| [`check-citations.py`](check-citations.py) | a `path:N` citation that points past the end of its target file |
| [`check-fuse-sync-wire.py`](check-fuse-sync-wire.py) `--self-test`, [`test-authority-lifecycle-strace.py`](test-authority-lifecycle-strace.py) | a change to either syscall-trace checker (the FUSE sync wire witness, the authority venue's lifecycle check) that breaks its paired valid and malformed controls |
| [`check-fail-open.py`](check-fail-open.py) | a gate that silently stops checking — the fail-open shape lint |

[`check-fail-open.py`](check-fail-open.py) is the one row `ci.yml` does not run; run it by hand.

Scanners the gates call rather than run themselves: [`fsguard-scan.py`](fsguard-scan.py),
[`vfs-purity-scan.py`](vfs-purity-scan.py), [`vfs-root-shape-scan.py`](vfs-root-shape-scan.py), [`dep-inventory.sh`](dep-inventory.sh).

## The live local lanes

Run by hand; some also run in CI. **NOT all of them have a self-test**, and the split
matters: [`linux-container.sh`](linux-container.sh) and [`ci-mounts.sh`](ci-mounts.sh)
each carry one, [`blocked-stderr.sh`](blocked-stderr.sh)'s `--self-test-witnesses` checks its own witness list, and [`stack.sh`](stack.sh)'s is the separate
[`stack-self-check.sh`](stack-self-check.sh). [`conformance.sh`](conformance.sh) and
[`demo.sh`](demo.sh) do NOT — they are driven end to end by
[`linux-container.sh --self-test`](linux-container.sh) instead, a different instrument.
[`unit-check.sh`](unit-check.sh) has no self-test either, and that instrument deliberately
does not drive `cmd_unit`; the unit check runs only through `linux-container.sh unit`.
[`demo-self-check.sh`](demo-self-check.sh) is [`demo.sh`](demo.sh)'s checker and a separate file, not a flag.

- **[`linux-container.sh`](linux-container.sh)** — the Linux repro harness. `test` runs two lanes
  (container-root for `granary-fuse`, container-nonroot for `granary-client`'s
  clippy and doc). The only local venue that compiles the Linux-gated daemon body.
  It is also the DISPATCHER for the four lanes that follow: they are the bodies of
  its `conform`, `mount`, `demo` and `unit` subcommands, its usage line advertises
  them, and it asserts their stdout markers by name.
- **[`conformance.sh`](conformance.sh)** — the conformance body behind
  [`linux-container.sh conform`](linux-container.sh); prints `CONFORM: identical, <n> rows`.
- **[`blocked-stderr.sh`](blocked-stderr.sh)** — the real-kernel stderr battery behind
  [`linux-container.sh mount`](linux-container.sh) and CI's `fuse` job. Its `--check-log` mode requires
  every named witness; `--self-test-witnesses` rejects deletions and duplicates.
  [`blocked-stderr-controls.sh`](blocked-stderr-controls.sh) builds the optional single-site mutants in scratch
  source copies using `blocked-stderr-controls/*.patch`.
- **[`demo.sh`](demo.sh)** (+ **[`demo-self-check.sh`](demo-self-check.sh)**) — the demo body and its own
  self-check, behind [`linux-container.sh demo`](linux-container.sh).
- **[`unit-check.sh`](unit-check.sh)** — the systemd unit check, run under sudo on a real
  systemd host by [`linux-container.sh unit`](linux-container.sh). Each case prints
  `UNIT: <case> PASS`.
- **[`stack.sh`](stack.sh)** (+ [`stack-self-check.sh`](stack-self-check.sh)) — the local object store, pinned-TLS
  server and publication stack.
- **[`minio-harness.sh`](minio-harness.sh)** — MinIO for the conditional-write lane.
- **[`ci-mounts.sh`](ci-mounts.sh)** — lists, checks or reaps the CI FUSE lane's mounts.
- **[`authority-venue.sh`](authority-venue.sh)** (+ **[`authority-venue-strace.py`](authority-venue-strace.py)**, its
  syscall-trace checker) — the authority log adapter's Linux venue: ext4 on a loop device
  behind a device-mapper table in the podman VM, the adapter's tests on it, a traced
  workload, a sync the device fails, the SIGKILL crash harness, and a power-loss attempt
  (a `flakey` table that drops writes, with a canary). Each lane prints `VENUE <lane>: OK`.
  The checker's lifecycle mode has paired controls, [`test-authority-lifecycle-strace.py`](test-authority-lifecycle-strace.py),
  which the gates job runs; the power-loss lane's controls are recorded with its runs.

[`conformance.sh`](conformance.sh), [`demo.sh`](demo.sh), [`demo-self-check.sh`](demo-self-check.sh) and [`unit-check.sh`](unit-check.sh) are live
local lanes: [`linux-container.sh`](linux-container.sh) invokes them even though no gate or CI job
does. Absence from gates and CI therefore does not make them closed harnesses.
[`linux-container.sh`](linux-container.sh) is itself not CI-invoked; its [`.github/`](../.github/) reference is
a comment, which does not count as an invocation.

## A library, not a script

[`vfs-scratch-fixture.sh`](vfs-scratch-fixture.sh) is **sourced**, not run: [`check-vfs-deps.sh`](check-vfs-deps.sh) and
[`check-vfs-purity.sh`](check-vfs-purity.sh) both pull it in for the scratch fixture. It would break
if invoked directly.

## Data a script reads

[`linux-container.Containerfile`](linux-container.Containerfile).

## Environment variables: the prefix names who sets it

| prefix | who sets it |
|---|---|
| `GRAN_*` | an operator, in `/etc/granary/mounts/<volume>.env`. A file format the shipped `gran-mount@.service` reads — **closed**, nothing new joins it |
| `GRANARY_<domain>_*` | a person, in a shell. Read with a default |
| `GRANARY_SELFTEST_*` | a self-test, to make something fail, lie, race or drop a grant so a refusal can be proven |
| `LANE_*` | nothing. The host half of `linux-container.sh` passes these to its own container half with `-e`; a host shell cannot reach them, which is why they are **not** in the `GRANARY_` namespace |

A name that is not read from the environment takes an ordinary descriptive
name and no prefix at all.
