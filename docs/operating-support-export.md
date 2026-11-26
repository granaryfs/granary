<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Operating local support exports

The local command produces a private diagnostic archive from disk with a
manifest describing its contents.
It reads no environment variable or credential source and runs before the
serving runtime starts. It does not contact the running server. Snapshot,
configuration, manifest, archive and log-metadata projection are frozen v1
(2026-10-06), with their byte layouts and decoder accept sets fixed. A normally
configured authority server produces the required support files.

## Provisioning

Provision `enrollment_dir/SUPPORT` before starting the authority server. It
must be a real directory owned by the server uid, with mode `0700`. The
server does not create it. Use an absolute, symlink-free path with protected
ancestors, following [the enrollment directory rules](operating-enrollment.md).
The separate authority state directory holds the configured volume logs.

The server publishes `SUPPORT-CONFIGURATION` once at startup, after the
listener binds, and `SUPPORT-SNAPSHOT` at a fixed **60 second** interval.
The snapshot copies cached observation, including counters and sanitized
grant state. Publication happens off the serving runtime, with one job in
flight; ticks during a blocked job are skipped. Both files use the support
directory's own flock. Their temporary names are `SUPPORT-CONFIGURATION.tmp`
and `SUPPORT-SNAPSHOT.tmp`. Missing, corrupt, unsafe or oversized required
files refuse the whole export, including before the first snapshot tick.

## Command and archive contents

```text
granary-server support-export --support-dir S --state-dir D --out A \
  [--incarnation incarnation:<32 lowercase hex>] \
  [--accept-unsupported-filesystem]
```

All three paths must be absolute. Run as the source directory owner or root.
`S` is the provisioned support directory and `D` is the authority state
directory. `A` names a new archive in an existing `0700` parent owned by the
invoking uid, outside both source trees. Publication creates a `0600` file
and refuses an existing destination. The filesystem acknowledgement waives
only filesystem eligibility; it never waives ownership, permissions, type
or symlink checks. On platforms without a supported filesystem profile it
is a development acknowledgement.

The archive carries `snapshot.bin`, `configuration.bin`, validated volume
log metadata members named `<volume>.logmeta`, and a manifest recording each
exported or refused source. Log members contain descriptor metadata and the
validated envelope projection; at most **4096 bytes** of each source log are
read. A log refusal is recorded without a member. Unknown files are refused
as `not-allowlisted` manifest entries under synthetic identifiers; their
names and contents are never copied. The snapshot holds volume views,
enrollment reader state and all nine enrollment counters, retained refusal
counters and principal rows, and structural debug-grant state and budgets.
The configuration is a field allowlist of validated startup settings and
the actual bound port.

It never carries key bytes (including public keys), TLS certificate or CA
files, enrollment credentials, their digests or bindings, raw enrollment,
grant, marker or log files, temporary contents, grant owner/reason labels,
configuration paths, endpoints, buckets, regions, access-key identifiers,
secret keys, tokens, proxy values, logging filters, event bodies or arbitrary
error text. Treat the archive as operator data: retained principal identifiers
and counters remain diagnostic information.

## Incarnation and snapshot age

The snapshot and configuration incarnations must agree. `--incarnation`
adds an operator expectation that must match both files. Its spelling is
exactly `incarnation:` followed by **32 lowercase hexadecimal digits**.
Copy the expected value from the server's readiness diagnostic when an
export must describe that run.

A matching pair can remain after a stopped server or from a prior run.
The archive describes disk-sampled state, with separately sampled domains;
it does not attest that a process is alive or that log history is committed.
Inspect the manifest's `incarnation`, `sampled_at`, `exported_at` and age.
An age strictly greater than **120 seconds** is `stalled-writer`; exactly
120 seconds remains fresh. A sample later than export time is
`clock-regressed`, with the positive clock lead recorded. Both conditions
remain exportable and must be interpreted explicitly. Investigate the writer
or clock rather than interpreting these samples as current process state.

## Publication and exit codes

Normal success is silent. A refusal prints one bounded line naming a fixed
reason, best effort with a bounded reporting wait. The verb reads the pair
under the support flock, releases it before metadata inspection and archive
construction, and never takes the authority state-directory flock. A blocked
verb does not involve serving. Publication uses a synced private temporary
and a no-replace pathname hard link, then syncs the parent. The final
check-to-link interval is inside the trusted-owner boundary.

| Exit | Meaning |
| --- | --- |
| 0 | A complete archive was durably published. |
| 64 | Invalid arguments; no export attempted. |
| 65 | Policy, protection, required-format or incarnation refusal before publication; no final archive. |
| 74 | I/O failure or publication uncertainty. A post-publication failure preserves the complete final artifact; inspect the destination before retrying. |

The command chooses no retention policy. Archive retention, upload and
deletion policy remain undecided; this command produces only the local artifact.
