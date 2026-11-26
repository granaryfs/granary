<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Client observability

What `gran` writes to its logs, how to choose where and in what shape, and the
names a script or a test may match. This page is for whoever runs a mount
([`operating-a-mount.md`](operating-a-mount.md)) or writes tooling around one.

The rule that governs everything below: **an event name and a field name are
identifiers, not prose.** They do not change with the wording of a message, and
a test of a failure asserts the event, not only the exit code. Messages and
filter details use fixed templates; callers cannot supply free text.

## Choosing the output

Four settings, each from a flag, an environment variable or a configuration
file:

| setting | flag | environment | file key | values | default |
|---|---|---|---|---|---|
| format | `--log-format` | `GRANARY_LOG_FORMAT` | `format` | `text`, `json` | `text` |
| destination | `--log-file` | `GRANARY_LOG_FILE` | `file` | a file path | standard error |
| paths | `--log-paths` | `GRANARY_LOG_PATHS` | `paths` | `redacted`, `full` | `redacted` |
| filter | `--log-filter` | `GRANARY_LOG_FILTER` | `filter` | tracing filter directives | `RUST_LOG`, else `info` |

The configuration file itself is named by `--log-config` or
`GRANARY_LOG_CONFIG`. The flags are the leading arguments of any command
(`gran --log-format json mount ...`); they are not available to `mount.gran`,
whose operands are the kernel's, so a mount started from `fstab` is configured
by the environment or the file.

`gran overlay discard` and `gran overlay reconcile` use a fixed, redacted JSON
event stream on stderr. They dispatch before logging configuration, and their
terminal diagnostics and stdout TSV keep their existing format.

**Precedence, per setting:** flag, then environment, then configuration file,
then the default. Foreign/dependency filter targets are inert under callsite admission.
For the filter, `RUST_LOG` sits below the configuration
file.

**A value that is not understood is refused, not rounded.** `gran` exits with
status 2 before it does anything else and names the source and the key:

    gran: --log-format: expected one of text, json; got "xml"
    gran: GRANARY_LOG_FILE: needs a nonempty file path
    gran: /etc/gran/log.conf: format: expected one of text, json; got "xml"

Every source is checked even when a higher one overrides it. An unreadable
`RUST_LOG` is the older exception: it runs the default filter and reports a
`log.filter_rejected` event.

The configuration file is `key = value` lines; blank lines and lines starting
with `#` are ignored; the keys are `format`, `file`, `filter` and `paths`; an unknown or
repeated key is refused. It must be a regular file owned by the user running
`gran`, not writable by group or other, no larger than 16 KiB, and not reached
through a final symbolic link. A process that entered through set-ID handling
reads no logging flag, environment variable (`RUST_LOG` included) or file,
and runs at the default filter; its leading `--log-*` arguments are removed
unread, so the command it names prints its own set-ID refusal. The file is
opened without waiting, so a named pipe at its path is refused at once.

### Destinations

- **Standard error** is the default and the right choice under a service
  manager: with systemd, standard error goes to the journal, so a unit needs
  nothing more than `--log-format json` if the journal's consumers want JSON.
- **A rotated file** (`--log-file`). The file is created private to the user
  (mode 0600), is not opened through a final symbolic link, and must be owned
  by the user running `gran`. When the next line would take it past 8 MiB,
  `<file>` becomes `<file>.1`, `.1` becomes `.2`, and so on, keeping three
  generations; the oldest is overwritten. A line is never split across files.
  One process owns a log file. If the file cannot be opened `gran` exits with
  status 1 before it starts. The path must be a regular file with a single
  hard link (a named pipe, a device or a file with other names is refused),
  and it is opened without waiting for a reader.
- **A log file that fails does not end logging.** If a rotation fails (a
  rename or the reopen), `gran` keeps appending to the current file, writes
  one line saying so (`cannot rotate the log file ...`) and tries again after
  the file has grown by another 8 MiB; a later success re-arms the line. If a
  write to the file fails, `gran` moves to standard error for the rest of the
  process, writes one line there saying so (`cannot write the log file ...`)
  and writes the line that failed to standard error too. In JSON these two
  lines are `log.line` objects.

### The output does not slow the mount

Records reach the destination through a bounded queue drained by one thread.
No producer waits on the destination, whether it is a full pipe or a slow
disk. When the queue is full, telemetry lines are dropped first and counted;
the user-facing results `gran mount` prints keep a reserved share and are
dropped only when that is full too, and counted. The counts are reported:

- in text, as `[gran log sink: N telemetry line(s) dropped under backpressure]`
  (and the variants naming protected messages);
- in JSON, as one `log.sink_loss` object with `telemetry_dropped` and
  `protected_lost` and `local_lost`. It carries no timestamp.

A count is reported when the destination drains again, and at shutdown within
the bound the process allows itself to exit.

Local and Protected records share a FIFO, the 64-slot reserve and priority over
telemetry within the 1024-record queue. One worker selects the destination for
each record. Local reports always go to the owned descriptor captured from
original standard error before redirection. No second worker is created. Both
destinations share one 500 ms best-effort close allowance; a blocked write can
delay either stream, and delivery after that allowance is not promised.

`local_lost` counts Local records refused at admission. Loss notices go to the
telemetry destination, including a selected log file, at reserved priority.
A permanently blocked or failed destination may prevent the notice too.
In text the existing loss template carries an additional `local_lost=N` field.

In JSON, telemetry is one object per line. Local and Protected operator results remain
plain text on original standard error, including when a log file is selected;
they are never wrapped into telemetry. Worker rotation and write notices are
`log.line` objects from fixed templates over a log-file class and I/O class.
The sink's counts become `log.sink_loss` directly, without parsing text.

Not everything is written through the queue. Text that `gran` writes directly
to standard error stays plain text in every format: a refusal of a logging
option or of a configuration file or log file (`gran: ...`), the usage text
and a command's argument-error message, a set-ID refusal, a panic report and a
command's own report (`gran publish --json` writes its own JSON report, in its
own schema). A refused namespace recovery writes its complete B5 stage inventory
as plain text directly to standard output. That inventory is never telemetry or
bundle input. These reports appear before the queue exists or outside it.

Counters and other metrics do not read the log filter: turning verbosity up or
down changes which lines are written and never what is counted.

Typed Local reports retain pinned publication, history, EQUIVOCATION, cache and
degraded-read information even with the log filter OFF. Local close warnings
carry a closed failure class and an optional numeric errno; they do not render
provider error text or chains. Local reports never become `log.line`, log-file
content or bundle input. A stderr/journal collector can still see their local
volume names and required digests. Workspace exhaustion reports disclose the
escaped captured namespace path, or boundary context, with needed and limit bytes
to stderr/journal collectors, independently of `--log-paths redacted`.
Caller-owned conflict status retains its exact namespace path and `ESTALE`, with
a 4096-byte path bound, independently of report delivery. Its separate `op.failed`
and `op.conflict` events share the operation id; by default they disclose the
conflict class and `<file>` path class.
The explicit full-path policy can disclose the ordinary conflict path in telemetry.
The bundle projection always retains `<file>`.

## Redaction

Debug output for logging settings, raw options, prepared arguments, rotated
files and destinations contains fixed classes only. An ordinary log path is
represented by `<log-file>`; filters, configuration, arguments and writers
have fixed classes too. The client credential renders `<credential>`, and its
errors render `<credential-error>` under Debug. Credential-error Display
retains the information used by local operator diagnostics.

The direct panic diagnostic is always `gran: panic: internal failure`, even
with logging off. It deliberately loses the payload, thread name, source
location and backtrace. `RUST_BACKTRACE` is ignored by this direct report.
The hook preserves Rust's unwind or abort behavior and failure status. Its
direct delivery waits at most 500 ms; a blocked destination can lose the
diagnostic while the process still exits.

Direct configuration refusals can disclose their invalid value and the
configuration-file path to stderr readers, including a journal collector.
The filter refusal includes the parser error chain, for example:

```text
gran: --log-filter: "sentinel_target=loud" was not understood (error parsing level filter: expected one of "off", "error", "warn", "info", "debug", "trace", or a number 0-5)
```

These refusals occur before subscriber installation and do not enter telemetry.
The installed subscriber admits only registered target, source-file and line
triples, then checks the complete field schema, scalar types and closed domains
before filtering or storage. Unknown tracing callsites and formatted Debug or
Display fields produce fixed `log.record_refused` reasons without their values.

Cache, store, resolver, transport and mount diagnostics retain fixed messages
and meaningful counts. Identity slots contain role classes such as `<volume>`
or `<object>`; ordinary paths contain role classes such as `<file>` and
`<cache-root>`, and names contain `<name>`. Provider errors contribute closed
failure classes rather than their formatted chains. The structure-walk
instrument keeps INFO level, its `granary_client::resolve` target, field
spellings and text prefix.

The default path tokens are `<file>`, `<directory>`, `<cache-root>`,
`<store-root>`, `<mountpoint>`, `<log-file>` and `<unknown>`; a directory-entry
name is `<name>`. These are semantic classes, never literal basenames.
`--log-paths full` authorizes only the inventoried ordinary path/name slots in
this process's text/JSON telemetry, including conflict detail, worker notices,
rotated generations and stderr fallback, plus the path slot in the direct B5
standard-output inventory. It does not authorize endpoints, buckets, regions,
scopes, principals, volume names, content digests, key identifiers, credentials,
tokens, signing/TLS/public-key or certificate bytes, or credential/certificate
file paths. Secrets deliberately embedded in an ordinary filename are disclosed
when that ordinary slot is explicitly enabled. Every fresh process defaults to
`redacted`; set-ID entry reads no configuration.

Within telemetry and stderr, full paths preserve supplied bytes without
filesystem lookup or expansion. Quotes, backslashes, control bytes and non-UTF-8
bytes are escaped. Each telemetry or stderr source path/name is bounded to 4096
bytes; a larger value becomes its class plus `path_too_large`, with no identifying
prefix. A telemetry record exceeding 32768 encoded bytes becomes a fixed
`log.record_refused` with `record_too_large`. The B5 stdout inventory instead
percent-encodes every byte outside ASCII alphanumerics and `._-/`; it is lossless
at every valid namespace-path length, including paths of roughly 4479 bytes.

Only exact lower-case `redacted` and `full` are accepted. File grammar trims
whitespace; flag/environment values do not. Invalid lower-priority sources
still refuse before output setup, with exit 2. The new refusals never echo the
invalid path-policy value, unknown key or configuration path:

```text
gran: log paths (flag): expected redacted or full
gran: log paths (environment): expected redacted or full
gran: log paths (configuration): expected redacted or full
gran: log paths (flag): missing value
gran: log paths (flag): repeated option
gran: log paths (configuration): repeated key
gran: log configuration: unknown key
gran: log paths (flag): value is not valid UTF-8
gran: log paths (environment): value is not valid UTF-8
```

Existing format/file/filter and configuration custody/read refusals retain
their direct local diagnostics and may quote values or paths as described
above. Neither refusal style enters telemetry or bundle history.

`log.record_refused` has only fixed reasons: `unregistered_callsite`,
`invalid_schema`, `invalid_scalar`, `invalid_domain`, `debug_field` and
`record_too_large`. It includes no rejected values or formatted error chain.
A dependency callsite the filter would admit is refused once per session, not once
per event, and a refusal reaches telemetry only if the filter admits a warning.

Bundle input is independently constructed as typed redacted records before
filtering, queue admission or storage; full telemetry policy never widens it.
The recent history keeps at most 1024 whole records and 1048576 encoded bytes,
evicts oldest records and counts loss. It receives facade events at INFO and
above, with their operation id, even when logging is OFF (the telemetry filter
never gates it), and independently projected worker/refusal records. Local
reports, direct diagnostics, raw configuration and captured log bytes have no
history ingress. The offline support-bundle writer does not collect this
in-memory history. It marks logs unavailable; rotated logs and captured stderr
are never a fallback bundle source.

## Support bundles

For a live mount whose process was started with `gran mount --support-bundle`,
request the producing process's bounded in-memory support data without reading
through the mounted filesystem:

```text
gran support-bundle MOUNTPOINT --output FILE
```

The live command has one two-second bound for connecting and receiving the
reply. An unavailable or unresponsive producer exits 1 with `support producer
unavailable`; a malformed reply exits 1 with `malformed support reply`. It
never switches to offline collection automatically. Invoke the offline form
separately when that is the intended source of evidence.

The requester resolves the mount target using the same parent-resolution rule
as mount and unmount. Source roots at or beneath that resolved target are not
walked: the mounted-namespace path and FUSE device exclude that namespace as a
whole. Source roots outside it are re-proved against the producer's identities
before publication. An output beneath the target is refused lexically before
the output path is opened.

When a mount process is down, write a bounded support bundle with explicit
source declarations:

```text
gran support-bundle --output FILE --offline \
  --cache-dir DIR|none --overlay-dir DIR|none --store-dir DIR|none \
  --mountpoint DIR|unknown
```

Use `none` only when that source was not configured. Use `unknown` only when
the mountpoint is not known; it cannot be combined with a declared source
path. A declared mountpoint must still exist so its filesystem identity can be
proved. The output parent must already satisfy the private archive custody
rules.

If the mount daemon has stopped but the FUSE mount is still attached, detach it
first with `gran umount MOUNTPOINT`, then run the offline command. A stale
attached mount can make the kernel return `ENOTCONN` while the writer proves the
declared mountpoint; the writer refuses that state rather than guessing its
identity.

Exit 0 means the archive was durably published, not that every member was
available. Exit 1 is a collection, encoding or pre-publication custody refusal;
exit 2 is invalid usage; exit 3 means publication landed but its final
durability or cleanup is uncertain, so inspect the named output before retrying.
Diagnostics have the fixed form `gran: support bundle: <reason>`.

An offline bundle always exports the invoking writer's build version. It does
not recover the stopped mount's version. Configuration, logs, failures and
metrics are refused as `unavailable`; cache and overlay are `not-applicable`
for `none`, otherwise `unavailable`.

Read the embedded manifest first. It has exactly one entry for each of
`version`, `configuration`, `logs`, `overlay`, `cache`, `failures` and
`metrics`. An exported entry gives the member length and digest; a refused
entry gives the closed reason and has no archive member. Verify the archive,
manifest digest and each exported member before interpreting its fields.

## Reading a line

Text uses scalar fields and operation context:

    WARN op{op="cor-0123456789abcdef" kind="commit" } granary_client::event event="op.retry" kind="commit" attempt=2 reason="conflict"

JSON places approved event fields beside `level` and `target`, with operation
context in `spans` (outermost first):

    {"level":"WARN","target":"granary_client::event","event":"op.retry","kind":"commit","attempt":2,"reason":"conflict","spans":[{"name":"op","op":"cor-0123456789abcdef","kind":"commit"}]}

Scalar encoders add no timestamp or terminal colour. Targets are registered
schema targets rather than arbitrary dependency module names. Correlation IDs
vary per operation; ordinary paths/names obey the scoped policy, and other
nonnumeric values come from closed domains.

## Correlation

Each client operation runs inside a span named `op` carrying two fields: `op`,
the operation's correlation id, and `kind`, what the operation is. Every event
emitted within an operation span, including those from code that knows nothing
of the span, carries both. Use the `op` field to join one operation across all of
its admitted events. Unknown foreign spans never supply inherited context. A line that is not an event emitted within a span (the notices
above, the sink's loss report, a direct refusal) carries no id, and neither
does an event from a thread or task that has not entered a span.

A correlation id is `cor-` followed by 16 lowercase hex digits, drawn from the
operating system's cryptographic randomness. It is never derived from a path, a
name, a clock or a counter. It is a different value from the publish operation
identity the wire carries (which is plain hex, with no prefix): the
`op.publish_bound` event names the wire identity in `publish_operation` inside
the operation's span, which is how the two are joined. Requests sent inside an
operation carry its id as `Granary-Request-Id`, the server logs it as
`wire_request_id`, and requests sent outside any operation (a FUSE kernel-thread
read, a prefetch called from one, or an operation whose entropy draw failed with
no enclosing operation) carry none. If the system could not
supply randomness the operation runs without an id and an `op.failed` event
with `class="unavailable"` says so.

The span is recorded at error level, so a filter that keeps any event keeps the
span and the id with it. One `gran` run is one `session` operation, entered on
the thread that runs the command, so the events that thread emits carry the
session's id. A thread or task that does not open an operation span carries no
id: an operation that runs on another thread or task must open its own span (a
narrower `kind`, its own id). The session, commit and fsync spans open theirs
around their work and carry them across the tasks and blocking hops they spawn.

## Events

Levels are as the logs print them. Fields are listed in emission order; every
event also carries `event`.

| event | level | fields | meaning |
|---|---|---|---|
| `overlay.recovery` | INFO | `outcome`, `files`, `bytes`, `record_index`, `cap`, `commit_requested`, `owed`, `stage_reserve`, `projected_reserve`, `ownership_reserve`, `completion_reserve`, `writer_reserve`, `journal_reserve`, `rolled_back_stages`, `rolled_back_bytes` | completed or pending overlay replay; outcome is clean, repaired or pending; a rollback makes a completed replay `repaired` and leaves a pending replay `pending`, with both outcomes reporting the number of stages rolled back and live extent bytes discarded; `cap` is the declared overlay cap; `commit_requested` is true when the overlay asks for an early commit, which includes recorded work above `cap`: it then opens, serves reads and refuses writes with `ENOSPC`; `owed` is how far charged, reserved and captured bytes exceed `cap` (zero within it), and the `*_reserve` fields are the reserve terms holding that room: every bound stage's re-bind and completion reserve, a retained projected seal's residual replacement growth, the ownership carrier's reserve, unresolved commits' completion slots, the writer record and the journal. Above `cap` no commit runs, and an automatic commit refused for room is retried only after ten minutes, or sooner when a handle closes, a landing installs, more room is measured or the overlay reopens; closing handles or raising `cap` (by more than `owed`, since room is also needed for the next write and commit) are the operator's levers. A pending recovery reports the same fields and still serves no reads; one that has not replayed (ownership not yet reconciled, or repair content unavailable) measures from the area's files, the journal's length and one stage per staged file, before unresolved commits' completion slots are known, so its `owed` is a lower bound |
| `overlay.cap_exhausted` | WARN | `reason`, `cap`, `charged`, `reserved`, `captured`, `needed` | overlay capacity refused a commit or sync reservation before filesystem I/O; refused data writes do not emit this event; `reason` is `OverlayCapacityExhausted`; `cap`, `charged`, `reserved`, and `captured` are the fresh failing-check measurement, while `needed` is the total additional request, not the shortfall (the shortfall is `charged + reserved + captured + needed - cap`) |
| `overlay.stage_rolled_back` | WARN | `rollback_seq`, `stage_id`, `old_size`, `restored_size`, `discarded_bytes`, `path` | an unacknowledged staging payload was durably restored. The escaped path follows the `--log-paths` policy. Re-emitted on reopen while no extent, truncate or file sync follows the rollback in the journal |
| `overlay.stage_rolled_back` | WARN | `rollback_seq`, `stage_id`, `old_size`, `restored_size`, `discarded_bytes` | as above for a detached stage, which has no path slot |
| `overlay.refused` | ERROR | `class`, `record_index`, `files`, `bytes` | overlay replay or commit refused; evidence retained |
| `overlay.discard_refused` | WARN | `reason` | An offline discard plan or move refused, or its output failed. `reason` is a fixed discard refusal identifier. Process admission failures use `set_id`. |
| `overlay.reconcile_refused` | WARN | `reason` | Archive reconciliation refused before reporting rows, reported an unresolved or integrity row, or could not write output. The two row outcomes use `OverlayArchiveUnresolved` and `OverlayArchiveRemoteIntegrity`. Pre-row refusals use the applicable fixed refusal identifier or `set_id`. A zero-row settlement emits no event. |
| `overlay.sweep` | INFO | `files`, `bytes` | unnamed staging removed after global evidence checks |
| `overlay.fault` | WARN | `point`, `phase`, `occurrence`, `record_index` | an armed test fault fired at a fixed persistence seam |
| `sync.fault` | WARN | `point`, `phase`, `occurrence`, `object_kind` | a feature-gated sync-engine fault seam fired; `point` is one of `sync.capture`, `sync.upload`, `sync.node_upload`, `sync.registration`, `sync.reply`, `sync.commit`, `sync.commit_wait`, `sync.floor`, `fuse.sync.view`, `fuse.sync.rename_directory`, `fuse.sync.reply`, `fuse.view.install` or `other`; `phase` is a fixed step name or `other` (`sync.commit` includes `boundary_recorded`, once the commit boundary is durable and before the submission is retained; `before_submit`, before the attempt charge and retained attempt save; `before_rebase`, before the merge onto a newer head; `after_rebase`, once the rebased candidate is saved durably; and `before_replace`, after the landed refresh is journaled and before the landed base replaces the overlay's; `fuse.view.install` has `before_switch`, once the session accepted the landed root and before the view switches, and `after_switch`, once the view switched); `object_kind` is `none`, `bin`, `manifest`, `grain_list`, `binmap`, `sheaf`, `directory` or `other`; exact capture and request identity stays in the harness control and is never logged |
| `op.begin` | DEBUG | `kind` | an operation began |
| `op.end` | DEBUG | `kind`, `outcome` | an operation ended |
| `op.retry` | WARN | `kind`, `attempt`, `reason` | an operation is being retried; `attempt` counts from 1 |
| `op.conflict` | WARN | `path`, `class` | namespace conflict detail; default path class, same operation join |
| `metrics.export_failed` | ERROR | `class` | exporter failed and cleared M19. `class=io` identifies listener I/O failure and `class=internal` identifies a failed metrics snapshot or render |
| `op.failed` | ERROR | `kind`, `class` | a loud failure: the operation could not do what it was asked and the caller was told |
| `overlay.failures_dropped` | ERROR | `dropped` | deferred OverlayWrite failures beyond the first eight, reported once when flushed |
| `commit.contention` | WARN | `commits`, `conflicts` | rising edge of the advisory contention flag; terminal window size and exhausted or same-path-conflicting commits |
| `commit.backoff` | WARN | `cause`, `outcome` | a writable mount's live commit entered an authority outage or reached the slow cadence after eight other refusals; `cause` is `outage` or `stall`, and `outcome` is `entered` |
| `commit.backoff` | INFO | `cause`, `outcome`, `attempts` | a live commit retry episode ended in a landing after `attempts` tries; `cause` is `outage` or `stall`, and `outcome` is `recovered` |
| `sync.workspace_exhausted` | WARN | `reason`, `needed`, `limit` | local cumulative construction work exceeded its budget; `reason` is `SyncWorkspaceExhausted`, with needed and limit bytes; the escaped path or boundary appears only in the local report |
| `commit.stopped` | ERROR | `cause` | a writable mount's live commit loop stopped; `cause` is `fenced` when the store is fenced or poisoned, or `closed` when the served view is closed or its session has ended |
| `op.publish_bound` | INFO | `publish_operation` | the wire's publish operation identity, as lowercase hex, for the enclosing operation |
| `log.config` | DEBUG | `format`, `destination` | the output configuration in force, once at startup; shown only when the filter admits DEBUG, so a quiet command writes nothing at the default filter |
| `log.filter_rejected` | WARN | `source`, `reason`, `detail` | a `RUST_LOG` value was not used and the default filter runs; `source` is `rust_log`; `detail` is a fixed explanation for malformed or non-Unicode input |
| `mount.view` | INFO | `cause`, `outcome`, `seq` | a writable mount's view moved to, or waits for, the root at `seq`, or reached the authority again; `cause` is `landed` when the mount's own commit published it and `adopted` when another writer did or when the background prober cleared the unreachable state; `outcome` is `installed` when the mount now serves it, or, for `adopted` only, `deferred` when the mount keeps its view for now (while it has local changes not yet committed, which ends when its own commit lands and takes in the other writer's; while a file is open for writing, which ends when the last such descriptor closes; while a sync or commit is in progress, a registration still owes the authority an answer, or the overlay is still recovering, which ends when that work settles) or `fresh` when the unreachable state ends while serving `seq`, including, with `cause=landed`, when the authority answered the mount's own commit while that state held |
| `mount.view` | WARN | `cause`, `outcome`, `seq` | a writable mount did not install the root at `seq` (`outcome` is `refused`; for `adopted` the mount keeps serving its view unless the install closed it; a view the install closed also emits `op.failed` with `kind=view`, and so, with `class=io`, does a kernel invalidation of that view's held inodes that is refused), or entered the unreachable state while serving `seq` (`cause` is `adopted`, `outcome` is `stale`; in `--view strict` mode, entering the state also emits `op.failed` with `kind=view` and `class=unavailable`) |
| `mount.unmount` | INFO | `trigger`, `outcome`, `seq`, `elapsed_ms` | a writable mount's shutdown ended with nothing left owed; `trigger` is `session_end` for the shutdown of a session that ended, or `signal` for a shutdown begun by a signal while the session serves, or `umount` for an owner control request, all of which then released their intent, or `start` when a start finished the work an earlier shutdown left in the store before serving, which keeps the intent for the mount it goes on to serve; `outcome` is `committed` when its commit published every acknowledged write in the root at `seq`, or `clean` when nothing was owed and `seq` is the base it ends on; `elapsed_ms` is from the latch that closed the mount to writes, or from the start of the finishing, to the report |
| `mount.unmount` | WARN | `trigger`, `outcome`, `cause`, `files`, `bytes`, `operations`, `elapsed_ms` | a writable mount's shutdown, or a start finishing one (`trigger`, as above), kept its intent; `outcome` is `incomplete` when work is left in the journal and staging for the next start, or `fenced` when the authority refused the mount's ownership or its commit; `cause` is `deadline` when the shutdown's bound ran out or a signal after the first stop request cut it. For a start, this means the shutdown bound ran out before the commit stage, the commit stage's own budget ran out, or too little time remained to wait for the authority's publish answer and the start refused to send it. The cause is `failed` when a step failed before its deadline (a fence included, and a failed step also emits `op.failed` with `kind=unmount`), or `internal` when the sequence was lost; `files`, `bytes` and `operations` are what was left unacknowledged at the report: the files still dirty, their dirty bytes, and the journal records since the base that are not bookkeeping, an upper bound on what the next start finds |
| `mount.unmount` | WARN | `trigger`, `outcome`, `cause`, `elapsed_ms` | as the row above, when what was left could not be read: the overlay was never opened or its state is poisoned; no count is guessed |
| `client.gran.mount.the.fuse.session.did.not.end.after.its.unmount` | WARN | `message`, `listed`, `connection` | the daemon stopped waiting for its FUSE session after the grace without waiting for `destroy` and its cache close. With the mount gone, this gives exit 3 subject to the exit-code precedence in [Stopping a writable mount](operating-a-mount.md#stopping-a-writable-mount). When the daemon's own unmount failed, the unmount-fallback warnings precede this event. `listed` reports whether the mount remains in the daemon's mount table. `connection` reports whether the mount's fusectl connection directory still exists. Reuse of the anonymous device's minor by another FUSE mount can make an ended connection read as alive. An unreadable mount table gives `listed=unknown`. An unknown mount device or unavailable fusectl observation gives `connection=unknown` |
| `recover.nothing` | WARN |  | an explicit recovery found no row for the selected writer in the authority's readback; nothing is taken over |
| `recover.signing_key_refused` | WARN |  | Explicit recovery could not use the existing signing seed and refused before submitting any request. |
| `recover.subsumed` | INFO | `relation`, `seq` | the verified root at `seq` proves the selection published by exact root ancestry or equal manifest, so nothing is published; `relation` is `equal` when that root is the prepared root at the head, `descendant` when the prepared root is on the chain below the head, and `later` when another verified root supplies an equal-manifest witness, including the prepared parent |
| `recover.stale` | WARN |  | the verified chain does not reach the prepared root's parent; the intent is kept and nothing is published |
| `recover.landed` | INFO | `seq` | the recovered root landed at `seq` |
| `recover.archived_landed` | WARN | `seq` | an archived candidate matched the verified published chain; recovery refuses and preserves local evidence |
| `recover.rebased` | INFO | `chain_len` | the recovered root landed merged onto a head `chain_len` roots past its own parent |
| `recover.conflict` | WARN | `path` | the recovered root or replayed journal and the head both changed a path; emitted per colliding path; nothing is published; `path` is `<file>` |
| `recover.selection_changed` | WARN | `token` | takeover refusal (`intent-changed`, `intent-superseded`, `intent-absent`), or `none` when ownership was already lost; only a renewed acknowledgement continues |
| `recover.landed_unowned` | WARN |  | the store's ownership was lost after its commit landed and before the landing was refreshed; the evidence is kept |
| `recover.journal_finished` | INFO | `base_seq` | Journal completion and durable writer release. |
| `recover.journal_blocked` | WARN | `reason` | Incomplete admitted journal work: replay, publication, obligations, namespace, limit or release. |
| `recover.fence_settled` | INFO | `how` | a settlement/install action; `how` is `landed`, `released` or `stripped` (a proved conflicting boundary was archived and stripped with dirty work preserved); overall journal completion requires `recover.journal_finished` |
| `recover.unresolved` | WARN | `seq` | publication classification remains unresolved; the boundary and its evidence remain, and an archived deferred tuple's sequence is not claimed published |
| `recover.resent` | WARN | `seq` | one explicitly acknowledged exact resend completed its transport call; its saved answer determines the ending and the fence remains until settled |

Worker records use both text and JSON encodings and are not tracing events:

| event | stream | fields | meaning |
|---|---|---|---|
| `log.sink_loss` | sink | `telemetry_dropped`, `protected_lost`, `local_lost` | lines dropped under backpressure, from the sink's own count |
| `log.line` | sink | `message`, `path`, `class` | fixed rotation or write-failure notice; the path is `<log-file>` by default and an ordinary eligible slot under `full` |

### Closed label domains

A field that is not a number takes its value from a closed list. A value
outside the list is a defect in `gran`, not a new spelling to tolerate.

| label | members |
|---|---|
| kind | `session`, `overlay_write`, `journal_append`, `intent_register`, `fsync`, `commit`, `rebase`, `retry`, `unmount`, `view` |
| outcome | `ok`, `failed`, `cancelled`, `refused` |
| outcome (recovery) | `clean`, `repaired`, `pending` |
| outcome (view) | `installed`, `deferred`, `refused`, `stale`, `fresh` |
| cause (view) | `landed`, `adopted` |
| cause (backoff) | `outage`, `stall` |
| outcome (backoff) | `entered`, `recovered` |
| cause (commit stopped) | `fenced`, `closed` |
| relation (recover) | `later`, `equal`, `descendant` |
| reason (journal recovery) | `replay`, `publication`, `obligations`, `namespace`, `limit`, `release`, `selected-root-not-proved-published` |
| reason (overlay capacity) | `OverlayCapacityExhausted` |
| outcome (unmount) | `committed`, `clean`, `incomplete`, `fenced` |
| cause (unmount) | `deadline`, `failed`, `internal` |
| trigger (unmount) | `session_end`, `signal`, `start`, `umount` |
| listed | `gone`, `listed`, `unknown` |
| connection | `alive`, `gone`, `unknown` |
| reason (retry) | `transient`, `conflict`, `unavailable` |
| class | `io`, `refused`, `conflict`, `unavailable`, `corrupt`, `internal` |
| format | `text`, `json` |
| destination | `stderr`, `file` |
| reason (filter) | `not_unicode`, `malformed` |

The `kind` members other than `session` name the write path's spans: the
overlay absorbing a write, a journal append, registering a write intent, a
durability barrier, a commit, a rebase, a retry sequence, the unmount and the
install of a landing as a writable mount's view. They are reserved here so the
operations that arrive later use one vocabulary.
The authority's intent operation kinds are defined in
[the authority operator document](operating-the-authority-lifecycle.md#intent-observability).

## The rule for a new failure

Every loud failure added to the client emits a stable event, and its test
asserts that event by name and fields, not only the exit code or the errno. A
failure that fits `op.failed` uses it with the class that fits. One that needs
a class, a kind or an event the tables lack adds it in the code, in this page
and in the table test together; the test that compares this page with the code
fails until all three agree.

## Metrics

A session owns its counters independently of log verbosity. Recording does no
I/O, allocation, subscriber lookup or mutex acquisition. A `ClientMetrics` clone
shares that session's recorder; another session has its own recorder, even when
both pools use the same validated connector and wire instrument. Histograms take
measured durations, never wall-clock subtraction. Their storage is fixed, so
samples cannot fill a queue.

The callable export routes are `ClientMetrics::snapshot` and the returned
`MetricsSnapshot::render_prometheus`. `MountSession::open` derives its recorder
from the remote store through `MountMetrics`, then supplies that same recorder
to cache observations. `MountSession::metrics` exposes the retained handle.
The command creates one recorder per mount and supplies it to the HTTP facade
through `HttpStore::with_metrics`, which builds a fresh connection pool and
shares the wire instrument. `MountOptions` contains only the copyable trust-gate
flags. Snapshot collection and rendering need no logging subscriber. Consumers should collect outside the operation
path and deduplicate exports of the same cumulative stream.

The catalogue schema is **2**. Every name below has the prefix
`granary_client_`. Labels are closed domains: no paths, users, volumes, hashes
or request identifiers can be supplied. Catalogue codes are stable and never
reused; an incompatible name, unit, label, count point or bucket change needs a
new schema and a collection discontinuity.

| code | name | type | labels and count point |
|---|---|---|---|
| M01 | `metrics_schema_version` | gauge | constant 2 |
| M02 | `metrics_incarnation` | gauge | `word=0,1,2,3`; four unsigned 32-bit words from a fresh cryptographic draw |
| M03 | `metrics_available` | gauge | `group=cache,transport,sync,commit,contention,fuse`; usable producer is 1 |
| M04 | `metrics_overflow` | gauge | `metric=M02,M05,M06,M07,M08,M09,M10,M11,M12,M13,M14,M15,M16,M17,M18,M20,M21`; sticky family invalidity |
| M05 | `commits_total` | counter | `result=ok,conflict,exhausted,failed,cancelled,unknown`; one local terminal observation per logical commit |
| M06 | `commit_duration_seconds` | histogram | same result domain; first attempt through local termination, including retries and backoff, excluding coalescing wait |
| M07 | `commit_retries_total` | counter | `reason=transient,conflict,unavailable`; additional attempts actually started |
| M08 | `rebase_conflicts_total` | counter | one per rebase attempt detecting overlapping names |
| M09 | `contention_flag` | gauge | absent until the authoritative policy supplies a decision, then 0 or 1 |
| M10 | `syncs_total` | counter | `outcome=ok,failed,cancelled,refused`; completed engine calls |
| M11 | `intent_registrations_total` | counter | `result=ok,failed,cancelled,unknown`; terminal registration exchanges |
| M12 | `intent_registration_duration_seconds` | histogram | same registration result domain; exchange through validation, error or abandonment |
| M13 | `sync_grains_uploaded_total` | counter | grains in novel successful bin uploads |
| M14 | `sync_uploaded_bytes_total` | counter | `object=bin,meta`; encoded payload in novel successful puts |
| M15 | `sync_rechunk_fallbacks_total` | counter | whole-file rechunk fallbacks actually taken |
| M16 | `cache_lookups_total` | counter | `phase=startup,read`, `result=hit,miss`; final hits and admitted misses per distinct want |
| M17 | `cache_hit_ratio` | gauge | `phase=startup,read`; sampled hits divided by sampled hits plus misses |
| M18 | `transport_body_bytes_total` | counter | `direction=up,down`; HTTP offered request payload per attempt / observed response DATA per frame |
| M19 | `metrics_listener_up` | gauge | absent when never configured, 1 after bind and worker startup, 0 after configured failure or shutdown |
| M20 | `metrics_scrapes_total` | counter | `result=ok,refused,limited,failed`; one terminal result per TLS-admitted connection |
| M21 | `fuse_requests_total` | counter | closed callback identity, `outcome=ok,failed,cancelled,refused`; one completion per dispatched reply, including explicit fsync refusals |
| M22 | `mount_view_stale` | gauge | 1 while the mount is in the unreachable state, 0 otherwise |

Commit and sync entries reserve recording interfaces for their producers.
Unavailable producers omit their families and report availability 0; an idle
wired producer exports zero. Cache observations are available even with caching
disabled: every admitted want is a miss, so the ratio becomes 0 once observed.
Contention requires both an available producer and an authoritative decision.
`set_contention` stores a decision and enables availability;
`set_available(MetricsGroup::Contention, false)` suppresses the retained decision
in both availability metadata and the contention family. No decision yet
reports availability 0 and omits the family, even if availability was enabled.
No cache observations yet means an absent ratio. Final cached content wider than
its
manifest declaration is still counted as a hit, even though delivery is refused.
Deferred wants and single-flight duplicates do not count again. Changing from
startup to reads resets the separate read-path instrument, never these counters.

Transport counts are **offered/observed, not wire-exact**: a failed connection
still contributes its offered request body, and a retry contributes it again.
Partial responses and the DATA frame crossing a response cap count before
refusal. Headers, TLS and TCP are excluded. Direct object-storage interfaces
cannot observe frames, so their transport metrics are unavailable. A successful
upload counter does not establish durability or remote receipt.

Both histograms have upper bounds, in seconds, of **0.001, 0.005, 0.01, 0.025,
0.05, 0.1, 0.25, 0.5, 1, 5, 30**, followed by `+Inf`. Durations round down to
integer microseconds. Snapshots copy each atomic once; cumulative buckets and
`_count` derive from the same copied vector, so `+Inf` equals `_count`.
The separately sampled `_sum` may straddle an update. Cross-metric conservation
and exact concurrent averages are unsupported; quiescent observations are exact.

Counters reset only with a new recorder incarnation. The snapshot carries that
incarnation and a nonwrapping collection sequence. Break rate windows when its
incarnation changes, even when a counter catches up between collections.
Entropy failure emits `op.failed` with `kind=session,class=unavailable`;
recording continues but exporting refuses. Sequence exhaustion also refuses
further snapshots. No crash recovery reconstructs these volatile observations.

**18446744073709551615** is an invalid sentinel; **18446744073709551614** is the
largest valid atomic value. Exhaustion is sticky and never wraps. Invalidity
omits only the affected label group (an entire bucket/sum/count group for a
histogram result), retains healthy siblings and sets the family's overflow
gauge. A mid-life missing series with overflow set is invalid, never a reset.
Derived ratio or histogram-count overflow follows the same rule.

The renderer emits Prometheus text 0.0.4 with a final newline and content type
`text/plain; version=0.0.4; charset=utf-8`. It bounds output to **512 sample
series**, **65536 bytes** and **512 bytes per line**, and refuses the whole
response on any limit. Snapshots fit within **16384 bytes**. It emits no
identifying labels, timestamps, exemplars or alternate formats. Prometheus's
floating-point storage can lose integer precision above **9007199254740992**.

### Scraping a mount locally

`gran mount` enables the listener only when all four options are supplied together, once each.

- `--metrics-listen <numeric-loopback:port>` takes `127.0.0.1:PORT` or `[::1]:PORT`
  with a port from 1 to 65535. Configure a distinct target for each session, with at most
  16 endpoints per process.
- `--metrics-token-file <file>` takes an owner-only regular file containing exactly
  64 lowercase hexadecimal characters with no newline. Provision 32 cryptographically
  random bytes independently of any signing credential. The loader checks the form only.
- `--metrics-tls-cert <file>` takes the dedicated server certificate chain in PEM.
  `--metrics-tls-key <file>` takes its matching PEM private key. Each file is capped
  at 65536 bytes. The token and key are checked on their open descriptors for ownership,
  mode, regular-file type, and single-link custody. Symlinks and granting ACLs under the
  platform custody checks are refused. The public certificate must resolve to a regular file
  and is opened without blocking. Existing local-filesystem custody limitations apply.

Use HTTPS with a collector that verifies the configured CA and numeric IP SAN before sending
the bearer. TLS 1.3 is required and session resumption is disabled. The server offers only
`http/1.1` ALPN. A client that omits ALPN may send HTTP/1.1. A client that offers only other
protocols fails the handshake. Send one `GET /metrics` without a query or body, with the numeric
Host matching the endpoint and one `Authorization: Bearer` header. Host may omit the port only
on 443. If a client sends a raw fragment suffix, the parser ignores it and the same bearer
check applies. A set-ID invocation refuses startup, as do invalid options and custody or TLS
configuration. A bind or worker startup failure leaves the mount running, reports
`op.failed{kind=session,class=io}`, and sets M19 to 0. M19 becomes 1 after both bind and worker
startup succeed and returns to 0 when the worker stops. The worker's first runtime failure
clears M19 and reports `metrics.export_failed` even after a renderer failure reported its own event.
Interrupted accepts and per-connection network errors are retried without an event or scrape count,
while any other accept error stops the listener and reports `metrics.export_failed{class=io}`.
A renderer failure clears M19, reports its own event once and leaves the listener running with 503
for the triggering scrape and later authorized scrapes for the worker's lifetime.

The listener permits four concurrent connections with a five-second lifetime starting before
the TLS handshake. The request head is capped at 8192 bytes and 16 headers. Handler responses
close and set `Cache-Control: no-store`. Hyper can close without a response on an HTTP/2
preface, or send an empty 400 for malformed framing or 431 for a head, header count or length
value exceeding the parser's range. These parser replies close and carry no metrics or
reflected input. They lack the cache directive, including for requests containing a bearer.

M19 and M20 are absent when the listener is never configured. The four M20 counters start at
zero once configured. M20 counts one result after TLS admission. A completed response carrying metrics is `ok`.
Handler and observed parser refusals, plus clean EOF before a request, are `refused`.
Lifetime expiry is `limited`. Cancellation, render failure and terminal I/O errors are
`failed`. A write error or deadline can mask a parser refusal, so its observed result can
be `failed` or `limited`. Pre-admission probes are uncounted. A scrape reports a snapshot
taken before its own terminal result.

The sync engine counts one final outcome per retained commit lane: landing,
fencing or terminal refusal. Cancellation, deadline and pending or unresolved
publication leave the lane open and contribute no terminal observation.
Timing starts with its first drive, after candidate construction and waiting,
and includes retries, backoff, later drives and local installation.
A recovered lane has no first-attempt monotonic token. Missing or reversed timing
omits the duration sample while preserving the terminal count; the existing
availability and overflow gauges signal unusable timing, without a new diagnostic.

Each drive emits `op.begin` and `op.end`. A terminal non-landing emits `op.failed`
with its classified failure; each fence is reported once. A permanent refusal
strips its proven-no-write boundary and keeps an in-memory ESTALE fence for the
mount's lifetime. An overlapping rebase or a conflicting retained suffix emits
`op.conflict` with the ordinary file-path policy. Rebase conflicts also send the
exact bounded path through the local conflict report. `overlay.refused` reports
retained staging files, charged bytes as of the last capacity check plus journal
records appended since, and retained journal records in `record_index`, including
work written after the commit boundary. Reporting performs no filesystem reads.
The journal and staging remain available for explicit recovery.

The sync engine records retries after the additional attempt's durable save,
immediately before dispatch, and emits `op.retry` with that attempt number.
A failed save or an interrupted backoff contributes no retry. Overlapping names
detected while preparing a rebase contribute one rebase-conflict observation;
candidate verification walks and disjoint rebases contribute none.

The contention flag is advisory and per volume. `gran mount --writable
--contention-rate <rate>` configures its threshold, default **0.25**; values must
be finite, greater than 0 and at most 1. The window is fixed at the last **16**
terminal logical commits, with no decision before **4** observations. Exhausted
commits and same-path conflicts enter the numerator; every terminal outcome
enters the denominator. A disjoint rebase that lands enters only the denominator.
The flag is 1 when the observed rate is greater than or equal to the threshold,
and 0 otherwise. `commit.contention` emits only on a rising edge, including the
first true decision, with `commits` as the observed window size and `conflicts`
as its numerator. The falling edge emits no event. The window is in memory and
resets on restart; startup-discovered terminal refusals contribute a fresh
observation, never reconstructed prior history. Until four observations the flag
is absent and contention availability is 0. A mount's recorder belongs to that
volume; separate volumes use separate recorders. The flag never authorizes a
write, controls retry, delays, refuses, reorders or serializes commits.

FUSE callback observations never count kernel refusals that precede dispatch.
Flush and release record callback completion only; they do not increment sync,
registration or upload counters. The callback domain is fixed by `granary_fuse::Callback`.
