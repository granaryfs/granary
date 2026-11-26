<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Operating local debug grants

For disk-sampled diagnostics and sanitized grant state, see
[local support exports](operating-support-export.md).

The local commands publish one scoped, expiring debug grant in `DEBUG-GRANT`
beside `ENROLLMENT` in the enrollment directory. Use the local commands below
to manage this file.
Commands run before the serving runtime or diagnostic subscriber starts.
They expose no HTTP operation, obtain no incarnation from a running process,
and perform no capture activation.

Run a command as the directory's owner or root. The protected-directory
contract is the same as [enrollment's](operating-enrollment.md): an absolute,
symlink-free directory path, trusted ancestor ownership and permissions,
owner-only directory access, and a supported filesystem profile. Every verb
also accepts `--accept-unsupported-filesystem` for development on a profile
whose protection cannot be claimed. This acknowledgement relaxes only the
filesystem-type check, never ownership or permissions.

Grant files must be regular, owned by the directory owner, and have no group
or other access (`mode & 077 == 0`). New temporaries use `0600`. Root assigns
the temporary to the directory owner and group before writing. Commands
refuse symlinks, nonregular files, inconsistent reads, oversized files and
undecodable files. An invalid existing file is never overwritten.

## Arguments

All mutations take:

```text
--dir D --incarnation I --expected-revision R
```

`D` is the absolute enrollment-directory path. `I` is `incarnation:` followed
by exactly 32 lowercase hexadecimal digits, explicitly supplied by the
operator. The verb carries those bytes into the grant; it cannot certify
that the marker belongs to a currently running server. `R` is the expected
file revision; zero means the file is missing. Numbers use canonical decimal
spelling, without a plus sign or leading zeroes. Generations are nonzero.
Missing, repeated, unknown and verb-inapplicable flags are invalid arguments.

Debug-grant is frozen v1 (2026-10-06), with its byte layout and decoder accept
set fixed. Mutations enforce revision, incarnation and generation checks;
activation follows the grant policy. `show` writes nothing.

A selector is `--principal P`, `--volume V`, or both. `P` is the enrollment
principal's canonical `principal:` written form. `V` is a canonical DNS-1123
volume label. Both selectors mean principal **AND** volume. Wildcards and
explicit diagnostic levels are not accepted.

## Issue

```text
granary-server debug-grant issue --dir D --incarnation I --expected-revision R \
  --principal P --volume V --duration-secs N --lines L --bytes B --owner O --reason Q
```

Supply either selector or both. Duration is 1 through 900 whole seconds,
lines 1 through 1024, and bytes 1024 through 1,048,576. These minimums are
issuance policy; the codec accepts zero ceilings for narrowing. Issuance and
expiry use the verb's injected clock, the server's existing wall clock in
production. Arithmetic overflow or an invalid clock timestamp refuses the
write. The original issuing effective uid is recorded.

Owner is 1 through 64 bytes and reason 1 through 256 bytes of printable ASCII
without whitespace or control bytes. They are operator-supplied **nonsecret**
labels. Quotes, backslashes, equals signs and braces are legal; the command
emits labels as quoted, escaped structured fields.

Issuance refuses a live, unrevoked grant for the supplied incarnation. A
named principal must be active in a protected, decodable enrollment set,
checked under the same directory lock. An absent or retired principal
refuses issuance. Volume-only issuance does not require an enrollment set.

A missing file starts revision and generation at one. Issuing after expiry
or revocation is allowed. Issue deliberately supersedes a grant written for
another incarnation, using its actual expected revision. Each issue increments both
the existing revision and generation; neither counter resets when the
incarnation changes. Checked counter overflow refuses publication.

## Narrow

```text
granary-server debug-grant narrow --dir D --incarnation I --expected-revision R \
  --generation G --principal P --volume V --expires-at T --lines L --bytes B
```

Selectors are a complete replacement, not a list of changes. `T` is epoch
seconds and exactly nine nanosecond digits, `SECONDS.NNNNNNNNN`, using the
format's UTC timestamp fields. Seconds are a canonical signed i64 decimal;
nanoseconds are below one billion. For example, `1800000000.000000000`.
Expiry must remain later than original issuance and within its 900-second
format duration bound.

Narrowing retains the generation, original issuance time, issuer uid, owner
and reason. It increments only the file revision. It refuses a missing
grant, wrong incarnation or generation, a revoked grant, or a grant expired
at the clock reading (`now >= expires_at`).

Principal-only may become a conjunction retaining that principal;
volume-only may become a conjunction retaining that volume. A principal
introduced by narrowing must be active in the checked enrollment set. A conjunction
retains both identifiers. Changing an identifier, removing a conjunct,
exchanging principal-only for volume-only, or the reverse, is widening and
refused. Expiry may only stay the same or decrease. Each ceiling may only
stay the same or decrease, including to zero. A replacement that changes
none of scope, expiry or ceilings is refused. These commands report
published ceilings, never live remaining allowances.

## Revoke and show

```text
granary-server debug-grant revoke --dir D --incarnation I --expected-revision R --generation G
granary-server debug-grant show --dir D
```

Revoke writes a tombstone: it increments the revision, sets the action to
revoke, and retains generation, incarnation, scope, timestamps, ceilings and
original metadata. Missing, wrong-incarnation, wrong-generation and already
revoked grants refuse. An expired grant may be revoked.

Show takes no lock and creates nothing. It performs the protected bounded
read and prints the decoded record and revision, or `state=missing` when
absent. Corrupt, oversized, unreadable or unprotected files refuse. It does
not report capture activation or live remaining budgets.

## Publication and exit codes

Enrollment and grant mutations flock the **same directory descriptor**.
Revision comparison happens inside that lock, after reading and validating
the existing grant. Two writers with one expected revision cannot both
publish. The lock remains held through the final directory sync.

The transaction constructs and encodes the replacement, decodes those bytes
and checks equality, exclusively creates `DEBUG-GRANT.tmp`, explicitly sets
its mode to `0600`, writes all bytes,
syncs the temporary, renames it over `DEBUG-GRANT`, and syncs the directory.
First creation also syncs the parent directory. A leftover temporary is
removed under the lock before the read. Failures before rename remove the
temporary best-effort; no grant is published.

A successful mutation prints one bounded record with
`event=debug_grant_issue|debug_grant_narrow|debug_grant_revoke`,
`phase=written`, incarnation, file revision, generation, complete scope,
issuance and expiry, published ceilings and original metadata. This
acknowledges durable publication. **Writing a file is not activation**;
these commands contain no grant reader or capture coordinator. An output
failure after publication also requires inspection before retrying.

| Exit | Meaning |
| --- | --- |
| 0 | Completed; a mutation durably published, or show reported present/missing. |
| 64 | Invalid arguments; no mutation attempted. |
| 65 | Policy, protection, format refusal, or I/O failure before rename; no published change. |
| 74 | Failure at rename or later, or reporting after completion failed; publication may be visible. Run show before retrying. |

## Activation, restart and local status

Copy the canonical incarnation from the running server's readiness diagnostic or
local observation snapshot. Startup draws it once through `SecureRandom`; all
serving clones share it. Readiness announces `debug_grant_restart=reset`, and
`debug_grant_activation=unsupported-clock-profile` on an unsupported platform.
Healthy readiness reports `debug_grant_activation=clock-supported`; activation
still requires a demand check and a compatible capture ceiling and producer.
The server never writes the operator directory or discovers an incarnation
through a socket, environment variable or token file.

Publication is pending until application. Requests trigger a demand check;
anonymous reads continue without waiting. Public volume status is a cached
projection and never touches the grant reader. Authenticated writes await a
refresh begun after their arrival before the bounded DEBUG producer. A fresh
local `GrainService::fresh_observation` does the same check before collecting
status. Both waits have a **2 second** deadline. A deadline or transient I/O
failure suspends capture without retiring the generation; request authorization
is unaffected. Completion can resume the same slot, remaining budget and expiry
latch. Cached `GrainService::observation` performs no file I/O and remains
available during stalled reads. There is one blocking refresh at a time, no
watcher, polling timer, expiry timer or signal handler.

Restart has no effective grant. An old file is refused as `stale-incarnation`
and left untouched; the snapshot preserves both expected and received markers.
Before the first demand read the state is `unread`, never `missing`. A decoded
first-seen narrowing can activate its complete scope. Later narrowing preserves
the slot and reduces scope, deadline and remaining budget. File revision and
capture revision are separate. Equal-revision different bytes and rollback
refuse. Missing after activation, corrupt, unprotected, stale, rollback,
revocation, expiry and an authentic **future-issued** file retire the high-water
generation, which may exceed the refused file's own generation;
restoring it cannot reset the budget. Recovery requires a higher generation and
file revision, or restart and re-issue for the new incarnation.

A protected file issued more than **30 seconds** ahead of the server's grant
clock refuses as `future-issued` and stays retired even after the clock catches
up. Fix the clock or restart and re-issue. Demand-driven reading would otherwise
activate a pre-dated file at an unannounced, request-dependent moment, making it
a time-delayed grant.

### Recovering from a clock correction

Compare local status's `future_issued_lead_secs` with the wall-clock/NTP
correction and whether server startup preceded synchronization. The lead is
measured at the refusal, rounded up to seconds and saturated at
**18446744073709551615**. Cached status preserves the measurement; a new demand
check updates it, and another verdict clears it. The lead alone does not identify
the clock's history.

If the wall clock stepped forward after a correct server start, undo the step,
revoke the current file and re-issue. Obtain its current revision/generation
with `show` for the revoke; obtain the resulting revision for the issue. The
verb derives the next file revision and grant generation from the current file,
each incremented by one. With the clock corrected and a file history that has
not regressed, these exceed the reader's high-water marks and restore capture.

If the server anchored its clock before NTP synchronized and NTP then corrected
the wall clock forward by more than **30 seconds**, every issue continues to lead
for that incarnation: grant time never resynchronizes. Only a restart recovers.
After synchronization, restart, obtain the new incarnation from readiness and
re-issue for it. This refusal fails closed and affects capture availability only;
request authorization is unaffected.

## Grant time and admission

Production grant time is startup UTC plus Linux `CLOCK_BOOTTIME` elapsed time,
including suspend. It never resynchronizes with the wall clock. Expiry can shift
by the startup wall-clock error; the **30 second** issued-at allowance bounds how
far ahead an issue may be. Clock-source failure or arithmetic overflow latches
permanently and disables activation and capture; expiry evidence already observed
wins. Other production clock profiles refuse activation; macOS tests inject a
clock, without claiming production support.

Scope and time are checked at capture admission. At `now >= expiry`, new capture
stops without rereading the file; snapshots also observe expiry and expose no
expired effective scope. Already queued records may drain. One attempt costs
one line and **1024 bytes**, without refund even on queue loss. Capture does not
perform destination I/O or wait for queue capacity. Re-reading never replenishes
allowance. Atomic replacement returns only after earlier wider capture has left
its guarded producer/enqueue section. Requests whose refresh preceded publication
may use the prior scope until application; a verb's return promises publication.

## Events and bounded observation

Server transition records name `debug_grant_issue`, `debug_grant_narrow`,
`debug_grant_revoke`, `debug_grant_refuse`, `debug_grant_expire` or
`debug_grant_stale`, with `phase=applied`. Refusals give a fixed reason and stage.
Events carry known incarnation, file revision/generation, capture revision/slot,
outcome, decoded `scope`, `effective_scope` at the transition selection point,
`capture_level=DEBUG`, `kind=AuthenticatedRequest`, expiry, ceilings and original
owner/reason/issuer. Refusal, revocation and expiry have no effective selectors.
Expiry retains its lease identity. Malformed raw bytes are
never echoed. Each observed transition emits once, after releasing capture and
coordinator guards; skipped file revisions are not reconstructed.

These diagnostics use the host subscriber and lossy sink, subject to immutable
host filtering. Snapshot state and counters remain authoritative if diagnostics
are filtered or lost. This is observational evidence, not a durable authority-log
audit record. Unsupported instrumentation, producer or host/contextual ceilings
refuse activation rather than reporting an applied silent no-op.

The local `debug_grant` section is bounded to the process incarnation, reader
state/reason, the observed lead of a future-issued refusal, one observed and one
accepted decoded record, revision/generation
high-water marks and retirement, effective scope/level/kind/expiry, slot/capture
revision and remaining budgets. Accepted metadata is history; only effective
denotes live capture. Metadata and effective scope share a capture revision; counters are
separately sampled, saturating process-lifetime totals. Required counters are
`admitted`, `suppressed`, and `expired` (once per generation), alongside budget,
contention and expiry suppression, malformed/oversize, queued/sink loss, reader
refusal/unreadable/stall, refresh/application/retirement totals. There is no
per-event history or public-wire grant exposure.

Owner and reason must be nonsecret operator labels. The sole DEBUG record retains
its principal, volume, operation, slot and capture-revision allowlist. Grants do
not enable TRACE, arbitrary tracing targets, payloads, credentials, dumps, packet
capture, profiling, remediation or projection access. Empty capture keeps its
producer fast return; demand filesystem work is additional request overhead.
