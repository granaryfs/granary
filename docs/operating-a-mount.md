<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Operating a granary mount

A granary mount is **Linux-only** and **long-lived**. It defaults to read-only;
`--writable` opts into authority-backed writable admission. This page is
for whoever runs one: the trust decision it forces, what `allow_other` actually
gives away, what "the mount is up" does and does not mean, and how to recover one
that has wedged.

This page does not restate why a mount's trust contract
and its synthesised attributes were chosen;
it tells you what
to type and what it costs.

## Preserving overlay recovery evidence

Stop all volume users and preserve the complete store, including
`publications/`. Run B5 extraction on the preservation working copy before
discard if you need local files. Use the scope digest S from
`overlay/<S>/<V>` or the B5 inventory. Run both commands against the store
you intend to retire. A healthy, unclaimed overlay refuses discard. An
existing discard claim lets you retry the same tuple.

```sh
gran overlay discard --plan --store-dir "$STORE" --scope "$S" --volume "$V"
gran overlay discard --store-dir "$STORE" --scope "$S" --volume "$V" \
  --writer "$W" --journal-incarnation "$I" \
  --acknowledge-unsynced-loss --acknowledge-may-land
```

Use the exact printed S, V, W and I. The first acknowledgement gives up
replaying local changes into writable service. The second acknowledges that
an earlier send can still land. After a durability or output failure, repeat
discard with the same tuple. `OverlayDiscardPending` fences the original
store even while the live tree remains in place. `OverlayArchived` means the
tree moved. Both retain the writer, grant and publication evidence.

For both forms of discard, exit 0 confirms that the command wrote and
flushed the result row. An operational refusal returns exit 1. Discard
attempts to report the refusal as a redacted `overlay.discard_refused`
JSON record on stderr even if writing the terminal diagnostic fails or
times out. A caller with a broken stderr can still use the exit status.
Discard help writes to stdout and returns exit 0. Invalid arguments print
usage to stderr and return exit 2. Both messages are best effort.

Reconcile with the same tuple and the authority's retained endpoint,
TLS pins and credential context. Supply the publisher public keys and the TLS
client certificate and key when required.

```sh
gran overlay reconcile --store-dir "$STORE" --scope "$S" --volume "$V" \
  --writer "$W" --journal-incarnation "$I" \
  --endpoint "$ENDPOINT" --pin "$PIN" --credential-context "$CONTEXT" \
  --publisher-key "$PUBLISHER_KEY"
```

Read a classified landing at the reported sequence through a separate read
cache using the [archived-store read procedure](#finishing-a-journal-with-explicit-recovery).
Exit 0 with no rows settles the archive's late-publication risk.
With `OverlayArchiveUnresolved`, use an independently verified published
sequence and keep the late-publication acknowledgement in force. Rerun when
missing authority evidence becomes available. For a local refusal, resolve the
local evidence problem first. `OverlayArchiveRemoteIntegrity`
calls for administrator investigation before writable continuation. Use a
separate fresh store and cache for writable service, with its own writer
and grant, bootstrapped from the verified current head.

## The command

```
gran mount <volume> <mountpoint>
  --endpoint <url> --pin sha256/...
  (--root-key ed25519:<64 hex> | --manifest-root <algo>:<hex> | --trust-server)
  --cache-dir <path> --foreground
  [--seq N] [--uid N] [--gid N] [--allow-other] [--reset-floor] [--force]

# Writable admission (native invocation only):
gran mount <volume> <mountpoint> --writable
  --endpoint <url> --pin sha256/... --root-key ed25519:<64 hex>
  --key-seed <existing-private-file> --store-dir <explicit-local-store>
  --client-cert <file> --client-key <private-file> --credential-context <principal-context>
  --cache-dir <explicit-cache> --foreground [--commit-on-sync] [--reset-floor]
  [--shutdown-bound <seconds>] [--uid N] [--gid N] [--force]
```

Exit codes: **0** clean · **1** runtime failure · **2** usage error · **3**
unmounted, but the cache could not be closed cleanly · **4** a writable mount's
shutdown stopped at its bound or by a signal after the first stop request, everything kept · **5**
fenced. "Stopping a writable mount" below has the full table.

The three optional flags the synopsis does not otherwise explain: `--uid`/`--gid`
set the owner every synthesised attribute reports, defaulting to the mounting
process — root, under the systemd unit. **On read-only mounts, `--seq N` pins a specific root sequence
and is deliberately EXEMPT from the freshness floor** — the floor answers a STORE
lying about where the head is, and an operator naming a sequence is not that. That
exemption is load-bearing: it is the documented escape hatch from a floor a
stranger poisoned. See the `StaleHead` note near the end for when to reach for it
and what it costs.

`--cache-dir` is required — the whole read path serves through it for the life of
the session, and there is no default-directory convention.
`--foreground` is required too: backgrounding is **not implemented**. There is no
pidfile and no log-redirection contract yet, so whatever supervises the mount is
what holds it open. The systemd unit below and the CI lane both pass it.

## Writable admission

The signing seed must already exist: mounting never creates it, announces its
public half, or repairs a missing public sidecar. Its derived public half must
match `--root-key`; a present sidecar must match the seed. Keep the seed in a
separate private file owned by the service identity, mode 0600, beneath protected
ancestors. Keep both signing files and the client TLS key outside the local store
and cache; the store and cache must also be separate. TLS credentials identify
the enrolled principal, while the signing seed authorises publisher signatures.
`--credential-context` names stable principal continuity across certificate rotation.
The authority must serve and initialise this volume, implement the intent family,
and permit this principal to read back, acquire and register intent. Publish once
before the first mount: writable admission requires a verified nonempty base.

Startup validates posture and local inputs before sending anything. It then
checks authority status and authenticated intent readback, verifies the head,
opens one locked local store, acquires or transfers ownership, replays the overlay
and durably registers initial prepared state. Only durable Serving, a ready overlay
and settled retained publication permit attachment. The prepared root remains a
candidate; it does not enter the root cache or become the pinned read view.
A writable mount whose journal holds no unpublished change and no recovery
leftover, and whose registered root is published content, restarts on the
current head. A refusal keeps its specific remedy in the table below. A store an
interrupted shutdown left holding work is first finished on its own base. The
steps before the commit stage have the shutdown's 30-second bound. The commit
stage has about 167 seconds so it can receive the authority's publish answer.
The publish itself waits up to 46 seconds. The stage also covers preparing
the commit, checking the published root, and registering the landing. It
finishes any retained commit, installs any recorded landing still to be
installed, and commits the remaining work once. The mount then serves the
resulting head.
A finish that cannot complete refuses and keeps the remaining work for the
next start. During a `503 unavailable` outage, saving a checked 503 answer
durably exempts that attempt from the charged budget, up to 64 exemptions
across starts. Further 503s are charged. A single start can spend several
attempts, and the store fences at the eighth charged attempt.
A start that finishes such work can therefore run for over three minutes, longer
than systemd's default 90 s stop timeout. A stop that kills the start while its
publish is in flight charges that attempt, so let a finishing start end on its own
during an outage rather than stopping it.

The attached session uses RW, nosuid, nodev and default_permissions, Owner ACL,
no allow_other, one worker and no writeback cache. It currently attaches the existing
filesystem adapter. Writable attachments report 0755 directories, 0644 regular
files (0755 with execute intent) and 0777 symlinks. Writes go to the local
overlay. Metadata outside the canonical mode, hard links, special nodes and
extended attributes are explicitly refused. Closing a
file (flush) does not sync; fsync, fdatasync, fsyncdir and `O_SYNC` or `O_DSYNC`
writes are durable as `--commit-on-sync` below describes. Ownership and
recovery files remain retained after refusal or after a shutdown that kept its
work; inspect them before retrying. Stopping the mount commits and releases its
intent within a bound: see "Stopping a writable mount" below.
No memory-erasure guarantee is made for signing material.

| Refusal | Remedy |
| --- | --- |
| `NoTrustMode`, `ConflictingTrustModes` | Supply exactly one trust mode. |
| `WritableTrustServerRefused`, `WritableManifestRootRefused` | Use the matching publisher `--root-key`. |
| `WritableAllowOtherRefused`, `WritableAllowRootRefused` | Remove sharing; writable admission requires Owner ACL. |
| `WritableSeqRefused` | Remove every explicit `--seq`, including today's head; let startup discover its base. |
| `WritableSigningKeyRequired`, `WritableCredentialsRequired`, `WritableStoreRequired`, `CacheDirRequired` | Supply the existing seed, certificate/key pair and context, explicit store and cache. |
| `WritableKeyInputRefused`, `WritableCredentialInputRefused` | Correct custody, file lengths, sidecar consistency and path separation. |
| `WritableKeyMismatch` | Select the seed corresponding to the configured root key; neither key is printed. |
| `WritableAuthorityRequired`, `WritableVolumeUnserved`, `WritableAuthorityUninitialised` | Configure an authority, serve this volume and initialise its log. |
| `WritableAuthorityUnavailable`, `WritableIntentUnavailable` | Restore service/connectivity before retrying; retained remote effects may remain. |
| `WritableDiscoveryInvalid`, `WritableIntentDiscoveryInvalid` | Investigate malformed or unverified authority answers. |
| `WritableIntentResourcesMissing`, `WritableIntentAccessRefused` | Install intent-family support or correct principal enrollment/access. |
| `NoHead` | Publish once first. |
| `StaleHead`, `CachedRootEquivocation`, `DegradedCacheRefused` | Follow the existing freshness, equivocation or cache remedy below. |
| `IntentNotImplemented`, `IntentSelectionChanged`, `IntentRetryDeadline`, `IntentFenced (ESTALE)` | Repair authority support, inspect retained selection/retry evidence or stop the displaced instance; do not automatically take over after fencing. If explicit recovery of a fenced store then reports `IntentSelectedWriterMissing` and the authority holds no row for its writer, follow the [fenced-store exit](operating-disk-loss-recovery.md#fenced-store-with-no-live-row). |
| `WritableRecoveryRequired` | Preserve the store. For admitted journal work, follow the [disk-loss recovery guide](operating-disk-loss-recovery.md); inspect damaged or missing evidence before retrying. |
| `JournalFinished` | Journal recovery completed and the writer row was released. Start the writable mount with this store. |
| `RecoveryLandedUnowned` | The commit landed but ownership was lost before refresh. Stop all displaced/displacing processes; preserve this store and the current selected prepared root. Inspect the selection before renewing `--acknowledge-takeover <writer>`. A fresh grant preserves the selected root; it does not prove its content published. Recovery registers the genuine landing and completes only with verified root-ID ancestry, an equal manifest on the verified chain, or immutable local journal evidence that this store registered the exact selection before the retained whole-tree capture's through-prefix. Otherwise it returns `RecoveryJournalBlocked` (`selected-root-not-proved-published`), keeps that exact prepared root live, and neither installs the landing nor releases the row. This preservation lasts until an owner's later register legitimately supersedes the selection or an operator acts. Preserve the authority intent state; recover the selection separately with corrected recovery, or resolve reported conflicts before retrying this store. Missing/released selection, unavailable proof or damaged evidence remains refused. Renewed consent never waives the publication proof. Older `gran recover` binaries still use writer-level subsumption and do not enforce this preservation. A displaced instance can still land a publication. |
| `RecoveryJournalBlocked` | Preserve this store. Journal recovery is incomplete; inspect the reported reason before retrying. Dirty-journal recovery also refuses with `selected-root-not-proved-published` before registering over or releasing an unproved foreign selection. |
| `IntentFreshInstanceRequired` | Preserve this store; do not delete its overlay area. An earlier run prepared this writer's release and it is unconfirmed, so recovery cannot own the writer again. No in-place repair is available. |
| `RecoveryConflict` | Inspect the collision evidence. A supported resolution must change the conflict or head before retrying; the same unchanged-head attempt remains blocked. |
| `RecoveryArchivedLanded` | An acknowledged archived publication landed at the event's `seq`. Stop every process using the volume and preserve the old store unchanged; follow the archived-store steps below. |
| `RecoveryArchivedUnresolved` | Archived evidence still owes classification. Its event's `seq` is not claimed published. Preserve the old store and follow the archived-store steps below using an independently known, verified published sequence. Never resend from the archive. |
| `RecoveryRemoteIntegrity: archived non-landing contradicted` | A settled archive contradicts the published chain. The authority/storage administrator must investigate the numbered root, decision log and trusted storage history. No authority repair command exists. Keep the volume read-only and preserve the old store until the administrator restores or validates the chain; then follow the read and fresh-store steps below. |
| `WritableMountAttachFailed` | Correct FUSE/mountpoint availability; ownership and registration may already have landed. |
| `WritableCacheCloseFailed` | The cache the start opened to finish an interrupted shutdown did not close cleanly; its lock is released and the finished work is on disk. Check the cache directory's storage, then start again. |
| `WritableFinishLeaked` | Finishing an interrupted shutdown left its engine holding the store; the finished work is on disk. Start again, and report the defect. |

### Finishing a journal with explicit recovery

The [disk-loss recovery guide](operating-disk-loss-recovery.md) is the complete
command, store-shape, exit-code and refusal reference. The summary here keeps the
mount-start handoff beside the writable admission procedure.

Stop the displaced process and preserve its store. Run `gran recover <store-dir>
<volume> --writer <writer> --key-seed <existing-seed> --endpoint <url> --pin
sha256/... --credential-context <name>` with the existing credentials and publisher
trust. Supply `--acknowledge-takeover <writer>` when recovering a lost store's
selected writer or renewing consent on this store after ownership was lost;
inspect that selection before acknowledging it. If the displacing writer already
released its row, recovery reports `IntentSelectedWriterMissing` and keeps the journal.
The same refusal on a fenced store whose writer has no row at the authority has no
in-place repair: preserve the store and follow the
[fenced-store exit](operating-disk-loss-recovery.md#fenced-store-with-no-live-row),
which retires the overlay and continues from a separate fresh store.

A landed commit whose refresh lost ownership uses the same renewed acknowledgement
on this store. After the fresh grant, recovery proves the selected prepared root
already represented on the verified published chain before refreshing the intent
to the landed root. If that proof fails, `RecoveryJournalBlocked` preserves the
selected root and local residual; inspect the selected writer's outstanding work
before retrying. A successful refresh installs the landing and retains the
remaining local work; it does not publish the landed commit again.

Recovery replays the actual journal after a fresh-instance grant, whether the
journal is plain dirty work or a remainder left by settlement or installation.
A successful strip or landing install continues in that invocation: recovery
finishes the admitted retained lane and commits the remaining work once. One
30-second deadline includes settlement, finishing and release. It never admits
new user writes or automatically resolves a conflict. A verified conflicting
boundary is archived and stripped with non-landing proof; its dirty files,
including work written after the boundary, replay on the old base. Recovery emits
`recover.fence_settled{how=stripped}`. An unchanged conflict then returns exit 1
with `RecoveryConflict` and `recover.journal_blocked{reason=publication}`,
reports each colliding path, and keeps the writer live. Resolve the files or
change the head before retrying.

`recover.fence_settled{how=landed|released|stripped}` reports a settlement/install action.
It is not an overall success signal. Only `JournalFinished` (exit 0) and
`recover.journal_finished{base_seq}` confirm a clean journal, settled publication,
no retained obligations, a detached engine and a durably released writer row.
An already released clean rerun reports nothing owed. Partial progress can still
end with exit 1 and `recover.journal_blocked{reason}` alongside a specific refusal
or `RecoveryJournalBlocked`.

The closed blocked reasons are `replay`, `publication`, `obligations`, `namespace`,
`limit` and `release`. Restore authenticated reads or service before retrying
transient failures; free space outside retained recovery files for capacity
failures. Missing evidence, namespace mismatch or retained debt without a
supported repair requires inspection or restoration of matching evidence. Release
uncertainty requires service restoration and exact retained replay before the
Release deadline; after expiry, the next `gran recover` refuses
`IntentFreshInstanceRequired`. Preserve this store; a same-state retry or writable
mount is not a repair for these conditions.
The archived-store refusals below retain their separate remedies.

For an archived-store refusal, stop every process using the volume and leave
`<old-store>` unchanged. Do not delete it, reuse it as a cache or store, or run
recover or resend against it. Read each known published file with:

```text
gran cat <volume> <path> --seq <published-seq> --root-key ... --endpoint ... --pin ... --cache-dir <separate-read-cache>
```

`RecoveryArchivedLanded` supplies the published sequence in
`recover.archived_landed{seq}`. For `RecoveryArchivedUnresolved`, use an
independently known and verified published sequence. For an integrity refusal,
wait until the administrator establishes a trustworthy chain before these reads
or writable continuation.

If writable service may proceed without the old unpublished changes, choose
empty, separate `<fresh-store>` and `<fresh-cache>` paths and run:

```text
gran mount <volume> <mountpoint> --writable --endpoint ... --pin ... --root-key ... --key-seed ... --store-dir <fresh-store> --client-cert ... --client-key ... --credential-context ... --cache-dir <fresh-cache> --foreground
```

The empty store acquires a fresh writer UUID; it does not take over the old row.
Retry a cursor-race refusal with the same fresh store. If row quota or another
admission refusal remains, preserve the old store and use `gran cat` until that
condition clears. This does not promise writable continuation through an
admission refusal or authorize changing the old store. Published data remains
readable; the residual overlay remains preserved in the old store and is absent
from the fresh one. Complete any wanted extraction before retiring that overlay.

### Construction and overlay capacity

With the stock 128 MiB overlay cap and default construction workspace, a
scratch probe tested fresh incompressible files in an empty namespace. It
used one process per size and bisected the boundary to 1 MiB resolution. The
largest file that sealed and landed was **45 MiB (47,185,920 bytes)**. The
46 MiB file returned `OverlayCapacityExhausted`, class `refused`. No committed
test pins that boundary.

For unsealed dirty bytes `D`, the commit must fit `2D + 32 MiB + graphs <= cap`.
Staging holds one copy, sealing pins another, and the ownership reserve and real
graphs share the same cap. Journal, metadata and other reserves reduce the room
available, so the capacity left for any one file depends on the rest of the
boundary.

`--construction-workspace-mib N` and `--overlay-cap-bytes N` are available on
writable mounts and `gran recover`. The overlay cap defaults to 134,217,728
bytes and must be at least 44,938,292 bytes. That floor is the smallest cap at
which an otherwise empty overlay can take one 65,536-byte buffer write, seal it,
and leave the eager trigger off. Both settings are runtime policy:
they are never persisted and must be supplied again on restart or recovery.
The construction workspace defaults to 1024 and accepts 1024 through 16384 MiB. The default is
1,073,741,824 bytes of cumulative construction work, charged conservatively at
eight times each operation's bytes plus 1024 bytes, including repeated fetches.
Materialisation and acceptance each have their own cumulative budget. The
per-engine lease ledger only records policy amounts through completion: it
reserves no memory and enforces no aggregate memory bound. Multiple budgets
and engines have independent counters; a projected sync can hold two leases.
These counters and the bookkeeping do not consume overlay space.

A refused attempt can leave unreferenced objects in the local object store,
outside the overlay cap: up to about 45 MiB in the stock-cap measurements.
This is a known cost; reclamation of these objects needs follow-up work.

Local workspace exhaustion reports `SyncWorkspaceExhausted`, class `refused`,
with the escaped captured path or boundary and needed/limit byte counts.
The event is `sync.workspace_exhausted{reason=SyncWorkspaceExhausted,needed,limit}`.
The whole boundary stays pending and the capacity backoff keeps the driver
running; closing a file or freeing room can wake it early. Preserve needed
bytes outside the mount. For a capacity-wedged 92 MiB tree, rerun the writable
mount or recovery with both `--overlay-cap-bytes 268435456` and
`--construction-workspace-mib 4096`. A repaired boundary includes unrelated
dirty files when it lands. Small rewrites of landed files can reuse unchanged
grains and land above the fresh-file limit; this does not promise arbitrary
file sizes.

Workspace exhaustion and a full overlay both return `ENOSPC` to sync calls.
Use the named report and `refused` class to distinguish workspace exhaustion
from overlay capacity exhaustion. Increasing only the workspace does not raise
the overlay cap or rescue the measured 46 MiB stock-cap case. Deleting a dirty
file detaches its name but frees no staging bytes before a successful landing,
so deletion alone cannot release a wedged overlay. Preserve retained recovery
evidence and retry with both limits sized for the pending tree.

### When the mount commits

A complete commit publishes the frozen live namespace and each named file's
captured bytes, clean checkpoint or authenticated base content. Writes after
that capture remain for a later commit. Earlier create/unlink/recreate and
replacement histories do not exclude surviving names from this snapshot.

A scoped sync still projects only eligible durable content. If that projection
cannot represent its selected file identity and bytes, it fails with
`EIO` (`SyncSelectionUnrepresentable`) before signing or registration and releases
its preparation reservations. A later complete commit can compact that history,
after which scoped syncs can succeed again. New writes can create another such
history. A selected file can retain an earlier eligible path in the published
projection while its live path remains in the overlay for a later complete
commit. Scoped sync does not promise to publish every unsynced namespace move.

A held descriptor for a detached file still blocks complete commits until it is
closed. Capacity admission deadlock, unresolved registrations, conflicts
and storage failures also remain blockers. Complete snapshots do not resolve them.

After a power loss, reopen rolls back a file whose buffered bytes were lost
when no fsync or commit had covered them: the file returns to its last synced
content, its published base or empty, and `overlay.stage_rolled_back` reports
it. Three power-loss shapes still refuse to reopen with the store untouched:
a power cut inside an fsync of a file that also has later unsynced
writes, a file rewritten while a commit held a capture of it, and a file synced
before a landing, held open across it and then overwritten without a sync.
Recover those by the fresh-store takeover in
[Retiring a refused overlay](operating-disk-loss-recovery.md#retiring-a-refused-overlay).

A writable mount publishes its changes on its own. It commits half a second after
the last write once no file is open for writing, and at most five seconds after
the first unpublished write while one is; it commits at once when its journal
passes 48 MiB or the next tree seal's captured bytes and sync graph, together
with its commit graph and current charges, reach three quarters of the cap. A commit that
fails on the way is resumed by the mount. While the authority cannot be reached,
the pause before each retry starts at 1 second, grows by 1.6 times up to 2 minutes,
and is spread by up to a fifth either way so that mounts that failed together do
not retry together. It starts again at 1 second as soon as the authority answers.
After eight refusals of any other kind, the mount
prints `COMMIT STALLED` and retries every 10 minutes, spread the same way. A commit
refused for room is retried every 10 minutes, or sooner when a file closes or a
landing frees room. The log records when such retrying begins and when it ends,
with the number of tries; each failed try is logged as well. Without an intervening
answer, a grown outage retries about once every two minutes (no sooner than 96
seconds); when reads answer but publication still fails, an answer can shorten the
pause, but never below one second. Answers do not shorten a stalled commit's
10-minute pause. The first checked `503 unavailable` starts a 31-minute window
for that retained commit in this process. Each checked `503 unavailable` that
arrives within the window is exempt from the eight-attempt budget, up to 64
persisted exemptions. The next poll waits at least a jittered 30–60 seconds.
A restart gets a fresh window and keeps the spent exemptions. A crash before the
answer is saved leaves that attempt charged. The default background drive gets
a fresh 167-second bound after construction and at each takeover. It includes
the size-scaled 45–46-second publish deadline, time for a status read and root
probe, and time for local verification and saves. The drive checks that the
publish deadline still fits before it reserves an attempt. Explicit shorter
drive bounds and enclosing deadlines still apply.

While the window is open and below the cap, published fsync and shutdown under
their normal bounds send nothing for the retained commit. Published fsync
reports `SyncCommitUnresolved` (class `unavailable`). Shutdown can report
incomplete if publication remains pending or its deadline expires while a
background drive holds the lane. Their bounds and mount-control's Final
deadline still apply. After any pending poll wait, expiry or the cap returns
further `503 unavailable` answers to the charged budget.
At eight charged attempts the mount is fenced, later writes and syncs fail with
`ESTALE`, and the retained work can be settled with `gran recover`.
Extra attempt frames use ordinary overlay capacity. A capacity refusal leaves
the commit retained and unfenced, with no new send.

The authority tokens `missing-reference`, `invalid-reference`, and
`publish-work-limit` stop automatic sends. A missing reference keeps the
publication and names its ID. After repairing the missing objects, use
`gran recover` with `--acknowledge-resend <publication-id>` for one exact
resend. An invalid reference or a work-limit refusal against this head rejects
the commit once the retained evidence rules out earlier decisions. Recovery
reports the token and requires existing non-landing proof before archiving.

While a commit is stalled, writes still land in the local
overlay and `fsync` fails with `EIO` (capacity refusals use `ENOSPC`); a restart finishes the commit. A commit still
in flight when the mount is stopped is waited for within `--shutdown-bound`; one
that outlasts the bound is kept for the next start, as every incomplete shutdown
is.

If the live commit loop stops because the store is fenced or poisoned, new writes
are refused and pending changes remain in the store; if it stops because the
served view is closed, the view refuses further calls and pending changes remain
in the store. In either case nothing more is committed while this mount runs; a
remount runs start recovery, which may refuse the mount while a fence holds.
After an I/O error on the overlay area, reboot the host before remounting: a
fresh open cannot always see an earlier failed write. The reboot restores no
bytes.
The corresponding local reports are
`gran mount: error: COMMIT STOPPED (fenced): new writes are refused; pending changes are kept in the store, but nothing more is committed while this mount runs; volume=<name>`
and
`gran mount: error: COMMIT STOPPED (closed): the served view is closed or its session has ended; pending changes are kept in the store, but nothing more is committed while this mount runs; volume=<name>`.

### Commits by other writers

A writable mount picks up commits another writer published when a file or
directory is opened, when a name it looks up is not found, and when a directory
listing is rewound. Each such call first asks the authority for its head. It
waits at most 2 seconds for the answer and for the new view; past that, it is
served on the view the mount already has, and the pickup completes in the
background. A descriptor opened before the pickup keeps reading the version it
opened. While the mount has local changes not yet published, a file open for
writing, or a sync in progress, it does not pick up other writers' commits: it
serves its own view until its own changes are committed, which happens within
the commit delay above, five seconds at most from the first unpublished write,
plus the commit itself, and that commit includes theirs. A writable descriptor
held open, such as an editor's or a log's, therefore delays pickup until it
closes. The first call that defers logs
`mount.view` with `cause=adopted` and `outcome=deferred`. A head the mount
cannot verify or serve is refused with a `mount.view` warning, and the mount
keeps serving its view.

**When the authority cannot be reached.** A call that asks for the head still waits at most 2 seconds. When the
answer shows the connection is down, the mount enters the *unreachable* state: at once when the connection is
refused, within about 20 seconds when it never completes, and within 45 seconds when the server accepts it and
never answers. Four answers count as down too: a status the protocol does not define, such as a proxy's `502` or
`504` in front of an authority that is gone; a response whose framing is broken; a response that stops making
progress; and a head answer the mount cannot read. Any other answer, even "busy" (`503` or `429`) or "not
found", is never treated as unreachable. On entry the mount logs `mount.view` with `outcome=stale` as a warning,
sets the `mount_view_stale` gauge to 1, and prints `STALE (pinned at seq N, since T)`. In the state no call asks for the head or waits, and the mount serves the
view at seq N. A background check retries after half a second, doubling to every 5 seconds. The first check
that gets the head ends the state and logs `mount.view` with `outcome=fresh`, and the next open picks up what
other writers committed meanwhile. The state ends at most 50 seconds after the authority can answer again (5
seconds when it was refusing connections), plus the time of one request. Until then, commits other writers made while the mount could not see them are not
visible. That is a deliberate exception to close-to-open, and `--view strict` removes it. Writes are unaffected:
files can be opened, created and written as usual, and the changes are kept locally and committed when the
authority returns.

**Checking the view.** Reading the `user.granary.view` attribute of the mount's root directory, for example
`getfattr -n user.granary.view /mnt/vol`, answers `fresh:<seq>` or `stale:<seq>:<since>`. `<seq>` is the
sequence number of the view the mount serves, and `<since>` is the Unix time, in seconds, when the unreachable
state began. `fresh` means the last check reached the authority. It does not mean no newer commit exists: a mount
with local changes or a file open for writing defers pickup as described above, and a head the mount refuses is
logged. Reading the attribute does not itself check the authority. A mount that makes no such call reads
`fresh` until one does. From that call the attribute can read `fresh` for up to 45 seconds more, before the
state begins. To get a confirmed answer, open a file on the mount first, or use `--view strict`.

**`--view strict`.** On a writable mount started with `--view strict`, a call that asks for the head is never
served on an unconfirmed view. It waits up to 45 seconds for an answer, retrying a busy server every half
second, and otherwise fails with `ETIMEDOUT`. In the unreachable state every such call fails with `ETIMEDOUT`
at once, and entering the state also logs `op.failed` with `kind=view` and `class=unavailable`. A strict call
can also time out against a server that is reachable but slower than 45 seconds. The mount serves one request
at a time, so a strict call that waits holds up every other request on the mount for as long. In the
unreachable state a strict mount also refuses new writers and new names: opening a file (for writing too),
creating a file, a directory or a symbolic link fail with `ETIMEDOUT`. Renaming an existing name
is not refused. Descriptors
already open keep reading what they read before, and writes through them are kept and committed as on any
mount. `EIO` still means a closed view or corrupt content.

### `--commit-on-sync`

Without this flag a writable mount's syncs keep the default profile: fsync,
fdatasync, fsyncdir and an `O_SYNC` or `O_DSYNC` write return once the synced
bytes are durably registered with the authority as prepared state. Publication
happens later, when the mount commits its work.

With `--commit-on-sync` each of those calls returns only once a publication of
its own has landed and been installed as the mount's view. The publication
holds the synced file at the bytes that sync captured and every other file at
the bytes it last durably synced; writes the call did not sync stay in the local
overlay for a later commit, and are neither published nor lost by it. A call that
cannot reach its own landing within its deadline fails with EIO, or with ESTALE
once its publication is fenced; neither is a success, and the work stays in the
overlay. EIO does not prove the work unpublished: the authority may already
hold the landing, and the call failed reading it back, refreshing or installing
it. ESTALE is sticky: once the publication's attempts are exhausted (for
example by repeated rate limiting) the mount is fenced, and later writes and
syncs also fail with ESTALE. Closing a file (flush and release) does not sync.

The flag is accepted only with `--writable`, and `mount.gran` does not take it:
`-o commit_on_sync` is an unknown option.

Every sync request is one publication, so the flag costs a root publication per
call. An `O_SYNC` or `O_DSYNC` write may cost two: the kernel can follow the
write's own sync request with an fsync of its own, which the mount answers as a
second request, and so as a second publication.

`--writable --reset-floor` clears only the mount-private floor after local binding
and authority/intent checks, before verifying the initial view. It does not clear
the shared floor, reset writer identity, discard the overlay or settle publication.
Remove the planted root first; use this option only after investigating the floor.
See [StaleHead recovery](#if-a-mount-refuses-to-start-with-stalehead).

`mount.gran` and fstab remain read-only: `-o writable` and `-o key_seed=...` are
unknown options. The systemd unit forwards native flags through `GRAN_MOUNT_EXTRA`.
For opt-in, put only file paths and the context in its private environment file:

```text
GRAN_MOUNT_EXTRA="--writable --key-seed /etc/gran/signing/volume.seed --store-dir /var/lib/gran/writable-volume --client-cert /etc/gran/client.crt --client-key /etc/gran/client.key --credential-context mount-service"
```

Keep seed bytes in the separate 0600 file owned by the unit's service identity,
under a protected directory. Never put key bytes in the environment file or
`GRAN_MOUNT_EXTRA`. The unit still supplies root-key, cache and foreground;
its native writable operands pass every common admission gate.

### Stopping a writable mount

The owner’s `gran umount`, `SIGTERM`, `SIGINT` and `systemctl stop` run one bounded shutdown **before** the
mount is unmounted: the mount syncs each dirty file, commits once and releases its
ownership, all within `--shutdown-bound <seconds>`. If a scoped pass returns
`SyncSelectionUnrepresentable`, shutdown releases that preparation, skips the
remaining scoped syncs and proceeds to its complete commit. Other errors still
stop shutdown. The failed scoped caller receives no success acknowledgement.
The bound is 1 to 3600 seconds,
default 30; any other value, or the flag without `--writable`, is a usage error
(exit 2). `mount.gran` has no `-o` form for it. From the first stop request, writes and
syncs answer `EROFS` and reads continue to be served. **A signal after that request stops the
shutdown at once**: nothing is discarded, and what was not committed is kept.

When a writable daemon exits it prints one status line to standard error (the
journal, under systemd). The table shows its data outcome; every line also names
the daemon's overall result and exit code. Released reports add the escaped
store and say counts were not reported; a clean report also names elapsed time.
`<store>` is the terminal-escaped spelling of your original `--store-dir`:

| Ending | Line |
| --- | --- |
| committed | `gran mount: shutdown committed seq=<seq> in <ms> ms` |
| nothing was owed | `gran mount: shutdown had nothing to commit` |
| the bound, or a signal | `gran mount: shutdown stopped at its bound after <ms> ms: <f> files (<b> bytes) unsynced, <o> operations uncommitted; the overlay, staging and intent are kept in <store>: preserve it; the next mount with this store can finish interrupted non-fenced shutdown before serving; fenced or damaged state needs explicit recovery` (`stopped by a signal` when that is what stopped it) |
| a step failed | `gran mount: shutdown failed (<class>) after <ms> ms:` and the same tail |
| the sequence was lost | `gran mount: shutdown lost its sequence after <ms> ms:` and the same tail |
| fenced | `gran mount: shutdown fenced after <ms> ms: <f> files (<b> bytes) unsynced, <o> operations uncommitted; the authority refused this mount's ownership or its commit; the overlay is kept in <store>: preserve it; recovery is explicit` |
| no shutdown ran | `gran mount: the shutdown did not run; the overlay is kept in <store>: preserve it; the next mount with this store can finish interrupted non-fenced shutdown before serving; fenced or damaged state needs explicit recovery` |

When the counts cannot be read, `what was left could not be read` stands in their
place. The same outcome is logged as `mount.unmount`
([`operating-client-observability.md`](operating-client-observability.md)).

The exit code reports the data first, then the session, then the cache; the first
row that applies wins:

| Code | Meaning |
| --- | --- |
| **5** | fenced: the authority refused this mount's ownership or its commit; the overlay is kept and recovery is explicit |
| **4** | stopped at the shutdown bound or by a signal after the first stop request; everything is kept |
| **1** | a runtime failure: a failed shutdown step, a lost sequence, or a session that did not end cleanly |
| **3** | unmounted, but the cache could not be closed cleanly, or the daemon exited with the mount already gone and before the session ended, so the cache close never ran |
| **0** | clean: released (or read-only), the session ended cleanly and the cache closed |
| **2** | a usage error; nothing was mounted |

**A file held open.** After its unmount the daemon waits up to 5 seconds for the
kernel to end the session. When nothing ends it, for example because a process
holds a file open on the mount, the daemon exits without waiting further, after
the commit: the holder then sees `ENOTCONN` (`Transport endpoint is not
connected`), and a shutdown that released exits 3, since the cache close never
ran. A mount namespace cloned while the mount existed can keep a private copy
and hold the session open the same way, even though the daemon's own unmount
succeeds. When the daemon stops waiting, it logs
`client.gran.mount.the.fuse.session.did.not.end.after.its.unmount` with
`listed` (`gone`, `listed`, or `unknown`) and `connection` (`alive`, `gone`,
or `unknown`). Once the kernel has begun tearing the session down, the daemon
waits for the cache close however long it takes.

**Unmounting without a signal.** Granary never refuses an unmount. A plain
`umount` or `fusermount -u` of a mount with a file held open is refused by the
kernel with `EBUSY`, and the mount serves on, writes included. With nothing held,
the kernel ends the session and the daemon runs the same bounded shutdown and
exits by the table. A lazy unmount (`umount -l`, `fusermount -u -z`) removes the
mount from the table at once but keeps serving held files, writes included; the
shutdown runs only at the last close, and its bound starts then.

**Owner `gran umount`.** The command checks kernel mount ownership, authenticates
its daemon through a private control socket and asks for shutdown before unmount.
It waits for the daemon's complete shutdown, session and cache result and returns
that daemon's 0/1/3/4/5. A committed data report alone does not mean exit 0.
A second owner command subscribes to the same sequence without cutting it.
Read-only mounts report their daemon ending without an overlay. Raw store paths
are escaped for terminal safety in both commands' status.

The client waits from its first Stop byte for the advertised shutdown bound plus
35.5 seconds: 65.5 seconds by default, 3635.5 seconds at the maximum, or 35.5
seconds for read-only. This includes a 30 second reporting allowance for cache
close; it does not cut the daemon's cache close. Handshake and Stop/Accepted each
have a separate absolute 2 second deadline. Client timeout, lost connection,
truncated reply or daemon death before a complete valid Final means **exit 1,
outcome unknown**, never exit 4 or successful flush. Preserve the named store
and inspect the daemon's status. There is no retry or second detach after Stop.
An unknown-cut report says “shutdown stopped; the cut was not recorded”.

Root controlling a different uid's mount performs **detach only; shutdown outcome
was not requested**. Its 0/1 attests the verified detach only. A non-root foreign
uid is refused. If an owner's endpoint is absent or refuses connection before
Stop, verified emergency detach remains possible, but returns **1** even on
success: **detached; shutdown outcome unavailable**. Credential, custody,
identity, version and framing refusals never authorize that fallback. Wait at
the original attachment target in the same mount namespace; moved or renamed
mounts have no endpoint relocation. Use the daemon's signal or service status
when a moved mount's shutdown outcome matters.

**Control runtime provisioning.** Non-root endpoints live beneath
`/run/user/<uid>/granary-umount`, with an already-provisioned owner-owned 0700
runtime parent. Root uses `/run/granary-umount`. No environment path or `/tmp`
fallback is used. Missing or insecure provisioning refuses a new attachment.
The systemd template uses `RuntimeDirectory=granary-umount`, mode 0700 and
`RuntimeDirectoryPreserve=yes`; use the same directives for a user service.
Non-logind deployments need administrator provisioning of `/run/user/<uid>`.
The parent must live as long as every daemon: user lingering may be needed.
Preservation across service stops does not prevent logind removing its parent
at logout. Never age-clean or recursively remove the shared directory. Each
daemon removes only its own socket and leaves its lock file. Unexpected
runtime-directory removal leaves connected clients usable but new discovery
unavailable; no live rebind occurs and cleanup leaves replacements untouched.

**The bound and systemd.** The default bound fits inside systemd's 90 s stop
timeout together with the cache close. A larger bound needs `TimeoutStopSec=`
above the bound plus the cache close's own time; otherwise systemd's `SIGKILL`
ends the shutdown before its bound does.

## Choose a trust mode; there is no default

Exactly one of the three is required. Omitting all three is an error, not a
fallback — a mount is ambient, and many programs will traverse it without knowing
where the bytes came from, so the posture may not be chosen silently.

| mode | what it verifies | what it gives up |
|---|---|---|
| `--root-key ed25519:<64 hex>` | the publisher's signature over the root, which commits the whole tree by hash; the freshness floor applies | nothing, beyond needing the key distributed |
| `--manifest-root <algo>:<hex>` | the resolved root's `manifest_root` equals the id you supplied — the caller-pinned-content shape (composefs's `digest=`, dm-verity's root hash) | **freshness**: it pins content, not currency. Needs no key and no trust document |
| `--trust-server` | that the pinned endpoint is the declared content authority, and nothing more; the freshness floor still applies | **publisher authority**: a TLS pin authenticates a server, not whoever signed the tree |

Note which modes carry a **freshness floor**, because it is what produces a
`StaleHead` refusal later: `--root-key` and `--trust-server` both do;
`--manifest-root` does not, because a caller-supplied digest pins content rather
than currency.

**What a mount reports it pinned.** Every successful mount prints, on its error
stream, one line naming the publication it opened, then the `history: not checked`
line:

    gran mount: pinned volume=<volume> seq=<n> root=<root id> manifest-root=<manifest id>
    gran mount: history: not checked

`root=` is the id of the root document at sequence `<n>`, as the publisher wrote
it; only `--root-key` checks its signature, so in the two keyless modes this line
says which root was opened, not that it was signed. `manifest-root=` is that
root's `manifest_root`, the id of the tree it names. It is the value
`--manifest-root` accepts, and the same id `gran publish` prints on its
`manifest-root` line (and `gran harvest` for a local store), so one publication
can be traced from the publisher to every mount. The two are different objects:
never compare a `root=` with a `manifest-root` value.

**All three keep the same structural integrity**: every object is re-hashed against
the id that named it, and the tree is walked at mount time. The two keyless modes print a
line beginning `gran mount: EQUIVOCATION: cache/wire root mismatch at …` when the
cached and wire views of a root disagree — grep for `EQUIVOCATION`, not for
"warning".

**Any machine-wide entry point requires `--root-key`** — the systemd unit,
`/sbin/mount.gran`, an fstab line, or any mount carrying `--allow-other`.
Delegating content authority for a whole machine is a decision only a publisher
signature can carry. What you will actually see, so you can grep for it:

- `--allow-other` (or `allow_root`) in a keyless mode:
  `allow_other makes this mount readable by every local user, which is a
  machine-wide entry point, and --root-key is required for one`
- `mount.gran` asked for a keyless mode:
  `mount.gran: --trust-server and --manifest-root are refused for this entry point`
- the unit, which hard-codes `--root-key`, given a second mode through
  `GRAN_MOUNT_EXTRA`: `more than one of --root-key, --manifest-root and
  --trust-server was given`, exit 2.

## `--allow-other`, in plain words

**Without it**, nobody but the user who mounted it can read the mount at all. For
the systemd unit that means root alone; every other local user gets
`Permission denied`.

**With it**, *every* local user who can reach the mountpoint can read the entire
snapshot and execute any entry carrying the signed exec bit, under their own
credentials — root included. That is the point of the flag and it is the whole
cost of it.

Either way: writes fail `EROFS`, and the mount always carries `nosuid` and `nodev`.
It deliberately does **not** carry `noexec` — executing a binary from the mount is
a supported operation, and the exec bit it honours is the one the publisher signed.

## One request at a time

The mount is **deliberately serial**: one FUSE worker under one global mutex.
`n_threads` is pinned to 1 and is not a tuning lever — under a single mutex it
would buy nothing. Real concurrency is a successor design, not a configuration.

Two consequences worth planning around: a slow read stalls every other reader of
that mount, and so does a cache compaction (compaction is triggered from a journal
append, and a cache HIT appends a touch record, so it runs on the serving path).

**How big is that compaction stall?** Measured on a 100,001-entry volume, reading
every file once: the one read that carried the compaction took **3.63 ms against a
1.00 ms median for the pass — an excess of 2.6 ms**, with the journal collapsing
2,685,585 → 7 bytes. So it is a millisecond-scale hiccup once per ~65k cache
touches, not a pause anyone will notice, and it is the *serial mount* that makes
it everyone's hiccup
rather than one reader's.

If you want a second mount, **give it its own `--cache-dir`** — this is not a
performance preference, it is a refusal. A second process on the same cache
directory cannot take the writer lock, and rather than run on with a floor it
could never persist, the mount refuses: `another process holds the writer lock on
this cache directory, so every floor write would be a silent no-op, and a mount
that cannot persist its floor must not pretend to have one — give the mount its
own --cache-dir`. Note also that the systemd unit is one instance per volume per
host, and `CacheDirectory=granary/%i` gives each instance its own directory
already.

## Readiness: the mount table is not the answer

`systemctl start` returning, or the process being alive, or even a row appearing in
the mount table, do **not** mean the mount is serving. The kernel mount is
established before the thread that answers requests is running, so there is a
window in which `findmnt` shows the filesystem and a read still has nobody to
answer it.

Wait for a **read**, under a bound:

```sh
mp=/srv/gran/<volume>
unit=gran-mount@<volume>.service

# 1. the row exists -- and the DAEMON is checked in the SAME iteration, so a
#    start-up failure surfaces in one pass with its journal, instead of after
#    the whole bound with a misleading ENOENT from step 2.
ready=0
for _ in $(seq 1 120); do
  if ! systemctl is-active --quiet "$unit"; then
    echo "the daemon is not active; its journal:" >&2
    journalctl -u "$unit" --no-pager >&2
    exit 1
  fi
  row="$(findmnt -rn -o SOURCE,FSTYPE --mountpoint "$mp" 2>/dev/null || true)"
  if [ "$row" = "gran fuse" ] || [ "$row" = "gran fuse.gran" ]; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" -eq 1 ] || { echo "no granary mount appeared within the poll bound" >&2; exit 1; }

# 2. and something can actually be read through it
timeout -k 5 30 cat "$mp"/<a-known-file> > /dev/null \
  || { echo "the mount is attached but not serving" >&2; exit 1; }
```

`fuse` is the route a privileged mount takes; `fuse.gran` is the unprivileged
`fusermount3` route. Accept whichever your deployment uses, and no other.

`systemctl is-active` is not a readiness test on its own — it is true from the
moment `gran` execs — but it is exactly the right liveness test to fold INTO the
poll, which is why the loop above uses it that way.

**How long is long enough?** The eager whole-tree walk runs before the kernel
mount, so the mount is not readable until the whole tree has been validated — and
that is round-trip-bound rather than CPU-bound, so a warm cache helps a great
deal. Measured on release binaries (aarch64, loopback TLS), medians of three
trials:

| volume | entries | cold | warm |
|---|---|---|---|
| 10 files | 15 | 44.5 ms | 32 ms |
| 10,001 files | ~10,500 | 285 ms | 44 ms |
| **100,001 files** | ~105,000 | **2.8 s** | **0.13 s** |

**A hundred-thousand-entry volume is readable in about three seconds cold, and
about a tenth of a second warm.** Budget for that, keep the poll bound above, and
do not mistake the wait for a hang. **That bound is 120 iterations, not 60
seconds**: each one runs `systemctl is-active` and `findmnt` before its
`sleep 0.5`, so the wall time is 60 s plus 120 probes' worth of work — more than
60 s, never less. Size it in iterations if you need a real deadline, or wrap the
loop in `timeout`.

**Why the poll bound holds, and what it buys you.** These numbers are
the resumable validation cursor's: the mount validates the whole tree
eagerly, but a walk stopped by a missing node resumes in the directory
it stopped in rather than restarting from the root. The measured cold
cost is ≈ 0.9 ms per structure node and close to LINEAR across the two
scaling points (10.2× the nodes for 9.7× the time). So the bound leaves
≈ 22× headroom on the largest volume measured here.

**Do not turn that into a capacity number for YOUR volume.** On this hardware
the slope extrapolates to roughly 67,000 structure nodes inside the bound —
about two million entries — but it is fitted to two points from one generator over
LOOPBACK TLS, and three things move it. The walk is **round-trip-bound**: 96.5–96.9 %
of a cold attach is the walk, and a round costs 1.1–2.2 ms whatever the volume,
which is the shape of a per-round network exchange rather than of decode work.
That per-round cost is what a real network inflates: a volume needing 1,300
rounds at 20 ms a round is 26 s where here it is 2.8. (The measurement does not
separate the round's own latency from this loopback's RTT — it reports the
round, not the wire — so treat the per-round figure as an upper bound on how
little a remote backend could cost, never as a subtraction.) A tree with fewer
entries per node reaches the same node count on a much smaller directory tree.
And a deep narrow tree serialises rounds that a wide one batches. **Measure your
own worst case, keep the bound, and raise it when the volume, the topology or
the distance to the backend says to** — a bound you never hit costs nothing.

The mount-time figures above are from the 2026-09-08 measurement of the
resumable cursor. That run repeated the compaction stall above — same read,
same 2,685,585 → 7 byte collapse — at 3.3 ms against a 1.0 ms median, where
the figure above is 3.63 ms: the same millisecond-scale hiccup, run to run.
The lazy validator and real read concurrency are not implemented.

**For a consumer unit**: `After=gran-mount@<volume>.service` orders you after the
daemon's `execve`, **not after its mount**. There is no ordering primitive that
waits for the mount today — poll, as above, in the consumer's own `ExecStartPre=`.

## The systemd unit

`packaging/gran-mount@.service` is a template: one file serves many volumes, one
instance per mount. **The instance name IS the volume name**, so the unit, its
cache and its configuration cannot disagree about which volume they are for.

Install:

1. Put the binary at **`/usr/local/bin/gran`** — and use `install` or `cp`, never
   `mv` from a temporary directory. On an SELinux-enforcing host systemd will only
   execute an appropriately labelled file; `/usr/local/bin` is `bin_t` by policy,
   but a `mv` PRESERVES the source's label and the unit then fails `203/EXEC`.
   Relocating the binary is a drop-in (`ExecStart=` to clear, then `ExecStart=…`).
2. Write `/etc/granary/mounts/<volume>.env`. The four lines `stack.sh start`
   emits are already the right shape; add `GRAN_MOUNTPOINT=` and, only if the mount
   is meant to serve the whole machine, `GRAN_MOUNT_EXTRA=--allow-other`. Nothing
   in this file is secret — an endpoint, a public SPKI pin, a public signing key and
   a volume name — so 0644 root-owned is fine, and it is worth saying so rather than
   leaving someone to guess that the "key" is private.
3. **Install the unit itself** — the step it is easiest to skip, and `enable`
   fails with `Unit gran-mount@.service not found` if you do:
   `install -m 0644 packaging/gran-mount@.service /etc/systemd/system/` then
   `systemctl daemon-reload`.
4. Create the mountpoint as an existing, empty directory, and note that
   `GRAN_MOUNTPOINT` must be an ABSOLUTE path.

   `gran mount` checks that the mountpoint itself is an existing directory,
   is not a symlink or an existing mount, and is empty unless you pass `--force`.
   Neither `gran mount` nor `gran umount` checks the ownership or permissions
   of its parent directories. The systemd unit runs as root. If another user
   can replace a path component between the check and use, root may mount
   or unmount at a different location. Use a root-owned path such as
   `/srv/gran/<volume>` and keep every component root-owned and `0755`
   or tighter. Avoid `/tmp`, home directories and group- or world-writable
   directories for both commands.
5. `systemctl enable --now gran-mount@<volume>`, then check it with the readiness
   probe above — `systemctl is-active` alone is not readiness.

The cache lives at **`/var/cache/granary/<volume>`**, mode 0700, created by
systemd's `CacheDirectory=` and **persisting across restarts**. It holds the
fetched objects, the journal, and the mount-private freshness floor at
`anchors/<volume>.mount`. Size your disk for it, and know where it is before you
need the recovery section.

**Logs.** The daemon writes to standard error, which systemd forwards to the
journal (`journalctl -u gran-mount@<volume>`). To get JSON lines for a log
pipeline, a rotated file, or the correlation id carried by the events of an
operation, see
[`operating-client-observability.md`](operating-client-observability.md): add
`GRANARY_LOG_FORMAT=json` (or `GRANARY_LOG_FILE=...`) to the instance's `.env`
file. The page also lists every event name and field a script may match.

**Do not add filesystem-namespace hardening to this unit.** `PrivateMounts=yes`,
`ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `ReadOnlyPaths=` and about twenty
siblings each put the service in its own mount namespace, and the mount it makes is
then invisible to every other process on the machine. **`PrivateMounts=no` does not
undo that** — it is the default, and the other directives create the namespace
independently. The unit ships a hardening set that is namespace-free **by
MEASUREMENT** — every directive in it was executed against a real mount on
systemd 259 and against the directive matrix on systemd 255 — and carries the
forbidden list in a comment with that reason. One member of that list behaves
differently and the unit says so rather than smoothing it over: `PrivateUsers=yes`
leaves the daemon in the host's namespace but makes the mount FAIL outright
(rc 32). So the rule is "own namespace, or a mount that cannot happen at all".
`scripts/unit-check.sh` is what actually enforces the list; the comment is not
the gate.

The instance name is a volume name, so it is already constrained to a DNS-1123
label — lowercase letters, digits and hyphens. It cannot contain a `/`, and
`systemd-escape --path` refuses any path that still contains `..` after
simplification, so there is no escaping trick that turns an instance name into a
path traversal out of `/etc/granary/mounts/`.

**Stopping, and why not to shortcut it.** The unit deliberately sets no
`TimeoutStopSec=`, so systemd's default of 90 s applies. That is not
carelessness: closing the cache flushes and may COMPACT synchronously, and a bound
chosen below that cost turns a slow-but-correct close into a SIGKILL — which
leaves precisely the disconnected mount the recovery section below exists for. So
a `systemctl stop` that takes tens of seconds is doing its job. **Do not
`kill -9` it at thirty seconds; that is how the wedge gets manufactured.** If you
need a bound for automation, set one that exceeds your own measured worst-case
close, and raise it rather than lowering it.

To relocate the binary, drop in
`/etc/systemd/system/gran-mount@.service.d/10-path.conf` with an empty
`ExecStart=` followed by your own `ExecStart=…`, then `systemctl daemon-reload`.

`Restart=` stays `no` on purpose: a daemon killed after the stop timeout leaves a
disconnected mount at the mountpoint, and the next start refuses while that row
exists, so restarting would only flap.

## Recovering a wedged mount

Symptoms: reads hang; or they fail with `Transport endpoint is not connected`; or
removing the mountpoint entry fails with `EBUSY`.

**Put every probe under a bound.** The first instinct at a wedged mount is to `ls`
it, and that hangs — a task blocked in a FUSE request is in a killable wait, so
plain `timeout` will signal and then wait forever for a child that ignores it. Use
`timeout -k 5 30 …`, and read the mount TABLE (`findmnt`) rather than `stat`ting
the path: a table read never blocks, and it is also the only probe that can tell
"mounted but disconnected" from "not mounted".

1. `systemctl stop gran-mount@<volume>` (or send `SIGTERM` to the daemon — a
   writable mount runs its shutdown first; then it unmounts itself and exits by
   the table in "Stopping a writable mount").
2. Verify: `findmnt -rn -o SOURCE,FSTYPE --mountpoint <mountpoint>`. Empty output
   means it is gone.
3. If a row survives, `sudo gran umount <mountpoint>`. This is a *different*
   process from the one serving the mount: for the owner it requests and waits
   for the daemon’s full result. Cross-uid root detaches only. An absent/dead/legacy
   endpoint permits verified detach but returns 1, outcome unavailable. It refuses
   a path that is not a granary mount.
4. `umount -l <mountpoint>` is the last resort, and the reason it is last is that
   it attests nothing: it can return success having detached nothing at all.
5. `systemctl reset-failed gran-mount@<volume>` before starting again.

**Exit code 3** means the filesystem was unmounted cleanly but the cache could not
be closed. The mount is gone and no lock is stranded — the writer lock is an
`flock` the kernel releases when the process exits. What survives an unclean close
is the **`guard` file**, which is removed only by a clean close, so the next open
on that directory warns `cache guard present at open: the previous writer did not
close cleanly`. Treat that as a real signal: a close that failed may also have
lost journal records, in which case the next open rebuilds from the snapshot and
the reads since the last compaction are simply gone. Nothing is corrupt; some
cached objects will just be refetched.

**Exit code 4** means a writable mount's shutdown stopped at its bound, or at a
signal after the first stop request, before it finished. Nothing was lost: the overlay,
the staging files and the writer intent are kept in the store the status line
names. Preserve that store; do not remove it or switch to another. The next mount
with this store can finish interrupted non-fenced shutdown before serving; fenced
or damaged state requires explicit recovery, as in the refusal table above. A
successful settlement action alone does not complete that recovery; require its
final exit and `JournalFinished` before starting the writable mount. To make the
next stop finish, give it more time: a larger
`--shutdown-bound`, and under systemd a `TimeoutStopSec=` above it.

**Exit code 5** means the mount was fenced: the authority refused its ownership
or its commit. The overlay is kept in the store the status line names; preserve it. Recovery is
explicit: stop the displaced instance and inspect the store, and do not take over
automatically, as for `IntentFenced` in the refusal table.

### If a mount refuses to start with `StaleHead`

The refusal names which floor blocked it — mount-private, shared, or the
manifest-root one — so read the message before doing anything.

**The order matters and it is not symmetric: remove the offending root from the
STORE first, then clear the floor.** Clearing the floor while a root with an
inflated sequence number is still in the store lets the mount succeed and then
re-poison the floor the instant that root is served again.

Removing it is a **store-side, operator action, not a `gran` verb** — the read
protocol has no delete (the server answers `405` to `DELETE`), so it is done
wherever the volume's roots actually live: through your object store's own
console or client. If you cannot do that, you cannot complete this recovery, and
clearing the floor first will only postpone it.

`--reset-floor` then clears **only** the mount-private floor at
`anchors/<volume>.mount` inside the cache directory, and nothing else. Under the
systemd unit the only way to pass it is `GRAN_MOUNT_EXTRA=--reset-floor` in the
env file — **for one start, and then remove it again.** Left in place it disarms
the rollback defence on every subsequent restart, which is the opposite of what
you wanted. Clearing the shared floor at `anchors/<volume>` is a separate and
more dangerous action; `--reset-floor` does not clear it.

**`--seq` is the other route out, and it is a legitimate one** — but know which
question you are answering. An explicit `--seq` is deliberately exempt from the
floor, so it mounts a root you have NAMED rather than one the store claimed was
the head. That is the designed escape hatch from a poisoned floor, and it is why
the floor was never bound to it. What it does NOT do is remove the poison: the
floor is still raised, and the next discovery-driven mount will still refuse. Use
`--seq` to get a working mount NOW; use the store-side removal plus
`--reset-floor` to actually fix it.

### If a mount refuses to start with `NoHead`

Publish once first. An initialised authority volume with no published head
does not supply an empty snapshot: the mount needs an existing root whose
signature and complete structure can be checked before it serves requests.

## What a mount does not do

- **No backgrounding.** `--foreground` is required; there is no pidfile and no
  log-redirection contract, so a supervisor holds the mount or nothing does.
- **`mount.gran` exists but fstab cannot use it yet**, and it is not
  installed: `/sbin/mount.gran` is a symlink to `gran` that you create.
  It translates `-o` options into the same daemon — `endpoint=`, `pin=`,
  `root_key=`, `manifest_root=`, `cache_dir=`, `seq=`, `uid=`, `gid=`,
  and the valueless `allow_other`, `foreground`, `reset_floor`, `force`.
  **`trust_server` and `manifest_root` are REFUSED on this entry point**
  (it is machine-wide, so publisher authentication with `--root-key`
  is required), and `foreground` is REQUIRED rather than optional. Both
  halves matter for fstab: the daemon refuses without `foreground`, and
  with it `mount -t gran` blocks.
- **No passthrough.** Registering a backing file descriptor needs `CAP_SYS_ADMIN`,
  which is exactly what an unprivileged mount does not have, so `gran mount`
  implements none: every read is served through the ordinary userspace path.
- **No `sd_notify` readiness.** The unit cannot tell systemd the mount is up; poll
  for it as above.
- **No writes, and no live snapshot following, on a read-only mount.** A
  read-only mount is pinned to the root it resolved at mount time.
