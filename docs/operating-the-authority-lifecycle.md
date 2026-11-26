<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Operating the authority lifecycle

Run these local commands as the state directory's owner or as root, with the
server stopped. They require no server configuration, publisher keys or store
access. They are not wire operations.

Provision the state directory before using either command:

```sh
install -d -o granary -g granary -m 0700 /var/lib/granary/authority
sudo -u granary granary-server initialise \
  --state-dir /var/lib/granary/authority --volume software
```

`--state-dir` must be absolute. The descriptor walk refuses symbolic links,
untrusted writable ancestors, incorrect ownership and a state directory with
any group or other access. The command holds the same exclusive, nonblocking
lock as the server for the whole operation. Stop the server before retrying a
lock refusal. The walk checks filesystem types: ext2/3/4, xfs and btrfs for the
state directory; overlay and tmpfs are allowed only for ancestors. Both commands
accept `--accept-unsupported-filesystem`, which lifts only type refusals. macOS
has no type table and needs this acknowledgement for development; both commands'
production boot readers require Linux. Deploy on a supported local filesystem
with Linux 4.13 or later so the authority can observe writeback errors on the
open log.

Initialise removes only the volume's exact leftover temporary, then reads and
classifies its log. A missing log creates a durable envelope with a new epoch
from operating-system randomness. An envelope without committed records keeps
its epoch, truncates an incomplete tail and completes the namespace barrier.
Committed records, a damaged file, a file without a complete envelope, an
unreadable log, failed temporary removal or unavailable entropy refuse. Creation
links the temporary without replacing any existing name, even if that name
appeared after the read. Initialise runs under the run marker as a server start
does. It refuses the rows startup refuses before writing anything: an unreadable
or malformed marker, running in this boot, or no marker with an occupied state
directory. It makes running under the current boot id durable before its first
change, including temporary removal. When it ends without uncertain publishing
I/O it writes clean, including on a refusal after that point (exit 65, marker clean).
A failed or uncertain publishing call writes nothing further (exit 74). It
usually leaves the marker running in this boot, so a same-boot server start
refuses. Two failures leave a marker the startup table admits: the running
write's temporary failing its sync (the marker keeps its earlier value), and the
final clean write's directory sync failing after its rename (the marker reads
clean). After exit 74, reboot the host before starting the server whatever the
marker reads, and unfence if the start then refuses; a start without the reboot
is outside the contract. A fresh directory initialised successfully by this
command therefore starts.

Success is one line: `created software <epoch>` or `kept software <epoch>`, where
`<epoch>` is 32 lowercase hexadecimal digits. Re-initialise after log loss begins
only after the operator removes the lost log's name. A re-initialise cancels
nothing at the store: a PUT the old epoch issued can still land.

A fence requires a **host kernel reboot**. A process restart, container or VM
restart retaining that kernel, remount or successful re-sync does not clear it.
After reboot, while the server remains stopped:

```sh
sudo -u granary granary-server unfence --state-dir /var/lib/granary/authority
```

Unfence refuses a marker that says running in this boot, whatever the times
say. It then requires every regular file's mtime and ctime and every directory's
ctime under the state directory, including the state directory itself, to be
strictly before the host kernel's boot start. It reads `/proc/stat`'s `btime` and checks
that the kernel boot identity is stable across the read; the proc mount must
represent the kernel whose page cache holds the state files. A missing or
malformed marker does not bypass the time check. An unreadable entry, symbolic
link or other nonregular entry refuses. On success it durably publishes a
`clean` marker and prints `clean`; it does not repair damaged log contents.

A same-boot chmod or chown changes file or directory ctime and defers unfence
until a later host reboot. A clock stepped back across a reboot can make the
check pass early; correct host clock operation is the operator's responsibility.
Except for the manual pair restoration below, deleting or editing files in the
state directory by hand is outside this contract;
unfence is the repair for a fenced marker.

Command exit codes are **0** (completed), **64** (usage), **65** (refused without
uncertain publishing I/O), and **74** (I/O once a publishing log or marker mutation begins, or
failed success output). A failed sync inside a mutation is uncertain: inspect
the state and follow the reboot/unfence procedure before retrying. A marker
write and temporary removal can have happened even when the later operation
refuses. These are local command codes; the running server's fence exit is **4**. Supervisors must not
restart that exit automatically; use `RestartPreventExitStatus=4` in systemd.

The Linux acceptance venue uses ext4 and syscall traces. Its successful unfence
uses the injectable boot-start reader with constructed times. It performs no
real host reboot and proves no real reboot occurred. After initialise it checks
that the marker reads clean, which admits the startup marker table; it does not
launch a server in this lane.

## Intent state

Each volume's `<volume>.intent` and `<volume>.intent.tmp` live beside its log,
under the same marker, directory lock and fence. A missing, corrupt,
unprovisioned or epoch-mismatched store returns `503 unavailable` for intent
requests. Restore an existing log and its matching intent store together
using [manual restoration](#manual-restoration).

Configuration does not initialise a volume. Before intent availability, stop the
host and run explicit `granary-server initialise` under the directory lock and
marker rules above. Creation installs and syncs the intent snapshot before
publishing the log; an existing snapshot is validated and rebound while preserving
all allocator, row, exact root and saved-grant state. Startup and minute maintenance
create neither file for a volume without a log and leave orphan snapshots unchanged.
An interrupted initialise stays unavailable until explicit completion. Keeping an
existing log does not create missing allocator state or repair a mismatched pair.
Readiness may proceed while intent service is unavailable; maintenance continues
for healthy volumes. Uninitialised volumes are skipped, with one info event per
volume when entering that state; they do not warn every minute. Each real failure
reports its volume and token, including when several volumes fail in one pass.
Enrollment failures are reported for the whole pass. Publication and status keep their
no-log behaviour. A mutation or sync failure stays fenced for the boot.

Allow 16 live rows, 64 total rows and 1,048,576 live root bytes per principal/volume.
Released rows retain state for max(collector grace, 86,400 seconds) without a
successful mutation. Allocator blocks retain 64 bytes per lifetime principal forever,
including retired principals with no rows. Plan disk capacity using historical
principal count; every snapshot replacement writes retained volume state.
Damage needs manual resolution with trustworthy non-regressing allocator state;
unknown high-water values require continued refusal. No collector runs against
live intents yet.

### Manual restoration

There is no binding-recovery command. An existing log with a missing, corrupt or
mismatched snapshot keeps answering `503 unavailable` until a trustworthy pair is
restored. `initialise` keeps that log and cannot repair the pair; `unfence` only
repairs the marker. Do not remove a present log to bypass this refusal.

1. Stop the server and disable automatic restart. Hold an exclusive `flock` on a
   descriptor for the protected state directory itself for the entire restoration; ensure no server or local
   lifecycle command can acquire its directory lock while files are being restored.
2. Preserve the refused log, snapshot, temporaries and marker as evidence outside
   the serving directory. Record their volume and epochs before replacing anything.
3. Establish a complete, validated log/snapshot pair for the same volume and epoch
   from trustworthy recovery material. Prove every lifetime principal's H is at
   least its highest previously issued value, including retired and zero-row
   principals, and preserve all rows, exact roots and saved grants. A matching epoch
   or an old backup alone does not prove this. If that proof or either member is
   unavailable, leave the volume refused; do not invent H=0, edit epochs or promote
   a temporary.
4. Restore both complete files while custody is held, retaining the protected
   ownership and file modes. Sync both files and the state directory with the
   restoration tooling before releasing custody. Preserve the run marker and its
   fence history; restoring a pair does not clear a fence.
5. If fenced or publishing durability was uncertain, reboot the host kernel after
   the final restoration write, then follow the `unfence` procedure above while
   the server remains stopped. Restored files' ctimes must precede that boot.
6. Start with the configured publisher keys. Startup must validate the complete
   pair, authenticate retained roots and grants, and complete durability barriers
   before serving intents. Confirm intent readback succeeds and retains the proven
   high-water values. If validation refuses, stop and retain the evidence; do not
   retry by resetting allocator state.

## Intent observability

Intent transactions emit `op.begin`, `op.end` and, on refusal or failure,
`op.failed`. Request transactions retain the validated wire request id in their
span. Outcomes are `ok` or `failed`; failure classes are `io`, `refused`,
`conflict`, `unavailable`, `corrupt` or `internal`. The closed server kind set is:

| kind | operation |
|---|---|
| `intent_register` | register or refresh |
| `intent_release` | release |
| `intent_ownership` | acquire or conditional takeover |
| `intent_readback` | principal-scoped control read |
| `intent_store` | explicit initialise snapshot installation, enrollment/retention maintenance and root visits |
