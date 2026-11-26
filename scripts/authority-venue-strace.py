#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Check a syscall trace of the authority log adapter's or the enrollment
verbs' venue runs.

Reads an `strace -f -y` log of one process of
`authority::file_log::tests::venue` (scripts/authority-venue.sh writes it)
and verifies that the authority calls complete the write and sync sequence
listed below.

  first, restart  each log opened through one description; every write to a
                  log synced through it before the log's next write and
                  before the run ends; a log's name linked only after its
                  file's sync, and the state directory synced after the
                  link before the log's next write; the marker's temporary
                  synced before its rename, and the state directory synced
                  after the rename before any log write; every sync
                  succeeded; and the counts that show the run did the work.
  failed          the first failed sync is followed by no mutating call at
                  all: the sync is never retried.
  lifecycle       initialise then unfence with constructed boot times; checks
                  exclusive creation, write, file sync, link/rename, temporary
                  unlink for initialise, state sync, anchor sync and return.
  enrollment      `enrollment::tests::venue`'s traced workload, a first mint
                  then a revoke, with STATE_DIR the enrollment directory:
                  each verb creates ENROLLMENT.tmp with O_CREAT|O_EXCL,
                  writes it, syncs it, renames it over ENROLLMENT, syncs the
                  directory, and (the first mint only, the file missing)
                  then syncs the directory's parent; and returns only after
                  (the run marks each return by creating
                  `enroll-returned-<verb>` in its control directory).
                  ENROLLMENT is never written in place; every sync
                  succeeded. Only calls on the directory, its files and its
                  parent are counted.

A name an `*at` call gives relative to a directory descriptor (the
adapter's and the verbs' calls on their held directories) is read as that
descriptor's path joined with the name, so it is checked as the absolute
path the call reached.

Usage: authority-venue-strace.py MODE STATE_DIR TRACE
Exit 0 when every check holds, 1 with each failure named, 2 on bad usage.
"""

import re
import sys

LINE = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+(\w+)\((.*)\)\s+=\s+(-?\d+)(?:<([^>]*)>)?(?:\s+(E[A-Z]+))?")
FD = re.compile(r"^(-?\d+|AT_FDCWD)<([^>]*)>")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
# A quoted name with the directory descriptor before it, if any.
AT_NAME = re.compile(r'(?:(-?\d+|AT_FDCWD)(?:<([^>]*)>)?, )?"((?:[^"\\]|\\.)*)"')
# The calls whose names are relative to a directory descriptor.
AT_CALLS = {"openat", "linkat", "renameat", "renameat2", "unlinkat", "mkdirat"}
SYNCS = {"fsync", "fdatasync"}
# The plain calls glibc issues where the architecture has them (x86_64),
# read as the *at forms they stand for: their path arguments are the same
# quoted strings.
PLAIN = {"open": "openat", "creat": "openat", "rename": "renameat", "link": "linkat",
         "unlink": "unlinkat", "mkdir": "mkdirat"}
MUTATING = SYNCS | {
    "pwrite64", "pwritev", "pwritev2", "write", "writev", "ftruncate", "truncate",
    "renameat", "renameat2", "linkat", "unlinkat", "mkdirat",
}


def parse(path):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            if "<unfinished" in raw or "resumed>" in raw:
                sys.exit(f"{path}: a split call; run the traced binary with --test-threads=1: {raw.strip()}")
            m = LINE.match(raw.strip())
            if not m:
                continue
            _, name, args, ret, ret_path, errno = m.groups()
            creat = "O_CREAT" in args or name == "creat"
            name = PLAIN.get(name, name)
            fd = FD.match(args)
            events.append({
                "name": name,
                "fd_path": clean(fd.group(2)) if fd and fd.group(1) != "AT_FDCWD" else None,
                "paths": names(name, args),
                "ret": int(ret),
                "ret_path": clean(ret_path) if ret_path else None,
                "errno": errno,
                "creat": creat,
                "raw": raw.strip(),
            })
    return events


def names(name, args):
    """The absolute paths a call names: its absolute quoted strings, and
    for an *at call each relative name joined to its descriptor's path."""
    if name not in AT_CALLS:
        return [clean(p) for p in QUOTED.findall(args) if p.startswith("/")]
    out = []
    for fdnum, fdpath, p in AT_NAME.findall(args):
        if p.startswith("/"):
            out.append(clean(p))
        elif fdpath and fdnum != "AT_FDCWD":
            out.append(f"{clean(fdpath)}/{p}")
    return out


def clean(p):
    return p[: -len(" (deleted)")] if p.endswith(" (deleted)") else p


def log_of(path, state):
    """The log a path is: `<state>/<volume>.log`, or its initialise
    temporary, which is the same file once linked. None for anything else."""
    if path is None or not path.startswith(state + "/"):
        return None
    name = path[len(state) + 1 :]
    if "/" in name:
        return None
    if name.endswith(".log.tmp"):
        return name[: -len(".tmp")]
    if name.endswith(".log"):
        return name
    return None


def check_run(events, state, mode):
    fail = []
    anchor = state.rsplit("/", 1)[0]
    marker, marker_tmp = f"{state}/MARKER", f"{state}/MARKER.tmp"
    opens = {}
    pending = {}  # log -> index of its write not yet synced
    link_owed = {}  # log -> index of its link not yet followed by a state-directory sync
    marker_owed = None  # index of a marker rename not yet followed by a state-directory sync
    marker_tmp_pending = None
    counts = {"log_sync": 0, "link": 0, "marker_rename": 0, "state_sync": 0, "anchor_sync": 0}
    for i, e in enumerate(events):
        name = e["name"]
        target = e["fd_path"]
        log = log_of(target, state)
        if name == "openat" and e["ret"] >= 0:
            opened = log_of(e["ret_path"] or (e["paths"][0] if e["paths"] else None), state)
            if opened:
                opens[opened] = opens.get(opened, 0) + 1
        if name in SYNCS:
            if e["ret"] != 0:
                fail.append(f"a sync failed in a {mode} run: {e['raw']}")
            if log:
                pending.pop(log, None)
                counts["log_sync"] += 1
            elif target == marker_tmp:
                marker_tmp_pending = None
            elif target == state:
                counts["state_sync"] += 1
                link_owed.clear()
                marker_owed = None
            elif target == anchor:
                counts["anchor_sync"] += 1
        if name.startswith("pwrite") or name in ("write", "writev"):
            if log:
                if log in pending:
                    fail.append(f"{log}: written again at {i} before the write at {pending[log]} was synced")
                if log in link_owed:
                    fail.append(f"{log}: written at {i} before the state directory's sync after its link at {link_owed[log]}")
                if marker_owed is not None:
                    fail.append(f"{log}: written at {i} before the state directory's sync after the marker's rename at {marker_owed}")
                pending[log] = i
            elif target == marker_tmp:
                marker_tmp_pending = i
        if name == "linkat" and e["ret"] == 0 and len(e["paths"]) == 2:
            linked = log_of(e["paths"][1], state)
            if linked:
                counts["link"] += 1
                if linked in pending:
                    fail.append(f"{linked}: linked at {i} before its write at {pending[linked]} was synced")
                link_owed[linked] = i
        if name in ("renameat", "renameat2") and e["ret"] == 0 and e["paths"][-1:] == [marker]:
            counts["marker_rename"] += 1
            if marker_tmp_pending is not None:
                fail.append(f"MARKER renamed at {i} before its temporary's write at {marker_tmp_pending} was synced")
            marker_owed = i
    for log, at in pending.items():
        fail.append(f"{log}: its write at {at} was never synced")
    for log, at in link_owed.items():
        fail.append(f"{log}: its link at {at} was never followed by the state directory's sync")
    if marker_owed is not None:
        fail.append(f"the marker's rename at {marker_owed} was never followed by the state directory's sync")
    for log, n in sorted(opens.items()):
        if n != 1:
            fail.append(f"{log}: opened {n} times; one description per log")
    logs = {"vol-a.log", "vol-b.log"}
    if set(opens) != logs:
        fail.append(f"logs opened: {sorted(opens)}; expected {sorted(logs)}")
    need = {
        "first": {"link": 2, "marker_rename": 2, "log_sync": 8, "state_sync": 3, "anchor_sync": 1},
        # vol-a holds records and is re-synced; vol-b holds only its
        # envelope, which recovery completes by namespace (the state
        # directory's and the anchor's syncs), not by a re-sync.
        "restart": {"marker_rename": 2, "log_sync": 1, "state_sync": 3, "anchor_sync": 1},
    }[mode]
    for k, n in need.items():
        if counts[k] < n:
            fail.append(f"{k}: {counts[k]} seen, at least {n} expected: the run did not do the work")
    return fail, counts


def touches(e, state):
    """Whether a call acts on the state directory, its files or its anchor
    (not the test harness's own output, which the trace also holds)."""
    anchor = state.rsplit("/", 1)[0]
    for p in [e["fd_path"], *e["paths"]]:
        if p is not None and (p == anchor or p.startswith(anchor + "/")):
            return True
    return False


def check_failed(events, state):
    fail = []
    first = next((i for i, e in enumerate(events) if e["name"] in SYNCS and e["ret"] != 0), None)
    if first is None:
        return ["no sync failed: the device was never failed"], {}
    if events[first]["errno"] != "EIO":
        fail.append(f"the failed sync's error is {events[first]['errno']}, not EIO: {events[first]['raw']}")
    after = [
        e["raw"]
        for e in events[first + 1 :]
        if (e["name"] in MUTATING or (e["name"] == "openat" and e["creat"])) and touches(e, state)
    ]
    if after:
        fail.append("calls after the failed sync:\n    " + "\n    ".join(after))
    return fail, {"failed_sync_at": first, "calls_after": len(after)}


RENAME = re.compile(r'^(-?\d+|AT_FDCWD)(?:<([^>]*)>)?, "((?:[^"\\]|\\.)*)", (-?\d+|AT_FDCWD)(?:<([^>]*)>)?, "((?:[^"\\]|\\.)*)"')
RETURNED = "enroll-returned-"
# The workload's verbs in order, and whether each found the file missing.
ENROLL_VERBS = [("mint", True), ("revoke", False)]


def check_enrollment(events, d):
    """The write order of each verb (module docs), verb by verb."""
    fail = []
    parent = d.rsplit("/", 1)[0]
    tmp, final = f"{d}/ENROLLMENT.tmp", f"{d}/ENROLLMENT"
    shown = []
    verbs = iter(ENROLL_VERBS)

    def fresh():
        return {"open": None, "written": None, "synced": None, "renamed": None,
                "dir_synced": None, "parent_synced": None}

    seg = fresh()
    done = []
    for i, e in enumerate(events):
        name, target, raw = e["name"], e["fd_path"], e["raw"]
        ret_path = e["ret_path"]
        if name == "openat" and e["creat"] and e["ret"] >= 0 and any(p.rsplit("/", 1)[-1].startswith(RETURNED) for p in e["paths"]):
            verb = next(p for p in e["paths"] if p.rsplit("/", 1)[-1].startswith(RETURNED)).rsplit("/", 1)[-1][len(RETURNED):]
            shown.append(f"{i:5} RETURNED {verb}")
            expected = next(verbs, None)
            if expected is None or expected[0] != verb:
                fail.append(f"verb {verb} returned at {i}; expected {expected}")
                seg = fresh()
                continue
            first = expected[1]
            if seg["renamed"] is None:
                fail.append(f"{verb}: returned at {i} with no rename of ENROLLMENT.tmp over ENROLLMENT")
            if seg["dir_synced"] is None:
                fail.append(f"{verb}: returned at {i} before the enrollment directory's sync")
            if first and seg["parent_synced"] is None:
                fail.append(f"{verb}: the file was missing, and it returned at {i} before the parent's sync")
            if not first and seg["parent_synced"] is not None:
                fail.append(f"{verb}: the file existed, yet the parent was synced at {seg['parent_synced']}")
            done.append(verb)
            seg = fresh()
            continue
        on = [p for p in [target, ret_path, *e["paths"]] if p is not None]
        if not any(p == d or p == parent or p.startswith(d + "/") for p in on):
            continue
        if name == "openat" and e["ret"] >= 0 and ret_path == tmp:
            shown.append(f"{i:5} {raw}")
            if "O_CREAT" not in raw or "O_EXCL" not in raw:
                fail.append(f"ENROLLMENT.tmp opened at {i} without O_CREAT|O_EXCL: {raw}")
            if seg["open"] is not None:
                fail.append(f"ENROLLMENT.tmp created twice in one verb, at {seg['open']} and {i}")
            seg["open"] = i
        elif name == "openat" and e["ret"] >= 0 and ret_path == final and ("O_WRONLY" in raw or "O_RDWR" in raw):
            fail.append(f"ENROLLMENT opened for writing at {i}: {raw}")
        elif name.startswith("pwrite") or name in ("write", "writev", "ftruncate", "truncate"):
            # truncate(2) names its file by path; the others by descriptor.
            if name == "truncate":
                target = e["paths"][0] if e["paths"] else None
            if target == tmp:
                shown.append(f"{i:5} {raw[:120]}")
                if seg["open"] is None:
                    fail.append(f"ENROLLMENT.tmp written at {i} before its O_EXCL creation")
                seg["written"] = i
                seg["synced"] = None
            elif target == final:
                fail.append(f"ENROLLMENT written in place at {i}: {raw}")
        elif name in SYNCS:
            shown.append(f"{i:5} {raw}")
            if e["ret"] != 0:
                fail.append(f"a sync failed at {i}: {raw}")
            if target == tmp:
                if seg["written"] is None:
                    fail.append(f"ENROLLMENT.tmp synced at {i} before anything was written")
                seg["synced"] = i
            elif target == d:
                if seg["renamed"] is None:
                    fail.append(f"the enrollment directory synced at {i} before the rename")
                else:
                    seg["dir_synced"] = i
            elif target == parent:
                if seg["renamed"] is not None:
                    if seg["dir_synced"] is None:
                        fail.append(f"the parent synced at {i} before the enrollment directory's sync")
                    seg["parent_synced"] = i
        elif name in ("renameat", "renameat2") and e["ret"] == 0:
            m = RENAME.match(raw[raw.index("(") + 1:])
            if not m:
                fail.append(f"a rename at {i} the checker cannot read: {raw}")
                continue
            def at(dirfd, path):
                # An absolute path ignores its directory descriptor (AT_FDCWD
                # or any other).
                return path if path.startswith("/") else f"{clean(dirfd or '')}/{path}"
            old = at(m.group(2), m.group(3))
            new = at(m.group(5), m.group(6))
            if new == final:
                shown.append(f"{i:5} {raw}")
                if old != tmp:
                    fail.append(f"ENROLLMENT replaced at {i} from {old}, not its temporary")
                if seg["synced"] is None:
                    fail.append(f"ENROLLMENT.tmp renamed at {i} before its write at {seg['written']} was synced")
                if seg["dir_synced"] is not None or seg["renamed"] is not None:
                    fail.append(f"a second rename over ENROLLMENT in one verb, at {i}")
                seg["renamed"] = i
    left = [v for v, _ in verbs]
    if left:
        fail.append(f"verbs that never returned: {left}")
    if seg["renamed"] is not None:
        fail.append(f"a rename at {seg['renamed']} after the last verb returned")
    print("\n".join(shown))
    return fail, {"verbs_returned": done}


def check_lifecycle(events, state):
    """Check running, intent, envelope, clean, then unfence at observed returns."""
    fail = []
    parent = state.rsplit("/", 1)[0]
    marker_tmp, marker = f"{state}/MARKER.tmp", f"{state}/MARKER"
    intent_tmp, intent = f"{state}/vol-a.intent.tmp", f"{state}/vol-a.intent"
    log_tmp, log = f"{state}/vol-a.log.tmp", f"{state}/vol-a.log"
    marker_stages = ["create", "write", "file-sync", "publish", "state-sync"]
    log_stages = marker_stages[:4] + ["unlink", "state-sync", "anchor-sync"]
    returned = []
    start = 0
    for verb in ("initialise", "unfence"):
        end = next((i for i in range(start, len(events))
                    if events[i]["name"] == "openat" and events[i]["creat"]
                    and events[i]["ret"] >= 0
                    and f"/control/lifecycle-returned-{verb}" in events[i]["paths"]), None)
        if end is None:
            fail.append(f"{verb}: no observed return")
            continue
        running_stages = marker_stages + ["anchor-sync"]
        intent_cleanup = any(
            e["name"] == "unlinkat" and e["paths"] == [intent_tmp]
            for e in events[start:end]
        )
        intent_stages = (["unlink", "state-sync"] if intent_cleanup else []) + marker_stages
        publications = [("running", running_stages),
                        ("intent", intent_stages),
                        ("log", log_stages),
                        ("clean", marker_stages)] if verb == "initialise" else [("clean", marker_stages)]
        stages = [f"{role}:{stage}" for role, parts in publications for stage in parts]
        seen = []
        active = None
        marker_creates = 0
        running_durable = False
        for e in events[start:end]:
            name, target = e["name"], e["fd_path"]
            stage = None
            if verb == "initialise" and not running_durable:
                if target in (log_tmp, log) or any(p in (log_tmp, log) for p in e["paths"]):
                    fail.append("initialise: log call before durable running marker")
                if target in (intent_tmp, intent) or any(p in (intent_tmp, intent) for p in e["paths"]):
                    fail.append("initialise: intent call before durable running marker")
            if name == "openat" and e["ret_path"] in (marker_tmp, intent_tmp, log_tmp):
                if e["ret_path"] == marker_tmp:
                    marker_creates += 1
                    active = "running" if verb == "initialise" and marker_creates == 1 else "clean"
                elif e["ret_path"] == intent_tmp:
                    active = "intent"
                else:
                    active = "log"
                if "O_CREAT" not in e["raw"] or "O_EXCL" not in e["raw"]:
                    fail.append(f"{verb}: temporary creation lacks O_CREAT|O_EXCL")
                stage = "create"
            elif (name.startswith("pwrite") or name in ("write", "writev")) and target in (marker_tmp, intent_tmp, log_tmp):
                stage = "write"
            elif name in SYNCS and target in (marker_tmp, intent_tmp, log_tmp, state, parent):
                stage = {marker_tmp: "file-sync", intent_tmp: "file-sync", log_tmp: "file-sync",
                         state: "state-sync", parent: "anchor-sync"}[target]
                if active == "running" and target == parent and e["ret"] >= 0:
                    running_durable = True
            elif name in ("linkat", "renameat", "renameat2") and e["paths"][-1:] in ([marker], [intent], [log]):
                if active == "log":
                    tmp, final, publish = log_tmp, log, ("linkat",)
                elif active == "intent":
                    tmp, final, publish = intent_tmp, intent, ("renameat", "renameat2")
                else:
                    tmp, final, publish = marker_tmp, marker, ("renameat", "renameat2")
                if name not in publish or e["paths"] != [tmp, final]:
                    fail.append(f"{verb}: wrong publication operation or source")
                if f"{active}:file-sync" not in seen:
                    op = "linked" if active == "log" else "renamed"
                    fail.append(f"{verb}: {active} {op} before its temporary was synced")
                stage = "publish"
            elif name == "unlinkat":
                if e["paths"] == [log_tmp] and "log:publish" in seen:
                    stage = "unlink"
                elif e["paths"] == [intent_tmp] and "intent:create" not in seen:
                    active = "intent"
                    stage = "unlink"
            if stage is not None:
                expected_tmp = log_tmp if active == "log" else (intent_tmp if active == "intent" else marker_tmp)
                if stage in ("write", "file-sync") and target != expected_tmp:
                    fail.append(f"{verb}: {stage} targets the wrong temporary")
                if e["ret"] < 0:
                    fail.append(f"{verb}: failed {stage}")
                # Short writes may repeat, but never across a sync or publication.
                labelled = f"{active}:{stage}"
                if stage == "write" and seen[-1:] == [labelled]:
                    continue
                seen.append(labelled)
        if seen != stages:
            fail.append(f"{verb}: publication sequence {seen}, expected {stages}")
        returned.append(verb)
        start = end + 1
    if returned != ["initialise", "unfence"]:
        fail.append("lifecycle: both verb identities must return")
    return fail, {"verbs_returned": len(returned)}


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("first", "restart", "failed", "enrollment", "lifecycle"):
        print(__doc__, file=sys.stderr)
        return 2
    mode, state, trace = sys.argv[1], sys.argv[2].rstrip("/"), sys.argv[3]
    try:
        events = parse(trace)
    except OSError as error:
        print(f"FAIL: trace could not be read: {error}")
        return 1
    if mode == "lifecycle":
        fail, counts = check_lifecycle(events, state)
    elif mode == "failed":
        fail, counts = check_failed(events, state)
    elif mode == "enrollment":
        fail, counts = check_enrollment(events, state)
    else:
        fail, counts = check_run(events, state, mode)
    print(f"strace {mode}: {len(events)} calls; {counts}")
    for f in fail:
        print(f"FAIL: {f}")
    print(f"strace {mode}: {'FAILED' if fail else 'OK'}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
