#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Refuse new server processes in a job's private checkout and temporary tree.

The baseline excludes processes predating the job. Runner workspaces and
RUNNER_TEMP must belong to one job at a time. No arguments or environment bytes
from inspected processes are read. SIGKILL bypasses fixture cleanup; this check
is a final backstop, provided the runner can still execute an always() step.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def proc_owner(pid):
    return os.stat(f"/proc/{pid}").st_uid


def snapshot(run=subprocess.run, readlink=os.readlink, owner=proc_owner):
    result = run(["ps", "-axo", "pid=,lstart=,stat=,comm="],
                 capture_output=True, text=True, check=True)
    rows = result.stdout.splitlines()
    if not rows:
        raise ValueError("empty process inventory")
    servers = []
    for row in rows:
        fields = row.split(None, 7)
        if len(fields) != 8 or not fields[0].isdigit():
            raise ValueError("malformed process inventory")
        pid, *_, status, executable = fields
        if status.startswith("Z"):
            continue
        if Path(executable).name != "granary-server":
            continue
        if sys.platform == "linux":
            try:
                executable = readlink(f"/proc/{pid}/exe")
            except FileNotFoundError:
                # A process may finish between ps and readlink. Permission and
                # other observation failures must refuse rather than omit it.
                if Path(f"/proc/{pid}").exists():
                    raise
                continue
            except PermissionError:
                # A job's servers run as the job's user; another user's server
                # is outside every root, and the kernel hides its executable.
                try:
                    foreign = owner(pid) != os.getuid()
                except FileNotFoundError:
                    continue  # exited after the readlink
                if foreign:
                    continue
                raise
            executable = executable.removesuffix(" (deleted)")
        elif Path(executable).is_absolute():
            # ps reports the spelling used at exec; roots are resolved, so a
            # symlinked component (macOS /var) must resolve here too.
            executable = os.path.realpath(executable)
        path = Path(executable)
        if not path.is_absolute():
            raise ValueError("server executable is not an absolute path")
        start = " ".join(fields[1:6])
        if sys.platform == "linux":
            try:
                stat = Path(f"/proc/{pid}/stat").read_text()
            except FileNotFoundError:
                continue
            values = stat.rsplit(")", 1)[-1].split()
            if len(values) < 20 or not values[19].isdigit():
                raise ValueError("malformed server process identity")
            start = "linux:" + values[19]
        servers.append({"pid": int(pid), "start": start, "executable": str(path)})
    return servers, len(rows)


def validate(state):
    if not isinstance(state, dict) or set(state) != {"version", "roots", "before", "observed"}:
        raise ValueError("invalid baseline fields")
    if state["version"] != 1 or type(state["observed"]) is not int or state["observed"] <= 0:
        raise ValueError("invalid baseline inventory count")
    roots = state["roots"]
    if not isinstance(roots, list) or not roots or any(
            not isinstance(root, str) or not Path(root).is_absolute() or Path(root) == Path("/")
            for root in roots):
        raise ValueError("invalid baseline roots")
    if not isinstance(state["before"], list):
        raise ValueError("invalid baseline identities")
    for row in state["before"]:
        if (not isinstance(row, dict) or set(row) != {"pid", "start", "executable"}
                or type(row["pid"]) is not int or row["pid"] <= 0
                or not isinstance(row["start"], str) or not row["start"].strip()
                or not isinstance(row["executable"], str)
                or not Path(row["executable"]).is_absolute()):
            raise ValueError("invalid baseline identity")
    return state


def survivors(state, current):
    validate(state)
    before = {(row["pid"], row["start"]) for row in state["before"]}
    return [row for row in current
            if (row["pid"], row["start"]) not in before
            and any(Path(row["executable"]).is_relative_to(root) for root in state["roots"])]


def begin(path, roots):
    current, count = snapshot()
    state = validate({"version": 1, "roots": [str(Path(root).resolve(strict=True)) for root in roots],
                      "before": current, "observed": count})
    with path.open("x", encoding="utf-8") as stream:
        json.dump(state, stream)
    print(f"SERVER-PROCESSES: baseline recorded; observed={count}")


def cleanup(leaked):
    if sys.platform != "linux" or not hasattr(signal, "pidfd_send_signal"):
        raise ValueError("safe survivor cleanup requires Linux pidfds")
    for row in leaked:
        try:
            fd = os.pidfd_open(row["pid"])
        except ProcessLookupError:
            continue
        try:
            # The descriptor pins the process. Recheck its full identity before
            # signalling so a recycled PID cannot select a foreign process.
            current, _ = snapshot()
            if row in current:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # exited after the recheck
        finally:
            os.close(fd)


def check(path, reap=False):
    state = validate(json.loads(path.read_text(encoding="utf-8")))
    current, count = snapshot()
    leaked = survivors(state, current)
    if leaked:
        if reap:
            cleanup(leaked)
        raise ValueError("granary-server survived this job: pids="
                         + ",".join(str(row["pid"]) for row in leaked)
                         + f"; observed={count}; leaks={len(leaked)}")
    print(f"SERVER-PROCESSES: clean; observed={count}; leaks=0")


def live_self_test():
    # Keep controls out of the scanner: it observes a real executable with the
    # shipping name, orphaned by a shell that exits before the check runs.
    import shutil
    import tempfile
    import time
    from unittest.mock import patch

    cases = 0
    with tempfile.TemporaryDirectory(prefix="granary-process-check-", dir=os.environ.get("RUNNER_TEMP")) as directory:
        root = Path(directory)
        binary = root / "granary-server"
        shutil.copyfile("/bin/sleep", binary)
        binary.chmod(0o700)
        if sys.platform == "darwin":
            # macOS kills a copied platform binary at exec; an ad-hoc
            # signature lets the fixture run under its new name.
            subprocess.run(["codesign", "--force", "--sign", "-", str(binary)],
                           capture_output=True, check=True)
        state_path = root / "baseline.json"
        begin(state_path, [root])
        command = [sys.executable, str(Path(__file__).resolve()), "check", "--state", str(state_path)]
        clean = subprocess.run(command, capture_output=True, text=True, check=False)
        if clean.returncode != 0 or "leaks=0" not in clean.stdout or "observed=" not in clean.stdout:
            raise ValueError(f"clean CLI control failed: {clean}")
        print(clean.stdout.strip())
        cases += 1
        shell = subprocess.run(["/bin/sh", "-c", '"$1" 30 </dev/null >/dev/null 2>&1 & echo $!',
                                "fixture", str(binary)], capture_output=True, text=True, check=True)
        pid = int(shell.stdout.strip())
        planted_row = None

        def planted_alive():
            return planted_row is not None and planted_row in snapshot()[0]

        try:
            deadline = time.monotonic() + 2
            while True:
                current, _ = snapshot()
                planted_row = next((row for row in current if row["pid"] == pid), None)
                if planted_row is not None:
                    break
                if time.monotonic() >= deadline:
                    raise ValueError(f"planted server absent: pid={pid}, inventory={current}")
                time.sleep(0.01)
            planted = subprocess.run(command, capture_output=True, text=True, check=False)
            if (planted.returncode != 1 or "granary-server survived this job:" not in planted.stderr
                    or "leaks=1" not in planted.stderr):
                raise ValueError(f"planted orphan did not fail the CLI: {planted}")
            print(f"CONTROL planted orphan: rc={planted.returncode} {planted.stderr.strip()}")
            cases += 1
            if sys.platform == "linux":
                reaped = subprocess.run(command + ["--cleanup"], capture_output=True, text=True, check=False)
                if reaped.returncode != 1 or "granary-server survived this job:" not in reaped.stderr:
                    raise ValueError(f"cleanup concealed orphan failure: {reaped}")
                deadline = time.monotonic() + 2
                while planted_alive():
                    if time.monotonic() >= deadline:
                        raise ValueError("cleanup did not kill the planted orphan")
                    time.sleep(0.01)
                print("CONTROL cleanup: refused the planted orphan after signalling it through a pidfd")
                cases += 1
            state = json.loads(state_path.read_text())
            state["before"] = current
            if survivors(state, current):
                raise ValueError("preexisting process was attributed to this job")
            state["before"] = []
            state["roots"] = [str(root / "other-job")]
            if survivors(state, current):
                raise ValueError("foreign workspace process was attributed to this job")
            cases += 2
        finally:
            # Signal the raw PID only while it still carries the planted
            # identity: after cleanup it may already belong to another process.
            if planted_alive():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + 2
        while planted_alive():
            if time.monotonic() >= deadline:
                raise ValueError("planted process survived cleanup")
            time.sleep(0.01)
        check(state_path)
        cases += 1
        good = json.loads(state_path.read_text())
        for bad, message in [({}, "invalid baseline fields"),
                             (dict(good, roots=[]), "invalid baseline roots"),
                             (dict(good, observed=0), "invalid baseline inventory count"),
                             (dict(good, before=[{}]), "invalid baseline identity")]:
            state_path.write_text(json.dumps(bad))
            try:
                check(state_path)
            except ValueError as error:
                if message not in str(error):
                    raise
                print(f"CONTROL malformed baseline: REFUSED {error}")
                cases += 1
            else:
                raise ValueError("malformed baseline passed")
        state_path.unlink()
        try:
            check(state_path)
        except FileNotFoundError:
            print("CONTROL missing baseline: REFUSED cannot read baseline")
            cases += 1
        else:
            raise ValueError("missing baseline passed")
        for output, message in [("", "empty process inventory"), ("bad row", "malformed process inventory")]:
            with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                try:
                    snapshot(run=subprocess.run)
                except ValueError as error:
                    if message not in str(error):
                        raise
                    print(f"CONTROL unreadable inventory: REFUSED {error}")
                    cases += 1
                else:
                    raise ValueError("invalid process inventory passed")
    print(f"SERVER-PROCESSES self-test: PASS cases={cases}")


def self_test():
    from unittest.mock import patch
    cases = 0
    root = "/fixture/job"
    state = {"version": 1, "roots": [root], "before": [], "observed": 1}
    good = "42 Thu Oct 15 12:00:00 2026 S /fixture/job/granary-server\n"
    def observed(output):
        run = lambda *args, **kwargs: subprocess.CompletedProcess([], 0, output, "")
        with patch("sys.platform", "darwin"):
            return snapshot(run=run)
    current, count = observed(good)
    if (len(survivors(state, current)), count) != (1, 1):
        raise ValueError("planted fixture passed")
    with patch("pathlib.Path.read_text", return_value=json.dumps(state)), patch(
            __name__ + ".snapshot", return_value=(current, count)):
        try:
            check(Path("baseline.json"))
        except ValueError as error:
            if "granary-server survived this job:" not in str(error) or "leaks=1" not in str(error):
                raise
            print(f"CONTROL planted fixture: REFUSED {error}")
            cases += 1
        else:
            raise ValueError("planted fixture passed check wiring")
    state["before"] = current
    if survivors(state, current):
        raise ValueError("preexisting fixture attributed to job")
    cases += 1
    state["before"] = []
    state["roots"] = [root + "/other"]
    if survivors(state, current):
        raise ValueError("foreign fixture attributed to job")
    cases += 1
    state["roots"] = [root]
    clean, count = observed("1 Thu Oct 15 12:00:00 2026 S /bin/sh\n")
    if survivors(state, clean) or count != 1:
        raise ValueError("clean fixture refused or inventory unobserved")
    with patch("pathlib.Path.read_text", return_value=json.dumps(state)), patch(
            __name__ + ".snapshot", return_value=(clean, count)):
        check(Path("baseline.json"))
    cases += 1
    for output, message in [("", "empty process inventory"), ("bad row", "malformed process inventory")]:
        try:
            observed(output)
        except ValueError as error:
            if message not in str(error):
                raise
            print(f"CONTROL inventory: REFUSED {error}")
            cases += 1
        else:
            raise ValueError("malformed inventory passed")
    for bad, message in [({}, "invalid baseline fields"),
                         (dict(state, roots=[]), "invalid baseline roots"),
                         (dict(state, observed=0), "invalid baseline inventory count"),
                         (dict(state, before=[{}]), "invalid baseline identity")]:
        try:
            validate(bad)
        except ValueError as error:
            if message not in str(error):
                raise
            print(f"CONTROL baseline: REFUSED {error}")
            cases += 1
        else:
            raise ValueError("malformed baseline passed")
    def unreadable(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "ps")
    try:
        snapshot(run=unreadable)
    except subprocess.CalledProcessError:
        print("CONTROL ps failure: REFUSED process inventory failed")
        cases += 1
    else:
        raise ValueError("failed ps passed")
    with patch("pathlib.Path.read_text", side_effect=PermissionError("fixture")):
        try:
            check(Path("baseline.json"))
        except PermissionError:
            print("CONTROL baseline read failure: REFUSED cannot read baseline")
            cases += 1
        else:
            raise ValueError("unreadable baseline passed")
    # Linux observer controls exercise executable and start-tick reads separately.
    with patch("sys.platform", "linux"):
        run = lambda *args, **kwargs: subprocess.CompletedProcess([], 0, good, "")
        stat = "42 (granary-server) " + " ".join(["0"] * 19 + ["123"])
        with patch("pathlib.Path.read_text", return_value=stat):
            linux, count = snapshot(run=run, readlink=lambda _: root + "/granary-server")
        if (linux[0]["start"], count) != ("linux:123", 1):
            raise ValueError(f"wrong Linux identity: {linux}")
        cases += 1
        for site in ("executable", "start ticks"):
            def denied(_):
                raise PermissionError("fixture observation denied")
            with patch("pathlib.Path.read_text", side_effect=PermissionError("fixture observation denied")):
                try:
                    snapshot(run=run, readlink=denied if site == "executable" else lambda _: root + "/granary-server",
                             owner=lambda _: os.getuid())
                except PermissionError:
                    print(f"CONTROL Linux {site}: REFUSED observation denied")
                    cases += 1
                else:
                    raise ValueError(f"unreadable {site} passed")
        foreign, _ = snapshot(run=run, readlink=denied, owner=lambda _: os.getuid() + 1)
        if foreign:
            raise ValueError(f"another user's server was observed: {foreign}")
        print("CONTROL Linux foreign user: skipped another uid's unreadable server")
        cases += 1
        for changed, expected_signals in [(False, 1), (True, 0)]:
            row = linux[0]
            current = [dict(row, start="linux:124")] if changed else linux
            with patch("os.pidfd_open", return_value=17, create=True), patch("os.close") as closed, patch(
                    "signal.pidfd_send_signal", create=True) as sent, patch(
                    __name__ + ".snapshot", return_value=(current, 1)):
                cleanup([row])
                if (sent.call_count, closed.call_count) != (expected_signals, 1):
                    raise ValueError("pidfd identity control failed")
                if expected_signals and sent.call_args.args != (17, signal.SIGKILL):
                    raise ValueError("cleanup did not signal the pinned descriptor")
            cases += 1
    print(f"SERVER-PROCESSES fixture self-test: PASS cases={cases}")


def workflow_wiring(text, expected, reap, portable=()):
    text = text.replace("python3 -I ", "python3 ")
    import re
    jobs = list(re.finditer(r"^  ([a-z][a-z0-9-]*):[^\n]*\n", text, re.M))
    blocks = {match[1]: text[match.end():jobs[i + 1].start() if i + 1 < len(jobs) else len(text)]
              for i, match in enumerate(jobs)}
    for job in expected | set(portable):
        block = blocks.get(job, "")
        before = 'python3 scripts/check-server-processes.py begin --state "$RUNNER_TEMP/server-processes.json" --root "$GITHUB_WORKSPACE" --root "$RUNNER_TEMP"'
        after = '        if: always()\n        run: python3 scripts/check-server-processes.py check '
        after += '--cleanup ' if reap and job not in portable else ''
        after += '--state "$RUNNER_TEMP/server-processes.json"'
        if block.count(before) != 1 or block.count(after) != 1 or block.index(before) > block.index(after):
            raise ValueError(f"missing server process lifecycle steps: {job}")
        if job in portable:
            # A command can still be present but skipped in one matrix leg.
            # Match the whole step, including any fields following its run line.
            steps = [step.rstrip() for step in block.split("\n      - ")[1:]]
            if (f"name: record server process baseline\n        run: {before}" not in steps
                    or f"name: no server may survive this job\n{after}" not in steps):
                raise ValueError(f"conditional or unfamiliar server process steps: {job}")
    if any('scripts/check-server-processes.py check ' in block for job, block in blocks.items() if job not in expected | set(portable)):
        raise ValueError("server process post-step has no baseline job")


def workflow_self_test(public=False):
    root = Path(__file__).resolve().parent.parent
    cases = 0
    for path, expected, reap in [
        (root / ".github/workflows/ci.yml", {"test", "breakage", "crash-points", "publish-restart", "fuse"}, True),
        (root / ".github/workflows/macos-weekly.yml", {"test"}, False),
    ]:
        text = path.read_text().replace("python3 -I ", "python3 ")
        portable = {"test-macos"} if public and path.name == "ci.yml" else set()
        workflow_wiring(text, expected, reap, portable)
        cases += 1
        for job in sorted(expected | portable):
            # A missing always() at each independently wired job must refuse.
            import re
            match = re.search(r"^  " + re.escape(job) + r":[^\n]*\n", text, re.M)
            end = re.search(r"^  [a-z][a-z0-9-]*:", text[match.end():], re.M)
            limit = match.end() + end.start() if end else len(text)
            block = text[match.start():limit]
            post = '        if: always()\n        run: python3 scripts/check-server-processes.py'
            controls = [(block.replace(post, post.replace("always()", "success()")),
                         f"missing server process lifecycle steps: {job}")]
            if job in portable:
                baseline = "      - name: record server process baseline\n"
                controls.append((block.replace(baseline, baseline + "        if: matrix.partition != 2\n"),
                                 f"conditional or unfamiliar server process steps: {job}"))
            for altered, diagnostic in controls:
                bad = text[:match.start()] + altered + text[limit:]
                try:
                    workflow_wiring(bad, expected, reap, portable)
                except ValueError as error:
                    if str(error) != diagnostic:
                        raise
                    print(f"CONTROL workflow: REFUSED {error}")
                    cases += 1
                else:
                    raise ValueError(f"accepted invalid workflow: {diagnostic}")
    print(f"SERVER-PROCESSES workflow self-test: PASS cases={cases}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("begin", "check", "self-test", "live-self-test"))
    parser.add_argument("--state", type=Path)
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--public", action="store_true", help="verify the public mixed-platform workflow wiring")
    parser.add_argument("--root", action="append", default=[])
    args = parser.parse_args()
    if args.cleanup and args.mode != "check":
        parser.error("--cleanup requires check")
    if args.mode in ("self-test", "live-self-test"):
        if args.state or args.root:
            parser.error("self-test accepts no state or roots")
        if args.mode == "self-test":
            self_test()
            workflow_self_test(args.public)
        else:
            live_self_test()
    elif args.state is None or (args.mode == "begin") != bool(args.root):
        parser.error("begin requires --state and --root; check requires only --state")
    elif args.mode == "begin":
        begin(args.state, args.root)
    else:
        check(args.state, reap=args.cleanup)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"SERVER-PROCESSES: REFUSED {error}", file=sys.stderr)
        sys.exit(1)
