#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Paired, socket-free controls of the POSIX parsers, triage and executable wiring."""

import contextlib
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, call, patch

spec = importlib.util.spec_from_file_location("checker", Path(__file__).with_name("posix-results.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
spec = importlib.util.spec_from_file_location("runner", Path(__file__).with_name("posix-conformance.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
TAP = "1..2\nok 1\nok 2\n"
ENTRY = dict(suite="pjdfstest", case="chmod/00.t", assertion=2, **{
    "class": "metadata-mutations", "operation": "chmod", "expected": "0", "errno": "ENOTSUP",
    "reason": "Section 12 refuses mode bits beyond execute intent.",
})
XFS_ENTRY = dict(suite="xfstests", case="generic/005", assertion=1, **{
    "class": "metadata-mutations", "operation": "utimensat", "expected": "0",
    "errno": "ENOTSUP", "reason": "Section 12 refuses timestamp mutation.",
})
XFS_ENTRIES = {
    case: dict(XFS_ENTRY, case=case)
    for case in ("generic/005", "generic/023", "generic/035")
}
GENERIC_005_OUT = (b"QA output created by 005\n"
                   b"*** touch deep symlinks\n\n"
                   b"ELOOP returned.  Good.\n\n"
                   b"*** touch recusive symlinks\n\n"
                   b"ELOOP returned.  Good.\n")
GENERIC_005_DIAGNOSTIC = b"touch: setting times of 'empty_file': Operation not supported\n"
GENERIC_023_OUT = b"QA output created by 023\nsamedir fixture\n"
GENERIC_035_OUT = (b"QA output created by 035\n"
                   b"overwriting regular file:\n"
                   b"overwriting directory:\n")
XFS_EXPECTED = {
    "generic/001": b"QA output created by 001\n",
    "generic/005": GENERIC_005_OUT,
    "generic/023": GENERIC_023_OUT,
    "generic/035": GENERIC_035_OUT,
}


def document(entries):
    return {"SPDX-FileCopyrightText": "2026 Adrian Ana <adrian@adrianana.com>",
            "SPDX-License-Identifier": "Apache-2.0", "failures": entries}


def xfs(case="generic/005", failed=False):
    return f"{case} 1s\nRan: {case}\n" + (
        f"Failures: {case}\nFailed 1 of 1 tests\n" if failed else "Passed all 1 tests\n")


def xfs_utimens(case, diagnostics, work="/venue/baseline"):
    rule = checker.XFS_UTIMENS_REFUSALS[case]
    detail = (f"{case}       - output mismatch (see {work}/xfs-{case.replace('/', '-')}/"
              f"{case}.out.bad)\n    {rule['hunk']}\n")
    detail += "".join(f"    +{line.decode().removesuffix(chr(10))}\n" for line in diagnostics)
    return detail + f"Ran: {case}\nFailures: {case}\nFailed 1 of 1 tests\n"


def probes():
    return [dict(case="utimens", got="ENOTSUP"), dict(case="non-exec-chmod", got="ENOTSUP"),
            dict(case="exec-chmod", got="0:0755")]


class PosixControls(unittest.TestCase):
    def test_pinned_selection_uses_open_for_file_creation(self):
        self.assertEqual(checker.PJD, (
            "open/00.t", "mkdir/00.t", "rmdir/00.t", "rename/00.t", "unlink/00.t",
            "symlink/00.t", "truncate/00.t", "ftruncate/00.t", "chmod/00.t", "chown/00.t",
            "utimensat/00.t",
        ))

    def exercise_commands(self, shutdown_error=None, collection_error=None,
                          xfs_cases=("generic/001",), authority_shutdown_error=None,
                          mount_row=(0, "gran fuse\n")):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            args = Mock(gran=Path("/fixture/gran"), server=Path("/fixture/server"),
                        tools=work / "tools", unlink_noop=False, ci_exit=False)
            mount = work / "mount"
            for suite, cases in (("pjdfstest", checker.PJD), ("xfstests", xfs_cases)):
                for case in cases:
                    source = args.tools / suite / "tests" / case
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text("# fixture source\n")
                    if suite == "xfstests":
                        if case == "generic/035":
                            Path(str(source) + ".cfg").write_text("nfs: nfs\n")
                            Path(str(source) + ".out.default").write_bytes(XFS_EXPECTED[case])
                            Path(str(source) + ".out.nfs").write_bytes(b"nfs output\n")
                        else:
                            Path(str(source) + ".out").write_bytes(XFS_EXPECTED[case])
            for name in ("writer-store", "cache"):
                (work / name).mkdir()
                (work / name / "fixture").write_text(name)

            attached = False
            phases = ["mount"] + ["mount-" + case.replace("/", "-") for case in xfs_cases[1:]]

            def capture(command, **kwargs):
                nonlocal attached
                if command[:3] == ["openssl", "genpkey", "-algorithm"]:
                    return bytes.fromhex("302e020100300506032b657004220420") + bytes(32)
                if command[:2] == ["openssl", "pkey"] and "-pubout" in command:
                    return bytes.fromhex("302a300506032b6570032100") + bytes(32)
                if command[0] == "cat":
                    return work.name.encode()
                if len(command) > 1 and "ci-mounts.sh" in str(command[1]):
                    attached = False
                return b""

            def spawn(command, **kwargs):
                nonlocal attached
                if command == [str(args.server)]:
                    kwargs["stdout"].write(b'{"fields":{"message":"listening","addr":"127.0.0.1:1234"}}\n')
                    kwargs["stdout"].flush()
                else:
                    self.assertEqual(command[:command.index("--endpoint")], [
                        str(args.gran), "--log-format", "json", "--log-filter",
                        "info,granary_client::event=debug", "mount", "posix", str(mount), "--writable",
                        "--foreground", "--root-key", "ed25519:" + "00" * 32,
                        "--cache-dir", str(work / "cache"), "--store-dir", str(work / "writer-store"),
                    ])
                    attached = True
                return Mock(poll=Mock(return_value=None))

            def findmnt(command, **kwargs):
                self.assertEqual(command, ["findmnt", "-rn", "-o", "SOURCE,FSTYPE", "--mountpoint", str(mount)])
                rc, stdout = mount_row if attached else (1, "")
                return Mock(returncode=rc, stdout=stdout)

            def run_case(command, stem, *, env, **kwargs):
                if command[0] == "./check":
                    self.assertEqual(env["TEST_DIR"], str(mount))

            def stop(child, label, *, mount=None, phase=None):
                if label == "mount" and shutdown_error:
                    raise runner.results.Refused(shutdown_error)
                if label == "authority" and authority_shutdown_error:
                    if isinstance(authority_shutdown_error, Exception):
                        raise authority_shutdown_error
                    raise runner.results.Refused(authority_shutdown_error)

            rows = self.green()
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(runner, "capture", side_effect=capture))
                stack.enter_context(patch.object(runner.subprocess, "Popen", side_effect=spawn))
                stack.enter_context(patch.object(runner.subprocess, "run", side_effect=findmnt))
                stopped = stack.enter_context(patch.object(runner, "stop", side_effect=stop))
                stack.enter_context(patch.object(runner, "refusal_probes"))
                stack.enter_context(patch.object(runner.results, "XFS", xfs_cases))
                stack.enter_context(patch.object(runner.results, "read_results", return_value=rows))
                calls = stack.enter_context(patch.object(runner, "run_case", side_effect=run_case))
                stdout = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                stderr = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                original = runner.collect_state

                def collect(work):
                    self.assertEqual(
                        [(item.args[1], item.kwargs) for item in stopped.call_args_list],
                        [("mount", dict(mount=mount, phase=phase)) for phase in phases] + [("authority", {})])
                    if collection_error:
                        raise runner.results.Refused(collection_error)
                    return original(work)

                collection = stack.enter_context(patch.object(runner, "collect_state", side_effect=collect))
                if shutdown_error or authority_shutdown_error or collection_error:
                    with self.assertRaises(runner.results.Refused) as caught:
                        runner.exercise(args, work, dict(PATH="/usr/bin:/bin"))
                    self.assertEqual(str(caught.exception), shutdown_error or
                                     authority_shutdown_error or collection_error)
                else:
                    self.assertEqual(runner.exercise(args, work, dict(PATH="/usr/bin:/bin")), rows)
                events = [json.loads(line) for line in stdout.getvalue().splitlines()]
                self.assertEqual([event for event in events if event["event"] == "mounted"], [
                    dict(event="mounted", source="gran", writable=True, phase=phase) for phase in phases
                ])
                self.assertEqual(collection.call_args_list, [call(work)])
                if shutdown_error and collection_error:
                    self.assertEqual(json.loads(stderr.getvalue())["reason"], collection_error)
            self.assertEqual((work / "diagnostic-state.tar").is_file(), collection_error is None)
            self.assertEqual((work / "pjdfstest" / "open-00.t.source").read_text(), "# fixture source\n")
            self.assertEqual((work / "xfstests" / "generic-001.source").read_text(), "# fixture source\n")
            for case in xfs_cases:
                self.assertEqual((work / "xfstests" / case.replace("/", "-")
                                  ).with_suffix(".source").read_text(), "# fixture source\n")
                self.assertEqual((work / "xfstests" /
                                  (case.replace("/", "-") + ".out")).read_bytes(),
                                 XFS_EXPECTED[case])
            return calls.call_args_list, len(rows)

    def test_xfstests_uses_the_default_fuse_source_in_every_phase(self):
        calls, observed = self.exercise_commands(xfs_cases=("generic/001", "generic/005"))
        self.assertEqual(([(command.args[0], command.kwargs["env"]["FSTYP"],
                            command.kwargs["env"]["TEST_DEV"]) for command in calls[-2:]], observed),
                         ([(["./check", "generic/001"], "fuse", "gran"),
                           (["./check", "generic/005"], "fuse", "gran")], 2))

    def test_mount_readiness_requires_the_default_fuse_source(self):
        for valid, rc, row, refusal in (
            ("gran fuse\n", 0, "other fuse\n", "mount-readiness-timeout"),
            ("gran fuse.gran\n", 0, "gran tmpfs\n", "mount-readiness-timeout"),
            ("gran fuse\n", 2, "gran fuse\n", "mount-table-unreadable"),
        ):
            with self.subTest(rc=rc, row=row):
                _, observed = self.exercise_commands(mount_row=(0, valid))
                with patch.object(runner.time, "monotonic", side_effect=[0, 0, 0, 0, 30]), \
                        patch.object(runner.time, "sleep"):
                    self.refuse(f"findmnt rc={rc} {row.strip()}", refusal,
                                lambda: self.exercise_commands(mount_row=(rc, row)), observed)

    def test_xfstests_defers_only_its_granary_mount_unmount(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "local.config"
            config.write_text(runner.XFS_LOCAL_CONFIG)
            umount = root / "umount"
            umount.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\nexit 3\n')
            umount.chmod(0o755)
            result = subprocess.run(
                ["/bin/bash", "-ec", '''
source "$1"
$UMOUNT_PROG "$TEST_DEV"
$UMOUNT_PROG "$TEST_DIR"
$UMOUNT_PROG -- /other-mount
''', "bash", config],
                env=dict(PATH=f"{root}:/usr/bin:/bin", TEST_DEV="gran",
                         TEST_DIR="/fixture-mount"), capture_output=True, text=True)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (3, "--\n/other-mount\n", ""))

    def test_xfstests_retains_cfg_selected_default_output(self):
        calls, observed = self.exercise_commands(xfs_cases=checker.XFS)
        self.assertEqual((calls[-1].args[0], observed), (["./check", "generic/035"], 2))
        print("CONTROL generic/035 expected output: resolved=035.out.default retained=generic-035.out")

        with tempfile.TemporaryDirectory() as directory:
            tests = Path(directory)
            case = tests / "generic" / "035"
            case.parent.mkdir()
            Path(str(case) + ".cfg").write_text("nfs: nfs\n")
            self.refuse("missing generic/035 default output", "xfstests-evidence-unreadable",
                        lambda: checker.xfs_expected_output(
                            tests, "generic/035", {"linux", "fuse"}), observed)

    def test_chown_has_budget_for_its_timestamp_sleeps(self):
        calls, observed = self.exercise_commands()
        pjd = {call.args[1].name: call.kwargs.get("timeout", 35) for call in calls[:-1]}
        self.assertEqual((pjd.pop("chown-00.t"), set(pjd.values()), observed), (150, {35}, 2))

    def test_unlink_control_scales_every_pjdfstest_budget(self):
        self.assertEqual(
            (runner.pjd_timeout("chown/00.t", True), runner.pjd_timeout("open/00.t", True),
             runner.pjd_timeout("chown/00.t", False), runner.pjd_timeout("open/00.t", False)),
            (225, 52.5, 150, 35))

    def test_copy_chain_has_budget_for_five_iterations(self):
        calls, observed = self.exercise_commands()
        self.assertEqual((calls[-1].kwargs.get("timeout", 35), observed), (480, 2))

    def test_slow_stop_records_matching_mount_holders_once(self):
        mount = "/posix/mount one"
        phase = "mount-generic-005"
        escaped = r"/posix/mount\040one"
        matching = f"31 24 0:42 / {escaped} rw shared:7 - fuse.gran gran rw\n"
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            namespace = proc / "mount-ns"
            namespace.touch()
            other_namespace = proc / "other-mount-ns"
            other_namespace.touch()
            for pid, table in (
                (31, matching + matching),
                (32, matching.replace(escaped, "/other-mount")),
                (33, matching.replace("0:42", "0:43").replace("fuse.gran gran", "fuse gran")),
                (34, f"31 24 0:42 / {escaped} rw - fuse.gran gran\n"),
                (35, matching),
                (36, matching),
                (37, ""),
                (38, matching.replace("fuse.gran", "tmpfs")),
                (39, matching.replace("0:42", "invalid")),
            ):
                entry = proc / str(pid)
                (entry / "ns").mkdir(parents=True)
                if table:
                    (entry / "mountinfo").write_text(table)
                if pid != 35:
                    (entry / "comm").write_bytes(b"gran\xff\n")
                if pid != 36:
                    (entry / "ns" / "mnt").symlink_to(other_namespace if pid == 33 else namespace)
            expected = dict(event="slow-stop-holders", mountpoint=mount, phase=phase, holders=[
                dict(pid=31, comm="gran\ufffd", mount_namespace_inode=namespace.stat().st_ino, device="0:42"),
                dict(pid=33, comm="gran\ufffd", mount_namespace_inode=other_namespace.stat().st_ino, device="0:43"),
            ])
            scan = runner.mount_holders
            self.assertEqual(scan(mount, proc), expected["holders"])
            for rc in (0, 3):
                with self.subTest(rc=rc), contextlib.redirect_stdout(io.StringIO()) as log:
                    events_before_wait = []

                    def wait(timeout):
                        if timeout == 1:
                            raise subprocess.TimeoutExpired("gran", timeout)
                        events_before_wait.extend(map(json.loads, log.getvalue().splitlines()))
                        return rc

                    child = Mock(poll=Mock(return_value=None), wait=Mock(side_effect=wait))
                    with patch.object(runner, "mount_holders", side_effect=lambda name: scan(name, proc)) as holders, \
                            patch.object(runner.time, "monotonic", side_effect=[10, 12, 12]):
                        if rc == 0:
                            runner.stop(child, "mount", mount=mount, phase=phase)
                        else:
                            with self.assertRaises(runner.results.Refused) as caught:
                                runner.stop(child, "mount", mount=mount, phase=phase)
                            self.assertEqual(str(caught.exception), "mount-shutdown: 3")
                    shutdown = [dict(event="shutdown", process="mount", rc=0)] if rc == 0 else []
                    self.assertEqual((list(map(json.loads, log.getvalue().splitlines())),
                                      events_before_wait, child.wait.call_args_list, holders.call_args_list),
                                     ([expected] + shutdown, [expected], [call(timeout=1), call(timeout=38)],
                                      [call(mount)]))
                    child.send_signal.assert_called_once_with(signal.SIGTERM)
                    child.kill.assert_not_called()

    def test_slow_holder_scan_cannot_extend_shutdown_deadline(self):
        mount = "/posix/mount"
        for exit_at, scan_ends_at, refusal in (
            (39, 38, None),
            (41, 42, "mount-shutdown-timeout"),
        ):
            with self.subTest(exit_at=exit_at, scan_ends_at=scan_ends_at), \
                    contextlib.redirect_stdout(io.StringIO()) as log:
                now = 0

                def wait(timeout):
                    nonlocal now
                    if exit_at > now + timeout:
                        now += timeout
                        raise subprocess.TimeoutExpired("gran", timeout)
                    now = max(now, exit_at)
                    return 0

                def scan(_mount):
                    nonlocal now
                    now = scan_ends_at
                    return []

                child = Mock(poll=Mock(return_value=None), wait=Mock(side_effect=wait))
                with patch.object(runner.time, "monotonic", side_effect=lambda: now), \
                        patch.object(runner, "mount_holders", side_effect=scan) as holders:
                    if refusal is None:
                        runner.stop(child, "mount", mount=mount, phase="mount")
                    else:
                        with self.assertRaises(runner.results.Refused) as caught:
                            runner.stop(child, "mount", mount=mount, phase="mount")
                        self.assertEqual(str(caught.exception), refusal)

                events = [json.loads(line)["event"] for line in log.getvalue().splitlines()]
                self.assertEqual((holders.call_count, now, events),
                                 (1, max(exit_at, scan_ends_at),
                                  ["slow-stop-holders"] if refusal else ["slow-stop-holders", "shutdown"]))
                holders.assert_called_once_with(mount)
                child.send_signal.assert_called_once_with(signal.SIGTERM)

    def test_collection_runs_after_shutdown_refusal_and_keeps_primary_error(self):
        for shutdown, collection in (("mount-shutdown: 1", None),
                                     (None, "diagnostic-state-unreadable: fixture"),
                                     ("mount-shutdown: 1", "diagnostic-state-unreadable: fixture")):
            with self.subTest(shutdown=shutdown, collection=collection):
                _, observed = self.exercise_commands(shutdown, collection)
                self.assertGreater(observed, 0)
                print(f"CONTROL collection wiring: observed={observed} refused={shutdown or collection}; secondary={collection}")

    def test_authority_shutdown_does_not_hide_primary_refusal(self):
        for secondary in ("authority-shutdown: 1", OSError("authority wait failed")):
            with self.subTest(secondary=secondary):
                _, observed = self.exercise_commands(
                    "mount-shutdown: 1", None, authority_shutdown_error=secondary)
                self.assertGreater(observed, 0)
                print("CONTROL authority shutdown secondary: observed=2 "
                      "refused=mount-shutdown: 1")

    def test_intermediate_shutdown_refusal_reaps_and_runs_later_xfstest(self):
        calls, observed = self.exercise_commands(
            "mount-shutdown: 1", xfs_cases=("generic/001", "generic/005"))
        self.assertEqual([item.args[0] for item in calls[-2:]],
                         [["./check", "generic/001"], ["./check", "generic/005"]])
        self.assertGreater(observed, 0)

    def test_diagnostic_state_pairs(self):
        for fault in ("missing", "empty", "read error"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                for name in ("writer-store", "cache"):
                    (work / name).mkdir()
                    (work / name / "journal").write_bytes(name.encode())
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    runner.collect_state(work)
                with tarfile.open(work / "diagnostic-state.tar") as archive:
                    self.assertEqual((archive.extractfile("writer-store/journal").read(),
                                      archive.extractfile("cache/journal").read()), (b"writer-store", b"cache"))
                self.assertEqual(json.loads(output.getvalue())["files"], 2)
                if fault == "missing":
                    (work / "cache" / "journal").unlink()
                    (work / "cache").rmdir()
                    self.refuse(fault, "diagnostic-state-unreadable", lambda: runner.collect_state(work), 2)
                elif fault == "empty":
                    for name in ("writer-store", "cache"):
                        (work / name / "journal").unlink()
                    self.refuse(fault, "diagnostic-state-empty", lambda: runner.collect_state(work), 2)
                else:
                    with patch.object(runner.tarfile.TarFile, "add", side_effect=OSError("fixture read error")):
                        self.refuse(fault, "diagnostic-state-unreadable", lambda: runner.collect_state(work), 2)

    def test_stat_diagnostics_fail_instead_of_invalidating_tap(self):
        for diagnostic in ("lstat returned -1", "stat returned -1"):
            with self.subTest(diagnostic=diagnostic):
                self.green()
                try:
                    rows = checker.parse_tap(TAP + diagnostic + "\n", "rename/00.t")
                except checker.Refused as error:
                    self.fail(f"expected a failed case with a nonzero count, got {error}")
                with contextlib.redirect_stdout(io.StringIO()):
                    counts, reasons = checker.verdict(rows, {})
                self.assertEqual((counts["run"], counts["failed"], reasons, rows[-1]["detail"]),
                                 (3, 1, ["unexpected-failure"], diagnostic))
                print(f"CONTROL {diagnostic}: run=3 failed=1 refused=unexpected-failure")
                self.refuse("unknown stat diagnostic", "tap-malformed",
                            lambda: checker.parse_tap(TAP + diagnostic + " extra\n", "rename/00.t"), 2)
                self.refuse("diagnostic missing assertion", "tap-incomplete",
                            lambda: checker.parse_tap("1..2\nok 1\n" + diagnostic + "\n", "rename/00.t"), 1)

    def refuse(self, label, reason, action, observed):
        with self.assertRaises((checker.Refused, runner.results.Refused)) as caught:
            action()
        self.assertEqual((str(caught.exception).split(":")[0], observed > 0), (reason, True))
        print(f"CONTROL {label}: refused={caught.exception} observed={observed}")

    def green(self):
        rows = checker.parse_tap(TAP, "chmod/00.t")
        with contextlib.redirect_stdout(io.StringIO()):
            counts, reasons = checker.verdict(rows, {})
        self.assertEqual((counts, reasons),
                         (dict(run=2, passed=2, failed=0, known=0, skipped=0), []))
        return rows

    def test_tap_structure_pairs(self):
        for label, text, reason in (
            ("missing plan", "ok 1\nok 2\n", "tap-empty-or-skipped"),
            ("unsupported quick_exit", "1..1\nok 1\n", "tap-empty-or-skipped"),
            ("zero plan", "1..0\nok 1\n", "tap-empty-or-skipped"),
            ("plan skip", "1..2 # SKIP writes\nok 1\nok 2\n", "tap-malformed"),
            ("duplicate plan", TAP + "1..2\n", "tap-empty-or-skipped"),
            ("missing assertion", "1..2\nok 1\n", "tap-incomplete"),
            ("duplicate assertion", "1..2\nok 1\nok 1\n", "tap-incomplete"),
            ("wrong assertion", "1..2\nok 1\nok 3\n", "tap-incomplete"),
            ("huge plan", "1..999999999999999999999999999\nok 1\n", "tap-incomplete"),
            ("bailout", TAP + "Bail out!\n", "tap-malformed"),
            ("garbage", TAP + "setup failed\n", "tap-malformed"),
            ("assertion number suffix", "1..2\nok 1suffix\nok 2\n", "tap-malformed"),
        ):
            with self.subTest(label=label):
                self.green()
                self.refuse(label, reason, lambda: checker.parse_tap(text, "chmod/00.t"),
                            sum(line.startswith(("ok ", "not ok ")) for line in text.splitlines()))

    def test_xfs_structure_pairs(self):
        for label, text, rc, reason in (
            ("empty", "Passed all 0 tests\nRan: generic/005\n", 0, "xfstests-verdict"),
            ("selection substitution", xfs("generic/006"), 0, "xfstests-selection"),
            ("duplicate", xfs() * 3, 0, "xfstests-duplicate"),
            ("interrupted", xfs() + "Interrupted!\n", 0, "xfstests-interrupted"),
            ("missing Ran", "generic/005 1s\nPassed all 1 tests\n", 0, "xfstests-empty"),
            ("banner only", "Ran: generic/005\nerror: Passed all 1 tests\n", 0, "xfstests-verdict"),
            ("bad exit", xfs(), 2, "xfstests-verdict"),
            ("timeout with partial output", "generic/005       ", 124, "xfstests-timeout"),
            ("timeout with pass summary", xfs(), 124, "xfstests-timeout"),
            ("inconsistent failure", xfs(failed=True), 0, "xfstests-verdict"),
            ("contradictory verdict", xfs(failed=True) + "Passed all 1 tests\n", 1, "xfstests-verdict"),
            ("argument refusal", "Usage: ./check [options] [testlist]\n", 1, "xfstests-empty"),
        ):
            with self.subTest(label=label):
                valid = checker.parse_xfs(xfs(), "generic/005", 0)
                self.assertEqual((len(valid), valid[0]["status"]), (1, "passed"))
                self.refuse(label, reason, lambda: checker.parse_xfs(text, "generic/005", rc), len(valid))

    def known(self, entries):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "known.json"
            path.write_text(json.dumps(document(entries)))
            return checker.load_known(path)

    def test_known_schema_pairs(self):
        for field, value, reason in (
            ("reason", " ", "known-reason"), ("reason", None, "known-reason"),
            ("class", "permission-denied", "known-refusal-class"),
            ("errno", "EIO", "known-refusal-class"),
            ("operation", "unlink", "known-refusal-class"),
            ("case", "chmod/*", "known-identity"),
            ("assertion", True, "known-identity"), ("assertion", 0, "known-identity"),
        ):
            with self.subTest(field=field, value=value):
                rows = self.green()
                self.assertEqual(len(self.known([ENTRY])), 1)
                bad = dict(ENTRY, **{field: value})
                self.refuse(f"known {field}", reason, lambda: self.known([bad]), len(rows))
        rows = self.green()
        self.refuse("duplicate known", "known-duplicate", lambda: self.known([ENTRY, ENTRY]), len(rows))
        self.refuse("unknown known field", "known-format", lambda: self.known([dict(ENTRY, glob="*")]), len(rows))
        self.assertEqual(len(self.known([XFS_ENTRY])), 1)
        self.assertEqual(len(self.known(list(XFS_ENTRIES.values()))), 3)
        for field, value in (("case", "generic/001"), ("operation", "utimens"),
                             ("errno", "EIO"), ("class", "unexpected-metadata")):
            with self.subTest(xfs_field=field, xfs_value=value):
                self.refuse("known xfs refusal", "known-refusal-class",
                            lambda field=field, value=value: self.known([
                                dict(XFS_ENTRY, **{field: value})]), len(rows))

    def test_known_cascade_and_fixed_attribute_pairs(self):
        direct = dict(ENTRY, assertion=1)
        cascade = dict(ENTRY, assertion=2, operation="stat", expected="0600",
                       errno="0644", cause=1,
                       reason="The allowed refusal at assertion 1 leaves mode 0644 unchanged.")
        rows = checker.parse_tap(
            "1..2\n"
            "not ok 1 - tried 'chmod file 0600', expected 0, got EOPNOTSUPP\n"
            "not ok 2 - tried 'stat file mode', expected 0600, got 0644\n",
            "chmod/00.t")
        with contextlib.redirect_stdout(io.StringIO()):
            counts, reasons = checker.verdict(rows, self.known([direct, cascade]))
        self.assertEqual((counts["run"], counts["known"], reasons), (2, 2, []))
        print("CONTROL known cascade: run=2 known=2 cause=1")

        changed = checker.parse_tap(
            "1..2\n"
            "not ok 1 - tried 'chmod file 0600', expected 0, got EIO\n"
            "not ok 2 - tried 'stat file mode', expected 0600, got 0644\n",
            "chmod/00.t")
        with contextlib.redirect_stdout(io.StringIO()):
            counts, reasons = checker.verdict(changed, self.known([direct, cascade]))
        self.assertEqual((counts["run"], counts["failed"], reasons),
                         (2, 2, ["unexpected-failure"]))
        print("CONTROL cascade without allowed refusal: run=2 failed=2 refused=unexpected-failure")

        observed = len(rows)
        self.refuse("missing cascade cause", "known-cause",
                    lambda: self.known([cascade]), observed)
        self.refuse("forward cascade cause", "known-cause",
                    lambda: self.known([direct, dict(cascade, cause=2)]), observed)
        self.refuse("null cascade cause", "known-cause",
                    lambda: self.known([dict(direct, cause=None)]), observed)

        fixed = dict(ENTRY, operation="lstat", expected="regular,0151",
                     errno="regular,0755", cause="attributes",
                     reason="Section 12 fixes writable regular-file modes.")
        fixed_rows = checker.parse_tap(
            "1..2\nok 1\n"
            "not ok 2 - tried 'lstat file type,mode', expected regular,0151, got regular,0755\n",
            "chmod/00.t")
        with contextlib.redirect_stdout(io.StringIO()):
            counts, reasons = checker.verdict(fixed_rows, self.known([fixed]))
        self.assertEqual((counts["run"], counts["known"], reasons), (2, 1, []))
        print("CONTROL fixed attribute: run=2 known=1 basis=attributes")

        missing = checker.parse_tap(
            "1..2\nok 1\n"
            "not ok 2 - tried 'lstat file type,mode', expected regular,0151, got ENOENT\n",
            "chmod/00.t")
        with contextlib.redirect_stdout(io.StringIO()):
            counts, reasons = checker.verdict(missing, self.known([fixed]))
        self.assertEqual((counts["run"], counts["failed"], reasons),
                         (2, 1, ["unexpected-failure"]))
        print("CONTROL missing path is not fixed attributes: run=2 failed=1 refused=unexpected-failure")

    def test_non_mounter_uid_refusal_and_consequence_pairs(self):
        reason = ("The writable mount refuses allow_other, so the kernel denies a uid other than "
                  "the mounter's with EACCES before the filesystem sees the call.")
        direct = dict(ENTRY, assertion=1, **{
            "class": "non-mounter-uid", "operation": "open", "errno": "EACCES",
            "reason": reason,
        })
        consequence = dict(ENTRY, assertion=2, **{
            "class": "non-mounter-uid", "operation": "lstat", "expected": "regular",
            "errno": "ENOENT", "cause": 1,
            "reason": "The denied create left no path for the following lstat.",
        })
        rows = checker.parse_tap(
            "1..2\n"
            "not ok 1 - tried '-u 65534 open file O_CREAT,O_WRONLY 0644', expected 0, got EACCES\n"
            "not ok 2 - tried 'lstat file type', expected regular, got ENOENT\n",
            "chmod/00.t")
        with contextlib.redirect_stdout(io.StringIO()):
            counts, reasons = checker.verdict(rows, self.known([direct, consequence]))
        self.assertEqual((counts["run"], counts["known"], reasons), (2, 2, []))
        print("CONTROL non-mounter uid: run=2 known=2 cause=1")

        for label, command in (("missing uid", "open file O_CREAT,O_WRONLY 0644"),
                               ("mounter uid", "-u 0 open file O_CREAT,O_WRONLY 0644")):
            changed = checker.parse_tap(
                "1..2\n"
                f"not ok 1 - tried '{command}', expected 0, got EACCES\n"
                "not ok 2 - tried 'lstat file type', expected regular, got ENOENT\n",
                "chmod/00.t")
            with contextlib.redirect_stdout(io.StringIO()):
                counts, reasons = checker.verdict(changed, self.known([direct, consequence]))
            self.assertEqual((counts["run"], counts["failed"], reasons),
                             (2, 2, ["unexpected-failure"]))
            print(f"CONTROL non-mounter {label}: run=2 failed=2 refused=unexpected-failure")
        self.refuse("non-mounter wrong reason", "known-refusal-class",
                    lambda: self.known([dict(direct, reason="Unrelated denial.")]), len(rows))

    def test_consequence_cannot_bypass_chmod_or_errno_guards(self):
        direct = dict(ENTRY, assertion=1, operation="chown")
        consequence = dict(ENTRY, assertion=2, operation="chmod", expected="0",
                           errno="ENOTSUP", cause=1,
                           reason="A cause must not excuse canonical chmod ENOTSUP.")
        rows = checker.parse_tap(
            "1..2\n"
            "not ok 1 - tried 'chown file 1 1', expected 0, got EOPNOTSUPP\n"
            "not ok 2 - tried 'chmod file 0644', expected 0, got EOPNOTSUPP\n",
            "chmod/00.t")
        self.refuse("caused canonical chmod ENOTSUP", "known-cause",
                    lambda: self.known([direct, consequence]), len(rows))
        other_errno = dict(consequence, errno="EIO")
        self.refuse("caused canonical chmod EIO", "known-cause",
                    lambda: self.known([direct, other_errno]), len(rows))
        absent = dict(ENTRY, assertion=2, operation="stat", expected="0", errno="ENOENT",
                      cause=1, reason="The refused create leaves the path absent.")
        self.assertEqual(len(self.known([direct, absent])), 2)
        own_refusal = dict(absent, errno="EACCES")
        self.refuse("caused consequence EACCES", "known-cause",
                    lambda: self.known([direct, own_refusal]), 1)

    def test_failed_stat_diagnostic_position_pair(self):
        direct = dict(ENTRY, assertion=2, **{
            "class": "special-files", "operation": "mkfifo",
        })
        diagnostic = dict(ENTRY, assertion=4, **{
            "class": "special-files", "operation": "stat", "expected": "0",
            "errno": "-1", "cause": 2, "after": 2, "before": 3,
            "reason": "The refused fifo leaves the following stat without a path.",
        })

        def counts(text):
            rows = checker.parse_tap(text, "chmod/00.t")
            with contextlib.redirect_stdout(io.StringIO()):
                return checker.verdict(rows, self.known([direct, diagnostic]))

        valid, reasons = counts(
            "1..3\nok 1\n"
            "not ok 2 - tried 'mkfifo file 0644', expected 0, got EOPNOTSUPP\n"
            "stat returned -1\nok 3\n")
        self.assertEqual((valid["run"], valid["known"], reasons), (4, 2, []))
        print("CONTROL positioned stat diagnostic: run=4 known=2 after=2 before=3")

        moved, reasons = counts(
            "1..3\nstat returned -1\nok 1\n"
            "not ok 2 - tried 'mkfifo file 0644', expected 0, got EOPNOTSUPP\n"
            "ok 3\n")
        self.assertEqual((moved["run"], moved["failed"], moved["known"], reasons),
                         (4, 1, 1, ["unexpected-failure"]))
        print("CONTROL moved stat diagnostic: run=4 failed=1 "
              "refused=unexpected-failure")

    def test_test_check_requires_preceding_operation_context(self):
        direct = dict(ENTRY, assertion=1)
        observed = dict(ENTRY, assertion=2, operation="stat", expected="0600",
                        errno="0644", cause=1,
                        reason="The refused chmod leaves the fixed mode unchanged.")
        check = dict(ENTRY, assertion=3, operation="test_check", expected="true",
                     errno="false", cause=1,
                     context={"command": "stat file mode", "expected": "0600",
                              "errno": "0644"},
                     reason="The check reads the unchanged mode observed immediately before it.")

        def counts(operation, expected, actual):
            rows = checker.parse_tap(
                "1..3\n"
                "not ok 1 - tried 'chmod file 0600', expected 0, got EOPNOTSUPP\n"
                f"not ok 2 - tried '{operation}', expected {expected}, got {actual}\n"
                "not ok 3\n", "chmod/00.t")
            with contextlib.redirect_stdout(io.StringIO()):
                return checker.verdict(rows, self.known([direct, observed, check]))

        valid, reasons = counts("stat file mode", "0600", "0644")
        self.assertEqual((valid["run"], valid["known"], reasons), (3, 3, []))
        print("CONTROL test_check context: run=3 known=3 context=stat-mode")
        unrelated, reasons = counts("stat file uid", "1", "0")
        self.assertEqual((unrelated["run"], unrelated["failed"], unrelated["known"], reasons),
                         (3, 2, 1, ["unexpected-failure"]))
        print("CONTROL unrelated test_check: run=3 failed=2 refused=unexpected-failure")

    def test_attribute_test_check_names_observed_fixed_attribute(self):
        observed = dict(ENTRY, assertion=1, operation="stat", expected="0600",
                        errno="0644", cause="attributes",
                        reason="Section 12 fixes the writable mode.")
        check = dict(ENTRY, assertion=2, operation="test_check", expected="true",
                     errno="false", cause="attributes", attribute="mode",
                     context={"command": "stat file mode", "expected": "0600",
                              "errno": "0644"},
                     reason="The check reads the fixed mode observed immediately before it.")
        rows = checker.parse_tap(
            "1..2\n"
            "not ok 1 - tried 'stat file mode', expected 0600, got 0644\n"
            "not ok 2\n", "chmod/00.t")
        with contextlib.redirect_stdout(io.StringIO()):
            counts, reasons = checker.verdict(rows, self.known([observed, check]))
        self.assertEqual((counts["run"], counts["known"], reasons), (2, 2, []))
        print("CONTROL attribute test_check: run=2 known=2 attribute=mode")
        for label, bad in (("missing attribute", {key: value for key, value in check.items()
                                                   if key != "attribute"}),
                           ("wrong attribute", dict(check, attribute="ownership"))):
            self.refuse(label, "known-context", lambda bad=bad: self.known([observed, bad]),
                        len(rows))

    def test_known_variable_attribute_pairs(self):
        timestamp_refusal = dict(ENTRY, assertion=1, operation="utimensat")
        timestamp = dict(ENTRY, assertion=2, operation="lstat", expected="1900000000",
                         errno="<timestamp>", cause=1,
                         reason="The allowed refusal leaves the published timestamp unchanged.")

        def timestamp_counts(actual):
            rows = checker.parse_tap(
                "1..2\n"
                "not ok 1 - tried 'utimensat file 1900000000', expected 0, got EOPNOTSUPP\n"
                f"not ok 2 - tried 'lstat file atime', expected 1900000000, got {actual}\n",
                "chmod/00.t")
            with contextlib.redirect_stdout(io.StringIO()):
                counts, reasons = checker.verdict(
                    rows, self.known([timestamp_refusal, timestamp]))
            return counts, reasons

        counts, reasons = timestamp_counts("1794781324")
        self.assertEqual((counts["run"], counts["known"], reasons), (2, 2, []))
        print("CONTROL other-run timestamp: run=2 known=2 got=1794781324")
        for actual in ("1900000000", "not-a-timestamp"):
            with self.subTest(timestamp=actual):
                counts, reasons = timestamp_counts(actual)
                self.assertEqual((counts["run"], counts["failed"], counts["known"], reasons),
                                 (2, 1, 1, ["unexpected-failure"]))
                print(f"CONTROL invalid timestamp: run=2 failed=1 got={actual} "
                      "refused=unexpected-failure")
        self.refuse("timestamp without assertion cause",
                    "known-cause",
                    lambda: self.known([
                        timestamp_refusal, dict(timestamp, cause="attributes")]), 2)

        inode_refusal = dict(ENTRY, assertion=1, **{
            "class": "hardlinks", "operation": "link",
        })
        inode = dict(ENTRY, assertion=2, operation="lstat",
                     expected="regular,<inode>,0644,2",
                     errno="regular,<inode>,0644,1", cause="attributes",
                     reason="Section 12 fixes the link count while preserving the inode.")

        def inode_counts(expected_inode, actual_inode):
            rows = checker.parse_tap(
                "1..2\n"
                "not ok 1 - tried 'link source target', expected 0, got EOPNOTSUPP\n"
                f"not ok 2 - tried 'lstat file type,inode,mode,nlink', "
                f"expected regular,{expected_inode},0644,2, "
                f"got regular,{actual_inode},0644,1\n",
                "chmod/00.t")
            with contextlib.redirect_stdout(io.StringIO()):
                counts, reasons = checker.verdict(rows, self.known([inode_refusal, inode]))
            return counts, reasons

        counts, reasons = inode_counts("73", "73")
        self.assertEqual((counts["run"], counts["known"], reasons), (2, 2, []))
        print("CONTROL other-run inode: run=2 known=2 inode=73")
        counts, reasons = inode_counts("73", "74")
        self.assertEqual((counts["run"], counts["failed"], counts["known"], reasons),
                         (2, 1, 1, ["unexpected-failure"]))
        print("CONTROL mismatched inode: run=2 failed=1 refused=unexpected-failure")
        self.refuse("inode only in observed pattern",
                    "known-format",
                    lambda: self.known([
                        inode_refusal, dict(inode, expected="regular,28,0644,2")]), 2)

    def test_xfstests_known_refusals_match_only_exact_timestamp_diffs(self):
        fixture_diagnostics = {
            "generic/005": [GENERIC_005_DIAGNOSTIC],
            "generic/023": [
                b"touch: setting times of '/venue/baseline/mount/tmp.fixture/foo': "
                b"Operation not supported\n",
            ],
            "generic/035": [
                b"touch: setting times of '/venue/baseline/mount/123/file1': "
                b"Operation not supported\n",
                b"touch: setting times of '/venue/baseline/mount/123/file2': "
                b"Operation not supported\n",
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for case, fallback_diagnostics in fixture_diagnostics.items():
                known = self.known([XFS_ENTRIES[case]])
                expected_bytes = XFS_EXPECTED[case]
                retained_bytes = (expected_bytes.splitlines(keepends=True)[0] +
                                  b"".join(fallback_diagnostics) +
                                  b"".join(expected_bytes.splitlines(keepends=True)[1:]))
                lines = retained_bytes.splitlines(keepends=True)
                diagnostics = [line for line in lines
                               if line.startswith(b"touch: setting times of '")]
                self.assertEqual(len(diagnostics),
                                 checker.XFS_UTIMENS_REFUSALS[case]["count"])
                expected_bytes = b"".join(line for line in lines if line not in diagnostics)
                expected = directory / "tests" / (case + ".out")
                expected.parent.mkdir(parents=True, exist_ok=True)
                expected.write_bytes(expected_bytes)
                actual = directory / "results" / (case + ".out.bad")
                actual.parent.mkdir(parents=True, exist_ok=True)
                actual.write_bytes(retained_bytes)
                detail = xfs_utimens(case, diagnostics)

                rows = checker.parse_xfs(detail, case, 1,
                                         expected_output=expected, actual_output=actual)
                with contextlib.redirect_stdout(io.StringIO()):
                    counts, reasons = checker.verdict(rows, known)
                self.assertEqual((counts["run"], counts["known"], reasons), (1, 1, []))
                print(f"CONTROL {case} independent expected output: known=1 exact-output=true")

                actual.write_bytes(b"".join(lines[:5] + [b"later mismatch\n"] + lines[5:]))
                rows = checker.parse_xfs(detail, case, 1,
                                         expected_output=expected, actual_output=actual)
                with contextlib.redirect_stdout(io.StringIO()):
                    counts, reasons = checker.verdict(rows, known)
                self.assertEqual((counts["known"], counts["failed"], reasons),
                                 (0, 1, ["unexpected-failure"]))
                print(f"CONTROL {case} extra changed line: known=0 failed=1")

                actual.write_bytes(diagnostics[0] + retained_bytes)
                rows = checker.parse_xfs(detail, case, 1,
                                         expected_output=expected, actual_output=actual)
                with contextlib.redirect_stdout(io.StringIO()):
                    counts, reasons = checker.verdict(rows, known)
                self.assertEqual((counts["known"], counts["failed"], reasons),
                                 (0, 1, ["unexpected-failure"]))
                print(f"CONTROL {case} wrong touch count: known=0 failed=1")

                if case == "generic/005":
                    wrong_diagnostic = diagnostics[0].replace(b"empty_file", b"other_file")
                else:
                    wrong_diagnostic = diagnostics[0].replace(b"/mount/", b"/other/")
                actual.write_bytes(retained_bytes.replace(diagnostics[0], wrong_diagnostic))
                rows = checker.parse_xfs(detail, case, 1,
                                         expected_output=expected, actual_output=actual)
                with contextlib.redirect_stdout(io.StringIO()):
                    counts, reasons = checker.verdict(rows, known)
                self.assertEqual((counts["known"], counts["failed"], reasons),
                                 (0, 1, ["unexpected-failure"]))
                print(f"CONTROL {case} wrong touch path: known=0 failed=1")

            case = "generic/005"
            detail = xfs_utimens(case, fixture_diagnostics[case])
            expected = directory / "tests" / (case + ".out")
            actual = directory / "results" / (case + ".out.bad")
            actual.unlink()
            self.refuse("missing generic/005 out.bad", "xfstests-evidence-unreadable",
                        lambda: checker.parse_xfs(
                            detail, case, 1,
                            expected_output=expected, actual_output=actual), 1)
            actual.write_bytes(GENERIC_005_OUT.replace(
                b"QA output created by 005\n",
                b"QA output created by 005\n" + GENERIC_005_DIAGNOSTIC))
            expected.unlink()
            self.refuse("missing generic/005 expected output", "xfstests-evidence-unreadable",
                        lambda: checker.parse_xfs(
                            detail, case, 1,
                            expected_output=expected, actual_output=actual), 1)

    def test_each_refusal_class_has_a_paired_control(self):
        for refusal, operations in checker.CLASSES.items():
            for operation in sorted(operations):
                with self.subTest(refusal=refusal, operation=operation):
                    entry = dict(ENTRY, operation=operation, **{"class": refusal})
                    known = self.known([entry])
                    command = "chmod file 0600" if operation == "chmod" else f"{operation} file"
                    for errno, expected_known, expected_reasons in (
                        ("ENOTSUP", 1, []), ("EOPNOTSUPP", 1, []), ("EIO", 0, ["unexpected-failure"]),
                    ):
                        rows = checker.parse_tap(f"1..2\nok 1\nnot ok 2 - tried '{command}', expected 0, got {errno}\n", "chmod/00.t")
                        with contextlib.redirect_stdout(io.StringIO()):
                            counts, reasons = checker.verdict(rows, known)
                        self.assertEqual((counts["run"], counts["known"], reasons), (2, expected_known, expected_reasons))
                    print(f"CONTROL {refusal}/{operation}: run=2 refused=unexpected-failure for EIO")

    def test_failure_and_skip_pairs(self):
        for bad, expected in (
            ("not ok 2 - incorrect unlink", "unexpected-failure"),
            ("ok 2 # SKIP write group", "skipped-write-group"),
            ("not ok 2 # TODO writes", "skipped-write-group"),
        ):
            self.green()
            rows = checker.parse_tap("1..2\nok 1\n" + bad + "\n", "unlink/00.t")
            with contextlib.redirect_stdout(io.StringIO()) as log:
                counts, reasons = checker.verdict(rows, {})
            self.assertEqual((reasons, counts["run"] > 0), ([expected], True))
            self.assertIn(bad.split("2", 1)[1].strip(), log.getvalue())
            print(f"CONTROL {expected}: counts={counts} refused={reasons}")
        self.green()
        # A second executed write case accompanies a wholly skipped group.
        rows = checker.parse_xfs(xfs() + "Not run: generic/005\n", "generic/005", 0)
        with contextlib.redirect_stdout(io.StringIO()):
            counts, reasons = checker.verdict(self.green() + rows, {})
        self.assertEqual((counts["run"], counts["skipped"], reasons), (2, 1, ["skipped-write-group"]))
        self.refuse("zero run", "zero-cases-run", lambda: checker.verdict([], {}), len(self.green()))
        rows = self.green()
        self.refuse("duplicate result", "results-duplicate", lambda: checker.verdict(rows + rows, {}), len(rows))

    def unlink_control_fixture(self, root, *, landed=True):
        known = self.fixture(root)
        known.write_text(json.dumps(document([dict(ENTRY, assertion=3)])))
        anchor = ("not ok 5 - tried 'lstat file type', expected ENOENT, got regular"
                  if landed else "ok 5")
        (root / "pjdfstest" / "unlink-00.t.log").write_text(
            f"1..5\nok 1\nok 2\nok 3\nnot ok 4 - unrelated failure\n{anchor}\n")
        (root / "unlink-witness.jsonl").write_text('{"operation":"unlink","path":"/fixture/file"}\n')
        return checker.read_results(root), checker.load_known(known)

    def test_unlink_control_reports_unobserved_known_and_completes(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            rows, known = self.unlink_control_fixture(work)
            args = Mock(unlink_noop=True, ci_exit=False, work=work)
            with contextlib.redirect_stdout(io.StringIO()) as log:
                runner.require_unlink_noop(rows, work)
                with self.assertRaises(runner.results.Refused) as caught:
                    runner.report_verdict(args, rows, known)
            events = [event for event in map(json.loads, log.getvalue().splitlines())
                      if event["event"] != "case"]
            self.assertEqual((str(caught.exception), events), ("unexpected-failure", [
                dict(event="unlink-noop-detected", assertion=5, witnesses=1),
                dict(event="known-unobserved", count=1, identities=[["pjdfstest", "chmod/00.t", 3]]),
                dict(event="counts", run=32, passed=30, failed=2, known=0, skipped=0),
                dict(event="unlink-control-complete", assertion=5),
            ]))
            print("CONTROL armed unlink: run=32, known-unobserved=1, unlink-control-complete, "
                  "refused=unexpected-failure")

    def test_unlink_control_fixture_still_refuses_in_baseline_and_strict_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            rows, known = self.unlink_control_fixture(Path(directory))
            for ci_exit in (False, True):
                mode = "baseline" if ci_exit else "strict"
                with self.subTest(mode=mode):
                    with contextlib.redirect_stdout(io.StringIO()) as log:
                        with self.assertRaises(checker.Refused) as caught:
                            checker.verdict(rows, known, ci_exit=ci_exit)
                    self.assertEqual((str(caught.exception), len(rows)),
                                     ("known-unobserved: assertion not executed", 32))
                    self.assertNotIn('"event": "known-unobserved"', log.getvalue())
                    print(f"CONTROL {mode}: observed=32, refused={caught.exception}")

    def test_unlink_control_requires_the_anchor_and_witness(self):
        for landed in (False, True):
            with self.subTest(landed=landed), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                rows, _ = self.unlink_control_fixture(work, landed=landed)
                if landed:
                    (work / "unlink-witness.jsonl").write_text("")
                with contextlib.redirect_stdout(io.StringIO()) as log:
                    with self.assertRaises(runner.results.Refused) as caught:
                        runner.require_unlink_noop(rows, work)
                self.assertEqual((str(caught.exception), len(rows), log.getvalue()),
                                 ("control-did-not-land", 32, ""))
                print(f"CONTROL {'empty witness' if landed else 'passed anchor'}: "
                      f"observed=32, refused={caught.exception}")

    def test_unlink_control_requires_executed_cases(self):
        self.green()
        rows = checker.parse_tap("1..2\nok 1 # SKIP\nok 2 # SKIP\n", "unlink/00.t")
        args = Mock(unlink_noop=True, ci_exit=False)
        with contextlib.redirect_stdout(io.StringIO()) as log:
            with self.assertRaises(runner.results.Refused) as caught:
                runner.report_verdict(args, rows, {})
        self.assertEqual((str(caught.exception), len(rows),
                          '"event": "unlink-control-complete"' in log.getvalue()),
                         ("zero-cases-run", 2, False))
        print(f"CONTROL all skipped: observed=2, run=0, refused={caught.exception}")

    def test_ci_exit_compares_identities_and_signatures(self):
        document = json.loads(Path(__file__).with_name("posix-exit-baseline.json").read_text())
        rows = {}
        for case, groups in document["device-nodes"].items():
            for operation, wanted, got, numbers in groups:
                detail = f"- tried '{operation} entry', expected {wanted}, got {got}"
                if operation == "mknod":
                    detail = "- tried 'mknod entry b 0644 1 2', expected 0, got EOPNOTSUPP"
                elif operation == "test_check":
                    detail = ""
                elif got == "-1":
                    detail = f"{operation} returned -1"
                for number in numbers:
                    rows["pjdfstest", case, number] = dict(status="failed", detail=detail)
        for case, numbers in document["test-check"].items():
            for number in numbers:
                rows["pjdfstest", case, number] = dict(status="failed", detail="")
        for detail, numbers in document["todos"].items():
            for number in numbers:
                rows["pjdfstest", "chown/00.t", number] = dict(status="skipped", detail=detail)
        counts = dict(run=1939, known=908)

        def compare(outcomes, observed=counts):
            with contextlib.redirect_stdout(io.StringIO()) as log:
                reasons = checker.exit_comparison(outcomes, observed)
            return reasons, json.loads(log.getvalue())

        reasons, event = compare(rows)
        self.assertEqual(reasons, [])
        self.assertEqual(event["matched"], {"device-nodes": 476, "test-check": 72, "todos": 27})
        node = ("pjdfstest", "unlink/00.t", 14)
        todo = ("pjdfstest", "chown/00.t", 650)
        for old, new in ((node, ("pjdfstest", "unlink/00.t", 5)),
                         (todo, ("pjdfstest", "chown/00.t", 651))):
            with self.subTest(new=new):
                moved = dict(rows)
                moved[new] = moved.pop(old)
                reasons, event = compare(moved)
                self.assertEqual(reasons, ["exit-outcome-drift"])
                self.assertEqual((event["new"], event["missing"]), ([list(new)], [list(old)]))
        for identity, detail in ((node, rows[node]["detail"].replace("EOPNOTSUPP", "EPERM")),
                                 (todo, rows[todo]["detail"].replace("TODO", "SKIP"))):
            with self.subTest(changed=identity):
                reasons, event = compare({**rows, identity: dict(rows[identity], detail=detail)})
                self.assertEqual(reasons, ["exit-outcome-drift"])
                self.assertEqual(event["changed"], [list(identity)])
        self.assertEqual(compare(rows, dict(counts, known=907))[0], ["exit-coverage-or-known-drift"])

    def test_ci_device_probe_distinguishes_reachable_and_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            mount = work / "mount"
            mount.mkdir()

            def mknod(path, mode, device):
                kind = path.name.rsplit("-", 1)[1]
                expected = runner.stat.S_IFBLK if kind == "block" else runner.stat.S_IFCHR
                self.assertEqual((mode, device), (expected | 0o600, os.makedev(1, 2)))
                if path.parent == mount:
                    raise OSError(errno.ENOTSUP, "granary refused the device")
                path.touch()

            with patch.object(runner.os, "mknod", side_effect=mknod, create=True) as syscall:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.device_node_probe(work, mount)
            self.assertEqual(syscall.call_count, 4)
            checker.require_device_reachability(work)
            probe = work / "device-node-probe.json"
            observed = json.loads(probe.read_text())
            for location in observed:
                with self.subTest(blocked=location):
                    probe.write_text(json.dumps({**observed, location: "EPERM"}))
                    with self.assertRaisesRegex(checker.Refused, "device-node-reachability"):
                        checker.require_device_reachability(work)

    def test_refused_operations_cannot_silently_succeed(self):
        for name, got in (("utimens", "0"), ("non-exec-chmod", "0"), ("exec-chmod", "ENOTSUP"),
                          ("exec-chmod", "0:0644"), ("utimens", "EIO")):
            valid = checker.parse_probes(json.dumps(probes()))
            self.assertEqual(checker.verdict(valid, {}), (dict(run=3, passed=3, failed=0, known=0, skipped=0), []))
            bad = probes()
            next(record for record in bad if record["case"] == name)["got"] = got
            with contextlib.redirect_stdout(io.StringIO()):
                counts, reasons = checker.verdict(checker.parse_probes(json.dumps(bad)), {})
            self.assertEqual((counts["run"], counts["failed"], reasons), (3, 1, ["unexpected-failure"]))
            print(f"CONTROL metadata {name} got={got}: run=3 refused=unexpected-failure")
        for label, records, reason in (
            ("missing probe", probes()[:-1], "probes-incomplete"),
            ("duplicate probe", probes()[:2] + probes()[:1], "probes-selection"),
            ("wrong probe", probes()[:2] + [dict(case="other", got="0")], "probes-selection"),
            ("missing observation", probes()[:2] + [dict(case="exec-chmod")], "probes-malformed"),
        ):
            valid = checker.parse_probes(json.dumps(probes()))
            self.refuse(label, reason, lambda: checker.parse_probes(json.dumps(records)), len(valid))

    def test_known_matches_exact_operation_errno_and_execute_intent(self):
        known = self.known([ENTRY])
        def check(command="chmod file 0600", expected="0", got="ENOTSUP", status="not ok"):
            rows = checker.parse_tap(f"1..2\nok 1\n{status} 2 - tried '{command}', expected {expected}, got {got}\n", "chmod/00.t")
            with contextlib.redirect_stdout(io.StringIO()):
                return checker.verdict(rows, known)

        for command, expected, got in (
            ("chmod file 0644", "0", "ENOTSUP"), ("chmod file 0755", "0", "ENOTSUP"),
            ("chmod file 0777", "0", "ENOTSUP"), ("unlink file", "0", "ENOTSUP"),
            ("chmod file 0600", "EACCES", "ENOTSUP"), ("chmod file 0600", "0", "EIO"),
        ):
            self.assertEqual(check(), (dict(run=2, passed=1, known=1, failed=0, skipped=0), []))
            counts, reasons = check(command, expected, got)
            self.assertEqual((counts["run"], counts["failed"], reasons), (2, 1, ["unexpected-failure"]))
            print(f"CONTROL unallowed refusal {command} {got}: run=2 refused=unexpected-failure")
        counts, reasons = check(status="ok", got="0")
        self.assertEqual((counts["run"], reasons[0].split(":")[0]), (2, "known-unexpected-success"))
        with contextlib.redirect_stdout(io.StringIO()):
            rows = checker.parse_tap("1..2\nok 1\nnot ok 2 - unclassified failure\n", "chmod/00.t")
            counts, reasons = checker.verdict(rows, self.known([dict(ENTRY, **{"class": "unexpected"})]))
        self.assertEqual((counts["run"], counts["failed"], reasons), (2, 1, ["unexpected-failure"]))
        self.refuse("unobserved known", "known-unobserved", lambda: checker.verdict(
            self.green(), self.known([dict(ENTRY, assertion=3)])), 2)

    def fixture(self, root):
        for suite, cases in (("pjdfstest", checker.PJD), ("xfstests", checker.XFS)):
            (root / suite).mkdir()
            for case in cases:
                stem = root / suite / case.replace("/", "-")
                Path(str(stem) + ".log").write_text(TAP if suite == "pjdfstest" else xfs(case))
                Path(str(stem) + ".rc").write_text("0\n")
        known = root / "known.json"
        known.write_text(json.dumps(document([])))
        (root / "refusals.json").write_text(json.dumps(probes()))
        return known

    def cli(self, root, known):
        child = subprocess.run([sys.executable, str(Path(__file__).with_name("posix-results.py")),
                                str(root), str(known)], capture_output=True, text=True, check=False)
        return child.returncode, [json.loads(line) for line in (child.stdout + child.stderr).splitlines()]

    def test_cli_wiring_read_failures_and_complete_identity(self):
        for label in ("missing-log", "missing-rc", "missing-known", "bad-known", "missing-probes", "bad-exit", "wrong-selection"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                known = self.fixture(root)
                rc, events = self.cli(root, known)
                self.assertEqual((rc, events[-1]), (0, dict(event="counts", run=29, passed=29, failed=0, known=0, skipped=0)))
                stem = root / "xfstests" / "generic-035"
                if label == "missing-log":
                    Path(str(stem) + ".log").unlink()
                elif label == "missing-rc":
                    Path(str(stem) + ".rc").unlink()
                elif label == "missing-known":
                    known.unlink()
                elif label == "bad-known":
                    known.write_text("{broken")
                elif label == "missing-probes":
                    (root / "refusals.json").unlink()
                elif label == "bad-exit":
                    Path(str(stem) + ".rc").write_text("124\n")
                else:
                    Path(str(stem) + ".log").write_text(xfs("generic/005"))
                rc, events = self.cli(root, known)
                reason = events[-1]["reason"]
                expected = {"bad-exit": "xfstests-timeout", "wrong-selection": "xfstests-selection",
                            "missing-known": "known-unreadable", "bad-known": "known-unreadable",
                            "missing-probes": "probes-unreadable"}.get(label, "results-unreadable")
                self.assertEqual((rc, reason.split(":")[0], events[-1]["observed"] > 0), (1, expected, True))
                print(f"CONTROL CLI {label}: rc={rc} observed={events[-1]['observed']} refused={expected}")

    def test_cli_consequential_verdicts(self):
        for label, last, entry, reason, failed, skipped in (
            ("unexpected failure", "not ok 2 - unlink left file", None, "unexpected-failure", 1, 0),
            ("skipped writes", "ok 2 # SKIP write group", None, "skipped-write-group", 0, 1),
            ("stale waiver", "ok 2", ENTRY, "known-unexpected-success", 0, 0),
            ("unclassified failure", "not ok 2 - defect", dict(ENTRY, **{"class": "unexpected"}), "unexpected-failure", 1, 0),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                known = self.fixture(root)
                self.assertEqual(self.cli(root, known)[0], 0)
                if entry:
                    known.write_text(json.dumps(document([entry])))
                (root / "pjdfstest" / "chmod-00.t.log").write_text(f"1..2\nok 1\n{last}\n")
                rc, events = self.cli(root, known)
                counts = next(event for event in events if event["event"] == "counts")
                self.assertEqual((rc, counts["run"], counts["failed"], counts["skipped"], events[-1]["reason"].split(":")[0]),
                                 (1, 29 - skipped, failed, skipped, reason))
                print(f"CONTROL CLI {label}: {counts} refused={events[-1]['reason']}")

    def test_cli_stat_diagnostic_is_a_case_failure(self):
        for diagnostic in ("stat returned -1", "lstat returned -1"):
            with self.subTest(diagnostic=diagnostic), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                known = self.fixture(root)
                self.assertEqual(self.cli(root, known)[0], 0)
                (root / "pjdfstest" / "rename-00.t.log").write_text(TAP + diagnostic + "\n")
                rc, events = self.cli(root, known)
                counts = next(event for event in events if event["event"] == "counts")
                failure = next(event for event in events if event["event"] == "case")
                self.assertEqual((rc, counts["run"], counts["failed"], failure["detail"], events[-1]["reason"]),
                                 (1, 30, 1, diagnostic, "unexpected-failure"))
                print(f"CONTROL CLI {diagnostic}: rc={rc} run=30 failed=1 refused=unexpected-failure")

    def test_timeout_waits_for_live_group_members_after_reaping_leader(self):
        command = ["./check", "generic/001"]
        supervisor = Mock()
        supervisor.spawn.return_value.pid = 4242
        supervisor.spawn.return_value.wait.side_effect = [subprocess.TimeoutExpired(command, 1), -9]
        supervisor.ps.side_effect = [b" 4242 D\n", b" 4242 Z\n 2121 S+\n"]
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            root = Path(directory)
            stem = root / "generic-001"
            stack.enter_context(patch.object(runner.subprocess, "Popen", supervisor.spawn))
            stack.enter_context(patch.object(runner.os, "killpg", supervisor.killpg))
            stack.enter_context(patch.object(runner, "capture", supervisor.ps))
            stack.enter_context(patch.object(runner.time, "sleep"))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            runner.run_case(command, stem, cwd=root, env={}, timeout=1)
            self.assertEqual(stem.with_suffix(".rc").read_text(), "124\n")
            self.assertEqual(json.loads(output.getvalue().splitlines()[-1])["rc"], 124)
        self.assertTrue(supervisor.spawn.call_args.kwargs["start_new_session"])
        self.assertEqual(supervisor.mock_calls[1:], [
            call.spawn().wait(timeout=1), call.killpg(4242, signal.SIGKILL), call.spawn().wait(),
            call.killpg(4242, 0), call.ps(["ps", "-axo", "pgid=,stat="], timeout=2),
            call.killpg(4242, 0), call.ps(["ps", "-axo", "pgid=,stat="], timeout=2),
        ])

    def test_timeout_refuses_even_with_a_complete_tap_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            stem = root / "pjdfstest" / "chown-00.t"
            command = [sys.executable, "-I", "-u", "-c", f"print({TAP!r}, end='')"]
            with contextlib.redirect_stdout(io.StringIO()):
                runner.run_case(command, stem, cwd=root, env=os.environ, timeout=1)
            self.assertEqual((Path(str(stem) + ".rc").read_text(), len(checker.read_results(root))), ("0\n", 29))
            command[-1] += "; import time; time.sleep(5)"
            with contextlib.redirect_stdout(io.StringIO()):
                runner.run_case(command, stem, cwd=root, env=os.environ, timeout=1)
            observed = []
            with self.assertRaises(checker.Refused) as caught:
                checker.read_results(root, observed)
            self.assertEqual((Path(str(stem) + ".rc").read_text(), str(caught.exception), len(observed)),
                             ("124\n", "pjdfstest-exit: chown/00.t: 124", 18))
            self.assertEqual(len(checker.parse_tap(Path(str(stem) + ".log").read_text(), "chown/00.t")), 2)
            print("CONTROL timeout: rc=124 observed=18 refused=pjdfstest-exit: chown/00.t: 124; complete TAP does not pass")

    def test_unlink_wrapper_is_opt_in_and_keeps_the_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, witness = root / "file", root / "witness"
            target.write_text("retained")
            env = dict(os.environ, POSIX_PJD_REAL="/usr/bin/true", POSIX_UNLINK_WITNESS=str(witness))
            wrapper = [sys.executable, str(Path(__file__).with_name("posix-unlink-control.py"))]
            plain = subprocess.run(wrapper + ["stat", str(target)], env=env, capture_output=True, text=True, check=False)
            self.assertEqual((plain.returncode, witness.exists()), (0, False))
            armed = subprocess.run(wrapper + ["unlink", str(target)], env=env, capture_output=True, text=True, check=False)
            self.assertEqual((armed.returncode, armed.stdout, target.read_text(), len(witness.read_text().splitlines())),
                             (0, "0\n", "retained", 1))
            self.assertEqual(json.loads(witness.read_text())["operation"], "unlink")
            print("CONTROL no-op unlink wrapper: rc=0 target=retained witnesses=1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
