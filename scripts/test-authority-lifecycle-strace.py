#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Paired controls for the lifecycle trace checker, including its CLI wiring."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("checker", Path(__file__).with_name("authority-venue-strace.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
STATE = "/venue/lifecycle/state"


def fixture(marker_publish="renameat", intent_cleanup=False):
    events = []

    def event(name, fd=None, paths=None, ret=0, ret_path=None, raw="", creat=False, label=""):
        events.append(dict(name=name, fd_path=fd, paths=paths or [], ret=ret,
                           ret_path=ret_path, raw=raw, creat=creat, label=label))

    def publication(role, tmp, final, publish, anchor=False):
        tmp_path, final_path = f"{STATE}/{tmp}", f"{STATE}/{final}"
        event("openat", paths=[tmp_path], ret=3, ret_path=tmp_path, raw="O_CREAT|O_EXCL", creat=True,
              label=f"{role}:create")
        event("pwrite64", fd=tmp_path, ret=10, label=f"{role}:write")
        event("fsync", fd=tmp_path, label=f"{role}:file-sync")
        event(publish, paths=[tmp_path, final_path], raw="0" if publish == "renameat2" else "",
              label=f"{role}:publish")
        if publish == "linkat":
            event("unlinkat", paths=[tmp_path], label=f"{role}:unlink")
        event("fsync", fd=STATE, label=f"{role}:state-sync")
        if anchor:
            event("fsync", fd=STATE.rsplit("/", 1)[0], label=f"{role}:anchor-sync")

    publication("initialise:running", "MARKER.tmp", "MARKER", marker_publish, anchor=True)
    if intent_cleanup:
        event("unlinkat", paths=[f"{STATE}/vol-a.intent.tmp"], label="initialise:intent:unlink")
        event("fsync", fd=STATE, label="initialise:intent:cleanup-sync")
    publication("initialise:intent", "vol-a.intent.tmp", "vol-a.intent", "renameat")
    publication("initialise:log", "vol-a.log.tmp", "vol-a.log", "linkat", anchor=True)
    publication("initialise:clean", "MARKER.tmp", "MARKER", marker_publish)
    event("openat", paths=["/control/lifecycle-returned-initialise"], ret=4, creat=True,
          label="initialise:return")
    publication("unfence:clean", "MARKER.tmp", "MARKER", marker_publish)
    event("openat", paths=["/control/lifecycle-returned-unfence"], ret=4, creat=True,
          label="unfence:return")
    return events


def pos(events, label):
    return next(i for i, e in enumerate(events) if e.get("label") == label)


class LifecycleControls(unittest.TestCase):
    def green(self, marker_publish="renameat", intent_cleanup=False):
        events = fixture(marker_publish, intent_cleanup=intent_cleanup)
        fail, counts = checker.check_lifecycle(events, STATE)
        self.assertEqual((fail, counts["verbs_returned"]), ([], 2))
        return events

    def test_marker_renameat2_and_log_link_only(self):
        self.green("renameat2")
        events = self.green()
        at = pos(events, "initialise:log:publish")
        events[at]["name"] = "renameat2"
        events[at]["raw"] = "0"
        fail, counts = checker.check_lifecycle(events, STATE)
        self.assertIn("initialise: wrong publication operation or source", fail)
        self.assertEqual(counts["verbs_returned"], 2)

    def test_directory_syncs_refuse_the_wrong_directory(self):
        for name, verb, stage in [
            ("initialise:running:state-sync", "initialise", "state-sync"),
            ("initialise:running:anchor-sync", "initialise", "anchor-sync"),
            ("initialise:intent:state-sync", "initialise", "state-sync"),
            ("initialise:log:state-sync", "initialise", "state-sync"),
            ("initialise:log:anchor-sync", "initialise", "anchor-sync"),
            ("initialise:clean:state-sync", "initialise", "state-sync"),
            ("unfence:clean:state-sync", "unfence", "state-sync"),
        ]:
            with self.subTest(verb=verb, stage=stage, event=name):
                events = self.green()
                at = pos(events, name)
                events[at]["fd_path"] = "/elsewhere"
                fail, counts = checker.check_lifecycle(events, STATE)
                self.assertTrue(any(f.startswith(f"{verb}: publication sequence") for f in fail), fail)
                self.assertEqual(counts["verbs_returned"], 2)

    def test_each_publication_stage_has_a_malformed_counterpart(self):
        base_events = fixture()
        return_at = pos(base_events, "initialise:return")
        for at in range(len(base_events)):
            with self.subTest(stage=at, label=base_events[at].get("label")):
                events = self.green()
                events.pop(at)
                fail, counts = checker.check_lifecycle(events, STATE)
                verb = "initialise" if at <= return_at else "unfence"
                self.assertTrue(any(f.startswith(f"{verb}: publication sequence") or f == f"{verb}: no observed return" for f in fail), fail)
                self.assertGreater(counts["verbs_returned"], 0)

    def test_exclusive_create_and_link_have_specific_refusals(self):
        for label in (
            "initialise:running:create",
            "initialise:intent:create",
            "initialise:log:create",
            "initialise:clean:create",
            "unfence:clean:create",
        ):
            with self.subTest(stage=label):
                events = self.green()
                at = pos(events, label)
                events[at]["raw"] = "O_CREAT"
                fail, counts = checker.check_lifecycle(events, STATE)
                self.assertTrue(any("temporary creation lacks O_CREAT|O_EXCL" in f for f in fail), fail)
                self.assertEqual(counts["verbs_returned"], 2)
        events = self.green()
        at = pos(events, "initialise:log:publish")
        events[at]["name"] = "renameat"
        fail, counts = checker.check_lifecycle(events, STATE)
        self.assertIn("initialise: wrong publication operation or source", fail)
        self.assertEqual(counts["verbs_returned"], 2)

    def test_rename_before_file_sync_refuses(self):
        for role in ("running", "intent", "clean"):
            with self.subTest(role=role):
                events = self.green()
                sync_at = pos(events, f"initialise:{role}:file-sync")
                publish_at = pos(events, f"initialise:{role}:publish")
                events[sync_at], events[publish_at] = events[publish_at], events[sync_at]
                fail, counts = checker.check_lifecycle(events, STATE)
                self.assertTrue(any(f.endswith("renamed before its temporary was synced") for f in fail), fail)
                self.assertEqual(counts["verbs_returned"], 2)

    def test_intent_cleanup_prefix_and_arbitrary_extra_sync(self):
        # 1. Valid cleanup prefix (unlink leftover temporary then state-dir sync): ACCEPTED
        cleanup_events = fixture(intent_cleanup=True)
        fail, counts = checker.check_lifecycle(cleanup_events, STATE)
        self.assertEqual((fail, counts["verbs_returned"]), ([], 2))

        # 2. Arbitrary extra sync without unlink: REFUSED
        extra_sync_events = self.green()
        intent_create = pos(extra_sync_events, "initialise:intent:create")
        extra_sync_events.insert(intent_create, dict(name="fsync", fd_path=STATE, paths=[], ret=0,
                                                     ret_path=None, raw="", creat=False, label="extra-sync"))
        fail, counts = checker.check_lifecycle(extra_sync_events, STATE)
        self.assertTrue(any(f.startswith("initialise: publication sequence") for f in fail), fail)
        self.assertEqual(counts["verbs_returned"], 2)

        # 3. Unlink of intent temporary without state-dir sync before create: REFUSED
        missing_sync_events = self.green()
        intent_create = pos(missing_sync_events, "initialise:intent:create")
        missing_sync_events.insert(intent_create, dict(name="unlinkat", fd_path=None,
                                                       paths=[f"{STATE}/vol-a.intent.tmp"], ret=0,
                                                       ret_path=None, raw="", creat=False, label="cleanup-unlink"))
        fail, counts = checker.check_lifecycle(missing_sync_events, STATE)
        self.assertTrue(any(f.startswith("initialise: publication sequence") for f in fail), fail)
        self.assertEqual(counts["verbs_returned"], 2)

    def test_temporary_writes_and_file_syncs_use_the_active_file(self):
        base_events = fixture()
        return_at = pos(base_events, "initialise:return")
        for label, stage in [
            ("initialise:running:write", "write"),
            ("initialise:running:file-sync", "file-sync"),
            ("initialise:intent:write", "write"),
            ("initialise:intent:file-sync", "file-sync"),
            ("initialise:log:write", "write"),
            ("initialise:log:file-sync", "file-sync"),
            ("initialise:clean:write", "write"),
            ("initialise:clean:file-sync", "file-sync"),
            ("unfence:clean:write", "write"),
            ("unfence:clean:file-sync", "file-sync"),
        ]:
            with self.subTest(stage=stage, label=label):
                events = self.green()
                at = pos(events, label)
                target = events[at]["fd_path"]
                events[at]["fd_path"] = f"{STATE}/vol-a.log.tmp" if target.endswith("MARKER.tmp") else f"{STATE}/MARKER.tmp"
                fail, counts = checker.check_lifecycle(events, STATE)
                verb = "initialise" if at <= return_at else "unfence"
                self.assertIn(f"{verb}: {stage} targets the wrong temporary", fail)
                self.assertEqual(counts["verbs_returned"], 2)

    def test_return_identity_is_the_control_directory(self):
        events = self.green()
        at = pos(events, "initialise:return")
        events[at]["paths"] = ["/elsewhere/lifecycle-returned-initialise"]
        fail, counts = checker.check_lifecycle(events, STATE)
        self.assertIn("initialise: no observed return", fail)
        self.assertGreater(counts["verbs_returned"], 0)

    def test_failed_sync_and_empty_trace_refuse(self):
        base_events = fixture()
        return_at = pos(base_events, "initialise:return")
        parent = STATE.rsplit("/", 1)[0]
        sync_positions = [i for i, e in enumerate(base_events) if e["name"] in ("fsync", "fdatasync")]
        for at in sync_positions:
            with self.subTest(event=at, label=base_events[at].get("label")):
                events = self.green()
                events[at]["ret"] = -1
                fail, counts = checker.check_lifecycle(events, STATE)
                verb = "initialise" if at <= return_at else "unfence"
                target = events[at]["fd_path"]
                stage = "file-sync" if target.endswith(".tmp") else "anchor-sync" if target == parent else "state-sync"
                self.assertIn(f"{verb}: failed {stage}", fail)
                self.assertEqual(counts["verbs_returned"], 2)
        fail, counts = checker.check_lifecycle([], STATE)
        self.assertIn("lifecycle: both verb identities must return", fail)
        self.assertEqual(counts["verbs_returned"], 0)

    def test_log_calls_before_running_and_swapped_publications_refuse(self):
        for early in [dict(name="unlinkat", fd_path=None, paths=[f"{STATE}/vol-a.log.tmp"], ret=-1, ret_path=None, raw="", creat=False),
                      dict(name="openat", fd_path=None, paths=[f"{STATE}/vol-a.log"], ret=-1, ret_path=None, raw="", creat=False)]:
            events = self.green()
            events.insert(0, early)
            fail, counts = checker.check_lifecycle(events, STATE)
            self.assertIn("initialise: log call before durable running marker", fail)
            self.assertEqual(counts["verbs_returned"], 2)
        events = self.green()
        running_end = pos(events, "initialise:running:anchor-sync") + 1
        intent_end = pos(events, "initialise:intent:state-sync") + 1
        events[:intent_end] = events[running_end:intent_end] + events[:running_end]
        fail, counts = checker.check_lifecycle(events, STATE)
        self.assertTrue(any(f.startswith("initialise: publication sequence") for f in fail), fail)
        self.assertEqual(counts["verbs_returned"], 2)

    def test_cli_wiring_and_unreadable_trace(self):
        self.green()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace"
            command = [sys.executable, str(Path(checker.__file__)), "lifecycle", STATE, str(path)]
            for marker_publish in ("renameat", "renameat2"):
                for cleanup in (False, True):
                    lines = []
                    for e in fixture(marker_publish, intent_cleanup=cleanup):
                        if e["name"] == "openat":
                            p = e["paths"][0]
                            lines.append(f'1 openat(AT_FDCWD, "{p}", O_CREAT|O_EXCL) = 3<{e["ret_path"] or p}>')
                        elif e["name"] == "pwrite64":
                            lines.append(f'1 pwrite64(3<{e["fd_path"]}>, "0123456789", 10, 0) = 10')
                        elif e["name"] == "fsync":
                            lines.append(f'1 fsync(3<{e["fd_path"]}>) = 0')
                        else:
                            args = ", ".join(f'AT_FDCWD, "{p}"' for p in e["paths"])
                            if e["name"] == "renameat2":
                                args += ", 0"
                            lines.append(f'1 {e["name"]}({args}) = 0')
                    path.write_text("\n".join(lines))
                    result = subprocess.run(command, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("'verbs_returned': 2", result.stdout)
            path.write_text("unparsed input")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("both verb identities must return", result.stdout)
            path.unlink()
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("trace could not be read", result.stdout)


if __name__ == "__main__":
    unittest.main()
