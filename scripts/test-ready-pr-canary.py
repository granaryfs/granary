#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Controls for the default-branch ready PR canary reader."""

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from email.message import Message
from types import SimpleNamespace

import cmarkgfm
from cmarkgfm.cmark import Options


SCRIPT = Path(__file__).resolve().with_name("run-ready-pr-canary.py")
SPEC = importlib.util.spec_from_file_location("ready_pr_canary", SCRIPT)
CANARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CANARY
SPEC.loader.exec_module(CANARY)
GUARD_SPEC = importlib.util.spec_from_file_location("ready_canary_guard", SCRIPT.with_name("check-fork-guard.py"))
GUARD = importlib.util.module_from_spec(GUARD_SPEC)
sys.modules[GUARD_SPEC.name] = GUARD
GUARD_SPEC.loader.exec_module(GUARD)
WORKFLOW = SCRIPT.parent.parent / ".github/workflows/ready-pr-metadata-canary.yml"
VALID = "Canary description.\n\nTask: #5\nClass: E\nAssisted-by: Test tool"
INVALID = "Canary description.\n\nTask: #5\nAssisted-by: Test tool"


def rendered(body):
    return cmarkgfm.github_flavored_markdown_to_html(
        body, Options.CMARK_OPT_UNSAFE | Options.CMARK_OPT_HARDBREAKS,
    )


def listing(nodes, more=False):
    return {"data": {"repository": {"nameWithOwner": "granaryfs/granary",
                                    "pullRequests": {"pageInfo": {"hasNextPage": more},
                                                     "nodes": nodes}}}}


def pair(number, body=VALID, state="OPEN", draft=False):
    return {"data": {"repository": {"nameWithOwner": "granaryfs/granary",
                                    "pullRequest": {"number": number, "state": state,
                                                    "isDraft": draft, "body": body,
                                                    "bodyHTML": rendered(body)}}}}


class ReadyCanaryTests(unittest.TestCase):
    def test_reader_invocation_disables_source_bytecode(self):
        sample = WORKFLOW.read_text().split("      - name: Sample ready PR metadata\n", 1)[1]
        self.assertIn('"$venv_python" -I -B scripts/run-ready-pr-canary.py', sample)

    def test_missing_checker_is_unavailable_not_policy_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / SCRIPT.name
            shutil.copy2(SCRIPT, script)
            spec = importlib.util.spec_from_file_location("missing_canary_checker", script)
            missing = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = missing
            spec.loader.exec_module(missing)
            self.assertIsNone(missing.CHECKER)
            env = dict(GITHUB_EVENT_NAME="schedule", GITHUB_REF="refs/heads/main",
                       GITHUB_REPOSITORY="granaryfs/granary", GITHUB_SHA="a" * 40,
                       GITHUB_TOKEN="synthetic-token")
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(missing.subprocess, "run", return_value=SimpleNamespace(stdout="a" * 40 + "\n")), \
                 patch.object(missing, "fetch", return_value=listing([])) as fetched:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(missing.main(), 3)
                self.assertEqual(json.loads(output.getvalue())["reason"], "SETUP")
                fetched.assert_not_called()

    def test_main_context_and_checkout_guard_precede_api(self):
        good = dict(GITHUB_EVENT_NAME="schedule", GITHUB_REF="refs/heads/main",
                    GITHUB_REPOSITORY="granaryfs/granary", GITHUB_SHA="a" * 40,
                    GITHUB_TOKEN="synthetic-token")
        changes = ({"GITHUB_EVENT_NAME": "workflow_dispatch"}, {"GITHUB_REF": "refs/heads/topic"},
                   {"GITHUB_REPOSITORY": "other/repo"}, {"GITHUB_SHA": "short"},
                   {"GITHUB_TOKEN": "bad token"})
        for changed in changes:
            with self.subTest(changed=changed), patch.dict(os.environ, good | changed, clear=True), \
                 patch.object(CANARY, "fetch", side_effect=AssertionError("API reached")), \
                 patch.object(CANARY.subprocess, "run", side_effect=AssertionError("git reached")):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(CANARY.main(), 3)
                self.assertEqual(json.loads(output.getvalue())["reason"], "CONTEXT")
        with patch.dict(os.environ, good, clear=True), \
             patch.object(CANARY, "fetch", return_value=listing([])) as fetched, \
             patch.object(CANARY.subprocess, "run", return_value=SimpleNamespace(stdout="b" * 40 + "\n")):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(CANARY.main(), 3)
            self.assertEqual(json.loads(output.getvalue())["reason"], "SETUP")
            fetched.assert_not_called()
        with patch.dict(os.environ, good, clear=True), \
             patch.object(CANARY, "fetch", return_value=listing([])) as fetched, \
             patch.object(CANARY.subprocess, "run", return_value=SimpleNamespace(stdout="a" * 40 + "\n")):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(CANARY.main(), 0)
            self.assertEqual(json.loads(output.getvalue())["reason"], "NO_OPEN_PRS")
            self.assertEqual(fetched.call_count, 1)

    def test_empty_listing_is_explicitly_not_a_content_verdict(self):
        output = io.StringIO()
        self.assertEqual(CANARY.run(lambda _name, _vars: listing([]), "granaryfs/granary", output), 0)
        row = json.loads(output.getvalue())
        self.assertEqual((row["status"], row["reason"]), ("SKIPPED", "NO_OPEN_PRS"))

    def test_fetch_rejects_transport_and_response_anomalies(self):
        raw = json.dumps(listing([])).encode()
        class Response:
            def __init__(self, status=200, content_type="application/json", length=None,
                         encoding=None, body=raw):
                self.status = status
                self.body = body
                self.headers = Message()
                self.headers["Content-Type"] = content_type
                if length is not None:
                    self.headers["Content-Length"] = length
                if encoding is not None:
                    self.headers["Content-Encoding"] = encoding
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, amount):
                self.requested = amount
                return self.body[:amount]
        class Connection:
            def __init__(self, response): self.response = response
            def request(self, method, path, payload, headers):
                self.request_data = (method, path, payload, headers)
            def getresponse(self): return self.response
            def close(self): pass
        def call(response):
            conn = Connection(response)
            with patch.object(CANARY.http.client, "HTTPSConnection", return_value=conn), \
                 patch.object(CANARY.ssl, "create_default_context", return_value=object()):
                result = CANARY.fetch(CANARY.LIST_QUERY, {"owner": "granaryfs", "name": "granary"},
                                      "synthetic-token")
            return result, conn
        result, conn = call(Response(length=str(len(raw))))
        self.assertEqual(result, listing([]))
        self.assertEqual(conn.request_data[:2], ("POST", "/graphql"))
        self.assertEqual(conn.response.requested, CANARY.MAX_RESPONSE + 1)
        for response in (Response(status=302), Response(status=500),
                         Response(content_type="text/html"), Response(length="wrong"),
                         Response(length="1"), Response(length=str(CANARY.MAX_RESPONSE + 1)),
                         Response(encoding="gzip"),
                         Response(body=b"{" * (CANARY.MAX_RESPONSE + 1))):
            with self.subTest(response=response.__dict__), self.assertRaises(CANARY.Unavailable):
                call(response)

    def test_public_guard_cli_rejects_changed_bytes_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            guard = root / "scripts/check-fork-guard.py"
            copied = workflows / WORKFLOW.name
            shutil.copy2(GUARD_SPEC.origin, guard)
            shutil.copy2(WORKFLOW, copied)
            command = [sys.executable, "-I", str(guard), "--public"]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            copied.write_bytes(copied.read_bytes() + b"\n")
            changed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(changed.returncode, 1)
            self.assertIn("differs from reviewed bytes", changed.stderr)
            self.assertNotIn("Traceback", changed.stderr)
            copied.unlink()
            copied.symlink_to(WORKFLOW)
            linked = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(linked.returncode, 1)
            self.assertIn("workflow must be a regular file", linked.stderr)
            self.assertNotIn("Traceback", linked.stderr)

    def test_exact_workflow_exception_rejects_mutations_and_other_paths(self):
        text = WORKFLOW.read_text()
        self.assertEqual(GUARD.check_workflow(WORKFLOW.name, text, public=True, path=WORKFLOW), (1, 0))
        mutations = (
            text + "\n",
            text.replace("schedule:", "workflow_dispatch:", 1),
            text.replace("pull-requests: read", "pull-requests: write", 1),
            text.replace("GITHUB_TOKEN: ${{ github.token }}", "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}", 1),
            text.replace("ref: ${{ github.sha }}", "ref: ${{ github.event.pull_request.head.sha }}", 1),
            text.replace("persist-credentials: false", "persist-credentials: true", 1),
            text.replace("    runs-on: ubuntu-24.04", "    runs-on: self-hosted", 1),
            text.replace("  sample:\n", "  sample:\n    if: always()\n", 1),
            text.replace("  schedule:\n", "  pull_request_target:\n", 1),
            text.replace("      - name: Sample ready PR metadata", "      - run: echo extra\n      - name: Sample ready PR metadata", 1),
            text.replace("permissions: {}", "permissions: { contents: write }", 1),
        )
        for mutated in mutations:
            with self.subTest(mutated=mutated), self.assertRaises(ValueError):
                GUARD.check_workflow(WORKFLOW.name, mutated, public=True, path=WORKFLOW)
        with self.assertRaises(ValueError):
            GUARD.check_workflow(WORKFLOW.name, text, public=True, path=WORKFLOW.with_name("other.yml"))

    def test_reviewed_exception_preserves_independent_structural_rules(self):
        text = WORKFLOW.read_text()
        harmless = text + "\n# harmless comment\n"
        with patch.object(GUARD, "CANARY_SHA256", hashlib.sha256(harmless.encode()).hexdigest()):
            self.assertEqual(GUARD.check_workflow(WORKFLOW.name, harmless, public=True,
                                                  path=WORKFLOW), (1, 0))
        mutations = (
            (text.replace("pull-requests: read", "pull-requests: write", 1), "explicit and read-only"),
            (text.replace("    runs-on: ubuntu-24.04", "    runs-on: self-hosted", 1), "literal standard hosted runner"),
            (text.replace("  sample:\n", "  sample:\n    if: always()\n", 1), "public workers must be unconditional"),
            (text.replace("persist-credentials: false", "persist-credentials: true", 1), "disable persisted credentials"),
            (text.replace("permissions: {}", "permissions: { contents: write }", 1), "workflow permissions must be empty"),
            (text.replace("  schedule:\n", "  pull_request_target:\n", 1), "names pull_request_target"),
        )
        for changed, diagnostic in mutations:
            with self.subTest(changed=changed), \
                 patch.object(GUARD, "CANARY_SHA256", hashlib.sha256(changed.encode()).hexdigest()):
                with self.assertRaisesRegex(ValueError, diagnostic):
                    GUARD.check_workflow(WORKFLOW.name, changed, public=True, path=WORKFLOW)

    def test_decode_requires_complete_unambiguous_json(self):
        self.assertEqual(CANARY.decode(200, "application/json", b'{"data":{}}'), {"data": {}})
        for status, content_type, raw in (
            (301, "application/json", b'{}'),
            (200, "text/html", b'{}'),
            (200, "application/json", b'\xff'),
            (200, "application/json", b'{"data":{},"data":{}}'),
            (200, "application/json", b'{"data":{"x":1,"x":2}}'),
            (200, "application/json", b'{"data":NaN}'),
            (200, "application/json", b'{"errors":[{}],"data":{}}'),
            (200, "application/json", b'{}'),
        ):
            with self.subTest(status=status, raw=raw), self.assertRaises(CANARY.Unavailable):
                CANARY.decode(status, content_type, raw)

    def test_listing_must_be_complete_and_distinct(self):
        self.assertEqual(CANARY.parse_listing(listing([]), "granaryfs/granary"), ())
        nodes = [{"number": 1, "isDraft": True}, {"number": 2, "isDraft": False}]
        self.assertEqual(CANARY.parse_listing(listing(nodes), "granaryfs/granary"), ((1, True), (2, False)))
        for value in (
            listing(nodes, more=True), listing(nodes + nodes[:1]),
            listing([{"number": True, "isDraft": False}]),
            listing([{"number": 1, "isDraft": 0}]),
            listing([{"number": 0, "isDraft": False}]),
            listing([{"number": n, "isDraft": False} for n in range(1, 22)]),
            {"data": {"repository": None}},
        ):
            with self.subTest(value=value), self.assertRaises(CANARY.Unavailable):
                CANARY.parse_listing(value, "granaryfs/granary")

    def test_pair_requires_one_current_body_and_html(self):
        self.assertEqual(CANARY.parse_pair(pair(7), "granaryfs/granary", 7), (VALID, rendered(VALID)))
        for value in (
            pair(8),
            {"data": {"repository": {"nameWithOwner": "other/repo", "pullRequest": pair(7)["data"]["repository"]["pullRequest"]}}},
            {"data": {"repository": {"nameWithOwner": "granaryfs/granary", "pullRequest": None}}},
            {"data": {"repository": {"nameWithOwner": "granaryfs/granary", "pullRequest": {"number": 7, "body": VALID}}}},
        ):
            with self.subTest(value=value), self.assertRaises(CANARY.Unavailable):
                CANARY.parse_pair(value, "granaryfs/granary", 7)
        for value in (pair(7, state="CLOSED"), pair(7, state="MERGED"), pair(7, draft=True)):
            with self.subTest(value=value), self.assertRaises(CANARY.ChangedState):
                CANARY.parse_pair(value, "granaryfs/granary", 7)
        with self.assertRaises(CANARY.Unavailable):
            CANARY.parse_pair(pair(7, state="BOGUS"), "granaryfs/granary", 7)

    def test_oversized_body_is_policy_refusal_after_valid_transport(self):
        body = "A" * (CANARY.CHECKER.BODY_BYTES + 1) + "\n\nClass: E\nAssisted-by: Test tool"
        def query(name, _variables):
            return listing([{"number": 7, "isDraft": False}]) if name == "list" else pair(7, body)
        output = io.StringIO()
        self.assertEqual(CANARY.run(query, "granaryfs/granary", output), 1)
        row = json.loads(output.getvalue())
        self.assertEqual((row["status"], row["reason"]), ("REFUSED", "POLICY"))

    def test_source_origin_and_viewer_html_are_each_required(self):
        good_html = rendered(VALID)
        source_hidden = "Canary description.\n\n```\n\nTask: #5\nClass: E\nAssisted-by: Test tool"
        _normalized, _first, _last, block, class_at = CANARY.CHECKER.terminal(source_hidden)
        CANARY.CHECKER.check_body_html(good_html, block, class_at)
        self.assertEqual(CANARY.classify(source_hidden, good_html), "REFUSED")
        with patch.object(CANARY.CHECKER, "local_origin", return_value=None):
            self.assertEqual(CANARY.classify(source_hidden, good_html), "PASS")
        bad_html = good_html.replace("Assisted-by: Test tool", "Assisted-by: Other tool")
        CANARY.CHECKER.local_origin(VALID)
        self.assertEqual(CANARY.classify(VALID, bad_html), "REFUSED")
        with patch.object(CANARY.CHECKER, "check_body_html", return_value=()):
            self.assertEqual(CANARY.classify(VALID, bad_html), "PASS")

    def test_state_change_after_listing_is_skip_not_content_verdict(self):
        def query(name, variables):
            return listing([{"number": 7, "isDraft": False}]) if name == "list" else pair(7, draft=True)
        output = io.StringIO()
        self.assertEqual(CANARY.run(query, "granaryfs/granary", output), 0)
        self.assertEqual(json.loads(output.getvalue())["reason"], "STATE_CHANGED")

    def test_checker_crash_is_per_pr_unavailable_and_scan_continues(self):
        seen = []
        def query(name, variables):
            if name == "list":
                return listing([{"number": 7, "isDraft": False}, {"number": 8, "isDraft": False}])
            seen.append(variables["number"])
            return pair(variables["number"])
        output = io.StringIO()
        with patch.object(CANARY.CHECKER, "check_body_html", side_effect=[IndexError("synthetic"), ()]):
            self.assertEqual(CANARY.run(query, "granaryfs/granary", output), 3)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(seen, [7, 8])
        self.assertEqual([(row["number"], row["status"], row["reason"]) for row in rows],
                         [(7, "UNAVAILABLE", "CHECKER"), (8, "PASS", "OK")])

    def test_classification_reuses_landed_checker(self):
        self.assertEqual(CANARY.classify(VALID, rendered(VALID)), "PASS")
        self.assertEqual(CANARY.classify(INVALID, rendered(INVALID)), "REFUSED")
        with self.assertRaises(CANARY.Unavailable):
            CANARY.classify(VALID, None)

    def test_run_skips_drafts_records_hashes_and_hides_untrusted_text(self):
        calls = []
        hostile = INVALID + "\n::error::secret-value"
        def query(name, variables):
            calls.append((name, variables))
            if name == "list":
                return listing([{"number": 11, "isDraft": True},
                                {"number": 12, "isDraft": False},
                                {"number": 13, "isDraft": False}])
            return pair(variables["number"], VALID if variables["number"] == 12 else hostile)
        output = io.StringIO()
        self.assertEqual(CANARY.run(query, "granaryfs/granary", output), 1)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([row["status"] for row in rows], ["SKIPPED", "PASS", "REFUSED"])
        self.assertEqual([call[0] for call in calls], ["list", "pair", "pair"])
        self.assertEqual([call[1].get("number") for call in calls[1:]], [12, 13])
        self.assertNotIn("secret-value", output.getvalue())
        self.assertNotIn("::error::", output.getvalue())
        self.assertEqual(set(rows[1]), {"number", "status", "reason", "body_sha256", "body_html_sha256"})

    def test_listing_unavailable_does_not_process_partial_page(self):
        calls = []
        def query(name, variables):
            calls.append(name)
            return listing([{"number": 7, "isDraft": False}], more=True)
        output = io.StringIO()
        self.assertEqual(CANARY.run(query, "granaryfs/granary", output), 3)
        self.assertEqual(calls, ["list"])
        self.assertEqual(json.loads(output.getvalue())["status"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
