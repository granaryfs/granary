#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Offline controls for the trusted event-aware PR metadata sampler."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
from types import SimpleNamespace
from unittest.mock import patch

import cmarkgfm
from cmarkgfm.cmark import Options


SCRIPT = Path(__file__).with_name("run-ready-pr-event-canary.py")
SPEC = importlib.util.spec_from_file_location("ready_pr_event_canary", SCRIPT)
CANARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CANARY
SPEC.loader.exec_module(CANARY)
BODY = "A bounded event observation.\n\nTask: #5\nClass: E\nAssisted-by: test tool"
HEAD = "a" * 40
BASE = "b" * 40
ROW_KEYS = {"status", "reason", "run_id", "attempt", "workflow_sha", "action", "number",
            "event_head", "current_head", "event_body_null", "event_body_sha256",
            "current_body_sha256", "current_body_html_sha256"}


def event(body=BODY, draft=False, action="opened"):
    return {"action": action, "number": 16,
            "repository": {"full_name": "granaryfs/granary"},
            "pull_request": {"number": 16, "state": "open", "draft": draft, "body": body,
                             "head": {"sha": HEAD},
                             "base": {"sha": BASE, "ref": "main",
                                      "repo": {"full_name": "granaryfs/granary"}}}}


def current(body=BODY, draft=False):
    html = cmarkgfm.github_flavored_markdown_to_html(
        body, Options.CMARK_OPT_UNSAFE | Options.CMARK_OPT_HARDBREAKS)
    return {"data": {"repository": {"nameWithOwner": "granaryfs/granary",
                                    "pullRequest": {"number": 16, "state": "OPEN",
                                                    "isDraft": draft, "headRefOid": HEAD,
                                                    "baseRefOid": BASE, "baseRefName": "main",
                                                    "body": body, "bodyHTML": html}}}}


class EventCanaryTests(unittest.TestCase):
    def observe(self, payload=None, reply=None):
        payload = event() if payload is None else payload
        reply = current() if reply is None else reply
        out = io.StringIO()
        calls = []
        def query(variables):
            calls.append(variables)
            return reply
        ambient_stdout, ambient_stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(ambient_stdout), redirect_stderr(ambient_stderr):
            code = CANARY.run(payload, query, out, run_id=71, attempt=2,
                              workflow_sha="c" * 40)
        self.assertEqual(ambient_stdout.getvalue(), "")
        self.assertEqual(ambient_stderr.getvalue(), "")
        rows = out.getvalue().splitlines()
        self.assertEqual(len(rows), 1)
        row = json.loads(rows[0])
        self.assertEqual(set(row), ROW_KEYS)
        return code, row, calls, out.getvalue()

    def test_ready_pair_and_one_exact_query(self):
        code, row, calls, output = self.observe()
        self.assertEqual((code, row["status"], row["reason"]), (0, "PASS", "OK"))
        self.assertEqual(calls, [{"owner": "granaryfs", "name": "granary", "number": 16}])
        self.assertEqual(row["event_body_sha256"], hashlib.sha256(BODY.encode()).hexdigest())
        self.assertEqual(row["current_body_sha256"], row["event_body_sha256"])
        self.assertEqual(row["action"], "opened")
        self.assertNotIn(BODY, output)
        self.assertIs(row["event_body_null"], False)

    def test_single_line_untrusted_text_is_absent_from_output(self):
        secret = "single-line-attacker-marker"
        code, row, _, output = self.observe(event(secret), current(secret))
        self.assertEqual((code, row["reason"]), (1, "POLICY"))
        self.assertNotIn(secret, output)
        reply = current()
        reply["data"]["repository"]["pullRequest"]["bodyHTML"] = "<p>" + secret + "</p>"
        code, row, _, output = self.observe(event(), reply)
        self.assertEqual((code, row["reason"]), (1, "POLICY"))
        self.assertNotIn(secret, output)

    def test_source_policy_and_viewer_policy_are_both_enforced(self):
        bad = "A bounded event observation.\n\nAssisted-by: test tool"
        code, row, _, _ = self.observe(event(bad), current(bad))
        self.assertEqual((code, row["status"], row["reason"]), (1, "REFUSED", "POLICY"))
        html_bad = current()
        html_bad["data"]["repository"]["pullRequest"]["bodyHTML"] = "<p>hidden</p>"
        code, row, _, _ = self.observe(event(), html_bad)
        self.assertEqual((code, row["status"], row["reason"]), (1, "REFUSED", "POLICY"))
        hidden_assistance = BODY + "\n<!-- Assisted-by: hidden -->"
        code, row, _, _ = self.observe(event(hidden_assistance), current(hidden_assistance))
        self.assertEqual((code, row["status"], row["reason"]), (1, "REFUSED", "POLICY"))

    def test_draft_and_action_matrix(self):
        for action in ("opened", "edited", "synchronize", "reopened", "converted_to_draft"):
            with self.subTest(action=action):
                code, row, calls, _ = self.observe(event("", True, action), current("", True))
                self.assertEqual((code, row["status"], row["reason"]), (0, "SKIPPED", "DRAFT"))
                self.assertEqual(len(calls), 1)
        code, row, _, _ = self.observe(event(BODY, False, "ready_for_review"), current())
        self.assertEqual((code, row["status"]), (0, "PASS"))
        code, row, _, _ = self.observe(event(BODY, False, "reopened"), current())
        self.assertEqual((code, row["status"]), (0, "PASS"))

    def test_null_webhook_body_has_explicit_empty_equivalence(self):
        code, row, calls, _ = self.observe(event(None, True), current("", True))
        self.assertEqual((code, row["status"], row["reason"], len(calls)),
                         (0, "SKIPPED", "DRAFT", 1))
        self.assertIs(row["event_body_null"], True)
        self.assertIsNone(row["event_body_sha256"])
        self.assertEqual(row["current_body_sha256"], hashlib.sha256(b"").hexdigest())
        code, row, calls, _ = self.observe(event(None), current(""))
        self.assertEqual((code, row["status"], row["reason"], len(calls)),
                         (1, "REFUSED", "POLICY", 1))
        code, row, calls, _ = self.observe(event(None), current("nonempty"))
        self.assertEqual((code, row["status"], row["reason"], len(calls)),
                         (3, "UNAVAILABLE", "STALE", 1))

    def test_fixed_head_edit_sequence_and_new_head_synchronize(self):
        bad = "A bounded event observation.\n\nAssisted-by: test tool"
        outcomes = []
        for body in (bad, BODY, bad, BODY):
            code, row, calls, _ = self.observe(event(body, action="edited"), current(body))
            outcomes.append((code, row["status"], row["event_head"]))
            self.assertEqual(len(calls), 1)
        self.assertEqual(outcomes, [(1, "REFUSED", HEAD), (0, "PASS", HEAD),
                                    (1, "REFUSED", HEAD), (0, "PASS", HEAD)])
        payload, reply = event(action="synchronize"), current()
        payload["pull_request"]["head"]["sha"] = "d" * 40
        reply["data"]["repository"]["pullRequest"]["headRefOid"] = "d" * 40
        code, row, _, _ = self.observe(payload, reply)
        self.assertEqual((code, row["status"], row["event_head"]), (0, "PASS", "d" * 40))

    def test_each_current_identity_or_state_mismatch_is_stale_without_policy_call(self):
        changes = {"nameWithOwner": "other/repo", "number": 17, "state": "CLOSED",
                   "isDraft": True, "headRefOid": "d" * 40, "baseRefOid": "e" * 40,
                   "baseRefName": "release", "body": BODY + "\n"}
        for field, value in changes.items():
            with self.subTest(field=field):
                reply = current()
                node = reply["data"]["repository"]
                target = node if field == "nameWithOwner" else node["pullRequest"]
                target[field] = value
                with patch.object(CANARY.CHECKER, "local_origin", side_effect=AssertionError("content called")):
                    code, row, calls, _ = self.observe(event(), reply)
                self.assertEqual((code, row["status"], row["reason"]), (3, "UNAVAILABLE", "STALE"))
                self.assertEqual(len(calls), 1)

    def test_event_identity_comparisons_and_draft_mismatch(self):
        changes = (("head", "sha", "d" * 40), ("base", "sha", "e" * 40))
        for group, field, value in changes:
            with self.subTest(group=group):
                payload = event()
                payload["pull_request"][group][field] = value
                code, row, calls, _ = self.observe(payload)
                self.assertEqual((code, row["reason"], len(calls)), (3, "STALE", 1))
        for payload, reply in ((event(BODY, True), current(BODY, False)),
                               (event(BODY + "\n"), current(BODY))):
            code, row, calls, _ = self.observe(payload, reply)
            self.assertEqual((code, row["reason"], len(calls)), (3, "STALE", 1))

    def test_invalid_event_is_context_without_query_or_raw_echo(self):
        for field, value in (("action", "closed"), ("number", True),
                             ("repository", {"full_name": "other/repo"})):
            with self.subTest(field=field):
                payload = event()
                payload[field] = value
                code, row, calls, output = self.observe(payload)
                self.assertEqual((code, row["reason"]), (3, "CONTEXT"))
                self.assertEqual(calls, [])
                self.assertNotIn(BODY, output)
        for action, draft in (("ready_for_review", True), ("converted_to_draft", False)):
            code, row, calls, _ = self.observe(event(BODY, draft, action))
            self.assertEqual((code, row["reason"], calls), (3, "CONTEXT", []))
        mutations = (("pull_request", "number", 17), ("pull_request", "state", "closed"),
                     ("pull_request", "draft", 1), ("head", "sha", "not-an-oid"),
                     ("base", "sha", "not-an-oid"), ("base", "ref", "release"),
                     ("base_repo", "full_name", "other/repo"))
        for target, field, value in mutations:
            with self.subTest(target=target, field=field):
                payload = event()
                node = payload["pull_request"]
                if target == "base_repo":
                    node = node["base"]["repo"]
                elif target != "pull_request":
                    node = node[target]
                node[field] = value
                code, row, calls, _ = self.observe(payload)
                self.assertEqual((code, row["reason"], calls), (3, "CONTEXT", []))

    def test_draft_snapshot_must_still_be_current(self):
        for field, value in (("body", "changed"), ("headRefOid", "d" * 40),
                             ("baseRefOid", "e" * 40), ("state", "CLOSED")):
            with self.subTest(field=field):
                reply = current("", True)
                reply["data"]["repository"]["pullRequest"][field] = value
                code, row, _, _ = self.observe(event("", True), reply)
                self.assertEqual((code, row["reason"]), (3, "STALE"))

    def test_query_error_is_unavailable_without_echo(self):
        reply = current()
        reply["errors"] = [{"message": "secret marker"}]
        code, row, calls, output = self.observe(event(), reply)
        self.assertEqual((code, row["reason"]), (3, "QUERY"))
        self.assertEqual(len(calls), 1)
        self.assertNotIn("secret marker", output)
        for reply in ([], {"data": {"repository": None}},
                      {"data": {"repository": {"pullRequest": None}}}):
            with self.subTest(reply=repr(reply)[:30]):
                code, row, _, _ = self.observe(event(), reply)
                self.assertEqual((code, row["reason"]), (3, "QUERY"))
        merged = current()
        merged["data"]["repository"]["pullRequest"]["state"] = "MERGED"
        code, row, _, _ = self.observe(event(), merged)
        self.assertEqual((code, row["reason"]), (3, "STALE"))
        reply = current()
        reply["data"]["repository"]["pullRequest"]["baseRefName"] = None
        code, row, _, _ = self.observe(event(), reply)
        self.assertEqual((code, row["reason"]), (3, "QUERY"))
        reply = current()
        del reply["data"]["repository"]["pullRequest"]["baseRefName"]
        code, row, _, _ = self.observe(event(), reply)
        self.assertEqual((code, row["reason"]), (3, "QUERY"))

    def test_checker_and_html_failures_are_not_policy(self):
        with patch.object(CANARY.CHECKER, "local_origin", side_effect=RuntimeError("secret marker")):
            code, row, calls, output = self.observe()
        self.assertEqual((code, row["status"], row["reason"], len(calls)),
                         (3, "UNAVAILABLE", "CHECKER", 1))
        self.assertNotIn("secret marker", output)
        with patch.object(CANARY.CHECKER, "check_body_html", side_effect=RuntimeError("secret marker")):
            code, row, _, output = self.observe()
        self.assertEqual((code, row["reason"]), (3, "CHECKER"))
        self.assertNotIn("secret marker", output)
        for html in ("x" * (CANARY.CHECKER.HTML_CHARS + 1), "<p>bad\0</p>"):
            reply = current()
            reply["data"]["repository"]["pullRequest"]["bodyHTML"] = html
            code, row, calls, _ = self.observe(event(), reply)
            self.assertEqual((code, row["status"], row["reason"], len(calls)),
                             (1, "REFUSED", "POLICY", 1))

    def test_duplicate_event_and_over_limit_input(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "event.json"
            for raw in (b'{"action":"opened","action":"edited"}', b"{", b"\xff",
                        b"[]", b"null", b" " * (CANARY.MAX_EVENT + 1)):
                with self.subTest(raw_size=len(raw)):
                    path.write_bytes(raw)
                    with self.assertRaises(CANARY.InputError):
                        CANARY.read_event(str(path))
            path.write_text(json.dumps(event()))
            self.assertEqual(CANARY.read_event(str(path)), event())
            self.assertEqual(CANARY.read_event(str(path)), event())
            link = Path(temp) / "linked-event.json"
            link.symlink_to(path)
            with self.assertRaises(CANARY.InputError):
                CANARY.read_event(str(link))

    def test_oversized_body_is_policy_and_not_transport(self):
        body = "x" * (CANARY.CHECKER.BODY_BYTES + 1)
        code, row, calls, _ = self.observe(event(body), current(body))
        self.assertEqual((code, row["status"], row["reason"], len(calls)),
                         (1, "REFUSED", "POLICY", 1))
        trailer = "\n\nTask: #5\nClass: E\nAssisted-by: test tool"
        lead = "A bounded event observation. "
        remaining = CANARY.CHECKER.BODY_BYTES - len((lead + trailer).encode())
        at_limit = lead + "é" * (remaining // 2) + "x" * (remaining % 2) + trailer
        self.assertEqual(len(at_limit.encode()), CANARY.CHECKER.BODY_BYTES)
        code, row, calls, _ = self.observe(event(at_limit), current(at_limit))
        self.assertEqual((code, row["status"], row["reason"], len(calls)),
                         (0, "PASS", "OK", 1))
        multibyte = lead + "é" * (remaining // 2) + "x" * (remaining % 2) + "x" + trailer
        self.assertEqual(len(multibyte.encode()), CANARY.CHECKER.BODY_BYTES + 1)
        code, row, calls, _ = self.observe(event(multibyte), current(multibyte))
        self.assertEqual((code, row["status"], row["reason"], len(calls)),
                         (1, "REFUSED", "POLICY", 1))
        with patch.object(CANARY.CHECKER, "BODY_BYTES", CANARY.CHECKER.BODY_BYTES + 1):
            code, row, _, _ = self.observe(event(multibyte), current(multibyte))
        self.assertEqual((code, row["status"]), (0, "PASS"))

    def test_main_checks_trusted_checkout_before_transport(self):
        good = {"GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_REPOSITORY": "granaryfs/granary",
                "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "c" * 40,
                "GITHUB_TOKEN": "synthetic-token", "GITHUB_RUN_ID": "71",
                "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_PATH": "/nonexistent/event.json"}
        for change, reason in (({"GITHUB_EVENT_NAME": "pull_request"}, "CONTEXT"),
                               ({"GITHUB_REF": "refs/pull/16/merge"}, "CONTEXT"),
                               ({"GITHUB_REPOSITORY": "other/repo"}, "CONTEXT"),
                               ({"GITHUB_SHA": "short"}, "CONTEXT"),
                               ({"GITHUB_TOKEN": "bad token"}, "CONTEXT"),
                               ({"GITHUB_RUN_ID": "false"}, "CONTEXT"),
                               ({"GITHUB_RUN_ATTEMPT": "0"}, "CONTEXT")):
            with self.subTest(change=change), patch.dict(os.environ, good | change, clear=True), \
                 patch.object(CANARY.subprocess, "run", side_effect=AssertionError("git reached")):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(CANARY.main(), 3)
                self.assertEqual(json.loads(output.getvalue())["reason"], reason)
        with patch.dict(os.environ, good, clear=True), \
             patch.object(CANARY.subprocess, "run", return_value=SimpleNamespace(stdout="d" * 40 + "\n")) as git:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(CANARY.main(), 3)
            self.assertEqual(json.loads(output.getvalue())["reason"], "SETUP")
            git.assert_called_once_with(["git", "rev-parse", "HEAD"], check=True,
                                        capture_output=True, text=True, timeout=5)
        with patch.dict(os.environ, good, clear=True), \
             patch.object(CANARY.subprocess, "run", side_effect=CANARY.subprocess.CalledProcessError(
                 1, ["git", "rev-parse", "HEAD"])):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(CANARY.main(), 3)
            self.assertEqual(json.loads(output.getvalue())["reason"], "SETUP")
        with patch.dict(os.environ, good, clear=True), patch.object(CANARY, "CHECKER", None):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(CANARY.main(), 3)
            self.assertEqual(json.loads(output.getvalue())["reason"], "CONTEXT")

    def test_main_uses_one_bounded_authenticated_graphql_response(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "event.json"
            path.write_text(json.dumps(event()))
            env = {"GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_REPOSITORY": "granaryfs/granary",
                   "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "c" * 40,
                   "GITHUB_TOKEN": "synthetic-token", "GITHUB_RUN_ID": "71",
                   "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_PATH": str(path)}
            raw = json.dumps(current()).encode()
            requests = []
            class Response:
                status = 200
                headers = Message()
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(len(raw))
                def __enter__(self): return self
                def __exit__(self, *_args): return False
                def read(self, limit):
                    self_limit = limit
                    assert self_limit == 4 * 1024 * 1024 + 1
                    return raw
            class Connection:
                def __init__(self, host, *, timeout, context):
                    assert host == "api.github.com"
                    assert timeout == 5
                    assert context is not None
                def request(self, method, endpoint, payload, headers):
                    requests.append((method, endpoint, json.loads(payload), headers))
                def getresponse(self): return Response()
                def close(self): pass
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(CANARY.subprocess, "run", return_value=SimpleNamespace(stdout="c" * 40 + "\n")), \
                 patch("http.client.HTTPSConnection", Connection):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(CANARY.main(), 0)
            row = json.loads(output.getvalue())
            self.assertEqual((row["status"], row["reason"]), ("PASS", "OK"))
            self.assertEqual(len(requests), 1)
            method, endpoint, payload, headers = requests[0]
            self.assertEqual((method, endpoint), ("POST", "/graphql"))
            self.assertEqual(payload["variables"], {"owner": "granaryfs", "name": "granary", "number": 16})
            self.assertIn("body bodyHTML", payload["query"])
            self.assertEqual(headers["Authorization"], "Bearer synthetic-token")
            self.assertIn("baseRefName", payload["query"])

    def test_main_transport_failure_emits_one_redacted_row(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "event.json"
            path.write_text(json.dumps(event()))
            token = "synthetic-secret-token"
            env = {"GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_REPOSITORY": "granaryfs/granary",
                   "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "c" * 40,
                   "GITHUB_TOKEN": token, "GITHUB_RUN_ID": "71",
                   "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_PATH": str(path)}
            for error in (OSError("secret transport marker"),):
                with self.subTest(error=type(error).__name__), patch.dict(os.environ, env, clear=True), \
                     patch.object(CANARY.subprocess, "run", return_value=SimpleNamespace(stdout="c" * 40 + "\n")), \
                     patch("http.client.HTTPSConnection", side_effect=error):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        self.assertEqual(CANARY.main(), 3)
                    rows = stdout.getvalue().splitlines()
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(json.loads(rows[0])["reason"], "QUERY")
                    self.assertNotIn(token, stdout.getvalue() + stderr.getvalue())
                    self.assertNotIn("secret transport marker", stdout.getvalue() + stderr.getvalue())
            path.unlink()
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(CANARY.subprocess, "run", return_value=SimpleNamespace(stdout="c" * 40 + "\n")):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    self.assertEqual(CANARY.main(), 3)
                self.assertEqual(json.loads(stdout.getvalue())["reason"], "SETUP")

    def test_workflow_and_guard_pin_are_exact(self):
        workflow = SCRIPT.parent.parent / ".github/workflows/ready-pr-metadata-event-canary.yml"
        spec = importlib.util.spec_from_file_location("event_canary_guard", SCRIPT.with_name("check-fork-guard.py"))
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        raw = workflow.read_bytes()
        self.assertEqual(set(guard.EVENT_CANARY_DEPENDENCIES), {
            "scripts/run-ready-pr-event-canary.py", "scripts/run-ready-pr-canary.py",
            "scripts/check-ready-pr-metadata.py", "scripts/ready-pr-metadata-requirements.txt"})
        self.assertEqual(hashlib.sha256(raw).hexdigest(), guard.EVENT_CANARY_SHA256)
        self.assertEqual(guard.check_workflow(workflow.name, raw.decode(), public=True, path=workflow), (1, 0))
        with self.assertRaisesRegex(ValueError, "reviewed bytes"):
            guard.check_workflow(workflow.name, raw.decode() + "\n", public=True, path=workflow)
        with patch.dict(guard.EVENT_CANARY_DEPENDENCIES,
                        {"scripts/run-ready-pr-event-canary.py": "0" * 64}):
            with self.assertRaisesRegex(ValueError, "trusted dependency differs"):
                guard.check_workflow(workflow.name, raw.decode(), public=True, path=workflow)
        with self.assertRaisesRegex(ValueError, "pull_request_target"):
            guard.check_workflow("copy.yml", raw.decode(), public=True, path=workflow.with_name("copy.yml"))
        self.assertIn('"$venv_python" -I -B scripts/run-ready-pr-event-canary.py', raw.decode())
        self.assertIn("permissions: {}", raw.decode())
        self.assertIn("permissions: { contents: read, pull-requests: read }", raw.decode())
        self.assertIn("persist-credentials: false", raw.decode())
        self.assertIn("types: [opened, edited, synchronize, reopened, ready_for_review, converted_to_draft]", raw.decode())
        self.assertIn("branches: [main]", raw.decode())
        self.assertIn("--require-hashes --only-binary=:all:", raw.decode())
        self.assertLess(raw.decode().index("Verify trusted checkout before repository code"),
                        raw.decode().index("Install pinned Markdown parser"))
        self.assertLess(raw.decode().index("Install pinned Markdown parser"),
                        raw.decode().index("Observe delivered PR event"))
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', raw.decode())
        self.assertEqual(raw.decode().count("GITHUB_TOKEN: ${{ github.token }}"), 1)
        self.assertIn("if: github.repository == 'granaryfs/granary'", raw.decode())
        self.assertNotIn("concurrency:", raw.decode())
        self.assertNotIn("pull_request.head.sha", raw.decode())
        self.assertNotIn("pull_request.head.ref", raw.decode())
        self.assertNotIn("github.head_ref", raw.decode())
        self.assertNotIn("cache:", raw.decode())
        with tempfile.TemporaryDirectory() as temp:
            link = Path(temp) / workflow.name
            link.symlink_to(workflow)
            with patch.object(guard, "EVENT_CANARY_WORKFLOW", link), \
                 self.assertRaisesRegex(ValueError, "regular file"):
                guard.check_workflow(link.name, raw.decode(), public=True, path=link)


if __name__ == "__main__":
    unittest.main()
