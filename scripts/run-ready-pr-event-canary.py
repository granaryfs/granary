#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Observe one delivered PR event using trusted code and a same-response viewer pair."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
CHECK_PATH = SCRIPT_DIR / "check-ready-pr-metadata.py"
try:
    SPEC = importlib.util.spec_from_file_location("event_ready_checker", CHECK_PATH)
    CHECKER = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = CHECKER
    SPEC.loader.exec_module(CHECKER)
except Exception:
    CHECKER = None

REPOSITORY = "granaryfs/granary"
OID = re.compile(r"[0-9a-f]{40}\Z")
TOKEN = re.compile(r"[A-Za-z0-9._-]{1,4096}\Z")
ACTIONS = frozenset(("opened", "edited", "synchronize", "reopened",
                     "ready_for_review", "converted_to_draft"))
MAX_EVENT = 1024 * 1024
QUERY = """query ReadyEventCanary($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    pullRequest(number: $number) {
      number state isDraft headRefOid baseRefOid baseRefName body bodyHTML
    }
  }
}"""


class InputError(ValueError):
    pass


class QueryError(RuntimeError):
    pass


def digest(text):
    return hashlib.sha256(text.encode("utf-8", "strict")).hexdigest()


def emit(output, status, reason, *, run_id=None, attempt=None, workflow_sha=None,
         action=None, number=None, event_head=None, current_head=None,
         event_body=None, event_body_null=None, current_body=None, current_html=None):
    row = {"status": status, "reason": reason, "run_id": run_id, "attempt": attempt,
           "workflow_sha": workflow_sha, "action": action, "number": number,
           "event_head": event_head, "current_head": current_head,
           "event_body_null": event_body_null,
           "event_body_sha256": digest(event_body) if event_body is not None else None,
           "current_body_sha256": digest(current_body) if current_body is not None else None,
           "current_body_html_sha256": digest(current_html) if current_html is not None else None}
    print(json.dumps(row, sort_keys=True, separators=(",", ":")), file=output)


def event_snapshot(payload):
    try:
        if type(payload) is not dict or payload.get("action") not in ACTIONS:
            raise InputError
        action = payload["action"]
        number, repo, pull = payload["number"], payload["repository"], payload["pull_request"]
        if (type(number) is not int or not 1 <= number < 2**31
                or type(repo) is not dict or repo["full_name"] != REPOSITORY
                or type(pull) is not dict or type(pull["number"]) is not int
                or pull["number"] != number or pull["state"] != "open"
                or type(pull["draft"]) is not bool or pull["body"] is not None
                and type(pull["body"]) is not str):
            raise InputError
        base, head = pull["base"], pull["head"]
        if (type(base) is not dict or type(head) is not dict
                or base["ref"] != "main" or base["repo"]["full_name"] != REPOSITORY
                or type(base["sha"]) is not str or not OID.fullmatch(base["sha"])
                or type(head["sha"]) is not str or not OID.fullmatch(head["sha"])
                or action == "ready_for_review" and pull["draft"]
                or action == "converted_to_draft" and not pull["draft"]):
            raise InputError
        body_is_null = pull["body"] is None
        body = "" if body_is_null else pull["body"]
        body.encode("utf-8", "strict")
        return action, number, pull["draft"], head["sha"], base["sha"], body, body_is_null
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise InputError from exc


def current_snapshot(reply, number):
    try:
        if type(reply) is not dict or "errors" in reply or type(reply["data"]) is not dict:
            raise QueryError
        repo = reply["data"]["repository"]
        pull = repo["pullRequest"]
        if (type(repo) is not dict or type(pull) is not dict
                or type(repo["nameWithOwner"]) is not str
                or type(pull["number"]) is not int
                or type(pull["state"]) is not str or type(pull["isDraft"]) is not bool
                or type(pull["headRefOid"]) is not str or not OID.fullmatch(pull["headRefOid"])
                or type(pull["baseRefOid"]) is not str or not OID.fullmatch(pull["baseRefOid"])
                or type(pull["baseRefName"]) is not str
                or type(pull["body"]) is not str or type(pull["bodyHTML"]) is not str
                ):
            raise QueryError
        pull["body"].encode("utf-8", "strict")
        pull["bodyHTML"].encode("utf-8", "strict")
        return (repo["nameWithOwner"], pull["number"], pull["state"], pull["isDraft"],
                pull["headRefOid"], pull["baseRefOid"], pull["baseRefName"],
                pull["body"], pull["bodyHTML"])
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise QueryError from exc


def classify(body, html):
    try:
        CHECKER.local_origin(body)
        _text, _first, _last, block, class_at = CHECKER.terminal(body)
        CHECKER.check_body_html(html, block, class_at)
        return "PASS"
    except CHECKER.Refused:
        return "REFUSED"
    except Exception as exc:
        raise QueryError from exc


def run(payload, query, output, *, run_id, attempt, workflow_sha):
    """One event and one authenticated detail query; output exactly one redacted row."""
    common = {"run_id": run_id, "attempt": attempt, "workflow_sha": workflow_sha}
    try:
        action, number, draft, head, base, body, body_is_null = event_snapshot(payload)
    except InputError:
        emit(output, "UNAVAILABLE", "CONTEXT", **common)
        return 3
    common.update(action=action, number=number, event_head=head,
                  event_body=None if body_is_null else body, event_body_null=body_is_null)
    try:
        pair = current_snapshot(query({"owner": "granaryfs", "name": "granary", "number": number}), number)
        repo, found_number, state, current_draft, current_head, current_base, current_base_name, current_body, html = pair
    except Exception:
        emit(output, "UNAVAILABLE", "QUERY", **common)
        return 3
    common.update(current_head=current_head, current_body=current_body, current_html=html)
    if (repo != REPOSITORY or found_number != number or state != "OPEN" or current_draft != draft
            or current_head != head or current_base != base or current_base_name != "main"
            or current_body != body):
        emit(output, "UNAVAILABLE", "STALE", **common)
        return 3
    if draft:
        emit(output, "SKIPPED", "DRAFT", **common)
        return 0
    try:
        status = classify(current_body, html)
    except Exception:
        emit(output, "UNAVAILABLE", "CHECKER", **common)
        return 3
    emit(output, status, "OK" if status == "PASS" else "POLICY", **common)
    return 0 if status == "PASS" else 1


def read_event(path):
    source = Path(path)
    if not path or source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_EVENT:
        raise InputError
    raw = source.read_bytes()
    if len(raw) > MAX_EVENT or CHECKER is None:
        raise InputError
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=CHECKER.unique_object,
                             parse_constant=CHECKER.invalid_constant)
        if type(payload) is not dict:
            raise InputError
        return payload
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InputError from exc


def main():
    env = os.environ
    sha, token = env.get("GITHUB_SHA", ""), env.get("GITHUB_TOKEN", "")
    run_id, attempt = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    if (CHECKER is None or env.get("GITHUB_EVENT_NAME") != "pull_request_target"
            or env.get("GITHUB_REPOSITORY") != REPOSITORY or env.get("GITHUB_REF") != "refs/heads/main"
            or not OID.fullmatch(sha) or not TOKEN.fullmatch(token)
            or len(run_id) > 20 or len(attempt) > 10
            or not run_id.isascii() or not run_id.isdecimal() or not attempt.isascii()
            or not attempt.isdecimal() or int(run_id) < 1 or int(attempt) < 1):
        emit(sys.stdout, "UNAVAILABLE", "CONTEXT")
        return 3
    try:
        actual = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True,
                                text=True, timeout=5).stdout.strip()
        if actual != sha:
            raise InputError
        payload = read_event(env.get("GITHUB_EVENT_PATH", ""))
    except Exception:
        emit(sys.stdout, "UNAVAILABLE", "SETUP", run_id=int(run_id), attempt=int(attempt),
             workflow_sha=sha)
        return 3
    try:
        spec = importlib.util.spec_from_file_location("scheduled_transport", SCRIPT_DIR / "run-ready-pr-canary.py")
        scheduled = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scheduled)
        def query(variables):
            return scheduled.fetch(QUERY, variables, token)
        return run(payload, query, sys.stdout, run_id=int(run_id), attempt=int(attempt), workflow_sha=sha)
    except Exception:
        emit(sys.stdout, "UNAVAILABLE", "SETUP", run_id=int(run_id), attempt=int(attempt),
             workflow_sha=sha)
        return 3


if __name__ == "__main__":
    sys.exit(main())
