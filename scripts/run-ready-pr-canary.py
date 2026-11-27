#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Sample open ready PR metadata from a scheduled default-branch run."""

from contextlib import closing
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys


CHECK_PATH = Path(__file__).resolve().with_name("check-ready-pr-metadata.py")
try:
    SPEC = importlib.util.spec_from_file_location("ready_metadata_checker", CHECK_PATH)
    CHECKER = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = CHECKER
    SPEC.loader.exec_module(CHECKER)
except Exception:
    CHECKER = None
MAX_RESPONSE = 4 * 1024 * 1024
MAX_PRS = 20
LIST_QUERY = """query ReadyCanary($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    pullRequests(first: 20, states: OPEN, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage }
      nodes { number isDraft }
    }
  }
}"""
PAIR_QUERY = """query ReadyCanaryBody($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    pullRequest(number: $number) { number state isDraft body bodyHTML }
  }
}"""


class Unavailable(RuntimeError):
    """The scheduled observation cannot be trusted."""


class CheckerUnavailable(Unavailable):
    """The local policy checker could not verify one PR."""


class ChangedState(RuntimeError):
    """A listed ready PR is no longer open and ready at detail time."""


def decode(status, content_type, raw):
    """Parse only a complete, unambiguous GraphQL response."""
    if status != 200 or content_type != "application/json" or len(raw) > MAX_RESPONSE:
        raise Unavailable("response")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=CHECKER.unique_object,
                          parse_constant=CHECKER.invalid_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Unavailable("response") from exc
    if not isinstance(data, dict) or "errors" in data or not isinstance(data.get("data"), dict):
        raise Unavailable("response")
    return data


def parse_listing(reply, repository):
    """Refuse an incomplete or malformed one-page open-PR census."""
    try:
        node = reply["data"]["repository"]
        if node["nameWithOwner"] != repository:
            raise Unavailable("listing")
        connection = node["pullRequests"]
        if connection["pageInfo"]["hasNextPage"] is not False:
            raise Unavailable("listing")
        entries = connection["nodes"]
        if not isinstance(entries, list) or len(entries) > MAX_PRS:
            raise Unavailable("listing")
        seen = set()
        rows = []
        for entry in entries:
            number, draft = entry["number"], entry["isDraft"]
            if type(number) is not int or not 1 <= number < 2**31 or type(draft) is not bool or number in seen:
                raise Unavailable("listing")
            seen.add(number)
            rows.append((number, draft))
        return tuple(rows)
    except (KeyError, TypeError, ValueError) as exc:
        raise Unavailable("listing") from exc


def parse_pair(reply, repository, number):
    """Bind body and bodyHTML from one response to the requested PR."""
    try:
        node = reply["data"]["repository"]
        pull = node["pullRequest"]
        if (node["nameWithOwner"] != repository or type(pull["number"]) is not int
                or pull["number"] != number or pull["state"] not in ("OPEN", "CLOSED", "MERGED")
                or type(pull["isDraft"]) is not bool):
            raise Unavailable("pair")
        if pull["state"] != "OPEN" or pull["isDraft"]:
            raise ChangedState("state changed")
        body, html = pull["body"], pull["bodyHTML"]
        if (not isinstance(body, str) or not isinstance(html, str)
                or len(html.encode("utf-8", "strict")) > CHECKER.HTML_CHARS
                or "\0" in html):
            raise Unavailable("pair")
        body.encode("utf-8", "strict")
        return body, html
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise Unavailable("pair") from exc


def classify(body, html):
    """Apply the landed checker's source and visible-HTML policy."""
    if not isinstance(body, str) or not isinstance(html, str):
        raise Unavailable("pair")
    try:
        CHECKER.local_origin(body)
        _normalized, _first, _last, block, class_at = CHECKER.terminal(body)
        CHECKER.check_body_html(html, block, class_at)
        return "PASS"
    except CHECKER.Refused:
        return "REFUSED"
    except CHECKER.Unavailable as exc:
        raise CheckerUnavailable("checker") from exc
    except Exception as exc:
        raise CheckerUnavailable("checker") from exc


def fetch(query, variables, token):
    """Fetch a bounded, authenticated response; never expose response text on error."""
    payload = json.dumps({"query": query, "variables": variables}).encode("ascii")
    try:
        with closing(http.client.HTTPSConnection(
            "api.github.com", timeout=5, context=ssl.create_default_context(),
        )) as connection:
            connection.request("POST", "/graphql", payload, headers={
                "Authorization": "Bearer " + token,
                "User-Agent": "granary-ready-pr-canary",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            })
            with connection.getresponse() as response:
                if response.headers.get("Content-Encoding", "identity") != "identity":
                    raise Unavailable("response")
                length = response.headers.get("Content-Length")
                if length is not None and (not re.fullmatch(r"[0-9]+", length)
                                           or int(length) > MAX_RESPONSE):
                    raise Unavailable("response")
                raw = response.read(MAX_RESPONSE + 1)
                if length is not None and len(raw) != int(length):
                    raise Unavailable("response")
                return decode(response.status, response.headers.get_content_type(), raw)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise Unavailable("response") from exc


def emit(output, number, status, reason, body=None, html=None):
    record = {"number": number, "status": status, "reason": reason,
              "body_sha256": hashlib.sha256(body.encode()).hexdigest() if body is not None else None,
              "body_html_sha256": hashlib.sha256(html.encode()).hexdigest() if html is not None else None}
    print(json.dumps(record, sort_keys=True), file=output)


def run(query, repository, output):
    """Return 0 for a clean scan, 1 for a refusal, 3 for unavailable evidence."""
    owner, name = repository.split("/", 1)
    try:
        rows = parse_listing(query("list", {"owner": owner, "name": name}), repository)
    except Unavailable:
        emit(output, None, "UNAVAILABLE", "LISTING")
        return 3
    if not rows:
        emit(output, None, "SKIPPED", "NO_OPEN_PRS")
        return 0
    result = 0
    for number, draft in rows:
        if draft:
            emit(output, number, "SKIPPED", "DRAFT")
            continue
        body = html = None
        try:
            body, html = parse_pair(query("pair", {"owner": owner, "name": name, "number": number}),
                                    repository, number)
            status = classify(body, html)
            reason = "OK" if status == "PASS" else "POLICY"
        except ChangedState:
            emit(output, number, "SKIPPED", "STATE_CHANGED")
            continue
        except CheckerUnavailable:
            status, reason = "UNAVAILABLE", "CHECKER"
        except Unavailable:
            status, reason = "UNAVAILABLE", "QUERY"
        emit(output, number, status, reason, body, html)
        result = max(result, 3 if status == "UNAVAILABLE" else 1 if status == "REFUSED" else 0)
    return result


def main():
    if CHECKER is None:
        emit(sys.stdout, None, "UNAVAILABLE", "SETUP")
        return 3
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if (os.environ.get("GITHUB_EVENT_NAME") != "schedule" or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or repository != "granaryfs/granary" or not re.fullmatch(r"[0-9a-f]{40}", sha)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,4096}", token)):
        emit(sys.stdout, None, "UNAVAILABLE", "CONTEXT")
        return 3
    try:
        actual = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True,
                                text=True, timeout=5).stdout.strip()
        if actual != sha:
            raise Unavailable("checkout")
        def query(kind, variables):
            return fetch(LIST_QUERY if kind == "list" else PAIR_QUERY, variables, token)
        return run(query, repository, sys.stdout)
    except Exception:
        emit(sys.stdout, None, "UNAVAILABLE", "SETUP")
        return 3


if __name__ == "__main__":
    sys.exit(main())
