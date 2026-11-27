#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Check a PR draft, prepare a squash proof, or verify a landed commit."""

import argparse
from dataclasses import dataclass
from hashlib import sha256
from html import unescape
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unicodedata


SIGNOFF = "signed-off-by"
AI_TRAILERS = {"assisted-by": "Assisted-by", "ai-reviewed-by": "AI-Reviewed-by"}
IDENTITY = re.compile(r"[^<>\s][^<>]*[ \t]<[^\s<>@]+@[^\s<>@]+>")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
SIGNOFF_EXAMPLE = re.compile(
    r"""
      <!-- .*? -->
    | ^[ ]{0,3} <!-- .*? \Z
    | ^[ ]{0,3} (`{3,}) [^`\n]* \n .*? (?: ^[ ]{0,3}\1`*[ \t]*$ | \Z )
    | ^[ ]{0,3} (~{3,}) [^\n]* \n .*? (?: ^[ ]{0,3}\2~*[ \t]*$ | \Z )
    """,
    re.MULTILINE | re.DOTALL | re.VERBOSE,
)
# Ready descriptions are Markdown; keep the landed-message masker independent.
CODE_SPAN = r"(?<!`)(?P<ticks>`+)(?!`)[^\n]*?(?<!`)(?P=ticks)(?!`)"
READY_REGION = re.compile(
    r"^[ ]{0,3}(`{3,})[^`\n]*\n.*?(?:^[ ]{0,3}\1`*[ \t]*$|\Z)"
    r"|^[ ]{0,3}(~{3,})[^\n]*\n.*?(?:^[ ]{0,3}\2~*[ \t]*$|\Z)"
    r"|^[ ]{0,3}<(?:pre|script|style|textarea)(?=[ \t>]|$).*?"
    r"(?:</(?:pre|script|style|textarea)>[^\n]*|\Z)"
    r"|^[ ]{0,3}<!--.*?(?:-->[^\n]*|\Z)"
    r"|^[ ]{0,3}<\?.*?(?:\?>[^\n]*|\Z)"
    r"|^[ ]{0,3}<!(?-i:[A-Z]).*?(?:>[^\n]*|\Z)"
    r"|^[ ]{0,3}<!\[(?-i:CDATA)\[.*?(?:\]\]>[^\n]*|\Z)"
    r"|<!--.*?-->"
    r"|" + CODE_SPAN, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.ASCII,
)


# Match tags, not every angle-bracketed string (e.g. an email autolink).
INLINE_LINK = (
    r"!?\[(?P<label>[^\[\]\n]*)\]\("
    r"(?:<[^<>\r\n]*>|(?:[^()<>\s]|\([^()\s]*\))*)"
    r'''(?:[ \t]+(?:"[^"\r\n]*"|'[^'\r\n]*'|\([^()\r\n]*\)))?\)'''
)
VALUE_TOKEN = re.compile(CODE_SPAN + r"|" + INLINE_LINK + r"|</?[A-Za-z][A-Za-z0-9-]*(?:[ \t](?:[^'\"<>]|'[^']*'|\"[^\"]*\")*)? */?>")
TRAILER_LINE = re.compile(r"[a-zA-Z0-9-]+[ \t]*:.*")
OID = re.compile(r"[0-9a-f]{40}")
APPROVAL_FIELDS = {"base", "head", "tested_merge", "tree", "author", "message_sha256"}


@dataclass(frozen=True)
class Commit:
    tree: str
    parents: tuple[str, ...]
    author: str
    message: bytes


def read_utf8(path):
    return path.read_bytes().decode("utf-8")


def check_title(title):
    if not isinstance(title, str) or not title.strip():
        raise ValueError("title is empty")
    if title.splitlines() != [title] or any(ord(char) < 32 or ord(char) == 127 for char in title):
        raise ValueError("title must be one line without control characters")


def check_description(body):
    if not isinstance(body, str) or not HTML_COMMENT.sub("", body).strip():
        raise ValueError("description is empty")
    if "\0" in body:
        raise ValueError("description contains a NUL")


def trailer_parts(line):
    key, separator, value = line.partition(":")
    return (key.rstrip(" \t").lower(), value.strip(" \t")) if separator else ("", "")


def check_trailers(message, *, check_ai=True):
    # Git defines the terminal trailer block. Its parser also distinguishes
    # a separate sign-off from one folded into a different trailer's value.
    result = subprocess.run(
        ["git", "-c", "trailer.separators=:", "interpret-trailers", "--parse", "--no-divider"],
        input=message, text=True, encoding="utf-8", capture_output=True, check=True,
    )
    signoffs = set()
    for line in result.stdout.split("\n"):
        key, value = trailer_parts(line)
        if key == SIGNOFF:
            if not IDENTITY.fullmatch(value):
                raise ValueError("malformed Signed-off-by trailer")
            signoffs.add(value)
        if check_ai and key in AI_TRAILERS and not value.strip():
            raise ValueError(f"{AI_TRAILERS[key]} is empty")
    return signoffs


def mask_examples(message):
    return SIGNOFF_EXAMPLE.sub(lambda match: re.sub(r"[^ \t\n]", "\0", match[0]), message)


def ready_region(match):
    if match['ticks']:
        return match[0]  # Literal text, not an HTML opener.
    return re.sub(r"[^ \t\n]", "\0", match[0])


def visible_assistance(value):
    def visible(text):
        # These four default-ignorable Hangul fillers fall outside categories C and M.
        return any(not c.isspace() and unicodedata.category(c)[0] not in 'CM'
                   and c not in '\u115f\u1160\u3164\uffa0' for c in text)

    end = 0
    for token in VALUE_TOKEN.finditer(value):
        if visible(unescape(value[end:token.start()])):
            return True
        if token['label'] and visible(unescape(token['label'])):
            return True
        if token['ticks'] and visible(token[0].strip('`')):
            return True
        end = token.end()
    return visible(unescape(value[end:]))


def check_ready_trailers(body):
    classes = []
    assistance = []
    for line in terminal_lines(READY_REGION.sub(ready_region, body)):
        if "\0" in line or not TRAILER_LINE.fullmatch(line):
            raise ValueError("ready PR must end with a standalone trailer block")
        key, value = trailer_parts(line)
        if key == "class":
            classes.append(value)
        elif key == "assisted-by":
            assistance.append(value)
    if len(classes) != 1 or classes[0] not in {"E", "I", "P", "S", "R"}:
        raise ValueError("ready PR requires exactly one Class trailer with value E/I/P/S/R")
    if len(assistance) != 1 or not visible_assistance(assistance[0]):
        raise ValueError("ready PR requires exactly one nonempty Assisted-by trailer")


def check_draft(event_path):
    event = json.loads(read_utf8(event_path))
    pr = event.get("pull_request") if isinstance(event, dict) else None
    if not isinstance(pr, dict):
        raise ValueError("event has no pull request object")
    draft = pr.get("draft", True)
    if not isinstance(draft, bool):
        raise ValueError("draft flag must be a boolean")
    title, body = pr.get("title"), pr.get("body")
    check_title(title)
    check_description(body)
    if not draft:
        body = body.replace("\r\n", "\n").replace("\r", "\n")
        check_ready_trailers(body)
    visible_body = HTML_COMMENT.sub("", body).replace("\r\n", "\n")
    # A draft can end in a Markdown example that Git's trailer heuristic
    # would treat as sign-offs. Check only a standalone trailer paragraph.
    if all(TRAILER_LINE.fullmatch(line) for line in terminal_lines(visible_body)):
        check_trailers(f"{title}\n\n{visible_body}")


def terminal_lines(message):
    lines = message.split("\n")
    end = len(lines)
    while end and not lines[end - 1].strip(" \t"):
        end -= 1
    start = end
    while start and lines[start - 1].strip(" \t"):
        start -= 1
    return lines[start:end]


def raw_signoffs(message, *, check_ai=True):
    parsed = check_trailers(message, check_ai=check_ai)
    # Git can parse trailer-shaped text inside comments and fenced examples.
    # Mask those characters without changing line and paragraph boundaries.
    visible = mask_examples(message)
    for line in terminal_lines(visible):
        key, value = trailer_parts(line)
        if key == SIGNOFF and "\0" not in line and value in parsed:
            yield line


def check_squash_message(message, required_lines):
    if "\r" in message:
        raise ValueError("squash message must use LF line endings")
    title, separator, body = message.partition("\n\n")
    check_title(title)
    if not separator:
        raise ValueError("separate the squash subject and description with a blank line")
    check_description(body)
    present = set(raw_signoffs(message))
    for line in required_lines:
        if not line:
            continue
        key, value = trailer_parts(line)
        if key != SIGNOFF or not IDENTITY.fullmatch(value):
            raise ValueError("malformed required sign-off")
        if line not in present:
            raise ValueError("missing required sign-off in the final trailer block")


def check_squash(message_path, signoffs_path):
    check_squash_message(read_utf8(message_path), read_utf8(signoffs_path).split("\n"))


def git(*args):
    # Proofs describe real objects. Read them without local replacements,
    # grafts, or an implicit fetch from a promisor remote.
    return subprocess.check_output(
        ["git", "--no-replace-objects", *args], stderr=subprocess.PIPE,
        env=dict(os.environ, GIT_GRAFT_FILE=os.devnull, GIT_NO_LAZY_FETCH="1"),
    )


def require_oid(oid):
    if not isinstance(oid, str) or not OID.fullmatch(oid):
        raise ValueError("expected a full commit SHA or tree ID")


def read_commit(oid):
    require_oid(oid)
    if git("cat-file", "-t", oid) != b"commit\n":
        raise ValueError("object is not a commit")
    headers, separator, message = git("cat-file", "commit", oid).partition(b"\n\n")
    lines = headers.split(b"\n")
    trees = [line[5:].decode("ascii") for line in lines if line.startswith(b"tree ")]
    authors = [line[7:] for line in lines if line.startswith(b"author ")]
    if not separator or len(trees) != 1 or len(authors) != 1:
        raise ValueError("could not read the commit headers")
    require_oid(trees[0])
    parents = tuple(line[7:].decode("ascii") for line in lines if line.startswith(b"parent "))
    author, timestamp, timezone = authors[0].rsplit(b" ", 2)
    if not timestamp.lstrip(b"-").isdigit() or not re.fullmatch(rb"[+-][0-9]{4}", timezone):
        raise ValueError("could not read the commit author")
    return Commit(trees[0], parents, author.decode("utf-8"), message)


def contribution_signoffs(base, head):
    if git("rev-parse", "--is-shallow-repository").strip() != b"false":
        raise ValueError("contribution sign-offs require complete Git history")
    commits = git("rev-list", "--reverse", f"{base}..{head}").decode("ascii").splitlines()
    if not commits:
        raise ValueError("no contribution commits between base and head")
    required = set()
    for oid in commits:
        message = read_commit(oid).message.decode("utf-8")
        signed = [
            line for line in raw_signoffs(message, check_ai=False)
            if not trailer_parts(line)[1].lower().endswith("[bot]@users.noreply.github.com>")
        ]
        if not signed:
            raise ValueError(f"commit {oid} has no human sign-off")
        required.update(signed)
    return required


def prepare_squash(message_path, base, head, tested_merge, author):
    read_commit(base)
    read_commit(head)
    tested = read_commit(tested_merge)
    if tested.parents != (base, head):
        raise ValueError("tested merge parents differ from base and head")
    if not IDENTITY.fullmatch(author):
        raise ValueError("expected the approved author as Name <email>")
    message = message_path.read_bytes()
    check_squash_message(message.decode("utf-8"), contribution_signoffs(base, head))
    return {
        "base": base, "head": head, "tested_merge": tested_merge, "tree": tested.tree,
        "author": author, "message_sha256": sha256(message).hexdigest(),
    }


def verify_landed(approval_path, landed_oid):
    approval = json.loads(read_utf8(approval_path))
    if not isinstance(approval, dict) or set(approval) != APPROVAL_FIELDS:
        raise ValueError("approval has unexpected fields")
    for key in ("base", "head", "tested_merge", "tree"):
        require_oid(approval[key])
    if not isinstance(approval["author"], str) or not IDENTITY.fullmatch(approval["author"]):
        raise ValueError("approval has an invalid author")
    digest = approval["message_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("approval has an invalid message digest")
    landed = read_commit(landed_oid)
    if landed.parents != (approval["base"],):
        raise ValueError("landed commit has a different base or is not a squash")
    if landed.tree != approval["tree"]:
        raise ValueError("landed tree differs from approval")
    if landed.author != approval["author"]:
        raise ValueError("landed author differs from approval")
    if sha256(landed.message).hexdigest() != digest:
        raise ValueError("landed message differs from approval")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="mode", required=True)
    draft = subcommands.add_parser("draft")
    draft.add_argument("event", type=Path, help="pull request event JSON")
    squash = subcommands.add_parser("squash")
    squash.add_argument("message", type=Path, help="exact squash message")
    squash.add_argument(
        "--required-signoffs", type=Path, required=True,
        help="trusted list of the required sign-off lines, one per line",
    )
    prepare = subcommands.add_parser("prepare-squash", help="prepare a proof for a signed contribution")
    prepare.add_argument("message", type=Path, help="exact squash message")
    prepare.add_argument("--base", required=True, help="verified base commit SHA")
    prepare.add_argument("--head", required=True, help="verified PR head commit SHA")
    prepare.add_argument("--tested-merge", required=True, help="merge commit used by verified CI")
    prepare.add_argument("--author", required=True, help="approved Git author, Name <email>")
    landed = subcommands.add_parser("verify-landed")
    landed.add_argument("approval", type=Path, help="trusted, approved prepare-squash JSON")
    landed.add_argument("commit", help="landed squash commit SHA")
    args = parser.parse_args()
    try:
        if args.mode == "draft":
            check_draft(args.event)
        elif args.mode == "squash":
            check_squash(args.message, args.required_signoffs)
        elif args.mode == "prepare-squash":
            print(json.dumps(prepare_squash(
                args.message, args.base, args.head, args.tested_merge, args.author,
            )))
            return 0
        else:
            verify_landed(args.approval, args.commit)
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.CalledProcessError):
        print("refused: could not read the input or required Git data", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"{args.mode} message checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
