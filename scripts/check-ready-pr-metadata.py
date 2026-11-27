#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Check a ready PR's terminal metadata against its source paragraph."""

from html.parser import HTMLParser
from dataclasses import dataclass, field
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import sys
import traceback
import unicodedata

try:
    import cmarkgfm
    from cmarkgfm.cmark import Options
except Exception:
    cmarkgfm = None
    Options = None


BODY_BYTES = 128 * 1024
HTML_CHARS = 2 * 1024 * 1024
CLASS = re.compile(r"Class: [EIPSR]")
TRAILER = re.compile(r"[A-Za-z0-9-]+[ \t]*:.*")
TASK = re.compile(r"Task: [A-Za-z0-9#./-][A-Za-z0-9 #./-]*")
AUTOLINK = re.compile(
    r"<(?:https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+|"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+)>"
)
SOURCE_MARKUP = re.compile(r"[<>\[\]`\\&*~]")
DECLARATIONS = ("class", "assisted-by")
SPACE = re.compile(r"\s+")
SPAN = re.compile(r"([1-9][0-9]{0,8}):([1-9][0-9]{0,8})-([1-9][0-9]{0,8}):([1-9][0-9]{0,8})")
VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())
BLOCK = frozenset(
    "p pre div details summary blockquote ul ol li table thead tbody tr td th "
    "h1 h2 h3 h4 h5 h6 hr dl dt dd section article figure figcaption "
    "address aside caption center colgroup dialog fieldset footer form header legend "
    "hgroup main menu nav search tfoot video audio canvas textarea".split()
)
DISALLOWED = frozenset("script style template iframe object svg ruby rp rt".split())
FINAL_MARKUP = frozenset(("p", "br", "a"))
SVG_GEOMETRY = frozenset(("path", "g", "circle", "rect", "line", "polyline", "polygon", "ellipse"))
FILLERS = frozenset("\u115f\u1160\u3164\uffa0")
BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
OTHER_LINE_BREAKS = frozenset("\v\f\u0085\u2028\u2029")
# Only these observed label lookalikes are ambiguous declarations, never valid trailers.
LABEL_SEPARATORS = str.maketrans({"\u2236": ":", "\ua789": ":", "\u2010": "-", "\u2011": "-"})
LABEL_INITIALS = str.maketrans({"\u0421": "C", "\u0441": "c"})
QUERY = """query ReadyBody($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    pullRequest(number: $number) { number body bodyHTML }
  }
}"""


class Refused(ValueError):
    """An ambiguous or invalid ready PR body."""


class Unavailable(RuntimeError):
    """The remote viewer could not be verified; retry the gate later."""


def terminal(body):
    """Return normalized body and the source line range of its trailer block."""
    if not isinstance(body, str):
        raise Refused("body must be a string")
    try:
        size = len(body.encode("utf-8", "strict"))
    except UnicodeEncodeError as exc:
        raise Refused("body is not UTF-8 encodable") from exc
    if size > BODY_BYTES:
        raise Refused("body exceeds the byte limit")
    body = body.replace("\r\n", "\n")
    if any(char in body for char in ("\r", "\0", "\ufeff")):
        raise Refused("body contains a lone carriage return, NUL or BOM")
    if any(char in OTHER_LINE_BREAKS for char in body):
        raise Refused("body contains an unsupported line separator")
    lines = body.split("\n")
    while lines and not lines[-1].strip(" \t"):
        lines.pop()
    end = len(lines)
    start = end
    while start and lines[start - 1].strip(" \t"):
        start -= 1
    block = lines[start:end]
    if not block or any(not TRAILER.fullmatch(line) for line in block):
        raise Refused("body must end with a standalone trailer block")
    keys = [line.partition(":")[0].rstrip(" \t").lower() for line in block]
    if keys.count("class") != 1 or keys.count("assisted-by") != 1:
        raise Refused("terminal block needs one Class and one Assisted-by")
    class_at, assisted_at = keys.index("class"), keys.index("assisted-by")
    if assisted_at != class_at + 1 or not CLASS.fullmatch(block[class_at]):
        raise Refused("Class E/I/P/S/R must immediately precede Assisted-by")
    if not block[assisted_at].startswith("Assisted-by: ") or not block[assisted_at][13:].strip():
        raise Refused("Assisted-by needs a nonempty value")
    if class_at > 1 or any(
        not TASK.fullmatch(line) or line != line.rstrip(" \t")
        for line in block[:class_at]
    ):
        raise Refused("at most one literal Task trailer may precede Class")
    if any(SOURCE_MARKUP.search(AUTOLINK.sub("", line)) for line in block):
        raise Refused("trailer block contains inline markup that can hide source lines")
    return body, start + 1, end, tuple(block), class_at


class RootBlocks(HTMLParser):
    """Retain only the final root element and its source position."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.last = None

    def handle_starttag(self, tag, attrs):
        if not self.stack:
            self.last = (tag, [value for key, value in attrs if key == "data-sourcepos"])
        if tag not in VOID:
            if len(self.stack) >= 256:
                raise Refused("local renderer nesting exceeds limit")
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        if tag not in VOID:
            raise Refused("local renderer used an ambiguous self-closing element")
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            raise Refused("local renderer has mismatched HTML")

    def handle_data(self, data):
        if not self.stack and data.strip(" \t\n\r\f"):
            self.last = None

    def handle_comment(self, _data):
        if not self.stack:
            self.last = None

    def handle_decl(self, _decl):
        raise Refused("local renderer has an unexpected declaration")

    unknown_decl = handle_decl
    handle_pi = handle_decl


def local_origin(body):
    """Return the final root paragraph span; this is not a visibility verdict."""
    text, first, last, _block, _class_at = terminal(body)
    if cmarkgfm is None or Options is None:
        raise Unavailable("required cmarkgfm dependency is unavailable")
    options = Options.CMARK_OPT_SOURCEPOS | Options.CMARK_OPT_HARDBREAKS
    try:
        html = cmarkgfm.github_flavored_markdown_to_html(text, options=options)
    except Exception as exc:
        raise Unavailable("local GFM conversion failed") from exc
    if not isinstance(html, str) or len(html) > HTML_CHARS:
        raise Refused("local GFM output is invalid or too large")
    roots = RootBlocks()
    try:
        roots.feed(html)
        roots.close()
    except Refused:
        raise
    except Exception as exc:
        raise Refused("local GFM HTML could not be parsed") from exc
    if roots.stack:
        raise Refused("local GFM HTML has an unclosed element")
    if roots.last is None or roots.last[0] != "p":
        raise Refused("terminal metadata is not a root paragraph")
    spans = roots.last[1]
    if len(spans) != 1 or not isinstance(spans[0], str):
        raise Refused("terminal paragraph lacks one source position")
    match = SPAN.fullmatch(spans[0])
    if match is None:
        raise Refused("terminal paragraph has an invalid source position")
    start_line, start_column, end_line, end_column = map(int, match.groups())
    if (start_line, start_column, end_line) != (first, 1, last):
        raise Refused("terminal paragraph does not span the literal trailer block")
    return start_line, start_column, end_line, end_column


@dataclass
class RenderedBlock:
    tag: str
    attrs: dict
    lines: list[str] = field(default_factory=list)
    line_rtl: list[bool] = field(default_factory=list)
    unsafe: bool = False


class ViewerHTML(HTMLParser):
    """Collect logical prose lines from GitHub's sanitized bodyHTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.roots = []
        self.parts = []
        self.parts_rtl = False
        self.nodes = 0
        self.directions = []

    def flush(self):
        if self.parts:
            line = SPACE.sub(" ", "".join(self.parts)).strip()
            if line:
                self.roots[-1].lines.append(line)
                self.roots[-1].line_rtl.append(self.parts_rtl)
            self.parts.clear()
            self.parts_rtl = False

    def handle_starttag(self, tag, attrs):
        self.nodes += 1
        if self.nodes > 8192 or len(self.stack) >= 128:
            raise Refused("viewer HTML exceeds structure limits")
        names = [name for name, _value in attrs]
        if len(names) != len(set(names)):
            raise Refused("viewer HTML has duplicate attributes")
        attributes = dict(attrs)
        if "dir" in attributes and attributes["dir"] != "auto":
            raise Refused("viewer HTML contains a direction override")
        if tag in ("bdi", "bdo"):
            raise Refused("viewer HTML contains a direction override")
        if "svg" in self.stack and tag not in SVG_GEOMETRY:
            raise Refused("viewer HTML contains unsupported SVG content")
        if tag == "svg" and attributes.get("aria-hidden") != "true":
            raise Refused("viewer HTML contains visible SVG content")
        if ("hidden" in attributes
                or "popover" in attributes
                or ("style" in attributes and tag != "img")
                or (attributes.get("aria-hidden") == "true" and tag != "svg")
                or (tag in DISALLOWED and tag != "svg")):
            raise Refused("viewer HTML contains hidden or unsupported content")
        if tag in BLOCK and "p" in self.stack:
            raise Refused("viewer HTML has a block nested inside a paragraph")
        if tag in BLOCK or tag == "br":
            self.flush()
        if not self.stack:
            self.roots.append(RenderedBlock(tag, attributes))
        if (tag not in FINAL_MARKUP or "hidden" in attributes or "style" in attributes
                or attributes.get("aria-hidden") == "true"):
            self.roots[-1].unsafe = True
        if tag not in VOID:
            self.stack.append(tag)
            self.directions.append({
                "auto": tag == "p" or attributes.get("dir") == "auto",
                "first": None,
            })

    def handle_startendtag(self, tag, attrs):
        if tag in SVG_GEOMETRY and "svg" in self.stack:
            self.handle_starttag(tag, attrs)
            self.handle_endtag(tag)
            return
        if tag not in VOID:
            raise Refused("viewer HTML has ambiguous self-closing markup")
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            raise Refused("viewer HTML has mismatched tags")
        if tag in BLOCK:
            self.flush()
        self.directions.pop()
        self.stack.pop()

    def handle_data(self, data):
        if "svg" in self.stack:
            if data.strip():
                raise Refused("viewer HTML contains visible SVG content")
            return
        if not self.stack:
            if data.strip():
                raise Refused("viewer HTML has text outside a root element")
            return
        if any(char in BIDI_CONTROLS for char in data):
            raise Refused("viewer HTML contains bidirectional controls")
        if any(char in OTHER_LINE_BREAKS for char in data):
            raise Refused("viewer HTML contains an unsupported line separator")
        if any(unicodedata.category(char) == "Cf" for char in data):
            self.roots[-1].unsafe = True
        first_strong = next(
            (unicodedata.bidirectional(char) for char in data
             if unicodedata.bidirectional(char) in ("L", "R", "AL")), None,
        )
        if first_strong is not None:
            for scope in reversed(self.directions):
                if scope["auto"]:
                    if scope["first"] is None:
                        scope["first"] = first_strong
                    break
        if "pre" in self.stack:
            return
        direction = next(
            (scope["first"] for scope in reversed(self.directions) if scope["auto"]),
            None,
        )
        self.parts_rtl |= direction in ("R", "AL")
        self.parts.append(data)

    def handle_decl(self, _decl):
        raise Refused("viewer HTML contains an unexpected declaration")

    unknown_decl = handle_decl
    handle_pi = handle_decl


def visible_assistance(value):
    return any(
        unicodedata.category(char)[0] in "LN"
        and char not in FILLERS
        for char in value
    )


def is_declaration(line, label, rtl_paragraph=False):
    line = unicodedata.normalize("NFKC", line).translate(LABEL_SEPARATORS)
    first_strong = next(
        (unicodedata.bidirectional(char) for char in line
         if unicodedata.bidirectional(char) in ("L", "R", "AL")), None,
    )
    prefix, colon, _value = line.partition(":")
    prefix = prefix.translate(LABEL_INITIALS)
    prefix = "".join(
        char for char in prefix
        if unicodedata.category(char)[0] not in "MC"
        and char not in FILLERS
        and char != "\u2800"
    )
    if colon and prefix.strip(" \t").casefold() == label:
        return True
    if first_strong not in ("R", "AL") and not rtl_paragraph:
        return False
    # A dir=auto paragraph can visually move a later Latin label to the edge.
    visible = "".join(
        char for char in line.translate(LABEL_INITIALS)
        if unicodedata.category(char)[0] not in "MC"
        and char not in FILLERS
        and char != "\u2800"
    ).casefold()
    return re.search(r"(?<![a-z0-9])" + re.escape(label) + r"[ \t]*:", visible) is not None


def check_body_html(html, raw_block, class_at):
    """Require the exact terminal declarations in the GitHub viewer output."""
    if not isinstance(html, str) or len(html) > HTML_CHARS or "\0" in html:
        raise Refused("viewer HTML is invalid or too large")
    viewer = ViewerHTML()
    try:
        viewer.feed(html)
        viewer.close()
    except Refused:
        raise
    except Exception as exc:
        raise Refused("viewer HTML could not be parsed") from exc
    if viewer.stack or viewer.directions or not viewer.roots or viewer.roots[-1].tag != "p":
        raise Refused("terminal metadata is not a root viewer paragraph")
    if any(len(block.lines) != len(block.line_rtl) for block in viewer.roots):
        raise Refused("viewer line directions are inconsistent")
    final = viewer.roots[-1]
    if final.unsafe:
        raise Refused("terminal viewer paragraph contains hidden or unsupported markup")
    if set(final.attrs) - {"dir"} or final.attrs.get("dir", "auto") != "auto":
        raise Refused("terminal viewer paragraph has unexpected attributes")
    if len(final.lines) != len(raw_block):
        raise Refused("viewer trailer lines differ from literal source lines")
    for raw_line, visible_line in zip(raw_block, final.lines):
        if raw_line.partition(":")[0] != visible_line.partition(":")[0]:
            raise Refused("viewer trailer label differs from literal source")
    expected = [
        SPACE.sub(" ", AUTOLINK.sub(lambda match: match.group()[1:-1], line)).strip()
        for line in raw_block
    ]
    if final.lines != expected:
        raise Refused("viewer trailer values differ from literal source")
    assisted = final.lines[class_at + 1]
    if not assisted.startswith("Assisted-by: ") or not visible_assistance(assisted[13:]):
        raise Refused("viewer Assisted-by value is not visible")
    for label in DECLARATIONS:
        count = sum(
            is_declaration(line, label, rtl)
            for block in viewer.roots if block.tag != "pre"
            for line, rtl in zip(block.lines, block.line_rtl)
        )
        if count != 1:
            raise Refused(f"viewer has {count} declarations for {label}")
    return tuple(final.lines)


def unique_object(pairs):
    """Reject ambiguous API/event JSON rather than accepting its last key."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("JSON has a duplicate key")
        result[key] = value
    return result


def invalid_constant(_value):
    raise Refused("JSON has an invalid constant")


def event_identity(event):
    """Validate a GitHub pull_request snapshot without making an API call."""
    try:
        pr = event["pull_request"]
        repo = event["repository"]["full_name"]
        number = event["number"]
        action = event["action"]
        if not (
            os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
            and type(action) is str
            and action in ("opened", "reopened", "synchronize", "edited",
                           "ready_for_review", "converted_to_draft")
            and type(repo) is str
            and repo == os.environ.get("GITHUB_REPOSITORY")
            and repo == pr["base"]["repo"]["full_name"]
            and re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repo)
            and type(number) is int
            and 1 <= number < 2**31
            and type(pr["number"]) is int
            and pr["number"] == number
        ):
            raise Unavailable("event identity is invalid")
        return repo, number
    except Unavailable:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise Unavailable("event identity is invalid") from exc


def fetch_viewer(event):
    """Fetch the current PR body and its GitHub-rendered HTML in one response."""
    repo, number = event_identity(event)
    try:
        token = os.environ.get("GITHUB_TOKEN", "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,4096}", token):
            raise Refused("GitHub credential is unavailable")
        owner, name = repo.split("/")
        payload = json.dumps({"query": QUERY, "variables": {
            "owner": owner, "name": name, "number": number,
        }}).encode("ascii")
        with closing(http.client.HTTPSConnection(
            "api.github.com", timeout=5, context=ssl.create_default_context(),
        )) as connection:
            connection.request("POST", "/graphql", payload, headers={
                "Authorization": "Bearer " + token,
                "User-Agent": "granary-ready-pr-metadata",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            })
            with connection.getresponse() as response:
                if response.status != 200 or response.headers.get_content_type() != "application/json":
                    raise Refused("GitHub viewer query failed")
                content_length = response.headers.get("Content-Length")
                if content_length is not None and (
                    not re.fullmatch(r"[0-9]+", content_length)
                    or int(content_length) > HTML_CHARS
                ):
                    raise Refused("GitHub viewer response has invalid length")
                data = response.read(HTML_CHARS + 1)
                if content_length is not None and len(data) != int(content_length):
                    raise Refused("GitHub viewer response is incomplete")
        if len(data) > HTML_CHARS:
            raise Refused("GitHub viewer response exceeds byte limit")
        reply = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=invalid_constant)
        if not isinstance(reply, dict) or "errors" in reply or not isinstance(reply.get("data"), dict):
            raise Refused("GitHub viewer returned an error")
        repository = reply["data"]["repository"]
        pull = repository["pullRequest"]
        if repository["nameWithOwner"] != repo or type(pull["number"]) is not int or pull["number"] != number:
            raise Refused("GitHub viewer returned a different PR")
        body, html = pull["body"], pull["bodyHTML"]
        if not isinstance(body, str) or not isinstance(html, str):
            raise Refused("GitHub viewer returned malformed body fields")
        if "\0" in html or len(html) > HTML_CHARS:
            raise Refused("GitHub viewer returned invalid HTML")
        return body, html
    except Refused as exc:
        raise Unavailable(str(exc)) from exc
    except (KeyError, TypeError, ValueError, OSError, RecursionError,
            http.client.HTTPException) as exc:
        raise Unavailable("GitHub viewer query could not be verified") from exc


def check_event(path, fetcher=fetch_viewer):
    try:
        event = json.loads(path.read_bytes().decode("utf-8"),
                           object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except Refused as exc:
        raise Unavailable(str(exc)) from exc
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise Unavailable("could not read PR event JSON") from exc
    pr = event.get("pull_request") if isinstance(event, dict) else None
    if not isinstance(pr, dict):
        raise Unavailable("event has no pull request object")
    draft = pr.get("draft")
    if not isinstance(draft, bool):
        raise Unavailable("draft flag must be a Boolean")
    event_identity(event)
    if event.get("action") == "ready_for_review" and draft:
        raise Unavailable("event action contradicts draft flag")
    if event.get("action") == "converted_to_draft" and not draft:
        raise Unavailable("event action contradicts draft flag")
    if draft:
        return
    try:
        raw_body = pr.get("body")
        origin = local_origin(raw_body)
        _normalized, _first, _last, block, class_at = terminal(raw_body)
        returned_body, html = fetcher(event)
        if returned_body != raw_body:
            raise Unavailable("GitHub viewer body differs from the event body")
        check_body_html(html, block, class_at)
        return origin
    except Refused as exc:
        raise Refused(f"ready PR {exc}") from exc


def main():
    if len(sys.argv) != 2:
        print("usage: python3 -I scripts/check-ready-pr-metadata.py EVENT",
              file=sys.stderr)
        return 2
    try:
        check_event(Path(sys.argv[1]))
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    except Unavailable as exc:
        print(f"unavailable: {exc}", file=sys.stderr)
        return 3
    except Exception:
        traceback.print_exc()
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
