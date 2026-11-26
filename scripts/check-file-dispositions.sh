#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# THE TRIGGER: **a source file under `crates/*/src` of more than 3,000
# physical lines owes a WRITTEN disposition** — either a compiler-proven
# test-only shield as specified below, or one of the three
# `// @file-disposition:` directives in its first 40 lines. A shielded
# test body is exempt because its disposition follows its parent's.
# This gate demands the sentence; it never proposes a split or refuses
# a `STAYS`. A gate is a COST on a boundary, not a vote on that boundary.
# A production file splits only when it contains more than one subject
# with a one-directional seam between them; size is neither a reason
# nor a bar. This script does not judge those subjects or that seam:
# gate architecture must not decide the restructure whose enforcement
# cost it is supposed to expose.
#
# >>> A SIZE TRIGGER CANNOT ESTABLISH THAT A DISPOSITION REMAINS TRUE. <<<
# Taking a file below the ceiling removes its obligation to carry a
# disposition; it must not make an existing directive invisible to the gate.
# Read directives at EVERY size, including those in
# `crates/granary-cli/src/attach.rs` and `crates/granary-cli/src/main.rs`.
# `check-fsguard-sites.sh` directs maintainers to the crate root's own
# disposition, so its sentence must describe the source it accompanies.
# Checking every `// @file-disposition:` line establishes its SHAPE,
# but a well-shaped directive can still contain a false sentence.
# Neither the marker's presence nor the file's size proves that the
# stated subject or remaining work is accurate.
#
# A directive may carry `// @file-disposition-lines: <N>`.
# That is a machine-checked ASSERTION: N must equal the file's current
# physical-line count, regardless of whether it exceeds the ceiling.
# Check the assertion whenever it is present, including in small files;
# a size-only check would miss precisely the files a split makes smaller.
# The assertion checks a FIGURE, not the truth of a subject judgement.
# Re-reading the disposition's prose remains the milestone-exit
# conformance pass's responsibility.
#
# Exit 0 = pass; 1 = a file over the ceiling carries neither disposition;
# 2 = malformed or the gate could not run (a git-tracked path this gate
# cannot open, an empty file list, git itself failing). A SIGNAL IS NOT A
# RESULT: without a handler bash dies 130/143, outside this vocabulary.
#
# THE SHIELD uses the same test-implying predicate rule as
# `scripts/fsguard-scan.py`'s `file_scoped_cfg_test` check.
# Apply that predicate rule exactly:
#   - FILE-SCOPED means depth 0 over all three delimiter kinds `{}()[]`,
#     found the same way fsguard's `delim_spans` finds it: an inner
#     attribute inside `nop!(#![cfg(test)]);` sits in a macro call's own
#     token tree, not the file, and the compiler does not gate the file
#     on it.
#   - THE PREDICATE MUST IMPLY `test`: a bare `test`, or an `all(...)`
#     naming `test` as a direct top-level conjunct — `#![cfg(all(test,
#     unix))]` IS the shield, exactly as fsguard's own control (a planted
#     `all(test, unix)` file bumps ITS licensed-site count, meaning
#     fsguard already treats it as test-only). Anything whose predicate
#     TEXT contains `any(`, `not(` or a `cfg_attr` wrapper is refused —
#     matched as a substring over the whole predicate, not just its top
#     level, which is deliberately more conservative than the accept
#     path: `#![cfg(any(test, feature = "x"))]` is real production code
#     under `--features x`, and `#![cfg(all(test, not(windows)))]` is
#     refused too even though `test` is still a top-level conjunct,
#     because there is nothing to gain by proving a nested case safe when
#     the sanctioned shape costs nothing to write instead. This gate accepts
#     bare `cfg(test)` and `all(...)` with `test` as a direct top-level
#     conjunct; it refuses the `any`/`not`/`cfg_attr` shapes above.
#     Self-test controls C10–C12 below exercise the `all`, `any` and
#     `not` shapes; no control covers `cfg_attr`.
#   - Position among a file's other inner attributes is irrelevant
#     (`#![expect(…)]` before or after the shield is fine).
#     Check file scope directly; do not infer it from an attribute's
#     order among its peers. This disposition gate additionally requires
#     the shield to precede the first real item and imposes a column
#     restriction beyond the filesystem scanner's file-scope check:
#     it must sit at COLUMN 0 (nothing, not even whitespace, before its `#`
#     on that physical line) and BEFORE the file's first real item — a
#     shield after a `fn`, a `struct`, or any other item is not read as
#     covering the whole file, because a reader scanning top to bottom
#     would already have found production code above it.
#
# THE DIRECTIVE and the shield are read by the SAME lexer, on purpose:
# the code lexer this gate replaced used `strip()` to strip `//`
# line comments along with `/* */` blocks and string literals, which is
# exactly wrong for a directive scan — a valid directive IS a `//` line,
# so a lexer built for "is this code" cannot answer "is this a real
# comment or a comment-shaped string/doc-comment/block-comment". This
# gate's lexer classifies every character as code, line-comment, block-
# comment, or string (regular, raw, or a char literal) in one pass, and
# builds two different views from that ONE classification: a CODE mask
# (line comments blanked too) for the shield, and a DIRECTIVE view (line
# comments kept, block comments and strings blanked) for the three
# directive forms. A directive inside a doc comment (`//!`/`///`), a
# block comment, a string literal (including a multi-line raw string), or
# indented by even one column does not count — each is its own self-test
# control below, because a check that asserts a PRESENCE has to fail
# toward "not found" on every scanner confusion, the same asymmetry
# `check-server-log-path.sh`'s header explains for its own presence check.
#
# THE PATHSPEC, AND A DEFECT THIS GATE ALMOST SHIPPED WITH. `git ls-files`
# is mandatory here — never a shell glob, per the recorded class ("a
# glob-scoped gate goes blind at the first subdirectory") — but the
# OBVIOUS pathspec, `crates/*/src/**/*.rs` with no magic prefix, is
# ITSELF blind, and in the opposite direction: verified against git
# 2.55.0, `git ls-files -- 'crates/*/src/**/*.rs'` matches a file two
# directories under `src/` but NOT a file directly in `src/` — because
# without glob-pathspec magic, `**` is read as an ordinary path SEGMENT
# that must consume a real directory component, not as "zero or more
# directories". Planting `crates/x/src/top.rs` and `crates/x/src/a/
# nested.rs` in a scratch repo, the bare pattern found only the nested
# one; `main.rs`, `resolve.rs`, `cache.rs`, `mechanism.rs`, `loopback.rs`
# — the files whose dispositions this gate checks — sit directly under `src/`
# and are invisible to the bare pattern. This gate uses the documented
# pathspec magic, `:(glob)crates/*/src/**/*.rs`, which turns on true
# zero-or-more-directory `**` semantics and was verified to match a file
# at depth 0, 1 and 2 in the same scratch repo.
# Self-test controls C1-C22 (all depth 0) and C23 (depth 2) are the
# standing proof that both ends of this are covered, not just the one
# the brief for this gate happened to name.
#
# WHAT THIS GATE DOES NOT DO. It does not parse Rust, does not resolve a
# module tree, does not know what "the file's subject" means, and does
# not check that a `STAYS` sentence is still true. The milestone-exit
# conformance pass must re-read that sentence against the file's subject.
# This gate lexes one file at a time, checking a mark and a sentence.
set -euo pipefail

# ARGUMENT VALIDATION, mirrored from the other check-*.sh gates: an argv
# that is not exactly `--self-test` must not fall through to the real
# gate and exit 0, where a typo'd invocation would read as a passing
# self-test. Refused here, before any setup, so the diagnostic names
# the argument.
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != "--self-test" ) ]]; then
  echo "check-file-dispositions: unrecognised argument(s): $* — the only accepted form is '--self-test' (or no argument, to run the gate). Refused rather than silently running the gate and reporting green." >&2
  exit 2
fi

cd "$(dirname "$0")/.."

# A SIGNAL IS NOT A RESULT: without a handler bash dies 130/143, outside
# the 0/1/2 vocabulary promised above.
trap 'printf "check-file-dispositions: NOT A RESULT: interrupted\n" >&2; exit 2' INT TERM

# THE PINNED INTEGER is 3,000, matching rustc tidy's ceiling with a written
# opt-out. The dependency-size percentile is context, not a formula for
# this threshold. Changing it requires changing the documented trigger
# above as well as this single constant; do not retune it from a new sample.
CEILING=3000

# ---- the check, and the self-test's own fixtures, share this code --------
# One python program does the read,
# so the self-test exercises the SAME code the real run does
# rather than a restatement of it. `run_gate <repo-dir>` prints its
# verdict and exits 0/1/2; called once for the real tree below, and once
# per scratch fixture from --self-test.
run_gate() { # run_gate <repo-dir>
  python3 - "$1" "$CEILING" <<'PY'
import os
import re
import subprocess
import sys

repo, ceiling = sys.argv[1], int(sys.argv[2])
PROG = "check-file-dispositions"

def blind(msg):
    print(f"{PROG}: THE GATE IS BLIND — it verified NOTHING. {msg}", file=sys.stderr)
    sys.exit(2)

# ---- 0. the file list: git ls-files, never a shell glob -------------------
# `:(glob)` is not decoration — see this file's header. Without it the
# bare pattern is blind to every file directly under `src/`, which in
# this tree is every file whose disposition this gate checks.
try:
    proc = subprocess.run(
        ["git", "-C", repo, "ls-files", "-z", "--", ":(glob)crates/*/src/**/*.rs"],
        capture_output=True,
    )
except OSError as e:
    blind(f"'git ls-files' could not even be started: {e}")

if proc.returncode != 0:
    blind(
        "git ls-files -- ':(glob)crates/*/src/**/*.rs' exited "
        f"{proc.returncode}: {proc.stderr.decode('utf-8', 'replace').strip()}"
    )

paths = sorted(p.decode("utf-8", "surrogateescape") for p in proc.stdout.split(b"\0") if p)
if not paths:
    blind(
        "':(glob)crates/*/src/**/*.rs' matched NOTHING in git's index. A "
        "moved crate, a renamed src/ directory, or a pathspec that stopped "
        "matching reads as a clean tree otherwise — refusing rather than "
        "reporting an empty scan as a pass."
    )

# ---- the lexer --------------------------------------------------------
# Classifies every character of a file's text as one of:
#   'c' code            'l' line comment (// to end of line)
#   'b' block comment (/* ... */, nesting)
#   's' string (regular, raw r"...", raw-with-hashes r#"..."#, or a char
#       literal / lifetime disambiguated the way check-server-log-path.sh's
#       ARG_SCANNER already does in this repo)
# ONE INDEX-BASED PASS over the whole file, not a per-line scan: a raw
# string or a block comment can span arbitrarily many lines, and
# re-deriving that from line-local state the way a `//`-only scanner can
# is exactly the class this gate exists to not repeat.
OPEN_TO_CLOSE = {"{": "}", "(": ")", "[": "]"}
CLOSE_TO_OPEN = {v: k for k, v in OPEN_TO_CLOSE.items()}


def classify(text):
    n = len(text)
    state = [""] * n
    i = 0
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = i
            while j < n and text[j] != "\n":
                state[j] = "l"
                j += 1
            i = j
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            state[i] = "b"
            state[i + 1] = "b"
            j = i + 2
            while j < n and depth > 0:
                if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    state[j] = "b"
                    state[j + 1] = "b"
                    depth += 1
                    j += 2
                    continue
                if text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    state[j] = "b"
                    state[j + 1] = "b"
                    depth -= 1
                    j += 2
                    continue
                state[j] = "b"
                j += 1
            i = j
            continue
        # raw string / raw byte string: r"...", r#"..."#, br#"..."#, ...
        if ch in ("r", "b"):
            k = i
            if text[k] == "b" and k + 1 < n and text[k + 1] == "r":
                k += 1
            if k < n and text[k] == "r":
                h = k + 1
                hashes = 0
                while h < n and text[h] == "#":
                    hashes += 1
                    h += 1
                if h < n and text[h] == '"':
                    start = i
                    j = h + 1
                    for m in range(start, j):
                        state[m] = "s"
                    closer = '"' + "#" * hashes
                    while j < n:
                        state[j] = "s"
                        if text[j] == '"' and text[j + 1 : j + 1 + hashes] == "#" * hashes:
                            for m in range(j, j + 1 + hashes):
                                state[m] = "s"
                            j += 1 + hashes
                            break
                        j += 1
                    i = j
                    continue
            # not a raw-string prefix after all; fall through as ordinary code
        if ch == '"':
            state[i] = "s"
            j = i + 1
            while j < n:
                state[j] = "s"
                if text[j] == "\\" and j + 1 < n:
                    state[j + 1] = "s"
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        if ch == "'":
            # ported from check-server-log-path.sh's ARG_SCANNER: a 4-char
            # escape `'\X'`, a 3-char literal `'X'`, or a lone `'` left as
            # ordinary code (a lifetime).
            if i + 3 < n and text[i + 1] == "\\" and text[i + 3] == "'":
                for m in range(i, i + 4):
                    state[m] = "s"
                i += 4
                continue
            if i + 2 < n and text[i + 1] != "'" and text[i + 2] == "'":
                for m in range(i, i + 3):
                    state[m] = "s"
                i += 3
                continue
            state[i] = "c"
            i += 1
            continue
        state[i] = "c"
        i += 1
    return state


def masked(text, state, keep):
    """`text` with every character whose state is not in `keep` replaced
    by a space — except a real newline, always kept, so line numbers
    (and the 40-line directive window) survive regardless of what state
    the newline itself carries."""
    out = []
    for ch, st in zip(text, state):
        out.append(ch if ch == "\n" or st in keep else " ")
    return "".join(out)


def find_matching(s, open_idx, open_ch, close_ch):
    depth = 0
    for i in range(open_idx, len(s)):
        if s[i] == open_ch:
            depth += 1
        elif s[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return None


def delim_spans(s):
    """Every matched pair across `{}`, `()` and `[]`, one pass, one
    stack — mirrors fsguard-scan.py's `delim_spans` exactly, because a
    brace-only span (`block_spans`) reads `nop!(#![cfg(test)]);` as
    file-scoped when it is not: the attribute sits inside the macro
    call's parens, which this net catches and a brace-only one would not."""
    stack = []
    spans = []
    for i, c in enumerate(s):
        if c in OPEN_TO_CLOSE:
            stack.append((c, i))
        elif c in CLOSE_TO_OPEN:
            if stack and stack[-1][0] == CLOSE_TO_OPEN[c]:
                _, op = stack.pop()
                spans.append((op, i))
    return spans


def split_top_commas_parens(text):
    parts, depth, start = [], 0, 0
    for i, c in enumerate(text):
        if c == "(":
            depth += 1
        elif c == ")":
            depth = depth - 1 if depth else 0
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


# Mirrors fsguard-scan.py's `_cfg_predicate_implies_test` exactly.
# Self-test controls C10–C12 below prove the accepted `all(test, unix)`
# and refused `any(test, unix)` / `not(test)` shapes:
# a bare `test`, or an `all(...)` naming `test` as a direct
# top-level conjunct. `any(`, `not(` or a `cfg_attr` wrapper ANYWHERE in
# the predicate text disqualifies it, deliberately more conservative than
# the accept path.
DISQUALIFY_RE = re.compile(r"\bany\s*\(|\bnot\s*\(|\bcfg_attr\b")
ALL_HEAD_RE = re.compile(r"^\s*all\s*\(")


def cfg_predicate_implies_test(predicate):
    if DISQUALIFY_RE.search(predicate):
        return False
    if predicate.strip() == "test":
        return True
    m = ALL_HEAD_RE.match(predicate)
    if not m:
        return False
    close = find_matching(predicate, m.end() - 1, "(", ")")
    if close is None:
        return False
    if predicate[close + 1 :].strip():
        return False
    inner = predicate[m.end() : close]
    return any(part.strip() == "test" for part in split_top_commas_parens(inner))


ATTR_RE = re.compile(r"#!\[")
CFG_HEAD_RE = re.compile(r"^\s*cfg\s*\(")


def first_item_pos(code):
    """Where the file's first real item begins, skipping whitespace and
    any `#[...]`/`#![...]` attribute (inner or outer, any content) —
    those precede items without being one. `None` when the whole file is
    attributes/whitespace (no item found at all)."""
    n = len(code)
    i = 0
    while i < n:
        ch = code[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "#":
            j = i + 1
            if j < n and code[j] == "!":
                j += 1
            if j < n and code[j] == "[":
                close = find_matching(code, j, "[", "]")
                if close is None:
                    return i  # malformed; cannot parse further
                i = close + 1
                continue
            return i  # '#' not followed by '[': not an attribute
        return i
    return None


def shield_present(text, state):
    """A file-scoped `#![cfg(P)]`, P implying `test`, at column 0, at
    delimiter depth 0, before the file's first item. Multiple candidates
    and other inner attributes are fine in any order — only one valid
    candidate positioned before the first item is required."""
    code = masked(text, state, {"c"})
    spans = delim_spans(code)
    candidates = []
    for m in ATTR_RE.finditer(code):
        hash_pos = m.start()
        open_bracket = m.end() - 1
        close_bracket = find_matching(code, open_bracket, "[", "]")
        if close_bracket is None:
            continue
        if any(lo < hash_pos < hi for lo, hi in spans):
            continue  # nested inside a {}/()/[] group: not file-scoped
        body = code[open_bracket + 1 : close_bracket]
        head = CFG_HEAD_RE.match(body)
        if not head:
            continue
        cfg_open = head.end() - 1
        cfg_close = find_matching(body, cfg_open, "(", ")")
        if cfg_close is None:
            continue
        if body[cfg_close + 1 :].strip():
            continue  # trailing token after cfg(...): not a bare attribute
        if not cfg_predicate_implies_test(body[cfg_open + 1 : cfg_close]):
            continue
        if hash_pos != 0 and text[hash_pos - 1] != "\n":
            continue  # not at column 0
        candidates.append(hash_pos)
    if not candidates:
        return False
    fip = first_item_pos(code)
    return fip is None or any(c < fip for c in candidates)


DIRECTIVE_RE = re.compile(r"^// @file-disposition: (SPLIT|STAYS|SETTLED) —(.*)$")
# The machine-readable half of a directive: a line count the gate can check. Digit
# groups may carry `,` or `_` because this repository writes both.
LINES_ASSERT_RE = re.compile(r"^// @file-disposition-lines: ([0-9][0-9,_]*)\s*$", re.M)
# >>> A NEAR MISS MUST NOT READ AS ABSENCE. <<< The marker is OPTIONAL, so a typo in
# it -- an indent, a double space, a missing space, a capital L, a trailing re-take
# date -- is indistinguishable from not writing one, and the gate goes green on a
# claim it never checked. This second pattern matches the NAME in any spelling; a
# line it matches that the canonical pattern does not is reported rather than
# skipped. Fail-closed on the author's typo, which is the only direction that helps.
#
# >>> THE `@` IS OPTIONAL HERE AND MANDATORY IN THE CANONICAL PATTERN, AND THAT
# ASYMMETRY IS THE POINT. <<< The sigil is a character that can be left out, so
# requiring it in the RECOGNISER makes dropping it a silent absence. A live
# `// file-disposition-lines: 9999` must be reported as a near miss rather than
# reducing the number of verified assertions at exit 0. Every character a
# near-miss pattern demands is a typo it cannot see.
LINES_ASSERT_LOOSE = re.compile(r"^\s*//+\s*@?file-disposition-lines\b.*$", re.M | re.I)


def directive_present(text, state):
    """One of the three `// @file-disposition:` forms, at column 0, in the first
    40 physical lines, with the dash exactly U+2014 and non-empty text
    after it. `//` line comments survive this view; `/* */` blocks and
    every string form are blanked."""
    view = masked(text, state, {"c", "l"})
    for line in view.split("\n")[:40]:
        m = DIRECTIVE_RE.match(line)
        if m and m.group(2).strip():
            return True
    return False


malformed = []
near_misses = []
n_asserts = 0
fails = []

# COVERAGE, not just a verdict. An `assert_pass` control that only checks "no
# FAIL line for this path" passes just as happily when the path was never
# scanned at all — a fixture moved out of the pathspec, a glob that went blind,
# a tracked-file listing that came back short. With this on, every scanned path
# is named on stderr and the self-test asserts its fixture is among them.
if os.environ.get("CHECK_FILE_DISPOSITIONS_LIST_SCANNED"):
    for rel in paths:
        print(f"SCANNED: {rel}", file=sys.stderr)

for rel in paths:
    full = os.path.join(repo, rel)
    try:
        with open(full, "rb") as f:
            raw = f.read()
    except OSError as e:
        malformed.append(f"{rel}: could not read it ({e})")
        continue
    # PHYSICAL lines, not newline terminators: a file whose last line has no
    # trailing newline has one more line than it has `\n`. `cargo fmt --check`
    # guarantees the trailing newline for tracked .rs upstream, so this only
    # bites a file that is already failing another gate — but the ceiling is
    # this gate's own to own, and a 3,001-line file must not pass it.
    lines = raw.count(b"\n") + (0 if (not raw or raw.endswith(b"\n")) else 1)
    text = raw.decode("utf-8", "replace")
    state = classify(text)

    # ---- 2. A DIRECTIVE IS CHECKED WHEREVER IT IS, NOT ONLY OVER THE CEILING ----
    # >>> SKIPPING AN UNDER-CEILING FILE WOULD LEAVE ITS DIRECTIVE UNCHECKED.
    # <<< A directive would stop being read by anything the moment
    # it was HONOURED: a file brought under the trigger leaves its directive
    # as unchecked prose, free to go false.
    #
    # WHAT IS CHECKED IS AN ASSERTION, NOT A SENTENCE. "Is this prose true" is not
    # a machine question and a regex over four different spellings of a line count
    # is a hand-typed list wearing a pattern. A directive may carry
    # `// @file-disposition-lines: <N>`, and where it does, N must be the file's CURRENT
    # physical line count -- the same move `cite-frozen:` makes for a citation: the
    # marker is a TRANSLATION of the sentence and is checkable where the sentence
    # is not. It is OPTIONAL, so nothing in the tree moves by its absence.
    for m in LINES_ASSERT_RE.finditer(text):
        if state[m.start()] != "l":
            continue          # inside a string or a block comment: not an assertion
        claimed = int(m.group(1).replace(",", "").replace("_", ""))
        if claimed != lines:
            fails.append(
                f"FAIL: {rel}: its `// @file-disposition-lines:` assertion says {claimed} "
                f"and the file is {lines} lines. A directive's figure goes stale on "
                f"the next commit that touches the file; re-take it or state it as "
                f"a past reading with its date."
            )
        n_asserts += 1
    for m in LINES_ASSERT_LOOSE.finditer(text):
        # THE STATE IS READ AT THE `//`, NOT AT THE MATCH START. This pattern begins
        # `^\s*`, so on an INDENTED near miss the match starts on whitespace, which
        # the lexer classifies as code — and the row written for the indented case
        # was the one it silently skipped. Its own control caught it.
        slashes = m.group(0).find("//")
        if slashes < 0 or state[m.start() + slashes] != "l":
            continue
        if LINES_ASSERT_RE.match(m.group(0)):
            continue
        near_misses.append(
            f"FAIL: {rel}: {m.group(0).strip()!r} is almost an `// @file-disposition-lines:` "
            f"assertion and is not one, so nothing checks it. The exact form is "
            f"`// @file-disposition-lines: <N>` at column 0, with one space after the colon "
            f"and nothing after the number."
        )

    if lines <= ceiling:
        continue
    if shield_present(text, state) or directive_present(text, state):
        continue
    fails.append(f"FAIL: {rel}: {lines} lines, no shield and no `// @file-disposition:` directive")

if malformed:
    print(
        f"{PROG}: THE GATE COULD NOT RUN for {len(malformed)} git-tracked "
        "path(s) — it verified NOTHING about them:",
        file=sys.stderr,
    )
    for m in malformed:
        print(f"  {m}", file=sys.stderr)
    sys.exit(2)

fails.extend(near_misses)
if fails:
    for f in fails:
        print(f, file=sys.stderr)
    # THE SUMMARY NAMES THE CLASS THAT ACTUALLY FIRED. Each class is counted
    # separately, so a stale line assertion is never summarised as a file
    # over the ceiling with no directive -- which it is not.
    n_stale = sum(1 for f in fails if "@file-disposition-lines" in f and "is almost" not in f)
    n_near = sum(1 for f in fails if "is almost" in f)
    n_missing = len(fails) - n_stale - n_near
    parts = []
    if n_missing:
        parts.append(
            f"{n_missing} file(s) over {ceiling} lines with neither a shield nor "
            "a `// @file-disposition:` directive — add one of the three "
            "`// @file-disposition: SPLIT|STAYS|SETTLED — ...` lines in the file's first "
            "40 lines, or a file-scoped `#![cfg(test)]` before its first item if "
            "it is a test body"
        )
    if n_near:
        parts.append(
            f"{n_near} line(s) that are ALMOST an `// @file-disposition-lines:` assertion and "
            "are not one — the marker is optional, so a typo in it is otherwise "
            "indistinguishable from choosing not to write one"
        )
    if n_stale:
        parts.append(
            f"{n_stale} file(s) whose `// @file-disposition-lines:` assertion no longer "
            "matches the file — that assertion is the checkable half of a "
            "directive and it is checked at EVERY size, not only over the ceiling"
        )
    print(f"{PROG}: " + "; ".join(parts)
          + ". This gate never proposes a split and never refuses a STAYS.",
          file=sys.stderr)
    sys.exit(1)

# THE COVERAGE, NOT JUST THE VERDICT. Without this figure a run that verified
# four assertions and a run that found none print identically, which is the
# shape this repository has a standing rule about.
print(f"{PROG}: ok: {len(paths)} file(s) scanned under crates/*/src, none over "
      f"{ceiling} lines without a disposition, {n_asserts} `@file-disposition-lines` "
      f"assertion(s) verified")
sys.exit(0)
PY
}

if [ "${1:-}" = "--self-test" ]; then
  st_tmp="$(mktemp -d)"
  trap 'rm -rf "$st_tmp"' EXIT
  st_count=0

  # ---- build every fixture repo up front, in one python pass -------------
  # Fixtures are built in a temp dir and never touch this tree. Every
  # "over the ceiling" file uses ceiling+5 lines except the two boundary
  # fixtures, which use exactly ceiling and ceiling+1.
  python3 - "$st_tmp" "$CEILING" <<'PY'
import os
import subprocess
import sys

work, ceiling = sys.argv[1], int(sys.argv[2])
DASH = "—"
over = ceiling + 5


def write(path, lines):
    full = os.path.join(work, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(("\n".join(lines) + "\n").encode("utf-8"))


def write_no_trailing_newline(path, lines):
    """Same as `write`, without the final newline — the shape whose PHYSICAL
    line count is one more than its `\n` count, and which a terminator count
    lets slip under the ceiling."""
    full = os.path.join(work, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write("\n".join(lines).encode("utf-8"))


def spdx():
    return [
        "// Test-Fixture-Copyright: 2026 Test <test@example.com>",
        "// Test-Fixture-Licence-Tag: not-a-real-Apache-2.0-line",
    ]


def pad(lines, total, filler="// filler"):
    lines = list(lines)
    while len(lines) < total:
        lines.append(filler)
    return lines[:total]


def at_line(line_no, text, tail=("fn foo() {}",)):
    lines = spdx()
    while len(lines) < line_no - 1:
        lines.append("// filler")
    while len(lines) < line_no:
        lines.append("")
    lines[line_no - 1] = text
    lines.extend(tail)
    return lines


m = "matrix/crates/x/src"
write(f"{m}/c01_none.rs", pad(spdx() + ["fn foo() {}"], over))
write(f"{m}/c02_split3.rs", pad(at_line(3, f"// @file-disposition: SPLIT {DASH} first child foo"), over))
write(f"{m}/c03_stays40.rs", pad(at_line(40, f"// @file-disposition: STAYS {DASH} one subject, this whole file"), over))
write(f"{m}/c04_stays41.rs", pad(at_line(41, f"// @file-disposition: STAYS {DASH} one subject, this whole file"), over))
# ---- the `// @file-disposition-lines:` assertion, and the SCOPE it is checked at ----
# These four are the controls for the hole this gate had: a directive stopped
# being read the moment it was honoured, so every live directive in the tree --
# all of them on files UNDER the ceiling -- was unchecked prose.
# `under` is deliberately a SMALL file, so these say something the ceiling rows
# cannot: the assertion is checked at every size.
# The figure is COMPUTED from the fixture rather than typed, because a
# hand-typed one is a second thing that can be wrong, and a typed one here
# was: it asserted 6 lines in a 5-line file and the gate was right.
_body = [f"// @file-disposition: STAYS {DASH} one subject", "fn foo() {}"]
under_ok = spdx() + [f"// @file-disposition-lines: {len(spdx()) + 1 + len(_body)}"] + _body
write(f"{m}/c25_lines_ok_under_ceiling.rs", under_ok)
write(f"{m}/c26_lines_wrong_under_ceiling.rs",
      spdx() + ["// @file-disposition-lines: 9999", f"// @file-disposition: STAYS {DASH} one subject", "fn foo() {}"])
write(f"{m}/c27_lines_wrong_over_ceiling.rs",
      pad(spdx() + ["// @file-disposition-lines: 7", f"// @file-disposition: STAYS {DASH} one subject", "fn foo() {}"], over))
# An assertion is a LINE COMMENT or it is not an assertion: inside a string it is
# data, which is the same rule the directive itself is read under.
# A NEAR MISS IS NOT AN ABSENCE. The marker is optional, so unless the gate reports
# one, every one of these reads exactly like not writing one and the gate goes green
# on a claim it never checked. Four spellings, one per fixture, because a class
# checked in one spelling is a hand-typed list wearing a pattern.
write(f"{m}/c29_lines_indented.rs",
      spdx() + ["  // @file-disposition-lines: 9999", f"// @file-disposition: STAYS {DASH} s", "fn foo() {}"])
write(f"{m}/c30_lines_no_space.rs",
      spdx() + ["//@file-disposition-lines: 9999", f"// @file-disposition: STAYS {DASH} s", "fn foo() {}"])
write(f"{m}/c31_lines_trailing_text.rs",
      spdx() + ["// @file-disposition-lines: 9999 (re-taken 2026-09-22)", f"// @file-disposition: STAYS {DASH} s", "fn foo() {}"])
write(f"{m}/c32_lines_capital.rs",
      spdx() + ["// @file-disposition-Lines: 9999", f"// @file-disposition: STAYS {DASH} s", "fn foo() {}"])
# The sigil DROPPED. This spelling is new with the `@` and is the near miss a reader
# is most likely to write, because the name reads perfectly well without it.
write(f"{m}/c33_lines_no_sigil.rs",
      spdx() + ["// file-disposition-lines: 9999", f"// @file-disposition: STAYS {DASH} s", "fn foo() {}"])
write(f"{m}/c28_lines_in_a_string.rs",
      spdx() + ['const RAW: &str = r"', "// @file-disposition-lines: 9999", '";', "fn foo() {}"])
write(f"{m}/c05_shield_first.rs", pad(spdx() + ["#![cfg(test)]", "", "fn foo() {}"], over))
write(f"{m}/c06_shield_after_fn.rs", pad(spdx() + ["fn foo() {}", "#![cfg(test)]"], over))
write(
    f"{m}/c07_expect_then_shield.rs",
    pad(spdx() + ['#![expect(clippy::disallowed_methods, reason = "x")]', "#![cfg(test)]", "fn foo() {}"], over),
)
write(f"{m}/c08_shield_block_comment.rs", pad(spdx() + ["/*", "#![cfg(test)]", "*/", "fn foo() {}"], over))
write(
    f"{m}/c09_directive_raw_string.rs",
    pad(spdx() + ['const RAW: &str = r"', f"// @file-disposition: SPLIT {DASH} first child foo", '";', "fn foo() {}"], over),
)
write(f"{m}/c10_shield_all_test.rs", pad(spdx() + ["#![cfg(all(test, unix))]", "fn foo() {}"], over))
write(f"{m}/c11_shield_any_test.rs", pad(spdx() + ["#![cfg(any(test, unix))]", "fn foo() {}"], over))
write(f"{m}/c12_shield_not_test.rs", pad(spdx() + ["#![cfg(not(test))]", "fn foo() {}"], over))
write(
    f"{m}/c13_directive_docbang.rs",
    pad(spdx() + [f"//! @file-disposition: SPLIT {DASH} first child foo", "fn foo() {}"], over),
)
write(
    f"{m}/c14_directive_block_comment.rs",
    pad(spdx() + ["/*", f"// @file-disposition: SPLIT {DASH} first child foo", "*/", "fn foo() {}"], over),
)
write(
    f"{m}/c15_directive_indented.rs",
    pad(spdx() + [f" // @file-disposition: SPLIT {DASH} first child foo", "fn foo() {}"], over),
)
write(f"{m}/c16_directive_no_text.rs", pad(spdx() + [f"// @file-disposition: SPLIT {DASH}", "fn foo() {}"], over))
write(
    f"{m}/c21_string_attr_text.rs",
    pad(
        spdx()
        + [
            "fn production_source() -> usize {",
            '    let marker = ["#[cfg(test)]\\n", "mod tests {"].concat();',
            '    let other = "#![cfg(test)]";',
            "    marker.len() + other.len()",
            "}",
        ],
        over,
    ),
)
write(
    f"{m}/c22_commented_and_string_shield.rs",
    pad(spdx() + ["// #![cfg(test)]", "fn planted() {", '    let _s = "#![cfg(test)]";', "}"], over),
)
write(f"matrix/crates/x/src/a/b/c23_nested_depth.rs", pad(spdx() + ["fn foo() {}"], over))

write("boundary_pass/crates/x/src/exact.rs", pad(spdx() + ["fn foo() {}"], ceiling))
write("boundary_fail/crates/x/src/over.rs", pad(spdx() + ["fn foo() {}"], ceiling + 1))
write("tests_ignored/crates/x/src/small.rs", spdx() + ["fn foo() {}"])
write("tests_ignored/crates/x/tests/big.rs", pad(spdx() + ["fn foo() {}"], over))
write_no_trailing_newline(
    "boundary_fail_no_eol/crates/x/src/over_no_eol.rs",
    pad(spdx() + ["fn foo() {}"], ceiling + 1),
)
write("unreadable/crates/x/src/small.rs", spdx() + ["fn foo() {}"])
write("unreadable/crates/x/src/phantom.rs", pad(spdx() + ["fn foo() {}"], over))

for repo in (
    "matrix",
    "boundary_pass",
    "boundary_fail",
    "boundary_fail_no_eol",
    "tests_ignored",
    "unreadable",
):
    root = os.path.join(work, repo)
    subprocess.run(["git", "init", "-q", root], check=True)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True)

# A git-tracked path this gate cannot open: staged, then deleted from the
# working tree. `git ls-files` reads the index, not the working tree, so
# it still lists this path while `open()` on it fails.
os.remove(os.path.join(work, "unreadable/crates/x/src/phantom.rs"))
PY

  expect() { # expect <label> <want-rc> <repo-dir>
    st_count=$((st_count + 1))
    local label="$1" want="$2" dir="$3" out rc
    set +e
    out="$(run_gate "$dir" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" != "$want" ]; then
      echo "check-file-dispositions self-test FAILED: $label wanted rc=$want, got rc=$rc" >&2
      echo "$out" | sed 's/^/    /' >&2
      exit 2
    fi
    echo "self-test: $label -> rc=$rc, as expected"
  }

  assert_fail() { # assert_fail <label> <relpath-under-matrix>
    st_count=$((st_count + 1))
    if grep -qF "FAIL: $2:" <<<"$matrix_out"; then
      echo "self-test: $1 ($2) -> reported FAIL, as expected"
    else
      echo "check-file-dispositions self-test FAILED: $1 ($2) — expected a FAIL line, found none" >&2
      echo "$matrix_out" | sed 's/^/    /' >&2
      exit 2
    fi
  }

  assert_pass() { # assert_pass <label> <relpath-under-matrix>
    st_count=$((st_count + 1))
    # COVERAGE FIRST: without this, a fixture the gate never scanned produces no
    # FAIL line and reads exactly like a fixture it scanned and accepted — the
    # control could not fail. Proven: moving an accepted fixture out of the
    # pathspec left every accept control green until this line existed.
    if ! grep -qF "SCANNED: $2" <<<"$matrix_out"; then
      echo "check-file-dispositions self-test FAILED: $1 ($2) — the gate never SCANNED this fixture, so its acceptance proves nothing" >&2
      echo "$matrix_out" | sed 's/^/    /' >&2
      exit 2
    fi
    if grep -qF "FAIL: $2:" <<<"$matrix_out"; then
      echo "check-file-dispositions self-test FAILED: $1 ($2) — reported FAIL, expected it to pass silently" >&2
      echo "$matrix_out" | sed 's/^/    /' >&2
      exit 2
    else
      echo "self-test: $1 ($2) -> no FAIL line, as expected"
    fi
  }

  # ---- the matrix: 19 controls, one gate invocation --------------------
  set +e
  matrix_out="$(CHECK_FILE_DISPOSITIONS_LIST_SCANNED=1 run_gate "$st_tmp/matrix" 2>&1)"
  matrix_rc=$?
  set -e
  if [ "$matrix_rc" != 1 ]; then
    echo "check-file-dispositions self-test FAILED: the matrix fixture wanted rc=1 (it plants real offenders), got rc=$matrix_rc — if this is 0, the pathspec matched nothing and every control below would be vacuous" >&2
    echo "$matrix_out" | sed 's/^/    /' >&2
    exit 2
  fi

  assert_fail "C1 over ceiling, no directive, no shield"          "crates/x/src/c01_none.rs"
  assert_pass "C2 valid SPLIT directive at line 3"                "crates/x/src/c02_split3.rs"
  assert_pass "C3 valid STAYS directive at line 40"               "crates/x/src/c03_stays40.rs"
  assert_fail "C4 valid STAYS directive at line 41 (outside the window)" "crates/x/src/c04_stays41.rs"
  assert_pass "C5 #![cfg(test)] as the first attribute"           "crates/x/src/c05_shield_first.rs"
  assert_fail "C6 #![cfg(test)] after a fn item"                  "crates/x/src/c06_shield_after_fn.rs"
  assert_pass "C7 #![expect(...)] first, #![cfg(test)] second"    "crates/x/src/c07_expect_then_shield.rs"
  assert_fail "C8 #![cfg(test)] inside a /* */ block comment"     "crates/x/src/c08_shield_block_comment.rs"
  assert_fail "C9 directive text inside a multi-line raw string"  "crates/x/src/c09_directive_raw_string.rs"
  assert_pass "C10 #![cfg(all(test, unix))] first"                "crates/x/src/c10_shield_all_test.rs"
  assert_fail "C11 #![cfg(any(test, unix))]"                      "crates/x/src/c11_shield_any_test.rs"
  assert_fail "C12 #![cfg(not(test))]"                            "crates/x/src/c12_shield_not_test.rs"
  assert_fail "C13 directive text inside //!"                     "crates/x/src/c13_directive_docbang.rs"
  assert_fail "C14 directive text inside /* */"                   "crates/x/src/c14_directive_block_comment.rs"
  assert_fail "C15 directive indented by one space"               "crates/x/src/c15_directive_indented.rs"
  assert_fail "C16 // @file-disposition: SPLIT with nothing after the dash" "crates/x/src/c16_directive_no_text.rs"
  # ---- the line assertion, at BOTH sizes, because the scope is the point ----
  assert_pass "C25 a correct @file-disposition-lines assertion, UNDER the ceiling" "crates/x/src/c25_lines_ok_under_ceiling.rs"
  assert_fail "C26 a WRONG assertion on a small file — the hole this gate had" "crates/x/src/c26_lines_wrong_under_ceiling.rs"
  assert_fail "C27 a WRONG assertion over the ceiling is caught too" "crates/x/src/c27_lines_wrong_over_ceiling.rs"
  assert_pass "C28 an assertion inside a string literal is data, not a claim" "crates/x/src/c28_lines_in_a_string.rs"
  # A near miss is reported, not skipped — a typo in an OPTIONAL marker is
  # otherwise indistinguishable from choosing not to write one.
  assert_fail "C29 an INDENTED near-miss marker is reported, not ignored" "crates/x/src/c29_lines_indented.rs"
  assert_fail "C30 a near miss with no space after //" "crates/x/src/c30_lines_no_space.rs"
  assert_fail "C31 a near miss with trailing text after the number" "crates/x/src/c31_lines_trailing_text.rs"
  assert_fail "C32 a near miss differing only in CASE" "crates/x/src/c32_lines_capital.rs"
  assert_fail "C33 a near miss with the @ sigil DROPPED — the class the rename created" "crates/x/src/c33_lines_no_sigil.rs"
  assert_fail "C21 main.rs:9057-shape attribute text inside strings" "crates/x/src/c21_string_attr_text.rs"
  assert_fail "C22 commented-out and in-string shield text must not establish a test-only shield" "crates/x/src/c22_commented_and_string_shield.rs"
  assert_fail "C23 the pathspec reaches a nested directory (depth 2)" "crates/x/src/a/b/c23_nested_depth.rs"

  # ---- four isolated controls -------------------------------------------
  expect "C17 exactly the ceiling (3000) lines, no disposition"    0 "$st_tmp/boundary_pass"
  expect "C18 ceiling+1 (3001) lines, no disposition"              1 "$st_tmp/boundary_fail"
  expect "C24 ceiling+1 (3001) PHYSICAL lines with NO trailing newline" 1 "$st_tmp/boundary_fail_no_eol"
  expect "C19 a file under crates/x/tests/ (not src/) is ignored"  0 "$st_tmp/tests_ignored"
  expect "C20 a git-tracked path this gate cannot open"            2 "$st_tmp/unreadable"

  echo "check-file-dispositions self-test: PASSED — $st_count controls"
  exit 0
fi

run_gate "$PWD"
