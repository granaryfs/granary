#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The structural scanner behind scripts/check-vfs-purity.sh's items 1 and 3
# (the source-axis rule). Reuses scripts/fsguard-scan.py's comment/string
# stripper and block-depth machinery rather than writing a third lexer —
# imported by file path (`fsguard-scan.py` is not a valid module name) via
# `importlib`, never copied.
#
# Two modes, one process each (never piped through `head`/`xargs`, for the
# same reason fsguard-scan.py gives: a batched or truncated capture can
# print more than one structured line, or none, into a caller's `$(...)`).
#
#   vfs-purity-scan.py --attr <path>
#       Item 1. Prints `ATTR <line>` for every ACTIVE, crate-level inner
#       attribute at <path> that is structurally
#       `#![cfg_attr(not(test), no_std)]` — parsed on the comment/string
#       -stripped text, so a commented-out or string-quoted spelling
#       (the self-test's DECOY) produces no line. The PREDICATE is matched
#       exactly: `not(any(test, feature = "x"))` is a different predicate
#       and produces no `ATTR` line either — this is what "assert the
#       predicate too" means structurally rather than as a separate check.
#       Also prints `NEAR-MISS <line>` for a `cfg_attr(not(...), no_std)`
#       whose predicate is NOT exactly `not(test)` — a diagnostic only,
#       never treated as a pass.
#       Exit 0 normally (whether or not any `ATTR` line was found — the
#       caller decides pass/fail); exit 2 if <path> cannot be read.
#
#   vfs-purity-scan.py --closure
#       Item 3. Reads NUL-separated file paths from stdin (`find <dir>
#       -name '*.rs' -print0 | vfs-purity-scan.py --closure`) and prints
#       `SOURCE <path>:<line>: <text>  <- <why>` for every `#[path]` or
#       `include!` (under any spelling: aliased, qualified, renamed —
#       fsguard-scan.py's own closure patterns) construction found.
#
#       DELIBERATELY NARROWER than `fsguard-scan.py --source-closure`:
#       that scanner also refuses every `macro_rules!` definition, which
#       item 2 (scripts/check-vfs-purity.sh, the post-expansion
#       `extern crate std` check) requires NOT to be banned here — its own
#       control is "a macro that EMITS the escape, BESIDE a legitimate
#       macro that must stay green", and a legitimate macro is exactly
#       what fsguard-scan.py's blanket closure mode refuses on sight. So
#       this mode calls the SAME underlying function
#       (`scan_source_inputs`) — no copied or re-derived regex — and
#       filters its `macro_rules!` findings out before printing, keeping
#       only the two constructions item 3 actually bans.
#       Exit 0 normally; exit 2 if any input file cannot be read (a file
#       this scanner cannot read must be a refusal, never a silent skip
#       that reads as "no findings").
#
import importlib.util
import os
import re
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_FSGUARD_PATH = os.path.join(_SCRIPT_DIR, "fsguard-scan.py")


def _load_fsguard_scan():
    spec = importlib.util.spec_from_file_location("fsguard_scan_lib", _FSGUARD_PATH)
    if spec is None or spec.loader is None:
        print(f"ERROR could not load {_FSGUARD_PATH} as a module", file=sys.stderr)
        sys.exit(2)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:  # noqa: BLE001 — any failure here is a refusal
        print(f"ERROR could not import {_FSGUARD_PATH}: {e}", file=sys.stderr)
        sys.exit(2)
    return mod


fsguard = _load_fsguard_scan()

# Non-optional `!` — fsguard.ATTR_OPEN_RE's own `!?` matches BOTH `#[` and
# `#![`, because it exists to find attributes of either kind; item 1 cares
# only about the INNER form, which is what makes an attribute crate-level
# when it sits outside every brace.
INNER_ATTR_OPEN_RE = re.compile(rf"#{fsguard.WS}*!{fsguard.WS}*\[")

# The exact predicate, whitespace-tolerant, anchored to the WHOLE
# attribute body (`fullmatch`) so `not(test)` cannot match inside a longer
# predicate it does not equal — `not(any(test, feature = "x"))` contains
# the substring `test` but is a different, weaker predicate.
CFG_ATTR_EXACT_RE = re.compile(
    rf"^{fsguard.WS}*cfg_attr{fsguard.WS}*\({fsguard.WS}*not{fsguard.WS}*"
    rf"\({fsguard.WS}*test{fsguard.WS}*\){fsguard.WS}*,{fsguard.WS}*no_std{fsguard.WS}*\){fsguard.WS}*$"
)
# A looser net for the diagnostic-only NEAR-MISS line: any `cfg_attr` whose
# first argument is a `not(...)` call and whose second is `no_std`, so a
# predicate that widened (or narrowed) the exact form still gets named
# rather than silently vanishing into "no attribute found at all". One
# level of nesting is allowed inside `not(...)` — `not(any(test, feature =
# "x"))` is exactly the widened predicate this exists to name — the same
# one-level allowance banned_call_re's turbofish match uses, for the same
# reason: a predicate this narrowly nested is what a real widening attempt
# looks like, and a second level would rather fall back to unmatched than
# be patched in here.
CFG_ATTR_NEAR_RE = re.compile(
    rf"^{fsguard.WS}*cfg_attr{fsguard.WS}*\({fsguard.WS}*not{fsguard.WS}*"
    rf"\({fsguard.WS}*(?:[^()]|\([^()]*\)){{0,500}}{fsguard.WS}*\)"
    rf"{fsguard.WS}*,{fsguard.WS}*no_std{fsguard.WS}*\){fsguard.WS}*$"
)


def scan_attr(path: str):
    """Item 1. Returns (attr_lines, near_miss_lines, error)."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except UnicodeDecodeError as e:
        return [], [], f"{path}: not valid UTF-8 ({e}) — refused, not skipped"
    except OSError as e:
        return [], [], f"{path}: could not read ({e})"

    clean = fsguard.RAW_IDENT_RE.sub("  ", fsguard.strip_comments_and_strings(fsguard.blank_shebang(raw)))
    spans = fsguard.block_spans(clean)
    attr_lines = []
    near_lines = []
    for m in INNER_ATTR_OPEN_RE.finditer(clean):
        open_bracket = m.end() - 1
        close_bracket = fsguard.find_matching(clean, open_bracket, "[", "]")
        if close_bracket is None:
            continue
        # CRATE-LEVEL: an inner attribute licenses to the end of its
        # enclosing block, which at file scope (no enclosing `{`) is the
        # whole file — `innermost_end` returning `len(clean)` is exactly
        # that condition, reused rather than re-derived.
        if fsguard.innermost_end(spans, m.start(), len(clean)) != len(clean):
            continue
        body = clean[open_bracket + 1 : close_bracket]
        line_no = clean.count("\n", 0, m.start()) + 1
        if CFG_ATTR_EXACT_RE.fullmatch(body):
            attr_lines.append(line_no)
        elif CFG_ATTR_NEAR_RE.fullmatch(body):
            near_lines.append(line_no)
    return attr_lines, near_lines, None


def scan_closure_narrow(path: str):
    """Item 3. Returns (hits, error) — `fsguard.scan_source_inputs`'s own
    hits, minus every one whose KIND is `fsguard.MACRO_RULES_KIND` (see
    module docstring: item 2 requires a legitimate macro to stay green,
    and fsguard's blanket closure mode refuses macro_rules! on sight).

    Filters on `.kind`, the machine-readable tag that
    `fsguard.scan_source_inputs` attaches to each `Hit`,
    never on a substring of the human-readable reason text.
    A filter using `" <- macro_rules! " not in h` would depend
    on the reason keeping that exact spelling: rewording it
    could make legitimate macros appear as item-3 findings.
    Putting the same phrase in a #[path]/include! reason
    could instead hide a real finding. The kind tag keeps
    this distinction independent of the diagnostic prose,
    so the reason can be reworded without changing which
    hits this function excludes from the closure scan.
    Only `fsguard.MACRO_RULES_KIND` hits are excluded."""
    hits, error = fsguard.scan_source_inputs(path)
    if error is not None:
        return [], error
    narrowed = [h for h in hits if h.kind != fsguard.MACRO_RULES_KIND]
    return narrowed, None




def main() -> None:
    argv = sys.argv[1:]
    if "--attr" in argv:
        i = argv.index("--attr")
        if i + 1 >= len(argv):
            print("ERROR --attr needs a path", file=sys.stderr)
            sys.exit(2)
        path = argv[i + 1]
        attr_lines, near_lines, error = scan_attr(path)
        if error is not None:
            print(f"ERROR {error}", file=sys.stderr)
            sys.exit(2)
        for ln in attr_lines:
            print(f"ATTR {path}:{ln}")
        for ln in near_lines:
            print(f"NEAR-MISS {path}:{ln}")
        return
    if "--closure" in argv:
        paths = [p for p in sys.stdin.buffer.read().split(b"\0") if p]
        for raw_path in paths:
            try:
                path = raw_path.decode("utf-8")
            except UnicodeDecodeError as e:
                print(
                    f"ERROR {raw_path!r}: the FILE NAME is not valid UTF-8 ({e}) — refused, not "
                    "skipped.",
                    file=sys.stderr,
                )
                sys.exit(2)
            hits, error = scan_closure_narrow(path)
            if error is not None:
                print(f"ERROR {error}", file=sys.stderr)
                sys.exit(2)
            for h in hits:
                print(f"SOURCE {h}")
        return
    print(
        "ERROR usage: vfs-purity-scan.py --attr <path> | --closure < NUL-separated paths",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
