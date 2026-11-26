#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The attribute scanner behind scripts/check-fsguard-sites.sh's checks 3
# (licensed-site count) and 4 (bare-allow kill switch).
#
# A SEPARATE FILE rather than an embedded heredoc, and it has to be:
# `find ... -print0 | python3 - <<'EOF'` does not work, because
# `python3 -` reads the SCRIPT ITSELF from stdin, so a heredoc attached
# to the same command is consumed as source code and nothing is left for
# `sys.stdin.buffer.read()`. `find` then writes into a pipe nobody
# drains and SIGPIPEs. A real file on disk frees stdin for the file list.
#
# Reads NUL-separated file paths from stdin (`find <dir> -name '*.rs'
# -print0 | python3 scripts/fsguard-scan.py`) in ONE process — never via
# `xargs`, which can batch its target command into more than one
# invocation and so print more than one `COUNT` line into a caller's
# `$(...)` capture.
#
# Prints `COUNT <n>` (the number of `#[expect(...)]`/`#![expect(...)]`
# attributes — including one nested inside `#[cfg_attr(cond, expect(...))]`
# — across every file whose lint LIST names the ban), then one
# `ALLOW <file>:<line>: <text>` line per `#[allow(...)]`/`#![allow(...)]`
# attribute (`cfg_attr`-nested included) that does (docs/coding-standards.md
# MUST-1: never a bare allow for this lint). On any file it cannot read
# as UTF-8, or any other read error, prints `ERROR <path>: <reason>` to
# stderr and exits 2 — refused, never silently skipped, because a
# scanner that skips a file it cannot read reports "clean" for it.
#
# WHAT THE SCANNER HAS TO GET RIGHT, and why each one is load-bearing.
# Every item below is a shape that is legal Rust, compiles, and hides an
# attribute from a matcher that does not model it:
#
#   - COMMENTS AND STRINGS ARE BLANKED FIRST, to same-length whitespace
#     with every newline preserved, so a commented-out attribute or a
#     `reason = "...#[expect(clippy::disallowed_methods)]..."` mention
#     cannot match, a stray `)` inside a string cannot confuse the
#     bracket matcher, and every line number stays exact.
#   - BLOCK COMMENTS NEST in Rust (`/* /* */ */` is ONE comment), so the
#     stripper carries a depth counter. Stopping at the first `*/`
#     leaves text after it exposed.
#   - A CHAR LITERAL HOLDING A DOUBLE QUOTE (`'"'`, which this crate
#     really does write, in `trim_matches('"')`) must be recognized as a
#     char literal. Treating its `"` as the start of a string blanks
#     everything up to the next literal `"` in the file — measured at 28
#     real lines in one file — hiding whatever sits in between. A
#     LIFETIME (`'a`, `'static`) is what a bare `'` means everywhere
#     else and simply fails the char-literal grammar, so it is left
#     alone.
#   - A `\`-NEWLINE LINE CONTINUATION inside a string is valid Rust.
#     Blanking the escaped character unconditionally eats the newline
#     itself and shifts every later line number by one per continuation.
#     The newline is preserved; only true two-character escapes blank
#     both bytes.
#   - THE ATTRIBUTE IS MATCHED WHOLE, by balanced bracket, and its body
#     is then searched for `allow(`/`expect(` ANYWHERE inside — so
#     `#[cfg_attr(cond, allow(...))]` (a real idiom in this crate) is
#     found, and so is a lint that is not the first token in the list.
#     Anchoring to "the lint immediately after `allow(`" misses both.
#   - THE THREE TOKENS `#`, `!`, `[` MAY BE SEPARATED BY WHITESPACE.
#     `# [allow(...)]` and `# ![allow(...)]` are both accepted by rustc.
#     `ATTR_OPEN_RE` is the shape of the tokens, not of one spelling.
#   - A RAW IDENTIFIER NAMES THE SAME THING: `clippy::r#disallowed_methods`
#     IS `clippy::disallowed_methods`, and `#[r#allow(...)]` IS
#     `#[allow(...)]`. `r#` prefixes are normalized away AFTER the lexer
#     (never before — an `r#` inside a raw STRING is not an identifier),
#     length-preservingly, so line numbers survive.
#   - WHITESPACE AROUND `::` is legal (`clippy :: disallowed_methods`),
#     and a comment inside the path collapses to whitespace once
#     comments are blanked, so one whitespace-tolerant pattern covers
#     both.
#   - THE SHEBANG RULE IS rustc's, not an approximation — see
#     `blank_shebang`. Getting it wrong in the over-discarding direction
#     BLANKS A LIVE INNER ATTRIBUTE and the gate then reports "no bare
#     #[allow]" on a file that switched the lint off for its whole self.
#   - RUST'S WHITESPACE SET IS NOT PYTHON'S — see `RUST_WHITESPACE` and
#     `WS`. Both the classifier and every regex need it, and fixing only
#     one of them leaves the same hole open.
#
# WHAT THE COMPILER CLOSES, AND WHAT IT DOES NOT.
# `crates/granary-client/Cargo.toml`'s `[lints.clippy]` table denies
# `allow_attributes` and `allow_attributes_without_reason` — in the
# MANIFEST, not on the two crate roots, so that it reaches every target
# of the crate including the seven `tests/*.rs` integration crates,
# which a `lib.rs`/`main.rs` attribute never covered. Both are resolved
# by rustc AFTER macro expansion, so for an OUTER `#[allow(...)]` on an
# item they close every route this scanner cannot see (a lint group
# name, an attribute assembled by a `macro_rules!` or a proc-macro, an
# `include!`d file, a spelling the lexer mis-reads). That is the real
# gate for that shape, and the scanner's kill switch is a second
# independent reading of it. It does NOT reach an `expect` with a
# reason, whichever lints it names — see the macro-route paragraph
# below.
#
# It does NOT close the INNER form. Measured directly on the pinned
# toolchain: a module-level `#![allow(clippy::all, reason = "...")]` —
# whether at the top of a module FILE or inside an inline `mod { ... }`
# — silences the filesystem ban for that whole module and produces NO
# `allow_attributes` diagnostic at all, while the same attribute written
# as an outer `#[allow(...)]` on an item is refused. For inner
# attributes this scanner is therefore not belt-and-braces; it is the
# only check there is, which is why `LINT_RE` below matches the lint's
# GROUP names as well as the lint itself — and why an `expect` naming a
# GROUP rather than the lint is reported as a suppression rather than
# counted as a licence (`LINT_EXACT_RE`).
#
# THE CATEGORICAL LIMIT, recorded next to the check it bounds: this is a
# SURFACE-SYNTAX scanner over the files it is handed, and it never sees
# macro-expanded output. Any construction that defers the attribute's
# own text to expansion time is invisible to it BY DESIGN, not by
# oversight, and would defeat any scanner short of invoking rustc's own
# expansion. WHAT THE SCANNER COVERS IS THE LITERAL SPELLINGS IN THE
# FILES IT WALKS; what narrows that gap is check 6 of
# `scripts/check-fsguard-sites.sh` — the gate's no-macro and
# source-input-closure rules, which refuse `macro_rules!`, `#[path]`,
# the `include` macro under any name, and symlinked sources under the
# crate, and pin its dependency and target-path sets.
#
# TWO ROUTES CHECK 6 CANNOT SEE, and they are not hypothetical:
#   - A MACRO IMPORTED FROM ANOTHER CRATE. Check 6 refuses `macro_rules!`
#     DEFINITIONS under this crate; a macro defined elsewhere and invoked
#     here expands inside a file this gate reads while carrying no
#     `macro_rules!` token at the use site. `libfuzzer_sys::fuzz_target!`
#     is exactly that shape and is live in
#     `crates/granary-client/fuzz/fuzz_targets/` today. The compensating
#     facts are that the dependency set is pinned (so a new macro source
#     is an audit change) and that `allow_attributes` still refuses an
#     OUTER `#[allow]` after expansion.
#   - A `build.rs`. It can generate source into `OUT_DIR` for an
#     `include!` that was written before the rule existed, and nothing in
#     check 6 refuses one being added to this crate. `granary-client` has
#     none today; that is a fact about the tree, not a rule.
#
# A spelling patched here can have a sibling. First, the macro route does
# not only hide a bare allow; it can ADD a group-wide LICENCE. Measured
# on the pinned toolchain, in this crate —
#
#   macro_rules! licensed { ($m:meta) => { #[$m] pub fn planted() {
#       let _ = std::fs::create_dir_all("/x"); } }; }
#   licensed!(expect(clippy::all, reason = "constructed group expect"));
#
# — produced NO `use of a disallowed method` diagnostic (the identical
# body without the licence produces one, run as the control), no
# `allow_attributes` diagnostic (it is an `expect`, and it carries a
# reason), and scanned as `COUNT 0` with no `ALLOW` line. So the ban was
# off for that function with nothing anywhere saying so. That spelling
# is closed here: the call site carries the attribute's tokens
# LITERALLY, so every `allow(...)`/`expect(...)` group in the file is
# matched and one that is not inside an attribute's brackets is reported
# as a hit — see the second loop in `scan_file`.
#
# Then the SIBLING, measured the same way: take the lint PATH as the
# argument instead of the whole attribute —
#
#   macro_rules! licensed { ($p:path) => { #[allow($p)] … } }
#   licensed!(clippy::all);
#
# — and the call site carries no `allow(`/`expect(` tokens at all. Both
# loops here have nothing to match, and the file scans clean. THAT is
# the point at which patching spellings stops: check 6 refuses the
# CONSTRUCTION (no `macro_rules!` under the crate at all), rather than
# resting this route on a compensating fact about today's tree that
# nothing enforces.

import re
import sys

HEX = "0123456789abcdefABCDEF"


# `rustc_lexer::is_whitespace`'s set, VERBATIM — not Python's
# `str.isspace()`. They disagree on U+200E and U+200F (the
# left-to-right and right-to-left marks), which Rust counts as
# whitespace and Python does not: `#!‎[allow(...)]` is an inner
# attribute rustc HONOURS (verified directly — it suppresses
# `dead_code` over an unused fn, zero warnings). An `isspace()`-driven
# classifier breaks at the mark, calls the line a shebang and BLANKS a
# live suppression.
RUST_WHITESPACE = frozenset(
    "\u0009\u000a\u000b\u000c\u000d\u0020"  # tab LF VT FF CR space
    "\u0085"                                  # NEL
    "\u200e\u200f"                            # LRM, RLM — the pair Python omits
    "\u2028\u2029"                            # line separator, paragraph separator
)


def skip_ws_and_comments(text: str, i: int) -> int:
    """Advance past a run of whitespace and comments starting at `i`.
    Deliberately skips DOC comments too, where `rustc_lexer` skips only
    non-doc ones — see `blank_shebang`'s note on which way the
    disagreement has to fall. Whitespace, by contrast, is matched
    EXACTLY (see `RUST_WHITESPACE`): there the safe direction is the
    other one, so a difference cannot be tolerated in either."""
    n = len(text)
    while i < n:
        c = text[i]
        if c in RUST_WHITESPACE:
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    depth += 1
                    i += 2
                elif text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue
        break
    return i


def blank_shebang(text: str) -> str:
    """Blank a FIRST line that rustc discards as a shebang, keeping its
    newline so every line number computed on the result still matches
    the original file: an unbalanced quote, bracket or block-comment
    opener inside a shebang is not Rust source and must not put the
    lexer below into a state the compiler itself is not in.

    The rule is `rustc_lexer::strip_shebang`'s, in full — it is NOT
    "`#![` is an inner attribute". rustc's actual test is: after `#!`,
    skip whitespace and comments — if the next token is `[`, this is an
    INNER ATTRIBUTE and nothing is discarded. So `#! [allow(…)]`,
    `#!` + newline + `[allow(…)]`, and `#!/* c */[allow(…)]` are all
    live inner attributes; recognizing only the adjacent form blanks all
    three, and the gate then reports "no bare #[allow]" with the lint
    suppressed for the whole file. Proved by execution rather than
    by reading rustc: each of those three first lines, wrapping
    `allow(dead_code)` over an unused fn, emits ZERO `never used`
    warnings from `rustc --edition 2024` (the attribute is honoured),
    while `#!/bin/sh is a real shebang` emits ONE (the line is
    discarded).

    A leading UTF-8 BOM is skipped before the classification, as rustc
    does — with a BOM in front a plain `startswith("#!")` is false and
    no shebang is recognized at all, so a BOM plus a QUOTED shebang
    blinds the lexer exactly as an unquoted one would. The
    BOM character itself is left in place: it is one character, not a
    newline, and no lexer or regex below reacts to it.

    Where this deliberately DISAGREES with rustc: `skip_ws_and_comments`
    skips DOC comments too, which rustc does not. The disagreement can
    only make this function decide "inner attribute" where rustc says
    "shebang" — i.e. blank LESS — and that direction is the safe one: it
    can produce a loud false refusal, never a silent miss. (The inputs
    that reach it, e.g. `#!/**d*/[allow(…)]`, do not compile as Rust
    anyway once rustc discards the line.)"""
    start = 1 if text.startswith("\ufeff") else 0
    body = text[start:]
    if not body.startswith("#!"):
        return text
    after = skip_ws_and_comments(body, 2)
    if after < len(body) and body[after] == "[":
        return text  # an inner attribute, exactly as rustc reads it
    end = body.find("\n")
    if end == -1:
        return text[:start] + " " * len(body)
    return text[:start] + " " * end + body[end:]


def try_char_literal(text: str, i: int, n: int):
    """text[i] == "'". Return the index one past the closing quote if
    text[i:] matches Rust's char-literal grammar (a single character, or
    a backslash escape: \\', \\", \\\\, \\n, \\r, \\t, \\0, \\xHH,
    \\u{1..6 hex}), immediately followed by a closing '. Otherwise None
    — the quote starts a LIFETIME (`'a`, `'static`, `'_`), which is
    never closed with a quote, so this grammar simply fails to match."""
    j = i + 1
    if j >= n:
        return None
    if text[j] == "\\":
        k = j + 1
        if k >= n:
            return None
        c = text[k]
        if c in ("'", '"', "\\", "n", "r", "t", "0"):
            k += 1
        elif c == "x":
            k += 1
            start = k
            while k < n and k - start < 2 and text[k] in HEX:
                k += 1
            if k - start != 2:
                return None
        elif c == "u":
            k += 1
            if k >= n or text[k] != "{":
                return None
            k += 1
            start = k
            while k < n and text[k] in HEX:
                k += 1
            if k == start or k >= n or text[k] != "}":
                return None
            k += 1
        else:
            return None
        if k < n and text[k] == "'":
            return k + 1
        return None
    if text[j] == "'":
        return None  # '' is not valid Rust
    k = j + 1
    if k < n and text[k] == "'":
        return k + 1
    return None


def strip_comments_and_strings(text: str) -> str:
    """Blank line comments, NESTED block comments, string literals (plain,
    byte, raw, byte-raw — backslash escapes handled, and a `\\`-newline
    line continuation inside a plain/byte string PRESERVES the newline
    rather than eating it, so line numbers computed on the result stay
    accurate for everything after it), and char/byte-char literals
    (distinguished from lifetimes by requiring the closing quote within
    the literal grammar) — replacing their content with same-length
    whitespace, never removing a newline, so line numbers and the
    surrounding structure both stay valid on the result."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                    continue
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                    continue
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        # raw / byte-raw string: r"...", r#"..."#, br"...", br##"..."##
        if c in ("r", "b"):
            j = i
            if text[j] == "b" and j + 1 < n and text[j + 1] == "r":
                j += 1
            if j < n and text[j] == "r":
                k = j + 1
                hashes = 0
                while k < n and text[k] == "#":
                    hashes += 1
                    k += 1
                if k < n and text[k] == '"':
                    start = i
                    close = '"' + ("#" * hashes)
                    end = text.find(close, k + 1)
                    end = n if end == -1 else end + len(close)
                    for ch in text[start:end]:
                        out.append("\n" if ch == "\n" else " ")
                    i = end
                    continue
        # byte char literal: b'x', b'\'', ...
        if c == "b" and i + 1 < n and text[i + 1] == "'":
            end = try_char_literal(text, i + 1, n)
            if end is not None:
                for ch in text[i:end]:
                    out.append("\n" if ch == "\n" else " ")
                i = end
                continue
        # char literal, vs a lifetime (`'a`, `'static`) which this grammar
        # simply does not match (no closing quote in range).
        if c == "'":
            end = try_char_literal(text, i, n)
            if end is not None:
                for ch in text[i:end]:
                    out.append("\n" if ch == "\n" else " ")
                i = end
                continue
            out.append(c)  # a lifetime marker — not stripped, harmless
            i += 1
            continue
        if c == '"':
            out.append(" ")
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    out.append(" ")
                    i += 1
                    # `\`-newline is a LINE CONTINUATION — preserve the
                    # newline itself so line numbers after it stay
                    # correct; any other escaped character is blanked.
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
                    continue
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def find_matching(text: str, open_pos: int, open_ch: str, close_ch: str):
    """text[open_pos] == open_ch. Return the index of the matching
    close_ch (balanced), or None if the text runs out unbalanced."""
    depth = 0
    i = open_pos
    n = len(text)
    while i < n:
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


# Python's regex `\s` is NOT Rust's whitespace: it omits U+200E and
# U+200F, which rustc treats as whitespace between tokens (the same
# divergence `RUST_WHITESPACE` exists for — and closing it in
# `skip_ws_and_comments` alone was NOT enough, measured: the shebang
# classification then correctly kept `#!<LRM>[allow(...)]` as an inner
# attribute and `ATTR_OPEN_RE` still failed to match it, so the file
# scanned clean). Every inter-token gap below therefore uses `WS`, never
# a bare `\s`. Going the other way — `\s` matching a few characters Rust
# does not, e.g. U+00A0 — only makes the matcher MORE willing to see an
# attribute, which is the safe direction for a kill switch.
WS = "[\\s\u200e\u200f]"

# Whitespace is legal EVERYWHERE between the three tokens `#`, `!` and
# `[` — `# [allow(...)]` and `# ![allow(...)]` are both accepted by
# rustc, verified directly. This is the shape of the TOKENS rather than
# of any one spelling.
ATTR_OPEN_RE = re.compile(rf"#{WS}*!?{WS}*\[")
LINT_GROUP_RE = re.compile(rf"\b(allow|expect){WS}*\(")
# A RAW IDENTIFIER prefix is invisible to the identifier it names:
# `r#disallowed_methods` IS `disallowed_methods` to rustc, and
# `#[allow(clippy::r#disallowed_methods)]` suppresses the lint exactly
# like the plain spelling (rustc parses it, and a matcher without this
# sees neither the lint nor, in the `r#allow` form, the attribute
# kind). Blanked to TWO SPACES rather than deleted so the text
# keeps its length: every line number below is computed by counting
# newlines up to an offset in this same string.
RAW_IDENT_RE = re.compile(r"\br#(?=[A-Za-z_])")
# Whitespace-tolerant on both sides of `::` — collapses the "whitespace
# in the path" evasion, and (since comments are already blanked to
# spaces before this runs) the "comment inside the path" evasion too,
# for free, with the same pattern.
#
# GROUP NAMES COUNT AS THE LINT. `disallowed_methods` sits in clippy's
# `style` group, so `clippy::style` and `clippy::all` suppress it just
# as naming it does — measured directly on the pinned toolchain against
# a bare `std::fs::create_dir_all` call: with either group allowed, the
# ban produced ZERO errors, while `clippy::restriction` and `warnings`
# each still produced one (`warnings` covers warn-level lints, and this
# crate's Cargo.toml sets `disallowed_methods = "deny"`). `warnings` is
# matched anyway: it is one Cargo.toml line away from being the same
# hole, and matching it costs nothing.
#
# The set is deliberately the lint's own group CHAIN plus `warnings`,
# not every clippy group — a group that does not contain the lint
# cannot suppress it, and matching one would make this refuse
# suppressions of unrelated lints.
LINT_RE = re.compile(rf"\bclippy{WS}*::{WS}*(?:disallowed_methods|style|all)\b|\bwarnings\b")
# The EXACT spelling, and the only one that counts toward the licensed-site
# total. A GROUP name in an `expect(...)` is not a narrower licence written
# loosely — it is a wholesale suppression that happens to be spelled
# `expect`: `#![expect(clippy::all, reason = "…")]` at the top of a file
# silences every lint in the group for that file, and the expectation is
# FULFILLED by the very calls it hides, so clippy stays silent about the
# attribute too. Counting it as a licence would let one narrow
# `#[expect(clippy::disallowed_methods, …)]` be swapped for a file-scoped
# group `expect` with EXPECTED_LICENSED_SITES never moving; outside `src/`
# there is no count at all, so nothing would notice. Group `expect`s are
# therefore reported exactly like a bare `allow`.
LINT_EXACT_RE = re.compile(rf"\bclippy{WS}*::{WS}*disallowed_methods\b")
# A GROUP NAME ANYWHERE IN THE LIST DISQUALIFIES THE WHOLE `expect`, even
# when the exact lint is named beside it. `#![expect(clippy::disallowed_methods,
# clippy::all, reason = "…")]` written over one narrow site reads to
# `LINT_EXACT_RE` as a licence — the count does not move — while every
# bare filesystem call in the file compiles clean, because `clippy::all`
# is what actually governs them. So the two conditions are AND-ed: an
# `expect` counts only if it names the lint EXACTLY and names no group at
# all. This does not touch the legitimate multi-lint `#[expect]`s in this
# crate (control D2 pins one): they name other LINTS, never a group.
LINT_GROUP_NAME_RE = re.compile(rf"\bclippy{WS}*::{WS}*(?:style|all)\b|\bwarnings\b")

# WHERE A WHOLESALE LICENCE IS LEGITIMATE. An INNER attribute
# (`#![expect(...)]`) licenses everything from where it sits to the end
# of its module — the whole FILE when it sits at file scope — which is a
# different object from the per-site `#[expect]`s the licensed-site
# count enumerates. Under `tests/` and `fuzz/` that is the sanctioned
# form and the only one available: the integration crates license their
# fixtures once at the top, and the fuzz target's banned call lives
# inside `libfuzzer_sys::fuzz_target!`'s expansion, where rustc discards
# an attribute on the invocation, so no narrower spelling exists.
#
# Under `src/` it is neither sanctioned nor necessary. Every production
# licence there is a reviewed fn/site-level `#[expect]`, and one inner
# attribute would silence the ban for a whole module of production code
# while moving the count by ONE — the count says how many licences
# exist, never how much each one covers, so a narrow site swapped for a
# module-wide licence is invisible to it. Reported like a bare `allow`
# instead of counted.
LICENCE_SCOPE_DIRS = ("tests", "fuzz")


def wholesale_licence_allowed(path: str, crate_dir: str = "") -> bool:
    """True where a file/module-scoped `#![expect]` is the sanctioned
    form: the crate-level `tests/` or `fuzz/` tree, and nothing else.

    THE FIRST COMPONENT after the crate directory decides it, not "a
    `tests` component somewhere". `tests/` and `fuzz/` are the two roots
    cargo gives a whole separate compilation to, which is what makes a
    file-scoped licence the only form available there. A `tests` or
    `fuzz` component ANYWHERE else is an ordinary module of an ordinary
    target — `src/tests/mod.rs`, `examples/tests/main.rs`,
    `benches/fuzz/main.rs` — and a licence written at the top of one of
    those covers production-shaped code that the per-site count never
    describes.

    Compared as PATH COMPONENTS, never as a substring: a file named
    `fuzzer.rs` is not `fuzz/`. With no crate directory given the whole
    path is read relative to nothing, so only a path that BEGINS
    `tests/` or `fuzz/` qualifies — the fail-closed reading.

    AND THE FILE MUST NOT BE INSIDE THE LIBRARY'S SOURCE TREE, which
    takes two conditions because the first-component rule alone depends
    on which root the caller scanned:

      - no `src` among the CRATE-RELATIVE components. Scanned from the
        crate root, `src/tests/mod.rs` fails the first-component test
        anyway; this is what refuses the odd shapes below it.
      - the crate directory itself must not BE the source tree. The
        licensed-site count is invoked with the crate's `src` as its
        crate directory, and under that invocation
        `crates/granary-client/src/tests/mod.rs` normalises to
        `tests/mod.rs` and would read as the crate-level tests tree. It
        is not — it is an ordinary module of the library that happens
        to be named `tests`.

    CRATE-RELATIVE, and that word is load-bearing: testing the WHOLE
    path for a `src` component reads the directory the repository
    happens to be checked out in. A clone under `~/src/granary` would
    then have every legitimate crate-level `tests/*.rs` licence refused
    — a gate failing on a tree that is correct, because of where
    someone put it. The scan root is stripped first, so nothing above
    the crate can change the answer.

    The two conditions together hold under BOTH invocations, which is
    the property that matters: the answer must not depend on where the
    walk started, and must not depend on anything above it."""
    norm = path.replace("\\", "/")
    root = crate_dir.replace("\\", "/").rstrip("/")
    if root and norm.startswith(root + "/"):
        norm = norm[len(root) + 1:]
    parts = [c for c in norm.split("/") if c not in ("", ".")]
    root_parts = [c for c in root.split("/") if c not in ("", ".")]
    root_is_source_tree = bool(root_parts) and root_parts[-1] == "src"
    return (
        bool(parts)
        and parts[0] in LICENCE_SCOPE_DIRS
        and "src" not in parts
        and not root_is_source_tree
    )


# ---- A file-scoped licence is ALSO allowed when the scanned file
# itself carries a FILE-SCOPED inner `cfg` attribute whose predicate
# implies `test`. `wholesale_licence_allowed` above checks the path;
# this check asks whether THIS FILE'S OWN CONTENT proves that it cannot
# contribute code outside `cfg(test)`. Either condition can independently
# sanction the licence. The content check admits this module arrangement:
#
#   src/foo.rs:        #[cfg(test)] mod tests;        (no lint attribute)
#   src/foo/tests.rs:  #![cfg(test)]
#                      #![expect(clippy::disallowed_methods, reason = "…")]
#
# The child's ordinary `src/**` path does not satisfy the separate
# crate-level `tests/`/`fuzz/` path rule. Its own shield supplies the proof.
# Do not resolve the PARENT's declaration to establish that proof:
# no owner is walked, no module path is resolved, and this check reads
# no second file. The compiler enforces a file's own `#![cfg(test)]`,
# so the file cannot contribute code to a production build regardless
# of which module declaration names it.
#
# THE THREE CONDITIONS THAT KEEP THIS FILE-CONTENT CHECK NARROW:
#   1. FILE-SCOPED MEANS DEPTH 0 OVER ALL THREE DELIMITER KINDS. An inner
#      attribute inside an inline `mod something { … }` governs only that
#      module, never the file; one inside a paren- or bracket-delimited
#      token group (`nop!(#![cfg(test)]);`, `nop![#![cfg(test)]]`) is not
#      the file's own attribute at all — a macro's argument list is not a
#      module, rustc does not gate the file on it, and the file compiles
#      normally either way. Checked below against `delim_spans`, which
#      tracks `{}`, `()` AND `[]` in one combined pass (unlike
#      `block_spans`, the brace-only machinery the `--banned-rows` half
#      uses to find a wholesale licence's own REACH — that extent is
#      always a module's `{`…`}` body, so it stays brace-only on purpose;
#      only the file-scope TEST below needs the wider net). "At file
#      scope" means: not enclosed by any `{`…`}`, `(`…`)` or `[`…`]` pair
#      — excluding the attribute's own `#![`…`]`, which naturally is not
#      counted as enclosing itself (the check below is a strict `<`).
#   2. THE PREDICATE MUST IMPLY `test`. A bare `test`, or an `all(…)` naming
#      `test` as a direct conjunct. Anything containing `any(`, `not(` or a
#      `cfg_attr` wrapper is refused — matched as a plain substring search
#      over the WHOLE predicate text, not just its top level, which is
#      deliberately more conservative than the accept path (which only
#      looks at direct, top-level conjuncts): the reason to refuse a nested
#      `not(...)`/`any(...)` is to keep acceptance conservative: the bare
#      `#[cfg(any(test, feature = "x"))]` case is real production code
#      under `--features x`, and there is nothing to gain by proving a
#      nested case safe when the narrow, sanctioned shape costs nothing to
#      write instead.
#   3. NOTHING ELSE IS ADMITTED. `wholesale_licence_allowed` keeps its own
#      three conditions (path components, `src`-tree exclusion) entirely
#      unchanged; this is OR-ed alongside it, never in place of it, so
#      control D8's fixture (`src/tests/mod.rs`, a file-scoped `#![expect]`
#      with NO `#![cfg(test)]` of its own) stays refused exactly as before —
#      it has no `#![cfg(test)]` anywhere in it, so this function returns
#      `False` for it and the OR contributes nothing.
CFG_HEAD_RE = re.compile(rf"^{WS}*cfg{WS}*\(")
ALL_HEAD_RE = re.compile(rf"^{WS}*all{WS}*\(")
# Anchored nowhere: this is deliberately a SUBSTRING search over the whole
# predicate, at any depth, per condition 2 above. `\bcfg_attr\b` (not
# `cfg_attr\s*\(`) also refuses a bare mention with no call syntax at all —
# there is no legitimate reason for that identifier to appear in a `cfg`
# predicate, and refusing the word is simpler than proving every shape it
# could take is safe.
CFG_TEST_DISQUALIFY_RE = re.compile(rf"\bany{WS}*\(|\bnot{WS}*\(|\bcfg_attr\b")


def _split_top_commas_parens(text: str):
    """`text` split on commas that are not inside a `(...)` group — the
    paren-nested twin of `_split_top_commas` below, needed because a `cfg`
    predicate groups its conjuncts with parentheses (`all(a, b)`), not the
    braces a `use` tree nests with."""
    parts, depth, start = [], 0, 0
    for i, c in enumerate(text):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1 if depth else 0
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


def _cfg_predicate_implies_test(predicate: str) -> bool:
    """True where `predicate` — the already comment/string-blanked text
    inside a `cfg(...)`'s own parentheses — IMPLIES `test`: a bare `test`,
    or an `all(...)` naming `test` as a direct, top-level conjunct. See the
    block comment above `CFG_HEAD_RE` for why the disqualifying search is a
    substring match over the whole text rather than a top-level-only one."""
    if CFG_TEST_DISQUALIFY_RE.search(predicate):
        return False
    if predicate.strip() == "test":
        return True
    m = ALL_HEAD_RE.match(predicate)
    if not m:
        return False
    close = find_matching(predicate, m.end() - 1, "(", ")")
    if close is None:
        return False
    # A trailing token after `all(...)`'s own close paren means the
    # predicate was not `all(...)` alone — refused rather than guessed at.
    if predicate[close + 1:].strip():
        return False
    inner = predicate[m.end():close]
    return any(part.strip() == "test" for part in _split_top_commas_parens(inner))


def file_scoped_cfg_test(clean: str, delims) -> bool:
    """True where `clean` (the same comment/string-blanked text `scan_file`
    already builds) carries a FILE-SCOPED inner `#![cfg(...)]` — at depth 0
    over all three delimiter kinds, per `delims` (`delim_spans(clean)`) —
    whose predicate implies `test`. `delims` is threaded in rather than
    recomputed so a caller cannot pass the brace-only `block_spans` here
    by mistake and reintroduce the paren/bracket fail-open this function
    exists to close.

    Deliberately does not require the attribute to be the FIRST thing in
    the file, or to be the only inner attribute: `cargo fmt` does not
    enforce an order among a file's own inner attributes. This check
    requires file scope, with no ordering among those attributes,
    and checks that scope directly rather than by position."""
    for attr_m in ATTR_OPEN_RE.finditer(clean):
        if "!" not in attr_m.group(0):
            continue  # an outer `#[...]` attribute is never file-scoped
        open_bracket = attr_m.end() - 1
        close_bracket = find_matching(clean, open_bracket, "[", "]")
        if close_bracket is None:
            continue
        if any(lo < open_bracket < hi for lo, hi in delims):
            continue  # nested inside a `{}`/`()`/`[]` group — condition 1.
            # The attribute's OWN bracket pair is (open_bracket,
            # close_bracket) with lo == open_bracket exactly, which fails
            # the strict `lo <` test — it is never read as nesting the
            # attribute inside itself.
        body = clean[open_bracket + 1 : close_bracket]
        head_m = CFG_HEAD_RE.match(body)
        if not head_m:
            continue  # not a bare `cfg(...)` attribute — a `cfg_attr(...)`
            # wrapper never matches this anchor, since `cfg_attr(` fails
            # `cfg{WS}*\(` at the same starting position
        cfg_open = head_m.end() - 1
        cfg_close = find_matching(body, cfg_open, "(", ")")
        if cfg_close is None:
            continue
        if body[cfg_close + 1:].strip():
            continue  # trailing token after `cfg(...)` — not a bare attribute
        if _cfg_predicate_implies_test(body[cfg_open + 1 : cfg_close]):
            return True
    return False


# ---- the SOURCE-INPUT CLOSURE patterns (`--source-closure` mode) ----
# What this scanner reads is "every `.rs` file `find` handed it, as
# surface syntax". Three constructions break that premise from inside a
# file it DID read, and each was measured on the pinned toolchain to
# compile while scanning clean:
#   - `macro_rules!` — an arm that ASSEMBLES the lint path from tokens
#     (`concat_idents`-style, or `$c::$l` with the halves passed
#     separately) produces a real `#[expect(...)]` after expansion, and
#     nothing this scanner can match ever carries the text.
#   - `#[path = "../../outside.rs"] mod evasion;` — rustc compiles a
#     file the walk never visits, and an inner `#![expect(clippy::all,
#     reason = "…")]` at the top of THAT file licenses everything in it.
#   - the `include` MACRO, under any name — `include!("…")` splices the
#     source inline instead of moduling it, and an aliased import or a
#     qualified path reaches the same macro carrying a different token
#     (see the three `INCLUDE_*` patterns below).
#     `include_str!`/`include_bytes!` are DATA, not source, and are not
#     matched at all: `_` is a word character, so `\binclude\b` never
#     matches inside them.
# SYMLINKED SOURCE is the fourth, and it is not a text pattern at all —
# `find -type f` skips a symlink while rustc follows it — so the gate
# matches it with `find -type l` instead, refusing a link whose name
# ends `.rs` and a linked DIRECTORY under a source root.
MACRO_RULES_RE = re.compile(rf"\bmacro_rules{WS}*!")
INCLUDE_RE = re.compile(rf"\binclude{WS}*!")
# `include!` is one spelling of the macro, not the macro. An ALIASED
# import reaches it carrying no `include` token at the call site at all:
#
#   use std::include as splice;
#   splice!("../../outside.rs");
#
# and a qualified invocation (`std::include!("…")`) is a second. So the
# IDENTIFIER is refused wherever it can name that macro — as a path
# segment, inside a `use`, or renamed with `as` — and not only where it
# is immediately followed by `!`. `include_str!`/`include_bytes!` are
# DATA and still are not matched: `_` is a word character, so `\binclude\b`
# never matches inside them.
INCLUDE_PATH_RE = re.compile(rf"::{WS}*include\b")
INCLUDE_IMPORT_RE = re.compile(rf"\buse\b[^;]{{0,500}}\binclude\b")
INCLUDE_ALIAS_RE = re.compile(rf"\binclude{WS}+as\b")
# Searched inside an ATTRIBUTE's brackets only, so a `let path = …`
# binding (which this crate writes constantly) cannot match, and
# `#[cfg_attr(unix, path = "…")]` — an attribute whose first token is
# not `path` — still can.
PATH_ATTR_RE = re.compile(rf"\bpath{WS}*=")

# ---- what a WHOLE-MODULE licence also licenses (`--banned-rows`) ----
# A `#[expect(clippy::disallowed_methods, …)]` on a `mod tests` item, or
# a `#![expect(…)]` at the top of a file, licenses THE LINT — not the
# filesystem half of it. `disallowed_methods` is ONE lint carrying every
# row of `disallowed-methods`, so a licence written for "fixtures use
# bare fs calls on their own scratch directories" equally silences the
# ambient-input determinism seams (`Instant::now`, `SystemTime::now`,
# `tokio::time::sleep`, the `rand` entry points) and the runtime-
# concurrency bans (`tokio::spawn` and its siblings) for the whole
# module. Documentation calling those methods "clippy-banned here"
# cannot preserve the ban: the module's own licence suppresses those
# rows as well, so the scanner must check their reach separately.
#
# So under such a licence the SCANNER holds the line: a call matching a
# NON-FS row is reported unless the site carries its own narrow
# `#[expect]`. Outside a wholesale licence nothing is reported — clippy
# is the check there, and reporting it here would be a second opinion on
# a diagnostic that already fires.
#
# THREE ROUTES ARE CLOSED, AND ONE IS NOT. Stated exactly, because "the
# scanner holds the line" read as a whole claim would be false:
#   - a call written as a PATH (`tokio::spawn(...)`,
#     `SystemTime::now()`) is matched, in the full and last-two-segment
#     spellings;
#   - an IMPORT of a banned path is matched, which is what closes the
#     ALIAS route by construction. `use std::process::id as p;` makes
#     `p()` unmatchable, and `use std::time::SystemTime::now;` makes a
#     bare `now()` unmatchable — but neither alias can come into being
#     without a `use` that spells the path out, so refusing the IMPORT
#     leaves the one-segment call with no banned path to have come from.
#     This is import-level, not name resolution, and that is the whole
#     reason it is a closure rather than another spelling patched.
#   - a RENAME OF THE PARENT MODULE is matched, which is the one shape
#     the other two miss. `use std::process as pr;` leaves `pr::id()`,
#     whose last two segments match no row, on an import line that names
#     no row — so neither the call pattern nor the import pattern sees
#     it. Renaming anything HIGHER changes nothing (`use std as s;`
#     still leaves `s::process::id()`, and `process::id` matches), and
#     renaming the whole path is the alias case above. So the parent is
#     the only rename that has to be refused, and it is, in every
#     spelling — `as`, `::{self as …}`, `::{parent as …}` and the glob
#     `::*`, at ANY nesting depth. Depth is why `flatten_use` exists: a
#     regex can allow one brace group before the segment it wants and
#     Rust puts no limit on the nesting, so the tree is EXPANDED into
#     full paths and the comparison is between two lists of segments.
#   - a RECEIVER spelling is NOT matched and cannot be. `set.spawn(...)`
#     for `tokio::task::JoinSet::spawn`, `handle.spawn(...)` for
#     `tokio::runtime::Handle::spawn`, `local.spawn_local(...)` — the
#     call site names a variable and a method, never the row's path, and
#     deciding what the receiver's type is means resolving names, which
#     no text scanner does. Under a whole-module licence clippy is
#     silent about those too, so nothing refuses them. There is no
#     control for this because there is nothing to control: it is the
#     reason a whole-module licence is the wrong shape, and the reason
#     every licence should be a narrow per-site one, where clippy itself
#     still decides every row the licence does not name.
#
# THREE ROUTES CLOSED, ONE OPEN, and that is the whole list. Every
# pattern above is built from the CONFIG's own rows at run time, so the
# closed set cannot drift from the ban.
#
# THE ROW SET IS THE CONFIG'S. It is read from the REPO-ROOT
# `clippy.toml` at run time, never restated here. That file's
# `disallowed-methods` rows ARE the crate file's non-fs half: check 1 of
# check-fsguard-sites.sh requires every root row to be present in
# `crates/granary-client/clippy.toml`, and check 2 pins the client's
# list to root's rows PLUS exactly the audited fs rows, by multiset and
# in both directions. Reading root's rows is also the fail-closed side
# of that pair — an intersection would SHRINK if a root row went
# missing, which is the moment the set most needs to be complete.


def banned_call_re(paths):
    """One regex matching a call to any of `paths`.

    Two spellings per row, because Rust code names a function by its
    PATH SUFFIX far more often than in full: `std::time::SystemTime::now`
    is written `SystemTime::now()` after a `use std::time::SystemTime`,
    and `tokio::task::spawn_blocking` as `task::spawn_blocking(…)`. So
    the full path and its LAST TWO segments are both matched, and never
    the last segment alone — a bare `spawn(`/`now(`/`id(` names half the
    method calls in any program and would report code that has nothing
    to do with the ban.

    `::` is whitespace-tolerant for the same reason as everywhere else
    here (comments are already blanked to spaces), and the match must be
    followed by `(` — the row bans a CALL, and a path in a `use` line or
    a doc reference is not one."""
    spellings = set()
    for row in paths:
        segments = [seg for seg in row.split("::") if seg]
        if not segments:
            continue
        spellings.add("::".join(segments))
        if len(segments) >= 2:
            spellings.add("::".join(segments[-2:]))
    if not spellings:
        return None
    # Longest first, so a full path is reported as itself rather than as
    # its own two-segment tail.
    alts = "|".join(
        # `re.escape` leaves `:` alone (it has escaped only genuinely
        # special characters since 3.7), so the separator is still the
        # literal `::` here and this substitution is the one that makes
        # the pattern whitespace-tolerant.
        re.escape(sp).replace("::", rf"{WS}*::{WS}*")
        for sp in sorted(spellings, key=len, reverse=True)
    )
    # A TURBOFISH may sit between the path and the paren:
    # `tokio::spawn::<_>(fut)` is the same call as `tokio::spawn(fut)`
    # and rustc lints it identically. One level of nesting is allowed
    # inside it (`<Vec<u8>>`), which covers every generic argument a
    # call site writes in practice; a deeper one would fall back to
    # being unmatched, and that is stated in the header rather than
    # patched with a third level.
    turbofish = rf"(?:{WS}*::{WS}*<(?:[^<>]|<[^<>]*>)*>)?"
    return re.compile(rf"\b({alts}){turbofish}{WS}*\(")


def banned_use_re(paths):
    """One regex matching an IMPORT of any of `paths`.

    THE IMPORT IS WHERE THE PATH IS SPELLED. A call oracle that matches
    `std::process::id(` sees nothing after
    `use std::process::id as ambient_pid;` — the call site is
    `ambient_pid()`, a name this scanner cannot resolve, and the same is
    true of `use std::time::SystemTime::now;` followed by a bare
    `now()`. Neither alias can come into being without a `use` that
    writes the banned path out in full, so the `use` is refused and the
    aliases never exist. That is a CLOSURE for the alias route, not a
    patch on one spelling of it.

    The brace form is matched too: `use std::process::{exit, id};`
    never contains the literal `std::process::id`, so the prefix is
    allowed to be followed by an opening brace and any earlier items in
    the group before the final segment."""
    alts = set()
    for row in paths:
        segments = [seg for seg in row.split("::") if seg]
        if not segments:
            continue
        forms = [segments]
        if len(segments) >= 2:
            forms.append(segments[-2:])
        for form in forms:
            if len(form) < 2:
                continue
            prefix = "::".join(form[:-1])
            last = form[-1]
            alts.add((prefix, last))
    if not alts:
        return None
    pattern = "|".join(
        re.escape(prefix).replace("::", rf"{WS}*::{WS}*")
        + rf"{WS}*::{WS}*(?:\{{[^}}]*)?\b"
        + re.escape(last)
        + r"\b"
        for prefix, last in sorted(alts, key=lambda a: len(a[0]) + len(a[1]), reverse=True)
    )
    return re.compile(pattern)


def banned_prefix_rename_re(paths):
    """One regex matching a `use` that RENAMES or GLOB-IMPORTS the
    PARENT of a banned path.

    THE ONE ROUTE THE OTHER TWO PATTERNS LEAVE OPEN. After `use P as A;`
    a call reads `A::<rest>`, and the call oracle matches a row's last
    TWO segments — so renaming `std` (`use std as s; s::process::id()`)
    changes nothing, because `process::id` still stands. It is renaming
    the row's path MINUS ITS LAST SEGMENT that breaks it:
    `use std::process as pr;` leaves `pr::id()`, whose last two segments
    are `pr::id` and match no row, while `banned_use_re` finds no `id`
    on the import line either. Both halves miss it, and the module-level
    rename is the only shape where that is true.

    Three spellings of the same thing, all anchored on the parent's FULL
    path so an unrelated identifier that happens to share a segment name
    cannot match:
      `use std::process as pr;`          the plain rename
      `use std::process::{self as pr};`  the self-rename
      `use std::{process as pr};`        the rename inside a brace group
      `use std::process::*;`             the glob
      `use std::process::{self, *};`     the glob inside a brace group

    The glob is the same defect reached without an alias: it brings the
    row's own name into scope unqualified, so the call reads `id()` —
    one segment, matching no row, on an import line naming none.
    """
    alts = []
    for row in paths:
        segments = [seg for seg in row.split("::") if seg]
        if len(segments) < 2:
            continue
        parent = segments[:-1]
        full = re.escape("::".join(parent)).replace("::", rf"{WS}*::{WS}*")
        # `use <parent> as X;`
        alts.append(rf"{full}{WS}*\bas\b")
        # `use <parent>::{self as X};`
        alts.append(rf"{full}{WS}*::{WS}*\{{[^}}]*\bself\b[^}}]*\bas\b")
        # `use <parent>::*;` and `use <parent>::{…, *};` — a GLOB brings
        # the row's own name into scope unqualified, so the call reads
        # `id()`: one segment, matching no row, on an import line that
        # names none either. Same family as the rename, and the same
        # answer — refuse the import.
        alts.append(rf"{full}{WS}*::{WS}*\*")
        alts.append(rf"{full}{WS}*::{WS}*\{{[^}}]*\*[^}}]*\}}")
        if len(parent) >= 2:
            grand = re.escape("::".join(parent[:-1])).replace("::", rf"{WS}*::{WS}*")
            last = re.escape(parent[-1])
            # `use <grandparent>::{<parent> as X};`
            alts.append(rf"{grand}{WS}*::{WS}*\{{[^}}]*\b{last}{WS}+as\b")
    if not alts:
        return None
    return re.compile("|".join(alts))


def _split_top_commas(text: str):
    """`text` split on commas that are not inside a brace group."""
    parts, depth, start = [], 0, 0
    for i, c in enumerate(text):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1 if depth else 0
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


def flatten_use(stmt: str):
    """Every path a `use` statement brings into scope, as
    (segments, alias, is_glob).

    NESTING IS WHY THIS EXISTS. A regex can allow ONE brace group before
    the segment it is looking for; it cannot allow an arbitrary number,
    and `use std::{process::{self as pr}};` is two deep. Rust puts no
    limit on the nesting, so matching the TEXT is a losing game and
    expanding the tree is not: `prefix::{a, b::{c, d as e}, *}` becomes
    `prefix::a`, `prefix::b::c`, `prefix::b::d` (aliased) and `prefix`
    (glob), after which the comparison is between two lists of segments
    and depth has stopped mattering.

    `self` resolves to the prefix itself (`std::process::{self as pr}`
    aliases `std::process`), and `*` marks the prefix as glob-imported.
    Anything this cannot split is left to the regex patterns beside it,
    which is why both run: a `use` too odd to parse must not read as a
    `use` that imports nothing."""
    out = []

    def expand(tree: str, prefix):
        for raw in _split_top_commas(tree):
            part = raw.strip()
            if not part:
                continue
            depth, brace = 0, None
            for i, c in enumerate(part):
                if c == "{":
                    if depth == 0:
                        brace = i
                        break
                    depth += 1
                elif c == "}":
                    depth -= 1 if depth else 0
            if brace is not None:
                close = find_matching(part, brace, "{", "}")
                if close is None:
                    continue
                head = part[:brace].strip()
                segs = [x.strip() for x in head.split("::") if x.strip()]
                expand(part[brace + 1:close], prefix + segs)
                continue
            alias = None
            m = re.search(rf"{WS}+as{WS}+", part)
            if m:
                alias = part[m.end():].strip()
                part = part[:m.start()]
            segs = [x.strip() for x in part.split("::") if x.strip()]
            is_glob = bool(segs) and segs[-1] == "*"
            if is_glob:
                segs = segs[:-1]
            if segs and segs[-1] == "self":
                segs = segs[:-1]
            out.append((prefix + segs, alias, is_glob))

    body = stmt
    m = re.match(rf"{WS}*use\b", body)
    if m:
        body = body[m.end():]
    expand(body, [])
    return out


def _suffix_match(got, want):
    """A written path names `want` when it IS `want` or ends in its last
    two segments — the same two spellings `banned_call_re` matches, for
    the same reason: Rust code names a path by its tail far more often
    than in full."""
    if got == want:
        return True
    return len(got) >= 2 and len(want) >= 2 and got[-2:] == want[-2:]


def use_tree_finding(stmt: str, rows):
    """`"named"`, `"parent"` or None for one `use` statement.

    `named` is an import of the row itself; `parent` is an import that
    RENAMES or GLOBS the row's parent module, which is what leaves a
    call this scanner cannot match."""
    entries = flatten_use(stmt)
    parents = False
    for segments, alias, is_glob in entries:
        for row in rows:
            want = [seg for seg in row.split("::") if seg]
            if _suffix_match(segments, want):
                return "named"
            if (alias is not None or is_glob) and len(want) >= 2:
                if _suffix_match(segments, want[:-1]):
                    parents = True
    return "parent" if parents else None


USE_RE = re.compile(r"\buse\b")


def use_statements(text: str):
    """(start, statement-text) for every `use` in `text`, the statement
    ending at its own `;`. Bounded at 2000 characters so a file with an
    unterminated `use` cannot make this quadratic."""
    out = []
    for m in USE_RE.finditer(text):
        end = text.find(";", m.start(), m.start() + 2000)
        if end == -1:
            continue
        out.append((m.start(), text[m.start():end]))
    return out


def block_spans(text: str):
    """Every `{`…`}` pair in `text`, as (open, close) offsets. One pass
    with a stack; unbalanced braces (a file this scanner mis-lexed)
    simply contribute no span rather than raising."""
    spans = []
    stack = []
    for i, c in enumerate(text):
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            spans.append((stack.pop(), i))
    return spans


# The FILE-SCOPED test-only shield check needs "is this position
# nested inside anything" over all three delimiter kinds Rust
# groups tokens with, not just `{`…`}`: `nop!(#![cfg(test)]);` and
# `nop![#![cfg(test)]]` put the inner attribute inside a paren- or
# bracket-delimited macro call, and neither is a `{`…`}` pair, so
# `block_spans` alone reads the attribute as sitting at file scope. It
# is not — the macro's token tree is not the file, rustc does not gate
# the file on an attribute buried inside a macro invocation's arguments,
# and the file compiles normally either way.
#
# One combined stack across `{`, `(` and `[` rather than three separate
# passes: Rust's delimiters nest properly in real (already
# comment/string-blanked) source, so a single stack that pushes any
# opener and pops on ITS OWN matching closer tracks cross-kind nesting
# correctly (`( [ ] )` closes cleanly; a stray/mismatched closer with no
# matching opener on top is left alone rather than raising, the same
# fail-quiet contract `block_spans` keeps for unbalanced braces).
_DELIM_OPEN_TO_CLOSE = {"{": "}", "(": ")", "[": "]"}
_DELIM_CLOSE_TO_OPEN = {v: k for k, v in _DELIM_OPEN_TO_CLOSE.items()}


def delim_spans(text: str):
    """Every matched pair, across all three delimiter kinds `{}`, `()`
    and `[]`, in `text` — as (open, close) offsets, from one pass with a
    single stack so nesting ACROSS kinds is tracked, not just within
    one. See the block comment above for why `block_spans` (brace-only)
    is not enough for the file-scope check this feeds."""
    spans = []
    stack = []
    for i, c in enumerate(text):
        if c in _DELIM_OPEN_TO_CLOSE:
            stack.append((c, i))
        elif c in _DELIM_CLOSE_TO_OPEN:
            if stack and stack[-1][0] == _DELIM_CLOSE_TO_OPEN[c]:
                _, open_pos = stack.pop()
                spans.append((open_pos, i))
            # else: a closer with no matching opener on top — ignored,
            # not raised, mirroring block_spans's unbalanced-input
            # contract.
    return spans


def innermost_end(spans, pos: int, default: int) -> int:
    """Where the block enclosing `pos` ends, or `default` (end of file)
    when `pos` is at file scope. This is the extent of an INNER
    `#![expect]`: it licenses to the end of its enclosing module, which
    at file scope is the whole file."""
    best = None
    for open_pos, close_pos in spans:
        if open_pos < pos < close_pos and (best is None or close_pos < best):
            best = close_pos
    return default if best is None else best


ATTR_SKIP_RE = re.compile(rf"{WS}*")
# NO `^`. This is used with `.match(text, pos)`, which already anchors
# at `pos`; a leading `^` would additionally require `pos` to be the
# start of the string, so the pattern would never match a `mod` found
# anywhere but byte 0 — and every `mod tests` item would then be read as
# a narrow, per-site licence instead of a wholesale one.
MOD_HEAD_RE = re.compile(
    rf"{WS}*(?:pub{WS}*(?:\({WS}*[^)]*\){WS}*)?)?(?:unsafe{WS}+)?mod\b"
)


# The keywords that introduce an item whose BODY is a brace group. For
# these the first `{` at depth 0 is the body and its `}` ends the item.
# `const`, `static`, `type` and `use` are items too and are deliberately
# NOT here: they end at a `;`, and a brace group inside their value is
# an expression like any other.
# ORDER-FREE, and `const` is one of them. Rust accepts every ordering
# of these modifiers — `async unsafe fn` and `unsafe async fn` are the
# same item — and a fixed sequence silently drops the orderings it did
# not spell. Getting that wrong is not a cosmetic miss: an unmatched
# `fn` falls to STATEMENT mode, a fn body ends with `}` and no `;`, and
# the span then runs on to the NEXT `;` at depth 0 and swallows the
# items after it. Under a wholesale licence that is UNDER-reporting —
# a banned call in the following item reads as licensed.
#
# NOT INDEPENDENTLY KILLABLE, and recorded as such rather than left to
# look like a tested guard. `STATEMENT_RESUME_RE`'s net below ends the
# span at the same brace for every input either of them handles —
# measured by holding the input fixed and disabling this list: the span
# ends at the identical offset. So no control can fail on this list
# alone, and control D12 is what proves the NET. This list is kept
# because it decides the span from the item's own SHAPE rather than
# from what happens to follow it: if the resume set ever fails to
# recognise a follower, this is what still ends the body at its brace.
_ITEM_MODIFIER = (
    rf"(?:pub{WS}*(?:\({WS}*[^)]*\){WS}*)?"
    rf"|const{WS}+|async{WS}+|unsafe{WS}+|default{WS}+|auto{WS}+"
    rf"|extern{WS}+(?:\"[^\"]*\"{WS}+)?)"
)
# `extern "C" { … }` is a brace-bodied item whose keyword is `extern`
# itself, with no `fn`/`mod`/… after it — the one body form the tail
# alternation below would otherwise miss.
BODY_ITEM_RE = re.compile(
    rf"(?:{_ITEM_MODIFIER})*"
    rf"(?:(?:fn|mod|impl|struct|enum|trait|union|macro_rules){WS}*[!(<{{;\s]"
    rf"|extern{WS}+(?:\"[^\"]*\"{WS}*)?\{{)"
)

# What a statement's span may NOT run past. Statement mode ends at the
# first `;` at depth 0; this is the second terminator, for a brace group
# that closed at depth 0 and is followed by something that starts a NEW
# item or statement rather than continuing an expression.
#
# It is the safety net for an item form the keyword list above does not
# know. `let x = Wrapper { n: 1 }.tag(…);` must NOT end at its struct
# literal — `.` continues the expression — so the net fires only on a
# lookahead that cannot: an attribute, an item keyword, `let`, or the
# end of the file.
STATEMENT_RESUME_RE = re.compile(
    rf"{WS}*(?:#|\Z|(?:pub|let|fn|mod|impl|struct|enum|trait|union|const|static"
    rf"|type|use|macro_rules|unsafe|async|extern|auto|default)\b)"
)


def item_extent(text: str, after: int):
    """The source the item or statement following an OUTER attribute at
    `after` covers, as (start, end), plus whether it is a `mod` and
    whether that `mod` is an out-of-line declaration.

    TWO MODES, because a brace group means different things in each.

    An ITEM WITH A BODY (`fn`, `mod`, `impl`, `struct`, `enum`, `trait`,
    `union`, `macro_rules!`) ends at the close of the first `{` opened
    at depth 0 — or at a `;` if one comes first, which is `mod foo;`,
    `struct X;` and a trait method declaration.

    ANYTHING ELSE is a STATEMENT — `#[expect(…)] let dir = …;`, the
    shape every per-site pid licence uses, and `const`/`static`/`type`/
    `use` — and ends at the first `;` at depth 0, with `{` counted as
    ordinary depth. Treating a statement's first brace group as its body
    ends the licence early: `let x = Wrapper { n: 1 }.tag(std::process::id());`
    would have its span stop at `Wrapper { n: 1 }`, leaving a correctly
    licensed call outside its own licence and reported as unlicensed —
    a gate refusing a tree that is right.

    THE ITEM LIST IS A KEYWORD LIST, and `BODY_ITEM_RE` says which
    keywords and which modifiers — order-free, `const` included, plus
    the bare `extern "C" { … }` block. A form it does not know falls to
    statement mode, and statement mode has a SECOND terminator for
    exactly that case: a brace group that opened and closed at depth 0
    and is followed by the start of a new item or statement ends the
    span there. So an unlisted braced item covers its own body and stops,
    rather than running on to the next `;` and covering the items after
    it — which was the real cost of a missing keyword, and it
    under-reports rather than over-reports.

    Stacked attributes in between are absorbed for free in both modes:
    their own `[`…`]` opens and closes at depth 0 without ever reaching
    a `;` or a brace."""
    n = len(text)
    # The head — past any stacked attributes — decides the mode and
    # answers the `mod` question, so it is read first.
    head = after
    while True:
        head_m = ATTR_SKIP_RE.match(text, head)
        head = head_m.end() if head_m else head
        attr_m = ATTR_OPEN_RE.match(text, head)
        if not attr_m:
            break
        close = find_matching(text, attr_m.end() - 1, "[", "]")
        if close is None:
            break
        head = close + 1
    is_mod = MOD_HEAD_RE.match(text, head) is not None
    body_item = BODY_ITEM_RE.match(text, head) is not None

    depth = 0
    depth_zero_brace = False
    i = after
    end = n
    while i < n:
        c = text[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1 if depth else 0
        elif c == "{":
            if depth == 0 and body_item:
                close = find_matching(text, i, "{", "}")
                end = n if close is None else close
                break
            if depth == 0:
                depth_zero_brace = True
            depth += 1
        elif c == "}":
            depth -= 1 if depth else 0
            # THE SAFETY NET. A brace group that opened and closed at
            # depth 0, with no `;` since, and followed by the start of a
            # new item or statement: whatever it was, it ended here.
            # Without this an item form the keyword list does not know
            # runs on to the next `;` and covers the items after it.
            if depth == 0 and depth_zero_brace and STATEMENT_RESUME_RE.match(text, i + 1):
                end = i
                break
        elif c == ";" and depth == 0:
            end = i
            break
        i += 1
    # `mod foo;` versus `mod foo { … }`. The walk above stops at a `;`
    # at depth 0 for the DECLARATION and at the block's own `}` for the
    # inline module, so the terminator is what tells them apart.
    is_mod_decl = is_mod and end < n and text[end] == ";"
    return after, end, is_mod, is_mod_decl


def scan_file(path: str, banned_re=None, banned_use_pattern=None, crate_dir="",
              banned_rename_pattern=None, banned_rows=()):
    """Returns (count, hits, reach, error). error is None on success, or
    a one-line diagnostic string (never a raw traceback) if the file
    could not be read as UTF-8 or otherwise processed — the caller must
    treat that as a hard failure, not a silent zero.

    `reach` is the `--banned-rows` half: calls to a NON-FS row of the
    lint sitting under a whole-module licence with no narrow `#[expect]`
    of their own. Empty when no row set was given.

    `licences` is how many WHOLESALE licences were found. It is the
    positive observable for that half: a caller that never sees a number
    above zero is looking at a scan where the machinery did not run, and
    "no findings" then means nothing."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except UnicodeDecodeError as e:
        return 0, [], [], 0, f"{path}: not valid UTF-8 ({e}) — refused, not skipped"
    except OSError as e:
        return 0, [], [], 0, f"{path}: could not read ({e})"

    # The shebang discard happens BEFORE the lexer, exactly as rustc
    # does it — a quote or comment opener inside a shebang is not Rust
    # source and must not steer the lexer. Raw-identifier prefixes are
    # normalized away AFTER the lexer, never before: an `r#` inside a
    # raw STRING (`r#"..."#`) is not an identifier, and by this point
    # every string is already blanked, so the only `r#` left is the real
    # thing.
    clean = RAW_IDENT_RE.sub("  ", strip_comments_and_strings(blank_shebang(raw)))
    raw_lines = raw.splitlines()
    count = 0
    hits = []
    # Every `#[...]`/`#![...]` attribute, WHOLE — cfg_attr(...) and any
    # other wrapper included — searched RECURSIVELY for every
    # allow(...)/expect(...) group anywhere inside it, not just one
    # sitting immediately after the attribute's own opening paren. This
    # is what makes `#[cfg_attr(cond, allow(clippy::disallowed_methods))]`
    # (already a real idiom in this crate, for `dead_code`) visible to
    # both the count and the kill switch.
    attr_ranges = []
    # The two extents the `--banned-rows` half needs: where a WHOLESALE
    # licence reaches, and where a NARROW one does. Both are collected
    # in the same pass that already finds every attribute, so the two
    # readings cannot disagree about which attributes exist.
    wholesale_spans = []
    narrow_spans = []
    # `blocks` (brace-only) is what `innermost_end` below needs: a
    # wholesale licence's REACH is always the extent of an enclosing
    # MODULE, which is a `{`…`}` body, never a paren or bracket group.
    # `delims` (all three kinds) is the separate, WIDER reading needed
    # to establish the file's own test-only shield — does
    # a `#![cfg(test)]` sit at FILE SCOPE — because a paren/bracket
    # macro argument list is not the file's own scope either, even
    # though it is not a module `innermost_end` would ever be asked
    # about. Both are the one PER-FILE property each is, not tied to any
    # one attribute's own position, so both are read once before the
    # loop below rather than recomputed per attribute.
    blocks = block_spans(clean)
    delims = delim_spans(clean)
    file_is_test_gated = file_scoped_cfg_test(clean, delims)
    for attr_m in ATTR_OPEN_RE.finditer(clean):
        open_bracket = attr_m.end() - 1
        close_bracket = find_matching(clean, open_bracket, "[", "]")
        if close_bracket is None:
            continue
        attr_ranges.append((open_bracket, close_bracket))
        body_start = open_bracket + 1
        body = clean[body_start:close_bracket]
        for group_m in LINT_GROUP_RE.finditer(body):
            kind = group_m.group(1)
            open_paren = body_start + group_m.end() - 1
            close_paren = find_matching(clean, open_paren, "(", ")")
            if close_paren is None:
                continue
            inner = clean[open_paren + 1 : close_paren]
            if not LINT_RE.search(inner):
                continue
            names_group = LINT_GROUP_NAME_RE.search(inner) is not None
            # A LICENCE BY PROXY. `#[expect(clippy::disallowed_methods,
            # …)] mod foo;` attaches to the DECLARATION and licenses the
            # whole of `foo.rs` — a file this scanner reads on its own,
            # where it finds no attribute at all. The count moves by
            # one; the coverage is a file. Refused outright: the licence
            # has to live in the file it covers, where the scan that
            # reads that file can see it.
            _, _, _, decl_is_mod_decl = (
                item_extent(clean, close_bracket + 1)
                if "!" not in attr_m.group(0)
                else (0, 0, False, False)
            )
            # `#!` rather than `#`: an INNER attribute licenses its whole
            # enclosing module, not the item after it. The `!` is read
            # from the attribute's own opening tokens, so `# ! [ …` (all
            # legal spacing) is the same attribute.
            is_inner = "!" in attr_m.group(0)
            # OR-ed, never in place of, `wholesale_licence_allowed`: the
            # file's own test-implying `cfg` attribute at file scope is a
            # SECOND, independent way to sanction a wholesale licence.
            # The path-based check still refuses `src/tests/mod.rs` when
            # that file has no test-only shield of its own.
            wholesale = is_inner and not (
                wholesale_licence_allowed(path, crate_dir) or file_is_test_gated
            )
            if decl_is_mod_decl:
                line_no = clean.count("\n", 0, open_paren) + 1
                orig_line = (
                    raw_lines[line_no - 1].strip() if 0 <= line_no - 1 < len(raw_lines) else ""
                )
                hits.append(
                    f"{path}:{line_no}: {orig_line}"
                    f"  <- an {kind} for this lint on an OUT-OF-LINE `mod name;` declaration. It "
                    "licenses the whole of that module's own file, which is scanned separately "
                    "and carries no attribute at all — the licence has to live in the file it "
                    "covers"
                )
                continue
            if kind == "expect" and LINT_EXACT_RE.search(inner) and not names_group:
                if banned_re is not None:
                    # An INNER attribute licenses to the end of its
                    # enclosing module (the whole file at file scope);
                    # an OUTER one licenses the item that follows, and
                    # that item is WHOLESALE only when it is a `mod`.
                    # Everything else — a fn, an impl, a `let` — is the
                    # narrow, per-site form, and is what excuses a call
                    # inside a wholesale region.
                    if is_inner:
                        wholesale_spans.append(
                            (close_bracket + 1,
                             innermost_end(blocks, open_bracket, len(clean)))
                        )
                    else:
                        # No `is_mod_decl` test here: an outer attribute
                        # on a `mod name;` was reported and skipped
                        # above, so what reaches this line is an inline
                        # module (WHOLESALE — its body is right here) or
                        # any other item (NARROW — a fn, an impl, a
                        # `let`).
                        start, end, is_mod, _ = item_extent(clean, close_bracket + 1)
                        (wholesale_spans if is_mod else narrow_spans).append((start, end))
                if not wholesale:
                    count += 1
                    continue
            line_no = clean.count("\n", 0, open_paren) + 1
            orig_line = (
                raw_lines[line_no - 1].strip() if 0 <= line_no - 1 < len(raw_lines) else ""
            )
            if kind == "expect" and wholesale:
                hits.append(
                    f"{path}:{line_no}: {orig_line}"
                    "  <- a file/module-scoped #![expect] outside tests/ and fuzz/ — it licenses "
                    "every call in its module while moving the licensed-site count by one"
                )
            elif kind == "expect":
                hits.append(
                    f"{path}:{line_no}: {orig_line}"
                    "  <- a group-wide expect is a wholesale suppression, not a licence"
                )
            else:
                hits.append(f"{path}:{line_no}: {orig_line}")

    # THE MACRO-ARGUMENT ROUTE. `licensed!(expect(clippy::all, reason =
    # "…"))` carries the same tokens, LITERALLY, at the call site — and
    # a `macro_rules!` arm that splices them into `#[$m]` produces a real
    # attribute the compiler honours. No `#[` precedes them, so the loop
    # above never looks inside, and the file scans `COUNT 0` with no
    # `ALLOW` line while a group-wide licence is in force.
    #
    # Every `allow(...)`/`expect(...)` group in the file is therefore
    # matched, and any that is NOT inside an attribute's brackets is
    # reported. A method call cannot collide: `.expect("…")`'s argument
    # is a string, blanked to spaces before this runs, so it fails
    # `LINT_RE` — only an argument literally naming the lint or one of
    # its groups is reported, and that is not a message anyone writes by
    # accident.
    for group_m in LINT_GROUP_RE.finditer(clean):
        open_paren = group_m.end() - 1
        if any(lo <= open_paren <= hi for lo, hi in attr_ranges):
            continue
        close_paren = find_matching(clean, open_paren, "(", ")")
        if close_paren is None:
            continue
        inner = clean[open_paren + 1 : close_paren]
        if not LINT_RE.search(inner):
            continue
        line_no = clean.count("\n", 0, open_paren) + 1
        orig_line = raw_lines[line_no - 1].strip() if 0 <= line_no - 1 < len(raw_lines) else ""
        hits.append(
            f"{path}:{line_no}: {orig_line}"
            "  <- attribute-shaped token stream outside an attribute — the macro route"
        )

    # ---- what the wholesale licence ALSO licenses --------------------
    reach = []
    if banned_re is not None and wholesale_spans:
        # THE IMPORT FIRST. An aliased import is what makes a call
        # unmatchable, so it is refused at the line that spells the path
        # — after which `ambient_pid()` and a bare `now()` have no
        # banned path to have come from.
        if banned_use_pattern is not None:
            for use_start, stmt in use_statements(clean):
                if not any(lo <= use_start < hi for lo, hi in wholesale_spans):
                    continue
                if any(lo <= use_start < hi for lo, hi in narrow_spans):
                    continue
                if any(lo <= use_start <= hi for lo, hi in attr_ranges):
                    continue
                # BOTH readings, OR-ed. The flattener is exact and
                # depth-independent; the regexes stay as the fallback
                # for a `use` it declines to split, so a statement too
                # odd to parse cannot read as one that imports nothing.
                tree = use_tree_finding(stmt, banned_rows) if banned_rows else None
                named = banned_use_pattern.search(stmt) or tree == "named"
                renamed = (
                    banned_rename_pattern.search(stmt)
                    if banned_rename_pattern is not None
                    else None
                ) or tree == "parent"
                if not named and not renamed:
                    continue
                line_no = clean.count("\n", 0, use_start) + 1
                orig_line = (
                    raw_lines[line_no - 1].strip()
                    if 0 <= line_no - 1 < len(raw_lines)
                    else ""
                )
                if named:
                    reach.append(
                        f"{path}:{line_no}: {orig_line}"
                        "  <- an IMPORT of a NON-FILESYSTEM row of the same lint, under a "
                        "whole-module #[expect] that licenses the lint rather than its "
                        "filesystem half. The import is where the path is spelled: refused "
                        "here, an alias (`use ... as name;`) or a one-segment call after it "
                        "never has a banned path to come from"
                    )
                else:
                    reach.append(
                        f"{path}:{line_no}: {orig_line}"
                        "  <- a RENAME of the parent module of a NON-FILESYSTEM row of the "
                        "same lint, under a whole-module #[expect]. After it the call reads "
                        "`alias::name(...)`, whose last two segments match no row and whose "
                        "import line names no row either — the one shape both other patterns "
                        "miss, so the rename itself is what is refused"
                    )
        for call_m in banned_re.finditer(clean):
            pos = call_m.start()
            if not any(lo <= pos < hi for lo, hi in wholesale_spans):
                continue
            if any(lo <= pos < hi for lo, hi in narrow_spans):
                continue
            # Not the licence's own text: an attribute body naming the
            # row (a `reason = "…std::process::id…"` is already blanked
            # with the string, but a path written bare inside the lint
            # list is not) is a description, never a call.
            if any(lo <= pos <= hi for lo, hi in attr_ranges):
                continue
            line_no = clean.count("\n", 0, pos) + 1
            orig_line = (
                raw_lines[line_no - 1].strip() if 0 <= line_no - 1 < len(raw_lines) else ""
            )
            called = " ".join(call_m.group(1).split())
            reach.append(
                f"{path}:{line_no}: {orig_line}"
                f"  <- `{called}` is a NON-FILESYSTEM row of the same lint, and the "
                "whole-module #[expect] above it licenses the lint, not the filesystem half "
                "of it — give this call its own #[expect] with a reason, or route it through "
                "the seam the row exists to protect"
            )
    return count, hits, reach, len(wholesale_spans), None


# Machine-readable identity for each `--source-closure` finding kind,
# separate from the human-readable reason text below — a caller that
# needs to single out ONE kind (scripts/vfs-purity-scan.py's item 3
# excludes MACRO_RULES so a legitimate macro can stay green, per item
# 2's own required control) filters on THIS, never on a substring of the
# prose, which this file's own maintainer is free to reword without
# breaking that caller.
MACRO_RULES_KIND = "macro_rules"
INCLUDE_BANG_KIND = "include_bang"
INCLUDE_ALIAS_KIND = "include_alias"
PATH_ATTR_KIND = "path_attr"


class Hit(str):
    """A `--source-closure` finding. Behaves exactly like the formatted
    hit string everywhere it is already used as one (this file's own
    `print(f"SOURCE {h}")` / `print(f"ALLOW {h}")`, and any `in`/
    substring check) — it IS a `str`, constructed from that same text —
    but also carries `.kind`, a machine-readable tag from the constants
    above, so a caller can filter by IDENTITY instead of by matching
    prose a rewording would silently break."""

    def __new__(cls, text: str, kind: str):
        obj = str.__new__(cls, text)
        obj.kind = kind
        return obj


def scan_source_inputs(path: str):
    """`--source-closure` mode: report every construction in `path` that
    makes rustc compile source this scanner did not read, or that defers
    an attribute's own text to expansion. Same blanking as `scan_file`
    — a `//! …#[path = "…"]…` sentence in a module doc must NOT match,
    and this crate really has four of them. Returns (hits, error), where
    each hit is a `Hit` (a `str` with an added `.kind` — see above)."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except UnicodeDecodeError as e:
        return [], f"{path}: not valid UTF-8 ({e}) — refused, not skipped"
    except OSError as e:
        return [], f"{path}: could not read ({e})"

    clean = RAW_IDENT_RE.sub("  ", strip_comments_and_strings(blank_shebang(raw)))
    raw_lines = raw.splitlines()
    hits = []

    def report_line(line_no: int, why: str, kind: str) -> None:
        orig = raw_lines[line_no - 1].strip() if 0 <= line_no - 1 < len(raw_lines) else ""
        hits.append(Hit(f"{path}:{line_no}: {orig}  <- {why}", kind))

    def report(pos: int, why: str, kind: str) -> None:
        report_line(clean.count("\n", 0, pos) + 1, why, kind)

    for m in MACRO_RULES_RE.finditer(clean):
        report(
            m.start(),
            "macro_rules! — an arm can assemble a lint path from tokens this scanner never sees",
            MACRO_RULES_KIND,
        )
    for m in INCLUDE_RE.finditer(clean):
        report(
            m.start(),
            "include! — rustc compiles source this scan never walked",
            INCLUDE_BANG_KIND,
        )
    # The same macro reached by another name. Deduplicated by LINE: the
    # three spellings overlap (an aliased import matches two of them at
    # once) and one line deserves one finding.
    aliased = set()
    for rx in (INCLUDE_PATH_RE, INCLUDE_IMPORT_RE, INCLUDE_ALIAS_RE):
        for m in rx.finditer(clean):
            aliased.add(clean.count("\n", 0, m.start()) + 1)
    for line_no in sorted(aliased):
        report_line(
            line_no,
            "the include macro named without the ! — an import, a rename or a qualified "
            "path still splices in source this scan never walked",
            INCLUDE_ALIAS_KIND,
        )
    for attr_m in ATTR_OPEN_RE.finditer(clean):
        open_bracket = attr_m.end() - 1
        close_bracket = find_matching(clean, open_bracket, "[", "]")
        if close_bracket is None:
            continue
        body = clean[open_bracket + 1 : close_bracket]
        for m in PATH_ATTR_RE.finditer(body):
            report(
                open_bracket + 1 + m.start(),
                "#[path] — rustc compiles a file outside the walked tree",
                PATH_ATTR_KIND,
            )
    return hits, None


def read_banned_rows(config_path: str):
    """The `disallowed-methods` paths in `config_path`. Any failure is a
    REFUSAL (exit 2) with one line, never an empty set: a row list that
    could not be read must not read as "no rows to check"."""
    if sys.version_info < (3, 11):
        print(
            "ERROR --banned-rows parses TOML with `tomllib`, which needs python 3.11 or newer "
            f"(found {sys.version_info.major}.{sys.version_info.minor}) — refused, never "
            "treated as an empty row set.",
            file=sys.stderr,
        )
        sys.exit(2)
    import tomllib  # noqa: PLC0415 — deliberately after the version guard

    try:
        with open(config_path, "rb") as fh:
            config = tomllib.load(fh)
    except Exception as e:  # noqa: BLE001 — any failure here is a refusal
        print(f"ERROR could not read {config_path}: {e} — refused, never treated as an "
              "empty row set.", file=sys.stderr)
        sys.exit(2)
    rows = config.get("disallowed-methods")
    if not isinstance(rows, list) or not rows:
        print(f"ERROR {config_path} has no `disallowed-methods` rows — refused: an empty row "
              "set would silently check nothing.", file=sys.stderr)
        sys.exit(2)
    paths = []
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("path"), str):
            paths.append(row["path"])
        elif isinstance(row, str):
            paths.append(row)
        else:
            print(f"ERROR {config_path} has a `disallowed-methods` row this scanner cannot "
                  f"read: {row!r} — refused.", file=sys.stderr)
            sys.exit(2)
    return paths


def main() -> None:
    source_closure = "--source-closure" in sys.argv[1:]
    banned_re = None
    banned_use_pattern = None
    banned_rename_pattern = None
    banned_rows = ()
    crate_dir = ""
    argv = sys.argv[1:]
    if "--crate-dir" in argv:
        i = argv.index("--crate-dir")
        if i + 1 >= len(argv):
            print("ERROR --crate-dir needs a path", file=sys.stderr)
            sys.exit(2)
        crate_dir = argv[i + 1]
    if "--banned-rows" in argv:
        i = argv.index("--banned-rows")
        if i + 1 >= len(argv):
            print("ERROR --banned-rows needs a clippy.toml path", file=sys.stderr)
            sys.exit(2)
        rows = read_banned_rows(argv[i + 1])
        banned_rows = tuple(rows)
        banned_re = banned_call_re(rows)
        banned_use_pattern = banned_use_re(rows)
        banned_rename_pattern = banned_prefix_rename_re(rows)
        if banned_re is None or banned_use_pattern is None or banned_rename_pattern is None:
            print("ERROR --banned-rows produced no matchable row — refused.", file=sys.stderr)
            sys.exit(2)
    paths = [p for p in sys.stdin.buffer.read().split(b"\0") if p]
    total = 0
    total_licences = 0
    all_hits = []
    all_reach = []
    for raw_path in paths:
        # A FILE NAME is bytes on unix, and `find` hands over whatever
        # is on disk. A `.rs` file whose NAME is not valid UTF-8 is
        # legal, compiles, and would take a plain `.decode("utf-8")` out
        # with a `UnicodeDecodeError` traceback — which the caller's
        # `scan_or_die` reports as an exit-2 refusal, but with a traceback
        # in place of a diagnosis. Refused the same way an unreadable file is:
        # named, one line, exit 2 — never skipped, since a name this
        # cannot decode is exactly where something would be hidden.
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as e:
            print(
                f"ERROR {raw_path!r}: the FILE NAME is not valid UTF-8 ({e}) — refused, not "
                "skipped: this scanner cannot report a path it cannot render.",
                file=sys.stderr,
            )
            sys.exit(2)
        if source_closure:
            hits, error = scan_source_inputs(path)
            c, reach = 0, []
            licences = 0
        else:
            c, hits, reach, licences, error = scan_file(
                path, banned_re, banned_use_pattern, crate_dir,
                banned_rename_pattern, banned_rows
            )
            total_licences += licences
        if error is not None:
            print(f"ERROR {error}", file=sys.stderr)
            sys.exit(2)
        total += c
        all_hits.extend(hits)
        all_reach.extend(reach)
    if source_closure:
        for h in all_hits:
            print(f"SOURCE {h}")
        return
    print(f"COUNT {total}")
    for h in all_hits:
        print(f"ALLOW {h}")
    print(f"LICENCES {total_licences}")
    for h in all_reach:
        print(f"REACH {h}")


if __name__ == "__main__":
    main()
