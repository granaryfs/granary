#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""The fail-open shape lint.

This lint checks for gates that silently stop
checking, using the fail-open shapes described below.

  scripts/check-fail-open.py              lint (exit 1 on any finding)
  scripts/check-fail-open.py --self-test  every rule's RED and its GREEN
  scripts/check-fail-open.py --report-r3  the DEFERRED rule's fire-set

WHAT IS AND IS NOT A RULE HERE, AND WHY -- because the obvious version of
this lint is itself fail-open.

The candidate shapes include `| head`, `| tee`
without a status check, `printf | grep -q`, `|| true`
after a status-bearing command, and Python `assert`
without a `-O` refusal. Context matters for some
shapes: flagging every bounded helper would
require waivers that could hide real failures. R3
therefore remains report-only; `--report-r3`
prints the candidate sites for inspection rather
than treating every match as a blocking defect.

PIPELINE FAILURE HAS DIFFERENT CAUSES THAT REQUIRE DIFFERENT RULES.

* `cmd | tee f` does NOT hide cmd's failure
under `set -o pipefail`. The pipeline can
fail when either command fails. R2 checks a
different case: tee's own write failure goes
unhandled in a script with no `set -e`. A
pipeline may preserve a nonzero status
without its caller acting on that status.
* The SIGPIPE class is real and SIZE-DEPENDENT. EXECUTED under
  `set -uo pipefail`, match on line 1 with megabytes behind it:
      printf '%s\n' "$big" | grep -q '^HIT$'  -> rc=141, reads as NO-MATCH
      cat 16MB.txt        | grep -q '^HIT$'   -> rc=141
      grep '^y' 16MB.txt  | head -n 1         -> rc=141
  The same three on small inputs return 0. That is why the shape survives
  review, and why "it passes today" is not a defence.

WHAT THIS LINT CLAIMS, AND WHAT IT DOES NOT — read
this before trusting a clean run. The self-test
exercises positive and negative fixtures. Shell-scanning
limitations include commands split across physical
lines and changes in errexit state within a file.

  * A backslash-CONTINUATION splits one command across physical lines, and every
    shell rule here matches within a line, so a piped `echo` continued onto a
    second line holding `tee -a "$OUT"` is invisible. Joining logical lines closes it AND produced two false
    positives: `'mount|tee x'`, a STRING LITERAL inside a list of spellings a
    scanner is required to recognise, and a `|| true` guarding a `record` call
    several continuations away from an unrelated `| head -1`.
  * `set +e` after `set -e` leaves an unprotected region this scanner does not
    track. Treating the whole file as unprotected closes it and fires on that
    same string-literal fixture list.

A handler that CANNOT FAIL (`|| { :; }`, `|| (true)`)
swallows the failure exactly like `|| true`, and
is checked. The remaining limitations include
mentions of handlers inside comments or strings
and refusals behind dead branches. These examples
show where textual matching and structural recognition
do not establish the behavior of the code:

  * `echo hi | tee -a "$OUT"  # TODO: || die "..."` — the handler pattern
    matches inside a COMMENT, and `|| echo "|| die"` matches inside a STRING.
    A comment merely MENTIONING __debug__ is not a refusal.
    R1 uses the Python parser to distinguish a name
    from a comment or string; R2 uses line patterns.
  * `if not __debug__:` + `if False: raise` — a refusal behind a dead branch.
    Closing this in general is reachability analysis; the constant-test case
    alone could be special-cased, and is not, because nobody writes it by
    accident and the threat model here is accident.

The root cause of all of them is one fact: A LINE REGEX CANNOT TELL A CONSTRUCT
FROM A MENTION OF IT, nor scope a `||` to the pipeline it follows. Shell needs a
parser and this is not one. So the honest claim is asymmetric and is stated
here rather than implied: **a finding is reliable — every positive this tool
reports has been a true one — but the ABSENCE of a shell finding is not a
guarantee.** It is an accident-catcher, not an adversary-proof gate, and the
threat model is a developer writing a fail-open shape by mistake, not someone
evading their own lint. R1 is different in kind: Python HAS a parser, R1 uses
it, and its claim is correspondingly stronger.

THIS FILE LINTS ITSELF. A scanner that contains
the literal patterns it hunts can match its own
source, so patterns below are assembled from
fragments and the rule documentation lives in
this docstring. This avoids treating a description
of a fail-open shape as an executable occurrence
of it. The shell scanner remains textual: its
comment skipping and pattern checks do not
establish the meaning of every shell construct.
"""
if not __debug__:  # pragma: no cover
    raise SystemExit("REFUSED: this lint's own checks include asserts; run without -O.")

import ast
import re
import subprocess
import sys
from pathlib import Path

# Assembled rather than written whole, so this file's source cannot match
# its own rules (see the docstring's last paragraph).
_Q = r"(?:\S*/)?grep\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*q"
_M = r"grep\s+-m\s*\d+"
_READER = r"\|\s*(?:\S*/)?(?:head\b|" + _Q + r"|" + _M + r")"
_ORTRUE = r"\|\|\s*(?:" + "tr" + "ue|:)"
# `git -c key=value grep` — the option takes a VALUE, so a bare word may
# sit between the flag and the subcommand.
_GITGREP = r"git\s+(?:-\S+\s+|\S+=\S+\s+)*" + "grep" + r"\b.*" + _ORTRUE
_TEE = r"\|\s*tee\b"

RE_READER = re.compile(_READER)
RE_ORTRUE = re.compile(_ORTRUE)
RE_GITGREP = re.compile(_GITGREP)
RE_TEE = re.compile(_TEE)
RE_COMMENT = re.compile(r"^\s*#")
RE_SETE = re.compile(r"^\s*set\s+-[a-z]*e", re.M)
# `set +e` after `set -e` leaves an unprotected region this
# scanner does not track. Treating the whole file as
# unprotected also risks matching shell-looking string
# literals. This limitation is documented rather than claiming
# that file-level detection tracks local state changes.
# The pipefail pattern allows multiple
# option words, including `set -o errexit -o pipefail`.
# Restricting it to the token immediately
# after the first `-o` would miss that
# spelling and disable the
# pipefail-dependent checks for the file.
RE_PIPEFAIL = re.compile(r"^\s*set\s+[-\w\s]*?pipefail\b", re.M)
RE_ASSERT = re.compile(r"^\s*assert ", re.M)


def root():
    """The repository root, or a REFUSAL.

    Falling back to the current directory when
    `git rev-parse` fails could scan a tree with
    no inputs and report a clean run. This function
    refuses when the repository root cannot be
    located: a tool that cannot locate what it
    is meant to examine has not examined it."""
    r = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        raise SystemExit(
            "REFUSED: could not locate the repository root "
            f"(git rev-parse exited {r.returncode}). This lint scans paths "
            "relative to it; without it there is nothing to report on, and "
            "'clean' would be a lie.")
    return Path(r.stdout.strip())


def files(base, suffix):
    out = []
    for d in ("scripts", "docs/research"):
        p = base / d
        if p.is_dir():
            out += sorted(q for q in p.rglob("*" + suffix) if q.is_file())
    return out


def lines(p):
    try:
        return p.read_text(errors="replace").splitlines()
    except OSError as e:                       # unreadable is not clean
        raise SystemExit(f"REFUSED: cannot read {p}: {e}")


# `|| true` and `|| :` are the OPPOSITE of a handler: they discard the status.
# Anything else after `||` -- a brace group, `die`, `exit`, `return`, `fail` --
# can still fail the script, which is what makes it a guard.
RE_DISCARD = re.compile(r"\|\|\s*(?:" + "tr" + r"ue|:)(?:\s|$|;|\)|\})")
# A handler that CANNOT FAIL is not a handler. `|| { :; }`
# and `|| (true)` swallow failure like `|| true`; reject
# those forms before testing the accepting handler pattern.
RE_NULL_BLOCK = re.compile(r"\|\|\s*[({]\s*(?:" + "tr" + r"ue|:)\s*;?\s*[)}]")
RE_HANDLER = re.compile(r"\|\|\s*(?:\{|\(|die\b|exit\b|return\b|fail\b|abort\b)")
# A CAPTURE of the pipeline, not merely a `$(` somewhere on the line: the
# assignment form, where the value is taken and therefore used.
RE_CAPTURE = re.compile(r"^\s*(?:local\s+|export\s+|declare\s+)?\w+=\"?\$\(")


def _tee_handled(line):
    """Is this `| tee` line's write failure actually dealt with?"""
    if RE_DISCARD.search(line) or RE_NULL_BLOCK.search(line):
        return False          # `|| true` is not a guard; it is the defect
    if RE_HANDLER.search(line):
        return True           # `|| { ...; exit 1; }`, `|| die ...`
    # The capture must CONTAIN the tee. In
    # `STAMP="$(date)"; echo hi | tee -a f`, the assignment captures
    # only date, not the unrelated pipeline after the semicolon.
    m = RE_CAPTURE.match(line)
    if not m:
        return False
    depth, i = 0, m.end() - 2          # at the "$(" the match ended on
    while i < len(line):
        if line.startswith("$(", i):
            depth += 1; i += 2; continue
        if line[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return RE_TEE.search(line[m.end():i]) is not None


def _negates_debug(test):
    """Is this `if` test true exactly when `__debug__` is FALSE?

    POLARITY IS THE WHOLE POINT: `if __debug__: raise
    SystemExit(...)` mentions the name and raises, but under
    `-O` both that guard and the asserts vanish. It refuses
    nothing in the mode that matters. Accepted forms are `not
    __debug__` and a comparison against a false constant."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return any(isinstance(x, ast.Name) and x.id == "__debug__"
                   for x in ast.walk(test.operand))
    if isinstance(test, ast.Compare):
        names = [x for x in ast.walk(test) if isinstance(x, ast.Name)]
        consts = [x for x in ast.walk(test) if isinstance(x, ast.Constant)]
        if any(n.id == "__debug__" for n in names) and any(
                c.value in (False, 0) for c in consts):
            return all(isinstance(o, (ast.Eq, ast.Is)) for o in test.ops)
    if isinstance(test, ast.BoolOp):
        return any(_negates_debug(v) for v in test.values)
    return False


def _refuses(body):
    """Does this block RAISE or EXIT unconditionally enough to be a refusal?

    A raise swallowed by its `try` handler is not a refusal.
    Descending blindly into that body could accept
    `try: raise SystemExit(...) except SystemExit: pass`. Only
    the `finally` and `else` blocks of a Try are searched here."""
    for stmt in body:
        if isinstance(stmt, ast.Raise):
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            fn = stmt.value.func
            name = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if name in ("exit", "_exit"):
                return True
        if isinstance(stmt, ast.Try):
            if _refuses(stmt.finalbody) or _refuses(stmt.orelse):
                return True
            continue                      # its body is not a refusal
        for field in ("body", "orelse"):
            inner = getattr(stmt, field, None)
            if isinstance(inner, list) and _refuses(inner):
                return True
    return False


def _is_debug_refusal(node):
    """An `if` that fires when `__debug__` is FALSE and then REFUSES.

    Not merely a reference to the name: `if __debug__:
    print(...)`, `x = __debug__` and `if not __debug__:
    print("warning")` all reference it and refuse
    nothing. `_negates_debug` checks the test polarity;
    `_refuses` checks the body for a refusal."""
    return (isinstance(node, ast.If)
            and _negates_debug(node.test)
            and _refuses(node.body))


def scan(base):
    """-> list of (rule, path, lineno, message). Empty means clean."""
    f = []

    # R1  A Python `assert` used as a check, with no -O refusal.
    #     `python3 -O` / PYTHONOPTIMIZE delete every assert, and the script
    #     then runs to completion checking NOTHING, printing exactly what it
    #     prints when the checks pass.
    #
    #     BY PARSER, NOT BY REGEX. The pattern `^\s*assert `
    #     misses `assert(cond)`, which is the same `Assert`
    #     node, deleted by -O just the same. A regex cannot
    #     enumerate the ways a statement can be spelled;
    #     the parser already knows.
    for p in files(base, ".py"):
        text = p.read_text(errors="replace")
        try:
            tree = ast.parse(text)
        except SyntaxError as e:
            # A file this lint cannot parse has NOT been checked. Saying
            # nothing about it is the fail-open shape one rule down.
            f.append(("R1", p, e.lineno or 1,
                      f"could not parse this file, so it was not checked: {e.msg}"))
            continue
        hits = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
        # Check the guard STRUCTURALLY, like the asserts.
        # A substring search for `__debug__` would also
        # accept mentions inside comments or strings.
        # The Python parser omits comments and represents
        # strings as Constants, so `_is_debug_refusal`
        # can distinguish a test using the name from
        # text merely describing it. The test and
        # body must also meet the refusal predicates.
        #
        # BUT A NAME IS NOT A GUARD EITHER. `if
        # __debug__: print(...)`, `x = __debug__`
        # and `if not __debug__: print("warning")`
        # all reference the name and refuse
        # NOTHING. Recognise the refusal: an
        # `if` whose test has the required
        # polarity and whose body raises or exits,
        # as checked by `_is_debug_refusal`.
        guarded = any(_is_debug_refusal(n) for n in ast.walk(tree))
        if hits and not guarded:
            f.append(("R1", p, min(n.lineno for n in hits),
                      f"{len(hits)} assert(s) used as checks and no -O refusal; "
                      f"add: if not __debug__: raise SystemExit(...)"))

    for p in files(base, ".sh"):
        text = p.read_text(errors="replace")
        sete = RE_SETE.search(text) is not None
        pipefail = RE_PIPEFAIL.search(text) is not None
        # Scan PHYSICAL lines. Joining backslash
        # continuations would expose split commands,
        # but a line regex cannot distinguish a command
        # from a string mentioning it or scope a
        # handler to the right pipeline. A fixture
        # string such as `mount|tee x` can look
        # executable, and a `|| true` on another
        # command can be mistaken for the handler of
        # a reader pipeline. The module docstring names
        # these limitations; extending the matched
        # span alone does not supply shell parsing.
        for n, l in enumerate(text.splitlines(), 1):
            if RE_COMMENT.match(l):
                continue

            # R2  A pipeline into `tee` whose WRITE failure is unhandled, in a
            #     script with no `set -e`. The transcript is lost silently. The
            #     guarded form is:
            #       echo "$X" | tee -a "$OUT" || { echo REFUSED >&2; exit 1; }
            #     A `||` token alone does not establish a
            #     handler: `|| true` explicitly discards
            #     failure. A `$(` token alone does not
            #     establish capture either: in
            #     `echo "$(date)" | tee -a "$OUT"`, it belongs
            #     to the producer. `_tee_handled` checks for
            #     a handler that can fail or an assignment
            #     whose substitution contains the tee pipeline.
            if RE_TEE.search(l) and not sete and not _tee_handled(l):
                f.append(("R2", p, n,
                          "unguarded tee in a script without set -e: " + l.strip()[:80]))

            # R4a: `git grep ... || true` erases the
            # distinction between no match and a failed
            # query, such as an unreadable index or a
            # repository ownership refusal. A query that
            # cannot complete must not read as a clean
            # tree; see check-licence-boundary.sh's header.
            #
            if RE_GITGREP.search(l):
                f.append(("R4a", p, n,
                          "git grep ... || true cannot tell 'no match' from "
                          "'git failed': " + l.strip()[:80]))

            # R4b  A short-circuit reader whose 141 is then discarded. Strictly
            #      worse than either half: the reader can SIGPIPE its producer
            #      AND the suffix throws the status away, so the construct can
            #      neither fail nor be detected. It is also the EVASION shape
            #      for the deferred R3 -- appending the suffix would silence it.
            if pipefail and RE_READER.search(l) and RE_ORTRUE.search(l):
                f.append(("R4b", p, n,
                          "short-circuit reader whose status is then discarded: "
                          + l.strip()[:80]))
    return f


def report_r3(base):
    """R3, DEFERRED -- NOT A GATE. Enumerated so a successor inherits it.

    The shape is a short-circuit reader in a pipefail script whose status is
    consumed. At scale the producer takes SIGPIPE and the status is 141
    whatever the data said. Whether a SITE is a defect turns on two things
    no regex decides: POLARITY (does a spurious 141 make the check pass, or
    merely fail noisily?) and BOUNDEDNESS (can the output ever get big?).

    13 of these sites are in one task-exit gate, almost all inside its own
    self-test over its own one-line diagnostics, where a spurious
    141 makes a control REPORT FAILURE -- fail-CLOSED and bounded. Calling
    those defects would be wrong, and the only route to green would be ~50
    waivers, which is the mechanism this lint exists to prevent.

    Narrowing R3 to "evidence-producing" directories
    silently exempts scripts outside that scope.
    Inside it, bounded fail-closed helpers still
    match the rule, so the narrowing still
    reports those sites as defects. Boundedness
    can change with the input; a path restriction
    neither distinguishes those helpers nor
    tracks changes in their output size.

    R3 therefore remains a report rather than a gate: its scan lists
    reader pipelines but does not decide whether their output is
    bounded or whether SIGPIPE causes a false pass. Two rewrites are:
        printf '%s' "$x" | grep -q P  -> grep -q P <<< "$x"
        cmd | head -1             -> cmd | sed -n 1p
    The here-string supplies the captured value directly to grep,
    removing the pipe and its producer. This does not establish
    whether the command that produced the captured value succeeded.
    For a command producer, `sed -n 1p` prints the first line but
    continues reading to EOF, draining the pipe instead of closing
    it early like `head -1`. It trades early closure for reading
    the whole stream; use it when the producer terminates (finite output)
    and reading all of that output is acceptable.
    """
    hits = 0
    for p in files(base, ".sh"):
        text = p.read_text(errors="replace")
        if not RE_PIPEFAIL.search(text):
            continue
        for n, l in enumerate(text.splitlines(), 1):
            if RE_COMMENT.match(l) or not RE_READER.search(l):
                continue
            if RE_ORTRUE.search(l):        # that one is R4b's, and is a gate
                continue
            print(f"  {p.relative_to(p.parents[len(p.parts) - 2])}:{n}"
                  if False else f"  {p}:{n}")
            hits += 1
    print(f"R3 (DEFERRED, not a gate): {hits} sites")
    return 0


def main(argv):
    base = root()
    if "--report-r3" in argv:
        return report_r3(base)
    if "--self-test" in argv:
        # Anchor the self-test on `__file__`. `root()`
        # selects the tree being linted, which may be
        # a different checkout from the one holding
        # this executable. Using that ambient root to
        # locate the probe would run the other checkout's
        # test code. The probe beside this script is
        # the one that tests this implementation.
        from importlib import util
        st = Path(__file__).resolve().parent / "probes" / "fail-open-lint-self-test.py"
        if not st.is_file():
            raise SystemExit(f"REFUSED: self-test not found beside this script at {st}")
        spec = util.spec_from_file_location("st", st)
        mod = util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.run(scan)
    n_examined = len(files(base, ".py")) + len(files(base, ".sh"))
    if n_examined == 0:
        raise SystemExit(
            f"REFUSED: no .py or .sh files found under {base}/scripts or "
            f"{base}/docs/research. A lint that examined NOTHING must not "
            "report 'clean' — that is the vacuous pass this project's "
            "standards rule forbids.")
    found = scan(base)
    print(f"fail-open lint: R1 python-optimise, R2 unguarded-tee, "
          f"R4a git-grep-swallowed, R4b reader-status-discarded "
          f"({n_examined} files examined)")
    for rule, p, n, msg in found:
        print(f"  {rule:<4} {p}:{n}\n        {msg}")
    if not found:
        print("fail-open lint: clean")
        return 0
    print(f"fail-open lint: FAILED -- {len(found)} site(s)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
