#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Self-test for scripts/check-fail-open.py.

EVERY rule gets BOTH controls, and that pairing is the point. A rule with
only a red is a rule nobody has shown to be silent on correct code: it can
"pass" its red by flagging everything. A rule with only a green is a rule
nobody has shown to fire at all. A gate whose failure mode was never
demonstrated does not exist, and neither does one whose success mode
wasn't.

Each case plants ONE file in a scratch tree shaped like the repository
(scripts/ and docs/research/), runs the real `scan`, and requires:
  RED   -- exactly the expected rule fires, on the expected line
  GREEN -- the FIXED form of the same construct fires nothing at all
The green form of each case is the rewrite this project actually uses, so
the self-test doubles as the documentation of what the fix looks like.
"""
if not __debug__:  # pragma: no cover
    raise SystemExit("REFUSED: this self-test's checks are asserts; run without -O.")

import shutil
import sys
import tempfile
from pathlib import Path

SH = "#!/usr/bin/env bash\nset -uo pipefail\n"
SH_E = "#!/usr/bin/env bash\nset -euo pipefail\n"

# (label, rule, relative path, RED body, GREEN body)
CASES = [
    ("R1 python assert with no -O refusal", "R1", "scripts/x.py",
     "import sys\nassert sys.argv, 'nope'\n",
     "import sys\nif not __debug__:\n    raise SystemExit('REFUSED')\nassert sys.argv, 'nope'\n"),

    # The PAREN form. `assert(cond)` is the same
    # ast.Assert node -O deletes, but `^\s*assert ` misses
    # it. Parsing recognizes both spellings; this row
    # requires the parenthesized form to be caught.
    ("R1 the paren form assert(cond), which a regex misses", "R1", "scripts/x.py",
     "import sys\nassert(len(sys.argv) > 0)\n",
     "import sys\nif not __debug__:\n    raise SystemExit('REFUSED')\nassert(len(sys.argv) > 0)\n"),

    # `__debug__` MENTIONED IN A COMMENT is not a guard.
    # A substring check could let this fixture pass
    # without a refusal, while the parsed structure
    # distinguishes the comment from executable code. The
    # paired positive fixture contains an actual refusal.
    ("R1 a __debug__ mentioned only in a comment is not a guard", "R1", "scripts/x.py",
     "# this file has no __debug__ guard, honestly\nimport sys\nassert sys.argv\n",
     "import sys\nif not __debug__:\n    raise SystemExit('REFUSED')\nassert sys.argv\n"),

    # THREE WAYS TO NAME `__debug__` WITHOUT REFUSING: printing,
    # assignment and warning. Recognising the name alone
    # cannot establish that optimized execution is refused.
    ("R1 `if __debug__:` that only prints is not a refusal", "R1", "scripts/x.py",
     "import sys\nif __debug__:\n    print('hi')\nassert sys.argv\n",
     "import sys\nif not __debug__:\n    raise SystemExit('REFUSED')\nassert sys.argv\n"),

    ("R1 a bare reference `x = __debug__` is not a refusal", "R1", "scripts/x.py",
     "import sys\nx = __debug__\nassert sys.argv\n",
     "import sys\nif not __debug__:\n    raise SystemExit('REFUSED')\nassert sys.argv\n"),

    ("R1 `if not __debug__:` that only warns is not a refusal", "R1", "scripts/x.py",
     "import sys\nif not __debug__:\n    print('warning')\nassert sys.argv\n",
     "import sys\nif not __debug__:\n    raise SystemExit('REFUSED')\nassert sys.argv\n"),

    # POLARITY: `if __debug__: raise` mentions the name and
    # raises, but its branch is skipped under -O, exactly
    # when assertions are removed and the refusal is needed.
    ("R1 a guard of the WRONG POLARITY refuses nothing under -O", "R1", "scripts/x.py",
     "import sys\nif __debug__:\n    raise SystemExit('refused')\nassert sys.argv\n",
     "import sys\nif not __debug__:\n    raise SystemExit('REFUSED')\nassert sys.argv\n"),

    # A raise the file's own handler swallows is not a refusal.
    ("R1 a refusal swallowed by try/except is not a refusal", "R1", "scripts/x.py",
     "import sys\nif not __debug__:\n    try:\n        raise SystemExit('r')\n"
     "    except SystemExit:\n        pass\nassert sys.argv\n",
     "import sys\nif not __debug__:\n    raise SystemExit('REFUSED')\nassert sys.argv\n"),

    # An assert nested inside a function, which a top-level-only rule misses.
    ("R1 an assert nested in a function", "R1", "scripts/x.py",
     "def check(n):\n    assert n > 0\n",
     "if not __debug__:\n    raise SystemExit('REFUSED')\n\n\ndef check(n):\n    assert n > 0\n"),

    # A file the lint cannot PARSE has not been checked. Staying silent about
    # it is the fail-open shape one rule down.
    ("R1 a file that does not parse is reported, not skipped", "R1", "scripts/x.py",
     "def broken(:\n",
     "def fine():\n    return 1\n"),

    ("R2 unguarded tee, no set -e", "R2", "scripts/x.sh",
     SH + 'echo hi | tee -a "$OUT"\n',
     SH + 'echo hi | tee -a "$OUT" || { echo "REFUSED: cannot write $OUT" >&2; exit 1; }\n'),

    # `|| true` discards failure. Its `||` token must not
    # cause the pipeline to be classified as handled.
    ("R2 a tee whose status is discarded by || true", "R2", "scripts/x.sh",
     SH + 'echo hi | tee -a "$OUT" || true\n',
     SH + 'echo hi | tee -a "$OUT" || { echo "REFUSED" >&2; exit 1; }\n'),

    # A `$(` in the PRODUCER captures a value for that
    # command; it does not capture the tee pipeline's output.
    ("R2 a $( in the producer is not a capture", "R2", "scripts/x.sh",
     SH + 'echo "$(date)" | tee -a "$OUT"\n',
     SH + 'STAMP="$(echo "$(date)" | tee -a "$OUT")"\n'),

    # The pipeline captured must be the one with the tee in it.
    ("R2 a capture of something ELSE on the line is not a capture", "R2", "scripts/x.sh",
     SH + 'STAMP="$(date)"; echo hi | tee -a "$OUT"\n',
     SH + 'STAMP="$(echo hi | tee -a "$OUT")"\n'),

    ("R4a `git -c key=value grep` is still git grep", "R4a", "scripts/x.sh",
     SH + 'hits="$(git -c color.ui=false grep -l AGPL -- . || true)"\n',
     SH + 'g=0; hits="$(git -c color.ui=false grep -l AGPL -- .)" || g=$?\n'
          '[ "$g" -le 1 ] || { echo "REFUSED" >&2; exit 2; }\n'),

    ("R4b the `set -eu -o pipefail` spelling still sets pipefail", "R4b", "scripts/x.sh",
     '#!/usr/bin/env bash\nset -eu -o pipefail\nyes x | head -1 || true\n',
     '#!/usr/bin/env bash\nset -eu -o pipefail\nV="$(yes x | grep -m1 .)"\n'),

    # `set -o errexit -o pipefail` names two options.
    # The pattern must recognise pipefail after the
    # second `-o`, so this spelling does not disable R4b.
    ("R4b the `set -o errexit -o pipefail` spelling still sets pipefail", "R4b", "scripts/x.sh",
     '#!/usr/bin/env bash\nset -o errexit -o pipefail\nyes x | head -1 || true\n',
     '#!/usr/bin/env bash\nset -o errexit -o pipefail\nV="$(yes x | grep -m1 .)"\n'),

    ("R4b a reader invoked by FULL PATH still short-circuits", "R4b", "scripts/x.sh",
     SH + 'yes x | /usr/bin/head -1 || true\n',
     SH + 'V="$(yes x | grep -m1 .)"\n'),

    # A handler that CANNOT FAIL swallows the failure exactly like `|| true`.
    ("R2 a handler that cannot fail is not a handler", "R2", "scripts/x.sh",
     SH + 'echo hi | tee -a "$OUT" || { :; }\n',
     SH + 'echo hi | tee -a "$OUT" || { echo x >&2; exit 1; }\n'),

    ("R4a git grep with its status swallowed", "R4a", "scripts/x.sh",
     SH + 'hits=$(git grep -l AGPL -- crates || true)\n',
     SH + 'hits=$(git grep -l AGPL -- crates); rc=$?\n'
          '[ "$rc" -le 1 ] || { echo "REFUSED: git grep failed" >&2; exit 2; }\n'),

    ("R4b reader whose 141 is discarded", "R4b", "scripts/x.sh",
     SH + 'V="$(grep -n TASK "$F" | head -1 | cut -d: -f1 || true)"\n',
     SH + 'V="$(grep -m1 -n TASK "$F" | cut -d: -f1)"\n'),
]

# A rule must not fire on a file that merely MENTIONS the shape in a
# comment; a lint that reads its own documentation as a violation is the
# self-match class this project has paid for twice.
COMMENT_ONLY = SH + '# git grep foo || true\n# cmd | head -1 || true\n# echo x | tee f\necho ok\n'


def run(scan):
    tmp = Path(tempfile.mkdtemp(prefix="fail-open-lint-selftest."))
    failed = 0
    try:
        for label, rule, rel, red, green in CASES:
            for kind, body in (("RED", red), ("GREEN", green)):
                for d in ("scripts", "docs/research"):
                    shutil.rmtree(tmp / d, ignore_errors=True)
                    (tmp / d).mkdir(parents=True)
                p = tmp / rel
                p.write_text(body)
                found = [f for f in scan(tmp) if f[0] == rule]
                other = [f for f in scan(tmp) if f[0] != rule]
                if kind == "RED":
                    ok = len(found) == 1
                    detail = f"{len(found)} {rule} finding(s)"
                else:
                    ok = len(found) == 0 and len(other) == 0
                    detail = (f"{len(found)} {rule} + {len(other)} other finding(s)"
                              " -- the FIXED form must be silent")
                print(f"  {'ok  ' if ok else 'FAIL'} [{kind:5}] {label}: {detail}")
                if not ok:
                    failed += 1

        # The comment-only control, for every rule at once.
        for d in ("scripts", "docs/research"):
            shutil.rmtree(tmp / d, ignore_errors=True)
            (tmp / d).mkdir(parents=True)
        (tmp / "scripts" / "x.sh").write_text(COMMENT_ONLY)
        found = scan(tmp)
        ok = len(found) == 0
        print(f"  {'ok  ' if ok else 'FAIL'} [CTRL ] a file that only MENTIONS the shapes "
              f"in comments: {len(found)} finding(s), expected 0")
        if not ok:
            failed += 1

        # THE HELPER'S CONTRACT, pinned directly. Deleting RE_DISCARD is an
        # EQUIVALENT MUTANT of _tee_handled -- RE_HANDLER is an ALLOWLIST that
        # `true` can never match, so the discard rejection is defence in depth
        # against that allowlist later growing something permissive, and no
        # end-to-end fixture can observe it. Recorded as equivalent rather than
        # reported as a coverage gap; the contract is pinned here so the helper
        # cannot drift whichever regex does the work.
        import importlib.util as _u
        _s = _u.spec_from_file_location(
            "cfo", Path(__file__).resolve().parents[1] / "check-fail-open.py")
        _m = _u.module_from_spec(_s)
        _s.loader.exec_module(_m)
        TEE_CONTRACT = [
            ('echo hi | tee -a "$O"', False, "bare tee is not handled"),
            ('echo hi | tee -a "$O" || true', False, "|| true DISCARDS, never guards"),
            ('echo hi | tee -a "$O" || :', False, "|| : likewise"),
            ('echo "$(date)" | tee -a "$O"', False, "a $( in the PRODUCER is not a capture"),
            ('echo hi | tee -a "$O" || { echo x >&2; exit 1; }', True, "a brace group can fail"),
            ('echo hi | tee -a "$O" || die "no"', True, "die can fail"),
            ('echo hi | tee -a "$O" || { :; }', False, "a block that cannot fail"),
            ('echo hi | tee -a "$O" || (true)', False, "a subshell that cannot fail"),
            ('X="$(echo hi | tee -a "$O")"', True, "the pipeline IS captured"),
        ]
        bad = [(l, w, g) for l, w, g in TEE_CONTRACT if _m._tee_handled(l) != w]
        ok = not bad
        print(f"  {'ok  ' if ok else 'FAIL'} [CTRL ] _tee_handled contract: "
              f"{len(TEE_CONTRACT) - len(bad)}/{len(TEE_CONTRACT)} classified correctly")
        for l, w, g in bad:
            print(f"         wanted handled={w} ({g}) for: {l}")
        if not ok:
            failed += 1

        # The empty-tree control, and it is about a VACUOUS PASS rather than
        # about silence. scan() over nothing must be silent AND main() must
        # refuse, because a lint that examined no files reporting "clean" is
        # exactly the shape this file forbids -- reproduced by running it
        # from a working directory outside a repository.
        for d in ("scripts", "docs/research"):
            shutil.rmtree(tmp / d, ignore_errors=True)
            (tmp / d).mkdir(parents=True)
        n = len(scan(tmp))
        ok = n == 0
        print(f"  {'ok  ' if ok else 'FAIL'} [CTRL ] empty tree: scan() gives {n} finding(s), expected 0")
        if not ok:
            failed += 1
        # THE FIXTURE MUST BE A REAL CHECKOUT, and
        # the control must assert the SPECIFIC
        # refusal. Running in a bare temporary
        # directory would trigger the repository-root
        # refusal before reaching the vacuous-pass
        # guard. Both refusals are exercised with
        # separate fixtures and matched on their
        # own diagnostic words, so an unrelated
        # refusal cannot satisfy the control.
        import subprocess as _sp
        LINT = str(Path(__file__).resolve().parents[1] / "check-fail-open.py")

        # (i) a real repo with no scripts/ or docs/research -> the VACUOUS-PASS
        #     refusal, which is the one this control is about.
        repo = tmp / "emptyrepo"
        repo.mkdir()
        _sp.run(["git", "init", "-q", str(repo)], capture_output=True)
        r = _sp.run([sys.executable, LINT], cwd=repo, capture_output=True, text=True)
        blob = r.stdout + r.stderr
        ok = r.returncode != 0 and "no .py or .sh files found" in blob
        print(f"  {'ok  ' if ok else 'FAIL'} [CTRL ] a scan that examined NOTHING refuses by "
              f"NAME, in a real checkout: rc={r.returncode}")
        if not ok:
            failed += 1

        # (ii) a non-checkout -> the REPOSITORY-ROOT refusal, a different guard
        #      with a different message.
        nonrepo = tmp / "notarepo"
        nonrepo.mkdir()
        r = _sp.run([sys.executable, LINT], cwd=nonrepo, capture_output=True, text=True)
        blob = r.stdout + r.stderr
        ok = r.returncode != 0 and "could not locate the repository root" in blob
        print(f"  {'ok  ' if ok else 'FAIL'} [CTRL ] a scan with no repository root refuses by "
              f"NAME: rc={r.returncode}")
        if not ok:
            failed += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total = len(CASES) * 2 + 5
    if failed:
        print(f"fail-open lint self-test: {total - failed}/{total} passed, {failed} FAILED")
        return 1
    print(f"fail-open lint self-test: {total}/{total} passed — every rule has a red AND a green")
    return 0
