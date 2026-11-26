#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
r"""A `path.rs:N` citation that points PAST THE END of its own target file is wrong, and until this
gate nothing checked it.

A non-shipping plan-block checker verifies the ANCHORED form `path:12 "verbatim fragment"`
only in non-shipping implementation plans. Everything else in the repo is BARE and counted as debt.
This gate covers the LIVE SET -- files under `docs/adr/` and `scripts/` -- with the one
check that needs no semantics: does the cited line exist in the file at all?

WHAT IT DELIBERATELY DOES NOT DO. It cannot tell a correct citation from one that resolves to the
WRONG construct. Do not re-point a citation by arithmetic: the resulting line can exist while
naming the wrong construct and can therefore survive review looking correct. This gate checks
line existence only; establishing that a citation names the intended construct requires reading it.

THE EXEMPTION IS PER CITATION, AND IT MUST VERIFY. A document's classification does not exempt
the citations inside it: each citation must have its own applicable, verified historical target.
A citation is exempt when a sha is in force for it -- in its own paragraph, or by a
`cite-frozen:` marker above it -- AND that sha is a real commit at which the file HELD that line.
Parsing a sha without checking the target file at that commit is not verification.
A marker must not suppress a citation that was already past EOF at its stated commit,
including when the marker's target is `*`.

COVERAGE IS ENFORCED, NOT JUST PRINTED. A gate that prints only a
verdict cannot be told from one whose scope collapsed to nothing, so
this one states how many citations it saw and how many it resolved —
AND REFUSES below a floor. Printing a count alone does not check it.

THE SHORTHAND CONTINUATION IS A SIBLING CLASS AND IT IS NOT READ. A
citation can continue with a backticked bare `:NNN`, as in
`handlers.rs:215` followed by `:362`. The census command strips Git's
own `path.md:123:` output prefix before matching citations, since
that prefix otherwise supplies a match unrelated to the source text.

    git grep -nE '`:[0-9]+(-[0-9]+)?`' -- docs/adr scripts ':!scripts/check-citations.py' \
      | sed -E 's/^[^:]+:[0-9]+://' | grep -E '\.({EXTS}):[0-9]' \
      | grep -ohE '`:[0-9]+(-[0-9]+)?`' | wc -l

A SELF-TEST FIXTURE THAT NAMES A REAL PATH IS CHECKED LIKE A CLAIM. A separate review harness
builds synthetic review reports to drive its own citation-resolution controls, and those reports carry
`path:N` strings. Most name deliberately absent paths (`nope/gone.py:12`) and land in `missing`,
which is the same bucket the existing `.rs` corpus already put `also/missing.rs:3-9` in. But
that harness plants `scripts/fsguard-scan.py:1057` four times, against a THROWAWAY repo
that creates its own one-line copy of that path -- and widening to `.py` binds those four to
granary's real 1,835-line scanner instead. They pass today. They become four findings the day
that file drops below 1,057 lines. These fixtures are not
masked: an exemption needs a positive control. If a fixture
citation fires because it collides with a real path, rename
it to a path created only in its throwaway repository.

AND THE FIXTURES MOVE THE FLOORS IN THE SAFE DIRECTION, WHICH IS WHY THEY ARE LEFT IN. They are
counted in the census: 16 of the 607 citations are synthetic strings, and
most land in `missing`, which report() SUBTRACTS. MEASURED both ways over the live corpus --
609/451 = 74.1% with them, 593/447 = 75.4% without -- so they cost 1.3 points and make the
fraction floor HARDER to clear, not easier. A census inflated by synthetic strings that tightens
the gate is a different problem from one that loosens it, and only the second would justify
narrowing the live set of files under `docs/adr/` and `scripts/`.

A FOREIGN-PATH EXEMPTION IS NOT IMPLEMENTED. A fixture or upstream
citation can collide with a real path in this tree, and the parser
cannot infer which repository the author meant. A separate marker
would need its own grammar, validation and positive controls;
treating an unverified annotation as an exemption would allow
unchecked citations to disappear from the gate. The existing freeze
marker instead requires a commit and validates the target there.

Bare `:NNN` continuations are a parser limitation that must remain explicit in its coverage claim.
When identifying affected parser behaviour here, use item names rather than unchecked coordinates:
this file is excluded from the gate's own corpus (`SELF not in f`), so the gate cannot validate
a coordinate written in this docstring against changes in its target.
Reading a continuation needs a resolver for what `:NNN` inherits -- the nearest preceding
citation on the line -- which is ambiguous when a line names two targets; three measured lines do.
These continuations are NOT read and NOT counted, so the element figure below is a FLOOR,
not a census of everything the prose cites.
Keep that under-count visible rather than presenting the element figure as complete coverage.
The command above lets a reader re-derive the continuation count.
"""
import os, re, sys, subprocess, pathlib, collections, typing

LIVE = ["docs/adr", "scripts"]
# A range may separate its endpoints with a typographic dash, including U+2013.
# Accept the dash characters in DASH as range separators so the upper endpoint is checked.
# Name the code point when describing a visually similar character; appearance alone
# cannot establish which character a parser accepts.
# This file's own prose coordinates are excluded from the gate, as the header explains.
#
# RANGE RECOGNITION AND TARGET-EXTENSION COVERAGE ARE SEPARATE REQUIREMENTS.
# Recognising a separator cannot make an excluded target extension enter the scan:
# a parser restricted to `.rs` targets cannot check a range into a `.md` file.
# An unchanged element count does not prove that both endpoints were read.
# An element is one comma-separated term, so `10-900` is one element whether the range parsed
# or the parser read only the bare `10`; that count is invariant under this parsing defect.
# Compare the parsed max() per citation to detect the missing upper endpoint.
# The measured `.rs` corpus uses only hyphens for ranges, so that cohort alone does not
# exercise typographic-dash recognition. Keep the accepted separators even when a cohort
# has no such range; the self-test must expose an upper endpoint silently left unchecked.
DASH = "\\-\u2010\u2011\u2012\u2013\u2014\u2015"
# THE SCOPE. Check citations into every extension listed in EXTS, including non-Rust files.
# The measured non-`.rs` cohort contains 188 citations and 190 line-number elements.
# A sample of four citations from that cohort found four wrong targets, yet all four line
# coordinates resolved; a bounds check alone therefore finds none of those semantic errors.
# Bounds-checking that cohort remains useful even when it produces no past-EOF finding.
# Cited text can change while its line still exists: roughly half the measured non-`.rs`
# citations name text that changed after the citation was written.
# Keep the population explicit when reporting such figures; citations, elements and changed
# target text are different quantities and cannot substitute for one another.
#
# WHAT EXTENSION COVERAGE CANNOT DO: resolving a line does not establish that its construct
# matches the citing sentence. TWO of the four sampled wrong citations are bare `:48-55`
# continuations that inherit their filename from a preceding citation, which no extension list
# reaches at all. Existence is the provable half; this gate says which half that is.
EXTS = "rs|toml|sh|py|yml|yaml|md"
# The header spells the extension list as `{EXTS}` and
# substitutes it here. Sharing that value keeps the offered
# census command aligned with the extensions the parser accepts.
__doc__ = __doc__.replace("{EXTS}", EXTS)
# A citation may carry a COMMA LIST of lines and ranges.
# Parse every comma-separated term, including each range's upper endpoint.
# Parsing only the head of the list leaves the remaining coordinates unchecked;
# the measured live set contains 19 line numbers in those continuation positions.
# A coordinate into a file absent from the published tree cannot be checked by its reader.
# A coordinate that exists can still name an assignment or comment unrelated to the claim.
# Those are separate limitations: reading every list element establishes bounds coverage,
# while identifying the intended construct still requires reading the target.
CIT = re.compile(rf'([A-Za-z0-9_/.-]*\.(?:{EXTS})):(\d+(?:[{DASH}]\d+)?(?:,\d+(?:[{DASH}]\d+)?)*)')
# THE COMMA-SPACE CONTINUATION. CIT stops at the first space,
# so a citation such as `mount.rs:351-358, 652-655, 1131-1134`
# needs CONT to read the remaining spans. Stopping after
# the head would leave those coordinates unchecked.
#
# THE KNOWN RISK, STATED RATHER THAN GUARDED, AND IT HAS TWO DIRECTIONS. A bare `,[ \t]+\d+` can
# in principle swallow prose. The LOUD direction manufactures a finding -- `a.rs:12, 2026 lines`
# reads 2026 as a line number and the gate refuses a sentence. The QUIET direction is likelier and
# easier to miss: a SMALL prose number, as in `a.rs:10, 5 more`,
# lands inside the file, produces no finding at all, and silently adds one to the element figure --
# corrupting the very disclosure it reports. Neither is guarded; both are pinned by a
# control, so the behaviour is a decision rather than an accident. MEASURED over the whole live
# set, an unbounded continuation extends exactly the nine real citations above and NOTHING else --
# zero prose matches, in either direction.
#
# The closing backtick of a citation sits where a
# comma-space continuation would start, so CONT refuses
# it; a control pins that boundary. Pairing backticks
# only within a line cannot establish Markdown inline-code
# scope: an odd tick can manufacture a span over
# prose, and a span opened on a previous line can
# leave a correctly ticked citation outside the computed
# spans. CONT therefore matches the continuation
# directly, without a backtick-span bound. A finding
# prints the FULL matched citation, continuations
# included, so a prose match is diagnosable rather
# than arriving as an unexplained past-EOF failure.
CONT = re.compile(rf',[ \t]+(\d+(?:[{DASH}]\d+)?(?:,\d+(?:[{DASH}]\d+)?)*)')
SPLIT = re.compile(f'[{DASH}]')
# git grep is POSIX ERE -- no \d, no (?:...). A separate SELECTOR picks candidate files and CIT
# parses them in Python. Keeping them apart stops a Python-only construct from silently selecting
# NOTHING, which would read as a clean run. It does NOT need the dash or comma-space forms: those
# only ever EXTEND a citation whose head already matches this, so a file holding one is selected
# either way.
SELECTOR = rf'[A-Za-z0-9_/.-]*\.({EXTS}):[0-9]+'
SHA = re.compile(r'`([0-9a-f]{7,40})`')
# The machine-readable freeze, modelled on the `<!-- cite-alias: name = path -->` marker.
# TARGET is a path, a basename, or `*`. The marker is
# syntax-agnostic because citations occur in Markdown,
# shell and Python. Restricting it to HTML comment syntax
# would exclude script comments. An explicit grammar also
# avoids deriving scope from prose that can be rephrased.
FROZEN = re.compile(r'cite-frozen:\s*(\S+?)\s*=\s*([0-9a-f]{7,40})\b')
# >>> WITHOUT AN EXPLICIT END, A FREEZE'S SCOPE IS THE REST OF THE FILE. <<<
# A marker applies forward, including to matching citations added below it later.
# A long file can therefore leave thousands of lines under a historical sha even when
# the citation that motivated the marker is far above the end of the file.
# Scope does not stop at the last citation that needs historical validation.
# Nor does a citation's validity in the current tree end the marker's scope:
# a freeze may cover citations that already fit within their current targets.
# Use an explicit terminator to end the intended scope rather than relying on either fact.
#
# THE TERMINATOR CARRIES THE SHA IT CLOSES.
# Documenting a marker must not create one: a
# bare target such as `*` can occur in prose
# explaining the grammar. The opening marker
# requires a SHA-SHAPED right-hand side that a
# placeholder cannot satisfy. The terminator
# requires one too, and names the freeze it
# closes, identifying which of several freezes
# it means. There is no wildcard close: `*` here
# is an ordinary target spelling matched against
# the opener, not a "close everything" verb.
FROZEN_END = re.compile(r'cite-frozen-end:\s*(\S+?)\s*=\s*([0-9a-f]{7,40})\b')
FENCE = re.compile(r'^\s*(```|~~~)')
SELF = "check-citations.py"
# A sentinel distinct from None: None means "the path did not exist at that sha", which is a real
# answer about a real commit. This means "I could not look".
class _Sentinel:
    """Sentinels that cannot be forged by an equal string. `n is UNREACHABLE` has to be TOTAL: if
    a re-implementation of at_sha ever returns its answer through a boundary that does not preserve
    identity -- a JSON cache, a subprocess, a double built from a literal elsewhere -- an equal
    `str` would fall through to `n >= end` and raise TypeError instead of classifying."""
    def __init__(self, n): self.n = n
    def __repr__(self): return self.n
UNREACHABLE = _Sentinel("UNREACHABLE")   # the sha is real, this clone just does not hold it
NOTACOMMIT = _Sentinel("NOTACOMMIT")     # the token is sha-SHAPED and is a commit nowhere

# The coverage floor. Not a target -- a ratchet, in the shape `check-fsguard-sites.sh` already uses
# for EXPECTED_LICENSED_SITES. Lower either number only with the reason written beside the change.
# THE `.rs` COHORT KEEPS ITS OWN FLOORS, and that is the point rather than a detail. An aggregate
# floor lets the WIDENING SUBSIDISE A REGRESSION: with the whole set at 608/74%, 22 of the
# checked `.rs` citations could go unresolved -- 251/420 = 59.8%, which fails the cohort floor -- and
# the aggregate would still read 428/608 = 70% and pass. The two are checked separately so a loss
# in the older, larger cohort cannot be paid for out of the newer one's headroom.
MIN_SEEN_RS = 380             # calibrated against a measured 422 citations; a separate
MIN_FRACTION_RS = 0.60        # measurement of the cohort gave
                              # 273/420 = 65%. At that measurement, headroom above
                              # these floors was 40 citations and 5 percentage points.
# The whole set, at the same ~10% cushion the `.rs` floors were set with (380/422 = 0.90).
MIN_SEEN = 545                # 607 measured in the calibration corpus
MIN_CHECKED_FRACTION = 0.67   # 449/607 = 0.74 measured
MIN_ELEMENTS = 575            # 642 measured
# The ELEMENT floor also splits by cohort: an aggregate floor can absorb
# losses in the `.rs` cohort using headroom from other files.
MIN_ELEMENTS_RS = 405         # calibrated against 452 `.rs` elements


def ends_of(line, m):
    """(every NUMBER the citation names, how many ELEMENTS those numbers came from,
    the citation AS WRITTEN).

    CIT stops at the first space, so the comma-SPACE continuations are read here.

    BOTH ENDS OF A RANGE ARE RETURNED, not just the last.
    Taking only `split(dash)[-1]` would read `900-10` as
    10 and leave the start unchecked in a 50-line file.
    The caller takes max() over all returned numbers.

    NUMBERS AND ELEMENTS ARE COUNTED SEPARATELY: an element is
    a comma-separated term, and a range is one element holding
    two numbers. The element count of `10-900` is one; that
    count alone cannot establish that both bounds were parsed.

    The last value is what a finding must print: `m.group(0)` covers only the head, so a finding
    triggered BY a continuation would name a line that exists and read as a gate bug."""
    def nums(spec):
        return [int(x) for t in spec.split(",") for x in SPLIT.split(t) if x]
    def nelem(spec):
        return len(spec.split(","))
    out, n, pos = nums(m.group(2)), nelem(m.group(2)), m.end()
    while True:
        c = CONT.match(line, pos)
        if not c:
            return out, n, line[m.start():pos]
        out += nums(c.group(1))
        n += nelem(c.group(1))
        pos = c.end()


def lines_of(text):
    """Line count agreeing with `wc -l`: discard the extra empty element produced by
    splitting newline-terminated text, so a citation one line past EOF cannot pass."""
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    return len(parts)


class Scan(typing.NamedTuple):
    """scan()'s result, NAMED. Positional offsets can silently select
    a different counter when fields are inserted. Named fields
    keep callers tied to the intended values without depending on
    tuple positions or the number of counters before `findings`."""
    seen: int            # citations parsed
    past: int            # past EOF, no sha in force
    frozen: int          # past EOF under a sha that VERIFIES
    ambig: int           # basename matches several tracked files
    missing: int         # matches no tracked file
    badfreeze: int       # past EOF under a sha that does NOT support it
    unverifiable: int    # past EOF under a sha this clone cannot resolve
    nread: int           # line-number ELEMENTS parsed (a range is one element)
    nskipped: int        # elements belonging to the ambig/missing/unverifiable citations
    seen_rs: int         # citations naming a `.rs` target
    unchecked_rs: int    # of those, the ones in the ambig/missing/unverifiable buckets
    nread_rs: int        # elements belonging to that cohort, floored separately
    findings: list


def scan(corpus, resolve, count, at_sha):
    """corpus: {path: [lines]}.  resolve(t) -> [paths].  count(p) -> lines.

    at_sha(sha, p) -> lines at that sha | None if the path was absent there | UNREACHABLE if the
    sha is real but this shallow clone lacks it | NOTACOMMIT if the token is a commit nowhere.
    Four distinct answers, four branches below."""
    seen = past = frozen = ambig = missing = badfreeze = unverifiable = nread = nskipped = 0
    seen_rs = unchecked_rs = nread_rs = 0
    findings = []
    for f, lines in corpus.items():
        # Fenced blocks are sample text -- a pasted backtrace or a compiler error is not a claim.
        # Not masking would make the first pasted `error[E0425] ... src/foo.rs:12` an
        # unfixable finding, and the pressure at that moment is to reach for a bogus freeze.
        infence, fenced = False, set()
        for i, l in enumerate(lines):
            if FENCE.match(l):
                infence = not infence
                fenced.add(i)
            elif infence:
                fenced.add(i)
        # A paragraph is a run of non-blank lines; a sha anywhere in it is in force for every
        # citation in it, BACKWARDS AS WELL AS FORWARDS. A sha written after a citation in
        # the same paragraph therefore applies to that citation.
        # A marker, by contrast, scopes forward only as a heading for what follows it.
        # Both directions have a control.
        para, start = {}, 0
        for i, l in enumerate(lines + [""]):
            if l.strip():
                continue
            blk = [j for j in range(start, i) if j not in fenced]
            shas = [m.group(1) for j in blk for m in SHA.finditer(lines[j])]
            for j in blk:
                para[j] = shas
            start = i + 1
        # Each declaration carries the exclusive line where its
        # scope ends. An unterminated marker extends to EOF; only
        # an explicit matching terminator shortens that scope.
        decl = []
        open_at = {}
        stray_end = []
        for i, l in enumerate(lines):
            for m in FROZEN.finditer(l):
                decl.append([i, m.group(1), m.group(2), len(lines)])
                open_at[m.group(1)] = len(decl) - 1
            for m in FROZEN_END.finditer(l):
                t, sha = m.group(1), m.group(2)
                # The TARGET and the SHA must both match the open freeze. A terminator naming a
                # different sha is closing a freeze the author has misremembered, which is worth
                # the same report as closing one that was never open.
                if t in open_at and decl[open_at[t]][2] == sha:
                    decl[open_at.pop(t)][3] = i
                else:
                    # A terminator with no open freeze means the author believes a freeze is in
                    # force that is not, which is the same misreading in the opposite direction.
                    # Reported as a FINDING rather than ignored: a silent no-op here would let an
                    # author close a scope that was never open and read the green as confirmation.
                    stray_end.append((i, t))

        def shas_for(target, i):
            out = list(para.get(i, []))
            for at, t, sha, end in decl:
                if i < at or i >= end:
                    continue
                if (t == "*" or target == t or target.endswith("/" + t)
                        or target.split("/")[-1] == t):
                    out.append(sha)
            return out

        for at, t in stray_end:
            findings.append((f, at + 1, f"cite-frozen-end: {t}", "", 0,
                             "a cite-frozen-end closes a freeze that is not open here — either "
                             "the opening `cite-frozen:` marker is missing, or it is BELOW this "
                             "line, or its target is spelled differently"))

        for i, l in enumerate(lines):
            if i in fenced:
                continue
            for m in CIT.finditer(l):
                seen += 1
                p = m.group(1)
                ends, nel, cited = ends_of(l, m)
                nread += nel
                end = max(ends)
                rs = p.endswith(".rs")
                seen_rs += rs
                nread_rs += nel * rs
                cands = resolve(p)
                if not cands:
                    missing += 1
                    nskipped += nel
                    unchecked_rs += rs
                    continue
                if len(cands) > 1:
                    ambig += 1
                    nskipped += nel
                    unchecked_rs += rs
                    continue
                if end <= count(cands[0]):
                    continue
                # Past EOF. A freeze saves it only if it VERIFIES.
                ok, blind, tried = False, False, []
                for sha in shas_for(p, i):
                    n = at_sha(sha, cands[0])
                    tried.append((sha, n))
                    if isinstance(n, _Sentinel):
                        blind = True
                        continue
                    if n is not None and end >= 1 and n >= end:
                        ok = True
                        break
                if ok:
                    frozen += 1
                    continue
                if blind:
                    unverifiable += 1
                    nskipped += nel
                    unchecked_rs += rs
                    why = "; ".join(f"`{sh}`: {nn}" for sh, nn in tried
                                    if isinstance(nn, _Sentinel))
                    remedy = ("a shallow checkout cannot run this gate honestly; give the job "
                              "`fetch-depth: 0`" if any(nn is UNREACHABLE for _, nn in tried)
                              else "that token is sha-SHAPED but is a commit nowhere — fix the "
                                   "TOKEN, not the checkout")
                    findings.append((f, i + 1, cited, cands[0], count(cands[0]),
                                     f"a sha is in force but could not be resolved ({why}) — "
                                     f"{remedy}"))
                    continue
                if tried:
                    badfreeze += 1
                    why = "; ".join(f"`{s}`: " + ("file absent there" if n is None
                                                  else f"only {n} lines there") for s, n in tried)
                    findings.append((f, i + 1, cited, cands[0], count(cands[0]),
                                     f"a sha is in force but does NOT support it ({why})"))
                else:
                    past += 1
                    findings.append((f, i + 1, cited, cands[0], count(cands[0]),
                                     "no sha is in force for it"))
    return Scan(seen, past, frozen, ambig, missing, badfreeze, unverifiable, nread, nskipped,
                seen_rs, unchecked_rs, nread_rs, findings)


def _argv_refused(args):
    """main() rejects `args` with the USAGE refusal — asserted on the TEXT, not on a rc.

    An exit-code-only assertion can pass when an unrelated
    error kills the child. Require the usage diagnostic as
    well as its status to identify the refusal under test.

    >>> AND THE CHILD IS MARKED, BECAUSE WITHOUT THAT THIS CONTROL IS A FORK BOMB. <<<
    MEASURED: with the argv guard mutated away, `--self-test --output` no longer refuses — it
    RUNS THE SELF-TEST, which reaches this helper, which spawns `--self-test --output` again.
    Hundreds of processes in seconds, from a control written to prove a guard fires. The
    marker below breaks it at depth one: a marked child skips the two argv rows and nothing
    recurses. The rows still discriminate, because the parent asserts the child REFUSED and a
    child that ran the suite instead did not.
    """
    env = dict(os.environ, CHECK_CITATIONS_ARGV_PROBE="1")
    r = subprocess.run([sys.executable, __file__, *args], capture_output=True, text=True,
                       env=env, timeout=120,
                       cwd=str(pathlib.Path(__file__).resolve().parent.parent))
    return r.returncode == 2 and "REFUSED — usage:" in (r.stderr + r.stdout)


def _venue_reaches_report():
    """Does `--output` actually reach report() as the OUTPUT venue?

    >>> THE ROWS ABOVE TEST report() AND main()'s GUARD, AND NOTHING TESTED THE WIRING
    BETWEEN THEM. <<< MEASURED: a mutant that hard-coded `venue="source"` at main's call to
    report left the whole suite green AND left the live `--output` run at rc 0 — because this
    repository's own corpus clears the SOURCE floors, so the two venues agree here and the
    mutation is invisible from inside the tree it runs in.

    `OUTPUT venue:` is printed by that branch and by nothing else, so it is the one observable
    that separates "the flag was parsed" from "the flag was acted on".
    """
    env = dict(os.environ, CHECK_CITATIONS_ARGV_PROBE="1")
    r = subprocess.run([sys.executable, __file__, "--output"], capture_output=True, text=True,
                       env=env, timeout=600,
                       cwd=str(pathlib.Path(__file__).resolve().parent.parent))
    return "OUTPUT venue:" in r.stdout


def report(s, nfiles, venue="source"):
    # `unverifiable` is subtracted like `ambig` and `missing`: a citation the gate could not look
    # at is not one it checked, and counting it inflates the very fraction the floor is computed
    # on -- so a clone that verified nothing could still clear it.
    checked = s.seen - s.ambig - s.missing - s.unverifiable
    frac = (checked / s.seen) if s.seen else 0.0
    # The checked ELEMENT count is the COMPLEMENT of the
    # skipped branches, computed from the same subtraction
    # rather than a second predicate. A unique candidate
    # alone is insufficient: an unverifiable citation
    # must not inflate the element coverage count.
    nchecked = s.nread - s.nskipped
    checked_rs = s.seen_rs - s.unchecked_rs
    frac_rs = (checked_rs / s.seen_rs) if s.seen_rs else 0.0
    print(f"== citation line-existence, live set {' '.join(LIVE)}"
          + ("" if venue == "source" else "  [OUTPUT venue]"))
    print(f"   {s.seen} `<path>:N` citations over {nfiles} files (floor {MIN_SEEN}), targets "
          f"matching {EXTS.replace('|', '/')}")
    print(f"   {s.nread} line-number ELEMENTS between them, {nchecked} on a citation that resolves")
    print("     (an element is one number or one RANGE, so this is what the parser READ — not a")
    print("      count of lines, and not everything a citation might name: see the")
    print("      shorthand-continuation limit in this file's header)")
    print(f"   {checked} resolve to exactly one tracked file and were CHECKED "
          f"({frac:.0%}, floor {MIN_CHECKED_FRACTION:.0%})")
    print(f"     of which the `.rs` cohort is {checked_rs} of {s.seen_rs} ({frac_rs:.0%}, floors "
          f"{MIN_SEEN_RS} and {MIN_FRACTION_RS:.0%}), checked SEPARATELY —")
    print("     widening the scope must not pay for a regression here out of the new headroom")
    print(f"   {s.ambig} basename matches several tracked files — UNDECIDABLE, not checked")
    print(f"   {s.missing} match no tracked file — moved, deleted, or an UPSTREAM crate's source")
    print(f"   {s.frozen} point past EOF under a sha that VERIFIES — frozen, correct as written")
    print(f"   {s.past} point past EOF with no sha in force")
    print(f"   {s.badfreeze} point past EOF under a sha that does NOT support them")
    print(f"   {s.unverifiable} point past EOF under a sha this clone does not contain")
    rc = 0
    # >>> THE OUTPUT VENUE HAS NO COVERAGE FLOORS. <<<
    # Do not give the published corpus a lower calibration of the source venue's four
    # coverage thresholds: that measures the same quantities against a smaller bar.
    # The output contract must state what the published corpus actually establishes.
    # Two properties make source-style coverage floors unsuitable here:
    #
    #   * In the measured published tree, 41 of its 67 `.rs` citations come from
    #     `check-fsguard-sites.sh` and NONE resolves, because they are expected-
    #     diagnostic strings naming temporary fixture files. A cohort fraction over a
    #     population that is three-fifths unresolvable BY CONSTRUCTION measures fixture text.
    #   * Nothing binds a floor set to the corpus it was derived from. The floors are typed
    #     constants and the corpus follows the publication selection, so a second set doubles
    #     the calibration surface. Changing which files ship can then fail published CI
    #     under a coverage diagnostic even though the parser still works.
    #
    # The OUTPUT venue requires a non-empty corpus and ZERO FINDINGS.
    # `s.findings` enforces the latter below independently of every coverage floor.
    # This checks line existence; it establishes neither coverage nor semantic correctness.
    # The parser's ability to detect faults is checked by `--self-test`, which must remain
    # in the shipping workflows; the live SOURCE run belongs to the source venue.
    if venue == "output":
        if s.seen == 0:
            print("\ncitations: FAILED — EMPTY CORPUS. The live set matched no citation at all, "
                  "which is what a gate reports when its scope has gone rather than when its "
                  "subject is clean. This venue carries no coverage floors, so this refusal is "
                  "the whole of its blindness check; the parser's own is `--self-test`.")
            rc = 1
        print(f"\n   OUTPUT venue: {s.seen} citation(s) over {nfiles} file(s), {checked} "
              f"checked. NO COVERAGE FLOOR IS APPLIED HERE and none is implied: this "
              f"establishes that no citation in this tree points past the end of its target "
              f"and that the corpus is not empty. It does NOT establish coverage, that the "
              f"cited coordinates name what their sentences claim, or that anything survived "
              f"an export intact.")
    elif s.seen < MIN_SEEN or frac < MIN_CHECKED_FRACTION:
        print(f"\ncitations: FAILED — COVERAGE COLLAPSE. Saw {s.seen} (floor {MIN_SEEN}) and checked "
              f"{frac:.0%} (floor {MIN_CHECKED_FRACTION:.0%}). A gate whose scope has quietly gone "
              f"to nothing reports green; this refuses instead. If the drop is intended, move the "
              f"floor in the same commit and say why.")
        rc = 1
    # THE `.rs` COHORT FLOOR. Separate from the aggregate above for the reason written beside the
    # constants: an aggregate floor is satisfiable by growth elsewhere, so it cannot protect the
    # cohort that was being checked before the scope widened.
    if venue == "source" and (s.seen_rs < MIN_SEEN_RS or frac_rs < MIN_FRACTION_RS):
        print(f"\ncitations: FAILED — `.rs` COHORT COLLAPSE. Saw {s.seen_rs} `.rs` citations "
              f"(floor {MIN_SEEN_RS}) and checked {frac_rs:.0%} (floor {MIN_FRACTION_RS:.0%}). "
              f"The aggregate above can stay healthy while this cohort rots, because widening the "
              f"scope added headroom it could be paid out of. Move this floor in the same commit "
              f"and say why.")
        rc = 1
    # THE ELEMENT FLOOR. Without it the element figure is printed and never checked, which is the
    # defect the citation floor above exists to refuse, one line lower down. It catches what the
    # citation count cannot: if the live set's continuations change shape -- a list wrapped across
    # two lines, a `;` separator -- the parser silently returns to reading heads only, `seen` does
    # not move, and every other number stays green.
    if venue == "source" and s.nread_rs < MIN_ELEMENTS_RS:
        print(f"\ncitations: FAILED — `.rs` ELEMENT COLLAPSE. Read {s.nread_rs} elements from the "
              f"`.rs` cohort (floor {MIN_ELEMENTS_RS}). `seen_rs` and its fraction do not move when "
              f"the parser stops reading the elements INSIDE those citations, and the aggregate "
              f"element floor can absorb losses in this cohort. Hence a floor per cohort.")
        rc = 1
    if venue == "source" and s.nread < MIN_ELEMENTS:
        print(f"\ncitations: FAILED — ELEMENT COLLAPSE. Read {s.nread} line-number elements "
              f"(floor {MIN_ELEMENTS}) from {s.seen} citations. The citation count can hold still "
              f"while the parser quietly stops reading the elements inside them; that is the whole "
              f"reason this figure is separate. Move the floor in the same commit and say why.")
        rc = 1
    if s.findings:
        print()
        for f, i, c, t, n, why in s.findings:
            print(f"   {f}:{i}: `{c}` — {t} is {n} lines, and {why}. Either the sentence names a "
                  f"CURRENT location and the citation is re-pointed BY ITEM NAME, or it reports a "
                  f"PAST event and takes a sha at which the file HAD that line. The "
                  f"exemption is per citation and it must VERIFY — see this file's header.")
        print(f"\ncitations: FAILED — {s.past + s.badfreeze + s.unverifiable} citation(s) past the "
              f"end of their own target ({s.past} unfrozen, {s.badfreeze} under a sha that does not "
              f"support them, {s.unverifiable} under a sha this clone does not contain)")
        rc = 1
    if rc == 0:
        print("citations: ALL GREEN")
    return rc


def quiet(fn):
    """Run fn with stdout swallowed -- a control that prints the gate's whole report is unreadable."""
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        return fn()


FIND = ("f", 1, "a.rs:9", "a.rs", 2, "a reason")


def healthy(**kw):
    """A HEALTHY Scan, overridden by keyword. A control says what it is about and nothing else,
    so a new field cannot shift an unrelated row's meaning."""
    base = dict(seen=MIN_SEEN, past=0, frozen=0, ambig=0, missing=0, badfreeze=0, unverifiable=0,
                nread=MIN_ELEMENTS, nskipped=0, seen_rs=MIN_SEEN_RS, unchecked_rs=0,
                nread_rs=MIN_ELEMENTS_RS, findings=[])
    base.update(kw)
    return Scan(**base)


def _git_grep_probe(ext):
    """True when `git grep -E SELECTOR` matches a synthetic citation with this extension."""
    import tempfile, os
    d = tempfile.mkdtemp()
    try:
        f = os.path.join(d, "probe.txt")
        pathlib.Path(f).write_text(f"see a/b/probe.{ext}:12 here\n")
        # Run Git with `-C <dir>`: `git grep --no-index` can refuse
        # a path outside the current repository. The probe must
        # run from its scratch directory to test the pattern.
        #
        # THROUGH `git_at`: a malformed caller configuration
        # can make Git exit nonzero and turn an environment
        # failure into an apparent SELECTOR mismatch.
        # The hermetic wrapper excludes global and system
        # configuration for this probe, matching the
        # isolation used by the other fixture commands.
        return git_at(d)("grep", "--no-index", "-qE", SELECTOR, "--", "probe.txt",
                         check=False) is not None
    finally:
        __import__("shutil").rmtree(d, ignore_errors=True)


def cited_by(r):
    """The citation text of r's first finding, or a sentinel. Returning a string rather than
    raising keeps a row that loses its finding a FAIL instead of a traceback that swallows every
    control after it."""
    return r.findings[0][2] if r.findings else "<NO FINDING AT ALL>"


def report_line(s):
    """report()'s ELEMENT line, captured. The floors are checked by exit code, but the figure
    itself is only ever printed -- so the one row that asserts its VALUE has to read the text."""
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        report(s, 1)
    return next((l.strip() for l in buf.getvalue().split("\n") if "ELEMENTS between them" in l),
                "<THE ELEMENT LINE IS NOT PRINTED AT ALL>")


def history_conditions():
    """>>> THE REPOSITORY STATES `at_sha` HAS TO TELL APART, BUILT RATHER THAN BORROWED. <<<

    Returns {name: answer}, each answer produced by the REAL `history()` bound to a repository
    this function constructed. Nothing here reads this clone's own history. SIX conditions over
    FOUR repositories -- the first answers two of them and the replace fixture answers two.

    Construct the repositories instead of borrowing this checkout's
    commits. A control whose expected history state is computed
    by `at_sha` would let the function under test decide its
    own expected answer. That circular expectation cannot
    distinguish an implementation that always returns the same
    state. Fixture commits and clone depth establish the
    expected states independently of the function being checked.

    The fixtures also make the self-test independent of development
    history: a published repository may lack every development
    commit while still needing to test all history states.

    The CI checkouts that run this gate use `fetch-depth: 0`,
    so the shallow arm is not reached there. The constructed
    depth-one clone exercises that state explicitly.
    """
    import shutil, tempfile
    def commit(g, msg):
        """A fixture commit whose IDENTITY is passed per invocation rather than written into
        the fixture's config -- the pattern three other
        gates here follow.

        The `git_at` wrapper defaults to `hermetic=True`,
        excluding the global and system configuration
        for fixtures. This helper supplies the commit
        identity per invocation; configuration isolation
        depends on the git callable passed in."""
        # Identity is per invocation; the hermetic wrapper excludes
        # global and system configuration for the fixture commands.
        g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", msg)
    d = tempfile.mkdtemp()
    try:
        full = os.path.join(d, "full")
        os.makedirs(full)
        g = git_at(full)
        g("init", "-q", ".")
        pathlib.Path(full, "f.txt").write_text("1\n2\n3\n")
        g("add", "-A"); commit(g, "one")
        old = (g("rev-parse", "HEAD") or "").strip()
        # A SECOND commit, so a depth-1 clone below genuinely lacks `old`. With one commit the
        # shallow clone would still contain it and that row would pass for the wrong reason.
        pathlib.Path(full, "g.txt").write_text("x\n")
        os.remove(os.path.join(full, "f.txt"))
        g("add", "-A"); commit(g, "two")

        bare = os.path.join(d, "nohistory")
        os.makedirs(bare)
        gb = git_at(bare)
        gb("init", "-q", ".")
        pathlib.Path(bare, "z.txt").write_text("z\n")
        gb("add", "-A"); commit(gb, "import")

        shal = os.path.join(d, "shallow")
        # The clone uses the hermetic wrapper. A failing global
        # `post-checkout` hook or `protocol.file.allow=never`
        # can make a fixture clone fail before it yields a
        # history state; excluding the configuration files
        # closes both paths, rather than overriding one key.
        git_at()("clone", "-q", "--depth", "1", "file://" + full, shal)

        # A REPLACED COMMIT tests `--no-replace-objects`. A
        # `refs/replace/<oid>` entry substitutes another tree
        # under the same commit id; counting that replacement's
        # lines would validate the wrong historical contents.
        repl = os.path.join(d, "replaced")
        os.makedirs(repl)
        gr = git_at(repl)
        gr("init", "-q", ".")
        pathlib.Path(repl, "f.txt").write_text("1\n2\n3\n")
        gr("add", "-A"); commit(gr, "r-one")
        r_old = (gr("rev-parse", "HEAD") or "").strip()
        pathlib.Path(repl, "f.txt").write_text("1\n2\n3\n4\n5\n6\n7\n8\n")
        gr("add", "-A"); commit(gr, "r-two")
        gr("replace", "-f", r_old, (gr("rev-parse", "HEAD") or "").strip())
        at_repl, _ = history(git_at(repl))
        # Check the OTHER DIRECTION too: read the same commit
        # without the flag and require the substitute's
        # eight lines. If the replacement was never installed,
        # this reads three lines instead; the pair
        # establishes that the perturbation actually landed.
        # Use the SAME wrapper with replacement enabled. A separate
        # environment setup could drift from `git_at` and leave
        # this fixture exposed to caller configuration.
        # `replace_objects=True` switches only the replacement flag.
        _unflagged = git_at(repl, replace_objects=True)("show", f"{r_old}:f.txt", check=False)

        at_full, shallow_full = history(git_at(full))
        at_none, _ = history(git_at(bare))
        at_shal, shallow_shal = history(git_at(shal))
        return {
            "present": at_full(old, "f.txt"),
            "absent-there": at_full(old, "g.txt"),
            "full-lacks-it": at_none(old, "f.txt"),
            "shallow-lacks-it": at_shal(old, "f.txt"),
            "full-is-not-shallow": shallow_full(),
            "shallow-is-shallow": shallow_shal(),
            # 3, not 8: the replacement's tree must not be what a freeze is verified against.
            "replace-ignored": at_repl(r_old, "f.txt"),
            # 8: the replace ref really is in force for a reader that does not disable it.
            "replace-in-force": lines_of(_unflagged) if _unflagged is not None else -1,
        }
    finally:
        shutil.rmtree(d, ignore_errors=True)


def git_dir_is_ignored():
    """True when a hostile `GIT_DIR` does NOT redirect `git_at(root)`.

    The wrapper owns the environment scrub, so test
    it directly. A hostile `GIT_DIR` must not redirect
    commands away from the scratch repository even
    when a working directory is also supplied.
    """
    import shutil, tempfile
    d = tempfile.mkdtemp()
    try:
        scratch, hostile = os.path.join(d, "scratch"), os.path.join(d, "hostile")
        os.makedirs(scratch); os.makedirs(hostile)
        git_at(scratch)("init", "-q", ".")
        git_at(hostile)("init", "-q", ".")
        saved = os.environ.get("GIT_DIR")
        os.environ["GIT_DIR"] = os.path.join(hostile, ".git")
        try:
            seen = (git_at(scratch)("rev-parse", "--absolute-git-dir") or "").strip()
        finally:
            if saved is None:
                os.environ.pop("GIT_DIR", None)
            else:
                os.environ["GIT_DIR"] = saved
        # Compared with realpath on both sides: the temp root is a symlink on macOS and a raw
        # string compare would pass this row for the wrong reason on one platform and fail it on
        # the other.
        return os.path.realpath(seen) == os.path.realpath(os.path.join(scratch, ".git"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def hermetic_ignores_the_global_config():
    """(non-hermetic answer, hermetic answer) for a key planted in a hostile `$HOME/.gitconfig`.

    `HOME` is not a `GIT_*` variable, so the scrub does not
    touch it. This fixture plants `protocol.file.allow=never`
    in a hostile global config and checks that hermetic
    commands ignore it while non-hermetic commands see it.

    Two directions in one row: WITHOUT `hermetic` the child must SEE `never`, or the fixture is
    not hostile and the other half proves nothing; WITH it the child must see nothing at all.
    """
    import shutil, tempfile
    d = tempfile.mkdtemp()
    try:
        home, scratch = os.path.join(d, "home"), os.path.join(d, "scratch")
        os.makedirs(home); os.makedirs(scratch)
        pathlib.Path(home, ".gitconfig").write_text('[protocol "file"]\n\tallow = never\n')
        git_at(scratch)("init", "-q", ".")
        saved = os.environ.get("HOME")
        os.environ["HOME"] = home
        try:
            exposed = git_at(scratch, hermetic=False)("config", "--get",
                                                      "protocol.file.allow", check=False)
            closed = git_at(scratch)("config", "--get", "protocol.file.allow", check=False)
        finally:
            if saved is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = saved
        return ((exposed or "").strip(), (closed or "").strip())
    finally:
        shutil.rmtree(d, ignore_errors=True)


def self_test(real):
    """Controls: drive `scan` on an in-memory corpus and probe resolution,
    counting, history and selection through the repository-backed implementations.
    Stubbing those implementations would not test their actual behavior."""
    SIZES = {"a/b/small.rs": 50, "a/b/big.rs": 5000, "x/dup.rs": 10, "y/dup.rs": 10,
             # One target per widened extension. `.yaml` contributes ZERO citations to the live
             # set, so the corpus is the only place its support can be shown at all -- a live
             # census cannot prove an extension nothing currently uses.
             "a/b/conf.toml": 40, "a/b/run.sh": 40, "a/b/tool.py": 40,
             "a/b/flow.yml": 40, "a/b/flow2.yaml": 40, "a/b/doc.md": 40}
    def resolve(t):
        return [t] if t in SIZES else [k for k in SIZES if k.split("/")[-1] == t.split("/")[-1]]
    def count(p):
        return SIZES[p]
    COMMITS = {"abc1234": 9000, "dec0de5": 20, "fade123": None}   # None = path absent THERE
    def at_sha(sha, p):
        # Mirrors build()'s at_sha exactly: is it a commit here? then is the path in it?
        if sha == "fee1dad":
            return UNREACHABLE          # a real sha this (shallow) clone lacks
        if sha not in COMMITS:
            return NOTACOMMIT           # sha-SHAPED, a commit nowhere
        return COMMITS[sha]
    ROWS = [
        ("past EOF with no sha is FOUND",
         ["see `a/b/small.rs:900`"],                                (1, 1, 0, 0, 0, 0, 0, 1)),
        ("inside the file is not flagged",
         ["see `a/b/small.rs:40`"],                                 (1, 0, 0, 0, 0, 0, 0, 1)),
        ("a VERIFYING sha in the paragraph freezes it",
         ["read at `abc1234`;", "see `a/b/small.rs:900`"],          (1, 0, 1, 0, 0, 0, 0, 1)),
        ("a sha that is TOO SHORT there does NOT freeze it",
         ["read at `dec0de5`;", "see `a/b/small.rs:900`"],          (1, 0, 0, 0, 0, 1, 0, 1)),
        ("a sha where the file is ABSENT does NOT freeze it",
         ["read at `fade123`;", "see `a/b/small.rs:900`"],         (1, 0, 0, 0, 0, 1, 0, 1)),
        ("a sha NOT IN THIS CLONE is its own answer, and it REFUSES",
         ["read at `fee1dad`;", "see `a/b/small.rs:900`"],         (1, 0, 0, 0, 0, 0, 1, 1)),
        # A sha-SHAPED token that is a commit NOWHERE lands in the same refusing bucket as a sha
        # this clone lacks -- both mean "could not resolve the freeze" -- but the MESSAGE differs,
        # and that is the half worth having: one says fix the checkout, the other says fix the
        # token. the control named "at_sha() calls a sha-shaped non-commit NOTACOMMIT in a full
        # clone" pins which answer at_sha gives -- BY NAME, because this pointer said "control 29"
        # until seven rows were inserted above it and moved that control to 36, inside the one file
        # this gate structurally excludes from its own scope.
        ("a sha-SHAPED byte count does not freeze anything",
         ["the cap is `1048576` bytes;", "see `a/b/small.rs:900`"], (1, 0, 0, 0, 0, 0, 1, 1)),
        ("a sha in a DIFFERENT paragraph does not reach it",
         ["read at `abc1234`;", "", "see `a/b/small.rs:900`"],      (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a sha BELOW the citation in the same paragraph DOES reach it",
         ["see `a/b/small.rs:900`, read at `abc1234`"],             (1, 0, 1, 0, 0, 0, 0, 1)),
        ("a cite-frozen marker ABOVE it freezes it",
         ["<!-- cite-frozen: small.rs = abc1234 -->", "",
          "see `a/b/small.rs:900`"],                                (1, 0, 1, 0, 0, 0, 0, 1)),
        ("a cite-frozen marker BELOW it does NOT — marker scope runs forward",
         ["see `a/b/small.rs:900`", "",
          "<!-- cite-frozen: small.rs = abc1234 -->"],              (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a marker for a DIFFERENT target does not freeze this one",
         ["<!-- cite-frozen: big.rs = abc1234 -->", "",
          "see `a/b/small.rs:900`"],                                (1, 1, 0, 0, 0, 0, 0, 1)),
        ("`*` freezes every target, but still only if the sha VERIFIES",
         ["<!-- cite-frozen: * = dec0de5 -->", "",
          "see `a/b/small.rs:900`"],                                (1, 0, 0, 0, 0, 1, 0, 1)),
        # ---- the SCOPE TERMINATOR. Without these rows the grammar is an assertion.
        ("a cite-frozen-end CLOSES the scope, so a citation below it is NOT frozen",
         ["<!-- cite-frozen: small.rs = abc1234 -->", "",
          "<!-- cite-frozen-end: small.rs = abc1234 -->", "",
          "see `a/b/small.rs:900`"],                                (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a citation BETWEEN the marker and its end IS still frozen — the control for the control",
         ["<!-- cite-frozen: small.rs = abc1234 -->", "",
          "see `a/b/small.rs:900`", "",
          "<!-- cite-frozen-end: small.rs = abc1234 -->"],                    (1, 0, 1, 0, 0, 0, 0, 1)),
        ("an end for a DIFFERENT target does not close this freeze",
         ["<!-- cite-frozen: small.rs = abc1234 -->", "",
          "<!-- cite-frozen-end: big.rs = abc1234 -->", "",
          "see `a/b/small.rs:900`"],                                (1, 0, 1, 0, 0, 0, 0, 1)),
        ("a `*` freeze is closed by naming `*` and its sha — `*` is a target, not a verb",
         ["<!-- cite-frozen: * = abc1234 -->", "",
          "<!-- cite-frozen-end: * = abc1234 -->", "",
          "see `a/b/small.rs:900`"],                                (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a terminator naming the right target but the WRONG sha does not close it",
         ["<!-- cite-frozen: small.rs = abc1234 -->", "",
          "<!-- cite-frozen-end: small.rs = dec0de5 -->", "",
          "see `a/b/small.rs:900`"],                                (1, 0, 1, 0, 0, 0, 0, 1)),
        # A terminator with nothing open is the same misreading in the other direction: the
        # author believes a freeze is in force. It is a FINDING, so `past` stays 1 AND the
        # finding count rises -- the row below pins the finding, this one pins the classification.
        ("a cite-frozen-end with no open freeze does not accidentally freeze anything",
         ["<!-- cite-frozen-end: small.rs = abc1234 -->", "",
          "see `a/b/small.rs:900`"],                                (1, 1, 0, 0, 0, 0, 0, 1)),
        # >>> DOCUMENTING THE GRAMMAR MUST NOT INVOKE IT. <<< The opening marker is already
        # immune because `<sha>` is not sha-shaped; the terminator has no sha, so its TARGET
        # pattern carries the immunity instead and refuses a token starting with `<`.
        ("prose explaining the syntax as `cite-frozen-end: <target> = <sha>` is INERT",
         ["<!-- cite-frozen: small.rs = abc1234 -->", "",
          "write `cite-frozen-end: <target> = <sha>` to close it", "",
          "see `a/b/small.rs:900`"],                                (1, 0, 1, 0, 0, 0, 0, 1)),
        ("and prose naming `*` is inert too",
         ["<!-- cite-frozen: small.rs = abc1234 -->", "",
          "or `cite-frozen-end: * = <sha>` for a wildcard freeze", "",
          "see `a/b/small.rs:900`"],                                (1, 0, 1, 0, 0, 0, 0, 1)),
        ("a marker in a SHELL comment works (no HTML comments in .sh)",
         ["# cite-frozen: small.rs = abc1234", "",
          "see `a/b/small.rs:900`"],                                (1, 0, 1, 0, 0, 0, 0, 1)),
        ("an END-of-range past EOF is caught, not just the start",
         ["see `a/b/small.rs:40-900`"],                             (1, 1, 0, 0, 0, 0, 0, 1)),
        # A TRANSPOSED range. Taking only the last number of a range made `900-10` report 10, which
        # a 50-line file swallows -- and the dash class had just added six more ways to spell one.
        ("a REVERSED range is caught on its start, which is the end nobody reads",
         ["see `a/b/small.rs:900-10`"],                             (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a reversed DASHED range is caught the same way",
         ["see `a/b/small.rs:900\u201310`"],                        (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a COMMA LIST checks every element, not just the head",
         ["see `a/b/small.rs:10,900,2000`"],                        (1, 1, 0, 0, 0, 0, 0, 3)),
        # The comma-SPACE form. Nine citations in the live set are written this way and the parser
        # stopped at the first space, so every element after the head went unchecked. The first row
        # is the defect; the second reads a longer list, because a fix that stopped after one
        # continuation would satisfy the first and still drop everything past it.
        ("a COMMA-SPACE list checks every element too",
         ["see `a/b/small.rs:10, 900`"],                            (1, 1, 0, 0, 0, 0, 0, 2)),
        ("a COMMA-SPACE list reads ALL its elements, not just the second",
         ["see `a/b/small.rs:10, 20, 900`"],                        (1, 1, 0, 0, 0, 0, 0, 3)),
        # A list can resume the no-space form after a
        # comma-space element. CONT must capture the full resumed
        # list, so `10, 20,30` includes 30 as well as 20.
        ("a list that RESUMES without a space after a comma-space element is still fully read",
         ["see `a/b/small.rs:10, 20,900`"],                         (1, 1, 0, 0, 0, 0, 0, 3)),
        # THE DISCLOSED RISK, PINNED AS BEHAVIOUR. There is no backtick bound: a continuation is
        # read wherever it sits. Measured over the whole live set an unbounded continuation extends
        # exactly the nine real citations and no prose, but this row states what would happen if a
        # sentence ever did have the shape, so the behaviour is a decision and not an accident.
        ("a continuation is read with NO backticks around it, which is the documented risk",
         ["see a/b/small.rs:10, 900 of them"],                      (1, 1, 0, 0, 0, 0, 0, 2)),
        # The QUIET half of that risk: a small prose number lands INSIDE the file, so it raises the
        # element figure and produces no finding. Pinned so the behaviour is chosen, not stumbled
        # into -- the quiet half is the easier one to miss.
        ("a SMALL prose number is swallowed silently, raising the element count and nothing else",
         ["see a/b/small.rs:10, 5 more"],                           (1, 0, 0, 0, 0, 0, 0, 2)),
        # A range separated by U+2013 must include its upper endpoint in the bounds check.
        # A hyphen-only class can read just the start line and silently leave the other end unchecked.
        ("an EN DASH range is a range, not a bare start line",
         ["see `a/b/small.rs:10–900`"],                        (1, 1, 0, 0, 0, 0, 0, 1)),
        ("an EM DASH range is read the same way",
         ["see `a/b/small.rs:10—900`"],                        (1, 1, 0, 0, 0, 0, 0, 1)),
        # GREEN-ONLY BY CONSTRUCTION, and recorded as such: revert the DASH class and this row's
        # input degenerates to a bare `a/b/small.rs:10` with a byte-identical expected tuple, so it
        # passes for a different input than its name names. Its red sibling above carries the proof.
        ("a dashed range wholly INSIDE the file is still not flagged",
         ["see `a/b/small.rs:10–40`"],                         (1, 0, 0, 0, 0, 0, 0, 1)),
        ("a citation inside a FENCE is sample text, not a claim",
         ["```", "error at `a/b/small.rs:900`", "```"],             (0, 0, 0, 0, 0, 0, 0, 0)),
        ("an AMBIGUOUS basename is reported, never counted clean",
         ["see `dup.rs:900`"],                                      (1, 0, 0, 1, 0, 0, 0, 1)),
        ("an UNRESOLVABLE target is reported, never counted clean",
         ["see `upstream/aws/builder.rs:900`"],                     (1, 0, 0, 0, 1, 0, 0, 1)),
        # THE WIDENING, one row per extension. Each drives the whole path -- CIT parses it,
        # resolve() finds it, and the bound is enforced -- so a future narrowing of EXTS turns
        # each admitted extension's row red by name rather than dropping coverage quietly.
        ("a `.toml` citation past EOF is FOUND, not skipped as a non-source",
         ["see `a/b/conf.toml:900`"],                               (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a `.sh` citation past EOF is FOUND",
         ["see `a/b/run.sh:900`"],                                  (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a `.py` citation past EOF is FOUND",
         ["see `a/b/tool.py:900`"],                                 (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a `.yml` citation past EOF is FOUND",
         ["see `a/b/flow.yml:900`"],                                (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a `.yaml` citation past EOF is FOUND, though the live set has none to prove it with",
         ["see `a/b/flow2.yaml:900`"],                              (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a `.md` citation past EOF is FOUND",
         ["see `a/b/doc.md:900`"],                                  (1, 1, 0, 0, 0, 0, 0, 1)),
        ("a widened citation INSIDE its file is not flagged, so the rows above are not just noise",
         ["see `a/b/conf.toml:20` and `a/b/doc.md:20`"],            (2, 0, 0, 0, 0, 0, 0, 2)),
        ("a widened target resolves by BASENAME too, not only by full path",
         ["see `conf.toml:900`"],                                   (1, 1, 0, 0, 0, 0, 0, 1)),
        ("an extension NOT in the set is still invisible — the scope is a list, not everything",
         ["see `a/b/thing.txt:900`, `a/b/thing.json:900`"],         (0, 0, 0, 0, 0, 0, 0, 0)),
        ("a citation in the LAST paragraph is scanned (no trailing blank line)",
         ["intro", "", "see `a/b/small.rs:900`"],                   (1, 1, 0, 0, 0, 0, 0, 1)),
    ]
    npass = nfail = 0
    for i, (name, lines, want) in enumerate(ROWS, 1):
        got = scan({"t.md": lines}, resolve, count, at_sha)[:8]
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} {i:2d} - {name}")
        if not ok:
            print(f"        wanted (seen,past,frozen,ambig,missing,badfreeze,unverifiable,nread)={want}, got {got}")
        npass += ok; nfail += not ok

    # --- the layers an in-memory corpus cannot reach -------------------------------------------
    R = real()
    upstream = scan({"t.md": ["see `crates/granary-cli/src/attach/control/client.rs:1`, "
                              "`attach/control/client.rs:1` and `upstream/h2/src/client.rs:900`"]},
                    R["resolve"], R["count"], R["at_sha"])
    resolution = (upstream.seen, upstream.past, upstream.missing, upstream.nread,
                  upstream.nskipped, upstream.findings)
    # Build the history fixtures once: repository
    # creation and commits are shared by the
    # controls, and repeating that work per row
    # would not change their expected answers.
    HC = history_conditions()
    HERM = hermetic_ignores_the_global_config()
    n = len(ROWS)
    checks = [
        # The rows above compare counters rather than diagnostic
        # contents. Stray terminators and prose immunity need
        # direct checks of `findings`: a parser that treats
        # grammar documentation as a marker can create a diagnostic
        # without changing the counters those rows assert.
        ("a cite-frozen-end with no open freeze is REPORTED, not silently ignored",
         len([x for x in scan({"t.md": ["<!-- cite-frozen-end: small.rs = abc1234 -->", "",
                                        "see `a/b/small.rs:900`"]},
                              resolve, count, at_sha).findings
              if "cite-frozen-end" in x[2]]) == 1),
        ("a MATCHED terminator reports nothing — the control for the control",
         len([x for x in scan({"t.md": ["<!-- cite-frozen: small.rs = abc1234 -->", "",
                                        "<!-- cite-frozen-end: small.rs = abc1234 -->"]},
                              resolve, count, at_sha).findings
              if "cite-frozen-end" in x[2]]) == 0),
        ("prose writing `cite-frozen-end: <target>` reports nothing — documenting is not invoking",
         len([x for x in scan({"t.md": ["write `cite-frozen-end: <target> = <sha>` to close a freeze"]},
                              resolve, count, at_sha).findings
              if "cite-frozen-end" in x[2]]) == 0),
        ("count() agrees with `wc -l` on a real file",
         R["count"]("scripts/check-citations.py") == R["wc"]("scripts/check-citations.py")),
        ("count() is not off by one on a newline-terminated file", lines_of("a\nb\n") == 2),
        ("lines_of handles a file with no trailing newline", lines_of("a\nb") == 2),
        ("resolve() finds a uniquely-named real source file",
         R["resolve"]("check-citations-nosuch.rs") == []
         and R["resolve"]("crates/granary-cli/src/main.rs") == ["crates/granary-cli/src/main.rs"]),
        ("resolve() reports a DUPLICATED basename as several, never picks one",
         len(R["resolve"]("tests.rs")) > 1),
        ("resolve() leaves a path-qualified UPSTREAM citation MISSING beside exact/suffix matches "
         f"(seen,past,missing,elements,skipped,findings)={resolution}",
         resolution == (3, 0, 1, 3, 1, [])),
        ("SELECTOR matches a real citation string",
         re.search(SELECTOR, "see `crates/granary-cli/src/main.rs:56` here") is not None),
        # SELECTOR is handed to `git grep -E`, which is POSIX ERE -- a Python-only construct here
        # would select NOTHING and read as a clean run. Every admitted extension is checked
        # against the REAL git, not against Python's re.
        ("SELECTOR selects every admitted extension under a POSIX ERE engine, not just Python's",
         all(R["ere_selects"](e) for e in EXTS.split("|"))),
        ("and it selects nothing outside the set, so that row is a discriminator",
         not any(R["ere_selects"](e) for e in ("txt", "json", "lock", "rsx"))),
        # >>> BOTH BASENAME EXPECTATIONS MUST HOLD IN THE PUBLISHED TREE. <<<
        # A real-file resolution control depends on which files are tracked in its venue.
        # Do not require a private workflow driver that does not ship.
        # Its absence from the published tree does not establish a resolver failure.
        # Both filenames below must name shipping inputs whose presence the control can require.
        # The assertions use `clippy.toml` and `deny.core.toml`, each at the repository root.
        # Removing either input changes the premise of this control and requires checking it.
        # Keep the expected paths literal so the resolver cannot supply its own expected answer.
        # For historical states, build the repository state needed by the control rather than
        # depending on a real commit that the published clone need not contain.
        ("resolve() finds a real non-.rs file by basename, which the index had to widen for",
         R["resolve"]("clippy.toml") == ["clippy.toml"]
         and R["resolve"]("deny.core.toml") == ["deny.core.toml"]),
        # Construct the history conditions in scratch
        # repositories. Each row names an expected answer
        # established by its fixture rather than by `at_sha`
        # itself. A constant implementation cannot satisfy
        # the different expected states. `history_conditions()`
        # supplies those states without requiring
        # development commits in this checkout.
        # THE SCRUB. Without it every row above still passes while the fixtures write into
        # whatever `GIT_DIR` names -- the failure is invisible to the answers, so it needs a row
        # about the mechanism rather than about the results.
        ("git_at() ignores a hostile GIT_DIR, so a fixture cannot write into another repository",
         git_dir_is_ignored()),
        # The scrub drops `GIT_CONFIG_GLOBAL` with everything else `GIT_*`, which GUARANTEES the
        # child reads the real `$HOME/.gitconfig` -- the opposite of what a fixture wants.
        ("a hostile global config reaches a non-hermetic child and NOT a hermetic one",
         HERM == ("never", "")),
        ("at_sha() gives the line count where the repository HAS the sha and the path was there",
         HC["present"] == 3),
        ("at_sha() gives None where the repository HAS the sha and the path was NOT there",
         HC["absent-there"] is None),
        # A repository with one import commit is full, even
        # when it contains none of the development history.
        # The missing-commit control must handle that state.
        ("at_sha() calls a sha a FULL repository does not contain NOTACOMMIT",
         HC["full-lacks-it"] is NOTACOMMIT),
        # The CI checkouts running this gate use `fetch-depth: 0`; a
        # constructed shallow clone exercises the arm they do not reach.
        ("at_sha() calls that same sha UNREACHABLE in a SHALLOW clone that lacks it",
         HC["shallow-lacks-it"] is UNREACHABLE),
        # The discriminator between the two rows above is `is_shallow`, so it needs its own
        # witness in both directions or those rows agree for a reason nothing checked.
        ("is_shallow() is False in a full repository", HC["full-is-not-shallow"] is False),
        ("is_shallow() is True in a shallow clone", HC["shallow-is-shallow"] is True),
        # A freeze is verified by COUNTING the bytes `git show <sha>:<path>` returns, so a
        # replace ref that swaps the tree under an unchanged commit id changes the verdict
        # silently. 3 is the real tree; 8 is the replacement's.
        ("at_sha() reads the REAL tree of a commit that carries a replace ref, not the substitute",
         HC["replace-ignored"] == 3),
        ("and the replace ref IS in force for a reader that does not disable it, so the row above "
         "is not certifying an empty fixture",
         HC["replace-in-force"] == 8),
        # In a FULL clone a sha-shaped non-commit is NOTACOMMIT, because the remedy is to fix the
        # token. In a SHALLOW one the gate cannot tell the two apart and says UNREACHABLE, whose
        # remedy is to deepen the checkout. Both are right; asserting one unconditionally is not.
        ("at_sha() calls a sha-shaped non-commit NOTACOMMIT in a full clone, UNREACHABLE in a shallow one",
         R["at_sha"]("dddddddd", "README.md") is (UNREACHABLE if R["shallow"]() else NOTACOMMIT)),
        # Adding an extension to EXTS supplies selector and basename
        # coverage, but scan() coverage also needs a SIZES target and
        # a ROWS fixture. This assertion makes a missing fixture
        # visible instead of leaving an admitted extension untested.
        ("every admitted extension has a target in the self-test corpus",
         {e for e in EXTS.split("|")} ==
         {k.rsplit(".", 1)[-1] for k in SIZES}),
        ("the live scope selects a non-empty file set", R["nfiles"] > 0),
        # THE FINDING MUST NAME THE CITATION AS WRITTEN. ROWS compares COUNTS, so nothing there can
        # see the finding's text -- and a finding triggered by a continuation that printed only
        # `m.group(0)` would name `a/b/small.rs:10`, a line that exists in a 50-line file, and read
        # as a gate bug rather than a citation defect.
        # The report subtracts nskipped from the element count,
        # so that counter needs its own witness: two citations
        # with 3 + 1 elements, only the first resolving.
        # The cohort tallies need a witness in scan(), not only in report(): the floors above are
        # driven by hand-built Scans, so a scan() that stopped counting the cohort would leave
        # every one of them green while the live run's cohort line silently went to zero.
        ("scan() splits the `.rs` cohort out of a mixed corpus",
         (lambda r: r.seen == 3 and r.seen_rs == 2)(
             scan({"t.md": ["`a/b/small.rs:1`", "`a/b/conf.toml:1`", "`a/b/big.rs:1`"]},
                  resolve, count, at_sha))),
        ("scan() records an UNRESOLVABLE `.rs` citation as unchecked in the cohort",
         (lambda r: r.seen_rs == 1 and r.unchecked_rs == 1)(
             scan({"t.md": ["`nowhere/at/all.rs:1`"]}, resolve, count, at_sha))),
        # Every unchecked cohort branch needs a witness. Missing,
        # ambiguous and unverifiable citations must all increment
        # `unchecked_rs`; losing any increment inflates the reported
        # checked fraction. These rows check the branches separately.
        ("an AMBIGUOUS `.rs` citation is unchecked in the cohort, not just a missing one",
         (lambda r: r.seen_rs == 1 and r.unchecked_rs == 1)(
             scan({"t.md": ["`dup.rs:1`"]}, resolve, count, at_sha))),
        ("an UNVERIFIABLE `.rs` freeze is unchecked in the cohort too",
         (lambda r: r.unverifiable == 1 and r.unchecked_rs == 1)(
             scan({"t.md": ["read at `fee1dad`;", "see `a/b/small.rs:900`"]},
                  resolve, count, at_sha))),
        ("and a non-`.rs` miss does NOT land in the `.rs` cohort's unchecked count",
         (lambda r: r.seen_rs == 0 and r.unchecked_rs == 0)(
             scan({"t.md": ["`nowhere/at/all.toml:1`"]}, resolve, count, at_sha))),
        # The cohort ELEMENT tally, same argument one field down.
        ("scan() counts the `.rs` cohort's elements separately from the whole",
         (lambda r: r.nread == 4 and r.nread_rs == 3)(
             scan({"t.md": ["`a/b/small.rs:1,2,3`", "`a/b/conf.toml:1`"]},
                  resolve, count, at_sha))),
        ("report() REFUSES when the `.rs` cohort's ELEMENT count falls through its floor",
         quiet(lambda: report(healthy(nread_rs=MIN_ELEMENTS_RS - 1), 1)) == 1),
        ("the cohort element floor fires while every AGGREGATE number is healthy",
         quiet(lambda: report(healthy(nread=MIN_ELEMENTS, nread_rs=MIN_ELEMENTS_RS - 1), 1)) == 1),
        ("elements of a citation that never resolved are counted as SKIPPED",
         (lambda r: r.nread == 4 and r.nskipped == 1)(
             scan({"t.md": ["`a/b/small.rs:1,2,3`", "`upstream/aws/builder.rs:9`"]},
                  resolve, count, at_sha))),
        # THE FINDING MUST NAME THE CITATION AS WRITTEN. ROWS compares COUNTS, so nothing there can
        # see the finding's text -- and a finding triggered by a continuation that printed only
        # `m.group(0)` would name `a/b/small.rs:10`, a line that exists in a 50-line file, and read
        # as a gate bug rather than a citation defect.
        #
        # Use `cited_by`, not a bare finding subscript. An empty
        # finding list must produce a failing assertion rather than
        # IndexError during construction of this list, which would
        # prevent later controls and the final tally from running.
        ("a finding names the whole citation, continuations included",
         cited_by(scan({"t.md": ["see `a/b/small.rs:10, 900`"]}, resolve, count, at_sha))
         == "a/b/small.rs:10, 900"),
        ("and it is not merely the head, which is what made this checkable",
         cited_by(scan({"t.md": ["see `a/b/small.rs:10, 900`"]}, resolve, count, at_sha))
         != "a/b/small.rs:10"),
        # A closing backtick stops CONT at the citation boundary.
        # This control checks that prose after a backticked citation
        # is not consumed as a continuation; accepting whitespace
        # or skipping over the tick would change that result.
        ("a closing backtick stops a continuation, which is what makes the live set safe",
         (lambda r: r.nread == 1 and r.past == 0)(
             scan({"t.md": ["see `a/b/small.rs:10`, 900 items"]}, resolve, count, at_sha))),
        # report() has its own rows because the coverage FLOORS are the only checks with no other
        # witness: a mutation that removes one leaves scan() untouched, so every scan control stays
        # green while the gate quietly stops refusing a collapsed scope. That is the exact shape of
        # "a gate must report coverage, not just a verdict" -- printing a number is not checking it.
        #
        # Build Scan by keyword: inserting another counter must not
        # shift fixture values into different fields. `ok()` names the
        # fields under test and defaults the others to a healthy run.
        # THE OUTPUT VENUE'S ROWS: checking only that its
        # thresholds are lower cannot establish the intended
        # behavior. Require disagreement on the same collapsed
        # scan: SOURCE refuses it and OUTPUT passes it. The
        # following controls then require OUTPUT to refuse
        # findings even though it omits coverage floors.
        ("the two venues DISAGREE about a collapsed scan: SOURCE refuses it",
         quiet(lambda: report(healthy(seen=MIN_SEEN - 1, nread=MIN_ELEMENTS - 1,
                                      seen_rs=MIN_SEEN_RS - 1,
                                      nread_rs=MIN_ELEMENTS_RS - 1), 1)) == 1),
        ("...and OUTPUT passes the same scan, because it carries no coverage floor",
         quiet(lambda: report(healthy(seen=MIN_SEEN - 1, nread=MIN_ELEMENTS - 1,
                                      seen_rs=MIN_SEEN_RS - 1,
                                      nread_rs=MIN_ELEMENTS_RS - 1), 1,
                              venue="output")) == 0),
        # A venue that tolerates a collapsed scan must NOT tolerate a finding, or "no floors"
        # has quietly become "no gate". The findings branch is deliberately outside the venue
        # switch for this reason, and this row is what holds it there.
        ("OUTPUT still REFUSES a finding — the floors are what it drops, not the findings",
         quiet(lambda: report(healthy(seen=MIN_SEEN - 1,
                                      findings=[("t.md", 1, "`a.rs:9`", "a.rs", 3,
                                                 "past EOF")]), 1,
                              venue="output")) == 1),
        ("OUTPUT REFUSES an EMPTY corpus, which is its whole blindness check",
         quiet(lambda: report(healthy(seen=0, nread=0, seen_rs=0, nread_rs=0), 0,
                              venue="output")) == 1),
        # The default is SOURCE, and a mutant that flipped it would make every row above pass
        # for the wrong venue while the live gate quietly stopped applying its floors.
        ("report()'s DEFAULT venue is SOURCE, not OUTPUT",
         quiet(lambda: report(healthy(seen=MIN_SEEN - 1), 1)) == 1),
        # A SPLICED-OUT ROW HAS TO LEAVE A MARK, OR THE SUITE
        # REPORTS A SMALLER TOTAL AND STILL SAYS "0 FAILED". The
        # marker below stops recursive probes (see `_argv_refused`).
        # A stray `CHECK_CITATIONS_ARGV_PROBE` in the environment
        # must not silently disable argv and venue-wiring
        # controls: the replacement row fails on purpose, so
        # a green run requires the three controls to run.
        *([("the argv/venue rows are SPLICED OUT: this run is a marked child of another "
            "self-test, and a marked child is never the run whose verdict is banked", False)]
          if os.environ.get("CHECK_CITATIONS_ARGV_PROBE") else [
            ("main() REFUSES an unknown argument rather than running a venue",
             _argv_refused(["--outupt"])),
            ("main() REFUSES both venue flags at once — they are different questions",
             _argv_refused(["--self-test", "--output"])),
            ("`--output` REACHES report() as the OUTPUT venue, not merely parses",
             _venue_reaches_report()),
        ]),
        ("report() REFUSES when the citation count falls through the floor",
         quiet(lambda: report(healthy(seen=MIN_SEEN - 1), 1)) == 1),
        ("report() REFUSES when the CHECKED fraction falls through the floor",
         quiet(lambda: report(healthy(seen=1000, ambig=900), 1)) == 1),
        ("report() REFUSES when the ELEMENT count falls through its own floor",
         quiet(lambda: report(healthy(nread=MIN_ELEMENTS - 1), 1)) == 1),
        # The element floor has to be able to fire while every OTHER number is healthy, or it is
        # just a second spelling of MIN_SEEN and catches nothing MIN_SEEN would not.
        ("the element floor is INDEPENDENT: it fires on a healthy citation count",
         quiet(lambda: report(healthy(seen=MIN_SEEN, nread=MIN_ELEMENTS - 1), 1)) == 1),
        ("report() REFUSES when the `.rs` cohort's citation count falls through its floor",
         quiet(lambda: report(healthy(seen_rs=MIN_SEEN_RS - 1), 1)) == 1),
        ("report() REFUSES when the `.rs` cohort's CHECKED fraction falls through its floor",
         quiet(lambda: report(healthy(seen_rs=1000, unchecked_rs=900), 1)) == 1),
        # AN EXECUTABLE COUNTEREXAMPLE: why the cohort needs a separate floor.
        # Aggregate-healthy, cohort-rotten: 608 citations at 74% clears MIN_SEEN and
        # MIN_CHECKED_FRACTION while the `.rs` half sits at 251/420 = 59.8%, under
        # MIN_FRACTION_RS. A single aggregate floor passes this run. This one must not.
        ("the cohort floor fires on a run whose AGGREGATE numbers are healthy",
         quiet(lambda: report(healthy(seen=608, ambig=158, nread=MIN_ELEMENTS,
                                      seen_rs=420, unchecked_rs=169), 1)) == 1),
        ("...and that same run clears every AGGREGATE floor, so the cohort floor is what caught it",
         608 >= MIN_SEEN and (608 - 158) / 608 >= MIN_CHECKED_FRACTION),
        ("report() PASSES a healthy run, so the floors are not simply always-refusing",
         quiet(lambda: report(healthy(), 1)) == 0),
        ("report() REFUSES on a finding even when coverage is healthy",
         quiet(lambda: report(healthy(past=1, findings=[FIND]), 1)) == 1),
        ("report() REFUSES on a NON-VERIFYING freeze, not only on an unfrozen one",
         quiet(lambda: report(healthy(badfreeze=1, findings=[FIND]), 1)) == 1),
        # The row CI actually needed: a freeze this clone cannot check must REFUSE, not certify.
        ("report() REFUSES when a freeze is UNVERIFIABLE in this clone",
         quiet(lambda: report(healthy(unverifiable=1, findings=[FIND]), 1)) == 1),
        # The checked-ELEMENT figure is the complement of the three unchecked branches, so an
        # unverifiable citation must lower it exactly as it lowers the checked CITATION count.
        ("the checked-element figure excludes an UNVERIFIABLE citation, like the checked count",
         report_line(healthy(seen=MIN_SEEN, nread=MIN_ELEMENTS, nskipped=7)).endswith(
             f"{MIN_ELEMENTS - 7} on a citation that resolves")),
    ]
    for j, (name, cond) in enumerate(checks, n + 1):
        print(f"  {'ok  ' if cond else 'FAIL'} {j:2d} - {name}")
        npass += bool(cond); nfail += not cond
    total = n + len(checks)
    print(f"\ncheck-citations.py self-test: {npass} ok, {nfail} FAILED, {total} controls")
    return 1 if nfail else 0


def git_at(root=None, hermetic=True, replace_objects=False):
    """A `git` callable over `root`, or over the repository in cwd. ONE wrapper, because the
    self-test's constructed repositories must be read by the same code the live run uses.

    >>> EVERY `GIT_*` IS SCRUBBED FROM THE CHILD, AND `-C` IS NOT A SUBSTITUTE FOR THAT. <<<
    `-C` sets only the starting directory; it does not clear
    the environment. A caller-set `GIT_DIR` can direct fixture
    commands to another repository while `-C` still names
    the scratch one. The child environment excludes every
    `GIT_*` variable before the command runs, so the caller
    cannot redirect the fixture through that variable.

    `scripts/bench/gen-w3.py` uses the same environment-scrubbing
    approach in `_git_env`. Setting a starting directory
    does not clear repository-selection variables. Fixture
    commands need both a scratch directory and an environment
    that cannot redirect them to the caller's checkout.

    `--no-replace-objects` for the same reason it is there: a `refs/replace/<oid>` entry
    substitutes another commit's tree under an UNCHANGED commit id, and this gate's whole job is
    to read `<sha>:<path>` and believe what comes back.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    if hermetic:
        # The environment scrub removes `GIT_CONFIG_GLOBAL`
        # and `GIT_CONFIG_NOSYSTEM` too, restoring Git's normal
        # configuration lookup unless these are set again.
        # Fixtures must not depend on the caller's global hooks,
        # protocol permissions or system settings. The hermetic
        # branch points global configuration at the null
        # device and disables system configuration; overriding
        # individual keys would leave the rest exposed.
        #
        # THIS IS DELIBERATELY NOT APPLIED TO THE LIVE RUN. A checkout on a self-hosted runner
        # can depend on a GLOBAL `safe.directory`, and a gate that discarded it would refuse the
        # repository for dubious ownership. The fixtures are directories this process just
        # created as itself, so they need nothing from the user's configuration and must not be
        # steered by it.
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_CONFIG_NOSYSTEM"] = "1"
    def git(*a, check=True):
        cmd = (["git"] + (["-C", root] if root else [])
               + ([] if replace_objects else ["--no-replace-objects"]) + list(a))
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if check and r.returncode:
            raise SystemExit(f"check-citations: {' '.join(cmd)} failed: {r.stderr.strip()}")
        return r.stdout if r.returncode == 0 else None
    return git


def build():
    # THE NON-HERMETIC LIVE CALLER IS DELIBERATE. The other non-hermetic
    # caller is the `exposed` half of the hermeticity control:
    # it must see the hostile key or its partner proves nothing.
    # `hermetic` defaults to TRUE so fixture callers are
    # isolated without remembering a flag. Caller
    # configuration must not derail a constructed repository
    # before the self-test can produce its verdict.
    # The LIVE run opts out: a checkout on a self-hosted runner can depend on a GLOBAL
    # `safe.directory`, and a gate that discarded the user's configuration would refuse the
    # repository for dubious ownership. A fixture this process just created needs nothing from
    # that configuration; the tree under measurement might.
    #
    # The live run needs a different policy: a checkout owned
    # by another user can rely on global `safe.directory`.
    # Discarding that configuration would cause Git to refuse
    # the repository for dubious ownership. The fixture
    # tests do not exercise a checkout owned by another
    # user, so they do not establish this live-run behavior.
    git = git_at(hermetic=False)
    tracked = set(git("ls-files").split())
    bybase = collections.defaultdict(list)
    # The basename index must cover every extension CIT parses, or a widened citation resolves to
    # NOTHING and lands in `missing` -- a silent loss of coverage rather than a loud failure.
    suffixes = tuple("." + e for e in EXTS.split("|"))
    for t in tracked:
        if t.endswith(suffixes):
            bybase[t.split("/")[-1]].append(t)
    def resolve(p):
        # AN EXACT TRACKED PATH WINS, AND AT THE REPO ROOT THAT IS A RULING. `Cargo.toml:27` is
        # both a tracked path (the workspace manifest) and the basename of fifteen crate
        # manifests; this branch answers "the root one" and never reaches the ambiguity test.
        # That matches how this repo writes them -- every bare `Cargo.toml:N` and `README.md:N`
        # in the live set does mean the root file, and a crate manifest is always written with
        # its path (`granary-client/Cargo.toml:102`) -- so the short-circuit encodes the
        # convention rather than guessing. The hazard is the inverse: a bare `Cargo.toml:200`
        # MEANING a crate manifest is silently bounds-checked against a 69-line root file and
        # reported against the wrong file. Exact tracked paths
        # take priority for every admitted extension. A path
        # containing `/` then matches only a tracked `/`-suffix;
        # no match means MISSING, not a basename fallback that
        # mistakes an upstream crate's source for our own.
        # A bare basename still resolves to every matching file
        # when no exact tracked path matches.
        if p in tracked:
            return [p]
        c = bybase.get(p.split("/")[-1], [])
        return [x for x in c if x.endswith("/" + p)] if "/" in p else c
    nlines = {}
    def count(p):
        if p not in nlines:
            nlines[p] = lines_of(pathlib.Path(p).read_text(errors="replace"))
        return nlines[p]
    at_sha, is_shallow = history(git)
    files = [f for f in git("grep", "-lE", SELECTOR, "--", *LIVE).split() if SELF not in f]
    return git, tracked, resolve, count, at_sha, files, is_shallow


def history(git):
    """`at_sha` and `is_shallow`, over whatever repository `git` runs in.

    The self-test binds these functions to repositories it
    constructs. Its expected states come from fixture commits and
    clone depth, not from asking `at_sha` to choose its own expected
    answer. This allows the same controls to run when the
    published checkout contains none of the development history.
    """
    cache, known, shallow = {}, {}, []
    def is_shallow():
        if not shallow:
            shallow.append(
                (git("rev-parse", "--is-shallow-repository", check=False) or "").strip() == "true")
        return shallow[0]
    def at_sha(sha, path):
        """lines at that sha, None if the path was absent there, UNREACHABLE if the sha is not in
        this clone at all AND the clone is shallow, NOTACOMMIT if it is not in a FULL one.

        The third case is not the second: a gate that read "the sha is missing" as "the file was
        absent" would report every correct freeze as a defect, while one that read it as
        "verified" would certify what it never checked. It is its own answer and it REFUSES.

        THE VENUES: the CI checkouts that run this gate
        set `fetch-depth: 0`, so no CI venue reaches the shallow
        arm. The constructed clone in history_conditions()
        exercises it instead. A full published repository reaches
        FULL-and-missing for commits it does not contain."""
        if sha not in known:
            known[sha] = git("cat-file", "-e", f"{sha}^{{commit}}", check=False) is not None
        if not known[sha]:
            # Splitting these two costs one cached call and buys the right REMEDY. A backticked
            # `1048576` is sha-SHAPED and is a commit nowhere; telling its author to set
            # `fetch-depth: 0` -- already set by this gate's CI checkouts -- sends them to fix a checkout
            # instead of a token. Whether the clone is SHALLOW is the discriminator.
            return UNREACHABLE if is_shallow() else NOTACOMMIT
        k = (sha, path)
        if k not in cache:
            out = git("show", f"{sha}:{path}", check=False)
            cache[k] = None if out is None else lines_of(out)
        return cache[k]
    return at_sha, is_shallow


def main(argv):
    # >>> ARGV IS VALIDATED, AND IT WAS NOT BEFORE. <<< `main` asked only whether
    # `"--self-test"` occurred ANYWHERE in argv and otherwise ran the live gate, so
    # `check-citations.py --outupt` ran the SOURCE venue and printed a confident verdict.
    # With two venues that is the difference between two different claims.
    #
    extra = [a for a in argv[1:] if a not in ("--self-test", "--output")]
    if extra or ("--self-test" in argv and "--output" in argv):
        print(f"REFUSED — usage: {argv[0]} [--self-test | --output]"
              + (f" (unknown: {' '.join(extra)})" if extra else
                 " (--self-test and --output are different questions; pass one)"),
              file=sys.stderr)
        return 2
    # >>> THE VENUE IS NAMED BY THE CALLER AND NEVER INFERRED. <<<
    # A gate that read OUTPUT
    # from "the private paths are missing" would let the ABSENCE of the evidence select the
    # standard the evidence is judged by, so a tree whose `docs/adr/` had been deleted by
    # accident would certify itself under the weaker reading.
    venue = "output" if "--output" in argv else "source"
    git, tracked, resolve, count, at_sha, files, is_shallow = build()
    if "--self-test" in argv:
        return self_test(lambda: {
            "count": count, "resolve": resolve, "at_sha": at_sha, "nfiles": len(files),
            # The fixture conditions come from history_conditions(),
            # independently of `at_sha`. The live shallow
            # check is also independent: it uses `git rev-parse`
            # rather than asking the function under
            # test to select its own expected result.
            "shallow": is_shallow,
            # Does SELECTOR match this extension under THE ENGINE THAT
            # WILL SEE IT? Asked of `git grep` itself, not Python's
            # `re` or system `grep -E`: differing regex engines can
            # accept different constructs. Testing a different engine
            # could report green while SELECTOR selects NOTHING,
            # the failure SELECTOR and CIT are split to prevent.
            # The probe string is synthetic, so this answers about the PATTERN and not about what
            # the live set happens to contain today.
            "ere_selects": lambda e: _git_grep_probe(e),
            "wc": lambda p: len(subprocess.run(["wc", "-l", p], capture_output=True, text=True)
                                .stdout.split()[0:1] and
                                subprocess.run(["wc", "-l", p], capture_output=True, text=True)
                                .stdout.split()[0]) and
                            int(subprocess.run(["wc", "-l", p], capture_output=True, text=True)
                                .stdout.split()[0]),
        })
    corpus = {f: pathlib.Path(f).read_text(errors="replace").split("\n") for f in sorted(files)}
    return report(scan(corpus, resolve, count, at_sha), nfiles=len(files), venue=venue)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
