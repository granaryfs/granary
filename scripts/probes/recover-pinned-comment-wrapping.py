#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Recover the EXACT line wrapping of a comment whose bytes are covered by a
# golden hash, when the supplied comment was PROSE.
#
# This recovers comment wrapping when a blake3 digest pins a source region but
# the supplied comment text does not specify its line breaks. Different
# wrappings of the same words can have the same byte count and different
# digests.
#
# THE KEY ARITHMETIC. For a fixed word sequence rendered as `k` comment lines,
# each line being <indent><prefix><space><words joined by single spaces>, the
# total byte length is
#
#     total = sum(len(w) for w in words) + len(words) + k * (indent + len(prefix) + 1)
#
# ...which is INDEPENDENT of where the breaks fall. So every k-line wrapping has
# the same length -- which is why a byte-count check passes while the hash fails
# -- and, inverted, the pinned length DETERMINES k uniquely. That collapses the
# search from "all wrappings" to "all ways to split N words into exactly k
# non-empty runs", which is small enough to enumerate.
#
#   scripts/probes/recover-pinned-comment-wrapping.py \
#       --words "The PRE-CURSOR validator, retained as ..." \
#       --target-bytes 256 --indent 4 --prefix '///' [--max-cols 100]
#
# It prints every candidate whose rendering matches --target-bytes. Hash each
# with the PROJECT'S OWN hash function (a temporary test calling it is the
# reliable way -- do not assume a plain digest) and keep the one that matches
# the golden value. A unique match identifies the pinned wrapping.
#
# If more than one candidate survives the hash, the pin does not identify a
# unique preimage and the spec must deliver the bytes literally instead.
import argparse, itertools, sys


def render(groups, indent, prefix):
    pad = " " * indent
    return "".join(f"{pad}{prefix} {' '.join(g)}\n" for g in groups)


# The self-test fixture's comment bytes are covered by a blake3 pin; exactly
# one of the candidates below hashed to the pinned digest.
FIXTURE_WORDS = (
    "The PRE-CURSOR validator, retained as the differential's independent "
    "oracle. NEVER edit it to track the production function: its whole value "
    "is that it is not the code under test. (M9 T2; the executing skeptic's "
    "FINDING 1.)"
)
FIXTURE_BYTES = 256
FIXTURE_ANSWER = (7, 16, 29)  # the pinned wrapping


def _line_cost(indent, prefix):
    """Bytes a line costs beyond its words: indent + prefix + the space after
    it + the newline, less the inter-word space a break consumes.

    Returned in BYTES, because the target is a byte count. `prefix` is
    almost always ASCII, but measuring it in characters here while the
    candidate is measured with `.encode()` below is precisely the mismatch
    this function exists to prevent.
    """
    if indent < 0:
        raise ValueError(f"indent must be >= 0, got {indent}")
    cost = indent + len(prefix.encode()) + 2 - 1
    if cost < 1:
        # Unreachable with indent >= 0 (the minimum is 1, at indent 0 and an
        # empty prefix), and asserted rather than assumed: a zero cost is a
        # division by zero two lines down, and a NEGATIVE one silently
        # inverts the search.
        raise ValueError(f"per-line cost {cost} is not positive")
    return cost


def candidates(words, target, indent, prefix, max_cols):
    n = len(words)
    per_line = _line_cost(indent, prefix)
    # BYTES, not characters. A word carrying any non-ASCII byte makes the two
    # differ, and the candidate below is measured with `.encode()` — so a
    # character count here reports "no whole number of lines" for a wrapping
    # that exists.
    body = sum(len(w.encode()) for w in words) + n
    if (target - body) % per_line:
        return None, None
    k = (target - body) // per_line
    if not 1 <= k <= n:
        return None, None
    out = []
    for cuts in itertools.combinations(range(1, n), k - 1):
        bounds = (0,) + cuts + (n,)
        groups = [words[i:j] for i, j in zip(bounds, bounds[1:])]
        text = render(groups, indent, prefix)
        if len(text.encode()) != target:
            continue
        if any(len(l) > max_cols for l in text.split("\n")):
            continue
        out.append((cuts, text))
    return k, out


def self_test():
    """Every control fires, and the known answer is found."""
    ok = True

    def check(label, cond):
        nonlocal ok
        print(f"  {'ok  ' if cond else 'FAIL'} {label}")
        ok = ok and cond

    words = FIXTURE_WORDS.split()
    k, cands = candidates(words, FIXTURE_BYTES, 4, "///", 100)
    check("the pinned length forces exactly 4 lines", k == 4)
    check("candidates are found at the pinned length", bool(cands))
    check("the KNOWN wrapping is among them",
          any(c == FIXTURE_ANSWER for c, _ in (cands or [])))
    # Every candidate really is the pinned length -- the property that makes a
    # byte-count check useless as a discriminator, and the reason this exists.
    # `all()` over an empty list is True, so every one of these checks says
    # "and there was something to check" first. Without that a run in which
    # `candidates` returned nothing passes three controls by vacuity -- the
    # exact shape of the broken control this self-test caught in its own
    # first revision.
    check("every candidate has the pinned byte length",
          bool(cands) and all(len(t.encode()) == FIXTURE_BYTES for _, t in cands))
    check("more than one candidate exists (byte count cannot discriminate)",
          len(cands or []) > 1)
    # Negative controls.
    k_bad, _ = candidates(words, FIXTURE_BYTES + 3, 4, "///", 100)
    check("a length no whole line count can produce is REFUSED", k_bad is None)
    k_pfx, _ = candidates(words, FIXTURE_BYTES, 4, "//", 100)
    check("a wrong comment prefix is REFUSED", k_pfx is None)
    _, narrow = candidates(words, FIXTURE_BYTES, 4, "///", 40)
    check("an impossible max-cols yields no candidate", narrow == [])
    # BYTES, not characters. U+00E9 is ONE character and TWO UTF-8 bytes, so a
    # character-counting body misses by exactly one byte and reports the
    # wrapping impossible. The one-line rendering `    /// \u00e9\n` is
    # 4 + 3 + 1 + 2 + 1 = 11 bytes and 10 characters.
    k_utf8, utf8 = candidates(["\u00e9"], 11, 4, "///", 100)
    check("a non-ASCII word is measured in BYTES", k_utf8 == 1 and bool(utf8))
    check("  and the rendering really is the target length",
          bool(utf8) and all(len(t.encode()) == 11 for _, t in utf8))
    check("  while its CHARACTER length would have missed",
          bool(utf8) and len(utf8[0][1]) == 10)
    # A per-line cost of zero or less is a division by zero, not a search.
    bad = None
    try:
        candidates(words, FIXTURE_BYTES, -3, "", 100)
    except ValueError as e:
        bad = str(e)
    check("a negative indent is REFUSED, not divided by", bad is not None)
    print("self-test: ALL GREEN" if ok else "self-test: FAILED")
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    ap = argparse.ArgumentParser()
    ap.add_argument("--words", required=True, help="the comment's text, one space-separated run")
    ap.add_argument("--target-bytes", type=int, required=True, help="pinned length of the rendered comment")
    ap.add_argument("--indent", type=int, default=4)
    ap.add_argument("--prefix", default="///")
    ap.add_argument("--max-cols", type=int, default=100, help="refuse a candidate line wider than this")
    a = ap.parse_args()

    words = a.words.split()
    n = len(words)
    # Each line costs indent + prefix + the space after it + a newline = P.
    # But a line break also CONSUMES one inter-word space, so adding a line
    # grows the total by P - 1, not P. Getting this wrong is what the
    # self-test below catches.
    # main() calls `candidates()` rather than re-deriving the same
    # arithmetic. With a hand-duplicated copy, a mutation on this path
    # alone leaves the self-test ALL GREEN while the real invocation returns
    # the wrong answer — and that self-test is wired into the gate
    # suite, which would make a duplicate a way for a gate to certify a
    # broken tool.
    try:
        per_line = _line_cost(a.indent, a.prefix)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(5)
    body = sum(len(w.encode()) for w in words) + n
    k, cands = candidates(words, a.target_bytes, a.indent, a.prefix, a.max_cols)
    if k is None:
        if (a.target_bytes - body) % per_line:
            print(f"no whole number of lines yields {a.target_bytes} bytes "
                  f"(body={body}, per_line={per_line}) -- check --indent/--prefix",
                  file=sys.stderr)
            sys.exit(2)
        print(f"implied line count is impossible for {n} words", file=sys.stderr)
        sys.exit(3)
    print(f"# {n} words, body {body} bytes, {per_line} bytes per line "
          f"=> EXACTLY {k} lines", file=sys.stderr)

    found = 0
    for cuts, text in cands:
        found += 1
        print(f"--- candidate {found} (splits at {cuts}) ---")
        print(text, end="")
    print(f"# {found} candidate(s) at {a.target_bytes} bytes; hash each with the "
          f"project's own function", file=sys.stderr)
    if not found:
        sys.exit(4)


if __name__ == "__main__":
    main()
