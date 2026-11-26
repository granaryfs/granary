#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Generator used by the propagation harness.
#
# The mount-time and memory workload uses about 100,000 entries in 1,000 to
# 10,000 directories, up to eight levels deep. Directory fan-out comes from a
# fixed table with a long tail. File sizes follow a log-normal distribution
# with a small median. The generator rejects a size cap of 16 MiB or more.
# Verify the actual file sizes independently before measuring.
#
# Every random draw comes from ONE `random.Random(seed)` instance, drawn
# in a FIXED order (directories, then per-directory file counts, then file
# sizes and bytes, then symlinks) -- so the same (seed, target_dirs,
# target_files, target_symlinks, max_depth, size_median, size_cap)
# reproduces byte-identical trees.
"""Arguments: <dest-dir> --seed N --dirs N --files N [--symlinks N]
          [--max-depth 8] [--size-median-bytes 1536] [--size-cap-bytes 1048576]

Prints one line: `GEN-TREE dest=<dest> dirs=<n> files=<n> symlinks=<n>
bytes=<n> seed=<n>` -- counts are what this generator INTENDED to write;
they are not a substitute for a tool-derived count (M3) and the record
must not use them as one. <dest> is never printed with an absolute path
prefix beyond what the caller supplied on argv, so a caller that avoids
/Users or /home in its own destination argument keeps this line clean.
"""
import argparse
import os
import random
import sys

# A FIXED table, per M2's own words ("a fixed table with a long tail") --
# not re-derived per call. Directory child-count and per-directory file
# count each draw from their own table below.
DIR_CHILD_TABLE = [0, 0, 1, 1, 1, 2, 2, 3, 5, 10, 20]
DIR_CHILD_WEIGHTS = [30, 15, 15, 10, 8, 8, 5, 4, 3, 1.5, 0.5]

FILE_COUNT_TABLE = [0, 0, 1, 1, 2, 3, 5, 10, 20, 50, 100, 300]
FILE_COUNT_WEIGHTS = [12, 10, 14, 12, 10, 10, 9, 8, 6, 5, 3, 1]


def build_dirs(rng, target_dirs, max_depth):
    dirs = [""]  # "" is the source root itself
    depths = {"": 0}
    queue = [("", 0)]
    qi = 0
    while qi < len(queue) and len(dirs) < target_dirs:
        path, depth = queue[qi]
        qi += 1
        if depth >= max_depth:
            continue
        n = rng.choices(DIR_CHILD_TABLE, weights=DIR_CHILD_WEIGHTS, k=1)[0]
        for _ in range(n):
            if len(dirs) >= target_dirs:
                break
            name = f"d{len(dirs):06d}"
            child = os.path.join(path, name) if path else name
            dirs.append(child)
            depths[child] = depth + 1
            queue.append((child, depth + 1))
    # The natural branching process (mean offspring set by DIR_CHILD_TABLE,
    # bounded by max_depth) can die out -- expected total nodes is a finite
    # sum over depth, and a long-tailed table's weighted mean can easily
    # land below what a large target_dirs needs -- before target_dirs is
    # reached (MEASURED: 38 of a 150 target on one seed). Rather than
    # retuning the table's own long tail to hit an arbitrary target exactly
    # (which would no longer be the FIXED table M2 asks for), attach the
    # shortfall as extra children of randomly chosen eligible (depth <
    # max_depth) existing directories, in the SAME rng stream so the
    # result stays a deterministic function of the seed.
    while len(dirs) < target_dirs:
        eligible = [d for d in dirs if depths[d] < max_depth]
        if not eligible:
            break
        parent = rng.choice(eligible)
        name = f"d{len(dirs):06d}"
        child = os.path.join(parent, name) if parent else name
        dirs.append(child)
        depths[child] = depths[parent] + 1
    return dirs


def assign_file_counts(rng, dirs, target_files):
    raw = [rng.choices(FILE_COUNT_TABLE, weights=FILE_COUNT_WEIGHTS, k=1)[0] for _ in dirs]
    total_raw = sum(raw)
    if total_raw == 0:
        raw = [1 for _ in dirs]
        total_raw = len(dirs)
    scale = target_files / total_raw
    counts = [round(c * scale) for c in raw]
    diff = target_files - sum(counts)
    # Distribute the rounding remainder across randomly chosen directories,
    # one unit at a time, rather than dumping it all on directory 0 (which
    # would bias the fan-out's own long tail toward a single artificial
    # outlier).
    idxs = list(range(len(dirs)))
    step = 1 if diff > 0 else -1
    remaining = abs(diff)
    while remaining > 0:
        i = rng.choice(idxs)
        if step < 0 and counts[i] <= 0:
            continue
        counts[i] += step
        remaining -= 1
    return counts


def lognormal_size(rng, median_bytes, cap_bytes):
    import math

    mu = math.log(max(median_bytes, 1))
    sigma = 1.0
    while True:
        v = rng.lognormvariate(mu, sigma)
        n = max(1, int(v))
        if n < cap_bytes:
            return n
        # Resample rather than clip at the cap: clipping would pile a
        # visible spike of files at exactly size_cap_bytes, which is not
        # what "log-normal file sizes" means.


def write_file(path, size, rng):
    # Deterministic pseudorandom content, seeded per file via the shared
    # rng stream (not all-zero/all-same content, which would make every
    # file's grains dedupe against each other and misrepresent a real
    # corpus's object-store novelty ratio).
    remaining = size
    with open(path, "wb") as f:
        while remaining > 0:
            chunk = min(remaining, 65536)
            f.write(rng.randbytes(chunk))
            remaining -= chunk


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dest")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--dirs", type=int, required=True)
    ap.add_argument("--files", type=int, required=True)
    ap.add_argument("--symlinks", type=int, default=0)
    ap.add_argument("--max-depth", type=int, default=8)
    ap.add_argument("--size-median-bytes", type=int, default=1536)
    ap.add_argument("--size-cap-bytes", type=int, default=1048576)
    args = ap.parse_args()

    if args.size_cap_bytes >= 16 * 1024 * 1024:
        print(
            f"GEN-TREE: refused -- size-cap-bytes={args.size_cap_bytes} is not "
            "strictly below 16777216 (16 MiB); the C2 no-spill precondition "
            "requires every regular file strictly under that bound.",
            file=sys.stderr,
        )
        sys.exit(9)

    rng = random.Random(args.seed)
    os.makedirs(args.dest, exist_ok=True)
    if os.listdir(args.dest):
        print(f"GEN-TREE: refused -- dest is not empty: {args.dest}", file=sys.stderr)
        sys.exit(9)

    dirs = build_dirs(rng, args.dirs, args.max_depth)
    for d in dirs:
        if d:
            os.makedirs(os.path.join(args.dest, d), exist_ok=True)

    counts = assign_file_counts(rng, dirs, args.files)

    all_files = []  # paths relative to dest, for the symlink pass below
    total_bytes = 0
    n_files = 0
    for d, n in zip(dirs, counts):
        for i in range(n):
            relp = os.path.join(d, f"f{i:05d}.dat") if d else f"f{i:05d}.dat"
            size = lognormal_size(rng, args.size_median_bytes, args.size_cap_bytes)
            write_file(os.path.join(args.dest, relp), size, rng)
            all_files.append(relp)
            total_bytes += size
            n_files += 1

    n_symlinks = 0
    if args.symlinks > 0 and all_files:
        for i in range(args.symlinks):
            target_rel = rng.choice(all_files)
            parent = rng.choice(dirs)
            link_rel = os.path.join(parent, f"s{i:05d}.lnk") if parent else f"s{i:05d}.lnk"
            link_abs = os.path.join(args.dest, link_rel)
            target_abs = os.path.join(args.dest, target_rel)
            rel_target = os.path.relpath(target_abs, os.path.dirname(link_abs))
            os.symlink(rel_target, link_abs)
            n_symlinks += 1

    print(
        f"GEN-TREE dest={args.dest} dirs={len(dirs)} files={n_files} "
        f"symlinks={n_symlinks} bytes={total_bytes} seed={args.seed}"
    )


if __name__ == "__main__":
    main()
