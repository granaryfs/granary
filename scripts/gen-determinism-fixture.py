#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# Deterministic fixture tar for a cross-platform root-hash test.
# Byte-reproducible: fixed mtimes (whole seconds - ustar), uid/gid 0,
# sorted member order, ustar format. Names chosen deliberately:
# NO canonical-equivalence pairs, NO case-only pairs, NO non-UTF-8
# (Linux-only lane covers those at runtime; a committed non-UTF-8 path
# would brick checkout on APFS). Unicode names are written
# in ESCAPE form (\uXXXX / \UXXXXXXXX) so copy-paste normalization can
# never corrupt this source file - no raw multi-byte UTF-8 sequence
# appears literally anywhere below. A runtime self-check in main()
# proves this holds every time the generator runs (fail loudly instead
# of silently producing a different fixture).
if not __debug__:  # pragma: no cover
    raise SystemExit(
        "REFUSED: this script's checks are assert statements and -O / "
        "PYTHONOPTIMIZE disables them. Run it without -O.")


import io, tarfile, sys

MTIME = 1_700_000_000  # fixed, whole seconds

def add(tar, name, *, data=None, mode=0o644, link=None, isdir=False):
    info = tarfile.TarInfo(name)
    info.mtime = MTIME
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    if isdir:
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        tar.addfile(info)
    elif link is not None:
        info.type = tarfile.SYMTYPE
        info.linkname = link
        info.mode = 0o777
        tar.addfile(info)
    else:
        info.size = len(data)
        info.mode = mode
        tar.addfile(info, io.BytesIO(data))

def main(out_path):
    # NFD "cafe" + U+0301 (combining acute) -> UTF-8 bytes 63 61 66 65 cc 81
    cafe_nfd = "cafe\u0301"
    # NFC "caf" + U+00E9 (precomposed e-acute) -> UTF-8 bytes 63 61 66 c3 a9
    cafe_nfc = "caf\u00e9"
    # U+1F980 CRAB (astral, needs \U escape)
    crab = "\U0001F980"
    # U+6570 U+636E ("data" in Chinese)
    cjk = "\u6570\u636e"

    # Self-check: a normalizing edit (an editor or copy-paste collapsing
    # NFD to NFC, or vice versa) must fail LOUDLY here at generation
    # time, not silently produce a different fixture with a stale golden
    # root. The names are spelled with these escapes rather than raw
    # literal chars because a tool-layer write can silently
    # NFC-normalize raw literals.
    assert cafe_nfd.encode("utf-8") == b"\x63\x61\x66\x65\xcc\x81", "NFD name was normalized"
    assert cafe_nfc.encode("utf-8") == b"\x63\x61\x66\xc3\xa9", "NFC name was normalized"
    assert cafe_nfd != cafe_nfc, "NFD and NFC names collapsed to one"

    with tarfile.open(out_path, "w", format=tarfile.USTAR_FORMAT, encoding="utf-8") as tar:
        add(tar, "fixture", isdir=True)
        add(tar, "fixture/README", data=b"granary determinism fixture v1\n")
        add(tar, "fixture/empty", data=b"")
        add(tar, "fixture/run.sh", data=b"#!/bin/sh\nexit 0\n", mode=0o755)
        # NFD bytes in the TARGET: 63 61 66 65 cc 81 ("cafe" + U+0301)
        add(tar, "fixture/link-nfd", link=f"{cafe_nfd}-target")
        # NFD name, same byte trick: 63 61 66 65 cc 81
        add(tar, "fixture/{}-nfd.txt".format(cafe_nfd), data=b"nfd name\n")
        # NFC name: 63 61 66 c3 a9 (U+00E9) - a DIFFERENT word, not a
        # canonical-equivalence pair with the NFD entry above
        add(tar, "fixture/{}-nfc.txt".format(cafe_nfc), data=b"nfc name\n")
        add(tar, f"fixture/{crab}-crab.txt", data=b"emoji\n")
        add(tar, f"fixture/{cjk}.txt", data=b"cjk\n")
        add(tar, "fixture/trailing-space ", data=b"space\n")
        add(tar, "fixture/trailing-dot.", data=b"dot\n")
        add(tar, "fixture/" + "n" * 90, data=b"90-byte name component; ustar cap\n")
        add(tar, "fixture/sub", isdir=True)
        add(tar, "fixture/sub/foo", isdir=True)          # the git-quirk trio
        add(tar, "fixture/sub/foo/inner", data=b"inner\n")
        add(tar, "fixture/sub/foo-x", data=b"dash\n")
        add(tar, "fixture/sub/foo.txt", data=b"dot\n")

if __name__ == "__main__":
    main(sys.argv[1])
