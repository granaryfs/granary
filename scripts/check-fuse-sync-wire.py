#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Reconstruct FUSE wire headers from strace read/readv and write/writev output.

Retains only direction, opcode, unique, error and interrupt-target identity;
payload bytes, paths and names are discarded during frame reassembly.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import sys

if not __debug__:
    raise SystemExit(
        "don't run check-fuse-sync-wire.py with -O: its self-test is assert-based"
    )

FUSE_IN_HEADER = struct.Struct("<IIQQIIIHH")
FUSE_INTERRUPT_IN = struct.Struct("<Q")
FUSE_OUT_HEADER = struct.Struct("<IiQ")

FUSE_WRITE = 16
FUSE_FSYNC = 20
FUSE_FSYNCDIR = 30
FUSE_INTERRUPT = 36
ENOSYS_ERROR = -38

SYNC_OPCODES = frozenset({FUSE_WRITE, FUSE_FSYNC, FUSE_FSYNCDIR})
KNOWN_FUSE_OPCODES = frozenset(set(range(1, 63)) | {4096})
# -xx applies to -y descriptor annotations as well as syscall buffers.
FUSE_FD_PATHS = (None, "</dev/fuse>", r"<\x2f\x64\x65\x76\x2f\x66\x75\x73\x65>")

SYSCALL_RE = re.compile(
    r"^(?:(?P<pid>\d+)\s+)?(?P<call>read|readv|write|writev)\((?P<fd>\d+)(?P<path><[^>]*>)?,\s*(?P<body>.*)\)\s*=\s*(?P<ret>-?\d+)\b"
)
UNFINISHED_RE = re.compile(
    r"^(?:(?P<pid>\d+)\s+)?(?P<prefix>(?:read|readv|write|writev)\(\d+(?:<[^>]*>)?,.*?)<unfinished \.\.\.>\s*$"
)
RESUMED_RE = re.compile(
    r"^(?:(?P<pid>\d+)\s+)?<\.\.\.\s*(?P<call>read|readv|write|writev)\s+resumed>(?P<rest>.*)$"
)
STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"(\.\.\.)?')


@dataclass(frozen=True)
class WireEvent:
    direction: str
    opcode: int | None
    unique: int
    error: int | None
    target_unique: int | None


class WireRefusal(ValueError):
    """Refusal with stable diagnostic text for malformed or incomplete traces."""


def decode_strace_string(escaped: str) -> bytes:
    out = bytearray()
    i = 0
    n = len(escaped)
    while i < n:
        ch = escaped[i]
        if ch != "\\":
            out.extend(ch.encode("latin1"))
            i += 1
            continue
        i += 1
        if i >= n:
            raise WireRefusal("truncated FUSE header")
        esc = escaped[i]
        if esc == "x":
            if i + 2 >= n:
                raise WireRefusal("truncated FUSE header")
            out.append(int(escaped[i + 1 : i + 3], 16))
            i += 3
        elif esc in "01234567":
            oct_digits = esc
            i += 1
            for _ in range(2):
                if i < n and escaped[i] in "01234567":
                    oct_digits += escaped[i]
                    i += 1
                else:
                    break
            out.append(int(oct_digits, 8) & 0xFF)
        elif esc == "n":
            out.append(0x0A)
            i += 1
        elif esc == "r":
            out.append(0x0D)
            i += 1
        elif esc == "t":
            out.append(0x09)
            i += 1
        elif esc == "\\":
            out.append(0x5C)
            i += 1
        elif esc == '"':
            out.append(0x22)
            i += 1
        else:
            out.extend(esc.encode("latin1"))
            i += 1
    return bytes(out)


class StreamAssembler:
    """Reassemble split FUSE headers while discarding all non-header payload bytes."""

    def __init__(self, direction: str) -> None:
        self.direction = direction
        self.header_buf = bytearray()
        self.frame_len: int | None = None
        self.header_goal = 40 if direction == "in" else 16
        self.skip_remaining = 0

    def feed(self, captured: bytes, total_transferred: int) -> list[WireEvent]:
        if total_transferred < len(captured):
            raise WireRefusal("FUSE frame length mismatch")
        events: list[WireEvent] = []
        offset = 0
        unprinted = total_transferred - len(captured)

        while offset < len(captured) or unprinted > 0:
            if self.skip_remaining > 0:
                avail = len(captured) - offset
                if avail > 0:
                    take = min(avail, self.skip_remaining)
                    offset += take
                    self.skip_remaining -= take
                    continue
                take = min(unprinted, self.skip_remaining)
                unprinted -= take
                self.skip_remaining -= take
                continue

            need = self.header_goal - len(self.header_buf)
            if need > 0:
                avail = len(captured) - offset
                if avail == 0:
                    raise WireRefusal("truncated FUSE header")
                take = min(need, avail)
                self.header_buf.extend(captured[offset : offset + take])
                offset += take
                if len(self.header_buf) < self.header_goal:
                    continue

            if self.direction == "in":
                if self.frame_len is None:
                    (
                        frame_len,
                        opcode,
                        _unique,
                        _nodeid,
                        _uid,
                        _gid,
                        _pid,
                        _extlen,
                        _pad,
                    ) = FUSE_IN_HEADER.unpack(self.header_buf[:40])
                    if opcode not in KNOWN_FUSE_OPCODES:
                        raise WireRefusal(f"unknown FUSE opcode: {opcode}")
                    if frame_len < 40:
                        raise WireRefusal("truncated FUSE header")
                    self.frame_len = frame_len
                    if opcode == FUSE_INTERRUPT:
                        if frame_len < 48:
                            raise WireRefusal("truncated FUSE header")
                        if frame_len != 48:
                            raise WireRefusal("FUSE frame length mismatch")
                        self.header_goal = 48
                        continue
                frame_len, opcode, unique, *_ = FUSE_IN_HEADER.unpack(
                    self.header_buf[:40]
                )
                target_unique: int | None = None
                if opcode == FUSE_INTERRUPT:
                    (target_unique,) = FUSE_INTERRUPT_IN.unpack(self.header_buf[40:48])
                consumed_header = self.header_goal
                self.skip_remaining = frame_len - consumed_header
                self.header_buf.clear()
                self.frame_len = None
                self.header_goal = 40
                events.append(
                    WireEvent(
                        direction="in",
                        opcode=opcode,
                        unique=unique,
                        error=None,
                        target_unique=target_unique,
                    )
                )
            else:
                frame_len, error, unique = FUSE_OUT_HEADER.unpack(self.header_buf[:16])
                if frame_len < 16:
                    raise WireRefusal("truncated FUSE header")
                self.skip_remaining = frame_len - 16
                self.header_buf.clear()
                self.frame_len = None
                self.header_goal = 16
                events.append(
                    WireEvent(
                        direction="out",
                        opcode=None,
                        unique=unique,
                        error=error,
                        target_unique=None,
                    )
                )
        return events

    def finish(self) -> None:
        if self.header_buf:
            raise WireRefusal("truncated FUSE header")
        if self.skip_remaining != 0:
            raise WireRefusal("FUSE frame length mismatch")


def parse_trace_text(
    text: str,
    allowed_fds: set[int] | None = None,
) -> list[WireEvent]:
    if not text.strip():
        raise empty_trace_refusal(text, allowed_fds)
    if "Operation not permitted" in text or "PTRACE_SEIZE" in text or "PTRACE_ATTACH" in text:
        raise empty_trace_refusal(text, allowed_fds)

    lines = text.splitlines(keepends=True)

    unfinished: dict[str, str] = {}
    in_stream = StreamAssembler("in")
    out_stream = StreamAssembler("out")
    events: list[WireEvent] = []
    requests: dict[int, int] = {}
    replied: set[int] = set()

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        unfin = UNFINISHED_RE.match(line)
        if unfin is not None:
            pid = unfin.group("pid") or ""
            unfinished[pid] = unfin.group("prefix")
            continue
        resumed = RESUMED_RE.match(line)
        if resumed is not None:
            pid = resumed.group("pid") or ""
            prefix = unfinished.pop(pid, None)
            if prefix is None:
                continue
            line = f"{pid + ' ' if pid else ''}{prefix}{resumed.group('rest')}".strip()

        match = SYSCALL_RE.match(line)
        if match is None:
            continue
        if match.group("path") not in FUSE_FD_PATHS:
            continue
        fd = int(match.group("fd"))
        if allowed_fds is not None and fd not in allowed_fds:
            continue
        ret = int(match.group("ret"))
        if ret <= 0:
            continue
        call = match.group("call")
        body = match.group("body")
        matches = list(STRING_RE.finditer(body))
        if not matches:
            continue
        captured = b"".join(decode_strace_string(m.group(1)) for m in matches)
        truncated = any(m.group(2) is not None for m in matches)
        if not truncated and len(captured) != ret:
            raise WireRefusal("FUSE frame length mismatch")
        if truncated and len(captured) > ret:
            raise WireRefusal("FUSE frame length mismatch")

        stream = in_stream if call in ("read", "readv") else out_stream
        for event in stream.feed(captured, ret):
            if event.direction == "in":
                if event.unique == 0:
                    raise WireRefusal("FUSE_INTERRUPT targets unknown request unique")
                if event.opcode == FUSE_INTERRUPT:
                    target = event.target_unique
                    if target is None or target not in requests or requests[target] == FUSE_INTERRUPT:
                        raise WireRefusal("FUSE_INTERRUPT targets unknown request unique")
                requests[event.unique] = event.opcode or 0
            else:
                if event.unique != 0:
                    if event.unique not in requests:
                        raise WireRefusal("duplicate terminal FUSE reply")
                    if event.unique in replied:
                        raise WireRefusal("duplicate terminal FUSE reply")
                    replied.add(event.unique)
            events.append(event)

    in_stream.finish()
    out_stream.finish()
    if not events:
        raise empty_trace_refusal(text, allowed_fds)
    return events


def empty_trace_refusal(text: str, allowed_fds: set[int] | None) -> WireRefusal:
    """Describe capture/filter failures using metadata only, never trace contents."""
    syscalls: dict[str, int] = {}
    seen: set[int] = set()
    matched: set[int] = set()
    lines = text.splitlines()
    for line in lines:
        call = re.match(r"^(?:\d+\s+)?(\w+)\((\d+)?(<[^>]*>)?", line.strip())
        if call is None:
            continue
        name, fd, path = call.groups()
        syscalls[name] = syscalls.get(name, 0) + 1
        if fd is not None:
            seen.add(int(fd))
            if (allowed_fds is None or int(fd) in allowed_fds) and path in FUSE_FD_PATHS:
                matched.add(int(fd))
    # No complete or partial frame is discarded: callers either have no input,
    # a ptrace refusal, or both strict assemblers finished without any events.
    return WireRefusal(
        f"empty or unreadable FUSE wire trace; trace_lines={len(lines)}; "
        f"syscalls={dict(sorted(syscalls.items()))}; fds_seen={sorted(seen)}; "
        f"fds_matched={sorted(matched)}; complete_frames=0; partial_frames_dropped=0"
    )


def load_trace_events(
    path: Path,
    allowed_fds: set[int] | None = None,
) -> list[WireEvent]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise empty_trace_refusal("", allowed_fds) from exc
    return parse_trace_text(text, allowed_fds=allowed_fds)


def verify_interrupt_trace(
    events: list[WireEvent],
    expect_sync_error: int,
    min_interrupts: int = 1,
    expect_opcode: int = FUSE_FSYNC,
) -> None:
    sync_requests: dict[int, int] = {}
    sync_replies: dict[int, tuple[int, int]] = {}
    interrupts_for_target: dict[int, list[tuple[int, int]]] = {}
    out_by_unique: dict[int, tuple[int, int]] = {}

    for idx, event in enumerate(events):
        if event.direction == "in":
            if event.opcode in SYNC_OPCODES:
                sync_requests[event.unique] = event.opcode
            elif event.opcode == FUSE_INTERRUPT:
                target = event.target_unique
                if target is None or target not in sync_requests:
                    raise WireRefusal("FUSE_INTERRUPT targets unknown request unique")
                if sync_requests[target] != expect_opcode:
                    raise WireRefusal("FUSE_INTERRUPT targets wrong original opcode")
                if target in sync_replies:
                    raise WireRefusal("original sync request settled before FUSE_INTERRUPT")
                interrupts_for_target.setdefault(target, []).append((idx, event.unique))
        else:
            out_by_unique[event.unique] = (idx, event.error or 0)
            if event.unique in sync_requests:
                sync_replies[event.unique] = (idx, event.error or 0)

    if not interrupts_for_target:
        raise WireRefusal("absent FUSE_INTERRUPT on wire")

    matched_targets = 0
    for target, intr_list in interrupts_for_target.items():
        if len(intr_list) < min_interrupts:
            raise WireRefusal("absent FUSE_INTERRUPT on wire")
        for _intr_idx, intr_unique in intr_list:
            reply = out_by_unique.get(intr_unique)
            if reply is None or reply[1] != ENOSYS_ERROR:
                raise WireRefusal("FUSE_INTERRUPT reply was not ENOSYS")
        orig_reply = sync_replies.get(target)
        if orig_reply is None:
            raise WireRefusal("missing terminal reply for interrupted sync request")
        first_intr_idx = intr_list[0][0]
        if orig_reply[0] < first_intr_idx:
            raise WireRefusal("original sync request settled before FUSE_INTERRUPT")
        if orig_reply[1] != expect_sync_error:
            raise WireRefusal(
                f"unexpected terminal sync reply error: got {orig_reply[1]}, expected {expect_sync_error}"
            )
        matched_targets += 1

    if matched_targets == 0:
        raise WireRefusal("absent FUSE_INTERRUPT on wire")


def poll_pending_interrupts(
    events: list[WireEvent], min_interrupts: int, expect_opcode: int
) -> bool:
    sync_requests: set[int] = set()
    sync_replied: set[int] = set()
    interrupt_targets: list[tuple[int, int]] = []
    out_errors: dict[int, int] = {}

    for event in events:
        if event.direction == "in":
            if event.opcode == expect_opcode:
                sync_requests.add(event.unique)
            elif event.opcode == FUSE_INTERRUPT and event.target_unique in sync_requests:
                if event.target_unique not in sync_replied:
                    interrupt_targets.append((event.unique, event.target_unique))
        else:
            out_errors[event.unique] = event.error or 0
            if event.unique in sync_requests:
                sync_replied.add(event.unique)

    answered = [
        (intr_u, target_u)
        for intr_u, target_u in interrupt_targets
        if out_errors.get(intr_u) == ENOSYS_ERROR and target_u not in sync_replied
    ]
    return len(answered) >= min_interrupts


def verify_no_interrupt_trace(
    events: list[WireEvent], expect_sync_error: int, expect_opcode: int
) -> None:
    sync_requests: set[int] = set()
    sync_replies: list[int] = []
    for event in events:
        if event.direction == "in":
            if event.opcode == expect_opcode:
                sync_requests.add(event.unique)
            elif event.opcode == FUSE_INTERRUPT:
                raise WireRefusal("unexpected FUSE_INTERRUPT on wire")
        else:
            if event.unique in sync_requests:
                sync_replies.append(event.error or 0)
    if not sync_replies or sync_replies[-1] != expect_sync_error:
        raise WireRefusal("missing expected sync reply on wire")


def _hex_lit(data: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in data)


def _in_hdr(length: int, opcode: int, unique: int, nodeid: int = 1) -> bytes:
    return FUSE_IN_HEADER.pack(length, opcode, unique, nodeid, 1000, 1000, 4242, 0, 0)


def _out_hdr(length: int, error: int, unique: int) -> bytes:
    return FUSE_OUT_HEADER.pack(length, error, unique)


def fuse_sync_wire_valid_and_malformed() -> int:
    cases = 0

    # 1. Valid fragmented trace: FUSE_FSYNC (split across 2 reads with 16-byte payload),
    # FUSE_INTERRUPT (split across readv iovecs), ENOSYS reply, and terminal FSYNC reply.
    fsync_frame = _in_hdr(56, FUSE_FSYNC, 10) + b"secret-path-bytes"[:16]
    intr_frame = _in_hdr(48, FUSE_INTERRUPT, 11) + FUSE_INTERRUPT_IN.pack(10)
    intr_reply = _out_hdr(16, ENOSYS_ERROR, 11)
    fsync_reply = _out_hdr(16, 0, 10)
    valid_trace = "\n".join(
        [
            f'2001 read(7, "{_hex_lit(fsync_frame[:24])}", 135168) = 24',
            f'2001 read(7, "{_hex_lit(fsync_frame[24:])}", 135168) = 32',
            f'2001 readv(7, [{{iov_base="{_hex_lit(intr_frame[:20])}", iov_len=20}}, {{iov_base="{_hex_lit(intr_frame[20:])}", iov_len=28}}], 2) = 48',
            f'2001 writev(7, [{{iov_base="{_hex_lit(intr_reply)}", iov_len=16}}], 1) = 16',
            f'2002 write(7, "{_hex_lit(fsync_reply[:8])}", 8) = 8',
            f'2002 write(7, "{_hex_lit(fsync_reply[8:])}", 8) = 8',
        ]
    ) + "\n"
    parsed = parse_trace_text(valid_trace, allowed_fds={7})
    assert parsed == [
        WireEvent("in", FUSE_FSYNC, 10, None, None),
        WireEvent("in", FUSE_INTERRUPT, 11, None, 10),
        WireEvent("out", None, 11, ENOSYS_ERROR, None),
        WireEvent("out", None, 10, 0, None),
    ], f"unexpected parsed events: {parsed!r}"
    assert "secret-path" not in repr(parsed)
    verify_interrupt_trace(parsed, expect_sync_error=0, min_interrupts=1)
    cases += 1

    # 2. Valid unfinished/resumed interleaving across worker and runtime threads.
    interleaved_trace = "\n".join(
        [
            f'2001 read(7, "{_hex_lit(fsync_frame)}", 135168) = 56',
            f'2001 read(7, "{_hex_lit(intr_frame)}", 135168) = 48',
            f'2001 writev(7, [{{iov_base="{_hex_lit(intr_reply)}", iov_len=16}}], 1) = 16',
            "2001 read(7,  <unfinished ...>",
            f'2002 writev(7, [{{iov_base="{_hex_lit(fsync_reply)}", iov_len=16}}], 1) = 16',
        ]
    ) + "\n"
    parsed_interleaved = parse_trace_text(interleaved_trace, allowed_fds={7})
    verify_interrupt_trace(parsed_interleaved, expect_sync_error=0, min_interrupts=1)
    cases += 1

    # 3. Malformed: truncated inbound header (< 40 bytes at EOF).
    truncated_in = f'2001 read(7, "{_hex_lit(fsync_frame[:20])}", 135168) = 20\n'
    # 4. Malformed: truncated inbound header declared in header.len (< 40).
    short_decl_in = f'2001 read(7, "{_hex_lit(_in_hdr(24, FUSE_FSYNC, 10))}", 135168) = 40\n'
    # 5. Malformed: truncated outbound header (< 16 bytes at EOF).
    truncated_out = "\n".join(
        [
            f'2001 read(7, "{_hex_lit(_in_hdr(40, FUSE_FSYNC, 10))}", 135168) = 40',
            f'2001 write(7, "{_hex_lit(fsync_reply[:10])}", 10) = 10',
        ]
    ) + "\n"
    # 6. Malformed: length mismatch (header says 64 bytes, only 40 bytes delivered before EOF).
    mismatch_in = f'2001 read(7, "{_hex_lit(_in_hdr(64, FUSE_FSYNC, 10))}", 135168) = 40\n'
    # 7. Malformed: length mismatch on FUSE_INTERRUPT (header says 56 bytes instead of 48).
    mismatch_intr = "\n".join(
        [
            f'2001 read(7, "{_hex_lit(_in_hdr(40, FUSE_FSYNC, 10))}", 135168) = 40',
            f'2001 read(7, "{_hex_lit(_in_hdr(56, FUSE_INTERRUPT, 11) + FUSE_INTERRUPT_IN.pack(10) + b"12345678")}", 135168) = 56',
        ]
    ) + "\n"
    # 8. Malformed: unknown opcode.
    unknown_opcode = f'2001 read(7, "{_hex_lit(_in_hdr(40, 999, 10))}", 135168) = 40\n'
    # 9. Malformed: interrupt with no matching original request unique.
    unmatched_intr = f'2001 read(7, "{_hex_lit(_in_hdr(48, FUSE_INTERRUPT, 11) + FUSE_INTERRUPT_IN.pack(999))}", 135168) = 48\n'
    # 10. Malformed: duplicate terminal reply to the same unique.
    duplicate_reply = "\n".join(
        [
            f'2001 read(7, "{_hex_lit(_in_hdr(40, FUSE_FSYNC, 10))}", 135168) = 40',
            f'2001 write(7, "{_hex_lit(fsync_reply)}", 16) = 16',
            f'2001 write(7, "{_hex_lit(fsync_reply)}", 16) = 16',
        ]
    ) + "\n"
    # 11. Malformed: empty trace.
    empty_trace = "   \n"
    # 12. Malformed: ptrace permission denied trace.
    denied_trace = "strace: attach: ptrace(PTRACE_SEIZE, 1234): Operation not permitted\n"

    malformed_parse_controls = [
        (truncated_in, "truncated FUSE header"),
        (short_decl_in, "truncated FUSE header"),
        (truncated_out, "truncated FUSE header"),
        (mismatch_in, "FUSE frame length mismatch"),
        (mismatch_intr, "FUSE frame length mismatch"),
        (unknown_opcode, "unknown FUSE opcode"),
        (unmatched_intr, "FUSE_INTERRUPT targets unknown request unique"),
        (duplicate_reply, "duplicate terminal FUSE reply"),
        (empty_trace, "empty or unreadable FUSE wire trace"),
        (denied_trace, "empty or unreadable FUSE wire trace"),
    ]
    for trace_text, expected_refusal in malformed_parse_controls:
        try:
            parse_trace_text(trace_text, allowed_fds={7})
        except WireRefusal as exc:
            assert expected_refusal in str(exc), (
                f"expected refusal {expected_refusal!r}, got {str(exc)!r}"
            )
            cases += 1
        else:
            raise AssertionError(
                f"malformed trace unexpectedly passed ({expected_refusal})"
            )

    # 13. Malformed verification: absent FUSE_INTERRUPT when one is required.
    no_intr_events = parse_trace_text(
        "\n".join(
            [
                f'2001 read(7, "{_hex_lit(_in_hdr(40, FUSE_FSYNC, 10))}", 135168) = 40',
                f'2001 write(7, "{_hex_lit(fsync_reply)}", 16) = 16',
            ]
        )
        + "\n",
        allowed_fds={7},
    )
    try:
        verify_interrupt_trace(no_intr_events, expect_sync_error=0)
    except WireRefusal as exc:
        assert "absent FUSE_INTERRUPT on wire" in str(exc), f"got {exc}"
        cases += 1
    else:
        raise AssertionError("absent FUSE_INTERRUPT unexpectedly passed")

    # 14. Malformed verification: original request replied BEFORE FUSE_INTERRUPT arrives.
    early_reply_events = parse_trace_text(
        "\n".join(
            [
                f'2001 read(7, "{_hex_lit(_in_hdr(40, FUSE_FSYNC, 10))}", 135168) = 40',
                f'2001 write(7, "{_hex_lit(fsync_reply)}", 16) = 16',
                f'2001 read(7, "{_hex_lit(intr_frame)}", 135168) = 48',
                f'2001 write(7, "{_hex_lit(intr_reply)}", 16) = 16',
            ]
        )
        + "\n",
        allowed_fds={7},
    )
    try:
        verify_interrupt_trace(early_reply_events, expect_sync_error=0)
    except WireRefusal as exc:
        assert "original sync request settled before FUSE_INTERRUPT" in str(exc), (
            f"got {exc}"
        )
        cases += 1
    else:
        raise AssertionError("early sync reply before FUSE_INTERRUPT unexpectedly passed")

    cases += trace_diagnostic_controls(valid_trace)
    cases += cli_controls(valid_trace, fsync_reply)
    assert cases == 50, f"expected 50 self-test cases, ran {cases}"
    return cases


def trace_diagnostic_controls(valid_trace: str) -> int:
    cases = 0
    controls = [
        ("", {7}, "trace_lines=0; syscalls={}; fds_seen=[]; fds_matched=[]"),
        (f'2001 read(7<{_hex_lit(b"/dev/fuse")}>, <unfinished ...>\n', {7},
         "trace_lines=1; syscalls={'read': 1}; fds_seen=[7]; fds_matched=[7]"),
        ("strace: ptrace(PTRACE_SEIZE): Operation not permitted\n", {7},
         "trace_lines=1; syscalls={}; fds_seen=[]; fds_matched=[]"),
        (valid_trace, {9},
         "trace_lines=6; syscalls={'read': 2, 'readv': 1, 'write': 2, 'writev': 1}; fds_seen=[7]; fds_matched=[]"),
        (f'2001 read(7<{_hex_lit(b"/unrelated")}>, "private-payload", 15) = 15\n', {7},
         "trace_lines=1; syscalls={'read': 1}; fds_seen=[7]; fds_matched=[]"),
        ('2001 pread64(8</dev/fuse>, "private-payload", 15, 0) = 15\n', {7, 8},
         "trace_lines=1; syscalls={'pread64': 1}; fds_seen=[8]; fds_matched=[8]"),
        ('2001 read(7</dev/fuse>, <unfinished ...>\n', {7},
         "trace_lines=1; syscalls={'read': 1}; fds_seen=[7]; fds_matched=[7]"),
    ]
    for contents, fds, summary in controls:
        # A valid counterpart must still produce all four header events.
        assert len(parse_trace_text(valid_trace, allowed_fds={7})) == 4
        try:
            parse_trace_text(contents, allowed_fds=fds)
        except WireRefusal as exc:
            expected = ("empty or unreadable FUSE wire trace; " + summary
                        + "; complete_frames=0; partial_frames_dropped=0")
            assert str(exc) == expected, (expected, str(exc))
            cases += 1
        else:
            raise AssertionError("frame-less trace unexpectedly passed")
    assert cases == 7, f"expected 7 trace diagnostic controls, ran {cases}"
    return cases


def harness_cli_shape(source: str) -> list[str]:
    body = source.partition("fn wire_command(")[2].partition("\n}\n")[0]
    arguments = re.findall(r'"(--[a-z-]+|FSYNC)"', body)
    if len(arguments) != 7:
        raise WireRefusal("cannot read wire harness CLI shape")
    return arguments


def load_harness_cli(path: Path) -> list[str]:
    try:
        return harness_cli_shape(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise WireRefusal("cannot read wire harness CLI source") from exc


def cli_controls(valid_trace: str, fsync_reply: bytes) -> int:
    cases = 0
    harness = Path(__file__).resolve().parent.parent / "crates/granary-client/src/mount/tests/writable/mounted/sync.rs"
    trace_opt, opcode_opt, opcode, expect, forbid, error_opt, fd_opt = load_harness_cli(harness)
    cases += 1
    for source, refusal in [("", "cannot read wire harness CLI shape"),
                            (harness.read_text().replace('"--fd"', '"fd"'), "cannot read wire harness CLI shape")]:
        try:
            harness_cli_shape(source)
        except WireRefusal as exc:
            assert str(exc) == refusal, (refusal, str(exc))
            cases += 1
        else:
            raise AssertionError(f"malformed harness CLI unexpectedly passed: {refusal}")
    try:
        load_harness_cli(harness.with_name("absent-wire-harness.rs"))
    except WireRefusal as exc:
        assert str(exc) == "cannot read wire harness CLI source", str(exc)
        cases += 1
    else:
        raise AssertionError("unreadable harness CLI unexpectedly passed")
    with tempfile.TemporaryDirectory(prefix="fuse-wire-") as scratch:
        trace = Path(scratch) / "wire.strace"
        command = [sys.executable, str(Path(__file__).resolve()), trace_opt, str(trace)]
        verify = [opcode_opt, opcode, expect, error_opt, "0", fd_opt, "7", fd_opt, "8"]
        no_interrupt = (
            f'2001 read(7, "{_hex_lit(_in_hdr(40, FUSE_FSYNC, 10))}", 40) = 40\n'
            f'2001 write(7, "{_hex_lit(fsync_reply)}", 16) = 16\n'
        )
        capped_trace = (
            f'2001 read(7, "{_hex_lit(_in_hdr(56, FUSE_FSYNC, 10) + bytes(8))}"..., 135168) = 56\n'
            + "\n".join(valid_trace.splitlines()[2:]) + "\n"
        )
        other_opcode_interrupt = (
            valid_trace.replace("\\x14\\x00\\x00\\x00", "\\x10\\x00\\x00\\x00")
            + f'2001 read(7, "{_hex_lit(_in_hdr(40, FUSE_FSYNC, 12))}", 40) = 40\n'
            + f'2001 write(7, "{_hex_lit(_out_hdr(16, 0, 12))}", 16) = 16\n'
        )
        controls = [
            (valid_trace, verify, None),
            (valid_trace.replace("(7,", "(7</dev/fuse>,"), verify, None),
            (valid_trace.replace("(7,", f"(7<{_hex_lit(b'/dev/fuse')}>,"), verify, None),
            ('2001 read(7</unrelated>, "ignored", 7) = 7\n' + valid_trace, verify, None),
            (valid_trace.replace("read(7,", "read(8,"), verify, None),
            (no_interrupt, [*verify[:2], forbid, *verify[3:]], None),
            (other_opcode_interrupt, [*verify[:2], forbid, *verify[3:]], "unexpected FUSE_INTERRUPT on wire"),
            (valid_trace, [], "trace verification arguments are required"),
            (valid_trace, verify[2:], "trace verification arguments are required"),
            (valid_trace, verify[:2] + verify[3:], "trace verification arguments are required"),
            (valid_trace, verify[:3] + verify[5:], "trace verification arguments are required"),
            (no_interrupt, verify, "absent FUSE_INTERRUPT on wire"),
            (valid_trace, ["--self-test"], "--self-test cannot verify --trace"),
            (valid_trace, [*verify, "--poll-interrupts", "1"], "absent pending FUSE_INTERRUPT ENOSYS reply"),
            (valid_trace.rsplit('2002 write', 2)[0], [*verify, "--poll-interrupts", "1"], None),
            (capped_trace, verify, None),
            (valid_trace, [*verify[:2], forbid, *verify[3:]],
             "unexpected FUSE_INTERRUPT on wire"),
            (valid_trace.replace("\\x14\\x00\\x00\\x00", "\\x10\\x00\\x00\\x00"),
             verify, "FUSE_INTERRUPT targets wrong original opcode"),
            (valid_trace, [*verify[:4], "-5", *verify[5:]], "unexpected terminal sync reply error"),
            (valid_trace.replace(_hex_lit(fsync_reply[0:8]), _hex_lit(_out_hdr(32, 0, 10)[0:8])),
             verify, "FUSE frame length mismatch"),
            (valid_trace, [*verify[:-4], "--fd", "9"], "empty or unreadable FUSE wire trace"),
            ("", verify, "empty or unreadable FUSE wire trace; trace_lines=0; syscalls={}; fds_seen=[]; fds_matched=[]; complete_frames=0; partial_frames_dropped=0"),
            (None, verify, "empty or unreadable FUSE wire trace; trace_lines=0; syscalls={}; fds_seen=[]; fds_matched=[]; complete_frames=0; partial_frames_dropped=0"),
            ('2001 pread64(7</dev/fuse>, "private-payload", 15, 0) = 15\n', verify,
             "empty or unreadable FUSE wire trace; trace_lines=1; syscalls={'pread64': 1}; fds_seen=[7]; fds_matched=[7]; complete_frames=0; partial_frames_dropped=0"),
            (valid_trace.replace("\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00", "\\xe7\\x03\\x00\\x00\\x00\\x00\\x00\\x00", 1),
             verify, "FUSE_INTERRUPT targets unknown request unique"),
        ]
        for contents, arguments, refusal in controls:
            if contents is None:
                trace.unlink(missing_ok=True)
            else:
                trace.write_text(contents, encoding="utf-8")
            result = subprocess.run(command + arguments, capture_output=True, text=True,
                                    timeout=5, check=False)
            if refusal is None:
                assert (result.returncode, result.stdout, result.stderr) == (0, '{"ok":true}\n', ''), result
            else:
                assert result.returncode != 0 and refusal in result.stderr, (refusal, result)
            cases += 1
    assert cases == 29, f"expected 29 CLI controls, ran {cases}"
    return cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run fuse_sync_wire_valid_and_malformed controls",
    )
    parser.add_argument("--trace", type=Path, help="path to strace output file")
    parser.add_argument("--fd", type=int, action="append",
                        help="/dev/fuse descriptor; repeat for every descriptor")
    parser.add_argument("--expect-opcode", choices=["WRITE", "FSYNC", "FSYNCDIR"])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--expect-interrupt", action="store_true")
    mode.add_argument("--forbid-interrupt", action="store_true")
    parser.add_argument("--expect-original-error", type=int)
    parser.add_argument("--poll-interrupts", type=int, default=0)
    args = parser.parse_args(argv)

    if args.self_test and args.trace is not None:
        parser.error("--self-test cannot verify --trace")
    if args.self_test:
        count = fuse_sync_wire_valid_and_malformed()
        print(f"PASS fuse_sync_wire_valid_and_malformed ({count} cases)")
        return 0

    if args.trace is None:
        parser.error("--trace or --self-test is required")

    if (args.expect_opcode is None or args.expect_original_error is None
            or not (args.expect_interrupt or args.forbid_interrupt)):
        parser.error("trace verification arguments are required: --expect-opcode, "
                     "--expect-interrupt/--forbid-interrupt, --expect-original-error")
    if args.poll_interrupts < 0 or (args.poll_interrupts and args.forbid_interrupt):
        parser.error("--poll-interrupts requires a positive count and --expect-interrupt")
    allowed_fds = set(args.fd) if args.fd else None
    opcode = {"WRITE": FUSE_WRITE, "FSYNC": FUSE_FSYNC, "FSYNCDIR": FUSE_FSYNCDIR}[args.expect_opcode]
    try:
        events = load_trace_events(args.trace, allowed_fds=allowed_fds)
        if args.poll_interrupts:
            if not poll_pending_interrupts(events, args.poll_interrupts, opcode):
                raise WireRefusal("absent pending FUSE_INTERRUPT ENOSYS reply")
        elif args.expect_interrupt:
            verify_interrupt_trace(events, expect_sync_error=args.expect_original_error,
                                   expect_opcode=opcode)
        else:
            verify_no_interrupt_trace(events, args.expect_original_error, opcode)
    except WireRefusal as exc:
        print(f"check-fuse-sync-wire.py: refused: {exc}", file=sys.stderr)
        return 1
    print('{"ok":true}')

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
