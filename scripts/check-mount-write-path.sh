#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# No bare standard-stream write on mount startup or shutdown. The terminal
# exception list is empty: every terminal reason uses bounded direct delivery.
# Being followed by a return never licenses a bare write.
#
# Inventory derived from the CLI dispatch and its local callees:
#   main.rs: dispatch, usage, pins/origin/wire arguments, clock, snapshot exit;
#   attach.rs: parsing, admission, preflight, session, daemon and shutdown;
#   attach/control/support.rs: bounded support-producer lifecycle and framing;
#   attach/mount_table.rs: mount preflight and shutdown verification;
#   admission.rs: process credentials and set-ID refusal;
#   sink.rs: the protected writer and its destination worker;
#   logging.rs: output selection, the rotated file and the destination the
#     sink's worker writes;
#   terminal.rs: bounded direct diagnostics and the panic hook.
#   keys.rs: existing-seed loading, descriptor custody and sidecar validation;
#   path_separation.rs: managed-path and protected-file separation;
#   publish_config.rs: authenticated authority credential configuration.
#   client/signing_input.rs and writable_start.rs: shared custody and every
#     admission/ownership/readiness callee, scanned whole without exclusions;
#     writable_start/finish.rs: the start's finishing of an interrupted
#     shutdown, scanned whole.
# These production files are scanned WHOLE, on every platform and feature.
# main's other verb arms and the explicitly named other-verb functions are
# outside this path. CacheOnDrop::drop belongs to publish/cat, not mount.
# Key creation/announcement and public-sidecar repair are publish-only functions,
# excluded by their anchored item names; the load-only entry remains scanned.
# All out-of-line test files are named too. A new, missing or symlinked .rs
# file refuses as BLIND, including an untracked helper; no git index needed.
#
# Boundaries use balanced Rust tokens, not line offsets or a test-module
# ceiling. Comments and string contents cannot supply anchors. An excluded
# item's missing anchor, an altered dispatch boundary or an altered test
# module declaration refuses as BLIND. New functions in scanned files are
# scanned by default, including nested functions and impl methods.
# Real stderr handles are accepted ONLY in the bounded-direct implementation's
# exact write_line_to call and sink_to's owned destination construction in main.
# Neither site licenses another handle, even inside the same enclosing item.
# Imports of standard-stream constructors, renamed I/O modules and constructor
# calls under any namespace refuse too. Only dot-prefixed methods are exempt:
# Command::stderr configures a child's stream instead of writing to ours.
# dbg! locks stderr synchronously just like eprintln!; clippy's dbg_macro
# lint is allow-by-default, so the source gate must name it explicitly.
#
# Like the server log-path gate, this checks common source spellings, not
# arbitrary handle aliases, raw fd syscalls or dependency-internal writes.
# Includes of source and path-remapped modules refuse rather than widening
# the inventory invisibly. Self-test copies the tree into a temporary root.
set -euo pipefail
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != "--self-test" ) ]]; then
  echo "mount-write-path: unrecognised argument(s): $* — the only accepted form is '--self-test' (or no argument, to run the gate). Refused rather than silently running the gate and reporting green." >&2
  exit 2
fi
cd "$(dirname "$0")/.."
python3 - "$0" "${1:-}" <<'PY'
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

SRC = pathlib.Path("crates/granary-cli/src")
PRODUCTION = {
    "attach/control.rs",
    "attach/control/client.rs",
    "attach/control/endpoint.rs",
    "attach/control/service.rs",
    "attach/control/support.rs",
    "attach/control/transport.rs",
    "attach/metrics_export.rs",
"main.rs", "attach.rs", "attach/mount_table.rs", "admission.rs", "sink.rs", "terminal.rs", "logging.rs", "keys.rs", "path_separation.rs", "publish_config.rs"}
# Overlay commands dispatch before logging setup, outside the mount path.
OTHER_VERBS = {"overlay_discard.rs", "overlay_discard/reconcile.rs",
               "publication.rs", "publication_report.rs", "recover.rs", "support_bundle.rs"}
CLIENT_SRC = pathlib.Path("crates/granary-client/src")
CLIENT_HELPERS = {
    "local_report.rs": {"install_local_reports", "escaped_path"},
    "signing_input.rs": {"load_existing_signing_key", "load_key_from_paths", "signing_seed_paths", "read_public_key_sidecar"},
    "writable_start.rs": {"start_writable", "start_with", "start_inner", "check_rails", "check_empty_mountpoint", "load_local", "readback", "drive", "check_managed_paths"},
    "writable_start/finish.rs": {"finish_interrupted_shutdown", "close_session"},
    "writable_start/shared_finish.rs": {"finish_bound_store", "finish_with"},
    "writable_start/sync.rs": {"attach_sync", "observe_engine_view"},
    "writable_start/sync/tests.rs": {"sync_mount_error_table_rows"},
}
TESTS = {
    "attach/control/tests.rs",
    "attach/control/testkit.rs",
    "attach/control/endpoint/tests.rs",
    "attach/control/client/tests.rs",
    "attach/control/service/tests.rs",
    "attach/control/support/tests.rs",
    "attach/control/transport/tests.rs",
    "attach/metrics_export/tests.rs",

    "tests.rs", "tests/tokio_signal_feature.rs", "attach/tests.rs", "support_bundle/tests.rs",
    "attach/tests/daemon_linux.rs", "attach/tests/bounded_unmount.rs", "attach/mount_table/tests.rs", "admission/tests.rs", "sink/tests.rs",
    "keys/tests.rs", "path_separation/tests.rs", "publish_config/tests.rs",
    "terminal/tests.rs", "publication/tests.rs", "publication_report/tests.rs", "recover/tests.rs",
    "overlay_discard/tests.rs", "overlay_discard/reconcile/tests.rs",
    "logging/tests.rs", "sink/tests/fixtures.rs", "tests/observability_scan.rs",
}
# These are item identities, never spans. Their bodies belong to other verbs.
OUTSIDE = {
    "main.rs": {
        "cmd_harvest", "cmd_harvest_with_credentials", "cmd_publish",
        "cmd_publish_with_credentials", "cmd_cat", "cmd_cat_with_credentials",
        "cmd_verify", "cmd_verify_with_credentials", "cmd_thresh",
        "cmd_thresh_with_credentials", "CacheOnDrop::drop",
    },

    "keys.rs": {"load_or_create_key_with_identity", "load_existing_key_from_paths"},
}
REQUIRED = {
    "attach/control.rs": {"wire_result", "mount_result", "peer_admitted"},
    "attach/control/client.rs": {"exchange", "umount"},
    "attach/control/endpoint.rs": {"Endpoint::bind", "Directory::open"},
    "attach/control/service.rs": {"serve", "Control::start", "Control::finish"},
    "attach/control/support.rs": {"answer", "request", "serve", "Support::start"},
    "attach/control/transport.rs": {"allocate_body"},
    "attach/metrics_export.rs": {"Options::prepare", "read_configuration", "start_with", "start", "record_event"},
    "main.rs": {"main", "usage", "usage_text", "cmd_mount_gran", "env_filter_from",
                "pins_from", "cache_origin", "wire_snapshot_args", "parse_cat_seq",
                "write_wire_snapshot_if_requested"},
    "attach.rs": {"mount_attempt_with_credentials", "run_fuse_daemon", "cmd_mount",
                  "emit_breakage_banner", "parse_mount", "parse_mount_gran",
                  "mount_preflight", "mount_requires_foreground", "run_coordinator"},
    # The preflight entry has separate platform definitions. Anchor its
    # unique bounded-reader helper instead; every definition is still scanned.
    "attach/mount_table.rs": {"read_bounded", "still_mounted_via_findmnt"},
    "admission.rs": {"process_credentials", "set_id_refusal"},
    "sink.rs": {"sink_to", "worker"},
    "terminal.rs": {"write_line", "write_line_to", "install_panic_hook", "report_panic"},
    "logging.rs": {"prepare", "install", "resolve", "read_config_file", "open_log"},
    "keys.rs": {"load_signing_key_only", "canonical_seed_paths"},
    "path_separation.rs": {"refuse_managed_paths", "refuse_tls_key_directory"},
    "publish_config.rs": {"PublishConfiguration::load", "PublishConfiguration::validate",
                          "PublishConfiguration::protected_files"},
}


class Blind(Exception):
    pass


def need(ok, message):
    if not ok:
        raise Blind(message)


def lex(source):
    """Rust tokens with source offsets; refuse incomplete lexical boundaries."""
    out = []
    i = 0
    while i < len(source):
        start = i
        if source[i].isspace():
            i += 1
            continue
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", i):
            depth = 1
            i += 2
            while i < len(source) and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            need(depth == 0, "unterminated block comment")
            continue
        raw = re.match(r'(?:br|cr|r)(#*)"', source[i:])
        if raw:
            end_mark = '"' + raw[1]
            end = source.find(end_mark, i + raw.end())
            need(end >= 0, "unterminated raw string")
            i = end + len(end_mark)
        elif source[i] == '"' or source[i:i+2] in ('b"', 'c"'):
            i += 1 if source[i] == '"' else 2
            while i < len(source) and source[i] != '"':
                i += 2 if source[i] == "\\" else 1
            need(i < len(source), "unterminated string")
            i += 1
        else:
            char = re.match(r"(?:b)?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'", source[i:])
            word = re.match(r"[A-Za-z_][A-Za-z_0-9]*|::|=>|->", source[i:])
            i += char.end() if char else word.end() if word else 1
        # Rust's escaped physical newline consumes the following whitespace.
        value = re.sub(r"\\\n\s*", "", source[start:i])
        out.append((value, start))
    return out


def values(source):
    return [token for token, _ in lex(source)]


def find_all(tokens, needle):
    return [i for i in range(len(tokens) - len(needle) + 1)
            if tokens[i:i+len(needle)] == needle]


def unique(tokens, spelling, label):
    hits = find_all(tokens, values(spelling))
    need(len(hits) == 1, f"missing or ambiguous anchor: {label}")
    return hits[0]


class Source:
    def __init__(self, path):
        self.text = path.read_text()
        lexed = lex(self.text)
        self.t = [v for v, _ in lexed]
        self.offsets = [p for _, p in lexed]
        self.pairs = {}
        stack = []
        for i, token in enumerate(self.t):
            if token in ("(", "[", "{"):
                stack.append(i)
            elif token in (")", "]", "}"):
                need(stack and self.t[stack[-1]] == {")": "(", "]": "[", "}": "{"}[token],
                     f"unbalanced Rust boundary in {path}")
                opening = stack.pop()
                self.pairs[opening] = i
        need(not stack, f"unclosed Rust boundary in {path}")
        # Locate impl containers before functions, so a method never inherits
        # the name of the last free function above it.
        impls = []
        for i, token in enumerate(self.t):
            if token == "impl":
                body = self.body_after(i + 1)
                if body is not None:
                    header = self.t[i+1:body]
                    if "for" in header:
                        header = header[header.index("for")+1:]
                    if header and re.fullmatch(r"\w+", header[0]):
                        impls.append((body, self.pairs[body], header[0]))
        self.items = []
        for i, token in enumerate(self.t[:-1]):
            if token != "fn" or not re.fullmatch(r"[A-Za-z_]\w*", self.t[i+1]):
                continue
            body = self.body_after(i + 2)
            if body is None:  # An extern declaration has no body to scan.
                continue
            name = self.t[i+1]
            parents = [p for p in impls if p[0] < i < p[1]]
            if parents:
                name = max(parents)[2] + "::" + name
            self.items.append((i, self.pairs[body], name))

    def body_after(self, i):
        while i < len(self.t):
            if self.t[i] == "{":
                return i
            if self.t[i] == ";":
                return None
            i = self.pairs[i] + 1 if self.t[i] in ("(", "[") else i + 1
        return None

    def item(self, name):
        hits = [(a, b) for a, b, n in self.items if n == name]
        need(len(hits) == 1, f"missing or ambiguous enclosing item: {name}")
        return hits[0]

    def enclosing(self, pos):
        hits = [(a, n) for a, b, n in self.items if a <= pos <= b]
        return max(hits)[1] if hits else "<module>"

    def line(self, pos):
        return self.text.count("\n", 0, self.offsets[pos]) + 1


def imports_stream(source, start, end, prefix=()):
    """Walk a use tree, including nested groups, renames and glob imports."""
    t = source.t
    path = prefix
    i = start
    while i < end:
        if t[i] == "{":
            close = source.pairs[i]
            child = i + 1
            j = child
            while j < close:
                if t[j] == ",":
                    if imports_stream(source, child, j, path):
                        return True
                    child = j + 1
                j = source.pairs[j] + 1 if t[j] == "{" else j + 1
            return imports_stream(source, child, close, path)
        if t[i] == "as":
            if path in (("std", "io"), ("std", "io", "self")):
                return True
            break
        if t[i] != "::":
            path += (t[i],)
        i += 1
    return path in (("std", "io", "stderr"), ("std", "io", "stdout"), ("std", "io", "*"))


def remaps_module(source, attribute):
    t = source.t
    end = source.pairs[attribute + 1]
    if not find_all(t[attribute+2:end], ["path", "="]):
        return False
    i = end + 1
    # An attribute can precede other attributes and restricted visibility.
    while t[i:i+2] == ["#", "["]:
        i = source.pairs[i+1] + 1
    if t[i:i+1] == ["pub"]:
        i += 1
        if t[i:i+1] == ["("]:
            i = source.pairs[i] + 1
    return t[i:i+1] == ["mod"]


# No terminal exceptions: only the two owned-destination constructions below.

SYNC_REFUSAL_FORWARDERS = {
    ("writable_store.rs", "refused"),  # Preserves the identifier after recording its session failure class.
    ("writable_store.rs", "ownership_verdict"),  # Preserves the refusal payload while converting the grant verdict.
    ("overlay_store.rs", "OverlayError::refused"),  # Preserves the identifier after recording an overlay failure.
    ("writable_start/sync.rs", "refused"),  # Wraps the caller's identifier in the coordination error.
    ("writable_start/sync.rs", "overlay_error"),  # Carries the coordination refusal identifier into the overlay error.
    ("writable_start/sync.rs", "sync_mount_error"),  # Sends a wrapped identifier back through the coordination mapping.
    ("sync/engine.rs", "refused"),  # Wraps the engine caller's identifier in the coordination error.
}


def sync_refusal_sources():
    # Scan a conservative superset of engine callees, including startup and
    # recovery in the same mediator/overlay modules. New helper files join it.
    paths = [CLIENT_SRC / f"{name}.rs" for name in ("sync", "writable_store", "overlay_store")]
    paths.append(CLIENT_SRC / "writable_start/sync.rs")

    def walk(directory):
        need(directory.is_dir() and not directory.is_symlink(), f"missing sync refusal directory: {directory}")
        for path in sorted(directory.iterdir()):
            need(not path.is_symlink(), f"symlinked sync refusal source: {path}")
            if path.name == "tests" or path.name == "tests.rs":
                continue
            if path.is_dir():
                walk(path)
            elif path.suffix == ".rs":
                paths.append(path)

    for name in ("sync", "writable_store", "overlay_store"):
        walk(CLIENT_SRC / name)
    return paths


def sync_refusal_identifiers():
    reasons = set()
    paths = sync_refusal_sources()
    for name, _ in SYNC_REFUSAL_FORWARDERS:
        need(CLIENT_SRC / name in paths, f"unscanned sync refusal forwarding source: {name}")
    for path in paths:
        need(path.is_file() and not path.is_symlink(), f"missing sync refusal source: {path}")
        source = Source(path)
        t = source.t
        name = path.relative_to(CLIENT_SRC).as_posix()
        for forward_path, item in SYNC_REFUSAL_FORWARDERS:
            if forward_path == name:
                source.item(item)
        excluded = []
        for start in find_all(t, values("#[cfg(test)] mod")):
            module = start + len(values("#[cfg(test)] mod"))
            if re.fullmatch(r"[A-Za-z_]\w*", t[module]) and t[module+1:module+2] == ["{"]:
                opening = module + 1
                excluded.append((start, source.pairs[opening]))
        for i, token in enumerate(t):
            if token not in ("refused", "Refused") or t[i+1:i+2] != ["("]:
                continue
            if any(start <= i <= end for start, end in excluded):
                continue
            end = source.pairs[i+1]
            arguments = t[i+2:end]
            # Function/variant declarations and match bindings do not construct errors.
            if t[i-1:i] == ["fn"] or arguments == values("&'static str"):
                continue
            literal = all(value.startswith('"') or value in ("|", ",") for value in arguments)
            if not literal and t[end+1:end+2] in (["=>"], ["if"]):
                continue
            need(literal or (name, source.enclosing(i)) in SYNC_REFUSAL_FORWARDERS,
                 f"nonliteral sync refusal: {path}:{source.line(i)}")
            if literal:
                reasons.update(value for value in arguments if value.startswith('"'))
    need(bool(reasons), "empty sync refusal source inventory")
    return reasons


def check_sync_refusals():
    reasons = sync_refusal_identifiers()
    source = Source(CLIENT_SRC / "writable_start/sync/tests.rs")
    start, end = source.item("sync_mount_error_engine_refusal_identifiers")
    unique(source.t[start:end], "for (reason, expected) in rows", "sync refusal row iteration")
    unique(source.t[start:end], "sync_mount_error(&refused(reason))", "sync refusal mapping assertion")
    unique(source.t[start:end], "sync_mount_error(&CoordinationError::Overlay(OverlayError::Refused(reason)))", "overlay refusal mapping assertion")
    rows = [source.t[i+1] for i in range(start, end)
            if source.t[i] == "(" and source.t[i+1].startswith('"') and source.t[i+2] == ","]
    need(len(rows) == len(set(rows)), "duplicate sync refusal table row")
    need(reasons == set(rows),
         f"sync refusal table differs from engine/store sources; missing={sorted(reasons - set(rows))}, extra={sorted(set(rows) - reasons)}")


def scan():
    need(SRC.is_dir() and not SRC.is_symlink(), f"missing or symlinked source root: {SRC}")
    expected = PRODUCTION | OTHER_VERBS | TESTS
    for path in SRC.rglob("*"):
        need(not path.is_symlink(), f"symlinked source boundary: {path}")
    actual = {str(p.relative_to(SRC)) for p in SRC.rglob("*.rs")}
    need(actual == expected,
         f"source inventory changed; missing={sorted(expected - actual)}, new={sorted(actual - expected)}")
    sources = {name: Source(SRC / name) for name in sorted(PRODUCTION | OTHER_VERBS)}
    for name in TESTS:
        t = values((SRC / name).read_text())
        need(bool(find_all(t, values("#![cfg(test)]"))), f"test boundary changed: {name}")
    for name, source in sources.items():
        t = source.t
        unique(t, "#[cfg(test)] mod tests;", f"{name} out-of-line tests")
        # This is a closed physical source inventory, not a macro expander.
        need(not find_all(t, values("#[path")), f"remapped source boundary: {name}")
        for attribute in find_all(t, ["#", "["]):
            need(not remaps_module(source, attribute), f"remapped source boundary: {name}")
        for macro in ("include", "include_str", "include_bytes", "macro_rules"):
            need(not find_all(t, [macro, "!"]), f"unscanned source expansion: {name}: {macro}!")
        names = {n for _, _, n in source.items}
        guarded = REQUIRED.get(name, set())
        for item in sorted(guarded):
            # Include methods and nested functions sharing a guarded name:
            # neither may borrow a free function's destination construction.
            leaf = item.rsplit("::", 1)[-1]
            occurrences = [a for a, _, _ in source.items if t[a+1] == leaf]
            need(len(occurrences) <= 1, f"duplicate guarded item name: {name}::{leaf}")
        for anchor in REQUIRED.get(name, set()) | OUTSIDE.get(name, set()):
            need(anchor in names, f"missing required anchor: {name}::{anchor}")

    for name, anchors in CLIENT_HELPERS.items():
        path = CLIENT_SRC / name
        need(path.is_file() and not path.is_symlink(), f"missing or symlinked common mount helper: {name}")
        source = Source(path)
        modules = find_all(source.t, ["mod"])
        if name == "local_report.rs":
            test_start = unique(source.t, "#[cfg(test)] mod tests;", "typed report test boundary")
            need(modules == [test_start + len(values("#[cfg(test)]"))], "unlisted typed report module")
            test_path = CLIENT_SRC / "local_report/tests.rs"
            need(test_path.is_file() and not test_path.is_symlink(), "missing or symlinked typed report tests")
        elif name == "writable_start.rs":
            sync_start = unique(source.t, "mod sync;", "writable start sync module")
            finish_start = unique(source.t, "mod finish;", "writable start finish module")
            shared_start = unique(source.t, "mod shared_finish;", "writable start shared finish module")
            need(modules == sorted([finish_start, shared_start, sync_start]), "unlisted common mount helper module: writable_start.rs")
            need("writable_start/finish.rs" in CLIENT_HELPERS, "finish phase missing from common helper inventory")
            need("writable_start/shared_finish.rs" in CLIENT_HELPERS, "shared finish missing from common helper inventory")
        elif name == "writable_start/sync.rs":
            test_start = unique(source.t, "#[cfg(test)] mod tests;", "sync test boundary")
            need(modules == [test_start + len(values("#[cfg(test)]"))], "unlisted sync helper module")
            need("writable_start/sync/tests.rs" in CLIENT_HELPERS, "sync tests missing from common helper inventory")
        else:
            need(not modules, f"unlisted common mount helper module: {name}")
        need(not find_all(source.t, values("#[path")), f"remapped common helper: {name}")
        for attribute in find_all(source.t, ["#", "["]):
            need(not remaps_module(source, attribute), f"remapped common helper: {name}")
        for anchor in anchors:
            source.item(anchor)
        for i, token in enumerate(source.t):
            if token in ("eprintln", "println", "eprint", "print", "dbg", "include", "include_str", "include_bytes") and source.t[i+1:i+2] == ["!"]:
                print(f"mount-write-path: FAIL: common mount helper bare write or source expansion: {name}", file=sys.stderr)
                return 1
            if token in ("stderr", "stdout") and source.t[i+1:i+2] == ["("] and source.t[max(0, i-1):i] != ["."]:
                print(f"mount-write-path: FAIL: common mount helper stream handle: {name}", file=sys.stderr)
                return 1
            if token == "use":
                end = i + 1
                while end < len(source.t) and source.t[end] != ";":
                    end = source.pairs[end] + 1 if source.t[end] == "{" else end + 1
                need(end < len(source.t), f"unclosed common helper import: {name}")
                if imports_stream(source, i + 1, end):
                    print(f"mount-write-path: FAIL: common mount helper stream import: {name}", file=sys.stderr)
                    return 1

    check_sync_refusals()
    exclusions = {name: [source.item(n) for n in OUTSIDE.get(name, set())]
                  for name, source in sources.items()}
    main = sources["main.rs"]
    a, b = main.item("main")
    # Exclude only the balanced bodies of OTHER verb arms in main's final
    # dispatch. The mount and umount arms, pre-dispatch code and fallback remain scanned.
    dispatch = unique(main.t, 'match args.first().and_then(|c| c.to_str()) {', "main verb dispatch")
    opening = main.body_after(dispatch + 1)
    need(a < dispatch < opening < main.pairs[opening] == b - 1, "moved main dispatch boundary")
    arms = []
    i = opening + 1
    while i < main.pairs[opening]:
        end = i
        while end < main.pairs[opening] and main.t[end] != ",":
            if main.t[end] == "{" and main.t[main.pairs[end] + 1] in ("Some", "_"):
                # Rust permits a block arm without a comma. The following arm
                # still has to match its exact closed inventory header below.
                end = main.pairs[end]
                break
            end = main.pairs[end] + 1 if main.t[end] in ("(", "[", "{") else end + 1
        arms.append((i, end))
        i = end + 1
    headers = {
        "thresh": 'Some("thresh") => match rest {',
        "harvest": 'Some("harvest") => match rest {',
        "publish": 'Some("publish") => {',
        "recover": 'Some("recover") => match recover::parse(rest, &|name| std::env::var(name).ok()) {',
        "cat": 'Some("cat") => match parse_cat(rest) {',
        "verify": 'Some("verify") => match parse_verify(rest) {',
        "mount": 'Some("mount") => match parse_mount(rest) {',
        "umount": 'Some("umount") => match parse_umount(rest) {',
        "fallback": '_ => usage()',
    }
    seen = set()
    for start, end in arms:
        matches = [key for key, header in headers.items()
                   if main.t[start:start+len(values(header))] == values(header)]
        need(len(matches) == 1, "moved main verb arm boundary")
        key = matches[0]
        need(key not in seen, f"duplicate main verb arm: {key}")
        seen.add(key)
        if key not in ("mount", "umount", "fallback"):
            exclusions["main.rs"].append((start, end))
    need(seen == set(headers), "missing main verb arm anchor")
    sink_statement = "let (log_sink, _log_worker) = sink::sink_to(logging::Destination::with_policy(original_stderr, log_file, log_settings.format, log_settings.paths, bundle_history.clone(),));"
    sink_start = unique(main.t, sink_statement, "owned sink destination in main")
    need(a < sink_start < dispatch, "moved sink destination boundary")
    capture_statement = "let original_stderr = match logging::capture_stderr(&std::io::stderr()) {"
    capture_start = unique(main.t, capture_statement, "captured original stderr")
    need(a < capture_start < sink_start, "original stderr must precede sink construction")
    sink_handle = unique(main.t[capture_start:capture_start+len(values(capture_statement))],
                         "stderr()", "captured sink destination handle") + capture_start
    hook_start = unique(main.t, "terminal::install_panic_hook();", "panic hook installation")
    need(a < hook_start < sink_start, "panic hook must precede the sink")
    direct = sources["terminal.rs"]
    start, end = direct.item("write_line")
    direct_statement = "write_line_to(std::io::stderr(), message, WRITE_BOUND);"
    direct_start = unique(direct.t, direct_statement, "bounded direct destination")
    need(start < direct_start < end, "moved bounded direct destination boundary")
    direct_handle = unique(direct.t[direct_start:direct_start+len(values(direct_statement))],
                           "stderr()", "bounded direct destination handle") + direct_start
    owned_handles = {("main.rs", sink_handle), ("terminal.rs", direct_handle)}
    violations = []
    for name in sorted(PRODUCTION):
        source = sources[name]
        t = source.t
        for i, token in enumerate(t):
            if token == "use":
                end = i + 1
                while end < len(t) and t[end] != ";":
                    end = source.pairs[end] + 1 if t[end] == "{" else end + 1
                need(end < len(t), f"unclosed import boundary: {name}:{source.line(i)}")
                if imports_stream(source, i + 1, end):
                    print(f"mount-write-path: FAIL: a standard-stream handle import or renamed std::io module at {SRC / name}:{source.line(i)}", file=sys.stderr)
                    return 1
            if any(start <= i <= end for start, end in exclusions[name]):
                continue
            end = None
            if token in ("eprintln", "println", "eprint", "print", "dbg") and t[i+1:i+2] == ["!"]:
                need(t[i+2] in ("(", "[", "{"), f"unreadable macro boundary: {name}:{source.line(i)}")
                end = source.pairs[i+2] + 1
            if token in ("stderr", "stdout") and t[i+1:i+2] == ["("] and t[max(0, i-1):i] != ["."]:
                end = source.pairs[i+1] + 1
            if end is None or (name, i) in owned_handles:
                continue
            item = source.enclosing(i)
            violations.append(f"  {SRC / name}:{source.line(i)}: {item}: {' '.join(t[i:end])}")
    if violations:
        print("mount-write-path: FAIL: a bare standard-stream write outside owned destination construction", file=sys.stderr)
        print("\n".join(violations), file=sys.stderr)
        return 1
    print("mount write path: ok")
    return 0


def self_test():
    # Each refusal asserts its own reason, not merely a nonzero exit status.
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        (root / "scripts").mkdir()
        gate = root / "scripts/check-mount-write-path.sh"
        shutil.copyfile(pathlib.Path("scripts/check-mount-write-path.sh"), gate)
        shutil.copytree(SRC, root / SRC)
        (root / CLIENT_SRC).mkdir(parents=True)
        for name in CLIENT_HELPERS:
            (root / CLIENT_SRC / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(CLIENT_SRC / name, root / CLIENT_SRC / name)
        for path in sync_refusal_sources():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, root / path)
        (root / CLIENT_SRC / "local_report").mkdir()
        shutil.copyfile(CLIENT_SRC / "local_report/tests.rs", root / CLIENT_SRC / "local_report/tests.rs")
        originals = {name: (root / SRC / name).read_text()
                     for name in PRODUCTION | {"keys.rs", "path_separation.rs", "publish_config.rs"}}
        cases = 0

        def expect(label, rc, message, *args):
            nonlocal cases
            run = subprocess.run(["bash", str(gate), *args], text=True, capture_output=True)
            output = run.stdout + run.stderr
            if run.returncode != rc or message not in output:
                print(f"mount-write-path self-test FAILED: {label}: cases={cases + 1}; rc={run.returncode}, want {rc}, reason={message!r}\n{output}", file=sys.stderr)
                raise SystemExit(2)
            print(f"self-test: {label} -> rc={rc}, and it named its own reason")
            cases += 1

        def replace(name, old, new):
            text = originals[name]
            need(text.count(old) == 1, f"self-test fixture anchor missing or ambiguous: {old}")
            (root / SRC / name).write_text(text.replace(old, new, 1))

        def restore(name):
            (root / SRC / name).write_text(originals[name])

        expect("sync refusal complete table", 0, "mount write path: ok")
        nonliteral_cases = [
            ("raw-string first argument", 'fn unlisted() { refused(r"IntentRegister"); }\n'),
            ("constant first argument", 'const REASON: &str = "IntentRegister"; fn unlisted() { refused(REASON); }\n'),
            ("unlisted forwarding function", "fn unlisted(reason: &'static str) { CoordinationError::Refused(reason); }\n"),
        ]
        helper = root / CLIENT_SRC / "writable_start/sync.rs"
        original = helper.read_text()
        for label, fixture in nonliteral_cases:
            helper.write_text(original + '\n' + fixture)
            expect(label, 2, "nonliteral sync refusal")
        helper.write_text(original)
        expect("nonliteral fixture restored", 0, "mount write path: ok")
        for name, item in sorted(SYNC_REFUSAL_FORWARDERS):
            helper = root / CLIENT_SRC / name
            original = helper.read_text()
            source = Source(helper)
            start, _ = source.item(item)
            opening = source.body_after(start + 2)
            at = source.offsets[opening] + 1
            helper.write_text(original[:at] + '\nlet forwarded = "IntentRegister"; let _ = crate::CoordinationError::Refused(forwarded);\n' + original[at:])
            expect(f"listed forwarder: {name}::{item}", 0, "mount write path: ok")
            helper.write_text(original)
        helper = root / CLIENT_SRC / "writable_store/unlisted.rs"
        module = 'mod other_tests { fn fixture() { refused("TestOnlyRefusal"); } }\n'
        helper.write_text('#[cfg(test)]\n' + module)
        expect("sync refusal differently named test module", 0, "mount write path: ok")
        helper.write_text(module)
        expect("sync refusal production module remains scanned", 2, "sync refusal table differs from engine/store sources; missing=['\"TestOnlyRefusal\"']")
        helper.unlink()
        refusal_tests = root / CLIENT_SRC / "writable_start/sync/tests.rs"
        refusal_original = refusal_tests.read_text()
        row = '("WritableRecoveryRequired", S::Backend(M::Io)),'
        need(refusal_original.count(row) == 1, "sync refusal row fixture anchor")
        refusal_tests.write_text(refusal_original.replace(row, "", 1))
        expect("sync refusal missing row", 2, "sync refusal table differs from engine/store sources; missing=['\"WritableRecoveryRequired\"']")
        refusal_tests.write_text(refusal_original.replace(row, row + row, 1))
        expect("sync refusal duplicate row", 2, "duplicate sync refusal table row")
        refusal_tests.write_text(refusal_original.replace("sync_mount_error(&refused(reason))", "unwired(reason)", 1))
        expect("sync refusal assertion wiring", 2, "sync refusal mapping assertion")
        refusal_tests.write_text(refusal_original.replace("sync_mount_error(&CoordinationError::Overlay(OverlayError::Refused(reason)))", "unwired(reason)", 1))
        expect("overlay refusal assertion wiring", 2, "overlay refusal mapping assertion")
        refusal_tests.write_text(refusal_original)
        helper = root / CLIENT_SRC / "writable_store/unlisted.rs"
        helper.write_text('fn new_guard() { refused("NewEngineRefusal"); }\n')
        expect("sync refusal new helper reason", 2, "sync refusal table differs from engine/store sources; missing=['\"NewEngineRefusal\"']")
        helper.unlink()
        expect("sync refusal helper restored", 0, "mount write path: ok")
        gate_contents = gate.read_text()
        reader = "        self.text =" + " path.read_text()"
        need(gate_contents.count(reader) == 1, "sync refusal reader fixture anchor")
        gate.write_text(gate_contents.replace(
            reader,
            '        if path.as_posix().endswith("writable_store/content.rs"):\n'
            '            raise PermissionError("synthetic sync refusal read denial")\n' + reader,
            1,
        ))
        expect("sync refusal failure-to-read", 2, "synthetic sync refusal read denial")
        gate.write_text(gate_contents)
        expect("sync refusal reader restored", 0, "mount write path: ok")

        for name in CLIENT_HELPERS:
            helper = root / CLIENT_SRC / name
            original = helper.read_bytes()
            helper.write_bytes(original + b'\nfn planted_common_helper() { eprintln!("PLANTED"); }\n')
            expect(f"common helper bare write: {name}", 1, "FAIL: common mount helper bare write")
            helper.write_bytes(original)
            helper.unlink()
            expect(f"common helper missing: {name}", 2, "THE GUARD IS BLIND (guard is blind): missing or symlinked common mount helper")
            helper.symlink_to("absent-common-helper")
            expect(f"common helper symlink: {name}", 2, "THE GUARD IS BLIND (guard is blind): missing or symlinked common mount helper")
            helper.unlink()
            helper.write_bytes(original)
            expect(f"common helper restored: {name}", 0, "mount write path: ok")

        refusal = "FAIL: a bare standard-stream write outside owned destination construction"
        blind = "THE GUARD IS BLIND (guard is blind)"
        for name in ("recover.rs", "recover/tests.rs"):
            path = root / SRC / name
            saved = path.read_bytes()
            path.unlink()
            expect(f"missing recovery source: {name}", 2, blind + ": source inventory changed")
            path.write_bytes(saved)
            expect(f"recovery source restored: {name}", 0, "mount write path: ok")
        path = root / SRC / "recover/tests.rs"
        saved = path.read_text()
        path.write_text(saved.replace("#![cfg(test)]", "#![cfg(unix)]", 1))
        expect("recovery test boundary", 2, blind + ": test boundary changed: recover/tests.rs")
        path.write_text(saved)
        gate_contents = gate.read_text()
        header = '''        "recover": 'Some("recover") => match recover::parse(rest, &|name| std::env::var(name).ok()) {',\n'''
        need(gate_contents.count(header) == 1, "recovery dispatch inventory fixture anchor")
        gate.write_text(gate_contents.replace(header, "", 1))
        expect("recovery dispatch inventory wiring", 2, blind + ": moved main verb arm boundary")
        gate.write_text(gate_contents)
        reader = "        self.text =" + " path.read_text()"
        need(gate_contents.count(reader) == 1, "recovery source reader fault anchor")
        gate.write_text(gate_contents.replace(
            reader,
            '        if path.name == "recover.rs":\n'
            '            raise PermissionError("synthetic recovery source read denial")\n' + reader,
            1,
        ))
        expect("recovery failure-to-read", 2, blind + ": synthetic recovery source read denial")
        gate.write_text(gate_contents)
        expect("recovery inventory restored", 0, "mount write path: ok")
        sync_helper = root / CLIENT_SRC / "writable_start/sync.rs"
        sync_original = sync_helper.read_text()
        need(sync_original.count("#[cfg(test)]\nmod tests;") == 1, "sync test boundary fixture anchor")
        sync_helper.write_text(sync_original.replace("#[cfg(test)]\nmod tests;", "mod tests;", 1))
        expect("sync tests require test boundary", 2, blind + ": missing or ambiguous anchor: sync test boundary")
        sync_helper.write_text(sync_original + "\nmod unlisted;\n")
        expect("sync helper refuses extra module", 2, blind + ": unlisted sync helper module")
        sync_helper.write_text(sync_original)
        expect("sync test boundary restored", 0, "mount write path: ok")
        gate_contents = gate.read_text()
        inventory = '    "writable_start/sync/tests.rs": {"sync_mount_error_table_rows"},\n'
        need(gate_contents.count(inventory) == 1, "sync test inventory fixture anchor")
        gate.write_text(gate_contents.replace(inventory, "", 1))
        expect("sync test inventory wiring", 2, blind + ": sync tests missing from common helper inventory")
        gate.write_text(gate_contents)
        reader = "        self.text =" + " path.read_text()"
        need(gate_contents.count(reader) == 1, "sync test reader fault anchor")
        gate.write_text(gate_contents.replace(
            reader,
            '        if path.as_posix().endswith("writable_start/sync/tests.rs"):\n'
            '            raise PermissionError("synthetic sync test read denial")\n' + reader,
            1,
        ))
        expect("sync tests failure-to-read", 2, blind + ": synthetic sync test read denial")
        gate.write_text(gate_contents)
        expect("sync test reader restored", 0, "mount write path: ok")
        start_helper = root / CLIENT_SRC / "writable_start.rs"
        start_original = start_helper.read_text()
        start_helper.write_text(start_original + "\nmod unlisted;\n")
        expect("writable start refuses extra module", 2, blind + ": unlisted common mount helper module: writable_start.rs")
        need(start_original.count("mod finish;") == 1, "writable start finish module fixture anchor")
        start_helper.write_text(start_original.replace("mod finish;", "", 1))
        expect("writable start requires its finish module", 2, blind + ": missing or ambiguous anchor: writable start finish module")
        start_helper.write_text(start_original)
        gate_contents = gate.read_text()
        inventory = '    "writable_start/shared_finish.rs": {"finish_bound_store", "finish_with"},\n'
        need(gate_contents.count(inventory) == 1, "finish inventory fixture anchor")
        gate.write_text(gate_contents.replace(inventory, "", 1))
        expect("finish inventory wiring", 2, blind + ": shared finish missing from common helper inventory")
        gate.write_text(gate_contents)
        expect("writable start modules restored", 0, "mount write path: ok")
        for name, target_mod in (("writable_start.rs", "mod sync;"),
                                 ("local_report.rs", "#[cfg(test)]\nmod tests;")):
            helper = root / CLIENT_SRC / name
            original_text = helper.read_text()
            for label, attribute in (
                (f"conditional common helper module path: {name}", '#[cfg_attr(unix, path = "elsewhere.rs")]'),
                (f"nested conditional common helper module path: {name}", '#[cfg_attr(unix, cfg_attr(test, path = "elsewhere.rs"))]'),
            ):
                need(original_text.count(target_mod) == 1, f"common helper module anchor missing: {name}")
                helper.write_text(original_text.replace(target_mod, attribute + "\n" + target_mod, 1))
                expect(label, 2, blind + f": remapped common helper: {name}")
                helper.write_text(original_text)
        expect("baseline — the unmutated fixture passes", 0, "mount write path: ok")
        owner_cases = cases
        umount_site = "Ok(mountpoint) => cmd_umount(&mountpoint, &mut mount_log),"
        replace("main.rs", umount_site, 'Ok(mountpoint) => { eprintln!("PLANTED"); cmd_umount(&mountpoint, &mut mount_log) },')
        expect("owner command dispatch bare write", 1, refusal)
        restore("main.rs")
        gate_contents = gate.read_text()
        reader = "        self.text =" + " path.read_text()"
        need(gate_contents.count(reader) == 1, "owner command reader fault anchor")
        gate.write_text(gate_contents.replace(reader,
            '        if path.name == "main.rs":\n'
            '            raise PermissionError("synthetic owner dispatch read denial")\n' + reader, 1))
        expect("owner command dispatch failure-to-read", 2, blind + ": synthetic owner dispatch read denial")
        gate.write_text(gate_contents)
        expect("owner command dispatch restored", 0, "mount write path: ok")
        need(cases - owner_cases == 3, "owner command paired controls must exercise three cases")
        print(f"self-test: owner command paired controls cases={cases - owner_cases}")
        control_count = 0
        for name in sorted(item for item in PRODUCTION if item.startswith("attach/control")):
            control_cases = cases
            helper = root / SRC / name
            original = helper.read_bytes()
            helper.write_bytes(original + b'\nfn planted_control_helper() { eprintln!("PLANTED"); }\n')
            expect(f"control helper bare write: {name}", 1, refusal)
            helper.write_bytes(original)
            expect(f"control helper restored: {name}", 0, "mount write path: ok")
            gate_contents = gate.read_text()
            inventory = f'    "{name}",\n'
            need(gate_contents.count(inventory) == 1, f"control helper inventory anchor: {name}")
            gate.write_text(gate_contents.replace(inventory, "", 1))
            expect(f"control helper inventory wiring: {name}", 2, blind + ": source inventory changed")
            gate.write_text(gate_contents)
            reader = "        self.text =" + " path.read_text()"
            need(gate_contents.count(reader) == 1, "control reader fault anchor")
            gate.write_text(gate_contents.replace(reader,
                f'        if path.as_posix().endswith("{name}"):\n'
                '            raise PermissionError("synthetic control helper read denial")\n' + reader, 1))
            expect(f"control helper failure-to-read: {name}", 2, blind + ": synthetic control helper read denial")
            gate.write_text(gate_contents)
            expect(f"control helper reader restored: {name}", 0, "mount write path: ok")
            need(cases - control_cases == 5, f"control helper paired controls must exercise five cases: {name}")
            print(f"self-test: control helper paired controls: {name}; cases={cases - control_cases}")
            control_count += 1
        need(control_count == 6, "control helper paired controls must cover six nonempty subjects")
        support_test_cases = cases
        support_tests = root / SRC / "attach/control/support/tests.rs"
        support_tests_original = support_tests.read_text()
        support_tests.unlink()
        expect(
            "support tests inventory wiring",
            2,
            blind + ": source inventory changed",
        )
        support_tests.write_text(support_tests_original.replace("#![cfg(test)]", "", 1))
        expect(
            "support tests require test boundary",
            2,
            blind + ": test boundary changed: attach/control/support/tests.rs",
        )
        support_tests.write_text(support_tests_original)
        expect("support tests restored", 0, "mount write path: ok")
        need(cases - support_test_cases == 3, "support test inventory controls must exercise three cases")
        print(f"self-test: support test inventory controls cases={cases - support_test_cases}")
        for name in ("keys.rs", "path_separation.rs", "publish_config.rs"):
            with (root / SRC / name).open("a") as out:
                out.write('\nfn planted_mount_helper() { eprintln!("PLANTED"); }\n')
            expect(f"mount helper bare write: {name}", 1, refusal)
            restore(name)
            expect(f"mount helper restored: {name}", 0, "mount write path: ok")
            (root / SRC / name).unlink()
            expect(f"missing mount helper: {name}", 2, blind + ": source inventory changed")
            restore(name)
            (root / SRC / name).unlink()
            (root / SRC / name).symlink_to("admission.rs")
            expect(f"symlinked mount helper: {name}", 2, blind + ": symlinked source boundary")
            (root / SRC / name).unlink()
            restore(name)
        replace("keys.rs", "fn load_signing_key_only(", "fn renamed_load_only(")
        expect("load-only entry missing", 2, blind + ": missing required anchor: keys.rs::load_signing_key_only")
        restore("keys.rs")
        for name, item in (("keys.rs", "load_signing_key_only"),
                           ("path_separation.rs", "refuse_managed_paths"),
                           ("publish_config.rs", "load")):
            text = originals[name]
            anchor = f"fn {item}("
            need(text.count(anchor) == 1, f"helper injection anchor: {name}::{item}")
            opening = text.index("{", text.index(anchor))
            (root / SRC / name).write_text(text[:opening + 1] + '\n eprintln!("PLANTED");' + text[opening + 1:])
            expect(f"reachable helper body: {name}", 1, refusal)
            restore(name)
        # Permission denial is not reproducible as root; invalid UTF-8 reliably
        # exercises the source reader's fail-closed branch on every host.
        (root / SRC / "keys.rs").write_bytes(b"\xff")
        expect("undecodable mount helper", 2, blind + ": 'utf-8' codec can't decode byte")
        restore("keys.rs")
        gate_contents = gate.read_text()
        reader = "        self.text =" + " path.read_text()"
        need(gate_contents.count(reader) == 1, "source reader fault anchor")
        gate.write_text(gate_contents.replace(
            reader,
            '        if path.name == "keys.rs":\n'
            '            raise PermissionError("synthetic mount helper read denial")\n' + reader,
            1,
        ))
        expect("mount helper failure-to-read", 2, blind + ": synthetic mount helper read denial")
        gate.write_text(gate_contents)
        expect("source reader restored", 0, "mount write path: ok")
        origin = "let origin = cache_origin(&margs.endpoint, &margs.tls_pins, margs.root_key.as_ref());"
        replace("attach.rs", origin, origin + '\n    eprintln!("PLANTED");')
        expect("non-terminal origin write", 1, refusal)
        restore("attach.rs")
        replace("attach.rs", origin, origin + '\n    dbg!(origin);')
        expect("debug macro write", 1, refusal)
        restore("attach.rs")
        for label, imported in (
            ("plain stream import", "use std::io::stderr;"),
            ("braced stream import", "use std::io::{self, stderr};"),
            ("renamed stream import", "use std::io::stdout as out;"),
            ("nested stream import", "use std::{io::{stdout as out, Write}};"),
            ("glob stream import", "use std::io::*;"),
            ("renamed I/O module with handle", "use std::io as io2; io2::stderr();"),
            ("braced I/O module rename", "use std::{io as out};"),
            ("self I/O module rename", "use std::io::{self as out};"),
        ):
            replace("attach.rs", origin, imported + "\n    " + origin)
            expect(label, 1, "FAIL: a standard-stream handle import")
            restore("attach.rs")
        replace("attach.rs", origin, origin + '''
    let _ = std::process::Command::new("findmnt")
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped());''')
        expect("child process stream configuration", 0, "mount write path: ok")
        restore("attach.rs")
        terminal_site = 'report(format_args!("gran mount: {e}"));\n        return Err(MountRefusal::SetIdExecution);'
        replace("attach.rs", terminal_site,
                terminal_site.replace('report(format_args!("gran mount: {e}"))', 'eprintln!("gran mount: {e}")'))
        expect("bare write before typed refusal", 1, refusal)
        restore("attach.rs")
        direct_site = "write_line_to(std::io::stderr(), message, WRITE_BOUND);"
        replace("terminal.rs", direct_site, direct_site + "\n    std::io::stderr();")
        expect("extra handle in bounded direct item", 1, refusal)
        restore("terminal.rs")
        logging_site = 'crate::terminal::write_line(format_args!("gran: {message}"));'
        replace("logging.rs", logging_site, 'eprintln!("PLANTED");')
        expect("bare write in the logging setup", 1, refusal)
        restore("logging.rs")
        mount_log_site = "let mut mount_log = log_sink.protected_writer();"
        replace("main.rs", mount_log_site, "std::io::stderr();\n    " + mount_log_site)
        expect("extra handle beside the owned sink destination", 1, refusal)
        restore("main.rs")
        replace("terminal.rs", direct_site, "write_line_to(std::io::sink(), message, WRITE_BOUND);")
        expect("missing direct destination", 2, blind + ": missing or ambiguous anchor: bounded direct destination")
        restore("terminal.rs")
        replace("terminal.rs", direct_site, direct_site + "\n    " + direct_site)
        expect("duplicate direct destination", 2, blind + ": missing or ambiguous anchor: bounded direct destination")
        restore("terminal.rs")
        replace("main.rs", "terminal::install_panic_hook();", "")
        expect("missing panic hook", 2, blind + ": missing or ambiguous anchor: panic hook installation")
        restore("main.rs")
        adapter_refusal = 'let fs = match granary_fuse::GranaryFs::new(snapshot, backend, generation, writability) {\n        Ok(fs) => fs,\n        Err(e) => {'
        replace("attach.rs", adapter_refusal, adapter_refusal + '\n            eprintln!("PLANTED");')
        expect("bare adapter refusal", 1, refusal)
        restore("attach.rs")
        duplicate_usage = '''fn usage() -> ExitCode {
    terminal::write_line(format_args!("{}", usage_text()));
    ExitCode::from(2)
}'''
        replace("main.rs", "fn usage_text() -> String {",
                "fn usage_text() -> String {\n" + duplicate_usage)
        expect("duplicate nested item", 2, blind + ": duplicate guarded item name: main.rs::usage")
        restore("main.rs")
        with (root / SRC / "main.rs").open("a") as out:
            out.write("\nstruct Planted;\nimpl Planted {\n" + duplicate_usage + "\n}\n")
        expect("duplicate method name", 2, blind + ": duplicate guarded item name: main.rs::usage")
        restore("main.rs")
        replace("main.rs", "fn usage_text() -> String {",
                "fn usage_text() -> String {\nfn usage_text() -> String { String::new() }")
        expect("duplicate required-only item", 2, blind + ": duplicate guarded item name: main.rs::usage_text")
        restore("main.rs")
        for label, attribute in (
            ("conditional module path", '#[cfg_attr(unix, path = "elsewhere.rs")]'),
            ("nested conditional module path", '#[cfg_attr(unix, cfg_attr(test, path = "elsewhere.rs"))]'),
        ):
            with (root / SRC / "attach.rs").open("a") as out:
                out.write("\n" + attribute + "\npub(crate) mod planted;\n")
            expect(label, 2, blind + ": remapped source boundary: attach.rs")
            restore("attach.rs")
        # Move an existing refusal into a new helper, replacing its diagnostic.
        # The return's terminal shape cannot authorise the helper's bare write.
        old = terminal_site
        replace("attach.rs", old, 'return planted_terminal_refusal();')
        with (root / SRC / "attach.rs").open("a") as out:
            out.write('''\nfn planted_terminal_refusal() -> Result<MountOutcome, MountRefusal> {
    eprintln!("PLANTED");
    return Err(MountRefusal::SetIdExecution);
}\n''')
        expect("terminal shape in an unlisted function", 1, refusal)
        restore("attach.rs")
        replace("attach.rs", "fn mount_attempt_with_credentials(", "fn renamed_mount_attempt(")
        expect("missing required anchor", 2, blind + ": missing required anchor: attach.rs::mount_attempt_with_credentials")
        restore("attach.rs")
        replace("attach.rs", "emit_breakage_banner(breakage.name(), log);",
                'eprintln!("{}", breakage_banner(breakage.name()));')
        expect("bare breakage banner", 1, refusal)
        restore("attach.rs")
        (root / SRC / "admission.rs").unlink()
        expect("missing source", 2, blind + ": source inventory changed")
        restore("admission.rs")
        (root / SRC / "new_helper.rs").write_text("fn new_helper() {}\n")
        expect("unlisted source", 2, blind + ": source inventory changed")
        (root / SRC / "new_helper.rs").unlink()
        replace("main.rs", "mod tests;", "mod renamed_tests;")
        expect("moved test boundary", 2, blind + ": missing or ambiguous anchor: main.rs out-of-line tests")
        restore("main.rs")
        for call in ('println!("PLANTED")', 'eprint!("PLANTED")', 'print!("PLANTED")',
                     'std::io::stderr()', 'std::io::stdout()', 'io::stderr()', 'io::stdout()',
                     'stderr()', 'stdout()', 'io2::stderr()', 'io2::stdout().lock()',
                     'io2::stderr(123)'):
            replace("attach.rs", origin, origin + f"\n    {call};")
            expect(f"bare spelling {call}", 1, refusal)
            restore("attach.rs")
        expect("unrecognised arguments", 2, "mount-write-path: unrecognised argument(s)", "self-test")
        expect("restored to clean", 0, "mount write path: ok")
        need(cases > 0, "empty self-test case set")
        print(f"mount-write-path self-test: ok; cases={cases}")
    return 0


try:
    sys.exit(self_test() if sys.argv[2] == "--self-test" else scan())
except (Blind, OSError, UnicodeError, IndexError) as error:
    print(f"mount-write-path: THE GUARD IS BLIND (guard is blind): {error}", file=sys.stderr)
    sys.exit(2)
PY
