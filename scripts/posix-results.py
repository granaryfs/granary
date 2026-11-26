#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Strict result and refusal triage for the writable POSIX venue."""

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import sys

PJD_COMMIT = "85a8aea9e685999ef0540392fd80535f873d7ff7"
XFS_COMMIT = "3d57f543ae0c149eb460574dcfb8d688aeadbfff"
PJD = tuple(f"{group}/00.t" for group in (
    "open", "mkdir", "rmdir", "rename", "unlink", "symlink",
    "truncate", "ftruncate", "chmod", "chown", "utimensat",
))
XFS = ("generic/001", "generic/005", "generic/023", "generic/035")
XFS_UTIMENS_REFUSALS = {
    "generic/005": {"count": 1, "path": r"empty_file", "hunk": "@@ -1,4 +1,5 @@"},
    "generic/023": {"count": 1, "path": r"tmp\.[^/'\n]+/foo", "hunk": "@@ -1,4 +1,5 @@"},
    "generic/035": {"count": 2, "path": r"[0-9]+/file[12]", "hunk": "@@ -1,3 +1,5 @@"},
}
PROBES = {"utimens": "ENOTSUP", "non-exec-chmod": "ENOTSUP", "exec-chmod": "0:0755"}
# The runner refuses unless effective uid 0 creates and owns the mount.
MOUNT_OWNER_UID = 0
NON_MOUNTER_REASON = ("The writable mount refuses allow_other, so the kernel denies a uid other than "
                      "the mounter's with EACCES before the filesystem sees the call.")
FIXED_ATTRIBUTES = {"mode", "ownership", "timestamp"}
CLASSES = {
    "metadata-mutations": {"chmod", "chown", "lchown", "utimensat"},
    "hardlinks": {"link", "linkat"},
    "special-files": {"mkfifo", "mknod", "bind"},
    "sparse-files": {"posix_fallocate", "fallocate"},
    "xattrs": {"setxattr", "getxattr", "listxattr", "removexattr"},
}
OPERATIONS = set().union(*CLASSES.values()) | {
    "create", "ftruncate", "lstat", "mkdir", "open", "rename", "rmdir",
    "stat", "symlink", "test_check", "truncate", "unlink",
}


class Refused(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def xfs_expected_output(tests, case, features):
    """Resolve the golden output with xfstests' _link_out_file rules."""
    base = tests / case
    config = Path(str(base) + ".cfg")
    try:
        if config.is_file():
            suffix = "default"
            for line in config.read_text().splitlines():
                fields = re.split(r" *: *", line)
                require(len(fields) == 2 and all(fields),
                        f"xfstests-evidence-unreadable: {case}: malformed output config")
                if all(option in features for option in fields[0].split(",")):
                    suffix = fields[1]
                    break
            output = Path(str(base) + ".out." + suffix)
        else:
            output = Path(str(base) + ".out")
        require(output.is_file(),
                f"xfstests-evidence-unreadable: {case}: expected output unavailable: {output}")
        with output.open("rb"):
            pass
    except (OSError, UnicodeError) as error:
        raise Refused(f"xfstests-evidence-unreadable: {case}: {error}") from error
    return output


def _xfs_mount(text, case):
    matches = re.findall(
        rf"^{re.escape(case)}\s+- output mismatch \(see (/.+/{case}.out.bad)\)$",
        text, re.MULTILINE)
    if len(matches) != 1:
        return None
    output = PurePosixPath(matches[0])
    expected_tail = ("xfs-" + case.replace("/", "-"), case.split("/")[0],
                     case.split("/")[1] + ".out.bad")
    if output.parts[-3:] != expected_tail:
        return None
    return str(output.parents[2] / "mount")


def _xfs_utimens_indices(lines, text, case):
    rule = XFS_UTIMENS_REFUSALS[case]
    if case == "generic/005":
        path = rule["path"]
    else:
        mount = _xfs_mount(text, case)
        if mount is None:
            return []
        path = re.escape(mount) + "/" + rule["path"]
    diagnostic = re.compile(
        rb"touch: setting times of '(?P<path>" + path.encode() +
        rb")': Operation not supported")
    matches = [(index, diagnostic.fullmatch(line.removesuffix(b"\n")))
               for index, line in enumerate(lines)]
    matches = [(index, match) for index, match in matches if match is not None]
    if case == "generic/035" and matches:
        paths = [PurePosixPath(match["path"].decode()) for _, match in matches]
        if ({path.name for path in paths} != {"file1", "file2"}
                or len({path.parent for path in paths}) != 1):
            return []
    return [index for index, _ in matches]


def parse_tap(text, case):
    rows, plans, diagnostics, pending_diagnostics = [], [], [], []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        plan = re.fullmatch(r"1\.\.(\d+)", line)
        row = re.fullmatch(r"(not ok|ok) (\d+)(| .*)", line)
        if plan:
            plans.append(int(plan[1]))
        elif row:
            assertion = int(row[2])
            for diagnostic in pending_diagnostics:
                diagnostic["_before"] = assertion
            pending_diagnostics.clear()
            parsed = dict(suite="pjdfstest", case=case, assertion=assertion,
                          status="failed" if row[1] == "not ok" else "passed",
                          detail=row[3].strip())
            if parsed["detail"] == "" and rows:
                parsed["_context"] = operation_context(rows[-1])
            rows.append(parsed)
            if re.search(r"#\s*(SKIP|TODO)\b", row[3], re.I):
                rows[-1]["status"] = "skipped"
        elif line in {"stat returned -1", "lstat returned -1"}:
            diagnostic = {"detail": line, "_after": rows[-1]["assertion"] if rows else 0}
            diagnostics.append(diagnostic)
            pending_diagnostics.append(diagnostic)
        else:
            raise Refused(f"tap-malformed: {case}: {line}")
    # require() in upstream misc.sh can report a single fake success without
    # exercising the selected test. Every selected file has multiple assertions.
    require(len(plans) == 1 and plans[0] > 1, f"tap-empty-or-skipped: {case}")
    require(len(rows) == plans[0] and all(row["assertion"] == number
            for number, row in enumerate(rows, 1)),
            f"tap-incomplete: {case}")
    for diagnostic in pending_diagnostics:
        diagnostic["_before"] = plans[0] + 1
    # Direct stat calls in the scripts can fail outside expect(). Keep their
    # diagnostics as additional failed cases, without filling missing TAP rows.
    rows.extend(dict(suite="pjdfstest", case=case, assertion=plans[0] + number,
                     status="failed", **diagnostic)
                for number, diagnostic in enumerate(diagnostics, 1))
    return rows


def parse_xfs(text, case, rc, *, expected_output=None, actual_output=None):
    require(rc != 124, f"xfstests-timeout: {case}")

    def values(prefix):
        return [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]

    ran, skipped, failed = values("Ran: "), values("Not run: "), values("Failures: ")
    require("Interrupted!" not in text, f"xfstests-interrupted: {case}")
    # check prints its summary twice (wrapup, then the collected section summary).
    require(all(value == case for value in ran + skipped + failed),
            f"xfstests-selection: {case}")
    require(len(ran) <= 2 and len(skipped) <= 2 and len(failed) <= 2,
            f"xfstests-duplicate: {case}")
    require(bool(ran), f"xfstests-empty: {case}")
    if skipped:
        require(not failed and rc == 0, f"xfstests-verdict: {case}")
        status = "skipped"
    elif failed:
        require(rc == 1 and "Failed 1 of 1 tests" in text.splitlines(),
                f"xfstests-verdict: {case}")
        require("Passed all 1 tests" not in text.splitlines(), f"xfstests-verdict: {case}")
        status = "failed"
    else:
        require(rc == 0 and "Passed all 1 tests" in text.splitlines(),
                f"xfstests-verdict: {case}")
        require("Failed 1 of 1 tests" not in text.splitlines(), f"xfstests-verdict: {case}")
        status = "passed"
    exact_output = False
    if case in XFS_UTIMENS_REFUSALS and status == "failed":
        try:
            expected = expected_output.read_bytes()
            actual = actual_output.read_bytes()
        except (AttributeError, OSError) as error:
            raise Refused(f"xfstests-evidence-unreadable: {case}: {error}") from error
        lines = actual.splitlines(keepends=True)
        matches = _xfs_utimens_indices(lines, text, case)
        exact_output = (len(matches) == XFS_UTIMENS_REFUSALS[case]["count"] and
                        b"".join(line for index, line in enumerate(lines)
                                 if index not in matches) == expected)
    return [dict(suite="xfstests", case=case, assertion=1, status=status, detail=text,
                 exact_output=exact_output)]


def parse_probes(text):
    records = json.loads(text)
    require(isinstance(records, list) and len(records) == len(PROBES), "probes-incomplete")
    require(all(isinstance(record, dict) and set(record) == {"case", "got"}
                and isinstance(record["case"], str) and isinstance(record["got"], str)
                for record in records), "probes-malformed")
    require(sorted(record["case"] for record in records) == sorted(PROBES), "probes-selection")
    return [dict(suite="refusals", case=record["case"], assertion=1,
                 status="passed" if record["got"] == PROBES[record["case"]] else "failed",
                 detail=f"expected {PROBES[record['case']]}, got {record['got']}") for record in records]


def load_known(path):
    document = json.loads(path.read_text())
    require(isinstance(document, dict) and set(document) == {
        "SPDX-FileCopyrightText", "SPDX-License-Identifier", "failures",
    }, "known-format: expected licensed failures document")
    entries = document["failures"]
    require(isinstance(entries, list), "known-format: expected a list")
    known = {}
    for entry in entries:
        fields = set(entry) if isinstance(entry, dict) else set()
        base_fields = {
            "suite", "case", "assertion", "class", "operation", "expected", "errno", "reason",
        }
        optional_fields = {"cause", "after", "before", "context", "attribute"}
        require(base_fields <= fields and fields <= base_fields | optional_fields,
                "known-format: entry fields")
        require(isinstance(entry["reason"], str) and bool(entry["reason"].strip()),
                "known-reason: missing reason")
        require(entry["suite"] in {"pjdfstest", "xfstests"}
                and entry["case"] in (PJD if entry["suite"] == "pjdfstest" else XFS)
                and type(entry["assertion"]) is int and entry["assertion"] > 0,
                "known-identity: outside selection")
        require(all(isinstance(entry[k], str) for k in ("class", "operation", "expected", "errno")),
                "known-format: expected strings")
        has_cause = "cause" in entry
        cause = entry.get("cause")
        if has_cause:
            require(entry["suite"] == "pjdfstest" and entry["class"] != "unexpected",
                    "known-cause: only pjdfstest allowed consequences have causes")
            if cause == "attributes":
                require(entry["class"] == "metadata-mutations"
                        and entry["operation"] in {"stat", "lstat", "test_check"},
                        "known-cause: invalid fixed-attribute consequence")
            else:
                require(type(cause) is int and 0 < cause < entry["assertion"],
                        "known-cause: invalid preceding assertion")
            require(entry["errno"] != "ENOTSUP",
                    "known-cause: consequence cannot carry ENOTSUP")
            # A consequence observes the path or attribute an earlier refusal
            # left behind: an absent path, a failed stat or a fixed attribute
            # value. Any other errno is a refusal of its own and needs its own
            # classification, not an inherited cause.
            require(not re.fullmatch(r"E[A-Z0-9]+", entry["errno"]) or entry["errno"] == "ENOENT",
                    "known-cause: consequence errno other than ENOENT")
        elif entry["class"] != "unexpected":
            xfs_utimens = (entry["suite"] == "xfstests"
                           and entry["case"] in XFS_UTIMENS_REFUSALS
                           and (entry["assertion"], entry["class"], entry["operation"],
                                entry["expected"], entry["errno"]) ==
                           (1, "metadata-mutations", "utimensat", "0", "ENOTSUP"))
            pjd_refusal = (entry["suite"] == "pjdfstest" and entry["errno"] == "ENOTSUP"
                           and entry["operation"] in CLASSES.get(entry["class"], set()))
            non_mounter = (entry["suite"] == "pjdfstest"
                           and entry["class"] == "non-mounter-uid"
                           and entry["errno"] == "EACCES"
                           and entry["reason"] == NON_MOUNTER_REASON)
            require(xfs_utimens or pjd_refusal or non_mounter,
                    "known-refusal-class: not an allowed refusal")
        if entry["errno"] == "-1":
            require(type(entry.get("after")) is int and type(entry.get("before")) is int
                    and type(cause) is int and entry["after"] >= cause
                    and entry["before"] == entry["after"] + 1,
                    "known-position: invalid failed-stat position")
        else:
            require("after" not in entry and "before" not in entry,
                    "known-position: position belongs only to failed stat")
        if entry["operation"] == "test_check":
            context = entry.get("context")
            require(has_cause and isinstance(context, dict)
                    and set(context) == {"command", "expected", "errno"}
                    and all(isinstance(value, str) and value.strip()
                            for value in context.values())
                    and context["command"].split()[0] in {"stat", "lstat"},
                    "known-context: test_check requires preceding operation context")
            if cause == "attributes":
                require(entry.get("attribute") in FIXED_ATTRIBUTES
                        and context_attribute(context) == entry["attribute"],
                        "known-context: invalid fixed attribute")
            else:
                require("attribute" not in entry,
                        "known-context: attribute belongs only to fixed attributes")
        else:
            require("context" not in entry and "attribute" not in entry,
                    "known-context: context belongs only to test_check")
        if entry["errno"] == "<timestamp>":
            require(type(cause) is int and entry["operation"] == "lstat"
                    and re.fullmatch(r"[0-9]+", entry["expected"]) is not None,
                    "known-cause: invalid timestamp consequence")
        if "<inode>" in entry["expected"] or "<inode>" in entry["errno"]:
            require(entry["operation"] == "lstat"
                    and entry["expected"].count("<inode>") == 1
                    and entry["errno"].count("<inode>") <= 1,
                    "known-format: invalid inode consequence")
        identity = entry["suite"], entry["case"], entry["assertion"]
        require(identity not in known, "known-duplicate: repeated assertion")
        known[identity] = entry
    for identity, entry in known.items():
        cause = entry.get("cause")
        if type(cause) is int:
            cause_entry = known.get((identity[0], identity[1], cause))
            section_12_refusal = (cause_entry is not None
                                  and cause_entry["errno"] == "ENOTSUP"
                                  and cause_entry["operation"] in
                                  CLASSES.get(cause_entry["class"], set()))
            non_mounter_refusal = (cause_entry is not None
                                   and cause_entry["class"] == "non-mounter-uid"
                                   and cause_entry["errno"] == "EACCES"
                                   and cause_entry["reason"] == NON_MOUNTER_REASON)
            require(cause_entry is not None and cause_entry["class"] == entry["class"]
                    and "cause" not in cause_entry and cause_entry["suite"] == "pjdfstest"
                    and (section_12_refusal or non_mounter_refusal),
                    "known-cause: missing allowed direct refusal")
    return known


def failure_signature(row):
    if row["detail"] == "":
        return "test_check", "true", "false", []
    if row["detail"] in {"stat returned -1", "lstat returned -1"}:
        return row["detail"].split()[0], "0", "-1", []
    match = re.fullmatch(r"- tried '(.*)', expected (.*), got (.*)", row["detail"])
    if not match:
        return None
    try:
        words = shlex.split(match[1])
    except ValueError:
        return None
    candidates = words[words.index(":") + 1:] if ":" in words else words
    operation = next((word for word in candidates if word in OPERATIONS), None)
    if operation is None:
        return None
    # pjdfstest names Linux's ENOTSUP/EOPNOTSUPP alias EOPNOTSUPP.
    actual = "ENOTSUP" if match[3] == "EOPNOTSUPP" else match[3]
    return operation, match[2], actual, words


def operation_context(row):
    signature = failure_signature(row)
    if signature is None or signature[0] == "test_check":
        return None
    _, expected, actual, words = signature
    normalized = [re.sub(r"pjdfstest_[0-9a-f]+", "<path>", word) for word in words]
    return {"command": " ".join(normalized), "expected": expected, "errno": actual}


def context_attribute(context):
    selector = context["command"].split()[-1]
    if "mode" in selector.split(","):
        return "mode"
    if {"uid", "gid"} & set(selector.split(",")):
        return "ownership"
    if {"atime", "mtime", "ctime", "birthtime"} & set(selector.split(",")):
        return "timestamp"
    return None


def invoking_uid(words):
    positions = [index for index, word in enumerate(words) if word == "-u"]
    if len(positions) != 1 or positions[0] + 1 >= len(words):
        return None
    value = words[positions[0] + 1]
    return int(value) if re.fullmatch(r"[0-9]+", value) is not None else None


def chmod_allowed(entry, operation, words):
    if entry["class"] != "metadata-mutations" or operation != "chmod":
        return True
    # Changing only execute intent is supported; these canonical modes must
    # never be excused as unsupported metadata. A directory's fixed 0755 mode
    # makes chmod(".", 0777) a non-execute mutation rather than a canonical one.
    index = words.index("chmod")
    return (len(words) > index + 2
            and re.fullmatch(r"0?[0-7]{3,4}", words[index + 2]) is not None
            and (int(words[index + 2], 8) not in {0o644, 0o755, 0o777}
                 or (words[index + 1] == "." and int(words[index + 2], 8) == 0o777)))


def known_signature_matches(operation, expected, actual, entry):
    if operation != entry["operation"]:
        return False
    if entry["errno"] == "<timestamp>":
        return (expected == entry["expected"]
                and re.fullmatch(r"[0-9]+", actual) is not None
                and actual != expected)
    if "<inode>" in entry["expected"]:
        pattern = re.escape(entry["expected"]).replace(
            re.escape("<inode>"), r"([1-9][0-9]*)")
        match = re.fullmatch(pattern, expected)
        if match is None:
            return False
        actual_pattern = re.escape(entry["errno"]).replace(
            re.escape("<inode>"), re.escape(match[1]))
        return re.fullmatch(actual_pattern, actual) is not None
    return (expected, actual) == (entry["expected"], entry["errno"])


def allowed(row, entry, known=None, observed=None):
    if entry["class"] == "unexpected":
        return False
    if row["suite"] == "xfstests":
        lines = row["detail"].splitlines()
        rule = XFS_UTIMENS_REFUSALS.get(row["case"])
        if rule is None:
            return False
        diagnostics = [line.strip().removeprefix("+").encode() for line in lines
                       if line.strip().startswith("+touch: setting times of '")]
        return ((row["assertion"], entry["operation"], entry["errno"]) ==
                (1, "utimensat", "ENOTSUP")
                and row.get("exact_output") is True
                and len(_xfs_utimens_indices(diagnostics, row["detail"], row["case"])) ==
                rule["count"]
                and re.search(rf"^{re.escape(row['case'])}\s+- output mismatch",
                              row["detail"], re.MULTILINE) is not None
                and any(line.strip() == rule["hunk"] for line in lines))
    signature = failure_signature(row)
    if signature is None:
        return False
    operation, expected, actual, words = signature
    if not known_signature_matches(operation, expected, actual, entry):
        return False
    if not chmod_allowed(entry, operation, words):
        return False
    cause = entry.get("cause")
    if entry["errno"] == "-1" and (row.get("_after"), row.get("_before")) != (
            entry["after"], entry["before"]):
        return False
    if operation == "test_check" and row.get("_context") != entry["context"]:
        return False
    if cause == "attributes":
        return (operation == "test_check" or
                (operation in {"stat", "lstat"} and actual not in {
                    "EACCES", "ENOENT", "ENOTSUP", "EPERM", "-1",
                }))
    if type(cause) is int:
        if known is None or observed is None:
            return False
        cause_identity = row["suite"], row["case"], cause
        cause_row = observed.get(cause_identity)
        cause_entry = known.get(cause_identity)
        return (cause_row is not None and cause_row["status"] == "failed"
                and cause_entry is not None
                and allowed(cause_row, cause_entry, known, observed))
    if entry["class"] == "non-mounter-uid":
        uid = invoking_uid(words)
        return actual == "EACCES" and uid is not None and uid != MOUNT_OWNER_UID
    return True


def exit_comparison(unclassified, counts):
    """Compare the CI baseline with the retained VM failures and upstream TODOs."""
    document = json.loads(Path(__file__).with_name("posix-exit-baseline.json").read_text())
    expected = {}
    for case, groups in document["device-nodes"].items():
        for operation, wanted, got, assertions in groups:
            for number in assertions:
                expected["pjdfstest", case, number] = ("device-nodes", (operation, wanted, got))
    for case, assertions in document["test-check"].items():
        for number in assertions:
            expected["pjdfstest", case, number] = ("test-check", "")
    for detail, assertions in document["todos"].items():
        for number in assertions:
            expected["pjdfstest", "chown/00.t", number] = ("todos", detail)

    matched = {"device-nodes": 0, "test-check": 0, "todos": 0}
    changed, new = [], []
    for identity, row in unclassified.items():
        if identity not in expected:
            new.append(identity)
            continue
        group, wanted = expected[identity]
        status = "skipped" if group == "todos" else "failed"
        actual = row["detail"]
        if group == "device-nodes":
            signature = failure_signature(row)
            actual = signature[:3] if signature is not None else None
            if actual and actual[0] == "mknod":
                words = signature[3]
                index = words.index("mknod")
                if words[index + 2:index + 3] not in (["b"], ["c"]):
                    actual = None
        if row["status"] == status and actual == wanted:
            matched[group] += 1
        else:
            changed.append(identity)
    missing = sorted(expected.keys() - unclassified.keys())
    print(json.dumps(dict(event="exit-comparison", matched=matched, new=sorted(new),
                          changed=sorted(changed), missing=missing)))
    reasons = []
    if new or changed or missing or matched != {"device-nodes": 476, "test-check": 72, "todos": 27}:
        reasons.append("exit-outcome-drift")
    if counts["run"] != 1939 or counts["known"] != 908:
        reasons.append("exit-coverage-or-known-drift")
    return reasons


def require_device_reachability(directory):
    observed = json.loads((directory / "device-node-probe.json").read_text())
    require(observed == {"host-block": "0", "host-char": "0",
                         "fuse-block": "ENOTSUP", "fuse-char": "ENOTSUP"},
            "device-node-reachability: expected host creation and FUSE ENOTSUP")


def verdict(rows, known, *, ci_exit=False, unlink_noop=False):
    counts = dict(run=0, passed=0, failed=0, known=0, skipped=0)
    reasons, seen = [], set()
    unclassified = {}
    observed = {(row["suite"], row["case"], row["assertion"]): row for row in rows}
    for row in rows:
        identity = row["suite"], row["case"], row["assertion"]
        require(identity not in seen, "results-duplicate: repeated assertion")
        seen.add(identity)
        status = row["status"]
        entry = known.get(identity)
        if status == "failed" and entry and allowed(row, entry, known, observed):
            status = "known"
        if status != "skipped":
            counts["run"] += 1
        counts[status] += 1
        if ci_exit and status in {"failed", "skipped"}:
            unclassified[identity] = row
        if status in {"failed", "known", "skipped"}:
            public = {key: value for key, value in row.items()
                      if key != "exact_output" and not key.startswith("_")}
            print(json.dumps(dict(event="case", **public, classification=status,
                                  reason=entry["reason"] if entry else "unexpected failure")))
        if status == "passed" and entry and entry["class"] != "unexpected":
            reasons.append("known-unexpected-success: " + repr(identity))
    require(counts["run"] > 0, "zero-cases-run")
    unobserved = known.keys() - seen
    if unlink_noop and not ci_exit:
        print(json.dumps(dict(event="known-unobserved", count=len(unobserved),
                              identities=sorted(unobserved))))
    else:
        require(not unobserved, "known-unobserved: assertion not executed")
    if ci_exit:
        reasons.extend(exit_comparison(unclassified, counts))
    else:
        if counts["skipped"]:
            reasons.append("skipped-write-group")
        if counts["failed"]:
            reasons.append("unexpected-failure")
    return counts, reasons


def read_results(directory, rows=None):
    rows = [] if rows is None else rows
    for suite, cases in (("pjdfstest", PJD), ("xfstests", XFS)):
        for case in cases:
            stem = directory / suite / case.replace("/", "-")
            try:
                text = Path(str(stem) + ".log").read_text()
                rc = int(Path(str(stem) + ".rc").read_text().strip())
            except (OSError, ValueError) as error:
                raise Refused(f"results-unreadable: {suite}/{case}: {error}") from error
            if suite == "pjdfstest":
                parsed = parse_tap(text, case)
                require(rc == 0, f"pjdfstest-exit: {case}: {rc}")
            else:
                parsed = parse_xfs(
                    text, case, rc,
                    expected_output=Path(str(stem) + ".out"),
                    actual_output=directory / ("xfs-" + case.replace("/", "-")) /
                    (case + ".out.bad"))
            rows.extend(parsed)
    try:
        rows.extend(parse_probes((directory / "refusals.json").read_text()))
    except (OSError, ValueError) as error:
        if isinstance(error, Refused):
            raise
        raise Refused(f"probes-unreadable: {error}") from error
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("known", type=Path)
    parser.add_argument("--ci-exit", action="store_true",
                        help="compare the CI baseline with the retained VM record in scripts/posix-exit-baseline.json")
    args = parser.parse_args()
    rows = []
    try:
        read_results(args.results, rows)
        try:
            known = load_known(args.known)
        except (OSError, ValueError, TypeError) as error:
            if isinstance(error, Refused):
                raise
            raise Refused(f"known-unreadable: {error}") from error
        counts, reasons = verdict(rows, known, ci_exit=args.ci_exit)
        print(json.dumps(dict(event="counts", **counts)))
        if args.ci_exit:
            require_device_reachability(args.results)
        if reasons:
            raise Refused(", ".join(reasons))
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps(dict(event="refused", reason=str(error),
                              observed=len(rows))), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
