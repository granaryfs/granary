#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Classify the change a merge writes onto its base; uncertainty keeps full CI.

ci-mode reads a checked-out pull request merge. merge-mode constructs that merge
from two commits. Both use the same raw diff, base-tree markers and byte readers.
"""
import argparse
import copy
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import tempfile
import textwrap
import tomllib

MARKER = ".ci-docs-only"
MARKER_BYTES = b"docs-only fast path: see scripts/ci-changes.py\n"
SKIPPABLE = (
    "lint", "test (ubuntu-24.04)", "test-macos", "candidate-identity / verify",
    "purity", "gates", "breakage", "crash-points", "publish-restart", "overlay-faults", "fuse",
)
GIT_ENV = {
    "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": "/dev/null",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
}
OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
CI_SCRIPT = re.compile(rb"(?:\./)?(scripts/[A-Za-z0-9_./-]+)")


def reader(data, root, document):
    """Match literal path runs, filenames and unresolved root directory tokens."""
    prefix, path = root.encode() + b"/", document.encode()
    name = PurePosixPath(document).name.encode()
    if path in data or name in data:
        return True
    runs = re.compile(re.escape(prefix) + rb"[A-Za-z0-9._/\\-]*")
    for match in runs.finditer(data):
        run = match[0]
        if any(part in run for part in (b"//", b"/./", b"/../", b"\\")) or run.endswith((b"/.", b"/..")):
            return True
        if path.startswith(run):
            return True
    # A specific literal file must not become a root-wide token match.
    remainder = runs.sub(b"\0", data)
    directory = re.escape(PurePosixPath(root).name.encode())
    token = rb"(?<![A-Za-z0-9_])" + directory + rb"(?=[/\\])|(?<=[/\\])" + directory + rb"(?![A-Za-z0-9_])"
    return any(re.search(token, remainder[max(0, match.start() - 1):match.end() + 1]) is not None
               for match in re.finditer(directory, remainder))


def worker_steps(workflow):
    """Discover invoked files from worker steps; never filter the byte scan."""
    selected = []
    for name in worker_ids():
        jobs = re.findall(rb"(?ms)^  " + name.encode() + rb":[^\n]*\n(.*?)(?=^  [a-z][a-z0-9-]*:|^\S|\Z)", workflow)
        if len(jobs) != 1:
            raise ValueError("missing or duplicate CI worker")
        steps = re.findall(rb"(?ms)^    steps:\n(.*)\Z", jobs[0])
        if not steps and name == "candidate-identity" and re.search(
                rb"(?m)^    uses: \./\.github/workflows/public-ci-candidate\.yml$", jobs[0]):
            selected.append(jobs[0])
        elif len(steps) == 1:
            selected.append(steps[0])
        else:
            raise ValueError("unreadable CI worker steps")
    return b"\n".join(selected)


def source_inputs(paths, read):
    """Enumerate compiled inputs and files named by the skipped workers."""
    chosen = {path for path in paths if PurePosixPath(path).name == "Cargo.toml"
              or path == ".cargo/config.toml"}
    packages = set()
    ci = ".github/workflows/ci.yml"
    if ci not in paths:
        raise ValueError("missing CI workflow")
    chosen.add(ci)
    scope = worker_steps(read(ci))
    if b"    uses: ./.github/workflows/public-ci-candidate.yml\n" in scope:
        chosen.add(".github/workflows/public-ci-candidate.yml")
    chosen.update(path.decode("ascii") for path in CI_SCRIPT.findall(scope))
    chosen.update(path for path in paths if path != ci and path.encode() in scope)
    for path in sorted(paths):
        if PurePosixPath(path).name == "Cargo.toml":
            manifest = tomllib.loads(read(path).decode("utf-8"))
            package = manifest.get("package", {})
            if not isinstance(package, dict):
                raise ValueError(f"{path}: unreadable package")
            if "package" in manifest:
                packages.add(str(PurePosixPath(path).parent))
            build = package.get("build", False)
            if not isinstance(build, (str, bool)):
                raise ValueError(f"{path}: unreadable build script declaration")
            if isinstance(build, str) or build is True:
                chosen.add(posixpath.normpath(str(PurePosixPath(path).parent / (build if isinstance(build, str) else "build.rs"))))
    chosen.update(path for path in paths if (path.endswith(".rs") or PurePosixPath(path).name == "build.rs")
                  and any(root == "." or path.startswith(root + "/") for root in packages))
    if not chosen <= set(paths):
        raise ValueError("unreadable source input")
    return {path: read(path) for path in sorted(chosen)}


def tree_inputs(tree, cwd=None):
    rows = git("ls-tree", "-r", "-z", tree, cwd=cwd).stdout.split(b"\0")
    if rows.pop() != b"":
        raise ValueError("unreadable source tree")
    objects = {}
    for row in rows:
        metadata, path = row.split(b"\t", 1)
        objects[path.decode("utf-8")] = metadata.split()

    def read(path):
        mode, kind, oid = objects[path]
        if mode not in {b"100644", b"100755"} or kind != b"blob":
            raise ValueError(f"{path}: source input is not a regular file")
        return git("cat-file", "blob", oid.decode("ascii"), cwd=cwd).stdout

    return b"\0".join(source_inputs(objects, read).values())


def git(*args, cwd=None, allow_conflict=False, env=None, data=None):
    settings = dict(os.environ, **GIT_ENV)
    if env:
        settings.update(env)
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args],
                            cwd=cwd, env=settings, input=data, capture_output=True)
    if result.returncode and not (allow_conflict and result.returncode == 1):
        raise ValueError(f"git {args[0]} failed: {result.stderr.decode(errors='replace').strip()}")
    return result


def worker_ids(names=SKIPPABLE):
    if (not isinstance(names, tuple) or not names
            or any(not isinstance(name, str) or (name != "candidate-identity / verify" and not re.fullmatch(r"[a-z][a-z0-9-]*(?: \([^()\n]+\))?", name))
                   for name in names)):
        raise ValueError("SKIPPABLE must contain check names of the form <id> or <id> (…)")
    ids = tuple(name.split(" (")[0].split(" / ")[0] for name in names)
    if len(set(ids)) != len(ids):
        raise ValueError("SKIPPABLE must name distinct workers")
    return ids


def commit(value, cwd=None):
    if not OID.fullmatch(value):
        raise ValueError("expected a full commit object id")
    resolved = git("rev-parse", "--verify", value + "^{commit}", cwd=cwd).stdout.strip().decode("ascii")
    if resolved != value:
        raise ValueError("commit identity differs")
    return resolved


def marked(path, tree, cwd=None, inputs=b""):
    for parent in PurePosixPath(path).parents:
        marker = str(parent / MARKER)
        row = git("ls-tree", "-z", tree, "--", marker, cwd=cwd).stdout
        if not row:
            continue
        metadata, found = row.rstrip(b"\0").split(b"\t", 1)
        mode, kind, oid = metadata.split()
        if found != marker.encode() or mode != b"100644" or kind != b"blob":
            continue
        if git("cat-file", "blob", oid.decode("ascii"), cwd=cwd).stdout == MARKER_BYTES:
            return not reader(inputs, str(parent), path)
    return False


def eligible(entry, tree, cwd=None, inputs=b""):
    old, new, status, raw_path = entry
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return (path.endswith(".md") and PurePosixPath(path).name != MARKER
            and not any(ord(char) < 32 or ord(char) == 127 for char in path)
            and status in {b"A", b"M", b"D"}
            and old in {b"000000", b"100644"} and new in {b"000000", b"100644"}
            and marked(path, tree, cwd, inputs))


def diff_entries(base, target, cwd=None):
    raw = git("diff", "--raw", "-z", "--no-renames", "--no-ext-diff", "--no-textconv",
              base, target, "--", cwd=cwd).stdout
    if not raw:
        return []
    fields = raw.split(b"\0")
    if fields.pop() != b"" or len(fields) % 2:
        raise ValueError("unreadable raw diff")
    entries = []
    for header, path in zip(fields[::2], fields[1::2]):
        match = re.fullmatch(rb":([0-7]{6}) ([0-7]{6}) [0-9a-f]+ [0-9a-f]+ ([A-Z][0-9]*)", header)
        if match is None or not path:
            raise ValueError("unreadable raw diff entry")
        entries.append((*match.groups(), path))
    return entries


def classify(base, target, cwd=None):
    entries = diff_entries(base, target, cwd)
    if not entries:
        return "full"
    inputs = tree_inputs(base, cwd)
    return "fast" if all(eligible(entry, base, cwd, inputs) for entry in entries) else "full"


def ci_mode(event, head, base, cwd=None):
    if event != "pull_request":
        return "full"
    commit(head, cwd)
    commit(base, cwd)
    parents = git("rev-list", "--parents", "-n", "1", "HEAD", cwd=cwd).stdout.split()
    if len(parents) != 3 or parents[1].decode() != base or parents[2].decode() != head:
        return "full"
    return classify(base, parents[0].decode(), cwd)


def merge_mode(base, head, cwd=None):
    commit(base, cwd)
    commit(head, cwd)
    result = git("merge-tree", "--write-tree", base, head, cwd=cwd, allow_conflict=True)
    tree = result.stdout.splitlines()[0].decode("ascii") if result.stdout else ""
    if not OID.fullmatch(tree):
        raise ValueError("merge-tree returned no tree")
    if result.returncode == 1:
        return "full"
    return classify(base, tree, cwd)


def aggregate(needs):
    ids = worker_ids()
    if not isinstance(needs, dict) or set(needs) != set(ids) | {"changes"}:
        raise ValueError("needs inventory differs from the declared workers and changes")
    changes = needs["changes"]
    mode = changes.get("outputs", {}).get("mode")
    if changes.get("result") != "success" or mode not in {"fast", "full"}:
        raise ValueError("changes must succeed with exactly fast or full")
    expected = "skipped" if mode == "fast" else "success"
    if any(needs[name].get("result") != expected for name in ids):
        raise ValueError(f"every worker must be {expected} under {mode}")


def self_test():
    from unittest.mock import patch

    cases = 0
    script = str(Path(__file__).resolve())

    def check(label, got, want):
        nonlocal cases
        if got != want:
            raise RuntimeError(f"{label}: got {got!r}, expected {want!r}")
        cases += 1
        print(f"ci-changes self-test: {label} PASS")

    def put(root, path, content=b"document\n"):
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)
        return file

    def save(root):
        git("add", "-A", cwd=root)
        git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "fixture", "--allow-empty", cwd=root)
        return git("rev-parse", "HEAD", cwd=root).stdout.strip().decode()

    def indexed(root, path):
        blob = git("hash-object", "-w", "--stdin", cwd=root, data=b"document\n").stdout.strip().decode()
        git("update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", cwd=root)

    rows = [
        ("marked documents", "fast", lambda r, b: put(r, "notes/x.md", b"changed\n")),
        ("missing CI workflow", None, lambda r, b: put(r, "notes/x.md", b"changed\n")),
        ("added document", "fast", lambda r, b: put(r, "notes/new.md")),
        ("bad base marker", "full", lambda r, b: put(r, "notes/x.md", b"changed\n")),
        ("one unmarked path", "full", lambda r, b: (put(r, "notes/x.md", b"changed\n"), put(r, "code.rs"))),
        ("deleted document", "fast", lambda r, b: (r / "notes/x.md").unlink()),
        ("empty diff", "full", lambda r, b: None),
        ("executable", "full", lambda r, b: (r / "notes/x.md").chmod(0o755)),
        ("symlink type change", "full", lambda r, b: ((r / "notes/x.md").unlink(), (r / "notes/x.md").symlink_to("other"))),
        ("added symlink", "full", lambda r, b: (r / "notes/link.md").symlink_to("x.md")),
        ("submodule", "full", lambda r, b: git("update-index", "--add", "--cacheinfo", f"160000,{b},notes/sub.md", cwd=r)),
        ("marker edited", "full", lambda r, b: put(r, "notes/" + MARKER, b"wrong\n")),
        ("marker deleted", "full", lambda r, b: (r / "notes" / MARKER).unlink()),
        ("marker added", "full", lambda r, b: put(r, "new/" + MARKER, MARKER_BYTES)),
        ("head-only code marker", "full", lambda r, b: (put(r, "code/" + MARKER, MARKER_BYTES), put(r, "code/x.md"))),
        ("rename out", "full", lambda r, b: (r / "notes/x.md").rename(r / "moved.md")),
        ("rename in", "full", lambda r, b: (r / "outside.md").rename(r / "notes/new.md")),
    ]
    readers = {"reader full path": b"// notes/x.md", "reader filename": b'include_str!("x.md")',
               "reader root token": b'concat!("no", "tes/", name); // /notes', "unrelated reader": b'"safe.md"',
               "symlink reader": None}
    for label in readers:
        rows.append((label, None if label == "symlink reader" else "fast" if label == "unrelated reader" else "full",
                     lambda r, b: put(r, "notes/x.md", b"changed\n")))
    for extension in ("py", "json", "sh", "MD"):
        rows.append((extension, "full", lambda r, b, e=extension: put(r, "notes/new." + e)))
    odd_paths = ("notes/line\nbreak.md", "notes/tab\there.md", "notes/bad\udcff.md")
    index_only = {"submodule", *(repr(path) for path in odd_paths)}
    for path in odd_paths:
        rows.append((repr(path), "full", lambda r, b, p=path: indexed(r, p)))
    for label, expected, edit in rows:
        with tempfile.TemporaryDirectory(prefix=".ci-changes-fixture-", dir=".") as directory:
            root = Path(directory).resolve()
            git("init", "-q", "-b", "main", str(root))
            git("config", "core.ignorecase", "true", cwd=root)
            put(root, "notes/" + MARKER, b"wrong\n" if label == "bad base marker" else MARKER_BYTES)
            put(root, "notes/x.md")
            put(root, "outside.md")
            if label != "missing CI workflow":
                put(root, ".github/workflows/ci.yml", b"jobs:\n" + b"".join(
                    b"  " + name.encode() + b":\n    steps:\n      - run: true\n" for name in worker_ids()))
            if label in readers:
                put(root, "Cargo.toml", b"[package]\n")
                if readers[label] is None:
                    (root / "reader.rs").symlink_to("notes/x.md")
                else:
                    put(root, "reader.rs", readers[label])
            base = save(root)
            git("checkout", "-qb", "topic", cwd=root)
            edit(root, base)
            # Index-only entries never need a host filesystem representation.
            if label in index_only:
                git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                    "-c", "commit.gpgsign=false", "commit", "-qm", "fixture", cwd=root)
                head = git("rev-parse", "HEAD", cwd=root).stdout.strip().decode()
            else:
                head = save(root)
            tree = git("rev-parse", head + "^{tree}", cwd=root).stdout.strip().decode()
            merged = git("commit-tree", tree, "-p", base, "-p", head, cwd=root, env={
                "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            }).stdout.strip().decode()
            if label in index_only:
                git("update-ref", "--no-deref", "HEAD", merged, cwd=root)
            else:
                git("checkout", "--detach", "-q", merged, cwd=root)
            for command in (("ci-mode", "--event", "pull_request", "--head", head, "--base", base),
                            ("merge-mode", base, head)):
                result = subprocess.run([sys.executable, script, *command], cwd=root, capture_output=True)
                wanted = (2, b"") if expected is None else (0, expected.encode() + b"\n")
                check(label + " " + command[0], (result.returncode, result.stdout), wanted)
            check("wrong head", ci_mode("pull_request", base, base, root), "full")
            check("wrong base", ci_mode("pull_request", head, head, root), "full")
            if label == "marked documents":
                for event in ("push", "schedule", "workflow_dispatch", "merge_group", "future"):
                    check(event, ci_mode(event, "", "", root), "full")
                put(root, "notes/" + MARKER, b"wrong\n")
                bad = save(root)
                check("base marker wrong bytes", merge_mode(bad, head, root), "full")
                git("checkout", "-q", "main", cwd=root)
                (root / "notes" / MARKER).unlink()
                dropped = save(root)
                check("main dropped marker", merge_mode(dropped, head, root), "full")
                git("checkout", "-q", "main", cwd=root)
                put(root, "outside.md", b"main edit\n")
                main = save(root)
                git("checkout", "-q", "topic", cwd=root)
                put(root, "outside.md", b"topic edit\n")
                conflict = save(root)
                check("merge conflict", merge_mode(main, conflict, root), "full")
            if label == "one unmarked path":
                git("replace", head, base, cwd=root)
                check("replace ref ignored", merge_mode(base, head, root), "full")
                check("CI replace ref ignored", ci_mode("pull_request", head, base, root), "full")
            if label == "rename out":
                git("checkout", "-q", "main", cwd=root)
                (root / "notes/x.md").rename(root / "embedded.md")
                main = save(root)
                git("checkout", "-qb", "edited", base, cwd=root)
                put(root, "notes/x.md", b"changed\n")
                edited = save(root)
                check("main moved the edited document", merge_mode(main, edited, root), "full")

    with tempfile.TemporaryDirectory(prefix=".ci-changes-error-", dir=".") as directory:
        for command in (("ci-mode", "--event", "pull_request", "--head", "a" * 40, "--base", "b" * 40),
                        ("merge-mode", "a" * 40, "b" * 40), ("merge-mode", "junk", "HEAD")):
            result = subprocess.run([sys.executable, script, *command], cwd=directory, capture_output=True)
            check("git or argument failure " + command[0], (result.returncode, result.stdout), (2, b""))
    def refusal(operation, value):
        try:
            operation(value)
        except (TypeError, ValueError) as exc:
            return str(exc)

    workflow_fixture = b"jobs:\n" + b"".join(
        b"  " + name.encode() + b":\n" + (
            b"    uses: ./.github/workflows/public-ci-candidate.yml\n" if name == "candidate-identity"
            else b"    steps:\n      - run: true\n") for name in worker_ids())
    witness_path = ".github/workflows/public-ci-candidate.yml"
    inputs = {".github/workflows/ci.yml": workflow_fixture, witness_path: b"name: witness\n"}
    check("relative witness is a source input", set(source_inputs(inputs, inputs.__getitem__)), set(inputs))
    try:
        source_inputs({".github/workflows/ci.yml": workflow_fixture}, inputs.__getitem__)
    except ValueError as exc:
        check("missing relative witness refuses source discovery", str(exc), "unreadable source input")
    else:
        raise RuntimeError("missing witness source accepted")
    try:
        worker_steps(workflow_fixture.replace(witness_path.encode(), witness_path.encode() + b"@main"))
    except ValueError as exc:
        check("explicit witness ref refuses source discovery", str(exc), "unreadable CI worker steps")
    else:
        raise RuntimeError("explicit witness ref accepted as exact relative call")
    check("worker tuple accepts an extra worker", refusal(worker_ids, SKIPPABLE + ("extra-worker",)), None)
    malformed = "SKIPPABLE must contain check names of the form <id> or <id> (…)"
    distinct = "SKIPPABLE must name distinct workers"
    for label, names, diagnostic in (
            ("worker tuple refuses empty", (), malformed),
            ("worker tuple refuses a list", list(SKIPPABLE), malformed),
            ("worker tuple refuses a non-string", (17,) + SKIPPABLE[1:], malformed),
            ("worker tuple refuses malformed names", ("bad/name",) + SKIPPABLE[1:], malformed),
            ("worker tuple refuses duplicate names", ("lint",) * len(SKIPPABLE), distinct),
            ("worker tuple refuses duplicate ids", SKIPPABLE + ("lint (extra)",), distinct)):
        check(label, refusal(worker_ids, names), diagnostic)
    for mode in ("fast", "full"):
        needs = {name: {"result": "skipped" if mode == "fast" else "success"} for name in worker_ids()}
        needs["changes"] = {"result": "success", "outputs": {"mode": mode}}
        aggregate(needs)
        check("aggregate " + mode, True, True)
        bad = []
        for result in ("success", "failure", "cancelled", "skipped"):
            if result != needs["lint"]["result"]:
                altered = copy.deepcopy(needs)
                altered["lint"]["result"] = result
                bad.append(altered)
        for result in ("failure", "skipped"):
            altered = copy.deepcopy(needs)
            altered["changes"]["result"] = result
            bad.append(altered)
        for value in ("", "FAST", "fast\n"):
            altered = copy.deepcopy(needs)
            altered["changes"]["outputs"]["mode"] = value
            bad.append(altered)
        altered = copy.deepcopy(needs)
        del altered["lint"]
        bad.extend([altered, dict(needs, extra={"result": "skipped"})])
        for altered in bad:
            try:
                aggregate(altered)
            except ValueError:
                check("aggregate refusal", True, True)
            else:
                raise RuntimeError("aggregate accepted invalid evidence")
    workflow = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"
    text = workflow.read_text()
    declared_needs = re.search(r"(?m)^  ci-green:.*\n(?: +#.*\n)*    needs: \[([^\]]+)\]", text)
    if declared_needs is None:
        raise RuntimeError(f"ci-green needs fixture: got {declared_needs!r}")
    needs = {name.strip(): {"result": "success"} for name in declared_needs[1].split(",")}
    needs["changes"]["outputs"] = {"mode": "full"}
    diagnostic = "needs inventory differs from the declared workers and changes"
    missing_worker = dict(needs)
    del missing_worker[worker_ids()[-1]]
    check("aggregate refuses needs missing a worker", (refusal(aggregate, needs), refusal(aggregate, missing_worker)),
          (None, diagnostic))
    with patch.object(worker_ids, "__defaults__", (SKIPPABLE[:-1],)):
        check("aggregate refuses a shortened declaration", (refusal(aggregate, missing_worker), refusal(aggregate, needs)),
              (None, diagnostic))

    upstream = text.split("      - name: upstream results succeeded\n", 1)[1]
    body = textwrap.dedent(upstream.split("          python3 -I - <<'EOF'\n", 1)[1].split("          EOF", 1)[0])
    needs = {name: {"result": "success"} for name in (*worker_ids(), "changes")}
    for mode in ("fast", "full", "", "junk"):
        needs["changes"]["outputs"] = {"mode": mode}
        result = subprocess.run([sys.executable, "-I", "-c", body], env={"NEEDS_JSON": json.dumps(needs)}, capture_output=True)
        check("report aggregate ignores " + repr(mode), result.returncode, 0)
    for name in (*worker_ids(), "changes"):
        for status in ("failure", "skipped", "cancelled", "neutral", "timed_out", None):
            altered = copy.deepcopy(needs)
            altered[name]["result"] = status
            altered["changes"]["outputs"] = {"mode": "fast"}
            result = subprocess.run([sys.executable, "-I", "-c", body], env={"NEEDS_JSON": json.dumps(altered)}, capture_output=True)
            check("report aggregate refuses " + name + " " + str(status), result.returncode, 1)
        altered = copy.deepcopy(needs)
        del altered[name]
        result = subprocess.run([sys.executable, "-I", "-c", body], env={"NEEDS_JSON": json.dumps(altered)}, capture_output=True)
        check("report aggregate refuses missing " + name,
              (result.returncode, result.stderr.strip()), (1, b"upstream job inventory differs"))
    for invalid in ({}, dict(needs, extra={"result": "success"}), [], None):
        result = subprocess.run([sys.executable, "-I", "-c", body], env={"NEEDS_JSON": json.dumps(invalid)}, capture_output=True)
        check("report aggregate refuses invalid inventory",
              (result.returncode, result.stderr.strip()), (1, b"upstream job inventory differs"))
    with tempfile.TemporaryDirectory(prefix="granary-ci-python-shadow-") as directory:
        root = Path(directory)
        (root / "scripts").mkdir()
        (root / "scripts/ci-changes.py").write_bytes(Path(__file__).read_bytes())
        for name in ("json.py", "runpy.py", "sitecustomize.py", "yaml.py"):
            (root / name).write_text('raise RuntimeError("workspace shadow imported")\n')
        result = subprocess.run([sys.executable, "-c", body], cwd=root,
                                env={"NEEDS_JSON": json.dumps(needs)}, capture_output=True)
        check("workspace shadow reproduces without isolation",
              (result.returncode, b"workspace shadow imported" in result.stderr), (1, True))
        result = subprocess.run([sys.executable, "-I", "-c", body], cwd=root,
                                env={"NEEDS_JSON": json.dumps(needs)}, capture_output=True)
        check("report aggregate ignores workspace shadows", (result.returncode, result.stderr), (0, b""))
    print(f"ci-changes self-test: {cases}/{cases} controls passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    commands = parser.add_subparsers(dest="command")
    ci = commands.add_parser("ci-mode")
    for name in ("event", "head", "base"):
        ci.add_argument("--" + name, required=True)
    merge = commands.add_parser("merge-mode")
    merge.add_argument("main_tip")
    merge.add_argument("head_oid")
    commands.add_parser("aggregate")
    commands.add_parser("skippable")
    args = parser.parse_args()
    if args.self_test and args.command is not None:
        parser.error("--self-test takes no subcommand")
    try:
        if args.self_test and args.command is None:
            self_test()
        elif args.command == "ci-mode":
            verdict = ci_mode(args.event, args.head, args.base)
            print(verdict)
        elif args.command == "merge-mode":
            verdict = merge_mode(args.main_tip, args.head_oid)
            print(verdict)
        elif args.command == "aggregate":
            aggregate(json.loads(os.environ["NEEDS_JSON"]))
        elif args.command == "skippable":
            worker_ids()
            print("\n".join(SKIPPABLE))
        else:
            parser.error("expected a subcommand or --self-test")
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        print(f"ci-changes: refused — {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
