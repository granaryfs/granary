#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Read-only evidence that a completed full main CI run is at most 26h old."""
import argparse
import ast
import copy
from contextlib import redirect_stderr
import io
from datetime import datetime, timedelta, timezone
import json
import os
import re
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from time import monotonic
from urllib.parse import urlencode
from unittest.mock import patch

# The fork guard scripts/check-fork-guard.py requires on every job on this
# repository's runners. It is true for every event this check counts (push,
# schedule, workflow_dispatch), so it is the one condition a worker may carry.
FORK_GUARD = ("github.event_name != 'pull_request'"
              " || github.event.pull_request.head.repo.full_name == github.repository")


def _declared_workers(detector):
    try:
        tree = ast.parse(Path(detector).read_text())
    except SyntaxError as exc:
        raise ValueError("malformed SKIPPABLE declaration") from exc
    declarations = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
            targets = [statement.target]
        else:
            continue
        if any(isinstance(node, ast.Name) and node.id == "SKIPPABLE" and isinstance(node.ctx, ast.Store)
               for target in targets for node in ast.walk(target)):
            declarations.append(statement)
    if len(declarations) != 1:
        raise ValueError("SKIPPABLE must have exactly one declaration")
    declaration, = declarations
    if not isinstance(declaration, ast.Assign) or not any(
            isinstance(target, ast.Name) and target.id == "SKIPPABLE" for target in declaration.targets):
        raise ValueError("malformed SKIPPABLE declaration")
    try:
        names = ast.literal_eval(declaration.value)
    except (TypeError, ValueError) as exc:
        raise ValueError("malformed SKIPPABLE declaration") from exc
    if (not isinstance(names, tuple) or not names
            or any(not isinstance(name, str) or (name != "candidate-identity / verify" and not re.fullmatch(r"[a-z][a-z0-9-]*(?: \([^()\n]+\))?", name))
                   for name in names)):
        raise ValueError("SKIPPABLE must contain check names of the form <id> or <id> (…)")
    if len({name.split(" (")[0].split(" / ")[0] for name in names}) != len(names):
        raise ValueError("SKIPPABLE must name distinct workers")
    return set(names)


DETECTOR = Path(__file__).with_name("ci-changes.py")


def timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return result


def pages(command, key):
    result = subprocess.run(["gh", "api", command, "--paginate", "--slurp"],
                            check=True, capture_output=True, text=True, timeout=20)
    data = json.loads(result.stdout)
    if not isinstance(data, list) or not data:
        raise ValueError("unreadable API pages")
    count = data[0]["total_count"]
    if not isinstance(count, int) or isinstance(count, bool) or count < 0 or any(not isinstance(page[key], list) for page in data):
        raise ValueError("unreadable API inventory")
    rows = [row for page in data for row in page[key]]
    if len(rows) != count or any(page["total_count"] != count for page in data):
        raise ValueError("truncated API history")
    return rows


def run_jobs(repo, run):
    attempt = run["run_attempt"]
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise ValueError("unreadable workflow run attempt")
    # Attempt-specific jobs cannot borrow completed workers from an older
    # attempt when only failed jobs or the aggregate were rerun.
    return pages(f"repos/{repo}/actions/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100", "jobs")


def inventory(workflow, workers, detector=None, public=False):
    # Read only the small schema used by this workflow; unfamiliar worker or
    # matrix declarations refuse instead of assuming coverage.
    text = Path(workflow).read_text()
    blocks = re.split(r"(?m)^  ([a-z][a-z0-9-]*):[^\n]*\n", text.split("\njobs:\n", 1)[1])
    jobs = dict(zip(blocks[1::2], blocks[2::2]))
    ids = {name.split(" (")[0].split(" / ")[0] for name in workers}
    # Only self-tests inject a detector to compare with the default inventory.
    if detector is not None and _declared_workers(detector) != workers:
        raise ValueError("SKIPPABLE inventory differs from the default declaration")
    needs = re.search(r"(?m)^    needs: \[([^\]]+)\]", jobs["ci-green"])
    if (set(jobs) != ids | {"ci-green", "changes"} or needs is None
            or {value.strip() for value in needs[1].split(",")} != ids | {"changes"}):
        raise ValueError("worker inventory differs from ci.yml")
    for name in ids | {"changes"}:
        job = jobs[name]
        # A more-indented line after `if:` folds into the condition
        # (`FORK_GUARD || true`), so the guard must end its condition.
        conditions = re.findall(r"(?m)^    if:(.*)\n((?:[ \t]*(?:#.*)?\n)*)(     )?", job)
        expected = [] if public else [(" " + FORK_GUARD, "")]
        if [(text, more) for text, _, more in conditions] != expected:
            raise ValueError("conditional worker cannot establish full coverage")
        if public:
            if name == "candidate-identity":
                if job.strip() != "permissions: {}\n    uses: ./.github/workflows/public-ci-candidate.yml":
                    raise ValueError("candidate identity must use the exact relative witness")
            elif re.findall(r"(?m)^    runs-on: (.*)$", job) != ["macos-26" if name == "test-macos" else "ubuntu-24.04"]:
                raise ValueError("public worker runner differs")
    for name, job in jobs.items():
        strategies = re.findall(r"""(?m)^    (?:strategy|'strategy'|"strategy") *:(.*)$""", job)
        # Only test uses a strategy. Refuse unfamiliar forms, including inline
        # strategies that the block-matrix parser below cannot inspect.
        if strategies != ([""] if name == "test" else []):
            raise ValueError("matrix inventory differs from ci.yml")
    matrices = re.findall(r"(?m)^      matrix:\n((?:        .*\n|\s*\n)+)", jobs["test"])
    if not matrices:
        raise ValueError("missing matrix inventory")
    bodies = ["".join(line.split("#")[0].strip() for line in matrix.splitlines()) for matrix in matrices]
    if bodies != ["os: [ubuntu-24.04]"]:
        raise ValueError("matrix inventory differs from ci.yml")


def full_evidence(run, jobs, now, workers):
    if (run["path"] != ".github/workflows/ci.yml" or run["head_branch"] != "main"
            or run["event"] not in {"push", "schedule", "workflow_dispatch"}
            or run["status"] != "completed" or run["conclusion"] not in {"success", "failure"}):
        return False
    names = [job["name"] for job in jobs]
    if set(names) != workers | {"ci-green", "changes"} or len(names) != len(set(names)):
        return False
    finishes = []
    for job in jobs:
        if (job["status"] != "completed" or job["conclusion"] not in {"success", "failure", "timed_out"}
                or job["head_sha"] != run["head_sha"] or not job["steps"]
                or any(step["status"] != "completed"
                       for step in job["steps"])
                or not any(step["conclusion"] in {"success", "failure"} for step in job["steps"])):
            return False
        finishes.append(timestamp(job["completed_at"]))
    finished = max(finishes)
    return now - timedelta(hours=26) <= finished <= now


def cutoff(now):
    # Two hours beyond the 26h completion window allow a full run to finish.
    return now - timedelta(hours=28)


def recent_runs(repo, now):
    query = urlencode(dict(branch="main", per_page=100,
                           created=">=" + cutoff(now).isoformat()))
    return pages(f"repos/{repo}/actions/workflows/ci.yml/runs?{query}", "workflow_runs")


def check(runs, jobs_for, now, workers):
    deadline = monotonic() + 180
    # GitHub returns newest-created runs first. Do not fetch old attempts.
    for run in runs:
        if timestamp(run["created_at"]) < cutoff(now):
            break
        if monotonic() >= deadline:
            raise ValueError("freshness query budget exhausted; no completed full main CI")
        if (run["path"] == ".github/workflows/ci.yml" and run["head_branch"] == "main"
                and run["event"] in {"push", "schedule", "workflow_dispatch"}
                and run["status"] == "completed" and run["conclusion"] in {"success", "failure"}):
            if full_evidence(run, jobs_for(run), now, workers):
                print(f"fresh full CI: {run['conclusion']} {run['head_sha']} {run['html_url']}")
                return
    raise ValueError("no completed full main ci.yml run within 26 hours")


def self_test(workers):
    now = datetime(2026, 1, 3, tzinfo=timezone.utc)
    run = dict(id=1, run_attempt=1, path=".github/workflows/ci.yml", head_branch="main", event="schedule",
               created_at=now.isoformat(), status="completed", conclusion="success", head_sha="a" * 40, html_url="https://example.invalid/run/1")
    jobs = [dict(name=name, status="completed", conclusion="success", head_sha=run["head_sha"],
                 completed_at=now.isoformat(), steps=[dict(status="completed", conclusion="success")])
            for name in sorted(workers | {"ci-green", "changes"})]
    cases = 0

    def refused(label, operation, message):
        nonlocal cases
        try:
            operation()
        except ValueError as exc:
            if message not in str(exc):
                raise RuntimeError(f"{label}: got {str(exc)!r}, expected {message!r}") from exc
        else:
            raise RuntimeError(f"{label}: accepted, expected {message!r}")
        cases += 1
        print(f"freshness self-test: {label} refused PASS")

    def case(label, change, want, diagnostic="no completed full main ci.yml run within 26 hours"):
        nonlocal cases
        cases += 1
        r, j = copy.deepcopy(run), copy.deepcopy(jobs)
        change(r, j)
        try:
            check([r], lambda _: j, now, workers)
        except ValueError as exc:
            if want or diagnostic not in str(exc):
                raise RuntimeError(label) from exc
        else:
            if not want:
                raise RuntimeError(label)
        print(f"freshness self-test: {label} PASS")

    case("fresh success", lambda r, j: None, True)
    case("fresh failed full run", lambda r, j: (r.update(conclusion="failure"), j[0].update(conclusion="failure")), True)
    case("failed worker with trailing skipped steps", lambda r, j: (
        r.update(conclusion="failure"), j[0].update(conclusion="failure", steps=[
            dict(status="completed", conclusion="failure"), dict(status="completed", conclusion="skipped")])), True)
    case("timed-out worker with cancelled trailing step", lambda r, j: (
        r.update(conclusion="failure"), j[0].update(conclusion="timed_out", steps=[
            dict(status="completed", conclusion="success"), dict(status="completed", conclusion="cancelled")])), True)
    for hours, want in [(26, True), (26.0001, False), (27, False)]:
        case(f"age {hours}h", lambda r, j, h=hours: [job.update(completed_at=(now-timedelta(hours=h)).isoformat()) for job in j], want)
    for field, value in [("event", "pull_request"), ("head_branch", "topic"), ("path", ".github/workflows/other.yml"),
                         ("conclusion", "cancelled"), ("conclusion", "skipped"), ("status", "in_progress")]:
        case(f"wrong {field} {value}", lambda r, j, f=field, v=value: r.update({f: v}), False)
    case("partial inventory", lambda r, j: j.pop(), False)
    case("duplicate worker", lambda r, j: j.append(j[0]), False)
    for value in ["cancelled", "skipped"]:
        case(f"worker {value}", lambda r, j, v=value: j[0].update(conclusion=v), False)
    case("wrong worker head", lambda r, j: j[0].update(head_sha="b"*40), False)
    for label, runs, getter, message in [
            ("absent", [], lambda _: [], "no completed"),
            ("unreadable API", [run], lambda _: (_ for _ in ()).throw(ValueError("unreadable API")), "unreadable API")]:
        cases += 1
        try:
            check(runs, getter, now, workers)
        except ValueError as exc:
            if message not in str(exc):
                raise RuntimeError(label) from exc
        else:
            raise RuntimeError(label)
        print(f"freshness self-test: {label} PASS")
    with tempfile.TemporaryDirectory(prefix="freshness-fixture-") as tmp:
        root = Path(tmp)
        stub = root / "gh"
        stub.write_text('#!/usr/bin/env python3\nimport os, sys\nif os.environ.get("FRESHNESS_ST_ENDPOINT") and sys.argv[2] != os.environ["FRESHNESS_ST_ENDPOINT"]: raise SystemExit(42)\nprint(os.environ["FRESHNESS_ST_PAGE"])\n')
        stub.chmod(0o755)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = tmp + os.pathsep + old_path
        try:
            for label, payload, want in [
                ("paginated API", [{"total_count": 2, "jobs": [1]}, {"total_count": 2, "jobs": [2]}], True),
                ("truncated API", [{"total_count": 2, "jobs": [1]}], False),
                ("unreadable API page", {}, False),
                ("unreadable JSON", "bad JSON", False)]:
                cases += 1
                os.environ["FRESHNESS_ST_PAGE"] = payload if isinstance(payload, str) else json.dumps(payload)
                try:
                    result = pages("fixture", "jobs")
                except ValueError as exc:
                    if want or not any(word in str(exc) for word in ["truncated", "unreadable", "Expecting value"]):
                        raise RuntimeError(label) from exc
                else:
                    if not want or result != [1, 2]:
                        raise RuntimeError(label)
                print(f"freshness self-test: {label} PASS")
            cases += 1
            os.environ["FRESHNESS_ST_PAGE"] = json.dumps([{"total_count": 1001, "workflow_runs": [{"id": i} for i in range(1000)]}])
            try:
                pages("fixture", "workflow_runs")
            except ValueError as exc:
                if "truncated API history" not in str(exc):
                    raise
            else:
                raise RuntimeError("lifetime run cap silently accepted")
            print("freshness self-test: lifetime 1000-result cap refuses truncated API history PASS")
            cases += 1
            os.environ["FRESHNESS_ST_PAGE"] = json.dumps([{"total_count": 0, "workflow_runs": []}])
            error = io.StringIO()
            with patch.object(sys, "argv", [sys.argv[0]]), patch.dict(os.environ, GITHUB_REPOSITORY="fixture/repo"), redirect_stderr(error):
                if main() != 1 or "no completed full main ci.yml run within 26 hours" not in error.getvalue():
                    raise RuntimeError("alarm must exit failed, not wait for cancellation")
            print("freshness self-test: empty-window CLI exits 1 with freshness diagnostic PASS")
            cases += 1
            os.environ["FRESHNESS_ST_PAGE"] = json.dumps([{"total_count": 1, "workflow_runs": [run]}])
            os.environ["FRESHNESS_ST_ENDPOINT"] = "repos/fixture/repo/actions/workflows/ci.yml/runs?branch=main&per_page=100&created=%3E%3D2026-01-01T20%3A00%3A00%2B00%3A00"
            if recent_runs("fixture/repo", now) != [run]:
                raise RuntimeError("unbounded run history")
            print("freshness self-test: creation-window query excludes lifetime history PASS")
            cases += 1
            os.environ["FRESHNESS_ST_PAGE"] = json.dumps([{"total_count": 2, "jobs": [1, 2]}])
            os.environ["FRESHNESS_ST_ENDPOINT"] = "repos/fixture/repo/actions/runs/1/attempts/2/jobs?per_page=100"
            if run_jobs("fixture/repo", dict(id=1, run_attempt=2)) != [1, 2]:
                raise RuntimeError("wrong attempt jobs")
            print("freshness self-test: jobs belong to the exact run attempt PASS")
        finally:
            os.environ.pop("FRESHNESS_ST_ENDPOINT", None)
            os.environ["PATH"] = old_path
            os.environ.pop("FRESHNESS_ST_PAGE", None)
        text = Path(".github/workflows/ci.yml").read_text()
        fixture = root / "ci.yml"
        fixture.write_text(text)
        inventory(fixture, workers)
        for label, replacement, message in [
                ("new worker", text + "\n  extra-worker:\n    runs-on: linux\n", "worker inventory"),
                ("missing need", text.replace("needs: [lint, test,", "needs: [test,"), "worker inventory"),
                ("conditional worker", text.replace("  lint:\n", "  lint:\n    if: false\n"), "conditional worker"),
                ("unguarded changes", text.replace("  changes:\n    if: " + FORK_GUARD + "\n", "  changes:\n"), "conditional worker"),
                ("conditional changes", text.replace("  changes:\n", "  changes:\n    if: false\n"), "conditional worker"),
                ("unguarded worker", text.replace("  lint:\n    if: " + FORK_GUARD + "\n", "  lint:\n"), "conditional worker"),
                ("altered fork guard", text.replace("  lint:\n    if: " + FORK_GUARD, "  lint:\n    if: github.event_name != 'pull_request'"),
                 "conditional worker"),
                ("continued fork guard", text.replace("  lint:\n    if: " + FORK_GUARD + "\n",
                                                      "  lint:\n    if: " + FORK_GUARD + "\n      || true\n"),
                 "conditional worker"),
                ("matrix changed", text.replace("os: [ubuntu-24.04]", "os: [ubuntu-24.04, macos-15]"), "matrix inventory"),
                ("matrix missing", text.replace("      matrix:\n", "      # matrix:\n"), "missing matrix inventory"),
                ("matrix on another worker", text.replace("  lint:\n", "  lint:\n    strategy:\n      matrix:\n        os: [ubuntu-24.04]\n"), "matrix inventory differs"),
                ("inline matrix on ci-green", text.replace("    needs: [lint,", "    strategy: {matrix: {os: [ubuntu-24.04]}}\n    needs: [lint,"), "matrix inventory differs")]:
            fixture.write_text(replacement)
            refused(label, lambda: inventory(fixture, workers), message)
        detector = root / "ci-changes.py"
        names = tuple(sorted(workers))
        declaration = "SKIPPABLE = " + repr(names) + "\n"
        absent = "SKIPPABLE must have exactly one declaration"
        malformed = "SKIPPABLE must contain check names of the form <id> or <id> (…)"
        distinct = "SKIPPABLE must name distinct workers"
        mismatch = "SKIPPABLE inventory differs from the default declaration"
        copy_script = root / "check-ci-freshness.py"
        copy_script.write_bytes(Path(__file__).read_bytes())
        detector.write_text(declaration + 'raise RuntimeError("detector executed")\n')
        copied = runpy.run_path(str(copy_script))
        derived = copied["_declared_workers"](copied["DETECTOR"])
        if derived != workers:
            raise RuntimeError(f"default SKIPPABLE derivation: got {derived!r}, expected {workers!r}")
        cases += 1
        print("freshness self-test: default SKIPPABLE derivation reads literal names PASS")
        env = os.environ.copy()
        env.pop("GITHUB_REPOSITORY", None)
        for label, source, diagnostic in [
                ("missing file", None, f"[Errno 2] No such file or directory: {str(detector)!r}"),
                ("missing declaration", "OTHER = ()\n", absent),
                ("duplicate declarations", declaration * 2, absent),
                ("annotated duplicate declaration", declaration + "SKIPPABLE: tuple = ()\n", absent),
                ("invalid declaration syntax", "SKIPPABLE = (", "malformed SKIPPABLE declaration"),
                ("nonliteral declaration", "SKIPPABLE = tuple()", "malformed SKIPPABLE declaration"),
                ("malformed declaration", "SKIPPABLE = " + repr(list(names)), malformed)]:
            if source is None:
                detector.unlink()
            else:
                detector.write_text(source)
            for mode, args in [("normal", []), ("--self-test", ["--self-test"])]:
                result = subprocess.run([sys.executable, str(copy_script), *args],
                                        env=env, capture_output=True, text=True)
                got = (result.returncode, result.stdout, result.stderr)
                expected = (1, "", f"freshness: refused — {diagnostic}\n")
                if got != expected:
                    raise RuntimeError(f"default detector {label} ({mode}): got {got!r}, expected {expected!r}")
                cases += 1
                print(f"freshness self-test: default detector {label} ({mode}) refused PASS")
        expanded = workers | {"extra-worker"}
        detector.write_text("SKIPPABLE = " + repr((*names, "extra-worker")) + "\n")
        derived = copied["_declared_workers"](copied["DETECTOR"])
        if derived != expanded:
            raise RuntimeError(f"expanded SKIPPABLE derivation: got {sorted(derived)!r}, expected {sorted(expanded)!r}")
        cases += 1
        print("freshness self-test: default SKIPPABLE derivation accepts a different worker count PASS")
        detector.write_text(declaration)
        inventory(".github/workflows/ci.yml", workers, detector)
        for label, source, diagnostic in [
                ("missing SKIPPABLE declaration", "OTHER = ()\n", absent),
                ("duplicate SKIPPABLE declarations", declaration * 2, absent),
                ("SKIPPABLE list type", "SKIPPABLE = " + repr(list(names)), malformed),
                ("SKIPPABLE empty tuple", "SKIPPABLE = ()", malformed),
                ("SKIPPABLE one short", "SKIPPABLE = " + repr(names[:-1]), mismatch),
                ("SKIPPABLE one extra", "SKIPPABLE = " + repr(names + ("extra-worker",)), mismatch),
                ("SKIPPABLE duplicate names", "SKIPPABLE = " + repr((names[1],) + names[1:]), distinct),
                ("SKIPPABLE duplicate ids", "SKIPPABLE = " + repr(names + (names[0] + " (extra)",)), distinct),
                ("SKIPPABLE non-string name", "SKIPPABLE = " + repr((17,) + names[1:]), malformed),
                ("SKIPPABLE name syntax", "SKIPPABLE = " + repr((names[0] + " (bad\n)",) + names[1:]), malformed),
                ("SKIPPABLE worker id equality", "SKIPPABLE = " + repr(("different",) + names[1:]), mismatch),
                ("SKIPPABLE check name changed with the same id", "SKIPPABLE = " + repr((names[0] + " (extra)",) + names[1:]), mismatch)]:
            detector.write_text(source)
            refused(label, lambda: inventory(".github/workflows/ci.yml", workers, detector), diagnostic)
        shortened = workers - {"lint"}
        detector.write_text("SKIPPABLE = " + repr(tuple(sorted(shortened))) + "\n")
        fixture.write_text(re.sub(r"(?ms)^  lint:.*?(?=^  [a-z][a-z0-9-]*:)", "", text)
                           .replace("needs: [lint, test,", "needs: [test,"))
        inventory(fixture, shortened, detector)
        refused("ci.yml and SKIPPABLE both one short", lambda: inventory(fixture, workers, detector), mismatch)
    # One recent incomplete run plus arbitrarily deep historical runs must
    # produce the alarm, with no attempt-job request for history.
    old = dict(run, created_at=(cutoff(now)-timedelta(seconds=1)).isoformat())
    requests = []
    try:
        check([dict(run, status="in_progress")] + [old] * 1001,
              lambda r: requests.append(r) or jobs, now, workers)
    except ValueError as exc:
        if "no completed full main ci.yml run within 26 hours" not in str(exc) or requests:
            raise RuntimeError("historical jobs fetched") from exc
    else:
        raise RuntimeError("missing freshness alarm")
    cases += 1
    print("freshness self-test: alarm ignores 1001 historical attempts PASS")
    check([run, old], lambda _: jobs, now, workers)
    cases += 1
    print("freshness self-test: bounded scan accepts fresh evidence PASS")
    with patch(__name__ + ".monotonic", side_effect=[0, 181]):
        try:
            check([run], lambda _: (_ for _ in ()).throw(RuntimeError("over-budget jobs fetched")), now, workers)
        except ValueError as exc:
            if "freshness query budget exhausted" not in str(exc):
                raise
        else:
            raise RuntimeError("query budget ignored")
    cases += 1
    print("freshness self-test: exhausted query budget fails before more jobs PASS")
    error = io.StringIO()
    with patch.object(sys, "argv", [sys.argv[0]]), patch.dict(os.environ, GITHUB_REPOSITORY="fixture/repo"), patch(__name__ + ".recent_runs", side_effect=subprocess.TimeoutExpired("stub API", 20)), redirect_stderr(error):
        if main() != 1 or "timed out after 20 seconds" not in error.getvalue():
            raise RuntimeError("API timeout did not exit failed")
    cases += 1
    print("freshness self-test: API timeout CLI exits 1 PASS")
    workflow = Path(".github/workflows/ci.yml").read_text()
    canary = Path(".github/workflows/ci-freshness.yml").read_text()
    def workflow_contract(ci, alarm):
        if "github.event_name == 'pull_request' && github.ref || github.run_id" not in ci:
            raise ValueError("full runs can replace pending runs")
        if "runs-on: ubuntu-24.04" not in alarm or "self-hosted" in alarm:
            raise ValueError("freshness alarm depends on self-hosted fleet")
        if "permissions: {}" not in alarm or "permissions: { actions: read, contents: read }" not in alarm:
            raise ValueError("freshness permissions must stay read-only")
    for label, ci, alarm, diagnostic in [
            ("shared full concurrency", workflow.replace("github.event_name == 'pull_request' && github.ref || github.run_id", "github.ref"), canary, "full runs can replace pending runs"),
            ("self-hosted alarm", workflow, canary.replace("runs-on: ubuntu-24.04", "runs-on: [self-hosted, linux]"), "freshness alarm depends on self-hosted fleet")]:
        cases += 1
        try:
            workflow_contract(ci, alarm)
        except ValueError as exc:
            if diagnostic not in str(exc):
                raise RuntimeError(label) from exc
        else:
            raise RuntimeError(label)
        print(f"freshness self-test: {label} refused PASS")
    workflow_contract(workflow, canary)
    cases += 1
    print("freshness self-test: independent full runs and hosted alarm PASS")
    if cases != 76:
        raise RuntimeError(f"wrong case count {cases}")
    inventory(".github/workflows/ci.yml", workers)
    print(f"freshness self-test: {cases}/{cases} controls passed; worker inventory matches")


def public_self_test(workers):
    # Replay every private/API/age/attempt control against its original guarded
    # schema in a disposable tree. The public schema has its own paired controls.
    previous = Path.cwd()
    text = Path(".github/workflows/ci.yml").read_text()
    canary = Path(".github/workflows/ci-freshness.yml").read_text()
    with tempfile.TemporaryDirectory(prefix="granary-freshness-public-") as directory:
        root = Path(directory)
        fixture = root / ".github/workflows/ci.yml"
        fixture.parent.mkdir(parents=True)
        private = re.sub(r"(?m)^  (?!ci-green:)([a-z][a-z0-9-]*):[^\n]*\n",
                         lambda match: match[0] + "    if: " + FORK_GUARD + "\n", text)
        fixture.write_text(private)
        (fixture.parent / "ci-freshness.yml").write_text(canary)
        try:
            os.chdir(root)
            self_test(workers)
        finally:
            os.chdir(previous)
        fixture.write_text(text)
        inventory(fixture, workers, public=True)
        cases = 1
        for label, altered, diagnostic in (
                ("conditional worker", text.replace("  lint:\n", "  lint:\n    if: false\n"), "conditional worker"),
                ("private runner", text.replace("    runs-on: ubuntu-24.04", "    runs-on: [self-hosted, linux]", 1), "runner differs"),
                ("wrong Mac image", text.replace("    runs-on: macos-26", "    runs-on: macos-15"), "runner differs"),
                ("missing need", text.replace("needs: [lint, test,", "needs: [test,"), "worker inventory"),
                ("extra worker", text + "  extra-worker:\n    runs-on: ubuntu-24.04\n", "worker inventory"),
                ("explicit witness ref", text.replace("uses: ./.github/workflows/public-ci-candidate.yml", "uses: ./.github/workflows/public-ci-candidate.yml@main"), "exact relative witness"),
                ("conditional witness", text.replace("  candidate-identity:\n", "  candidate-identity:\n    if: false\n"), "conditional worker")):
            fixture.write_text(altered)
            try:
                inventory(fixture, workers, public=True)
            except ValueError as exc:
                if diagnostic not in str(exc):
                    raise RuntimeError(f"{label}: unexpected refusal {exc}") from exc
            else:
                raise RuntimeError(f"{label}: public inventory accepted invalid workflow")
            cases += 1
            print(f"public freshness self-test: {label} refused PASS")
    inventory(".github/workflows/ci.yml", workers, public=True)
    print(f"public freshness self-test: {cases}/{cases} controls passed; worker inventory matches")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--public", action="store_true", help="require the hosted public worker schema")
    args = parser.parse_args()
    try:
        workers = _declared_workers(DETECTOR)
        if args.self_test:
            if args.public:
                public_self_test(workers)
            else:
                self_test(workers)
        else:
            inventory(".github/workflows/ci.yml", workers, public=args.public)
            repo = os.environ["GITHUB_REPOSITORY"]
            now = datetime.now(timezone.utc)
            runs = recent_runs(repo, now)
            check(runs, lambda run: run_jobs(repo, run), now, workers)
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"freshness: refused — {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
