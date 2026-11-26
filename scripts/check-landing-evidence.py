#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Read-only preflight for a pinned GitHub Actions PR landing candidate.

The trusted controller supplies a reviewed gate path list and selects the run
ID. This command verifies the selected run's current attempt and returns a
point-in-time evidence record.
"""

import argparse
import json
import os
import re
import subprocess
import sys


OID = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+")
PATH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml")
API = "https://api.github.com"


def expect(row, diagnostic, **fields):
    if not isinstance(row, dict) or any(
        type(row.get(key)) is not type(value) or row[key] != value for key, value in fields.items()
    ):
        raise ValueError(diagnostic)


def positive(value):
    return type(value) is int and value > 0


def unique_fields(pairs):
    row = dict(pairs)
    if len(row) != len(pairs):
        raise ValueError("GitHub response contains a duplicate JSON field")
    return row


def github(endpoint, *, pages=False):
    cmd = ["gh", "api", endpoint, "--hostname", "github.com", "--method", "GET",
           "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28"]
    if pages:
        cmd.extend(["--paginate", "--slurp"])
    result = subprocess.run(cmd, check=True, capture_output=True, encoding="utf-8", timeout=30)
    return json.loads(result.stdout, object_pairs_hook=unique_fields)


def git(*args):
    return subprocess.check_output(
        ["git", "--no-replace-objects", "--literal-pathspecs", *args], stderr=subprocess.PIPE,
        env=dict(os.environ, GIT_GRAFT_FILE=os.devnull, GIT_NO_LAZY_FETCH="1"), timeout=10,
    )


def gate_entry(oid, path):
    entry = git("ls-tree", "-z", oid, "--", path)
    header, separator, name = entry.partition(b"\t")
    if not separator or name != path.encode("ascii") + b"\0" or not re.fullmatch(
        rb"100(?:644|755) blob [0-9a-f]{40}", header,
    ):
        raise ValueError(f"trusted gate {path} must be a regular Git blob")
    mode, _, blob = header.decode("ascii").split()
    return mode, blob


def validate_policy(args):
    if not REPO.fullmatch(args.repo) or args.repo.split("/")[1] in {".", ".."}:
        raise ValueError("expected the canonical GitHub owner/repository")
    if not all(OID.fullmatch(oid) for oid in (args.base, args.head, args.tested_merge)):
        raise ValueError("expected full lowercase Git object IDs")
    if not PATH.fullmatch(args.base_ref):
        raise ValueError("invalid base branch")
    git("check-ref-format", f"refs/heads/{args.base_ref}")
    if not all(WORKFLOW.fullmatch(path) for path in (args.workflow_path, args.reusable_workflow)):
        raise ValueError("expected two .github/workflows/ YAML paths")
    gate_paths = [args.workflow_path, args.reusable_workflow, *args.gate_path]
    if len(set(gate_paths)) != len(gate_paths) or any(
        not PATH.fullmatch(path) or {".", ".."}.intersection(path.split("/")) for path in gate_paths
    ):
        raise ValueError("expected distinct repository-relative trusted gate paths")
    if (args.required_job == args.identity_job or not args.identity_job.strip() or not args.required_job.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in args.required_job + args.identity_job)):
        raise ValueError("expected distinct names for the summary and candidate identity jobs")
    if len({args.base, args.head, args.tested_merge}) != 3:
        raise ValueError("base, head and tested merge must be distinct commits")
    for oid in (args.base, args.head, args.tested_merge):
        if git("cat-file", "-t", oid) != b"commit\n":
            raise ValueError("base, head and tested merge must be Git commits")
    headers, separator, _ = git("cat-file", "commit", args.tested_merge).partition(b"\n\n")
    parents = tuple(line[7:] for line in headers.splitlines() if line.startswith(b"parent "))
    if not separator or parents != (args.base.encode("ascii"), args.head.encode("ascii")):
        raise ValueError("tested merge parents differ from the pinned base and head")
    manifest = []
    for path in sorted(gate_paths):
        base_entry = gate_entry(args.base, path)
        if base_entry != gate_entry(args.tested_merge, path):
            raise ValueError(f"trusted gate differs from the published base at {path}")
        mode, blob = base_entry
        manifest.append({"path": path, "mode": mode, "blob": blob})
    return manifest


def read_candidate(args, root):
    live_pr = github(f"{root}/pulls/{args.pr}")
    expect(live_pr, "live PR is not the pinned open, ready PR with the tested merge",
           number=args.pr, state="open", draft=False, merged=False, merge_commit_sha=args.tested_merge)
    expect(live_pr["base"], "live PR base differs from the pinned base", ref=args.base_ref, sha=args.base)
    expect(live_pr["base"]["repo"], "live PR targets the wrong repository",
           id=args.repo_id, full_name=args.repo)
    expect(live_pr["head"], "live PR head differs from the pinned head", sha=args.head)
    head_repo = live_pr["head"]["repo"]["id"]
    head_ref = live_pr["head"]["ref"]
    if not positive(head_repo) or not isinstance(head_ref, str) or not head_ref:
        raise ValueError("live PR head repository or ref is unavailable")
    for ref, sha in [(f"heads/{args.base_ref}", args.base), (f"pull/{args.pr}/merge", args.tested_merge)]:
        row = github(f"{root}/git/ref/{ref}")
        expect(row, f"live Git ref refs/{ref} is unavailable", ref=f"refs/{ref}")
        expect(row["object"], f"live Git ref refs/{ref} differs from the pinned commit", type="commit", sha=sha)
    return head_repo, head_ref


def validate_run(row, args, head_identity):
    expect(row, "workflow run differs from the pinned completed pull_request run and attempt",
           id=args.run_id, workflow_id=args.workflow_id, path=args.workflow_path, event="pull_request",
           head_sha=args.head, head_branch=head_identity[1], run_attempt=args.attempt,
           status="completed", conclusion="success")
    expect(row["repository"], "workflow run repository differs from the pinned repository",
           id=args.repo_id, full_name=args.repo)
    expect(row["head_repository"], "workflow run head repository differs from the live PR", id=head_identity[0])
    if not positive(row.get("check_suite_id")):
        raise ValueError("workflow run has no valid check suite")

    # GitHub resolves a relative reusable workflow at the caller's commit.
    # Require the observed server-resolved shape as well as the exact merge
    # ref. A nested call could resolve the witness at another caller's commit,
    # so the witness must be the run's sole referenced workflow. The run's
    # pull_requests array only matches open PRs by branch/SHA.
    # Rehearse the resolved shape and explicit-ref refusal on a controlled
    # fork before relying on this preflight for production landing.
    prefix = f"{args.repo}/{args.reusable_workflow}"
    refs = row.get("referenced_workflows")
    if not isinstance(refs, list) or len(refs) != 1:
        raise ValueError("expected the pinned reusable workflow to be the run's sole reference")
    reference = {"path": f"{prefix}@{args.tested_merge}", "sha": args.tested_merge, "ref": f"refs/pull/{args.pr}/merge"}
    expect(refs[0], "reusable workflow does not prove the pinned PR merge ref and commit", **reference)
    return row["check_suite_id"], {key: refs[0][key] for key in reference}


def read_jobs(attempt):
    pages = github(f"{attempt}/jobs?per_page=100", pages=True)
    if not isinstance(pages, list) or not pages or any(
        not isinstance(page, dict) or not positive(page.get("total_count"))
        or not isinstance(page.get("jobs"), list) or not page["jobs"] for page in pages
    ):
        raise ValueError("unreadable attempt job inventory")
    jobs = [job for page in pages for job in page["jobs"]]
    if any(page["total_count"] != len(jobs) for page in pages):
        raise ValueError("incomplete attempt job inventory")
    return jobs


def read_run_evidence(args, root, run_path, head_identity):
    suite, reusable = validate_run(github(run_path), args, head_identity)
    attempt = f"{run_path}/attempts/{args.attempt}"
    if validate_run(github(attempt), args, head_identity) != (suite, reusable):
        raise ValueError("workflow run and attempt disagree on the check suite")

    jobs = read_jobs(attempt)
    seen = set()
    for job in jobs:
        expect(job, "attempt job does not match the workflow run, attempt and head",
               run_id=args.run_id, run_attempt=args.attempt, head_sha=args.head)
        if not positive(job.get("id")) or job["id"] in seen or not isinstance(job.get("name"), str):
            raise ValueError("invalid or duplicate attempt job in the inventory")
        seen.add(job["id"])

    evidence = {}
    for name in (args.required_job, args.identity_job):
        matches = [job for job in jobs if job["name"] == name]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one required job {name}")
        job, = matches
        check_path = f"{root}/check-runs/{job['id']}"
        expect(job, f"required job {name} is not a successful GitHub Actions job",
               status="completed", conclusion="success", check_run_url=f"{API}/{check_path}")
        check = github(check_path)
        expect(check, f"check run for {name} does not match the successful Actions job",
               id=job["id"], name=name, status="completed", conclusion="success", head_sha=args.head)
        expect(check["check_suite"], f"check run for {name} has the wrong suite", id=suite)
        expect(check["app"], f"check run for {name} has the wrong GitHub Actions App",
               id=args.actions_app_id, slug="github-actions")
        evidence[name] = job["id"]
    return suite, reusable, evidence


def verify_registration(args, root):
    workflow_path = f"{root}/actions/workflows/{args.workflow_id}"
    expect(github(workflow_path), "published workflow has the wrong ID, path or state",
           id=args.workflow_id, path=args.workflow_path, state="active")


def preflight(args):
    manifest = validate_policy(args)
    root = f"repos/{args.repo}"
    verify_registration(args, root)

    head_identity = read_candidate(args, root)
    run_path = f"{root}/actions/runs/{args.run_id}"
    suite, reusable, jobs = read_run_evidence(args, root, run_path, head_identity)
    if read_run_evidence(args, root, run_path, head_identity) != (suite, reusable, jobs):
        raise ValueError("required job or check suite identity changed during preflight")
    if read_candidate(args, root) != head_identity:
        raise ValueError("live PR head identity changed during preflight")
    verify_registration(args, root)
    if validate_run(github(run_path), args, head_identity) != (suite, reusable):
        raise ValueError("workflow run check suite changed during preflight")

    return {"repository": args.repo, "repository_id": args.repo_id, "pr": args.pr,
            "base_ref": args.base_ref, "base": args.base, "head": args.head, "tested_merge": args.tested_merge,
            "head_repository_id": head_identity[0], "head_ref": head_identity[1],
            "workflow_id": args.workflow_id, "workflow_path": args.workflow_path, "run_id": args.run_id,
            "run_attempt": args.attempt, "check_suite_id": suite, "actions_app_id": args.actions_app_id,
            "reusable_workflow": reusable, "jobs": jobs, "trusted_gate_manifest": manifest}


def positive_id(text):
    if not re.fullmatch(r"[1-9][0-9]{0,18}", text):
        raise argparse.ArgumentTypeError("expected a positive decimal ID")
    return int(text)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
        epilog=(
            "Run the trusted copy with owner-pinned policy and Git objects. gh supplies GitHub read access.\n"
            "A successful result describes the observed state. Refs and attempts can change after it."
        ),
    )
    parser.add_argument("--repo", required=True)
    parser.add_argument("--repo-id", required=True, type=positive_id)
    parser.add_argument("--pr", required=True, type=positive_id)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tested-merge", required=True)
    parser.add_argument("--workflow-id", required=True, type=positive_id)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--required-job", required=True, help="exact published summary job name")
    parser.add_argument("--actions-app-id", required=True, type=positive_id)
    parser.add_argument("--run-id", required=True, type=positive_id, help="trusted selection of the workflow run")
    parser.add_argument("--attempt", required=True, type=positive_id, help="the selected run's current attempt")
    parser.add_argument("--reusable-workflow", required=True, help="published same-commit witness workflow path")
    parser.add_argument("--identity-job", required=True, help="exact published reusable witness job name")
    parser.add_argument("--gate-path", action="append", default=[],
                        help="path to an additional trusted gate dependency, repeat for each")
    args = parser.parse_args()
    try:
        print(json.dumps(preflight(args)))
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError, KeyError, TypeError):
        print("refused: could not read the required GitHub or Git evidence", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
