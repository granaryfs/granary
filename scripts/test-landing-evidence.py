#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Exercise the landing preflight with pinned Git objects and GitHub REST shapes."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECK = Path(__file__).with_name("check-landing-evidence.py").resolve()
REPO = "example/granary"
REPO_ID = 523043277
FORK_ID = 910311225
PR = 17
WORKFLOW = ".github/workflows/ci.yml"
REUSABLE = ".github/workflows/public-ci-candidate.yml"
GATE = "scripts/check-ci-ok.py"
EXTRA_GATE = "scripts/worker-policy.py"
WORKFLOW_ID = 47404346
RUN = 45741664832
SUITE = 123759420551
APP = 15368
SUMMARY_JOB = 139647899143
IDENTITY_JOB = 139647900852
OTHER_HEAD = "a" * 40
OTHER_BASE = "b" * 40
OTHER_MERGE = "c" * 40

ROOT = f"repos/{REPO}"
PR_ENDPOINT = f"{ROOT}/pulls/{PR}"
WORKFLOW_ENDPOINT = f"{ROOT}/actions/workflows/{WORKFLOW_ID}"
RUN_ENDPOINT = f"{ROOT}/actions/runs/{RUN}"
ATTEMPT_ENDPOINT = f"{RUN_ENDPOINT}/attempts/1"
JOBS_ENDPOINT = f"{ATTEMPT_ENDPOINT}/jobs?per_page=100"
BASE_ENDPOINT = f"{ROOT}/git/ref/heads/main"
MERGE_ENDPOINT = f"{ROOT}/git/ref/pull/{PR}/merge"


def check_run_endpoint(job_id):
    return f"{ROOT}/check-runs/{job_id}"


# Model only the external service boundary. Any unexpected request or method
# fails the test, and repeated reads can receive an advanced ref or attempt.
FAKE_GH = r'''
import json
from pathlib import Path
import sys

fixture = Path(".git/gh-fixture.json")
calls = Path(".git/gh-calls")
args = sys.argv[1:]
assert args[0] == "api"
endpoints = [arg for arg in args if arg.startswith("repos/")]
endpoint, = endpoints
assert args[args.index("--hostname") + 1] == "github.com"
assert args[args.index("--method") + 1] == "GET"
assert sorted(args[index + 1] for index, arg in enumerate(args) if arg == "-H") == [
    "Accept: application/vnd.github+json", "X-GitHub-Api-Version: 2022-11-28",
]
assert ("--paginate" in args) == ("--slurp" in args) == ("/jobs?" in endpoint)
history = calls.read_text().splitlines() if calls.exists() else []
with calls.open("a") as log:
    log.write(endpoint + "\n")
responses = json.loads(fixture.read_text())[endpoint]
print(json.dumps(responses[min(history.count(endpoint), len(responses) - 1)]))
'''


class LandingEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.git("init", "-q")
        self.git("config", "commit.gpgsign", "false")
        self.base_tree = self.tree()
        self.base = self.commit(self.base_tree, "base")
        self.head = self.commit(self.tree(contributed=True), "head", self.base)
        self.merge = self.commit(self.tree(contributed=True), "merge", self.base, self.head)
        gh = self.directory / ".git" / "gh"
        gh.write_text(f"#!{sys.executable}\n" + FAKE_GH)
        gh.chmod(0o755)

    def git(self, *args, data=None):
        env = dict(os.environ, GIT_AUTHOR_NAME="Fixture", GIT_COMMITTER_NAME="Fixture",
                   GIT_AUTHOR_EMAIL="fixture@example.invalid", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        return subprocess.check_output(["git", *args], cwd=self.directory, input=data, env=env).decode().strip()

    def tree(self, *, contributed=False, override=None):
        files = {
            WORKFLOW: ("100644", b"jobs:\n  candidate-identity:\n    uses: ./.github/workflows/public-ci-candidate.yml\n"),
            REUSABLE: ("100644", b"on: workflow_call\njobs:\n  verify:\n    runs-on: ubuntu-latest\n"),
            GATE: ("100644", b"print('trusted gate')\n"),
            EXTRA_GATE: ("100755", b"print('worker policy')\n"),
        }
        if contributed:
            files["test-data"] = ("100644", b"contributed file\n")
        if override:
            path, mode, contents = override
            files[path] = (mode, contents)
        index = dict(os.environ, GIT_INDEX_FILE=str(self.directory / ".git" / "fixture-index"))
        subprocess.run(["git", "read-tree", "--empty"], cwd=self.directory, env=index, check=True)
        for path, (mode, contents) in files.items():
            oid = self.git("hash-object", "-w", "--stdin", data=contents)
            subprocess.run(["git", "update-index", "--add", "--cacheinfo", f"{mode},{oid},{path}"],
                           cwd=self.directory, env=index, check=True)
        return subprocess.check_output(["git", "write-tree"], cwd=self.directory, env=index).decode().strip()

    def commit(self, tree, message, *parents):
        args = ["commit-tree", tree]
        for parent in parents:
            args += ["-p", parent]
        return self.git(*args, data=f"{message}\n".encode())

    def fixture(self):
        # The fork's empty association list and the reusable-workflow reference
        # follow github.com/astral-sh/ruff/actions/runs/45741664832/attempts/1.
        run = {
            "id": RUN, "workflow_id": WORKFLOW_ID, "path": WORKFLOW,
            "repository": {"id": REPO_ID, "full_name": REPO},
            "head_repository": {"id": FORK_ID, "full_name": "example-fork/granary"},
            "head_branch": "patch", "head_sha": self.head, "check_suite_id": SUITE,
            "status": "completed", "conclusion": "success", "event": "pull_request", "run_attempt": 1,
            "pull_requests": [],
            "referenced_workflows": [{"path": f"{REPO}/{REUSABLE}@{self.merge}", "sha": self.merge,
                                      "ref": f"refs/pull/{PR}/merge"}],
        }
        pr = {"number": PR, "state": "open", "draft": False, "merged": False, "merge_commit_sha": self.merge,
              "base": {"ref": "main", "sha": self.base, "repo": {"id": REPO_ID, "full_name": REPO}},
              "head": {"ref": "patch", "sha": self.head, "repo": {"id": FORK_ID}}}
        responses = {PR_ENDPOINT: [pr],
                     WORKFLOW_ENDPOINT: [{"id": WORKFLOW_ID, "path": WORKFLOW, "state": "active"}],
                     RUN_ENDPOINT: [run], ATTEMPT_ENDPOINT: [copy.deepcopy(run)],
                     BASE_ENDPOINT: [{"ref": "refs/heads/main", "object": {"type": "commit", "sha": self.base}}],
                     MERGE_ENDPOINT: [{"ref": f"refs/pull/{PR}/merge",
                                       "object": {"type": "commit", "sha": self.merge}}]}
        jobs = []
        for job_id, name in [(SUMMARY_JOB, "ci-green"), (IDENTITY_JOB, "candidate-identity / verify")]:
            check_endpoint = check_run_endpoint(job_id)
            jobs.append({"id": job_id, "run_id": RUN, "run_attempt": 1, "name": name,
                         "head_sha": self.head, "status": "completed", "conclusion": "success",
                         "check_run_url": f"https://api.github.com/{check_endpoint}"})
            responses[check_endpoint] = [{"id": job_id, "name": name, "head_sha": self.head,
                                          "status": "completed", "conclusion": "success",
                                          "check_suite": {"id": SUITE}, "app": {"id": APP, "slug": "github-actions"}}]
        responses[JOBS_ENDPOINT] = [[{"total_count": 2, "jobs": jobs}]]
        return responses

    def check(self, responses=None, *, error=None, gate_paths=(GATE,)):
        fixtures = self.directory / ".git" / "gh-fixture.json"
        fixtures.write_text(json.dumps(responses if responses is not None else self.fixture()))
        (self.directory / ".git" / "gh-calls").unlink(missing_ok=True)
        env = dict(os.environ, PATH=f"{self.directory / '.git'}{os.pathsep}{os.environ['PATH']}")
        args = [
            sys.executable, str(CHECK), "--repo", REPO, "--repo-id", str(REPO_ID), "--pr", str(PR),
            "--base-ref", "main", "--base", self.base, "--head", self.head, "--tested-merge", self.merge,
            "--workflow-id", str(WORKFLOW_ID), "--workflow-path", WORKFLOW, "--required-job", "ci-green",
            "--actions-app-id", str(APP), "--run-id", str(RUN), "--attempt", "1",
            "--reusable-workflow", REUSABLE, "--identity-job", "candidate-identity / verify",
        ]
        for path in gate_paths:
            args.extend(["--gate-path", path])
        result = subprocess.run(args, cwd=self.directory, env=env, text=True, capture_output=True, check=False)
        if error is None:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(error, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_fork_run_binds_exact_candidate(self):
        self.assertEqual(self.check(), {
            "repository": REPO, "repository_id": REPO_ID, "pr": PR,
            "base_ref": "main", "base": self.base, "head": self.head, "tested_merge": self.merge,
            "head_repository_id": FORK_ID, "head_ref": "patch",
            "workflow_id": WORKFLOW_ID, "workflow_path": WORKFLOW, "run_id": RUN,
            "run_attempt": 1, "check_suite_id": SUITE, "actions_app_id": APP,
            "reusable_workflow": {"path": f"{REPO}/{REUSABLE}@{self.merge}", "sha": self.merge,
                                  "ref": f"refs/pull/{PR}/merge"},
            "jobs": {"ci-green": SUMMARY_JOB, "candidate-identity / verify": IDENTITY_JOB},
            "trusted_gate_manifest": [
                {"path": path, "mode": "100644", "blob": self.git("rev-parse", f"{self.base}:{path}")}
                for path in (WORKFLOW, REUSABLE, GATE)
            ],
        })

    def test_manifest_change_changes_receipt_with_same_candidate(self):
        first = self.check()
        with_extra = self.check(gate_paths=(EXTRA_GATE, GATE))
        self.assertEqual(with_extra, self.check(gate_paths=(GATE, EXTRA_GATE)))
        extra = {"path": EXTRA_GATE, "mode": "100755", "blob": self.git("rev-parse", f"{self.base}:{EXTRA_GATE}")}
        self.assertEqual(with_extra, dict(first, trusted_gate_manifest=[*first["trusted_gate_manifest"], extra]))

    def test_ambiguous_gate_manifest_policy_refuses(self):
        self.check(gate_paths=(GATE, GATE), error="distinct repository-relative trusted gate paths")

    def test_published_workflow_registration_must_be_active_at_pinned_path(self):
        for key, value in [("state", "disabled_manually"), ("id", WORKFLOW_ID + 1),
                           ("path", ".github/workflows/impostor.yml")]:
            with self.subTest(key=key):
                responses = self.fixture()
                responses[WORKFLOW_ENDPOINT][0][key] = value
                self.check(responses, error="published workflow")

    def test_current_runs_and_attempt_rows_bind_repo_workflow_event_head_and_attempt(self):
        controls = [
            ("id", RUN + 1), ("repository", {"id": REPO_ID + 1, "full_name": REPO}),
            ("workflow_id", WORKFLOW_ID + 1), ("path", ".github/workflows/impostor.yml"),
            ("event", "workflow_dispatch"), ("head_sha", OTHER_HEAD), ("head_branch", "same-head"),
            ("head_repository", {"id": FORK_ID + 1}), ("run_attempt", True),
            ("run_attempt", 2), ("status", "in_progress"), ("conclusion", "failure"),
        ]
        for endpoint in [RUN_ENDPOINT, ATTEMPT_ENDPOINT]:
            for key, value in controls:
                with self.subTest(endpoint=endpoint, key=key, value=value):
                    responses = self.fixture()
                    responses[endpoint][0][key] = value
                    self.check(responses, error="workflow run")

    def test_run_and_attempt_must_have_same_suite(self):
        responses = self.fixture()
        responses[ATTEMPT_ENDPOINT][0]["check_suite_id"] = SUITE + 1
        self.check(responses, error="disagree on the check suite")

    def test_reference_must_authenticate_both_candidate_commit_and_pr(self):
        for key, value in [("ref", "refs/pull/18/merge"), ("sha", OTHER_MERGE),
                           ("ref", None), ("path", f"{REPO}/{REUSABLE}@refs/pull/{PR}/merge")]:
            with self.subTest(key=key):
                responses = self.fixture()
                for endpoint in [RUN_ENDPOINT, ATTEMPT_ENDPOINT]:
                    responses[endpoint][0]["referenced_workflows"][0][key] = value
                self.check(responses, error="reusable workflow")

    def test_no_reference_refuses_even_with_a_matching_pr_association(self):
        responses = self.fixture()
        for endpoint in [RUN_ENDPOINT, ATTEMPT_ENDPOINT]:
            del responses[endpoint][0]["referenced_workflows"]
            responses[endpoint][0]["pull_requests"] = [responses[PR_ENDPOINT][0]]
        self.check(responses, error="reusable workflow")

    def test_duplicate_reference_refuses(self):
        responses = self.fixture()
        for endpoint in [RUN_ENDPOINT, ATTEMPT_ENDPOINT]:
            refs = responses[endpoint][0]["referenced_workflows"]
            refs.append(copy.deepcopy(refs[0]))
        self.check(responses, error="reusable workflow")

    def test_indirect_call_cannot_supply_the_witness(self):
        responses = self.fixture()
        for endpoint in [RUN_ENDPOINT, ATTEMPT_ENDPOINT]:
            responses[endpoint][0]["referenced_workflows"].insert(0, {
                "path": f"{REPO}/.github/workflows/indirect.yml@refs/pull/{PR}/merge",
                "sha": self.merge, "ref": f"refs/pull/{PR}/merge",
            })
        self.check(responses, error="reusable workflow")

    def test_job_inventory_must_be_complete_and_each_required_job_unique(self):
        for mutation in ["missing", "duplicate", "duplicate-id", "truncated", "skipped-summary", "skipped-identity",
                         "older-attempt", "other-run", "wrong-head", "spoof-url"]:
            with self.subTest(mutation=mutation):
                responses = self.fixture()
                page = responses[JOBS_ENDPOINT][0][0]
                summary, identity = page["jobs"]
                if mutation == "missing":
                    identity["name"] = "wrong job"
                elif mutation == "duplicate":
                    identity["name"] = "ci-green"
                elif mutation == "duplicate-id":
                    identity["id"] = summary["id"]
                elif mutation == "truncated":
                    page["total_count"] += 1
                elif mutation == "skipped-summary":
                    summary["conclusion"] = "skipped"
                elif mutation == "skipped-identity":
                    identity["conclusion"] = "skipped"
                elif mutation == "older-attempt":
                    summary["run_attempt"] = 0
                elif mutation == "other-run":
                    summary["run_id"] = RUN + 1
                elif mutation == "wrong-head":
                    summary["head_sha"] = OTHER_HEAD
                else:
                    summary["check_run_url"] = "https://example.invalid/check-runs/1"
                self.check(responses, error="job")

    def test_jobs_must_be_checked_across_pages(self):
        responses = self.fixture()
        summary, identity = responses[JOBS_ENDPOINT][0][0]["jobs"]
        responses[JOBS_ENDPOINT][0] = [{"total_count": 2, "jobs": [summary]}, {"total_count": 2, "jobs": [identity]}]
        self.assertEqual(self.check(responses)["jobs"], {"ci-green": SUMMARY_JOB, "candidate-identity / verify": IDENTITY_JOB})
        responses[JOBS_ENDPOINT][0][1]["total_count"] = 3
        self.check(responses, error="incomplete attempt job inventory")

    def test_check_run_authenticates_app_suite_job_and_outcome(self):
        controls = [("app", {"id": APP + 1, "slug": "github-actions"}), ("app", {"id": APP, "slug": "impostor"}),
                    ("check_suite", {"id": SUITE + 1}),
                    ("id", SUMMARY_JOB + 1), ("conclusion", "skipped"), ("head_sha", OTHER_HEAD)]
        for key, value in controls:
            with self.subTest(key=key):
                responses = self.fixture()
                responses[check_run_endpoint(SUMMARY_JOB)][0][key] = value
                self.check(responses, error="check run")

    def test_current_pr_and_refs_must_match_pinned_objects(self):
        controls = [(PR_ENDPOINT, "merge_commit_sha", OTHER_MERGE), (PR_ENDPOINT, "number", PR + 1),
                    (PR_ENDPOINT, "state", "closed"), (PR_ENDPOINT, "draft", True),
                    (BASE_ENDPOINT, "object", {"type": "commit", "sha": OTHER_BASE}),
                    (MERGE_ENDPOINT, "object", {"type": "commit", "sha": OTHER_MERGE})]
        for endpoint, key, value in controls:
            with self.subTest(endpoint=endpoint, key=key):
                responses = self.fixture()
                responses[endpoint][0][key] = value
                self.check(responses, error="refused")

    def test_advancement_during_preflight_refuses(self):
        controls = [
            (RUN_ENDPOINT, "run_attempt", 2, "workflow run"),
            (PR_ENDPOINT, "merge_commit_sha", OTHER_MERGE, "live PR"),
            (BASE_ENDPOINT, "object", {"type": "commit", "sha": OTHER_BASE}, "refs/heads/main"),
            (MERGE_ENDPOINT, "object", {"type": "commit", "sha": OTHER_MERGE}, f"refs/pull/{PR}/merge"),
            (check_run_endpoint(SUMMARY_JOB), "conclusion", "failure", "check run"),
            (WORKFLOW_ENDPOINT, "state", "disabled_manually", "published workflow"),
        ]
        for endpoint, key, value, error in controls:
            with self.subTest(endpoint=endpoint):
                responses = self.fixture()
                responses[endpoint].append(dict(responses[endpoint][0], **{key: value}))
                self.check(responses, error=error)

    def test_rerun_between_final_candidate_and_return_refuses(self):
        responses = self.fixture()
        first = responses[RUN_ENDPOINT][0]
        responses[RUN_ENDPOINT] = [first, first, dict(first, run_attempt=2)]
        self.check(responses, error="workflow run")

    def test_job_identity_cannot_change_between_reads(self):
        responses = self.fixture()
        new_id = SUMMARY_JOB + 1
        new_path = check_run_endpoint(new_id)
        after = copy.deepcopy(responses[JOBS_ENDPOINT][0])
        after[0]["jobs"][0].update(id=new_id, check_run_url=f"https://api.github.com/{new_path}")
        responses[JOBS_ENDPOINT].append(after)
        responses[new_path] = [dict(responses[check_run_endpoint(SUMMARY_JOB)][0], id=new_id)]
        self.check(responses, error="identity changed during preflight")

    def test_candidate_merge_must_have_exact_ordered_parents(self):
        self.merge = self.commit(self.tree(contributed=True), "reversed merge", self.head, self.base)
        self.check(error="parents")

    def test_git_replacement_cannot_hide_wrong_parents(self):
        replacement = self.merge
        self.merge = self.commit(self.tree(contributed=True), "reversed merge", self.head, self.base)
        self.git("replace", self.merge, replacement)
        self.assertEqual(self.git("cat-file", "commit", self.merge), self.git("cat-file", "commit", replacement))
        self.check(error="parents")

    def test_candidate_cannot_replace_trusted_gate_files_or_modes(self):
        controls = [(WORKFLOW, "100644", b"untrusted caller\n"), (REUSABLE, "100644", b"untrusted marker\n"),
                    (GATE, "100644", b"exit(0)\n"), (GATE, "100755", b"print('trusted gate')\n"),
                    (GATE, "120000", b"test-data")]
        for override in controls:
            with self.subTest(path=override[0], mode=override[1]):
                tree = self.tree(contributed=True, override=override)
                self.merge = self.commit(tree, "changed gate", self.base, self.head)
                self.check(error="trusted gate")


if __name__ == "__main__":
    unittest.main()
