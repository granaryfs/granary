#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Check the squash preparation and readback against real Git objects."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECK = Path(__file__).resolve().with_name("check-pr-message.py")
AUTHOR = "Alice Example <alice@example.invalid>"
ALICE = f"Signed-off-by: {AUTHOR}"
BOB = "Signed-off-by: Bob Example <bob@example.invalid>"
BOT = "Signed-off-by: builder[bot] <builder[bot]@users.noreply.github.com>"


class LandingProofTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.git("init", "-q")
        self.git("config", "commit.gpgsign", "false")
        self.base_tree = self.tree("base")
        self.squash_tree = self.tree("contributed bytes")
        self.base = self.commit(self.base_tree, [], "root without a sign-off\n")
        first = self.commit(self.squash_tree, [self.base], f"first\n\n{ALICE}\n")
        self.head = self.commit(self.squash_tree, [first], f"second\n\n{ALICE}\n{BOB}\n")
        self.tested = self.make_tested_merge(self.base, self.head)
        self.message = self.repo / "squash-message"
        self.message.write_bytes(f"change behavior\n\nExplain what changed.\n\n{ALICE}\n{BOB}\n".encode())

    def git(self, *args, data=None, author=AUTHOR):
        name, email = author.split(" <", 1)
        env = dict(os.environ, GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email[:-1],
                   GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        return subprocess.check_output(["git", *args], cwd=self.repo, env=env, input=data)

    def tree(self, contents):
        blob = self.git("hash-object", "-w", "--stdin", data=contents.encode()).strip()
        return self.git("mktree", data=b"100644 blob " + blob + b"\tfile\n").decode().strip()

    def commit(self, tree, parents, message, author=AUTHOR):
        args = ["commit-tree", tree]
        for parent in parents:
            args.extend(["-p", parent])
        if isinstance(message, str):
            message = message.encode()
        return self.git(*args, data=message, author=author).decode().strip()

    def make_tested_merge(self, base, head):
        return self.commit(self.squash_tree, [base, head], "test merge\n")

    def check(self, *args, error=None):
        result = subprocess.run([sys.executable, str(CHECK), *map(str, args)], cwd=self.repo,
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0 if error is None else 1, result.stderr)
        if error:
            self.assertIn(error, result.stderr)
            self.assertEqual(result.stdout, "")
        return result.stdout

    def prepare(self, *, head=None, tested=None, error=None):
        output = self.check("prepare-squash", self.message, "--base", self.base,
                            "--head", head or self.head, "--tested-merge", tested or self.tested,
                            "--author", AUTHOR, error=error)
        if error:
            return
        return json.loads(output)

    def verify(self, landed, *, error=None):
        approval = self.repo / "approval.json"
        approval.write_text(json.dumps(self.prepare()))
        self.check("verify-landed", approval, landed, error=error)

    def test_proof_binds_exact_tested_tree_identity_and_message(self):
        proof = self.prepare()
        self.assertEqual(proof, {
            "base": self.base,
            "head": self.head,
            "tested_merge": self.tested,
            "tree": self.squash_tree,
            "author": AUTHOR,
            "message_sha256": hashlib.sha256(self.message.read_bytes()).hexdigest(),
        })
        landed = self.commit(self.squash_tree, [self.base], self.message.read_bytes())
        self.verify(landed)

    def test_requires_signoff_on_each_contribution_commit(self):
        unsigned = self.commit(self.squash_tree, [self.base], "unsigned change\n")
        head = self.commit(self.squash_tree, [unsigned], f"follow-up\n\n{ALICE}\n{BOB}\n")
        self.prepare(head=head, tested=self.make_tested_merge(self.base, head),
                     error=f"commit {unsigned} has no human sign-off")

    def test_signoff_in_a_commit_code_sample_does_not_certify_commit(self):
        note = f"illustrate the format\n\n```text\n{ALICE}\n```\n"
        head = self.commit(self.squash_tree, [self.base], note)
        self.prepare(head=head, tested=self.make_tested_merge(self.base, head),
                     error=f"commit {head} has no human sign-off")

    def test_signoff_in_an_html_comment_does_not_certify_commit(self):
        note = f"illustrate the format\n\n<!--\n{ALICE}\n-->\n"
        head = self.commit(self.squash_tree, [self.base], note)
        self.prepare(head=head, tested=self.make_tested_merge(self.base, head),
                     error=f"commit {head} has no human sign-off")

    def test_required_signoff_cannot_be_hidden_in_the_squash(self):
        self.message.write_text(f"change behavior\n\nExplain what changed.\n\n<!--\n{ALICE}\n-->\n{BOB}\n")
        self.prepare(error="missing required sign-off")

    def test_signoff_in_an_unclosed_fence_does_not_certify_commit(self):
        note = f"illustrate the format\n\n```text\n\n{ALICE}\n"
        head = self.commit(self.squash_tree, [self.base], note)
        self.prepare(head=head, tested=self.make_tested_merge(self.base, head),
                     error=f"commit {head} has no human sign-off")

    def test_visible_signoffs_after_fenced_example_are_preserved(self):
        self.message.write_text(f"change behavior\n\n```text\n<!--\n```\n\n{ALICE}\n{BOB}\n")
        self.prepare()

    def test_bot_only_signoff_does_not_certify_commit(self):
        head = self.commit(self.squash_tree, [self.base], f"generated change\n\n{BOT}\n")
        self.prepare(head=head, tested=self.make_tested_merge(self.base, head),
                     error=f"commit {head} has no human sign-off")

    def test_requires_exact_signoffs_from_all_contribution_commits(self):
        self.message.write_text(f"change behavior\n\nExplain what changed.\n\n{ALICE}\n")
        self.prepare(error="missing required sign-off")

    def test_requires_signoff_spacing_as_committed(self):
        carried = ALICE.replace(": ", ":  ")
        head = self.commit(self.squash_tree, [self.base], f"change\n\n{carried}\n")
        self.prepare(head=head, tested=self.make_tested_merge(self.base, head),
                     error="missing required sign-off")
        self.message.write_text(f"change behavior\n\nExplain what changed.\n\n{carried}\n")
        self.prepare(head=head, tested=self.make_tested_merge(self.base, head))

    def test_refuses_tested_merge_with_reversed_parents(self):
        self.prepare(tested=self.make_tested_merge(self.head, self.base),
                     error="tested merge parents differ from base and head")

    def test_refuses_tested_merge_for_another_head(self):
        other = self.commit(self.squash_tree, [self.base], f"other change\n\n{ALICE}\n")
        self.prepare(tested=self.make_tested_merge(self.base, other),
                     error="tested merge parents differ from base and head")

    def test_refuses_symbolic_base(self):
        self.git("update-ref", "refs/heads/main", self.base)
        self.base = "main"
        self.prepare(error="expected a full commit SHA")

    def test_refuses_git_replace_of_source_signoff(self):
        unsigned = self.commit(self.squash_tree, [self.base], "unsigned change\n")
        signed = self.commit(self.squash_tree, [self.base], f"signed change\n\n{ALICE}\n{BOB}\n")
        self.git("replace", unsigned, signed)
        self.prepare(head=unsigned, tested=self.make_tested_merge(self.base, unsigned),
                     error=f"commit {unsigned} has no human sign-off")

    def test_refuses_git_graft_hiding_unsigned_commit(self):
        unsigned = self.commit(self.squash_tree, [self.base], "unsigned change\n")
        head = self.commit(self.squash_tree, [unsigned], f"signed change\n\n{ALICE}\n{BOB}\n")
        tested = self.make_tested_merge(self.base, head)
        (self.repo / ".git/info/grafts").write_text(f"{head} {self.base}\n")
        self.prepare(head=head, tested=tested, error=f"commit {unsigned} has no human sign-off")

    def test_requires_complete_git_history(self):
        (self.repo / ".git/shallow").write_text(f"{self.base}\n")
        self.prepare(error="contribution sign-offs require complete Git history")

    def test_readback_refuses_a_squash_onto_an_advanced_base(self):
        advanced = self.commit(self.base_tree, [self.base], "main advanced\n")
        landed = self.commit(self.squash_tree, [advanced], self.message.read_bytes())
        self.verify(landed, error="landed commit has a different base")

    def test_readback_refuses_an_unapproved_tree(self):
        landed = self.commit(self.base_tree, [self.base], self.message.read_bytes())
        self.verify(landed, error="landed tree differs")

    def test_readback_refuses_an_unapproved_author(self):
        landed = self.commit(self.squash_tree, [self.base], self.message.read_bytes(),
                             author="Bob Example <bob@example.invalid>")
        self.verify(landed, error="landed author differs")

    def test_readback_refuses_change_to_final_message_bytes(self):
        landed = self.commit(self.squash_tree, [self.base], self.message.read_bytes() + b"\n")
        self.verify(landed, error="landed message differs")


if __name__ == "__main__":
    unittest.main()
