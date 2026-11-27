#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Exercise the public PR and squash message command from its file inputs."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECK = Path(__file__).with_name("check-pr-message.py")
ALICE = "Signed-off-by: Alice Example <alice@example.invalid>"
BOB = "Signed-off-by: Bob Example <bob@example.invalid>"
BODY = "Explain why the runner check needs a timeout."


class MessageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)

    def run_check(self, expected_error, *args):
        result = subprocess.run(
            [sys.executable, str(CHECK), *map(str, args)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0 if expected_error is None else 1, result.stderr)
        if expected_error:
            self.assertIn(expected_error, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def draft(self, title, body, expected_error=None):
        event = self.directory / "event.json"
        event.write_text(json.dumps({"pull_request": {"title": title, "body": body}}))
        return self.run_check(expected_error, "draft", event)

    def squash(self, message, signoffs, expected_error=None):
        candidate = self.directory / "message"
        candidate.write_text(message, encoding="utf-8")
        required = self.directory / "signoffs"
        required.write_text(signoffs, encoding="utf-8")
        self.run_check(expected_error, "squash", candidate, "--required-signoffs", required)
        self.assertEqual(candidate.read_text(encoding="utf-8"), message)

    def test_metadata_edit_corrects_the_same_pull_request(self):
        self.draft("check runner timeout", "<!-- explain what changed -->", "description is empty")
        self.draft("check runner timeout", BODY)

    def test_event_requires_a_pull_request_object(self):
        event = self.directory / "event.json"
        event.write_text('{"pull_request": null}')
        self.run_check("event has no pull request", "draft", event)

    def test_null_description_is_refused(self):
        self.draft("check runner timeout", None, "description is empty")

    def test_multiline_subject_is_refused(self):
        self.draft("check runner timeout\nsecond subject", BODY, "title must be one line")

    def test_trailing_unicode_line_separator_is_refused(self):
        self.draft("check runner timeout\u2028", BODY, "title must be one line")

    def test_punctuation_in_normal_markdown_is_accepted(self):
        self.draft("Check runner timeout on macOS", 'Use `$shell` with a literal value: "test".')

    def test_empty_ai_trailer_is_refused(self):
        for whitespace in (" ", "\u00a0"):
            with self.subTest(whitespace=whitespace):
                self.draft(
                    "check runner timeout", f"{BODY}\n\nAI-Reviewed-by: {whitespace}",
                    "AI-Reviewed-by is empty",
                )

    def test_malformed_optional_draft_signoff_is_refused(self):
        self.draft("check runner timeout", f"{BODY}\n\nSigned-off-by: Alice", "malformed Signed-off-by")

    def test_draft_code_sample_is_not_a_trailer(self):
        self.draft("explain sign-offs", "Show the syntax.\n\n```text\nSigned-off-by: Alice\n```")

    def test_squash_preserves_every_required_signoff(self):
        message = f"check runner timeout\n\n{BODY}\n\n{BOB}\n{ALICE}\n"
        self.squash(message, f"{ALICE}\n{BOB}\n")

    def test_squash_preserves_terminal_signoff_spacing(self):
        signoff = ALICE + "  "
        self.squash(f"check runner timeout\n\n{BODY}\n\n{signoff}\n\n", f"{signoff}\n")

    def test_squash_refuses_missing_signoff(self):
        message = f"check runner timeout\n\n{BODY}\n\n{ALICE}\n"
        self.squash(message, f"{ALICE}\n{BOB}\n", "missing required sign-off")

    def test_squash_refuses_a_changed_signoff(self):
        changed = ALICE.replace("Alice Example", "Alice")
        message = f"check runner timeout\n\n{BODY}\n\n{changed}\n"
        self.squash(message, f"{ALICE}\n", "missing required sign-off")

    def test_squash_requires_signoff_in_terminal_trailers(self):
        message = f"check runner timeout\n\n{ALICE}\n\n{BODY}\n"
        self.squash(message, f"{ALICE}\n", "missing required sign-off")

    def test_squash_refuses_signoff_folded_into_another_trailer(self):
        message = f"check runner timeout\n\n{BODY}\n\nNote: example\n {ALICE}\n"
        self.squash(message, f"{ALICE}\n", "missing required sign-off")

    def test_squash_refuses_unicode_whitespace_folded_into_signoff(self):
        message = f"check runner timeout\n\n{BODY}\n\n{ALICE}\n\t\u00a0\n"
        self.squash(message, f"{ALICE}\n", "malformed Signed-off-by")

    def test_squash_refuses_malformed_signoff_evidence(self):
        message = f"check runner timeout\n\n{BODY}\n\n{ALICE}\n"
        self.squash(message, "not a sign-off\n", "malformed required sign-off")

    def test_squash_accepts_an_explicit_empty_signoff_list(self):
        self.squash(f"check runner timeout\n\n{BODY}\n", "")


if __name__ == "__main__":
    unittest.main()
