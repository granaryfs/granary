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

    def draft(self, title, body, expected_error=None, *, draft_state=...):
        pull_request = {"title": title, "body": body}
        if draft_state is not ...:
            pull_request["draft"] = draft_state
        event = self.directory / "event.json"
        event.write_text(json.dumps({"pull_request": pull_request}))
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

    def test_ready_metadata(self):
        title = "check runner timeout"
        cls = "Class: E"
        assisted = "Assisted-by: none"
        fields = f"{cls}\n{assisted}"
        for value in "EIPSR":
            with self.subTest(valid_class=value):
                self.draft(title, f"{BODY}\r\n\r\nClass: {value}\r\n{assisted}", draft_state=False)

        for label, trailers in (
            ("missing class", assisted),
            ("missing assistance", cls),
            ("duplicate class", f"{fields}\n{cls}"),
            ("duplicate assistance", f"{fields}\nAssisted-by: editor"),
            ("invalid class", f"Class: X\n{assisted}"),
            ("empty class", f"Class:\n{assisted}"),
            ("blank assistance", f"{cls}\nAssisted-by: \t"),
            ("comment", f"<!--\n{fields}\n-->"),
            ("backtick fence", f"```text\n{fields}\n```"),
            ("tilde fence", f"~~~text\n{fields}\n~~~"),
            ("earlier paragraph", f"{fields}\n\n{ALICE}"),
        ):
            with self.subTest(case=label):
                self.draft(title, f"{BODY}\n\n{trailers}", "ready PR", draft_state=False)

        examples = f"```text\n{fields}\n```\n\n<!--\n{fields}\n-->"
        credits = "AI-Reviewed-by: reviewer one\nAI-Reviewed-by: reviewer two"
        self.draft(title, f"{BODY}\n\n{examples}\n\n{fields}\n{credits}", draft_state=False)

    def test_ready_metadata_visibility(self):
        fields = "Class: E\nAssisted-by: none"
        for label, tail, expected_error in (
            ("processing instruction", f"<?target\n\n{fields}", "ready PR"),
            ("declaration", f"<!DOCTYPE html\n\n{fields}", "ready PR"),
            ("CDATA", f"<![CDATA[\n\n{fields}", "ready PR"),
            ("pre block", f"<pre>\n\n{fields}", "ready PR"),
            ("style closer ends pre block", f"<pre>\n</style>\n\n{fields}", None),
            ("empty link", "Class: E\nAssisted-by: [](x)", "ready PR"),
            ("empty titled link", "Class: E\nAssisted-by: [](<a b> 'Codex')", "ready PR"),
            ("empty image", "Class: E\nAssisted-by: ![](x)", "ready PR"),
            ("visible link label", "Class: E\nAssisted-by: [Codex](x)", None),
            ("visible titled label", "Class: E\nAssisted-by: [Codex](a(b)c (title))", None),
            ("literal link in code span", "Class: E\nAssisted-by: `[](x)`", None),
            ("empty span", "Class: E\nAssisted-by: <span></span>", "ready PR"),
            ("zero width space", "Class: E\nAssisted-by: \u200b", "ready PR"),
            ("space entity", "Class: E\nAssisted-by: &#32;", "ready PR"),
            ("Hangul filler entity", "Class: E\nAssisted-by: &#x3164;", "ready PR"),
            ("Hangul filler with visible text", "Class: E\nAssisted-by: &#x3164;한", None),
            ("duplicate after CR", f"{fields}\rAssisted-by: editor", "ready PR"),
            ("malformed signoff after CR", f"{fields}\rSigned-off-by: invalid", "malformed Signed-off-by trailer"),
            ("literal comment in code span", "Class: E\nAssisted-by: `<!-- note -->`", None),
            ("fenced declaration", f"```text\n<!DOCTYPE html\n```\n\n{fields}", None),
        ):
            with self.subTest(case=label):
                self.draft("check runner timeout", f"{BODY}\n\n{tail}", expected_error, draft_state=False)

    def test_explicit_draft_state(self):
        title = "check runner timeout"
        self.draft(title, BODY, draft_state=True)
        for state in (None, 0, 1, "false"):
            with self.subTest(state=state):
                self.draft(title, BODY, "draft flag", draft_state=state)

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
