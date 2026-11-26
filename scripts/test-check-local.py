# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Exercise the contributor check without building the Rust workspace."""

import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest


CHECK = Path(__file__).with_name("check-local.sh").resolve()


class LocalCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.log = self.root / "cargo.log"
        self.cargo = self.root / "cargo"
        self.cargo.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$CHECK_LOG"\n'
            'if [ "$1" = clippy ] && [ "$CARGO_BUILD_WARNINGS" != deny ]; then\n'
            '    exit 90\n'
            'fi\n'
            'if [ "$1" = "$FAIL_CHECK" ]; then\n'
            '    exit 23\n'
            'fi\n'
        )
        self.cargo.chmod(0o755)

    def run_check(self, failure=""):
        return subprocess.run(
            ["/bin/bash", CHECK],
            cwd=self.root,
            env={"PATH": os.fspath(self.root), "CHECK_LOG": self.log, "FAIL_CHECK": failure},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_runs_the_format_lint_and_test_commands(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.log.read_text().splitlines(),
            [
                "fmt --check",
                "clippy --workspace --all-targets --locked",
                "nextest run --profile ci --locked -p granary-core -p granary-vfs",
            ],
        )

    def test_reports_missing_cargo(self):
        self.cargo.unlink()
        result = self.run_check()
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertIn("cargo", result.stderr)

    def test_propagates_a_required_check_failure(self):
        result = self.run_check(failure="clippy")
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(
            self.log.read_text().splitlines(),
            ["fmt --check", "clippy --workspace --all-targets --locked"],
        )


if __name__ == "__main__":
    unittest.main()
