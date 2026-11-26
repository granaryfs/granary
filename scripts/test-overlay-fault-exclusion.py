#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Paired controls for source gating, artifact identity and arming exclusion."""
import contextlib
import importlib.util
import io
import os
import runpy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if not __debug__:
    raise SystemExit("OVERLAY-FAULT REFUSED: Python optimization is forbidden")

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("guard", Path(__file__).with_name("check-overlay-fault-exclusion.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class Exclusion(unittest.TestCase):
    def test_accessor_gate_valid_and_malformed_controls(self):
        valid = '''
    /// Return a read-only snapshotter for an instrumented integration harness.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn metrics_snapshot(
        &self,
    ) -> impl Fn() {}
'''
        malformed = valid.replace(
            '#[cfg(any(test, feature = "overlay-fault-tests"))]',
            '#[cfg(test)]',
        )
        cases = 0
        for source, wanted_rc, wanted_text in [
            (valid, 0, "OVERLAY-FAULT PASS: metrics_snapshot source gate present; cases=1"),
            (malformed, 1, "OVERLAY-FAULT REFUSED: metrics_snapshot source gate missing or ambiguous; cases=1"),
        ]:
            cases += 1
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = guard.inspect_accessor_gate(source)
            self.assertEqual((rc, output.getvalue().strip()), (wanted_rc, wanted_text))
        self.assertEqual(cases, 2)
        with tempfile.TemporaryDirectory(prefix="overlay-source-") as temporary:
            missing = Path(temporary) / "missing.rs"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = guard.inspect_accessor_source(missing)
            self.assertEqual(
                (rc, output.getvalue().strip()),
                (2, "OVERLAY-FAULT REFUSED: cannot read metrics_snapshot source: FileNotFoundError"),
            )

    def test_paired_symbols_and_reader_failures(self):
        with tempfile.TemporaryDirectory(prefix="overlay-artifact-") as temporary:
            artifact = Path(temporary) / "fixture.rlib"
            artifact.write_bytes(b"artifact")
            count = 0
            cases = [
                (0, "0000 T _RNvX12granary_clientXOverlayStore4open\n", 0, "OVERLAY-FAULT PASS: artifacts=1 symbols=1 armed=0"),
                (0, "0000 T _RNvX12granary_clientXFaultControl3arm\n", 1, "OVERLAY-FAULT REFUSED: arming API present; artifacts=1 symbols=1 armed=1"),
                (0, "0000 T _RNvX12granary_clientXFaultControl10trace_sync\n", 1, "OVERLAY-FAULT REFUSED: arming API present; artifacts=1 symbols=1 armed=1"),
                (0, "0000 T _RNvX12granary_clientXFaultControl10sync_fired\n", 1, "OVERLAY-FAULT REFUSED: arming API present; artifacts=1 symbols=1 armed=1"),
                (0, "0000 T _RNvX12granary_clientXFaultControl10sync_point\n", 1, "OVERLAY-FAULT REFUSED: arming API present; artifacts=1 symbols=1 armed=1"),
                (0, "0000 T _RNvX12granary_clientXFaultControl22rename_directory_point\n", 1, "OVERLAY-FAULT REFUSED: arming API present; artifacts=1 symbols=1 armed=1"),
                (0, "fixture.granary_client.rcgu.o:\n", 2, "OVERLAY-FAULT REFUSED: no client symbols inspected"),
                (0, " U _RNvX12granary_clientXFaultControl3arm\n", 2, "OVERLAY-FAULT REFUSED: no client symbols inspected"),
                (1, "0000 T _RNvX12granary_clientXOverlayStore4open\n", 2, "OVERLAY-FAULT REFUSED: symbol reader failed"),
            ]
            for reader_rc, symbols, wanted_rc, wanted_text in cases:
                count += 1
                with self.subTest(wanted_text=wanted_text), patch.object(guard.subprocess, "run", return_value=subprocess.CompletedProcess([], reader_rc, symbols, "")) as reader:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        rc = guard.inspect(artifact)
                    self.assertEqual((rc, output.getvalue().strip()), (wanted_rc, wanted_text))
                    self.assertEqual(reader.call_args.args[0], ["nm", "-g", str(artifact)])
            artifact.unlink()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = guard.inspect(artifact)
            self.assertEqual((rc, output.getvalue().strip()), (2, "OVERLAY-FAULT REFUSED: cannot read artifact or symbols: FileNotFoundError"))
            artifact.write_bytes(b"")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = guard.inspect(artifact)
            self.assertEqual((rc, output.getvalue().strip()), (2, "OVERLAY-FAULT REFUSED: cannot read artifact or symbols: ValueError"))
            self.assertEqual(count + 2, 11)

    def test_gate_and_ci_wiring(self):
        root = Path(__file__).resolve().parent.parent
        ci = (root / ".github/workflows/ci.yml").read_text()
        self.assertTrue("run: ./scripts/check-overlay-faults.sh" in ci, "CI overlay lane missing")
        self.assertTrue("  overlay-faults:" in ci, "CI overlay job missing")
        lines = [line.partition("#")[0].rstrip() for line in ci.splitlines()]
        start = lines.index("  ci-green:")
        end = next(
            (index for index in range(start + 1, len(lines))
             if lines[index].startswith("  ") and not lines[index].startswith("    ")),
            len(lines),
        )
        _, needs_line = next(
            line.split(":", 1) for line in lines[start + 1 : end] if line.startswith("    needs: [")
        )
        self.assertIn("overlay-faults", needs_line.strip().removeprefix("[").removesuffix("]").split(", "))
        lane = (root / "scripts/check-overlay-faults.sh").read_text()
        for command in [
            "python3 scripts/check-overlay-fault-exclusion.py --self-test",
            "cargo clippy --locked -p granary-client --all-targets --features overlay-fault-tests",
            "cargo clippy --locked -p granary-server --all-targets --features overlay-fault-tests",
            "cargo nextest run --profile ci --locked -p granary-client --features overlay-fault-tests",
            "cargo nextest run --profile ci --locked --no-tests fail -p granary-server --lib --features overlay-fault-tests -E 'test(integration_)'",
            "cargo nextest run --profile ci --locked -p granary-sim --features overlay-fault-tests --test sync_engine",
            "cargo build --release --locked -p granary-client --lib",
            "python3 scripts/check-overlay-fault-exclusion.py target/release/libgranary_client.rlib",
            "cargo build --release --locked -p granary-client --features overlay-fault-tests",
            "overlay-fault-tests must not compile into a release artifact",
        ]:
            self.assertTrue(command in lane, command)

    def test_lane_paired_refusals(self):
        root = Path(__file__).resolve().parent.parent
        matrices = ["crash_and_failure_matrix_has_fired_seams_and_disarmed_controls", "replacement_crash_matrix_keeps_old_or_complete_new_journal", "sweep_and_tail_cut_crash_matrix_restarts_idempotently", "establishment_crash_matrix_never_promotes_temporary_state", "stage_creation_shrink_and_rollback_crash_matrix"]
        with tempfile.TemporaryDirectory(prefix="overlay-lane-") as temporary:
            bin_dir = Path(temporary)
            cargo = bin_dir / "cargo"
            cargo.write_text("#!/usr/bin/env bash\n" + r'''set -eu
prefix=overlay_discard::tests::linux::discard_refuses_
echo "CARGO $*" >&2
case "$*" in
  'nextest list '*--list-type' binaries-only --message-format json')
    echo '{"rust-binaries":{"granary-client":{"binary-path":"mock-client-tests"}}}'
    ;;
  'nextest list '*--run-ignored' default '*)
    for row in empty_destination_race nonempty_destination_race dangling_destination_race foreign_mode granting_posix_acl unpaired_hard_link; do
      case "$OVERLAY_TEST_CASE:$row" in
        missing-discard:empty_destination_race|ignored-unprivileged:foreign_mode) continue ;;
        suffixed-discard:foreign_mode) row=foreign_mode_helper ;;
      esac
      echo "granary-client $prefix$row"
    done
    ;;
  'nextest list '*--run-ignored' ignored-only '*)
    echo "granary-client ${prefix}foreign_owner"
    if [ "$OVERLAY_TEST_CASE" != missing-ignored ]; then
      echo "granary-client ${prefix}mount_crossing"
    fi
    if [ "$OVERLAY_TEST_CASE" = extra-ignored ]; then
      echo "granary-client overlay_discard::tests::linux::extra_ignored_row"
    fi
    ;;
  'nextest list '*--run-ignored*) exit 31 ;;
  'nextest list '*)
    [ "$OVERLAY_TEST_CASE" != listing-error ] || exit 27
    [ "$OVERLAY_TEST_CASE" != missing-matrix ] || exit 0
''' + "\n".join("    echo overlay_store::tests::" + m for m in matrices) + r'''
    ;;
  'nextest run '*) [ "$OVERLAY_TEST_CASE" != test-error ] || exit 28 ;;
  'build --release --locked -p granary-client --features overlay-fault-tests')
    if [ "$OVERLAY_TEST_CASE" = wrong-wall ]; then echo "unrelated compiler failure"; exit 101; fi
    echo "overlay-fault-tests must not compile into a release artifact"
    [ "$OVERLAY_TEST_CASE" != wall-success ] || exit 0
    exit 101 ;;
esac
''')
            python = bin_dir / "python3"
            python.write_text("#!/usr/bin/env bash\n" + r'''if [[ "$1" == -c ]]; then exec "$OVERLAY_TEST_PYTHON" "$@"; fi
echo "PYTHON $*"
case "$*" in
  *--self-test) [ "$OVERLAY_TEST_CASE" != self-test-error ] || exit 29 ;;
  *target/release/libgranary_client.rlib) [ "$OVERLAY_TEST_CASE" != release-reader-error ] || exit 2 ;;
  *target/debug/libgranary_client.rlib)
    if [ "$OVERLAY_TEST_CASE" = wrong-armed ]; then echo "symbol reader failed"; exit 1; fi
    echo "OVERLAY-FAULT REFUSED: arming API present; artifacts=1 symbols=3 armed=3"
    [ "$OVERLAY_TEST_CASE" != armed-success ] || exit 0
    exit 1 ;;
esac
''')
            # Exercise Linux lane admission on every host. The privileged
            # command below is a fixture for libtest output.
            uname = bin_dir / "uname"
            uname.write_text("#!/usr/bin/env bash\necho Linux\n")
            sudo = bin_dir / "sudo"
            sudo.write_text("#!/usr/bin/env bash\n" + r'''set -eu
prefix=overlay_discard::tests::linux::discard_refuses_
[[ "$*" == "--non-interactive unshare --mount --propagation private -- mock-client-tests --ignored --exact --format pretty ${prefix}foreign_owner ${prefix}mount_crossing" ]] || exit 32
if [ "$OVERLAY_TEST_CASE" = runner-error-privileged ]; then
  echo "privileged runner failed"
  exit 33
fi
if [ "$OVERLAY_TEST_CASE" != zero-privileged ]; then
  echo "test ${prefix}foreign_owner ... ok"
fi
case "$OVERLAY_TEST_CASE" in
  zero-privileged|one-privileged) ;;
  ignored-result-privileged) echo "test ${prefix}mount_crossing ... ignored" ;;
  wrong-name-privileged) echo "test ${prefix}mount_crossing_helper ... ok" ;;
  duplicate-result-privileged) echo "test ${prefix}foreign_owner ... ok" ;;
  *) echo "test ${prefix}mount_crossing ... ok" ;;
esac
''')
            for executable in [cargo, python, uname, sudo]:
                executable.chmod(0o700)
            cases = [
                ("valid", 0), ("listing-error", 27), ("missing-matrix", 1),
                ("test-error", 28), ("wall-success", 1), ("wrong-wall", 1),
                ("armed-success", 1), ("wrong-armed", 1), ("self-test-error", 29),
                ("release-reader-error", 2), ("missing-discard", 1), ("ignored-unprivileged", 1),
                ("suffixed-discard", 1), ("valid-privileged", 0),
                ("zero-privileged", 1), ("one-privileged", 1),
                ("runner-error-privileged", 33), ("missing-ignored", 1), ("extra-ignored", 1),
                ("ignored-result-privileged", 1), ("wrong-name-privileged", 1), ("duplicate-result-privileged", 1),
            ]
            for case, expected in cases:
                env = os.environ.copy()
                env.update(
                    PATH=str(bin_dir) + os.pathsep + env["PATH"],
                    OVERLAY_TEST_CASE=case,
                    OVERLAY_TEST_PYTHON=sys.executable,
                    GRANARY_REQUIRE_DISCARD_CUSTODY="1" if case.endswith("-privileged") else "0",
                )
                result = subprocess.run(["bash", str(root / "scripts/check-overlay-faults.sh")], env=env, capture_output=True, text=True, check=False)
                with self.subTest(case=case):
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    banner = "OVERLAY-FAULT PASS: armed matrices, shipping symbols and release wall"
                    self.assertEqual(banner in result.stdout, expected == 0)
                    if expected == 0:
                        self.assertIn("CARGO nextest run --profile ci --locked -p granary-client --features overlay-fault-tests", result.stderr)
                        self.assertIn("PYTHON scripts/check-overlay-fault-exclusion.py --self-test", result.stdout)
                    if case == "missing-discard":
                        self.assertIn("missing Linux discard row empty_destination_race (default)", result.stderr)
                    if case in {"ignored-unprivileged", "suffixed-discard"}:
                        self.assertIn("missing Linux discard row foreign_mode (default)", result.stderr)
                    if case == "missing-ignored":
                        self.assertIn("missing Linux discard row mount_crossing (ignored-only)", result.stderr)
                    if case == "extra-ignored":
                        self.assertIn("unexpected ignored Linux discard rows", result.stderr)
                    if case in {"zero-privileged", "one-privileged"}:
                        self.assertIn("expected exactly two privileged discard test results", result.stderr)
                    if case == "runner-error-privileged":
                        self.assertIn("privileged runner failed", result.stderr)
                    if case in {"ignored-result-privileged", "wrong-name-privileged", "duplicate-result-privileged"}:
                        self.assertIn("privileged discard test did not pass overlay_discard::tests::linux::discard_refuses_mount_crossing", result.stderr)

    def test_self_test_dispatch_propagates_child_status(self):
        with patch.object(sys, "argv", [guard.__file__, "--self-test"]), patch.object(guard.subprocess, "run", return_value=subprocess.CompletedProcess([], 37)) as child:
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(guard.__file__, run_name="__main__")
            self.assertEqual(result.exception.code, 37)
            self.assertEqual(child.call_args.args[0], [sys.executable, str(Path(guard.__file__).with_name("test-overlay-fault-exclusion.py"))])

    def test_cli_wiring_and_optimization_refusal(self):
        with tempfile.TemporaryDirectory(prefix="overlay-cli-") as temporary:
            missing = Path(temporary) / "missing.rlib"
            result = subprocess.run([sys.executable, guard.__file__, str(missing)], capture_output=True, text=True, check=False)
            self.assertEqual(
                (result.returncode, result.stdout.strip()),
                (
                    2,
                    "OVERLAY-FAULT PASS: metrics_snapshot source gate present; cases=1\n"
                    "OVERLAY-FAULT REFUSED: cannot read artifact or symbols: FileNotFoundError",
                ),
            )
            for script in [guard.__file__, __file__]:
                result = subprocess.run([sys.executable, "-O", script, str(missing)], capture_output=True, text=True, check=False)
                self.assertEqual((result.returncode, result.stderr.strip()), (1, "OVERLAY-FAULT REFUSED: Python optimization is forbidden"))


if __name__ == "__main__":
    unittest.main()
