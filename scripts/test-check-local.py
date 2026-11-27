# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Exercise the real Cargo invocation and isolate the driver's child commands."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / 'scripts' / 'check-local.sh'
XTASK = ['run', '--quiet', '--locked', '--package', 'xtask', '--']
FMT = ['fmt', '--check']
CLIPPY = ['clippy', '--workspace', '--all-targets', '--locked']
NEXTEST = ['nextest', 'run', '--profile', 'ci', '--locked', '--retries', '0',
           '--no-tests', 'fail']
QUICK = [FMT, CLIPPY, NEXTEST + ['-p', 'granary-core', '-p', 'granary-vfs']]
FULL = [FMT, CLIPPY, NEXTEST, ['test', '--doc', '--locked']]


def member(root, env):
    data = subprocess.check_output(
        ['cargo', 'metadata', '--no-deps', '--locked', '--format-version', '1'],
        cwd=root, env=env, text=True,
    )
    return next(Path(p['manifest_path']).parent for p in json.loads(data)['packages']
                if p['name'] == 'granary-core')


class CargoHelpTests(unittest.TestCase):
    def test_real_cargo_help(self):
        usage = 'Usage: cargo ' + ' '.join(XTASK) + ' <task>'
        with TemporaryDirectory() as target:
            env = dict(os.environ, CARGO_TARGET_DIR=target)
            for cwd in (ROOT, member(ROOT, env)):
                with self.subTest(cwd=cwd):
                    result = subprocess.run(['cargo', *XTASK, '--help'], cwd=cwd,
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(usage, result.stdout.splitlines())
                    for task in ('check', 'check-full'):
                        self.assertIn(task, (result.stdout + result.stderr).split())


RECORDER = '''import json, os, signal, sys
e = os.environ
args = sys.argv[1:]
with open(e['CHECK_LOG'], 'a', encoding='utf-8') as log:
    print(json.dumps([args, os.getcwd(), e.get('CARGO_BUILD_WARNINGS'),
                      e.get('TMPDIR')]), file=log)
if args[:1] == [e.get('FAIL_STEP')]:
    sys.exit(23)
if args[:1] == [e.get('MISSING_STEP')]:
    sys.exit('error: no such command: ' + args[0])
if args[:1] == [e.get('SIGNAL_STEP')]:
    os.kill(os.getpid(), signal.SIGTERM)
'''


class ProbeCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.temp = Path(temp.name).resolve()
        cls.bin = cls.temp / 'bin'
        cls.bin.mkdir()
        recorder = cls.temp / 'record.py'
        recorder.write_text(RECORDER, encoding='utf-8')
        if os.name == 'nt':
            # Command::new("cargo") needs a native executable, not a .cmd file.
            src = cls.temp / 'probe.rs'
            src.write_text('''use std::{env, process::{Command, exit}};
fn main() {
    let status = Command::new(env::var_os("CHECK_PYTHON").unwrap())
        .arg(env::var_os("CHECK_RECORDER").unwrap()).args(env::args_os().skip(1))
        .status().unwrap();
    exit(status.code().unwrap_or(1));
}
''', encoding='utf-8')
            subprocess.run(['rustc', src, '-o', cls.bin / 'cargo.exe'],
                           cwd=cls.temp, check=True)
        else:
            cargo = cls.bin / 'cargo'
            cargo.write_text('#!/bin/sh\nexec "$CHECK_PYTHON" "$CHECK_RECORDER" "$@"\n',
                             encoding='utf-8')
            cargo.chmod(0o755)

    def setUp(self):
        temp = TemporaryDirectory(dir=self.temp)
        self.addCleanup(temp.cleanup)
        self.scratch = Path(temp.name)
        self.log = self.scratch / 'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin), CHECK_LOG=str(self.log),
                        CHECK_PYTHON=sys.executable, CHECK_RECORDER=str(self.temp / 'record.py'),
                        TMPDIR=str(self.scratch), FAIL_STEP='', MISSING_STEP='', SIGNAL_STEP='')
        for name in ('CARGO', 'CARGO_BUILD_WARNINGS', 'CARGO_MANIFEST_DIR'):
            self.env.pop(name, None)

    def invoke(self, argv, cwd, **env):
        return subprocess.run(argv, cwd=cwd, env={**self.env, **env},
                              capture_output=True, text=True)

    def assert_calls(self, expected, root):
        rows = [json.loads(line) for line in self.log.read_text(encoding='utf-8').splitlines()] if self.log.exists() else []
        self.assertEqual([row[0] for row in rows], expected)
        for args, cwd, warnings, tmpdir in rows:
            self.assertTrue(Path(cwd).samefile(root), (cwd, root))
            self.assertEqual(tmpdir, str(self.scratch))
            if args == CLIPPY:
                self.assertEqual(warnings, 'deny')


class CargoRunTests(ProbeCase):
    def invoke_task(self, task, cwd=ROOT, **env):
        original_path = os.environ.get('PATH', os.defpath)
        cargo = shutil.which('cargo', path=original_path)
        self.assertIsNotNone(cargo, 'real Cargo is required')
        return self.invoke(
            [os.path.abspath(cargo), *XTASK, task], cwd,
            PATH=str(self.bin) + os.pathsep + original_path,
            CARGO_TARGET_DIR=str(self.temp / 'target'), **env,
        )

    def test_real_check_from_root(self):
        result = self.invoke_task('check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_calls(QUICK, ROOT)

    def test_real_check_full_from_member(self):
        result = self.invoke_task('check-full', cwd=member(ROOT, os.environ))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_calls(FULL, ROOT)

    def test_real_cargo_failure_code(self):
        result = self.invoke_task('check', FAIL_STEP='clippy')
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls(QUICK[:2], ROOT)

    @unittest.skipUnless(os.name == 'posix', 'Unix child termination')
    def test_real_cargo_signalled_child(self):
        result = self.invoke_task('check-full', SIGNAL_STEP='clippy')
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assert_calls(FULL[:2], ROOT)


class DriverTests(ProbeCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        target = cls.temp / 'target'
        env = dict(os.environ, CARGO_TARGET_DIR=str(target))
        subprocess.run(['cargo', 'build', '--locked', '-p', 'xtask'],
                       cwd=ROOT, env=env, check=True)
        cls.driver = target / 'debug' / ('xtask.exe' if os.name == 'nt' else 'xtask')
        # A driver hard-coding its build checkout must not pass the member test.
        cls.other = cls.temp / 'checkout'
        for path in ('Cargo.toml', '.cargo/config.toml', 'xtask/Cargo.toml'):
            marker = cls.other / path
            marker.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, marker)
        cls.member = cls.other / 'crates' / 'granary-core'
        cls.member.mkdir(parents=True)

    def test_quick_from_root(self):
        result = self.invoke([self.driver, 'check'], ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_calls(QUICK, ROOT)

    def test_full_from_member(self):
        result = self.invoke([self.driver, 'check-full'], self.member)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_calls(FULL, self.other)

    def test_failure_code(self):
        result = self.invoke([self.driver, 'check'], ROOT, FAIL_STEP='clippy')
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls(QUICK[:2], ROOT)

    def test_missing_nextest(self):
        result = self.invoke([self.driver, 'check-full'], ROOT, MISSING_STEP='nextest')
        self.assertNotEqual(result.returncode, 0)
        self.assert_calls(FULL[:3], ROOT)

    def test_missing_cargo(self):
        result = self.invoke([self.driver, 'check'], ROOT, PATH=str(self.scratch))
        self.assertNotEqual(result.returncode, 0)
        self.assert_calls([], ROOT)

    def test_bad_arguments(self):
        for args in (['unknown'], ['check', 'extra'], ['check-full', 'extra']):
            with self.subTest(args=args):
                result = self.invoke([self.driver, *args], ROOT)
                self.assertNotEqual(result.returncode, 0)
                self.assert_calls([], ROOT)

    @unittest.skipUnless(os.name == 'posix', 'Unix child termination')
    def test_signalled_child(self):
        result = self.invoke([self.driver, 'check-full'], ROOT, SIGNAL_STEP='clippy')
        self.assertNotEqual(result.returncode, 0)
        self.assert_calls(FULL[:2], ROOT)


@unittest.skipUnless(os.name == 'posix' and Path('/bin/bash').is_file(), 'requires Bash')
class ShimTests(ProbeCase):
    def test_delegates_from_repo(self):
        result = self.invoke(['/bin/bash', CHECK], self.scratch, FAIL_STEP='run',
                             PATH=str(self.bin) + os.pathsep + os.defpath)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls([XTASK + ['check']], ROOT)

    def test_historical_no_cargo_error(self):
        result = self.invoke(['/bin/bash', CHECK], self.scratch, PATH=str(self.scratch))
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertEqual(result.stderr.rstrip('\n'),
                         'cargo is required. Install Rust with rustup and add Cargo to PATH.')
        self.assert_calls([], ROOT)


if __name__ == '__main__':
    unittest.main()
