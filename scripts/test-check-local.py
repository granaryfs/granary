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
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / 'scripts' / 'check-local.sh'
BLOCKED_CONTROLS = ROOT / 'scripts' / 'blocked-stderr-controls.sh'
XTASK = ['run', '--quiet', '--locked', '--package', 'xtask', '--']
FMT = ['fmt', '--check']
CLIPPY = ['clippy', '--workspace', '--all-targets', '--locked']
NEXTEST = ['nextest', 'run', '--profile', 'ci', '--locked', '--retries', '0',
           '--no-tests', 'fail']
QUICK = [FMT, CLIPPY, NEXTEST + ['-p', 'granary-core', '-p', 'granary-vfs']]
FULL = [FMT, CLIPPY, NEXTEST + ['--workspace'],
        ['test', '--doc', '--locked', '--workspace']]
BASH = shutil.which('bash', path=os.environ.get('PATH', os.defpath))
if BASH is not None:
    BASH = os.path.abspath(BASH)
RECORDER_CONTROLS = ('LOCATE_MODE', 'LOCATE_MANIFEST', 'MEMBER_LOCATE_MODE',
                     'MEMBER_LOCATE_OUTPUT', 'PKGID_MODE', 'PROBE_SIGNAL',
                     'FAIL_STEP', 'FAIL_CODE', 'MISSING_STEP', 'SIGNAL_STEP')


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


@unittest.skipUnless(os.name == 'posix' and BASH is not None, 'requires Bash')
class BlockedStderrCopyTests(unittest.TestCase):
    def test_staged_workspace_loads_with_xtask_member(self):
        with TemporaryDirectory(dir='/tmp') as scratch:
            out = Path(scratch) / 'staged-control'
            result = subprocess.run([BASH, BLOCKED_CONTROLS, '--self-test', out],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('STDERR-CONTROL-COPY: workspace metadata includes xtask',
                          result.stdout)
            self.assertIn('STDERR-CONTROL-COPY: missing xtask member, wrong name, and wrong root are refused',
                          result.stdout)


class CargoBuildTargetTests(unittest.TestCase):
    def test_non_native_target_setting_does_not_move_direct_driver(self):
        env = dict(os.environ, CARGO_BUILD_TARGET='granary-invalid-target')
        result = subprocess.run(
            [sys.executable, '-I', __file__, 'DriverTests.test_quick_from_root', '-v'],
            cwd=ROOT, env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Ran 1 test', result.stderr)


class OutsideWorkspaceTests(unittest.TestCase):
    def test_unrelated_cargo_ancestor_does_not_count_as_outside(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'Cargo.toml').write_text('[workspace]\n', encoding='utf-8')
            scratch = root / 'scratch'
            scratch.mkdir()
            env = dict(os.environ, TMPDIR=str(scratch))
            result = subprocess.run(
                [sys.executable, '-I', __file__, 'DriverTests.test_outside_workspace', '-v'],
                cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Ran 1 test', result.stderr)


class RecorderIsolationTests(unittest.TestCase):
    def test_ambient_fault_controls_do_not_change_other_tests(self):
        env = dict(os.environ, **dict.fromkeys(RECORDER_CONTROLS, 'poison'))
        env.update(LOCATE_MODE='empty', FAIL_CODE='99')
        result = subprocess.run(
            [sys.executable, '-I', __file__,
             'DriverTests.test_recorder_controls_are_absent',
             'CargoRunTests.test_real_cargo_failure_code', '-v'],
            cwd=ROOT, env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertIn('Ran 2 tests', result.stderr)


RECORDER = '''import json, os, signal, subprocess, sys
e = os.environ
args = sys.argv[1:]
if args[:1] in (['locate-project'], ['pkgid']):
    with open(e['CHECK_PROBE_LOG'], 'a', encoding='utf-8') as log:
        print(json.dumps(args), file=log)
if args[:1] == ['locate-project'] and '--manifest-path' in args and e.get('MEMBER_LOCATE_MODE') == 'nonzero':
    print(e['MEMBER_LOCATE_OUTPUT'])
    print('member locate-project: deliberately invalid workspace', file=sys.stderr)
    sys.exit(42)
if args == ['locate-project', '--workspace', '--message-format', 'plain']:
    if e.get('LOCATE_MODE') == 'empty':
        sys.exit(0)
    if e.get('LOCATE_MODE') == 'nonzero':
        print(e['LOCATE_MANIFEST'])
        print('lookup refused', file=sys.stderr)
        sys.exit(42)
    if e.get('LOCATE_MODE') == 'signal':
        os.kill(os.getpid(), signal.SIGTERM)
    sys.exit(subprocess.run([e['CHECK_REAL_CARGO'], *args]).returncode)
if args[:1] == ['pkgid'] and e.get('PKGID_MODE') == 'empty':
    print('   ')
    sys.exit(0)
if args[:1] == ['pkgid'] and e.get('PKGID_MODE') == 'nonzero':
    print('path+file:///plausible#xtask@0.1.0')
    print('pkgid: deliberately malformed manifest', file=sys.stderr)
    sys.exit(42)
if e.get('PROBE_SIGNAL') == args[0] and args[0] in ('pkgid', 'locate-project'):
    os.kill(os.getpid(), signal.SIGTERM)
if args[:1] in (['locate-project'], ['pkgid']):
    sys.exit(subprocess.run([e['CHECK_REAL_CARGO'], *args]).returncode)
with open(e['CHECK_LOG'], 'a', encoding='utf-8') as log:
    print(json.dumps([args, os.getcwd(), e.get('CARGO_BUILD_WARNINGS'),
                      e.get('TMPDIR')]), file=log)
if args[:1] == [e.get('FAIL_STEP')]:
    sys.exit(int(e.get('FAIL_CODE', '23')))
if args[:1] == [e.get('MISSING_STEP')]:
    print('error: no such command: ' + args[0], file=sys.stderr)
    sys.exit(101)
if args[:1] == [e.get('SIGNAL_STEP')]:
    os.kill(os.getpid(), signal.SIGTERM)
'''


class ProbeCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.temp = Path(temp.name).resolve()
        # Every synthetic checkout under this tree uses the repository pin.
        shutil.copyfile(ROOT / 'rust-toolchain.toml',
                        cls.temp / 'rust-toolchain.toml')
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
        .arg("-I").arg(env::var_os("CHECK_RECORDER").unwrap())
        .args(env::args_os().skip(1))
        .status().unwrap();
    exit(status.code().unwrap_or(1));
}
''', encoding='utf-8')
            subprocess.run(['rustc', src, '-o', cls.bin / 'cargo.exe'],
                           cwd=cls.temp, check=True)
        else:
            cargo = cls.bin / 'cargo'
            cargo.write_text('#!/bin/sh\nexec "$CHECK_PYTHON" -I "$CHECK_RECORDER" "$@"\n',
                             encoding='utf-8')
            cargo.chmod(0o755)

    def setUp(self):
        temp = TemporaryDirectory(dir=self.temp)
        self.addCleanup(temp.cleanup)
        self.scratch = Path(temp.name)
        self.log = self.scratch / 'calls.jsonl'
        self.probe_log = self.scratch / 'probes.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin), CHECK_LOG=str(self.log),
                        CHECK_PROBE_LOG=str(self.probe_log),
                        CHECK_PYTHON=sys.executable, CHECK_RECORDER=str(self.temp / 'record.py'),
                        CHECK_REAL_CARGO=os.path.abspath(shutil.which('cargo')),
                        TMPDIR=str(self.scratch))
        for name in ('CARGO', 'CARGO_BUILD_WARNINGS', 'CARGO_MANIFEST_DIR',
                     *RECORDER_CONTROLS):
            self.env.pop(name, None)

    def invoke(self, argv, cwd, **env):
        return subprocess.run(argv, cwd=cwd, env={**self.env, **env},
                              capture_output=True, text=True)

    def poison_pythonpath(self):
        poison = self.scratch / 'poison-pythonpath'
        poison.mkdir(exist_ok=True)
        (poison / 'json.py').write_text('raise RuntimeError("PYTHONPATH used")\n',
                                        encoding='utf-8')
        return str(poison)

    def assert_calls(self, expected, root, check_warnings=True):
        rows = [json.loads(line) for line in self.log.read_text(encoding='utf-8').splitlines()] if self.log.exists() else []
        self.assertEqual([row[0] for row in rows], expected)
        for args, cwd, warnings, tmpdir in rows:
            self.assertTrue(Path(cwd).samefile(root), (cwd, root))
            self.assertEqual(tmpdir, str(self.scratch))
            if check_warnings:
                self.assertEqual(warnings, 'deny')


class CargoRunTests(ProbeCase):
    def invoke_task(self, task, cwd=ROOT, **env):
        original_path = os.environ.get('PATH', os.defpath)
        cargo = shutil.which('cargo', path=original_path)
        self.assertIsNotNone(cargo, 'real Cargo is required')
        # A relative inherited entry would make xtask select Cargo's CARGO
        # executable instead of the recorder this test is asserting against.
        absolute_path = [entry for entry in original_path.split(os.pathsep)
                         if os.path.isabs(entry)]
        return self.invoke(
            [os.path.abspath(cargo), *XTASK, task], cwd,
            PATH=os.pathsep.join([str(self.bin), *absolute_path]),
            CARGO_TARGET_DIR=str(self.temp / 'target'), **env,
        )

    def test_real_check_from_root(self):
        result = self.invoke_task('check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_calls(QUICK, ROOT)

    @unittest.skipUnless(os.name == 'posix', 'relative PATH fixture')
    def test_real_check_ignores_inherited_relative_path(self):
        fail_cargo = self.scratch / 'fail-cargo'
        fail_cargo.write_text('#!/bin/sh\nexit 47\n', encoding='utf-8')
        fail_cargo.chmod(0o755)
        inherited = os.environ.get('PATH', os.defpath) + os.pathsep + '.'
        with mock.patch.dict(os.environ, PATH=inherited):
            result = self.invoke_task('check', CARGO=str(fail_cargo),
                                      FAIL_STEP='fmt')
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls([FMT], ROOT)

    @unittest.skipUnless(os.name == 'posix', 'POSIX relative PATH dispatch')
    def test_real_cargo_run_from_member_preserves_cargo_identity(self):
        checkout = self.scratch / 'checkout:colon'
        checkout.mkdir()
        # A dependency-free Cargo workspace exercises the real cargo-run
        # handoff without requiring a warm registry or network access.
        (checkout / 'Cargo.toml').write_text(
            '[workspace]\nresolver = "3"\n'
            'members = ["xtask", "crates/granary-core", "crates/granary-vfs"]\n'
            '[workspace.package]\nedition = "2024"\nrust-version = "1.97"\n'
            'license = "Apache-2.0"\npublish = false\n'
            '[workspace.lints.rust]\nunsafe_code = "forbid"\n',
            encoding='utf-8')
        for name in ('rust-toolchain.toml', 'xtask/Cargo.toml', 'xtask/src/main.rs'):
            target = checkout / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        for name in ('granary-core', 'granary-vfs'):
            crate = checkout / 'crates' / name
            (crate / 'src').mkdir(parents=True)
            (crate / 'Cargo.toml').write_text(
                '[package]\nname = "' + name
                + '"\nversion = "0.0.1"\nedition = "2024"\n',
                encoding='utf-8')
            (crate / 'src' / 'lib.rs').write_text('', encoding='utf-8')
        lock = self.invoke([self.env['CHECK_REAL_CARGO'],
                            'generate-lockfile', '--offline'], checkout,
                           CARGO_NET_OFFLINE='true')
        self.assertEqual(lock.returncode, 0, lock.stderr)

        member = checkout / 'crates' / 'granary-core'
        decoy_marker = self.scratch / 'decoy.log'
        for directory in (checkout / 'bin', member / 'bin'):
            directory.mkdir()
            decoy = directory / 'cargo'
            decoy.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$PWD" >> "$DECOY_MARKER"\nexit 77\n',
                encoding='utf-8')
            decoy.chmod(0o755)
        toolbin = self.scratch / 'toolbin'
        toolbin.mkdir()
        fmt_marker = self.scratch / 'fmt.log'
        later_marker = self.scratch / 'later.log'
        for name, marker, code in (('cargo-fmt', 'FMT_MARKER', 47),
                                    ('cargo-clippy', 'LATER_MARKER', 99),
                                    ('cargo-nextest', 'LATER_MARKER', 99)):
            stub = toolbin / name
            stub.write_text('#!/bin/sh\nprintf "%s|%s\\n" "$PWD" "$*" > "'
                            + '${' + marker + '}"\nexit ' + str(code) + '\n',
                            encoding='utf-8')
            stub.chmod(0o755)
        host_path = [entry for entry in os.environ.get('PATH', os.defpath).split(os.pathsep)
                     if os.path.isabs(entry)]
        search_path = os.pathsep.join(['bin', str(toolbin), *host_path])
        env = dict(PATH=search_path, DECOY_MARKER=str(decoy_marker),
                   FMT_MARKER=str(fmt_marker), LATER_MARKER=str(later_marker),
                   CARGO_TARGET_DIR=str(self.scratch / 'target-relative'),
                   CARGO_NET_OFFLINE='true')
        self.assertNotIn('CARGO', self.env)
        for cwd in (member, checkout):
            bare = self.invoke(['cargo', '--version'], cwd, **env)
            self.assertEqual(bare.returncode, 77, bare.stderr)
        self.assertEqual(len(decoy_marker.read_text(encoding='utf-8').splitlines()), 2)
        decoy_marker.unlink()
        result = self.invoke([self.env['CHECK_REAL_CARGO'], *XTASK, 'check'],
                             member, PYTHONPATH=self.poison_pythonpath(), **env)
        self.assertEqual(result.returncode, 47, result.stderr[-2000:])
        self.assertIn('cargo fmt --check failed', result.stderr)
        self.assertFalse(decoy_marker.exists(), 'runner must bypass both decoys')
        self.assertFalse(later_marker.exists(), 'runner must stop after fmt')
        self.assertTrue(fmt_marker.is_file())
        fmt_cwd, separator, fmt_args = fmt_marker.read_text(encoding='utf-8').partition('|')
        self.assertEqual(separator, '|')
        self.assertEqual(fmt_cwd, str(checkout))
        self.assertIn('--check', fmt_args.split())

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
        rustc_version = subprocess.check_output(['rustc', '-vV'], cwd=ROOT,
                                                env=env, text=True)
        host = next(line.removeprefix('host: ') for line in rustc_version.splitlines()
                    if line.startswith('host: '))
        subprocess.run(['cargo', 'build', '--locked', '-p', 'xtask', '--target', host],
                       cwd=ROOT, env=env, check=True)
        cls.driver = target / host / 'debug' / ('xtask.exe' if os.name == 'nt' else 'xtask')
        # A driver hard-coding its build checkout must not pass the member test.
        cls.other = cls.temp / 'checkout'
        for path in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
                     'xtask/Cargo.toml',
                     'crates/granary-core/Cargo.toml', 'crates/granary-vfs/Cargo.toml',
                     'crates/granary-core/src/lib.rs', 'crates/granary-vfs/src/lib.rs',
                     'xtask/src/main.rs'):
            marker = cls.other / path
            marker.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, marker)
        cls.member = cls.other / 'crates' / 'granary-core'
        cls.member.mkdir(parents=True, exist_ok=True)

    def test_relocated_fixture_keeps_pinned_toolchain(self):
        self.assertEqual((self.other / 'rust-toolchain.toml').read_bytes(),
                         (ROOT / 'rust-toolchain.toml').read_bytes())
        env = dict(os.environ)
        env.pop('RUSTUP_TOOLCHAIN', None)
        self.assertEqual(subprocess.check_output(['rustc', '--version'], cwd=self.member,
                                                 env=env, text=True),
                         subprocess.check_output(['rustc', '--version'], cwd=ROOT,
                                                 env=env, text=True))

    def test_recorder_controls_are_absent(self):
        self.assertTrue(all(name not in self.env for name in RECORDER_CONTROLS))

    def test_recorder_python_imports_ignore_pythonpath(self):
        result = self.invoke([self.driver, 'check'], ROOT,
                             PYTHONPATH=self.poison_pythonpath())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_calls(QUICK, ROOT)

    def test_quick_from_root(self):
        result = self.invoke([self.driver, 'check'], ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_calls(QUICK, ROOT)

    def test_full_from_member(self):
        result = self.invoke([self.driver, 'check-full'], self.member)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_calls(FULL, self.other)

    @unittest.skipUnless(os.name == 'posix', 'relative PATH executable fixture')
    def test_relative_path_cargo_from_member_keeps_executable(self):
        checkout = self.scratch / 'checkout:with-colon'
        shutil.copytree(self.other, checkout)
        member = checkout / 'crates' / 'granary-core'
        member_bin = member / 'bin'
        member_bin.mkdir()
        identity = self.scratch / 'cargo-identity.log'
        decoy = member_bin / 'cargo'
        decoy.write_text('#!/bin/sh\nexit 77\n', encoding='utf-8')
        decoy.chmod(0o755)
        selected = self.scratch / 'selected-cargo'
        selected.write_text(
            '#!/bin/sh\nprintf "selected-cargo\\n" >> "$CHECK_IDENTITY_LOG"\n'
            'exec "$CHECK_PYTHON" -I "$CHECK_RECORDER" "$@"\n',
            encoding='utf-8')
        selected.chmod(0o755)
        for search_path in ('bin', str(member_bin) + os.pathsep + '.'):
            with self.subTest(search_path=search_path):
                result = self.invoke([self.driver, 'check'], member,
                                     PATH=search_path, CARGO=str(selected),
                                     CHECK_IDENTITY_LOG=str(identity),
                                     PYTHONPATH=self.poison_pythonpath())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_calls(QUICK, checkout)
                probe_count = len(self.probe_log.read_text(encoding='utf-8').splitlines())
                self.assertEqual(probe_count, 10)
                self.assertEqual(len(identity.read_text(encoding='utf-8').splitlines()),
                                 10 + len(QUICK))
                self.log.unlink()
                self.probe_log.unlink()
                identity.unlink()

    def test_nested_xtask_manifest_does_not_shadow_workspace(self):
        with TemporaryDirectory(dir=self.temp) as temp:
            checkout = Path(temp) / 'checkout'
            for path in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'xtask/Cargo.toml',
                         'crates/granary-core/Cargo.toml',
                         'crates/granary-vfs/Cargo.toml',
                         'crates/granary-core/src/lib.rs', 'crates/granary-vfs/src/lib.rs',
                         'xtask/src/main.rs'):
                marker = checkout / path
                marker.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, marker)
            member = checkout / 'crates' / 'granary-core'
            nested = member / 'xtask' / 'Cargo.toml'
            nested.parent.mkdir()
            nested.write_text('[package]\nname = "xtask"\nversion = "0.1.0"\n',
                              encoding='utf-8')
            result = self.invoke([self.driver, 'check-full'], member)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_calls(FULL, checkout)

    def test_complete_nested_marker_set_does_not_shadow_workspace(self):
        with TemporaryDirectory(dir=self.temp) as temp:
            checkout = Path(temp) / 'checkout'
            for path in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'xtask/Cargo.toml',
                         'crates/granary-core/Cargo.toml',
                         'crates/granary-vfs/Cargo.toml',
                         'crates/granary-core/src/lib.rs', 'crates/granary-vfs/src/lib.rs',
                         'xtask/src/main.rs'):
                marker = checkout / path
                marker.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, marker)
            member = checkout / 'crates' / 'granary-core'
            for path in ('xtask/Cargo.toml', 'crates/granary-core/Cargo.toml',
                         'crates/granary-vfs/Cargo.toml'):
                nested = member / path
                nested.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, nested)
            result = self.invoke([self.driver, 'check-full'], member)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_calls(FULL, checkout)

    def test_edited_relocated_manifest_still_finds_workspace(self):
        with TemporaryDirectory(dir=self.temp) as temp:
            checkout = Path(temp) / 'checkout'
            for path in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'xtask/Cargo.toml',
                         'crates/granary-core/Cargo.toml',
                         'crates/granary-vfs/Cargo.toml',
                         'crates/granary-core/src/lib.rs', 'crates/granary-vfs/src/lib.rs',
                         'xtask/src/main.rs'):
                marker = checkout / path
                marker.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, marker)
            manifest = checkout / 'Cargo.toml'
            manifest.write_text(manifest.read_text(encoding='utf-8')
                                + '\n# local manifest edit\n', encoding='utf-8')
            result = self.invoke([self.driver, 'check'],
                                 checkout / 'crates' / 'granary-core')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_calls(QUICK, checkout)

    def test_failure_code(self):
        result = self.invoke([self.driver, 'check'], ROOT, FAIL_STEP='clippy')
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls(QUICK[:2], ROOT)

    def test_child_status_overlap_is_distinguished_by_diagnostic(self):
        for code in (1, 127):
            with self.subTest(code=code):
                self.log.unlink(missing_ok=True)
                result = self.invoke([self.driver, 'check'], ROOT,
                                     FAIL_STEP='fmt', FAIL_CODE=str(code))
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertIn('cargo fmt --check failed:', result.stderr)
                self.assertNotIn('not a Granary workspace', result.stderr)
                self.assert_calls([FMT], ROOT)

    def test_missing_nextest(self):
        result = self.invoke([self.driver, 'check-full'], ROOT, MISSING_STEP='nextest')
        self.assertEqual(result.returncode, 101, result.stderr)
        self.assertIn('no such command: nextest', result.stderr)
        self.assert_calls(FULL[:3], ROOT)

    def test_missing_cargo(self):
        result = self.invoke([self.driver, 'check'], ROOT, PATH=str(self.scratch))
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertIn('could not launch cargo locate-project', result.stderr)
        self.assert_calls([], ROOT)

    def test_lookup_empty_output_stops_before_checks(self):
        result = self.invoke([self.driver, 'check'], ROOT, LOCATE_MODE='empty')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('invalid workspace manifest', result.stderr)
        self.assert_calls([], ROOT)

    def test_lookup_failure_ignores_plausible_stdout(self):
        result = self.invoke([self.driver, 'check'], ROOT, LOCATE_MODE='nonzero',
                             LOCATE_MANIFEST=str(ROOT / 'Cargo.toml'))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('lookup refused', result.stderr)
        self.assertIn('cannot find workspace root', result.stderr)
        self.assert_calls([], ROOT)

    def test_empty_pkgid_output_stops_before_checks(self):
        result = self.invoke([self.driver, 'check'], ROOT, PKGID_MODE='empty')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('not a Granary workspace', result.stderr)
        self.assert_calls([], ROOT)

    def test_failed_pkgid_preserves_cargo_diagnostic(self):
        result = self.invoke([self.driver, 'check'], ROOT, PKGID_MODE='nonzero')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('pkgid: deliberately malformed manifest', result.stderr)
        self.assert_calls([], ROOT)
        probes = [json.loads(line) for line in self.probe_log.read_text().splitlines()]
        self.assertEqual(sum(args[0] == 'pkgid' for args in probes), 1)

    def test_failed_member_locate_stops_before_pkgid(self):
        result = self.invoke([self.driver, 'check'], ROOT,
                             MEMBER_LOCATE_MODE='nonzero',
                             MEMBER_LOCATE_OUTPUT=str(ROOT / 'Cargo.toml'))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('deliberately invalid workspace', result.stderr)
        probes = [json.loads(line) for line in self.probe_log.read_text().splitlines()]
        self.assertEqual([args[0] for args in probes], ['locate-project', 'locate-project'])
        self.assert_calls([], ROOT)

    @unittest.skipUnless(os.name == 'posix', 'Unix child termination')
    def test_signalled_member_probes_preserve_signal_status(self):
        for probe in ('locate-project', 'pkgid'):
            with self.subTest(probe=probe):
                result = self.invoke([self.driver, 'check'], ROOT,
                                     PROBE_SIGNAL=probe)
                self.assertEqual(result.returncode, 143, result.stderr)
                self.assert_calls([], ROOT)

    @unittest.skipUnless(os.name == 'posix', 'Unix child termination')
    def test_lookup_signalled_child(self):
        result = self.invoke([self.driver, 'check'], ROOT, LOCATE_MODE='signal')
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assert_calls([], ROOT)

    def test_bad_arguments(self):
        for args, diagnostic in (([], 'missing task'),
                                 (['unknown'], 'unknown task'),
                                 (['check', 'extra'], 'unexpected argument'),
                                 (['check-full', 'extra'], 'unexpected argument')):
            with self.subTest(args=args):
                result = self.invoke([self.driver, *args], ROOT, LOCATE_MODE='nonzero',
                                     LOCATE_MANIFEST=str(ROOT / 'Cargo.toml'))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(diagnostic, result.stderr)
                self.assertNotIn('lookup refused', result.stderr)
                self.assert_calls([], ROOT)

    def test_outside_workspace(self):
        def has_cargo_ancestor(path):
            return any(parent.joinpath('Cargo.toml').is_file()
                       for parent in (path, *path.parents))

        scratch = self.scratch.resolve()
        if has_cargo_ancestor(scratch):
            if os.name == 'posix':
                parents = (Path('/tmp'), Path('/var/tmp'))
            else:
                parents = tuple(Path(os.environ[name]) for name in ('TEMP', 'TMP')
                                if os.environ.get(name))
            for parent in parents:
                if has_cargo_ancestor(parent.resolve()):
                    continue
                try:
                    external = TemporaryDirectory(dir=parent)
                except OSError:
                    continue
                self.addCleanup(external.cleanup)
                scratch = Path(external.name).resolve()
                break
        self.assertFalse(has_cargo_ancestor(scratch), 'no external scratch directory')
        result = self.invoke([self.driver, 'check'], scratch)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('cannot find workspace root', result.stderr)
        self.assert_calls([], ROOT)

    def test_unrelated_cargo_workspace_is_refused(self):
        other = self.scratch / 'other-workspace'
        (other / 'src').mkdir(parents=True)
        (other / 'Cargo.toml').write_text(
            '[package]\nname = "unrelated"\nversion = "0.1.0"\nedition = "2024"\n'
            '[workspace]\n',
            encoding='utf-8')
        (other / 'src' / 'main.rs').write_text('fn main() {}\n', encoding='utf-8')
        result = self.invoke([self.driver, 'check-full'], other)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('not a Granary workspace', result.stderr)
        self.assert_calls([], ROOT)

    def test_cargo_selected_root_requires_each_granary_marker(self):
        markers = (('xtask/Cargo.toml', 'xtask'),
                   ('crates/granary-core/Cargo.toml', 'granary-core'),
                   ('crates/granary-vfs/Cargo.toml', 'granary-vfs'))
        for missing, _ in markers:
            with self.subTest(missing=missing):
                other = self.scratch / missing.replace('/', '-')
                other.mkdir()
                def workspace_members(selected):
                    (other / 'Cargo.toml').write_text(
                        '[workspace]\nresolver = "3"\nmembers = '
                        + json.dumps([str(Path(path).parent) for path, _ in selected])
                        + '\n', encoding='utf-8')

                workspace_members(markers)
                for marker, name in markers:
                    path = other / marker
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('[package]\nname = "' + name
                                    + '"\nversion = "0.1.0"\nedition = "2024"\n',
                                    encoding='utf-8')
                    source = path.parent / 'src/lib.rs'
                    source.parent.mkdir()
                    source.write_text('', encoding='utf-8')
                subprocess.run(['cargo', 'generate-lockfile'], cwd=other,
                               check=True, capture_output=True)
                positive = self.invoke([self.driver, 'check-full'], other)
                self.assertEqual(positive.returncode, 0, positive.stderr)
                self.assert_calls(FULL, other)
                self.log.unlink()

                (other / missing).unlink()
                survivors = tuple(item for item in markers if item[0] != missing)
                workspace_members(survivors)
                subprocess.run(['cargo', 'generate-lockfile'], cwd=other,
                               check=True, capture_output=True)
                for marker, name in survivors:
                    probe = subprocess.run(
                        ['cargo', 'pkgid', '--locked', '--manifest-path',
                         str(other / marker), '-p', name], cwd=other,
                        capture_output=True, text=True)
                    self.assertEqual(probe.returncode, 0, probe.stderr)
                result = self.invoke([self.driver, 'check-full'], other)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('not a Granary workspace', result.stderr)
                self.assert_calls([], ROOT)

    def test_unrelated_workspace_with_all_markers_is_refused(self):
        other = self.scratch / 'complete-decoy'
        other.mkdir()
        (other / 'Cargo.toml').write_text('[workspace]\n', encoding='utf-8')
        for marker in ('xtask/Cargo.toml', 'crates/granary-core/Cargo.toml',
                       'crates/granary-vfs/Cargo.toml'):
            path = other / marker
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('[package]\nname = "decoy"\nversion = "0.1.0"\n',
                            encoding='utf-8')
        result = self.invoke([self.driver, 'check-full'], other)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('not a Granary workspace', result.stderr)
        self.assert_calls([], ROOT)

    def test_named_marker_packages_in_separate_workspaces_are_refused(self):
        other = self.scratch / 'separate-workspaces'
        other.mkdir()
        (other / 'Cargo.toml').write_text(
            '[workspace]\nexclude = ["xtask", "crates/*"]\n', encoding='utf-8')
        for marker, name in (('xtask/Cargo.toml', 'xtask'),
                             ('crates/granary-core/Cargo.toml', 'granary-core'),
                             ('crates/granary-vfs/Cargo.toml', 'granary-vfs')):
            path = other / marker
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('[package]\nname = "' + name
                            + '"\nversion = "0.1.0"\nedition = "2024"\n[workspace]\n',
                            encoding='utf-8')
            source = path.parent / 'src' / 'lib.rs'
            source.parent.mkdir()
            source.write_text('', encoding='utf-8')
            located = subprocess.run(
                ['cargo', 'locate-project', '--workspace', '--message-format', 'plain',
                 '--manifest-path', str(path)], cwd=other, capture_output=True, text=True)
            self.assertEqual(located.returncode, 0, located.stderr)
            self.assertEqual(Path(located.stdout.strip()), path)
            subprocess.run(['cargo', 'generate-lockfile', '--manifest-path', str(path)],
                           cwd=other, check=True, capture_output=True)
            pkgid = subprocess.run(['cargo', 'pkgid', '--locked',
                                    '--manifest-path', str(path), '-p', name],
                                   cwd=other, capture_output=True, text=True)
            self.assertEqual(pkgid.returncode, 0, pkgid.stderr)
        result = self.invoke([self.driver, 'check'], other)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('not a Granary workspace', result.stderr)
        self.assert_calls([], ROOT)

    def test_swapped_package_names_at_member_paths_are_refused(self):
        markers = (('xtask/Cargo.toml', 'xtask'),
                   ('crates/granary-core/Cargo.toml', 'granary-core'),
                   ('crates/granary-vfs/Cargo.toml', 'granary-vfs'))
        for wrong_path, wrong_name in markers:
            with self.subTest(wrong_path=wrong_path):
                other = self.scratch / ('wrong-' + wrong_name)
                other.mkdir()
                (other / 'Cargo.toml').write_text(
                    '[workspace]\nresolver = "3"\nmembers = '
                    + json.dumps([str(Path(path).parent) for path, _ in markers]
                                 + ['tools/shadow']) + '\n', encoding='utf-8')
                all_packages = (*markers, ('tools/shadow/Cargo.toml', 'shadow'))
                for marker, name in all_packages:
                    path = other / marker
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('[package]\nname = "' + name
                                    + '"\nversion = "0.1.0"\nedition = "2024"\n',
                                    encoding='utf-8')
                    source = path.parent / 'src/lib.rs'
                    source.parent.mkdir()
                    source.write_text('', encoding='utf-8')
                subprocess.run(['cargo', 'generate-lockfile'], cwd=other,
                               check=True, capture_output=True)
                positive = self.invoke([self.driver, 'check'], other)
                self.assertEqual(positive.returncode, 0, positive.stderr)
                self.assert_calls(QUICK, other)
                self.log.unlink()

                (other / wrong_path).write_text(
                    '[package]\nname = "shadow"\nversion = "0.1.0"\nedition = "2024"\n',
                    encoding='utf-8')
                (other / 'tools/shadow/Cargo.toml').write_text(
                    '[package]\nname = "' + wrong_name
                    + '"\nversion = "0.1.0"\nedition = "2024"\n',
                    encoding='utf-8')
                subprocess.run(['cargo', 'generate-lockfile'], cwd=other,
                               check=True, capture_output=True)
                metadata = json.loads(subprocess.check_output(
                    ['cargo', 'metadata', '--no-deps', '--locked', '--format-version', '1'],
                    cwd=other, text=True))
                self.assertEqual(len(metadata['workspace_members']), 4)
                for marker, expected in markers:
                    manifest = other / marker
                    located = subprocess.run(
                        ['cargo', 'locate-project', '--workspace', '--message-format',
                         'plain', '--manifest-path', str(manifest)],
                        cwd=other, capture_output=True, text=True)
                    self.assertEqual(located.returncode, 0, located.stderr)
                    self.assertEqual(Path(located.stdout.strip()), other / 'Cargo.toml')
                    selected = subprocess.run(['cargo', 'pkgid', '--locked',
                                               '--manifest-path', str(manifest)],
                                              cwd=other, capture_output=True, text=True)
                    by_name = subprocess.run(['cargo', 'pkgid', '--locked',
                                              '--manifest-path', str(manifest), '-p', expected],
                                             cwd=other, capture_output=True, text=True)
                    self.assertEqual(selected.returncode, 0, selected.stderr)
                    self.assertEqual(by_name.returncode, 0, by_name.stderr)
                    self.assertEqual(selected.stdout == by_name.stdout, marker != wrong_path)
                result = self.invoke([self.driver, 'check'], other)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('not a Granary workspace', result.stderr)
                self.assert_calls([], ROOT)

    @unittest.skipUnless(os.name == 'posix', 'Unix child termination')
    def test_signalled_child(self):
        result = self.invoke([self.driver, 'check-full'], ROOT, SIGNAL_STEP='clippy')
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assert_calls(FULL[:2], ROOT)


@unittest.skipUnless(os.name == 'posix' and BASH is not None, 'requires Bash')
class ShimTests(ProbeCase):
    def test_dash_prefixed_relative_symlink_uses_target_checkout(self):
        shortcut_dir = self.scratch / '-tools'
        shortcut_dir.mkdir()
        (shortcut_dir / 'check-local.sh').symlink_to(CHECK)
        result = self.invoke([BASH, '--', '-tools/check-local.sh'], self.scratch,
                             PATH=str(self.bin) + os.pathsep + os.defpath,
                             FAIL_STEP='run')
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls([XTASK + ['check']], ROOT, check_warnings=False)

    def test_symlink_target_ending_newline_uses_target_checkout(self):
        shortcut = self.scratch / 'check-local.sh'
        second = self.scratch / 'trailing-newline\n'
        second.symlink_to(CHECK)
        shortcut.symlink_to(second.name)
        result = self.invoke([BASH, shortcut], self.scratch, FAIL_STEP='run',
                             PATH=str(self.bin) + os.pathsep + os.defpath)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls([XTASK + ['check']], ROOT, check_warnings=False)

    def test_symlink_readlink_failure_stops_before_cargo(self):
        shortcut = self.scratch / 'check-local.sh'
        shortcut.symlink_to(CHECK)
        readlink = self.scratch / 'readlink'
        readlink.write_text('#!/bin/sh\nexit 41\n', encoding='utf-8')
        readlink.chmod(0o755)
        result = self.invoke([BASH, shortcut], self.scratch,
                             PATH=str(self.scratch) + os.pathsep + str(self.bin))
        self.assertEqual(result.returncode, 41, result.stderr)
        self.assert_calls([], ROOT)

    def test_symlinked_script_uses_target_checkout(self):
        shortcut = self.scratch / 'check-local.sh'
        shortcut.symlink_to(CHECK)
        result = self.invoke([BASH, shortcut], self.scratch, FAIL_STEP='run',
                             PATH=str(self.bin) + os.pathsep + os.defpath)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls([XTASK + ['check']], ROOT, check_warnings=False)

    def test_relative_symlinked_script_uses_target_checkout(self):
        shortcut = self.scratch / 'check-local.sh'
        second = self.scratch / 'second-link.sh'
        second.symlink_to(os.path.relpath(CHECK, self.scratch))
        shortcut.symlink_to(second.name)
        result = self.invoke([BASH, shortcut], self.scratch, FAIL_STEP='run',
                             PATH=str(self.bin) + os.pathsep + os.defpath)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls([XTASK + ['check']], ROOT, check_warnings=False)

    def test_delegates_from_repo(self):
        marker = self.scratch / 'bash-invoked'
        wrapper = self.scratch / 'bash'
        wrapper.write_text('#!/bin/sh\nprintf "hit\\n" > "$BASH_MARKER"\n'
                           'exec "$CHECK_BASH" "$@"\n', encoding='utf-8')
        wrapper.chmod(0o755)
        result = self.invoke([CHECK], self.scratch, FAIL_STEP='run',
                             PATH=os.pathsep.join((str(self.scratch), str(self.bin), os.defpath)),
                             CHECK_BASH=BASH, BASH_MARKER=str(marker))
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertTrue(marker.is_file(), 'the shebang must resolve Bash from PATH')
        self.assertEqual(marker.read_text(encoding='utf-8'), 'hit\n')
        self.assert_calls([XTASK + ['check']], ROOT, check_warnings=False)

    def test_rejects_arguments(self):
        result = self.invoke([BASH, CHECK, 'check-full'], self.scratch,
                             PATH=str(self.bin) + os.pathsep + os.defpath)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr,
                         'Unexpected argument: check-full\nUsage: check-local.sh\n')
        self.assert_calls([], ROOT)

    def test_relative_path_cargo_available_after_cd(self):
        checkout = self.scratch / 'checkout'
        outside = self.scratch / 'outside'
        (checkout / 'scripts').mkdir(parents=True)
        (checkout / 'toolbin').mkdir()
        outside.mkdir()
        script = checkout / 'scripts' / 'check-local.sh'
        shutil.copyfile(CHECK, script)
        cargo = checkout / 'toolbin' / 'cargo'
        cargo.write_text('#!/bin/sh\nexec "$CHECK_PYTHON" -I "$CHECK_RECORDER" "$@"\n',
                         encoding='utf-8')
        cargo.chmod(0o755)
        result = self.invoke([BASH, script], outside, PATH='toolbin',
                             FAIL_STEP='run', PYTHONPATH=self.poison_pythonpath())
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_calls([XTASK + ['check']], checkout, check_warnings=False)

    def test_relative_path_cargo_missing_after_cd(self):
        checkout = self.scratch / 'checkout'
        outside = self.scratch / 'outside'
        (checkout / 'scripts').mkdir(parents=True)
        (outside / 'toolbin').mkdir(parents=True)
        script = checkout / 'scripts' / 'check-local.sh'
        shutil.copyfile(CHECK, script)
        cargo = outside / 'toolbin' / 'cargo'
        cargo.write_text('#!/bin/sh\nexit 23\n', encoding='utf-8')
        cargo.chmod(0o755)
        result = self.invoke([BASH, script], outside, PATH='toolbin')
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertEqual(result.stderr.rstrip('\n'),
                         'cargo is required. Install Rust with rustup and add Cargo to PATH.')
        self.assert_calls([], checkout)

    def test_historical_no_cargo_error(self):
        result = self.invoke([BASH, CHECK], self.scratch, PATH=str(self.scratch))
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertEqual(result.stderr.rstrip('\n'),
                         'cargo is required. Install Rust with rustup and add Cargo to PATH.')
        self.assert_calls([], ROOT)


if __name__ == '__main__':
    unittest.main()
