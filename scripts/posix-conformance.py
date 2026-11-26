#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Run pinned POSIX selections against a fresh authority-backed writable mount.

Linux root only. Work must be a new directory on ext4, xfs or btrfs, outside
the checkout. Raw logs, exit statuses and provenance are retained there.
"""

import argparse
import base64
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

spec = importlib.util.spec_from_file_location("results", Path(__file__).with_name("posix-results.py"))
results = importlib.util.module_from_spec(spec)
spec.loader.exec_module(results)
spec = importlib.util.spec_from_file_location("publication", Path(__file__).with_name("check-publish-restart.py"))
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)

# The selected cases use a pre-mounted TEST_DEV. Defer check's teardown
# of that mount until Granary can publish and unmount it on SIGTERM.
XFS_LOCAL_CONFIG = '''\
gran_posix_umount() {
    if [ "$#" -eq 1 ] && { [ "$1" = "$TEST_DEV" ] || [ "$1" = "$TEST_DIR" ]; }; then
        return 0
    fi
    command umount "$@"
}
export UMOUNT_PROG=gran_posix_umount
export -f gran_posix_umount
'''


# The armed unlink control starts a Python wrapper for every pjdfstest call,
# and its no-op unlink leaves files behind, so each case runs longer than its
# baseline. The measured slowdown was 1.20–1.54x, with chown/00.t cut off at
# assertion 1114 of 1280 at 100 s. A timed-out case still refuses.
CONTROL_SCALE = 1.5


def pjd_timeout(case, control):
    """Per-case pjdfstest budget in seconds, scaled for the armed control."""
    # chown/00.t's three timestamp sections sleep for 38, 19 and
    # 19 seconds across their seven file types, before syscall overhead.
    base = 150 if case == "chown/00.t" else 35
    return base * CONTROL_SCALE if control else base


def capture(command, *, cwd=None, env=None, timeout=35):
    return subprocess.run([str(v) for v in command], cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=True).stdout


def wait_case_group(pgid, case):
    # wait() reaps the leader only. A descendant in a FUSE syscall can still
    # hold the mount after SIGKILL is sent. Zombies have already closed it.
    deadline = time.monotonic() + 10
    while True:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        processes = capture(["ps", "-axo", "pgid=,stat="], timeout=2).decode().splitlines()
        if not any(group == str(pgid) and state[0] not in "ZX"
                   for group, state in (line.split() for line in processes)):
            return
        results.require(time.monotonic() < deadline, f"case-process-group-still-live: {case}")
        time.sleep(0.05)


def run_case(command, stem, *, cwd, env, timeout=35):
    start = time.monotonic()
    print(json.dumps(dict(event="case-start", case=stem.name, command=[str(v) for v in command],
                          date=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))), flush=True)
    with open(str(stem) + ".log", "wb") as log:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            rc = 124
    Path(str(stem) + ".rc").write_text(f"{rc}\n")
    wait_case_group(child.pid, stem.name)
    print(json.dumps(dict(event="duration", case=stem.name,
                          seconds=round(time.monotonic() - start, 3), rc=rc)), flush=True)


def collect_state(work):
    """Save closed writer journals, staging and immutable objects for replay."""
    try:
        with tarfile.open(work / "diagnostic-state.tar", "w") as archive:
            for name in ("writer-store", "cache"):
                results.require((work / name).is_dir(), f"diagnostic-state-unreadable: {name}")
                archive.add(work / name, arcname=name)
            files = sum(member.isfile() for member in archive.getmembers())
            results.require(files > 0, "diagnostic-state-empty")
    except (OSError, tarfile.TarError) as error:
        raise results.Refused(f"diagnostic-state-unreadable: {error}") from error
    print(json.dumps(dict(event="diagnostic-state", archive="diagnostic-state.tar", files=files)), flush=True)


def await_ready(child, predicate, label):
    until = time.monotonic() + 30
    while time.monotonic() < until:
        results.require(child.poll() is None, f"{label}-exited: {child.returncode}")
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise results.Refused(f"{label}-readiness-timeout")


def mount_holders(mount, proc=Path("/proc")):
    """Snapshot processes whose mount tables list a FUSE mount at this path."""
    try:
        entries = list(proc.iterdir())
    except OSError:
        return []
    mount_bytes = os.fsencode(mount)
    holders = []
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            table = (entry / "mountinfo").read_bytes()
            for line in table.splitlines():
                before, _, after = line.partition(b" - ")
                fields = before.split(b" ", 5)
                filesystem = after.split(b" ")
                if len(fields) != 6 or len(filesystem) != 3:
                    continue
                fstype = filesystem[0]
                if fstype != b"fuse" and not fstype.startswith(b"fuse."):
                    continue
                # Mountinfo fields 3 and 5 are the device and the escaped mountpoint.
                device = fields[2]
                target = re.sub(rb"\\(040|011|012|134)",
                                lambda escape: bytes([int(escape.group(1), 8)]), fields[4])
                if target != mount_bytes or not re.fullmatch(rb"[0-9]+:[0-9]+", device):
                    continue
                comm = (entry / "comm").read_text(encoding="utf-8", errors="replace")
                inode = (entry / "ns" / "mnt").stat().st_ino
                holders.append(dict(pid=int(entry.name), comm=comm.removesuffix("\n"),
                                    mount_namespace_inode=inode, device=device.decode("ascii")))
                break
        except OSError:
            # Processes can exit or become unreadable while /proc is scanned.
            continue
    return sorted(holders, key=lambda holder: holder["pid"])


def stop(child, label, *, mount=None, phase=None):
    if child.poll() is None:
        child.send_signal(signal.SIGTERM)
    deadline = time.monotonic() + 40
    try:
        try:
            rc = child.wait(timeout=1 if mount is not None else 40)
        except subprocess.TimeoutExpired:
            if mount is None:
                raise
            try:
                print(json.dumps(dict(event="slow-stop-holders", mountpoint=str(mount), phase=phase,
                                      holders=mount_holders(mount))), flush=True)
            except OSError:
                pass
            rc = child.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
        raise results.Refused(f"{label}-shutdown-timeout")
    # wait can reap a child that exited after the deadline during the scan.
    results.require(time.monotonic() <= deadline, f"{label}-shutdown-timeout")
    results.require(rc == 0, f"{label}-shutdown: {rc}")
    print(json.dumps(dict(event="shutdown", process=label, rc=rc)), flush=True)


def reap_mount(work):
    """Detach any mount left by a completed or refused daemon shutdown."""
    capture(["bash", Path(__file__).with_name("ci-mounts.sh"), "reap", "--under", work])


def certificate(work, name):
    capture(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:prime256v1", "-nodes", "-subj", f"/CN={name}",
             "-keyout", work / f"{name}.key", "-out", work / f"{name}.csr"])
    usage = "serverAuth" if name == "server" else "clientAuth"
    extensions = work / f"{name}.ext"
    extensions.write_text(f"extendedKeyUsage={usage}\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    capture(["openssl", "x509", "-req", "-in", work / f"{name}.csr", "-CA", work / "ca.pem",
             "-CAkey", work / "ca.key", "-CAcreateserial", "-days", "2", "-extfile", extensions,
             "-out", work / f"{name}.pem"])


def refusal_probes(mount, work):
    path = mount / "posix-refusal-probe"
    path.write_bytes(b"probe")
    records = []
    for name, operation in (
        ("utimens", lambda: os.utime(path, ns=(1, 1))),
        ("non-exec-chmod", lambda: os.chmod(path, 0o600)),
        ("exec-chmod", lambda: os.chmod(path, 0o755)),
    ):
        try:
            operation()
            got = "0"
            if name == "exec-chmod":
                got += f":{stat.S_IMODE(path.stat().st_mode):04o}"
        except OSError as error:
            got = "ENOTSUP" if error.errno == errno.ENOTSUP else errno.errorcode.get(error.errno, str(error.errno))
        records.append(dict(case=name, got=got))
    (work / "refusals.json").write_text(json.dumps(records) + "\n")
    path.unlink()


def device_node_probe(work, mount):
    observed = {}
    for location, directory in (("host", work), ("fuse", mount)):
        for kind, mode in (("block", stat.S_IFBLK), ("char", stat.S_IFCHR)):
            name = f"{location}-{kind}"
            path = directory / f"posix-device-probe-{kind}"
            try:
                os.mknod(path, mode | 0o600, os.makedev(1, 2))
            except OSError as error:
                observed[name] = ("ENOTSUP" if error.errno == errno.ENOTSUP
                                  else errno.errorcode.get(error.errno, str(error.errno)))
            else:
                observed[name] = "0"
                path.unlink()
    (work / "device-node-probe.json").write_text(json.dumps(observed) + "\n")
    print(json.dumps(dict(event="device-node-probe", **observed)), flush=True)


def require_unlink_noop(rows, work):
    anchor = next((row for row in rows if (row["suite"], row["case"], row["assertion"]) ==
                   ("pjdfstest", "unlink/00.t", 5)), None)
    witness = (work / "unlink-witness.jsonl").read_text().splitlines()
    results.require(witness and anchor is not None and anchor["status"] == "failed"
                    and anchor["detail"].endswith("expected ENOENT, got regular"),
                    "control-did-not-land")
    print(json.dumps(dict(event="unlink-noop-detected", assertion=5, witnesses=len(witness))), flush=True)


def exercise(args, work, env):
    capture(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=POSIX venue CA",
             "-days", "2", "-keyout", work / "ca.key", "-out", work / "ca.pem",
             "-addext", "basicConstraints=critical,CA:TRUE"])
    for name in ("server", "client"):
        certificate(work, name)
    # OpenSSL's standard Ed25519 PKCS#8 and SPKI encodings contain the raw
    # 32-byte seed and public key used by gran's signing-key files.
    private = capture(["openssl", "genpkey", "-algorithm", "ED25519", "-outform", "DER"])
    results.require(len(private) == 48 and private[:16].hex() == "302e020100300506032b657004220420",
                    "signing-key-encoding")
    (work / "signing.der").write_bytes(private)
    public = capture(["openssl", "pkey", "-inform", "DER", "-in", work / "signing.der",
                      "-pubout", "-outform", "DER"])
    results.require(len(public) == 44 and public[:12].hex() == "302a300506032b6570032100",
                    "signing-public-encoding")
    (work / "seed").write_bytes(private[-32:])
    (work / "seed.pub").write_bytes(public[-32:])
    root_key = "ed25519:" + public[-32:].hex()
    pem = capture(["openssl", "x509", "-in", work / "server.pem", "-pubkey", "-noout"])
    (work / "server.pub").write_bytes(pem)
    spki = capture(["openssl", "pkey", "-pubin", "-in", work / "server.pub", "-outform", "DER"])
    pin = "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode()
    for name in ("authority", "enrollment", "source", "mount", "pjdfstest", "xfstests"):
        (work / name).mkdir(mode=0o700)
    (work / "source" / "sentinel").write_text(work.name)
    capture([args.server, "initialise", "--state-dir", work / "authority", "--volume", "posix"])
    capture([args.server, "enrollment", "mint", "--dir", work / "enrollment",
             "--tenant", "posix", "--credential", work / "client.pem"])
    server_env = dict(env, GRANARY_AUTHORITY="single-process", GRANARY_AUTHORITY_VOLUMES="posix",
                      GRANARY_AUTHORITY_STATE_DIR=str(work / "authority"),
                      GRANARY_AUTHORITY_ENROLLMENT_DIR=str(work / "enrollment"),
                      GRANARY_AUTHORITY_CLIENT_CA=str(work / "ca.pem"),
                      GRANARY_AUTHORITY_VOLUME_POSIX_PUBLISHER_KEYS=root_key,
                      GRANARY_STORE="memory:", GRANARY_LISTEN="127.0.0.1:0",
                      GRANARY_TLS_CERT=str(work / "server.pem"), GRANARY_TLS_KEY=str(work / "server.key"))
    server_log = work / "server.log"
    mount = work / "mount"
    with server_log.open("wb") as log:
        server = subprocess.Popen([str(args.server)], env=server_env, stdout=log, stderr=log)
    daemon = phase = None
    deferred_shutdown = None
    try:
        def address():
            matches = []
            for line in server_log.read_text().splitlines():
                try:
                    fields = json.loads(line).get("fields", {})
                except ValueError:
                    continue
                if fields.get("message") == "listening":
                    matches.append(fields.get("addr", ""))
            return matches[0] if len(matches) == 1 and re.fullmatch(r"127\.0\.0\.1:\d+", matches[0]) else None

        endpoint = "https://" + await_ready(server, address, "authority")
        credentials = ["--endpoint", endpoint, "--pin", pin, "--key-seed", str(work / "seed"),
                       "--client-cert", str(work / "client.pem"), "--client-key", str(work / "client.key"),
                       "--credential-context", "posix"]
        capture([args.gran, "publish", work / "publish-store", work / "source", "posix", *credentials], env=env)

        def mounted():
            row = subprocess.run(["findmnt", "-rn", "-o", "SOURCE,FSTYPE", "--mountpoint", str(mount)],
                                 capture_output=True, text=True, timeout=5, check=False)
            results.require(row.returncode in {0, 1}, "mount-table-unreadable")
            return row.stdout.strip() in {"gran fuse", "gran fuse.gran"}

        def attach(label):
            nonlocal daemon, phase
            with (work / f"{label}.log").open("wb") as log:
                daemon = subprocess.Popen([str(args.gran), "--log-format", "json", "--log-filter",
                                           "info,granary_client::event=debug", "mount", "posix", str(mount), "--writable",
                                           "--foreground", "--root-key", root_key, "--cache-dir", str(work / "cache"),
                                           "--store-dir", str(work / "writer-store"), *credentials],
                                          env=env, stdout=log, stderr=log)
            phase = label
            await_ready(daemon, mounted, "mount")
            results.require(capture(["cat", mount / "sentinel"]).decode() == work.name, "sentinel-mismatch")
            print(json.dumps(dict(event="mounted", source="gran", writable=True, phase=label)), flush=True)

        attach("mount")
        refusal_probes(mount, work)
        if args.ci_exit:
            device_node_probe(work, mount)
        pjd = args.tools / "pjdfstest"
        if args.unlink_noop:
            baseline = results.read_results(args.baseline)
            anchor = next(row for row in baseline if (row["suite"], row["case"], row["assertion"]) ==
                          ("pjdfstest", "unlink/00.t", 5))
            results.require(anchor["status"] == "passed", "control-baseline-unlink-did-not-pass")
            shutil.copytree(pjd, work / "armed-pjdfstest")
            pjd = work / "armed-pjdfstest"
            (pjd / "pjdfstest").rename(pjd / "pjdfstest.real")
            shutil.copyfile(Path(__file__).with_name("posix-unlink-control.py"), pjd / "pjdfstest")
            (pjd / "pjdfstest").chmod(0o755)
            env = dict(env, POSIX_PJD_REAL=str(pjd / "pjdfstest.real"),
                       POSIX_UNLINK_WITNESS=str(work / "unlink-witness.jsonl"))
        for case in results.PJD:
            scratch = mount / ("pjd-" + case.replace("/", "-"))
            scratch.mkdir()
            stem = work / "pjdfstest" / case.replace("/", "-")
            shutil.copyfile(pjd / "tests" / case, str(stem) + ".source")
            run_case(["/bin/sh", str(pjd / "tests" / case)], stem,
                     cwd=scratch, env=env, timeout=pjd_timeout(case, args.unlink_noop))
        xfs_env = dict(env, TEST_DIR=str(mount), FSTYP="fuse", FUSE_SUBTYP="",
                       HOST_OPTIONS=str(work / "local.config"), USE_KMEMLEAK="no", TEST_DEV="gran")
        (work / "local.config").write_text(XFS_LOCAL_CONFIG)
        for index, case in enumerate(results.XFS):
            # run_case has drained its group. Finish the writer's shutdown
            # and verify detachment before attaching its store again.
            if index:
                try:
                    stop(daemon, "mount", mount=mount, phase=phase)
                except results.Refused as error:
                    if deferred_shutdown is None:
                        deferred_shutdown = error
                finally:
                    daemon = None
                    reap_mount(work)
                results.require(not mounted(), "mount-left-after-xfstests")
                attach("mount-" + case.replace("/", "-"))
            stem = work / "xfstests" / case.replace("/", "-")
            shutil.copyfile(args.tools / "xfstests" / "tests" / case, str(stem) + ".source")
            features = {"linux", xfs_env["FSTYP"]}
            mount_options = xfs_env.get("MOUNT_OPTIONS", "")
            if mount_options:
                features.update(mount_options.removeprefix("-o ").split(","))
            expected = results.xfs_expected_output(
                args.tools / "xfstests" / "tests", case, features)
            try:
                shutil.copyfile(expected, str(stem) + ".out")
            except OSError as error:
                raise results.Refused(
                    f"xfstests-evidence-unreadable: {case}: {error}") from error
            # The VM took up to 92s; CI reached the fifth iteration at the
            # 300s cutoff. Allow 480s for the slower venue and final cleanup.
            run_case(["./check", case], stem,
                     cwd=args.tools / "xfstests", timeout=480 if case == "generic/001" else 35,
                     env=dict(xfs_env, RESULT_BASE=str(work / ("xfs-" + stem.name))))
        rows = results.read_results(work)
        if args.unlink_noop:
            require_unlink_noop(rows, work)
        if deferred_shutdown is not None:
            raise deferred_shutdown
        return rows
    finally:
        try:
            pending = sys.exc_info()[0] is not None
            if daemon is not None:
                try:
                    stop(daemon, "mount", mount=mount, phase=phase)
                except results.Refused as error:
                    if not pending:
                        raise
                    print(json.dumps(dict(event="refused", reason=str(error))), file=sys.stderr)
                finally:
                    reap_mount(work)
            else:
                reap_mount(work)
        finally:
            pending = sys.exc_info()[0] is not None
            try:
                try:
                    stop(server, "authority")
                except Exception as error:
                    if not pending:
                        raise
                    print(json.dumps(dict(event="refused", reason=str(error))),
                          file=sys.stderr)
            finally:
                if (work / "mount.log").exists():
                    # Collection must run even on an incomplete shutdown, but
                    # a secondary collection error must preserve that refusal.
                    pending = sys.exc_info()[0] is not None
                    try:
                        collect_state(work)
                    except results.Refused as error:
                        if not pending:
                            raise
                        print(json.dumps(dict(event="refused", reason=str(error))), file=sys.stderr)


def report_verdict(args, rows, known):
    counts, reasons = results.verdict(rows, known, ci_exit=args.ci_exit, unlink_noop=args.unlink_noop)
    print(json.dumps(dict(event="counts", **counts)), flush=True)
    if args.ci_exit:
        results.require_device_reachability(args.work)
    if args.unlink_noop and "unexpected-failure" in reasons:
        print(json.dumps(dict(event="unlink-control-complete", assertion=5)), flush=True)
    results.require(not reasons, ", ".join(reasons))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tools", "work", "gran", "server"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--known", type=Path, default=Path(__file__).with_name("posix-known-failures.json"))
    parser.add_argument("--ci-exit", action="store_true", help="check the CI baseline against the VM record")
    parser.add_argument("--unlink-noop", action="store_true")
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    try:
        results.require(platform.system() == "Linux" and os.geteuid() == 0, "linux-root-required")
        results.require(re.fullmatch(r"[0-9a-f]{40}", args.revision), "revision-required")
        results.require(not args.unlink_noop or args.baseline is not None, "control-baseline-required")
        results.require(not (args.ci_exit and args.unlink_noop), "ci-exit-is-baseline-only")
        for name in ("tools", "gran", "server", "known"):
            setattr(args, name, getattr(args, name).resolve(strict=True))
        args.work = args.work.parent.resolve(strict=True) / args.work.name
        results.require(not args.work.is_relative_to(Path(__file__).resolve().parent.parent),
                        "work-directory-inside-repository")
        results.require(not args.work.exists(), "work-directory-must-be-new")
        # Reuse the publication venue's supported filesystem/kernel predicate.
        venue = publication.venue_evidence({"TMPDIR": str(args.work.parent)})
        publication.venue(venue)
        known = results.load_known(args.known)
        for suite, commit in (("pjdfstest", results.PJD_COMMIT), ("xfstests", results.XFS_COMMIT)):
            got = capture(["git", "-C", args.tools / suite, "rev-parse", "HEAD"]).decode().strip()
            results.require(got == commit, f"suite-pin: {suite}: {got}")
            capture(["git", "-C", args.tools / suite, "diff", "--exit-code", "HEAD"])
        os.umask(0o077)
        args.work.mkdir(mode=0o700)
        env = dict(PATH=os.environ["PATH"], HOME=str(args.work), LC_ALL="C", RUST_LOG="info")
        # A linked worktree's git directory lives outside its container bind.
        # The controller supplies HEAD alongside the retained dirty-tree diff.
        provenance = dict(event="provenance", revision=args.revision,
                          host=platform.node(), kernel=platform.release(), date=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          filesystem=venue["filesystem"], mount_options=venue["options"],
                          pjd=results.PJD_COMMIT, xfs=results.XFS_COMMIT,
                          selection=dict(pjdfstest=results.PJD, xfstests=results.XFS), unlink_noop=args.unlink_noop)
        (args.work / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
        print(json.dumps(provenance), flush=True)
        rows = exercise(args, args.work, env)
        report_verdict(args, rows, known)
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(event="refused", reason=str(error))), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
