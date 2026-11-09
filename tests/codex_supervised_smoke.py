"""Opt-in synthetic Codex smoke under transient user cgroups, not production.

Requires systemd user delegation, user/network namespaces, bwrap, ip and Codex.
The target and credentials are synthetic. Run after building the Rust fixture:
python3 tests/codex_supervised_smoke.py
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


WRAPPER = r'''#!/usr/bin/python3
import os, pathlib, signal, sys, time
child = os.fork()
if child == 0:
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    pathlib.Path('/scratch/descendant-started').write_text('synthetic')
    time.sleep(8)
    pathlib.Path('/scratch/descendant-survived').write_text('synthetic')
    os._exit(0)
os.execv('/codex-real', ['/codex-real'] + sys.argv[1:])
'''


def run_unit(binary, probe_dir=None, explicit_cancel=False, tasks_max=64, crash_main=False, missing_listener=False, crash_controller=False):
    unit = "tucupi-codex-test-" + uuid.uuid4().hex + ".service"
    script = Path(__file__).resolve().with_name("codex_isolated_smoke.py")
    command = [
        "systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect", "--unit", unit,
        "--property=MemoryMax=512M", f"--property=TasksMax={tasks_max}", "--property=CPUQuota=50%",
        "--property=TimeoutStopSec=1", "--property=KillMode=control-group",
        "--property=RuntimeMaxSec=" + ("3" if probe_dir and not explicit_cancel and not crash_main and not crash_controller else "30"),
        "--setenv=PYTHONUNBUFFERED=1", "--setenv=TUCUPI_VERIFY_CGROUP=1", "--setenv=TUCUPI_CODEX_FIXTURE_BINARY=" + binary,
    ]
    if probe_dir is not None:
        command.append("--setenv=TUCUPI_CANCEL_PROBE_DIR=" + str(probe_dir))
    if missing_listener:
        command.append("--setenv=TUCUPI_TEST_MISSING_LISTENER=1")
    command.extend(["/usr/bin/python3", str(script)])
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    finished = False
    try:
        if explicit_cancel or crash_main or crash_controller:
            deadline = time.monotonic() + 15
            while not ((probe_dir / "descendant-started").exists() and (probe_dir / "request-started").exists()):
                if process.poll() is not None or time.monotonic() >= deadline:
                    if process.poll() is None:
                        subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=10, check=False)
                    stdout, stderr = process.communicate(timeout=5)
                    raise RuntimeError(f"fixture did not reach cancellation point; exit={process.returncode}; stdout={stdout[-4000:]!r}; stderr={stderr[-4000:]!r}")
                time.sleep(0.05)
            if process.poll() is not None:
                raise RuntimeError("fixture exited before explicit cancellation")
            if crash_controller:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError("synthetic controller exited unexpectedly")
            if crash_main:
                subprocess.run(["systemctl", "--user", "kill", "--kill-whom=main", "--signal=SIGKILL", unit], capture_output=True, timeout=10, check=True)
            else:
                subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=10, check=True)
        stdout, stderr = process.communicate(timeout=45)
        # A failed client cannot prove that its service has stopped.
        finished = process.returncode == 0
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    finally:
        if not finished:
            # Only this unique transient fixture service is targeted.
            subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=10, check=False)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


def main():
    binary = shutil.which("codex")
    if binary is None:
        raise RuntimeError("codex CLI unavailable")
    binary = os.path.realpath(binary)
    listener = Path(__file__).resolve().parent.parent / "target/debug/examples/codex_transport_fixture"
    unit = "tucupi-codex-test-" + uuid.uuid4().hex + ".service"
    try:
        bad_limits = subprocess.run([
            "systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect", "--unit", unit,
            "--property=MemoryMax=512M", "--property=TasksMax=128", "--property=CPUQuota=50%",
            "--property=RuntimeMaxSec=5", "--setenv=TUCUPI_FIXTURE_VERIFY_CGROUP=1",
            "--setenv=TOKIO_WORKER_THREADS=2", str(listener), "1",
        ], text=True, capture_output=True, timeout=15, check=False)
    except subprocess.TimeoutExpired:
        subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=10, check=False)
        raise
    if bad_limits.returncode == 0 or bad_limits.stdout.strip() or "cgroup limit exceeds fixture policy" not in bad_limits.stderr:
        raise RuntimeError(f"Rust listener did not reject excessive cgroup limits: {bad_limits.stderr[-4000:]!r}")
    print("Rust listener rejected excessive cgroup limits before binding")
    unit = "tucupi-codex-test-" + uuid.uuid4().hex + ".service"
    try:
        wrong_group = subprocess.run([
            "systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect", "--unit", unit,
            "--property=MemoryMax=512M", "--property=TasksMax=64", "--property=CPUQuota=50%",
            "--property=RuntimeMaxSec=5", "--setenv=TUCUPI_FIXTURE_VERIFY_CGROUP=1",
            "--setenv=TUCUPI_FIXTURE_EXPECTED_CGROUP=/not-the-owned-cgroup",
            "--setenv=TOKIO_WORKER_THREADS=2", str(listener), "1",
        ], text=True, capture_output=True, timeout=15, check=False)
    except subprocess.TimeoutExpired:
        subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=10, check=False)
        raise
    if wrong_group.returncode == 0 or wrong_group.stdout.strip() or "cgroup membership mismatch" not in wrong_group.stderr:
        raise RuntimeError(f"Rust listener accepted incorrect cgroup membership: {wrong_group.stderr[-4000:]!r}")
    print("Rust listener rejected incorrect cgroup membership before binding")
    normal = run_unit(binary)
    if normal.returncode != 0 or "supervised cgroup limits verified" not in normal.stdout or "synthetic tool-call response rejected" not in normal.stdout:
        raise RuntimeError(f"supervised Codex synthetic flow failed; exit={normal.returncode}; stdout={normal.stdout[-4000:]!r}; stderr={normal.stderr[-4000:]!r}")
    print("supervised Codex synthetic flow passed; cgroup settings and sandbox membership verified")
    with tempfile.TemporaryDirectory(prefix="tucupi-codex-preflight-", dir=Path.home()) as directory:
        probe = Path(directory)
        fake_codex = probe / "codex"
        marker = probe / "launched"
        fake_codex.write_text("#!/usr/bin/python3\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('launched')\n")
        fake_codex.chmod(0o700)
        subprocess.run([str(fake_codex)], env={}, check=True, timeout=5)
        if not marker.is_file():
            raise RuntimeError("synthetic Codex launch control failed")
        marker.unlink()
        unavailable = run_unit(str(fake_codex), tasks_max=32)
        if unavailable.returncode == 0 or "fixture cgroup limits unavailable" not in unavailable.stderr:
            raise RuntimeError("incorrect cgroup limits were not rejected by the preflight")
        if marker.exists():
            raise RuntimeError("Codex launched despite incorrect cgroup limits")
        print("incorrect cgroup limits rejected before synthetic Codex launch")
        unavailable = run_unit(str(fake_codex), missing_listener=True)
        if unavailable.returncode == 0 or "NotADirectoryError" not in unavailable.stderr:
            raise RuntimeError(f"missing synthetic listener was not rejected: {unavailable.stderr[-4000:]!r}")
        if marker.exists():
            raise RuntimeError("Codex launched despite missing synthetic listener")
        print("missing listener rejected before synthetic Codex launch")
    with tempfile.TemporaryDirectory(prefix="tucupi-codex-cancel-", dir=Path.home()) as directory:
        probe = Path(directory)
        wrapper = probe / "wrapper"
        wrapper.write_text(WRAPPER)
        wrapper.chmod(0o700)
        started = time.monotonic()
        cancelled = run_unit(binary, probe)
        if cancelled.returncode == 0:
            raise RuntimeError("timed-out fixture unexpectedly succeeded")
        if not (probe / "descendant-started").exists() or not (probe / "request-started").exists():
            raise RuntimeError("Codex and its detached descendant did not reach the synthetic cancellation point")
        time.sleep(max(0, 10 - (time.monotonic() - started)))
        if (probe / "descendant-survived").exists():
            raise RuntimeError("synthetic Codex descendant survived timeout")
        print("timed-out Codex synthetic flow: detached descendant did not survive")
    with tempfile.TemporaryDirectory(prefix="tucupi-codex-stop-", dir=Path.home()) as directory:
        probe = Path(directory)
        wrapper = probe / "wrapper"
        wrapper.write_text(WRAPPER)
        wrapper.chmod(0o700)
        stopped = run_unit(binary, probe, explicit_cancel=True)
        if "synthetic tool-call response rejected" in stopped.stdout:
            raise RuntimeError("cancelled fixture reported a completed review")
        time.sleep(9)
        if (probe / "descendant-survived").exists():
            raise RuntimeError("synthetic Codex descendant survived explicit cancellation")
        print("explicitly stopped Codex synthetic flow: detached descendant did not survive")
    with tempfile.TemporaryDirectory(prefix="tucupi-codex-crash-", dir=Path.home()) as directory:
        probe = Path(directory)
        wrapper = probe / "wrapper"
        wrapper.write_text(WRAPPER)
        wrapper.chmod(0o700)
        crashed = run_unit(binary, probe, crash_main=True)
        if crashed.returncode == 0 or "synthetic tool-call response rejected" in crashed.stdout:
            raise RuntimeError("crashed fixture reported a completed review")
        time.sleep(9)
        if (probe / "descendant-survived").exists():
            raise RuntimeError("synthetic Codex descendant survived main process crash")
        print("killed fixture main during synthetic Codex request: detached descendant did not survive")
    with tempfile.TemporaryDirectory(prefix="tucupi-codex-controller-", dir=Path.home()) as directory:
        probe = Path(directory)
        wrapper = probe / "wrapper"
        wrapper.write_text(WRAPPER)
        wrapper.chmod(0o700)
        try:
            run_unit(binary, probe, crash_controller=True)
        except RuntimeError as error:
            if str(error) != "synthetic controller exited unexpectedly":
                raise
        else:
            raise RuntimeError("controller crash unexpectedly succeeded")
        time.sleep(9)
        if (probe / "descendant-survived").exists():
            raise RuntimeError("synthetic Codex descendant survived controller failure")
        print("fixture cleanup after controller failure: detached descendant did not survive")


if __name__ == "__main__":
    main()
