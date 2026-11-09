"""Compare synthetic direct-child interruption with and without the batch runtime."""
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time


def wait_for(predicate, name):
    deadline = time.monotonic() + 8
    while not predicate():
        if time.monotonic() >= deadline:
            raise RuntimeError(f"timeout waiting for {name}")
        time.sleep(.01)


def case(binary, exit_runtime, retain_fixture=False):
    with tempfile.TemporaryDirectory(prefix="tucupi-rollback-test-", dir=Path.home()) as directory:
        root = Path(directory)
        manifest = root / "Cargo.toml"
        manifest.write_text("synthetic-original\n")
        if exit_runtime:
            (root / "runtime-exit-mode").touch()
        executable = root / "cargo"
        executable.write_text("#!/usr/bin/python3\nimport os,pathlib,time\np=pathlib.Path('.')\n(p/'Cargo.toml').write_text('synthetic-modified\\n')\n(p/'pid').write_text(str(os.getpid()))\n(p/'ready').touch()\ntime.sleep(8)\n")
        executable.chmod(0o700)
        env = {"HOME": directory, "TMPDIR": directory, "PATH": directory}
        if retain_fixture:
            env["TUCUPI_RETAIN_BACKUP_CHILD"] = directory
            test_name = "batch::impact_tests::synthetic_retained_backup_survives_runtime_exit"
        else:
            env["TUCUPI_ROLLBACK_CHILD"] = directory
            test_name = "batch::impact_tests::synthetic_upgrade_interruption_backup_rollback_fixture"
        harness = subprocess.Popen([binary, "--exact", test_name], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pidfd = None
        try:
            wait_for(lambda: (root / "ready").exists() or harness.poll() is not None, "synthetic upgrade")
            if not (root / "ready").exists():
                raise RuntimeError("batch test exited before synthetic upgrade")
            pid = int((root / "pid").read_text())
            if pid <= 1:
                raise RuntimeError("invalid synthetic process identity")
            pidfd = os.pidfd_open(pid)
            if manifest.read_text() != "synthetic-modified\n":
                raise RuntimeError("synthetic mutation did not occur")
            snapshots = [path for path in root.glob(".tmp*/Cargo.toml") if path.read_text() == "synthetic-original\n"]
            if len(snapshots) != 1:
                raise RuntimeError("expected exactly one synthetic backup snapshot")
            if exit_runtime:
                (root / "exit-runtime").touch()
                if harness.wait(timeout=8) != 0:
                    raise RuntimeError("runtime-exit harness failed")
                if select.select([pidfd], [], [], 0)[0]:
                    raise RuntimeError("synthetic direct child exited prematurely")
                if not retain_fixture and snapshots[0].exists():
                    raise RuntimeError("synthetic snapshot unexpectedly survived runtime exit")
                if retain_fixture:
                    recorded = Path((root / "snapshot-path").read_text())
                    if recorded != snapshots[0].parent or snapshots[0].read_text() != "synthetic-original\n":
                        raise RuntimeError("retained synthetic backup is missing or inconsistent")
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            if not select.select([pidfd], [], [], 8)[0]:
                raise RuntimeError("synthetic direct child did not exit")
            if not exit_runtime and harness.wait(timeout=8) != 0:
                raise RuntimeError("live-runtime harness failed")
            observed = manifest.read_text()
            if exit_runtime:
                if observed != "synthetic-modified\n" or (root / "failure-observed").exists():
                    raise RuntimeError("unexpected rollback after runtime exit")
                if retain_fixture:
                    if snapshots[0].read_text() != "synthetic-original\n":
                        raise RuntimeError("synthetic retained snapshot changed")
                    print("fixture-only retained snapshot survives runtime exit; manifest remains modified and no restore ran")
                else:
                    print("runtime exited before child interruption: synthetic manifest remains modified; temporary snapshot removed")
            else:
                if observed != "synthetic-original\n" or not (root / "failure-observed").exists():
                    raise RuntimeError("live runtime did not restore the synthetic manifest")
                print("live runtime: interrupted child reported failure and synthetic manifest restored")
        finally:
            if harness.poll() is None:
                harness.kill()
                harness.wait()
            if pidfd is not None:
                if not select.select([pidfd], [], [], 0)[0]:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    select.select([pidfd], [], [], 8)
                os.close(pidfd)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[2] == "retain-fixture":
        case(sys.argv[1], True, True)
    else:
        case(sys.argv[1], False)
        case(sys.argv[1], True)
