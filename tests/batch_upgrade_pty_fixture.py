"""Drive the test-only batch entry in an isolated Linux pseudoterminal."""
import os
import fcntl
from pathlib import Path
import select
import signal
import sys
import struct
import termios
import tempfile
import time


def run_case(binary, error_case):
    with tempfile.TemporaryDirectory(prefix="tucupi-upgrade-pty-", dir=Path.home()) as directory:
        root = Path(directory)
        program = root / "brew"
        program.write_text("#!/usr/bin/python3\nimport os,pathlib,time\np=pathlib.Path('.')\n(p/'worker-pid').write_text(str(os.getpid()))\nprint('synthetic-log',flush=True)\n(p/'started').touch()\nfor _ in range(500):\n if (p/'proceed').exists(): break\n time.sleep(.01)\n(p/'finished').touch()\n")
        program.chmod(0o700)
        pid, master = os.forkpty()
        if pid == 0:
            env = {"HOME": directory, "TMPDIR": directory, "PATH": directory, "TERM": "xterm", "LANG": "en_US.UTF-8", "TUCUPI_UPGRADE_PTY_CHILD": directory}
            os.execve(binary, [binary, "--exact", "batch::impact_tests::interactive_synthetic_upgrade_pty", "--nocapture"], env)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
        status = None
        worker_fd = None
        output = bytearray()

        def wait_for(predicate, label):
            deadline = time.monotonic() + 8
            while not predicate():
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"timeout waiting for {label}: {bytes(output[-2000:])!r}")
                if select.select([master], [], [], .05)[0]:
                    try:
                        output.extend(os.read(master, 16384))
                    except OSError:
                        pass

        try:
            wait_for(lambda: (root / "started").exists(), "synthetic worker")
            worker_fd = os.pidfd_open(int((root / "worker-pid").read_text()))
            os.write(master, b"l")
            wait_for(lambda: b"Upgrade Logs" in output, "logs popup")
            wait_for(lambda: b"synthetic-log" in output, "worker log")
            os.write(master, b"q")
            wait_for(lambda: b"Wait for the upgrade to finish" in output, "quit warning")
            if error_case:
                (root / "inject-error").touch()
                wait_for(lambda: (root / "result").exists(), "terminal failure result")
                text = (root / "result").read_text()
                if "synthetic terminal failure" not in text or "completion and recovery were not verified" not in text:
                    raise RuntimeError(f"missing terminal error or unknown-completion warning: {text!r}")
                (root / "proceed").touch()
            else:
                if (root / "result").exists():
                    raise RuntimeError("batch exited before synthetic worker finished")
                (root / "proceed").touch()
                wait_for(lambda: b"Upgrade Report" in output, "completion report")
                os.write(master, b"q")
                wait_for(lambda: (root / "result").exists(), "normal exit")
                if (root / "result").read_text() != "ok" or not (root / "finished").exists():
                    raise RuntimeError("completion was not preserved")
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                waited, candidate = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = candidate
                    break
                time.sleep(.02)
            if status is None or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                raise RuntimeError(f"test child failed: {status!r}")
            if not select.select([worker_fd], [], [], 6)[0]:
                raise RuntimeError("synthetic worker did not terminate")
        finally:
            (root / "proceed").touch()
            if status is None:
                try:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except ProcessLookupError:
                    pass
            if worker_fd is not None:
                select.select([worker_fd], [], [], 6)
                os.close(worker_fd)
            os.close(master)


def run_disconnect(binary):
    with tempfile.TemporaryDirectory(prefix="tucupi-upgrade-disconnect-", dir=Path.home()) as directory:
        root = Path(directory)
        program = root / "brew"
        program.write_text("#!/usr/bin/python3\nimport os,pathlib,time\np=pathlib.Path('.')\n(p/'worker-pid').write_text(str(os.getpid()))\n(p/'started').touch()\nfor _ in range(500):\n if (p/'proceed').exists(): break\n time.sleep(.01)\n(p/'finished').touch()\n")
        program.chmod(0o700)
        pid, master = os.forkpty()
        if pid == 0:
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            env = {"HOME": directory, "TMPDIR": directory, "PATH": directory, "TERM": "xterm", "LANG": "en_US.UTF-8", "TUCUPI_UPGRADE_PTY_CHILD": directory}
            os.execve(binary, [binary, "--exact", "batch::impact_tests::interactive_synthetic_upgrade_pty", "--nocapture"], env)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
        status = None
        worker_fd = None
        try:
            deadline = time.monotonic() + 8
            while not (root / "started").exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("synthetic worker did not start")
                if select.select([master], [], [], .05)[0]:
                    os.read(master, 16384)
            worker_fd = os.pidfd_open(int((root / "worker-pid").read_text()))
            os.close(master)
            master = None
            deadline = time.monotonic() + 2
            while not (root / "result").exists() and time.monotonic() < deadline:
                waited, candidate = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = candidate
                    break
                time.sleep(.01)
            if not (root / "result").exists():
                raise RuntimeError(f"batch did not return its warning after real PTY disconnect; test process status: {status!r}")
            text = (root / "result").read_text()
            if "completion and recovery were not verified" not in text or "os error" not in text:
                raise RuntimeError(f"missing unknown-completion warning: {text!r}")
            if not (root / "cursor-restore-failed").exists():
                raise RuntimeError("test did not exercise failed cursor restoration")
            if not (root / "backend-dropped").exists():
                raise RuntimeError("terminal backend was not dropped")
            if select.select([worker_fd], [], [], 0)[0]:
                raise RuntimeError("synthetic worker exited before the batch returned its warning")
            (root / "proceed").touch()
            deadline = time.monotonic() + 8
            while status is None and time.monotonic() < deadline:
                waited, candidate = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = candidate
                    break
                time.sleep(.02)
            # The Rust test harness itself can exit 101 after its own stdout is disconnected.
            if status is None or not os.WIFEXITED(status) or os.WEXITSTATUS(status) not in (0, 101):
                raise RuntimeError(f"disconnected test child failed: {status!r}")
            if not select.select([worker_fd], [], [], 6)[0]:
                raise RuntimeError("synthetic worker did not terminate")
            print("real PTY disconnect: warning returned; synthetic direct process exited; completion marker:", (root / "finished").exists())
        finally:
            (root / "proceed").touch()
            if status is None:
                try:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except ProcessLookupError:
                    pass
            if worker_fd is not None:
                select.select([worker_fd], [], [], 6)
                os.close(worker_fd)
            if master is not None:
                os.close(master)


if __name__ == "__main__":
    run_case(sys.argv[1], False)
    run_case(sys.argv[1], True)
    run_disconnect(sys.argv[1])
    print("batch PTY: logs quit blocked; completion and injected terminal failure verified")
