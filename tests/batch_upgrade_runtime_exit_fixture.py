"""Observe two bounded synthetic processes after a batch test runtime exits."""
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time


def wait_for(predicate, label):
    deadline = time.monotonic() + 8
    while not predicate():
        if time.monotonic() >= deadline:
            raise RuntimeError(f"timeout waiting for {label}")
        time.sleep(.01)


def main():
    kill_on_drop = len(sys.argv) > 2 and sys.argv[2] == "kill-on-drop"
    with tempfile.TemporaryDirectory(prefix="tucupi-upgrade-exit-", dir=Path.home()) as directory:
        root = Path(directory)
        child_code = "import pathlib,time\np=pathlib.Path('.')\nfor _ in range(800):\n if (p/'release').exists(): break\n time.sleep(.01)\nelse: raise SystemExit(2)\n(p/'descendant-after').touch()\n"
        code = "#!/usr/bin/python3\nimport os,pathlib,subprocess,time\np=pathlib.Path('.')\nc=subprocess.Popen(['/usr/bin/python3','-c'," + repr(child_code) + "],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,env={})\n(p/'direct-pid').write_text(str(os.getpid()))\n(p/'descendant-pid').write_text(str(c.pid))\n(p/'ready').touch()\nfor _ in range(800):\n if (p/'release').exists(): break\n time.sleep(.01)\nelse: raise SystemExit(2)\n(p/'direct-after').touch()\n"
        program = root / "brew"
        program.write_text(code)
        program.chmod(0o700)
        env = {"HOME": directory, "TMPDIR": directory, "PATH": directory}
        if kill_on_drop:
            env["TUCUPI_KILL_DROP_CHILD"] = directory
            test_name = "batch::impact_tests::synthetic_kill_on_drop_runtime_exit_experiment"
        else:
            env["TUCUPI_UPGRADE_EXIT_CHILD"] = directory
            test_name = "batch::impact_tests::synthetic_batch_upgrade_runtime_exit_process_lifetimes"
        harness = subprocess.Popen([sys.argv[1], "--exact", test_name], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        fds = []
        try:
            wait_for(lambda: (root / "ready").exists() or harness.poll() is not None, "synthetic processes")
            if not (root / "ready").exists():
                raise RuntimeError("fixture exited before synthetic processes started")
            direct = int((root / "direct-pid").read_text())
            descendant = int((root / "descendant-pid").read_text())
            if direct <= 1 or descendant <= 1 or direct == descendant:
                raise RuntimeError("invalid synthetic process identities")
            status = Path(f"/proc/{descendant}/status").read_text()
            if f"PPid:\t{direct}\n" not in status:
                raise RuntimeError("synthetic process parentage mismatch")
            fds = [os.pidfd_open(direct), os.pidfd_open(descendant)]
            (root / "runtime-exit").touch()
            if harness.wait(timeout=8) != 0:
                raise RuntimeError("test runtime did not exit successfully")
            if kill_on_drop and not select.select([fds[0]], [], [], 8)[0]:
                raise RuntimeError("direct child survived kill-on-drop")
            alive = [not bool(select.select([fd], [], [], 0)[0]) for fd in fds]
            (root / "release").touch()
            for fd in fds:
                if not select.select([fd], [], [], 8)[0]:
                    raise RuntimeError("synthetic process did not exit")
            markers = [(root / name).exists() for name in ("direct-after", "descendant-after")]
            print(f"runtime exit: direct/descendant alive={alive}; post-exit markers={markers}")
            expected = ([False, True], [False, True]) if kill_on_drop else ([True, True], [True, True])
            if (alive, markers) != expected:
                raise RuntimeError("synthetic process lifetime differed from observed behavior")
        finally:
            (root / "release").touch()
            if harness.poll() is None:
                harness.kill()
                harness.wait()
            for fd in fds:
                select.select([fd], [], [], 8)
                os.close(fd)


if __name__ == "__main__":
    main()
