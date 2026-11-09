"""Opt-in systemd-user supervision experiment; not Tucupi's production runner.

Runs only synthetic processes in a uniquely named transient user service.
Requires a user systemd manager with delegated cgroup v2 controllers.
Run: python3 tests/codex_supervision_fixture.py
"""

import pathlib
import subprocess
import tempfile
import time
import uuid


WORKER = r'''
import errno, os, pathlib, signal, sys, time
mode, marker = sys.argv[1:]
entry = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2]
group = pathlib.Path('/sys/fs/cgroup') / entry.lstrip('/')
assert int((group / 'memory.max').read_text()) == 128 * 1024 * 1024
assert int((group / 'pids.max').read_text()) == 8
quota, period = (group / 'cpu.max').read_text().split()
assert quota != 'max' and int(quota) * 2 <= int(period)
if mode == 'control':
    child = os.fork()
    if child == 0:
        pathlib.Path(marker).write_text('synthetic')
        os._exit(0)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    print('control marker written', flush=True)
    sys.exit(0)
if mode == 'resources':
    def counters(name):
        return {key: int(value) for key, value in (line.split() for line in (group / name).read_text().splitlines())}
    before_cpu = counters('cpu.stat')
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        pass
    after_cpu = counters('cpu.stat')
    assert after_cpu['nr_throttled'] > before_cpu['nr_throttled'], 'CPU quota did not throttle'
    print('CPU throttling observed', flush=True)
    sys.exit(0)
if mode == 'crash':
    child = os.fork()
    if child == 0:
        os.setsid()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        pathlib.Path(marker + '.ready').write_text('synthetic')
        time.sleep(6)
        pathlib.Path(marker).write_text('survived')
        os._exit(0)
    deadline = time.monotonic() + 2
    while not pathlib.Path(marker + '.ready').exists():
        assert time.monotonic() < deadline
        time.sleep(0.01)
    print('synthetic supervisor exiting unexpectedly', flush=True)
    os._exit(42)
children = []
blocked = False
try:
    for _ in range(12):
        try:
            child = os.fork()
        except OSError as error:
            assert error.errno == errno.EAGAIN
            blocked = True
            break
        if child == 0:
            time.sleep(10)
            os._exit(0)
        children.append(child)
finally:
    for child in children:
        os.kill(child, signal.SIGKILL)
    for child in children:
        os.waitpid(child, 0)
assert blocked, 'pids limit not enforced'
child = os.fork()
if child == 0:
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(6)
    pathlib.Path(marker).write_text('survived')
    os._exit(0)
print('limits verified; descendant started', flush=True)
os.waitpid(child, 0)
'''


def run_service(mode, marker):
    unit = "tucupi-fixture-" + uuid.uuid4().hex + ".service"
    command = [
        "systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect",
        "--unit", unit, "--property=MemoryMax=128M", "--property=TasksMax=8",
        "--property=CPUQuota=50%", "--property=RuntimeMaxSec=" + ("10" if mode == "resources" else "3"),
        "--property=TimeoutStopSec=1", "--property=KillMode=control-group",
        "/usr/bin/python3", "-c", WORKER, mode, str(marker),
    ]
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=12, check=False)
    except subprocess.TimeoutExpired:
        # This exact, randomly named unit is the only unit this test created.
        subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=5, check=False)
        raise


def main():
    with tempfile.TemporaryDirectory(prefix="tucupi-supervision-", dir=pathlib.Path.home()) as directory:
        marker = pathlib.Path(directory) / "synthetic-marker"
        control = run_service("control", marker)
        if control.returncode != 0 or not marker.is_file():
            raise RuntimeError("transient service or positive control unavailable")
        marker.unlink()
        resources = run_service("resources", marker)
        if resources.returncode != 0 or "CPU throttling observed" not in resources.stdout:
            raise RuntimeError(f"resource enforcement test failed: stdout={resources.stdout!r}, stderr={resources.stderr!r}")
        print("CPU quota throttled synthetic load")
        started = time.monotonic()
        crashed = run_service("crash", marker)
        if crashed.returncode == 0 or "synthetic supervisor exiting unexpectedly" not in crashed.stdout or not pathlib.Path(str(marker) + ".ready").exists():
            raise RuntimeError("synthetic supervisor crash scenario did not start")
        time.sleep(max(0, 7 - (time.monotonic() - started)))
        if marker.exists():
            raise RuntimeError("detached descendant survived synthetic supervisor crash")
        print("synthetic service main crashed; systemd cleaned up its detached descendant")
        started = time.monotonic()
        cancelled = run_service("cancel", marker)
        if cancelled.returncode == 0 or "limits verified; descendant started" not in cancelled.stdout:
            raise RuntimeError("resource preflight or runtime cancellation failed")
        time.sleep(max(0, 7 - (time.monotonic() - started)))
        if marker.exists():
            raise RuntimeError("detached synthetic descendant survived cancellation")
        print("cgroup limits: memory=128MiB, pids=8, cpu<=50%; pids limit enforced")
        print("positive control wrote marker; timed-out service and detached descendant did not")


if __name__ == "__main__":
    main()
