"""Opt-in Linux cgroup memory enforcement experiment, not a production runner.

Runs an isolated synthetic allocator in a uniquely named transient user service.
The external observer reads only that service's cgroup. No Codex or real secrets.
"""

import pathlib
import subprocess
import tempfile
import time
import uuid


ALLOCATOR = r'''
import os, pathlib, sys, time
directory = pathlib.Path(sys.argv[1])
entry = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2]
group = pathlib.Path('/sys/fs/cgroup') / entry.lstrip('/')
assert int((group / 'memory.max').read_text()) == 128 * 1024 * 1024
(directory / 'group').write_text(str(group))
deadline = time.monotonic() + 10
while not (directory / 'start').exists():
    assert time.monotonic() < deadline
    time.sleep(0.01)
chunks = []
for _ in range(64):
    chunks.append(bytearray(4 * 1024 * 1024))
    time.sleep(0.01)
(directory / 'unlimited').write_text('allocation exceeded limit')
'''


def counters(path):
    return {key: int(value) for key, value in (line.split() for line in path.read_text().splitlines())}


def main():
    with tempfile.TemporaryDirectory(prefix='tucupi-memory-fixture-', dir=pathlib.Path.home()) as directory:
        scratch = pathlib.Path(directory)
        unit = 'tucupi-memory-test-' + uuid.uuid4().hex + '.service'
        command = [
            'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', unit,
            '--property=MemoryMax=128M', '--property=MemorySwapMax=0', '--property=TasksMax=8',
            '--property=RuntimeMaxSec=12', '--property=TimeoutStopSec=1',
            '--property=KillMode=control-group', '/usr/bin/python3', '-c', ALLOCATOR, str(scratch),
        ]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 8
            while not (scratch / 'group').exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('allocator did not initialize in the transient service')
                time.sleep(0.01)
            group = pathlib.Path((scratch / 'group').read_text())
            # Validate the observed path before reading. Never use it for cleanup.
            if group.name != unit or not group.is_relative_to('/sys/fs/cgroup'):
                raise RuntimeError('unexpected fixture cgroup')
            events = group / 'memory.events'
            before = counters(events)
            (scratch / 'start').write_text('start')
            observed = before
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    observed = counters(events)
                except FileNotFoundError:
                    break
                if observed.get('oom_kill', 0) > before.get('oom_kill', 0):
                    break
                time.sleep(0.001)
            stdout, stderr = process.communicate(timeout=15)
            if process.returncode == 0 or (scratch / 'unlimited').exists():
                raise RuntimeError('allocator unexpectedly exceeded the memory limit')
            if observed.get('oom_kill', 0) <= before.get('oom_kill', 0):
                raise RuntimeError(f'no cgroup OOM kill observed: before={before}, after={observed}, exit={process.returncode}, stdout={stdout!r}, stderr={stderr!r}')
            print(f"cgroup memory.max=128MiB; oom_kill {before['oom_kill']} -> {observed['oom_kill']}; allocator exit={process.returncode}")
        finally:
            if process.poll() is None:
                subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=5, check=False)
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == '__main__':
    main()
