"""Opt-in delegated fixture: inject a descriptor into the real Rust spawn path."""
from pathlib import Path
import subprocess
import tempfile
import uuid


WORKER = r'''
import os, pathlib, selectors, subprocess, sys, time
directory = pathlib.Path(sys.argv[1])
helper = sys.argv[2]
marker = directory / 'synthetic-descriptor'
marker.touch()
fd = os.open(marker, os.O_RDONLY)
script = directory / 'inspect-child.py'
script.write_text("import os,pathlib,time\np=pathlib.Path(%r)\ntry:\n x=os.readlink('/proc/self/fd/'+%r)\nexcept FileNotFoundError:\n x=''\np.joinpath('result').write_text('inherited' if x == %r else 'absent')\ntime.sleep(20)\n" % (str(directory), str(fd), str(marker)))
process = subprocess.Popen([helper, 'owned-spawn-fixture', str(directory), '/usr/bin', str(script)],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, env={}, pass_fds=(fd,))
try:
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=8) or process.stdout.readline().strip() != 'rust-created-admitted-before-worker-exec':
            raise RuntimeError('Rust fixture did not start')
    if os.readlink(f'/proc/{process.pid}/fd/{fd}') != str(marker):
        raise RuntimeError('descriptor was not inherited by Rust controller')
    deadline = time.monotonic() + 5
    while not (directory / 'result').exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('synthetic gated child did not report')
        time.sleep(0.01)
    if (directory / 'result').read_text() != 'absent':
        raise RuntimeError('synthetic descriptor leaked to gated child')
    stdout, stderr = process.communicate('cancel-fixture\n', timeout=8)
    if process.returncode != 0 or 'rust-cancelled-empty-pending' not in stdout:
        raise RuntimeError('fixture cancellation failed: ' + stderr[-1000:])
    print('real fixture spawn: controller held inherited fd; gated child did not; cancellation observed empty', flush=True)
finally:
    os.close(fd)
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)
'''


def main():
    root = Path(__file__).resolve().parent.parent
    helper = root / 'target/debug/examples/codex_protocol_fixture'
    unit = 'tucupi-real-fd-test-' + uuid.uuid4().hex + '.service'
    with tempfile.TemporaryDirectory(prefix='tucupi-real-fd-', dir=Path.home()) as directory:
        result = subprocess.run([
            'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', unit,
            '--property=Delegate=yes', '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=30', '--property=TimeoutStopSec=1',
            '--property=MemoryMax=128M', '--property=TasksMax=32',
            '/usr/bin/python3', '-c', WORKER, directory, str(helper),
        ], capture_output=True, text=True, timeout=40)
        expected = 'real fixture spawn: controller held inherited fd; gated child did not; cancellation observed empty'
        if result.returncode != 0 or expected not in result.stdout:
            raise RuntimeError('real fixture fd probe failed: ' + result.stderr[-1500:])
        print(expected)


if __name__ == '__main__':
    main()
