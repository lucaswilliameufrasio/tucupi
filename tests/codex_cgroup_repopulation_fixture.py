"""Opt-in synthetic cgroup repopulation observation; never a production runner.

Requires a delegated systemd user unit and the codex_protocol_fixture example
built with codex-fixture. All children and the unit belong to this test.
"""
import pathlib
import subprocess
import uuid


WORKER = r'''
import pathlib, selectors, subprocess, sys
relative = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2]
group = pathlib.Path('/sys/fs/cgroup') / relative.lstrip('/') / 'tucupi-repopulation-test'
group.mkdir()
children = []
observer = None
def spawn_child():
    child = subprocess.Popen(['/usr/bin/sleep', '30'])
    children.append(child)
    (group / 'cgroup.procs').write_text(str(child.pid))
    return child
def expect(line):
    with selectors.DefaultSelector() as selector:
        selector.register(observer.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=3) or observer.stdout.readline().strip() != line:
            raise RuntimeError('unexpected synthetic observer state: ' + line)
try:
    first = spawn_child()
    observer = subprocess.Popen([sys.argv[1], 'observe-repopulation-fixture', str(group)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    expect('observed-populated')
    (group / 'cgroup.kill').write_text('1')
    first.wait(timeout=3)
    observer.stdin.write('empty\n')
    observer.stdin.flush()
    expect('observed-empty')
    second = spawn_child()
    observer.stdin.write('repopulated\n')
    observer.stdin.flush()
    stdout, stderr = observer.communicate(timeout=3)
    if observer.returncode != 0 or stdout.strip() != 'repopulation-rejected':
        raise RuntimeError('Rust observer did not reject repopulation: ' + stderr[-500:])
    (group / 'cgroup.kill').write_text('1')
    second.wait(timeout=3)
    print('synthetic quarantined review: populated -> empty -> repopulated rejected')
finally:
    if observer is not None and observer.poll() is None:
        observer.kill()
        observer.wait(timeout=3)
    (group / 'cgroup.kill').write_text('1')
    for child in children:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
    group.rmdir()
'''


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    binary = root / 'target/debug/examples/codex_protocol_fixture'
    unit = 'tucupi-repopulation-test-' + uuid.uuid4().hex + '.service'
    try:
        result = subprocess.run([
            'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', unit,
            '--property=Delegate=yes', '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=20', '--property=TimeoutStopSec=1',
            '--property=MemoryMax=128M', '--property=TasksMax=16',
            '/usr/bin/python3', '-c', WORKER, str(binary),
        ], capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0 or 'repopulated rejected' not in result.stdout:
            raise RuntimeError(f'synthetic repopulation fixture failed: {result.stderr[-2000:]}')
        print(result.stdout.strip())
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=10, check=False)


if __name__ == '__main__':
    main()
