"""Opt-in combined synthetic manager/cgroup/fd boundary experiment."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

from codex_systemd_escape_fixture import start, unchanged
from codex_systemd_main_fixture import show


PROBE = r'''
import errno, os, pathlib, socket, subprocess, sys, time
target, unit, fd, runtime, port, abstract, outer_net = sys.argv[1:]
if os.readlink('/proc/self/ns/net') == outer_net:
    raise RuntimeError('network namespace did not change')
before = pathlib.Path('/proc/self/cgroup').read_text()
try:
    inherited = os.readlink('/proc/self/fd/' + fd)
except FileNotFoundError:
    inherited = ''
if inherited == target:
    raise RuntimeError('supervisor descriptor inherited')
try:
    pathlib.Path(target).write_text(str(os.getpid()))
except OSError as error:
    if error.errno != errno.EROFS:
        raise
else:
    raise RuntimeError('cgroup pathname unexpectedly writable')
subprocess.run(['/usr/bin/systemctl', '--version'], check=True, capture_output=True, timeout=5)
env = {'XDG_RUNTIME_DIR': runtime, 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus'}
query = subprocess.run(['/usr/bin/systemctl', '--user', 'show', unit], env=env, capture_output=True, timeout=5)
if query.returncode == 0:
    raise RuntimeError('manager query unexpectedly succeeded')
for family, address in ((socket.AF_INET, ('127.0.0.1', int(port))), (socket.AF_UNIX, '\0' + abstract)):
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(1)
        try:
            sock.connect(address)
        except OSError:
            pass
        else:
            raise RuntimeError('synthetic external endpoint was reachable')
    finally:
        sock.close()
if pathlib.Path('/proc/self/cgroup').read_text() != before:
    raise RuntimeError('synthetic process membership changed')
pathlib.Path('/fixture/combined-result').write_text('fd absent; cgroup read-only; manager query denied; synthetic TCP and abstract socket denied')
time.sleep(6)
pathlib.Path('/fixture/combined-late').touch()
time.sleep(20)
'''

WORKER = r'''
import os, pathlib, selectors, socket, subprocess, sys, time, uuid
directory = pathlib.Path(sys.argv[1])
helper, bwrap, target, unit, probe, runtime = sys.argv[2:8]
crash_mode = len(sys.argv) > 8 and sys.argv[8] == 'crash'
control_env = {'XDG_RUNTIME_DIR': runtime, 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus'}
subprocess.run(['/usr/bin/systemctl', '--user', 'show', unit], env=control_env, check=True, capture_output=True, timeout=5)
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.bind(('127.0.0.1', 0))
tcp.listen(2)
port = tcp.getsockname()[1]
abstract = 'tucupi-synthetic-' + uuid.uuid4().hex
unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
unix.bind('\0' + abstract)
unix.listen(2)
for family, address, listener in ((socket.AF_INET, ('127.0.0.1', port), tcp), (socket.AF_UNIX, '\0' + abstract, unix)):
    with socket.socket(family, socket.SOCK_STREAM) as control:
        control.settimeout(2)
        control.connect(address)
        listener.settimeout(2)
        peer, _ = listener.accept()
        peer.close()
outer_net = os.readlink('/proc/self/ns/net')
fd = os.open(target, os.O_WRONLY)
script = directory / 'combined-child.py'
args = [bwrap, '--die-with-parent', '--unshare-net', '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
        '--ro-bind', '/lib64', '/lib64', '--ro-bind', '/sys/fs/cgroup', '/sys/fs/cgroup',
        '--proc', '/proc', '--dev', '/dev', '--bind', str(directory), '/fixture',
        '/usr/bin/python3', '-c', probe, target, unit, str(fd), runtime, str(port), abstract, outer_net]
script.write_text('import os\nos.execve(%r, %r, {})\n' % (bwrap, args))
command = [helper, 'owned-spawn-fixture', str(directory), '/usr/bin', str(script)]
if crash_mode:
    command.append('systemd-main-aux')
process = subprocess.Popen(command,
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, env={}, pass_fds=(fd,))
try:
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=8) or process.stdout.readline().strip() != 'rust-created-admitted-before-worker-exec':
            raise RuntimeError('Rust fixture did not start')
    if os.readlink(f'/proc/{process.pid}/fd/{fd}') != target:
        raise RuntimeError('controller did not hold synthetic cgroup descriptor')
    result = directory / 'combined-result'
    deadline = time.monotonic() + 8
    while not result.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('combined synthetic child did not report')
        time.sleep(0.02)
    if result.read_text() != 'fd absent; cgroup read-only; manager query denied; synthetic TCP and abstract socket denied':
        raise RuntimeError('unexpected combined synthetic result')
    for listener in (tcp, unix):
        listener.setblocking(False)
        try:
            peer, _ = listener.accept()
        except BlockingIOError:
            pass
        else:
            peer.close()
            raise RuntimeError('synthetic external listener received unexpected connection')
    if crash_mode:
        (directory / 'combined-controller-pid').write_text(str(process.pid))
        (directory / 'combined-crash-ready').touch()
        time.sleep(20)
        raise RuntimeError('crash test controller was not terminated')
    stdout, stderr = process.communicate('cancel-fixture\n', timeout=8)
    if process.returncode != 0 or 'rust-cancelled-empty-pending' not in stdout:
        raise RuntimeError('fixture cancellation failed: ' + stderr[-1000:])
    print('combined: manager query and synthetic TCP/abstract endpoints denied; controller fd absent; child group empty', flush=True)
finally:
    tcp.close()
    unix.close()
    os.close(fd)
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)
'''


def main():
    root = Path(__file__).resolve().parent.parent
    bwrap = shutil.which('bwrap')
    if not bwrap:
        raise RuntimeError('bubblewrap unavailable; experiment not run')
    suffix = uuid.uuid4().hex
    target_unit = 'tucupi-combined-target-' + suffix + '.service'
    source_unit = 'tucupi-combined-source-' + suffix + '.service'
    target_info = None
    with tempfile.TemporaryDirectory(prefix='tucupi-combined-', dir=Path.home()) as directory:
        try:
            target_info = start(target_unit, ['/usr/bin/sleep', '25'])
            unchanged(target_unit, target_info)
            target = '/sys/fs/cgroup' + target_info['ControlGroup'] + '/cgroup.procs'
            runtime = '/run/user/' + str(os.getuid())
            result = subprocess.run([
                'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', source_unit,
                '--property=Delegate=yes', '--property=KillMode=control-group',
                '--property=RuntimeMaxSec=20', '--property=TimeoutStopSec=1',
                '--property=MemoryMax=256M', '--property=TasksMax=32',
                '/usr/bin/python3', '-c', WORKER, directory,
                str(root / 'target/debug/examples/codex_protocol_fixture'), bwrap,
                target, target_unit, PROBE, runtime,
            ], capture_output=True, text=True, timeout=30)
            expected = 'combined: manager query and synthetic TCP/abstract endpoints denied; controller fd absent; child group empty'
            if result.returncode != 0 or expected not in result.stdout:
                raise RuntimeError('combined fixture failed: ' + result.stderr[-1500:])
            unchanged(target_unit, target_info)
            print(expected)
        finally:
            if target_info is not None:
                state = show(target_unit)
                if state['InvocationID'] == target_info['InvocationID'] and state['ActiveState'] not in ('inactive', 'failed'):
                    subprocess.run(['systemctl', '--user', 'stop', target_unit], check=True, timeout=10)


if __name__ == '__main__':
    main()
