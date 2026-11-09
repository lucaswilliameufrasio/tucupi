"""Opt-in synthetic inherited cgroup descriptor probe; not a sandbox."""
import shutil
import subprocess
import uuid

from codex_systemd_escape_fixture import start, unchanged
from codex_systemd_main_fixture import show


INNER = r'''
import errno, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
before = pathlib.Path('/proc/self/cgroup').read_text()
try:
    path.write_text(str(os.getpid()))
except OSError as error:
    if error.errno != errno.EROFS:
        raise
else:
    raise RuntimeError('read-only pathname accepted write')
if sys.argv[3] in ('sanitized-all', 'parent-proc'):
    if os.readlink('/proc/self/fd/0') != '/dev/null':
        raise RuntimeError('synthetic stdin not replaced')
    for entry in pathlib.Path('/proc/self/fd').iterdir():
        try:
            link = os.readlink(entry)
        except FileNotFoundError:
            continue
        if link == str(path):
            raise RuntimeError('synthetic cgroup descriptor inherited')
    try:
        os.open('/proc/self/fd/3', os.O_WRONLY)
    except OSError as error:
        if error.errno not in (errno.ENOENT, errno.EBADF):
            raise
    else:
        raise RuntimeError('extra inherited descriptor accessible via proc')
    if pathlib.Path('/proc/self/cgroup').read_text() != before:
        raise RuntimeError('sanitized control changed membership')
    if sys.argv[3] == 'parent-proc':
        pid = os.getppid()
        found = False
        for _ in range(4):
            proc = pathlib.Path('/proc') / str(pid)
            if (proc / 'cgroup').read_text() != before:
                break
            for entry in (proc / 'fd').iterdir():
                try:
                    if os.readlink(entry) != str(path):
                        continue
                    found = True
                    reopened = os.open(entry, os.O_WRONLY)
                    try:
                        os.write(reopened, str(os.getpid()).encode())
                    finally:
                        os.close(reopened)
                    break
                except (FileNotFoundError, PermissionError):
                    continue
            if found and sys.argv[2] in pathlib.Path('/proc/self/cgroup').read_text().splitlines():
                print('parent proc fd: reopened fixture parent cgroup descriptor; synthetic process moved', flush=True)
                sys.exit(0)
            status = (proc / 'status').read_text().splitlines()
            pid = int(next(line.split()[1] for line in status if line.startswith('PPid:')))
            if pid <= 1:
                break
        print('parent proc fd: reopening bypass not observed in bounded ancestor search', flush=True)
        sys.exit(0)
    print('sanitized spawn: standard input replaced; extra cgroup fd closed', flush=True)
    sys.exit(0)
if sys.argv[3] == 'sanitized':
    try:
        os.write(0, str(os.getpid()).encode())
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
    else:
        raise RuntimeError('sanitized stdin unexpectedly writable')
    if pathlib.Path('/proc/self/cgroup').read_text() != before:
        raise RuntimeError('sanitized control changed membership')
    print('sanitized stdin: no inherited writable cgroup descriptor', flush=True)
    sys.exit(0)
os.write(0, str(os.getpid()).encode())
after = pathlib.Path('/proc/self/cgroup').read_text()
if before == after or sys.argv[2] not in after.splitlines():
    raise RuntimeError('inherited descriptor did not move synthetic process')
print('read-only path denied; inherited writable descriptor moved synthetic process', flush=True)
'''

WRAPPER = r'''
import os, subprocess, sys
bwrap, target, membership, inner, mode = sys.argv[1:]
fd = os.open(target if mode in ('inherited', 'sanitized-all', 'parent-proc') else '/dev/null',
             (os.O_WRONLY if mode in ('inherited', 'sanitized-all', 'parent-proc') else os.O_RDONLY) | os.O_CLOEXEC)
if fd != 0:
    os.dup2(fd, 0)
    os.close(fd)
os.set_inheritable(0, True)
if mode in ('sanitized-all', 'parent-proc'):
    os.dup2(0, 3, inheritable=True)
args = [bwrap, '--die-with-parent',
        '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
        '--ro-bind', '/lib64', '/lib64', '--ro-bind', '/sys/fs/cgroup', '/sys/fs/cgroup',
        '--proc', '/proc', '--dev', '/dev',
        '/usr/bin/python3', '-c', inner, target, membership, mode]
if mode in ('sanitized-all', 'parent-proc'):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, close_fds=True, env={}, timeout=8)
    sys.exit(result.returncode)
os.execve(bwrap, args, {})
'''


def main():
    bwrap = shutil.which('bwrap')
    if not bwrap:
        raise RuntimeError('bubblewrap unavailable; experiment not run')
    suffix = uuid.uuid4().hex
    target = 'tucupi-fd-target-' + suffix + '.service'
    target_info = None
    try:
        target_info = start(target, ['/usr/bin/sleep', '25'])
        unchanged(target, target_info)
        destination = '/sys/fs/cgroup' + target_info['ControlGroup'] + '/cgroup.procs'
        for mode, expected in (
            ('sanitized', 'sanitized stdin: no inherited writable cgroup descriptor'),
            ('sanitized-all', 'sanitized spawn: standard input replaced; extra cgroup fd closed'),
            ('parent-proc', 'parent proc fd:'),
            ('inherited', 'read-only path denied; inherited writable descriptor moved synthetic process'),
        ):
            source = 'tucupi-fd-' + mode + '-' + suffix + '.service'
            result = subprocess.run([
                'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect',
                '--unit', source, '--property=KillMode=control-group',
                '--property=RuntimeMaxSec=10', '--property=MemoryMax=128M', '--property=TasksMax=16',
                '/usr/bin/python3', '-c', WRAPPER, bwrap, destination,
                '0::' + target_info['ControlGroup'], INNER, mode,
            ], capture_output=True, text=True, timeout=20)
            if result.returncode != 0 or expected not in result.stdout:
                raise RuntimeError('descriptor probe failed or unsupported: ' + result.stderr[-1500:])
            unchanged(target, target_info)
            print(result.stdout.strip())
    finally:
        if target_info is not None:
            state = show(target)
            if state['InvocationID'] == target_info['InvocationID'] and state['ActiveState'] not in ('inactive', 'failed'):
                subprocess.run(['systemctl', '--user', 'stop', target], check=True, timeout=10)


if __name__ == '__main__':
    main()
