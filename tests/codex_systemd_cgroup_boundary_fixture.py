"""Opt-in systemd ProtectControlGroups probe, not a production sandbox."""
import subprocess
import uuid

from codex_systemd_escape_fixture import start, unchanged
from codex_systemd_main_fixture import show


PROBE = r'''
import errno, os, pathlib, sys
destination = pathlib.Path(sys.argv[1])
protected = sys.argv[2] == 'protected'
before = pathlib.Path('/proc/self/cgroup').read_text()
try:
    destination.write_text(str(os.getpid()))
except OSError as error:
    if not protected:
        raise RuntimeError('unprotected control could not move') from error
    if error.errno not in (errno.EROFS, errno.EACCES, errno.EPERM):
        raise
    if pathlib.Path('/proc/self/cgroup').read_text() != before:
        raise RuntimeError('membership changed after denied write')
    print('synthetic self-move denied:', errno.errorcode[error.errno], flush=True)
else:
    if protected:
        raise RuntimeError('synthetic self-move unexpectedly succeeded')
    if pathlib.Path('/proc/self/cgroup').read_text() == before:
        raise RuntimeError('unprotected control membership did not change')
    print('unprotected synthetic self-move succeeded', flush=True)
'''


def main():
    suffix = uuid.uuid4().hex
    source = 'tucupi-protect-source-' + suffix + '.service'
    control = 'tucupi-protect-control-' + suffix + '.service'
    target = 'tucupi-protect-target-' + suffix + '.service'
    target_info = None
    try:
        target_info = start(target, ['/usr/bin/sleep', '25'])
        unchanged(target, target_info)
        destination = '/sys/fs/cgroup' + target_info['ControlGroup'] + '/cgroup.procs'
        control_result = subprocess.run([
            'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect',
            '--unit', control, '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=10', '--property=MemoryMax=128M', '--property=TasksMax=16',
            '/usr/bin/python3', '-c', PROBE, destination, 'control',
        ], capture_output=True, text=True, timeout=20)
        if control_result.returncode != 0 or 'unprotected synthetic self-move succeeded' not in control_result.stdout:
            raise RuntimeError('unprotected control failed: ' + control_result.stderr[-1000:])
        unchanged(target, target_info)
        print(control_result.stdout.strip())
        result = subprocess.run([
            'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect',
            '--unit', source, '--property=ProtectControlGroups=yes',
            '--property=KillMode=control-group', '--property=RuntimeMaxSec=10',
            '--property=MemoryMax=128M', '--property=TasksMax=16',
            '/usr/bin/python3', '-c', PROBE, destination, 'protected',
        ], capture_output=True, text=True, timeout=20)
        if result.returncode != 0 or 'synthetic self-move denied:' not in result.stdout:
            raise RuntimeError('boundary unavailable or probe failed: ' + result.stderr[-1000:])
        unchanged(target, target_info)
        print(result.stdout.strip())
        print('target fixture unit remained unchanged')
    finally:
        if target_info is not None:
            state = show(target)
            if state['InvocationID'] == target_info['InvocationID'] and state['ActiveState'] not in ('inactive', 'failed'):
                subprocess.run(['systemctl', '--user', 'stop', target], check=True, timeout=10)


if __name__ == '__main__':
    main()
