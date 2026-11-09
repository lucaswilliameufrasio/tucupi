"""Opt-in same-user systemd bus authority probe against one synthetic unit."""
import os
from pathlib import Path
import select
import subprocess
import uuid

from codex_systemd_escape_fixture import start, unchanged
from codex_systemd_main_fixture import show


PROBE = r'''
import errno, os, pathlib, subprocess, sys
unit, invocation, pid, group = sys.argv[1:]
if not unit.startswith('tucupi-bus-target-') or not unit.endswith('.service') or not group.endswith('/' + unit):
    raise RuntimeError('invalid synthetic target')
result = subprocess.run(['/usr/bin/systemctl', '--user', 'show', unit,
                         '--property=InvocationID,MainPID,ControlGroup,ActiveState'],
                        check=True, capture_output=True, text=True, timeout=5)
values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
if (values.get('InvocationID') != invocation or values.get('MainPID') != pid
        or values.get('ControlGroup') != group or values.get('ActiveState') != 'active'):
    raise RuntimeError('synthetic unit identity changed')
path = pathlib.Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.procs'
try:
    path.write_text(str(os.getpid()))
except OSError as error:
    if error.errno != errno.EROFS:
        raise
else:
    raise RuntimeError('protected cgroup path unexpectedly writable')
subprocess.run(['/usr/bin/systemctl', '--user', 'stop', unit],
               check=True, capture_output=True, text=True, timeout=8)
print('protected cgroup path denied; user manager stopped verified synthetic target', flush=True)
'''


def main():
    suffix = uuid.uuid4().hex
    target = 'tucupi-bus-target-' + suffix + '.service'
    source = 'tucupi-bus-source-' + suffix + '.service'
    restricted = 'tucupi-bus-hidden-' + suffix + '.service'
    restricted_both = 'tucupi-bus-hidden-both-' + suffix + '.service'
    target_info = None
    pidfd = None
    try:
        target_info = start(target, ['/usr/bin/sleep', '25'])
        unchanged(target, target_info)
        pidfd = os.pidfd_open(int(target_info['MainPID']))
        runtime = '/run/user/' + str(os.getuid())
        if not Path(runtime, 'bus').exists():
            raise RuntimeError('user bus unavailable; boundary not tested')
        hidden = subprocess.run([
            'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', restricted,
            '--property=ProtectControlGroups=yes', '--property=InaccessiblePaths=' + runtime + '/bus',
            '--property=KillMode=control-group', '--property=RuntimeMaxSec=10',
            '--property=MemoryMax=128M', '--property=TasksMax=16',
            '--setenv=XDG_RUNTIME_DIR=' + runtime,
            '--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=' + runtime + '/bus',
            '/usr/bin/python3', '-c',
            "import subprocess,sys; r=subprocess.run(['/usr/bin/systemctl','--user','show',sys.argv[1]],capture_output=True,timeout=5); print('hidden bus: manager query denied' if r.returncode else 'hidden bus: manager query still succeeded')",
            target,
        ], capture_output=True, text=True, timeout=20)
        if hidden.returncode != 0 or 'hidden bus:' not in hidden.stdout:
            raise RuntimeError('hidden bus control failed: ' + hidden.stdout[-1000:] + hidden.stderr[-1000:])
        unchanged(target, target_info)
        print(hidden.stdout.strip() + '; synthetic target remained active')
        both = subprocess.run([
            'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', restricted_both,
            '--property=ProtectControlGroups=yes',
            '--property=InaccessiblePaths=' + runtime + '/bus ' + runtime + '/systemd/private',
            '--property=KillMode=control-group', '--property=RuntimeMaxSec=10',
            '--property=MemoryMax=128M', '--property=TasksMax=16',
            '--setenv=XDG_RUNTIME_DIR=' + runtime,
            '--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=' + runtime + '/bus',
            '/usr/bin/python3', '-c',
            "import subprocess,sys; r=subprocess.run(['/usr/bin/systemctl','--user','show',sys.argv[1]],capture_output=True,timeout=5); print('both sockets: manager query denied' if r.returncode else 'both sockets: unexpected access'); sys.exit(0 if r.returncode else 1)",
            target,
        ], capture_output=True, text=True, timeout=20)
        if both.returncode != 0 or 'both sockets: manager query denied' not in both.stdout:
            raise RuntimeError('hidden sockets control failed: ' + both.stdout[-1000:] + both.stderr[-1000:])
        unchanged(target, target_info)
        print('both sockets: manager query denied; synthetic target remained active')
        result = subprocess.run([
            'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', source,
            '--property=ProtectControlGroups=yes', '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=15', '--property=MemoryMax=128M', '--property=TasksMax=16',
            '--setenv=XDG_RUNTIME_DIR=' + runtime,
            '--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=' + runtime + '/bus',
            '/usr/bin/python3', '-c', PROBE, target, target_info['InvocationID'],
            target_info['MainPID'], target_info['ControlGroup'],
        ], capture_output=True, text=True, timeout=25)
        expected = 'protected cgroup path denied; user manager stopped verified synthetic target'
        if result.returncode != 0 or expected not in result.stdout:
            raise RuntimeError('bus probe blocked or unavailable: ' + result.stderr[-1500:])
        if not select.select([pidfd], [], [], 5)[0]:
            raise RuntimeError('target process termination not observed')
        state = show(target)
        events = Path('/sys/fs/cgroup') / target_info['ControlGroup'].lstrip('/') / 'cgroup.events'
        collected = not state.get('InvocationID') and not events.exists()
        stopped = (state.get('InvocationID') == target_info['InvocationID']
                   and state.get('ActiveState') in ('inactive', 'failed')
                   and (not events.exists() or 'populated 0' in events.read_text().splitlines()))
        if not (collected or stopped):
            raise RuntimeError('target unit state or invocation unexpected')
        print(expected)
        print('synthetic target termination verified by pidfd')
    finally:
        if pidfd is not None:
            os.close(pidfd)
        if target_info is not None:
            state = show(target)
            if state['InvocationID'] == target_info['InvocationID'] and state['ActiveState'] not in ('inactive', 'failed'):
                subprocess.run(['systemctl', '--user', 'stop', target], check=True, timeout=10)


if __name__ == '__main__':
    main()
