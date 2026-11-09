"""Opt-in systemd unit replacement and stale cgroup repopulation probe."""
import errno
import os
from pathlib import Path
import select
import signal
import subprocess
import time
import uuid

from codex_systemd_main_fixture import show


def start(unit):
    subprocess.run([
        'systemd-run', '--user', '--quiet', '--collect', '--unit', unit,
        '--property=Delegate=yes', '--property=KillMode=control-group',
        '--property=RuntimeMaxSec=25', '--property=TimeoutStopSec=1',
        '--property=MemoryMax=128M', '--property=TasksMax=16',
        '/usr/bin/sleep', '25',
    ], check=True, capture_output=True, text=True, timeout=10)
    state = show(unit)
    if (not state['InvocationID'] or int(state['MainPID']) <= 1
            or not state['ControlGroup'].endswith('/' + unit)
            or state['KillMode'] != 'control-group' or state['ActiveState'] != 'active'):
        raise RuntimeError('unexpected fixture unit identity')
    return state


def same_attempt(expected, current):
    return all(expected[key] == current[key] for key in ('InvocationID', 'MainPID', 'ControlGroup'))


def main():
    unit = 'tucupi-replace-test-' + uuid.uuid4().hex + '.service'
    owned = None
    old_dir = old_procs = old_pidfd = None
    try:
        original = start(unit)
        owned = original
        old_pid = int(original['MainPID'])
        group = Path('/sys/fs/cgroup') / original['ControlGroup'].lstrip('/')
        old_dir = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        old_procs = os.open('cgroup.procs', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=old_dir)
        old_pidfd = os.pidfd_open(old_pid)
        if not same_attempt(original, show(unit)) or f"0::{original['ControlGroup']}" not in Path(f'/proc/{old_pid}/cgroup').read_text().splitlines():
            raise RuntimeError('original fixture identity changed')
        subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)
        if not select.select([old_pidfd], [], [], 5)[0]:
            raise RuntimeError('original main process did not terminate')
        deadline = time.monotonic() + 5
        while group.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError('old fixture cgroup still exists')
            time.sleep(0.02)
        owned = None
        replacement = start(unit)
        owned = replacement
        if replacement['InvocationID'] == original['InvocationID'] or same_attempt(original, replacement):
            raise RuntimeError('replacement did not acquire a new invocation')
        if same_attempt(original, show(unit)):
            raise RuntimeError('stale attempt incorrectly accepted replacement')
        new_pid = int(replacement['MainPID'])
        new_pidfd = os.pidfd_open(new_pid)
        try:
            if not same_attempt(replacement, show(unit)) or f"0::{replacement['ControlGroup']}" not in Path(f'/proc/{new_pid}/cgroup').read_text().splitlines():
                raise RuntimeError('replacement fixture identity changed')
            try:
                os.write(old_procs, str(new_pid).encode())
            except OSError as error:
                if error.errno not in (errno.ENODEV, errno.ENOENT, errno.ESRCH, errno.EOPNOTSUPP):
                    raise
                print(f'old pinned cgroup rejected repopulation: {errno.errorcode[error.errno]}')
            else:
                raise RuntimeError('removed cgroup unexpectedly accepted repopulation')
            if select.select([new_pidfd], [], [], 0)[0] or not same_attempt(replacement, show(unit)):
                raise RuntimeError('replacement was disturbed')
            if f"0::{replacement['ControlGroup']}" not in Path(f'/proc/{new_pid}/cgroup').read_text().splitlines():
                raise RuntimeError('replacement process moved unexpectedly')
            print('same unit name: new invocation rejected by stale identity; replacement remains active')
            new_group = Path('/sys/fs/cgroup') / replacement['ControlGroup'].lstrip('/')
            subgroup = new_group / ('repopulate-' + uuid.uuid4().hex)
            subgroup.mkdir()
            try:
                if 'populated 0' not in (subgroup / 'cgroup.events').read_text().splitlines():
                    raise RuntimeError('new synthetic subgroup unexpectedly populated')
                if not same_attempt(replacement, show(unit)):
                    raise RuntimeError('replacement identity changed before repopulation')
                (subgroup / 'cgroup.procs').write_text(str(new_pid))
                if ('populated 1' not in (subgroup / 'cgroup.events').read_text().splitlines()
                        or f"0::{replacement['ControlGroup']}/{subgroup.name}" not in Path(f'/proc/{new_pid}/cgroup').read_text().splitlines()):
                    raise RuntimeError('synthetic subgroup repopulation not observed')
                if not same_attempt(replacement, show(unit)):
                    raise RuntimeError('replacement identity changed during repopulation')
                (new_group / 'cgroup.procs').write_text(str(new_pid))
                if 'populated 0' not in (subgroup / 'cgroup.events').read_text().splitlines():
                    raise RuntimeError('synthetic subgroup did not become empty again')
                print('live delegated subgroup: empty -> populated -> empty observed')
            finally:
                # Only remove our empty subgroup; the service stop handles any
                # remaining fixture processes if a preceding check fails.
                if subgroup.exists() and 'populated 0' in (subgroup / 'cgroup.events').read_text().splitlines():
                    subgroup.rmdir()
        finally:
            os.close(new_pidfd)
    finally:
        for fd in (old_pidfd, old_procs, old_dir):
            if fd is not None:
                os.close(fd)
        if owned is not None:
            current = show(unit)
            if current.get('InvocationID') == owned['InvocationID'] and current.get('ActiveState') not in ('inactive', 'failed'):
                subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)
            events = Path('/sys/fs/cgroup') / owned['ControlGroup'].lstrip('/') / 'cgroup.events'
            if current.get('InvocationID') == owned['InvocationID'] and events.exists() and 'populated 0' not in events.read_text().splitlines():
                raise RuntimeError('owned fixture unit cleanup not observed')


if __name__ == '__main__':
    main()
