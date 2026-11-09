"""Opt-in impact preview experiment, not a production supervisor."""
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time
import uuid

from codex_systemd_main_fixture import show


def main():
    root = Path(__file__).resolve().parent.parent
    helper = root / 'target/debug/examples/codex_protocol_fixture'
    unit = 'tucupi-impact-boundary-' + uuid.uuid4().hex + '.service'
    info = None
    with tempfile.TemporaryDirectory(prefix='tucupi-impact-boundary-', dir=Path.home()) as directory:
        directory = Path(directory)
        state = directory / 'state'
        state.mkdir(mode=0o700)
        try:
            marker = subprocess.run([str(helper), 'recovery-marker-arm-identity', str(state)],
                                    env={}, capture_output=True, text=True, timeout=5)
            if marker.returncode != 0 or marker.stdout.strip() != 'fixture-marker-armed':
                raise RuntimeError('synthetic recovery marker not persisted')
            subprocess.run([
                'systemd-run', '--user', '--quiet', '--unit', unit,
                '--property=KillMode=control-group', '--property=RuntimeMaxSec=25',
                '--property=TimeoutStopSec=1', '--property=MemoryMax=128M', '--property=TasksMax=16',
                '/usr/bin/env', '-i', 'HOME=' + str(directory), 'PATH=/usr/bin:/bin',
                str(helper), 'impact-systemd-fixture', str(directory),
            ], check=True, capture_output=True, text=True, timeout=10)
            info = show(unit)
            pid = int(info['MainPID'])
            group = info['ControlGroup']
            if pid <= 1 or not info['InvocationID'] or not group.endswith('/' + unit) or info['KillMode'] != 'control-group':
                raise RuntimeError('synthetic unit identity invalid')
            deadline = time.monotonic() + 8
            while not all((directory / name).exists() for name in ('child-ready', 'worker-pid', 'child-pid')):
                if time.monotonic() >= deadline or show(unit)['ActiveState'] != 'active':
                    raise RuntimeError('synthetic preview did not start')
                time.sleep(0.01)
            worker = int((directory / 'worker-pid').read_text())
            child = int((directory / 'child-pid').read_text())
            if len({pid, worker, child}) != 3 or min(pid, worker, child) <= 1:
                raise RuntimeError('invalid fixture process identities')
            pidfds = []
            try:
                for value in (pid, worker, child):
                    pidfds.append(os.pidfd_open(value))
                current = show(unit)
                if any(current[key] != info[key] for key in ('InvocationID', 'MainPID', 'ControlGroup')):
                    raise RuntimeError('synthetic unit changed')
                for value, parent in ((worker, pid), (child, worker)):
                    status = Path(f'/proc/{value}/status').read_text().splitlines()
                    membership = Path(f'/proc/{value}/cgroup').read_text().splitlines()
                    if f'PPid:\t{parent}' not in status or f'0::{group}' not in membership:
                        raise RuntimeError('synthetic preview process identity mismatch')
                signal.pidfd_send_signal(pidfds[0], signal.SIGKILL)
                deadline = time.monotonic() + 8
                events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
                while time.monotonic() < deadline:
                    current = show(unit)
                    if current['InvocationID'] != info['InvocationID']:
                        raise RuntimeError('synthetic unit invocation changed')
                    if current['ActiveState'] in ('inactive', 'failed') and (not events.exists() or 'populated 0' in events.read_text().splitlines()):
                        break
                    time.sleep(0.02)
                else:
                    raise RuntimeError('synthetic unit cleanup not observed')
                for fd in pidfds:
                    if not select.select([fd], [], [], 5)[0]:
                        raise RuntimeError('synthetic process exit not observed')
            finally:
                for fd in pidfds:
                    os.close(fd)
            time.sleep(6)
            if (directory / 'late').exists():
                raise RuntimeError('synthetic detached child survived unit termination')
            restarted = subprocess.run([str(helper), 'app-fixture-recovery-check', str(state)],
                                       env={}, capture_output=True, text=True, timeout=5)
            if restarted.returncode != 0 or restarted.stdout.strip() != 'app-fixture-blocked':
                raise RuntimeError('new fixture App did not retain marker block')
            unavailable = subprocess.run([str(helper), 'app-fixture-recovery-check', str(state / 'missing')],
                                         env={}, capture_output=True, text=True, timeout=5)
            if unavailable.returncode != 0 or unavailable.stdout.strip() != 'app-fixture-blocked':
                raise RuntimeError('unavailable fixture state did not block')
            print('synthetic preview: systemd stopped worker and detached child; late marker absent')
            print('separate fixture App: persisted marker and unavailable state both block')
        finally:
            if info is not None:
                current = show(unit)
                if current.get('InvocationID') == info['InvocationID'] and current.get('ActiveState') not in ('inactive', 'failed'):
                    subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)


if __name__ == '__main__':
    main()
