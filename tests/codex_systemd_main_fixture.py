"""Opt-in systemd user-unit crash experiment, not a production sandbox."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid


def show(unit):
    result = subprocess.run(
        ['systemctl', '--user', 'show', unit, '--property=MainPID,ControlGroup,InvocationID,ActiveState,KillMode'],
        check=True, capture_output=True, text=True, timeout=5,
    )
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def main():
    root = Path(__file__).resolve().parent.parent
    codex = shutil.which('codex')
    if not codex:
        raise RuntimeError('fixture CLI unavailable')
    unit = 'tucupi-main-test-' + uuid.uuid4().hex + '.service'
    invocation = None
    with tempfile.TemporaryDirectory(prefix='tucupi-main-', dir=Path.home()) as directory:
        directory = Path(directory)
        try:
            subprocess.run([
                'systemd-run', '--user', '--quiet', '--unit', unit,
                '--property=Delegate=yes', '--property=KillMode=control-group',
                '--property=RuntimeMaxSec=30', '--property=TimeoutStopSec=1',
                '--property=MemoryMax=512M', '--property=TasksMax=64',
                str(root / 'target/debug/examples/codex_protocol_fixture'),
                'owned-spawn-fixture', str(directory), str(Path(codex).parent),
                str(root / 'tests/codex_private_bridge_fixture.py'), 'systemd-main-aux',
            ], check=True, capture_output=True, text=True, timeout=10)
            info = show(unit)
            invocation = info['InvocationID']
            pid = int(info['MainPID'])
            group = info['ControlGroup']
            if not invocation or pid <= 1 or not group.endswith('/' + unit) or info['KillMode'] != 'control-group':
                raise RuntimeError('unexpected transient unit identity')
            deadline = time.monotonic() + 20
            while not (directory / 'request-in-flight').exists():
                if time.monotonic() >= deadline or show(unit)['ActiveState'] != 'active':
                    raise RuntimeError('synthetic request did not start')
                time.sleep(0.02)
            auxiliaries = [int((directory / name).read_text()) for name in ('watchdog-ready', 'custodian-ready')]
            if len(set([pid] + auxiliaries)) != 3 or any(child <= 1 for child in auxiliaries):
                raise RuntimeError('invalid synthetic process identities')
            pidfds = []
            try:
                for process_pid in [pid] + auxiliaries:
                    pidfds.append(os.pidfd_open(process_pid))
                current = show(unit)
                membership = Path(f'/proc/{pid}/cgroup').read_text().splitlines()
                if (current['InvocationID'] != invocation or int(current['MainPID']) != pid
                        or current['ControlGroup'] != group or f'0::{group}' not in membership):
                    raise RuntimeError('unit identity changed before signal')
                for child in auxiliaries:
                    status = Path(f'/proc/{child}/status').read_text().splitlines()
                    membership = Path(f'/proc/{child}/cgroup').read_text().splitlines()
                    if f'PPid:\t{pid}' not in status or f'0::{group}' not in membership:
                        raise RuntimeError('synthetic auxiliary identity mismatch')
                # Freeze the auxiliaries before killing the controller so neither
                # watchdog nor custodian can perform the cleanup being measured.
                for fd in pidfds[1:]:
                    signal.pidfd_send_signal(fd, signal.SIGSTOP)
                for child in auxiliaries:
                    deadline = time.monotonic() + 3
                    while True:
                        state = Path(f'/proc/{child}/status').read_text().splitlines()
                        if any(line.startswith('State:') and '\tT' in line for line in state):
                            break
                        if time.monotonic() >= deadline:
                            raise RuntimeError('auxiliary did not stop')
                        time.sleep(0.01)
                for fd in pidfds[1:]:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                signal.pidfd_send_signal(pidfds[0], signal.SIGKILL)
            finally:
                for fd in pidfds:
                    os.close(fd)
            deadline = time.monotonic() + 10
            group_path = Path('/sys/fs/cgroup') / group.lstrip('/')
            while time.monotonic() < deadline:
                state = show(unit)
                if state['InvocationID'] != invocation:
                    raise RuntimeError('unit invocation changed during cleanup')
                events = group_path / 'cgroup.events'
                if state['ActiveState'] in ('failed', 'inactive') and (not events.exists() or 'populated 0' in events.read_text().splitlines()):
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError('systemd unit cleanup not observed')
            time.sleep(7)
            if (directory / 'survived').exists():
                raise RuntimeError('detached synthetic descendant survived')
            if (directory / 'watchdog-stop-requested').exists() or (directory / 'custodian-stop-requested').exists():
                raise RuntimeError('an auxiliary requested cleanup')
            print('systemd MainPID and synthetic watchdog/custodian killed: unit stopped; cgroup empty or removed; late marker absent')
        finally:
            if invocation:
                try:
                    current = show(unit)
                    if current.get('InvocationID') == invocation and current.get('ActiveState') not in ('inactive', 'failed'):
                        subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)
                except subprocess.CalledProcessError as error:
                    raise RuntimeError('could not verify or stop fixture unit') from error


if __name__ == '__main__':
    main()
