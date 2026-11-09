"""Opt-in systemd crash test of the synthetic combined boundary."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

from codex_combined_boundary_fixture import PROBE, WORKER
from codex_systemd_escape_fixture import start, unchanged
from codex_systemd_main_fixture import show


def main():
    root = Path(__file__).resolve().parent.parent
    bwrap = shutil.which('bwrap')
    if not bwrap:
        raise RuntimeError('bubblewrap unavailable; experiment not run')
    suffix = uuid.uuid4().hex
    target_unit = 'tucupi-combined-crash-target-' + suffix + '.service'
    source_unit = 'tucupi-main-test-' + suffix + '.service'
    target_info = source_info = None
    with tempfile.TemporaryDirectory(prefix='tucupi-combined-crash-', dir=Path.home()) as directory:
        directory = Path(directory)
        try:
            target_info = start(target_unit, ['/usr/bin/sleep', '25'])
            unchanged(target_unit, target_info)
            target = '/sys/fs/cgroup' + target_info['ControlGroup'] + '/cgroup.procs'
            runtime = '/run/user/' + str(os.getuid())
            subprocess.run([
                'systemd-run', '--user', '--quiet', '--unit', source_unit,
                '--property=Delegate=yes', '--property=KillMode=control-group',
                '--property=RuntimeMaxSec=20', '--property=TimeoutStopSec=1',
                '--property=MemoryMax=256M', '--property=TasksMax=32',
                '/usr/bin/python3', '-c', WORKER, str(directory),
                str(root / 'target/debug/examples/codex_protocol_fixture'), bwrap,
                target, target_unit, PROBE, runtime, 'crash',
            ], check=True, capture_output=True, text=True, timeout=10)
            source_info = show(source_unit)
            main_pid = int(source_info['MainPID'])
            group = source_info['ControlGroup']
            if (main_pid <= 1 or not source_info['InvocationID'] or not group.endswith('/' + source_unit)
                    or source_info['KillMode'] != 'control-group'):
                raise RuntimeError('unexpected synthetic source identity')
            deadline = time.monotonic() + 12
            while not (directory / 'combined-crash-ready').exists():
                if time.monotonic() >= deadline or show(source_unit)['ActiveState'] != 'active':
                    raise RuntimeError('combined synthetic crash fixture not ready')
                time.sleep(0.01)
            controller = int((directory / 'combined-controller-pid').read_text())
            watchdog = int((directory / 'watchdog-ready').read_text())
            custodian = int((directory / 'custodian-ready').read_text())
            pids = [main_pid, controller, watchdog, custodian]
            if len(set(pids)) != 4 or any(pid <= 1 for pid in pids):
                raise RuntimeError('invalid synthetic process identities')
            pidfds = []
            try:
                for pid in pids:
                    pidfds.append(os.pidfd_open(pid))
                unchanged(source_unit, source_info)
                unchanged(target_unit, target_info)
                for index, pid in enumerate(pids):
                    status = Path(f'/proc/{pid}/status').read_text().splitlines()
                    membership = Path(f'/proc/{pid}/cgroup').read_text().splitlines()
                    expected_parent = main_pid if index == 1 else controller
                    if f'0::{group}' not in membership or (index > 0 and f'PPid:\t{expected_parent}' not in status):
                        raise RuntimeError('synthetic process ownership mismatch')
                # Freeze every fixture controller before sending fatal signals;
                # no fixture process may perform the cleanup being measured.
                for fd in pidfds:
                    signal.pidfd_send_signal(fd, signal.SIGSTOP)
                for pid in pids:
                    deadline = time.monotonic() + 3
                    while not any(line.startswith('State:') and '\tT' in line for line in Path(f'/proc/{pid}/status').read_text().splitlines()):
                        if time.monotonic() >= deadline:
                            raise RuntimeError('synthetic process did not stop')
                        time.sleep(0.01)
                for fd in pidfds[2:]:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                signal.pidfd_send_signal(pidfds[1], signal.SIGKILL)
                signal.pidfd_send_signal(pidfds[0], signal.SIGKILL)
            finally:
                for fd in pidfds:
                    os.close(fd)
            events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                state = show(source_unit)
                if state['InvocationID'] != source_info['InvocationID']:
                    raise RuntimeError('source invocation changed')
                if state['ActiveState'] in ('inactive', 'failed') and (not events.exists() or 'populated 0' in events.read_text().splitlines()):
                    break
                time.sleep(0.02)
            else:
                raise RuntimeError('source unit cleanup not observed')
            time.sleep(7)
            for name in ('combined-late', 'watchdog-stop-requested', 'custodian-stop-requested'):
                if (directory / name).exists():
                    raise RuntimeError('unexpected synthetic late or auxiliary stop marker: ' + name)
            unchanged(target_unit, target_info)
            print('combined crash: main, controller and auxiliaries killed; unit empty or removed; late marker absent')
        finally:
            for unit, info in ((source_unit, source_info), (target_unit, target_info)):
                if info is not None:
                    state = show(unit)
                    if state.get('InvocationID') == info['InvocationID'] and state.get('ActiveState') not in ('inactive', 'failed'):
                        subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)


if __name__ == '__main__':
    main()
