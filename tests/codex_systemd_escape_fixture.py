"""Opt-in, unprivileged cross-unit cgroup movement probe; not a sandbox test."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid

from codex_systemd_main_fixture import show


SOURCE = r'''
import pathlib, subprocess, sys, time
directory = pathlib.Path(sys.argv[1])
code = "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); p.joinpath('child').write_text(str(__import__('os').getpid())); time.sleep(6); p.joinpath('survived').touch(); time.sleep(20)"
subprocess.Popen(['/usr/bin/python3', '-c', code, str(directory)], start_new_session=True)
time.sleep(25)
'''


def start(unit, command):
    subprocess.run([
        'systemd-run', '--user', '--quiet', '--unit', unit,
        '--property=Delegate=yes', '--property=KillMode=control-group',
        '--property=RuntimeMaxSec=25', '--property=TimeoutStopSec=1',
        '--property=MemoryMax=128M', '--property=TasksMax=16', *command,
    ], check=True, capture_output=True, text=True, timeout=10)
    info = show(unit)
    if (not info['InvocationID'] or int(info['MainPID']) <= 1
            or not info['ControlGroup'].endswith('/' + unit)
            or info['KillMode'] != 'control-group'):
        raise RuntimeError('unexpected fixture unit identity')
    return info


def unchanged(unit, original):
    info = show(unit)
    if any(info[key] != original[key] for key in ('InvocationID', 'MainPID', 'ControlGroup')):
        raise RuntimeError('fixture unit identity changed')


def main():
    suffix = uuid.uuid4().hex
    source = 'tucupi-escape-source-' + suffix + '.service'
    target = 'tucupi-escape-target-' + suffix + '.service'
    owned = []
    with tempfile.TemporaryDirectory(prefix='tucupi-escape-', dir=Path.home()) as directory:
        directory = Path(directory)
        try:
            dst = start(target, ['/usr/bin/sleep', '25'])
            owned.append((target, dst))
            src = start(source, ['/usr/bin/python3', '-c', SOURCE, str(directory)])
            owned.append((source, src))
            deadline = time.monotonic() + 4
            while not (directory / 'child').exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError('synthetic child not started')
                time.sleep(0.01)
            child = int((directory / 'child').read_text())
            main_pid = int(src['MainPID'])
            with_pid = [os.pidfd_open(main_pid), os.pidfd_open(child)]
            try:
                unchanged(source, src)
                unchanged(target, dst)
                status = Path(f'/proc/{child}/status').read_text().splitlines()
                member = Path(f'/proc/{child}/cgroup').read_text().splitlines()
                if f'PPid:\t{main_pid}' not in status or f"0::{src['ControlGroup']}" not in member:
                    raise RuntimeError('synthetic child identity mismatch')
                destination = Path('/sys/fs/cgroup') / dst['ControlGroup'].lstrip('/') / 'cgroup.procs'
                try:
                    destination.write_text(str(child))
                except PermissionError:
                    print('cross-unit move denied: no escaped-process cleanup conclusion')
                    return
                member = Path(f'/proc/{child}/cgroup').read_text().splitlines()
                if f"0::{dst['ControlGroup']}" not in member:
                    raise RuntimeError('cross-unit move not observed')
                unchanged(source, src)
                unchanged(target, dst)
                signal.pidfd_send_signal(with_pid[0], signal.SIGKILL)
                deadline = time.monotonic() + 8
                while show(source)['ActiveState'] not in ('inactive', 'failed'):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('source unit did not stop')
                    time.sleep(0.02)
                source_events = Path('/sys/fs/cgroup') / src['ControlGroup'].lstrip('/') / 'cgroup.events'
                if source_events.exists() and 'populated 0' not in source_events.read_text().splitlines():
                    raise RuntimeError('source cgroup still populated')
                deadline = time.monotonic() + 8
                while not (directory / 'survived').exists():
                    if time.monotonic() >= deadline:
                        raise RuntimeError('escaped synthetic child did not write marker')
                    time.sleep(0.02)
                if f"0::{dst['ControlGroup']}" not in Path(f'/proc/{child}/cgroup').read_text().splitlines():
                    raise RuntimeError('escaped child not in target fixture unit')
                print('escaped child survived source unit termination inside target fixture unit')
            finally:
                for fd in with_pid:
                    os.close(fd)
        finally:
            for unit, original in reversed(owned):
                info = show(unit)
                if info['InvocationID'] == original['InvocationID'] and info['ActiveState'] not in ('inactive', 'failed'):
                    subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)
                events = Path('/sys/fs/cgroup') / original['ControlGroup'].lstrip('/') / 'cgroup.events'
                if info['InvocationID'] == original['InvocationID'] and events.exists() and 'populated 0' not in events.read_text().splitlines():
                    raise RuntimeError('fixture unit cleanup not observed')


if __name__ == '__main__':
    main()
