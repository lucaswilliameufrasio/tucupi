"""Opt-in lifecycle test for the synthetic private bridge, not production.

Uses uniquely named transient user units and only loopback fake services and
synthetic credentials. Requires systemd user services, Codex, namespaces,
bubblewrap and the built codex_transport_fixture example.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def invocation_id(unit):
    result = subprocess.run(
        ['systemctl', '--user', 'show', '--property=InvocationID', '--value', unit],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout.strip()
    if result == '0' * 32 or len(result) != 32 or any(char not in '0123456789abcdef' for char in result):
        raise RuntimeError('synthetic unit identity unavailable')
    return result


def stop_if_same_invocation(unit, expected):
    # This point-in-time check is not an atomic identity-bound stop.
    if invocation_id(unit) != expected:
        raise RuntimeError('synthetic unit identity changed; refusing stop')
    subprocess.run(['systemctl', '--user', 'stop', unit], check=True,
                   capture_output=True, timeout=10)


def run_case(mode):
    codex = shutil.which('codex')
    if codex is None:
        raise RuntimeError('Codex CLI unavailable')
    script = Path(__file__).resolve().with_name('codex_private_bridge_fixture.py')
    unit = 'tucupi-private-bridge-test-' + uuid.uuid4().hex + '.service'
    with tempfile.TemporaryDirectory(prefix='tucupi-bridge-supervisor-', dir=Path.home()) as directory:
        command = [
            'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', unit,
            '--property=MemoryMax=512M', '--property=TasksMax=64', '--property=CPUQuota=50%',
            '--property=KillMode=control-group', '--property=TimeoutStopSec=1',
            '--property=RuntimeMaxSec=45', '--setenv=PYTHONUNBUFFERED=1',
            '--setenv=PATH=' + str(Path(codex).parent) + ':/usr/bin:/bin',
            '--setenv=TUCUPI_BRIDGE_TEST_DIR=' + directory,
        ]
        if mode in ('cancel', 'controller-failure'):
            command.append('--setenv=TUCUPI_BRIDGE_CANCEL_FIXTURE=' + directory)
        if mode == 'invalid-response':
            command.append('--setenv=TUCUPI_BRIDGE_BAD_RESPONSE=1')
        command.extend(['/usr/bin/python3', str(script)])
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        identity = None
        try:
            if mode in ('cancel', 'controller-failure'):
                marker = Path(directory) / 'request-in-flight'
                deadline = time.monotonic() + 25
                while not marker.exists():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('synthetic CLI request did not reach the held upstream')
                    time.sleep(0.02)
                identity = invocation_id(unit)
                unit_group = subprocess.run(
                    ['systemctl', '--user', 'show', '--property=ControlGroup', '--value', unit],
                    check=True, capture_output=True, text=True, timeout=5,
                ).stdout.strip()
                descendant = int((Path(directory) / 'started').read_text())
                membership = Path(f'/proc/{descendant}/cgroup').read_text().splitlines()
                if not unit_group or membership != ['0::' + unit_group]:
                    raise RuntimeError('detached synthetic descendant is not in the test unit cgroup')
                if mode == 'controller-failure':
                    process.kill()
                    process.wait(timeout=5)
                stop_if_same_invocation(unit, identity)
                stdout, stderr = process.communicate(timeout=10)
                # systemd-run can return zero for an explicitly stopped unit;
                # cancellation is determined by the controller, not this code.
                if 'Codex CLI: synthetic review received' in stdout:
                    raise RuntimeError('cancelled request produced a completed review')
                time.sleep(7)
                if (Path(directory) / 'survived').exists():
                    raise RuntimeError('detached synthetic descendant survived cancellation')
                print(mode + ': descendant in unit did not survive explicit unit stop')
            elif mode == 'invalid-response':
                stdout, stderr = process.communicate(timeout=55)
                if process.returncode == 0 or 'synthetic Codex CLI failed' not in stderr:
                    raise RuntimeError('invalid tool-call response did not fail the supervised flow')
                if 'Codex CLI: synthetic review received' in stdout:
                    raise RuntimeError('invalid response produced a completed review')
                print('supervised CLI: synthetic tool-call response rejected')
            else:
                stdout, stderr = process.communicate(timeout=55)
                if process.returncode != 0 or 'Codex CLI: synthetic review received' not in stdout:
                    raise RuntimeError(f'supervised private bridge failed: {stderr[-2000:]}')
                print(stdout.strip())
        finally:
            # Do not stop an unverified or replaced unit by name. RuntimeMaxSec
            # is the test-only fallback if identity could not be established.
            if identity is not None:
                try:
                    stop_if_same_invocation(unit, identity)
                except (RuntimeError, subprocess.SubprocessError):
                    pass
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


if __name__ == '__main__':
    run_case('success')
    run_case('invalid-response')
    run_case('cancel')
    run_case('controller-failure')
