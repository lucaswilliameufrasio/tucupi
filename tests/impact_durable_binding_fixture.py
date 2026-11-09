"""Opt-in synthetic impact admission and interruption experiment, not authority."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from codex_authority_lifecycle_fixture import commit, inspect
from codex_systemd_main_fixture import show


def controller(directory, attempt, stage):
    unit = 'tucupi-review-' + attempt + '.service'
    state = directory / 'state'
    commit(state, 'intent', {'attempt': attempt, 'unit': unit})
    if stage == 'after-intent':
        os._exit(71)
    helper = Path(__file__).resolve().parent.parent / 'target/debug/examples/codex_protocol_fixture'
    subprocess.run([
        'systemd-run', '--user', '--quiet', '--unit', unit,
        '--property=KillMode=control-group', '--property=RuntimeMaxSec=25',
        '--property=TimeoutStopSec=1', '--property=MemoryMax=128M', '--property=TasksMax=16',
        '/usr/bin/env', '-i', 'HOME=' + str(directory), 'PATH=/usr/bin:/bin',
        str(helper), 'impact-systemd-fixture', str(directory), 'gated',
    ], check=True, capture_output=True, text=True, timeout=10)
    info = show(unit)
    if not info['InvocationID'] or int(info['MainPID']) <= 1 or not info['ControlGroup'].endswith('/' + unit):
        raise RuntimeError('invalid synthetic unit')
    # A harness-only receipt for safe cleanup, not a recovery or authority record.
    print('created:' + info['InvocationID'], flush=True)
    if stage == 'after-create':
        os._exit(72)
    commit(state, 'binding', {'attempt': attempt, 'unit': unit, 'invocation': info['InvocationID']})
    (directory / 'release-gate').touch(exist_ok=False)
    deadline = time.monotonic() + 8
    while not (directory / 'child-ready').exists():
        if time.monotonic() >= deadline:
            raise RuntimeError('synthetic gated preview did not start')
        time.sleep(0.01)
    os._exit(73)


def main():
    if len(sys.argv) > 1:
        mode, directory, attempt = sys.argv[1:4]
        if mode == 'controller':
            controller(Path(directory), attempt, sys.argv[4])
        elif mode == 'inspect':
            print(inspect(Path(directory) / 'state', attempt))
        return
    script = str(Path(__file__).resolve())
    for stage in ('after-intent', 'after-create', 'after-binding'):
        attempt = uuid.uuid4().hex
        unit = 'tucupi-review-' + attempt + '.service'
        invocation = None
        with tempfile.TemporaryDirectory(prefix='tucupi-impact-binding-', dir=Path.home()) as directory:
            directory = Path(directory)
            (directory / 'state').mkdir(mode=0o700)
            try:
                result = subprocess.run([sys.executable, script, 'controller', str(directory), attempt, stage],
                                        capture_output=True, text=True, timeout=20)
                if result.stdout.startswith('created:'):
                    invocation = result.stdout.strip().removeprefix('created:')
                expected_code = {'after-intent': 71, 'after-create': 72, 'after-binding': 73}[stage]
                if result.returncode != expected_code:
                    raise RuntimeError('synthetic controller failed: ' + result.stderr[-1000:])
                observed = subprocess.run([sys.executable, script, 'inspect', str(directory), attempt],
                                          check=True, capture_output=True, text=True, timeout=5).stdout.strip()
                expected = 'blocked:binding-unverified' if stage == 'after-binding' else 'blocked:unknown-creation'
                if observed != expected:
                    raise RuntimeError('unknown synthetic attempt was not blocked')
                if stage == 'after-create':
                    deadline = time.monotonic() + 5
                    while not (directory / 'gate-waiting').exists():
                        if time.monotonic() >= deadline or show(unit)['ActiveState'] != 'active':
                            raise RuntimeError('synthetic preview did not reach gate')
                        time.sleep(0.01)
                    if (directory / 'release-gate').exists() or (directory / 'child-ready').exists():
                        raise RuntimeError('synthetic workload was released without binding')
                if stage == 'after-binding':
                    binding = json.loads((directory / 'state' / 'binding').read_text())
                    if binding != {'attempt': attempt, 'unit': unit, 'invocation': invocation}:
                        raise RuntimeError('synthetic durable binding mismatch')
                duplicate = subprocess.run([sys.executable, script, 'controller', str(directory), attempt, stage],
                                           capture_output=True, text=True, timeout=10)
                if duplicate.returncode == 0 or 'FileExistsError' not in duplicate.stderr:
                    raise RuntimeError('duplicate synthetic admission was not rejected')
                print(stage + ': ' + observed + '; duplicate rejected', flush=True)
            finally:
                if invocation:
                    state = show(unit)
                    if state.get('InvocationID') != invocation:
                        raise RuntimeError('cannot safely clean synthetic unit: invocation changed')
                    if state.get('ActiveState') not in ('inactive', 'failed'):
                        subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)
                    events = Path('/sys/fs/cgroup') / state['ControlGroup'].lstrip('/') / 'cgroup.events'
                    if events.exists() and 'populated 0' not in events.read_text().splitlines():
                        raise RuntimeError('synthetic unit cgroup not observed empty')


if __name__ == '__main__':
    main()
