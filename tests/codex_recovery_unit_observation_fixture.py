"""Opt-in unit identity observation; no production recovery or reconciliation."""
from pathlib import Path
import subprocess
import tempfile
import uuid

from codex_systemd_escape_fixture import start, unchanged
from codex_systemd_main_fixture import show


def main():
    root = Path(__file__).resolve().parent.parent
    helper = root / 'target/debug/examples/codex_protocol_fixture'
    unit = 'tucupi-registry-test-' + uuid.uuid4().hex + '.service'
    info = None
    with tempfile.TemporaryDirectory(prefix='tucupi-unit-record-', dir=Path.home()) as directory:
        def call(*args):
            return subprocess.run([str(helper), *map(str, args)], env={}, capture_output=True, text=True, timeout=5)

        try:
            if call('recovery-marker-arm-identity', directory).stdout.strip() != 'fixture-marker-armed':
                raise RuntimeError('failed to arm fixture marker')
            info = start(unit, ['/usr/bin/sleep', '25'])
            unchanged(unit, info)
            bound = call('recovery-marker-bind-unit', directory, unit, info['InvocationID'])
            if bound.returncode != 0 or bound.stdout.strip() != 'fixture-unit-observed':
                raise RuntimeError('fixture unit observation failed: ' + bound.stderr[-1000:])
            expected = 'fixture-unit-v1:0123456789abcdef0123456789abcdef:' + unit + ':' + info['InvocationID'] + '\n'
            if (Path(directory) / 'unit-observation').read_text() != expected:
                raise RuntimeError('persisted fixture unit observation mismatch')
            unavailable = subprocess.run([
                '/usr/bin/systemctl', '--user', 'show', unit,
            ], env={'XDG_RUNTIME_DIR': str(Path(directory) / 'missing'),
                    'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(Path(directory) / 'missing-bus')},
                capture_output=True, text=True, timeout=5)
            if unavailable.returncode == 0:
                raise RuntimeError('synthetic manager outage was not reproduced')
            if call('app-fixture-recovery-check', directory).stdout.strip() != 'app-fixture-blocked':
                raise RuntimeError('new fixture App did not fail closed')
            if call('recovery-marker-bind-unit', directory, unit, info['InvocationID']).returncode == 0:
                raise RuntimeError('fixture unit observation was replaced')
            unchanged(unit, info)
            print('fixture unit invocation recorded; simulated manager outage leaves restarted App blocked')
        finally:
            if info is not None:
                state = show(unit)
                if state.get('InvocationID') == info['InvocationID'] and state.get('ActiveState') not in ('inactive', 'failed'):
                    subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)


if __name__ == '__main__':
    main()
