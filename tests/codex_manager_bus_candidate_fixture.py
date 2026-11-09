"""Read-only bus identity candidate plus a synthetic transient unit."""
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

from codex_systemd_escape_fixture import start, unchanged
from codex_systemd_main_fixture import show


def bus_call(method, *args):
    result = subprocess.run([
        '/usr/bin/busctl', '--user', 'call', 'org.freedesktop.DBus',
        '/org/freedesktop/DBus', 'org.freedesktop.DBus', method, *args,
    ], check=True, capture_output=True, text=True, timeout=5)
    text = result.stdout.strip()
    if not (text.startswith('s "') and text.endswith('"')):
        raise RuntimeError('unexpected synthetic bus response')
    return text[3:-1]


def main():
    root = Path(__file__).resolve().parent.parent
    helper = root / 'target/debug/examples/codex_protocol_fixture'
    attempt = uuid.uuid4().hex
    unit = 'tucupi-review-' + attempt + '.service'
    info = None
    with tempfile.TemporaryDirectory(prefix='tucupi-bus-identity-', dir=Path.home()) as directory:
        directory = Path(directory)
        try:
            info = start(unit, ['/usr/bin/sleep', '25'])
            unchanged(unit, info)
            bus_id = bus_call('GetId')
            owner = bus_call('GetNameOwner', 's', 'org.freedesktop.systemd1')
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')
            record = ('tucupi-recovery-attempt-v1\nattempt=' + attempt + '\nunit=' + unit
                      + '\ninvocation=' + info['InvocationID'] + '\nboot=' + boot
                      + '\nmanager_epoch=' + bus_id + '\n')
            pending = directory / 'pending-attempt'
            pending.write_text(record)
            pending.chmod(0o600)
            owner_file = directory / 'manager-owner'
            owner_file.write_text(owner + '\n')
            def inspect(runtime):
                return subprocess.run([str(helper), 'manager-bus-candidate-fixture', str(directory), runtime], env={}, capture_output=True, text=True, timeout=15)

            runtime = '/run/user/' + str(os.getuid())
            result = inspect(runtime)
            expected = 'synthetic unit and bus candidate matched persisted fixture; recovery remains blocked'
            if result.returncode != 0 or expected not in result.stdout:
                raise RuntimeError('bus candidate fixture unavailable: ' + result.stderr[-1000:])
            owner_file.write_text(':1.999999999\n')
            if inspect(runtime).returncode == 0:
                raise RuntimeError('mismatched fixture owner accepted')
            if inspect(str(directory / 'missing-runtime')).returncode == 0:
                raise RuntimeError('unavailable fixture runtime accepted')
            if pending.read_text() != record:
                raise RuntimeError('synthetic recovery record changed')
            unchanged(unit, info)
            print(expected)
            print('changed owner and unavailable runtime rejected; record retained')
        finally:
            if info is not None:
                state = show(unit)
                if state['InvocationID'] == info['InvocationID'] and state['ActiveState'] not in ('inactive', 'failed'):
                    subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)


if __name__ == '__main__':
    main()
