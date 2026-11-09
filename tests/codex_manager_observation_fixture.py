"""Opt-in read-only manager observation against a dedicated synthetic unit."""
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

from codex_systemd_escape_fixture import start, unchanged
from codex_systemd_main_fixture import show


OUTAGE_WORKER = r'''
import os, subprocess, sys
helper, binary, project, state, home = sys.argv[1:]
env = {'HOME': home, 'XDG_STATE_HOME': state, 'LANG': 'en_US.UTF-8', 'PATH': '/usr/bin:/bin'}
app = subprocess.run([helper, 'app-production-observation-fixture', project], env=env, capture_output=True, text=True, timeout=8)
if app.returncode != 0 or 'app-production-observation:Some(ManagerUnavailable)' not in app.stdout:
    raise RuntimeError('default App did not observe simulated manager outage')
batch = subprocess.run([binary, '-i', project], env=env, capture_output=True, text=True, timeout=18)
if batch.returncode == 0 or 'Review cleanup was not verified' not in batch.stderr:
    raise RuntimeError('real batch did not block during simulated manager outage')
print('default App and real batch fail closed while manager sockets are hidden', flush=True)
'''


def main():
    root = Path(__file__).resolve().parent.parent
    helper = root / 'target/debug/examples/codex_protocol_fixture'
    attempt = uuid.uuid4().hex
    unit = 'tucupi-review-' + attempt + '.service'
    info = None
    with tempfile.TemporaryDirectory(prefix='tucupi-manager-observe-', dir=Path.home()) as directory:
        directory = Path(directory)
        try:
            info = start(unit, ['/usr/bin/sleep', '25'])
            unchanged(unit, info)
            original = ('tucupi-recovery-attempt-v1\n' + 'attempt=' + attempt + '\n' + 'unit=' + unit
                        + '\ninvocation=' + info['InvocationID']
                        + '\nboot=' + 'b' * 32 + '\nmanager_epoch=' + 'c' * 32 + '\n')
            record = directory / 'pending-attempt'
            record.write_text(original)
            record.chmod(0o600)
            setup = subprocess.run([str(helper), 'state-provision-fixture', str(directory)], env={}, capture_output=True, text=True, timeout=5)
            if setup.returncode != 0:
                raise RuntimeError('fixture state provisioning failed')
            state_record = directory / 'state' / 'pending-attempt'
            state_record.write_text(original)
            state_record.chmod(0o600)
            def inspect(runtime):
                result = subprocess.run([str(helper), 'inspect-persisted-fixture', str(directory / 'state'), runtime], env={}, capture_output=True, text=True, timeout=8)
                if result.returncode != 0:
                    raise RuntimeError('fixture reconciliation inspection failed')
                return result.stdout.strip()

            runtime = '/run/user/' + str(os.getuid())
            rust = subprocess.run([str(helper), 'same-connection-rust-fixture', unit, runtime], env={}, capture_output=True, text=True, timeout=8)
            if rust.returncode != 0 or rust.stdout.strip() != unit + ' ' + info['InvocationID']:
                raise RuntimeError('same-connection Rust observation failed: ' + rust.stderr[-1000:])
            if inspect(runtime) != 'fixture-recovery-observation:ManagerEpochUnknown':
                raise RuntimeError('matching synthetic unit did not remain blocked on unknown manager generation')
            if inspect(str(directory / 'unavailable')) != 'fixture-recovery-observation:ManagerUnavailable':
                raise RuntimeError('manager outage did not remain blocked')
            project = directory / 'project'
            project.mkdir()
            (project / 'tucupi.toml').write_text("[security]\nreview_provider = 'codex'\n")
            state_parent = directory / 'xdg' / 'tucupi'
            state_parent.mkdir(parents=True)
            state_parent.chmod(0o700)
            provisioned = subprocess.run([str(helper), 'state-provision-fixture', str(state_parent), 'recovery'], env={}, capture_output=True, text=True, timeout=5)
            if provisioned.returncode != 0:
                raise RuntimeError('shared fixture state provisioning failed')
            shared_record = state_parent / 'recovery' / 'pending-attempt'
            shared_record.write_text(original)
            shared_record.chmod(0o600)
            env = {'HOME': str(directory), 'XDG_STATE_HOME': str(directory / 'xdg'), 'LANG': 'en_US.UTF-8', 'PATH': '/usr/bin:/bin'}
            app = subprocess.run([str(helper), 'app-production-observation-fixture', str(project)], env=env, capture_output=True, text=True, timeout=8)
            if app.returncode != 0 or 'app-production-observation:Some(ManagerEpochUnknown)' not in app.stdout:
                raise RuntimeError('default App did not inspect synthetic unit: ' + app.stderr[-1000:])
            batch = subprocess.run([str(root / 'target/debug/tucupi'), '-i', str(project)], env=env, capture_output=True, text=True, timeout=8)
            if batch.returncode == 0 or 'Review cleanup was not verified' not in batch.stderr:
                raise RuntimeError('real batch entry did not remain blocked')
            shared_record.write_text(original.replace(info['InvocationID'], 'd' * 32))
            app_mismatch = subprocess.run([str(helper), 'app-production-observation-fixture', str(project)], env=env, capture_output=True, text=True, timeout=8)
            if app_mismatch.returncode != 0 or 'app-production-observation:Some(UnitIdentityMismatch)' not in app_mismatch.stdout:
                raise RuntimeError('default App did not detect mismatched invocation')
            batch_mismatch = subprocess.run([str(root / 'target/debug/tucupi'), '-i', str(project)], env=env, capture_output=True, text=True, timeout=8)
            if batch_mismatch.returncode == 0 or 'Review cleanup was not verified' not in batch_mismatch.stderr:
                raise RuntimeError('real batch entry accepted mismatched invocation')
            shared_record.write_text(original)
            outage_unit = 'tucupi-outage-probe-' + uuid.uuid4().hex + '.service'
            outage = subprocess.run([
                'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', outage_unit,
                '--property=InaccessiblePaths=' + runtime + '/bus ' + runtime + '/systemd/private',
                '--property=KillMode=control-group', '--property=RuntimeMaxSec=40',
                '--property=MemoryMax=512M', '--property=TasksMax=256',
                '/usr/bin/python3', '-c', OUTAGE_WORKER, str(helper), str(root / 'target/debug/tucupi'),
                str(project), str(directory / 'xdg'), str(directory),
            ], capture_output=True, text=True, timeout=45)
            if outage.returncode != 0 or 'default App and real batch fail closed while manager sockets are hidden' not in outage.stdout:
                raise RuntimeError('synthetic manager outage scenario failed: ' + outage.stderr[-1000:])
            def observe(runtime):
                return subprocess.run([str(helper), 'observe-manager-fixture', str(directory), runtime], env={}, capture_output=True, text=True, timeout=8)

            result = observe('/run/user/' + str(os.getuid()))
            expected = 'synthetic manager observation matched persisted unit and invocation; recovery remains blocked'
            if result.returncode != 0 or expected not in result.stdout:
                raise RuntimeError('real manager observation failed: ' + result.stderr[-1000:])
            if observe(str(directory / 'unavailable')).returncode == 0:
                raise RuntimeError('invalid manager runtime unexpectedly succeeded')
            record.write_text(original.replace(info['InvocationID'], 'd' * 32))
            state_record.write_text(original.replace(info['InvocationID'], 'd' * 32))
            if observe('/run/user/' + str(os.getuid())).returncode == 0:
                raise RuntimeError('mismatched invocation was accepted')
            if inspect(runtime) != 'fixture-recovery-observation:UnitIdentityMismatch':
                raise RuntimeError('mismatched invocation was not classified')
            record.write_text(original)
            state_record.write_text(original)
            if record.read_text() != original:
                raise RuntimeError('synthetic record changed unexpectedly')
            unchanged(unit, info)
            print(expected)
            print('synthetic manager unavailable and mismatched invocation rejected; record retained')
            print('shared reconciliation: manager epoch unknown, outage and mismatch remain blocked')
            print('default App observed unknown manager epoch and mismatch; real batch stayed blocked')
            print('default App and real batch fail closed while manager sockets are hidden')
        finally:
            if info is not None:
                state = show(unit)
                if state['InvocationID'] == info['InvocationID'] and state['ActiveState'] not in ('inactive', 'failed'):
                    subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)


if __name__ == '__main__':
    main()
