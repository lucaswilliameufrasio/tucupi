"""Opt-in real-cgroup test of App task cancellation with a synthetic worker.

Builds a Rust test binary and runs one ignored test in unique delegated user
units. It uses the local synthetic bridge and no real provider credentials.
This is not a production isolation or cleanup proof.
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid


def test_binary():
    result = subprocess.run([
        'cargo', 'test', '--locked', '--all-features', '--lib', '--no-run',
        '--message-format=json',
    ], check=True, capture_output=True, text=True, timeout=120)
    binaries = []
    for line in result.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (message.get('reason') == 'compiler-artifact'
                and message.get('profile', {}).get('test')
                and message.get('target', {}).get('name') == 'tucupi'
                and message.get('executable')):
            binaries.append(message['executable'])
    if len(binaries) != 1:
        raise RuntimeError('could not identify the Rust library test binary')
    return binaries[0]


def main():
    codex = shutil.which('codex')
    if codex is None:
        raise RuntimeError('Codex CLI unavailable')
    binary = test_binary()
    test = 'app::tests::supervised_review_fixture_stops_on_cancel_or_worker_panic'
    for mode in ('cancel', 'panic', 'replace', 'startup', 'startup-replace', 'startup-drop', 'startup-shutdown', 'startup-after-release', 'startup-cancel-failure', 'startup-before-attach', 'startup-before-create', 'startup-after-create', 'startup-close-failure', 'startup-moved-child', 'startup-moved-after-check', 'stale-handle'):
        unit = 'tucupi-app-review-test-' + uuid.uuid4().hex + '.service'
        with tempfile.TemporaryDirectory(prefix='tucupi-app-review-', dir=Path.home()) as directory:
            try:
                selected_test = ('codex_supervision::tests::stale_fixture_handle_rejects_recreated_group'
                                 if mode == 'stale-handle' else
                                 'app::tests::fixture_app_cancel_during_startup_rejects_gate'
                                 if mode in ('startup', 'startup-replace', 'startup-drop', 'startup-shutdown', 'startup-after-release', 'startup-cancel-failure', 'startup-before-attach', 'startup-before-create', 'startup-after-create', 'startup-close-failure', 'startup-moved-child', 'startup-moved-after-check') else test)
                result = subprocess.run([
                    'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', unit,
                    '--property=Delegate=yes', '--property=KillMode=control-group',
                    '--property=RuntimeMaxSec=40', '--property=TimeoutStopSec=1',
                    '--property=MemoryMax=512M', '--property=TasksMax=64', '--property=CPUQuota=50%',
                    '--setenv=TUCUPI_APP_FIXTURE_DIR=' + directory,
                    '--setenv=TUCUPI_APP_FIXTURE_CODEX_DIR=' + str(Path(codex).parent),
                    '--setenv=TUCUPI_APP_FIXTURE_MODE=' + mode,
                    binary, '--exact', selected_test, '--ignored', '--nocapture',
                ], capture_output=True, text=True, timeout=50, check=False)
                expected = ('stale fixture handle rejected; replacement child remained running'
                            if mode == 'stale-handle' else
                            'app startup-close-failure: exec rejected; cgroup empty; session blocked'
                            if mode == 'startup-close-failure' else
                            'app startup-moved-after-check: child self-check rejected; direct child reaped; session blocked'
                            if mode == 'startup-moved-after-check' else
                            'app startup-moved-child: membership mismatch rejected; direct child reaped; session blocked'
                            if mode == 'startup-moved-child' else
                            'app startup-after-create: empty cgroup retained; worker not started; session blocked'
                            if mode == 'startup-after-create' else
                            'app startup-before-create: cancellation observed; cgroup and worker not created'
                            if mode == 'startup-before-create' else
                            'app startup-cancel-failure: failure reported while populated; later cleanup did not clear block'
                            if mode == 'startup-cancel-failure' else
                            'app startup-after-release: cgroup emptied before startup resumed; child reaped; detached marker absent'
                            if mode == 'startup-after-release' else
                            'app ' + mode + ': admitted child reaped; cgroup empty; worker not started'
                            if mode in ('startup', 'startup-replace', 'startup-drop', 'startup-shutdown', 'startup-before-attach') else
                            'app ' + mode + ': synthetic cgroup empty; direct child reaped; detached marker absent')
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'synthetic app fixture failed: {result.stdout[-2000:]} {result.stderr[-2000:]}')
                print(expected)
                if mode == 'startup-after-create':
                    group = Path((Path(directory) / 'created-cgroup-path').read_text())
                    if (not group.is_relative_to('/sys/fs/cgroup') or '..' in group.parts
                            or unit not in group.parts):
                        raise RuntimeError('synthetic cgroup path did not belong to the test unit')
                    try:
                        group.stat()
                    except FileNotFoundError:
                        pass
                    else:
                        raise RuntimeError('synthetic empty cgroup remained after unit exit')
                    print('outer synthetic unit exit: empty child cgroup no longer visible')
            finally:
                subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True,
                               timeout=10, check=False)


if __name__ == '__main__':
    main()
