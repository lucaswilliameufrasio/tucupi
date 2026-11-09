"""Opt-in synthetic creation journal experiment; not an independent authority."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

from codex_systemd_escape_fixture import start
from codex_systemd_main_fixture import show


def commit(directory, name, payload):
    path = directory / name
    with path.open('x') as record:
        json.dump(payload, record, sort_keys=True)
        record.write('\n')
        record.flush()
        os.fsync(record.fileno())
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def worker(directory, attempt, stage):
    unit = 'tucupi-review-' + attempt + '.service'
    commit(directory, 'intent', {'attempt': attempt, 'unit': unit})
    if stage == 'after-intent':
        os._exit(71)
    info = start(unit, ['/usr/bin/sleep', '25'])
    # Harness-only cleanup receipt; it is not authority or a recovery record.
    print('created:' + info['InvocationID'], flush=True)
    if stage == 'after-create':
        os._exit(72)
    commit(directory, 'binding', {'attempt': attempt, 'unit': unit, 'invocation': info['InvocationID']})
    os._exit(73)


def inspect(directory, attempt):
    # Missing, malformed, incomplete and bound-but-unreconciled all block.
    try:
        intent = json.loads((directory / 'intent').read_text())
        if intent != {'attempt': attempt, 'unit': 'tucupi-review-' + attempt + '.service'}:
            raise ValueError('mismatched intent')
        binding_path = directory / 'binding'
        if not binding_path.exists():
            return 'blocked:unknown-creation'
        binding = json.loads(binding_path.read_text())
        if (binding.get('attempt') != attempt or binding.get('unit') != intent['unit']
                or not re.fullmatch('[0-9a-f]{32}', binding.get('invocation', ''))):
            raise ValueError('invalid binding')
        return 'blocked:binding-unverified'
    except (OSError, ValueError, TypeError):
        return 'blocked:invalid-or-missing'


def main():
    if len(sys.argv) > 1:
        mode, directory, attempt = sys.argv[1:4]
        if mode == 'worker':
            worker(Path(directory), attempt, sys.argv[4])
        elif mode == 'inspect':
            print(inspect(Path(directory), attempt))
        return
    script = str(Path(__file__).resolve())
    for stage in ('after-intent', 'after-create', 'after-binding'):
        attempt = uuid.uuid4().hex
        unit = 'tucupi-review-' + attempt + '.service'
        invocation = None
        with tempfile.TemporaryDirectory(prefix='tucupi-authority-', dir=Path.home()) as directory:
            try:
                run = subprocess.run([sys.executable, script, 'worker', directory, attempt, stage],
                                     capture_output=True, text=True, timeout=15)
                if run.stdout.startswith('created:'):
                    invocation = run.stdout.strip().removeprefix('created:')
                expected_code = {'after-intent': 71, 'after-create': 72, 'after-binding': 73}[stage]
                if run.returncode != expected_code:
                    raise RuntimeError('synthetic controller failed: ' + run.stderr[-1000:])
                result = subprocess.run([sys.executable, script, 'inspect', directory, attempt],
                                        check=True, capture_output=True, text=True, timeout=5).stdout.strip()
                expected = 'blocked:binding-unverified' if stage == 'after-binding' else 'blocked:unknown-creation'
                if result != expected:
                    raise RuntimeError('restart did not preserve inconclusive state')
                if stage != 'after-intent':
                    state = show(unit)
                    if not invocation or state['InvocationID'] != invocation or state['ActiveState'] != 'active':
                        raise RuntimeError('synthetic unit identity changed')
                    if stage == 'after-binding':
                        binding = json.loads((Path(directory) / 'binding').read_text())
                        if binding['invocation'] != invocation or binding['unit'] != unit:
                            raise RuntimeError('persisted binding mismatched synthetic unit')
                duplicate = subprocess.run([sys.executable, script, 'worker', directory, attempt, stage],
                                           capture_output=True, text=True, timeout=10)
                if duplicate.returncode == 0 or 'FileExistsError' not in duplicate.stderr or duplicate.stdout.startswith('created:'):
                    raise RuntimeError('duplicate admission was not rejected')
                if stage == 'after-binding':
                    binding_path = Path(directory) / 'binding'
                    binding['attempt'] = uuid.uuid4().hex
                    binding_path.write_text(json.dumps(binding))
                    invalid = subprocess.run([sys.executable, script, 'inspect', directory, attempt],
                                             check=True, capture_output=True, text=True, timeout=5)
                    if invalid.stdout.strip() != 'blocked:invalid-or-missing':
                        raise RuntimeError('mismatched synthetic binding was accepted')
                    print('mismatched binding: blocked:invalid-or-missing', flush=True)
                print(stage + ': ' + result + '; duplicate rejected', flush=True)
            finally:
                if invocation:
                    state = show(unit)
                    if state.get('InvocationID') != invocation:
                        raise RuntimeError('cannot safely clean fixture: unit invocation changed')
                    if state.get('ActiveState') not in ('inactive', 'failed'):
                        subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)


if __name__ == '__main__':
    main()
