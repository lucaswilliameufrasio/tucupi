"""Opt-in separate-process test of the fixture-only persistent marker."""
from pathlib import Path
import subprocess
import tempfile


def main():
    helper = Path(__file__).resolve().parent.parent / 'target/debug/examples/codex_protocol_fixture'
    with tempfile.TemporaryDirectory(prefix='tucupi-recovery-', dir=Path.home()) as directory:
        def run(mode, path=directory):
            return subprocess.run([str(helper), mode, str(path)], capture_output=True, text=True, timeout=5)

        if run('recovery-marker-check').stdout.strip() != 'fixture-recovery-clear':
            raise RuntimeError('fresh synthetic marker not clear')
        if run('recovery-marker-arm').stdout.strip() != 'fixture-marker-armed':
            raise RuntimeError('synthetic marker not persisted')
        if run('recovery-marker-check').stdout.strip() != 'fixture-recovery-blocked':
            raise RuntimeError('new process failed to recover block')
        if run('app-fixture-recovery-check').stdout.strip() != 'app-fixture-blocked':
            raise RuntimeError('new App process failed to recover fixture block')
        if run('recovery-marker-arm').returncode == 0:
            raise RuntimeError('second synthetic admission was accepted')
        if run('recovery-marker-check', Path(directory) / 'missing').stdout.strip() != 'fixture-recovery-blocked':
            raise RuntimeError('unavailable synthetic state did not fail closed')
        if run('app-fixture-recovery-check', Path(directory) / 'missing').stdout.strip() != 'app-fixture-blocked':
            raise RuntimeError('new App process did not fail closed on unavailable state')
        guarded = Path(directory) / 'recovery-state'
        guarded.mkdir()
        if run('recovery-marker-arm', guarded).stdout.strip() != 'fixture-marker-armed':
            raise RuntimeError('guarded synthetic marker not armed')
        blocked = subprocess.run([
            str(helper), 'owned-spawn-fixture', directory, '/usr/bin',
            str(Path(directory) / 'never-started.py'), 'recovery-guarded',
        ], env={}, capture_output=True, text=True, timeout=5)
        if blocked.returncode == 0 or 'File exists' not in blocked.stderr:
            raise RuntimeError('guarded fixture was not rejected before spawn')
        identified = Path(directory) / 'identified-state'
        identified.mkdir()
        if run('recovery-marker-arm-identity', identified).stdout.strip() != 'fixture-marker-armed':
            raise RuntimeError('fixture identity was not persisted')
        expected_identity = 'fixture-attempt-v1:0123456789abcdef0123456789abcdef\n'
        if (identified / 'unverified').read_text() != expected_identity:
            raise RuntimeError('fixture identity changed across process boundary')
        if run('app-fixture-recovery-check', identified).stdout.strip() != 'app-fixture-blocked':
            raise RuntimeError('new App did not block identified fixture attempt')
        batch_state = Path(directory) / 'batch-state'
        batch_state.mkdir()
        if run('batch-fixture-manager-failure', batch_state).stdout.strip() != 'batch-fixture-failed-blocked':
            raise RuntimeError('synthetic batch manager failure not recorded')
        if run('app-fixture-recovery-check', batch_state).stdout.strip() != 'app-fixture-blocked':
            raise RuntimeError('new App did not observe batch fixture failure')
        print('separate processes: persisted marker blocks retry; unavailable state blocks')
        print('new App process: persisted and unavailable fixture state both block')
        print('guarded fixture: pre-existing marker rejected startup without manager access')
        print('separate App process: identified fixture attempt remains blocked')
        print('separate App process: synthetic batch manager failure remains blocked')


if __name__ == '__main__':
    main()
