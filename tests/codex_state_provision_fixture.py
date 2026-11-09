"""Explicit Linux state provisioning across processes; no manager calls."""
from pathlib import Path
import subprocess
import tempfile


def main():
    helper = Path(__file__).resolve().parent.parent / 'target/debug/examples/codex_protocol_fixture'
    with tempfile.TemporaryDirectory(prefix='tucupi-provision-', dir=Path.home()) as directory:
        def run(mode):
            return subprocess.run([str(helper), mode, directory], env={}, capture_output=True, text=True, timeout=5)

        if run('state-inspect-fixture').returncode == 0:
            raise RuntimeError('missing state accepted')
        if run('state-provision-fixture').stdout.strip() != 'fixture-state-provisioned':
            raise RuntimeError('explicit provisioning failed')
        inspected = run('state-inspect-fixture')
        if inspected.returncode != 0 or inspected.stdout.strip() != 'fixture-state-format-valid-not-clean-proof':
            raise RuntimeError('separate process could not inspect state')
        if run('state-provision-fixture').returncode == 0:
            raise RuntimeError('existing state was reinitialized')
        print('explicit provisioning: fresh process reopens; existing state never reinitialized')
    with tempfile.TemporaryDirectory(prefix='tucupi-provision-race-', dir=Path.home()) as directory:
        args = [str(helper), 'state-provision-fixture', directory]
        workers = [subprocess.Popen(args, env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        for worker in workers:
            worker.communicate(timeout=5)
        if sorted(worker.returncode for worker in workers) != [0, 1]:
            raise RuntimeError('concurrent provisioning did not admit exactly one process')
        result = subprocess.run([str(helper), 'state-inspect-fixture', directory], env={}, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            raise RuntimeError('concurrent provisioning left invalid format')
        print('concurrent provisioning: exactly one creator accepted')


if __name__ == '__main__':
    main()
