"""Isolated real batch-entry preflight; no package commands or manager calls."""
from pathlib import Path
import os
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent.parent
    helper = root / 'target/debug/examples/codex_protocol_fixture'
    binary = root / 'target/debug/tucupi'
    with tempfile.TemporaryDirectory(prefix='tucupi-prod-preflight-', dir=Path.home()) as directory:
        root_dir = Path(directory)
        project = root_dir / 'project'
        state_parent = root_dir / 'xdg-state' / 'tucupi'
        project.mkdir()
        state_parent.mkdir(parents=True, mode=0o700)
        os.chmod(state_parent, 0o700)
        (project / 'tucupi.toml').write_text("[security]\nreview_provider = 'codex'\n")
        env = {'HOME': directory, 'XDG_STATE_HOME': str(root_dir / 'xdg-state'), 'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'}

        def check():
            result = subprocess.run([str(binary), '-i', str(project)], env=env, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 or 'Review cleanup was not verified' not in result.stderr:
                raise RuntimeError('real batch preflight did not fail closed: ' + result.stderr[-1000:])
            if '\x1b[' in result.stdout:
                raise RuntimeError('batch entered terminal mode before blocking')

        check()
        provisioned = subprocess.run([str(helper), 'state-provision-fixture', str(state_parent), 'recovery'], env=env, capture_output=True, text=True, timeout=5)
        if provisioned.returncode != 0:
            raise RuntimeError('fixture provisioning failed: ' + provisioned.stderr[-1000:])
        check()
        check()
        print('real batch entry: missing and provisioned-but-unreconciled state blocked across processes')
        marker = state_parent / 'recovery' / 'format'
        marker.unlink()  # This marker was created in this fixture's temporary directory.
        os.mkfifo(marker, 0o600)
        app = subprocess.run([str(helper), 'app-production-observation-fixture', str(project)],
                             env=env, capture_output=True, text=True, timeout=4)
        if app.returncode != 0 or 'app-production-observation:Some(StateUnavailable)' not in app.stdout:
            raise RuntimeError('App did not reject synthetic FIFO marker')
        batch = subprocess.run([str(binary), '-i', str(project)], env=env, capture_output=True, text=True, timeout=4)
        if batch.returncode == 0 or 'Review cleanup was not verified' not in batch.stderr:
            raise RuntimeError('batch did not reject synthetic FIFO marker')
        print('synthetic FIFO marker: App and batch return promptly and remain blocked')


if __name__ == '__main__':
    main()
