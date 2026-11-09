"""Test real batch config loading with a private synthetic FIFO, no package work."""
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    binary = Path(__file__).resolve().parent.parent / 'target/debug/tucupi'
    with tempfile.TemporaryDirectory(prefix='tucupi-config-fifo-', dir=Path.home()) as directory:
        root = Path(directory)
        os.mkfifo(root / 'tucupi.toml', 0o600)
        env = {'HOME': directory, 'XDG_STATE_HOME': str(root / 'state'),
               'PATH': directory, 'LANG': 'en_US.UTF-8'}
        result = subprocess.run([str(binary), '-i', directory], env=env,
                                capture_output=True, text=True, timeout=4)
        if result.returncode == 0 or 'tucupi.toml' not in result.stderr:
            raise RuntimeError('batch failed to reject synthetic FIFO config')
        if result.stdout:
            raise RuntimeError('batch unexpectedly entered terminal mode')
        print('batch: synthetic FIFO config rejected promptly before terminal and package work')


if __name__ == '__main__':
    main()
