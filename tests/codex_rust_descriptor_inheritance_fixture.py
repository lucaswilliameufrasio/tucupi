"""Synthetic std::process::Command inheritance probe; no credentials or cgroups."""
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    helper = Path(__file__).resolve().parent.parent / 'target/debug/examples/codex_protocol_fixture'
    with tempfile.TemporaryDirectory(prefix='tucupi-descriptor-', dir=Path.home()) as directory:
        marker = Path(directory) / 'synthetic-handle'
        marker.touch()
        fd = os.open(marker, os.O_RDONLY)
        try:
            args = [str(helper), 'descriptor-inheritance-probe', str(fd), str(marker)]
            inherited = subprocess.run(args, pass_fds=(fd,), check=True, capture_output=True, text=True, timeout=10)
            sanitized = subprocess.run(args + ['sanitized'], pass_fds=(fd,), check=True, capture_output=True, text=True, timeout=10)
            closed = subprocess.run(args, close_fds=True, check=True, capture_output=True, text=True, timeout=10)
            if inherited.stdout.strip() != 'descriptor inherited':
                raise RuntimeError('inheritable synthetic descriptor was not observed')
            if closed.stdout.strip() not in ('descriptor absent', 'descriptor replaced'):
                raise RuntimeError('closed descriptor control failed')
            if sanitized.stdout.strip() not in ('descriptor absent', 'descriptor replaced'):
                raise RuntimeError('fixture close-on-exec did not remove descriptor')
            print('Rust Command: explicitly inheritable synthetic descriptor reached child')
            print('fixture close_range: inherited synthetic descriptor absent after exec')
            print('closed descriptor control: synthetic descriptor absent')
        finally:
            os.close(fd)


if __name__ == '__main__':
    main()
