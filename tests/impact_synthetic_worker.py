"""Harmless synthetic preview worker for the opt-in systemd fixture."""
import os
from pathlib import Path
import subprocess
import sys
import time

directory = Path(sys.argv[1])
if len(sys.argv) > 2 and sys.argv[2] == 'gated':
    (directory / 'gate-waiting').touch()
    deadline = time.monotonic() + 15
    while not (directory / 'release-gate').exists():
        if time.monotonic() >= deadline:
            sys.exit(2)
        time.sleep(0.01)
code = "import pathlib,sys,time; pathlib.Path(sys.argv[1]).touch(); time.sleep(5); pathlib.Path(sys.argv[2]).touch(); time.sleep(10)"
child = subprocess.Popen(['/usr/bin/python3', '-c', code, str(directory / 'child-ready'),
                          str(directory / 'late')], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, env={})
(directory / 'worker-pid').write_text(str(os.getpid()))
(directory / 'child-pid').write_text(str(child.pid))
time.sleep(20)
