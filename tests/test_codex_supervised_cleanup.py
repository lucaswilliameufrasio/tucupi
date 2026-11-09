"""Unit regression for the synthetic supervisor's owned-unit cleanup."""

from pathlib import Path
import tempfile
import unittest
from unittest import mock

import codex_supervised_smoke as smoke


class CleanupTests(unittest.TestCase):
    def test_failed_controller_exit_stops_owned_unit(self):
        process = mock.MagicMock()
        process.returncode = 1
        process.communicate.return_value = ("", "controller failed")
        with mock.patch.object(smoke.subprocess, "Popen", return_value=process), \
                mock.patch.object(smoke.subprocess, "run") as run:
            result = smoke.run_unit("synthetic-codex")
        self.assertEqual(result.returncode, 1)
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["systemctl", "--user", "stop"])
        self.assertTrue(command[3].startswith("tucupi-codex-test-"))
        self.assertTrue(command[3].endswith(".service"))

    def test_exited_controller_does_not_skip_owned_unit_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory)
            (probe / "descendant-started").touch()
            (probe / "request-started").touch()
            process = mock.MagicMock()
            process.poll.side_effect = [None, -9]
            process.communicate.return_value = ("", "")
            with mock.patch.object(smoke.subprocess, "Popen", return_value=process), \
                    mock.patch.object(smoke.subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "synthetic controller exited unexpectedly"):
                    smoke.run_unit("synthetic-codex", probe, crash_controller=True)
            process.kill.assert_called_once()
            self.assertEqual(run.call_count, 1)
            command = run.call_args.args[0]
            self.assertEqual(command[:3], ["systemctl", "--user", "stop"])
            self.assertTrue(command[3].startswith("tucupi-codex-test-"))
            self.assertTrue(command[3].endswith(".service"))


if __name__ == "__main__":
    unittest.main()
