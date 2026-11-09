"""Regression checks for fixture-only systemd identity handling."""
import unittest
from unittest import mock

import codex_private_bridge_supervised as supervisor


class IdentityTests(unittest.TestCase):
    def test_zero_identity_is_rejected(self):
        with mock.patch.object(supervisor.subprocess, 'run') as run:
            run.return_value.stdout = '0' * 32 + '\n'
            with self.assertRaisesRegex(RuntimeError, 'identity unavailable'):
                supervisor.invocation_id('synthetic.service')

    def test_changed_identity_never_stops_named_unit(self):
        with mock.patch.object(supervisor, 'invocation_id', return_value='b' * 32), \
                mock.patch.object(supervisor.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                supervisor.stop_if_same_invocation('synthetic.service', 'a' * 32)
            run.assert_not_called()

    def test_missing_identity_never_stops_named_unit(self):
        with mock.patch.object(supervisor, 'invocation_id', side_effect=RuntimeError('missing')), \
                mock.patch.object(supervisor.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'missing'):
                supervisor.stop_if_same_invocation('synthetic.service', 'a' * 32)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
