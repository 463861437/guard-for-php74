"""An installed dependency transaction must expose subsequent check failures."""
import importlib.util
import pathlib
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'php_guard.py'
SPEC = importlib.util.spec_from_file_location('php_guard_postcheck_test', SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class PostcheckOutputTests(unittest.TestCase):
    def render(self, result):
        with mock.patch.object(guard, 'say') as say, mock.patch.object(
                guard, 'run_cmd', side_effect=AssertionError('output must not execute commands')):
            guard.be_show_postcheck(result)
        return '\n'.join(call.args[0] for call in say.call_args_list)

    def test_missing_and_unresolved_are_visible_without_unrelated_fields(self):
        output = self.render({'ok': False, 'doctor': {'blockers': ['dependency not verified'],
            'dependencies': {'missing': ['gcc'], 'unresolved': ['curl-devel >= 7.9'],
                             'reason': 'rpm_database_unavailable'},
            'next_commands': ['untrusted command --secret=should-not-print']}})
        for value in ['dependency not verified', 'gcc', 'curl-devel >= 7.9', 'rpm_database_unavailable']:
            self.assertIn(value, output)
        self.assertNotIn('should-not-print', output)

    def test_child_failure_is_visible_and_terminal_controls_are_removed(self):
        output = self.render({'ok': False, 'error': 'Permission denied\x1b[31m\n/path'})
        self.assertIn('Permission denied', output)
        self.assertNotIn('\x1b', output)

    def test_missing_details_do_not_claim_success(self):
        output = self.render({'ok': False})
        self.assertIn('build_user_check', output)
        self.assertNotIn('通过', output)


if __name__ == '__main__':
    unittest.main()
