"""Route selection must not confuse a build recipe with an installed fix."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'php_guard.py'
SPEC = importlib.util.spec_from_file_location('guard_remediation_test', SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.inv = {'os': {'id': 'amzn', 'version_id': '2'}, 'packages': [
            {'name': 'php-cli', 'source': 'php', 'version': '7.4.33-1.amzn2',
             'arch': 'x86_64'}]}
        self.plan = {'updates': [], 'blockers': [{'source': 'php', 'branch': '7.4',
            'reason': 'no complete trusted fixed build in same branch'}]}
        self.preflight = {'blockers': []}

    def test_exact_recipe_routes_to_build_without_claiming_deployment(self):
        result = guard.remediation_plan(self.inv, self.plan, self.preflight)
        self.assertEqual('al2_php74_source_build_required', result['route'])
        self.assertFalse(result['deployed'])
        self.assertFalse(result['repository_candidates_ready'])
        self.assertEqual('dedicated_al2_x86_64_build_host', result['steps'][0]['where'])
        self.assertIn('setup', result['steps'][1]['argv'])
        self.assertIn('auto', result['steps'][2]['description'])

    def test_other_os_version_arch_or_package_set_never_gets_this_recipe(self):
        for field, value in [('version', '7.4.33-2.other'), ('arch', 'aarch64'),
                             ('source', 'php74-php')]:
            inv = dict(self.inv, packages=[dict(self.inv['packages'][0], **{field: value})])
            self.assertEqual('vendor_backport_or_migration_required',
                             guard.remediation_plan(inv, self.plan, {})['route'])
        inv = dict(self.inv, os={'id': 'centos', 'version_id': '7'})
        self.assertEqual('vendor_backport_or_migration_required',
                         guard.remediation_plan(inv, self.plan, {})['route'])

    def test_lifecycle_and_coverage_do_not_claim_install_ready(self):
        for plan, preflight, route in [
                ({'updates': [{}]}, {'blockers': [{'reason': 'unknown process'}]}, 'lifecycle_review_required'),
                ({'updates': [{}], 'blockers': [{'kind': 'container'}]}, {}, 'review_required')]:
            result = guard.remediation_plan(self.inv, plan, preflight)
            self.assertEqual(route, result['route'])
            self.assertFalse(result['repository_candidates_ready'])

    def test_candidates_are_not_deployment_and_no_service_is_selected(self):
        result = guard.remediation_plan(self.inv, {'updates': [{}]}, {})
        self.assertTrue(result['repository_candidates_ready'])
        self.assertFalse(result['deployed'])
        self.assertNotIn('argv', result['steps'][0])

    def test_grouped_lifecycle_preserves_pids_and_hint_only(self):
        preflight = {'blockers': [dict(pid=pid, ppid=4, parent_comm='sh',
                                      lifecycle={'origin': 'cron'}) for pid in [10, 11, 10]]}
        result = guard.remediation_plan(self.inv, self.plan, preflight)
        self.assertEqual([10, 11], result['lifecycle'][0]['pids'])
        self.assertEqual(['sh'], result['lifecycle'][0]['parents'])
        self.assertFalse(result['repository_candidates_ready'])

    def test_saved_commands_do_not_execute_or_interpolate_report_data(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(
                guard, 'run_cmd', side_effect=AssertionError('must not execute')):
            result = guard.save_remediation(folder, self.inv, self.plan, self.preflight)
            self.assertEqual(result, json.loads((pathlib.Path(folder) / 'remediation.json').read_text()))
            self.assertIn('auto', (pathlib.Path(folder) / 'next-steps.txt').read_text())

    def test_console_uses_process_names_not_arguments(self):
        preflight = {'blockers': [{'pid': 12, 'ppid': 9, 'parent_comm': 'sh',
            'reason': 'PHP process PID 12 has no mapped systemd service',
            'lifecycle': {'origin': 'cron'}, 'cmdline': 'php --token=should-not-print'}]}
        with mock.patch.object(guard, 'say') as output:
            guard.print_blockers({}, {}, preflight)
        text = '\n'.join(call.args[0] for call in output.call_args_list)
        self.assertIn('cron', text)
        self.assertIn('ps -p 12', text)
        self.assertNotIn('should-not-print', text)


if __name__ == '__main__':
    unittest.main()
