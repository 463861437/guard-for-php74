"""Lock diagnostics must not turn a blocked query into a repair attempt."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'php_guard.py'
SPEC = importlib.util.spec_from_file_location('lock_cli_guard', SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class LockCliTests(unittest.TestCase):
    def test_busy_query_saves_inventory_and_owner_without_attempting_transaction(self):
        inventory = {'os': {'id': 'amzn', 'version_id': '2'}, 'package_manager': 'yum',
                     'packages': [], 'warnings': []}
        detail = {'backend': 'yum', 'pid': 3416, 'path': '/var/run/yum.pid', 'wait_seconds': 0}
        with tempfile.TemporaryDirectory() as temporary:
            folder = pathlib.Path(temporary) / 'report'
            with mock.patch.object(guard.sys, 'platform', 'linux'), \
                 mock.patch.object(guard.os, 'geteuid', return_value=0), \
                 mock.patch.object(guard.os, 'umask'), \
                 mock.patch.object(guard, 'collect_inventory', return_value=inventory), \
                 mock.patch.object(guard, 'fetch_candidates', side_effect=guard.PackageManagerLockTimeout('busy', detail)), \
                 mock.patch.object(guard, 'package_transaction') as transaction, \
                 mock.patch.object(guard, 'say') as say:
                code = guard.main(['plan', '--lock-wait', '0', '--output-dir', str(folder)])
            report = json.loads((folder / 'report.json').read_text())
        self.assertEqual(20, code)
        self.assertEqual('package_manager_busy_no_update', report['result'])
        self.assertEqual(detail, report['package_manager_lock'])
        self.assertEqual(inventory, report['inventory_before'])
        transaction.assert_not_called()
        output = '\n'.join(call.args[0] for call in say.call_args_list)
        self.assertIn('最多 0 秒', output)
        self.assertIn('ps -p 3416', output)
        self.assertIn('本次尚未安装修复包', output)

    def test_invalid_lock_budget_fails_before_host_inspection(self):
        for value in ['-1', '3601', '1.5', 'abc']:
            with self.subTest(value=value), mock.patch.object(guard, 'collect_inventory') as inventory, \
                 mock.patch('sys.stderr'), self.assertRaises(SystemExit) as caught:
                guard.main(['plan', '--lock-wait', value])
            self.assertEqual(2, caught.exception.code)
            inventory.assert_not_called()

    def test_explain_preserves_lock_details_without_querying_current_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'report.json'
            path.write_text(json.dumps({'result': 'package_manager_busy_no_update',
                'package_manager_lock': {'pid': 3416, 'path': '/var/run/yum.pid', 'wait_seconds': 120}}))
            with mock.patch.object(guard, 'collect_inventory') as inventory, \
                 mock.patch.object(guard, 'say') as say:
                result = guard.main(['explain', '--report', str(path)])
        self.assertEqual(0, result)
        inventory.assert_not_called()
        self.assertIn('ps -p 3416', '\n'.join(call.args[0] for call in say.call_args_list))


if __name__ == '__main__':
    unittest.main()
