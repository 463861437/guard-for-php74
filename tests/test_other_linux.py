"""Native manager boundaries: inspection is not permission to use another solver."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'php_guard.py'
SPEC = importlib.util.spec_from_file_location('guard_other_linux_test', SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class ManagerInventoryTests(unittest.TestCase):
    def inspect(self, tools, outputs):
        warnings = []
        def command(argv, timeout=30):
            self.assertIn(argv[0], outputs)
            return outputs[argv[0]]
        with mock.patch.object(guard, '_inv_tool', side_effect=lambda name, unused: tools.get(name)), \
             mock.patch.object(guard, '_inv_cmd', side_effect=command):
            result = guard._inv_packages(warnings)
        return result, warnings

    def response(self, text='', code=0):
        return dict(code=code, stdout=text, stderr='fixture error' if code else '')

    def test_zypper_uses_read_only_rpm_inventory(self):
        result, warnings = self.inspect({'rpm': '/usr/bin/rpm', 'zypper': '/usr/bin/zypper'},
            {'/usr/bin/rpm': self.response('php7-cli\t0\t7.4.33\t1\tphp7-7.4.33-1.src.rpm\tx86_64\tSUSE\n')})
        self.assertEqual('zypper', result[0])
        self.assertEqual('php7', result[1][0]['source'])
        self.assertEqual([], warnings)

    def test_rpm_without_native_solver_is_explicit(self):
        result, unused = self.inspect({'rpm': '/usr/bin/rpm'}, {'/usr/bin/rpm': self.response()})
        self.assertEqual('rpm', result[0])

    def test_unknown_manager_has_coverage_warning(self):
        result, warnings = self.inspect({}, {})
        self.assertEqual('unknown', result[0])
        self.assertTrue(any('unavailable' in line for line in warnings))

    def test_apk_versions_keep_hyphenated_package_names(self):
        result, warnings = self.inspect({'apk': '/sbin/apk'}, {'/sbin/apk': self.response(
            'php83-8.3.28-r0\nphp83-fpm-8.3.28-r0\nphp83-pecl-redis-6.1.0-r0\nbusybox-1.37.0-r2\n')})
        self.assertEqual('apk', result[0])
        self.assertEqual(['php83', 'php83-fpm', 'php83-pecl-redis'], [p['name'] for p in result[1]])
        self.assertEqual('8.3.28-r0', result[1][0]['version'])
        self.assertTrue(any('coverage is incomplete' in line for line in warnings))

    def test_pacman_does_not_treat_php_extensions_as_php_source_build(self):
        result, warnings = self.inspect({'pacman': '/usr/bin/pacman'}, {'/usr/bin/pacman': self.response(
            'php 8.4.26-1\nphp-redis 6.2.0-1\nbash 5.3-1\n')})
        self.assertEqual('pacman', result[0])
        self.assertEqual(['php', 'php-redis'], [p['name'] for p in result[1]])
        self.assertFalse(guard.is_core_package(result[1][1]))
        self.assertTrue(any('coverage is incomplete' in line for line in warnings))

    def test_apk_failure_preserves_explicit_incomplete_coverage(self):
        result, warnings = self.inspect({'apk': '/sbin/apk'}, {'/sbin/apk': self.response(code=1)})
        self.assertEqual('apk', result[0])
        self.assertEqual([], result[1])
        self.assertTrue(any('inventory failed' in line for line in warnings))

    def test_empty_foreign_dpkg_database_does_not_hide_native_yum(self):
        result, warnings = self.inspect({'rpm': '/usr/bin/rpm', 'yum': '/usr/bin/yum', 'dpkg-query': '/usr/bin/dpkg-query'},
            {'/usr/bin/dpkg-query': self.response(), '/usr/bin/rpm': self.response(
                'php-cli\t0\t7.4.33\t1.amzn2\tphp-7.4.33-1.amzn2.src.rpm\tx86_64\tAmazon\n')})
        self.assertEqual('yum', result[0])
        self.assertFalse(any('Both DPKG' in line for line in warnings))

    def test_two_populated_databases_block_mixed_repairs(self):
        result, warnings = self.inspect({'rpm': '/usr/bin/rpm', 'dpkg-query': '/usr/bin/dpkg-query'},
            {'/usr/bin/dpkg-query': self.response('php7.4-cli\t7.4.3-1\tphp7.4\tamd64\tii \t7.4.3-1\n'),
             '/usr/bin/rpm': self.response('php-cli\t0\t7.4.33\t1\tphp-7.4.33-1.src.rpm\tx86_64\tFixture\n')})
        capability = guard.manager_capabilities({'package_manager': result[0], 'warnings': warnings})
        self.assertFalse(capability['automatic_fix'])
        self.assertEqual('mixed_package_managers', capability['blockers'][0]['kind'])


class ManagerBoundaryTests(unittest.TestCase):
    def host(self, manager):
        return dict(os={'id': 'fixture', 'version_id': '1'}, package_manager=manager,
                    packages=[], runtimes=[], services=[], processes=[], containers=[], warnings=[])

    def test_native_backends_are_explicit(self):
        for manager, backend in (('apt', 'python-apt'), ('yum', 'python-yum'), ('dnf', 'python-dnf')):
            with self.subTest(manager=manager):
                capability = guard.manager_capabilities(self.host(manager))
                self.assertTrue(capability['automatic_fix'])
                self.assertEqual(backend, capability['backend'])

    def test_unimplemented_backend_never_falls_back_to_rpm_transaction(self):
        with mock.patch.object(guard, 'rpm_transaction') as rpm, \
             mock.patch.object(guard, 'apt_transaction') as apt:
            for manager in ('apk', 'pacman', 'zypper', 'rpm', 'unknown', None):
                with self.subTest(manager=manager):
                    result = guard.package_transaction(self.host(manager), [], {}, execute=True)
                    self.assertFalse(result['ok'])
                    self.assertFalse(result['executed'])
                    self.assertIn('只读审计', result['error'])
        rpm.assert_not_called()
        apt.assert_not_called()

    def test_unimplemented_backend_never_fetches_foreign_repository(self):
        with mock.patch.object(guard, 'rpm_candidates') as rpm, \
             mock.patch.object(guard, 'apt_candidates') as apt, \
             mock.patch.object(guard, 'run_cmd') as command:
            for manager in ('apk', 'pacman', 'zypper', 'rpm', 'unknown'):
                with self.subTest(manager=manager), self.assertRaises(RuntimeError):
                    guard.fetch_candidates(self.host(manager), {}, refresh=True)
        rpm.assert_not_called()
        apt.assert_not_called()
        command.assert_not_called()

    def test_unknown_plan_and_fix_save_actionable_blocker_without_queries_or_restarts(self):
        for mode in ('plan', 'fix'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                output = pathlib.Path(tmp) / 'report'
                inv = self.host('apk')
                with mock.patch.object(guard.sys, 'platform', 'linux'), \
                     mock.patch.object(guard.os, 'geteuid', return_value=0), \
                     mock.patch.object(guard, 'collect_inventory', return_value=inv), \
                     mock.patch.object(guard, 'fetch_candidates') as fetch, \
                     mock.patch.object(guard, 'acquire_repair_lock', return_value=None), \
                     mock.patch.object(guard, 'service_preflight') as preflight, \
                     mock.patch.object(guard, 'execute_repair') as repair, \
                     mock.patch.object(guard, 'say'):
                    code = guard.main([mode, '--yes', '--output-dir', str(output)])
                report = json.loads((output / 'report.json').read_text())
                self.assertEqual(10, code)
                self.assertEqual('blocked_no_update', report['result'])
                self.assertEqual('unsupported_package_manager', report['plan']['blockers'][0]['kind'])
                self.assertEqual('read_only_audit', report['package_manager_capabilities']['scope'])
                fetch.assert_not_called()
                preflight.assert_not_called()
                repair.assert_not_called()

    def test_unknown_audit_still_runs_and_reports_missing_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / 'report'
            with mock.patch.object(guard.sys, 'platform', 'linux'), \
                 mock.patch.object(guard.os, 'geteuid', return_value=0), \
                 mock.patch.object(guard, 'collect_inventory', return_value=self.host('unknown')), \
                 mock.patch.object(guard, 'fetch_candidates') as fetch, \
                 mock.patch.object(guard, 'say'):
                code = guard.main(['audit', '--output-dir', str(output)])
            report = json.loads((output / 'report.json').read_text())
        self.assertEqual(10, code)
        self.assertEqual('unresolved', report['result'])
        self.assertFalse(report['package_manager_capabilities']['automatic_fix'])
        fetch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
