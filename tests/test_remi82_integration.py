"""Cross-module regression coverage for PHP 8.2 native routing and deployment."""
import copy
import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guard_remi82_integration_tests', ROOT / 'php_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
# Exercise current sources before assembly, as well as their shared namespace.
for name in ('common', 'remi82_builder', 'remi82_install', 'native_environment', 'platform_support', 'oneclick', 'cli'):
    exec(compile((ROOT / ('src/' + name + '.py')).read_bytes(), str(ROOT / ('src/' + name + '.py')), 'exec'), guard.__dict__)


def package(name, source='php', version='8.2.20-1.el7.remi'):
    return dict(name=name, source=source, version=version, upstream=version.split('-', 1)[0],
                arch='x86_64', source_rpm=source + '-' + version + '.src.rpm')


def inventory(layouts=('system', 'scl'), patched=False):
    version = guard.R82_VERSION + '-' + guard.R82_RELEASE if patched else '8.2.20-1.el7.remi'
    rows = []
    if 'system' in layouts:
        rows += [package('php-cli', version=version), package('php-common', version=version),
                 package('php-pecl-zip', source='php-pecl-zip', version='1.22.3-1.el7.remi.8.2')]
    if 'scl' in layouts:
        rows += [package('php82-php-common', source='php82-php', version=version),
                 package('php82-php-pecl-zip', source='php82-php-pecl-zip', version='1.22.3-1.el7.remi'),
                 package('php82-runtime', source='php82', version='8.2-5.el7.remi')]
    return dict(os={'id': 'centos', 'version_id': '7.9'}, package_manager='yum', packages=rows,
                warnings=[], processes=[], services=[], runtimes=[], containers=[])


class IntegrationRoutingTests(unittest.TestCase):
    def test_system_scl_and_mixed_remi82_routes(self):
        for layouts in (('system',), ('scl',), ('system', 'scl')):
            for patched in (False, True):
                with self.subTest(layouts=layouts, patched=patched):
                    inv = inventory(layouts, patched)
                    self.assertEqual('remi82', guard.oc_source_route(inv, 'x86_64'))
                    self.assertEqual(list(layouts), guard.r82_layouts(inv))

    def test_existing_php74_routes_keep_their_recipes(self):
        cases = [('amzn', '2', '7.4.33-1.amzn2', 'al2'),
                 ('centos', '7.9', '7.4.33-15.el7.remi', 'remi')]
        for system, release, version, expected in cases:
            inv = inventory(('system',)); inv['os'] = {'id': system, 'version_id': release}
            inv['packages'] = [package('php-cli', version=version)]
            self.assertEqual(expected, guard.oc_source_route(inv, 'x86_64'))
        inv = dict(os={'id': 'ubuntu', 'version_id': '20.04'}, package_manager='apt',
                   packages=[dict(name='php7.4-cli', source='php7.4', arch='amd64', upstream='7.4.33',
                                  version='1:7.4.33-15+ubuntu20.04.1+deb.sury.org+1')])
        self.assertEqual('ubuntu20', guard.oc_source_route(inv, 'x86_64'))

    def test_mixed_minor_and_unreviewed_vendor_baselines_do_not_route(self):
        inv = inventory(); inv['packages'].append(package('php74-php-common', 'php74-php', '7.4.33-15.el7.remi'))
        self.assertIsNone(guard.oc_source_route(inv, 'x86_64'))
        for changes in ({'source_rpm': 'unknown.src.rpm'}, {'version': '8.2.21-1.el7.remi'}, {'arch': 'i686'}):
            inv = inventory(); inv['packages'][0].update(changes)
            self.assertIsNone(guard.oc_source_route(inv, 'x86_64'))
        self.assertIsNone(guard.oc_source_route(inventory(), 'aarch64'))

    def test_only_exact_known_scl_metadata_wrappers_are_exempt(self):
        for name in ('php82', 'php82-runtime', 'php82-syspaths', 'php82-build'):
            value = package(name, 'php82', '8.2-5.el7.remi')
            self.assertFalse(guard.is_core_package(value))
            value['version'] = '0:8.2-5.el7.remi'
            self.assertFalse(guard.is_core_package(value))
            value['version'] = '1:8.2-5.el7.remi'
            self.assertTrue(guard.is_core_package(value))
        for changes in ({'version': '8.2-6.el7.remi'}, {'source_rpm': 'custom.src.rpm'}, {'name': 'php82-unknown'}):
            value = package('php82-runtime', 'php82', '8.2-5.el7.remi'); value.update(changes)
            self.assertTrue(guard.is_core_package(value))
        self.assertTrue(guard.is_core_package(package('php82-php-common', 'php82-php')))
        self.assertFalse(guard.is_core_package(package('php82-php-pecl-zip', 'php82-php-pecl-zip')))

    def test_support_matrix_names_the_exact_baseline_and_layouts(self):
        routes = guard.platform_support()['local_source_routes']
        route = next(row for row in routes if row.get('target') == '8.2.35')
        self.assertEqual('7', route['os_major']); self.assertEqual('x86_64', route['architecture'])
        self.assertEqual(2, len(route['layouts'])); self.assertIn('8.2.20-1.el7.remi', route['baseline'])

    def test_cli_dispatches_native_php82_build_and_install(self):
        with mock.patch.object(guard, 'native_build_main', return_value=17) as build:
            self.assertEqual(17, guard.main(['build-remi-el7-php82', 'doctor', '--layout', 'scl']))
            build.assert_called_once_with('remi82', ['doctor', '--layout', 'scl'])
        with mock.patch.object(guard, 'remi82_install_main', return_value=18) as install:
            self.assertEqual(18, guard.main(['remi-el7-php82', 'audit']))
            install.assert_called_once_with(['audit'])


class ReceiptOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.inv = inventory(patched=True)
        self.addCleanup(mock.patch.stopall)
        for name, value in dict(be_report_directory=self.temp.name, collect_inventory=self.inv,
                                r82_receipt={}, check_package_integrity=[],
                                manager_capabilities={'automatic_fix': True, 'blockers': []},
                                fetch_candidates={}, enrich_origin=None,
                                service_preflight={'services': [], 'blockers': [], 'checks': []},
                                health_checks=[], show_summary=None, say=None).items():
            mock.patch.object(guard, name, return_value=value).start()
        mock.patch.object(guard.sys, 'platform', 'linux').start()
        mock.patch.object(guard.os, 'geteuid', return_value=0).start()
        mock.patch.object(guard.os, 'umask', return_value=0).start()
        mock.patch.object(guard.os, 'uname', return_value=('Linux', '', '', '', 'x86_64')).start()
        self.build = mock.patch.object(guard, 'oc_source_apply', return_value=10).start()
        self.install = mock.patch.object(guard, 'execute_repair', return_value={'ok': True}).start()

    def report(self):
        return json.loads((pathlib.Path(self.temp.name) / 'oneclick.json').read_text())

    def test_generic_assessment_never_certifies_unreceipted_local_835(self):
        for row in guard.r82_core_packages(self.inv):
            self.assertEqual('unknown', guard.package_status(row, self.inv, guard.POLICY)[0])
        self.assertTrue(all(row['status'] == 'unknown' for row in guard.oc_assess(self.inv, None)))
        self.assertTrue(all(row['status'] == 'unknown' for row in guard.oc_assess(self.inv, 'remi82')))

    def test_repository_plan_cannot_turn_missing_receipt_into_empty_success(self):
        findings = guard.oc_assess(self.inv, 'remi82')
        plan = guard.build_plan(self.inv, findings, {}, guard.POLICY)
        self.assertTrue(plan['blockers']); self.assertEqual([], plan['updates'])
        self.assertEqual(0, guard.php74_patch_main(['plan']))
        self.assertEqual('remi82', self.report()['selected_route'])
        self.assertEqual('route_plan_ready', self.report()['result'])
        self.install.assert_not_called()

    def test_fix_without_receipt_takes_build_validation_not_repository_noop(self):
        with mock.patch.object(guard.os, 'open', return_value=9876), \
             mock.patch.object(guard.os, 'close'), mock.patch('fcntl.flock'):
            self.assertEqual(10, guard.php74_patch_main(['fix', '--yes']))
        self.build.assert_called_once(); self.install.assert_not_called()
        self.assertEqual('remi82', self.build.call_args.args[0])
        self.assertNotEqual('already_fixed_within_scope', self.report()['result'])

    def test_matching_receipt_path_is_used_before_repository_access(self):
        with mock.patch.object(guard, 'r82_assess', return_value=[{'kind': 'package', 'status': 'fixed'}]) as assess, \
             mock.patch.object(guard, 'fetch_candidates') as fetch:
            self.assertEqual(0, guard.php74_patch_main(['audit']))
        assess.assert_called_once_with(self.inv, {})
        self.assertEqual('already_fixed_within_scope', self.report()['result'])
        fetch.assert_not_called(); self.build.assert_not_called(); self.install.assert_not_called()


class BuildReportHandoffTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        self.args = types.SimpleNamespace(build_user=None, work_dir=None, jobs=2, lock_wait=300,
                                         build_timeout=21600, progress_interval=15, service=['supervisord.service'],
                                         health_url=['http://127.0.0.1/health'], health_host='example.test', scan_root=['/srv/php'])
        self.inv = inventory()
        self.report = {'inventory_before': self.inv, 'service_preflight': {'services': ['php-fpm.service', 'supervisord.service']}}
        self.events = []
        mock.patch.object(guard, 'oc_builder_account', return_value=types.SimpleNamespace(pw_dir='/home/build', pw_name='build')).start()
        mock.patch.object(guard, 'write_json').start(); mock.patch.object(guard, 'say').start()
        mock.patch.object(guard, 'collect_inventory', return_value=self.inv).start()
        mock.patch.object(guard, 'oc_assess', return_value=[{'status': 'fixed'}]).start()
        mock.patch.object(guard, 'residual_process_check', return_value={'ok': True}).start()
        def maintain(args, report, path, action):
            self.events.append('maintenance'); return action()
        mock.patch.object(guard, 'oc_maintenance_run', side_effect=maintain).start()
        self.installer = mock.patch.object(guard, 'remi82_install_main', side_effect=lambda argv: self.events.append('install') or 0).start()
        self.reports = ['/home/build/one/system/build-first/build.json', '/home/build/one/scl/build-second/build.json']
        mock.patch.object(guard, 'NB_LAST_BUILD_REPORTS', self.reports).start()

    def test_both_layouts_build_before_maintenance_and_pass_exact_reports(self):
        with mock.patch.object(guard, 'native_build_main', side_effect=lambda *argv: self.events.append('build') or 0) as build:
            self.assertEqual(0, guard.oc_source_apply('remi82', self.args, self.report, '/private/oneclick.json'))
        self.assertEqual(['build', 'maintenance', 'install'], self.events)
        self.assertEqual('remi82', build.call_args.args[0])
        argv = build.call_args.args[1]
        self.assertEqual(['system', 'scl'], [argv[i + 1] for i, value in enumerate(argv) if value == '--layout'])
        deployed = self.installer.call_args.args[0]
        self.assertNotIn('--work-dir', deployed)
        self.assertEqual(self.reports, [deployed[i + 1] for i, value in enumerate(deployed) if value == '--build-report'])
        self.assertIn('supervisord.service', deployed); self.assertIn('http://127.0.0.1/health', deployed)
        self.assertEqual(self.reports, self.report['build_reports'])

    def test_default_dedicated_account_directory_fits_both_legacy_shebangs(self):
        account = types.SimpleNamespace(pw_dir='/var/lib/php-cve-guard-build', pw_name='phpguard-build')
        with mock.patch.object(guard, 'oc_builder_account', return_value=account), \
             mock.patch.object(guard, 'native_build_main', return_value=20) as build:
            self.assertEqual(20, guard.oc_source_apply('remi82', self.args, self.report, '/private/oneclick.json'))
        argv = build.call_args.args[1]
        folder = argv[argv.index('--work-dir') + 1]
        self.assertEqual('/var/lib/php-cve-guard-build/php82-remi-el7', folder)
        for layout in ('system', 'scl'):
            self.assertLessEqual(guard.r82_test_path_preflight(folder + '/' + layout)['shebang_bytes'], 127)

    def test_long_explicit_work_directory_blocks_before_dependency_transaction(self):
        self.args.work_dir = '/var/lib/php-cve-guard-build/php82-patch-remi-el7-1.8.0'
        with mock.patch.object(guard, 'native_build_main') as build:
            with self.assertRaisesRegex(RuntimeError, '--work-dir'):
                guard.oc_source_apply('remi82', self.args, self.report, '/private/oneclick.json')
        build.assert_not_called()
        self.installer.assert_not_called()
        self.assertEqual([], self.events)

    def test_missing_layout_report_blocks_before_maintenance_or_install(self):
        with mock.patch.object(guard, 'native_build_main', return_value=0), \
             mock.patch.object(guard, 'NB_LAST_BUILD_REPORTS', self.reports[:1]):
            with self.assertRaises(RuntimeError):
                guard.oc_source_apply('remi82', self.args, self.report, '/private/oneclick.json')
        self.installer.assert_not_called(); self.assertEqual([], self.events)

    def test_failed_second_build_never_adopts_prior_successful_report(self):
        with mock.patch.object(guard, 'native_build_main', return_value=20):
            self.assertEqual(20, guard.oc_source_apply('remi82', self.args, self.report, '/private/oneclick.json'))
        self.installer.assert_not_called(); self.assertEqual('build_incomplete_no_php_deployment', self.report['result'])

    def test_native_child_separates_layout_directories_and_collects_current_reports(self):
        account = dict(name='build', uid=1000, gid=1000, home='/home/build', work_dir='/home/build/php82')
        calls = []
        def builder(argv):
            calls.append(argv)
            if argv[0] == 'build':
                layout = argv[argv.index('--layout') + 1]
                guard.R82_LAST_BUILD_REPORT = '/home/build/php82/' + layout + '/build-new/build.json'
            return 0
        with mock.patch.object(guard, 'be_worker_call', side_effect=lambda callback: callback()), \
             mock.patch.object(guard, 'be_drop_privileges'), \
             mock.patch.object(guard.os, 'geteuid', return_value=1000), \
             mock.patch.object(guard, 'remi82_build_main', side_effect=builder):
            result = guard.nb_child('remi82', account, True, 2, ['system', 'scl'])
        self.assertTrue(result['ok'])
        self.assertEqual(['prepare', 'doctor', 'build'] * 2, [row[0] for row in calls])
        self.assertEqual(['/home/build/php82/system/build-new/build.json', '/home/build/php82/scl/build-new/build.json'], result['build_reports'])
        self.assertIn('/home/build/php82/system', calls[0]); self.assertIn('/home/build/php82/scl', calls[3])

    def test_native_child_second_layout_failure_never_returns_success(self):
        account = dict(name='build', uid=1000, gid=1000, home='/home/build', work_dir='/home/build/php82')
        def builder(argv):
            layout = argv[argv.index('--layout') + 1]
            if argv[0] == 'build':
                guard.R82_LAST_BUILD_REPORT = '/home/build/php82/system/build-old/build.json'
            return 20 if layout == 'scl' and argv[0] == 'build' else 0
        with mock.patch.object(guard, 'be_worker_call', side_effect=lambda callback: callback()), \
             mock.patch.object(guard, 'be_drop_privileges'), \
             mock.patch.object(guard.os, 'geteuid', return_value=1000), \
             mock.patch.object(guard, 'remi82_build_main', side_effect=builder):
            result = guard.nb_child('remi82', account, True, 2, ['system', 'scl'])
        self.assertFalse(result['ok']); self.assertEqual('scl', result['layout'])
        self.assertEqual(1, len(result['build_reports']))


if __name__ == '__main__':
    unittest.main()
