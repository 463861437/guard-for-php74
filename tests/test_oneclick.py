"""One-command orchestration: exact recipes, no accidental install and truthful results."""
import copy
import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('oneclick_guard_test', ROOT / 'php_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
# Load working sources too, so tests cover edits before assembling the release.
for module in ('remi_builder', 'deb_builder', 'oneclick'):
    exec(compile((ROOT / ('src/' + module + '.py')).read_text(), module, 'exec'), guard.__dict__)


def inventory(route='al2'):
    os_info, manager, source, version, arch = {
        'al2': ({'id': 'amzn', 'version_id': '2'}, 'yum', 'php', '7.4.33-1.amzn2', 'x86_64'),
        'remi': ({'id': 'centos', 'version_id': '7.9'}, 'yum', 'php', '7.4.33-15.el7.remi', 'x86_64'),
        'ubuntu20': ({'id': 'ubuntu', 'version_id': '20.04'}, 'apt', 'php7.4',
                     '1:7.4.33-15+ubuntu20.04.1+deb.sury.org+1', 'amd64'),
    }[route]
    package = dict(name='php7.4-cli' if manager == 'apt' else 'php-cli', source=source,
        version=version, upstream='7.4.33', arch=arch)
    if manager != 'apt': package['source_rpm'] = 'php-' + version + '.src.rpm'
    return dict(os=os_info, package_manager=manager, packages=[package], warnings=[],
                processes=[], services=[], runtimes=[], containers=[])


class RecipeRoutingTests(unittest.TestCase):
    def test_exact_three_native_baselines_and_receipt_versions_are_routed(self):
        for route in ('al2', 'remi', 'ubuntu20'):
            with self.subTest(route=route):
                inv = inventory(route)
                self.assertEqual(route, guard.oc_source_route(inv, 'x86_64'))
                version = {'al2': guard.BAOTA_AL2_VERSION + '-' + guard.BAOTA_AL2_RELEASE,
                           'remi': guard.RB_VERSION + '-' + guard.RB_RELEASE,
                           'ubuntu20': guard.DB_VERSION}[route]
                inv['packages'][0].update(version=version, upstream='7.4.34')
                if route != 'ubuntu20': inv['packages'][0]['source_rpm'] = 'php-' + version + '.src.rpm'
                self.assertEqual(route, guard.oc_source_route(inv, 'x86_64'))

    def test_rpm_route_binds_original_build_source_and_platform(self):
        for route in ('al2', 'remi'):
            for key, value in (('source', 'php74-php'), ('source_rpm', 'php-custom.src.rpm'),
                               ('arch', 'aarch64'), ('version', '7.4.33-31.el7.remi'),
                               ('version', '7.4.33-2.amzn2')):
                inv = inventory(route); inv['packages'][0][key] = value
                with self.subTest(route=route, key=key, value=value):
                    self.assertIsNone(guard.oc_source_route(inv, 'x86_64'))
            inv = inventory(route); inv['os']['version_id'] = '2023'
            self.assertIsNone(guard.oc_source_route(inv, 'x86_64'))
            self.assertIsNone(guard.oc_source_route(inventory(route), 'aarch64'))

    def test_ubuntu_ppa_route_never_accepts_official_or_other_distribution_packaging(self):
        for version in ('7.4.3-4ubuntu2.29', '1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1',
                        '1:7.4.33-31+ubuntu20.04.1+deb.sury.org+1evil', '1:7.4.32-1+ubuntu20.04.1+deb.sury.org+1'):
            inv = inventory('ubuntu20'); inv['packages'][0]['version'] = version
            with self.subTest(version=version): self.assertIsNone(guard.oc_source_route(inv, 'x86_64'))
        for field, value in (('source', 'php8.2'), ('arch', 'i386')):
            inv = inventory('ubuntu20'); inv['packages'][0][field] = value
            self.assertIsNone(guard.oc_source_route(inv, 'x86_64'))

    def test_empty_mixed_and_unknown_package_sets_never_select_native_recipe(self):
        inv = inventory(); inv['packages'] = []
        self.assertIsNone(guard.oc_source_route(inv, 'x86_64'))
        inv = inventory(); inv['packages'].append(dict(name='php82-cli', source='php82',
            version='8.2.34-1', upstream='8.2.34', arch='x86_64'))
        self.assertIsNone(guard.oc_source_route(inv, 'x86_64'))
        inv = inventory(); inv['package_manager'] = 'dnf'
        self.assertIsNone(guard.oc_source_route(inv, 'x86_64'))

    def test_receipt_recipe_context_is_restored_even_when_assessment_raises(self):
        guard.BI_ACTIVE_RECIPE = 'original'; guard.BI_RECEIPT = '/original.json'
        def fail(inv, receipt):
            self.assertEqual(guard.RB_RECIPE, guard.BI_ACTIVE_RECIPE)
            raise RuntimeError('assessment failure')
        with mock.patch.object(guard, 'bi_receipt', return_value={}, create=True), \
             mock.patch.object(guard, 'bi_assess', side_effect=fail, create=True), self.assertRaises(RuntimeError):
            guard.oc_assess(inventory('remi'), 'remi')
        self.assertEqual(('original','/original.json'), (guard.BI_ACTIVE_RECIPE, guard.BI_RECEIPT))


class OneclickTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.inv = inventory()
        self.findings = [dict(kind='package', package_name='php-cli', status='affected')]
        self.plan = dict(updates=[], blockers=[dict(reason='no verified repository candidate')])
        self.mocks = {}
        defaults = dict(
            be_report_directory=self.temp.name, collect_inventory=self.inv,
            oc_assess=self.findings, manager_capabilities=dict(automatic_fix=True, blockers=[]),
            fetch_candidates={}, enrich_origin=None, build_plan=self.plan,
            service_preflight=dict(services=['php-fpm.service'], blockers=[], checks=[]),
            health_checks=[], package_transaction=dict(ok=True), execute_repair=dict(ok=True),
            residual_process_check=dict(ok=True, errors=[]), acquire_repair_lock=9877,
            oc_source_apply=0, show_summary=None, print_blockers=None, show_package_lock=None, say=None)
        for name, result in defaults.items():
            patch = mock.patch.object(guard, name, return_value=result, create=True)
            self.mocks[name] = patch.start(); self.addCleanup(patch.stop)
        for target, attribute, value in ((guard.sys,'platform','linux'),):
            patch = mock.patch.object(target, attribute, value); patch.start(); self.addCleanup(patch.stop)
        for target, attribute, value in ((guard.os,'geteuid',0),(guard.os,'umask',0),
                                          (guard.os,'uname',('Linux','','','','x86_64')),
                                          (guard.os,'open',9876),(guard.os,'close',None)):
            patch = mock.patch.object(target, attribute, return_value=value); patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch('fcntl.flock'); patch.start(); self.addCleanup(patch.stop)

    def run_main(self, args):
        code = guard.php74_patch_main(args)
        return code, json.loads((pathlib.Path(self.temp.name) / 'oneclick.json').read_text())

    def test_default_and_plan_yes_never_install_build_dependencies_or_php(self):
        for args in ([], ['plan'], ['plan','--yes']):
            with self.subTest(args=args):
                code, report = self.run_main(args)
                self.assertEqual(0, code); self.assertEqual('route_plan_ready', report['result'])
                self.assertEqual('al2', report['selected_route'])
                self.mocks['oc_source_apply'].assert_not_called()
                self.mocks['execute_repair'].assert_not_called()
                self.mocks['fetch_candidates'].assert_called_with(self.inv, guard.POLICY, refresh=True, lock_wait=300)

    def test_amazon_linux_python27_platform_is_accepted(self):
        with mock.patch.object(guard.sys, 'platform', 'linux2'):
            code, report = self.run_main(['plan'])
        self.assertEqual(0, code)
        self.assertEqual('al2', report['selected_route'])
        self.mocks['oc_source_apply'].assert_not_called()

    def test_audit_never_refreshes_metadata_or_runs_mutating_path_even_with_yes(self):
        code, report = self.run_main(['audit','--yes'])
        self.assertEqual(10, code); self.assertEqual('unresolved', report['result'])
        self.mocks['fetch_candidates'].assert_called_once_with(self.inv, guard.POLICY, refresh=False, lock_wait=300)
        for name in ('oc_source_apply','execute_repair','package_transaction','service_preflight'):
            self.mocks[name].assert_not_called()

    def test_coverage_and_service_blockers_stop_before_environment_installation(self):
        self.mocks['oc_assess'].return_value = self.findings + [dict(kind='container',status='unknown')]
        code, report = self.run_main(['--yes'])
        self.assertEqual(10, code); self.assertEqual('blocked_inventory', report['result'])
        self.mocks['service_preflight'].assert_not_called(); self.mocks['oc_source_apply'].assert_not_called()
        self.mocks['oc_assess'].return_value = self.findings
        self.mocks['service_preflight'].return_value = dict(services=[], blockers=[dict(reason='unmapped process')])
        code, report = self.run_main(['--yes'])
        self.assertEqual(10, code); self.assertEqual('blocked_services', report['result'])
        self.mocks['oc_source_apply'].assert_not_called(); self.mocks['execute_repair'].assert_not_called()

    def test_requested_health_check_is_not_reported_as_tested_when_preflight_blocks(self):
        self.mocks['service_preflight'].return_value = dict(services=[], blockers=[dict(reason='unmapped process')])
        code, report = self.run_main(['--yes','--health-url','https://example.test/health'])
        self.assertEqual(10, code); self.assertTrue(report['business_health_requested'])
        self.assertFalse(report['business_health_tested']); self.mocks['health_checks'].assert_not_called()

    def test_failed_health_check_blocks_before_build_or_repository_install(self):
        self.mocks['health_checks'].return_value = [dict(ok=False, url='https://example.test/health')]
        code, report = self.run_main(['--yes','--health-url','https://example.test/health'])
        self.assertEqual(10, code); self.assertEqual('blocked_health_before', report['result'])
        self.assertTrue(report['business_health_tested']); self.mocks['oc_source_apply'].assert_not_called()

    def test_receipt_verified_rerun_is_offline_and_does_not_build(self):
        self.mocks['oc_assess'].return_value = [dict(kind='package',status='fixed')]
        code, report = self.run_main(['--yes'])
        self.assertEqual(0, code); self.assertEqual('already_fixed_within_scope', report['result'])
        self.mocks['fetch_candidates'].assert_not_called(); self.mocks['oc_source_apply'].assert_not_called()
        self.mocks['execute_repair'].assert_not_called(); self.assertFalse(report['business_health_tested'])

    def test_receipt_verified_rerun_still_runs_explicit_health_check(self):
        self.mocks['oc_assess'].return_value = [dict(kind='package',status='fixed')]
        self.mocks['health_checks'].return_value = [dict(ok=False)]
        code, report = self.run_main(['--yes','--health-url','https://example.test/health'])
        self.assertEqual(10, code); self.assertEqual('blocked_health_before', report['result'])
        self.mocks['health_checks'].assert_called_once_with(['https://example.test/health'], None)
        self.assertTrue(report['business_health_tested']); self.mocks['fetch_candidates'].assert_not_called()

    def test_same_branch_repository_repair_takes_priority_over_source_build(self):
        self.plan.update(updates=[dict(name='php-cli', version='7.4.33-2.amzn2')], blockers=[])
        self.mocks['oc_assess'].side_effect = [self.findings,self.findings,[dict(kind='package',status='fixed')]]
        code, report = self.run_main(['--yes'])
        self.assertEqual(0, code); self.assertEqual('repository', report['selected_route'])
        self.assertEqual('fixed_within_scope', report['result'])

        self.mocks['execute_repair'].assert_called_once(); self.mocks['oc_source_apply'].assert_not_called()

    def test_remi_postcheck_queries_the_new_installed_signed_state(self):
        self.mocks['build_plan'].return_value = dict(updates=[dict(name='php-cli', vendor_provenance={'kind': 'remi-rpm'})], blockers=[])
        self.mocks['oc_assess'].side_effect = [self.findings, self.findings, [dict(kind='package', status='fixed')]]
        before_candidates = {'php-cli': [{'vendor_provenance': {'installed_match': False}}]}
        after_candidates = {'php-cli': [{'vendor_provenance': {'installed_match': True}}]}
        self.mocks['fetch_candidates'].side_effect = [before_candidates, after_candidates]
        code, report = self.run_main(['--yes'])
        self.assertEqual(0, code)
        self.assertEqual('fixed_within_scope', report['result'])
        self.assertEqual(2, self.mocks['fetch_candidates'].call_count)
        self.assertFalse(self.mocks['fetch_candidates'].call_args.kwargs['refresh'])
        self.assertEqual(after_candidates, self.mocks['enrich_origin'].call_args.args[1])
        self.mocks['execute_repair'].assert_called_once(); self.mocks['oc_source_apply'].assert_not_called()

    def test_repository_partial_failure_never_falls_back_to_source_build(self):
        self.plan.update(updates=[dict(name='php-cli',version='7.4.33-2.amzn2')], blockers=[])
        self.mocks['execute_repair'].return_value = dict(ok=False, may_have_changed=True)
        code, report = self.run_main(['--yes'])
        self.assertEqual(20, code); self.assertEqual('installation_or_verification_incomplete', report['result'])
        self.mocks['oc_source_apply'].assert_not_called()

    def test_busy_package_query_retains_owner_details_and_never_starts_source_repair(self):
        lock = dict(pid=3416, path='/var/run/yum.pid', wait_seconds=300, backend='yum')
        self.mocks['fetch_candidates'].side_effect = guard.PackageManagerLockTimeout('busy', lock)
        code, report = self.run_main(['--yes'])
        self.assertEqual(20, code); self.assertEqual('package_manager_busy_no_update', report['result'])
        self.assertEqual(lock, report['package_manager_lock'])
        self.mocks['show_package_lock'].assert_called_once_with(lock)
        self.mocks['oc_source_apply'].assert_not_called(); self.mocks['execute_repair'].assert_not_called()

    def test_nonroot_and_bad_parallelism_stop_before_inventory(self):
        with mock.patch.object(guard.os, 'geteuid', return_value=1000):
            self.assertEqual(2, guard.php74_patch_main(['--yes']))
        self.mocks['collect_inventory'].assert_not_called()
        for jobs in ('0', '33', '-1'):
            with self.subTest(jobs=jobs), mock.patch('sys.stderr'), self.assertRaises(SystemExit) as raised:
                guard.php74_patch_main(['--jobs', jobs])
            self.assertEqual(2, raised.exception.code)
        self.mocks['collect_inventory'].assert_not_called()

    def test_invalid_build_monitor_limits_stop_before_inventory(self):
        for option, values in (('--build-timeout', ('0', '59', '86401', 'inf')),
                               ('--progress-interval', ('0', '4', '301', 'bad'))):
            for value in values:
                with self.subTest(option=option, value=value), mock.patch('sys.stderr'), \
                     self.assertRaises(SystemExit) as raised:
                    guard.php74_patch_main([option, value, '--yes'])
                self.assertEqual(2, raised.exception.code)
        self.mocks['collect_inventory'].assert_not_called()

    def test_repository_success_requires_nonempty_fixed_assessment_and_no_residual_process(self):
        self.plan.update(updates=[dict(name='php-cli',version='7.4.33-2.amzn2')], blockers=[])
        for assessment, residual in (([],dict(ok=True)),([dict(status='affected')],dict(ok=True)),
                                     ([dict(status='fixed')],dict(ok=False))):
            self.mocks['oc_assess'].side_effect = [self.findings,self.findings,assessment]
            self.mocks['residual_process_check'].return_value = residual
            with self.subTest(assessment=assessment,residual=residual):
                code, report = self.run_main(['--yes'])
                self.assertEqual(10, code); self.assertEqual('unresolved_after_update', report['result'])

    def test_missing_verified_recipe_never_auto_crossgrades_ubuntu_official_php(self):
        self.inv.clear(); self.inv.update(inventory('ubuntu20'))
        self.inv['packages'][0].update(version='7.4.3-4ubuntu2.29',upstream='7.4.3')
        code, report = self.run_main(['--yes'])
        self.assertEqual(10, code); self.assertEqual('no_verified_route', report['result'])
        self.mocks['oc_source_apply'].assert_not_called(); self.mocks['service_preflight'].assert_not_called()

    def test_no_php74_mixed_branch_and_unsupported_manager_never_install(self):
        for variation in ('none','mixed','unsupported'):
            self.inv.clear(); self.inv.update(inventory())
            self.mocks['manager_capabilities'].return_value = dict(automatic_fix=True,blockers=[])
            if variation == 'none': self.inv['packages'] = []
            elif variation == 'mixed': self.inv['packages'].append(dict(name='php82',source='php82',version='8.2.35'))
            else: self.mocks['manager_capabilities'].return_value = dict(automatic_fix=False,blockers=[dict(reason='apk')])
            with self.subTest(variation=variation): self.assertEqual(10,self.run_main(['--yes'])[0])
        self.mocks['oc_source_apply'].assert_not_called(); self.mocks['execute_repair'].assert_not_called()


class BuildHandoffTests(unittest.TestCase):
    def setUp(self):
        self.args = types.SimpleNamespace(build_user='builder',work_dir='/home/builder/php74',jobs=2,
            lock_wait=300,service=['worker.service'],health_url=['https://example.test/health'],
            health_host='example.test',scan_root=['/opt/custom'])
        self.report = dict(inventory_before=inventory(),service_preflight=dict(services=['php-fpm.service']))
        self.mocks = {}
        for name, result in dict(oc_builder_account=types.SimpleNamespace(pw_name='builder',pw_dir='/home/builder'),
                write_json=None, say=None, baota_al2_build_main=0, native_build_main=0,
                baota_install_main=0,remi_install_main=0,deb_install_main=0,
                collect_inventory=inventory(),oc_assess=[dict(kind='package',status='fixed')],
                residual_process_check=dict(ok=True,errors=[])).items():
            patch=mock.patch.object(guard,name,return_value=result,create=True)
            self.mocks[name]=patch.start(); self.addCleanup(patch.stop)

    def test_failed_build_never_installs_or_adopts_an_old_build(self):
        for route in ('al2','remi','ubuntu20'):
            self.mocks['baota_al2_build_main'].return_value = 20
            self.mocks['native_build_main'].return_value = 20
            with self.subTest(route=route):
                self.assertEqual(20,guard.oc_source_apply(route,self.args,self.report,'/report'))
                self.assertEqual('build_incomplete_no_php_deployment',self.report['result'])
        for name in ('baota_install_main','remi_install_main','deb_install_main','collect_inventory'):
            self.mocks[name].assert_not_called()

    def test_custom_build_limits_reach_all_native_build_routes(self):
        self.args.build_timeout, self.args.progress_interval = 7200, 30
        for route, command in (('al2', 'baota_al2_build_main'),
                               ('remi', 'native_build_main'), ('ubuntu20', 'native_build_main')):
            self.mocks[command].return_value = 20
            with self.subTest(route=route), mock.patch.object(guard, 'oc_maintenance_run') as maintenance:
                self.assertEqual(20, guard.oc_source_apply(route, self.args, self.report, '/report'))
                args = self.mocks[command].call_args.args[-1]
                self.assertEqual('7200', args[args.index('--build-timeout') + 1])
                self.assertEqual('30', args[args.index('--progress-interval') + 1])
                maintenance.assert_not_called()

    def test_source_build_then_installer_then_original_scope_recheck(self):
        calls=[]
        self.mocks['native_build_main'].side_effect=lambda *a: calls.append('build') or 0
        self.mocks['remi_install_main'].side_effect=lambda *a: calls.append('install') or 0
        self.mocks['collect_inventory'].side_effect=lambda *a: calls.append('inventory') or inventory('remi')
        self.assertEqual(0,guard.oc_source_apply('remi',self.args,self.report,'/report'))
        self.assertEqual(['build','install','inventory'],calls)
        self.assertEqual('all',self.mocks['native_build_main'].call_args.args[1][0])
        self.assertIn('--yes',self.mocks['native_build_main'].call_args.args[1])
        argv=self.mocks['remi_install_main'].call_args.args[0]
        self.assertEqual(['fix','--yes'],argv[:2]); self.assertIn('worker.service',argv)
        self.assertIn('https://example.test/health',argv); self.assertIn('example.test',argv)
        self.mocks['collect_inventory'].assert_called_once_with(['/opt/custom'])
        self.assertEqual('fixed_within_scope',self.report['result'])

    def test_installer_failure_is_not_relabelled_as_fixed(self):
        self.mocks['deb_install_main'].return_value=10
        self.assertEqual(10,guard.oc_source_apply('ubuntu20',self.args,self.report,'/report'))
        self.assertEqual('installation_or_verification_incomplete',self.report['result'])
        self.mocks['collect_inventory'].assert_not_called()

    def test_new_unmanaged_runtime_in_extra_scan_root_prevents_success(self):
        self.mocks['oc_assess'].return_value=[dict(kind='package',status='fixed'),
                                               dict(kind='unmanaged_runtime',status='unknown')]
        self.assertEqual(10,guard.oc_source_apply('al2',self.args,self.report,'/report'))
        self.assertEqual('unresolved_after_update',self.report['result'])

    def test_no_assessment_or_residual_process_never_claims_fixed_after_source_install(self):
        self.mocks['oc_assess'].return_value=[]
        self.assertEqual(10,guard.oc_source_apply('al2',self.args,self.report,'/report'))
        self.mocks['oc_assess'].return_value=[dict(status='fixed')]
        self.mocks['residual_process_check'].return_value=dict(ok=False,errors=[dict(pid=42)])
        self.assertEqual(10,guard.oc_source_apply('al2',self.args,self.report,'/report'))


if __name__ == '__main__':
    unittest.main()
