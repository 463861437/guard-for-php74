"""Native dependency-planner safety checks; never modify host packages."""
import pathlib
import json
import sys
import tempfile
import types
import unittest
from unittest import mock

SRC = pathlib.Path(__file__).resolve().parents[1] / 'src'
backend = {'__name__': 'build_environment_backend_test'}
exec(compile((SRC / 'rpm_backend.py').read_text(), '<rpm-backend>', 'exec'), backend)
exec(compile((SRC / 'build_env_backend.py').read_text(), '<build-env-backend>', 'exec'), backend)


def make_worker():
    worker = {'__name__': 'build_environment_worker_test'}
    source = backend['_RPM_WORKER'].rsplit('if __name__', 1)[0] + backend['_BUILD_ENV_WORKER_SUFFIX']
    exec(compile(source, '<build-env-worker>', 'exec'), worker)
    return worker


def compare(left, right):
    def key(value):
        return int(value[0]), tuple(int(v) for v in value[1].split('.')), value[2]
    return (key(left) > key(right)) - (key(left) < key(right))


class Package:
    def __init__(self, name='gcc', version='2.0', arch='x86_64', repo='amzn2-core'):
        self.name, self.version, self.arch, self.repoid = name, version, arch, repo
        self.epoch, self.release = 0, '1.amzn2'
        self.sourcerpm = name + '-' + version + '-' + self.release + '.src.rpm'


class DependencyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.worker = make_worker()
        patch = mock.patch.dict(sys.modules, {'rpm': types.SimpleNamespace(labelCompare=compare)})
        patch.start()
        self.addCleanup(patch.stop)
        self.repo = lambda name: types.SimpleNamespace(gpgcheck=True)

    def test_requirements_preserve_native_version_constraints(self):
        checked, internal = self.worker['env_requirements']([
            'curl-devel >= 7.9', 'pkgconfig(libsodium) >= 1.0.9', '/usr/bin/perl',
            'gcc', 'gcc', 'rpmlib(CompressedFileNames) <= 3.0.4-1'])
        self.assertIn('curl-devel >= 7.9', checked)
        self.assertEqual(4, len(checked))
        self.assertEqual(['rpmlib(CompressedFileNames) <= 3.0.4-1'], internal)

    def test_requirement_patterns_and_shell_syntax_are_not_accepted(self):
        for bad in ('gcc*', 'gcc[0-9]', '@development', '--nogpgcheck', 'gcc;id',
                    '$(id)', 'gcc\nphp', 'gcc >=', '', 5, None):
            with self.subTest(requirement=bad), self.assertRaises(RuntimeError):
                self.worker['env_requirements']([bad])

    def test_empty_or_unbounded_requirement_lists_are_rejected(self):
        for bad in ([], ['gcc'] * 301, 'gcc', ['rpmlib(Foo) <= 1.0']):
            with self.subTest(requirements=bad), self.assertRaises(RuntimeError):
                self.worker['env_requirements'](bad)

    def test_services_are_protected_and_build_layout_exceptions_are_exact(self):
        protected = ['php', 'php74-php', 'php-pecl-redis', 'pecl-foo', 'lsphp74',
                     'httpd', 'httpd24', 'nginx', 'nginx-mod-http-perl', 'apache2',
                     'supervisor', 'supervisord', 'cronie', 'crontabs', 'cron', 'at',
                     'postgresql14-server', 'mysql-community-server', 'MariaDB-server',
                     'mongodb-org-server', 'redis6', 'memcached', 'mod_ssl']
        for name in protected:
            with self.subTest(name=name):
                self.assertTrue(self.worker['env_protected'](name))
        for name in ['httpd-devel', 'httpd-tools', 'httpd-filesystem', 'nginx-filesystem',
                     'postgresql-devel', 'mariadb-devel', 'gcc', 'openssl-libs']:
            with self.subTest(name=name):
                self.assertFalse(self.worker['env_protected'](name))

    def test_install_and_paired_strict_upgrade_are_allowed(self):
        old = Package('openssl-devel', '1.0')
        new = Package('openssl-devel', '2.0')
        before = self.worker['env_snapshot']([old])
        changes = self.worker['env_changes'](
            [('install', Package()), ('upgrade', new), ('upgraded', old)], before, self.repo)
        self.assertEqual(['install', 'upgrade'], [item['action'] for item in changes])
        expected = self.worker['env_expected_snapshot'](before, changes)
        self.assertEqual(['2.0-1.amzn2'], expected[('openssl-devel', 'x86_64')])
        self.assertEqual(['1.0-1.amzn2'], before[('openssl-devel', 'x86_64')])

    def test_remove_downgrade_obsoletes_and_reinstall_blocked(self):
        for action in ('remove', 'downgrade', 'obsoletes', 'reinstall', 'forbidden'):
            with self.subTest(action=action), self.assertRaises(RuntimeError):
                self.worker['env_changes']([(action, Package())], {}, self.repo)

    def test_unpaired_same_version_and_reverse_upgrades_are_blocked(self):
        old = Package(version='2.0')
        before = self.worker['env_snapshot']([old])
        cases = [[('upgrade', Package(version='3.0'))],
                 [('upgraded', old)], [('upgrade', old), ('upgraded', old)],
                 [('upgrade', Package(version='1.0')), ('upgraded', old)],
                 [('install', old)]]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                self.worker['env_changes'](rows, before, self.repo)

    def test_protected_packages_unsigned_repos_and_wrong_arch_are_blocked(self):
        for pkg in [Package('php-devel'), Package('nginx'), Package(repo='third-party'),
                    Package(arch='i686')]:
            with self.subTest(package=pkg.name), self.assertRaises(RuntimeError):
                self.worker['env_changes']([('install', pkg)], {}, self.repo)
        with self.assertRaises(RuntimeError):
            self.worker['env_changes']([('install', Package())], {},
                                      lambda name: types.SimpleNamespace(gpgcheck=False))

    def test_snapshots_retain_multiple_installed_versions(self):
        snapshot = self.worker['env_snapshot']([Package('kernel', '1.0'), Package('kernel', '2.0')])
        self.assertEqual(['1.0-1.amzn2', '2.0-1.amzn2'], snapshot[('kernel', 'x86_64')])

    def test_solver_final_provides_must_meet_versioned_requirement(self):
        base = types.SimpleNamespace(returnInstalledPackagesByDep=lambda req: [],
                                     returnPackagesByDep=lambda req: [Package(version='2.0')])
        with self.assertRaisesRegex(RuntimeError, 'does not satisfy'):
            self.worker['env_verify_requirements'](base, ['gcc >= 2.0'],
                                                   {('gcc', 'x86_64'): ['1.0-1.amzn2']})


class RepositorySet:
    def __init__(self):
        self.repos = {name: types.SimpleNamespace(id=name, gpgcheck=True, enabled=name == 'unrelated')
                      for name in ('amzn2-core', 'amzn2extra-php7.4', 'unrelated')}

    def disableRepo(self, pattern):
        for repo in self.repos.values(): repo.enabled = False

    def enableRepo(self, name): self.repos[name].enabled = True
    def getRepo(self, name): return self.repos[name]
    def listEnabled(self): return [repo for repo in self.repos.values() if repo.enabled]


class NativeFlowTests(unittest.TestCase):
    def setUp(self):
        self.worker = make_worker()
        self.state = dict(installed=False, installs=[], downloads=0, signatures=0, runs=0,
                          unlocked=False, close=0, package=Package(), missing_provider=False,
                          signature_error=False, download_error=False, run_error=False,
                          after_extra=False, mutate_solver=False)
        state = self.state
        constants = types.ModuleType('yum.constants')
        constants.TS_INSTALL, constants.TS_TRUEINSTALL = 1, 2
        constants.TS_UPDATE, constants.TS_UPDATED = 3, 4
        class FakeYum:
            def __init__(base):
                state['base'] = base
                base.preconf = types.SimpleNamespace()
                base.conf = types.SimpleNamespace(installroot='/', persistdir='/var/lib/yum')
                base.repos = RepositorySet()
                base._lockfile = None
                base.members = []
                base.tsInfo = types.SimpleNamespace(getMembers=lambda: base.members)
            def doLock(base): base._lockfile = '/var/run/yum.pid'
            def doUnlock(base): state['unlocked'] = True
            def close(base): state['close'] += 1
            def closeRpmDB(base): pass
            def returnInstalledPackagesByDep(base, req):
                return [state['package']] if state['installed'] else []
            def returnPackagesByDep(base, req):
                return [] if state['missing_provider'] else [state['package']]
            def install(base, **kwargs):
                state['installs'].append(kwargs)
                base.members = [types.SimpleNamespace(output_state=constants.TS_INSTALL, po=state['package'])]
            def buildTransaction(base): return 2, []
            def downloadPkgs(base, packages):
                state['downloads'] += 1
                return ['download failed'] if state['download_error'] else []
            def sigCheckPkg(base, pkg):
                state['signatures'] += 1
                return (1, 'missing key') if state['signature_error'] else (0, '')
            def processTransaction(base):
                if state['mutate_solver']:
                    base.members.append(types.SimpleNamespace(output_state=constants.TS_INSTALL,
                                                             po=Package('php')))
                base.runTransaction(None)
            def runTransaction(base, callback):
                state['runs'] += 1
                state['installed'] = True
                return types.SimpleNamespace(return_code=1 if state['run_error'] else 0)
        yum = types.ModuleType('yum')
        yum.YumBase = FakeYum
        yum.constants = constants
        yum.misc = types.ModuleType('yum.misc')
        yum.misc.find_unfinished_transactions = lambda **kwargs: []
        patch = mock.patch.dict(sys.modules, {'yum': yum, 'yum.constants': constants, 'yum.misc': yum.misc,
                                              'rpm': types.SimpleNamespace(labelCompare=compare)})
        patch.start()
        self.addCleanup(patch.stop)
        def snapshot():
            packages = [state['package']] if state['installed'] else []
            if state['installed'] and state['after_extra']: packages.append(Package('php'))
            return self.worker['env_snapshot'](packages)
        self.worker['env_read_snapshot'] = snapshot
        self.worker['env_host_check'] = lambda execute: None
        self.worker['yum_acquire_lock'] = lambda base, wait: base.doLock()

    def run_request(self, execute=False, **kwargs):
        request = dict(requirements=['gcc >= 2.0'], execute=execute, lock_wait=0)
        request.update(kwargs)
        with tempfile.TemporaryDirectory() as temp:
            req, resp = pathlib.Path(temp) / 'request.json', pathlib.Path(temp) / 'response.json'
            req.write_text(json.dumps(request))
            with mock.patch.object(sys, 'argv', ['worker', str(req), str(resp)]):
                self.worker['env_main']()
            return json.loads(resp.read_text())

    def test_preview_does_not_download_install_or_modify_packages(self):
        result = self.run_request()
        self.assertTrue(result['ok'], result)
        self.assertEqual('environment_plan', result['state'])
        self.assertEqual([{'pattern': 'gcc >= 2.0'}], self.state['installs'])
        self.assertFalse(self.state['installed'])
        self.assertEqual(0, self.state['downloads'])
        self.assertEqual(0, self.state['runs'])
        self.assertTrue(self.state['unlocked'])

    def test_execute_checks_signatures_twice_and_final_snapshot(self):
        result = self.run_request(True)
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['executed'])
        self.assertFalse(result['may_have_changed'])
        self.assertEqual(2, self.state['signatures'])
        self.assertEqual(result['snapshots']['expected_after'], result['snapshots']['after'])

    def test_fully_installed_environment_is_idempotent(self):
        self.state['installed'] = True
        result = self.run_request(True, expected_changes=[])
        self.assertTrue(result['ok'], result)
        self.assertEqual([], result['changes'])
        self.assertFalse(result['executed'])
        self.assertEqual(0, self.state['runs'])

    def test_previous_preview_mismatch_prevents_download_and_execution(self):
        result = self.run_request(True, expected_changes=[])
        self.assertFalse(result['ok'])
        self.assertIn('previously reviewed plan', result['error'])
        self.assertFalse(result['may_have_changed'])
        self.assertEqual(0, self.state['downloads'])

    def test_missing_provider_blocks_with_clear_requirement(self):
        self.state['missing_provider'] = True
        result = self.run_request(True)
        self.assertFalse(result['ok'])
        self.assertIn('gcc >= 2.0', result['error'])
        self.assertFalse(result['may_have_changed'])

    def test_protected_runtime_dependency_is_blocked(self):
        self.state['package'] = Package('php-common')
        result = self.run_request(True)
        self.assertFalse(result['ok'])
        self.assertIn('php-common', result['error'])
        self.assertEqual(0, self.state['runs'])

    def test_missing_signing_key_never_enters_rpm_execution(self):
        self.state['signature_error'] = True
        result = self.run_request(True)
        self.assertFalse(result['ok'])
        self.assertIn('signature', result['error'])
        self.assertFalse(result['may_have_changed'])
        self.assertEqual(0, self.state['runs'])

    def test_download_failure_does_not_claim_package_changes(self):
        self.state['download_error'] = True
        result = self.run_request(True)
        self.assertFalse(result['ok'])
        self.assertFalse(result['may_have_changed'])
        self.assertEqual(0, self.state['runs'])

    def test_native_rpm_failure_explicitly_reports_partial_change_risk(self):
        self.state['run_error'] = True
        result = self.run_request(True)
        self.assertFalse(result['ok'])
        self.assertTrue(result['may_have_changed'])
        self.assertTrue(result['transaction_started'])
        self.assertIn('after', result['snapshots'])
        self.assertTrue(self.state['unlocked'])

    def test_unplanned_post_install_package_change_is_not_success(self):
        self.state['after_extra'] = True
        result = self.run_request(True)
        self.assertFalse(result['ok'])
        self.assertTrue(result['may_have_changed'])
        self.assertIn('snapshot differs', result['error'])

    def test_solver_mutation_inside_native_process_transaction_is_blocked(self):
        self.state['mutate_solver'] = True
        result = self.run_request(True)
        self.assertFalse(result['ok'])
        self.assertFalse(result['may_have_changed'])
        self.assertEqual(0, self.state['runs'])

    def test_lock_timeout_retains_owner_details(self):
        lock = {'pid': 123, 'path': '/var/run/yum.pid', 'wait_seconds': 0}
        def lock_error(base, seconds): raise self.worker['NativeLockTimeout']('busy', lock)
        self.worker['yum_acquire_lock'] = lock_error
        result = self.run_request(True)
        self.assertEqual('package_manager_lock_timeout', result['error_kind'])
        self.assertEqual(lock, result['lock'])
        self.assertFalse(result['may_have_changed'])
        self.assertFalse(self.state['unlocked'])

    def test_missing_or_unsigned_required_repo_fails_without_changing_config(self):
        for mode in ('missing', 'unsigned'):
            repos = RepositorySet()
            if mode == 'missing': del repos.repos['amzn2extra-php7.4']
            else: repos.repos['amzn2extra-php7.4'].gpgcheck = False
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                self.worker['env_configure_repos'](types.SimpleNamespace(repos=repos))
            self.assertTrue(repos.repos['unrelated'].enabled)

    def test_repository_selection_is_temporary_and_exact(self):
        repos = RepositorySet()
        self.worker['env_configure_repos'](types.SimpleNamespace(repos=repos))
        self.assertEqual({'amzn2-core', 'amzn2extra-php7.4'}, {repo.id for repo in repos.listEnabled()})


class WrapperTests(unittest.TestCase):
    def test_wrapper_rejects_invalid_lock_wait_before_worker_start(self):
        for value in (-1, 3601, True, '120'):
            result = backend['build_environment_transaction'](['gcc'], lock_wait=value)
            self.assertFalse(result['ok'])
            self.assertFalse(result['may_have_changed'])

    def test_wrapper_reports_uncertainty_if_execution_worker_dies(self):
        with mock.patch.dict(backend, {'_rpm_system_backend': lambda unused: ('/usr/bin/python', 'yum'),
                                       'run_cmd': lambda *args, **kwargs: {'code': -9}}), \
                mock.patch.object(backend['os'], 'geteuid', return_value=0):
            result = backend['build_environment_transaction'](['gcc'], execute=True)
        self.assertFalse(result['ok'])
        self.assertTrue(result['may_have_changed'])

    def test_wrapper_blocks_nonroot_execution_without_worker(self):
        with mock.patch.object(backend['os'], 'geteuid', return_value=1000):
            result = backend['build_environment_transaction'](['gcc'], execute=True)
        self.assertFalse(result['ok'])
        self.assertFalse(result['may_have_changed'])
        self.assertIn('Root', result['error'])


if __name__ == '__main__':
    unittest.main()
