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
    def __init__(self, name='gcc', version='2.0', arch='x86_64', repo='amzn2-core',
                 epoch=0, release='1.amzn2'):
        self.name, self.version, self.arch, self.repoid = name, version, arch, repo
        self.epoch, self.release = epoch, release
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


class El7CloudRepositoryTests(unittest.TestCase):
    def repos(self, signed=True, enabled=True):
        repos = RepositorySet()
        repos.repos = {name: types.SimpleNamespace(id=name, gpgcheck=True, enabled=True)
                       for name in ('os', 'updates', 'extras', 'epel', 'remi-safe', 'remi-php74', 'nginx')}
        repos.repos['os'].gpgcheck = signed
        repos.repos['os'].enabled = enabled
        return repos

    def test_tencent_os_is_selected_without_enabling_unrelated_or_disabled_repos(self):
        for enabled in (True, False):
            worker = make_worker(); worker['ENV_PROFILE'] = 'remi-el7'
            repos = self.repos(enabled=enabled)
            worker['env_configure_repos'](types.SimpleNamespace(repos=repos))
            self.assertEqual(enabled, repos.repos['os'].enabled)
            self.assertFalse(repos.repos['nginx'].enabled)
            evidence = worker['ENV_ACTIVITY']['repositories']
            self.assertEqual(['nginx'], evidence['excluded'])
            self.assertEqual(enabled, 'os' in evidence['selected'])

    def test_unsigned_os_is_rejected_before_repo_selection_changes(self):
        worker = make_worker(); worker['ENV_PROFILE'] = 'remi-el7'
        repos = self.repos(signed=False)
        with self.assertRaisesRegex(RuntimeError, 'GPG checking disabled: os'):
            worker['env_configure_repos'](types.SimpleNamespace(repos=repos))
        self.assertTrue(repos.repos['nginx'].enabled)

    def test_os_packages_keep_signature_architecture_and_runtime_guards(self):
        worker = make_worker(); worker['ENV_PROFILE'] = 'remi-el7'
        repos = self.repos()
        worker['env_configure_repos'](types.SimpleNamespace(repos=repos))
        with mock.patch.dict(sys.modules, {'rpm': types.SimpleNamespace(labelCompare=compare)}):
            pkg = Package('aspell-devel', '0.60.6.1', repo='os', epoch=12, release='9.el7')
            changes = worker['env_changes']([('install', pkg)], {}, repos.getRepo)
            self.assertEqual('os', changes[0]['repo'])
            self.assertEqual('12:0.60.6.1-9.el7', changes[0]['version'])
            for bad in (Package('php', repo='os'), Package('aspell-devel', arch='i686', repo='os')):
                with self.assertRaises(RuntimeError):
                    worker['env_changes']([('install', bad)], {}, repos.getRepo)
        base = types.SimpleNamespace(repos=repos, sigCheckPkg=lambda pkg: (1, 'fixture bad signature'))
        with self.assertRaisesRegex(RuntimeError, 'signature validation failed'):
            worker['env_verify_signatures'](base, [pkg])


class HttpdDependencySelectionTests(unittest.TestCase):
    def setUp(self):
        self.worker = make_worker()
        patch = mock.patch.dict(sys.modules, {'rpm': types.SimpleNamespace(labelCompare=compare)})
        patch.start()
        self.addCleanup(patch.stop)
        self.base = types.SimpleNamespace(repos=RepositorySet())
        self.runtime = Package('httpd', '2.4.62', release='1.amzn2.0.2')
        self.match = Package('httpd-devel', '2.4.62', release='1.amzn2.0.2')
        self.newer = Package('httpd-devel', '2.4.65', release='1.amzn2.0.1')

    def select(self, providers, installed=None, requirement='httpd-devel >= 2.0.46-1'):
        before = self.worker['env_snapshot']([self.runtime] if installed is None else installed)
        return self.worker['env_httpd_devel_provider'](self.base, requirement, before, providers)

    def test_selects_matching_version_release_and_arch_instead_of_latest(self):
        same_version_wrong_release = Package('httpd-devel', '2.4.62', release='1.amzn2.0.3')
        self.assertIs(self.match, self.select([self.newer, same_version_wrong_release, self.match]))
        evidence = self.worker['ENV_ACTIVITY']['dependency_selection'][0]
        self.assertEqual('selected', evidence['state'])
        self.assertEqual(3, evidence['candidate_count'])
        self.assertEqual(1, evidence['matching_count'])
        self.assertEqual('2.4.62-1.amzn2.0.2', evidence['selected']['version'])
        json.dumps(evidence)

    def test_epoch_is_part_of_matching_native_evr(self):
        self.runtime.epoch = 2
        with self.assertRaisesRegex(RuntimeError, 'matches installed httpd 2:'):
            self.select([self.match])
        self.match.epoch = '2'
        self.assertIs(self.match, self.select([self.match, self.newer]))

    def test_missing_exact_candidate_blocks_without_falling_back_to_newer(self):
        with self.assertRaisesRegex(RuntimeError, 'web server will not be upgraded'):
            self.select([self.newer])
        evidence = self.worker['ENV_ACTIVITY']['dependency_selection'][0]
        self.assertEqual('blocked', evidence['state'])
        self.assertEqual('matching_httpd_devel_unavailable', self.worker['ENV_ACTIVITY']['error_kind'])
        self.assertNotIn('selected', evidence)

    def test_native_versioned_provides_results_are_not_bypassed(self):
        # A matching EVR exists in the repository but is absent from the native
        # >= lookup. The selector must not search by package name and install it.
        with self.assertRaisesRegex(RuntimeError, 'httpd-devel >= 2.4.65'):
            self.select([self.newer], requirement='httpd-devel >= 2.4.65')
        with self.assertRaisesRegex(RuntimeError, 'No allowed GPG-checked'):
            self.select([])

    def test_wrong_arch_name_unapproved_or_unsigned_repository_cannot_match(self):
        for attribute, value in (('arch', 'i686'), ('arch', 'noarch'),
                                 ('name', 'other-devel'), ('repoid', 'unrelated')):
            candidate = Package('httpd-devel', '2.4.62', release='1.amzn2.0.2')
            setattr(candidate, attribute, value)
            with self.subTest(attribute=attribute, value=value), self.assertRaises(RuntimeError):
                self.select([candidate])
        self.base.repos.getRepo('amzn2-core').gpgcheck = False
        with self.assertRaises(RuntimeError):
            self.select([self.match])

    def test_duplicate_providers_choose_approved_repo_deterministically(self):
        other = Package('httpd-devel', '2.4.62', repo='amzn2extra-php7.4', release='1.amzn2.0.2')
        for candidates in ([other, self.match], [self.match, other]):
            self.assertIs(self.match, self.select(candidates))
        self.base.repos.getRepo('amzn2-core').gpgcheck = False
        self.assertIs(other, self.select([self.match, other]))

    def test_multiple_installed_versions_or_architectures_require_review(self):
        for installed in ([self.runtime, Package('httpd', '2.4.65')],
                          [self.runtime, Package('httpd', '2.4.62', arch='i686')],
                          [Package('httpd', '2.4.62', arch='i686')]):
            with self.subTest(installed=installed), self.assertRaisesRegex(RuntimeError, 'exactly one'):
                self.select([self.match], installed=installed)

    def test_narrow_policy_preserves_other_profiles_requirements_and_fresh_hosts(self):
        self.assertIsNone(self.select([self.match], installed=[]))
        self.assertIsNone(self.select([self.match], requirement='httpd-tools'))
        self.worker['ENV_PROFILE'] = 'remi-el7'
        self.assertIsNone(self.select([self.match]))
        self.assertEqual([], self.worker['ENV_ACTIVITY']['dependency_selection'])


class NativeFlowTests(unittest.TestCase):
    def setUp(self):
        self.worker = make_worker()
        self.state = dict(installed=False, installs=[], downloads=0, signatures=0, runs=0,
                          unlocked=False, close=0, package=Package(), missing_provider=False,
                          signature_error=False, download_error=False, run_error=False,
                          after_extra=False, mutate_solver=False, baseline=[], providers=None,
                          solver_httpd_upgrade=False)
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
                if state['missing_provider']: return []
                return state['providers'] if state['providers'] is not None else [state['package']]
            def install(base, **kwargs):
                state['installs'].append(kwargs)
                state['package'] = kwargs.get('po', state['package'])
                base.members = [types.SimpleNamespace(output_state=constants.TS_INSTALL, po=state['package'])]
            def buildTransaction(base):
                if state['solver_httpd_upgrade']:
                    base.members.append(types.SimpleNamespace(output_state=constants.TS_UPDATE,
                                                             po=Package('httpd', '2.4.65')))
                    base.members.append(types.SimpleNamespace(output_state=constants.TS_UPDATED,
                                                             po=state['baseline'][0]))
                return 2, []
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
            packages = list(state['baseline']) + ([state['package']] if state['installed'] else [])
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

    def prepare_httpd(self):
        self.state['baseline'] = [Package('httpd', '2.4.62', release='1.amzn2.0.2')]
        self.state['package'] = Package('httpd-devel', '2.4.65')
        matching = Package('httpd-devel', '2.4.62', release='1.amzn2.0.2')
        self.state['providers'] = [self.state['package'], matching]
        return matching

    def test_httpd_plan_pins_exact_provider_without_changing_installed_runtime(self):
        matching = self.prepare_httpd()
        result = self.run_request(requirements=['httpd-devel >= 2.0.46-1'])
        self.assertTrue(result['ok'], result)
        self.assertEqual([{'po': matching}], self.state['installs'])
        self.assertEqual(['httpd-devel'], [item['name'] for item in result['changes']])
        self.assertEqual(result['snapshots']['before'][0], result['snapshots']['expected_after'][0])
        self.assertEqual(0, self.state['runs'])

    def test_httpd_matching_install_preserves_signature_snapshot_and_requirement_gates(self):
        self.prepare_httpd()
        result = self.run_request(True, requirements=['httpd-devel >= 2.0.46-1'])
        self.assertTrue(result['ok'], result)
        self.assertEqual(2, self.state['signatures'])
        self.assertEqual(result['snapshots']['expected_after'], result['snapshots']['after'])
        self.assertEqual('2.4.62-1.amzn2.0.2', result['dependency_selection'][0]['selected']['version'])

    def test_httpd_missing_matching_provider_retains_block_evidence_without_download(self):
        self.prepare_httpd()
        self.state['providers'] = [self.state['package']]
        result = self.run_request(True, requirements=['httpd-devel >= 2.0.46-1'])
        self.assertFalse(result['ok'])
        self.assertEqual('matching_httpd_devel_unavailable', result['error_kind'])
        self.assertEqual('blocked', result['dependency_selection'][0]['state'])
        self.assertFalse(result['may_have_changed'])
        self.assertEqual([], self.state['installs'])
        self.assertEqual(0, self.state['downloads'])
        self.assertEqual(0, self.state['runs'])

    def test_httpd_runtime_change_is_still_blocked_after_exact_provider_selection(self):
        self.prepare_httpd()
        self.state['solver_httpd_upgrade'] = True
        result = self.run_request(True, requirements=['httpd-devel >= 2.0.46-1'])
        self.assertFalse(result['ok'])
        self.assertIn('Protected runtime/service package change blocked: httpd', result['error'])
        self.assertEqual('selected', result['dependency_selection'][0]['state'])
        self.assertFalse(result['may_have_changed'])
        self.assertEqual(0, self.state['downloads'])

    def test_already_satisfied_httpd_requirement_does_not_force_repository_alignment(self):
        self.prepare_httpd()
        self.state['installed'] = True
        result = self.run_request(True, requirements=['httpd-devel >= 2.0.46-1'], expected_changes=[])
        self.assertTrue(result['ok'], result)
        self.assertEqual(['httpd-devel >= 2.0.46-1'], result['already_satisfied'])
        self.assertEqual([], result['dependency_selection'])
        self.assertEqual([], self.state['installs'])
        self.assertEqual(0, self.state['runs'])


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
