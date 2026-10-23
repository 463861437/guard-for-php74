"""Native build dependency transactions and privilege boundaries, without installs."""
import argparse
import contextlib
import copy
import io
import json
import os
import pathlib
import platform
import sys
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = {'__name__': 'native_environment_test'}
for name in ('common', 'build_monitor', 'backport_builder', 'apt_backend', 'rpm_backend',
             'build_env_backend', 'build_environment', 'native_environment'):
    exec(compile((ROOT / ('src/' + name + '.py')).read_text(), name, 'exec'), MODULE)


def make_apt_worker():
    apt = types.ModuleType('apt'); native = types.ModuleType('apt_pkg')
    progress = types.ModuleType('apt.progress'); base = types.ModuleType('apt.progress.base')
    base.AcquireProgress = mock.Mock(); base.InstallProgress = mock.Mock()
    apt.progress = progress; progress.base = base
    modules = {'apt': apt, 'apt_pkg': native, 'apt.progress': progress, 'apt.progress.base': base}
    worker = {'__name__': 'native_apt_worker_test'}
    prefix = MODULE['APT_WORKER'].split('\ntry:\n    with open(sys.argv[1])', 1)[0]
    suffix = MODULE['NB_APT_ENV_WORKER'].split('\ntry:\n    with open(sys.argv[1])', 1)[0]
    with mock.patch.dict(sys.modules, modules):
        exec(prefix + suffix, worker)
    return worker, apt, native


def version(value='2', archive='focal-updates', trusted=True, architecture='amd64'):
    return types.SimpleNamespace(version=value, architecture=architecture,
        origins=[types.SimpleNamespace(origin='Ubuntu', archive=archive, trusted=trusted)])


class Package:
    def __init__(self, name='libfoo-dev', candidate=None, installed=None):
        self.name = name; self.fullname = name + ':amd64'
        self.candidate = candidate if candidate is not None else version()
        self.installed = installed
        self._pkg = types.SimpleNamespace(selected_state=0)
        self.marked_install = self.marked_upgrade = self.marked_delete = False
        self.marked_downgrade = self.marked_reinstall = False
        self.marked = []

    def mark_install(self, **kwargs):
        self.marked.append(kwargs)
        self.marked_install = self.installed is None
        self.marked_upgrade = self.installed is not None


class Cache:
    def __init__(self, packages=(), providers=None):
        self.packages = dict((p.name, p) for p in packages)
        self.providers = providers or {}
        self.broken_count = 0
        self.commit = mock.Mock(return_value=True)

    def __iter__(self): return iter(self.packages.values())
    def __contains__(self, name): return name in self.packages
    def __getitem__(self, name): return self.packages[name]
    def get_providing_packages(self, name): return self.providers.get(name, [])
    def get_changes(self):
        return [p for p in self if p.marked_install or p.marked_upgrade or p.marked_delete or
                p.marked_downgrade or p.marked_reinstall]


class AptDependencyTests(unittest.TestCase):
    def setUp(self):
        self.worker, self.apt, self.native = make_apt_worker()
        self.native.init_config = mock.Mock(); self.native.init_system = mock.Mock()
        self.native.config = mock.Mock(); self.native.config.find.return_value = 'amd64'
        self.native.SELSTATE_HOLD = 2
        self.native.SystemLock = mock.MagicMock()
        self.native.version_compare = lambda a,b: (int(a) > int(b)) - (int(a) < int(b))
        self.native.check_dep = lambda a,op,b: {'>=': int(a)>=int(b), '>': int(a)>int(b),
            '>>': int(a)>int(b), '<=': int(a)<=int(b), '<': int(a)<int(b),
            '<<': int(a)<int(b), '=': a==b}[op]
        self.groups = [[('libfoo-dev', '2', '>=')]]; self.conflicts = []
        self.native.parse_src_depends = mock.Mock(side_effect=lambda value,*args:
            self.groups if value == 'build deps' else self.conflicts)
        self.package = Package(); self.cache = Cache([self.package])
        self.apt.Cache = mock.Mock(return_value=self.cache)
        self.worker['open'] = lambda path: io.StringIO('ID=ubuntu\nVERSION_ID="20.04"\n')
        patch = mock.patch.object(self.worker['os'], 'uname', return_value=('Linux','','','','x86_64'))
        patch.start(); self.addCleanup(patch.stop)

    def run_request(self, **kwargs):
        data = dict(build_depends='build deps', build_conflicts='build conflicts', lock_wait=0, execute=False)
        data.update(kwargs)
        return self.worker['env_work'](data)

    def test_versioned_dependency_groups_are_parsed_natively_and_lock_held(self):
        result = self.run_request()
        self.assertTrue(result['ok'])
        self.assertEqual('2', result['changes'][0]['version'])
        self.native.parse_src_depends.assert_has_calls([
            mock.call('build deps', True, 'amd64'), mock.call('build conflicts', True, 'amd64')])
        self.native.SystemLock.return_value.__enter__.assert_called_once()
        self.native.SystemLock.return_value.__exit__.assert_called_once()
        self.cache.commit.assert_not_called()

    def test_unsatisfied_version_cannot_be_replaced_by_presence_only(self):
        self.package.candidate.version = '1'
        with self.assertRaisesRegex(RuntimeError, 'No permitted native provider'):
            self.run_request()
        self.cache.commit.assert_not_called()

    def test_alternative_provider_selected_when_first_missing(self):
        self.groups = [[('missing-dev', '', ''), ('libfoo-dev', '2', '>=')]]
        self.assertTrue(self.run_request()['ok'])
        self.assertEqual(1, len(self.package.marked))

    def test_unversioned_virtual_provider_allowed_but_version_is_not_package_version(self):
        self.cache.providers['virtual-dev'] = [self.package]
        self.groups = [[('virtual-dev', '', '')]]
        self.assertTrue(self.run_request()['ok'])
        self.assertEqual([], self.worker['options'](self.cache, ('virtual-dev', '1', '>='), False))

    def test_already_installed_version_is_reused_without_upgrading_to_latest(self):
        self.package.installed = version('2'); self.package.candidate = version('3')
        self.assertEqual([], self.run_request()['changes'])
        self.assertEqual([], self.package.marked)

    def test_existing_build_conflict_is_never_removed(self):
        conflict = Package('bind-dev', installed=version('1'))
        self.cache.packages[conflict.name] = conflict
        self.conflicts = [[('bind-dev', '', '')]]
        with self.assertRaisesRegex(RuntimeError, 'Installed Build-Conflicts'):
            self.run_request()
        self.assertFalse(conflict.marked_delete)
        self.cache.commit.assert_not_called()

    def test_solver_deletion_downgrade_reinstall_hold_or_runtime_change_is_rejected(self):
        for attr in ('marked_delete', 'marked_downgrade', 'marked_reinstall'):
            self.package.mark_install(); setattr(self.package, attr, True)
            with self.subTest(attr=attr), self.assertRaisesRegex(RuntimeError, 'Protected/unapproved'):
                self.worker['verified_changes'](self.cache)
            setattr(self.package, attr, False)
        self.package._pkg.selected_state = 2
        with self.assertRaises(RuntimeError): self.worker['verified_changes'](self.cache)
        for name in ('php7.4-cli', 'php7.4-fpm', 'nginx', 'apache2', 'supervisor', 'cron', 'systemd',
                     'cronie', 'crontabs', 'at', 'firebird3.0-server', 'firebird3.0-server-core',
                     'firebird2.5-super', 'valkey-server', 'valkey', 'couchdb', 'influxdb',
                     'clickhouse-server', 'libapache2-mod-fcgid'):
            p = Package(name); p.mark_install()
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                self.worker['verified_changes'](Cache([p]))

    def test_database_build_headers_remain_installable_without_server_exemption(self):
        for name in ('firebird-dev', 'firebird3.0-common', 'libfbclient2', 'postgresql-client-common',
                     'mysql-client', 'libmariadb-dev', 'valkey-dev'):
            p = Package(name); p.mark_install()
            with self.subTest(name=name):
                self.assertEqual('install', self.worker['verified_changes'](Cache([p]))[0]['action'])

    def test_existing_apache_binary_may_not_upgrade_but_empty_build_host_can_install_it(self):
        p = Package('apache2-bin'); p.mark_install()
        self.assertEqual('install', self.worker['verified_changes'](Cache([p]))[0]['action'])
        p.installed = version('1'); p.mark_install()
        with self.assertRaisesRegex(RuntimeError, 'Protected/unapproved'):
            self.worker['verified_changes'](Cache([p]))

    def test_wrong_release_untrusted_architecture_and_non_strict_upgrade_are_rejected(self):
        for v in (version(archive='jammy'), version(trusted=False), version(architecture='arm64')):
            p = Package(candidate=v); p.mark_install()
            with self.subTest(version=v), self.assertRaises(RuntimeError):
                self.worker['verified_changes'](Cache([p]))
        for v in ('1','2'):
            p = Package(candidate=version(v), installed=version('2')); p.mark_install()
            with self.assertRaisesRegex(RuntimeError, 'strict upgrades'):
                self.worker['verified_changes'](Cache([p]))

    def test_dependency_plan_change_is_rejected_before_commit(self):
        with self.assertRaisesRegex(RuntimeError, 'changed since preview'):
            self.run_request(execute=True, expected_changes=[])
        self.cache.commit.assert_not_called()
        self.assertFalse(self.worker['ACTIVITY']['may_have_changed'])

    def test_package_state_change_before_commit_is_rejected(self):
        changed = Cache([Package('unrelated', installed=version('1'))])
        self.apt.Cache.side_effect = [self.cache, changed]
        with self.assertRaisesRegex(RuntimeError, 'state changed before'):
            self.run_request(execute=True)
        self.cache.commit.assert_not_called()

    def test_commit_failure_reports_possible_partial_changes(self):
        self.apt.Cache.side_effect = [self.cache, Cache()]
        self.cache.commit.return_value = False
        with self.assertRaisesRegex(RuntimeError, 'installation failed'):
            self.run_request(execute=True)
        self.assertTrue(self.worker['ACTIVITY']['may_have_changed'])
        self.assertFalse(self.worker['ACTIVITY']['executed'])

    def test_post_install_snapshot_mismatch_never_reports_success(self):
        self.apt.Cache.side_effect = [self.cache, Cache(), Cache()]
        with self.assertRaisesRegex(RuntimeError, 'Installed dependency state differs'):
            self.run_request(execute=True)
        self.assertTrue(self.worker['ACTIVITY']['may_have_changed'])

    def test_successful_install_requires_exact_fresh_package_snapshot(self):
        self.apt.Cache.side_effect = [self.cache, Cache(), Cache([Package(installed=version('2'))])]
        result = self.run_request(execute=True)
        self.assertTrue(result['ok']); self.assertTrue(result['executed'])
        self.assertFalse(result['may_have_changed'])

    def test_wrong_host_or_native_architecture_stops_before_dependency_solving(self):
        self.worker['open'] = lambda path: io.StringIO('ID=debian\nVERSION_ID=11\n')
        with self.assertRaisesRegex(RuntimeError, 'Ubuntu 20.04'):
            self.run_request()
        self.native.parse_src_depends.assert_not_called()
        self.worker['open'] = lambda path: io.StringIO('ID=ubuntu\nVERSION_ID=20.04\n')
        self.native.config.find.return_value = 'arm64'
        with self.assertRaisesRegex(RuntimeError, 'architecture'):
            self.run_request()


class RpmProfileTests(unittest.TestCase):
    def setUp(self):
        self.worker = {'__name__': 'rpm_environment_profile_test'}
        exec(MODULE['_RPM_WORKER'].rsplit('if __name__', 1)[0] + MODULE['_BUILD_ENV_WORKER_SUFFIX'], self.worker)
        self.worker['ENV_PROFILE'] = 'remi-el7'

    def repositories(self):
        repos = {name: types.SimpleNamespace(id=name, enabled=name in ('base','remi-safe','third-party'), gpgcheck=True)
                 for name in ('base','remi-safe','remi-php74','third-party','amzn2-core','amzn2extra-php7.4')}
        wrapper = types.SimpleNamespace(repos=repos,
            listEnabled=lambda: [p for p in repos.values() if p.enabled],
            getRepo=lambda name: repos[name],
            disableRepo=lambda pattern: [setattr(p,'enabled',False) for p in repos.values()],
            enableRepo=lambda name: setattr(repos[name],'enabled',True))
        return types.SimpleNamespace(repos=wrapper)

    def test_remi_keeps_only_previously_enabled_approved_signed_repositories(self):
        base = self.repositories()
        self.worker['env_configure_repos'](base)
        self.assertEqual({'base','remi-safe'}, {p.id for p in base.repos.listEnabled()})
        self.assertFalse(base.repos.repos['remi-php74'].enabled)

    def test_remi_no_approved_repo_or_disabled_signature_fails_without_enabling_new_source(self):
        base = self.repositories()
        base.repos.repos['base'].enabled = base.repos.repos['remi-safe'].enabled = False
        with self.assertRaisesRegex(RuntimeError, 'No approved enabled'):
            self.worker['env_configure_repos'](base)
        base = self.repositories(); base.repos.repos['base'].gpgcheck = False
        with self.assertRaisesRegex(RuntimeError, 'GPG checking disabled'):
            self.worker['env_configure_repos'](base)
        self.assertFalse(base.repos.repos['remi-php74'].enabled)

    def test_al2_profile_resets_remi_repository_state(self):
        base = self.repositories(); self.worker['env_configure_repos'](base)
        self.worker['ENV_PROFILE'] = 'al2'
        self.worker['env_configure_repos'](base)
        self.assertEqual({'amzn2-core','amzn2extra-php7.4'}, {p.id for p in base.repos.listEnabled()})

    def test_remi_profile_refuses_another_os_version_or_architecture(self):
        for release, arch in [('ID=centos\nVERSION_ID=8\n','x86_64'),
                              ('ID=amzn\nVERSION_ID=2\n','x86_64'),
                              ('ID=centos\nVERSION_ID=7\n','aarch64')]:
            with mock.patch.dict(self.worker, {'open': lambda path, data=release: io.StringIO(data)}), \
                 mock.patch.object(platform, 'machine', return_value=arch):
                with self.assertRaisesRegex(RuntimeError, 'does not match'):
                    self.worker['env_host_check'](False)


class SetupBoundaryTests(unittest.TestCase):
    def test_ubuntu_jobs_limit_checked_before_any_environment_change(self):
        account = mock.Mock(side_effect=RuntimeError('account boundary'))
        entry = mock.Mock()
        overrides = {'nb_account': account, 'remi_build_main': entry, 'deb_builder_main': entry,
                     'parse_lock_wait': int, 'say': mock.Mock(), '_display_value': str}
        with mock.patch.dict(MODULE, overrides), contextlib.redirect_stderr(io.StringIO()):
            for action in ('setup', 'all'):
                with self.assertRaises(SystemExit) as stopped:
                    MODULE['native_build_main']('ubuntu20', [action, '--yes', '--jobs', '33'])
                self.assertEqual(2, stopped.exception.code)
            account.assert_not_called()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(20, MODULE['native_build_main']('ubuntu20', ['all', '--jobs', '32']))
                self.assertEqual(20, MODULE['native_build_main']('remi', ['all', '--jobs', '64']))
            self.assertEqual(2, account.call_count)

    def test_build_privileges_drop_groups_gid_uid_before_any_build_path_access(self):
        account = dict(name='builder', uid=1001, gid=1001, home='/home/builder')
        events = []
        fake = types.SimpleNamespace(initgroups=lambda *args: events.append('groups'),
            setgid=lambda *args: events.append('gid'), setuid=lambda *args: events.append('uid'),
            geteuid=lambda: 1001, environ={'TOKEN':'secret'},
            chdir=lambda path: events.append(('chdir',path)), umask=lambda value: events.append('umask'))
        with mock.patch.dict(MODULE, {'os':fake}):
            MODULE['be_drop_privileges'](account, '/trusted/launcher.sh')
        self.assertEqual(['groups','gid','uid',('chdir','/home/builder'),'umask'], events)
        self.assertNotIn('TOKEN',fake.environ)
        self.assertEqual('/home/builder',fake.environ['HOME'])

    def test_failed_drop_stops_before_home_access_or_environment_reset(self):
        fake = types.SimpleNamespace(initgroups=mock.Mock(),setgid=mock.Mock(),setuid=mock.Mock(),
            geteuid=lambda:0,environ={'TOKEN':'secret'},chdir=mock.Mock(),umask=mock.Mock())
        with mock.patch.dict(MODULE, {'os':fake}), self.assertRaisesRegex(RuntimeError, 'Failed to drop'):
            MODULE['be_drop_privileges'](dict(name='builder',uid=1001,gid=1001,home='/home/builder'),None)
        fake.chdir.assert_not_called(); self.assertIn('TOKEN',fake.environ)

    def test_apt_setup_uses_fixed_requirements_and_never_times_out_install(self):
        calls=[]
        def worker(code,data,modules,timeout):
            calls.append((data,timeout)); return {'ok':True}
        with mock.patch.dict(MODULE, {'worker_call':worker}):
            MODULE['nb_apt_environment'](False,30)
            MODULE['nb_apt_environment'](True,30,[])
        self.assertIn(MODULE['NB_UBUNTU_BUILD_DEPENDS'],calls[0][0]['build_depends'])
        self.assertEqual(630,calls[0][1]);self.assertIsNone(calls[1][1])
        self.assertEqual([],calls[1][0]['expected_changes'])


if __name__ == '__main__':
    unittest.main()
