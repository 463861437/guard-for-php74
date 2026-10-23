"""Local DEB safety regressions with fake native bindings and inventories."""
import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
guard = types.ModuleType('guard_deb_install')
for module in ('common', 'inventory', 'apt_backend', 'rpm_backend', 'service_ops',
               'backport_builder', 'deb_builder', 'baota_install', 'deb_install', 'cli'):
    exec(compile((ROOT / 'src' / (module + '.py')).read_text(), module + '.py', 'exec'), guard.__dict__)
guard.POLICY = json.loads((ROOT / 'vendor-policy.json').read_text())

OLD = '1:7.4.33-31+ubuntu20.04.1+deb.sury.org+1'


def manifest():
    rows = [dict(name=name, version=guard.DB_VERSION, arch='amd64', source='php7.4',
                 source_version=guard.DB_VERSION,
                 filename='%s_%s_amd64.deb' % (name, guard.DB_VERSION.split(':', 1)[-1]),
                 sha256=hashlib.sha256(b'deb fixture').hexdigest()) for name in sorted(guard.DI_REQUIRED)]
    return dict(recipe=guard.DB_RECIPE, target_version=guard.DB_VERSION, packaging_version=guard.DB_PACKAGING_VERSION,
                distribution='ubuntu', distribution_version='20.04', architecture='amd64',
                upstream_commit=guard.BP_COMMIT, state='built_and_tested_not_deployed', stage='complete',
                signed=False, php_selftests_passed=True, inputs=guard.db_input_hashes(),
                source_archive_sha256=guard.DB_SOURCE_SHA, packaging_sha256=guard.DB_PACKAGING_SHA,
                regression_patch_sha256=guard.BP_TEST_PATCH_SHA,
                php_selftest_summary=dict(total=10, passed=10, failed=0, borked=0, leaked=0),
                mitigation_smoke_tests=[dict(sapi=name, version_id=70434, oom_exit=1, shutdown_callback_ran=False)
                                        for name in ('cli', 'fpm')], artifacts=rows)


def host():
    return dict(os={'id': 'ubuntu', 'version_id': '20.04'}, package_manager='apt',
                packages=[dict(name='php7.4-cli', source='php7.4', arch='amd64', version=OLD, upstream='7.4.33')],
                runtimes=[], services=[], processes=[], containers=[], warnings=[])


def artifact():
    return dict(next(row for row in manifest()['artifacts'] if row['name'] == 'php7.4-cli'),
                path='/private/php7.4-cli.deb', md5sums_sha256='a' * 64)


class ManifestTests(unittest.TestCase):
    def test_complete_unsigned_fixed_recipe_accepted(self):
        report = manifest()
        self.assertEqual(report['artifacts'], guard.di_validate_build(report))

    def test_incomplete_or_cross_distribution_identity_is_rejected(self):
        for key, value in [('recipe', 'baota-al2-php74'), ('distribution_version', '22.04'),
                           ('architecture', 'arm64'), ('signed', True), ('php_selftests_passed', False),
                           ('regression_patch_sha256', '0' * 64), ('packaging_version', '7.4.3')]:
            report = manifest(); report[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): guard.di_validate_build(report)

    def test_unlisted_input_failed_test_or_path_traversal_cannot_pass(self):
        reports = []
        report = manifest(); report['inputs']['unexpected.patch'] = '0' * 64; reports.append(report)
        report = manifest(); report['php_selftest_summary']['failed'] = 1; reports.append(report)
        report = manifest(); report['artifacts'][0]['filename'] = '../bad.deb'; reports.append(report)
        report = manifest(); report['artifacts'].pop(); reports.append(report)
        report = manifest(); report['artifacts'].append(copy.deepcopy(report['artifacts'][0])); reports.append(report)
        report = manifest(); report['mitigation_smoke_tests'][0]['shutdown_callback_ran'] = True; reports.append(report)
        for report in reports:
            with self.subTest(report=report), self.assertRaises(RuntimeError): guard.di_validate_build(report)

    def test_actual_control_metadata_and_source_version_are_checked(self):
        raw = 'Package: php7.4-cli\nVersion: %s\nArchitecture: amd64\nSource: php7.4 (%s)\nDescription: PHP\n long description\n' % (guard.DB_VERSION, guard.DB_VERSION)
        with mock.patch.object(guard, 'run_cmd', return_value=dict(code=0, stdout=raw, stderr='')):
            result = guard.di_metadata('/private/php.deb')
        self.assertEqual(guard.DB_VERSION, result['source_version'])
        for modified in (raw.replace('Architecture: amd64', 'Architecture: arm64'),
                         raw + 'Filename: /outside/package.deb\n',
                         raw + 'Package: malicious\n', raw.replace('Source: php7.4', 'Source: php8.2')):
            with self.subTest(raw=modified), mock.patch.object(guard, 'run_cmd',
                  return_value=dict(code=0, stdout=modified, stderr='')), self.assertRaises(RuntimeError):
                guard.di_metadata('/private/php.deb')

    def test_stage_hash_failure_precedes_dpkg_metadata_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); report = manifest()
            log = b'test log'; report['build_log_sha256'] = hashlib.sha256(log).hexdigest()
            (root / 'build.json').write_text(json.dumps(report)); (root / 'build.log').write_bytes(log)
            (root / report['artifacts'][0]['filename']).write_bytes(b'tampered')
            output = root / 'accepted'; output.mkdir()
            with mock.patch.object(guard, 'bp_selftest_summary', return_value=report['php_selftest_summary']), \
                 mock.patch.object(guard, 'di_metadata') as metadata, self.assertRaises(RuntimeError):
                guard.di_stage(str(root / 'build.json'), str(output))
            metadata.assert_not_called()


class PlanTests(unittest.TestCase):
    def test_exact_focal_ppa_package_is_an_upgrade(self):
        with mock.patch.object(guard, 'native_compare', return_value=1), \
             mock.patch.object(guard, 'check_package_integrity', return_value=[]):
            result = guard.di_plan(host(), [artifact()])
        self.assertEqual([], result['blockers'])
        self.assertEqual(guard.DB_VERSION, result['updates'][0]['version'])

    def test_official_esm_or_other_ppa_distribution_never_uses_source_replacement(self):
        versions = ['7.4.3-4ubuntu2.29+esm5', '1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1',
                    '1:7.4.33-31+debian11+deb.sury.org+1', '1:7.4.32-1+ubuntu20.04.1+deb.sury.org+1']
        with mock.patch.object(guard, 'native_compare') as compare, \
             mock.patch.object(guard, 'check_package_integrity', return_value=[]):
            for version in versions:
                inv = host(); inv['packages'][0]['version'] = version
                with self.subTest(version=version):
                    self.assertTrue(guard.di_plan(inv, [artifact()])['blockers'])
        compare.assert_not_called()

    def test_other_os_arch_and_missing_installed_extension_are_blocked(self):
        for changes in ({'arch': 'arm64'}, {'name': 'php7.4-oci8'}, {'source': 'custom-php7.4'}):
            inv = host(); inv['packages'][0].update(changes)
            with self.subTest(changes=changes), mock.patch.object(guard, 'check_package_integrity', return_value=[]):
                self.assertTrue(guard.di_plan(inv, [artifact()])['blockers'])
        inv = host(); inv['os']['version_id'] = '22.04'
        self.assertTrue(guard.di_plan(inv, [artifact()])['blockers'])

    def test_same_version_requires_matching_payload(self):
        inv = host(); inv['packages'][0].update(version=guard.DB_VERSION, upstream='7.4.34')
        with mock.patch.object(guard, 'check_package_integrity', return_value=[]), \
             mock.patch.object(guard, 'di_payload_ok', return_value=False):
            result = guard.di_plan(inv, [artifact()])
        self.assertTrue(result['blockers']); self.assertEqual([], result['updates'])

    def test_no_receipt_does_not_prove_patch_and_bad_payload_cannot_be_accepted(self):
        inv = host(); inv['packages'][0].update(version=guard.DB_VERSION, upstream='7.4.34')
        with mock.patch.object(guard, 'check_package_integrity', return_value=[]), \
             mock.patch.object(guard, 'di_installed', return_value=dict(version=guard.DB_VERSION, source_version=guard.DB_VERSION)), \
             mock.patch.object(guard, 'di_payload_ok', return_value=False):
            findings = guard.di_assess(inv, {'packages': [artifact()]})
        self.assertEqual('affected', findings[0]['status'])

    def test_receipt_never_accepts_another_architecture_of_same_package(self):
        inv = host(); inv['packages'][0].update(name='php7.4-cli:amd64', version=guard.DB_VERSION, upstream='7.4.34')
        inv['packages'].append(dict(inv['packages'][0], name='php7.4-cli:i386', arch='i386'))
        with mock.patch.object(guard, 'check_package_integrity', return_value=[]), \
             mock.patch.object(guard, 'di_installed', return_value=dict(version=guard.DB_VERSION, source_version=guard.DB_VERSION)), \
             mock.patch.object(guard, 'di_payload_ok', return_value=True):
            findings = guard.di_assess(inv, {'packages': [artifact()]})
        status = dict((row['package_name'], row['status']) for row in findings)
        self.assertEqual('fixed', status['php7.4-cli:amd64'])
        self.assertNotEqual('fixed', status['php7.4-cli:i386'])


class NativeAPTTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        path = pathlib.Path(self.tmp.name) / 'php.deb'; path.write_bytes(b'deb fixture')
        self.update = dict(artifact(), path=str(path), old_version=OLD)
        self.data = dict(updates=[self.update], apt_config={}, lock_wait=0, execute=False)
        apt = types.ModuleType('apt'); native = types.ModuleType('apt_pkg')
        progress = types.ModuleType('apt.progress'); base = types.ModuleType('apt.progress.base')
        apt.progress = progress; progress.base = base
        base.AcquireProgress = mock.Mock(); base.InstallProgress = mock.Mock()
        native.init_config = mock.Mock(); native.init_system = mock.Mock(); native.config = mock.Mock()
        native.SystemLock = mock.MagicMock(); native.SELSTATE_HOLD = 2
        native.version_compare = lambda a, b: (a > b) - (a < b)
        self.native = native
        self.old = types.SimpleNamespace(version=OLD, architecture='amd64', source_name='php7.4')
        self.new = types.SimpleNamespace(version=guard.DB_VERSION, architecture='amd64', source_name='php7.4',
                        source_version=guard.DB_VERSION, _cand=types.SimpleNamespace(depends_list={}))
        self.package = types.SimpleNamespace(name='php7.4-cli', fullname='php7.4-cli:amd64', installed=self.old,
                        candidate=self.new, versions=[self.new], _pkg=types.SimpleNamespace(selected_state=0),
                        marked_upgrade=True, marked_delete=False, marked_downgrade=False,
                        mark_install=mock.Mock())
        self.cache = mock.MagicMock()
        self.cache.update.return_value = True; self.cache.dpkg_journal_dirty = False; self.cache.broken_count = 0
        self.cache.__contains__.return_value = True; self.cache.__getitem__.return_value = self.package
        self.cache.__iter__.side_effect = lambda: iter([self.package])
        self.cache.get_changes.return_value = [self.package]
        apt.Cache = mock.Mock(return_value=self.cache)
        self.apt = apt
        self.ns = {}
        with mock.patch.dict(sys.modules, {'apt': apt, 'apt_pkg': native,
                                          'apt.progress': progress, 'apt.progress.base': base}):
            exec(guard.APT_WORKER.split('\ntry:\n    with open(sys.argv[1])', 1)[0], self.ns)
            exec(guard._DI_WORKER.split("\nwith open(sys.argv[1]) as handle: request", 1)[0], self.ns)
        def commit(*args):
            self.package.installed = self.new
            return True
        self.cache.commit.side_effect = commit

    def test_preview_uses_native_solver_and_never_commits(self):
        result = self.ns['di_native'](self.data)
        self.assertTrue(result['ok']); self.assertFalse(result['executed'])
        self.cache.commit.assert_not_called()
        self.native.SystemLock.return_value.__exit__.assert_called_once()

    def test_apply_uses_cache_commit_and_compares_post_snapshot(self):
        self.data['execute'] = True
        result = self.ns['di_native'](self.data)
        self.assertTrue(result['ok']); self.assertTrue(result['executed'])
        self.cache.commit.assert_called_once(); self.cache.open.assert_called_once()

    def test_system_target_release_does_not_reject_private_flat_index(self):
        class Config(dict):
            def set(self, key, value): self[key] = value
            def clear(self, key): self.pop(key, None)
        self.native.config = Config({'APT::Default-Release': 'focal', 'Dir::Etc::preferences': '/etc/apt/preferences'})
        def open_cache(**kwargs):
            if self.native.config.get('APT::Default-Release'):
                raise RuntimeError('The value focal is invalid for APT::Default-Release')
            return self.cache
        self.apt.Cache.side_effect = open_cache
        self.assertTrue(self.ns['di_native'](self.data)['ok'])
        self.assertEqual('/etc/apt/preferences', self.native.config['Dir::Etc::preferences'])
        self.cache.commit.assert_not_called()

    def test_any_additional_install_delete_or_downgrade_is_rejected(self):
        for flag in ('marked_delete', 'marked_downgrade'):
            setattr(self.package, flag, True)
            with self.subTest(flag=flag):
                self.assertFalse(self.ns['di_native'](self.data)['ok'])
            setattr(self.package, flag, False)
        extra = types.SimpleNamespace(name='unapproved-lib')
        self.cache.get_changes.return_value.append(extra)
        result = self.ns['di_native'](self.data)
        self.assertFalse(result['ok']); self.cache.commit.assert_not_called()

    def test_replaces_unapproved_installed_package_is_blocked_even_without_remove_action(self):
        existing = types.SimpleNamespace(name='another-package', current_ver=types.SimpleNamespace(ver_str='1.0'))
        target = types.SimpleNamespace(parent_pkg=existing, ver_str='1.0')
        dep = types.SimpleNamespace(all_targets=lambda: [target])
        for kind in ('Replaces', 'Conflicts', 'Breaks'):
            self.new._cand.depends_list = {kind: [[dep]]}
            with self.subTest(kind=kind):
                result = self.ns['di_native'](self.data)
                self.assertFalse(result['ok']); self.assertIn(kind, result['error'])
        self.cache.commit.assert_not_called()

    def test_old_replaces_condition_not_matching_current_version_is_allowed(self):
        existing = types.SimpleNamespace(name='another-package', current_ver=types.SimpleNamespace(ver_str='2.0'))
        target = types.SimpleNamespace(parent_pkg=existing, ver_str='1.0')
        self.new._cand.depends_list = {'Replaces': [[types.SimpleNamespace(all_targets=lambda: [target])]]}
        self.assertTrue(self.ns['di_native'](self.data)['ok'])

    def test_hold_or_dirty_journal_blocks_before_commit(self):
        self.package._pkg.selected_state = 2
        self.assertFalse(self.ns['di_native'](self.data)['ok'])
        self.package._pkg.selected_state = 0; self.cache.dpkg_journal_dirty = True
        self.assertFalse(self.ns['di_native'](self.data)['ok']); self.cache.commit.assert_not_called()

    def test_checksum_change_and_source_mismatch_are_rejected(self):
        self.new.source_name = 'malicious'
        self.assertFalse(self.ns['di_native'](self.data)['ok'])
        self.new.source_name = 'php7.4'; pathlib.Path(self.update['path']).write_bytes(b'changed')
        self.assertFalse(self.ns['di_native'](self.data)['ok']); self.cache.commit.assert_not_called()

    def test_commit_failure_marks_possible_partial_install(self):
        self.data['execute'] = True; self.cache.commit.side_effect = RuntimeError('dpkg failed')
        result = self.ns['di_native'](self.data)
        self.assertFalse(result['ok']); self.assertTrue(result['executed'])

    def test_post_snapshot_mismatch_is_not_reported_as_success(self):
        self.data['execute'] = True; self.cache.commit.side_effect = None; self.cache.commit.return_value = True
        result = self.ns['di_native'](self.data)
        self.assertFalse(result['ok']); self.assertTrue(result['executed'])
        self.assertIn('snapshot differs', result['error'])


class PrivateRepositoryTests(unittest.TestCase):
    def test_private_sources_and_lists_do_not_write_system_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(guard, 'worker_call', return_value={'ok': True}) as worker:
                guard.di_transaction([dict(artifact(), old_version=OLD)], tmp, lock_wait=300)
            data = worker.call_args.args[1]; config = data['apt_config']
            self.assertTrue(config['Dir::Etc::sourcelist'].startswith(tmp + '/'))
            self.assertTrue(config['Dir::State::lists'].startswith(tmp + '/'))
            self.assertEqual('/var/lib/dpkg/status', config['Dir::State::status'])
            source = pathlib.Path(config['Dir::Etc::sourcelist']).read_text()
            self.assertEqual('deb [trusted=yes] file:' + tmp + '/debs ./\n', source)
            self.assertEqual(900, worker.call_args.kwargs['timeout'])


class DeployFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.addCleanup(mock.patch.stopall)
        self.inv = host(); self.plan = dict(updates=[dict(artifact(), old_version=OLD)], blockers=[])
        self.preflight = dict(services=['php7.4-fpm.service'], blockers=[])
        self.good = dict(ok=True, inventory=self.inv)
        for name, value in [('bi_private_dir', None), ('say', None), ('collect_inventory', self.inv),
                            ('acquire_repair_lock', None), ('di_stage', []), ('di_plan', self.plan),
                            ('service_preflight', self.preflight), ('di_assess', [{'status': 'fixed'}]),
                            ('di_save_receipt', {}), ('residual_process_check', {'ok': True})]:
            mock.patch.object(guard, name, return_value=value).start()
        mock.patch.object(guard.sys, 'platform', 'linux').start()
        mock.patch.object(guard.os, 'geteuid', return_value=0).start()
        mock.patch.object(guard.os, 'umask').start()
        mock.patch.object(guard.os, 'uname', return_value=('Linux', 'host', '', '', 'x86_64')).start()
        mock.patch.object(guard.tempfile, 'mkdtemp', return_value=self.tmp.name).start()
        self.transaction = mock.patch.object(guard, 'di_transaction', return_value={'ok': True, 'executed': True}).start()
        self.revalidate = mock.patch.object(guard, 'repair_revalidate', return_value=self.good).start()
        self.backup = mock.patch.object(guard, 'backup_configuration', return_value='backup').start()
        self.restart = mock.patch.object(guard, 'restart_services', return_value={'ok': True}).start()
        mock.patch.object(guard, 'health_checks', return_value=[]).start()

    def invoke(self, *flags):
        return guard.deb_install_main(['fix', '--build-report', '/build/build.json'] + list(flags))

    def test_no_yes_is_preview_only(self):
        self.assertEqual(0, self.invoke())
        self.assertEqual(1, self.transaction.call_count)
        self.assertFalse(self.transaction.call_args.kwargs.get('execute', False))
        self.backup.assert_not_called(); self.restart.assert_not_called()

    def test_uncovered_worker_blocks_before_package_preview(self):
        self.preflight['blockers'].append({'reason': 'unmapped PHP worker'})
        self.assertEqual(10, self.invoke('--yes'))
        self.transaction.assert_not_called(); self.restart.assert_not_called()

    def test_host_change_blocks_install_after_preview(self):
        self.revalidate.return_value = {'ok': False}
        self.assertEqual(10, self.invoke('--yes'))
        self.assertEqual(1, self.transaction.call_count)
        self.backup.assert_not_called(); self.restart.assert_not_called()

    def test_partial_failure_does_not_restart_or_issue_receipt(self):
        self.transaction.side_effect = [{'ok': True}, {'ok': False, 'executed': True}]
        self.assertEqual(20, self.invoke('--yes'))
        self.restart.assert_not_called(); guard.di_save_receipt.assert_not_called()
        report = json.loads((pathlib.Path(self.tmp.name) / 'report.json').read_text())
        self.assertTrue(report['deployed'])
        self.assertEqual('installation_failed_or_partial', report['result'])

    def test_same_accepted_build_is_not_reinstalled_or_restarted(self):
        self.plan['updates'] = []
        self.assertEqual(0, self.invoke('--yes'))
        self.transaction.assert_not_called(); self.restart.assert_not_called()
        guard.di_save_receipt.assert_called_once()

    def test_success_revalidates_and_restarts_before_receipt(self):
        self.assertEqual(0, self.invoke('--yes'))
        self.assertEqual(2, self.revalidate.call_count)
        self.restart.assert_called_once_with(['php7.4-fpm.service'])
        guard.di_save_receipt.assert_called_once()


if __name__ == '__main__':
    unittest.main()
