"""PHP 8.2 EL7 deployment preserves system/SCL layouts and fails closed."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guard_remi82_install_tests', ROOT / 'php_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
# Also permit focused tests before the top-level assembly is regenerated.
for name in ('remi82_builder', 'remi82_install'):
    exec(compile((ROOT / ('src/' + name + '.py')).read_bytes(), str(ROOT / ('src/' + name + '.py')), 'exec'), guard.__dict__)
PINNED_INPUTS = dict((layout, guard.r82_input_hashes(layout)) for layout in ('system', 'scl'))


def recipe_patch():
    values = dict(R82_RECIPE='upstream-remi-el7-php82', R82_VERSION='8.2.35',
                  R82_RELEASE='1.el7.remi.phpguard20261023.1', R82_SOURCE_SHA='a' * 64,
                  R82_SIGNATURE_FINGERPRINT='F' * 40)
    return mock.patch.multiple(guard, create=True, **values)


def profile(layout):
    return dict(commit=('a' if layout == 'system' else 'b') * 40,
                spec_name='php82.spec', source_name='php' if layout == 'system' else 'php82-php',
                core_names=[('' if layout == 'system' else 'php82-') + name for name in ('php', 'php-cli', 'php-common', 'php-fpm')],
                smoke_sapis=('build-cgi', 'build-ztscli') if layout == 'system' else ('build-cgi',))


def input_hashes(layout):
    return {'php82.spec': hashlib.sha256(b'pinned spec').hexdigest(),
            'php.tar.xz': hashlib.sha256(b'pinned source').hexdigest()}


def package(name, source='php', version='8.2.20-1.el7.remi', arch='x86_64'):
    return dict(name=name, source=source, version=version, upstream=version.split('-')[0], arch=arch,
                source_rpm=source + '-' + version + '.src.rpm')


def inventory():
    return dict(os=dict(id='centos', version_id='7'), package_manager='yum',
                packages=[package('php-cli'), package('php-common'),
                          package('php82-php-common', source='php82-php'),
                          package('php-pecl-zip', source='php-pecl-zip', version='1.22.3-1.el7.remi.8.2'),
                          package('php82-php-pecl-zip', source='php82-php-pecl-zip', version='1.22.3-1.el7.remi'),
                          package('php82-runtime', source='php82', version='8.2-5.el7.remi')],
                runtimes=[], processes=[], containers=[], warnings=[], services=[])


def artifact(name, layout='system'):
    return dict(name=name, version=guard.R82_VERSION, release=guard.R82_RELEASE, arch='x86_64',
                file='%s-%s-%s.x86_64.rpm' % (name, guard.R82_VERSION, guard.R82_RELEASE),
                sha256=hashlib.sha256(b'rpm').hexdigest(), header_sha1='d' * 40,
                layout=layout, source='php' if layout == 'system' else 'php82-php')


def artifacts():
    return [artifact(name) for name in ('php', 'php-cli', 'php-common', 'php-fpm')] + [
        artifact('php82-' + name, 'scl') for name in ('php', 'php-cli', 'php-common', 'php-fpm')]


def build_report(layout='system'):
    summary = dict(total=15000, passed=15000, failed=0, borked=0, leaked=0, warned=0,
                   skipped=0, xfailed=0, xleaked=0, accepted_xpasses=[],
                   critical_regressions=dict.fromkeys(guard.R82_SECURITY_TESTS, 'PASS'))
    security_summary = copy.deepcopy(summary)
    security_summary.update(total=len(guard.R82_SECURITY_TESTS), passed=len(guard.R82_SECURITY_TESTS))
    return dict(recipe=guard.R82_RECIPE, layout=layout, target_version=guard.R82_VERSION,
                target_release=guard.R82_RELEASE, state='built_not_deployed', stage='complete',
                packaging_commit=profile(layout)['commit'], source_sha256=guard.R82_SOURCE_SHA,
                inputs=input_hashes(layout), signed=False, source_signature_verified=True,
                source_signature_fingerprint=guard.R82_SIGNATURE_FINGERPRINT,
                tests_required=True, php_selftests_passed=True,
                host=dict(platform='linux', os_id='centos', os_version='7', architecture='x86_64', uid=1000),
                php_selftest_summary=summary, security_test_summary=security_summary,
                mitigation_smoke_tests=[dict(sapi=sapi, version=guard.R82_VERSION, version_id=80235,
                                             zts=1 if sapi == 'build-ztscli' else 0, int_size=8)
                    for sapi in (('build-cgi', 'build-ztscli') if layout == 'system' else ('build-cgi',))],
                artifacts=[row for row in artifacts() if row['layout'] == layout])


class RecipeTestCase(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        recipe_patch().start()
        mock.patch.object(guard, 'r82_profile', side_effect=profile, create=True).start()
        mock.patch.object(guard, 'r82_input_hashes', side_effect=input_hashes, create=True).start()
        mock.patch.object(guard, 'r82_host_supported', return_value=True, create=True).start()
        mock.patch.object(guard.os, 'uname', return_value=('Linux', '', '', '', 'x86_64')).start()
        mock.patch.object(guard, 'check_package_integrity', return_value=[]).start()
        mock.patch.object(guard, 'native_compare', return_value=1).start()


class LayoutPlanTests(RecipeTestCase):
    def test_mixed_layout_updates_all_installed_core_but_no_extra_sapis_or_extensions(self):
        plan = guard.r82_plan(inventory(), artifacts())
        self.assertEqual([], plan['blockers'])
        self.assertEqual({'php-cli', 'php-common', 'php82-php-common'}, {r['name'] for r in plan['updates']})
        self.assertEqual(['system', 'scl'], plan['layouts'])
        self.assertEqual({'php', 'php82-php'}, {r['source'] for r in plan['updates']})
        self.assertFalse(plan['installs_new_sapis'])

    def test_missing_scl_artifacts_is_not_partial_success(self):
        plan = guard.r82_plan(inventory(), [r for r in artifacts() if r['layout'] == 'system'])
        self.assertTrue(any('php82-php-common' in r['reason'] for r in plan['blockers']))

    def test_every_installed_core_extension_requires_matching_artifact(self):
        inv = inventory(); inv['packages'].append(package('php-ldap'))
        plan = guard.r82_plan(inv, artifacts())
        self.assertTrue(any('php-ldap' in r['reason'] for r in plan['blockers']))

    def test_wrong_host_unknown_baseline_epoch_source_and_branch_rejected(self):
        cases = []
        inv = inventory(); inv['os']['id'] = 'amzn'; cases.append(inv)
        inv = inventory(); inv['os']['version_id'] = '8'; cases.append(inv)
        inv = inventory(); inv['package_manager'] = 'dnf'; cases.append(inv)
        for value in ['8.2.19-1.el7.remi', '8.2.20-2.el7.remi', '1:8.2.20-1.el7.remi', '7.4.33-15.el7.remi']:
            inv = inventory(); inv['packages'][0] = package('php-cli', version=value); cases.append(inv)
        inv = inventory(); inv['packages'][0]['source_rpm'] = 'different.src.rpm'; cases.append(inv)
        inv = inventory(); inv['packages'].append(package('php81-php-common', source='php81-php')); cases.append(inv)
        for inv in cases:
            with self.subTest(inv=inv):
                self.assertFalse(guard.r82_inventory_supported(inv))
                self.assertTrue(guard.r82_plan(inv, artifacts())['blockers'])
        self.assertFalse(guard.r82_inventory_supported(inventory(), 'aarch64'))

    def test_wrapper_exemption_requires_exact_metadata(self):
        valid = package('php82-runtime', source='php82', version='8.2-5.el7.remi')
        self.assertTrue(guard.r82_wrapper(valid))
        for key, value in [('version', '8.2-1.el8.remi'), ('source_rpm', 'evil.src.rpm'), ('name', 'php82-other')]:
            altered = dict(valid); altered[key] = value
            self.assertFalse(guard.r82_wrapper(altered))

    def test_duplicate_artifact_and_downgrade_block(self):
        rows = artifacts(); rows.append(copy.deepcopy(rows[0]))
        self.assertTrue(guard.r82_plan(inventory(), rows)['blockers'])
        with mock.patch.object(guard, 'native_compare', return_value=-1):
            self.assertTrue(guard.r82_plan(inventory(), artifacts())['blockers'])

    def test_same_evr_mismatched_header_not_adopted(self):
        inv = inventory(); inv['packages'][0] = package('php-cli', version=guard.R82_VERSION + '-' + guard.R82_RELEASE)
        with mock.patch.object(guard, 'native_compare', return_value=0), \
             mock.patch.object(guard, 'bi_metadata', return_value={'header_sha1': 'e' * 40}):
            self.assertTrue(guard.r82_plan(inv, artifacts())['blockers'])

    def test_unmanaged_runtime_remains_blocking(self):
        inv = inventory(); inv['runtimes'] = [dict(path='/usr/local/php/bin/php', package=None)]
        self.assertTrue(any(r.get('kind') == 'unmanaged_runtime' for r in guard.r82_plan(inv, artifacts())['blockers']))

    def test_native_worker_is_used_without_extra_package_requests(self):
        updates = guard.r82_plan(inventory(), artifacts())['updates']
        with mock.patch.object(guard, 'bi_transaction', return_value={'ok': True}) as worker:
            guard.r82_transaction(updates, '/private', execute=True, lock_wait=42)
        worker.assert_called_once_with(updates, '/private', execute=True, lock_wait=42)


class BuildEvidenceTests(RecipeTestCase):
    def test_both_layouts_have_their_own_complete_manifest(self):
        for layout in ('system', 'scl'):
            report = build_report(layout)
            self.assertEqual(report['artifacts'], guard.r82_validate_build(report))

    def test_incomplete_or_untrusted_manifest_rejected(self):
        for key, value in [('recipe', 'other'), ('state', 'build_failed'), ('target_version', '8.2.20'),
                           ('inputs', {}), ('signed', True), ('source_signature_verified', False),
                           ('tests_required', False), ('php_selftests_passed', False), ('packaging_commit', 'x')]:
            report = build_report(); report[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                guard.r82_validate_build(report)
        for field in ('php_selftest_summary', 'security_test_summary'):
            report = build_report(); report[field]['failed'] = 1
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                guard.r82_validate_build(report)

    def test_missing_family_or_wrong_layout_artifacts_rejected(self):
        report = build_report(); report['artifacts'].pop()
        with self.assertRaises(RuntimeError): guard.r82_validate_build(report)
        report = build_report(); report['artifacts'][0]['file'] = '../../evil.rpm'
        with self.assertRaises(RuntimeError): guard.r82_validate_build(report)
        report = build_report('scl'); report['artifacts'][0]['name'] = 'php-common'
        with self.assertRaises(RuntimeError): guard.r82_validate_build(report)
        report = build_report(); report['artifacts'].append(copy.deepcopy(report['artifacts'][0]))
        with self.assertRaises(RuntimeError): guard.r82_validate_build(report)

    def test_all_seven_critical_tests_are_required_in_both_summaries(self):
        self.assertEqual(7, len(guard.R82_SECURITY_TESTS))
        for layout in ('system', 'scl'):
            for field in ('php_selftest_summary', 'security_test_summary'):
                for name in guard.R82_SECURITY_TESTS:
                    report = build_report(layout)
                    del report[field]['critical_regressions'][name]
                    with self.subTest(layout=layout, field=field, name=name), self.assertRaises(RuntimeError):
                        guard.r82_validate_build(report)
            for field in ('skipped', 'xfailed', 'xleaked'):
                report = build_report(layout)
                report['security_test_summary'][field] = 1
                with self.subTest(layout=layout, field=field), self.assertRaises(RuntimeError):
                    guard.r82_validate_build(report)

    def test_legacy_openssl_compatibility_input_is_bound_to_report_and_receipt(self):
        for layout in ('system', 'scl'):
            pins = PINNED_INPUTS[layout]
            self.assertEqual(guard.R82_OPENSSL_COMPAT_SHA, pins[guard.R82_OPENSSL_COMPAT_PATCH])
            with mock.patch.object(guard, 'r82_input_hashes', return_value=pins):
                report = build_report(layout); report['inputs'] = dict(pins)
                guard.r82_validate_build(report)
                del report['inputs'][guard.R82_OPENSSL_COMPAT_PATCH]
                with self.assertRaises(RuntimeError): guard.r82_validate_build(report)
                receipt = guard.r82_receipt_evidence([artifact(profile(layout)['core_names'][0], layout)])
                receipt['inputs'][layout] = dict(pins)
                del receipt['inputs'][layout][guard.R82_OPENSSL_COMPAT_PATCH]
                self.assertFalse(guard.r82_receipt_valid(receipt))

    def test_only_one_pinned_full_suite_fpm_xpass_is_accepted(self):
        report = build_report()
        known = {'test': guard.R82_KNOWN_XPASS, 'source_sha256': guard.R82_KNOWN_XPASS_SHA, 'result': 'XPASS'}
        report['php_selftest_summary'].update(warned=1, passed=14999, accepted_xpasses=[known])
        guard.r82_validate_build(report)
        for changes in ({'warned': 0}, {'warned': 2}, {'accepted_xpasses': [known, known]},
                        {'accepted_xpasses': [dict(known, test='other.phpt')]},
                        {'accepted_xpasses': [dict(known, source_sha256='0' * 64)]},
                        {'accepted_xpasses': [dict(known, result='WARN')]}):
            altered = copy.deepcopy(report)
            altered['php_selftest_summary'].update(changes)
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                guard.r82_validate_build(altered)
        report = build_report()
        report['security_test_summary'].update(accepted_xpasses=[known])
        with self.assertRaises(RuntimeError): guard.r82_validate_build(report)

    def test_root_build_and_failed_smoke_are_rejected(self):
        report = build_report(); report['host']['uid'] = 0
        with self.assertRaises(RuntimeError): guard.r82_validate_build(report)
        report = build_report(); report['mitigation_smoke_tests'][0]['version_id'] = 80220
        with self.assertRaises(RuntimeError): guard.r82_validate_build(report)

    def test_runtime_rpms_cannot_ship_test_extension_in_either_layout(self):
        for path in ('/usr/lib64/php/modules/zend_test.so',
                     '/opt/remi/php82/root/usr/lib64/php/modules/zend_test.so',
                     '/usr/lib64/php/modules/zend_test.so.1',
                     '/usr/lib/debug/zend_test.so.debug',
                     '/usr/lib64/php/modules/zend_test_shared.so',
                     '/usr/lib64/php/modules/zend_test-8.2.so',
                     '/usr/lib64/php/modules/ZEND_TEST.SO'):
            with mock.patch.object(guard, 'run_cmd', return_value={'code': 0, 'stdout': path + '\n'}):
                with self.assertRaisesRegex(RuntimeError, 'Test-only'):
                    guard.r82_runtime_payload_check('/accepted/package.rpm')
        with mock.patch.object(guard, 'run_cmd', return_value={'code': 1, 'stdout': ''}):
            with self.assertRaisesRegex(RuntimeError, 'Cannot inspect'):
                guard.r82_runtime_payload_check('/accepted/package.rpm')
        with mock.patch.object(guard, 'run_cmd', return_value={'code': 0, 'stdout': '/usr/lib64/php/modules/opcache.so\n'}) as query:
            guard.r82_runtime_payload_check('/accepted/package.rpm')
        query.assert_called_once_with(['/usr/bin/rpm', '-qpl', '--', '/accepted/package.rpm'], timeout=30)

    def test_copy_rejects_symlink_hash_mismatch_and_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); src = root / 'source'; src.write_bytes(b'original')
            link = root / 'link'; link.symlink_to(src)
            for path, limit, digest in [(link, 100, None), (src, 1, None), (src, 100, '0' * 64)]:
                with self.subTest(path=path, limit=limit), self.assertRaises(RuntimeError):
                    guard.r82_copy_input(str(path), str(root / 'accepted'), limit, digest)

    def test_copy_detects_path_replacement_while_copying(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); src = root / 'source'; src.write_bytes(b'original')
            replacement = root / 'new'; replacement.write_bytes(b'changed')
            real_lstat = guard.os.lstat
            calls = [0]
            def changed(path):
                calls[0] += 1
                if calls[0] == 2:
                    replacement.replace(src)
                return real_lstat(path)
            with mock.patch.object(guard.os, 'lstat', side_effect=changed):
                with self.assertRaisesRegex(RuntimeError, 'replaced'):
                    guard.r82_copy_input(str(src), str(root / 'accepted'), 100)

    def test_input_tampering_blocks_before_rpm_header_or_test_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); work = root / 'work'; build = work / 'build-one'
            build.mkdir(parents=True); (build / 'rpmbuild/SOURCES').mkdir(parents=True)
            report = build_report(); (build / 'build.json').write_text(json.dumps(report))
            (build / 'rpmbuild/SOURCES/php82.spec').write_bytes(b'changed spec')
            (build / 'rpmbuild/SOURCES/php.tar.xz').write_bytes(b'pinned source')
            accepted = root / 'accepted'; accepted.mkdir()
            with mock.patch.object(guard, 'bi_metadata') as rpm:
                with self.assertRaises(RuntimeError):
                    guard.r82_stage([str(build / 'build.json')], str(accepted))
                rpm.assert_not_called()

    def stage_fixture(self, root):
        build = root / 'work/build-one'; sources = build / 'rpmbuild/SOURCES'
        sources.mkdir(parents=True)
        (sources / 'php82.spec').write_bytes(b'pinned spec')
        (sources / 'php.tar.xz').write_bytes(b'pinned source')
        (build / 'rpmbuild/SPECS').mkdir()
        (build / 'rpmbuild/SPECS/php82-guard.spec').write_bytes(b'rendered spec')
        (build / 'build.log').write_text('full log')
        (build / 'security-tests.log').write_text('security log')
        rpms = build / 'rpmbuild/RPMS/x86_64'; rpms.mkdir(parents=True)
        report = build_report()
        report['spec_sha256'] = hashlib.sha256(b'rendered spec').hexdigest()
        for row in report['artifacts']:
            (rpms / row['file']).write_bytes(b'rpm')
        (build / 'build.json').write_text(json.dumps(report))
        accepted = root / 'accepted'; accepted.mkdir()
        return build, accepted, report

    def test_staging_rechecks_signature_spec_both_logs_and_all_artifact_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            build, accepted, report = self.stage_fixture(pathlib.Path(tmp))
            def metadata(path=None, package=None):
                row = next(row for row in report['artifacts'] if row['file'] == pathlib.Path(path).name)
                return dict(row, source_rpm='php-' + guard.R82_VERSION + '-' + guard.R82_RELEASE + '.src.rpm')
            with mock.patch.object(guard, 'r82_verify_source_signature', create=True,
                     return_value={'verified': True, 'fingerprint': guard.R82_SIGNATURE_FINGERPRINT}) as signature, \
                 mock.patch.object(guard, 'r82_render_spec', create=True, return_value=b'rendered spec'), \
                 mock.patch.object(guard, 'r82_selftest_summary', create=True,
                     side_effect=[report['php_selftest_summary'], report['security_test_summary']]) as summary, \
                 mock.patch.object(guard, 'r82_runtime_payload_check') as payload, \
                 mock.patch.object(guard, 'bi_metadata', side_effect=metadata):
                rows = guard.r82_stage([str(build / 'build.json')], str(accepted))
            self.assertEqual(4, len(rows)); signature.assert_called_once()
            self.assertEqual(2, summary.call_count)
            self.assertTrue(summary.call_args.kwargs['targeted'])
            self.assertTrue(all(str(accepted) in row['path'] for row in rows))
            self.assertEqual([mock.call(row['path']) for row in rows], payload.call_args_list)

    def test_staging_signature_failure_does_not_inspect_or_install_rpms(self):
        with tempfile.TemporaryDirectory() as tmp:
            build, accepted, report = self.stage_fixture(pathlib.Path(tmp))
            with mock.patch.object(guard, 'r82_verify_source_signature', create=True,
                     return_value={'verified': False}) as signature, \
                 mock.patch.object(guard, 'bi_metadata') as metadata:
                with self.assertRaises(RuntimeError):
                    guard.r82_stage([str(build / 'build.json')], str(accepted))
                signature.assert_called_once(); metadata.assert_not_called()


class InstallerLifecycleTests(RecipeTestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.inv = inventory()
        self.updates = guard.r82_plan(self.inv, artifacts())['updates']
        mock.patch.object(guard.sys, 'platform', 'linux').start()
        mock.patch.object(guard.os, 'geteuid', return_value=0).start()
        mock.patch.object(guard.os, 'umask', return_value=0).start()
        mock.patch.object(guard, 'bi_private_dir').start()
        mock.patch.object(guard.tempfile, 'mkdtemp', return_value=self.tmp.name).start()
        mock.patch.object(guard, 'collect_inventory', return_value=self.inv).start()
        mock.patch.object(guard, 'r82_stage', return_value=artifacts()).start()
        mock.patch.object(guard, 'configure_optional_services', return_value=[]).start()
        mock.patch.object(guard, 'service_preflight', return_value={'services': ['php-fpm.service'], 'blockers': []}).start()
        mock.patch.object(guard, 'r82_extension_headers', return_value=[{'name': 'php82-php-pecl-zip', 'header': 'kept'}]).start()
        mock.patch.object(guard, 'health_checks', return_value=[]).start()
        mock.patch.object(guard, 'acquire_repair_lock', return_value=None).start()
        mock.patch.object(guard, 'write_json').start()
        mock.patch.object(guard, 'say').start()
        self.transaction = mock.patch.object(guard, 'r82_transaction', return_value={'ok': True, 'executed': False}).start()
        self.restart = mock.patch.object(guard, 'restart_services', return_value={'ok': True}).start()
        self.receipt = mock.patch.object(guard, 'r82_save_receipt', return_value=guard.r82_receipt_evidence(artifacts())).start()
        self.backup = mock.patch.object(guard, 'backup_configuration').start()

    def invoke(self, mode='fix'):
        return guard.remi82_install_main([mode, '--yes', '--build-report', '/system/build.json',
                                         '--build-report', '/scl/build.json'])

    def test_missing_family_blocks_before_any_native_transaction(self):
        with mock.patch.object(guard, 'r82_stage', return_value=[r for r in artifacts() if r['layout'] == 'system']):
            self.assertEqual(10, self.invoke())
        self.transaction.assert_not_called(); self.restart.assert_not_called(); self.receipt.assert_not_called()

    def test_plan_only_previews_without_install_or_restart(self):
        self.assertEqual(0, self.invoke('plan'))
        self.transaction.assert_called_once()
        self.assertFalse(self.transaction.call_args.kwargs.get('execute', False))
        self.restart.assert_not_called(); self.receipt.assert_not_called()

    def test_health_failure_prevents_install_after_preview(self):
        with mock.patch.object(guard, 'health_checks', return_value=[{'ok': False}]):
            self.assertEqual(10, self.invoke())
        self.transaction.assert_called_once(); self.restart.assert_not_called(); self.backup.assert_not_called()

    def test_refreshed_inventory_failure_prevents_install(self):
        with mock.patch.object(guard, 'repair_revalidate', return_value={'ok': False, 'inventory': self.inv}):
            self.assertEqual(10, self.invoke())
        self.transaction.assert_called_once(); self.restart.assert_not_called(); self.backup.assert_not_called()

    def test_unchanged_versions_but_modified_third_party_header_prevents_install(self):
        with mock.patch.object(guard, 'repair_revalidate', return_value={'ok': True, 'inventory': self.inv}), \
             mock.patch.object(guard, 'r82_extension_headers', side_effect=[[{'header': 'before'}], [{'header': 'after'}]]):
            self.assertEqual(10, self.invoke())
        self.transaction.assert_called_once(); self.restart.assert_not_called(); self.backup.assert_not_called()

    def test_partial_native_failure_never_claims_fixed_or_restarts(self):
        self.transaction.side_effect = [{'ok': True}, {'ok': False, 'executed': True}]
        with mock.patch.object(guard, 'repair_revalidate', return_value={'ok': True, 'inventory': self.inv}):
            self.assertEqual(20, self.invoke())
        self.restart.assert_not_called(); self.receipt.assert_not_called()
        self.assertTrue(self.transaction.call_args.kwargs['execute'])

    def test_success_requires_receipt_residual_and_health_after_checks(self):
        self.transaction.side_effect = [{'ok': True}, {'ok': True, 'executed': True}]
        with mock.patch.object(guard, 'repair_revalidate', return_value={'ok': True, 'inventory': self.inv}), \
             mock.patch.object(guard, 'r82_assess', return_value=[{'status': 'fixed'}]), \
             mock.patch.object(guard, 'residual_process_check', return_value={'ok': False}):
            self.assertEqual(10, self.invoke())
        self.restart.assert_called_once_with(['php-fpm.service']); self.receipt.assert_not_called()

    def test_failed_restart_does_not_save_receipt(self):
        self.transaction.side_effect = [{'ok': True}, {'ok': True, 'executed': True}]
        self.restart.return_value = {'ok': False}
        with mock.patch.object(guard, 'repair_revalidate', return_value={'ok': True, 'inventory': self.inv}):
            self.assertEqual(20, self.invoke())
        self.receipt.assert_not_called()

    def test_failed_post_install_health_does_not_save_receipt(self):
        self.transaction.side_effect = [{'ok': True}, {'ok': True, 'executed': True}]
        with mock.patch.object(guard, 'repair_revalidate', return_value={'ok': True, 'inventory': self.inv}), \
             mock.patch.object(guard, 'r82_assess', return_value=[{'status': 'fixed'}]), \
             mock.patch.object(guard, 'residual_process_check', return_value={'ok': True}), \
             mock.patch.object(guard, 'health_checks', side_effect=[[{'ok': True}], [{'ok': False}]]):
            self.assertEqual(10, self.invoke())
        self.receipt.assert_not_called()

    def test_extension_change_after_restart_does_not_save_receipt(self):
        self.transaction.side_effect = [{'ok': True}, {'ok': True, 'executed': True}]
        retained = [{'name': 'php82-runtime', 'header': 'before'}]
        changed = [{'name': 'php82-runtime', 'header': 'changed'}]
        with mock.patch.object(guard, 'repair_revalidate', return_value={'ok': True, 'inventory': self.inv}), \
             mock.patch.object(guard, 'r82_assess', return_value=[{'status': 'fixed'}]), \
             mock.patch.object(guard, 'residual_process_check', return_value={'ok': True}), \
             mock.patch.object(guard, 'r82_extension_headers', side_effect=[retained, retained, retained, changed]):
            self.assertEqual(10, self.invoke())
        self.receipt.assert_not_called()

    def test_receipt_follows_all_runtime_checks_and_is_reassessed_after_saving(self):
        events = []
        self.transaction.side_effect = [{'ok': True}, {'ok': True, 'executed': True}]
        self.receipt.side_effect = lambda unused: events.append('receipt') or {'saved': True}
        with mock.patch.object(guard, 'repair_revalidate', return_value={'ok': True, 'inventory': self.inv}), \
             mock.patch.object(guard, 'r82_assess', side_effect=lambda inv, receipt: events.append('assess_saved' if receipt.get('saved') else 'assess') or [{'status': 'fixed'}]), \
             mock.patch.object(guard, 'residual_process_check', side_effect=lambda *args: events.append('residual') or {'ok': True}), \
             mock.patch.object(guard, 'health_checks', side_effect=lambda *args: events.append('health') or [{'ok': True}]):
            self.assertEqual(0, self.invoke())
        self.assertEqual(['health', 'assess', 'residual', 'health', 'receipt', 'assess_saved'], events)

    def test_package_change_during_receipt_write_cannot_claim_fixed(self):
        self.transaction.side_effect = [{'ok': True}, {'ok': True, 'executed': True}]
        with mock.patch.object(guard, 'repair_revalidate', return_value={'ok': True, 'inventory': self.inv}), \
             mock.patch.object(guard, 'r82_assess', side_effect=[[{'status': 'fixed'}], [{'status': 'unknown'}]]), \
             mock.patch.object(guard, 'residual_process_check', return_value={'ok': True}):
            self.assertEqual(10, self.invoke())
        self.receipt.assert_called_once()

    def test_same_version_retry_checks_apache_mappings_without_simulating_a_restart(self):
        self.inv['packages'].append(package('php'))
        with mock.patch.object(guard, 'r82_plan', return_value={'updates': [], 'blockers': []}), \
             mock.patch.object(guard, 'r82_assess', return_value=[{'status': 'fixed'}]), \
             mock.patch.object(guard, 'service_preflight', return_value={'services': ['httpd.service'], 'blockers': []}) as preflight, \
             mock.patch.object(guard, 'residual_process_check', return_value={'ok': False, 'errors': ['old libphp mapping']}) as residual:
            self.assertEqual(10, self.invoke())
        self.assertEqual(guard.r82_core_packages(self.inv), preflight.call_args.args[1])
        residual.assert_called_once_with({'processes': []}, self.inv, [], ['httpd.service'])
        self.receipt.assert_not_called(); self.transaction.assert_not_called(); self.restart.assert_not_called()

    def test_same_version_retry_honors_requested_health_check(self):
        with mock.patch.object(guard, 'r82_plan', return_value={'updates': [], 'blockers': []}), \
             mock.patch.object(guard, 'r82_assess', return_value=[{'status': 'fixed'}]), \
             mock.patch.object(guard, 'residual_process_check', return_value={'ok': True}), \
             mock.patch.object(guard, 'health_checks', return_value=[{'ok': False}]) as health:
            self.assertEqual(10, guard.remi82_install_main(['fix', '--yes', '--build-report', '/build.json',
                                                         '--health-url', 'http://127.0.0.1/health']))
        health.assert_called_once_with(['http://127.0.0.1/health'], None)
        self.receipt.assert_not_called(); self.transaction.assert_not_called(); self.restart.assert_not_called()

    def test_same_version_retry_saves_only_after_current_runtime_and_health_pass(self):
        with mock.patch.object(guard, 'r82_plan', return_value={'updates': [], 'blockers': []}), \
             mock.patch.object(guard, 'r82_assess', return_value=[{'status': 'fixed'}]) as assess, \
             mock.patch.object(guard, 'residual_process_check', return_value={'ok': True}):
            self.assertEqual(0, self.invoke())
        self.receipt.assert_called_once(); self.transaction.assert_not_called(); self.restart.assert_not_called()
        self.assertEqual(2, assess.call_count)
        self.assertEqual(self.receipt.return_value, assess.call_args.args[1])

    def test_same_version_partial_saved_receipt_is_not_success(self):
        with mock.patch.object(guard, 'r82_plan', return_value={'updates': [], 'blockers': []}), \
             mock.patch.object(guard, 'r82_assess', side_effect=[[{'status': 'fixed'}], [{'status': 'unknown'}]]), \
             mock.patch.object(guard, 'residual_process_check', return_value={'ok': True}):
            self.assertEqual(10, self.invoke())
        self.receipt.assert_called_once(); self.transaction.assert_not_called(); self.restart.assert_not_called()


class ReceiptTests(RecipeTestCase):
    def patched_inventory(self):
        inv = inventory()
        inv['packages'] = [package('php-cli', version=guard.R82_VERSION + '-' + guard.R82_RELEASE)]
        return inv

    def test_version_alone_does_not_attest_local_build(self):
        finding = guard.r82_assess(self.patched_inventory(), {})[0]
        self.assertEqual('unknown', finding['status'])

    def test_valid_receipt_header_and_payload_are_all_required(self):
        row = artifact('php-cli'); receipt = guard.r82_receipt_evidence([row])
        meta = dict(name='php-cli', version=guard.R82_VERSION, release=guard.R82_RELEASE,
                    header_sha1=row['header_sha1'], source_rpm='php-' + guard.R82_VERSION + '-' + guard.R82_RELEASE + '.src.rpm')
        for header, payload, expected in [(row['header_sha1'], True, 'fixed'), ('e' * 40, True, 'unknown'),
                                          (row['header_sha1'], False, 'unknown')]:
            meta['header_sha1'] = header
            with mock.patch.object(guard, 'bi_metadata', return_value=meta), \
                 mock.patch.object(guard, 'bi_payload_ok', return_value=payload):
                self.assertEqual(expected, guard.r82_assess(self.patched_inventory(), receipt)[0]['status'])

    def test_receipt_wrong_source_evidence_not_used(self):
        receipt = guard.r82_receipt_evidence([artifact('php-cli')])
        receipt['source_sha256'] = '0' * 64
        with mock.patch.object(guard, 'bi_metadata') as meta:
            self.assertEqual('unknown', guard.r82_assess(self.patched_inventory(), receipt)[0]['status'])
            meta.assert_not_called()

    def test_scl_receipt_cannot_cover_system_package(self):
        row = artifact('php-cli', 'scl'); receipt = guard.r82_receipt_evidence([row])
        meta = dict(version=guard.R82_VERSION, release=guard.R82_RELEASE, header_sha1=row['header_sha1'],
                    source_rpm='php-' + guard.R82_VERSION + '-' + guard.R82_RELEASE + '.src.rpm')
        with mock.patch.object(guard, 'bi_metadata', return_value=meta), \
             mock.patch.object(guard, 'bi_payload_ok', return_value=True):
            self.assertEqual('unknown', guard.r82_assess(self.patched_inventory(), receipt)[0]['status'])

    def test_extension_header_capture_includes_both_pecl_layouts_and_wrapper(self):
        def metadata(path=None, package=None):
            name = package.rsplit('.', 1)[0]
            return dict(name=name, arch='x86_64', version='1', release='1', header_sha1='a' * 40, source_rpm=name + '.src.rpm')
        with mock.patch.object(guard, 'bi_metadata', side_effect=metadata):
            rows = guard.r82_extension_headers(inventory())
        self.assertEqual({'php-pecl-zip', 'php82-php-pecl-zip', 'php82-runtime'}, {r['name'] for r in rows})


if __name__ == '__main__':
    unittest.main()
