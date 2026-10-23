"""Offline EL7 local-RPM deployment guards; no RPM or host mutation."""
import copy
import hashlib
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
guard = types.ModuleType('guard_remi_install')
for module in ('common', 'inventory', 'apt_backend', 'rpm_backend', 'service_ops',
               'backport_builder', 'remi_builder', 'baota_install', 'cli'):
    exec(compile((ROOT / 'src' / (module + '.py')).read_text(), module + '.py', 'exec'), guard.__dict__)
guard.POLICY = json.loads((ROOT / 'vendor-policy.json').read_text())


def manifest():
    names = sorted(guard.RB_CORE_NAMES)
    rows = [dict(name=name, version=guard.RB_VERSION, release=guard.RB_RELEASE, arch='x86_64',
                 file='%s-%s-%s.x86_64.rpm' % (name, guard.RB_VERSION, guard.RB_RELEASE),
                 sha256=hashlib.sha256(b'RPM fixture').hexdigest()) for name in names]
    return dict(recipe=guard.RB_RECIPE, state='built_not_deployed', stage='complete',
                target_version=guard.RB_VERSION, target_release=guard.RB_RELEASE,
                upstream_commit=guard.BP_COMMIT, packaging_commit=guard.RB_COMMIT,
                source_sha256=guard.RB_SOURCE_SHA, source_signature_verified=False, signed=False,
                tests_required=True, regression_patch_sha256=guard.BP_TEST_PATCH_SHA,
                php_selftests_passed=True, inputs=guard.rb_input_hashes(),
                php_selftest_summary=dict(total=10, passed=10, failed=0, borked=0, leaked=0),
                mitigation_smoke_tests=[dict(sapi=sapi, version=guard.RB_VERSION,
                    oom_exit=1, shutdown_callback_ran=False) for sapi in guard.RB_SMOKE_SAPIS],
                artifacts=rows)


def host():
    return dict(os=dict(id='centos', version_id='7'), package_manager='yum',
                packages=[dict(name='php-cli', source='php', arch='x86_64',
                     version='7.4.33-15.el7.remi', upstream='7.4.33',
                     source_rpm='php-7.4.33-15.el7.remi.src.rpm')],
                runtimes=[], processes=[], containers=[], services=[], warnings=[])


def artifact(name='php-cli'):
    return dict(next(row for row in manifest()['artifacts'] if row['name'] == name),
                header_sha1='a' * 40, path='/private/' + name + '.rpm')


class RemiRecipeTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(guard, 'BI_ACTIVE_RECIPE', guard.RB_RECIPE)
        patch.start(); self.addCleanup(patch.stop)
        command = mock.patch.object(guard, 'run_cmd', side_effect=AssertionError('unexpected host command'))
        command.start(); self.addCleanup(command.stop)

    def test_complete_unsigned_git_recipe_is_accepted_without_aws_signature(self):
        report = manifest()
        self.assertNotIn('rpm_signature_verified', report)
        self.assertEqual(report['artifacts'], guard.bi_validate_build(report))
        self.assertFalse(guard.bi_recipe()['requires_srpm_signature'])

    def test_other_recipe_or_build_identity_is_rejected(self):
        for key, value in [('recipe', 'baota-al2-php74'), ('target_release', guard.BAOTA_AL2_RELEASE),
                           ('target_version', '7.4.33'), ('packaging_commit', '0' * 40),
                           ('upstream_commit', '0' * 40), ('source_sha256', '0' * 64),
                           ('regression_patch_sha256', '0' * 64)]:
            report = manifest(); report[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                guard.bi_validate_build(report)

    def test_fictitious_signature_flags_or_unrun_tests_are_rejected(self):
        for key, value in [('source_signature_verified', True), ('signed', True),
                           ('tests_required', False), ('php_selftests_passed', False), ('stage', 'compile_test_package')]:
            report = manifest(); report[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                guard.bi_validate_build(report)

    def test_every_pinned_source_and_packaging_input_is_required(self):
        for name in guard.rb_input_hashes():
            report = manifest(); report['inputs'].pop(name)
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                guard.bi_validate_build(report)

    def test_al2_smoke_sapi_name_is_not_accepted_as_remi_build(self):
        report = manifest(); report['mitigation_smoke_tests'][0]['sapi'] = 'build-apache'
        with self.assertRaisesRegex(RuntimeError, 'mitigation'):
            guard.bi_validate_build(report)

    def test_failure_or_missing_core_artifact_cannot_be_accepted(self):
        reports = []
        report = manifest(); report['php_selftest_summary']['failed'] = 1; reports.append(report)
        report = manifest(); report['artifacts'].pop(); reports.append(report)
        report = manifest(); report['artifacts'][0]['file'] = '../../outside.rpm'; reports.append(report)
        report = manifest(); report['artifacts'].append(copy.deepcopy(report['artifacts'][0])); reports.append(report)
        for report in reports:
            with self.subTest(report=report), self.assertRaises(RuntimeError):
                guard.bi_validate_build(report)

    def test_stage_checks_payload_hash_before_rpm_and_rejects_wrong_source_rpm(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); report = manifest()
            (root / 'build.json').write_text(json.dumps(report)); (root / 'build.log').write_text('fixture log')
            rpms = root / 'rpmbuild' / 'RPMS' / 'x86_64'; rpms.mkdir(parents=True)
            row = report['artifacts'][0]; (rpms / row['file']).write_bytes(b'RPM fixture')
            dest = root / 'accepted'; dest.mkdir()
            meta = dict(row, header_sha1='a' * 40,
                        source_rpm='php-%s-%s.src.rpm' % (guard.BAOTA_AL2_VERSION, guard.BAOTA_AL2_RELEASE))
            with mock.patch.object(guard, 'bp_selftest_summary', return_value=report['php_selftest_summary']), \
                 mock.patch.object(guard, 'bi_metadata', return_value=meta):
                with self.assertRaisesRegex(RuntimeError, 'source RPM identity'):
                    guard.bi_stage(str(root / 'build.json'), str(dest))

    def test_unrelated_host_versions_or_managers_reject_before_package_work(self):
        for os_id, version, manager in [('amzn', '2', 'yum'), ('centos', '8', 'dnf'),
                                         ('ubuntu', '20.04', 'apt'), ('rocky', '7', 'yum')]:
            inv = host(); inv.update(os={'id': os_id, 'version_id': version}, package_manager=manager)
            with self.subTest(os_id=os_id):
                self.assertTrue(guard.bi_plan(inv, [artifact()])['blockers'])

    def test_centos7_and_rhel7_exact_remi_packages_can_plan(self):
        for os_id, version in [('centos', '7.9'), ('centos', '7'), ('rhel', '7.9')]:
            inv = host(); inv['os'] = {'id': os_id, 'version_id': version}
            with self.subTest(os_id=os_id), mock.patch.object(guard, 'native_compare', return_value=1), \
                 mock.patch.object(guard, 'check_package_integrity', return_value=[]):
                plan = guard.bi_plan(inv, [artifact()])
            self.assertEqual([], plan['blockers'])
            self.assertEqual('7.4.34-' + guard.RB_RELEASE, plan['updates'][0]['version'])

    def test_native_centos_aws_scl_or_wrong_branch_packages_are_not_replaced(self):
        cases = [dict(version='7.4.33-1.el7', source_rpm='php-7.4.33-1.el7.src.rpm'),
                 dict(version='7.4.33-1.amzn2', source_rpm='php-7.4.33-1.amzn2.src.rpm'),
                 dict(name='php74-php-cli', source='php74-php'),
                 dict(source_rpm='not-the-installed-source.src.rpm'),
                 dict(version='8.2.35-1.el7.remi', upstream='8.2.35'), dict(arch='aarch64')]
        with mock.patch.object(guard, 'native_compare') as compare, \
             mock.patch.object(guard, 'check_package_integrity', return_value=[]):
            for changes in cases:
                inv = host(); inv['packages'][0].update(changes)
                with self.subTest(changes=changes):
                    plan = guard.bi_plan(inv, [artifact()])
                    self.assertTrue(plan['blockers']); self.assertEqual([], plan['updates'])
        compare.assert_not_called()

    def test_installed_extension_without_compatible_artifact_blocks_partial_upgrade(self):
        inv = host(); inv['packages'].append(dict(inv['packages'][0], name='php-oci8'))
        with mock.patch.object(guard, 'native_compare', return_value=1), \
             mock.patch.object(guard, 'check_package_integrity', return_value=[]):
            plan = guard.bi_plan(inv, [artifact()])
        self.assertTrue(plan['blockers'])
        self.assertIn('php-oci8', plan['blockers'][0]['reason'])

    def test_no_receipt_does_not_turn_vendor_version_string_into_security_proof(self):
        inv = host(); inv['packages'][0].update(version=guard.RB_VERSION + '-' + guard.RB_RELEASE,
                                             upstream=guard.RB_VERSION)
        with mock.patch.object(guard, 'check_package_integrity', return_value=[]):
            findings = guard.bi_assess(inv, {})
        self.assertEqual('affected', findings[0]['status'])

    def test_changed_payload_overrides_matching_receipt_header(self):
        inv = host(); item = artifact()
        meta = dict(version=guard.RB_VERSION, release=guard.RB_RELEASE, header_sha1=item['header_sha1'])
        with mock.patch.object(guard, 'check_package_integrity', return_value=[]), \
             mock.patch.object(guard, 'bi_metadata', return_value=meta), \
             mock.patch.object(guard, 'bi_payload_ok', return_value=False):
            findings = guard.bi_assess(inv, {'packages': [item]})
        self.assertTrue(any(x.get('kind') == 'binary_integrity' for x in findings))

    def test_receipt_cannot_accept_same_name_with_another_architecture_for_either_recipe(self):
        for recipe_name in ('baota-al2-php74', guard.RB_RECIPE):
            with mock.patch.object(guard, 'BI_ACTIVE_RECIPE', recipe_name):
                recipe = guard.bi_recipe()
                meta = dict(version=recipe['version'], release=recipe['release'], header_sha1='a' * 40)
                receipt = {'packages': [dict(name='php-cli', arch='x86_64', header_sha1='a' * 40)]}
                for arches in (('x86_64',), ('x86_64', 'i686')):
                    inv = host()
                    inv['packages'] = [dict(name='php-cli', source='php', arch=arch,
                        version=recipe['version'] + '-' + recipe['release'], upstream=recipe['version'])
                        for arch in arches]
                    with self.subTest(recipe=recipe_name, arches=arches), \
                         mock.patch.object(guard, 'check_package_integrity', return_value=[]), \
                         mock.patch.object(guard, 'bi_metadata', return_value=meta), \
                         mock.patch.object(guard, 'bi_payload_ok', return_value=True):
                        findings = guard.bi_assess(inv, receipt)
                    self.assertEqual(len(arches), len(findings))
                    self.assertEqual(len(arches) == 1, all(row['status'] == 'fixed' for row in findings))
                    if len(arches) > 1:
                        self.assertFalse(any(row['status'] == 'fixed' for row in findings))

    def test_al2_default_context_and_signature_requirement_are_preserved(self):
        with mock.patch.object(guard, 'BI_ACTIVE_RECIPE', 'baota-al2-php74'):
            config = guard.bi_recipe()
            self.assertTrue(config['requires_srpm_signature'])
            self.assertEqual(guard.BAOTA_AL2_RELEASE, config['release'])
            with self.assertRaises(RuntimeError):
                guard.bi_validate_build(manifest())


class RemiWrapperTests(unittest.TestCase):
    def test_recipe_and_receipt_are_scoped_and_restored_even_on_error(self):
        original = guard.BI_ACTIVE_RECIPE, guard.BI_RECEIPT
        def invoke(argv):
            self.assertEqual('baota-remi-el7-php74', guard.BI_ACTIVE_RECIPE)
            self.assertEqual('/var/lib/php-cve-guard/baota-remi-el7-php74.json', guard.BI_RECEIPT)
            raise RuntimeError('fixture')
        with mock.patch.object(guard, 'baota_install_main', side_effect=invoke):
            with self.assertRaisesRegex(RuntimeError, 'fixture'):
                guard.remi_install_main(['plan', '--build-report', '/fixture/build.json'])
        self.assertEqual(original, (guard.BI_ACTIVE_RECIPE, guard.BI_RECEIPT))

    def test_cross_distribution_is_rejected_before_reading_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            inv = host(); inv['os'] = {'id': 'amzn', 'version_id': '2'}
            with mock.patch.object(guard.sys, 'platform', 'linux'), \
                 mock.patch.object(guard.os, 'geteuid', return_value=0), \
                 mock.patch.object(guard.os, 'umask'), \
                 mock.patch.object(guard, 'bi_private_dir'), \
                 mock.patch.object(guard.tempfile, 'mkdtemp', return_value=tmp), \
                 mock.patch.object(guard, 'say'), \
                 mock.patch.object(guard, 'collect_inventory', return_value=inv), \
                 mock.patch.object(guard, 'bi_stage') as stage, \
                 mock.patch.object(guard, 'bi_transaction') as transaction:
                code = guard.remi_install_main(['plan', '--build-report', '/fixture/build.json'])
            report = json.loads((pathlib.Path(tmp) / 'report.json').read_text())
        self.assertEqual(10, code)
        self.assertEqual('unsupported_host', report['result'])
        self.assertEqual(guard.RB_RECIPE, report['recipe'])
        stage.assert_not_called(); transaction.assert_not_called()


if __name__ == '__main__':
    unittest.main()
