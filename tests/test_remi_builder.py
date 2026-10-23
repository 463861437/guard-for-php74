"""Pinned Remi EL7 rebuild boundaries; never compile/install host packages."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guard_remi_builder_test', ROOT / 'php_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
exec(compile((ROOT / 'src/remi_builder.py').read_text(), '<remi-builder>', 'exec'), guard.__dict__)
ORIGINAL = (ROOT / 'tests/fixtures/php74-remi-el7.spec').read_bytes()


class RemiRecipeTests(unittest.TestCase):
    def test_spec_pin_source_identity_and_old_security_stack_are_preserved(self):
        rendered = guard.rb_render_spec(ORIGINAL).decode()
        self.assertIn('%global upver        7.4.34', rendered)
        self.assertIn('Release: ' + guard.RB_RELEASE, rendered)
        self.assertIn('Source0: ' + guard.RB_SOURCE_URL, rendered)
        self.assertIn(guard.RB_SOURCE_SHA, rendered)
        self.assertNotIn('Source20:', rendered)
        self.assertNotIn('Source21:', rendered)
        self.assertNotIn('%{?gpgverify:', rendered)
        for line in ORIGINAL.decode().splitlines():
            if line.startswith(('Patch', '%patch')):
                self.assertIn(line, rendered)
        self.assertIn('%patch -P400 -p1 -F0', rendered)
        self.assertIn('./buildconf --force', rendered)
        self.assertNotIn('rm ext/date/tests/bug33415-2.phpt', rendered)
        self.assertNotIn('  #exit 1', rendered)
        self.assertIn('make test TESTS=-j%{phpguard_jobs}', rendered)
        for identity in ('PHP_API_VERSION', 'ZEND_MODULE_API_NO', 'PDO_DRIVER_API'):
            self.assertIn(identity, rendered)

    def test_modified_baseline_rejects_before_any_rewrite(self):
        with self.assertRaisesRegex(RuntimeError, 'pinned upstream'):
            guard.rb_render_spec(ORIGINAL + b'\n# different upstream')

    def test_profile_is_el7_x86_only_not_generic_rpm(self):
        valid = dict(platform='linux', os_id='centos', os_version='7', architecture='x86_64')
        self.assertTrue(guard.rb_host_supported(valid))
        self.assertTrue(guard.rb_host_supported(dict(valid, os_id='rhel', os_version='7.9')))
        for changes in ({'os_id': 'amzn', 'os_version': '2'}, {'os_version': '8'},
                        {'os_id': 'rocky'}, {'architecture': 'aarch64'},
                        {'platform': 'darwin'}, {'os_version': '70'}):
            self.assertFalse(guard.rb_host_supported(dict(valid, **changes)))

    def test_inputs_pin_every_packaging_file_source_and_regression_patch(self):
        hashes = guard.rb_input_hashes()
        self.assertEqual(guard.RB_PACKAGING['php74.spec'], hashlib.sha256(ORIGINAL).hexdigest())
        self.assertEqual(49, len(hashes))
        self.assertEqual(guard.RB_SOURCE_SHA, hashes[guard.RB_ARCHIVE])
        self.assertEqual(guard.BP_TEST_PATCH_SHA, hashes[guard.BP_TEST_PATCH_NAME])
        self.assertIn('php-cve-2024-5458.patch', hashes)

    def test_macro_definitions_keep_rhel7_tests_and_fuzz_zero(self):
        definitions = guard.rb_definitions('/tmp/rpmbuild', 3)
        for definition in ('rhel 7', 'dist .el7.remi', 'runselftest 1',
                           '_default_patch_fuzz 0', 'phpguard_jobs 3', '_smp_mflags -j3'):
            self.assertIn(definition, definitions)
        self.assertFalse(any('amzn' in value for value in definitions))

    def test_dependencies_keep_remi_native_versions_and_disable_optional_oci(self):
        self.assertIn('pkgconfig(icu-i18n) >= 73', guard.RB_BUILD_REQUIRES)
        self.assertIn('pkgconfig(gdlib) >= 2.3.3', guard.RB_BUILD_REQUIRES)
        self.assertIn('oniguruma5php-devel', guard.RB_BUILD_REQUIRES)
        self.assertFalse(any('oracle' in value for value in guard.RB_BUILD_REQUIRES))


class RemiBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard-remi-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.args = argparse.Namespace(work_dir=str(self.root), jobs=2)
        self.host = dict(platform='linux', os_id='centos', os_version='7', architecture='x86_64', uid=1000)
        self.commands = []
        self.report_hashes = {'php74.spec': guard.RB_PACKAGING['php74.spec']}
        (self.root / 'inputs').mkdir()
        (self.root / 'inputs/php74.spec').write_bytes(ORIGINAL)
        for name, value in [('bp_doctor_host', self.host), ('say', None), ('rb_smoke_tests', []),
                            ('bp_selftest_summary', {'passed': 200, 'failed': 0}),
                            ('rb_check_artifacts', [{'name': 'php-cli'}]),
                            ('bp_failure_summary', {'hint': 'check log'}),
                            ('bp_tool', '/usr/bin/stub'), ('os.geteuid', 1000)]:
            target = guard.os if name == 'os.geteuid' else guard
            attribute = 'geteuid' if name == 'os.geteuid' else name
            patch = mock.patch.object(target, attribute, return_value=value)
            patch.start(); self.addCleanup(patch.stop)

    def command(self, argv, log=None, **kwargs):
        self.commands.append(argv)
        if '-ba' in argv:
            top = pathlib.Path(argv[argv.index('--define') + 1].split(' ', 1)[1])
            source = top / 'SRPMS' / ('php-' + guard.RB_VERSION + '-' + guard.RB_RELEASE + '.src.rpm')
            source.write_bytes(b'build output fixture')
        return ''

    def build(self, command=None):
        with mock.patch.object(guard, 'rb_verify_prepared', return_value=str(self.root / 'inputs')), \
             mock.patch.object(guard, 'rb_input_hashes', return_value=self.report_hashes), \
             mock.patch.object(guard, 'bp_call', side_effect=command or self.command):
            return guard.rb_build(self.args)

    def report(self):
        return json.loads(next(self.root.glob('build-*/build.json')).read_text())

    def test_non_al2_build_runs_native_prep_before_compile_and_never_deploys(self):
        self.assertEqual(0, self.build())
        self.assertEqual(['-bp', '-ba'], [argv[-2] for argv in self.commands])
        report = self.report()
        self.assertEqual('built_not_deployed', report['state'])
        self.assertFalse(report['deployed'])
        self.assertFalse(report['source_signature_verified'])
        self.assertFalse(report['signed'])
        self.assertEqual(guard.RB_COMMIT, report['packaging_commit'])
        self.assertEqual(guard.BP_COMMIT, report['upstream_commit'])
        self.assertEqual('complete', report['stage'])

    def test_missing_dependency_or_conflicting_patch_stops_before_compile(self):
        with self.assertRaisesRegex(RuntimeError, 'missing dependency'):
            self.build(command=mock.Mock(side_effect=RuntimeError('missing dependency')))
        report = self.report()
        self.assertEqual('build_failed', report['state'])
        self.assertEqual('prepare_and_dependencies', report['stage'])
        self.assertFalse(report['deployed'])

    def test_full_suite_failure_never_marks_artifacts_valid(self):
        with mock.patch.object(guard, 'bp_selftest_summary', side_effect=RuntimeError('test failure')), \
             mock.patch.object(guard, 'rb_check_artifacts') as check:
            with self.assertRaisesRegex(RuntimeError, 'test failure'):
                self.build()
        check.assert_not_called()
        self.assertEqual('build_failed', self.report()['state'])
        self.assertNotIn('artifacts', self.report())

    def test_root_and_other_os_block_before_prepared_files(self):
        with mock.patch.object(guard, 'rb_verify_prepared') as verify, \
             mock.patch.object(guard.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'normal user'):
                guard.rb_build(self.args)
            verify.assert_not_called()
        with mock.patch.object(guard, 'rb_verify_prepared') as verify, \
             mock.patch.object(guard, 'bp_doctor_host', return_value=dict(self.host, os_version='8')):
            with self.assertRaisesRegex(RuntimeError, 'only supports'):
                guard.rb_build(self.args)
            verify.assert_not_called()


class RemiInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard-remi-inputs-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def fixture(self):
        inputs = self.root / 'inputs'; inputs.mkdir()
        (inputs / 'php74.spec').write_bytes(ORIGINAL)
        (self.root / 'php74-baota.spec').write_bytes(guard.rb_render_spec(ORIGINAL))
        return inputs

    def test_changed_prepared_spec_is_rejected_even_if_prepare_json_claims_ready(self):
        self.fixture()
        (self.root / 'php74-baota.spec').write_bytes(b'%prep\nmalicious command\n')
        with mock.patch.object(guard, 'rb_input_hashes', return_value={'php74.spec': guard.RB_PACKAGING['php74.spec']}), \
             mock.patch.object(guard, 'bp_verify_baota_archive'):
            with self.assertRaisesRegex(RuntimeError, 'Prepared SPEC changed'):
                guard.rb_verify_prepared(str(self.root))

    def test_symlink_input_is_rejected_before_hash_or_archive_processing(self):
        inputs = self.root / 'inputs'; inputs.mkdir()
        (self.root / 'outside').write_bytes(ORIGINAL)
        (inputs / 'php74.spec').symlink_to(self.root / 'outside')
        with mock.patch.object(guard, 'rb_input_hashes', return_value={'php74.spec': guard.RB_PACKAGING['php74.spec']}), \
             mock.patch.object(guard, 'bp_verify') as verify:
            with self.assertRaisesRegex(RuntimeError, 'not a regular file'):
                guard.rb_verify_prepared(str(self.root))
            verify.assert_not_called()

    def test_cli_rejects_missing_workdir_and_unbounded_jobs(self):
        for argv in (['build'], ['prepare'], ['build', '--work-dir', '/tmp/a', '--source-tar', 'x'],
                     ['doctor', '--jobs', '0'], ['build', '--work-dir', '/tmp/a', '--jobs', '65']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                guard.remi_build_main(argv)
            self.assertEqual(2, caught.exception.code)


if __name__ == '__main__':
    unittest.main()
