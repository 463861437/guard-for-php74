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
exec(compile((ROOT / 'src/backport_builder.py').read_text(), '<backport-builder>', 'exec'), guard.__dict__)
exec(compile((ROOT / 'src/remi_builder.py').read_text(), '<remi-builder>', 'exec'), guard.__dict__)
ORIGINAL = (ROOT / 'tests/fixtures/php74-remi-el7.spec').read_bytes()
CVE203 = (ROOT / 'tests/fixtures/php-cve-2023-0662-remi.patch').read_bytes()


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
                self.assertIn('Patch203: ' + guard.RB_CVE203_PATCH if line.startswith('Patch203:') else line, rendered)
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
        self.assertEqual(50, len(hashes))
        self.assertEqual(guard.RB_SOURCE_SHA, hashes[guard.RB_ARCHIVE])
        self.assertEqual(guard.BP_TEST_PATCH_SHA, hashes[guard.BP_TEST_PATCH_NAME])
        self.assertIn('php-cve-2024-5458.patch', hashes)

    def test_cve203_keeps_missing_fix_and_news_and_checks_exact_source_state(self):
        adapted = guard.rb_compat_patch_bytes(CVE203)
        self.assertEqual((ROOT / 'patches' / guard.RB_CVE203_PATCH).read_bytes(), adapted)
        self.assertEqual(guard.RB_CVE203_SHA, hashlib.sha256(adapted).hexdigest())
        self.assertNotIn(b'From ' + guard.RB_CVE203_INCLUDED_COMMIT.encode(), adapted)
        for commit in ('3a2fdef1ae38881110006616ee1f0534b082ca45',
                       '472db3ee3a00ac00d36019eee0b3b7362334481c',
                       'c04f310440a906fc4ca885f4ecf6e3e4cd36edc7'):
            self.assertIn(('From ' + commit).encode(), adapted)
        self.assertIn(b'+\t\t\t\tif (upload_cnt == 0)', adapted)
        self.assertNotIn(b'+++ b/main/main.c', adapted)
        rendered = guard.rb_render_spec(ORIGINAL).decode()
        self.assertLess(rendered.index(guard.rb_source_guard(guard.RB_CVE203_BEFORE)),
                        rendered.index('%patch -P203 '))
        self.assertGreater(rendered.index(guard.rb_source_guard(guard.RB_CVE203_AFTER)),
                           rendered.index('%patch -P400 '))
        self.assertNotIn('--forward', rendered)
        self.assertNotIn('|| true', rendered)
        with self.assertRaisesRegex(RuntimeError, 'pinned input'):
            guard.rb_compat_patch_bytes(CVE203 + b'\n')

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
                            ('rb_multipart_smoke_tests', guard.RB_MULTIPART_EXPECTED),
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

    def test_multipart_failure_never_marks_artifacts_valid(self):
        with mock.patch.object(guard, 'rb_multipart_smoke_tests', side_effect=RuntimeError('multipart failed')), \
             mock.patch.object(guard, 'rb_check_artifacts') as check:
            with self.assertRaisesRegex(RuntimeError, 'multipart failed'):
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


class RemiMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard-remi-migration-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        self.content = {'php74.spec': ORIGINAL, 'php-cve-2023-0662.patch': CVE203,
                        guard.RB_ARCHIVE: b'fixed archive fixture', guard.BP_TEST_PATCH_NAME: guard.BP_TEST_PATCH}
        self.previous = {name: hashlib.sha256(value).hexdigest() for name, value in self.content.items()}
        self.current = dict(self.previous, **{guard.RB_CVE203_PATCH: guard.RB_CVE203_SHA})
        for name, value in self.content.items():
            (self.inputs / name).write_bytes(value)
        old_spec = guard._rb_render_legacy_spec(ORIGINAL)
        (self.root / 'php74-baota.spec').write_bytes(old_spec)
        self.old_report = dict(recipe=guard.RB_RECIPE, state='sources_prepared_not_built',
                               packaging_commit=guard.RB_COMMIT, target_version=guard.RB_VERSION,
                               target_release=guard.RB_RELEASE, source_signature_verified=False,
                               inputs=self.previous, spec_sha256=hashlib.sha256(old_spec).hexdigest())
        (self.root / 'prepare.json').write_text(json.dumps(self.old_report))
        self.old_build = self.root / 'build-previous'; self.old_build.mkdir()
        (self.old_build / 'prep.log').write_bytes(b'original failing log\n')
        for name, value in [('rb_input_hashes', self.current), ('bp_verify_baota_archive', None)]:
            patch = mock.patch.object(guard, name, return_value=value)
            patch.start(); self.addCleanup(patch.stop)

    def migrate(self):
        return guard.rb_migrate_prepared(str(self.root))

    def test_fixed_legacy_preparation_migrates_and_is_idempotent(self):
        self.assertTrue(self.migrate())
        self.assertFalse(self.migrate())
        self.assertEqual(guard.rb_render_spec(ORIGINAL), (self.root / 'php74-baota.spec').read_bytes())
        self.assertEqual(guard.rb_compat_patch_bytes(CVE203), (self.inputs / guard.RB_CVE203_PATCH).read_bytes())
        self.assertEqual(self.current, json.loads((self.root / 'prepare.json').read_text())['inputs'])
        self.assertEqual(b'original failing log\n', (self.old_build / 'prep.log').read_bytes())
        guard.rb_verify_prepared(str(self.root))

    def test_interruption_between_each_atomic_write_can_resume(self):
        real_write = guard.rb_atomic_prepare_file
        for cutoff in (0, 1, 2):
            with self.subTest(cutoff=cutoff):
                (self.root / 'php74-baota.spec').write_bytes(guard._rb_render_legacy_spec(ORIGINAL))
                (self.root / 'prepare.json').write_text(json.dumps(self.old_report))
                path = self.inputs / guard.RB_CVE203_PATCH
                if path.exists(): path.unlink()
                calls = []
                def interrupted(folder, relative, content):
                    if len(calls) == cutoff: raise RuntimeError('simulated interruption')
                    calls.append(relative); return real_write(folder, relative, content)
                with mock.patch.object(guard, 'rb_atomic_prepare_file', side_effect=interrupted):
                    with self.assertRaisesRegex(RuntimeError, 'simulated interruption'):
                        self.migrate()
                self.assertTrue(self.migrate())
                self.assertFalse(self.migrate())
                guard.rb_verify_prepared(str(self.root))

    def test_changed_spec_or_unknown_input_or_tampered_patch_rejected_without_writes(self):
        spec = self.root / 'php74-baota.spec'
        for kind in ('spec', 'unknown', 'patch', 'report'):
            with self.subTest(kind=kind):
                spec.write_bytes(guard._rb_render_legacy_spec(ORIGINAL))
                (self.root / 'prepare.json').write_text(json.dumps(self.old_report))
                unknown = self.inputs / 'unexpected.patch'
                extra = self.inputs / guard.RB_CVE203_PATCH
                if unknown.exists(): unknown.unlink()
                if extra.exists(): extra.unlink()
                if kind == 'spec': spec.write_bytes(spec.read_bytes() + b'\n# changed')
                if kind == 'unknown': unknown.write_bytes(b'unknown input')
                if kind == 'patch': extra.write_bytes(b'tampered patch')
                if kind == 'report': (self.root / 'prepare.json').write_text('{}')
                with mock.patch.object(guard, 'rb_atomic_prepare_file') as write:
                    with self.assertRaises(RuntimeError): self.migrate()
                    write.assert_not_called()

    def test_old_prepared_directory_is_not_accepted_by_readonly_verifier(self):
        with self.assertRaisesRegex(RuntimeError, 'missing or not a regular file'):
            guard.rb_verify_prepared(str(self.root))


class RemiMultipartTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard-remi-cgi-')
        self.addCleanup(self.tmp.cleanup)
        self.top = pathlib.Path(self.tmp.name) / 'rpmbuild'; self.top.mkdir()
        php = self.top / 'BUILD' / ('php-' + guard.RB_VERSION) / 'build-cgi/sapi/cgi/php-cgi'
        php.parent.mkdir(parents=True); php.write_bytes(b'fixture binary')
        self.calls = []
        self.failure = None

    def run_cgi(self, argv, log, **kwargs):
        self.calls.append((argv, kwargs))
        upload = any(x == 'max_file_uploads=0' for x in argv)
        post = [] if upload else {'first': 'one'}
        warning = ('Maximum number of allowable file uploads has been exceeded' if upload else
                   'Multipart body parts limit exceeded 1. To increase the limit change max_multipart_body_parts in php.ini.')
        output = 'PHP Warning: ' + warning + '\nContent-Type: text/html\r\n\r\n'
        if self.failure == 'repeat': output = output + 'PHP Warning: ' + warning + '\n'
        if self.failure == 'missing': output = ''
        result = {'version': guard.RB_VERSION, 'post': post, 'files': []}
        if self.failure == 'fields' and not upload: result['post']['second'] = 'two'
        if self.failure == 'files' and upload: result['files'] = ['first_upload']
        if self.failure == 'identity': result['version'] = '7.4.33'
        output += 'PHP_GUARD_MULTIPART=' + json.dumps(result) + '\n'
        pathlib.Path(log).write_text(output)

    def test_native_cgi_checks_both_quotas_using_isolated_request_environment(self):
        with mock.patch.object(guard, 'bm_run', side_effect=self.run_cgi):
            self.assertEqual(guard.RB_MULTIPART_EXPECTED, guard.rb_multipart_smoke_tests(str(self.top)))
        self.assertEqual(2, len(self.calls))
        for argv, kwargs in self.calls:
            self.assertEqual('-n', argv[1])
            self.assertEqual(30, kwargs['timeout'])
            self.assertEqual('POST', kwargs['env']['REQUEST_METHOD'])
            self.assertEqual(str(len(kwargs['data'])), kwargs['env']['CONTENT_LENGTH'])
            self.assertEqual('/dev/null', kwargs['env']['PHP_INI_SCAN_DIR'])
            self.assertNotIn('HTTP_COOKIE', kwargs['env'])
            self.assertIn(b'Content-Disposition: form-data;', kwargs['data'])

    def test_ignored_limit_repeated_or_missing_warning_or_wrong_binary_are_rejected(self):
        for failure in ('fields', 'files', 'repeat', 'missing', 'identity'):
            with self.subTest(failure=failure):
                self.failure = failure
                with mock.patch.object(guard, 'bm_run', side_effect=self.run_cgi):
                    with self.assertRaisesRegex(RuntimeError, 'multipart regression failed'):
                        guard.rb_multipart_smoke_tests(str(self.top))


if __name__ == '__main__':
    unittest.main()
