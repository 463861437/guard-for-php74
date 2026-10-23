"""Pinned PHP 8.2 EL7 recipe boundaries; never install or build host packages."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guard_remi82_builder_test', ROOT / 'php_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
exec(compile((ROOT / 'src/remi82_builder.py').read_text(), '<remi82-builder>', 'exec'), guard.__dict__)
ORIGINAL = {layout: (ROOT / ('tests/fixtures/php82-remi-el7-' + layout + '.spec')).read_bytes()
            for layout in ('system', 'scl')}


class Remi82RecipeTests(unittest.TestCase):
    def test_both_layouts_pin_original_and_preserve_native_names_scriptlets_abi(self):
        for layout in ('system', 'scl'):
            with self.subTest(layout=layout):
                profile = guard.r82_profile(layout)
                self.assertEqual(hashlib.sha256(ORIGINAL[layout]).hexdigest(),
                                 profile['packaging'][profile['spec_name']])
                text = guard.r82_render_spec(ORIGINAL[layout], layout).decode()
                self.assertIn('Release: ' + guard.R82_RELEASE, text)
                self.assertIn('Source0: ' + guard.R82_SOURCE_URL, text)
                self.assertIn('%global upver        8.2.35', text)
                self.assertIn('%global with_tests 1', text)
                self.assertIn('make test TESTS=-j%{phpguard_jobs}', text)
                self.assertIn('BuildRequires: tzdata >= 2022b', text)
                self.assertEqual(1, text.count('--enable-zend-test=shared'))
                self.assertIn('make -C build-fpm install-fpm', text)
                self.assertNotIn('make -C build-fpm install-modules', text)
                self.assertNotIn('  #exit 1', text)
                self.assertIn('php-8.2.23-systzdata-v24.patch', text)
                self.assertIn('php-8.2.25-phpinfo.patch', text)
                for line in ORIGINAL[layout].decode().splitlines():
                    if line.startswith(('%patch', '%post', '%pre', '%config', '%global apiver',
                                        '%global zendver', '%global pdover', 'Name:')):
                        self.assertIn(line, text)
                self.assertIn('Provides:      bundled(pcre2) = 10.40', text)

    def test_fpm_subprocesses_load_test_helper_only_during_check(self):
        for layout in ('system', 'scl'):
            with self.subTest(layout=layout):
                text = guard.r82_render_spec(ORIGINAL[layout], layout).decode()
                check = text.split('\n%check\n', 1)[1].split('\n%install\n', 1)[0]
                export = 'export TEST_FPM_EXTENSION_DIR="$PWD/modules"'
                self.assertEqual(1, text.count(export))
                self.assertIn('cd build-fpm\n' + export, check)
                self.assertLess(check.index(export), check.index('make test'))
                self.assertIn('unset NO_INTERACTION REPORT_EXIT_STATUS MALLOC_CHECK_ TEST_FPM_EXTENSION_DIR', check)
                self.assertNotIn('TEST_FPM_EXTENSION_DIR', text.split('\n%check\n', 1)[0])

    def test_openssl_compat_input_is_fixed_and_applied_to_both_layouts(self):
        patch = (ROOT / 'patches' / guard.R82_OPENSSL_COMPAT_PATCH).read_bytes()
        self.assertEqual(guard.R82_OPENSSL_COMPAT_BYTES, patch)
        self.assertEqual(guard.R82_OPENSSL_COMPAT_SHA, hashlib.sha256(patch).hexdigest())
        self.assertIn(b'+#if PHP_OPENSSL_API_VERSION < 0x10100', patch)
        self.assertIn(b'+static const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *asn1)', patch)
        self.assertIn(b'+\treturn M_ASN1_STRING_data(asn1);', patch)
        self.assertEqual(1, patch.count(b'--- a/'))
        self.assertIn(b'--- a/ext/openssl/xp_ssl.c', patch)
        for layout in ('system', 'scl'):
            text = guard.r82_render_spec(ORIGINAL[layout], layout).decode()
            self.assertEqual(guard.R82_OPENSSL_COMPAT_SHA,
                             guard.r82_input_hashes(layout)[guard.R82_OPENSSL_COMPAT_PATCH])
            self.assertIn('Patch400: ' + guard.R82_OPENSSL_COMPAT_PATCH, text)
            self.assertEqual(1, text.count('%patch -P400 -p1 -b .openssl10-compat'))

    def test_openssl_compat_patch_written_and_tampering_fails_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            guard.r82_write_compat_patch(directory)
            target = pathlib.Path(directory) / guard.R82_OPENSSL_COMPAT_PATCH
            self.assertEqual(guard.R82_OPENSSL_COMPAT_BYTES, target.read_bytes())
            target.unlink()
            with mock.patch.object(guard, 'R82_OPENSSL_COMPAT_BYTES', b'changed'), \
                 self.assertRaisesRegex(RuntimeError, 'SHA256 mismatch'):
                guard.r82_write_compat_patch(directory)
            self.assertFalse(target.exists())

    def test_fixed_openssl_test_patch_preserves_exact_error_check(self):
        patch = (ROOT / 'patches' / guard.R82_TEST_COMPAT_PATCH).read_bytes()
        self.assertEqual(guard.R82_TEST_COMPAT_BYTES, patch)
        self.assertEqual(guard.R82_TEST_COMPAT_SHA, hashlib.sha256(patch).hexdigest())
        self.assertIn(b'OPENSSL_VERSION_NUMBER >= 0x10002000 && OPENSSL_VERSION_NUMBER < 0x10100000', patch)
        self.assertIn(b"[$is_openssl_102 ? '040A1079' : '04099079']", patch)
        fixture = (ROOT / 'tests/fixtures/php82-fpm-known-xpass.phpt').read_bytes()
        self.assertEqual(guard.R82_KNOWN_XPASS_SHA, hashlib.sha256(fixture).hexdigest())
        self.assertIn(b'--XFAIL--\nFails intermittently\n', fixture)

    def test_changed_original_is_rejected_before_spec_edit(self):
        for layout in ('system', 'scl'):
            with self.assertRaisesRegex(RuntimeError, 'pinned packaging'):
                guard.r82_render_spec(ORIGINAL[layout] + b'\n', layout)

    def test_inputs_include_signature_and_are_specific_to_layout(self):
        for layout in ('system', 'scl'):
            hashes = guard.r82_input_hashes(layout)
            self.assertEqual(guard.R82_SOURCE_SHA, hashes[guard.R82_ARCHIVE])
            self.assertEqual(guard.R82_SIGNATURE_SHA, hashes[guard.R82_SIGNATURE])
            self.assertEqual(guard.R82_KEYRING_SHA, hashes[guard.R82_KEYRING])
            self.assertIn(guard.r82_profile(layout)['spec_name'], hashes)
            self.assertNotIn('php-8.1.0-systzdata-v24.patch', hashes)
            self.assertNotIn('php-8.1.0-phpinfo.patch', hashes)
        self.assertNotEqual(guard.r82_input_hashes('system'), guard.r82_input_hashes('scl'))

    def test_only_native_el7_x86_64_supported(self):
        host = dict(platform='linux', os_id='centos', os_version='7.9', architecture='x86_64')
        self.assertTrue(guard.r82_host_supported(host))
        self.assertTrue(guard.r82_host_supported(dict(host, os_id='rhel')))
        for changes in ({'os_id': 'amzn'}, {'os_version': '8'}, {'platform': 'darwin'},
                        {'architecture': 'aarch64'}, {'os_version': '70'}):
            self.assertFalse(guard.r82_host_supported(dict(host, **changes)))

    def test_scl_requires_native_macros_without_changing_system_layout(self):
        base = guard.r82_build_requirements(['system'])
        both = guard.r82_build_requirements(['system', 'scl'])
        self.assertNotIn('php82-build', base)
        self.assertIn('php82-build = 8.2-5.el7.remi', both)
        self.assertIn('scl-utils-build', both)
        self.assertIn('pkgconfig(enchant-2)', base)
        self.assertIn('pkgconfig(libselinux)', base)
        self.assertIn('gnupg2', base)
        self.assertIn('tzdata >= 2022b', base)
        self.assertNotIn('scl php82', guard.r82_definitions('/x', 2, 'system'))
        self.assertIn('scl php82', guard.r82_definitions('/x', 2, 'scl'))
        self.assertIn('_default_patch_fuzz 0', guard.r82_definitions('/x', 2, 'system'))
        with self.assertRaises(RuntimeError):
            guard.r82_build_requirements([])
        with self.assertRaises(RuntimeError):
            guard.r82_profile('php74')


class Remi82SummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name) / 'tests.log'

    def summary(self, targeted=False, replace=None):
        total = len(guard.R82_SECURITY_TESTS) if targeted else 15000
        lines = ['PASS regression [' + name + ']' for name in guard.R82_SECURITY_TESTS]
        if not targeted:
            lines.append('TEST RESULT SUMMARY')
        lines += ['Number of tests : %d' % total,
                  'Tests skipped : 0', 'Tests warned : 0', 'Tests failed : 0',
                  'Tests passed : %d' % total, 'Time taken : 12 seconds']
        text = '\n'.join(lines) + '\n'
        if replace:
            text = replace(text)
        self.path.write_text(text)
        return guard.r82_selftest_summary(str(self.path), targeted=targeted)

    def test_complete_full_and_targeted_have_required_security_evidence(self):
        for targeted in (False, True):
            result = self.summary(targeted)
            self.assertEqual(dict.fromkeys(guard.R82_SECURITY_TESTS, 'PASS'), result['critical_regressions'])
            for key in ('failed', 'warned', 'borked', 'leaked'):
                self.assertEqual(0, result[key])

    def test_failure_warning_skipped_critical_and_missing_summary_block(self):
        variants = [lambda s: s.replace('Tests failed : 0', 'Tests failed : 1'),
                    lambda s: s.replace('Tests warned : 0', 'Tests warned : 1'),
                    lambda s: s.replace('PASS regression', 'SKIP regression', 1),
                    lambda s: s.replace('Time taken : 12 seconds', ''),
                    lambda s: s + s,
                    lambda s: s.replace('15000', '50')]
        for change in variants:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.summary(replace=change)

    def test_selected_titleless_summary_is_not_accepted_as_a_full_suite(self):
        with self.assertRaisesRegex(RuntimeError, 'summary is missing'):
            self.summary(False, lambda text: text.replace('TEST RESULT SUMMARY\n', ''))
        with self.assertRaisesRegex(RuntimeError, 'ambiguous summary'):
            self.summary(True, lambda text: text + text[text.index('Number of tests'):])

    def test_targeted_must_run_all_security_cases_no_filter_or_extra_summary(self):
        with self.assertRaisesRegex(RuntimeError, 'skipped or filtered'):
            self.summary(True, lambda s: s.replace(': 7', ': 8'))
        with self.assertRaisesRegex(RuntimeError, 'duplicate critical'):
            self.summary(True, lambda s: s + 'PASS regression [' + guard.R82_SECURITY_TESTS[0] + ']\n')


    def test_full_known_upstream_xpass_preserves_warning_and_evidence(self):
        line = 'WARN FPM buffered log [' + guard.R82_KNOWN_XPASS + ']  (warn: XFAIL section but test passes)\n'
        result = self.summary(replace=lambda text: line + text.replace('Tests warned : 0', 'Tests warned : 1').replace('Tests passed : 15000', 'Tests passed : 14999'))
        self.assertEqual(1, result['warned'])
        self.assertEqual([{'test': guard.R82_KNOWN_XPASS, 'source_sha256': guard.R82_KNOWN_XPASS_SHA,
                           'result': 'XPASS'}], result['accepted_xpasses'])
        for changed in (line + line, line.replace('XFAIL section but test passes', 'Test passed on retry attempt'),
                        line.replace(guard.R82_KNOWN_XPASS, 'unrelated.phpt')):
            with self.subTest(line=changed), self.assertRaises(RuntimeError):
                self.summary(replace=lambda text: changed + text)
        with self.assertRaises(RuntimeError):
            self.summary(True, lambda text: line + text)


class Remi82SignatureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name)

    def verify(self, status=None, code=0):
        calls = []
        def command(argv, **kwargs):
            calls.append(argv)
            if '--dearmor' in argv:
                pathlib.Path(argv[argv.index('--output') + 1]).write_bytes(b'keyring fixture')
                return dict(code=0, stdout='', stderr='')
            return dict(code=code, stdout=status if status is not None else
                        '[GNUPG:] VALIDSIG ' + guard.R82_SIGNATURE_FINGERPRINT + ' 2026-10-21 0 0 4 0 1 8 00\n', stderr='')
        with mock.patch.object(guard, 'bp_verify'), \
             mock.patch.object(guard, 'r82_gpg_tool', return_value='/usr/bin/gpg2'), \
             mock.patch.object(guard, 'run_cmd', side_effect=command):
            result = guard.r82_verify_source_signature(str(self.path), str(self.path))
        return result, calls

    def test_dearmor_isolated_keyring_then_exact_release_fingerprint(self):
        result, calls = self.verify()
        self.assertTrue(result['verified'])
        self.assertIn('--dearmor', calls[0])
        self.assertIn('--no-options', calls[1])
        self.assertIn('--no-default-keyring', calls[1])
        self.assertIn('--verify', calls[1])
        self.assertEqual([], list(self.path.iterdir()))

    def test_wrong_fingerprint_revoked_expired_missing_and_failed_command_block(self):
        for status, code in [('[GNUPG:] VALIDSIG ' + 'A' * 40 + ' x\n', 0),
                             ('[GNUPG:] VALIDSIG ' + guard.R82_SIGNATURE_FINGERPRINT + ' x\n[GNUPG:] REVKEYSIG x\n', 0),
                             ('[GNUPG:] EXPKEYSIG x\n', 0), ('', 0), ('', 1)]:
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                self.verify(status, code)
            self.assertEqual([], list(self.path.iterdir()))


class Remi82BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard-remi82-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / 'inputs').mkdir()
        self.host = dict(platform='linux', os_id='centos', os_version='7', architecture='x86_64', uid=1000)
        for name, result in [('bp_doctor_host', self.host), ('say', None),
                             ('r82_verify_source_signature', {'fingerprint': guard.R82_SIGNATURE_FINGERPRINT}),
                             ('r82_selftest_summary', {'total': 15000, 'passed': 15000, 'failed': 0}),
                             ('r82_smoke_tests', []), ('r82_check_artifacts', [{'name': 'fixture'}]),
                             ('bp_failure_summary', {'hint': 'check log'}), ('bp_tool', '/usr/bin/stub')]:
            patch = mock.patch.object(guard, name, return_value=result)
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(guard.os, 'geteuid', return_value=1000)
        patch.start(); self.addCleanup(patch.stop)
        self.commands = []

    def build(self, layout, command=None):
        profile = guard.r82_profile(layout)
        (self.root / 'inputs' / profile['spec_name']).write_bytes(ORIGINAL[layout])
        args = argparse.Namespace(layout=layout, work_dir=str(self.root), jobs=2)
        def run(argv, **kwargs):
            self.commands.append(argv)
            if '-ba' in argv:
                top = pathlib.Path(argv[argv.index('--define') + 1].split(' ', 1)[1])
                (top / 'SRPMS' / (profile['source_name'] + '-' + guard.R82_VERSION + '-' + guard.R82_RELEASE + '.src.rpm')).write_bytes(b'srpm fixture')
                helper = top / 'BUILD' / ('php-' + guard.R82_VERSION) / 'build-fpm/modules/zend_test.so'
                helper.parent.mkdir(parents=True)
                helper.write_bytes(b'test module fixture')
            return ''
        with mock.patch.object(guard, 'r82_verify_prepared', return_value=str(self.root / 'inputs')), \
             mock.patch.object(guard, 'r82_input_hashes', return_value={profile['spec_name']: profile['packaging'][profile['spec_name']]}), \
             mock.patch.object(guard, 'bp_call', side_effect=command or run):
            return guard.r82_build(args)

    def report(self):
        return json.loads(pathlib.Path(guard.R82_LAST_BUILD_REPORT).read_text())

    def test_both_layouts_prep_build_security_and_bind_report_without_install(self):
        for layout in ('system', 'scl'):
            with self.subTest(layout=layout):
                self.commands = []
                self.assertEqual(0, self.build(layout))
                report = self.report()
                self.assertEqual('built_not_deployed', report['state'])
                self.assertEqual(layout, report['layout'])
                self.assertTrue(report['source_signature_verified'])
                self.assertTrue(report['php_selftests_passed'])
                self.assertFalse(report['deployed'])
                self.assertFalse(report['signed'])
                self.assertEqual(['-bp', '-ba'], [v[-2] for v in self.commands[:2]])
                self.assertIn('run-tests.php', self.commands[2][2])
                self.assertIn('/build-fpm/sapi/cli/php', self.commands[2][0])
                self.assertIn('extension=', self.commands[2][5])
                top = pathlib.Path(guard.R82_LAST_BUILD_REPORT).parent / 'rpmbuild'
                self.assertEqual(ORIGINAL[layout], (top / 'SOURCES' / guard.r82_profile(layout)['spec_name']).read_bytes())

    def test_compile_failure_records_stage_and_never_exposes_installable_artifacts(self):
        with self.assertRaisesRegex(RuntimeError, 'compile failed'):
            self.build('system', mock.Mock(side_effect=RuntimeError('compile failed')))
        report = self.report()
        self.assertEqual('build_failed', report['state'])
        self.assertEqual('prepare_and_dependencies', report['stage'])
        self.assertNotIn('artifacts', report)

    def test_failed_security_summary_blocks_artifact_validation(self):
        with mock.patch.object(guard, 'r82_selftest_summary', side_effect=[{}, RuntimeError('security skipped')]), \
             mock.patch.object(guard, 'r82_check_artifacts') as check:
            with self.assertRaisesRegex(RuntimeError, 'security skipped'):
                self.build('scl')
        check.assert_not_called()
        self.assertEqual('security_regressions', self.report()['stage'])

    def test_root_and_unsupported_hosts_cannot_start(self):
        args = argparse.Namespace(layout='system', work_dir=str(self.root), jobs=2)
        with mock.patch.object(guard.os, 'geteuid', return_value=0), \
             mock.patch.object(guard, 'r82_verify_prepared') as prepared:
            with self.assertRaisesRegex(RuntimeError, 'normal user'):
                guard.r82_build(args)
            prepared.assert_not_called()
        with mock.patch.object(guard, 'bp_doctor_host', return_value=dict(self.host, os_version='8')):
            with self.assertRaisesRegex(RuntimeError, 'CentOS 7'):
                guard.r82_build(args)


class Remi82PreparedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard82-input-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.layout = 'scl'
        profile = guard.r82_profile(self.layout)
        self.hashes = {profile['spec_name']: profile['packaging'][profile['spec_name']]}
        (self.root / 'inputs').mkdir()
        (self.root / 'inputs' / profile['spec_name']).write_bytes(ORIGINAL[self.layout])
        rendered = guard.r82_render_spec(ORIGINAL[self.layout], self.layout)
        (self.root / 'php82-guard.spec').write_bytes(rendered)
        self.report = dict(recipe=guard.R82_RECIPE, layout=self.layout,
                           packaging_commit=profile['commit'], inputs=self.hashes,
                           spec_sha256=hashlib.sha256(rendered).hexdigest(),
                           state='sources_prepared_not_built', source_signature_verified=True)
        self.save()

    def save(self):
        (self.root / 'prepare.json').write_text(json.dumps(self.report))

    def verify(self):
        with mock.patch.object(guard, 'r82_input_hashes', return_value=self.hashes), \
             mock.patch.object(guard, 'r82_verify_archive'):
            return guard.r82_verify_prepared(str(self.root), self.layout)

    def test_prepared_binds_layout_commit_and_source_hashes(self):
        self.assertEqual(str(self.root / 'inputs'), self.verify())
        for field, wrong in [('layout', 'system'), ('recipe', 'baota-remi-el7-php74'),
                             ('packaging_commit', 'other'), ('inputs', {}),
                             ('source_signature_verified', False), ('state', 'prepare_failed')]:
            old = self.report[field]
            self.report[field] = wrong
            self.save()
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'selected layout'):
                self.verify()
            self.report[field] = old

    def test_mutated_input_cannot_be_reused(self):
        spec = self.root / 'inputs' / guard.r82_profile(self.layout)['spec_name']
        spec.write_bytes(spec.read_bytes() + b'\n')
        with self.assertRaisesRegex(RuntimeError, 'SHA256'):
            self.verify()

    def test_rendered_spec_change_cannot_be_reused(self):
        spec = self.root / 'php82-guard.spec'
        spec.write_bytes(spec.read_bytes() + b'\n')
        with self.assertRaisesRegex(RuntimeError, 'fixed recipe'):
            self.verify()

    def test_symbolic_input_or_spec_is_not_accepted(self):
        spec = self.root / 'php82-guard.spec'
        actual = self.root / 'actual.spec'
        spec.rename(actual)
        spec.symlink_to(actual)
        with self.assertRaisesRegex(RuntimeError, 'symbolic'):
            self.verify()


class Remi82ArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard82-artifact-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def artifacts(self, layout, mutate=None, omit=False, files="/usr/bin/php"):

        profile = guard.r82_profile(layout)
        names = profile['core_names'][1:] if omit else profile['core_names']
        paths, headers = [], {}
        for name in names:
            path = self.root / (name + '-' + guard.R82_VERSION + '-' + guard.R82_RELEASE + '.x86_64.rpm')
            path.write_bytes(b'rpm-fixture-' + name.encode())
            source = profile['source_name'] + '-' + guard.R82_VERSION + '-' + guard.R82_RELEASE + '.src.rpm'
            fields = [name, guard.R82_VERSION, guard.R82_RELEASE, 'x86_64', source]
            if mutate:
                fields = mutate(fields)
            paths.append(str(path)); headers[str(path)] = '\t'.join(fields)
        with mock.patch.object(guard, 'bp_call', side_effect=lambda args: files if '-qpl' in args else headers[args[-1]]):
            return guard.r82_check_artifacts(paths, '/usr/bin/rpm', layout)

    def test_system_and_scl_artifacts_must_come_from_their_exact_source_rpm(self):
        for layout in ('system', 'scl'):
            result = self.artifacts(layout)
            self.assertEqual(set(guard.r82_profile(layout)['core_names']), set(x['name'] for x in result))
            with self.assertRaises(RuntimeError):
                self.artifacts(layout, lambda fields: fields[:4] + ['unrelated.src.rpm'])

    def test_test_module_cannot_escape_into_runtime_rpms(self):
        for name in ('zend_test.so', 'zend_test.so.1', 'zend_test.so.debug', 'zend_test-8.2.so', 'zend_test_shared.so', 'ZEND_TEST.SO'):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'Test-only'):
                self.artifacts('system', files='/usr/lib64/php/modules/' + name)

    def test_incomplete_wrong_version_and_wrong_architecture_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Incomplete'):
            self.artifacts('system', omit=True)
        for index, value in [(1, '8.2.20'), (2, '1.el7.remi'), (3, 'aarch64')]:
            def change(fields):
                fields[index] = value
                return fields
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                self.artifacts('scl', mutate=change)


class Remi82ArchiveTests(unittest.TestCase):
    def validate(self, extra):
        import io
        class Member:
            size = 100
            def __init__(self, name, regular=False):
                self.name, self.regular = name, regular
            def isfile(self):
                return self.regular
            def isdir(self):
                return not self.regular
        class Archive:
            def __iter__(self):
                members = [Member(b'php-8.2.35/directory-%d' % i) for i in range(10000)]
                members += [Member(('php-8.2.35/' + name).encode(), True)
                            for name in ('main/php_version.h', guard.R82_KNOWN_XPASS) + guard.R82_SECURITY_TESTS]
                members.append(Member(extra, True))
                return iter(members)
            def close(self):
                pass
            def extractfile(self, member):
                if member.name.endswith(guard.R82_KNOWN_XPASS.encode()):
                    return io.BytesIO((ROOT / 'tests/fixtures/php82-fpm-known-xpass.phpt').read_bytes())
                return io.BytesIO(b'#define PHP_VERSION "8.2.35"\n')
        decoder = mock.Mock(stdout=io.BytesIO(), stderr=io.BytesIO())
        decoder.poll.return_value = 0
        decoder.wait.return_value = 0
        with mock.patch.object(guard, 'bp_verify'), \
             mock.patch.object(guard, 'bp_tool', return_value='/usr/bin/xz'), \
             mock.patch.object(guard.subprocess, 'Popen', return_value=decoder), \
             mock.patch.object(guard.tarfile, 'open', return_value=Archive()):
            guard.r82_verify_archive('/fixture/php.tar.xz')

    def test_python27_style_byte_filenames_allow_valid_utf8(self):
        self.validate('php-8.2.35/tests/有效UTF8.php'.encode())

    def test_invalid_utf8_or_parent_traversal_is_rejected(self):
        for name in (b'php-8.2.35/tests/\xff.php', b'php-8.2.35/../escape'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                self.validate(name)
