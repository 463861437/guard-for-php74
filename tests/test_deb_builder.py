"""Local DEB build safety tests; never invoke a host package transaction."""
import argparse
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('deb_builder_guard', ROOT / 'php_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
exec(compile((ROOT / 'src/deb_builder.py').read_text(), str(ROOT / 'src/deb_builder.py'), 'exec'), guard.__dict__)


class SafeExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def archive(self, name, kind=tarfile.REGTYPE, mode=0o644, linkname=''):
        path = self.root / 'test.tar'
        with tarfile.open(path, 'w') as archive:
            member = tarfile.TarInfo(name)
            member.type, member.mode, member.linkname = kind, mode, linkname
            member.size = 1 if kind == tarfile.REGTYPE else 0
            archive.addfile(member, io.BytesIO(b'x') if member.size else None)
        return path

    def test_regular_file_extraction_retains_execute_but_not_setuid(self):
        source = self.archive('debian/rules', mode=0o4755)
        guard.db_extract(str(source), str(self.root / 'out'), 'debian')
        self.assertEqual(b'x', (self.root / 'out/debian/rules').read_bytes())
        self.assertEqual(0o755, (self.root / 'out/debian/rules').stat().st_mode & 0o7777)

    def test_traversal_links_devices_and_wrong_prefix_are_rejected(self):
        for name, kind, link in [('debian/../escape', tarfile.REGTYPE, ''),
                                  ('/debian/rules', tarfile.REGTYPE, ''),
                                  ('other/rules', tarfile.REGTYPE, ''),
                                  ('debian/link', tarfile.SYMTYPE, '/etc'),
                                  ('debian/hardlink', tarfile.LNKTYPE, 'debian/rules'),
                                  ('debian/device', tarfile.CHRTYPE, '')]:
            with self.subTest(name=name):
                archive = self.archive(name, kind=kind, linkname=link)
                with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                    guard.db_extract(str(archive), str(self.root / 'out'), 'debian')
                self.assertFalse((self.root / 'out').exists())

    def test_existing_output_is_never_overwritten(self):
        destination = self.root / 'out'
        destination.mkdir()
        archive = self.archive('debian/rules')
        with self.assertRaisesRegex(RuntimeError, 'Fresh'):
            guard.db_extract(str(archive), str(destination), 'debian')


class BuildEnvironmentTests(unittest.TestCase):
    def test_debian_rules_force_full_tests_with_actual_built_cgi_path(self):
        rules = ('RUN_TESTS := no\n' * 4 +
                 'TEST_PHP_CGI_EXECUTABLE=$(CURDIR)/cgi-build/sapi/php-cgi\n')
        changed = guard.db_render_rules(rules)
        self.assertEqual(1, changed.count('RUN_TESTS := yes'))
        self.assertEqual(3, changed.count('RUN_TESTS := no'))
        self.assertIn('TEST_PHP_CGI_EXECUTABLE=$(CURDIR)/cgi-build/sapi/cgi/php-cgi', changed)

    def test_changed_testing_rules_cannot_be_silently_accepted(self):
        for rules in ('RUN_TESTS := no\n', 'RUN_TESTS := no\n' * 4):
            with self.subTest(rules=rules), self.assertRaises(RuntimeError):
                guard.db_render_rules(rules)

    def test_prepare_rerun_recreates_preview_and_preserves_previous_edits(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            (root / 'inputs').mkdir()
            (root / 'preview/source').mkdir(parents=True)
            (root / 'preview/source/edited').write_text('previous user edit')

            def materialize(inputs, target):
                path = pathlib.Path(target) / 'source'
                path.mkdir()
                (path / 'reviewed').write_text('fresh pinned content')
                return str(path), []

            with mock.patch.object(guard.os, 'geteuid', return_value=1000), \
                 mock.patch.object(guard, 'db_verify_inputs', return_value=str(root / 'inputs')) as verify, \
                 mock.patch.object(guard, 'db_materialize', side_effect=materialize), \
                 mock.patch.object(guard, 'bp_fetch') as fetch, mock.patch.object(guard, 'say'):
                result = guard.db_prepare(argparse.Namespace(work_dir=folder))
            self.assertEqual(0, result)
            verify.assert_called_once_with(folder)
            fetch.assert_not_called()
            self.assertFalse((root / 'preview/source/edited').exists())
            self.assertEqual('fresh pinned content', (root / 'preview/source/reviewed').read_text())
            report = json.loads((root / 'prepare.json').read_text())
            self.assertTrue(report['reused_inputs'])
            self.assertEqual('previous user edit', (pathlib.Path(report['previous_preview']) / 'source/edited').read_text())

    def test_prepare_rerun_rejects_changed_input_before_recreating_source(self):
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(guard.os, 'geteuid', return_value=1000), \
             mock.patch.object(guard, 'db_verify_inputs', side_effect=RuntimeError('Pinned SHA256 mismatch')), \
             mock.patch.object(guard, 'db_materialize') as materialize:
            with self.assertRaisesRegex(RuntimeError, 'SHA256'):
                guard.db_prepare(argparse.Namespace(work_dir=folder))
            materialize.assert_not_called()

    def test_caller_cannot_disable_tests_or_ignore_make_errors(self):
        with mock.patch.dict(guard.os.environ, {'DEB_BUILD_OPTIONS': 'nocheck',
                'DEB_BUILD_PROFILES': 'nocheck', 'MAKEFLAGS': '-i', 'TESTS': 'one.phpt',
                'TEST_PHP_EXECUTABLE': '/unrelated/php', 'PHP_TEST_INI': '/custom.ini',
                'SKIP_ONLINE_TESTS': '1', 'RUN_TESTS': 'no', 'CFLAGS': '-DBAD'}, clear=True):
            env = guard.db_build_env(3)
        self.assertEqual('parallel=3', env['DEB_BUILD_OPTIONS'])
        self.assertEqual('', env['DEB_BUILD_PROFILES'])
        self.assertEqual('1', env['REPORT_EXIT_STATUS'])
        for key in ('MAKEFLAGS', 'TESTS', 'TEST_PHP_EXECUTABLE', 'PHP_TEST_INI',
                    'SKIP_ONLINE_TESTS', 'RUN_TESTS', 'CFLAGS'):
            self.assertNotIn(key, env)

    def test_prepare_refuses_root_before_downloading(self):
        with mock.patch.object(guard.os, 'geteuid', return_value=0), \
             mock.patch.object(guard, 'bp_fetch') as fetch:
            with self.assertRaisesRegex(RuntimeError, 'ordinary'):
                guard.db_prepare(argparse.Namespace(work_dir='/unused'))
        fetch.assert_not_called()

    def test_blocked_doctor_prevents_any_build_process(self):
        with mock.patch.object(guard, 'db_doctor', return_value={'blockers': ['missing deps']}), \
             mock.patch.object(guard, 'say'), mock.patch.object(guard.subprocess, 'Popen') as process:
            self.assertEqual(10, guard.db_build(argparse.Namespace(work_dir='/unused', jobs=2)))
        process.assert_not_called()

    def test_offline_sources_are_only_allowed_for_prepare(self):
        with self.assertRaises(SystemExit):
            guard.deb_builder_main(['build', '--work-dir', '/unused', '--source-tar', '/unused'])

    def test_build_parallelism_is_bounded(self):
        for value in ('0', '33'):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                guard.deb_builder_main(['build', '--work-dir', '/unused', '--jobs', value])


class SmokeTests(unittest.TestCase):
    def test_both_built_sapis_must_show_70434_and_immediate_oom_exit(self):
        replies = [{'code': 0, 'stdout': '70434', 'stderr': ''},
                   {'code': 1, 'stdout': '', 'stderr': 'Allowed memory size exhausted'}] * 2
        with mock.patch.object(guard.os.path, 'isfile', return_value=True), \
             mock.patch.object(guard, 'run_cmd', side_effect=replies) as run:
            result = guard.db_smoke('/build/source')
        self.assertEqual({'cli', 'fpm'}, {x['sapi'] for x in result})
        self.assertTrue(all(x['shutdown_callback_ran'] is False for x in result))
        self.assertEqual(4, run.call_count)

    def test_version_only_or_shutdown_callback_is_not_a_pass(self):
        for response in [{'code': 0, 'stdout': '', 'stderr': 'Allowed memory size'},
                         {'code': 1, 'stdout': 'PHP_GUARD_SHUTDOWN_RAN', 'stderr': 'Allowed memory size'}]:
            with mock.patch.object(guard.os.path, 'isfile', return_value=True), \
                 mock.patch.object(guard, 'run_cmd', side_effect=[
                     {'code': 0, 'stdout': '70434', 'stderr': ''}, response]):
                with self.assertRaisesRegex(RuntimeError, 'OOM'):
                    guard.db_smoke('/build/source')


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)
        self.names = ['php7.4', 'php7.4-cli', 'php7.4-common', 'php7.4-fpm',
                      'php7.4-opcache', 'libapache2-mod-php7.4']
        for name in self.names:
            (self.folder / (name + '.deb')).write_bytes(b'fake package content')

    def metadata(self, argv):
        name = pathlib.Path(argv[-1]).stem
        return '\t'.join([name, guard.DB_VERSION, 'all' if name == 'php7.4' else 'amd64',
                          '' if name == 'php7.4' else 'php7.4 (' + guard.DB_VERSION + ')']) + '\n'

    def test_exact_source_version_and_complete_native_artifacts_are_recorded(self):
        with mock.patch.object(guard, 'bp_tool', return_value='/usr/bin/dpkg-deb'), \
             mock.patch.object(guard, 'bp_call', side_effect=self.metadata):
            artifacts = guard.db_artifacts(str(self.folder))
        self.assertEqual(6, len(artifacts))
        self.assertTrue(all(x['source'] == 'php7.4' for x in artifacts))
        self.assertTrue(all(len(x['sha256']) == 64 for x in artifacts))

    def test_incomplete_artifact_set_is_rejected(self):
        (self.folder / 'php7.4-fpm.deb').unlink()
        with mock.patch.object(guard, 'bp_tool', return_value='/usr/bin/dpkg-deb'), \
             mock.patch.object(guard, 'bp_call', side_effect=self.metadata):
            with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                guard.db_artifacts(str(self.folder))

    def test_wrong_source_or_version_is_rejected(self):
        for source, version in [('php7.4-custom', guard.DB_VERSION), ('php7.4', '7.4.34-1')]:
            with mock.patch.object(guard, 'bp_tool', return_value='/usr/bin/dpkg-deb'), \
                 mock.patch.object(guard, 'bp_call', return_value='php7.4-cli\t%s\tamd64\t%s\n' % (version, source)):
                with self.assertRaisesRegex(RuntimeError, 'identity'):
                    guard.db_artifacts(str(self.folder))


if __name__ == '__main__':
    unittest.main()
