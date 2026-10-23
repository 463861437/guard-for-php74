"""Read-only build planning, safe resume and conservative auto orchestration."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(os.environ.get('PHP_GUARD_TEST_SCRIPT', str(
    pathlib.Path(__file__).resolve().parents[1] / 'php_guard.py')))
SPEC = importlib.util.spec_from_file_location('php_guard_doctor_under_test', SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class DoctorCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='phpguard-doctor-')
        self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)
        self.args = argparse.Namespace(work_dir=str(self.folder / 'prepared'), jobs=2)
        for name in ('run_cmd', 'bp_call'):
            patch = mock.patch.object(guard, name, side_effect=AssertionError('unexpected command'))
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(guard, 'say')
        self.say = patch.start()
        self.addCleanup(patch.stop)
        self.host = dict(platform='linux', os_id='amzn', os_version='2', architecture='x86_64',
                         uid=1000, user='ec2-user', build_user='ec2-user', build_home=str(self.folder))
        self.resources = dict(memory_total_bytes=4 * 1024**3, disk_free_bytes=20 * 1024**3,
                              recommended_jobs=2, capacity_advisory_only=True)

    def report(self, host=None, prepared=False, missing=(), dependencies=None):
        if prepared:
            pathlib.Path(self.args.work_dir).mkdir(exist_ok=True)
        def tool(name):
            if name in missing:
                raise RuntimeError('missing: ' + name)
            return '/usr/bin/' + name
        with mock.patch.object(guard, 'bp_doctor_host', return_value=host or self.host), \
                mock.patch.object(guard, 'bp_doctor_resources', return_value=self.resources), \
                mock.patch.object(guard, 'bp_tool', side_effect=tool), \
                mock.patch.object(guard, 'bp_prepared_inputs', return_value={}), \
                mock.patch.object(guard, 'bp_doctor_requirements', return_value=dependencies or {'state': 'satisfied', 'missing': []}):
            return guard.bp_doctor_report(self.args)


class DoctorPlanTests(DoctorCase):
    def test_missing_tools_and_sources_produce_install_prepare_recheck_without_build(self):
        result = self.report(missing=('gcc', 'g++', 'rpmbuild'))
        self.assertEqual('build_preflight_blocked', result['state'])
        self.assertTrue(result['read_only'])
        self.assertFalse(result['deployed'])
        commands = result['next_commands']
        self.assertEqual('sudo yum install gcc gcc-c++ rpm-build', commands[0])
        self.assertIn(' prepare --output-dir ', commands[1])
        self.assertIn(' doctor --work-dir ', commands[2])
        self.assertFalse(any(' build --work-dir ' in command for command in commands))
        self.assertFalse(pathlib.Path(self.args.work_dir).exists())

    def test_root_host_support_is_distinct_from_ordinary_user_requirement(self):
        result = self.report(host=dict(self.host, uid=0, user='root'), prepared=True)
        self.assertEqual(1, len(result['blockers']))
        self.assertIn('root', result['blockers'][0])
        self.assertTrue(result['next_commands'][0].startswith("sudo -u 'ec2-user' -H "))
        self.assertIn(' doctor --work-dir ', result['next_commands'][0])
        self.assertFalse(any('yum install' in command for command in result['next_commands']))

    def test_unsupported_host_never_suggests_yum_or_build_commands(self):
        result = self.report(host=dict(self.host, os_id='ubuntu', os_version='22.04'))
        self.assertEqual([], result['next_commands'])
        self.assertIn('Amazon Linux 2', result['blockers'][0])

    def test_prepared_and_all_dependencies_present_suggests_build_without_claiming_patch(self):
        result = self.report(prepared=True)
        self.assertEqual('ready_for_build', result['state'])
        self.assertFalse(result['deployed'])
        self.assertEqual(1, len(result['next_commands']))
        self.assertIn(' build --work-dir ', result['next_commands'][0])
        self.assertIn('--jobs 2', result['next_commands'][0])

    def test_missing_dependencies_give_pinned_srpm_builddep_and_recheck(self):
        result = self.report(prepared=True, dependencies={'state': 'missing', 'missing': ['libxml2-devel >= 2.7']})
        commands = result['next_commands']
        self.assertTrue(any('yum-builddep' in item and guard.BP_SRPM in item for item in commands))
        self.assertTrue(any(' doctor --work-dir ' in item for item in commands))
        self.assertFalse(any(' build --work-dir ' in item for item in commands))

    def test_doctor_cli_rejects_mutation_inputs_and_returns_blocked_exit(self):
        with mock.patch.object(guard, 'bp_doctor_report', return_value={'state': 'build_preflight_blocked'}):
            self.assertEqual(10, guard.backport_main(['doctor']))
        for argv in (['doctor', '--srpm', 'a'], ['auto'], ['auto', '--work-dir', 'a', '--key-file', 'key']):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exc:
                    guard.backport_main(argv)
                self.assertEqual(2, exc.exception.code)

    def test_launcher_environment_uses_absolute_existing_shell_even_outside_cwd(self):
        launcher = self.folder / "script's folder" / 'php-cve-guard.sh'
        launcher.parent.mkdir()
        launcher.write_text('#!/bin/bash\n')
        with mock.patch.dict(guard.os.environ, {'PHP_GUARD_LAUNCHER': str(launcher)}):
            result = self.report(prepared=True)
        self.assertEqual(str(launcher), result['launcher_path'])
        self.assertIn(guard.bp_shell_quote(str(launcher)), result['next_commands'][0])
        self.assertFalse(any('/path/to/php-cve-guard.sh' in warning for warning in result['warnings']))

    def test_missing_launcher_uses_visible_placeholder_and_warning(self):
        with mock.patch.dict(guard.os.environ, {'PHP_GUARD_LAUNCHER': '/does/not/exist.sh'}), \
                mock.patch.object(guard.os, 'getcwd', return_value=str(self.folder)):
            result = self.report(prepared=True)
        self.assertEqual('/path/to/php-cve-guard.sh', result['launcher_path'])
        self.assertTrue(any('/path/to/php-cve-guard.sh' in warning for warning in result['warnings']))

    def test_existing_non_shell_environment_path_is_ignored_in_favor_of_cwd_launcher(self):
        wrong = self.folder / 'not-a-shell.py'
        wrong.write_text('')
        launcher = self.folder / 'php-cve-guard.sh'
        launcher.write_text('#!/bin/bash\n')
        with mock.patch.dict(guard.os.environ, {'PHP_GUARD_LAUNCHER': str(wrong)}), \
                mock.patch.object(guard.os, 'getcwd', return_value=str(self.folder)):
            result = self.report(prepared=True)
        self.assertEqual(str(launcher), result['launcher_path'])

    def test_incomplete_directory_is_preserved_and_not_suggested_for_prepare(self):
        target = pathlib.Path(self.args.work_dir)
        target.mkdir()
        marker = target / 'keep'
        marker.write_text('unchanged')
        with mock.patch.object(guard, 'bp_doctor_host', return_value=self.host), \
                mock.patch.object(guard, 'bp_doctor_resources', return_value=self.resources), \
                mock.patch.object(guard, 'bp_tool', return_value='/usr/bin/stub'):
            result = guard.bp_doctor_report(self.args)
        self.assertEqual('incomplete_or_changed', result['preparation'])
        self.assertFalse(any(' prepare ' in command or ' build ' in command for command in result['next_commands']))
        self.assertEqual('unchanged', marker.read_text())


class RequirementQueryTests(DoctorCase):
    def test_capabilities_checked_without_scripts_or_install_and_ambiguity_stays_unknown(self):
        with mock.patch.object(guard, 'bp_verify') as verify, \
                mock.patch.object(guard, 'run_cmd', return_value=dict(code=0,
                    stdout='gcc\nlibxml2-devel >= 2.7\nrpmlib(CompressedFileNames) <= 3.0.4-1\n', stderr='')) as command, \
                mock.patch.object(guard, 'bp_installed_requirements', return_value={
                    'gcc': dict(state='satisfied', providers=['gcc-7.3.1']),
                    'libxml2-devel >= 2.7': dict(state='missing', providers=[]),
                }) as installed:
            result = guard.bp_doctor_requirements('/fixed/source.rpm', '/usr/bin/rpm')
        verify.assert_called_once_with('/fixed/source.rpm', guard.BP_SRPM_SHA)
        self.assertEqual('missing', result['state'])
        self.assertEqual(['libxml2-devel >= 2.7'], result['missing'])
        command.assert_called_once_with(['/usr/bin/rpm', '-qp', '--requires', '/fixed/source.rpm'], timeout=30)
        installed.assert_called_once_with(['gcc', 'libxml2-devel >= 2.7'])
        with mock.patch.object(guard, 'bp_verify'), \
                mock.patch.object(guard, 'run_cmd', return_value=dict(code=0, stdout='gcc\n', stderr='')), \
                mock.patch.object(guard, 'bp_installed_requirements', return_value={
                    'gcc': dict(state='unknown', error='RPM database unavailable')}):
            result = guard.bp_doctor_requirements('/fixed/source.rpm', '/usr/bin/rpm')
        self.assertEqual('unknown', result['state'])
        self.assertEqual([], result['missing'])
        self.assertEqual(['gcc'], result['unresolved'])

    def test_bad_pin_prevents_rpm_query(self):
        source = self.folder / 'bad.rpm'
        source.write_bytes(b'bad')
        with self.assertRaisesRegex(RuntimeError, 'SHA256 mismatch'):
            guard.bp_doctor_requirements(str(source), '/usr/bin/rpm')


class PreparationResumeTests(DoctorCase):
    def make_prepared(self):
        folder = pathlib.Path(self.args.work_dir)
        (folder / 'inputs').mkdir(parents=True)
        (folder / 'preview').mkdir()
        inputs = [(guard.BP_SRPM, 'BP_SRPM_SHA'), (guard.BP_PATCH, 'BP_PATCH_SHA'), (guard.BP_KEY, 'BP_KEY_SHA')]
        for filename, constant in inputs + [('php-7.4.33.tar.xz', 'BP_SOURCE_SHA'), (guard.BP_TEST_PATCH_NAME, 'BP_TEST_PATCH_SHA')]:
            contents = filename.encode('ascii')
            digest = hashlib.sha256(contents).hexdigest()
            patch = mock.patch.object(guard, constant, digest)
            patch.start()
            self.addCleanup(patch.stop)
            if (filename, constant) in inputs:
                (folder / 'inputs' / filename).write_bytes(contents)
            if filename not in (guard.BP_SRPM, guard.BP_KEY):
                (folder / 'preview' / filename).write_bytes(contents)
        (folder / 'preview' / 'php.spec').write_bytes(b'fixture spec')
        report = dict(state='sources_prepared_not_built', upstream_commit=guard.BP_COMMIT,
                      target_release=guard.BP_RELEASE, inputs=dict(guard.bp_inputs(str(folder))),
                      regression_patch_sha256=guard.BP_TEST_PATCH_SHA,
                      spec_sha256=guard.bp_hash(str(folder / 'preview' / 'php.spec')))
        report['preview_sha256'] = {entry.name: guard.bp_hash(str(entry)) for entry in (folder / 'preview').iterdir()}
        (folder / 'prepare.json').write_text(json.dumps(report))
        return folder

    def test_verified_completed_prepare_reuses_without_fetch_or_rewrite(self):
        folder = self.make_prepared()
        before = {str(path): path.read_bytes() for path in folder.rglob('*') if path.is_file()}
        args = argparse.Namespace(output_dir=str(folder), srpm=None, patch_file=None, key_file=None)
        with mock.patch.object(guard, 'bp_fetch', side_effect=AssertionError('must not download')):
            self.assertEqual(0, guard.bp_prepare(args))
        after = {str(path): path.read_bytes() for path in folder.rglob('*') if path.is_file()}
        self.assertEqual(before, after)

    def test_changed_input_or_preview_cannot_be_reused_or_overwritten(self):
        folder = self.make_prepared()
        original = folder / 'inputs' / guard.BP_PATCH
        original.write_bytes(b'changed')
        args = argparse.Namespace(output_dir=str(folder), srpm=None, patch_file=None, key_file=None)
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            guard.bp_prepare(args)
        self.assertEqual(b'changed', original.read_bytes())
        original.write_bytes(guard.BP_PATCH.encode('ascii'))
        (folder / 'preview' / 'php.spec').write_bytes(b'local edit')
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            guard.bp_prepare(args)
        self.assertEqual(b'local edit', (folder / 'preview' / 'php.spec').read_bytes())

    def test_failed_prepare_and_symlink_report_are_not_reused(self):
        folder = self.make_prepared()
        report = folder / 'prepare.json'
        report.write_text(json.dumps({'state': 'prepare_failed'}))
        with self.assertRaisesRegex(RuntimeError, 'incomplete'):
            guard.bp_prepared_inputs(str(folder))
        report.unlink()
        target = self.folder / 'report'
        target.write_text('{}')
        report.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'regular file'):
            guard.bp_prepared_inputs(str(folder))


class AutoAndFailureTests(DoctorCase):
    def test_auto_rejects_host_before_any_prepare_or_build(self):
        with mock.patch.object(guard, 'bp_host_check', side_effect=RuntimeError('not as root')), \
                mock.patch.object(guard, 'bp_prepare') as prepare, \
                mock.patch.object(guard, 'bp_build') as build:
            with self.assertRaisesRegex(RuntimeError, 'not as root'):
                guard.bp_auto(self.args)
        prepare.assert_not_called()
        build.assert_not_called()

    def test_auto_preserves_prepared_sources_but_blocks_missing_dependencies(self):
        report = dict(state='build_preflight_blocked', resources=self.resources)
        with mock.patch.object(guard, 'bp_host_check'), \
                mock.patch.object(guard, 'bp_tool', return_value='/usr/bin/stub'), \
                mock.patch.object(guard, 'bp_prepare') as prepare, \
                mock.patch.object(guard, 'bp_doctor_report', return_value=report), \
                mock.patch.object(guard, 'bp_build') as build:
            self.assertEqual(10, guard.bp_auto(self.args))
        prepare.assert_called_once()
        build.assert_not_called()

    def test_auto_runs_build_only_after_ready_and_caps_low_memory_parallelism(self):
        report = dict(state='ready_for_build', resources=dict(self.resources, recommended_jobs=1))
        with mock.patch.object(guard, 'bp_host_check'), \
                mock.patch.object(guard, 'bp_tool', return_value='/usr/bin/stub'), \
                mock.patch.object(guard, 'bp_prepare') as prepare, \
                mock.patch.object(guard, 'bp_doctor_report', return_value=report), \
                mock.patch.object(guard, 'bp_build', return_value=0) as build:
            self.assertEqual(0, guard.bp_auto(self.args))
        prepare.assert_called_once()
        build.assert_called_once()
        self.assertEqual(1, build.call_args.args[0].jobs)

    def test_failure_summary_classifies_without_leaking_log_environment_or_commands(self):
        samples = [('Failed build dependencies:\n libxml2-devel is needed', 'missing_build_dependencies', 'prepare_and_dependencies'),
                   ('gcc: fatal error: Killed signal terminated program cc1', 'possible_host_memory_exhaustion', 'compile_test_package'),
                   ('FAILED TEST SUMMARY\nFAIL some test', 'php_tests_failed', 'compile_test_package')]
        for text, kind, stage in samples:
            with self.subTest(kind=kind):
                name = 'prep.log' if stage == 'prepare_and_dependencies' else 'build.log'
                (self.folder / name).write_text('SECRET=must-never-appear\ncurl https://private/token\n' + text)
                result = guard.bp_failure_summary(str(self.folder), stage)
                self.assertEqual(kind, result['kind'])
                encoded = json.dumps(result)
                self.assertNotIn('must-never-appear', encoded)
                self.assertNotIn('private/token', encoded)
                self.assertFalse(result['raw_log_included'])


if __name__ == '__main__':
    unittest.main()
