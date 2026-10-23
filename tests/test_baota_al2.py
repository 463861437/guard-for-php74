"""Pinned BaoTa source + original AL2 RPM packaging; no host mutation."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guard_baota_al2_under_test', ROOT / 'php_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
for name in ('backport_builder', 'build_environment'):
    source = ROOT / 'src' / (name + '.py')
    exec(compile(source.read_text(), str(source), 'exec'), guard.__dict__)
ORIGINAL_SPEC = (ROOT / 'tests/fixtures/php74-amzn2.spec').read_bytes()


class BaotaRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='phpguard-baota-al2-')
        self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)
        self.say = mock.patch.object(guard, 'say').start()
        mock.patch.object(guard, 'run_cmd', side_effect=AssertionError('unexpected host command')).start()
        mock.patch.object(guard.subprocess, 'Popen', side_effect=AssertionError('unexpected process')).start()
        self.addCleanup(mock.patch.stopall)

    def recipe(self):
        return mock.patch.multiple(guard, **guard.BP_BAOTA_RECIPE)

    def test_recipe_is_scoped_and_default_source_remains_unchanged(self):
        default = dict((key, getattr(guard, key)) for key in guard.BP_BAOTA_RECIPE)
        seen = []
        def dispatch(argv):
            seen.append((guard.BP_RECIPE, guard.BP_VERSION, guard.BP_RELEASE, guard.BP_COMMAND, list(argv)))
            return 17
        with mock.patch.object(guard, 'backport_main', side_effect=dispatch):
            self.assertEqual(17, guard.baota_al2_build_main(['doctor']))
        self.assertEqual([('baota-al2-php74', '7.4.34', guard.BAOTA_AL2_RELEASE,
                           'build-baota-al2-php74', ['doctor'])], seen)
        self.assertEqual(default, dict((key, getattr(guard, key)) for key in default))
        self.assertEqual('7.4.33', guard.BP_VERSION)

    def test_parse_failure_restores_all_default_recipe_values(self):
        default = dict((key, getattr(guard, key)) for key in guard.BP_BAOTA_RECIPE)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            guard.baota_al2_build_main(['build'])
        self.assertEqual(default, dict((key, getattr(guard, key)) for key in default))

    def test_every_action_runs_under_selected_recipe(self):
        cases = [('doctor', [], 'bp_doctor'), ('setup', [], 'be_setup'),
                 ('prepare', ['--output-dir', str(self.folder / 'new')], 'bp_prepare'),
                 ('build', ['--work-dir', str(self.folder / 'prepared')], 'bp_build'),
                 ('auto', ['--work-dir', str(self.folder / 'prepared')], 'bp_auto')]
        for action, options, function in cases:
            with self.subTest(action=action):
                def run(args):
                    self.assertEqual('baota-al2-php74', guard.BP_RECIPE)
                    self.assertEqual('7.4.34', guard.BP_VERSION)
                    return 0
                with mock.patch.object(guard, function, side_effect=run):
                    self.assertEqual(0, guard.baota_al2_build_main([action] + options))
                self.assertEqual('7.4.33', guard.BP_VERSION)

    def test_baota_spec_preserves_native_layout_abi_and_test_failure_gate(self):
        with self.recipe():
            rendered = guard.bp_render_spec(ORIGINAL_SPEC).decode()
        self.assertIn('%global upver        7.4.34', rendered)
        self.assertIn('Source0: https://download.bt.cn/src/php-7.4.34.tar.gz', rendered)
        self.assertIn('Release: ' + guard.BAOTA_AL2_RELEASE, rendered)
        self.assertNotIn('Patch200:', rendered)
        self.assertNotIn('%patch200 ', rendered)
        self.assertIn('%patch201 -p1 -F0 -b .guardtests', rendered)
        for marker in ('%global apiver      20190902', '%global zendver     20190902',
                       '%global pdover      20170320', '%patch42 -p1 -b .systzdata',
                       '%patch300 -p1 -b .datetests', './buildconf --force',
                       '--with-config-file-path=%{_sysconfdir}', 'INSTALL_ROOT=$RPM_BUILD_ROOT'):
            self.assertIn(marker, rendered)
        self.assertNotIn('  #exit 1\n', rendered)
        self.assertIn('configure.ac)', next(line for line in rendered.splitlines() if line.startswith('pver=')))
        self.assertIn('vapi=`sed', rendered)
        self.assertNotIn('/www/server/php', rendered)

    def test_default_spec_still_uses_original_version_and_applies_official_patch(self):
        rendered = guard.bp_render_spec(ORIGINAL_SPEC).decode()
        self.assertIn('%global upver        7.4.33', rendered)
        self.assertIn('%patch200 -p1 -F0 -b .cve2026', rendered)
        self.assertIn('main/php_version.h)', next(line for line in rendered.splitlines() if line.startswith('pver=')))
        self.assertNotIn('download.bt.cn', rendered)

    def test_baota_extra_input_is_pinned_and_default_input_set_is_unchanged(self):
        default = guard.bp_inputs(str(self.folder))
        self.assertEqual(3, len(default))
        with self.recipe():
            extra = guard.bp_inputs(str(self.folder))
        self.assertEqual(default, extra[:3])
        self.assertEqual(('php-7.4.34.tar.gz', guard.BAOTA_AL2_SOURCE_SHA), extra[-1])

    def test_offline_source_tar_only_allowed_for_baota_prepare(self):
        for invocation in (guard.backport_main, guard.baota_al2_build_main):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                invocation(['doctor', '--source-tar', 'untrusted.tar.gz'])
        with mock.patch.object(guard, 'bp_prepare', return_value=0) as prepare:
            self.assertEqual(0, guard.baota_al2_build_main([
                'prepare', '--output-dir', str(self.folder / 'new'), '--source-tar', '/offline/source.tar.gz']))
        self.assertEqual('/offline/source.tar.gz', prepare.call_args.args[0].source_tar)

    def test_bad_source_bytes_are_rejected_before_archive_open(self):
        source = self.folder / 'corrupt.tar.gz'
        source.write_bytes(b'not the pinned vendor source')
        with mock.patch.object(guard.tarfile, 'open') as archive, self.assertRaisesRegex(RuntimeError, 'SHA256'):
            guard.bp_verify_baota_archive(str(source))
        archive.assert_not_called()

    def test_archive_validation_rejects_symlinks_traversal_and_other_roots(self):
        for name, kind in [('php-7.4.34/../escape', tarfile.REGTYPE),
                           ('other/configure.ac', tarfile.REGTYPE),
                           ('php-7.4.34/link', tarfile.SYMTYPE)]:
            source = self.folder / 'source.tar.gz'
            with tarfile.open(str(source), 'w:gz') as archive:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                archive.addfile(member, io.BytesIO(b''))
            with self.subTest(name=name), mock.patch.object(guard, 'bp_verify'):
                with self.assertRaisesRegex(RuntimeError, 'Unexpected BaoTa'):
                    guard.bp_verify_baota_archive(str(source))

    def test_archive_with_missing_reviewed_identity_files_is_rejected(self):
        source = self.folder / 'source.tar.gz'
        with tarfile.open(str(source), 'w:gz') as archive:
            member = tarfile.TarInfo('php-7.4.34/configure.ac')
            member.size = 3
            archive.addfile(member, io.BytesIO(b'bad'))
        with mock.patch.object(guard, 'bp_verify'), self.assertRaisesRegex(RuntimeError, 'identities'):
            guard.bp_verify_baota_archive(str(source))

    def test_recipe_mismatch_blocks_existing_work_directory_before_file_acceptance(self):
        for path in ('inputs', 'preview'):
            (self.folder / path).mkdir()
        report = {'state': 'sources_prepared_not_built', 'upstream_commit': guard.BP_COMMIT,
                  'target_release': guard.BP_RELEASE, 'inputs': dict(guard.bp_inputs(str(self.folder))),
                  'regression_patch_sha256': guard.BP_TEST_PATCH_SHA}
        (self.folder / 'prepare.json').write_text(json.dumps(report))
        with self.recipe(), mock.patch.object(guard, 'bp_verify') as verify:
            with self.assertRaisesRegex(RuntimeError, 'another pinned recipe'):
                guard.bp_prepared_inputs(str(self.folder))
        verify.assert_not_called()

    def test_baota_artifacts_cannot_accept_old_source_version_or_missing_core(self):
        rpm = self.folder / 'php.rpm'
        rpm.write_bytes(b'rpm stub')
        with self.recipe():
            for version, source in [('7.4.33', 'php-7.4.34-' + guard.BP_RELEASE + '.src.rpm'),
                                    ('7.4.34', 'php-7.4.33-' + guard.BP_RELEASE + '.src.rpm')]:
                output = '\t'.join(('php', version, guard.BP_RELEASE, 'x86_64', source))
                with mock.patch.object(guard, 'bp_call', return_value=output), self.assertRaisesRegex(RuntimeError, 'identity'):
                    guard.bp_check_artifacts([str(rpm)], '/usr/bin/rpm')
            output = '\t'.join(('php', '7.4.34', guard.BP_RELEASE, 'x86_64',
                                 'php-7.4.34-' + guard.BP_RELEASE + '.src.rpm'))
            with mock.patch.object(guard, 'bp_call', return_value=output), self.assertRaisesRegex(RuntimeError, 'Incomplete core'):
                guard.bp_check_artifacts([str(rpm)], '/usr/bin/rpm')

    def test_baota_smoke_requires_generated_version_and_oom_in_both_sapis(self):
        for sapi in ('build-apache', 'build-ztscli'):
            binary = self.folder / 'BUILD/php-7.4.34' / sapi / 'sapi/cli/php'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'unexecuted stub')
        version = dict(code=0, stdout='7.4.34', stderr='')
        oom = dict(code=1, stdout='', stderr='PHP Fatal error: Allowed memory size exhausted')
        with self.recipe(), mock.patch.object(guard, 'run_cmd', side_effect=[version, oom] * 2):
            results = guard.bp_smoke_tests(str(self.folder))
        self.assertEqual(['7.4.34', '7.4.34'], [row['version'] for row in results])
        with self.recipe(), mock.patch.object(guard, 'run_cmd', return_value=dict(version, stdout='7.4.31-dev')):
            with self.assertRaisesRegex(RuntimeError, 'version smoke'):
                guard.bp_smoke_tests(str(self.folder))

    def test_valid_build_records_vendor_source_separately_from_aws_signature(self):
        from test_backport_builder import passing_selftest_log
        (self.folder / 'inputs').mkdir()
        with self.recipe():
            for name, unused in guard.bp_inputs(str(self.folder)):
                (self.folder / 'inputs' / name).write_bytes(b'fixture')
            def extract(source, target):
                pathlib.Path(target).mkdir()
                (pathlib.Path(target) / 'php.spec').write_bytes(ORIGINAL_SPEC)
            def command(argv, log=None, cwd=None, data=None):
                if '--checksig' in argv:
                    return 'Header V4 RSA/SHA256 Signature, key ID c87f5b1a: OK'
                if '-ba' in argv:
                    pathlib.Path(log).write_text(passing_selftest_log())
                    top = pathlib.Path(argv[-1]).parent.parent
                    target = top / 'RPMS/x86_64'
                    target.mkdir()
                    for name in guard.BP_CORE_NAMES:
                        (target / (name + '.rpm')).write_bytes(b'rpm stub')
                    (top / 'SRPMS' / ('php-' + guard.BP_VERSION + '-' + guard.BP_RELEASE + '.src.rpm')).write_bytes(b'srpm')
                if '-qp' in argv:
                    return '\t'.join((pathlib.Path(argv[-1]).stem, guard.BP_VERSION, guard.BP_RELEASE,
                                      'x86_64', 'php-' + guard.BP_VERSION + '-' + guard.BP_RELEASE + '.src.rpm'))
                return ''
            with mock.patch.object(guard, 'bp_host_check'), mock.patch.object(guard, 'bp_verify'), \
                    mock.patch.object(guard, 'bp_tool', side_effect=lambda name: '/usr/bin/' + name), \
                    mock.patch.object(guard, 'bp_extract_srpm', side_effect=extract), \
                    mock.patch.object(guard, 'bp_stage_recipe_inputs'), \
                    mock.patch.object(guard, 'bp_smoke_tests', return_value=[dict(version='7.4.34', oom_exit=1)]), \
                    mock.patch.object(guard, 'bp_call', side_effect=command):
                self.assertEqual(0, guard.bp_build(argparse.Namespace(work_dir=str(self.folder), jobs=2)))
        report = json.loads(next(self.folder.glob('build-*/build.json')).read_text())
        self.assertEqual('built_not_deployed', report['state'])
        self.assertEqual('baota-al2-php74', report['recipe'])
        self.assertEqual('7.4.34', report['target_version'])
        self.assertEqual(guard.BAOTA_AL2_SOURCE_SHA, report['inputs']['php-7.4.34.tar.gz'])
        self.assertTrue(report['rpm_signature_verified'])
        self.assertFalse(report['vendor_source_signature_verified'])
        self.assertFalse(report['signed'])
        self.assertFalse(report['deployed'])
        self.assertTrue(report['php_selftests_passed'])
        self.assertEqual(len(guard.BP_CORE_NAMES), len(report['artifacts']))
        self.assertIn('php-7.4.34-', report['source_rpm']['file'])


class BaotaAllTests(unittest.TestCase):
    recipe = BaotaRecipeTests.recipe

    def setUp(self):
        BaotaRecipeTests.setUp(self)
        self.args = argparse.Namespace(action='all', yes=True, build_user='builder',
            work_dir=str(self.folder / 'build'), jobs=2, lock_wait=300,
            output_dir=None, srpm=None, patch_file=None, key_file=None, source_tar=None)
        self.account = dict(name='builder', uid=1001, gid=1001, home=str(self.folder),
                            work_dir=self.args.work_dir)

    def test_all_is_only_available_for_baota_recipe_and_defaults_to_preview(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            guard.backport_main(['all'])
        with mock.patch.object(guard, 'be_all', return_value=0) as action:
            self.assertEqual(0, guard.baota_al2_build_main(['all']))
        self.assertFalse(action.call_args.args[0].yes)
        with mock.patch.object(guard, 'be_all', return_value=0) as action:
            self.assertEqual(0, guard.baota_al2_build_main(['all', '--yes', '--build-user', 'builder',
                '--work-dir', self.args.work_dir, '--jobs', '2', '--lock-wait', '300']))
        self.assertTrue(action.call_args.args[0].yes)
        self.assertEqual(300, action.call_args.args[0].lock_wait)
        self.assertEqual(2, action.call_args.args[0].jobs)

    def test_all_rejects_untrusted_input_overrides_before_actions(self):
        with mock.patch.object(guard, 'be_all') as action:
            for option in ('--srpm', '--patch-file', '--key-file', '--source-tar', '--output-dir'):
                with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    guard.baota_al2_build_main(['all', '--yes', option, 'untrusted'])
        action.assert_not_called()

    def test_preview_runs_setup_plan_only_and_does_not_fork_build(self):
        self.args.yes = False
        with self.recipe(), mock.patch.object(guard, 'be_validate_host_user', return_value=self.account), \
                mock.patch.object(guard, 'be_setup', return_value=0) as setup, \
                mock.patch.object(guard, 'be_build_as_user') as build, \
                mock.patch.object(guard, 'be_report_directory') as report:
            self.assertEqual(0, guard.be_all(self.args))
        self.assertEqual('setup', setup.call_args.args[0].action)
        self.assertFalse(setup.call_args.args[0].yes)
        build.assert_not_called()
        report.assert_not_called()

    def run_all(self, setup_code, build_result):
        with self.recipe(), mock.patch.object(guard, 'be_validate_host_user', return_value=self.account), \
                mock.patch.object(guard, 'be_setup', return_value=setup_code) as setup, \
                mock.patch.object(guard, 'be_build_as_user', return_value=build_result) as build, \
                mock.patch.object(guard.os, 'umask'), \
                mock.patch.object(guard, 'be_report_directory', return_value=str(self.folder)):
            code = guard.be_all(self.args)
        report = json.loads((self.folder / 'all.json').read_text())
        return code, setup, build, report

    def test_failed_setup_or_postcheck_stops_before_build(self):
        for failure in (10, 20):
            code, setup, build, report = self.run_all(failure, {})
            self.assertEqual(failure, code)
            build.assert_not_called()
            self.assertFalse(report['build_started'])
            self.assertFalse(report['php_deployed'])
            self.assertEqual('environment_not_ready', report['state'])

    def test_successful_setup_then_build_reports_path_without_installing_php(self):
        result = dict(ok=True, exit_code=0, effective_uid=1001,
                      build_report='/home/builder/build/build-one/build.json')
        code, setup, build, report = self.run_all(0, result)
        self.assertEqual(0, code)
        self.assertTrue(setup.call_args.args[0].yes)
        build.assert_called_once_with(self.account, 2)
        self.assertEqual('built_not_deployed', report['state'])
        self.assertFalse(report['php_deployed'])
        self.assertEqual(result, report['build_user_result'])
        self.assertTrue(any(result['build_report'] in call.args[0] for call in self.say.call_args_list))

    def test_failed_child_returns_failure_and_keeps_build_log_location(self):
        result = dict(ok=False, exit_code=20, effective_uid=1001,
                      error='selftests failed', build_report='/home/builder/build/build-one/build.json')
        code, setup, build, report = self.run_all(0, result)
        self.assertEqual(20, code)
        self.assertEqual('build_incomplete', report['state'])
        self.assertEqual(result, report['build_user_result'])
        self.assertFalse(report['php_deployed'])

    class ChildExited(BaseException):
        pass

    def run_build_child(self, uid=1001, build_code=0, raise_error=None):
        events, payload, exit_codes = [], io.BytesIO(), []
        def exit_child(code):
            exit_codes.append(code)
            raise self.ChildExited()
        def auto(args):
            events.append(('auto', args.work_dir, args.jobs))
            guard.BP_LAST_BUILD_REPORT = '/home/builder/build/build-new/build.json'
            if raise_error:
                raise RuntimeError(raise_error)
            return build_code
        with mock.patch.object(guard.os, 'pipe', return_value=(901, 902)), \
                mock.patch.object(guard.os, 'fork', return_value=0), \
                mock.patch.object(guard.os, 'close'), \
                mock.patch.object(guard.os, 'initgroups', side_effect=lambda name, gid: events.append(('groups', name, gid))), \
                mock.patch.object(guard.os, 'setgid', side_effect=lambda gid: events.append(('gid', gid))), \
                mock.patch.object(guard.os, 'setuid', side_effect=lambda value: events.append(('uid', value))), \
                mock.patch.object(guard.os, 'geteuid', return_value=uid), \
                mock.patch.dict(guard.os.environ, {'UNTRUSTED_ENV': 'inherited', 'LD_PRELOAD': 'hostile'}, clear=True), \
                mock.patch.object(guard.os, 'chdir', side_effect=lambda folder: events.append(('chdir', folder))), \
                mock.patch.object(guard.os, 'umask'), \
                mock.patch.object(guard.os, 'fdopen', return_value=contextlib.nullcontext(payload)), \
                mock.patch.object(guard.os, '_exit', side_effect=exit_child), \
                mock.patch.object(guard, 'bp_auto', side_effect=auto):
            with self.assertRaises(self.ChildExited):
                guard.be_build_as_user(self.account, 2)
            environment = dict(guard.os.environ)
        return events, json.loads(payload.getvalue().decode('ascii')), exit_codes, environment

    def test_build_child_drops_groups_gid_uid_and_environment_before_auto(self):
        events, result, exits, environment = self.run_build_child()
        self.assertEqual([('groups', 'builder', 1001), ('gid', 1001), ('uid', 1001)], events[:3])
        self.assertEqual(('chdir', str(self.folder)), events[3])
        self.assertEqual(('auto', self.args.work_dir, 2), events[4])
        self.assertNotIn('UNTRUSTED_ENV', environment)
        self.assertNotIn('LD_PRELOAD', environment)
        self.assertEqual(str(self.folder), environment['HOME'])
        self.assertTrue(result['ok'])
        self.assertFalse(result['php_deployed'])
        self.assertEqual([0], exits)
        self.assertIn('build-new/build.json', result['build_report'])

    def test_failed_privilege_drop_never_runs_auto_or_claims_success(self):
        for uid in (0, 1002):
            with self.subTest(uid=uid):
                events, result, exits, environment = self.run_build_child(uid=uid)
                self.assertFalse(result['ok'])
                self.assertIn('Failed to drop', result['error'])
                self.assertEqual([20], exits)
                self.assertFalse(any(event[0] in ('chdir', 'auto') for event in events))
                self.assertIsNone(result['build_report'])

    def test_build_exception_and_blocked_exit_return_failure_with_report(self):
        for code, error, expected in [(10, None, 10), (20, None, 20), (0, 'compile failed', 20)]:
            events, result, exits, environment = self.run_build_child(build_code=code, raise_error=error)
            self.assertFalse(result['ok'])
            self.assertEqual([expected], exits)
            self.assertTrue(result['build_report'])

    def test_parent_rejects_nonzero_wait_status_even_with_success_payload(self):
        payload = json.dumps(dict(ok=True, exit_code=0, effective_uid=1001,
            build_report='/home/builder/build/build-new/build.json')).encode('ascii')
        with mock.patch.object(guard.os, 'pipe', return_value=(901, 902)), \
                mock.patch.object(guard.os, 'fork', return_value=999), \
                mock.patch.object(guard.os, 'close'), \
                mock.patch.object(guard.os, 'fdopen', return_value=contextlib.nullcontext(io.BytesIO(payload))), \
                mock.patch.object(guard.os, 'waitpid', return_value=(999, 20 << 8)) as wait:
            result = guard.be_build_as_user(self.account, 2)
        wait.assert_called_once_with(999, 0)
        self.assertFalse(result['ok'])
        self.assertEqual(20, result['exit_code'])

    def test_parent_handles_empty_worker_result_as_build_failure(self):
        with mock.patch.object(guard.os, 'pipe', return_value=(901, 902)), \
                mock.patch.object(guard.os, 'fork', return_value=999), \
                mock.patch.object(guard.os, 'close'), \
                mock.patch.object(guard.os, 'fdopen', return_value=contextlib.nullcontext(io.BytesIO(b''))), \
                mock.patch.object(guard.os, 'waitpid', return_value=(999, 1)):
            result = guard.be_build_as_user(self.account, 2)
        self.assertFalse(result['ok'])
        self.assertEqual(20, result['exit_code'])


if __name__ == '__main__':
    unittest.main()
