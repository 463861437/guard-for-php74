"""Environment setup must not install outside the verified AL2 build workflow."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import pwd
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(os.environ.get('PHP_GUARD_TEST_SCRIPT', str(
    pathlib.Path(__file__).resolve().parents[1] / 'php_guard.py')))
SPEC = importlib.util.spec_from_file_location('php_guard_environment_under_test', SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class EnvironmentCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='phpguard-environment-')
        self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)
        for name in ('run_cmd', 'bp_call'):
            patch = mock.patch.object(guard, name, side_effect=AssertionError('unexpected host command'))
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(guard.subprocess, 'Popen', side_effect=AssertionError('unexpected subprocess'))
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(guard, 'say')
        self.say = patch.start()
        self.addCleanup(patch.stop)


class EnvironmentRequirementTests(EnvironmentCase):
    def test_bad_source_hash_stops_before_rpm_query(self):
        source = self.folder / 'untrusted.src.rpm'
        source.write_bytes(b'not the pinned source RPM')
        with self.assertRaisesRegex(RuntimeError, 'SHA256 mismatch'):
            guard.be_requirements(str(source), '/usr/bin/rpm')

    def test_query_uses_pinned_source_and_passes_capabilities_as_data(self):
        output = ('gcc\nlibxml2-devel >= 2.7\n/usr/bin/pkg-config\ngcc\n'
                  'rpmlib(CompressedFileNames) <= 3.0.4-1\n')
        events = []
        def verify(path, digest):
            events.append(('verify', path, digest))
        def query(argv, **kwargs):
            events.append(('query', argv))
            return dict(code=0, stdout=output, stderr='')
        with mock.patch.object(guard, 'bp_verify', side_effect=verify), \
                mock.patch.object(guard, 'run_cmd', side_effect=query):
            result = guard.be_requirements('/fixed/source.src.rpm', '/usr/bin/rpm')
        self.assertEqual(('verify', '/fixed/source.src.rpm', guard.BP_SRPM_SHA), events[0])
        self.assertEqual(('query', ['/usr/bin/rpm', '-qp', '--requires', '/fixed/source.src.rpm']), events[1])
        self.assertCountEqual(['gcc', 'libxml2-devel >= 2.7', '/usr/bin/pkg-config'], result)
        self.assertEqual(3, len(result))

    def test_query_failure_empty_internal_only_and_oversized_data_are_rejected(self):
        invalid = [dict(code=1, stdout='gcc\n', stderr='query failed'),
                   dict(code=124, stdout='', stderr=''),
                   dict(code=0, stdout='', stderr=''),
                   dict(code=0, stdout=' \n\t\n', stderr=''),
                   dict(code=0, stdout='rpmlib(CompressedFileNames) <= 3.0.4-1\n', stderr=''),
                   dict(code=0, stdout='\n'.join('pkg%04d' % i for i in range(257)), stderr=''),
                   dict(code=0, stdout='a' * 16384, stderr='')]
        for response in invalid:
            with self.subTest(code=response['code'], size=len(response['stdout'])), \
                    mock.patch.object(guard, 'bp_verify'), \
                    mock.patch.object(guard, 'run_cmd', return_value=response):
                with self.assertRaises(RuntimeError):
                    guard.be_requirements('/fixed/source.src.rpm', '/usr/bin/rpm')

    def test_unsafe_capabilities_are_not_allowed_into_install_arguments(self):
        for requirement in ('--install', 'gcc;touch /tmp/unwanted', '$(id)', '`id`',
                            'gcc | sh', 'gcc\x00extra', 'gcc\t;false',
                            'rpmlib(CompressedFileNames);id'):
            response = dict(code=0, stdout='make\n' + requirement + '\n', stderr='')
            with self.subTest(requirement=repr(requirement)), \
                    mock.patch.object(guard, 'bp_verify'), \
                    mock.patch.object(guard, 'run_cmd', return_value=response):
                with self.assertRaises(RuntimeError):
                    guard.be_requirements('/fixed/source.src.rpm', '/usr/bin/rpm')


class EnvironmentHostTests(EnvironmentCase):
    def setUp(self):
        super().setUp()
        self.args = argparse.Namespace(build_user='builder', work_dir=None, yes=True, lock_wait=5)
        self.host = dict(platform='linux', os_id='amzn', os_version='2', architecture='x86_64',
                         uid=0, user='root', build_user='ec2-user', build_home='/home/ec2-user')
        self.account = pwd.struct_passwd(('builder', 'x', 1001, 1001, '', str(self.folder), '/bin/bash'))

    def test_unsupported_host_stops_before_account_lookup_reports_and_transactions(self):
        cases = [dict(platform='darwin'), dict(os_id='ubuntu'), dict(os_version='2023'),
                 dict(architecture='aarch64')]
        for changed in cases:
            with self.subTest(changed=changed), \
                    mock.patch.object(guard, 'bp_doctor_host', return_value=dict(self.host, **changed)), \
                    mock.patch.object(pwd, 'getpwnam') as lookup, \
                    mock.patch.object(guard, 'be_report_directory') as report, \
                    mock.patch.object(guard, 'build_environment_transaction') as transaction, \
                    mock.patch.object(guard, 'be_as_user') as child:
                with self.assertRaisesRegex(RuntimeError, 'Amazon Linux 2'):
                    guard.be_setup(self.args)
            lookup.assert_not_called()
            report.assert_not_called()
            transaction.assert_not_called()
            child.assert_not_called()

    def test_nonroot_setup_cannot_begin_installation(self):
        with mock.patch.object(guard, 'bp_doctor_host', return_value=self.host), \
                mock.patch.object(guard.os, 'geteuid', return_value=1000), \
                mock.patch.object(guard, 'be_report_directory') as report, \
                mock.patch.object(guard, 'build_environment_transaction') as transaction:
            with self.assertRaisesRegex(RuntimeError, 'sudo/root'):
                guard.be_setup(self.args)
        report.assert_not_called()
        transaction.assert_not_called()

    def test_root_and_nonlogin_build_accounts_cannot_begin_installation(self):
        for uid, shell in [(0, '/bin/bash'), (1001, '/sbin/nologin'),
                           (1001, '/usr/sbin/nologin'), (1001, '/bin/false')]:
            account = pwd.struct_passwd(('builder', 'x', uid, 1001, '', str(self.folder), shell))
            with self.subTest(uid=uid, shell=shell), \
                    mock.patch.object(guard, 'bp_doctor_host', return_value=self.host), \
                    mock.patch.object(guard.os, 'geteuid', return_value=0), \
                    mock.patch.object(pwd, 'getpwnam', return_value=account), \
                    mock.patch.object(guard, 'be_report_directory') as report, \
                    mock.patch.object(guard, 'build_environment_transaction') as transaction:
                with self.assertRaisesRegex(RuntimeError, '非 root'):
                    guard.be_setup(self.args)
            report.assert_not_called()
            transaction.assert_not_called()

    def test_unknown_build_account_has_controlled_failure_before_reports(self):
        with mock.patch.object(guard, 'bp_doctor_host', return_value=self.host), \
                mock.patch.object(guard.os, 'geteuid', return_value=0), \
                mock.patch.object(pwd, 'getpwnam', side_effect=KeyError('missing')), \
                mock.patch.object(guard, 'be_report_directory') as report, \
                mock.patch.object(guard, 'build_environment_transaction') as transaction:
            with self.assertRaises(RuntimeError):
                guard.be_setup(self.args)
        report.assert_not_called()
        transaction.assert_not_called()

    def test_explicit_build_account_controls_default_work_directory(self):
        with mock.patch.object(guard, 'bp_doctor_host', return_value=self.host), \
                mock.patch.object(guard.os, 'geteuid', return_value=0), \
                mock.patch.object(pwd, 'getpwnam', return_value=self.account) as lookup:
            result = guard.be_validate_host_user(self.args)
        lookup.assert_called_once_with('builder')
        self.assertEqual(dict(name='builder', uid=1001, gid=1001,
                              home=str(self.folder), work_dir=str(self.folder / 'php74-backport')), result)

    def test_invalid_work_path_rejected_before_report_creation(self):
        self.args.work_dir = str(self.folder / 'unsafe directory')
        with mock.patch.object(guard, 'bp_doctor_host', return_value=self.host), \
                mock.patch.object(guard.os, 'geteuid', return_value=0), \
                mock.patch.object(pwd, 'getpwnam', return_value=self.account), \
                mock.patch.object(guard, 'be_report_directory') as report:
            with self.assertRaisesRegex(RuntimeError, 'ASCII'):
                guard.be_setup(self.args)
        report.assert_not_called()


class EnvironmentWorkflowTests(EnvironmentCase):
    def setUp(self):
        super().setUp()
        self.args = argparse.Namespace(build_user='builder', work_dir=str(self.folder / 'build'),
                                       yes=False, lock_wait=7)
        self.account = dict(name='builder', uid=1001, gid=1001, home=str(self.folder),
                            work_dir=self.args.work_dir)
        self.preview = dict(ok=True, changes=[dict(name='gcc', action='install', version='7.3.1')])
        self.applied = dict(ok=True, changes=self.preview['changes'], executed=True)
        self.checked = dict(ok=True, doctor=dict(state='ready_for_build'), effective_uid=1001, prepared=True)
        self.patches = {}
        stubs = dict(be_validate_host_user=self.account, be_report_directory=str(self.folder),
                     _inv_tool='/usr/bin/tool', be_private_inputs=('/private/source.src.rpm', '/usr/bin/rpm'),
                     be_requirements=['gcc', 'libxml2-devel >= 2.7'], acquire_repair_lock=901,
                     be_as_user=self.checked)
        for name, value in stubs.items():
            patch = mock.patch.object(guard, name, return_value=value)
            self.patches[name] = patch.start()
            self.addCleanup(patch.stop)
        for name in ('umask', 'close'):
            patch = mock.patch.object(guard.os, name)
            self.patches[name] = patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(guard, 'bp_prepare', side_effect=AssertionError('setup must use unprivileged child'))
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(guard, 'bp_build', side_effect=AssertionError('setup must not build PHP'))
        patch.start()
        self.addCleanup(patch.stop)

    def report(self):
        return json.loads((self.folder / 'setup.json').read_text())

    def test_dry_run_resolves_plan_without_installation_privilege_child_or_build(self):
        with mock.patch.object(guard, 'build_environment_transaction', return_value=self.preview) as transaction:
            result = guard.be_setup(self.args)
        self.assertEqual(0, result)
        self.assertEqual('environment_plan_ready', self.report()['state'])
        self.assertFalse(self.report()['php_deployed'])
        self.assertFalse(self.report()['build_started'])
        self.assertEqual([], self.report()['transactions'])
        self.assertEqual(1, transaction.call_count)
        self.assertFalse(transaction.call_args.kwargs.get('execute', False))
        self.assertEqual(7, transaction.call_args.kwargs['lock_wait'])
        self.patches['be_as_user'].assert_not_called()
        self.patches['acquire_repair_lock'].assert_not_called()

    def test_blocked_preview_does_not_install_or_prepare_as_user(self):
        self.args.yes = True
        with mock.patch.object(guard, 'build_environment_transaction', return_value=dict(ok=False, error='unsafe PHP dependency')) as transaction:
            self.assertEqual(10, guard.be_setup(self.args))
        self.assertEqual(1, transaction.call_count)
        self.assertFalse(transaction.call_args.kwargs.get('execute', False))
        self.assertEqual('dependency_plan_blocked', self.report()['state'])
        self.patches['be_as_user'].assert_not_called()
        self.patches['close'].assert_called_once_with(901)

    def test_failed_install_does_not_prepare_or_run_postcheck(self):
        self.args.yes = True
        with mock.patch.object(guard, 'build_environment_transaction', side_effect=[
                self.preview, dict(ok=False, error='rpm transaction failed', executed=True)]) as transaction:
            self.assertEqual(20, guard.be_setup(self.args))
        self.assertEqual('dependency_install_failed', self.report()['state'])
        self.assertFalse(self.report()['php_deployed'])
        self.assertTrue(transaction.call_args.kwargs['execute'])
        self.assertEqual(self.preview['changes'], transaction.call_args.kwargs['expected_changes'])
        self.patches['be_as_user'].assert_not_called()
        self.patches['close'].assert_called_once_with(901)

    def test_failed_srpm_signature_never_reaches_dependency_transaction(self):
        self.args.yes = True
        self.patches['be_private_inputs'].side_effect = RuntimeError('signature failed')
        with mock.patch.object(guard, 'build_environment_transaction') as transaction:
            self.assertEqual(20, guard.be_setup(self.args))
        transaction.assert_not_called()
        self.patches['be_as_user'].assert_not_called()
        self.assertEqual('environment_setup_error', self.report()['state'])
        self.assertIn('signature failed', self.report()['error'])

    def test_successful_install_must_pass_ordinary_user_doctor_before_ready(self):
        self.args.yes = True
        with mock.patch.object(guard, 'build_environment_transaction', side_effect=[self.preview, self.applied]) as transaction:
            self.assertEqual(0, guard.be_setup(self.args))
        self.assertEqual('environment_ready_not_built', self.report()['state'])
        self.assertEqual(self.checked, self.report()['build_user_check'])
        self.patches['be_as_user'].assert_called_once_with(self.account)
        self.assertFalse(self.report()['php_deployed'])
        self.assertFalse(self.report()['build_started'])
        self.assertEqual(self.preview['changes'], transaction.call_args.kwargs['expected_changes'])

    def test_doctor_blocked_after_install_is_not_success(self):
        self.args.yes = True
        self.patches['be_as_user'].return_value = dict(ok=False, prepared=True, effective_uid=1001,
            doctor=dict(state='build_preflight_blocked', blockers=['dependency still missing']))
        with mock.patch.object(guard, 'build_environment_transaction', side_effect=[self.preview, self.applied]):
            self.assertEqual(10, guard.be_setup(self.args))
        self.assertEqual('environment_postcheck_failed', self.report()['state'])
        self.assertFalse(self.report()['php_deployed'])
        self.assertFalse(self.report()['build_started'])
        self.assertFalse(self.report()['build_user_check']['ok'])

    def test_bootstrap_dry_run_stops_before_fetch_or_install(self):
        self.patches['_inv_tool'].side_effect = lambda name, ignored: None if name == 'curl' else '/usr/bin/rpm'
        with mock.patch.object(guard, 'build_environment_transaction', return_value=self.preview) as transaction:
            self.assertEqual(0, guard.be_setup(self.args))
        self.assertEqual('bootstrap_plan_ready', self.report()['state'])
        transaction.assert_called_once_with(['curl'], lock_wait=7)
        self.patches['be_private_inputs'].assert_not_called()
        self.patches['be_as_user'].assert_not_called()

    def test_failed_bootstrap_install_stops_before_fetch_or_user_work(self):
        self.args.yes = True
        self.patches['_inv_tool'].return_value = None
        with mock.patch.object(guard, 'build_environment_transaction', side_effect=[
                self.preview, dict(ok=False, executed=True, error='bootstrap failed')]) as transaction:
            self.assertEqual(20, guard.be_setup(self.args))
        self.assertEqual('bootstrap_failed', self.report()['state'])
        self.assertEqual(['rpm', 'curl'], transaction.call_args.args[0])
        self.assertTrue(transaction.call_args.kwargs['execute'])
        self.patches['be_private_inputs'].assert_not_called()
        self.patches['be_as_user'].assert_not_called()


class EnvironmentCliTests(EnvironmentCase):
    def test_setup_defaults_to_preview_and_passes_explicit_execution_flags(self):
        with mock.patch.object(guard, 'be_setup', return_value=10) as setup:
            self.assertEqual(10, guard.backport_main(['setup']))
        self.assertFalse(setup.call_args.args[0].yes)
        self.assertEqual(120, setup.call_args.args[0].lock_wait)
        with mock.patch.object(guard, 'be_setup', return_value=0) as setup:
            self.assertEqual(0, guard.backport_main(['setup', '--yes', '--build-user', 'builder',
                '--work-dir', str(self.folder), '--lock-wait', '300']))
        args = setup.call_args.args[0]
        self.assertTrue(args.yes)
        self.assertEqual('builder', args.build_user)
        self.assertEqual(str(self.folder), args.work_dir)
        self.assertEqual(300, args.lock_wait)

    def test_invalid_or_misplaced_setup_flags_fail_before_actions(self):
        invalid = [
            ['setup', '--srpm', 'user-controlled.src.rpm'],
            ['setup', '--patch-file', 'patch'], ['setup', '--key-file', 'key'],
            ['setup', '--output-dir', 'directory'],
            ['setup', '--lock-wait', '-1'], ['setup', '--lock-wait', '3601'],
            ['setup', '--lock-wait', '1.5'],
            ['doctor', '--yes'], ['doctor', '--build-user', 'builder'],
            ['doctor', '--lock-wait', '300'], ['doctor', '--lock-wait', '120'],
            ['auto', '--work-dir', str(self.folder), '--yes'],
        ]
        with mock.patch.object(guard, 'be_setup') as setup, \
                mock.patch.object(guard, 'bp_doctor') as doctor, \
                mock.patch.object(guard, 'bp_auto') as auto:
            for argv in invalid:
                with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as failure:
                        guard.backport_main(argv)
                    self.assertEqual(2, failure.exception.code)
        setup.assert_not_called()
        doctor.assert_not_called()
        auto.assert_not_called()


class EnvironmentPrivilegeTests(EnvironmentCase):
    def run_child(self, effective_uid=1001, doctor_state='ready_for_build'):
        account = dict(name='builder', uid=1001, gid=1001, home=str(self.folder),
                       work_dir=str(self.folder / 'prepared'))
        events = []
        def prepare(args):
            events.append(('prepare', args.output_dir))
        def doctor(args):
            events.append(('doctor', args.work_dir))
            return dict(state=doctor_state)
        with mock.patch.object(guard, 'be_worker_call', side_effect=lambda callback: callback()), \
                mock.patch.object(guard.os, 'initgroups', side_effect=lambda name, gid: events.append(('groups', name, gid))), \
                mock.patch.object(guard.os, 'setgid', side_effect=lambda gid: events.append(('gid', gid))), \
                mock.patch.object(guard.os, 'setuid', side_effect=lambda uid: events.append(('uid', uid))), \
                mock.patch.object(guard.os, 'geteuid', return_value=effective_uid), \
                mock.patch.dict(guard.os.environ, {'UNTRUSTED_ENV': 'inherited'}, clear=True), \
                mock.patch.object(guard.os, 'chdir', side_effect=lambda folder: events.append(('chdir', folder))), \
                mock.patch.object(guard.os, 'umask'), \
                mock.patch.object(guard, 'bp_prepare', side_effect=prepare), \
                mock.patch.object(guard, 'bp_doctor_report', side_effect=doctor):
            result = guard.be_as_user(account)
            environment = dict(guard.os.environ)
        return events, result, environment

    def test_child_drops_groups_gid_uid_and_environment_before_prepare(self):
        events, result, environment = self.run_child()
        self.assertEqual([('groups', 'builder', 1001), ('gid', 1001), ('uid', 1001)], events[:3])
        self.assertEqual(('chdir', str(self.folder)), events[3])
        self.assertEqual(('prepare', str(self.folder / 'prepared')), events[4])
        self.assertEqual(('doctor', str(self.folder / 'prepared')), events[5])
        self.assertNotIn('UNTRUSTED_ENV', environment)
        self.assertEqual(str(self.folder), environment['HOME'])
        self.assertTrue(result['ok'])
        self.assertEqual(1001, result['effective_uid'])
        self.assertEqual(0, result['exit_code'])

    def test_privilege_drop_failure_cannot_prepare_or_report_ready(self):
        for uid in (0, 1002):
            with self.subTest(uid=uid):
                events, result, _ = self.run_child(effective_uid=uid)
                self.assertFalse(result['ok'])
                self.assertIn('Failed to drop', result['error'])
                self.assertFalse(any(event[0] in ('prepare', 'doctor', 'chdir') for event in events))
                self.assertEqual(20, result['exit_code'])

    def test_user_doctor_failure_still_returns_nonzero_child_status(self):
        _, result, _ = self.run_child(doctor_state='build_preflight_blocked')
        self.assertFalse(result['ok'])
        self.assertTrue(result['prepared'])
        self.assertEqual('build_preflight_blocked', result['doctor']['state'])
        self.assertEqual(10, result['exit_code'])


if __name__ == '__main__':
    unittest.main()
