"""Native installed-provider queries must preserve RPM dependency constraints."""
import importlib.util
import json
import os
import pathlib
import sys
import types
import unittest
from unittest import mock

SCRIPT = pathlib.Path(os.environ.get('PHP_GUARD_TEST_SCRIPT', str(
    pathlib.Path(__file__).resolve().parents[1] / 'php_guard.py')))
SPEC = importlib.util.spec_from_file_location('php_guard_requirement_versions', SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class NativeProviderQueryTests(unittest.TestCase):
    def query(self, requirements, response=None, code=0, stderr=''):
        if response is None:
            response = {'ok': True, 'requirements': {
                item: {'state': 'satisfied', 'providers': ['provider-1.0-1.x86_64']}
                for item in requirements}}
        with mock.patch.object(guard, '_rpm_system_backend', return_value=('/usr/bin/python', 'yum')), \
                mock.patch.object(guard, 'run_cmd', return_value={
                    'code': code, 'stdout': json.dumps(response), 'stderr': stderr}) as command:
            answer = guard.bp_installed_requirements(requirements)
        return answer, command

    def test_every_constraint_reaches_one_isolated_system_interpreter_without_shell(self):
        requirements = ['libtool >= 1.4.3', 'curl-devel = 1:8.3.0-1.amzn2',
                        'pkgconfig(libsodium) >= 1.0.9', 'libtool <= 9999',
                        'libtool < 9999', 'libtool > 1.0', '/usr/bin/make']
        answer, command = self.query(requirements)
        command.assert_called_once()
        argv = command.call_args.args[0]
        self.assertEqual(['/usr/bin/python', '-E', '-s', '-c'], argv[:4])
        self.assertEqual(requirements, json.loads(argv[-1]))
        self.assertTrue(all(item['state'] == 'satisfied' for item in answer.values()))
        self.assertNotIn('--whatprovides', argv)

    def test_virtual_provider_identity_and_missing_high_version_remain_distinct(self):
        requirements = ['curl-devel >= 7.9', 'libtool >= 9999']
        evidence = {'curl-devel >= 7.9': {'state': 'satisfied',
                    'providers': ['libcurl-devel-8.3.0-1.amzn2.x86_64']},
                    'libtool >= 9999': {'state': 'missing', 'providers': []}}
        answer, unused = self.query(requirements, {'ok': True, 'requirements': evidence})
        self.assertEqual(evidence, answer)

    def test_worker_timeout_or_database_error_is_unknown_not_missing(self):
        for code, stderr in [(124, ''), (1, 'permission denied'), (0, 'database warning')]:
            with self.subTest(code=code, stderr=stderr):
                answer, unused = self.query(['gcc'], code=code, stderr=stderr)
                self.assertEqual('unknown', answer['gcc']['state'])
                self.assertIn('error', answer['gcc'])

    def test_missing_native_bindings_cannot_claim_success(self):
        with mock.patch.object(guard, '_rpm_system_backend', side_effect=RuntimeError('no bindings')), \
                mock.patch.object(guard, 'run_cmd', side_effect=AssertionError('no CLI fallback')):
            answer = guard.bp_installed_requirements(['gcc'])
        self.assertEqual('unknown', answer['gcc']['state'])

    def test_wrong_native_backend_cannot_claim_success(self):
        with mock.patch.object(guard, '_rpm_system_backend', return_value=('/usr/bin/python3', 'dnf')), \
                mock.patch.object(guard, 'run_cmd', side_effect=AssertionError('no DNF fallback')):
            answer = guard.bp_installed_requirements(['gcc'])
        self.assertEqual('unknown', answer['gcc']['state'])

    def test_incomplete_or_contradictory_provider_evidence_is_unknown(self):
        for response in [None, [], {'ok': False, 'error': 'database unreadable'},
                {'ok': True, 'requirements': {}},
                {'ok': True, 'requirements': {'gcc': {'state': 'satisfied', 'providers': []}}},
                {'ok': True, 'requirements': {'gcc': {'state': 'missing', 'providers': ['gcc']}}},
                {'ok': True, 'requirements': {'gcc': {'state': 'satisfied', 'providers': [42]}}}]:
            with self.subTest(response=response):
                actual_response = 'not-a-response' if response is None else response
                answer, unused = self.query(['gcc'], actual_response)
                self.assertEqual('unknown', answer['gcc']['state'])

    def test_invalid_worker_json_is_unknown(self):
        with mock.patch.object(guard, '_rpm_system_backend', return_value=('/usr/bin/python', 'yum')), \
                mock.patch.object(guard, 'run_cmd', return_value={
                    'code': 0, 'stdout': 'not JSON', 'stderr': ''}):
            answer = guard.bp_installed_requirements(['gcc'])
        self.assertEqual('unknown', answer['gcc']['state'])


class NativeWorkerIsolationTests(unittest.TestCase):
    def test_worker_reads_only_installed_sack_and_keeps_complete_constraints(self):
        requirements = ['libtool >= 1.4.3', 'libtool >= 9999', 'pkgconfig(libsodium) >= 1.0.9']
        calls = []
        class InstalledOnlyBase(object):
            def __init__(self):
                self.preconf = types.SimpleNamespace()
                self.conf = types.SimpleNamespace(installroot='/')
            def returnInstalledPackagesByDep(self, requirement):
                self.assert_configuration()
                calls.append(requirement)
                return [] if '9999' in requirement else ['provider-for-' + requirement]
            def assert_configuration(self):
                if self.preconf.init_plugins is not False:
                    raise AssertionError('plugins must be disabled')
            def closeRpmDB(self): calls.append('close-rpmdb')
            def close(self): calls.append('close')
            def __getattr__(self, name):
                raise AssertionError('Unexpected repository, lock or transaction access: ' + name)
        scope = {'__name__': 'test_worker'}
        with mock.patch.dict(sys.modules, {'yum': types.SimpleNamespace(YumBase=InstalledOnlyBase)}), \
                mock.patch.object(sys, 'path', list(sys.path)):
            exec(compile(guard._BP_REQUIREMENTS_WORKER, '<worker>', 'exec'), scope)
            answer = scope['requirement_providers'](requirements)
        self.assertEqual(requirements + ['close-rpmdb', 'close'], calls)
        self.assertEqual('satisfied', answer[requirements[0]]['state'])
        self.assertEqual('missing', answer[requirements[1]]['state'])
        self.assertEqual(['provider-for-' + requirements[2]], answer[requirements[2]]['providers'])

    def test_worker_database_failure_stays_unknown_and_cleanup_runs(self):
        base = mock.Mock()
        base.conf.installroot = '/'
        base.returnInstalledPackagesByDep.side_effect = RuntimeError('RPM database unavailable')
        scope = {'__name__': 'test_worker'}
        with mock.patch.dict(sys.modules, {'yum': types.SimpleNamespace(YumBase=lambda: base)}), \
                mock.patch.object(sys, 'path', list(sys.path)):
            exec(compile(guard._BP_REQUIREMENTS_WORKER, '<worker>', 'exec'), scope)
            answer = scope['requirement_providers'](['gcc'])
        self.assertEqual('unknown', answer['gcc']['state'])
        base.closeRpmDB.assert_called_once()
        base.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
