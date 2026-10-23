"""YUM lock contention tests; use fake bindings and clocks, never host packages."""
import importlib.util
import json
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[1] / 'src' / 'rpm_backend.py'
SPEC = importlib.util.spec_from_file_location('guard_yum_lock_backend', PATH)
backend = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backend)
worker = {'__name__': 'yum_lock_test'}
exec(compile(backend._RPM_WORKER, '<yum-lock-worker>', 'exec'), worker)


class LockError(Exception):
    def __init__(self, errno=0, pid=3416):
        super().__init__('native lock failure')
        self.errno, self.pid = errno, pid


class Clock:
    def __init__(self):
        self.now, self.sleeps = 100.0, []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class YumLockTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.events = []
        self.outcomes = []
        self.close_error = False
        self.transaction_error = None
        owner = self
        self.yum = types.ModuleType('yum')
        self.constants = types.ModuleType('yum.constants')
        self.constants.YUM_PID_FILE = '/var/run/yum.pid'
        self.constants.TS_UPDATE, self.constants.TS_UPDATED = 10, 90
        self.misc = types.ModuleType('yum.misc')
        self.misc.find_unfinished_transactions = lambda **kwargs: []
        self.yum.constants, self.yum.misc = self.constants, self.misc
        self.yum.Errors = types.SimpleNamespace(LockError=LockError)

        class FakeYum:
            def __init__(self):
                self._lockfile = None
                self.preconf = types.SimpleNamespace()
                self.conf = types.SimpleNamespace(installroot='/', persistdir='/var/lib/yum')
                self.repos = types.SimpleNamespace(listEnabled=lambda: [types.SimpleNamespace()])
                self.rpmdb = types.SimpleNamespace(returnPackages=lambda: [])
                self.tsInfo = types.SimpleNamespace(getMembers=lambda: [])

            def doLock(self):
                owner.events.append('lock')
                outcome = owner.outcomes.pop(0) if owner.outcomes else None
                if isinstance(outcome, Exception):
                    raise outcome
                if outcome != 'no_lock':
                    self._lockfile = '/var/run/yum.pid'

            def close(self):
                owner.events.append('close')
                if owner.close_error:
                    raise RuntimeError('close failed')

            def closeRpmDB(self):
                owner.events.append('close_rpmdb')

            def doUnlock(self):
                owner.events.append('unlock')
                self._lockfile = None

            def buildTransaction(self):
                owner.events.append('solve')
                return 2, []

            def downloadPkgs(self, packages):
                owner.events.append('download')
                return []

            def processTransaction(self):
                owner.events.append('transaction')
                if owner.transaction_error:
                    raise owner.transaction_error

        self.yum.YumBase = FakeYum
        self.modules = mock.patch.dict(sys.modules, {'yum': self.yum,
                              'yum.constants': self.constants, 'yum.misc': self.misc})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.clock_patch = mock.patch.dict(worker, {'time': self.clock})
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)

    def candidates(self, seconds):
        return worker['yum_run']({'operation': 'candidates', 'inventory': {'packages': []},
                                  'lock_wait': seconds})

    def test_release_then_continue_only_acquires_again(self):
        self.outcomes = [LockError(), LockError(), None]
        self.assertTrue(self.candidates(5)['ok'])
        self.assertEqual([1.0, 1.0], self.clock.sleeps)
        self.assertEqual(['lock', 'lock', 'lock', 'close', 'close_rpmdb', 'unlock'], self.events)

    def test_wait_zero_still_attempts_once_and_never_unlocks_foreign_lock(self):
        self.outcomes = [LockError()]
        with self.assertRaises(worker['NativeLockTimeout']) as caught:
            self.candidates(0)
        self.assertEqual(3416, caught.exception.lock['pid'])
        self.assertEqual('/var/run/yum.pid', caught.exception.lock['path'])
        self.assertEqual([], self.clock.sleeps)
        self.assertEqual(['lock', 'close', 'close_rpmdb'], self.events)

    def test_wait_expires_at_bound_without_unlock_or_transaction(self):
        self.outcomes = [LockError()] * 5
        with self.assertRaises(worker['NativeLockTimeout']) as caught:
            self.candidates(2)
        self.assertEqual(2, caught.exception.lock['wait_seconds'])
        self.assertEqual(2, caught.exception.lock['waited_seconds'])
        self.assertEqual(2, sum(self.clock.sleeps))
        self.assertNotIn('unlock', self.events)
        self.assertNotIn('transaction', self.events)

    def test_permission_and_invalid_pid_are_not_retried(self):
        for error in (LockError(1), LockError(13), LockError(pid=0),
                      LockError(pid=-1), LockError(pid='3416'), LockError(pid=True)):
            with self.subTest(error=(error.errno, error.pid)):
                self.events[:] = []
                self.outcomes = [error]
                with self.assertRaises(LockError):
                    self.candidates(120)
                self.assertEqual(['lock', 'close', 'close_rpmdb'], self.events)
                self.assertEqual([], self.clock.sleeps)

    def test_missing_native_lock_is_not_treated_as_acquired(self):
        self.outcomes = ['no_lock']
        with self.assertRaisesRegex(RuntimeError, 'could not acquire'):
            self.candidates(0)
        self.assertNotIn('unlock', self.events)

    def test_acquired_lock_releases_even_if_close_fails(self):
        self.close_error = True
        with self.assertRaisesRegex(RuntimeError, 'close failed'):
            self.candidates(0)
        self.assertEqual(['lock', 'close', 'close_rpmdb', 'unlock'], self.events)

    def test_execute_error_is_not_retried_even_when_it_is_a_lock_error(self):
        self.transaction_error = LockError()
        overrides = {'prepare': lambda values: {}, 'verify_existing': lambda *args: None,
                     'validate_changes': lambda *args: [], 'verify_after': lambda *args: None}
        with mock.patch.dict(worker, overrides), mock.patch.object(worker['os'], 'geteuid', return_value=0):
            with self.assertRaises(LockError):
                worker['yum_run']({'operation': 'transaction', 'updates': [], 'execute': True,
                                   'lock_wait': 120})
        self.assertEqual(1, self.events.count('transaction'))
        self.assertEqual(1, self.events.count('lock'))
        self.assertEqual(1, self.events.count('unlock'))
        self.assertEqual([], self.clock.sleeps)

    def test_invalid_wait_is_rejected_before_native_lock(self):
        for seconds in (-1, 3601, True, 1.5, '120', None):
            with self.subTest(seconds=seconds), self.assertRaisesRegex(RuntimeError, 'non-negative integer'):
                self.candidates(seconds)
        self.assertNotIn('lock', self.events)

    def test_python2_clock_uses_elapsed_time_instead_of_wall_clock(self):
        with mock.patch.dict(worker, {'time': types.SimpleNamespace()}), \
                mock.patch.object(worker['os'], 'times', return_value=(0, 0, 0, 0, 123.5)):
            self.assertEqual(123.5, worker['lock_time']())

    def test_worker_timeout_response_preserves_details(self):
        self.outcomes = [LockError()]
        with tempfile.TemporaryDirectory() as directory:
            request, response = [str(pathlib.Path(directory) / name) for name in ('in.json', 'out.json')]
            pathlib.Path(request).write_text(json.dumps({'backend': 'yum', 'operation': 'candidates',
                'inventory': {'packages': []}, 'lock_wait': 0}))
            with mock.patch.object(sys, 'argv', ['worker', request, response]):
                worker['main']()
            result = json.loads(pathlib.Path(response).read_text())
        self.assertFalse(result['ok'])
        self.assertFalse(result['executed'])
        self.assertEqual('package_manager_lock_timeout', result['error_kind'])
        self.assertEqual(3416, result['lock']['pid'])


class PublicLockResultTests(unittest.TestCase):
    def test_candidates_exposes_structured_timeout(self):
        result = dict(ok=False, error='busy', error_kind='package_manager_lock_timeout',
                      lock={'backend': 'yum', 'pid': 3416})
        with mock.patch.object(backend, '_rpm_worker_call', return_value=result):
            with self.assertRaises(backend.PackageManagerLockTimeout) as caught:
                backend.rpm_candidates({'packages': []})
        self.assertEqual(3416, caught.exception.lock['pid'])
        self.assertEqual('package_manager_lock_timeout', caught.exception.error_kind)

    def test_transactions_keep_structured_failure(self):
        result = dict(ok=False, error='busy', error_kind='package_manager_lock_timeout',
                      lock={'backend': 'yum', 'pid': 3416}, executed=False)
        with mock.patch.object(backend, '_rpm_worker_call', return_value=result):
            self.assertEqual(result, backend.rpm_transaction([], execute=True))

    def test_worker_receives_wait_budget_and_execute_is_never_killed_on_timer(self):
        seen = []

        def command(argv, timeout):
            request = json.loads(pathlib.Path(argv[-2]).read_text())
            seen.append((request, timeout))
            pathlib.Path(argv[-1]).write_text(json.dumps({'ok': True}))
            return {'code': 0}

        with mock.patch.object(backend, '_rpm_system_backend', return_value=('/usr/bin/python', 'yum')), \
                mock.patch.object(backend, 'run_cmd', command, create=True), \
                mock.patch.object(backend, 'RPM_LOCK_WAIT_SECONDS', 15):
            backend._rpm_worker_call({'operation': 'candidates'})
            backend._rpm_worker_call({'operation': 'transaction', 'execute': True})
        self.assertEqual(15, seen[0][0]['lock_wait'])
        self.assertEqual(615, seen[0][1])
        self.assertIsNone(seen[1][1])


if __name__ == '__main__':
    unittest.main()
