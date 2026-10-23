"""Real, unprivileged fork lifecycles; no package managers or host services."""
import errno
import fcntl
import os
import pathlib
import select
import signal
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
guard = types.ModuleType('build_worker_lifecycle_under_test')
for name in ('common', 'build_monitor', 'build_environment', 'native_environment'):
    exec(compile((ROOT / ('src/' + name + '.py')).read_text(), name, 'exec'), guard.__dict__)


@unittest.skipUnless(hasattr(os, 'fork') and os.name == 'posix', 'requires POSIX fork')
class WorkerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='phpguard-worker-')
        self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)
        self.handlers = {number: signal.getsignal(number) for number in
                         (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        self.child_pids = []
        self.real_fork = os.fork

    def tearDown(self):
        for number, handler in self.handlers.items():
            self.assertIs(handler, signal.getsignal(number))

    def record_fork(self):
        pid = self.real_fork()
        if pid:
            self.child_pids.append(pid)
        return pid

    def invoke(self, callback):
        with mock.patch.object(guard.os, 'fork', side_effect=self.record_fork):
            return guard.be_worker_call(callback)

    def assert_children_reaped(self):
        self.assertTrue(self.child_pids)
        for pid in self.child_pids:
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

    def test_successful_worker_has_own_session_and_is_reaped(self):
        result = self.invoke(lambda: dict(ok=True, exit_code=0, pid=os.getpid(),
                                          session=os.getsid(0), effective_uid=os.geteuid()))
        self.assertTrue(result['ok'])
        self.assertEqual(result['pid'], result['session'])
        self.assertNotEqual(os.getpid(), result['pid'])
        self.assertEqual(os.geteuid(), result['effective_uid'])
        self.assert_children_reaped()

    def test_blocked_build_preserves_failure_code(self):
        result = self.invoke(lambda: dict(ok=False, exit_code=10, error='preflight blocked'))
        self.assertFalse(result['ok'])
        self.assertEqual(10, result['exit_code'])
        self.assert_children_reaped()

    def test_child_exiting_without_result_is_a_failure(self):
        result = self.invoke(lambda: os._exit(7))
        self.assertFalse(result['ok'])
        self.assertEqual(20, result['exit_code'])
        self.assertIn('without a complete result', result['error'])
        self.assert_children_reaped()

    def test_nonzero_child_exit_cannot_hide_behind_success_json(self):
        real_exit = os._exit
        with mock.patch.object(guard.os, '_exit', side_effect=lambda unused: real_exit(7)):
            result = self.invoke(lambda: dict(ok=True, exit_code=0))
        self.assertFalse(result['ok'])
        self.assertEqual(20, result['exit_code'])
        self.assert_children_reaped()

    def test_child_exceptions_and_oversized_response_are_failures(self):
        def failed():
            raise RuntimeError('fixture build failed')
        callbacks = (failed, lambda: dict(ok=True, payload='x' * (4 * 1024 * 1024 + 1)))
        for callback in callbacks:
            with self.subTest(callback=callback):
                result = self.invoke(callback)
                self.assertFalse(result['ok'])
                self.assertEqual(20, result['exit_code'])
        self.assert_children_reaped()

    def test_all_cancellation_signals_wait_for_cleanup_and_override_success(self):
        parent = os.getpid()
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            marker = self.folder / ('cleaned-' + str(number))
            def worker():
                try:
                    os.kill(parent, number)
                    time.sleep(3)
                except guard.BuildInterrupted:
                    time.sleep(0.05)
                    marker.write_text('cleanup finished')
                    # Even a worker swallowing cancellation cannot authorize
                    # the parent to move on to a deployment.
                    return dict(ok=True, exit_code=0)
                return dict(ok=True, exit_code=0)
            with self.subTest(signal=number):
                result = self.invoke(worker)
                self.assertEqual('cleanup finished', marker.read_text())
                self.assertFalse(result['ok'])
                self.assertEqual(20, result['exit_code'])
                self.assertEqual(number, result['interrupted_signal'])
        self.assert_children_reaped()

    def test_parent_signal_stops_monitored_build_before_worker_returns(self):
        parent = os.getpid()
        process_marker = self.folder / 'build-pid'
        cleanup_marker = self.folder / 'worker-cleaned'
        log = str(self.folder / 'build.log')
        code = ('import os,time\n'
                'with open(%r,"w") as f: f.write(str(os.getpid()))\n'
                'os.kill(%d,%d)\ntime.sleep(20)\n' %
                (str(process_marker), parent, signal.SIGTERM))
        def worker():
            try:
                guard.bm_run([sys.executable, '-c', code], log,
                             timeout=10, interval=0.05)
            finally:
                cleanup_marker.write_text('worker finished monitor cleanup')
            return dict(ok=True, exit_code=0)
        with mock.patch.object(guard, '_bm_display'):
            result = self.invoke(worker)
        self.assertFalse(result['ok'])
        self.assertTrue(cleanup_marker.exists())
        build_pid = int(process_marker.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(build_pid, 0)
        self.assert_children_reaped()

    def test_parent_select_error_still_cancels_and_reaps_its_worker(self):
        real_select = select.select
        count = [0]
        def failing_select(*args):
            count[0] += 1
            if count[0] == 2:
                raise OSError(errno.EIO, 'fixture pipe failure')
            return real_select(*args)
        def worker():
            time.sleep(3)
            return dict(ok=True)
        with mock.patch.object(select, 'select', side_effect=failing_select):
            with self.assertRaisesRegex(OSError, 'fixture pipe failure'):
                self.invoke(worker)
        self.assert_children_reaped()

    def test_fork_failure_restores_handlers(self):
        with mock.patch.object(guard.os, 'fork', side_effect=OSError(errno.EAGAIN, 'fork unavailable')):
            with self.assertRaisesRegex(OSError, 'fork unavailable'):
                guard.be_worker_call(lambda: dict(ok=True))

    def test_parent_fcntl_error_before_wait_still_reaps_its_worker(self):
        real_fcntl = fcntl.fcntl
        def failing_fcntl(fd, operation, *args):
            if operation == fcntl.F_SETFL:
                raise OSError(errno.EIO, 'fixture fcntl failure')
            return real_fcntl(fd, operation, *args)
        def worker():
            time.sleep(3)
            return dict(ok=True)
        with mock.patch.object(fcntl, 'fcntl', side_effect=failing_fcntl):
            with self.assertRaisesRegex(OSError, 'fixture fcntl failure'):
                self.invoke(worker)
        self.assert_children_reaped()

    def test_parent_close_error_does_not_skip_cancellation_and_reap(self):
        parent, closes = os.getpid(), [0]
        real_close = os.close
        def failing_close(fd):
            real_close(fd)
            if os.getpid() == parent:
                closes[0] += 1
                if closes[0] == 2:
                    raise OSError(errno.EIO, 'fixture close failure')
        def worker():
            time.sleep(3)
            return dict(ok=True)
        with mock.patch.object(guard.os, 'close', side_effect=failing_close), \
                mock.patch.object(select, 'select', side_effect=OSError(errno.EIO, 'fixture read failure')):
            with self.assertRaisesRegex(OSError, 'fixture close failure'):
                self.invoke(worker)
        self.assert_children_reaped()


class NativeWorkerBoundaryTests(unittest.TestCase):
    def test_native_worker_failure_remains_failure_after_uid_check(self):
        account = dict(name='builder', uid=1234, gid=1234, home='/home/builder',
                       work_dir='/home/builder/build')
        response = dict(ok=False, exit_code=20, effective_uid=1234,
                        interrupted_signal=signal.SIGTERM)
        with mock.patch.object(guard, 'be_worker_call', return_value=response), \
                mock.patch.dict(guard.__dict__, {'remi_build_main': mock.Mock(),
                                                'deb_builder_main': mock.Mock()}):
            result = guard.nb_child('remi', account, True, 2)
        self.assertFalse(result['ok'])
        self.assertEqual(signal.SIGTERM, result['interrupted_signal'])


if __name__ == '__main__':
    unittest.main()
