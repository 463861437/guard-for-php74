"""Bounded real subprocess checks. Never start package managers or PHP services."""
import contextlib
import errno
import importlib.util
import io
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'src/build_monitor.py'
SPEC = importlib.util.spec_from_file_location('build_monitor_test_module', SOURCE)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


def running(pid):
    if sys.platform.startswith('linux'):
        try:
            fields = pathlib.Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
            if fields[0] == 'Z':
                return False
        except FileNotFoundError:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


@unittest.skipUnless(os.name == 'posix', 'POSIX build worker')
class BuildMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.log = self.directory / 'build.log'
        self.terminal = io.StringIO()

    def run_command(self, code, **kwargs):
        with contextlib.redirect_stdout(self.terminal):
            return monitor.bm_run([sys.executable, '-c', code], str(self.log),
                                  timeout=kwargs.pop('timeout', 4),
                                  interval=kwargs.pop('interval', 0.03), **kwargs)

    def status(self):
        return json.loads(pathlib.Path(str(self.log) + '.progress.json').read_text())

    def assert_clean(self):
        status = self.status()
        self.assertTrue(status['cleanup_complete'])
        if status.get('pid'):
            self.assertFalse(running(status['pid']))

    def test_live_output_is_logged_and_progress_has_real_test_counts(self):
        result = self.run_command("import sys,time; print('checking compiler'); sys.stdout.flush(); "
                                  "time.sleep(.08); print('TEST 3/10 [secret/path.phpt]'); "
                                  "sys.stdout.flush(); time.sleep(.08)")
        self.assertEqual('', result)
        self.assertIn('checking compiler', self.log.read_text())
        state = self.status()
        self.assertEqual(('succeeded', 'completed', 'tests', 3, 10),
                         (state['state'], state['reason'], state['stage'],
                          state['test_current'], state['test_total']))
        self.assertIn('3/10', self.terminal.getvalue())
        self.assertNotIn('secret/path', self.terminal.getvalue())
        self.assertNotIn('secret/path', json.dumps(state))
        self.assert_clean()

    def test_default_stdin_is_eof_and_explicit_input_is_delivered(self):
        self.run_command("import sys; assert sys.stdin.read() == ''")
        self.run_command("import sys; assert sys.stdin.read() == 'input secret'", data='input secret')
        self.assertEqual('succeeded', self.status()['state'])
        self.assertNotIn('input secret', self.terminal.getvalue())

    def test_empty_log_nonzero_exit_is_not_success(self):
        with self.assertRaisesRegex(RuntimeError, 'exit code 7'):
            self.run_command('import sys; sys.exit(7)')
        state = self.status()
        self.assertEqual(('failed', 'exit_nonzero', 7, 0),
                         (state['state'], state['reason'], state['exit_code'], state['log_bytes']))
        self.assert_clean()

    def test_silent_process_times_out_and_is_reaped(self):
        with self.assertRaisesRegex(RuntimeError, 'total limit'):
            self.run_command('import time; time.sleep(60)', timeout=0.15)
        self.assertEqual('timeout', self.status()['reason'])
        self.assert_clean()

    def test_silent_but_active_build_gets_warning_without_early_termination(self):
        with mock.patch.object(monitor, 'BM_QUIET_SECONDS', 0.04):
            self.run_command('import time; time.sleep(.15)', timeout=1)
        self.assertEqual('succeeded', self.status()['state'])
        self.assertIn('长时间无日志更新', self.terminal.getvalue())

    def test_child_surviving_successful_parent_is_killed_and_build_fails(self):
        pid_path = self.directory / 'child.pid'
        code = ("import os,time; child=os.fork(); "
                "open(%r,'w').write(str(child)) if child else time.sleep(60)" % str(pid_path))
        with mock.patch.object(monitor, 'BM_CLEANUP_GRACE_SECONDS', 0.15):
            with self.assertRaisesRegex(RuntimeError, 'child processes remained'):
                self.run_command(code)
        self.assertEqual('remaining_children', self.status()['reason'])
        self.assertFalse(running(int(pid_path.read_text())))
        self.assert_clean()

    def test_timeout_cleans_grandchild_that_ignores_term(self):
        pid_path = self.directory / 'grandchild.pid'
        code = ("import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                "child=os.fork(); open(%r,'w').write(str(child)) if child else None; time.sleep(60)"
                % str(pid_path))
        started = time.monotonic()
        with mock.patch.object(monitor, 'BM_CLEANUP_GRACE_SECONDS', 0.15):
            with self.assertRaises(RuntimeError):
                self.run_command(code, timeout=0.15)
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(running(int(pid_path.read_text())))
        self.assert_clean()

    def test_output_failure_stops_owned_command(self):
        with mock.patch.object(monitor, '_bm_display', side_effect=BrokenPipeError()):
            with self.assertRaisesRegex(RuntimeError, 'BrokenPipeError'):
                self.run_command('import time; time.sleep(60)')
        self.assertEqual('failed', self.status()['state'])
        self.assert_clean()

    def test_progress_write_failure_after_launch_stops_owned_command(self):
        actual_write = monitor._bm_atomic_status
        count = [0]
        def fail_once(path, value):
            count[0] += 1
            if count[0] == 2:
                raise OSError('simulated full status disk')
            return actual_write(path, value)
        with mock.patch.object(monitor, '_bm_atomic_status', side_effect=fail_once):
            with self.assertRaises(RuntimeError):
                self.run_command('import time; time.sleep(60)')
        self.assertEqual('failed', self.status()['state'])
        self.assertEqual('status_write_failed', self.status()['reason'])
        self.assert_clean()

    def test_monitor_does_not_print_command_environment_or_raw_log(self):
        environment = os.environ.copy()
        environment['BUILD_SECRET_FIXTURE'] = 'fixture-secret-never-display'
        self.run_command("import os; print(os.environ['BUILD_SECRET_FIXTURE'])", env=environment)
        self.assertIn('fixture-secret-never-display', self.log.read_text())
        self.assertNotIn('fixture-secret-never-display', self.terminal.getvalue())
        self.assertNotIn('fixture-secret-never-display', json.dumps(self.status()))

    def test_large_output_is_direct_to_file_and_tail_is_bounded(self):
        self.run_command("import sys; sys.stdout.write('x' * 2000000 + '\\nTEST 1/2 [private]\\n')")
        self.assertGreater(self.status()['log_bytes'], 2000000)
        self.assertEqual((1, 2), (self.status()['test_current'], self.status()['test_total']))
        self.assertLess(len(self.terminal.getvalue()), 10000)

    def test_missing_executable_records_failure_without_leaking_arguments(self):
        with contextlib.redirect_stdout(self.terminal), self.assertRaises(RuntimeError):
            monitor.bm_run(['/nonexistent/build-fixture', 'hidden-fixture'], str(self.log),
                           timeout=1, interval=.05)
        self.assertEqual(('failed', 'monitor_error'), (self.status()['state'], self.status()['reason']))
        self.assertNotIn('hidden-fixture', json.dumps(self.status()))

    def test_original_signal_handlers_are_restored(self):
        originals = {value: signal.getsignal(value) for value in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        self.run_command('pass')
        self.assertEqual(originals, {value: signal.getsignal(value) for value in originals})

    def test_signal_during_final_status_write_is_not_success(self):
        actual_write = monitor._bm_atomic_status
        count = [0]
        def terminate_after_final_write(path, value):
            actual_write(path, value)
            if value['state'] == 'succeeded':
                count[0] += 1
                if count[0] == 2:
                    os.kill(os.getpid(), signal.SIGTERM)
        with mock.patch.object(monitor, '_bm_atomic_status', side_effect=terminate_after_final_write):
            with self.assertRaises(monitor.BuildInterrupted):
                self.run_command('pass')
        self.assertEqual(('interrupted', 'signal'), (self.status()['state'], self.status()['reason']))
        self.assert_clean()

    def test_fifo_log_fails_without_waiting_for_a_reader(self):
        os.mkfifo(str(self.log))
        started = time.monotonic()
        with self.assertRaises(RuntimeError):
            self.run_command('pass')
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual('failed', self.status()['state'])

    def test_unknown_proc_state_is_not_treated_as_exited(self):
        with mock.patch.object(monitor.os, 'killpg'), \
                mock.patch.object(monitor, '_bm_group_snapshot', return_value=None):
            self.assertTrue(monitor._bm_group_alive(123456))

    def test_permission_denied_proc_snapshot_is_unknown(self):
        with mock.patch.object(monitor.sys, 'platform', 'linux'), \
                mock.patch.object(monitor.os.path, 'isdir', return_value=True), \
                mock.patch.object(monitor.os, 'listdir', return_value=['123']), \
                mock.patch.object(monitor.os, 'sysconf', return_value=100), \
                mock.patch('builtins.open', side_effect=OSError(errno.EACCES, 'denied')):
            self.assertIsNone(monitor._bm_group_snapshot(123))

    def test_python2_sysconf_uses_integer_even_with_unicode_literals(self):
        def strict_python2_sysconf(value):
            if not isinstance(value, int):
                raise TypeError('configuration names must be strings or integers')
            self.assertEqual(31415, value)
            return 100
        with mock.patch.object(monitor.sys, 'platform', 'linux2'), \
                mock.patch.object(monitor.os.path, 'isdir', return_value=True), \
                mock.patch.object(monitor.os, 'listdir', return_value=[]), \
                mock.patch.object(monitor.os, 'sysconf_names', {'SC_CLK_TCK': 31415}), \
                mock.patch.object(monitor.os, 'sysconf', side_effect=strict_python2_sysconf) as query:
            self.assertEqual({}, monitor._bm_group_snapshot(123))
            query.assert_called_once_with(31415)

    def test_sampling_error_preserves_type_without_false_persistence_diagnosis(self):
        with mock.patch.object(monitor._BMLogReader, 'sample', side_effect=ValueError('private data')):
            with self.assertRaisesRegex(RuntimeError, 'ValueError') as raised:
                self.run_command('import time; time.sleep(60)')
        self.assertNotIn('private data', str(raised.exception))
        self.assertEqual(('failed', 'monitor_error', 'ValueError'),
                         (self.status()['state'], self.status()['reason'], self.status()['error_type']))
        self.assertNotIn('private data', json.dumps(self.status()))
        self.assert_clean()

    def test_real_signal_stops_child_and_returns_interrupted(self):
        # The monitor runs in its own test process so a failed fixture cannot
        # deliver a terminating signal to the unittest runner itself.
        code = ("import runpy,sys; m=runpy.run_path(sys.argv[1]); "
                "m['bm_run'].__globals__['BM_CLEANUP_GRACE_SECONDS']=.15\n"
                "try: m['bm_run']([sys.executable,'-c','import time; time.sleep(60)'],sys.argv[2],timeout=10,interval=.03)\n"
                "except m['BuildInterrupted']: sys.exit(23)\n")
        process = subprocess.Popen([sys.executable, '-c', code, str(SOURCE), str(self.log)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 4
            state = {}
            while time.monotonic() < deadline:
                try:
                    state = self.status()
                    if state.get('state') == 'running':
                        break
                except (FileNotFoundError, ValueError):
                    pass
                if process.poll() is not None:
                    break
                time.sleep(.02)
            self.assertEqual('running', state.get('state'))
            os.kill(process.pid, signal.SIGTERM)
            output, errors = process.communicate(timeout=5)
            self.assertEqual(23, process.returncode, errors.decode())
            self.assertEqual(('interrupted', 'signal', signal.SIGTERM),
                             (self.status()['state'], self.status()['reason'], self.status()['signal']))
            self.assert_clean()
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)


class LogReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = pathlib.Path(self.temporary.name) / 'build.log'
        self.path.write_bytes(b'checking fixture compiler\n')
        self.reader = monitor._BMLogReader(str(self.path))
        self.addCleanup(self.reader.close)

    def test_truncate_resets_stage_and_counters(self):
        self.assertEqual('configure', self.reader.sample()[0]['stage'])
        self.path.write_bytes(b'TEST 1/2\n')
        state, changed = self.reader.sample()
        self.assertTrue(changed)
        self.assertTrue(state['log_truncated'])
        self.assertEqual(('tests', 1, 2), (state['stage'], state['test_current'], state['test_total']))

    def test_rotation_follows_original_open_file_and_reports_path_change(self):
        self.reader.sample()
        rotated = self.path.with_suffix('.old')
        self.path.rename(rotated)
        self.path.write_bytes(b'fake replacement\n')
        with rotated.open('ab') as output:
            output.write(b'TEST 2/3\n')
        state, changed = self.reader.sample()
        self.assertTrue(state['log_path_replaced'])
        self.assertTrue(changed)
        self.assertEqual((2, 3), (state['test_current'], state['test_total']))

    def test_split_progress_line_and_packaging_transition(self):
        with self.path.open('ab') as output:
            output.write(b'TEST 4/')
        self.reader.sample()
        with self.path.open('ab') as output:
            output.write(b'12 [private]\r')
        self.assertEqual(12, self.reader.sample()[0]['test_total'])
        with self.path.open('ab') as output:
            output.write(b'Wrote: /private/rpm/path\n')
        state, unused = self.reader.sample()
        self.assertEqual('packaging', state['stage'])
        self.assertIsNone(state['test_total'])
        self.assertNotIn('private', json.dumps(state))

    def test_invalid_test_counts_are_not_reported(self):
        base = {'stage': 'running', 'test_current': None, 'test_total': None}
        for text in (b'TEST 9/2\n', b'TEST 0/2\n', b'TEST 4/0\n'):
            self.assertEqual(base, monitor._bm_parse_progress(text, base))

    def test_silent_remi_libtool_moves_configuration_to_compilation(self):
        self.assertEqual('configure', self.reader.sample()[0]['stage'])
        with self.path.open('ab') as output:
            output.write(b'/bin/sh /private/build-cgi/libtool --silent --preserve-dup-deps '
                         b'--tag=CC --mode=compile cc -std=gnu99 -Iext/snmp/ '
                         b'-c /private/ext/snmp/snmp.c -o ext/snmp/snmp.lo\n')
        state, changed = self.reader.sample()
        self.assertTrue(changed)
        self.assertEqual('compile', state['stage'])
        self.assertNotIn('private', json.dumps(state))
        with self.path.open('ab') as output:
            output.write(b'/bin/sh /private/build-cgi/libtool --silent --mode=link cc -o php\n')
        self.assertEqual('compile', self.reader.sample()[0]['stage'])
        with self.path.open('ab') as output:
            output.write(b'TEST 1/20000\n')
        self.assertEqual('tests', self.reader.sample()[0]['stage'])


if __name__ == '__main__':
    unittest.main()
