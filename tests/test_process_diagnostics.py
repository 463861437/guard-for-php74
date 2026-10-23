"""Process identity/ancestry checks with fake procfs; no host processes touched."""
import errno
import pathlib
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1] / 'src'
guard = types.ModuleType('guard_process_diagnostics')
guard.as_text = str
for name in ('inventory.py', 'service_ops.py'):
    exec(compile((ROOT / name).read_text(), str(ROOT / name), 'exec'), guard.__dict__)


def proc(pid=5000, ppid=1, comm='php', start=100, tty=0):
    return dict(pid=pid, ppid=ppid, comm=comm, state='S',
                tty_nr=tty, start_ticks=start)


def statline(pid=5000, ppid=1, comm='php', start=100, tty=0):
    values = ['S', str(ppid), '0', '0', str(tty)] + ['0'] * 14 + [str(start)]
    return '%s (%s) %s\n' % (pid, comm, ' '.join(values))


class ProcIdentityTests(unittest.TestCase):
    def test_stat_parser_preserves_identity_with_parentheses_in_name(self):
        with mock.patch.object(guard, '_inv_read', return_value=statline(comm='php ) job', tty=34816)):
            result = guard._inv_proc_stat(5000)
        self.assertEqual('php ) job', result['comm'])
        self.assertEqual(100, result['start_ticks'])
        self.assertEqual(1, result['ppid'])
        self.assertEqual(34816, result['tty_nr'])

    def test_malformed_or_wrong_pid_stat_does_not_confirm_identity(self):
        for text in ('', 'broken', statline(pid=5001), statline(start=-1)):
            with self.subTest(text=text), mock.patch.object(guard, '_inv_read', return_value=text):
                self.assertIsNone(guard._inv_proc_stat(5000))

    def test_only_definite_absence_counts_as_exit(self):
        for code, expected in ((errno.ENOENT, True), (errno.ESRCH, True),
                               (errno.EACCES, False), (errno.EIO, False)):
            with self.subTest(code=code), mock.patch.object(guard.os, 'stat', side_effect=OSError(code, 'fixture')):
                self.assertEqual(expected, guard._inv_proc_absent(5000))

    def test_verified_cron_ancestry_contains_no_argv_or_environment(self):
        files = {'/proc/4000/stat': statline(4000, 3000, 'sh'),
                 '/proc/3000/stat': statline(3000, 1, 'crond'),
                 '/proc/1/stat': statline(1, 0, 'systemd')}

        def read(path, limit=65536):
            self.assertTrue(path.endswith('/stat'), 'unexpected sensitive procfs read')
            return files.get(path)

        with mock.patch.object(guard, '_inv_read', side_effect=read):
            result = guard._inv_process_lifecycle(proc(ppid=4000))
        self.assertEqual('cron', result['origin'])
        self.assertTrue(result['ancestry_complete'])
        self.assertEqual([4000, 3000, 1], [item['pid'] for item in result['ancestors']])
        self.assertEqual({'pid', 'ppid', 'comm', 'start_ticks'}, set(result['ancestors'][0]))

    def test_terminal_hint_requires_tty_not_just_a_shell_ancestor(self):
        for tty, origin in ((0, 'unknown'), (34816, 'terminal')):
            with self.subTest(tty=tty), mock.patch.object(guard, '_inv_proc_stat', return_value=proc(1, 0, 'bash', tty=tty)):
                result = guard._inv_process_lifecycle(proc(ppid=1))
            self.assertEqual(origin, result['origin'])

    def test_reused_ancestor_is_not_presented_as_verified_origin(self):
        records = [proc(1, 0, 'crond', 10), proc(1, 0, 'crond', 11)]
        with mock.patch.object(guard, '_inv_proc_stat', side_effect=records):
            result = guard._inv_process_lifecycle(proc(ppid=1))
        self.assertEqual('unknown', result['origin'])
        self.assertEqual([], result['ancestors'])
        self.assertFalse(result['ancestry_complete'])

    def test_inspector_pid_is_never_a_php_runtime(self):
        with mock.patch.object(guard.os, 'listdir', return_value=['5000']), \
             mock.patch.object(guard.os, 'getpid', return_value=5000), \
             mock.patch.object(guard, '_inv_read') as read:
            self.assertEqual([], guard._inv_processes([], []))
        read.assert_not_called()

    def test_process_confirmed_exited_during_inventory_is_omitted(self):
        with mock.patch.object(guard.os, 'listdir', return_value=['5000']), \
             mock.patch.object(guard.os, 'getpid', return_value=9999), \
             mock.patch.object(guard.os, 'readlink', return_value='/usr/bin/php (deleted)'), \
             mock.patch.object(guard, '_inv_read', return_value='php'), \
             mock.patch.object(guard, '_inv_proc_stat', side_effect=[proc(ppid=0), None]), \
             mock.patch.object(guard, '_inv_proc_absent', return_value=True):
            self.assertEqual([], guard._inv_processes([], []))

    def test_exit_after_exe_read_before_first_stat_is_also_omitted(self):
        with mock.patch.object(guard.os, 'listdir', return_value=['5000']), \
             mock.patch.object(guard.os, 'getpid', return_value=9999), \
             mock.patch.object(guard.os, 'readlink', return_value='/usr/bin/php'), \
             mock.patch.object(guard, '_inv_read', return_value='php'), \
             mock.patch.object(guard, '_inv_proc_stat', return_value=None), \
             mock.patch.object(guard, '_inv_proc_absent', return_value=True):
            self.assertEqual([], guard._inv_processes([], []))

    def test_unreadable_initial_identity_is_not_treated_as_exit(self):
        with mock.patch.object(guard.os, 'listdir', return_value=['5000']), \
             mock.patch.object(guard.os, 'getpid', return_value=9999), \
             mock.patch.object(guard.os, 'readlink', return_value='/usr/bin/php'), \
             mock.patch.object(guard, '_inv_read', return_value='php'), \
             mock.patch.object(guard, '_inv_proc_stat', return_value=None), \
             mock.patch.object(guard, '_inv_proc_absent', return_value=False), \
             mock.patch.object(guard.os, 'stat', side_effect=OSError(errno.EACCES, 'fixture')):
            result = guard._inv_processes([], [])
        self.assertEqual(1, len(result))
        self.assertIsNone(result[0]['version'])
        self.assertNotIn('start_ticks', result[0])

    def test_pid_reuse_during_inventory_marks_coverage_incomplete(self):
        warnings = []
        with mock.patch.object(guard.os, 'listdir', return_value=['5000']), \
             mock.patch.object(guard.os, 'getpid', return_value=9999), \
             mock.patch.object(guard.os, 'readlink', return_value='/usr/bin/php (deleted)'), \
             mock.patch.object(guard, '_inv_read', return_value='php'), \
             mock.patch.object(guard, '_inv_proc_stat', side_effect=[proc(ppid=0), proc(ppid=0, start=101)]):
            self.assertEqual([], guard._inv_processes([], warnings))
        self.assertTrue(any('incomplete' in item for item in warnings))


class ProcessPreflightTests(unittest.TestCase):
    def setUp(self):
        self.process = dict(pid=5000, comm='php', exe='/usr/bin/php', service=None,
                            start_ticks=100, ppid=4000, parent_comm='sh',
                            lifecycle={'origin': 'cron', 'ancestors': [], 'ancestry_complete': True})
        tool = mock.patch.object(guard, '_inv_tool', return_value='/usr/bin/systemctl')
        tool.start()
        self.addCleanup(tool.stop)

    def preflight(self, current, absent=False):
        with mock.patch.object(guard, '_inv_proc_stat', return_value=current), \
             mock.patch.object(guard, '_inv_proc_absent', return_value=absent):
            return guard.service_preflight({'processes': [self.process]}, [])

    def test_confirmed_exit_no_longer_blocks_but_is_reported(self):
        result = self.preflight(None, absent=True)
        self.assertEqual([], result['blockers'])
        self.assertEqual('process-exited-before-preflight', result['checks'][0]['check'])

    def test_permission_failure_cannot_be_treated_as_exit(self):
        result = self.preflight(None, absent=False)
        self.assertIn('Cannot revalidate', result['blockers'][0]['reason'])

    def test_reused_pid_requires_new_inventory(self):
        result = self.preflight(proc(start=101))
        self.assertIn('reused', result['blockers'][0]['reason'])

    def test_live_unknown_php_still_blocks_with_actionable_metadata(self):
        result = self.preflight(proc())
        self.assertEqual([], result['services'])
        blocker = result['blockers'][0]
        self.assertIn('no mapped systemd service', blocker['reason'])
        self.assertEqual(5000, blocker['pid'])
        self.assertEqual(4000, blocker['ppid'])
        self.assertEqual('sh', blocker['parent_comm'])
        self.assertEqual('cron', blocker['lifecycle']['origin'])

    def test_supervisor_hint_does_not_automatically_select_entire_service(self):
        self.process['service'] = 'supervisord.service'
        self.process['lifecycle']['origin'] = 'supervisor'
        result = self.preflight(proc())
        self.assertEqual([], result['services'])
        self.assertEqual('supervisord.service', result['blockers'][0]['service'])
        self.assertIn('explicitly select', result['blockers'][0]['reason'])

    def test_legacy_snapshot_without_identity_remains_conservative(self):
        del self.process['start_ticks']
        result = self.preflight(None, absent=True)
        self.assertTrue(result['blockers'])
        self.assertEqual([], result['checks'])


class ResidualIdentityTests(unittest.TestCase):
    def check(self, old_ticks, new_ticks, deleted=False):
        old = dict(pid=5000, exe='/usr/bin/php', comm='php',
                   service='job.service', start_ticks=old_ticks)
        new = dict(old, start_ticks=new_ticks, deleted=deleted)
        return guard.residual_process_check({'processes': [old]}, {'processes': [new]},
                                            services=['job.service'])

    def test_reused_pid_with_same_executable_is_a_new_process(self):
        self.assertTrue(self.check(100, 101)['ok'])

    def test_same_start_time_still_proves_old_process_survived(self):
        result = self.check(100, 100)
        self.assertFalse(result['ok'])
        self.assertIn('survived', result['errors'][0]['reason'])

    def test_missing_identity_on_either_side_stays_conservative(self):
        for before, after in ((None, 101), (100, None), (None, None)):
            with self.subTest(before=before, after=after):
                self.assertFalse(self.check(before, after)['ok'])

    def test_new_pid_identity_does_not_excuse_deleted_binary(self):
        result = self.check(100, 101, deleted=True)
        self.assertFalse(result['ok'])
        self.assertEqual('Process still uses a deleted executable', result['errors'][0]['reason'])


if __name__ == '__main__':
    unittest.main()
