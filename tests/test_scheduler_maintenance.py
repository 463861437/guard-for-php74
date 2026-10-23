"""Cron maintenance evidence and restoration tests; no host signals or units."""
import copy
import errno
import pathlib
import signal
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1] / 'src'
guard = types.ModuleType('scheduler_maintenance_test_module')
guard.as_text = str
guard.run_cmd = mock.Mock()
guard.write_json = mock.Mock()
for filename in ('inventory.py', 'service_ops.py', 'scheduler_maintenance.py'):
    exec(compile((ROOT / filename).read_text(), str(ROOT / filename), 'exec'), guard.__dict__)


def proc(pid=100, parent=1, comm='crond', ticks=10, state='S'):
    return dict(pid=pid, ppid=parent, comm=comm, start_ticks=ticks, state=state)


def group(name='/system.slice/crond.service'):
    return dict(version=1, relative=name, path='/sys/fs/cgroup/systemd' + name)


def props(active='active'):
    return dict(Id='crond.service', LoadState='loaded', ActiveState=active,
                SubState='running' if active == 'active' else 'dead',
                MainPID='100' if active == 'active' else '0', KillMode='process',
                KillSignal='15', SendSIGHUP='no', ExecStartPre='', ExecStartPost='',
                ExecStop='', ExecStopPost='', RootDirectory='', RootImage='', User='',
                ControlGroup='/system.slice/crond.service',
                ExecStart='{ path=/usr/sbin/crond ; argv[]=/usr/sbin/crond -n ; }')


def service(active=True):
    return dict(name='crond.service', active=active, executable='/usr/sbin/crond',
                main=proc() if active else None, group=group() if active else None,
                properties=props('active' if active else 'inactive'))


def plan(active=True):
    return dict(ok=True, services=[service(active)], systemctl='/usr/bin/systemctl',
                covered_processes=[dict(pid=200, start_ticks=20)] if active else [])


class SchedulerValidationTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        self.properties = props()
        mock.patch.object(guard, '_sm_show', side_effect=lambda *a: self.properties).start()
        mock.patch.object(guard, '_inv_trusted_executable', return_value=(True, None)).start()
        mock.patch.object(guard, '_sm_identity', return_value=proc()).start()
        mock.patch.object(guard, '_sm_host_namespace').start()
        mock.patch.object(guard.os, 'stat', return_value=types.SimpleNamespace(st_uid=0, st_dev=1, st_ino=2)).start()
        mock.patch.object(guard.os, 'readlink', return_value='/usr/sbin/crond').start()
        mock.patch.object(guard, '_sm_group', return_value=group()).start()
        mock.patch.object(guard, '_sm_group_members', return_value={100}).start()

    def validate(self):
        return guard._sm_validate('/usr/bin/systemctl', 'crond.service')

    def test_standard_cronie_unit_is_accepted(self):
        result = self.validate()
        self.assertEqual((100, 10), guard._sm_key(result['main']))
        self.assertTrue(result['active'])

    def test_exact_scheduler_names_only(self):
        for name in ('cron', 'crond', 'php-fpm.service', 'cron@root.service', 'other.service'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                guard._sm_validate('/usr/bin/systemctl', name)

    def test_alias_namespace_hooks_and_cgroup_kill_are_blocked(self):
        changes = dict(Id='alias.service', LoadState='not-found', ActiveState='activating',
                       KillMode='control-group', KillSignal='9', SendSIGHUP='yes',
                       ExecStop='/bin/custom', ExecStopPost='/bin/custom',
                       ExecStartPre='/bin/custom', ExecStartPost='/bin/custom',
                       RootDirectory='/chroot', RootImage='/image', User='apache',
                       ExecStart='{ path=/tmp/crond ; argv[]=/tmp/crond ; }')
        for key, value in changes.items():
            with self.subTest(key=key):
                self.properties = props()
                self.properties[key] = value
                with self.assertRaises(ValueError):
                    self.validate()

    def test_standard_systemd_argument_variables_are_not_executed_or_logged(self):
        self.properties['ExecStart'] = '{ path=/usr/sbin/crond ; argv[]=/usr/sbin/crond -n $CRONDARGS ; }'
        result = self.validate()
        self.assertNotIn('ExecStart', result['properties'])
        self.assertEqual(64, len(result['properties']['ExecStartSHA256']))
        self.assertNotIn('CRONDARGS', str(result))

    def test_inactive_scheduler_never_needs_a_process_signal(self):
        self.properties = props('inactive')
        result = self.validate()
        self.assertFalse(result['active'])
        self.assertIsNone(result['main'])
        guard._sm_identity.assert_not_called()

    def test_scheduler_already_frozen_is_not_claimed_by_tool(self):
        guard._sm_identity.return_value = proc(state='T')
        with self.assertRaises(ValueError):
            self.validate()

    def test_deleted_or_untrusted_binary_is_rejected(self):
        guard.os.readlink.return_value = '/usr/sbin/crond (deleted)'
        with self.assertRaises(ValueError):
            self.validate()
        guard.os.readlink.return_value = '/usr/sbin/crond'
        guard._inv_trusted_executable.return_value = (False, 'fixture')
        with self.assertRaises(ValueError):
            self.validate()

    def test_reused_main_pid_is_rejected(self):
        guard._sm_identity.side_effect = [proc(), proc(ticks=11)]
        with self.assertRaises(ValueError):
            self.validate()

    def test_container_or_namespace_failure_is_not_suppressed(self):
        guard._sm_host_namespace.side_effect = ValueError('separate namespace')
        with self.assertRaises(ValueError):
            self.validate()


class SchedulerPropertyTests(unittest.TestCase):
    def test_systemd_219_empty_command_arrays_are_verified_individually(self):
        properties = props()
        omitted = ('RootImage', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost')
        output = '\n'.join(key + '=' + value for key, value in properties.items() if key not in omitted)
        def command(argv, timeout=30):
            if argv[-1] == '--all':
                return dict(code=0, stdout=output, stderr='')
            self.assertIn(argv[-1], ['--property=' + key for key in omitted[1:]])
            return dict(code=0, stdout='', stderr='')
        with mock.patch.object(guard, 'run_cmd', side_effect=command):
            result = guard._sm_show('/usr/bin/systemctl', 'crond.service')
        self.assertEqual('', result['ExecStop'])
        self.assertEqual('', result['ExecStopPost'])

    def test_missing_required_property_does_not_default_to_safe(self):
        output = '\n'.join(key + '=' + value for key, value in props().items() if key != 'SendSIGHUP')
        with mock.patch.object(guard, 'run_cmd', return_value=dict(code=0, stdout=output)), self.assertRaises(ValueError):
            guard._sm_show('/usr/bin/systemctl', 'crond.service')

    def test_known_v1_and_v2_cgroup_paths_are_parsed_as_data(self):
        for raw, version in [('1:name=systemd:/system.slice/crond.service\n', 1),
                             ('0::/user.slice/user-0.slice/session-c1.scope\n', 2)]:
            with self.subTest(version=version), mock.patch.object(guard, '_inv_read', return_value=raw):
                result = guard._sm_group(100)
                self.assertEqual(version, result['version'])
        with mock.patch.object(guard, '_inv_read', return_value='1:name=systemd:/../../tmp/fixture\n'), self.assertRaises(ValueError):
            guard._sm_group(100)

    def test_subgroup_normalizes_to_narrow_session_boundary(self):
        nested = group('/user.slice/user-0.slice/session-c1.scope/job/child')
        boundary = guard._sm_scope(nested, '/system.slice/crond.service')
        self.assertEqual('/user.slice/user-0.slice/session-c1.scope', boundary['relative'])
        self.assertEqual('/sys/fs/cgroup/systemd/user.slice/user-0.slice/session-c1.scope', boundary['path'])
        self.assertIsNone(guard._sm_scope(group('/user.slice/user-0.slice'), '/system.slice/crond.service'))


class SchedulerPlanTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(guard, '_inv_tool', return_value='/usr/bin/systemctl').start()
        mock.patch.object(guard, '_sm_validate', return_value=service()).start()
        mock.patch.object(guard, '_sm_descends', side_effect=lambda p, main: p['pid'] == 200).start()
        mock.patch.object(guard, '_sm_group', return_value=group('/user.slice/user-0.slice/session-c1.scope')).start()
        mock.patch.object(guard, '_sm_group_members', return_value={200}).start()
        self.command = mock.patch.object(guard, 'run_cmd').start()
        self.processes = [dict(pid=200, start_ticks=20, comm='php', exe='/usr/bin/php'),
                          dict(pid=300, start_ticks=30, comm='php', exe='/usr/bin/php',
                               lifecycle={'origin': 'cron', 'ancestors': [proc()]})]

    def test_only_verified_ancestry_is_pending_even_with_spoofed_hint(self):
        result = guard.sm_plan({'processes': self.processes}, ['crond.service'])
        self.assertTrue(result['ok'], result)
        self.assertEqual([200], result['pending_pids'])
        self.assertEqual(20, result['covered_processes'][0]['start_ticks'])
        self.command.assert_not_called()

    def test_broad_user_slice_is_not_accepted_as_job_scope(self):
        guard._sm_group.return_value = group('/user.slice/user-0.slice')
        result = guard.sm_plan({'processes': self.processes}, ['crond.service'])
        self.assertFalse(result['ok'])
        self.assertEqual([], result['covered_processes'])

    def test_permission_failure_blocks_without_dropping_process(self):
        guard._sm_group_members.side_effect = OSError(errno.EACCES, 'fixture')
        result = guard.sm_plan({'processes': self.processes}, ['crond.service'])
        self.assertFalse(result['ok'])
        self.assertTrue(result['blockers'])

    def test_empty_request_and_inactive_scheduler_do_not_cover_jobs(self):
        self.assertTrue(guard.sm_plan({}, [])['ok'])
        guard._sm_validate.return_value = service(False)
        result = guard.sm_plan({'processes': self.processes}, ['crond.service'])
        self.assertTrue(result['ok'])
        self.assertEqual([], result['pending_pids'])


class SchedulerProcessTests(unittest.TestCase):
    def test_identity_permission_error_is_not_process_exit(self):
        with mock.patch.object(guard, '_inv_proc_stat', return_value=None), \
             mock.patch.object(guard, '_inv_proc_absent', return_value=False), \
             self.assertRaises(ValueError):
            guard._sm_identity(100)

    def test_reused_pid_is_never_signaled(self):
        with mock.patch.object(guard, '_sm_identity', return_value=proc(ticks=11)), \
             mock.patch.object(guard.os, 'kill') as kill, self.assertRaises(ValueError):
            guard._sm_signal(proc(), signal.SIGCONT)
        kill.assert_not_called()

    def test_exited_process_does_not_receive_signal(self):
        with mock.patch.object(guard, '_sm_identity', return_value=None), \
             mock.patch.object(guard.os, 'kill') as kill:
            self.assertFalse(guard._sm_signal(proc(), signal.SIGCONT))
        kill.assert_not_called()

    def test_scope_tracks_reparented_grandchild_after_shell_exit(self):
        shell = proc(200, 100, 'sh', 20)
        grandchild = proc(300, 1, 'sleep', 30)
        records = {100: proc(), 300: grandchild}
        scoped = group('/user.slice/user-0.slice/session-c1.scope')
        tracked = {(200, 20): shell}
        groups = {scoped['path']: scoped}
        with mock.patch.object(guard, '_sm_identity', side_effect=lambda p: records.get(p)), \
             mock.patch.object(guard, '_sm_group', return_value=scoped), \
             mock.patch.object(guard, '_sm_group_members', side_effect=lambda g: {100} if g == group() else {300}):
            alive = guard._sm_capture(service(), records, tracked, groups)
        self.assertEqual([(300, 30)], [guard._sm_key(p) for p in alive])
        self.assertIn((300, 30), tracked)

    def test_pid_reuse_means_old_job_exited_not_new_process_owned(self):
        old = proc(200, 1, 'sh', 20)
        replacement = proc(200, 1, 'unrelated', 99)
        with mock.patch.object(guard, '_sm_identity', return_value=replacement), \
             mock.patch.object(guard, '_sm_group_members', return_value=set()):
            alive = guard._sm_capture(service(), {200: replacement}, {(200, 20): old}, {})
        self.assertEqual([], alive)

    def test_scope_escape_blocks_instead_of_losing_reparented_job(self):
        job = proc(200, 1, 'sh', 20)
        with mock.patch.object(guard, '_sm_identity', return_value=job), \
             mock.patch.object(guard, '_sm_group', return_value=group('/user.slice/user-0.slice')), \
             mock.patch.object(guard, '_sm_group_members', return_value=set()), self.assertRaises(ValueError):
            guard._sm_capture(service(), {200: job}, {(200, 20): job}, {})


class SchedulerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        self.validate = mock.patch.object(guard, '_sm_validate', return_value=service()).start()
        self.show = mock.patch.object(guard, '_sm_show', return_value=props('inactive')).start()
        self.identity = mock.patch.object(guard, '_sm_identity', side_effect=[proc(state='T'), None]).start()
        self.signals = mock.patch.object(guard, '_sm_signal', return_value=True).start()
        self.snapshots = mock.patch.object(guard, '_sm_snapshot', return_value={}).start()
        self.capture = mock.patch.object(guard, '_sm_capture', return_value=[]).start()
        self.commands = mock.patch.object(guard, 'run_cmd', return_value=dict(code=0, stdout='', stderr='')).start()
        self.inventory = mock.patch.object(guard, 'collect_inventory', return_value=dict(processes=[], warnings=[])).start()
        self.save = mock.patch.object(guard, '_sm_save').start()
        mock.patch.object(guard.time, 'sleep').start()

    def enter(self):
        return guard.sm_enter(plan(), ['/srv/php'], 3, '/report/maintenance.json')

    def test_success_pauses_only_main_and_defers_restore_to_caller(self):
        result = self.enter()
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['entered'])
        self.assertTrue(result['stopped'][0]['restore_required'])
        self.inventory.assert_called_once_with(['/srv/php'])
        self.assertEqual([mock.call(proc(), signal.SIGSTOP)], self.signals.call_args_list)
        self.commands.assert_called_once_with(['/usr/bin/systemctl', 'stop', '--no-block', 'crond.service'], timeout=30)
        self.assertGreaterEqual(self.save.call_count, 3)

    def test_unit_identity_change_never_stops(self):
        altered = service()
        altered['main']['start_ticks'] = 99
        self.validate.return_value = altered
        result = self.enter()
        self.assertFalse(result['ok'])
        self.signals.assert_not_called()
        self.commands.assert_not_called()

    def test_capture_permission_failure_thaws_main_without_stopping(self):
        self.capture.side_effect = OSError(errno.EACCES, 'fixture')
        result = self.enter()
        self.assertFalse(result['ok'])
        self.assertTrue(result['recovery']['ok'])
        self.assertEqual(signal.SIGCONT, self.signals.call_args_list[-1].args[1])
        self.commands.assert_not_called()

    def test_stop_failure_recovers_and_does_not_run_inventory(self):
        self.commands.side_effect = [dict(code=1, stdout='', stderr='fixture'), dict(code=0, stdout='', stderr='')]
        result = self.enter()
        self.assertFalse(result['ok'])
        self.assertTrue(result['recovery']['ok'], result)
        self.inventory.assert_not_called()
        self.assertFalse(result['stopped'][0]['restore_required'])

    def test_timeout_does_not_kill_jobs_and_restores_scheduler(self):
        self.capture.return_value = [proc(200, 1, 'sleep', 20)]
        with mock.patch.object(guard, '_sm_clock', side_effect=[0, 0, 10]):
            result = self.enter()
        self.assertFalse(result['ok'])
        self.assertTrue(any('did not finish' in error for error in result['errors']), result)
        self.assertEqual({signal.SIGSTOP, signal.SIGCONT}, {call.args[1] for call in self.signals.call_args_list})
        self.assertTrue(result['recovery']['ok'])

    def test_post_drain_unknown_php_process_blocks_install(self):
        self.inventory.return_value = dict(warnings=[], processes=[dict(pid=800, start_ticks=80, comm='php', service=None)])
        result = self.enter()
        self.assertFalse(result['ok'])
        self.assertTrue(any('unmapped' in error for error in result['errors']))
        self.assertTrue(result['recovery']['ok'])

    def test_incomplete_post_drain_inventory_is_not_success(self):
        self.inventory.return_value = dict(warnings=['/proc unavailable; process inventory incomplete.'], processes=[])
        result = self.enter()
        self.assertFalse(result['ok'])
        self.assertTrue(result['recovery']['ok'])

    def test_zero_wait_checks_once_without_sleeping(self):
        with mock.patch.object(guard, '_sm_clock', side_effect=[0, 0, 0]):
            result = guard.sm_enter(plan(), [], 0, None)
        self.assertTrue(result['ok'], result)
        guard.time.sleep.assert_not_called()

    def test_plan_scopes_are_tracked_before_first_snapshot(self):
        expected = group('/user.slice/user-0.slice/session-c1.scope')
        selected = plan()
        selected['services'][0]['job_groups'] = [expected]
        result = guard.sm_enter(selected, [], 3, None)
        self.assertTrue(result['ok'], result)
        for call in self.capture.call_args_list:
            self.assertEqual(expected, call.args[3][expected['path']])

    def test_inactive_scheduler_is_never_started(self):
        self.validate.return_value = service(False)
        result = guard.sm_enter(plan(False), [], 3, None)
        self.assertTrue(result['ok'])
        self.assertTrue(guard.sm_exit(result)['ok'])
        self.commands.assert_not_called()
        self.signals.assert_not_called()

    def test_recovery_queues_start_while_stop_is_still_deactivating(self):
        result = self.enter()
        transition = service()
        transition['active'] = False
        transition['properties']['ActiveState'] = 'deactivating'
        self.validate.side_effect = [transition, service()]
        recovered = guard.sm_exit(result)
        self.assertTrue(recovered['ok'], recovered)
        self.commands.assert_called_with(['/usr/bin/systemctl', 'start', 'crond.service'], timeout=60)

    def test_recovery_failure_stays_visible_and_can_be_retried(self):
        result = self.enter()
        self.validate.return_value = service(False)
        self.commands.return_value = dict(code=1, stdout='', stderr='fixture')
        recovery = guard.sm_exit(result)
        self.assertFalse(recovery['ok'])
        self.assertFalse(result['ok'])
        self.assertTrue(result['stopped'][0]['restore_required'])
        self.assertIn('systemctl start crond.service', recovery['errors'][0]['recovery_command'])
        self.commands.return_value = dict(code=0, stdout='', stderr='')
        self.validate.side_effect = [service(False), service()]
        self.assertTrue(guard.sm_exit(result)['ok'])
        count = self.commands.call_count
        self.assertTrue(guard.sm_exit(result)['ok'])
        self.assertEqual(count, self.commands.call_count)

    def test_final_journal_failure_restores_and_cannot_authorize_install(self):
        failed = []
        def save(state):
            if state['ok'] and not failed:
                failed.append(True)
                raise OSError(errno.EIO, 'temporary final journal failure')
        self.save.side_effect = save
        result = self.enter()
        self.assertFalse(result['ok'], result)
        self.assertFalse(result['entered'])
        self.assertTrue(result['recovery']['ok'], result)
        self.assertFalse(result['stopped'][0]['restore_required'])
        self.assertEqual(['stop', 'start'], [call.args[0][1] for call in self.commands.call_args_list])

    def test_unexpected_recovery_exception_preserves_state_for_finally_retry(self):
        self.capture.side_effect = ValueError('capture fixture failure')
        with mock.patch.object(guard, 'sm_exit', side_effect=TypeError('recovery fixture failure')):
            result = self.enter()
        self.assertFalse(result['ok'])
        self.assertFalse(result['entered'])
        self.assertFalse(result['recovery']['ok'])
        self.assertIn('recovery fixture failure', result['recovery']['errors'][0]['reason'])
        self.assertTrue(result['frozen'], 'must preserve identities for the outer finally retry')

    def test_recovery_serialization_failure_returns_visible_failure(self):
        result = self.enter()
        self.save.side_effect = TypeError('serialization fixture failure')
        recovered = guard.sm_exit(result)
        self.assertFalse(recovered['ok'])
        self.assertFalse(result['ok'])
        self.assertIn('serialization fixture failure', recovered['errors'][0]['reason'])

    def test_report_failure_after_pause_still_restores(self):
        self.save.side_effect = [None, None, OSError(errno.EIO, 'fixture'), None, None]
        result = self.enter()
        self.assertFalse(result['ok'])
        self.assertTrue(result['recovery']['ok'])
        self.assertEqual(signal.SIGCONT, self.signals.call_args_list[-1].args[1])


if __name__ == '__main__':
    unittest.main()
