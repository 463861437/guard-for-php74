"""Maintenance is explicit, bounded, restored, and never weakens service checks."""
import copy
import pathlib
import signal
import tempfile
import types
import unittest
from unittest import mock

import test_oneclick as fixtures

guard = fixtures.guard


def cron_process(pid=536, start_ticks=100):
    return dict(pid=pid, start_ticks=start_ticks, ppid=535, comm='php',
                exe='/usr/bin/php', service=None,
                lifecycle=dict(origin='cron', ancestry_complete=True, ancestors=[]))


def scheduler_plan(processes=None):
    return dict(ok=True, requested=['crond.service'], services=['crond.service'],
                covered_processes=processes or [], blockers=[], errors=[])


def unmapped(process=None):
    process = process or cron_process()
    return dict(process, reason='PHP process PID %s has no mapped systemd service; '
                'manual lifecycle handling is required' % process['pid'])


class MaintenanceWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(pathlib.Path(self.temp.name) / 'oneclick.json')
        self.inv = fixtures.inventory()
        self.args = types.SimpleNamespace(pause_scheduler=['crond.service'],
            drain_wait=17, scan_root=['/opt/php'], service=['worker.service'])
        self.preflight = dict(services=['php-fpm.service', 'worker.service'], blockers=[], checks=[])
        self.report = dict(inventory_before=copy.deepcopy(self.inv),
            service_preflight=copy.deepcopy(self.preflight), selected_route='al2',
            repository_plan=dict(updates=[], blockers=[dict(reason='source build required')]))
        self.state = dict(ok=True, inventory=copy.deepcopy(self.inv), errors=[])
        self.mocks = {}
        for name, value in dict(collect_inventory=copy.deepcopy(self.inv),
                sm_plan=scheduler_plan(), sm_enter=self.state,
                sm_exit=dict(ok=True, errors=[]), service_preflight=self.preflight,
                write_json=None, say=None).items():
            patch = mock.patch.object(guard, name, return_value=value, create=True)
            self.mocks[name] = patch.start()
            self.addCleanup(patch.stop)
        self.action = mock.Mock(return_value=0)

    def run_action(self):
        return guard.oc_maintenance_run(self.args, self.report, self.path, self.action)

    def test_without_explicit_scheduler_no_scheduler_or_extra_scan_is_used(self):
        self.args.pause_scheduler = []
        self.action.return_value = 10
        self.assertEqual(10, self.run_action())
        self.action.assert_called_once_with()
        for name in ('collect_inventory', 'sm_plan', 'sm_enter', 'sm_exit'):
            self.mocks[name].assert_not_called()

    def test_success_enters_before_action_and_restores_after_it(self):
        calls = []
        self.mocks['sm_enter'].side_effect = lambda *a, **k: calls.append('enter') or self.state
        self.action.side_effect = lambda: calls.append('deploy') or 0
        self.mocks['sm_exit'].side_effect = lambda *a, **k: calls.append('restore') or dict(ok=True, errors=[])
        self.assertEqual(0, self.run_action())
        self.assertEqual(['enter', 'deploy', 'restore'], calls)
        self.assertEqual([mock.call(['/opt/php']), mock.call(['/opt/php'])],
                         self.mocks['collect_inventory'].call_args_list)
        self.assertIn('maintenance.json', str(self.mocks['sm_enter'].call_args))
        self.assertIn(17, self.mocks['sm_enter'].call_args.args)
        self.mocks['service_preflight'].assert_called_once()
        self.assertEqual(self.state['inventory'], self.mocks['service_preflight'].call_args.args[0])
        self.assertEqual(['worker.service'], self.mocks['service_preflight'].call_args.args[2])

    def test_unsatisfied_pause_plan_never_enters_or_deploys(self):
        self.mocks['sm_plan'].return_value = dict(ok=False, blockers=[dict(reason='unknown scheduler')], errors=['unknown scheduler'])
        self.assertNotEqual(0, self.run_action())
        self.mocks['sm_enter'].assert_not_called()
        self.action.assert_not_called()

    def test_drain_timeout_never_deploys_and_cleanup_is_idempotently_requested(self):
        self.state.update(ok=False, errors=['drain timeout'])
        self.assertNotEqual(0, self.run_action())
        self.action.assert_not_called()
        self.mocks['sm_exit'].assert_called_once_with(self.state)

    def test_changed_php_package_identity_never_deploys_after_draining(self):
        for field, value in (('name', 'php-common'), ('arch', 'aarch64'),
                             ('version', '7.4.33-2.amzn2'), ('source', 'php-custom')):
            with self.subTest(field=field):
                self.state['inventory'] = copy.deepcopy(self.inv)
                self.state['inventory']['packages'][0][field] = value
                self.mocks['collect_inventory'].side_effect = [copy.deepcopy(self.inv), self.state['inventory']]
                self.action.reset_mock()
                self.mocks['sm_exit'].reset_mock()
                self.assertNotEqual(0, self.run_action())
                self.action.assert_not_called()
                self.mocks['sm_exit'].assert_called_once_with(self.state)

    def test_removed_or_added_php_package_never_deploys(self):
        added = dict(self.inv['packages'][0], name='php-common')
        for packages in ([], self.inv['packages'] + [added]):
            with self.subTest(packages=packages):
                self.state['inventory'] = copy.deepcopy(self.inv)
                self.state['inventory']['packages'] = packages
                self.mocks['collect_inventory'].side_effect = [copy.deepcopy(self.inv), self.state['inventory']]
                self.action.reset_mock()
                self.assertNotEqual(0, self.run_action())
                self.action.assert_not_called()

    def test_recheck_cannot_ignore_new_unknown_process_or_configuration_failure(self):
        for reason in ('PHP process PID 999 has no mapped systemd service; manual lifecycle handling is required',
                       'PHP-FPM configuration test failed'):
            with self.subTest(reason=reason):
                self.mocks['service_preflight'].return_value = dict(self.preflight, blockers=[dict(reason=reason)])
                self.action.reset_mock()
                self.mocks['sm_exit'].reset_mock()
                self.assertNotEqual(0, self.run_action())
                self.action.assert_not_called()
                self.mocks['sm_exit'].assert_called_once_with(self.state)

    def test_selected_service_set_cannot_expand_or_shrink_after_draining(self):
        for services in (['php-fpm.service'], ['php-fpm.service', 'worker.service', 'new-worker.service']):
            with self.subTest(services=services):
                self.mocks['service_preflight'].return_value = dict(self.preflight, services=services)
                self.action.reset_mock()
                self.assertNotEqual(0, self.run_action())
                self.action.assert_not_called()

    def test_service_order_does_not_change_approved_scope(self):
        self.mocks['service_preflight'].return_value = dict(self.preflight,
            services=list(reversed(self.preflight['services'])))
        self.assertEqual(0, self.run_action())
        self.action.assert_called_once()

    def test_nonzero_install_result_is_preserved_and_scheduler_is_restored(self):
        self.action.return_value = 10
        self.assertEqual(10, self.run_action())
        self.mocks['sm_exit'].assert_called_once_with(self.state)

    def test_install_exception_still_restores_scheduler(self):
        self.action.side_effect = RuntimeError('install raised')
        try:
            code = self.run_action()
        except RuntimeError as exc:
            self.assertEqual('install raised', str(exc))
        else:
            self.assertNotEqual(0, code)
        self.mocks['sm_exit'].assert_called_once_with(self.state)

    def test_restore_failure_never_reports_success_and_preserves_deployment_result(self):
        def deploy():
            self.report['result'] = 'fixed_within_scope'
            return 0
        self.action.side_effect = deploy
        self.mocks['sm_exit'].return_value = dict(ok=False, errors=['crond failed to resume'])
        self.assertEqual(20, self.run_action())
        self.assertEqual('maintenance_restore_failed', self.report['result'])
        self.assertEqual('fixed_within_scope', self.report['deployment_result'])

    def test_restore_exception_is_a_failed_result_not_a_successful_deployment(self):
        self.mocks['sm_exit'].side_effect = RuntimeError('resume failed')
        self.assertEqual(20, self.run_action())
        self.assertEqual('maintenance_restore_failed', self.report['result'])

    def test_recheck_exception_still_restores_without_installing(self):
        self.mocks['service_preflight'].side_effect = RuntimeError('service inspection failed')
        self.assertNotEqual(0, self.run_action())
        self.action.assert_not_called()
        self.mocks['sm_exit'].assert_called_once_with(self.state)

    def test_signal_received_during_package_action_is_deferred_until_restore(self):
        handlers = {}
        def install_handler(number, handler):
            handlers[number] = handler
            return signal.SIG_DFL
        def deploy():
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            self.report['result'] = 'fixed_within_scope'
            return 0
        self.action.side_effect = deploy
        with mock.patch('signal.signal', side_effect=install_handler):
            self.assertNotEqual(0, self.run_action())
        self.action.assert_called_once()
        self.mocks['sm_exit'].assert_called_once_with(self.state)

    def test_signal_during_enter_prevents_package_action_but_restores(self):
        handlers = {}
        def install_handler(number, handler):
            handlers[number] = handler
            return signal.SIG_DFL
        def enter(*args, **kwargs):
            handlers[signal.SIGINT](signal.SIGINT, None)
            return self.state
        self.mocks['sm_enter'].side_effect = enter
        with mock.patch('signal.signal', side_effect=install_handler):
            self.assertNotEqual(0, self.run_action())
        self.action.assert_not_called()
        self.mocks['sm_exit'].assert_called_once_with(self.state)

    def test_signal_during_final_preflight_prevents_starting_a_package_action(self):
        handlers = {}
        def install_handler(number, handler):
            handlers[number] = handler
            return signal.SIG_DFL
        def recheck(*args, **kwargs):
            handlers[signal.SIGHUP](signal.SIGHUP, None)
            return self.preflight
        self.mocks['service_preflight'].side_effect = recheck
        with mock.patch('signal.signal', side_effect=install_handler):
            self.assertNotEqual(0, self.run_action())
        self.action.assert_not_called()
        self.mocks['sm_exit'].assert_called_once_with(self.state)


class MaintenancePlanningTests(unittest.TestCase):
    setUp = fixtures.OneclickTests.setUp
    run_main = fixtures.OneclickTests.run_main

    def prepare_cron(self):
        process = cron_process()
        self.inv['processes'] = [process]
        self.mocks['service_preflight'].return_value = dict(services=['php-fpm.service'],
            blockers=[unmapped(process)], checks=[])
        return process

    def test_plan_only_defers_the_exact_declared_scheduler_process(self):
        process = self.prepare_cron()
        with mock.patch.object(guard, 'sm_plan', return_value=scheduler_plan([process]), create=True), \
             mock.patch.object(guard, 'sm_enter', create=True) as enter:
            code, report = self.run_main(['plan', '--yes', '--pause-scheduler', 'crond.service'])
        self.assertEqual(0, code)
        self.assertEqual('route_plan_ready', report['result'])
        enter.assert_not_called()
        self.mocks['oc_source_apply'].assert_not_called()
        self.mocks['execute_repair'].assert_not_called()

    def test_same_pid_with_different_start_time_does_not_bypass_service_blocker(self):
        process = self.prepare_cron()
        wrong_identity = dict(process, start_ticks=process['start_ticks'] + 1)
        with mock.patch.object(guard, 'sm_plan', return_value=scheduler_plan([wrong_identity]), create=True), \
             mock.patch.object(guard, 'sm_enter', create=True) as enter:
            code, report = self.run_main(['--yes', '--pause-scheduler', 'crond.service'])
        self.assertEqual(10, code)
        self.assertEqual('blocked_services', report['result'])
        enter.assert_not_called()
        self.mocks['oc_source_apply'].assert_not_called()

    def test_job_in_explicit_scheduler_service_can_be_drained_without_restarting_it_as_php(self):
        process = self.prepare_cron()
        process['service'] = 'crond.service'
        self.mocks['service_preflight'].return_value['blockers'] = [dict(process,
            reason='Long-running PHP process PID 536 is not covered; explicitly select its service with --service')]
        with mock.patch.object(guard, 'sm_plan', return_value=scheduler_plan([process]), create=True):
            code, report = self.run_main(['plan', '--pause-scheduler', 'crond.service'])
        self.assertEqual(0, code)
        self.assertEqual(['php-fpm.service'], report['service_preflight']['services'])
        self.assertEqual(1, len(report['service_preflight']['pending_scheduler_drain']))

    def test_scheduler_scope_does_not_cover_supervisor_or_configuration_failures(self):
        process = self.prepare_cron()
        for service, reason in (
                ('supervisord.service', 'Long-running PHP process PID 536 is not covered; explicitly select its service with --service'),
                ('crond.service', 'PHP-FPM configuration test failed')):
            with self.subTest(service=service, reason=reason):
                self.mocks['service_preflight'].return_value['blockers'] = [dict(process, service=service, reason=reason)]
                with mock.patch.object(guard, 'sm_plan', return_value=scheduler_plan([process]), create=True):
                    code, report = self.run_main(['plan', '--pause-scheduler', 'crond.service'])
                self.assertEqual(10, code)

    def test_unknown_process_is_not_covered_just_because_another_process_is_cron(self):
        self.prepare_cron()
        with mock.patch.object(guard, 'sm_plan', return_value=scheduler_plan([cron_process(pid=999)]), create=True):
            code, report = self.run_main(['--yes', '--pause-scheduler', 'crond.service'])
        self.assertEqual(10, code)
        self.assertEqual('blocked_services', report['result'])
        self.mocks['oc_source_apply'].assert_not_called()

    def test_supervisor_and_other_blocker_reasons_are_never_suppressed(self):
        process = self.prepare_cron()
        for reason in ('Long-running PHP process PID 536 is not covered; explicitly select its service with --service',
                       'Cannot revalidate PHP process PID 536 identity; inspection may be restricted',
                       'PHP-FPM configuration test failed'):
            with self.subTest(reason=reason):
                self.mocks['service_preflight'].return_value = dict(services=['php-fpm.service'],
                    blockers=[dict(process, reason=reason)], checks=[])
                with mock.patch.object(guard, 'sm_plan', return_value=scheduler_plan([process]), create=True):
                    code, report = self.run_main(['--yes', '--pause-scheduler', 'crond.service'])
                self.assertEqual(10, code)
                self.assertEqual('blocked_services', report['result'])
        self.mocks['oc_source_apply'].assert_not_called()

    def test_drain_wait_rejects_negative_or_unbounded_values_before_inventory(self):
        for value in ('-1', '3601', 'not-an-int'):
            with self.subTest(value=value), mock.patch('sys.stderr'), self.assertRaises(SystemExit) as raised:
                guard.php74_patch_main(['plan', '--pause-scheduler', 'crond.service', '--drain-wait', value])
            self.assertEqual(2, raised.exception.code)
        self.mocks['collect_inventory'].assert_not_called()

    def test_repository_install_and_postcheck_execute_inside_maintenance(self):
        self.plan.update(updates=[dict(name='php-cli', version='7.4.33-2.amzn2')], blockers=[])
        self.mocks['oc_assess'].side_effect = [self.findings, self.findings, [dict(kind='package', status='fixed')]]
        calls = []
        self.mocks['execute_repair'].side_effect = lambda *a: calls.append('install') or dict(ok=True)
        self.mocks['residual_process_check'].side_effect = lambda *a: calls.append('postcheck') or dict(ok=True, errors=[])
        def maintenance(args, report, path, action):
            calls.append('pause')
            try:
                return action()
            finally:
                calls.append('restore')
        with mock.patch.object(guard, 'sm_plan', return_value=scheduler_plan(), create=True), \
             mock.patch.object(guard, 'oc_maintenance_run', side_effect=maintenance, create=True):
            code, report = self.run_main(['--yes', '--pause-scheduler', 'crond.service'])
        self.assertEqual(0, code)
        self.assertEqual('fixed_within_scope', report['result'])
        self.assertEqual(['pause', 'install', 'postcheck', 'restore'], calls)


class SourceBuildMaintenanceTests(unittest.TestCase):
    setUp = fixtures.BuildHandoffTests.setUp

    def test_failed_build_never_enters_maintenance(self):
        self.args.pause_scheduler = ['crond.service']
        self.args.drain_wait = 30
        self.mocks['baota_al2_build_main'].return_value = 20
        self.mocks['native_build_main'].return_value = 20
        with mock.patch.object(guard, 'oc_maintenance_run', create=True) as maintenance:
            for route in ('al2', 'remi', 'ubuntu20'):
                with self.subTest(route=route):
                    self.assertEqual(20, guard.oc_source_apply(route, self.args, self.report, '/report'))
        maintenance.assert_not_called()

    def test_pause_happens_after_build_and_covers_install_and_original_scope_postcheck(self):
        self.args.pause_scheduler = ['crond.service']
        self.args.drain_wait = 30
        calls = []
        self.mocks['native_build_main'].side_effect = lambda *a: calls.append('build') or 0
        self.mocks['remi_install_main'].side_effect = lambda *a: calls.append('install') or 0
        self.mocks['collect_inventory'].side_effect = lambda *a: calls.append('postcheck') or fixtures.inventory('remi')
        def maintenance(args, report, path, action):
            calls.append('pause')
            try:
                return action()
            finally:
                calls.append('restore')
        with mock.patch.object(guard, 'oc_maintenance_run', side_effect=maintenance, create=True):
            self.assertEqual(0, guard.oc_source_apply('remi', self.args, self.report, '/report'))
        self.assertEqual(['build', 'pause', 'install', 'postcheck', 'restore'], calls)


if __name__ == '__main__':
    unittest.main()
