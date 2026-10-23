"""Privilege and fresh-report handoff for native dual-layout builds."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('php82_setup_guard', ROOT / 'php_guard.py')
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)


class NativeSetupTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.account = dict(name='builder', uid=1234, gid=1234, home='/home/builder', work_dir='/home/builder/php82')

    def test_child_drops_privileges_before_both_layouts_and_returns_exact_reports(self):
        events = []
        def entry(argv):
            events.append(argv)
            if argv[0] == 'build':
                g.R82_LAST_BUILD_REPORT = argv[argv.index('--work-dir') + 1] + '/build-new/build.json'
            return 0
        with mock.patch.object(g, 'be_drop_privileges', side_effect=lambda *a: events.append('drop')), \
             mock.patch.object(g, 'be_worker_call', side_effect=lambda fn: fn()), \
             mock.patch.object(g, 'remi82_build_main', side_effect=entry), \
             mock.patch.object(g.os, 'geteuid', return_value=1234):
            result = g.nb_child('remi82', self.account, True, 2, ['system', 'scl'])
        self.assertTrue(result['ok'])
        self.assertEqual('drop', events[0])
        self.assertEqual(['prepare','doctor','build'] * 2, [argv[0] for argv in events[1:]])
        self.assertEqual(['/home/builder/php82/system/build-new/build.json',
                          '/home/builder/php82/scl/build-new/build.json'], result['build_reports'])

    def test_second_layout_failure_or_wrong_uid_does_not_publish_build_success(self):
        for uid in (0, 1234):
            def entry(argv):
                if argv[0] == 'build':
                    g.R82_LAST_BUILD_REPORT = '/fresh/system/build.json'
                return 20 if '--layout' in argv and argv[argv.index('--layout') + 1] == 'scl' else 0
            with mock.patch.object(g, 'be_drop_privileges'), \
                 mock.patch.object(g, 'be_worker_call', side_effect=lambda fn: fn()), \
                 mock.patch.object(g, 'remi82_build_main', side_effect=entry), \
                 mock.patch.object(g.os, 'geteuid', return_value=uid):
                result = g.nb_child('remi82', self.account, True, 2, ['system', 'scl'])
            self.assertFalse(result['ok'])

    def test_build_repo_reaches_preview_and_exact_execution_for_php74_and_php82(self):
        for kind in ('remi','remi82'):
            dependency = mock.Mock(return_value=dict(ok=True, changes=[]))
            child = mock.Mock(return_value=dict(ok=True, stage='built_not_deployed',
                                               build_reports=['/fresh/system/build.json']))
            with mock.patch.object(g, 'nb_account', return_value=self.account), \
                 mock.patch.object(g, 'be_report_directory', return_value=self.folder.name), \
                 mock.patch.object(g, 'build_environment_transaction', dependency), \
                 mock.patch.object(g, 'nb_child', child), mock.patch.object(g, 'say'):
                code = g.native_build_main(kind, ['all','--yes','--build-user','builder','--build-repo','remi'])
            self.assertEqual(0, code)
            self.assertEqual(2, dependency.call_count)
            for call in dependency.call_args_list:
                self.assertEqual(['remi'], call.kwargs['build_repos'])
                self.assertEqual('remi82-el7' if kind == 'remi82' else 'remi-el7', call.kwargs['profile'])
            self.assertEqual([], dependency.call_args.kwargs['expected_changes'])
            if kind == 'remi82': self.assertEqual(['/fresh/system/build.json'], g.NB_LAST_BUILD_REPORTS)

    def test_failed_second_build_clears_previous_success_reports(self):
        g.NB_LAST_BUILD_REPORTS = ['/old/build.json']
        with mock.patch.object(g, 'nb_account', return_value=self.account), \
             mock.patch.object(g, 'be_report_directory', return_value=self.folder.name), \
             mock.patch.object(g, 'build_environment_transaction', return_value=dict(ok=True, changes=[])), \
             mock.patch.object(g, 'nb_child', return_value=dict(ok=False, build_reports=['/partial/build.json'])), \
             mock.patch.object(g, 'say'):
            self.assertEqual(20, g.native_build_main('remi82', ['all','--yes','--build-user','builder']))
        self.assertEqual([], g.NB_LAST_BUILD_REPORTS)
