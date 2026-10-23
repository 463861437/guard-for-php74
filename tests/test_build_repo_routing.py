"""Explicit Remi build repository reaches only compiler setup, never deployment."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('build_repo_guard', ROOT / 'php_guard.py')
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)


class BuildRepositoryRoutingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.account = dict(name='builder', uid=1234, gid=1234, home='/home/builder', work_dir='/home/builder/php74')

    def test_explicit_repo_reaches_preview_and_exact_execution(self):
        dependency = mock.Mock(return_value=dict(ok=True, changes=[]))
        with mock.patch.object(g, 'nb_account', return_value=self.account), \
             mock.patch.object(g, 'be_report_directory', return_value=self.folder.name), \
             mock.patch.object(g, 'build_environment_transaction', dependency), \
             mock.patch.object(g, 'nb_child', return_value=dict(ok=True, stage='built_not_deployed')), \
             mock.patch.object(g, 'say'):
            self.assertEqual(0, g.native_build_main('remi', ['all', '--yes', '--build-user', 'builder', '--build-repo', 'remi']))
        self.assertEqual(2, dependency.call_count)
        self.assertEqual([False, True], [call.kwargs['execute'] for call in dependency.call_args_list])
        for call in dependency.call_args_list:
            self.assertEqual(['remi'], call.kwargs['build_repos'])
            self.assertEqual('remi-el7', call.kwargs['profile'])
        self.assertEqual([], dependency.call_args.kwargs['expected_changes'])
        report = json.loads((Path(self.folder.name) / 'native-setup.json').read_text())
        self.assertEqual(['remi'], report['requested_build_repositories'])

    def test_default_setup_does_not_request_disabled_repositories(self):
        dependency = mock.Mock(return_value=dict(ok=True, changes=[]))
        with mock.patch.object(g, 'nb_account', return_value=self.account), \
             mock.patch.object(g, 'be_report_directory', return_value=self.folder.name), \
             mock.patch.object(g, 'build_environment_transaction', dependency), mock.patch.object(g, 'say'):
            self.assertEqual(0, g.native_build_main('remi', ['setup']))
        self.assertEqual([], dependency.call_args.kwargs['build_repos'])
        self.assertFalse(dependency.call_args.kwargs['execute'])

    def test_oneclick_forwards_only_to_native_build_and_does_not_install_on_failure(self):
        args = argparse.Namespace(build_repo=['remi'], build_user='builder', work_dir=None, jobs=2, lock_wait=300)
        report = {}
        build = mock.Mock(return_value=20)
        with mock.patch.object(g, 'oc_builder_account', return_value=types.SimpleNamespace(pw_dir='/home/builder', pw_name='builder')), \
             mock.patch.object(g, 'native_build_main', build), mock.patch.object(g, 'remi_install_main') as install, \
             mock.patch.object(g, 'say'):
            self.assertEqual(20, g.oc_source_apply('remi', args, report, str(Path(self.folder.name) / 'oneclick.json')))
        self.assertEqual('remi', build.call_args.args[0])
        values = build.call_args.args[1]
        self.assertEqual('remi', values[values.index('--build-repo') + 1])
        install.assert_not_called()
        self.assertEqual('build_incomplete_no_php_deployment', report['result'])

    def test_other_routes_reject_override_before_creating_build_account(self):
        args = argparse.Namespace(build_repo=['remi'])
        for route in ('al2', 'ubuntu20', 'repository'):
            with mock.patch.object(g, 'oc_builder_account') as account, self.assertRaises(RuntimeError):
                g.oc_source_apply(route, args, {}, '/unused')
            account.assert_not_called()
