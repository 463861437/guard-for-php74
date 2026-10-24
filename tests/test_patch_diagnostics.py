"""Bounded native patch failure diagnostics must not echo build secrets."""
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guard_patch_diagnostics', ROOT / 'php_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
exec(compile((ROOT / 'src/backport_builder.py').read_bytes(),
             str(ROOT / 'src/backport_builder.py'), 'exec'), guard.__dict__)


class PatchDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)

    def summary(self, content, stage='prepare_and_dependencies'):
        name = {'prepare_and_dependencies': 'prep.log',
                'security_regressions': 'security-tests.log'}.get(stage, 'build.log')
        (self.folder / name).write_text(content)
        return guard.bp_failure_summary(str(self.folder), stage)

    def test_native_partial_duplicate_patch_names_each_failing_file(self):
        result = self.summary(
            '+ SECRET=must-never-appear\n'
            '+ echo \'Patch #203 (php-cve-2023-0662.patch):\'\n'
            'Patch #203 (php-cve-2023-0662.patch):\n'
            '+ /usr/bin/cat /private/token/source.patch\n'
            'patching file main/rfc1867.c\nHunk #1 succeeded at 947 (offset 25 lines).\n'
            'patching file main/main.c\n'
            'Reversed (or previously applied) patch detected!  Assume -R? [n]\n'
            'Apply anyway? [n]\nSkipping patch.\n'
            '1 out of 1 hunk ignored -- saving rejects to file main/main.c.rej\n'
            'patching file main/rfc1867.c\n'
            'Reversed (or previously applied) patch detected!  Assume -R? [n]\n'
            '3 out of 3 hunks ignored -- saving rejects to file main/rfc1867.c.rej\n')
        self.assertEqual('patch_application_failed', result['kind'])
        self.assertEqual([
            dict(kind='reversed_or_previously_applied', patch='php-cve-2023-0662.patch', patch_number=203, file='main/main.c'),
            dict(kind='reversed_or_previously_applied', patch='php-cve-2023-0662.patch', patch_number=203, file='main/rfc1867.c'),
        ], result['patch_failures'])
        with mock.patch.object(guard, 'say') as output:
            guard.bp_print_failure_summary(result)
        printed = '\n'.join(call.args[0] for call in output.call_args_list)
        self.assertIn('php-cve-2023-0662.patch', printed)
        self.assertIn('main/main.c', printed); self.assertIn('main/rfc1867.c', printed)
        self.assertIn('反向或此前已应用', printed)
        for forbidden in ('must-never-appear', 'private/token', 'Assume -R', 'Apply anyway', '/usr/bin/cat'):
            self.assertNotIn(forbidden, printed + json.dumps(result))
        self.assertFalse(result['raw_log_included'])

    def test_failed_hunks_preserve_fixed_numeric_fields_without_duplicate_aggregate(self):
        result = self.summary('Patch #9 (php-test.patch):\npatching file ext/test.c\n'
                              'Hunk #2 FAILED at 123.\nHunk #3 FAILED at 900.\n'
                              '2 out of 3 hunks FAILED -- saving rejects to file ext/test.c.rej\n')
        self.assertEqual([2, 3], [row['hunk'] for row in result['patch_failures']])
        self.assertEqual([123, 900], [row['line'] for row in result['patch_failures']])
        self.assertEqual({'hunk_failed'}, {row['kind'] for row in result['patch_failures']})
        result = self.summary('patching file ext/aggregate.c\n1 out of 1 hunk FAILED -- saving rejects to file ext/aggregate.c.rej\n')
        self.assertEqual([{'kind': 'hunk_failed', 'file': 'ext/aggregate.c'}], result['patch_failures'])

    def test_patch_header_and_unsafe_file_reset_previous_context(self):
        result = self.summary('Patch #1 (safe.patch):\npatching file old.c\n'
                              'Patch #2 ($(private-token).patch):\n'
                              'patching file ../../private-token\nHunk #1 FAILED at 1.\n')
        self.assertEqual([dict(kind='hunk_failed', patch_number=2, hunk=1, line=1)], result['patch_failures'])
        self.assertNotIn('private-token', json.dumps(result))
        for value in ('/private/token', '../token', 'main/../../token', 'main/a\x1b[31m.c',
                      'main/a\nSECRET=token', 'token?secret', '-bad.c', 'a' * 241):
            self.assertIsNone(guard.bp_failure_filename(value))
        self.assertIsNone(guard.bp_failure_filename('directory/safe.patch', patch=True))

    def test_shell_traces_and_source_text_are_not_treated_as_patch_diagnostics(self):
        result = self.summary("+ echo 'Reversed (or previously applied) patch detected!'\n"
                              '+ Hunk #1 FAILED at 1.\n- Hunk #2 FAILED at 2.\n'
                              '+ Patch #1 (private-token.patch):\n')
        self.assertEqual('unclassified', result['kind'])
        self.assertNotIn('patch_failures', result)

    def test_bounded_tail_drops_partial_line_and_limits_report_rows(self):
        result = self.summary('SECRET=token' + 'x' * 70000 + 'Reversed (or previously applied) patch detected!\n')
        self.assertEqual('unclassified', result['kind'])
        result = self.summary('Patch #1 (safe.patch):\n' + ''.join(
            'patching file main/file%s.c\nHunk #1 FAILED at 1.\n' % index for index in range(30)))
        self.assertEqual(16, len(result['patch_failures']))
        self.assertTrue(result['patch_failures_truncated'])

    def test_symlinks_and_nonregular_diagnostic_files_are_not_read(self):
        target = self.folder / 'private'; target.write_text('Reversed (or previously applied) patch detected!\n')
        log = self.folder / 'prep.log'; log.symlink_to(target)
        progress = self.folder / 'prep.log.progress.json'; progress.symlink_to(target)
        with mock.patch.object(guard.os, 'open', side_effect=AssertionError('must not open a symlink')):
            self.assertEqual('unclassified', guard.bp_failure_summary(str(self.folder), 'prepare_and_dependencies')['kind'])
        log.unlink(); progress.unlink()
        os.mkfifo(str(log))
        self.assertEqual('', guard.bp_failure_read(str(log), tail=True))

    def test_safe_printer_revalidates_fields_instead_of_trusting_report_text(self):
        summary = dict(kind='unknown', hint='SECRET=token', log='/tmp/log\nSECRET=token',
                       patch_failures=[dict(kind='hunk_failed', patch='$(token).patch', file='/private/token', hunk='1\nSECRET'),
                                       dict(kind='SECRET=token')])
        with mock.patch.object(guard, 'say') as output:
            guard.bp_print_failure_summary(summary)
        printed = '\n'.join(call.args[0] for call in output.call_args_list)
        self.assertNotIn('token', printed); self.assertNotIn('SECRET', printed)
        self.assertIn('补丁块应用失败', printed)

    def test_monitor_failure_precedes_partial_patch_output(self):
        (self.folder / 'prep.log.progress.json').write_text(json.dumps({'reason': 'timeout', 'secret': 'not-printed'}))
        result = self.summary('Reversed (or previously applied) patch detected!\n')
        self.assertEqual('build_timeout', result['kind'])
        self.assertNotIn('not-printed', json.dumps(result))

    def test_previous_failure_categories_are_preserved(self):
        for content, kind in [('Failed build dependencies:\n libxml2-devel is needed', 'missing_build_dependencies'),
                              ('gcc: fatal error: Killed signal terminated program cc1', 'possible_host_memory_exhaustion'),
                              ('FAILED TEST SUMMARY\nFAIL some test', 'php_tests_failed')]:
            with self.subTest(kind=kind):
                self.assertEqual(kind, self.summary(content)['kind'])

    def test_php_failure_summary_prints_only_counts_and_relative_test_names(self):
        result = self.summary(
            'TEST 100/100 [1/2 workers]\r \r\x1b[1;31mFAIL\x1b[0m secret title [sapi/cli/tests/021.phpt]\n'
            'TEST RESULT SUMMARY\nNumber of tests : 18781 11000\nTests skipped : 7781 (41.4%)\n'
            'Tests warned : 1\nTests failed : 1\nExpected fail : 6\nTests passed : 10992\n'
            'Time taken : 143 seconds\n=====================================================================\n'
            'EXPECTED FAILED TEST SUMMARY\nExpected description [ext/filter/tests/known.phpt]\n'
            '=====================================================================\nFAILED TEST SUMMARY\n'
            'Untrusted secret title [sapi/cli/tests/021.phpt]\n=====================================================================\n'
            'WARNED TEST SUMMARY\nHidden title [sapi/fpm/tests/known.phpt] (warn: XFAIL section but test passes)\n'
            '=====================================================================\nTEST FAILURE: ../sapi/cli/tests/021.diff --\n'
            '001+ SECRET=/private/token\n', stage='compile_test_package')
        self.assertEqual('php_tests_failed', result['kind'])
        self.assertEqual(18781, result['test_counts']['total'])
        self.assertEqual(1, result['test_counts']['failed'])
        self.assertTrue(result['test_counts_complete'])
        self.assertEqual([{'result': 'FAIL', 'test': 'sapi/cli/tests/021.phpt'},
                          {'result': 'WARN', 'test': 'sapi/fpm/tests/known.phpt'}], result['test_failures'])
        with mock.patch.object(guard, 'say') as output:
            guard.bp_print_failure_summary(result)
        rendered = '\n'.join(call.args[0] for call in output.call_args_list)
        self.assertIn('失败 1', rendered); self.assertIn('[FAIL] sapi/cli/tests/021.phpt', rendered)
        for forbidden in ('secret title', 'Hidden title', 'private/token', 'SECRET', 'known.phpt] (warn'):
            self.assertNotIn(forbidden, rendered + json.dumps(result))
        self.assertTrue(all('\n' not in call.args[0] and '\r' not in call.args[0] for call in output.call_args_list))

    def test_expected_failures_do_not_classify_an_unrelated_build_error_as_php_failure(self):
        for content in ('EXPECTED FAILED TEST SUMMARY\nExpected description [tests/known.phpt]\n',
                        'TEST RESULT SUMMARY\nNumber of tests : 2\nTests skipped : 0\nTests warned : 0\n'
                        'Tests failed : 0\nExpected fail : 1\nTests passed : 1\nTime taken : 1 seconds\n'
                        'EXPECTED FAILED TEST SUMMARY\nExpected description [tests/known.phpt]\n',
                        '+ echo FAILED TEST SUMMARY\n+ Tests failed : 9\n'):
            with self.subTest(content=content):
                self.assertEqual('unclassified', self.summary(content)['kind'])

    def test_php_result_path_bounds_and_injection_are_rejected(self):
        unsafe = ['/private/token/sapi/cli/tests/021.phpt', 'tests/../token.phpt',
                  'tests/token\x1b]0;secret.phpt', 'tests/a$(secret).phpt',
                  'private/secret.phpt', 'tests/' + 'x' * 241 + '.phpt']
        content = 'FAILED TEST SUMMARY\n' + '\n'.join('title [' + path + ']' for path in unsafe)
        result = self.summary(content)
        self.assertEqual('php_tests_failed', result['kind'])
        self.assertFalse(result.get('test_failures'))
        self.assertNotIn('secret', json.dumps(result)); self.assertNotIn('private/token', json.dumps(result))
        content = ''.join('FAIL title [tests/fail%s.phpt]\n' % n for n in range(24))
        result = self.summary(content)
        self.assertEqual(16, len(result['test_failures']))
        self.assertTrue(result['test_failures_truncated'])

    def test_partial_duplicate_and_invalid_test_counts_are_not_reported_complete(self):
        samples = [
            ('Number of tests : 100\nTests failed : 1\n', {'total': 100, 'failed': 1}),
            ('TEST RESULT SUMMARY\nNumber of tests : 100\nTests failed : 1\nTests failed : 2\n', {}),
            ('TEST RESULT SUMMARY\nNumber of tests : -1\nTests failed : 99999999\nTests passed : SECRET\n', {}),
            ('TEST RESULT SUMMARY\nNumber of tests : 10\nTests skipped : 0\nTests warned : 0\n'
             'Tests failed : 1\nTests passed : 10\nTime taken : 1 seconds\n',
             {'total': 10, 'skipped': 0, 'warned': 0, 'failed': 1, 'passed': 10}),
        ]
        for text, counts in samples:
            with self.subTest(text=text):
                result = guard.bp_php_test_diagnostics(text)
                self.assertEqual(counts, result['test_counts'])
                self.assertFalse(result['test_counts_complete'])

    def test_security_regressions_use_their_own_log_and_monitor_record(self):
        (self.folder / 'build.log').write_text('FAILED TEST SUMMARY\nold [tests/old.phpt]\n')
        (self.folder / 'build.log.progress.json').write_text(json.dumps({'reason': 'timeout'}))
        result = self.summary('FAIL security test [tests/security/new.phpt]\n', stage='security_regressions')
        self.assertEqual(str(self.folder / 'security-tests.log'), result['log'])
        self.assertEqual('php_tests_failed', result['kind'])
        self.assertEqual([{'result': 'FAIL', 'test': 'tests/security/new.phpt'}], result['test_failures'])
        (self.folder / 'security-tests.log.progress.json').write_text(json.dumps({'reason': 'timeout'}))
        result = guard.bp_failure_summary(str(self.folder), 'security_regressions')
        self.assertEqual('build_timeout', result['kind'])
        self.assertEqual(str(self.folder / 'security-tests.log.progress.json'), result['progress_report'])

    def test_printer_revalidates_test_paths_status_and_integer_counts(self):
        summary = {'kind': 'php_tests_failed', 'test_counts': {'total': 'SECRET', 'failed': True, 'passed': 1.0, 'warned': 10000000},
                   'test_failures': [{'result': 'FAIL\nSECRET', 'test': 'tests/ok.phpt'},
                                     {'result': 'FAIL', 'test': '/private/token.phpt'},
                                     {'result': 'FAIL', 'test': 'tests/ok.phpt\nSECRET'},
                                     {'result': 'BORK', 'test': 'sapi/cli/tests/021.phpt'}]}
        with mock.patch.object(guard, 'say') as output:
            guard.bp_print_failure_summary(summary)
        rendered = '\n'.join(call.args[0] for call in output.call_args_list)
        self.assertNotIn('SECRET', rendered); self.assertNotIn('private/token', rendered)
        self.assertNotIn('测试计数', rendered)
        self.assertIn('[BORK] sapi/cli/tests/021.phpt', rendered)


if __name__ == '__main__':
    unittest.main()
