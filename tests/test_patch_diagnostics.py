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
        name = 'prep.log' if stage == 'prepare_and_dependencies' else 'build.log'
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


if __name__ == '__main__':
    unittest.main()
