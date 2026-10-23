"""Offline PHPT evidence bounds; never launch containers or execute PHP tests."""
import importlib.util
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('php74_ci_fixture_test', ROOT / 'tools/php74_el7_smoke.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class EvidenceTests(unittest.TestCase):
    def setup_case(self, directory, name='case'):
        source = pathlib.Path(directory) / 'build/rpmbuild/BUILD/php-7.4.34/ext/date/tests'
        source.mkdir(parents=True, exist_ok=True)
        for suffix in ('.phpt', '.diff', '.out', '.exp', '.log'):
            (source / (name + suffix)).write_text('test')
        return source

    def test_only_failure_siblings_are_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = str(pathlib.Path(directory).resolve())
            source = self.setup_case(directory)
            (source / 'case.sh').write_text('environment should not be copied')
            (source / 'other.log').write_text('unrelated')
            dest = pathlib.Path(directory) / 'evidence'
            result = fixture.collect_test_failures(str(pathlib.Path(directory) / 'build'), str(dest))
            self.assertEqual(result['cases'], 1)
            self.assertEqual(len(result['files']), 5)
            self.assertEqual(result['bytes'], 20)
            self.assertFalse(list(dest.rglob('*.sh')))
            self.assertFalse(list(dest.rglob('other.log')))

    def test_symlink_files_and_directories_are_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = str(pathlib.Path(directory).resolve())
            source = self.setup_case(directory)
            outside = pathlib.Path(directory) / 'outside'
            outside.mkdir()
            (outside / 'secret').write_text('private')
            (outside / 'fake.phpt').write_text('test')
            (outside / 'fake.diff').write_text('outside')
            (source / 'case.out').unlink()
            (source / 'case.out').symlink_to(outside / 'secret')
            (source / 'linked').symlink_to(outside, target_is_directory=True)
            result = fixture.collect_test_failures(str(pathlib.Path(directory) / 'build'),
                                                  str(pathlib.Path(directory) / 'evidence'))
            self.assertEqual(result['cases'], 1)
            self.assertEqual(len(result['files']), 4)
            self.assertEqual([entry['reason'] for entry in result['omitted']], ['symlink'])

    def test_file_total_and_case_limits_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = str(pathlib.Path(directory).resolve())
            source = self.setup_case(directory, 'a')
            self.setup_case(directory, 'b')
            (source / 'a.out').write_text('oversized')
            result = fixture.collect_test_failures(str(pathlib.Path(directory) / 'build'),
                                                  str(pathlib.Path(directory) / 'evidence'),
                                                  max_cases=1, max_file_bytes=4, max_total_bytes=8)
            self.assertEqual(result['cases'], 1)
            self.assertEqual(result['bytes'], 8)
            self.assertEqual(len(result['files']), 2)
            self.assertIn('file_limit', [entry['reason'] for entry in result['omitted']])
            self.assertIn('total_limit', [entry['reason'] for entry in result['omitted']])
            self.assertIn('case_limit', [entry['reason'] for entry in result['omitted']])

    def test_only_fixed_cgi_response_and_error_logs_are_collected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            work, state = root / 'work', root / 'state'
            probe = work / 'build-one/multipart-regressions-one'
            probe.mkdir(parents=True)
            names = ('body_parts_limit.log', 'file_upload_limit.log',
                     'body_parts_limit.errors.log', 'file_upload_limit.errors.log')
            for name in names + ('unexpected.log',):
                (probe / name).write_text('synthetic result')
            outside = root / 'outside.log'
            outside.write_text('private')
            (probe / 'file_upload_limit.log').unlink()
            (probe / 'file_upload_limit.log').symlink_to(outside)
            copied = []

            def copy_bounded(source, target, maximum):
                self.assertEqual(maximum, 2 * 1024 * 1024)
                copied.append(pathlib.Path(source).name)
                shutil.copyfile(source, target)

            with mock.patch.object(fixture, 'WORK', str(work)), \
                    mock.patch.object(fixture, 'STATE', str(state)), \
                    mock.patch.object(fixture, 'load_file', return_value={'r82_copy_input': copy_bounded}):
                fixture.collect_evidence()
            self.assertEqual(set(copied), set(names) - {'file_upload_limit.log'})
            self.assertFalse(list(state.rglob('unexpected.log')))


if __name__ == '__main__':
    unittest.main()
