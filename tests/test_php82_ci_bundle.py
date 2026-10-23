"""Offline bundle selection checks; never launch containers or install packages."""
import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('php82_ci_fixture_test', ROOT / 'tools/php82_el7_smoke.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class BundleSelectionTests(unittest.TestCase):
    def make_report(self, directory, layout, attempt='build-one'):
        path = pathlib.Path(directory) / layout / attempt / 'build.json'
        path.parent.mkdir(parents=True)
        path.write_text('{}')
        return path

    def test_selects_both_layouts_without_loading_or_trusting_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            system = self.make_report(directory, 'system')
            scl = self.make_report(directory, 'scl')
            self.assertEqual([str(system), str(scl)], fixture.bundle_reports(directory, ['system', 'scl']))

    def test_missing_or_ambiguous_layout_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_report(directory, 'system')
            with self.assertRaisesRegex(RuntimeError, 'missing'):
                fixture.bundle_reports(directory, ['system', 'scl'])
            self.make_report(directory, 'system', 'build-two')
            with self.assertRaisesRegex(RuntimeError, 'Exactly one'):
                fixture.bundle_reports(directory, ['system'])

    def test_report_and_build_directory_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.make_report(directory, 'system')
            external = pathlib.Path(directory) / 'external.json'
            external.write_text('{}')
            report.unlink()
            report.symlink_to(external)
            with self.assertRaisesRegex(RuntimeError, 'regular file'):
                fixture.bundle_reports(directory, ['system'])
            report.unlink()
            report.parent.rmdir()
            external_dir = pathlib.Path(directory) / 'external-build'
            external_dir.mkdir()
            (external_dir / 'build.json').write_text('{}')
            report.parent.symlink_to(external_dir, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'regular file'):
                fixture.bundle_reports(directory, ['system'])

    def test_layout_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            original = self.make_report(directory, 'system')
            (pathlib.Path(directory) / 'scl').symlink_to(original.parent.parent, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                fixture.bundle_reports(directory, ['scl'])


if __name__ == '__main__':
    unittest.main()
