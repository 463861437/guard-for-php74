"""Pure safety-boundary tests. Never import RPM/DNF/YUM or touch host packages."""
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[1] / 'src' / 'rpm_backend.py'
SPEC = importlib.util.spec_from_file_location('guard_rpm_backend', PATH)
backend = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backend)
worker = {'__name__': 'rpm_worker_test'}
exec(compile(backend._RPM_WORKER, '<rpm-worker>', 'exec'), worker)


def compare(left, right):
    # Only a fake binding for fixed test values, never used by production code.
    def numeric(item):
        epoch, version, release = item
        return int(epoch), tuple(map(int, version.split('.'))), release
    return (numeric(left) > numeric(right)) - (numeric(left) < numeric(right))


class Package:
    def __init__(self, name='php-fpm', version='8.2.35', release='1.amzn2.0.1',
                 arch='x86_64', source='php', repo='amzn2extra-php8.2', epoch=0):
        self.name, self.version, self.release = name, version, release
        self.arch, self.repoid, self.epoch = arch, repo, epoch
        self.sourcerpm = source + '-' + version + '-' + release + '.src.rpm'
        self.vendor = 'Amazon Linux'


class NativeRpmPolicyTests(unittest.TestCase):
    def setUp(self):
        self.patch = mock.patch.dict(sys.modules, {'rpm': types.SimpleNamespace(labelCompare=compare)})
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.item = dict(name='php-fpm', arch='x86_64', source='php',
                         old_version='8.2.34-1.amzn2.0.1', version='8.2.35-1.amzn2.0.1')
        self.desired = worker['prepare']([self.item])
        self.new, self.old = Package(), Package(version='8.2.34')

    def test_exact_upgrade_has_paired_old_and_new(self):
        result = worker['validate_changes']([('upgrade', self.new), ('upgraded', self.old)], self.desired)
        self.assertEqual(1, len(result))
        self.assertEqual('upgrade', result[0]['action'])

    def test_dependency_install_and_obsoletes_are_rejected(self):
        for action in ('install', 'remove', 'downgrade', 'obsolete', 'reinstall', 'forbidden'):
            with self.subTest(action=action), self.assertRaises(RuntimeError):
                worker['validate_changes']([(action, self.new), ('upgraded', self.old)], self.desired)
        with self.assertRaises(RuntimeError):
            worker['validate_changes']([('upgrade', self.new), ('upgraded', self.old),
                                        ('upgrade', Package(name='unplanned'))], self.desired)

    def test_missing_old_wrong_source_wrong_arch_and_duplicate_fail(self):
        rows = [[('upgrade', self.new)],
                [('upgrade', Package(source='evil')), ('upgraded', self.old)],
                [('upgrade', Package(arch='aarch64')), ('upgraded', self.old)],
                [('upgrade', self.new), ('upgraded', self.old), ('upgrade', self.new)]]
        for values in rows:
            with self.subTest(rows=values), self.assertRaises(RuntimeError):
                worker['validate_changes'](values, self.desired)

    def test_minor_changes_and_downgrades_fail_before_solver(self):
        for version in ('8.3.36-1.amzn2.0.1', '8.2.33-1.amzn2.0.1', self.item['old_version']):
            item = dict(self.item, version=version)
            with self.subTest(version=version), self.assertRaises(RuntimeError):
                worker['prepare']([item])

    def test_stale_inventory_is_rejected(self):
        with self.assertRaises(RuntimeError):
            worker['verify_existing']([Package(version='8.2.32')], self.desired)

    def test_disabled_gpg_and_ambiguous_candidate_fail(self):
        with self.assertRaises(RuntimeError):
            worker['choose']([self.new], self.item, lambda name: types.SimpleNamespace(gpgcheck=False))
        with self.assertRaises(RuntimeError):
            worker['choose']([self.new, Package(repo='unrelated')], self.item,
                             lambda name: types.SimpleNamespace(gpgcheck=True))
        selected = worker['choose']([self.new, Package(repo='unrelated')],
                                    dict(self.item, repo=self.new.repoid),
                                    lambda name: types.SimpleNamespace(gpgcheck=True))
        self.assertIs(self.new, selected)

    def test_epoch_zero_normalizes_but_nonzero_is_preserved(self):
        self.assertTrue(worker['equal_evr']('0:8.2.35-1', '8.2.35-1'))
        self.assertEqual('1:8.2.35-1.amzn2.0.1', worker['evr'](Package(epoch=1)))

    def test_candidate_failure_is_never_empty_success(self):
        with mock.patch.object(backend, '_rpm_worker_call', return_value=dict(ok=False, error='metadata failed')):
            with self.assertRaises(RuntimeError):
                backend.rpm_candidates(dict(packages=[]))

    def test_transaction_failure_is_explicit(self):
        with mock.patch.object(backend, '_rpm_worker_call', side_effect=RuntimeError('locked')):
            result = backend.rpm_transaction([self.item], execute=True)
        self.assertFalse(result['ok'])
        self.assertEqual('locked', result['error'])


if __name__ == '__main__':
    unittest.main()
