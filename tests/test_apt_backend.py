"""APT adapter regression tests; fake bindings never modify host packages."""
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('apt_backend_under_test', ROOT / 'src/apt_backend.py')
backend = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backend)
backend.re = __import__('re')
backend.as_text = str


def worker():
    apt = types.ModuleType('apt')
    progress = types.ModuleType('apt.progress')
    base = types.ModuleType('apt.progress.base')
    progress.base = base
    apt.progress = progress
    native = types.ModuleType('apt_pkg')
    namespace = {}
    with mock.patch.dict(sys.modules, {'apt': apt, 'apt.progress': progress,
                                     'apt.progress.base': base, 'apt_pkg': native}):
        exec(backend.APT_WORKER.split('\ntry:\n    with open(sys.argv[1])', 1)[0], namespace)
    return namespace, apt, native


class CodenameTests(unittest.TestCase):
    def test_inventory_reads_codename_without_executing_os_release(self):
        spec = importlib.util.spec_from_file_location('apt_inventory_under_test', ROOT / 'src/inventory.py')
        inventory = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inventory)
        content = 'ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal\nUBUNTU_CODENAME=focal\n'
        with mock.patch.object(inventory, '_inv_read', return_value=content):
            result = inventory._inv_os()
        self.assertEqual('ubuntu', result['id'])
        self.assertEqual('20.04', result['version_id'])
        self.assertEqual('focal', result['version_codename'])
        self.assertEqual('focal', result['ubuntu_codename'])

    def test_host_codename_supported_without_matching_php_policy(self):
        for os_id, codename in [('ubuntu', 'focal'), ('debian', 'bullseye')]:
            inv = {'os': {'id': os_id, 'version_codename': codename}}
            self.assertEqual(codename, backend.apt_codename(inv, {}))

    def test_policy_fallback_keeps_legacy_inventory_compatible(self):
        policy = {'entries': [{'os_id': 'ubuntu', 'os_version': '20.04', 'os_codename': 'focal'}]}
        self.assertEqual('focal', backend.apt_codename({'os': {'id': 'ubuntu', 'version_id': '20.04'}}, policy))

    def test_invalid_or_unknown_codename_is_not_guessed(self):
        self.assertEqual('__unknown__', backend.apt_codename({'os': {'id': 'custom', 'codename': 'foo;bar'}}, {}))


class NativeLockTests(unittest.TestCase):
    def setUp(self):
        self.worker, self.apt, self.native = worker()

    def test_lock_is_acquired_in_enter_and_released_on_exit(self):
        lock = mock.MagicMock()
        self.native.SystemLock = mock.Mock(return_value=lock)
        with self.worker['_system_lock'](0):
            lock.__enter__.assert_called_once_with()
        lock.__exit__.assert_called_once_with(None, None, None)

    def test_busy_lock_is_retried_without_removing_lock_file(self):
        first, second = mock.MagicMock(), mock.MagicMock()
        first.__enter__.side_effect = RuntimeError('Could not get lock /var/lib/dpkg/lock (11: Resource temporarily unavailable)')
        self.native.SystemLock = mock.Mock(side_effect=[first, second])
        with mock.patch.dict(self.worker, {'_clock': mock.Mock(side_effect=[0, 0.1, 0.2])}), \
             mock.patch.object(self.worker['time'], 'sleep') as sleeper:
            with self.worker['_system_lock'](2):
                pass
        sleeper.assert_called_once()
        self.assertEqual(2, self.native.SystemLock.call_count)

    def test_permission_error_is_not_retried(self):
        lock = mock.MagicMock()
        lock.__enter__.side_effect = RuntimeError('Could not open lock file (13: Permission denied)')
        self.native.SystemLock = mock.Mock(return_value=lock)
        with mock.patch.object(self.worker['time'], 'sleep') as sleeper:
            with self.assertRaisesRegex(RuntimeError, 'Permission denied'):
                with self.worker['_system_lock'](300):
                    pass
        sleeper.assert_not_called()

    def test_busy_timeout_is_explicit(self):
        lock = mock.MagicMock()
        lock.__enter__.side_effect = RuntimeError('Unable to lock; it is held by process 123')
        self.native.SystemLock = mock.Mock(return_value=lock)
        with self.assertRaisesRegex(RuntimeError, 'remained busy for 0 seconds'):
            with self.worker['_system_lock'](0):
                pass

    def test_invalid_wait_is_rejected(self):
        for value in (-1, 3601, True, '120'):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.worker['_system_lock'](value)


class WrapperTests(unittest.TestCase):
    def test_preview_timeout_includes_lock_wait(self):
        with mock.patch.object(backend, 'worker_call', create=True,
                               return_value={'ok': True}) as call:
            backend.apt_transaction([{}], lock_wait=300)
        self.assertEqual(420, call.call_args.kwargs['timeout'])
        self.assertEqual(300, call.call_args.args[1]['lock_wait'])


class NativeTransactionTests(unittest.TestCase):
    def setUp(self):
        self.worker, self.apt, self.native = worker()
        self.native.init_config = mock.Mock()
        self.native.init_system = mock.Mock()
        self.native.config = mock.Mock()
        self.native.SystemLock = mock.MagicMock()
        self.native.SELSTATE_HOLD = 2
        versions = ['7.4.3-4ubuntu2.28', '7.4.3-4ubuntu2.29+esm5']
        self.native.version_compare = lambda a,b: (versions.index(a)>versions.index(b))-(versions.index(a)<versions.index(b))
        origin = types.SimpleNamespace(trusted=True, origin='UbuntuESMApps', archive='focal-apps-security')
        self.old = types.SimpleNamespace(version=versions[0], architecture='amd64', source_name='php7.4')
        self.new = types.SimpleNamespace(version=versions[1], architecture='amd64', source_name='php7.4', source_version=versions[1], origins=[origin])
        self.package = types.SimpleNamespace(installed=self.old, candidate=self.new, versions=[self.new],
            _pkg=types.SimpleNamespace(selected_state=0), fullname='php7.4-cli:amd64', name='php7.4-cli',
            marked_upgrade=True, marked_delete=False, marked_downgrade=False,
            mark_install=mock.Mock())
        self.cache = mock.MagicMock()
        self.cache.__contains__.return_value = True
        self.cache.__getitem__.return_value = self.package
        self.cache.get_changes.return_value = [self.package]
        self.cache.broken_count = 0
        self.apt.Cache = mock.Mock(return_value=self.cache)
        self.item = {'name': 'php7.4-cli', 'version': versions[1], 'old_version': versions[0], 'arch': 'amd64',
                     'source': 'php7.4', 'source_version': versions[1], 'official_origin': True,
                     'repo': 'UbuntuESMApps/focal-apps-security'}
        self.data = {'action': 'transaction', 'updates': [self.item], 'codename': 'focal', 'lock_wait': 0}

    def test_ubuntu_esm_exact_candidate_preview(self):
        result = self.worker['work'](self.data)
        self.assertTrue(result['ok'])
        self.cache.commit.assert_not_called()

    def test_origin_switch_is_rejected(self):
        self.new.origins[0].archive = 'focal-apps-updates'
        with self.assertRaisesRegex(RuntimeError, 'origin changed'):
            self.worker['work'](self.data)

    def test_lost_official_origin_is_rejected(self):
        self.new.origins[0].origin = 'LP-PPA-ondrej-php'
        with self.assertRaisesRegex(RuntimeError, 'source/trust mismatch'):
            self.worker['work'](self.data)

    def test_installed_arch_or_source_change_is_rejected(self):
        for field, value in [('architecture', 'arm64'), ('source_name', 'php7.4-custom')]:
            previous = getattr(self.old, field)
            setattr(self.old, field, value)
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'installed package changed'):
                self.worker['work'](self.data)
            setattr(self.old, field, previous)

    def test_duplicate_updates_and_equal_versions_fail_before_solver(self):
        self.data['updates'] = [self.item, self.item]
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
            self.worker['work'](self.data)
        self.data['updates'] = [dict(self.item, version=self.item['old_version'])]
        with self.assertRaisesRegex(RuntimeError, 'strict upgrades'):
            self.worker['work'](self.data)

    def test_exact_source_version_is_rechecked(self):
        self.new.source_version = '7.4.3-4ubuntu2.30'
        with self.assertRaisesRegex(RuntimeError, 'source version changed'):
            self.worker['work'](self.data)


if __name__ == '__main__':
    unittest.main()
