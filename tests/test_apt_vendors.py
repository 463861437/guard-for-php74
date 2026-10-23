"""Authenticated Ondrej APT updates; no target system or package mutation."""
import copy
import json
import pathlib
import re
import types
import unittest
from unittest import mock

import test_apt_backend as apt_tests

worker, backend = apt_tests.worker, apt_tests.backend

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / 'vendor-policy.json').read_text())
RULES = [row for row in POLICY['entries'] if row.get('provenance') == 'ondrej-apt']
COMMON = {'__name__': 'apt_vendor_common_test'}
exec(compile((ROOT / 'src/common.py').read_text(), 'common', 'exec'), COMMON)
exec(compile((ROOT / 'src/apt_backend.py').read_text(), 'apt_backend', 'exec'), COMMON)


def vendor_package(rule, **changes):
    origin = rule['apt_origin']
    package = dict(name='php7.4-cli', version=rule['min_version'], source_version=rule['min_version'],
                   source='php7.4', upstream='7.4.33', arch='amd64', trusted=True,
                   official_origin=False, origins=[dict(trusted=True, origin=origin['origin'],
                       archive=origin['archive'], codename=origin['codename'], site=origin['sites'][0])])
    package.update(changes)
    return package


def vendor_inventory(rule, packages=()):
    return dict(os=dict(id=rule['os_id'], version_id=rule['os_version'], version_codename=rule['os_codename']),
                package_manager='apt', packages=list(packages), runtimes=[], processes=[], services=[], warnings=[])


def compare_fixture(a, b, manager):
    if a == b: return 0
    left = int(re.match(r'^1:7\.4\.33-([0-9]+)', a).group(1))
    right = int(re.match(r'^1:7\.4\.33-([0-9]+)', b).group(1))
    return (left > right) - (left < right)


class VendorPolicyTests(unittest.TestCase):
    def status(self, package, rule):
        with mock.patch.dict(COMMON, native_compare=compare_fixture):
            return COMMON['package_status'](package, vendor_inventory(rule), POLICY)[0]

    def test_all_verified_repository_minima_are_recognized_without_official_flag(self):
        self.assertEqual(8, len(RULES))
        for rule in RULES:
            with self.subTest(os=rule['os_id'], release=rule['os_version'], origin=rule['apt_origin']['origin']):
                self.assertEqual('fixed', self.status(vendor_package(rule), rule))

    def test_previous_revision_is_not_fixed(self):
        for rule in RULES:
            older = rule['min_version'].replace('7.4.33-31+', '7.4.33-30+', 1)
            self.assertNotEqual('fixed', self.status(vendor_package(rule, version=older, source_version=older), rule))

    def test_origin_fields_must_all_match_one_authenticated_record(self):
        rule = RULES[0]
        for key, bad in [('trusted', False), ('origin', 'LP-PPA-attacker-php'),
                         ('site', 'unreviewed-mirror.example'), ('archive', 'noble'), ('codename', 'noble')]:
            package = vendor_package(rule)
            package['origins'][0][key] = bad
            with self.subTest(field=key):
                self.assertNotEqual('fixed', self.status(package, rule))
        package = vendor_package(rule)
        valid = package['origins'][0]
        package['origins'] = [dict(valid, trusted=False), dict(valid, site='other.example')]
        self.assertNotEqual('fixed', self.status(package, rule))

    def test_changed_binary_or_source_version_cannot_inherit_vendor_fix(self):
        rule = RULES[0]
        for field in ('version', 'source_version'):
            for value in ('1:7.4.33-999+local1', '1:7.4.33-31+ubuntu24.04.1+deb.sury.org+1'):
                package = vendor_package(rule)
                package[field] = value
                with self.subTest(field=field, version=value):
                    self.assertNotEqual('fixed', self.status(package, rule))
        self.assertNotEqual('fixed', self.status(vendor_package(rule, source='php7.4-custom'), rule))

    def test_wrong_architecture_candidate_is_not_selected(self):
        rule = RULES[0]
        fixed = vendor_package(rule, arch='arm64')
        old_version = rule['min_version'].replace('7.4.33-31+', '7.4.33-30+', 1)
        installed = vendor_package(rule, version=old_version, source_version=old_version)
        inv = vendor_inventory(rule, [installed])
        with mock.patch.dict(COMMON, native_compare=compare_fixture):
            plan = COMMON['build_plan'](inv, [], {'php7.4-cli': [fixed]}, POLICY)
        self.assertFalse(plan['updates'])
        self.assertTrue(plan['blockers'])


class OriginEvidenceTests(unittest.TestCase):
    def test_package_file_codename_is_used_without_guessing(self):
        namespace, unused_apt, unused_native = worker()
        origin = types.SimpleNamespace(trusted=True, origin='LP-PPA-ondrej-php', archive='jammy', site='ppa.launchpadcontent.net')
        version = types.SimpleNamespace(origins=[origin])
        self.assertEqual('', namespace['origin_records'](version)[0]['codename'])
        package_file = types.SimpleNamespace(origin=origin.origin, archive='jammy', site=origin.site, codename='noble')
        version._cand = types.SimpleNamespace(file_list=[(package_file, 0)])
        self.assertEqual('noble', namespace['origin_records'](version)[0]['codename'])
        package_file.site = 'different.example'
        self.assertEqual('', namespace['origin_records'](version)[0]['codename'])

    def test_vendor_origin_never_becomes_ubuntu_official(self):
        namespace, unused_apt, unused_native = worker()
        origin = types.SimpleNamespace(trusted=True, origin='LP-PPA-ondrej-php', archive='jammy', site='ppa.launchpadcontent.net', codename='jammy')
        version = types.SimpleNamespace(version=RULES[0]['min_version'], source_version=RULES[0]['min_version'],
            architecture='amd64', source_name='php7.4', origins=[origin])
        record = namespace['record'](version, 'jammy')
        self.assertFalse(record['official_origin'])
        self.assertEqual('ppa.launchpadcontent.net', record['origins'][0]['site'])

    def test_enrichment_requires_installed_version_source_arch_and_source_version(self):
        rule = RULES[0]
        candidate = vendor_package(rule)
        for field, value in [('version', '1:7.4.33-30'), ('source', 'php7.4-custom'),
                             ('arch', 'arm64'), ('source_version', '1:7.4.33-999')]:
            installed = vendor_package(rule)
            installed.pop('origins')
            installed[field] = value
            inv = vendor_inventory(rule, [installed])
            result = backend.enrich_origin(inv, {'php7.4-cli': [candidate]})
            with self.subTest(field=field): self.assertNotIn('origins', result['packages'][0])
        installed = vendor_package(rule)
        installed.pop('origins')
        result = backend.enrich_origin(vendor_inventory(rule, [installed]), {'php7.4-cli': [candidate]})
        self.assertEqual(candidate['origins'], result['packages'][0]['origins'])

    def test_rpm_vendor_proof_is_only_inherited_after_installed_bytes_match(self):
        for installed_match in (False, None, True):
            candidate = vendor_package(RULES[0])
            candidate['vendor_provenance'] = {'installed_match': installed_match, 'signer': 'fixture'}
            installed = vendor_package(RULES[0])
            result = backend.enrich_origin(vendor_inventory(RULES[0], [installed]), {'php7.4-cli': [candidate]})
            with self.subTest(installed_match=installed_match):
                self.assertEqual(installed_match is True, 'vendor_provenance' in result['packages'][0])


class VendorNativeTransactionTests(unittest.TestCase):
    def setUp(self):
        apt_tests.NativeTransactionTests.setUp(self)
        rule = RULES[0]
        old_version = rule['min_version'].replace('7.4.33-31+', '7.4.33-30+', 1)
        self.old.version = old_version
        self.new.version = self.new.source_version = rule['min_version']
        origin = rule['apt_origin']
        self.new.origins = [types.SimpleNamespace(trusted=True, origin=origin['origin'],
            archive=origin['archive'], site=origin['sites'][0], codename=origin['codename'])]
        self.item.update(self.worker['record'](self.new, 'jammy'))
        self.item['old_version'] = old_version
        self.data['codename'] = 'jammy'
        self.native.version_compare = lambda a,b: compare_fixture(a,b,'apt')
        self.apt.progress.base.AcquireProgress = mock.Mock()
        self.apt.progress.base.InstallProgress = mock.Mock()
        self.cache.commit.return_value = True

    def test_exact_vendor_candidate_can_preview_and_execute(self):
        self.assertTrue(self.worker['work'](self.data)['ok'])
        self.cache.commit.assert_not_called()
        self.data['execute'] = True
        self.assertTrue(self.worker['work'](self.data)['ok'])
        self.cache.commit.assert_called_once()

    def test_same_origin_and_suite_at_different_site_is_rejected(self):
        for execute in (False, True):
            self.data['execute'] = execute
            self.new.origins[0].site = 'other.example'
            with self.assertRaisesRegex(RuntimeError, 'Release identity changed'):
                self.worker['work'](self.data)
        self.cache.commit.assert_not_called()

    def test_codename_change_is_rejected_even_if_suite_is_unchanged(self):
        self.new.origins[0].codename = 'noble'
        with self.assertRaisesRegex(RuntimeError, 'Release identity changed'):
            self.worker['work'](self.data)

    def test_missing_vendor_evidence_is_not_allowed(self):
        self.item.pop('origins')
        with self.assertRaisesRegex(RuntimeError, 'Missing pinned vendor'):
            self.worker['work'](self.data)

    def test_missing_codename_cannot_be_guessed_even_when_plan_is_the_same(self):
        self.new.origins[0].codename = ''
        self.item['origins'][0]['codename'] = ''
        with self.assertRaisesRegex(RuntimeError, 'could not be verified'):
            self.worker['work'](self.data)

    def test_official_or_another_release_old_package_is_not_migrated(self):
        for value in ('7.4.33-1+deb11u10', '1:7.4.33-30+ubuntu24.04.1+deb.sury.org+1'):
            self.old.version = self.item['old_version'] = value
            self.native.version_compare = lambda a,b: 1
            with self.subTest(version=value), self.assertRaisesRegex(RuntimeError, 'vendor/distribution lineage'):
                self.worker['work'](self.data)

    def test_candidate_architecture_and_source_are_revalidated(self):
        self.new.architecture = 'arm64'
        with self.assertRaisesRegex(RuntimeError, 'exact candidate missing'):
            self.worker['work'](self.data)
        self.new.architecture = 'amd64'
        self.new.source_name = 'php7.4-custom'
        with self.assertRaisesRegex(RuntimeError, 'source/trust mismatch'):
            self.worker['work'](self.data)


if __name__ == '__main__':
    unittest.main()
