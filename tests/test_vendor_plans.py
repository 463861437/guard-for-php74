"""A verified candidate must never become an implicit vendor migration."""
import copy
import json
import pathlib
import unittest
from unittest import mock

import test_guard
import test_apt_vendors

guard = test_guard.guard


class VendorPlanTests(unittest.TestCase):
    def test_scl_collection_metadata_does_not_look_like_a_mixed_php_engine(self):
        for major in ('8', '9', '10'):
            for name in ('php74', 'php74-runtime', 'php74-syspaths'):
                wrapper = dict(name=name, source='php74', version='7.4-3.el' + major + '.remi',
                    source_rpm='php74-7.4-3.el' + major + '.remi.src.rpm')
                self.assertFalse(guard.is_core_package(wrapper))
                self.assertTrue(guard.is_core_package(dict(wrapper, source_rpm='custom.src.rpm')))
                self.assertTrue(guard.is_core_package(dict(wrapper, name='php74-unknown')))
        self.assertTrue(guard.is_core_package(dict(name='php74-php-cli', source='php74-php', version='7.4.33-31.el9.remi')))

    def test_ppa_and_sury_only_upgrade_their_own_installed_lineage(self):
        for rule in test_apt_vendors.RULES:
            target = test_apt_vendors.vendor_package(rule)
            old = dict(target, version=target['version'].replace('-31+', '-30+', 1))
            old['source_version'] = old['version']
            inv = test_apt_vendors.vendor_inventory(rule, [old])
            with mock.patch.object(guard, 'native_compare', side_effect=test_apt_vendors.compare_fixture):
                result = guard.build_plan(inv, [], {'php7.4-cli': [target]}, test_apt_vendors.POLICY)
            self.assertEqual(1, len(result['updates']), rule)
            for unapproved in ('7.4.33-1+deb11u10', '7.4.3-4ubuntu2.29', '1:7.4.33-30+local1'):
                old.update(version=unapproved, source_version=unapproved)
                with mock.patch.object(guard, 'native_compare', side_effect=AssertionError('must reject before compare')):
                    result = guard.build_plan(inv, [], {'php7.4-cli': [target]}, test_apt_vendors.POLICY)
                self.assertFalse(result['updates'])
                self.assertTrue(result['blockers'])

    def test_remi_proof_is_bound_to_the_exact_host_package_key_and_cves(self):
        policy = guard.RP_REMI_POLICY
        key = policy['keys']['9']
        package = dict(name='php-cli', source='php', arch='x86_64', upstream='7.4.33',
                       version='7.4.33-31.module_php.7.4.el9.remi', trusted=True)
        inv = dict(os=dict(id='rocky', version_id='9.6'), package_manager='dnf', packages=[package])
        proof = dict(kind='remi-rpm', signature_verified=True, key_sha256=key['sha256'],
            key_fingerprint=key['fingerprints'][0], artifact_sha256='a' * 64,
            os_id='rocky', os_major='9', source='php', package_name='php-cli',
            version=package['version'], arch='x86_64', cves=guard.CVES, installed_match=True)
        package['vendor_provenance'] = proof
        self.assertEqual('fixed', guard.package_status(package, inv, {})[0])
        for field in proof:
            if field == 'installed_match': continue  # enforced by native enrichment, not candidates
            changed = copy.deepcopy(package)
            changed['vendor_provenance'][field] = None
            self.assertNotEqual('fixed', guard.package_status(changed, inv, {})[0], field)
        for os_id, release in [('amzn', '2023'), ('rocky', '8.10'), ('custom', '9')]:
            different = dict(inv, os=dict(id=os_id, version_id=release))
            self.assertNotEqual('fixed', guard.package_status(package, different, {})[0])
        for source in ('php74-php', 'php-custom'):
            self.assertNotEqual('fixed', guard.package_status(dict(package, source=source), inv, {})[0])
        for old_version, allowed in [('7.4.33-30.module_php.7.4.el9.remi', True),
                                     ('7.4.13-1.module_php.7.4.el9.remi', True),
                                     ('7.4.33-30.el9.remi', False),
                                     ('7.4.33-1.el9', False), ('7.4.33-30.module_php.7.4.el8.remi', False)]:
            self.assertEqual(allowed, guard.vendor_candidate_same_lineage(dict(package, version=old_version), package, inv, {}))

    def test_support_output_does_not_require_root_or_network(self):
        with mock.patch.object(guard, 'say') as output, \
             mock.patch.object(guard.os, 'geteuid', side_effect=AssertionError('no privilege requirement')), \
             mock.patch.object(guard, 'run_cmd', side_effect=AssertionError('no commands')):
            self.assertEqual(0, guard.php74_patch_main(['--support']))
        report = json.loads(output.call_args[0][0])
        self.assertEqual('1.7.2', report['version'])
        self.assertEqual(3, len(report['local_source_routes']))
        self.assertIn('apk', report['detection_only'])
