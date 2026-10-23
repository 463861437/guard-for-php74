"""Remi proof boundaries; no system packages, keys or repositories are modified."""
import copy
import hashlib
import json
import os
import pathlib
import sys
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
module = {'__name__': 'remi_proof_backend_test'}
exec((ROOT / 'src/rpm_provenance.py').read_text(), module)
module['RP_REMI_POLICY'] = json.loads((ROOT / 'remi-policy.json').read_text())
exec((ROOT / 'src/rpm_backend.py').read_text(), module)
worker = {'__name__': 'remi_proof_worker_test'}
exec(compile(module['_RPM_WORKER'], '<rpm-remi-worker>', 'exec'), worker)


class Package:
    def __init__(self, name='php-cli', revision=31, major=9, source='php', arch='x86_64'):
        self.name, self.version, self.arch = name, '7.4.33', arch
        self.epoch, self.repoid = 0, 'remi-modular'
        self.release = '%s.%sel%s.remi' % (revision, 'module_php.7.4.' if source == 'php' else '', major)
        self.sourcerpm = '%s-%s-%s.src.rpm' % (source, self.version, self.release)


def fake_compare(a, b):
    def parts(value):
        epoch, version, release = value
        return int(epoch), version, int(release.split('.')[0])
    return (parts(a) > parts(b)) - (parts(a) < parts(b))


class RemiPolicyTests(unittest.TestCase):
    host = {'os_id': 'rocky', 'os_major': '9'}

    def test_pinned_keys_match_bytes_and_distinct_major_fingerprints(self):
        keys = worker['RP_REMI_POLICY']['keys']
        self.assertEqual({'8', '9', '10'}, set(keys))
        for major, key in keys.items():
            self.assertEqual(key['sha256'], hashlib.sha256(key['armor'].encode('ascii')).hexdigest())
            self.assertEqual(2, len(key['fingerprints']))
            self.assertTrue(all(len(value) == 40 for value in key['fingerprints']))
            self.assertIn('/enterprise/' + major + '/', key['url'])

    def test_exact_native_and_scl_build_families(self):
        for major in (8, 9, 10):
            for source in ('php', 'php74-php'):
                for arch in ('x86_64', 'aarch64', 'noarch'):
                    self.assertTrue(worker['rp_eligible'](Package(major=major, source=source, arch=arch),
                                                        {'os_major': str(major)}))

    def test_el7_other_abi_old_revision_and_custom_builds_rejected(self):
        self.assertFalse(worker['rp_eligible'](Package(major=8), self.host))
        self.assertFalse(worker['rp_eligible'](Package(revision=30), self.host))
        self.assertFalse(worker['rp_eligible'](Package(major=7), self.host))
        self.assertFalse(worker['rp_eligible'](Package(arch='i686'), self.host))
        self.assertFalse(worker['rp_eligible'](Package(source='php-custom'), self.host))
        self.assertFalse(worker['rp_eligible'](Package(), None))
        for field, value in [('version', '7.4.34'), ('epoch', 1), ('release', '31.module_php.7.4.el9.remi.custom')]:
            pkg = Package(); setattr(pkg, field, value)
            self.assertFalse(worker['rp_eligible'](pkg, self.host))

    def test_signature_requires_pinned_signer_and_success_not_digest_only(self):
        key = worker['RP_REMI_POLICY']['keys']['9']
        valid = 'Header V4 RSA/SHA256 Signature, key ID 478f8947: OK\nPayload SHA256 digest: OK\n'
        self.assertTrue(worker['rp_signature_output'](0, valid, key))
        self.assertFalse(worker['rp_signature_output'](1, valid, key))
        for output in ('Payload SHA256 digest: OK', valid + 'NOKEY', valid.replace('478f8947', '5f11735a'),
                       valid.replace(': OK', ': BAD'), valid + 'Header V4 RSA/SHA256 Signature, key ID deadbeef: OK'):
            self.assertFalse(worker['rp_signature_output'](0, output, key))

    def test_host_is_read_from_os_release_not_id_like(self):
        values = ['ID=rocky\nVERSION_ID="9.5"\n', 'ID=amzn\nVERSION_ID=2023\nID_LIKE="rhel fedora"\n',
                  'ID=centos\nVERSION_ID=7.9\n', 'ID=custom\nVERSION_ID=9\nID_LIKE=rhel\n']
        for index, content in enumerate(values):
            with mock.patch('builtins.open', mock.mock_open(read_data=content)):
                result = worker['rp_host']()
                self.assertEqual(self.host if index == 0 else None, result)

    def test_only_newest_complete_set_and_installed_version_are_downloaded(self):
        available = {'php-cli': [Package(revision=x) for x in (29,31,32,33)],
                     'php-common': [Package(name='php-common', revision=x) for x in (29,31,32)]}
        inventory = {'packages': [dict(name=name, arch='x86_64', upstream='7.4.33', source='php',
                                      version='7.4.33-31.module_php.7.4.el9.remi') for name in available]}
        base = types.SimpleNamespace(download_packages=mock.Mock())
        prove = mock.Mock(return_value={'signature_verified': True})
        with mock.patch.dict(worker, rp_prove_package=prove), mock.patch.dict(sys.modules, rpm=types.SimpleNamespace(labelCompare=fake_compare)):
            result = worker['rp_candidate_map'](base, inventory, available, self.host)
        downloaded = base.download_packages.call_args[0][0]
        self.assertEqual(4, len(downloaded))
        self.assertEqual({'31', '32'}, {p.release.split('.')[0] for p in downloaded})
        self.assertEqual(4, prove.call_count)
        self.assertNotIn('vendor_provenance', result['php-cli'][-1])
        self.assertNotIn('vendor_provenance', result['php-cli'][0])

    def test_missing_family_member_does_not_approve_a_partial_new_build(self):
        pkg = Package()
        inventory = {'packages': [dict(name=name, arch='x86_64', source='php', upstream='7.4.33',
                                      version='7.4.33-29.module_php.7.4.el9.remi') for name in ('php-cli', 'php-common')]}
        base = types.SimpleNamespace(download_packages=mock.Mock())
        with mock.patch.dict(sys.modules, rpm=types.SimpleNamespace(labelCompare=fake_compare)):
            result = worker['rp_candidate_map'](base, inventory, {'php-cli': [pkg], 'php-common': []}, self.host)
        base.download_packages.assert_not_called()
        self.assertNotIn('vendor_provenance', result['php-cli'][0])

    def test_preview_and_execution_revalidate_every_proof_field(self):
        pkg = Package()
        proof = dict(kind='remi-rpm', signature_verified=True, key_sha256='key', key_fingerprint='fingerprint',
                     artifact_sha256='rpm', os_id='rocky', os_major='9', source='php', package_name='php-cli',
                     version=worker['evr'](pkg), arch='x86_64', cves=['CVE-2026-109618','CVE-2026-109619'])
        desired = {('php-cli','x86_64'): {'vendor_provenance': proof}}
        base = types.SimpleNamespace(download_packages=mock.Mock())
        with mock.patch.dict(worker, rp_host=lambda: self.host, rp_prove_package=lambda *a, **kw: proof):
            worker['rp_revalidate_selected'](base, [pkg], desired)
        for key in proof:
            changed = dict(proof, **{key: 'changed'})
            with mock.patch.dict(worker, rp_host=lambda: self.host, rp_prove_package=lambda *a, **kw: changed):
                with self.assertRaises(RuntimeError, msg=key):
                    worker['rp_revalidate_selected'](base, [pkg], desired)


class InstalledContentTests(unittest.TestCase):
    def setUp(self):
        self.header = dict(name='php-cli', epoch=0, version='7.4.33', release='31.module_php.7.4.el9.remi',
                           arch='x86_64', sourcerpm='php-7.4.33-31.module_php.7.4.el9.remi.src.rpm',
                           filenames=['/usr/bin/php'], filedigests=['abc'], filedigestalgo=8,
                           fileflags=[0], filemodes=[33261], filelinktos=[''], fileusername=['root'],
                           filegroupname=['root'], filecaps=[''])

    def verify(self, installed=None, response=(0,'','')):
        installed = copy.deepcopy(self.header) if installed is None else installed
        ts = types.SimpleNamespace(dbMatch=lambda *args: [installed])
        with mock.patch.dict(sys.modules, rpm=types.SimpleNamespace(TransactionSet=lambda *args: ts)), \
             mock.patch.dict(worker, rp_command=lambda *args: response):
            return worker['rp_installed_matches'](self.header, '/usr/bin/rpm')

    def test_matching_signed_metadata_and_clean_files_are_required(self):
        self.assertTrue(self.verify())
        self.assertTrue(self.verify(response=(1,'S.5....T.  c /etc/php.ini\n','')))
        for field, value in [('filedigests', ['tampered']), ('sourcerpm','custom.src.rpm'),
                             ('filemodes',[33279]), ('filecaps',['cap_sys_admin+ep']), ('version','7.4.34')]:
            changed = dict(self.header, **{field: value})
            self.assertFalse(self.verify(installed=changed))

    def test_nonconfig_changes_missing_files_or_verifier_failure_block(self):
        for response in [(1,'S.5....T.    /usr/bin/php\n',''), (1,'missing     /usr/bin/php\n',''), (1,'',''),
                         (1,'','permission denied'), (2,'',''), (1,'unrecognized output\n','')]:
            self.assertFalse(self.verify(response=response))


class RemiSclServiceTests(unittest.TestCase):
    def test_native_scl_fpm_unit_uses_existing_config_preflight(self):
        # Actual 7.4.33-31.el9.remi unit: direct binary, no EnvironmentFile.
        service = {'__name__': 'scl_service_test'}
        exec((ROOT / 'src/service_ops.py').read_text(), service)
        binary = '/opt/remi/php74/root/usr/sbin/php-fpm'
        properties = {'ExecStart': '{ path=' + binary + '; argv[]=' + binary + ' --nodaemonize ; }'}
        with mock.patch.dict(service, _inv_trusted_executable=lambda path: (path == binary, None)), \
             mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(service['_svc_fpm']('php74-php-fpm.service'))
            self.assertEqual([binary, '-t'], service['_svc_fpm_test_argv'](properties))
            properties['Environment'] = 'PHPRC=/unexpected'
            with self.assertRaises(ValueError):
                service['_svc_fpm_test_argv'](properties)


if __name__ == '__main__':
    unittest.main()
