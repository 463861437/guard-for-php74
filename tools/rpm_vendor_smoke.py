#!/usr/bin/env python3
"""CI-only real DNF/RPM signature smoke test. Never installs PHP packages.

Run on a clean EL 8/9/10 host with Remi already configured and the remi-7.4
module enabled. Exercises the production worker, pinned signature verification,
metadata matching, package-status policy and candidate selection. A successful
result is not deployment or application validation.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('php_guard_smoke', str(ROOT / 'php_guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def public_keys():
    return subprocess.check_output(['/usr/bin/rpm', '-qa', 'gpg-pubkey*', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}\n']).decode().splitlines()


def main():
    host = guard._inv_os()
    major = host.get('version_id', '').split('.')[0]
    if host.get('id') not in ('rocky', 'almalinux', 'centos', 'rhel') or major not in ('8', '9', '10'):
        raise SystemExit('This CI smoke test requires clean EL 8, 9 or 10.')
    arch = os.uname()[4]
    old = '7.4.33-29.module_php.7.4.el%s.remi' % major
    inv = dict(os=host, package_manager='dnf', packages=[
        dict(name=name, arch=arch, upstream='7.4.33', source='php', version=old)
        for name in ('php-cli', 'php-common')])
    before = sorted(public_keys())
    candidates = guard.rpm_candidates(inv)
    result = []
    for name in ('php-cli', 'php-common'):
        fixed = [item for item in candidates[name] if item.get('vendor_provenance')]
        if not fixed:
            raise AssertionError('No vendor-verified candidate returned for ' + name)
        for package in fixed:
            proof = package['vendor_provenance']
            assert proof['signature_verified'] is True
            assert proof['installed_match'] is False, 'This smoke test must not have PHP installed'
            assert proof['source'] == 'php' and proof['os_major'] == major
            status, reason = guard.package_status(package, inv, guard.POLICY)
            assert status == 'fixed', (status, reason)
            result.append(dict(name=name, version=package['version'], proof=proof, status=status, reason=reason))
    after = sorted(public_keys())
    assert before == after, 'Candidate verification modified the system RPM keyring'
    print(json.dumps(dict(kind='native_rpm_candidate_signature_smoke', host=host, architecture=arch,
                          php_installed=False, deployment_tested=False, system_keyring_unchanged=True,
                          candidates=result), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
