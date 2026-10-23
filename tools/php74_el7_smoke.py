#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build the production PHP 7.4 Remi recipe in disposable native EL7 CI.

This fixture never installs its generated PHP RPMs. Archive repositories and
signing keys are configured only inside the explicitly marked container.
"""
from __future__ import print_function

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = '/var/lib/phpguard-php74-ci'
WORK = '/home/phpguardbuild/php74-ci'
BUNDLE = '/var/lib/phpguard-php74-ci-build'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def disposable_guard():
    require(sys.platform.startswith('linux') and os.geteuid() == 0 and
            os.path.isfile('/.dockerenv') and
            os.environ.get('PHP_GUARD_DISPOSABLE_PHP74_EL7_CI') == '1',
            'This fixture requires its explicitly marked disposable root Docker container.')
    with open('/etc/os-release') as handle:
        host = dict(line.strip().split('=', 1) for line in handle if '=' in line)
    require(host.get('ID', '').strip('"') == 'centos' and
            host.get('VERSION_ID', '').strip('"') == '7' and os.uname()[4] == 'x86_64',
            'Only the native CentOS 7 x86_64 fixture is supported.')
    if not os.path.isdir(STATE):
        os.mkdir(STATE, 0o700)


def load_file(path, name):
    namespace = {'__name__': name, '__file__': path}
    with open(path, 'rb') as handle:
        exec(compile(handle.read(), path, 'exec'), namespace)
    return namespace


def bootstrap():
    # Reuse the reviewed CI-only signing-key pins, TLS and archive policy. Only
    # the fixture state directory and PHP branch repository differ.
    helper = load_file(os.path.join(ROOT, 'tools', 'php82_el7_smoke.py'), 'php74_ci_bootstrap')
    helper['STATE'] = STATE
    helper['disposable_guard'] = disposable_guard
    helper['REPOSITORIES'] = tuple(
        ('remi-php74', 'https://rpms.remirepo.net/enterprise/7/php74/x86_64/', row[2])
        if row[0] == 'remi-php82' else row for row in helper['REPOSITORIES'])
    helper['bootstrap']()
    # httpd is an explicit build fixture, never an implicit production change.
    # Match the installer's preferred Python 3 orchestration; YUM uses Python 2.
    helper['command'](['/usr/bin/yum', '-y', '--noplugins', 'install', 'httpd', 'python3'])


def php_headers():
    output = subprocess.check_output(['rpm', '-qa', '--qf',
                                     '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\t%{SHA1HEADER}\n'])
    return sorted(row for row in output.decode('ascii').splitlines()
                  if row.split('\t', 1)[0].startswith('php'))


def completed_report(guard):
    matches = glob.glob(os.path.join(WORK, 'build-*', 'build.json'))
    require(len(matches) == 1, 'This fresh CI build must produce exactly one build report.')
    report = guard['bi_read_json'](matches[0])
    guard['BI_ACTIVE_RECIPE'] = guard['RB_RECIPE']
    guard['bi_validate_build'](report)
    return matches[0], report


def build(jobs):
    require(sys.version_info[0] == 3, 'Run the production build orchestration with the fixture Python 3.')
    guard = load_file(os.path.join(ROOT, 'php_guard.py'), 'php74_native_ci')
    before = php_headers()
    os.environ['PHP_GUARD_LAUNCHER'] = os.path.join(ROOT, 'php-cve-guard.sh')
    code = guard['native_build_main']('remi', [
        'all', '--yes', '--build-user', 'phpguardbuild', '--work-dir', WORK,
        '--jobs', str(jobs), '--lock-wait', '120', '--build-repo', 'remi',
        '--progress-interval', '30', '--build-timeout', '18000'])
    require(code == 0, 'Production PHP 7.4 native setup/build failed.')
    path, report = completed_report(guard)
    build_dir = os.path.dirname(path)
    summary = guard['bp_selftest_summary'](os.path.join(build_dir, 'build.log'))
    require(summary == report['php_selftest_summary'], 'Full test log differs from its report.')
    artifacts = guard['rb_check_artifacts'](
        sorted(glob.glob(os.path.join(build_dir, 'rpmbuild', 'RPMS', '*', '*.rpm'))), '/usr/bin/rpm')
    require(artifacts == report['artifacts'], 'Native RPM metadata or payload checksums changed.')
    require(php_headers() == before, 'Build setup or compilation changed installed PHP packages.')
    result = dict(kind='native_php74_el7_build_only', source_version=guard['RB_VERSION'],
                  build_report=path, source_sha256=report['source_sha256'],
                  spec_sha256=report['spec_sha256'], artifact_count=len(artifacts),
                  php_selftest_summary=summary,
                  mitigation_smoke_tests=report['mitigation_smoke_tests'],
                  multipart_smoke_tests=report['multipart_smoke_tests'],
                  native_prep_and_full_build_passed=True, php_runtime_packages_unchanged=True,
                  generated_packages_installed=False, source_signature_verified=False,
                  source_provenance='Pinned BaoTa HTTPS source and Remi packaging hashes; local unsigned RPMs.',
                  systemd_lifecycle_tested=False, business_tested=False)
    with open(os.path.join(STATE, 'result.json'), 'w') as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def collect_evidence():
    for build_dir in glob.glob(os.path.join(WORK, 'build-*')):
        destination = os.path.join(STATE, 'build-evidence', os.path.basename(build_dir))
        if not os.path.isdir(destination):
            os.makedirs(destination, 0o700)
        for name in ('build.json', 'prep.log', 'build.log'):
            source = os.path.join(build_dir, name)
            if os.path.isfile(source) and not os.path.islink(source):
                shutil.copyfile(source, os.path.join(destination, name))
    guard = load_file(os.path.join(ROOT, 'php_guard.py'), 'php74_export_ci')
    reports = glob.glob(os.path.join(WORK, 'build-*', 'build.json'))
    if len(reports) != 1 or guard['bi_read_json'](reports[0]).get('state') != 'built_not_deployed':
        return
    path, report = completed_report(guard)
    build_dir = os.path.dirname(path)
    copies = [(path, 'build.json', None), (os.path.join(build_dir, 'build.log'), 'build.log', None),
              (os.path.join(build_dir, 'prep.log'), 'prep.log', None),
              (os.path.join(build_dir, 'rpmbuild', 'SPECS', 'php74-baota.spec'),
               'rpmbuild/SPECS/php74-baota.spec', report['spec_sha256'])]
    copies.extend((os.path.join(WORK, 'inputs', name), 'inputs/' + name, digest)
                  for name, digest in guard['rb_input_hashes']().items())
    copies.extend((os.path.join(build_dir, 'rpmbuild', 'RPMS', row['arch'], row['file']),
                   'rpmbuild/RPMS/' + row['arch'] + '/' + row['file'], row['sha256'])
                  for row in report['artifacts'])
    source_rpm = report['source_rpm']
    expected = 'php-' + guard['RB_VERSION'] + '-' + guard['RB_RELEASE'] + '.src.rpm'
    require(source_rpm['file'] == expected, 'Unexpected source RPM identity.')
    copies.append((os.path.join(build_dir, 'rpmbuild', 'SRPMS', expected),
                   'rpmbuild/SRPMS/' + expected, source_rpm['sha256']))
    for source, relative, expected_hash in copies:
        target = os.path.join(BUNDLE, relative)
        if not os.path.isdir(os.path.dirname(target)):
            os.makedirs(os.path.dirname(target), 0o700)
        guard['r82_copy_input'](source, target, 512 * 1024 * 1024, expected_hash)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['all', 'build'])
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    require(1 <= args.jobs <= 8, 'Invalid CI concurrency.')
    disposable_guard()
    if args.action == 'all':
        bootstrap()
        return subprocess.call(['/usr/bin/python3', os.path.abspath(__file__), 'build',
                                '--jobs', str(args.jobs)])
    try:
        build(args.jobs)
    finally:
        collect_evidence()
    return 0


if __name__ == '__main__':
    sys.exit(main())
