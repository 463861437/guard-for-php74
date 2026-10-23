#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Real PHP 8.2 EL7 build/install fixture; never run this on a server.

The archived repositories below are configured only after the container guard
passes. Production setup never changes repository files or imports these keys.
"""
from __future__ import print_function

import argparse
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = '/var/lib/phpguard-php82-ci'
BUNDLES = '/var/lib/phpguard-php82-ci-builds'
KEYS = (
    ('RPM-GPG-KEY-CentOS-7', None,
     '8b48b04b336bd725b9e611c441c65456a4168083c4febc28e88828d8ec14827f'),
    ('RPM-GPG-KEY-EPEL-7', 'https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7',
     '028b9accc59bab1d21f2f3f544df5469910581e728a64fd8c411a725a82300c2'),
    ('RPM-GPG-KEY-remi', 'https://rpms.remirepo.net/RPM-GPG-KEY-remi',
     'b0d1d4ca043e2bd60ff71899b5c0145af64f9c0ec6f2073357dfb64deada59e4'),
    ('RPM-GPG-KEY-remi2018', 'https://rpms.remirepo.net/RPM-GPG-KEY-remi2018',
     '01992da5a631f40d0c733441f8623e0ceddcb98541b70ad528c51f04877875fb'),
)
REPOSITORIES = (
    ('base', 'https://vault.centos.org/7.9.2009/os/x86_64/', 'RPM-GPG-KEY-CentOS-7'),
    ('updates', 'https://vault.centos.org/7.9.2009/updates/x86_64/', 'RPM-GPG-KEY-CentOS-7'),
    ('extras', 'https://vault.centos.org/7.9.2009/extras/x86_64/', 'RPM-GPG-KEY-CentOS-7'),
    ('epel', 'https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/', 'RPM-GPG-KEY-EPEL-7'),
    ('remi', 'https://rpms.remirepo.net/enterprise/7/remi/x86_64/', 'RPM-GPG-KEY-remi'),
    ('remi-safe', 'https://rpms.remirepo.net/enterprise/7/safe/x86_64/', 'RPM-GPG-KEY-remi'),
    ('remi-php82', 'https://rpms.remirepo.net/enterprise/7/php82/x86_64/', 'RPM-GPG-KEY-remi'),
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(argv):
    print('CI command: ' + ' '.join(argv))
    sys.stdout.flush()
    subprocess.check_call(argv)


def digest(path):
    result = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1048576), b''):
            result.update(block)
    return result.hexdigest()


def disposable_guard():
    require(sys.platform.startswith('linux') and os.geteuid() == 0 and
            os.path.isfile('/.dockerenv') and
            os.environ.get('PHP_GUARD_DISPOSABLE_PHP82_EL7_CI') == '1',
            'This fixture only runs as root in its explicitly marked disposable Docker container.')
    with open('/etc/os-release') as handle:
        host = dict(line.strip().split('=', 1) for line in handle if '=' in line)
    require(host.get('ID', '').strip('"') == 'centos' and
            host.get('VERSION_ID', '').strip('"') == '7' and os.uname()[4] == 'x86_64',
            'This fixture requires the CentOS 7 x86_64 container image.')
    if not os.path.isdir(STATE):
        os.mkdir(STATE, 0o700)


def bootstrap():
    """Use official archives in this fixture, with pinned keys and GPG checks."""
    disposable_guard()
    backup = os.path.join(STATE, 'original-repos')
    if not os.path.isdir(backup):
        os.mkdir(backup, 0o700)
        for path in glob.glob('/etc/yum.repos.d/*.repo'):
            shutil.move(path, os.path.join(backup, os.path.basename(path)))
    for name, url, expected in KEYS:
        path = '/etc/pki/rpm-gpg/' + name
        if url:
            command(['/usr/bin/curl', '-fL', '--proto', '=https', '--proto-redir', '=https',
                     '--connect-timeout', '20', '--max-time', '120', '--retry', '2', url, '-o', path])
        require(digest(path) == expected, 'Pinned CI repository signing key differs: ' + name)
        command(['/usr/bin/rpm', '--import', path])
    with open('/etc/yum.repos.d/phpguard-ci.repo', 'w') as handle:
        for name, baseurl, key in REPOSITORIES:
            handle.write('[%s]\nname=PHP Guard disposable CI %s\nbaseurl=%s\n'
                         'enabled=1\ngpgcheck=1\nsslverify=1\nskip_if_unavailable=0\n'
                         'gpgkey=file:///etc/pki/rpm-gpg/%s\n\n' % (name, name, baseurl, key))
    command(['/usr/bin/yum', '-y', '--noplugins', 'install',
             'ca-certificates', 'python', 'rpm-build', 'yum-utils', 'sudo', 'shadow-utils',
             'gnupg2', 'curl', 'patch', 'procps-ng', 'which', 'findutils', 'tar', 'xz'])
    try:
        import pwd
        account = pwd.getpwnam('phpguardbuild')
        require(account.pw_uid != 0, 'CI build account must not be root.')
    except KeyError:
        command(['/usr/sbin/useradd', '--create-home', '--shell', '/bin/bash', 'phpguardbuild'])
    print(json.dumps(dict(stage='ci_bootstrap_complete', production_repository_changes=False,
                          fixture_repositories=[row[0] for row in REPOSITORIES],
                          pinned_keys=True, gpgcheck=True, sslverify=True), sort_keys=True))


def load_guard():
    namespace = {'__name__': 'php82_el7_native_smoke', '__file__': os.path.join(ROOT, 'php_guard.py')}
    with open(namespace['__file__'], 'rb') as handle:
        exec(compile(handle.read(), namespace['__file__'], 'exec'), namespace)
    return namespace


def package_inventory(guard):
    # This fixture exercises the package transaction API, not systemd lifecycle
    # orchestration. Inventory is collected from the real RPM DB; services and
    # container detection are deliberately outside this API-level test scope.
    warnings = []
    manager, packages, unused_dpkg, unused_rpm = guard['_inv_packages'](warnings)
    require(not warnings and manager == 'yum', 'Native RPM inventory must be complete.')
    return dict(os=guard['_inv_os'](), package_manager=manager, packages=packages,
                runtimes=[], services=[], processes=[], containers=[], warnings=[])


def runtime_paths(layout):
    if layout == 'system':
        return '/usr/bin/php', '/usr/sbin/php-fpm', '/etc/php.ini', '/etc/php-fpm.d/www.conf'
    return ('/opt/remi/php82/root/usr/bin/php', '/opt/remi/php82/root/usr/sbin/php-fpm',
            '/etc/opt/remi/php82/php.ini', '/etc/opt/remi/php82/php-fpm.d/www.conf')


def runtime_details(layout):
    php = runtime_paths(layout)[0]
    code = ('echo json_encode(array("version"=>PHP_VERSION,"config"=>PHP_CONFIG_FILE_PATH,'
            '"scan"=>PHP_CONFIG_FILE_SCAN_DIR,"extensions"=>PHP_EXTENSION_DIR,'
            '"modules"=>get_loaded_extensions()));')
    value = json.loads(subprocess.check_output([php, '-r', code]).decode('utf-8'))
    value['modules'] = sorted(value['modules'])
    return value


def abi_provides(layout):
    package = 'php-common' if layout == 'system' else 'php82-php-common'
    rows = subprocess.check_output(['rpm', '-q', '--provides', package]).decode('ascii').splitlines()
    return sorted(row for row in rows if '(api)' in row or '(zend-abi)' in row)


def fixture(layouts):
    # httpd is an explicit pre-existing fixture. Production dependency setup
    # must continue refusing to introduce or replace a web server implicitly.
    command(['/usr/bin/yum', '-y', '--noplugins', 'install', 'httpd'])
    names = []
    for layout in layouts:
        prefix = '' if layout == 'system' else 'php82-'
        for component in ('cli', 'common', 'fpm', 'opcache', 'pdo', 'mysqlnd',
                          'mbstring', 'xml', 'gd', 'intl', 'bcmath', 'sodium'):
            names.append(prefix + 'php-' + component + '-8.2.20-1.el7.remi')
        names.append(prefix + 'php-pecl-redis6')
    command(['/usr/bin/yum', '-y', '--noplugins', 'install'] + names)
    guard = load_guard()
    inv = package_inventory(guard)
    require(set(guard['r82_layouts'](inv)) == set(layouts),
            'The runtime fixture layouts differ from the requested build layouts.')
    configs = {}
    for layout in layouts:
        for path in runtime_paths(layout)[2:]:
            with open(path, 'a') as handle:
                handle.write('\n; PHP Guard CI configuration preservation marker\n')
            configs[path] = digest(path)
    result = dict(extensions=guard['r82_extension_headers'](inv),
                  core=sorted(row['name'] for row in guard['r82_core_packages'](inv)),
                  configs=configs, runtimes=dict((layout, runtime_details(layout)) for layout in layouts),
                  abi=dict((layout, abi_provides(layout)) for layout in layouts))
    require(all(row['version'] == '8.2.20' for row in result['runtimes'].values()),
            'The installed fixture must start at PHP 8.2.20.')
    require(all('redis' in row['modules'] for row in result['runtimes'].values()),
            'The fixture must exercise a real separately packaged Redis extension.')
    require(all(result['abi'].values()), 'The fixture must expose real PHP/Zend ABI provides.')
    with open(os.path.join(STATE, 'before.json'), 'w') as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
    return result


def build(layouts, jobs):
    guard = load_guard()
    os.environ['PHP_GUARD_LAUNCHER'] = os.path.join(ROOT, 'php-cve-guard.sh')
    argv = ['all', '--yes', '--build-user', 'phpguardbuild', '--work-dir',
            '/home/phpguardbuild/php82-ci', '--jobs', str(jobs), '--lock-wait', '120',
            '--progress-interval', '30', '--build-timeout', '18000']
    for layout in layouts:
        argv.extend(['--layout', layout])
    require(guard['native_build_main']('remi82', argv) == 0,
            'The production native build/setup workflow did not finish successfully.')
    reports = guard['NB_LAST_BUILD_REPORTS']
    require(len(reports) == len(layouts), 'One successful build report per layout is required.')
    with open(os.path.join(STATE, 'reports.json'), 'w') as handle:
        json.dump(reports, handle)
    return reports


def verify_install(layouts, reports=None):
    guard = load_guard()
    if reports is None:
        with open(os.path.join(STATE, 'reports.json')) as handle:
            reports = json.load(handle)
    with open(os.path.join(STATE, 'before.json')) as handle:
        before = json.load(handle)
    folder = tempfile.mkdtemp(prefix='install-', dir=STATE)
    artifacts = guard['r82_stage'](reports, folder)
    inv = package_inventory(guard)
    # Setup may add the one pinned SCL build-macro package after the original
    # runtime snapshot. Preserve every original extension/wrapper, then compare
    # all headers immediately before and after the PHP installation itself.
    before_install_extensions = guard['r82_extension_headers'](inv)
    original_headers = dict(((row['name'], row['arch']), row) for row in before['extensions'])
    current_headers = dict(((row['name'], row['arch']), row) for row in before_install_extensions)
    require(all(current_headers.get(key) == row for key, row in original_headers.items()),
            'Build setup changed a pre-existing extension or SCL wrapper.')
    added_build_packages = [row for key, row in current_headers.items() if key not in original_headers]
    require(all('scl' in layouts and row['name'] == 'php82-build' and
                row['arch'] == 'x86_64' and row['version'] == '8.2' and
                row['release'] == '5.el7.remi' and
                row['source_rpm'] == 'php82-8.2-5.el7.remi.src.rpm'
                for row in added_build_packages),
            'Build setup added an unexpected PHP extension or wrapper.')
    with open(os.path.join(folder, 'before-install-extensions.json'), 'w') as handle:
        json.dump(dict(headers=before_install_extensions, setup_additions=added_build_packages),
                  handle, indent=2, sort_keys=True)
    plan = guard['r82_plan'](inv, artifacts)
    require(not plan['blockers'] and plan['updates'], 'Production package plan was blocked: ' + json.dumps(plan['blockers']))
    require(sorted(row['name'] for row in plan['updates']) == before['core'],
            'The plan must upgrade exactly the pre-existing PHP core packages.')
    preview = guard['r82_transaction'](plan['updates'], folder, lock_wait=120)
    require(preview.get('ok') is True and not preview.get('executed'),
            'Native RPM test transaction failed: ' + str(preview.get('error')))
    applied = guard['r82_transaction'](plan['updates'], folder, execute=True, lock_wait=120)
    require(applied.get('ok') is True and applied.get('executed') is True,
            'Native RPM upgrade transaction did not complete: ' + str(applied.get('error')))
    after = package_inventory(guard)
    require(guard['r82_extension_headers'](after) == before_install_extensions,
            'Third-party extensions or SCL wrapper packages changed.')
    require(sorted(row['name'] for row in guard['r82_core_packages'](after)) == before['core'],
            'A new SAPI/core package was installed or an existing package was removed.')
    for path, expected in before['configs'].items():
        require(digest(path) == expected, 'An existing modified INI/FPM configuration was overwritten.')
    for layout in layouts:
        after_runtime = runtime_details(layout)
        require(after_runtime['version'] == guard['R82_VERSION'], 'The installed PHP version differs from the build.')
        require(all(after_runtime[key] == before['runtimes'][layout][key]
                    for key in ('config', 'scan', 'extensions', 'modules')),
                'PHP configuration/module layout or loaded extensions changed.')
        require(abi_provides(layout) == before['abi'][layout], 'PHP/Zend RPM ABI provides changed.')
        require('zend_test' not in after_runtime['modules'] and
                not os.path.lexists(os.path.join(after_runtime['extensions'], 'zend_test.so')),
                'A test-only zend_test module reached the installed runtime.')
        command([runtime_paths(layout)[1], '-t'])
    receipt = guard['r82_save_receipt'](artifacts)
    findings = guard['r82_assess'](after, receipt)
    core = set(before['core'])
    assessed = dict((row.get('package_name'), row.get('status')) for row in findings
                    if row.get('kind') == 'package' and row.get('package_name') in core)
    require(set(assessed) == core and all(value == 'fixed' for value in assessed.values()),
            'Installed core payloads failed accepted-build assessment.')
    summaries = []
    for path in reports:
        with open(path) as handle:
            report = json.load(handle)
        summaries.append(dict(layout=report['layout'], full_tests=report['php_selftest_summary'],
                              security_tests=report['security_test_summary'],
                              source_signature_verified=report['source_signature_verified'],
                              artifact_count=len(report['artifacts'])))
    result = dict(kind='native_php82_el7_build_and_package_upgrade', layouts=layouts,
                  full_builds=summaries, source_version=guard['R82_VERSION'],
                  upgraded_package_count=len(plan['updates']), native_rpm_transaction_passed=True,
                  config_and_installation_paths_preserved=True, php_zend_abi_preserved=True,
                  third_party_extensions_and_wrappers_unchanged=True, loaded_extensions_preserved=True,
                  pinned_build_macro_packages_added_by_setup=added_build_packages,
                  no_new_sapis_installed=True, fpm_config_test_passed=True,
                  test_only_module_not_installed=True,
                  installed_payload_and_receipt_verified=True, production_server_modified=False,
                  systemd_lifecycle_tested=False, business_tested=False)
    with open(os.path.join(STATE, 'result.json'), 'w') as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def export_build_bundles(layouts):
    """Export only complete builds and explicitly selected public build files.

    The resulting tree can be moved to another identical EL7 fixture and fed to
    the production r82_stage API. Its verification remains mandatory there.
    Private GnuPG homes, environment files and compiler work trees are excluded.
    """
    guard = load_guard()
    for layout in layouts:
        for build_dir in glob.glob('/home/phpguardbuild/php82-ci/' + layout + '/build-*'):
            report_path = os.path.join(build_dir, 'build.json')
            if not os.path.isfile(report_path):
                continue
            with open(report_path) as handle:
                report = json.load(handle)
            if report.get('state') != 'built_not_deployed':
                continue
            artifacts = guard['r82_validate_build'](report)
            require(report['layout'] == layout, 'The completed report layout differs from its build directory.')
            parent = os.path.join(BUNDLES, layout)
            if not os.path.isdir(parent):
                os.makedirs(parent, 0o700)
            destination = os.path.join(parent, os.path.basename(build_dir))
            require(not os.path.lexists(destination), 'A completed build bundle already exists.')
            temporary = tempfile.mkdtemp(prefix='.export-', dir=parent)
            copies = [('build.json', None, 4 * 1024 * 1024),
                      ('build.log', None, 128 * 1024 * 1024),
                      ('security-tests.log', None, 128 * 1024 * 1024),
                      ('rpmbuild/SPECS/php82-guard.spec', report['spec_sha256'], 4 * 1024 * 1024)]
            copies.extend(('rpmbuild/SOURCES/' + name, expected, 128 * 1024 * 1024)
                          for name, expected in guard['r82_input_hashes'](layout).items())
            copies.extend(('rpmbuild/RPMS/' + row['arch'] + '/' + row['file'],
                           row['sha256'], 512 * 1024 * 1024) for row in artifacts)
            source_rpm = report['source_rpm']
            expected_srpm = '%s-%s-%s.src.rpm' % (guard['r82_profile'](layout)['source_name'],
                                                 guard['R82_VERSION'], guard['R82_RELEASE'])
            require(source_rpm['file'] == expected_srpm, 'The completed source RPM identity differs.')
            copies.append(('rpmbuild/SRPMS/' + expected_srpm, source_rpm['sha256'], 512 * 1024 * 1024))
            try:
                for relative, expected, maximum in copies:
                    target = os.path.join(temporary, relative)
                    if not os.path.isdir(os.path.dirname(target)):
                        os.makedirs(os.path.dirname(target), 0o700)
                    guard['r82_copy_input'](os.path.join(build_dir, relative), target, maximum, expected)
                os.rename(temporary, destination)
            finally:
                if os.path.isdir(temporary):
                    shutil.rmtree(temporary)
            print('Completed public native build bundle: ' + destination)


def bundle_reports(directory, layouts):
    """Locate one unambiguous completed-build report per requested layout."""
    directory = os.path.abspath(directory)
    require(os.path.isdir(directory) and not os.path.islink(directory),
            'Build bundles must be a real directory.')
    reports = []
    for layout in layouts:
        require(layout in ('system', 'scl'), 'Unknown bundle layout.')
        parent = os.path.join(directory, layout)
        require(os.path.isdir(parent) and not os.path.islink(parent),
                'The requested layout bundle is missing or is a symlink: ' + layout)
        matches = glob.glob(os.path.join(parent, 'build-*', 'build.json'))
        require(len(matches) == 1, 'Exactly one build.json per layout is required: ' + layout)
        report = matches[0]
        require(not os.path.islink(os.path.dirname(report)) and not os.path.islink(report) and
                os.path.isfile(report) and
                os.path.realpath(report).startswith(os.path.realpath(parent) + os.sep),
                'The selected build report must be a regular file within its layout bundle.')
        reports.append(report)
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['bootstrap', 'fixture', 'build', 'verify', 'all', 'verify-bundles'])
    parser.add_argument('--layout', action='append', choices=['system', 'scl'])
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--bundle-dir', help='Read-only directory containing one completed build bundle per layout.')
    args = parser.parse_args()
    layouts = args.layout or ['system', 'scl']
    require(len(layouts) == len(set(layouts)) and 1 <= args.jobs <= 8, 'Invalid CI layout/jobs selection.')
    require(bool(args.bundle_dir) == (args.action == 'verify-bundles'),
            '--bundle-dir is required only for verify-bundles.')
    disposable_guard()
    reports = bundle_reports(args.bundle_dir, layouts) if args.action == 'verify-bundles' else None
    if reports is not None:
        require(not os.path.exists(os.path.join(STATE, 'before.json')),
                'verify-bundles requires a fresh disposable fixture.')
    try:
        if args.action in ('bootstrap', 'all', 'verify-bundles'):
            bootstrap()
        if args.action in ('fixture', 'all', 'verify-bundles'):
            fixture(layouts)
        if args.action in ('build', 'all'):
            build(layouts, args.jobs)
        if args.action in ('verify', 'all', 'verify-bundles'):
            if reports is not None:
                with open(os.path.join(STATE, 'reports.json'), 'w') as handle:
                    json.dump(reports, handle, indent=2)
                with open(os.path.join(STATE, 'bundle-reuse.json'), 'w') as handle:
                    json.dump(dict(reused=True, reports=reports), handle, indent=2)
            verify_install(layouts, reports)
    finally:
        for layout in layouts:
            pattern = '/home/phpguardbuild/php82-ci/' + layout + '/build-*'
            for build_dir in glob.glob(pattern):
                destination = os.path.join(STATE, 'build-evidence', layout, os.path.basename(build_dir))
                if not os.path.isdir(destination):
                    os.makedirs(destination, 0o700)
                for name in ('build.json', 'prep.log', 'build.log', 'security-tests.log'):
                    source = os.path.join(build_dir, name)
                    if os.path.isfile(source) and not os.path.islink(source):
                        shutil.copyfile(source, os.path.join(destination, name))
        export_build_bundles(layouts)


if __name__ == '__main__':
    main()
