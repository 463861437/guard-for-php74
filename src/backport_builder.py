# -*- coding: utf-8 -*-
"""Pinned AL2 PHP 7.4 source rebuild; never installs the resulting packages."""

BP_SRPM = 'php-7.4.33-1.amzn2.src.rpm'
BP_SRPM_SHA = '7d1cd66b0c150054d15e83154e6d5eb5a25285056b33a765fbec4befeffe8795'
BP_SRPM_URL = ('https://amazonlinux-2-repos-us-east-1.s3.dualstack.us-east-1.amazonaws.com/'
               'blobstore/' + BP_SRPM_SHA + '/' + BP_SRPM)
BP_COMMIT = '712e60f9edfd03f0960fc4fc3c2c375f42b90aa2'
BP_PATCH = 'php74-CVE-2026-109618-109619.patch'
BP_PATCH_SHA = '5fe57ca6ee96d59b36c6e0ca842843c50884f177bef1e85234cf669b577f5e48'
BP_PATCH_URL = 'https://github.com/php/php-src/commit/' + BP_COMMIT + '.patch'
BP_KEY = 'RPM-GPG-KEY-amazon-linux-2'
BP_KEY_SHA = '4fbbf63a42fe615ff67c0c5fe334bd3deee326f774c3de5e727ac625e321379f'
BP_KEY_URL = 'https://cdn.amazonlinux.com/_assets/11CF1F95C87F5B1A.asc'
BP_SPEC_SHA = '747d5148ab1082169143fee516876082bd28515fde15389e9da0969b50bac14c'
BP_SOURCE_SHA = '924846abf93bc613815c55dd3f5809377813ac62a9ec4eb3778675b82a27b927'
BP_RELEASE = '1.amzn2.phpguard20261023.1'
BP_TEST_PATCH_NAME = 'php74-backport-tests.patch'
BP_TEST_PATCH_SHA = 'beca75fb0d1d5810aa91a195e227adc77627a39cc26b1bbf9e9a2b0a0f66d76f'
BP_VERSION = '7.4.33'
BP_COMMAND = 'build-al2-php74'
BP_RECIPE = 'al2-php74-upstream-backport'
BP_DEFAULT_WORKDIR = 'php74-backport'
BP_SOURCE_ARCHIVE = 'php-7.4.33.tar.xz'
BP_SOURCE_ARCHIVE_SHA = BP_SOURCE_SHA
BP_SOURCE_ARCHIVE_URL = None
BP_APPLY_UPSTREAM_PATCH = True
BP_LAST_BUILD_REPORT = None
BAOTA_AL2_VERSION = '7.4.34'
BAOTA_AL2_RELEASE = '1.amzn2.phpguard.baota20261023.1'
BAOTA_AL2_SOURCE_SHA = '343fe09e745ff4eacdd4e223b45085620ffd0e9a85eb467fc33eb361ab34ddf9'
BP_BAOTA_RECIPE = {
    'BP_VERSION': BAOTA_AL2_VERSION,
    'BP_COMMAND': 'build-baota-al2-php74',
    'BP_RECIPE': 'baota-al2-php74',
    'BP_DEFAULT_WORKDIR': 'php74-baota-al2',
    'BP_RELEASE': BAOTA_AL2_RELEASE,
    'BP_SOURCE_ARCHIVE': 'php-7.4.34.tar.gz',
    'BP_SOURCE_ARCHIVE_SHA': BAOTA_AL2_SOURCE_SHA,
    'BP_SOURCE_ARCHIVE_URL': 'https://download.bt.cn/src/php-7.4.34.tar.gz',
    'BP_APPLY_UPSTREAM_PATCH': False,
}
BP_CORE_NAMES = set(('php php-bcmath php-cli php-common php-dba php-enchant php-fpm '
                     'php-gd php-gmp php-intl php-json php-ldap php-mbstring php-mysqlnd '
                     'php-odbc php-opcache php-pdo php-pgsql php-process php-pspell '
                     'php-snmp php-soap php-sodium php-xml php-xmlrpc').split())


def bp_hash(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def bp_verify(path, expected):
    if os.path.islink(path) or not os.path.isfile(path) or bp_hash(path) != expected:
        raise RuntimeError('Pinned SHA256 mismatch or non-regular input: ' + path)


def bp_tool(name):
    for directory in ['/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/local/bin']:
        path = os.path.join(directory, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise RuntimeError('Required build tool missing: ' + name)


def bp_call(argv, log=None, cwd=None, data=None):
    """Stream potentially long builds to a file; no shell interpolation or sudo."""
    env = os.environ.copy()
    # Inherited make options can ignore errors; PHP test options can select a
    # subset or use an unrelated executable. The pinned recipe owns these.
    controls = set(('MAKEFLAGS MFLAGS GNUMAKEFLAGS MAKELEVEL MAKEOVERRIDES MAKEFILES TESTS '
                    'PHP_EXECUTABLE PHP_INI_SCAN_DIR PHPRC SHOW_ONLY_GROUPS '
                    'NO_PHPTEST_SUMMARY REPORT_EXIT_STATUS NO_INTERACTION').split())
    for name in list(env):
        if name in controls or name.startswith(('TEST_PHP', 'PHP_TEST_', 'SKIP_')):
            del env[name]
    env.update({'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC', 'USE_ZEND_ALLOC': '1'})
    if log:
        with open(log, 'wb') as output:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                    stdout=output, stderr=subprocess.STDOUT)
            proc.communicate(data)
        if proc.returncode:
            raise RuntimeError('Command failed (exit %s), see %s' % (proc.returncode, log))
        return ''
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(data)
    if proc.returncode:
        raise RuntimeError('Command failed (exit %s): %s' % (proc.returncode, as_text(err)[-2000:]))
    return as_text(out)


def bp_fetch(local, url, digest, destination):
    if local:
        bp_verify(local, digest)
        shutil.copyfile(local, destination)
    else:
        result = run_cmd([bp_tool('curl'), '--fail', '--location', '--silent', '--show-error',
                          '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '20',
                          '--max-time', '180', '--retry', '1', '--output', destination, url], timeout=400)
        if result['code']:
            raise RuntimeError('Download failed (exit %s): %s' % (result['code'], url))
    bp_verify(destination, digest)


def bp_extract_srpm(source, destination):
    # The exact official RPM is pinned before any archive tool sees it.
    bp_verify(source, BP_SRPM_SHA)
    os.makedirs(destination, 0o700)
    tar = None
    for candidate in ['bsdtar', 'tar']:
        try:
            path = bp_tool(candidate)
            if 'bsdtar' in bp_call([path, '--version']):
                tar = path
                break
        except RuntimeError:
            pass
    if tar:
        names = bp_call([tar, '-tf', source]).splitlines()
        if any(not re.match(r'^[A-Za-z0-9_.+-]+$', n) or n in ('.', '..') for n in names):
            raise RuntimeError('Unexpected source RPM archive layout')
        bp_call([tar, '-xf', source, '-C', destination])
    else:
        proc = subprocess.Popen([bp_tool('rpm2cpio'), source], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        payload, errors = proc.communicate()
        if proc.returncode:
            raise RuntimeError('rpm2cpio failed: ' + as_text(errors)[-1000:])
        cpio = bp_tool('cpio')
        names = bp_call([cpio, '-t', '--quiet'], data=payload).splitlines()
        if any(not re.match(r'^(?:\./)?[A-Za-z0-9_.+-]+$', n) or n in ('.', '..') for n in names):
            raise RuntimeError('Unexpected source RPM archive layout')
        bp_call([cpio, '-idm', '--quiet', '--no-absolute-filenames'], cwd=destination, data=payload)
    for name in os.listdir(destination):
        if not stat.S_ISREG(os.lstat(os.path.join(destination, name)).st_mode):
            raise RuntimeError('Non-regular file in source RPM')
    bp_verify(os.path.join(destination, 'php.spec'), BP_SPEC_SHA)
    bp_verify(os.path.join(destination, 'php-7.4.33.tar.xz'), BP_SOURCE_SHA)


def bp_render_spec(original):
    if hashlib.sha256(original).hexdigest() != BP_SPEC_SHA:
        raise RuntimeError('Unexpected SPEC; refusing a best-effort rewrite')
    value = original.decode('utf-8')
    security_declaration = ('Patch200: ' + BP_PATCH + '\n') if BP_APPLY_UPSTREAM_PATCH else ''
    security_application = '%patch200 -p1 -F0 -b .cve2026\n' if BP_APPLY_UPSTREAM_PATCH else ''
    replacements = [
        ('Release: 1%{?dist}%{?_trivial}%{?_buildid}', 'Release: ' + BP_RELEASE),
        ('# Security fixes (200+)\n', '# Security fixes (200+)\n' + security_declaration + 'Patch201: ' + BP_TEST_PATCH_NAME + '\n'),
        ('# security patches\n', '# security patches\n' + security_application + '%patch201 -p1 -F0 -b .guardtests\n'),
        ('  #exit 1\n', '  exit 1\n'),
        ('%changelog\n', '%changelog\n* Fri Oct 23 2026 PHP Guard local rebuild <noreply@example.invalid> - ' + BP_VERSION + '-' + BP_RELEASE + '\n'
         + ('- Apply upstream ' + BP_COMMIT + ' for CVE-2026-109618/109619.\n' if BP_APPLY_UPSTREAM_PATCH else
            '- Rebuild pinned BaoTa 7.4.34 source containing upstream ' + BP_COMMIT + '.\n'
            '- Preserve Amazon Linux 2 packaging, configurations and extension ABI checks.\n'
            '- Read the authoritative configure.ac version before generated headers are refreshed.\n')
         + '- Adapt known upload-progress/OOM test expectations and add a regression.\n'
         '- Refresh historical timezone expectations and generate SNI test certificates.\n'
         '- Require upstream regression tests to succeed. This is a local rebuild.\n\n'),
    ]
    if not BP_APPLY_UPSTREAM_PATCH:
        # The pinned BaoTa archive has stale generated configure/version-header
        # files. Its configure.ac is authoritative; the unchanged %build calls
        # buildconf --force and configure regenerates main/php_version.h.
        replacements.extend([
            ('%global upver        7.4.33', '%global upver        ' + BP_VERSION),
            ('Source0: http://www.php.net/distributions/php-%{upver}%{?rcver}.tar.xz',
             'Source0: ' + BP_SOURCE_ARCHIVE_URL),
            ('pver=$(sed -n \'/#define PHP_VERSION /{s/.* "//;s/".*$//;p}\' main/php_version.h)',
             'pver=$(sed -n \'s/^AC_INIT(\\[PHP\\],\\[\\([^]]*\\)\\].*/\\1/p\' configure.ac)'),
        ])
    for before, after in replacements:
        if value.count(before) != 1:
            raise RuntimeError('SPEC anchor is missing or ambiguous')
        value = value.replace(before, after, 1)
    return value.encode('utf-8')


def bp_inputs(folder):
    inputs = [(BP_SRPM, BP_SRPM_SHA), (BP_PATCH, BP_PATCH_SHA), (BP_KEY, BP_KEY_SHA)]
    if BP_SOURCE_ARCHIVE_URL:
        inputs.append((BP_SOURCE_ARCHIVE, BP_SOURCE_ARCHIVE_SHA))
    return inputs


def bp_fetch_entries(args):
    entries = [(args.srpm, BP_SRPM_URL, BP_SRPM_SHA, BP_SRPM),
               (args.patch_file, BP_PATCH_URL, BP_PATCH_SHA, BP_PATCH),
               (args.key_file, BP_KEY_URL, BP_KEY_SHA, BP_KEY)]
    if BP_SOURCE_ARCHIVE_URL:
        entries.append((getattr(args, 'source_tar', None), BP_SOURCE_ARCHIVE_URL,
                        BP_SOURCE_ARCHIVE_SHA, BP_SOURCE_ARCHIVE))
    return entries


def bp_verify_baota_archive(path):
    """Check the pinned vendor tar without extracting or executing its content."""
    bp_verify(path, BAOTA_AL2_SOURCE_SHA)
    expected = {
        'configure.ac': '2f38c7704869bd1b4ebc96bb09f0a0cb64c0ca2122faffc7949678fee3b1bdc8',
        'main/php_version.h': '419299555431fad855ec430956ca552cfaeb3799fb821246b1cde9a57167a243',
        'main/php.h': '1587522522ab45cd8262791f01234e0b1a1507ec1d3fecffe1f241362b8e5f56',
        'Zend/zend_modules.h': 'a38ca36953308f1f746bf79a5fbeded77595866290f3471c73c7dcf493a1994e',
        'ext/pdo/php_pdo_driver.h': '8b2d3a5b1ba1676e61c5b51a3a9b85e7b1b136efe28a4bc6666f690b42eb0f9f',
    }
    found, names = {}, set()
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            parts = member.name.rstrip('/').split('/')
            if (not parts or parts[0] != 'php-7.4.34' or
                    any(part in ('', '.', '..') for part in parts) or
                    not (member.isdir() or member.isfile()) or member.name in names):
                raise RuntimeError('Unexpected BaoTa source archive member')
            names.add(member.name)
            relative = '/'.join(parts[1:])
            if relative in expected:
                if not member.isfile() or member.size > 1024 * 1024:
                    raise RuntimeError('Invalid BaoTa source identity file')
                found[relative] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    if found != expected:
        raise RuntimeError('BaoTa source version/API identities do not match the reviewed archive')


def bp_stage_recipe_inputs(inputs, destination):
    if BP_SOURCE_ARCHIVE_URL:
        source = os.path.join(inputs, BP_SOURCE_ARCHIVE)
        bp_verify_baota_archive(source)
        shutil.copyfile(source, os.path.join(destination, BP_SOURCE_ARCHIVE))
    if BP_APPLY_UPSTREAM_PATCH:
        shutil.copyfile(os.path.join(inputs, BP_PATCH), os.path.join(destination, BP_PATCH))
    bp_write_test_patch(destination)


def bp_write_test_patch(destination):
    if hashlib.sha256(BP_TEST_PATCH).hexdigest() != BP_TEST_PATCH_SHA:
        raise RuntimeError('Embedded regression-test patch checksum mismatch')
    with open(os.path.join(destination, BP_TEST_PATCH_NAME), 'wb') as handle:
        handle.write(BP_TEST_PATCH)


def bp_prepare(args):
    folder = os.path.abspath(args.output_dir)
    if os.path.lexists(folder):
        try:
            bp_prepared_inputs(folder)
            for local, unused_url, digest, name in bp_fetch_entries(args):
                if local:
                    bp_verify(local, digest)
        except (IOError, OSError, RuntimeError, ValueError, TypeError) as exc:
            raise RuntimeError('Output directory already exists and is incomplete or changed; '
                               'choose a new directory. ' + as_text(exc))
        say('已验证并复用准备完成的源码目录：' + folder)
        say('未重复下载、编译或部署；build 仍会重新校验固定输入与 AWS RPM 签名。')
        return 0
    os.makedirs(folder, 0o700)
    inputs = os.path.join(folder, 'inputs')
    os.mkdir(inputs, 0o700)
    report = {'tool_version': VERSION, 'state': 'preparing', 'deployed': False,
              'cves': CVES, 'upstream_commit': BP_COMMIT, 'target_release': BP_RELEASE,
              'recipe': BP_RECIPE, 'target_version': BP_VERSION,
              'source_archive_url': BP_SOURCE_ARCHIVE_URL,
              'source_archive_sha256': BP_SOURCE_ARCHIVE_SHA}
    report_path = os.path.join(folder, 'prepare.json')
    try:
        for local, url, digest, name in bp_fetch_entries(args):
            say('正在准备并校验：' + name)
            bp_fetch(local, url, digest, os.path.join(inputs, name))
        preview = os.path.join(folder, 'preview')
        bp_extract_srpm(os.path.join(inputs, BP_SRPM), preview)
        with open(os.path.join(preview, 'php.spec'), 'rb') as handle:
            prepared = bp_render_spec(handle.read())
        with open(os.path.join(preview, 'php.spec'), 'wb') as handle:
            handle.write(prepared)
        bp_stage_recipe_inputs(inputs, preview)
        report.update({'state': 'sources_prepared_not_built', 'rpm_signature_verified': False,
                       'inputs': dict(bp_inputs(folder)), 'regression_patch_sha256': BP_TEST_PATCH_SHA,
                       'spec_sha256': bp_hash(os.path.join(preview, 'php.spec')),
                       'preview_sha256': dict((name, bp_hash(os.path.join(preview, name)))
                                              for name in os.listdir(preview))})
        write_json(report_path, report)
        say('源码与 SPEC 已准备：' + folder)
        say('尚未编译或部署；prepare 验证固定 SHA256，build 还会独立验证 AWS RPM 签名。')
        return 0
    except Exception as exc:
        report.update({'state': 'prepare_failed', 'error': as_text(exc)})
        write_json(report_path, report)
        raise



def bp_prepared_inputs(folder):
    """Inspect a completed preparation without trusting it as a built artifact."""
    for path in [folder, os.path.join(folder, 'inputs'), os.path.join(folder, 'preview')]:
        if os.path.islink(path) or not os.path.isdir(path):
            raise RuntimeError('Prepared directory missing or symbolic link: ' + path)
    report_path = os.path.join(folder, 'prepare.json')
    if os.path.islink(report_path) or not os.path.isfile(report_path):
        raise RuntimeError('Completed prepare.json is missing or not a regular file')
    with open(report_path) as handle:
        report = json.load(handle)
    if (not isinstance(report, dict) or report.get('state') != 'sources_prepared_not_built' or
            report.get('upstream_commit') != BP_COMMIT or report.get('target_release') != BP_RELEASE or
            report.get('recipe', 'al2-php74-upstream-backport') != BP_RECIPE or
            report.get('target_version', '7.4.33') != BP_VERSION or
            report.get('inputs') != dict(bp_inputs(folder)) or
            report.get('regression_patch_sha256') != BP_TEST_PATCH_SHA):
        raise RuntimeError('Preparation is incomplete or belongs to another pinned recipe')
    for name, digest in bp_inputs(folder):
        bp_verify(os.path.join(folder, 'inputs', name), digest)
    preview = os.path.join(folder, 'preview')
    critical = [(BP_TEST_PATCH_NAME, BP_TEST_PATCH_SHA),
                (BP_SOURCE_ARCHIVE, BP_SOURCE_ARCHIVE_SHA if BP_SOURCE_ARCHIVE_URL else BP_SOURCE_SHA),
                ('php.spec', report.get('spec_sha256'))]
    if BP_APPLY_UPSTREAM_PATCH:
        critical.append((BP_PATCH, BP_PATCH_SHA))
    for name, digest in critical:
        bp_verify(os.path.join(preview, name), digest)
    # Older prepare reports record the critical files above. New reports also
    # record the complete flat preview; neither report authorizes deployment.
    manifest = report.get('preview_sha256')
    if manifest is not None:
        if not isinstance(manifest, dict) or set(manifest) != set(os.listdir(preview)):
            raise RuntimeError('Prepared preview file set changed')
        for name, digest in manifest.items():
            if not re.match(r'^[A-Za-z0-9_.+-]+$', name) or name in ('.', '..'):
                raise RuntimeError('Invalid preview manifest filename')
            bp_verify(os.path.join(preview, name), digest)
    return report


def bp_shell_quote(value):
    return "'" + as_text(value).replace("'", "'\"'\"'") + "'"


def bp_doctor_host():
    import pwd
    values = {}
    try:
        with open('/etc/os-release') as handle:
            for line in handle:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    values[key] = value.strip('"\'')
    except (IOError, OSError):
        pass
    uid = os.geteuid()
    try:
        current = pwd.getpwuid(uid)
        user, user_home = current.pw_name, current.pw_dir
    except KeyError:
        user, user_home = str(uid), None
    build_user, build_home = (user, user_home) if uid else (None, None)
    if not uid:
        try:
            candidate = pwd.getpwnam('ec2-user')
            if candidate.pw_uid > 0 and candidate.pw_shell not in ('/sbin/nologin', '/bin/false'):
                build_user, build_home = candidate.pw_name, candidate.pw_dir
        except KeyError:
            pass
    return {'platform': sys.platform, 'os_id': values.get('ID'),
            'os_version': values.get('VERSION_ID'), 'architecture': os.uname()[4],
            'uid': uid, 'user': user, 'build_user': build_user, 'build_home': build_home}


def bp_doctor_resources(folder):
    memory = {}
    try:
        with open('/proc/meminfo') as handle:
            for line in handle:
                match = re.match(r'^(MemTotal|MemAvailable|SwapTotal):\s+(\d+)\s+kB$', line.strip())
                if match:
                    memory[match.group(1)] = int(match.group(2)) * 1024
    except (IOError, OSError):
        pass
    ancestor = folder
    while not os.path.isdir(ancestor) and ancestor != os.path.dirname(ancestor):
        ancestor = os.path.dirname(ancestor)
    free = None
    try:
        usage = os.statvfs(ancestor)
        free = usage.f_bavail * usage.f_frsize
    except (IOError, OSError):
        pass
    total = memory.get('MemTotal')
    jobs = 1 if total is None or total < 4 * 1024 ** 3 else 2
    return {'memory_total_bytes': total, 'memory_available_bytes': memory.get('MemAvailable'),
            'swap_total_bytes': memory.get('SwapTotal'), 'disk_free_bytes': free,
            'disk_checked_path': ancestor, 'recommended_jobs': jobs,
            'capacity_advisory_only': True}


_BP_REQUIREMENTS_WORKER = r'''
from __future__ import print_function
import json, sys
sys.path = [path for path in sys.path if path not in ('', '.')]

def requirement_providers(requirements):
    # Only the installed RPM sack is read. Do not initialize repositories,
    # plugins, acquire YUM locks, or resolve/execute a package transaction.
    import yum
    base = yum.YumBase()
    try:
        base.preconf.init_plugins = False
        base.preconf.debuglevel = 0
        base.preconf.errorlevel = 0
        if base.conf.installroot != '/':
            raise RuntimeError('Build dependency check requires the running RPM database')
        answers = {}
        for requirement in requirements:
            try:
                packages = base.returnInstalledPackagesByDep(str(requirement))
                providers = sorted(set(str(package) for package in packages))
                answers[requirement] = {'state': 'satisfied' if providers else 'missing',
                                        'providers': providers}
            except Exception as exc:
                answers[requirement] = {'state': 'unknown', 'error': str(exc)}
        return answers
    finally:
        try: base.closeRpmDB()
        finally: base.close()

if __name__ == '__main__':
    try:
        answer = {'ok': True, 'requirements': requirement_providers(json.loads(sys.argv[1]))}
    except Exception as exc:
        answer = {'ok': False, 'error': str(exc)}
    print(json.dumps(answer, ensure_ascii=True))
'''


def bp_installed_requirements(requirements):
    """Use the system YUM/RPM implementation for versioned installed Provides."""
    try:
        interpreter, backend = _rpm_system_backend('yum')
        if backend != 'yum':
            raise RuntimeError('AL2 build dependency check requires system YUM bindings')
        result = run_cmd([interpreter, '-E', '-s', '-c', _BP_REQUIREMENTS_WORKER,
                          json.dumps(requirements, ensure_ascii=True)], timeout=120)
        if result['code'] or result['stderr'].strip():
            raise RuntimeError('Installed dependency query failed (exit %s): %s' % (
                result['code'], result['stderr'].strip()))
        answer = json.loads(result['stdout'])
        if not isinstance(answer, dict) or answer.get('ok') is not True:
            raise RuntimeError('Installed dependency query failed: ' +
                               as_text(answer.get('error') if isinstance(answer, dict) else answer))
        values = answer.get('requirements')
        if not isinstance(values, dict) or set(values) != set(requirements):
            raise RuntimeError('Incomplete installed dependency query response')
        for value in values.values():
            if not isinstance(value, dict) or value.get('state') not in ('satisfied', 'missing', 'unknown'):
                raise RuntimeError('Invalid installed dependency query response')
            if value['state'] != 'unknown':
                providers = value.get('providers')
                if (not isinstance(providers, list) or
                        any(not isinstance(item, type('')) or not item for item in providers) or
                        bool(providers) != (value['state'] == 'satisfied')):
                    raise RuntimeError('Invalid installed provider evidence')
        return values
    except (IOError, OSError, RuntimeError, ValueError, TypeError) as exc:
        return dict((requirement, {'state': 'unknown', 'error': as_text(exc)})
                    for requirement in requirements)


def bp_doctor_requirements(srpm, rpm):
    """Read pinned SRPM capabilities; no SPEC expansion, scripts or repositories."""
    bp_verify(srpm, BP_SRPM_SHA)
    query = run_cmd([rpm, '-qp', '--requires', srpm], timeout=30)
    if query['code']:
        return {'state': 'unknown', 'reason': 'cannot_query_srpm_requirements', 'missing': []}
    requires = sorted(set(line.strip() for line in query['stdout'].splitlines() if line.strip()))
    if not requires or len(requires) > 256:
        return {'state': 'unknown', 'reason': 'unexpected_srpm_requirements', 'missing': []}
    missing, unknown, ignored, checked = [], [], [], []
    for requirement in requires:
        if requirement.startswith('rpmlib('):
            ignored.append(requirement)
            continue
        if not re.match(r'^[A-Za-z0-9_/][A-Za-z0-9_./+():,~%-]*(?:\s+(?:>=|<=|=|>|<)\s+[A-Za-z0-9_.:+~%^-]+)?$', requirement):
            unknown.append(requirement)
            continue
        checked.append(requirement)
    # RPM 4.11 --whatprovides indexes a capability name literally. Passing
    # 'libtool >= 1.4.3' gives a false missing result; YUM's installed-provider
    # API parses the operator/EVR and performs RPM-aware range matching.
    evidence = bp_installed_requirements(checked) if checked else {}
    for requirement, value in sorted(evidence.items()):
        if value['state'] == 'missing':
            missing.append(requirement)
        elif value['state'] != 'satisfied':
            unknown.append(requirement)
    return {'state': 'unknown' if unknown else ('missing' if missing else 'satisfied'),
            'missing': missing, 'unresolved': unknown, 'checked': len(requires) - len(ignored),
            'rpm_internal_capabilities': ignored,
            'provider_evidence': evidence,
            'query_backend': 'system_yum_installed_rpmdb',
            'scope': 'native versioned installed Provides for pinned SRPM requirements; build still validates SPEC dependencies'}


def bp_doctor_report(args):
    host = bp_doctor_host()
    folder = os.path.abspath(args.work_dir) if args.work_dir else os.path.join(
        host.get('build_home') or '/tmp', BP_DEFAULT_WORKDIR)
    result = {'tool_version': VERSION, 'state': 'build_preflight', 'deployed': False,
              'read_only': True, 'host': host, 'work_dir': folder, 'blockers': [],
              'warnings': [], 'next_commands': [], 'recipe': BP_RECIPE,
              'target_version': BP_VERSION, 'target_release': BP_RELEASE}
    blockers, warnings = result['blockers'], result['warnings']
    supported = (host['platform'] == 'linux' and host['os_id'] == 'amzn' and
                 host['os_version'] == '2' and host['architecture'] == 'x86_64')
    if not supported:
        blockers.append('需要 Amazon Linux 2 x86_64 构建机。')
    if not host['uid']:
        blockers.append('当前是 root；prepare/build 请切换到普通构建用户。')
    if not re.match(r'^/[A-Za-z0-9_./-]+$', folder):
        blockers.append('构建目录必须为绝对路径，仅包含 ASCII 字母、数字和 /_.-。')
    tools = {}
    for name in ['rpm', 'rpmbuild', 'rpm2cpio', 'cpio', 'curl', 'gcc', 'g++', 'make',
                 'autoconf', 'automake', 'libtool', 'patch', 'xz']:
        try:
            tools[name] = bp_tool(name)
        except RuntimeError:
            tools[name] = None
    result['tools'] = tools
    missing_tools = sorted(name for name, path in tools.items() if not path)
    if missing_tools:
        blockers.append('缺少构建工具：' + ', '.join(missing_tools))
    resources = bp_doctor_resources(folder)
    result['resources'] = resources
    if resources['memory_total_bytes'] is None or resources['memory_total_bytes'] < 2 * 1024 ** 3:
        warnings.append('建议至少 2 GiB 内存；低内存机器使用 --jobs 1，实际用量取决于构建和测试。')
    if resources['disk_free_bytes'] is None or resources['disk_free_bytes'] < 10 * 1024 ** 3:
        warnings.append('建议至少预留 10 GiB 磁盘；容量提示不是构建成功保证。')
    prepared = False
    if os.path.lexists(folder):
        try:
            bp_prepared_inputs(folder)
            prepared = True
            result['preparation'] = 'verified_inputs'
        except (IOError, OSError, RuntimeError, ValueError, TypeError):
            result['preparation'] = 'incomplete_or_changed'
            blockers.append('现有工作目录未通过完成记录和固定输入校验；保留该目录，使用新的 --output-dir。')
    else:
        result['preparation'] = 'not_prepared'
        blockers.append('尚未准备并校验固定源码输入。')
    if prepared and host['uid'] and not os.access(folder, os.W_OK | os.X_OK):
        blockers.append('当前构建用户不能写入工作目录；请使用该用户自己的新目录。')
    if prepared and tools['rpm'] and supported:
        result['dependencies'] = bp_doctor_requirements(os.path.join(folder, 'inputs', BP_SRPM), tools['rpm'])
        if result['dependencies']['state'] != 'satisfied':
            blockers.append('构建依赖缺失或未能完整核实；请查看 dependencies。')
    else:
        result['dependencies'] = {'state': 'not_checked', 'missing': [],
                                  'reason': 'requires_prepared_inputs_and_AL2_rpm'}
    launcher = os.environ.get('PHP_GUARD_LAUNCHER')
    script = os.path.abspath(launcher) if launcher else None
    if not script or not script.endswith('.sh') or not os.path.isfile(script):
        script = os.path.join(os.getcwd(), 'php-cve-guard.sh')
    if not os.path.isfile(script):
        script = '/path/to/php-cve-guard.sh'
        warnings.append('未定位启动脚本；请将下一步命令中的 /path/to/php-cve-guard.sh 替换为实际绝对路径。')
    result['launcher_path'] = script
    invocation = 'bash ' + bp_shell_quote(script)
    runner = ''
    if not host['uid'] and host.get('build_user'):
        runner = 'sudo -u ' + bp_shell_quote(host['build_user']) + ' -H '
    admin = 'sudo ' if host['uid'] else ''
    if supported:
        if missing_tools:
            packages = {'rpm': 'rpm', 'rpmbuild': 'rpm-build', 'rpm2cpio': 'rpm', 'cpio': 'cpio',
                        'curl': 'curl', 'gcc': 'gcc', 'g++': 'gcc-c++', 'make': 'make',
                        'autoconf': 'autoconf', 'automake': 'automake', 'libtool': 'libtool',
                        'patch': 'patch', 'xz': 'xz'}
            result['next_commands'].append(admin + 'yum install ' + ' '.join(
                sorted(set(packages[name] for name in missing_tools))))
        if host.get('build_user'):
            safe_folder = bool(re.match(r'^/[A-Za-z0-9_./-]+$', folder))
            if result['preparation'] == 'not_prepared' and safe_folder:
                result['next_commands'].append(runner + invocation + ' ' + BP_COMMAND + ' prepare --output-dir ' + bp_shell_quote(folder))
            if prepared:
                if result['dependencies']['state'] != 'satisfied':
                    result['next_commands'].append(admin + 'yum install yum-utils')
                    result['next_commands'].append(admin + "yum-builddep --disablerepo='*' "
                        '--enablerepo=amzn2-core,amzn2extra-php7.4 ' + bp_shell_quote(os.path.join(folder, 'inputs', BP_SRPM)))
                # Recheck after preparation/dependency installation, before a build.
                if safe_folder:
                    if not host['uid'] or missing_tools or result['dependencies']['state'] != 'satisfied':
                        result['next_commands'].append(runner + invocation + ' ' + BP_COMMAND + ' doctor --work-dir ' + bp_shell_quote(folder))
                    else:
                        result['next_commands'].append(runner + invocation + ' ' + BP_COMMAND + ' build --work-dir ' +
                                                       bp_shell_quote(folder) + ' --jobs ' + str(resources['recommended_jobs']))
            elif result['preparation'] == 'not_prepared' and safe_folder:
                result['next_commands'].append(runner + invocation + ' ' + BP_COMMAND + ' doctor --work-dir ' + bp_shell_quote(folder))
        else:
            warnings.append('未发现 ec2-user；请选定已有普通用户后，以该用户运行 doctor。')
    result['state'] = 'ready_for_build' if not blockers else 'build_preflight_blocked'
    if supported and host.get('build_user') and re.match(r'^/[A-Za-z0-9_./-]+$', folder):
        result['automatic_setup_command'] = (admin + invocation + ' ' + BP_COMMAND + ' setup --yes --build-user ' +
            bp_shell_quote(host['build_user']) + ' --work-dir ' + bp_shell_quote(folder))
    return result


def bp_print_doctor(report):
    say('构建预检（只读；不安装依赖、不切换仓库、不编译）：')
    say(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    say('该结果只检查构建准备情况，不代表 PHP 漏洞已修复。')
    return 0 if report['state'] == 'ready_for_build' else 10


def bp_doctor(args):
    return bp_print_doctor(bp_doctor_report(args))


def bp_auto(args):
    # This orchestration never elevates privileges or installs dependencies.
    bp_host_check()
    folder = os.path.abspath(args.work_dir)
    if not re.match(r'^/[A-Za-z0-9_./-]+$', folder):
        raise RuntimeError('Use an absolute build directory containing only ASCII letters, numbers, /_.-')
    if not os.path.lexists(folder):
        for name in ['curl', 'rpm2cpio', 'cpio']:
            try:
                bp_tool(name)
            except RuntimeError:
                return bp_doctor(args)
    prepare = argparse.Namespace(output_dir=folder, srpm=None, patch_file=None, key_file=None)
    bp_prepare(prepare)
    report = bp_doctor_report(args)
    if report['state'] != 'ready_for_build':
        return bp_print_doctor(report)
    jobs = min(args.jobs, report['resources']['recommended_jobs'])
    say('构建准备检查通过；开始编译和完整源码测试，并发数：' + str(jobs))
    return bp_build(argparse.Namespace(work_dir=folder, jobs=jobs))


def bp_failure_summary(build, stage):
    """Classify a bounded log tail; never echo raw commands or environment."""
    name = 'prep.log' if stage == 'prepare_and_dependencies' else 'build.log'
    path = os.path.join(build, name)
    tail = ''
    try:
        if not os.path.islink(path) and os.path.isfile(path):
            with open(path, 'rb') as handle:
                handle.seek(0, os.SEEK_END)
                handle.seek(max(0, handle.tell() - 65536))
                tail = as_text(handle.read(65536))
    except (IOError, OSError):
        pass
    result = {'kind': 'unclassified', 'log': path, 'raw_log_included': False}
    if 'Failed build dependencies:' in tail:
        result.update({'kind': 'missing_build_dependencies',
                       'hint': '运行 ' + BP_COMMAND + ' doctor --work-dir 工作目录，核实缺失依赖后重新构建。'})
    elif re.search(r'(?:FAILED TEST SUMMARY|Tests failed\s*:\s*[1-9]|PHP regression tests failed)', tail):
        result.update({'kind': 'php_tests_failed',
                       'hint': 'PHP 自测失败；查看 build.log 与测试生成的 .diff/.out 文件，修正原因后重新构建，不要跳过测试。'})
    elif re.search(r'(?:cannot allocate memory|virtual memory exhausted|killed signal terminated program cc1|oom-kill)', tail, re.I):
        result.update({'kind': 'possible_host_memory_exhaustion',
                       'hint': '日志出现内存不足信号；核对系统内存和内核日志，增加资源或使用 --jobs 1。'})
    else:
        result['hint'] = '查看本机构建日志确认失败原因；本次未部署 PHP。'
    return result

def bp_host_check():
    if sys.platform != 'linux':
        raise RuntimeError('Build requires an Amazon Linux 2 x86_64 build machine')
    if os.geteuid() == 0:
        raise RuntimeError('Run the build as a normal user on a dedicated build machine, not as root')
    values = {}
    with open('/etc/os-release') as handle:
        for line in handle:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                values[key] = value.strip('"\'')
    if values.get('ID') != 'amzn' or values.get('VERSION_ID') != '2' or os.uname()[4] != 'x86_64':
        raise RuntimeError('This rebuild recipe only supports Amazon Linux 2 x86_64')


def bp_check_artifacts(paths, rpm):
    artifacts, names = [], set()
    for path in paths:
        text = bp_call([rpm, '-qp', '--qf', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}', path])
        fields = text.strip().split('\t')
        if len(fields) != 5:
            raise RuntimeError('Unexpected built RPM metadata')
        name, version, release, arch, source = fields
        if (version != BP_VERSION or release != BP_RELEASE or arch not in ('x86_64', 'noarch') or
                source != 'php-' + BP_VERSION + '-' + BP_RELEASE + '.src.rpm' or
                not re.match(r'^php(?:-[a-z0-9-]+)?$', name)):
            raise RuntimeError('Unexpected built RPM identity: ' + os.path.basename(path))
        names.add(name)
        artifacts.append({'file': os.path.basename(path), 'sha256': bp_hash(path),
                          'name': name, 'version': version, 'release': release, 'arch': arch})
    missing = sorted(BP_CORE_NAMES - names)
    if missing:
        raise RuntimeError('Incomplete core package set: ' + ', '.join(missing))
    return artifacts


def bp_smoke_tests(top):
    results = []
    for subdir in ['build-apache', 'build-ztscli']:
        php = os.path.join(top, 'BUILD', 'php-' + BP_VERSION, subdir, 'sapi', 'cli', 'php')
        if not os.path.isfile(php):
            raise RuntimeError('Built CLI missing: ' + subdir)
        version = run_cmd([php, '-n', '-r', 'echo PHP_VERSION;'], timeout=15)
        if version['code'] or version['stdout'] != BP_VERSION:
            raise RuntimeError('Built CLI version smoke test failed: ' + subdir)
        # Controlled 16 MiB limit: verify the official EOL OOM behavior without
        # exhausting the host or running application code.
        code = ('register_shutdown_function(function(){fwrite(STDERR,"PHP_GUARD_SHUTDOWN_RAN");});'
                '$v=str_repeat("x",32*1024*1024);')
        result = run_cmd([php, '-n', '-d', 'memory_limit=16M', '-r', code], timeout=15,
                         env={'USE_ZEND_ALLOC': '1'})
        combined = result['stdout'] + result['stderr']
        if (result['code'] != 1 or 'Allowed memory size' not in result['stderr'] or
                'PHP_GUARD_SHUTDOWN_RAN' in combined):
            raise RuntimeError('OOM immediate-exit smoke test failed: ' + subdir)
        results.append({'sapi': subdir, 'version': BP_VERSION, 'oom_exit': 1,
                        'shutdown_callback_ran': False})
    return results


def bp_selftest_summary(path):
    """Require a complete full-suite result and the pinned critical regressions."""
    expected = dict((('ext/session/tests/' + name + '.phpt'), 'XFAIL') for name in
                    ('rfc1867', 'rfc1867_inter', 'rfc1867_sid_cookie', 'rfc1867_sid_get',
                     'rfc1867_sid_get_2', 'rfc1867_sid_invalid', 'rfc1867_sid_only_cookie',
                     'rfc1867_sid_post'))
    expected.update({'ext/session/tests/phpguard_upload_progress_disabled.phpt': 'PASS',
                     'tests/lang/bug45392.phpt': 'PASS',
                     'ext/date/tests/bug33415-2.phpt': 'PASS',
                     'ext/openssl/tests/sni_server.phpt': 'PASS',
                     'ext/openssl/tests/sni_server_key_cert.phpt': 'PASS'})
    results, summaries, current = {}, [], None
    labels = {'Number of tests': 'total', 'Tests skipped': 'skipped',
              'Tests warned': 'warned', 'Tests failed': 'failed', 'Tests passed': 'passed',
              'Tests borked': 'borked', 'Tests leaked': 'leaked',
              'Expected fail': 'xfailed', 'Expected leak': 'xleaked'}
    with open(path, 'rb') as handle:
        for raw in handle:
            # run-tests.php emits a carriage-return progress prefix per test.
            line = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', as_text(raw)).split('\r')[-1].strip()
            result = re.match(r'^(PASS|XFAIL|SKIP|FAIL|BORK|WARN|LEAK)\s+.*\[([^\]]+)\]', line)
            if result and result.group(2) in expected:
                name = result.group(2)
                if name in results:
                    raise RuntimeError('PHP regression tests failed: duplicate critical test result')
                results[name] = result.group(1)
            if line == 'TEST RESULT SUMMARY':
                if current is not None or summaries:
                    raise RuntimeError('PHP regression tests failed: ambiguous full-suite summary')
                current = {}
            elif current is not None:
                count = re.match(r'^([^:]+?)\s*:\s*(\d+)(?:\s|$)', line)
                if count and count.group(1).strip() in labels:
                    name = labels[count.group(1).strip()]
                    if name in current:
                        raise RuntimeError('PHP regression tests failed: duplicate summary count')
                    current[name] = int(count.group(2))
                if re.match(r'^Time taken\s*:\s*\d+ seconds$', line):
                    summaries.append(current)
                    current = None
    if current is not None or len(summaries) != 1:
        raise RuntimeError('PHP regression tests failed: complete full-suite summary missing')
    counts = summaries[0]
    if not set(('total', 'skipped', 'warned', 'failed', 'passed')).issubset(counts):
        raise RuntimeError('PHP regression tests failed: incomplete summary counts')
    for name in ('borked', 'leaked', 'xfailed', 'xleaked'):
        counts.setdefault(name, 0)
    if (counts['total'] <= 0 or counts['passed'] <= 0 or
            any(counts[name] for name in ('failed', 'borked', 'leaked')) or
            counts['total'] != sum(value for name, value in counts.items() if name != 'total')):
        raise RuntimeError('PHP regression tests failed: failing or inconsistent summary')
    if results != expected:
        raise RuntimeError('PHP regression tests failed: required PASS/XFAIL results missing or changed')
    counts['critical_regressions'] = results
    return counts


def bp_build(args):
    global BP_LAST_BUILD_REPORT
    bp_host_check()
    folder = os.path.abspath(args.work_dir)
    # RPM's generated shell scripts and macro expansion need a simple path.
    if not re.match(r'^/[A-Za-z0-9_./-]+$', folder):
        raise RuntimeError('Use an absolute build directory containing only ASCII letters, numbers, /_.-')
    inputs = os.path.join(folder, 'inputs')
    for name, digest in bp_inputs(folder):
        bp_verify(os.path.join(inputs, name), digest)
    rpm, rpmbuild = bp_tool('rpm'), bp_tool('rpmbuild')
    build = tempfile.mkdtemp(prefix='build-', dir=folder)
    report_path = os.path.join(build, 'build.json')
    BP_LAST_BUILD_REPORT = report_path
    report = {'tool_version': VERSION, 'state': 'building', 'deployed': False,
              'inputs': dict(bp_inputs(folder)), 'upstream_commit': BP_COMMIT,
              'target_release': BP_RELEASE, 'target_version': BP_VERSION, 'recipe': BP_RECIPE,
              'source_archive_url': BP_SOURCE_ARCHIVE_URL,
              'source_archive_sha256': BP_SOURCE_ARCHIVE_SHA,
              'source_provenance': ('AWS signed SRPM plus pinned upstream security patch' if BP_APPLY_UPSTREAM_PATCH else
                                    'Pinned BaoTa HTTPS source archive; AWS signature authenticates packaging baseline only'),
              'vendor_source_signature_verified': False,
              'tests_required': True, 'signed': False}
    write_json(report_path, report)
    try:
        # A private key database trusts only the pinned AWS public key.
        keydb = os.path.join(build, 'keydb')
        os.mkdir(keydb, 0o700)
        bp_call([rpm, '--dbpath', keydb, '--initdb'])
        bp_call([rpm, '--dbpath', keydb, '--import', os.path.join(inputs, BP_KEY)])
        signature = bp_call([rpm, '--dbpath', keydb, '--checksig', '--verbose', os.path.join(inputs, BP_SRPM)])
        if not re.search(r'Signature[^\n]*key ID c87f5b1a: OK', signature, re.I):
            raise RuntimeError('Expected AWS RPM signature not confirmed')
        report['rpm_signature_verified'] = True
        top = os.path.join(build, 'rpmbuild')
        os.mkdir(top, 0o700)
        sources = os.path.join(top, 'SOURCES')
        bp_extract_srpm(os.path.join(inputs, BP_SRPM), sources)
        for name in ['BUILD', 'BUILDROOT', 'RPMS', 'SPECS', 'SRPMS', 'tmp']:
            os.mkdir(os.path.join(top, name), 0o700)
        spec = os.path.join(top, 'SPECS', 'php.spec')
        with open(os.path.join(sources, 'php.spec'), 'rb') as handle:
            prepared = bp_render_spec(handle.read())
        os.unlink(os.path.join(sources, 'php.spec'))
        with open(spec, 'wb') as handle:
            handle.write(prepared)
        bp_stage_recipe_inputs(inputs, sources)
        definitions = ['_topdir ' + top, '_tmppath ' + os.path.join(top, 'tmp'),
                       'dist .amzn2', 'amzn 2', 'rhel 7', 'runselftest 1',
                       '_default_patch_fuzz 0', '_smp_mflags -j%d' % args.jobs]
        base = [rpmbuild]
        for value in definitions:
            base += ['--define', value]
        report['rpm_definitions'] = definitions
        report['spec_sha256'] = bp_hash(spec)
        report['regression_patch_sha256'] = BP_TEST_PATCH_SHA
        report['expected_upload_progress_xfails'] = 8
        report['stage'] = 'prepare_and_dependencies'
        write_json(report_path, report)
        say('正在检查构建依赖和补丁；日志：' + os.path.join(build, 'prep.log'))
        bp_call(base + ['-bp', spec], log=os.path.join(build, 'prep.log'))
        report['stage'] = 'compile_test_package'
        write_json(report_path, report)
        say('正在构建全部 RPM 并运行测试，可能耗时较长；日志：' + os.path.join(build, 'build.log'))
        bp_call(base + ['-ba', spec], log=os.path.join(build, 'build.log'))
        report['stage'] = 'verify_selftest_results'
        write_json(report_path, report)
        report['php_selftest_summary'] = bp_selftest_summary(os.path.join(build, 'build.log'))
        report['stage'] = 'mitigation_smoke_tests'
        write_json(report_path, report)
        report['mitigation_smoke_tests'] = bp_smoke_tests(top)
        paths = sorted(glob.glob(os.path.join(top, 'RPMS', '*', '*.rpm')))
        artifacts = bp_check_artifacts(paths, rpm)
        source_rpm = os.path.join(top, 'SRPMS', 'php-' + BP_VERSION + '-' + BP_RELEASE + '.src.rpm')
        if not os.path.isfile(source_rpm):
            raise RuntimeError('Rebuilt source RPM missing')
        report.update({'state': 'built_not_deployed', 'stage': 'complete', 'artifacts': artifacts,
                       'source_rpm': {'file': os.path.basename(source_rpm), 'sha256': bp_hash(source_rpm)},
                       'business_tests_passed': False, 'php_selftests_passed': True})
        write_json(report_path, report)
        say('RPM 构建和源码测试完成：' + os.path.join(top, 'RPMS'))
        say('产物尚未签名、未部署；还需在测试机验证第三方扩展、FPM 和业务后安排上线。')
        say('构建记录：' + report_path)
        return 0
    except Exception as exc:
        summary = bp_failure_summary(build, report.get('stage'))
        report.update({'state': 'build_failed', 'error': as_text(exc), 'failure_summary': summary})
        write_json(report_path, report)
        say('构建失败诊断：' + summary['hint'])
        say('构建记录：' + report_path)
        raise


def backport_main(argv):
    allow_all = BP_RECIPE == 'baota-al2-php74'
    parser = argparse.ArgumentParser(prog='php-cve-guard.sh ' + BP_COMMAND,
        description=('AL2 PHP 7.4：setup 安装构建依赖，auto 构建回补 RPM；' +
                     ('all 串联环境安装与普通用户构建；' if allow_all else '') +
                     '不自动部署生成的 PHP 包。'))
    parser.add_argument('action', choices=['doctor', 'setup', 'prepare', 'build', 'auto'] + (['all'] if allow_all else []))
    parser.add_argument('--output-dir', help='prepare 新建或验证复用已完成的工作目录')
    parser.add_argument('--work-dir', help='build/auto 工作目录；doctor/setup 可选，默认普通用户家目录下 ' + BP_DEFAULT_WORKDIR)
    parser.add_argument('--srpm', help='可选离线原始 SRPM，必须匹配内置 SHA256')
    parser.add_argument('--patch-file', help='可选离线官方补丁，必须匹配内置 SHA256')
    parser.add_argument('--key-file', help='可选离线 AWS 公钥，必须匹配内置 SHA256')
    if BP_SOURCE_ARCHIVE_URL:
        parser.add_argument('--source-tar', help='仅 prepare：离线宝塔 7.4.34 源码包，必须匹配内置 SHA256')
    parser.add_argument('--jobs', type=int, default=2, help='编译并发数，默认 2；auto 根据内存调低并发')
    setup_actions = 'setup/all' if allow_all else 'setup'
    parser.add_argument('--yes', action='store_true', help='仅 ' + setup_actions + '：执行环境安装' +
                        ('（all 随后构建）' if allow_all else '') + '；不提供时只生成环境计划')
    parser.add_argument('--build-user', help='仅 ' + setup_actions + '：普通构建用户，默认检测 ec2-user')
    parser.add_argument('--lock-wait', type=parse_lock_wait, default=None, help='仅 ' + setup_actions + '：等待 YUM 锁秒数，默认 120')
    args = parser.parse_args(argv)
    if getattr(args, 'source_tar', None) and args.action != 'prepare':
        parser.error('--source-tar only applies to prepare')
    if args.action not in ('setup', 'all') and (args.yes or args.build_user or args.lock_wait is not None):
        parser.error('--yes, --build-user and --lock-wait only apply to ' + setup_actions)
    if args.lock_wait is None:
        args.lock_wait = 120
    if args.action in ('setup', 'all') and (args.output_dir or args.srpm or args.patch_file or args.key_file):
        parser.error(setup_actions + ' downloads its own pinned inputs; use --work-dir and optional --build-user')
    if args.action == 'prepare' and (not args.output_dir or args.work_dir):
        parser.error('prepare requires --output-dir and does not accept --work-dir')
    if args.action in ('build', 'auto') and (not args.work_dir or args.output_dir or args.srpm or args.patch_file or args.key_file):
        parser.error('build/auto requires --work-dir; separate input overrides require prepare')
    if args.action == 'doctor' and (args.output_dir or args.srpm or args.patch_file or args.key_file):
        parser.error('doctor accepts optional --work-dir, not prepare input arguments')
    if args.jobs < 1 or args.jobs > 64:
        parser.error('--jobs must be between 1 and 64')
    try:
        if args.action == 'all':
            return be_all(args)
        if args.action == 'setup':
            return be_setup(args)
        if args.action == 'doctor':
            return bp_doctor(args)
        if args.action == 'auto':
            return bp_auto(args)
        return bp_prepare(args) if args.action == 'prepare' else bp_build(args)
    except (IOError, OSError, RuntimeError, ValueError) as exc:
        say('构建流程未完成：' + as_text(exc))
        return 20


def baota_al2_build_main(argv):
    """Use the BaoTa source recipe only for this synchronous CLI invocation.

    Forked unprivileged setup workers inherit these pinned values. Restore all
    defaults even when argparse raises, so embedded callers cannot alter a later
    ordinary build-al2-php74 invocation. This does not deploy any PHP RPM.
    """
    previous = dict((name, globals()[name]) for name in BP_BAOTA_RECIPE)
    globals().update(BP_BAOTA_RECIPE)
    try:
        return backport_main(argv)
    finally:
        globals().update(previous)
