# -*- coding: utf-8 -*-
"""Pinned BaoTa source + Ondrej packaging, rebuilt locally on Ubuntu 20.04.

This is a local rebuild, not a Canonical/Ondrej binary release.  No generated
DEB is installed here. The generic local installer must validate its manifest.
"""

DB_RECIPE = 'baota-ubuntu20.04-php74-ppa'
DB_VERSION = '1:7.4.34-0phpguard1~ubuntu20.04.1'
DB_PACKAGING_VERSION = '1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1'
DB_PACKAGING = 'php7.4_7.4.33-31+ubuntu22.04.1+deb.sury.org+1.debian.tar.xz'
DB_PACKAGING_SHA = '9bb6273e01ea4c127ebe95cedd0cedf6bc3f6658b4ac5e7c830f91ae7e7e3749'
DB_PACKAGING_URL = ('https://launchpad.net/~ondrej/+archive/ubuntu/php/+sourcefiles/php7.4/'
                    + DB_PACKAGING_VERSION + '/' + DB_PACKAGING)
DB_SOURCE = 'php-7.4.34.tar.gz'
DB_SOURCE_SHA = BAOTA_AL2_SOURCE_SHA
DB_SOURCE_URL = 'https://download.bt.cn/src/php-7.4.34.tar.gz'
DB_CONTROL_SHA = 'd557af22fdbf751e14aae9f1ed7f564853ca30f46749d3a799d5ebed26841bcd'
DB_SERIES_SHA = 'e043c70eb3a3694677eef80bc7e38a71aeba58ae134ff812e303d8033c6ba742'
DB_REBASE_136_SHA = '562d5bbdd2e66edf70b6cbef94fa7be94f92043d3302208c67753bf8f83a332e'
DB_REBASE_164_SHA = '7350d481983cec1af242ae37b71630194892f45df6027cce9b248edf32b470a3'
DB_TOOLS = ['dpkg-buildpackage', 'dpkg-checkbuilddeps', 'dpkg-deb', 'fakeroot',
            'make', 'gcc', 'g++', 'autoconf', 'automake', 'bison', 're2c', 'patch']
DB_LAST_BUILD_REPORT = None


def db_inputs():
    return {DB_SOURCE: DB_SOURCE_SHA, DB_PACKAGING: DB_PACKAGING_SHA}


def db_input_hashes():
    return db_inputs()


def db_extract(archive_path, destination, prefix):
    """Extract only regular files/directories, never links/devices or parents."""
    if os.path.lexists(destination):
        raise RuntimeError('Fresh extraction directory required: ' + destination)
    with tarfile.open(archive_path, 'r:*') as archive:
        entries, seen, total = [], set(), 0
        for member in archive:
            name = member.name.rstrip('/')
            parts = name.split('/')
            if (parts[0] != prefix or any(x in ('', '.', '..') for x in parts) or
                    name in seen or not (member.isfile() or member.isdir())):
                raise RuntimeError('Unsafe source archive member: ' + name)
            total += member.size
            if member.size > 64 * 1024 * 1024 or total > 256 * 1024 * 1024:
                raise RuntimeError('Source archive exceeds expected size bounds')
            seen.add(name)
            entries.append(member)
        os.makedirs(destination, 0o700)
        for member in entries:
            target = os.path.join(destination, member.name.rstrip('/'))
            if member.isdir():
                if not os.path.isdir(target): os.makedirs(target, 0o700)
            else:
                parent = os.path.dirname(target)
                if not os.path.isdir(parent): os.makedirs(parent, 0o700)
                with archive.extractfile(member) as source, open(target, 'wb') as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
    return os.path.join(destination, prefix)


def db_patch_rebase_136(original, source):
    """Keep all six ctype fixes; one is already in BaoTa's new upload parser."""
    import difflib
    with open(os.path.join(source, 'main/rfc1867.c')) as handle:
        before = handle.read()
    after = before
    for expression, count in [('line[0]', 1), ('*value', 0), ('*str', 1),
                              ('*strend', 1), ('*cd', 2)]:
        old, new = 'isspace(' + expression + ')', 'isspace((unsigned char)' + expression + ')'
        if after.count(old) != count or (not count and after.count(new) != 1):
            raise RuntimeError('Reviewed RFC1867 ctype context changed')
        after = after.replace(old, new)
    replacement = 'diff --git a/main/rfc1867.c b/main/rfc1867.c\n' + ''.join(
        difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                             fromfile='a/main/rfc1867.c', tofile='b/main/rfc1867.c'))
    start = original.index('diff --git a/main/rfc1867.c ')
    end = original.index('diff --git ', start + 10)
    result = original[:start] + replacement + original[end:]
    if hashlib.sha256(result.encode('utf-8')).hexdigest() != DB_REBASE_136_SHA:
        raise RuntimeError('Rebased ctype patch differs from reviewed fixed patch')
    return result


def db_patch_rebase_164(original):
    """A single blank line accounts for the vendor's equivalent security diff."""
    header = '@@ -437,10 +445,15 @@'
    line = '+\t\t\t/* Keep only headers we use, and ignore duplicates */'
    if original.count(header) != 1 or original.count(line) != 1:
        raise RuntimeError('Reviewed security patch context changed')
    result = original.replace(header, '@@ -437,10 +445,16 @@').replace(line, '+\n' + line)
    if hashlib.sha256(result.encode('utf-8')).hexdigest() != DB_REBASE_164_SHA:
        raise RuntimeError('Security proof patch differs from reviewed fixed patch')
    return result


def db_patch(source, patch, log, reverse=False, dry_run=False):
    argv = [bp_tool('patch'), '-f', '-p1', '-F0']
    if dry_run: argv.append('--dry-run')
    if reverse: argv.append('-R')
    argv += ['-i', os.path.abspath(patch)]
    proc = subprocess.Popen(argv, cwd=source, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, unused = proc.communicate()
    with open(log, 'ab') as handle:
        handle.write(('\nPATCH %s reverse=%s dry_run=%s\n' %
                      (os.path.basename(patch), reverse, dry_run)).encode('utf-8'))
        handle.write(out)
    return proc.returncode == 0


def db_render_rules(rules):
    if rules.count('RUN_TESTS := no') != 4 or 'RUN_TESTS := yes' in rules:
        raise RuntimeError('Pinned Debian testing rules changed')
    old_cgi = 'TEST_PHP_CGI_EXECUTABLE=$(CURDIR)/cgi-build/sapi/php-cgi'
    if rules.count(old_cgi) != 1:
        raise RuntimeError('Pinned Debian CGI test path changed')
    # Original packaging disables tests and has a stale CGI path. PHP's own
    # sapi/cgi/config9.m4 defines SAPI_CGI_PATH=sapi/cgi/php-cgi.
    return rules.replace('RUN_TESTS := no', 'RUN_TESTS := yes', 1).replace(
        old_cgi, 'TEST_PHP_CGI_EXECUTABLE=$(CURDIR)/cgi-build/sapi/cgi/php-cgi')


def db_materialize(inputs, folder):
    """Recreate source from immutable inputs; never trust an edited source tree."""
    for name, digest in db_inputs().items():
        bp_verify(os.path.join(inputs, name), digest)
    bp_verify_baota_archive(os.path.join(inputs, DB_SOURCE))
    source = db_extract(os.path.join(inputs, DB_SOURCE), os.path.join(folder, 'upstream'), 'php-7.4.34')
    packaging = db_extract(os.path.join(inputs, DB_PACKAGING), os.path.join(folder, 'packaging'), 'debian')
    os.rename(source, os.path.join(folder, 'source'))
    source = os.path.join(folder, 'source')
    shutil.copytree(packaging, os.path.join(source, 'debian'))
    patch_dir = os.path.join(source, 'debian', 'patches')
    series_path = os.path.join(patch_dir, 'series')
    bp_verify(series_path, DB_SERIES_SHA)
    bp_verify(os.path.join(source, 'debian', 'control'), DB_CONTROL_SHA)
    with open(series_path) as handle:
        original_series = handle.read()
    names = [line.strip() for line in original_series.splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    if len(names) != 164:
        raise RuntimeError('Pinned packaging patch count changed')
    log = os.path.join(folder, 'patchstack.log')
    reconciled = []
    for name in names:
        if not re.match(r'^[A-Za-z0-9_.+-]+$', name):
            raise RuntimeError('Unexpected quilt series entry')
        path = os.path.join(patch_dir, name)
        if name.startswith('0136-') or name.startswith('0164-'):
            with open(path) as handle:
                original = handle.read()
            changed = db_patch_rebase_136(original, source) if name.startswith('0136-') else db_patch_rebase_164(original)
            path = os.path.join(folder, 'rebased-' + name)
            with open(path, 'w') as handle:
                handle.write(changed)
        if db_patch(source, path, log, dry_run=True):
            if not db_patch(source, path, log):
                raise RuntimeError('Patch failed after successful dry run: ' + name)
            state = 'applied'
        elif db_patch(source, path, log, reverse=True, dry_run=True):
            state = 'already_present_reverse_verified'
        else:
            raise RuntimeError('Packaging patch conflicts; no security patch was discarded: ' + name)
        reconciled.append({'patch': name, 'state': state, 'applied_sha256': bp_hash(path)})
    if sum(x['state'] == 'applied' for x in reconciled) != 162:
        raise RuntimeError('Patch reconciliation differs from reviewed 162/2 result')
    # All patch content is now in source. Empty quilt series prevents dpkg-source
    # --before-build from applying the same patches for a second time.
    with open(series_path, 'w') as handle:
        handle.write('# Applied and verified by php-cve-guard; see phpguard-patch-reconciliation.json\n')
    write_json(os.path.join(source, 'debian', 'phpguard-patch-reconciliation.json'), reconciled)
    test_patch = os.path.join(folder, BP_TEST_PATCH_NAME)
    with open(test_patch, 'wb') as handle:
        handle.write(BP_TEST_PATCH)
    bp_verify(test_patch, BP_TEST_PATCH_SHA)
    if not db_patch(source, test_patch, log, dry_run=True) or not db_patch(source, test_patch, log):
        raise RuntimeError('Pinned regression tests could not be applied')
    rules_path = os.path.join(source, 'debian', 'rules')
    with open(rules_path) as handle:
        rules = handle.read()
    rules = db_render_rules(rules)
    with open(rules_path, 'w') as handle:
        handle.write(rules)
    os.chmod(rules_path, 0o755)
    changelog_path = os.path.join(source, 'debian', 'changelog')
    with open(changelog_path) as handle:
        changelog = handle.read()
    prefix = ('php7.4 (%s) focal; urgency=high\n\n'
              '  * Local BaoTa 7.4.34 rebuild, retaining reviewed Ondrej packaging patches.\n'
              '  * Enable full PHP tests and pinned CVE regressions.\n\n'
              ' -- PHP CVE Guard <phpguard@localhost>  Fri, 23 Oct 2026 00:00:00 +0000\n\n') % DB_VERSION
    with open(changelog_path, 'w') as handle:
        handle.write(prefix + changelog)
    return source, reconciled


def db_verify_inputs(folder):
    inputs = os.path.join(folder, 'inputs')
    for path in (folder, inputs):
        if not os.path.isdir(path) or os.path.islink(path):
            raise RuntimeError('Prepared directory missing or symlink: ' + path)
    for name, digest in db_inputs().items():
        bp_verify(os.path.join(inputs, name), digest)
    return inputs


def db_prepare(args):
    if os.geteuid() == 0:
        raise RuntimeError('Run source preparation as an ordinary build user')
    folder = os.path.abspath(args.work_dir)
    reused = os.path.lexists(folder)
    if reused:
        db_verify_inputs(folder)
    else:
        os.makedirs(os.path.join(folder, 'inputs'), 0o700)
    report = {'tool_version': VERSION, 'recipe': DB_RECIPE, 'state': 'preparing',
              'target_version': DB_VERSION, 'packaging_version': DB_PACKAGING_VERSION,
              'inputs': db_inputs(), 'deployed': False, 'distribution': 'ubuntu',
              'distribution_version': '20.04', 'architecture': 'amd64',
              'provenance': 'Pinned BaoTa tarball plus pinned Launchpad Ondrej Debian packaging; local rebuild',
              'reused_inputs': reused}
    try:
        for local, url, digest, name in [
                (getattr(args, 'source_tar', None), DB_SOURCE_URL, DB_SOURCE_SHA, DB_SOURCE),
                (getattr(args, 'packaging_tar', None), DB_PACKAGING_URL, DB_PACKAGING_SHA, DB_PACKAGING)]:
            say('正在准备并校验：' + name)
            if reused:
                if local: bp_verify(local, digest)
            else:
                bp_fetch(local, url, digest, os.path.join(folder, 'inputs', name))
        # Never trust/compile a cached preview after a rerun. Recreate it from
        # verified inputs, preserving any previous preview for diagnosis.
        prepared = tempfile.mkdtemp(prefix='prepare-', dir=folder)
        source, patches = db_materialize(os.path.join(folder, 'inputs'), prepared)
        preview = os.path.join(folder, 'preview')
        if os.path.lexists(preview):
            previous = tempfile.mkdtemp(prefix='preview-previous-', dir=folder)
            os.rmdir(previous)
            os.rename(preview, previous)
            report['previous_preview'] = previous
        os.rename(prepared, preview)
        source = os.path.join(preview, 'source')
        report.update(state='sources_prepared_not_built', source_dir=source, patch_reconciliation=patches)
        write_json(os.path.join(folder, 'prepare.json'), report)
        say('Ubuntu 20.04 / PPA PHP 7.4 源码已准备；尚未编译或部署：' + folder)
        return 0
    except Exception as exc:
        report.update(state='prepare_failed', error=as_text(exc))
        write_json(os.path.join(folder, 'prepare.json'), report)
        raise


def db_doctor(folder):
    import platform
    blockers, tools_found = [], {}
    system = _inv_os()
    machine = platform.machine()
    if sys.platform not in ('linux', 'linux2') or system.get('id') != 'ubuntu' or system.get('version_id') != '20.04' or machine != 'x86_64':
        blockers.append('This pinned DEB recipe only builds on Ubuntu 20.04 amd64')
    if os.geteuid() == 0:
        blockers.append('PHP source must be compiled by an ordinary build user')
    source = os.path.join(os.path.abspath(folder), 'preview', 'source')
    dependencies = {'state': 'not_checked'}
    try:
        db_verify_inputs(os.path.abspath(folder))
        # setup consumes only this pinned control file, never a caller-edited one.
        bp_verify(os.path.join(source, 'debian', 'control'), DB_CONTROL_SHA)
    except (RuntimeError, IOError, OSError) as exc:
        blockers.append(as_text(exc))
    for name in DB_TOOLS:
        try: tools_found[name] = bp_tool(name)
        except RuntimeError: tools_found[name] = None
    missing = [name for name in DB_TOOLS if not tools_found[name]]
    if missing:
        blockers.append('Missing build tools: ' + ', '.join(missing))
    if tools_found.get('dpkg-checkbuilddeps') and os.path.isfile(os.path.join(source, 'debian', 'control')):
        result = run_cmd([tools_found['dpkg-checkbuilddeps'], os.path.join(source, 'debian', 'control')], timeout=60)
        dependencies = {'state': 'satisfied' if result['code'] == 0 else 'missing_or_conflicting',
                        'exit_code': result['code'], 'diagnostic': (result['stderr'] + result['stdout'])[-12000:]}
        if result['code']:
            blockers.append('Native dpkg-checkbuilddeps reported missing/conflicting build dependencies')
    return {'tool_version': VERSION, 'recipe': DB_RECIPE,
            'state': 'build_ready' if not blockers else 'build_preflight_blocked',
            'blockers': blockers, 'host': system, 'machine': machine,
            'tools': tools_found, 'dependencies': dependencies, 'source_dir': source,
            'work_dir': os.path.abspath(folder), 'deployed': False}


def db_build_env(jobs):
    env = os.environ.copy()
    for name in list(env):
        if (name.startswith(('DEB_', 'DPKG_', 'DH_', 'TEST_PHP', 'PHP_TEST_', 'SKIP_')) or
                name in ('MAKEFLAGS', 'MFLAGS', 'GNUMAKEFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES',
                         'MAKEFILES', 'TESTS', 'RUN_TESTS', 'PHP_EXECUTABLE', 'PHPRC',
                         'PHP_INI_SCAN_DIR', 'NO_PHPTEST_SUMMARY', 'SHOW_ONLY_GROUPS',
                         'CC', 'CXX', 'CPP', 'LD', 'CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS')):
            del env[name]
    env.update(LC_ALL='C', LANG='C', TZ='UTC', USE_ZEND_ALLOC='1',
               DEB_BUILD_OPTIONS='parallel=' + str(jobs), DEB_BUILD_PROFILES='',
               NO_INTERACTION='1', REPORT_EXIT_STATUS='1')
    return env


def db_smoke(source):
    results = []
    for sapi in ('cli', 'fpm'):
        php = os.path.join(source, sapi + '-build', 'sapi', 'cli', 'php')
        if not os.path.isfile(php):
            raise RuntimeError('Built CLI missing for ' + sapi)
        result = run_cmd([php, '-n', '-r', 'echo PHP_VERSION_ID;'], timeout=15)
        if result['code'] or result['stdout'] != '70434':
            raise RuntimeError('Built CLI version check failed for ' + sapi)
        result = run_cmd([php, '-n', '-d', 'memory_limit=16M', '-r',
                          'register_shutdown_function(function(){fwrite(STDERR,"PHP_GUARD_SHUTDOWN_RAN");});'
                          '$v=str_repeat("x",32*1024*1024);'], timeout=15,
                         env={'USE_ZEND_ALLOC': '1', 'PHPRC': '', 'PHP_INI_SCAN_DIR': ''})
        if (result['code'] != 1 or 'Allowed memory size' not in result['stderr'] or
                'PHP_GUARD_SHUTDOWN_RAN' in result['stdout'] + result['stderr']):
            raise RuntimeError('OOM immediate-exit smoke failed for ' + sapi)
        results.append({'sapi': sapi, 'version_id': 70434, 'oom_exit': 1, 'shutdown_callback_ran': False})
    return results


def db_artifacts(folder):
    artifacts = []
    for path in sorted(glob.glob(os.path.join(folder, '*.deb'))):
        if os.path.islink(path) or not os.path.isfile(path):
            raise RuntimeError('Invalid DEB output')
        output = bp_call([bp_tool('dpkg-deb'), '--show',
                          '--showformat=${Package}\t${Version}\t${Architecture}\t${Source}\n', path]).rstrip('\r\n')
        fields = output.split('\t')
        if len(fields) != 4:
            raise RuntimeError('DEB metadata malformed')
        name, version, arch, source = fields
        source = source or name
        match = re.match(r'^php7\.4(?: \(([^)]+)\))?$', source)
        if (not match or (match.group(1) or version) != DB_VERSION or version != DB_VERSION or
                arch not in ('amd64', 'all') or
                not re.match(r'^(?:php7\.4(?:-[a-z0-9-]+)?|libphp7\.4-embed|libapache2-mod-php7\.4)$', name)):
            raise RuntimeError('Unexpected DEB package identity: ' + name)
        artifacts.append({'name': name, 'version': version, 'arch': arch, 'source': 'php7.4',
                          'source_version': DB_VERSION, 'filename': os.path.basename(path), 'sha256': bp_hash(path)})
    required = {'php7.4', 'php7.4-cli', 'php7.4-common', 'php7.4-fpm', 'php7.4-opcache', 'libapache2-mod-php7.4'}
    if not required.issubset(set(x['name'] for x in artifacts)) or len(artifacts) > 80:
        raise RuntimeError('DEB artifact set is incomplete or unexpected')
    return artifacts


def db_build(args):
    global DB_LAST_BUILD_REPORT
    folder = os.path.abspath(args.work_dir)
    preflight = db_doctor(folder)
    if preflight['blockers']:
        say(json.dumps(preflight, ensure_ascii=False, indent=2))
        return 10
    build = tempfile.mkdtemp(prefix='build-', dir=folder)
    report_path = os.path.join(build, 'build.json')
    DB_LAST_BUILD_REPORT = report_path
    report = {'tool_version': VERSION, 'recipe': DB_RECIPE, 'target_version': DB_VERSION,
              'packaging_version': DB_PACKAGING_VERSION, 'inputs': db_inputs(), 'state': 'building',
              'distribution': 'ubuntu', 'distribution_version': '20.04', 'architecture': 'amd64',
              'cves': CVES, 'upstream_commit': BP_COMMIT, 'signed': False, 'deployed': False,
              'regression_patch_sha256': BP_TEST_PATCH_SHA,
              'source_archive_sha256': DB_SOURCE_SHA, 'packaging_sha256': DB_PACKAGING_SHA,
              'compatible_upgrade_from': 'Ubuntu 20.04 amd64 Ondrej PPA php7.4 1:7.4.33 only',
              'stage': 'source_preparation'}
    write_json(report_path, report)
    try:
        source, patches = db_materialize(db_verify_inputs(folder), build)
        report.update(stage='compile_and_full_php_tests', patch_reconciliation=patches)
        write_json(report_path, report)
        log = os.path.join(build, 'build.log')
        report['build_monitor'] = {'timeout_seconds': BM_TIMEOUT_SECONDS,
                                   'interval_seconds': BM_INTERVAL_SECONDS,
                                   'progress_report': log + '.progress.json'}
        write_json(report_path, report)
        say('正在普通用户环境构建 Ubuntu DEB 并运行完整 PHP 测试：' + log)
        bm_run([bp_tool('dpkg-buildpackage'), '-us', '-uc', '-b', '-j' + str(args.jobs)],
               log, cwd=source, env=db_build_env(args.jobs))
        report['stage'] = 'full_test_verification'
        report['php_selftest_summary'] = bp_selftest_summary(log)
        report['mitigation_smoke_tests'] = db_smoke(source)
        report['artifacts'] = db_artifacts(build)
        report.update(state='built_and_tested_not_deployed', stage='complete', php_selftests_passed=True,
                      business_tests_passed=False, build_log_sha256=bp_hash(log))
        write_json(report_path, report)
        say('DEB 构建及强制测试通过，尚未部署：' + report_path)
        return 0
    except Exception as exc:
        report.update(state='build_failed', error=as_text(exc))
        write_json(report_path, report)
        raise


def deb_builder_main(argv=None):
    parser = argparse.ArgumentParser(prog='php-cve-guard.sh build-baota-ubuntu20-php74',
        description='Ubuntu20.04 amd64 / 原Ondrej PPA PHP7.4.33 的本地Baota源码DEB构建；不安装生成包')
    parser.add_argument('action', choices=['prepare', 'doctor', 'build'])
    parser.add_argument('--work-dir', '--output-dir', dest='work_dir', required=True)
    parser.add_argument('--source-tar', help='prepare 使用的固定SHA256宝塔源码包')
    parser.add_argument('--packaging-tar', help='prepare 使用的固定SHA256 Debian打包归档')
    parser.add_argument('--jobs', type=int, default=2)
    bm_add_arguments(parser)
    args = parser.parse_args(argv)
    bm_configure(args)
    if args.jobs < 1 or args.jobs > 32:
        parser.error('--jobs must be between 1 and 32')
    if args.action != 'prepare' and (args.source_tar or args.packaging_tar):
        parser.error('offline input options only apply to prepare')
    try:
        if args.action == 'prepare': return db_prepare(args)
        if args.action == 'build': return db_build(args)
        report = db_doctor(args.work_dir)
        say(json.dumps(report, ensure_ascii=False, indent=2))
        return 10 if report['blockers'] else 0
    except (RuntimeError, OSError, IOError, ValueError) as exc:
        say('Ubuntu DEB 构建操作失败：' + as_text(exc))
        return 20
