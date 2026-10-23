# -*- coding: utf-8 -*-
"""Local Ubuntu PPA-compatible DEB deployment, with native APT transactions."""

DI_RECEIPT = '/var/lib/php-cve-guard/baota-ubuntu20.04-php74-ppa.json'
DI_NAMES = r'^(?:php7\.4(?:-[a-z0-9-]+)?|libphp7\.4-embed|libapache2-mod-php7\.4)$'
DI_REQUIRED = set(('php7.4', 'php7.4-cli', 'php7.4-common', 'php7.4-fpm',
                   'php7.4-opcache', 'libapache2-mod-php7.4'))


def di_host_supported(inv):
    system = inv.get('os') or {}
    return (system.get('id') == 'ubuntu' and system.get('version_id') == '20.04' and
            inv.get('package_manager') == 'apt')


def di_validate_build(report):
    if (report.get('recipe') != DB_RECIPE or report.get('target_version') != DB_VERSION or
            report.get('packaging_version') != DB_PACKAGING_VERSION or
            report.get('distribution') != 'ubuntu' or report.get('distribution_version') != '20.04' or
            report.get('architecture') != 'amd64' or report.get('upstream_commit') != BP_COMMIT or
            report.get('state') != 'built_and_tested_not_deployed' or report.get('stage') != 'complete' or
            report.get('signed') is not False or report.get('php_selftests_passed') is not True or
            report.get('inputs') != db_input_hashes() or
            report.get('source_archive_sha256') != DB_SOURCE_SHA or
            report.get('packaging_sha256') != DB_PACKAGING_SHA or
            report.get('regression_patch_sha256') != BP_TEST_PATCH_SHA):
        raise RuntimeError('需要完整通过 build-baota-ubuntu20-php74 构建及测试的固定配方 build.json。')
    summary = report.get('php_selftest_summary') or {}
    if (not summary.get('total') or not summary.get('passed') or
            any(summary.get(key, -1) != 0 for key in ('failed', 'borked', 'leaked'))):
        raise RuntimeError('Complete successful PHP selftests are required')
    smoke = report.get('mitigation_smoke_tests') or []
    if (len(smoke) != 2 or set(item.get('sapi') for item in smoke) != set(('cli', 'fpm')) or
            any(item.get('version_id') != 70434 or item.get('oom_exit') != 1 or
                item.get('shutdown_callback_ran') is not False for item in smoke)):
        raise RuntimeError('Both Debian build CLI mitigation tests must pass')
    rows = report.get('artifacts')
    if not isinstance(rows, list) or not len(DI_REQUIRED) <= len(rows) <= 80:
        raise RuntimeError('Incomplete DEB artifact list')
    seen = set()
    for row in rows:
        name, arch = row.get('name', ''), row.get('arch', '')
        expected = '%s_%s_%s.deb' % (name, DB_VERSION.split(':', 1)[-1], arch)
        if (not re.match(DI_NAMES, name) or arch not in ('amd64', 'all') or
                row.get('version') != DB_VERSION or row.get('source') != 'php7.4' or
                row.get('source_version') != DB_VERSION or row.get('filename') != expected or
                not re.match(r'^[a-f0-9]{64}$', row.get('sha256', '')) or name in seen):
            raise RuntimeError('Unexpected/duplicate DEB identity')
        seen.add(name)
    if not DI_REQUIRED.issubset(seen):
        raise RuntimeError('Missing core PHP DEBs')
    return rows


def di_control_fields(raw):
    """Read one control stanza without executing maintainer scripts."""
    if len(raw) > 4 * 1024 * 1024 or not raw.strip():
        raise RuntimeError('DEB control stanza is missing or too large')
    fields, previous = {}, None
    for line in raw.strip('\n').splitlines():
        if line.startswith((' ', '\t')):
            if previous is None: raise RuntimeError('Invalid control continuation')
            fields[previous] += '\n' + line
            continue
        match = re.match(r'^([A-Za-z0-9-]+):\s?(.*)$', line)
        if not match or match.group(1).lower() in fields:
            raise RuntimeError('Invalid/duplicate DEB control field')
        previous = match.group(1).lower()
        fields[previous] = match.group(2)
    return fields


def di_metadata(path):
    result = run_cmd(['/usr/bin/dpkg-deb', '--field', path], timeout=60)
    if result['code']: raise RuntimeError('Cannot read staged DEB metadata')
    fields = di_control_fields(result['stdout'])
    name, version, arch = [fields.get(key, '') for key in ('package', 'version', 'architecture')]
    source = fields.get('source') or name
    match = re.match(r'^php7\.4(?: \(([^)]+)\))?$', source)
    if (not re.match(DI_NAMES, name) or version != DB_VERSION or arch not in ('amd64', 'all') or
            not match or (match.group(1) or version) != DB_VERSION or
            any(key in fields for key in ('filename', 'size', 'sha256', 'md5sum', 'sha1'))):
        raise RuntimeError('Staged DEB metadata does not match the fixed recipe')
    return {'name': name, 'version': version, 'arch': arch, 'source': 'php7.4',
            'source_version': match.group(1) or version, 'control': result['stdout'].rstrip() + '\n'}


def di_copy(source, destination, limit):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as src:
        info = os.fstat(src.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise RuntimeError('Expected a bounded regular build input')
        remaining = info.st_size
        with open(destination, 'wb') as dst:
            while remaining:
                data = src.read(min(1048576, remaining))
                if not data: raise RuntimeError('Build input changed while copying')
                dst.write(data); remaining -= len(data)
            if src.read(1): raise RuntimeError('Build input grew while copying')


def di_deb_md5(path):
    """Hash the package's checksum manifest without extracting any paths."""
    import io
    with open(os.devnull, 'wb') as errors:
        process = subprocess.Popen(['/usr/bin/dpkg-deb', '--ctrl-tarfile', path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        timer = threading.Timer(60, process.kill); timer.daemon = True; timer.start()
        try:
            raw = process.stdout.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                process.kill(); raise RuntimeError('DEB control archive too large')
            process.wait()
            if process.returncode: raise RuntimeError('DEB control archive unreadable')
        finally:
            timer.cancel()
            if process.poll() is None: process.kill(); process.wait()
            process.stdin.close(); process.stdout.close()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        manifests = [item for item in archive if item.name in ('md5sums', './md5sums')]
        if len(manifests) != 1 or not manifests[0].isfile() or manifests[0].size > 4 * 1024 * 1024:
            raise RuntimeError('Missing or invalid package md5sums manifest')
        data = archive.extractfile(manifests[0]).read()
    return hashlib.sha256(data).hexdigest()


def di_stage(report_path, folder):
    report = bi_read_json(report_path)
    rows = di_validate_build(report)
    origin = os.path.dirname(os.path.abspath(report_path))
    log = os.path.join(folder, 'accepted-build.log')
    di_copy(os.path.join(origin, 'build.log'), log, 512 * 1024 * 1024)
    if bp_hash(log) != report.get('build_log_sha256') or bp_selftest_summary(log) != report['php_selftest_summary']:
        raise RuntimeError('Full test log does not match accepted build record')
    directory = os.path.join(folder, 'debs'); os.mkdir(directory, 0o700)
    artifacts, records = [], []
    for row in rows:
        target = os.path.join(directory, row['filename'])
        di_copy(os.path.join(origin, row['filename']), target, 1024 ** 3)
        bp_verify(target, row['sha256'])
        metadata = di_metadata(target)
        if any(metadata[key] != row[key] for key in ('name', 'version', 'arch', 'source', 'source_version')):
            raise RuntimeError('DEB metadata differs from build record')
        records.append(metadata['control'] + 'Filename: ./' + row['filename'] + '\n' +
                       'Size: ' + str(os.path.getsize(target)) + '\nSHA256: ' + row['sha256'] + '\n')
        artifacts.append(dict(row, path=target, md5sums_sha256=di_deb_md5(target)))
    with open(os.path.join(directory, 'Packages'), 'wb') as handle:
        handle.write(('\n'.join(records) + '\n').encode('utf-8'))
    write_json(os.path.join(folder, 'build-record.json'), report)
    return artifacts


def di_installed(name, arch):
    query = '${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n'
    result = run_cmd(['/usr/bin/dpkg-query', '-W', '-f=' + query, name + ':' + arch])
    fields = result['stdout'].rstrip('\n').split('\t')
    if (result['code'] or len(fields) != 6 or len(fields[-1]) < 2 or fields[-1][1] != 'i' or
            fields[0].split(':')[0] != name or fields[2] != arch or fields[3] != 'php7.4'):
        raise RuntimeError('Installed DEB identity cannot be confirmed')
    return dict(name=name, version=fields[1], arch=fields[2], source=fields[3], source_version=fields[4])


def di_payload_ok(row):
    name, arch = row['name'], row['arch']
    paths = ['/var/lib/dpkg/info/' + name + ':' + arch + '.md5sums',
             '/var/lib/dpkg/info/' + name + '.md5sums']
    matches = []
    for path in paths:
        try:
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022:
                matches.append(bp_hash(path))
        except OSError:
            continue
    if row.get('md5sums_sha256') not in matches: return False
    result = run_cmd(['/usr/bin/dpkg', '--verify', name + ':' + arch], timeout=60)
    if result['code'] != 0 or result['stderr'].strip(): return False
    # dpkg --verify may return zero even when it lists changed files.
    for line in result['stdout'].splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3 and fields[1] == 'c': continue
        return False
    return True


def di_receipt():
    try:
        bi_private_dir(os.path.dirname(DI_RECEIPT))
        info = os.lstat(DI_RECEIPT)
        if info.st_uid != 0 or info.st_mode & 0o022: return {}
        value = bi_read_json(DI_RECEIPT)
        if value.get('recipe') != DB_RECIPE or value.get('source_sha256') != DB_SOURCE_SHA:
            return {}
        return value
    except (IOError, OSError, ValueError, RuntimeError):
        return {}


def di_assess(inv, receipt):
    findings = assess_inventory(inv, POLICY) + check_package_integrity(inv)
    accepted = set()
    for row in receipt.get('packages', []):
        if not re.match(DI_NAMES, row.get('name', '')) or row.get('arch') not in ('amd64', 'all'):
            continue
        try:
            installed = di_installed(row['name'], row['arch'])
            if installed['version'] == DB_VERSION and installed['source_version'] == DB_VERSION and di_payload_ok(row):
                accepted.add((row['name'], row['arch']))
        except RuntimeError:
            continue
    for finding in findings:
        matching = [package for package in inv.get('packages', [])
                    if package.get('name') == finding.get('package_name')]
        if (finding.get('kind') == 'package' and matching and
                all((package['name'].split(':')[0], package.get('arch')) in accepted and
                    package.get('version') == DB_VERSION and package.get('source') == 'php7.4'
                    for package in matching)):
            finding.update(status='fixed', reason='Matches accepted local Baota-source DEB receipt and package payload; not vendor signing')
    return findings


def di_plan(inv, artifacts):
    if not di_host_supported(inv):
        return {'updates': [], 'blockers': [{'reason': '仅支持 Ubuntu 20.04 amd64 的 Ondrej PHP 7.4.33 原生包。'}]}
    updates, blockers = [], []
    core = [package for package in inv.get('packages', []) if is_core_package(package)]
    if not core: blockers.append({'reason': '未发现已安装的 PHP 核心包。'})
    available = dict((row['name'], row) for row in artifacts)
    for package in core:
        name = package['name'].split(':')[0]
        version = package.get('version', '')
        original = bool(re.match(r'^1:7\.4\.33-[A-Za-z0-9.~+]+\+ubuntu20\.04(?:\.[0-9]+)?\+deb\.sury\.org\+[0-9]+$', version))
        if (package.get('source') != 'php7.4' or not re.match(DI_NAMES, name) or
                package.get('arch') not in ('amd64', 'all') or not (original or version == DB_VERSION)):
            blockers.append({'reason': '此源码包只兼容原 Ubuntu 20.04 Ondrej PHP 7.4.33；官方 7.4.3 请走 ESM 仓库修复：' + name})
            continue
        item = available.get(name)
        if not item or item['arch'] != package['arch']:
            blockers.append({'reason': '本次构建缺少已安装 PHP 子包或架构不匹配：' + name}); continue
        if version == DB_VERSION:
            if not di_payload_ok(item):
                blockers.append({'reason': '同版本 DEB 内容与本次构建不一致：' + name})
        elif native_compare(DB_VERSION, version, 'apt') <= 0:
            blockers.append({'reason': '拒绝降级或同版本重装：' + name})
        else:
            updates.append(dict(item, name=package['name'], old_version=version))
    blockers.extend(finding for finding in assess_inventory(inv, POLICY) + check_package_integrity(inv)
                    if finding.get('kind') != 'package')
    return {'updates': updates, 'blockers': blockers}


_DI_WORKER = r'''
import hashlib

def di_changes(cache, wanted):
    changes = []
    for package in cache.get_changes():
        name = package.name
        item = wanted.get(name)
        if not item: raise RuntimeError('Unapproved DEB transaction change: ' + name)
        candidate = package.candidate
        if (not package.marked_upgrade or package.marked_delete or package.marked_downgrade or
                not package.installed or not candidate or candidate.version != item['version'] or
                candidate.architecture != item['arch'] or candidate.source_name != 'php7.4' or
                candidate.source_version != item['version']):
            raise RuntimeError('Unapproved DEB transaction change: ' + name)
        changes.append(name)
    if set(changes) != set(wanted): raise RuntimeError('DEB transaction does not exactly match selected packages')
    return changes

def di_cross_replacements(cache, candidate, wanted):
    # Replaces can transfer file ownership without removing a package, so the
    # normal APT action list alone cannot prove that unrelated packages survive.
    for kind in ('Replaces', 'Conflicts', 'Breaks'):
        for group in candidate._cand.depends_list.get(kind, []):
            for dependency in group:
                for version in dependency.all_targets():
                    package = version.parent_pkg
                    installed = package.current_ver
                    if installed and installed.ver_str == version.ver_str and package.name not in wanted:
                        raise RuntimeError('DEB %s affects unapproved installed package: %s' % (kind, package.name))

def di_snapshot(cache):
    return dict((package.fullname, (package.installed.version, package.installed.architecture,
                package.installed.source_name)) for package in cache if package.installed)

def di_native(data):
    executed = False
    try:
        apt_pkg.init_config()
        config = apt_pkg.config
        for key, value in data['apt_config'].items(): config.set(key, value)
        # A system target such as focal is absent from this private flat index.
        # Clear only that target in this process; configured pinning still applies.
        config.clear('APT::Default-Release')
        config.set('APT::Get::AllowUnauthenticated', 'false')
        config.set('Acquire::AllowInsecureRepositories', 'false')
        config.set('Acquire::AllowDowngradeToInsecureRepositories', 'false')
        config.set('APT::Install-Recommends', 'false')
        config.set('APT::Install-Suggests', 'false')
        config.set('Dpkg::Options::', '--force-confold')
        config.set('APT::Sandbox::User', 'root')  # Only the root-private local file repository.
        apt_pkg.init_system()
        cache = apt.Cache(memonly=True)
        if not cache.update(): raise RuntimeError('Private local APT index could not be loaded')
        cache.close()
        with _system_lock(data.get('lock_wait', 120)):
            cache = apt.Cache(memonly=True)
            if cache.dpkg_journal_dirty or cache.broken_count:
                raise RuntimeError('Pre-existing dpkg journal or broken dependency state; no install attempted')
            wanted = dict((row['name'].split(':')[0], row) for row in data['updates'])
            if not wanted or len(wanted) != len(data['updates']): raise RuntimeError('Empty/duplicate DEB transaction')
            before = di_snapshot(cache)
            expected = dict(before)
            def verify_files():
                for row in data['updates']:
                    h = hashlib.sha256()
                    with open(row['path'], 'rb') as handle:
                        for chunk in iter(lambda: handle.read(1048576), b''): h.update(chunk)
                    if h.hexdigest() != row['sha256']: raise RuntimeError('Staged DEB checksum changed')
            verify_files()
            for name, row in wanted.items():
                if name not in cache: raise RuntimeError('DEB package is no longer installed: ' + name)
                package = cache[name]
                old = package.installed
                if (not old or old.version != row['old_version'] or old.architecture != row['arch'] or
                        old.source_name != 'php7.4' or apt_pkg.version_compare(row['version'], old.version) <= 0):
                    raise RuntimeError('Installed DEB changed or upgrade is not strict: ' + name)
                if package._pkg.selected_state == apt_pkg.SELSTATE_HOLD:
                    raise RuntimeError('DEB package is held: ' + name)
                hits = [v for v in package.versions if v.version == row['version'] and v.architecture == row['arch']]
                if len(hits) != 1 or not package.candidate or package.candidate.version != row['version']:
                    raise RuntimeError('Local DEB candidate missing or pinning forbids it: ' + name)
                selected = hits[0]
                if selected.source_name != 'php7.4' or selected.source_version != row['version']:
                    raise RuntimeError('Local DEB source mismatch')
                di_cross_replacements(cache, selected, wanted)
                package.candidate = selected
                expected[package.fullname] = (row['version'], row['arch'], 'php7.4')
            for name in wanted: cache[name].mark_install(auto_fix=True, auto_inst=True, from_user=False)
            if cache.broken_count: raise RuntimeError('Local DEB dependencies cannot be satisfied without new packages')
            changes = di_changes(cache, wanted)
            if data.get('execute'):
                verify_files(); di_changes(cache, wanted)
                os.environ['DEBIAN_FRONTEND'] = 'noninteractive'; os.environ['NEEDRESTART_MODE'] = 'l'
                executed = True
                # Cache.commit/install_archives handles the inner dpkg lock;
                # invoking dpkg directly while holding SystemLock would deadlock.
                if not cache.commit(apt.progress.base.AcquireProgress(), apt.progress.base.InstallProgress()):
                    raise RuntimeError('Local APT commit failed; partial changes may have occurred')
                cache.open()
                if di_snapshot(cache) != expected or cache.broken_count:
                    raise RuntimeError('Installed package snapshot differs after DEB transaction')
            return dict(ok=True, executed=executed, changes=changes,
                        provenance='operator-accepted local unsigned DEBs, private file repository')
    except Exception as exc:
        return dict(ok=False, executed=executed, error=str(exc))

with open(sys.argv[1]) as handle: request = json.load(handle)
answer = di_native(request)
with open(sys.argv[2], 'w') as handle: json.dump(answer, handle)
'''


def di_transaction(updates, folder, execute=False, lock_wait=120):
    if not updates: return {'ok': True, 'executed': False, 'changes': []}
    if not re.match(r'^/[A-Za-z0-9_./-]+$', folder):
        raise RuntimeError('Private APT transaction path must contain only safe ASCII path characters')
    repository = os.path.join(folder, 'debs')
    state = tempfile.mkdtemp(prefix='apt-', dir=folder)
    for name in ('lists', 'lists/partial', 'archives', 'archives/partial', 'sourceparts'):
        os.mkdir(os.path.join(state, name), 0o700)
    sources = os.path.join(state, 'sources.list')
    # Trust is scoped to this root-private index after explicit local-build
    # selection. System sources and their signature policy are never changed.
    with open(sources, 'w') as handle:
        handle.write('deb [trusted=yes] file:' + repository + ' ./\n')
    config = {'Dir': '/', 'Dir::State::status': '/var/lib/dpkg/status',
              'Dir::Etc::sourcelist': sources, 'Dir::Etc::sourceparts': os.path.join(state, 'sourceparts'),
              'Dir::State::lists': os.path.join(state, 'lists'),
              'Dir::Cache::archives': os.path.join(state, 'archives'),
              'Dir::Cache::pkgcache': '', 'Dir::Cache::srcpkgcache': '', 'Acquire::Languages': 'none'}
    prelude = APT_WORKER.split('\ntry:\n    with open(sys.argv[1])', 1)[0]
    return worker_call(prelude + '\n' + _DI_WORKER,
                       {'updates': updates, 'execute': execute, 'lock_wait': lock_wait, 'apt_config': config},
                       ['apt', 'apt_pkg'], timeout=None if execute else 600 + lock_wait)


def di_save_receipt(artifacts):
    bi_private_dir(os.path.dirname(DI_RECEIPT))
    rows = []
    for row in artifacts:
        try:
            installed = di_installed(row['name'], row['arch'])
            if installed['version'] == DB_VERSION and installed['source_version'] == DB_VERSION and di_payload_ok(row):
                rows.append(dict((key, row[key]) for key in ('name', 'arch', 'sha256', 'md5sums_sha256')))
        except RuntimeError:
            pass
    receipt = {'recipe': DB_RECIPE, 'source_sha256': DB_SOURCE_SHA, 'packages': rows,
               'accepted_at': datetime.datetime.now().isoformat(), 'trust': 'operator-selected local unsigned DEBs'}
    fd, temporary = tempfile.mkstemp(prefix='.receipt-', dir=os.path.dirname(DI_RECEIPT)); os.close(fd)
    try:
        write_json(temporary, receipt); os.rename(temporary, DI_RECEIPT)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    return receipt


def deb_install_main(argv):
    parser = argparse.ArgumentParser(prog='php-cve-guard.sh baota-ubuntu20-php74',
        description='Ubuntu 20.04 amd64 Ondrej PHP 7.4.33 的本地宝塔源码 DEB 升级。')
    parser.add_argument('mode', choices=['audit', 'plan', 'fix'])
    parser.add_argument('--build-report'); parser.add_argument('--work-dir')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--service', action='append', default=[])
    parser.add_argument('--health-url', action='append', default=[]); parser.add_argument('--health-host')
    parser.add_argument('--lock-wait', type=parse_lock_wait, default=120)
    args = parser.parse_args(argv)
    if args.build_report and args.work_dir: parser.error('use either --build-report or --work-dir')
    if args.mode != 'audit' and not (args.build_report or args.work_dir): parser.error('plan/fix requires a build report or work directory')
    if sys.platform not in ('linux', 'linux2') or os.geteuid() != 0:
        say('请在 Ubuntu 20.04 amd64 上使用 sudo/root。未执行升级。'); return 2
    os.umask(0o077); base = '/var/log/php-cve-guard'; bi_private_dir(base)
    folder = tempfile.mkdtemp(prefix='baota-deb-upgrade-', dir=base)
    path = os.path.join(folder, 'report.json')
    report = {'tool_version': VERSION, 'recipe': DB_RECIPE, 'mode': args.mode, 'result': 'inspecting', 'deployed': False}
    lock_fd = None
    try:
        if args.mode == 'fix' and args.yes: lock_fd = acquire_repair_lock()
        inv = collect_inventory(); report['inventory_before'] = inv
        if not di_host_supported(inv) or os.uname()[4] != 'x86_64':
            report['result'] = 'unsupported_host'; say('仅支持 Ubuntu 20.04 amd64；未执行升级。'); return 10
        if args.mode == 'audit':
            findings = di_assess(inv, di_receipt()); report['findings'] = findings
            show_summary(inv, findings, folder)
            good = all(row['status'] == 'fixed' for row in findings)
            report['result'] = 'fixed_within_scope' if good else 'unresolved'; return 0 if good else 10
        selected = args.build_report or bi_latest_report(args.work_dir)
        report['selected_build_report'] = os.path.abspath(selected)
        artifacts = di_stage(selected, folder)
        plan = di_plan(inv, artifacts); preflight = service_preflight(inv, plan['updates'], args.service)
        report.update(plan=plan, service_preflight=preflight)
        for item in plan['updates']: say('计划：%s %s -> %s' % (item['name'], item['old_version'], item['version']))
        if plan['blockers'] or preflight['blockers']:
            report['result'] = 'blocked_no_update'; print_blockers(inv, plan, preflight); return 10
        if not plan['updates']:
            findings = di_assess(inv, {'packages': artifacts}); report['findings'] = findings
            if any(item['status'] != 'fixed' for item in findings):
                report['result'] = 'no_update_unresolved'; return 10
            if args.mode == 'fix' and args.yes: di_save_receipt(artifacts)
            report['result'] = 'already_installed_verified'; return 0
        preview = di_transaction(plan['updates'], folder, lock_wait=args.lock_wait); report['transaction_preview'] = preview
        if not preview.get('ok'):
            report['result'] = 'blocked_transaction'; say(_display_value(preview.get('error'))); return 20
        if args.mode == 'plan' or not args.yes:
            report['result'] = 'plan_ready'; say('计划通过；fix --yes 接受本地未签名 DEB，安装脚本可能重启 PHP。'); return 0
        report['health_before'] = health_checks(args.health_url, args.health_host)
        if any(not row['ok'] for row in report['health_before']):
            report['result'] = 'blocked_health_before'; return 10
        fresh = repair_revalidate(inv, plan['updates'], preflight['services'], POLICY); report['revalidate_before'] = fresh
        if not fresh['ok']: report['result'] = 'blocked_host_changed'; return 10
        report['backup'] = backup_configuration(fresh['inventory'], plan['updates'], folder)
        report['result'] = 'installing'; write_json(path, report)
        applied = di_transaction(plan['updates'], folder, execute=True, lock_wait=args.lock_wait)
        report.update(transaction=applied, deployed=bool(applied.get('executed')))
        if not applied.get('ok'): report['result'] = 'installation_failed_or_partial'; return 20
        after_check = repair_revalidate(inv, plan['updates'], preflight['services'], POLICY, after_update=True)
        report['revalidate_after'] = after_check
        if not after_check['ok']: report['result'] = 'installed_followup_required'; return 20
        report['restart'] = restart_services(preflight['services'])
        if not report['restart']['ok']: report['result'] = 'installed_restart_failed'; return 20
        after = collect_inventory(); report['inventory_after'] = after
        receipt = di_save_receipt(artifacts); report['receipt_path'] = DI_RECEIPT
        findings = di_assess(after, receipt); report['findings_after'] = findings
        report['residual_process_check'] = residual_process_check(inv, after, plan['updates'], preflight['services'])
        report['health_after'] = health_checks(args.health_url, args.health_host)
        good = (all(row['status'] == 'fixed' for row in findings) and report['residual_process_check']['ok'] and
                all(row['ok'] for row in report['health_after']))
        report['result'] = 'fixed_within_scope' if good else 'installed_followup_required'
        say('本次覆盖的 PHP 包与重启检查通过。' if good else '已安装，仍有未通过的校验，详见报告。')
        if not args.health_url: say('未提供业务健康检查 URL，业务功能尚未验证。')
        return 0 if good else 10
    except Exception as exc:
        report.update(result='error', error=as_text(exc)); say('操作未完成：' + _display_value(exc)); return 20
    finally:
        write_json(path, report); say('报告：' + path)
        if lock_fd is not None: os.close(lock_fd)
