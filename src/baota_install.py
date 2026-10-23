# -*- coding: utf-8 -*-
"""Deploy local AL2 RPMs built from the pinned Baota source recipe.

A local build report is the operator's build record, not a vendor signature.
Root copies and verifies the complete bundle before RPM sees any package.
"""

BI_RECEIPT = '/var/lib/php-cve-guard/baota-al2-php74.json'
BI_QF = '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{SHA1HEADER}\n'
BI_ACTIVE_RECIPE = 'baota-al2-php74'


def bi_recipe():
    """Fixed recipe contexts; never derive a deployment recipe from a report."""
    if BI_ACTIVE_RECIPE == 'baota-remi-el7-php74':
        return {'id': RB_RECIPE, 'version': RB_VERSION, 'release': RB_RELEASE,
                'source_sha256': RB_SOURCE_SHA, 'inputs': rb_input_hashes(),
                'packaging_commit': RB_COMMIT, 'core_names': RB_CORE_NAMES,
                'smoke_sapis': RB_SMOKE_SAPIS, 'min_artifacts': len(RB_CORE_NAMES),
                'command': 'baota-remi-el7-php74', 'build_command': 'build-baota-remi-el7-php74',
                'host_label': 'CentOS 7 / RHEL 7 x86_64（Remi 系统 PHP 7.4）',
                'scope': 'EL7 native Remi RPM PHP 7.4, Baota source local build',
                'requires_srpm_signature': False}
    if BI_ACTIVE_RECIPE != 'baota-al2-php74':
        raise RuntimeError('Unknown local RPM deployment recipe')
    return {'id': 'baota-al2-php74', 'version': BAOTA_AL2_VERSION,
            'release': BAOTA_AL2_RELEASE, 'source_sha256': BAOTA_AL2_SOURCE_SHA,
            'inputs': {BP_SRPM: BP_SRPM_SHA, BP_KEY: BP_KEY_SHA,
                       BP_PATCH: BP_PATCH_SHA, 'php-7.4.34.tar.gz': BAOTA_AL2_SOURCE_SHA},
            'core_names': BP_CORE_NAMES, 'smoke_sapis': ('build-apache', 'build-ztscli'),
            'min_artifacts': 25, 'command': 'baota-al2-php74',
            'build_command': 'build-baota-al2-php74', 'host_label': 'Amazon Linux 2 x86_64',
            'scope': 'AL2 native RPM PHP 7.4, Baota source local build',
            'requires_srpm_signature': True}


def bi_host_supported(inv):
    system = inv.get('os') or {}
    if inv.get('package_manager') != 'yum':
        return False
    if BI_ACTIVE_RECIPE == 'baota-remi-el7-php74':
        return (system.get('id') in ('centos', 'rhel') and
                as_text(system.get('version_id') or '').split('.')[0] == '7')
    return system.get('id') == 'amzn' and system.get('version_id') == '2'


def bi_read_json(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024 * 1024:
        raise RuntimeError('Expected a regular JSON file no larger than 4 MiB: ' + path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        actual = os.fstat(handle.fileno())
        if not stat.S_ISREG(actual.st_mode):
            raise RuntimeError('JSON input changed type')
        raw = handle.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeError('JSON exceeds size limit')
    value = json.loads(raw.decode('utf-8'))
    if not isinstance(value, dict):
        raise RuntimeError('JSON object required')
    return value


def bi_private_dir(path):
    if not os.path.lexists(path):
        parent = os.path.dirname(path)
        bi_private_dir(parent)
        os.mkdir(path, 0o700)
    current = path
    while True:
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Unsafe root-owned directory: ' + current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent


def bi_metadata(path=None, package=None):
    argv = ['/usr/bin/rpm', '-qp' if path else '-q', '--qf', BI_QF,
            '--', path or package]
    result = run_cmd(argv, timeout=30)
    fields = result['stdout'].strip().split('\t')
    if result['code'] or len(fields) != 6 or not re.match(r'^[a-fA-F0-9]{40}$', fields[-1]):
        raise RuntimeError('Cannot verify RPM identity/header: ' + (path or package))
    return dict(zip(('name', 'version', 'release', 'arch', 'source_rpm', 'header_sha1'), fields))


def bi_validate_build(report):
    recipe = bi_recipe()
    if (report.get('recipe') != recipe['id'] or
            report.get('state') != 'built_not_deployed' or report.get('stage') != 'complete' or
            report.get('target_version') != recipe['version'] or
            report.get('target_release') != recipe['release'] or
            report.get('upstream_commit') != BP_COMMIT or
            report.get('php_selftests_passed') is not True):
        raise RuntimeError('需要 %s 完整构建通过的 build.json，不能用源码准备报告或其他配方产物。' % recipe['build_command'])
    if recipe['requires_srpm_signature']:
        if report.get('rpm_signature_verified') is not True:
            raise RuntimeError('AL2 source RPM signature verification is required')
    elif (report.get('packaging_commit') != recipe['packaging_commit'] or
          report.get('source_sha256') != recipe['source_sha256'] or
          report.get('regression_patch_sha256') != BP_TEST_PATCH_SHA or
          report.get('source_signature_verified') is not False or report.get('signed') is not False or
          report.get('rpm_signature_verified') is True or
          report.get('tests_required') is not True):
        raise RuntimeError('Remi pinned git/source/test provenance mismatch; this recipe does not have a vendor-signed SRPM')
    inputs = report.get('inputs') or {}
    if recipe['id'] == 'baota-remi-el7-php74' and inputs != recipe['inputs']:
        raise RuntimeError('Remi build inputs must exactly match the pinned recipe')
    for name, digest in recipe['inputs'].items():
        if inputs.get(name) != digest:
            raise RuntimeError('Build input recipe mismatch: ' + name)
    summary = report.get('php_selftest_summary') or {}
    if (not summary.get('total') or not summary.get('passed') or
            any(summary.get(k, -1) != 0 for k in ('failed', 'borked', 'leaked'))):
        raise RuntimeError('Successful full PHP selftests are required')
    smoke = report.get('mitigation_smoke_tests') or []
    if (len(smoke) != 2 or set(x.get('sapi') for x in smoke) != set(recipe['smoke_sapis']) or
            any(x.get('version') != recipe['version'] or x.get('oom_exit') != 1 or
                x.get('shutdown_callback_ran') is not False for x in smoke)):
        raise RuntimeError('Both built CLI mitigation tests must pass')
    rows = report.get('artifacts')
    if not isinstance(rows, list) or not recipe['min_artifacts'] <= len(rows) <= 64:
        raise RuntimeError('Incomplete or invalid RPM artifact list')
    seen, names = set(), set()
    for row in rows:
        name, arch, filename = row.get('name', ''), row.get('arch', ''), row.get('file', '')
        if (not re.match(r'^php(?:-[a-z0-9-]+)?$', name) or arch not in ('x86_64', 'noarch') or
                row.get('version') != recipe['version'] or row.get('release') != recipe['release'] or
                filename != '%s-%s-%s.%s.rpm' % (name, recipe['version'], recipe['release'], arch) or
                not re.match(r'^[a-f0-9]{64}$', row.get('sha256', '')) or (name, arch) in seen):
            raise RuntimeError('Unexpected/duplicate artifact identity')
        seen.add((name, arch))
        names.add(name)
    if not recipe['core_names'].issubset(names):
        raise RuntimeError('Missing core PHP RPMs in build')
    return rows


def bi_latest_report(folder):
    paths = glob.glob(os.path.join(os.path.abspath(folder), 'build-*', 'build.json'))
    if not paths:
        raise RuntimeError('工作目录没有 build-*/build.json，请先完成 all/auto 构建。')
    # Deliberately choose the latest attempt, even if it failed. Never silently
    # fall back to an older build when a new attempt has not passed validation.
    return max(paths, key=lambda path: (os.lstat(path).st_mtime, path))


def bi_stage(report_path, folder):
    recipe = bi_recipe()
    report_path = os.path.abspath(report_path)
    report = bi_read_json(report_path)
    rows = bi_validate_build(report)
    build_dir = os.path.dirname(report_path)
    # Reparse the full test log instead of trusting its JSON summary alone.
    log_path = os.path.join(build_dir, 'build.log')
    log_fd = os.open(log_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    copied_log = os.path.join(folder, 'accepted-build.log')
    with os.fdopen(log_fd, 'rb') as src:
        info = os.fstat(src.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 512 * 1024 * 1024:
            raise RuntimeError('Build log is not a regular bounded file')
        remaining = info.st_size
        with open(copied_log, 'wb') as dst:
            while remaining:
                data = src.read(min(1048576, remaining))
                if not data: raise RuntimeError('Build log changed while reading')
                dst.write(data)
                remaining -= len(data)
            if src.read(1): raise RuntimeError('Build log grew while reading')
    summary = bp_selftest_summary(copied_log)
    if summary != report['php_selftest_summary']:
        raise RuntimeError('Build log and test report differ')
    stage = os.path.join(folder, 'rpms')
    os.mkdir(stage, 0o700)
    artifacts = []
    for row in rows:
        source = os.path.join(build_dir, 'rpmbuild', 'RPMS', row['arch'], row['file'])
        destination = os.path.join(stage, row['file'])
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(source_fd, 'rb') as src:
            info = os.fstat(src.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 ** 3:
                raise RuntimeError('Invalid or oversized RPM input')
            with open(destination, 'wb') as dst:
                remaining = info.st_size
                while remaining:
                    data = src.read(min(1024 * 1024, remaining))
                    if not data:
                        raise RuntimeError('RPM input changed during copy')
                    dst.write(data)
                    remaining -= len(data)
                if src.read(1):
                    raise RuntimeError('RPM input grew during copy')
        bp_verify(destination, row['sha256'])
        meta = bi_metadata(path=destination)
        if any(meta[key] != row[key] for key in ('name', 'version', 'release', 'arch')):
            raise RuntimeError('RPM metadata disagrees with build manifest')
        if meta['source_rpm'] != 'php-%s-%s.src.rpm' % (recipe['version'], recipe['release']):
            raise RuntimeError('Unexpected source RPM identity')
        artifacts.append(dict(row, path=destination, header_sha1=meta['header_sha1']))
    write_json(os.path.join(folder, 'build-record.json'), report)
    return artifacts


def bi_receipt():
    recipe = bi_recipe()
    try:
        bi_private_dir(os.path.dirname(BI_RECEIPT))
        info = os.lstat(BI_RECEIPT)
        if info.st_uid != 0 or info.st_mode & 0o022:
            return {}
        value = bi_read_json(BI_RECEIPT)
        if value.get('recipe') != recipe['id'] or value.get('source_sha256') != recipe['source_sha256']:
            return {}
        if recipe.get('packaging_commit') and value.get('packaging_commit') != recipe['packaging_commit']:
            return {}
        return value
    except (IOError, OSError, ValueError, RuntimeError):
        return {}


def bi_assess(inv, receipt):
    recipe = bi_recipe()
    findings = assess_inventory(inv, POLICY) + check_package_integrity(inv)
    accepted = set()
    for row in receipt.get('packages', []):
        name, arch = row.get('name', ''), row.get('arch', '')
        if not re.match(r'^php(?:-[a-z0-9-]+)?$', name) or arch not in ('x86_64', 'noarch'):
            continue
        try:
            metadata = bi_metadata(package=name + '.' + arch)
            if (metadata['version'] == recipe['version'] and metadata['release'] == recipe['release'] and
                    metadata['header_sha1'] == row.get('header_sha1')):
                accepted.add((name, arch))
                if not bi_payload_ok(name + '.' + arch):
                    findings.append({'kind': 'binary_integrity', 'package_name': name,
                                     'status': 'unknown', 'reason': 'RPM non-config payload changed or could not be verified'})
        except RuntimeError:
            pass
    for finding in findings:
        # RPM inventory may contain the same name for several architectures.
        # Findings have no architecture field, so only accept a name when every
        # corresponding installed identity is covered by the accepted receipt.
        matching = [package for package in inv.get('packages', [])
                    if package.get('name') == finding.get('package_name')]
        if (finding.get('kind') == 'package' and matching and
                all((package['name'], package.get('arch')) in accepted and
                    package.get('version') == recipe['version'] + '-' + recipe['release'] and
                    package.get('source') == 'php' for package in matching)):
            finding.update(status='fixed', reason='Matches locally accepted Baota-source %s RPM header; local build receipt, not vendor signing' % recipe['id'])
    return findings


def bi_payload_ok(package):
    result = run_cmd(['/usr/bin/rpm', '-V', '--', package], timeout=60)
    if result['code'] == 0:
        return True
    if result['code'] != 1 or not result['stdout'].strip() or result['stderr'].strip():
        return False
    for line in result['stdout'].splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3 and fields[1] == 'c':
            continue  # Deliberate php.ini/FPM configuration changes are retained.
        if (len(fields) < 2 or len(fields[0]) != 9 or
                re.search(r'[S5L?]', fields[0])):
            return False
    return True


def bi_plan(inv, artifacts):
    recipe = bi_recipe()
    blockers, updates = [], []
    if not bi_host_supported(inv):
        return {'updates': [], 'blockers': [{'reason': '此兼容 RPM 安装路径仅支持 %s。' % recipe['host_label']}]}
    core = [p for p in inv.get('packages', []) if is_core_package(p)]
    if not core:
        blockers.append({'reason': '未发现系统 RPM 管理的 PHP；宝塔面板路径不能用本命令覆盖。'})
    available = dict(((p['name'], p['arch']), p) for p in artifacts)
    for package in core:
        if package.get('source') != 'php' or branch_of(package.get('version')) != '7.4' or package.get('arch') not in ('x86_64', 'noarch'):
            blockers.append({'reason': '存在不适用此配方的 PHP 包：' + package['name']})
            continue
        if (recipe['id'] == 'baota-remi-el7-php74' and
                (not re.match(r'^7\.4\.\d+-[A-Za-z0-9._+~]*\.el7\.remi(?:[A-Za-z0-9._+~-]*)$', package.get('version', '')) or
                 package.get('source_rpm') != 'php-' + package['version'] + '.src.rpm')):
            blockers.append({'reason': '仅允许原 Remi EL7 系统 PHP 7.4 包；不覆盖 SCL、CentOS 自带或其他来源：' + package['name']})
            continue
        item = available.get((package['name'], package['arch']))
        if not item:
            blockers.append({'reason': '构建产物缺少已安装包：' + package['name']})
            continue
        version = item['version'] + '-' + item['release']
        comparison = native_compare(version, package['version'], 'yum')
        if comparison < 0:
            blockers.append({'reason': '拒绝降级已安装包：' + package['name']})
        elif comparison == 0:
            metadata = bi_metadata(package=package['name'] + '.' + package['arch'])
            if metadata['header_sha1'] != item['header_sha1']:
                blockers.append({'reason': '同版本包内容与本次构建不一致：' + package['name']})
        else:
            updates.append(dict(item, old_version=package['version'], version=version,
                                upstream=item['version'], source='php'))
    for finding in assess_inventory(inv, POLICY) + check_package_integrity(inv):
        if finding.get('kind') != 'package':
            blockers.append(finding)
    return {'updates': updates, 'blockers': blockers}


_BI_WORKER = r'''
import hashlib, subprocess

def bi_native(request):
    import yum, yum.misc, yum.constants
    updates = request['updates']
    desired = prepare(updates)
    base = yum.YumBase()
    locked, executed = False, False
    try:
        base.preconf.init_plugins = False
        base.preconf.debuglevel = 0
        base.preconf.errorlevel = 0
        if base.conf.installroot != '/': raise RuntimeError('Only the running host may be updated')
        yum_acquire_lock(base, request['lock_wait'])
        locked = bool(getattr(base, '_lockfile', None))
        if not locked: raise RuntimeError('YUM lock not acquired')
        if yum.misc.find_unfinished_transactions(yumlibpath=base.conf.persistdir):
            raise RuntimeError('Unfinished YUM transaction; no update attempted')
        verify_existing(base.rpmdb.returnPackages(), desired)
        def verify_inputs():
            for item in updates:
                h = hashlib.sha256()
                with open(item['path'], 'rb') as stream:
                    for data in iter(lambda: stream.read(1048576), b''): h.update(data)
                if h.hexdigest() != item['sha256']: raise RuntimeError('Staged RPM checksum changed')
        verify_inputs()
        # Resolve only these local RPMs against installed packages. This is an
        # in-memory repository setting; no repository file or GPG policy changes.
        base.repos.disableRepo('*')
        base.conf.skip_broken = False
        base.conf.obsoletes = True  # Match rpm --upgrade's obsolete handling.
        for item in updates:
            base.installLocal(item['path'], updateonly=True)
        code, messages = base.buildTransaction()
        if code != 2:
            raise RuntimeError('Local RPM dependency resolution failed: ' + text(messages))
        def changes():
            for member in base.tsInfo.getMembers():
                if member.output_state == yum.constants.TS_UPDATE: action = 'upgrade'
                elif member.output_state == yum.constants.TS_UPDATED: action = 'upgraded'
                else: action = 'forbidden'
                yield action, member.po
        validate_changes(changes(), desired)
        paths = [x['path'] for x in updates]
        with open(request['log'], 'ab') as log:
            code = subprocess.call(['/usr/bin/rpm', '--upgrade', '--test', '--'] + paths, stdout=log, stderr=log)
            if code: raise RuntimeError('RPM dependency/conflict test failed; see rpm-transaction.log')
            if request['execute']:
                verify_inputs()
                validate_changes(changes(), desired)
                executed = True
                code = subprocess.call(['/usr/bin/rpm', '--upgrade', '-vh', '--'] + paths, stdout=log, stderr=log)
                if code: raise RuntimeError('RPM installation failed; partial changes may have occurred')
                verify_after(desired)
        return dict(ok=True, executed=executed, changes=updates,
                    provenance='explicit_local_build_manifest_and_sha256; unsigned local RPMs')
    except NativeLockTimeout:
        raise
    except Exception as exc:
        return dict(ok=False, executed=executed, error=text(exc))
    finally:
        try:
            try: base.close()
            finally: base.closeRpmDB()
        finally:
            if locked: base.doUnlock()

request_path, response_path = sys.argv[1:3]
try:
    with open(request_path) as handle: request = json.load(handle)
    result = bi_native(request)
except NativeLockTimeout as exc:
    result = dict(ok=False, executed=False, error=text(exc), lock=exc.lock)
except Exception as exc:
    result = dict(ok=False, executed=False, error=text(exc))
with open(response_path, 'w') as handle: json.dump(result, handle)
'''


def bi_transaction(updates, folder, execute=False, lock_wait=120):
    if not updates:
        return {'ok': True, 'executed': False, 'changes': []}
    interpreter, backend = _rpm_system_backend('yum')
    if backend != 'yum':
        raise RuntimeError('Native YUM Python bindings required for this local RPM recipe')
    worker = os.path.join(folder, 'local-rpm-worker.py')
    request_path = os.path.join(folder, 'local-rpm-request.json')
    response_path = os.path.join(folder, 'local-rpm-response.json')
    with open(worker, 'wb') as handle:
        # Reuse native lock, exact EVR checks and RPM post-transaction checks.
        prelude = _RPM_WORKER.rsplit("if __name__ == '__main__': main()", 1)[0]
        handle.write((prelude + '\n' + _BI_WORKER).encode('utf-8'))
    write_json(request_path, {'updates': updates, 'execute': execute, 'lock_wait': lock_wait,
                             'log': os.path.join(folder, 'rpm-transaction.log')})
    result = run_cmd([interpreter, '-E', '-s', worker, request_path, response_path],
                     timeout=None if execute else 600 + lock_wait)
    if result['code']:
        raise RuntimeError('Local RPM worker failed; inspect rpm-transaction.log and installed packages')
    return bi_read_json(response_path)


def bi_save_receipt(artifacts):
    recipe = bi_recipe()
    bi_private_dir(os.path.dirname(BI_RECEIPT))
    rows = []
    for row in artifacts:
        try:
            meta = bi_metadata(package=row['name'] + '.' + row['arch'])
        except RuntimeError:
            continue  # A build contains more subpackages than this host uses.
        if (meta['header_sha1'] == row['header_sha1'] and meta['version'] == recipe['version'] and
                meta['release'] == recipe['release']):
            rows.append(dict((key, row[key]) for key in ('name', 'arch', 'header_sha1', 'sha256')))
    receipt = {'recipe': recipe['id'], 'source_sha256': recipe['source_sha256'],
               'packages': rows, 'accepted_at': datetime.datetime.now().isoformat(),
               'trust': 'operator_selected_local_build; not vendor-signed'}
    if recipe.get('packaging_commit'):
        receipt['packaging_commit'] = recipe['packaging_commit']
    fd, temporary = tempfile.mkstemp(prefix='.receipt-', dir=os.path.dirname(BI_RECEIPT))
    os.close(fd)
    try:
        write_json(temporary, receipt)
        os.rename(temporary, BI_RECEIPT)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    return receipt


def baota_install_main(argv):
    recipe = bi_recipe()
    parser = argparse.ArgumentParser(prog='php-cve-guard.sh ' + recipe['command'],
        description='将宝塔源码构建的本地 PHP 7.4.34 RPM 升级到 %s；保留系统路径。' % recipe['host_label'])
    parser.add_argument('mode', choices=['audit', 'plan', 'fix'])
    parser.add_argument('--build-report', help='完整构建通过的 build-*/build.json；同目录须有 build.log 和 rpmbuild/RPMS')
    parser.add_argument('--work-dir', help='自动选此目录最近一次 build-*/build.json；失败构建不会回退旧产物')
    parser.add_argument('--yes', action='store_true', help='确认使用本地未签名构建产物安装并重启 PHP 服务')
    parser.add_argument('--service', action='append', default=[], help='额外 PHP 后台 systemd 服务，可重复')
    parser.add_argument('--service-if-present', action='append', default=[],
                        help='服务存在时批准重启，明确不存在时跳过；可重复')
    parser.add_argument('--health-url', action='append', default=[])
    parser.add_argument('--health-host')
    parser.add_argument('--lock-wait', type=parse_lock_wait, default=120)
    args = parser.parse_args(argv)
    if args.build_report and args.work_dir:
        parser.error('use either --build-report or --work-dir')
    if args.mode != 'audit' and not (args.build_report or args.work_dir):
        parser.error('plan/fix requires --build-report or --work-dir')
    if sys.platform not in ('linux', 'linux2') or os.geteuid() != 0:
        say('请在 %s 上以 sudo/root 运行。未执行升级。' % recipe['host_label'])
        return 2
    os.umask(0o077)
    base = '/var/log/php-cve-guard'
    bi_private_dir(base)
    prefix = 'baota-upgrade-' if recipe['id'] == 'baota-al2-php74' else recipe['command'] + '-upgrade-'
    folder = tempfile.mkdtemp(prefix=prefix, dir=base)
    path = os.path.join(folder, 'report.json')
    report = {'tool_version': VERSION, 'mode': args.mode, 'result': 'inspecting',
              'scope': recipe['scope'], 'recipe': recipe['id'], 'deployed': False}
    lock_fd = None
    try:
        if args.mode == 'fix' and args.yes:
            lock_fd = acquire_repair_lock()
        inv = collect_inventory()
        report['inventory_before'] = inv
        if not bi_host_supported(inv) or os.uname()[4] != 'x86_64':
            report['result'] = 'unsupported_host'
            say('此源码兼容 RPM 配方仅支持 %s；其他系统未执行升级。' % recipe['host_label'])
            return 10
        if args.mode == 'audit':
            findings = bi_assess(inv, bi_receipt())
            show_summary(inv, findings, folder)
            report['findings'] = findings
            report['result'] = 'fixed_within_scope' if all(f['status'] == 'fixed' for f in findings) else 'unresolved'
            return 0 if report['result'] == 'fixed_within_scope' else 10
        selected_report = args.build_report or bi_latest_report(args.work_dir)
        report['selected_build_report'] = os.path.abspath(selected_report)
        say('使用构建记录：' + _display_value(report['selected_build_report']))
        artifacts = bi_stage(selected_report, folder)
        plan = bi_plan(inv, artifacts)
        optional_blockers = configure_optional_services(args, inv, report)
        preflight = service_preflight(inv, plan['updates'], args.service)
        preflight['blockers'].extend(optional_blockers)
        report.update(plan=plan, service_preflight=preflight)
        say('宝塔 7.4.34 源码兼容包计划：%d 项已安装 PHP 包升级。' % len(plan['updates']))
        for item in plan['updates']:
            say('  %s：%s -> %s' % (item['name'], item['old_version'], item['version']))
        if plan['blockers'] or preflight['blockers']:
            report['result'] = 'blocked_no_update'
            print_blockers(inv, plan, preflight)
            return 10
        if not plan['updates']:
            # Matching RPM headers were checked by bi_plan. Adoption of an
            # already installed local build is explicit and never restarts it.
            receipt = {'packages': artifacts}
            findings = bi_assess(inv, receipt)
            report['findings'] = findings
            if any(f['status'] != 'fixed' for f in findings):
                report['result'] = 'no_update_unresolved'
                return 10
            if args.mode == 'fix' and args.yes:
                bi_save_receipt(artifacts)
            report['result'] = 'already_installed_verified'
            say('本次构建已安装且包内容验证通过；未重复安装或重启。')
            return 0
        preview = bi_transaction(plan['updates'], folder, lock_wait=args.lock_wait)
        report['transaction_preview'] = preview
        if not preview.get('ok'):
            report['result'] = 'blocked_transaction'
            say(_display_value(preview.get('error')))
            show_package_lock(preview.get('lock'))
            return 20
        if args.mode == 'plan' or not args.yes:
            report['result'] = 'plan_ready'
            say('计划通过。fix --yes 将安装本地未签名构建的兼容 RPM；RPM 脚本可能在事务内重启 PHP。')
            return 0
        health_before = health_checks(args.health_url, args.health_host)
        report['health_before'] = health_before
        if any(not row['ok'] for row in health_before):
            report['result'] = 'blocked_health_before'
            return 10
        fresh = repair_revalidate(inv, plan['updates'], preflight['services'], POLICY)
        report['revalidate_before'] = fresh
        if not fresh['ok']:
            report['result'] = 'blocked_host_changed'
            return 10
        report['backup'] = backup_configuration(fresh['inventory'], plan['updates'], folder)
        report['result'] = 'installing'
        write_json(path, report)
        say('开始升级；RPM 自带脚本可能重启 PHP-FPM，请勿中断事务。')
        applied = bi_transaction(plan['updates'], folder, execute=True, lock_wait=args.lock_wait)
        report['transaction'] = applied
        report['deployed'] = bool(applied.get('executed'))
        if not applied.get('ok'):
            report['result'] = 'installation_failed_or_partial'
            say('安装未完成，需按事务日志核对当前包状态；未自动回滚。')
            return 20
        after_check = repair_revalidate(inv, plan['updates'], preflight['services'], POLICY, after_update=True)
        report['revalidate_after'] = after_check
        if not after_check['ok']:
            report['result'] = 'installed_followup_required'
            say('包事务已完成，但安装后检查未通过；未再次主动重启服务，见报告。')
            return 20
        report['restart'] = restart_services(preflight['services'])
        if not report['restart']['ok']:
            report['result'] = 'installed_restart_failed'
            return 20
        after = collect_inventory()
        report['inventory_after'] = after
        receipt = bi_save_receipt(artifacts)
        report['receipt_path'] = BI_RECEIPT
        findings = bi_assess(after, receipt)
        report['findings_after'] = findings
        report['residual_process_check'] = residual_process_check(inv, after, plan['updates'], preflight['services'])
        report['health_after'] = health_checks(args.health_url, args.health_host)
        success = (all(f['status'] == 'fixed' for f in findings) and
                   report['residual_process_check']['ok'] and all(x['ok'] for x in report['health_after']))
        report['result'] = 'fixed_within_scope' if success else 'installed_followup_required'
        say('本次覆盖的 PHP 包与重启检查通过。' if success else '已安装，但仍有未通过的校验；详见报告。')
        if not args.health_url:
            say('未提供业务健康检查 URL，业务功能尚未验证。')
        return 0 if success else 10
    except Exception as exc:
        report.update(result='error', error=as_text(exc))
        say('操作未完成：' + _display_value(exc))
        return 20
    finally:
        write_json(path, report)
        say('报告：' + path)
        if lock_fd is not None:
            os.close(lock_fd)


def remi_install_main(argv):
    """Select the EL7 recipe explicitly and restore the AL2 caller context."""
    global BI_ACTIVE_RECIPE, BI_RECEIPT
    previous = BI_ACTIVE_RECIPE, BI_RECEIPT
    BI_ACTIVE_RECIPE = 'baota-remi-el7-php74'
    BI_RECEIPT = '/var/lib/php-cve-guard/baota-remi-el7-php74.json'
    try:
        return baota_install_main(argv)
    finally:
        BI_ACTIVE_RECIPE, BI_RECEIPT = previous
