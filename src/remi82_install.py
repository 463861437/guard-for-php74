# -*- coding: utf-8 -*-
"""Accept only the pinned local PHP 8.2 EL7 builds, preserving both RPM layouts.

Build reports are operator-selected records, not vendor signatures. Every input,
SPEC, test log and binary RPM is copied into root-owned storage before use.
"""

R82_RECEIPT = '/var/lib/php-cve-guard/upstream-remi-el7-php82.json'
R82_BASE_VERSION = '8.2.20-1.el7.remi'


def r82_layout_source(layout):
    if layout not in ('system', 'scl'):
        raise RuntimeError('Unknown PHP 8.2 RPM layout')
    return 'php' if layout == 'system' else 'php82-php'


def r82_wrapper(package):
    version = package.get('version') or ''
    return (package.get('source') == 'php82' and
            package.get('name') in ('php82', 'php82-runtime', 'php82-syspaths') and
            version == '8.2-5.el7.remi' and
            package.get('source_rpm') == 'php82-' + version + '.src.rpm')


def r82_core_packages(inv):
    return [p for p in inv.get('packages', []) if is_core_package(p) and not r82_wrapper(p)]


def r82_layouts(inv):
    sources = set(p.get('source') for p in r82_core_packages(inv))
    return [layout for layout in ('system', 'scl') if r82_layout_source(layout) in sources]


def r82_package_supported(package):
    source = package.get('source')
    if source not in ('php', 'php82-php'):
        return False
    name = package.get('name') or ''
    version = package.get('version') or ''
    return (re.match(r'^' + re.escape(source) + r'(?:-[a-z0-9-]+)?\Z', name) is not None and
            package.get('arch') in ('x86_64', 'noarch') and
            version in (R82_BASE_VERSION, R82_VERSION + '-' + R82_RELEASE) and
            package.get('source_rpm') == source + '-' + version + '.src.rpm')


def r82_inventory_supported(inv, architecture=None):
    system = inv.get('os') or {}
    core = r82_core_packages(inv)
    return (inv.get('package_manager') == 'yum' and
            system.get('id') in ('centos', 'rhel') and
            re.match(r'^7(?:\.|$)', system.get('version_id') or '') is not None and
            (architecture or os.uname()[4]) == 'x86_64' and bool(core) and
            all(r82_package_supported(p) for p in core))


def r82_copy_input(source, destination, maximum, expected=None):
    """Copy bounded immutable regular bytes, then hash the private copy."""
    info = os.lstat(source)
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise RuntimeError('Local build input must be a bounded regular file')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                value.st_mtime, value.st_ctime)
    with os.fdopen(fd, 'rb') as src:
        if identity(info) != identity(os.fstat(src.fileno())):
            raise RuntimeError('Local build input changed before copying')
        with open(destination, 'wb') as dst:
            remaining = info.st_size
            while remaining:
                data = src.read(min(1048576, remaining))
                if not data:
                    raise RuntimeError('Local build input changed during copying')
                dst.write(data)
                remaining -= len(data)
            if src.read(1) or identity(info) != identity(os.fstat(src.fileno())):
                raise RuntimeError('Local build input changed during copying')
        if identity(info) != identity(os.lstat(source)):
            raise RuntimeError('Local build input was replaced during copying')
    if expected:
        bp_verify(destination, expected)
    return destination


def r82_artifact_source(row):
    return r82_layout_source(row['layout'])


def r82_validate_build(report):
    layout = report.get('layout')
    source = r82_layout_source(layout)
    if (report.get('recipe') != R82_RECIPE or report.get('state') != 'built_not_deployed' or
            report.get('stage') != 'complete' or report.get('target_version') != R82_VERSION or
            report.get('target_release') != R82_RELEASE or
            report.get('packaging_commit') != r82_profile(layout)['commit'] or
            report.get('source_sha256') != R82_SOURCE_SHA or
            report.get('inputs') != r82_input_hashes(layout) or
            report.get('source_signature_verified') is not True or
            report.get('source_signature_fingerprint') != R82_SIGNATURE_FINGERPRINT or
            report.get('signed') is not False or report.get('tests_required') is not True or
            report.get('php_selftests_passed') is not True):
        raise RuntimeError('需要固定 PHP 8.2 官方源码与 Remi EL7 配方完整构建通过的 build.json。')
    host = report.get('host') or {}
    if not r82_host_supported(host) or host.get('uid') in (None, 0):
        raise RuntimeError('构建报告必须来自 EL7 x86_64 普通构建用户。')
    summary = report.get('php_selftest_summary') or {}
    if (not summary.get('total') or not summary.get('passed') or
            any(summary.get(key, -1) != 0 for key in ('failed', 'borked', 'leaked'))):
        raise RuntimeError('Successful complete PHP source tests are required')
    smoke = report.get('mitigation_smoke_tests') or []
    if (len(smoke) != len(r82_profile(layout)['smoke_sapis']) or
            set(row.get('sapi') for row in smoke) != set(r82_profile(layout)['smoke_sapis']) or
            any(row.get('version') != R82_VERSION or row.get('version_id') != 80235 or
                row.get('int_size') != 8 or row.get('zts') != (1 if row.get('sapi') == 'build-ztscli' else 0)
                for row in smoke)):
        raise RuntimeError('Both built PHP CLI mitigation tests must pass')
    security_summary = report.get('security_test_summary') or {}
    if (not security_summary.get('total') or not security_summary.get('passed') or
            any(security_summary.get(key, -1) != 0 for key in ('failed', 'borked', 'leaked'))):
        raise RuntimeError('Required security regression tests did not pass')
    rows = report.get('artifacts')
    if not isinstance(rows, list) or not rows or len(rows) > 64:
        raise RuntimeError('Invalid PHP 8.2 artifact list')
    seen = set()
    for row in rows:
        name, arch = row.get('name', ''), row.get('arch', '')
        if (re.match(r'^' + re.escape(source) + r'(?:-[a-z0-9-]+)?\Z', name) is None or
                arch not in ('x86_64', 'noarch') or row.get('version') != R82_VERSION or
                row.get('release') != R82_RELEASE or
                row.get('file') != '%s-%s-%s.%s.rpm' % (name, R82_VERSION, R82_RELEASE, arch) or
                re.match(r'^[a-f0-9]{64}\Z', row.get('sha256', '')) is None or (name, arch) in seen):
            raise RuntimeError('Unexpected or duplicate PHP 8.2 artifact identity')
        seen.add((name, arch))
    required = set(r82_profile(layout)['core_names'])
    if not required.issubset(set(name for name, arch in seen)):
        raise RuntimeError('Missing core PHP 8.2 RPM artifacts for ' + layout)
    return rows


def r82_stage(report_paths, folder):
    if not report_paths or len(report_paths) > 2:
        raise RuntimeError('Provide one completed build report per installed PHP 8.2 layout')
    stage = os.path.join(folder, 'accepted-builds')
    os.mkdir(stage, 0o700)
    artifacts, layouts = [], set()
    for report_path in report_paths:
        report_path = os.path.abspath(report_path)
        # The caller selects the report; all paths below are derived by us.
        report = bi_read_json(report_path)
        rows = r82_validate_build(report)
        layout = report['layout']
        if layout in layouts:
            raise RuntimeError('Duplicate PHP 8.2 layout reports')
        layouts.add(layout)
        accepted = os.path.join(stage, layout)
        os.mkdir(accepted, 0o700)
        build_dir = os.path.dirname(report_path)
        inputs = os.path.join(accepted, 'inputs')
        os.mkdir(inputs, 0o700)
        for name, digest in sorted(r82_input_hashes(layout).items()):
            if os.path.basename(name) != name:
                raise RuntimeError('Invalid fixed recipe filename')
            r82_copy_input(os.path.join(build_dir, 'rpmbuild', 'SOURCES', name), os.path.join(inputs, name),
                           128 * 1024 * 1024, digest)
        signature = r82_verify_source_signature(inputs, accepted)
        if signature.get('verified') is not True or signature.get('fingerprint') != R82_SIGNATURE_FINGERPRINT:
            raise RuntimeError('PHP source signature was not independently verified during staging')
        with open(os.path.join(inputs, r82_profile(layout)['spec_name']), 'rb') as handle:
            expected_spec = r82_render_spec(handle.read(), layout)
        expected_spec_sha = hashlib.sha256(expected_spec).hexdigest()
        if report.get('spec_sha256') != expected_spec_sha:
            raise RuntimeError('Build SPEC differs from the pinned PHP 8.2 recipe')
        r82_copy_input(os.path.join(build_dir, 'rpmbuild', 'SPECS', 'php82-guard.spec'),
                       os.path.join(accepted, 'php82-guard.spec'), 4 * 1024 * 1024, expected_spec_sha)
        log = r82_copy_input(os.path.join(build_dir, 'build.log'), os.path.join(accepted, 'build.log'),
                             512 * 1024 * 1024)
        if r82_selftest_summary(log) != report['php_selftest_summary']:
            raise RuntimeError('PHP source test log and build summary disagree')
        security_log = r82_copy_input(os.path.join(build_dir, 'security-tests.log'),
                                      os.path.join(accepted, 'security-tests.log'), 64 * 1024 * 1024)
        if r82_selftest_summary(security_log, targeted=True) != report.get('security_test_summary'):
            raise RuntimeError('Required security regression test log and report disagree')
        rpms = os.path.join(accepted, 'rpms')
        os.mkdir(rpms, 0o700)
        for row in rows:
            local = r82_copy_input(os.path.join(build_dir, 'rpmbuild', 'RPMS', row['arch'], row['file']),
                                   os.path.join(rpms, row['file']), 1024 ** 3, row['sha256'])
            meta = bi_metadata(path=local)
            if any(meta.get(key) != row[key] for key in ('name', 'version', 'release', 'arch')):
                raise RuntimeError('RPM header differs from accepted PHP 8.2 artifact manifest')
            source = r82_layout_source(layout)
            if meta.get('source_rpm') != '%s-%s-%s.src.rpm' % (source, R82_VERSION, R82_RELEASE):
                raise RuntimeError('PHP 8.2 RPM source/layout identity mismatch')
            artifacts.append(dict(row, layout=layout, source=source, path=local,
                                  header_sha1=meta['header_sha1']))
        write_json(os.path.join(accepted, 'build.json'), report)
    return artifacts


def r82_plan(inv, artifacts):
    blockers, updates = [], []
    if not r82_inventory_supported(inv):
        return {'updates': [], 'blockers': [{'reason':
            '仅支持 EL7 x86_64 的 Remi PHP 8.2.20-1.el7.remi 系统/SCL 原生包及本工具已安装构建；不同来源、分支或布局不覆盖。'}]}
    available = {}
    for row in artifacts:
        key = (row['name'], row['arch'])
        if key in available:
            blockers.append({'reason': '重复的 PHP RPM 产物：' + row['name']})
        available[key] = row
    for package in r82_core_packages(inv):
        item = available.get((package['name'], package['arch']))
        if not item or item.get('source') != package.get('source'):
            blockers.append({'reason': '构建产物缺少已安装核心包及其布局：' + package['name']})
            continue
        version = item['version'] + '-' + item['release']
        comparison = native_compare(version, package['version'], 'yum')
        if comparison < 0:
            blockers.append({'reason': '拒绝降级：' + package['name']})
        elif comparison == 0:
            if bi_metadata(package=package['name'] + '.' + package['arch'])['header_sha1'] != item['header_sha1']:
                blockers.append({'reason': '同版本已安装包与本次构建内容不同：' + package['name']})
        else:
            updates.append(dict(item, old_version=package['version'], version=version,
                                upstream=item['version']))
    for finding in assess_inventory(inv, POLICY) + check_package_integrity(inv):
        if finding.get('kind') != 'package':
            blockers.append(finding)
    return {'updates': updates, 'blockers': blockers,
            'layouts': r82_layouts(inv), 'installs_new_sapis': False,
            'third_party_extensions': 'retained; native RPM dependency test must accept unchanged ABI requirements'}


def r82_transaction(updates, folder, execute=False, lock_wait=120):
    # The existing native worker disables repositories for this transaction,
    # validates every old/new source+EVR, forbids installs/removals/downgrades,
    # then runs rpm --upgrade --test before changing installed packages.
    return bi_transaction(updates, folder, execute=execute, lock_wait=lock_wait)


def r82_receipt_evidence(artifacts):
    layouts = sorted(set(row['layout'] for row in artifacts))
    return {'recipe': R82_RECIPE, 'source_sha256': R82_SOURCE_SHA,
            'packaging_commits': dict((layout, r82_profile(layout)['commit']) for layout in layouts),
            'inputs': dict((layout, r82_input_hashes(layout)) for layout in layouts),
            'packages': artifacts}


def r82_receipt_valid(receipt):
    if receipt.get('recipe') != R82_RECIPE or receipt.get('source_sha256') != R82_SOURCE_SHA:
        return False
    try:
        layouts = sorted(set(row['layout'] for row in receipt.get('packages', [])))
        return (bool(layouts) and all(layout in ('system', 'scl') for layout in layouts) and
                receipt.get('packaging_commits') == dict((layout, r82_profile(layout)['commit']) for layout in layouts) and
                receipt.get('inputs') == dict((layout, r82_input_hashes(layout)) for layout in layouts))
    except (KeyError, TypeError):
        return False


def r82_receipt():
    try:
        bi_private_dir(os.path.dirname(R82_RECEIPT))
        info = os.lstat(R82_RECEIPT)
        if info.st_uid != 0 or info.st_mode & 0o022:
            return {}
        receipt = bi_read_json(R82_RECEIPT)
        return receipt if r82_receipt_valid(receipt) else {}
    except (IOError, OSError, ValueError, RuntimeError):
        return {}


def r82_assess(inv, receipt):
    findings = assess_inventory(inv, POLICY) + check_package_integrity(inv)
    accepted = set()
    for row in receipt.get('packages', []) if r82_receipt_valid(receipt) else []:
        name, arch = row.get('name', ''), row.get('arch', '')
        if re.match(r'^(?:php|php82-php)(?:-[a-z0-9-]+)?\Z', name) is None or arch not in ('x86_64', 'noarch'):
            continue
        try:
            meta = bi_metadata(package=name + '.' + arch)
            if (meta['version'] == R82_VERSION and meta['release'] == R82_RELEASE and
                    meta['header_sha1'] == row.get('header_sha1') and
                    meta['source_rpm'] == r82_layout_source(row.get('layout')) + '-' +
                    R82_VERSION + '-' + R82_RELEASE + '.src.rpm'):
                if bi_payload_ok(name + '.' + arch):
                    accepted.add((name, arch))
                else:
                    findings.append({'kind': 'binary_integrity', 'package_name': name, 'status': 'unknown',
                                     'reason': 'PHP 8.2 RPM non-config payload changed or could not be verified'})
        except (KeyError, RuntimeError):
            pass
    for finding in findings:
        matching = [p for p in inv.get('packages', []) if p.get('name') == finding.get('package_name')]
        if finding.get('kind') != 'package' or not matching:
            continue
        local = any(p.get('version') == R82_VERSION + '-' + R82_RELEASE for p in matching)
        if local:
            if all((p['name'], p.get('arch')) in accepted and r82_package_supported(p) and
                   p.get('version') == R82_VERSION + '-' + R82_RELEASE for p in matching):
                finding.update(status='fixed', reason='Matches accepted local PHP 8.2 source build, RPM header and payload; not vendor-signed')
            else:
                finding.update(status='unknown', reason='Local PHP 8.2 version requires a matching accepted build receipt and unchanged RPM payload')
    return findings


def r82_save_receipt(artifacts):
    bi_private_dir(os.path.dirname(R82_RECEIPT))
    rows = []
    for row in artifacts:
        try:
            meta = bi_metadata(package=row['name'] + '.' + row['arch'])
        except RuntimeError:
            continue  # Extra built SAPIs are never installed merely to adopt them.
        if (meta.get('version') == R82_VERSION and meta.get('release') == R82_RELEASE and
                meta.get('header_sha1') == row['header_sha1'] and
                meta.get('source_rpm') == r82_artifact_source(row) + '-' + R82_VERSION + '-' + R82_RELEASE + '.src.rpm' and
                bi_payload_ok(row['name'] + '.' + row['arch'])):
            rows.append(dict((key, row[key]) for key in ('name', 'arch', 'layout', 'header_sha1', 'sha256')))
    receipt = r82_receipt_evidence(rows)
    receipt.update(accepted_at=datetime.datetime.now().isoformat(),
                   trust='operator_selected_local_build; binary RPMs are not vendor-signed')
    fd, temporary = tempfile.mkstemp(prefix='.php82-receipt-', dir=os.path.dirname(R82_RECEIPT))
    os.close(fd)
    try:
        write_json(temporary, receipt)
        os.rename(temporary, R82_RECEIPT)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return receipt


def r82_extension_headers(inv):
    """Record all untouched PHP extensions/wrappers before the local transaction."""
    core = set((p['name'], p['arch']) for p in r82_core_packages(inv))
    rows = []
    for package in inv.get('packages', []):
        if (package['name'], package['arch']) not in core:
            meta = bi_metadata(package=package['name'] + '.' + package['arch'])
            rows.append(dict((key, meta[key]) for key in ('name', 'arch', 'version', 'release', 'header_sha1', 'source_rpm')))
    return sorted(rows, key=lambda row: (row['name'], row['arch']))


def remi82_install_main(argv):
    parser = argparse.ArgumentParser(prog='php-cve-guard.sh remi-el7-php82',
        description='验证并安装官方 PHP 8.2.35 源码构建的 Remi EL7 本地 RPM，保留系统及 SCL 布局。')
    parser.add_argument('mode', choices=['audit', 'plan', 'fix'])
    parser.add_argument('--build-report', action='append', default=[], help='每个布局完整通过的 build.json，可重复')
    parser.add_argument('--yes', action='store_true', help='允许安装已验证本地未签名 RPM 并重启已批准的 PHP 服务')
    parser.add_argument('--service', action='append', default=[])
    parser.add_argument('--service-if-present', action='append', default=[])
    parser.add_argument('--health-url', action='append', default=[])
    parser.add_argument('--health-host')
    parser.add_argument('--lock-wait', type=parse_lock_wait, default=120)
    args = parser.parse_args(argv)
    if args.mode != 'audit' and not args.build_report:
        parser.error('plan/fix requires one --build-report per installed layout')
    if sys.platform not in ('linux', 'linux2') or os.geteuid() != 0:
        say('请在 CentOS/RHEL 7 x86_64 上以 root/sudo 运行；尚未安装。')
        return 2
    os.umask(0o077)
    base = '/var/log/php-cve-guard'
    bi_private_dir(base)
    folder = tempfile.mkdtemp(prefix='remi-el7-php82-upgrade-', dir=base)
    path = os.path.join(folder, 'report.json')
    report = {'tool_version': VERSION, 'mode': args.mode, 'recipe': R82_RECIPE,
              'result': 'inspecting', 'deployed': False}
    lock_fd = None
    try:
        if args.mode == 'fix' and args.yes:
            lock_fd = acquire_repair_lock()
        inv = collect_inventory()
        report['inventory_before'] = inv
        if not r82_inventory_supported(inv):
            report['result'] = 'unsupported_host'
            say('此配方仅支持 EL7 x86_64 的指定 Remi PHP 8.2 系统/SCL 包；未执行安装。')
            return 10
        if args.mode == 'audit':
            findings = r82_assess(inv, r82_receipt())
            show_summary(inv, findings, folder)
            report['findings'] = findings
            success = bool(findings) and all(f['status'] == 'fixed' for f in findings)
            report['result'] = 'fixed_within_scope' if success else 'unresolved'
            return 0 if success else 10
        artifacts = r82_stage(args.build_report, folder)
        report['selected_build_reports'] = [os.path.abspath(p) for p in args.build_report]
        plan = r82_plan(inv, artifacts)
        optional_blockers = configure_optional_services(args, inv, report)
        preflight = service_preflight(inv, plan['updates'], args.service)
        preflight['blockers'].extend(optional_blockers)
        report.update(plan=plan, service_preflight=preflight)
        say('PHP 8.2 原生包计划：%d 项已安装核心包升级；保留现有系统/SCL 布局及第三方扩展。' % len(plan['updates']))
        for item in plan['updates']:
            say('  %s：%s -> %s' % (item['name'], item['old_version'], item['version']))
        if plan['blockers'] or preflight['blockers']:
            report['result'] = 'blocked_no_update'
            print_blockers(inv, plan, preflight)
            return 10
        if not plan['updates']:
            findings = r82_assess(inv, r82_receipt_evidence(artifacts))
            report['findings'] = findings
            if not findings or any(f['status'] != 'fixed' for f in findings):
                report['result'] = 'no_update_unresolved'
                return 10
            if args.mode == 'fix' and args.yes:
                r82_save_receipt(artifacts)
            report['result'] = 'already_installed_verified'
            say('已安装包与本次完整构建及内容校验一致；无需重复安装或重启。')
            return 0
        report['retained_package_headers'] = r82_extension_headers(inv)
        preview = r82_transaction(plan['updates'], folder, lock_wait=args.lock_wait)
        report['transaction_preview'] = preview
        if not preview.get('ok'):
            report['result'] = 'blocked_transaction'
            say(_display_value(preview.get('error')))
            show_package_lock(preview.get('lock'))
            return 20
        if args.mode == 'plan' or not args.yes:
            report['result'] = 'plan_ready'
            say('原生依赖及 ABI 事务预演通过；fix --yes 将安装本地未签名 RPM 并重启已批准服务。')
            return 0
        report['health_before'] = health_checks(args.health_url, args.health_host)
        if any(not row['ok'] for row in report['health_before']):
            report['result'] = 'blocked_health_before'
            return 10
        fresh = repair_revalidate(inv, plan['updates'], preflight['services'], POLICY)
        report['revalidate_before'] = fresh
        if not fresh['ok'] or r82_extension_headers(fresh['inventory']) != report['retained_package_headers']:
            report['result'] = 'blocked_host_changed'
            return 10
        report['backup'] = backup_configuration(fresh['inventory'], plan['updates'], folder)
        report['result'] = 'installing'
        write_json(path, report)
        say('开始安装已验证的本地 PHP 8.2 RPM；请勿中断包事务。')
        applied = r82_transaction(plan['updates'], folder, execute=True, lock_wait=args.lock_wait)
        report['transaction'] = applied
        report['deployed'] = bool(applied.get('executed'))
        if not applied.get('ok'):
            report['result'] = 'installation_failed_or_partial'
            say('包事务未完成，需核对日志及当前包状态；未自动回滚。')
            return 20
        after_check = repair_revalidate(inv, plan['updates'], preflight['services'], POLICY, after_update=True)
        report['revalidate_after'] = after_check
        report['retained_packages_unchanged'] = (r82_extension_headers(after_check['inventory']) == report['retained_package_headers'])
        if not after_check['ok'] or not report['retained_packages_unchanged']:
            report['result'] = 'installed_followup_required'
            say('已安装，但安装后库存/配置或扩展校验未通过；详见报告。')
            return 20
        report['restart'] = restart_services(preflight['services'])
        if not report['restart']['ok']:
            report['result'] = 'installed_restart_failed'
            return 20
        after = collect_inventory()
        report['inventory_after'] = after
        receipt = r82_save_receipt(artifacts)
        report['receipt_path'] = R82_RECEIPT
        findings = r82_assess(after, receipt)
        report['findings_after'] = findings
        report['residual_process_check'] = residual_process_check(inv, after, plan['updates'], preflight['services'])
        report['health_after'] = health_checks(args.health_url, args.health_host)
        success = (bool(findings) and all(f['status'] == 'fixed' for f in findings) and
                   report['residual_process_check']['ok'] and
                   r82_extension_headers(after) == report['retained_package_headers'] and
                   all(row['ok'] for row in report['health_after']))
        report['result'] = 'fixed_within_scope' if success else 'installed_followup_required'
        say('本次覆盖的 PHP 8.2 包、服务及残留进程检查通过。' if success else '已安装，但仍有后续检查未通过；详见报告。')
        if not args.health_url:
            say('未提供业务健康检查 URL，业务功能尚未验证。')
        return 0 if success else 10
    except Exception as exc:
        report.update(result='error', error=as_text(exc))
        say('PHP 8.2 原生包操作未完成：' + _display_value(exc))
        return 20
    finally:
        write_json(path, report)
        say('报告：' + path)
        if lock_fd is not None:
            os.close(lock_fd)
