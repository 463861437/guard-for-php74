# -*- coding: utf-8 -*-
"""One entry point, native repository updates or a pinned native PHP 7.4 recipe."""


def oc_source_route(inv, architecture=None):
    system = inv.get('os', {})
    core = [p for p in inv.get('packages', []) if is_core_package(p)]
    if r82_inventory_supported(inv, architecture):
        return 'remi82'
    if not core or any(branch_of(p.get('upstream') or p.get('version')) != '7.4' for p in core):
        return None
    architecture = architecture or os.uname()[4]
    if architecture != 'x86_64':
        return None
    manager = inv.get('package_manager')
    if manager == 'yum' and system.get('id') == 'amzn' and system.get('version_id') == '2':
        allowed = ('7.4.33-1.amzn2', BAOTA_AL2_VERSION + '-' + BAOTA_AL2_RELEASE)
        if all(p.get('source') == 'php' and p.get('arch') in ('x86_64', 'noarch') and
               p.get('version') in allowed and
               p.get('source_rpm') == 'php-' + p['version'] + '.src.rpm' for p in core):
            return 'al2'
    if (manager == 'yum' and system.get('id') in ('centos', 'rhel') and
            system.get('version_id', '').split('.')[0] == '7'):
        allowed = ('7.4.33-15.el7.remi', RB_VERSION + '-' + RB_RELEASE)
        if all(p.get('source') == 'php' and p.get('arch') in ('x86_64', 'noarch') and
               p.get('version') in allowed and
               p.get('source_rpm') == 'php-' + p['version'] + '.src.rpm' for p in core):
            return 'remi'
    if manager == 'apt' and system.get('id') == 'ubuntu' and system.get('version_id') == '20.04':
        if all(p.get('source') == 'php7.4' and p.get('arch') in ('amd64', 'all') and
               (p.get('version') == DB_VERSION or
                re.match(r'^1:7\.4\.33-[0-9]+\+ubuntu20\.04\.1\+deb\.sury\.org\+[0-9]+$', p.get('version', '')))
               for p in core):
            return 'ubuntu20'
    return None


def oc_assess(inv, source_route):
    global BI_ACTIVE_RECIPE, BI_RECEIPT
    if source_route == 'ubuntu20':
        return di_assess(inv, di_receipt())
    if source_route == 'remi82':
        return r82_assess(inv, r82_receipt())
    if source_route in ('al2', 'remi'):
        previous = BI_ACTIVE_RECIPE, BI_RECEIPT
        BI_ACTIVE_RECIPE = 'baota-al2-php74' if source_route == 'al2' else RB_RECIPE
        BI_RECEIPT = '/var/lib/php-cve-guard/' + BI_ACTIVE_RECIPE + '.json'
        try:
            return bi_assess(inv, bi_receipt())
        finally:
            BI_ACTIVE_RECIPE, BI_RECEIPT = previous
    return assess_inventory(inv, POLICY) + check_package_integrity(inv)


def oc_builder_account(requested=None, create=False):
    import pwd
    candidates = [requested] if requested else [os.environ.get('SUDO_USER'), 'ec2-user', 'ubuntu', 'phpguard-build']
    for name in candidates:
        if not name or name == 'root':
            continue
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            continue
        if entry.pw_uid and entry.pw_shell not in ('/bin/false', '/sbin/nologin', '/usr/sbin/nologin'):
            return entry
    if requested:
        raise RuntimeError('指定构建用户不存在或不可用：' + requested)
    if not create:
        return None
    # A dedicated locked-password system account is created only after --yes.
    # Never reuse a pre-existing directory/account with different properties.
    name, home = 'phpguard-build', '/var/lib/php-cve-guard-build'
    try:
        pwd.getpwnam(name)
        raise RuntimeError('已有 phpguard-build 账户不可用；请指定 --build-user。')
    except KeyError:
        pass
    if os.path.lexists(home):
        raise RuntimeError('构建账户目录已存在但账户缺失；请指定 --build-user。')
    parent = os.lstat('/var/lib')
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid or parent.st_mode & 0o022:
        raise RuntimeError('Unsafe build account parent directory')
    command = _inv_tool('useradd', [])
    if not command:
        raise RuntimeError('缺少系统 useradd；请指定已有 --build-user。')
    result = run_cmd([command, '--system', '--create-home', '--home-dir', home,
                      '--shell', '/bin/bash', name], timeout=60)
    if result['code']:
        raise RuntimeError('创建普通构建账户失败：' + result['stderr'])
    entry = pwd.getpwnam(name)
    if not entry.pw_uid or entry.pw_dir != home or entry.pw_shell != '/bin/bash':
        raise RuntimeError('新构建账户核验失败')
    return entry


def oc_install_args(args, work_dir):
    values = ['fix', '--yes', '--work-dir', work_dir, '--lock-wait', str(args.lock_wait)]
    for service in args.service:
        values += ['--service', service]
    for url in args.health_url:
        values += ['--health-url', url]
    if args.health_host:
        values += ['--health-host', args.health_host]
    return values


def oc_fixed_health(args, report):
    # A verified receipt avoids repeat installation, but an explicitly requested
    # health check must still run before reporting a successful rerun.
    report['health_before'] = health_checks(args.health_url, args.health_host)
    if any(not row['ok'] for row in report['health_before']):
        report['result'] = 'blocked_health_before'
        say('包内容已核实，但指定业务健康检查未通过。')
        return 10
    report['result'] = 'already_fixed_within_scope'
    return 0


def oc_scheduler_preflight(inv, preflight, requested):
    """Defer only scheduler descendants whose identities were verified now."""
    maintenance = sm_plan(inv, requested)
    approved = set((p['pid'], p['start_ticks']) for p in maintenance.get('covered_processes', [])
                   if p.get('start_ticks') is not None) if maintenance.get('ok') else set()
    result = dict(preflight, blockers=[], pending_scheduler_drain=[])
    for item in preflight.get('blockers', []):
        reason, service = item.get('reason', ''), item.get('service')
        scheduler_job = ((not service and 'no mapped systemd service' in reason) or
                         (service in requested and 'is not covered; explicitly select its service' in reason))
        if scheduler_job and (item.get('pid'), item.get('start_ticks')) in approved:
            result['pending_scheduler_drain'].append(item)
        else:
            result['blockers'].append(item)
    result['blockers'].extend(maintenance.get('blockers', []))
    return result, maintenance


def oc_maintenance_run(args, report, path, action):
    """Pause explicitly selected scheduling only around deployment, not builds."""
    requested = getattr(args, 'pause_scheduler', [])
    if not requested:
        return action()
    state, handlers, interrupted = None, {}, []
    code = 20
    maintenance_path = os.path.join(os.path.dirname(path), 'maintenance.json')
    report['maintenance_report'] = maintenance_path

    def note_signal(signum, unused):
        # No I/O in a signal handler: a closed terminal must not interrupt
        # communicate() and leave a native package worker running unattended.
        interrupted.append(signum)

    try:
        # run_cmd starts native workers in their own process groups. Defer the
        # parent's INT/TERM/HUP until an in-flight package operation has returned.
        for name in ('SIGINT', 'SIGTERM', 'SIGHUP'):
            signum = getattr(signal, name)
            handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, note_signal)
        fresh = collect_inventory(args.scan_root)
        maintenance = sm_plan(fresh, requested)
        report['maintenance_preflight'] = maintenance
        if not maintenance.get('ok'):
            report['result'] = 'blocked_scheduler_maintenance'
            print_blockers(fresh, {'blockers': []}, {'blockers': maintenance.get('blockers', [])})
            code = 10
        else:
            say('补丁已准备；开始维护调度器：' + ', '.join(requested) + '。等待在途任务自然结束，不强杀任务。')
            state = sm_enter(maintenance, args.scan_root, getattr(args, 'drain_wait', 300), maintenance_path)
            report['maintenance_enter'] = state
            if not state.get('ok'):
                report['result'] = 'scheduler_drain_failed_no_deployment'
                say('调度维护或任务等待未通过，本次未开始安装补丁；详见 ' + maintenance_path)
                code = 10
            elif interrupted:
                report['result'] = 'maintenance_interrupted_before_deployment'
                code = 128 + interrupted[0]
            else:
                current = collect_inventory(args.scan_root)
                before = report['inventory_before']
                def rows(inv):
                    return sorted((p.get('name', ''), p.get('arch', ''), p.get('version', ''), p.get('source', ''))
                                  for p in inv.get('packages', []))
                updates = (report.get('repository_plan') or {}).get('updates', [])
                if report.get('selected_route') != 'repository':
                    updates = [dict(p, old_version=p['version']) for p in before.get('packages', []) if is_core_package(p)]
                check = service_preflight(current, updates, args.service)
                errors = list(check.get('blockers', []))
                if rows(current) != rows(before):
                    errors.append({'reason': 'PHP package state changed before maintenance deployment; rerun plan'})
                if set(check.get('services', [])) != set(report['service_preflight'].get('services', [])):
                    errors.append({'reason': 'PHP service scope changed before maintenance deployment; rerun plan'})
                report['maintenance_deploy_preflight'] = dict(check, blockers=errors)
                if errors:
                    report['result'] = 'blocked_after_scheduler_drain'
                    print_blockers(current, {'blockers': []}, {'blockers': errors})
                    code = 10
                else:
                    report['stage'] = 'maintenance_deployment'
                    write_json(path, report)
                    if interrupted:
                        report['result'] = 'maintenance_interrupted_before_deployment'
                        code = 128 + interrupted[0]
                    else:
                        code = action()
                        report['deployment_exit_code'] = code
                        report['deployment_result'] = report.get('result')
                    if interrupted and report.get('deployment_result'):
                        report['result'] = 'maintenance_interrupted_after_operation'
                        code = 128 + interrupted[0]
    except Exception as exc:
        report['deployment_result'] = report.get('result')
        report.update(result='maintenance_error', maintenance_error=as_text(exc))
        say('维护流程未完成：' + _display_value(exc))
        code = 20
    finally:
        try:
            if state is not None:
                restored = sm_exit(state)
                report['maintenance_restore'] = restored
                if not restored.get('ok'):
                    report.setdefault('deployment_result', report.get('result'))
                    report['result'] = 'maintenance_restore_failed'
                    say('调度器恢复未通过，请按维护报告中的恢复命令处理：' + maintenance_path)
                    code = 20
                else:
                    say('调度器已恢复到本次维护前的运行状态。')
        except Exception as exc:
            report.setdefault('deployment_result', report.get('result'))
            report.update(result='maintenance_restore_failed', maintenance_restore_error=as_text(exc))
            say('调度器恢复发生错误，请查看 ' + maintenance_path)
            code = 20
        finally:
            if interrupted and code == 0:
                report.setdefault('deployment_result', report.get('result'))
                report['result'] = 'maintenance_interrupted_after_operation'
                code = 128 + interrupted[0]
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
            report['maintenance_exit_code'] = code
            report['exit_code'] = code
            write_json(path, report)
    return code


def oc_source_apply(route, args, report, path):
    requested_repos = getattr(args, 'build_repo', [])
    if requested_repos and route not in ('remi', 'remi82'):
        raise RuntimeError('--build-repo 仅适用于 Remi EL7 本地构建路线')
    entry = oc_builder_account(args.build_user, create=True)
    work_name = 'php82-remi-el7' if route == 'remi82' else 'php74-patch-' + route + '-1.5.0'
    work_dir = os.path.abspath(args.work_dir or os.path.join(entry.pw_dir, work_name))
    if not re.match(r'^/[A-Za-z0-9_./-]+$', work_dir):
        raise RuntimeError('构建路径只允许 ASCII 字母、数字和 /_.-。')
    if route == 'remi82':
        for layout in r82_layouts(report['inventory_before']):
            r82_test_path_preflight(os.path.join(work_dir, layout))
    report.update(build_user=entry.pw_name, work_dir=work_dir, stage='setup_build_test')
    write_json(path, report)
    values = ['all', '--yes', '--build-user', entry.pw_name, '--work-dir', work_dir,
              '--jobs', str(args.jobs), '--lock-wait', str(args.lock_wait)]
    values += ['--build-timeout', str(getattr(args, 'build_timeout', BM_TIMEOUT_SECONDS)),
               '--progress-interval', str(getattr(args, 'progress_interval', BM_INTERVAL_SECONDS))]
    for repo in requested_repos:
        values += ['--build-repo', repo]
    if route == 'remi82':
        for layout in r82_layouts(report['inventory_before']):
            values += ['--layout', layout]
    say('将自动准备构建环境、编译并测试；构建通过后继续安装和服务复查。')
    if route == 'al2':
        code = baota_al2_build_main(values)
    else:
        code = native_build_main(route, values)
    if code:
        report.update(result='build_incomplete_no_php_deployment', exit_code=code)
        return code
    build_reports = list(NB_LAST_BUILD_REPORTS) if route == 'remi82' else []
    if route == 'remi82' and len(build_reports) != len(r82_layouts(report['inventory_before'])):
        raise RuntimeError('每套 PHP 8.2 安装布局都必须有本次成功构建报告；未开始安装。')
    if build_reports:
        report['build_reports'] = build_reports
    def deploy():
        report['stage'] = 'install_and_verify'
        write_json(path, report)
        install = {'al2': baota_install_main, 'remi': remi_install_main, 'remi82': remi82_install_main,
                   'ubuntu20': deb_install_main}[route]
        install_args = oc_install_args(args, work_dir)
        if route == 'remi82':
            index = install_args.index('--work-dir')
            del install_args[index:index + 2]
            for build_report in build_reports:
                install_args += ['--build-report', build_report]
        code = install(install_args)
        if code:
            report.update(result='installation_or_verification_incomplete', exit_code=code)
            return code
        # Native installers rescan their default paths. Preserve any extra roots
        # requested at this entry point after a potentially long source build.
        after = collect_inventory(args.scan_root)
        remaining = oc_assess(after, route)
        before = report['inventory_before']
        updated = [dict(p, old_version=p['version']) for p in before.get('packages', []) if is_core_package(p)]
        residual = residual_process_check(before, after, updated, report['service_preflight']['services'])
        report.update(inventory_after=after, findings_after=remaining, residual_process_check=residual)
        success = bool(remaining) and all(f['status'] == 'fixed' for f in remaining) and residual['ok']
        report.update(result='fixed_within_scope' if success else 'unresolved_after_update', exit_code=0 if success else 10)
        if not success:
            say('安装后原扫描范围仍有未通过的检查，不能认定修复完成。')
        return report['exit_code']
    return oc_maintenance_run(args, report, path, deploy)


def php74_patch_main(argv):
    global RPM_LOCK_WAIT_SECONDS
    parser = argparse.ArgumentParser(prog='php74-patch.sh',
        description='PHP 一键补丁：PHP7.4 已适配路线及 Remi EL7 PHP8.2 原生构建；仅针对 CVE-2026-109618/109619。')
    parser.add_argument('mode', nargs='?', choices=['audit', 'plan', 'fix'], default='fix')
    parser.add_argument('--yes', action='store_true', help='执行依赖安装、必要的本地构建、PHP 升级与相关服务重启')
    parser.add_argument('--build-repo', action='append', choices=['remi'], default=[],
                        help='仅 Remi EL7 构建依赖：临时使用已配置且签名校验开启的 remi 主仓库')
    parser.add_argument('--build-user', help='可选普通构建用户；自动选择 sudo 用户/ec2-user/ubuntu，无可用用户时创建专用账户')
    parser.add_argument('--work-dir', help='可选源码构建目录')
    parser.add_argument('--jobs', type=int, default=2, help='源码编译并发数，1–32，默认2')
    parser.add_argument('--lock-wait', type=parse_lock_wait, default=300)
    parser.add_argument('--service', action='append', default=[], help='明确批准重启的额外 PHP 后台 systemd 服务')
    parser.add_argument('--service-if-present', action='append', default=[],
                        help='可重复；本机存在时批准重启，明确不存在时跳过；异常状态及未知状态仍阻止部署')
    parser.add_argument('--pause-scheduler', action='append', default=[], choices=['cron.service', 'crond.service'],
                        help='明确允许在部署阶段暂停整个 cron 调度器并随后恢复；需要严格进程/单元预检')
    parser.add_argument('--drain-wait', type=parse_lock_wait, default=300,
                        help='等待已发现的 cron 在途任务自然结束的秒数，0–3600，默认300；超时不杀任务')
    parser.add_argument('--health-url', action='append', default=[], help='修复前后必须返回200/204的业务健康检查地址')
    parser.add_argument('--health-host')
    parser.add_argument('--scan-root', action='append', default=[])
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--support', action='store_true', help='输出本版本支持的系统、包来源和修复路线；不联网、不修改系统')
    bm_add_arguments(parser)
    args = parser.parse_args(argv)
    bm_configure(args)
    if args.support:
        say(json.dumps(platform_support(), ensure_ascii=False, indent=2))
        return 0
    if not 1 <= args.jobs <= 32:
        parser.error('--jobs must be between 1 and 32')
    if sys.platform not in ('linux', 'linux2') or os.geteuid() != 0:
        say('请在目标 Linux 服务器使用 sudo/root 运行。')
        return 2
    RPM_LOCK_WAIT_SECONDS = args.lock_wait
    os.umask(0o077)
    folder = be_report_directory()
    path = os.path.join(folder, 'oneclick.json')
    report = dict(tool_version=VERSION, cves=CVES, mode=args.mode, stage='inventory', result='inspecting',
                  scope='PHP 7.4 supported native packages and Remi EL7 PHP 8.2 pinned native builds; not all PHP vulnerabilities')
    outer_lock = repair_lock = None
    try:
        if args.mode == 'fix' and args.yes:
            import fcntl
            # Separate orchestration lock: installers acquire the common repair
            # lock themselves, without recursive lock deadlocks.
            lock_path = '/var/log/php-cve-guard/php74-patch.lock'
            outer_lock = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            fcntl.flock(outer_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        say('正在检测 Linux 发行版、PHP 包版本、来源和运行服务……')
        inv = collect_inventory(args.scan_root)
        report['inventory_before'] = inv
        core = [p for p in inv.get('packages', []) if is_core_package(p)]
        route = oc_source_route(inv)
        target_branch = '8.2' if route == 'remi82' else '7.4'
        target = [p for p in core if branch_of(p.get('upstream') or p.get('version')) == target_branch]
        report['target_branch'] = target_branch if target else None
        if not target:
            report['result'] = 'no_managed_php74'
            versions = sorted(set(p.get('upstream') or p.get('version') or 'unknown' for p in core))
            report['detected_core_versions'] = versions
            say('未发现适配的 PHP 7.4 或 Remi EL7 PHP 8.2 包；未执行升级，不能视为已修复。')
            if versions:
                say('检测到 PHP 版本：' + _display_value(', '.join(versions)))
            return 10
        if len(core) != len(target):
            report['result'] = 'mixed_php_branches'
            say('当前同时安装其他 PHP 分支；统一入口不自动扩大升级或重启范围，请分别处理。')
            return 10
        report['source_recipe'] = route
        findings = oc_assess(inv, route)
        # Receipt-verified local builds can be audited offline and are idempotent.
        if findings and all(f['status'] == 'fixed' for f in findings):
            report.update(findings=findings)
            say('PHP 包内容与已有修复记录一致，未重复构建或安装。')
            return oc_fixed_health(args, report)
        capabilities = manager_capabilities(inv)
        report['capabilities'] = capabilities
        if not capabilities['automatic_fix']:
            report.update(result='unsupported_package_manager', blockers=capabilities['blockers'])
            say('当前包管理器仅支持检测，尚无自动安装适配；未执行升级。')
            return 10
        candidates = fetch_candidates(inv, POLICY, refresh=args.mode != 'audit', lock_wait=args.lock_wait)
        enrich_origin(inv, candidates)
        findings = oc_assess(inv, route)
        report['findings'] = findings
        show_summary(inv, findings, folder)
        if findings and all(f['status'] == 'fixed' for f in findings):
            return oc_fixed_health(args, report)
        if args.mode == 'audit':
            report['result'] = 'unresolved'
            return 10
        plan = build_plan(inv, findings, candidates, POLICY)
        report['repository_plan'] = plan
        gaps = [f for f in findings if f.get('kind') != 'package']
        if gaps:
            report.update(result='blocked_inventory', blockers=gaps)
            print_blockers(inv, {'updates': [], 'blockers': gaps}, {'blockers': []})
            return 10
        if plan['blockers'] and not route:
            report.update(result='no_verified_route', blockers=plan['blockers'])
            print_blockers(inv, plan, {'blockers': []})
            if inv.get('os', {}).get('id') == 'ubuntu' and inv['os'].get('version_id') == '20.04':
                say('Ubuntu 20.04 官方 PHP 7.4.3 需要已授权的 Ubuntu Pro/ESM 修复源；不会自动替换成 PPA 打包规则。')
            say('没有与本系统、架构及包来源匹配的已核实补丁配方；未强制覆盖或跨发行版安装。')
            return 10
        route = route if plan['blockers'] else 'repository'
        report['selected_route'] = route
        report['requested_build_repositories'] = args.build_repo
        if args.build_repo and route not in ('remi', 'remi82'):
            report['result'] = 'unsupported_build_repository_override'
            say('--build-repo 仅适用于 Remi EL7 本地源码构建；当前路线不适用，未修改系统。')
            return 10
        # Check lifecycle and configuration before installing any build tools.
        updates = plan['updates'] if route == 'repository' else [dict(p, old_version=p['version']) for p in target]
        optional_blockers = configure_optional_services(args, inv, report)
        preflight = service_preflight(inv, updates, args.service)
        preflight['blockers'].extend(optional_blockers)
        if args.pause_scheduler:
            preflight, maintenance = oc_scheduler_preflight(inv, preflight, args.pause_scheduler)
            report['maintenance_plan'] = maintenance
            say('已指定调度维护：' + ', '.join(args.pause_scheduler) + '；构建期间保持调度，部署时暂停并恢复。')
        report['service_preflight'] = preflight
        if preflight['blockers']:
            report['result'] = 'blocked_services'
            print_blockers(inv, {'updates': [], 'blockers': []}, preflight)
            return 10
        report['health_before'] = health_checks(args.health_url, args.health_host)
        if any(not h['ok'] for h in report['health_before']):
            report['result'] = 'blocked_health_before'
            say('业务健康检查未通过；未修改依赖或 PHP 包。')
            return 10
        say('自动选择修复路径：' + {'al2':'AL2 原生 RPM 本地构建', 'remi':'CentOS/RHEL 7 Remi 原生 RPM 本地构建',
                                  'remi82':'CentOS/RHEL 7 Remi PHP 8.2 原生 RPM 本地构建（保留系统/SCL布局）',
                                  'ubuntu20':'Ubuntu 20.04 PPA 原生 DEB 本地构建', 'repository':'当前可信仓库的同分支修复包'}[route])
        if args.mode == 'plan' or not args.yes:
            if route == 'repository':
                preview = package_transaction(inv, plan['updates'], POLICY, lock_wait=args.lock_wait)
                report['transaction_preview'] = preview
                if not preview.get('ok'):
                    report['result'] = 'blocked_transaction'
                    say(_display_value(preview.get('error')))
                    return 20
            report['result'] = 'route_plan_ready'
            say('路径与服务预检完成。使用 --yes 会继续解析构建依赖并执行完整修复；此结果尚未编译或安装补丁。')
            return 0
        if route != 'repository':
            return oc_source_apply(route, args, report, path)
        repair_lock = acquire_repair_lock()
        def deploy_repository():
            report['stage'] = 'repository_install_and_verify'
            report['repair'] = execute_repair(inv, plan, preflight, POLICY, folder, args.health_url,
                                              args.health_host, args.scan_root, args.lock_wait)
            if not report['repair']['ok']:
                report['result'] = 'installation_or_verification_incomplete'
                return 20
            after = collect_inventory(args.scan_root)
            # RPM provenance binds installed file metadata to a signed artifact.
            # A proof made before installation cannot certify the new RPMDB state.
            if any((p.get('vendor_provenance') or {}).get('kind') == 'remi-rpm' for p in plan['updates']):
                post_candidates = fetch_candidates(after, POLICY, refresh=False, lock_wait=args.lock_wait)
            else:
                post_candidates = candidates
            enrich_origin(after, post_candidates)
            remaining = oc_assess(after, None)
            residual = residual_process_check(inv, after, plan['updates'], preflight['services'])
            report.update(inventory_after=after, findings_after=remaining, residual_process_check=residual)
            success = bool(remaining) and all(f['status'] == 'fixed' for f in remaining) and residual['ok']
            report['result'] = 'fixed_within_scope' if success else 'unresolved_after_update'
            say('PHP 补丁安装与复查通过。' if success else '安装后仍有未通过的检查，不能认定修复完成。')
            return 0 if success else 10
        return oc_maintenance_run(args, report, path, deploy_repository)

    except PackageManagerLockTimeout as exc:
        report.update(result='package_manager_busy_no_update', error=as_text(exc),
                      package_manager_lock=exc.lock)
        say('包管理器仍被其他任务占用，本次未安装 PHP 补丁。')
        show_package_lock(exc.lock)
        return 20
    except Exception as exc:
        report.update(result='error', error=as_text(exc))
        say('一键修复未完成：' + _display_value(exc))
        return 20
    finally:
        report['business_health_requested'] = bool(args.health_url)
        report['business_health_tested'] = bool(report.get('health_before'))
        write_json(path, report)
        say('本次报告：' + path)
        for lock in (repair_lock, outer_lock):
            if lock is not None:
                os.close(lock)
