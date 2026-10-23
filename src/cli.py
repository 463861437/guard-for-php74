# -*- coding: utf-8 -*-

def say(message):
    message = as_text(message)
    try:
        print(message, flush=True)
    except TypeError:  # Python 2.7
        sys.stdout.write(message.encode('utf-8') + b'\n')
        sys.stdout.flush()

def health_checks(urls, host=None):
    results = []
    for url in urls:
        if not re.match(r'^https?://[^\s]+$', url) or re.match(r'^https?://[^/]*@', url):
            results.append({'url': url, 'ok': False, 'error': 'invalid URL or embedded credentials'})
            continue
        args = ['/usr/bin/curl', '--noproxy', '*', '--max-time', '15', '--silent',
                '--output', '/dev/null', '--write-out', '%{http_code}']
        if host:
            args += ['--header', 'Host: ' + host]
        r = run_cmd(args + [url], timeout=20)
        results.append({'url': url, 'ok': r['code'] == 0 and r['stdout'] in ('200', '204'),
                        'status': r['stdout'], 'exit_code': r['code']})
    return results

def package_transaction(inv, updates, policy, execute=False, lock_wait=120):
    capabilities = manager_capabilities(inv)
    if not capabilities['automatic_fix']:
        return {'ok': False, 'changes': [], 'executed': False,
                'error': '; '.join(item['reason'] for item in capabilities['blockers'])}
    if inv['package_manager'] == 'apt':
        return apt_transaction(updates, execute=execute, codename=ubuntu_codename(inv, policy),
                               lock_wait=lock_wait)
    return rpm_transaction(updates, execute=execute)

def repair_revalidate(inv, updates, services, policy, scan_roots=None, after_update=False):
    """Refresh processes/configuration without enlarging the approved restart set."""
    fresh = collect_inventory(scan_roots or [])
    errors = []
    def package_rows(packages):
        return sorted((p.get('name', ''), p.get('arch', ''), p.get('version', ''),
                       p.get('source', '')) for p in packages)
    expected = [dict(p) for p in inv.get('packages', [])]
    if after_update:
        targets = dict(((p['name'], p['arch']), p) for p in updates)
        for p in expected:
            update = targets.get((p.get('name'), p.get('arch')))
            if update:
                p['version'] = update['version']
    if package_rows(expected) != package_rows(fresh.get('packages', [])):
        errors.append({'kind': 'package_state_changed', 'reason':
                       'PHP package inventory differs from the expected transaction state; rerun plan'})
    # Deleted executables belonging to selected services are expected after an
    # upgrade, and are resolved by the explicit restart. Other gaps still block.
    restartable = set(p['pid'] for p in fresh.get('processes', [])
                      if p.get('service') in services and not p.get('container'))
    for finding in assess_inventory(fresh, policy) + check_package_integrity(fresh):
        if finding.get('kind') == 'package':
            continue
        if (after_update and finding.get('kind') == 'stale_process' and
                finding.get('pid') in restartable):
            continue
        errors.append(finding)
    check = service_preflight(fresh, updates, services)
    errors.extend(check.get('blockers', []))
    if set(check.get('services', [])) != set(services):
        errors.append({'kind': 'service_scope_changed', 'reason':
                       'Active PHP service set changed; rerun plan to review the new restart scope'})
    return {'ok': not errors, 'inventory': fresh, 'preflight': check, 'errors': errors}


def execute_repair(inv, plan, preflight, policy, folder, health_urls=None, health_host=None,
                   scan_roots=None, lock_wait=120):
    """No mutation until all requested package and service preflights pass."""
    if plan.get('blockers') or preflight.get('blockers'):
        return {'ok': False, 'stage': 'preflight', 'error': 'unresolved blockers; no update attempted'}
    updates = plan['updates']
    health_before = health_checks(health_urls or [], health_host)
    if any(not x['ok'] for x in health_before):
        return {'ok': False, 'stage': 'health_before', 'health': health_before}
    if not updates:
        return {'ok': True, 'stage': 'no_updates', 'restarted': [], 'health': health_before}
    transaction = package_transaction(inv, updates, policy, execute=False, lock_wait=lock_wait)
    if not transaction.get('ok'):
        return {'ok': False, 'stage': 'transaction_preview', 'transaction': transaction}
    write_json(os.path.join(folder, 'transaction.json'), transaction)
    before = repair_revalidate(inv, updates, preflight['services'], policy, scan_roots)
    write_json(os.path.join(folder, 'revalidate-before.json'), before)
    if not before['ok']:
        return {'ok': False, 'stage': 'revalidate_before', 'revalidation': before,
                'error': 'Host changed or new PHP processes appeared; no package update attempted'}
    backup = backup_configuration(before['inventory'], updates, folder)
    say('配置备份完成；开始安装已核验的同分支修复包。包事务期间请勿中断。')
    applied = package_transaction(inv, updates, policy, execute=True, lock_wait=lock_wait)
    if not applied.get('ok'):
        return {'ok': False, 'stage': 'package_update', 'backup': backup,
                'transaction': applied, 'error': 'package manager failed; inspect its logs and current package state'}
    # Re-test configuration against the new executables before any explicit restart.
    check_again = repair_revalidate(inv, updates, preflight['services'], policy,
                                    scan_roots, after_update=True)
    write_json(os.path.join(folder, 'revalidate-after.json'), check_again)
    if not check_again['ok']:
        return {'ok': False, 'stage': 'config_after', 'backup': backup,
                'revalidation': check_again,
                'error': 'Packages changed; new coverage or lifecycle blockers require attention before explicit restart'}
    say('安装完成，正在重启相关服务并检查进程。')
    restarted = restart_services(preflight['services'])
    if not restarted.get('ok'):
        return {'ok': False, 'stage': 'restart', 'backup': backup, 'restart': restarted}
    health_after = health_checks(health_urls or [], health_host)
    return {'ok': all(x['ok'] for x in health_after), 'stage': 'verification',
            'backup': backup, 'restart': restarted, 'health': health_after}

def fetch_candidates(inv, policy, refresh=False, lock_wait=120):
    capabilities = manager_capabilities(inv)
    if not capabilities['automatic_fix']:
        raise RuntimeError('; '.join(item['reason'] for item in capabilities['blockers']))
    if inv['package_manager'] == 'apt':
        if refresh:
            say('正在刷新 APT 元数据……')
            r = run_cmd(['/usr/bin/apt-get', '-o', 'Acquire::AllowInsecureRepositories=false',
                         '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false', 'update'], timeout=600)
            if r['code'] or re.search(r'Failed to fetch|Some index files failed', r['stderr'] + r['stdout']):
                raise RuntimeError('APT metadata refresh failed; repository configuration was not changed')
        return apt_candidates(inv, policy)
    if inv['package_manager'] in ('yum', 'dnf'):
        return rpm_candidates(inv)
    raise RuntimeError('supported native package manager not found')

def check_package_integrity(inv):
    findings = []
    # Verify only PHP executable content, not deliberately customized configs.
    for rt in inv.get('runtimes', []):
        if not rt.get('package'):
            continue
        path = rt['realpath']
        if inv['package_manager'] == 'apt':
            owner = rt['package']
            candidates = ['/var/lib/dpkg/info/' + owner + '.md5sums']
            if ':' not in owner:
                candidates += glob.glob('/var/lib/dpkg/info/' + owner + ':*.md5sums')
            expected = None
            for file_path in candidates:
                try:
                    with open(file_path) as handle:
                        for line in handle:
                            fields = line.split(None, 1)
                            if len(fields) == 2 and '/' + fields[1].strip().lstrip('/') == path:
                                expected = fields[0]
                except IOError:
                    pass
            try:
                digest = hashlib.md5()
                with open(path, 'rb') as handle:
                    for data in iter(lambda: handle.read(1024 * 1024), b''):
                        digest.update(data)
                good = expected and digest.hexdigest() == expected
            except IOError:
                good = False
        else:
            r = run_cmd(['/usr/bin/rpm', '-Vf', path], timeout=60)
            good = r['code'] in (0, 1) and not any(line.rstrip().endswith(' ' + path) for line in r['stdout'].splitlines())
            if r['code'] == 1 and not r['stdout'].strip():
                good = False
        if not good:
            findings.append({'kind': 'binary_integrity', 'path': path, 'status': 'unknown',
                             'reason': 'executable checksum could not be confirmed against local package database'})
    return findings

def show_summary(inv, findings, folder):
    say('系统：%s；包管理器：%s' % (inv['os'].get('pretty_name'), inv.get('package_manager')))
    labels = {'fixed': '已达到修复判据', 'affected': '受影响/回补未确认', 'unknown': '待人工确认'}
    for finding in findings:
        name = finding.get('package_name') or finding.get('path') or finding.get('container') or finding.get('kind')
        say('  [%s] %s %s' % (labels[finding['status']], name, finding.get('version', '')))
    say('详细报告：' + folder)

def _display_value(value):
    # Reports are data; remove terminal control sequences, never execute text.
    return re.sub(r'[\x00-\x1f\x7f]', ' ', as_text(value or ''))

def show_package_lock(lock):
    if not isinstance(lock, dict):
        return
    say('YUM 锁等待超时（最多 %s 秒）；占锁 PID：%s，锁文件：%s。' % (
        _display_value(as_text(lock.get('wait_seconds', '?'))), _display_value(lock.get('pid')),
        _display_value(lock.get('path'))))
    pid = as_text(lock.get('pid', ''))
    if pid.isdigit() and int(pid) > 0:
        say('可只读查看：ps -p %s -o pid,ppid,comm,etime,stat' % pid)
    say('等待现有包管理任务结束后重试；不要直接删除其锁文件或强制终止正在安装的进程。')

def parse_lock_wait(value):
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError('--lock-wait requires an integer between 0 and 3600')
    if seconds < 0 or seconds > 3600:
        raise argparse.ArgumentTypeError('--lock-wait must be between 0 and 3600')
    return seconds

def print_blockers(inv, plan, preflight):
    package_blockers = plan.get('blockers') or []
    service_blockers = preflight.get('blockers') or []
    for item in package_blockers:
        target = item.get('source') or item.get('path') or item.get('kind') or 'unknown'
        branch = item.get('branch') or ''
        reason = item.get('reason') or 'reason missing'
        if reason == 'no complete trusted fixed build in same branch':
            say('  [包阻止] %s PHP %s：当前候选中没有完整且已核实修复的同分支构建。' % (_display_value(target), _display_value(branch)))
            say('    涉及：' + ', '.join(_display_value(p) for p in item.get('packages', [])))
            for candidate in (item.get('candidate_diagnostics') or [])[:5]:
                versions = ', '.join(_display_value(v) for v in candidate.get('available_versions', []))
                if candidate.get('available_versions_omitted'):
                    versions += '（已截断，另有 %s 个不同版本未显示）' % _display_value(candidate['available_versions_omitted'])
                say('    %s：候选 %s，同分支 %s，修复已验证 %s，可选 %s；候选版本样例：%s' % (
                    _display_value(candidate.get('package')), candidate.get('total', '?'),
                    candidate.get('same_branch', '?'), candidate.get('verified_fixed', '?'),
                    candidate.get('accepted', '?'), versions))
            if len(item.get('candidate_diagnostics') or []) > 5:
                say('    其余包的候选统计见 report.json。')
        else:
            say('  [覆盖阻止] %s %s：%s' % (_display_value(target), _display_value(branch), _display_value(reason)))
            if item.get('packages'):
                say('    涉及：' + ', '.join(_display_value(p) for p in item['packages']))
    # Group equal service issues and retain every PID in the detailed report.
    groups = {}
    for item in service_blockers:
        service = item.get('service') or '(未映射 systemd 服务)'
        reason = item.get('reason') or 'reason missing'
        normalized = re.sub(r'PID \d+', 'PID *', reason)
        groups.setdefault((service, normalized), []).append(item)
    for (service, normalized), items in sorted(groups.items()):
        say('  [服务阻止] %s：%s%s' % (_display_value(service), _display_value(items[0].get('reason', 'reason missing')),
            ('；同类 %d 项' % len(items)) if len(items) > 1 else ''))
        origins = {}
        for item in items:
            origin = (item.get('lifecycle') or {}).get('origin', 'unknown')
            origins[origin] = origins.get(origin, 0) + 1
        known = {'cron': 'cron 定时任务', 'supervisor': 'Supervisor',
                 'terminal': '终端会话', 'systemd': 'systemd', 'unknown': '来源待确认'}
        if any(item.get('lifecycle') for item in items):
            say('    祖先进程线索：' + '；'.join('%s %d 项' % (known.get(origin, '来源待确认'), count)
                                                    for origin, count in sorted(origins.items())))
            for item in items[:3]:
                if isinstance(item.get('pid'), int) and item['pid'] > 0:
                    say('    PID %s，父 PID %s（%s）；只读查看：ps -p %s -o pid,ppid,comm,etime,stat' % (
                        item['pid'], _display_value(item.get('ppid')), _display_value(item.get('parent_comm')), item['pid']))
        if 'explicitly select its service with --service' in normalized:
            if service in ('cron.service', 'crond.service'):
                say('    一键入口 php74-patch.sh 可显式使用 --pause-scheduler %s --drain-wait 300；暂停整个调度器并等待已发现任务结束，需通过维护预检。' % service)
            elif 'supervisor' in service:
                say('    --service %s 会重启整个 Supervisor 单元及受其管理的任务；确认任务范围后再指定，不能只为消除提示而添加。' % _display_value(service))
            else:
                say('    补丁就绪后，还需安排该后台任务的重启；可显式指定 --service %s。' % _display_value(service))
        elif 'no mapped systemd service' in normalized:
            say('    需确认这些进程由 cron、终端还是其他管理器启动；在维护窗口安排停止、更新和重新启动。')
            if 'cron' in origins:
                say('    已观察到 cron 祖先进程；维护时需暂停对应 PHP 调度并等待在途任务结束，不能只等待当前 PID 消失。')
                say('    一键入口 php74-patch.sh 新增 --pause-scheduler crond.service --drain-wait 300（Ubuntu/Debian 通常为 cron.service）；将暂停整个指定调度器，仍需核实任务归属。')
        elif any(message in normalized for message in (
                'Systemd service does not exist', 'Service is not a loaded systemd unit',
                'Service is not active', 'Systemd property enumeration is incomplete',
                'Cannot read systemd service properties')):
            if 'Systemd service does not exist' in normalized:
                say('    该服务在当前机器上不存在；核对是否沿用了其他服务器的 --service 参数。确认名称和业务范围后，删除多余参数或改为本机实际服务名，再运行 plan。')
                say('    跨机器共用命令可用 --service-if-present 指定可选服务：仅明确不存在时跳过；实际 PHP 进程仍须完整覆盖。')
            elif 'Service is not active' in normalized:
                say('    该服务当前未处于 active 状态；先核对其业务用途和状态，脚本不会自动启动或忽略该服务。')
            else:
                say('    尚无法核实该服务；先检查是否已加载、名称是否正确及 systemd 状态，不能仅为通过预检而删除服务参数。')
            # Reports can be supplied externally. Emit a pasteable command
            # only for validated unit names, without including environment.
            try:
                unit = _svc_name(service)
            except ValueError:
                unit = None
            if unit:
                say('    只读查看：systemctl show %s --no-pager -p LoadState -p ActiveState -p FragmentPath' % unit)
    system = inv.get('os') or {}
    has_al2_74 = (system.get('id') == 'amzn' and system.get('version_id') == '2' and
                 any(x.get('branch') == '7.4' and x.get('source') == 'php' for x in package_blockers))
    if has_al2_74:
        say('  [Amazon Linux 2 / PHP 7.4] 重复 fix --yes 不能生成仓库中缺失的补丁包。')
        say('    保留 PHP 7.4 的路线：按官方回补源码制作并测试兼容的 RPM，或迁移至有该补丁的受支持 PHP 7.4 运行时。')
        say('    在专用 AL2 x86_64 构建机先运行 build-al2-php74 doctor；auto 会串联源码准备、依赖检查和编译测试。')
        say('    官方源码：https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619')
        say('    当前未完成修复；关闭上传进度仅为部分缓解，也不能把新建 RPM 的版本号当作补丁证明。')
    if not package_blockers and not service_blockers:
        say('报告中没有记录 blockers；请结合记录的结果和执行阶段判断。')

def explain_report(path):
    try:
        if not path:
            raise ValueError('explain requires --report')
        with open(path, 'rb') as handle:
            raw = handle.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError('report exceeds 16 MiB')
        report = json.loads(raw.decode('utf-8'))
        if not isinstance(report, dict):
            raise ValueError('report must be an object')
        sections = {}
        for key in ('inventory_before', 'plan', 'service_preflight', 'repair'):
            value = report.get(key, {})
            if not isinstance(value, dict):
                raise ValueError('invalid report section: ' + key)
            sections[key] = value
        for key in ('plan', 'service_preflight'):
            values = sections[key].get('blockers', [])
            if not isinstance(values, list) or any(not isinstance(x, dict) for x in values):
                raise ValueError('blockers must be a list of objects')
        say('读取历史报告：' + _display_value(path))
        say('记录的结果：' + _display_value(report.get('result', 'unknown')))
        show_package_lock(report.get('package_manager_lock'))
        preview = report.get('transaction_preview')
        if isinstance(preview, dict):
            show_package_lock(preview.get('lock'))
        print_blockers(sections['inventory_before'], sections['plan'], sections['service_preflight'])
        repair = sections['repair']
        if repair:
            say('执行阶段：%s；记录的 ok：%s' % (_display_value(repair.get('stage', 'unknown')), repair.get('ok', 'unknown')))
            for key in ('error',):
                if repair.get(key):
                    say('失败原因：' + _display_value(repair[key]))
            transaction = repair.get('transaction')
            if isinstance(transaction, dict) and transaction.get('error'):
                say('包事务原因：' + _display_value(transaction['error']))
                show_package_lock(transaction.get('lock'))
        for key in ('error', 'repository_error'):
            if report.get(key):
                say('%s：%s' % (key, _display_value(report[key])))
        say('explain 仅解释已有记录，未扫描或修改当前系统。')
        return 0
    except (IOError, OSError, ValueError, TypeError, KeyError) as exc:
        say('报告读取失败：' + _display_value(exc))
        return 2

def acquire_repair_lock():
    import fcntl
    lock_fd = os.open('/run/lock/php-cve-guard.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        os.close(lock_fd)
        raise
    return lock_fd

def main(argv=None):
    global RPM_LOCK_WAIT_SECONDS
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == 'php74-patch':
        return php74_patch_main(argv[1:])
    if argv and argv[0] == 'build-baota-remi-el7-php74':
        return native_build_main('remi', argv[1:])
    if argv and argv[0] == 'baota-remi-el7-php74':
        return remi_install_main(argv[1:])
    if argv and argv[0] == 'build-baota-ubuntu20-php74':
        return native_build_main('ubuntu20', argv[1:])
    if argv and argv[0] == 'baota-ubuntu20-php74':
        return deb_install_main(argv[1:])
    if argv and argv[0] == 'build-al2-php74':
        return backport_main(argv[1:])
    if argv and argv[0] == 'build-baota-al2-php74':
        return baota_al2_build_main(argv[1:])
    if argv and argv[0] == 'baota-al2-php74':
        return baota_install_main(argv[1:])
    parser = argparse.ArgumentParser(prog='php-cve-guard.sh', description='PHP CVE-2026-109618/109619 检测及同分支包修复；不是全漏洞扫描器。')
    parser.epilog = '一键 PHP7.4 修复：php74-patch --yes；AL2 官方回补：build-al2-php74 --help；宝塔源码 RPM：build-baota-al2-php74 --help；本地包升级：baota-al2-php74 --help'
    parser.add_argument('mode', nargs='?', choices=['audit', 'plan', 'fix', 'explain'], default='audit')
    parser.add_argument('--report', help='explain 模式读取已有 report.json，不执行主机操作')
    parser.add_argument('--yes', action='store_true', help='执行安装及服务重启；仅 fix 使用')
    parser.add_argument('--scan-root', action='append', default=[], help='额外 PHP 安装目录，可重复')
    parser.add_argument('--service', action='append', default=[], help='需同步重启的 PHP 后台服务，可重复')
    parser.add_argument('--service-if-present', action='append', default=[],
                        help='可重复；服务存在时批准重启，明确不存在时跳过；异常或未知状态仍阻止部署')
    parser.add_argument('--health-url', action='append', default=[], help='修复前后均需返回 200/204 的无副作用健康检查 URL')
    parser.add_argument('--health-host', help='健康检查使用的 HTTP Host')
    parser.add_argument('--output-dir', help='新建报告目录（必须尚不存在）')
    parser.add_argument('--lock-wait', type=parse_lock_wait, default=120,
                        help='等待 YUM/APT 包事务原生锁的最大秒数，0 表示立即返回，默认 120')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args(argv)
    RPM_LOCK_WAIT_SECONDS = args.lock_wait
    if args.mode == 'explain':
        return explain_report(args.report)
    if args.report:
        parser.error('--report only applies to explain')
    if sys.platform not in ('linux', 'linux2'):
        say('仅支持 Linux。未执行检查或修改。')
        return 2
    if os.geteuid() != 0:
        say('请使用 sudo/root 运行，以免遗漏 FPM、模块和进程。')
        return 2
    os.umask(0o077)
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    folder = os.path.abspath(args.output_dir or '/var/log/php-cve-guard/%s-%s' % (stamp, os.getpid()))
    if os.path.lexists(folder):
        say('输出目录已存在，拒绝覆盖：' + folder)
        return 2
    os.makedirs(folder, 0o700)
    report = {'tool_version': VERSION, 'policy_date': POLICY['checked_on'], 'cves': CVES,
              'mode': args.mode, 'started_at': datetime.datetime.now().isoformat(),
              'yum_lock_wait_seconds': args.lock_wait,
              'scope': 'host PHP packages, discovered binaries/processes; no exploit or compromise test'}
    report_path = os.path.join(folder, 'report.json')
    lock_fd = None
    try:
        if args.mode == 'fix' and args.yes:
            lock_fd = acquire_repair_lock()
        say('正在检查系统、所有已安装 PHP 包与运行进程……')
        inv = collect_inventory(args.scan_root)
        report['inventory_before'] = inv
        capabilities = manager_capabilities(inv)
        report['package_manager_capabilities'] = capabilities
        candidates = {}
        if capabilities['automatic_fix'] and (inv.get('package_manager') == 'apt' or args.mode in ('plan', 'fix')):
            if inv.get('package_manager') == 'yum':
                say('正在查询 YUM 仓库；若其他包管理任务占锁，最多等待 %s 秒。' % args.lock_wait)
            try:
                candidates = fetch_candidates(inv, POLICY, refresh=args.mode in ('plan', 'fix'),
                                              lock_wait=args.lock_wait)
                enrich_origin(inv, candidates)
            except RuntimeError as exc:
                report['repository_error'] = as_text(exc)
                if args.mode in ('plan', 'fix'):
                    raise
                inv['warnings'].append('Repository provenance unavailable: ' + as_text(exc))
        findings = assess_inventory(inv, POLICY) + check_package_integrity(inv)
        report.update({'inventory_before': inv, 'findings_before': findings})
        show_summary(inv, findings, folder)
        if args.mode == 'audit':
            report['result'] = 'fixed_within_scope' if all(f['status'] == 'fixed' for f in findings) else 'unresolved'
            write_json(report_path, report)
            return 0 if report['result'] == 'fixed_within_scope' else 10
        if not capabilities['automatic_fix']:
            plan = {'updates': [], 'blockers': capabilities['blockers']}
            preflight = {'services': [], 'checks': [], 'blockers': []}
            report.update({'plan': plan, 'service_preflight': preflight,
                           'result': 'blocked_no_update'})
            report['remediation'] = save_remediation(folder, inv, plan, preflight)
            say('修复尚未执行，当前系统仅完成只读审计：')
            print_blockers(inv, plan, preflight)
            write_json(report_path, report)
            return 10
        plan = build_plan(inv, findings, candidates, POLICY)
        optional_blockers = configure_optional_services(args, inv, report)
        preflight = service_preflight(inv, plan['updates'], args.service)
        preflight['blockers'].extend(optional_blockers)
        # Unknown runtimes/coverage do not justify silently proceeding with only a subset.
        for finding in findings:
            if finding['kind'] != 'package':
                plan['blockers'].append(finding)
        report.update({'plan': plan, 'service_preflight': preflight})
        report['remediation'] = save_remediation(folder, inv, plan, preflight)
        say('修复路径：%s；具体下一步见 %s' % (report['remediation']['route'],
                                                   os.path.join(folder, 'next-steps.txt')))
        for item in plan['updates']:
            say('计划：%s %s -> %s' % (item['name'], item['old_version'], item['version']))
        if plan['blockers'] or preflight['blockers']:
            report['result'] = 'blocked_no_update'
            say('修复尚未执行，具体阻止原因如下：')
            print_blockers(inv, plan, preflight)
            write_json(report_path, report)
            return 10
        if args.mode == 'plan' or not args.yes:
            if plan['updates']:
                report['transaction_preview'] = package_transaction(
                    inv, plan['updates'], POLICY, execute=False, lock_wait=args.lock_wait)
                if not report['transaction_preview'].get('ok'):
                    report['result'] = 'blocked_no_update'
                    show_package_lock(report['transaction_preview'].get('lock'))
                    write_json(report_path, report)
                    return 20
            report['result'] = 'plan_ready'
            say('计划已生成。执行修复命令需使用 fix --yes；该命令会重启相关 PHP 服务。')
            write_json(report_path, report)
            return 0
        repair = execute_repair(inv, plan, preflight, POLICY, folder, args.health_url,
                                args.health_host, args.scan_root, args.lock_wait)
        report['repair'] = repair
        if not repair['ok']:
            report['result'] = 'repair_failed'
            say('修复未完成；已停止后续操作，请检查报告和包管理器日志。')
            show_package_lock((repair.get('transaction') or {}).get('lock'))
            for item in (repair.get('revalidation') or {}).get('errors', []):
                say('  [重新检查] ' + _display_value(item.get('reason', 'state changed')))
            write_json(report_path, report)
            return 20
        after = collect_inventory(args.scan_root)
        if any((p.get('vendor_provenance') or {}).get('kind') == 'remi-rpm' for p in plan['updates']):
            candidates = fetch_candidates(after, POLICY, refresh=False, lock_wait=args.lock_wait)
        enrich_origin(after, candidates)
        remaining = assess_inventory(after, POLICY) + check_package_integrity(after)
        residual = residual_process_check(inv, after, plan['updates'], preflight['services']) if plan['updates'] else {'ok': True, 'errors': []}
        report['residual_process_check'] = residual
        for error in residual['errors']:
            remaining.append({'kind': 'stale_process', 'status': 'unknown', 'reason': error['reason'], 'pid': error.get('pid')})
        report.update({'inventory_after': after, 'findings_after': remaining})
        unresolved = any(f['status'] != 'fixed' for f in remaining)
        report['result'] = 'unresolved_after_update' if unresolved else 'fixed_within_scope'
        report['business_health_tested'] = bool(args.health_url)
        write_json(report_path, report)
        say('仍有待处理项，不能认定修复完成。' if unresolved else '本次覆盖的 PHP 组件已达到修复判据，相关服务已验证。')
        if not args.health_url:
            say('未提供业务健康检查地址；应用功能仍需验证。')
        return 10 if unresolved else 0
    except PackageManagerLockTimeout as exc:
        report.update({'result': 'package_manager_busy_no_update',
                       'error': as_text(exc), 'package_manager_lock': exc.lock})
        write_json(report_path, report)
        show_package_lock(exc.lock)
        say('本次尚未安装修复包。报告：' + report_path)
        return 20
    except Exception as exc:
        report.update({'result': 'error', 'error': as_text(exc)})
        write_json(report_path, report)
        say('操作失败：%s。报告：%s' % (as_text(exc), report_path))
        return 20
    finally:
        if lock_fd is not None:
            os.close(lock_fd)

if __name__ == '__main__':
    sys.exit(main())
