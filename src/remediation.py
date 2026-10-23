# -*- coding: utf-8 -*-
"""Produce reviewable next steps from evidence; never execute report text."""

def remediation_plan(inv, plan, preflight):
    result = {'schema_version': 1, 'route': 'review_required', 'deployed': False,
              'steps': [], 'lifecycle': [], 'repository_candidates_ready': False}
    missing = [b for b in plan.get('blockers', [])
               if b.get('reason') == 'no complete trusted fixed build in same branch']
    system = inv.get('os', {})
    al2 = system.get('id') == 'amzn' and system.get('version_id') == '2'
    core = [p for p in inv.get('packages', []) if is_core_package(p)]
    exact74 = bool(core) and all(p.get('source') == 'php' and
        p.get('version') == '7.4.33-1.amzn2' and p.get('arch') == 'x86_64' for p in core)
    if (al2 and exact74 and missing and
            all(b.get('source') == 'php' and b.get('branch') == '7.4' for b in missing)):
        result['route'] = 'al2_php74_source_build_required'
        result['steps'] = [
            {'action': 'inspect_build_host', 'where': 'dedicated_al2_x86_64_build_host',
             'argv': ['bash', './php-cve-guard.sh', 'build-al2-php74', 'doctor'],
             'description': '只读检查构建环境；使用下一步 setup 命令自动补齐工具与依赖。'},
            {'action': 'setup_build_environment', 'where': 'dedicated_al2_x86_64_build_host',
             'argv': ['sudo', 'bash', './php-cve-guard.sh', 'build-al2-php74', 'setup', '--yes'],
             'description': '自动安装编译工具与固定源码包所需依赖，再以普通用户准备源码并检查。可用 --build-user 指定已有普通用户；默认工作目录在该用户家目录。'},
            {'action': 'prepare_check_build', 'where': 'dedicated_al2_x86_64_build_host',
             'description': '执行 setup 成功后输出的 auto 命令：以普通用户复用已校验输入，构建并测试 RPM。'},
            {'action': 'validate_publish_deploy', 'where': 'staging_then_maintenance_window',
             'description': '构建通过后验证扩展与业务，签名发布，并安排所有 PHP 后台任务停止/重启。构建成功不等于已部署。'}]
    elif missing:
        result['route'] = 'vendor_backport_or_migration_required'
        result['steps'] = [{'action': 'obtain_verified_build',
                            'description': '缺少完整可信的同分支补丁包；此主机不符合内置 AL2 PHP 7.4 构建配方，需要适配原发行版构建或安排版本迁移。'}]
    elif plan.get('blockers'):
        result['steps'] = [{'action': 'resolve_coverage',
                            'description': '先处理未覆盖的运行时、容器、完整性或版本信息，详见 blockers。'}]
    elif preflight.get('blockers'):
        result['route'] = 'lifecycle_review_required'
        result['steps'] = [{'action': 'resolve_lifecycle',
                            'description': '补丁候选已就绪，先明确后台 PHP 进程的停止/重启方式，再重新运行 plan。'}]
    elif plan.get('updates'):
        result['route'] = 'repository_candidates_ready'
        result['repository_candidates_ready'] = True
        result['steps'] = [{'action': 'apply_repository_plan',
                            'description': '候选与服务前检通过，仍需包事务预检。维护窗口执行 fix --yes，并保留本次 --service、--scan-root 和业务健康检查参数；安装前会重新扫描。'}]
    else:
        result['route'] = 'no_package_update_planned'
        result['steps'] = [{'action': 'review_audit',
                            'description': '没有包更新计划；结合 findings 与覆盖范围判断，不能据此认定所有漏洞已修复。'}]
    groups = {}
    for blocker in preflight.get('blockers', []):
        origin = (blocker.get('lifecycle') or {}).get('origin', 'unknown')
        key = (blocker.get('service') or '', origin)
        entry = groups.setdefault(key, {'service': key[0] or None, 'origin': origin,
                                        'pids': [], 'parents': []})
        if isinstance(blocker.get('pid'), int) and blocker['pid'] > 0:
            entry['pids'].append(blocker['pid'])
        if blocker.get('parent_comm'):
            entry['parents'].append(blocker['parent_comm'])
    for key in sorted(groups):
        item = groups[key]
        item['pids'] = sorted(set(item['pids']))
        item['parents'] = sorted(set(item['parents']))
        result['lifecycle'].append(item)
    return result


def save_remediation(folder, inv, plan, preflight):
    result = remediation_plan(inv, plan, preflight)
    write_json(os.path.join(folder, 'remediation.json'), result)
    lines = ['修复路径：' + result['route'], '命令仅供审核，尚未执行；在工具目录运行。']
    for step in result['steps']:
        lines.append(step['description'])
        if step.get('argv'):
            # All command tokens above are fixed literals, never report data.
            lines.append('  ' + ' '.join(step['argv']))
    with open(os.path.join(folder, 'next-steps.txt'), 'wb') as handle:
        handle.write(('\n'.join(lines) + '\n').encode('utf-8'))
    return result
