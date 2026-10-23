# -*- coding: utf-8 -*-
"""Native build setup: fixed dependencies, reviewed transactions, unprivileged builds."""

NB_UBUNTU_BUILD_DEPENDS = 'debhelper (>= 9.20160709~), dh-apache2, dpkg-dev (>= 1.16.1~), apache2-bin (>= 2.4), apache2-dev (>= 2.4), autoconf (>= 2.63), automake, bison, chrpath, default-libmysqlclient-dev | libmysqlclient-dev, firebird-dev [!hurd-any !m68k !hppa !ppc64] | firebird2.5-dev [!hurd-any !m68k !hppa !ppc64] | firebird2.1-dev [!hurd-any !m68k !hppa !ppc64], flex, freetds-dev, libacl1-dev, libapparmor-dev [linux-any], libapr1-dev (>= 1.2.7-8), libargon2-dev | libargon2-0-dev, libbz2-dev, libc-client-dev, libcurl4-openssl-dev | libcurl-dev, libdb-dev, libedit-dev (>= 2.11-20080614-4), libenchant-2-dev | libenchant-dev, libevent-dev (>= 1.4.11), libexpat1-dev (>= 1.95.2-2.1), libffi-dev, libfreetype6-dev, libgcrypt20-dev (>> 1.6.3) | libgcrypt11-dev (<< 1.5.4), libgd-dev (>= 2.1.0) | libgd2-dev, libglib2.0-dev, libgmp3-dev, libicu-dev, libjpeg-dev | libjpeg62-dev, libkrb5-dev, libldap2-dev, liblmdb-dev, libmagic-dev, libmhash-dev (>= 0.8.8), libnss-myhostname [linux-any], libonig-dev, libpam0g-dev, libpcre2-dev (>= 10.30), libpng-dev, libpq-dev, libpspell-dev, libqdbm-dev, libsasl2-dev, libsnmp-dev, libsodium-dev, libsqlite3-dev, libssl-dev, libsystemd-dev [linux-any], libtidy-dev (>= 1:5.2.0), libtool (>= 2.2), libwebp-dev, libwrap0-dev, libxml2-dev, libxmlrpc-epi-dev, libxslt1-dev (>= 1.0.18), libzip-dev (>= 1.0.0), locales-all | language-pack-de, netbase, netcat-openbsd, php-common, re2c, systemtap-sdt-dev, tzdata, unixodbc-dev, zlib1g-dev'
NB_UBUNTU_BUILD_CONFLICTS = 'bind-dev, libxmlrpc-core-c3-dev'
NB_LAST_BUILD_REPORTS = []

NB_APT_ENV_WORKER = r'''
ACTIVITY = dict(ok=False, executed=False, may_have_changed=False, changes=[])

def protected(name):
    # apache2-bin is required by apache2-dev on an empty build host. Its
    # installed daemon must never be upgraded while preparing PHP build tools;
    # verified_changes enforces that separate install-only exception.
    if name in ('php-common', 'dh-php', 'pkg-php-tools', 'apache2-bin', 'apache2-dev', 'apache2-utils'):
        return False
    return bool(re.match(r'^(?:php|libphp|lsphp|nginx|apache2|httpd|supervisor|cron|cronie|crontabs|systemd)(?:[0-9.-]|$)', name) or
                name.startswith('libapache2-mod-') or name == 'at' or
                re.match(r'^firebird[0-9.-]*(?:server|super|classic)(?:-|$)', name) or
                name in ('couchdb', 'influxdb', 'clickhouse-server') or
                re.match(r'^(?:mysql|mariadb|postgresql|redis|valkey|mongodb|memcached)(?:[0-9.-]|$)', name) and
                not name.endswith(('-dev', '-client', '-client-common')))

def snapshot(cache):
    return dict((p.fullname, p.installed.version) for p in cache if p.installed)

def options(cache, dep, installed):
    name, version, op = dep
    result = []
    if name in cache:
        p = cache[name]
        v = p.installed if installed else p.candidate
        if v and (not op or apt_pkg.check_dep(v.version, op, version)):
            result.append(p)
    # A provider's package version is not a versioned virtual Provides value.
    # The pinned recipe only uses unversioned virtual alternatives here.
    if not op:
        for p in cache.get_providing_packages(name):
            if (p.installed if installed else p.candidate) and p not in result:
                result.append(p)
    return result

def available_version(package):
    if package.marked_delete:
        return None
    return package.candidate if package.marked_install or package.marked_upgrade else package.installed

def satisfied(cache, group):
    for name, version, op in group:
        if name in cache:
            v = available_version(cache[name])
            if v and (not op or apt_pkg.check_dep(v.version, op, version)):
                return True
        if not op:
            if any(available_version(p) for p in cache.get_providing_packages(name)):
                return True
    return False

def verified_changes(cache):
    changes = []
    for p in cache.get_changes():
        v = p.candidate
        if (p.marked_delete or p.marked_downgrade or p.marked_reinstall or
                not v or protected(p.name) or
                (p.name == 'apache2-bin' and p.installed) or
                p._pkg.selected_state == apt_pkg.SELSTATE_HOLD or
                v.architecture not in ('amd64', 'all')):
            raise RuntimeError('Protected/unapproved build dependency change: ' + p.name)
        if p.installed and (not p.marked_upgrade or apt_pkg.version_compare(v.version, p.installed.version) <= 0):
            raise RuntimeError('Only installs and strict upgrades are allowed: ' + p.name)
        if not p.installed and not p.marked_install:
            raise RuntimeError('Unexpected dependency transaction action: ' + p.name)
        if not any(o.trusted and (o.archive == 'focal' or o.archive.startswith('focal-'))
                   for o in v.origins):
            raise RuntimeError('Build dependency lacks trusted focal origin: ' + p.name)
        changes.append(dict(name=p.fullname, version=v.version,
                            old_version=p.installed.version if p.installed else None,
                            action='upgrade' if p.installed else 'install', repo=origin_repo(v)))
    return sorted(changes, key=lambda x: x['name'])

def env_work(request):
    release = {}
    with open('/etc/os-release') as handle:
        for line in handle:
            if '=' in line:
                k,v=line.rstrip().split('=',1); release[k]=v.strip('"\'')
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '20.04' or os.uname()[4] != 'x86_64':
        raise RuntimeError('This native DEB build setup requires Ubuntu 20.04 amd64')
    apt_pkg.init_config()
    for key in ('APT::Get::AllowUnauthenticated', 'Acquire::AllowInsecureRepositories',
                'Acquire::AllowDowngradeToInsecureRepositories', 'APT::Install-Recommends', 'APT::Install-Suggests'):
        apt_pkg.config.set(key,'false')
    apt_pkg.config.set('Dpkg::Options::','--force-confold')
    apt_pkg.init_system()
    if apt_pkg.config.find('APT::Architecture') != 'amd64':
        raise RuntimeError('Native APT architecture must be amd64')
    groups=apt_pkg.parse_src_depends(request['build_depends'], True, 'amd64')
    conflicts=apt_pkg.parse_src_depends(request['build_conflicts'], True, 'amd64')
    if not groups:
        raise RuntimeError('No native build dependency groups')
    with _system_lock(request['lock_wait']):
        cache=apt.Cache()
        before=snapshot(cache)
        for group in conflicts:
            if any(options(cache,dep,True) for dep in group):
                raise RuntimeError('Installed Build-Conflicts; no package removed: '+str(group))
        for group in groups:
            if satisfied(cache,group):
                continue
            chosen=None
            for dep in group:
                for p in options(cache,dep,False):
                    if p._pkg.selected_state != apt_pkg.SELSTATE_HOLD and not protected(p.name):
                        chosen=p; break
                if chosen is not None: break
            if chosen is None:
                raise RuntimeError('No permitted native provider for build dependency: '+str(group))
            chosen.mark_install(auto_fix=True, auto_inst=True, from_user=False)
        if cache.broken_count or any(not satisfied(cache,g) for g in groups):
            raise RuntimeError('APT could not satisfy every versioned build dependency')
        if any(satisfied(cache,g) for g in conflicts):
            raise RuntimeError('Solver introduced a Build-Conflicts package')
        changes=verified_changes(cache)
        ACTIVITY['changes']=changes
        if request.get('expected_changes') is not None and changes != request['expected_changes']:
            raise RuntimeError('Dependency transaction changed since preview')
        if request['execute'] and changes:
            if snapshot(apt.Cache()) != before or verified_changes(cache) != changes:
                raise RuntimeError('Package state changed before installation')
            ACTIVITY['may_have_changed']=True
            os.environ['DEBIAN_FRONTEND']='noninteractive'
            os.environ['NEEDRESTART_MODE']='l'
            if not cache.commit(apt.progress.base.AcquireProgress(), apt.progress.base.InstallProgress()):
                raise RuntimeError('APT dependency installation failed; inspect installed state')
            expected=dict(before)
            for row in changes: expected[row['name']]=row['version']
            fresh=apt.Cache()
            if snapshot(fresh) != expected or any(not satisfied(fresh,g) for g in groups):
                raise RuntimeError('Installed dependency state differs from the verified plan')
            ACTIVITY.update(executed=True,may_have_changed=False)
        ACTIVITY.update(ok=True,state='environment_ready' if request['execute'] else 'environment_plan')
        return ACTIVITY

try:
    with open(sys.argv[1]) as handle: request=json.load(handle)
    answer=env_work(request)
except Exception as exc:
    answer=dict(ACTIVITY,error=str(exc),state='environment_failed' if ACTIVITY['may_have_changed'] else 'environment_blocked')
with open(sys.argv[2],'w') as handle: json.dump(answer,handle)
'''


def nb_apt_environment(execute=False, lock_wait=120, expected_changes=None):
    # These literal dependency fields are from the pinned Ondrej DSC, never
    # a root-read Build-Depends field in a user-editable source directory.
    code = APT_WORKER.split('\ntry:\n    with open(sys.argv[1])', 1)[0] + NB_APT_ENV_WORKER
    deps = NB_UBUNTU_BUILD_DEPENDS + ', build-essential, fakeroot, quilt, patch, curl, xz-utils, ca-certificates'
    try:
        return worker_call(code, dict(build_depends=deps, build_conflicts=NB_UBUNTU_BUILD_CONFLICTS,
            execute=bool(execute), lock_wait=lock_wait, expected_changes=expected_changes),
            ['apt', 'apt_pkg'], timeout=None if execute else 600 + lock_wait)
    except Exception as exc:
        return dict(ok=False, executed=False, may_have_changed=bool(execute), error=as_text(exc))


def nb_account(kind, args):
    import pwd
    host = _inv_os()
    if kind in ('remi', 'remi82'):
        valid = host.get('id') in ('centos', 'rhel') and host.get('version_id', '').split('.')[0] == '7'
    elif kind == 'ubuntu20':
        valid = host.get('id') == 'ubuntu' and host.get('version_id') == '20.04'
    else:
        valid = False
    if sys.platform not in ('linux', 'linux2') or not valid or os.uname()[4] != 'x86_64':
        raise RuntimeError('构建环境配方与当前系统或架构不匹配。')
    if os.geteuid() != 0:
        raise RuntimeError('setup/all 需要 sudo/root；源码编译随后降权运行。')
    name = args.build_user or os.environ.get('SUDO_USER')
    if not name or name == 'root':
        raise RuntimeError('请用 --build-user 指定已有普通构建账户。')
    account = pwd.getpwnam(name)
    if account.pw_uid == 0 or account.pw_shell in ('/bin/false', '/sbin/nologin', '/usr/sbin/nologin'):
        raise RuntimeError('需要可登录的非 root 构建账户。')
    folder = os.path.abspath(args.work_dir or os.path.join(account.pw_dir,
        'php82-remi-el7' if kind == 'remi82' else 'php74-baota-' + kind))
    if not re.match(r'^/[A-Za-z0-9_./-]+$', folder):
        raise RuntimeError('构建路径只允许 ASCII 字母、数字和 /_.-。')
    return dict(name=account.pw_name, uid=account.pw_uid, gid=account.pw_gid,
                home=account.pw_dir, work_dir=folder)


def nb_child(kind, account, build, jobs, layouts=None):
    launcher = os.path.abspath(os.environ.get('PHP_GUARD_LAUNCHER') or './php-cve-guard.sh')
    def work():
        result = dict(ok=False, exit_code=20)
        try:
            be_drop_privileges(account, launcher)
            if kind == 'remi82':
                reports = []
                for layout in (layouts or ['system']):
                    work_dir = os.path.join(account['work_dir'], layout)
                    steps = [['prepare', '--layout', layout, '--output-dir', work_dir],
                             ['doctor', '--layout', layout, '--work-dir', work_dir]]
                    if build:
                        steps.append(['build', '--layout', layout, '--work-dir', work_dir, '--jobs', str(jobs)])
                    for argv in steps:
                        code = remi82_build_main(argv)
                        if code:
                            return dict(ok=False, exit_code=code, stage=argv[0], layout=layout,
                                        effective_uid=os.geteuid(), build_reports=reports)
                    if build:
                        if not R82_LAST_BUILD_REPORT:
                            raise RuntimeError('PHP 8.2 builder did not return a completed build report')
                        reports.append(R82_LAST_BUILD_REPORT)
                return dict(ok=True, exit_code=0, effective_uid=os.geteuid(), build_reports=reports,
                            stage='built_not_deployed' if build else 'environment_ready_not_built')
            entry = remi_build_main if kind == 'remi' else deb_builder_main
            steps = [['prepare', '--output-dir', account['work_dir']],
                     ['doctor', '--work-dir', account['work_dir']]]
            if build:
                steps.append(['build', '--work-dir', account['work_dir'], '--jobs', str(jobs)])
            for argv in steps:
                code = entry(argv)
                if code:
                    result.update(exit_code=code, stage=argv[0])
                    break
            else:
                result.update(ok=True,exit_code=0,stage='built_not_deployed' if build else 'environment_ready_not_built')
        except Exception as exc:
            result['error'] = as_text(exc)
        result['effective_uid'] = os.geteuid()
        return result
    result = be_worker_call(work)
    if result.get('effective_uid') != account['uid']:
        result.update(ok=False,exit_code=20)
    return result


def native_build_main(kind, argv):
    global NB_LAST_BUILD_REPORTS
    NB_LAST_BUILD_REPORTS = []
    entry = remi82_build_main if kind == 'remi82' else remi_build_main if kind == 'remi' else deb_builder_main
    if not argv or argv[0] not in ('setup', 'all'):
        return entry(argv)
    parser = argparse.ArgumentParser(description='准备原生构建环境，普通用户编译；不安装生成的 PHP 包。')
    parser.add_argument('action', choices=['setup', 'all'])
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--build-user')
    parser.add_argument('--work-dir')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--lock-wait', type=parse_lock_wait, default=120)
    if kind in ('remi', 'remi82'):
        parser.add_argument('--build-repo', action='append', choices=['remi'], default=[],
                            help='临时使用已配置且开启 GPG 校验的 Remi 构建依赖仓库；不修改 repo 文件')
    if kind == 'remi82':
        parser.add_argument('--layout', action='append', choices=['system', 'scl'], default=[],
                            help='可重复；只构建所选原生安装布局，默认 system')
    bm_add_arguments(parser)
    args = parser.parse_args(argv)
    bm_configure(args)
    max_jobs = 64 if kind in ('remi', 'remi82') else 32
    if not 1 <= args.jobs <= max_jobs:
        parser.error('--jobs must be between 1 and %s' % max_jobs)
    folder = None
    report = dict(tool_version=VERSION, profile=kind, action=args.action, deployed=False, state='planning')
    try:
        account = nb_account(kind, args)
        folder = be_report_directory()
        report.update(build_user=account['name'], work_dir=account['work_dir'],
                      requested_build_repositories=getattr(args, 'build_repo', []))
        if kind in ('remi', 'remi82'):
            layouts = sorted(set(getattr(args, 'layout', []) or ['system']))
            requirements = sorted(set((r82_build_requirements(layouts) if kind == 'remi82' else RB_BUILD_REQUIRES) + BE_TOOLS))
            def transaction(execute=False, expected_changes=None):
                return build_environment_transaction(requirements, execute=execute, lock_wait=args.lock_wait,
                    expected_changes=expected_changes, profile='remi82-el7' if kind == 'remi82' else 'remi-el7',
                    build_repos=args.build_repo)
        else:
            def transaction(execute=False, expected_changes=None):
                return nb_apt_environment(execute, args.lock_wait, expected_changes)
        plan = transaction()
        report['environment_plan'] = plan
        if not plan.get('ok'):
            report['state']='environment_blocked'
            say('环境准备被阻止：' + _display_value(plan.get('error')))
            repositories = plan.get('repositories') or {}
            if repositories:
                say('构建查询仓库：' + _display_value(', '.join(repositories.get('selected', []))))
                if repositories.get('excluded'):
                    say('未纳入构建查询的仓库：' + _display_value(', '.join(repositories['excluded'])))
            return 10
        say('原生构建依赖计划：%s 项包变更。' % len(plan.get('changes', [])))
        if not args.yes:
            report['state']='environment_plan'
            return 0
        applied = transaction(True, plan.get('changes', []))
        report['environment_transaction']=applied
        if not applied.get('ok'):
            report['state']='environment_install_incomplete'
            say('依赖事务未完成：'+_display_value(applied.get('error')))
            return 20
        report['state']='building_as_user' if args.action == 'all' else 'preparing_as_user'
        write_json(os.path.join(folder,'native-setup.json'), report)
        say('构建依赖已就绪，正在以普通用户 %s 继续。' % _display_value(account['name']))
        if kind == 'remi82':
            result=nb_child(kind, account, args.action=='all', args.jobs, layouts)
            NB_LAST_BUILD_REPORTS = list(result.get('build_reports', [])) if result.get('ok') else []
        else:
            result=nb_child(kind, account, args.action=='all', args.jobs)
        report['build_user_result']=result
        report['state']=result.get('stage', 'build_incomplete') if result.get('ok') else 'build_incomplete'
        if result.get('error'): say(_display_value(result['error']))
        if result.get('ok'): say('原生构建流程完成；生成的 PHP 包尚未部署。')
        return 0 if result.get('ok') else 20
    except Exception as exc:
        report.update(state='error',error=as_text(exc))
        say('原生构建流程未完成：'+_display_value(exc))
        return 20
    finally:
        if folder:
            path=os.path.join(folder,'native-setup.json')
            write_json(path,report)
            say('环境与构建报告：'+path)
