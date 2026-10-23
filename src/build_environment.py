# -*- coding: utf-8 -*-
"""Install the pinned AL2 build environment; never install the resulting PHP RPMs."""

BE_TOOLS = ['rpm', 'rpm-build', 'yum-utils', 'gcc', 'gcc-c++', 'make', 'autoconf',
            'automake', 'libtool', 'patch', 'cpio', 'xz', 'curl']


def be_validate_host_user(args):
    import pwd
    host = bp_doctor_host()
    if (host['platform'] not in ('linux', 'linux2') or host['os_id'] != 'amzn' or
            host['os_version'] != '2' or host['architecture'] != 'x86_64'):
        raise RuntimeError('自动环境准备目前仅适配 Amazon Linux 2 x86_64 的 PHP 7.4 构建配方；未安装任何包。')
    if os.geteuid() != 0:
        raise RuntimeError('setup 需要 sudo/root 安装构建依赖；编译仍以普通用户运行。')
    name = args.build_user or host.get('build_user')
    if not name:
        raise RuntimeError('没有可用的普通构建用户；请用 --build-user 指定已存在的用户。')
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        raise RuntimeError('指定的构建用户不存在；请使用已有普通用户。')
    if account.pw_uid == 0 or account.pw_shell in ('/sbin/nologin', '/usr/sbin/nologin', '/bin/false'):
        raise RuntimeError('构建用户必须是已存在、可登录的非 root 用户。')
    folder = os.path.abspath(args.work_dir or os.path.join(account.pw_dir, BP_DEFAULT_WORKDIR))
    if not re.match(r'^/[A-Za-z0-9_./-]+$', folder):
        raise RuntimeError('构建目录只允许 ASCII 字母、数字和 /_.-。')
    return {'name': account.pw_name, 'uid': account.pw_uid, 'gid': account.pw_gid,
            'home': account.pw_dir, 'work_dir': folder}


def be_report_directory():
    # Root never reads build inputs from a directory controlled by the build user.
    base = '/var/log/php-cve-guard'
    if not os.path.lexists(base):
        os.mkdir(base, 0o700)
    for path in ['/var', '/var/log', base]:
        entry = os.lstat(path)
        if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != 0 or entry.st_mode & 0o022):
            raise RuntimeError('Unsafe root report directory: ' + path)
    return tempfile.mkdtemp(prefix='build-env-', dir=base)


def be_requirements(srpm, rpm):
    bp_verify(srpm, BP_SRPM_SHA)
    query = run_cmd([rpm, '-qp', '--requires', srpm], timeout=30)
    if query['code']:
        raise RuntimeError('Cannot read pinned SRPM build requirements')
    lines = query['stdout'].splitlines()
    if not lines or len(lines) > 256:
        raise RuntimeError('Unexpected SRPM requirement count')
    result = []
    for line in lines:
        requirement = line.strip()
        if (not requirement or len(requirement) > 512 or not re.match(
                r'^[A-Za-z0-9_/][A-Za-z0-9_./+():,~-]*(?:\s+(?:>=|<=|=|>|<)\s+[A-Za-z0-9_.:+~%-]+)?$',
                requirement)):
            raise RuntimeError('Invalid SRPM capability expression')
        if not requirement.startswith('rpmlib('):
            result.append(requirement)
    if not result:
        raise RuntimeError('No external SRPM build requirements found')
    return sorted(set(result))


def be_private_inputs(folder):
    rpm = _inv_tool('rpm', [])
    if not rpm or not _inv_tool('curl', []):
        raise RuntimeError('Trusted rpm/curl required before source inspection')
    srpm = os.path.join(folder, BP_SRPM)
    key = os.path.join(folder, BP_KEY)
    bp_fetch(None, BP_SRPM_URL, BP_SRPM_SHA, srpm)
    bp_fetch(None, BP_KEY_URL, BP_KEY_SHA, key)
    keydb = os.path.join(folder, 'keydb')
    os.mkdir(keydb, 0o700)
    bp_call([rpm, '--dbpath', keydb, '--initdb'])
    bp_call([rpm, '--dbpath', keydb, '--import', key])
    signature = bp_call([rpm, '--dbpath', keydb, '--checksig', '--verbose', srpm])
    if not re.search(r'Signature[^\n]*key ID c87f5b1a: OK', signature, re.I):
        raise RuntimeError('AWS SRPM signature verification failed; no build dependency transaction attempted')
    return srpm, rpm


def be_drop_privileges(account, launcher):
    """Called only in a forked worker, before reading any build-user paths."""
    os.initgroups(account['name'], account['gid'])
    os.setgid(account['gid'])
    os.setuid(account['uid'])
    if os.geteuid() == 0 or os.geteuid() != account['uid']:
        raise RuntimeError('Failed to drop build privileges')
    os.environ.clear()
    os.environ.update({'HOME': account['home'], 'USER': account['name'],
                       'LOGNAME': account['name'], 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                       'LANG': 'C', 'LC_ALL': 'C'})
    if launcher:
        os.environ['PHP_GUARD_LAUNCHER'] = launcher
    os.chdir(account['home'])
    os.umask(0o077)


def be_worker_call(callback):
    """Wait for our fork, forwarding cancellation without reading user files.

    A ready byte is sent only after the child has its own session and signal
    handlers. The parent never signals a PID learned from child-controlled
    JSON, and never signals its fork again after waitpid has reaped it.
    """
    import errno
    import fcntl
    import select
    limit = 4 * 1024 * 1024
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    handlers, interrupted = {}, []
    read_fd = write_fd = None
    pid, status, result, forwarded = None, None, None, False

    def record(signum, unused_frame):
        # No I/O or exceptions here: the worker must finish its own cleanup.
        if not interrupted:
            interrupted.append(signum)

    def child_interrupt(signum, unused_frame):
        raise BuildInterrupted('Build worker interrupted by signal %s' % signum)

    def write_all(fd, value):
        offset = 0
        while offset < len(value):
            try:
                offset += os.write(fd, value[offset:])
            except OSError as exc:
                if exc.errno != errno.EINTR:
                    raise

    try:
        for signum in signals:
            handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, record)
        read_fd, write_fd = os.pipe()
        for fd in (read_fd, write_fd):
            fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.fcntl(fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            # The terminal signals the parent; it forwards exactly once after
            # readiness, so Ctrl-C cannot interrupt the child's cleanup twice.
            child_result = dict(ok=False, exit_code=20, php_deployed=False)
            try:
                try:
                    os.setsid()
                    for signum in signals:
                        signal.signal(signum, child_interrupt)
                    write_all(write_fd, b'R\n')
                    if interrupted:
                        raise BuildInterrupted('Build cancelled before worker started')
                    child_result = callback()
                    if not isinstance(child_result, dict):
                        raise RuntimeError('Invalid build-worker result')
                    payload = json.dumps(child_result, ensure_ascii=True).encode('ascii')
                    if len(payload) > limit:
                        raise RuntimeError('Build-user result exceeded size limit')
                except BaseException as exc:
                    child_result = dict(ok=False, exit_code=20, php_deployed=False,
                                        effective_uid=os.geteuid(), error=as_text(exc))
                    payload = json.dumps(child_result, ensure_ascii=True).encode('ascii')
                write_all(write_fd, payload)
            finally:
                os._exit(0 if child_result.get('ok') else
                         (10 if child_result.get('exit_code') == 10 else 20))
        os.close(write_fd)
        write_fd = None
        fcntl.fcntl(read_fd, fcntl.F_SETFL, fcntl.fcntl(read_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        raw, ready, eof, protocol_error = b'', False, False, None
        while True:
            # An exited, unreaped child still owns its PID. Poll before any
            # cancellation so a reaped PID is never used as a signal target.
            if status is None:
                try:
                    done, child_status = os.waitpid(pid, os.WNOHANG)
                    if done:
                        status = child_status
                except OSError as exc:
                    if exc.errno != errno.EINTR:
                        raise
            if ready and status is None and not forwarded and (interrupted or protocol_error):
                try:
                    os.kill(pid, interrupted[0] if interrupted else signal.SIGTERM)
                except OSError as exc:
                    if exc.errno != errno.ESRCH:
                        raise
                forwarded = True
            if eof:
                if status is not None:
                    break
                # A closed result pipe is not proof that the worker exited.
                time.sleep(0.05)
                continue
            try:
                readable, unused_write, unused_error = select.select([read_fd], [], [], 0 if status is not None else 0.2)
                if not readable:
                    if status is not None:
                        break
                    continue
                chunk = os.read(read_fd, 65536)
            except (OSError, select.error) as exc:
                if exc.args[0] in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                raise
            if not chunk:
                eof = True
                continue
            if protocol_error:
                # Drain rather than allocating or leaving the child blocked
                # on a full pipe while its cancellation is being handled.
                continue
            raw += chunk
            if not ready and len(raw) >= 2:
                if raw[:2] != b'R\n':
                    protocol_error = 'Build worker readiness was not confirmed'
                    # No work can start before our own ready write. A malformed
                    # response is rejected, never an instruction to signal PID.
                else:
                    ready, raw = True, raw[2:]
            if len(raw) > limit:
                protocol_error = 'Build-user result exceeded size limit'
                raw = b''
        try:
            if protocol_error or not ready:
                raise ValueError(protocol_error or 'Build worker exited before readiness')
            result = json.loads(raw.decode('ascii'))
            if not isinstance(result, dict):
                raise ValueError('Invalid build-worker result')
        except (ValueError, UnicodeError) as exc:
            result = dict(ok=False, exit_code=20, php_deployed=False,
                          error='Build worker exited without a complete result: ' + as_text(exc))
        if status or not result.get('ok'):
            result['ok'] = False
            if result.get('exit_code') not in (10, 20):
                result['exit_code'] = 20
    finally:
        try:
            close_error = None
            for fd in (read_fd, write_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError as exc:
                        close_error = exc
            # On a parent-side I/O/error path, cancellation still belongs only
            # to this unreaped fork. Close its read end before waiting so a
            # large result cannot block the worker's final write.
            if pid and status is None:
                if not forwarded:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except OSError as exc:
                        if exc.errno != errno.ESRCH:
                            raise
                while True:
                    try:
                        unused, status = os.waitpid(pid, 0)
                        break
                    except OSError as exc:
                        if exc.errno != errno.EINTR:
                            raise
            if close_error is not None:
                raise close_error
        finally:
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
            if interrupted and result is not None:
                if result.get('error'):
                    result['worker_error'] = result['error']
                result.update(ok=False, exit_code=20, php_deployed=False,
                              interrupted_signal=interrupted[0],
                              error='Build interrupted; worker exited; no PHP deployment attempted')
    return result


def be_as_user(account):
    """Fork already-loaded code, drop privileges before touching user paths."""
    launcher = os.environ.get('PHP_GUARD_LAUNCHER')
    launcher = os.path.abspath(launcher) if launcher else None
    def work():
        result = None
        try:
            be_drop_privileges(account, launcher)
            bp_prepare(argparse.Namespace(output_dir=account['work_dir'], srpm=None,
                                          patch_file=None, key_file=None))
            doctor = bp_doctor_report(argparse.Namespace(work_dir=account['work_dir']))
            result = {'ok': doctor['state'] == 'ready_for_build', 'doctor': doctor,
                      'effective_uid': os.geteuid(), 'prepared': True}
        except Exception as exc:
            result = {'ok': False, 'error': as_text(exc), 'effective_uid': os.geteuid()}
        result['exit_code'] = 0 if result.get('ok') else 10
        return result
    result = be_worker_call(work)
    if result.get('effective_uid') != account['uid']:
        result.update(ok=False, exit_code=20)
    return result


def be_build_as_user(account, jobs):
    """Compile with already-loaded code after dropping every root privilege."""
    global BP_LAST_BUILD_REPORT
    launcher = os.environ.get('PHP_GUARD_LAUNCHER')
    launcher = os.path.abspath(launcher) if launcher else None
    def work():
        global BP_LAST_BUILD_REPORT
        BP_LAST_BUILD_REPORT = None
        result = {'ok': False, 'exit_code': 20, 'php_deployed': False}
        try:
            be_drop_privileges(account, launcher)
            code = bp_auto(argparse.Namespace(work_dir=account['work_dir'], jobs=jobs))
            if code == 0 and not BP_LAST_BUILD_REPORT:
                raise RuntimeError('Build returned success without a build report')
            result.update({'ok': code == 0, 'exit_code': code})
        except Exception as exc:
            result['error'] = as_text(exc)
        result.update({'effective_uid': os.geteuid(), 'build_report': BP_LAST_BUILD_REPORT})
        return result
    result = be_worker_call(work)
    if result.get('effective_uid') != account['uid'] or not result.get('ok'):
        result['ok'] = False
        if result.get('exit_code') not in (10, 20):
            result['exit_code'] = 20
    elif result.get('exit_code') != 0 or not result.get('build_report'):
        result.update({'ok': False, 'exit_code': 20, 'error': 'Incomplete successful build-worker result'})
    return result


def be_all(args):
    """BaoTa AL2 only: root environment setup, then unprivileged RPM build."""
    if BP_RECIPE != 'baota-al2-php74':
        raise RuntimeError('all is available only for the BaoTa AL2 source recipe')
    account = be_validate_host_user(args)
    setup_args = argparse.Namespace(**vars(args))
    setup_args.action = 'setup'
    if not args.yes:
        return be_setup(setup_args)
    os.umask(0o077)
    report_folder = be_report_directory()
    path = os.path.join(report_folder, 'all.json')
    report = {'tool_version': VERSION, 'action': 'all', 'recipe': BP_RECIPE,
              'state': 'setting_up', 'target_version': BP_VERSION,
              'target_release': BP_RELEASE, 'php_deployed': False,
              'build_user': account['name'], 'work_dir': account['work_dir'],
              'jobs_requested': args.jobs, 'build_started': False}
    write_json(path, report)
    try:
        code = be_setup(setup_args)
        report['setup_exit_code'] = code
        if code:
            report['state'] = 'environment_not_ready'
            return code
        report.update({'state': 'building_as_user', 'build_started': True})
        write_json(path, report)
        say('构建环境已就绪，正在以普通用户 %s 自动编译和测试 RPM。' % _display_value(account['name']))
        checked = be_build_as_user(account, args.jobs)
        report['build_user_result'] = checked
        report['state'] = 'built_not_deployed' if checked.get('ok') else 'build_incomplete'
        if checked.get('build_report'):
            say('构建记录：' + _display_value(checked['build_report']))
        if checked.get('error'):
            say('  [普通用户构建] ' + _display_value(checked['error']))
        if checked.get('ok'):
            say('一键环境准备与 RPM 构建完成；生成的 PHP RPM 尚未安装。')
            return 0
        return checked.get('exit_code') if checked.get('exit_code') in (10, 20) else 20
    except Exception as exc:
        report.update({'state': 'all_failed', 'error': as_text(exc)})
        say('一键构建未完成：' + _display_value(exc))
        return 20
    finally:
        write_json(path, report)
        say('一键构建报告：' + path)


def be_show_postcheck(checked):
    """Show the reason without interpreting saved commands or dumping logs."""
    if checked.get('error'):
        say('  [普通用户检查] ' + _display_value(checked['error']))
    doctor = checked.get('doctor') or {}
    for reason in doctor.get('blockers') or []:
        say('  [预检阻止] ' + _display_value(reason))
    dependencies = doctor.get('dependencies') or {}
    for key, label in [('missing', '缺少依赖'), ('unresolved', '依赖尚未核实')]:
        for requirement in dependencies.get(key) or []:
            say('  [%s] %s' % (label, _display_value(requirement)))
    if dependencies.get('reason'):
        say('  [依赖查询] ' + _display_value(dependencies['reason']))
    if not checked.get('error') and not doctor.get('blockers'):
        say('  未获得明确预检原因；请查看报告中的 build_user_check。')


def be_setup(args):
    account = be_validate_host_user(args)
    os.umask(0o077)
    folder = be_report_directory()
    path = os.path.join(folder, 'setup.json')
    report = {'tool_version': VERSION, 'action': 'setup', 'state': 'inspecting',
              'php_deployed': False, 'build_started': False, 'build_user': account['name'],
              'work_dir': account['work_dir'], 'execute_requested': bool(args.yes),
              'transactions': [], 'report': path, 'recipe': BP_RECIPE,
              'target_version': BP_VERSION, 'target_release': BP_RELEASE}
    lock_fd = None
    try:
        if args.yes:
            lock_fd = acquire_repair_lock()
        # AL2 normally includes these two base tools. A missing base tool uses
        # the same native, signed-package transaction policy before download.
        bootstrap = [name for name in ('rpm', 'curl') if not _inv_tool(name, [])]
        if bootstrap:
            preview = build_environment_transaction(bootstrap, lock_wait=args.lock_wait)
            report['bootstrap_preview'] = preview
            if not preview.get('ok'):
                report['state'] = 'bootstrap_blocked'
                return 10
            if not args.yes:
                report['state'] = 'bootstrap_plan_ready'
                say('基础工具需要先安装；当前仅生成计划，使用 setup --yes 自动继续。')
                return 0
            applied = build_environment_transaction(bootstrap, execute=True,
                lock_wait=args.lock_wait, expected_changes=preview.get('changes', []))
            report['transactions'].append(applied)
            write_json(path, report)
            if not applied.get('ok'):
                report['state'] = 'bootstrap_failed'
                return 20
        srpm, rpm = be_private_inputs(folder)
        requirements = sorted(set(BE_TOOLS + be_requirements(srpm, rpm)))
        report.update({'rpm_signature_verified': True, 'srpm_sha256': BP_SRPM_SHA,
                       'requirements': requirements, 'state': 'resolving'})
        write_json(path, report)
        say('已核实系统与 AL2 打包基线 SRPM 签名，正在解析编译工具和构建依赖……')
        preview = build_environment_transaction(requirements, lock_wait=args.lock_wait)
        report['transaction_preview'] = preview
        write_json(path, report)
        for selection in preview.get('dependency_selection', []):
            selected = selection.get('selected', {})
            if selection.get('state') == 'selected' and selected.get('name') == 'httpd-devel':
                say('构建依赖匹配：httpd-devel %s.%s，与已安装 Apache 保持同版本。' % (
                    _display_value(selected.get('version')), _display_value(selected.get('arch'))))
        if not preview.get('ok'):
            report['state'] = 'dependency_plan_blocked'
            say('依赖计划未通过：' + _display_value(preview.get('error', 'unknown error')))
            if preview.get('error_kind') == 'matching_httpd_devel_unavailable':
                say('未找到可安全选用的同版 Apache 开发包；需取得匹配的开发包，或在匹配的独立 AL2 构建机制作补丁。')
            return 10
        say('构建环境计划：%s 项包变更；完整清单：%s' % (len(preview.get('changes', [])), path))
        if not args.yes:
            report['state'] = 'environment_plan_ready'
            say('仅生成环境计划；使用相同参数加 --yes 自动安装，安装可能升级共用依赖库。')
            return 0
        report['state'] = 'installing_dependencies'
        write_json(path, report)
        applied = build_environment_transaction(requirements, execute=True,
            lock_wait=args.lock_wait, expected_changes=preview.get('changes', []))
        report['transactions'].append(applied)
        write_json(path, report)
        if not applied.get('ok'):
            report['state'] = 'dependency_install_failed'
            say('构建依赖安装未完成；请按事务记录核对当前包状态，不要假定所有变更已回滚。')
            return 20
        report['state'] = 'checking_build_user'
        write_json(path, report)
        checked = be_as_user(account)
        report['build_user_check'] = checked
        report['state'] = 'environment_ready_not_built' if checked.get('ok') else 'environment_postcheck_failed'
        if checked.get('ok'):
            say('构建工具和依赖已补齐，普通用户源码准备与预检通过；尚未编译或部署 PHP。')
            script = os.environ.get('PHP_GUARD_LAUNCHER')
            script = os.path.abspath(script) if script else '/path/to/php-cve-guard.sh'
            say('下一步：sudo -u %s -H bash %s %s auto --work-dir %s --jobs 2' % (
                bp_shell_quote(account['name']), bp_shell_quote(script), BP_COMMAND, bp_shell_quote(account['work_dir'])))
        else:
            say('依赖事务已完成，但普通用户预检未通过；详见 setup.json 中 build_user_check。')
            be_show_postcheck(checked)
        return 0 if checked.get('ok') else 10
    except Exception as exc:
        report.update({'state': 'environment_setup_error', 'error': as_text(exc)})
        say('环境准备未完成：' + _display_value(exc))
        return 20
    finally:
        write_json(path, report)
        say('环境准备报告：' + path)
        if lock_fd is not None:
            os.close(lock_fd)
