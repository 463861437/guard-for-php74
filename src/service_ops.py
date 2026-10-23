# -*- coding: utf-8 -*-
"""Conservative systemd preflight, restart verification and config snapshots.

No inspection or mutation takes place at import time. The release concatenates
this module after common.py and inventory.py.
"""
import os
import re
import stat
import glob
import time
import json
import tarfile
import tempfile


def _svc_name(name):
    name = as_text(name)
    if not name.endswith('.service'):
        name += '.service'
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service$', name):
        raise ValueError('Invalid systemd service name')
    return name


def _svc_fpm(name):
    return bool(re.match(r'^(?:(?:rh-)?php(?:[0-9]+(?:\.[0-9]+)?)?(?:-php)?-fpm(?:[-.]?[0-9]+(?:\.[0-9]+)?)?)\.service$', name))


def _svc_container_manager(name):
    return bool(re.match(r'^(?:docker|podman|containerd|cri-o|crio|kubelet|lxc|libvirtd)(?:[.@-]|$)', name or ''))


def _svc_php_process(process):
    return bool(re.search(r'php|fpm|lsphp|frankenphp',
                          (process.get('comm') or '') + ' ' +
                          os.path.basename(process.get('exe') or ''), re.I))


def _svc_block(result, name, reason, process=None):
    item = {'service': name, 'reason': reason}
    if process:
        for key in ('pid', 'ppid', 'parent_comm', 'start_ticks', 'lifecycle'):
            if key in process:
                item[key] = process[key]
    if item not in result['blockers']:
        result['blockers'].append(item)


def _svc_show(systemctl, name):
    wanted = ('Id', 'LoadState', 'ActiveState', 'ExecStart', 'Environment', 'EnvironmentFiles',
              'RootDirectory', 'RootImage', 'WorkingDirectory', 'User', 'Group')
    response = run_cmd([systemctl, 'show', name, '--no-pager',
                        '--property=Id,LoadState,ActiveState,ExecStart,Environment,EnvironmentFiles,RootDirectory,RootImage,WorkingDirectory,User,Group'], timeout=30)
    fallback = response['code'] != 0
    if fallback:
        # systemd 219 exits 1 for the unsupported RootImage property, even
        # though the unit exists. Enumerate the supported properties instead.
        # Capture in memory and retain only the required whitelist; never log
        # the complete response or environment values.
        response = run_cmd([systemctl, 'show', name, '--no-pager', '--all'], timeout=30)
    if response['code'] != 0:
        raise ValueError('Cannot read systemd service properties')
    values = {}
    for line in as_text(response['stdout']).splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            if key in wanted:
                values[key] = value
    # Unloaded units on older systemd expose only generic unit properties.
    # Report an observed state before requiring service-specific properties;
    # an absent state is still unknown and must pass the completeness guard.
    load_state = values.get('LoadState')
    if load_state == 'not-found':
        raise ValueError('Systemd service does not exist (LoadState=not-found)')
    if load_state and load_state != 'loaded':
        state = load_state if load_state in ('stub', 'error', 'masked', 'bad-setting', 'merged') else 'unknown'
        raise ValueError('Service is not a loaded systemd unit (LoadState=%s)' % state)
    active_state = values.get('ActiveState')
    if load_state == 'loaded' and active_state and active_state != 'active':
        state = active_state if active_state in ('inactive', 'failed', 'activating', 'deactivating', 'reloading', 'maintenance', 'refreshing') else 'unknown'
        raise ValueError('Service is not active (ActiveState=%s)' % state)
    if fallback and 'EnvironmentFiles' not in values:
        # systemd 219 omits the empty EnvironmentFiles array even with --all.
        # Accept absence only if a dedicated query succeeds with no output.
        empty_files = run_cmd([systemctl, 'show', name, '--no-pager', '--all',
                               '--property=EnvironmentFiles'], timeout=30)
        if empty_files['code'] == 0 and not as_text(empty_files['stdout']).strip():
            values['EnvironmentFiles'] = ''
    if fallback and any(key not in values for key in wanted if key != 'RootImage'):
        raise ValueError('Systemd property enumeration is incomplete; cannot verify service configuration')
    if values.get('LoadState') != 'loaded':
        raise ValueError('Service is not a loaded systemd unit')
    if values.get('ActiveState') != 'active':
        raise ValueError('Service is not active')
    return values


def _svc_exec_start(raw):
    """Accept one simple systemd command, rejecting ambiguous escaping.

    systemctl's formatted ExecStart is not a shell command. Do not eval it,
    shell-split it, expand variables or emit it in diagnostics.
    """
    if not raw or len(raw) > 16384 or raw.count('argv[]=') != 1:
        raise ValueError('ExecStart must contain exactly one inspectable command')
    if raw.count('{') != 1 or raw.count('}') != 1:
        raise ValueError('Multiple or ambiguous ExecStart commands')
    match_path = re.search(r'(?:^|[\s{;])path=([^\s;{}]+)', raw)
    match_argv = re.search(r'(?:^|[\s{;])argv\[\]=(.*?)\s*;', raw)
    if not match_path or not match_argv:
        raise ValueError('ExecStart path or argument representation is unsupported')
    path = match_path.group(1)
    argv_text = match_argv.group(1)
    if re.search(r'[\\\x00-\x1f\x7f\'"$`{}|&<>]', path + argv_text):
        raise ValueError('ExecStart contains escaping or expansion that cannot be reconstructed safely')
    argv = argv_text.split()
    if not argv or argv[0] != path or not os.path.isabs(path):
        raise ValueError('ExecStart executable is not an absolute, direct binary invocation')
    return path, argv[1:]


def _svc_fpm_test_argv(properties):
    # An environment/config namespace would change what -t tests. Failing
    # closed is preferable to testing a different service configuration.
    if properties.get('RootDirectory') or properties.get('RootImage'):
        raise ValueError('Service uses a separate root; configuration test requires manual validation')
    if properties.get('Environment') or properties.get('EnvironmentFiles'):
        raise ValueError('Service environment cannot be reproduced without exposing or reading credentials; manual preflight required')
    if properties.get('User') not in (None, '', 'root'):
        raise ValueError('Service uses a non-root master user; matching privilege preflight is required')
    if properties.get('WorkingDirectory') not in (None, '', '/'):
        raise ValueError('Service uses a custom working directory; manual preflight required')
    if any(key in os.environ for key in ('PHPRC', 'PHP_INI_SCAN_DIR')):
        raise ValueError('Caller PHP configuration environment differs from systemd; remove PHPRC/PHP_INI_SCAN_DIR and retry')
    path, args = _svc_exec_start(properties.get('ExecStart'))
    if not re.match(r'^php(?:[0-9]+(?:\.[0-9]+)?)?-fpm(?:[-.]?[0-9]+(?:\.[0-9]+)?)?$', os.path.basename(path)):
        raise ValueError('FPM service ExecStart is not a recognized direct PHP-FPM binary')
    trusted, reason = _inv_trusted_executable(path)
    if not trusted:
        raise ValueError('FPM executable or its parent directories are untrusted')
    command = [path, '-t']
    value_flags = {'-y': '-y', '--fpm-config': '-y', '-c': '-c', '--php-ini': '-c',
                   '-d': '-d', '--define': '-d', '-p': '-p', '--prefix': '-p'}
    drop_flags = set(['-F', '--nodaemonize', '-D', '--daemonize', '-O', '--force-stderr',
                      '-R', '--allow-to-run-as-root'])
    i = 0
    while i < len(args):
        token = args[i]
        if token in drop_flags:
            i += 1
            continue
        if token == '-n' or token == '--no-php-ini':
            command.append('-n')
            i += 1
            continue
        flag, value = None, None
        if token in value_flags:
            flag = value_flags[token]
            i += 1
            if i >= len(args):
                raise ValueError('FPM option is missing its value')
            value = args[i]
        elif token.startswith('--') and '=' in token:
            key, value = token.split('=', 1)
            flag = value_flags.get(key)
        elif len(token) > 2 and token[:2] in ('-y', '-c', '-d', '-p'):
            flag, value = token[:2], token[2:]
        else:
            raise ValueError('FPM ExecStart has an unsupported option; manual preflight required')
        if flag is None or not value or value.startswith('-'):
            raise ValueError('FPM ExecStart contains an ambiguous configuration option')
        if flag in ('-y', '-c', '-p') and not os.path.isabs(value):
            raise ValueError('FPM config/prefix paths must be absolute for reliable preflight')
        if flag == '-d' and not re.match(r'^[A-Za-z0-9_.-]+(?:=.*)?$', value):
            raise ValueError('FPM -d setting has an unsupported form')
        command.extend([flag, value])
        i += 1
    return command


def _svc_apache_test_argv(name, properties, warnings):
    if any(key in os.environ for key in ('PHPRC', 'PHP_INI_SCAN_DIR', 'APACHE_CONFDIR', 'APACHE_ENVVARS', 'APACHE_ARGUMENTS')):
        raise ValueError('Caller Apache/PHP environment may select a different configuration; remove overrides and retry')
    if properties.get('RootDirectory') or properties.get('RootImage'):
        raise ValueError('Apache service uses a separate root; manual preflight required')
    if properties.get('Environment') or properties.get('EnvironmentFiles'):
        raise ValueError('Apache service environment cannot be reproduced reliably; manual preflight required')
    if properties.get('WorkingDirectory') not in (None, '', '/'):
        raise ValueError('Apache service has a custom working directory; manual preflight required')
    path, args = _svc_exec_start(properties.get('ExecStart'))
    basename = os.path.basename(path)
    if basename in ('apachectl', 'apache2ctl') and args in (['start'], ['-k', 'start']):
        trusted, reason = _inv_trusted_executable(path)
        if not trusted:
            raise ValueError('Apache control executable or its parent directories are untrusted')
        return [path, 'configtest']
    if basename not in ('httpd', 'apache2'):
        raise ValueError('Apache service does not directly invoke a supported control/binary command')
    trusted, reason = _inv_trusted_executable(path)
    if not trusted:
        raise ValueError('Apache executable or its parent directories are untrusted')
    command = [path, '-t']
    i = 0
    while i < len(args):
        value = args[i]
        if value in ('-DFOREGROUND', '-DNO_DETACH'):
            i += 1
            continue
        if value == '-k' and i + 1 < len(args) and args[i + 1] == 'start':
            i += 2
            continue
        if value in ('-f', '-d', '-D') and i + 1 < len(args):
            argument = args[i + 1]
            if argument.startswith('-') or (value in ('-f', '-d') and not os.path.isabs(argument)):
                raise ValueError('Apache config path or define is ambiguous')
            command.extend([value, argument])
            i += 2
            continue
        if value.startswith('-D') and len(value) > 2:
            command.append(value)
            i += 1
            continue
        raise ValueError('Apache ExecStart contains unsupported configuration options; manual preflight required')
    return command


def service_preflight(inv, updates, extra_services=None):
    result = {'services': [], 'blockers': [], 'checks': []}
    warnings = []
    systemctl = _inv_tool('systemctl', warnings)
    if not systemctl:
        _svc_block(result, None, 'Trusted systemctl unavailable; automatic restart is not possible')
        return result
    explicit = set()
    for requested in (extra_services or []):
        try:
            name = _svc_name(requested)
            if _svc_container_manager(name):
                raise ValueError('Container engine services cannot be restarted by this tool')
            explicit.add(name)
        except ValueError as exc:
            _svc_block(result, None, as_text(exc))
    selected = set(explicit)
    mod_php = any(re.search(r'(^mod_php|libapache2-mod-php|(?:^|-)php[0-9.]*-apache)',
                            update.get('name', ''), re.I) for update in updates)
    # RPM's mod_php may live in the core package named php / php82-php.
    rpm_module_update = any(re.match(r'^(?:(?:rh-)?php[0-9]+-)?php(?:[0-9.]*)?$',
                                     update.get('name', '')) and
                            inv.get('package_manager') in ('yum', 'dnf') for update in updates)
    active_apache = set()
    for service in inv.get('services', []):
        name = service.get('name') or ''
        if service.get('active') != 'active':
            continue
        if _svc_fpm(name):
            selected.add(name)
        if name in ('apache2.service', 'httpd.service'):
            active_apache.add(name)
    if mod_php or rpm_module_update:
        selected.update(active_apache)
        for service in inv.get('services', []):
            name = service.get('name') or ''
            if (service.get('active') == 'active' and re.search(r'apache|httpd', name, re.I)
                    and name not in active_apache):
                _svc_block(result, name, 'Nonstandard Apache service requires matching configuration test and module restart verification; automatic update blocked')
    for process in inv.get('processes', []):
        if not _svc_php_process(process):
            continue
        service = process.get('service')
        if process.get('start_ticks') is not None:
            current = _inv_proc_stat(process['pid'])
            if current is None and _inv_proc_absent(process['pid']):
                result['checks'].append({'pid': process['pid'],
                                         'check': 'process-exited-before-preflight', 'ok': True})
                continue
            if current is None:
                _svc_block(result, service, 'Cannot revalidate PHP process PID %s identity; inspection may be restricted' % process['pid'], process)
                continue
            if current['start_ticks'] != process['start_ticks']:
                _svc_block(result, service, 'PHP process PID %s was reused since inventory; rerun inspection before update' % process['pid'], process)
                continue
        if process.get('container') or _svc_container_manager(service):
            _svc_block(result, service, 'PHP process PID %s belongs to a container; update and recreate its image separately' % process.get('pid'), process)
        elif not service:
            _svc_block(result, None, 'PHP process PID %s has no mapped systemd service; manual lifecycle handling is required' % process.get('pid'), process)
        elif service not in selected:
            _svc_block(result, service, 'Long-running PHP process PID %s is not covered; explicitly select its service with --service' % process.get('pid'), process)
    for name in sorted(selected):
        try:
            properties = _svc_show(systemctl, name)
            if _svc_container_manager(properties.get('Id', name)):
                raise ValueError('Container engine services cannot be restarted by this tool')
            if _svc_fpm(name):
                command = _svc_fpm_test_argv(properties)
                response = run_cmd(command, timeout=60)
                passed = response['code'] == 0
                result['checks'].append({'service': name, 'check': 'fpm-config-test', 'ok': passed,
                                         'detail': 'Exact whitelisted ExecStart configuration options tested; diagnostic output suppressed to protect secrets'})
                if not passed:
                    raise ValueError('PHP-FPM configuration test failed (exit %s); inspect service logs locally' % response['code'])
            elif name in ('apache2.service', 'httpd.service'):
                command = _svc_apache_test_argv(name, properties, warnings)
                response = run_cmd(command, timeout=60)
                passed = response['code'] == 0
                result['checks'].append({'service': name, 'check': 'apache-config-test', 'ok': passed})
                if not passed:
                    raise ValueError('Apache configuration test failed (exit %s); inspect diagnostics locally' % response['code'])
            else:
                result['checks'].append({'service': name, 'check': 'explicit-cli-service', 'ok': True,
                                         'detail': 'Loaded and active; no generic syntax test exists for long-running CLI applications'})
            result['services'].append(name)
        except (ValueError, OSError) as exc:
            _svc_block(result, name, as_text(exc))
    return result


def restart_services(names):
    result = {'ok': True, 'errors': []}
    systemctl = _inv_tool('systemctl', [])
    if not systemctl:
        return {'ok': False, 'errors': ['Trusted systemctl unavailable']}
    for requested in names:
        try:
            name = _svc_name(requested)
            if _svc_container_manager(name):
                raise ValueError('Refusing to restart a container engine service')
            # Revalidate unit identity and activity immediately before mutation.
            properties = _svc_show(systemctl, name)
            if _svc_container_manager(properties.get('Id', name)):
                raise ValueError('Refusing to restart a container engine service')
            response = run_cmd([systemctl, 'restart', name], timeout=120)
            active = run_cmd([systemctl, 'is-active', name], timeout=30)
            if response['code'] != 0 or active['code'] != 0 or as_text(active['stdout']).strip() != 'active':
                raise ValueError('Restart or post-restart active-state verification failed')
        except (ValueError, OSError) as exc:
            result['ok'] = False
            result['errors'].append({'service': requested, 'reason': as_text(exc)})
            break
    return result


def residual_process_check(before, after, updates=None, services=None):
    """Fail on deleted binaries and unchanged PHP PIDs after selected restarts.

    This does not claim to determine an Apache module version from its PID.
    """
    selected = set(services or [])
    old = dict((p.get('pid'), p) for p in before.get('processes', [])
               if _svc_php_process(p) or p.get('service') in selected)
    errors = []
    for process in after.get('processes', []):
        if process.get('deleted'):
            errors.append({'pid': process.get('pid'), 'reason': 'Process still uses a deleted executable'})
        previous = old.get(process.get('pid'))
        same_identity = (previous and
                         (previous.get('start_ticks') is None or
                          process.get('start_ticks') is None or
                          previous['start_ticks'] == process['start_ticks']))
        if (previous and process.get('service') in selected and
                previous.get('exe') == process.get('exe') and same_identity):
            errors.append({'pid': process.get('pid'), 'reason': 'Process PID survived its service restart; loaded PHP version is unverified'})
        if process.get('service') in selected and process.get('comm') in ('httpd', 'apache2'):
            try:
                with open('/proc/%s/maps' % process['pid']) as handle:
                    if any('libphp' in line and '(deleted)' in line for line in handle):
                        errors.append({'pid': process['pid'], 'reason': 'Apache still maps a deleted PHP module'})
            except IOError:
                if os.path.exists('/proc/%s' % process['pid']):
                    errors.append({'pid': process['pid'], 'reason': 'Cannot verify Apache PHP module mappings'})
    return {'ok': not errors, 'errors': errors}


def _svc_backup_allowed(path):
    name = os.path.basename(path).lower()
    if name.startswith('.') or re.search(r'(?:^|[._-])(?:key|pem|p12|pfx|password|passwd|credential|secret|token|env)(?:[._-]|$)', name):
        return False
    return name.endswith(('.ini', '.conf', '.load')) or name in ('magic', 'envvars')


def backup_configuration(inv, updates, folder):
    """Archive selected PHP/Apache config only; never packages or site data.

    Symlinks are retained as links, never dereferenced. Known authentication,
    certificate/key and .env files are excluded, including under config roots.
    """
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        os.makedirs(folder, 0o700)
    if os.path.islink(folder):
        raise ValueError('Backup directory must not be a symlink')
    os.chmod(folder, 0o700)
    archive = os.path.join(folder, 'php-apache-config-%s-%s.tar.gz' % (time.strftime('%Y%m%d-%H%M%S'), os.getpid()))
    patterns = ['/etc/php*', '/etc/opt/remi/php*', '/etc/opt/rh/*php*', '/etc/httpd', '/etc/apache2']
    roots = sorted(set(path for pattern in patterns for path in glob.glob(pattern)))
    paths = set()
    for root in roots:
        if os.path.isfile(root) or os.path.islink(root):
            if _svc_backup_allowed(root):
                paths.add(root)
            continue
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not d.startswith('.') and
                             not re.search(r'(?i)^(?:ssl|private|keys|certs|credentials|secrets)$', d) and
                             not os.path.islink(os.path.join(current, d)))
            for name in files:
                path = os.path.join(current, name)
                if _svc_backup_allowed(path):
                    paths.add(path)
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        with tarfile.open(archive, 'w:gz', dereference=False) as target:
            for path in sorted(paths):
                info = os.lstat(path)
                if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    target.add(path, arcname=path.lstrip(os.sep), recursive=False)
        os.chmod(archive, 0o600)
        manifest = archive + '.json'
        fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write((json.dumps({'archive': archive, 'files': sorted(paths),
                                      'scope': 'Selected PHP/Apache .ini/.conf/.load and standard config files only; symlinks are not dereferenced; authentication/key/.env files excluded.',
                                      'limitations': 'Configuration snapshot only. Not a package rollback, application backup, database backup or complete disaster recovery archive.'},
                                     ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
        return archive
    except Exception:
        try:
            os.unlink(archive)
        except OSError:
            pass
        raise
