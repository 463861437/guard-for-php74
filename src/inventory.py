# -*- coding: utf-8 -*-
"""Read-only host inventory. Compatible with Python 2.7 and Python 3.6+.

This module is also concatenated after common.py in the release script.
Importing it performs no inspection and executes no external commands.
"""

import os
import json
import re
import sys
import subprocess
import glob
import hashlib
import time
import tempfile
import shutil
import stat
import errno

try:
    _inv_string_types = (basestring,)
except NameError:
    _inv_string_types = (str, bytes)


def _inv_text(value):
    helper = globals().get('as_text')
    if helper is not None:
        return helper(value)
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    try:
        return unicode(value)
    except NameError:
        return str(value)


def _inv_warn(warnings, message):
    if message not in warnings:
        warnings.append(message)


def _inv_read(path, limit=65536):
    try:
        with open(path, 'rb') as handle:
            return _inv_text(handle.read(limit))
    except (IOError, OSError):
        return None


def _inv_cmd(argv, timeout=30):
    # run_cmd is supplied by the common prelude; tests can inject a fake.
    try:
        result = run_cmd(argv, timeout=timeout)
        return {'code': result.get('code', 1),
                'stdout': _inv_text(result.get('stdout') or ''),
                'stderr': _inv_text(result.get('stderr') or '')}
    except Exception as exc:
        return {'code': 1, 'stdout': '', 'stderr': _inv_text(exc)}


def _inv_trusted_executable(path):
    """Check both lexical and resolved paths, including every ancestor.

    Symlink permission bits are not access controls; their ownership and
    the ownership/mode of each link's parent and final target are checked.
    This is a point-in-time check, not protection against a hostile root.
    """
    path = os.path.abspath(path)
    try:
        real = os.path.realpath(path)
        seen = set()
        pending = [path, real]
        while pending:
            current = pending.pop()
            while current not in seen:
                seen.add(current)
                info = os.lstat(current)
                if info.st_uid != 0:
                    return False, 'non-root owner: ' + current
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(current)
                    if not os.path.isabs(target):
                        target = os.path.join(os.path.dirname(current), target)
                    pending.append(os.path.abspath(target))
                elif info.st_mode & 0o022:
                    return False, 'group/other writable: ' + current
                parent = os.path.dirname(current)
                if parent == current:
                    break
                current = parent
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
            return False, 'not an executable regular file: ' + path
        return True, None
    except (OSError, IOError) as exc:
        return False, 'cannot verify executable: %s (%s)' % (path, _inv_text(exc))


def _inv_tool(name, warnings):
    directories = ['/usr/sbin', '/usr/bin', '/sbin', '/bin',
                   '/usr/local/sbin', '/usr/local/bin']
    directories.extend(os.environ.get('PATH', '').split(os.pathsep))
    seen = set()
    for directory in directories:
        if not directory or not os.path.isabs(directory):
            continue
        path = os.path.join(directory, name)
        if path in seen:
            continue
        seen.add(path)
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        trusted, reason = _inv_trusted_executable(path)
        if trusted:
            return path
        _inv_warn(warnings, 'Skipped untrusted command %s: %s' % (path, reason))
    return None


def _inv_os():
    result = {'id': None, 'version_id': None, 'pretty_name': None,
              'codename': None, 'version_codename': None, 'ubuntu_codename': None}
    content = _inv_read('/etc/os-release')
    if content is None:
        content = _inv_read('/usr/lib/os-release')
    for line in (content or '').splitlines():
        match = re.match(r'^(ID|VERSION_ID|PRETTY_NAME|VERSION_CODENAME|UBUNTU_CODENAME)=(.*)$', line)
        if not match:
            continue
        value = match.group(2).strip()
        if len(value) > 1 and value[0] == value[-1] and value[0] in ('"', "'"):
            quote = value[0]
            value = value[1:-1]
            if quote == '"':
                value = re.sub(r'\\([\\"$`])', r'\1', value)
        result[match.group(1).lower()] = value
    return result


def _inv_php_package(name, source):
    pattern = r'(^|[-_])(php[0-9]*|lsphp[0-9]*)([-_.:]|$)'
    return bool(re.search(pattern, name.lower()) or
                re.search(pattern, (source or '').lower()) or
                name.lower().startswith('libapache2-mod-php') or
                name.lower().startswith('mod_php'))


def _inv_upstream(version):
    # Keep the exact vendor version separately; this number does NOT account
    # for security fixes backported by a distribution.
    value = version.split(':', 1)[-1]
    match = re.match(r'(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z]+\d*)?)', value)
    return match.group(1) if match else None


def _inv_lightweight_packages(manager, tool, warnings):
    """Read PHP packages from managers without a dpkg/RPM database.

    apk and pacman do not expose the RPM/DPKG metadata that the remediation
    backends require.  We still collect their installed PHP package names and
    versions for audit, while deliberately leaving provenance unset.  The
    caller must keep these managers in audit-only mode.
    """
    if manager == 'apk':
        response = _inv_cmd([tool, 'info', '-v'], timeout=60)
    elif manager == 'pacman':
        response = _inv_cmd([tool, '-Q'], timeout=60)
    else:
        return []
    if response['code'] != 0:
        _inv_warn(warnings, '%s package inventory failed; PHP package coverage is incomplete.' % manager)
        return []
    try:
        arch = os.uname()[4]
    except (AttributeError, OSError):
        arch = None
    packages = []
    for line in response['stdout'].splitlines():
        line = line.strip()
        if not line:
            continue
        if manager == 'pacman':
            fields = line.split()
            if len(fields) < 2:
                continue
            name, version = fields[0], fields[1]
        else:
            # apk prints e.g. php83-fpm-8.3.28-r0.  Split only at the
            # hyphen immediately before a numeric upstream version so package
            # names containing hyphens remain intact.
            match = re.match(r'^(.*?)-(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._+~-]+)?)$', line)
            if not match:
                continue
            name, version = match.groups()
        if not _inv_php_package(name, ''):
            continue
        packages.append({'name': name, 'version': version,
                         'upstream': _inv_upstream(version),
                         'source': name, 'arch': arch or 'unknown',
                         'source_version': version, 'vendor': None})
    return packages


def _inv_packages(warnings):
    packages = []
    database_rows = {'dpkg': 0, 'rpm': 0}
    dpkg = _inv_tool('dpkg-query', warnings)
    rpm = _inv_tool('rpm', warnings)
    manager = None
    if dpkg:
        manager = 'apt'
        query = '${binary:Package}\t${Version}\t${source:Package}\t${Architecture}\t${db:Status-Abbrev}\t${source:Version}\n'
        response = _inv_cmd([dpkg, '-W', '-f=' + query])
        if response['code'] == 0:
            for line in response['stdout'].splitlines():
                fields = line.split('\t')
                if len(fields) < 5:
                    continue
                name, version, source, arch, state = fields[:5]
                source_version = fields[5] if len(fields) > 5 else version
                # The second status character denotes the installed state;
                # include held packages as well as normally selected packages.
                if len(state) < 2 or state[1] != 'i':
                    continue
                database_rows['dpkg'] += 1
                if _inv_php_package(name, source):
                    packages.append({'name': name, 'version': version,
                                     'upstream': _inv_upstream(version),
                                     'source': source or name, 'arch': arch,
                                     'source_version': source_version or version,
                                     'vendor': None})
        else:
            _inv_warn(warnings, 'dpkg-query inventory failed; Debian package coverage is incomplete.')
    if rpm:
        if manager is None or not database_rows['dpkg']:
            if _inv_tool('dnf', warnings):
                manager = 'dnf'
            elif _inv_tool('yum', warnings):
                manager = 'yum'
            elif _inv_tool('zypper', warnings):
                # RPM inventory is useful for audit on openSUSE/SLE, but the
                # remediation worker only supports native yum/dnf bindings.
                manager = 'zypper'
            else:
                # Keep the fact that an RPM database exists.  This prevents a
                # misleading "no package manager" message and lets audit
                # report package versions while plan/fix remain blocked.
                manager = 'rpm'
        query = '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\t%{VENDOR}\n'
        response = _inv_cmd([rpm, '-qa', '--qf', query])
        if response['code'] == 0:
            for line in response['stdout'].splitlines():
                fields = line.split('\t')
                if len(fields) < 6:
                    continue
                database_rows['rpm'] += 1
                name, epoch, upstream, release, source, arch = fields[:6]
                vendor = fields[6] if len(fields) > 6 else None
                if not _inv_php_package(name, source):
                    continue
                version = upstream + ('-' + release if release else '')
                source_version = version
                source_rpm = source
                suffix = '-' + upstream + '-' + release + '.src.rpm'
                if source.endswith(suffix):
                    source = source[:-len(suffix)]
                else:
                    source = re.sub(r'-[^-]+-[^-]+\.(?:src|nosrc)\.rpm$', '', source)
                if epoch and epoch not in ('(none)', '(null)', '0'):
                    version = epoch + ':' + version
                packages.append({'name': name, 'version': version,
                                 'upstream': _inv_upstream(upstream),
                                 'source': source, 'arch': arch,
                                 'source_rpm': source_rpm,
                                 'source_version': source_version,
                                 'vendor': vendor if vendor not in ('(none)', '(null)') else None})
        else:
            _inv_warn(warnings, 'rpm inventory failed; RPM package coverage is incomplete.')
    if not dpkg and not rpm:
        for candidate in ('apk', 'pacman'):
            path = _inv_tool(candidate, warnings)
            if path:
                manager = candidate
                packages = _inv_lightweight_packages(candidate, path, warnings)
                break
        if manager is None:
            _inv_warn(warnings, 'Neither a trusted dpkg-query/rpm/apk/pacman was found; package inventory is unavailable.')
            manager = 'unknown'
    if manager in ('apk', 'pacman'):
        _inv_warn(warnings, '%s audit coverage is incomplete: package source, ownership and integrity verification are not implemented; automatic repair is unavailable.' % manager)
    if database_rows['dpkg'] and database_rows['rpm']:
        _inv_warn(warnings, 'Both DPKG and RPM databases are present; mixed package-manager coverage is incomplete and automatic repair is unavailable.')
    packages.sort(key=lambda item: (item['name'], item['arch'], item['version']))
    return manager, packages, dpkg, rpm


def manager_capabilities(inv):
    """Describe the exact implemented adapter, never infer it from ID_LIKE.

    A Fedora/RHEL-like label does not make a zypper/APK/Pacman host compatible
    with the YUM solver.  A mixed database is similarly unsafe for one native
    transaction even though both inventories can be shown in the report.
    """
    manager = inv.get('package_manager') or 'unknown'
    backend = {'apt': 'python-apt', 'yum': 'python-yum', 'dnf': 'python-dnf'}.get(manager)
    blockers = []
    if not backend:
        blockers.append({'kind': 'unsupported_package_manager', 'status': 'unknown',
                         'reason': '检测到包管理器 %s；当前仅支持只读审计，尚无经过验证的原生自动修复适配器。不会使用其他发行版的 RPM/DEB 替换本机 PHP。' % manager})
    if any('Both DPKG and RPM databases' in warning for warning in inv.get('warnings', [])):
        blockers.append({'kind': 'mixed_package_managers', 'status': 'unknown',
                         'reason': '同时检测到 DPKG 和 RPM 数据库，无法确认单一原生包事务的完整覆盖；自动修复被阻止。'})
    return {'manager': manager, 'backend': backend,
            'automatic_fix': bool(backend) and not blockers,
            'scope': 'native_repository_upgrade' if backend and not blockers else 'read_only_audit',
            'blockers': blockers}


def _inv_runtime_name(name):
    return bool(re.match(r'^(?:php(?:[0-9]+(?:\.[0-9]+)?)?(?:-(?:fpm|cgi))?'
                         r'|php-(?:fpm|cgi)(?:[0-9]+(?:\.[0-9]+)?)?'
                         r'|lsphp[0-9]*(?:\.[0-9]+)?)$', name))


def _inv_candidates(extra_roots, warnings):
    candidates = set()
    directories = ['/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']
    directories.extend(os.environ.get('PATH', '').split(os.pathsep))
    patterns = ['/opt/remi/php*/root/usr/bin', '/opt/remi/php*/root/usr/sbin',
                '/opt/rh/*php*/root/usr/bin', '/opt/rh/*php*/root/usr/sbin',
                '/www/server/php/*/bin', '/www/server/php/*/sbin',
                '/usr/local/php*/bin', '/usr/local/php*/sbin',
                '/usr/local/lsws/lsphp*/bin', '/usr/local/lsws/fcgi-bin']
    for pattern in patterns:
        directories.extend(glob.glob(pattern))
    for directory in sorted(set(directories)):
        if not directory or not os.path.isabs(directory):
            continue
        try:
            for name in os.listdir(directory):
                if _inv_runtime_name(name):
                    path = os.path.join(directory, name)
                    if os.path.isfile(path) and os.access(path, os.X_OK):
                        candidates.add(os.path.abspath(path))
        except (OSError, IOError):
            continue
    roots = extra_roots or []
    if isinstance(roots, _inv_string_types):
        roots = [roots]
    for requested in roots:
        root = os.path.abspath(os.path.expanduser(_inv_text(requested)))
        if os.path.isfile(root):
            if _inv_runtime_name(os.path.basename(root)):
                candidates.add(root)
            continue
        if not os.path.isdir(root):
            _inv_warn(warnings, 'Extra scan root does not exist or is unreadable: ' + root)
            continue
        visited = [0]
        root_depth = root.rstrip(os.sep).count(os.sep)

        def onerror(error):
            _inv_warn(warnings, 'Extra scan directory unreadable: ' + _inv_text(error.filename))

        # Do not follow symlink directories. Bound both depth and work so a
        # mistakenly supplied / cannot cause an unbounded filesystem scan.
        for current, dirs, files in os.walk(root, topdown=True, onerror=onerror, followlinks=False):
            visited[0] += 1
            if visited[0] > 2000:
                _inv_warn(warnings, 'Extra root scan stopped at 2000 directories: ' + root)
                break
            depth = current.rstrip(os.sep).count(os.sep) - root_depth
            if depth >= 5:
                dirs[:] = []
            else:
                dirs[:] = sorted(d for d in dirs if not d.startswith('.') and
                                 not os.path.islink(os.path.join(current, d)))
            for name in files:
                if _inv_runtime_name(name):
                    path = os.path.join(current, name)
                    if os.path.isfile(path) and os.access(path, os.X_OK):
                        candidates.add(path)
    return sorted(candidates)


def _inv_owner(path, dpkg, rpm, cache):
    real = os.path.realpath(path)
    if real in cache:
        return cache[real]
    owner = None
    for candidate in [real, path] if real != path else [path]:
        if rpm:
            response = _inv_cmd([rpm, '-qf', '--qf', '%{NAME}\n', candidate])
            if response['code'] == 0 and response['stdout'].strip():
                owner = response['stdout'].splitlines()[0].strip()
        if owner is None and dpkg:
            response = _inv_cmd([dpkg, '-S', candidate])
            if response['code'] == 0:
                for line in response['stdout'].splitlines():
                    if ': ' in line:
                        name, owned_path = line.split(': ', 1)
                        if owned_path == candidate and not name.startswith('diversion by '):
                            owner = name
                            break
        if owner:
            break
    cache[real] = owner
    return owner


def _inv_runtimes(extra_roots, warnings, dpkg, rpm):
    runtimes = []
    seen = set()
    owners = {}
    for path in _inv_candidates(extra_roots, warnings):
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        runtime = {'path': path, 'realpath': real, 'version': None,
                   'sapi': None, 'package': _inv_owner(path, dpkg, rpm, owners),
                   'config_file': None, 'scan_dir': None}
        runtimes.append(runtime)
        trusted, reason = _inv_trusted_executable(path)
        if not trusted:
            _inv_warn(warnings, 'Skipped PHP execution for %s: %s' % (path, reason))
            continue
        response = _inv_cmd([path, '-n', '-v'], timeout=10)
        version_output = response['stdout'] + '\n' + response['stderr']
        match = re.search(r'\bPHP\s+(\d+\.\d+\.\d+(?:[-+A-Za-z0-9.]*)?)\b', version_output)
        if response['code'] != 0 or not match:
            _inv_warn(warnings, 'PHP version probe failed or returned no PHP version: ' + path)
            continue
        runtime['version'] = match.group(1)
        sapi = re.search(r'\bPHP\s+\S+\s+\(([^)]+)\)', version_output)
        if sapi:
            runtime['sapi'] = sapi.group(1)
        # -n forbids php.ini loading. Retain only explicitly allowlisted
        # information; never return phpinfo environment or request contents.
        response = _inv_cmd([path, '-n', '-i'], timeout=10)
        if response['code'] == 0:
            for line in response['stdout'].splitlines():
                match = re.match(r'^(Server API|Loaded Configuration File|Scan this dir for additional \.ini files)\s*=>\s*(.*?)\s*$', line)
                if not match:
                    continue
                key, value = match.groups()
                if key == 'Server API' and not runtime['sapi']:
                    runtime['sapi'] = value
                elif key == 'Loaded Configuration File' and value not in ('', '(none)', 'none'):
                    runtime['config_file'] = value
                elif key == 'Scan this dir for additional .ini files' and value not in ('', '(none)', 'none'):
                    runtime['scan_dir'] = value
    if runtimes:
        _inv_warn(warnings, 'PHP probes use -n and do not load php.ini; config_file/scan_dir do not establish configuration used by running services.')
    return runtimes


def _inv_service_name(name):
    return bool(re.search(r'php|fpm|httpd|apache2|lsws|litespeed|frankenphp', name, re.I))


def _inv_services(warnings):
    services = []
    systemctl = _inv_tool('systemctl', warnings)
    if not systemctl:
        _inv_warn(warnings, 'systemctl unavailable; service inventory is incomplete.')
        return services
    names = set()
    queries = [['list-unit-files', '--type=service', '--no-legend', '--no-pager'],
               ['list-units', '--all', '--type=service', '--no-legend', '--no-pager']]
    successful = False
    for query in queries:
        response = _inv_cmd([systemctl] + query)
        if response['code'] != 0:
            continue
        successful = True
        for line in response['stdout'].splitlines():
            # A failed unit can have a leading bullet; select the unit token.
            for field in line.split()[:2]:
                if field.endswith('.service') and _inv_service_name(field):
                    names.add(field)
                    break
    if not successful:
        _inv_warn(warnings, 'systemctl could not list services; service inventory is incomplete.')
    for name in sorted(names):
        response = _inv_cmd([systemctl, 'show', name, '--no-pager',
                             '--property=ActiveState,ExecStart,MainPID'])
        active = None
        executable = None
        main_pid = None
        if response['code'] == 0:
            for line in response['stdout'].splitlines():
                if line.startswith('ActiveState='):
                    active = line.split('=', 1)[1].strip()
                elif line.startswith('MainPID='):
                    value = line.split('=', 1)[1].strip()
                    main_pid = int(value) if value.isdigit() else None
                elif line.startswith('ExecStart='):
                    # Do not expose argv, which can contain credentials.
                    paths = re.findall(r'(?:^|[\s{;])path=([^\s;{}]+)', line.split('=', 1)[1])
                    executable = ', '.join(paths) if paths else None
        else:
            _inv_warn(warnings, 'Cannot inspect service state: ' + name)
        services.append({'name': name, 'active': active, 'exec_start': executable,
                         'main_pid': main_pid})
    return services


def _inv_proc_stat(pid):
    """Read only identity/lifecycle fields, never argv or environment values."""
    raw = _inv_read('/proc/%s/stat' % pid, 8192)
    if not raw:
        return None
    # comm may itself contain spaces and ')'; numeric fields follow the last ')'.
    left, right = raw.find('('), raw.rfind(')')
    if left < 1 or right <= left:
        return None
    fields = raw[right + 1:].split()
    try:
        if int(raw[:left].strip()) != int(pid) or len(fields) < 20:
            return None
        value = {'pid': int(pid), 'ppid': int(fields[1]),
                 'comm': re.sub(r'[\x00-\x1f\x7f]', '?', raw[left + 1:right])[:64],
                 'state': fields[0], 'tty_nr': int(fields[4]),
                 'start_ticks': int(fields[19])}
        if value['pid'] <= 0 or value['ppid'] < 0 or value['start_ticks'] < 0:
            return None
        return value
    except (ValueError, TypeError, IndexError):
        return None


def _inv_proc_absent(pid):
    """Only ENOENT/ESRCH confirms exit; permission failures must not hide PHP."""
    try:
        os.stat('/proc/%s' % pid)
    except (OSError, IOError) as exc:
        return exc.errno in (errno.ENOENT, errno.ESRCH)
    return False


def _inv_process_lifecycle(identity, service=None):
    """Bounded ancestry hints, not authority to kill/restart any process.

    comm is mutable by a process. These observed names help the operator find
    the owner; they never authorize an automatic action or claim its config.
    """
    result = {'origin': 'systemd' if service else 'unknown', 'ancestors': [],
              'ancestry_complete': False}
    if not identity:
        return result
    seen = set([identity['pid']])
    parent = identity['ppid']
    terminal = bool(identity.get('tty_nr'))
    for unused in range(16):
        if not parent:
            result['ancestry_complete'] = True
            break
        if parent in seen:
            break
        seen.add(parent)
        record = _inv_proc_stat(parent)
        if not record:
            break
        again = _inv_proc_stat(parent)
        if not again or (record['start_ticks'], record['ppid']) != (again['start_ticks'], again['ppid']):
            break
        result['ancestors'].append(dict((key, record[key]) for key in
                                       ('pid', 'ppid', 'comm', 'start_ticks')))
        name = record['comm'].lower()
        if result['origin'] not in ('cron', 'supervisor'):
            if name in ('cron', 'crond'):
                result['origin'] = 'cron'
            elif name in ('supervisord', 'supervisor'):
                result['origin'] = 'supervisor'
        if record.get('tty_nr') and name in ('sh', 'bash', 'dash', 'zsh', 'ksh', 'fish', 'sshd'):
            terminal = True
        parent = record['ppid']
    if result['origin'] == 'unknown' and terminal:
        result['origin'] = 'terminal'
    return result


def _inv_processes(runtimes, warnings, services=None):
    processes = []
    runtime_map = dict((item['realpath'], item['version']) for item in runtimes)
    service_pids = dict((item['main_pid'], item['name']) for item in (services or [])
                        if item.get('main_pid'))
    try:
        pids = sorted((entry for entry in os.listdir('/proc') if entry.isdigit()), key=int)
    except (IOError, OSError):
        _inv_warn(warnings, '/proc unavailable; running process inventory is incomplete.')
        return processes
    inaccessible = 0
    for pid in pids:
        if int(pid) == os.getpid():
            # The Python inspector is not a PHP runtime, regardless of a
            # wrapper/script name containing 'php'. Do not exclude ancestors.
            continue
        prefix = '/proc/' + pid
        comm = (_inv_read(prefix + '/comm', 4096) or '').strip()
        try:
            exe = os.readlink(prefix + '/exe')
        except (IOError, OSError):
            exe = None
        if not (_inv_service_name(comm) or (exe and _inv_service_name(os.path.basename(exe)))):
            continue
        identity = _inv_proc_stat(pid)
        if identity is None and _inv_proc_absent(pid):
            continue
        deleted = bool(exe and exe.endswith(' (deleted)'))
        clean_exe = exe[:-10] if deleted else exe
        cgroup = _inv_read(prefix + '/cgroup', 16384) or ''
        in_container = bool(re.search(r'(?:docker|libpod|kubepods|containerd|lxc)(?:[-/.]|$)', cgroup))
        units = re.findall(r'(?:^|/)([^/\n]+\.service)(?:/|$)', cgroup, re.M)
        service = units[-1] if units else service_pids.get(int(pid))
        version = None
        if clean_exe and not deleted:
            try:
                running = os.stat(prefix + '/exe')
                installed = os.stat(clean_exe)
                if (running.st_dev, running.st_ino) == (installed.st_dev, installed.st_ino):
                    version = runtime_map.get(os.path.realpath(clean_exe))
            except (IOError, OSError):
                pass
        lifecycle = _inv_process_lifecycle(identity, service)
        if identity:
            current = _inv_proc_stat(pid)
            if current is None and _inv_proc_absent(pid):
                continue
            if current and identity['start_ticks'] != current['start_ticks']:
                _inv_warn(warnings, 'Process PID %s was reused during inspection; process inventory is incomplete, rerun inspection.' % pid)
                continue
            if current and identity['ppid'] != current['ppid']:
                # Reparenting means the ancestry hint no longer describes the
                # current owner. Keep the live runtime, without stale hints.
                identity = current
                lifecycle = {'origin': 'systemd' if service else 'unknown',
                             'ancestors': [], 'ancestry_complete': False}
        if exe is None:
            inaccessible += 1
        if deleted:
            _inv_warn(warnings, 'Process %s uses a deleted executable; its loaded version is unknown: %s' % (pid, clean_exe))
        process = {'pid': int(pid), 'exe': exe, 'deleted': deleted,
                   'comm': comm, 'service': service, 'version': version,
                   'container': in_container, 'lifecycle': lifecycle}
        if identity:
            process.update(start_ticks=identity['start_ticks'], ppid=identity['ppid'])
            parents = lifecycle['ancestors']
            process['parent_comm'] = parents[0]['comm'] if parents else None
        processes.append(process)
    if inaccessible:
        _inv_warn(warnings, 'Executable access denied or process exited for %d matching processes.' % inaccessible)
    return processes


def _inv_containers(warnings):
    containers = []
    for engine in ('docker', 'podman'):
        command = _inv_tool(engine, warnings)
        if not command:
            continue
        response = _inv_cmd([command, 'ps', '--no-trunc', '--format', '{{json .}}'])
        if response['code'] != 0:
            _inv_warn(warnings, '%s container listing unavailable; container coverage is incomplete.' % engine)
            continue
        for line in response['stdout'].splitlines():
            try:
                data = json.loads(line)
            except (ValueError, TypeError):
                _inv_warn(warnings, 'Unrecognized %s ps output; container coverage is incomplete.' % engine)
                continue
            if not isinstance(data, dict):
                continue
            name = data.get('Names') or data.get('Name')
            if isinstance(name, list):
                name = ', '.join(_inv_text(item) for item in name)
            containers.append({'engine': engine,
                               'id': data.get('ID') or data.get('Id') or data.get('id'),
                               'image': data.get('Image') or data.get('ImageName'),
                               'name': name,
                               'status': data.get('Status') or data.get('State')})
        _inv_warn(warnings, '%s ps only lists the current engine/context; PHP inside containers, stopped containers and other users/rootless engines is not covered.' % engine)
    return containers


def collect_inventory(extra_roots=None):
    """Collect installed/on-disk/running evidence without changing the host."""
    warnings = []
    manager, packages, dpkg, rpm = _inv_packages(warnings)
    runtimes = _inv_runtimes(extra_roots, warnings, dpkg, rpm)
    services = _inv_services(warnings)
    processes = _inv_processes(runtimes, warnings, services)
    containers = _inv_containers(warnings)
    result = {'os': _inv_os(), 'package_manager': manager,
              'packages': packages, 'runtimes': runtimes, 'services': services,
              'processes': processes, 'containers': containers, 'warnings': warnings}
    result['package_manager_capabilities'] = manager_capabilities(result)
    return result
