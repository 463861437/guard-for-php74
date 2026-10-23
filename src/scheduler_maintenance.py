# -*- coding: utf-8 -*-
"""Explicit, bounded cron maintenance; never kills a scheduled job.

Concatenated after service_ops.py. Only the verified scheduler main process is
briefly frozen, so that its discovered jobs and narrow systemd scopes can be
recorded before stopping scheduling. Process identities and scope membership
remain evidence; process names alone never authorize a stop or a drain bypass.
"""
import errno
import hashlib
import os
import re
import signal
import stat
import time


_SM_NAMES = ('cron.service', 'crond.service')
_SM_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID',
                  'KillMode', 'KillSignal', 'SendSIGHUP', 'ExecStart',
                  'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost',
                  'RootDirectory', 'RootImage', 'User', 'ControlGroup')


def _sm_key(process):
    return (int(process['pid']), int(process['start_ticks']))


def _sm_error(message):
    raise ValueError(message)


def _sm_identity(pid):
    value = _inv_proc_stat(pid)
    if value is None and not _inv_proc_absent(pid):
        _sm_error('Cannot read process PID %s identity; maintenance inspection is incomplete' % pid)
    return value


def _sm_show(systemctl, name):
    result = run_cmd([systemctl, 'show', name, '--no-pager', '--all'], timeout=30)
    if result['code'] != 0:
        _sm_error('Cannot inspect scheduler unit %s' % name)
    properties = {}
    for line in as_text(result.get('stdout', '')).splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            if key in _SM_PROPERTIES:
                properties[key] = value
    # systemd 219 omits empty command arrays even with --all. Confirm each
    # empty array via a successful dedicated property query; never infer it
    # from an otherwise incomplete response.
    optional_arrays = ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost')
    for key in optional_arrays:
        if key not in properties:
            empty = run_cmd([systemctl, 'show', name, '--no-pager', '--all',
                             '--property=' + key], timeout=30)
            if empty['code'] == 0 and not as_text(empty.get('stdout', '')).strip():
                properties[key] = ''
    required = set(_SM_PROPERTIES) - set(['RootImage'])
    if not required.issubset(properties):
        _sm_error('Scheduler properties are incomplete: ' + ', '.join(sorted(required - set(properties))))
    return properties


def _sm_host_namespace(pid):
    if any(os.path.exists(path) for path in ('/.dockerenv', '/run/.containerenv', '/run/systemd/container')):
        _sm_error('Container scheduler maintenance is unsupported')
    init = _sm_identity(1)
    if not init or init.get('comm') != 'systemd':
        _sm_error('A host systemd PID 1 is required for scheduler maintenance')
    for target in ('self', str(pid)):
        for namespace in ('pid', 'user'):
            reference = os.stat('/proc/1/ns/' + namespace)
            current = os.stat('/proc/' + target + '/ns/' + namespace)
            if (reference.st_dev, reference.st_ino) != (current.st_dev, current.st_ino):
                _sm_error('Scheduler or inspector uses a separate %s namespace' % namespace)
        root = os.stat('/proc/' + target + '/root')
        host = os.stat('/')
        if (root.st_dev, root.st_ino) != (host.st_dev, host.st_ino):
            _sm_error('Scheduler or inspector uses a separate root directory')


def _sm_group(pid):
    raw = _inv_read('/proc/%s/cgroup' % pid, 65536)
    if raw is None:
        if _inv_proc_absent(pid):
            return None
        _sm_error('Cannot read process PID %s systemd cgroup' % pid)
    values = []
    for line in raw.splitlines():
        fields = line.split(':', 2)
        if len(fields) != 3:
            _sm_error('Malformed systemd cgroup record for PID %s' % pid)
        number, controllers, path = fields
        if controllers == '' and number == '0':
            values.append({'version': 2, 'relative': path,
                           'path': '/sys/fs/cgroup' + path})
        elif 'name=systemd' in controllers.split(','):
            values.append({'version': 1, 'relative': path,
                           'path': '/sys/fs/cgroup/systemd' + path})
    if len(values) != 1:
        _sm_error('Cannot identify a unique systemd cgroup for PID %s' % pid)
    group = values[0]
    relative = group['relative']
    if (not relative.startswith('/') or relative.startswith('//') or
            any(part in ('.', '..', '') for part in relative.split('/')[1:]) or
            not re.match(r'^/[A-Za-z0-9_.:@/-]+$', relative)):
        _sm_error('Unsupported systemd cgroup path for PID %s' % pid)
    return group


def _sm_scope(group, scheduler_group):
    relative = group['relative']
    if relative == scheduler_group or relative.startswith(scheduler_group + '/'):
        scope = scheduler_group
    else:
        match = re.match(r'^(/user\.slice/user-[0-9]+\.slice/session-[A-Za-z0-9_.:-]+\.scope)(?:/|$)', relative)
        if not match:
            return None
        scope = match.group(1)
    value = dict(group)
    value['relative'] = scope
    value['path'] = group['path'][:-len(relative)] + scope
    return value


def _sm_narrow_group(group, scheduler_group):
    return _sm_scope(group, scheduler_group) is not None


def _sm_group_members(group):
    """Read narrow, root-owned scopes and child cgroups; never a user slice."""
    base = group['path']
    if os.path.realpath(base) != base:
        _sm_error('Scheduler job cgroup path contains a symbolic link')
    pending = [base]
    members = set()
    while pending:
        folder = pending.pop()
        try:
            info = os.lstat(folder)
        except (OSError, IOError) as exc:
            if exc.errno in (errno.ENOENT, errno.ESRCH):
                if folder == base:
                    return None
                continue
            raise
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _sm_error('Job cgroup is not a root-owned, protected directory')
        with open(os.path.join(folder, 'cgroup.procs'), 'rb') as handle:
            raw = as_text(handle.read(1024 * 1024 + 1))
        if len(raw) > 1024 * 1024:
            _sm_error('Job cgroup membership exceeds the inspection limit')
        for value in raw.split():
            if not value.isdigit() or int(value) <= 0:
                _sm_error('Malformed job cgroup membership')
            members.add(int(value))
        for entry in os.listdir(folder):
            path = os.path.join(folder, entry)
            try:
                child = os.lstat(path)
            except (OSError, IOError) as exc:
                if exc.errno in (errno.ENOENT, errno.ESRCH):
                    continue
                raise
            if stat.S_ISLNK(child.st_mode):
                _sm_error('Symbolic link found in job cgroup')
            if stat.S_ISDIR(child.st_mode):
                pending.append(path)
    return members


def _sm_exec_path(raw):
    # systemd may retain $CRONDARGS/$EXTRA_OPTS in its display. Arguments are
    # neither reconstructed nor executed here; the running inode is checked.
    if not raw or len(raw) > 16384 or raw.count('{') != 1 or raw.count('}') != 1:
        _sm_error('Scheduler ExecStart must contain one inspectable command')
    paths = re.findall(r'(?:^|[\s{;])path=([^\s;{}]+)', raw)
    if len(paths) != 1 or raw.count('argv[]=') != 1:
        _sm_error('Scheduler ExecStart executable is ambiguous')
    return paths[0]


def _sm_validate(systemctl, name, recovery=False):
    if name not in _SM_NAMES:
        _sm_error('Only exact cron.service or crond.service names may be paused')
    properties = _sm_show(systemctl, name)
    if properties['Id'] != name or properties['LoadState'] != 'loaded':
        _sm_error('Scheduler unit identity is not an exact loaded match')
    if properties['ActiveState'] not in (('active', 'inactive', 'failed', 'activating', 'deactivating') if recovery else ('active', 'inactive')):
        _sm_error('Scheduler unit is in a transitional or failed state')
    if properties['KillMode'] != 'process' or properties['KillSignal'] not in ('15', 'SIGTERM'):
        _sm_error('Scheduler requires KillMode=process and KillSignal=SIGTERM to preserve jobs')
    if properties['SendSIGHUP'] not in ('no', 'false', '0'):
        _sm_error('Scheduler SendSIGHUP must be disabled to preserve jobs')
    if any(properties[key] for key in ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost')):
        _sm_error('Custom scheduler start/stop hooks require manual maintenance')
    if properties.get('RootDirectory') or properties.get('RootImage'):
        _sm_error('Scheduler uses a separate root namespace')
    if properties['User'] not in ('', 'root', '0'):
        _sm_error('Scheduler main process must run as root')
    executable = _sm_exec_path(properties['ExecStart'])
    expected = '/usr/sbin/' + name[:-8]
    if executable != expected:
        _sm_error('Scheduler ExecStart must be the direct standard cron/crond executable')
    trusted, reason = _inv_trusted_executable(executable)
    if not trusted:
        _sm_error('Scheduler executable or parent directories are untrusted')
    if not properties['MainPID'].isdigit():
        _sm_error('Scheduler MainPID is malformed')
    pid = int(properties['MainPID'])
    safe_properties = dict(properties)
    safe_properties.pop('ExecStart')
    safe_properties['ExecStartSHA256'] = hashlib.sha256(
        as_text(properties['ExecStart']).encode('utf-8')).hexdigest()
    result = {'name': name, 'active': properties['ActiveState'] == 'active',
              'executable': executable, 'properties': safe_properties,
              'main': None, 'group': None, 'job_groups': []}
    if pid == 0:
        if result['active']:
            _sm_error('Active scheduler has no MainPID')
        return result
    if not result['active'] and properties['ActiveState'] in ('inactive', 'failed'):
        _sm_error('Inactive scheduler still has a MainPID')
    identity = _sm_identity(pid)
    if (not identity or identity['comm'] != name[:-8] or identity.get('state') in ('T', 't', 'Z', 'X') or
            os.stat('/proc/%s' % pid).st_uid != 0):
        _sm_error('Scheduler MainPID identity or ownership could not be verified')
    _sm_host_namespace(pid)
    running = os.stat('/proc/%s/exe' % pid)
    installed = os.stat(executable)
    if (running.st_dev, running.st_ino) != (installed.st_dev, installed.st_ino):
        _sm_error('Scheduler MainPID is not running its trusted ExecStart executable')
    if os.readlink('/proc/%s/exe' % pid).endswith(' (deleted)'):
        _sm_error('Scheduler is running a deleted executable')
    group = _sm_group(pid)
    if (not group or group['relative'] != properties['ControlGroup'] or
            not re.match(r'^/system\.slice/(?:cron|crond)\.service$', group['relative'])):
        _sm_error('Scheduler is not in its exact standard systemd control group')
    members = _sm_group_members(group)
    if members is None or pid not in members:
        _sm_error('Scheduler control-group membership cannot be verified')
    again = _sm_identity(pid)
    if not again or _sm_key(again) != _sm_key(identity):
        _sm_error('Scheduler MainPID changed while being inspected')
    result.update(main=identity, group=group)
    return result


def _sm_descends(process, main):
    """Re-read the live ancestry, rather than trusting inventory hints."""
    current = _sm_identity(process['pid'])
    if not current:
        return False
    if process.get('start_ticks') is None or _sm_key(current) != _sm_key(process):
        _sm_error('PHP process identity changed before scheduler planning')
    seen = set()
    for unused in range(256):
        if _sm_key(current) == _sm_key(main):
            return True
        if current['pid'] in seen or current['ppid'] <= 1:
            return False
        seen.add(current['pid'])
        parent = _sm_identity(current['ppid'])
        again = _sm_identity(current['pid'])
        if not again or _sm_key(again) != _sm_key(current) or again['ppid'] != current['ppid']:
            _sm_error('Process ancestry changed during scheduler planning')
        if not parent:
            return False
        current = parent
    _sm_error('Process ancestry exceeds the scheduler inspection limit')


def sm_plan(inv, requested):
    """Read-only plan. covered_processes only contains exact live descendants."""
    result = {'ok': True, 'blockers': [], 'services': [],
              'covered_processes': [], 'pending_pids': [], 'read_only': True}
    requested = list(requested or [])
    if not requested:
        return result
    try:
        if len(set(requested)) != len(requested):
            _sm_error('Duplicate scheduler selections are not allowed')
        systemctl = _inv_tool('systemctl', [])
        if not systemctl:
            _sm_error('Trusted systemctl is unavailable')
        result['systemctl'] = systemctl
        for name in requested:
            service = _sm_validate(systemctl, name)
            result['services'].append(service)
            if not service['active']:
                continue
            for process in inv.get('processes', []):
                if process.get('container') or not _svc_php_process(process):
                    continue
                if _sm_descends(process, service['main']):
                    group = _sm_group(process['pid'])
                    if not group or not _sm_narrow_group(group, service['group']['relative']):
                        _sm_error('PHP job PID %s lacks a narrow verifiable scheduler/session cgroup' % process['pid'])
                    group = _sm_scope(group, service['group']['relative'])
                    members = _sm_group_members(group)
                    if members is None or process['pid'] not in members:
                        _sm_error('PHP job PID %s cgroup membership cannot be verified' % process['pid'])
                    if group not in service.setdefault('job_groups', []):
                        service['job_groups'].append(group)
                    result['covered_processes'].append({'pid': process['pid'],
                                                       'start_ticks': process['start_ticks'],
                                                       'scheduler': name})
                    result['pending_pids'].append(process['pid'])
    except (ValueError, IOError, OSError) as exc:
        result['ok'] = False
        result['blockers'].append({'reason': as_text(exc)})
        result['covered_processes'] = []
        result['pending_pids'] = []
    return result


def _sm_snapshot():
    records = {}
    for value in os.listdir('/proc'):
        if value.isdigit():
            identity = _sm_identity(int(value))
            if identity:
                records[identity['pid']] = identity
    return records


def _sm_signal(identity, sig):
    current = _sm_identity(identity['pid'])
    if not current:
        return False
    if _sm_key(current) != _sm_key(identity):
        _sm_error('Scheduler PID was reused; refusing to signal it')
    os.kill(identity['pid'], sig)
    return True


def _sm_clock():
    return getattr(time, 'monotonic', time.time)()


def _sm_save(state):
    if state.get('report_path'):
        write_json(state['report_path'], state)


def _sm_capture(service, snapshot, tracked, groups):
    main = service['main']
    included = set([main['pid']])
    for process in list(tracked.values()):
        live = snapshot.get(process['pid'])
        if live and _sm_key(live) == _sm_key(process):
            included.add(process['pid'])
    changed = True
    while changed:
        changed = False
        for pid, process in snapshot.items():
            if pid not in included and process['ppid'] in included:
                included.add(pid)
                changed = True
    for pid in sorted(included):
        if pid == main['pid']:
            continue
        process = snapshot.get(pid)
        if not process:
            continue
        group = _sm_group(pid)
        if not group:
            continue
        if not _sm_narrow_group(group, service['group']['relative']):
            _sm_error('Scheduled descendant PID %s left a verifiable scheduler/session scope' % pid)
        group = _sm_scope(group, service['group']['relative'])
        tracked[_sm_key(process)] = process
        groups[group['path']] = group
    groups[service['group']['path']] = service['group']
    # A complete narrow scope also covers a shell's grandchildren if the
    # shell exits between /proc scans and its children are reparented to init.
    for group in list(groups.values()):
        members = _sm_group_members(group)
        if members is None:
            # A vanished scope is normal only after every recorded member
            # exited; a live escape invalidates the evidence.
            for process in list(tracked.values()):
                live = snapshot.get(process['pid'])
                if live and _sm_key(live) == _sm_key(process):
                    current_group = _sm_group(process['pid'])
                    if not current_group or current_group['path'] != group['path']:
                        continue
                    _sm_error('A live scheduled job has an unreadable cgroup')
            continue
        for pid in sorted(members):
            if pid == main['pid']:
                continue
            process = _sm_identity(pid)
            if not process:
                continue
            actual_group = _sm_group(pid)
            if not actual_group or not (actual_group['path'] == group['path'] or
                                        actual_group['path'].startswith(group['path'] + '/')):
                _sm_error('Job cgroup membership changed during inspection')
            tracked[_sm_key(process)] = process
    # Keep identity records even if their parent exited. A missing/reused PID
    # means that exact job exited, not permission to signal its replacement.
    alive = []
    for process in list(tracked.values()):
        current = _sm_identity(process['pid'])
        if current and _sm_key(current) == _sm_key(process) and current.get('state') != 'Z':
            group = _sm_group(process['pid'])
            if not group or not any(group['path'] == path or group['path'].startswith(path + '/')
                                    for path in groups):
                _sm_error('Tracked scheduled job PID %s escaped its recorded scope' % process['pid'])
            alive.append(current)
    return alive


def sm_enter(plan, scan_roots, timeout, report_path):
    """Stop requested schedulers and naturally drain discovered jobs/scopes.

    Failures restore scheduling here. Call sm_exit in the caller's finally as
    well; it is idempotent. A successful result leaves scheduling paused only
    for the caller's guarded installation window.
    """
    state = {'ok': False, 'entered': False, 'stopped': [], 'frozen': [],
             'errors': [], 'drain': [], 'report_path': report_path,
             'systemctl': plan.get('systemctl'), 'recovery': None}
    try:
        if not plan.get('ok'):
            _sm_error('Scheduler plan contains blockers')
        if isinstance(timeout, bool) or int(timeout) < 0 or int(timeout) > 3600:
            _sm_error('Scheduler drain timeout must be between 0 and 3600 seconds')
        timeout = int(timeout)
        for original in plan.get('services', []):
            current = _sm_validate(state['systemctl'], original['name'])
            if current['active'] != original['active'] or (current['active'] and
                    (_sm_key(current['main']) != _sm_key(original['main']) or
                     current['properties'] != original['properties'])):
                _sm_error('Scheduler changed since its plan; rerun inspection')
            if not current['active']:
                continue
            main = current['main']
            frozen_record = dict(main)
            frozen_record['freeze_requested'] = False
            frozen_record['recovery_instruction'] = (
                'Verify /proc/%s/stat start_ticks is %s before kill -CONT %s; never signal a reused PID'
                % (main['pid'], main['start_ticks'], main['pid']))
            state['frozen'].append(frozen_record)
            _sm_save(state)
            frozen_record['freeze_requested'] = True
            if not _sm_signal(main, signal.SIGSTOP):
                _sm_error('Scheduler exited before it could be frozen')
            frozen_deadline = _sm_clock() + 5
            while True:
                identity = _sm_identity(main['pid'])
                if not identity or _sm_key(identity) != _sm_key(main):
                    _sm_error('Scheduler identity changed while freezing')
                if identity['state'] == 'T':
                    break
                if _sm_clock() >= frozen_deadline:
                    _sm_error('Scheduler did not enter a stopped state')
                time.sleep(0.05)
            tracked = {}
            groups = dict((item['path'], item) for item in original.get('job_groups', []))
            # Repeat while the scheduler is frozen. Children may keep working;
            # exact cgroup scopes close the parent-exit/reparenting gap.
            stable = None
            for unused in range(5):
                snapshot = _sm_snapshot()
                alive = _sm_capture(current, snapshot, tracked, groups)
                identities = sorted(_sm_key(process) for process in alive)
                if identities == stable:
                    break
                stable = identities
            else:
                _sm_error('Scheduled job membership did not stabilize; retry in a quieter window')
            entry = {'name': current['name'], 'main': main, 'active_before': True,
                     'restore_required': True, 'stop_requested': False,
                     'recovery_command': 'systemctl start ' + current['name']}
            state['stopped'].append(entry)
            _sm_save(state)
            # Mark before the request, since systemctl can submit a stop job
            # even if the client subsequently times out or is interrupted.
            entry['stop_requested'] = True
            _sm_save(state)
            response = run_cmd([state['systemctl'], 'stop', '--no-block', current['name']], timeout=30)
            # systemd sends SIGCONT immediately after its KillSignal. Do not
            # thaw here: --no-block may return before TERM was delivered,
            # allowing another cron fork in that gap. Failure recovery thaws.
            if response['code'] != 0:
                _sm_error('Scheduler stop request failed for ' + current['name'])
            deadline = _sm_clock() + timeout
            while True:
                properties = _sm_show(state['systemctl'], current['name'])
                identity = _sm_identity(main['pid'])
                scheduler_exited = not identity or _sm_key(identity) != _sm_key(main)
                if properties['Id'] != current['name'] or properties['LoadState'] != 'loaded':
                    _sm_error('Scheduler unit identity changed during drain')
                if properties['ActiveState'] == 'active' and scheduler_exited:
                    _sm_error('Scheduler unexpectedly restarted during drain')
                alive = _sm_capture(current, _sm_snapshot(), tracked, groups)
                state['drain'] = [{'pid': item['pid'], 'start_ticks': item['start_ticks'],
                                   'comm': item['comm']} for item in alive]
                if properties['ActiveState'] == 'inactive' and scheduler_exited and not alive:
                    state['frozen'].remove(frozen_record)
                    break
                if properties['ActiveState'] == 'failed':
                    _sm_error('Scheduler stop failed; scheduled jobs were not terminated by this tool')
                if _sm_clock() >= deadline:
                    _sm_error('Scheduled jobs did not finish within %s seconds; no job was killed' % timeout)
                time.sleep(min(1, max(0.05, deadline - _sm_clock())))
            entry['scopes'] = [item['relative'] for item in groups.values()]
            entry['drained_jobs'] = len(tracked)
            _sm_save(state)
        # Inventory is intentionally fresh and retains scan roots. The caller
        # still runs its full service/package preflight before installation.
        inventory = collect_inventory(scan_roots)
        for warning in inventory.get('warnings', []):
            if re.search(r'/proc|process.*(?:incomplete|reused)|executable access denied', warning, re.I):
                _sm_error('Post-drain process inventory is incomplete')
        covered = set((item['pid'], item['start_ticks']) for item in plan.get('covered_processes', []))
        for process in inventory.get('processes', []):
            if not _svc_php_process(process):
                continue
            if process.get('start_ticks') is None or not process.get('service'):
                _sm_error('Post-drain inventory contains an unmapped or unverified PHP process PID %s' % process.get('pid'))
            if _sm_key(process) in covered or process.get('service') in [x['name'] for x in plan.get('services', [])]:
                _sm_error('Post-drain inventory still contains a scheduled PHP process')
        state.update(ok=True, entered=True, inventory=inventory)
        _sm_save(state)
    except (Exception, KeyboardInterrupt) as exc:
        # The final journal write can fail after the successful state was set.
        # Recovery resumes scheduling, so never return permission to install.
        state.update(ok=False, entered=False)
        state['errors'].append(as_text(exc) or exc.__class__.__name__)
        try:
            state['recovery'] = sm_exit(state)
        except (Exception, KeyboardInterrupt) as recovery_exc:
            # Preserve the stop/freeze journal for the caller's finally retry,
            # even if an unexpected recovery or serialization failure occurs.
            state['recovery'] = {'ok': False, 'restored': [], 'errors': [
                {'reason': 'Scheduler recovery raised an exception: ' +
                 (as_text(recovery_exc) or recovery_exc.__class__.__name__)}]}
        try:
            _sm_save(state)
        except (Exception, KeyboardInterrupt) as report_exc:
            state['errors'].append('Cannot save maintenance report: ' + as_text(report_exc))
    return state


def sm_exit(state):
    """Restore only originally active schedulers for which a stop was requested."""
    result = {'ok': True, 'errors': [], 'restored': []}
    for main in list(reversed(state.get('frozen', []))):
        try:
            if main.get('freeze_requested'):
                _sm_signal(main, signal.SIGCONT)
            state['frozen'].remove(main)
        except (Exception, KeyboardInterrupt) as exc:
            result['ok'] = False
            result['errors'].append({'pid': main['pid'], 'reason': as_text(exc)})
    for entry in reversed(state.get('stopped', [])):
        if not (entry.get('active_before') and entry.get('restore_required') and entry.get('stop_requested')):
            continue
        try:
            checked = _sm_validate(state['systemctl'], entry['name'], recovery=True)
            properties = checked['properties']
            # Synchronously request start even when still active: the earlier
            # asynchronous stop may remain queued. systemd replaces/waits for
            # that job; an immediate active-state read alone is insufficient.
            response = run_cmd([state['systemctl'], 'start', entry['name']], timeout=60)
            if response['code'] != 0:
                _sm_error('Scheduler start failed; run ' + entry['recovery_command'])
            verified = _sm_validate(state['systemctl'], entry['name'])
            if not verified['active']:
                _sm_error('Scheduler recovery did not become active; run ' + entry['recovery_command'])
            entry['restore_required'] = False
            result['restored'].append(entry['name'])
        except (Exception, KeyboardInterrupt) as exc:
            result['ok'] = False
            result['errors'].append({'service': entry['name'], 'reason': as_text(exc),
                                     'recovery_command': entry['recovery_command']})
    state['recovery'] = result
    if not result['ok']:
        state['ok'] = False
    try:
        _sm_save(state)
    except (Exception, KeyboardInterrupt) as exc:
        result['ok'] = False
        state['ok'] = False
        result['errors'].append({'reason': 'Cannot save maintenance recovery report: ' + as_text(exc)})
    return result
