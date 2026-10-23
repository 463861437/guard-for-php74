# -*- coding: utf-8 -*-
"""Conservative native RPM backend; Python 2.7 / 3.6 compatible.

Standalone system-interpreter worker avoids importing distro modules into a
non-system Python. No repository/stream/AL2023 release selection is changed.
"""
import json
import os
import re
import shutil
import stat
import sys
import tempfile

RPM_LOCK_WAIT_SECONDS = 120


class PackageManagerLockTimeout(RuntimeError):
    """A native package-manager lock stayed busy; no transaction was retried."""
    def __init__(self, message, lock=None):
        RuntimeError.__init__(self, message)
        self.error_kind = 'package_manager_lock_timeout'
        self.lock = dict(lock or {})


_RPM_WORKER = r'''
from __future__ import print_function
import json, os, re, sys, time

def text(value):
    try: return unicode(value)
    except NameError: return str(value)

class NativeLockTimeout(RuntimeError):
    def __init__(self, message, lock):
        RuntimeError.__init__(self, message)
        self.lock = lock

def lock_time():
    # Python 2.7 lacks time.monotonic. Linux os.times elapsed real time is
    # independent of wall-clock adjustments, unlike time.time.
    monotonic = getattr(time, 'monotonic', None)
    return monotonic() if monotonic else os.times()[4]

def yum_acquire_lock(base, wait_seconds):
    import yum, yum.constants
    try: integer_types = (int, long)
    except NameError: integer_types = (int,)
    if (isinstance(wait_seconds, bool) or not isinstance(wait_seconds, integer_types) or
            wait_seconds < 0 or wait_seconds > 3600):
        raise RuntimeError('lock_wait must be a non-negative integer no greater than 3600')
    started = lock_time()
    deadline = started + wait_seconds
    while True:
        try:
            base.doLock()
            return
        except yum.Errors.LockError as exc:
            pid = getattr(exc, 'pid', None)
            # errno=0 specifically means another live process owns the YUM
            # lock. Permission, malformed state and other failures are not busy.
            if (getattr(exc, 'errno', None) != 0 or isinstance(pid, bool) or
                    not isinstance(pid, integer_types) or pid <= 0):
                raise
            remaining = deadline - lock_time()
            if remaining <= 0:
                path = os.path.normpath(base.conf.installroot + '/' + yum.constants.YUM_PID_FILE)
                detail = dict(backend='yum', path=path, pid=pid,
                              wait_seconds=wait_seconds,
                              waited_seconds=round(max(0, lock_time() - started), 3))
                raise NativeLockTimeout(
                    'YUM package-manager lock %s is held by PID %s; wait limit %s seconds exceeded' %
                    (path, pid, wait_seconds), detail)
            time.sleep(min(1.0, remaining))

def evr(pkg):
    epoch = text(pkg.epoch or '0')
    vr = text(pkg.version) + '-' + text(pkg.release)
    return (epoch + ':' if epoch != '0' else '') + vr

def source(pkg):
    value = text(getattr(pkg, 'sourcerpm', '') or '')
    return re.sub(r'-[^-]+-[^-]+\.(?:src|nosrc)\.rpm$', '', value)

def split_evr(value):
    value = text(value)
    if ':' in value: epoch, value = value.split(':', 1)
    else: epoch = '0'
    version, release = value.rsplit('-', 1)
    if not epoch.isdigit() or not version or not release:
        raise RuntimeError('Invalid RPM EVR')
    return epoch, version, release

def equal_evr(a, b):
    import rpm
    return rpm.labelCompare(split_evr(a), split_evr(b)) == 0

def package_record(pkg):
    return dict(version=evr(pkg), upstream=text(pkg.version), source=source(pkg),
                arch=text(pkg.arch), repo=text(pkg.repoid),
                vendor=text(getattr(pkg, 'vendor', '') or ''), trusted=True,
                source_version=text(pkg.version) + '-' + text(pkg.release), official_origin=False)

def branch(value):
    match = re.match(r'^(\d+)\.(\d+)\.', value)
    if not match: raise RuntimeError('Cannot verify package minor branch: ' + value)
    return match.group(1), match.group(2)

def prepare(updates):
    import rpm
    desired = {}
    if not updates: raise RuntimeError('Empty RPM transaction is not an upgrade')
    for item in updates:
        for key in ('name', 'version', 'arch', 'old_version', 'source'):
            if not item.get(key): raise RuntimeError('Missing transaction field: ' + key)
        key = (item['name'], item['arch'])
        if key in desired: raise RuntimeError('Duplicate package in transaction')
        old = split_evr(item['old_version'])
        new = split_evr(item['version'])
        if rpm.labelCompare(new, old) <= 0:
            raise RuntimeError('Only strict upgrades are allowed: ' + item['name'])
        if branch(old[1]) != branch(new[1]):
            raise RuntimeError('Cross-minor package upgrade blocked: ' + item['name'])
        desired[key] = item
    return desired

def verify_existing(items, desired):
    found = {}
    for pkg in items:
        key = (text(pkg.name), text(pkg.arch))
        if key not in desired: continue
        if key in found: raise RuntimeError('Multiple installed EVRs for ' + key[0])
        expect = desired[key]
        if not equal_evr(evr(pkg), expect['old_version']) or source(pkg) != expect['source']:
            raise RuntimeError('Installed package changed or source mismatch: ' + key[0])
        found[key] = pkg
    if set(found) != set(desired): raise RuntimeError('Requested packages are not all installed')
    return found

def choose(candidates, item, repo_lookup):
    hits = []
    for pkg in candidates:
        if text(pkg.name) != item['name'] or text(pkg.arch) != item['arch']: continue
        if not equal_evr(evr(pkg), item['version']) or source(pkg) != item['source']: continue
        if item.get('repo') and text(pkg.repoid) != item['repo']: continue
        repo = repo_lookup(pkg.repoid)
        if not bool(repo.gpgcheck):
            raise RuntimeError('Repository package GPG verification is disabled: ' + text(pkg.repoid))
        hits.append(pkg)
    if len(hits) != 1:
        raise RuntimeError('Exact signed-repository candidate is missing or ambiguous: ' + item['name'])
    return hits[0]

def validate_changes(rows, desired):
    # Each upgrade must have exactly one incoming and one outgoing package.
    seen_new, seen_old, changes = set(), set(), []
    for action, pkg in rows:
        key = (text(pkg.name), text(pkg.arch))
        if key not in desired: raise RuntimeError('Unplanned dependency change: ' + key[0])
        item = desired[key]
        if source(pkg) != item['source']: raise RuntimeError('Transaction source changed: ' + key[0])
        if action == 'upgrade':
            if key in seen_new or not equal_evr(evr(pkg), item['version']):
                raise RuntimeError('Unexpected incoming version: ' + key[0])
            seen_new.add(key)
            changes.append(dict(name=key[0], arch=key[1], old_version=item['old_version'],
                                version=evr(pkg), source=source(pkg), repo=text(pkg.repoid), action='upgrade'))
        elif action == 'upgraded':
            if key in seen_old or not equal_evr(evr(pkg), item['old_version']):
                raise RuntimeError('Unexpected outgoing version: ' + key[0])
            seen_old.add(key)
        else:
            raise RuntimeError('Install/remove/downgrade/reinstall/obsoletes action blocked: ' + key[0])
    if seen_new != set(desired) or seen_old != set(desired):
        raise RuntimeError('Solver did not produce every exact requested upgrade')
    return sorted(changes, key=lambda row: (row['name'], row['arch']))

def verify_after(desired):
    # Read a fresh RPM transaction/database, not package-manager cached objects.
    import rpm
    ts = rpm.TransactionSet('/')
    for key, item in desired.items():
        headers = [h for h in ts.dbMatch('name', key[0]) if text(h['arch']) == key[1]]
        if len(headers) != 1: raise RuntimeError('Post-transaction package count mismatch: ' + key[0])
        h = headers[0]
        version = (text(h['epoch'] or 0) + ':' + text(h['version']) + '-' + text(h['release']))
        if not equal_evr(version, item['version']):
            raise RuntimeError('Post-transaction RPM version mismatch: ' + key[0])

def dnf_setup():
    import dnf
    base = dnf.Base()
    base.conf.read()
    # Match installed configuration variables, especially AL2023 releasever.
    substitutions = base.conf.substitutions
    substitutions.update_from_etc(base.conf.installroot, varsdir=base.conf.varsdir)
    base.conf.exit_on_lock = True
    base.init_plugins()
    if hasattr(base, 'pre_configure_plugins'): base.pre_configure_plugins()
    base.read_all_repos()
    base.configure_plugins()
    enabled = list(base.repos.iter_enabled())
    if not enabled: raise RuntimeError('No enabled repositories')
    for repo in enabled:
        # Fail instead of silently skipping a broken source; do not change sources.
        repo.skip_if_unavailable = False
        repo.metadata_expire = 0
    return base

def dnf_run(request):
    import dnf, dnf.lock, dnf.transaction
    base = dnf_setup()
    try:
        if request['operation'] == 'candidates':
            base.fill_sack(load_system_repo=True, load_available_repos=True)
            result, available = {}, {}
            provenance_host = rp_host() if 'rp_host' in globals() else None
            for item in request['inventory']['packages']:
                hits = base.sack.query().available().filter(name=item['name'], arch=item['arch'])
                packages = [p for p in hits if bool(base.repos[p.repoid].gpgcheck)]
                available.setdefault(item['name'], []).extend(packages)
            if provenance_host:
                result = rp_candidate_map(base, request['inventory'], available, provenance_host)
            else:
                result = dict((name, [package_record(p) for p in packages])
                              for name, packages in available.items())
            return dict(ok=True, candidates=result)
        desired = prepare(request['updates'])
        # DNF do_transaction creates another ProcessLock for this path. Reuse the
        # same native reentrant object so nested release cannot drop our lock
        # between solve/validation/download/RPM execution. Unsupported API fails.
        builder = dnf.lock.build_rpmdb_lock
        lock = builder(base.conf.persistdir, True)
        if not hasattr(lock, 'count') or not hasattr(lock, '__enter__'):
            raise RuntimeError('DNF lock API is unsupported; execution blocked')
        def same_lock(persistdir, exit_on_lock):
            if persistdir != base.conf.persistdir:
                raise RuntimeError('Unexpected DNF lock directory')
            return lock
        dnf.lock.build_rpmdb_lock = same_lock
        try:
            with lock:
                base.fill_sack(load_system_repo=True, load_available_repos=True)
                verify_existing(base.sack.query().installed(), desired)
                selected = []
                for item in request['updates']:
                    query = base.sack.query().available().filter(name=item['name'], arch=item['arch'])
                    pkg = choose(query, item, lambda name: base.repos[name])
                    selected.append(pkg)
                    base.package_upgrade(pkg)
                if 'rp_revalidate_selected' in globals():
                    rp_revalidate_selected(base, selected, desired)
                base.resolve(allow_erasing=False)
                def rows():
                    for ti in base.transaction:
                        if ti.action == dnf.transaction.PKG_UPGRADE: action = 'upgrade'
                        elif ti.action == dnf.transaction.PKG_UPGRADED: action = 'upgraded'
                        else: action = 'forbidden'
                        yield action, ti.pkg
                changes = validate_changes(rows(), desired)
                if request.get('execute'):
                    if os.geteuid() != 0: raise RuntimeError('Root is required for RPM execution')
                    base.download_packages(list(base.transaction.install_set))
                    for pkg in base.transaction.install_set:
                        if not bool(base.repos[pkg.repoid].gpgcheck):
                            raise RuntimeError('GPG policy changed')
                        code, message = base.package_signature_check(pkg)
                        if code != 0: raise RuntimeError('RPM signature validation failed: ' + text(message))
                    validate_changes(rows(), desired)
                    if 'rp_revalidate_selected' in globals():
                        rp_revalidate_selected(base, selected, desired)
                    base.do_transaction()
                    verify_after(desired)
                return dict(ok=True, changes=changes, error=None, executed=bool(request.get('execute')))
        finally:
            dnf.lock.build_rpmdb_lock = builder
    finally:
        base.close()

def yum_run(request):
    import yum, yum.constants, yum.misc
    desired = prepare(request['updates']) if request['operation'] != 'candidates' else None
    class GuardYum(yum.YumBase):
        def runTransaction(self, cb):
            validate_changes(yum_rows(self), desired)
            result = yum.YumBase.runTransaction(self, cb)
            if getattr(result, 'return_code', None) != 0:
                raise RuntimeError('YUM transaction returned an error; inspect RPM state')
            return result
    def yum_rows(base):
        for ti in base.tsInfo.getMembers():
            if ti.output_state == yum.constants.TS_UPDATE: action = 'upgrade'
            elif ti.output_state == yum.constants.TS_UPDATED: action = 'upgraded'
            else: action = 'forbidden'
            yield action, ti.po
    base = GuardYum()
    locked = False
    try:
        base.preconf.init_plugins = True
        base.preconf.debuglevel = 0
        base.preconf.errorlevel = 0
        config = base.conf
        config.skip_broken = False
        yum_acquire_lock(base, request.get('lock_wait', 120))
        locked = bool(getattr(base, '_lockfile', None))
        if not locked: raise RuntimeError('YUM could not acquire its native lock')
        enabled = base.repos.listEnabled()
        if not enabled: raise RuntimeError('No enabled repositories')
        for repo in enabled:
            repo.skip_if_unavailable = False
            repo.metadata_expire = 0
        if request['operation'] == 'candidates':
            result = {}
            for item in request['inventory']['packages']:
                hits = base.pkgSack.searchNevra(name=item['name'], arch=item['arch'])
                result.setdefault(item['name'], []).extend(package_record(p) for p in hits
                    if bool(base.repos.getRepo(p.repoid).gpgcheck))
            return dict(ok=True, candidates=result)
        if yum.misc.find_unfinished_transactions(yumlibpath=config.persistdir):
            raise RuntimeError('An unfinished YUM transaction must be resolved first')
        verify_existing(base.rpmdb.returnPackages(), desired)
        for item in request['updates']:
            hits = base.pkgSack.searchNevra(name=item['name'], arch=item['arch'])
            pkg = choose(hits, item, base.repos.getRepo)
            base.update(po=pkg, update_to=True)
        code, messages = base.buildTransaction()
        if code != 2: raise RuntimeError('YUM did not resolve an upgrade: ' + text(messages))
        changes = validate_changes(yum_rows(base), desired)
        if request.get('execute'):
            if os.geteuid() != 0: raise RuntimeError('Root is required for RPM execution')
            packages = [ti.po for ti in base.tsInfo.getMembers()
                        if ti.output_state == yum.constants.TS_UPDATE]
            problems = base.downloadPkgs(packages)
            if problems: raise RuntimeError('RPM download failed: ' + text(problems))
            for pkg in packages:
                if not bool(base.repos.getRepo(pkg.repoid).gpgcheck): raise RuntimeError('GPG policy changed')
                code, message = base.sigCheckPkg(pkg)
                if code != 0: raise RuntimeError('RPM signature validation failed: ' + text(message))
            validate_changes(yum_rows(base), desired)
            # Native path repeats signature check, performs RPM test, and runs
            # the guarded runTransaction. No key import is automatically accepted.
            base.processTransaction()
            verify_after(desired)
        return dict(ok=True, changes=changes, error=None, executed=bool(request.get('execute')))
    finally:
        try:
            try:
                base.close()
            finally:
                base.closeRpmDB()
        finally:
            if locked: base.doUnlock()

def main():
    request_path, response_path = sys.argv[1:3]
    try:
        with open(request_path) as handle: request = json.load(handle)
        result = dnf_run(request) if request['backend'] == 'dnf' else yum_run(request)
    except NativeLockTimeout as exc:
        result = dict(ok=False, changes=[], error=text(exc), executed=False,
                      error_kind='package_manager_lock_timeout', lock=exc.lock)
    except Exception as exc:
        result = dict(ok=False, changes=[], error=text(exc), executed=False)
    with open(response_path, 'w') as handle: json.dump(result, handle)

if __name__ == '__main__': main()
'''

# The self-contained release embeds the independently reviewed vendor keys and
# verifier. Importing this backend alone keeps its original conservative behavior
# (no vendor proof is fabricated when the optional verifier is not supplied).
if '_RPM_PROVENANCE_WORKER' in globals() and 'RP_REMI_POLICY' in globals():
    _RPM_WORKER = _RPM_WORKER.replace('import json, os, re, sys, time\n',
        'import json, os, re, sys, time\nRP_REMI_POLICY = ' + repr(RP_REMI_POLICY) + '\n' +
        _RPM_PROVENANCE_WORKER + '\n', 1)

_rpm_selected_backend = None


def _rpm_system_backend(preferred=None):
    global _rpm_selected_backend
    if _rpm_selected_backend is not None:
        return _rpm_selected_backend
    engines = ['yum', 'dnf'] if preferred == 'yum' else ['dnf', 'yum']
    paths = ['/usr/libexec/platform-python', '/usr/bin/python3',
             '/usr/bin/python2.7', '/usr/bin/python2', '/usr/bin/python']
    for engine in engines:
        for path in paths:
            if not os.path.isfile(path) or not os.access(path, os.X_OK):
                continue
            verifier = globals().get('_inv_trusted_executable')
            if verifier:
                trusted, unused = verifier(path)
                if not trusted:
                    continue
            else:
                info = os.stat(path)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    continue
            probe = run_cmd([path, '-E', '-s', '-c',
                             'import sys; sys.path = [p for p in sys.path if p]; import rpm; import ' + engine], timeout=15)
            if probe.get('code') == 0:
                _rpm_selected_backend = (path, engine)
                return _rpm_selected_backend
    raise RuntimeError('No supported system Python with native DNF/YUM and RPM bindings; RPM update blocked')


def _rpm_worker_call(payload, preferred=None):
    interpreter, backend = _rpm_system_backend(preferred)
    payload = dict(payload)
    payload['backend'] = backend
    payload['lock_wait'] = RPM_LOCK_WAIT_SECONDS
    directory = tempfile.mkdtemp(prefix='php-guard-rpm-')
    try:
        paths = [os.path.join(directory, name) for name in ('worker.py', 'request.json', 'response.json')]
        for path, content in [(paths[0], _RPM_WORKER),
                              (paths[1], json.dumps(payload)), (paths[2], '{}')]:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(content.encode('utf-8'))
        result = run_cmd([interpreter, '-E', '-s', paths[0], paths[1], paths[2]],
                         timeout=None if payload.get('execute') else 600 + payload['lock_wait'])
        if result.get('code') != 0:
            raise RuntimeError('Native RPM worker failed (exit %s); inspect package-manager logs; no success assumed' % result.get('code'))
        with open(paths[2]) as handle:
            answer = json.load(handle)
        if not isinstance(answer, dict) or 'ok' not in answer:
            raise RuntimeError('Invalid native RPM worker response')
        return answer
    finally:
        shutil.rmtree(directory)


def rpm_candidates(inv):
    """Return exact enabled-repository candidates, or raise on inability to inspect."""
    result = _rpm_worker_call(dict(operation='candidates', inventory=inv),
                              inv.get('package_manager'))
    if not result.get('ok'):
        if result.get('error_kind') == 'package_manager_lock_timeout':
            raise PackageManagerLockTimeout(result.get('error') or 'Package-manager lock timeout',
                                            result.get('lock'))
        raise RuntimeError(result.get('error') or 'RPM candidate query failed')
    return result.get('candidates', {})


def rpm_transaction(updates, execute=False):
    """Solve afresh, validate every native action, optionally apply under a lock."""
    try:
        return _rpm_worker_call(dict(operation='transaction', updates=updates,
                                     execute=bool(execute)))
    except Exception as exc:
        return dict(ok=False, changes=[], error=str(exc), executed=False)
