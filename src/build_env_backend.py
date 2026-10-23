# -*- coding: utf-8 -*-
"""Native AL2 build-dependency installer, composed after rpm_backend.py.

The caller supplies the requirements read from the hash-verified, pinned SRPM
plus its fixed build-tool list. This backend never expands a SPEC or runs a shell.
"""

_BUILD_ENV_WORKER_SUFFIX = r'''
ENV_REPOS = ('amzn2-core', 'amzn2extra-php7.4')
ENV_PROFILE = 'al2'
ENV_ACTIVITY = dict(changes=[], executed=False, transaction_started=False,
                    may_have_changed=False, snapshots={}, dependency_selection=[])

def env_requirements(values):
    try: string_types = (basestring,)
    except NameError: string_types = (str,)
    if not isinstance(values, list) or not values or len(values) > 300:
        raise RuntimeError('Expected a nonempty bounded list of pinned build requirements')
    checked, internal = [], []
    pattern = r'^[A-Za-z0-9_/][A-Za-z0-9_./+():,~%-]*(?:\s+(?:>=|<=|=|>|<)\s+[A-Za-z0-9_.:+~%^-]+)?$'
    for value in values:
        if (not isinstance(value, string_types) or len(value) > 300 or
                value != value.strip() or '\n' in value or '\r' in value or
                not re.match(pattern, value)):
            raise RuntimeError('Invalid or unsupported pinned build requirement: ' + text(value))
        if value.startswith('rpmlib('): internal.append(value)
        else: checked.append(value)
    if not checked: raise RuntimeError('No installable build requirements were supplied')
    return sorted(set(checked)), sorted(set(internal))

def env_protected(name):
    name = name.lower()
    # These contain build headers/tools or directory ownership, not web servers.
    if name in ('httpd-devel', 'httpd-tools', 'httpd-filesystem', 'nginx-filesystem'):
        return False
    if (re.match(r'^(?:php|pecl|lsphp|(?:rh-)?php\d)', name) or
            re.match(r'^(?:httpd|apache|nginx)(?:[0-9-]|$)', name) or name.startswith('supervisor') or
            name.startswith('mod_') or
            re.match(r'^(?:cron|cronie|crontabs)(?:-|$)', name) or name == 'at'):
        return True
    if (re.match(r'^(?:mysql|mariadb|postgresql|percona|mongodb|mongo)[a-z0-9-]*server(?:-|$)', name) or
            re.match(r'^(?:redis|valkey|memcached)(?:[0-9-]|$)', name) or
            name in ('firebird', 'couchdb', 'influxdb', 'clickhouse-server')):
        return True
    return False

def env_snapshot(packages):
    result = {}
    for pkg in packages:
        key = (text(pkg.name), text(pkg.arch))
        result.setdefault(key, []).append(evr(pkg))
    for versions in result.values(): versions.sort()
    return result

def env_read_snapshot():
    import rpm
    result = {}
    transaction = rpm.TransactionSet('/')
    for header in transaction.dbMatch():
        key = (text(header['name']), text(header['arch']))
        epoch = text(header['epoch'] or 0)
        version = text(header['version']) + '-' + text(header['release'])
        if epoch != '0': version = epoch + ':' + version
        result.setdefault(key, []).append(version)
    for versions in result.values(): versions.sort()
    return result

def env_snapshot_json(snapshot):
    return [dict(name=key[0], arch=key[1], versions=versions)
            for key, versions in sorted(snapshot.items())]

def env_rows(base):
    import yum.constants
    install_states = (yum.constants.TS_INSTALL, yum.constants.TS_TRUEINSTALL)
    for ti in base.tsInfo.getMembers():
        if ti.output_state in install_states: action = 'install'
        elif ti.output_state == yum.constants.TS_UPDATE: action = 'upgrade'
        elif ti.output_state == yum.constants.TS_UPDATED: action = 'upgraded'
        else: action = 'forbidden'
        yield action, ti.po

def env_changes(rows, before, repo_lookup):
    import rpm
    incoming, outgoing, changes = {}, {}, []
    for action, pkg in rows:
        key = (text(pkg.name), text(pkg.arch))
        if env_protected(key[0]):
            raise RuntimeError('Protected runtime/service package change blocked: ' + key[0])
        if action not in ('install', 'upgrade', 'upgraded'):
            raise RuntimeError('Remove/downgrade/obsoletes/reinstall action blocked: ' + key[0])
        if action == 'upgraded':
            if key in outgoing or before.get(key) != [evr(pkg)]:
                raise RuntimeError('Unexpected outgoing package: ' + key[0])
            outgoing[key] = evr(pkg)
            continue
        if key in incoming or key[1] not in ('x86_64', 'noarch'):
            raise RuntimeError('Duplicate or unsupported incoming package architecture: ' + key[0])
        repo = text(pkg.repoid)
        if repo not in ENV_REPOS or not bool(repo_lookup(repo).gpgcheck):
            raise RuntimeError('Build dependency is not from an allowed GPG-checked repository: ' + key[0])
        old = before.get(key, [])
        if action == 'install':
            if old: raise RuntimeError('Install would replace an existing package: ' + key[0])
            old_version = None
        else:
            if len(old) != 1 or rpm.labelCompare(split_evr(evr(pkg)), split_evr(old[0])) <= 0:
                raise RuntimeError('Only strict package upgrades are allowed: ' + key[0])
            old_version = old[0]
        incoming[key] = action
        changes.append(dict(name=key[0], arch=key[1], old_version=old_version,
                            version=evr(pkg), repo=repo, source=source(pkg), action=action))
    if set(outgoing) != set(key for key, action in incoming.items() if action == 'upgrade'):
        raise RuntimeError('Every package upgrade must have one matching outgoing package')
    return sorted(changes, key=lambda item: (item['name'], item['arch']))

def env_expected_snapshot(before, changes):
    result = dict((key, list(value)) for key, value in before.items())
    for item in changes:
        result[(item['name'], item['arch'])] = [item['version']]
    return result

def env_verify_requirements(base, requirements, expected):
    # Check the final solver package set against native versioned Provides.
    # Checking only package names would miss requirements such as curl-devel >= X.
    for requirement in requirements:
        providers = (list(base.returnInstalledPackagesByDep(requirement)) +
                     list(base.returnPackagesByDep(requirement)))
        if not any(evr(pkg) in expected.get((text(pkg.name), text(pkg.arch)), [])
                   for pkg in providers):
            raise RuntimeError('Solved transaction does not satisfy build requirement: ' + requirement)

def env_httpd_devel_provider(base, requirement, before, providers):
    # AL2 httpd-devel requires the matching httpd build. Asking YUM for the
    # newest provider can otherwise pull a web-server upgrade into a compiler
    # setup transaction. Select only from native versioned Provides results;
    # every downstream transaction/signature/snapshot check still applies.
    if ENV_PROFILE != 'al2' or requirement.split()[0] != 'httpd-devel':
        return None
    installed = [dict(name=name, arch=arch, version=version)
                 for (name, arch), versions in sorted(before.items())
                 if name == 'httpd' for version in versions]
    if not installed:
        return None
    evidence = dict(requirement=requirement, policy='installed_httpd_evr_arch',
                    installed_httpd=installed, candidate_count=len(providers),
                    matching_count=0, state='blocked')
    ENV_ACTIVITY['dependency_selection'].append(evidence)
    def blocked(message):
        evidence['reason'] = message
        ENV_ACTIVITY['error_kind'] = 'matching_httpd_devel_unavailable'
        raise RuntimeError(message)
    if len(installed) != 1 or installed[0]['arch'] != 'x86_64':
        blocked('Cannot select httpd-devel safely: expected exactly one installed '
                'x86_64 httpd build; multiple versions/architectures require review')
    current = installed[0]
    import rpm
    matching = []
    for pkg in providers:
        repo = text(pkg.repoid)
        if (text(pkg.name) == 'httpd-devel' and text(pkg.arch) == current['arch'] and
                rpm.labelCompare(split_evr(evr(pkg)), split_evr(current['version'])) == 0 and
                repo in ENV_REPOS and bool(base.repos.getRepo(repo).gpgcheck)):
            matching.append(pkg)
    evidence['matching_count'] = len(matching)
    if not matching:
        blocked('No allowed GPG-checked httpd-devel provider satisfies %s and matches '
                'installed httpd %s.%s; the web server will not be upgraded. '
                'Configure an approved repository containing the matching development '
                'package, or build on a separate matching AL2 host' %
                (requirement, current['version'], current['arch']))
    # Equivalent NEVRA providers may exist in multiple approved repositories.
    # Keep selection deterministic; expected_changes also pins this repository
    # between preview and execution. RPM signatures are checked before install.
    matching.sort(key=lambda pkg: (ENV_REPOS.index(text(pkg.repoid)), evr(pkg)))
    selected = matching[0]
    evidence.update(state='selected', selected=dict(name=text(selected.name),
                    arch=text(selected.arch), version=evr(selected), repo=text(selected.repoid)))
    return selected

def env_host_check(execute):
    import platform
    release = {}
    with open('/etc/os-release') as handle:
        for line in handle:
            if '=' in line:
                key, value = line.rstrip('\n').split('=', 1)
                release[key] = value.strip('"\'')
    if ENV_PROFILE == 'al2':
        valid = release.get('ID') == 'amzn' and release.get('VERSION_ID') == '2'
    elif ENV_PROFILE == 'remi-el7':
        valid = release.get('ID') in ('centos', 'rhel') and release.get('VERSION_ID', '').split('.')[0] == '7'
    else:
        valid = False
    if not valid or platform.machine() != 'x86_64':
        raise RuntimeError('Build-environment profile does not match the running OS/architecture: ' + ENV_PROFILE)
    if execute and os.geteuid() != 0:
        raise RuntimeError('Root is required to install build dependencies')

def env_configure_repos(base):
    global ENV_REPOS
    # Only this in-memory YumBase changes. No repository files or Extras settings
    # are written, and an absent repository is never created automatically.
    configured = base.repos.repos
    if ENV_PROFILE == 'al2':
        ENV_REPOS = ('amzn2-core', 'amzn2extra-php7.4')
    elif ENV_PROFILE == 'remi-el7':
        # Tencent Cloud's CentOS 7 base repository is named "os". It must
        # already be enabled and pass the same GPG and transaction checks.
        allowed = ('base', 'os', 'updates', 'extras', 'epel', 'remi', 'remi-safe', 'remi-php74',
                   'rhel-7-server-rpms', 'rhel-7-server-optional-rpms', 'rhel-7-server-extras-rpms')
        ENV_REPOS = tuple(sorted(text(repo.id) for repo in base.repos.listEnabled()
                                 if text(repo.id) in allowed))
        if not ENV_REPOS:
            raise RuntimeError('No approved enabled EL7 build repository; configure signed CentOS/RHEL/EPEL/Remi sources first')
    else:
        raise RuntimeError('Unsupported build environment profile')
    enabled = sorted(text(repo.id) for repo in base.repos.listEnabled())
    ENV_ACTIVITY['repositories'] = dict(enabled_before=enabled,
        selected=list(ENV_REPOS), excluded=sorted(set(enabled) - set(ENV_REPOS)))
    for name in ENV_REPOS:
        if name not in configured:
            raise RuntimeError('Required repository is not configured: ' + name)
        if not bool(configured[name].gpgcheck):
            raise RuntimeError('Required repository has GPG checking disabled: ' + name)
    base.repos.disableRepo('*')
    for name in ENV_REPOS:
        base.repos.enableRepo(name)
        repo = base.repos.getRepo(name)
        repo.skip_if_unavailable = False
        repo.metadata_expire = 0
    if set(text(repo.id) for repo in base.repos.listEnabled()) != set(ENV_REPOS):
        raise RuntimeError('Unexpected repository remained enabled')

def env_verify_signatures(base, packages):
    for pkg in packages:
        if text(pkg.repoid) not in ENV_REPOS or not bool(base.repos.getRepo(pkg.repoid).gpgcheck):
            raise RuntimeError('GPG/repository policy changed before build-dependency installation')
        code, message = base.sigCheckPkg(pkg)
        if code != 0:
            raise RuntimeError('Build-dependency RPM signature validation failed: ' + text(message))

def env_run(request):
    global ENV_PROFILE
    import yum, yum.constants, yum.misc
    ENV_PROFILE = request.get('profile', 'al2')
    if ENV_PROFILE not in ('al2', 'remi-el7'):
        raise RuntimeError('Unsupported build environment profile')
    requirements, internal = env_requirements(request.get('requirements'))
    execute = bool(request.get('execute'))
    env_host_check(execute)
    before = {}
    expected_changes = []
    packages = []
    class BuildEnvironmentYum(yum.YumBase):
        def runTransaction(self, cb):
            if env_changes(env_rows(self), before, self.repos.getRepo) != expected_changes:
                raise RuntimeError('Build-dependency solver changed before RPM execution')
            if env_read_snapshot() != before:
                raise RuntimeError('Installed package database changed before RPM execution')
            env_verify_signatures(self, packages)
            ENV_ACTIVITY['transaction_started'] = True
            ENV_ACTIVITY['may_have_changed'] = True
            result = yum.YumBase.runTransaction(self, cb)
            if getattr(result, 'return_code', None) != 0:
                raise RuntimeError('YUM dependency transaction failed; installed packages may have changed')
            return result
    base = BuildEnvironmentYum()
    locked = False
    try:
        base.preconf.init_plugins = True
        base.preconf.debuglevel = 0
        base.preconf.errorlevel = 0
        config = base.conf
        if os.path.normpath(config.installroot) != '/':
            raise RuntimeError('Build dependency installroot must be the running system')
        config.skip_broken = False
        # Missing signing keys fail at the explicit sigCheckPkg gate. No prompt,
        # --nogpgcheck, or automatic key import is used.
        config.assumeyes = False
        yum_acquire_lock(base, request.get('lock_wait', 120))
        locked = bool(getattr(base, '_lockfile', None))
        if not locked: raise RuntimeError('YUM could not acquire its native lock')
        env_configure_repos(base)
        if yum.misc.find_unfinished_transactions(yumlibpath=config.persistdir):
            raise RuntimeError('An unfinished YUM transaction must be resolved first')
        before = env_read_snapshot()
        ENV_ACTIVITY['snapshots']['before'] = env_snapshot_json(before)
        already_satisfied = []
        requested = []
        for requirement in requirements:
            if base.returnInstalledPackagesByDep(requirement):
                already_satisfied.append(requirement)
                continue
            # YumBase.install(pattern=...) falls back to version-aware Provides
            # lookup for capabilities and >= constraints; no command is shelled.
            providers = list(base.returnPackagesByDep(requirement))
            provider = env_httpd_devel_provider(base, requirement, before, providers)
            if not providers:
                ENV_ACTIVITY.update(error_kind='build_requirement_unavailable',
                                    missing_requirement=requirement)
                raise RuntimeError('No allowed-repository provider for build requirement: ' + requirement)
            if provider is None:
                base.install(pattern=requirement)
            else:
                base.install(po=provider)
            requested.append(requirement)
        if requested:
            code, messages = base.buildTransaction()
            if code not in (0, 2):
                raise RuntimeError('YUM could not solve build dependencies: ' + text(messages))
        expected_changes = env_changes(env_rows(base), before, base.repos.getRepo)
        ENV_ACTIVITY['changes'] = expected_changes
        if request.get('expected_changes') is not None and expected_changes != request['expected_changes']:
            raise RuntimeError('Build-dependency transaction differs from the previously reviewed plan')
        expected = env_expected_snapshot(before, expected_changes)
        ENV_ACTIVITY['snapshots']['expected_after'] = env_snapshot_json(expected)
        env_verify_requirements(base, requirements, expected)
        if execute and expected_changes:
            packages = [ti.po for ti in base.tsInfo.getMembers()
                        if ti.output_state in (yum.constants.TS_INSTALL, yum.constants.TS_TRUEINSTALL,
                                               yum.constants.TS_UPDATE)]
            problems = base.downloadPkgs(packages)
            if problems: raise RuntimeError('Build-dependency RPM download failed: ' + text(problems))
            env_verify_signatures(base, packages)
            base.processTransaction()
            if not ENV_ACTIVITY['transaction_started']:
                raise RuntimeError('YUM did not execute the reviewed build-dependency transaction')
            actual = env_read_snapshot()
            ENV_ACTIVITY['snapshots']['after'] = env_snapshot_json(actual)
            if actual != expected:
                raise RuntimeError('Post-install RPM snapshot differs from the reviewed dependency transaction')
            # Re-open the RPM DB before checking native Provides after install.
            base.closeRpmDB()
            missing = [req for req in requirements if not base.returnInstalledPackagesByDep(req)]
            if missing:
                raise RuntimeError('Installed build dependencies remain unsatisfied: ' + ', '.join(missing))
            ENV_ACTIVITY['executed'] = True
            ENV_ACTIVITY['may_have_changed'] = False
        elif env_read_snapshot() != before:
            raise RuntimeError('Package database changed while preparing the dependency plan')
        result = dict(ENV_ACTIVITY)
        result.update(ok=True, state='environment_ready' if execute else 'environment_plan',
                      error=None, blocked_reasons=[], requirements=requirements,
                      already_satisfied=already_satisfied, requested=requested,
                      rpm_internal_capabilities=internal, repositories=list(ENV_REPOS))
        return result
    finally:
        try:
            try: base.close()
            finally: base.closeRpmDB()
        finally:
            if locked: base.doUnlock()

def env_main():
    request_path, response_path = sys.argv[1:3]
    try:
        with open(request_path) as handle: request = json.load(handle)
        result = env_run(request)
    except Exception as exc:
        result = dict(ENV_ACTIVITY)
        result.update(ok=False, state='environment_setup_failed' if result['transaction_started'] else 'environment_blocked',
                      error=text(exc), blocked_reasons=[text(exc)])
        if result['transaction_started']:
            result['may_have_changed'] = True
            try: result['snapshots']['after'] = env_snapshot_json(env_read_snapshot())
            except Exception as snapshot_error: result['snapshot_error'] = text(snapshot_error)
        if isinstance(exc, NativeLockTimeout):
            result.update(error_kind='package_manager_lock_timeout', lock=exc.lock)
    with open(response_path, 'w') as handle: json.dump(result, handle)

if __name__ == '__main__': env_main()
'''


def build_environment_transaction(requirements, execute=False, lock_wait=120, expected_changes=None, profile='al2'):
    """Plan/apply AL2 build dependencies, never PHP deployment or service restart.

    Failure after entering RPM execution explicitly sets may_have_changed; a
    killed worker also reports uncertainty instead of claiming no changes.
    """
    directory = None
    started = False
    try:
        if profile not in ('al2', 'remi-el7'):
            raise RuntimeError('Unsupported build environment profile')
        try: integer_types = (int, long)
        except NameError: integer_types = (int,)
        if isinstance(lock_wait, bool) or not isinstance(lock_wait, integer_types) or not 0 <= lock_wait <= 3600:
            raise RuntimeError('lock_wait must be an integer between 0 and 3600')
        if execute and os.geteuid() != 0:
            raise RuntimeError('Root is required to install build dependencies')
        interpreter, backend = _rpm_system_backend('yum')
        if backend != 'yum': raise RuntimeError('This build-environment setup requires native YUM bindings')
        payload = dict(requirements=requirements, execute=bool(execute), lock_wait=lock_wait,
                       expected_changes=expected_changes, profile=profile)
        worker = _RPM_WORKER.rsplit("if __name__", 1)[0] + _BUILD_ENV_WORKER_SUFFIX
        directory = tempfile.mkdtemp(prefix='php-guard-build-env-')
        paths = [os.path.join(directory, name) for name in ('worker.py', 'request.json', 'response.json')]
        for path, content in ((paths[0], worker), (paths[1], json.dumps(payload)), (paths[2], '{}')):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as handle: handle.write(content.encode('utf-8'))
        started = True
        command = run_cmd([interpreter, '-E', '-s', paths[0], paths[1], paths[2]],
                          timeout=None if execute else 600 + lock_wait)
        if command.get('code') != 0:
            raise RuntimeError('Native build-dependency worker failed (exit %s); inspect YUM/RPM state' % command.get('code'))
        with open(paths[2]) as handle: result = json.load(handle)
        if not isinstance(result, dict) or 'ok' not in result or 'may_have_changed' not in result:
            raise RuntimeError('Invalid native build-dependency worker response')
        return result
    except Exception as exc:
        return dict(ok=False, state='environment_setup_failed' if execute and started else 'environment_blocked',
                    error=str(exc), blocked_reasons=[str(exc)], changes=[], executed=False,
                    may_have_changed=bool(execute and started))
    finally:
        if directory: shutil.rmtree(directory)
