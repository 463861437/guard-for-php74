# -*- coding: utf-8 -*-
APT_WORKER = r'''
from __future__ import print_function
import os, sys, json, re, time
import apt, apt_pkg
import apt.progress.base

def origins(v, codename):
    trusted = any(o.trusted for o in v.origins)
    official = any(o.trusted and o.origin in ('Ubuntu','UbuntuESM','UbuntuESMApps','UbuntuESMInfra')
                  and (o.archive == codename or o.archive.startswith(codename + '-'))
                  for o in v.origins)
    return trusted, official

def origin_repo(v):
    """Return a stable description of trusted origins for plan pinning."""
    return ','.join(sorted(set(o.origin + '/' + o.archive for o in v.origins
                                if o.trusted)))

def origin_records(v):
    """Keep each authenticated Release identity together; never mix fields.

    Origin has no public codename attribute on older python-apt. PackageFile
    supplies the actual Release codename, joined by the same origin/site/suite.
    An absent codename remains absent, rather than being guessed from the host.
    """
    files = [pair[0] for pair in getattr(getattr(v, '_cand', None), 'file_list', [])]
    records = []
    for origin in v.origins:
        identity = dict(trusted=bool(origin.trusted), origin=origin.origin,
                        archive=origin.archive, site=getattr(origin, 'site', ''))
        codenames = set(getattr(f, 'codename', '') or '' for f in files
            if all(getattr(f, key, '') == identity[key] for key in ('origin', 'archive', 'site')))
        if not codenames:
            codenames.add(getattr(origin, 'codename', '') or '')
        for codename in codenames:
            row = dict(identity, codename=codename)
            if row not in records: records.append(row)
    return sorted(records, key=lambda row: (row['origin'], row['archive'], row['site'],
                                            row['codename'], row['trusted']))

def ondrej_lineage(version):
    """A package-manager version family is a constraint, not patch proof."""
    ppa = re.match(r'^1:7\.4\.[0-9]+-[0-9]+\+ubuntu([0-9]+\.[0-9]+)\.[0-9]+\+deb\.sury\.org\+[0-9]+$', version)
    if ppa: return ('ppa', 'ubuntu', ppa.group(1))
    sury = re.match(r'^1:7\.4\.[0-9]+-[0-9]+\+0~[0-9]{8}\.[0-9]+\+(debian|ubuntu)([0-9]+(?:\.[0-9]+)?)~[0-9]+\.gbp[0-9a-f]+$', version)
    if sury: return ('sury', sury.group(1), sury.group(2))
    return None

def record(v, codename):
    trusted, official = origins(v, codename)
    raw = v.version.split(':',1)[-1]
    match = re.match(r'(\d+\.\d+\.\d+(?:[A-Za-z]+\d*)?)', raw)
    return {'version':v.version, 'upstream':match.group(1) if match else None,
            'source':v.source_name, 'source_version':v.source_version,
            'arch':v.architecture, 'trusted':trusted, 'official_origin':official,
            'repo':origin_repo(v), 'origins':origin_records(v)}

def _lock_wait(value):
    try:
        integer_types = (int, long)
    except NameError:
        integer_types = (int,)
    if isinstance(value, bool) or not isinstance(value, integer_types) or value < 0 or value > 3600:
        raise RuntimeError('lock_wait must be a non-negative integer no greater than 3600')
    return value

def _clock():
    monotonic = getattr(time, 'monotonic', None)
    return monotonic() if monotonic else os.times()[4]

class _system_lock(object):
    """Bounded native lock wait; permission/configuration errors fail fast."""
    def __init__(self, wait_seconds):
        self.wait_seconds = _lock_wait(wait_seconds)
        self.native = None

    def __enter__(self):
        deadline = _clock() + self.wait_seconds
        while True:
            native = apt_pkg.SystemLock()
            try:
                # SystemLock acquires here, not in its constructor.
                value = native.__enter__()
                self.native = native
                return value
            except Exception as exc:
                message = str(exc)
                busy = (re.search(r'lock', message, re.I) and
                        re.search(r'Resource temporarily unavailable|is held by|'
                                  r'another process|another package manager', message, re.I))
                if not busy:
                    raise
                remaining = deadline - _clock()
                if remaining <= 0:
                    raise RuntimeError('APT package-manager lock remained busy for %s seconds: %s' %
                                       (self.wait_seconds, message))
                time.sleep(min(1.0, remaining))

    def __exit__(self, *args):
        if self.native is not None:
            return self.native.__exit__(*args)

def work(data):
    apt_pkg.init_config()
    apt_pkg.config.set('APT::Get::AllowUnauthenticated','false')
    apt_pkg.config.set('Acquire::AllowInsecureRepositories','false')
    apt_pkg.config.set('Acquire::AllowDowngradeToInsecureRepositories','false')
    apt_pkg.config.set('APT::Install-Recommends','false')
    apt_pkg.config.set('APT::Install-Suggests','false')
    apt_pkg.config.set('Dpkg::Options::','--force-confold')
    apt_pkg.init_system()
    codename=data.get('codename','__unknown__')
    if data['action']=='candidates':
        cache=apt.Cache()
        result={}
        for name in data['names']:
            if name not in cache: continue
            package=cache[name]
            # Respect apt pinning: only the policy candidate may be upgraded to.
            choices=[]
            if package.candidate: choices.append(package.candidate)
            if package.installed and all(v.version!=package.installed.version for v in choices):
                choices.append(package.installed)
            result[name]=[record(v,codename) for v in choices]
        return {'ok':True,'candidates':result}
    with _system_lock(data.get('lock_wait', 120)):
        cache=apt.Cache()
        if not data['updates']:
            raise RuntimeError('Empty APT transaction is not an upgrade')
        wanted={x['name']:x for x in data['updates']}
        if len(wanted) != len(data['updates']):
            raise RuntimeError('Duplicate package in APT transaction')
        aliases={}
        for name,item in wanted.items():
            for key in ('name', 'version', 'arch', 'old_version', 'source'):
                if not item.get(key): raise RuntimeError('Missing transaction field: ' + key)
            if apt_pkg.version_compare(item['version'], item['old_version']) <= 0:
                raise RuntimeError('Only strict upgrades are allowed: ' + name)
            branches = [re.match(r'^(\d+\.\d+)\.', item[key].split(':',1)[-1])
                        for key in ('version', 'old_version')]
            if not all(branches) or branches[0].group(1) != branches[1].group(1):
                raise RuntimeError('Cross-minor package upgrade blocked: ' + name)
            if name not in cache: raise RuntimeError('package missing: '+name)
            package=cache[name]
            if (not package.installed or package.installed.version!=item['old_version'] or
                    package.installed.architecture != item['arch'] or
                    package.installed.source_name != item['source']):
                raise RuntimeError('installed package changed since plan: '+name)
            if package._pkg.selected_state==apt_pkg.SELSTATE_HOLD:
                raise RuntimeError('package is held: '+name)
            matches=[v for v in package.versions if v.version==item['version'] and v.architecture==item['arch']]
            if len(matches)!=1: raise RuntimeError('exact candidate missing: '+name)
            v=matches[0]
            trusted, official = origins(v,codename)
            if (v.source_name!=item['source'] or not trusted or
                    (item.get('official_origin') and not official)):
                raise RuntimeError('source/trust mismatch: '+name)
            if item.get('repo') and origin_repo(v) != item['repo']:
                raise RuntimeError('candidate origin changed since plan: '+name)
            current_origins = origin_records(v)
            if item.get('origins') is not None and current_origins != item['origins']:
                raise RuntimeError('candidate Release identity changed since plan: '+name)
            vendor_origin = any(o['trusted'] and o['origin'] in ('LP-PPA-ondrej-php', 'deb.sury.org')
                                for o in current_origins)
            if vendor_origin:
                if not item.get('origins'):
                    raise RuntimeError('Missing pinned vendor Release identity: '+name)
                sites = {'LP-PPA-ondrej-php': ('ppa.launchpadcontent.net', 'ppa.launchpad.net'),
                         'deb.sury.org': ('packages.sury.org',)}
                if not any(o['trusted'] and o['site'] in sites.get(o['origin'], ()) and
                           o['archive'] == codename and o['codename'] == codename and
                           codename != '__unknown__' for o in current_origins):
                    raise RuntimeError('Vendor Release origin/site/suite/codename could not be verified: '+name)
                if (not ondrej_lineage(v.version) or
                        ondrej_lineage(v.version) != ondrej_lineage(package.installed.version)):
                    raise RuntimeError('Changing PHP vendor/distribution lineage is not approved: '+name)
            if item.get('source_version') and v.source_version != item['source_version']:
                raise RuntimeError('candidate source version changed since plan: '+name)
            if not package.candidate or package.candidate.version!=v.version:
                raise RuntimeError('candidate violates current apt policy: '+name)
            package.candidate=v
            aliases[package.fullname]=name
        for name in wanted:
            cache[name].mark_install(auto_fix=True,auto_inst=True,from_user=False)
        if cache.broken_count: raise RuntimeError('unresolved dependencies')
        changes=[]
        for p in cache.get_changes():
            name=aliases.get(p.fullname)
            item=wanted.get(name)
            if (not item or not p.marked_upgrade or p.marked_delete or p.marked_downgrade
                or not p.installed or p.candidate.version!=item['version']):
                raise RuntimeError('transaction changes an unapproved package: '+p.name)
            changes.append({'name':name,'old_version':p.installed.version,'version':p.candidate.version,'action':'upgrade'})
        if set(x['name'] for x in changes)!=set(wanted):
            raise RuntimeError('transaction does not exactly match plan')
        if data.get('execute'):
            os.environ['DEBIAN_FRONTEND']='noninteractive'
            os.environ['NEEDRESTART_MODE']='l'
            if not cache.commit(apt.progress.base.AcquireProgress(),apt.progress.base.InstallProgress()):
                raise RuntimeError('apt transaction failed')
        return {'ok':True,'changes':changes,'error':None}

try:
    with open(sys.argv[1]) as f: data=json.load(f)
    result=work(data)
except Exception as exc:
    result={'ok':False,'changes':[],'error':str(exc)}
with open(sys.argv[2],'w') as f: json.dump(result,f)
'''

def apt_codename(inv, policy):
    """Resolve the host's codename before consulting the fixed policy.

    VERSION_CODENAME/UBUNTU_CODENAME is authoritative for an installed
    Ubuntu/Debian host.  The policy fallback keeps compatibility with older
    inventories that only recorded ID and VERSION_ID.
    """
    system = inv.get('os', {})
    for key in ('codename', 'version_codename', 'ubuntu_codename'):
        value = system.get(key)
        if value and re.match(r'^[A-Za-z][A-Za-z0-9_-]*$', as_text(value)):
            return as_text(value)
    for entry in policy.get('entries', []):
        if entry['os_id'] == system.get('id') and entry['os_version'] == system.get('version_id'):
            return entry.get('os_codename', '__unknown__')
    return '__unknown__'

def ubuntu_codename(inv, policy):
    # Backwards-compatible public name used by the generic CLI.
    return apt_codename(inv, policy)

def apt_candidates(inv, policy):
    result = worker_call(APT_WORKER, {'action': 'candidates',
        'names': [p['name'] for p in inv['packages'] if is_core_package(p)],
        'codename': apt_codename(inv, policy)}, ['apt', 'apt_pkg'])
    if not result.get('ok'):
        raise RuntimeError(result.get('error', 'apt metadata failed'))
    return result['candidates']

def apt_transaction(updates, execute=False, codename='__unknown__', lock_wait=120):
    try:
        return worker_call(APT_WORKER, {'action': 'transaction', 'updates': updates,
            'execute': execute, 'codename': codename, 'lock_wait': lock_wait}, ['apt', 'apt_pkg'],
            timeout=None if execute else 120 + lock_wait)
    except RuntimeError as exc:
        return {'ok': False, 'changes': [], 'error': as_text(exc)}

def enrich_origin(inv, candidates):
    for p in inv.get('packages', []):
        for c in candidates.get(p['name'], []):
            if (c['version'] == p['version'] and c['arch'] == p['arch'] and c['source'] == p['source'] and
                    (not p.get('source_version') or p['source_version'] == (c.get('source_version') or c['version']))):
                p['official_origin'] = c.get('official_origin', False)
                p['trusted'] = c.get('trusted', False)
                p['repo'] = c.get('repo')
                p['origins'] = c.get('origins', [])
                p['source_version'] = c.get('source_version') or c['version']
                proof = c.get('vendor_provenance')
                if isinstance(proof, dict) and proof.get('installed_match') is True:
                    p['vendor_provenance'] = dict(proof)
    return inv
