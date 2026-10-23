# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import sys
sys.path = [p for p in sys.path if p not in ('', '.')]
import os
import sys
import re
import json
import subprocess
import tempfile
import threading
import time
import shutil
import stat
import glob
import hashlib
import argparse
import tarfile
import datetime
import functools
import signal

VERSION = '1.7.6'
CVES = ['CVE-2026-109618', 'CVE-2026-109619']
MINIMA = {'8.2': (8, 2, 35), '8.3': (8, 3, 36),
          '8.4': (8, 4, 27), '8.5': (8, 5, 12)}

def as_text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    try:
        return unicode(value)
    except NameError:
        return str(value)

def run_cmd(argv, timeout=30, env=None):
    child_env = os.environ.copy()
    child_env.update({'LC_ALL': 'C', 'LANG': 'C'})
    if env:
        child_env.update(env)
    timer = None
    timed_out = [False]
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=child_env,
                             preexec_fn=os.setsid if os.name == 'posix' else None)
        def stop():
            timed_out[0] = True
            try:
                if os.name == 'posix':
                    os.killpg(p.pid, signal.SIGKILL)
                else:
                    p.kill()
            except OSError:
                pass
        if timeout:
            timer = threading.Timer(timeout, stop)
            timer.daemon = True
            timer.start()
        out, err = p.communicate()
        return {'code': 124 if timed_out[0] else p.returncode,
                'stdout': as_text(out), 'stderr': as_text(err)}
    except OSError as exc:
        return {'code': 127, 'stdout': '', 'stderr': as_text(exc)}
    finally:
        if timer:
            timer.cancel()

def version_tuple(value):
    value = as_text(value or '').split(':', 1)[-1]
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)(.*)$', value)
    if not m or re.search(r'(?:alpha|beta|RC|dev|snapshot)', m.group(4), re.I):
        return None
    if m.group(4) and m.group(4)[0] not in '-+~':
        return None
    return tuple(int(x) for x in m.groups()[:3])

def branch_of(version):
    value = version_tuple(version)
    return '%d.%d' % value[:2] if value else None

def upstream_status(version):
    value = version_tuple(version)
    if not value:
        return 'unknown'
    branch = branch_of(version)
    if branch in MINIMA:
        return 'fixed' if value >= MINIMA[branch] else 'affected'
    if (5, 0, 0) <= value < (8, 2, 0):
        return 'affected'
    return 'unknown'

def is_core_package(package):
    source = package.get('source') or ''
    # Remi SCL collection metadata and symlinks are not PHP engine binaries.
    # Bind this exception to the exact source-RPM family; unknown packages must
    # still be reported rather than hidden behind an unparseable version.
    wrapper_version = (package.get('version') or '').split(':', 1)[-1]
    if (source == 'php74' and package.get('name') in ('php74', 'php74-runtime', 'php74-syspaths') and
            re.match(r'^7\.4-[0-9]+\.el(?:8|9|10)\.remi\Z', wrapper_version) and
            package.get('source_rpm') == 'php74-' + wrapper_version + '.src.rpm'):
        return False
    return bool(re.match(r'^(?:php(?:\d+(?:\.\d+)?)?|(?:rh-)?php\d+-php|lsphp\d*)$', source))

def native_compare(a, b, manager):
    if a == b:
        return 0
    if manager == 'apt':
        for op, answer in [('gt', 1), ('lt', -1)]:
            r = run_cmd(['/usr/bin/dpkg', '--compare-versions', a, op, b])
            if r['code'] == 0:
                return answer
            if r['code'] != 1:
                raise RuntimeError('dpkg version comparison failed')
        return 0
    code = "import rpm,sys\ndef evr(s):\n e,v=(s.split(':',1) if ':' in s else ('0',s)); v,r=v.rsplit('-',1) if '-' in v else (v,''); return(e,v,r)\nprint(rpm.labelCompare(evr(sys.argv[1]),evr(sys.argv[2])))"
    for py in ['/usr/libexec/platform-python', '/usr/bin/python3', '/usr/bin/python2', '/usr/bin/python']:
        if os.path.exists(py):
            r = run_cmd([py, '-E', '-s', '-c', "import sys;sys.path=[p for p in sys.path if p];" + code, a, b])
            if r['code'] == 0 and r['stdout'].strip() in ('-1', '0', '1'):
                return int(r['stdout'].strip())
    raise RuntimeError('RPM Python bindings unavailable; refusing approximate EVR comparison')

def policy_version_matches(expression, value):
    match = re.match(expression, value or '')
    return bool(match and match.group(0) == value)

def apt_vendor_rule_matches(package, inv, rule):
    if rule.get('provenance') != 'ondrej-apt' or inv.get('package_manager') != 'apt':
        return False
    expected = rule['apt_origin']
    if not package.get('trusted'):
        return False
    if not all(policy_version_matches(rule['version_regex'], value) for value in
               (package.get('version'), package.get('source_version') or package.get('version'))):
        return False
    # All fields must belong to ONE authenticated release; evidence from
    # different repositories must never be combined into a trusted origin.
    return any(row.get('trusted') is True and row.get('origin') == expected['origin'] and
               row.get('site') in expected['sites'] and row.get('archive') == expected['archive'] and
               row.get('codename') == expected['codename']
               for row in package.get('origins', []))

def remi_vendor_matches(package, inv):
    proof = package.get('vendor_provenance') or {}
    policy = globals().get('RP_REMI_POLICY', {})
    system = inv.get('os', {})
    major = system.get('version_id', '').split('.')[0]
    key = policy.get('keys', {}).get(major)
    if (inv.get('package_manager') not in ('yum', 'dnf') or not key or
            system.get('id') not in policy.get('supported_os_ids', []) or
            package.get('source') not in policy.get('sources', []) or
            package.get('arch') not in policy.get('supported_architectures', []) + ['noarch']):
        return False
    expected = dict(kind='remi-rpm', signature_verified=True, key_sha256=key['sha256'],
                    key_fingerprint=key['fingerprints'][0], os_id=system['id'], os_major=major,
                    source=package['source'], package_name=package['name'],
                    version=package['version'], arch=package['arch'], cves=CVES)
    if any(proof.get(name) != value for name, value in expected.items()):
        return False
    if not policy_version_matches(r'[0-9a-f]{64}', proof.get('artifact_sha256', '')):
        return False
    suffix = r'\.module_php\.7\.4\.' if package['source'] == 'php' else r'\.'
    match = re.match(r'^(?:0:)?7\.4\.33-([0-9]+)' + suffix + r'el' + major + r'\.remi\Z', package['version'])
    return bool(match and int(match.group(1)) >= policy['fixed_revision'])

def vendor_candidate_same_lineage(installed, candidate, inv, policy):
    if (candidate.get('vendor_provenance') or {}).get('kind') == 'remi-rpm':
        if not remi_vendor_matches(candidate, inv):
            return False
        major = inv['os']['version_id'].split('.')[0]
        suffix = r'\.module_php\.7\.4\.' if candidate['source'] == 'php' else r'\.'
        expression = r'^(?:0:)?7\.4\.[0-9]+-[0-9]+' + suffix + r'el' + major + r'\.remi\Z'
        return policy_version_matches(expression, installed.get('version'))
    # Native vendor versions are also a lineage guard: an official Ubuntu or
    # Debian package must not migrate to PPA/Sury merely because its source
    # package has the same name.
    if candidate.get('origins') and not candidate.get('official_origin'):
        rules = [r for r in policy.get('entries', []) if
                 r.get('os_id') == inv.get('os', {}).get('id') and
                 r.get('os_version') == inv.get('os', {}).get('version_id') and
                 r.get('source_package') == candidate.get('source') and
                 apt_vendor_rule_matches(candidate, inv, r)]
        if rules:
            return any(policy_version_matches(r['installed_version_regex'], installed.get('version')) and
                       policy_version_matches(r['installed_version_regex'],
                                              installed.get('source_version') or installed.get('version'))
                       for r in rules)
    return True

def package_status(package, inv, policy):
    status = upstream_status(package.get('upstream') or package.get('version'))
    if status == 'fixed':
        return 'fixed', 'upstream security release threshold met'
    if remi_vendor_matches(package, inv):
        return 'fixed', 'Remi PHP 7.4 revision 31+: both CVEs and pinned RPM signature verified'
    system = inv.get('os', {})
    for rule in policy.get('entries', []):
        if (rule['os_id'] != system.get('id') or
            rule['os_version'] != system.get('version_id') or
            rule['source_package'] != package.get('source') or
            rule['branch'] != branch_of(package.get('upstream') or package.get('version'))):
            continue
        # Vendor backports require matching authenticated repository provenance.
        if rule.get('provenance') == 'ondrej-apt':
            if not apt_vendor_rule_matches(package, inv, rule):
                continue
        elif not package.get('official_origin'):
            continue
        try:
            if native_compare(package.get('source_version') or package['version'],
                              rule['min_version'], inv.get('package_manager')) >= 0:
                return 'fixed', rule['advisory'] + ': ' + rule['url']
        except RuntimeError:
            return 'unknown', 'native vendor version comparison unavailable'
    return status, ('below upstream security threshold; vendor backport not verified'
                    if status == 'affected' else 'version outside verified policy')

def assess_inventory(inv, policy):
    findings = []
    core = {}
    for p in inv.get('packages', []):
        if not is_core_package(p):
            continue
        status, reason = package_status(p, inv, policy)
        core[p['name']] = p
        findings.append({'kind': 'package', 'package_name': p['name'],
                         'version': p['version'], 'status': status, 'reason': reason})
    for rt in inv.get('runtimes', []):
        owner = rt.get('package')
        p = core.get(owner) or core.get((owner or '').split(':')[0])
        if not p:
            findings.append({'kind': 'unmanaged_runtime', 'path': rt['path'],
                             'status': 'unknown', 'reason': 'not mapped to managed PHP core package; manual patch verification required'})
        elif not rt.get('version') or version_tuple(rt['version']) != version_tuple(p.get('upstream')):
            findings.append({'kind': 'runtime_mismatch', 'path': rt['path'],
                             'status': 'unknown', 'reason': 'binary version unavailable or differs from installed package'})
    for proc in inv.get('processes', []):
        if proc.get('deleted'):
            findings.append({'kind': 'stale_process', 'pid': proc['pid'], 'status': 'unknown',
                             'reason': 'running deleted executable; restart required'})
        elif re.search(r'php|fpm|franken|lsphp', proc.get('comm', ''), re.I) and not proc.get('version'):
            findings.append({'kind': 'unverified_process', 'pid': proc['pid'], 'status': 'unknown',
                             'reason': 'running PHP executable version could not be mapped'})
    for container in inv.get('containers', []):
        findings.append({'kind': 'container', 'container': container.get('name'), 'status': 'unknown',
                         'reason': 'container PHP not scanned; update image separately'})
    for warning in inv.get('warnings', []):
        if re.search(r'incomplete|unavailable|untrusted|denied|stopped at|failed|unreadable', warning, re.I):
            findings.append({'kind': 'coverage', 'status': 'unknown', 'reason': warning})
    if not core and not inv.get('runtimes'):
        findings.append({'kind': 'coverage', 'status': 'unknown', 'reason': 'no managed PHP runtime found; this is not a whole-host safety verdict'})
    return findings

def build_plan(inv, findings, candidates, policy):
    updates, blockers = [], []
    groups = {}
    for p in inv.get('packages', []):
        if is_core_package(p):
            groups.setdefault((p.get('source'), branch_of(p.get('upstream'))), []).append(p)
    for group, packages in sorted(groups.items(), key=lambda x: as_text(x[0])):
        if all(package_status(p, inv, policy)[0] == 'fixed' for p in packages):
            continue
        possible = []
        failed = []
        diagnostics = []
        for p in packages:
            acceptable = []
            options = candidates.get(p['name'], [])
            same_branch_versions = set(c['version'] for c in options
                                       if branch_of(c.get('upstream') or c['version']) == group[1])
            version_examples = sorted(set(c['version'] for c in options),
                                      key=lambda version: (version not in same_branch_versions, version))
            diagnostic = {'package': p['name'], 'installed': p['version'], 'total': len(options),
                          'same_branch': 0, 'trusted_source_arch': 0, 'verified_fixed': 0,
                          'accepted': 0, 'comparison_errors': 0,
                          'available_versions': version_examples[:12],
                          'available_versions_omitted': max(0, len(version_examples) - 12)}
            for c in options:
                if branch_of(c.get('upstream') or c['version']) == group[1]:
                    diagnostic['same_branch'] += 1
                if (not c.get('trusted') or c.get('source') != p.get('source') or
                    c.get('arch') != p.get('arch') or
                    branch_of(c.get('upstream') or c['version']) != group[1]):
                    continue
                diagnostic['trusted_source_arch'] += 1
                if not vendor_candidate_same_lineage(p, c, inv, policy):
                    continue
                if package_status(c, inv, policy)[0] != 'fixed':
                    continue
                diagnostic['verified_fixed'] += 1
                try:
                    if native_compare(c['version'], p['version'], inv['package_manager']) < 0:
                        continue
                except RuntimeError:
                    diagnostic['comparison_errors'] += 1
                    continue
                acceptable.append(c)
            diagnostic['accepted'] = len(acceptable)
            diagnostics.append(diagnostic)
            if not acceptable:
                failed.append(p['name'])
            possible.append((p, acceptable))
        # A source build's ABI-coupled core packages must move together.
        common_versions = None
        for p, options in possible:
            versions = set(c.get('source_version') or c['version'] for c in options)
            common_versions = versions if common_versions is None else common_versions & versions
        if failed or not common_versions:
            blockers.append({'source': group[0], 'branch': group[1],
                             'reason': 'no complete trusted fixed build in same branch',
                             'packages': failed or [p['name'] for p in packages],
                             'candidate_diagnostics': diagnostics})
            continue
        target = sorted(common_versions, key=functools.cmp_to_key(
            lambda a, b: native_compare(a, b, inv['package_manager'])))[-1]
        for p, options in possible:
            c = next(x for x in options if (x.get('source_version') or x['version']) == target)
            if c['version'] != p['version']:
                item = dict(c)
                item.update({'name': p['name'], 'old_version': p['version'], 'source': p['source']})
                updates.append(item)
    return {'updates': updates, 'blockers': blockers}

def write_json(path, obj):
    with open(path, 'wb') as handle:
        handle.write((json.dumps(obj, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))

def worker_call(source, payload, modules, timeout=120):
    """Run package-manager bindings with the system Python, never shell-eval data."""
    selected = None
    for py in ['/usr/bin/python3', '/usr/libexec/platform-python', '/usr/bin/python2', '/usr/bin/python']:
        if os.path.exists(py) and run_cmd([py, '-E', '-s', '-c', "import sys; sys.path=[p for p in sys.path if p];" + ';'.join('import ' + m for m in modules)])['code'] == 0:
            selected = py
            break
    if not selected:
        raise RuntimeError('system Python module missing: ' + ', '.join(modules))
    folder = tempfile.mkdtemp(prefix='php-guard-worker-')
    os.chmod(folder, 0o700)
    try:
        script, data, result = [os.path.join(folder, n) for n in ('worker.py', 'input.json', 'result.json')]
        with open(script, 'wb') as handle:
            handle.write(source.encode('utf-8'))
        write_json(data, payload)
        r = run_cmd([selected, '-E', '-s', script, data, result], timeout=timeout)
        if r['code'] or not os.path.exists(result):
            raise RuntimeError('package backend failed (exit %s): %s' % (r['code'], r['stderr'][-3000:]))
        with open(result) as handle:
            return json.load(handle)
    finally:
        shutil.rmtree(folder)
