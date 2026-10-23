# -*- coding: utf-8 -*-
"""Pinned Remi signatures for native EL 8/9/10 PHP 7.4 packages.

The worker never imports keys into the system RPM database. Repository labels,
package Vendor and version text alone do not establish a fixed build.
"""

_RPM_PROVENANCE_WORKER = r'''
import functools, hashlib, shutil, stat, subprocess, tempfile

def rp_host():
    values = {}
    with open('/etc/os-release') as handle:
        for line in handle:
            if '=' not in line: continue
            key, value = line.strip().split('=', 1)
            values[key] = value.strip('"\'')
    major = values.get('VERSION_ID', '').split('.')[0]
    if values.get('ID') not in RP_REMI_POLICY['supported_os_ids'] or major not in RP_REMI_POLICY['keys']:
        return None
    return dict(os_id=values['ID'], os_major=major)

def rp_eligible(pkg, host):
    # Require the exact recorded vendor revision family. Do not infer an EL
    # release from ID_LIKE, or accept a higher unrelated custom version.
    if not host or text(pkg.version) != '7.4.33' or text(pkg.epoch or '0') != '0': return False
    if source(pkg) not in ('php', 'php74-php'): return False
    if text(pkg.arch) not in ('x86_64', 'aarch64', 'noarch'): return False
    suffix = (r'\.module_php\.7\.4\.' if source(pkg) == 'php' else r'\.')
    expression = r'^([0-9]+)' + suffix + 'el' + re.escape(host['os_major']) + r'\.remi$'
    match = re.match(expression, text(pkg.release))
    return bool(match and int(match.group(1)) >= 31)

def rp_command(argv):
    env = dict(os.environ)
    env.update(LC_ALL='C', LANG='C')
    for name in ('PYTHONPATH', 'PYTHONHOME', 'LD_PRELOAD', 'LD_LIBRARY_PATH'):
        env.pop(name, None)
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, err = process.communicate()
    return process.returncode, out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')

def rp_rpm_path():
    for path in ('/usr/bin/rpm', '/bin/rpm'):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            # Trusted native executable: reject a mutable ancestor or target.
            for target in (path, os.path.realpath(path)):
                while True:
                    info = os.lstat(target)
                    if info.st_uid or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
                        raise RuntimeError('Untrusted RPM executable path: ' + target)
                    parent = os.path.dirname(target)
                    if parent == target: break
                    target = parent
            return path
    raise RuntimeError('Native rpm executable is required for isolated signature verification')

def rp_signature_output(code, output, key):
    if code or re.search(r'NOT OK|NOKEY|BAD|NOTTRUSTED|UNKNOWN', output, re.I):
        return False
    ids = re.findall(r'(?:RSA|DSA|PGP)[^\n]*Signature[^\n]*key ID ([0-9a-f]+):\s*OK\b', output, re.I)
    allowed = [value.lower() for value in key['fingerprints']]
    return bool(ids) and all(any(fingerprint.endswith(value.lower()) for fingerprint in allowed)
                             for value in ids)

def rp_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block: break
            digest.update(block)
    return digest.hexdigest()

def rp_header_identity(header):
    epoch = text(header['epoch'] or 0)
    return dict(name=text(header['name']), arch=text(header['arch']),
                version=(epoch + ':' if epoch != '0' else '') + text(header['version']) + '-' + text(header['release']),
                source_rpm=text(header['sourcerpm']))

def rp_header_content(header):
    # These signed header values describe the installed content. Install time,
    # database ids and mutable transaction bookkeeping are intentionally absent.
    keys = ('filenames', 'filedigests', 'filedigestalgo', 'fileflags', 'filemodes',
            'filelinktos', 'fileusername', 'filegroupname', 'filecaps')
    return dict((key, header[key]) for key in keys)

def rp_installed_matches(header, rpm_path):
    import rpm
    expected = rp_header_identity(header)
    ts = rpm.TransactionSet('/')
    matches = [item for item in ts.dbMatch('name', expected['name'])
               if text(item['arch']) == expected['arch']]
    if len(matches) != 1 or rp_header_identity(matches[0]) != expected:
        return False
    if rp_header_content(matches[0]) != rp_header_content(header): return False
    # Config files may be customized, but modified/missing binaries, extension
    # files or unreadable verification output never inherit a signed package pass.
    label = expected['name'] + '-' + expected['version'] + '.' + expected['arch']
    code, out, err = rp_command([rpm_path, '-V', '--nodeps', '--noscripts', label])
    if code not in (0, 1) or err.strip(): return False
    if code == 1 and not out.strip(): return False
    for line in out.splitlines():
        if not line.strip(): continue
        if not re.match(r'^.{9}\s+c\s+/', line): return False
    return True

def rp_prove_package(pkg, host, verify_installed=False):
    import rpm
    if not rp_eligible(pkg, host):
        raise RuntimeError('Remi signature proof requested for ineligible package')
    key = RP_REMI_POLICY['keys'][host['os_major']]
    armor = key['armor'].encode('ascii')
    if hashlib.sha256(armor).hexdigest() != key['sha256']:
        raise RuntimeError('Embedded Remi key digest mismatch')
    rpm_path = rp_rpm_path()
    directory = tempfile.mkdtemp(prefix='php-guard-remi-signature-')
    try:
        key_path = os.path.join(directory, 'remi.key')
        database = os.path.join(directory, 'rpmdb')
        artifact = os.path.join(directory, 'package.rpm')
        os.mkdir(database, 0o700)
        with open(key_path, 'wb') as handle: handle.write(armor)
        # Snapshot to a private file, so header/hash/signature see the same bytes.
        original = pkg.localPkg()
        with open(original, 'rb') as source_handle, open(artifact, 'wb') as target:
            shutil.copyfileobj(source_handle, target, 1024 * 1024)
        for action in (['--initdb'], ['--import', key_path]):
            code, out, err = rp_command([rpm_path, '--dbpath', database] + action)
            if code: raise RuntimeError('Cannot initialize isolated Remi verification database: ' + err)
        code, out, err = rp_command([rpm_path, '--dbpath', database, '--checksig', '--verbose', artifact])
        if not rp_signature_output(code, out + err, key):
            raise RuntimeError('RPM did not verify against the pinned Remi signing key: ' + text(pkg.name))
        ts = rpm.TransactionSet('/')
        # The private snapshot has JUST passed signature verification using only
        # the pinned key. Read its header without requiring that same key in the
        # host keyring. This read-only TS is never reused for installation; the
        # native transaction retains its own mandatory signature checks.
        ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
        with open(artifact, 'rb') as handle: header = ts.hdrFromFdno(handle.fileno())
        expected = dict(name=text(pkg.name), arch=text(pkg.arch), version=evr(pkg), source_rpm=text(pkg.sourcerpm))
        if rp_header_identity(header) != expected:
            raise RuntimeError('Signed RPM header differs from repository candidate: ' + text(pkg.name))
        # Check native availability of every tag needed by the post-install
        # comparison before a candidate can enter an installation plan.
        rp_header_content(header)
        proof = dict(kind='remi-rpm', signature_verified=True, key_sha256=key['sha256'],
                     key_fingerprint=key['fingerprints'][0], artifact_sha256=rp_sha256(artifact),
                     os_id=host['os_id'], os_major=host['os_major'], source=source(pkg),
                     package_name=text(pkg.name), version=evr(pkg), arch=text(pkg.arch),
                     cves=['CVE-2026-109618', 'CVE-2026-109619'],
                     advisory_url='https://rpms.remirepo.net/enterprise/' + host['os_major'] + '/php74/' +
                                  ('x86_64' if pkg.arch == 'noarch' else text(pkg.arch)) + '/repoview/php.html',
                     installed_match=False)
        if verify_installed: proof['installed_match'] = rp_installed_matches(header, rpm_path)
        # The downloader's cache must still contain the verified snapshot.
        if rp_sha256(original) != proof['artifact_sha256']:
            raise RuntimeError('RPM cache content changed during signature verification')
        return proof
    finally:
        shutil.rmtree(directory)

def rp_candidate_map(base, inventory, available, host):
    import rpm
    # Verify only the newest complete source-build set plus installed versions.
    # Historical candidates remain unverified, and are never all downloaded.
    groups, installed = {}, {}
    for item in inventory['packages']:
        installed[(item['name'], item['arch'])] = item['version']
        if item.get('source') in ('php', 'php74-php') and text(item.get('upstream', '')).startswith('7.4.'):
            versions = set(evr(pkg) for pkg in available.get(item['name'], [])
                           if text(pkg.arch) == item['arch'] and source(pkg) == item['source'] and rp_eligible(pkg, host))
            key = item['source']
            groups[key] = versions if key not in groups else groups[key] & versions
    targets = {}
    comparator = functools.cmp_to_key(lambda a, b: rpm.labelCompare(split_evr(a), split_evr(b)))
    for key, versions in groups.items():
        if versions: targets[key] = sorted(versions, key=comparator)[-1]
    selected = []
    for packages in available.values():
        for pkg in packages:
            if not rp_eligible(pkg, host): continue
            old = installed.get((text(pkg.name), text(pkg.arch)))
            if evr(pkg) == targets.get(source(pkg)) or (old and equal_evr(evr(pkg), old)):
                selected.append(pkg)
    if selected: base.download_packages(selected)
    proofs = {}
    for pkg in selected:
        key = (text(pkg.name), text(pkg.arch), evr(pkg), text(pkg.repoid))
        proofs[key] = rp_prove_package(pkg, host, verify_installed=True)
    result = {}
    for name, packages in available.items():
        records = []
        for pkg in packages:
            record = package_record(pkg)
            record['name'] = text(pkg.name)
            key = (text(pkg.name), text(pkg.arch), evr(pkg), text(pkg.repoid))
            if key in proofs: record['vendor_provenance'] = proofs[key]
            records.append(record)
        result[name] = records
    return result

def rp_revalidate_selected(base, selected, desired):
    selected = [pkg for pkg in selected if desired[(text(pkg.name), text(pkg.arch))].get('vendor_provenance')]
    if not selected: return
    host = rp_host()
    base.download_packages(selected)
    for pkg in selected:
        previous = desired[(text(pkg.name), text(pkg.arch))]['vendor_provenance']
        current = rp_prove_package(pkg, host)
        for key in ('kind', 'signature_verified', 'key_sha256', 'key_fingerprint', 'artifact_sha256',
                    'os_id', 'os_major', 'source', 'package_name', 'version', 'arch', 'cves'):
            if current.get(key) != previous.get(key):
                raise RuntimeError('Remi RPM provenance changed since plan: ' + text(pkg.name))
'''
