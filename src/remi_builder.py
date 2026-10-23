# -*- coding: utf-8 -*-
"""Pinned Remi EL7 PHP 7.4 packaging + BaoTa 7.4.34 source.

Only prepares/builds native RPMs. Never installs generated PHP packages.
"""

RB_COMMIT = 'd3fb24595d6bcebd6bd29477bc59916f333f5233'
RB_BASE_URL = 'https://git.remirepo.net/git/rpms/php/php74.git/plain/'
RB_RECIPE = 'baota-remi-el7-php74'
RB_VERSION = '7.4.34'
RB_RELEASE = '15.el7.remi.phpguard.baota20261023.1'
RB_ARCHIVE = 'php-7.4.34.tar.gz'
RB_SOURCE_URL = 'https://download.bt.cn/src/' + RB_ARCHIVE
RB_SOURCE_SHA = '343fe09e745ff4eacdd4e223b45085620ffd0e9a85eb467fc33eb361ab34ddf9'
RB_LAST_BUILD_REPORT = None
RB_CVE203_PATCH = 'php74-remi-cve20230662-compat.patch'
RB_CVE203_SHA = '5b4c9d94e247b0769246655e2d7ba703c84d4adf51a94627562bc8adf70e0ee9'
RB_CVE203_INCLUDED_COMMIT = '8ec78d28d20c82c75c4747f44c52601cfdb22516'
RB_CVE203_BEFORE = {
    'main/main.c': 'd5d6aeb6aca1225ba6bdeb62dfa92219bbfb570542629f3d4c931a0d01c620b1',
    'main/rfc1867.c': '3f4df06e9136d8420375186ce4609da9c4116b867ffb6779a06b81d7eacf2813'}
RB_CVE203_AFTER = {
    'main/main.c': 'd5d6aeb6aca1225ba6bdeb62dfa92219bbfb570542629f3d4c931a0d01c620b1',
    'main/rfc1867.c': 'd9e9a513d143988654c9ed2c0a4ff469a8aa895007d7940208ca2d819c249db3'}
RB_MULTIPART_EXPECTED = [
    {'case': 'body_parts_limit', 'body_parts_limit': 1, 'accepted_fields': ['first'],
     'accepted_files': [], 'warning_count': 1},
    {'case': 'file_upload_limit', 'file_upload_limit': 0, 'accepted_fields': [],
     'accepted_files': [], 'warning_count': 1}]
RB_TOOLS = ['rpm', 'rpmbuild', 'curl', 'gcc', 'g++', 'make', 'autoconf',
            'automake', 'libtool', 'patch', 'perl', 'sha256sum']
RB_CORE_NAMES = {'php', 'php-cli', 'php-common', 'php-fpm', 'php-opcache', 'php-pdo',
                 'php-mysqlnd', 'php-mbstring', 'php-xml'}
RB_SMOKE_SAPIS = ('build-cgi', 'build-ztscli')
# Reviewed default EL7 x86_64 BuildRequires from the pinned SPEC, with imap,
# firebird, dtrace and ZTS enabled; optional OCI8 and bundled zip disabled.
# rpmbuild still independently checks its fully expanded native requirements.
RB_BUILD_REQUIRES = [
    'gnupg2', 'tzdata >= 2022b', 'bzip2-devel', 'pkgconfig(libcurl) >= 7.15.5', 'httpd-devel >= 2.0.46-1',
    'pam-devel', 'libstdc++-devel', 'openssl-devel >= 1.0.1',
    'pkgconfig(sqlite3) >= 3.7.4', 'pkgconfig(zlib) >= 1.2.0.4',
    'smtpdaemon', 'pkgconfig(libedit)', 'bzip2', 'perl', 'autoconf', 'automake',
    'make', 'gcc', 'gcc-c++', 'libtool', 'libtool-ltdl-devel', 'systemtap-sdt-devel',
    '/bin/ps', 'libacl-devel', 'pkgconfig(libsystemd) >= 209', 'pkgconfig(krb5)',
    'pkgconfig(krb5-gssapi)', 'libc-client-devel', 'pkgconfig(libsasl2)', 'openldap-devel',
    'krb5-devel', 'postgresql-devel', 'unixODBC-devel', 'pkgconfig(libxml-2.0) >= 2.7.6',
    'firebird-devel', 'net-snmp-devel', 'pkgconfig(libxslt) >= 1.1', 'pkgconfig(libexslt)',
    'oniguruma5php-devel', 'pkgconfig(gdlib) >= 2.3.3', 'gmp-devel', 'libdb-devel',
    'tokyocabinet-devel', 'gdbm-devel', 'lmdb-devel', 'libtidy-devel', 'freetds-devel >= 0.91',
    'aspell-devel >= 0.50.0', 'pkgconfig(icu-i18n) >= 73', 'pkgconfig(icu-io) >= 73',
    'pkgconfig(icu-uc) >= 73', 'pkgconfig(enchant)', 'pkgconfig(libsodium) >= 1.0.14',
    'pkgconfig(libffi)']


RB_PACKAGING = {'10-opcache.ini': 'f7dcbff2a62d9deac450dec6ec8323472a91578091c1301535e6436e8deed5dd', '20-ffi.ini': 'f5e968fdd3eca54f3dab2399e243931cf16cd9da034f0364800aefab222271c0', '20-oci8.ini': '47c0431dfe70750480217338e97ef637377be51157c24965a22d13d3af61060c', 'macros.php': 'dc77edd8f8b6644888c4921d01747c499bea89e7a70709fb9539fcd26a69b3ea', 'nginx-fpm.conf': '54432bc051686f00b1685bad91a73f9a2fbe3b650c1fba4e9a4232363c4dfa99', 'nginx-php.conf': '88dfe176f02a0f8cba0a91711d1f5075bedbc01d2cdcd149e50890e2c71b3080', 'opcache-default.blacklist': '4eef0875e1a0c6a75b8a2bafd4ddc029b83be74dd336a6a99214b0c32808cb38', 'php-7.0.10-datetests.patch': 'ca95c78c11d3ab81d2f71f850bf50676dd25b6413370ab0d3862d6e7025ccd0f', 'php-7.0.7-curl.patch': 'c571aafedc98461765f388c96ac4334a7288e2dd23b800c50e998cc75384dfc7', 'php-7.2.0-includedir.patch': '110440143614b0e93364a4547e9c9c2df86d06d19a06fc36bc062da6079bcddb', 'php-7.2.0-libdb.patch': '11d2847b9196331ae18f7833382ace40993b89ab57a738eed34b05e3bc935e33', 'php-7.2.0-oci8conf.patch': '629a020a1114361bdd2329f1fc3c5a972667492418f0f14dc09bcfdee12709ee', 'php-7.3.3-systzdata-v19.patch': 'ddee850227c6a47d19cc4d2967c010dfd9d5764f8475ab74057fcdf4e1ffed0f', 'php-7.4.0-embed.patch': '6700631457238da7043c82eeff46a3b3a51f47a0415ed24a8059639cd2bf4878', 'php-7.4.0-httpd.patch': '844a7c2a0e014c2cd5de526019087052ce7b01a9863b749b2df4d7927d3663bb', 'php-7.4.0-ldap_r.patch': '4c1e296e1cb89c86dd1be82bf59623521c0e98e7c06ea0aed900641bcfc3cd75', 'php-7.4.0-phpize.patch': 'fee1ef9da805c498407ce1dc8ec26f0891b002b04947a752fb80e6d39761e058', 'php-7.4.20-argon2.patch': 'd65372ed9d03e9476e5bad58d35db67360038645a17a0182ac90d9c34e5cccac', 'php-7.4.26-openssl3.patch': '3762044138f09f9be93d9a57081d13bb11eaafed5201310d0ef0bb013147bd6a', 'php-7.4.26-snmp.patch': 'd93bc624d04922a06c0e6e802647ab6d6b5ad546e5267793cd0ac2255f6d0934', 'php-7.4.33-gcc14.patch': '1b44b6bc2048a9158132557a0eea1278f6bf074ee450b90a47c8f14928ddaaa6', 'php-7.4.33-libxml212.patch': 'fb3a9fc84ce3e443d51e3c8b2655ca231ebe5855845150fe6e16eb36de94f7de', 'php-7.4.33-tests.patch': 'fafcb49e1adc88b8795d0e95f71fa0893ef25ded68de93e1b3faccd527ae59ed', 'php-7.4.33-zlib-tests.patch': '1678f6f5de4c7b317c18a76871babaf6556bd74af729cb3aaa569f9c2b5a2f9d', 'php-7.4.8-phpinfo.patch': '21caf1d0151a56b10b8e0e53083b3d3d0ad52d5fd8a79e7db4c8638cd3588434', 'php-bug81740.patch': '50aae01084678a7a24a43567935aa06dcaf99411a4b0d79f84e7b1d345e9d857', 'php-bug81744.patch': '7adc763b4995167d8defabb7d1ccf7b25ca96240a6960a707b78cc7d3efb4053', 'php-bug81746.patch': '2f03696a5dceeaa5f42f465bf2567ffdf03ebb78607510f92583e6979013e208', 'php-cve-2023-0662.patch': 'e688d4c0179c0b58b2d5b02e3079bb0afe4e355b33f9702355d83d4b0e92269d', 'php-cve-2023-3247.patch': '9298c76a847278682d6b67d4c3584e687c75805856df74980e811a761b14743c', 'php-cve-2023-3823.patch': 'dc2caacd87b2eea562103756dde49efcd52474cdad7d43f7e1eea922d19a5289', 'php-cve-2023-3824.patch': 'b8703eb8502208eb556cb696c5caa3b9f94a8021de7d7414895dfdad9ca33e5b', 'php-cve-2024-2756.patch': 'c65bbc618aaa1fcdc097a1f12e258d1608b21f4c76aaf991ad16a6c503b2deaa', 'php-cve-2024-3096.patch': '614b035732192ba9601fbb3ef5e9228238b702114ec8ad33653ba33e87a87940', 'php-cve-2024-5458.patch': '411a08a17380ae5c7fcd8fcb52f1dbbda164aa7c2688f01dba768d146609cee7', 'php-fpm-www.conf': '7fbee69282e4398e88728324e2f57efd013bab0e52b358d66452dede130d1ce1', 'php-fpm.conf': 'bb261d53b9b42bb163a7637bb373ffa18a20dddf27a3efe6cb5ed1b1cf5981a9', 'php-fpm.logrotate': '7d8279bebb9ffabc596a2699150e93d4ce4513245890b9b786d337288b19fa79', 'php-fpm.service': '2313ce7c0f16d88a8185ec0ffda5c72f8927bb4f289950d18573d26ac4dc774a', 'php-fpm.sysconfig': '87835ddbdb7747105190cb611c391ffbe77732115a0ce8ea17b1082e69b9380a', 'php-fpm.wants': '846297e91ba02bd0e29b6635eeddcca01a7ad4faf5a8f27113543804331d0328', 'php.conf': '2f45408c6f0b0b64300218a590e9d7a7fa850d80ba579c8bf8b0825d17d966b2', 'php.conf2': '61279aedd207fba6ad38fd3d4793ef95b8ddcbcb9cb7421a43d4831eaad48131', 'php.ini': '76d2418fbe0d83d44fe103e4bcef1ae8a3ad5fefdb125966918277ab7900883d', 'php.modconf': '07bf65bfa5c58189e5de72cd8b989499fb993e122351eda5a11cbcbc24b5f23f', 'php.ztsmodconf': '4be354afe67b216e582f592886d9bbedb6be37898adb5fee7fac36db8c0853df', 'php74.spec': '26cba4921765723a0dc30662e0a8c349a121c8f8f869829fbd85eab38bc94586'}

def _rb_render_legacy_spec(original):
    if hashlib.sha256(original).hexdigest() != RB_PACKAGING['php74.spec']:
        raise RuntimeError('Remi EL7 SPEC differs from the pinned upstream packaging commit')
    value = original.decode('utf-8')
    replacements = [
        ('%global upver        7.4.33', '%global upver        ' + RB_VERSION),
        ('Release: 15%{?dist}', 'Release: ' + RB_RELEASE),
        ('Source0: http://www.php.net/distributions/php-%{upver}%{?rcver}.tar.xz',
         'Source0: ' + RB_SOURCE_URL),
        ('Source20: https://www.php.net/distributions/php-keyring.gpg\n', ''),
        ('Source21: https://www.php.net/distributions/php-%{upver}%{?rcver}.tar.xz.asc\n', ''),
        ("%{?gpgverify:%{gpgverify} --keyring='%{SOURCE20}' --signature='%{SOURCE21}' --data='%{SOURCE0}'}",
         "printf '" + RB_SOURCE_SHA + "  %s\\n' '%{SOURCE0}' | sha256sum -c -"),
        ('# WIP\n', '# WIP\nPatch400: ' + BP_TEST_PATCH_NAME + '\n'),
        ('# WIP patch\n', '# WIP patch\n%patch -P400 -p1 -F0 -b .phpguardtests\n'),
        ('rm ext/date/tests/bug33415-2.phpt', '# Keep the timezone regression repaired by Patch400.'),
        ('pver=$(sed -n \'/#define PHP_VERSION /{s/.* "//;s/".*$//;p}\' main/php_version.h)',
         'pver=$(sed -n \'s/^AC_INIT(\\[PHP\\],\\[\\([^]]*\\)\\].*/\\1/p\' configure.ac)'),
        ('make test TESTS=-j4', 'make test TESTS=-j%{phpguard_jobs}'),
        ('  #exit 1\n', '  exit 1\n'),
        ('%changelog\n', '%changelog\n* Fri Oct 23 2026 PHP Guard local rebuild <noreply@example.invalid> - '
         + RB_VERSION + '-' + RB_RELEASE + '\n'
         '- Rebuild pinned BaoTa source; preserve Remi EL7 packaging and existing security patches.\n'
         '- Require full regression suite and the CVE-2026-109618/109619 mitigation tests.\n'
         '- This is an unsigned local rebuild, not a Remi vendor release.\n\n'),
    ]
    for old, new in replacements:
        if value.count(old) != 1:
            raise RuntimeError('Pinned Remi SPEC anchor missing or ambiguous: ' + old[:60])
        value = value.replace(old, new, 1)
    return value.encode('utf-8')


def rb_compat_patch_bytes(original):
    """Remove only the already included commit from the fixed Remi input."""
    if hashlib.sha256(original).hexdigest() != RB_PACKAGING['php-cve-2023-0662.patch']:
        raise RuntimeError('Original Remi CVE-2023-0662 patch differs from the pinned input')
    first = ('From ' + RB_CVE203_INCLUDED_COMMIT + ' Mon Sep 17 00:00:00 2001\n').encode('ascii')
    following = b'From 472db3ee3a00ac00d36019eee0b3b7362334481c Mon Sep 17 00:00:00 2001\n'
    if original.count(first) != 1 or original.count(following) != 1 or original.index(first) >= original.index(following):
        raise RuntimeError('Fixed Remi CVE-2023-0662 commit boundaries changed')
    header = (b'PHP Guard adaptation for pinned BaoTa PHP 7.4.34 source.\n'
              b'Retain the upload-warning fix and both Remi NEWS commits.\n'
              b'Commit 8ec78d28d20c82c75c4747f44c52601cfdb22516 is already present\n'
              b'in this fixed source archive and must not be applied in reverse.\n'
              b'Original PHP Group changes: PHP License 3.01.\n\n')
    result = header + original[:original.index(first)] + original[original.index(following):]
    if hashlib.sha256(result).hexdigest() != RB_CVE203_SHA:
        raise RuntimeError('Adapted Remi CVE-2023-0662 patch SHA256 mismatch')
    return result


def rb_source_guard(hashes):
    return "printf '%s\\n' " + ' '.join("'%s  %s'" % (digest, name)
        for name, digest in sorted(hashes.items())) + ' | sha256sum -c -\n'


def rb_render_spec(original):
    value = _rb_render_legacy_spec(original).decode('utf-8')
    replacements = [
        # Remi uses system tzdata. Patch400's exact Iran 1977 expectations
        # require the historical correction first shipped in IANA 2022b.
        ('BuildRequires: gnupg2\n', 'BuildRequires: gnupg2\nBuildRequires: tzdata >= 2022b\n'),
        ('Patch203: php-cve-2023-0662.patch', 'Patch203: ' + RB_CVE203_PATCH),
        ('%patch -P203 -p1 -b .cve0662\n',
         '# Verify the fixed source already contains the multipart body-part limit.\n'
         + rb_source_guard(RB_CVE203_BEFORE) + '%patch -P203 -p1 -b .cve0662\n'),
        ('%patch -P400 -p1 -F0 -b .phpguardtests\n',
         '%patch -P400 -p1 -F0 -b .phpguardtests\n'
         '# The complete patch stack must preserve the body limit and add the warning limit.\n'
         + rb_source_guard(RB_CVE203_AFTER)),
    ]
    for old, new in replacements:
        if value.count(old) != 1:
            raise RuntimeError('Fixed Remi compatibility anchor missing or ambiguous')
        value = value.replace(old, new, 1)
    return value.encode('utf-8')


def rb_input_hashes():
    values = dict(RB_PACKAGING)
    values.update({RB_ARCHIVE: RB_SOURCE_SHA, BP_TEST_PATCH_NAME: BP_TEST_PATCH_SHA,
                   RB_CVE203_PATCH: RB_CVE203_SHA})
    return values


def rb_verify_prepared(folder):
    inputs = os.path.join(folder, 'inputs')
    for name, digest in rb_input_hashes().items():
        path = os.path.join(inputs, name)
        if os.path.islink(path) or not os.path.isfile(path):
            raise RuntimeError('Prepared input is missing or not a regular file: ' + name)
        bp_verify(path, digest)
    bp_verify_baota_archive(os.path.join(inputs, RB_ARCHIVE))
    spec = os.path.join(folder, 'php74-baota.spec')
    with open(os.path.join(inputs, 'php74.spec'), 'rb') as handle:
        expected = rb_render_spec(handle.read())
    if os.path.islink(spec):
        raise RuntimeError('Prepared SPEC must not be a symlink')
    with open(spec, 'rb') as handle:
        if handle.read() != expected:
            raise RuntimeError('Prepared SPEC changed; do not execute edited recipe as a privileged user')
    return inputs


def rb_atomic_prepare_file(folder, relative, content):
    # Keep temporary files outside inputs so a killed migration can be retried
    # without treating a partial input as a trusted patch. rename is atomic.
    fd, temporary = tempfile.mkstemp(prefix='.phpguard-remi-', dir=folder)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(temporary, os.path.join(folder, relative))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def rb_migrate_prepared(folder):
    """Upgrade only the exact old preparation, including interrupted writes."""
    inputs = os.path.join(folder, 'inputs')
    if any(os.path.islink(path) or not os.path.isdir(path) for path in (folder, inputs)):
        raise RuntimeError('Prepared Remi directory must be a regular directory')
    previous = dict(rb_input_hashes())
    previous.pop(RB_CVE203_PATCH)
    names = set(os.listdir(inputs))
    if not set(previous).issubset(names) or names - set(rb_input_hashes()):
        raise RuntimeError('Prepared Remi directory has missing or unknown inputs')
    for name, digest in previous.items():
        path = os.path.join(inputs, name)
        if os.path.islink(path) or not os.path.isfile(path):
            raise RuntimeError('Prepared input is missing or not a regular file: ' + name)
        bp_verify(path, digest)
    bp_verify_baota_archive(os.path.join(inputs, RB_ARCHIVE))
    if RB_CVE203_PATCH in names:
        path = os.path.join(inputs, RB_CVE203_PATCH)
        if os.path.islink(path) or not os.path.isfile(path):
            raise RuntimeError('Prepared compatibility patch is not a regular file')
        bp_verify(path, RB_CVE203_SHA)
    with open(os.path.join(inputs, 'php74.spec'), 'rb') as handle:
        original = handle.read()
    old_spec, new_spec = _rb_render_legacy_spec(original), rb_render_spec(original)
    old_sha, new_sha = (hashlib.sha256(value).hexdigest() for value in (old_spec, new_spec))
    spec_path, report_path = os.path.join(folder, 'php74-baota.spec'), os.path.join(folder, 'prepare.json')
    if any(os.path.islink(path) or not os.path.isfile(path) for path in (spec_path, report_path)):
        raise RuntimeError('Prepared Remi SPEC/report must be regular files')
    with open(spec_path, 'rb') as handle:
        actual = handle.read()
    if actual not in (old_spec, new_spec):
        raise RuntimeError('Prepared Remi SPEC changed; refusing automatic recipe migration')
    with open(report_path) as handle:
        report = json.load(handle)
    expected = {'recipe': RB_RECIPE, 'state': 'sources_prepared_not_built',
                'packaging_commit': RB_COMMIT, 'target_version': RB_VERSION,
                'target_release': RB_RELEASE, 'source_signature_verified': False}
    if any(report.get(key) != value for key, value in expected.items()):
        raise RuntimeError('Prepared Remi report is not a recognized fixed recipe')
    old_report = report.get('inputs') == previous and report.get('spec_sha256') == old_sha
    new_report = report.get('inputs') == rb_input_hashes() and report.get('spec_sha256') == new_sha
    if (not (old_report or new_report) or
            (actual == new_spec and RB_CVE203_PATCH not in names) or
            (new_report and actual != new_spec)):
        raise RuntimeError('Prepared Remi recipe state is inconsistent')
    if new_report:
        return False
    with open(os.path.join(inputs, 'php-cve-2023-0662.patch'), 'rb') as handle:
        adapted = rb_compat_patch_bytes(handle.read())
    rb_atomic_prepare_file(folder, os.path.join('inputs', RB_CVE203_PATCH), adapted)
    rb_atomic_prepare_file(folder, 'php74-baota.spec', new_spec)
    report.update({'tool_version': VERSION, 'inputs': rb_input_hashes(), 'spec_sha256': new_sha,
                   'recipe_update': {'previous_spec_sha256': old_sha,
                                     'reason': 'Preserve existing multipart body limit; add missing warning limit',
                                     'existing_build_logs_preserved': True}})
    rb_atomic_prepare_file(folder, 'prepare.json',
                           (json.dumps(report, ensure_ascii=True, indent=2) + '\n').encode('utf-8'))
    return True


def rb_prepare(args):
    folder = os.path.abspath(args.output_dir)
    if os.path.lexists(folder):
        if rb_migrate_prepared(folder):
            say('已核验并更新旧 Remi 准备目录的重复安全补丁处理；原有构建日志保留。')
        rb_verify_prepared(folder)
        say('已复用并重新校验 Remi EL7 构建输入：' + folder)
        return 0
    os.makedirs(folder, 0o700)
    inputs = os.path.join(folder, 'inputs')
    os.mkdir(inputs, 0o700)
    report = {'tool_version': VERSION, 'recipe': RB_RECIPE, 'state': 'preparing',
              'deployed': False, 'packaging_commit': RB_COMMIT,
              'packaging_origin': RB_BASE_URL, 'target_version': RB_VERSION,
              'target_release': RB_RELEASE, 'inputs': rb_input_hashes(),
              'source_signature_verified': False,
              'provenance': 'Pinned Remi HTTPS git files and pinned BaoTa HTTPS source; not a signed vendor SRPM'}
    report_path = os.path.join(folder, 'prepare.json')
    write_json(report_path, report)
    try:
        for name, digest in sorted(RB_PACKAGING.items()):
            local = os.path.join(args.packaging_dir, name) if getattr(args, 'packaging_dir', None) else None
            bp_fetch(local, RB_BASE_URL + name + '?id=' + RB_COMMIT,
                     digest, os.path.join(inputs, name))
        bp_fetch(getattr(args, 'source_tar', None), RB_SOURCE_URL, RB_SOURCE_SHA,
                 os.path.join(inputs, RB_ARCHIVE))
        bp_verify_baota_archive(os.path.join(inputs, RB_ARCHIVE))
        with open(os.path.join(inputs, BP_TEST_PATCH_NAME), 'wb') as handle:
            handle.write(BP_TEST_PATCH)
        with open(os.path.join(inputs, 'php-cve-2023-0662.patch'), 'rb') as handle:
            adapted = rb_compat_patch_bytes(handle.read())
        rb_atomic_prepare_file(folder, os.path.join('inputs', RB_CVE203_PATCH), adapted)
        with open(os.path.join(inputs, 'php74.spec'), 'rb') as handle:
            rendered = rb_render_spec(handle.read())
        with open(os.path.join(folder, 'php74-baota.spec'), 'wb') as handle:
            handle.write(rendered)
        report.update({'state': 'sources_prepared_not_built', 'spec_sha256': hashlib.sha256(rendered).hexdigest()})
        write_json(report_path, report)
        say('CentOS 7 / Remi 源码与原生 SPEC 已准备：' + folder)
        say('保留原 Remi 功能及安全补丁；尚未编译、安装或验证业务。')
        return 0
    except Exception as exc:
        report.update({'state': 'prepare_failed', 'error': as_text(exc)})
        write_json(report_path, report)
        raise


def rb_host_supported(host):
    return (host.get('platform') == 'linux' and host.get('os_id') in ('centos', 'rhel') and
            re.match(r'^7(?:\.|$)', host.get('os_version') or '') is not None and
            host.get('architecture') == 'x86_64')


def rb_definitions(top, jobs):
    return ['_topdir ' + top, '_tmppath ' + os.path.join(top, 'tmp'),
            'dist .el7.remi', 'rhel 7', 'runselftest 1', '_default_patch_fuzz 0',
            'phpguard_jobs %d' % jobs, '_smp_mflags -j%d' % jobs]


def rb_rpmbuild_command(top, jobs):
    command = [bp_tool('rpmbuild')]
    for value in rb_definitions(top, jobs):
        command += ['--define', value]
    return command


def rb_doctor(args):
    host = bp_doctor_host()
    blockers = []
    if not rb_host_supported(host):
        blockers.append('此配方需要 CentOS 7 / RHEL 7 x86_64 构建机；不得在 EL8/9、AL2 或其他系统复用。')
    if host.get('uid') == 0:
        blockers.append('编译必须由普通用户运行；root 仅负责安装构建依赖。')
    tools = {}
    for name in RB_TOOLS:
        try: tools[name] = bp_tool(name)
        except RuntimeError: tools[name] = None
    missing = [name for name in RB_TOOLS if not tools[name]]
    if missing:
        blockers.append('缺少构建工具：' + ', '.join(missing))
    preparation = 'not_prepared'
    if args.work_dir:
        try:
            rb_verify_prepared(os.path.abspath(args.work_dir))
            preparation = 'verified_inputs'
        except Exception as exc:
            blockers.append('源码准备未通过：' + as_text(exc))
    else:
        blockers.append('需要先 prepare 并提供 --work-dir。')
    report = {'tool_version': VERSION, 'recipe': RB_RECIPE, 'host': host,
              'tools': tools, 'blockers': blockers, 'preparation': preparation,
              'state': 'build_preflight_blocked' if blockers else 'ready_for_dependency_check',
              'read_only': True, 'deployed': False,
              'dependency_check': 'rpmbuild -bp performs exact native SPEC dependency validation before compilation',
              'warnings': ['CentOS 7 已停止维护；构建依赖仅使用现有已配置仓库，不自动切换 Vault 或引入第三方源。',
                           '此配方重建 Remi 普通 php-* 包；不适用于 php74-php-* SCL、IUS 或其他来源。']}
    say(json.dumps(report, ensure_ascii=False, indent=2))
    return 10 if blockers else 0


def rb_smoke_tests(top):
    results = []
    for subdir in RB_SMOKE_SAPIS:
        php = os.path.join(top, 'BUILD', 'php-' + RB_VERSION, subdir, 'sapi', 'cli', 'php')
        if not os.path.isfile(php):
            raise RuntimeError('Built Remi CLI missing: ' + subdir)
        version = run_cmd([php, '-n', '-r', 'echo PHP_VERSION;'], timeout=15)
        if version['code'] or version['stdout'] != RB_VERSION:
            raise RuntimeError('Built Remi CLI does not report ' + RB_VERSION)
        code = ('register_shutdown_function(function(){fwrite(STDERR,"PHP_GUARD_SHUTDOWN_RAN");});'
                '$v=str_repeat("x",32*1024*1024);')
        result = run_cmd([php, '-n', '-d', 'memory_limit=16M', '-r', code], timeout=15,
                         env={'USE_ZEND_ALLOC': '1'})
        if (result['code'] != 1 or 'Allowed memory size' not in result['stderr'] or
                'PHP_GUARD_SHUTDOWN_RAN' in result['stdout'] + result['stderr']):
            raise RuntimeError('Built Remi OOM mitigation regression failed: ' + subdir)
        results.append({'sapi': subdir, 'version': RB_VERSION, 'oom_exit': 1,
                        'shutdown_callback_ran': False})
    return results


def rb_multipart_smoke_tests(top):
    php = os.path.join(top, 'BUILD', 'php-' + RB_VERSION, 'build-cgi', 'sapi', 'cgi', 'php-cgi')
    if os.path.islink(php) or not os.path.isfile(php):
        raise RuntimeError('Built Remi CGI is missing for multipart security regressions')
    directory = tempfile.mkdtemp(prefix='multipart-regressions-', dir=os.path.dirname(top))
    script = os.path.join(directory, 'probe.php')
    with open(script, 'w') as handle:
        # Remi builds JSON as a shared extension. Keep this -n probe dependent
        # only on core functions, with exact serialization of the fixed input.
        handle.write('<?php echo "\\nPHP_GUARD_MULTIPART=" . PHP_VERSION . "|" . '
                     'serialize($_POST) . "|" . serialize(array_keys($_FILES)) . "\\n";')
    boundary = 'phpguard-fixed-multipart-boundary'
    fields = ('--' + boundary + '\r\nContent-Disposition: form-data; name="first"\r\n\r\none\r\n'
              '--' + boundary + '\r\nContent-Disposition: form-data; name="second"\r\n\r\ntwo\r\n'
              '--' + boundary + '--\r\n').encode('ascii')
    files = b''
    for name in ('first_upload', 'second_upload'):
        files += ('--' + boundary + '\r\nContent-Disposition: form-data; name="' + name +
                  '"; filename="probe.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n').encode('ascii')
    files += ('--' + boundary + '--\r\n').encode('ascii')
    cases = [
        ('body_parts_limit', fields, 1, 20, 'a:1:{s:5:"first";s:3:"one";}',
         'Multipart body parts limit exceeded 1. To increase the limit change max_multipart_body_parts in php.ini.'),
        ('file_upload_limit', files, 1000, 0, 'a:0:{}',
         'Maximum number of allowable file uploads has been exceeded')]
    results = []
    for index, (name, body, parts_limit, files_limit, expected_post, warning) in enumerate(cases):
        # On Linux, PHP reopens error_log=/dev/stderr with O_APPEND and a
        # separate offset. CGI stdout can then overwrite the same regular log.
        # Keep PHP diagnostics separate from bm_run's captured CGI response.
        error_log = os.path.join(directory, name + '.errors.log')
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC',
               'PHPRC': '/dev/null', 'PHP_INI_SCAN_DIR': '/dev/null', 'USE_ZEND_ALLOC': '1',
               'GATEWAY_INTERFACE': 'CGI/1.1', 'SERVER_PROTOCOL': 'HTTP/1.1',
               'SERVER_NAME': '127.0.0.1', 'SERVER_PORT': '80', 'REDIRECT_STATUS': '200',
               'REQUEST_METHOD': 'POST', 'SCRIPT_FILENAME': script, 'SCRIPT_NAME': '/probe.php',
               'CONTENT_TYPE': 'multipart/form-data; boundary=' + boundary,
               'CONTENT_LENGTH': str(len(body))}
        argv = [php, '-n']
        settings = ['cgi.force_redirect=0', 'display_errors=0', 'log_errors=1', 'error_log=' + error_log,
                    'html_errors=0', 'error_reporting=-1', 'file_uploads=1', 'max_input_vars=1000',
                    'post_max_size=1M', 'max_input_time=30', 'upload_tmp_dir=' + directory,
                    'sys_temp_dir=' + directory, 'max_multipart_body_parts=%d' % parts_limit,
                    'max_file_uploads=%d' % files_limit]
        for setting in settings:
            argv += ['-d', setting]
        log = os.path.join(directory, name + '.log')
        bm_run(argv, log, cwd=directory, env=env, data=body, timeout=30, interval=5)
        with open(log, 'rb') as handle:
            output = as_text(handle.read())
        if os.path.islink(error_log) or not os.path.isfile(error_log):
            raise RuntimeError('Built Remi CGI multipart regression failed: ' + name +
                               '; PHP warning log is missing: ' + error_log)
        with open(error_log, 'rb') as handle:
            errors = as_text(handle.read())
        combined = output + '\n' + errors
        values = re.findall(r'^PHP_GUARD_MULTIPART=(.+)$', output, re.M)
        expected = RB_VERSION + '|' + expected_post + '|a:0:{}'
        if (values != [expected] or
                errors.count(warning) != 1 or len(re.findall(r'PHP Warning:', combined)) != 1 or
                re.search(r'(?:PHP )?(?:Fatal error|Parse error|Notice|Deprecated):', combined)):
            raise RuntimeError('Built Remi CGI multipart regression failed: ' + name +
                               '; response log: ' + log + '; warning log: ' + error_log)
        results.append(dict(RB_MULTIPART_EXPECTED[index]))
    return results


def rb_check_artifacts(paths, rpm):
    artifacts, names = [], set()
    for path in paths:
        output = bp_call([rpm, '-qp', '--qf', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}', path])
        fields = output.strip().split('\t')
        if len(fields) != 5:
            raise RuntimeError('Unexpected rebuilt Remi RPM metadata')
        name, version, release, arch, source = fields
        if (version != RB_VERSION or release != RB_RELEASE or arch not in ('x86_64', 'noarch') or
                source != 'php-' + RB_VERSION + '-' + RB_RELEASE + '.src.rpm' or
                not re.match(r'^php(?:-[a-z0-9-]+)?$', name)):
            raise RuntimeError('Unexpected rebuilt Remi RPM identity: ' + os.path.basename(path))
        filename = '%s-%s-%s.%s.rpm' % (name, version, release, arch)
        if os.path.basename(path) != filename or name in names:
            raise RuntimeError('Ambiguous rebuilt Remi artifact identity')
        names.add(name)
        artifacts.append({'file': filename, 'sha256': bp_hash(path), 'name': name,
                          'version': version, 'release': release, 'arch': arch})
    if not RB_CORE_NAMES.issubset(names):
        raise RuntimeError('Incomplete Remi core RPM set: ' + ', '.join(sorted(RB_CORE_NAMES - names)))
    return artifacts


def rb_build(args):
    global RB_LAST_BUILD_REPORT
    host = bp_doctor_host()
    if not rb_host_supported(host):
        raise RuntimeError('This Remi rebuild recipe only supports CentOS 7 / RHEL 7 x86_64')
    if os.geteuid() == 0:
        raise RuntimeError('Run Remi RPM compilation as a normal user, not root')
    if isinstance(args.jobs, bool) or not isinstance(args.jobs, int) or args.jobs < 1 or args.jobs > 64:
        raise RuntimeError('Build concurrency must be between 1 and 64')
    folder = os.path.abspath(args.work_dir)
    if not re.match(r'^/[A-Za-z0-9_./-]+$', folder):
        raise RuntimeError('Use a simple absolute ASCII build path containing only letters, numbers, /_.-')
    inputs = rb_verify_prepared(folder)
    build = tempfile.mkdtemp(prefix='build-', dir=folder)
    RB_LAST_BUILD_REPORT = os.path.join(build, 'build.json')
    report = {'tool_version': VERSION, 'recipe': RB_RECIPE, 'state': 'building', 'deployed': False,
              'stage': 'prepare_and_dependencies', 'host': host, 'packaging_commit': RB_COMMIT,
              'inputs': rb_input_hashes(), 'target_version': RB_VERSION, 'target_release': RB_RELEASE,
              'upstream_commit': BP_COMMIT, 'source_sha256': RB_SOURCE_SHA,
              'source_signature_verified': False, 'signed': False, 'tests_required': True,
              'provenance': 'Pinned Remi HTTPS git files and pinned BaoTa HTTPS source; not a signed vendor SRPM'}
    write_json(RB_LAST_BUILD_REPORT, report)
    try:
        top = os.path.join(build, 'rpmbuild')
        for name in ('SOURCES', 'BUILD', 'BUILDROOT', 'RPMS', 'SPECS', 'SRPMS', 'tmp'):
            os.makedirs(os.path.join(top, name), 0o700)
        for name in rb_input_hashes():
            if name != 'php74.spec':
                shutil.copyfile(os.path.join(inputs, name), os.path.join(top, 'SOURCES', name))
        spec = os.path.join(top, 'SPECS', 'php74-baota.spec')
        with open(os.path.join(inputs, 'php74.spec'), 'rb') as handle:
            rendered = rb_render_spec(handle.read())
        with open(spec, 'wb') as handle:
            handle.write(rendered)
        command = rb_rpmbuild_command(top, args.jobs)
        report.update({'spec_sha256': hashlib.sha256(rendered).hexdigest(),
                       'regression_patch_sha256': BP_TEST_PATCH_SHA,
                       'rpm_definitions': rb_definitions(top, args.jobs)})
        write_json(RB_LAST_BUILD_REPORT, report)
        say('正在验证 CentOS 7 / Remi 原生依赖与完整补丁栈：' + os.path.join(build, 'prep.log'))
        bp_call(command + ['-bp', spec], log=os.path.join(build, 'prep.log'))
        report['stage'] = 'compile_test_package'
        report['build_monitor'] = {'timeout_seconds': BM_TIMEOUT_SECONDS,
                                   'interval_seconds': BM_INTERVAL_SECONDS,
                                   'progress_report': os.path.join(build, 'build.log.progress.json')}
        write_json(RB_LAST_BUILD_REPORT, report)
        say('正在编译 Remi 兼容 RPM 并运行完整测试：' + os.path.join(build, 'build.log'))
        bp_call(command + ['-ba', spec], log=os.path.join(build, 'build.log'))
        report['stage'] = 'verify_tests_and_artifacts'
        write_json(RB_LAST_BUILD_REPORT, report)
        report['php_selftest_summary'] = bp_selftest_summary(os.path.join(build, 'build.log'))
        report['mitigation_smoke_tests'] = rb_smoke_tests(top)
        report['multipart_smoke_tests'] = rb_multipart_smoke_tests(top)
        report['artifacts'] = rb_check_artifacts(sorted(glob.glob(os.path.join(top, 'RPMS', '*', '*.rpm'))), bp_tool('rpm'))
        srpm = os.path.join(top, 'SRPMS', 'php-' + RB_VERSION + '-' + RB_RELEASE + '.src.rpm')
        if not os.path.isfile(srpm):
            raise RuntimeError('Rebuilt Remi source RPM missing')
        report.update({'source_rpm': {'file': os.path.basename(srpm), 'sha256': bp_hash(srpm)},
                       'state': 'built_not_deployed', 'stage': 'complete',
                       'php_selftests_passed': True, 'business_tests_passed': False})
        write_json(RB_LAST_BUILD_REPORT, report)
        say('Remi 原生 RPM 已构建并通过源码测试，尚未安装：' + os.path.join(top, 'RPMS'))
        return 0
    except Exception as exc:
        report.update({'state': 'build_failed', 'error': as_text(exc),
                       'failure_summary': bp_failure_summary(build, report.get('stage'))})
        write_json(RB_LAST_BUILD_REPORT, report)
        say('构建未完成；记录：' + RB_LAST_BUILD_REPORT)
        bp_print_failure_summary(report['failure_summary'])
        raise


def remi_build_main(argv):
    parser = argparse.ArgumentParser(prog='php-cve-guard.sh build-baota-remi-el7-php74',
        description='保留 Remi EL7 原生打包与安全补丁，以宝塔 7.4.34 源码构建 PHP RPM；不自动安装。')
    parser.add_argument('action', choices=['prepare', 'doctor', 'build'])
    parser.add_argument('--output-dir')
    parser.add_argument('--work-dir')
    parser.add_argument('--source-tar', help='prepare：可选离线宝塔源码，必须匹配固定 SHA256')
    parser.add_argument('--packaging-dir', help='prepare：可选离线固定 Remi git 文件目录，逐文件校验 SHA256')
    parser.add_argument('--jobs', type=int, default=2)
    bm_add_arguments(parser)
    args = parser.parse_args(argv)
    bm_configure(args)
    if args.jobs < 1 or args.jobs > 64:
        parser.error('--jobs must be between 1 and 64')
    if args.action == 'prepare':
        if not args.output_dir or args.work_dir:
            parser.error('prepare requires --output-dir and does not accept --work-dir')
    elif args.output_dir or args.source_tar or args.packaging_dir:
        parser.error('input overrides apply only to prepare')
    elif args.action == 'build' and not args.work_dir:
        parser.error('build requires --work-dir')
    try:
        if args.action == 'prepare': return rb_prepare(args)
        if args.action == 'doctor': return rb_doctor(args)
        return rb_build(args)
    except Exception as exc:
        say('CentOS 7 / Remi 构建未完成：' + as_text(exc))
        return 20
