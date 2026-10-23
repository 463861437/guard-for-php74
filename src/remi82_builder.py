# -*- coding: utf-8 -*-
"""PHP 8.2.35 + pinned Remi EL7 system/SCL native packaging; never installs RPMs."""

R82_RECIPE = 'upstream-remi-el7-php82'
R82_VERSION = '8.2.35'
R82_RELEASE = '1.el7.remi.phpguard20261023.1'
R82_ARCHIVE = 'php-8.2.35.tar.xz'
R82_SOURCE_URL = 'https://www.php.net/distributions/' + R82_ARCHIVE
R82_SOURCE_SHA = '5737b98601fe5ab1b8c5db0c82ed3158acb9283ed3081ffe2faffb9ac81455e6'
R82_SIGNATURE = R82_ARCHIVE + '.asc'
R82_SIGNATURE_SHA = '79af893d2e7571e0e312754af8e5536179d722b6a102481b888c28d605c4aca0'
R82_KEYRING = 'php-keyring.gpg'
R82_KEYRING_SHA = '43fcb3eaf65536cb0833c229b492c70cfad8562138164dd13673e08925d6c56c'
R82_SIGNATURE_FINGERPRINT = 'E60913E4DF209907D8E30D96659A97C9CF2A795A'
R82_PATCH_COMMIT = '68bc1389a1eacb0f2f388780b3282471ec1374ce'
R82_REFRESHED_PATCHES = ('php-8.2.23-systzdata-v24.patch', 'php-8.2.25-phpinfo.patch')
R82_PATCH_BASE_URL = 'https://git.remirepo.net/git/rpms/php/php82.git/plain/'
R82_LAST_BUILD_REPORT = None
R82_OPENSSL_COMPAT_PATCH = 'php82-el7-openssl10-compat.patch'
R82_OPENSSL_COMPAT_SHA = '574d694fe4f480ee99bae370145b016107246487206ab21eadb88128236aafd4'
# PHP-3.01; exact accessor and version guard from signed PHP 8.2.35 openssl.c.
R82_OPENSSL_COMPAT_BYTES = b'From: Guard for PHP contributors\nSubject: [PATCH] openssl: expose the existing legacy ASN1 const accessor in xp_ssl\n\nCopyright (c) The PHP Group; PHP License 3.01.\nOrigin: PHP 8.2.35 ext/openssl/openssl.c, compatibility functions.\nhttps://github.com/php/php-src/blob/php-8.2.35/ext/openssl/openssl.c\n\nThe signed PHP 8.2.35 source already uses this accessor in openssl.c.\nReuse the identical implementation and API-version guard in the separate\nxp_ssl.c translation unit for OpenSSL 1.0.2. Peer-name and SAN validation\nare unchanged. Newer OpenSSL and LibreSSL APIs keep their native accessor.\n\n--- a/ext/openssl/xp_ssl.c\n+++ b/ext/openssl/xp_ssl.c\n@@ -36,6 +36,14 @@\n #include <openssl/bn.h>\n #include <openssl/dh.h>\n \n+#if PHP_OPENSSL_API_VERSION < 0x10100\n+/* Same legacy const accessor as ext/openssl/openssl.c. */\n+static const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *asn1)\n+{\n+\treturn M_ASN1_STRING_data(asn1);\n+}\n+#endif\n+\n #ifdef PHP_WIN32\n #include "win32/winutil.h"\n #include "win32/time.h"\n'
R82_TOOLS = ['rpm', 'rpmbuild', 'curl', 'gcc', 'g++', 'make', 'autoconf',
             'automake', 'libtool', 'patch', 'perl', 'sha256sum', 'xz']
R82_SECURITY_TESTS = (
    'ext/session/tests/rfc1867_no_user_code.phpt',
    'ext/session/tests/rfc1867_incomplete_class_reserved_props.phpt',
    'Zend/tests/oom_hard_limit_exceeded_during_complilation.phpt',
    'Zend/tests/oom_soft_limit_exceeded.phpt',
    'Zend/tests/oom_soft_limit_in_callback.phpt',
    'ext/openssl/tests/bug68879.phpt',
    'ext/openssl/tests/GHSA-xr7j-rvgx-xq5p.phpt',
)
# Reviewed EL7 defaults: system and SCL preserve the original optional-extension
# choices. rpmbuild independently verifies fully expanded dependencies.
R82_BUILD_REQUIRES = [
    'gnupg2', 'bzip2-devel', 'pkgconfig(libcurl) >= 7.29.0', 'httpd-devel >= 2.0.46-1',
    'pam-devel', 'libstdc++-devel', 'openssl-devel >= 1.0.2',
    'pkgconfig(sqlite3) >= 3.7.4', 'pkgconfig(zlib) >= 1.2.0.4',
    'smtpdaemon', 'pkgconfig(libedit)', 'bzip2', 'perl', 'autoconf', 'automake',
    'make', 'gcc', 'gcc-c++', 'libtool', 'libtool-ltdl-devel', 'systemtap-sdt-devel',
    '/bin/ps', 'tzdata', 'libacl-devel', 'pkgconfig(libsystemd) >= 209',
    'pkgconfig(libselinux)', 'pkgconfig(krb5)', 'pkgconfig(krb5-gssapi)',
    'libc-client-devel', 'pkgconfig(libsasl2)', 'openldap-devel', 'krb5-devel',
    'postgresql-devel', 'unixODBC-devel', 'pkgconfig(libxml-2.0) >= 2.7.6',
    'firebird-devel', 'net-snmp-devel', 'pkgconfig(libxslt) >= 1.1', 'pkgconfig(libexslt)',
    'oniguruma5php-devel', 'pkgconfig(gdlib) >= 2.3.3', 'gmp-devel', 'libdb-devel',
    'tokyocabinet-devel', 'lmdb-devel', 'libtidy-devel', 'freetds-devel >= 0.91',
    'aspell-devel >= 0.50.0', 'pkgconfig(icu-i18n) >= 73', 'pkgconfig(icu-io) >= 73',
    'pkgconfig(icu-uc) >= 73', 'pkgconfig(enchant-2)', 'pkgconfig(libsodium) >= 1.0.14',
    'pkgconfig(libffi)']

R82_PROFILES = {'system': {'commit': '1ab9a9ffc372334e3c063034087159eaa2b48093', 'base_url': 'https://git.remirepo.net/git/rpms/php/php82.git/plain/', 'spec_name': 'php82.spec', 'prefix': '', 'source_name': 'php', 'packaging': {'php.conf': '1ae4b506066eeae8e114575293d2468000e4f99f4c6c7930426d3c0f1dc6a748', 'php.ini': 'a7bc569f08dd17a02c2f2a8acfb7065ab155c04b60532e6673f49233b7c1ca33', 'macros.php': 'dc77edd8f8b6644888c4921d01747c499bea89e7a70709fb9539fcd26a69b3ea', 'php-fpm.conf': 'f5c32fe5a450d65a27177d43267c61c66d6d2165b3e515293678440319aeb0b7', 'php-fpm-www.conf': '7fbee69282e4398e88728324e2f57efd013bab0e52b358d66452dede130d1ce1', 'php-fpm.service': '2313ce7c0f16d88a8185ec0ffda5c72f8927bb4f289950d18573d26ac4dc774a', 'php-fpm.logrotate': '7d8279bebb9ffabc596a2699150e93d4ce4513245890b9b786d337288b19fa79', 'php-fpm.sysconfig': '87835ddbdb7747105190cb611c391ffbe77732115a0ce8ea17b1082e69b9380a', 'php.modconf': '500b887c43b1083ae65d50534e8567083f7041c7b63734a666760db7340b0361', 'php.conf2': '973f1b1afef05c03b629085f96d93adc9d08041cd43cb30d8eb83ab07e3dbd15', 'php-fpm.wants': '846297e91ba02bd0e29b6635eeddcca01a7ad4faf5a8f27113543804331d0328', 'nginx-fpm.conf': '54432bc051686f00b1685bad91a73f9a2fbe3b650c1fba4e9a4232363c4dfa99', 'nginx-php.conf': '88dfe176f02a0f8cba0a91711d1f5075bedbc01d2cdcd149e50890e2c71b3080', '10-opcache.ini': '64c58b25419713e281f20394a0af2208630a5b608aeabd2b9dc3f962261f3640', 'opcache-default.blacklist': '4eef0875e1a0c6a75b8a2bafd4ddc029b83be74dd336a6a99214b0c32808cb38', '20-oci8.ini': '4ac1b94139bf323ccd3b548d1e2dbdbde5e57dda3428b64bf1e7a0e3ae243250', '20-ffi.ini': 'f5e968fdd3eca54f3dab2399e243931cf16cd9da034f0364800aefab222271c0', 'php-7.4.0-httpd.patch': '844a7c2a0e014c2cd5de526019087052ce7b01a9863b749b2df4d7927d3663bb', 'php-7.2.0-includedir.patch': '6bdced1ae99f86dc4bd46cad07a212b329f2829d8852767e8fe79e6e1877b8de', 'php-8.0.0-embed.patch': 'c7736d68fd76c26a27a3f4c3e53ebb2f97cbe0017c442722d2fdf896115454d0', 'php-8.1.0-libdb.patch': '729bfdf88f7be05dccc459075855a407cdd77302bbb806b896f6f1ff531d4634', 'php-8.2.0-curl.patch': '1558bd7be340782f4a9fdfc4b8d64b1d6795b0ae99e541214252b74c51c5c486', 'php-8.2.0-parser.patch': '6c561eb20438481e9040de95c1abbc5e588d686ad6003ce549c5ef0cfd23e582', 'php-8.2.23-systzdata-v24.patch': '23983294045d2df9c1733403825042ca3eff75337a6810e5d06babd7e16adcea', 'php-7.4.0-phpize.patch': 'fee1ef9da805c498407ce1dc8ec26f0891b002b04947a752fb80e6d39761e058', 'php-7.4.0-ldap_r.patch': '4c1e296e1cb89c86dd1be82bf59623521c0e98e7c06ea0aed900641bcfc3cd75', 'php-8.0.7-argon2.patch': '1d2e5ce4a58fde146c9c0c77c593a0abbf627a0b6ed2766fc4023dc858b7e7e0', 'php-8.2.25-phpinfo.patch': '614777597f5a0bb2b66fbaf791ef6ea7a134fd16e2d104588f00497db4ee7635', 'php-7.2.0-oci8conf.patch': '94fd7e7872c9069899068fce1a24142ae864717a240a1e6be4e407276b60b2d8', 'php-7.4.0-datetests.patch': 'd78165ed88d315567f1eabc9a904e51c94fdee236a4ae571830d0c3f161ec157', 'php82.spec': '87a69f2ca9e82b67d6b743cd9dc5a08a0e5e27af72fa1993fa49a497ccec7a68'}, 'smoke_sapis': ['build-cgi', 'build-ztscli'], 'core_names': ['php', 'php-cli', 'php-common', 'php-fpm', 'php-opcache', 'php-pdo', 'php-mysqlnd', 'php-mbstring', 'php-xml']}, 'scl': {'commit': '475b78223d7a4bca5fc6d75aeee91f7be0613dc5', 'base_url': 'https://git.remirepo.net/git/rpms/scl-php82/php.git/plain/', 'spec_name': 'php.spec', 'prefix': 'php82-', 'source_name': 'php82-php', 'packaging': {'php.conf': '1ae4b506066eeae8e114575293d2468000e4f99f4c6c7930426d3c0f1dc6a748', 'php.ini': 'a7bc569f08dd17a02c2f2a8acfb7065ab155c04b60532e6673f49233b7c1ca33', 'macros.php': 'b3243ff3cbd79c229b4d5a98847f5f6c328a29a7046033d9492753020430df5b', 'php-fpm.conf': 'f5c32fe5a450d65a27177d43267c61c66d6d2165b3e515293678440319aeb0b7', 'php-fpm-www.conf': 'd346a632fc4e5a368bf5c375660a79ac60c9bd63819bedae388e17150c17bbca', 'php-fpm.service': '58911ad05ea7fa9448ef7bf4f3af2f834abace6607c9c7f601eb981b53ae4576', 'php-fpm.logrotate': '7d8279bebb9ffabc596a2699150e93d4ce4513245890b9b786d337288b19fa79', 'php-fpm.sysconfig': 'b3003b92f4d644f034f99cc8e06a52305a2b3f5bbeee843f351e8b2ec6a2950f', 'php.modconf': '500b887c43b1083ae65d50534e8567083f7041c7b63734a666760db7340b0361', 'php.conf2': 'a2ea5978876469b973590274664078556ad952fbc3983698b3b26ac2e15aab12', 'php-fpm.wants': '846297e91ba02bd0e29b6635eeddcca01a7ad4faf5a8f27113543804331d0328', '10-opcache.ini': '64c58b25419713e281f20394a0af2208630a5b608aeabd2b9dc3f962261f3640', 'opcache-default.blacklist': '4eef0875e1a0c6a75b8a2bafd4ddc029b83be74dd336a6a99214b0c32808cb38', '20-oci8.ini': '4ac1b94139bf323ccd3b548d1e2dbdbde5e57dda3428b64bf1e7a0e3ae243250', '20-ffi.ini': 'f5e968fdd3eca54f3dab2399e243931cf16cd9da034f0364800aefab222271c0', 'php-7.4.0-httpd.patch': '844a7c2a0e014c2cd5de526019087052ce7b01a9863b749b2df4d7927d3663bb', 'php-7.2.0-includedir.patch': 'b990ede60564fdfcd8528f04a1026f2bf130258bc23c8f921fac4c572241c74a', 'php-8.0.0-embed.patch': 'c7736d68fd76c26a27a3f4c3e53ebb2f97cbe0017c442722d2fdf896115454d0', 'php-8.1.0-libdb.patch': '729bfdf88f7be05dccc459075855a407cdd77302bbb806b896f6f1ff531d4634', 'php-8.2.0-curl.patch': '1558bd7be340782f4a9fdfc4b8d64b1d6795b0ae99e541214252b74c51c5c486', 'php-8.2.0-parser.patch': '6c561eb20438481e9040de95c1abbc5e588d686ad6003ce549c5ef0cfd23e582', 'php-8.2.23-systzdata-v24.patch': '23983294045d2df9c1733403825042ca3eff75337a6810e5d06babd7e16adcea', 'php-7.4.0-phpize.patch': 'fee1ef9da805c498407ce1dc8ec26f0891b002b04947a752fb80e6d39761e058', 'php-7.4.0-ldap_r.patch': '4c1e296e1cb89c86dd1be82bf59623521c0e98e7c06ea0aed900641bcfc3cd75', 'php-8.0.7-argon2.patch': '1d2e5ce4a58fde146c9c0c77c593a0abbf627a0b6ed2766fc4023dc858b7e7e0', 'php-8.2.25-phpinfo.patch': '614777597f5a0bb2b66fbaf791ef6ea7a134fd16e2d104588f00497db4ee7635', 'php-7.2.0-oci8conf.patch': '94fd7e7872c9069899068fce1a24142ae864717a240a1e6be4e407276b60b2d8', 'php-7.4.0-datetests.patch': 'd78165ed88d315567f1eabc9a904e51c94fdee236a4ae571830d0c3f161ec157', 'php.spec': '94453fb1dd66d35d2e633edf6949b888e9292741064085c686c2705e74b98d86'}, 'smoke_sapis': ['build-cgi'], 'core_names': ['php82-php', 'php82-php-cli', 'php82-php-common', 'php82-php-fpm', 'php82-php-opcache', 'php82-php-pdo', 'php82-php-mysqlnd', 'php82-php-mbstring', 'php82-php-xml']}}


def r82_profile(layout):
    if layout not in R82_PROFILES:
        raise RuntimeError('PHP 8.2 layout must be system or scl')
    return R82_PROFILES[layout]


def r82_build_requirements(layouts):
    if not layouts:
        raise RuntimeError('At least one PHP 8.2 layout must be selected')
    result = list(R82_BUILD_REQUIRES)
    for layout in layouts:
        r82_profile(layout)
    if 'scl' in layouts:
        result += ['scl-utils-build', 'php82-build = 8.2-5.el7.remi']
    return sorted(set(result))


def r82_input_hashes(layout):
    result = dict(r82_profile(layout)['packaging'])
    result.update({R82_ARCHIVE: R82_SOURCE_SHA, R82_SIGNATURE: R82_SIGNATURE_SHA,
                   R82_KEYRING: R82_KEYRING_SHA, R82_OPENSSL_COMPAT_PATCH: R82_OPENSSL_COMPAT_SHA})
    return result


def r82_gpg_tool():
    for name in ('gpg2', 'gpg'):
        try:
            return bp_tool(name)
        except RuntimeError:
            pass
    raise RuntimeError('PHP source signature verification requires gnupg2')


def r82_verify_source_signature(inputs, logdir):
    # An isolated keyring, pinned bytes and pinned signing fingerprint avoid
    # trusting user keyrings, gpg options or automatic remote key retrieval.
    for name, digest in ((R82_ARCHIVE, R82_SOURCE_SHA), (R82_SIGNATURE, R82_SIGNATURE_SHA),
                         (R82_KEYRING, R82_KEYRING_SHA)):
        bp_verify(os.path.join(inputs, name), digest)
    home = tempfile.mkdtemp(prefix='source-gpg-', dir=logdir)
    try:
        # php-keyring.gpg is ASCII armored. GnuPG 2.0 on EL7 requires a
        # dearmored keyring even though newer versions accept the armor.
        ring = os.path.join(home, 'php-release-keys.gpg')
        decoded = run_cmd([r82_gpg_tool(), '--no-options', '--homedir', home,
                           '--batch', '--dearmor', '--output', ring,
                           os.path.abspath(os.path.join(inputs, R82_KEYRING))], timeout=60)
        if decoded['code'] or not os.path.isfile(ring):
            raise RuntimeError('Pinned PHP release keyring could not be decoded')
        result = run_cmd([r82_gpg_tool(), '--no-options', '--homedir', home,
                          '--batch', '--no-default-keyring', '--keyring', ring,
                          '--status-fd', '1', '--verify',
                          os.path.join(inputs, R82_SIGNATURE), os.path.join(inputs, R82_ARCHIVE)], timeout=60)
        valid = re.findall(r'^\[GNUPG:\] VALIDSIG ([A-F0-9]+) ', result['stdout'], re.M)
        forbidden = re.search(r'^\[GNUPG:\] (?:BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|NO_PUBKEY)\b', result['stdout'], re.M)
        if result['code'] or valid != [R82_SIGNATURE_FINGERPRINT] or forbidden:
            raise RuntimeError('Pinned PHP source OpenPGP signature did not validate with its release-manager fingerprint')
        return {'verified': True, 'fingerprint': R82_SIGNATURE_FINGERPRINT,
                'archive_sha256': R82_SOURCE_SHA, 'keyring_sha256': R82_KEYRING_SHA}
    finally:
        shutil.rmtree(home)


def r82_render_spec(original, layout):
    profile = r82_profile(layout)
    if hashlib.sha256(original).hexdigest() != profile['packaging'][profile['spec_name']]:
        raise RuntimeError('PHP 8.2 Remi SPEC differs from the pinned packaging commit')
    value = original.decode('utf-8')
    def replace(old, new):
        if value.count(old) != 1:
            raise RuntimeError('Pinned PHP 8.2 SPEC anchor missing or ambiguous: ' + old[:80])
        return value.replace(old, new, 1)
    # New source includes the security fixes. Preserve EL7 layout, extension
    # ABI/provides, scriptlets and configuration-noreplace declarations.
    value = replace('%global upver' + ('          ' if layout == 'system' else '        ') + '8.2.20',
                    '%global upver        ' + R82_VERSION)
    value = replace('Release: 1%{?dist}', 'Release: ' + R82_RELEASE)
    value = replace('Source0: http://www.php.net/distributions/php-%{upver}%{?rcver}.tar.xz',
                    'Source0: ' + R82_SOURCE_URL)
    # Only these two context updates are replaced with current Remi equivalents.
    value = replace('php-8.1.0-systzdata-v24.patch', 'php-8.2.23-systzdata-v24.patch')
    value = replace('php-8.1.0-phpinfo.patch', 'php-8.2.25-phpinfo.patch')
    value = replace('Patch300: php-7.4.0-datetests.patch',
                    'Patch300: php-7.4.0-datetests.patch\n'
                    '# PHP-3.01 legacy API accessor from signed PHP 8.2.35 openssl.c.\n'
                    'Patch400: ' + R82_OPENSSL_COMPAT_PATCH)
    value = replace('%setup -q -n php-%{upver}%{?rcver}',
                    '%setup -q -n php-%{upver}%{?rcver}\n'
                    '%patch -P400 -p1 -b .openssl10-compat')
    value = replace("%{?gpgverify:%{gpgverify} --keyring='%{SOURCE20}' --signature='%{SOURCE21}' --data='%{SOURCE0}'}",
                    "printf '" + R82_SOURCE_SHA + "  %s\\n' '%{SOURCE0}' | sha256sum -c -")
    value = replace('make test TESTS=-j4', 'make test TESTS=-j%{phpguard_jobs}')
    value = replace('  #exit 1\n', '  exit 1\n')
    value = replace('%changelog\n', '%changelog\n* Fri Oct 23 2026 PHP Guard local rebuild <noreply@example.invalid> - '
                    + R82_VERSION + '-' + R82_RELEASE + '\n'
                    '- Rebuild signed official PHP 8.2.35 source with original Remi EL7 layout.\n'
                    '- Refresh matching upstream Remi timezone and phpinfo patch contexts.\n'
                    '- Reuse upstream legacy ASN1 const accessor in the TLS stream unit.\n'
                    '- Require the original complete test suite and dedicated security regressions.\n'
                    '- Unsigned local rebuild, not an official Remi release.\n\n')
    # On EL7 this macro normally defaults to one, but bind it explicitly in
    # both the SPEC and command to prevent user macros from skipping %check.
    value = value.replace('%bcond_without        tests', '%global with_tests 1')
    if '%global with_tests 1' not in value:
        raise RuntimeError('PHP 8.2 test enablement anchor missing')
    return value.encode('utf-8')


def r82_verify_archive(path):
    bp_verify(path, R82_SOURCE_SHA)
    # Python 2.7 tarfile cannot read XZ. Stream verified bytes through the native
    # decoder, never extract untrusted paths or load the entire source in RAM.
    decoder = subprocess.Popen([bp_tool('xz'), '--decompress', '--stdout', path],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    required = set(('main/php_version.h',) + R82_SECURITY_TESTS)
    found, count = set(), 0
    prefix = 'php-' + R82_VERSION
    try:
        archive = tarfile.open(fileobj=decoder.stdout, mode='r|')
        try:
            for member in archive:
                count += 1
                # tarfile 2.7 yields byte filenames even under the assembled
                # unicode_literals module. Decode explicitly; locale coercion
                # must not turn a valid UTF-8 fixture into an ASCII exception.
                try:
                    name = member.name.decode('utf-8') if isinstance(member.name, bytes) else member.name
                except UnicodeDecodeError:
                    raise RuntimeError('PHP 8.2 source archive contains an invalid UTF-8 path')
                if (count > 100000 or (name != prefix and not name.startswith(prefix + '/')) or
                        '..' in name.split('/') or name.startswith('/') or
                        not (member.isfile() or member.isdir())):
                    raise RuntimeError('Unsupported PHP 8.2 source archive member')
                relative = name[len(prefix) + 1:]
                if relative in required:
                    if relative in found or not member.isfile() or member.size > 1024 * 1024:
                        raise RuntimeError('Required PHP security source member is ambiguous')
                    found.add(relative)
                    if relative == 'main/php_version.h':
                        version = archive.extractfile(member).read()
                        if b'#define PHP_VERSION "8.2.35"' not in version:
                            raise RuntimeError('PHP source version header is unexpected')
        finally:
            archive.close()
        decoder.stdout.close()
        errors = decoder.stderr.read()
        if decoder.wait() or count < 10000 or found != required:
            raise RuntimeError('PHP 8.2 archive validation is incomplete')
    finally:
        if decoder.poll() is None:
            decoder.terminate()
            decoder.wait()
        decoder.stdout.close()
        decoder.stderr.close()


def r82_verify_prepared(folder, layout):
    profile = r82_profile(layout)
    if os.path.islink(folder) or not os.path.isdir(folder):
        raise RuntimeError('Prepared PHP 8.2 directory is not a regular directory')
    inputs = os.path.join(folder, 'inputs')
    if os.path.islink(inputs) or not os.path.isdir(inputs):
        raise RuntimeError('Prepared PHP 8.2 input directory is invalid')
    for name, digest in r82_input_hashes(layout).items():
        bp_verify(os.path.join(inputs, name), digest)
    r82_verify_archive(os.path.join(inputs, R82_ARCHIVE))
    with open(os.path.join(inputs, profile['spec_name']), 'rb') as handle:
        rendered = r82_render_spec(handle.read(), layout)
    path = os.path.join(folder, 'php82-guard.spec')
    if os.path.islink(path) or not os.path.isfile(path):
        raise RuntimeError('Prepared PHP 8.2 SPEC is missing or symbolic')
    with open(path, 'rb') as handle:
        if handle.read() != rendered:
            raise RuntimeError('Prepared PHP 8.2 SPEC differs from the fixed recipe')
    path = os.path.join(folder, 'prepare.json')
    if os.path.islink(path):
        raise RuntimeError('Prepared report is symbolic')
    with open(path) as handle:
        report = json.load(handle)
    expected = {'recipe': R82_RECIPE, 'layout': layout, 'packaging_commit': profile['commit'],
                'inputs': r82_input_hashes(layout), 'spec_sha256': hashlib.sha256(rendered).hexdigest(),
                'state': 'sources_prepared_not_built', 'source_signature_verified': True}
    if any(report.get(key) != value for key, value in expected.items()):
        raise RuntimeError('Prepared PHP 8.2 report does not match the selected layout and inputs')
    return inputs


def r82_write_compat_patch(inputs):
    if hashlib.sha256(R82_OPENSSL_COMPAT_BYTES).hexdigest() != R82_OPENSSL_COMPAT_SHA:
        raise RuntimeError('Embedded PHP 8.2 OpenSSL compatibility patch SHA256 mismatch')
    target = os.path.join(inputs, R82_OPENSSL_COMPAT_PATCH)
    with open(target, 'wb') as handle:
        handle.write(R82_OPENSSL_COMPAT_BYTES)
    bp_verify(target, R82_OPENSSL_COMPAT_SHA)


def r82_prepare(args):
    layout = args.layout
    profile = r82_profile(layout)
    folder = os.path.abspath(args.output_dir)
    if os.path.lexists(folder):
        inputs = r82_verify_prepared(folder, layout)
        r82_verify_source_signature(inputs, folder)
        say('已重新校验 PHP 8.2 Remi EL7 ' + layout + ' 输入：' + folder)
        return 0
    os.makedirs(folder, 0o700)
    inputs = os.path.join(folder, 'inputs')
    os.mkdir(inputs, 0o700)
    report = {'tool_version': VERSION, 'recipe': R82_RECIPE, 'layout': layout,
              'state': 'preparing', 'deployed': False, 'packaging_commit': profile['commit'],
              'packaging_refresh_commit': R82_PATCH_COMMIT, 'target_version': R82_VERSION,
              'target_release': R82_RELEASE, 'inputs': r82_input_hashes(layout),
              'source_signature_verified': False}
    report_path = os.path.join(folder, 'prepare.json')
    write_json(report_path, report)
    try:
        r82_write_compat_patch(inputs)
        for name, digest in sorted(profile['packaging'].items()):
            base, commit = ((R82_PATCH_BASE_URL, R82_PATCH_COMMIT) if name in R82_REFRESHED_PATCHES
                            else (profile['base_url'], profile['commit']))
            local = os.path.join(args.packaging_dir, name) if getattr(args, 'packaging_dir', None) else None
            bp_fetch(local, base + name + '?id=' + commit, digest, os.path.join(inputs, name))
        for name, digest, local in ((R82_ARCHIVE, R82_SOURCE_SHA, getattr(args, 'source_tar', None)),
                                    (R82_SIGNATURE, R82_SIGNATURE_SHA, getattr(args, 'signature', None)),
                                    (R82_KEYRING, R82_KEYRING_SHA, getattr(args, 'keyring', None))):
            bp_fetch(local, 'https://www.php.net/distributions/' + name, digest, os.path.join(inputs, name))
        r82_verify_archive(os.path.join(inputs, R82_ARCHIVE))
        signature = r82_verify_source_signature(inputs, folder)
        with open(os.path.join(inputs, profile['spec_name']), 'rb') as handle:
            rendered = r82_render_spec(handle.read(), layout)
        with open(os.path.join(folder, 'php82-guard.spec'), 'wb') as handle:
            handle.write(rendered)
        report.update({'state': 'sources_prepared_not_built', 'source_signature_verified': True,
                       'source_signature_fingerprint': signature['fingerprint'],
                       'spec_sha256': hashlib.sha256(rendered).hexdigest()})
        write_json(report_path, report)
        say('PHP 8.2.35 官方源码签名与 Remi EL7 ' + layout + ' 打包输入已核实；尚未编译或部署。')
        return 0
    except Exception as exc:
        report.update({'state': 'prepare_failed', 'error': as_text(exc)})
        write_json(report_path, report)
        raise


def r82_host_supported(host):
    return (host.get('platform') in ('linux', 'linux2') and
            host.get('os_id') in ('centos', 'rhel') and
            re.match(r'^7(?:\.|$)', host.get('os_version') or '') is not None and
            host.get('architecture') == 'x86_64')


def r82_definitions(top, jobs, layout):
    r82_profile(layout)
    values = ['_topdir ' + top, '_tmppath ' + os.path.join(top, 'tmp'),
              'dist .el7.remi', 'rhel 7', 'with_tests 1', '_default_patch_fuzz 0',
              'phpguard_jobs %d' % jobs, '_smp_mflags -j%d' % jobs]
    if layout == 'scl':
        values.append('scl php82')
    return values


def r82_rpmbuild_command(top, jobs, layout):
    command = [bp_tool('rpmbuild')]
    for definition in r82_definitions(top, jobs, layout):
        command += ['--define', definition]
    return command


def r82_doctor(args):
    host = bp_doctor_host()
    blockers = []
    profile = r82_profile(args.layout)
    if not r82_host_supported(host):
        blockers.append('此构建配方仅支持 CentOS 7 / RHEL 7 x86_64。')
    if host.get('uid') == 0:
        blockers.append('编译必须以普通用户执行；root 仅负责依赖安装和部署。')
    missing = []
    for name in R82_TOOLS:
        try:
            bp_tool(name)
        except RuntimeError:
            missing.append(name)
    try:
        r82_gpg_tool()
    except RuntimeError:
        missing.append('gnupg2')
    if missing:
        blockers.append('缺少构建工具：' + ', '.join(missing))
    try:
        if not args.work_dir:
            raise RuntimeError('需要 --work-dir 指向已 prepare 的目录')
        inputs = r82_verify_prepared(os.path.abspath(args.work_dir), args.layout)
        r82_verify_source_signature(inputs, os.path.abspath(args.work_dir))
    except Exception as exc:
        blockers.append('源码预检未通过：' + as_text(exc))
    report = {'tool_version': VERSION, 'recipe': R82_RECIPE, 'layout': args.layout,
              'host': host, 'blockers': blockers, 'read_only': True, 'deployed': False,
              'state': 'build_preflight_blocked' if blockers else 'ready_for_dependency_check',
              'dependencies': r82_build_requirements([args.layout]),
              'dependency_check': 'rpmbuild -bp validates native expanded requirements before compilation',
              'packaging_commit': profile['commit']}
    say(json.dumps(report, ensure_ascii=False, indent=2))
    return 10 if blockers else 0


def r82_selftest_summary(path, targeted=False):
    expected = dict((name, 'PASS') for name in R82_SECURITY_TESTS)
    results, summaries, current = {}, [], None
    labels = {'Number of tests': 'total', 'Tests skipped': 'skipped',
              'Tests warned': 'warned', 'Tests failed': 'failed', 'Tests passed': 'passed',
              'Tests borked': 'borked', 'Tests leaked': 'leaked',
              'Expected fail': 'xfailed', 'Expected leak': 'xleaked'}
    with open(path, 'rb') as handle:
        for raw in handle:
            line = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', as_text(raw)).split('\r')[-1].strip()
            match = re.match(r'^(PASS|XFAIL|SKIP|FAIL|BORK|WARN|LEAK)\s+.*\[([^\]]+)\]', line)
            if match:
                name = match.group(2)
                # Absolute filenames occur with direct run-tests invocation.
                for critical in expected:
                    if name == critical or name.endswith('/' + critical):
                        if critical in results:
                            raise RuntimeError('PHP 8.2 tests contain duplicate critical results')
                        results[critical] = match.group(1)
            if line == 'TEST RESULT SUMMARY':
                if current is not None or summaries:
                    raise RuntimeError('PHP 8.2 tests contain ambiguous summary')
                current = {}
            elif current is not None:
                match = re.match(r'^([^:]+?)\s*:\s*(\d+)(?:\s|$)', line)
                if match and match.group(1).strip() in labels:
                    name = labels[match.group(1).strip()]
                    if name in current:
                        raise RuntimeError('PHP 8.2 tests contain duplicate summary counts')
                    current[name] = int(match.group(2))
                if re.match(r'^Time taken\s*:\s*\d+(?:\.\d+)? seconds$', line):
                    summaries.append(current)
                    current = None
    if current is not None or len(summaries) != 1:
        raise RuntimeError('PHP 8.2 complete test summary is missing')
    counts = summaries[0]
    if not set(('total', 'skipped', 'warned', 'failed', 'passed')).issubset(counts):
        raise RuntimeError('PHP 8.2 test summary is incomplete')
    for name in ('borked', 'leaked', 'xfailed', 'xleaked'):
        counts.setdefault(name, 0)
    if (counts['passed'] <= 0 or any(counts[name] for name in ('failed', 'borked', 'leaked', 'warned')) or
            counts['total'] != sum(value for name, value in counts.items() if name != 'total')):
        raise RuntimeError('PHP 8.2 test summary has failures or inconsistent counts')
    if targeted:
        if counts['total'] != len(expected) or counts['passed'] != len(expected):
            raise RuntimeError('PHP 8.2 security tests were skipped or filtered')
    elif counts['total'] < 10000:
        raise RuntimeError('PHP 8.2 full regression suite was filtered')
    if results != expected:
        raise RuntimeError('PHP 8.2 required security regression PASS results are missing')
    counts['critical_regressions'] = results
    return counts


def r82_smoke_tests(top, layout):
    results = []
    for subdir in r82_profile(layout)['smoke_sapis']:
        php = os.path.join(top, 'BUILD', 'php-' + R82_VERSION, subdir, 'sapi', 'cli', 'php')
        if not os.path.isfile(php):
            raise RuntimeError('Built PHP 8.2 CLI is missing: ' + subdir)
        value = run_cmd([php, '-n', '-r',
                         'echo json_encode(array("version"=>PHP_VERSION,"version_id"=>PHP_VERSION_ID,"zts"=>PHP_ZTS,"int_size"=>PHP_INT_SIZE));'],
                        timeout=15, env={'PHPRC': '/dev/null', 'PHP_INI_SCAN_DIR': '/dev/null'})
        expected = {'version': R82_VERSION, 'version_id': 80235,
                    'zts': 1 if subdir == 'build-ztscli' else 0, 'int_size': 8}
        try:
            actual = json.loads(value['stdout'])
        except (ValueError, TypeError):
            actual = None
        if value['code'] or actual != expected:
            raise RuntimeError('Built PHP 8.2 executable identity failed: ' + subdir)
        expected['sapi'] = subdir
        results.append(expected)
    return results


def r82_check_artifacts(paths, rpm, layout):
    profile = r82_profile(layout)
    artifacts, names = [], set()
    source_name = profile['source_name'] + '-' + R82_VERSION + '-' + R82_RELEASE + '.src.rpm'
    for path in paths:
        if os.path.islink(path) or not os.path.isfile(path):
            raise RuntimeError('PHP 8.2 artifact is missing or symbolic')
        fields = bp_call([rpm, '-qp', '--qf', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}', path]).strip().split('\t')
        if len(fields) != 5:
            raise RuntimeError('Unexpected PHP 8.2 RPM header')
        name, version, release, arch, source = fields
        if (version != R82_VERSION or release != R82_RELEASE or arch not in ('x86_64', 'noarch') or
                source != source_name or
                not re.match('^' + re.escape(profile['source_name']) + r'(?:-[a-z0-9-]+)?$', name)):
            raise RuntimeError('Unexpected rebuilt PHP 8.2 RPM identity')
        filename = '%s-%s-%s.%s.rpm' % (name, version, release, arch)
        if os.path.basename(path) != filename or name in names:
            raise RuntimeError('Ambiguous rebuilt PHP 8.2 artifact identity')
        names.add(name)
        artifacts.append({'file': filename, 'sha256': bp_hash(path), 'name': name,
                          'version': version, 'release': release, 'arch': arch})
    if not set(profile['core_names']).issubset(names):
        raise RuntimeError('Incomplete PHP 8.2 core RPM set')
    return artifacts


def r82_build(args):
    global R82_LAST_BUILD_REPORT
    layout, host = args.layout, bp_doctor_host()
    profile = r82_profile(layout)
    if not r82_host_supported(host):
        raise RuntimeError('PHP 8.2 Remi rebuild requires CentOS 7 / RHEL 7 x86_64')
    if os.geteuid() == 0:
        raise RuntimeError('Run PHP 8.2 RPM compilation as a normal user, not root')
    if isinstance(args.jobs, bool) or not isinstance(args.jobs, int) or not 1 <= args.jobs <= 64:
        raise RuntimeError('Build concurrency must be between 1 and 64')
    folder = os.path.abspath(args.work_dir)
    if not re.match(r'^/[A-Za-z0-9_./-]+$', folder):
        raise RuntimeError('Use a simple absolute ASCII build directory')
    inputs = r82_verify_prepared(folder, layout)
    build = tempfile.mkdtemp(prefix='build-', dir=folder)
    R82_LAST_BUILD_REPORT = os.path.join(build, 'build.json')
    report = {'tool_version': VERSION, 'recipe': R82_RECIPE, 'layout': layout,
              'state': 'building', 'stage': 'verify_signature', 'deployed': False,
              'host': host, 'packaging_commit': profile['commit'],
              'packaging_refresh_commit': R82_PATCH_COMMIT,
              'inputs': r82_input_hashes(layout), 'target_version': R82_VERSION,
              'target_release': R82_RELEASE, 'source_sha256': R82_SOURCE_SHA,
              'source_signature_verified': False, 'signed': False, 'tests_required': True,
              'business_tests_passed': False}
    write_json(R82_LAST_BUILD_REPORT, report)
    try:
        signature = r82_verify_source_signature(inputs, build)
        report.update({'source_signature_verified': True,
                       'source_signature_fingerprint': signature['fingerprint']})
        top = os.path.join(build, 'rpmbuild')
        for name in ('SOURCES', 'BUILD', 'BUILDROOT', 'RPMS', 'SPECS', 'SRPMS', 'tmp'):
            os.makedirs(os.path.join(top, name), 0o700)
        for name in r82_input_hashes(layout):
            shutil.copyfile(os.path.join(inputs, name), os.path.join(top, 'SOURCES', name))
        with open(os.path.join(inputs, profile['spec_name']), 'rb') as handle:
            rendered = r82_render_spec(handle.read(), layout)
        spec = os.path.join(top, 'SPECS', 'php82-guard.spec')
        with open(spec, 'wb') as handle:
            handle.write(rendered)
        command = r82_rpmbuild_command(top, args.jobs, layout)
        report.update({'spec_sha256': hashlib.sha256(rendered).hexdigest(),
                       'rpm_definitions': r82_definitions(top, args.jobs, layout),
                       'stage': 'prepare_and_dependencies'})
        write_json(R82_LAST_BUILD_REPORT, report)
        say('正在验证 PHP 8.2 ' + layout + ' 原生依赖和补丁栈：' + os.path.join(build, 'prep.log'))
        bp_call(command + ['-bp', spec], log=os.path.join(build, 'prep.log'))
        report.update({'stage': 'compile_test_package', 'build_monitor': {
            'timeout_seconds': BM_TIMEOUT_SECONDS, 'interval_seconds': BM_INTERVAL_SECONDS,
            'progress_report': os.path.join(build, 'build.log.progress.json')}})
        write_json(R82_LAST_BUILD_REPORT, report)
        say('正在编译 PHP 8.2 ' + layout + ' 全部 RPM 并运行完整源码测试：' + os.path.join(build, 'build.log'))
        bp_call(command + ['-ba', spec], log=os.path.join(build, 'build.log'))
        report['php_selftest_summary'] = r82_selftest_summary(os.path.join(build, 'build.log'))
        report['stage'] = 'security_regressions'
        write_json(R82_LAST_BUILD_REPORT, report)
        source = os.path.join(top, 'BUILD', 'php-' + R82_VERSION)
        php = os.path.join(source, 'build-cgi', 'sapi', 'cli', 'php')
        bp_call([php, '-n', os.path.join(source, 'run-tests.php'), '-n', '-p', php,
                 '--no-color', '-q', '-j%d' % args.jobs] +
                [os.path.join(source, name) for name in R82_SECURITY_TESTS],
                cwd=source, log=os.path.join(build, 'security-tests.log'))
        report['security_test_summary'] = r82_selftest_summary(os.path.join(build, 'security-tests.log'), targeted=True)
        report['mitigation_smoke_tests'] = r82_smoke_tests(top, layout)
        report['artifacts'] = r82_check_artifacts(sorted(glob.glob(os.path.join(top, 'RPMS', '*', '*.rpm'))), bp_tool('rpm'), layout)
        srpm = os.path.join(top, 'SRPMS', profile['source_name'] + '-' + R82_VERSION + '-' + R82_RELEASE + '.src.rpm')
        if os.path.islink(srpm) or not os.path.isfile(srpm):
            raise RuntimeError('Rebuilt PHP 8.2 source RPM is missing')
        report.update({'source_rpm': {'file': os.path.basename(srpm), 'sha256': bp_hash(srpm)},
                       'state': 'built_not_deployed', 'stage': 'complete', 'php_selftests_passed': True})
        write_json(R82_LAST_BUILD_REPORT, report)
        say('PHP 8.2.35 ' + layout + ' RPM 已构建并通过源码测试，尚未安装：' + os.path.join(top, 'RPMS'))
        return 0
    except Exception as exc:
        report.update({'state': 'build_failed', 'error': as_text(exc),
                       'failure_summary': bp_failure_summary(build, report.get('stage'))})
        write_json(R82_LAST_BUILD_REPORT, report)
        say('PHP 8.2 构建未完成；报告：' + R82_LAST_BUILD_REPORT)
        raise


def remi82_build_main(argv):
    parser = argparse.ArgumentParser(prog='php-cve-guard.sh build-remi-el7-php82',
        description='以签名官方 PHP 8.2.35 源码和固定 Remi EL7 打包规则构建原生 RPM；保留 system / SCL 布局，不安装。')
    parser.add_argument('action', choices=['prepare', 'doctor', 'build'])
    parser.add_argument('--layout', choices=['system', 'scl'], default='system')
    parser.add_argument('--output-dir')
    parser.add_argument('--work-dir')
    parser.add_argument('--source-tar')
    parser.add_argument('--signature')
    parser.add_argument('--keyring')
    parser.add_argument('--packaging-dir')
    parser.add_argument('--jobs', type=int, default=2)
    bm_add_arguments(parser)
    args = parser.parse_args(argv)
    bm_configure(args)
    if args.jobs < 1 or args.jobs > 64:
        parser.error('--jobs must be between 1 and 64')
    if args.action == 'prepare':
        if not args.output_dir or args.work_dir:
            parser.error('prepare requires --output-dir and does not accept --work-dir')
    elif args.output_dir or args.source_tar or args.signature or args.keyring or args.packaging_dir:
        parser.error('input overrides apply only to prepare')
    elif not args.work_dir:
        parser.error('doctor/build require --work-dir')
    try:
        if args.action == 'prepare':
            return r82_prepare(args)
        if args.action == 'doctor':
            return r82_doctor(args)
        return r82_build(args)
    except Exception as exc:
        say('PHP 8.2 Remi EL7 构建未完成：' + as_text(exc))
        return 20
