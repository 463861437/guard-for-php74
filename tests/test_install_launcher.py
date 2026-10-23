"""Offline POSIX launcher tests; mocks are shell functions in a separate harness.

Production has no environment override for its pinned release URL or digest.
No test invokes a host package manager, sudo, or network connection.
"""
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'install.sh').read_text()
LIBRARY = SOURCE.rsplit('\npg_main "$@"\nexit $?\n', 1)[0]


class InstallLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.events = self.root / 'events'
        self.payload = self.root / 'payload'
        self.payload.write_text('#!/bin/bash\nprintf "payload" >> "$PG_TEST_EVENTS"\n'
                                'printf "<%s>" "$@" >> "$PG_TEST_EVENTS"\n'
                                'printf "\\n" >> "$PG_TEST_EVENTS"\nexit 17\n')

    def run_shell(self, code, overrides='', args=(), env=None):
        harness = self.root / 'harness.sh'
        harness.write_text(LIBRARY + '\n' + overrides + '\n' + code + '\n')
        environment = os.environ.copy()
        environment.update(PG_TEST_EVENTS=str(self.events), PG_TEST_PAYLOAD=str(self.payload))
        environment.update(env or {})
        return subprocess.run(['/bin/sh', str(harness)] + list(args), env=environment,
                              capture_output=True, text=True, timeout=15)

    def base(self):
        digest = hashlib.sha256(self.payload.read_bytes()).hexdigest()
        return '''
PG_SHA256=%s
uname() { if [ "$1" = -m ]; then printf 'x86_64\\n'; else printf 'Linux\\n'; fi; }
id() { printf '0\\n'; }
pg_detect_os() { PG_OS=ubuntu; PG_OS_VERSION=20.04; }
pg_detect_manager() { PG_MANAGER=apt; PG_SUPPORTED=1; }
pg_dependencies() { PG_PACKAGES=''; PG_DOWNLOADER=curl; pg_hash_tool; }
pg_fetch() { printf 'fetch\\n' >> "$PG_TEST_EVENTS"; cp "$PG_TEST_PAYLOAD" "$1"; }
mktemp() { /usr/bin/mktemp -d %s/launcher.XXXXXXXX; }
''' % (shlex.quote(digest), shlex.quote(str(self.root)))

    def events_text(self):
        return self.events.read_text() if self.events.exists() else ''

    def assert_cleaned(self):
        self.assertEqual([], list(self.root.glob('launcher.*')))

    def test_posix_syntax_and_offline_help_version(self):
        result = subprocess.run(['/bin/sh', '-n', str(ROOT / 'install.sh')], capture_output=True)
        self.assertEqual(0, result.returncode)
        for args, expected in ((['--version'], '1.7.3'), (['--help'], '统一 Linux 下载启动器')):
            result = self.run_shell('pg_main "$@"', self.base() + '\npg_detect_os() { exit 99; }', args)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn(expected, result.stdout)
            self.assertEqual('', self.events_text())

    def test_non_linux_and_unsupported_system_do_not_download_or_bootstrap(self):
        for override, expected in (("uname() { printf 'Darwin\\n'; }", '仅支持 Linux'),
                                   ('pg_detect_manager() { PG_MANAGER=apk; PG_SUPPORTED=0; }', '尚无适配')):
            with self.subTest(expected=expected):
                result = self.run_shell('pg_main "$@"', self.base() + override, ['--yes'])
                self.assertEqual(10, result.returncode, result.stderr)
                self.assertIn(expected, result.stderr)
                self.assertEqual('', self.events_text())

    def test_check_is_unprivileged_and_never_installs_or_downloads(self):
        overrides = self.base() + '''
id() { printf '1000\\n'; }
pg_dependencies() { PG_PACKAGES='python3 python3-apt'; }
pg_as_root() { printf 'forbidden\\n' >> "$PG_TEST_EVENTS"; return 99; }
'''
        result = self.run_shell('pg_main "$@"', overrides, ['--check', '--yes'])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('缺少启动依赖', result.stdout)
        self.assertEqual('', self.events_text())

    def test_default_forwards_explicit_plan_and_preserves_exit_code_and_cleanup(self):
        result = self.run_shell('pg_main "$@"', self.base())
        self.assertEqual(17, result.returncode, result.stderr)
        self.assertIn('payload<plan>', self.events_text())
        self.assert_cleaned()

    def test_argument_boundaries_preserved_for_root_and_sudo_execution(self):
        for root in (True, False):
            with self.subTest(root=root):
                overrides = self.base()
                if not root:
                    overrides += '''
id() { printf '1001\\n'; }
pg_have() { [ "$1" = sudo ] || command -v "$1" >/dev/null 2>&1; }
sudo() { printf 'sudo\\n' >> "$PG_TEST_EVENTS"; [ "$1" = -- ] || return 99; shift; "$@"; }
'''
                args = ['--yes', '--work-dir', '/home/a path/build', '--service', 'queue@a.service',
                        '--health-url', 'https://example.invalid/a?x=1&y=2',
                        '--pause-scheduler', 'crond.service', '--drain-wait=300',
                        '--progress-interval', '15', '--build-timeout=21600']
                result = self.run_shell('pg_main "$@"', overrides, args)
                self.assertEqual(17, result.returncode, result.stderr)
                self.assertIn('payload' + ''.join('<' + x + '>' for x in args), self.events_text())
                if not root:
                    self.assertIn('sudo\n', self.events_text())
                self.assert_cleaned()
                self.events.unlink()

    def test_unprivileged_without_sudo_stops(self):
        overrides = self.base() + '''
id() { printf '1001\\n'; }
pg_have() { [ "$1" != sudo ] && command -v "$1" >/dev/null 2>&1; }
'''
        result = self.run_shell('pg_main "$@"', overrides, ['--yes'])
        self.assertEqual(2, result.returncode)
        self.assertNotIn('payload', self.events_text())
        self.assertIn('需要 root', result.stderr)
        self.assert_cleaned()

    def test_missing_dependencies_are_never_bootstrapped_without_fix_yes(self):
        overrides = self.base() + '''
pg_dependencies() { PG_PACKAGES='python3 python3-apt'; }
pg_bootstrap() { printf 'bootstrap\\n' >> "$PG_TEST_EVENTS"; return 99; }
'''
        for args in ([], ['plan'], ['audit', '--yes'], ['plan', '--yes'], ['fix']):
            with self.subTest(args=args):
                result = self.run_shell('pg_main "$@"', overrides, args)
                self.assertEqual(10, result.returncode, result.stderr)
                self.assertEqual('', self.events_text())

    def test_bootstrap_requires_successful_dependency_recheck(self):
        overrides = self.base() + '''
PG_TEST_INSTALLED=0
pg_dependencies() {
    PG_PACKAGES='python3 python3-apt'
    if [ "$PG_TEST_INSTALLED" -eq 1 ]; then PG_PACKAGES=''; fi
    PG_DOWNLOADER=curl; pg_hash_tool
}
pg_bootstrap() { printf 'bootstrap\\n' >> "$PG_TEST_EVENTS"; PG_TEST_INSTALLED=1; }
'''
        result = self.run_shell('pg_main "$@"', overrides, ['--yes'])
        self.assertEqual(17, result.returncode, result.stderr)
        self.assertEqual(['bootstrap', 'fetch', 'payload<--yes>'], self.events_text().splitlines())
        self.assert_cleaned()
        self.events.unlink()
        result = self.run_shell('pg_main "$@"', overrides + '\npg_bootstrap() { return 0; }', ['--yes'])
        self.assertEqual(2, result.returncode)
        self.assertEqual('', self.events_text())

    def test_package_manager_failure_never_downloads(self):
        overrides = self.base() + '''
pg_dependencies() { PG_PACKAGES=python3; }
pg_bootstrap() { return 42; }
'''
        result = self.run_shell('pg_main "$@"', overrides, ['--yes'])
        self.assertEqual(2, result.returncode)
        self.assertIn('安装失败', result.stderr)
        self.assertEqual('', self.events_text())

    def test_failed_empty_truncated_wrong_hash_downloads_never_execute(self):
        cases = (
            'pg_fetch() { printf partial > "$1"; return 22; }',
            'pg_fetch() { : > "$1"; }',
            'pg_fetch() { printf "#!/bin/bash\\n" > "$1"; }',
            "PG_SHA256='" + '0' * 64 + "'",
            "PG_SHA256='__RELEASE_SHA256__'",
        )
        for override in cases:
            with self.subTest(override=override):
                result = self.run_shell('pg_main "$@"', self.base() + override, ['--yes'])
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertNotIn('payload', self.events_text())
                self.assert_cleaned()

    def test_release_url_and_digest_cannot_be_overridden_by_environment(self):
        result = self.run_shell('printf "%s\\n%s\\n" "$PG_URL" "$PG_SHA256"', env={
            'PG_URL': 'http://attacker.invalid/x.sh', 'PG_SHA256': 'attacker'})
        self.assertIn('https://github.com/463861437/guard-for-php74/releases/download/v1.7.3/', result.stdout)
        self.assertNotIn('attacker', result.stdout)

    def test_pinned_digest_matches_generated_release_payload(self):
        digest = next(line.split("'", 2)[1] for line in SOURCE.splitlines()
                      if line.startswith("PG_SHA256='"))
        if digest == '__RELEASE_SHA256__':
            self.skipTest('Release assembly must replace the SHA256 placeholder before publishing')
        self.assertEqual(hashlib.sha256((ROOT / 'php74-patch.sh').read_bytes()).hexdigest(), digest)

    def test_os_release_is_parsed_as_data_not_shell_code(self):
        data = self.root / 'os-release'
        data.write_text('NAME="Test"\nID="ubuntu"\nVERSION_ID=\'20.04\'\n'
                        'PRETTY_NAME="$(touch ' + str(self.events) + ')"\n'
                        'ID=$(touch ' + str(self.events) + ')\n')
        result = self.run_shell('pg_read_os ' + shlex.quote(str(data)) +
                                '; printf "%s:%s\\n" "$PG_OS" "$PG_OS_VERSION"')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('ubuntu:20.04\n', result.stdout)
        self.assertEqual('', self.events_text())

    def test_platform_support_matrix_does_not_follow_foreign_manager(self):
        cases = [
            ('ubuntu', '20.04', 'apt-get yum', 'apt', 1),
            ('debian', '12', 'apt-get', 'apt', 1),
            ('debian', '9', 'apt-get', 'apt', 0),
            ('centos', '7.9', 'yum', 'yum', 1),
            ('rhel', '8.9', 'dnf yum', 'dnf', 1),
            ('rocky', '9.5', 'dnf', 'dnf', 1),
            ('amzn', '2', 'yum dnf', 'yum', 1),
            ('amzn', '2023', 'dnf yum', 'dnf', 1),
            ('alpine', '3.21', 'apk apt-get', 'apk', 0),
            ('arch', '2026.10', 'pacman', 'pacman', 0),
            ('opensuse-leap', '15.6', 'zypper', 'zypper', 0),
            ('unknown', '99', 'apt-get', 'apt-get', 0),
            ('ubuntu', '20.04', 'yum', 'unknown', 0),
        ]
        for system, version, commands, manager, supported in cases:
            with self.subTest(system=system, version=version):
                overrides = 'PG_OS=%s; PG_OS_VERSION=%s\npg_have() { case " %s " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }' % (
                    shlex.quote(system), shlex.quote(version), commands)
                result = self.run_shell('pg_detect_manager; printf "%s:%s\\n" "$PG_MANAGER" "$PG_SUPPORTED"', overrides)
                self.assertEqual(manager + ':' + str(supported) + '\n', result.stdout)

    def test_bootstrap_uses_only_fixed_minimal_packages_and_signature_enforcement(self):
        for manager, command in (('apt', 'apt-get'), ('yum', 'yum'), ('dnf', 'dnf')):
            with self.subTest(manager=manager):
                overrides = 'PG_MANAGER=%s; PG_PACKAGES="bash python3 curl"\npg_as_root() { printf "<%%s>" "$@"; }' % manager
                result = self.run_shell('pg_bootstrap', overrides)
                self.assertEqual(0, result.returncode)
                self.assertIn('<' + command + '>', result.stdout)
                self.assertIn('<install><bash><python3><curl>', result.stdout)
                self.assertNotIn('<upgrade>', result.stdout)
                self.assertNotIn('nogpgcheck', result.stdout)
                self.assertIn('AllowUnauthenticated=false' if manager == 'apt' else 'gpgcheck=1', result.stdout)

    def test_apt_bootstrap_refreshes_indexes_strictly_before_install(self):
        overrides = """
PG_MANAGER=apt; PG_PACKAGES='python3 python3-apt'
pg_as_root() { printf '%s\\n' "$*" >> "$PG_TEST_EVENTS"; printf 'Reading package lists...\\n'; }
"""
        result = self.run_shell('pg_bootstrap', overrides)
        self.assertEqual(0, result.returncode, result.stderr)
        events = self.events_text().splitlines()
        self.assertEqual(2, len(events))
        self.assertTrue(events[0].endswith(' update'), events)
        self.assertIn('APT::Update::Error-Mode=any', events[0])
        self.assertIn('Acquire::AllowInsecureRepositories=false', events[0])
        self.assertIn('Acquire::AllowDowngradeToInsecureRepositories=false', events[0])
        self.assertTrue(events[1].endswith(' install python3 python3-apt'), events)

    def test_apt_partial_or_failed_refresh_never_installs_from_old_indexes(self):
        for log, code in [('W: Failed to fetch https://example.invalid index', 0),
                          ('W: Some index files failed to download', 0),
                          ('E: repository has no Release file', 0),
                          ('Repository failed', 100)]:
            with self.subTest(log=log, code=code):
                overrides = """
PG_MANAGER=apt; PG_PACKAGES=python3
pg_as_root() { printf '%%s\\n' "$*" >> "$PG_TEST_EVENTS"; printf '%%s\\n' %s; return %s; }
""" % (shlex.quote(log), code)
                result = self.run_shell('pg_bootstrap', overrides)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(1, len(self.events_text().splitlines()))
                self.assertNotIn(' install ', self.events_text())
                self.events.unlink()

    def test_dependency_detection_installs_only_missing_tools_and_native_bindings(self):
        for manager, expected in (('apt', 'python3 python3-apt curl coreutils ca-certificates'),
                                  ('yum', 'python yum rpm-python curl coreutils ca-certificates'),
                                  ('dnf', 'python3 python3-dnf python3-rpm curl coreutils ca-certificates')):
            overrides = """
PG_MANAGER=%s
pg_python_ready() { return 1; }
pg_binding_ready() { return 1; }
pg_download_tool() { return 1; }
pg_hash_tool() { return 1; }
pg_certificates_ready() { return 1; }
""" % manager
            result = self.run_shell('pg_dependencies; printf "%s\\n" "$PG_PACKAGES"', overrides)
            self.assertEqual(expected + '\n', result.stdout)
        overrides += """
pg_python_ready() { return 0; }
pg_binding_ready() { return 0; }
pg_download_tool() { return 0; }
pg_hash_tool() { return 0; }
pg_certificates_ready() { return 0; }
"""
        result = self.run_shell('pg_dependencies; printf "%s\\n" "$PG_PACKAGES"', overrides)
        self.assertEqual('\n', result.stdout)

    def test_busybox_wget_is_not_assumed_to_verify_tls_or_restrict_redirects(self):
        overrides = """
pg_have() { [ "$1" = wget ]; }
wget() { printf 'BusyBox v1.36 usage: wget URL\\n'; }
"""
        result = self.run_shell('pg_download_tool', overrides)
        self.assertEqual(1, result.returncode)
        overrides += "\nwget() { printf 'GNU Wget 1.21\\n'; }"
        result = self.run_shell('pg_download_tool; printf "%s\\n" "$PG_DOWNLOADER"', overrides)
        self.assertEqual(0, result.returncode)
        self.assertEqual('wget\n', result.stdout)

    def test_no_yes_with_options_is_explicitly_planned(self):
        result = self.run_shell('pg_main "$@"', self.base(), ['--jobs', '2'])
        self.assertEqual(17, result.returncode)
        self.assertIn('payload<plan><--jobs><2>', self.events_text())

    def test_unknown_or_incomplete_arguments_do_not_download_or_install(self):
        for args in (['--yes', '--unknown'], ['--jobs'], ['plan', 'fix', '--yes']):
            with self.subTest(args=args):
                result = self.run_shell('pg_main "$@"', self.base(), args)
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertEqual('', self.events_text())

    def test_https_and_redirect_enforcement_are_passed_to_downloaders(self):
        for downloader in ('curl', 'wget'):
            overrides = 'PG_DOWNLOADER=%s\n%s() { printf "<%%s>" "$@"; }' % (downloader, downloader)
            result = self.run_shell('pg_fetch /tmp/test-destination', overrides)
            self.assertEqual(0, result.returncode)
            self.assertIn('<https://github.com/', result.stdout)
            if downloader == 'curl':
                self.assertIn('<--proto><=https><--proto-redir><=https>', result.stdout)
                self.assertIn('<--fail>', result.stdout)
            else:
                self.assertIn('<--https-only>', result.stdout)
                self.assertIn('<--secure-protocol=TLSv1_2>', result.stdout)


if __name__ == '__main__':
    unittest.main()
