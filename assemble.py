from pathlib import Path
import base64, json
root = Path(__file__).resolve().parent
license_files = ['LICENSE', 'LICENSES/PHP-3.01.txt', 'LICENSES/THIRD-PARTY-MIT.txt', 'LICENSES/Apache-1.0.txt']
notices = 'Guard for PHP 7.4. Original tooling: MIT; third-party portions retain their licenses.\n'
notices += 'This product includes PHP software, freely available from <http://www.php.net/software/>.\n'
notices += 'This product includes software developed by the Apache Group for use in the Apache HTTP server project (http://www.apache.org/).\n'
notices += '\n'.join((root / name).read_text() for name in license_files)
license_header = '# -*- coding: utf-8 -*-\n' + '\n'.join('# ' + line for line in notices.splitlines()) + '\n'
code = license_header + (root / 'src/common.py').read_text()
policy = json.loads((root / 'vendor-policy.json').read_text())
code += '\nPOLICY = json.loads(' + repr(json.dumps(policy, ensure_ascii=True)) + ')\n'
remi_policy = json.loads((root / 'remi-policy.json').read_text())
code += '\nRP_REMI_POLICY = json.loads(' + repr(json.dumps(remi_policy, ensure_ascii=True)) + ')\n'
code += 'import base64\nBP_TEST_PATCH = base64.b64decode(' + repr(base64.b64encode((root / 'patches/php74-backport-tests.patch').read_bytes()).decode()) + ')\n'
for name in ['inventory', 'apt_backend', 'rpm_provenance', 'rpm_backend', 'service_ops', 'backport_builder', 'remi_builder', 'deb_builder', 'build_env_backend', 'build_environment', 'native_environment', 'remediation', 'baota_install', 'deb_install', 'platform_support', 'oneclick', 'cli']:
    code += '\n' + (root / ('src/' + name + '.py')).read_text()
(root / 'php_guard.py').write_text(code)
launcher = (root / 'php-cve-guard.sh').read_text().split("<<'PHP_GUARD_PYTHON_PAYLOAD'", 1)[0]
(root / 'php-cve-guard.sh').write_text(launcher + "<<'PHP_GUARD_PYTHON_PAYLOAD'\n" + code + '\nPHP_GUARD_PYTHON_PAYLOAD\n')

# A standalone, self-contained single-command launcher.
(root / "php74-patch.sh").write_text((root / "php-cve-guard.sh").read_text().replace(' - "$@" <<', ' - php74-patch "$@" <<', 1))
