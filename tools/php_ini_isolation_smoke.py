#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Real PHP 7.4 configuration-isolation regression (Python 3.6+, POSIX).

Run after assemble.py, supplying an already-built PHP 7.4 CLI and its source:
  python3 tools/php_ini_isolation_smoke.py --php /path/to/php \
      --source /path/to/php-source

Copies the CLI, unmodified upstream test runner, one PHPT, and the upstream
make-test recipe into a temporary fixture. Its default php.ini and scan-dir
fixtures disable shell_exec. The old environment must fail the actual SPL
test; production RPM and DEB environments must pass the same test. No build,
package installation, system configuration edits, or network access occurs.
Only these targeted tests are run: this is not full PHP/build validation.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import runpy
import shutil
import subprocess
import tempfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST = 'tests/run-test/bug75042-2.phpt'
PROBE = ('echo php_ini_loaded_file(), "\n", ini_get("disable_functions"), "\n", '
         'implode(",", get_loaded_extensions()), "\n";')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read(path):
    with open(path, 'r') as source:
        return source.read()


def write(path, value):
    with open(path, 'w') as output:
        output.write(value)


def sha256(path):
    with open(path, 'rb') as source:
        return hashlib.sha256(source.read()).hexdigest()


def invoke(argv, cwd, env):
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        output = process.communicate(timeout=90)[0].decode('utf-8', 'replace')
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise RuntimeError('Targeted PHP regression exceeded 90 seconds')
    return process.returncode, output


def baseline_environment():
    env = os.environ.copy()
    for name in list(env):
        if name in ('PHPRC', 'PHP_INI_SCAN_DIR', 'MAKEFLAGS', 'MFLAGS',
                    'GNUMAKEFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES', 'MAKEFILES',
                    'TESTS', 'PHP_EXECUTABLE', 'SHOW_ONLY_GROUPS',
                    'NO_PHPTEST_SUMMARY', 'REPORT_EXIT_STATUS', 'NO_INTERACTION') or \
                name.startswith(('TEST_PHP', 'PHP_TEST_', 'SKIP_')):
            del env[name]
    env.update(LC_ALL='C', LANG='C', TZ='UTC', PHP_INI_SCAN_DIR=os.devnull)
    return env


def case_fixture(root, name, binary, source):
    directory = os.path.join(root, name)
    os.makedirs(os.path.join(directory, 'bin'))
    os.makedirs(os.path.join(directory, 'build'))
    os.makedirs(os.path.join(directory, 'tests', 'run-test'))
    os.makedirs(os.path.join(directory, 'modules'))
    php = os.path.join(directory, 'bin', 'php')
    shutil.copy2(binary, php)
    for filename in ('run-tests.php', 'build/shtool', TEST):
        shutil.copy2(os.path.join(source, filename), os.path.join(directory, filename))
    upstream = read(os.path.join(source, 'build', 'Makefile.global'))
    start = upstream.index('PHP_TEST_SETTINGS = ')
    end = upstream.index('\nclean:', start)
    recipe = upstream[start:end]
    require('test: all' in recipe and 'tmp-php.ini' in recipe,
            'Unexpected upstream make-test recipe')
    # The only synthetic build target is a no-op prerequisite. The test recipe
    # itself is copied verbatim, so its php.ini collection and runner are real.
    makefile = ('top_srcdir := $(CURDIR)\ntop_builddir := $(CURDIR)\n'
                'PHP_EXECUTABLE := $(CURDIR)/bin/php\nEGREP := grep -E\n'
                'TESTS :=\n'
                'export NO_INTERACTION := 1\nexport REPORT_EXIT_STATUS := 1\n'
                '.PHONY: all test\nall:\n\t@:\n\n' + recipe + '\n')
    write(os.path.join(directory, 'Makefile'), makefile)
    return directory, php


def test_summary(output):
    result = {}
    for name, label in (('extensions_tested', 'Exts tested'),
                        ('tests_failed', 'Tests failed'),
                        ('tests_passed', 'Tests passed'),
                        ('tests_skipped', 'Tests skipped')):
        match = re.search(r'^' + re.escape(label) + r'\s*:\s*(\d+)', output, re.M)
        require(match is not None, 'Missing PHP summary field: ' + label + '\n' + output[-4000:])
        result[name] = int(match.group(1))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--php', required=True, help='Already-built PHP 7.4 CLI executable')
    parser.add_argument('--source', required=True, help='PHP 7.4 source directory with run-tests.php')
    args = parser.parse_args()
    require(os.name == 'posix', 'This regression requires Linux or macOS')
    binary, source = os.path.abspath(args.php), os.path.abspath(args.source)
    for filename in ('run-tests.php', 'build/Makefile.global', 'build/shtool', TEST):
        require(os.path.isfile(os.path.join(source, filename)), 'Missing PHP source file: ' + filename)
    require(os.path.isfile(binary) and os.access(binary, os.X_OK), 'PHP executable is missing')
    require(shutil.which('make') is not None, 'make is required')
    guard = runpy.run_path(os.path.join(ROOT, 'php_guard.py'), run_name='ini_isolation_smoke_guard')
    env = baseline_environment()
    code, version = invoke([binary, '-n', '-r', 'echo PHP_VERSION;'], ROOT, env)
    require(code == 0 and version.startswith('7.4.'), 'A working PHP 7.4 CLI is required')
    before_environment = dict(os.environ)
    result = {
        'kind': 'real_php74_build_ini_isolation_regression',
        'tool_version': guard['VERSION'], 'php_version': version,
        'platform': platform.system(), 'architecture': platform.machine(),
        'upstream_test': TEST,
        'input_sha256': {filename: sha256(os.path.join(source, filename))
                         for filename in ('run-tests.php', 'build/Makefile.global', TEST)},
        'cases': [], 'full_php_build_tested': False, 'packages_installed': False,
        'services_modified': False, 'system_configuration_modified': False,
    }
    with tempfile.TemporaryDirectory(prefix='phpguard-ini-isolation-') as temporary:
        # Makefile recipes use unquoted build paths, matching upstream PHP.
        require(not re.search(r'[\s$#]', temporary), 'Use a temporary directory without make-special characters')
        for mode in ('default_ini', 'scanned_ini'):
            directory, php = case_fixture(temporary, mode, binary, source)
            polluted_ini = os.path.join(directory, 'bin', 'php.ini')
            scan = os.path.join(directory, 'scan')
            os.mkdir(scan)
            case_env = dict(env)
            if mode == 'default_ini':
                write(polluted_ini, 'disable_functions=shell_exec\n')
            else:
                polluted_ini = os.path.join(scan, 'fixture.ini')
                write(polluted_ini, 'disable_functions=shell_exec\n')
                case_env.update(PHPRC=os.devnull, PHP_INI_SCAN_DIR=scan)
            fixture_hash = sha256(polluted_ini)
            code, probe = invoke([php, '-r', PROBE], directory, case_env)
            require(code == 0 and probe.splitlines()[1] == 'shell_exec',
                    'The contamination fixture was not loaded: ' + probe)
            if mode == 'default_ini':
                require(os.path.realpath(probe.splitlines()[0]) == os.path.realpath(polluted_ini),
                        'PHP did not discover the fixture through its default php.ini search')
            code, failed = invoke(['make', 'test'], directory, case_env)
            failed_summary = test_summary(failed)
            failed_diff = read(os.path.join(directory, 'tests', 'run-test', 'bug75042-2.diff'))
            require(code != 0 and failed_summary['tests_failed'] == 1 and
                    failed_summary['extensions_tested'] == 1 and
                    '/SPL.so' in failed_diff,
                    'Old-environment SPL failure was not reproduced: ' + failed[-4000:] + failed_diff)
            item = {'contamination': mode, 'before': dict(failed_summary, exit_code=code,
                    attempted_static_spl_shared_load=True), 'after': {}}
            # The caller really contains the hostile environment for both
            # production boundaries. Restore it even if a regression fails.
            os.environ.clear()
            os.environ.update(case_env)
            try:
                for backend in ('rpm', 'deb'):
                    if backend == 'rpm':
                        def run(argv):
                            return guard['bp_call'](argv, cwd=directory)
                    else:
                        deb_env = guard['db_build_env'](2)

                        def run(argv):
                            returncode, output = invoke(argv, directory, deb_env)
                            require(returncode == 0, 'DEB environment child failed: ' + output[-4000:])
                            return output
                    probe = run([php, '-r', PROBE]).splitlines()
                    require(probe[0] == os.devnull and probe[1] == '' and 'SPL' in probe[2].split(','),
                            backend + ' did not isolate automatic PHP configuration')
                    passed = run(['make', 'test'])
                    passed_summary = test_summary(passed)
                    require(passed_summary['tests_failed'] == 0 and
                            passed_summary['tests_passed'] == 1 and
                            passed_summary['tests_skipped'] == 0 and
                            passed_summary['extensions_tested'] > 1,
                            backend + ' did not pass the unmodified SPL test: ' + passed[-4000:])
                    explicit = os.path.join(directory, 'explicit.ini')
                    write(explicit, 'memory_limit=29M\n')
                    script = 'echo ini_get("memory_limit");'
                    require(run([php, '-c', explicit, '-r', script]) == '29M',
                            backend + ' isolation suppressed explicit -c')
                    require(run([php, '-c', explicit, '-d', 'memory_limit=31M', '-r', script]) == '31M',
                            backend + ' isolation suppressed explicit -d')
                    item['after'][backend] = dict(passed_summary, exit_code=0,
                        explicit_c_honored=True, explicit_d_honored=True,
                        automatic_config_isolated=True)
            finally:
                os.environ.clear()
                os.environ.update(before_environment)
            require(sha256(polluted_ini) == fixture_hash, 'The fixture configuration was modified')
            item['contaminated_configuration_unchanged'] = True
            result['cases'].append(item)
    require(dict(os.environ) == before_environment, 'The caller environment was not restored')
    result['caller_environment_unchanged'] = True
    result['state'] = 'passed'
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
