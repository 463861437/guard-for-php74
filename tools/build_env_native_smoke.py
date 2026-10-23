#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CI-only AL2 dependency regression, inside a disposable official container.

Plans the pinned PHP SRPM's complete build requirements, then installs only
httpd-devel and its dependencies. No PHP build/install or service operations.
The container fixture intentionally includes an older official httpd package.
"""
from __future__ import print_function

import json
import os
import shutil
import subprocess
import sys
import tempfile


BASELINE = '2.4.62-1.amzn2.0.2'
MODULE_BASELINE = '1.15.19-1.amzn2.0.2'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def rpm_snapshot(names=None):
    query = ['/usr/bin/rpm', '-q' if names else '-qa', '--qf',
             '%{NAME}|%{ARCH}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n']
    if names:
        query.extend(names)
    return sorted(subprocess.check_output(query).decode('ascii').splitlines())


def selection(result, state):
    matches = [item for item in result.get('dependency_selection', [])
               if item.get('policy') == 'installed_httpd_evr_arch']
    require(len(matches) == 1, 'Expected exactly one httpd-devel selection: ' + json.dumps(result))
    require(matches[0].get('state') == state, 'Unexpected dependency-selection state')
    return matches[0]


def confirm_no_runtime_changes(result):
    forbidden = [item for item in result.get('changes', [])
                 if item['name'] == 'httpd' or item['name'].startswith('php')]
    require(not forbidden, 'Build dependency plan changed httpd/PHP: ' + json.dumps(forbidden))


def main():
    require(os.environ.get('PHP_GUARD_DISPOSABLE_BUILD_ENV_CI') == '1' and
            os.path.isfile('/.dockerenv') and os.geteuid() == 0,
            'Run only in the disposable CI container; do not run on a server.')
    namespace = {'__name__': 'build_environment_native_smoke',
                 '__file__': os.path.join(ROOT, 'php_guard.py')}
    with open(namespace['__file__'], 'rb') as source:
        exec(compile(source.read(), namespace['__file__'], 'exec'), namespace)
    host = namespace['_inv_os']()
    require(host.get('id') == 'amzn' and host.get('version_id') == '2' and
            os.uname()[4] == 'x86_64', 'This fixture requires Amazon Linux 2 x86_64.')
    runtime_before = rpm_snapshot(['httpd', 'httpd-tools', 'httpd-filesystem'])
    require(all(row.split('|')[2] == '0:' + BASELINE for row in runtime_before),
            'The installed httpd fixture version is not the pinned baseline.')
    module_before = rpm_snapshot(['mod_http2'])
    require(module_before == ['mod_http2|x86_64|0:' + MODULE_BASELINE],
            'The installed mod_http2 fixture version is not the pinned baseline.')
    with open(os.devnull, 'wb') as sink:
        require(subprocess.call(['/usr/bin/rpm', '-q', 'httpd-devel'],
                                stdout=sink, stderr=subprocess.STDOUT) != 0,
                'The fixture must begin without httpd-devel installed.')
    before = rpm_snapshot()
    folder = tempfile.mkdtemp(prefix='php-guard-native-env-')
    try:
        srpm, rpm = namespace['be_private_inputs'](folder)
        requirements = sorted(set(namespace['BE_TOOLS'] + namespace['be_requirements'](srpm, rpm)))
        transaction = namespace['build_environment_transaction']
        complete = transaction(requirements, lock_wait=30)
        require(complete.get('ok') is True, 'Full SRPM build dependency plan failed: ' + json.dumps(complete))
        require(not complete.get('executed') and not complete.get('transaction_started'),
                'Read-only dependency plan unexpectedly executed a transaction.')
        selected = selection(complete, 'selected')
        require(selected['selected']['version'] == BASELINE and selected['selected']['arch'] == 'x86_64',
                'The native solver did not select httpd-devel matching the installed httpd.')
        require(selected['candidate_count'] > selected['matching_count'] >= 1,
                'This fixture must include newer/nonmatching provider candidates.')
        confirm_no_runtime_changes(complete)
        require(before == rpm_snapshot(), 'Full dependency preview changed the RPM database.')

        # A legitimate stricter requirement has repository providers, but none
        # can match the installed httpd. Even execute=True must stop pre-install.
        blocked = transaction(['httpd-devel > ' + BASELINE], execute=True, lock_wait=30)
        require(blocked.get('ok') is False and not blocked.get('may_have_changed') and
                not blocked.get('transaction_started'), 'No-match request did not fail before RPM execution.')
        require(blocked.get('error_kind') == 'matching_httpd_devel_unavailable',
                'No-match request did not report the intended compatibility blocker.')
        denied = selection(blocked, 'blocked')
        require(denied['candidate_count'] >= 1 and denied['matching_count'] == 0,
                'No-match fixture did not exercise a real newer provider.')
        require(before == rpm_snapshot(), 'Blocked dependency request changed the RPM database.')

        # Exercise production signature checks and transaction revalidation on
        # the smallest relevant real install, not the complete PHP build stack.
        minimal = transaction(['httpd-devel >= 2.0.46-1'], lock_wait=30)
        require(minimal.get('ok') is True, 'Minimal dependency preview failed: ' + json.dumps(minimal))
        confirm_no_runtime_changes(minimal)
        require(before == rpm_snapshot(), 'Minimal dependency preview changed the RPM database.')
        applied = transaction(['httpd-devel >= 2.0.46-1'], execute=True, lock_wait=30,
                              expected_changes=minimal['changes'])
        require(applied.get('ok') is True and applied.get('executed') is True and
                applied.get('may_have_changed') is False, 'Native dependency install failed: ' + json.dumps(applied))
        require(runtime_before == rpm_snapshot(['httpd', 'httpd-tools', 'httpd-filesystem']),
                'Native dependency installation modified the pinned httpd fixture.')
        require(module_before == rpm_snapshot(['mod_http2']),
                'Native dependency installation modified the pinned mod_http2 fixture.')
        require(rpm_snapshot(['httpd-devel']) == ['httpd-devel|x86_64|0:' + BASELINE],
                'Installed httpd-devel differs from the existing httpd version.')
        require(applied['snapshots']['expected_after'] == applied['snapshots']['after'],
                'Native dependency transaction did not match its reviewed snapshot.')
        print(json.dumps(dict(
            kind='native_al2_httpd_build_dependency_regression', python=sys.version.split()[0],
            host=host, architecture='x86_64', httpd_baseline=BASELINE,
            mod_http2_baseline=MODULE_BASELINE, mod_http2_unchanged=True,
            srpm_signature_verified=True, srpm_sha256=namespace['BP_SRPM_SHA'],
            complete_requirement_count=len(requirements), complete_plan_change_count=len(complete['changes']),
            complete_plan_selection=selected, no_matching_provider=denied,
            minimal_install_change_count=len(applied['changes']),
            installed_httpd_unchanged=True, httpd_devel_installed_matching=True,
            preview_and_blocked_request_rpmdb_unchanged=True,
            installed_snapshot_matches_reviewed_plan=True,
            php_build_tested=False, php_install_tested=False, services_modified=False),
            indent=2, sort_keys=True))
    finally:
        shutil.rmtree(folder)


if __name__ == '__main__':
    main()
