#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Check real environment-file permissions in an opted-in disposable container.

Uses the generated production validator under Python 2.7 or Python 3. Only this
fixture's private files are created, inspected and removed. No systemd command,
package transaction, dependency installation or service operation is performed.
"""
from __future__ import print_function

import json
import os
import shutil
import stat
import sys
import tempfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SmokeFailure(Exception):
    pass


def require(condition, label):
    if not condition:
        raise SmokeFailure(label)


def protect_container():
    require(sys.platform.startswith('linux'), 'linux_required')
    require(os.geteuid() == 0, 'root_required')
    require(os.path.isfile('/.dockerenv'), 'disposable_docker_container_required')
    require(os.environ.get('PHP_GUARD_DISPOSABLE_BUILD_ENV_CI') == '1', 'explicit_ci_opt_in_required')


def trusted_parent(path):
    current = path
    while True:
        info = os.lstat(current)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022),
                'trusted_temporary_parent_required')
        parent = os.path.dirname(current)
        if current == parent:
            return
        current = parent


def load_validator():
    namespace = {'__name__': 'service_environment_native_smoke',
                 '__file__': os.path.join(ROOT, 'php_guard.py')}
    with open(namespace['__file__'], 'rb') as source:
        exec(compile(source.read(), namespace['__file__'], 'exec'), namespace)
    validator = namespace.get('_svc_require_empty_environment')
    require(callable(validator), 'production_environment_validator_required')
    return validator


def main():
    report = dict(kind='native_service_environment_file_regression',
                  python=sys.version.split()[0], passed=False, checks=0,
                  accepted_checks=0, rejected_checks=0, cleanup_ok=True,
                  services_modified=False, packages_modified=False)
    folder, folder_identity = None, None
    current_case = 'container_protection'
    try:
        # These gates precede loading production code or creating any files.
        protect_container()
        current_case = 'load_production_validator'
        validator = load_validator()
        current_case = 'create_private_fixture'
        trusted_parent('/run')
        folder = tempfile.mkdtemp(prefix='phpguard-service-env-smoke-', dir='/run')
        created = os.lstat(folder)
        folder_identity = (created.st_dev, created.st_ino)
        require(stat.S_ISDIR(created.st_mode) and created.st_uid == 0 and
                not (created.st_mode & 0o077), 'private_fixture_required')

        def write_file(name, content, mode=0o644):
            path = os.path.join(folder, name)
            with open(path, 'wb') as handle:
                handle.write(content)
            os.chmod(path, mode)
            return path

        def entry(path, optional=False):
            return path + ' (ignore_errors=' + ('yes' if optional else 'no') + ')'

        def check(entries, accepted):
            denied = False
            try:
                validator({'Environment': '', 'EnvironmentFiles': entries})
            except (ValueError, OSError):
                denied = True
            require(denied != accepted, 'unexpected_environment_validation_result')
            report['checks'] += 1
            key = 'accepted_checks' if accepted else 'rejected_checks'
            report[key] += 1

        current_case = 'comments_crlf_and_semicolon_accepted'
        comments = write_file('comments', b'# Fixture comment\r\n \t# Indented comment\n; Comment\r\n\n')
        check(entry(comments), True)

        current_case = 'empty_file_accepted'
        blank = write_file('blank', b' \t\r\n')
        check(entry(blank), True)

        current_case = 'all_empty_files_accepted'
        check(entry(comments) + '\n' + entry(blank), True)

        current_case = 'assignment_rejected'
        assignment = write_file('assignment', b'PHPRC=/fixture-only\n')
        check(entry(assignment), False)

        current_case = 'later_file_assignment_rejected'
        check(entry(comments) + '\n' + entry(assignment), False)

        current_case = 'carriage_return_assignment_rejected'
        carriage_return = write_file('carriage-return', b'# Fixture comment\rPHPRC=/fixture-only\n')
        check(entry(carriage_return), False)

        current_case = 'group_writable_file_rejected'
        writable = write_file('writable', b'# Fixture comment\n', mode=0o664)
        check(entry(writable), False)

        current_case = 'symlink_rejected'
        link = os.path.join(folder, 'link')
        os.symlink(comments, link)
        check(entry(link), False)

        current_case = 'required_missing_file_rejected'
        absent = os.path.join(folder, 'absent')
        check(entry(absent), False)

        current_case = 'optional_missing_file_accepted'
        check(entry(absent, optional=True), True)

        current_case = 'foreign_owned_readable_file_rejected'
        foreign = write_file('foreign-owned', b'# Fixture comment\n', mode=0o644)
        os.chown(foreign, 65534, 65534)
        try:
            check(entry(foreign), False)
        finally:
            # Restore our own fixture's owner even if its assertion fails.
            os.chown(foreign, 0, 0)

        current_case = 'unchanged_preflight_file_accepted'
        changing = write_file('changing', b'# Fixture comment\n')
        check(entry(changing), True)

        current_case = 'changed_preflight_file_rejected'
        write_file('changing', b'PHPRC=/fixture-only\n')
        check(entry(changing), False)

        report['passed'] = True
    except (Exception, KeyboardInterrupt) as exc:
        # Never emit filenames, environment-file contents, or raw exceptions.
        report['failed_case'] = current_case
        report['error_type'] = type(exc).__name__
    finally:
        if folder is not None:
            try:
                found = os.lstat(folder)
                require(stat.S_ISDIR(found.st_mode) and found.st_uid == 0 and
                        (found.st_dev, found.st_ino) == folder_identity,
                        'fixture_identity_changed')
                shutil.rmtree(folder)
            except (Exception, KeyboardInterrupt):
                report['cleanup_ok'] = False
                report['passed'] = False
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['passed'] and report['cleanup_ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
