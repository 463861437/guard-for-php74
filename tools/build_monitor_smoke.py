#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Real short subprocess checks; no package builds, installs, or service changes.

Kept compatible with Python 2.7 and 3.6 for the native startup-image matrix.
Only this fixture's temporary directory and its short-lived children are used.
"""
from __future__ import print_function

import errno
import json
import os
import shutil
import signal
import sys
import tempfile
import time


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_guard():
    path = os.path.join(ROOT, 'php_guard.py')
    namespace = {'__name__': 'build_monitor_smoke_guard', '__file__': path}
    with open(path, 'rb') as source:
        exec(compile(source.read(), path, 'exec'), namespace)
    require(callable(namespace.get('bm_run')),
            'Generated payload has no build monitor; run assemble.py before this check.')
    require(callable(namespace.get('be_worker_call')),
            'Generated payload has no build-worker boundary; run assemble.py before this check.')
    return namespace


def read_json(path):
    with open(path, 'r') as source:
        return json.load(source)


def running(pid):
    """Independently distinguish running fixture processes from reaped/zombie ones."""
    try:
        os.kill(pid, 0)
    except OSError as error:
        if error.errno == errno.ESRCH:
            return False
        raise
    if sys.platform.startswith('linux'):
        try:
            with open('/proc/%d/stat' % pid, 'r') as source:
                raw = source.read()
            return raw[raw.rfind(')') + 2:].split()[0] != 'Z'
        except (IOError, OSError) as error:
            if error.errno == errno.ENOENT:
                return False
            raise
    return True


def failed_run(guard, argv, log, directory, timeout):
    try:
        guard['bm_run'](argv, log, cwd=directory, timeout=timeout, interval=0.05)
    except RuntimeError:
        pass
    else:
        raise RuntimeError('A failing fixture command was reported as successful.')
    return read_json(log + '.progress.json')


def main():
    require(os.name == 'posix', 'The process-group build monitor requires POSIX.')
    guard = load_guard()
    directory = tempfile.mkdtemp(prefix='phpguard-monitor-smoke-')
    timeout_started = None
    try:
        success_log = os.path.join(directory, 'success.log')
        success = ('import sys, time\n'
                   'assert sys.stdin.read() == "", "stdin did not reach EOF"\n'
                   'sys.stdout.write("TEST 1/2\\n"); sys.stdout.flush()\n'
                   'time.sleep(0.15)\n'
                   'sys.stdout.write("TEST 2/2\\n"); sys.stdout.flush()\n')
        guard['bm_run']([sys.executable, '-c', success], success_log,
                        cwd=directory, timeout=5, interval=0.05)
        succeeded = read_json(success_log + '.progress.json')
        require(succeeded.get('state') == 'succeeded' and
                succeeded.get('reason') == 'completed' and
                succeeded.get('exit_code') == 0 and
                succeeded.get('cleanup_complete') is True,
                'Successful child produced an invalid completion status.')
        require(succeeded.get('stage') == 'tests' and
                succeeded.get('test_current') == 2 and succeeded.get('test_total') == 2,
                'Final TEST 2/2 progress was not recorded.')
        require(succeeded.get('log_bytes', 0) > 0,
                'Successful child did not produce observable log output.')

        failure_log = os.path.join(directory, 'nonzero.log')
        failed = failed_run(guard, [sys.executable, '-c', 'import sys; sys.exit(7)'],
                            failure_log, directory, 5)
        require(failed.get('state') == 'failed' and
                failed.get('reason') == 'exit_nonzero' and failed.get('exit_code') == 7 and
                failed.get('cleanup_complete') is True,
                'Nonzero child exit was not preserved as a failed build.')

        timeout_log = os.path.join(directory, 'timeout.log')
        marker = os.path.join(directory, 'timeout-child.json')
        # Both processes end naturally after three seconds if a regression in
        # the monitor prevents cleanup. No background process can run forever.
        sleeper = ('import json, os, subprocess, sys, time\n'
                   'assert sys.stdin.read() == ""\n'
                   'child = subprocess.Popen([sys.executable, "-c", '
                   '"import time; time.sleep(3)"])\n'
                   'with open(sys.argv[1], "w") as output:\n'
                   '    json.dump({"parent": os.getpid(), "child": child.pid}, output)\n'
                   'time.sleep(3)\n'
                   'child.wait()\n')
        timeout_started = time.time()
        timed_out = failed_run(guard, [sys.executable, '-c', sleeper, marker],
                               timeout_log, directory, 0.5)
        require(timed_out.get('state') == 'failed' and
                timed_out.get('reason') == 'timeout' and
                timed_out.get('cleanup_complete') is True,
                'Timeout did not record a failed build with completed cleanup.')
        require(os.path.isfile(marker), 'Timeout child did not start before the fixture deadline.')
        identities = read_json(marker)
        require(timed_out.get('pid') == identities['parent'],
                'Timeout status refers to an unexpected child process.')
        require(not running(identities['parent']) and not running(identities['child']),
                'Timeout left a fixture process running.')

        owner = os.getpid()
        def successful_worker():
            return {'ok': True, 'exit_code': 0, 'php_deployed': False,
                    'fixture_pid': os.getpid(), 'effective_uid': os.geteuid()}
        worker_result = guard['be_worker_call'](successful_worker)
        require(worker_result.get('ok') is True and worker_result.get('exit_code') == 0 and
                worker_result.get('effective_uid') == os.geteuid() and
                worker_result.get('fixture_pid') != owner and
                not running(worker_result['fixture_pid']),
                'Successful worker result did not cross the fork boundary correctly.')

        def failed_worker():
            raise RuntimeError('bounded-worker-smoke-failure')
        worker_failure = guard['be_worker_call'](failed_worker)
        require(worker_failure.get('ok') is False and worker_failure.get('exit_code') == 20 and
                worker_failure.get('php_deployed') is False and
                worker_failure.get('error') == 'bounded-worker-smoke-failure',
                'Worker exception was not preserved as a failed result.')

        signal_log = os.path.join(directory, 'worker-signal.log')
        previous_handler = signal.getsignal(signal.SIGTERM)
        def interrupted_worker():
            # Only this smoke process receives SIGTERM. The nested child sends
            # it after bm_run has installed its handlers, avoiding timing races.
            # The parent must forward cancellation, then await monitor cleanup.
            code = ('import os, signal, sys, time\n'
                    'os.kill(int(sys.argv[1]), signal.SIGTERM)\n'
                    'time.sleep(3)\n')
            guard['bm_run']([sys.executable, '-c', code, str(owner)], signal_log,
                            cwd=directory, timeout=5, interval=0.05)
            return {'ok': True, 'exit_code': 0, 'php_deployed': False}
        cancelled = guard['be_worker_call'](interrupted_worker)
        cancelled_status = read_json(signal_log + '.progress.json')
        require(cancelled.get('ok') is False and cancelled.get('exit_code') == 20 and
                cancelled.get('php_deployed') is False and
                cancelled.get('interrupted_signal') == signal.SIGTERM,
                'Parent cancellation did not produce a failed worker result.')
        require(cancelled_status.get('state') == 'interrupted' and
                cancelled_status.get('reason') == 'signal' and
                cancelled_status.get('cleanup_complete') is True and
                not running(cancelled_status['pid']),
                'Forwarded signal left a monitor child running or reported success.')
        require(signal.getsignal(signal.SIGTERM) == previous_handler,
                'Worker boundary did not restore the original signal handler.')
        print(json.dumps({'result': 'real_build_monitor_subprocesses_passed',
                          'python': sys.version.split()[0],
                          'checks': ['stdin_eof', 'test_progress', 'successful_exit',
                                     'nonzero_exit', 'timeout', 'process_group_cleanup',
                                     'worker_success', 'worker_exception',
                                     'parent_signal_forwarding', 'worker_monitor_cleanup'],
                          'php_build_tested': False, 'php_install_tested': False,
                          'services_modified': False}, sort_keys=True))
        return 0
    finally:
        # On an assertion failure, let this fixture's bounded children finish
        # naturally before removing their directory. Never search/kill PHP jobs.
        if timeout_started is not None and sys.exc_info()[0] is not None:
            remaining = 4 - (time.time() - timeout_started)
            if remaining > 0:
                time.sleep(remaining)
        shutil.rmtree(directory)


if __name__ == '__main__':
    sys.exit(main())
