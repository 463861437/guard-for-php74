#!/usr/bin/env python3
"""Real cron/systemd fixture for disposable GitHub-hosted Ubuntu runners only.

This does not invoke the installer, upgrade PHP, build packages, or kill jobs.
It temporarily adjusts the runner's cron PAM fixture to exercise session.scope
ancestry as well as natural draining and restoration after a zero-second wait.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
OPT_IN = 'github-hosted-disposable-only'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*args, check=True):
    return subprocess.run(args, check=check, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=60)


def active():
    return command('systemctl', 'is-active', 'cron.service', check=False).stdout.strip() == 'active'


def protect_runner():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
            os.environ.get('PHPGUARD_SCHEDULER_SMOKE') == OPT_IN,
            'Refusing service operations: explicit disposable GitHub-hosted smoke environment is required.')
    require(sys.platform == 'linux' and os.geteuid() == 0, 'This CI fixture requires root on Linux.')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'The runner must be a real systemd VM.')
    require(not any(Path(path).exists() for path in ('/.dockerenv', '/run/.containerenv', '/run/systemd/container')),
            'Container fixtures cannot establish host scheduler behavior.')
    data = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                if '=' in line and not line.startswith('#'))
    require(data.get('ID', '').strip('"') == 'ubuntu' and data.get('VERSION_ID', '').strip('"') == '22.04',
            'This smoke fixture is intentionally limited to Ubuntu 22.04.')
    require(command('systemctl', 'is-active', 'systemd-logind.service', check=False).stdout.strip() == 'active',
            'An active systemd-logind service is required to test PAM session scopes.')


def load_guard():
    spec = importlib.util.spec_from_file_location('scheduler_smoke_guard', ROOT / 'php_guard.py')
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    require(all(callable(getattr(guard, name, None)) for name in ('sm_plan', 'sm_enter', 'sm_exit')),
            'Generated release payload does not include scheduler maintenance; run assemble.py before CI.')
    return guard


def fixture_script(directory, name, seconds):
    script = directory / (name + '.php')
    # An exclusive token makes the minute schedule harmless after its first run.
    # No PHP process, parent PID, command name, or cgroup identity is fabricated.
    script.write_text("""<?php
$token = @fopen(__DIR__ . '/NAME.once', 'x');
if ($token === false) { exit(0); }
fclose($token);
$stat = file_get_contents('/proc/self/stat');
$fields = preg_split('/\\s+/', substr($stat, strrpos($stat, ')') + 2));
file_put_contents(__DIR__ . '/NAME.started.json', json_encode(array('pid' => getmypid(), 'start_ticks' => (int)$fields[19])), LOCK_EX);
$deadline = microtime(true) + 90;
while (!is_file(__DIR__ . '/NAME.release') && microtime(true) < $deadline) { usleep(100000); }
if (!is_file(__DIR__ . '/NAME.release')) { exit(2); }
sleep(SECONDS);
file_put_contents(__DIR__ . '/NAME.finished', 'finished naturally\\n', LOCK_EX);
""".replace('NAME', name).replace('SECONDS', str(seconds)))
    script.chmod(0o600)
    return script


def await_job(guard, directory, name):
    marker = directory / (name + '.started.json')
    deadline = time.monotonic() + 90
    next_notice = 0
    while time.monotonic() < deadline:
        if marker.exists():
            try:
                started = json.loads(marker.read_text())
                pid = int(started['pid'])
            except (ValueError, KeyError):
                time.sleep(0.05)
                continue
            inventory = guard.collect_inventory([])
            jobs = [row for row in inventory['processes'] if row['pid'] == pid]
            require(len(jobs) == 1 and jobs[0].get('start_ticks') is not None,
                    'Real scheduled PHP fixture exited before inventory or its identity could not be read.')
            require(jobs[0]['start_ticks'] == int(started['start_ticks']), 'Scheduled fixture PID was reused.')
            require('/php' in (jobs[0].get('exe') or ''), 'The scheduled process is not running PHP.')
            return inventory, jobs[0]
        if time.monotonic() >= next_notice:
            print('Waiting for real minute-boundary cron fixture: ' + name, flush=True)
            next_notice = time.monotonic() + 15
        time.sleep(0.1)
    raise RuntimeError('Cron fixture did not start within 90 seconds: ' + name)


def same_live_job(guard, job):
    current = guard._inv_proc_stat(job['pid'])
    return bool(current and current['start_ticks'] == job['start_ticks'] and current.get('state') != 'Z')


def plan_job(guard, inventory, job):
    plan = guard.sm_plan(inventory, ['cron.service'])
    require(plan['ok'], 'Native scheduler planning failed: ' + json.dumps(plan['blockers']))
    identity = (job['pid'], job['start_ticks'])
    require(identity in {(row['pid'], row['start_ticks']) for row in plan['covered_processes']},
            'The actual PHP descendant was not covered by the read-only scheduler plan.')
    groups = [group['relative'] for service in plan['services'] for group in service['job_groups']]
    require(any(re.match(r'^/user\.slice/user-0\.slice/session-[A-Za-z0-9_.:-]+\.scope$', group) for group in groups),
            'Fixture did not establish the intended real PAM session.scope: ' + json.dumps(groups))
    return plan, groups


def interrupt(unused_number, unused_frame):
    # sm_enter catches KeyboardInterrupt and restores its own partially entered
    # state; the outer fixture also has a finally cleanup for files and PAM.
    raise KeyboardInterrupt('CI smoke interrupted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', help='Optional JSON evidence file on this disposable runner')
    args = parser.parse_args(argv)
    protect_runner()  # All filesystem writes and service operations follow this gate.
    guard = load_guard()
    summary = dict(scope='Real service preflight and cron/PAM/session.scope maintenance; no PHP repair or build',
                   php_repair_executed=False, passed=False, scenarios=[], cleanup_errors=[])
    directory = Path(tempfile.mkdtemp(prefix='phpguard-scheduler-smoke-', dir='/run'))
    cron_file = Path('/etc/cron.d/phpguard-smoke-' + uuid.uuid4().hex)
    pam = Path('/etc/pam.d/cron')
    pam_original = None
    pam_fixture = None
    states, jobs = [], []
    was_active = active()
    original_handler = signal.signal(signal.SIGTERM, interrupt)
    try:
        # Query a unique nonexistent unit on the real systemd daemon. No unit
        # files are created and no start/restart operation is needed here.
        missing_unit = 'phpguard-missing-' + uuid.uuid4().hex + '.service'
        observed = command('systemctl', 'show', missing_unit, '--no-pager',
                           '-p', 'LoadState', check=False)
        require('LoadState=not-found' in observed.stdout.splitlines(),
                'Missing-unit fixture did not return a verifiable not-found state.')
        try:
            guard._svc_show(shutil.which('systemctl'), missing_unit)
        except ValueError as exc:
            require(str(exc) == 'Systemd service does not exist (LoadState=not-found)',
                    'Missing-unit preflight returned the wrong diagnostic: ' + str(exc))
        else:
            raise RuntimeError('Missing-unit preflight incorrectly passed.')
        summary['missing_service_preflight'] = 'not-found, blocked without service mutation'
        info = pam.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022),
                'Cron PAM fixture requires a protected root-owned regular file.')
        pam_original = pam.read_bytes()
        pam_fixture = pam_original + b'\n# Disposable phpguard scheduler CI fixture\nsession required pam_systemd.so\n'
        pam.write_bytes(pam_fixture)
        if not was_active:
            command('systemctl', 'start', 'cron.service')
        require(active(), 'Cron did not become active.')
        summary['php_fixture_version'] = command('/usr/bin/php', '-n', '-r', 'echo PHP_VERSION;').stdout.strip()
        for name, seconds, timeout in (('natural-drain', 10, 30), ('bounded-timeout', 25, 0)):
            script = fixture_script(directory, name, seconds)
            # Both paths are generated ASCII names under the private /run dir.
            # chmod 0644 is required for cron.d; job contents contain no secrets.
            cron_file.write_text('SHELL=/bin/sh\nPATH=/usr/bin:/bin\nMAILTO=""\n'
                                 '* * * * * root /usr/bin/php -n ' + str(script) + ' >/dev/null 2>&1\n')
            cron_file.chmod(0o644)
            inventory, job = await_job(guard, directory, name)
            jobs.append(job)
            plan, groups = plan_job(guard, inventory, job)
            # Inventory duration varies across hosted images. Release the real
            # job's bounded fixture wait only after its live ancestry is proven.
            (directory / (name + '.release')).write_text('begin bounded sleep\n')
            state = guard.sm_enter(plan, [], timeout, str(directory / (name + '-maintenance.json')))
            states.append(state)
            evidence = dict(name=name, job_pid=job['pid'], job_start_ticks=job['start_ticks'],
                            job_groups=groups, timeout_seconds=timeout, entered=state['ok'],
                            errors=state.get('errors', []), php_deployment_executed=False)
            summary['scenarios'].append(evidence)
            if timeout:
                require(state['ok'], 'Natural drain failed: ' + json.dumps(state['errors']))
                require(not active(), 'Scheduler must remain inactive during the simulated deployment window.')
                require(not same_live_job(guard, job), 'The original PHP job is still live after a successful drain.')
                require((directory / (name + '.finished')).exists(), 'PHP job did not record natural completion.')
                evidence.update(scheduler_paused=True, job_finished_naturally=True)
            else:
                require(not state['ok'], 'Zero-second drain unexpectedly accepted a live long-running PHP job.')
                require(any('within 0 seconds' in error for error in state['errors']),
                        'Timeout case failed for a reason other than its expected bounded wait.')
                require(same_live_job(guard, job), 'Timeout killed or lost the original scheduled PHP job.')
                require(active(), 'Timeout must automatically restore scheduling before returning failure.')
                evidence.update(job_still_alive=True, scheduler_restored_on_failure=True, no_deployment=True)
            restored = guard.sm_exit(state)
            require(restored['ok'] and active(), 'Scheduler did not restore after the fixture: ' + json.dumps(restored))
            evidence['restore_ok'] = True
            print(json.dumps(evidence, sort_keys=True), flush=True)
        summary['passed'] = True
    except (Exception, KeyboardInterrupt) as exc:
        summary['error'] = str(exc) or type(exc).__name__
    finally:
        # Remove only this fixture's schedule first, so cleanup cannot enqueue
        # more jobs. Let our own jobs finish naturally; never send them a signal.
        try:
            cron_file.unlink(missing_ok=True)
        except Exception as exc:
            summary['cleanup_errors'].append('Own cron fixture removal: ' + str(exc))
        for state in reversed(states):
            try:
                restored = guard.sm_exit(state)
                if not restored['ok']:
                    summary['cleanup_errors'].append('Scheduler recovery: ' + json.dumps(restored))
            except Exception as exc:
                summary['cleanup_errors'].append('Scheduler recovery exception: ' + str(exc))
        # Failed planning may precede release; let any real fixture already
        # launched complete its bounded sleep before removing its directory.
        for name in ('natural-drain', 'bounded-timeout'):
            marker = directory / (name + '.started.json')
            if marker.exists():
                try:
                    (directory / (name + '.release')).write_text('cleanup permits natural exit\n')
                    started = json.loads(marker.read_text())
                    identity = dict(pid=int(started['pid']), start_ticks=int(started['start_ticks']))
                    if not any((job['pid'], job['start_ticks']) == (identity['pid'], identity['start_ticks']) for job in jobs):
                        jobs.append(identity)
                except Exception as exc:
                    summary['cleanup_errors'].append('Own fixture identity or release: ' + str(exc))
        deadline = time.monotonic() + 45
        while any(same_live_job(guard, job) for job in jobs) and time.monotonic() < deadline:
            time.sleep(0.2)
        jobs_alive = any(same_live_job(guard, job) for job in jobs)
        if jobs_alive:
            summary['cleanup_errors'].append('Own bounded fixture is still live; no job was killed and its directory was retained.')
        if pam_original is not None:
            try:
                require(pam.read_bytes() == pam_fixture, 'PAM file changed outside this fixture; refusing to overwrite it.')
                pam.write_bytes(pam_original)
            except Exception as exc:
                summary['cleanup_errors'].append('Cron PAM restoration: ' + str(exc))
        try:
            if active() != was_active:
                command('systemctl', 'start' if was_active else 'stop', 'cron.service')
            require(active() == was_active, 'Cron initial activity state was not restored.')
        except Exception as exc:
            summary['cleanup_errors'].append('Cron original state restoration: ' + str(exc))
        if not jobs_alive:
            try:
                shutil.rmtree(directory)
            except Exception as exc:
                summary['cleanup_errors'].append('Own fixture directory removal: ' + str(exc))
        signal.signal(signal.SIGTERM, original_handler)
        if summary['cleanup_errors']:
            summary['passed'] = False
        summary['original_scheduler_state_restored'] = active() == was_active
        if args.report:
            Path(args.report).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
        print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
