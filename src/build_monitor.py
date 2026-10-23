# -*- coding: utf-8 -*-
import errno
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

BM_TIMEOUT_SECONDS = 21600
BM_INTERVAL_SECONDS = 15
BM_QUIET_SECONDS = 300
BM_CLEANUP_GRACE_SECONDS = 2


class BuildInterrupted(RuntimeError):
    """The monitor's own build group was stopped after a handled signal."""


def _bm_clock():
    # os.times elapsed is monotonic on the supported POSIX Python 2.7 hosts.
    monotonic = getattr(time, 'monotonic', None)
    return monotonic() if monotonic else os.times()[4]


def _bm_atomic_status(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix='.build-progress-',
                                             dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                    indent=2).encode('utf-8') + b'\n')
            output.flush()
            os.fsync(output.fileno())
        os.rename(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _bm_group_snapshot(group):
    """Only the newly created process group; never process names or PHP PIDs."""
    if not sys.platform.startswith('linux') or not os.path.isdir('/proc'):
        return None
    tasks = {}
    try:
        entries = os.listdir('/proc')
        # Python 2's sysconf rejects unicode names. The assembled program uses
        # unicode_literals, so pass the platform's integer constant instead.
        ticks = float(os.sysconf(os.sysconf_names['SC_CLK_TCK']))
        if ticks <= 0:
            return None
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open('/proc/' + entry + '/stat', 'rb') as source:
                raw = source.read(8192).decode('ascii', 'replace')
            fields = raw[raw.rfind(')') + 2:].split()
            if int(fields[2]) != group or fields[0] == 'Z':
                continue
            tasks[(int(entry), int(fields[19]))] = (int(fields[11]) + int(fields[12])) / ticks
        except (IOError, OSError) as error:
            if error.errno in (errno.ENOENT, errno.ESRCH):
                continue
            # Permission or /proc read failures are unknown, never evidence
            # that the process group has exited. killpg(0) remains authoritative.
            return None
        except (ValueError, IndexError):
            return None
    return tasks


def _bm_group_alive(group):
    try:
        os.killpg(group, 0)
    except OSError as error:
        if error.errno == errno.ESRCH:
            return False
        raise
    tasks = _bm_group_snapshot(group)
    return bool(tasks) if tasks is not None else True


def _bm_cleanup(process):
    if process is None:
        return True
    # setsid makes this identifier unique to the command started by bm_run.
    if process.pid == os.getpgrp():
        raise RuntimeError('Refusing to signal the monitor process group')
    for selected in (signal.SIGTERM, signal.SIGKILL):
        process.poll()
        if not _bm_group_alive(process.pid):
            break
        try:
            os.killpg(process.pid, selected)
        except OSError as error:
            if error.errno != errno.ESRCH:
                raise
        deadline = _bm_clock() + BM_CLEANUP_GRACE_SECONDS
        while _bm_clock() < deadline:
            process.poll()
            if not _bm_group_alive(process.pid):
                break
            time.sleep(0.05)
    process.poll()
    return process.returncode is not None and not _bm_group_alive(process.pid)


def _bm_resource_snapshot(directory):
    result = {'disk_free_bytes': None, 'memory_available_bytes': None}
    try:
        disk = os.statvfs(directory)
        result['disk_free_bytes'] = disk.f_bavail * disk.f_frsize
    except (OSError, AttributeError):
        pass
    if sys.platform.startswith('linux'):
        try:
            with open('/proc/meminfo', 'r') as source:
                for line in source:
                    if line.startswith('MemAvailable:'):
                        result['memory_available_bytes'] = int(line.split()[1]) * 1024
                        break
        except (IOError, OSError, ValueError):
            pass
    return result


def _bm_parse_progress(chunk, previous):
    """Return a fixed vocabulary only: build logs may contain credentials."""
    result = dict(previous)
    text = chunk.decode('utf-8', 'replace') if isinstance(chunk, bytes) else chunk
    for line in re.split(r'[\r\n]', text):
        test = re.search(r'\bTEST\s+([0-9]{1,8})\s*/\s*([0-9]{1,8})\b', line)
        if test and 0 < int(test.group(1)) <= int(test.group(2)):
            result.update(stage='tests', test_current=int(test.group(1)), test_total=int(test.group(2)))
        elif re.match(r'^\s*(?:TEST RESULT SUMMARY|Tests (?:passed|failed|skipped)|Number of tests)\b', line):
            result['stage'] = 'tests'
        elif re.match(r'^\s*(?:Executing\(%install\)|Processing files:|Wrote:|dpkg-deb: building package|dh_builddeb\b)', line):
            result.update(stage='packaging', test_current=None, test_total=None)
        elif re.match(r'^\s*(?:checking |\+ (?:\./)?configure\b|configure:)', line):
            result.update(stage='configure', test_current=None, test_total=None)
        elif re.match(r'^\s*(?:libtool: (?:compile|link):|(?:cc|gcc|g\+\+|clang|clang\+\+)\s|/\S*/(?:cc|gcc|g\+\+|clang)\s|\+ make(?:\s|$))', line):
            result.update(stage='compile', test_current=None, test_total=None)
    return result


class _BMLogReader(object):
    def __init__(self, path):
        self.path = path
        self.reader = open(path, 'rb')
        self.identity = os.fstat(self.reader.fileno())
        self.position = 0
        self.previous_size = 0
        self.previous_mtime = None
        self.pending = b''
        self.progress = {'stage': 'starting', 'test_current': None, 'test_total': None}

    def sample(self):
        current = os.fstat(self.reader.fileno())
        changed = current.st_size != self.previous_size or current.st_mtime != self.previous_mtime
        truncated = current.st_size < self.position
        if truncated:
            self.position = 0
            self.pending = b''
            self.progress = {'stage': 'running', 'test_current': None, 'test_total': None}
        # Bound memory and parsing work even for a compiler producing gigabytes.
        start = max(self.position, current.st_size - 65536)
        if start != self.position:
            self.pending = b''
        self.reader.seek(start)
        content = self.pending + self.reader.read(max(0, current.st_size - start))
        self.position = current.st_size
        split = max(content.rfind(b'\n'), content.rfind(b'\r'))
        if split >= 0:
            self.progress = _bm_parse_progress(content[:split + 1], self.progress)
            self.pending = content[split + 1:][-4096:]
        else:
            self.pending = content[-4096:]
        # run-tests can emit an unterminated progress line while a test executes.
        progress = _bm_parse_progress(self.pending, self.progress)
        self.previous_size = current.st_size
        self.previous_mtime = current.st_mtime
        try:
            target = os.stat(self.path)
            replaced = (target.st_dev, target.st_ino) != (self.identity.st_dev, self.identity.st_ino)
        except OSError:
            replaced = True
        progress.update(log_bytes=current.st_size, log_path_replaced=replaced,
                        log_truncated=truncated)
        return progress, changed

    def close(self):
        self.reader.close()


def _bm_display(status):
    labels = {'starting': '启动', 'running': '运行', 'configure': '配置',
              'compile': '编译', 'tests': '源码测试', 'packaging': '生成安装包'}
    parts = ['构建进度：已运行 %d 秒' % status['elapsed_seconds'],
             '阶段 %s' % labels.get(status['stage'], '运行'),
             '日志 %.1f MiB' % (status['log_bytes'] / (1024.0 * 1024)),
             '距日志更新 %d 秒' % status['seconds_since_log_change']]
    if status.get('test_total'):
        parts.append('测试 %d/%d' % (status['test_current'], status['test_total']))
    if status.get('process_count') is not None:
        parts.append('构建进程 %d' % status['process_count'])
    if status.get('cpu_activity_percent') is not None:
        parts.append('采样 CPU %.0f%%' % status['cpu_activity_percent'])
    if status.get('disk_free_bytes') is not None:
        parts.append('磁盘可用 %.1f GiB' % (status['disk_free_bytes'] / (1024.0 ** 3)))
    if status.get('memory_available_bytes') is not None:
        parts.append('内存可用 %.1f GiB' % (status['memory_available_bytes'] / (1024.0 ** 3)))
    if status.get('quiet_warning'):
        parts.append('长时间无日志更新，请结合进程活动查看日志；仍受总时限约束')
    line = '；'.join(parts) + '\n'
    if sys.version_info[0] < 3:
        line = line.decode('utf-8') if isinstance(line, str) else line
        line = line.encode('utf-8', 'replace')
    sys.stdout.write(line)
    sys.stdout.flush()


def bm_run(argv, log, cwd=None, env=None, data=None, timeout=None, interval=None):
    """Bound and observe one source-build command without buffering its output."""
    if os.name != 'posix':
        raise RuntimeError('Build monitoring requires POSIX process groups')
    timeout = float(BM_TIMEOUT_SECONDS if timeout is None else timeout)
    interval = float(BM_INTERVAL_SECONDS if interval is None else interval)
    if not (0 < timeout < float('inf') and 0 < interval < float('inf')):
        raise ValueError('Build timeout and progress interval must be finite positive numbers')
    path = os.path.abspath(log)
    progress_path = path + '.progress.json'
    started = _bm_clock()
    process = output = input_stream = reader = None
    old_handlers = {}
    interrupted = []
    last_change = started
    previous_tasks = None
    previous_sample = started
    failure = None
    cleanup_ok = True
    status = {'state': 'starting', 'reason': None, 'stage': 'starting',
              'elapsed_seconds': 0, 'timeout_seconds': timeout,
              'progress_interval_seconds': interval, 'pid': None,
              'exit_code': None, 'log_bytes': 0, 'seconds_since_log_change': 0,
              'test_current': None, 'test_total': None,
              'process_count': None, 'cpu_activity_percent': None,
              'quiet_warning': False, 'cleanup_complete': None}

    def received(number, unused_frame):
        # A signal must not interrupt cleanup or leave a child waiting on a pipe.
        interrupted.append(number)

    def sample(now, show):
        values, changed = reader.sample() if reader else ({}, False)
        status.update(values)
        status['elapsed_seconds'] = round(max(0, now - started), 3)
        status.update(_bm_resource_snapshot(cwd or os.path.dirname(path)))
        tasks = _bm_group_snapshot(process.pid) if process else None
        status['process_count'] = len(tasks) if tasks is not None else None
        if tasks is not None and previous_tasks is not None and now > previous_sample:
            cpu = sum(max(0, value - previous_tasks.get(key, 0)) for key, value in tasks.items())
            status['cpu_activity_percent'] = round(cpu * 100 / (now - previous_sample), 1)
        changed_at = now if changed else last_change
        status['seconds_since_log_change'] = round(max(0, now - changed_at), 3)
        status['quiet_warning'] = now - changed_at >= BM_QUIET_SECONDS
        try:
            _bm_atomic_status(progress_path, status)
        except BaseException:
            status['reason'] = 'status_write_failed'
            raise
        if show:
            _bm_display(status)
        return changed_at, tasks

    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[number] = signal.getsignal(number)
            signal.signal(number, received)
        try:
            _bm_atomic_status(progress_path, status)
        except BaseException:
            status['reason'] = 'status_write_failed'
            raise
        flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NONBLOCK |
                 getattr(os, 'O_NOFOLLOW', 0))
        descriptor = os.open(path, flags, 0o600)
        output = os.fdopen(descriptor, 'wb', 0)
        if not stat.S_ISREG(os.fstat(output.fileno()).st_mode):
            raise RuntimeError('Build log must be a regular file')
        reader = _BMLogReader(path)
        if data is None:
            input_stream = open(os.devnull, 'rb')
        else:
            input_stream = tempfile.TemporaryFile()
            if not isinstance(data, bytes):
                data = data.encode('utf-8')
            input_stream.write(data)
            input_stream.seek(0)
        if interrupted:
            raise BuildInterrupted('Build interrupted before launch')
        process = subprocess.Popen(argv, stdin=input_stream, stdout=output, stderr=output,
                                   cwd=cwd, env=env, preexec_fn=os.setsid, close_fds=True)
        status.update(state='running', pid=process.pid)
        next_sample = started
        while True:
            now = _bm_clock()
            if interrupted:
                status.update(reason='signal', signal=interrupted[0])
                raise BuildInterrupted('Build interrupted by signal %d' % interrupted[0])
            code = process.poll()
            if code is not None:
                status['exit_code'] = code
                if code:
                    status['reason'] = 'exit_nonzero'
                    raise RuntimeError('Build command failed with exit code %d; see %s' % (code, path))
                if _bm_group_alive(process.pid):
                    status['reason'] = 'remaining_children'
                    raise RuntimeError('Build command exited while child processes remained; see %s' % path)
                status.update(state='succeeded', reason='completed', cleanup_complete=True)
                last_change, previous_tasks = sample(now, False)
                break
            if now - started >= timeout:
                status['reason'] = 'timeout'
                raise RuntimeError('Build exceeded its %.0f-second total limit; see %s' % (timeout, path))
            if now >= next_sample:
                last_change, previous_tasks = sample(now, True)
                previous_sample = now
                next_sample = now + interval
            time.sleep(min(0.2, interval, max(0.001, timeout - (now - started))))
    except BaseException as error:
        failure = error
        status.update(state='interrupted' if isinstance(error, BuildInterrupted) else 'failed',
                      reason=status.get('reason') or ('signal' if interrupted else 'monitor_error'),
                      error_type=type(error).__name__)
    finally:
        if process is not None:
            try:
                cleanup_ok = _bm_cleanup(process)
            except BaseException:
                cleanup_ok = False
            status['exit_code'] = process.returncode
        status['cleanup_complete'] = cleanup_ok
        if not cleanup_ok:
            status.update(state='failed', reason='cleanup_failed')
            failure = RuntimeError('Build process group cleanup did not complete; see %s' % progress_path)
        if interrupted and failure is None:
            status.update(state='interrupted', reason='signal', signal=interrupted[0])
            failure = BuildInterrupted('Build interrupted by signal %d' % interrupted[0])
        if failure is not None and interrupted:
            status['signal'] = interrupted[0]
        try:
            last_change, previous_tasks = sample(_bm_clock(), False)
        except BaseException as error:
            # Sampling includes log/proc/resource reads as well as persistence;
            # do not mislabel every diagnostic error as a JSON write failure.
            reason = ('status_write_failed' if status.get('reason') == 'status_write_failed'
                      else 'monitor_error')
            failure = RuntimeError('Cannot finalize build progress (%s); command stopped; see %s' %
                                   (type(error).__name__, path))
            status.update(state='failed', reason=reason, error_type=type(error).__name__)
            # Retry once with the explicit failure state; never claim success.
            try:
                _bm_atomic_status(progress_path, status)
            except BaseException:
                pass
        for stream in (reader, input_stream, output):
            if stream is not None:
                try:
                    stream.close()
                except (IOError, OSError):
                    pass
        # A termination request arriving during the last fsync must not be
        # silently converted into a successful build result.
        if interrupted and failure is None:
            status.update(state='interrupted', reason='signal', signal=interrupted[0])
            failure = BuildInterrupted('Build interrupted by signal %d' % interrupted[0])
            try:
                _bm_atomic_status(progress_path, status)
            except BaseException:
                failure = RuntimeError('Cannot persist interrupted build status; see %s' % path)
        for number, previous in old_handlers.items():
            signal.signal(number, previous)
    if failure is not None:
        if isinstance(failure, BuildInterrupted):
            raise failure
        if isinstance(failure, RuntimeError):
            raise failure
        raise RuntimeError('Build monitor failed (%s); see %s' % (type(failure).__name__, path))
    return ''
