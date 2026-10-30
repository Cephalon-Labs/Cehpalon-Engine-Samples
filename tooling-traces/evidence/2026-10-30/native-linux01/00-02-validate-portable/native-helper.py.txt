"""Owned Linux strace + native counter diagnostic lane, not performance acceptance."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading
import time

from tooling_os_observer import observe_process, parse_linux_stat

PREFIX = re.compile(r'^\s*(?:\[pid\s+)?(?P<pid>\d+)\]?\s+(?P<stamp>\d+\.\d+)\s+(?P<body>.*)$')
CALL = re.compile(r'^(?P<name>[a-zA-Z_][a-zA-Z_0-9]*)\(')
RESUMED = re.compile(r'^<\.\.\. (?P<name>[a-zA-Z_][a-zA-Z_0-9]*) resumed>')
DURATION = re.compile(r'\s+<(?P<duration>\d+\.\d+)>$')
RAW_BUFFERS = 'read,pread64,write,pwrite64,readv,writev'
SYSCALLS = 'execve,clone,clone3,fork,vfork,exit,exit_group,openat,read,pread64,write,pwrite64,readv,writev,newfstatat,statx,access,close,fsync,fdatasync,rename,renameat,renameat2,mmap,munmap'


def _integer_result(text):
    match = re.match(r'(-?(?:0x[0-9a-fA-F]+|\d+))', text)
    return int(match[1], 0) if match else None


def _decimal_seconds_ns(text):
    whole, fraction = (text.split('.', 1) + [''])[:2]
    return int(whole) * 1_000_000_000 + int((fraction + '000000000')[:9])


def parse_strace(path):
    """Retain unmatched/incomplete input rather than manufacturing zero duration."""
    events, pending, unknown, lifecycle, decode_replacements = [], {}, [], [], []
    with Path(path).open(encoding='utf-8', errors='replace') as stream:
        for number, raw in enumerate(stream, 1):
            line = raw.rstrip('\n')
            if '\ufffd' in line:
                decode_replacements.append(number)
            match = PREFIX.match(line)
            if not match:
                unknown.append({'line': number, 'raw': line}); continue
            pid, stamp, body = int(match['pid']), float(match['stamp']), match['body']
            stamp_ns = _decimal_seconds_ns(match['stamp'])
            if body.startswith(('+++', '---')):
                lifecycle.append({'pid_or_tid': pid, 'printed_epoch_seconds': stamp, 'printed_epoch_ns': stamp_ns,
                                  'line': number, 'raw': body}); continue
            resumed = RESUMED.match(body)
            if resumed:
                name = resumed['name']; initial = pending.pop(pid, None)
                if initial is None or initial['name'] != name:
                    unknown.append({'line': number, 'raw': line, 'reason': 'resumed_without_matching_entry'})
                    if initial is not None:
                        events.append({**initial, 'status': 'incomplete_replaced_by_other_resume'})
                    initial = {'pid_or_tid': pid, 'name': name, 'entry_line': None,
                               'printed_entry_epoch_seconds': None, 'raw_entry': None}
                initial.update(resume_line=number, printed_resume_epoch_seconds=stamp,
                               printed_resume_epoch_ns=stamp_ns, raw_resume=body)
            else:
                call = CALL.match(body)
                if not call:
                    unknown.append({'line': number, 'raw': line}); continue
                name = call['name']
                initial = {'pid_or_tid': pid, 'name': name, 'entry_line': number,
                           'printed_entry_epoch_seconds': stamp, 'printed_entry_epoch_ns': stamp_ns, 'raw_entry': body}
                if '<unfinished ...>' in body:
                    if pid in pending:
                        events.append({**pending[pid], 'status': 'incomplete_replaced_by_new_entry'})
                    pending[pid] = initial; continue
            duration = DURATION.search(body)
            return_text = body.rsplit(' = ', 1)[1] if ' = ' in body else None
            if return_text is not None and duration:
                return_text = return_text[:return_text.rfind(' <')]
            recorded = (initial.get('raw_entry') or '') + (' ' + body if resumed else '')
            initial.update(status='completed' if duration else 'completed_duration_unavailable',
                           observed_syscall_wall_seconds=float(duration['duration']) if duration else None,
                           observed_syscall_wall_ns=_decimal_seconds_ns(duration['duration']) if duration else None,
                           return_text=return_text, return_value=_integer_result(return_text) if return_text else None,
                           path_renderings=re.findall(r'<((?:/|UNIX|TCP|UDP)[^<>]*)>', recorded),
                           quoted_argument_renderings=re.findall(r'"(?:[^"\\]|\\.)*"', recorded))
            events.append(initial)
    for item in pending.values():
        events.append({**item, 'status': 'incomplete_at_end', 'observed_syscall_wall_seconds': None})
    counts, durations, returns = {}, {}, {}
    for event in events:
        name = event['name']; counts[name] = counts.get(name, 0) + 1
        duration = event.get('observed_syscall_wall_seconds')
        if duration is not None:
            durations[name] = durations.get(name, 0.0) + duration
        if name in ('read', 'pread64', 'readv', 'write', 'pwrite64', 'writev'):
            value = event.get('return_value')
            if value is not None and value >= 0:
                returns[name] = returns.get(name, 0) + value
    return {'schema_version': 1, 'scope': 'ptrace-observed syscall intervals/counts, not physical disk latency or benchmark timing',
            'kernel_event_loss_count': None, 'loss_status': 'strace supplies no kernel event-loss counter; incomplete/unparsed input retained',
            'syscall_counts': counts, 'sum_observed_syscall_wall_seconds': durations,
            'positive_buffer_syscall_return_bytes': returns, 'unparsed_lines': unknown,
            'utf8_replacement_line_numbers': decode_replacements,
            'incomplete_events': sum(e['status'].startswith('incomplete') for e in events),
            'lifecycle': lifecycle, 'events': events}


def _owned_target_identity(tracer, pid):
    """Only a live direct child in this still-owned tracer's session/group."""
    if tracer.returncode is not None:
        return None
    try:
        leader = parse_linux_stat(Path('/proc', str(tracer.pid), 'stat').read_text(encoding='utf-8'))
        target = parse_linux_stat(Path('/proc', str(pid), 'stat').read_text(encoding='utf-8'))
        if (leader['parent_pid'] != os.getpid() or leader['process_group_id'] != tracer.pid
                or leader['session_id'] != tracer.pid or target['parent_pid'] != tracer.pid
                or target['process_group_id'] != tracer.pid or target['session_id'] != tracer.pid
                or target['state'] == 'Z'):
            return None
        return {'pid': pid, 'starttime_ticks': target['starttime_ticks']}
    except (OSError, ValueError):
        return None


def _discover_target(tracer, raw_path, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        children = Path('/proc') / str(tracer.pid) / 'task' / str(tracer.pid) / 'children'
        try:
            ids = [int(x) for x in children.read_text(encoding='ascii').split()]
            if len(ids) == 1:
                identity = _owned_target_identity(tracer, ids[0])
                if identity is not None:
                    return ids[0], 'owned_strace_direct_child_proc', identity
        except OSError:
            pass
        try:
            with raw_path.open(encoding='utf-8', errors='replace') as stream:
                for line in stream:
                    match = PREFIX.match(line)
                    if match and match['body'].startswith('execve('):
                        pid = int(match['pid']); identity = _owned_target_identity(tracer, pid)
                        return pid, 'owned_strace_first_execve_record', identity
        except OSError:
            pass
        if tracer.poll() is not None:
            break
        time.sleep(.001)
    return None, 'unavailable_before_trace_exit_or_discovery_timeout', None


def _signal_owned_group(child, expected_birth, sig, report):
    """Do not reap between verifying the owned leader and signaling its group.

    The unreaped direct child pins its PID/group identity during this operation.
    No other thread in this standalone helper reaps that child.
    """
    event = {'signal': sig, 'tracer_pid': child.pid}
    if child.returncode is not None or expected_birth is None:
        event['status'] = 'not_signaled_owned_leader_unavailable'
    else:
        try:
            stat = parse_linux_stat(Path('/proc', str(child.pid), 'stat').read_text(encoding='utf-8'))
            if (stat['starttime_ticks'] != expected_birth or stat['parent_pid'] != os.getpid()
                    or stat['process_group_id'] != child.pid or stat['session_id'] != child.pid):
                event['status'] = 'not_signaled_identity_mismatch'
            else:
                os.killpg(child.pid, sig)
                event['status'] = 'signaled_verified_owned_unreaped_group'
        except ProcessLookupError:
            event['status'] = 'group_already_gone'
        except (OSError, ValueError) as error:
            event.update(status='not_signaled_verification_unavailable', reason=type(error).__name__)
    report.setdefault('cleanup_group_signals', []).append(event)
    return event['status'] == 'signaled_verified_owned_unreaped_group'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='Fresh diagnostic attempt directory')
    parser.add_argument('--interval-ms', type=float, default=10)
    parser.add_argument('--timeout-seconds', type=float, default=240)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if os.name != 'posix' or not Path('/proc/self/stat').exists():
        parser.error('This native lane requires Linux procfs and strace')
    if not command or not (.001 <= args.interval_ms / 1000 <= 1) or args.timeout_seconds <= 0:
        parser.error('Target command and positive timeout/1..1000ms interval required')
    forbidden = ('--password', '--token', '--secret', '--authorization', '--certificate', '--public-key')
    if any(arg.lower() == key or arg.lower().startswith(key + '=') for arg in command for key in forbidden):
        parser.error('Credential-bearing command options are outside this diagnostic lane')
    inherited = [name for name in ('DOTNET_DiagnosticPorts', 'DOTNET_EnableEventPipe', 'DOTNET_EventPipeConfig',
                                   'DOTNET_EventPipeOutputPath', 'DOTNET_DefaultDiagnosticPortSuspend') if os.environ.get(name)]
    if inherited:
        parser.error('Separate native lane refuses inherited EventPipe control variables: ' + ','.join(inherited))
    executable = shutil.which(command[0])
    if executable is None:
        parser.error('Target executable not found')
    tracer = shutil.which('strace')
    if tracer is None:
        parser.error('strace is unavailable; no installation or permission changes attempted')
    output = Path(args.output).resolve(); output.mkdir(parents=True, exist_ok=False)
    (output / 'native-helper.py.txt').write_bytes(Path(__file__).read_bytes())
    (output / 'os-observer.py.txt').write_bytes(Path(__file__).with_name('tooling_os_observer.py').read_bytes())
    report = {'schema_version': 1, 'mode': 'native_diagnostic_not_benchmark', 'status': 'started',
              'command': command, 'target_executable_resolved': executable,
              'started_monotonic_ns': time.monotonic_ns(), 'started_utc_ns': time.time_ns(),
              'interval_seconds': args.interval_ms / 1000, 'timeout_seconds': args.timeout_seconds,
              'credentials_policy': 'caller must supply credential-free fixtures; helper rejects common credential flags and retains no environment/buffer payloads; arbitrary child stdout/stderr is not scrubbed',
              'stderr_scope': 'target and tracer standard error combined',
              'performance_qualification': 'not_applicable_diagnostic_only',
              'limits': ['Ptrace and counter polling perturb execution; no benchmark acceptance or direct disk latency.',
                         'Scheduler samples are cumulative observations, not exact CSwitch events.',
                         'strace follows owned target descendants; pid_or_tid is retained until lifecycle/observer identity resolves it.',
                         'Unseen short-lived threads and last-lifetime counters remain possible.',
                         'Separate EventPipe/native executions cannot be fused as exact causal overlaps.']}
    def save():
        (output / 'manifest.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n', encoding='utf-8', newline='\n')
    save()
    raw = output / 'native.raw.log'
    launch_command = [executable, *command[1:]]
    argv = [tracer, '-f', '-ttt', '-T', '-yy', '-e', 'trace=' + SYSCALLS,
            '-e', 'raw=' + RAW_BUFFERS, '-o', str(raw), '--', *launch_command]
    report['tracer_argv'] = argv
    stop = threading.Event(); observation = {}; worker = None; child = None; tracer_birth = None
    stdout = stderr = None; communication_complete = False
    try:
        version = subprocess.run([tracer, '--version'], capture_output=True, check=True)
        (output / 'strace-version.txt').write_bytes(version.stdout + version.stderr)
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        launched = time.monotonic()
        try:
            tracer_birth = parse_linux_stat(Path('/proc', str(child.pid), 'stat').read_text(encoding='utf-8'))['starttime_ticks']
        except (OSError, ValueError):
            pass
        report['tracer_pid'] = child.pid; save()
        target, discovery, identity = _discover_target(child, raw, min(5, args.timeout_seconds))
        report.update(target_pid=target, target_discovery=discovery, target_owned_identity=identity)
        if target is not None and identity is not None:
            def sample():
                try:
                    observation.update(observe_process(target, output / 'proc.jsonl', stop,
                                                       interval=args.interval_ms / 1000, expected_identity=identity))
                except Exception as error:
                    observation.update(status='observer_failed', error={'type': type(error).__name__, 'message': str(error)})
            worker = threading.Thread(target=sample, name='owned-native-proc-observer'); worker.start()
            try:
                observed_exe = os.readlink('/proc/' + str(target) + '/exe')
                report['target_executable_observed'] = observed_exe
                report['target_executable_matches_requested'] = os.path.samefile(observed_exe, executable)
                report['target_executable_match_scope'] = 'sample may precede exec transition; raw owned execve record also retained'
            except OSError as error:
                report['target_executable_observation_error'] = type(error).__name__
        save()
        try:
            stdout, stderr = child.communicate(timeout=max(0, args.timeout_seconds - (time.monotonic() - launched)))
            communication_complete = True
        except subprocess.TimeoutExpired as timeout:
            report['timed_out'] = True
            stdout, stderr = timeout.stdout, timeout.stderr
            # Only the still-unreaped owned session leader and its process group.
            _signal_owned_group(child, tracer_birth, signal.SIGINT, report)
            try:
                stdout, stderr = child.communicate(timeout=10)
                communication_complete = True
            except subprocess.TimeoutExpired:
                _signal_owned_group(child, tracer_birth, signal.SIGKILL, report)
                stdout, stderr = child.communicate(timeout=10)
                communication_complete = True
        report['exit'] = child.returncode
        report['status'] = 'completed' if child.returncode == 0 and not report.get('timed_out') else 'failed_target_or_tracer'
    except Exception as error:
        report.update(status='failed', error={'type': type(error).__name__, 'message': str(error)})
        if isinstance(error, subprocess.TimeoutExpired):
            stdout, stderr = error.stdout, error.stderr
        if child is not None and child.poll() is None:
            _signal_owned_group(child, tracer_birth, signal.SIGTERM, report)
            try:
                stdout, stderr = child.communicate(timeout=10)
                communication_complete = True
            except subprocess.TimeoutExpired:
                _signal_owned_group(child, tracer_birth, signal.SIGKILL, report)
                try:
                    stdout, stderr = child.communicate(timeout=10)
                    communication_complete = True
                except subprocess.TimeoutExpired as timeout:
                    stdout, stderr = timeout.stdout or b'', timeout.stderr or b''
                    report['cleanup_unresolved'] = True
            report['exit'] = child.returncode
    finally:
        stop.set()
        if worker is not None:
            worker.join()
        report['observer'] = observation if worker is not None else None
        for name, data in [('stdout', stdout), ('stderr', stderr)]:
            report[name + '_capture_status'] = ('complete' if communication_complete else 'partial') if data is not None else 'unavailable'
            if data is not None:
                (output / (name + '.txt')).write_bytes(data)
        report['coverage_status'] = 'sampled_partial_lifetime' if observation.get('samples', 0) else 'native_log_only_no_counter_samples'
        if raw.exists():
            parsed = parse_strace(raw)
            (output / 'parsed.json').write_text(json.dumps(parsed, indent=2, allow_nan=False) + '\n', encoding='utf-8', newline='\n')
            report['native_summary'] = {k: v for k, v in parsed.items() if k not in ('events', 'lifecycle', 'unparsed_lines')}
            report['native_summary']['unparsed_lines'] = len(parsed['unparsed_lines'])
        report.update(finished_monotonic_ns=time.monotonic_ns(), finished_utc_ns=time.time_ns())
        save()
    print(json.dumps({'status': report['status'], 'target_pid': report.get('target_pid'), 'output': str(output)}))
    return 0 if report['status'] == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
