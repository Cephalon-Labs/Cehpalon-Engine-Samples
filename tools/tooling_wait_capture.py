"""Owned same-process Linux EventPipe + strace wait/I/O diagnostic capture.

No benchmark or physical-I/O qualification. This module never attaches to an
unrelated PID, alters tracing policy, or enables privileges.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import types

import trace_tooling as runtime
import trace_tooling_native as native
import tooling_os_observer as os_observer

SYSCALLS = native.SYSCALLS + ',futex,futex_waitv,clock_nanosleep,sched_yield,restart_syscall'
RAW_BUFFERS = native.RAW_BUFFERS
PROVIDERS = 'Microsoft-Windows-DotNETRuntime:0x411C14FCCBD:5,Cehpalon-Tooling-Diagnostic:0x1:4'


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _clock():
    before = time.perf_counter_ns()
    utc = time.time_ns()
    after = time.perf_counter_ns()
    return {'perf_counter_ns': before, 'utc_ns': utc, 'perf_before_ns': before, 'perf_after_ns': after}


def _save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n', encoding='utf-8', newline='\n')


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _functions(module):
    for value in vars(module).values():
        if isinstance(value, types.FunctionType) and value.__module__ == module.__name__:
            yield value
        elif isinstance(value, type) and value.__module__ == module.__name__:
            for member in vars(value).values():
                if isinstance(member, (staticmethod, classmethod)):
                    member = member.__func__
                if isinstance(member, types.FunctionType):
                    yield member


def _compiled_codes(code, qualified=''):
    # Python 3.10 CodeType has no co_qualname. Reconstruct lexical paths;
    # function bodies (CO_NEWLOCALS) insert <locals>, class bodies do not.
    result = {qualified or '<module>': code}
    for child in code.co_consts:
        if isinstance(child, types.CodeType):
            parent = qualified + ('.<locals>' if qualified and code.co_flags & 0x02 else '')
            child_qualified = (parent + '.' if parent else '') + child.co_name
            result.update(_compiled_codes(child, child_qualified))
    return result


def _code_info(code):
    def constant(value):
        if isinstance(value, types.CodeType):
            return {'code': _code_info(value)}
        if isinstance(value, bytes):
            return {'bytes': value.hex()}
        if isinstance(value, tuple):
            return {'tuple': [constant(v) for v in value]}
        if isinstance(value, frozenset):
            return {'frozenset': sorted((constant(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))}
        if value is Ellipsis:
            return {'ellipsis': True}
        if isinstance(value, complex):
            return {'complex': [value.real, value.imag]}
        return value
    return {name: getattr(code, name) for name in
            ('co_name', 'co_filename', 'co_firstlineno', 'co_argcount',
             'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals', 'co_stacksize',
             'co_flags', 'co_names', 'co_varnames', 'co_freevars', 'co_cellvars')} | {
                 'co_code': code.co_code.hex(), 'co_linetable': code.co_linetable.hex(),
                 'co_qualname_if_available': getattr(code, 'co_qualname', None),
                 'co_exceptiontable_if_available': getattr(code, 'co_exceptiontable', b'').hex(),
                 'co_consts': [constant(value) for value in code.co_consts]}


def _source_state():
    """Match executed function code to frozen source, and keep both fingerprints.

    Source hashes alone cannot identify modules loaded before an on-disk edit.
    Matching compiled function/method code detects that mismatch, including stale
    pyc function code. This is checked provenance, not immutable attestation.
    """
    state = {}
    for name, (module, path, original) in _BOOT_SOURCES.items():
        _require(path.read_bytes() == original, 'Source changed since module import: ' + str(path))
        functions = list(_functions(module))
        _require({function.__qualname__ for function in functions} == _BOOT_FUNCTION_NAMES[name],
                 'Loaded function inventory changed: ' + name)
        code_filenames = {function.__code__.co_filename for function in functions}
        compiled = {filename: _compiled_codes(compile(original, filename, 'exec', dont_inherit=True,
                                                       optimize=sys.flags.optimize)) for filename in code_filenames}
        codes = {}
        for function in functions:
            code = function.__code__
            candidate = compiled[code.co_filename].get(function.__qualname__)
            info = _code_info(code)
            fingerprint = _sha(json.dumps(info, sort_keys=True).encode('utf-8'))
            _require(candidate is not None and _code_info(candidate) == info,
                     'Loaded function differs from frozen source: ' + name + ':' + function.__qualname__)
            codes[function.__qualname__] = fingerprint
        state[name] = {'absolute_path': str(path), 'source_sha256': _sha(original),
                       'loaded_function_code_sha256': codes}
    _require(SYSCALLS == _BOOT_CONSTANTS['syscalls'] and RAW_BUFFERS == _BOOT_CONSTANTS['raw_buffers']
             and PROVIDERS == _BOOT_CONSTANTS['providers']
             and runtime.PROVIDERS == _BOOT_CONSTANTS['legacy_providers'], 'Loaded capture constants changed')
    return state


def _absolute_file(value):
    path = Path(value)
    _require(path.is_absolute() and path.is_file(), 'Absolute existing diagnostic input required: ' + str(value))
    return path.resolve()


def _wait(predicate, tracer, deadline, description, collector=None, *, allow_successful_tracer_exit=False):
    while time.perf_counter() < deadline:
        if predicate():
            return
        tracer_exit = tracer.poll()
        _require(tracer_exit is None or allow_successful_tracer_exit and tracer_exit == 0,
                 'Tracer/target exited before ' + description)
        if collector is not None:
            _require(collector.poll() is None, 'Collector exited before ' + description)
        time.sleep(.010)
    raise TimeoutError('Timed out waiting for ' + description)


def _remaining(deadline):
    remaining = deadline - time.perf_counter()
    if remaining <= 0:
        raise TimeoutError('Combined capture deadline expired')
    return remaining


def _discover_managed_target(tracer, raw, executable, deadline, report):
    """Join successful exact-host execve to a live owned child before leasing.

    strace may briefly create setup children that never exec the target. Their
    presence under /proc/.../children is diagnostic only, never target identity.
    """
    discovery = {'proc_child_candidate_ids': [], 'execve_records': [],
                 'scope': 'Only successful exact-host raw execve plus live birth/parent/group/session and matching executable establishes target lease'}
    report['target_discovery_diagnostics'] = discovery
    children_seen, pending, candidates = set(), {}, []
    offset, partial, line_number = 0, b'', 0
    exec_path = re.compile(r'^execve\(("(?:[^"\\]|\\.)*"),')
    while time.perf_counter() < deadline:
        try:
            children = Path('/proc', str(tracer.pid), 'task', str(tracer.pid), 'children').read_text(encoding='ascii')
            children_seen.update(int(value) for value in children.split())
            discovery['proc_child_candidate_ids'] = sorted(children_seen)
        except (OSError, ValueError) as error:
            discovery['last_proc_children_error'] = type(error).__name__
        try:
            with raw.open('rb') as stream:
                stream.seek(offset)
                chunk = stream.read(1024 * 1024)
                offset += len(chunk)
            lines = (partial + chunk).split(b'\n')
            partial = lines.pop()
            for encoded in lines:
                line_number += 1
                match = native.PREFIX.match(encoded.decode('utf-8'))
                if not match:
                    continue
                pid, body = int(match['pid']), match['body']
                if body.startswith('execve('):
                    record = {'pid_candidate': pid, 'entry_line': line_number,
                              'printed_entry_epoch_text': match['stamp'], 'status': 'raw_execve_observed_not_leased'}
                    path = exec_path.match(body)
                    if path:
                        # The pinned SDK path is ASCII and needs no strace C
                        # escaping. Fail closed on unsupported renderings.
                        if path[1].isascii() and '\\' not in path[1]:
                            record['executable_rendered'] = path[1][1:-1]
                        else:
                            record['path_parse_status'] = 'escaped_or_nonascii_path_unsupported'
                    if '<unfinished ...>' in body:
                        pending[pid] = record
                        continue
                elif body.startswith('<... execve resumed>'):
                    record = pending.pop(pid, None)
                    if record is None:
                        discovery.setdefault('orphan_execve_resume_lines', []).append(line_number)
                        continue
                    record['resume_line'] = line_number
                else:
                    continue
                result = body.rsplit(' = ', 1)[1] if ' = ' in body else None
                value = native._integer_result(result) if result is not None else None
                record['return_value'] = value
                discovery['execve_records'].append(record)
                if value != 0 or not record.get('executable_rendered'):
                    record['status'] = 'execve_not_successful_or_exact_path_unavailable'
                    continue
                try:
                    exact_path = os.path.samefile(record['executable_rendered'], executable)
                except OSError as error:
                    record.update(status='execve_path_verification_unavailable', reason=type(error).__name__)
                    continue
                if not exact_path:
                    record['status'] = 'foreign_execve_path_not_target'
                    continue
                candidates.append(record)
        except FileNotFoundError:
            discovery['raw_status'] = 'not_yet_created'
        except OSError as error:
            discovery.update(raw_status='read_unavailable', raw_error=type(error).__name__)
        _require(len(partial) <= 1024 * 1024, 'Raw startup line exceeds bounded discovery buffer')
        for record in candidates:
            if record.get('permanently_rejected'):
                continue
            pid = record['pid_candidate']
            identity = native._owned_target_identity(tracer, pid)
            if identity is None:
                record['status'] = 'successful_execve_but_live_owned_child_unavailable'
                continue
            first = record.setdefault('first_live_owned_identity', identity)
            if identity != first:
                record.update(status='birth_changed_before_lease_rejected', permanently_rejected=True)
                continue
            try:
                observed = os.readlink('/proc/' + str(pid) + '/exe')
                same = os.path.samefile(observed, executable)
            except OSError as error:
                record.update(status='live_executable_query_unavailable', reason=type(error).__name__)
                continue
            after = native._owned_target_identity(tracer, pid)
            if after != identity:
                record.update(status='birth_or_ownership_changed_during_exec_join_rejected', permanently_rejected=True)
                continue
            if not same:
                record['status'] = 'live_image_not_matching_successful_execve'
                continue
            record['status'] = 'successful_exact_execve_and_live_owned_image_joined'
            discovery['partial_raw_line_bytes_at_lease'] = len(partial)
            proof = {'target_executable_observed': observed, 'target_executable_matches_requested': True,
                     'owned_exec_verified_perf_counter_ns': time.perf_counter_ns(),
                     'target_execve_entry_line': record['entry_line'],
                     'target_execve_resume_line': record.get('resume_line')}
            return pid, 'successful_exact_execve_live_owned_child_join', identity, proof
        _require(tracer.poll() is None, 'Owned tracer exited before a successful managed execve/live child join')
        time.sleep(.010)
    discovery['pending_execve_candidates'] = list(pending.values())
    discovery['partial_raw_line_bytes_at_timeout'] = len(partial)
    raise TimeoutError('No successful exact managed execve could be joined to a live owned child before deadline')


def _cleanup_tracer(tracer, birth, report):
    item = {'role': 'strace-session-leader', 'pid': tracer.pid, 'kill_requested': False}
    if tracer.returncode is None:
        # wait(timeout) does not reap a still-running leader. Do not call poll()
        # before the ownership guard: the unreaped leader pins the group ID.
        try:
            item['returncode'] = tracer.wait(timeout=.05)
            item['joined'] = True
        except subprocess.TimeoutExpired:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                signaled = native._signal_owned_group(tracer, birth, sig, report)
                item['kill_requested'] |= signaled
                if not signaled:
                    item.update(joined=False, ownership_unavailable=True)
                    break
                try:
                    item['returncode'] = tracer.wait(timeout=10)
                    item['joined'] = True
                    break
                except subprocess.TimeoutExpired:
                    item['joined'] = False
    else:
        item.update(returncode=tracer.returncode, joined=True)
    return item


def capture(command, cwd, folder, dotnet, tool, analyzer, timeout=600):
    """Capture one owned Linux target, returning success OR retained failure.

    Creates a fresh folder. After folder creation all preparation/launch/capture
    failures return status=failed with capture.json; callers must check status.
    File/IPC/collector cleanup failures also fail the capture. Existing output is
    never overwritten. Target/tracer output is written directly to separate
    stdout/stderr files, so neither pipe can block while startup is suspended.
    """
    folder = Path(folder).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    trace, raw = folder / 'runtime.nettrace', folder / 'native.raw.log'
    report = {'schema_version': 1, 'mode': 'combined_wait_diagnostic_not_benchmark',
              'role': 'diagnostic_perturbed', 'canonical': False, 'status': 'started',
              'started': _clock(), 'target_argv': list(map(str, command)), 'cwd': str(cwd),
              'providers': PROVIDERS, 'profile': 'dotnet-sampled-thread-time',
              'buffer_mb': 256, 'buffer_mode': 'Drop', 'observer_interval_seconds': .010,
              'python_version': sys.version,
              'clock': {'name': 'perf_counter_ns', 'implementation': time.get_clock_info('perf_counter').implementation,
                        'resolution_seconds': time.get_clock_info('perf_counter').resolution,
                        'utc_mapping': 'bracketed startup/readiness/header/exit/final anchors; no guarantee against between-anchor UTC steps'},
              'startup_coordination': 'owned strace child suspended on one reverse port; verified OS observer ready before collector resumes that same endpoint',
              'target_stderr_scope': 'owned target plus strace diagnostics combined',
              'event_loss': {'native_kernel_event_loss_count': None, 'eventpipe_reported_loss': None,
                             'status': 'EventPipe analysis required; strace provides no kernel loss count'},
              'limits': ['strace, EventPipe, startup coordination, proc polling and rundown perturb this SAME target execution.',
                         'futex wall intervals include scheduling/ptrace and may restart; they are not CPU time or proof of a managed lock owner.',
                         'Native syscalls/CPU counters and runtime GC episodes require bounded clock/TID correlation before attribution.',
                         'Buffer payload contents are suppressed; caller must supply credential-free arguments and fixture output.',
                         'Child stdout/stderr and syscall file/address metadata are retained, not scrubbed.',
                         'I/O includes diagnostic IPC; logical byte returns/mmap/waits are not physical disk latency.',
                         'Scheduler counters remain sampled partial lifetime; no exact CSwitch or privilege changes.',
                         'Restarted/incomplete/unparsed raw records remain explicit; unknown native loss is never zero.']}
    tracer = collector = observer = None
    tracer_birth = None
    handles = []
    ipc_dir = None
    observed = {}
    stop, ready = threading.Event(), threading.Event()
    source_before = binary_before = None
    _save(folder / 'capture.json', report)
    try:
        _require(sys.platform.startswith('linux') and Path('/proc/self/stat').is_file(), 'Linux procfs required; no policy changes attempted')
        _require(type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0,
                 'Positive finite capture timeout required')
        report['timeout_seconds'] = timeout
        snapshots = folder / 'source-snapshots'
        snapshots.mkdir()
        for name, (_, _, original) in _BOOT_SOURCES.items():
            (snapshots / (name + '.py.txt')).write_bytes(original)
        report['imported_source_sha256'] = {name: _sha(original) for name, (_, _, original) in _BOOT_SOURCES.items()}
        source_before = _source_state()
        report['source_provenance_before'] = source_before
        report['source_provenance_scope'] = 'Frozen import-time source bytes match loaded function/method code and inventory; fingerprints checked before/after capture. Globals/defaults/imported bindings are not attested; trusted caller/checkout, not immutable execution attestation.'
        cwd = Path(cwd).resolve()
        _require(cwd.is_dir(), 'Target working directory exists')
        dotnet, tool, analyzer = map(_absolute_file, (dotnet, tool, analyzer))
        command = list(map(str, command))
        _require(len(command) >= 2, 'Direct dotnet managed target command required')
        executable, assembly = map(_absolute_file, command[:2])
        _require(os.path.samefile(executable, dotnet), 'Managed target uses the pinned dotnet host')
        command[:2] = [str(executable), str(assembly)]
        forbidden = ('--password', '--token', '--secret', '--authorization', '--certificate', '--public-key')
        _require(not any(arg.lower() == key or arg.lower().startswith(key + '=') for arg in command for key in forbidden),
                 'Credential-bearing command flags are outside this fixture lane')
        strace = shutil.which('strace')
        _require(strace is not None, 'strace unavailable; no install/elevation attempted')
        strace = _absolute_file(strace)
        binary_before = {str(p): _sha(p.read_bytes()) for p in set((dotnet, tool, analyzer, assembly, strace))}
        report.update(target_argv=command, cwd=str(cwd), binary_sha256=binary_before)
        report['prelaunch_hashing_scope'] = 'Hashing/preparation can prime filesystem caches; not cold disk'
        # Both subprocesses get independent non-suspending base environments.
        # Only strace/its target receives this private suspended target endpoint.
        collector_environment, removed = runtime.diagnostics_environment(dict(os.environ), False)
        active_eventpipe = [prefix + name for prefix in ('DOTNET_', 'COMPlus_')
                            for name in ('EnableEventPipe', 'EventPipeConfig', 'EventPipeOutputPath', 'EventPipeThreadSamplingRate')
                            if collector_environment.get(prefix + name)]
        _require(not active_eventpipe, 'Inherited automatic EventPipe control is outside this lane: ' + ','.join(active_eventpipe))
        ipc_dir = Path(tempfile.mkdtemp(prefix='cehpalon-wait-'))
        ipc_dir.chmod(0o700)
        port = str(ipc_dir / 'p.sock')
        environment = dict(collector_environment, DOTNET_DiagnosticPorts=port + ',connect,suspend')
        report.update(child_removed_diagnostic_aliases=removed, diagnostic_port=port,
                      target_executable_resolved=str(executable), syscall_filter=SYSCALLS, raw_buffer_filter=RAW_BUFFERS)
        argv = [str(strace), '-f', '-ttt', '-T', '-yy', '-e', 'trace=' + SYSCALLS,
                '-e', 'raw=' + RAW_BUFFERS, '-o', str(raw), '--', *command]
        collect = [str(dotnet), 'exec', '--roll-forward', 'Major', str(tool), 'collect', '--output', str(trace),
                   '--profile', 'dotnet-sampled-thread-time', '--providers', PROVIDERS,
                   '--diagnostic-port', port, '--resume-runtime:true', '--buffersize', '256', '--buffering-mode', 'Drop']
        report.update(tracer_argv=argv, collector_argv=collect)
        for name in ('collector.stdout.txt', 'collector.stderr.txt', 'target.stdout.txt', 'target.stderr.txt'):
            handles.append((folder / name).open('wb'))
        deadline = time.perf_counter() + timeout
        report['target_launch_perf_counter_ns'] = time.perf_counter_ns()
        report['target_launch_utc_ns'] = time.time_ns()
        tracer = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=handles[2], stderr=handles[3],
                                  stdin=subprocess.DEVNULL, start_new_session=True)
        report['tracer_pid'] = tracer.pid
        tracer_birth = os_observer.parse_linux_stat(Path('/proc', str(tracer.pid), 'stat').read_text())['starttime_ticks']
        report['tracer_starttime_ticks'] = tracer_birth
        pid, discovery, identity, executable_proof = _discover_managed_target(
            tracer, raw, executable, min(deadline, time.perf_counter() + 10), report)
        report.update(target_pid=pid, target_discovery=discovery, target_owned_identity=identity)
        report.update(executable_proof)
        _save(folder / 'capture.json', report)

        def observe():
            try:
                observed['summary'] = os_observer.observe_process(pid, folder / 'os.jsonl', stop, interval=.010,
                                                                 expected_identity=identity, ready_event=ready)
            except Exception:
                observed['failure'] = traceback.format_exc()

        observer = threading.Thread(target=observe, name='owned-combined-os-observer', daemon=True)
        observer.start()
        _wait(lambda: ready.is_set() or 'failure' in observed or 'summary' in observed, tracer,
              min(deadline, time.perf_counter() + 30), 'observer live identity sample')
        _require(ready.is_set() and 'failure' not in observed, 'Observer flushed live identity sample before any resume')
        _require(native._owned_target_identity(tracer, pid) == identity
                 and (folder / 'target.stdout.txt').stat().st_size == 0, 'Owned startup-suspended target lease preserved')
        report['observer_ready_perf_counter_ns'] = time.perf_counter_ns()
        report['observer_ready_clock_anchor'] = _clock()
        report['collector_launch_perf_counter_ns'] = time.perf_counter_ns()
        collector = subprocess.Popen(collect, cwd=cwd, env=collector_environment, stdout=handles[0], stderr=handles[1],
                                     stdin=subprocess.PIPE)
        report['collector_pid'] = collector.pid
        _save(folder / 'capture.json', report)
        log = folder / 'collector.stdout.txt'
        def session_ready():
            text = log.read_text(encoding='utf-8', errors='replace')
            return 'Process' in text and 'Output File' in text
        # Fast targets may exit before stdout header polling; the collector
        # header is checked first, then liveness only while still waiting.
        _wait(session_ready, tracer, min(deadline, time.perf_counter() + 60), 'same-port EventPipe session', collector,
              allow_successful_tracer_exit=True)
        report['session_and_reverse_resume_header_observed_perf_counter_ns'] = time.perf_counter_ns()
        report['session_header_clock_anchor'] = _clock()
        report['header_timing_scope'] = 'post-resume acknowledgment upper bound, never the exact resume clock'
        _save(folder / 'capture.json', report)
        report['tracer_exit'] = tracer.wait(timeout=_remaining(deadline))
        report['target_exit_perf_counter_ns'] = time.perf_counter_ns()
        report['tracer_exit_clock_anchor'] = _clock()
        report['target_exit_clock_scope'] = 'upper bound after strace followed-group completion; exact target exit remains in native raw lifecycle'
        stop.set()
        observer.join(timeout=15)
        _require(not observer.is_alive(), 'OS observer joined')
        _require('failure' not in observed and observed.get('summary', {}).get('samples', 0) > 0, 'Successful sampled observer output')
        report['collector_exit'] = collector.wait(timeout=min(120, _remaining(deadline)))
        _require(report['tracer_exit'] == 0 and report['collector_exit'] == 0, 'Tracer and collector completed successfully')
        _require(trace.is_file() and trace.stat().st_size > 0 and raw.is_file() and raw.stat().st_size > 0,
                 'Both retained raw streams are nonempty')
        report.update(status='completed', trace_bytes=trace.stat().st_size, trace_sha256=_sha(trace.read_bytes()))
    except Exception:
        report.update(status='failed', failure=traceback.format_exc())
    finally:
        stop.set()
        cleanup = []
        if tracer is not None:
            try:
                cleanup.append(_cleanup_tracer(tracer, tracer_birth, report))
            except Exception:
                cleanup.append({'role': 'strace-session-leader', 'pid': tracer.pid,
                                'joined': False, 'failure': traceback.format_exc()})
        if collector is not None:
            item = {'role': 'collector', 'pid': collector.pid, 'kill_requested': False}
            try:
                if collector.poll() is None:
                    collector.kill()
                    item['kill_requested'] = True
                item.update(returncode=collector.wait(timeout=15), joined=True)
            except Exception:
                item.update(joined=False, failure=traceback.format_exc())
            cleanup.append(item)
            if collector.stdin is not None:
                try:
                    collector.stdin.close()
                except Exception:
                    report.update(status='failed', collector_stdin_close_failure=traceback.format_exc())
        report['owned_process_cleanup'] = cleanup
        if report.get('target_owned_identity') is not None:
            try:
                identity = report['target_owned_identity']
                remaining_target = os_observer.parse_linux_stat(Path('/proc', str(identity['pid']), 'stat').read_text())
                if remaining_target['starttime_ticks'] == identity['starttime_ticks']:
                    if remaining_target['state'] == 'Z':
                        report['target_cleanup_status'] = 'same_birth_zombie_not_running'
                    else:
                        report.update(status='failed', cleanup_failure=True,
                                      target_cleanup_status='same_birth_process_still_observed_no_unverified_signal')
                else:
                    report['target_cleanup_status'] = 'pid_reused_no_signal'
            except FileNotFoundError:
                report['target_cleanup_status'] = 'proc_entry_absent_after_owned_tracer_cleanup'
            except Exception:
                report.update(status='failed', cleanup_failure=True,
                              target_cleanup_status='unavailable', target_cleanup_failure=traceback.format_exc())
        if observer is not None:
            observer.join(timeout=15)
            report['observer_joined'] = not observer.is_alive()
        report['observer'] = observed
        if any(not row.get('joined') or row.get('kill_requested') for row in cleanup) or report.get('observer_joined') is False:
            report.update(status='failed', cleanup_failure=True)
        for handle in handles:
            try:
                handle.close()
            except Exception:
                report.setdefault('output_close_failures', []).append(traceback.format_exc())
                report['status'] = 'failed'
        if raw.exists():
            try:
                parsed = native.parse_strace(raw)
                _save(folder / 'parsed.json', parsed)
                report['native_summary'] = {k: v for k, v in parsed.items() if k not in ('events', 'lifecycle', 'unparsed_lines')}
                report['native_summary']['unparsed_lines'] = len(parsed['unparsed_lines'])
                exits = [row for row in parsed['lifecycle'] if row['pid_or_tid'] == report.get('target_pid')
                         and row['raw'] == '+++ exited with 0 +++']
                report['target_exit'] = 0 if len(exits) == 1 else None
                if report['status'] == 'completed' and len(exits) != 1:
                    report.update(status='failed', target_exit_unproven=True)
            except Exception:
                report.update(status='failed', native_parse_failure=traceback.format_exc())
        if ipc_dir is not None:
            try:
                socket = ipc_dir / 'p.sock'
                if socket.exists():
                    socket.unlink()
                ipc_dir.rmdir()
            except OSError:
                report.update(status='failed', retained_ipc_directory=str(ipc_dir))
        if source_before is not None:
            try:
                report['source_provenance_after'] = _source_state()
                _require(source_before == report['source_provenance_after'], 'Loaded source/runtime function fingerprints changed during capture')
            except Exception:
                report.update(status='failed', source_freeze_failure=traceback.format_exc())
        if binary_before is not None:
            try:
                report['binary_sha256_after'] = {p: _sha(Path(p).read_bytes()) for p in binary_before}
                _require(binary_before == report['binary_sha256_after'], 'Pinned binary bytes changed during capture')
            except Exception:
                report.update(status='failed', binary_freeze_failure=traceback.format_exc())
        report['finished'] = _clock()
        _save(folder / 'capture.json', report)
    return report


# Freeze bytes immediately upon this module import, before caller preparation or
# any capture starts. Runtime code fingerprints must agree with these snapshots.
_BOOT_MODULES = [sys.modules[__name__], runtime, native, os_observer, runtime.benchmark]
_launch_main = sys.modules.get('__main__')
if (getattr(_launch_main, '__file__', None)
        and Path(_launch_main.__file__).resolve() == Path(runtime.__file__).resolve()):
    _BOOT_MODULES.append(_launch_main)
_BOOT_SOURCES = {module.__name__: (module, Path(module.__file__).resolve(), Path(module.__file__).read_bytes())
                 for module in _BOOT_MODULES}
_BOOT_FUNCTION_NAMES = {name: {function.__qualname__ for function in _functions(module)}
                        for name, (module, _, _) in _BOOT_SOURCES.items()}
_BOOT_CONSTANTS = {'syscalls': SYSCALLS, 'raw_buffers': RAW_BUFFERS, 'providers': PROVIDERS,
                   'legacy_providers': runtime.PROVIDERS}
