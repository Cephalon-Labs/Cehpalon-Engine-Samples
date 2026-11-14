"""Offline, conditional same-execution wait correlation; never acceptance evidence.

No targets, profilers, builds, subprocesses or remote operations are launched.
All output goes to one NEW directory. Original evidence is read only.
"""
import argparse
from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import posixpath
import re
import sys
import traceback
import types

RUNTIME = 'Microsoft-Windows-DotNETRuntime'
MARKER = 'Cehpalon-Tooling-Diagnostic'
EPOCH_TICKS = 621355968000000000
EXPECTED_STAGES = ['fixture.startup', 'fixture.cpu', 'fixture.managed-wait',
                   'fixture.native-futex-wait', 'fixture.explicit-gc-conformance-only',
                   'fixture.file-write-read', 'fixture.result']
STAGE_COUNTS = {'execute.setup': 330, 'generator.run': 168, 'pe.emit': 330,
                'compiler.wall': 330, 'journal.persistence': 306, 'ast.verify': 348,
                'runtime.verify': 42, 'fixture.setup': 60, 'fixture.edit': 54, 'hash': 988}
LIMITS = [
    'Diagnostic execution is perturbed; no benchmark, production or provider qualification.',
    'WaitHandle start/stop is elapsed runtime observation, not blocked time, CPU time or a proven managed-lock owner.',
    'Futex intervals are tracer-observed syscall wall intervals, including ptrace/scheduling; EAGAIN/EINTR/restarts are separate outcomes.',
    'Native epoch joins assume no hidden wall-clock excursion between retained anchors and a constant offset on the selected bracket.',
    'Agreement at anchors cannot prove absence of an intervening clock step; incompatible offsets remain unassigned.',
    'Printed strace timestamps/durations carry plus-or-minus one printed unit; integer nanoseconds do not imply nanosecond accuracy.',
    'Native kernel event loss is unknown even after normal exit; observed omissions and parser failures remain explicit.',
    'Overlap unions are physically capped and nonexclusive; GC, managed waits and native calls may overlap each other.',
    'Missing/unpaired GC or wait events are not proof that no GC/wait occurred.',
    'Proc counters are sampled partial lifetime only; no interpolation/prorating, exact CSwitch or physical-disk latency claim.',
    'CLI without markers has no precise EventPipe-to-native temporal join; only lifetime counts/distributions and wait pairs.',
    'Source snapshots/hashes are provenance, not immutable executing-code attestation.']


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def records(path):
    with Path(path).open(encoding='utf-8-sig') as stream:
        for line in stream:
            yield json.loads(line)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def ep_ns(value):
    return Fraction(str(value)) * 1_000_000


def ticks_ns(ticks, frequency):
    require(type(ticks) is int and type(frequency) is int and frequency > 0, 'Integer clock ticks and positive frequency')
    return Fraction(ticks * 1_000_000_000, frequency)


def floor(value):
    return value.numerator // value.denominator if isinstance(value, Fraction) else math.floor(value)


def ceil(value):
    return -floor(-value)


def union_length(intervals):
    total = Fraction(0)
    end = None
    for a, b in sorted((a, b) for a, b in intervals if b > a):
        if end is None or a > end:
            total += b - a
        elif b > end:
            total += b - end
        end = max(end, b) if end is not None else b
    return total


def union_overlap(row_start, row_end, candidates, duration):
    """Conservative conditional core/envelope union bounds, never exclusive causes.

    Every candidate is (startLower,startUpper,endLower,endUpper). Quantization
    and clock uncertainty are retained rather than assigning point estimates.
    """
    guaranteed = union_length((max(row_start[1], x[1]), min(row_end[0], x[2])) for x in candidates)
    possible = union_length((max(row_start[0], x[0]), min(row_end[1], x[3])) for x in candidates)
    return {'guaranteed_observed_union_ns': floor(min(duration, max(0, guaranteed))),
            'possible_observed_union_ns': ceil(min(duration, max(0, possible))),
            'physical_span_duration_ns_lower': floor(duration),
            'physical_span_duration_ns_upper': ceil(duration), 'candidate_intervals': len(candidates)}


def wait_pairs(events, pid):
    active, poisoned, paired, errors = {}, set(), [], []
    unidentified = []
    def compatible(pattern, key):
        return all(a is None or a == b for a,b in zip(pattern,key))
    previous = {}
    for event in events:
        if event.get('provider') != RUNTIME or event.get('eventId') not in (301, 302):
            continue
        payload = event.get('payload', {})
        identity = (event.get('processId'), payload.get('ClrInstanceID'), event.get('threadId'))
        valid = identity[0] == pid and type(identity[1]) is int and identity[1] >= 0 and type(identity[2]) is int and identity[2] > 0
        if not valid:
            errors.append({'reason': 'invalid_wait_identity', 'event': event})
            pattern = tuple(value if type(value) is int and value >= (0 if i == 1 else 1) else None
                            for i,value in enumerate(identity))
            unidentified.append(pattern)
            for key in list(active):
                if compatible(pattern,key):
                    errors.append({'reason':'unidentifiable_wait_record_poisoned_compatible_active_key',
                                   'previous':active.pop(key),'event':event})
                    poisoned.add(key)
            continue
        if any(compatible(pattern,identity) for pattern in unidentified):
            poisoned.add(identity)
            active.pop(identity,None)
        timestamp = ep_ns(event['timeMsec'])
        if identity in previous and timestamp < previous[identity]:
            poisoned.add(identity)
            active.pop(identity, None)
            errors.append({'reason': 'out_of_order_wait_clock_key_poisoned', 'event': event})
        previous[identity] = timestamp
        if identity in poisoned:
            errors.append({'reason': 'wait_identity_poisoned_for_rest_of_trace', 'event': event})
            continue
        if event['eventId'] == 301:
            if identity in active:
                errors.append({'reason': 'nested_ambiguous_start_key_poisoned', 'previous': active.pop(identity), 'event': event})
                poisoned.add(identity)
            elif type(payload.get('WaitSource')) is not int or 'AssociatedObjectID' not in payload:
                poisoned.add(identity)
                errors.append({'reason': 'missing_start_metadata_key_poisoned', 'event': event})
            else:
                active[identity] = event
        else:
            start = active.pop(identity, None)
            if start is None:
                poisoned.add(identity)
                errors.append({'reason': 'stop_without_unique_start_key_poisoned', 'event': event})
            elif timestamp < ep_ns(start['timeMsec']):
                poisoned.add(identity)
                errors.append({'reason': 'negative_wait_interval_key_poisoned', 'start': start, 'event': event})
            else:
                paired.append({'processId': pid, 'clrInstanceId': identity[1], 'osThreadId': identity[2],
                               'startMsec': start['timeMsec'], 'endMsec': event['timeMsec'],
                               'waitSource': start['payload']['WaitSource'],
                               'associatedObjectId': start['payload']['AssociatedObjectID'],
                               'observed_elapsed_ns_lower': floor(timestamp - ep_ns(start['timeMsec'])),
                               'observed_elapsed_ns_upper': ceil(timestamp - ep_ns(start['timeMsec'])),
                               'scope': 'observed_start_stop_elapsed_not_blocked_or_cpu_time'})
    errors.extend({'reason': 'start_without_stop', 'event': event} for event in active.values())
    return paired, errors, poisoned


def attribute_wait_pairs(pairs, ambiguous_tids, errors):
    retained, by_tid = [], defaultdict(list)
    for pair in pairs:
        if pair['osThreadId'] in ambiguous_tids:
            pair['identity_attribution_status'] = 'native_tid_generation_ambiguous_temporal_attribution_excluded'
            errors.append({'reason':'native_tid_generation_identity_ambiguous','pair':pair})
        else:
            pair['identity_attribution_status'] = 'no_native_tid_reuse_observed_in_retained_scope'
            retained.append(pair)
            by_tid[pair['osThreadId']].append(pair)
    return retained, by_tid


def validate_span_identity(spans,pid):
    require(all(s['processId'] == pid and type(s['osThreadId']) is int and s['osThreadId'] > 0
                and type(s['frequency']) is int and s['frequency'] > 0 for s in spans), 'Every span belongs to capture target PID/native TID/clock')


def anchors_from_spans(spans):
    anchors = {}
    for span in spans:
        frequency = span['frequency']
        options = [('startup', span.get('anchorBeforeTicks'), span.get('anchorAfterTicks'), span.get('utcAnchorTicks'))]
        if all(k in span for k in ('utcSampleBeforeTicks', 'utcSampleAfterTicks', 'utcSampleTicks')):
            options.append(('span:' + str(span['sequence']), span['utcSampleBeforeTicks'], span['utcSampleAfterTicks'], span['utcSampleTicks']))
        for label, before, after, utc in options:
            require(all(type(v) is int for v in (before, after, utc)) and before <= after, 'Ordered integer UTC sample bracket')
            key = (before, after, utc, frequency, span['processId'])
            anchors[key] = {'id': label, 'before': before, 'after': after, 'utcTicks': utc,
                            'frequency': frequency, 'pid': span['processId']}
    return sorted(anchors.values(), key=lambda a: (a['before'], a['after'], a['utcTicks']))


def constant_offset(span, anchors):
    """Exactly the predeclared nearest-bracket/interior strict intersection."""
    start, end, frequency, pid = (span[k] for k in ('startTicks', 'endTicks', 'frequency', 'processId'))
    same = [a for a in anchors if a['frequency'] == frequency and a['pid'] == pid]
    before = [a for a in same if a['before'] <= start]
    after = [a for a in same if a['after'] >= end]
    if not before or not after:
        return {'status': 'unbracketed_native_unassigned', 'anchors_used': 0}, None
    first = max(before, key=lambda a: (a['before'], a['after']))
    last = min(after, key=lambda a: (a['after'], a['before']))
    chosen = [a for a in same if first['before'] <= a['before'] and a['after'] <= last['after']]
    # Retain both brackets even if their acquisition windows overlap unusually.
    for a in (first, last):
        if a not in chosen:
            chosen.append(a)
    bounds = []
    for a in chosen:
        utc = (a['utcTicks'] - EPOCH_TICKS) * 100
        bounds.append((Fraction(utc) - ticks_ns(a['after'], frequency),
                       Fraction(utc + 100) - ticks_ns(a['before'], frequency)))
    lower, upper = max(a for a, _ in bounds), min(b for _, b in bounds)
    info = {'status': 'supported_conditional_constant_offset' if lower <= upper else 'unsupported_constant_offset_native_unassigned',
            'anchors_used': len(chosen), 'first_anchor': first['id'], 'last_anchor': last['id'],
            'offset_lower_ns': floor(lower), 'offset_upper_ns': ceil(upper),
            'utc_quantization_ns': 100, 'assumption': 'no hidden clock excursion/nonconstant offset between retained anchors'}
    return info, (lower, upper) if lower <= upper else None


def eventpipe_offset(spans, markers):
    bounds = []
    for span in spans:
        require(span['sequence'] in markers, 'Missing EventPipe marker')
        marker = markers[span['sequence']]
        require(marker['processId'] == span['processId'] and marker['threadId'] == span['osThreadId'], 'Marker native PID/TID match')
        for key in ('sequence', 'stage', 'startTicks', 'endTicks', 'frequency', 'processId', 'osThreadId',
                    'caseIndex', 'size', 'state', 'variant', 'pairSequence', 'phase', 'markerBeforeTicks',
                    'anchorBeforeTicks', 'anchorAfterTicks', 'utcAnchorTicks'):
            require(marker['payload'].get(key) == span.get(key), 'EventPipe marker/sidecar identity: ' + key)
        require(span['startTicks'] <= span['endTicks'] <= span['markerBeforeTicks'] <= span['markerAfterTicks'], 'Marker bracket clock order')
        stamp = ep_ns(marker['timeMsec'])
        bounds.append((stamp - ticks_ns(span['markerAfterTicks'], span['frequency']),
                       stamp - ticks_ns(span['markerBeforeTicks'], span['frequency'])))
    require(len(markers) == len(spans), 'All marker events match sidecar records')
    lower, upper = max(a for a, _ in bounds), min(b for _, b in bounds)
    return (lower, upper) if lower <= upper else None


def raw_precision(path):
    result = {}
    with Path(path).open(encoding='utf-8', errors='replace') as stream:
        for number, line in enumerate(stream, 1):
            stamp = re.match(r'^\s*(?:\[pid\s+)?\d+\]?\s+\d+\.(\d+)\s+', line)
            duration = re.search(r'\s+<\d+\.(\d+)>\s*$', line)
            result[number] = {'entry_unit_ns': 10 ** (9 - len(stamp[1])) if stamp and 1 <= len(stamp[1]) <= 9 else None,
                              'duration_unit_ns': 10 ** (9 - len(duration[1])) if duration and 1 <= len(duration[1]) <= 9 else None}
    return result


def classify_native(event, precision):
    name = event['name']
    text = (event.get('raw_entry') or '') + ' ' + (event.get('raw_resume') or '')
    outcome = event.get('return_text') or ''
    operation, category, address = None, 'other', None
    if name == 'futex':
        match = re.search(r'^futex\(([^,]+),\s*([^,]+)', text)
        if match:
            address, operation = match[1].strip(), match[2].strip()
            first = operation.split('|')[0].strip()
            if first.startswith('FUTEX_'):
                if first in ('FUTEX_WAIT', 'FUTEX_WAIT_PRIVATE', 'FUTEX_WAIT_BITSET', 'FUTEX_WAIT_BITSET_PRIVATE',
                             'FUTEX_WAIT_REQUEUE_PI', 'FUTEX_WAIT_REQUEUE_PI_PRIVATE'):
                    category = 'wait_capable'
                elif any(first.startswith(x) for x in ('FUTEX_WAKE', 'FUTEX_REQUEUE', 'FUTEX_CMP_REQUEUE')):
                    category = 'wake_or_requeue'
                elif first.startswith(('FUTEX_LOCK_PI', 'FUTEX_TRYLOCK_PI', 'FUTEX_UNLOCK_PI')):
                    category = 'pi_lock_operation_separate'
                else:
                    category = 'unknown_futex_operation'
            else:
                try:
                    command = int(first, 0) & ~(128 | 256)
                    category = 'wait_capable' if command in (0, 9, 11) else 'wake_or_requeue' if command in (1, 3, 4, 5, 10, 12) else 'unknown_futex_operation'
                except ValueError:
                    category = 'unknown_futex_operation'
        else:
            category = 'unparsed_futex_operation'
    elif name == 'futex_waitv':
        category, operation = 'wait_vector_capable', 'futex_waitv_vector_not_single_address'
    elif name == 'restart_syscall':
        category = 'restart_wrapper'
    elif name in ('clock_nanosleep', 'sched_yield'):
        category = 'sleep_or_yield_separate'
    complete = event.get('status') == 'completed' and type(event.get('printed_entry_epoch_ns')) is int and type(event.get('observed_syscall_wall_ns')) is int
    if 'ERESTART' in outcome:
        result = 'restart_pending_not_blocked_duration'
    elif 'EAGAIN' in outcome or 'EWOULDBLOCK' in outcome:
        result = 'condition_mismatch_not_blocked_duration'
    elif 'EINTR' in outcome:
        result = 'interrupted_not_blocked_duration'
    elif not complete:
        result = 'incomplete_or_duration_unavailable'
    elif 'ETIMEDOUT' in outcome:
        result = 'returned_timeout_observed_elapsed'
    elif type(event.get('return_value')) is int and event['return_value'] >= 0:
        result = 'returned_nonnegative_observed_elapsed'
    else:
        result = 'other_error_or_unknown_return'
    eligible = category in ('wait_capable', 'wait_vector_capable') and result in ('returned_timeout_observed_elapsed', 'returned_nonnegative_observed_elapsed')
    entry = precision.get(event.get('entry_line'), {})
    finish = precision.get(event.get('resume_line') or event.get('entry_line'), {})
    q, d = entry.get('entry_unit_ns'), finish.get('duration_unit_ns')
    interval = None
    if eligible and q is not None and d is not None:
        t, elapsed = event['printed_entry_epoch_ns'], event['observed_syscall_wall_ns']
        require(elapsed >= 0, 'Nonnegative printed syscall duration')
        interval = (Fraction(t - q), Fraction(t + q), Fraction(t - q + max(0, elapsed - d)), Fraction(t + q + elapsed + d))
    record = {'native_tid': event['pid_or_tid'], 'syscall': name, 'entry_line': event.get('entry_line'),
              'resume_line': event.get('resume_line'), 'operation': operation, 'address_rendering': address,
              'category': category, 'outcome': result, 'return_text': outcome, 'raw_status': event.get('status'),
              'observed_syscall_wall_ns': event.get('observed_syscall_wall_ns'),
              'eligible_observed_wait_interval': interval is not None,
              'entry_print_unit_ns': q, 'duration_print_unit_ns': d}
    return record, interval


def io_conformance(folder, capture, parsed, precision, spans, anchors):
    known = read(folder/'known.json')
    pid = capture['target_pid']
    expected_hash = 'd67c656e01756650d77717b0839985a056ec28ffe174601d690fc407a2ceffca'
    require(known['status'] == 'passed' and known['processId'] == known['mainNativeTid'] == pid
            and known['workerJoined'] is True and known['managedWaitTimedOut'] is True
            and known['nativeFutexErrno'] == 110 and known['bytes'] == 4096
            and known['sha256'] == expected_hash and known['forcedGcFixtureOnly'] is True,
            'Controlled wait/worker/GC/4096-byte semantics')
    require((folder/'known.bin').stat().st_size == 4096 and sha(folder/'known.bin') == expected_hash,
            'Actual4096-byte known file content')
    span = next(s for s in spans if s['stage'] == 'fixture.file-write-read')
    model, offset = constant_offset(span, anchors)
    require(offset is not None, 'Known file IO has supported constant-offset bracket')
    start_upper = ticks_ns(span['startTicks'],span['frequency']) + offset[1]
    end_lower = ticks_ns(span['endTicks'],span['frequency']) + offset[0]
    path = posixpath.join(posixpath.dirname(capture['target_argv'][-1]),'known.bin')
    require(path.startswith('/'), 'Known absolute Linux fixture output path')
    active, closed, operations = {}, [], []
    read_bytes = write_bytes = 0
    for event in sorted(parsed['events'],key=lambda e:e.get('entry_line') or 0):
        raw = event.get('raw_entry') or ''
        if event['name'] == 'openat':
            rendered = re.fullmatch(r'\d+<([^<>]+)>',event.get('return_text') or '')
            if rendered and rendered[1] == path:
                fd = event['return_value']
                require(event['pid_or_tid'] == pid and fd not in active, 'Known file main-TID FD open lifetime')
                active[fd] = {'fd':fd,'open_line':event['entry_line'],'read_bytes':0,'write_bytes':0}
                operations.append(event)
        match = re.match(r'\w+\((0x[0-9a-fA-F]+|\d+)(?=[,<)])',raw)
        fd = int(match[1],0) if match else None
        if fd not in active:
            continue
        require(event['pid_or_tid'] == pid, 'Known FD cross-thread use requires separate model')
        if event['name'] in ('read','pread64','readv','write','pwrite64','writev'):
            require(type(event.get('return_value')) is int and event['return_value'] >= 0, 'Known file nonnegative return')
            direction = 'read' if event['name'] in ('read','pread64','readv') else 'write'
            active[fd][direction+'_bytes'] += event['return_value']
            if direction == 'read': read_bytes += event['return_value']
            else: write_bytes += event['return_value']
            operations.append(event)
        elif event['name'] == 'close':
            require(event['return_value'] == 0 and path in event['path_renderings'], 'Known FD exact-path close')
            row = active.pop(fd)
            row['close_line'] = event['entry_line']
            closed.append(row)
            operations.append(event)
    require(not active and len(closed) == 2 and read_bytes == write_bytes == 4096,
            'Exactly two closed known FD lifetimes/4096 bytes each direction')
    for event in operations:
        q = precision.get(event.get('entry_line'),{}).get('entry_unit_ns')
        d = precision.get(event.get('resume_line') or event.get('entry_line'),{}).get('duration_unit_ns')
        require(event['status'] == 'completed' and q is not None and d is not None
                and type(event.get('observed_syscall_wall_ns')) is int, 'Known IO complete timestamp/duration/precision')
        require(event['printed_entry_epoch_ns'] - q >= start_upper
                and event['printed_entry_epoch_ns'] + q + event['observed_syscall_wall_ns'] + d <= end_lower,
                'Whole observed IO uncertainty envelope fits conditional known file phase')
    return {'status':'passed_conditional_collector_conformance_only','bytes_read':read_bytes,'bytes_written':write_bytes,
            'fd_lifetimes':closed,'native_lines':[e['entry_line'] for e in operations],'sha256':expected_hash,
            'clock_model':model,'scope':'logical return bytes, not physical IO/durability'}


def native_thread_scope(parsed, pid, proc_samples):
    """Trace-process membership from CLONE_THREAD, with conservative reuse refusal."""
    events = sorted(parsed['events'], key=lambda e: e.get('entry_line') or 0)
    lifetimes = defaultdict(list)
    exits = defaultdict(list)
    for row in parsed['lifecycle']:
        if row['raw'].startswith('+++'):
            exits[row['pid_or_tid']].append(row['line'])
    lifetimes[pid].append((0, min(exits[pid]) if exits[pid] else math.inf, 'owned_main_pid_birth_lease'))
    for event in events:
        line = event.get('entry_line')
        if line is None or event['name'] not in ('clone', 'clone3') or type(event.get('return_value')) is not int or event['return_value'] <= 0:
            continue
        text = (event.get('raw_entry') or '') + ' ' + (event.get('raw_resume') or '')
        if 'CLONE_THREAD' not in text or not any(a <= line <= b for a, b, _ in lifetimes[event['pid_or_tid']]):
            continue
        tid = event['return_value']
        end = min((x for x in exits[tid] if x > line), default=math.inf)
        lifetimes[tid].append((line, end, 'successful_owned_CLONE_THREAD'))
    births = defaultdict(set)
    for sample in proc_samples:
        for thread in sample.get('threads', []):
            births[thread['tid']].add(thread.get('starttime_ticks'))
    ambiguous = {tid for tid in set(lifetimes) | set(births) if len(lifetimes[tid]) > 1 or len(births[tid]) > 1}
    def member(event):
        tid, line = event['pid_or_tid'], event.get('entry_line')
        return tid not in ambiguous and line is not None and any(a <= line <= b for a, b, _ in lifetimes[tid])
    return member, {'thread_ids_from_lifecycle': sorted(t for t,v in lifetimes.items() if v), 'ambiguous_or_reused_tid_numbers': sorted(ambiguous),
                    'proc_observed_births': {str(k): sorted(v, key=lambda x: (x is None, x)) for k, v in births.items()},
                    'scope': 'owned main plus successful CLONE_THREAD lineage; unknown/reused TIDs unassigned; proc observations partial'}


def replay_native(folder, capture):
    """Use frozen reviewed parser source directly, without pyc or primary writes."""
    snapshots = folder / 'source-snapshots'
    modules = {}
    old = sys.modules.get('tooling_os_observer')
    try:
        for name in ('tooling_os_observer', 'trace_tooling_native'):
            path = snapshots / (name + '.py.txt')
            expected = capture['source_provenance_before'][name]['source_sha256']
            require(sha(path) == expected, 'Frozen native parser/observer source hash')
            module = types.ModuleType('_offline_' + name)
            module.__file__ = str(path)
            if name == 'tooling_os_observer':
                sys.modules[name] = module
            exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
            modules[name] = module
        parsed = modules['trace_tooling_native'].parse_strace(folder / 'native.raw.log')
        replay_hash = hashlib.sha256()
        for chunk in json.JSONEncoder(indent=2,allow_nan=False).iterencode(parsed):
            replay_hash.update(chunk.encode('utf-8'))
        replay_hash.update(b'\n')
        require(replay_hash.hexdigest() == sha(folder/'parsed.json'), 'Native parsed bytes equal frozen parser/writer raw replay')
        return parsed
    finally:
        if old is None:
            sys.modules.pop('tooling_os_observer', None)
        else:
            sys.modules['tooling_os_observer'] = old


def matrix(spans, generator):
    rows = [s for s in spans if s['stage'] == 'compiler.wall' and s['phase'] in ('primer', 'measurement')]
    require(Counter(s['stage'] for s in spans) == Counter(STAGE_COUNTS) and len(spans) == 2956, 'Full diagnostic stage matrix retained')
    wanted = {(phase, case, seq, variant) for case in range(9) for phase, seqs in [('primer', range(2)), ('measurement', range(2, 17))]
              for seq in seqs for variant in ('generator', 'manual')}
    actual = [(s['phase'], s['caseIndex'], s['pairSequence'], s['variant']) for s in rows]
    require(len(actual) == 306 and len(set(actual)) == 306 and set(actual) == wanted, 'Exact306 phase/case/pair/variant spans')
    for key, count in [('primers', 36), ('measurements', 270), ('stateSeeds', 12), ('preflight', 3), ('postflight', 18)]:
        require(len(generator[key]) == count, 'Original generator semantic matrix ' + key)
    for phase, name in [('primer', 'primers'), ('measurement', 'measurements')]:
        expected = {(r['caseIndex'], r['pairSequence'], r['variant']) for r in generator[name]}
        require(expected == {(s['caseIndex'], s['pairSequence'], s['variant']) for s in rows if s['phase'] == phase}, 'Every generator row retains one span')
    return rows


def dump_lines(path, rows):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        for row in rows:
            stream.write(json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n')


def distribution(values):
    values = sorted(values)
    return {'count': len(values), 'sum_observed_elapsed_ns': sum(values),
            'minimum_ns': min(values) if values else None, 'maximum_ns': max(values) if values else None,
            'p50_ns': values[math.ceil(.5*len(values))-1] if values else None,
            'p95_ns': values[math.ceil(.95*len(values))-1] if values else None,
            'scope': 'observed syscall wall only; parallel sums may exceed process wall; never blocked or CPU duration'}


def analyze(folder, output, conformance=False):
    folder = Path(folder).resolve()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    summary = {'schema_version': 1, 'status': 'started', 'canonical': False,
               'role': 'offline_same_execution_wait_analysis_not_acceptance', 'limits': LIMITS}
    try:
        c = read(folder / 'capture.json')
        a = read(folder / 'analysis/summary.json')
        pid = c['target_pid']
        require(c['mode'] == 'combined_wait_diagnostic_not_benchmark' and c['status'] == 'completed'
                and c['canonical'] is False and c['target_exit'] == c['tracer_exit'] == c['collector_exit'] == 0,
                'Completed same-execution combined capture required')
        require(len({pid, c['tracer_pid'], c['collector_pid']}) == 3, 'Target/tracer/collector roles use distinct native PIDs')
        require(c['observer_joined'] is True and len(c['owned_process_cleanup']) == 2
                and {x['role'] for x in c['owned_process_cleanup']} == {'strace-session-leader','collector'}
                and all(x.get('joined') and not x.get('kill_requested') for x in c['owned_process_cleanup']), 'Normal owned cleanup')
        require(c['source_provenance_before'] == c['source_provenance_after'] and c['binary_sha256'] == c['binary_sha256_after'], 'Frozen source/binary provenance')
        require(sha(folder / 'runtime.nettrace') == c['trace_sha256'] == a['inputSha256'], 'Same raw trace input bytes')
        require(a['status'] == 'completed', 'Runtime parser completed; quality evaluated separately')
        # Stream every raw record/count; keep only the small relevant payloads.
        wait_events, runtime_pids, event_counts = [], set(), Counter()
        markers = {}
        for event in records(folder/'analysis/events.jsonl'):
            event_counts[event['provider']+'/'+event['name']] += 1
            if event['provider'] == RUNTIME:
                runtime_pids.add(event['processId'])
                if event.get('eventId') in (301,302):
                    wait_events.append(event)
            if event['provider'] == MARKER and 'sequence' in event['payload']:
                seq = event['payload']['sequence']
                require(seq not in markers, 'Unique marker event sequence')
                markers[seq] = event
        require(runtime_pids == {pid}, 'Runtime events belong to actual target PID')
        require(dict(event_counts) == a['eventCounts'] and sum(event_counts.values()) == a['events'], 'Every raw event count replayed without filtering')
        pairs, errors, poisoned = wait_pairs(wait_events,pid)
        parsed = replay_native(folder, c)
        require(parsed['kernel_event_loss_count'] is None, 'Unknown native kernel event loss remains unknown')
        require(not any(e['pid_or_tid'] in (c['tracer_pid'], c['collector_pid']) for e in parsed['events']), 'Native trace excludes collector/tracer own syscall scope')
        samples = []
        for sample in records(folder/'os.jsonl'):
            if sample['kind'] != 'sample':
                continue
            stat = sample['process_stat']
            require(sample['target_identity'] == c['target_owned_identity'] and stat['id'] == pid
                    and stat['starttime_ticks'] == c['target_owned_identity']['starttime_ticks']
                    and stat['parent_pid'] == stat['process_group_id'] == stat['session_id'] == c['tracer_pid'],
                    'All proc samples match owned birth/parent/group/session')
            samples.append({'threads':[{'tid':t['tid'],'starttime_ticks':t.get('starttime_ticks')} for t in sample['threads']]})
        require(samples,'Positive actual proc samples')
        member, thread_scope = native_thread_scope(parsed, pid, samples)
        ambiguous_tids = set(thread_scope['ambiguous_or_reused_tid_numbers'])
        attributable_pairs,pairs_by_tid = attribute_wait_pairs(pairs,ambiguous_tids,errors)
        precision = raw_precision(folder / 'native.raw.log')
        native_rows, native_intervals = [], []
        for event in parsed['events']:
            if event['name'] not in ('futex', 'futex_waitv', 'restart_syscall', 'clock_nanosleep', 'sched_yield'):
                continue
            record, interval = classify_native(event, precision)
            owned = member(event)
            record['owned_target_thread_lifecycle'] = owned
            if not owned:
                record['eligible_observed_wait_interval'] = False
            native_rows.append(record)
            if interval is not None and owned:
                native_intervals.append((event['pid_or_tid'], interval, record))
        dump_lines(output / 'wait-pairs.jsonl', pairs)
        dump_lines(output / 'wait-pairing-errors.jsonl', errors)
        dump_lines(output / 'native-waits.jsonl', native_rows)
        span_files = list(folder.glob('*.spans.jsonl'))
        require(len(span_files) <= 1, 'Unambiguous target span sidecar')
        spans = list(records(span_files[0])) if span_files else []
        validate_span_identity(spans,pid)
        require(not markers or spans, 'No orphan marker events without sidecar')
        row_reports, conformance_rows = [], []
        model_counts = Counter()
        ep_offset = eventpipe_offset(spans, markers) if spans else None
        if spans:
            require([s['sequence'] for s in spans] == list(range(1, len(spans) + 1)), 'Complete ordered target marker sequence')
            anchors = anchors_from_spans(spans)
            if (folder / 'generator.json').is_file():
                selected = matrix(spans, read(folder / 'generator.json'))
                query_role = 'generator306_all_primers_and_measurements'
            else:
                require(conformance, 'Non-generator target spans require explicit conformance mode')
                require([s['stage'] for s in spans] == EXPECTED_STAGES, 'Seven predeclared synthetic stages')
                selected, query_role = spans, 'synthetic_collector_conformance_only'
            gc_data = read(folder / 'analysis/intervals.json').get('suspensions', [])
            gc = [(ep_ns(g['startMsec']), ep_ns(g['startMsec']), ep_ns(g['endMsec']), ep_ns(g['endMsec']))
                  for g in gc_data if g['processId'] == pid and g['gcRelated']]
            managed = [(ep_ns(p['startMsec']), ep_ns(p['startMsec']), ep_ns(p['endMsec']), ep_ns(p['endMsec'])) for p in attributable_pairs]
            for span in selected:
                duration = ticks_ns(span['endTicks'] - span['startTicks'], span['frequency'])
                info, utc_offset = constant_offset(span, anchors)
                model_counts[info['status']] += 1
                r = {'sequence': span['sequence'], 'stage': span['stage'], 'phase': span['phase'],
                     'caseIndex': span['caseIndex'], 'size': span['size'], 'state': span['state'],
                     'variant': span['variant'], 'pairSequence': span['pairSequence'], 'osThreadId': span['osThreadId'],
                     'duration_ns_lower': floor(duration), 'duration_ns_upper': ceil(duration), 'native_clock_model': info,
                     'eventpipe_clock_model': 'strict_all_marker_intersection' if ep_offset else 'unsupported_native_and_runtime_temporal_joins_unassigned',
                     'gc_pairing_status': a.get('eePairingStatus'), 'gc_pairing_errors_processwide': a.get('eePairingErrors'),
                     'native_overlap': None, 'managed_wait_overlap': None, 'gc_envelope_overlap': None,
                     'caller_native_overlap': None, 'caller_native_timeout_overlap': None, 'caller_managed_wait_overlap': None,
                     'same_tid_managed_wait_native_observed_overlap': None,
                     'overlap_scope': 'process-wide proven target threads, including idle/background workers; caller-only fields are separate'}
                if ep_offset:
                    s = ticks_ns(span['startTicks'], span['frequency'])
                    e = ticks_ns(span['endTicks'], span['frequency'])
                    row_s, row_e = (s + ep_offset[0], s + ep_offset[1]), (e + ep_offset[0], e + ep_offset[1])
                    r['managed_wait_overlap'] = union_overlap(row_s, row_e, managed, duration)
                    caller_managed = [(ep_ns(p['startMsec']),ep_ns(p['startMsec']),ep_ns(p['endMsec']),ep_ns(p['endMsec']))
                                      for p in pairs_by_tid[span['osThreadId']]]
                    r['caller_managed_wait_overlap'] = union_overlap(row_s, row_e, caller_managed, duration)
                    r['gc_envelope_overlap'] = union_overlap(row_s, row_e, gc, duration)
                if utc_offset is not None:
                    s = ticks_ns(span['startTicks'], span['frequency'])
                    e = ticks_ns(span['endTicks'], span['frequency'])
                    row_s, row_e = (s + utc_offset[0], s + utc_offset[1]), (e + utc_offset[0], e + utc_offset[1])
                    relevant_native = [(tid, interval, record) for tid, interval, record in native_intervals
                                       if interval[3] >= row_s[0] and interval[0] <= row_e[1]]
                    candidates = [interval for _, interval, _ in relevant_native]
                    r['native_overlap'] = union_overlap(row_s, row_e, candidates, duration)
                    r['caller_native_overlap'] = union_overlap(row_s, row_e,
                        [interval for tid,interval,_ in relevant_native if tid == span['osThreadId']],duration)
                    r['caller_native_timeout_overlap'] = union_overlap(row_s, row_e,
                        [interval for tid,interval,record in relevant_native if tid == span['osThreadId']
                         and record['outcome'] == 'returned_timeout_observed_elapsed'],duration)
                    if ep_offset:
                        intersections = []
                        for tid,n,_ in relevant_native:
                            for pair in pairs_by_tid[tid]:
                                ws = ep_ns(pair['startMsec'])
                                we = ep_ns(pair['endMsec'])
                                # UTC = EventPipe - EPoffset + UTCoffset. Keep
                                # both uncertainties; no assumed clock equality.
                                w = (ws - ep_offset[1] + utc_offset[0], ws - ep_offset[0] + utc_offset[1],
                                     we - ep_offset[1] + utc_offset[0], we - ep_offset[0] + utc_offset[1])
                                if w[3] >= row_s[0] and w[0] <= row_e[1]:
                                    intersections.append((max(w[0], n[0]), max(w[1], n[1]), min(w[2], n[2]), min(w[3], n[3])))
                        r['same_tid_managed_wait_native_observed_overlap'] = union_overlap(row_s, row_e, intersections, duration)
                row_reports.append(r)
            if conformance:
                require(not errors and a['eventsLost'] == 0 and a.get('etlxEventsLost') == 0
                        and a.get('payloadReadErrors') == 0 and a.get('jitStartToLoadIntervals',0) > 0
                        and a.get('sampledThreadEvents',0) > 0 and a.get('gcRelatedEnvelopes',0) > 0,
                        'Positive actual wait/JIT/sample/GC collection with no reported loss or wait pairing error')
                by_stage = {r['stage']: r for r in row_reports}
                managed_row = by_stage['fixture.managed-wait']
                native_row = by_stage['fixture.native-futex-wait']
                require(managed_row['osThreadId'] == pid and managed_row['caller_managed_wait_overlap'] is not None
                        and managed_row['caller_managed_wait_overlap']['guaranteed_observed_union_ns'] > 0, 'Positive caller observed managed WaitHandle overlap')
                require(native_row['native_clock_model']['status'] == 'supported_conditional_constant_offset'
                        and native_row['osThreadId'] == pid and native_row['caller_native_timeout_overlap'] is not None
                        and native_row['caller_native_timeout_overlap']['guaranteed_observed_union_ns'] > 0,
                        'Positive strictly bounded controlled native futex overlap')
                require(any(record['native_tid'] == pid and record['outcome'] == 'returned_timeout_observed_elapsed'
                            and record['eligible_observed_wait_interval'] for record in native_rows), 'Controlled main native futex ETIMEDOUT observed')
                summary['io_conformance'] = io_conformance(folder,c,parsed,precision,spans,anchors)
                summary['conformance_status'] = 'passed_wait_collection_and_conditional_clocks_only'
        else:
            require(not conformance, 'Synthetic conformance requires target markers')
            query_role = 'cli_lifetime_only_no_precise_eventpipe_native_temporal_join'
        dump_lines(output / 'rows.jsonl', row_reports)
        outcomes = Counter((r['category'], r['outcome']) for r in native_rows)
        consumed = [folder/'capture.json',folder/'runtime.nettrace',folder/'analysis/events.jsonl',
                    folder/'analysis/summary.json',folder/'native.raw.log',folder/'parsed.json',folder/'os.jsonl',
                    folder/'source-snapshots/tooling_os_observer.py.txt',folder/'source-snapshots/trace_tooling_native.py.txt']
        if spans:
            consumed.extend([span_files[0],folder/'analysis/intervals.json'])
        if (folder/'generator.json').is_file():
            consumed.append(folder/'generator.json')
        if conformance:
            consumed.extend([folder/'known.json',folder/'known.bin'])
        summary.update(status='completed', query_role=query_role, target_pid=pid,
                       rows=len(row_reports), marker_events=len(markers), sidecar_spans=len(spans),
                       input_runtime_raw_events=sum(event_counts.values()),
                       wait_starts=sum(e.get('eventId') == 301 for e in wait_events),
                       wait_stops=sum(e.get('eventId') == 302 for e in wait_events),
                       paired_waits=len(pairs), attributable_wait_pairs=len(attributable_pairs),
                       wait_pairing_errors=len(errors), permanently_poisoned_wait_keys=len(poisoned),
                       native_outcomes=[{'category': k[0], 'outcome': k[1], 'count': n,
                           'observed_syscall_wall_distribution': distribution([r['observed_syscall_wall_ns'] for r in native_rows
                               if (r['category'],r['outcome']) == k and type(r['observed_syscall_wall_ns']) is int])}
                           for k, n in sorted(outcomes.items())],
                       native_eligible_observed_wait_intervals=len(native_intervals), native_clock_models=dict(model_counts),
                       eventpipe_reported_loss=a['eventsLost'], etlx_reported_loss=a.get('etlxEventsLost'),
                       runtime_payload_errors=a.get('payloadReadErrors'), gc_pairing_errors=a.get('eePairingErrors'),
                       gc_correlation_scope='observed_paired_episodes_only_no_absence_proof',
                       native_kernel_event_loss_count=None, native_incomplete_events=parsed['incomplete_events'],
                       native_unparsed_lines=len(parsed['unparsed_lines']), native_utf8_replacements=len(parsed.get('utf8_replacement_line_numbers', [])),
                       native_thread_scope=thread_scope,
                       proc_scope={'samples': len(samples), 'status': c.get('observer', {}).get('summary', {}).get('status'),
                                   'counter_attribution': 'not assigned to phases; cumulative samples and endpoint windows retained in source',
                                   'no_linear_prorating': True},
                       source_inputs_sha256={str(p.relative_to(folder)): sha(p) for p in consumed},
                       analyzer_source_sha256=sha(__file__))
        summary['quality'] = 'observed_with_explicit_partial_dimensions' if (errors or a['eventsLost'] or a.get('payloadReadErrors')
            or a.get('eePairingErrors') or parsed['incomplete_events'] or parsed['unparsed_lines']
            or any(status != 'supported_conditional_constant_offset' for status in model_counts)) else 'observed_under_declared_clock_assumptions_not_qualified'
        summary['output_sha256'] = {p.name: sha(p) for p in output.iterdir() if p.is_file()}
    except Exception:
        summary.update(status='failed', failure=traceback.format_exc())
    with (output/'summary.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(summary, stream, indent=2, allow_nan=False)
        stream.write('\n')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--conformance', action='store_true')
    args = parser.parse_args()
    result = analyze(args.folder, args.output, args.conformance)
    print(json.dumps({'status': result['status'], 'rows': result.get('rows'), 'output': args.output}))
    raise SystemExit(0 if result['status'] == 'completed' else 1)
