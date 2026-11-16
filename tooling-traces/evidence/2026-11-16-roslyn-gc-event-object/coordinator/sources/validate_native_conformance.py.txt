"""Offline, fail-closed gates for the synchronous 4096-byte native fixture.

This validates collector conformance only. It neither qualifies performance nor
turns sampled counters or ptrace syscall duration into physical disk latency.
"""
import argparse
import hashlib
import json
from pathlib import Path
import posixpath
import re

from trace_tooling_native import parse_strace

EXPECTED_HASH = 'd67c656e01756650d77717b0839985a056ec28ffe174601d690fc407a2ceffca'
STAGES = ['fixture.startup', 'fixture.cpu', 'fixture.explicit-gc-conformance-only',
          'fixture.file-write-read', 'fixture.result']
SOURCE_FILES = {'native-helper.py.txt': 'trace_tooling_native.py',
                'os-observer.py.txt': 'tooling_os_observer.py'}
UNIX_EPOCH_DOTNET_TICKS = 621355968000000000


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _fd(event):
    match = re.match(r'\w+\((0x[0-9a-fA-F]+|\d+)(?=[,<)])', event.get('raw_entry') or '')
    return int(match[1], 0) if match else None


def _complete(event):
    return (event.get('status') == 'completed'
            and type(event.get('observed_syscall_wall_ns')) is int
            and event['observed_syscall_wall_ns'] >= 0
            and type(event.get('printed_entry_epoch_ns')) is int)


def validate_native_conformance(folder, *, expected_source_sha256=None):
    """Return gated evidence or raise ValueError; never modify the attempt.

    The optional mapping pins snapshot filenames to predeclared SHA256 values.
    Otherwise snapshots must match these two helper files beside this validator.
    This fixture deliberately performs all known.bin operations synchronously on
    its main native TID. A future concurrent fixture needs an explicit FD-sharing
    model rather than broadening this gate to every traced descendant.
    """
    folder = Path(folder)
    manifest, parsed, known = [_read(folder / name) for name in
                               ('manifest.json', 'parsed.json', 'known.json')]
    snapshots = {name: _digest(folder / name) for name in SOURCE_FILES}
    expected = expected_source_sha256 if expected_source_sha256 is not None else {
        name: _digest(Path(__file__).with_name(source)) for name, source in SOURCE_FILES.items()}
    _require(set(expected) == set(SOURCE_FILES) and snapshots == expected,
             'Native/observer source snapshot hashes differ from pinned source')
    _require(parsed == parse_strace(folder / 'native.raw.log'), 'Parsed evidence differs from retained raw bytes')
    _require(manifest.get('status') == 'completed' and manifest.get('exit') == 0
             and not manifest.get('timed_out') and not manifest.get('cleanup_unresolved')
             and not manifest.get('cleanup_group_signals'), 'Native target/tracer completion and unsignaled cleanup')
    _require(all(manifest.get(name + '_capture_status') == 'complete' for name in ('stdout', 'stderr')),
             'Complete child stdout/stderr required')
    pid, tracer = manifest.get('target_pid'), manifest.get('tracer_pid')
    identity = manifest.get('target_owned_identity')
    _require(type(pid) is int and type(tracer) is int and pid != tracer
             and isinstance(identity, dict) and identity.get('pid') == pid
             and type(identity.get('starttime_ticks')) is int, 'Owned PID and birth lease required')
    _require(manifest.get('target_executable_matches_requested') is True, 'Observed target executable identity')
    _require(known.get('status') == 'passed'
             and known.get('role') == 'synthetic_collector_conformance_not_acceptance'
             and known.get('processId') == pid and known.get('bytes') == 4096
             and known.get('sha256') == EXPECTED_HASH and known.get('forcedGcFixtureOnly') is True,
             'Known semantic PID/4096-byte/hash/fixture-only result')
    _require((folder / 'known.bin').stat().st_size == 4096 and _digest(folder / 'known.bin') == EXPECTED_HASH,
             'Actual known.bin 4096-byte content hash')
    _require(not parsed.get('unparsed_lines') and not parsed.get('utf8_replacement_line_numbers')
             and parsed.get('incomplete_events') == 0, 'No silently missing native records')
    _require(parsed.get('kernel_event_loss_count') is None, 'Unknown native event-loss counter stays unknown')
    events = sorted(parsed['events'], key=lambda e: e['entry_line'])
    _require(any(e['name'] == 'execve' and e['pid_or_tid'] == pid and e.get('return_value') == 0
                 and _complete(e) for e in events), 'Successful exact-target execve')
    exits = [e for e in parsed['lifecycle'] if e['pid_or_tid'] == pid and e['raw'] == '+++ exited with 0 +++']
    _require(len(exits) == 1, 'Exactly one successful exact-target native exit')
    exit_utc = exits[0]['printed_epoch_ns']
    rows = [json.loads(line) for line in (folder / 'proc.jsonl').read_text(encoding='utf-8').splitlines()]
    samples = [row for row in rows if row['kind'] == 'sample']
    observer = manifest.get('observer') or {}
    summaries = [row['data'] for row in rows if row['kind'] == 'observer_summary']
    _require(summaries == [observer], 'Manifest observer summary exactly matches retained JSONL summary')
    _require(observer.get('target_identity') == identity and observer.get('expected_target_identity') == identity
             and observer.get('samples') == len(samples) and len(samples) > 1, 'Owned counter samples and count')
    previous = None
    seen_tids = set()
    for sample in samples:
        stat = sample['process_stat']
        _require(sample['target_identity'] == identity and stat['id'] == pid
                 and stat['starttime_ticks'] == identity['starttime_ticks']
                 and stat['parent_pid'] == tracer and stat['process_group_id'] == tracer
                 and stat['session_id'] == tracer, 'Every process sample preserves owned birth/parent/group/session')
        begin, end = sample['begin']['perf_counter_ns'], sample['end']['perf_counter_ns']
        _require(begin <= end and sample['read_duration_ns'] == end - begin
                 and (previous is None or begin >= previous), 'Ordered perf-counter samples and read durations')
        previous = end
        for thread in sample['threads']:
            seen_tids.add(thread['tid'])
            _require(thread['tid'] == thread['stat']['id']
                     and thread['starttime_ticks'] == thread['stat']['starttime_ticks']
                     and (thread['tid'] != pid or thread['starttime_ticks'] == identity['starttime_ticks']),
                     'Native TID birth identity')
    _require(observer.get('races') == 0 and all(not s['races'] for s in samples), 'Fixture has no unexplained sample races')
    failures = observer.get('read_failures', [])
    if observer.get('status') == 'partial_target_unavailable':
        # procfs can disappear between normal process exit and the next poll.
        # Accept that observation only with independent target exit and bounded
        # terminal evidence, retaining the partial-lifetime label and tail.
        _require(len(failures) == 1 and failures[0]['reason'] == 'FileNotFoundError'
                 and failures[0]['message'].endswith("'/proc/" + str(pid) + "/stat'")
                 and samples[-1]['end']['utc_ns'] <= exit_utc <= failures[0]['utc_ns']
                 and failures[0]['perf_counter_ns'] <= observer['finished']['perf_counter_ns'],
                 'Partial observer failure must be terminal proc disappearance after independently observed normal exit')
    else:
        _require(observer.get('status') == 'completed_exit_observed' and not failures,
                 'Unexpected observer failure/status')
    markers = [json.loads(line) for line in (folder / 'known.json.spans.jsonl').read_text(encoding='utf-8').splitlines()]
    _require(len(markers) == 5 and [m['stage'] for m in markers] == STAGES
             and [m['sequence'] for m in markers] == list(range(1, 6)), 'Five ordered known fixture markers')
    previous_end = None
    anchor = markers[0]
    for marker in markers:
        _require(marker['processId'] == pid and marker['osThreadId'] == pid and pid in seen_tids
                 and marker['frequency'] == 1_000_000_000, 'Same-process Linux native main TID and nanosecond marker clock')
        _require(all(marker[key] == anchor[key] for key in ('utcAnchorTicks', 'anchorBeforeTicks', 'anchorAfterTicks')),
                 'Consistent same-execution UTC/perf anchor')
        _require(marker['anchorBeforeTicks'] <= marker['anchorAfterTicks'] <= marker['startTicks']
                 <= marker['endTicks'] <= marker['markerBeforeTicks'] <= marker['markerAfterTicks']
                 and (previous_end is None or marker['startTicks'] >= previous_end), 'Marker/anchor clock ordering')
        _require(samples[0]['begin']['perf_counter_ns'] <= marker['startTicks']
                 and marker['markerAfterTicks'] <= samples[-1]['end']['perf_counter_ns'], 'Markers within observed process lifetime')
        previous_end = marker['markerAfterTicks']
    # Only this fixture's exact remote absolute path, not another known.bin.
    command = manifest['command']
    remote_file = posixpath.join(posixpath.dirname(command[-1]), 'known.bin')
    _require(remote_file.startswith('/') and command[-1].endswith('/known.json'), 'Exact absolute fixture output argument')
    file_marker = markers[3]
    utc_anchor = (anchor['utcAnchorTicks'] - UNIX_EPOCH_DOTNET_TICKS) * 100
    span_min = utc_anchor + file_marker['startTicks'] - anchor['anchorAfterTicks']
    span_max = utc_anchor + file_marker['endTicks'] - anchor['anchorBeforeTicks']
    offsets = [clock['utc_ns'] - clock['perf_counter_ns'] for sample in samples
               for clock in (sample['begin'], sample['end'])]
    active, intervals, operations = {}, [], []
    reads = writes = 0
    for event in events:
        name, tid = event['name'], event['pid_or_tid']
        if name == 'openat' and event.get('return_value', -1) is not None and event.get('return_value', -1) >= 0:
            result_path = re.fullmatch(r'\d+<([^<>]+)>', event.get('return_text') or '')
            if result_path and result_path[1] == remote_file:
                _require(tid == pid and _complete(event), 'Known file open belongs to synchronous fixture main TID')
                fd = event['return_value']
                _require(fd not in active, 'No overlapping known-file descriptor reuse')
                active[fd] = {'fd': fd, 'open_line': event['entry_line'], 'read_bytes': 0, 'write_bytes': 0}
                operations.append(event)
        fd = _fd(event)
        if fd not in active:
            continue
        _require(tid == pid, 'Known descriptor use on another TID requires a separate FD-sharing model')
        if name in ('read', 'pread64', 'readv', 'write', 'pwrite64', 'writev'):
            _require(_complete(event) and type(event.get('return_value')) is int and event['return_value'] >= 0,
                     'Known-file buffer syscall has complete nonnegative return/duration')
            count = event['return_value']
            direction = 'read' if name in ('read', 'pread64', 'readv') else 'write'
            active[fd][direction + '_bytes'] += count
            reads += count if direction == 'read' else 0
            writes += count if direction == 'write' else 0
            operations.append(event)
        elif name == 'close':
            _require(_complete(event) and event.get('return_value') == 0
                     and remote_file in event.get('path_renderings', []), 'Successful exact-known-file close')
            interval = active.pop(fd)
            interval['close_line'] = event['entry_line']
            intervals.append(interval)
            operations.append(event)
    _require(not active and reads == writes == 4096 and len(intervals) >= 2,
             'Closed known-file FD lifetimes attribute exactly 4096 read and 4096 written bytes')
    for event in operations:
        _require(span_min <= event['printed_entry_epoch_ns']
                 and event['printed_entry_epoch_ns'] + event['observed_syscall_wall_ns'] <= span_max,
                 'Known-file syscall interval fits same-execution marker UTC uncertainty envelope')
    return {'status': 'passed', 'role': 'synthetic_native_collector_conformance_not_acceptance',
            'source_sha256': snapshots, 'target_identity': identity, 'known_file_sha256': EXPECTED_HASH,
            'evidence_sha256': {name: _digest(folder / name) for name in
                                ('manifest.json', 'native.raw.log', 'parsed.json', 'proc.jsonl',
                                 'known.json', 'known.json.spans.jsonl', 'known.bin')},
            'known_file_read_bytes': reads, 'known_file_write_bytes': writes, 'fd_lifetimes': intervals,
            'known_file_native_lines': [e['entry_line'] for e in operations],
            'same_execution_file_span_utc_envelope_ns': [span_min, span_max],
            'observed_utc_minus_perf_offset_ns': {'min': min(offsets), 'max': max(offsets),
                                                 'spread': max(offsets) - min(offsets)},
            'observer_status': observer['status'], 'observer_samples': len(samples),
            'observer_thread_cpu_ns': observer['observer_thread_cpu_ns'],
            'tail_since_last_sample_ns': observer['tail_since_last_sample_ns'],
            'kernel_event_loss_count': None,
            'limits': ['Sampled partial lifetime; startup and terminal counters are not complete.',
                       'Unknown native kernel loss; syscall duration includes ptrace/scheduler perturbation.',
                       'Known file buffer return bytes do not prove physical disk traffic or durability.',
                       'One startup UTC/perf anchor assumes no intervening UTC clock step; sampled offsets can miss between-poll changes.',
                       'Separate native/EventPipe executions cannot be joined as exact causal overlaps.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder')
    args = parser.parse_args()
    print(json.dumps(validate_native_conformance(args.folder), indent=2, allow_nan=False))
