"""ADR0022 positive marker/task fixture validation; offline, not performance acceptance."""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import analyze_tooling_tasks as tasks

CASES = ['scheduled', 'completed-before-wait', 'synchronous-block', 'forced-inline', 'nested', 'exception', 'cancellation']
MARKER = 'Cehpalon-Task-Conformance'
FIELDS = ('sequence', 'caseName', 'kind', 'taskId', 'schedulerId', 'processId', 'nativeTid', 'stopwatchTicks', 'frequency')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def lines(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8-sig').splitlines()]


def verify(events, analysis, capture, target, points):
    check = tasks.require
    check(target.get('status') == 'passed' and target.get('ownedThreadsJoined') is True, 'Target semantic/owned join gates')
    pid = target['processId']
    check(tasks.integer(pid, 1) and tasks.integer(target.get('mainNativeTid'), 1), 'Exact positive target identity')
    check(capture.get('status') == 'completed' and type(capture.get('target_pid')) is int and capture.get('target_pid') == pid, 'Owned successful capture identity')
    check([c['name'] for c in target['cases']] == CASES, 'Complete fixed seven-case order')
    check(not any('EventSourceMessage' in e.get('name', '') for e in events), 'Provider error message rejected')
    observed = [e for e in events if e.get('provider') == MARKER]
    check(len(observed) == len(points) > 0, 'All positive sidecar markers required')
    marker_by_sequence = {}
    for e in observed:
        payload = e['payload']
        check(all(type(e[k]) is int for k in ('eventId', 'version', 'opcode')) and e['eventId'] == 1 and e['version'] == 0 and e['opcode'] == 0, 'Exact marker template')
        sequence = payload['sequence']
        check(type(sequence) is int and sequence not in marker_by_sequence, 'Unique integer marker sequence')
        marker_by_sequence[sequence] = e
    check([e['payload']['sequence'] for e in observed] == list(range(1, len(points) + 1)), 'Raw marker order complete')
    check([p['sequence'] for p in points] == list(range(1, len(points) + 1)), 'Complete ordered sidecar sequence')
    lower = upper = None
    by_case = {}
    for point in points:
        e = marker_by_sequence[point['sequence']]
        check(all(type(point.get(k)) is int for k in ('sequence', 'taskId', 'schedulerId', 'processId', 'nativeTid', 'stopwatchTicks', 'frequency', 'markerBeforeTicks', 'markerAfterTicks')), 'Exact sidecar integer fields')
        check(type(e['processId']) is int and type(e['threadId']) is int and point['nativeTid'] > 0, 'Exact marker header integer identity')
        check(e['processId'] == pid == point['processId'] and e['threadId'] == point['nativeTid'], 'Marker header identity')
        check(all(type(e['payload'].get(k)) is type(point[k]) and e['payload'][k] == point[k] for k in FIELDS), 'Exact sidecar payload parity')
        check(point['frequency'] > 0 and point['markerBeforeTicks'] <= point['markerAfterTicks'], 'Valid marker brackets')
        stamp = Fraction(str(e['timeMsec']))
        lo = stamp - Fraction(point['markerAfterTicks'] * 1000, point['frequency'])
        hi = stamp - Fraction(point['markerBeforeTicks'] * 1000, point['frequency'])
        lower = lo if lower is None else max(lower, lo)
        upper = hi if upper is None else min(upper, hi)
        by_case.setdefault(point['caseName'], []).append((point, e))
    check(lower <= upper, 'Common marker clock intersection')
    check(set(by_case) == set(CASES), 'Only declared cases')
    result = tasks.analyze(events, analysis, pid)
    check(not result['errors'] and not result['unfinished_waits'], 'All observed selected-task identities complete and unpoisoned')
    states = {t['task_id']: t for t in result['tasks']}
    bindings = {}
    proof = []
    for case in target['cases']:
        name = case['name']; records = by_case[name]
        check(case.get('outcome') == ('exception' if name == 'exception' else 'canceled' if name == 'cancellation' else 'success'), 'Declared semantic outcome')
        check(case.get('expectedTaskWait') is (name != 'completed-before-wait'), 'Declared wait expectation')
        check(records[0][0]['kind'] == 'case.start' and records[-1][0]['kind'] == 'case.end', 'Case boundaries')
        bound = [(p, e) for p, e in records if p['kind'] == 'task.bound']
        expected = {case['taskId']}
        if name == 'nested': expected.add(case['childTaskId'])
        check({p['taskId'] for p, e in bound} == expected and len(bound) == len(expected), 'All declared tasks uniquely bound')
        for p, marker in bound:
            task_id = p['taskId']
            check(task_id not in bindings, 'No cross-case task ID reuse')
            bindings[task_id] = name
            state = states.get(task_id)
            if name == 'completed-before-wait':
                check(state is None and not any(w['task_id'] == task_id for w in result['waits']), 'Completed task has no fabricated lifecycle/wait')
                continue
            check(state is not None and state['status'] == 'complete_observed_lifetime', 'Complete task lifecycle')
            check(state['destination_scheduler_id'] == p['schedulerId'], 'Destination scheduler bind parity')
            body = [(q, e) for q, e in records if q['taskId'] == task_id and q['kind'] in ('task.body.enter', 'task.body.exit')]
            check([q['kind'] for q, e in body] == ['task.body.enter', 'task.body.exit'], 'Both task body witnesses')
            start = state['start']['event']; end = state['complete']['event']
            check(all(e['threadId'] == start['threadId'] == end['threadId'] for q, e in body), 'Task body TID matches execution headers')
            check(start['timeMsec'] <= body[0][1]['timeMsec'] <= body[1][1]['timeMsec'] <= end['timeMsec'], 'Task body inside observed execution')
            check(end['payload']['IsExceptional'] == (name == 'exception'), 'Exception semantics; cancellation not IsFaulted')
            begin = [(q, e) for q, e in records if q['taskId'] == task_id and q['kind'] == 'wait.begin']
            finish = [(q, e) for q, e in records if q['taskId'] == task_id and q['kind'] == 'wait.end']
            check(len(begin) == len(finish) == 1, 'Exactly one declared wait bracket')
            check(begin[0][0]['nativeTid'] == finish[0][0]['nativeTid'], 'Wait marker caller thread stable')
            waits = [w for w in result['waits'] if w['task_id'] == task_id and w['caller_native_tid'] == begin[0][0]['nativeTid']]
            check(len(waits) == 1 and waits[0]['status'] == 'synchronous_wait_bracket_observed', 'Matching synchronous caller task wait')
            wait = waits[0]
            check(begin[0][1]['timeMsec'] <= wait['begin']['event']['timeMsec'] <= wait['end']['event']['timeMsec'] <= finish[0][1]['timeMsec'], 'Wait events inside fixture caller bracket')
            if name == 'forced-inline':
                check(state['execution_native_tid'] == wait['caller_native_tid'] == target['mainNativeTid'], 'Inline work on waiting caller')
                check(wait['begin']['event']['timeMsec'] <= start['timeMsec'] <= end['timeMsec'] <= wait['end']['event']['timeMsec'], 'Inline execution inside task wait is not blocked duration')
            proof.append({'case': name, 'task_id': task_id, 'execution_native_tid': state['execution_native_tid'], 'caller_native_tid': wait['caller_native_tid'], 'destination_scheduler_id': state['destination_scheduler_id'], 'execution_origin_scheduler_id': start['payload']['OriginatingTaskSchedulerID']})
    check(set(states) == set(bindings) - {target['cases'][1]['taskId']}, 'No omitted or unrelated lifecycle promoted')
    return {'status': 'passed_bounded_synthetic_conformance', 'cases': len(CASES), 'sidecar_markers': len(points),
            'complete_task_lifetimes': len(states), 'observed_synchronous_waits': len(result['waits']), 'proof': proof,
            'marker_clock_offset_ms': {'lower': float(lower), 'upper': float(upper)},
            'limits': ['Synthetic target only; no Roslyn lineage or production claim.', 'Wait brackets are not blocked/CPU/scheduler time.',
                       'Source/target identity and clock bounds are observational, not immutable attestation.', 'No scheduler tracing or GC pairing acceptance.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(); folder = Path(args.folder)
    paths = {'events': folder/'analysis/events.jsonl', 'analysis': folder/'analysis/summary.json',
             'capture': folder/'capture.json', 'target': folder/'target.json', 'points': folder/'target.json.points.jsonl'}
    try:
        report = verify(lines(paths['events']), read(paths['analysis']), read(paths['capture']), read(paths['target']), lines(paths['points']))
    except (ValueError, KeyError, TypeError, IndexError) as error:
        report = {'status': 'failed', 'reason': str(error)}
    report['inputs_sha256'] = {k: tasks.sha(v) for k, v in paths.items()}
    report['sources_sha256'] = {'verifier': tasks.sha(__file__), 'assembler': tasks.sha(tasks.__file__)}
    with Path(args.output).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
    print(json.dumps(report))
    return 0 if report['status'] == 'passed_bounded_synthetic_conformance' else 1

if __name__ == '__main__':
    raise SystemExit(main())
