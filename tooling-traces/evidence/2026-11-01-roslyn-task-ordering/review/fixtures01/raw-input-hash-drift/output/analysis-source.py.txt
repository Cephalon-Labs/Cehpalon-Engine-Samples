"""ADR0024 offline literal task-event ordering; no queue, CPU or blocked durations."""
import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import analyze_tooling_tasks as tpl

TPL_SHA = '7fe853f20ad5f257c726283b1a5d72329057508b3c50731e19e3984cd452773b'
LINEAGE_SHA = 'f7599be4aa4629625b6cfd9773746e785108cc9f441c373d28734f8217f7ac79'
UNKNOWN = 'unknown_execution_context'
TIE = 'same_recorded_timestamp_order_unresolved'
RELATIONS = ('schedule_vs_wait_begin', 'execution_start_vs_wait_begin',
             'execution_completion_vs_wait_begin', 'execution_completion_vs_wait_end')
require = tpl.require


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def records(path):
    with Path(path).open(encoding='utf-8-sig') as stream:
        for line in stream:
            yield json.loads(line)


def timestamp(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0, 'Nonnegative finite recorded timestamp')
    return Fraction(str(value))


def relation(left, right):
    a, b = timestamp(left), timestamp(right)
    return 'before' if a < b else 'after' if a > b else TIE


def typed_equal(left, right):
    if type(left) is not type(right): return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(typed_equal(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(typed_equal(a, b) for a, b in zip(left, right))
    if type(left) is float and not math.isfinite(left): return False
    return left == right


def bind_reference(ref, raw, index):
    require(type(ref) is dict and type(ref.get('raw_record_index')) is int and ref['raw_record_index'] >= 0
            and type(index) is int and index == ref['raw_record_index'], 'Exact zero-based raw reference index')
    require(type(ref.get('event')) is dict and typed_equal(ref['event'], raw), 'Typed exact copied event/raw binding')
    return True


def frame(ref, event_id, task_id, pid):
    require(type(ref) is dict and type(ref.get('raw_record_index')) is int and ref['raw_record_index'] >= 0, 'Exact nonnegative reference index')
    e = ref.get('event'); require(type(e) is dict, 'Event reference object')
    require(e.get('provider') == tpl.PROVIDER and type(e.get('processId')) is int and e['processId'] == pid
            and tpl.integer(e.get('threadId'), 1), 'Exact selected process/native header')
    require(all(type(e.get(k)) is int for k in ('eventId', 'version', 'opcode'))
            and (e['eventId'], e['version'], e['opcode']) == (event_id, tpl.VERSIONS[event_id], tpl.OPCODES[event_id])
            and type(e.get('templateType')) is str and bool(e['templateType']), 'Exact TPL metadata')
    payload = e.get('payload'); require(type(payload) is dict and type(payload.get('TaskID')) is int and payload['TaskID'] == task_id
            and tpl.integer(payload.get('OriginatingTaskSchedulerID'), 1) and tpl.integer(payload.get('OriginatingTaskID')), 'Exact task and origin identity')
    if event_id == 7:
        require(tpl.integer(payload.get('CreatingTaskID')) and tpl.integer(payload.get('TaskCreationOptions')) and tpl.integer(payload.get('appDomain'), 1), 'Exact schedule payload identity')
    if event_id == 9:
        require(type(payload.get('IsExceptional')) is bool, 'Exact completion exceptional flag')
    timestamp(e.get('timeMsec'))
    return e


def classify_wait(wait, state, pid):
    require(tpl.integer(pid, 1) and type(wait) is dict and tpl.integer(wait.get('task_id'), 1)
            and tpl.integer(wait.get('caller_native_tid'), 1), 'Exact selected wait identities')
    task_id = wait['task_id']; begin = frame(wait.get('begin'), 10, task_id, pid); end = frame(wait.get('end'), 11, task_id, pid)
    require(begin['threadId'] == end['threadId'] == wait['caller_native_tid'], 'Same observed wait caller header')
    require(all(begin['payload'][k] == end['payload'][k] for k in ('OriginatingTaskSchedulerID', 'OriginatingTaskID')), 'Same wait origin context')
    require(type(wait.get('behavior')) is int and wait['behavior'] in (1, 2)
            and type(begin['payload'].get('Behavior')) is int and begin['payload']['Behavior'] == wait['behavior']
            and tpl.integer(begin['payload'].get('ContinueWithTaskID')), 'Exact wait behavior/context')
    if wait.get('status') in ('synchronous_wait_bracket_observed', 'asynchronous_wait_not_same_thread_duration'):
        require(wait['behavior'] == (1 if wait['status'] == 'synchronous_wait_bracket_observed' else 2), 'Wait status and behavior agree')
    require(timestamp(begin['timeMsec']) <= timestamp(end['timeMsec']), 'Non-reversed wait bracket')
    result = {'awaited_task_id': task_id, 'caller_native_tid': wait['caller_native_tid'], 'behavior': wait['behavior'],
        'wait_begin_record_index': wait['begin']['raw_record_index'], 'wait_end_record_index': wait['end']['raw_record_index'],
        **{k: UNKNOWN for k in RELATIONS}, 'execution_header_tid_relation': UNKNOWN, 'status': UNKNOWN,
        'direct_waitforworkers_callsite_proven': False, 'native_lifetime_proven': False,
        'queue_time_ms': None, 'blocked_time_ms': None, 'scheduler_delay_ms': None, 'cpu_time_ms': None}
    if state is None: return result
    require(type(state) is dict and type(state.get('task_id')) is int and state['task_id'] == task_id
            and type(state.get('process_id')) is int and state['process_id'] == pid, 'Execution context matches selected task/process')
    if state.get('status') != 'complete_observed_lifetime' or not all(state.get(k) for k in ('schedule', 'start', 'complete')):
        return result
    if wait.get('status') not in ('synchronous_wait_bracket_observed', 'asynchronous_wait_not_same_thread_duration'):
        return result
    schedule = frame(state['schedule'], 7, task_id, pid); start = frame(state['start'], 8, task_id, pid); complete = frame(state['complete'], 9, task_id, pid)
    require(tpl.integer(state.get('execution_native_tid'), 1) and start['threadId'] == complete['threadId'] == state['execution_native_tid'], 'Same execution emitter header')
    require(all(start['payload'][k] == complete['payload'][k] for k in ('OriginatingTaskSchedulerID', 'OriginatingTaskID')), 'Execution ambient context stable')
    require(timestamp(schedule['timeMsec']) <= timestamp(start['timeMsec']) <= timestamp(complete['timeMsec']), 'Observed execution lifecycle clock order')
    result.update(status='literal_recorded_event_order',
        schedule_vs_wait_begin=relation(schedule['timeMsec'], begin['timeMsec']),
        execution_start_vs_wait_begin=relation(start['timeMsec'], begin['timeMsec']),
        execution_completion_vs_wait_begin=relation(complete['timeMsec'], begin['timeMsec']),
        execution_completion_vs_wait_end=relation(complete['timeMsec'], end['timeMsec']),
        execution_header_tid_relation='same_recorded_native_tid' if start['threadId'] == begin['threadId'] else 'different_recorded_native_tid',
        execution_native_tid=start['threadId'], schedule_record_index=state['schedule']['raw_record_index'],
        execution_start_record_index=state['start']['raw_record_index'], execution_completion_record_index=state['complete']['raw_record_index'])
    return result


def counts(items):
    return {'associations': len(items), 'distinct_waits': len({x['wait_index'] for x in items}),
        'relations': {k: dict(Counter(x[k] for x in items)) for k in RELATIONS},
        'start_vs_wait_begin_by_header_relation': dict(Counter(x['execution_header_tid_relation'] + '/' + x['execution_start_vs_wait_begin'] for x in items)),
        'unknown_execution_contexts': sum(x['status'] == UNKNOWN for x in items)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('capture', 'lineage', 'expected-lineage-summary-sha256', 'output'): parser.add_argument('--'+key, required=True)
    args = parser.parse_args(); base = Path(args.capture); lineage = Path(args.lineage); out = Path(args.output); out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).read_bytes(); (out/'analysis-source.py.txt').write_bytes(source)
    require(tpl.sha(tpl.__file__) == TPL_SHA, 'Pinned TPL assembler source')
    summary_path = lineage/'summary.json'; require(tpl.sha(summary_path) == args.expected_lineage_summary_sha256, 'Reviewed lineage summary hash')
    summary = read(summary_path); require(summary['status'] == 'completed_bounded_context_observations'
        and summary['source_sha256'] == LINEAGE_SHA and summary['assembler_sha256'] == TPL_SHA, 'Pinned completed lineage sources')
    for name, digest in summary['inputs_sha256'].items(): require(tpl.sha(base/name) == digest, 'Lineage raw input hash '+name)
    for name, digest in summary['outputs_sha256'].items(): require(tpl.sha(lineage/name) == digest, 'Lineage output hash '+name)
    capture = read(base/'capture.json'); pid = capture['target_pid']
    require(capture['status'] == 'completed' and tpl.integer(pid, 1) and summary['pid'] == pid, 'One successful owned capture identity')
    model = read(lineage/'task-observations.json'); require(type(model['process_id']) is int and model['process_id'] == pid, 'Task model process scope')
    require(type(model.get('tasks')) is list and len(model['tasks']) == 19527 and type(model.get('waits')) is list and len(model['waits']) == 2372, 'Complete declared global execution/wait corpus')
    states = {}; references = []
    for state in model['tasks']:
        task_id = state['task_id']; require(tpl.integer(task_id, 1) and task_id not in states, 'Unique non-reused model task identities'); states[task_id] = state
        references.extend(state[k] for k in ('schedule', 'start', 'complete') if state.get(k) is not None)
    for wait in model['waits']: references.extend((wait['begin'], wait['end']))
    # Retain poisoned/malformed error references in provenance as well, without accepting their identity.
    references.extend(e for e in model['errors'] if 'raw_record_index' in e and 'event' in e)
    refs = {}
    for ref in references:
        index = ref.get('raw_record_index'); require(type(index) is int and index >= 0, 'Exact raw reference key')
        if index in refs: require(typed_equal(ref, refs[index]), 'No conflicting copies of one raw record')
        else: refs[index] = ref
    found = set(); raw_count = 0
    for index, raw in enumerate(records(base/'analysis/events.jsonl')):
        raw_count += 1
        if index in refs: bind_reference(refs[index], raw, index); found.add(index)
    require(found == set(refs) and type(summary['raw_events']) is int and raw_count == summary['raw_events'], 'All referenced and full raw records consumed')
    orders = [{**classify_wait(w, states.get(w['task_id']), pid), 'wait_index': i} for i, w in enumerate(model['waits'])]
    rows = list(records(lineage/'rows.jsonl')); require(len(rows) == 306 and len({r['emit_sequence'] for r in rows}) == 306, 'All 306 unique Emit rows retained')
    output_rows = []; groups = {}; all_associations = []
    for row in rows:
        linked = []
        for w in row['observed_caller_waits']:
            index = w['wait_index']; require(type(index) is int and 0 <= index < len(orders), 'Exact lineage wait reference')
            order = orders[index]; require(w['awaited_task_id'] == order['awaited_task_id'] and w['wait_begin_record_index'] == order['wait_begin_record_index']
                and w['wait_end_record_index'] == order['wait_end_record_index'] and order['caller_native_tid'] == pid, 'Exact row-wait task/raw caller references')
            item = {**order, 'row_scope': w['row_scope'], 'caller_context_witness_count': w['caller_context_witness_count'],
                    'compiler_point_context_count': len(w['compiler_points_during_wait_in_emit'])}
            linked.append(item); all_associations.append(item)
        output_rows.append({k: row[k] for k in ('row_identity', 'emit_sequence')} | {'wait_event_orderings': linked})
    require(len(all_associations) == 2177, 'Complete declared row-wait associations; no selection')
    for phase, expected in (('primer', 36), ('measurement', 270)):
        selected = [r for r in output_rows if r['row_identity']['phase'] == phase]; require(len(selected) == expected, 'Complete fixed phase rows')
        items = [w for r in selected for w in r['wait_event_orderings']]; caller = [w for w in items if w['caller_context_witness_count'] > 0]
        groups[phase] = {'rows': len(selected), 'all_observed_caller_waits': counts(items), 'caller_waitforworkers_point_subset': counts(caller),
                         'caller_and_compiler_point_subset': counts([w for w in caller if w['compiler_point_context_count'] > 0])}
    for name, values in (('wait-orderings.jsonl', orders), ('row-orderings.jsonl', output_rows)):
        with (out/name).open('x', encoding='utf-8', newline='\n') as stream:
            for item in values: stream.write(json.dumps(item, separators=(',', ':'))+'\n')
    result = {'status': 'completed_literal_event_ordering', 'source_sha256': hashlib.sha256(source).hexdigest(),
        'assembler_sha256': TPL_SHA, 'lineage_source_sha256': LINEAGE_SHA, 'lineage_summary_sha256': tpl.sha(summary_path),
        'pid': pid, 'raw_events_consumed': raw_count, 'raw_reference_copies_bound': len(references), 'distinct_raw_references_bound': len(refs),
        'all_paired_waits': counts(orders), 'main_caller_waits': counts([w for w in orders if w['caller_native_tid'] == pid]),
        'nonmain_waits': counts([w for w in orders if w['caller_native_tid'] != pid]), 'all_row_wait_associations': counts(all_associations),
        'groups': groups, 'unpaired_source_waits': len(model['unfinished_waits']), 'source_tpl_errors': len(model['errors']),
        'inputs_sha256': {'lineage_summary': tpl.sha(summary_path), **{str(base/name): digest for name, digest in summary['inputs_sha256'].items()},
                          **{str(lineage/name): digest for name, digest in summary['outputs_sha256'].items()}},
        'outputs_sha256': {p.name: tpl.sha(p) for p in out.iterdir() if p.is_file()},
        'limits': ['Literal event timestamps only; equal values remain order-unresolved despite record index.',
                   'No queue/runqueue/blocked/CPU/GC duration or exact direct WaitForWorkers/inline callpath/native-lifetime proof.',
                   'Task execution-complete event is not unconditional logical completion; cross-event races/timeouts are preserved.',
                   'Observed waits do not include every already-completed GetResult fast path.',
                   'All method contexts and scopes are inherited unchanged; no favorable subset or new workload.']}
    require(tpl.sha(__file__) == result['source_sha256'] and tpl.sha(tpl.__file__) == TPL_SHA, 'Analysis source pins unchanged during replay')
    (out/'summary.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8', newline='\n'); print(json.dumps(result))

if __name__ == '__main__': main()
