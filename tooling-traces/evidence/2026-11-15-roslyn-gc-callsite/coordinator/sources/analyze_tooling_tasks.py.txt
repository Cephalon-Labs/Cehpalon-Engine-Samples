"""ADR0022 offline, single-process TPL lifetime/wait observations. Never CPU or blocked time."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

PROVIDER = 'System.Threading.Tasks.TplEventSource'
VERSIONS = {7: 1, 8: 0, 9: 1, 10: 3, 11: 0}
OPCODES = {7: 9, 8: 0, 9: 0, 10: 9, 11: 0}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 2147483647


class Tasks:
    """A TaskID is process scoped; origin schedulers are contextual, not lifetime keys."""
    def __init__(self, pid):
        require(integer(pid, 1), 'Positive selected PID')
        self.pid = pid
        self.tasks = {}
        self.waits = {}
        self.finished_waits = []
        self.errors = []
        self.ignored = Counter()
        self.records = 0
        self.poisoned = set()
        self.previous = {}

    def fail(self, task, reason, index, event):
        candidate = task
        if type(task) is str:
            try: candidate = int(task)
            except ValueError: candidate = None
        elif type(task) in (float, bool):
            candidate = int(task) if type(task) is bool or (math.isfinite(task) and task.is_integer()) else None
        if integer(candidate, 1):
            self.poisoned.add(candidate)
        self.errors.append({'task_id': task, 'reason': reason, 'raw_record_index': index, 'event': event})

    def add(self, event, index):
        if event.get('provider') != PROVIDER:
            return
        self.records += 1
        payload = event.get('payload', {})
        task = payload.get('TaskID') if isinstance(payload, dict) else None
        event_id = event.get('eventId')
        if type(event_id) is not int:
            self.fail(task, 'malformed_event_id', index, event)
            return
        if event_id <= 0:
            self.fail(task, 'provider_error_or_invalid_event_id', index, event)
            return
        if event_id not in VERSIONS:
            self.ignored[str(event_id)] += 1
            return
        valid = (type(event_id) is int and event.get('processId') == self.pid and integer(event.get('processId'), 1)
                 and integer(event.get('threadId'), 1) and integer(task, 1)
                 and type(event.get('opcode')) is int and event['opcode'] == OPCODES[event_id]
                 and type(event.get('version')) is int and event['version'] == VERSIONS[event_id]
                 and type(event.get('templateType')) is str and bool(event['templateType'])
                 and type(event.get('timeMsec')) in (float, int) and math.isfinite(event['timeMsec'])
                 and event['timeMsec'] >= 0
                 and integer(payload.get('OriginatingTaskSchedulerID'), 1)
                 and integer(payload.get('OriginatingTaskID')))
        if event_id == 7:
            valid = valid and integer(payload.get('CreatingTaskID')) and integer(payload.get('TaskCreationOptions')) and integer(payload.get('appDomain'), 1)
        elif event_id == 9:
            valid = valid and type(payload.get('IsExceptional')) is bool
        elif event_id == 10:
            valid = valid and type(payload.get('Behavior')) is int and payload['Behavior'] in (1, 2) and integer(payload.get('ContinueWithTaskID'))
        if not valid:
            self.fail(task, 'malformed_identity_payload_or_template', index, event)
            return
        if task in self.poisoned:
            self.fail(task, 'persistently_poisoned_task_identity', index, event)
            return
        # Across a task's lifecycle and waits, clocks must never move backwards.
        if event['timeMsec'] < self.previous.get(task, -1):
            self.fail(task, 'task_clock_reversal', index, event)
            return
        self.previous[task] = event['timeMsec']
        item = {'raw_record_index': index, 'event': event}
        if event_id == 7:
            if task in self.tasks:
                self.fail(task, 'duplicate_or_reused_task_id', index, event)
            else:
                self.tasks[task] = {'task_id': task, 'schedule': item, 'start': None, 'complete': None}
        elif event_id in (8, 9):
            state = self.tasks.get(task)
            if state is None:
                self.fail(task, 'execution_without_unique_schedule', index, event)
            elif event_id == 8:
                if state['start'] is not None or state['complete'] is not None:
                    self.fail(task, 'duplicate_or_late_execution_start', index, event)
                else:
                    state['start'] = item
            elif state['start'] is None or state['complete'] is not None:
                self.fail(task, 'completion_without_unique_execution', index, event)
            elif state['start']['event']['threadId'] != event['threadId']:
                self.fail(task, 'execution_native_thread_changed', index, event)
            elif any(payload[k] != state['start']['event']['payload'][k] for k in ('OriginatingTaskSchedulerID', 'OriginatingTaskID')):
                self.fail(task, 'execution_origin_context_changed', index, event)
            else:
                state['complete'] = item
        else:
            key = (event['threadId'], task, payload['OriginatingTaskSchedulerID'], payload['OriginatingTaskID'])
            if event_id == 10:
                if key in self.waits:
                    self.fail(task, 'overlapping_or_duplicate_wait_begin', index, event)
                else:
                    self.waits[key] = item
            elif key not in self.waits:
                self.fail(task, 'wait_end_without_same_caller_context', index, event)
            else:
                start = self.waits.pop(key)
                self.finished_waits.append({'task_id': task, 'caller_native_tid': event['threadId'],
                    'begin': start, 'end': item, 'behavior': start['event']['payload']['Behavior']})

    def result(self):
        tasks = []
        for task, state in sorted(self.tasks.items()):
            status = ('rejected_poisoned_identity' if task in self.poisoned else
                      'complete_observed_lifetime' if state['start'] and state['complete'] else 'unfinished_or_unexecuted_unknown')
            tasks.append({**state, 'status': status, 'process_id': self.pid,
                          'destination_scheduler_id': state['schedule']['event']['payload']['OriginatingTaskSchedulerID'],
                          'execution_native_tid': state['start']['event']['threadId'] if state['start'] else None,
                          'cpu_time_ms': None})
        by_id = {t['task_id']: t for t in tasks}
        waits = []
        for wait in self.finished_waits:
            state = by_id.get(wait['task_id'])
            status = ('rejected_poisoned_identity' if wait['task_id'] in self.poisoned else
                      'synchronous_wait_bracket_observed' if wait['behavior'] == 1 else 'asynchronous_wait_not_same_thread_duration')
            waits.append({**wait, 'status': status, 'linked_complete_lifetime': bool(state and state['status'] == 'complete_observed_lifetime'),
                          'blocked_time_ms': None, 'scheduler_delay_ms': None})
        unfinished = [{'key': list(key), 'begin': begin, 'status': 'unfinished_wait_unknown'} for key, begin in self.waits.items()]
        return {'status': 'completed_offline_observations', 'process_id': self.pid,
                'tpl_records': self.records, 'ignored_event_ids': dict(self.ignored), 'tasks': tasks, 'waits': waits,
                'unfinished_waits': unfinished, 'errors': self.errors, 'poisoned_task_ids': sorted(self.poisoned),
                'limits': ['PID scope must be joined to an owned capture/process generation externally.',
                           'TaskID reuse rejects the entire identity; no inferred generations.',
                           'Schedule destination scheduler differs from execution/wait ambient scheduler.',
                           'TaskWait bracket may contain inline/spin/block; no CPU or blocked time.',
                           'Complete observed lifetime means schedule/start/completion events, not logical Task.IsCompleted for attached-child paths.',
                           'No Roslyn task ownership, GC pairing or scheduler transition cause is established.']}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def analyze(events, report, pid):
    require(report.get('status') == 'completed'
            and all(type(report.get(k)) is int and report[k] == 0 for k in ('eventsLost', 'etlxEventsLost', 'payloadReadErrors'))
            and type(report.get('events')) is int and report['events'] >= 0,
            'Completed parser and all reported loss/read-error gates required')
    tracker = Tasks(pid)
    count = 0
    for index, event in enumerate(events):
        require(type(event) is dict, 'Raw event object required')
        tracker.add(event, index)
        count += 1
    require(count == report['events'], 'All raw parser records must be consumed exactly')
    return tracker.result()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', required=True)
    parser.add_argument('--analysis', required=True)
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    report = json.loads(Path(args.analysis).read_text(encoding='utf-8-sig'))
    with Path(args.events).open(encoding='utf-8-sig') as stream:
        result = analyze((json.loads(line) for line in stream), report, args.pid)
    result['source_sha256'] = sha(__file__)
    result['inputs_sha256'] = {'events': sha(args.events), 'analysis': sha(args.analysis)}
    with Path(args.output).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'tasks': len(result['tasks']), 'waits': len(result['waits']), 'errors': len(result['errors']), 'output': args.output}))

if __name__ == '__main__':
    main()
