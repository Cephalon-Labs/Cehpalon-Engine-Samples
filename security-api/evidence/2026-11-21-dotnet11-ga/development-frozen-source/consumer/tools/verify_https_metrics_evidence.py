"""Run adversarial validation against an actual completed HTTPS conformance capture."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import analyze_https_metrics as analyzer


def verify(root):
    complete = analyzer.analyze(root)
    if complete['profile'] != 'conformance':
        raise ValueError('Use the actual four-arm conformance capture')
    base = root / 'tenant-01-listener'
    original = {name: json.loads((base / (name + '.json')).read_bytes()) for name in ['host', 'client', 'controller']}
    mutations = {
        'dropped_offer': lambda d: d['client']['phases'][1]['Rows'][0].__setitem__('Outcome', 'dropped'),
        'missing_offer': lambda d: d['client']['phases'][1]['Rows'].pop(),
        'changed_schedule': lambda d: d['client']['phases'][1]['Rows'][0].__setitem__('Scheduled', 0),
        'new_tls_connection': lambda d: d['client']['tls'].append(d['client']['tls'][0]),
        'shared_process': lambda d: d['controller'].__setitem__('client_pid', d['controller']['host_pid']),
        'wrong_cleanup': lambda d: d['host']['store'].__setitem__('Disposals', d['host']['store']['Disposals'] - 1),
        'reopened_budget': lambda d: d['host']['snapshot'].__setitem__('IsAdmissionClosed', False),
        'wrong_callback_count': lambda d: d['host']['samples'][1].__setitem__('Callbacks', 4),
        'deleted_sample': lambda d: d['host']['samples'].pop(1),
        'duplicate_sample_index': lambda d: d['host']['samples'][1].__setitem__('Index', 0),
        'wrong_terminal_sample_count': lambda d: d['host'].__setitem__('sampleCount', 1),
        'wrong_terminal_callback_total': lambda d: d['host'].__setitem__('totalCallbacks', 1),
        'nonincreasing_sample_clock': lambda d: d['host']['samples'][1].__setitem__('StartedTicks', d['host']['samples'][0]['StartedTicks']),
        'disabled_work': lambda d: d['host']['counters'].__setitem__('ForbiddenFactories', 1),
        'callbacks_after_disposal': lambda d: d['host'].__setitem__('postDisposalCallbacks', 1),
        'denial_missing': lambda d: d['client'].__setitem__('crossTenantDenials', 3),
        'no_meter': lambda d: d['host'].__setitem__('meterCreated', False),
    }
    results = {}
    for name, mutate in mutations.items():
        altered = copy.deepcopy(original)
        mutate(altered)
        try:
            analyzer.validate_arm(**altered, conformance=True)
        except ValueError as error:
            results[name] = {'rejected': True, 'reason': str(error)}
        else:
            raise AssertionError(name)
    return {'status': 'passed', 'validated_real_arms': len(complete['arms']), 'rejected_mutations': results,
            'verification_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'input_sha256': complete['input_sha256']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.input)
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(report, output, indent=2); output.write('\n')
    print(json.dumps({'status': report['status'], 'rejected': len(report['rejected_mutations'])}))


if __name__ == '__main__':
    main()
