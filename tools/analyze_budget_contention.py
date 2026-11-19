"""Validate every lane in the fixed concurrent budget observer series."""
import argparse
import hashlib
import json
from pathlib import Path
from statistics import median


def require(condition, message):
    if not condition:
        raise ValueError(message)


def analyze(raw):
    data = json.loads(raw)
    require(data['status'] == 'passed' and data['failure'] is None, 'Attempt did not finish successfully')
    require((data['producers'], data['warmup'], data['iterations'], data['repetitions']) == (4, 1000, 25000, 5),
            'Fixed protocol differs')
    frequency = data['stopwatchFrequency']
    require(type(frequency) is int and frequency > 0, 'Invalid clock frequency')
    require(len(data['pairs']) == 5, 'Expected all five pairs')
    expected_counts = {key: 25000 for key in ['Identities', 'Memberships', 'Resources', 'Policies', 'Factories', 'Disposals']}
    expected_open = {'Total': {'MaximumConcurrentOperations': 8, 'ActiveOperations': 0, 'IsAdmissionClosed': False},
                     'MaximumConcurrentOperationsPerTenant': 2, 'ActiveTenants': 0}
    expected_closed = expected_open | {'Total': expected_open['Total'] | {'IsAdmissionClosed': True}}
    rows = []
    for repetition, pair in enumerate(data['pairs']):
        require(pair['Repetition'] == repetition and pair['ObservedFirst'] is (repetition % 2 == 1),
                'Pairs are reordered or duplicated')
        summary = {'repetition': repetition, 'observed_first': pair['ObservedFirst']}
        for mode, enabled in [('Control', False), ('Observed', True)]:
            lane = pair[mode]
            require(lane['Observe'] is enabled, 'Observer mode differs')
            require(type(lane['ElapsedTicks']) is int and lane['ElapsedTicks'] > 0, 'Invalid wall ticks')
            producers = lane['Producers']
            observer = lane['Observer']
            require(len(producers) == 4, 'Expected four producers')
            actors = [p['ThreadId'] for p in producers] + [observer['ThreadId']]
            require(all(type(actor) is int and actor > 0 for actor in actors) and len(set(actors)) == 5,
                    'Actor thread identities differ')
            for producer in producers:
                require(producer['Checksum'] == 25000 * 24999 // 2 and producer['Counts'] == expected_counts,
                        'Producer outcomes, fresh authority or cleanup counts differ')
                require(type(producer['AllocatedBytes']) is int and producer['AllocatedBytes'] >= 0,
                        'Invalid producer allocations')
            require(type(observer['Reads']) is int and (observer['Reads'] > 0 if enabled else observer['Reads'] == 0),
                    'Observer read count differs')
            require(type(observer['ElapsedTicks']) is int and observer['ElapsedTicks'] >= 0,
                    'Invalid observer loop ticks')
            require(type(observer['AllocatedBytes']) is int and observer['AllocatedBytes'] >= 0,
                    'Invalid observer allocations')
            require(lane['BeforeDrain'] == expected_open and lane['Drained'] == expected_closed,
                    'Terminal operation, tenant or drain state differs')
            summary[mode.lower()] = {
                'wall_milliseconds': lane['ElapsedTicks'] * 1000 / frequency,
                'wall_nanoseconds_per_offered_operation': lane['ElapsedTicks'] * 1e9 / frequency / 100000,
                'producer_bytes_per_operation': sum(p['AllocatedBytes'] for p in producers) / 100000,
                'observer_reads': observer['Reads'], 'observer_allocated_bytes': observer['AllocatedBytes'],
                'observer_loop_nanoseconds_per_read': (observer['ElapsedTicks'] * 1e9 / frequency / observer['Reads']
                                                       if enabled else None)}
        summary['paired_wall_difference_milliseconds'] = summary['observed']['wall_milliseconds'] - summary['control']['wall_milliseconds']
        rows.append(summary)
    return {'status': 'validated', 'input_sha256': hashlib.sha256(raw).hexdigest(),
            'completed_operations': 1000000, 'lane_count': 10, 'pairs': rows,
            'median_wall_milliseconds': {mode: median(row[mode]['wall_milliseconds'] for row in rows)
                                          for mode in ['control', 'observed']},
            'median_paired_difference_milliseconds': median(row['paired_wall_difference_milliseconds'] for row in rows),
            'scope': 'Wall time includes observer join and scheduling; comparison does not isolate lock contention'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.input.read_bytes())
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({'status': result['status'], 'completed_operations': result['completed_operations']}))


if __name__ == '__main__':
    main()
