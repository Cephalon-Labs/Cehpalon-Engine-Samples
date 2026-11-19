"""Validate all periodic MeterListener collections and retain cold-call measurements."""
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
    require((data['warmup'], data['iterations'], data['repetitions']) == (0, 20, 1), 'Protocol differs')
    require(data['created'] == data['disposed'] == 2, 'Owned handlers did not reconcile')
    frequency = data['stopwatchFrequency']
    require(type(frequency) is int and frequency > 0, 'Invalid clock frequency')
    expected = [('idle-open', 0, False), ('cleanup-open', 1, False),
                ('cleanup-closed', 1, True), ('drained', 0, True)]
    require(len(data['stages']) == 4, 'Missing stages')
    summaries = []
    for stage, (name, active, closed) in zip(data['stages'], expected):
        total = {'MaximumConcurrentOperations': 2, 'ActiveOperations': active, 'IsAdmissionClosed': closed}
        tenant = {'Total': total, 'MaximumConcurrentOperationsPerTenant': 1, 'ActiveTenants': active}
        require(stage['Name'] == name and stage['Core'] == total and stage['Tenant'] == tenant, 'State differs')
        require(stage['Publications'] == 8 and stage['DelayMilliseconds'] == 10, 'Instrument or delay policy differs')
        rows = stage['samples']
        require(len(rows) == 20 and [r['Index'] for r in rows] == list(range(20)), 'Collections missing or reordered')
        starts, micros, allocated = [], [], []
        for row in rows:
            require(row['Callbacks'] == 8, 'Unexpected callback count')
            require(type(row['StartedTicks']) is int and row['StartedTicks'] >= 0, 'Invalid collection timestamp')
            require(type(row['ElapsedTicks']) is int and row['ElapsedTicks'] > 0, 'Invalid measured duration')
            require(type(row['AllocatedBytes']) is int and row['AllocatedBytes'] >= 0, 'Invalid allocated bytes')
            starts.append(row['StartedTicks'])
            micros.append(row['ElapsedTicks'] * 1_000_000 / frequency)
            allocated.append(row['AllocatedBytes'])
        differences = [right - left for left, right in zip(starts, starts[1:])]
        require(all(value > 0 for value in differences), 'Nonincreasing observation clock')
        cadence = [value * 1000 / frequency for value in differences]
        summaries.append({'stage': name, 'collection_count': 20, 'callback_count': 160,
                          'microseconds': micros, 'allocated_bytes': allocated,
                          'first_collection_microseconds': micros[0],
                          'median_collection_microseconds': median(micros),
                          'minimum_collection_microseconds': min(micros),
                          'maximum_collection_microseconds': max(micros),
                          'cadence_milliseconds': cadence,
                          'median_cadence_milliseconds': median(cadence)})
    return {'status': 'validated', 'input_sha256': hashlib.sha256(raw).hexdigest(),
            'collection_count': 80, 'callback_count': 640, 'stages': summaries,
            'scope': 'Measured collection includes eight validation callbacks and retains the first collection'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.input.read_bytes())
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(json.dumps({'status': report['status'], 'collection_count': report['collection_count']}))


if __name__ == '__main__':
    main()
