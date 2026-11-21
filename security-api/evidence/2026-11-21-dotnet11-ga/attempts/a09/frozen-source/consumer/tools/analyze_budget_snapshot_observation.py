"""Validate the fixed snapshot observer series and summarize every measured stage."""
import argparse
import hashlib
import json
from pathlib import Path
from statistics import median


LANES = ['cached-core', 'core', 'cached-tenant', 'tenant']
STAGES = [('idle-open', 0, False), ('cleanup-open', 1, False),
          ('cleanup-closed', 1, True), ('drained', 0, True)]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def analyze(raw):
    result = json.loads(raw)
    require(result['iterations'] == 1_000_000 and result['warmup'] == 10_000
            and result['repetitions'] == 5, 'Unexpected fixed protocol')
    require(result['created'] == result['disposed'] == 2, 'Handler ownership differs')
    frequency = result['stopwatchFrequency']
    require(type(frequency) is int and frequency > 0, 'Invalid clock frequency')
    stages = result['stages']
    require(len(stages) == 4, 'Expected all four stages')
    summaries = []
    for stage, (name, active, closed) in zip(stages, STAGES):
        core = {'MaximumConcurrentOperations': 2, 'ActiveOperations': active, 'IsAdmissionClosed': closed}
        tenant = {'Total': core, 'MaximumConcurrentOperationsPerTenant': 1, 'ActiveTenants': active}
        require(stage['Name'] == name and stage['Core'] == core and stage['Tenant'] == tenant,
                'Controlled snapshot state differs')
        rows = stage['Measurements']
        expected_order = [(repetition, order, LANES[(repetition + order) % 4])
                          for repetition in range(5) for order in range(4)]
        require([(r['Repetition'], r['Order'], r['Lane']) for r in rows] == expected_order,
                'Missing, reordered or duplicated measurements')
        fingerprints = {'core': 200 + active * 10 + int(closed)}
        fingerprints['tenant'] = fingerprints['core'] * 100 + 10 + active
        grouped = {lane: [] for lane in LANES}
        for row in rows:
            lane = row['Lane']
            family = lane.removeprefix('cached-')
            require(row['Checksum'] == fingerprints[family] * 1_000_000, 'Snapshot checksum differs')
            require(type(row['ElapsedTicks']) is int and row['ElapsedTicks'] > 0,
                    'Invalid elapsed ticks')
            require(type(row['AllocatedBytes']) is int and row['AllocatedBytes'] >= 0,
                    'Invalid allocation count')
            grouped[lane].append({'nanoseconds_per_read': row['ElapsedTicks'] * 1e9 / frequency / 1_000_000,
                                  'bytes_per_read': row['AllocatedBytes'] / 1_000_000})
        lane_summary = {}
        for lane, values in grouped.items():
            ns = [value['nanoseconds_per_read'] for value in values]
            lane_summary[lane] = {'median_nanoseconds_per_read': median(ns),
                                  'minimum_nanoseconds_per_read': min(ns),
                                  'maximum_nanoseconds_per_read': max(ns),
                                  'bytes_per_read': [value['bytes_per_read'] for value in values]}
        paired = {family: [actual['nanoseconds_per_read'] - cached['nanoseconds_per_read']
                           for actual, cached in zip(grouped[family], grouped['cached-' + family])]
                  for family in ['core', 'tenant']}
        summaries.append({'stage': name, 'lanes': lane_summary, 'paired_differences': paired,
                          'median_paired_differences': {key: median(values) for key, values in paired.items()}})
    return {'status': 'validated', 'input_sha256': hashlib.sha256(raw).hexdigest(),
            'measurement_count': 80, 'scope': result['scope'], 'stages': summaries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.input.read_bytes())
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(json.dumps({'status': report['status'], 'measurement_count': report['measurement_count']}))


if __name__ == '__main__':
    main()
