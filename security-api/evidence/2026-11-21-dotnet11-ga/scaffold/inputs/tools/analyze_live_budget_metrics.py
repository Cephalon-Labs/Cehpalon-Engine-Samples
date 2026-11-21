"""Validate every aggregate collection in the generated protected HTTPS metrics proof."""
import argparse
import hashlib
import json
from pathlib import Path
from statistics import median


PREFIX = 'cehpalon.operation_budget.'
PHASES = ['ready', 'held', 'midpoint', 'closing', 'stopped']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def analyze(raw):
    data = json.loads(raw)
    require(data['status'] == 'passed', 'Live metrics attempt failed')
    require(data['disabled'] == {'meterCreated': False, 'HostFactories': 0, 'hasApplication': False},
            'All-off profile created work')
    require(data['requestedDelayMilliseconds'] == 10, 'Collection delay differs')
    frequency = data['stopwatchFrequency']
    require(type(frequency) is int and frequency > 0, 'Invalid clock frequency')
    cases = data['cases']
    require(len(cases) == 2 and [row['tenantLimited'] for row in cases] == [False, True], 'Budget modes differ')
    summaries = []
    extended = ['overlapReads' in case for case in cases]
    require(extended[0] == extended[1], 'Mixed workload revisions')
    overlap = extended[0]
    total_reads = 404 if overlap else 400
    phases = PHASES[:-2] + ['overlap'] + PHASES[-2:] if overlap else PHASES
    for case in cases:
        require(case['status'] == 'passed' and case['crossTenantDenials'] == 4
                and case['postDisposalCallbacks'] == 0 and case['hostDisposals'] == 1, 'Lifecycle did not reconcile')
        if overlap:
            require(case['trafficReads'] == 400 and case['overlapReads'] == 4, 'Overlap workload differs')
        require(case['store'] == {'Factories': total_reads + 1, 'Disposals': total_reads + 1, 'Reads': total_reads, 'Writes': 1},
                'Operation or cleanup counts differ')
        names = {PREFIX + suffix for suffix in ['active', 'capacity', 'closed']}
        if case['tenantLimited']:
            names |= {PREFIX + 'active_tenants', PREFIX + 'tenant_capacity'}
        require(set(case['metricNames']) == names and len(case['metricNames']) == len(names), 'Gauge set differs')
        rows = case['collections']
        require([r['index'] for r in rows] == list(range(len(rows))), 'Collections missing or duplicated')
        require([r['phase'] for r in rows if r['phase'] != 'periodic'] == phases, 'Controlled phases differ')
        require(any(r['phase'] == 'periodic' and r['businessReads'] == 200 for r in rows),
                'Periodic observer did not witness the controlled traffic midpoint')
        if overlap:
            require(any(r['phase'] == 'periodic' and r['values'].get(PREFIX + 'active') == 5
                        and r['businessReads'] == 400 for r in rows), 'Periodic observer missed held read overlap')
        last_start, last_closed, last_reads = -1, 0, 0
        micros, allocated, starts = [], [], []
        for row in rows:
            require(row['phase'] in phases + ['periodic'], 'Unknown collection phase')
            require(type(row['startedTicks']) is int and row['startedTicks'] > last_start, 'Clock is not increasing')
            require(type(row['elapsedTicks']) is int and row['elapsedTicks'] > 0, 'Invalid collection duration')
            require(type(row['allocatedBytes']) is int and row['allocatedBytes'] >= 0, 'Invalid collection allocation')
            require(row['callbacks'] == len(names) and set(row['values']) == names, 'Collection gauge cardinality differs')
            values = row['values']
            active, closed = values[PREFIX + 'active'], values[PREFIX + 'closed']
            require(type(active) is int and 0 <= active <= 8 and values[PREFIX + 'capacity'] == 8, 'Capacity bounds differ')
            require(closed in (0, 1) and closed >= last_closed, 'Closure reverted')
            require(type(row['businessReads']) is int and last_reads <= row['businessReads'] <= total_reads, 'Read count differs')
            if case['tenantLimited']:
                tenants = values[PREFIX + 'active_tenants']
                require(type(tenants) is int and 0 <= tenants <= 2 and values[PREFIX + 'tenant_capacity'] == 4,
                        'Tenant gauge bounds differ')
            if row['phase'] != 'periodic':
                phase = row['phase']
                expected_active = 1 if phase in ['held', 'midpoint', 'closing'] else 0
                if overlap and phase in ['overlap', 'closing']:
                    expected_active = 5
                expected_closed = int(phase in ['closing', 'stopped'])
                expected_reads = {'ready': 0, 'held': 0, 'midpoint': 200, 'overlap': 400, 'closing': 400, 'stopped': total_reads}[phase]
                require((active, closed, row['businessReads']) == (expected_active, expected_closed, expected_reads),
                        'Controlled phase state differs')
                if case['tenantLimited']:
                    expected_tenants = 2 if expected_active == 5 else expected_active
                    require(values[PREFIX + 'active_tenants'] == expected_tenants, 'Controlled active tenants differ')
            last_start, last_closed, last_reads = row['startedTicks'], closed, row['businessReads']
            starts.append(last_start)
            micros.append(row['elapsedTicks'] * 1_000_000 / frequency)
            allocated.append(row['allocatedBytes'])
        summaries.append({'tenant_limited': case['tenantLimited'], 'collections': len(rows),
                          'periodic_collections': sum(r['phase'] == 'periodic' for r in rows),
                          'observed_active_values': sorted({r['values'][PREFIX + 'active'] for r in rows}),
                          'first_collection_microseconds': micros[0],
                          'median_collection_microseconds': median(micros),
                          'minimum_collection_microseconds': min(micros),
                          'maximum_collection_microseconds': max(micros),
                          'allocated_bytes': allocated,
                          'start_intervals_milliseconds': [(right-left)*1000/frequency for left, right in zip(starts, starts[1:])]})
    return {'status': 'validated', 'input_sha256': hashlib.sha256(raw).hexdigest(),
            'completed_reads': total_reads * 2, 'completed_writes': 2, 'cross_tenant_denials': 8, 'cases': summaries,
            'scope': 'Controlled HTTPS fixture and collection cost; per-gauge values can represent different instants'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.input.read_bytes())
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(json.dumps({'status': report['status'], 'completed_reads': report['completed_reads']}))


if __name__ == '__main__':
    main()
