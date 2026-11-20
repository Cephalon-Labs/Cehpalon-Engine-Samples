"""Validate every offer and sample, then summarize all frozen HTTPS metric pairs."""
import argparse
import hashlib
import json
import math
from pathlib import Path
from statistics import mean, median, stdev


def require(value, message):
    if not value:
        raise ValueError(message)


def percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def distribution(values):
    average = mean(values)
    return {'mean': average, 'median': median(values), 'minimum': min(values), 'maximum': max(values),
            'sample_cv_percent': stdev(values) / abs(average) * 100 if len(values) > 1 and average else None}


def validate_arm(host, client, controller, conformance=False):
    require(host['status'] == client['status'] == controller['status'] == 'passed', 'Failed arm')
    enabled, tenant = controller['listener'], controller['tenant']
    require(host['listener'] == enabled and host['tenant'] == tenant, 'Arm identity differs')
    require(host['environment']['pid'] == controller['host_pid'] != controller['client_pid'] == client['environment']['pid'], 'Process identity differs')
    require(host['environment']['stopwatchFrequency'] == client['environment']['stopwatchFrequency'] > 0, 'Clock frequency differs')
    frequency = host['environment']['stopwatchFrequency']
    warm, measured, rate = (128, 256, 128) if conformance else (1500, 5000, 500)
    require(client['prepared'] == 32 and client['crossTenantDenials'] == 4 and client['expectedConnections'] == 32, 'Preparation differs')
    tls = client['tls']
    require(len(tls) == 32 and sorted(t['Lane'] for t in tls) == list(range(32)), 'New or missing TLS connections')
    require(all(t['Protocol'] == 'Tls13' and t['HttpVersion'] == '1.1' and t['Cipher'] for t in tls), 'TLS protocol differs')
    require([p['Name'] for p in client['phases']] == ['warmup', 'measured'], 'Phase sequence differs')
    for phase, count in zip(client['phases'], [warm, measured]):
        require(phase['Rate'] == rate and len(phase['Rows']) == count, 'Offered workload differs')
        for i, row in enumerate(phase['Rows']):
            require(row['Index'] == i and row['Lane'] == i % 32, 'Offer identity differs')
            require(row['Scheduled'] == phase['Origin'] + i * frequency // rate, 'Schedule differs')
            require(0 < row['Scheduled'] <= row['Sent'] <= row['Completed'] <= phase['Completed'], 'Offer clock differs')
            require(row['Status'] == 200 and row['Outcome'] == 'passed' and row['Bytes'] > 0, 'Dropped, failed or unvalidated offer')
    expected = 32 + warm + measured
    require(host['store'] == {'Factories': expected, 'Constructors': expected, 'Reads': expected, 'Writes': 0, 'Disposals': expected}, 'Business/cleanup counts differ')
    counters = host['counters']
    require(counters['HostFactories'] == counters['HostDisposals'] == counters['ApiFactories'] == counters['GraphQLFactories'] == 1
            and counters['ForbiddenFactories'] == 0 and counters['GraphQLServices'] > 0, 'Activation differs')
    require(host['snapshot'] == {'MaximumConcurrentOperations': 64, 'ActiveOperations': 0, 'IsAdmissionClosed': True}, 'Terminal budget differs')
    require(host['invalidCallbacks'] == host['postDisposalCallbacks'] == 0, 'Invalid callback or disposed-meter observation')
    begin, end = host['observations']['begin'], host['observations']['end']
    require(begin == controller['begin_signal']['snapshot'] and end == controller['end_signal']['snapshot'], 'Boundary signal differs')
    require(begin['ticks'] < end['ticks'] and end['allocatedBytes'] >= begin['allocatedBytes'] and end['cpuTicks'] >= begin['cpuTicks'], 'Resource boundary differs')
    for boundary, count in [(begin, 32 + warm), (end, expected)]:
        require(all(boundary[key] == count for key in ['factories', 'constructors', 'reads', 'disposals']) and boundary['writes'] == 0, 'Boundary operation counts differ')
    samples = host['samples']
    require(len(samples) == host['sampleCount'] and [s['Index'] for s in samples] == list(range(len(samples))), 'Missing or duplicated samples')
    require(sum(s['Callbacks'] for s in samples) == host['totalCallbacks'], 'Terminal callback count differs')
    require(all(host[key] == enabled for key in ['meterCreated', 'listenerCreated', 'samplerCreated']), 'Listener policy differs')
    cadence, durations, allocations = [], [], []
    measured_samples = 0
    if enabled:
        require(len(samples) >= 3 and samples[0]['Phase'] == 'initial' and samples[-1]['Phase'] == 'closed', 'Sample lifecycle differs')
        require(host['requestedDelayMilliseconds'] == 10, 'Requested cadence differs')
        last = -1
        for i, sample in enumerate(samples):
            require(sample['StartedTicks'] > last and sample['ElapsedTicks'] > 0 and sample['AllocatedBytes'] >= 0, 'Sample clock/allocation differs')
            require(sample['Callbacks'] == (5 if tenant else 3), 'Callback count differs')
            require(0 <= sample['Active'] <= 64 and sample['Capacity'] == 64 and sample['Closed'] == int(i == len(samples) - 1), 'Gauge bounds/closure differ')
            if tenant:
                require(0 <= sample['ActiveTenants'] <= 2 and sample['TenantCapacity'] == 32, 'Tenant gauge bounds differ')
            if 0 < i < len(samples) - 1:
                require(sample['Phase'] == 'periodic', 'Unknown sample phase')
            if i:
                cadence.append((sample['StartedTicks'] - last) * 1000 / frequency)
            last = sample['StartedTicks']
            durations.append(sample['ElapsedTicks'] * 1_000_000 / frequency)
            allocations.append(sample['AllocatedBytes'])
            measured_samples += begin['ticks'] <= last <= end['ticks']
        require(samples[0]['Active'] == samples[-1]['Active'] == 0 and measured_samples > 0, 'Controlled sample differs')
        if tenant:
            require(samples[0]['ActiveTenants'] == samples[-1]['ActiveTenants'] == 0, 'Terminal tenant sample differs')
    else:
        require(not samples and host['requestedDelayMilliseconds'] == 0, 'Baseline created observations')
    rows = client['phases'][1]['Rows']
    latencies = [(r['Completed'] - r['Sent']) * 1000 / frequency for r in rows]
    scheduled = [(r['Completed'] - r['Scheduled']) * 1000 / frequency for r in rows]
    lag = [(r['Sent'] - r['Scheduled']) * 1000 / frequency for r in rows]
    values = {'server_cpu_ms_per_read': (end['cpuTicks'] - begin['cpuTicks']) / 10000 / measured,
              'server_allocated_bytes_per_read': (end['allocatedBytes'] - begin['allocatedBytes']) / measured,
              'response_mean_ms': mean(latencies), 'response_p95_ms': percentile(latencies, .95),
              'response_p99_ms': percentile(latencies, .99), 'scheduled_p95_ms': percentile(scheduled, .95),
              'completion_rate_per_second': measured * frequency / (client['phases'][1]['Completed'] - client['phases'][1]['Origin'])}
    return {'values': values, 'server_bracket_seconds': (end['ticks'] - begin['ticks']) / frequency,
            'gc_collections': [right - left for left, right in zip(begin['gc'], end['gc'])],
            'response_median_ms': median(latencies), 'send_lag_ms': distribution(lag),
            'collections': len(samples), 'measured_collections': measured_samples,
            'first_collection_microseconds': durations[0] if durations else None,
            'collection_microseconds': distribution(durations) if durations else None,
            'collection_allocated_bytes_values': sorted(set(allocations)),
            'actual_cadence_milliseconds': distribution(cadence) if cadence else None}


def analyze(root):
    manifest = json.loads((root / 'manifest.json').read_bytes())
    require(manifest['status'] == 'passed' and manifest['profile'] in ['measure', 'conformance'], 'Incomplete attempt')
    require(manifest['engine_revision'] == '5f8f252e901e85c50d7fc6f4b760e457965ce3bb' and manifest['sdk'] == '11.0.100-rc.3.26522.148', 'Pinned source/runtime differs')
    conformance = manifest['profile'] == 'conformance'
    repetitions = 1 if conformance else 6
    expected = [(tenant, pair, enabled) for tenant in [False, True] for pair in range(1, repetitions + 1)
                for enabled in ([False, True] if pair % 2 else [True, False])]
    require([(r['tenant'], r['pair'], r['listener']) for r in manifest['arms']] == expected, 'Frozen arm order differs')
    summaries, digests = [], {}
    for arm in manifest['arms']:
        require(arm['status'] == 'passed', 'Incomplete arm')
        files = {name: root / arm['name'] / (name + '.json') for name in ['host', 'client', 'controller']}
        data = {name: json.loads(path.read_bytes()) for name, path in files.items()}
        summary = validate_arm(**data, conformance=conformance)
        summaries.append({**arm, **summary})
        digests.update({str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files.values()})
    pairs = []
    for tenant in [False, True]:
        for pair in range(1, repetitions + 1):
            group = [row for row in summaries if row['tenant'] == tenant and row['pair'] == pair]
            baseline = next(row for row in group if not row['listener'])['values']
            observed = next(row for row in group if row['listener'])['values']
            pairs.append({'tenant': tenant, 'pair': pair, 'differences': {
                key: {'listener_minus_baseline': observed[key] - baseline[key],
                      'listener_over_baseline': observed[key] / baseline[key] if baseline[key] else None}
                for key in baseline}})
    groups = []
    for tenant in [False, True]:
        selected = [pair for pair in pairs if pair['tenant'] == tenant]
        metrics = {}
        for key in selected[0]['differences']:
            differences = distribution([p['differences'][key]['listener_minus_baseline'] for p in selected])
            # Signed differences have no ratio-scale origin; CV is meaningful
            # for the positive arm measurements, not these paired deltas.
            differences.pop('sample_cv_percent')
            metrics[key] = {'paired_differences': differences,
                            'baseline': distribution([r['values'][key] for r in summaries if r['tenant'] == tenant and not r['listener']]),
                            'listener': distribution([r['values'][key] for r in summaries if r['tenant'] == tenant and r['listener']])}
        groups.append({'tenant': tenant, 'metrics': metrics})
    return {'status': 'validated', 'profile': manifest['profile'], 'arms': summaries, 'pairs': pairs, 'groups': groups,
            'input_sha256': digests, 'measured_reads': len(summaries) * (256 if conformance else 5000),
            'analysis_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'qualification': 'Unchanged canonical gates; shared-host descriptive paired observation only. Negative deltas do not establish a speedup.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.input)
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(report, output, indent=2); output.write('\n')
    print(json.dumps({'status': report['status'], 'arms': len(report['arms']), 'measured_reads': report['measured_reads']}))


if __name__ == '__main__':
    main()
