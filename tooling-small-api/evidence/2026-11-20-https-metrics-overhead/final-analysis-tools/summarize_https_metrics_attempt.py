"""Preserve every arm of an incomplete attempt without qualifying or pooling it."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import analyze_https_metrics as full


def summarize(root):
    manifest = json.loads((root / 'manifest.json').read_bytes())
    rows = []
    for arm in manifest['arms']:
        files = {name: root / arm['name'] / (name + '.json') for name in ['host', 'client', 'controller']}
        data = {name: json.loads(path.read_bytes()) for name, path in files.items() if path.exists()}
        result = {**arm, 'input_sha256': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in files.values() if p.exists()}, 'valid_arm': False}
        if len(data) == 3:
            try:
                result['summary'] = full.validate_arm(**data, conformance=manifest['profile'] == 'conformance')
                result['valid_arm'] = True
            except ValueError as error:
                result['validation_rejection'] = str(error)
        else:
            result['missing_reports'] = [name for name in files if name not in data]
        if 'host' in data:
            result['terminal_store'] = data['host']['store']
            result['terminal_budget'] = data['host']['snapshot']
        if 'client' in data:
            result['phases'] = []
            frequency = data['client']['environment']['stopwatchFrequency']
            for phase in data['client']['phases']:
                raw = phase['Rows']
                dropped = [r for r in raw if r['Outcome'] == 'dropped']
                result['phases'].append({'name': phase['Name'], 'rows': len(raw),
                    'outcomes': dict(Counter(r['Outcome'] for r in raw)),
                    'dropped': [{'index': r['Index'], 'lane': r['Lane'], 'recorded_ticks': r['Completed'],
                                 'preceding_same_lane': raw[r['Index'] - 32] if r['Index'] >= 32 else None} for r in dropped],
                    'maximum_response_ms': max(((r['Completed'] - r['Sent']) * 1000 / frequency for r in raw if r['Sent']), default=None),
                    'maximum_send_lag_ms': max(((r['Sent'] - r['Scheduled']) * 1000 / frequency for r in raw if r['Sent']), default=None)})
        rows.append(result)
    pairs = []
    for tenant in [False, True]:
        for pair in range(1, 7):
            arms = [r for r in rows if r['tenant'] == tenant and r['pair'] == pair]
            if len(arms) == 2 and all(r['valid_arm'] for r in arms):
                baseline = next(r for r in arms if not r['listener'])['summary']['values']
                listener = next(r for r in arms if r['listener'])['summary']['values']
                pairs.append({'tenant': tenant, 'pair': pair, 'differences': {
                    k: {'listener_minus_baseline': listener[k] - baseline[k],
                        'listener_over_baseline': listener[k] / baseline[k] if baseline[k] else None} for k in baseline}})
    return {'status': 'partial-audit', 'attempt_status': manifest['status'], 'arms': rows,
            'complete_pairs_within_this_attempt': pairs,
            'qualification': False, 'analysis_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'scope': 'Every entered arm retained, including failed and unpaired arms. Do not pool with another attempt or infer a completed series.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = summarize(args.input)
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(report, output, indent=2); output.write('\n')
    print(json.dumps({'status': report['status'], 'entered_arms': len(report['arms']),
                      'valid_arms': sum(r['valid_arm'] for r in report['arms']), 'qualification': False}))


if __name__ == '__main__':
    main()
