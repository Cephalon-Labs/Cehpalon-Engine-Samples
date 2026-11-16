"""ADR0021 passive readiness inventory; never starts tracing or changes host settings."""
import argparse, hashlib, json, os, platform
from pathlib import Path

EVENTS = ('sched_switch', 'sched_wakeup', 'sched_wakeup_new', 'sched_process_fork', 'sched_process_exit')

def observe(path):
    try:
        raw = Path(path).read_bytes()
        return {'status': 'readable', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                'text': raw.decode('utf-8', errors='replace')}
    except FileNotFoundError:
        return {'status': 'missing'}
    except PermissionError:
        return {'status': 'denied'}
    except OSError as error:
        return {'status': 'unavailable', 'error_type': type(error).__name__}

def assess(system, observations):
    failures = []
    if system != 'Linux':
        failures.append('linux_scheduler_probe_not_applicable')
    for name in EVENTS:
        item = observations.get(name, {})
        if item.get('status') != 'readable':
            failures.append(name + ':' + item.get('status', 'unknown'))
        elif not item.get('bytes', 0):
            failures.append(name + ':empty_format')
    return {'status': 'not_established', 'passive_format_inventory_complete': not failures,
            'obstacles': failures, 'active_capture_permission': 'untested',
            'event_delivery_loss_clock_identity': 'untested',
            'causal_worker_gc_scheduler_readiness': False,
            'reason': 'Passive access never establishes successful owned collection, task lineage, loss or clock joins.'}

def probe(root='/'):
    root = Path(root)
    events = {name: observe(root / ('sys/kernel/tracing/events/sched/' + name + '/format')) for name in EVENTS}
    return {'schema_version': 1, 'system': platform.system(), 'kernel': platform.release(),
            'uid': os.getuid() if hasattr(os, 'getuid') else None,
            'events': events, 'perf_event_paranoid': observe(root / 'proc/sys/kernel/perf_event_paranoid'),
            'capabilities': observe(root / 'proc/self/status'),
            'assessment': assess(platform.system(), events),
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'limits': ['No target or perf capture launched.', 'No permission or kernel configuration changed.',
                       'Missing or denied formats do not prove events absent.',
                       'Readable formats or sysctl values do not prove capture permission or zero loss.']}

def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        p = Path(directory) / 'format'
        assert observe(p)['status'] == 'missing'
        p.write_bytes(b'event-format')
        r = observe(p)
        assert r['bytes'] == 12 and r['sha256'] == hashlib.sha256(b'event-format').hexdigest()
    good = {k: {'status': 'readable', 'bytes': 12} for k in EVENTS}
    assert assess('Linux', good)['passive_format_inventory_complete']
    assert not assess('Linux', good)['causal_worker_gc_scheduler_readiness']
    assert assess('Linux', good)['active_capture_permission'] == 'untested'
    assert not assess('Windows', good)['passive_format_inventory_complete']
    for status in ('denied', 'missing', 'unavailable', 'unknown'):
        bad = dict(good); bad[EVENTS[0]] = {'status': status}
        assert not assess('Linux', bad)['passive_format_inventory_complete']
    bad = dict(good); bad[EVENTS[0]] = {'status': 'readable', 'bytes': 0}
    assert not assess('Linux', bad)['passive_format_inventory_complete']
    assert len(assess('Linux', {})['obstacles']) == len(EVENTS)
    return {'self_test': 'passed', 'checks': 12}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    result = self_test() if args.self_test else probe()
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        with Path(args.output).open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
    else:
        print(text, end='')
