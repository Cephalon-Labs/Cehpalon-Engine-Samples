import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil

root = Path(__file__).resolve().parents[1]
target = root / 'tooling-small-api/evidence/2026-11-20-https-metrics-overhead'
target.mkdir(parents=True, exist_ok=False)
integrity = {}

def retain(source, relative, compress=False):
    raw = source.read_bytes()
    assert not re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}|gh[pousr]_[A-Za-z0-9]{30,}', raw), source
    output = target / (relative + ('.gz' if compress else ''))
    output.parent.mkdir(parents=True, exist_ok=True)
    stored = gzip.compress(raw, mtime=0) if compress else raw
    output.write_bytes(stored)
    if compress:
        assert gzip.decompress(output.read_bytes()) == raw
    integrity[output.relative_to(target).as_posix()] = {
        'raw_path': relative, 'encoding': 'gzip' if compress else 'identity',
        'raw_sha256': hashlib.sha256(raw).hexdigest(), 'stored_sha256': hashlib.sha256(stored).hexdigest(),
        'raw_bytes': len(raw), 'stored_bytes': len(stored)}

for host in ['win01', 'wsl01']:
    name = 'https-overhead-functional-' + host
    source = root / '.local' / name
    for filename in ['manifest.json', 'self-test.json', 'capacity.json', 'tenant-capacity.json', 'drain.json',
                     'live-metrics.json', 'live-metrics-analysis.json', 'consumer-packages.lock.json',
                     'OperationRegistrations.g.cs.txt', 'sdk-version.txt']:
        retain(source / filename, name + '/' + filename)

for host in ['win01', 'win02', 'win03', 'wsl01']:
    name = 'https-overhead-prepare-' + host
    source = root / '.local' / name
    manifest = json.loads((source / 'manifest.json').read_bytes())
    registry = list((source / 'artifacts/obj/Consumer').rglob('OperationRegistrations.g.cs'))
    assert len(registry) == 1
    functional = json.loads((source / 'functional-manifest.json').read_bytes())
    assert hashlib.sha256(registry[0].read_bytes()).hexdigest() == functional['generated_registry_sha256']
    retain(registry[0], name + '/OperationRegistrations.g.cs.txt')
    for filename in ['manifest.json', 'functional-manifest.json', 'original.Consumer.csproj.txt', 'sdk.txt', 'restore.txt', 'build.txt']:
        retain(source / filename, name + '/' + filename)
    for directory in ['frozen', 'consumer']:
        files = ((source / directory).iterdir() if directory == 'consumer' else (source / directory).rglob('*'))
        for path in files:
            if path.is_file():
                if directory == 'consumer':
                    assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest['source_files_sha256'][path.name]
                retain(path, name + '/' + path.relative_to(source).as_posix())

runs = ['https-overhead-conformance-win01', 'https-overhead-conformance-win02', 'https-overhead-conformance-win03',
        'https-overhead-conformance-wsl01', 'https-overhead-abort-win01',
        'https-overhead-measure-win01', 'https-overhead-measure-win02', 'https-overhead-measure-wsl01']
for name in runs:
    source = root / '.local' / name
    for path in source.rglob('*'):
        if path.is_file() and path.suffix in ['.json', '.cs', '.py', '.md', '.txt']:
            relative = path.relative_to(source)
            compress = path.name in ['host.json', 'client.json', 'controller.json']
            retain(path, name + '/' + relative.as_posix(), compress)

for name in ['analyze_https_metrics.py', 'summarize_https_metrics_attempt.py', 'verify_https_metrics_evidence.py', 'observe_https_metrics.py']:
    retain(root / 'tools' / name, 'final-analysis-tools/' + name)
retain(Path(__file__), 'final-analysis-tools/archive_https_metrics.py')

(target / 'raw-integrity.json').write_text(json.dumps(integrity, indent=2) + '\n', encoding='utf-8', newline='\n')
(target / 'README.md').write_text('''# HTTPS metrics overhead evidence

The frozen mixed HTTP/GraphQL workload uses separate server/client processes, actual generated Core gateways, fresh fixture tenant checks, 32 observed TLS1.3/HTTP1.1 connections and fixed offered traffic. Engine product source remains 5f8f252e901e85c50d7fc6f4b760e457965ce3bb; SDK is 11.0.100-rc.3.26522.148.

WSL measurement 01 completed all 24 arms (six alternating pairs per budget mode), 120,000 measured reads, no drops/failures/new TLS connections and exact owned cleanup. Its analysis-corrected.json is the final descriptive analysis. Original analysis.json remains retained: the correction only removes CV for signed paired differences; input hashes, arm values, pairs and means/medians/ranges are identical. Baseline/listener arm CV remains available. These shared-host observations do not qualify canonical performance or production.

Windows measurement 01 is incomplete: three arms passed, then a fourth warmup failed; its client rows were not persisted because of a controller defect. All available output is retained. The corrected controller explicitly ABORTs the waiting client and awaits partial output before cleanup. The intentional abort fixture preserves 128 warmup rows and 160 handler disposals. Separately declared Windows measurement 02 passed two arms, then retained all 1,500 warmup rows: 1,495 passed and five assigned-lane drops. No further timing rerun was made. Both partial-analysis.json files retain every entered, failed and unpaired arm separately; do not pool attempts.

Preparations win01/win02/win03 and wsl01 retain their actual frozen code/protocol, original and augmented generated projects, locks, emitted registry and binary hashes. No binaries or private fixture state are published. Functional verifier reports preserve all 160 checks and original 39 self-tests on each host. Four conformance captures and 17 final adversarial mutations per host are retained. Initial source/control corrections are documented in the frozen protocols. Frozen files describe executing source, not a later code snapshot.

Raw host/client/controller JSON is losslessly gzip-compressed with deterministic mtime. raw-integrity.json maps each stored file to its original relative path, size and SHA-256; SHA256SUMS.txt covers stored bytes. To reproduce analysis, reconstruct files into a fresh local directory with those original relative paths, decompress gzip entries, and verify every raw digest. Use the frozen analyzer for original outputs and final-analysis-tools for the corrected output/partial audit. Treat archive paths as data and keep extraction inside the chosen directory.

All first callbacks, samples, warmup rows, measured rows and recorded failures are retained. Metrics allocation differences are whole-server-process differences; CPU includes background work and matching control gaps. Actual sampler cadence differs from the requested delay. Negative timing deltas do not establish a speedup. #3 remains Blocked, #18/#20 In Progress/M0 and original benchmark criteria remain unchanged.

[Report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/https-metrics-overhead.md)
''', encoding='utf-8', newline='\n')
(target / 'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(target).as_posix() + '\n'
    for p in sorted(target.rglob('*')) if p.is_file()), encoding='utf-8', newline='\n')
print(json.dumps({'files': len(integrity), 'stored_bytes': sum(v['stored_bytes'] for v in integrity.values()),
                  'raw_bytes': sum(v['raw_bytes'] for v in integrity.values())}))
