import gzip,hashlib,json,re
from pathlib import Path

root=Path(__file__).resolve().parents[1];target=root/'tooling-small-api/evidence/2026-11-20-timer-publication';target.mkdir(parents=True,exist_ok=False)
entries={};private=[]
def retain(path,name):
    raw=path.read_bytes()
    assert not re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}|gh[pousr]_[A-Za-z0-9]{30,}',raw),path
    compress=path.suffix=='.jsonl' or path.name.endswith('.receipts.json') or (path.suffix=='.json' and len(raw)>100000)
    stored=gzip.compress(raw,mtime=0) if compress else raw
    out=target/(name+('.gz' if compress else ''));out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(stored)
    if compress:assert gzip.decompress(stored)==raw
    entries[out.relative_to(target).as_posix()]={'raw_path':name,'encoding':'gzip' if compress else 'identity',
        'raw_sha256':hashlib.sha256(raw).hexdigest(),'stored_sha256':hashlib.sha256(stored).hexdigest(),'raw_bytes':len(raw),'stored_bytes':len(stored)}

base=root/'.local/timer-publication-prepare01'
for path in base.iterdir():
    if path.is_file() and path.suffix in ['.txt','.json']:retain(path,base.name+'/'+path.name)
for directory in ['frozen','original','consumer']:
    for path in (base/directory).iterdir():
        if path.is_file():retain(path,base.name+'/'+path.relative_to(base).as_posix())
for name in ['RuntimeTrace.cs','RuntimeTrace.csproj','packages.lock.json']:
    retain(root/'.local/warmup-trace-prepare03/frozen'/name,'reused-collector-source/'+name)
for name in ['observe_https_metrics.py','trace_https_warmup.py','analyze_https_warmup.py','observe_timer_publication.py',
             'analyze_timer_publication.py','test_timer_publication.py','summarize_timer_publication.py']:
    retain(root/'tools'/name,'analysis-and-unchanged-helpers/'+name)
for name in ['timer-publication-preflight01','timer-publication-compare01']:
    source=root/'.local'/name
    for path in source.rglob('*'):
        if not path.is_file():continue
        if path.suffix=='.nettrace':private.append({'local_path':path.relative_to(root).as_posix(),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size,'published':False})
        elif path.suffix in ['.json','.jsonl','.txt','.py','.cs','.md']:retain(path,name+'/'+path.relative_to(source).as_posix())
retain(root/'.local/timer-publication-readiness.json','timer-publication-readiness.json')
retain(Path(__file__),'analysis-and-unchanged-helpers/archive_timer_publication.py')
(target/'raw-integrity.json').write_text(json.dumps(entries,indent=2)+'\n',encoding='utf-8',newline='\n')
(target/'private-traces.json').write_text(json.dumps(private,indent=2)+'\n',encoding='utf-8',newline='\n')
(target/'README.md').write_text('''# Timer/continuation publication evidence

All four alternating untraced/traced pairs and all 4,096 synthetic trials are retained. Profiles: Task.Delay(1), one-shot timer/async completion, timer/inline-eligible completion and accepted ThreadPool work/async completion. Existing HTTPS pacer, benchmark source and Engine policy are unchanged. No timing rerun or outlier/first-call removal.

Preflight retains one positive GC/TPL/marker fixture and two eight-trial-per-profile processes. The comparison requires that exact preparation's validated preflight. Source, locks, original/augmented consumer, unchanged emitted registry, collector dependency hashes, normalized exports and raw point/receipt ledgers are retained. Unchanged helper/collector source snapshots are included for replay; original capture freezes identify the exact pre-run inputs.

Bounds permit callbacks before arm/queue return and resumption before the publisher's after-point. Same TID alone is not inline proof. All 1,024 inline-eligible trials resume within publication on the callback thread; async profiles never do so. Four traced processes reconcile 14,856 markers with reported loss zero and no GC inner/envelope overlap in analyzed probe legs. These are bounded observations, not historical five-drop causality, kernel-ready/switch timing or production policy advice.

Large analysis/receipt/event files use deterministic lossless gzip. raw-integrity.json maps original logical paths, raw/stored sizes and hashes. Reconstruct into a fresh local directory, constrain paths to it, decompress entries and verify all raw digests; the normalized analysis runs without original nettraces. Keep private-traces.json's six original nettraces in ignored local storage. No private handshake, credential, raw nettrace or binary is published.

[Protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/windows-timer-publication.md) and [report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/windows-timer-publication.md). #3 remains Blocked and all original benchmark criteria remain unchanged.
''',encoding='utf-8',newline='\n')
(target/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(target).as_posix()+'\n' for p in sorted(target.rglob('*')) if p.is_file()),encoding='utf-8',newline='\n')
print(json.dumps({'files':len(entries),'stored_bytes':sum(v['stored_bytes'] for v in entries.values()),'private_traces':len(private),'private_bytes':sum(v['bytes'] for v in private)}))
