import gzip
import hashlib
import json
from pathlib import Path
import re

root=Path(__file__).resolve().parents[1]
target=root/'tooling-small-api/evidence/2026-11-20-windows-warmup-drops'
target.mkdir(parents=True,exist_ok=False)
integrity={};private=[]

def keep(path,name,compress=False):
    raw=path.read_bytes()
    assert not re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}|gh[pousr]_[A-Za-z0-9]{30,}',raw),path
    stored=gzip.compress(raw,mtime=0) if compress else raw
    out=target/(name+('.gz' if compress else ''));out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(stored)
    if compress:assert gzip.decompress(stored)==raw
    integrity[out.relative_to(target).as_posix()]={'raw_path':name,'encoding':'gzip' if compress else 'identity',
        'raw_sha256':hashlib.sha256(raw).hexdigest(),'stored_sha256':hashlib.sha256(stored).hexdigest(),
        'raw_bytes':len(raw),'stored_bytes':len(stored)}

for name in ['failed-RuntimeTrace.cs.txt','preparation-failure.json']:
    keep(root/'.local/warmup-runtime-build01'/name,'initial-tool-build/'+name)
for attempt in ['01','02','03']:
    source=root/'.local'/('warmup-trace-prepare'+attempt)
    for path in source.iterdir():
        if path.is_file() and path.suffix in ['.json','.txt']:keep(path,source.name+'/'+path.name)
    for directory in ['frozen','original','consumer']:
        for path in (source/directory).iterdir():
            if path.is_file():keep(path,source.name+'/'+path.relative_to(source).as_posix())
    registry=list((source/'consumer-artifacts/obj/Consumer').rglob('OperationRegistrations.g.cs'))
    assert len(registry)==1
    old=root/'.local/https-overhead-prepare-win03/OperationRegistrations.g.cs.txt'
    # The prior registry may be retained in the functional manifest's verifier output instead.
    expected=json.loads((source/'base-manifest.json').read_bytes())
    original_registry=root/'.local/https-overhead-functional-win01/OperationRegistrations.g.cs.txt'
    assert registry[0].read_bytes()==original_registry.read_bytes()
    keep(registry[0],source.name+'/OperationRegistrations.g.cs.txt')

for name in ['warmup-trace-fixtures01','warmup-trace-fixtures02','warmup-trace-conformance01',
             'warmup-trace-conformance02','warmup-trace-windows01']:
    source=root/'.local'/name
    for path in source.rglob('*'):
        if not path.is_file():continue
        if path.suffix=='.nettrace':
            private.append({'local_relative_path':path.relative_to(root).as_posix(),
                'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size,'published':False})
        elif path.suffix in ['.json','.jsonl','.txt','.cs','.py','.csproj','.md']:
            compress=path.suffix=='.jsonl' or path.name.endswith('.receipts.json') or (path.suffix=='.json' and path.stat().st_size>100000)
            keep(path,name+'/'+path.relative_to(source).as_posix(),compress)
for name in ['windows-drop-history01.json','windows-warmup-native-readiness.json']:
    keep(root/'.local'/name,name)
for name in ['analyze_https_warmup.py','trace_https_warmup.py','test_https_warmup.py','summarize_https_warmup.py']:
    keep(root/'tools'/name,'final-tools/'+name)
keep(Path(__file__),'final-tools/archive_warmup_trace.py')
(target/'private-trace-index.json').write_text(json.dumps(private,indent=2)+'\n',encoding='utf-8',newline='\n')
(target/'raw-integrity.json').write_text(json.dumps(integrity,indent=2)+'\n',encoding='utf-8',newline='\n')
(target/'README.md').write_text('''# Windows warmup drop evidence

Historical replay proves five overdue busy-lane decisions occurred in an 11.8 us burst over an 8 ms offered schedule, with 32 recorded requests pending at each drop. The missing historical GC/kernel trace cannot be reconstructed.

Four fixed new EventPipe warmups (baseline/listener/listener/baseline) each validate 1,500 reads and zero drops. All 806 producer await intervals and 6,000 request stage windows remain in analysis.json; no matching-drop retry was made. Independent process/native-thread/QPC receipt checks, terminal marker counts, known CLR templates and positive GC/TPL controls pass. Original analysis-initial.json is retained; final analysis adds planned server-stage/tail and pool endpoint fields without changing execution or raw inputs. Windows and WSL offline replay bytes match.

Initial source/compiler failure, unused preparation 01, preparation 02's controls and rejected server-stage preflight, corrected preparation 03's controls/preflight and all four fixed warmups are preserved. The first fixture analysis missed TaskScheduled/Transfer; the same raw data validates with the corrected parser. The first server hook lacked the base request activity; its conformance is rejected and not used to authorize the fixed warmups. See each frozen source/protocol and rejection record. Fixture forced collection is isolated from HTTPS work.

The current Windows token is unelevated and has no SeSystemProfilePrivilege or SeDebugPrivilege. No kernel session was started. CLR suspension overlap and managed task envelopes are not OS ready-to-running time or exclusive causal shares. In particular, GC suspension itself may include scheduling of GC threads. Uncovered time remains unknown. New zero-drop executions do not resolve the original five-drop runtime cause or qualify the old Windows benchmark.

Raw private nettraces remain in ignored local storage. private-trace-index.json records all original hashes/sizes. Public exports omit unapproved payloads, strings and raw pointer identities; receipt/normalized-event JSON is losslessly gzip compressed with separate raw/stored hashes. Reconstruct entries from raw-integrity.json into a fresh directory, verify raw SHA-256 and use final-tools for analysis. Keep extraction inside that directory. No credentials, private handshake, raw nettrace or binaries are published.

[Protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/windows-warmup-drops.md) and [report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/windows-warmup-drops.md). #3 stays Blocked; #18/#20 In Progress/M0 and original benchmark criteria remain unchanged.
''',encoding='utf-8',newline='\n')
(target/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.relative_to(target).as_posix()+'\n'
    for path in sorted(target.rglob('*')) if path.is_file()),encoding='utf-8',newline='\n')
print(json.dumps({'files':len(integrity),'private_original_traces':len(private),'stored_public_bytes':sum(v['stored_bytes'] for v in integrity.values()),'retained_private_bytes':sum(v['bytes'] for v in private)}))
