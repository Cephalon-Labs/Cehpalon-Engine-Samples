from pathlib import Path
import hashlib,json,re,shutil

root=Path('/mnt/d/Cephalon/Cehpalon-Engine-Samples')
worktrees=root.parent/'.worktrees'
out=root/'small-api-benchmark/evidence/2026-10-28-collector'
entries=[];excluded=[]
private=re.compile(rb'(?m)^-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END (?:[A-Z]+ )?PRIVATE KEY-----')

def retain(source,relative):
    if 'artifacts' in relative.parts:
        excluded.append(relative.as_posix());return
    if source.suffix.lower() in ('.pfx','.p12','.key','.dll','.exe','.so','.dmp') or source.name.lower()=='core' or source.name.lower().startswith('core.'):
        raise ValueError('Refused private/binary/dump evidence '+str(relative))
    data=source.read_bytes()
    if private.search(data):raise ValueError('Private key material refused '+str(relative))
    if len(data)>=100*1024*1024:raise ValueError('Evidence file exceeds normal Git limit '+str(relative))
    target=out/relative;target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists() and target.read_bytes()!=data:raise ValueError('Existing retained evidence differs '+str(relative))
    if not target.exists():shutil.copyfile(source,target)
    digest=hashlib.sha256(data).hexdigest()
    if hashlib.sha256(target.read_bytes()).hexdigest()!=digest:raise ValueError('Copy differs '+str(relative))
    entries.append({'path':relative.as_posix(),'bytes':len(data),'sha256':digest})

def tree(source,relative):
    if not source.is_dir():raise ValueError('Missing retained evidence source '+str(source))
    for path in sorted(source.rglob('*')):
        if path.is_file():retain(path,relative/path.relative_to(source))

native=Path.home()/'.local/share/cehpalon-benchmark-runs'
for name in ('benchmark-observation-04','collector-readiness-probe-01'):
    tree(native/name,Path(name))
for name in ('collector-conformance-win-01','collector-conformance-linux-01','collector-conformance-win-02','collector-conformance-linux-02'):
    tree(root/'.local'/name,Path(name))
tree(worktrees/'w2-collector-readiness/.local/collector-proof',Path('collector-offline-proof'))
tree(worktrees/'w2-collector-adversarial/.local/collector-robustness-01',Path('collector-robustness-01'))
for name in ('collector_robustness.py',):
    retain(worktrees/'w2-collector-adversarial/.local'/name,Path('collector-robustness-source')/name)
for path in sorted((worktrees/'w2-collector-probe/.local').glob('collector-*')):
    if path.is_file():retain(path,Path('collector-metadata-proof')/path.name)
for name in ('canonical-classifier-review.json','test-canonical-classifier.py','run-small-api-benchmark-04.ps1','benchmark-windows-launcher-04.json','run-small-api-collector-probe-01.ps1','collector-probe-windows-launcher-01.json','stage-collector-app.py','stage-collector-app-02.py','collector-final-app-staging.json','collector-final-app-staging-02.json','collector-sdk-reverification.json','collector-sdk-reverification-02.json'):
    retain(root/'.local'/name,Path('execution-preparation')/name)
retain(Path(__file__),Path('execution-preparation')/Path(__file__).name)
manifest={'schema':1,'scope':'All complete canonical04 and twelve connection probes, both conformance01 outcomes including Windows failure, complete sequential02 validation, collector robustness/offline proofs and execution preparation. Lossless raw bytes; private fixtures, compiled artifacts and dumps excluded; original native/worktree data retained.','samples_source_revision':'a3bd8b5c5747440c81124774ac10b6451d88ff82','engine_revision':'6804271d429106864e01e4ec546a41dff771f84b','entries':entries,'excluded_artifact_paths':excluded}
(out/'execution-retention-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({'files':len(entries),'bytes':sum(x['bytes'] for x in entries),'largest':max(x['bytes'] for x in entries),'excluded_artifact_files':len(excluded),'target':str(out)}))
