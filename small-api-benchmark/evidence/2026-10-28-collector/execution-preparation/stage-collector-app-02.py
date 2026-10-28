from pathlib import Path
import hashlib, json, os, posixpath, shutil, subprocess

root=Path('/mnt/d/Cephalon/Cehpalon-Engine-Samples')
build=root/'.local/collector-conformance-linux-02'
manifest=json.loads((build/'manifest.json').read_text())
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert manifest['status']=='passed' and manifest['source_state']=='exact clean committed source'
assert manifest['samples_source_revision']==head
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
source=build/'artifacts/bin/SmallApi.Benchmark/release'
target=Path.home()/'.local/share/cehpalon-benchmark-deployment/collector-20261028/app-final-02'
target.parent.mkdir(parents=True,exist_ok=True)
os.chmod(target.parent,0o700)
shutil.copytree(source,target,symlinks=True)
os.chmod(target,0o700)
entries=[]
for f in sorted(source.rglob('*')):
    if not f.is_file(): continue
    relative=f.relative_to(source)
    assert 'evidence' not in relative.parts and f.suffix.lower() not in ('.pfx','.p12','.key')
    digest=hashlib.sha256(f.read_bytes()).hexdigest()
    assert hashlib.sha256((target/relative).read_bytes()).hexdigest()==digest
    entries.append({'path':relative.as_posix(),'bytes':f.stat().st_size,'sha256':digest})
assert hashlib.sha256((target/'SmallApi.Benchmark.dll').read_bytes()).hexdigest()==manifest['assembly_sha256']
report={'source':str(source),'target':str(target),'samples_source_revision':head,'engine_revision':manifest['engine_revision'],'assembly_sha256':manifest['assembly_sha256'],'all_hashes_match':True,'files':entries,'startup_tracing_enabled':False,'scope':'Exact clean conformance-tested native app/cwd; both variants share bytes, SDK, runtime and environment.'}
(root/'.local/collector-final-app-staging-02.json').write_text(json.dumps(report,indent=2)+'\n')
sdk=json.loads((root/'.local/startup-layout-sdk-staging.json').read_text())
base=Path(sdk['target']);links=json.loads((root/'.local/startup-sdk-link-manifest.json').read_text())
for item in sdk['files']:
    assert hashlib.sha256((base/item['path']).read_bytes()).hexdigest()==item['sha256']
for item in links:
    path=base/item['path']
    expected=posixpath.normpath(item['target'].replace('\\','/'))
    assert path.is_symlink() and os.readlink(path)==expected
sdk_report={'target':str(base),'regular_files_verified':len(sdk['files']),'symlinks_verified':len(links),'all_hashes_and_targets_match':True,'link_representation':'Windows manifest separators normalized to POSIX before exact native readlink comparison','source_manifest_sha256':hashlib.sha256((root/'.local/startup-layout-sdk-staging.json').read_bytes()).hexdigest(),'link_manifest_sha256':hashlib.sha256((root/'.local/startup-sdk-link-manifest.json').read_bytes()).hexdigest()}
(root/'.local/collector-sdk-reverification-02.json').write_text(json.dumps(sdk_report,indent=2)+'\n')
print(json.dumps({'app_files':len(entries),'app_bytes':sum(x['bytes'] for x in entries),'target':str(target),'sdk_regular_files':len(sdk['files']),'sdk_links':len(links)}))
