from pathlib import Path
import hashlib,json,shutil,os
root=Path('/mnt/d/Cephalon/Cehpalon-Engine-Samples')
source=root/'.local/tuning-conformance-linux-01/artifacts/bin/SmallApi.Benchmark/release'
target=Path.home()/'.local/share/cehpalon-benchmark-deployment/tuning-20261028/app-final-01'
manifest=json.loads((root/'.local/tuning-conformance-linux-01/manifest.json').read_text())
assert manifest['status']=='passed' and manifest['source_state']=='exact clean committed source'
assert manifest['samples_source_revision']=='fb77069ec2af583b29814f941643a318222b420e'
shutil.copytree(source,target,symlinks=True)
os.chmod(target,0o700)
entries=[]
for f in sorted(source.rglob('*')):
 if f.is_file():
  rel=f.relative_to(source);h=hashlib.sha256(f.read_bytes()).hexdigest()
  assert hashlib.sha256((target/rel).read_bytes()).hexdigest()==h
  assert 'evidence' not in rel.parts
  assert f.suffix.lower() not in ('.pfx','.p12','.key')
  entries.append({'path':rel.as_posix(),'bytes':f.stat().st_size,'sha256':h})
assembly=target/'SmallApi.Benchmark.dll'
assert hashlib.sha256(assembly.read_bytes()).hexdigest()==manifest['assembly_sha256']
report={'source':str(source),'target':str(target),'samples_source_revision':manifest['samples_source_revision'],'engine_revision':manifest['engine_revision'],'source_build_manifest_sha256':hashlib.sha256((root/'.local/tuning-conformance-linux-01/manifest.json').read_bytes()).hexdigest(),'assembly_sha256':manifest['assembly_sha256'],'files':entries,'all_hashes_match':True,'evidence_content_files':0,'canonical_startup_tracing_enabled':False,'scope':'Uniform native deployment of exact conformance-tested artifact for both variants, no recompilation/R2R/runtime knob change.'}
(root/'.local/tuning-final-app-staging.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'files':len(entries),'bytes':sum(x['bytes'] for x in entries),'target':str(target)}))
