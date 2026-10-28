from pathlib import Path
import hashlib,json,shutil,os
source=Path('/mnt/d/Cephalon/.tools/dotnet11/linux-x64')
target=Path.home()/'.local/share/cehpalon-benchmark-deployment/tuning-20261028/sdk'
target.parent.mkdir(parents=True,exist_ok=True)
os.chmod(target.parent,0o700)
if target.exists(): raise ValueError('Fresh staging target required')
shutil.copytree(source,target,symlinks=True)
entries=[]
for f in sorted(source.rglob('*')):
 if f.is_file() and not f.is_symlink():
  other=target/f.relative_to(source)
  a=hashlib.sha256(f.read_bytes()).hexdigest();b=hashlib.sha256(other.read_bytes()).hexdigest()
  if a!=b: raise ValueError('Staged SDK bytes differ')
  entries.append({'path':f.relative_to(source).as_posix(),'bytes':f.stat().st_size,'sha256':a})
os.chmod(target/'dotnet',0o755)
report={'source':str(source),'target':str(target),'all_regular_file_hashes_match':True,'files':entries,'scope':'Identical private pinned SDK/shared runtime deployment; no installation, version change or public distribution.'}
out=Path('/mnt/d/Cephalon/Cehpalon-Engine-Samples/.local/startup-layout-sdk-staging.json')
out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'files':len(entries),'bytes':sum(x['bytes'] for x in entries),'target':str(target)}))
