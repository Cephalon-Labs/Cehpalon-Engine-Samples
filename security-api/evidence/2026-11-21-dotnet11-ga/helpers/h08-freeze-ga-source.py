import hashlib,json,subprocess
from pathlib import Path
root=Path.cwd();engine=Path('D:/Cephalon/.worktrees/ga-integration');out=root/'.local/dotnet-ga-locked-frozen01';out.mkdir(exist_ok=False)
m={'engine_revision':subprocess.check_output(['git','-C',str(engine),'rev-parse','HEAD'],text=True).strip(),'source_sha256':{},'scope':'Frozen before first locked GA Windows consumer verification'}
for prefix,repo,folders in [('consumer',root,['small-api','security-api','audit-outbox','tools']),('engine',engine,['src'])]:
 for folder in folders:
  for f in sorted((repo/folder).rglob('*')):
   if f.is_file() and not {'evidence','.local','.git','bin','obj','__pycache__'}.intersection(f.relative_to(repo).parts) and f.suffix in {'.cs','.csproj','.json','.txt','.py','.Config','.props','.targets'}:
    key=prefix+'/'+f.relative_to(repo).as_posix();d=f.read_bytes();p=out/'frozen-source'/key;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(d);m['source_sha256'][key]=hashlib.sha256(d).hexdigest()
for prefix,repo,files in [('consumer',root,['global.json','NuGet.Config']),('engine',engine,['global.json','NuGet.Config','Directory.Packages.props'])]:
 for name in files:
  f=repo/name;d=f.read_bytes();key=prefix+'/'+name;p=out/'frozen-source'/key;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(d);m['source_sha256'][key]=hashlib.sha256(d).hexdigest()
(out/'manifest.json').write_text(json.dumps(m,indent=2)+'\n');print(json.dumps({'frozen':len(m['source_sha256']),'output':str(out)}))
