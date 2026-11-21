import hashlib,json,subprocess,sys
from pathlib import Path
r=Path.cwd();e=Path('D:/Cephalon/.worktrees/rb-engine');o=r/sys.argv[1];o.mkdir(exist_ok=False);m={'status':'frozen-before-sdk','engine_revision':subprocess.check_output(['git','-C',str(e),'rev-parse','HEAD'],text=True).strip(),'consumer_revision':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_sha256':{}}
for prefix,root,folders in [('consumer',r,['audit-outbox','security-api']),('engine',e,['src'])]:
 for folder in folders:
  for f in sorted((root/folder).rglob('*')):
   if f.is_file() and not {'evidence','bin','obj','.local','.git'}.intersection(f.relative_to(root).parts) and f.suffix in {'.cs','.csproj','.json','.txt','.props','.Config'}:
    key=prefix+'/'+f.relative_to(root).as_posix();data=f.read_bytes();p=o/'frozen-source'/key;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);m['source_sha256'][key]=hashlib.sha256(data).hexdigest()
for prefix,root,names in [('consumer',r,['global.json','NuGet.Config','tools/verify_audit_outbox.py']),('engine',e,['global.json','NuGet.Config','Directory.Packages.props'])]:
 for name in names:
  data=(root/name).read_bytes();key=prefix+'/'+name;p=o/'frozen-source'/key;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);m['source_sha256'][key]=hashlib.sha256(data).hexdigest()
(o/'manifest.json').write_text(json.dumps(m,indent=2)+'\n');print(json.dumps({'source_count':len(m['source_sha256']),'engine':m['engine_revision']}))
