import hashlib,json,subprocess,sys
from pathlib import Path
root=Path.cwd();engine=Path('D:/Cephalon/.worktrees/al-engine');out=(root/sys.argv[1]).resolve();assert out.is_relative_to(root/'.local') and out!=root/'.local';out.mkdir(exist_ok=False)
report={'status':'frozen-before-sdk','engine_revision':subprocess.check_output(['git','-C',str(engine),'rev-parse','HEAD'],text=True).strip(),'consumer_revision':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_sha256':{}}
def retain(prefix,repo,path):
 key=prefix+'/'+path.relative_to(repo).as_posix();data=path.read_bytes();target=out/'frozen-source'/key;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);report['source_sha256'][key]=hashlib.sha256(data).hexdigest()
for prefix,repo,folders in [('consumer',root,['audit-outbox','security-api']),('engine',engine,['src'])]:
 for folder in folders:
  for file in sorted((repo/folder).rglob('*')):
   if file.is_file() and not {'evidence','bin','obj','.local','.git'}.intersection(file.relative_to(repo).parts) and file.suffix in {'.cs','.csproj','.json','.txt','.props','.targets','.Config'}:retain(prefix,repo,file)
for prefix,repo,names in [('consumer',root,['global.json','NuGet.Config','tools/verify_audit_outbox.py']),('engine',engine,['global.json','NuGet.Config','Directory.Packages.props'])]:
 for name in names:retain(prefix,repo,repo/name)
(out/'frozen-freezer.py.txt').write_bytes(Path(__file__).read_bytes());(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps({'frozen_inputs':len(report['source_sha256']),'engine_revision':report['engine_revision']}))
