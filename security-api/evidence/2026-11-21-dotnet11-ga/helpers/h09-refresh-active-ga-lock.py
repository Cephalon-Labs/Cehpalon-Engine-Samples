"""Private deliberate GA lock refresh; freeze all executing inputs before SDK work."""
import argparse, hashlib, json, os, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--dotnet',required=True);p.add_argument('--engine-root',required=True);p.add_argument('--output',required=True);p.add_argument('--project',required=True);a=p.parse_args()
engine=Path(a.engine_root).resolve();out=(ROOT/a.output).resolve();assert out.is_relative_to(ROOT/'.local') and out!=ROOT/'.local';out.mkdir(parents=True,exist_ok=False)
report={'status':'frozen-before-sdk','scope':'Deliberate active consumer GA lock refresh; no benchmark qualification','source_sha256':{},'lock_before':{},'lock_after':{},'project':a.project,'engine_revision':subprocess.check_output(['git','-C',str(engine),'rev-parse','HEAD'],text=True).strip()}
def save():(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
def freeze(prefix,root,path):
 data=path.read_bytes();key=prefix+'/'+path.relative_to(root).as_posix();target=out/'frozen-source'/key;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);report['source_sha256'][key]=hashlib.sha256(data).hexdigest()
for prefix,root,folders in [('consumer',ROOT,['small-api','security-api','audit-outbox']),('engine',engine,['src'])]:
 for folder in folders:
  for file in sorted((root/folder).rglob('*')):
   if file.is_file() and not {'bin','obj','evidence','.local','.git'}.intersection(file.relative_to(root).parts) and file.suffix in {'.cs','.csproj','.json','.txt','.props','.targets','.Config'}:freeze(prefix,root,file)
for prefix,root,names in [('consumer',ROOT,['global.json','NuGet.Config','tools/verify_small_api.py','tools/verify_optional_security.py','tools/verify_audit_outbox.py']),('engine',engine,['global.json','NuGet.Config','Directory.Packages.props'])]:
 for name in names:freeze(prefix,root,root/name)
freeze('consumer',ROOT,Path(__file__).resolve())
locks=[ROOT/folder/'packages.lock.json' for folder in ['small-api','security-api','audit-outbox']]
report['lock_before']={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in locks};save()
env=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1')
def run(command,name):
 result=subprocess.run(list(map(str,command)),cwd=ROOT,env=env,capture_output=True);(out/name).write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError('Failed '+name+'; retained raw output')
 return result.stdout.decode('utf-8').strip()
try:
 report['sdk']=run([a.dotnet,'--version'],'sdk.txt');assert report['sdk']=='11.0.100';assert json.loads((engine/'global.json').read_bytes())['sdk']['version']==report['sdk'];save()
 run([a.dotnet,'restore',ROOT/a.project,'--configfile',ROOT/'NuGet.Config','--artifacts-path',out/'artifacts','-p:EngineRoot='+str(engine)],'restore.txt')
 for file in locks:
  data=file.read_bytes();report['lock_after'][str(file.relative_to(ROOT))]=hashlib.sha256(data).hexdigest();target=out/'resulting-locks'/file.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
 report['status']='passed'
except Exception as e:
 report.update(status='failed',error=str(e));save();raise
save();print(json.dumps({'status':report['status'],'sdk':report['sdk'],'output':str(out)}))
