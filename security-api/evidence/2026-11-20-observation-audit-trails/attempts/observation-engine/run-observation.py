import argparse,hashlib,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('output');p.add_argument('project');p.add_argument('--init',action='store_true');a=p.parse_args();root=Path.cwd();out=root/a.output;out.mkdir(parents=True,exist_ok=False);project=(root/a.project).resolve();env=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1');sdk='D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe';inventory={}
for folder in ['src/Cehpalon.Engine.Core','src/Cehpalon.Engine.Composition','src/Cehpalon.Engine.Identity.Contracts','src/Cehpalon.Engine.Identity.AspNetCore','src/Cehpalon.Engine.Tenancy','Tests/Observation.ContractTests']:
 for f in (root/folder).rglob('*'):
  if f.is_file() and not {'bin','obj','evidence','.local'}.intersection(f.relative_to(root/folder).parts) and f.suffix.lower() in ('.cs','.csproj','.json','.md'):inventory[f.relative_to(root).as_posix()]=f
for name in ['global.json','NuGet.Config','Directory.Packages.props']:inventory[name]=root/name
if not project.is_relative_to(root/'Tests'):
 for f in project.parent.iterdir():
  if f.is_file():inventory['probe/'+f.name]=f
hashes={}
for rel,f in inventory.items():
 data=f.read_bytes();target=out/'frozen'/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);hashes[rel]=hashlib.sha256(data).hexdigest()
(out/'source-sha256.json').write_text(json.dumps(hashes,indent=2)+'\n',encoding='utf-8');report={'engine_revision':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_state':subprocess.check_output(['git','status','--porcelain'],text=True).strip(),'first_lock_initialization':a.init,'status':'started'}
def save():(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
def run(args,name):
 r=subprocess.run([sdk,*map(str,args)],env=env,capture_output=True);(out/name).write_bytes(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError('Failed '+name+' exit '+str(r.returncode))
 return r.stdout.decode('utf-8')
save()
try:
 report['sdk']=run(['--version'],'sdk.txt').strip();assert report['sdk']==json.loads((root/'global.json').read_text())['sdk']['version'];common=['--artifacts-path',out/'artifacts'];run(['restore',project,'--configfile',root/'NuGet.Config',*common,*([] if a.init else ['--locked-mode'])],'restore.txt');lock=project.parent/'packages.lock.json';(out/'postrestore-lock.json').write_bytes(lock.read_bytes());run(['build',project,'-c','Release','--no-restore',*common,'-p:UseSharedCompilation=false','-warnaserror'],'build.txt');run([out/'artifacts/bin'/project.stem/'release'/(project.stem+'.dll'),'--output='+str(out/'tests.json')],'run.txt');report['status']='passed'
except Exception as e:report.update(status='failed',error=str(e));save();raise
save();print(json.dumps(report))
