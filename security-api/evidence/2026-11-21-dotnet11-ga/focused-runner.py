from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,os,subprocess

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--dotnet',required=True);p.add_argument('--action',choices=['prepare','focus'],required=True);p.add_argument('--attempt',required=True);a=p.parse_args()
assert '/' not in a.attempt and '\\' not in a.attempt
out=ROOT/'.local'/a.attempt;out.mkdir(parents=True,exist_ok=False)
tracked=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
sources={};locks={}
for relative in sorted(x for x in tracked if x):
 f=ROOT/relative
 if not f.is_file() or 'evidence' in f.parts or f.suffix not in {'.cs','.csproj','.json','.props','.config','.py','.md','.slnx','.yml','.txt'}:continue
 data=f.read_bytes();sources[relative]=hashlib.sha256(data).hexdigest();target=out/'frozen'/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
 if f.name=='packages.lock.json':locks[relative]=data.decode('utf-8')
relative='.local/run-ga-engine.py';sources[relative]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();target=out/'frozen'/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(Path(__file__).read_bytes())
report={'status':'started','action':a.action,'attempt':a.attempt,'observed_at_utc':datetime.now(timezone.utc).isoformat(),'baseline_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'source_sha256':sources,'scope':'Explicit GA package-graph preparation or focused local CLI/platform smoke; no supported-host, real provider, benchmark or production qualification'}
def save():(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
save();env=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_CLI_HOME=str(ROOT/'.local'/'ga-cli-home'))
report['process_environment']={key:env[key] for key in ['DOTNET_NOLOGO','DOTNET_CLI_TELEMETRY_OPTOUT','DOTNET_CLI_HOME']};save()
def run(command,filename):
 r=subprocess.run(list(map(str,command)),cwd=ROOT,env=env,capture_output=True);(out/filename).write_bytes(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError('Failed '+filename+'; raw retained')
 return r.stdout.decode('utf-8')
try:
 report['sdk']=run([a.dotnet,'--version'],'sdk.txt').strip();assert report['sdk']=='11.0.100'
 run([a.dotnet,'--info'],'sdk-info.txt');run([a.dotnet,'--list-runtimes'],'runtimes.txt')
 artifacts=out/'artifacts'
 if a.action=='prepare':
  for name,project in [('solution','Cehpalon.Engine.slnx'),('platform','Tests/PlatformQualification/PlatformQualification.csproj')]:
   run([a.dotnet,'restore',project,'--configfile',ROOT/'NuGet.Config','--artifacts-path',artifacts],name+'-restore-unlocked.txt')
   run([a.dotnet,'build',project,'--no-restore','-c','Release','--artifacts-path',artifacts,'-p:UseSharedCompilation=false','-warnaserror'],name+'-build.txt')
  changed=[]
  for relative,before in locks.items():
   f=ROOT/relative;after=f.read_text();data=f.read_bytes();target=out/'restored-locks'/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
   if json.loads(before)!=json.loads(after):changed.append(relative)
  report.update(status='passed',changed_lock_files=changed,post_restore_lock_sha256={relative:hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() for relative in locks})
 else:
  summaries=[]
  for name,project in [('tooling','Tests/Tooling.ContractTests/Tooling.ContractTests.csproj'),('platform','Tests/PlatformQualification/PlatformQualification.csproj')]:
   run([a.dotnet,'restore',project,'--locked-mode','--configfile',ROOT/'NuGet.Config','--artifacts-path',artifacts],name+'-restore-locked.txt')
   run([a.dotnet,'build',project,'--no-restore','-c','Release','--artifacts-path',artifacts,'-p:UseSharedCompilation=false','-warnaserror'],name+'-build.txt')
   assembly='Tooling.ContractTests' if name=='tooling' else 'PlatformQualification';result=out/(name+'-results.json')
   run([a.dotnet,artifacts/'bin'/assembly/'release'/(assembly+'.dll'),'--output='+str(result)],name+'-run.txt');value=json.loads(result.read_bytes())
   if name=='tooling':assert value['failed']==0 and value['passed']>=156;summaries.append({'project':assembly,'passed':value['passed'],'failed':value['failed']})
   else:
    assert value['failed']==0;summaries.append({'project':assembly,'result':value})
  for relative,digest in sources.items():assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()==digest,relative
  report.update(status='passed',source_unchanged=True,summaries=summaries)
except Exception as error:report.update(status='failed',error=str(error));save();raise
save();print(json.dumps({key:report[key] for key in ['status','action','attempt']}))
