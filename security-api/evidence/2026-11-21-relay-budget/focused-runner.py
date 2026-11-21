from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,os,subprocess

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--attempt',required=True);a=p.parse_args()
assert '/' not in a.attempt and '\\' not in a.attempt
out=ROOT/'.local'/a.attempt;out.mkdir(parents=True,exist_ok=False)
dotnet='D:/Cephalon/.tools/dotnet11-ga/win-x64/dotnet.exe'
tracked=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
tracked+=['Tests/AuditOutbox.ContractTests/RelayBudgetChecks.cs','.local/run-relay-budget.py']
sources={}
for relative in sorted(set(x for x in tracked if x)):
 f=ROOT/relative
 if not f.is_file() or 'evidence' in f.parts or f.suffix.lower() not in {'.cs','.csproj','.json','.props','.config','.py','.md','.slnx','.yml','.txt'}:continue
 data=f.read_bytes();sources[relative]=hashlib.sha256(data).hexdigest();target=out/'frozen'/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
report={'status':'started','attempt':a.attempt,'observed_at_utc':datetime.now(timezone.utc).isoformat(),'baseline_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'source_sha256':sources,'scope':'Bounded cooperative relay budget component contracts and original outbox/status regressions; no real provider, performance, hard deadline or production qualification'}
env=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1')
def save():(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
def run(command,filename):
 r=subprocess.run(list(map(str,command)),cwd=ROOT,env=env,capture_output=True);(out/filename).write_bytes(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError('Failed '+filename+'; raw retained')
 return r.stdout.decode('utf-8')
save()
try:
 report['sdk']=run([dotnet,'--version'],'sdk.txt').strip();assert report['sdk']=='11.0.100'
 run([dotnet,'--info'],'sdk-info.txt');run([dotnet,'--list-runtimes'],'runtimes.txt')
 summaries=[];art=out/'artifacts'
 for name in ['AuditOutbox.ContractTests','OutboxStatus.ContractTests']:
  project='Tests/'+name+'/'+name+'.csproj'
  run([dotnet,'restore',project,'--locked-mode','--configfile',ROOT/'NuGet.Config','--artifacts-path',art],name+'-restore.txt')
  run([dotnet,'build',project,'--no-restore','-c','Release','--artifacts-path',art,'-p:UseSharedCompilation=false','-warnaserror'],name+'-build.txt')
  result=out/(name+'.json');run([dotnet,art/'bin'/name/'release'/(name+'.dll'),'--output='+str(result)],name+'-run.txt')
  value=json.loads(result.read_bytes());assert value['failed']==0
  summaries.append({'project':name,'passed':value['passed'],'failed':value['failed']})
 for relative,digest in sources.items():assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()==digest,relative
 report.update(status='passed',source_unchanged=True,summaries=summaries)
except Exception as error:report.update(status='failed',error=str(error));save();raise
save();print(json.dumps({key:report[key] for key in ['status','attempt','summaries']}))
