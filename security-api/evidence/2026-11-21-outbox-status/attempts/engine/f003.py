from pathlib import Path
import json,hashlib,subprocess,os,sys
root=Path(__file__).resolve().parents[1];out=root/'.local'/sys.argv[1];out.mkdir(parents=True,exist_ok=False)
dotnet='D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe';sources={}
paths=[root/'.local/run-outbox-status.py',root/'Directory.Packages.props',root/'global.json',root/'NuGet.Config']
for folder in ['src/Cehpalon.Engine.Core','src/Cehpalon.Engine.Identity.Contracts','src/Cehpalon.Engine.Tenancy','Tests/OutboxStatus.ContractTests']:
 paths.extend(p for p in (root/folder).rglob('*') if p.is_file() and not {'bin','obj'}.intersection(p.relative_to(root/folder).parts))
for p in paths:
 rel=p.relative_to(root).as_posix();sources[rel]=hashlib.sha256(p.read_bytes()).hexdigest();target=out/'frozen'/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(p.read_bytes())
report={'status':'started','source_sha256':sources,'baseline_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'scope':'Focused portable checked aggregate status only; real provider snapshot, hard deadline, benchmark and production qualification separate','attempt':sys.argv[1]}
def save():(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
def run(args,name):
 p=subprocess.run(list(map(str,args)),cwd=root,capture_output=True,env=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1'));(out/name).write_bytes(p.stdout+p.stderr)
 if p.returncode:raise RuntimeError('Failed '+name)
 return p.stdout.decode('utf-8')
save()
try:
 report['sdk']=run([dotnet,'--version'],'sdk.txt').strip();assert report['sdk']==json.loads((root/'global.json').read_bytes())['sdk']['version']
 project=root/'Tests/OutboxStatus.ContractTests/OutboxStatus.ContractTests.csproj';artifacts=out/'artifacts'
 run([dotnet,'restore',project,'--locked-mode','--configfile',root/'NuGet.Config','--artifacts-path',artifacts],'restore.txt')
 run([dotnet,'build',project,'--no-restore','-c','Release','--artifacts-path',artifacts,'-p:UseSharedCompilation=false','-warnaserror'],'build.txt')
 run([dotnet,artifacts/'bin/OutboxStatus.ContractTests/release/OutboxStatus.ContractTests.dll','--output='+str(out/'results.json')],'run.txt')
 result=json.loads((out/'results.json').read_bytes());assert result['failed']==0 and result['passed']>=40
 for rel,digest in sources.items():assert hashlib.sha256((root/rel).read_bytes()).hexdigest()==digest,rel
 report.update(status='passed',passed=result['passed'],failed=result['failed'],source_unchanged=True)
except Exception as e:report.update(status='failed',error=str(e));save();raise
save();print(json.dumps({k:report[k] for k in ['status','passed','failed','attempt']}))
