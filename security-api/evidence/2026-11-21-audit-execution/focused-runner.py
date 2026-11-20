from pathlib import Path
import sys,json,hashlib,subprocess,os
root=Path(__file__).resolve().parents[1]
out=root/'.local'/sys.argv[1]
out.mkdir(parents=True,exist_ok=False)
dotnet='D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe'
sources={}
folders=['src/Cehpalon.Engine.Core','src/Cehpalon.Engine.Identity.Contracts','src/Cehpalon.Engine.Tenancy','Tests/AuditExecution.ContractTests']
paths=[]
for folder in folders:
 paths.extend(p for p in (root/folder).rglob('*') if p.is_file() and not {'bin','obj','evidence'}.intersection(p.relative_to(root/folder).parts) and p.suffix in {'.cs','.csproj','.json','.md'})
paths += [root/p for p in ['global.json','Directory.Packages.props','NuGet.Config','.local/run-audit-execution.py']]
for p in sorted(paths):
 rel=p.relative_to(root).as_posix();data=p.read_bytes();sources[rel]=hashlib.sha256(data).hexdigest();target=out/'frozen'/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
report={'status':'started','source_sha256':sources,'baseline_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'scope':'Focused local audit execution contracts only; no transaction/provider/production qualification','attempt':out.name}
def save(): (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
save()
def run(command,name):
 result=subprocess.run(list(map(str,command)),cwd=root,env=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1'),capture_output=True);(out/name).write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError(f'{name} failed exit{result.returncode}')
 return result.stdout.decode('utf-8')
try:
 report['sdk']=run([dotnet,'--version'],'sdk.txt').strip()
 assert report['sdk']==json.loads((root/'global.json').read_bytes())['sdk']['version']
 project=root/'Tests/AuditExecution.ContractTests/AuditExecution.ContractTests.csproj';artifacts=out/'artifacts'
 run([dotnet,'restore',project,'--locked-mode','--configfile',root/'NuGet.Config','--artifacts-path',artifacts],'restore.txt')
 run([dotnet,'build',project,'--no-restore','-c','Release','--artifacts-path',artifacts,'-p:UseSharedCompilation=false','-warnaserror'],'build.txt')
 run([dotnet,artifacts/'bin/AuditExecution.ContractTests/release/AuditExecution.ContractTests.dll','--output='+str(out/'results.json')],'run.txt')
 result=json.loads((out/'results.json').read_bytes());assert result['failed']==0 and result['passed']>=30
 for rel,digest in sources.items():assert hashlib.sha256((root/rel).read_bytes()).hexdigest()==digest,rel
 report.update(status='passed',passed=result['passed'],failed=result['failed'],source_unchanged=True)
except Exception as e:report.update(status='failed',error=str(e));save();raise
save();print(json.dumps({k:report[k] for k in ['status','passed','failed','attempt']}))
