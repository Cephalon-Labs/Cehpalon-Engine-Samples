"""Sequential predeclared GA regression continuation; private inputs never copied into logs."""
from pathlib import Path
import hashlib,json,os,subprocess
E=Path('D:/Cephalon/.worktrees/ga-integration');S=Path('D:/Cephalon/.worktrees/ga-consumer');L=E/'.local';out=L/'dotnet-ga-final-driver01';out.mkdir(exist_ok=False)
EW=L/'dotnet-ga-wsl-source01';SW=L/'dotnet-ga-samples-wsl-source01'
win='D:/Cephalon/.tools/dotnet11-ga/win-x64/dotnet.exe';linux='/mnt/d/Cephalon/.tools/dotnet11-ga/linux-x64/dotnet'
def unix(p):return '/mnt/d/'+Path(p).as_posix().removeprefix('D:/')
report={'status':'started','scope':'Serial GA functional regression only; no original benchmark recapture','runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'phases':[]}
(out/'runner.py.txt').write_bytes(Path(__file__).read_bytes())
def save():(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
def run(cmd,name,cwd=E,input=None):
 r=subprocess.run(list(map(str,cmd)),cwd=cwd,input=input,capture_output=True);(out/(name+'.stdout.txt')).write_bytes(r.stdout);(out/(name+'.stderr.txt')).write_bytes(r.stderr)
 report['phases'].append({'name':name,'exit':r.returncode});save()
 if r.returncode:raise RuntimeError('Failed '+name+'; raw retained')
 return r.stdout
def wsl(cwd,args,name,input=None):return run(['wsl','--cd',unix(cwd),*args],name,input=input)
def platform(root,host):
 target=root/'.local'/('dotnet-ga-platform-'+host+'01');target.mkdir(exist_ok=False);art=target/'artifacts';sources={}
 for rel in ['global.json','NuGet.Config','Directory.Packages.props','Tests/PlatformQualification/Program.cs','Tests/PlatformQualification/PlatformQualification.csproj','Tests/PlatformQualification/packages.lock.json']:
  f=root/rel;data=f.read_bytes();sources[rel]=hashlib.sha256(data).hexdigest();p=target/'frozen'/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 m={'status':'frozen','engine_revision':'b68d8e8705a48ea9a815b72126b05deedf2351b9','source_sha256':sources,'scope':'GA SDK/runtime/package smoke; PostgreSQL/RabbitMQ not selected in this no-server lane'}
 def savep():(target/'manifest.json').write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
 savep();path=lambda p:str(p) if host=='windows' else unix(p);dot=win if host=='windows' else linux
 def sdk(args,n):
  cmd=[dot,*args];data=run(cmd,'platform-'+host+'-'+n,cwd=root) if host=='windows' else wsl(root,cmd,'platform-'+host+'-'+n)
  (target/(n+'.txt')).write_bytes(data);return data
 try:
  m['sdk']=sdk(['--version'],'sdk').decode().strip();assert m['sdk']=='11.0.100'
  sdk(['--info'],'sdk-info');sdk(['--list-runtimes'],'runtimes')
  sdk(['restore','Tests/PlatformQualification/PlatformQualification.csproj','--locked-mode','--configfile',path(root/'NuGet.Config'),'--artifacts-path',path(art)],'restore')
  sdk(['build','Tests/PlatformQualification/PlatformQualification.csproj','--no-restore','-c','Release','--artifacts-path',path(art),'-p:UseSharedCompilation=false','-warnaserror'],'build')
  sdk([path(art/'bin/PlatformQualification/release/PlatformQualification.dll'),'--output='+path(target/'result.json')],'run')
  result=json.loads((target/'result.json').read_bytes());assert result['failed']==0;m.update(status='passed',result=result)
 except Exception as ex:m.update(status='failed',error=str(ex));savep();raise
 savep()
try:
 for f in [L/'dotnet-ga-windows-final01/manifest.json',EW/'.local/dotnet-ga-wsl-final01/manifest.json']:
  m=json.loads(f.read_bytes());assert m['status']=='passed' and m['sdk']=='11.0.100'
 platform(E,'windows');platform(EW,'wsl')
 assert run(['git','rev-parse','HEAD'],'samples-revision',cwd=S).decode().strip()=='66db9282a2273c941d50c608bb0d1334167ae6eb'
 assert not run(['git','status','--porcelain'],'samples-state',cwd=S).strip()
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','outbox'),('verify_small_api.py','small-api')]:
  cmd=['python','-B','tools/'+tool,'--dotnet',win,'--engine-root',str(E),'--output','.local/dotnet-ga-'+name+'-windows-final01']
  if name=='outbox':cmd+=['--connection-file',str(S/'.local/private-pg18-windows-connection.env'),'--fixture-info',str(S/'.local/postgres18-fixture.json')]
  run(cmd,'windows-'+name,cwd=S)
 wsl(L,['git','clone','--depth','1','--no-checkout','--single-branch','--branch','features/dotnet-ga-consumer','file:///mnt/d/Cephalon/Cehpalon-Engine-Samples',unix(SW)],'samples-wsl-clone')
 patterns=b'/*\n!/*/\n/tools/\n/security-api/\n/audit-outbox/\n/small-api/\n!/security-api/evidence/\n!/audit-outbox/evidence/\n!/small-api/evidence/\n'
 wsl(SW,['git','sparse-checkout','set','--no-cone','--stdin'],'samples-wsl-sparse',input=patterns)
 wsl(SW,['git','checkout','--detach','66db9282a2273c941d50c608bb0d1334167ae6eb'],'samples-wsl-detach')
 assert not wsl(SW,['git','status','--porcelain'],'samples-wsl-state').strip()
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','outbox'),('verify_small_api.py','small-api')]:
  cmd=['python3','-B','tools/'+tool,'--dotnet',linux,'--engine-root',unix(EW),'--output','.local/dotnet-ga-'+name+'-wsl-final01']
  if name=='outbox':cmd+=['--connection-file',unix(S/'.local/private-pg18-connection.env'),'--fixture-info',unix(S/'.local/postgres18-fixture.json')]
  wsl(SW,cmd,'wsl-'+name)
 report['status']='passed'
except Exception as ex:report.update(status='failed',error=str(ex));save();raise
save();print(json.dumps({'status':report['status'],'phases':len(report['phases'])}))
