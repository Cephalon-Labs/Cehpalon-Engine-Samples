"""Frozen serial final regressions; root launches only after child releases SDK."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--consumer-revision',required=True);a=p.parse_args()
E=Path('D:/Cephalon/.worktrees/rb-integration');EW=E/'.local/rb-wsl-source01';S=Path('D:/Cephalon/.worktrees/rb-consumer');SW=Path('D:/Cephalon/.worktrees/rb-wsl-consumer');O=E/'.local/rb-final-driver01';O.mkdir(exist_ok=False)
def unix(p):return '/mnt/d/'+Path(p).as_posix().removeprefix('D:/')
WIN='D:/Cephalon/.tools/dotnet11-ga/win-x64/dotnet.exe';LIN='/mnt/d/Cephalon/.tools/dotnet11-ga/linux-x64/dotnet'
r={'status':'started','engine_revision':'3eb2b0eb957304bae24a1ef749160b8dd159772f','consumer_revision':a.consumer_revision,'scope':'Serial exact committed GA functional regressions only; original benchmark not run','runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'phases':[]};(O/'runner.py.txt').write_bytes(Path(__file__).read_bytes())
def save():(O/'manifest.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
def run(cmd,name,cwd=E,input=None):
 q=subprocess.run(list(map(str,cmd)),cwd=cwd,input=input,capture_output=True);(O/(name+'.stdout.txt')).write_bytes(q.stdout);(O/(name+'.stderr.txt')).write_bytes(q.stderr);r['phases'].append({'name':name,'exit':q.returncode});save()
 if q.returncode:raise RuntimeError('Failed '+name+'; raw retained')
 return q.stdout
def wsl(cwd,cmd,name,input=None):return run(['wsl','--cd',unix(cwd),*cmd],name,input=input)
save()
try:
 assert len(a.consumer_revision)==40 and all(c in '0123456789abcdef' for c in a.consumer_revision)
 assert run(['git','rev-parse','HEAD'],'engine-head').decode().strip()==r['engine_revision'];assert not run(['git','status','--porcelain'],'engine-state').strip()
 assert run(['git','rev-parse','HEAD'],'consumer-head',cwd=S).decode().strip()==a.consumer_revision;assert not run(['git','status','--porcelain'],'consumer-state',cwd=S).strip()
 for name in ['audit-outbox/Program.cs','audit-outbox/RelayBudgetChecks.cs','tools/verify_audit_outbox.py','audit-outbox/README.md']:
  assert subprocess.check_output(['git','show','HEAD:'+name],cwd=S)==(S/name).read_bytes(),name
 run(['python','-B','tools/verify_w1.py','--dotnet',WIN,'--output','.local/rb-windows-final01'],'components-windows')
 wsl(EW,['python3','-B','tools/verify_w1.py','--dotnet',LIN,'--output','.local/rb-wsl-final01'],'components-wsl')
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','postgres')]:
  cmd=['python','-B','tools/'+tool,'--dotnet',WIN,'--engine-root',str(E),'--output','.local/rb-'+name+'-windows-final01']
  if name=='postgres':cmd+=['--connection-file',str(S/'.local/private-pg18-windows-connection.env'),'--fixture-info',str(S/'.local/postgres18-fixture.json')]
  run(cmd,name+'-windows',cwd=S)
 assert not SW.exists();SW.mkdir()
 wsl(SW,['git','init','--quiet'],'wsl-consumer-init')
 alt=SW/'.git/objects/info/alternates';alt.parent.mkdir(parents=True,exist_ok=True);alt.write_text('/mnt/d/Cephalon/Cehpalon-Engine-Samples/.git/objects\n',encoding='utf-8')
 (O/'wsl-borrowed-source.json').write_text(json.dumps({'consumer_revision':a.consumer_revision,'source':str(SW),'alternates':alt.read_text().strip(),'policy':'Read-only borrowed primary objects, not an independent archive; retain primary store and all commits','outside_engine_parent_policy':True},indent=2)+'\n',encoding='utf-8')
 wsl(SW,['git','config','core.autocrlf','false'],'wsl-source-eol')
 wsl(SW,['git','update-ref','refs/heads/features/relay-budget-source',a.consumer_revision],'wsl-source-ref')
 wsl(SW,['git','symbolic-ref','HEAD','refs/heads/features/relay-budget-source'],'wsl-source-head')
 patterns=b'/*\n!/*/\n/tools/\n/security-api/\n/audit-outbox/\n!/security-api/evidence/\n!/audit-outbox/evidence/\n'
 wsl(SW,['git','sparse-checkout','set','--no-cone','--stdin'],'wsl-source-sparse',input=patterns)
 wsl(SW,['git','checkout','--detach',a.consumer_revision],'wsl-source-detach')
 assert not wsl(SW,['git','status','--porcelain'],'wsl-source-state').strip()
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','postgres')]:
  cmd=['python3','-B','tools/'+tool,'--dotnet',LIN,'--engine-root',unix(EW),'--output','.local/rb-'+name+'-wsl-final01']
  if name=='postgres':cmd+=['--connection-file',unix(S/'.local/private-pg18-connection.env'),'--fixture-info',unix(S/'.local/postgres18-fixture.json')]
  wsl(SW,cmd,name+'-wsl')
 r['status']='passed'
except Exception as ex:r.update(status='failed',error=str(ex));save();raise
save();print(json.dumps({'status':r['status'],'phases':len(r['phases'])}))
