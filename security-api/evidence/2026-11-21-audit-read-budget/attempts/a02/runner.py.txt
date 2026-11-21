"""Root-only six serial committed-source lanes; no original timed benchmark."""
from pathlib import Path
import argparse, hashlib, json, subprocess
p=argparse.ArgumentParser()
p.add_argument('--engine-revision',required=True);p.add_argument('--consumer-revision',required=True);a=p.parse_args()
B=Path('D:/Cephalon');E=B/'.worktrees/arb-integration';EW=E/'.local/arb-wsl-source01';S=B/'.worktrees/arb-consumer';SW=B/'.worktrees/arb-wsl-consumer';O=E/'.local/arb-final-driver01';O.mkdir(exist_ok=False)
def unix(path):return '/mnt/d/'+Path(path).as_posix().removeprefix('D:/')
WIN='D:/Cephalon/.tools/dotnet11-ga/win-x64/dotnet.exe';LIN='/mnt/d/Cephalon/.tools/dotnet11-ga/linux-x64/dotnet'
r={'status':'started','engine_revision':a.engine_revision,'consumer_revision':a.consumer_revision,'scope':'Six serial exact committed audit read budget component/security/PostgreSQL lanes; no original timed benchmark','runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'phases':[]};(O/'runner.py.txt').write_bytes(Path(__file__).read_bytes())
def save():(O/'manifest.json').write_bytes((json.dumps(r,indent=2)+'\n').encode())
def run(cmd,name,cwd=E,input=None):
 q=subprocess.run(list(map(str,cmd)),cwd=cwd,input=input,capture_output=True);(O/(name+'.stdout.txt')).write_bytes(q.stdout);(O/(name+'.stderr.txt')).write_bytes(q.stderr);r['phases'].append({'name':name,'exit':q.returncode});save()
 if q.returncode:raise RuntimeError('Failed '+name+'; raw retained')
 return q.stdout
def wsl(cwd,cmd,name,input=None):return run(['wsl','--cd',unix(cwd),*cmd],name,input=input)
save()
try:
 for sha in [a.engine_revision,a.consumer_revision]:assert len(sha)==40 and all(c in '0123456789abcdef' for c in sha)
 for root,sha,name in [(E,a.engine_revision,'engine'),(S,a.consumer_revision,'consumer')]:
  assert run(['git','rev-parse','HEAD'],name+'-head',cwd=root).decode().strip()==sha;assert not run(['git','status','--porcelain'],name+'-state',cwd=root).strip()
 assert wsl(EW,['git','rev-parse','HEAD'],'wsl-engine-head').decode().strip()==a.engine_revision
 assert not wsl(EW,['git','status','--porcelain'],'wsl-engine-state').strip()
 for root,base in [(E,'d0d49c7eb47ae8fedc23743dfe76b359b677d796'),(S,'d3397bef35af335ecc74d174d9746be88b9a4982')]:
  for name in subprocess.check_output(['git','diff','--name-only',base,'HEAD'],cwd=root).decode().splitlines():assert subprocess.check_output(['git','show','HEAD:'+name],cwd=root)==(root/name).read_bytes(),name
 run(['python','-B','tools/verify_w1.py','--dotnet',WIN,'--output','.local/arb-windows-final01'],'components-windows')
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','postgres')]:
  cmd=['python','-B','tools/'+tool,'--dotnet',WIN,'--engine-root',str(E),'--output','.local/arb-'+name+'-windows-final01']
  if name=='postgres':cmd+=['--connection-file',str(S/'.local/private-pg18-windows-connection.env'),'--fixture-info',str(S/'.local/postgres18-fixture.json')]
  run(cmd,name+'-windows',cwd=S)
 wsl(EW,['python3','-B','tools/verify_w1.py','--dotnet',LIN,'--output','.local/arb-wsl-final01'],'components-wsl')
 assert not SW.exists();SW.mkdir();wsl(SW,['git','init','--quiet'],'wsl-consumer-init')
 alt=SW/'.git/objects/info/alternates';alt.parent.mkdir(parents=True,exist_ok=True);alt.write_bytes(b'/mnt/d/Cephalon/Cehpalon-Engine-Samples/.git/objects\n')
 (O/'wsl-borrowed-source.json').write_bytes((json.dumps({'consumer_revision':a.consumer_revision,'source':str(SW),'alternates':alt.read_text().strip(),'policy':'Read-only borrowed primary objects; retain all source/raw/worktrees, not independent archive','outside_engine_parent_policy':True},indent=2)+'\n').encode())
 wsl(SW,['git','config','core.autocrlf','false'],'wsl-source-eol');wsl(SW,['git','update-ref','refs/heads/features/audit-read-budget-source',a.consumer_revision],'wsl-source-ref');wsl(SW,['git','symbolic-ref','HEAD','refs/heads/features/audit-read-budget-source'],'wsl-source-head')
 patterns=b'/*\n!/*/\n/tools/\n/security-api/\n/audit-outbox/\n!/security-api/evidence/\n!/audit-outbox/evidence/\n'
 wsl(SW,['git','sparse-checkout','set','--no-cone','--stdin'],'wsl-source-sparse',input=patterns);wsl(SW,['git','checkout','--detach',a.consumer_revision],'wsl-source-detach');assert not wsl(SW,['git','status','--porcelain'],'wsl-source-state').strip()
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','postgres')]:
  cmd=['python3','-B','tools/'+tool,'--dotnet',LIN,'--engine-root',unix(EW),'--output','.local/arb-'+name+'-wsl-final01']
  if name=='postgres':cmd+=['--connection-file',unix(S/'.local/private-pg18-connection.env'),'--fixture-info',unix(S/'.local/postgres18-fixture.json')]
  wsl(SW,cmd,name+'-wsl')
 r['status']='passed'
except Exception as error:r.update(status='failed',error=str(error));save();raise
save();print(json.dumps({'status':r['status'],'phases':len(r['phases'])}))
