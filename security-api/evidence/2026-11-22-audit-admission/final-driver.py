"""Root's serial changed-consumer verification; unchanged Engine baseline is not rerun."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--consumer-revision',required=True);a=p.parse_args()
E=Path('D:/Cephalon/.worktrees/arh-engine');EW=E/'.local/arh-wsl-source01';S=Path('D:/Cephalon/.worktrees/ara-consumer');SW=Path('D:/Cephalon/.worktrees/ara-wsl-consumer');O=E/'.local/ara-final-driver01';O.mkdir(exist_ok=False)
def unix(path):return '/mnt/d/'+Path(path).as_posix().removeprefix('D:/')
WIN='D:/Cephalon/.tools/dotnet11-ga/win-x64/dotnet.exe';LIN='/mnt/d/Cephalon/.tools/dotnet11-ga/linux-x64/dotnet'
r={'status':'started','engine_revision':'5184517a92a087abe4e0091d256142b6c35a2b39','consumer_revision':a.consumer_revision,'scope':'Changed optional shared audit-read admission consumer four serial lanes only; no repeated W1, new Engine code/CI or timed benchmark','runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'phases':[]};(O/'runner.py.txt').write_bytes(Path(__file__).read_bytes())
def save():(O/'manifest.json').write_bytes((json.dumps(r,indent=2)+'\n').encode())
def run(cmd,name,cwd=E,input=None):
 q=subprocess.run(list(map(str,cmd)),cwd=cwd,input=input,capture_output=True);(O/(name+'.stdout.txt')).write_bytes(q.stdout);(O/(name+'.stderr.txt')).write_bytes(q.stderr);r['phases'].append({'name':name,'exit':q.returncode});save()
 if q.returncode:raise RuntimeError('Failed '+name+'; all raw retained')
 return q.stdout
def wsl(cwd,cmd,name,input=None):return run(['wsl','--cd',unix(cwd),*cmd],name,input=input)
save()
try:
 assert len(a.consumer_revision)==40 and all(c in '0123456789abcdef' for c in a.consumer_revision)
 assert run(['git','rev-parse','HEAD'],'engine-head').decode().strip()==r['engine_revision'];assert not run(['git','status','--porcelain'],'engine-state').strip()
 assert run(['git','rev-parse','HEAD'],'consumer-head',cwd=S).decode().strip()==a.consumer_revision;assert not run(['git','status','--porcelain'],'consumer-state',cwd=S).strip()
 for name in subprocess.check_output(['git','diff','--name-only','05f119e75bcc2458bee9c610e4ba64f04d4dc6d0','HEAD'],cwd=S).decode().splitlines():assert subprocess.check_output(['git','show','HEAD:'+name],cwd=S)==(S/name).read_bytes(),name
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','postgres')]:
  cmd=['python','-B','tools/'+tool,'--dotnet',WIN,'--engine-root',str(E),'--output','.local/ara-'+name+'-windows-final01']
  if name=='postgres':cmd+=['--connection-file',str(S/'.local/private-pg18-windows-connection.env'),'--fixture-info',str(S/'.local/postgres18-fixture.json')]
  if name=='postgres':
   original=S/'.local/audit-read-admission-windows-dev01';manifest=original/'manifest.json';m=json.loads(manifest.read_bytes())
   assert m['status']=='passed' and m['total_passed']==332 and m['consumer_revision']==a.consumer_revision and m['engine_revision']==r['engine_revision'] and not m['engine_dirty'] and not m['consumer_source_dirty']
   for key,digest in m['source_sha256'].items():
    prefix,relative=key.split('/',1);base=E if prefix=='engine' else S
    assert hashlib.sha256((base/relative).read_bytes()).hexdigest()==digest,key
    assert hashlib.sha256((original/'frozen-source'/key).read_bytes()).hexdigest()==digest,key
   proof={'status':'passed','actual_execution':str(original),'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'same_committed_source':True,'additional_sdk_execution':False,'declaration':'audit-read-admission-declaration02','unique_functional_executions_including_original':4}
   (O/'postgres-windows-reuse.json').write_bytes((json.dumps(proof,indent=2)+'\n').encode());r['phases'].append({'name':'postgres-windows-reused-original-committed-execution','exit':0});r['windows_provider_reused_execution']=proof;save()
  else:run(cmd,name+'-windows',cwd=S)
 assert not SW.exists();SW.mkdir();wsl(SW,['git','init','--quiet'],'wsl-consumer-init')
 alt=SW/'.git/objects/info/alternates';alt.parent.mkdir(parents=True,exist_ok=True);alt.write_bytes(b'/mnt/d/Cephalon/Cehpalon-Engine-Samples/.git/objects\n')
 (O/'wsl-borrowed-source.json').write_bytes((json.dumps({'consumer_revision':a.consumer_revision,'source':str(SW),'alternates':alt.read_text().strip(),'policy':'Read-only borrowed primary objects, not independent archive; retain primary store/worktrees/raw','outside_engine_parent_policy':True},indent=2)+'\n').encode())
 wsl(SW,['git','config','core.autocrlf','false'],'wsl-source-eol');wsl(SW,['git','update-ref','refs/heads/features/audit-read-admission-source',a.consumer_revision],'wsl-source-ref');wsl(SW,['git','symbolic-ref','HEAD','refs/heads/features/audit-read-admission-source'],'wsl-source-head')
 patterns=b'/*\n!/*/\n/tools/\n/security-api/\n/audit-outbox/\n!/security-api/evidence/\n!/audit-outbox/evidence/\n'
 wsl(SW,['git','sparse-checkout','set','--no-cone','--stdin'],'wsl-source-sparse',input=patterns);wsl(SW,['git','checkout','--detach',a.consumer_revision],'wsl-source-detach');assert not wsl(SW,['git','status','--porcelain'],'wsl-source-state').strip()
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','postgres')]:
  cmd=['python3','-B','tools/'+tool,'--dotnet',LIN,'--engine-root',unix(EW),'--output','.local/ara-'+name+'-wsl-final01']
  if name=='postgres':cmd+=['--connection-file',unix(S/'.local/private-pg18-connection.env'),'--fixture-info',unix(S/'.local/postgres18-fixture.json')]
  wsl(SW,cmd,name+'-wsl')
 r['status']='passed'
except Exception as error:r.update(status='failed',error=str(error));save();raise
save();print(json.dumps({'status':r['status'],'phases':len(r['phases'])}))
