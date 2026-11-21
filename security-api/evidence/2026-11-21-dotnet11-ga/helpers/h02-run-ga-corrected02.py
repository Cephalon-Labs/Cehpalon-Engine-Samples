from pathlib import Path
import json,subprocess
E=Path('D:/Cephalon/.worktrees/ga-integration');L=E/'.local';S=Path('D:/Cephalon/.worktrees/ga-consumer');SW=Path('D:/Cephalon/.worktrees/ga-wsl-consumer');old=L/'dotnet-ga-samples-wsl-source01';out=L/'dotnet-ga-final-driver02';out.mkdir(exist_ok=False)
def unix(p):return '/mnt/d/'+Path(p).as_posix().removeprefix('D:/')
r={'status':'started','reason':'Fix inherited parent central package policy by moving actual consumer source checkout outside Engine; same committed bytes/strict locks/flags','engine_revision':'b68d8e8705a48ea9a815b72126b05deedf2351b9','consumer_revision':'66db9282a2273c941d50c608bb0d1334167ae6eb','phases':[]}
(out/'runner.py.txt').write_bytes(Path(__file__).read_bytes())
def save():(out/'manifest.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
def wsl(cwd,args,name,input=None):
 p=subprocess.run(['wsl','--cd',unix(cwd),*map(str,args)],input=input,capture_output=True);(out/(name+'.stdout.txt')).write_bytes(p.stdout);(out/(name+'.stderr.txt')).write_bytes(p.stderr);r['phases'].append({'name':name,'exit':p.returncode});save()
 if p.returncode:raise RuntimeError('Failed '+name+'; raw retained')
 return p.stdout
save()
try:
 assert json.loads((L/'dotnet-ga-final-driver01/manifest.json').read_bytes())['status']=='failed'
 assert not SW.exists()
 wsl(SW.parent,['git','clone','--shared','--no-checkout','--single-branch','--branch','features/dotnet-ga-consumer',unix(old),unix(SW)],'clone')
 patterns=b'/*\n!/*/\n/tools/\n/security-api/\n/audit-outbox/\n/small-api/\n!/security-api/evidence/\n!/audit-outbox/evidence/\n!/small-api/evidence/\n'
 wsl(SW,['git','sparse-checkout','set','--no-cone','--stdin'],'sparse',input=patterns)
 wsl(SW,['git','checkout','--detach',r['consumer_revision']],'checkout')
 assert not wsl(SW,['git','status','--porcelain'],'state').strip()
 assert wsl(SW,['git','rev-parse','HEAD'],'head').decode().strip()==r['consumer_revision']
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','outbox'),('verify_small_api.py','small-api')]:
  cmd=['python3','-B','tools/'+tool,'--dotnet','/mnt/d/Cephalon/.tools/dotnet11-ga/linux-x64/dotnet','--engine-root',unix(L/'dotnet-ga-wsl-source01'),'--output','.local/dotnet-ga-'+name+'-wsl-final02']
  if name=='outbox':cmd+=['--connection-file',unix(S/'.local/private-pg18-connection.env'),'--fixture-info',unix(S/'.local/postgres18-fixture.json')]
  wsl(SW,cmd,name)
 r['status']='passed'
except Exception as ex:r.update(status='failed',error=str(ex));save();raise
save();print(json.dumps({'status':r['status']}))
