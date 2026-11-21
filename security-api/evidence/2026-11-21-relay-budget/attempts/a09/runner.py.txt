from pathlib import Path
import hashlib,json,subprocess
E=Path('D:/Cephalon/.worktrees/rb-integration');EW=E/'.local/rb-wsl-source01';S=Path('D:/Cephalon/.worktrees/rb-consumer');SW=Path('D:/Cephalon/.worktrees/rb-wsl-consumer');O=E/'.local/rb-final-driver02';O.mkdir(exist_ok=False)
r={'status':'started','reason':'Linux Git alternates requires LF; correct Windows CRLF controlfile before first WSL consumer execution','engine_revision':'3eb2b0eb957304bae24a1ef749160b8dd159772f','consumer_revision':'e95d1c281662701daacd7dea11257db4f450cd25','prior_driver_failed_before_wsl_consumers':True,'phases':[]};(O/'runner.py.txt').write_bytes(Path(__file__).read_bytes())
def unix(p):return '/mnt/d/'+Path(p).as_posix().removeprefix('D:/')
def save():(O/'manifest.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
def wsl(cmd,name,input=None):
 p=subprocess.run(['wsl','--cd',unix(SW),*map(str,cmd)],input=input,capture_output=True);(O/(name+'.stdout.txt')).write_bytes(p.stdout);(O/(name+'.stderr.txt')).write_bytes(p.stderr);r['phases'].append({'name':name,'exit':p.returncode});save()
 if p.returncode:raise RuntimeError('Failed '+name+'; raw retained')
 return p.stdout
save()
try:
 prior=json.loads((E/'.local/rb-final-driver01/manifest.json').read_bytes());assert prior['status']=='failed' and prior['phases'][-1]=={'name':'wsl-source-ref','exit':128}
 expected=['/mnt/d/Cephalon/Cehpalon-Engine-Samples/.git/objects']
 alt=SW/'.git/objects/info/alternates';before=alt.read_bytes();assert before==(expected[0]+'\r\n').encode();(O/'alternates-before.txt').write_bytes(before)
 alt.write_bytes((expected[0]+'\n').encode());(O/'alternates-after.txt').write_bytes(alt.read_bytes());r['control_file_only_crlf_to_lf']=True;save()
 assert wsl(['git','cat-file','-t',r['consumer_revision']],'object-type').decode().strip()=='commit'
 wsl(['git','update-ref','refs/heads/features/relay-budget-source',r['consumer_revision']],'source-ref')
 wsl(['git','symbolic-ref','HEAD','refs/heads/features/relay-budget-source'],'source-head')
 patterns=b'/*\n!/*/\n/tools/\n/security-api/\n/audit-outbox/\n!/security-api/evidence/\n!/audit-outbox/evidence/\n'
 wsl(['git','sparse-checkout','set','--no-cone','--stdin'],'source-sparse',input=patterns)
 wsl(['git','checkout','--detach',r['consumer_revision']],'source-detach');assert not wsl(['git','status','--porcelain'],'source-state').strip()
 for tool,name in [('verify_optional_security.py','security'),('verify_audit_outbox.py','postgres')]:
  args=['python3','-B','tools/'+tool,'--dotnet','/mnt/d/Cephalon/.tools/dotnet11-ga/linux-x64/dotnet','--engine-root',unix(EW),'--output','.local/rb-'+name+'-wsl-final01']
  if name=='postgres':args+=['--connection-file',unix(S/'.local/private-pg18-connection.env'),'--fixture-info',unix(S/'.local/postgres18-fixture.json')]
  wsl(args,name)
 r['status']='passed'
except Exception as ex:r.update(status='failed',error=str(ex));save();raise
save();print(json.dumps({'status':r['status']}))
