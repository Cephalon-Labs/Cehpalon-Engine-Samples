from pathlib import Path
import hashlib,json,subprocess,time
E=Path('D:/Cephalon/.worktrees/ga-integration');S=Path('D:/Cephalon/.worktrees/ga-scaffold');O=S/'driver02';O.mkdir(exist_ok=False)
r={'status':'waiting_serial_predecessor','scope':'Original scaffold functional harness on separately declared GA inputs; no benchmark','phases':[],'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
def save():(O/'manifest.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
(O/'runner.py.txt').write_bytes(Path(__file__).read_bytes());save()
try:
 deadline=time.monotonic()+900
 while True:
  m=json.loads((E/'.local/dotnet-ga-final-driver02/manifest.json').read_bytes())
  if m['status']=='passed':break
  if m['status']=='failed':raise RuntimeError('Serial predecessor failed; scaffold not executed')
  if time.monotonic()>deadline:raise RuntimeError('Serial predecessor wait expired; scaffold not executed')
  time.sleep(1)
 f=json.loads((S/'inputs-frozen-before-sdk.json').read_bytes())
 for name,digest in f['copied_bytes_sha256'].items():assert hashlib.sha256((S/name).read_bytes()).hexdigest()==digest,name
 assert hashlib.sha256((S/'tooling-small-api/engine-lock.json').read_bytes()).hexdigest()==f['new_lock_sha256']
 r['status']='started';save()
 for host in ['windows','wsl']:
  args=['tools/verify_tooling_small_api.py','--dotnet','D:/Cephalon/.tools/dotnet11-ga/win-x64/dotnet.exe' if host=='windows' else '/mnt/d/Cephalon/.tools/dotnet11-ga/linux-x64/dotnet','--engine-root',str(E) if host=='windows' else '/mnt/d/Cephalon/.worktrees/ga-integration/.local/dotnet-ga-wsl-source01','--engine-revision','b68d8e8705a48ea9a815b72126b05deedf2351b9','--output','.local/ga-'+host+'01']
  cmd=['python','-B',*args] if host=='windows' else ['wsl','--cd','/mnt/d/Cephalon/.worktrees/ga-scaffold','python3','-B',*args]
  p=subprocess.run(cmd,cwd=S,capture_output=True);(O/(host+'.stdout.txt')).write_bytes(p.stdout);(O/(host+'.stderr.txt')).write_bytes(p.stderr);r['phases'].append({'host':host,'exit':p.returncode});save()
  if p.returncode:raise RuntimeError('Failed scaffold '+host+'; raw retained')
 r['status']='passed'
except Exception as ex:r.update(status='failed',error=str(ex));save();raise
save();print(json.dumps({'status':r['status']}))
