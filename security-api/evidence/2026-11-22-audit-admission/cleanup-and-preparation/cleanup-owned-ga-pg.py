"""Run only after root confirms final owned PostgreSQL consumer runs complete."""
import ctypes,hashlib,json,socket,subprocess,time
from pathlib import Path
root=Path(__file__).resolve().parent
assert root==Path('D:/Cephalon/.worktrees/ara-consumer/.local')
out=root/'audit-read-admission-fixture-cleanup.json';assert not out.exists(),'Never overwrite cleanup evidence'
fixture=json.loads((root/'postgres18-fixture.json').read_bytes());report={'status':'started','cleanup_profile':'audit-read-admission','scope':'Stop only owned fixture/helpers; retain volume, image, schemas and all raw attempts','container_id':fixture['container_id'],'retained_volume':fixture['volume'],'private_config_exported':False}
def save():out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
def run(args):
 r=subprocess.run(args,capture_output=True)
 if r.returncode:raise RuntimeError('Owned cleanup command failed; no arbitrary process fallback')
 return r.stdout.decode().strip()
docker=['wsl','-d','Ubuntu','--','docker'];fmt='{"id":"{{.Id}}","image":"{{.Image}}","name":"{{.Name}}","running":{{.State.Running}},"mounts":{{json .Mounts}}}'
def inspect():return json.loads(run(docker+['inspect',fixture['container_id'],'--format',fmt]))
def guard(observed):
 assert observed['id']==fixture['container_id'] and observed['image']==fixture['image_id'] and observed['name']=='/'+fixture['container_name']
 assert any(m.get('Type')=='volume' and m.get('Name')==fixture['volume'] and m.get('Destination')=='/var/lib/postgresql' for m in observed['mounts'])
try:
 observed=inspect();guard(observed);report['identity_verified']=True;report['running_before']=observed['running'];save()
 # Read only owned process command identity. No command line contents are exported.
 proxy=json.loads((root/'pg-proxy-owned-process.json').read_bytes());proxy_pid=proxy['pid'];assert proxy['bind'].startswith('127.0.0.1:');proxy_port=int(proxy['bind'].rsplit(':',1)[1]);assert 0<proxy_port<65536;report['windows_proxy_bind']=proxy['bind'];assert isinstance(proxy_pid,int) and proxy_pid>0
 ps=['powershell','-NoProfile','-Command',f"$p=Get-CimInstance Win32_Process -Filter 'ProcessId = {proxy_pid}'; if($p){{ $p.CommandLine }}"]
 command=run(ps);assert str(root/'pg-loopback-proxy.py').replace('\\','/') in command.replace('\\','/')
 anchor=json.loads((root/'pg-wsl-anchor-owned-process.json').read_bytes());anchor_pid=anchor['pid'];assert isinstance(anchor_pid,int) and anchor_pid>0
 anchor_command=run(['wsl','-d','Ubuntu','--','ps','-p',str(anchor_pid),'-o','args=']);assert '/mnt/d/Cephalon/.worktrees/ara-consumer/.local/pg-wsl-anchor.py' in anchor_command
 report['owned_helpers_identity_verified']=True;save()
 if observed['running']:run(docker+['stop','--time','10',fixture['container_id']])
 observed=inspect();guard(observed);assert not observed['running'];report['container_stopped']=True;save()
 for name in ['pg-proxy.stop','pg-wsl-anchor.stop']:
  marker=root/name;assert not marker.exists();marker.write_text('Root confirmed final audit read admission consumer runs complete. Stop owned helper only.\n',encoding='utf-8')
 closed=False
 listener_command=['powershell','-NoProfile','-Command',f"[System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object {{ $_.Port -eq {proxy_port} }} | ForEach-Object {{ 'bound' }}"]
 for _ in range(40):
  closed=not run(listener_command)
  if closed:break
  time.sleep(.25)
 assert closed;report['windows_proxy_listener_closed']=True;report['listener_check']='Native IPGlobalProperties.GetActiveTcpListeners; no timed-connect inference';report['native_listener_count_after']=0
 (root/'pg-proxy-native-listener-after.json').write_text(json.dumps({'method':'Native IPGlobalProperties.GetActiveTcpListeners','port':proxy_port,'listener_count':0,'status':'observed-after-cleanup'},indent=2)+'\n',encoding='utf-8')
 for _ in range(40):
  process=run(ps)
  if not process:break
  time.sleep(.25)
 assert not process;report['owned_proxy_exited']=True
 proxy_launcher=json.loads((root/'pg-proxy-windows-process.json').read_bytes())['pid']
 for _ in range(40):
  observed_proxy_launcher=run(['powershell','-NoProfile','-Command',f"if(Get-Process -Id {proxy_launcher} -ErrorAction SilentlyContinue){{'alive'}}"])
  if not observed_proxy_launcher:break
  time.sleep(.25)
 assert not observed_proxy_launcher;report['owned_proxy_launcher_exited']=True
 # Closing the lifetime anchor may stop WSL itself; Windows launcher exit is checked without restarting WSL.
 launcher=json.loads((root/'pg-wsl-anchor-windows-process.json').read_bytes())['pid']
 for _ in range(40):
  observed_anchor=run(['powershell','-NoProfile','-Command',f"if(Get-Process -Id {launcher} -ErrorAction SilentlyContinue){{'alive'}}"])
  if not observed_anchor:break
  time.sleep(.25)
 assert not observed_anchor;report['owned_anchor_launcher_exited']=True
 report['cleanup_source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();report['status']='passed';save();print(json.dumps(report))
except Exception as e:
 report.update(status='failed',error=str(e));save();raise
