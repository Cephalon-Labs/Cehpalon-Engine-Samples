from pathlib import Path
import json,subprocess,hashlib
D=Path.cwd();root=Path('D:/Cephalon/.worktrees/ara-consumer/.local');out=root/'pg-reactivation-setup03.json';assert not out.exists()
old=D/'.local/recover-audit-read-admission-fixture.py';(root/'pg-reactivation-recovery02.py.txt').write_bytes(old.read_bytes())
failure={'status':'failed','stage':'preparation_controller_cleanup_acknowledgment','command_exit':1,'observation':'Stop-Process could not find enumerated child720152 after parent688780 was stopped; initial controller and child subsequently verified absent. Fixture/helpers remain live.','source_sha256':hashlib.sha256(old.read_bytes()).hexdigest(),'no_sdk_executed':True,'raw_error':'Stop-Process : Cannot find a process with the process identifier 720152. CalledProcessError exit1.'}
(root/'pg-reactivation-setup02-failure.json').write_bytes((json.dumps(failure,indent=2)+'\n').encode())
def run(args):return subprocess.check_output(args).decode().strip()
fixture=json.loads((root/'postgres18-fixture.json').read_bytes());fmt='{"id":"{{.Id}}","image":"{{.Image}}","name":"{{.Name}}","running":{{.State.Running}},"mounts":{{json .Mounts}}}'
x=json.loads(run(['wsl','-d','Ubuntu','--','docker','inspect',fixture['container_id'],'--format',fmt]));assert x['id']==fixture['container_id'] and x['image']==fixture['image_id'] and x['name']=='/'+fixture['container_name'] and x['running']
assert any(m.get('Type')=='volume' and m.get('Name')==fixture['volume'] for m in x['mounts'])
proxy=json.loads((root/'pg-proxy-owned-process.json').read_bytes());port=int(proxy['bind'].rsplit(':',1)[1]);assert proxy['bind'].startswith('127.0.0.1:') and 0<port<65536
ps=['powershell','-NoProfile','-Command'];cmd=run(ps+[f"(Get-CimInstance Win32_Process -Filter 'ProcessId = {int(proxy['pid'])}').CommandLine"]);assert 'ara-consumer/.local/pg-loopback-proxy.py' in cmd.replace('\\','/')
anchor=json.loads((root/'pg-wsl-anchor-owned-process.json').read_bytes());assert '/ara-consumer/.local/pg-wsl-anchor.py' in run(['wsl','-d','Ubuntu','--','ps','-p',str(int(anchor['pid'])),'-o','args='])
assert run(ps+[f"@([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object Port -eq {port}).Count"])=='1'
assert run(ps+["@(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -like '*setup-audit-read-admission-fixture.py*' }).Count"])=='0'
assert (root/'private-pg18-windows-connection.env').is_file()
receipt={'status':'passed','scope':'Read-only readiness after retained controller acknowledgment failures; no second container/proxy/anchor launch','exact_fixture_identity_verified':True,'owned_helper_identity_verified':True,'native_listener_count':1,'windows_proxy_port':port,'initial_controller_absent':True,'sdk_executed':False,'fixture_restarted':False,'helpers_relaunched':False,'private_values_printed':False,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
out.write_bytes((json.dumps(receipt,indent=2)+'\n').encode());print(json.dumps({'status':'passed','native_listener_count':1,'initial_controller_absent':True,'fixture_relaunch':False}))
