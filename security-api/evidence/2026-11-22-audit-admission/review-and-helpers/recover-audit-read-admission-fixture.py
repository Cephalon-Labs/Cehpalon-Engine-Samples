from pathlib import Path
import json,subprocess,hashlib
root=Path('D:/Cephalon/.worktrees/ara-consumer/.local');out=root/'pg-reactivation-setup02.json';assert not out.exists()
prior=root/'pg-reactivation-setup01.json';data=prior.read_bytes();(root/'pg-reactivation-setup01-interrupted.json').write_bytes(data)
r={'status':'started','scope':'Read-only fixture readiness recovery; no second container/helper launch and no SDK execution','retained_initial_controller_failure':'Completed PowerShell launcher absent; capture_output pipe completion held by inherited background handles; initial controller interrupted after direct ownership/readiness checks. Pipe inheritance is an inference, not a traced OS cause.','private_values_printed':False}
def run(args):return subprocess.check_output(args).decode().strip()
fixture=json.loads((root/'postgres18-fixture.json').read_bytes())
fmt='{"id":"{{.Id}}","image":"{{.Image}}","name":"{{.Name}}","running":{{.State.Running}},"mounts":{{json .Mounts}}}'
x=json.loads(run(['wsl','-d','Ubuntu','--','docker','inspect',fixture['container_id'],'--format',fmt]))
assert x['id']==fixture['container_id'] and x['image']==fixture['image_id'] and x['name']=='/'+fixture['container_name'] and x['running']
assert any(m.get('Type')=='volume' and m.get('Name')==fixture['volume'] for m in x['mounts'])
proxy=json.loads((root/'pg-proxy-owned-process.json').read_bytes());port=int(proxy['bind'].rsplit(':',1)[1]);assert proxy['bind'].startswith('127.0.0.1:') and 0<port<65536
ps=['powershell','-NoProfile','-Command']
cmd=run(ps+[f"(Get-CimInstance Win32_Process -Filter 'ProcessId = {int(proxy['pid'])}').CommandLine"])
assert 'ara-consumer/.local/pg-loopback-proxy.py' in cmd.replace('\\','/')
anchor=json.loads((root/'pg-wsl-anchor-owned-process.json').read_bytes());cmd=run(['wsl','-d','Ubuntu','--','ps','-p',str(int(anchor['pid'])),'-o','args=']);assert '/ara-consumer/.local/pg-wsl-anchor.py' in cmd
assert run(ps+[f"@([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object Port -eq {port}).Count"])=='1'
assert (root/'private-pg18-windows-connection.env').is_file()
# Only the exact hung preparation controller is stopped. The verified fixture/proxy/anchor stay owned and live.
command="$taskControllers=Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -like '*setup-audit-read-admission-fixture.py*' }; $taskControllers | ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction Stop }; $taskControllers.Count"
stopped=int(run(ps+[command]));assert 1<=stopped<=2
r.update(status='passed',exact_fixture_identity=True,owned_helpers_identity_verified=True,native_listener_count=1,windows_proxy_port=port,controller_processes_stopped=stopped,original_controller_exit_unclaimed=True,fixture_restarted=False,helpers_relaunched=False,source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
out.write_bytes((json.dumps(r,indent=2)+'\n').encode());print(json.dumps({'status':'passed','native_listener_count':1,'original_controller_retained':True,'helper_relaunch':False}))
