from pathlib import Path
from datetime import datetime,timezone
import json,subprocess
D=Path.cwd();prior=Path('D:/Cephalon/.worktrees/ara-consumer/.local');f=json.loads((prior/'postgres18-fixture.json').read_bytes());c=json.loads((prior/'audit-read-admission-fixture-cleanup.json').read_bytes());port=int(c['windows_proxy_bind'].rsplit(':',1)[1])
assert c['status']=='passed'
fmt='{"id":"{{.Id}}","image":"{{.Image}}","name":"{{.Name}}","running":{{.State.Running}}}'
x=json.loads(subprocess.check_output(['wsl','-d','Ubuntu','--exec','docker','inspect',f['container_id'],'--format',fmt]));assert x['id']==f['container_id'] and x['image']==f['image_id'] and x['name']=='/'+f['container_name'] and not x['running']
query=f"@([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object Port -eq {port}).Count";assert subprocess.check_output(['powershell','-NoProfile','-Command',query]).decode().strip()=='0'
out=D/'internal/evidence/audit-contract-export/offline-fixture-stopped.json';assert not out.exists();data={'status':'passed','observed_at_utc':datetime.now(timezone.utc).isoformat(),'scope':'Before both offline SDK lanes; exact retained owned PostgreSQL stopped and previous Windows proxy port unbound','container_id':f['container_id'],'container_running':False,'previous_proxy_port':port,'native_listener_count':0,'new_helpers_not_started':True,'new_connection_files_not_copied':True,'offline_cli_must_not_require_database_or_secret_arguments':True}
assert not Path('D:/Cephalon/.worktrees/ahx-consumer/.local/private-pg18-connection.env').exists();out.write_bytes((json.dumps(data,indent=2)+'\n').encode());print(json.dumps({'status':'passed','container_running':False,'native_listener_count':0,'connection_files_copied':False}))
