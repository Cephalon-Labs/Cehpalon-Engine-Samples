from pathlib import Path
import hashlib,json,subprocess
D=Path.cwd();old=Path('D:/Cephalon/.worktrees/arh-consumer/.local');new=Path('D:/Cephalon/.worktrees/ara-consumer/.local');new.mkdir(exist_ok=True)
out=new/'pg-reactivation-setup01.json';assert not out.exists()
r={'status':'preparing','profile':'audit-read-admission','retained_previous_fixture':True,'private_config_exported':False,'helpers':{}}
def save():out.write_bytes((json.dumps(r,indent=2)+'\n').encode())
save()
try:
    for name in ('start-owned-helpers.ps1','pg-loopback-proxy.py','pg-stdio-bridge.py','pg-wsl-anchor.py','cleanup-owned-ga-pg.py'):
        target=new/name;assert not target.exists()
        text=(old/name).read_text(encoding='utf-8').replace('arh-consumer','ara-consumer').replace('resource-transport','audit-read-admission').replace('resource transport consumer','audit read admission consumer')
        assert 'arh-consumer' not in text;target.write_bytes(text.encode());r['helpers'][name]=hashlib.sha256(target.read_bytes()).hexdigest()
    for name in ('postgres18-fixture.json','private-pg18-connection.env'):
        assert not (new/name).exists();(new/name).write_bytes((old/name).read_bytes())
    fixture=json.loads((new/'postgres18-fixture.json').read_bytes());r['container_id']=fixture['container_id'];r['retained_volume']=fixture['volume']
    docker=['wsl','-d','Ubuntu','--','docker'];fmt='{"id":"{{.Id}}","image":"{{.Image}}","name":"{{.Name}}","running":{{.State.Running}},"mounts":{{json .Mounts}}}'
    p=subprocess.run(docker+['inspect',fixture['container_id'],'--format',fmt],capture_output=True,check=True);(new/'pg-reactivation-inspect-before.json').write_bytes(p.stdout)
    x=json.loads(p.stdout);assert x['id']==fixture['container_id'] and x['image']==fixture['image_id'] and x['name']=='/'+fixture['container_name'] and not x['running']
    assert any(m.get('Type')=='volume' and m.get('Name')==fixture['volume'] and m.get('Destination')=='/var/lib/postgresql' for m in x['mounts'])
    p=subprocess.run(docker+['start',fixture['container_id']],capture_output=True);(new/'pg-reactivation-start.stdout').write_bytes(p.stdout);(new/'pg-reactivation-start.stderr').write_bytes(p.stderr);assert p.returncode==0
    p=subprocess.run(['powershell','-NoProfile','-File',str(new/'start-owned-helpers.ps1')],capture_output=True);(new/'pg-reactivation-helpers.stdout').write_bytes(p.stdout);(new/'pg-reactivation-helpers.stderr').write_bytes(p.stderr);assert p.returncode==0
    r.update(status='passed',exact_identity_verified=True,native_listener_count=1,fixture_and_private_files_retained_locally=True);save();print(json.dumps({'status':r['status'],'owned_listener':1,'private_values_printed':False}))
except Exception as error:r.update(status='failed',error=str(error));save();raise
