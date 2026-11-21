from pathlib import Path
import hashlib,json,subprocess
D=Path.cwd();old=Path('D:/Cephalon/.worktrees/ara-consumer/.local');new=Path('D:/Cephalon/.worktrees/ahx-consumer/.local/fixture03');new.mkdir(parents=True,exist_ok=True)
out=new/'pg-reactivation-setup01.json';assert not out.exists();r={'status':'preparing','profile':'audit-contract-export','retained_previous_fixture':True,'private_config_exported':False,'helpers':{},'launch_io':'File-backed stdout/stderr plus DEVNULL stdin and process wait; no captured pipes'}
def save():out.write_bytes((json.dumps(r,indent=2)+'\n').encode())
save()
try:
    for name in ('start-owned-helpers.ps1','pg-loopback-proxy.py','pg-stdio-bridge.py','pg-wsl-anchor.py','cleanup-owned-ga-pg.py'):
        target=new/name;assert not target.exists();text=(old/name).read_text(encoding='utf-8').replace('ara-consumer','ahx-consumer').replace('audit-read-admission','audit-contract-export').replace('audit read admission consumer','audit contract export consumer').replace('/ahx-consumer/.local','/ahx-consumer/.local/fixture03')
        assert 'ara-consumer' not in text;target.write_bytes(text.encode());r['helpers'][name]=hashlib.sha256(target.read_bytes()).hexdigest()
    for name in ('postgres18-fixture.json','private-pg18-connection.env'):
        assert not (new/name).exists();(new/name).write_bytes((old/name).read_bytes())
    fixture=json.loads((new/'postgres18-fixture.json').read_bytes());r.update(container_id=fixture['container_id'],retained_volume=fixture['volume'])
    docker=['wsl','-d','Ubuntu','--exec','docker'];fmt='{"id":"{{.Id}}","image":"{{.Image}}","name":"{{.Name}}","running":{{.State.Running}},"mounts":{{json .Mounts}}}'
    p=subprocess.run(docker+['inspect',fixture['container_id'],'--format',fmt],capture_output=True,check=True);(new/'pg-reactivation-inspect-before.json').write_bytes(p.stdout);x=json.loads(p.stdout)
    assert x['id']==fixture['container_id'] and x['image']==fixture['image_id'] and x['name']=='/'+fixture['container_name'] and not x['running']
    assert any(m.get('Type')=='volume' and m.get('Name')==fixture['volume'] and m.get('Destination')=='/var/lib/postgresql' for m in x['mounts'])
    p=subprocess.run(docker+['start',fixture['container_id']],capture_output=True);(new/'pg-reactivation-start.stdout').write_bytes(p.stdout);(new/'pg-reactivation-start.stderr').write_bytes(p.stderr);assert p.returncode==0
    with (new/'pg-reactivation-helpers.stdout').open('wb') as stdout,(new/'pg-reactivation-helpers.stderr').open('wb') as stderr:
        p=subprocess.run(['powershell','-NoProfile','-File',str(new/'start-owned-helpers.ps1')],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,close_fds=True)
    assert p.returncode==0,'Owned helper launcher failed; all attempt files retained'
    listener=json.loads((new/'pg-proxy-native-listener-before.json').read_text(encoding='utf-8-sig'));assert listener['listener_count']==1
    r.update(status='passed',exact_identity_verified=True,native_listener_count=1,launcher_exit=p.returncode,windows_proxy_port=listener['port'],fixture_and_private_files_retained_locally=True);save();print(json.dumps({'status':'passed','owned_listener':1,'launcher_exit':p.returncode,'capture_pipes_used':False,'private_values_printed':False}))
except Exception as e:r.update(status='failed',error=str(e));save();raise
