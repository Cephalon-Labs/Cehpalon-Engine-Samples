"""Root serial targeted matrix: two builds, two offline runs, then same binaries for wire."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--consumer-revision',required=True);a=p.parse_args()
B=Path('D:/Cephalon');D=B/'Cehpalon-Engine-Docs';E=B/'.worktrees/arh-engine';EW=E/'.local/arh-wsl-source01';S=B/'.worktrees/ahx-consumer';SW=B/'.worktrees/ahx-wsl-consumer';O=E/'.local/ahx-driver03';O.mkdir(exist_ok=False)
WIN='D:/Cephalon/.tools/dotnet11-ga/win-x64/dotnet.exe';LIN='/mnt/d/Cephalon/.tools/dotnet11-ga/linux-x64/dotnet'
def unix(path):return '/mnt/d/'+Path(path).as_posix().removeprefix('D:/')
r={'status':'started','engine_revision':'5184517a92a087abe4e0091d256142b6c35a2b39','consumer_revision':a.consumer_revision,'scope':'New16targetedchecks perhost;8offline+8wire, two builds and same binary reuse. Prior332/651/Engine/CI baseline only; no timed benchmark','runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'phases':[]};(O/'runner.py.txt').write_bytes(Path(__file__).read_bytes())
def save():(O/'manifest.json').write_bytes((json.dumps(r,indent=2)+'\n').encode())
def run(cmd,name,cwd=E,input=None):
    q=subprocess.run(list(map(str,cmd)),cwd=cwd,input=input,capture_output=True);(O/(name+'.stdout.txt')).write_bytes(q.stdout);(O/(name+'.stderr.txt')).write_bytes(q.stderr);r['phases'].append({'name':name,'exit':q.returncode});save()
    if q.returncode:raise RuntimeError('Failed '+name+'; actual raw retained')
    return q.stdout
def wsl(cwd,cmd,name,input=None):return run(['wsl','--cd',unix(cwd),'--exec',*cmd],name,input=input)
save()
try:
    assert len(a.consumer_revision)==40 and all(c in '0123456789abcdef' for c in a.consumer_revision)
    assert run(['git','rev-parse','HEAD'],'engine-head').decode().strip()==r['engine_revision'];assert not run(['git','status','--porcelain'],'engine-state').strip()
    assert run(['git','rev-parse','HEAD'],'consumer-head',S).decode().strip()==a.consumer_revision;assert not run(['git','status','--porcelain'],'consumer-state',S).strip()
    stopped=json.loads((D/'internal/evidence/audit-contract-export/offline-fixture-stopped03.json').read_bytes());assert stopped['status']=='passed' and not stopped['container_running'] and stopped['native_listener_count']==0
    fixture=json.loads((B/'.worktrees/ara-consumer/.local/postgres18-fixture.json').read_bytes())
    assert run(['wsl','-d','Ubuntu','--exec','docker','inspect',fixture['container_id'],'--format','{{.State.Running}}'],'fixture-still-stopped').decode().strip()=='false'
    decl=D/'.local/audit-contract-export-declaration01';decl2=D/'.local/audit-contract-export-declaration02';decl3=D/'.local/audit-contract-export-declaration03'
    run(['python','-B','tools/verify_audit_contracts.py','--phase','offline','--dotnet',WIN,'--engine-root',E,'--output','.local/ahx-offline-windows03','--declarations-root',decl,'--declarations-root',decl2,'--declarations-root',decl3],'offline-windows',S)
    assert SW.is_dir()
    assert not wsl(SW,['git','status','--porcelain'],'wsl-existing-clean').strip()
    old=wsl(SW,['git','rev-parse','HEAD'],'wsl-existing-head').decode().strip();assert old=='d013d61ae2cc22f2d79fefc29fd64482b4888f13'
    wsl(SW,['git','merge-base','--is-ancestor',old,a.consumer_revision],'wsl-source-forward-check')
    wsl(SW,['git','update-ref','refs/heads/features/audit-contract-export-source',a.consumer_revision,old],'wsl-source-ref-forward')
    wsl(SW,['git','checkout','--detach',a.consumer_revision],'wsl-source-detach');assert not wsl(SW,['git','status','--porcelain'],'wsl-source-state').strip()
    (O/'wsl-source-borrowing.json').write_bytes((json.dumps({'source':str(SW),'previous_source':old,'consumer_revision':a.consumer_revision,'borrowed_objects':'/mnt/d/Cephalon/Cehpalon-Engine-Samples/.git/objects','independent_source_archive':False,'retain_primary_objects_worktrees_and_old_outputs':True},indent=2)+'\n').encode())
    wsl(SW,['python3','-B','tools/verify_audit_contracts.py','--phase','offline','--dotnet',LIN,'--engine-root',unix(EW),'--output','.local/ahx-offline-wsl03','--declarations-root',unix(decl),'--declarations-root',unix(decl2),'--declarations-root',unix(decl3)],'offline-wsl')
    for root,name in [(S,'ahx-offline-windows03'),(SW,'ahx-offline-wsl03')]:
        m=json.loads((root/'.local'/name/'manifest.json').read_bytes());assert m['status']=='passed' and m['passed']==8 and m['failed']==0 and m['consumer_revision']==a.consumer_revision
    setup=D/'.local/setup-audit-contract-export-fixture03.py';(O/'executing-fixture-setup.py.txt').write_bytes(setup.read_bytes());r['fixture_setup_sha256']=hashlib.sha256(setup.read_bytes()).hexdigest();save()
    run(['python','-B',setup],'fixture-start-after-offline',D)
    run(['python','-B','tools/verify_audit_contracts.py','--phase','wire','--dotnet',WIN,'--engine-root',E,'--output','.local/ahx-wire-windows03','--offline-output','.local/ahx-offline-windows03','--connection-file',S/'.local/fixture03/private-pg18-windows-connection.env','--fixture-info',S/'.local/fixture03/postgres18-fixture.json'],'wire-windows',S)
    wsl(SW,['python3','-B','tools/verify_audit_contracts.py','--phase','wire','--dotnet',LIN,'--engine-root',unix(EW),'--output','.local/ahx-wire-wsl03','--offline-output','.local/ahx-offline-wsl03','--connection-file',unix(S/'.local/fixture03/private-pg18-connection.env'),'--fixture-info',unix(S/'.local/fixture03/postgres18-fixture.json')],'wire-wsl')
    r.update(status='passed',new_checks_per_host=16,builds=2,wire_rebuilds=0,prior_full_suites_rerun=False)
except Exception as e:r.update(status='failed',error=str(e));save();raise
save();print(json.dumps({'status':r['status'],'completed_phases':len(r['phases']),'new_checks_per_host':16,'builds':2,'wire_rebuilds':0}))
