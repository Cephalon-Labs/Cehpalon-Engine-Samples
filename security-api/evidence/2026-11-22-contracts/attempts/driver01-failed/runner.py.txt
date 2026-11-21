"""Root serial targeted matrix: two builds, two offline runs, then same binaries for wire."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--consumer-revision',required=True);a=p.parse_args()
B=Path('D:/Cephalon');D=B/'Cehpalon-Engine-Docs';E=B/'.worktrees/arh-engine';EW=E/'.local/arh-wsl-source01';S=B/'.worktrees/ahx-consumer';SW=B/'.worktrees/ahx-wsl-consumer';O=E/'.local/ahx-driver01';O.mkdir(exist_ok=False)
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
    stopped=json.loads((D/'internal/evidence/audit-contract-export/offline-fixture-stopped.json').read_bytes());assert stopped['status']=='passed' and not stopped['container_running'] and stopped['native_listener_count']==0
    fixture=json.loads((B/'.worktrees/ara-consumer/.local/postgres18-fixture.json').read_bytes())
    assert run(['wsl','-d','Ubuntu','--exec','docker','inspect',fixture['container_id'],'--format','{{.State.Running}}'],'fixture-still-stopped').decode().strip()=='false'
    decl=D/'.local/audit-contract-export-declaration01'
    run(['python','-B','tools/verify_audit_contracts.py','--phase','offline','--dotnet',WIN,'--engine-root',E,'--output','.local/ahx-offline-windows01','--declarations-root',decl],'offline-windows',S)
    assert not SW.exists();SW.mkdir();wsl(SW,['git','init','--quiet'],'wsl-source-init')
    alt=SW/'.git/objects/info/alternates';alt.parent.mkdir(parents=True,exist_ok=True);alt.write_bytes(b'/mnt/d/Cephalon/Cehpalon-Engine-Samples/.git/objects\n')
    (O/'wsl-source-borrowing.json').write_bytes((json.dumps({'source':str(SW),'consumer_revision':a.consumer_revision,'borrowed_objects':alt.read_text().strip(),'independent_source_archive':False,'retain_primary_objects_and_worktrees':True},indent=2)+'\n').encode())
    wsl(SW,['git','config','core.autocrlf','false'],'wsl-source-eol');wsl(SW,['git','update-ref','refs/heads/features/audit-contract-export-source',a.consumer_revision],'wsl-source-ref');wsl(SW,['git','symbolic-ref','HEAD','refs/heads/features/audit-contract-export-source'],'wsl-source-head')
    patterns=b'/*\n!/*/\n/tools/\n/security-api/\n/audit-outbox/\n!/security-api/evidence/\n!/audit-outbox/evidence/\n'
    wsl(SW,['git','sparse-checkout','set','--no-cone','--stdin'],'wsl-source-sparse',input=patterns);wsl(SW,['git','checkout','--detach',a.consumer_revision],'wsl-source-detach');assert not wsl(SW,['git','status','--porcelain'],'wsl-source-state').strip()
    wsl(SW,['python3','-B','tools/verify_audit_contracts.py','--phase','offline','--dotnet',LIN,'--engine-root',unix(EW),'--output','.local/ahx-offline-wsl01','--declarations-root',unix(decl)],'offline-wsl')
    for root,name in [(S,'ahx-offline-windows01'),(SW,'ahx-offline-wsl01')]:
        m=json.loads((root/'.local'/name/'manifest.json').read_bytes());assert m['status']=='passed' and m['passed']==8 and m['failed']==0 and m['consumer_revision']==a.consumer_revision
    setup=D/'.local/setup-audit-contract-export-fixture.py';(O/'executing-fixture-setup.py.txt').write_bytes(setup.read_bytes());r['fixture_setup_sha256']=hashlib.sha256(setup.read_bytes()).hexdigest();save()
    run(['python','-B',setup],'fixture-start-after-offline',D)
    run(['python','-B','tools/verify_audit_contracts.py','--phase','wire','--dotnet',WIN,'--engine-root',E,'--output','.local/ahx-wire-windows01','--offline-output','.local/ahx-offline-windows01','--connection-file',S/'.local/private-pg18-windows-connection.env','--fixture-info',S/'.local/postgres18-fixture.json'],'wire-windows',S)
    wsl(SW,['python3','-B','tools/verify_audit_contracts.py','--phase','wire','--dotnet',LIN,'--engine-root',unix(EW),'--output','.local/ahx-wire-wsl01','--offline-output','.local/ahx-offline-wsl01','--connection-file',unix(S/'.local/private-pg18-connection.env'),'--fixture-info',unix(S/'.local/postgres18-fixture.json')],'wire-wsl')
    r.update(status='passed',new_checks_per_host=16,builds=2,wire_rebuilds=0,prior_full_suites_rerun=False)
except Exception as e:r.update(status='failed',error=str(e));save();raise
save();print(json.dumps({'status':r['status'],'completed_phases':len(r['phases']),'new_checks_per_host':16,'builds':2,'wire_rebuilds':0}))
