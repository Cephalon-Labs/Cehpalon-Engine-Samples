from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--attempt',required=True);a=p.parse_args();B=Path('D:/Cephalon');S=B/'.worktrees/ara-consumer';E=B/'.worktrees/arh-engine';D=B/'Cehpalon-Engine-Docs';out=S/'.local'/(a.attempt+'-source');out.mkdir(parents=True,exist_ok=False)
assert not subprocess.check_output(['git','-C',str(E),'status','--porcelain']).strip()
inputs={}
def keep(prefix,root,file):
    key=prefix+'/'+file.relative_to(root).as_posix();data=file.read_bytes();target=out/key;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);inputs[key]=hashlib.sha256(data).hexdigest()
for prefix,root,folders in [('consumer',S,['audit-outbox','security-api']),('engine',E,['src'])]:
    for folder in folders:
        for file in sorted((root/folder).rglob('*')):
            if file.is_file() and not {'evidence','bin','obj','.local','.git'}.intersection(file.relative_to(root).parts) and file.suffix in {'.cs','.csproj','.json','.txt'}:keep(prefix,root,file)
for prefix,root,names in [('consumer',S,['global.json','NuGet.Config','tools/verify_audit_outbox.py','tools/verify_optional_security.py']),('engine',E,['global.json','NuGet.Config','Directory.Packages.props','src/Cehpalon.Engine.CodeGeneration/NuGet.Config'])]:
    for name in names:
        file=root/name
        if file.is_file() and prefix+'/'+name not in inputs:keep(prefix,root,file)
declarations={}
decl=D/'.local/audit-read-admission-declaration01'
for file in sorted(decl.rglob('*')):
    if file.is_file():
        rel=file.relative_to(decl);data=file.read_bytes();target=out/'declaration'/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);declarations[rel.as_posix()]=hashlib.sha256(data).hexdigest()
manifest={'status':'frozen_before_sdk','attempt':a.attempt,'source_sha256':inputs,'declaration_sha256':declarations,'consumer_head':subprocess.check_output(['git','-C',str(S),'rev-parse','HEAD']).decode().strip(),'engine_head':subprocess.check_output(['git','-C',str(E),'rev-parse','HEAD']).decode().strip(),'source_count':len(inputs),'declaration_count':len(declarations)}
(out/'manifest.json').write_bytes((json.dumps(manifest,indent=2)+'\n').encode());(out/'freezer.py.txt').write_bytes(Path(__file__).read_bytes());print(json.dumps({'status':manifest['status'],'inputs':len(inputs),'declarations':len(declarations)}))
