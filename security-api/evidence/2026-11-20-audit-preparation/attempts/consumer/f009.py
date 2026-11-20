from pathlib import Path
import json,hashlib,os,subprocess,sys
samples=Path.cwd();engine=Path('D:/Cephalon/.worktrees/audit-preparation-integration');out=samples/('.local/ap-consumer-windows-'+sys.argv[1]+'-source');out.mkdir(parents=True,exist_ok=False)
files={}
for root,prefix in [(samples/'security-api','consumer/security-api'),(engine/'src','engine/src')]:
 for current,dirs,names in os.walk(root):
  dirs[:]=[d for d in dirs if d not in ('evidence','artifacts','bin','obj','.local','.git')]
  for name in names:
   p=Path(current)/name
   if p.suffix.lower() in ('.cs','.csproj','.json','.txt','.md','.props','.config'):files[prefix+'/'+p.relative_to(root).as_posix()]=p
for root,prefix,names in [(samples,'consumer',['global.json','NuGet.Config','tools/verify_optional_security.py']),(engine,'engine',['global.json','NuGet.Config','Directory.Packages.props'])]:
 for name in names:files[prefix+'/'+name]=root/name
hashes={}
for rel,p in files.items():
 data=p.read_bytes();target=out/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);hashes[rel]=hashlib.sha256(data).hexdigest()
(out/'source-sha256.json').write_text(json.dumps(hashes,indent=2)+'\n',encoding='utf-8',newline='\n');(out/'provenance.json').write_text(json.dumps({'engine_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=engine,text=True).strip(),'consumer_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=samples,text=True).strip(),'source_state':'consumer uncommitted source frozen before run; engine exact clean committed','files':len(hashes)},indent=2)+'\n',encoding='utf-8',newline='\n');print('Frozen',len(hashes),'executing/support files before '+sys.argv[1])
