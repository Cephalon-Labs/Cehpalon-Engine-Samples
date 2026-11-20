from pathlib import Path
import hashlib,json,os,subprocess,sys
root=Path.cwd();attempt=root/sys.argv[1];project=root/sys.argv[2];assembly=sys.argv[3];initialize='--initialize-lock' in sys.argv
attempt.mkdir(parents=True,exist_ok=True);frozen=attempt/'frozen';frozen.mkdir(exist_ok=False);hashes={}
paths=[]
for base in [root/'src',project.parent]:
 for current,dirs,files in os.walk(base):
  dirs[:]=[d for d in dirs if d not in ('bin','obj','evidence','.git','.local')]
  for name in files:
   p=Path(current)/name
   if p.suffix in ('.cs','.csproj','.json'):paths.append(p)
paths.extend(root/name for name in ('global.json','NuGet.Config','Directory.Packages.props'))
for p in paths:
 rel=p.relative_to(root);data=p.read_bytes();dest=frozen/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data);hashes[rel.as_posix()]=hashlib.sha256(data).hexdigest()
(attempt/'source-sha256.json').write_text(json.dumps(hashes,indent=2)+'\n',encoding='utf-8',newline='\n')
dotnet='D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe';artifacts=attempt/'artifacts';env=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1')
def run(args,name):
 p=subprocess.run([dotnet,*map(str,args)],capture_output=True,env=env);(attempt/name).write_bytes(p.stdout+p.stderr)
 if p.returncode:raise RuntimeError('Failed '+name)
run(['restore',project,'--configfile',root/'NuGet.Config','--artifacts-path',artifacts,*([] if initialize else ['--locked-mode'])],'restore.txt')
run(['build',project,'-c','Release','--no-restore','--artifacts-path',artifacts,'-p:UseSharedCompilation=false','-warnaserror'],'build.txt')
args=[artifacts/'bin'/assembly/'release'/(assembly+'.dll')]
if assembly!='Probe':args+=['--output='+str(attempt/'tests.json')]
run(args,'run.txt')
print((attempt/'run.txt').read_text(encoding='utf-8'))
