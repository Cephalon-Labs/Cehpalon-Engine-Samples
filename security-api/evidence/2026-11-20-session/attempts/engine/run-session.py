from pathlib import Path
import subprocess,json,hashlib,os,sys
root=Path.cwd();out=root/'.local'/sys.argv[1];out.mkdir(parents=True,exist_ok=False)
manifest={}
for folder in ['src/Cehpalon.Engine.Identity.Contracts','src/Cehpalon.Engine.Identity.AspNetCore','src/Cehpalon.Engine.Tenancy','src/Cehpalon.Engine.Core','src/Cehpalon.Engine.Composition','Tests/Session.ContractTests']:
 for p in sorted((root/folder).rglob('*')):
  if p.is_file() and not {'bin','obj'}.intersection(p.relative_to(root/folder).parts):
   rel=p.relative_to(root);q=out/'frozen'/rel;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(p.read_bytes());manifest[rel.as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
for name in ['global.json','NuGet.Config','Directory.Packages.props']:
 p=root/name;q=out/'frozen'/name;q.write_bytes(p.read_bytes());manifest[name]=hashlib.sha256(p.read_bytes()).hexdigest()
(out/'source-sha256.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
dotnet='D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe';art=out/'artifacts';project='Tests/Session.ContractTests/Session.ContractTests.csproj';env=dict(os.environ,DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_NOLOGO='1')
commands=[('restore',[dotnet,'restore',project,'--artifacts-path',str(art),'--configfile',str(root/'NuGet.Config')]+([] if len(sys.argv)>2 else ['--locked-mode'])),('build',[dotnet,'build',project,'--artifacts-path',str(art),'-c','Release','--no-restore','-p:UseSharedCompilation=false','-warnaserror']),('run',[dotnet,str(art/'bin/Session.ContractTests/release/Session.ContractTests.dll'),'--output='+str(out/'tests.json')])]
for label,cmd in commands:
 r=subprocess.run(cmd,env=env,capture_output=True);(out/(label+'.txt')).write_bytes(r.stdout+r.stderr)
 if r.returncode:print('FAILED',label,'exit',r.returncode,'raw',out);sys.exit(r.returncode)
print((out/'tests.json').read_text())
