from pathlib import Path
import hashlib,json,os,subprocess,sys
root=Path.cwd();out=root/'.local'/sys.argv[1];out.mkdir(exist_ok=False);frozen=out/'frozen';inventory={}
for rel in ['src/Cehpalon.Engine.Tenancy','src/Cehpalon.Engine.Identity.Contracts','src/Cehpalon.Engine.Core','Tests/AuditTrail.ContractTests']:
 for source in sorted((root/rel).rglob('*')):
  if not source.is_file() or {'bin','obj','evidence','.local'}.intersection(source.relative_to(root).parts):continue
  if source.suffix.lower() not in ('.cs','.csproj','.json','.md'):continue
  target=frozen/source.relative_to(root);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read_bytes());inventory[source.relative_to(root).as_posix()]=hashlib.sha256(source.read_bytes()).hexdigest()
for rel in ['global.json','NuGet.Config','Directory.Packages.props']:
 source=root/rel;target=frozen/rel;target.write_bytes(source.read_bytes());inventory[rel]=hashlib.sha256(source.read_bytes()).hexdigest()
(out/'source-sha256.json').write_text(json.dumps(inventory,indent=2)+'\n',encoding='utf-8')
artifacts=out/'artifacts';sdk='D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe';project='Tests/AuditTrail.ContractTests/AuditTrail.ContractTests.csproj';env=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1')
commands=[('restore',[sdk,'restore',project,'--configfile',str(root/'NuGet.Config'),'--artifacts-path',str(artifacts),*([] if len(sys.argv)>2 and sys.argv[2]=='initialize-lock' else ['--locked-mode'])]),('build',[sdk,'build',project,'-c','Release','--no-restore','--artifacts-path',str(artifacts),'-p:UseSharedCompilation=false','-warnaserror']),('run',[sdk,str(artifacts/'bin/AuditTrail.ContractTests/release/AuditTrail.ContractTests.dll'),'--output='+str(out/'tests.json')])]
for name,command in commands:
 result=subprocess.run(command,cwd=root,env=env,capture_output=True);(out/(name+'.txt')).write_bytes(result.stdout+result.stderr)
 if result.returncode:print(name,'failed',result.returncode);sys.exit(result.returncode)
print((out/'tests.json').read_text(encoding='utf-8'))
