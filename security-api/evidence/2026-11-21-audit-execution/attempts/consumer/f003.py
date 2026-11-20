from pathlib import Path
import hashlib,json,os,subprocess
root=Path(__file__).resolve().parents[1]
engine=Path('D:/Cephalon/.worktrees/ae-engine')
attempt=root/'.local/audit-execution-consumer-freeze01'
attempt.mkdir(exist_ok=False)
inventory={}
for source,label in [(root/'security-api','consumer/security-api'),(engine/'src','engine/src')]:
 for current,dirs,files in os.walk(source):
  dirs[:]=[d for d in dirs if d not in {'evidence','bin','obj','.git','.local'}]
  for name in files:
   file=Path(current)/name
   if file.suffix not in {'.cs','.csproj','.json','.txt','.props','.config'}:continue
   rel=label+'/'+file.relative_to(source).as_posix();target=attempt/'source'/rel
   target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(file.read_bytes());inventory[rel]=hashlib.sha256(file.read_bytes()).hexdigest()
for source,label in [(root/'tools/verify_optional_security.py','consumer/tools/verify_optional_security.py'),(root/'global.json','consumer/global.json'),(root/'NuGet.Config','consumer/NuGet.Config'),(engine/'global.json','engine/global.json'),(engine/'NuGet.Config','engine/NuGet.Config'),(engine/'Directory.Packages.props','engine/Directory.Packages.props')]:
 target=attempt/'source'/label;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read_bytes());inventory[label]=hashlib.sha256(source.read_bytes()).hexdigest()
(attempt/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
print(json.dumps({'frozen':len(inventory),'before_sdk':True}))
result=subprocess.run(['python','-B','tools/verify_optional_security.py','--dotnet','D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe','--engine-root',str(engine),'--output','.local/audit-execution-consumer-dev01'],cwd=root,capture_output=True)
(attempt/'verifier-output.txt').write_bytes(result.stdout+result.stderr)
print(result.stdout.decode(errors='replace'));print(result.stderr.decode(errors='replace'));raise SystemExit(result.returncode)
