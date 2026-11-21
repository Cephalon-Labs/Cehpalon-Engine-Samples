from pathlib import Path,PurePosixPath
import json,hashlib,urllib.request,zipfile,tarfile,subprocess,os
root=Path(__file__).resolve().parent;selection=json.loads((root/'selection.json').read_bytes())
base=Path('D:/Cephalon/.tools/dotnet11-ga');base.mkdir(parents=True,exist_ok=True)
report={'status':'started','scope':'Private verified .NET11GA SDK side by side with preserved RC; no global install/PATH/runtime replacement','selection':selection,'archives':[]}
def save():(root/'install-manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
def run(command,name):
 result=subprocess.run(command,capture_output=True);(root/name).write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError('Failed '+name)
 return result.stdout.decode(errors='replace').strip()
save()
try:
 for item in selection['archives']:
  filename=item['url'].rsplit('/',1)[1];archive=base/filename;partial=base/(filename+'.partial');target=base/item['rid']
  assert not archive.exists() and not partial.exists(),filename
  target.mkdir(exist_ok=False);digest=hashlib.sha512();size=0
  with urllib.request.urlopen(item['url'],timeout=120) as response,partial.open('xb') as writer:
   while True:
    block=response.read(2*1024*1024)
    if not block:break
    writer.write(block);digest.update(block);size+=len(block)
  actual=digest.hexdigest();assert actual.lower()==item['sha512'].lower(),('SHA512 mismatch',filename)
  partial.rename(archive);entry=dict(item,archive=str(archive),bytes=size,actual_sha512=actual,verified=True);report['archives'].append(entry);save()
  if item['rid']=='win-x64':
   with zipfile.ZipFile(archive) as sdk:
    for member in sdk.infolist():
     name=PurePosixPath(member.filename.replace('\\','/'));assert not name.is_absolute() and '..' not in name.parts and ':' not in member.filename
    sdk.extractall(target)
   entry['version']=run([str(target/'dotnet.exe'),'--version'],'windows-sdk-version.txt')
   run([str(target/'dotnet.exe'),'--info'],'windows-sdk-info.txt');run([str(target/'dotnet.exe'),'--list-runtimes'],'windows-runtimes.txt')
  else:
   with tarfile.open(archive) as sdk:
    for member in sdk.getmembers():
     name=PurePosixPath(member.name);assert not name.is_absolute() and '..' not in name.parts
     if member.issym() or member.islnk():
      link=PurePosixPath(member.linkname);assert not link.is_absolute() and '..' not in link.parts
   unix='/mnt/d/Cephalon/.tools/dotnet11-ga'
   run(['wsl','-d','Ubuntu','--','tar','-xzf',unix+'/'+filename,'-C',unix+'/linux-x64'],'linux-extract.txt')
   entry['version']=run(['wsl','-d','Ubuntu','--cd',unix+'/linux-x64','./dotnet','--version'],'linux-sdk-version.txt')
   run(['wsl','-d','Ubuntu','--cd',unix+'/linux-x64','./dotnet','--info'],'linux-sdk-info.txt');run(['wsl','-d','Ubuntu','--cd',unix+'/linux-x64','./dotnet','--list-runtimes'],'linux-runtimes.txt')
  assert entry['version']=='11.0.100',entry['version'];save()
 report.update(status='passed',sdk='11.0.100',global_environment_unchanged=True);save()
except Exception as error:report.update(status='failed',error=str(error));save();raise
print(json.dumps({'status':report['status'],'sdk':'11.0.100','verified_archives':len(report['archives'])}))
