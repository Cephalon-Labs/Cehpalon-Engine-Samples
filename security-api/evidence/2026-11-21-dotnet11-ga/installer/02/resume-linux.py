from pathlib import Path
import json,hashlib,subprocess,tarfile,posixpath
root=Path(__file__).resolve().parent;root.mkdir(exist_ok=True);prior=root.parent/'dotnet-ga-install01';selection=json.loads((prior/'selection.json').read_bytes())
archive=Path('D:/Cephalon/.tools/dotnet11-ga/dotnet-sdk-11.0.100-linux-x64.tar.gz');target=archive.parent/'linux-x64';assert target.is_dir() and not any(target.iterdir())
report={'status':'started','scope':'Correct over-restrictive link validation before first Linux extraction; no redownload/Windows overwrite/RC change','prior_failed_attempt':'dotnet-ga-install01','selection':selection}
def save():(root/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
def run(args,name):
 r=subprocess.run(args,capture_output=True);(root/name).write_bytes(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError('Failed '+name)
 return r.stdout.decode(errors='replace').strip()
save()
try:
 with archive.open('rb') as f:actual=hashlib.file_digest(f,'sha512').hexdigest()
 expected=next(a for a in selection['archives'] if a['rid']=='linux-x64')['sha512'];assert actual.lower()==expected.lower();report['actual_sha512']=actual
 links=0
 with tarfile.open(archive) as sdk:
  for member in sdk.getmembers():
   name=posixpath.normpath(member.name);assert not posixpath.isabs(name) and name!='..' and not name.startswith('../')
   if member.issym() or member.islnk():
    links+=1;resolved=posixpath.normpath(posixpath.join(posixpath.dirname(member.name),member.linkname) if member.issym() else member.linkname);assert not posixpath.isabs(resolved) and resolved!='..' and not resolved.startswith('../')
 report['links_resolve_inside_sdk']=links;save()
 base='/mnt/d/Cephalon/.tools/dotnet11-ga'
 run(['wsl','-d','Ubuntu','--','tar','-xzf',base+'/'+archive.name,'-C',base+'/linux-x64'],'extract.txt')
 report['linux_sdk_probe']=run(['wsl','-d','Ubuntu','--cd',base+'/linux-x64','./dotnet','--version'],'linux-sdk-version.txt');assert report['linux_sdk_probe']=='11.0.100'
 run(['wsl','-d','Ubuntu','--cd',base+'/linux-x64','./dotnet','--info'],'linux-sdk-info.txt');run(['wsl','-d','Ubuntu','--cd',base+'/linux-x64','./dotnet','--list-runtimes'],'linux-runtimes.txt')
 report['windows_sdk_probe']=run(['D:/Cephalon/.tools/dotnet11-ga/win-x64/dotnet.exe','--version'],'windows-sdk-version.txt');assert report['windows_sdk_probe']=='11.0.100'
 report.update(status='passed',global_environment_unchanged=True,old_rc_sdk_retained=True);save()
except Exception as error:report.update(status='failed',error=str(error));save();raise
print(json.dumps({'status':'passed','windows':report['windows_sdk_probe'],'linux':report['linux_sdk_probe'],'verified_internal_links':links}))
