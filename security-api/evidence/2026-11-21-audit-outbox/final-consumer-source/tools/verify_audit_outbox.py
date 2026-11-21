"""Owned PostgreSQL audit transaction/outbox proof; retain every attempt, never export private connection files."""
import argparse,hashlib,json,os,subprocess,sys,time,uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
IMAGE='docker.io/library/postgres@sha256:ec003ee60c23d320d1b81868f255a6fc724ac06d8f1ced4468532f7d8593f357'
CONTAINER='cehpalon-audit-outbox-pg18-20261121'

def main():
 p=argparse.ArgumentParser();p.add_argument('--dotnet',required=True);p.add_argument('--engine-root',required=True);p.add_argument('--connection-file',required=True);p.add_argument('--fixture-info',required=True);p.add_argument('--output',required=True);p.add_argument('--initialize-lock',action='store_true');a=p.parse_args()
 out=(ROOT/a.output).resolve();assert out.is_relative_to(ROOT/'.local') and out!=ROOT/'.local';out.mkdir(parents=True,exist_ok=False)
 engine=Path(a.engine_root).resolve();connection=Path(a.connection_file).resolve();assert connection.is_file() and connection.suffix=='.env'
 fixture=json.loads(Path(a.fixture_info).read_bytes());assert fixture['image']==IMAGE and fixture['container_name']==CONTAINER
 report={'status':'started','scope':'Owned PostgreSQL18.7/Npgsql10.0.3 conformance; no power-loss, benchmark or production qualification.','provider_topology':'Windows.NET Npgsql via owned Windows loopback/binary stdio proxy to WSL container; not native Windows Postgres' if os.name=='nt' else 'WSL.NET Npgsql directly to owned WSL loopback PostgreSQL container','engine_revision':subprocess.check_output(['git','-C',str(engine),'rev-parse','HEAD'],text=True).strip(),'consumer_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'engine_dirty':bool(subprocess.check_output(['git','-C',str(engine),'status','--porcelain'],text=True).strip()),'consumer_source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--','audit-outbox','security-api','tools/verify_audit_outbox.py'],cwd=ROOT,text=True).strip()),'source_sha256':{},'schemas':[]}
 def save():(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
 def retain(prefix,root,file):
  relative=file.relative_to(root);key=prefix+'/'+relative.as_posix();data=file.read_bytes();report['source_sha256'][key]=hashlib.sha256(data).hexdigest();target=out/'frozen-source'/key;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
 for prefix,root,folders in [('consumer',ROOT,['audit-outbox','security-api']),('engine',engine,['src'])]:
  for folder in folders:
   for file in sorted((root/folder).rglob('*')):
    if file.is_file() and not {'evidence','bin','obj','.local','.git'}.intersection(file.relative_to(root).parts) and file.suffix in {'.cs','.csproj','.json','.txt'}:retain(prefix,root,file)
 for prefix,root,names in [('consumer',ROOT,['global.json','NuGet.Config','tools/verify_audit_outbox.py']),('engine',engine,['global.json','NuGet.Config','Directory.Packages.props'])]:
  for name in names:retain(prefix,root,root/name)
 (out/'fixture-info.json').write_text(json.dumps(fixture,indent=2)+'\n',encoding='utf-8');save()
 env=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1')
 def run(command,filename):
  result=subprocess.run(list(map(str,command)),cwd=ROOT,env=env,capture_output=True);(out/filename).write_bytes(result.stdout+result.stderr)
  if result.returncode:raise RuntimeError('Failed '+filename+'; retained raw output')
  return result.stdout.decode('utf-8')
 try:
  report['sdk']=run([a.dotnet,'--version'],'sdk.txt').strip();assert report['sdk']==json.loads((engine/'global.json').read_bytes())['sdk']['version']
  artifacts=out/'artifacts';project=ROOT/'audit-outbox/PostgresAuditOutbox.Consumer.csproj';common=['--artifacts-path',artifacts,'-p:EngineRoot='+str(engine)]
  run([a.dotnet,'restore',project,'--configfile',ROOT/'NuGet.Config',*common,*([] if a.initialize_lock else ['--locked-mode'])],'restore.txt')
  retain('consumer',ROOT,ROOT/'audit-outbox/packages.lock.json');save()
  run([a.dotnet,'build',project,'--no-restore','-c','Release',*common,'-p:UseSharedCompilation=false','-warnaserror'],'build.txt')
  dll=artifacts/'bin/PostgresAuditOutbox.Consumer/release/PostgresAuditOutbox.Consumer.dll'
  run([a.dotnet,dll,'--connection-file='+str(connection),'--schema=ao_'+uuid.uuid4().hex,'--output='+str(out/'tests.json')],'run.txt')
  tests=json.loads((out/'tests.json').read_bytes());assert tests['failed']==0 and tests['passed']>=30;report['passed']=tests['passed'];report['schemas'].extend(tests['schemas']);report['settings']=tests['settings']
  # Two independently launched processes with the same private owned schema around an actual server restart.
  restart_schema='ao_'+uuid.uuid4().hex;report['restart_schema']=restart_schema;save()
  run([a.dotnet,dll,'--connection-file='+str(connection),'--schema='+restart_schema,'--phase=restart-write','--output='+str(out/'restart-write.json')],'restart-write.txt')
  docker=(['wsl','-d','Ubuntu','--'] if os.name=='nt' else [])+['docker']
  container_id=fixture['container_id'];assert len(container_id)==64 and all(c in '0123456789abcdef' for c in container_id)
  observed=run([*docker,'inspect',container_id,'--format','{{.Id}} {{.Image}} {{.Name}}'],'owned-server-identity.txt').strip().split()
  assert observed==[container_id,fixture['image_id'],'/'+CONTAINER],observed
  run([*docker,'restart','--time','10',container_id],'owned-server-restart.txt')
  ready=[]
  for index in range(30):
   probe=subprocess.run([*docker,'exec',container_id,'pg_isready','-U','cehpalon_audit','-d','cehpalon_audit'],capture_output=True)
   ready.append({'attempt':index+1,'exit_code':probe.returncode,'output':(probe.stdout+probe.stderr).decode(errors='replace')})
   if probe.returncode==0:break
   time.sleep(.5)
  (out/'owned-server-readiness.json').write_text(json.dumps(ready,indent=2)+'\n',encoding='utf-8');assert ready[-1]['exit_code']==0,'Owned restarted server not ready'
  run([a.dotnet,dll,'--connection-file='+str(connection),'--schema='+restart_schema,'--phase=restart-read','--output='+str(out/'restart-read.json')],'restart-read.txt')
  restart=[json.loads((out/name).read_bytes()) for name in ['restart-write.json','restart-read.json']];assert all(x['failed']==0 for x in restart)
  report['restart_passed']=sum(x['passed'] for x in restart);report['schemas'].append(restart_schema)
  generated=list((artifacts/'obj/PostgresAuditOutbox.Consumer').rglob('OperationRegistrations.g.cs'));assert len(generated)==1
  (out/'generated-relay.g.cs.txt').write_bytes(generated[0].read_bytes());report['relay_registry_sha256']=hashlib.sha256(generated[0].read_bytes()).hexdigest()
  existing=list((artifacts/'obj/SecurityApi.Consumer').rglob('OperationRegistrations.g.cs'));assert len(existing)==1;report['security_registry_sha256']=hashlib.sha256(existing[0].read_bytes()).hexdigest();assert report['security_registry_sha256']=='0534d97c0deba2f33744091b828da6a8a4e375d46c44ef2ca938f2088f148489'
  deps=json.loads(dll.with_suffix('.deps.json').read_bytes());assert not any('CodeAnalysis' in k or 'CodeGeneration' in k for k in deps['libraries']);report['runtime_libraries']=sorted(deps['libraries'])
  for key,digest in report['source_sha256'].items():
   prefix,relative=key.split('/',1);file=(engine if prefix=='engine' else ROOT)/relative;assert hashlib.sha256(file.read_bytes()).hexdigest()==digest,key
  report.update(status='passed',source_unchanged=True,total_passed=report['passed']+report['restart_passed'])
 except Exception as error:report.update(status='failed',error=str(error));save();raise
 save();print(json.dumps({k:report[k] for k in ['status','passed','restart_passed','total_passed']}))

if __name__=='__main__':main()
