from pathlib import Path
import subprocess,json,time,os,tempfile
root=Path('/mnt/d/Cephalon/Cehpalon-Engine-Samples');out=Path.home()/'.local/share/cehpalon-benchmark-runs/collector-preflight-03';out.parent.mkdir(parents=True,exist_ok=True);out.mkdir()
dotnet='/home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/sdk/dotnet';assembly=Path('/home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/app-final-01/SmallApi.Benchmark.dll')
environment=dict(os.environ,DOTNET_PROCESSOR_COUNT='2',DOTNET_EnableDiagnostics='0')
fixture=Path(tempfile.mkdtemp(prefix='smoke-',dir=Path.home()/'.local/share/cehpalon-benchmark-fixtures'))/'fixture'
subprocess.run([dotnet,str(assembly),'--create-fixture='+str(fixture)],check=True,env=environment,capture_output=True,cwd=assembly.parent)
results=[]
for variant in ['baseline','engine']:
 for wire in ['http','graphql']:
  d=out/(variant+'-'+wire);d.mkdir();ready=d/'ready.json'
  with (d/'server.log').open('wb') as log:
   server=subprocess.Popen(['taskset','-c','0,2',dotnet,str(assembly),'--mode=serve','--variant='+variant,'--transport='+wire,'--fixture-dir='+str(fixture),'--ready-file='+str(ready),'--state-file='+str(d/'state.json')],stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,env=environment,cwd=assembly.parent)
   try:
    deadline=time.monotonic()+30
    while not ready.exists():
     if server.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Server failed readiness')
     time.sleep(.02)
    time.sleep(.05);r=json.loads(ready.read_text());assert r['processId']==server.pid;load=d/'driver';load.mkdir()
    command=['taskset','-c','4,6',dotnet,str(assembly),'--load-client','--url='+r['address'],'--ca-file='+str(fixture/'root-ca.der'),'--transport='+wire,'--output='+str(load),'--warmup=1','--seconds=2','--rate=1000']
    result=subprocess.run(command,env=environment,capture_output=True,cwd=assembly.parent);(d/'driver.log').write_bytes(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError('Driver code failed')
    value=json.loads((load/'load-result.json').read_text());assert value['warmup']['correct']==1000 and value['warmup']['errors']==0 and value['measured']['correct']==2000 and value['measured']['errors']==0 and value['state']['passed'] and value['initialValidation']['passed'],value['measured']
    account=json.loads((load/'measured-evidence-accounting.json').read_text());assert account['observedCount']==2000 and account['requestsCompletedTicks']<=account['completionMetricsStartedTicks']<=account['completionMetricsCompletedTicks']<=account['persistenceStartedTicks'];assert account['clientBefore'] and account['clientAfter'];assert value['tlsConnections'] and all(t['protocol']=='Tls13' for t in value['tlsConnections']);print(variant,wire,'warmup+measure+TLS passed',flush=True)
    results.append({'variant':variant,'transport':wire,'measured':value['measured'],'state':value['state'],'logicalManifestHash':value['logicalManifestHash']})
   finally:
    if server.poll() is None:
     server.stdin.write(b'STOP\n');server.stdin.flush()
     try:server.wait(timeout=5)
     except subprocess.TimeoutExpired:server.kill();server.wait();raise
(out/'summary.json').write_text(json.dumps({'scope':'Short infrastructure/data-collector preflight only; not a substitute for full timed protocol','results':results},indent=2)+'\n')
print([(x['variant'],x['transport'],x['measured']['correct']) for x in results])
