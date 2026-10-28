from pathlib import Path
from types import SimpleNamespace
import hashlib,importlib.util,json,os,shutil,subprocess,sys,time

root=Path('/mnt/d/Cephalon/Cehpalon-Engine-Samples')
spec=importlib.util.spec_from_file_location('benchmark',root/'tools/benchmark_small_api.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
attempt=sys.argv[1] if len(sys.argv)>1 else '02'
build=sys.argv[2] if len(sys.argv)>2 else '03'
out=root/f'.local/startup-layout-diagnostic-{attempt}';out.mkdir(parents=True,exist_ok=False)
shutil.copyfile(Path(__file__),out/'diagnose-startup-layout.py')
base=Path.home()/'.local/share/cehpalon-benchmark-deployment/tuning-20261028'
sdks={'drvfs':Path('/mnt/d/Cephalon/.tools/dotnet11/linux-x64/dotnet'),'native':base/'sdk/dotnet'}
drvapp=Path(f'/mnt/d/Cephalon/.worktrees/w2-startup-tuning/.local/startup-trace-build{build}/artifacts/bin/SmallApi.Benchmark/release')
nativeapp=base/f'app-trace-{build}';shutil.copytree(drvapp,nativeapp,symlinks=True)
entries=[]
for p in sorted(drvapp.rglob('*')):
 if p.is_file():
  rel=p.relative_to(drvapp);h=hashlib.sha256(p.read_bytes()).hexdigest()
  assert hashlib.sha256((nativeapp/rel).read_bytes()).hexdigest()==h
  entries.append({'path':rel.as_posix(),'sha256':h,'bytes':p.stat().st_size})
apps={'drvfs':drvapp/'SmallApi.Benchmark.dll','native':nativeapp/'SmallApi.Benchmark.dll'}
args=SimpleNamespace(dotnet=sdks['drvfs'],assembly=apps['drvfs'],engine_root=root.parent/'Cehpalon-Engine',phases=[],server_working_directory=drvapp)
runner=b.Runner(args,out)
fixture=base/f'diagnostic-fixture-{attempt}';runner.fixture=fixture;runner.ca=fixture/'root-ca.der'
runner.invoke(runner.command(b.SERVER_CPUS,'--create-fixture='+str(fixture)),'fixture-create')
assert fixture.stat().st_mode&0o777==0o700
assert (fixture/'server.pfx').stat().st_mode&0o777==0o600
layouts={'A':('drvfs','drvfs'),'B':('native','drvfs'),'C':('drvfs','native'),'D':('native','native')}
manifest={'scope':'ADR0010 descriptive diagnostic only; not budget scoring. Same traced binary; layout app factor includes cwd/content root. Ready/state/trace files stay on fixed DrvFs.','orders':['ABCD','BCDA','CDAB','DABC'],'lanes':[['baseline','http'],['engine','http'],['baseline','graphql'],['engine','graphql']],'layouts':layouts,'app_files':entries,'private_fixture_path':str(fixture),'private_keys_in_output':False,'assembly_sha256':b.sha(apps['drvfs']),'source_files':{p.name:b.sha(p) for p in Path('/mnt/d/Cephalon/.worktrees/w2-startup-tuning/small-api-benchmark').glob('*.cs')}}
b.write_json(out/'manifest.json',manifest)
observations=[]
try:
 for rep,order in enumerate(manifest['orders']):
  for layout in order:
   sdk,app=layouts[layout];args.dotnet=sdks[sdk];args.assembly=apps[app];args.server_working_directory=apps[app].parent
   for variant,transport in manifest['lanes']:
    directory=out/f'{rep:02d}-{layout}-{variant}-{transport}'
    trace=directory/'startup-trace.json'
    command=runner.command
    runner.command=lambda cpus,*values:command(cpus,*values,'--startup-trace='+str(trace))
    b.ROOT=apps[app].parent
    runner.progress.update(phase='layout-diagnostic',repetition=rep,layout=layout,variant=variant,transport=transport)
    try:
     with b.Server(runner,directory,variant,transport) as server:
      maps=Path(f'/proc/{server.process.pid}/maps').read_text()
      runtime_paths=sorted({line.split()[-1] for line in maps.splitlines() if 'libcoreclr.so' in line or 'libhostpolicy.so' in line})
      if not any(str(sdks[sdk].parent) in p for p in runtime_paths):raise ValueError('Resolved runtime differs from layout')
      row={'rep':rep,'layout':layout,'variant':variant,'transport':transport,'startup_ms':server.startup_milliseconds,'started_monotonic_ns':server.started_ns,'verified_monotonic_ns':server.verified_ns,'resolved_runtime_paths':runtime_paths}
     row['shutdown']=server.shutdown
     row['trace']=json.loads(trace.read_text())
     assert row['shutdown']['passed']
     observations.append(row);b.write_json(out/'observations.json',observations)
    finally:
     runner.command=command;b.ROOT=root
 summary=[]
 for layout in layouts:
  for variant,transport in manifest['lanes']:
   vals=[r['startup_ms'] for r in observations if (r['layout'],r['variant'],r['transport'])==(layout,variant,transport)]
   summary.append({'layout':layout,'variant':variant,'transport':transport,'all_startup_ms':vals,'median_ms':__import__('statistics').median(vals)})
 b.write_json(out/'summary.json',{'completed':len(observations),'observations':summary,'acceptance_gate':'Not scored; diagnostic only'})
 runner.progress.update(phase='complete',status='completed',completed=len(observations))
except BaseException as error:
 b.write_json(out/'failure.json',{'status':'invalid-aborted','reason':repr(error),'completed_of_64':len(observations),'scope':'All raw retained; no selective adoption. Complete diagnostic must rerun after a reviewed repair.'})
 raise
finally:
 for process in reversed(runner.owned): runner.terminate(process)
 runner.progress.events.close()
print(json.dumps({'completed':len(observations),'output':str(out)}))
