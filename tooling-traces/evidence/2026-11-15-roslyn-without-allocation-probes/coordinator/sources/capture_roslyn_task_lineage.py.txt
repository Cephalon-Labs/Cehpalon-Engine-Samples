"""ADR0023: one full unchanged diagnostic generator with additional TPL events."""
import argparse,hashlib,json,os,subprocess,sys,traceback,types
from pathlib import Path
import trace_tooling as runtime
import tooling_wait_capture as provenance
ROOT=Path(__file__).resolve().parents[1]
ENGINE='55c630fc5d4c47258a1a2b0da4a16ce8bc42b9f7'
DRIVER='21d061db61ac77608f470f168b431cb5a631a099bfb1b07ed64cd5be04d53b5c'
PROVIDERS='Microsoft-Windows-DotNETRuntime:0x411C14FCCBD:5,Cehpalon-Tooling-Diagnostic:0x1:4,System.Threading.Tasks.TplEventSource:0x43:5'
PINS={'trace_tooling.py':'3091e8d8557571830d16a90e243638a0a021051478881d9036ae338eff3ab468','tooling_os_observer.py':'7799acf6244227d8ada325d366daf51c6df06483c7c29c25475fec65e7e4c203','tooling_wait_capture.py':'3350325def09143eddc04f95fa7d8235085878bb4c985a205429dc92525def26','trace_tooling_native.py':'55b3b9244ad13b01b11985d805e4ec28f887a00b42dbde74a0ecc60e79b783ff','validate_native_conformance.py':'cacef75ce72981be94028ee1e6181ca396bc29c547a4f7fd533a3b796dd3ab1d','benchmark_tooling.py':'32183755ca2db53030698a7e202b851afb0b759fb39142a155d53731469549d9'}
def require(ok,message):
    if not ok:raise ValueError(message)
def digest(data):return hashlib.sha256(data).hexdigest()
def sha(path):return digest(Path(path).read_bytes())
def save(path,value):Path(path).write_text(json.dumps(value,indent=2,allow_nan=False)+'\n',encoding='utf-8',newline='\n')
def code_state(module,frozen):
    functions=list(provenance._functions(module));compiled={}
    for filename in {f.__code__.co_filename for f in functions}:compiled[filename]=provenance._compiled_codes(compile(frozen,filename,'exec',dont_inherit=True,optimize=sys.flags.optimize))
    result={}
    for f in functions:
        candidate=compiled[f.__code__.co_filename].get(f.__qualname__)
        actual=provenance._code_info(f.__code__)
        require(candidate is not None and provenance._code_info(candidate)==actual,'Loaded function differs from frozen source: '+module.__name__+':'+f.__qualname__)
        result[f.__qualname__]=digest(json.dumps(actual,sort_keys=True).encode())
    return result
MODULES=[sys.modules[__name__],runtime,provenance,provenance.native,provenance.os_observer,runtime.benchmark,sys.modules['validate_native_conformance']]
SOURCES={m.__name__:(m,Path(m.__file__).resolve(),Path(m.__file__).read_bytes()) for m in MODULES}
def state():
    result={}
    for name,(module,path,original) in SOURCES.items():
        require(path.read_bytes()==original,'Module bytes changed after import: '+str(path))
        result[name]=dict(path=str(path),source_sha256=digest(original),functions=code_state(module,original))
    return result
def bindings():
    return {name:(getattr(runtime,name).__module__,getattr(runtime,name).__qualname__,id(getattr(runtime,name))) for name in ['capture_runtime','analyze','verify_generator','observe_process','process','sha','read','require','save']}
def self_test():
    n=0
    def check(value):
        nonlocal n
        require(value,'Self-test assertion');n+=1
    def rejected(fn):
        try:fn()
        except ValueError:return True
        return False
    module=types.ModuleType('fixture');source=b'def answer():\n return 42\n';exec(compile(source,'synthetic-fixture.py','exec'),module.__dict__)
    a=code_state(module,source);check('answer' in a);check(a==code_state(module,source))
    check(rejected(lambda:code_state(module,b'def answer():\n return 41\n')))
    exec(compile(b'def answer():\n return 40\n','synthetic-fixture.py','exec'),module.__dict__);check(rejected(lambda:code_state(module,source)))
    check(len(PINS)==6);check('0x43:5' in PROVIDERS);check('0x411C14FCCBD:5' in PROVIDERS)
    check(DRIVER=='21d061db61ac77608f470f168b431cb5a631a099bfb1b07ed64cd5be04d53b5c')
    check(state()==state());check(bindings()==bindings())
    print(json.dumps(dict(status='passed',checks=n)))
def inventory(paths):return {str(p):sha(p) for p in paths}
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--self-test',action='store_true')
    for name in ['dotnet','driver','driver-source','trace-tool','analyzer','engine-root','output']:parser.add_argument('--'+name)
    a=parser.parse_args()
    if a.self_test:return self_test()
    require(os.name!='nt','Declared lane is Linux/WSL only')
    require(all(getattr(a,k) for k in ['dotnet','driver','driver_source','trace_tool','analyzer','engine_root','output']),'All diagnostic arguments required')
    dotnet,driver,driver_source,tool,analyzer,engine,out=[Path(x).resolve() for x in [a.dotnet,a.driver,a.driver_source,a.trace_tool,a.analyzer,a.engine_root,a.output]]
    require(out!=ROOT/'.local' and out.is_relative_to(ROOT/'.local'),'New output under this isolated Samples .local')
    out.mkdir(parents=True,exist_ok=False);snap=out/'source-snapshots';snap.mkdir()
    report=dict(status='preparing',canonical=False,role='one_complete_roslyn_tpl_diagnostic_not_benchmark',engine_revision=ENGINE,providers=PROVIDERS,source_freeze_scope='Loaded Python function/method code and import-time bytes; declared runtime.PROVIDERS extension. Does not attest globals/defaults/imported binding behavior or filesystem immutability.',limits=['No scheduler/native syscalls or physical IO evidence.','Task link is not runnable delay, GC pause or exclusive cause.','TPL/proc/stack/rundown observers perturb this execution; no overhead estimate/comparison.','Legacy GC pairing fields are not newly certified.'])
    save(out/'manifest.json',report)
    try:
        require(subprocess.check_output(['git','rev-parse','HEAD'],cwd=engine,text=True).strip()==ENGINE,'Exact Engine revision')
        require(not subprocess.check_output(['git','status','--porcelain'],cwd=engine,text=True).strip(),'Clean Engine')
        require(sha(driver)==DRIVER,'Byte-identical prior diagnostic driver; no rebuild')
        require(all(sha(ROOT/'tools'/name)==value for name,value in PINS.items()),'Unchanged pinned capture/semantic/fingerprint helpers')
        prepared=runtime.read(driver_source/'wait-diagnostic-manifest.json')
        require(prepared['engine_revision']==ENGINE,'Prepared source Engine revision')
        for name,value in prepared['final_files_sha256'].items():require(sha(driver_source/name)==value,'Prepared source hash '+name)
        for _,path,original in SOURCES.values():(snap/(path.name+'.txt')).write_bytes(original)
        for path in sorted(driver_source.iterdir()):
            if path.is_file():(snap/('driver__'+path.name+'.txt')).write_bytes(path.read_bytes())
        binaries=[dotnet,tool,analyzer]+sorted(p for p in driver.parent.iterdir() if p.is_file() and p.suffix in ['.dll','.json','.pdb'])
        runtime_dir=dotnet.parent/'shared/Microsoft.NETCore.App/11.0.0-rc.3.26522.148'
        require(runtime_dir.is_dir(),'Pinned runtime exists')
        binaries+=sorted(p for p in runtime_dir.iterdir() if p.is_file())
        binary_before=inventory(binaries);report['binary_sha256_before']=binary_before
        environment,_=runtime.diagnostics_environment(dict(os.environ),False)
        info=subprocess.run([str(dotnet),'--info'],cwd=ROOT,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        (out/'dotnet-info.stdout.txt').write_bytes(info.stdout);(out/'dotnet-info.stderr.txt').write_bytes(info.stderr)
        require(info.returncode==0,'SDK/runtime information command')
        runtime.PROVIDERS=PROVIDERS
        before=state();bound=bindings();report['source_provenance_before']=before;report['binding_identity_before']=bound
        require(runtime.PROVIDERS==PROVIDERS,'Explicit provider extension')
        save(out/'manifest.json',report)
        folder=out/'generator'
        capture=runtime.capture_runtime([str(dotnet),str(driver),'--output='+str(folder/'generator.json')],ROOT,folder,dotnet,tool,analyzer,timeout=600)
        report['capture_status']=capture['status'];require(capture['status']=='completed','Capture completed')
        analysis=runtime.analyze(folder,dotnet,analyzer,folder/'generator.json.spans.jsonl',expected_markers=2956)
        report['semantics']=runtime.verify_generator(folder/'generator.json')
        require(analysis['payloadReadErrors']==0 and analysis['eventsLost']==0 and analysis['etlxEventsLost']==0,'Explicit parser/loss gates')
        counts={};metadata={};pid=capture['target_pid']
        with (folder/'analysis/events.jsonl').open(encoding='utf-8') as f:
            for line in f:
                e=json.loads(line)
                require(e['name']!='EventSourceMessage','Provider error invalidates collection')
                if e['provider']=='System.Threading.Tasks.TplEventSource':
                    require(e['processId']==pid,'TPL owned target header')
                    key=str(e['eventId'])+':'+str(e['version'])+':'+e['name'];counts[key]=counts.get(key,0)+1
        require(all(any(k.startswith(str(i)+':') for k in counts) for i in [7,8,9,10,11]),'Positive actual TPL lifecycle/wait channels')
        report['tpl_event_counts']=counts
        report['source_provenance_after']=state();report['binding_identity_after']=bindings();report['binary_sha256_after']=inventory(binaries)
        require(before==report['source_provenance_after'],'Loaded source code and inventory unchanged')
        require(bound==report['binding_identity_after'] and runtime.PROVIDERS==PROVIDERS,'Used bindings/provider unchanged')
        require(binary_before==report['binary_sha256_after'],'All pinned binary bytes unchanged')
        report.update(status='completed',root_quality=analysis['root_quality'])
    except Exception:report.update(status='failed',failure=traceback.format_exc());raise
    finally:save(out/'manifest.json',report)
    print(json.dumps(dict(status=report['status'],output=str(out))))
if __name__=='__main__':main()
