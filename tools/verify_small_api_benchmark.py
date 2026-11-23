"""Locked build and complete ordered conformance, with retained failed attempts."""
import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--dotnet',required=True)
    parser.add_argument('--engine-root',default=str(ROOT.parent/'Cehpalon-Engine'))
    parser.add_argument('--output',required=True)
    parser.add_argument('--build-only',action='store_true')
    parser.add_argument('--require-clean',action='store_true')
    args=parser.parse_args()
    output=(ROOT/args.output).resolve();private=(ROOT/'.local').resolve()
    if not output.is_relative_to(private) or output==private:raise ValueError('Use a fresh directory beneath ignored Samples .local')
    output.mkdir(parents=True,exist_ok=False)
    engine=Path(args.engine_root).resolve();lock=json.loads((ROOT/'small-api-benchmark/engine-lock.json').read_text())
    environment=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1',MSBUILDDISABLENODEREUSE='1')
    def run(command,log=None,cwd=ROOT):
        result=subprocess.run(list(map(str,command)),cwd=cwd,env=environment,capture_output=True)
        if log:(output/log).write_bytes(result.stdout+result.stderr)
        if result.returncode:raise RuntimeError(f'Failed ({result.returncode}); retained {log}')
        return result.stdout.decode('utf-8').strip()
    if run(['git','rev-parse','HEAD'],cwd=engine)!=lock['engine_revision'] or run(['git','status','--porcelain'],cwd=engine):raise ValueError('Require exact clean locked Engine source')
    dirty=run(['git','status','--porcelain'])
    if args.require_clean and dirty:raise ValueError('Require clean committed Samples source')
    sdk=run([args.dotnet,'--version'],'sdk-version.txt')
    if sdk!=lock['sdk']:raise ValueError('SDK differs from Engine pin')
    sources=[*sorted((ROOT/'small-api-benchmark').glob('*.cs')),*sorted((ROOT/'small-api-benchmark').glob('*.csproj')),*sorted((ROOT/'small-api-benchmark').glob('*.json')),Path(__file__),ROOT/'global.json',ROOT/'NuGet.Config',ROOT/'Directory.Build.targets']
    if (ROOT/'tools/benchmark_small_api.py').exists():sources.append(ROOT/'tools/benchmark_small_api.py')
    for name in ('small_api_collector_evidence.py','probe_small_api_collector.py'):
        if (ROOT/'tools'/name).exists():sources.append(ROOT/'tools'/name)
    report={'observed_at_utc':datetime.now(timezone.utc).isoformat(),'engine_revision':lock['engine_revision'],'samples_source_revision':run(['git','rev-parse','HEAD']),'source_state':'uncommitted integration' if dirty else 'exact clean committed source','sdk':sdk,'source_sha256':{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},'status':'started','scope':'Public synthetic fixture conformance and build; not protected tenant/IdP, dedicated performance reference, supported-Windows or production qualification'}
    def save():(output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    save()
    try:
        run([args.dotnet,'--info'],'sdk-info.txt');artifacts=output/'artifacts';project=ROOT/'small-api-benchmark/SmallApi.Benchmark.csproj';prop='-p:EngineRoot='+str(engine)
        run([args.dotnet,'restore',project,'--locked-mode','--artifacts-path',artifacts,'--configfile',ROOT/'NuGet.Config',prop],'restore.txt')
        run([args.dotnet,'build',project,'-c','Release','--no-restore','--artifacts-path',artifacts,prop,'-p:UseSharedCompilation=false','-nr:false','-warnaserror'],'build.txt')
        assembly=artifacts/'bin/SmallApi.Benchmark/release/SmallApi.Benchmark.dll'
        deps=json.loads(assembly.with_suffix('.deps.json').read_text())
        if any(any(word in name.lower() for word in ['codeanalysis','codegeneration']) for name in deps['libraries']):raise ValueError('Compiler-only library in runtime graph')
        generated=list((artifacts/'obj').rglob('OperationRegistrations.g.cs'))
        if len(generated)!=1:raise ValueError('Expected one actual generated registry')
        (output/'OperationRegistrations.g.cs.txt').write_bytes(generated[0].read_bytes())
        report.update(assembly_sha256=hashlib.sha256(assembly.read_bytes()).hexdigest(),generated_registry_sha256=hashlib.sha256(generated[0].read_bytes()).hexdigest(),runtime_libraries=sorted(deps['libraries']))
        if not args.build_only:
            run([args.dotnet,assembly,'--mode=conformance','--output='+str(output/'conformance')],'conformance-run.txt')
            result=json.loads((output/'conformance/summary.json').read_text())
            if result['failed'] or result['status']!='passed':raise ValueError('Conformance failed; every raw result retained')
            report['conformance']=result
        report['status']='build-only' if args.build_only else 'passed'
    except Exception as error:
        report.update(status='failed',error=str(error));save();raise
    save();print(json.dumps({'status':report['status'],'source_state':report['source_state'],'output':str(output)}))

if __name__=='__main__':main()
