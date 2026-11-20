"""Retained locked Release build and experimental component contracts; no hosted-CI inference."""
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
    parser.add_argument('--output',required=True,help='New attempt directory; never overwritten')
    args=parser.parse_args()
    output=(ROOT/args.output).resolve()
    private=(ROOT/'.local').resolve()
    if not output.is_relative_to(private) or output==private: raise ValueError('Use a fresh directory beneath ignored Engine .local')
    output.mkdir(parents=True,exist_ok=False)
    artifacts=output/'artifacts'
    environment=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1')
    def run(command,log):
        result=subprocess.run(list(map(str,command)),cwd=ROOT,env=environment,capture_output=True)
        (output/log).write_bytes(result.stdout+result.stderr)
        if result.returncode: raise RuntimeError(f'Failed ({result.returncode}), see {output/log}')
        return result.stdout.decode('utf-8')
    revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    dirty=subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip()
    report={'observed_at_utc':datetime.now(timezone.utc).isoformat(),'engine_revision':revision,'source_state':'uncommitted integration' if dirty else 'exact clean committed source','scope':'Local experimental component and localhost adapter contracts; not supported-Windows, hosted CI, real IdP/provider, full workload/benchmark/production qualification','source_sha256':{},'tests':[],'status':'started'}
    for folder in ['src/Cehpalon.Engine.Core','src/Cehpalon.Engine.Composition','src/Cehpalon.Engine.CodeGeneration','src/Cehpalon.Engine.Identity.Contracts','src/Cehpalon.Engine.Authorization','src/Cehpalon.Engine.Identity.AspNetCore','src/Cehpalon.Engine.Identity.JwtBearer','src/Cehpalon.Engine.Tenancy','src/Cehpalon.Engine.Transports.Http','src/Cehpalon.Engine.Transports.GraphQL','src/Cehpalon.Engine.Tooling','Tests/Tooling.ContractTests','Tests/Http.ContractTests','Tests/GraphQL.ContractTests','Tests/Core.ContractTests','Tests/Composition.ContractTests','Tests/CodeGeneration.ContractTests','Tests/Identity.ContractTests','Tests/Access.ContractTests','Tests/AuthProfile.ContractTests','Tests/Jwe.ContractTests','Tests/KeyRing.ContractTests','Tests/Session.ContractTests','Tests/Observation.ContractTests','Tests/AuditTrail.ContractTests','Tests/AuditPreparation.ContractTests','Tests/TenantReadSet.ContractTests','Tests/Tenancy.ContractTests','Benchmarks/W1.Components','Benchmarks/Tenancy.Components','Benchmarks/Tooling.Components']:
        for path in sorted((ROOT/folder).rglob('*')):
            if not path.is_file() or {'bin','obj','evidence'}.intersection(path.relative_to(ROOT/folder).parts): continue
            if path.suffix in ('.cs','.csproj','.json','.py') or 'Templates' in path.relative_to(ROOT/folder).parts: report['source_sha256'][path.relative_to(ROOT).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    for filename in ['global.json','NuGet.Config','Directory.Packages.props','Cehpalon.Engine.slnx','tools/verify_w1.py']:
        report['source_sha256'][filename]=hashlib.sha256((ROOT/filename).read_bytes()).hexdigest()
    def save(): (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    save()
    try:
        report['sdk']=run([args.dotnet,'--version'],'sdk-version.txt').strip()
        if report['sdk']!=json.loads((ROOT/'global.json').read_text())['sdk']['version']: raise ValueError('SDK differs from global.json')
        run([args.dotnet,'--info'],'sdk-info.txt')
        run([args.dotnet,'restore','Cehpalon.Engine.slnx','--locked-mode','--configfile',ROOT/'NuGet.Config','--artifacts-path',artifacts],'restore.txt')
        run([args.dotnet,'build','Cehpalon.Engine.slnx','-c','Release','--no-restore','--artifacts-path',artifacts,'-p:UseSharedCompilation=false','-warnaserror'],'build.txt')
        for project in ['Core.ContractTests','Composition.ContractTests','CodeGeneration.ContractTests','Identity.ContractTests','Access.ContractTests','AuthProfile.ContractTests','Jwe.ContractTests','KeyRing.ContractTests','Session.ContractTests','Observation.ContractTests','AuditTrail.ContractTests','AuditPreparation.ContractTests','TenantReadSet.ContractTests','Tenancy.ContractTests','Http.ContractTests','GraphQL.ContractTests','Tooling.ContractTests']:
            result_path=output/(project+'.json')
            run([args.dotnet,artifacts/'bin'/project/'release'/(project+'.dll'),'--output='+str(result_path)],project+'.txt')
            test=json.loads(result_path.read_text())
            if test['failed'] or test['passed']<=0: raise ValueError('Not all tests passed: '+project)
            report['tests'].append({'project':project,'passed':test['passed'],'failed':test['failed'],'output':result_path.name,'output_sha256':hashlib.sha256(result_path.read_bytes()).hexdigest()})
        assembly=artifacts/'bin/CompilerFixture/release/CompilerFixture.dll'
        fixture=json.loads(run([args.dotnet,assembly],'compiler-fixture.json'))
        if fixture.get('passed') is not True: raise ValueError('Actual compiler consumer failed')
        deps=json.loads(assembly.with_suffix('.deps.json').read_text())
        if any(any(word in name.lower() for word in ('codeanalysis','codegeneration')) for name in deps['libraries']): raise ValueError('Compiler-only dependency leaked into runtime consumer')
        generated=list((artifacts/'obj/CompilerFixture').rglob('OperationRegistrations.g.cs'))
        if len(generated)!=1: raise ValueError('Expected emitted compiler fixture registry')
        (output/'compiler-fixture-generated.g.cs.txt').write_bytes(generated[0].read_bytes())
        report.update(status='passed',total_passed=sum(x['passed'] for x in report['tests']),compiler_fixture=fixture,consumer_runtime_libraries=sorted(deps['libraries']),generated_registry_sha256=hashlib.sha256(generated[0].read_bytes()).hexdigest())
    except Exception as error:
        report.update(status='failed',error=str(error)); save(); raise
    save()
    print(json.dumps({'status':report['status'],'total_passed':report['total_passed'],'source_state':report['source_state'],'output':str(output)}))
if __name__=='__main__': main()
