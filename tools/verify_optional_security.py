"""Locked local security consumer proof. Retain failed attempts; no benchmark or real IdP claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dotnet', required=True)
    p.add_argument('--engine-root', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--initialize-lock', action='store_true')
    a = p.parse_args()
    output = (ROOT / a.output).resolve()
    if not output.is_relative_to(ROOT / '.local'):
        raise ValueError('Use a fresh ignored Samples .local directory')
    output.mkdir(parents=True, exist_ok=False)
    engine = Path(a.engine_root).resolve()
    env = dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1')
    report = {'status':'started', 'engine_revision':subprocess.check_output(['git','-C',str(engine),'rev-parse','HEAD'],text=True).strip(),
              'engine_dirty':bool(subprocess.check_output(['git','-C',str(engine),'status','--porcelain'],text=True).strip()),
              'consumer_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              'consumer_source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--','security-api','tools/verify_optional_security.py'],cwd=ROOT,text=True).strip()),
              'scope':'Local generated Core/Composition HTTP/GraphQL/JWT RBAC/ABAC/audit fixture; no supported-host, durable provider or benchmark qualification',
              'source_sha256':{}}
    for root in [ROOT/'security-api', engine/'src']:
        for file in sorted(root.rglob('*')):
            if file.is_file() and not {'obj','bin','evidence','.local'}.intersection(file.relative_to(root).parts) and file.suffix in ('.cs','.csproj','.json','.txt'):
                key = ('consumer/' if root==ROOT/'security-api' else 'engine/')+file.relative_to(root).as_posix()
                report['source_sha256'][key]=hashlib.sha256(file.read_bytes()).hexdigest()
    for file in [Path(__file__).resolve(), ROOT/'global.json', ROOT/'NuGet.Config', ROOT/'Directory.Build.targets', ROOT/'build/SampleRunArguments.cs', engine/'global.json', engine/'NuGet.Config', engine/'Directory.Packages.props']:
        prefix = 'engine/' if file.is_relative_to(engine) else 'consumer/'
        relative = file.relative_to(engine if prefix=='engine/' else ROOT).as_posix()
        report['source_sha256'][prefix+relative]=hashlib.sha256(file.read_bytes()).hexdigest()
    (output/'frozen-verifier.py.txt').write_bytes(Path(__file__).read_bytes())
    artifacts=output/'artifacts'
    def run(args, name):
        result=subprocess.run([a.dotnet,*map(str,args)],cwd=ROOT,env=env,capture_output=True)
        (output/name).write_bytes(result.stdout+result.stderr)
        if result.returncode: raise RuntimeError('Failed '+name)
        return result.stdout.decode('utf-8')
    def save(): (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    save()
    try:
        report['sdk']=run(['--version'],'sdk.txt').strip()
        if report['sdk']!=json.loads((engine/'global.json').read_text())['sdk']['version']: raise ValueError('SDK mismatch')
        common=['--artifacts-path',artifacts,'-p:EngineRoot='+str(engine)]
        run(['restore','security-api/SecurityApi.Consumer.csproj','--configfile',ROOT/'NuGet.Config',*common,*([] if a.initialize_lock else ['--locked-mode'])],'restore.txt')
        # First lock initialization is explicit; freeze the resulting graph before compilation.
        lock=ROOT/'security-api/packages.lock.json'
        report['source_sha256']['consumer/packages.lock.json']=hashlib.sha256(lock.read_bytes()).hexdigest()
        save()
        run(['build','security-api/SecurityApi.Consumer.csproj','-c','Release','--no-restore',*common,'-p:UseSharedCompilation=false','-warnaserror'],'build.txt')
        dll=artifacts/'bin/SecurityApi.Consumer/release/SecurityApi.Consumer.dll'
        run([dll,'--output='+str(output/'tests.json')],'run.txt')
        tests=json.loads((output/'tests.json').read_text())
        if tests['failed'] or tests['passed']<=0: raise ValueError('Consumer checks failed')
        emitted=list((artifacts/'obj/SecurityApi.Consumer').rglob('OperationRegistrations.g.cs'))
        if len(emitted)!=1: raise ValueError('Expected actual typed generated registry')
        (output/'generated.g.cs.txt').write_bytes(emitted[0].read_bytes())
        deps=json.loads(dll.with_suffix('.deps.json').read_text())
        if any('CodeAnalysis' in k or 'CodeGeneration' in k for k in deps['libraries']): raise ValueError('Compiler dependency leaked')
        report.update(status='passed',passed=tests['passed'],failed=tests['failed'],runtime_libraries=sorted(deps['libraries']),
                      registry_sha256=hashlib.sha256(emitted[0].read_bytes()).hexdigest(),tests_sha256=hashlib.sha256((output/'tests.json').read_bytes()).hexdigest())
    except Exception as e:
        report.update(status='failed',error=str(e));save();raise
    save()
    print(json.dumps({'status':report['status'],'passed':report['passed'],'output':str(output)}))

if __name__=='__main__': main()
