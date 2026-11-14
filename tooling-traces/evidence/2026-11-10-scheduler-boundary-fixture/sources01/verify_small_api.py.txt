"""Locked external-consumer proof. Retain each attempt; never publish fixture keys/tokens."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dotnet', required=True)
    parser.add_argument('--engine-root', default=str(ROOT.parent/'Cehpalon-Engine'))
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    engine = Path(args.engine_root).resolve()
    output = (ROOT/args.output).resolve()
    private = (ROOT/'.local').resolve()
    if not output.is_relative_to(private) or output == private:
        raise ValueError('Use a fresh directory beneath ignored Samples .local')
    output.mkdir(parents=True, exist_ok=False)
    def run(command, log=None, cwd=ROOT):
        result = subprocess.run(list(map(str, command)), cwd=cwd, env=dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1'), capture_output=True)
        if log: (output/log).write_bytes(result.stdout+result.stderr)
        if result.returncode: raise RuntimeError(f'Failed ({result.returncode}); retained log {log}')
        return result.stdout.decode('utf-8').strip()
    lock = json.loads((ROOT/'small-api/engine-lock.json').read_text())
    if not re.fullmatch('[0-9a-f]{40}', lock['engine_revision']): raise ValueError('Actual full Engine SHA required')
    if run(['git','rev-parse','HEAD'], cwd=engine) != lock['engine_revision']: raise ValueError('Engine HEAD differs from consumer lock')
    if run(['git','status','--porcelain'], cwd=engine): raise ValueError('Require clean committed Engine source')
    sdk = run([args.dotnet, '--version'], 'sdk-version.txt')
    if sdk != lock['sdk']: raise ValueError('SDK differs from lock')
    manifest = {'observed_at_utc':datetime.now(timezone.utc).isoformat(), 'engine_revision':lock['engine_revision'], 'sdk':sdk, 'status':'started', 'scope':lock['scope'], 'source_sha256':{}}
    sources = [*sorted((ROOT/'small-api').glob('*.cs')), ROOT/'small-api/SmallApi.Consumer.csproj', ROOT/'small-api/packages.lock.json', ROOT/'small-api/engine-lock.json', Path(__file__), ROOT/'global.json', ROOT/'NuGet.Config']
    for path in sources: manifest['source_sha256'][path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    def save(): (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
    save()
    try:
        run([args.dotnet,'--info'],'sdk-info.txt')
        artifacts = output/'artifacts'
        project = ROOT/'small-api/SmallApi.Consumer.csproj'
        engine_property = '-p:EngineRoot='+str(engine)
        run([args.dotnet,'restore',project,'--locked-mode','--artifacts-path',artifacts,'--configfile',ROOT/'NuGet.Config',engine_property],'restore.txt')
        run([args.dotnet,'build',project,'-c','Release','--no-restore','--artifacts-path',artifacts,engine_property,'-p:UseSharedCompilation=false','-warnaserror'],'build.txt')
        assembly = artifacts/'bin/SmallApi.Consumer/release/SmallApi.Consumer.dll'
        run([args.dotnet,assembly,'--output='+str(output/'consumer.json')],'run.txt')
        result = json.loads((output/'consumer.json').read_text())
        if result['failed'] or result['passed'] <= 0: raise ValueError('Consumer checks failed')
        deps = json.loads(assembly.with_suffix('.deps.json').read_text())
        if any(any(word in name.lower() for word in ('codeanalysis','codegeneration')) for name in deps['libraries']): raise ValueError('Build-time generator leaked into runtime graph')
        generated = list((artifacts/'obj').rglob('OperationRegistrations.g.cs'))
        if len(generated) != 1: raise ValueError('Expected one emitted generated registry')
        (output/'OperationRegistrations.g.cs.txt').write_bytes(generated[0].read_bytes())
        manifest.update(status='passed', checks=result['passed'], runtime_libraries=sorted(deps['libraries']), generated_registry_sha256=hashlib.sha256(generated[0].read_bytes()).hexdigest(), assembly_sha256=hashlib.sha256(assembly.read_bytes()).hexdigest())
    except Exception as error:
        manifest.update(status='failed',error=str(error)); save(); raise
    save()
    print(json.dumps({'status':manifest['status'],'checks':manifest['checks'],'output':str(output)}))

if __name__ == '__main__': main()
