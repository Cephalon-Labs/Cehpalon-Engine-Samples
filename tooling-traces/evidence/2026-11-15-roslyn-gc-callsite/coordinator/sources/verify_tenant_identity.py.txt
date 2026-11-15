"""Build/run the pinned in-process consumer, retaining every attempt directory."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def run(command,cwd,log=None):
    environment=dict(os.environ,DOTNET_NOLOGO='1',DOTNET_CLI_TELEMETRY_OPTOUT='1')
    result=subprocess.run(list(map(str,command)),cwd=cwd,env=environment,capture_output=True)
    if log: log.write_bytes(result.stdout+result.stderr)
    if result.returncode: raise RuntimeError(f'Operation failed ({result.returncode}); retained log: {log}')
    return result.stdout.decode('utf-8').strip()
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--dotnet',required=True)
    parser.add_argument('--engine-root',default=str(ROOT.parent/'Cehpalon-Engine'))
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    engine=Path(args.engine_root).resolve()
    lock=json.loads((ROOT/'tenant-identity/engine-lock.json').read_text())
    if not re.fullmatch('[0-9a-f]{40}',lock['engine_revision']): raise ValueError('Engine revision must be an actual committed full SHA')
    if run(['git','rev-parse','HEAD'],engine)!=lock['engine_revision']: raise ValueError('Engine HEAD differs from consumer lock')
    if run(['git','status','--porcelain'],engine): raise ValueError('Engine working tree must be clean before consumer restore/build')
    if run([args.dotnet,'--version'],ROOT)!=lock['sdk']: raise ValueError('SDK differs from consumer lock')
    output=(ROOT/args.output).resolve()
    private=(ROOT/'.local').resolve()
    if not output.is_relative_to(private) or output==private: raise ValueError('Use a fresh result directory inside ignored Samples .local')
    output.mkdir(parents=True,exist_ok=False)
    project=ROOT/'tenant-identity/TenantIdentity.Consumer.csproj'
    artifact=output/'artifacts'
    manifest={'observed_at_utc':datetime.now(timezone.utc).isoformat(),'engine_revision':lock['engine_revision'],'sdk':lock['sdk'],'scope':lock['scope'],'source_sha256':{},'status':'started'}
    for name in ['tenant-identity/TenantIdentity.Consumer.csproj','tenant-identity/Program.cs','tenant-identity/engine-lock.json','tenant-identity/packages.lock.json','tools/verify_tenant_identity.py','global.json','NuGet.Config']:
        manifest['source_sha256'][name]=sha(ROOT/name)
    for path in sorted((ROOT/'tenant-identity/profiles').glob('*.json')): manifest['source_sha256'][str(path.relative_to(ROOT))]=sha(path)
    manifest_path=output/'manifest.json'
    def save(): manifest_path.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
    save()
    try:
        engine_property='-p:EngineRoot='+str(engine)
        run([args.dotnet,'restore',project,'--locked-mode','--artifacts-path',artifact,'--configfile',ROOT/'NuGet.Config',engine_property],ROOT,output/'restore.txt')
        run([args.dotnet,'build',project,'-c','Release','--no-restore','--artifacts-path',artifact,engine_property,'-p:UseSharedCompilation=false'],ROOT,output/'build.txt')
        assembly=artifact/'bin/TenantIdentity.Consumer/release/TenantIdentity.Consumer.dll'
        run([args.dotnet,assembly,'--output='+str(output/'consumer.json')],ROOT,output/'run.txt')
        deps=json.loads(assembly.with_suffix('.deps.json').read_text())
        forbidden=[name for name in deps['libraries'] if any(word in name.lower() for word in ('codeanalysis','codegeneration'))]
        if forbidden: raise ValueError('Build-time-only components leaked into runtime graph: '+str(forbidden))
        generated=list((artifact/'obj').rglob('OperationRegistrations.g.cs'))
        if len(generated)!=1: raise ValueError('Expected exactly one emitted registry source')
        (output/'OperationRegistrations.g.cs').write_bytes(generated[0].read_bytes())
        result=json.loads((output/'consumer.json').read_text())
        if result['failed'] or result['passed']!=10: raise ValueError('Consumer checks did not all pass')
        manifest.update(status='passed',checks=result['passed'],runtime_libraries=sorted(deps['libraries']),generated_registry_sha256=sha(generated[0]))
    except Exception as error:
        manifest.update(status='failed',error=str(error)); save(); raise
    save()
    print(json.dumps({'status':manifest['status'],'checks':manifest['checks'],'output':str(output)}))
if __name__=='__main__': main()
