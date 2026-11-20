"""Frozen synthetic Windows timer/publication probes, separate from HTTPS acceptance."""
import argparse
import json
import os
from pathlib import Path
import shutil

from observe_https_metrics import ROOT, fresh, read, save, sha
from trace_https_warmup import Owned, attach, finish, fixture, replace_once, run_command

PROTOCOL=ROOT.parent/'Cehpalon-Engine-Docs/internal/validation/windows-timer-publication.md'


def freeze(output):
    directory=output/'frozen';directory.mkdir();hashes={}
    files=[ROOT/'tooling-small-api/metrics-trace/TimerProbe.cs',Path(__file__),
           ROOT/'tools/analyze_timer_publication.py',ROOT/'tools/test_timer_publication.py',
           ROOT/'tools/trace_https_warmup.py',ROOT/'tools/analyze_https_warmup.py',PROTOCOL]
    for path in files:
        shutil.copyfile(path,directory/path.name);hashes[path.name]=sha(path)
    save(directory/'SHA256.json',hashes)
    return hashes


def prepare(args):
    output=fresh(args.output);report={'status':'started'};save(output/'manifest.json',report)
    try:
        if os.name!='nt':raise ValueError('Windows-only live probes')
        report['frozen_sha256']=freeze(output)
        base=(ROOT/args.base).resolve();old=read(base/'manifest.json')
        if old['status']!='prepared' or old['engine_revision']!='5f8f252e901e85c50d7fc6f4b760e457965ce3bb':raise ValueError('Wrong diagnostic source')
        consumer=output/'consumer';consumer.mkdir();original=output/'original';original.mkdir()
        for name,digest in old['source_sha256'].items():
            source=base/'consumer'/name
            if sha(source)!=digest:raise ValueError('Prepared source drift')
            shutil.copyfile(source,consumer/name);shutil.copyfile(source,original/name)
        for name,digest in old['binary_sha256'].items():
            if sha(base/name)!=digest:raise ValueError('Prior diagnostic binary drift')
        shutil.copyfile(base/'manifest.json',output/'base-manifest.json')
        shutil.copytree(Path(old['tool']).parent,output/'tool')
        shutil.copyfile(ROOT/'tooling-small-api/metrics-trace/TimerProbe.cs',consumer/'TimerProbe.cs')
        path=consumer/'Entry.cs';text=path.read_text(encoding='utf-8')
        text=replace_once(text,'"trace-fixture" => await Diagnostic.Fixture(options),',
                          '"trace-fixture" => await Diagnostic.Fixture(options),\n                "timer-probe" => await TimerProbe.Run(options),')
        path.write_text(text,encoding='utf-8',newline='\n')
        path=consumer/'Consumer.csproj';text=path.read_text(encoding='utf-8')
        text=replace_once(text,'</Project>','<ItemGroup><Compile Include="TimerProbe.cs"/></ItemGroup></Project>')
        path.write_text(text,encoding='utf-8',newline='\n')
        for name in old['source_sha256']:
            if name not in ['Entry.cs','Consumer.csproj'] and sha(consumer/name)!=old['source_sha256'][name]:raise ValueError('Unapproved source change')
        sdk=__import__('subprocess').check_output([args.dotnet,'--version'],cwd=consumer,text=True).strip()
        if sdk!='11.0.100-rc.3.26522.148':raise ValueError('Wrong SDK')
        artifacts=output/'artifacts';project=consumer/'Consumer.csproj'
        run_command([args.dotnet,'restore',project,'--locked-mode','--configfile',consumer/'NuGet.Config','--artifacts-path',artifacts],consumer,output/'restore')
        run_command([args.dotnet,'build',project,'-c','Release','--no-restore','--artifacts-path',artifacts,'-p:UseSharedCompilation=false','-warnaserror'],consumer,output/'build')
        assembly=next((artifacts/'bin/Consumer/release').glob('PortableConsumer.*.dll'))
        registry=list((artifacts/'obj/Consumer').rglob('OperationRegistrations.g.cs'))
        if len(registry)!=1:raise ValueError('Registry count differs')
        prior_registry=next((base/'consumer-artifacts/obj/Consumer').rglob('OperationRegistrations.g.cs'))
        if registry[0].read_bytes()!=prior_registry.read_bytes():raise ValueError('Generated registry differs')
        shutil.copyfile(registry[0],output/'OperationRegistrations.g.cs.txt')
        report.update(status='prepared',engine_revision=old['engine_revision'],sdk=sdk,dotnet=args.dotnet,
            assembly=str(assembly),tool=str(output/'tool/RuntimeTrace.dll'),
            source_sha256={p.name:sha(p) for p in consumer.iterdir() if p.is_file()},
            binary_sha256={p.relative_to(output).as_posix():sha(p) for directory in [assembly.parent,output/'tool'] for p in directory.rglob('*') if p.is_file()})
    except Exception as error:
        report.update(status='failed',failure_type=type(error).__name__);raise
    finally:save(output/'manifest.json',report)
    print(json.dumps({'status':report['status'],'output':str(output)}))


def capture(prepared,folder,observed,mode):
    folder.mkdir();target=collector=None;report={'status':'started','observed':observed,'probe_mode':mode}
    try:
        target=Owned([prepared['dotnet'],prepared['assembly'],'timer-probe','--profile','conformance',
                      '--output',folder/'timer-probe.json','--diagnostic-trace',str(observed).lower(),'--probe-mode',mode],
                     Path(prepared['assembly']).parent,folder/'target-stderr.txt')
        if observed:
            collector,metadata=attach(prepared,folder,target,'timer-probe')
            finish(prepared,folder,target,collector,'timer-probe',metadata);report['capture']=metadata
            if metadata['exit']!=0:raise RuntimeError('Observed probe failed; partial data retained')
        elif target.process.wait(timeout=45)!=0:raise RuntimeError('Control probe failed; partial data retained')
        report['status']='captured'
    except Exception as error:
        report.update(status='failed',failure_type=type(error).__name__);raise
    finally:
        for child in [target,collector]:
            if child is not None:child.close()
        save(folder/'capture.json',report)


def run(args):
    output=fresh(args.output);base=(ROOT/args.prepared).resolve();prepared=read(base/'manifest.json')
    report={'status':'started','mode':args.mode,'cases':[],'qualification':False}
    save(output/'manifest.json',report)
    try:
        if prepared['status']!='prepared':raise ValueError('Preparation incomplete')
        report['frozen_sha256']=freeze(output)
        if report['frozen_sha256']!=prepared['frozen_sha256']:raise ValueError('Capture source changed')
        for name,digest in prepared['source_sha256'].items():
            if sha(base/'consumer'/name)!=digest:raise ValueError('Source changed')
        for name,digest in prepared['binary_sha256'].items():
            if sha(base/name)!=digest:raise ValueError('Binary changed')
        report['prepared_manifest_sha256']=sha(base/'manifest.json')
        if args.mode=='compare':
            if not args.preflight:raise ValueError('Validated preflight is required')
            preflight=read((ROOT/args.preflight).resolve())
            if preflight['status']!='validated' or preflight['mode']!='preflight' or preflight['prepared_manifest_sha256']!=report['prepared_manifest_sha256']:
                raise ValueError('Preflight belongs to different or invalid preparation')
            report['preflight_analysis_sha256']=sha((ROOT/args.preflight).resolve())
        shutil.copyfile(base/'manifest.json',output/'preparation-manifest.json')
        cases=([('positive-fixture',True),('control',False),('trace',True)] if args.mode=='preflight' else
               [(f'{pair:02d}-{"trace" if observed else "control"}',observed) for pair in range(1,5)
                for observed in ([False,True] if pair%2 else [True,False])])
        for name,observed in cases:
            item={'name':name,'status':'started'};report['cases'].append(item);save(output/'manifest.json',report)
            if name=='positive-fixture':fixture(prepared,output/name,True)
            else:capture(prepared,output/name,observed,'conformance' if args.mode=='preflight' else 'compare')
            item['status']='captured';save(output/'manifest.json',report)
        report['status']='captured'
    except Exception as error:
        report.update(status='failed',failure_type=type(error).__name__);raise
    finally:save(output/'manifest.json',report)
    print(json.dumps({'status':report['status'],'cases':len(report['cases'])}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='action',required=True)
    p=commands.add_parser('prepare');p.add_argument('--base',required=True);p.add_argument('--dotnet',required=True);p.add_argument('--output',required=True)
    p=commands.add_parser('run');p.add_argument('--prepared',required=True);p.add_argument('--mode',choices=['preflight','compare'],required=True);p.add_argument('--preflight');p.add_argument('--output',required=True)
    args=parser.parse_args();(prepare if args.action=='prepare' else run)(args)
