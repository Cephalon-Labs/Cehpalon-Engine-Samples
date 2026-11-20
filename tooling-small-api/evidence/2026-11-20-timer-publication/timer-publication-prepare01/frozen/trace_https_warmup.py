"""Bounded owned Windows EventPipe investigation; never benchmark qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading

from observe_https_metrics import Child, fresh, read, save, sha, ROOT

SOURCE = ROOT / 'tooling-small-api/metrics-trace'
PROTOCOL = ROOT.parent / 'Cehpalon-Engine-Docs/internal/validation/windows-warmup-drops.md'


def environment(source):
    disabled = {(prefix + name).casefold() for prefix in ['DOTNET_', 'COMPlus_']
                for name in ['EnableDiagnostics', 'EnableDiagnostics_IPC']}
    aliases = {(prefix + name).casefold() for prefix in ['DOTNET_', 'COMPlus_']
               for name in ['DiagnosticPorts', 'DefaultDiagnosticPortSuspend']}
    if any(k.casefold() in disabled and v.casefold() in ['0', 'false'] for k, v in source.items()):
        raise ValueError('Inherited policy disables diagnostics; not overridden')
    removed = [k for k in source if k.casefold() in aliases]
    result = {k: v for k, v in source.items() if k.casefold() not in aliases}
    result.update(DOTNET_DefaultDiagnosticPortSuspend='0', DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1')
    return result, removed


class Owned(Child):
    def __init__(self, argv, cwd, stderr):
        self.err = stderr.open('wb')
        env, self.removed_aliases = environment(dict(os.environ))
        self.process = subprocess.Popen(list(map(str, argv)), cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.err, text=True, encoding='utf-8', bufsize=1, env=env)
        self.queue = queue.Queue()
        def reader():
            for line in self.process.stdout:
                self.queue.put(line)
            self.queue.put(None)
        self.reader = threading.Thread(target=reader, daemon=True); self.reader.start()


def freeze(output):
    directory = output / 'frozen'; directory.mkdir()
    paths = [*sorted(SOURCE.iterdir()), Path(__file__), ROOT / 'tools/analyze_https_warmup.py',
             ROOT / 'tools/test_https_warmup.py', PROTOCOL]
    hashes = {}
    for path in paths:
        if path.is_file():
            shutil.copyfile(path, directory / path.name); hashes[path.name] = sha(path)
    save(directory / 'SHA256.json', hashes)
    return hashes


def run_command(argv, cwd, prefix):
    result = subprocess.run(list(map(str, argv)), cwd=cwd, capture_output=True, timeout=240, env=environment(dict(os.environ))[0])
    prefix.with_suffix('.stdout.txt').write_bytes(result.stdout)
    prefix.with_suffix('.stderr.txt').write_bytes(result.stderr)
    save(prefix.with_suffix('.command.json'), {'argv': list(map(str, argv)), 'cwd': str(cwd), 'exit': result.returncode})
    if result.returncode:
        raise RuntimeError('Preparation/decoding failed; exact command and output retained')


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Reviewed source anchor differs')
    return text.replace(before, after)


def prepare(args):
    output = fresh(args.output); report = {'status': 'started'}; save(output / 'manifest.json', report)
    try:
        if os.name != 'nt': raise ValueError('Windows-only capture')
        report['frozen_sha256'] = freeze(output)
        base = (ROOT / args.base).resolve(); previous = read(base / 'manifest.json')
        if previous['status'] != 'prepared': raise ValueError('Expected exact prepared generated source')
        consumer = output / 'consumer'; consumer.mkdir()
        original = output / 'original'; original.mkdir()
        for name, digest in previous['source_files_sha256'].items():
            path = base / 'consumer' / name
            if sha(path) != digest: raise ValueError('Prepared source changed')
            shutil.copyfile(path, consumer / name); shutil.copyfile(path, original / name)
        shutil.copyfile(base / 'manifest.json', output / 'base-manifest.json')
        shutil.copyfile(SOURCE / 'Diagnostic.cs', consumer / 'Diagnostic.cs')
        p = consumer / 'Entry.cs'; text = p.read_text(encoding='utf-8')
        text = replace_once(text, 'if (File.Exists(options["--output"])) throw new IOException();',
            'if (File.Exists(options["--output"])) throw new IOException();\n'
            '            Diagnostic.Enabled = options.GetValueOrDefault("--diagnostic-trace") == "true";\n'
            '            if (Diagnostic.Enabled) await Diagnostic.Begin(args[0], options["--output"]);')
        text = replace_once(text, 'return args[0] switch', 'var result = args[0] switch')
        text = replace_once(text, '"client" => await Client.Run(options),',
                            '"client" => await Client.Run(options),\n                "trace-fixture" => await Diagnostic.Fixture(options),')
        text = replace_once(text, '            };\n        }',
                            '            };\n            if (Diagnostic.Enabled) await Diagnostic.Finish();\n            return result;\n        }')
        p.write_text(text, encoding='utf-8', newline='\n')
        p = consumer / 'Client.cs'; text = p.read_text(encoding='utf-8')
        text = replace_once(text, 'Request(int lane, bool denied = false)',
                            'Request(int lane, bool denied = false, int traceIndex = -1, int tracePhase = 0)')
        text = replace_once(text, '            return request;',
                            '            if (traceIndex >= 0) request.Headers.Add("X-Cehpalon-Trace", (tracePhase * 10000 + traceIndex).ToString(System.Globalization.CultureInfo.InvariantCulture));\n            return request;')
        text = replace_once(text, '            var rows = new Row[count];',
                            '            var phase = name == "warmup" ? 1 : 2;\n            var delayId = 0;\n            var rows = new Row[count];')
        text = replace_once(text, '                var sent = Entry.Now;',
                            '                var sent = Entry.Now;\n                Diagnostic.Mark(20, phase, i, lane);')
        text = replace_once(text, 'using var request = Request(lane);',
                            'using var request = Request(lane, traceIndex: i, tracePhase: phase);')
        text = replace_once(text, '                    var result = await Validate(response, lane);',
                            '                    Diagnostic.Mark(22, phase, i, lane);\n                    var result = await Validate(response, lane);\n                    Diagnostic.Mark(23, phase, i, lane);')
        text = replace_once(text, 'finally { Volatile.Write(ref busy[lane], 0); }',
                            'finally { Diagnostic.Mark(24, phase, i, lane); Volatile.Write(ref busy[lane], 0); Diagnostic.Mark(25, phase, i, lane); }')
        text = replace_once(text, 'while (Entry.Now < due) await Task.Delay(1);',
                            'while (Entry.Now < due) { var delay = ++delayId; Diagnostic.Mark(10, phase, delay, i); await Task.Delay(1); Diagnostic.Mark(11, phase, delay, i); }')
        text = replace_once(text, '                if (Interlocked.CompareExchange(ref busy[lane], 1, 0) != 0)',
                            '                Diagnostic.Mark(19, phase, i, lane);\n                if (Interlocked.CompareExchange(ref busy[lane], 1, 0) != 0)')
        text = replace_once(text, '                    rows[i] = new(i, lane, due, 0, Entry.Now, 0, 0, "dropped");',
                            '                    rows[i] = new(i, lane, due, 0, Entry.Now, 0, 0, "dropped");\n                    Diagnostic.Mark(21, phase, i, lane);')
        p.write_text(text, encoding='utf-8', newline='\n')
        p = consumer / 'Consumer.csproj'; text = p.read_text(encoding='utf-8')
        text = replace_once(text, '</Project>', '<PropertyGroup><AllowUnsafeBlocks>true</AllowUnsafeBlocks></PropertyGroup><ItemGroup><Compile Include="Diagnostic.cs"/></ItemGroup></Project>')
        p.write_text(text, encoding='utf-8', newline='\n')
        for name in ['FixtureHost.cs', 'Catalog.cs', 'ContractExport.cs']:
            if sha(consumer / name) != previous['source_files_sha256'][name]: raise ValueError('Business source changed')
        sdk = subprocess.check_output([args.dotnet, '--version'], cwd=consumer, text=True).strip()
        if sdk != '11.0.100-rc.3.26522.148': raise ValueError('Pinned SDK differs')
        for label, project, artifacts in [('consumer', consumer / 'Consumer.csproj', output / 'consumer-artifacts'),
                                           ('tool', SOURCE / 'RuntimeTrace.csproj', output / 'tool-artifacts')]:
            run_command([args.dotnet, 'restore', project, '--locked-mode', '--configfile', consumer / 'NuGet.Config', '--artifacts-path', artifacts], consumer, output / (label + '-restore'))
            run_command([args.dotnet, 'build', project, '-c', 'Release', '--no-restore', '--artifacts-path', artifacts, '-p:UseSharedCompilation=false', '-warnaserror'], consumer, output / (label + '-build'))
        assembly = next((output / 'consumer-artifacts/bin/Consumer/release').glob('PortableConsumer.*.dll'))
        tool = output / 'tool-artifacts/bin/RuntimeTrace/release/RuntimeTrace.dll'
        report.update(status='prepared', sdk=sdk, engine_revision=previous['engine_revision'], dotnet=args.dotnet,
            assembly=str(assembly), tool=str(tool), source_sha256={p.name: sha(p) for p in consumer.iterdir() if p.is_file()},
            binary_sha256={str(p.relative_to(output)): sha(p) for directory in [assembly.parent, tool.parent] for p in directory.rglob('*') if p.is_file()})
    except Exception as error:
        report.update(status='failed', failure_type=type(error).__name__); raise
    finally:
        save(output / 'manifest.json', report)
    print(json.dumps({'status': 'prepared', 'output': str(output)}))


def launch(prepared, folder, role, profile, observed, extra=()):
    return Owned([prepared['dotnet'], prepared['assembly'], role, '--profile', profile,
                  '--output', folder / (role + '.json'), '--diagnostic-trace', str(observed).lower(), *extra],
                 Path(prepared['assembly']).parent, folder / (role + '-stderr.txt'))


def attach(prepared, folder, target, role):
    ready = target.receive('trace-ready')
    if ready['pid'] != target.process.pid or target.process.poll() is not None: raise ValueError('Owned target identity differs')
    collector = Owned([prepared['dotnet'], prepared['tool'], 'collect', '--pid', str(target.process.pid), '--output', folder / (role + '.nettrace')],
                      Path(prepared['tool']).parent, folder / (role + '-collector-stderr.txt'))
    attached = collector.receive('attached'); target.send('CAPTURE')
    return collector, {'ready': ready, 'attached': attached, 'removed_aliases': target.removed_aliases}


def finish(prepared, folder, target, collector, role, metadata):
    metadata['finished'] = target.receive('trace-finished')
    collector.send('STOP'); metadata['collected'] = collector.receive('collected')
    if collector.process.wait(timeout=20) != 0: raise RuntimeError('Collector failed')
    target.send('RELEASE'); metadata['exit'] = target.process.wait(timeout=15)
    run_command([prepared['dotnet'], prepared['tool'], 'analyze', '--trace', folder / (role + '.nettrace'),
                 '--pid', str(target.process.pid), '--output', folder / (role + '-events')], folder, folder / (role + '-decode'))


def fixture(prepared, folder, observed):
    folder.mkdir(); target = collector = None; report = {'status': 'started', 'observed': observed}
    try:
        target = launch(prepared, folder, 'trace-fixture', 'conformance', observed)
        if observed:
            collector, metadata = attach(prepared, folder, target, 'trace-fixture')
            finish(prepared, folder, target, collector, 'trace-fixture', metadata); report['capture'] = metadata
        else:
            if target.process.wait(timeout=45) != 0: raise RuntimeError('Control fixture failed')
        report['status'] = 'captured'
    finally:
        for child in [target, collector]:
            if child is not None: child.close()
        save(folder / 'capture.json', report)


def warmup(prepared, folder, enabled, profile):
    folder.mkdir(); children = []; report = {'status': 'started', 'listener': enabled, 'profile': profile, 'kernel_scheduler': False}
    try:
        host = launch(prepared, folder, 'host', profile, True, ['--tenant', 'false', '--listener', str(enabled).lower()]); children.append(host)
        hc, hm = attach(prepared, folder, host, 'host'); children.append(hc)
        private = host.receive('ready')
        report['host_environment'] = private['environment']
        client = launch(prepared, folder, 'client', profile, True); children.append(client)
        cc, cm = attach(prepared, folder, client, 'client'); children.append(cc)
        client.send(json.dumps({k: private[k] for k in ['address', 'root', 'alice', 'bob']})); private.clear()
        report['warmup_signal'] = client.receive('warmed')
        client.send('ABORT'); report['persisted'] = client.receive('persisted')
        finish(prepared, folder, client, cc, 'client', cm)
        host.send('STOP'); report['stopped'] = host.receive('stopped')
        finish(prepared, folder, host, hc, 'host', hm)
        report.update(status='captured', client_capture=cm, host_capture=hm)
    finally:
        for child in reversed(children): child.close()
        save(folder / 'capture.json', report)


def run(args):
    output = fresh(args.output); base = (ROOT / args.prepared).resolve(); prepared = read(base / 'manifest.json')
    report = {'status': 'started', 'mode': args.mode, 'cases': [], 'qualification': False}
    save(output / 'manifest.json', report)
    try:
        report['frozen_sha256'] = freeze(output)
        if report['frozen_sha256'] != prepared['frozen_sha256']: raise ValueError('Prepared capture source changed')
        for name, digest in prepared['source_sha256'].items():
            if sha(base / 'consumer' / name) != digest: raise ValueError('Diagnostic source changed')
        for name, digest in prepared['binary_sha256'].items():
            if sha(base / name) != digest: raise ValueError('Diagnostic binary changed')
        shutil.copyfile(base / 'manifest.json', output / 'preparation-manifest.json')
        cases = ([(f'{pair:02d}-{"trace" if enabled else "control"}', enabled) for pair in range(1, 5)
                  for enabled in ([False, True] if pair % 2 else [True, False])] if args.mode == 'fixtures'
                 else [('conformance', True)] if args.mode == 'conformance'
                 else [(f'{i:02d}-{"listener" if enabled else "baseline"}', enabled) for i, enabled in enumerate([False, True, True, False], 1)])
        for name, enabled in cases:
            item = {'name': name, 'status': 'started'}; report['cases'].append(item); save(output / 'manifest.json', report)
            if args.mode == 'fixtures': fixture(prepared, output / name, enabled)
            else: warmup(prepared, output / name, enabled, 'conformance' if args.mode == 'conformance' else 'measure')
            item['status'] = 'captured'; save(output / 'manifest.json', report)
        report['status'] = 'captured'
    except Exception as error:
        report.update(status='failed', failure_type=type(error).__name__); raise
    finally:
        save(output / 'manifest.json', report)
    print(json.dumps({'status': report['status'], 'cases': len(cases)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='action', required=True)
    p = commands.add_parser('prepare'); p.add_argument('--base', required=True); p.add_argument('--dotnet', required=True); p.add_argument('--output', required=True)
    p = commands.add_parser('run'); p.add_argument('--prepared', required=True); p.add_argument('--output', required=True); p.add_argument('--mode', choices=['fixtures', 'conformance', 'warmups'], required=True)
    args = parser.parse_args(); (prepare if args.action == 'prepare' else run)(args)


if __name__ == '__main__': main()
