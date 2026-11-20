"""Prepare and run the frozen separate-process protected HTTPS listener comparison."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
ENGINE = '5f8f252e901e85c50d7fc6f4b760e457965ce3bb'
SDK = '11.0.100-rc.3.26522.148'
SOURCES = ROOT / 'tooling-small-api/metrics-overhead'
PROTOCOL = ROOT.parent / 'Cehpalon-Engine-Docs/internal/validation/https-metrics-overhead.md'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + '\n', encoding='utf-8', newline='\n')


def fresh(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT / '.local') or path == ROOT / '.local':
        raise ValueError('Use a fresh ignored Samples .local output')
    path.mkdir(parents=True, exist_ok=False)
    return path


def freeze(output):
    target = output / 'frozen'
    target.mkdir()
    files = [*sorted(SOURCES.glob('*.cs')), Path(__file__), ROOT / 'tools/analyze_https_metrics.py', PROTOCOL]
    hashes = {}
    for path in files:
        shutil.copyfile(path, target / path.name)
        hashes[path.name] = sha(path)
    save(target / 'SHA256.json', hashes)
    return hashes


def prepare(args):
    output = fresh(args.output)
    manifest = {'status': 'started', 'commands': [], 'started_utc': datetime.now(timezone.utc).isoformat()}
    save(output / 'manifest.json', manifest)
    try:
        manifest['frozen_source_sha256'] = freeze(output)
        source = (ROOT / args.functional).resolve()
        functional = read(source / 'manifest.json')
        assert functional['status'] == 'passed' and len(functional['checks']) == 160
        assert functional['engine_revision'] == ENGINE and functional['source_state'] == 'exact clean committed source'
        assert functional['sdk'] == SDK
        generated = Path(functional['new_result']['output'])
        project = output / 'consumer'
        project.mkdir()
        for name, expected in functional['generated_files_sha256'].items():
            assert sha(generated / name) == expected, name
            shutil.copyfile(generated / name, project / name)
        shutil.copyfile(generated / 'packages.lock.json', project / 'packages.lock.json')
        assert sha(project / 'packages.lock.json') == functional['consumer_package_lock_sha256']
        shutil.copyfile(source / 'manifest.json', output / 'functional-manifest.json')
        shutil.copyfile(project / 'Consumer.csproj', output / 'original.Consumer.csproj.txt')
        for path in SOURCES.glob('*.cs'):
            shutil.copyfile(path, project / path.name)
        p = project / 'Consumer.csproj'
        original = p.read_text(encoding='utf-8')
        addition = ('<PropertyGroup><StartupObject>MetricsOverhead.Entry</StartupObject></PropertyGroup>\n'
                    '<ItemGroup><Compile Include="Entry.cs"/><Compile Include="Host.cs"/><Compile Include="Client.cs"/></ItemGroup>\n')
        assert original.count('</Project>') == 1
        p.write_text(original.replace('</Project>', addition + '</Project>'), encoding='utf-8', newline='\n')
        environment = dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1')
        for name, argv in [
            ('sdk', [args.dotnet, '--version']),
            ('restore', [args.dotnet, 'restore', str(p), '--locked-mode', '--configfile', str(project / 'NuGet.Config'), '--artifacts-path', str(output / 'artifacts')]),
            ('build', [args.dotnet, 'build', str(p), '-c', 'Release', '--no-restore', '--artifacts-path', str(output / 'artifacts'), '-p:UseSharedCompilation=false', '-warnaserror'])
        ]:
            result = subprocess.run(argv, cwd=project, env=environment, capture_output=True, timeout=240)
            log = output / (name + '.txt'); log.write_bytes(result.stdout + result.stderr)
            manifest['commands'].append({'argv': argv, 'exit': result.returncode, 'log': log.name, 'sha256': sha(log)})
            save(output / 'manifest.json', manifest)
            assert result.returncode == 0, name
            if name == 'sdk':
                assert result.stdout.decode('utf-8-sig').strip() == SDK
        assemblies = list((output / 'artifacts/bin/Consumer/release').glob('PortableConsumer.*.dll'))
        assert len(assemblies) == 1
        assembly = assemblies[0]
        manifest.update(status='prepared', engine_revision=ENGINE, sdk=SDK, assembly=str(assembly), dotnet=args.dotnet,
                        source_files_sha256={p.relative_to(project).as_posix(): sha(p) for p in project.iterdir() if p.is_file()},
                        binary_sha256={p.relative_to(assembly.parent).as_posix(): sha(p) for p in assembly.parent.rglob('*') if p.is_file()},
                        functional_manifest_sha256=sha(source / 'manifest.json'),
                        storage={'project_and_app': str(project), 'binary': str(assembly.parent), 'output': str(output)})
    except Exception as error:
        manifest.update(status='failed', failure_type=type(error).__name__)
        raise
    finally:
        save(output / 'manifest.json', manifest)
    print(json.dumps({'status': manifest['status'], 'output': str(output)}))


class Child:
    def __init__(self, argv, cwd, stderr):
        self.err = stderr.open('wb')
        self.process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.err, text=True, encoding='utf-8', bufsize=1,
                                        env=dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1'))
        self.queue = queue.Queue()

        def reader():
            for line in self.process.stdout:
                self.queue.put(line)
            self.queue.put(None)
        self.reader = threading.Thread(target=reader, daemon=True)
        self.reader.start()

    def send(self, value):
        self.process.stdin.write(value + '\n')
        self.process.stdin.flush()

    def receive(self, kind):
        line = self.queue.get(timeout=45)
        if line is None:
            raise RuntimeError('Owned child exited before expected signal')
        data = json.loads(line)
        if data.get('kind') != kind:
            raise RuntimeError('Owned child returned an unexpected signal')
        return data

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=15)
        self.reader.join(timeout=5)
        self.err.close()


def arm(prepared, output, tenant, enabled, profile):
    output.mkdir()
    dotnet, assembly = prepared['dotnet'], prepared['assembly']
    common = ['--profile', profile]
    host = client = None
    record = {'status': 'started', 'tenant': tenant, 'listener': enabled}
    save(output / 'controller.json', record)
    try:
        host = Child([dotnet, assembly, 'host', *common, '--tenant', str(tenant).lower(), '--listener', str(enabled).lower(),
                      '--output', str(output / 'host.json')], Path(assembly).parent, output / 'host-stderr.txt')
        private = host.receive('ready')
        # Never retain tokens or the private handshake JSON. Root certificate is public, hashed only here.
        record.update(host_pid=host.process.pid, host_environment=private['environment'],
                      address=private['address'], public_root_sha256=hashlib.sha256(__import__('base64').b64decode(private['root'])).hexdigest())
        client = Child([dotnet, assembly, 'client', *common, '--output', str(output / 'client.json')],
                       Path(assembly).parent, output / 'client-stderr.txt')
        record['client_pid'] = client.process.pid
        assert client.process.pid != host.process.pid
        client.send(json.dumps({key: private[key] for key in ['address', 'root', 'alice', 'bob']}))
        private.clear()
        warmed = client.receive('warmed'); record['warmup_signal'] = warmed
        if not warmed['passed'] or warmed['connections'] != 32:
            # The client is waiting at its phase barrier. Let its finally persist
            # every warmup row before stopping the host or terminating anything.
            client.send('ABORT')
            record['persisted_signal'] = client.receive('persisted')
            client.process.wait(timeout=15)
            record['failure_phase'] = 'warmup'
            raise RuntimeError('Warmup rejected; client rows preserved')
        host.send('BEGIN'); record['begin_signal'] = host.receive('begin')
        client.send('MEASURE'); measured = client.receive('measured')
        host.send('END'); record['end_signal'] = host.receive('end')
        record['measured_signal'] = measured
        client.send('PERSIST'); record['persisted_signal'] = client.receive('persisted')
        assert client.process.wait(timeout=15) == 0
        host.send('STOP'); record['stopped_signal'] = host.receive('stopped')
        assert host.process.wait(timeout=15) == 0
        assert measured['status'] == 'passed'
        record['status'] = 'passed'
    except Exception as error:
        record.update(status='failed', failure_type=type(error).__name__)
        # Retain a managed host's partial observations when possible; terminate only owned children.
        if host is not None and host.process.poll() is None:
            try:
                host.send('STOP'); host.process.wait(timeout=10)
            except Exception:
                pass
        raise
    finally:
        for child in [client, host]:
            if child is not None:
                child.close()
        save(output / 'controller.json', record)


def run(args):
    output = fresh(args.output)
    prepared_root = (ROOT / args.prepared).resolve()
    prepared = read(prepared_root / 'manifest.json')
    assert prepared['status'] == 'prepared' and prepared['engine_revision'] == ENGINE
    manifest = {'status': 'started', 'profile': args.profile, 'engine_revision': ENGINE,
                'sdk': SDK, 'started_utc': datetime.now(timezone.utc).isoformat(), 'arms': []}
    save(output / 'manifest.json', manifest)
    try:
        manifest['frozen_source_sha256'] = freeze(output)
        assert manifest['frozen_source_sha256'] == prepared['frozen_source_sha256'], 'Source changed after preparation'
        for name, digest in prepared['source_files_sha256'].items():
            assert sha(prepared_root / 'consumer' / name) == digest
        for name, digest in prepared['binary_sha256'].items():
            assert sha(Path(prepared['assembly']).parent / name) == digest
        shutil.copyfile(prepared_root / 'manifest.json', output / 'preparation-manifest.json')
        pairs = 6 if args.profile == 'measure' else 1
        for tenant in [False, True]:
            for pair in range(1, pairs + 1):
                for enabled in ([False, True] if pair % 2 else [True, False]):
                    name = f'{"tenant" if tenant else "host"}-{pair:02d}-{"listener" if enabled else "baseline"}'
                    entry = {'name': name, 'tenant': tenant, 'pair': pair, 'listener': enabled, 'status': 'started'}
                    manifest['arms'].append(entry); save(output / 'manifest.json', manifest)
                    try:
                        arm(prepared, output / name, tenant, enabled, args.profile)
                    except Exception:
                        entry['status'] = 'failed'
                        raise
                    entry['status'] = 'passed'; save(output / 'manifest.json', manifest)
        manifest['status'] = 'passed'
    except Exception as error:
        manifest.update(status='failed', failure_type=type(error).__name__)
        raise
    finally:
        manifest['finished_utc'] = datetime.now(timezone.utc).isoformat()
        save(output / 'manifest.json', manifest)
    print(json.dumps({'status': manifest['status'], 'arms': len(manifest['arms']), 'output': str(output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    prep = commands.add_parser('prepare')
    prep.add_argument('--dotnet', required=True)
    prep.add_argument('--functional', required=True)
    prep.add_argument('--output', required=True)
    execute = commands.add_parser('run')
    execute.add_argument('--prepared', required=True)
    execute.add_argument('--profile', choices=['conformance', 'measure'], required=True)
    execute.add_argument('--output', required=True)
    args = parser.parse_args()
    (prepare if args.action == 'prepare' else run)(args)


if __name__ == '__main__':
    main()
