"""Invoke the real CLI and compile/run its fresh consumer; retain every attempt."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dotnet', required=True)
    parser.add_argument('--engine-root', default=str(ROOT.parent / 'Cehpalon-Engine'))
    parser.add_argument('--output', required=True)
    parser.add_argument('--integration', action='store_true', help='Retained preliminary proof only; final proof requires clean locked Engine')
    args = parser.parse_args()
    engine = Path(args.engine_root).resolve()
    output = (ROOT / args.output).resolve()
    private = (ROOT / '.local').resolve()
    if not output.is_relative_to(private) or output == private:
        raise ValueError('Use a fresh directory beneath ignored Samples .local')
    output.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1')
    report = {'started_utc': datetime.now(timezone.utc).isoformat(), 'status': 'started', 'commands': [],
              'scope': 'Experimental portable console scaffolding only; no tenant authority, transport/provider, packaging, supported-Windows or production qualification',
              'harness_sha256': sha(Path(__file__)), 'checks': []}

    def save():
        (output / 'manifest.json').write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')

    def run(command, cwd, log, expected=0):
        command = list(map(str, command))
        try:
            result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, timeout=240)
        except subprocess.TimeoutExpired as error:
            (output / log).write_bytes((error.stdout or b'') + (error.stderr or b''))
            report['commands'].append({'argv': command, 'cwd': str(cwd), 'exit': None,
                                       'timed_out_seconds': 240, 'log': log, 'sha256': sha(output / log)})
            save()
            raise
        (output / log).write_bytes(result.stdout + result.stderr)
        report['commands'].append({'argv': command, 'cwd': str(cwd), 'exit': result.returncode,
                                   'log': log, 'sha256': sha(output / log)})
        save()
        if result.returncode != expected:
            raise RuntimeError(f'Expected exit {expected}, got {result.returncode}: {log}')
        return result.stdout.decode('utf-8-sig').strip()

    def check(condition, description):
        if not condition:
            raise ValueError(description)
        report['checks'].append(description)

    save()
    try:
        report['engine_revision'] = run(['git', 'rev-parse', 'HEAD'], engine, 'engine-head.txt')
        dirty = run(['git', 'status', '--porcelain'], engine, 'engine-status.txt')
        report['source_state'] = 'uncommitted integration' if dirty else 'exact clean committed source'
        report['tooling_source_sha256'] = {p.relative_to(engine).as_posix(): sha(p)
            for p in sorted((engine / 'src/Cehpalon.Engine.Tooling').iterdir()) if p.is_file()}
        lock = json.loads((ROOT / 'tooling/engine-lock.json').read_text(encoding='utf-8'))
        if not args.integration:
            check(not dirty and re.fullmatch('[0-9a-f]{40}', lock['engine_revision']) is not None
                  and report['engine_revision'] == lock['engine_revision'], 'clean Engine matches actual locked revision')
        report['sdk'] = run([args.dotnet, '--version'], engine, 'sdk-version.txt')
        check(report['sdk'] == lock['sdk'], 'exact pinned SDK')
        source_engine = engine
        if not args.integration:
            # A real local clone exercises XML-escaped ProjectReference source paths,
            # not merely a destination containing special characters. The CLI does
            # not run git; this independently controlled verifier does.
            source_engine = output / 'engine source ไทย & spaces'
            run(['git', 'clone', '--local', '--no-hardlinks', '--no-checkout', engine, source_engine], ROOT, 'source-clone.txt')
            run(['git', 'checkout', '--detach', lock['engine_revision']], source_engine, 'source-checkout.txt')
            check(run(['git', 'rev-parse', 'HEAD'], source_engine, 'clone-head.txt') == lock['engine_revision']
                  and not run(['git', 'status', '--porcelain'], source_engine, 'clone-status.txt'),
                  'actual clean source clone under Unicode ampersand and space path')
        report['consumer_engine_root'] = str(source_engine)
        artifacts = output / 'engine-artifacts'
        project = engine / 'src/Cehpalon.Engine.Tooling/Cehpalon.Engine.Tooling.csproj'
        run([args.dotnet, 'restore', project, '--locked-mode', '--configfile', engine / 'NuGet.Config', '--artifacts-path', artifacts], engine, 'cli-restore.txt')
        run([args.dotnet, 'build', project, '-c', 'Release', '--no-restore', '--artifacts-path', artifacts,
             '-p:UseSharedCompilation=false', '-warnaserror'], engine, 'cli-build.txt')
        cli = [args.dotnet, artifacts / 'bin/Cehpalon.Engine.Tooling/release/cehpalon.dll']
        consumer = output / 'generated consumer ไทย & spaces'
        raw = run(cli + ['new', '--name', 'PortableProof', '--output', consumer, '--engine-root', source_engine], ROOT, 'new.txt')
        report['new_result'] = json.loads(raw)
        expected_files = {'Consumer.csproj', 'Program.cs', 'Catalog.cs', 'appsettings.json', 'appsettings.off.json',
                          'global.json', 'NuGet.Config', 'engine-source.json', 'README.md'}
        check({p.name for p in consumer.iterdir()} == expected_files, 'exact nine fresh scaffold files')
        report['generated_files_sha256'] = {p.name: sha(p) for p in sorted(consumer.iterdir())}
        source = json.loads((consumer / 'engine-source.json').read_text(encoding='utf-8'))
        report['observed_source_manifest'] = source
        check(source.get('provenance') == 'observed-source-bytes-not-git-attestation'
              and source.get('schemaVersion') == 1, 'source manifest declares observation boundary')
        seen = set()
        for item in source['inputs']:
            relative = Path(item['path'])
            actual = (source_engine / relative).resolve()
            check(not relative.is_absolute() and actual.is_relative_to(source_engine)
                  and item['path'] not in seen, 'unique bounded source input ' + item['path'])
            seen.add(item['path'])
            check(sha(actual) == item['sha256'] and actual.stat().st_size == item['bytes'],
                  'observed source bytes match ' + item['path'])
        check({'global.json', 'NuGet.Config', 'Directory.Packages.props'}.issubset(seen)
              and any('Cehpalon.Engine.CodeGeneration' in p for p in seen), 'source manifest includes locks and generator')
        generated_artifacts = output / 'consumer-artifacts'
        # Initial restore creates a lock for the fresh consumer; the second uses locked mode.
        run([args.dotnet, 'restore', consumer / 'Consumer.csproj', '--configfile', consumer / 'NuGet.Config',
             '--artifacts-path', generated_artifacts], consumer, 'consumer-restore.txt')
        consumer_lock = consumer / 'packages.lock.json'
        check(consumer_lock.is_file(), 'initial consumer restore actually creates package lock')
        report['consumer_package_lock_sha256'] = sha(consumer_lock)
        (output / 'consumer-packages.lock.json').write_bytes(consumer_lock.read_bytes())
        run([args.dotnet, 'restore', consumer / 'Consumer.csproj', '--locked-mode', '--configfile', consumer / 'NuGet.Config',
             '--artifacts-path', generated_artifacts], consumer, 'consumer-locked-restore.txt')
        check(sha(consumer_lock) == report['consumer_package_lock_sha256'], 'locked restore preserves actual consumer lock')
        run([args.dotnet, 'build', consumer / 'Consumer.csproj', '-c', 'Release', '--no-restore',
             '--artifacts-path', generated_artifacts, '-p:UseSharedCompilation=false', '-warnaserror'], consumer, 'consumer-build.txt')
        registries = list((generated_artifacts / 'obj').rglob('OperationRegistrations.g.cs'))
        check(len(registries) == 1, 'exact one emitted operation registry')
        registry = registries[0].read_text(encoding='utf-8-sig')
        check('RegisterAll' in registry and 'sample.echo' in registry, 'actual emitted typed operation registration')
        (output / 'OperationRegistrations.g.cs.txt').write_bytes(registries[0].read_bytes())
        report['generated_registry_sha256'] = sha(registries[0])
        assemblies = list((generated_artifacts / 'bin/Consumer/release').glob('*.runtimeconfig.json'))
        check(len(assemblies) == 1, 'one executable consumer runtime')
        assembly = assemblies[0].with_name(assemblies[0].name.removesuffix('.runtimeconfig.json') + '.dll')
        deps = json.loads(assembly.with_suffix('.deps.json').read_text(encoding='utf-8'))
        report['runtime_libraries'] = sorted(deps['libraries'])
        check(not any(any(x in name.lower() for x in ('codeanalysis', 'codegeneration', 'tooling'))
                      for name in deps['libraries']), 'no compiler or CLI dependency in runtime consumer')
        run_consumer_cases(run, check, report, cli, args.dotnet, assembly, consumer, output)
        collision_results = {}
        for name in ['Program', 'Console', 'Path', 'JsonSerializer', 'File', 'System', 'OperationContext', 'ModuleRole']:
            target = output / ('name-' + name)
            run(cli + ['new', '--name', name, '--output', target, '--engine-root', source_engine], ROOT, 'name-' + name + '-new.txt')
            name_artifacts = output / ('name-' + name + '-artifacts')
            run([args.dotnet, 'restore', target / 'Consumer.csproj', '--configfile', target / 'NuGet.Config',
                 '--artifacts-path', name_artifacts], target, 'name-' + name + '-restore.txt')
            run([args.dotnet, 'build', target / 'Consumer.csproj', '-c', 'Release', '--no-restore',
                 '--artifacts-path', name_artifacts, '-p:UseSharedCompilation=false', '-warnaserror'], target, 'name-' + name + '-build.txt')
            dll = name_artifacts / ('bin/Consumer/release/PortableConsumer.' + name + '.dll')
            result = json.loads(run([args.dotnet, dll, target / 'appsettings.json'], target, 'name-' + name + '-run.txt'))
            check(result.get('status') == 'passed' and result.get('response') == 'hello'
                  and result.get('handlersConstructed') == result.get('handlersDisposed') == result.get('dispatches') == 1,
                  'valid type-collision name compiles and dispatches: ' + name)
            collision_results[name] = result
        report['name_collision_observations'] = collision_results
        report.update(status='passed', finished_utc=datetime.now(timezone.utc).isoformat())
    except Exception as error:
        report.update(status='failed', error=str(error), finished_utc=datetime.now(timezone.utc).isoformat())
        save()
        raise
    save()
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'output': str(output)}))


def run_consumer_cases(run, check, report, cli, dotnet, assembly, consumer, output):
    observations = {}
    for name, filename, count in [('enabled', 'appsettings.json', 1), ('off', 'appsettings.off.json', 0)]:
        config = consumer / filename
        validation = json.loads(run(cli + ['validate', '--config', config], consumer, name + '-validate.txt'))
        check(validation.get('status') == 'passed', name + ' pure configuration validation')
        result = json.loads(run([dotnet, assembly, config], consumer, name + '-run.txt'))
        check(result.get('status') == 'passed', name + ' consumer passed')
        check(result.get('factories') == {'core': count, 'app': count, 'optional': 0}, name + ' exact module factory counts')
        check(result.get('handlersConstructed') == count and result.get('handlersDisposed') == count
              and result.get('dispatches') == count and result.get('modulesDisposed') == count * 2,
              name + ' balanced handler/module cleanup and dispatch counts')
        check(result.get('response') == ('hello' if count else None), name + ' business response')
        check(result.get('activationOrder') == (['core', 'app'] if count else []), name + ' actual composition activation order')
        observations[name] = result
    invalid = consumer / 'invalid.json'
    invalid.write_text(json.dumps({'Cehpalon': {'SchemaVersion': 1, 'Architecture': 'Modular',
                       'Topology': 'SingleProcess', 'Pattern': 'RequestReply',
                       'Modules': {'core': {'Enabled': False}, 'app': {'Enabled': True},
                                   'optional': {'Enabled': False}}}}), encoding='utf-8')
    # stderr is retained in the log; no counters/success output should be emitted.
    stdout = run([dotnet, assembly, invalid], consumer, 'invalid-run.txt', expected=2)
    check(stdout == '', 'invalid consumer emits no success/activation output')
    invalid_result = json.loads((output / 'invalid-run.txt').read_text(encoding='utf-8-sig'))
    check(invalid_result.get('code') == 'config.invalid' and bool(invalid_result.get('diagnostics')),
          'invalid dependency rejected by Composition before activation')
    check(invalid_result.get('factories') == {'core': 0, 'app': 0, 'optional': 0}
          and all(invalid_result.get(k) == 0 for k in ['handlersConstructed', 'handlersDisposed', 'dispatches', 'modulesDisposed']),
          'invalid consumer observed zero activation and dispatch counters')
    stdout = run(cli + ['validate', '--config', invalid], consumer, 'invalid-validate.txt', expected=2)
    check(stdout == '', 'invalid CLI validation emits no success output')
    report['consumer_observations'] = observations
    report['invalid_observation'] = invalid_result


if __name__ == '__main__':
    main()
