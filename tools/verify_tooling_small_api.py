"""Build and execute the actual CLI-generated protected Small API; retain every attempt."""
import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_FILES = {'Consumer.csproj', 'Program.cs', 'SelfTest.cs', 'FixtureHost.cs', 'Catalog.cs', 'ContractExport.cs',
                  'appsettings.json', 'appsettings.graphql.json', 'appsettings.graphql-only.json',
                  'appsettings.off.json', 'global.json', 'NuGet.Config', 'engine-source.json', 'README.md'}
CONFIGS = {'appsettings.json': {'host', 'api'}, 'appsettings.graphql.json': {'host', 'api', 'graphql'},
           'appsettings.graphql-only.json': {'host', 'graphql'}, 'appsettings.off.json': set()}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def counter(values, name):
    matching = [value for key, value in values.items() if key.casefold() == name.casefold()]
    if len(matching) != 1 or not isinstance(matching[0], int):
        raise ValueError('Expected one integer counter: ' + name)
    return matching[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dotnet', required=True)
    parser.add_argument('--engine-root', default=str(ROOT.parent / 'Cehpalon-Engine'))
    parser.add_argument('--output', required=True)
    revisions = parser.add_mutually_exclusive_group()
    revisions.add_argument('--integration', action='store_true', help='Retained preliminary proof, not a final clean-revision result')
    revisions.add_argument('--engine-revision', help='Exact clean Engine SHA for a separately scoped verification')
    parser.add_argument('--capacity', action='store_true', help='Exercise the opt-in capacity profile on the selected Engine revision')
    args = parser.parse_args()
    engine = Path(args.engine_root).resolve()
    output = (ROOT / args.output).resolve()
    private = (ROOT / '.local').resolve()
    if output == private or not output.is_relative_to(private):
        raise ValueError('Use a fresh ignored Samples .local directory')
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1')
    report = {'started_utc': datetime.now(timezone.utc).isoformat(), 'status': 'started', 'commands': [], 'checks': [],
              'scope': 'Experimental CLI-generated protected localhost Small API correctness only; no real IdP/database/broker, performance, packaging, supported-platform or production qualification',
              'harness_sha256': sha(Path(__file__)), 'private_material_policy': 'Ephemeral TLS PFX/JWT tokens/password stay in restricted ignored Windows .local/.private-fixtures or native Unix temporary directory; private material is excluded from retained raw evidence'}

    def save():
        (output / 'manifest.json').write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8', newline='\n')

    def check(ok, description):
        if not ok:
            raise ValueError(description)
        report['checks'].append(description)

    def run(command, cwd, log, expected=0, environment=None):
        command = list(map(str, command))
        try:
            result = subprocess.run(command, cwd=cwd, env=environment or env, capture_output=True, timeout=240)
        except subprocess.TimeoutExpired as error:
            (output / log).write_bytes((error.stdout or b'') + (error.stderr or b''))
            report['commands'].append({'argv': command, 'cwd': str(cwd), 'exit': None, 'timed_out_seconds': 240,
                                       'log': log, 'sha256': sha(output / log)})
            save()
            raise
        (output / log).write_bytes(result.stdout + result.stderr)
        report['commands'].append({'argv': command, 'cwd': str(cwd), 'exit': result.returncode,
                                   'log': log, 'sha256': sha(output / log)})
        save()
        accepted = {expected} if isinstance(expected, int) else set(expected)
        if result.returncode not in accepted:
            raise RuntimeError(f'Expected exit {sorted(accepted)}, got {result.returncode}: {log}')
        return result.stdout.decode('utf-8-sig').strip()

    save()
    try:
        revision = run(['git', 'rev-parse', 'HEAD'], engine, 'engine-head.txt')
        dirty = run(['git', 'status', '--porcelain'], engine, 'engine-status.txt')
        report.update(engine_revision=revision, source_state='uncommitted integration' if dirty else 'exact clean committed source')
        report['tooling_source_sha256'] = {p.relative_to(engine).as_posix(): sha(p)
            for p in sorted((engine / 'src/Cehpalon.Engine.Tooling').rglob('*'))
            if p.is_file() and not {'bin', 'obj'}.intersection(p.relative_to(engine / 'src/Cehpalon.Engine.Tooling').parts)}
        lock = read_json(ROOT / 'tooling-small-api/engine-lock.json')
        if not args.integration:
            expected_revision = args.engine_revision or lock['engine_revision']
            check(not dirty and re.fullmatch('[0-9a-f]{40}', expected_revision) is not None
                  and revision == expected_revision, 'clean Engine matches exact selected revision')
        report['sdk'] = run([args.dotnet, '--version'], engine, 'sdk-version.txt')
        check(report['sdk'] == lock['sdk'], 'exact pinned SDK')
        source_engine = engine
        if not args.integration:
            source_engine = output / 'engine source ไทย & spaces'
            run(['git', 'clone', '--local', '--no-hardlinks', '--no-checkout', engine, source_engine], ROOT, 'source-clone.txt')
            run(['git', 'checkout', '--detach', revision], source_engine, 'source-checkout.txt')
            check(run(['git', 'rev-parse', 'HEAD'], source_engine, 'clone-head.txt') == revision
                  and not run(['git', 'status', '--porcelain'], source_engine, 'clone-status.txt'),
                  'actual clean Engine clone under Unicode ampersand and space path')
        report['consumer_engine_root'] = str(source_engine)
        artifacts = output / 'engine-artifacts'
        project = engine / 'src/Cehpalon.Engine.Tooling/Cehpalon.Engine.Tooling.csproj'
        run([args.dotnet, 'restore', project, '--locked-mode', '--configfile', engine / 'NuGet.Config', '--artifacts-path', artifacts], engine, 'cli-restore.txt')
        run([args.dotnet, 'build', project, '-c', 'Release', '--no-restore', '--artifacts-path', artifacts,
             '-p:UseSharedCompilation=false', '-warnaserror'], engine, 'cli-build.txt')
        cli = [args.dotnet, artifacts / 'bin/Cehpalon.Engine.Tooling/release/cehpalon.dll']
        consumer = output / 'generated Small API ไทย & spaces'
        report['new_result'] = json.loads(run(cli + ['new', '--profile', 'small-api', '--name', 'SmallApiProof',
            '--output', consumer, '--engine-root', source_engine], ROOT, 'new.txt'))
        check({p.name for p in consumer.iterdir()} == EXPECTED_FILES, 'exact fourteen Small API scaffold files, no key/port/fixture state')
        first = {p.name: sha(p) for p in sorted(consumer.iterdir())}
        report['generated_files_sha256'] = first
        twin = output / 'determinism twin'
        run(cli + ['new', '--profile', 'small-api', '--name', 'SmallApiProof', '--output', twin,
                   '--engine-root', source_engine], ROOT, 'new-twin.txt')
        check(first == {p.name: sha(p) for p in sorted(twin.iterdir())}, 'same inputs produce identical published bytes across output paths')
        source = read_json(consumer / 'engine-source.json')
        report['observed_source_manifest'] = source
        check(source.get('provenance') == 'observed-source-bytes-not-git-attestation'
              and source.get('schemaVersion') == 1, 'observed source manifest explicitly limits provenance')
        seen = set()
        for item in source['inputs']:
            relative = Path(item['path'])
            actual = (source_engine / relative).resolve()
            check(not relative.is_absolute() and actual.is_relative_to(source_engine) and item['path'] not in seen,
                  'unique bounded source input ' + item['path'])
            seen.add(item['path'])
            check(sha(actual) == item['sha256'] and actual.stat().st_size == item['bytes'],
                  'observed source bytes match ' + item['path'])
        for family in ['Core', 'Composition', 'CodeGeneration', 'Identity.Contracts', 'Tenancy', 'Transports.Http', 'Transports.GraphQL']:
            check(any(p.startswith('src/Cehpalon.Engine.' + family + '/') for p in seen), 'source observation covers ' + family)
        validate_configs(cli, consumer, output, run, check, report)
        generated = output / 'consumer-artifacts'
        run([args.dotnet, 'restore', consumer / 'Consumer.csproj', '--configfile', consumer / 'NuGet.Config',
             '--artifacts-path', generated], consumer, 'consumer-restore.txt')
        consumer_lock = consumer / 'packages.lock.json'
        check(consumer_lock.is_file(), 'actual initial consumer restore creates package lock')
        report['consumer_package_lock_sha256'] = sha(consumer_lock)
        (output / 'consumer-packages.lock.json').write_bytes(consumer_lock.read_bytes())
        run([args.dotnet, 'restore', consumer / 'Consumer.csproj', '--locked-mode', '--configfile', consumer / 'NuGet.Config',
             '--artifacts-path', generated], consumer, 'consumer-locked-restore.txt')
        check(sha(consumer_lock) == report['consumer_package_lock_sha256'], 'locked restore preserves actual consumer package graph')
        run([args.dotnet, 'build', consumer / 'Consumer.csproj', '-c', 'Release', '--no-restore', '--artifacts-path', generated,
             '-p:UseSharedCompilation=false', '-warnaserror'], consumer, 'consumer-build.txt')
        registries = list((generated / 'obj').rglob('OperationRegistrations.g.cs'))
        check(len(registries) == 1, 'exact one emitted operation registry')
        registry = registries[0].read_text(encoding='utf-8-sig')
        check(all('"' + operation + '"' in registry for operation in ['catalog.get', 'catalog.list', 'catalog.set'])
              and registry.count('builder.Register<') == 3 and registry.count('factory.Create<') == 3,
              'actual three generated typed lazy gateway registrations')
        (output / 'OperationRegistrations.g.cs.txt').write_bytes(registries[0].read_bytes())
        report['generated_registry_sha256'] = sha(registries[0])
        configs = list((generated / 'bin/Consumer/release').glob('*.runtimeconfig.json'))
        check(len(configs) == 1, 'one Small API executable runtime')
        assembly = configs[0].with_name(configs[0].name.removesuffix('.runtimeconfig.json') + '.dll')
        deps = read_json(assembly.with_suffix('.deps.json'))
        libraries = sorted(deps['libraries'])
        report['runtime_libraries'] = libraries
        check(not any(any(word in name.lower() for word in ['codeanalysis', 'codegeneration', 'tooling']) for name in libraries),
              'compiler/analyzer/CLI does not leak into consumer runtime')
        check(all(any(name.startswith('Cehpalon.Engine.' + family + '/') for name in libraries)
                  for family in ['Core', 'Composition', 'Identity.Contracts', 'Tenancy', 'Transports.Http', 'Transports.GraphQL']),
              'runtime contains actual Engine authority and transport adapters')
        result = output / 'self-test.json'
        run([args.dotnet, assembly, '--self-test', '--output', result], consumer, 'self-test.txt')
        verify_self_test(read_json(result), check, report)
        verify_serve_early(cli, args.dotnet, assembly, consumer, output, run, check, report)
        if args.capacity:
            verify_capacity(args.dotnet, assembly, consumer, output, run, check, report)
        verify_external_serve(args.dotnet, assembly, consumer, output, env, run, check, report, save, capacity=args.capacity)
        report.update(status='passed', finished_utc=datetime.now(timezone.utc).isoformat())
    except Exception as error:
        report.update(status='failed', error=str(error), finished_utc=datetime.now(timezone.utc).isoformat())
        save()
        raise
    save()
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'self_test_passed': report['self_test']['passed'], 'output': str(output)}))


def validate_configs(cli, consumer, output, run, check, report):
    validations = {}
    for name, expected in CONFIGS.items():
        result = json.loads(run(cli + ['validate', '--profile', 'small-api', '--config', consumer / name], consumer, name + '-validate.txt'))
        order = result.get('activationOrder')
        check(result.get('status') == 'passed' and set(order or []) == expected,
              'pure profile config selects actual expected activation set: ' + name)
        if expected:
            check(order[0] == 'host', 'host dependency precedes selected API entrypoints: ' + name)
        validations[name] = result
    invalid = read_json(consumer / 'appsettings.json')
    invalid['Cehpalon']['Pattern'] = 'Unsupported'
    invalid_path = output / 'invalid-config.json'
    invalid_path.write_text(json.dumps(invalid), encoding='utf-8')
    run(cli + ['validate', '--profile', 'small-api', '--config', invalid_path], consumer, 'invalid-config-validate.txt', expected=2)
    bad = read_json(output / 'invalid-config-validate.txt')
    check(bad.get('code') == 'config.invalid', 'invalid profile rejected before any activation')
    worker = read_json(consumer / 'appsettings.json')
    worker['Cehpalon']['Modules']['worker'] = {'Enabled': True}
    worker_path = output / 'worker-config.json'
    worker_path.write_text(json.dumps(worker), encoding='utf-8')
    run(cli + ['validate', '--profile', 'small-api', '--config', worker_path], consumer, 'worker-config-validate.txt', expected=2)
    report['config_validation'] = validations


def verify_self_test(result, check, report):
    rows = result.get('checks', [])
    check(result.get('failed') == 0 and result.get('passed') == 39 and len(rows) == 39
          and len({row['name'] for row in rows}) == 39 and all(row.get('passed') is True for row in rows),
          'complete exact thirty-nine real HTTPS self-test cases pass without shrinkage')
    names = {row['name'] for row in rows}
    required = {'invalid configuration fails before host/module factories',
                'unsupported worker profile fails before host/module factories',
                'all entrypoints disabled creates no WebApplication/listener/services',
                'GraphQL-only keeps API entrypoint disabled', 'api-graphql: introspection disabled'}
    for profile in ['api-only', 'api-graphql']:
        required.update(profile + ': ' + suffix for suffix in ['strict custom CA trust and hostname', 'wrong TLS hostname rejected',
            'untrusted TLS fixture CA rejected', 'disabled endpoints/schema/IDE/WS remain absent', 'shutdown owns handlers and closes listener'])
        for wire in ['http', 'graphql'] if profile == 'api-graphql' else ['http']:
            required.update(profile + '/' + wire + ': ' + suffix for suffix in [
                'anonymous/bad JWT denies before business', 'same ID A/B remains isolated despite metadata',
                'both cross-tenant directions deny with zero business', 'revocation/owner mismatch/default policy deny',
                'validation precedes business mutation', 'not-found/list/update/conflict semantics',
                'abort observed and no delayed mutation', 'malformed/oversized body does no business'])
    check(names == required, 'actual case names cover complete tenant/transport/lifecycle corpus')
    profiles = {profile['name']: profile for profile in result.get('profiles', [])}
    check(set(profiles) == {'api-only', 'api-graphql'}, 'both actual API-only and API-plus-GraphQL host profiles tested')
    for name, profile in profiles.items():
        values = profile['counters']
        store = profile['store']
        check(counter(values, 'HostFactories') == 1 and counter(values, 'ApiFactories') == 1
              and counter(values, 'ForbiddenFactories') == 0, name + ' actual host/API activated and forbidden providers stayed off')
        check(counter(values, 'HostDisposals') == 1, name + ' owned WebApplication disposed after listener shutdown')
        check(counter(store, 'Factories') == counter(store, 'Disposals') and counter(store, 'Factories') > 0,
              name + ' owned business handlers disposed')
        check(profile.get('crossTenantDeniedRequests') == (6 if name == 'api-only' else 12),
              name + ' all three business operations deny both cross-tenant directions before work')
        check(counter(store, 'Count') == 20000, name + ' tenant state remains bounded at twenty thousand items')
        if name == 'api-only':
            check(counter(values, 'GraphQLFactories') == counter(values, 'GraphQLServices') == 0,
                  'API-only actual GraphQL factory/services stay zero despite runtime package presence')
        else:
            check(counter(values, 'GraphQLFactories') == 1 and counter(values, 'GraphQLServices') > 0,
                  'API-plus-GraphQL actual vendor services are registered only when enabled')
    scenarios = result.get('scenarios', {})
    check(set(scenarios) == {'invalid', 'worker', 'off', 'graphqlOnly'}, 'all non-default activation scenarios recorded')
    for name in ['invalid', 'worker', 'off']:
        scenario = scenarios[name]
        check(scenario.get('hasApplication') is False and all(counter(scenario['counters'], field) == 0
              for field in ['HostFactories', 'HostDisposals', 'ApiFactories', 'GraphQLFactories', 'ForbiddenFactories', 'GraphQLServices', 'Endpoints']),
              name + ' actually creates no host/listener/services/entrypoint factories')
    gql = scenarios['graphqlOnly']['counters']
    check(counter(gql, 'HostFactories') == counter(gql, 'GraphQLFactories') == 1
          and counter(gql, 'ApiFactories') == counter(gql, 'ForbiddenFactories') == 0 and counter(gql, 'GraphQLServices') > 0,
          'GraphQL-only actually keeps HTTP API module disabled')
    check(counter(gql, 'HostDisposals') == 1, 'GraphQL-only owned WebApplication is disposed')
    report['self_test'] = result


def verify_serve_early(cli, dotnet, assembly, consumer, output, run, check, report):
    missing_cert = output / 'does-not-exist.pfx'
    missing_key = output / 'does-not-exist.pem'
    check(not missing_cert.exists() and not missing_key.exists(), 'serve negative paths are actually nonexistent')
    def command(config, ready):
        return [dotnet, assembly, '--serve', '--config', config, '--certificate', missing_cert,
                '--public-key', missing_key, '--ready', ready]
    off_ready = output / 'off-ready.json'
    run(command(consumer / 'appsettings.off.json', off_ready), consumer, 'serve-off.txt')
    off = read_json(off_ready)
    check(off.get('status') == 'disabled' and off.get('address') is None
          and all(counter(off['counters'], field) == 0 for field in ['HostFactories', 'HostDisposals', 'ApiFactories', 'GraphQLFactories', 'ForbiddenFactories', 'GraphQLServices', 'Endpoints']),
          'normal serve all-off requires no certificate/key and activates nothing')
    invalid_ready = output / 'invalid-ready.json'
    run(command(output / 'invalid-config.json', invalid_ready), consumer, 'serve-invalid.txt', expected=2)
    invalid = read_json(output / 'serve-invalid.txt')
    check(not invalid_ready.exists() and invalid.get('code') == 'config.invalid'
          and all(counter(invalid['counters'], field) == 0 for field in ['HostFactories', 'HostDisposals', 'ApiFactories', 'GraphQLFactories', 'ForbiddenFactories', 'GraphQLServices', 'Endpoints']),
          'normal serve invalid composition rejects with zero activation and no readiness before credential access')
    clash = output / 'existing-ready.json'
    clash.write_bytes(b'outsider-readiness-sentinel\n')
    before = sha(clash)
    run(command(consumer / 'appsettings.json', clash), consumer, 'serve-existing-ready.txt', expected=3)
    clash_result = read_json(output / 'serve-existing-ready.txt')
    check(sha(clash) == before and clash_result.get('code') == 'ready.exists'
          and all(counter(clash_result['counters'], field) == 0 for field in ['HostFactories', 'HostDisposals', 'ApiFactories', 'GraphQLFactories', 'ForbiddenFactories', 'GraphQLServices', 'Endpoints']),
          'normal serve refuses existing readiness before activation without overwriting outsider bytes')
    report['normal_serve_early'] = {'off': off, 'invalid': invalid, 'existing_ready': clash_result,
                                  'invalid_ready_absent': True, 'existing_ready_preserved': True}


def verify_capacity(dotnet, assembly, consumer, output, run, check, report):
    limit_option = '--max-concurrent-operations'
    result_path = output / 'capacity.json'
    run([dotnet, assembly, '--self-test-capacity', '--output', result_path], consumer, 'capacity.txt')
    proof = read_json(result_path)
    check(proof.get('status') == 'passed' and proof.get('maximumConcurrentOperations') == 1
          and proof.get('saturated') == {'http': 503, 'graphQL': 200, 'code': 'operation.capacity_exceeded'}
          and proof.get('crossTenantDenials') == 4
          and proof.get('store') == {'Factories': 2, 'Disposals': 2, 'Reads': 1, 'Writes': 1},
          'one real shared protected budget denies overload, preserves cross-tenant denial and admits after release')

    ready = output / 'capacity-ready.json'
    command = [dotnet, assembly, '--serve', '--config', output / 'missing-config.json',
               '--certificate', output / 'missing.pfx', '--public-key', output / 'missing.pem', '--ready', ready]
    invalid = {}
    for index, value in enumerate(['0', '-1', '+1', '1.0', ' 1', '2147483648', '١']):
        log = f'capacity-invalid-{index}.txt'
        run(command + [limit_option, value], consumer, log, expected=2)
        payload = read_json(output / log)
        check(payload.get('code') == 'usage.max_concurrent_operations' and not ready.exists()
              and counter(payload['counters'], 'HostFactories') == 0,
              'invalid capacity fails before reading config or credentials: case ' + str(index))
        invalid[str(index)] = payload['code']
    run(command + [limit_option, '1', limit_option, '2'], consumer, 'capacity-duplicate.txt', expected=2)
    duplicate = read_json(output / 'capacity-duplicate.txt')
    check(duplicate.get('code') == 'usage.option' and not ready.exists(), 'duplicate capacity is rejected')

    off_config = consumer / 'appsettings.off.json'
    run(command[:4] + [off_config] + command[5:] + [limit_option, '2147483647'], consumer, 'capacity-off.txt')
    disabled = read_json(ready)
    check(disabled.get('status') == 'disabled' and disabled.get('address') is None
          and all(value == 0 for value in disabled['counters'].values()),
          'maximum valid limit leaves all-off profile without services or credential reads')
    exported = output / 'capacity-disabled-contracts'
    run([dotnet, assembly, '--export-contracts', '--config', off_config, '--output', exported],
        consumer, 'capacity-export-off.txt')
    export = read_json(output / 'capacity-export-off.txt')
    check(export.get('status') == 'passed' and export.get('files') == ['manifest.json']
          and all(value == 0 for value in export['counters'].values()),
          'all-off contract export has only a manifest and zero work')
    report['capacity'] = {'proof': proof, 'invalid': invalid, 'duplicate': duplicate['code'],
                          'disabled': disabled, 'export': export}


def verify_external_serve(dotnet, assembly, consumer, output, env, run, check, report, save, capacity=False):
    helper = output / 'fixture-helper'
    helper.mkdir()
    (helper / 'FixtureMaterial.csproj').write_text(FIXTURE_PROJECT, encoding='utf-8')
    (helper / 'Program.cs').write_text(FIXTURE_SOURCE, encoding='utf-8')
    report['private_fixture_helper_source_sha256'] = sha(helper / 'Program.cs')
    fixture_root = output / '.private-fixtures' if os.name == 'nt' else Path(tempfile.gettempdir()) / ('cehpalon-small-api-private-' + uuid.uuid4().hex)
    fixture_env = dict(env, CEHPALON_TLS_PASSWORD=secrets.token_urlsafe(32))
    helper_artifacts = output / 'fixture-helper-artifacts'
    run([dotnet, 'restore', helper / 'FixtureMaterial.csproj', '--configfile', consumer / 'NuGet.Config',
         '--artifacts-path', helper_artifacts], helper, 'fixture-helper-restore.txt')
    run([dotnet, 'build', helper / 'FixtureMaterial.csproj', '-c', 'Release', '--no-restore', '--artifacts-path', helper_artifacts,
         '-p:UseSharedCompilation=false', '-warnaserror'], helper, 'fixture-helper-build.txt')
    fixture_observation = json.loads(run([dotnet, helper_artifacts / 'bin/FixtureMaterial/release/FixtureMaterial.dll', fixture_root], helper,
        'fixture-helper-run.txt', environment=fixture_env))
    check(fixture_observation.get('status') == 'created' and fixture_observation.get('permissionsVerified') is True,
          'private fixture directory has verified current-user-only DACL or Unix0700/0600 before use')
    report['private_fixture_permissions'] = fixture_observation
    material = read_json(fixture_root / 'material.json')
    ready = output / 'serve-ready.json'
    command = [dotnet, assembly, '--serve', '--config', consumer / 'appsettings.json',
               '--certificate', fixture_root / 'server.pfx', '--public-key', fixture_root / 'jwt-public.pem']
    if capacity:
        command.extend(['--max-concurrent-operations', '1'])
    command = list(map(str, command + ['--ready', ready]))
    stdout_path = output / 'serve-stdout.txt'
    stderr_path = output / 'serve-stderr.txt'
    process = None
    stopped = None
    address = None
    observations = []
    with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
        try:
            process = subprocess.Popen(command, cwd=consumer, env=fixture_env, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr)
            report['serve_process'] = {'argv': command, 'pid': process.pid, 'owned': True, 'exit': None,
                                       'stdout': stdout_path.name, 'stderr': stderr_path.name}
            save()
            deadline = time.monotonic() + 30
            while not ready.exists():
                if process.poll() is not None:
                    raise RuntimeError('Normal serve exited before complete readiness; see serve logs')
                if time.monotonic() >= deadline:
                    raise TimeoutError('Normal serve did not publish readiness within thirty seconds')
                time.sleep(0.02)
            readiness = read_json(ready)
            address = urlsplit(readiness['address'])
            check(readiness.get('status') == 'ready' and address.scheme == 'https'
                  and address.hostname in {'localhost', '127.0.0.1'} and address.port is not None,
                  'normal serve starts actual loopback HTTPS with caller-supplied certificate/public key')
            context = ssl.create_default_context(cafile=str(fixture_root / 'root-ca.pem'))
            def request(tenant, subject=None, token_override=None, path='/api/catalog/get'):
                connection = http.client.HTTPSConnection(address.hostname, address.port, timeout=10, context=context)
                headers = {'Content-Type': 'application/json', 'X-Tenant': 'tenant-b', 'X-Role': 'admin', 'X-Subject': 'bob'}
                token = token_override if token_override is not None else material.get(subject) if subject else None
                if token:
                    headers['Authorization'] = 'Bearer ' + token
                try:
                    connection.request('POST', path, json.dumps({'tenant': tenant, 'id': 1}), headers)
                    response = connection.getresponse()
                    body = response.read()
                    parsed = json.loads(body) if body else None
                    observation = {'subject': subject or 'anonymous', 'credential_kind': 'untrusted-signing-key' if token_override else 'owner-fixture-token' if subject else 'anonymous', 'tenant': tenant, 'path': path,
                                   'status': response.status, 'body': parsed}
                    observations.append(observation)
                    return observation
                finally:
                    connection.close()
            for tenant, subject in [('tenant-a', 'alice'), ('tenant-b', 'bob')]:
                response = request(tenant, subject)
                check(response['status'] == 200 and response['body']['tenant'] == tenant and response['body']['id'] == 1,
                      'normal serve accepts authenticated same-ID owner despite spoofed headers: ' + subject)
            for tenant, subject in [('tenant-b', 'alice'), ('tenant-a', 'bob')]:
                response = request(tenant, subject)
                check(response['status'] == 403 and response['body'].get('code') == 'access.denied',
                      'normal serve denies actual cross-tenant request: ' + subject)
            check(request('tenant-a')['status'] == 401, 'normal serve rejects anonymous request')
            check(request('tenant-a', token_override=material['untrusted'])['status'] == 401,
                  'normal serve rejects token signed by an untrusted key')
            check(request('tenant-a', 'alice', path='/graphql')['status'] == 404,
                  'normal API-only serve has no GraphQL endpoint')
            process.stdin.write(b'stop\n')
            process.stdin.flush()
            process.stdin.close()
            code = process.wait(timeout=15)
            stdout.flush(); stderr.flush()
            check(code == 0, 'normal serve documented stop command exits successfully after awaited cleanup')
            stopped_rows = []
            for line in stdout_path.read_text(encoding='utf-8-sig').splitlines():
                try:
                    value = json.loads(line)
                    if value.get('status') == 'stopped': stopped_rows.append(value)
                except (ValueError, AttributeError):
                    pass
            check(len(stopped_rows) == 1, 'normal serve reports one post-cleanup stopped observation')
            stopped = stopped_rows[0]
            values = stopped['counters']; store = stopped['store']
            check(counter(values, 'HostFactories') == counter(values, 'ApiFactories') == 1
                  and counter(values, 'GraphQLFactories') == counter(values, 'GraphQLServices') == counter(values, 'ForbiddenFactories') == 0,
                  'normal serve keeps disabled module factories/services zero')
            check(counter(values, 'HostDisposals') == 1, 'normal serve awaited WebApplication disposal exactly once')
            check(counter(store, 'Factories') == counter(store, 'Disposals') == 2
                  and counter(store, 'Reads') == 2 and counter(store, 'Writes') == 0,
                  'normal serve denies before business and disposes both owner handlers')
            try:
                socket.create_connection((address.hostname, address.port), timeout=1).close()
            except OSError:
                check(True, 'normal serve closes owned listener after graceful stop')
            else:
                raise ValueError('Normal serve listener still accepts connections after stop')
            late_command = command[:-1] + [str(output / 'missing-ready-parent' / 'ready.json')]
            run(late_command, consumer, 'serve-late-ready-failure.txt', expected=3, environment=fixture_env)
            late = read_json(output / 'serve-late-ready-failure.txt')
            check(late.get('code') == 'consumer.failure'
                  and counter(late['counters'], 'HostFactories') == counter(late['counters'], 'HostDisposals') == 1
                  and counter(late['counters'], 'GraphQLServices') == counter(late['counters'], 'ForbiddenFactories') == 0,
                  'late readiness failure honestly reports activated host and awaited cleanup before key disposal')
            report['late_ready_failure'] = late
        finally:
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                    report['serve_process']['forced_termination_after_failure'] = True
                report['serve_process'].update(exit=process.returncode, stdout_sha256=sha(stdout_path), stderr_sha256=sha(stderr_path))
                report['external_serve'] = {'observations': observations, 'stopped': stopped,
                                           'credentials_retained_in_raw': False, 'material_scope': material.get('scope')}
                save()


FIXTURE_PROJECT = '''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework>
  <ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  <IsPackable>false</IsPackable></PropertyGroup>
</Project>
'''

FIXTURE_SOURCE = r'''using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

var folder = Path.GetFullPath(args.Single());
if (Directory.Exists(folder)) throw new IOException("Use a new private fixture directory.");
Directory.CreateDirectory(folder);
if (OperatingSystem.IsWindows())
{
    var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException();
    var security = new DirectorySecurity();
    security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
    security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
    new DirectoryInfo(folder).SetAccessControl(security);
    var observed = new DirectoryInfo(folder).GetAccessControl();
    var rules = observed.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
    if (!observed.AreAccessRulesProtected || rules.Length != 1 || rules[0].IdentityReference != sid
        || rules[0].AccessControlType != AccessControlType.Allow || rules[0].FileSystemRights != FileSystemRights.FullControl)
        throw new InvalidOperationException("Private fixture DACL is not current-user-only.");
}
else
{
    File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    if (File.GetUnixFileMode(folder) != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute))
        throw new InvalidOperationException("Private fixture directory is not Unix0700.");
}
var password = Environment.GetEnvironmentVariable("CEHPALON_TLS_PASSWORD") ?? throw new InvalidOperationException();
using var caKey = RSA.Create(2048);
var caRequest = new CertificateRequest("CN=Cehpalon generated-serve proof CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
var now = DateTimeOffset.UtcNow;
using var ca = caRequest.CreateSelfSigned(now.AddMinutes(-2), now.AddHours(1));
using var leafKey = RSA.Create(2048);
var leafRequest = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); san.AddIpAddress(IPAddress.Loopback);
leafRequest.CertificateExtensions.Add(san.Build());
using var leaf = leafRequest.Create(ca, now.AddMinutes(-1), now.AddMinutes(20), RandomNumberGenerator.GetBytes(16));
using var server = leaf.CopyWithPrivateKey(leafKey);
File.WriteAllBytes(Path.Combine(folder, "server.pfx"), server.Export(X509ContentType.Pfx, password));
File.WriteAllText(Path.Combine(folder, "root-ca.pem"), ca.ExportCertificatePem());
using var jwt = RSA.Create(2048);
using var wrong = RSA.Create(2048);
File.WriteAllText(Path.Combine(folder, "jwt-public.pem"), jwt.ExportSubjectPublicKeyInfoPem());
string Base64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
string Token(string subject, RSA key)
{
    var header = Base64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "at+jwt" }));
    var payload = Base64(JsonSerializer.SerializeToUtf8Bytes(new { iss = "urn:cehpalon:small-api-fixture", aud = "cehpalon-small-api-fixture",
        sub = subject, nbf = now.AddMinutes(-1).ToUnixTimeSeconds(), exp = now.AddMinutes(10).ToUnixTimeSeconds() }));
    var unsigned = header + "." + payload;
    return unsigned + "." + Base64(key.SignData(Encoding.ASCII.GetBytes(unsigned), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
}
File.WriteAllText(Path.Combine(folder, "material.json"), JsonSerializer.Serialize(new { alice = Token("alice", jwt), bob = Token("bob", jwt),
    untrusted = Token("alice", wrong), scope = "Ephemeral synthetic generated-serve proof material only; no production credentials" }));
if (!OperatingSystem.IsWindows())
    foreach (var path in Directory.EnumerateFiles(folder))
    {
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        if (File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
            throw new InvalidOperationException("Private fixture file is not Unix0600.");
    }
Console.WriteLine(JsonSerializer.Serialize(new { status = "created", permissionsVerified = true,
    permissions = OperatingSystem.IsWindows() ? "current-user-only protected DACL" : "Unix0700 directory and0600 files",
    scope = "Ephemeral private fixture; keys, password and tokens not printed" }));
'''


if __name__ == '__main__':
    main()
