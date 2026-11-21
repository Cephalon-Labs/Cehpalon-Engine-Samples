"""Targeted audit contract proof. Root owns serial scheduling and exact fixture lifecycle.

Offline builds once and executes eight checks without a connection file. Wire reuses
those exact verified binaries for eight checks; no build or legacy332/651 rerun.
Every attempt has a new ignored output directory and retains failed raw/source bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ENGINE_REVISION = '5184517a92a087abe4e0091d256142b6c35a2b39'
BASELINE = 'e30fd5c97c792b0b78e8838fa3ae1cba69451bb7'
SERVICE = 'e3a87d11187d0b7e958a7f90c86dfca56bca8bb880e8be1f06499d312b21ece4'
SECURITY = '0534d97c0deba2f33744091b828da6a8a4e375d46c44ef2ca938f2088f148489'
IMAGE = 'docker.io/library/postgres@sha256:ec003ee60c23d320d1b81868f255a6fc724ac06d8f1ced4468532f7d8593f357'
CONTAINER = 'cehpalon-audit-outbox-pg18-20261121'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_bytes())


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def local(path):
    value = (ROOT / path).resolve()
    assert value.is_relative_to(ROOT / '.local') and value != ROOT / '.local'
    return value


def source_map(engine):
    result = {}
    for prefix, root, folders in [('consumer', ROOT, ['audit-outbox', 'security-api']), ('engine', engine, ['src'])]:
        for folder in folders:
            for file in sorted((root / folder).rglob('*')):
                if (file.is_file() and not file.is_symlink()
                        and not {'evidence', 'bin', 'obj', '.local', '.git'}.intersection(file.relative_to(root).parts)
                        and file.suffix.lower() in {'.cs', '.csproj', '.json', '.txt', '.config', '.props'}):
                    result[prefix + '/' + file.relative_to(root).as_posix()] = sha(file)
    for prefix, root, names in [
        ('consumer', ROOT, ['global.json', 'NuGet.Config', 'tools/verify_audit_contracts.py', 'tools/verify_audit_outbox.py', 'tools/verify_optional_security.py']),
        ('engine', engine, ['global.json', 'NuGet.Config', 'Directory.Packages.props'])]:
        for name in names:
            result[prefix + '/' + name] = sha(root / name)
    return result


def preserve_old_suite_source():
    names = git(ROOT, 'ls-tree', '-r', '--name-only', BASELINE, '--', 'audit-outbox').decode().splitlines()
    checks = [name for name in names if name.endswith('Checks.cs')]
    names = checks + ['tools/verify_audit_outbox.py', 'tools/verify_optional_security.py', 'audit-outbox/packages.lock.json',
                     'audit-outbox/PostgresAuditOutbox.Consumer.csproj', 'security-api/packages.lock.json', 'security-api/SecurityApi.Consumer.csproj']
    preserved = {}
    for name in names:
        data = git(ROOT, 'show', BASELINE + ':' + name)
        assert data == (ROOT / name).read_bytes(), ('legacy-source-changed', name)
        preserved[name] = hashlib.sha256(data).hexdigest()
    marker = b'var arguments=args.Select'
    old = git(ROOT, 'show', BASELINE + ':audit-outbox/Program.cs')
    current = (ROOT / 'audit-outbox/Program.cs').read_bytes()
    assert current[current.index(marker):] == old[old.index(marker):], 'Legacy normal runner tail changed'
    return {'baseline': BASELINE, 'legacy_check_files': len(checks), 'preserved_source_sha256': preserved,
            'normal_program_tail_byte_identical': True, 'prior_provider_332_and_security_651_reused_not_rerun': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', required=True, choices=['offline', 'wire'])
    parser.add_argument('--dotnet', required=True)
    parser.add_argument('--engine-root', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--offline-output')
    parser.add_argument('--declarations-root', '--declaration-root', action='append', dest='declarations')
    parser.add_argument('--connection-file')
    parser.add_argument('--fixture-info')
    args = parser.parse_args()
    out = local(args.output); out.mkdir(parents=True, exist_ok=False)
    engine = Path(args.engine_root).resolve()
    report = {'status': 'started', 'phase': args.phase, 'engine_revision': git(engine, 'rev-parse', 'HEAD').decode().strip(),
              'consumer_revision': git(ROOT, 'rev-parse', 'HEAD').decode().strip(), 'source_sha256': {}, 'binary_sha256': {},
              'passed': None, 'failed': None, 'source_unchanged': False,
              'scope': 'Targeted eight checks per phase/host; existing332-provider/651-security and unchanged Engine/CI are reused baseline, not rerun totals. M0/original benchmarks unchanged.'}

    def save():
        (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')

    def run(command, name):
        p = subprocess.run(list(map(str, command)), cwd=ROOT, env=dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1'), capture_output=True)
        (out / (name + '.stdout.txt')).write_bytes(p.stdout); (out / (name + '.stderr.txt')).write_bytes(p.stderr)
        if p.returncode:
            raise RuntimeError('Failed ' + name + '; retained exact stdout/stderr/source, no automatic rerun')
        return p.stdout.decode('utf-8')

    save()
    try:
        assert report['engine_revision'] == ENGINE_REVISION
        dotnet = Path(args.dotnet).resolve(); assert dotnet.is_file()
        report['dotnet_executable'] = str(dotnet); report['dotnet_executable_sha256'] = sha(dotnet)
        assert not git(engine, 'status', '--porcelain').strip() and not git(ROOT, 'status', '--porcelain').strip(), 'Use clean committed source only'
        report['legacy_source_preservation'] = preserve_old_suite_source()
        report['source_sha256'] = source_map(engine)
        for key, digest in report['source_sha256'].items():
            prefix, name = key.split('/', 1); root = engine if prefix == 'engine' else ROOT
            data = (root / name).read_bytes(); assert hashlib.sha256(data).hexdigest() == digest
            revision = ENGINE_REVISION if prefix == 'engine' else report['consumer_revision']
            assert git(root, 'show', revision + ':' + name) == data, ('committed-source', key)
            target = out / 'frozen-source' / key; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        (out / 'verifier.py.txt').write_bytes(Path(__file__).read_bytes())
        if args.phase == 'offline':
            assert not args.connection_file and not args.offline_output, 'Offline proof must not receive a private connection file'
            assert args.declarations, 'Freeze the declared protocol before SDK execution'
            declaration = {}
            for directory in args.declarations:
                root = Path(directory).resolve(); assert root.is_dir()
                for file in sorted(root.rglob('*')):
                    if file.is_file() and not file.is_symlink():
                        name = root.name + '/' + file.relative_to(root).as_posix(); target = out / 'frozen-declarations' / name
                        target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(file.read_bytes()); declaration[name] = sha(file)
            report['declaration_sha256'] = declaration
            save()
            report['sdk'] = run([args.dotnet, '--version'], 'sdk').strip()
            assert report['sdk'] == load(engine / 'global.json')['sdk']['version']
            run([args.dotnet, '--list-runtimes'], 'runtime')
            artifacts = out / 'artifacts'; project = ROOT / 'audit-outbox/PostgresAuditOutbox.Consumer.csproj'
            common = ['--artifacts-path', str(artifacts), '-p:EngineRoot=' + str(engine)]
            run([args.dotnet, 'restore', project, '--configfile', ROOT / 'NuGet.Config', '--locked-mode', *common], 'restore')
            run([args.dotnet, 'build', project, '--no-restore', '-c', 'Release', *common, '-p:UseSharedCompilation=false', '-warnaserror'], 'build')
            for folder, expected, filename in [('PostgresAuditOutbox.Consumer', SERVICE, 'generated-service.cs.txt'), ('SecurityApi.Consumer', SECURITY, 'generated-security.cs.txt')]:
                found = list((artifacts / 'obj' / folder).rglob('OperationRegistrations.g.cs')); assert len(found) == 1
                assert sha(found[0]) == expected, folder
                (out / filename).write_bytes(found[0].read_bytes())
                report['service_registry_sha256' if folder.startswith('Postgres') else 'security_registry_sha256'] = expected
            dll = artifacts / 'bin/PostgresAuditOutbox.Consumer/release/PostgresAuditOutbox.Consumer.dll'
            for file in sorted(dll.parent.rglob('*')):
                if file.is_file(): report['binary_sha256'][file.relative_to(out).as_posix()] = sha(file)
            assert report['binary_sha256']
            deps = load(dll.with_suffix('.deps.json')); assert not any('CodeAnalysis' in k or 'CodeGeneration' in k for k in deps['libraries'])
            report['runtime_libraries'] = sorted(deps['libraries']); report['build_executed'] = True
            report['offline_fixture_boundary'] = 'Root verifies exact stopped fixture/native listener independently; no private connection-file is supplied to this verifier or actual export CLI'
        else:
            assert args.offline_output and args.connection_file and args.fixture_info
            offline = local(args.offline_output); original = load(offline / 'manifest.json')
            assert original['status'] == 'passed' and original['phase'] == 'offline' and original['passed'] == 8 and original['failed'] == 0
            assert original['engine_revision'] == report['engine_revision'] and original['consumer_revision'] == report['consumer_revision']
            assert original['dotnet_executable'] == report['dotnet_executable'] and original['dotnet_executable_sha256'] == report['dotnet_executable_sha256'], 'Wire must reuse the same dotnet host executable'
            assert original['source_sha256'] == report['source_sha256']
            for key, digest in original['source_sha256'].items(): assert sha(offline / 'frozen-source' / key) == digest
            for name, digest in original['binary_sha256'].items():
                path = PurePosixPath(name); assert not path.is_absolute() and '..' not in path.parts and ':' not in name
                assert sha(offline.joinpath(*path.parts)) == digest, ('binary-before-wire', name)
            fixture = load(args.fixture_info)
            assert fixture['image'] == IMAGE and fixture['container_name'] == CONTAINER
            container_id = fixture['container_id']; assert len(container_id) == 64 and all(c in '0123456789abcdef' for c in container_id)
            docker = ['wsl', '-d', 'Ubuntu', '--exec', 'docker'] if os.name == 'nt' else ['docker']
            expected = [container_id, fixture['image_id'], '/' + CONTAINER, 'true']
            observed = run([*docker, 'inspect', container_id, '--format', '{{.Id}} {{.Image}} {{.Name}} {{.State.Running}}'], 'owned-fixture-identity').strip().split()
            assert observed == expected, 'Wire proof requires root-started exact owned fixture'
            (out / 'fixture-info.json').write_bytes(Path(args.fixture_info).read_bytes())
            connection = Path(args.connection_file).resolve(); assert connection.is_file() and connection.suffix == '.env'
            artifacts = offline / 'artifacts'; dll = artifacts / 'bin/PostgresAuditOutbox.Consumer/release/PostgresAuditOutbox.Consumer.dll'
            report.update(offline_output=str(offline), offline_manifest_sha256=sha(offline / 'manifest.json'), binary_sha256=original['binary_sha256'],
                          sdk=original['sdk'], service_registry_sha256=original['service_registry_sha256'], security_registry_sha256=original['security_registry_sha256'],
                          build_executed=False, exact_offline_binaries_reused=True,
                          provider_topology='Windows.NET via owned Windows loopback/stdio proxy to WSL PostgreSQL; not native Windows DB' if os.name == 'nt' else 'WSL.NET direct owned loopback PostgreSQL')
            (out / 'generated-service.cs.txt').write_bytes((offline / 'generated-service.cs.txt').read_bytes()); (out / 'generated-security.cs.txt').write_bytes((offline / 'generated-security.cs.txt').read_bytes())
        save()
        cmd = [args.dotnet, dll, '--verify-audit-contracts=' + args.phase, '--output=' + str(out / 'tests.json')]
        if args.phase == 'wire': cmd += ['--connection-file=' + str(Path(args.connection_file).resolve())]
        run(cmd, 'run')
        tests = load(out / 'tests.json'); assert tests['phase'] == args.phase and tests['passed'] == 8 and tests['failed'] == 0 and len(tests['checks']) == 8 and len(tests['observations']) == 8
        assert all(x['passed'] is True for x in tests['checks'])
        assert source_map(engine) == report['source_sha256']
        binary_base = out if args.phase == 'offline' else local(args.offline_output)
        for name, digest in report['binary_sha256'].items(): assert sha(binary_base / name) == digest, ('binary-after-phase', name)
        report.update(status='passed', passed=8, failed=0, source_unchanged=True, observations=tests['observations'], schemas=tests['schemas'])
        if args.phase == 'offline':
            deterministic = out / 'contract-proof/deterministic'
            report['deterministic_artifact_sha256'] = {file.name: sha(file) for file in sorted(deterministic.iterdir()) if file.is_file()}
    except Exception as error:
        result = out / 'tests.json'
        if result.is_file():
            try:
                observed_tests = load(result)
                report['passed'] = observed_tests.get('passed'); report['failed'] = observed_tests.get('failed')
                report['observed_check_count'] = len(observed_tests.get('checks', []))
                report['observations'] = observed_tests.get('observations', []); report['schemas'] = observed_tests.get('schemas', [])
            except (ValueError, OSError) as read_error:
                report['partial_test_result_read_error'] = type(read_error).__name__
        report.update(status='failed', error=str(error)); save(); raise
    save(); print(json.dumps({k: report[k] for k in ('status', 'phase', 'passed', 'failed', 'source_unchanged', 'build_executed')}))


if __name__ == '__main__':
    main()
