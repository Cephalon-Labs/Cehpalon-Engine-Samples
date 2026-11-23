"""Real empty-argument entrypoint checks for the six consumer startup projects.
Provider setup guidance is reported separately from executed conformance tests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CONSUMERS = {'portable-core': ('PortableCore.Consumer', 5), 'tenant-identity': ('TenantIdentity.Consumer', 10),
             'small-api': ('SmallApi.Consumer', 40), 'security-api': ('SecurityApi.Consumer', 651)}
DEBUG_PROFILE_CONSUMERS = {'small-api', 'security-api'}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', required=True)
    p.add_argument('--dotnet', default='dotnet')
    a = p.parse_args()
    out = (ROOT / a.output).resolve()
    if not out.is_relative_to(ROOT / '.local') or out == ROOT / '.local':
        raise ValueError('Use a fresh .local directory')
    out.mkdir(parents=True, exist_ok=False)
    report = {'status': 'started', 'checks': [], 'commands': [], 'consumer_checks': {},
              'scope': 'Six consumer entrypoints; no native GUI/provider/performance qualification',
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in ['build/SampleRunArguments.cs', 'Directory.Build.targets', 'tools/verify_sample_launches.py',
                                             *[f'{key}/Program.cs' for key in CONSUMERS], 'audit-outbox/Program.cs', 'small-api-benchmark/Program.cs']}}

    def save():
        (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    def check(value, name):
        if not value:
            raise AssertionError(name)
        report['checks'].append(name); save()

    def run(folder, assembly, args, name, expected=0, launch_profile=False):
        dll = ROOT / folder / 'bin/Debug/net11.0' / (assembly + '.dll')
        command = [a.dotnet, str(dll)]
        if launch_profile:
            project = ROOT / folder / (assembly + '.csproj')
            command = [a.dotnet, 'run', '--no-build', '--project', str(project), '--launch-profile', assembly, '--']
        result = subprocess.run([*command, *map(str, args)], cwd=ROOT / folder, capture_output=True, timeout=180)
        (out / (name + '.txt')).write_bytes(result.stdout + result.stderr)
        report['commands'].append({'entrypoint': folder, 'launch_profile': assembly if launch_profile else None,
                                   'arguments': list(map(str, args)), 'exit': result.returncode, 'log': name + '.txt'})
        check(result.returncode == expected, name + ': exit ' + str(expected))
        return result.stdout.decode('utf-8-sig', errors='replace'), result.stderr.decode('utf-8-sig', errors='replace')

    save()
    try:
        sentinel = out / 'existing.json'; sentinel.write_bytes(b'preserve previous report\r\n')
        for folder, (assembly, count) in CONSUMERS.items():
            uses_profile = folder in DEBUG_PROFILE_CONSUMERS
            if uses_profile:
                settings = ROOT / folder / 'Properties/launchSettings.json'
                raw = settings.read_bytes()
                report['source_sha256'][settings.relative_to(ROOT).as_posix()] = hashlib.sha256(raw).hexdigest()
                profiles = json.loads(raw)['profiles']
                profile = profiles[assembly]
                check(next(iter(profiles)) == assembly and profile.get('commandName') == 'Project'
                      and profile.get('launchBrowser') is False and 'applicationUrl' not in profile
                      and not profile.get('commandLineArgs'), folder + ': default debug profile runs a finite self-test')
            stdout, _ = run(folder, assembly, [], folder + '-default', launch_profile=uses_profile)
            paths = [Path(line[8:]) for line in stdout.splitlines() if line.startswith('Report: ')]
            check(len(paths) == 1 and paths[0].is_relative_to(ROOT / '.local' / (folder + '-runs')), folder + ': ignored default report')
            raw = paths[0].read_bytes(); result = json.loads(raw.decode('utf-8'))
            check(result['passed'] == count and result['failed'] == 0, folder + ': complete existing conformance suite')
            (out / (folder + '-consumer.json')).write_bytes(raw)
            report['consumer_checks'][folder] = count
            for label, arguments in [('empty', ['--output=']), ('unknown', ['--unknown']),
                                     ('duplicate', ['--output=x.json', '--output=y.json']), ('existing', ['--output=' + str(sentinel)])]:
                stdout, stderr = run(folder, assembly, arguments, folder + '-' + label, expected=2)
                check(bool(stderr) and 'Report: ' not in stdout, folder + '-' + label + ': preflight diagnostic')
            stdout, _ = run(folder, assembly, ['--help'], folder + '-help')
            check('Usage:' in stdout and 'Report: ' not in stdout, folder + ': help before fixtures')
        check(sentinel.read_bytes() == b'preserve previous report\r\n', 'sentinel bytes preserved')
        folder, assembly = 'audit-outbox', 'PostgresAuditOutbox.Consumer'
        stdout, _ = run(folder, assembly, [], 'audit-default')
        check('setup guide only' in stdout, 'audit default is setup guidance, not a provider pass')
        report['audit_provider_tests_run'] = False
        for label, args in [('missing', ['--output=x.json']), ('malformed', ['--schema']),
                            ('duplicate', ['--schema=a', '--schema=b']),
                            ('missing-private-file', ['--schema=ao_startup', '--output=' + str(out / 'audit.json'), '--connection-file=' + str(out / 'absent-private-file')])]:
            stdout, stderr = run(folder, assembly, args, 'audit-' + label, expected=2)
            check(bool(stderr) and 'PostgreSQL audit outbox:' not in stdout, 'audit-' + label + ': actionable preflight')
        stdout, _ = run('small-api-benchmark', 'SmallApi.Benchmark', [], 'benchmark-default')
        result = next(json.loads(line) for line in stdout.splitlines() if line.startswith('{') and '"passed"' in line)
        check(result.get('passed') is True, 'benchmark default is finite correctness smoke only')
        for transport in ['http', 'graphql']:
            stdout, _ = run('small-api-benchmark', 'SmallApi.Benchmark', ['--mode=self-test', '--variant=baseline', '--transport=' + transport], 'benchmark-explicit-' + transport)
            check(any('"passed":true' in line for line in stdout.splitlines()), 'explicit benchmark smoke ' + transport + ' unchanged')
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error=str(error)); raise
    finally:
        save()
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'consumer_checks': report['consumer_checks'], 'audit_provider_tests_run': False}))


if __name__ == '__main__':
    main()
