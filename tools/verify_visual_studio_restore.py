"""Retained build recovery checks; run only in an isolated Samples checkout.

Moves (never deletes) each consumer obj directory to the fresh evidence folder.
Uses real VS MSBuild with BuildingInsideVisualStudio, not an IDE automation claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = [
    'portable-core/PortableCore.Consumer.csproj',
    'tenant-identity/TenantIdentity.Consumer.csproj',
    'small-api/SmallApi.Consumer.csproj',
    'security-api/SecurityApi.Consumer.csproj',
    'audit-outbox/PostgresAuditOutbox.Consumer.csproj',
    'small-api-benchmark/SmallApi.Benchmark.csproj',
]
MARKER = 'restoring missing NuGet assets for Visual Studio Build.'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine-root', required=True)
    parser.add_argument('--msbuild', required=True)
    parser.add_argument('--dotnet', default='dotnet')
    parser.add_argument('--output', required=True)
    parser.add_argument('--run-consumers', action='store_true')
    args = parser.parse_args()
    engine = Path(args.engine_root).resolve()
    if ROOT == Path('D:/Cephalon/Cehpalon-Engine-Samples').resolve():
        raise ValueError('Use an isolated Samples checkout; never move user obj directories')
    if engine == ROOT or not engine.is_dir() or not Path(args.msbuild).is_file():
        raise ValueError('Supply an existing Engine checkout and VS MSBuild executable')
    if subprocess.check_output(['git', '-C', str(engine), 'status', '--porcelain']).strip():
        raise ValueError('Engine validation checkout must be clean')
    out = (ROOT / args.output).resolve()
    if not out.is_relative_to(ROOT / '.local') or out == ROOT / '.local':
        raise ValueError('Use a fresh ignored .local directory')
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1',
               DOTNET_CLI_UI_LANGUAGE='en-US', VSLANG='1033')
    report = {'scope': 'Checked-in consumer build recovery; no benchmark/provider/platform qualification',
              'engine_revision': subprocess.check_output(['git', '-C', str(engine), 'rev-parse', 'HEAD'], text=True).strip(),
              'status': 'started', 'commands': [], 'checks': [], 'source_sha256': {}}
    sources = ['build/SampleRunArguments.cs', 'global.json', 'NuGet.Config', 'Directory.Build.targets', 'Cehpalon.Samples.slnx',
               'small-api/SmallApi.Consumer.slnx', 'tools/verify_visual_studio_restore.py']
    sources += [x for p in PROJECTS for x in [p, (Path(p).parent / 'packages.lock.json').as_posix()]]
    for name in sources:
        report['source_sha256'][name] = sha(ROOT / name)
    (out / 'verifier.py.txt').write_bytes(Path(__file__).read_bytes())
    (out / 'Directory.Build.targets.txt').write_bytes((ROOT / 'Directory.Build.targets').read_bytes())

    def save():
        (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    def run(argv, label, expected=0):
        argv = list(map(str, argv))
        log = out / (label + '.txt')
        try:
            result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired as error:
            log.write_bytes((error.stdout or b'') + (error.stderr or b''))
            report['commands'].append({'argv': argv, 'exit': None, 'log': log.name, 'timeout': 300})
            save()
            raise
        log.write_bytes(result.stdout + result.stderr)
        report['commands'].append({'argv': argv, 'exit': result.returncode, 'log': log.name, 'sha256': sha(log)})
        save()
        if result.returncode != expected:
            raise RuntimeError(f'{label}: expected {expected}, got {result.returncode}; see {log}')
        return log.read_text(encoding='utf-8-sig', errors='replace')

    def check(value, description):
        if not value:
            raise AssertionError(description)
        report['checks'].append(description)
        save()

    def references(project, seen):
        if project in seen:
            return
        seen.add(project)
        for ref in ET.parse(project).iter('ProjectReference'):
            value = ref.attrib['Include'].replace('$(EngineRoot)', str(engine))
            references((project.parent / value).resolve(), seen)

    save()
    try:
        report['sdk'] = run([args.dotnet, '--version'], 'sdk').strip()
        check(report['sdk'] == json.loads((ROOT / 'global.json').read_text())['sdk']['version'], 'pinned SDK')
        closure = set()
        for project in PROJECTS:
            references((ROOT / project).resolve(), closure)
        solution = ET.parse(ROOT / 'Cehpalon.Samples.slnx')
        members = set()
        for project in solution.iter('Project'):
            value = project.attrib['Path']
            actual = (engine / value[len('../Cehpalon-Engine/'):]) if value.startswith('../Cehpalon-Engine/') else ROOT / value
            members.add(actual.resolve())
            project.set('Path', actual.resolve().as_posix())
        check(members == closure, 'solution contains the exact six-consumer / ten-Engine project-reference closure')
        solution.write(out / 'Validation.slnx', encoding='utf-8', xml_declaration=True)
        prop = '-p:EngineRoot=' + str(engine)
        for relative in PROJECTS:
            project = ROOT / relative
            name = project.stem
            lock = project.parent / 'packages.lock.json'
            lock_before = sha(lock)
            # Seed referenced binaries at their normal paths using the clean Engine.
            run([args.dotnet, 'build', project, prop, '-p:RestoreLockedMode=true',
                 '-p:UseSharedCompilation=false', '-warnaserror', '-v:minimal'], name + '-seed')
            obj = project.parent / 'obj'
            check(obj.is_dir() and obj.resolve().is_relative_to(ROOT), name + ': owned obj path')
            obj.rename(out / (name + '-obj-before'))
            assets = obj / 'project.assets.json'
            check(not assets.exists(), name + ': entire obj absent before recovery')
            no_restore = run([args.dotnet, 'build', project, '--no-restore', prop,
                              '-p:UseSharedCompilation=false', '-v:minimal'], name + '-explicit-no-restore', expected=1)
            check('NETSDK1004' in no_restore and not assets.exists(), name + ': CLI --no-restore retains its explicit contract')
            common = [args.msbuild, project, '-nologo', '-v:minimal', prop,
                      '-p:BuildingInsideVisualStudio=true', '-p:UseSharedCompilation=false', '-warnaserror']
            cold = run([*common, '-t:Build'], name + '-cold')
            check(MARKER in cold and assets.is_file(), name + ': VS MSBuild cold recovery compiled')
            before = (sha(assets), assets.stat().st_mtime_ns)
            warm = run([*common, '-t:Build'], name + '-warm')
            check(MARKER not in warm and before == (sha(assets), assets.stat().st_mtime_ns), name + ': warm build skips recovery')
            for case, inside, design in [('design-time', 'true', 'true'), ('non-vs', 'false', 'false'), ('opt-out', 'true', 'false')]:
                missing = out / (name + '-' + case) / 'project.assets.json'
                text = run([args.msbuild, project, '-nologo', '-v:minimal', prop,
                            '-t:RestoreMissingVisualStudioAssets', '-p:BuildingInsideVisualStudio=' + inside,
                            '-p:DesignTimeBuild=' + design, '-p:ProjectAssetsFile=' + str(missing),
                            '-p:CehpalonRestoreMissingAssets=' + ('false' if case == 'opt-out' else 'true')], name + '-' + case)
                check(MARKER not in text and not missing.exists(), name + ': ' + case + ' skips restore')
            check(sha(lock) == lock_before, name + ': package lock unchanged')
        missing = out / 'trace-tool-must-not-restore/project.assets.json'
        trace = run([args.msbuild, ROOT / 'tooling-traces/TraceAnalysis/TraceAnalysis.csproj',
                     '-nologo', '-v:minimal', prop, '-p:BuildingInsideVisualStudio=true',
                     '-t:RestoreMissingVisualStudioAssets', '-p:ProjectAssetsFile=' + str(missing)], 'non-consumer')
        check(MARKER not in trace and not missing.exists(), 'trace tool excluded even with a caller-supplied EngineRoot')
        # Exercise normal CLI implicit restore separately; never relabel this as VS UI evidence.
        small_obj = ROOT / 'small-api/obj'
        small_obj.rename(out / 'SmallApi.Consumer-obj-before-cli')
        cli = run([args.dotnet, 'build', ROOT / PROJECTS[2], prop, '-p:RestoreLockedMode=true',
                   '-p:UseSharedCompilation=false', '-warnaserror', '-v:minimal'], 'cli-implicit-restore')
        check(MARKER not in cli and (small_obj / 'project.assets.json').is_file(), 'normal CLI implicit restore works without VS fallback')
        if args.run_consumers:
            for relative in PROJECTS[:4]:
                project = ROOT / relative
                output = out / (project.stem + '-consumer.json')
                dll = project.parent / 'bin/Debug/net11.0' / (project.stem + '.dll')
                run([args.dotnet, dll, '--output=' + str(output)], project.stem + '-run')
                result = json.loads(output.read_text())
                check(result['failed'] == 0 and result['passed'] > 0, project.stem + ': consumer conformance')
                report.setdefault('consumers', {})[project.stem] = {'passed': result['passed'], 'failed': result['failed']}
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        save()
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'consumers': report.get('consumers', {}), 'output': str(out)}))


if __name__ == '__main__':
    main()
