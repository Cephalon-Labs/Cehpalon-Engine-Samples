"""Windows no-argument guidance checks; never invoke a collector/actor protocol."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = [
    ('tooling-traces/Conformance/Conformance.csproj', 0),
    ('tooling-traces/WaitConformance/WaitConformance.csproj', 0),
    ('tooling-traces/TaskConformance/TaskConformance.csproj', 0),
    ('tooling-traces/TraceAnalysis/TraceAnalysis.csproj', 0),
    ('tooling-small-api/metrics-trace/RuntimeTrace.csproj', 0),
    ('tooling-traces/ThreadPoolConformance/ThreadPoolConformance.csproj', 2),
    ('tooling-traces/GCWaitCallsiteFixture/GCWaitCallsiteFixture.csproj', 2),
]


def main():
    p = argparse.ArgumentParser(); p.add_argument('--output', required=True); p.add_argument('--dotnet', default='dotnet'); a = p.parse_args()
    if os.name != 'nt':
        raise ValueError('Windows guidance check only; Linux actors require their explicit owned controllers')
    out = (ROOT / a.output).resolve()
    if not out.is_relative_to(ROOT / '.local') or out == ROOT / '.local': raise ValueError('Use fresh .local output')
    out.mkdir(parents=True, exist_ok=False)
    report = {'status': 'started', 'scope': 'Guidance/platform rejection only; no actual trace, native actor or scheduler qualification', 'projects': []}
    def save(): (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    save()
    try:
        for name, expected in PROJECTS:
            project = ROOT / name; label = project.stem
            build = subprocess.run([a.dotnet, 'build', str(project), '-p:UseSharedCompilation=false', '-warnaserror', '-v:minimal'], cwd=ROOT, capture_output=True, timeout=240)
            (out / (label + '-build.txt')).write_bytes(build.stdout + build.stderr)
            if build.returncode: raise RuntimeError('Build failed: ' + label)
            dll = project.parent / 'bin/Debug/net11.0' / (label + '.dll')
            run = subprocess.run([a.dotnet, str(dll)], cwd=project.parent, capture_output=True, timeout=30)
            (out / (label + '-empty.txt')).write_bytes(run.stdout + run.stderr)
            if run.returncode != expected or not (run.stdout + run.stderr).strip() or b'Unhandled exception' in run.stderr:
                raise RuntimeError('Guidance/platform rejection failed: ' + label)
            report['projects'].append({'project': name, 'exit': run.returncode, 'mode': 'usage' if expected == 0 else 'unsupported-platform',
                                       'assembly_sha256': hashlib.sha256(dll.read_bytes()).hexdigest()}); save()
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error=str(error)); raise
    finally: save()
    print(json.dumps({'status': report['status'], 'projects': len(report['projects']), 'trace_captures': 0}))


if __name__ == '__main__': main()
