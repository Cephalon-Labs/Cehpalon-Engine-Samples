"""Exercise the actual Small API binary with VS-style empty args and CLI errors."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--assembly', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--dotnet', default='dotnet')
    args = parser.parse_args()
    dll = Path(args.assembly).resolve()
    out = (ROOT / args.output).resolve()
    if not out.is_relative_to(ROOT / '.local') or out == ROOT / '.local':
        raise ValueError('Use a fresh ignored .local output directory')
    out.mkdir(parents=True, exist_ok=False)
    manifest = {'status': 'started', 'checks': [], 'commands': [],
                'assembly_sha256': hashlib.sha256(dll.read_bytes()).hexdigest(),
                'helper_sha256': hashlib.sha256((ROOT / 'build/SampleRunArguments.cs').read_bytes()).hexdigest(),
                'program_sha256': hashlib.sha256((ROOT / 'small-api/Program.cs').read_bytes()).hexdigest(),
                'scope': 'No-argument/explicit-report fixture launch; no serving, provider or benchmark qualification'}

    def save():
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')

    def check(value, name):
        if not value:
            raise AssertionError(name)
        manifest['checks'].append(name)
        save()

    def run(arguments, cwd, name, expected=0):
        command = [args.dotnet, str(dll), *map(str, arguments)]
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired as error:
            (out / (name + '.txt')).write_bytes((error.stdout or b'') + (error.stderr or b''))
            raise
        (out / (name + '.txt')).write_bytes(result.stdout + result.stderr)
        manifest['commands'].append({'arguments': list(map(str, arguments)), 'cwd': str(cwd),
                                     'exit': result.returncode, 'log': name + '.txt'})
        save()
        check(result.returncode == expected, name + ': exit ' + str(expected))
        return result.stdout.decode('utf-8-sig', errors='replace'), result.stderr.decode('utf-8-sig', errors='replace')

    save()
    try:
        reports = []
        for name, cwd in [('no-args-repo', ROOT), ('no-args-project', ROOT / 'small-api')]:
            stdout, _ = run([], cwd, name)
            lines = [line[8:] for line in stdout.splitlines() if line.startswith('Report: ')]
            check(len(lines) == 1, name + ': reported output path')
            report = Path(lines[0])
            check(report.is_relative_to(ROOT / '.local/small-api-runs') and report.is_file(), name + ': ignored report location')
            data = json.loads(report.read_bytes().decode('utf-8'))
            check(data['passed'] == 40 and data['failed'] == 0, name + ': 40 conformance checks')
            (out / (name + '.json')).write_bytes(report.read_bytes())
            reports.append(report)
        check(reports[0] != reports[1], 'repeated empty-argument runs preserve distinct reports')
        explicit = out / 'explicit-report.json'
        run(['--output=' + str(explicit)], ROOT, 'explicit')
        data = json.loads(explicit.read_bytes().decode('utf-8'))
        check(data['passed'] == 40 and data['failed'] == 0, 'explicit report: 40 conformance checks')
        existing = out / 'existing.json'
        existing.write_bytes(b'preserve this earlier report\r\n')
        before_reports = {p: p.read_bytes() for p in reports}
        for name, arguments in [('empty', ['--output=']), ('unknown', ['--unknown']),
                                ('duplicate', ['--output=' + str(out / 'duplicate-a.json'), '--output=' + str(out / 'duplicate-b.json')]),
                                ('existing', ['--output=' + str(existing)]), ('directory', ['--output=' + str(out)])]:
            stdout, stderr = run(arguments, ROOT, name, expected=2)
            check(bool(stderr) and 'Report: ' not in stdout and 'Small API protected consumer:' not in stdout,
                  name + ': actionable error before fixture execution')
        check(existing.read_bytes() == b'preserve this earlier report\r\n', 'existing report bytes preserved')
        check(all(p.read_bytes() == content for p, content in before_reports.items()), 'automatic earlier reports preserved')
        stdout, _ = run(['--help'], ROOT, 'help')
        check('Usage:' in stdout and 'Report: ' not in stdout, 'help without fixture execution')
        check(not (out / 'duplicate-a.json').exists() and not (out / 'duplicate-b.json').exists(), 'duplicate args create no output')
        manifest.update(status='passed', consumer_checks=120)
    except Exception as error:
        manifest.update(status='failed', error=str(error))
        raise
    finally:
        save()
    print(json.dumps({'status': manifest['status'], 'checks': len(manifest['checks']), 'consumer_checks': 120, 'output': str(out)}))


if __name__ == '__main__':
    main()
