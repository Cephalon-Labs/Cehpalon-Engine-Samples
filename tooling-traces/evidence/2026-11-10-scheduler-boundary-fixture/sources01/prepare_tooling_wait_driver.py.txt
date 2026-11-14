"""Fresh diagnostic copy with repeated post-body UTC/Stopwatch anchor brackets."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import prepare_tooling_trace_driver as base


def clock_support(source):
    old = '        var markerBefore = Stopwatch.GetTimestamp();'
    new = '''        var utcSampleBefore = Stopwatch.GetTimestamp();
        var utcSample = DateTimeOffset.UtcNow.UtcTicks;
        var utcSampleAfter = Stopwatch.GetTimestamp();
        var markerBefore = Stopwatch.GetTimestamp();'''
    source = base.replace_once(source, old, new)
    source = base.replace_once(source, '            markerBefore, markerAfter));',
                               '            markerBefore, markerAfter, utcSample, utcSampleBefore, utcSampleAfter));')
    return base.replace_once(source, '        long MarkerBeforeTicks, long MarkerAfterTicks);',
                             '        long MarkerBeforeTicks, long MarkerAfterTicks, long UtcSampleTicks, long UtcSampleBeforeTicks, long UtcSampleAfterTicks);')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine-root', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    helper = Path(base.__file__).resolve()
    output = Path(args.output).resolve()
    subprocess.run([sys.executable, str(helper), '--engine-root', str(Path(args.engine_root).resolve()),
                    '--output', str(output)], check=True)
    original = (output / 'DiagnosticSupport.cs').read_bytes()
    (output / 'DiagnosticSupport.before-wait-clocks.cs.txt').write_bytes(original)
    (output / 'DiagnosticSupport.cs').write_text(clock_support(original.decode('utf-8')), encoding='utf-8', newline='\n')
    digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    result = {'role': 'diagnostic_only_repeated_post_body_clock_anchors', 'canonical': False,
              'engine_revision': '55c630fc5d4c47258a1a2b0da4a16ce8bc42b9f7',
              'helper_sha256': digest(__file__), 'base_helper_sha256': digest(helper),
              'base_preparation_manifest_sha256': digest(output / 'diagnostic-manifest.json'),
              'original_body_instrumented_program_unchanged': True,
              'final_files_sha256': {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()},
              'clock_model': 'Startup plus every post-body UTC read bracketed by target Stopwatch; UTC ticks quantized100ns. Preserve all anchors; conditional constant-offset joins only, not proof no hidden clock excursion.',
              'limit': 'Adds clocks after stage body and original metric brackets; perturbs following work. Base manifest describes the preceding preparation stage, not final support bytes.'}
    (output / 'wait-diagnostic-manifest.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'status': 'prepared', 'canonical': False, 'output': str(output)}))


if __name__ == '__main__':
    main()
