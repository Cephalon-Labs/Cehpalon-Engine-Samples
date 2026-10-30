"""Frozen, observational #20 tooling protocol. All failures and primers are retained."""
import argparse
import hashlib
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ('new-portable', 'new-small-api', 'validate-portable', 'validate-small-api',
             'export-api', 'export-both', 'export-graphql', 'export-off')
PORTABLE = {'Consumer.csproj', 'Program.cs', 'Catalog.cs', 'appsettings.json',
            'appsettings.off.json', 'global.json', 'NuGet.Config', 'engine-source.json', 'README.md'}
SMALL = PORTABLE | {'SelfTest.cs', 'FixtureHost.cs', 'ContractExport.cs',
                    'appsettings.graphql.json', 'appsettings.graphql-only.json'}
EXPORTS = {'api': ('appsettings.json', True, False), 'both': ('appsettings.graphql.json', True, True),
           'graphql': ('appsettings.graphql-only.json', False, True), 'off': ('appsettings.off.json', False, False)}
OPERATIONS = ['catalog.get', 'catalog.list', 'catalog.set']
NAME = 'BenchmarkSample'
TIMEOUT = 240


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def file_hashes(folder):
    return {p.name: sha(p) for p in sorted(folder.iterdir()) if p.is_file()}


def filesystem_info(path):
    """Observe the filesystem containing a path; never infer speed or reservation."""
    path = Path(path).resolve()
    result = {'path': str(path), 'device': path.stat().st_dev, 'filesystem': None, 'mount': None}
    if os.name == 'nt':
        import ctypes
        mount = ctypes.create_unicode_buffer(1024)
        filesystem = ctypes.create_unicode_buffer(1024)
        kernel = ctypes.windll.kernel32
        if kernel.GetVolumePathNameW(str(path), mount, len(mount)):
            result['mount'] = mount.value
            if kernel.GetVolumeInformationW(mount.value, None, 0, None, None, None, filesystem, len(filesystem)):
                result['filesystem'] = filesystem.value
    elif Path('/proc/self/mountinfo').is_file():
        matches = []
        for line in Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines():
            before, after = line.split(' - ', 1)
            mount = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), before.split()[4])
            if path.is_relative_to(Path(mount)):
                matches.append((len(mount), mount, after.split()[0]))
        if matches:
            _, result['mount'], result['filesystem'] = max(matches)
    return result


def schedule():
    rows = []
    for round_number in range(18):
        offset = round_number % len(SCENARIOS)
        order = list(SCENARIOS[offset:] + SCENARIOS[:offset])
        if round_number % 2:
            order.reverse()
        base = len(rows)
        rows.extend({'sequence': base + position, 'round': round_number,
                     'position': position, 'phase': 'primer' if round_number < 3 else 'measured',
                     'scenario': name} for position, name in enumerate(order))
    return rows


def summarize(rows):
    result = {}
    for scenario in SCENARIOS:
        values = [r['elapsed_ns'] / 1_000_000 for r in rows
                  if r['scenario'] == scenario and r['phase'] == 'measured']
        require(len(values) == 15, 'complete fifteen measured launches: ' + scenario)
        mean = statistics.mean(values)
        deviation = statistics.stdev(values)
        cv = deviation / mean * 100 if mean else None
        result[scenario] = {'unit': 'milliseconds', 'count': len(values), 'minimum': min(values), 'maximum': max(values),
                            'median': sorted(values)[math.ceil(.50 * len(values)) - 1],
                            'p50': sorted(values)[math.ceil(.50 * len(values)) - 1], 'p95': sorted(values)[math.ceil(.95 * len(values)) - 1],
                            'mean': mean, 'sample_standard_deviation': deviation, 'cv_percent': cv,
                            'unstable_observation': cv is None or cv > 15,
                            'percentile_method': 'nearest rank ceil(p*n)', 'filtering': 'none'}
    return result


def source_hashes(engine):
    # Include templates, all runtime sources, benchmark/helpers and root build/package configuration.
    names = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
                           cwd=engine, capture_output=True, check=True).stdout
    return {name: sha(engine / name) for name in sorted(names.decode('utf-8').split('\0'))
            if name and (engine / name).is_file()}


def verify_new(folder, result, profile, engine, frozen=None):
    expected = PORTABLE if profile == 'portable-request-reply' else SMALL
    require({p.name for p in folder.iterdir()} == expected and all(p.is_file() for p in folder.iterdir()),
            'exact scaffold files ' + profile)
    require(result.get('success') is True and result.get('status') == 'passed'
            and result.get('name') == NAME and result.get('profile') == profile
            and Path(result.get('output', '')).resolve() == folder
            and len(result.get('files', [])) == len(expected) and set(result['files']) == expected
            and result.get('sourceInputs') == (17 if profile == 'portable-request-reply' else 32), 'actual new result identity')
    manifest = read(folder / 'engine-source.json')
    require(manifest.get('schemaVersion') == 1 and manifest.get('provenance') == 'observed-source-bytes-not-git-attestation'
            and Path(manifest.get('sourceRoot', '')).resolve() == engine, 'bounded observed source identity')
    inputs = manifest.get('inputs', [])
    require(len(inputs) == result['sourceInputs'] and len({i['path'] for i in inputs}) == len(inputs), 'exact unique source inputs')
    for item in inputs:
        relative = Path(item['path'])
        actual = (engine / relative).resolve()
        require(not relative.is_absolute() and actual.is_relative_to(engine)
                and sha(actual) == item['sha256'] and actual.stat().st_size == item['bytes'], 'actual observed source bytes')
    hashes = file_hashes(folder)
    if frozen is not None:
        require(hashes == frozen, 'deterministic complete scaffold bytes')
    return {'files_sha256': hashes, 'source_manifest': manifest}


def verify_validate(result, profile, frozen=None):
    order = ['core', 'app'] if profile == 'portable-request-reply' else ['host', 'api']
    require(result.get('success') is True and result.get('status') == 'passed' and result.get('profile') == profile
            and result.get('schemaVersion') == 1 and result.get('activationOrder') == order
            and isinstance(result.get('modules'), list), 'exact pure validation plan')
    if frozen is not None:
        require(result == frozen, 'complete unchanged validation result')
    return result


def verify_export(folder, result, kind, frozen=None):
    _, api, graphql = EXPORTS[kind]
    expected = {'manifest.json'} | ({'openapi.json'} if api else set()) | ({'schema.graphql'} if graphql else set())
    require({p.name for p in folder.iterdir()} == expected and all(p.is_file() for p in folder.iterdir()), 'exact selected artifact set')
    manifest = read(folder / 'manifest.json')
    order = ['host'] + (['api'] if api else []) + (['graphql'] if graphql else []) if api or graphql else []
    require(manifest.get('schemaVersion') == 1 and manifest.get('profile') == 'small-api'
            and manifest.get('activationOrder') == order and manifest.get('generatedOperationIds') == OPERATIONS
            and manifest.get('httpOperationIds') == (OPERATIONS if api else []), 'actual selected operation metadata')
    counters = manifest['counters']
    for metric in ['HandlerFactoryCalls', 'DispatchCalls', 'HostFactories', 'TlsReads', 'AuthorityCalls']:
        require(counters.get(metric) == 0, 'zero offline business/host/TLS/authority: ' + metric)
    require(counters.get('HttpSchemaOperations') == (3 if api else 0), 'selected HTTP metadata')
    for metric in ['GraphQLRegistrations', 'GraphQLSchemaBuilds', 'GraphQLProvidersCreated', 'GraphQLProvidersDisposed']:
        require(counters.get(metric) == (1 if graphql else 0), 'actual selected GraphQL lifetime: ' + metric)
    require(isinstance(counters.get('GraphQLServices'), int)
            and (counters['GraphQLServices'] > 0 if graphql else counters['GraphQLServices'] == 0), 'selected vendor service registration')
    artifacts = manifest.get('artifacts', [])
    require(len(artifacts) == len(expected) - 1 and {a['name'] for a in artifacts} == expected - {'manifest.json'}, 'complete artifact declarations')
    for item in artifacts:
        path = folder / item['name']
        require(sha(path) == item['sha256'] and path.stat().st_size == item['bytes'], 'actual artifact bytes')
    require(result.get('status') == 'passed' and set(result.get('files', [])) == expected
            and result.get('counters') == counters, 'export stdout agrees with actual artifacts')
    if api:
        document = read(folder / 'openapi.json')
        require(str(document.get('openapi', '')).startswith('3.1.')
                and set(document['paths']) == {'/api/catalog/get', '/api/catalog/list', '/api/catalog/set'}
                and {p['post']['operationId'] for p in document['paths'].values()} == set(OPERATIONS), 'actual bounded HTTP schema')
    hashes = file_hashes(folder)
    if frozen is not None:
        require(hashes == frozen, 'deterministic complete exported artifact bytes')
    return {'files_sha256': hashes, 'manifest': manifest}


def verify_driver(result):
    expected = {'operationCounts': [1, 3, 32], 'states': ['fresh', 'noop', 'edit'], 'primersPerState': 2,
                'repetitions': 5, 'iterationsPerRepetition': 3}
    parameters = result.get('parameters', {})
    metadata = {'timedGenerator', 'timedManual', 'trackingTimed', 'cvBasis', 'cvDescriptiveThresholdPercent', 'percentileMethod'}
    require(all(parameters.get(key) == value for key, value in expected.items())
            and set(parameters) <= set(expected) | metadata and result.get('correctnessPassed') is True
            and result.get('status') == 'completed', 'frozen generator benchmark parameters/correctness')
    require(parameters.get('timedGenerator') == 'RunGeneratorsAndUpdateCompilation+Emit'
            and parameters.get('timedManual') == 'already-authored typed registration Emit'
            and parameters.get('trackingTimed') is False and parameters.get('cvDescriptiveThresholdPercent') == 15
            and parameters.get('cvBasis') == 'five repetition means; sample standard deviation ddof=1'
            and parameters.get('percentileMethod') == 'nearest-rank over all 15 measured rows; index=ceil(p*n)-1'
            and result.get('correctnessStatus') == 'passed' and result.get('performanceStatus') == 'observed'
            and result.get('qualificationStatus') == 'not_qualified',
            'actual generator/manual scope and descriptive variability metadata')
    require(len(result.get('measurements', [])) == 270 and len(result.get('primers', [])) == 36
            and len(result.get('stateSeeds', [])) == 12, 'complete actual driver observation matrix')
    require(len(result.get('preflight', [])) == 3 and len(result.get('postflight', [])) == 18, 'complete driver semantic pre/postflight')
    for phase, repetitions, iterations in [('measurements', range(5), range(3)), ('primers', [-1], range(2))]:
        rows = result[phase]
        expected_tuples = {(size, state, variant, repetition, iteration)
                           for size in [1, 3, 32] for state in ['fresh', 'noop', 'edit']
                           for variant in ['manual', 'generator'] for repetition in repetitions for iteration in iterations}
        actual_tuples = {(r['size'], r['state'], r['variant'], r['repetition'], r['iteration']) for r in rows}
        require(actual_tuples == expected_tuples and len(rows) == len(actual_tuples), 'exact driver ' + phase + ' tuples')
        for row in rows:
            case_index = [1, 3, 32].index(row['size']) * 3 + ['fresh', 'noop', 'edit'].index(row['state'])
            sequence = row['iteration'] if phase == 'primers' else 2 + row['repetition'] * 3 + row['iteration']
            pair_order = ['generator', 'manual'] if (case_index + sequence) % 2 == 0 else ['manual', 'generator']
            version = 1 if row['state'] == 'edit' and sequence % 2 == 0 else 0
            ids = ['bench.changed000' if i == 0 and version == 1 else f'bench.op{i:03d}' for i in range(row['size'])]
            require(row['caseIndex'] == case_index and row['pairSequence'] == sequence
                    and row['pairOrder'] == pair_order and row['version'] == version and row['actualIds'] == ids
                    and row['orderInPair'] in [0, 1] and row['pairOrder'][row['orderInPair']] == row['variant'], 'actual paired driver order')
            require(row.get('emitSuccess') is True and all(re.fullmatch('[a-f0-9]{64}', row.get(key, ''))
                    for key in ['sourceHash', 'registryHash', 'peHash']), 'successful actual source/registry/PE emit hashes')
            require(all(isinstance(row.get(key), (int, float)) and not isinstance(row[key], bool) and row[key] >= 0
                        and math.isfinite(row[key]) for key in ['wallTicks', 'wallNanoseconds', 'cpuTicks', 'allocatedBytes', 'gc0', 'gc1', 'gc2']),
                    'real nonnegative finite driver observations')
            require(row.get('diagnostics') == [] and row.get('peBytes', 0) > 0, 'actual emitted executable without error diagnostics')
        require([(r['caseIndex'], r['pairSequence'], r['orderInPair']) for r in rows]
                == sorted((r['caseIndex'], r['pairSequence'], r['orderInPair']) for r in rows), 'actual predeclared driver sequence')
        for index in range(0, len(rows), 2):
            first, second = rows[index:index + 2]
            require(first['caseIndex'] == second['caseIndex'] and first['pairSequence'] == second['pairSequence']
                    and first['sourceHash'] == second['sourceHash'] and first['version'] == second['version']
                    and first['actualIds'] == second['actualIds'], 'each paired variant observes identical business input')
    for phase in ['stateSeeds', 'postflight']:
        expected_tuples = {(size, state, variant) for size in [1, 3, 32]
                           for state in (['noop', 'edit'] if phase == 'stateSeeds' else ['fresh', 'noop', 'edit'])
                           for variant in ['manual', 'generator']}
        rows = result[phase]
        require({(r['size'], r['state'], r['variant']) for r in rows} == expected_tuples, 'complete semantic stage tuples')
        for row in rows:
            size = row['size']
            version = 1 if phase == 'postflight' and row['state'] == 'edit' else 0
            ids = ['bench.changed000' if i == 0 and version == 1 else f'bench.op{i:03d}' for i in range(size)]
            semantic = ','.join(sorted(ids)) + f'|{size * (size - 1)}|{size}|{size}|{size}'
            require(row.get('passed') is True and row.get('emitSuccess') is True and row.get('semantic') == semantic
                    and row.get('version') == version and row.get('actualIds') == ids
                    and re.fullmatch('[a-f0-9]{64}', row.get('peHash', '')), 'actual lazy registration/dispatch/disposal runtime parity')
    require({r['size'] for r in result['preflight']} == {1, 3, 32}, 'exact preflight operation sizes')
    for row in result['preflight']:
        require(row.get('passed') is True and row.get('compilerDependencySeparationPassed') is True
                and row.get('trackingTimed') is False and len(row.get('noopReasons', [])) == row['size']
                and all(reason in ['Cached', 'Unchanged'] for reason in row['noopReasons'])
                and any(reason not in ['Cached', 'Unchanged'] for reason in row.get('editReasons', [])), 'actual cache reuse and edit invalidation outside timing')
    summaries = result.get('summaries', [])
    require(len(summaries) == 18 and len({(s['size'], s['state'], s['variant']) for s in summaries}) == 18, 'complete driver summaries')
    for summary in summaries:
        rows = [r for r in result['measurements']
                if (r['size'], r['state'], r['variant']) == (summary['size'], summary['state'], summary['variant'])]
        require(len(rows) == summary['count'] == 15, 'exact unfiltered driver summary input count')
        values = [r['wallNanoseconds'] for r in rows]
        means = [statistics.mean(r['wallNanoseconds'] for r in rows if r['repetition'] == repetition) for repetition in range(5)]
        require(len(summary['repetitionMeansNanoseconds']) == 5 and all(math.isclose(a, b, rel_tol=1e-10, abs_tol=1e-6)
                for a, b in zip(means, summary['repetitionMeansNanoseconds'])), 'five unfiltered repetition means replay')
        mean, deviation = statistics.mean(means), statistics.stdev(means)
        expected_summary = {'meanNanoseconds': mean, 'sampleStandardDeviationNanoseconds': deviation,
                            'cvPercent': deviation / mean * 100 if mean else 0,
                            'minNanoseconds': min(values), 'maxNanoseconds': max(values),
                            'p50Nanoseconds': sorted(values)[math.ceil(.5 * len(values)) - 1],
                            'p95Nanoseconds': sorted(values)[math.ceil(.95 * len(values)) - 1]}
        require(all(math.isclose(summary.get(key, math.nan), value, rel_tol=1e-10, abs_tol=1e-6)
                    for key, value in expected_summary.items()), 'unfiltered raw extrema/percentile/CV summary replay')
    require(result.get('measurementStatus') == ('unstable-observed' if any(s['cvPercent'] > 15 for s in summaries) else 'observed'),
            'driver variability flag remains descriptive')
    return {'measurements': 270, 'primers': 36, 'state_seeds': 12, 'preflight': 3, 'postflight': 18,
            'correctnessPassed': True, 'parameters': parameters}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dotnet', required=True)
    parser.add_argument('--engine-root', default=str(ROOT.parent / 'Cehpalon-Engine'))
    parser.add_argument('--output', required=True)
    parser.add_argument('--integration', action='store_true', help='Retained preliminary uncommitted-source attempt; never canonical')
    parser.add_argument('--prepare-only', action='store_true', help='Build/verify fixtures only; no timed driver/CLI series and no benchmark pass')
    args = parser.parse_args()
    engine = Path(args.engine_root).resolve()
    output = (ROOT / args.output).resolve()
    private = (ROOT / '.local').resolve()
    require(output != private and output.is_relative_to(private), 'Use a fresh ignored Samples .local subdirectory')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'logs').mkdir()
    (output / 'cases').mkdir()
    (output / 'harness.py.txt').write_bytes(Path(__file__).read_bytes())
    (output / 'engine-lock.json').write_bytes((ROOT / 'tooling-benchmark/engine-lock.json').read_bytes())
    (output / 'protocol-README.md').write_bytes((ROOT / 'tooling-benchmark/README.md').read_bytes())
    environment = dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1', MSBUILDDISABLENODEREUSE='1')
    report = {'schema_version': 1, 'status': 'started', 'correctness_status': 'pending', 'performance_status': 'observed',
              'qualification_status': 'not_qualified', 'started_utc': datetime.now(timezone.utc).isoformat(),
              'canonical': not args.integration and not args.prepare_only, 'preparation': [], 'launches': [],
              'schedule': schedule(), 'scope': 'Bounded #20 observations only; #3 Blocked; full Test/Benchmark Planned; runtime M0',
              'cache_state': 'fresh process; OS/filesystem-cache-primed by preparation, primers and verification; not cold disk',
              'timer': 'perf_counter_ns immediately before subprocess.run through return with stdout/stderr pipes drained; excludes log persistence and verification',
              'cpu_policy': 'per-process CPU unavailable through this portable subprocess runner; null, never inferred from wall or aggregate child CPU',
              'hardware_reservation': 'not established; no dedicated/reference-host claim',
              'comparison': 'CLI absolute observations only; generator comparison is bounded DriverRun+Emit versus independent manual typed registry Emit',
              'environment': {'os': platform.platform(), 'machine': platform.machine(), 'python': sys.version,
                              'logical_cpu_count': os.cpu_count(), 'affinity': sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
                              'dotnet_executable': str(Path(args.dotnet).resolve()), 'source_root': str(engine), 'output_root': str(output)},
              'harness_sha256': sha(Path(__file__)), 'lock_sha256': sha(ROOT / 'tooling-benchmark/engine-lock.json'),
              'protocol_readme_sha256': sha(ROOT / 'tooling-benchmark/README.md')}

    def save():
        (output / 'manifest.json').write_text(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + '\n', encoding='utf-8', newline='\n')

    def invoke(argv, cwd, label, timed=None):
        argv = list(map(str, argv))
        row = {'argv': argv, 'cwd': str(cwd), 'exit': None, 'timed_out': False,
               'clock_role': 'cli_benchmark' if timed else 'preparation_not_benchmark',
               'process_cpu_ns': None, 'process_cpu_status': 'unavailable', 'verification_status': 'pending' if timed else 'not_applicable'}
        if timed:
            row.update(timed)
        start = time.perf_counter_ns()
        try:
            completed = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True, timeout=TIMEOUT)
            end = time.perf_counter_ns()
            stdout, stderr = completed.stdout, completed.stderr
            row['exit'] = completed.returncode
        except subprocess.TimeoutExpired as error:
            end = time.perf_counter_ns()
            stdout, stderr = error.stdout or b'', error.stderr or b''
            row.update(timed_out=True, timeout_seconds=TIMEOUT, error=str(error))
        except OSError as error:
            end = time.perf_counter_ns()
            stdout, stderr = b'', b''
            row.update(error=str(error), launch_failed=True)
        row.update(start_monotonic_ns=start, end_monotonic_ns=end, elapsed_ns=end - start)
        if row['exit'] != 0 or row.get('error'):
            row['verification_status'] = 'failed'
        for stream, data in [('stdout', stdout), ('stderr', stderr)]:
            path = output / 'logs' / (label + '.' + stream + '.txt')
            path.write_bytes(data)
            row[stream] = {'path': path.relative_to(output).as_posix(), 'bytes': len(data), 'sha256': sha(path)}
        (report['launches'] if timed else report['preparation']).append(row)
        save()
        require(row['exit'] == 0 and not row.get('error'), 'Process failed; retained ' + label)
        return stdout.decode('utf-8-sig').strip(), row

    def prep(argv, cwd, label):
        return invoke(argv, cwd, label)[0]

    def build(project, artifacts, label, cwd=engine, initial=False):
        restore = [args.dotnet, 'restore', project, '--configfile', cwd / 'NuGet.Config', '--artifacts-path', artifacts]
        if not initial:
            restore.append('--locked-mode')
        prep(restore, cwd, label + '-restore')
        prep([args.dotnet, 'build', project, '-c', 'Release', '--no-restore', '--artifacts-path', artifacts,
              '-p:UseSharedCompilation=false', '-warnaserror'], cwd, label + '-build')

    save()
    try:
        report['environment']['filesystems'] = {'sdk': filesystem_info(Path(args.dotnet).resolve()),
                                               'source': filesystem_info(engine), 'output': filesystem_info(output)}
        lock = read(ROOT / 'tooling-benchmark/engine-lock.json')
        revision = prep(['git', 'rev-parse', 'HEAD'], engine, 'engine-head')
        dirty = prep(['git', 'status', '--porcelain'], engine, 'engine-status')
        report.update(engine_revision=revision, source_state='uncommitted integration' if dirty else 'exact clean committed source')
        if not args.integration:
            require(not dirty and re.fullmatch('[a-f0-9]{40}', lock['engine_revision']) is not None
                    and revision == lock['engine_revision'], 'Clean Engine must match actual locked revision')
        report['sdk'] = prep([args.dotnet, '--version'], engine, 'sdk-version')
        require(report['sdk'] == lock['sdk'], 'Exact pinned SDK')
        report['dotnet_info'] = prep([args.dotnet, '--info'], engine, 'sdk-info')
        report['engine_source_sha256'] = source_hashes(engine)
        engine_artifacts = output / 'engine-artifacts'
        build(engine / 'src/Cehpalon.Engine.Tooling/Cehpalon.Engine.Tooling.csproj', engine_artifacts, 'cli')
        build(engine / 'Benchmarks/Tooling.Components/Tooling.Components.csproj', engine_artifacts, 'generator')
        cli = [args.dotnet, engine_artifacts / 'bin/Cehpalon.Engine.Tooling/release/cehpalon.dll']
        driver = engine_artifacts / 'bin/Tooling.Components/release/Tooling.Components.dll'
        require(Path(cli[1]).is_file() and driver.is_file(), 'Actual built CLI and generator benchmark executables')
        fixtures, new_frozen, validate_frozen = {}, {}, {}
        report['fixtures'] = {}
        for short, profile in [('portable', 'portable-request-reply'), ('small-api', 'small-api')]:
            folder = output / ('fixture-' + short)
            result = json.loads(prep(cli + ['new', '--profile', profile, '--name', NAME, '--output', folder,
                                           '--engine-root', engine], ROOT, 'fixture-' + short))
            observation = verify_new(folder, result, profile, engine)
            report['fixtures'][short] = observation
            fixtures[short], new_frozen[short] = folder, observation['files_sha256']
            validation = json.loads(prep(cli + ['validate', '--profile', profile, '--config', folder / 'appsettings.json'],
                                         ROOT, 'validate-fixture-' + short))
            validate_frozen[short] = verify_validate(validation, profile)
        report['frozen_validation'] = validate_frozen
        small = fixtures['small-api']
        consumer_artifacts = output / 'consumer-artifacts'
        # First restore produces the actual lock, retained before the locked restore/build.
        prep([args.dotnet, 'restore', small / 'Consumer.csproj', '--configfile', small / 'NuGet.Config',
              '--artifacts-path', consumer_artifacts], small, 'consumer-initial-restore')
        require((small / 'packages.lock.json').is_file(), 'Actual consumer package lock created')
        (output / 'consumer-packages.lock.json').write_bytes((small / 'packages.lock.json').read_bytes())
        report['consumer_package_lock_sha256'] = sha(small / 'packages.lock.json')
        build(small / 'Consumer.csproj', consumer_artifacts, 'consumer', cwd=small)
        require(sha(small / 'packages.lock.json') == report['consumer_package_lock_sha256'], 'Locked consumer restore preserves actual graph')
        registries = list((consumer_artifacts / 'obj').rglob('OperationRegistrations.g.cs'))
        require(len(registries) == 1, 'Exactly one actual emitted registry')
        registry = registries[0].read_text(encoding='utf-8-sig')
        require(registry.count('builder.Register<') == registry.count('factory.Create<') == 3
                and all('"' + op + '"' in registry for op in OPERATIONS), 'Actual typed lazy operation registry')
        (output / 'OperationRegistrations.g.cs.txt').write_bytes(registries[0].read_bytes())
        report['registry_sha256'] = sha(registries[0])
        assembly = consumer_artifacts / ('bin/Consumer/release/PortableConsumer.' + NAME + '.dll')
        libraries = sorted(read(assembly.with_suffix('.deps.json'))['libraries'])
        require(not any(name.startswith('Microsoft.CodeAnalysis') or name.split('/')[0] in
                        {'Cehpalon.Engine.CodeGeneration', 'Cehpalon.Engine.Tooling'} for name in libraries),
                'Compiler/analyzer/CLI excluded from actual consumer runtime')
        require(all(any(name.startswith('Cehpalon.Engine.' + family + '/') for name in libraries)
                    for family in ['Core', 'Composition', 'Identity.Contracts', 'Tenancy', 'Transports.Http', 'Transports.GraphQL']),
                'Actual Core/Composition and authority/transport runtime graph')
        report['runtime_libraries'] = libraries
        export_frozen = {}
        report['frozen_exports'] = {}
        for kind, (config, _, _) in EXPORTS.items():
            target = output / ('fixture-export-' + kind)
            result = json.loads(prep([args.dotnet, assembly, '--export-contracts', '--config', small / config, '--output', target],
                                     small, 'fixture-export-' + kind))
            observation = verify_export(target, result, kind)
            report['frozen_exports'][kind] = observation
            export_frozen[kind] = observation['files_sha256']
        fixed_inputs = [small / name for name, _, _ in EXPORTS.values()] + [fixtures['portable'] / 'appsettings.json']
        report['frozen_configs_sha256'] = {str(p): sha(p) for p in fixed_inputs}
        report['binary_sha256'] = {str(p.relative_to(output)): sha(p) for p in [Path(cli[1]), driver, assembly]}
        save()
        if args.prepare_only:
            report.update(status='completed', mode='preparation_only', benchmark_complete=False,
                          correctness_status='not_run', correctness_gate='not run')
        else:
            generator_output = output / 'generator-observations.json'
            prep([args.dotnet, driver, '--output=' + str(generator_output)], engine, 'generator-observations')
            report['generator'] = verify_driver(read(generator_output))
            report['generator']['raw_sha256'] = sha(generator_output)
            journal = generator_output.with_name(generator_output.name + '.rows.jsonl')
            journal_rows = [json.loads(line) for line in journal.read_text(encoding='utf-8').splitlines()]
            raw_driver = read(generator_output)
            require(len(journal_rows) == 306 and [r['row'] for r in journal_rows if r['phase'] == 'primer'] == raw_driver['primers']
                    and [r['row'] for r in journal_rows if r['phase'] == 'measurement'] == raw_driver['measurements'],
                    'actual append-only raw driver journal preserves every ordered primer/measurement')
            require([(r['row']['caseIndex'], r['row']['pairSequence'], r['row']['orderInPair']) for r in journal_rows]
                    == sorted((r['row']['caseIndex'], r['row']['pairSequence'], r['row']['orderInPair']) for r in journal_rows),
                    'raw driver journal preserves complete cross-phase pair order')
            report['generator']['raw_journal_sha256'] = sha(journal)
            save()
            for planned in report['schedule']:
                scenario = planned['scenario']
                label = f"{planned['sequence']:03d}-{planned['phase']}-{scenario}"
                target = output / 'cases' / label
                require(not target.exists(), 'Fresh invocation destination')
                if scenario.startswith('new-'):
                    short = scenario.removeprefix('new-')
                    profile = 'portable-request-reply' if short == 'portable' else 'small-api'
                    argv = cli + ['new', '--profile', profile, '--name', NAME, '--output', target, '--engine-root', engine]
                    cwd = ROOT
                elif scenario.startswith('validate-'):
                    short = scenario.removeprefix('validate-')
                    profile = 'portable-request-reply' if short == 'portable' else 'small-api'
                    argv = cli + ['validate', '--profile', profile, '--config', fixtures[short] / 'appsettings.json']
                    cwd = ROOT
                else:
                    kind = scenario.removeprefix('export-')
                    argv = [args.dotnet, assembly, '--export-contracts', '--config', small / EXPORTS[kind][0], '--output', target]
                    cwd = small
                stdout, row = invoke(argv, cwd, label, timed={**planned, 'destination': str(target) if not scenario.startswith('validate-') else None})
                try:
                    if not scenario.startswith('validate-') and target.is_dir():
                        row['observed_output_sha256'] = file_hashes(target)
                    result = json.loads(stdout)
                    if scenario.startswith('new-'):
                        row['artifacts'] = verify_new(target, result, profile, engine, new_frozen[short])
                    elif scenario.startswith('validate-'):
                        row['plan'] = verify_validate(result, profile, validate_frozen[short])
                    else:
                        row['artifacts'] = verify_export(target, result, kind, export_frozen[kind])
                    row['verification_status'] = 'passed'
                except Exception as error:
                    row.update(verification_status='failed', verification_error=str(error))
                    save()
                    raise
                save()
            require(len(report['launches']) == 144 and all(row['verification_status'] == 'passed' for row in report['launches'])
                    and [{k: row[k] for k in planned} for row, planned in zip(report['launches'], report['schedule'])] == report['schedule'],
                    'Complete exact predeclared 144-launch schedule passes every verification')
            report['summaries'] = summarize(report['launches'])
            report.update(status='completed', benchmark_complete=True, correctness_status='passed', correctness_gate='100% complete matrix and output checks',
                          unstable_observation=any(x['unstable_observation'] for x in report['summaries'].values()),
                          performance_gate='no numeric performance PASS; descriptive absolute costs only')
        require(source_hashes(engine) == report['engine_source_sha256'] and sha(Path(__file__)) == report['harness_sha256']
                and sha(ROOT / 'tooling-benchmark/engine-lock.json') == report['lock_sha256']
                and sha(ROOT / 'tooling-benchmark/README.md') == report['protocol_readme_sha256'],
                'Source/harness/lock/protocol bytes unchanged through attempt')
        require(all(sha(Path(p)) == digest for p, digest in report['frozen_configs_sha256'].items()), 'Frozen configuration inputs unchanged')
        require(prep(['git', 'rev-parse', 'HEAD'], engine, 'engine-final-head') == revision, 'Engine revision unchanged through attempt')
        if not args.integration:
            require(not prep(['git', 'status', '--porcelain'], engine, 'engine-final-status'), 'Final Engine remains clean')
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    except Exception as error:
        report.update(status='failed', correctness_status='failed', error=str(error), benchmark_complete=False, finished_utc=datetime.now(timezone.utc).isoformat())
        save()
        raise
    save()
    print(json.dumps({'status': report['status'], 'canonical': report['canonical'], 'launches': len(report['launches']), 'output': str(output)}))


if __name__ == '__main__':
    main()
