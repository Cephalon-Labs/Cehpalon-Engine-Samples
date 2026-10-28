"""Full-duration, retained Small API observations; this shared WSL host does not qualify W0.

Never lower protocol defaults to turn a failed gate into a pass. The optional phase
selector only leaves explicitly unrun phases; it does not shorten an executed phase.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import time
import tempfile
import traceback
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
ENGINE_REVISION = '6804271d429106864e01e4ec546a41dff771f84b'
SERVER_CPUS, DRIVER_CPUS, ORCHESTRATOR_CPUS = (0, 2), (4, 6), (8, 10)
ORDER = ('BE', 'EB', 'BE', 'EB', 'BE')
MIB = 1024 * 1024


def stamp():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    """Replace only this attempt's owned observation, not another attempt's evidence."""
    path = Path(path)
    temporary = path.with_name(path.name + '.writing')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n', encoding='utf-8', newline='\n')
    temporary.replace(path)


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def optional_read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


class InfrastructureFailure(RuntimeError):
    pass


class Progress:
    def __init__(self, output):
        self.output = output
        self.state = {'observed_at_utc': stamp(), 'status': 'preflight', 'phase': 'preflight'}
        self.last = 0.0
        self.clock_offset_ns = time.time_ns() - time.monotonic_ns()
        self.clock_failed = False
        self.events = (output / 'progress-events.jsonl').open('x', encoding='utf-8', buffering=1)

    def update(self, **values):
        self.state.update(values)
        self.state['observed_at_utc'] = stamp()
        self.tick(force=True)

    def tick(self, force=False):
        now = time.monotonic()
        deviation = time.time_ns() - time.monotonic_ns() - self.clock_offset_ns
        self.state['wall_monotonic_offset_deviation_ns'] = deviation
        if abs(deviation) > 1_000_000_000 and not self.clock_failed:
            self.clock_failed = True
            raise InfrastructureFailure('Wall/monotonic clock continuity changed by more than1s; retain this whole attempt as invalid.')
        if force or now - self.last >= 30:
            self.state['heartbeat_at_utc'] = stamp()
            write_json(self.output / 'progress.json', self.state)
            self.events.write(json.dumps(self.state, allow_nan=False) + '\n')
            self.events.flush()
            self.last = now

    def wait_until(self, deadline, process=None):
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                raise InfrastructureFailure('Owned server exited during timed observation.')
            self.tick()
            time.sleep(min(.25, max(0, deadline - time.monotonic())))


class Runner:
    def __init__(self, args, output):
        self.args, self.output = args, output
        self.progress = Progress(output)
        self.environment = dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_EnableDiagnostics='0', DOTNET_PROCESSOR_COUNT='2')
        self.owned = []
        self.fixture = None
        self.ca = None
        self.manifest = {}

    def invoke(self, command, name, cwd=ROOT):
        with (self.output / (name + '.stdout.txt')).open('xb') as stdout, (self.output / (name + '.stderr.txt')).open('xb') as stderr:
            process = subprocess.Popen(list(map(str, command)), cwd=cwd, env=self.environment, stdout=stdout, stderr=stderr, start_new_session=True)
            self.owned.append(process)
            deadline = time.monotonic() + 180
            while process.poll() is None:
                self.progress.tick()
                if time.monotonic() > deadline:
                    self.terminate(process)
                    raise InfrastructureFailure('Preflight command timed out: ' + name)
                time.sleep(.1)
            if process.returncode:
                raise InfrastructureFailure('Preflight command failed; retained logs: ' + name)
        return (self.output / (name + '.stdout.txt')).read_text().strip()

    @staticmethod
    def terminate(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def command(self, cpus, *arguments):
        return list(map(str, ['taskset', '--cpu-list', ','.join(map(str, cpus)), self.args.dotnet, self.args.assembly, *arguments]))

    def preflight(self):
        def git(directory, *arguments):
            return subprocess.check_output(['git', *arguments], cwd=directory, text=True).strip()
        engine = self.args.engine_root
        if git(engine, 'rev-parse', 'HEAD') != ENGINE_REVISION or git(engine, 'status', '--porcelain'):
            raise InfrastructureFailure('Require exact clean pinned Engine commit ' + ENGINE_REVISION)
        if git(ROOT, 'status', '--porcelain'):
            raise InfrastructureFailure('Require clean committed Samples source before any measurement.')
        original_affinity = sorted(os.sched_getaffinity(0))
        needed = set(SERVER_CPUS + DRIVER_CPUS + ORCHESTRATOR_CPUS)
        if not needed.issubset(original_affinity):
            raise InfrastructureFailure('Predeclared CPU allocation is unavailable; do not silently remap a measured attempt.')
        os.sched_setaffinity(0, ORCHESTRATOR_CPUS)
        sdk = self.invoke([self.args.dotnet, '--version'], 'sdk-version')
        lock = json.loads((ROOT / 'global.json').read_text())['sdk']['version']
        if sdk != lock:
            raise InfrastructureFailure('SDK differs from global.json.')
        self.invoke([self.args.dotnet, '--info'], 'sdk-info')
        self.invoke(['lscpu', '--json'], 'lscpu')
        self.invoke(['ldd', '--version'], 'glibc')
        self.invoke(['taskset', '--version'], 'taskset-version')
        source_hashes = {}
        for name, directory in [('samples', ROOT), ('engine', engine)]:
            for relative in git(directory, 'ls-files').splitlines():
                path = directory / relative
                if 'evidence' in path.parts or path.suffix not in ('.cs', '.csproj', '.py', '.json', '.props', '.slnx') and path.name != 'NuGet.Config':
                    continue
                if path.is_file():
                    working = path.read_bytes()
                    committed = subprocess.check_output(['git', 'show', 'HEAD:' + relative], cwd=directory)
                    if working != committed:
                        raise InfrastructureFailure('Source bytes differ from committed bytes: ' + name + '/' + relative)
                    source_hashes[name + '/' + relative] = hashlib.sha256(working).hexdigest()
        other = []
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal() or int(entry.name) == os.getpid():
                continue
            try:
                command = (entry / 'cmdline').read_bytes()
                if b'SmallApi.Benchmark.dll' in command or b'benchmark_small_api.py' in command:
                    other.append(int(entry.name))
            except OSError:
                pass
        if other:
            raise InfrastructureFailure('Another benchmark/conformance process is active: ' + str(other))
        cgroup = optional_read('/proc/self/cgroup')
        cgroup_path = None
        if cgroup:
            unified = next((line.split(':', 2)[2] for line in cgroup.splitlines() if line.startswith('0::')), None)
            if unified is not None:
                cgroup_path = Path('/sys/fs/cgroup') / unified.lstrip('/')
        cgroup_files = {name: optional_read(cgroup_path / name) if cgroup_path else None for name in ['cpu.max', 'cpu.stat', 'cpuset.cpus.effective', 'memory.max', 'memory.current', 'memory.events']}
        self.manifest = {
            'schema_version': 1, 'declared_at_utc': stamp(), 'status': 'preflight-complete',
            'orchestrator_pid': os.getpid(),
            'classification': 'OBSERVATIONAL; nonqualifying W0 reference environment',
            'reference_environment_qualified': False,
            'reference_failures': ['WSL CPUs are shared and nonreserved; affinity does not establish dedicated vCPUs.', 'No owned 2GiB application memory cap is established.', 'Host and driver share one WSL/Windows machine; this is not native deployment proof.'],
            'budgets_unchanged': True,
            'engine_revision': ENGINE_REVISION, 'samples_revision': git(ROOT, 'rev-parse', 'HEAD'), 'sdk': sdk,
            'source_sha256': source_hashes, 'assembly': str(self.args.assembly), 'assembly_sha256': sha(self.args.assembly),
            'artifact_provenance_boundary': 'Caller-supplied compiled artifact hash captured; clean committed source and package hashes captured. Compilation provenance must also be retained by the build workflow.',
            'runtimeconfig': json.loads(self.args.assembly.with_suffix('.runtimeconfig.json').read_text()),
            'deps_sha256': sha(self.args.assembly.with_suffix('.deps.json')),
            'environment': {'uname': list(platform.uname()), 'python': sys.version, 'openssl': ssl.OPENSSL_VERSION, 'page_size': os.sysconf('SC_PAGE_SIZE'), 'original_affinity': original_affinity, 'server_cpus': SERVER_CPUS, 'driver_cpus': DRIVER_CPUS, 'orchestrator_cpus': ORCHESTRATOR_CPUS, 'cpu_governors': {str(cpu): optional_read(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor') for cpu in SERVER_CPUS}, 'meminfo': optional_read('/proc/meminfo'), 'cgroup': cgroup, 'cgroup_files': cgroup_files, 'dotnet_environment': {key: self.environment.get(key) for key in ['DOTNET_NOLOGO', 'DOTNET_CLI_TELEMETRY_OPTOUT', 'DOTNET_EnableDiagnostics', 'DOTNET_PROCESSOR_COUNT', 'DOTNET_gcServer', 'DOTNET_GCHeapHardLimit', 'COMPlus_gcServer', 'COMPlus_TieredCompilation', 'COMPlus_ReadyToRun']}},
            'protocol': {'requested_phases': self.args.phases, 'startup_launches_per_variant_transport': 30, 'startup_order': 'BE/EB alternation by index', 'idle_pairs_per_transport': 5, 'load_pairs_per_transport': 5, 'pair_order': ORDER, 'warmup_seconds': 60, 'idle_settle_seconds': 120, 'idle_samples': 60, 'idle_sample_hz': 1, 'measured_load_seconds': 180, 'offered_requests_per_second': 1000, 'maximum_outstanding': 128, 'request_timeout_seconds': 1, 'latency': 'completed minus scheduled; drops/errors retained; no outlier filtering', 'diagnostic_rate_sweeps': 'Not run: 100/500/2000 diagnostic series is separate from acceptance series', 'startup_cache_boundary': 'Fresh processes with OS cache state observed; not machine-cold boots', 'cv_analysis': 'Population standard deviation divided by mean, all five p95 observations per variant/transport'},
            'budgets': {'startup_p95_ms': 1000, 'startup_engine_extra_ms': 150, 'idle_rss_mib': 256, 'idle_engine_extra_mib': 16, 'load_p95_ms': 20, 'load_p99_ms': 50, 'engine_p95_extra': 'max(1ms,15% baseline p95)', 'engine_allocation_extra_bytes_per_request': 1024, 'success_floor': .999, 'unplanned_errors_timeouts_drops': 0, 'p95_coefficient_of_variation': .10},
            'private_fixture': 'Private server.pfx stays in task-owned Linux-home .local/share storage with verified0700/0600 modes; never copy it into evidence. Only public CA DER/hash may be retained externally.'
        }
        write_json(self.output / 'manifest.json', self.manifest)
        private_base = Path.home() / '.local/share/cehpalon-benchmark-fixtures'
        private_base.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(private_base, 0o700)
        container = Path(tempfile.mkdtemp(prefix='attempt-', dir=private_base))
        self.fixture = container / 'fixture'
        self.ca = self.fixture / 'root-ca.der'
        self.invoke([self.args.dotnet, self.args.assembly, '--create-fixture=' + str(self.fixture)], 'fixture-create')
        os.chmod(self.fixture, 0o700)
        private = self.fixture / 'server.pfx'
        if not private.is_file() or not self.ca.is_file():
            raise InfrastructureFailure('Fixture preparation did not produce the declared certificate files.')
        os.chmod(private, 0o600)
        if self.fixture.stat().st_mode & 0o777 != 0o700 or private.stat().st_mode & 0o777 != 0o600:
            raise InfrastructureFailure('Private fixture permissions are not enforced; no timing may start.')
        self.manifest['private_fixture_path'] = str(self.fixture)
        self.manifest['private_fixture_modes_verified'] = {'directory': '0700', 'pfx': '0600'}
        self.manifest['public_ca_sha256'] = sha(self.ca)
        write_json(self.output / 'manifest.json', self.manifest)

    def startup(self):
        observations = []
        for transport in ('http', 'graphql'):
            for index in range(30):
                order = 'BE' if index % 2 == 0 else 'EB'
                for letter in order:
                    variant = 'baseline' if letter == 'B' else 'engine'
                    directory = self.output / 'startup' / transport / f'{index:02d}-{variant}'
                    self.progress.update(phase='startup', transport=transport, index=index, variant=variant)
                    with Server(self, directory, variant, transport) as server:
                        item = {'transport': transport, 'variant': variant, 'index': index, 'pair_order': order, 'startup_milliseconds': server.startup_milliseconds, 'started_monotonic_ns': server.started_ns, 'ready_and_verified_monotonic_ns': server.verified_ns, 'verified_first_business_response': True}
                    item['shutdown'] = server.shutdown
                    item['budget_observation_passed'] = server.startup_milliseconds <= 1000 and server.shutdown['passed']
                    observations.append(item)
                    write_json(directory / 'observation.json', item)
                    write_json(self.output / 'startup-observations.json', observations)
        summaries = []
        for transport in ('http', 'graphql'):
            b = [x['startup_milliseconds'] for x in observations if x['transport'] == transport and x['variant'] == 'baseline']
            e = [x['startup_milliseconds'] for x in observations if x['transport'] == transport and x['variant'] == 'engine']
            bp, ep = percentile(b, .95), percentile(e, .95)
            passed = len(b) == len(e) == 30 and bp <= 1000 and ep <= 1000 and ep <= bp + 150 and all(x['shutdown']['passed'] for x in observations if x['transport'] == transport)
            summaries.append({'transport': transport, 'baseline_count': len(b), 'engine_count': len(e), 'baseline_p95_ms': bp, 'engine_p95_ms': ep, 'budget_observation_passed': passed, 'reference_gate_passed': False})
        write_json(self.output / 'startup-summary.json', summaries)
        return summaries

    def child_driver(self, server, directory, warm_only=False):
        directory.mkdir(parents=True, exist_ok=False)
        command = self.command(DRIVER_CPUS, '--load-client', '--url=' + server.ready['address'], '--ca-file=' + str(self.ca), '--transport=' + server.transport, '--output=' + str(directory), '--warmup=60', '--seconds=' + ('1' if warm_only else '180'), '--rate=1000')
        if warm_only:
            command.append('--warmup-only=true')
        write_json(directory / 'invocation.json', {'command': command, 'observed_at_utc': stamp()})
        with (directory / 'stdout.txt').open('xb') as stdout, (directory / 'stderr.txt').open('xb') as stderr:
            process = subprocess.Popen(command, cwd=ROOT, env=self.environment, stdout=stdout, stderr=stderr, start_new_session=True)
            self.owned.append(process)
            deadline = time.monotonic() + (120 if warm_only else 300)
            try:
                while process.poll() is None:
                    if server.process.poll() is not None:
                        raise InfrastructureFailure('Server died during driver phase.')
                    if time.monotonic() > deadline:
                        raise InfrastructureFailure('Load driver exceeded its bounded protocol timeout.')
                    self.progress.tick()
                    time.sleep(.25)
            finally:
                if process.poll() is None:
                    self.terminate(process)
        result_path = directory / ('warmup-result.json' if warm_only else 'load-result.json')
        if not result_path.is_file():
            raise InfrastructureFailure('Driver produced no structured result; inspect retained stdout/stderr.')
        result = json.loads(result_path.read_text())
        required = ('warmup', 'state', 'manifestHash', 'logicalManifestHash') if warm_only else ('warmup', 'measured', 'state', 'initialValidation', 'initialMetrics', 'finalMetrics', 'manifestHash', 'logicalManifestHash')
        if not isinstance(result, dict) or any(key not in result for key in required):
            raise InfrastructureFailure('Driver result schema is incomplete or incompatible; no selective continuation.')
        result['driver_exit_code'] = process.returncode
        # A structured correctness/budget failure is preserved and scored, never hidden by retries.
        return result

    def idle(self):
        observations, pairs = [], []
        for transport in ('http', 'graphql'):
            for index, order in enumerate(ORDER):
                pair = {}
                for letter in order:
                    variant = 'baseline' if letter == 'B' else 'engine'
                    directory = self.output / 'idle' / transport / f'{index:02d}-{variant}'
                    self.progress.update(phase='idle-warmup', transport=transport, pair=index, variant=variant)
                    with Server(self, directory, variant, transport) as server:
                        warmup = self.child_driver(server, directory / 'warmup', warm_only=True)
                        warm_valid = phase_correct(warmup.get('warmup'), 60000) and warmup.get('state', {}).get('passed') is True and warmup['driver_exit_code'] == 0
                        started_ns = time.monotonic_ns()
                        started = started_ns / 1e9
                        self.progress.update(phase='idle-settle-120s', transport=transport, pair=index, variant=variant)
                        self.progress.wait_until(started + 120, server.process)
                        self.progress.update(phase='idle-sample-60s', transport=transport, pair=index, variant=variant)
                        samples = []
                        for second in range(60):
                            target_ns = started_ns + (120 + second) * 1_000_000_000
                            self.progress.wait_until(target_ns / 1e9, server.process)
                            observed_ns = time.monotonic_ns()
                            resident = int(Path(f'/proc/{server.process.pid}/statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
                            samples.append({'index': second, 'scheduled_monotonic_ns': target_ns, 'observed_monotonic_ns': observed_ns, 'schedule_lateness_ns': observed_ns - target_ns, 'sampling_slot_valid': target_ns <= observed_ns < target_ns + 1_000_000_000, 'rss_bytes': resident})
                            write_json(directory / 'rss-samples.json', samples)
                        self.progress.wait_until(started + 180, server.process)
                        values = [x['rss_bytes'] for x in samples]
                        item = {'variant': variant, 'transport': transport, 'pair': index, 'pair_order': order, 'warmup_valid': warm_valid, 'warmup_manifest_hash': warmup['manifestHash'], 'rss_sample_count': len(values), 'sampling_schedule_valid': all(sample['sampling_slot_valid'] for sample in samples), 'median_rss_bytes': statistics.median(values), 'maximum_rss_bytes': max(values), 'minimum_rss_bytes': min(values), 'idle_started_monotonic_ns': started_ns}
                    item['shutdown'] = server.shutdown
                    item['budget_observation_passed'] = warm_valid and item['sampling_schedule_valid'] and max(values) <= 256 * MIB and server.shutdown['passed']
                    observations.append(item)
                    pair[variant] = item
                    write_json(directory / 'observation.json', item)
                    write_json(self.output / 'idle-observations.json', observations)
                passed = all(x['budget_observation_passed'] for x in pair.values()) and pair['engine']['median_rss_bytes'] <= pair['baseline']['median_rss_bytes'] + 16 * MIB and pair['engine']['warmup_manifest_hash'] == pair['baseline']['warmup_manifest_hash']
                pairs.append({'transport': transport, 'pair': index, 'pair_order': order, 'baseline_median_rss_bytes': pair['baseline']['median_rss_bytes'], 'engine_median_rss_bytes': pair['engine']['median_rss_bytes'], 'budget_observation_passed': passed, 'reference_gate_passed': False})
                write_json(self.output / 'idle-summary.json', pairs)
        return pairs

    def load(self):
        observations, pairs = [], []
        for transport in ('http', 'graphql'):
            for index, order in enumerate(ORDER):
                pair = {}
                for letter in order:
                    variant = 'baseline' if letter == 'B' else 'engine'
                    directory = self.output / 'load' / transport / f'{index:02d}-{variant}'
                    self.progress.update(phase='load-warmup60-measure180', transport=transport, pair=index, variant=variant)
                    with Server(self, directory, variant, transport) as server:
                        result = self.child_driver(server, directory / 'driver')
                    measured = result.get('measured', {})
                    initial, final = result.get('initialMetrics', {}), result.get('finalMetrics', {})
                    allocation = (final['totalAllocatedBytes'] - initial['totalAllocatedBytes']) / 180000 if 'totalAllocatedBytes' in initial and 'totalAllocatedBytes' in final else None
                    valid = phase_correct(result.get('warmup'), 60000) and phase_correct(measured, 180000) and result.get('initialValidation', {}).get('passed') is True and result.get('state', {}).get('passed') is True and result['driver_exit_code'] == 0
                    item = {'variant': variant, 'transport': transport, 'pair': index, 'pair_order': order, 'driver_valid': valid, 'measured': measured, 'manifest_hash': result.get('manifestHash'), 'logical_manifest_hash': result.get('logicalManifestHash'), 'final_state_hash': result.get('finalState', {}).get('stateHash'), 'allocations_bytes_per_offered_request': allocation, 'shutdown': server.shutdown}
                    item['budget_observation_passed'] = valid and allocation is not None and allocation >= 0 and measured.get('p95Ms', float('inf')) <= 20 and measured.get('p99Ms', float('inf')) <= 50 and server.shutdown['passed']
                    observations.append(item)
                    pair[variant] = item
                    write_json(directory / 'observation.json', item)
                    write_json(self.output / 'load-observations.json', observations)
                baseline, engine = pair['baseline'], pair['engine']
                bp, ep = baseline['measured'].get('p95Ms'), engine['measured'].get('p95Ms')
                same = baseline['manifest_hash'] is not None and baseline['manifest_hash'] == engine['manifest_hash'] and baseline['logical_manifest_hash'] == engine['logical_manifest_hash'] and baseline['final_state_hash'] is not None and baseline['final_state_hash'] == engine['final_state_hash']
                overhead = bp is not None and ep is not None and ep <= bp + max(1, .15 * bp)
                allocation = baseline['allocations_bytes_per_offered_request'] is not None and engine['allocations_bytes_per_offered_request'] is not None and engine['allocations_bytes_per_offered_request'] <= baseline['allocations_bytes_per_offered_request'] + 1024
                pairs.append({'transport': transport, 'pair': index, 'pair_order': order, 'same_manifest': same, 'baseline_p95_ms': bp, 'engine_p95_ms': ep, 'p95_overhead_passed': overhead, 'allocation_overhead_passed': allocation, 'budget_observation_passed': same and overhead and allocation and baseline['budget_observation_passed'] and engine['budget_observation_passed'], 'reference_gate_passed': False})
                write_json(self.output / 'load-pairs.json', pairs)
        stability = []
        for transport in ('http', 'graphql'):
            for variant in ('baseline', 'engine'):
                values = [x['measured'].get('p95Ms') for x in observations if x['transport'] == transport and x['variant'] == variant]
                valid = len(values) == 5 and all(isinstance(x, (int, float)) and x > 0 for x in values)
                cv = statistics.pstdev(values) / statistics.mean(values) if valid else None
                stability.append({'transport': transport, 'variant': variant, 'p95_observations_ms': values, 'population_coefficient_of_variation': cv, 'budget_observation_passed': cv is not None and cv <= .10})
        logical = {item['logical_manifest_hash'] for item in observations}
        logical_parity = len(logical) == 1 and None not in logical
        baseline_capable = all(item['driver_valid'] for item in observations if item['variant'] == 'baseline')
        series_valid = baseline_capable and logical_parity and all(item['budget_observation_passed'] for item in stability)
        result = {'pairs': pairs, 'stability': stability, 'logical_manifest_parity_across_transports': logical_parity, 'baseline_sustained_offered_work': baseline_capable, 'observational_performance_series_valid': series_valid, 'all_budget_observations_passed': series_valid and all(x['budget_observation_passed'] for x in pairs + stability), 'reference_gate_passed': False}
        write_json(self.output / 'load-summary.json', result)
        return result


def phase_correct(phase, expected):
    return isinstance(phase, dict) and phase.get('offered') == expected and phase.get('correct') == expected and phase.get('errors') == 0 and phase.get('dropped') == 0 and phase.get('successfulWithinDrain', 0) >= .999 * expected


class Server:
    def __init__(self, runner, directory, variant, transport):
        self.runner, self.directory, self.variant, self.transport = runner, directory, variant, transport
        self.process = None
        self.shutdown = None
        self.ready = None

    def __enter__(self):
        self.directory.mkdir(parents=True, exist_ok=False)
        ready_file, self.state_file = self.directory / 'ready.json', self.directory / 'final-state.json'
        command = self.runner.command(SERVER_CPUS, '--mode=serve', '--variant=' + self.variant, '--transport=' + self.transport, '--fixture-dir=' + str(self.runner.fixture), '--ready-file=' + str(ready_file), '--state-file=' + str(self.state_file))
        write_json(self.directory / 'invocation.json', {'command': command, 'observed_at_utc': stamp()})
        self.stdout = (self.directory / 'server.stdout.txt').open('xb')
        self.stderr = (self.directory / 'server.stderr.txt').open('xb')
        self.started_ns = time.monotonic_ns()
        self.process = subprocess.Popen(command, cwd=ROOT, env=self.runner.environment, stdin=subprocess.PIPE, stdout=self.stdout, stderr=self.stderr, text=True, start_new_session=True)
        self.runner.owned.append(self.process)
        try:
            deadline = time.monotonic() + 60
            while self.ready is None:
                if self.process.poll() is not None:
                    raise InfrastructureFailure('Server exited before readiness; see retained server logs.')
                if time.monotonic() > deadline:
                    raise InfrastructureFailure('Server readiness exceeded 60 seconds.')
                if ready_file.is_file():
                    try:
                        value = json.loads(ready_file.read_text())
                        if value.get('address') and value.get('tlsProtocol') == 'Tls13':
                            self.ready = value
                    except json.JSONDecodeError:
                        pass
                self.runner.progress.tick()
                if self.ready is None:
                    time.sleep(.005)
            self.verify_first_response()
            self.startup_milliseconds = (self.verified_ns - self.started_ns) / 1e6
            return self
        except BaseException:
            self.stop()
            raise

    def verify_first_response(self):
        address = urlsplit(self.ready['address'])
        if address.scheme != 'https' or address.hostname not in ('localhost', '127.0.0.1', '::1'):
            raise InfrastructureFailure('Only owned localhost HTTPS fixture addresses are allowed.')
        if self.ready.get('processId') != self.process.pid or self.ready.get('datasetId') != 'cehpalon-small-api-v1':
            raise InfrastructureFailure('Ready identity/dataset differs from the owned process.')
        if base64.b64decode(self.ready['rootCaDerBase64']) != self.runner.ca.read_bytes():
            raise InfrastructureFailure('Readiness CA differs from precreated fixture CA.')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(self.runner.ca.read_bytes()))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        client = http.client.HTTPSConnection(address.hostname, address.port, context=context, timeout=10)
        try:
            payload = {'id': 1} if self.transport == 'http' else {'query': '{catalogItem(input:{id:1}){id label revision amountMinorUnits}}'}
            client.request('POST', '/api/catalog/get' if self.transport == 'http' else '/graphql', json.dumps(payload, separators=(',', ':')).encode(), {'Content-Type': 'application/json'})
            tls_protocol = client.sock.version() if client.sock else None
            tls_cipher = client.sock.cipher() if client.sock else None
            response = client.getresponse()
            body = json.loads(response.read())
            if response.status != 200 or 'errors' in body:
                raise InfrastructureFailure('First business response was not a valid success.')
            item = body if self.transport == 'http' else body.get('data', {}).get('catalogItem')
            if item != {'id': 1, 'label': 'item-00001', 'revision': 0, 'amountMinorUnits': 17}:
                raise InfrastructureFailure('First verified business result differs from frozen dataset.')
            self.verified_ns = time.monotonic_ns()
            write_json(self.directory / 'first-response.json', {'http_status': response.status, 'body': body, 'tls_protocol': tls_protocol, 'tls_cipher': tls_cipher})
        finally:
            client.close()

    def stop(self):
        if self.shutdown is not None:
            return
        started = time.monotonic_ns()
        graceful = False
        error = None
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.stdin.write('STOP\n')
                self.process.stdin.flush()
                try:
                    self.process.wait(timeout=5)
                    graceful = True
                except subprocess.TimeoutExpired:
                    error = 'Owned shutdown exceeded5seconds; process terminated after retaining failure.'
                    self.runner.terminate(self.process)
            else:
                error = 'Owned server was already absent before requested shutdown.'
        except (OSError, BrokenPipeError) as exception:
            error = repr(exception)
            if self.process is not None:
                self.runner.terminate(self.process)
        elapsed = (time.monotonic_ns() - started) / 1e6
        closed = False
        if self.ready:
            address = urlsplit(self.ready['address'])
            try:
                with socket.create_connection((address.hostname, address.port), timeout=.25):
                    pass
            except OSError:
                closed = True
        try:
            state = json.loads(self.state_file.read_text()) if self.state_file.is_file() else None
        except (OSError, json.JSONDecodeError) as exception:
            state = None
            error = (error + '; ' if error else '') + 'Incomplete final state: ' + repr(exception)
        owned = state is not None and state.get('factories') == state.get('disposals') and state.get('factories') is not None
        probes = state.get('probes', {}) if state else {}
        forbidden = probes.get('forbiddenFactories', probes.get('ForbiddenFactories'))
        disabled = forbidden == 0
        if self.transport == 'http':
            for name in ('GraphQLFactories', 'GraphQLServices', 'GraphQLDiagnosticConstructors', 'GraphQLExecutorInitializations', 'GraphQLSchemasReady'):
                disabled = disabled and probes.get(name[0].lower() + name[1:], probes.get(name)) == 0
        passed = graceful and elapsed <= 5000 and self.process.returncode == 0 and closed and owned and disabled
        self.shutdown = {'requested_monotonic_ns': started, 'elapsed_ms': elapsed, 'graceful': graceful, 'exit_code': self.process.returncode if self.process else None, 'listener_closed': closed, 'owned_handlers_balanced': owned, 'disabled_probes_zero': disabled, 'passed': passed, 'error': error}
        write_json(self.directory / 'shutdown.json', self.shutdown)
        self.stdout.close()
        self.stderr.close()

    def __exit__(self, exception_type, exception, tb):
        self.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dotnet', required=True, type=Path)
    parser.add_argument('--assembly', required=True, type=Path)
    parser.add_argument('--engine-root', type=Path, default=ROOT.parent / 'Cehpalon-Engine')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--phases', default='startup,idle,load')
    parser.add_argument('--preflight-only', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('This observational orchestrator is Linux-only; Windows remains a separate proof gate.')
    args.dotnet, args.assembly, args.engine_root = args.dotnet.resolve(), args.assembly.resolve(), args.engine_root.resolve()
    args.phases = args.phases.split(',')
    if len(set(args.phases)) != len(args.phases) or any(phase not in ('startup', 'idle', 'load') for phase in args.phases):
        parser.error('Select unique phases from startup,idle,load; full defaults are never shortened.')
    output = (ROOT / args.output).resolve()
    private = (ROOT / '.local').resolve()
    if not output.is_relative_to(private) or output == private:
        parser.error('Use a fresh attempt directory beneath ignored Samples .local.')
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    runner = Runner(args, output)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Received signal ' + str(signum) + '; stopping only owned processes.')
    signal.signal(signal.SIGTERM, interrupted)
    summary = {'started_at_utc': stamp(), 'classification': 'OBSERVATIONAL; nonqualifying W0 reference environment', 'reference_gate_passed': False, 'completed_phases': [], 'not_run_phases': ['startup', 'idle', 'load']}
    try:
        runner.preflight()
        if not args.preflight_only:
            for phase in args.phases:
                summary[phase] = getattr(runner, phase)()
                summary['completed_phases'].append(phase)
                summary['not_run_phases'].remove(phase)
                write_json(output / 'summary.json', summary)
        numeric = []
        for phase in summary['completed_phases']:
            numeric.append(summary[phase]['all_budget_observations_passed'] if phase == 'load' else all(item['budget_observation_passed'] for item in summary[phase]))
        summary.update(status='preflight-only' if args.preflight_only else 'observations-complete', numeric_budget_observations_passed=all(numeric) if numeric else None, completed_at_utc=stamp())
        runner.manifest.update(status=summary['status'], completed_at_utc=summary['completed_at_utc'])
        write_json(output / 'manifest.json', runner.manifest)
        write_json(output / 'summary.json', summary)
        runner.progress.update(status=summary['status'], phase='complete', reference_gate_passed=False)
        print(json.dumps({'status': summary['status'], 'completed_phases': summary['completed_phases'], 'reference_gate_passed': False, 'output': str(output)}))
        return 0
    except BaseException as error:
        summary.update(status='aborted-infrastructure', error=repr(error), completed_at_utc=stamp())
        runner.manifest.update(status='aborted-infrastructure', error=repr(error), completed_at_utc=summary['completed_at_utc'])
        write_json(output / 'manifest.json', runner.manifest)
        (output / 'failure-traceback.txt').write_text(traceback.format_exc(), encoding='utf-8')
        write_json(output / 'summary.json', summary)
        runner.progress.update(status='aborted-infrastructure', error=repr(error), phase='aborted')
        print(json.dumps({'status': summary['status'], 'error': repr(error), 'output': str(output)}), file=sys.stderr)
        return 1
    finally:
        for process in reversed(runner.owned):
            runner.terminate(process)
        runner.progress.events.close()


if __name__ == '__main__':
    raise SystemExit(main())
