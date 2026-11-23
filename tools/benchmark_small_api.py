"""Full-duration Small API observations and guarded two-host W0 reference execution.

Never lower protocol defaults to turn a failed gate into a pass. The optional phase
selector only leaves explicitly unrun phases; it does not shorten an executed phase.
"""
import argparse
import base64
import errno
from ipaddress import IPv4Address, IPv4Network
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
from small_api_collector_evidence import audit_reference_driver, audit_successful_preflight_rows, validate_collector_preparation, validate_phase_telemetry, validate_preflight_rejection

ROOT = Path(__file__).resolve().parents[1]
SERVER_CPUS, DRIVER_CPUS, ORCHESTRATOR_CPUS = (0, 2), (4, 6), (8, 10)
ORDER = ('BE', 'EB', 'BE', 'EB', 'BE')
MIB = 1024 * 1024
PHASES = ('startup', 'idle', 'load', 'diagnostics')
OBSERVATIONAL = 'OBSERVATIONAL; nonqualifying W0 reference environment'
LAB = 'LAB; nonqualifying remote TLS preflight only'
REFERENCE = 'W0; guarded two-host reference attempt'
PRIVATE_SUBNETS = tuple(IPv4Network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


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


def read_remote_configuration(path, lab):
    config = json.loads(path.read_text(encoding='utf-8'))
    required = {'app', 'driver'} if lab else {'app', 'driver', 'build_manifest'}
    if not isinstance(config, dict) or set(config) != required:
        raise ValueError('Unexpected remote configuration fields; see the private configuration contract.')
    app, driver = config['app'], config['driver']
    app_keys = {'listen_ip', 'driver_ip'} if lab else {'listen_ip', 'driver_ip', 'resources'}
    if not isinstance(app, dict) or set(app) != app_keys or not isinstance(driver, dict):
        raise ValueError('Expected app and driver configuration objects with the declared fields.')
    listen, peer = IPv4Address(app['listen_ip']), IPv4Address(app['driver_ip'])
    if not all(isinstance(app[key], str) and any(ip in network for network in PRIVATE_SUBNETS)
               for key, ip in (('listen_ip', listen), ('driver_ip', peer))):
        raise ValueError('Remote benchmark fixture requires two RFC1918 IPv4 addresses.')
    if listen == peer or driver.get('app_host') != str(listen):
        raise ValueError('App bind IP, declared driver IP and TLS destination do not agree.')
    if not lab and (not isinstance(config['build_manifest'], str) or not Path(config['build_manifest']).is_absolute()):
        raise ValueError('Use the absolute path to the exact locked Release build manifest.')
    return config


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
        self.remote = None
        self.app_resources = None
        self.reference_preflight_passed = False
        self.remote_config = getattr(args, 'remote_config', None)
        self.remote_preflight_lab = getattr(args, 'remote_preflight_lab', False)
        self.classification = (LAB if self.remote_preflight_lab else REFERENCE) if self.remote_config else OBSERVATIONAL
        self.manifest = {'classification': self.classification, 'reference_environment_qualified': False}

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

    def configure_remote(self, engine_revision, samples_revision, sdk):
        from small_api_remote_driver import RemoteDriver
        config = read_remote_configuration(self.remote_config, self.remote_preflight_lab)
        self.network = config['app']
        if not self.remote_preflight_lab:
            from small_api_reference_resources import AppResources
            self.app_resources = AppResources(self.network['resources'])
            app = self.app_resources.check()
            build = Path(config['build_manifest'])
            receipt = json.loads(build.read_text(encoding='utf-8'))
            deployment = self.args.assembly.parent
            paths = sorted(deployment.rglob('*'))
            if any(path.is_symlink() for path in paths):
                raise InfrastructureFailure('The locked Release deployment contains a symbolic link.')
            files = {path.relative_to(deployment).as_posix(): sha(path) for path in paths if path.is_file()}
            if (receipt.get('status') not in ('build-only', 'passed') or receipt.get('sdk') != sdk
                    or receipt.get('source_state') != 'exact clean committed source'
                    or receipt.get('samples_source_revision') != samples_revision
                    or receipt.get('engine_revision') != engine_revision
                    or receipt.get('assembly_sha256') != sha(self.args.assembly)
                    or not files or receipt.get('deployment_sha256') != files):
                raise InfrastructureFailure('Release artifact does not match the exact locked build receipt.')
            self.manifest['reference_build_manifest_sha256'] = sha(build)
            self.manifest['reference_app_resources'] = app
        # Align runtime switches on both sides with the helper's fixed launch environment.
        fixed = {'DOTNET_NOLOGO': '1', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
                 'DOTNET_EnableDiagnostics': '0', 'DOTNET_PROCESSOR_COUNT': '2', 'DOTNET_ROLL_FORWARD': 'Disable'}
        self.environment = {key: value for key, value in self.environment.items()
                            if not key.upper().startswith(('DOTNET_', 'COMPLUS_'))}
        self.environment.update(fixed)
        self.remote = RemoteDriver(config['driver'], self.args.assembly, sdk, lab=self.remote_preflight_lab)
        driver = self.remote.probe()
        self.manifest['remote_driver'] = driver
        if not self.remote_preflight_lab:
            from small_api_reference_resources import verify_driver_resources
            self.manifest['reference_driver_resources'] = verify_driver_resources(app, driver['resources'])
        self.manifest['network'] = {'topology': 'TLS app and SSH-launched load driver',
                                    'app_ip': self.network['listen_ip'], 'driver_ip': self.network['driver_ip'],
                                    'startup_first_business_response': 'App host via the same private TLS listener'}

    def server_command(self, *arguments):
        if self.remote is None:
            return self.command(SERVER_CPUS, *arguments)
        arguments += ('--fixture-listen-ip=' + self.network['listen_ip'],
                      '--fixture-peer-ip=' + self.network['driver_ip'])
        if self.app_resources is not None:
            return self.app_resources.command(self.args.dotnet, self.args.assembly, *arguments)
        return list(map(str, (self.args.dotnet, self.args.assembly, *arguments)))

    def preflight(self):
        def git(directory, *arguments):
            return subprocess.check_output(['git', *arguments], cwd=directory, text=True).strip()
        engine = self.args.engine_root
        benchmark_lock = json.loads((ROOT / 'small-api-benchmark/engine-lock.json').read_text(encoding='utf-8'))
        engine_revision = benchmark_lock['engine_revision']
        if git(engine, 'rev-parse', 'HEAD') != engine_revision or git(engine, 'status', '--porcelain'):
            raise InfrastructureFailure('Require exact clean pinned Engine commit ' + engine_revision)
        if git(ROOT, 'status', '--porcelain'):
            raise InfrastructureFailure('Require clean committed Samples source before any measurement.')
        original_affinity = sorted(os.sched_getaffinity(0))
        if not self.remote_config:
            needed = set(SERVER_CPUS + DRIVER_CPUS + ORCHESTRATOR_CPUS)
            if not needed.issubset(original_affinity):
                raise InfrastructureFailure('Predeclared CPU allocation is unavailable; do not silently remap a measured attempt.')
            os.sched_setaffinity(0, ORCHESTRATOR_CPUS)
        sdk = self.invoke([self.args.dotnet, '--version'], 'sdk-version')
        sdk_pin = json.loads((ROOT / 'global.json').read_text(encoding='utf-8'))['sdk']['version']
        if sdk != sdk_pin or sdk != benchmark_lock['sdk']:
            raise InfrastructureFailure('SDK differs from global.json or the benchmark lock.')
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
        samples_revision = git(ROOT, 'rev-parse', 'HEAD')
        if self.remote_config:
            self.configure_remote(engine_revision, samples_revision, sdk)
        self.manifest.update({
            'schema_version': 1, 'declared_at_utc': stamp(), 'status': 'preflight-preparing',
            'orchestrator_pid': os.getpid(),
            'reference_failures': [] if self.app_resources is not None else (
                ['Remote laboratory proof is preflight-only and does not establish dedicated hardware.'] if self.remote else
                ['Loopback observation does not establish reserved app resources or an independent load driver.']),
            'budgets_unchanged': True,
            'collector_preparation': {'decision': 'ADR0011', 'control_pool_separate': True, 'load_pool_initially_fresh': True, 'held_http11_responses_required': 128, 'load_tls_connection_identities_required': 128, 'shared_barrier_deadline_seconds': 30, 'preflight_seconds': 2, 'preparation_retries': 0, 'entered_phase_tls_evidence_required': True, 'boundary': 'A verified simultaneous held-response barrier establishes observed preparation readiness; it is not sustained capacity or production qualification.'},
            'engine_revision': engine_revision, 'samples_revision': samples_revision, 'sdk': sdk,
            'source_sha256': source_hashes, 'assembly': str(self.args.assembly), 'assembly_sha256': sha(self.args.assembly),
            'deployment': {'dotnet': str(self.args.dotnet), 'assembly_directory': str(self.args.assembly.parent), 'server_working_directory': str(self.args.server_working_directory), 'output_directory': str(self.output), 'boundary': 'Filesystem/deployment paths are explicit and shared by both variants; native storage does not establish dedicated CPU/RAM or native OS deployment proof.'},
            'artifact_provenance_boundary': 'Caller-supplied compiled artifact hash captured; clean committed source and package hashes captured. Compilation provenance must also be retained by the build workflow.',
            'runtimeconfig': json.loads(self.args.assembly.with_suffix('.runtimeconfig.json').read_text()),
            'deps_sha256': sha(self.args.assembly.with_suffix('.deps.json')),
            'environment': {'uname': list(platform.uname()), 'python': sys.version, 'openssl': ssl.OPENSSL_VERSION, 'page_size': os.sysconf('SC_PAGE_SIZE'), 'original_affinity': original_affinity, 'controller_affinity': sorted(os.sched_getaffinity(0)), 'server_cpus': SERVER_CPUS if self.remote is None else None, 'driver_cpus': DRIVER_CPUS if self.remote is None else None, 'orchestrator_cpus': ORCHESTRATOR_CPUS if self.remote is None else None, 'cpu_governors': {str(cpu): optional_read(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor') for cpu in SERVER_CPUS} if self.remote is None else None, 'meminfo': optional_read('/proc/meminfo'), 'cgroup': cgroup, 'cgroup_files': cgroup_files, 'dotnet_environment': {key: self.environment.get(key) for key in ['DOTNET_NOLOGO', 'DOTNET_CLI_TELEMETRY_OPTOUT', 'DOTNET_EnableDiagnostics', 'DOTNET_PROCESSOR_COUNT', 'DOTNET_ROLL_FORWARD', 'DOTNET_ROOT', 'DOTNET_gcServer', 'DOTNET_GCHeapHardLimit', 'DOTNET_TieredCompilation', 'DOTNET_TieredPGO', 'DOTNET_ReadyToRun', 'DOTNET_TC_QuickJit', 'DOTNET_TC_QuickJitForLoops', 'COMPlus_gcServer', 'COMPlus_TieredCompilation', 'COMPlus_TieredPGO', 'COMPlus_ReadyToRun']}},
            'protocol': {'requested_phases': self.args.phases, 'startup_launches_per_variant_transport': 30, 'startup_order': 'BE/EB alternation by index', 'idle_pairs_per_transport': 5, 'load_pairs_per_transport': 5, 'pair_order': ORDER, 'warmup_seconds': 60, 'idle_settle_seconds': 120, 'idle_samples': 60, 'idle_sample_hz': 1, 'measured_load_seconds': 180, 'offered_requests_per_second': 1000, 'maximum_outstanding': 128, 'request_timeout_seconds': 1, 'latency': 'completed minus scheduled; drops/errors retained; no outlier filtering', 'diagnostic_rate_sweeps': {'rates_and_order': [{'rate': 100, 'order': 'BE'}, {'rate': 500, 'order': 'EB'}, {'rate': 2000, 'order': 'BE'}], 'transports': ['http', 'graphql'], 'warmup_seconds': 60, 'measured_seconds': 180, 'maximum_outstanding': 128, 'acceptance_budget_role': 'None: diagnostics never replace or select an acceptance rate; structured failed collector preflights remain failed attempts without timed runs.'}, 'startup_cache_boundary': 'Fresh processes with OS cache state observed; not machine-cold boots', 'cv_analysis': 'Population standard deviation divided by mean, all five p95 observations per variant/transport'},
            'budgets': {'startup_p95_ms': 1000, 'startup_engine_extra_ms': 150, 'idle_rss_mib': 256, 'idle_engine_extra_mib': 16, 'load_p95_ms': 20, 'load_p99_ms': 50, 'engine_p95_extra': 'max(1ms,15% baseline p95)', 'engine_allocation_extra_bytes_per_request': 1024, 'success_floor': .999, 'unplanned_errors_timeouts_drops': 0, 'p95_coefficient_of_variation': .10},
            'private_fixture': 'Private server.pfx stays in task-owned Linux-home .local/share storage with verified0700/0600 modes; never copy it into evidence. Only public CA DER/hash may be retained externally.'
        })
        write_json(self.output / 'manifest.json', self.manifest)
        private_base = Path.home() / '.local/share/cehpalon-benchmark-fixtures'
        private_base.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(private_base, 0o700)
        container = Path(tempfile.mkdtemp(prefix='attempt-', dir=private_base))
        self.fixture = container / 'fixture'
        self.ca = self.fixture / 'root-ca.der'
        fixture_command = [self.args.dotnet, self.args.assembly, '--create-fixture=' + str(self.fixture)]
        if self.remote is not None:
            fixture_command.append('--fixture-listen-ip=' + self.network['listen_ip'])
        self.invoke(fixture_command, 'fixture-create')
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
        if self.remote is not None:
            self.remote_preflight()
        self.manifest['status'] = 'preflight-complete'
        write_json(self.output / 'manifest.json', self.manifest)

    def remote_preflight(self):
        cases = []
        for transport in ('http', 'graphql'):
            for variant in ('baseline', 'engine'):
                directory = self.output / 'remote-preflight' / transport / variant
                self.progress.update(phase='remote-preflight', variant=variant, transport=transport)
                with Server(self, directory, variant, transport) as server:
                    preflight = self.child_driver(server, directory / 'driver', preflight_only=True)
                if not server.shutdown['passed']:
                    raise InfrastructureFailure('Remote qualification fixture did not shut down cleanly.')
                raw = audit_successful_preflight_rows(directory / 'driver', 1000)
                cases.append({'variant': variant, 'transport': transport, **preflight, 'raw_accounting': raw})
                write_json(self.output / 'remote-preflight-summary.json',
                           {'completed_lanes': cases, 'timed_phases_entered': False})
        self.reference_preflight_passed = self.app_resources is not None
        self.manifest['reference_environment_qualified'] = self.reference_preflight_passed

    def audit_reference_timed_evidence(self):
        receipts = []
        for phase, subdir in (('idle', 'warmup'), ('load', 'driver')):
            for transport in ('http', 'graphql'):
                for index in range(5):
                    for variant in ('baseline', 'engine'):
                        directory = self.output / phase / transport / f'{index:02d}-{variant}' / subdir
                        receipt = audit_reference_driver(directory, transport, warm_only=phase == 'idle')
                        receipts.append({'directory': directory.relative_to(self.output).as_posix(), **receipt})
            self.progress.tick(force=True)
        write_json(self.output / 'reference-timed-evidence-audit.json', {'status': 'passed', 'drivers': receipts})
        return len(receipts)

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

    def wait_for_driver(self, server, process, timeout):
        self.owned.append(process)
        deadline = time.monotonic() + timeout
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

    def child_driver(self, server, directory, warm_only=False, rate=1000, allow_capacity_failure=False, preflight_only=False):
        directory.mkdir(parents=True, exist_ok=False)
        arguments = ['--load-client', '--url=' + server.ready['address'], '--transport=' + server.transport,
                     '--warmup=60', '--seconds=' + ('1' if warm_only else '180'), '--rate=' + str(rate)]
        if warm_only:
            arguments.append('--warmup-only=true')
        if preflight_only:
            arguments.append('--preflight-only=true')
        timeout = 120 if warm_only or preflight_only else 300
        if self.remote is not None:
            write_json(directory / 'invocation.json', {'driver_location': 'separate SSH host', 'arguments': arguments,
                                                        'observed_at_utc': stamp()})
            process = self.remote.start(arguments, self.ca, directory, timeout)
            # Transport timeout includes collection of raw evidence, outside driver clocks.
            self.wait_for_driver(server, process, timeout + 60)
            if getattr(process, 'failure', None) or process.returncode not in (0, 1):
                raise InfrastructureFailure('Remote driver transport, resource validation or owned cleanup failed.')
        else:
            command = self.command(DRIVER_CPUS, *arguments, '--ca-file=' + str(self.ca), '--output=' + str(directory))
            write_json(directory / 'invocation.json', {'command': command, 'observed_at_utc': stamp()})
            with (directory / 'stdout.txt').open('xb') as stdout, (directory / 'stderr.txt').open('xb') as stderr:
                process = subprocess.Popen(command, cwd=self.args.server_working_directory, env=self.environment,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                self.wait_for_driver(server, process, timeout)
        # Missing readiness/failure telemetry is an infrastructure defect, even if
        # the driver emitted a plausible numerical result or a nonzero exit.
        try:
            preparation = validate_collector_preparation(directory)
            accounting = validate_phase_telemetry(directory, 'preflight')
        except (ValueError, OSError, KeyError, TypeError) as error:
            raise InfrastructureFailure('Incomplete collector readiness/preflight evidence: ' + str(error)) from error
        if preflight_only:
            result = json.loads((directory / 'preflight-result.json').read_text(encoding='utf-8'))
            canonical = {
                'schemaVersion': 1, 'mode': 'preflight-only', 'status': 'passed',
                'transport': server.transport, 'rate': rate, 'seconds': 2, 'offeredCount': rate * 2,
                'plannedManifestOffers': rate * 180, 'enteredPhases': ['preflight'],
                'warmupEntered': False, 'measuredEntered': False,
                'telemetryFile': 'preflight-evidence-accounting.json',
            }
            later = ('warmup-requests.jsonl.gz', 'measured-requests.jsonl.gz', 'load-result.json', 'warmup-result.json')
            collector = json.loads((directory / 'collector-preflight.json').read_text(encoding='utf-8'))
            if (process.returncode != 0 or any(result.get(key) != value for key, value in canonical.items())
                    or result.get('preparation', {}).get('barrier') != preparation['barrier']
                    or not phase_correct(result.get('preflight'), rate * 2)
                    or result.get('state', {}).get('passed') is not True
                    or result['preflight'] != collector.get('preflight') or result['state'] != collector.get('state')
                    or accounting['offeredCount'] != rate * 2 or any((directory / name).exists() for name in later)):
                raise InfrastructureFailure('Remote TLS/collector preflight did not satisfy the original contract.')
            return {'offered': result['offeredCount'], 'correct': result['preflight']['correct'],
                    'held_tls_connections': preparation['barrier']['distinctConnectionCount'],
                    'measured_entered': False, 'warmup_entered': False}
        result_path = directory / ('warmup-result.json' if warm_only else 'load-result.json')
        if not result_path.is_file():
            preflight_path = directory / 'collector-preflight.json'
            if allow_capacity_failure and not warm_only and process.returncode == 1 and preflight_path.is_file():
                preflight = json.loads(preflight_path.read_text())
                if diagnostic_preflight_failed(preflight, rate):
                    try:
                        validate_preflight_rejection(directory, rate, server.transport)
                    except (ValueError, OSError, KeyError, TypeError) as error:
                        raise InfrastructureFailure('Diagnostic exit is not a complete preflight rejection: ' + str(error)) from error
                    return {'diagnostic_preflight_failed': True, 'collector_preflight': preflight, 'driver_exit_code': process.returncode, 'rate': rate, 'timed_measurement_executed': False}
            raise InfrastructureFailure('Driver produced no structured result; inspect retained stdout/stderr.')
        result = json.loads(result_path.read_text())
        required = ('warmup', 'state', 'manifestHash', 'logicalManifestHash') if warm_only else ('warmup', 'measured', 'state', 'initialValidation', 'initialMetrics', 'finalMetrics', 'manifestHash', 'logicalManifestHash')
        if not isinstance(result, dict) or any(key not in result for key in required):
            raise InfrastructureFailure('Driver result schema is incomplete or incompatible; no selective continuation.')
        try:
            validate_phase_telemetry(directory, 'warmup')
            if not warm_only:
                validate_phase_telemetry(directory, 'measured')
        except (ValueError, OSError, KeyError, TypeError) as error:
            raise InfrastructureFailure('Incomplete collector entered-phase evidence: ' + str(error)) from error
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

    def diagnostics(self):
        """Fixed diagnostic attempts: never used to select/replace the 1000req/s gates."""
        observations, pairs = [], []
        for transport in ('http', 'graphql'):
            for rate, order in ((100, 'BE'), (500, 'EB'), (2000, 'BE')):
                pair = {}
                for letter in order:
                    variant = 'baseline' if letter == 'B' else 'engine'
                    directory = self.output / 'diagnostics' / transport / f'{rate:04d}-{variant}'
                    self.progress.update(phase='diagnostic-warmup60-measure180', transport=transport, rate=rate, pair_order=order, variant=variant)
                    with Server(self, directory, variant, transport) as server:
                        result = self.child_driver(server, directory / 'driver', rate=rate, allow_capacity_failure=True)
                    if result.get('diagnostic_preflight_failed') is True:
                        item = {
                            'variant': variant, 'transport': transport, 'rate': rate, 'pair_order': order,
                            'diagnostic_status': 'collector-preflight-failed', 'timed_measurement_executed': False,
                            'failure_classification': 'Capacity/contract preflight observation; warmup and measurement were not entered.',
                            'collector_preflight': result['collector_preflight'], 'driver_exit_code': result['driver_exit_code'],
                            'shutdown': server.shutdown, 'acceptance_budget_gate': 'Not applicable; diagnostic attempts cannot replace the 1000req/s series.'
                        }
                    else:
                        measured = result['measured']
                        valid = phase_correct(result['warmup'], rate * 60) and phase_correct(measured, rate * 180) and result['initialValidation'].get('passed') is True and result['state'].get('passed') is True and result['driver_exit_code'] == 0
                        initial, final = result['initialMetrics'], result['finalMetrics']
                        allocation = (final['totalAllocatedBytes'] - initial['totalAllocatedBytes']) / (rate * 180) if 'totalAllocatedBytes' in initial and 'totalAllocatedBytes' in final else None
                        item = {
                            'variant': variant, 'transport': transport, 'rate': rate, 'pair_order': order,
                            'diagnostic_status': 'completed' if valid else 'completed-with-capacity-or-contract-errors',
                            'timed_measurement_executed': True, 'contract_and_offered_work_observation_valid': valid,
                            'measured': measured, 'manifest_hash': result['manifestHash'], 'logical_manifest_hash': result['logicalManifestHash'],
                            'final_state_hash': result.get('finalState', {}).get('stateHash'), 'driver_exit_code': result['driver_exit_code'],
                            'allocations_bytes_per_offered_request': allocation, 'shutdown': server.shutdown,
                            'acceptance_budget_gate': 'Not applicable; diagnostic rates have no latency/allocation pass gate and never replace 1000req/s.'
                        }
                    observations.append(item)
                    pair[variant] = item
                    write_json(directory / 'observation.json', item)
                    write_json(self.output / 'diagnostic-observations.json', observations)
                baseline, engine = pair['baseline'], pair['engine']
                comparable = baseline['timed_measurement_executed'] and engine['timed_measurement_executed']
                paired = {
                    'transport': transport, 'rate': rate, 'pair_order': order, 'paired_measurements_available': comparable,
                    'baseline_status': baseline['diagnostic_status'], 'engine_status': engine['diagnostic_status'],
                    'same_manifest': baseline.get('manifest_hash') is not None and baseline.get('manifest_hash') == engine.get('manifest_hash') if comparable else None,
                    'baseline_p95_ms': baseline.get('measured', {}).get('p95Ms'), 'engine_p95_ms': engine.get('measured', {}).get('p95Ms'),
                    'baseline_p99_ms': baseline.get('measured', {}).get('p99Ms'), 'engine_p99_ms': engine.get('measured', {}).get('p99Ms'),
                    'baseline_allocation_bytes_per_offered_request': baseline.get('allocations_bytes_per_offered_request'),
                    'engine_allocation_bytes_per_offered_request': engine.get('allocations_bytes_per_offered_request'),
                    'acceptance_budget_gate': 'Not scored; no acceptance rate selection or substitution.'
                }
                pairs.append(paired)
                write_json(self.output / 'diagnostic-pairs.json', pairs)
                write_json(self.output / 'diagnostic-summary.json', diagnostic_summary(observations, pairs))
        summary = diagnostic_summary(observations, pairs)
        if summary['attempted_runs'] != 12 or not summary['all_planned_attempts_accounted_for']:
            raise InfrastructureFailure('Diagnostic series omitted a planned attempt.')
        return summary


def phase_correct(phase, expected):
    return isinstance(phase, dict) and phase.get('offered') == expected and phase.get('correct') == expected and phase.get('errors') == 0 and phase.get('dropped') == 0 and phase.get('successfulWithinDrain', 0) >= .999 * expected


def diagnostic_preflight_failed(result, rate):
    """Recognize only a complete, genuinely failed collector report, not an arbitrary crash."""
    if not isinstance(result, dict) or not isinstance(result.get('preflight'), dict) or not isinstance(result.get('state'), dict):
        return False
    phase, state = result['preflight'], result['state']
    keys = ('offered', 'correct', 'errors', 'dropped', 'successfulWithinDrain')
    if any(not isinstance(phase.get(key), int) or isinstance(phase.get(key), bool) or phase[key] < 0 for key in keys):
        return False
    if phase['offered'] != rate * 2 or phase['correct'] + phase['errors'] != phase['offered'] or phase['dropped'] > phase['errors'] or not isinstance(state.get('passed'), bool):
        return False
    kinds = phase.get('errorKinds')
    if (not isinstance(kinds, dict)
            or any(not isinstance(key, str) or not key or not isinstance(value, int) or isinstance(value, bool) or value <= 0 for key, value in kinds.items())
            or sum(kinds.values()) != phase['errors']
            or kinds.get('offered.dropped', 0) != phase['dropped']
            or phase['successfulWithinDrain'] > phase['correct']):
        return False
    return phase['correct'] != rate * 2 or phase['errors'] != 0 or phase['dropped'] != 0 or not state['passed']


def diagnostic_summary(observations, pairs):
    planned = {(transport, rate, variant) for transport in ('http', 'graphql') for rate in (100, 500, 2000) for variant in ('baseline', 'engine')}
    actual = {(item['transport'], item['rate'], item['variant']) for item in observations}
    return {
        'planned_runs': 12, 'attempted_runs': len(observations),
        'timed_measurement_runs': sum(item['timed_measurement_executed'] for item in observations),
        'collector_preflight_failures': sum(item['diagnostic_status'] == 'collector-preflight-failed' for item in observations),
        'timed_runs_with_capacity_or_contract_errors': sum(item['diagnostic_status'] == 'completed-with-capacity-or-contract-errors' for item in observations),
        'shutdown_failures': sum(not item['shutdown']['passed'] for item in observations),
        'all_planned_attempts_accounted_for': len(observations) == len(actual) == 12 and actual == planned,
        'observations': observations, 'pairs': pairs,
        'acceptance_budget_gate': 'Not applicable; all diagnostic outcomes remain separate from unchanged1000req/s acceptance series.',
        'reference_gate_passed': False
    }


class Server:
    def __init__(self, runner, directory, variant, transport):
        self.runner, self.directory, self.variant, self.transport = runner, directory, variant, transport
        self.process = None
        self.shutdown = None
        self.ready = None
        self.resource_before = None
        self.resource_live = None

    def __enter__(self):
        self.directory.mkdir(parents=True, exist_ok=False)
        ready_file, self.state_file = self.directory / 'ready.json', self.directory / 'final-state.json'
        if self.runner.app_resources is not None:
            self.resource_before = self.runner.app_resources.verify_after(self.runner.manifest['reference_app_resources'])
            write_json(self.directory / 'app-resources-before.json', self.resource_before)
        command = self.runner.server_command('--mode=serve', '--variant=' + self.variant, '--transport=' + self.transport, '--fixture-dir=' + str(self.runner.fixture), '--ready-file=' + str(ready_file), '--state-file=' + str(self.state_file))
        write_json(self.directory / 'invocation.json', {'command': command, 'observed_at_utc': stamp()})
        self.stdout = (self.directory / 'server.stdout.txt').open('xb')
        self.stderr = (self.directory / 'server.stderr.txt').open('xb')
        self.started_ns = time.monotonic_ns()
        self.process = subprocess.Popen(command, cwd=self.runner.args.server_working_directory, env=self.runner.environment, stdin=subprocess.PIPE, stdout=self.stdout, stderr=self.stderr, text=True, start_new_session=True)
        self.runner.owned.append(self.process)
        try:
            deadline = time.monotonic() + 60
            while self.ready is None:
                if self.process.poll() is not None:
                    raise InfrastructureFailure('Server exited before readiness; see retained server logs.')
                if time.monotonic() > deadline:
                    raise InfrastructureFailure('Server readiness exceeded 60 seconds.')
                try:
                    if ready_file.is_file():
                        value = json.loads(ready_file.read_text())
                        if value.get('address') and value.get('tlsProtocol') == 'Tls13':
                            self.ready = value
                except json.JSONDecodeError:
                    pass
                except OSError as error:
                    # A cross-filesystem readiness publication can race stat/read.
                    # Retry only transient absence; the original deadline and
                    # startup stopwatch continue to include this waiting time.
                    if error.errno not in (errno.ENOENT, errno.EAGAIN, errno.ENODATA):
                        raise
                self.runner.progress.tick()
                if self.ready is None:
                    time.sleep(.005)
            self.verify_first_response()
            self.startup_milliseconds = (self.verified_ns - self.started_ns) / 1e6
            # Provenance inspection follows the counted first response and is
            # outside startup/load timing; both variants use this same observer.
            if self.resource_before is not None:
                self.resource_live = self.runner.app_resources.observe(self.process.pid)
                write_json(self.directory / 'app-process-resources.json', self.resource_live)
            mappings = Path(f'/proc/{self.process.pid}/maps').read_text()
            runtime_names = ('libcoreclr.so', 'libhostpolicy.so', 'System.Private.CoreLib.dll')
            kestrel = 'Microsoft.AspNetCore.Server.Kestrel.Core.dll'
            loaded = sorted({line.split(maxsplit=5)[-1] for line in mappings.splitlines()
                             if any(name in line for name in (*runtime_names, kestrel))})
            write_json(self.directory / 'loaded-runtime.json', {'process_id': self.process.pid, 'paths': loaded, 'inspection_after_first_response': True})
            if self.runner.remote is not None:
                shared = self.runner.args.dotnet.parent / 'shared'
                required = {str(shared / 'Microsoft.NETCore.App' / '11.0.0' / name) for name in runtime_names}
                required.add(str(shared / 'Microsoft.AspNetCore.App' / '11.0.0' / kestrel))
                if set(loaded) != required:
                    raise InfrastructureFailure('Loaded app runtime differs from the pinned .NET/ASP.NET Core 11.0.0 deployment.')
            return self
        except BaseException:
            self.stop()
            raise

    def verify_first_response(self):
        address = urlsplit(self.ready['address'])
        hosts = ('localhost', '127.0.0.1', '::1') if self.runner.remote is None else (self.runner.network['listen_ip'],)
        if (address.scheme != 'https' or address.hostname not in hosts or not address.port or address.username
                or address.password or address.path not in ('', '/') or address.query or address.fragment):
            raise InfrastructureFailure('Readiness address differs from the owned HTTPS fixture endpoint.')
        if (self.ready.get('processId') != self.process.pid or self.ready.get('datasetId') != 'cehpalon-small-api-v1'
                or self.ready.get('variant') != self.variant or self.ready.get('transport') != self.transport):
            raise InfrastructureFailure('Ready identity/dataset differs from the owned process.')
        if base64.b64decode(self.ready['rootCaDerBase64']) != self.runner.ca.read_bytes():
            raise InfrastructureFailure('Readiness CA differs from precreated fixture CA.')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(self.runner.ca.read_bytes()))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        source_address = (self.runner.network['listen_ip'], 0) if self.runner.remote is not None else None
        client = http.client.HTTPSConnection(address.hostname, address.port, context=context, timeout=10,
                                            source_address=source_address)
        try:
            payload = {'id': 1} if self.transport == 'http' else {'query': '{catalogItem(input:{id:1}){id label revision amountMinorUnits}}'}
            client.request('POST', '/api/catalog/get' if self.transport == 'http' else '/graphql', json.dumps(payload, separators=(',', ':')).encode(), {'Content-Type': 'application/json'})
            tls_protocol = client.sock.version() if client.sock else None
            tls_cipher = client.sock.cipher() if client.sock else None
            response = client.getresponse()
            body = json.loads(response.read())
            if tls_protocol != 'TLSv1.3' or not tls_cipher or response.status != 200 or 'errors' in body:
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
        resource_failure = None
        if self.resource_before is not None and self.process is not None and self.process.poll() is None:
            try:
                live = self.runner.app_resources.verify_after(self.resource_live or self.resource_before, self.process.pid)
                write_json(self.directory / 'app-process-resources-before-stop.json', live)
            except (OSError, RuntimeError, ValueError) as exception:
                resource_failure = str(exception)
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
            except OSError as exception:
                closed = self.runner.remote is None or exception.errno == errno.ECONNREFUSED
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
        if self.resource_before is not None:
            try:
                verified = self.runner.app_resources.verify_after(self.resource_before)
                write_json(self.directory / 'app-resources-after.json', verified)
            except (OSError, RuntimeError, ValueError) as exception:
                resource_failure = resource_failure or str(exception)
        if resource_failure is not None:
            write_json(self.directory / 'app-resource-failure.json', {'error': resource_failure})
        passed = graceful and elapsed <= 5000 and self.process.returncode == 0 and closed and owned and disabled and resource_failure is None
        self.shutdown = {'requested_monotonic_ns': started, 'elapsed_ms': elapsed, 'graceful': graceful, 'exit_code': self.process.returncode if self.process else None, 'listener_closed': closed, 'owned_handlers_balanced': owned, 'disabled_probes_zero': disabled, 'passed': passed, 'error': error}
        write_json(self.directory / 'shutdown.json', self.shutdown)
        self.stdout.close()
        self.stderr.close()

    def __exit__(self, exception_type, exception, tb):
        self.stop()
        if exception_type is None and (self.directory / 'app-resource-failure.json').is_file():
            raise InfrastructureFailure('Application resource evidence changed during the run.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dotnet', required=True, type=Path)
    parser.add_argument('--assembly', required=True, type=Path)
    parser.add_argument('--engine-root', type=Path, default=ROOT.parent / 'Cehpalon-Engine')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--server-working-directory', type=Path, default=ROOT)
    parser.add_argument('--phases', default='startup,idle,load,diagnostics')
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--remote-config', type=Path)
    parser.add_argument('--remote-preflight-lab', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('The Small API benchmark orchestrator requires Linux.')
    args.dotnet, args.assembly, args.engine_root = args.dotnet.resolve(), args.assembly.resolve(), args.engine_root.resolve()
    args.server_working_directory = args.server_working_directory.resolve()
    if not args.server_working_directory.is_dir():
        parser.error('Server working directory must already exist.')
    args.phases = args.phases.split(',')
    if len(set(args.phases)) != len(args.phases) or any(phase not in ('startup', 'idle', 'load', 'diagnostics') for phase in args.phases):
        parser.error('Select unique phases from startup,idle,load,diagnostics; full defaults are never shortened.')
    if args.remote_preflight_lab and not (args.remote_config and args.preflight_only):
        parser.error('Laboratory remote mode requires --remote-config and --preflight-only.')
    if args.remote_config and not args.preflight_only and tuple(args.phases) != PHASES:
        parser.error('The original reference run requires all W0 phases in the declared order.')
    output = (ROOT / args.output).resolve()
    private = (ROOT / '.local').resolve()
    native_private = (Path.home() / '.local/share/cehpalon-benchmark-runs').resolve()
    if not ((output.is_relative_to(private) and output != private) or (output.is_relative_to(native_private) and output != native_private)):
        parser.error('Use a fresh attempt directory beneath ignored Samples .local or task-owned Linux-home .local/share/cehpalon-benchmark-runs.')
    if output.is_relative_to(native_private):
        native_private.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(native_private, 0o700)
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    runner = Runner(args, output)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Received signal ' + str(signum) + '; stopping only owned processes.')
    signal.signal(signal.SIGTERM, interrupted)
    summary = {'started_at_utc': stamp(), 'classification': runner.classification, 'reference_preflight_passed': False,
               'reference_gate_passed': False, 'completed_phases': [], 'not_run_phases': list(PHASES)}
    try:
        runner.preflight()
        summary['reference_preflight_passed'] = runner.reference_preflight_passed
        if args.remote_config and not args.preflight_only and not runner.reference_preflight_passed:
            raise InfrastructureFailure('Timed reference phases require successful real-host and remote collector preflight.')
        if not args.preflight_only:
            for phase in args.phases:
                summary[phase] = getattr(runner, phase)()
                summary['completed_phases'].append(phase)
                summary['not_run_phases'].remove(phase)
                write_json(output / 'summary.json', summary)
        numeric = []
        for phase in summary['completed_phases']:
            if phase == 'diagnostics':
                continue  # Diagnostic capacity failures are reported, never scored as acceptance budgets.
            numeric.append(summary[phase]['all_budget_observations_passed'] if phase == 'load' else all(item['budget_observation_passed'] for item in summary[phase]))
        passed = runner.reference_preflight_passed and tuple(summary['completed_phases']) == PHASES and all(numeric)
        if passed:
            runner.progress.update(phase='reference-audit')
            summary['reference_timed_driver_audits'] = runner.audit_reference_timed_evidence()
        status = ('preflight-only' if args.preflight_only else 'observations-complete' if not args.remote_config
                  else 'reference-passed' if passed else 'reference-failed')
        summary.update(status=status, reference_gate_passed=passed,
                       numeric_budget_observations_passed=all(numeric) if numeric else None, completed_at_utc=stamp())
        runner.manifest.update(status=status, reference_gate_passed=passed, completed_at_utc=summary['completed_at_utc'])
        write_json(output / 'manifest.json', runner.manifest)
        write_json(output / 'summary.json', summary)
        runner.progress.update(status=status, phase='complete', reference_gate_passed=passed)
        print(json.dumps({'status': status, 'completed_phases': summary['completed_phases'],
                          'reference_preflight_passed': runner.reference_preflight_passed,
                          'reference_gate_passed': passed, 'output': str(output)}))
        return 1 if status == 'reference-failed' else 0
    except BaseException as error:
        summary.update(status='aborted-infrastructure', error=repr(error), completed_at_utc=stamp())
        runner.manifest.update(status='aborted-infrastructure', error=repr(error), completed_at_utc=summary['completed_at_utc'])
        if isinstance(getattr(error, 'evidence', None), dict):
            write_json(output / 'failed-resource-evidence.json', error.evidence)
        write_json(output / 'manifest.json', runner.manifest)
        (output / 'failure-traceback.txt').write_text(traceback.format_exc(), encoding='utf-8')
        write_json(output / 'summary.json', summary)
        runner.progress.update(status='aborted-infrastructure', error=repr(error), phase='aborted')
        print(json.dumps({'status': summary['status'], 'error': repr(error), 'output': str(output)}), file=sys.stderr)
        return 1
    finally:
        cleanup_errors = []
        for process in reversed(runner.owned):
            try:
                runner.terminate(process)
            except Exception as error:
                cleanup_errors.append(repr(error))
        runner.progress.events.close()
        if cleanup_errors:
            write_json(output / 'cleanup-failures.json', {'errors': cleanup_errors})
            summary.update(status='aborted-infrastructure', reference_gate_passed=False, owned_cleanup_failed=True)
            runner.manifest.update(status=summary['status'], reference_gate_passed=False, owned_cleanup_failed=True)
            write_json(output / 'summary.json', summary)
            write_json(output / 'manifest.json', runner.manifest)
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
